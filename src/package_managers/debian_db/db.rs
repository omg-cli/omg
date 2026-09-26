//! Pure Rust Debian/Ubuntu Database Parser - ULTRA FAST
//!
//! Parses /var/lib/apt/lists/*_Packages and /var/lib/dpkg/status files directly
//! and provides a high-performance index with zero-copy deserialization via rkyv.
//!
//! Performance features:
//! - Zero-copy rkyv access over owned cache snapshots
//! - SIMD-accelerated search via memchr/memmem
//! - One atomically published snapshot for native and archived views
//! - Parallel parsing via rayon

#![cfg(any(feature = "debian", feature = "debian-pure"))]

use std::collections::HashMap;
use std::fs;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use ahash::AHashSet;
use anyhow::{Context, Result};
use fst::{IntoStreamer, Map, Streamer};
use memchr::memmem;
use rayon::prelude::*;
use rkyv::util::AlignedVec;
use sha2::{Digest, Sha256};
use std::sync::RwLock;

use crate::core::paths;
use crate::core::{Package, PackageSource};
use crate::runtimes::common::{BudgetedWriter, decode_xz_to};

/// TTL for cache eviction safety net (30 minutes)
const CACHE_TTL_SECS: u64 = 30 * 60;
const MAX_INDEX_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;

fn read_index_snapshot(path: &Path, limit: u64) -> Result<AlignedVec> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("Failed to open index snapshot at {}", path.display()))?;
    read_index_snapshot_file(&file, limit)
}

fn read_index_snapshot_file(file: &fs::File, limit: u64) -> Result<AlignedVec> {
    let metadata = file.metadata()?;
    anyhow::ensure!(metadata.is_file(), "Index snapshot must be a regular file");
    anyhow::ensure!(
        metadata.len() <= limit,
        "Index snapshot exceeds {limit} bytes"
    );

    let mut file = file.try_clone()?;
    std::io::Seek::rewind(&mut file)?;
    let mut bytes = AlignedVec::new();
    bytes.extend_from_reader(&mut Read::by_ref(&mut file).take(limit))?;
    let mut extra = [0];
    anyhow::ensure!(
        file.read(&mut extra)? == 0,
        "Index snapshot exceeds {limit} bytes"
    );
    Ok(bytes)
}

/// Current time as unix seconds (`0` if the clock is before the epoch).
fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// TTL check for `unix_now_secs()`-stamped access times (`0` = never accessed).
fn is_access_expired(last_accessed: u64) -> bool {
    let last = if last_accessed == 0 {
        return false; // never accessed: nothing to expire yet
    } else {
        last_accessed
    };
    unix_now_secs().saturating_sub(last) > CACHE_TTL_SECS
}

/// Global cache for Debian package index
static DEBIAN_INDEX_CACHE: LazyLock<RwLock<DebianIndexCache>> =
    LazyLock::new(|| RwLock::new(DebianIndexCache::default()));

/// Global cache for dpkg/status to avoid reparsing on every call
static DPKG_STATUS_CACHE: LazyLock<RwLock<DpkgStatusCache>> =
    LazyLock::new(|| RwLock::new(DpkgStatusCache::default()));

#[derive(Default)]
struct DebianIndexCache {
    index: Option<DebianPackageIndex>,
    fst_mapping: Option<FstMappingId>,
    /// Source set and mtimes used to invalidate the complete index.
    file_mtimes: HashMap<PathBuf, std::time::SystemTime>,
    /// Contiguous search buffer for SIMD search: "name desc\0name desc\0..."
    search_buffer: Vec<u8>,
    /// Offsets into the search buffer
    package_offsets: Vec<usize>,
    /// Last access time for TTL-based eviction (unix seconds; `0` = never)
    last_accessed: u64,
}

#[derive(Debug, PartialEq, Eq)]
enum IndexRefresh {
    Memory,
    Disk,
    Rebuild,
}

impl DebianIndexCache {
    fn refresh_requirement(
        &mut self,
        current_files: &HashMap<PathBuf, std::time::SystemTime>,
    ) -> IndexRefresh {
        let sources_match = self.file_mtimes == *current_files;
        let has_index = self.index.is_some();
        let expired = is_access_expired(self.last_accessed);
        if has_index && sources_match && !expired {
            self.last_accessed = unix_now_secs();
            return IndexRefresh::Memory;
        }
        if expired {
            *self = Self::default();
        }
        // Cold or expired-but-unchanged state may reuse a disk snapshot.
        // An observed change, including removal of the last list, must rebuild.
        if !has_index || sources_match {
            IndexRefresh::Disk
        } else {
            IndexRefresh::Rebuild
        }
    }
}

/// Cache for /var/lib/dpkg/status to avoid expensive reparsing
struct DpkgStatusCache {
    packages: Vec<DpkgPackageEntry>,
    /// Shared installed-name set. `Arc` lets hot readers (`search_fast`,
    /// `is_installed_fast`) take a reference per query without cloning N
    /// strings or holding the writer lock.
    installed_set: Arc<AHashSet<String>>,
    status_mtime: std::time::SystemTime,
    extended_states_mtime: Option<std::time::SystemTime>,
    /// Last access time for TTL-based eviction (unix seconds; `0` = never).
    /// Atomic so cache HITS only need the read lock.
    last_accessed: AtomicU64,
}

impl Default for DpkgStatusCache {
    fn default() -> Self {
        Self {
            packages: Vec::new(),
            installed_set: Arc::new(AHashSet::new()),
            status_mtime: std::time::UNIX_EPOCH,
            extended_states_mtime: None,
            last_accessed: AtomicU64::new(0),
        }
    }
}

fn installed_cache_is_current(
    cache: &DpkgStatusCache,
    status_mtime: std::time::SystemTime,
    extended_states_mtime: Option<std::time::SystemTime>,
) -> bool {
    !cache.packages.is_empty()
        && cache.status_mtime == status_mtime
        && cache.extended_states_mtime == extended_states_mtime
        && !is_access_expired(cache.last_accessed.load(Ordering::Relaxed))
}

/// Names of all installed packages from the dpkg-status cache.
///
/// Hot path for `search_fast`: returns a shared `Arc` of the cached set after
/// validating the source mtimes, so a search pays two `stat` calls instead of
/// deep-cloning every installed entry and re-hashing N names.
fn installed_names() -> Result<Arc<AHashSet<String>>> {
    let status_path = Path::new("/var/lib/dpkg/status");
    let status_mtime = required_mtime(status_path)?;
    let extended_states_mtime = optional_mtime(Path::new("/var/lib/apt/extended_states"))?;

    {
        let cache = crate::core::sync::read_cache(&DPKG_STATUS_CACHE);
        if installed_cache_is_current(&cache, status_mtime, extended_states_mtime) {
            cache
                .last_accessed
                .store(unix_now_secs(), Ordering::Relaxed);
            return Ok(Arc::clone(&cache.installed_set));
        }
    }

    // Cold or stale: refresh through the standard path, which rebuilds and
    // swaps in the complete set under one writer acquisition.
    list_installed_fast()?;
    let cache = crate::core::sync::read_cache(&DPKG_STATUS_CACHE);
    Ok(Arc::clone(&cache.installed_set))
}

/// Global owned snapshot of the on-disk mmap-format index.
static DEBIAN_MMAP_INDEX: LazyLock<RwLock<Option<DebianMmapIndex>>> =
    LazyLock::new(|| RwLock::new(None));

/// Global FST index for `O(query_len)` prefix searches
/// FST provides logarithmic complexity for prefix matching vs O(n) full scan
static DEBIAN_FST_INDEX: LazyLock<RwLock<Option<FstIndex>>> = LazyLock::new(|| RwLock::new(None));

/// Canonical name-to-row identity, independent of timestamps and file names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FstMappingId([u8; 32]);

fn sorted_fst_entries<'a>(names: impl IntoIterator<Item = (&'a str, u64)>) -> Vec<(String, u64)> {
    let mut entries: HashMap<String, u64> = HashMap::new();
    for (name, index) in names {
        entries
            .entry(name.to_lowercase())
            .and_modify(|previous| *previous = (*previous).max(index))
            .or_insert(index);
    }
    let mut entries: Vec<_> = entries.into_iter().collect();
    entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    entries
}

impl FstMappingId {
    fn hash_entry(hash: &mut Sha256, name: &[u8], index: u64) {
        hash.update((name.len() as u64).to_le_bytes());
        hash.update(name);
        hash.update(index.to_le_bytes());
    }

    fn from_names<'a>(names: impl IntoIterator<Item = (&'a str, u64)>) -> Self {
        let mut hash = Sha256::new();
        for (name, index) in sorted_fst_entries(names) {
            Self::hash_entry(&mut hash, name.as_bytes(), index);
        }
        Self(hash.finalize().into())
    }

    fn from_map(map: &Map<AlignedVec>) -> Self {
        let mut hash = Sha256::new();
        let mut stream = map.stream();
        while let Some((name, index)) = stream.next() {
            Self::hash_entry(&mut hash, name, index);
        }
        Self(hash.finalize().into())
    }
}

/// FST-based search index with TTL-based eviction
struct FstIndex {
    map: Map<AlignedVec>,
    /// Identity derived from the validated name-to-row mapping.
    mapping: FstMappingId,
    /// Last access time for TTL-based eviction
    last_accessed: AtomicU64,
}

impl FstIndex {
    /// Open an FST and derive its identity from the actual mapping. Legacy
    /// `.gen` files are not evidence of which bytes an open descriptor owns.
    fn open(path: &Path) -> Result<Self> {
        let bytes = read_index_snapshot(path, MAX_INDEX_SNAPSHOT_BYTES)?;
        let map = Map::new(bytes).map_err(|e| anyhow::anyhow!("Corrupted FST index: {e}"))?;
        map.as_fst().verify().context("Corrupted FST checksum")?;
        let mapping = FstMappingId::from_map(&map);

        Ok(Self {
            map,
            mapping,
            last_accessed: AtomicU64::new(unix_now_secs()),
        })
    }

    /// Check if expired based on TTL
    fn is_expired(&self) -> bool {
        is_access_expired(self.last_accessed.load(Ordering::Relaxed))
    }

    /// Update last accessed time
    fn touch(&self) {
        self.last_accessed.store(unix_now_secs(), Ordering::Relaxed);
    }
}

/// Owned snapshot of the mmap-format Debian index, with zero-copy package access.
pub struct DebianMmapIndex {
    bytes: AlignedVec,
    fst_mapping: FstMappingId,
    last_accessed: AtomicU64,
}

impl DebianMmapIndex {
    /// Open and validate an existing read-only package index.
    pub fn open(path: &Path) -> Result<Self> {
        Self::from_bytes(read_index_snapshot(path, MAX_INDEX_SNAPSHOT_BYTES)?)
    }

    fn from_file(file: &fs::File) -> Result<Self> {
        Self::from_bytes(read_index_snapshot_file(file, MAX_INDEX_SNAPSHOT_BYTES)?)
    }

    fn from_bytes(bytes: AlignedVec) -> Result<Self> {
        let archive =
            rkyv::access::<rkyv::Archived<DebianPackageIndex>, rkyv::rancor::Error>(&bytes)
                .map_err(|error| anyhow::anyhow!("Corrupted Debian package index: {error}"))?;
        let fst_mapping = FstMappingId::from_names(
            archive
                .name_to_idx
                .iter()
                .map(|(name, index)| (name.as_str(), u64::from(u32::from(*index)))),
        );
        Ok(Self {
            bytes,
            fst_mapping,
            last_accessed: AtomicU64::new(unix_now_secs()),
        })
    }

    /// Build the native view from this exact validated inode, not another
    /// pathname that may have been replaced during publication.
    fn deserialize(&self) -> Result<DebianPackageIndex> {
        rkyv::deserialize::<DebianPackageIndex, rkyv::rancor::Error>(self.archive())
            .context("Failed to deserialize Debian snapshot")
    }

    fn archive(&self) -> &rkyv::Archived<DebianPackageIndex> {
        // SAFETY: `open` validates these aligned, owned bytes before construction.
        // No mutable access is exposed, and external writers cannot change them.
        #[expect(unsafe_code)]
        unsafe {
            rkyv::access_unchecked::<rkyv::Archived<DebianPackageIndex>>(&self.bytes)
        }
    }

    /// Resolve `name[:architecture[:component]]` without deserializing the index.
    /// Uses the same fallback order as [`DebianPackageIndex::get_query`].
    pub fn get(&self, query: &str) -> Result<Option<&rkyv::Archived<DebianPackage>>> {
        let archive = self.archive();
        let index = if let Some((name, rest)) = query.split_once(':') {
            if let Some((architecture, _)) = rest.split_once(':') {
                archive
                    .name_arch_component_to_idx
                    .get(query)
                    .or_else(|| {
                        archive
                            .name_arch_to_idx
                            .get(format!("{name}:{architecture}").as_str())
                    })
                    .or_else(|| archive.name_to_idx.get(name))
            } else {
                archive
                    .name_arch_to_idx
                    .get(query)
                    .or_else(|| archive.name_to_idx.get(name))
            }
        } else {
            archive.name_to_idx.get(query)
        };
        let Some(index) = index else {
            return Ok(None);
        };
        Ok(archive.packages.get(u32::from(*index) as usize))
    }

    /// Access all archived packages without deserializing the index.
    pub fn packages(&self) -> Result<&rkyv::vec::ArchivedVec<rkyv::Archived<DebianPackage>>> {
        Ok(&self.archive().packages)
    }

    /// Recorded build time (`updated_at`), in seconds. This metadata is not
    /// a unique snapshot identity or a publication token.
    pub fn generation(&self) -> i64 {
        i64::from(self.archive().updated_at)
    }

    #[must_use]
    pub fn is_expired(&self) -> bool {
        is_access_expired(self.last_accessed.load(Ordering::Relaxed))
    }

    pub fn touch(&self) {
        self.last_accessed.store(unix_now_secs(), Ordering::Relaxed);
    }
}

/// A Debian package entry optimized for zero-copy access
///
/// `suite` and `source_key` record where the entry was parsed from (derived
/// from the apt lists filename) so download URLs can be built against the
/// repository that actually published the package.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone)]
pub struct DebianPackage {
    pub name: String,
    pub version: String,
    pub description: String,
    pub section: String,
    pub priority: String,
    pub installed_size: u64,
    pub maintainer: String,
    pub architecture: String,
    pub depends: Vec<String>,
    pub filename: String,
    pub size: u64,
    pub sha256: String,
    pub homepage: String,
    pub component: String,
    pub suite: String,
    pub source_key: String,
}

use crate::package_managers::types::parse_version_or_zero;

impl DebianPackage {
    #[must_use]
    pub fn to_package(&self) -> Package {
        Package {
            name: self.name.clone(),
            version: parse_version_or_zero(&self.version),
            description: self.description.clone(),
            source: PackageSource::Official,
            installed: false,
        }
    }
}

fn package_with_installed_state(
    package: &DebianPackage,
    installed_set: &AHashSet<String>,
) -> Package {
    let mut result = package.to_package();
    result.installed = installed_set.contains(package.name.as_str());
    result
}

fn archived_package_to_package(
    package: &rkyv::Archived<DebianPackage>,
    installed: bool,
) -> Package {
    Package {
        name: package.name.to_string(),
        version: parse_version_or_zero(package.version.as_str()),
        description: package.description.to_string(),
        source: PackageSource::Official,
        installed,
    }
}

/// In-memory Debian package index with name/arch/component lookup maps.
///
/// Fields are private by design: the lookup maps must only ever be mutated
/// through [`DebianPackageIndex::add_package`], which keeps them consistent
/// with `packages`. Note that the maps deliberately use std `HashMap` for
/// direct rkyv serialization compatibility.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Default, Clone)]
pub struct DebianPackageIndex {
    packages: Vec<DebianPackage>,
    name_to_idx: HashMap<String, usize>,
    name_arch_to_idx: HashMap<String, usize>,
    name_arch_component_to_idx: HashMap<String, usize>,
    updated_at: i64,
}

impl DebianPackageIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// All indexed packages in insertion order.
    #[must_use]
    pub fn packages(&self) -> &[DebianPackage] {
        &self.packages
    }

    pub fn add_package(&mut self, pkg: DebianPackage) {
        let idx = self.packages.len();
        let name = pkg.name.clone();
        let arch = pkg.architecture.clone();
        let component = pkg.component.clone();

        if let Some(existing_idx) = self.name_to_idx.get(&name).copied() {
            if let Some(existing_pkg) = self.packages.get(existing_idx)
                && is_better_name_candidate(&pkg, existing_pkg)
            {
                self.name_to_idx.insert(name.clone(), idx);
            }
        } else {
            self.name_to_idx.insert(name.clone(), idx);
        }

        let name_arch_key = format!("{name}:{arch}");
        if let Some(existing_idx) = self.name_arch_to_idx.get(&name_arch_key).copied() {
            if let Some(existing_pkg) = self.packages.get(existing_idx)
                && is_better_arch_candidate(&pkg, existing_pkg)
            {
                self.name_arch_to_idx.insert(name_arch_key.clone(), idx);
            }
        } else {
            self.name_arch_to_idx.insert(name_arch_key, idx);
        }

        let name_arch_component_key = format!("{name}:{arch}:{component}");
        self.name_arch_component_to_idx
            .insert(name_arch_component_key, idx);
        self.packages.push(pkg);
    }

    /// One deterministic best candidate per package name, ordered by name.
    #[must_use]
    pub fn best_candidates(&self) -> Vec<&DebianPackage> {
        let mut names: Vec<&String> = self.name_to_idx.keys().collect();
        names.sort_unstable();
        names
            .into_iter()
            .filter_map(|name| self.name_to_idx.get(name).map(|&idx| &self.packages[idx]))
            .collect()
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&DebianPackage> {
        self.name_to_idx.get(name).map(|&idx| &self.packages[idx])
    }

    #[must_use]
    pub fn get_name_arch(&self, name: &str, arch: &str) -> Option<&DebianPackage> {
        let key = format!("{name}:{arch}");
        self.name_arch_to_idx
            .get(&key)
            .map(|&idx| &self.packages[idx])
    }

    #[must_use]
    pub fn get_name_arch_component(
        &self,
        name: &str,
        arch: &str,
        component: &str,
    ) -> Option<&DebianPackage> {
        let key = format!("{name}:{arch}:{component}");
        self.name_arch_component_to_idx
            .get(&key)
            .map(|&idx| &self.packages[idx])
    }

    #[must_use]
    pub fn get_query(&self, query: &str) -> Option<&DebianPackage> {
        if let Some((name, rest)) = query.split_once(':') {
            if let Some((arch, component)) = rest.split_once(':') {
                return self
                    .get_name_arch_component(name, arch, component)
                    .or_else(|| self.get_name_arch(name, arch))
                    .or_else(|| self.get(name));
            }

            return self.get_name_arch(name, rest).or_else(|| self.get(name));
        }

        self.get(query)
    }
}

/// The Debian architecture name for the running binary (e.g. `x86_64` ->
/// `amd64`). Single source of truth for index scoring, sync URLs, and
/// maintainer-script environments.
#[must_use]
pub fn debian_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "i386",
        "arm" => "armhf",
        other => other,
    }
}

fn name_candidate_score(pkg: &DebianPackage) -> u8 {
    let mut score = 0u8;
    if pkg.architecture == debian_arch() {
        score += 4;
    } else if pkg.architecture == "all" {
        score += 2;
    }
    if pkg.component == "main" {
        score += 1;
    }
    score
}

fn is_better_name_candidate(new_pkg: &DebianPackage, existing_pkg: &DebianPackage) -> bool {
    let new_score = name_candidate_score(new_pkg);
    let existing_score = name_candidate_score(existing_pkg);
    if new_score != existing_score {
        return new_score > existing_score;
    }

    crate::package_managers::types::compare_deb_versions(&new_pkg.version, &existing_pkg.version)
        == std::cmp::Ordering::Greater
}

fn is_better_arch_candidate(new_pkg: &DebianPackage, existing_pkg: &DebianPackage) -> bool {
    if new_pkg.component == "main" && existing_pkg.component != "main" {
        return true;
    }
    if new_pkg.component != "main" && existing_pkg.component == "main" {
        return false;
    }

    crate::package_managers::types::compare_deb_versions(&new_pkg.version, &existing_pkg.version)
        == std::cmp::Ordering::Greater
}

fn apt_lists_from_read_dir(result: std::io::Result<fs::ReadDir>) -> Result<fs::ReadDir> {
    result.context("Failed to read APT lists directory")
}

fn apt_lists_entry(result: std::io::Result<fs::DirEntry>) -> Result<fs::DirEntry> {
    result.context("Failed to read APT lists directory entry")
}

fn required_mtime(path: &Path) -> Result<std::time::SystemTime> {
    fs::metadata(path)
        .and_then(|meta| meta.modified())
        .with_context(|| format!("Failed to read mtime {}", path.display()))
}

fn optional_mtime(path: &Path) -> Result<Option<std::time::SystemTime>> {
    match fs::metadata(path) {
        Ok(meta) => {
            Ok(Some(meta.modified().with_context(|| {
                format!("Failed to read mtime {}", path.display())
            })?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("Failed to read mtime {}", path.display()))
        }
    }
}

fn hydrate_index_cache(
    cache: &mut DebianIndexCache,
    index: DebianPackageIndex,
    file_mtimes: HashMap<PathBuf, std::time::SystemTime>,
) {
    let estimated_size = index
        .packages
        .iter()
        .map(|package| package.name.len() + package.description.len() + 2)
        .sum();
    let mut search_buffer = Vec::with_capacity(estimated_size);
    let mut package_offsets = Vec::with_capacity(index.packages.len() + 1);

    for package in &index.packages {
        package_offsets.push(search_buffer.len());
        search_buffer.extend(package.name.bytes().map(|byte| byte.to_ascii_lowercase()));
        search_buffer.push(b' ');
        search_buffer.extend(
            package
                .description
                .bytes()
                .map(|byte| byte.to_ascii_lowercase()),
        );
        search_buffer.push(0);
    }
    package_offsets.push(search_buffer.len());

    cache.fst_mapping = Some(FstMappingId::from_names(
        index
            .name_to_idx
            .iter()
            .map(|(name, index)| (name.as_str(), *index as u64)),
    ));
    cache.index = Some(index);
    cache.file_mtimes = file_mtimes;
    cache.search_buffer = search_buffer;
    cache.package_offsets = package_offsets;
    cache.last_accessed = unix_now_secs();
}

pub fn ensure_index_loaded() -> Result<()> {
    let lists_dir = Path::new("/var/lib/apt/lists");
    if !lists_dir.exists() {
        *crate::core::sync::write_cache(&DEBIAN_INDEX_CACHE) = DebianIndexCache::default();
        *crate::core::sync::write_cache(&DEBIAN_MMAP_INDEX) = None;
        *crate::core::sync::write_cache(&DEBIAN_FST_INDEX) = None;
        return Ok(());
    }

    // Get current package files and their mtimes
    let mut current_files = HashMap::new();
    let entries = apt_lists_from_read_dir(fs::read_dir(lists_dir))?;
    for entry in entries {
        let entry = apt_lists_entry(entry)?;
        let path = entry.path();
        let Some(filename) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !filename.contains("_Packages")
            || path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("diff"))
        {
            continue;
        }
        let mtime = required_mtime(&path)?;
        current_files.insert(path, mtime);
    }

    let refresh =
        crate::core::sync::write_cache(&DEBIAN_INDEX_CACHE).refresh_requirement(&current_files);
    if refresh == IndexRefresh::Memory {
        return Ok(());
    }

    // The existing v8 mmap is the sole package-metadata snapshot. Legacy LZ4
    // duplicates are neither read nor rewritten. Invalid snapshots rebuild
    // from APT lists after checked archive validation fails.
    let mmap_path = paths::cache_dir().join("debian_index_v8.mmap");
    let snapshot = if refresh == IndexRefresh::Disk && disk_cache_is_fresh(&mmap_path, lists_dir) {
        match DebianMmapIndex::open(&mmap_path)
            .and_then(|mmap| mmap.deserialize().map(|index| (index, mmap)))
        {
            Ok(snapshot) => Some(snapshot),
            Err(error) => {
                tracing::debug!(%error, path = %mmap_path.display(), "Debian snapshot is unusable; rebuilding");
                None
            }
        }
    } else {
        None
    };

    if let Some((index, mmap)) = snapshot {
        tracing::debug!(
            "Mapped snapshot is fresh for the APT directory and {} Packages files, skipping rebuild",
            current_files.len()
        );
        *crate::core::sync::write_cache(&DEBIAN_MMAP_INDEX) = Some(mmap);
        *crate::core::sync::write_cache(&DEBIAN_FST_INDEX) = None;
        let mut cache = crate::core::sync::write_cache(&DEBIAN_INDEX_CACHE);
        hydrate_index_cache(&mut cache, index, current_files);
        return Ok(());
    }

    *crate::core::sync::write_cache(&DEBIAN_MMAP_INDEX) = None;
    *crate::core::sync::write_cache(&DEBIAN_FST_INDEX) = None;
    let all_files: Vec<PathBuf> = current_files.keys().cloned().collect();
    let index = rebuild_package_index(&all_files)?;
    // Release serialization buffers before hydrating in-memory search state.
    {
        if let Some(p) = mmap_path.parent() {
            fs::create_dir_all(p).with_context(|| {
                format!("Failed to create Debian cache directory: {}", p.display())
            })?;
        }
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&index)
            .map_err(|e| anyhow::anyhow!("Serialization error: {e}"))?;

        use std::io::Write;
        use tempfile::NamedTempFile;

        let parent = mmap_path.parent().unwrap_or_else(|| Path::new("."));
        // Atomic write for the sole metadata snapshot
        // CRITICAL: Must use atomic rename to avoid crashing readers holding an mmap
        let mut temp_mmap =
            NamedTempFile::new_in(parent).context("Failed to create temporary mmap file")?;
        temp_mmap
            .write_all(&bytes)
            .context("Failed to write mmap data")?;
        temp_mmap
            .as_file_mut()
            .sync_all()
            .context("Failed to sync Debian mmap index")?;
        // Capture the validated inode before publication. Reopening the path
        // could pair this native index with another writer's replacement.
        let mmap_index = DebianMmapIndex::from_file(temp_mmap.as_file())?;
        temp_mmap
            .persist(&mmap_path)
            .map_err(|error| error.error)
            .context("Failed to persist mmap file")?;
        *crate::core::sync::write_cache(&DEBIAN_MMAP_INDEX) = Some(mmap_index);

        // Build FST index for O(query_len) prefix searches
        // FST requires sorted input, so we need to sort packages by name
        let fst_path = paths::cache_dir().join("debian_index_v8.fst");
        let fst_build_start = std::time::Instant::now();

        let sorted_packages = sorted_fst_entries(
            index
                .name_to_idx
                .iter()
                .map(|(name, index)| (name.as_str(), *index as u64)),
        );

        // Build FST map: lowercased package name -> package index
        let mut fst_builder = fst::MapBuilder::memory();
        for (name, idx) in sorted_packages {
            fst_builder
                .insert(name.as_bytes(), idx)
                .with_context(|| format!("Failed to insert '{name}' into FST"))?;
        }

        let fst_bytes = fst_builder
            .into_inner()
            .context("Failed to build FST index")?;

        // Publish the complete mapping in one rename. Readers fingerprint
        // its contents rather than trusting separately published metadata.
        let mut temp_fst =
            NamedTempFile::new_in(parent).context("Failed to create temporary FST file")?;
        temp_fst
            .write_all(&fst_bytes)
            .context("Failed to write FST data")?;
        temp_fst
            .as_file_mut()
            .sync_all()
            .context("Failed to sync Debian FST index")?;
        temp_fst
            .persist(&fst_path)
            .map_err(|error| error.error)
            .context("Failed to persist FST file")?;

        tracing::debug!(
            "Built FST index with {} entries ({} bytes) in {:?}",
            index.packages.len(),
            fst_bytes.len(),
            fst_build_start.elapsed()
        );

        // Load the FST index
        if let Ok(fst_index) = FstIndex::open(&fst_path) {
            let mut fst_guard = crate::core::sync::write_cache(&DEBIAN_FST_INDEX);
            if fst_guard.is_some() {
                tracing::debug!("Replacing existing Debian FST index with updated version");
            }
            *fst_guard = Some(fst_index);
        }
    }

    let mut cache = crate::core::sync::write_cache(&DEBIAN_INDEX_CACHE);
    hydrate_index_cache(&mut cache, index, current_files);

    Ok(())
}

fn rebuild_package_index(files: &[PathBuf]) -> Result<DebianPackageIndex> {
    let packages = files
        .par_iter()
        .map(|path| parse_packages_file_sync(path))
        .collect::<Result<Vec<Vec<DebianPackage>>>>()?;
    let mut index = DebianPackageIndex::new();
    for package in packages.into_iter().flatten() {
        index.add_package(package);
    }
    index.updated_at = jiff::Timestamp::now().as_second();
    Ok(index)
}

fn disk_cache_is_fresh(cache_path: &Path, lists_dir: &Path) -> bool {
    let Ok(cache_mtime) = fs::metadata(cache_path).and_then(|metadata| metadata.modified()) else {
        return false;
    };
    // Deletions and renames can leave every surviving file older than the
    // cache. The directory timestamp records those namespace changes.
    let Ok(directory_mtime) = required_mtime(lists_dir) else {
        return false;
    };
    if directory_mtime > cache_mtime {
        return false;
    }
    let Ok(entries) = fs::read_dir(lists_dir) else {
        return false;
    };
    let mut found_package_list = false;
    for entry in entries {
        let Ok(entry) = entry else {
            return false;
        };
        let path = entry.path();
        let Some(filename) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !filename.contains("_Packages")
            || path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("diff"))
        {
            continue;
        }
        let Ok(package_mtime) = fs::metadata(&path).and_then(|metadata| metadata.modified()) else {
            return false;
        };
        found_package_list = true;
        if package_mtime > cache_mtime {
            return false;
        }
    }
    found_package_list
}

/// Load an optional FST only when its mapping matches the current mmap.
fn ensure_fst_loaded() {
    let fst_path = paths::cache_dir().join("debian_index_v8.fst");
    if !disk_cache_is_fresh(&fst_path, Path::new("/var/lib/apt/lists")) {
        *crate::core::sync::write_cache(&DEBIAN_FST_INDEX) = None;
        return;
    }

    // Always acquire mmap before FST when holding both locks.
    let mmap_guard = crate::core::sync::read_cache(&DEBIAN_MMAP_INDEX);
    let Some(mmap) = mmap_guard.as_ref() else {
        return;
    };
    {
        let guard = crate::core::sync::read_cache(&DEBIAN_FST_INDEX);
        if let Some(fst) = guard.as_ref()
            && !fst.is_expired()
            && fst.mapping == mmap.fst_mapping
        {
            fst.touch();
            return;
        }
    }
    let candidate = match FstIndex::open(&fst_path) {
        Ok(fst) if fst.mapping == mmap.fst_mapping => Some(fst),
        Ok(_) => None,
        Err(error) => {
            tracing::debug!(%error, "FST cache rejected; using regular search");
            None
        }
    };
    *crate::core::sync::write_cache(&DEBIAN_FST_INDEX) = candidate;
}

/// Ensure the mmap index is loaded from disk (if available).
///
/// Validates the archive and fingerprints its name mapping once on open,
/// without deserializing the full index. Subsequent accesses reuse the mapping.
#[must_use]
pub fn ensure_mmap_loaded() -> bool {
    let mmap_path = paths::cache_dir().join("debian_index_v8.mmap");
    if !disk_cache_is_fresh(&mmap_path, Path::new("/var/lib/apt/lists")) {
        *crate::core::sync::write_cache(&DEBIAN_MMAP_INDEX) = None;
        return false;
    }

    // Check if already loaded
    {
        let guard = crate::core::sync::read_cache(&DEBIAN_MMAP_INDEX);
        if let Some(ref mmap) = *guard {
            if mmap.is_expired() {
                drop(guard);
                let mut write_guard = crate::core::sync::write_cache(&DEBIAN_MMAP_INDEX);
                *write_guard = None;
            } else {
                mmap.touch();
                return true;
            }
        }
    }

    // Try to load from disk
    if let Ok(mmap_index) = DebianMmapIndex::open(&mmap_path) {
        let mut guard = crate::core::sync::write_cache(&DEBIAN_MMAP_INDEX);
        *guard = Some(mmap_index);
        tracing::debug!("Loaded mmap index from disk (zero-copy)");
        true
    } else {
        false
    }
}

fn parse_packages_file_sync(path: &Path) -> Result<Vec<DebianPackage>> {
    let component = extract_component_from_path(path);
    let suite = extract_suite_from_path(path);
    let source_key = extract_source_key_from_path(path);
    let content = read_packages_file_content(path)?;

    // Collect paragraph byte ranges first
    let double_newline_iter = memmem::find_iter(content.as_bytes(), b"\n\n");
    let mut paragraph_ranges = Vec::new();
    let mut start = 0;

    for end in double_newline_iter {
        if end > start {
            paragraph_ranges.push((start, end));
        }
        start = end + 2;
    }

    // Handle last paragraph
    if start < content.len() {
        paragraph_ranges.push((start, content.len()));
    }

    // Parse paragraphs in parallel for large files (>100 packages)
    let packages = if paragraph_ranges.len() > 100 {
        paragraph_ranges
            .par_iter()
            .map(|(start, end)| {
                parse_packages_paragraph(&content[*start..*end], &component, &suite, &source_key)
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        paragraph_ranges
            .iter()
            .map(|(start, end)| {
                parse_packages_paragraph(&content[*start..*end], &component, &suite, &source_key)
            })
            .collect::<Result<Vec<_>>>()?
    };

    Ok(packages.into_iter().flatten().collect())
}

fn parse_packages_paragraph(
    paragraph: &str,
    component: &str,
    suite: &str,
    source_key: &str,
) -> Result<Option<DebianPackage>> {
    if paragraph.trim().is_empty() {
        Ok(None)
    } else {
        parse_paragraph_str(paragraph, component, suite, source_key).map(Some)
    }
}

fn read_packages_file_content(path: &Path) -> Result<String> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::with_capacity(64 * 1024, file);

    let mut buf = String::new();
    if path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("lz4"))
    {
        let mut decoder = lz4_flex::frame::FrameDecoder::new(reader);
        decoder.read_to_string(&mut buf)?;
    } else if path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("gz"))
    {
        let mut decoder = flate2::read::GzDecoder::new(reader);
        decoder.read_to_string(&mut buf)?;
    } else if path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("xz"))
    {
        let mut decompressed = BudgetedWriter::new(Vec::new(), MAX_INDEX_SNAPSHOT_BYTES);
        decode_xz_to(&mut reader, &mut decompressed)?;
        buf = String::from_utf8(decompressed.into_inner())
            .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in xz-compressed Packages file: {e}"))?;
    } else {
        reader.read_to_string(&mut buf)?;
    }

    Ok(buf)
}

fn parse_minimal_package_info(paragraph: &str, expected_name: &str) -> Option<(String, String)> {
    let mut name_matches = false;
    let mut version = String::new();
    let mut description = String::new();
    let mut collecting_description = false;

    for line in paragraph.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if collecting_description {
                if !description.is_empty() {
                    description.push('\n');
                }
                description.push_str(line.trim_start());
            }
            continue;
        }

        let Some(colon_pos) = memchr::memchr(b':', line.as_bytes()) else {
            continue;
        };

        collecting_description = false;
        let key = &line[..colon_pos];
        let value = line[colon_pos + 1..].trim_start();

        match key.as_bytes() {
            b"Package" => {
                if value != expected_name {
                    return None;
                }
                name_matches = true;
            }
            b"Version" => version = value.to_string(),
            b"Description" => {
                description = value.to_string();
                collecting_description = true;
            }
            _ => {}
        }
    }

    if name_matches && !version.is_empty() {
        Some((version, description))
    } else {
        None
    }
}

fn extract_component_from_path(path: &Path) -> String {
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();

    if let Some(binary_pos) = filename.find("_binary-") {
        let prefix = &filename[..binary_pos];
        if let Some(component) = prefix.rsplit('_').next()
            && !component.is_empty()
        {
            return component.to_string();
        }
    }

    if let Some(stripped) = filename.strip_suffix("_Packages")
        && let Some((component, _)) = stripped.split_once('_')
        && !component.is_empty()
    {
        return component.to_string();
    }

    String::from("main")
}

/// Extract the distribution suite from a lists filename like
/// `deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages`.
/// Returns an empty string for flat layouts without a `_dists_` marker.
fn extract_suite_from_path(path: &Path) -> String {
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();

    filename
        .split("_dists_")
        .nth(1)
        .and_then(|rest| rest.split('_').next())
        .filter(|suite| !suite.is_empty())
        .unwrap_or_default()
        .to_string()
}

/// Apt prefixes lists files with an encoded repository host and base path.
/// Preserve that prefix so later URL resolution cannot select another mirror
/// merely because it publishes the same suite and component.
fn extract_source_key_from_path(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(|filename| filename.split_once("_dists_").map(|(source, _)| source))
        .unwrap_or_default()
        .to_string()
}

fn find_info_from_apt_lists_fast(name: &str) -> Result<Option<Package>> {
    let lists_dir = Path::new("/var/lib/apt/lists");
    if !lists_dir.exists() {
        return Ok(None);
    }

    let start_pattern = format!("Package: {name}\n");
    let mid_pattern = format!("\nPackage: {name}\n");

    let Ok(entries) = fs::read_dir(lists_dir) else {
        return Ok(None);
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let Some(filename) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        if !filename.contains("_Packages")
            || path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("diff"))
        {
            continue;
        }

        let Ok(content) = read_packages_file_content(&path) else {
            continue;
        };
        let bytes = content.as_bytes();

        let match_pos = if bytes.starts_with(start_pattern.as_bytes()) {
            Some(0usize)
        } else {
            memmem::find(bytes, mid_pattern.as_bytes()).map(|pos| pos + 1)
        };

        let Some(match_pos) = match_pos else {
            continue;
        };

        let mut paragraph_start = match_pos;
        while paragraph_start >= 2 {
            if bytes[paragraph_start - 2] == b'\n' && bytes[paragraph_start - 1] == b'\n' {
                break;
            }
            paragraph_start -= 1;
        }
        if paragraph_start < 2 {
            paragraph_start = 0;
        }

        let paragraph_end =
            memmem::find(&bytes[match_pos..], b"\n\n").map_or(bytes.len(), |rel| match_pos + rel);

        let paragraph = &content[paragraph_start..paragraph_end];
        if let Some((version, description)) = parse_minimal_package_info(paragraph, name) {
            return Ok(Some(Package {
                name: name.to_string(),
                version: parse_version_or_zero(&version),
                description,
                source: PackageSource::Official,
                installed: is_installed_fast(name)?,
            }));
        }
    }

    Ok(None)
}

fn append_dependencies(value: &str, dependencies: &mut Vec<String>) {
    dependencies.reserve(value.matches(',').count() + 1);
    for dependency in value.split(',') {
        let dependency = dependency.trim();
        if !dependency.is_empty() {
            dependencies.push(dependency.to_string());
        }
    }
}

#[inline]
fn parse_paragraph_str(
    paragraph: &str,
    component: &str,
    suite: &str,
    source_key: &str,
) -> Result<DebianPackage> {
    let mut name = String::new();
    let mut version = String::new();
    let mut description = String::with_capacity(128); // Pre-allocate for description
    let mut section = String::new();
    let mut priority = String::new();
    let mut installed_size = 0u64;
    let mut maintainer = String::new();
    let mut architecture = String::new();
    let mut depends = Vec::new();
    let mut filename = String::new();
    let mut size = 0u64;
    let mut sha256 = String::new();
    let mut homepage = String::new();
    let mut current_field = None;

    for line in paragraph.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            let value = line.trim_start();
            match current_field {
                Some("Description") if !description.is_empty() => {
                    description.push('\n');
                    if value != "." {
                        description.push_str(value);
                    }
                }
                Some("Depends" | "Pre-Depends") => append_dependencies(value, &mut depends),
                _ => {}
            }
            continue;
        }
        if line.is_empty() {
            continue;
        }

        let colon_pos = memchr::memchr(b':', line.as_bytes())
            .with_context(|| format!("Invalid deb822 field without a colon: {line}"))?;
        let key = &line[..colon_pos];
        let value = line[colon_pos + 1..].trim_start();
        current_field = Some(key);

        match key.as_bytes() {
            b"Package" => name = value.to_string(),
            b"Version" => version = value.to_string(),
            b"Description" => description = value.to_string(),
            b"Section" => section = value.to_string(),
            b"Priority" => priority = value.to_string(),
            b"Installed-Size" => {
                installed_size = value
                    .parse()
                    .with_context(|| format!("Invalid Installed-Size value: {value}"))?;
            }
            b"Maintainer" => maintainer = value.to_string(),
            b"Architecture" => architecture = value.to_string(),
            b"Depends" | b"Pre-Depends" => append_dependencies(value, &mut depends),
            b"Filename" => filename = value.to_string(),
            b"Size" => {
                size = value
                    .parse()
                    .with_context(|| format!("Invalid Size value: {value}"))?;
            }
            b"SHA256" => sha256 = value.to_string(),
            b"Homepage" => homepage = value.to_string(),
            _ => {}
        }
    }

    if name.is_empty() {
        anyhow::bail!("Invalid package entry: missing 'Package' field in Packages file");
    }
    Ok(DebianPackage {
        name,
        version,
        description,
        section,
        priority,
        installed_size,
        maintainer,
        architecture,
        depends,
        filename,
        size,
        sha256,
        homepage,
        component: component.to_string(),
        suite: suite.to_string(),
        source_key: source_key.to_string(),
    })
}

pub fn get_detailed_packages() -> Result<Vec<DebianPackage>> {
    if crate::core::paths::test_mode() {
        return Ok(vec![DebianPackage {
            name: "apt".to_string(),
            version: "2.6.1".to_string(),
            description: "Debian package manager".to_string(),
            section: "admin".to_string(),
            priority: "optional".to_string(),
            installed_size: 1024,
            maintainer: "Debian".to_string(),
            architecture: "amd64".to_string(),
            depends: vec![],
            filename: "pool/main/a/apt/apt_2.6.1_amd64.deb".to_string(),
            size: 500,
            sha256: "hash".to_string(),
            homepage: "https://debian.org".to_string(),
            component: "main".to_string(),
            suite: "bookworm".to_string(),
            source_key: "deb.debian.org_debian".to_string(),
        }]);
    }
    ensure_index_loaded()?;
    let guard = crate::core::sync::read_cache(&DEBIAN_INDEX_CACHE);
    let index = guard.index.as_ref().context(
        "Debian package index not loaded. Run 'omg sync' to refresh the package database",
    )?;
    Ok(index.packages.clone())
}

pub fn get_detailed_best_candidates() -> Result<Vec<DebianPackage>> {
    if crate::core::paths::test_mode() {
        return get_detailed_packages();
    }
    ensure_index_loaded()?;
    let guard = crate::core::sync::read_cache(&DEBIAN_INDEX_CACHE);
    let index = guard.index.as_ref().context(
        "Debian package index not loaded. Run 'omg sync' to refresh the package database",
    )?;
    Ok(index.best_candidates().into_iter().cloned().collect())
}

pub fn search_fast(query: &str) -> Result<Vec<Package>> {
    if crate::core::paths::test_mode() {
        return Ok(vec![Package {
            name: "apt".to_string(),
            version: parse_version_or_zero("2.6.1"),
            description: "Debian package manager".to_string(),
            source: PackageSource::Official,
            installed: true,
        }]);
    }

    // ULTRA-FAST PATH: FST + mmap (no index loading, no decompression)
    if !query.is_empty() && !query.contains(':') && ensure_mmap_loaded() {
        ensure_fst_loaded();
        let installed_set = installed_names()?;
        // Retain the exact checked pair through the search. Do not reacquire
        // either lock after validation, or reverse the mmap -> FST order.
        let mmap_guard = crate::core::sync::read_cache(&DEBIAN_MMAP_INDEX);
        let fst_guard = crate::core::sync::read_cache(&DEBIAN_FST_INDEX);
        if let Some(mmap) = mmap_guard.as_ref()
            && let Some(fst_index) = fst_guard.as_ref()
            && fst_index.mapping == mmap.fst_mapping
        {
            fst_index.touch();
            mmap.touch();
            return Ok(fst_mmap_search(
                &fst_index.map,
                mmap,
                &query.to_lowercase(),
                &installed_set,
            ));
        }
    }

    // Repository and installed inventories have independent freshness rules.
    ensure_index_loaded()?;
    let installed_set = installed_names()?;

    let guard = crate::core::sync::read_cache(&DEBIAN_INDEX_CACHE);
    let index = guard.index.as_ref().context(
        "Debian package index not loaded. Run 'omg sync' to refresh the package database",
    )?;

    if query.is_empty() {
        return Ok(index
            .packages
            .iter()
            .map(|pkg| package_with_installed_state(pkg, &installed_set))
            .collect());
    }

    // Fast path: check for exact package name match first
    if let Some(exact_pkg) = index.get_query(query) {
        return Ok(vec![package_with_installed_state(
            exact_pkg,
            &installed_set,
        )]);
    }

    let query_lower = query.to_lowercase();
    if query_lower != query
        && let Some(exact_pkg) = index.get_query(&query_lower)
    {
        return Ok(vec![package_with_installed_state(
            exact_pkg,
            &installed_set,
        )]);
    }

    // FST search with in-memory index
    let fst_guard = crate::core::sync::read_cache(&DEBIAN_FST_INDEX);
    if let Some(ref fst_index) = *fst_guard
        && guard.fst_mapping == Some(fst_index.mapping)
    {
        fst_index.touch();
        return Ok(fst_search(
            &fst_index.map,
            index,
            &query_lower,
            &installed_set,
        ));
    }
    drop(fst_guard);

    // Fallback: SIMD search
    Ok(simd_search_fallback(
        index,
        &query_lower,
        &guard.search_buffer,
        &guard.package_offsets,
        &installed_set,
    ))
}

/// FST-based search: `O(query_len)` prefix matching
/// Much faster than full buffer scan for common queries
#[inline]
fn fst_search(
    fst_map: &Map<AlignedVec>,
    index: &DebianPackageIndex,
    query_lower: &str,
    installed_set: &AHashSet<String>,
) -> Vec<Package> {
    let query_bytes = query_lower.as_bytes();

    // 1. Try exact match first (fastest - single lookup)
    if let Some(idx) = fst_map.get(query_bytes)
        && let Some(pkg) = index.packages.get(idx as usize)
    {
        return vec![package_with_installed_state(pkg, installed_set)];
    }

    // 2. Prefix search (very fast - early termination)
    let mut prefix_matches = Vec::with_capacity(100);
    let mut stream = fst_map.range().ge(query_bytes).into_stream();

    while let Some((name_bytes, idx)) = stream.next() {
        // Early exit when prefix no longer matches
        if !name_bytes.starts_with(query_bytes) {
            break;
        }

        if let Some(pkg) = index.packages.get(idx as usize) {
            prefix_matches.push(package_with_installed_state(pkg, installed_set));
        }

        if prefix_matches.len() >= 100 {
            break;
        }
    }

    // If we found prefix matches, return them
    if !prefix_matches.is_empty() {
        return prefix_matches;
    }

    // 3. Substring search fallback (slower but comprehensive)
    // Only do this if no prefix matches were found
    let finder = memmem::Finder::new(query_bytes);
    let mut substring_matches = Vec::with_capacity(100);

    let mut stream = fst_map.stream().into_stream();
    while let Some((name_bytes, idx)) = stream.next() {
        // Check if query appears anywhere in the name
        if finder.find(name_bytes).is_some() {
            if let Some(pkg) = index.packages.get(idx as usize) {
                substring_matches.push(package_with_installed_state(pkg, installed_set));
            }

            if substring_matches.len() >= 100 {
                break;
            }
        }
    }

    substring_matches
}

/// FST+mmap search: completely bypasses `ensure_index_loaded()`
/// Uses FST for name matching and mmap for zero-copy package details
#[inline]
fn fst_mmap_search(
    fst_map: &Map<AlignedVec>,
    mmap: &DebianMmapIndex,
    query_lower: &str,
    installed_set: &AHashSet<String>,
) -> Vec<Package> {
    let query_bytes = query_lower.as_bytes();

    // 1. Try exact match first
    if let Some(_idx) = fst_map.get(query_bytes)
        && let Ok(Some(pkg)) = mmap.get(query_lower)
    {
        return vec![archived_package_to_package(
            pkg,
            installed_set.contains(pkg.name.as_str()),
        )];
    }

    // 2. Prefix search
    let mut results = Vec::with_capacity(100);
    let mut stream = fst_map.range().ge(query_bytes).into_stream();

    while let Some((name_bytes, _idx)) = stream.next() {
        if !name_bytes.starts_with(query_bytes) {
            break;
        }
        if let Ok(name_str) = std::str::from_utf8(name_bytes)
            && let Ok(Some(pkg)) = mmap.get(name_str)
        {
            results.push(archived_package_to_package(
                pkg,
                installed_set.contains(pkg.name.as_str()),
            ));
        }
        if results.len() >= 100 {
            break;
        }
    }

    if !results.is_empty() {
        return results;
    }

    // 3. Substring search fallback
    let finder = memmem::Finder::new(query_bytes);
    let mut stream = fst_map.stream().into_stream();
    while let Some((name_bytes, _idx)) = stream.next() {
        if finder.find(name_bytes).is_some()
            && let Ok(name_str) = std::str::from_utf8(name_bytes)
            && let Ok(Some(pkg)) = mmap.get(name_str)
        {
            results.push(archived_package_to_package(
                pkg,
                installed_set.contains(pkg.name.as_str()),
            ));
        }
        if results.len() >= 100 {
            break;
        }
    }

    results
}

#[inline]
fn simd_search_fallback(
    index: &DebianPackageIndex,
    query_lower: &str,
    search_buffer: &[u8],
    package_offsets: &[usize],
    installed_set: &AHashSet<String>,
) -> Vec<Package> {
    let finder = memmem::Finder::new(query_lower.as_bytes());
    let mut exact_matches = Vec::with_capacity(4);
    let mut prefix_matches = Vec::with_capacity(32);
    let mut substring_matches = Vec::with_capacity(128);
    let mut seen_indices = AHashSet::new();

    for match_idx in finder.find_iter(search_buffer) {
        let pkg_idx = match package_offsets.binary_search(&match_idx) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };
        if seen_indices.insert(pkg_idx)
            && let Some(pkg) = index.packages.get(pkg_idx)
        {
            let package = package_with_installed_state(pkg, installed_set);

            // Categorize by match type for better relevance
            let name_lower = package.name.to_lowercase();
            if name_lower == query_lower {
                exact_matches.push(package);
            } else if name_lower.starts_with(query_lower) {
                prefix_matches.push(package);
            } else {
                substring_matches.push(package);
            }
        }
        if exact_matches.len() + prefix_matches.len() + substring_matches.len() >= 100 {
            break;
        }
    }

    // Return results in relevance order: exact > prefix > substring
    exact_matches.extend(prefix_matches);
    exact_matches.extend(substring_matches);
    exact_matches
}

pub fn get_info_fast(name: &str) -> Result<Option<Package>> {
    if crate::core::paths::test_mode() {
        return Ok(Some(Package {
            name: name.to_string(),
            version: parse_version_or_zero("1.0.0"),
            description: "Mock package".to_string(),
            source: PackageSource::Official,
            installed: true,
        }));
    }

    // ULTRA-FAST PATH: mmap O(1) lookup (no index loading needed)
    if ensure_mmap_loaded() {
        let mmap_guard = crate::core::sync::read_cache(&DEBIAN_MMAP_INDEX);
        if let Some(ref mmap) = *mmap_guard {
            mmap.touch();
            if let Ok(Some(pkg)) = mmap.get(name) {
                return Ok(Some(archived_package_to_package(
                    pkg,
                    is_installed_fast(pkg.name.as_str())?,
                )));
            }
            // Package not in mmap - still return None without loading full index
            return Ok(None);
        }
    }

    // Fallback: load full index
    if !name.contains(':')
        && let Some(pkg) = find_info_from_apt_lists_fast(name)?
    {
        return Ok(Some(pkg));
    }

    ensure_index_loaded()?;
    let installed_set = installed_names()?;
    let guard = crate::core::sync::read_cache(&DEBIAN_INDEX_CACHE);
    let index = guard.index.as_ref().context(
        "Debian package index not loaded. Run 'omg sync' to refresh the package database",
    )?;
    if let Some(pkg) = index.get_query(name) {
        Ok(Some(package_with_installed_state(pkg, &installed_set)))
    } else {
        Ok(None)
    }
}

/// One installed-package entry parsed from `/var/lib/dpkg/status`.
///
/// Distinct from [`crate::package_managers::types::LocalPackage`], which is
/// the normalized cross-backend view (parsed `Version`, install size).
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct DpkgPackageEntry {
    pub name: String,
    pub version: String,
    pub description: String,
    pub architecture: String,
    pub is_explicit: bool,
}

/// Parse a dpkg status paragraph into `DpkgPackageEntry` fields
#[inline]
fn parse_status_paragraph(paragraph: &str) -> Option<(String, String, String, String)> {
    let mut name = String::new();
    let mut version = String::new();
    let mut description = String::new();
    let mut arch = String::new();
    let mut current_field = None;

    for line in paragraph.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if current_field == Some("Description") && !description.is_empty() {
                let value = line.trim_start();
                description.push('\n');
                if value != "." {
                    description.push_str(value);
                }
            }
            continue;
        }
        let Some(colon_pos) = memchr::memchr(b':', line.as_bytes()) else {
            current_field = None;
            continue;
        };
        let key = &line[..colon_pos];
        let value = line[colon_pos + 1..].trim_start();
        current_field = Some(key);

        match key.as_bytes() {
            b"Package" => name = value.to_string(),
            b"Version" => version = value.to_string(),
            b"Description" => description = value.to_string(),
            b"Architecture" => arch = value.to_string(),
            _ => {}
        }
    }

    if name.is_empty() {
        None
    } else {
        Some((name, version, description, arch))
    }
}

/// Security exports read every installed stanza without a name-only cache or
/// silently dropping incomplete identities.
pub fn security_inventory() -> Result<Vec<crate::package_managers::types::SecurityPackage>> {
    parse_security_inventory(&fs::read_to_string("/var/lib/dpkg/status")?)
}

fn parse_security_inventory(
    contents: &str,
) -> Result<Vec<crate::package_managers::types::SecurityPackage>> {
    let mut packages = Vec::new();
    let mut identities = std::collections::BTreeSet::new();
    for paragraph in status_paragraphs(contents) {
        if paragraph.trim().is_empty() {
            continue;
        }
        let mut statuses = paragraph
            .lines()
            .filter_map(|line| line.strip_prefix("Status:"));
        let status = statuses.next().context("dpkg entry lacks Status")?;
        anyhow::ensure!(
            statuses.next().is_none(),
            "dpkg entry has duplicate Status fields"
        );
        let fields: Vec<_> = status.split_whitespace().collect();
        anyhow::ensure!(
            fields.len() == 3
                && matches!(
                    fields[0],
                    "install" | "hold" | "deinstall" | "purge" | "unknown"
                )
                && fields[1] == "ok",
            "Invalid or broken dpkg package status: {status}"
        );
        if matches!(fields[2], "not-installed" | "config-files") {
            continue;
        }
        anyhow::ensure!(
            fields[2] == "installed",
            "Incomplete dpkg package state: {status}"
        );
        for field in ["Package", "Version", "Architecture"] {
            let count = paragraph
                .lines()
                .filter_map(|line| line.split_once(':'))
                .filter(|(key, _)| key.eq_ignore_ascii_case(field))
                .count();
            anyhow::ensure!(
                count == 1,
                "Installed dpkg entry must contain exactly one {field} field"
            );
        }
        let (name, version, description, architecture) = parse_status_paragraph(paragraph)
            .context("Installed dpkg entry lacks a package name")?;
        anyhow::ensure!(
            !version.is_empty() && !architecture.is_empty(),
            "Installed dpkg entry '{name}' lacks version or architecture"
        );
        anyhow::ensure!(
            identities.insert((name.clone(), architecture.clone())),
            "Duplicate installed dpkg identity: {name}:{architecture}"
        );
        packages.push(crate::package_managers::types::SecurityPackage {
            name,
            version,
            description,
            architecture: Some(architecture),
            licenses: Vec::new(),
        });
    }
    Ok(packages)
}

#[cfg(test)]
mod security_inventory_tests {
    use super::parse_security_inventory;

    #[test]
    fn security_inventory_matches_native_dpkg_identities() {
        let output = crate::core::privilege::system_command("dpkg-query")
            .unwrap()
            .args([
                "--show",
                "--showformat=${Package}\t${Architecture}\t${Version}\t${db:Status-Status}\n",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let reference = String::from_utf8(output.stdout).unwrap();
        let mut expected: Vec<_> = reference
            .lines()
            .filter_map(|line| {
                let (identity, state) = line.rsplit_once('\t').expect("dpkg query row lacks state");
                (state == "installed").then(|| identity.to_owned())
            })
            .collect();
        let mut actual: Vec<_> = super::security_inventory()
            .unwrap()
            .into_iter()
            .map(|package| {
                format!(
                    "{}\t{}\t{}",
                    package.name,
                    package.architecture.unwrap(),
                    package.version
                )
            })
            .collect();
        expected.sort();
        actual.sort();
        assert!(
            !expected.is_empty(),
            "native dpkg fixture must contain installed packages"
        );
        assert_eq!(
            actual, expected,
            "security inventory changed native package identities"
        );
    }

    #[test]
    fn security_inventory_rejects_ambiguous_or_incomplete_package_states() {
        let entry =
            "Package: fixture\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n";
        for duplicate in [
            "Package: spoofed\n",
            "Version: 999\n",
            "Architecture: i386\n",
        ] {
            assert!(
                parse_security_inventory(&format!("{entry}{duplicate}")).is_err(),
                "duplicate identity accepted: {duplicate}"
            );
        }
        assert!(
            parse_security_inventory(&entry.replace("Status: install ok installed\n", "")).is_err()
        );
        for status in [
            "install ok unpacked",
            "install ok half-installed",
            "install ok half-configured",
            "install ok triggers-awaited",
            "install ok triggers-pending",
            "install reinstreq installed",
            "invalid ok installed",
            "install ok invented",
        ] {
            assert!(
                parse_security_inventory(&entry.replace("install ok installed", status)).is_err(),
                "{status}"
            );
        }
        assert!(
            parse_security_inventory(&entry.replace(
                "Status: install ok installed",
                "Status: install ok installed\nStatus: deinstall ok config-files"
            ))
            .is_err()
        );
        for selection in ["install", "hold", "deinstall", "purge", "unknown"] {
            assert_eq!(
                parse_security_inventory(
                    &entry.replace("install ok installed", &format!("{selection} ok installed"))
                )
                .unwrap()
                .len(),
                1
            );
        }
    }

    #[test]
    fn security_inventory_preserves_multiarch_epochs_and_refuses_partial_entries() {
        let first = "Package: libfixture\nStatus: install ok installed\nVersion: 2:1.0~rc1-3\nArchitecture: amd64\nDescription: first\n";
        let second = first.replace("amd64", "i386");
        let fixture = format!("{first}\n{second}");
        let packages = parse_security_inventory(&fixture).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(
            parse_security_inventory(&format!("{fixture}\n\n"))
                .unwrap()
                .len(),
            2
        );
        assert!(parse_security_inventory("\n\n").unwrap().is_empty());
        assert_eq!(packages[0].version, "2:1.0~rc1-3");
        assert_eq!(packages[1].architecture.as_deref(), Some("i386"));
        for missing in [
            "Package: libfixture\n",
            "Version: 2:1.0~rc1-3\n",
            "Architecture: amd64\n",
        ] {
            assert!(parse_security_inventory(&first.replace(missing, "")).is_err());
        }
        assert!(parse_security_inventory(&format!("{first}\n{first}")).is_err());
        assert!(
            parse_security_inventory(
                &first.replace("install ok installed", "deinstall ok config-files")
            )
            .unwrap()
            .is_empty()
        );
    }
}

pub fn list_installed_fast() -> Result<Vec<DpkgPackageEntry>> {
    if crate::core::paths::test_mode() {
        return Ok(vec![DpkgPackageEntry {
            name: "apt".to_string(),
            version: "2.6.1".to_string(),
            description: "Debian package manager".to_string(),
            architecture: "amd64".to_string(),
            is_explicit: true,
        }]);
    }

    let status_path = Path::new("/var/lib/dpkg/status");
    if !status_path.exists() {
        anyhow::bail!("dpkg status file not found: {}", status_path.display());
    }

    let extended_states_path = Path::new("/var/lib/apt/extended_states");

    let status_mtime = required_mtime(status_path)?;
    let extended_states_mtime = optional_mtime(extended_states_path)?;

    // Check cache first. Hits take the READ lock only: `last_accessed` is
    // atomic, and the returned Vec is cloned under the read guard.
    {
        let cache = crate::core::sync::read_cache(&DPKG_STATUS_CACHE);
        if !is_access_expired(cache.last_accessed.load(Ordering::Relaxed))
            && cache.status_mtime == status_mtime
            && cache.extended_states_mtime == extended_states_mtime
            && !cache.packages.is_empty()
        {
            // Cache hit! Update last accessed without writer contention.
            cache
                .last_accessed
                .store(unix_now_secs(), Ordering::Relaxed);
            return Ok(cache.packages.clone());
        }
    }

    // Cache miss - parse from disk
    let status_content = fs::read_to_string(status_path)?;

    // Fast parse of extended_states using memchr for line iteration
    let auto_installed = read_auto_installed_names(extended_states_path)?;

    // Pre-allocate for estimated package count
    let mut packages = Vec::with_capacity(status_content.len() / 300);
    let mut installed_set = AHashSet::new();

    for paragraph in status_paragraphs(&status_content) {
        if !status_paragraph_is_installed(paragraph) {
            continue;
        }

        if let Some((name, version, description, arch)) = parse_status_paragraph(paragraph) {
            let is_explicit = !auto_installed.contains(&name);
            installed_set.insert(name.clone());
            packages.push(DpkgPackageEntry {
                name,
                version,
                description,
                architecture: arch,
                is_explicit,
            });
        }
    }

    // Update cache
    {
        let mut cache = crate::core::sync::write_cache(&DPKG_STATUS_CACHE);
        // Clear stale entries when the TTL safety net has lapsed so the
        // unbounded-growth protection still applies on refresh paths.
        if is_access_expired(cache.last_accessed.load(Ordering::Relaxed)) {
            *cache = DpkgStatusCache::default();
        }
        cache.packages.clone_from(&packages);
        cache.installed_set = Arc::new(installed_set);
        cache.status_mtime = status_mtime;
        cache.extended_states_mtime = extended_states_mtime;
        cache
            .last_accessed
            .store(unix_now_secs(), Ordering::Relaxed);
    }

    Ok(packages)
}

/// Get info about an installed package from dpkg/status
#[inline]
pub fn get_installed_info_fast(name: &str) -> Result<Option<DpkgPackageEntry>> {
    if crate::core::paths::test_mode() {
        return Ok(Some(DpkgPackageEntry {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            description: "Mock package".to_string(),
            architecture: "amd64".to_string(),
            is_explicit: true,
        }));
    }

    // Ensure cache is populated
    list_installed_fast()?;

    let cache = crate::core::sync::read_cache(&DPKG_STATUS_CACHE);
    Ok(cache.packages.iter().find(|p| p.name == name).cloned())
}

#[inline]
pub fn is_installed_fast(name: &str) -> Result<bool> {
    if crate::core::paths::test_mode() {
        return Ok(matches!(name, "apt" | "git"));
    }

    // `installed_names` validates dpkg/status and extended_states mtimes plus
    // the cache TTL before answering. A hot lookup must not outlive a package
    // transaction performed by another process.
    installed_names()
        .map(|installed| installed.contains(name))
        .with_context(|| format!("failed to determine whether '{name}' is installed"))
}

pub fn list_explicit_fast() -> Result<Vec<String>> {
    if crate::core::paths::test_mode() {
        return Ok(vec!["apt".to_string(), "git".to_string()]);
    }
    let installed = list_installed_fast()?;
    Ok(installed
        .into_iter()
        .filter(|p| p.is_explicit)
        .map(|p| p.name)
        .collect())
}

/// Fast installed/explicit counts from the dpkg-status cache.
///
/// The orphan and update counts are **always `0`**: computing them requires
/// the full index and a reverse-dependency walk. Callers that must not
/// present zeros as real values should route through
/// [`crate::package_managers::debian_db::resolve_status_counts`] with an
/// accurate fallback (see `apt.rs::get_system_status`).
pub fn get_counts_fast() -> Result<(usize, usize, usize, usize)> {
    let installed = list_installed_fast()?;

    let total = installed.len();

    let explicit = installed.iter().filter(|p| p.is_explicit).count();

    Ok((total, explicit, 0, 0))
}

/// Cleanup expired memory-mapped indices to prevent resource leaks
///
/// Should be called periodically (e.g., every 30 minutes) to free 500MB+ mmaps
/// that haven't been accessed within the TTL window. This is a safety net for
/// long-running daemons that may accumulate stale mmap resources.
pub fn cleanup_expired_mmaps() {
    let mut mmap_guard = crate::core::sync::write_cache(&DEBIAN_MMAP_INDEX);

    if let Some(ref mmap) = *mmap_guard
        && mmap.is_expired()
    {
        let size = mmap.bytes.len();
        tracing::info!(
            "Cleaning up expired Debian mmap index (size: {} MB)",
            size / 1024 / 1024
        );
        *mmap_guard = None;
    }
}

/// Check if the mmap index is available (avoids loading full index into memory)
#[must_use]
pub fn is_mmap_available() -> bool {
    let guard = crate::core::sync::read_cache(&DEBIAN_MMAP_INDEX);
    guard.is_some()
}

/// Get updates using the mmap index with parallel version comparison.
///
/// This is the ultra-fast path that avoids loading the entire index into
/// memory: installed versions are compared against the mmap index with rayon.
#[expect(clippy::implicit_hasher)]
///
/// # Errors
/// Fails when the mmap index is not loaded (call [`ensure_mmap_loaded`]
/// first) or the archived index fails validation.
pub fn get_updates_from_mmap(
    installed_map: &std::collections::HashMap<String, &str>,
) -> Result<Vec<(String, String, String)>> {
    let mmap_guard = crate::core::sync::read_cache(&DEBIAN_MMAP_INDEX);
    let Some(ref mmap) = *mmap_guard else {
        anyhow::bail!("Mmap index not available");
    };

    mmap.touch(); // Update access time for TTL

    // Get zero-copy access to all packages
    let packages = mmap.packages()?;

    // Parallel version comparison using rayon
    let updates: Vec<(String, String, String)> = packages
        .par_iter()
        .filter_map(|pkg| {
            // Convert archived strings to &str using rkyv's archived string access
            let pkg_name: &str = pkg.name.as_str();
            let pkg_version: &str = pkg.version.as_str();

            let installed_ver = installed_version_for_arch(
                installed_map,
                pkg_name,
                pkg.architecture.as_str(),
                debian_arch(),
            )?;
            (crate::package_managers::types::compare_deb_versions(pkg_version, installed_ver)
                == std::cmp::Ordering::Greater)
                .then(|| {
                    (
                        pkg_name.to_string(),
                        (*installed_ver).to_string(),
                        pkg_version.to_string(),
                    )
                })
        })
        .collect();

    Ok(best_update_versions(updates))
}

pub(crate) fn best_update_versions(
    updates: impl IntoIterator<Item = (String, String, String)>,
) -> Vec<(String, String, String)> {
    let mut best = HashMap::<String, (String, String)>::new();
    for (name, old_version, new_version) in updates {
        let replace = best.get(&name).is_none_or(|(_, existing_new)| {
            crate::package_managers::types::compare_deb_versions(&new_version, existing_new)
                == std::cmp::Ordering::Greater
        });
        if replace {
            best.insert(name, (old_version, new_version));
        }
    }
    let mut updates: Vec<_> = best
        .into_iter()
        .map(|(name, (old_version, new_version))| (name, old_version, new_version))
        .collect();
    updates.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    updates
}

fn status_paragraph_is_installed(paragraph: &str) -> bool {
    let Some(status) = paragraph
        .lines()
        .find_map(|line| line.strip_prefix("Status:"))
    else {
        return false;
    };
    let mut fields = status.split_whitespace();
    fields.next().is_some()
        && fields.next() == Some("ok")
        && fields.next() == Some("installed")
        && fields.next().is_none()
}

pub(crate) fn installed_version_for_arch<'a>(
    installed_map: &'a std::collections::HashMap<String, &'a str>,
    package_name: &str,
    available_arch: &str,
    host_arch: &str,
) -> Option<&'a str> {
    if available_arch != host_arch && available_arch != "all" {
        return None;
    }

    let exact_key = format!("{package_name}:{available_arch}");
    installed_map.get(&exact_key).copied().or_else(|| {
        (available_arch == "all")
            .then(|| installed_map.get(&format!("{package_name}:{host_arch}")))
            .flatten()
            .copied()
    })
}

/// Split a dpkg-style control file into paragraphs separated by blank lines.
/// The final paragraph needs no trailing blank line.
fn status_paragraphs(content: &str) -> impl Iterator<Item = &str> {
    content.split("\n\n")
}

fn dependencies_from_status(content: &str, package_name: &str) -> (Vec<String>, Vec<String>) {
    let mut dependencies = Vec::new();
    let mut reverse_deps = Vec::new();

    for paragraph in status_paragraphs(content) {
        if !status_paragraph_is_installed(paragraph) {
            continue;
        }

        let mut current_pkg = String::new();
        let mut current_deps = Vec::new();

        for line in paragraph.lines() {
            if let Some(pkg) = line.strip_prefix("Package: ") {
                current_pkg = pkg.trim().to_string();
            } else if let Some(deps_str) = line
                .strip_prefix("Depends: ")
                .or_else(|| line.strip_prefix("Pre-Depends: "))
            {
                append_dependency_names(deps_str, &mut current_deps);
            }
        }

        if current_pkg == package_name {
            dependencies = current_deps;
        } else if !current_pkg.is_empty() && current_deps.iter().any(|dep| dep == package_name) {
            reverse_deps.push(current_pkg);
        }
    }

    (dependencies, reverse_deps)
}

/// Extract dependency package names from a `Depends:`/`Pre-Depends:` value,
/// stripping version constraints and multi-arch qualifiers and taking the
/// first alternative of `|` groups.
fn append_dependency_names(value: &str, out: &mut Vec<String>) {
    for dep in value.split(',') {
        let dep = dep.split('|').next().unwrap_or("");
        if let Some(dep_name) = dep.split_whitespace().next() {
            let dep_name = dep_name.split(':').next().unwrap_or(dep_name);
            if !dep_name.is_empty() {
                out.push(dep_name.to_string());
            }
        }
    }
}

/// Get package dependencies from `/var/lib/dpkg/status`.
///
/// Returns `(dependencies, reverse_dependencies)` for the specified package.
///
/// # Errors
pub fn get_package_dependencies(package_name: &str) -> Result<(Vec<String>, Vec<String>)> {
    if crate::core::paths::test_mode() {
        return Ok((vec!["libc6".to_string()], vec![]));
    }

    let status_path = Path::new("/var/lib/dpkg/status");
    if !status_path.exists() {
        anyhow::bail!("dpkg status file not found: {}", status_path.display());
    }

    let content = fs::read_to_string(status_path)?;
    Ok(dependencies_from_status(&content, package_name))
}

/// Installed-Size is recorded in KiB; convert to bytes with overflow checks.
fn status_size_bytes(size_str: &str, package_name: &str) -> Result<i64> {
    size_str
        .trim()
        .parse::<i64>()
        .with_context(|| format!("invalid Installed-Size for {package_name}: {size_str}"))?
        .checked_mul(1024)
        .with_context(|| format!("Installed-Size overflow for {package_name}: {size_str}"))
}

fn package_size_from_status(content: &str, package_name: &str) -> Result<Option<i64>> {
    for paragraph in status_paragraphs(content) {
        if !status_paragraph_is_installed(paragraph) {
            continue;
        }
        let mut in_package = false;
        for line in paragraph.lines() {
            if let Some(pkg) = line.strip_prefix("Package: ") {
                in_package = pkg.trim() == package_name;
            } else if in_package && let Some(size_str) = line.strip_prefix("Installed-Size: ") {
                return Ok(Some(status_size_bytes(size_str, package_name)?));
            }
        }
    }

    Ok(None)
}

fn packages_with_sizes_from_status(content: &str) -> Result<Vec<(String, i64)>> {
    let mut results = Vec::new();

    for paragraph in status_paragraphs(content) {
        if !status_paragraph_is_installed(paragraph) {
            continue;
        }
        let mut current_pkg = String::new();
        let mut current_size: i64 = 0;

        for line in paragraph.lines() {
            if let Some(pkg) = line.strip_prefix("Package: ") {
                current_pkg = pkg.trim().to_string();
            } else if let Some(size_str) = line.strip_prefix("Installed-Size: ") {
                current_size = status_size_bytes(size_str, &current_pkg)?;
            }
        }

        if !current_pkg.is_empty() && current_size > 0 {
            results.push((current_pkg, current_size));
        }
    }

    Ok(results)
}

/// Get package size from `/var/lib/dpkg/status`.
/// Returns `Ok(None)` if the package is not present.
pub fn get_package_size(package_name: &str) -> Result<Option<i64>> {
    if crate::core::paths::test_mode() {
        return Ok(Some(1024 * 1024));
    }

    let status_path = Path::new("/var/lib/dpkg/status");
    if !status_path.exists() {
        anyhow::bail!("dpkg status file not found: {}", status_path.display());
    }

    let content = fs::read_to_string(status_path)?;
    package_size_from_status(&content, package_name)
}

/// Get all packages with their sizes from `/var/lib/dpkg/status`
/// Returns `Vec<(package_name, size_in_bytes)>`
pub fn get_all_packages_with_sizes() -> Result<Vec<(String, i64)>> {
    if crate::core::paths::test_mode() {
        return Ok(vec![
            ("apt".to_string(), 4 * 1024 * 1024),
            ("vim".to_string(), 3 * 1024 * 1024),
        ]);
    }

    let status_path = Path::new("/var/lib/dpkg/status");
    if !status_path.exists() {
        anyhow::bail!("dpkg status file not found: {}", status_path.display());
    }

    let content = fs::read_to_string(status_path)?;
    packages_with_sizes_from_status(&content)
}

/// Get package version from /var/lib/dpkg/status
/// Returns None if the package is not installed
pub fn get_package_version(package_name: &str) -> Result<Option<String>> {
    if crate::core::paths::test_mode() {
        return Ok(Some("1.0.0".to_string()));
    }

    let status_path = Path::new("/var/lib/dpkg/status");
    if !status_path.exists() {
        anyhow::bail!("dpkg status file not found: {}", status_path.display());
    }

    let content = fs::read_to_string(status_path)?;
    Ok(installed_version_from_status(&content, package_name))
}

fn installed_version_from_status(content: &str, package_name: &str) -> Option<String> {
    status_paragraphs(content)
        .filter(|paragraph| status_paragraph_is_installed(paragraph))
        .find_map(|paragraph| {
            let name = paragraph
                .lines()
                .find_map(|line| line.strip_prefix("Package: "))?
                .trim();
            (name == package_name).then(|| {
                paragraph
                    .lines()
                    .find_map(|line| line.strip_prefix("Version: "))
                    .map(str::trim)
                    .map(str::to_string)
            })?
        })
}

/// Load APT Auto-Installed names from `extended_states`.
///
/// A missing file is an empty set (no auto-install tracking), matching APT.
/// An unreadable existing file is an error so auto-installed packages are not hidden.
fn read_auto_installed_names(path: &Path) -> Result<AHashSet<String>> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(auto_installed_names_from_extended_states(&content)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(AHashSet::new()),
        Err(error) => Err(error)
            .with_context(|| format!("Failed to read APT extended_states {}", path.display())),
    }
}

fn auto_installed_names_from_extended_states(content: &str) -> AHashSet<String> {
    let mut auto_installed = AHashSet::new();
    let mut current_pkg = String::new();
    for line in content.lines() {
        if let Some(name) = line.strip_prefix("Package: ") {
            current_pkg = name.trim().to_string();
        } else if line.starts_with("Auto-Installed: 1") && !current_pkg.is_empty() {
            auto_installed.insert(std::mem::take(&mut current_pkg));
        }
    }
    auto_installed
}

/// Check if package is auto-installed (dependency) from `/var/lib/apt/extended_states`
/// Returns `true` if auto-installed, `false` if explicitly installed
pub fn is_package_auto_installed(package_name: &str) -> Result<bool> {
    if crate::core::paths::test_mode() {
        return Ok(false);
    }

    let auto_installed = read_auto_installed_names(Path::new("/var/lib/apt/extended_states"))?;
    Ok(auto_installed.contains(package_name))
}

/// List orphaned packages on Debian/Ubuntu systems
///
/// An orphan is a package that:
/// - Was automatically installed (as a dependency)
/// - Is no longer required by any manually-installed package
///
/// This function uses a simpler but effective approach:
/// 1. Get all installed packages
/// 2. Get auto-installed set from `/var/lib/apt/extended_states`
/// 3. Recursively get all dependencies of manually-installed packages
/// 4. Orphans = auto-installed packages NOT in the dependency set
pub fn list_orphans_fast() -> Result<Vec<String>> {
    if crate::core::paths::test_mode() {
        return Ok(vec!["libunused1".to_string()]);
    }

    // Get all installed packages with their auto-install status
    let installed = list_installed_fast()?;

    // Split into auto-installed and manually-installed
    let auto_installed: AHashSet<String> = installed
        .iter()
        .filter(|p| !p.is_explicit)
        .map(|p| p.name.clone())
        .collect();

    let manual_packages: Vec<String> = installed
        .iter()
        .filter(|p| p.is_explicit)
        .map(|p| p.name.clone())
        .collect();

    // Build the set of all packages required (directly or transitively) by manual packages
    let mut required_set = AHashSet::new();
    let mut to_visit = manual_packages;

    // Parse dpkg/status once to build a dependency map
    let dep_map = build_dependency_map()?;

    while let Some(pkg_name) = to_visit.pop() {
        if !required_set.insert(pkg_name.clone()) {
            continue; // Already visited
        }

        // Add all dependencies of this package to visit queue
        if let Some(deps) = dep_map.get(&pkg_name) {
            for dep in deps {
                if !required_set.contains(dep) {
                    to_visit.push(dep.clone());
                }
            }
        }
    }

    // Orphans are auto-installed packages that are NOT required by any manual package
    let orphans: Vec<String> = auto_installed
        .into_iter()
        .filter(|pkg| !required_set.contains(pkg))
        .collect();

    Ok(orphans)
}

/// Build a dependency map from all installed packages
/// Returns `HashMap<package_name, Vec<dependency_names>>`
fn build_dependency_map() -> Result<HashMap<String, Vec<String>>> {
    let status_path = Path::new("/var/lib/dpkg/status");
    if !status_path.exists() {
        anyhow::bail!("dpkg status file not found: {}", status_path.display());
    }

    let content = fs::read_to_string(status_path)?;
    Ok(dependency_map_from_status(&content))
}

fn dependency_map_from_status(content: &str) -> HashMap<String, Vec<String>> {
    let mut dep_map = HashMap::new();

    for paragraph in status_paragraphs(content) {
        let mut current_pkg = String::new();
        let mut current_deps: Vec<String> = Vec::new();
        for line in paragraph.lines() {
            if let Some(pkg) = line.strip_prefix("Package: ") {
                current_pkg = pkg.trim().to_string();
            } else if let Some(deps_str) = line
                .strip_prefix("Depends: ")
                .or_else(|| line.strip_prefix("Pre-Depends: "))
            {
                append_dependency_names(deps_str, &mut current_deps);
            }
        }

        if status_paragraph_is_installed(paragraph)
            && !current_pkg.is_empty()
            && !current_deps.is_empty()
        {
            dep_map.insert(current_pkg, current_deps);
        }
    }

    dep_map
}

/// Clean the APT package cache at `/var/cache/apt/archives/`
///
/// Removes all `.deb` files from:
/// - `/var/cache/apt/archives/`
/// - `/var/cache/apt/archives/partial/`
///
/// Returns `(files_removed, bytes_freed)`
pub fn clean_package_cache() -> Result<(usize, u64)> {
    if crate::core::paths::test_mode() {
        return Ok((5, 50_000_000)); // 5 files, 50 MB
    }

    let cache_dir = Path::new("/var/cache/apt/archives");
    let (removed_main, freed_main) = remove_deb_files(cache_dir)?;
    let (removed_partial, freed_partial) = remove_deb_files(&cache_dir.join("partial"))?;
    Ok((removed_main + removed_partial, freed_main + freed_partial))
}

fn remove_deb_files(dir: &Path) -> Result<(usize, u64)> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0)),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Failed to read APT cache directory {}", dir.display()));
        }
    };

    let mut removed = 0;
    let mut freed = 0u64;
    for entry in entries {
        let path = entry
            .with_context(|| format!("Failed to read APT cache directory {}", dir.display()))?
            .path();
        let Some(filename) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !filename
            .rsplit_once('.')
            .is_some_and(|(_, ext)| ext.eq_ignore_ascii_case("deb"))
        {
            continue;
        }
        let meta = fs::symlink_metadata(&path)
            .with_context(|| format!("Failed to inspect APT cache entry {}", path.display()))?;
        if !meta.file_type().is_file() && !meta.file_type().is_symlink() {
            continue;
        }
        fs::remove_file(&path)
            .with_context(|| format!("Failed to remove APT cache file {}", path.display()))?;
        freed += meta.len();
        removed += 1;
    }
    Ok((removed, freed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write as _;

    #[test]
    fn index_snapshot_enforces_byte_budget() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("index");
        fs::write(&path, b"abc")?;
        assert_eq!(read_index_snapshot(&path, 3)?.as_slice(), b"abc");
        assert!(read_index_snapshot(&path, 2).is_err());
        File::create(&path)?.set_len(MAX_INDEX_SNAPSHOT_BYTES + 1)?;
        let error = DebianMmapIndex::open(&path)
            .err()
            .expect("oversized index rejected");
        assert!(error.to_string().contains("exceeds"));
        Ok(())
    }

    #[test]
    fn index_snapshot_rejects_symlinks_and_special_files() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let target = directory.path().join("target");
        let link = directory.path().join("link");
        fs::write(&target, b"unchanged")?;
        std::os::unix::fs::symlink(&target, &link)?;
        assert!(read_index_snapshot(&link, 64).is_err());
        assert_eq!(fs::read(&target)?, b"unchanged");
        assert!(read_index_snapshot(directory.path(), 64).is_err());
        let fifo = directory.path().join("fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU)?;
        assert!(read_index_snapshot(&fifo, 64).is_err());
        Ok(())
    }

    #[test]
    fn package_snapshot_survives_external_overwrite_and_truncation() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("index.mmap");
        let mut source = DebianPackageIndex::new();
        source.updated_at = 41;
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&source)?;
        fs::write(&path, &bytes)?;
        let mut writer = fs::OpenOptions::new().write(true).open(&path)?;
        let index = DebianMmapIndex::open(&path)?;
        assert_eq!(index.generation(), 41);

        source.updated_at = 42;
        let replacement = rkyv::to_bytes::<rkyv::rancor::Error>(&source)?;
        assert_eq!(bytes.len(), replacement.len());
        writer.write_all(&replacement)?;
        assert_eq!(index.generation(), 41);
        assert_eq!(DebianMmapIndex::open(&path)?.generation(), 42);
        writer.set_len(0)?;
        assert_eq!(index.generation(), 41);
        assert!(index.packages()?.is_empty());
        assert!(DebianMmapIndex::open(&path).is_err());
        Ok(())
    }

    #[test]
    fn fst_snapshot_survives_external_overwrite_and_truncation() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("index.fst");
        let bytes = Map::from_iter([("demo", 1)])?.into_fst().into_inner();
        let replacement = Map::from_iter([("demo", 2)])?.into_fst().into_inner();
        assert_eq!(bytes.len(), replacement.len());
        fs::write(&path, &bytes)?;
        fs::write(path.with_added_extension("gen"), b"41")?;
        let mut writer = fs::OpenOptions::new().write(true).open(&path)?;
        let index = FstIndex::open(&path)?;
        assert_eq!(index.map.get("demo"), Some(1));

        writer.write_all(&replacement)?;
        assert_eq!(index.map.get("demo"), Some(1));
        assert_eq!(FstIndex::open(&path)?.map.get("demo"), Some(2));
        writer.set_len(0)?;
        assert_eq!(index.map.get("demo"), Some(1));
        assert!(FstIndex::open(&path).is_err());
        Ok(())
    }

    #[test]
    fn fst_rejects_different_mapping_with_the_same_timestamp() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let fst_path = directory.path().join("index.fst");
        let mut builder = fst::MapBuilder::memory();
        builder.insert("bash", 0)?;
        builder.insert("zsh", 1)?;
        fs::write(&fst_path, builder.into_inner()?)?;
        fs::write(directory.path().join("index.fst.gen"), b"42")?;
        let fst = FstIndex::open(&fst_path)?;

        let mut index = DebianPackageIndex::new();
        index.updated_at = 42;
        for name in ["zsh", "bash"] {
            index.add_package(parse_paragraph_str(
                &format!("Package: {name}\nVersion: 1\nArchitecture: amd64\nDescription: shell\n"),
                "main",
                "stable",
                "fixture",
            )?);
        }
        let mmap_path = directory.path().join("index.mmap");
        fs::write(
            &mmap_path,
            rkyv::to_bytes::<rkyv::rancor::Error>(&index)
                .map_err(|error| anyhow::anyhow!("fixture serialization: {error}"))?,
        )?;
        let mapped = DebianMmapIndex::open(&mmap_path)?;
        let unchecked = fst_search(&fst.map, &index, "ba", &AHashSet::new());
        assert_eq!(
            unchecked.first().context("unchecked prefix lookup")?.name,
            "zsh",
            "the old timestamp guard admitted the wrong row for a native prefix lookup"
        );
        // The mmap helper re-resolves names rather than trusting row numbers;
        // unchanged name sets do not misroute its exact lookup.
        let mmap_exact = fst_mmap_search(&fst.map, &mapped, "bash", &AHashSet::new());
        assert_eq!(
            mmap_exact.first().context("mmap exact lookup")?.name,
            "bash"
        );
        assert_ne!(
            fst.mapping, mapped.fst_mapping,
            "same-second indexes with different mappings must not pair"
        );
        let mut cache = DebianIndexCache::default();
        hydrate_index_cache(&mut cache, index, HashMap::new());
        assert_eq!(cache.fst_mapping, Some(mapped.fst_mapping));

        let mut replacement = fst::MapBuilder::memory();
        replacement.insert("bash", 1)?;
        replacement.insert("zsh", 0)?;
        crate::core::safe_ops::atomic_write_file_sync(&fst_path, replacement.into_inner()?)?;
        let current = FstIndex::open(&fst_path)?;
        assert_eq!(current.mapping, mapped.fst_mapping);
        assert_ne!(
            fst.mapping, current.mapping,
            "an open old inode keeps its own identity"
        );
        assert_eq!(fst.map.get("bash"), Some(0));
        let results = fst_mmap_search(&current.map, &mapped, "bash", &AHashSet::new());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "bash");
        let prefix = fst_search(
            &current.map,
            cache.index.as_ref().context("native index")?,
            "ba",
            &AHashSet::new(),
        );
        assert_eq!(
            prefix.first().context("validated prefix lookup")?.name,
            "bash"
        );
        Ok(())
    }

    #[test]
    fn fst_identity_ignores_sidecars_and_rejects_corrupt_contents() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("index.fst");
        let mut builder = fst::MapBuilder::memory();
        builder.insert("bash", 0)?;
        let mut bytes = builder.into_inner()?;
        fs::write(&path, &bytes)?;
        let index = FstIndex::open(&path)?;
        assert_eq!(index.mapping, FstMappingId::from_names([("bash", 0)]));
        fs::write(
            directory.path().join("index.fst.gen"),
            b"untrusted old generation",
        )?;
        assert_eq!(FstIndex::open(&path)?.mapping, index.mapping);
        *bytes.last_mut().context("FST checksum")? ^= 1;
        let corrupt = directory.path().join("corrupt.fst");
        fs::write(&corrupt, bytes)?;
        assert!(FstIndex::open(&corrupt).is_err());
        Ok(())
    }

    #[test]
    fn fst_identity_preserves_case_collision_policy_and_ignores_input_order() {
        let names = [("Bash", 0), ("bash", 1), ("Zsh", 2)];
        let expected = FstMappingId::from_names([("bash", 1), ("zsh", 2)]);
        assert_eq!(FstMappingId::from_names(names), expected);
        assert_eq!(FstMappingId::from_names(names.into_iter().rev()), expected);
        assert_ne!(
            FstMappingId::from_names([("bash", 0), ("zsh", 2)]),
            expected
        );
    }

    /// Serializes every test that mutates process-global `OMG_TEST_MODE`;
    /// env vars are shared by all parallel test threads.
    static ENV_LOCK: LazyLock<std::sync::Mutex<()>> = LazyLock::new(|| std::sync::Mutex::new(()));

    /// Application-cold readers, warm OS page cache; not a disk-cold benchmark.
    /// Uses owned buffers; earlier mmap measurements do not describe this reader.
    #[test]
    #[ignore = "bounded synthetic benchmark; run optimized with --ignored --nocapture"]
    fn snapshot_load_benchmark() -> Result<()> {
        for count in [10_000, 50_000] {
            let directory = tempfile::tempdir()?;
            let mut index = DebianPackageIndex::new();
            index.updated_at = 42;
            let description = "Synthetic package metadata for snapshot loading. ".repeat(6);
            for number in 0..count {
                index.add_package(parse_paragraph_str(&format!(
                    "Package: fixture-{number:06}\nVersion: 1.2.3-1\nArchitecture: amd64\nDescription: {description}\nDepends: libc6 (>= 2.34), libgcc-s1, zlib1g\nFilename: pool/main/f/fixture-{number:06}.deb\nInstalled-Size: 1024\nSize: 524288\n",
                ), "main", "stable", "fixture")?);
            }
            let raw = rkyv::to_bytes::<rkyv::rancor::Error>(&index)?;
            let mut compressed = b"ODXI".to_vec();
            compressed.extend_from_slice(&2_u32.to_le_bytes());
            compressed.extend_from_slice(&lz4_flex::compress_prepend_size(&raw));
            let mmap_path = directory.path().join("index.mmap");
            let legacy_path = directory.path().join("index.lz4");
            fs::write(&mmap_path, &raw)?;
            fs::write(&legacy_path, &compressed)?;
            let raw_bytes = raw.len();
            let compressed_bytes = compressed.len();
            drop((raw, compressed, index));

            let measure = |legacy: bool| -> Result<u128> {
                let start = std::time::Instant::now();
                let (index, mapped) = if legacy {
                    // Compare redundant LZ4 decoding plus an owned archive
                    // snapshot against deriving both views from one snapshot.
                    let index = {
                        let framed = fs::read(&legacy_path)?;
                        anyhow::ensure!(
                            framed.get(..8) == Some(b"ODXI\x02\x00\x00\x00"),
                            "fixture header"
                        );
                        let bytes = lz4_flex::decompress_size_prepended(&framed[8..])?;
                        rkyv::from_bytes::<DebianPackageIndex, rkyv::rancor::Error>(&bytes)?
                    };
                    let mapped = DebianMmapIndex::open(&mmap_path)?;
                    anyhow::ensure!(
                        mapped.generation() == index.updated_at,
                        "fixture generation"
                    );
                    (index, mapped)
                } else {
                    let mapped = DebianMmapIndex::open(&mmap_path)?;
                    (mapped.deserialize()?, mapped)
                };
                assert_eq!(index.packages.len(), count);
                assert_eq!(
                    index
                        .get("fixture-000000")
                        .context("fixture lookup")?
                        .version,
                    "1.2.3-1"
                );
                let mut cache = DebianIndexCache::default();
                hydrate_index_cache(&mut cache, index, HashMap::new());
                // Include destruction in both timings; prevent dead-code removal.
                drop(std::hint::black_box((cache, mapped)));
                Ok(start.elapsed().as_micros())
            };
            measure(true)?;
            measure(false)?;
            let mut legacy_us = Vec::new();
            let mut snapshot_us = Vec::new();
            for sample in 0..7 {
                if sample % 2 == 0 {
                    legacy_us.push(measure(true)?);
                    snapshot_us.push(measure(false)?);
                } else {
                    snapshot_us.push(measure(false)?);
                    legacy_us.push(measure(true)?);
                }
            }
            println!(
                "SNAPSHOT_BENCH {}",
                serde_json::json!({
                    "packages": count, "raw_bytes": raw_bytes, "compressed_bytes": compressed_bytes,
                    "legacy_us": legacy_us, "snapshot_us": snapshot_us,
                    "cache_state": "fresh readers; warm OS page cache; one warmup per path",
                    "storage": "owned bounded buffers; not mmap",
                })
            );
        }
        Ok(())
    }

    #[test]
    fn native_and_mmap_views_use_the_same_snapshot() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut index = DebianPackageIndex::new();
        index.updated_at = 42;
        index.add_package(parse_paragraph_str(
            "Package: demo\nVersion: 1\nArchitecture: amd64\nDescription: fixture\n",
            "main",
            "stable",
            "fixture",
        )?);
        let old_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&index)?;
        let mut legacy = b"ODXI".to_vec();
        legacy.extend_from_slice(&2_u32.to_le_bytes());
        legacy.extend_from_slice(&lz4_flex::compress_prepend_size(&old_bytes));
        let legacy_path = directory.path().join("debian_index_v8.lz4");
        fs::write(&legacy_path, &legacy)?;
        index.packages[0].version = "2".to_string();
        let path = directory.path().join("debian_index_v8.mmap");
        let mut pending = tempfile::NamedTempFile::new_in(directory.path())?;
        std::io::Write::write_all(
            pending.as_file_mut(),
            &rkyv::to_bytes::<rkyv::rancor::Error>(&index)?,
        )?;
        pending.as_file().sync_all()?;
        let mapped = DebianMmapIndex::from_file(pending.as_file())?;
        pending.persist(&path)?;
        let native = mapped.deserialize()?;
        assert_eq!(native.updated_at, mapped.generation());
        assert_eq!(
            native.get("demo").context("native package")?.version,
            mapped
                .get("demo")?
                .context("mapped package")?
                .version
                .as_str(),
            "equal timestamps cannot justify combining different metadata snapshots"
        );
        assert_eq!(native.get("demo").context("native package")?.version, "2");
        index.packages[0].version = "3".to_string();
        crate::core::safe_ops::atomic_write_file_sync(
            &path,
            rkyv::to_bytes::<rkyv::rancor::Error>(&index)?,
        )?;
        let replacement = DebianMmapIndex::open(&path)?;
        assert_eq!(
            replacement
                .deserialize()?
                .get("demo")
                .context("replacement package")?
                .version,
            "3"
        );
        assert_eq!(
            mapped
                .deserialize()?
                .get("demo")
                .context("retained package")?
                .version,
            "2"
        );
        assert_eq!(
            fs::read(&legacy_path)?,
            legacy,
            "legacy duplicates remain untouched"
        );
        Ok(())
    }

    #[test]
    fn mapped_index_snapshot_round_trips_to_native() -> Result<()> {
        let mut index = DebianPackageIndex::new();
        index.add_package(DebianPackage {
            name: "demo".to_string(),
            version: "1.0".to_string(),
            description: String::new(),
            section: String::new(),
            priority: String::new(),
            installed_size: 0,
            maintainer: String::new(),
            architecture: debian_arch().to_string(),
            depends: Vec::new(),
            filename: String::new(),
            size: 0,
            sha256: String::new(),
            homepage: String::new(),
            component: "main".to_string(),
            suite: "stable".to_string(),
            source_key: "deb.example_debian".to_string(),
        });
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("index.mmap");
        fs::write(&path, rkyv::to_bytes::<rkyv::rancor::Error>(&index)?)?;
        let decoded = DebianMmapIndex::open(&path)?.deserialize()?;
        assert_eq!(
            decoded.get("demo").map(|package| package.version.as_str()),
            Some("1.0")
        );
        Ok(())
    }

    #[test]
    fn non_archive_inputs_are_rejected_by_snapshot_reader() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("index.mmap");
        for bytes in [
            b"short".as_slice(),
            b"NOPE\x01\x00\x00\x00bad",
            b"ODXI\x02\x00\x00\x00bad",
            b"ODXI\x01\x00\x00\x00bad",
        ] {
            fs::write(&path, bytes)?;
            assert!(DebianMmapIndex::open(&path).is_err());
        }
        Ok(())
    }

    #[test]
    fn empty_snapshot_deserializes_without_becoming_a_cache_miss() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("empty.mmap");
        fs::write(
            &path,
            rkyv::to_bytes::<rkyv::rancor::Error>(&DebianPackageIndex::new())?,
        )?;
        let mapped = DebianMmapIndex::open(&path)?;
        assert!(mapped.deserialize()?.packages.is_empty());
        assert!(mapped.packages()?.is_empty());
        Ok(())
    }

    #[test]
    fn rebuild_package_index_uses_only_current_lists() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let kept = directory
            .path()
            .join("kept_dists_stable_main_binary-amd64_Packages");
        let removed = directory
            .path()
            .join("removed_dists_stable_main_binary-amd64_Packages");
        fs::write(&kept, b"Package: kept\nVersion: 1\nArchitecture: amd64\n\n")?;
        fs::write(
            &removed,
            b"Package: removed\nVersion: 2\nArchitecture: amd64\n\n",
        )?;
        let before = rebuild_package_index(&[kept.clone(), removed.clone()])?;
        assert!(before.get("kept").is_some());
        assert!(before.get("removed").is_some());
        let mut sources = HashMap::from([
            (kept.clone(), required_mtime(&kept)?),
            (removed.clone(), required_mtime(&removed)?),
        ]);
        let mut cache = DebianIndexCache::default();
        assert_eq!(cache.refresh_requirement(&sources), IndexRefresh::Disk);
        hydrate_index_cache(&mut cache, before, sources.clone());
        assert_eq!(cache.refresh_requirement(&sources), IndexRefresh::Memory);

        fs::remove_file(&removed)?;
        sources.remove(&removed);
        assert_eq!(cache.refresh_requirement(&sources), IndexRefresh::Rebuild);
        let after = rebuild_package_index(std::slice::from_ref(&kept))?;
        assert_eq!(after.packages().len(), 1);
        assert!(after.get("kept").is_some());
        assert!(after.get("removed").is_none());
        assert!(after.get_name_arch("removed", "amd64").is_none());
        assert!(
            after
                .get_name_arch_component("removed", "amd64", "main")
                .is_none()
        );
        hydrate_index_cache(&mut cache, after, sources.clone());
        assert_eq!(cache.refresh_requirement(&sources), IndexRefresh::Memory);
        fs::remove_file(kept)?;
        sources.clear();
        assert_eq!(cache.refresh_requirement(&sources), IndexRefresh::Rebuild);
        let empty = rebuild_package_index(&[])?;
        assert!(empty.packages().is_empty());
        assert!(empty.get("kept").is_none());
        assert!(empty.get_name_arch("kept", "amd64").is_none());
        assert!(
            empty
                .get_name_arch_component("kept", "amd64", "main")
                .is_none()
        );
        hydrate_index_cache(&mut cache, empty, sources.clone());
        assert_eq!(cache.refresh_requirement(&sources), IndexRefresh::Memory);
        Ok(())
    }

    #[test]
    fn rebuild_package_index_rejects_incomplete_input() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let good = directory.path().join("good_Packages");
        let bad = directory.path().join("bad_Packages");
        fs::write(&good, b"Package: kept\nVersion: 1\n\n")?;
        fs::write(&bad, b"Version: 2\n\n")?;
        assert!(rebuild_package_index(&[good.clone(), bad.clone()]).is_err());
        fs::remove_file(&bad)?;
        assert!(rebuild_package_index(&[good, bad]).is_err());
        Ok(())
    }

    #[test]
    fn disk_cache_rejects_removed_package_lists() -> Result<()> {
        use std::fs::FileTimes;
        use std::time::{Duration, UNIX_EPOCH};

        let directory = tempfile::tempdir()?;
        for extension in ["lz4", "mmap", "fst"] {
            let lists = directory.path().join(extension);
            fs::create_dir(&lists)?;
            let kept = lists.join("kept_dists_stable_main_binary-amd64_Packages");
            let removed = lists.join("removed_dists_stable_main_binary-amd64_Packages");
            for path in [&kept, &removed] {
                fs::write(path, b"Package: fixture\nVersion: 1\n")?;
                File::open(path)?.set_times(
                    FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(10)),
                )?;
            }
            File::open(&lists)?
                .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(10)))?;
            let cache = directory.path().join(format!("index.{extension}"));
            fs::write(&cache, b"cache")?;
            File::open(&cache)?
                .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(20)))?;
            assert!(disk_cache_is_fresh(&cache, &lists));

            fs::remove_file(removed)?;
            File::open(&lists)?
                .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(30)))?;
            assert!(
                !disk_cache_is_fresh(&cache, &lists),
                "{extension} must not validate only the surviving list's old timestamp"
            );
            fs::remove_file(kept)?;
            assert!(!disk_cache_is_fresh(&cache, &lists));
            fs::remove_dir(lists)?;
            assert!(!disk_cache_is_fresh(
                &cache,
                directory.path().join(extension).as_path()
            ));
        }
        Ok(())
    }

    #[test]
    fn disk_cache_older_than_an_apt_package_list_is_stale() -> Result<()> {
        use std::fs::FileTimes;
        use std::time::{Duration, UNIX_EPOCH};

        let directory = tempfile::tempdir()?;
        let lists = directory.path().join("lists");
        std::fs::create_dir(&lists)?;
        let cache = directory.path().join("debian_index_v8.mmap");
        let packages = lists.join("mirror_dists_stable_main_binary-amd64_Packages");
        std::fs::write(&cache, b"cache")?;
        std::fs::write(&packages, b"Package: demo\n")?;
        std::fs::File::options()
            .write(true)
            .open(&cache)?
            .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(10)))?;
        std::fs::File::options()
            .write(true)
            .open(&packages)?
            .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(20)))?;

        assert!(!disk_cache_is_fresh(&cache, &lists));
        File::open(&lists)?
            .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(10)))?;

        std::fs::File::options()
            .write(true)
            .open(&cache)?
            .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(30)))?;
        assert!(disk_cache_is_fresh(&cache, &lists));
        Ok(())
    }

    #[test]
    fn parse_paragraph_reads_required_and_numeric_fields() -> Result<()> {
        let paragraph = "Package: vim\nVersion: 2:9.1.0-1\nDescription: Vi IMproved - enhanced vi editor\nSection: editors\nPriority: optional\nInstalled-Size: 3500\n";

        let package = parse_paragraph_str(paragraph, "main", "bookworm", "deb.example_debian")?;

        assert_eq!(package.name, "vim");
        assert_eq!(package.source_key, "deb.example_debian");
        assert_eq!(package.version, "2:9.1.0-1");
        assert_eq!(package.description, "Vi IMproved - enhanced vi editor");
        assert_eq!(package.installed_size, 3500);
        Ok(())
    }

    #[test]
    fn parse_paragraph_preserves_description_continuations() -> Result<()> {
        let paragraph = "Package: curl\nVersion: 8.5.0-1\nDescription: command line tool for transferring data\n curl is a tool to transfer data from or to a server\n .\n using one of the supported protocols.\nSection: net\n";

        let package = parse_paragraph_str(paragraph, "main", "bookworm", "deb.example_debian")?;

        assert_eq!(
            package.description,
            "command line tool for transferring data\ncurl is a tool to transfer data from or to a server\n\nusing one of the supported protocols."
        );
        Ok(())
    }

    #[test]
    fn status_parser_preserves_description_continuations() {
        let paragraph = "Package: demo\nVersion: 1.0\nArchitecture: amd64\nDescription: first line\n second line\n .\n final line\n";

        let (_, _, description, _) =
            parse_status_paragraph(paragraph).expect("valid status paragraph");

        assert_eq!(description, "first line\nsecond line\n\nfinal line");
    }

    #[test]
    fn parse_paragraph_rejects_missing_package_name() {
        assert!(
            parse_paragraph_str("Version: 1.0\n", "main", "bookworm", "deb.example_debian")
                .is_err()
        );
    }

    #[test]
    fn parse_paragraph_rejects_invalid_numeric_fields() {
        let error = parse_paragraph_str(
            "Package: curl\nSize: many\n",
            "main",
            "bookworm",
            "deb.example_debian",
        )
        .expect_err("a nonnumeric package size must be rejected");

        assert!(error.to_string().contains("Invalid Size value"));
    }

    #[test]
    fn parse_paragraph_reads_multiline_dependencies() -> Result<()> {
        let paragraph = "Package: bash\nDepends: libc6 (>= 2.38),\n libreadline8 (>= 8.1), libtinfo6 | ncurses-term\n";

        let package = parse_paragraph_str(paragraph, "main", "bookworm", "deb.example_debian")?;

        assert_eq!(
            package.depends,
            [
                "libc6 (>= 2.38)",
                "libreadline8 (>= 8.1)",
                "libtinfo6 | ncurses-term"
            ]
        );
        let pre_depends = parse_paragraph_str(
            "Package: init-system\nPre-Depends: libc6 (>= 2.36)\n",
            "main",
            "bookworm",
            "deb.example_debian",
        )?;
        assert_eq!(pre_depends.depends, ["libc6 (>= 2.36)"]);
        Ok(())
    }

    #[test]
    fn test_mmap_index_open_nonexistent_file() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let test_file = temp_dir.path().join("does_not_exist.rkyv");

        let result = DebianMmapIndex::open(&test_file);
        assert!(result.is_err(), "Should fail to open nonexistent file");
    }

    #[test]
    fn test_mmap_index_get_corrupted_archive() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let test_file = temp_dir.path().join("corrupted.rkyv");
        std::fs::write(&test_file, b"corrupted data").unwrap();

        let result = DebianMmapIndex::open(&test_file);

        assert!(result.is_err(), "Should reject a corrupted archive at open");
    }

    #[test]
    fn test_mmap_index_open_empty_file() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let test_file = temp_dir.path().join("empty.rkyv");
        std::fs::write(&test_file, b"").unwrap();

        let result = DebianMmapIndex::open(&test_file);

        assert!(result.is_err(), "Should reject an empty archive at open");
    }

    #[test]
    fn test_mmap_index_packages_corrupted() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let test_file = temp_dir.path().join("corrupted.rkyv");
        std::fs::write(&test_file, vec![0xFF; 100]).unwrap();

        let result = DebianMmapIndex::open(&test_file);

        assert!(result.is_err(), "Should reject a corrupted archive at open");
    }

    #[test]
    fn test_clean_package_cache_test_mode() {
        let _env = ENV_LOCK.lock().expect("env lock");
        // Enable test mode
        // SAFETY: Test-only code, no concurrent access to environment
        #[expect(unsafe_code)]
        unsafe {
            std::env::set_var("OMG_TEST_MODE", "1");
        }

        let result = clean_package_cache().unwrap();
        assert_eq!(result.0, 5); // files removed
        assert_eq!(result.1, 50_000_000); // bytes freed

        // SAFETY: Test cleanup, no concurrent access
        #[expect(unsafe_code)]
        unsafe {
            std::env::remove_var("OMG_TEST_MODE");
        }
    }

    #[test]
    fn test_list_orphans_test_mode() {
        let _env = ENV_LOCK.lock().expect("env lock");
        // Enable test mode
        // SAFETY: Test-only code, no concurrent access to environment
        #[expect(unsafe_code)]
        unsafe {
            std::env::set_var("OMG_TEST_MODE", "1");
        }

        let orphans = list_orphans_fast().unwrap();
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0], "libunused1");

        // SAFETY: Test cleanup, no concurrent access
        #[expect(unsafe_code)]
        unsafe {
            std::env::remove_var("OMG_TEST_MODE");
        }
    }

    #[test]
    fn test_packages_with_sizes_from_status_last_paragraph_without_trailing_blank() {
        let without_blank = "Package: apt\nStatus: install ok installed\nInstalled-Size: 4\n\nPackage: vim\nStatus: install ok installed\nInstalled-Size: 3";
        assert_eq!(
            packages_with_sizes_from_status(without_blank).expect("valid sizes"),
            vec![("apt".to_string(), 4 * 1024), ("vim".to_string(), 3 * 1024),]
        );
        let with_blank = "Package: vim\nStatus: install ok installed\nInstalled-Size: 3\n\n";
        assert_eq!(
            packages_with_sizes_from_status(with_blank).expect("valid sizes"),
            vec![("vim".to_string(), 3 * 1024)]
        );
    }

    #[test]
    fn test_installed_size_parse_rejects_corrupt_values() {
        let corrupt = "Package: vim\nStatus: install ok installed\nInstalled-Size: not-a-number";
        let error = package_size_from_status(corrupt, "vim")
            .expect_err("corrupt Installed-Size must not look like zero bytes");
        assert!(
            error.to_string().contains("invalid Installed-Size"),
            "got: {error}"
        );
        let list_error = packages_with_sizes_from_status(corrupt)
            .expect_err("corrupt Installed-Size must not omit the package as zero");
        assert!(
            list_error.to_string().contains("invalid Installed-Size"),
            "got: {list_error}"
        );
        assert_eq!(
            package_size_from_status(
                "Package: vim\nStatus: install ok installed\nInstalled-Size: 3",
                "vim",
            )
            .expect("valid size")
            .expect("installed"),
            3 * 1024
        );
        assert_eq!(
            package_size_from_status(
                "Package: vim\nStatus: install ok installed\nInstalled-Size: 3",
                "bash",
            )
            .expect("missing package is a miss"),
            None
        );
    }

    #[test]
    fn package_sizes_ignore_removed_and_partial_dpkg_states() {
        let content = "Package: installed\nStatus: install ok installed\nInstalled-Size: 3\n\nPackage: removed\nStatus: deinstall ok config-files\nInstalled-Size: 8\n\nPackage: partial\nStatus: install ok half-installed\nInstalled-Size: 5";

        assert_eq!(package_size_from_status(content, "removed").unwrap(), None);
        assert_eq!(
            packages_with_sizes_from_status(content).unwrap(),
            [("installed".to_string(), 3 * 1024)]
        );
    }

    #[test]
    fn update_candidates_are_deduplicated_with_debian_version_ordering() {
        let updates = best_update_versions([
            ("zlib".to_string(), "1.0".to_string(), "2.0~rc1".to_string()),
            ("zlib".to_string(), "1.0".to_string(), "2.0".to_string()),
            ("apt".to_string(), "1.0".to_string(), "1.1".to_string()),
            ("apt".to_string(), "1.0".to_string(), "1.1".to_string()),
        ]);

        assert_eq!(
            updates,
            [
                ("apt".to_string(), "1.0".to_string(), "1.1".to_string()),
                ("zlib".to_string(), "1.0".to_string(), "2.0".to_string()),
            ]
        );
    }

    #[test]
    fn installed_status_accepts_held_packages_but_not_partial_states() {
        assert!(status_paragraph_is_installed(
            "Package: libc6\nStatus: hold ok installed\nVersion: 2.1"
        ));
        assert!(!status_paragraph_is_installed(
            "Package: libc6\nStatus: install ok half-installed\nVersion: 2.1"
        ));
        assert!(!status_paragraph_is_installed(
            "Package: libc6\nVersion: 2.1"
        ));
    }

    #[test]
    fn installed_version_lookup_rejects_foreign_architectures() {
        let mut installed = std::collections::HashMap::new();
        installed.insert("libc6:amd64".to_string(), "2.36-1");
        installed.insert("libc6:i386".to_string(), "2.35-1");

        assert_eq!(
            installed_version_for_arch(&installed, "libc6", "amd64", "amd64"),
            Some("2.36-1")
        );
        assert_eq!(
            installed_version_for_arch(&installed, "libc6", "i386", "amd64"),
            None
        );
        assert_eq!(
            installed_version_for_arch(&installed, "libc6", "all", "amd64"),
            Some("2.36-1")
        );
    }

    #[test]
    fn test_dependencies_from_status_last_paragraph_without_trailing_blank() {
        let last_is_target = "Package: gvim\nStatus: install ok installed\nDepends: vim\n\nPackage: vim\nStatus: install ok installed\nDepends: libc6";
        let (deps, reverse) = dependencies_from_status(last_is_target, "vim");
        assert_eq!(deps, vec!["libc6".to_string()]);
        assert_eq!(reverse, vec!["gvim".to_string()]);

        let last_is_reverse = "Package: vim\nStatus: install ok installed\nDepends: libc6\n\nPackage: gvim\nStatus: install ok installed\nDepends: vim";
        let (deps, reverse) = dependencies_from_status(last_is_reverse, "vim");
        assert_eq!(deps, vec!["libc6".to_string()]);
        assert_eq!(reverse, vec!["gvim".to_string()]);
    }

    #[test]
    fn dependencies_include_pre_depends_and_ignore_removed_reverse_dependencies() {
        let content = "Package: target\nStatus: install ok installed\nPre-Depends: init-system (>= 1)\nDepends: libc6\n\nPackage: live-client\nStatus: install ok installed\nDepends: target\n\nPackage: removed-client\nStatus: deinstall ok config-files\nDepends: target";

        let (dependencies, reverse) = dependencies_from_status(content, "target");
        assert_eq!(dependencies, ["init-system", "libc6"]);
        assert_eq!(reverse, ["live-client"]);
    }

    #[test]
    fn incomplete_dpkg_states_are_not_treated_as_installed() {
        let content = "Package: partial\nStatus: install ok half-installed\nVersion: 1.0\nDepends: libc6\n\nPackage: complete\nStatus: hold ok installed\nVersion: 2.0\nDepends: libc6";

        assert_eq!(installed_version_from_status(content, "partial"), None);
        assert_eq!(
            installed_version_from_status(content, "complete").as_deref(),
            Some("2.0")
        );
        let dependencies = dependency_map_from_status(content);
        assert!(!dependencies.contains_key("partial"));
        assert_eq!(dependencies["complete"], ["libc6"]);
    }

    #[test]
    fn test_installed_version_from_status_last_paragraph_without_trailing_blank() {
        let with_blank = "Package: vim\nStatus: install ok installed\nVersion: 2:9.1.0-1\n\n";
        let without_blank = "Package: vim\nStatus: install ok installed\nVersion: 2:9.1.0-1";
        assert_eq!(
            installed_version_from_status(with_blank, "vim").as_deref(),
            Some("2:9.1.0-1")
        );
        assert_eq!(
            installed_version_from_status(without_blank, "vim").as_deref(),
            Some("2:9.1.0-1")
        );
        assert_eq!(installed_version_from_status(without_blank, "bash"), None);
    }

    #[test]
    fn test_build_dependency_map_missing_status_is_an_error() {
        if Path::new("/var/lib/dpkg/status").exists() {
            build_dependency_map().expect("existing dpkg status must parse");
            return;
        }
        let error = build_dependency_map()
            .expect_err("missing dpkg status must not look like zero dependencies");
        assert!(
            error.to_string().contains("dpkg status file not found"),
            "got: {error}"
        );
    }

    #[test]
    fn installed_names_missing_status_is_an_error() {
        if Path::new("/var/lib/dpkg/status").exists() {
            installed_names().expect("existing dpkg status must load");
            return;
        }
        let error = installed_names()
            .expect_err("missing dpkg status must not look like an empty installed set");
        assert!(
            error.to_string().contains("/var/lib/dpkg/status"),
            "got: {error}"
        );
    }

    #[test]
    fn test_extract_component_from_path_binary_pattern() {
        let p = Path::new(
            "/var/lib/apt/lists/deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages",
        );
        assert_eq!(extract_component_from_path(p), "main");
    }

    #[test]
    fn test_extract_component_from_path_simple_pattern() {
        let p = Path::new("/tmp/contrib_amd64_Packages");
        assert_eq!(extract_component_from_path(p), "contrib");
    }

    #[test]
    fn mmap_lookup_preserves_qualified_query_selection() -> Result<()> {
        let mut index = DebianPackageIndex::new();
        for (architecture, component, version) in [
            ("amd64", "main", "1.0"),
            ("amd64", "contrib", "2.0"),
            ("i386", "main", "3.0"),
        ] {
            let paragraph = format!(
                "Package: demo\nVersion: {version}\nArchitecture: {architecture}\nDescription: fixture\n"
            );
            index.add_package(parse_paragraph_str(
                &paragraph, component, "stable", "fixture",
            )?);
        }
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("index.mmap");
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&index)
            .map_err(|error| anyhow::anyhow!("fixture serialization: {error}"))?;
        fs::write(&path, &bytes)?;
        let mapped = DebianMmapIndex::open(&path)?;

        for (query, architecture, component, version) in [
            ("demo:amd64", "amd64", "main", "1.0"),
            ("demo:amd64:contrib", "amd64", "contrib", "2.0"),
            ("demo:i386", "i386", "main", "3.0"),
            ("demo:i386:absent", "i386", "main", "3.0"),
        ] {
            let package = mapped
                .get(query)?
                .with_context(|| format!("mmap lost qualified lookup {query}"))?;
            assert_eq!(package.name.as_str(), "demo");
            assert_eq!(package.architecture.as_str(), architecture);
            assert_eq!(package.component.as_str(), component);
            assert_eq!(package.version.as_str(), version);
        }
        for query in ["demo", "demo:unknown", "demo:unknown:absent"] {
            let expected = index.get_query(query).context("normal index result")?;
            let actual = mapped.get(query)?.context("mapped index result")?;
            assert_eq!(actual.architecture.as_str(), expected.architecture);
            assert_eq!(actual.component.as_str(), expected.component);
            assert_eq!(actual.version.as_str(), expected.version);
        }
        assert!(mapped.get("missing:amd64:main")?.is_none());
        Ok(())
    }

    #[test]
    fn test_index_get_query_name_arch_component() {
        let mut idx = DebianPackageIndex::new();

        idx.add_package(DebianPackage {
            name: "bash".to_string(),
            version: "5.2.15-2".to_string(),
            description: "GNU shell".to_string(),
            section: "shells".to_string(),
            priority: "required".to_string(),
            installed_size: 100,
            maintainer: "Debian".to_string(),
            architecture: "amd64".to_string(),
            depends: vec![],
            filename: "pool/main/b/bash/bash_amd64.deb".to_string(),
            size: 100,
            sha256: "x".to_string(),
            homepage: "https://example.org".to_string(),
            component: "main".to_string(),
            suite: "bookworm".to_string(),
            source_key: "deb.debian.org_debian".to_string(),
        });

        idx.add_package(DebianPackage {
            name: "bash".to_string(),
            version: "5.2.15-1".to_string(),
            description: "GNU shell".to_string(),
            section: "shells".to_string(),
            priority: "required".to_string(),
            installed_size: 100,
            maintainer: "Debian".to_string(),
            architecture: "amd64".to_string(),
            depends: vec![],
            filename: "pool/contrib/b/bash/bash_amd64.deb".to_string(),
            size: 100,
            sha256: "x".to_string(),
            homepage: "https://example.org".to_string(),
            component: "contrib".to_string(),
            suite: "bookworm".to_string(),
            source_key: "deb.debian.org_debian".to_string(),
        });

        idx.add_package(DebianPackage {
            name: "bash".to_string(),
            version: "5.2.14-1".to_string(),
            description: "GNU shell".to_string(),
            section: "shells".to_string(),
            priority: "required".to_string(),
            installed_size: 100,
            maintainer: "Debian".to_string(),
            architecture: "i386".to_string(),
            depends: vec![],
            filename: "pool/main/b/bash/bash_i386.deb".to_string(),
            size: 100,
            sha256: "x".to_string(),
            homepage: "https://example.org".to_string(),
            component: "main".to_string(),
            suite: "bookworm".to_string(),
            source_key: "deb.debian.org_debian".to_string(),
        });

        let by_name = idx.get_query("bash").expect("name lookup");
        assert_eq!(by_name.architecture, "amd64");
        assert_eq!(by_name.component, "main");
        let best = idx.best_candidates();
        assert_eq!(best.len(), 1);
        assert!(std::ptr::eq(best[0], by_name));

        let by_arch = idx.get_query("bash:i386").expect("arch lookup");
        assert_eq!(by_arch.architecture, "i386");

        let by_arch_component = idx
            .get_query("bash:amd64:contrib")
            .expect("arch+component lookup");
        assert_eq!(by_arch_component.component, "contrib");
    }

    #[test]
    fn is_installed_fast_test_mode_returns_ok_for_known_and_unknown() {
        let _env = ENV_LOCK.lock().expect("env lock");
        // SAFETY: Test-only code, no concurrent access to environment
        #[expect(unsafe_code)]
        unsafe {
            std::env::set_var("OMG_TEST_MODE", "1");
        }

        let installed = is_installed_fast("apt").expect("test-mode install lookup");
        assert!(installed);
        let unknown =
            is_installed_fast("definitely-not-installed").expect("test-mode missing lookup");
        assert!(!unknown);

        // SAFETY: Test cleanup, no concurrent access
        #[expect(unsafe_code)]
        unsafe {
            std::env::remove_var("OMG_TEST_MODE");
        }
    }

    #[test]
    fn read_auto_installed_names_missing_file_is_empty_set() {
        let names = read_auto_installed_names(Path::new("/no/such/extended_states"))
            .expect("missing extended_states is an empty auto-install set");
        assert!(names.is_empty());
    }

    #[test]
    fn auto_installed_names_from_extended_states_reads_auto_flag() {
        let content = "Package: libc6\nAuto-Installed: 1\n\nPackage: bash\nAuto-Installed: 0\n";
        let names = auto_installed_names_from_extended_states(content);
        assert!(names.contains("libc6"));
        assert!(!names.contains("bash"));
    }

    #[test]
    fn read_auto_installed_names_unreadable_file_is_error() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("extended_states");
        std::fs::create_dir(&path).expect("directory is not a readable file");

        let error = read_auto_installed_names(&path)
            .expect_err("unreadable extended_states must not look like all packages are explicit");
        let message = format!("{error:#}");
        assert!(
            message.contains("Failed to read APT extended_states"),
            "got: {message}"
        );
    }

    #[test]
    fn apt_lists_from_read_dir_allows_success() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        apt_lists_from_read_dir(fs::read_dir(dir.path())).expect("readable APT lists directory");
    }

    #[test]
    fn apt_lists_from_read_dir_rejects_unreadable() {
        let error = apt_lists_from_read_dir(Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "denied",
        )))
        .expect_err("unreadable APT lists directory must not look empty");
        assert!(
            error
                .to_string()
                .contains("Failed to read APT lists directory"),
            "got: {error}"
        );
    }

    #[test]
    fn apt_lists_entry_allows_success() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        std::fs::write(dir.path().join("foo_Packages"), b"").expect("lists file");
        let entry = fs::read_dir(dir.path())
            .expect("readable temp lists dir")
            .next()
            .expect("temp lists dir should contain one file");
        apt_lists_entry(entry).expect("readable APT lists entry must be kept");
    }

    #[test]
    fn apt_lists_entry_rejects_error() {
        let error = apt_lists_entry(Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "denied",
        )))
        .expect_err("failed APT lists entry must not look like fewer Packages files");
        assert!(
            error
                .to_string()
                .contains("Failed to read APT lists directory entry"),
            "got: {error}"
        );
    }

    #[test]
    fn required_mtime_allows_success() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("status");
        std::fs::write(&path, b"").expect("status file");
        required_mtime(&path).expect("readable file mtime must be kept");
    }

    #[test]
    fn required_mtime_rejects_missing() {
        let error = required_mtime(Path::new("/no/such/dpkg/status"))
            .expect_err("missing file mtime must not look like a cache hit");
        assert!(
            error.to_string().contains("Failed to read mtime"),
            "got: {error}"
        );
    }

    #[test]
    fn optional_mtime_missing_file_is_none() {
        let mtime = optional_mtime(Path::new("/no/such/extended_states"))
            .expect("missing extended_states mtime is optional");
        assert!(mtime.is_none());
    }

    #[test]
    fn optional_mtime_rejects_unreadable_existing() {
        // chmod 000 does not make a path unreadable to root (Debian CI).
        if rustix::process::geteuid().is_root() {
            eprintln!(
                "skipping optional_mtime_rejects_unreadable_existing: chmod 000 is ignored for root"
            );
            return;
        }
        let dir = tempfile::TempDir::new().expect("temp dir");
        let nested = dir.path().join("extended_states");
        std::fs::create_dir(&nested).expect("nested dir");
        let original = std::fs::metadata(dir.path())
            .expect("parent metadata")
            .permissions();
        let mut denied = original.clone();
        std::os::unix::fs::PermissionsExt::set_mode(&mut denied, 0o000);
        std::fs::set_permissions(dir.path(), denied).expect("deny parent");
        let result = optional_mtime(&nested);
        std::fs::set_permissions(dir.path(), original).expect("restore parent");
        let error = result.expect_err("unreadable existing extended_states must not look missing");
        assert!(
            error.to_string().contains("Failed to read mtime"),
            "got: {error}"
        );
    }

    #[test]
    fn parse_packages_file_sync_rejects_corrupt_paragraph() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("test_Packages");
        std::fs::write(
            &path,
            "Package: vim\nVersion: 1.0\n\nVersion: 2.0\n\nPackage: bash\nVersion: 1.0\n",
        )
        .expect("packages file");
        let error = parse_packages_file_sync(&path)
            .expect_err("corrupt Packages paragraph must not be skipped");
        assert!(
            error.to_string().contains("missing 'Package' field"),
            "got: {error}"
        );
    }

    #[test]
    fn parse_packages_file_sync_reads_valid_packages() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("test_Packages");
        std::fs::write(
            &path,
            "Package: vim\nVersion: 1.0\n\nPackage: bash\nVersion: 1.0\n",
        )
        .expect("packages file");
        let packages = parse_packages_file_sync(&path).expect("valid Packages file");
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "vim");
        assert_eq!(packages[1].name, "bash");
    }

    #[test]
    fn parse_packages_file_sync_accepts_sha256_checked_xz() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("fixture_Packages.xz");
        std::fs::write(
            &path,
            include_bytes!("../../../tests/data/xz-subset/apt-packages-sha256.xz"),
        )
        .expect("write APT Packages index");
        let packages = parse_packages_file_sync(&path).expect("decode SHA-256 checked index");
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "fixture");
    }

    #[test]
    fn remove_deb_files_missing_dir_is_empty() {
        let (removed, freed) = remove_deb_files(Path::new("/no/such/apt/archives"))
            .expect("missing APT cache directory is empty");
        assert_eq!(removed, 0);
        assert_eq!(freed, 0);
    }

    #[test]
    fn remove_deb_files_deletes_deb_and_skips_other_files() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let deb = dir.path().join("foo.deb");
        let other = dir.path().join("keep.txt");
        std::fs::write(&deb, b"deb").expect("deb file");
        std::fs::write(&other, b"keep").expect("non-deb file");
        let (removed, freed) = remove_deb_files(dir.path()).expect("cache cleanup");
        assert_eq!(removed, 1);
        assert_eq!(freed, 3);
        assert!(!deb.exists());
        assert!(other.exists());
    }

    #[test]
    fn remove_deb_files_unlinks_symlinks_without_counting_their_targets() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let target = dir.path().join("target");
        let link = dir.path().join("cached.deb");
        std::fs::write(&target, b"large target contents").expect("target");
        std::os::unix::fs::symlink(&target, &link).expect("cache symlink");
        let link_size = std::fs::symlink_metadata(&link)
            .expect("link metadata")
            .len();

        let (removed, freed) = remove_deb_files(dir.path()).expect("cache cleanup");
        assert_eq!(removed, 1);
        assert_eq!(freed, link_size);
        assert!(std::fs::symlink_metadata(&link).is_err());
        assert!(
            target.exists(),
            "cleanup must not remove the symlink target"
        );
    }

    #[test]
    fn loaded_index_cache_populates_all_derived_search_state() {
        let mut index = DebianPackageIndex::new();
        index.add_package(DebianPackage {
            name: "bash".to_string(),
            version: "5.2.15-2".to_string(),
            description: "GNU shell".to_string(),
            section: "shells".to_string(),
            priority: "required".to_string(),
            installed_size: 100,
            maintainer: "Debian".to_string(),
            architecture: "amd64".to_string(),
            depends: vec![],
            filename: "pool/main/b/bash/bash_amd64.deb".to_string(),
            size: 100,
            sha256: "x".to_string(),
            homepage: "https://example.org".to_string(),
            component: "main".to_string(),
            suite: "bookworm".to_string(),
            source_key: "deb.debian.org_debian".to_string(),
        });
        let current_files = HashMap::from([(
            PathBuf::from("/var/lib/apt/lists/example_Packages"),
            std::time::UNIX_EPOCH,
        )]);
        let mut cache = DebianIndexCache::default();

        hydrate_index_cache(&mut cache, index, current_files.clone());

        assert_eq!(cache.file_mtimes, current_files);
        assert_eq!(cache.search_buffer, b"bash gnu shell\0");
        assert_eq!(cache.package_offsets, vec![0, cache.search_buffer.len()]);
        assert_eq!(
            cache.index.as_ref().map(|index| index.packages.len()),
            Some(1)
        );
    }

    #[test]
    fn search_results_follow_status_without_rebuilding_repository() -> Result<()> {
        let mut index = DebianPackageIndex::new();
        index.add_package(parse_paragraph_str(
            "Package: bash\nVersion: 1\nArchitecture: amd64\nDescription: GNU shell\n",
            "main",
            "stable",
            "fixture",
        )?);
        let sources = HashMap::new();
        let mut cache = DebianIndexCache::default();
        hydrate_index_cache(&mut cache, index, sources.clone());

        let directory = tempfile::tempdir()?;
        let fst_path = directory.path().join("index.fst");
        let mut builder = fst::MapBuilder::memory();
        builder.insert("bash", 0)?;
        fs::write(&fst_path, builder.into_inner()?)?;
        fs::write(fst_path.with_added_extension("gen"), b"0")?;
        let fst = FstIndex::open(&fst_path)?;

        for (status, expected) in [
            ("install ok installed", true),
            ("deinstall ok config-files", false),
            ("install ok installed", true),
        ] {
            let content =
                format!("Package: bash\nStatus: {status}\nVersion: 1\nArchitecture: amd64\n\n");
            let installed: AHashSet<String> = status_paragraphs(&content)
                .filter(|paragraph| status_paragraph_is_installed(paragraph))
                .filter_map(parse_status_paragraph)
                .map(|(name, _, _, _)| name)
                .collect();
            assert_eq!(cache.refresh_requirement(&sources), IndexRefresh::Memory);
            let index = cache.index.as_ref().context("repository index")?;
            for query in ["bash", "ba", "ash"] {
                for results in [
                    simd_search_fallback(
                        index,
                        query,
                        &cache.search_buffer,
                        &cache.package_offsets,
                        &installed,
                    ),
                    fst_search(&fst.map, index, query, &installed),
                ] {
                    assert_eq!(results.len(), 1, "{query} / {status}");
                    assert_eq!(results[0].name, "bash");
                    assert_eq!(results[0].installed, expected, "{query} / {status}");
                }
            }
            let package = index.get_query("bash:amd64").context("qualified package")?;
            assert_eq!(
                package_with_installed_state(package, &installed).installed,
                expected
            );
        }
        Ok(())
    }

    #[test]
    fn installed_cache_rejects_changed_dpkg_source_mtimes() {
        let cached_mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(10);
        let current_mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(11);
        let cache = DpkgStatusCache {
            packages: vec![DpkgPackageEntry {
                name: "curl".to_string(),
                version: "1.0".to_string(),
                description: String::new(),
                architecture: "amd64".to_string(),
                is_explicit: true,
            }],
            status_mtime: cached_mtime,
            last_accessed: AtomicU64::new(unix_now_secs()),
            ..DpkgStatusCache::default()
        };

        assert!(installed_cache_is_current(&cache, cached_mtime, None));
        assert!(!installed_cache_is_current(&cache, current_mtime, None));
    }

    #[test]
    fn extract_suite_from_lists_filename() {
        let p = Path::new(
            "/var/lib/apt/lists/deb.debian.org_debian_dists_bookworm-updates_main_binary-amd64_Packages",
        );
        assert_eq!(extract_suite_from_path(p), "bookworm-updates");
        assert_eq!(extract_source_key_from_path(p), "deb.debian.org_debian");

        let flat = Path::new("/var/lib/apt/lists/some-repo_amd64_Packages");
        assert_eq!(extract_suite_from_path(flat), "");
        assert_eq!(extract_source_key_from_path(flat), "");
    }
}
