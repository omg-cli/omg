//! Pure Rust pacman database parser.
//!
//! Parses /var/lib/pacman/sync/*.db and /var/lib/pacman/local/ without
//! libalpm via direct tar.gz/tar.zst parsing. First load parses all DBs;
//! subsequent lookups are served from the in-memory cache.

use alpm_db;
use alpm_repo_db;
use alpm_types::Version;
use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Cursor, Read, Seek, Write};
use std::os::unix::{
    ffi::OsStrExt,
    fs::{MetadataExt, OpenOptionsExt},
};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::RwLock;

use std::time::SystemTime;
use tracing::instrument;

use crate::core::paths;
use crate::runtimes::common::{BudgetedReader, BudgetedSink, BudgetedWriter};

/// TTL for cache eviction safety net (30 minutes)
const CACHE_TTL_SECS: u64 = 30 * 60;
const MAX_DESC_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SYNC_ENTRIES: usize = 100_000;

/// Sync database cache, validated against its source identity on reuse.
static SYNC_DB_CACHE: std::sync::LazyLock<RwLock<DbCache>> =
    std::sync::LazyLock::new(|| RwLock::new(DbCache::default()));

/// Global cache for local database
static LOCAL_DB_CACHE: std::sync::LazyLock<RwLock<LocalDbCache>> =
    std::sync::LazyLock::new(|| RwLock::new(LocalDbCache::default()));

#[derive(Default, Serialize, Deserialize)]
struct DbCache {
    packages: HashMap<String, SyncDbPackage>,
    last_modified: Option<SyncDbEpoch>,
    #[serde(skip)]
    last_accessed: Option<SystemTime>,
}

fn load_sync_packages(sync_dir: &Path) -> Result<HashMap<String, SyncDbPackage>> {
    let db_paths = collect_sync_db_paths(sync_dir)?;
    let parsed: Vec<HashMap<String, SyncDbPackage>> = db_paths
        .par_iter()
        .map(|(path, name)| {
            parse_sync_db(path, name)
                .with_context(|| format!("Failed to parse database: {} ({})", path.display(), name))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut packages = HashMap::with_capacity(20000);
    for pkgs in parsed {
        // First repo wins: official repos are collected before custom ones
        // (see `collect_sync_db_paths`), so a custom repo cannot silently
        // shadow an official package of the same name in update checks.
        for (name, pkg) in pkgs {
            packages.entry(name).or_insert(pkg);
        }
    }
    Ok(packages)
}

fn collect_sync_db_paths(sync_dir: &Path) -> Result<Vec<(PathBuf, String)>> {
    if !sync_dir.exists() {
        return Ok(Vec::new());
    }

    let config = crate::core::pacman_conf::PacmanConfig::parse(paths::pacman_conf_path())
        .context("Failed to read pacman repository priority")?;
    let repo_order = config.get_repo_names();
    let mut available = HashMap::with_capacity(repo_order.len());

    for entry in std::fs::read_dir(sync_dir).with_context(|| {
        format!(
            "Failed to read pacman sync directory {}",
            sync_dir.display()
        )
    })? {
        let entry = entry.with_context(|| {
            format!(
                "Failed to read pacman sync directory entry in {}",
                sync_dir.display()
            )
        })?;
        let path = entry.path();
        let meta = entry.metadata().with_context(|| {
            format!(
                "Failed to read pacman sync file metadata {}",
                path.display()
            )
        })?;
        if !meta.is_file() {
            continue;
        }

        // Only process .db files (not .db.sig or other extensions)
        if !path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("db"))
        {
            continue;
        }

        if let Some(name) = path.file_stem().and_then(|name| name.to_str()) {
            available.insert(name.to_string(), path);
        }
    }

    Ok(repo_order
        .into_iter()
        .filter_map(|name| available.remove(name).map(|path| (path, name.to_string())))
        .collect())
}

#[derive(Default, Serialize, Deserialize)]
struct LocalDbCache {
    packages: HashMap<String, LocalDbPackage>,
    last_modified: Option<LocalDbEpoch>,
    /// Last access time for TTL-based eviction (30-minute safety net)
    #[serde(skip)]
    last_accessed: Option<SystemTime>,
}

/// A package entry from the sync database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncDbPackage {
    pub name: String,
    pub version: Version,
    pub desc: String,
    pub filename: String,
    pub csize: u64, // Compressed size (download size)
    pub isize: u64, // Installed size
    pub url: String,
    pub arch: String,
    pub repo: String,
    pub licenses: Vec<String>,
    pub depends: Vec<String>,
    pub makedepends: Vec<String>,
    pub optdepends: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    pub provides: Vec<String>,
    pub conflicts: Vec<String>,
    pub replaces: Vec<String>,
}

impl Default for SyncDbPackage {
    fn default() -> Self {
        Self {
            name: String::new(),
            version: super::super::types::zero_version(),
            desc: String::new(),
            filename: String::new(),
            csize: 0,
            isize: 0,
            url: String::new(),
            arch: String::new(),
            repo: String::new(),
            licenses: Vec::new(),
            depends: Vec::new(),
            makedepends: Vec::new(),
            optdepends: Vec::new(),
            groups: Vec::new(),
            provides: Vec::new(),
            conflicts: Vec::new(),
            replaces: Vec::new(),
        }
    }
}

/// A package from the local database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalDbPackage {
    pub name: String,
    pub version: Version,
    pub desc: String,
    pub install_date: String,
    pub licenses: Vec<String>,
    pub explicit: bool, // Explicitly installed vs dependency
    /// Runtime dependencies this package declares (`%DEPENDS%`).
    ///
    /// Reverse dependencies are derived from these sets at query time (see
    /// [`compute_required_names`]): modern pacman never writes
    /// `%REQUIREDBY%`/`%OPTFOR%` sections into local desc files, so trusting
    /// such fields made every non-explicit package look like an orphan.
    pub depends: Vec<String>,
    /// Optional dependencies this package declares (`%OPTDEPENDS%`).
    #[serde(default)]
    pub optdepends: Vec<String>,
    /// Virtual packages/capabilities this package satisfies (`%PROVIDES%`).
    pub provides: Vec<String>,
}

impl Default for LocalDbPackage {
    fn default() -> Self {
        Self {
            name: String::new(),
            version: super::super::types::zero_version(),
            desc: String::new(),
            install_date: String::new(),
            licenses: Vec::new(),
            explicit: false,
            depends: Vec::new(),
            optdepends: Vec::new(),
            provides: Vec::new(),
        }
    }
}

/// Parse a sync database file (core.db, extra.db, multilib.db)
/// Returns a `HashMap` of package name -> `SyncDbPackage`
pub fn parse_sync_db(path: &Path, repo_name: &str) -> Result<HashMap<String, SyncDbPackage>> {
    let mut file =
        File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;

    let reader: Box<dyn Read> = {
        let mut probe = [0u8; 263];
        let probe_len = file.read(&mut probe)?;
        file.rewind()?;

        if probe.starts_with(&[0x1f, 0x8b]) {
            Box::new(BudgetedReader::new(
                GzDecoder::new(file),
                BudgetedSink::max_budget(),
            ))
        } else if probe.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
            let decoder = ruzstd::decoding::StreamingDecoder::new(file)
                .map_err(|e| anyhow::anyhow!("zstd init: {e}"))?;
            Box::new(BudgetedReader::new(decoder, BudgetedSink::max_budget()))
        } else if probe.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
            let mut output = BudgetedWriter::new(Vec::new(), BudgetedSink::max_budget());
            lzma_rs::xz_decompress(&mut BufReader::new(file), &mut output)
                .context("Failed to decompress xz pacman database")?;
            Box::new(Cursor::new(output.into_inner()))
        } else if probe.starts_with(&[0x04, 0x22, 0x4d, 0x18]) {
            Box::new(BudgetedReader::new(
                lz4_flex::frame::FrameDecoder::new(file),
                BudgetedSink::max_budget(),
            ))
        } else if probe_len >= 262 && &probe[257..262] == b"ustar" {
            Box::new(BudgetedReader::new(file, BudgetedSink::max_budget()))
        } else {
            anyhow::bail!(
                "Unsupported pacman database compression: {}",
                path.display()
            );
        }
    };

    let mut archive = tar::Archive::new(reader);
    let mut packages = HashMap::new();
    let mut entry_count = 0usize;

    for entry in archive.entries().with_context(|| {
        format!(
            "Failed to read tar entries from {} (repo: {})",
            path.display(),
            repo_name
        )
    })? {
        entry_count += 1;
        anyhow::ensure!(
            entry_count <= MAX_SYNC_ENTRIES,
            "Pacman sync database has too many entries"
        );
        let entry = entry?;
        let entry_path = entry.path()?.to_path_buf();
        let path_str = entry_path.to_string_lossy();

        if path_str.ends_with("/desc") {
            anyhow::ensure!(
                entry.size() <= MAX_DESC_BYTES,
                "Pacman sync database desc exceeds the {MAX_DESC_BYTES}-byte limit"
            );
            // The db is a tar stream; a desc can legitimately be arbitrary
            // bytes on a damaged mirror. Lossy-decode instead of failing the
            // whole repository read (matches pacman's tolerant reader).
            let mut raw = Vec::new();
            entry
                .take(MAX_DESC_BYTES + 1)
                .read_to_end(&mut raw)
                .with_context(|| {
                    format!(
                        "Failed to read desc {} from repo {repo_name}",
                        entry_path.display()
                    )
                })?;
            anyhow::ensure!(
                raw.len() as u64 <= MAX_DESC_BYTES,
                "Pacman sync database desc exceeds the {MAX_DESC_BYTES}-byte limit"
            );
            let content = String::from_utf8_lossy(&raw).into_owned();

            match parse_desc_content(&content, repo_name) {
                Ok(pkg) if !pkg.name.is_empty() => {
                    packages.insert(pkg.name.clone(), pkg);
                }
                Ok(_) => {
                    tracing::warn!(
                        repo = repo_name,
                        entry = %entry_path.display(),
                        "Ignoring sync database entry without a package name"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        repo = repo_name,
                        entry = %entry_path.display(),
                        error = %error,
                        "Ignoring malformed sync database package entry"
                    );
                }
            }
        }
    }

    Ok(packages)
}

/// Extract a human-readable message from a `catch_unwind` panic payload.
fn panic_message(info: &(dyn std::any::Any + Send)) -> &str {
    info.downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| info.downcast_ref::<&str>().copied())
        .unwrap_or("unknown panic")
}

/// Convert an alpm desc (V1 or V2) into a `SyncDbPackage`.
/// Both desc types expose identical field names, so a macro avoids duplication.
macro_rules! sync_pkg_from_desc {
    ($desc:expr, $repo:expr) => {
        SyncDbPackage {
            name: $desc.name.to_string(),
            version: $desc.version.into(),
            desc: $desc.description.to_string(),
            filename: $desc.file_name.to_string(),
            csize: $desc.compressed_size,
            isize: $desc.installed_size,
            url: $desc
                .url
                .as_ref()
                .map(std::string::ToString::to_string)
                .unwrap_or_default(),
            arch: $desc.arch.to_string(),
            repo: $repo.to_string(),
            licenses: $desc.license.iter().map(ToString::to_string).collect(),
            depends: $desc
                .dependencies
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            makedepends: $desc
                .make_dependencies
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            optdepends: $desc
                .optional_dependencies
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            groups: $desc
                .groups
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            provides: $desc
                .provides
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            conflicts: $desc
                .conflicts
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            replaces: $desc
                .replaces
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
        }
    };
}

fn parse_desc_content(content: &str, repo: &str) -> Result<SyncDbPackage> {
    // Try V2 first (newer format without MD5SUM).
    // Wrap in catch_unwind because alpm_repo_db can panic on corrupted data
    // (e.g., PackageRelation::from_str panics on malformed dependency strings).
    let v2_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        alpm_repo_db::desc::RepoDescFileV2::from_str(content)
    }));

    match v2_result {
        Ok(Ok(desc)) => return Ok(sync_pkg_from_desc!(desc, repo)),
        Ok(Err(_)) => {}
        Err(panic_info) => {
            tracing::warn!(
                repo = repo,
                error = panic_message(&*panic_info),
                "Corrupted package desc in repo (V2 parse panic), trying V1 fallback"
            );
        }
    }

    // Fallback to V1 (older format with MD5SUM)
    let v1_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        alpm_repo_db::desc::RepoDescFileV1::from_str(content)
    }));

    match v1_result {
        Ok(Ok(desc)) => return Ok(sync_pkg_from_desc!(desc, repo)),
        Ok(Err(_)) => {}
        Err(panic_info) => {
            tracing::warn!(
                repo = repo,
                error = panic_message(&*panic_info),
                "Corrupted package desc in repo (V1 parse panic), trying manual fallback"
            );
        }
    }

    // Both V2 and V1 failed - use manual lenient parser as final fallback
    // This handles cases like "Unknown Packager" without email (common in custom repos)
    parse_desc_manual(content, repo)
}

fn parse_desc_manual(content: &str, repo: &str) -> Result<SyncDbPackage> {
    let mut pkg = SyncDbPackage {
        repo: repo.to_string(),
        ..SyncDbPackage::default()
    };

    let mut current_section = "";
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if line.starts_with('%') && line.ends_with('%') {
            current_section = line;
            continue;
        }

        match current_section {
            "%NAME%" => pkg.name = line.to_string(),
            "%VERSION%" => {
                pkg.version = require_package_version(line)?;
            }
            "%DESC%" => pkg.desc = line.to_string(),
            "%URL%" => pkg.url = line.to_string(),
            "%ARCH%" => pkg.arch = line.to_string(),
            "%CSIZE%" => {
                pkg.csize = line
                    .parse()
                    .with_context(|| format!("Invalid compressed size in repo {repo}: {line}"))?;
            }
            "%ISIZE%" => {
                pkg.isize = line
                    .parse()
                    .with_context(|| format!("Invalid installed size in repo {repo}: {line}"))?;
            }
            "%FILENAME%" => pkg.filename = line.to_string(),
            "%DEPENDS%" => pkg.depends.push(line.to_string()),
            "%PROVIDES%" => pkg.provides.push(line.to_string()),
            "%CONFLICTS%" => pkg.conflicts.push(line.to_string()),
            "%REPLACES%" => pkg.replaces.push(line.to_string()),
            "%OPTDEPENDS%" => pkg.optdepends.push(line.to_string()),
            "%GROUPS%" => pkg.groups.push(line.to_string()),
            "%MAKEDEPENDS%" => pkg.makedepends.push(line.to_string()),
            "%LICENSE%" => pkg.licenses.push(line.to_string()),
            _ => {}
        }
    }

    Ok(pkg)
}

/// Parse the local package database (/var/lib/pacman/local/)
/// Returns a `HashMap` of package name -> `LocalDbPackage`
pub fn parse_local_db(path: &Path) -> Result<HashMap<String, LocalDbPackage>> {
    let mut packages = HashMap::with_capacity(2000); // Pre-allocate for typical system

    if !path.exists() {
        return Ok(packages);
    }

    for entry in std::fs::read_dir(path)
        .with_context(|| format!("Failed to read pacman local directory {}", path.display()))?
    {
        // Match the sync-db policy: one corrupt entry must never take down
        // the whole local database (it breaks every pacman feature).
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "Ignoring unreadable pacman local directory entry"
                );
                continue;
            }
        };
        let pkg_path = entry.path();
        let meta = match entry.metadata() {
            Ok(meta) => meta,
            Err(error) => {
                tracing::warn!(
                    pkg_dir = %pkg_path.display(),
                    error = %error,
                    "Ignoring pacman local package with unreadable metadata"
                );
                continue;
            }
        };
        if !meta.is_dir() {
            continue;
        }

        let desc_path = pkg_path.join("desc");
        if !desc_path.exists() {
            tracing::warn!(
                pkg_dir = %pkg_path.display(),
                "Ignoring local package directory missing its desc file (corrupt pacman local db entry)"
            );
            continue;
        }

        match parse_local_desc(&desc_path) {
            Ok(pkg) if !pkg.name.is_empty() => {
                packages.insert(pkg.name.clone(), pkg);
            }
            Ok(_) => {
                tracing::warn!(
                    pkg_dir = %pkg_path.display(),
                    "Ignoring local package entry without a package name"
                );
            }
            Err(error) => {
                tracing::warn!(
                    pkg_dir = %pkg_path.display(),
                    error = %error,
                    "Ignoring malformed local pacman database package entry"
                );
            }
        }
    }

    Ok(packages)
}

fn require_package_version(raw: &str) -> Result<Version> {
    Version::from_str(raw)
        .map_err(|error| anyhow::anyhow!("Invalid package version {raw}: {error}"))
}

fn parse_local_desc(path: &Path) -> Result<LocalDbPackage> {
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    let file = options
        .open(path)
        .with_context(|| format!("Failed to open local package desc {}", path.display()))?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file(),
        "Local package desc must be a regular file"
    );
    anyhow::ensure!(
        metadata.len() <= MAX_DESC_BYTES,
        "Local package desc exceeds the {MAX_DESC_BYTES}-byte limit"
    );
    let mut content = String::new();
    file.take(MAX_DESC_BYTES + 1)
        .read_to_string(&mut content)
        .with_context(|| format!("Failed to read local package desc {}", path.display()))?;
    anyhow::ensure!(
        content.len() as u64 <= MAX_DESC_BYTES,
        "Local package desc exceeds the {MAX_DESC_BYTES}-byte limit"
    );

    // Modern pacman never writes `%REQUIREDBY%`/`%OPTFOR%` sections into local
    // desc files, so reverse dependencies cannot be read from disk. They are
    // derived from `%DEPENDS%`/`%PROVIDES%` at query time (see
    // `compute_required_names`) under the canonical orphan rule
    // (`types::is_orphan_package`, `pacman -Qdt` semantics).
    if let Ok(desc) = alpm_db::desc::DbDescFileV1::from_str(&content) {
        Ok(LocalDbPackage {
            name: desc.name.to_string(),
            version: desc.version.into(),
            desc: desc.description.to_string(),
            install_date: desc.installdate.to_string(),
            licenses: desc.license.iter().map(ToString::to_string).collect(),
            explicit: matches!(desc.reason, alpm_types::PackageInstallReason::Explicit),
            depends: desc.depends.iter().map(ToString::to_string).collect(),
            optdepends: desc.optdepends.iter().map(ToString::to_string).collect(),
            provides: desc.provides.iter().map(ToString::to_string).collect(),
        })
    } else if let Ok(desc) = alpm_db::desc::DbDescFileV2::from_str(&content) {
        // V2 (has XDATA support)
        Ok(LocalDbPackage {
            name: desc.name.to_string(),
            version: desc.version.into(),
            desc: desc.description.to_string(),
            install_date: desc.installdate.to_string(),
            licenses: desc.license.iter().map(ToString::to_string).collect(),
            explicit: matches!(desc.reason, alpm_types::PackageInstallReason::Explicit),
            depends: desc.depends.iter().map(ToString::to_string).collect(),
            optdepends: desc.optdepends.iter().map(ToString::to_string).collect(),
            provides: desc.provides.iter().map(ToString::to_string).collect(),
        })
    } else {
        // Fallback: manual parsing for edge cases
        parse_local_desc_manual(&content)
    }
}

/// Manual local desc parser as fallback
fn parse_local_desc_manual(content: &str) -> Result<LocalDbPackage> {
    let mut name = String::new();
    let mut version = String::new();
    let mut desc = String::new();
    let mut install_date = String::new();
    let mut reason = String::new();
    let mut licenses = Vec::new();
    let mut depends = Vec::new();
    let mut optdepends = Vec::new();
    let mut provides = Vec::new();
    let mut current_field: Option<&str> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            current_field = None;
            continue;
        }

        if line.starts_with('%') && line.ends_with('%') {
            current_field = Some(line);
            continue;
        }

        match current_field {
            Some("%NAME%") => name = line.to_string(),
            Some("%VERSION%") => version = line.to_string(),
            Some("%DESC%") => desc = line.to_string(),
            Some("%INSTALLDATE%") => install_date = line.to_string(),
            Some("%REASON%") => reason = line.to_string(),
            Some("%LICENSE%") => licenses.push(line.to_string()),
            Some("%DEPENDS%") => depends.push(line.to_string()),
            Some("%OPTDEPENDS%") => optdepends.push(line.to_string()),
            Some("%PROVIDES%") => provides.push(line.to_string()),
            _ => {}
        }
    }

    if name.is_empty() {
        anyhow::bail!("Failed to parse local desc file: no NAME found");
    }

    // pacman writes 0 for explicitly installed and 1 for dependencies.
    // Anything else is malformed; fail loudly instead of guessing.
    let explicit = match reason.as_str() {
        "" | "0" => true,
        "1" => false,
        other => anyhow::bail!("Invalid %REASON% value in local desc: {other}"),
    };

    Ok(LocalDbPackage {
        name,
        version: require_package_version(&version)?,
        desc,
        install_date,
        licenses,
        explicit,
        depends,
        optdepends,
        provides,
    })
}

/// Save cache to disk in binary format
fn save_cache_to_disk<T: Serialize>(cache: &T, name: &str) -> Result<()> {
    save_cache_to_disk_in(cache, &paths::cache_dir(), name)
}

fn save_cache_to_disk_in<T: Serialize>(cache: &T, cache_dir: &Path, name: &str) -> Result<()> {
    fs::create_dir_all(cache_dir).with_context(|| {
        format!(
            "Failed to create package cache directory: {}",
            cache_dir.display()
        )
    })?;
    let path = cache_dir.join(format!("{name}.bin"));
    let data = bitcode::serialize(cache)?;
    let mut file = tempfile::NamedTempFile::new_in(cache_dir).with_context(|| {
        format!(
            "Failed to create temporary package cache in {}",
            cache_dir.display()
        )
    })?;
    file.write_all(&data)?;
    file.as_file_mut().sync_all()?;
    file.persist(&path)
        .map_err(|error| error.error)
        .with_context(|| format!("Failed to persist package cache at {}", path.display()))?;
    Ok(())
}

fn persist_cache_best_effort<T: Serialize>(cache: &T, name: &str) {
    if let Err(error) = save_cache_to_disk(cache, name) {
        tracing::warn!("Failed to persist {name} package cache: {error}");
    }
}

/// Load cache from disk.
///
/// SECURITY (audit sec04 F1): when omg runs elevated (root via sudo), the
/// cache directory still belongs to the ORIGINAL user, who is fully
/// adversarial relative to the root process. Parsing attacker-writable
/// bytes as trusted derived state lets them poison what root reads/writes.
/// Elevated runs therefore bypass user-owned derived caches entirely and go
/// to ground truth (ALPM/dpkg); the cache remains a fast path for the
/// unprivileged user's own sessions.
fn load_cache_from_disk<T: for<'de> Deserialize<'de>>(name: &str) -> Result<T> {
    #[cfg(unix)]
    if crate::core::is_root() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = paths::cache_dir();
        if let Ok(meta) = std::fs::metadata(&dir)
            && meta.uid() != 0
        {
            tracing::debug!(
                "Elevated run: ignoring user-owned derived cache {}",
                dir.display()
            );
            anyhow::bail!("derived cache skipped under elevation");
        }
    }
    load_cache_from_disk_in(&paths::cache_dir(), name)
}

fn load_cache_from_disk_in<T: for<'de> Deserialize<'de>>(
    cache_dir: &Path,
    name: &str,
) -> Result<T> {
    let path = cache_dir.join(format!("{name}.bin"));
    let data = fs::read(&path)?;
    let cache: T = bitcode::deserialize(&data)?;
    Ok(cache)
}

/// Check if cache is expired based on TTL (30-minute safety net)
fn is_cache_expired(last_accessed: Option<SystemTime>) -> bool {
    if let Some(last_access) = last_accessed
        && let Ok(elapsed) = SystemTime::now().duration_since(last_access)
    {
        return elapsed.as_secs() > CACHE_TTL_SECS;
    }
    false
}

fn is_cache_reusable<E: Copy + Eq>(
    cache_epoch: Option<E>,
    current_epoch: E,
    has_packages: bool,
    last_accessed: Option<SystemTime>,
) -> bool {
    cache_epoch == Some(current_epoch) && has_packages && !is_cache_expired(last_accessed)
}

/// Shared access to the fields that both on-disk caches serialize, so a
/// single generic loader serves both timestamp and metadata identities.
/// Each cache's disk namespace identifies its persisted representation.
trait PackageCache: Serialize + for<'de> Deserialize<'de> {
    type Package;
    type Epoch: Copy + Eq;

    fn packages(&self) -> &HashMap<String, Self::Package>;
    fn packages_mut(&mut self) -> &mut HashMap<String, Self::Package>;
    fn last_modified(&self) -> Option<Self::Epoch>;
    fn set_last_modified(&mut self, time: Option<Self::Epoch>);
    fn last_accessed(&self) -> Option<SystemTime>;
    fn set_last_accessed(&mut self, time: Option<SystemTime>);
}

impl PackageCache for DbCache {
    type Package = SyncDbPackage;
    type Epoch = SyncDbEpoch;

    fn packages(&self) -> &HashMap<String, Self::Package> {
        &self.packages
    }
    fn packages_mut(&mut self) -> &mut HashMap<String, Self::Package> {
        &mut self.packages
    }
    fn last_modified(&self) -> Option<SyncDbEpoch> {
        self.last_modified
    }
    fn set_last_modified(&mut self, time: Option<SyncDbEpoch>) {
        self.last_modified = time;
    }
    fn last_accessed(&self) -> Option<SystemTime> {
        self.last_accessed
    }
    fn set_last_accessed(&mut self, time: Option<SystemTime>) {
        self.last_accessed = time;
    }
}

impl PackageCache for LocalDbCache {
    type Package = LocalDbPackage;
    type Epoch = LocalDbEpoch;

    fn packages(&self) -> &HashMap<String, Self::Package> {
        &self.packages
    }
    fn packages_mut(&mut self) -> &mut HashMap<String, Self::Package> {
        &mut self.packages
    }
    fn last_modified(&self) -> Option<LocalDbEpoch> {
        self.last_modified
    }
    fn set_last_modified(&mut self, time: Option<LocalDbEpoch>) {
        self.last_modified = time;
    }
    fn last_accessed(&self) -> Option<SystemTime> {
        self.last_accessed
    }
    fn set_last_accessed(&mut self, time: Option<SystemTime>) {
        self.last_accessed = time;
    }
}

/// Locking helpers. A panic while holding the cache lock only leaves derived
/// data in an unspecified state; recovering via `PoisonError::into_inner`
/// keeps package operations working instead of poisoning every later call.
/// https://doc.rust-lang.org/std/sync/struct.RwLock.html#poisoning
fn read_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Ensure `cache_lock` holds a cache for `current_epoch`, using (in order of
/// cost) memory, disk, or `load_fresh`. Rechecking after blocking work avoids
/// replacing an already reusable cache; concurrent parses can still occur.
///
/// Expired in-memory entries are not cleared eagerly; they are never reusable
/// (`is_cache_reusable`), so the first load replaces them wholesale.
fn ensure_cache_loaded<C: PackageCache>(
    cache_lock: &RwLock<C>,
    disk_name: &str,
    current_epoch: C::Epoch,
    load_fresh: impl FnOnce() -> Result<HashMap<String, C::Package>>,
) -> Result<()> {
    let reusable = |cache: &C| {
        is_cache_reusable(
            cache.last_modified(),
            current_epoch,
            !cache.packages().is_empty(),
            cache.last_accessed(),
        )
    };
    let now = || Some(SystemTime::now());

    // Fast path: in-memory hit (brief write lock only to refresh the TTL).
    {
        let mut cache = write_lock(cache_lock);
        if reusable(&cache) {
            cache.set_last_accessed(now());
            return Ok(());
        }
    }

    // Try to load from disk cache first (FAST < 5ms)
    if let Ok(disk_cache) = load_cache_from_disk::<C>(disk_name)
        && reusable(&disk_cache)
    {
        let mut cache = write_lock(cache_lock);
        // Double-check: another thread may have loaded while we were waiting.
        if reusable(&cache) {
            cache.set_last_accessed(now());
            return Ok(());
        }
        *cache = disk_cache;
        cache.set_last_accessed(now());
        return Ok(());
    }

    // Cache miss or stale - need to reload/parse
    let packages = load_fresh()?;

    let mut cache = write_lock(cache_lock);
    // Re-check: another thread may have loaded while we were parsing.
    if reusable(&cache) {
        cache.set_last_accessed(now());
        return Ok(());
    }

    *cache.packages_mut() = packages;
    cache.set_last_modified(Some(current_epoch));
    cache.set_last_accessed(now());

    // Persist for faster restarts; the in-memory cache is authoritative
    // for this process, so a disk write failure is logged, not fatal.
    persist_cache_best_effort(&*cache, disk_name);

    Ok(())
}

/// Ensure sync cache is loaded (fast if already loaded)
fn ensure_sync_cache_loaded(sync_dir: &Path) -> Result<()> {
    let current_mtime = SyncDbEpoch::from_sync_dir(sync_dir)?;
    // The legacy sync_db bitcode stores a timestamp, not this identity.
    ensure_cache_loaded(&SYNC_DB_CACHE, "sync_db_source_v1", current_mtime, || {
        load_sync_packages(sync_dir)
    })
}

/// Ensure local cache is loaded (fast if already loaded)
fn ensure_local_cache_loaded(local_dir: &Path) -> Result<()> {
    let current_epoch = LocalDbEpoch::from_local_dir(local_dir)?;
    // The previous local_db_rdeps layout stores only a directory timestamp.
    ensure_cache_loaded(&LOCAL_DB_CACHE, "local_db_source_v1", current_epoch, || {
        parse_local_db(local_dir)
    })
}

/// Metadata identity of the complete sync directory. Ordering is meaningless:
/// compare identities for equality, never for increasing time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncDbEpoch(Option<[u8; 32]>);

impl SyncDbEpoch {
    /// Sentinel for an absent directory, retained under its existing API name.
    /// An existing empty directory has its own observed identity.
    pub const UNIX_EPOCH: Self = Self(None);

    /// Reads the current sync directory metadata identity.
    pub fn observe() -> Result<Self> {
        Self::from_sync_dir(&paths::pacman_sync_dir_result()?)
    }

    /// Observe names and metadata, including symlink targets, without locking writers.
    pub fn from_sync_dir(sync_dir: &Path) -> Result<Self> {
        Ok(Self(DirectoryMetadata::observe(sync_dir)?.fingerprint))
    }
}

struct DirectoryMetadata {
    fingerprint: Option<[u8; 32]>,
    directories: Vec<PathBuf>,
}

impl DirectoryMetadata {
    fn hash_metadata(hash: &mut Sha256, metadata: &fs::Metadata) {
        for value in [
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            u64::from(metadata.mode()),
        ] {
            hash.update(value.to_le_bytes());
        }
        for value in [
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        ] {
            hash.update(value.to_le_bytes());
        }
    }

    fn observe(directory_path: &Path) -> Result<Self> {
        let directory = match fs::symlink_metadata(directory_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    fingerprint: None,
                    directories: Vec::new(),
                });
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("Failed to observe {}", directory_path.display()));
            }
        };
        let mut entries = fs::read_dir(directory_path)
            .with_context(|| {
                format!(
                    "Failed to read catalog directory {}",
                    directory_path.display()
                )
            })?
            .collect::<std::io::Result<Vec<_>>>()
            .context("Failed to enumerate catalog directory entries")?;
        entries.sort_by_cached_key(fs::DirEntry::file_name);
        let mut hash = Sha256::new();
        Self::hash_metadata(&mut hash, &directory);
        if directory.file_type().is_symlink() {
            Self::hash_metadata(&mut hash, &fs::metadata(directory_path)?);
        }
        let mut directories = Vec::new();
        for entry in entries {
            let name = entry.file_name();
            hash.update((name.as_bytes().len() as u64).to_le_bytes());
            hash.update(name.as_bytes());
            let metadata = entry
                .metadata()
                .with_context(|| format!("Failed to observe {}", entry.path().display()))?;
            Self::hash_metadata(&mut hash, &metadata);
            if metadata.file_type().is_symlink() {
                let target = fs::metadata(entry.path()).with_context(|| {
                    format!("Failed to observe target of {}", entry.path().display())
                })?;
                Self::hash_metadata(&mut hash, &target);
                if target.is_dir() {
                    directories.push(entry.path());
                }
            } else if metadata.is_dir() {
                directories.push(entry.path());
            }
        }
        Ok(Self {
            fingerprint: Some(hash.finalize().into()),
            directories,
        })
    }
}

/// Metadata identity of local/ and the files in each package directory.
/// This is neither chronological ordering nor content authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalDbEpoch(Option<[u8; 32]>);

impl LocalDbEpoch {
    /// Sentinel for an absent local database, not a chronological value.
    pub const UNIX_EPOCH: Self = Self(None);

    pub fn observe() -> Result<Self> {
        Self::from_local_dir(&paths::pacman_local_dir_result()?)
    }

    pub fn from_local_dir(local_dir: &Path) -> Result<Self> {
        let root = DirectoryMetadata::observe(local_dir)?;
        let Some(fingerprint) = root.fingerprint else {
            return Ok(Self::UNIX_EPOCH);
        };
        let mut hash = Sha256::new();
        hash.update(fingerprint);
        // ALPM stores package metadata as files directly inside each package
        // directory. Observe those files, not only the local/ directory entry.
        for package in root.directories {
            let child = DirectoryMetadata::observe(&package)?;
            let fingerprint = child
                .fingerprint
                .with_context(|| format!("Package directory disappeared: {}", package.display()))?;
            hash.update(fingerprint);
        }
        Ok(Self(Some(hash.finalize().into())))
    }
}

/// Combined on-disk identity for libalpm: sync catalogs and the local db.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlpmCatalogEpoch {
    pub(crate) sync: SyncDbEpoch,
    pub(crate) local: LocalDbEpoch,
}

impl AlpmCatalogEpoch {
    /// Bracket construction with observations; discard the value on mismatch.
    /// Equal metadata does not establish a transactionally consistent snapshot.
    pub(crate) fn load_stable<T>(
        mut observe: impl FnMut() -> Result<Self>,
        load: impl FnOnce() -> Result<T>,
    ) -> Result<(T, Self)> {
        let epoch = observe()?;
        let value = load()?;
        epoch.ensure_unchanged(observe()?)?;
        Ok((value, epoch))
    }

    /// Reject observed changes, without claiming to lock external writers.
    pub(crate) fn ensure_unchanged(self, after: Self) -> Result<()> {
        anyhow::ensure!(
            self == after,
            "Package databases changed while loading; retry the operation"
        );
        Ok(())
    }

    pub const UNIX_EPOCH: Self = Self {
        sync: SyncDbEpoch::UNIX_EPOCH,
        local: LocalDbEpoch::UNIX_EPOCH,
    };

    pub fn observe() -> Result<Self> {
        Ok(Self {
            sync: SyncDbEpoch::observe()?,
            local: LocalDbEpoch::observe()?,
        })
    }
}

/// Force refresh of all caches (call after sync/install)
pub fn invalidate_caches() -> Result<()> {
    {
        let mut cache = write_lock(&SYNC_DB_CACHE);
        cache.packages.clear();
        cache.last_modified = None;
        cache.last_accessed = None;
    }
    {
        let mut cache = write_lock(&LOCAL_DB_CACHE);
        cache.packages.clear();
        cache.last_modified = None;
        cache.last_accessed = None;
    }
    super::super::alpm_direct::clear_alpm_cache();

    invalidate_derived_cache_files(&paths::cache_dir())
}

fn invalidate_derived_cache_files(cache_dir: &Path) -> Result<()> {
    for name in [
        "sync_db_source_v1",
        "local_db_source_v1",
        "sync_db",
        "local_db_rdeps",
        "local_db",
    ] {
        remove_cache_file(&cache_dir.join(format!("{name}.bin")))?;
    }
    Ok(())
}

fn remove_cache_file(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("Failed to remove package cache file {}", path.display())),
    }
}

/// Detailed sync packages for indexing consumers (daemon, resolver).
pub fn get_detailed_packages() -> Result<Vec<SyncDbPackage>> {
    let sync_dir = paths::pacman_sync_dir_result()?;
    ensure_sync_cache_loaded(&sync_dir)?;

    let cache = read_lock(&SYNC_DB_CACHE);
    Ok(cache.packages.values().cloned().collect())
}

/// A pending update derived from the pure-Rust pacman caches.
#[derive(Debug, Clone)]
pub struct CachedUpdate {
    pub name: String,
    pub old_version: Version,
    pub new_version: Version,
    pub repo: String,
}

/// Cached update check across all configured repositories.
#[instrument]
pub fn check_updates_cached() -> Result<Vec<CachedUpdate>> {
    let pacman_config = crate::core::pacman_conf::PacmanConfig::parse(paths::pacman_conf_path())
        .context("Failed to load update filters from pacman.conf")?;
    let ignored_packages = compile_ignore_patterns(&pacman_config.ignore_pkg, "IgnorePkg")?;
    let ignored_groups = compile_ignore_patterns(&pacman_config.ignore_group, "IgnoreGroup")?;
    let sync_dir = paths::pacman_sync_dir_result()?;
    let local_dir = paths::pacman_local_dir_result()?;

    // Ensure caches are loaded (will be fast if already loaded)
    ensure_sync_cache_loaded(&sync_dir)?;
    ensure_local_cache_loaded(&local_dir)?;

    // Hold both cache locks simultaneously - no cloning!
    let sync_cache = read_lock(&SYNC_DB_CACHE);
    let local_cache = read_lock(&LOCAL_DB_CACHE);

    // Compare versions - Parallelized with Rayon for <1ms update check on 2000+ pkgs
    // Optimized: filter references first, then clone only needed data at the end
    let updates: Vec<_> = local_cache
        .packages
        .par_iter()
        .filter_map(|(name, local_pkg)| {
            sync_cache
                .packages
                .get(name)
                .filter(|sync_pkg| {
                    !sync_package_is_ignored(sync_pkg, &ignored_packages, &ignored_groups)
                })
                .filter(|sync_pkg| {
                    crate::package_managers::types::compare_versions(
                        &local_pkg.version,
                        &sync_pkg.version,
                    ) == std::cmp::Ordering::Less
                })
                .map(|sync_pkg| (name, local_pkg, sync_pkg))
        })
        .map(|(name, local_pkg, sync_pkg)| {
            // Only clone once at the end
            CachedUpdate {
                name: name.clone(),
                old_version: local_pkg.version.clone(),
                new_version: sync_pkg.version.clone(),
                repo: sync_pkg.repo.clone(),
            }
        })
        .collect();

    Ok(updates)
}

fn compile_ignore_patterns(patterns: &[String], setting: &str) -> Result<globset::GlobSet> {
    let mut builder = globset::GlobSetBuilder::new();
    for pattern in patterns {
        let glob = globset::Glob::new(pattern)
            .with_context(|| format!("Invalid {setting} pattern {pattern:?}"))?;
        builder.add(glob);
    }
    builder
        .build()
        .with_context(|| format!("Failed to compile {setting} patterns"))
}

fn sync_package_is_ignored(
    package: &SyncDbPackage,
    ignored_packages: &globset::GlobSet,
    ignored_groups: &globset::GlobSet,
) -> bool {
    ignored_packages.is_match(&package.name)
        || package
            .groups
            .iter()
            .any(|group| ignored_groups.is_match(group))
}

/// Get a specific local package - FAST (<1ms)
#[inline]
pub fn get_local_package(name: &str) -> Result<Option<LocalDbPackage>> {
    let local_dir = paths::pacman_local_dir_result()?;
    ensure_local_cache_loaded(&local_dir)?;

    let cache = read_lock(&LOCAL_DB_CACHE);
    Ok(cache.packages.get(name).cloned())
}

/// Get a specific sync package by exact name - FAST (<1ms)
#[inline]
pub fn get_sync_package(name: &str) -> Result<Option<SyncDbPackage>> {
    let sync_dir = paths::pacman_sync_dir_result()?;
    ensure_sync_cache_loaded(&sync_dir)?;

    let cache = read_lock(&SYNC_DB_CACHE);
    Ok(cache.packages.get(name).cloned())
}

/// List all local packages using cache - FAST (<1ms)
pub fn list_local_cached() -> Result<Vec<LocalDbPackage>> {
    let local_dir = paths::pacman_local_dir_result()?;
    ensure_local_cache_loaded(&local_dir)?;

    let cache = read_lock(&LOCAL_DB_CACHE);
    Ok(cache.packages.values().cloned().collect())
}

/// Identify potential AUR packages (installed but not in any sync database).
///
/// Uses pure Rust cache for extreme speed (<1ms).
/// Excludes packages from ALL sync databases (official + custom repos).
pub fn get_potential_aur_packages() -> Result<Vec<String>> {
    let sync_dir = paths::pacman_sync_dir_result()?;
    let local_dir = paths::pacman_local_dir_result()?;

    ensure_sync_cache_loaded(&sync_dir)?;
    ensure_local_cache_loaded(&local_dir)?;

    let sync_cache = read_lock(&SYNC_DB_CACHE);
    let local_cache = read_lock(&LOCAL_DB_CACHE);

    let mut potential = Vec::with_capacity(local_cache.packages.len() / 10);
    for name in local_cache.packages.keys() {
        if !sync_cache.packages.contains_key(name) {
            potential.push(name.clone());
        }
    }

    Ok(potential)
}

/// Reduce an alpm relation or optdepend string to the bare name that participates in
/// dependency resolution: `"curl>=7.0"` → `"curl"`,
/// `"libfoo.so=1-64"` → `"libfoo.so"`,
/// `"python-pillow: for image support"` → `"python-pillow"`.
fn dependency_base_name(relation: &str) -> &str {
    relation
        .split(['<', '>', '=', ':'])
        .next()
        .unwrap_or(relation)
        .trim()
}

/// Names of installed packages that at least one other installed package
/// requires or optionally requires, derived from the cached `%DEPENDS%`/`%OPTDEPENDS%`/`%PROVIDES%` sets.
///
/// Mirrors libalpm's reverse-dependency resolution (including virtual
/// dependencies satisfied by provisions) so the pure-Rust fast path matches
/// `pacman -Qdt` ("only packages neither required nor optionally required")
/// instead of trusting `%REQUIREDBY%` sections, which modern pacman no longer writes.
fn compute_required_names(
    packages: &HashMap<String, LocalDbPackage>,
) -> std::collections::HashSet<String> {
    // Virtual dependencies ("app depends on virtual-svc") are satisfied by
    // the installed packages whose `%PROVIDES%` name that capability.
    let mut providers: HashMap<&str, Vec<&str>> = HashMap::new();
    for (name, pkg) in packages {
        for provide in &pkg.provides {
            providers
                .entry(dependency_base_name(provide))
                .or_default()
                .push(name);
        }
    }

    let mut required: std::collections::HashSet<String> =
        std::collections::HashSet::with_capacity(packages.len());
    for pkg in packages.values() {
        for depend in &pkg.depends {
            let target = dependency_base_name(depend);
            if target == pkg.name {
                continue;
            }
            if packages.contains_key(target) {
                required.insert(target.to_owned());
            }
            if let Some(provider_names) = providers.get(target) {
                required.extend(
                    provider_names
                        .iter()
                        .filter(|provider| **provider != pkg.name)
                        .map(|provider| (*provider).to_owned()),
                );
            }
        }
        for optdepend in &pkg.optdepends {
            let target = dependency_base_name(optdepend);
            if target == pkg.name {
                continue;
            }
            if packages.contains_key(target) {
                required.insert(target.to_owned());
            }
            if let Some(provider_names) = providers.get(target) {
                required.extend(
                    provider_names
                        .iter()
                        .filter(|provider| **provider != pkg.name)
                        .map(|provider| (*provider).to_owned()),
                );
            }
        }
    }

    required
}

/// Get total package counts - INSTANT (<1ms with cache)
///
/// The third element counts orphans under the canonical rule
/// (`types::is_orphan_package`, `pacman -Qdt` semantics): dependencies that
/// no other installed package requires. Reverse dependencies are derived
/// from the cached `%DEPENDS%`/`%PROVIDES%` sets via
/// [`compute_required_names`]; modern pacman never writes `%REQUIREDBY%`
/// into local desc files.
#[inline]
pub fn get_counts_fast() -> Result<(usize, usize, usize)> {
    let local_dir = paths::pacman_local_dir_result()?;
    ensure_local_cache_loaded(&local_dir)?;

    let cache = read_lock(&LOCAL_DB_CACHE);
    let total = cache.packages.len();
    let required = compute_required_names(&cache.packages);
    let mut explicit = 0;
    let mut orphans = 0;
    for (name, pkg) in &cache.packages {
        if pkg.explicit {
            explicit += 1;
        } else if crate::package_managers::types::is_orphan_package(
            pkg.explicit,
            !required.contains(name),
        ) {
            orphans += 1;
        }
    }

    Ok((total, explicit, orphans))
}

/// Get explicit package count only - INSTANT
#[inline]
pub fn get_explicit_count() -> Result<usize> {
    let (_, explicit, _) = get_counts_fast()?;
    Ok(explicit)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::expect_used)] // Idiomatic in tests: panics on failure with clear error context
mod tests {
    use super::*;

    /// Regression for ARCH-N1: `alpm_types::Version`'s `Ord` impl unwraps
    /// `parse::<usize>()` on numeric segments above `usize::MAX` and panics
    /// inside comparators reached from `check_updates_cached`. Ordering must
    /// route through `compare_versions`, stay deterministic, and preserve
    /// the upstream ordering for valid versions that fit in `usize`.
    #[test]
    fn version_comparison_with_overflow_numeric_segment_does_not_panic() {
        use std::cmp::Ordering;

        let huge = crate::package_managers::parse_version_or_zero("1.18446744073709551616-1");
        let one = crate::package_managers::parse_version_or_zero("1.0-1");
        let compare = |a: &alpm_types::Version, b: &alpm_types::Version| {
            crate::package_managers::types::compare_versions(a, b)
        };

        // Deterministic and antisymmetric on both sides of the overflow.
        assert_eq!(compare(&huge, &one), Ordering::Greater);
        assert_eq!(compare(&one, &huge), Ordering::Less);
        assert_eq!(compare(&huge, &one), compare(&huge, &one));
        assert_eq!(compare(&huge, &huge), Ordering::Equal);

        // Versions without overflowing segments must keep the exact
        // upstream ordering (the helper must be a pure passthrough there).
        let battery = ["1.0-1", "2.0", "1:2.3.4-5", "10.1-2", "1.10", "1.9"];
        for a in battery {
            for b in battery {
                let va = crate::package_managers::parse_version_or_zero(a);
                let vb = crate::package_managers::parse_version_or_zero(b);
                assert_eq!(compare(&va, &vb), va.cmp(&vb), "{a} vs {b}");
            }
        }
    }

    /// Regression: the compression-format probe must rewind the stream before
    /// handing it to a decoder. It previously consumed the first 4 bytes, so
    /// every real sync database failed to parse ("invalid gzip header" /
    /// "zstd init: BadMagicNumber").
    #[test]
    fn parse_sync_db_handles_gzip_and_zstd_after_magic_probe() {
        let temp = tempfile::TempDir::new().unwrap();

        // Modeled on a real core.db desc entry (single-percent sections).
        let desc = b"%FILENAME%\nbash-5.3.15-1-x86_64.pkg.tar.zst\n\n\
%NAME%\nbash\n\n\
%BASE%\nbash\n\n\
%VERSION%\n5.3.15-1\n\n\
%DESC%\nThe GNU Bourne Again shell\n\n\
%CSIZE%\n150821\n\n\
%ISIZE%\n353496\n\n\
%SHA256SUM%\ndca9ec50cf51243b86a67367a55e78b1851d31240b1edaf9c011f8511765d999\n\n\
%URL%\nhttps://www.gnu.org/software/bash/\n\n\
%LICENSE%\nGPL-3.0-or-later\n\n\
%ARCH%\nx86_64\n\n\
%BUILDDATE%\n1700000000\n\n\
%PACKAGER%\nArch Linux <archlinux@archlinux.org>\n\n";

        let build_tar = || -> Vec<u8> {
            let mut tar = tar::Builder::new(Vec::new());
            let mut header = tar::Header::new_gnu();
            header.set_size(desc.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, "bash-5.3.15-1/desc", &desc[..])
                .unwrap();
            tar.into_inner().unwrap()
        };
        let raw = build_tar();

        let mut gzip_bytes = Vec::new();
        flate2::write::GzEncoder::new(&mut gzip_bytes, flate2::Compression::fast())
            .write_all(&raw)
            .unwrap();
        let gzip_path = temp.path().join("core.db");
        std::fs::write(&gzip_path, &gzip_bytes).unwrap();
        let parsed = parse_sync_db(&gzip_path, "core").expect("gzip db must parse after probe");
        assert!(
            parsed.contains_key("bash"),
            "bash must be found, got keys {:?}",
            parsed.keys()
        );

        let zstd_bytes = zstd::stream::encode_all(&raw[..], 3).unwrap();
        let mut xz_bytes = Vec::new();
        lzma_rs::xz_compress(&mut Cursor::new(&raw), &mut xz_bytes).unwrap();
        let mut lz4_encoder = lz4_flex::frame::FrameEncoder::new(Vec::new());
        lz4_encoder.write_all(&raw).unwrap();
        let lz4_bytes = lz4_encoder.finish().unwrap();

        for (name, bytes) in [
            ("zstd", zstd_bytes),
            ("xz", xz_bytes),
            ("lz4", lz4_bytes),
            ("raw tar", raw),
        ] {
            let path = temp.path().join(format!("{name}.db"));
            std::fs::write(&path, bytes).unwrap();
            let parsed = parse_sync_db(&path, "custom")
                .unwrap_or_else(|error| panic!("{name} db must parse: {error:#}"));
            assert!(parsed.contains_key("bash"), "{name} db omitted bash");
        }

        let unknown = temp.path().join("unknown.db");
        std::fs::write(&unknown, b"not an archive").unwrap();
        let error = parse_sync_db(&unknown, "unknown").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Unsupported pacman database compression")
        );
    }

    #[test]
    fn malformed_sync_package_does_not_hide_valid_repository_entries() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("custom.db");
        let invalid = b"%NAME%\nbroken\n\n%VERSION%\nnot a version!!!\n\n";
        let valid = b"%NAME%\ngood\n\n%VERSION%\n1.0-1\n\n";

        let mut tar = tar::Builder::new(Vec::new());
        for (entry_path, content) in [
            ("broken-1/desc", invalid.as_slice()),
            ("good-1.0-1/desc", valid.as_slice()),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, entry_path, content).unwrap();
        }
        let raw = tar.into_inner().unwrap();
        let mut compressed = Vec::new();
        {
            let mut encoder =
                flate2::write::GzEncoder::new(&mut compressed, flate2::Compression::fast());
            encoder.write_all(&raw).unwrap();
            encoder.finish().unwrap();
        }
        std::fs::write(&path, compressed).unwrap();

        let packages = parse_sync_db(&path, "custom").unwrap();
        assert!(packages.contains_key("good"));
        assert!(!packages.contains_key("broken"));
    }

    #[test]
    fn oversized_sync_and_local_desc_are_rejected_before_materialization() {
        let temp = tempfile::tempdir().unwrap();
        let oversized = vec![b'a'; MAX_DESC_BYTES as usize + 1];
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(oversized.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "oversized-1/desc", oversized.as_slice())
            .unwrap();
        let raw = tar.into_inner().unwrap();
        let mut compressed = Vec::new();
        flate2::write::GzEncoder::new(&mut compressed, flate2::Compression::fast())
            .write_all(&raw)
            .unwrap();
        let sync_path = temp.path().join("oversized.db");
        std::fs::write(&sync_path, compressed).unwrap();
        assert!(
            format!("{:#}", parse_sync_db(&sync_path, "oversized").unwrap_err())
                .contains("desc exceeds")
        );

        let local_path = temp.path().join("desc");
        std::fs::write(&local_path, oversized).unwrap();
        assert!(
            format!("{:#}", parse_local_desc(&local_path).unwrap_err()).contains("desc exceeds")
        );
    }

    #[test]
    fn cached_update_filters_honour_ignored_packages_and_groups() {
        let mut package = SyncDbPackage {
            name: "linux".to_string(),
            groups: vec!["kernel".to_string()],
            ..SyncDbPackage::default()
        };
        let packages = compile_ignore_patterns(&["linux".to_string()], "IgnorePkg").unwrap();
        let groups = compile_ignore_patterns(&["kernel".to_string()], "IgnoreGroup").unwrap();
        let none = compile_ignore_patterns(&[], "empty").unwrap();
        assert!(sync_package_is_ignored(&package, &packages, &none));
        assert!(sync_package_is_ignored(&package, &none, &groups));
        let base = compile_ignore_patterns(&["base".to_string()], "IgnoreGroup").unwrap();
        assert!(!sync_package_is_ignored(&package, &none, &base));

        package.name = "linux-zen".to_string();
        package.groups = vec!["kernel-zen".to_string()];
        let packages = compile_ignore_patterns(&["linux-*".to_string()], "IgnorePkg").unwrap();
        let groups = compile_ignore_patterns(&["kernel-*".to_string()], "IgnoreGroup").unwrap();
        assert!(sync_package_is_ignored(&package, &packages, &none));
        assert!(sync_package_is_ignored(&package, &none, &groups));
    }

    #[test]
    #[serial_test::serial]
    fn sync_database_order_follows_pacman_configuration() {
        if crate::core::is_root() {
            // Elevated processes ignore OMG_PACMAN_* overrides, so this
            // fixture test only applies to unprivileged runs.
            eprintln!("skipped: elevated processes ignore caller path overrides");
            return;
        }
        let temp_dir = tempfile::tempdir().unwrap();
        std::fs::write(temp_dir.path().join("core.db"), b"core").unwrap();
        std::fs::write(temp_dir.path().join("custom.db"), b"custom").unwrap();
        let config = temp_dir.path().join("pacman.conf");
        std::fs::write(
            &config,
            "[options]\n[custom]\nServer = https://custom.example/$repo/$arch\n[core]\nServer = https://core.example/$repo/$arch\n",
        )
        .unwrap();

        temp_env::with_var("OMG_PACMAN_CONF", Some(config.as_os_str()), || {
            let names = collect_sync_db_paths(temp_dir.path())
                .unwrap()
                .into_iter()
                .map(|(_, name)| name)
                .collect::<Vec<_>>();
            assert_eq!(names, ["custom", "core"]);
        });
    }

    #[test]
    #[serial_test::serial]
    fn test_collect_sync_db_paths_excludes_sig_files() {
        if crate::core::is_root() {
            // Elevated processes ignore OMG_PACMAN_* overrides, so this
            // fixture test only applies to unprivileged runs.
            eprintln!("skipped: elevated processes ignore caller path overrides");
            return;
        }
        let temp_dir = tempfile::TempDir::new().unwrap();
        let config = temp_dir.path().join("pacman.conf");
        std::fs::write(
            &config,
            "[options]\n[core]\nServer = https://core.example/$repo/$arch\n[extra]\nServer = https://extra.example/$repo/$arch\n[custom-repo]\nServer = https://custom.example/$repo/$arch\n",
        )
        .unwrap();

        std::fs::write(temp_dir.path().join("core.db"), b"dummy").unwrap();
        std::fs::write(temp_dir.path().join("core.db.sig"), b"signature").unwrap();
        std::fs::write(temp_dir.path().join("extra.db"), b"dummy").unwrap();
        std::fs::write(temp_dir.path().join("extra.db.sig"), b"signature").unwrap();
        std::fs::write(temp_dir.path().join("custom-repo.db"), b"dummy").unwrap();
        std::fs::write(temp_dir.path().join("custom-repo.db.sig"), b"signature").unwrap();
        std::fs::write(temp_dir.path().join("not-a-db.txt"), b"text").unwrap();

        let db_paths = temp_env::with_var("OMG_PACMAN_CONF", Some(config.as_os_str()), || {
            collect_sync_db_paths(temp_dir.path()).unwrap()
        });

        let collected_names: Vec<_> = db_paths
            .iter()
            .map(|(path, _)| path.file_name().unwrap().to_str().unwrap())
            .collect();

        assert!(
            collected_names.contains(&"core.db"),
            "Should include core.db"
        );
        assert!(
            collected_names.contains(&"extra.db"),
            "Should include extra.db"
        );
        assert!(
            collected_names.contains(&"custom-repo.db"),
            "Should include custom-repo.db"
        );
        assert!(
            !collected_names.contains(&"core.db.sig"),
            "Should NOT include .sig files"
        );
        assert!(
            !collected_names.contains(&"extra.db.sig"),
            "Should NOT include .sig files"
        );
        assert!(
            !collected_names.contains(&"custom-repo.db.sig"),
            "Should NOT include .sig files"
        );
        assert!(
            !collected_names.contains(&"not-a-db.txt"),
            "Should NOT include non-.db files"
        );
    }

    #[test]
    fn test_collect_sync_db_paths_missing_dir_is_empty() {
        let missing = tempfile::TempDir::new()
            .unwrap()
            .path()
            .join("does-not-exist");
        let db_paths = collect_sync_db_paths(&missing).unwrap();
        assert!(db_paths.is_empty());
    }

    #[test]
    fn test_collect_sync_db_paths_unreadable_dir_errors() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let original = std::fs::metadata(temp_dir.path()).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(temp_dir.path(), std::fs::Permissions::from_mode(0o000))
                .unwrap();
        }
        let blocked = std::fs::read_dir(temp_dir.path()).is_err();
        let result = collect_sync_db_paths(temp_dir.path());
        let _ = std::fs::set_permissions(temp_dir.path(), original);
        if !blocked {
            return;
        }
        assert!(
            result.is_err(),
            "unreadable sync dir must fail closed, got {result:?}"
        );
    }

    #[test]
    fn local_identity_missing_dir_is_absent() {
        let missing = tempfile::TempDir::new()
            .unwrap()
            .path()
            .join("does-not-exist");
        assert_eq!(
            LocalDbEpoch::from_local_dir(&missing).unwrap(),
            LocalDbEpoch::UNIX_EPOCH
        );
    }

    #[test]
    fn test_parse_local_db_missing_dir_is_empty() {
        let missing = tempfile::TempDir::new()
            .unwrap()
            .path()
            .join("does-not-exist");
        let packages = parse_local_db(&missing).unwrap();
        assert!(packages.is_empty());
    }

    /// Wave-2 policy fix: a package directory without its desc file is a
    /// corrupt-entry condition - it must be skipped with a warning, not abort
    /// the whole local database read.
    #[test]
    fn test_parse_local_db_missing_desc_is_skipped() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(temp_dir.path().join("vim-9.1.0-1")).unwrap();
        let packages = parse_local_db(temp_dir.path()).unwrap();
        assert!(packages.is_empty(), "desc-less entry must be skipped");
    }

    #[test]
    fn test_parse_local_desc_invalid_version_errors() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let pkg_dir = temp_dir.path().join("vim-bad");
        std::fs::create_dir(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("desc"),
            "%NAME%\nvim\n\n%VERSION%\nnot a version!!!\n\n%DESC%\nVi Improved\n",
        )
        .unwrap();
        // A malformed version means the entry itself is dropped (per the
        // sync-db's per-entry degrade policy); the read as a whole succeeds.
        let packages = parse_local_db(temp_dir.path()).unwrap();
        assert!(packages.is_empty(), "invalid entry must be skipped");
    }

    #[test]
    fn sync_identity_missing_directory_is_absent() {
        let missing = tempfile::TempDir::new()
            .unwrap()
            .path()
            .join("does-not-exist");
        let identity = SyncDbEpoch::from_sync_dir(&missing).unwrap();
        assert_eq!(identity, SyncDbEpoch::UNIX_EPOCH);
    }

    #[test]
    #[ignore = "bounded filesystem metadata benchmark; run optimized with --ignored --nocapture"]
    fn local_identity_scan_benchmark() -> Result<()> {
        for packages in [100, 1_000, 3_000] {
            let directory = tempfile::tempdir()?;
            for number in 0..packages {
                let package = directory.path().join(format!("fixture-{number}-1"));
                fs::create_dir(&package)?;
                for name in ["desc", "files", "mtree"] {
                    fs::write(package.join(name), b"synthetic metadata")?;
                }
            }
            let expected = LocalDbEpoch::from_local_dir(directory.path())?;
            let mut micros = Vec::new();
            for _ in 0..7 {
                let start = std::time::Instant::now();
                let observed = LocalDbEpoch::from_local_dir(directory.path())?;
                micros.push(start.elapsed().as_micros());
                assert_eq!(observed, expected);
                std::hint::black_box(observed);
            }
            println!(
                "LOCAL_SCAN {}",
                serde_json::json!({
                    "packages": packages, "files_per_package": 3, "microseconds": micros,
                    "cache_state": "one warmup; OS cache not flushed"
                })
            );
        }
        Ok(())
    }

    #[test]
    fn local_identity_tracks_package_symlinks_and_file_removal() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let local = directory.path().join("local");
        let target = directory.path().join("package");
        fs::create_dir(&local)?;
        fs::create_dir(&target)?;
        fs::write(target.join("desc"), b"metadata")?;
        std::os::unix::fs::symlink(&target, local.join("demo-1"))?;
        let before = LocalDbEpoch::from_local_dir(&local)?;
        assert_eq!(before, LocalDbEpoch::from_local_dir(&local)?);
        fs::remove_file(target.join("desc"))?;
        let after = LocalDbEpoch::from_local_dir(&local)?;
        assert_ne!(before, after);
        assert!(!is_cache_reusable(Some(before), after, true, None));
        fs::remove_dir(&target)?;
        assert!(LocalDbEpoch::from_local_dir(&local).is_err());
        Ok(())
    }

    #[test]
    fn local_identity_detects_desc_edits_without_root_changes() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let package = directory.path().join("demo-1");
        fs::create_dir(&package)?;
        let desc = package.join("desc");
        fs::write(&desc, b"%REASON%\n0\n")?;
        let root_mtime = fs::metadata(directory.path())?.modified()?;
        let before = LocalDbEpoch::from_local_dir(directory.path())?;
        fs::write(&desc, b"%REASON%\n1\n")?;
        File::open(&desc)?.set_times(fs::FileTimes::new().set_modified(SystemTime::UNIX_EPOCH))?;
        assert_eq!(fs::metadata(directory.path())?.modified()?, root_mtime);
        assert_ne!(
            before,
            LocalDbEpoch::from_local_dir(directory.path())?,
            "desc changes must invalidate the local source identity"
        );
        Ok(())
    }

    #[test]
    fn catalog_load_preserves_stable_values_and_observation_failures() -> Result<()> {
        let epoch = AlpmCatalogEpoch::UNIX_EPOCH;
        let (value, observed) = AlpmCatalogEpoch::load_stable(|| Ok(epoch), || Ok("snapshot"))?;
        assert_eq!((value, observed), ("snapshot", epoch));
        let called = std::cell::Cell::new(false);
        let result = AlpmCatalogEpoch::load_stable(
            || anyhow::bail!("observation unavailable"),
            || {
                called.set(true);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(
            !called.get(),
            "do not initialize when the initial observation fails"
        );
        let mut observations = 0;
        let result = AlpmCatalogEpoch::load_stable(
            || {
                observations += 1;
                if observations == 1 {
                    Ok(epoch)
                } else {
                    anyhow::bail!("source disappeared")
                }
            },
            || Ok("unpublishable"),
        );
        assert!(result.is_err());
        assert_eq!(observations, 2);
        Ok(())
    }

    #[test]
    fn catalog_load_rejects_changes_during_construction() -> Result<()> {
        struct Probe<'a>(&'a std::cell::Cell<bool>);
        impl Drop for Probe<'_> {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("core.db");
        fs::write(&database, b"old")?;
        let dropped = std::cell::Cell::new(false);
        let result = AlpmCatalogEpoch::load_stable(
            || {
                Ok(AlpmCatalogEpoch {
                    sync: SyncDbEpoch::from_sync_dir(directory.path())?,
                    local: LocalDbEpoch::UNIX_EPOCH,
                })
            },
            || {
                fs::write(&database, b"new generation")?;
                Ok(Probe(&dropped))
            },
        );
        assert!(
            result.is_err(),
            "a load must not be tagged with a later source identity"
        );
        assert!(dropped.get(), "discard the unpublished loaded resource");
        Ok(())
    }

    #[test]
    fn sync_identity_detects_changes_hidden_by_a_future_timestamp() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let future = directory.path().join("core.db");
        let changed = directory.path().join("extra.db");
        fs::write(&future, b"future")?;
        fs::write(&changed, b"before")?;
        File::open(&future)?.set_times(
            fs::FileTimes::new()
                .set_modified(SystemTime::now() + std::time::Duration::from_hours(24)),
        )?;
        File::open(&changed)?.set_times(
            fs::FileTimes::new()
                .set_modified(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(10)),
        )?;
        let before = SyncDbEpoch::from_sync_dir(directory.path())?;
        fs::write(&changed, b"after!")?;
        File::open(&changed)?.set_times(
            fs::FileTimes::new()
                .set_modified(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(20)),
        )?;
        let after = SyncDbEpoch::from_sync_dir(directory.path())?;
        assert_ne!(
            before, after,
            "a future-dated neighbor must not mask source changes"
        );
        Ok(())
    }

    #[test]
    fn sync_identity_detects_replacement_with_preserved_mtime() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("core.db");
        fs::write(&path, b"before")?;
        let mtime = fs::metadata(&path)?.modified()?;
        let before = SyncDbEpoch::from_sync_dir(directory.path())?;
        assert_eq!(before, SyncDbEpoch::from_sync_dir(directory.path())?);
        let replacement = directory.path().join("replacement");
        fs::write(&replacement, b"after!")?;
        File::open(&replacement)?.set_times(fs::FileTimes::new().set_modified(mtime))?;
        fs::rename(&replacement, &path)?;
        let after = SyncDbEpoch::from_sync_dir(directory.path())?;
        assert_ne!(before, after);
        assert!(!is_cache_reusable(
            Some(before),
            after,
            true,
            Some(SystemTime::now())
        ));
        assert!(is_cache_reusable(
            Some(after),
            after,
            true,
            Some(SystemTime::now())
        ));
        Ok(())
    }

    #[test]
    fn sync_identity_tracks_symlink_targets_and_rejects_dangling_links() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let sync = directory.path().join("sync");
        fs::create_dir(&sync)?;
        let target = directory.path().join("target.db");
        fs::write(&target, b"one")?;
        std::os::unix::fs::symlink(&target, sync.join("core.db"))?;
        let before = SyncDbEpoch::from_sync_dir(&sync)?;
        fs::write(&target, b"different size")?;
        assert_ne!(before, SyncDbEpoch::from_sync_dir(&sync)?);
        fs::remove_file(&target)?;
        assert!(SyncDbEpoch::from_sync_dir(&sync).is_err());
        Ok(())
    }

    #[test]
    fn sync_identity_cache_uses_versioned_namespace() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let cache = DbCache {
            last_modified: Some(SyncDbEpoch::from_sync_dir(directory.path())?),
            ..DbCache::default()
        };
        fs::write(directory.path().join("sync_db.bin"), b"legacy cache")?;
        fs::write(
            directory.path().join("sync_db_source_v1.bin"),
            bitcode::serialize(&cache)?,
        )?;
        let decoded: DbCache = load_cache_from_disk_in(directory.path(), "sync_db_source_v1")?;
        assert_eq!(decoded.last_modified, cache.last_modified);
        assert_eq!(
            fs::read(directory.path().join("sync_db.bin"))?,
            b"legacy cache"
        );
        Ok(())
    }

    #[test]
    fn invalidate_derived_cache_files_removes_live_and_legacy_names() -> Result<()> {
        let directory = tempfile::tempdir()?;
        for name in [
            "sync_db_source_v1.bin",
            "local_db_source_v1.bin",
            "sync_db.bin",
            "local_db_rdeps.bin",
            "local_db.bin",
            "unrelated.bin",
        ] {
            fs::write(directory.path().join(name), b"cache")?;
        }
        invalidate_derived_cache_files(directory.path())?;
        for name in [
            "sync_db_source_v1.bin",
            "local_db_source_v1.bin",
            "sync_db.bin",
            "local_db_rdeps.bin",
            "local_db.bin",
        ] {
            assert!(
                !directory.path().join(name).exists(),
                "{name} must be removed"
            );
        }
        assert_eq!(fs::read(directory.path().join("unrelated.bin"))?, b"cache");
        invalidate_derived_cache_files(directory.path())?;
        Ok(())
    }

    #[test]
    fn sync_directory_additions_and_removals_change_cache_identity() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let database = temp_dir.path().join("core.db");
        let empty = SyncDbEpoch::from_sync_dir(temp_dir.path()).unwrap();
        assert_ne!(empty, SyncDbEpoch::UNIX_EPOCH);

        std::fs::write(&database, b"database").unwrap();
        let populated = SyncDbEpoch::from_sync_dir(temp_dir.path()).unwrap();
        assert_ne!(populated, empty);

        std::fs::remove_file(database).unwrap();
        let removed = SyncDbEpoch::from_sync_dir(temp_dir.path()).unwrap();
        assert_ne!(removed, populated);
    }

    #[test]
    fn catalog_epoch_changes_when_local_db_changes() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let older = AlpmCatalogEpoch::UNIX_EPOCH;
        std::fs::write(temp_dir.path().join("ALPM_DB_VERSION"), b"9\n").unwrap();
        let newer = AlpmCatalogEpoch {
            sync: SyncDbEpoch::UNIX_EPOCH,
            local: LocalDbEpoch::from_local_dir(temp_dir.path()).unwrap(),
        };
        assert_ne!(newer, older);
        assert_ne!(newer.local, older.local);
        assert_eq!(newer.sync, older.sync);
    }

    #[test]
    fn sync_identity_unreadable_directory_errors() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let original = std::fs::metadata(temp_dir.path()).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(temp_dir.path(), std::fs::Permissions::from_mode(0o000))
                .unwrap();
        }
        let blocked = std::fs::read_dir(temp_dir.path()).is_err();
        let result = SyncDbEpoch::from_sync_dir(temp_dir.path());
        let _ = std::fs::set_permissions(temp_dir.path(), original);
        if !blocked {
            return;
        }
        assert!(
            result.is_err(),
            "unreadable sync dir must fail closed, got {result:?}"
        );
    }

    #[test]
    fn test_remove_cache_file_allows_missing() {
        let missing = tempfile::TempDir::new()
            .unwrap()
            .path()
            .join("does-not-exist.bin");
        remove_cache_file(&missing).unwrap();
    }

    #[test]
    fn test_remove_cache_file_rejects_directory() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let error = remove_cache_file(temp_dir.path()).expect_err("directory is not a cache file");
        assert!(
            error
                .to_string()
                .contains("Failed to remove package cache file"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn test_get_local_package() {
        // Only run if we have a real system
        if crate::core::paths::pacman_local_dir().exists() {
            // pacman should always be installed
            if let Ok(Some(pkg)) = get_local_package("pacman") {
                assert!(!pkg.version.to_string().is_empty());
            }
        }
    }

    #[test]
    fn test_get_package_counts_consistent_on_real_systems() {
        if crate::core::paths::pacman_local_dir().exists() {
            let (total, explicit, deps) = match get_counts_fast() {
                Ok(counts) => counts,
                Err(e) => unreachable!("Failed to get counts: {e}"),
            };
            assert!(total > 0);
            // `deps` counts TRUE ORPHANS only, which are a subset of the
            // non-explicit packages — not a disjoint class that closes the
            // accounting equation (most dependencies have dependants).
            assert!(explicit <= total);
            assert!(explicit + deps <= total);
        }
    }

    /// Fixture helper: writes local desc files shaped like modern pacman's
    /// output — no `%REQUIREDBY%`/`%OPTFOR%` sections ever — so reverse
    /// dependencies exist only in other packages' `%DEPENDS%`/`%OPTDEPENDS%`
    /// sections, exactly like `pacman -Qdt` sees them.
    fn write_local_desc(temp: &tempfile::TempDir, name: &str, reason: &str, extra: &str) {
        let dir = temp.path().join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("desc"),
            format!("%NAME%\n{name}\n\n%VERSION%\n1.0-1\n\n%REASON%\n{reason}\n{extra}"),
        )
        .unwrap();
    }

    /// Parse the fixture db and apply the canonical orphan rule with
    /// reverse dependencies derived from `%DEPENDS%`/`%PROVIDES%`.
    fn fixture_orphans(temp: &tempfile::TempDir) -> Vec<String> {
        let packages = parse_local_db(temp.path()).unwrap();
        let required = compute_required_names(&packages);
        let mut orphans: Vec<String> = packages
            .iter()
            .filter(|(name, pkg)| {
                crate::package_managers::types::is_orphan_package(
                    pkg.explicit,
                    !required.contains(name.as_str()),
                )
            })
            .map(|(name, _)| name.clone())
            .collect();
        orphans.sort();
        orphans
    }

    #[test]
    fn dependency_base_name_strips_version_constraints_and_sonames() {
        assert_eq!(dependency_base_name("curl"), "curl");
        assert_eq!(dependency_base_name("curl>=7.0"), "curl");
        assert_eq!(dependency_base_name("libfoo.so=1-64"), "libfoo.so");
    }

    /// Regression (audit ARCH-R1): a dependency whose desc lacks the dead
    /// `%REQUIREDBY%` section — as every modern pacman desc does — but which
    /// another package's `%DEPENDS%` names is NOT an orphan. The fast path
    /// previously counted every such package as an orphan.
    #[test]
    fn required_dependency_without_requireby_section_is_not_an_orphan() {
        let temp = tempfile::TempDir::new().unwrap();
        write_local_desc(&temp, "app-main", "0", "\n%DEPENDS%\nlib-used>=1.0\n");
        write_local_desc(&temp, "lib-used", "1", "");

        let packages = parse_local_db(temp.path()).unwrap();
        assert_eq!(packages["app-main"].depends, ["lib-used>=1.0".to_string()]);
        assert!(packages["lib-used"].depends.is_empty());

        assert!(!fixture_orphans(&temp).contains(&"lib-used".to_string()));
    }

    /// Under `pacman -Qdt` rules ("print only packages neither required nor
    /// optionally required by any currently installed package"), a dependency
    /// that appears in another package's `%OPTDEPENDS%` is NOT an orphan.
    #[test]
    fn optdepend_package_is_not_orphan_under_pacman_qdt_rules() {
        let temp = tempfile::TempDir::new().unwrap();
        write_local_desc(
            &temp,
            "app-main",
            "0",
            "\n%OPTDEPENDS%\nlib-opt: extra features\n",
        );
        write_local_desc(&temp, "lib-opt", "1", "");

        assert!(fixture_orphans(&temp).is_empty());
    }

    /// A dependency with neither direct dependents nor optional dependents IS an orphan.
    #[test]
    fn unrequired_dependency_is_counted_as_orphan() {
        let temp = tempfile::TempDir::new().unwrap();
        write_local_desc(&temp, "app-main", "0", "");
        write_local_desc(&temp, "lonely-dep", "1", "");

        assert_eq!(fixture_orphans(&temp), ["lonely-dep"]);
    }

    /// Explicitly installed packages are never orphans, even when unrequired.
    #[test]
    fn explicit_packages_are_never_orphans() {
        let temp = tempfile::TempDir::new().unwrap();
        write_local_desc(&temp, "explicit-tool", "0", "");
        write_local_desc(&temp, "explicit-with-deps", "0", "\n%DEPENDS%\nsome-lib\n");
        write_local_desc(&temp, "some-lib", "1", "");
        write_local_desc(&temp, "lonely-dep", "1", "");

        let orphans = fixture_orphans(&temp);
        assert_eq!(orphans, ["lonely-dep"]);
        assert!(!orphans.contains(&"explicit-tool".to_string()));
        assert!(!orphans.contains(&"explicit-with-deps".to_string()));
    }

    /// A dependency satisfied through `%PROVIDES%` keeps its provider alive,
    /// matching libalpm's reverse-dependency resolution.
    #[test]
    fn provides_satisfies_virtual_dependency_for_orphan_counting() {
        let temp = tempfile::TempDir::new().unwrap();
        write_local_desc(&temp, "app-virtual", "0", "\n%DEPENDS%\nvirtual-svc\n");
        write_local_desc(&temp, "lib-provides", "1", "\n%PROVIDES%\nvirtual-svc\n");
        write_local_desc(&temp, "lonely-dep", "1", "");

        assert_eq!(fixture_orphans(&temp), ["lonely-dep"]);
    }

    /// Isolated fixture pinning the orphan-accounting rule end to end:
    /// under `pacman -Qdt` semantics exactly the never-required dependency
    /// is an orphan, while required, virtually-required, and explicit
    /// packages are not.
    #[test]
    fn orphan_accounting_matches_is_orphan_package_on_synthetic_local_db() {
        let temp = tempfile::TempDir::new().unwrap();
        write_local_desc(&temp, "explicit-tool", "0", "");
        write_local_desc(
            &temp,
            "app-main",
            "0",
            "\n%DEPENDS%\nlib-used>=1.0\n\n%OPTDEPENDS%\nlib-opt: extra features\n",
        );
        write_local_desc(&temp, "lib-used", "1", "");
        write_local_desc(&temp, "lib-opt", "1", "");
        write_local_desc(&temp, "lib-provides", "1", "\n%PROVIDES%\nvirtual-svc\n");
        write_local_desc(&temp, "app-virtual", "0", "\n%DEPENDS%\nvirtual-svc\n");
        write_local_desc(&temp, "lonely-orphan", "1", "");

        let packages = parse_local_db(temp.path()).unwrap();
        assert_eq!(packages.len(), 7);
        let required = compute_required_names(&packages);
        assert_eq!(
            required.len(),
            3,
            "lib-used + lib-opt + lib-provides: {required:?}"
        );
        assert_eq!(fixture_orphans(&temp), ["lonely-orphan"]);
    }

    /// The pure-Rust fast path and the libalpm-backed path must agree on the
    /// same fixture local database (counts including orphan classification).
    #[test]
    #[serial_test::serial]
    fn fast_path_and_libalpm_counts_agree_on_fixture_local_db() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        let db_dir = root.join("var/lib/pacman");
        let local_dir = db_dir.join("local");
        std::fs::create_dir_all(&local_dir).unwrap();
        // libalpm refuses a local database without its schema version file.
        std::fs::write(local_dir.join("ALPM_DB_VERSION"), "9\n").unwrap();

        let write_alpm_desc = |name: &str, reason: &str, extra: &str| {
            let dir = local_dir.join(format!("{name}-1.0-1"));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("desc"),
                format!("%NAME%\n{name}\n\n%VERSION%\n1.0-1\n\n%REASON%\n{reason}\n{extra}"),
            )
            .unwrap();
        };
        write_alpm_desc("explicit-tool", "0", "");
        write_alpm_desc(
            "app-main",
            "0",
            "\n%DEPENDS%\nlib-used>=1.0\n\n%OPTDEPENDS%\nlib-opt: extra features\n",
        );
        write_alpm_desc("lib-used", "1", "");
        write_alpm_desc("lib-opt", "1", "");
        write_alpm_desc("lib-provides", "1", "\n%PROVIDES%\nvirtual-svc\n");
        write_alpm_desc("app-virtual", "0", "\n%DEPENDS%\nvirtual-svc\n");
        write_alpm_desc("lonely-orphan", "1", "");

        let conf = temp.path().join("pacman.conf");
        std::fs::write(&conf, "[options]\n").unwrap();
        let cache_dir = temp.path().join("cache");
        std::fs::create_dir_all(&cache_dir).unwrap();

        crate::package_managers::alpm_direct::clear_alpm_cache();
        crate::core::paths::set_test_overrides(Some(root), Some(db_dir));
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                crate::core::paths::reset_test_overrides();
                crate::package_managers::alpm_direct::clear_alpm_cache();
            }
        }
        let _restore = Restore;

        let expected = (7, 3, 1);
        temp_env::with_vars(
            [
                ("OMG_PACMAN_CONF", Some(conf.to_str().unwrap())),
                ("OMG_CACHE_DIR", Some(cache_dir.to_str().unwrap())),
            ],
            || {
                let fast = get_counts_fast().expect("fast-path counts must succeed");
                let ffi = crate::package_managers::alpm_direct::get_counts()
                    .expect("libalpm counts must succeed");
                assert_eq!(fast, expected, "fast path diverged on fixture");
                assert_eq!(ffi, expected, "libalpm path diverged on fixture");
                assert_eq!(fast, ffi, "fast path and libalpm path must agree");
            },
        );
    }

    #[test]
    fn test_is_cache_reusable_rejects_expired_entries() {
        let now = SystemTime::now();
        let expired = now - std::time::Duration::from_secs(CACHE_TTL_SECS + 5);

        assert!(!is_cache_reusable(Some(now), now, true, Some(expired)));
    }

    #[test]
    fn test_is_cache_reusable_rejects_empty_entries() {
        let now = SystemTime::now();
        let fresh = now - std::time::Duration::from_secs(1);

        assert!(!is_cache_reusable(Some(now), now, false, Some(fresh)));
    }

    #[test]
    fn package_cache_round_trips_through_atomic_persist() {
        let temp = tempfile::TempDir::new().unwrap();
        let cache = LocalDbCache {
            packages: HashMap::from([(
                "firefox".to_string(),
                LocalDbPackage {
                    name: "firefox".to_string(),
                    ..Default::default()
                },
            )]),
            last_modified: Some(LocalDbEpoch::from_local_dir(temp.path()).unwrap()),
            last_accessed: None,
        };

        fs::write(temp.path().join("local_db_rdeps.bin"), b"legacy cache").unwrap();
        save_cache_to_disk_in(&cache, temp.path(), "local_db_source_v1").unwrap();
        let loaded: LocalDbCache =
            load_cache_from_disk_in(temp.path(), "local_db_source_v1").unwrap();
        assert!(loaded.packages.contains_key("firefox"));
        assert_eq!(loaded.last_modified, cache.last_modified);
        assert_eq!(
            fs::read(temp.path().join("local_db_rdeps.bin")).unwrap(),
            b"legacy cache"
        );
    }

    #[test]
    fn package_cache_persist_refuses_to_clobber_a_directory() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(temp.path().join("local_db.bin")).unwrap();

        let error = save_cache_to_disk_in(&LocalDbCache::default(), temp.path(), "local_db")
            .expect_err("must refuse to persist over a directory");
        assert!(!error.to_string().is_empty());
    }

    #[test]
    fn test_is_cache_reusable_accepts_fresh_matching_cache() {
        let now = SystemTime::now();
        let fresh = now - std::time::Duration::from_secs(2);

        assert!(is_cache_reusable(Some(now), now, true, Some(fresh)));
    }
}
