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
use std::collections::{HashMap, HashSet};
use std::fs;
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

use crate::core::pacman_conf::{PacmanConfig, RepoUsage};
use crate::core::paths;
use crate::runtimes::common::{BudgetedReader, BudgetedSink, BudgetedWriter, decode_xz_to};

/// TTL for cache eviction safety net (30 minutes)
const CACHE_TTL_SECS: u64 = 30 * 60;
const MAX_DESC_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SYNC_ENTRIES: usize = 100_000;
const MAX_DERIVED_CACHE_BYTES: u64 = 512 * 1024 * 1024;
const SYNC_CACHE_NAME: &str = "sync_db_source_v5";
const LOCAL_CACHE_NAME: &str = "local_db_source_v5";

/// Sync database cache, validated against its source identity on reuse.
static SYNC_DB_CACHE: std::sync::LazyLock<RwLock<DbCache>> =
    std::sync::LazyLock::new(|| RwLock::new(DbCache::default()));

/// Global cache for local database
static LOCAL_DB_CACHE: std::sync::LazyLock<RwLock<LocalDbCache>> =
    std::sync::LazyLock::new(|| RwLock::new(LocalDbCache::default()));

#[derive(Default, Serialize, Deserialize)]
struct DbCache {
    packages: Vec<RepositoryPackages>,
    last_modified: Option<SyncDbEpoch>,
    #[serde(skip)]
    last_accessed: Option<SystemTime>,
}

#[derive(Serialize, Deserialize)]
struct RepositoryPackages {
    name: String,
    usage: RepoUsage,
    packages: std::result::Result<HashMap<String, SyncDbPackage>, String>,
}

impl DbCache {
    fn validate_usage(&self, usage: RepoUsage) -> Result<()> {
        for repository in &self.packages {
            if !repository.usage.intersects(usage) {
                continue;
            }
            repository.packages.as_ref().map_err(|error| {
                anyhow::anyhow!(
                    "Repository '{}' is unavailable or incomplete: {error}. Run 'omg sync' and retry",
                    repository.name
                )
            })?;
        }
        Ok(())
    }

    fn get_validated(&self, name: &str, usage: RepoUsage) -> Option<&SyncDbPackage> {
        for repository in &self.packages {
            if !repository.usage.intersects(usage) {
                continue;
            }
            if let Ok(packages) = repository.packages.as_ref()
                && let Some(package) = packages.get(name)
            {
                return Some(package);
            }
        }
        None
    }

    fn select(&self, usage: RepoUsage) -> Result<HashMap<&str, &SyncDbPackage>> {
        let mut selected = HashMap::with_capacity(20_000);
        for repository in &self.packages {
            if !repository.usage.intersects(usage) {
                continue;
            }
            let packages = repository.packages.as_ref().map_err(|error| {
                anyhow::anyhow!(
                    "Repository '{}' is unavailable or incomplete: {error}. Run 'omg sync' and retry",
                    repository.name
                )
            })?;
            for (name, package) in packages {
                selected.entry(name.as_str()).or_insert(package);
            }
        }
        Ok(selected)
    }
}

fn load_sync_packages(sync_dir: &Path) -> Result<Vec<RepositoryPackages>> {
    let config = PacmanConfig::parse(paths::pacman_conf_path())
        .context("Failed to read pacman repository policy")?;
    let available: HashMap<_, _> = collect_sync_db_paths_with_config(sync_dir, &config)?
        .into_iter()
        .map(|(path, name)| (name, path))
        .collect();
    Ok(config
        .repos
        .par_iter()
        .map(|repo| {
            let path = available
                .get(&repo.name)
                .cloned()
                .unwrap_or_else(|| sync_dir.join(format!("{}.db", repo.name)));
            RepositoryPackages {
                name: repo.name.clone(),
                usage: repo.usage,
                packages: parse_sync_db(&path, &repo.name)
                    .map_err(|error| format!("{}: {error:#}", path.display())),
            }
        })
        .collect())
}

#[cfg(test)]
fn collect_sync_db_paths(sync_dir: &Path) -> Result<Vec<(PathBuf, String)>> {
    if !sync_dir.exists() {
        return Ok(Vec::new());
    }
    let config = crate::core::pacman_conf::PacmanConfig::parse(paths::pacman_conf_path())
        .context("Failed to read pacman repository priority")?;
    collect_sync_db_paths_with_config(sync_dir, &config)
}

fn collect_sync_db_paths_with_config(
    sync_dir: &Path,
    config: &PacmanConfig,
) -> Result<Vec<(PathBuf, String)>> {
    if !sync_dir.exists() {
        return Ok(Vec::new());
    }

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
    #[serde(deserialize_with = "deserialize_package_version")]
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
    #[serde(deserialize_with = "deserialize_package_version")]
    pub version: Version,
    pub desc: String,
    pub install_date: String,
    pub url: Option<String>,
    pub size: u64,
    pub licenses: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
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
            url: None,
            size: 0,
            licenses: Vec::new(),
            groups: Vec::new(),
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
    let mut packages = HashMap::new();
    parse_sync_db_into(
        path,
        repo_name,
        &|desc| desc.into_package(repo_name),
        &mut |entry, package| {
            anyhow::ensure!(
                packages.insert(package.name.clone(), package).is_none(),
                "Duplicate package identity in {} from repository {repo_name}",
                entry.display()
            );
            Ok(())
        },
    )?;
    Ok(packages)
}

/// Validate the entire catalog while retaining only one requested package.
/// Unrelated metadata, duplicate names and the compressed footer still matter.
pub(crate) fn parse_sync_db_package(
    path: &Path,
    repo_name: &str,
    name: &str,
) -> Result<Option<SyncDbPackage>> {
    let mut names = std::collections::HashSet::new();
    let mut selected = None;
    parse_sync_db_into(
        path,
        repo_name,
        &|desc| {
            let identity = desc.name().to_owned();
            let package = (identity == name).then(|| desc.into_package(repo_name));
            (identity, package)
        },
        &mut |entry, (identity, package)| {
            anyhow::ensure!(
                names.insert(identity),
                "Duplicate package identity in {} from repository {repo_name}",
                entry.display()
            );
            if let Some(package) = package {
                selected = Some(package);
            }
            Ok(())
        },
    )?;
    Ok(selected)
}

fn parse_sync_db_into<T: Send>(
    path: &Path,
    repo_name: &str,
    project: &(impl Fn(ParsedSyncDesc) -> T + Sync),
    collect: &mut impl FnMut(&Path, T) -> Result<()>,
) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("Failed to open {}", path.display()))?;
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "Pacman sync database is not a regular file: {}",
        path.display()
    );

    let reader: Box<dyn Read> = {
        let mut probe = [0u8; 263];
        let probe_len = file.read(&mut probe)?;
        file.rewind()?;

        if probe.starts_with(&[0x1f, 0x8b]) {
            Box::new(BudgetedReader::new(
                GzDecoder::new(file),
                BudgetedSink::max_budget(),
            ))
        } else if probe.starts_with(b"BZh") {
            Box::new(BudgetedReader::new(
                bzip2::read::MultiBzDecoder::new(file),
                BudgetedSink::max_budget(),
            ))
        } else if probe.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
            let decoder = ruzstd::decoding::StreamingDecoder::new(file)
                .map_err(|e| anyhow::anyhow!("zstd init: {e}"))?;
            Box::new(BudgetedReader::new(decoder, BudgetedSink::max_budget()))
        } else if probe.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
            let mut output = BudgetedWriter::new(Vec::new(), BudgetedSink::max_budget());
            decode_xz_to(BufReader::new(file), &mut output)
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

    let mut archive = tar::Archive::new(BufReader::with_capacity(64 * 1024, reader));
    let mut entry_count = 0usize;
    let mut descriptions = Vec::new();
    let mut buffered_bytes = 0usize;

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
            buffered_bytes += raw.len() + entry_path.as_os_str().len();
            descriptions.push((entry_path, raw));
            if descriptions.len() == 512 || buffered_bytes >= 1024 * 1024 {
                parse_sync_descriptions(&mut descriptions, repo_name, project, collect)?;
                buffered_bytes = 0;
            }
        }
    }

    parse_sync_descriptions(&mut descriptions, repo_name, project, collect)?;

    std::io::copy(&mut archive.into_inner(), &mut std::io::sink()).with_context(|| {
        format!(
            "Failed to finish decoding repository database {}",
            path.display()
        )
    })?;
    Ok(())
}

fn parse_sync_desc(entry_path: &Path, raw: Vec<u8>, repo_name: &str) -> Result<ParsedSyncDesc> {
    let content = String::from_utf8(raw).with_context(|| {
        format!(
            "Invalid UTF-8 in {} from repository {repo_name}",
            entry_path.display()
        )
    })?;
    let pkg = parse_desc_content(&content, repo_name).with_context(|| {
        format!(
            "Malformed desc {} from repository {repo_name}",
            entry_path.display()
        )
    })?;
    anyhow::ensure!(
        !pkg.name().is_empty(),
        "Missing package name in {} from repository {repo_name}",
        entry_path.display()
    );
    let package_version = pkg.canonical_version();
    require_package_version(&package_version)?;
    let directory = entry_path
        .parent()
        .and_then(Path::to_str)
        .context("Invalid sync package directory identity")?;
    anyhow::ensure!(
        !directory.contains('/'),
        "Nested sync package directory identity in {} from repository {repo_name}",
        entry_path.display()
    );
    alpm_types::Name::from_str(pkg.name()).with_context(|| {
        format!(
            "Invalid package name in {} from repository {repo_name}",
            entry_path.display()
        )
    })?;
    let (before_release, _) = directory
        .rsplit_once('-')
        .context("Missing sync package release in directory identity")?;
    let (native_name, _) = before_release
        .rsplit_once('-')
        .context("Missing sync package version in directory identity")?;
    let native_version = require_package_version(&directory[native_name.len() + 1..])?;
    anyhow::ensure!(
        native_name == pkg.name() && native_version.to_string() == package_version,
        "Inconsistent package identity in {} from repository {repo_name}",
        entry_path.display()
    );
    Ok(pkg)
}

fn parse_sync_descriptions<T: Send>(
    descriptions: &mut Vec<(PathBuf, Vec<u8>)>,
    repo_name: &str,
    project: &(impl Fn(ParsedSyncDesc) -> T + Sync),
    collect: &mut impl FnMut(&Path, T) -> Result<()>,
) -> Result<()> {
    static POOL: std::sync::LazyLock<Option<rayon::ThreadPool>> = std::sync::LazyLock::new(|| {
        let workers = std::thread::available_parallelism().map_or(1, |count| count.get().min(4));
        match rayon::ThreadPoolBuilder::new().num_threads(workers).build() {
            Ok(pool) => Some(pool),
            Err(error) => {
                tracing::warn!(
                    "Cannot start repository parsing workers; parsing serially: {error}"
                );
                None
            }
        }
    });
    if descriptions.is_empty() {
        return Ok(());
    }
    let minimum_records = descriptions.len().div_ceil(4).max(16);
    let entries = std::mem::take(descriptions);
    let parse = |(path, raw): (PathBuf, Vec<u8>)| {
        let package = parse_sync_desc(&path, raw, repo_name).map(project);
        (path, package)
    };
    let parsed: Vec<_> = match &*POOL {
        Some(pool) => pool.install(|| {
            entries
                .into_par_iter()
                .with_min_len(minimum_records)
                .map(parse)
                .collect()
        }),
        None => entries.into_iter().map(parse).collect(),
    };
    for (path, package) in parsed {
        collect(&path, package?)?;
    }
    Ok(())
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
            version: Version::from($desc.version),
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

enum ParsedSyncDesc {
    V2(alpm_repo_db::desc::RepoDescFileV2),
    V1(alpm_repo_db::desc::RepoDescFileV1),
    Manual(SyncDbPackage),
}

impl ParsedSyncDesc {
    fn name(&self) -> &str {
        match self {
            Self::V2(desc) => desc.name.as_ref(),
            Self::V1(desc) => desc.name.as_ref(),
            Self::Manual(package) => &package.name,
        }
    }

    fn canonical_version(&self) -> String {
        match self {
            Self::V2(desc) => desc.version.to_string(),
            Self::V1(desc) => desc.version.to_string(),
            Self::Manual(package) => package.version.to_string(),
        }
    }

    fn into_package(self, repo: &str) -> SyncDbPackage {
        match self {
            Self::V2(desc) => sync_pkg_from_desc!(desc, repo),
            Self::V1(desc) => sync_pkg_from_desc!(desc, repo),
            Self::Manual(package) => package,
        }
    }
}

fn parse_desc_content(content: &str, repo: &str) -> Result<ParsedSyncDesc> {
    // Try V2 first (newer format without MD5SUM).
    // Wrap in catch_unwind because alpm_repo_db can panic on corrupted data
    // (e.g., PackageRelation::from_str panics on malformed dependency strings).
    let v2_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        alpm_repo_db::desc::RepoDescFileV2::from_str(content)
    }));

    match v2_result {
        Ok(Ok(desc)) => return Ok(ParsedSyncDesc::V2(desc)),
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
        Ok(Ok(desc)) => return Ok(ParsedSyncDesc::V1(desc)),
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
    parse_desc_manual(content, repo).map(ParsedSyncDesc::Manual)
}

fn parse_desc_manual(content: &str, repo: &str) -> Result<SyncDbPackage> {
    validate_desc_cardinality(
        content,
        &[
            "%NAME%",
            "%VERSION%",
            "%DESC%",
            "%URL%",
            "%ARCH%",
            "%CSIZE%",
            "%ISIZE%",
            "%FILENAME%",
        ],
    )?;
    let mut pkg = SyncDbPackage {
        repo: repo.to_string(),
        ..SyncDbPackage::default()
    };

    let mut current_section = "";
    let mut has_version = false;
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
                has_version = true;
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

    anyhow::ensure!(has_version, "Missing package version in repository {repo}");
    Ok(pkg)
}

fn validate_desc_cardinality(content: &str, scalar_sections: &[&str]) -> Result<()> {
    // Sparse vendor records still follow the upstream section cardinality rules.
    let mut sections = HashSet::new();
    let mut scalar = None;
    let mut value_seen = false;
    for line in content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if line.starts_with('%') && line.ends_with('%') {
            anyhow::ensure!(
                sections.insert(line),
                "Duplicate descriptor section {}",
                crate::cli::style::sanitize_terminal_text(line)
            );
            scalar = scalar_sections.contains(&line).then_some(line);
            value_seen = false;
        } else if let Some(section) = scalar {
            anyhow::ensure!(
                !value_seen,
                "Multiple values in descriptor section {section}"
            );
            value_seen = true;
        }
    }
    Ok(())
}

/// Doctor resolves dependencies from one validated package snapshot.
#[cfg(test)]
pub(crate) fn check_local_db_health(path: &Path) -> Result<(usize, Vec<UnsatisfiedDependency>)> {
    let snapshot = LocalHealthSnapshot::capture(path)?;
    validate_health_relations(&snapshot.packages)?;
    let missing = unsatisfied_dependencies(&snapshot.packages);
    snapshot.revalidate(path)?;
    Ok((snapshot.packages.len(), missing))
}

/// Offline health results from the validated Rust snapshot and native ALPM.
/// No sync databases, transactions, package hooks or external manager are used.
pub(crate) struct NativeLocalDbHealth {
    pub packages: usize,
    pub missing: Vec<UnsatisfiedDependency>,
    pub native: Result<()>,
}

pub(crate) async fn check_native_local_db_health(path: &Path) -> Result<NativeLocalDbHealth> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        anyhow::ensure!(
            path.is_absolute(),
            "ALPM local database path must be absolute"
        );
        anyhow::ensure!(
            path.file_name() == Some(std::ffi::OsStr::new("local")),
            "Native ALPM check requires a local directory under its database path"
        );
        let snapshot = LocalHealthSnapshot::capture(&path)?;
        validate_health_relations(&snapshot.packages)?;
        let missing = unsatisfied_dependencies(&snapshot.packages);
        let result = inspect_native_local_database(&path, &snapshot);
        snapshot.revalidate(&path)?;
        Ok(NativeLocalDbHealth {
            packages: snapshot.packages.len(),
            missing,
            native: result,
        })
    })
    .await
    .context("Native local database health check task failed")?
}

fn inspect_native_local_database(path: &Path, snapshot: &LocalHealthSnapshot) -> Result<()> {
    let database = path.parent().context("ALPM local database has no parent")?;
    let handle = crate::package_managers::alpm_ops::open_alpm_at(Path::new("/"), database)?;
    handle
        .localdb()
        .is_valid()
        .context("Invalid native local database")?;
    let packages = handle.localdb().pkgs();
    anyhow::ensure!(
        packages.len() == snapshot.packages.len(),
        "Native local database inventory is incomplete"
    );
    for package in packages {
        let observed = snapshot
            .packages
            .get(package.name())
            .context("Native local database inventory differs from the validated snapshot")?;
        // Rust ALPM omits the implied zero epoch, which libalpm can still report.
        let native_version = package.version().as_str();
        let native_version = native_version.strip_prefix("0:").unwrap_or(native_version);
        anyhow::ensure!(
            native_version == observed.version.to_string(),
            "Native local database version differs for {}",
            package.name()
        );
    }
    let empty = std::iter::empty::<&alpm::Pkg>();
    let missing = handle.check_deps(empty.clone(), empty, packages.iter(), false);
    if let Some(dependency) = missing.iter().next() {
        anyhow::bail!(
            "Installed package {} requires {}",
            crate::cli::style::sanitize_terminal_text(dependency.target()),
            crate::cli::style::sanitize_terminal_text(&dependency.depend().to_string())
        );
    }
    let conflicts = handle.check_conflicts(packages.iter());
    if let Some(conflict) = conflicts.iter().next() {
        anyhow::bail!(
            "Installed package conflict: {} and {} ({})",
            crate::cli::style::sanitize_terminal_text(conflict.package1().name()),
            crate::cli::style::sanitize_terminal_text(conflict.package2().name()),
            crate::cli::style::sanitize_terminal_text(&conflict.reason().to_string())
        );
    }
    let mut owners = HashMap::new();
    for package in packages {
        for file in package.files().files() {
            let name = file.name();
            if name.ends_with(b"/") {
                continue;
            }
            if let Some(previous) = owners.insert(name, package.name()) {
                anyhow::ensure!(
                    previous == package.name(),
                    "Duplicate installed file ownership: {} and {} own {}",
                    crate::cli::style::sanitize_terminal_text(previous),
                    crate::cli::style::sanitize_terminal_text(package.name()),
                    crate::cli::style::sanitize_terminal_text(&String::from_utf8_lossy(name))
                );
            }
        }
    }
    Ok(())
}

struct LocalHealthSnapshot {
    packages: HashMap<String, LocalDbPackage>,
    fingerprints: std::collections::BTreeMap<PathBuf, Vec<u8>>,
}

fn health_identity(metadata: &fs::Metadata) -> Vec<u8> {
    let mut result = Vec::new();
    for value in [
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        u64::from(metadata.mode()),
    ] {
        result.extend_from_slice(&value.to_be_bytes());
    }
    for value in [
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    ] {
        result.extend_from_slice(&value.to_be_bytes());
    }
    result
}

fn health_file(path: &Path) -> Result<(Vec<u8>, Vec<u8>)> {
    let before = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        before.is_file(),
        "Local package file must be regular: {}",
        path.display()
    );
    anyhow::ensure!(
        before.len() <= MAX_DESC_BYTES,
        "Local package file exceeds size limit: {}",
        path.display()
    );
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("Failed to open local package file {}", path.display()))?;
    let identity = health_identity(&before);
    anyhow::ensure!(
        identity == health_identity(&file.metadata()?),
        "Local package file changed: {}",
        path.display()
    );
    let mut bytes = Vec::new();
    (&file).take(MAX_DESC_BYTES + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_DESC_BYTES,
        "Local package file exceeds size limit: {}",
        path.display()
    );
    anyhow::ensure!(
        identity == health_identity(&file.metadata()?)
            && identity == health_identity(&fs::symlink_metadata(path)?),
        "Local package file changed: {}",
        path.display()
    );
    let mut fingerprint = identity;
    fingerprint.extend_from_slice(&Sha256::digest(&bytes));
    Ok((bytes, fingerprint))
}

impl LocalHealthSnapshot {
    fn capture(path: &Path) -> Result<Self> {
        let mut packages = HashMap::new();
        let fingerprints = Self::observe(path, Some(&mut packages))?;
        Ok(Self {
            packages,
            fingerprints,
        })
    }

    fn revalidate(&self, path: &Path) -> Result<()> {
        anyhow::ensure!(
            self.fingerprints == Self::observe(path, None)?,
            "Local package database changed during health inspection"
        );
        Ok(())
    }

    /// Revalidation checks identities and bytes, without another tolerant parse.
    fn observe(
        path: &Path,
        mut packages: Option<&mut HashMap<String, LocalDbPackage>>,
    ) -> Result<std::collections::BTreeMap<PathBuf, Vec<u8>>> {
        let root = fs::symlink_metadata(path).with_context(|| {
            format!(
                "Failed to observe local package database {}",
                path.display()
            )
        })?;
        anyhow::ensure!(
            root.is_dir(),
            "Local package database must be a nonsymlink directory"
        );
        let root_identity = health_identity(&root);
        let mut fingerprints = std::collections::BTreeMap::new();
        fingerprints.insert(PathBuf::new(), root_identity.clone());
        let mut directories = 0;
        let mut entries = 0;
        for entry in fs::read_dir(path)
            .with_context(|| format!("Failed to read local package database {}", path.display()))?
        {
            let entry = entry.context("Failed to enumerate local package database")?;
            entries += 1;
            anyhow::ensure!(
                entries <= 20_000,
                "Local package database has too many entries"
            );
            let relative = PathBuf::from(entry.file_name());
            let metadata = fs::symlink_metadata(entry.path())?;
            anyhow::ensure!(
                !metadata.file_type().is_symlink(),
                "Local package entry must not be a symlink"
            );
            let identity = health_identity(&metadata);
            fingerprints.insert(relative.clone(), identity.clone());
            if !metadata.is_dir() {
                continue;
            }
            directories += 1;
            for required in ["desc", "files"] {
                let file_path = entry.path().join(required);
                let (bytes, fingerprint) = health_file(&file_path).with_context(|| {
                    format!(
                        "Invalid local package entry {} {required}",
                        entry.path().display()
                    )
                })?;
                if required == "desc"
                    && let Some(ref mut packages) = packages
                {
                    let content =
                        std::str::from_utf8(&bytes).context("Local package desc is not UTF-8")?;
                    let package = parse_local_desc_content(content)?;
                    anyhow::ensure!(!package.name.is_empty(), "Local package entry has no name");
                    let name = package.name.clone();
                    anyhow::ensure!(
                        packages.insert(name.clone(), package).is_none(),
                        "Duplicate local package name {name}"
                    );
                }
                fingerprints.insert(relative.join(required), fingerprint);
            }
            anyhow::ensure!(
                identity == health_identity(&fs::symlink_metadata(entry.path())?),
                "Local package directory changed during health inspection"
            );
        }
        anyhow::ensure!(directories > 0, "Local package database is empty");
        anyhow::ensure!(
            root_identity == health_identity(&fs::symlink_metadata(path)?),
            "Local package database changed during health inspection"
        );
        Ok(fingerprints)
    }
}

/// Parse the local package database (/var/lib/pacman/local/)
/// Returns a `HashMap` of package name -> `LocalDbPackage`
pub fn parse_local_db(path: &Path) -> Result<HashMap<String, LocalDbPackage>> {
    if !path.try_exists().with_context(|| {
        format!(
            "Failed to inspect pacman local directory {}",
            path.display()
        )
    })? {
        return Ok(HashMap::new());
    }

    let mut desc_paths = Vec::with_capacity(2000);
    for entry in std::fs::read_dir(path)
        .with_context(|| format!("Failed to read pacman local directory {}", path.display()))?
    {
        let entry =
            entry.with_context(|| format!("Failed to read local entry in {}", path.display()))?;
        let pkg_path = entry.path();
        let meta = entry
            .metadata()
            .with_context(|| format!("Failed to inspect local entry {}", pkg_path.display()))?;
        if !meta.is_dir() {
            continue;
        }
        desc_paths.push(pkg_path.join("desc"));
    }

    let parsed: Vec<LocalDbPackage> = desc_paths
        .into_par_iter()
        .map(|desc_path| {
            parse_local_desc(&desc_path)
                .with_context(|| format!("Incomplete local package entry {}", desc_path.display()))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut packages = HashMap::with_capacity(parsed.len());
    for pkg in parsed {
        packages.insert(pkg.name.clone(), pkg);
    }

    Ok(packages)
}

fn require_package_version(raw: &str) -> Result<Version> {
    crate::package_managers::parse_version(raw)
        .with_context(|| format!("Invalid package version {raw:?}"))
}

fn deserialize_package_version<'de, D>(deserializer: D) -> std::result::Result<Version, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let version = Version::deserialize(deserializer)?;
    require_package_version(&version.to_string()).map_err(serde::de::Error::custom)
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

    parse_local_desc_content(&content)
}

fn parse_local_desc_content(content: &str) -> Result<LocalDbPackage> {
    use alpm_db::desc::DbDescFile;

    // Modern pacman never writes `%REQUIREDBY%`/`%OPTFOR%` sections into local
    // desc files, so reverse dependencies cannot be read from disk. They are
    // derived from `%DEPENDS%`/`%PROVIDES%` at query time (see
    // `compute_required_names`) under the canonical orphan rule
    // (`types::is_orphan_package`, `pacman -Qdt` semantics).
    let desc = match DbDescFile::from_str(content) {
        Ok(DbDescFile::V1(desc)) => desc,
        Ok(DbDescFile::V2(desc)) => desc.into(),
        Err(_) => match alpm_db::desc::DbDescFileV1::from_str(content) {
            Ok(desc) => desc,
            Err(_) => return parse_local_desc_manual(content),
        },
    };
    Ok(LocalDbPackage {
        name: desc.name.to_string(),
        version: require_package_version(&desc.version.to_string())?,
        desc: desc.description.to_string(),
        install_date: desc.installdate.to_string(),
        url: desc.url.as_ref().map(ToString::to_string),
        size: desc.size,
        licenses: desc.license.iter().map(ToString::to_string).collect(),
        groups: desc.groups.iter().map(ToString::to_string).collect(),
        explicit: matches!(desc.reason, alpm_types::PackageInstallReason::Explicit),
        depends: desc.depends.iter().map(ToString::to_string).collect(),
        optdepends: desc.optdepends.iter().map(ToString::to_string).collect(),
        provides: desc.provides.iter().map(ToString::to_string).collect(),
    })
}
/// Manual local desc parser as fallback
fn parse_local_desc_manual(content: &str) -> Result<LocalDbPackage> {
    validate_desc_cardinality(
        content,
        &[
            "%NAME%",
            "%VERSION%",
            "%DESC%",
            "%INSTALLDATE%",
            "%URL%",
            "%SIZE%",
            "%REASON%",
        ],
    )?;
    let mut name = String::new();
    let mut version = String::new();
    let mut desc = String::new();
    let mut install_date = String::new();
    let mut url = None;
    let mut size = 0;
    let mut reason = String::new();
    let mut licenses = Vec::new();
    let mut groups = Vec::new();
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
            Some("%URL%") => url = Some(line.to_string()),
            Some("%SIZE%") => {
                size = line.parse().context("Invalid %SIZE% value in local desc")?;
            }
            Some("%REASON%") => reason = line.to_string(),
            Some("%LICENSE%") => licenses.push(line.to_string()),
            Some("%GROUPS%") => groups.push(line.to_string()),
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
        url,
        size,
        licenses,
        groups,
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

fn open_package_cache_directory(path: &Path, create: bool) -> Result<fs::File> {
    use rustix::fs::{Mode, OFlags, mkdirat, open, openat};
    use std::path::Component;

    anyhow::ensure!(
        path.is_absolute(),
        "Package cache directory must be absolute"
    );
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let owner = nix::unistd::geteuid().as_raw();
    let mut directory = fs::File::from(open("/", flags, Mode::empty())?);
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let next = match openat(&directory, name, flags, Mode::empty()) {
                    Ok(next) => next,
                    Err(rustix::io::Errno::NOENT) if create => {
                        match mkdirat(&directory, name, Mode::RWXU) {
                            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                            Err(error) => return Err(error.into()),
                        }
                        openat(&directory, name, flags, Mode::empty())?
                    }
                    Err(error) => return Err(error.into()),
                };
                let next = fs::File::from(next);
                let metadata = next.metadata()?;
                // Root-owned sticky temporary directories are safe ancestors,
                // but the cache itself must have an exclusive writer below them.
                let sticky_root = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
                anyhow::ensure!(
                    (metadata.uid() == owner || metadata.uid() == 0)
                        && (metadata.mode() & 0o022 == 0 || sticky_root),
                    "Package cache has an untrusted ancestor: {}",
                    path.display()
                );
                directory = next;
            }
            _ => anyhow::bail!("Package cache path must not traverse parent directories"),
        }
    }
    let metadata = directory.metadata()?;
    anyhow::ensure!(
        metadata.uid() == owner && metadata.mode() & 0o022 == 0,
        "Package cache must be owned by the effective user and not writable by others"
    );
    Ok(directory)
}

fn save_cache_to_disk_in<T: Serialize>(cache: &T, cache_dir: &Path, name: &str) -> Result<()> {
    use rustix::fs::{Mode, OFlags, openat, renameat};

    let directory = open_package_cache_directory(cache_dir, true)?;
    let data = bitcode::serialize(cache)?;
    anyhow::ensure!(
        data.len() as u64 <= MAX_DERIVED_CACHE_BYTES,
        "Package cache exceeds size limit"
    );
    let temporary = format!(".{name}-{}.tmp", uuid::Uuid::new_v4());
    let mut file = fs::File::from(openat(
        &directory,
        &temporary,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )?);
    let result = (|| {
        file.write_all(&data)?;
        file.sync_all()?;
        renameat(&directory, &temporary, &directory, format!("{name}.bin"))?;
        directory.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        remove_temporary_package_cache(&directory, &temporary);
    }
    result
}

fn remove_temporary_package_cache(directory: &fs::File, temporary: &str) {
    if let Err(error) = rustix::fs::unlinkat(directory, temporary, rustix::fs::AtFlags::empty())
        && error != rustix::io::Errno::NOENT
    {
        tracing::warn!("Failed to remove temporary package cache: {error}");
    }
}

fn persist_cache_best_effort<T: Serialize>(cache: &T, name: &str) {
    if let Err(error) = save_cache_to_disk(cache, name) {
        tracing::warn!("Failed to persist {name} package cache: {error}");
    }
}

/// Load derived state only through the effective user's trusted cache directory.
fn load_cache_from_disk<T: for<'de> Deserialize<'de>>(name: &str) -> Result<T> {
    load_cache_from_disk_in(&paths::cache_dir(), name)
}

fn load_cache_from_disk_in<T: for<'de> Deserialize<'de>>(
    cache_dir: &Path,
    name: &str,
) -> Result<T> {
    use rustix::fs::{Mode, OFlags, openat};

    let directory = open_package_cache_directory(cache_dir, false)?;
    let file = fs::File::from(openat(
        &directory,
        format!("{name}.bin"),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let before = file.metadata()?;
    anyhow::ensure!(
        before.is_file()
            && before.uid() == nix::unistd::geteuid().as_raw()
            && before.mode() & 0o022 == 0
            && before.nlink() == 1,
        "Derived package cache must be a regular, singly linked file owned by the effective user and not writable by others"
    );
    anyhow::ensure!(
        before.len() <= MAX_DERIVED_CACHE_BYTES,
        "Package cache exceeds size limit"
    );
    let mut data = Vec::new();
    (&file)
        .take(MAX_DERIVED_CACHE_BYTES + 1)
        .read_to_end(&mut data)?;
    anyhow::ensure!(
        data.len() as u64 <= MAX_DERIVED_CACHE_BYTES,
        "Package cache exceeds size limit"
    );
    anyhow::ensure!(
        health_identity(&before) == health_identity(&file.metadata()?),
        "Package cache changed while reading"
    );
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
    type Packages;

    fn has_packages(&self) -> bool;
    type Epoch: Copy + Eq;

    fn packages_mut(&mut self) -> &mut Self::Packages;
    fn last_modified(&self) -> Option<Self::Epoch>;
    fn set_last_modified(&mut self, time: Option<Self::Epoch>);
    fn last_accessed(&self) -> Option<SystemTime>;
    fn set_last_accessed(&mut self, time: Option<SystemTime>);
}

impl PackageCache for DbCache {
    type Packages = Vec<RepositoryPackages>;

    fn has_packages(&self) -> bool {
        !self.packages.is_empty()
    }
    type Epoch = SyncDbEpoch;

    fn packages_mut(&mut self) -> &mut Self::Packages {
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
    type Packages = HashMap<String, LocalDbPackage>;

    fn has_packages(&self) -> bool {
        !self.packages.is_empty()
    }
    type Epoch = LocalDbEpoch;

    fn packages_mut(&mut self) -> &mut Self::Packages {
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
    load_fresh: impl FnOnce() -> Result<C::Packages>,
) -> Result<()> {
    let reusable = |cache: &C| {
        is_cache_reusable(
            cache.last_modified(),
            current_epoch,
            cache.has_packages(),
            cache.last_accessed(),
        )
    };
    let now = || Some(SystemTime::now());

    // Fast path: in-memory hit under shared read lock when recently accessed.
    {
        let cache = read_lock(cache_lock);
        if reusable(&cache)
            && cache
                .last_accessed()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|elapsed| elapsed.as_secs() < 5)
        {
            return Ok(());
        }
    }

    // Refresh TTL under brief write lock on warm hit.
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

/// Ensure sync cache is loaded for an already-observed epoch.
fn ensure_sync_cache_loaded_at(sync_dir: &Path, current_epoch: SyncDbEpoch) -> Result<()> {
    // Older cache generations may contain descriptors accepted before cardinality checks.
    ensure_cache_loaded(&SYNC_DB_CACHE, SYNC_CACHE_NAME, current_epoch, || {
        let packages = load_sync_packages(sync_dir)?;
        anyhow::ensure!(
            current_epoch == SyncDbEpoch::from_configured_sync_dir(sync_dir)?,
            "Package databases or configuration changed while loading; retry the operation"
        );
        Ok(packages)
    })
}

/// Ensure local cache is loaded for an already-observed epoch.
fn ensure_local_cache_loaded_at(local_dir: &Path, current_epoch: LocalDbEpoch) -> Result<()> {
    // Revalidate installed descriptors before using fields from an older generation.
    ensure_cache_loaded(&LOCAL_DB_CACHE, LOCAL_CACHE_NAME, current_epoch, || {
        let packages = parse_local_db(local_dir)?;
        #[cfg(test)]
        AFTER_LOCAL_PARSE.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                hook();
            }
        });
        anyhow::ensure!(
            current_epoch == LocalDbEpoch::from_local_dir(local_dir)?,
            "Local package database changed while loading; retry the operation"
        );
        Ok(packages)
    })
}

#[cfg(test)]
thread_local! {
    static AFTER_LOCAL_PARSE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

/// Metadata identity of the complete sync directory. Ordering is meaningless:
/// compare identities for equality, never for increasing time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncDbEpoch(Option<[u8; 32]>);

impl SyncDbEpoch {
    /// Sentinel for an absent directory, retained under its existing API name.
    /// An existing empty directory has its own observed identity.
    pub const UNIX_EPOCH: Self = Self(None);

    /// Reads the sync catalog and expanded pacman configuration identity.
    pub fn observe() -> Result<Self> {
        Self::from_configured_sync_dir(&paths::pacman_sync_dir_result()?)
    }

    fn from_configured_sync_dir(sync_dir: &Path) -> Result<Self> {
        let directory = Self::from_sync_dir(sync_dir)?;
        let configuration =
            crate::core::pacman_conf::PacmanConfig::fingerprint(&paths::pacman_conf_path())?;
        let mut hash = Sha256::new();
        hash.update(b"omg-configured-sync-v1");
        match directory.0 {
            Some(identity) => {
                hash.update([1]);
                hash.update(identity);
            }
            None => hash.update([0]),
        }
        hash.update(configuration);
        Ok(Self(Some(hash.finalize().into())))
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

/// Combined identity for libalpm: configured sync catalogs and the local db.
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
        SYNC_CACHE_NAME,
        "sync_db_source_v4",
        "sync_db_source_v3",
        "sync_db_source_v2",
        LOCAL_CACHE_NAME,
        "local_db_source_v4",
        "local_db_source_v3",
        "local_db_source_v2",
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

/// Search-eligible packages, with duplicate names selected by repository priority.
pub fn get_detailed_packages() -> Result<Vec<SyncDbPackage>> {
    let sync_dir = paths::pacman_sync_dir_result()?;
    let epoch = SyncDbEpoch::from_configured_sync_dir(&sync_dir)?;
    ensure_sync_cache_loaded_at(&sync_dir, epoch)?;

    let cache = read_lock(&SYNC_DB_CACHE);
    let packages = cache
        .select(RepoUsage::SEARCH)?
        .into_values()
        .cloned()
        .collect();
    anyhow::ensure!(
        cache.last_modified == Some(SyncDbEpoch::from_configured_sync_dir(&sync_dir)?),
        "Package databases changed while querying; retry the operation"
    );
    Ok(packages)
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
    let before = AlpmCatalogEpoch::observe()?;
    let pacman_config = crate::core::pacman_conf::PacmanConfig::parse(paths::pacman_conf_path())
        .context("Failed to load update filters from pacman.conf")?;
    let ignored_packages = compile_package_patterns(&pacman_config.ignore_pkg, "IgnorePkg")?;
    let ignored_groups = compile_package_patterns(&pacman_config.ignore_group, "IgnoreGroup")?;
    let sync_dir = paths::pacman_sync_dir_result()?;
    let local_dir = paths::pacman_local_dir_result()?;

    // Ensure caches are loaded using the already-observed epoch
    ensure_sync_cache_loaded_at(&sync_dir, before.sync)?;
    ensure_local_cache_loaded_at(&local_dir, before.local)?;

    // Hold both cache locks simultaneously - no cloning or 20k-entry map rebuild!
    let sync_cache = read_lock(&SYNC_DB_CACHE);
    let local_cache = read_lock(&LOCAL_DB_CACHE);
    sync_cache.validate_usage(RepoUsage::UPGRADE)?;

    // Compare versions - Parallelized with Rayon for <1ms update check on 2000+ pkgs
    // Optimized: filter references first, then clone only needed data at the end
    let updates: Vec<_> = local_cache
        .packages
        .par_iter()
        .filter_map(|(name, local_pkg)| {
            if package_is_ignored(
                &local_pkg.name,
                &local_pkg.groups,
                &ignored_packages,
                &ignored_groups,
            ) {
                return None;
            }
            sync_cache
                .get_validated(name.as_str(), RepoUsage::UPGRADE)
                .filter(|sync_pkg| {
                    !package_is_ignored(
                        &sync_pkg.name,
                        &sync_pkg.groups,
                        &ignored_packages,
                        &ignored_groups,
                    )
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

    anyhow::ensure!(
        before == AlpmCatalogEpoch::observe()?,
        "Package catalogs changed while checking updates; retry the operation"
    );
    Ok(updates)
}

pub(crate) struct PacmanPatterns(Vec<(String, std::ffi::CString)>);

impl PacmanPatterns {
    #[expect(
        unsafe_code,
        reason = "POSIX fnmatch is the native pacman pattern grammar; owned CStrings satisfy its read-only pointer contract"
    )]
    pub(crate) fn matching_pattern(&self, name: &str) -> Option<&str> {
        let name = std::ffi::CString::new(name).ok()?;
        self.0.iter().find_map(|(source, pattern)| {
            // SAFETY: both pointers refer to live NUL-terminated strings; fnmatch only reads them.
            (unsafe { nix::libc::fnmatch(pattern.as_ptr(), name.as_ptr(), 0) } == 0)
                .then_some(source.as_str())
        })
    }

    pub(crate) fn is_match(&self, name: &str) -> bool {
        self.matching_pattern(name).is_some()
    }
}

pub(crate) fn compile_package_patterns(
    patterns: &[String],
    setting: &str,
) -> Result<PacmanPatterns> {
    patterns
        .iter()
        .map(|pattern| {
            let native = std::ffi::CString::new(pattern.as_str())
                .with_context(|| format!("Invalid {setting} pattern {pattern:?}"))?;
            Ok((pattern.clone(), native))
        })
        .collect::<Result<Vec<_>>>()
        .map(PacmanPatterns)
}

fn package_is_ignored(
    name: &str,
    groups: &[String],
    ignored_packages: &PacmanPatterns,
    ignored_groups: &PacmanPatterns,
) -> bool {
    ignored_packages.is_match(name) || groups.iter().any(|group| ignored_groups.is_match(group))
}

/// Read installed package-info from its source, without trusting derived caches.
pub(crate) fn read_local_package(name: &str) -> Result<Option<LocalDbPackage>> {
    read_local_package_at(&paths::pacman_local_dir_result()?, name)
}

/// Read an installed record within an explicit local database scope.
pub(crate) fn read_local_package_at(
    local_dir: &Path,
    name: &str,
) -> Result<Option<LocalDbPackage>> {
    let epoch = LocalDbEpoch::from_local_dir(local_dir)?;
    let package = find_local_package(local_dir, name)?;
    anyhow::ensure!(
        epoch == LocalDbEpoch::from_local_dir(local_dir)?,
        "Local package database changed while querying; retry the operation"
    );
    Ok(package)
}

fn find_local_package(local_dir: &Path, name: &str) -> Result<Option<LocalDbPackage>> {
    let entries = match fs::read_dir(local_dir) {
        Ok(entries) => Some(entries),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("Failed to read local package database"),
    };
    let prefix = format!("{name}-");
    let mut package = None;
    for entry in entries.into_iter().flatten() {
        let entry = entry.context("Failed to enumerate local package database")?;
        if !entry.file_name().as_bytes().starts_with(prefix.as_bytes()) {
            continue;
        }
        let metadata = entry
            .file_type()
            .context("Failed to inspect local package entry")?;
        anyhow::ensure!(
            !metadata.is_symlink(),
            "Local package entry must not be a symlink"
        );
        if !metadata.is_dir() {
            continue;
        }
        let desc = entry.path().join("desc");
        let parsed = parse_local_desc(&desc)
            .with_context(|| format!("Incomplete local package entry {}", desc.display()))?;
        if parsed.name == name {
            anyhow::ensure!(package.is_none(), "Duplicate local package name {name}");
            package = Some(parsed);
        }
    }
    Ok(package)
}

fn with_local_cache<T>(operation: &str, f: impl FnOnce(&LocalDbCache) -> Result<T>) -> Result<T> {
    let local_dir = paths::pacman_local_dir_result()?;
    let epoch = LocalDbEpoch::from_local_dir(&local_dir)?;
    ensure_local_cache_loaded_at(&local_dir, epoch)?;

    let cache = read_lock(&LOCAL_DB_CACHE);
    let value = f(&cache)?;
    anyhow::ensure!(
        cache.last_modified == Some(LocalDbEpoch::from_local_dir(&local_dir)?),
        "Local package database changed while {operation}; retry the operation"
    );
    Ok(value)
}

/// Look up a single installed package from the cached local database.
pub fn get_local_package(name: &str) -> Result<Option<LocalDbPackage>> {
    with_local_cache("querying", |cache| Ok(cache.packages.get(name).cloned()))
}

/// Get the first install-eligible sync package by exact name.
pub fn get_sync_package(name: &str) -> Result<Option<SyncDbPackage>> {
    let sync_dir = paths::pacman_sync_dir_result()?;
    let epoch = SyncDbEpoch::from_configured_sync_dir(&sync_dir)?;
    ensure_sync_cache_loaded_at(&sync_dir, epoch)?;

    let cache = read_lock(&SYNC_DB_CACHE);
    cache.validate_usage(RepoUsage::INSTALL)?;
    let package = cache.get_validated(name, RepoUsage::INSTALL).cloned();
    anyhow::ensure!(
        cache.last_modified == Some(SyncDbEpoch::from_configured_sync_dir(&sync_dir)?),
        "Package databases changed while querying; retry the operation"
    );
    Ok(package)
}

/// List all installed packages from the cached local database.
pub fn list_local_cached() -> Result<Vec<LocalDbPackage>> {
    with_local_cache("querying", |cache| {
        Ok(cache.packages.values().cloned().collect())
    })
}

/// A declared dependency that nothing installed satisfies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsatisfiedDependency {
    /// The installed package that declares the dependency.
    pub package: String,
    /// The complete declared dependency, including its version constraint.
    pub dependency: String,
}

/// Required relations use the installed or explicitly provided version.
/// Optional dependencies are excluded. Diagnostics retain the original relation.
fn unsatisfied_dependencies(
    packages: &HashMap<String, LocalDbPackage>,
) -> Vec<UnsatisfiedDependency> {
    let mut provided: HashMap<&str, Vec<HealthRelation<'_>>> = HashMap::new();
    for package in packages.values() {
        for raw in &package.provides {
            if let Ok(relation) = health_relation(raw)
                && matches!(relation.operator, "" | "=")
            {
                provided.entry(relation.name).or_default().push(relation);
            }
        }
    }
    let mut missing = Vec::new();
    for package in packages.values() {
        for raw in &package.depends {
            let satisfied = health_relation(raw).is_ok_and(|required| {
                packages
                    .get(required.name)
                    .is_some_and(|installed| required.accepts(Some(&installed.version.to_string())))
                    || provided.get(required.name).is_some_and(|providers| {
                        providers
                            .iter()
                            .any(|provider| required.accepts(provider.version))
                    })
            });
            if !satisfied {
                missing.push(UnsatisfiedDependency {
                    package: package.name.clone(),
                    dependency: raw.clone(),
                });
            }
        }
    }
    missing.sort_by(|a, b| {
        a.package
            .cmp(&b.package)
            .then_with(|| a.dependency.cmp(&b.dependency))
    });
    missing
}

struct HealthRelation<'a> {
    name: &'a str,
    operator: &'a str,
    version: Option<&'a str>,
}

fn health_relation(raw: &str) -> Result<HealthRelation<'_>> {
    anyhow::ensure!(
        !raw.as_bytes().contains(&0),
        "NUL in dependency or provision"
    );
    alpm_types::RelationOrSoname::from_str(raw)
        .with_context(|| format!("Invalid required dependency or provision {raw}"))?;
    if let Some(index) = raw.find(['<', '>', '=']) {
        let tail = &raw[index..];
        let width = if tail.starts_with("<=") || tail.starts_with(">=") {
            2
        } else {
            1
        };
        Ok(HealthRelation {
            name: &raw[..index],
            operator: &tail[..width],
            version: Some(&tail[width..]),
        })
    } else {
        Ok(HealthRelation {
            name: raw,
            operator: "",
            version: None,
        })
    }
}

impl HealthRelation<'_> {
    fn accepts(&self, candidate: Option<&str>) -> bool {
        let Some(required) = self.version else {
            return true;
        };
        let Some(candidate) = candidate else {
            return false;
        };
        let comparison = alpm::vercmp(candidate, required);
        match self.operator {
            "=" => comparison.is_eq(),
            ">" => comparison.is_gt(),
            ">=" => !comparison.is_lt(),
            "<" => comparison.is_lt(),
            "<=" => !comparison.is_gt(),
            _ => false,
        }
    }
}

fn validate_health_relations(packages: &HashMap<String, LocalDbPackage>) -> Result<()> {
    for package in packages.values() {
        alpm_types::Name::from_str(&package.name).context("Invalid local package name")?;
        for dependency in &package.depends {
            health_relation(dependency)
                .with_context(|| format!("Invalid dependency declared by {}", package.name))?;
        }
        for provision in &package.provides {
            let relation = health_relation(provision)
                .with_context(|| format!("Invalid provision declared by {}", package.name))?;
            anyhow::ensure!(
                matches!(relation.operator, "" | "="),
                "Unsupported provision {provision} declared by {}",
                package.name
            );
        }
    }
    Ok(())
}

/// Read foreign identities and metadata from the same epoch-checked cached catalogs.
pub(crate) fn get_potential_aur_package_records() -> Result<Vec<LocalDbPackage>> {
    let before = AlpmCatalogEpoch::observe()?;
    let sync_dir = paths::pacman_sync_dir_result()?;
    let local_dir = paths::pacman_local_dir_result()?;

    ensure_sync_cache_loaded_at(&sync_dir, before.sync)?;
    ensure_local_cache_loaded_at(&local_dir, before.local)?;

    let sync_cache = read_lock(&SYNC_DB_CACHE);
    let local_cache = read_lock(&LOCAL_DB_CACHE);

    sync_cache.validate_usage(RepoUsage::ALL)?;
    let mut potential = Vec::with_capacity(local_cache.packages.len() / 10);
    for package in local_cache.packages.values() {
        if sync_cache
            .get_validated(package.name.as_str(), RepoUsage::ALL)
            .is_none()
        {
            potential.push(package.clone());
        }
    }

    anyhow::ensure!(
        before == AlpmCatalogEpoch::observe()?,
        "Package catalogs changed while classifying foreign packages; retry the operation"
    );
    Ok(potential)
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
) -> Result<std::collections::HashSet<String>> {
    // Virtual dependencies ("app depends on virtual-svc") are satisfied by
    // the installed packages whose `%PROVIDES%` name that capability.
    let mut providers: HashMap<&str, Vec<(&str, HealthRelation<'_>)>> = HashMap::new();
    for (name, pkg) in packages {
        for provide in &pkg.provides {
            let relation = health_relation(provide)?;
            anyhow::ensure!(
                matches!(relation.operator, "" | "="),
                "Unsupported provision {provide} declared by {name}"
            );
            providers
                .entry(relation.name)
                .or_default()
                .push((name, relation));
        }
    }

    let mut required: std::collections::HashSet<String> =
        std::collections::HashSet::with_capacity(packages.len());
    for pkg in packages.values() {
        for raw in pkg.depends.iter().chain(&pkg.optdepends) {
            let raw = raw
                .split_once(": ")
                .map_or(raw.as_str(), |(relation, _)| relation);
            let relation = health_relation(raw)
                .with_context(|| format!("Invalid dependency declared by {}", pkg.name))?;
            if let Some(installed) = packages.get(relation.name)
                && installed.name != pkg.name
                && relation.accepts(Some(&installed.version.to_string()))
            {
                required.insert(installed.name.clone());
            }
            if let Some(candidates) = providers.get(relation.name) {
                required.extend(
                    candidates
                        .iter()
                        .filter(|(owner, provided)| {
                            *owner != pkg.name && relation.accepts(provided.version)
                        })
                        .map(|(owner, _)| (*owner).to_owned()),
                );
            }
        }
    }

    Ok(required)
}

/// Return `(total, explicit, orphans)` counts from the cached local database.
///
/// The third element counts orphans under the canonical rule
/// (`types::is_orphan_package`, `pacman -Qdt` semantics): dependencies that
/// no other installed package requires. Reverse dependencies are derived
/// from the cached `%DEPENDS%`/`%PROVIDES%` sets via
/// [`compute_required_names`]; modern pacman never writes `%REQUIREDBY%`
/// into local desc files.
pub fn get_counts_fast() -> Result<(usize, usize, usize)> {
    with_local_cache("counting", |cache| {
        let total = cache.packages.len();
        let required = compute_required_names(&cache.packages)?;
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
    })
}

/// Count explicitly installed packages from the cached local database (skips orphan graph).
pub fn get_explicit_count() -> Result<usize> {
    with_local_cache("counting", |cache| {
        Ok(cache.packages.values().filter(|pkg| pkg.explicit).count())
    })
}

#[cfg(test)]
#[path = "native_health_tests.rs"]
mod native_health_tests;

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::expect_used)] // Idiomatic in tests: panics on failure with clear error context
#[path = "db_tests.rs"]
mod tests;
