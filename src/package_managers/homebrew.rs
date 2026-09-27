//! Pure Rust macOS Homebrew package manager backend
//!
//! This implementation uses DIRECT filesystem access and JSON APIs with NO CLI wrappers.
//! Performance targets: search <50ms (vs brew's 2s), `list_installed` <20ms (vs brew's 500ms).
//!
//! ## Architecture
//!
//! - Installed packages: Direct read from `/opt/homebrew/Cellar/` (ARM) or `/usr/local/Cellar/` (Intel)
//! - Metadata: Parse `INSTALL_RECEIPT.json` in each package version directory
//! - Search: Fetch and cache `formula.json` (~3.4MB, ~7000 packages) from Homebrew API
//! - Binary cache: Use rkyv for zero-copy deserialization on subsequent loads
//! - Fuzzy matching: nucleo-matcher for intelligent search ranking

use std::cmp::Ordering;
use std::future::Future;
use std::pin::Pin;

use ahash::AHashSet;
use anyhow::{Context, Result, bail};
use nucleo_matcher::{
    Config as MatcherConfig, Matcher, Utf32Str,
    pattern::{CaseMatching, Normalization, Pattern},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::sync::{Arc, LazyLock};
use std::time::{Instant, SystemTime};
use tokio::fs;

use crate::core::{Package, PackageSource};
use crate::package_managers::{
    PackageManager,
    types::{UpdateInfo, parse_version_or_zero},
};

/// Homebrew installation prefix (ARM Macs)
const HOMEBREW_PREFIX_ARM: &str = "/opt/homebrew";
/// Homebrew installation prefix (Intel Macs)
const HOMEBREW_PREFIX_INTEL: &str = "/usr/local";
/// Homebrew Cellar directory name
const CELLAR_DIR: &str = "Cellar";
/// Cask installation directory name
const CASKROOM_DIR: &str = "Caskroom";
/// Install receipt filename
const INSTALL_RECEIPT: &str = "INSTALL_RECEIPT.json";
/// Homebrew formula API endpoint
const FORMULA_API: &str = "https://formulae.brew.sh/api/formula.json";
/// Homebrew cask API endpoint
const CASK_API: &str = "https://formulae.brew.sh/api/cask.json";
const FORMULA_CACHE_FILE: &str = "formula.jws.json";
const CASK_CACHE_FILE: &str = "cask.jws.json";
const HOMEBREW_CACHE_TTL_SECS: u64 = 604_800;
/// Cache TTL for installed packages (30 seconds)
const INSTALLED_CACHE_TTL_SECS: u64 = 30;

/// Global cache for installed Homebrew package names
///
/// Provides O(1) lookup for `is_installed()` checks instead of filesystem access.
/// Invalidates when Cellar mtime changes or after 30 seconds.
static INSTALLED_CACHE: LazyLock<RwLock<InstalledCache>> =
    LazyLock::new(|| RwLock::new(InstalledCache::default()));

/// Cache for installed package names with mtime-based invalidation
#[derive(Default)]
struct InstalledCache {
    /// Set of installed formula and cask names for O(1) lookup
    packages: AHashSet<String>,
    /// Cellar directory mtime for invalidation
    cellar_mtime: Option<SystemTime>,
    /// Caskroom directory mtime for invalidation
    caskroom_mtime: Option<SystemTime>,
    /// Last cache refresh time for TTL
    last_refreshed: Option<Instant>,
}

fn installed_cache_requires_rebuild(
    cache: &InstalledCache,
    cellar_mtime: Option<SystemTime>,
    caskroom_mtime: Option<SystemTime>,
) -> bool {
    cache.last_refreshed.is_none()
        || cache.cellar_mtime != cellar_mtime
        || cache.caskroom_mtime != caskroom_mtime
}

/// Install receipt metadata from Homebrew
#[derive(Debug, Clone, Deserialize, Serialize)]
struct InstallReceipt {
    homebrew_version: Option<String>,
    poured_from_bottle: Option<bool>,
    installed_on_request: Option<bool>,
    time: Option<i64>,
    runtime_dependencies: Option<Vec<RuntimeDependency>>,
    source: Option<SourceInfo>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RuntimeDependency {
    full_name: String,
    version: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct SourceInfo {
    tap: Option<String>,
    spec: Option<String>,
}

/// Homebrew formula metadata from API
#[derive(
    Debug, Clone, Deserialize, Serialize, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
#[rkyv(attr(derive(Debug)))]
struct FormulaInfo {
    name: String,
    #[serde(default)]
    full_name: String,
    #[serde(default)]
    desc: String,
    homepage: Option<String>,
    versions: FormulaVersions,
    #[serde(default)]
    installed: Vec<InstalledVersion>,
}

#[derive(
    Debug, Clone, Deserialize, Serialize, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
#[rkyv(attr(derive(Debug)))]
struct FormulaVersions {
    stable: Option<String>,
    head: Option<String>,
    bottle: Option<bool>,
}

#[derive(
    Debug, Clone, Deserialize, Serialize, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
#[rkyv(attr(derive(Debug)))]
struct InstalledVersion {
    version: String,
    installed_on_request: Option<bool>,
}

/// Homebrew cask metadata from API
#[derive(
    Debug, Clone, Deserialize, Serialize, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
#[rkyv(attr(derive(Debug)))]
struct CaskInfo {
    token: String,
    #[serde(default)]
    full_token: String,
    /// The live cask API ships an explicit `"desc": null` for roughly 2,600
    /// casks, so this must tolerate null rather than defaulting on absence.
    #[serde(default)]
    desc: Option<String>,
    homepage: Option<String>,
    version: Option<String>,
}

/// The two full-index responses consumed by the live Homebrew backend.
#[derive(Clone, Copy)]
pub(crate) enum HomebrewIndexKind {
    Formula,
    Cask,
}

/// Doctor uses the live backend's typed response shapes rather than treating
/// an HTTP 200 with an HTML login page or partial JSON as a healthy API.
pub(crate) fn validate_homebrew_index(kind: HomebrewIndexKind, body: &[u8]) -> Result<()> {
    match kind {
        HomebrewIndexKind::Formula => {
            let formulas: Vec<FormulaInfo> =
                serde_json::from_slice(body).context("Homebrew formula index is not parseable")?;
            anyhow::ensure!(!formulas.is_empty(), "Homebrew formula index is empty");
        }
        HomebrewIndexKind::Cask => {
            let casks: Vec<CaskInfo> =
                serde_json::from_slice(body).context("Homebrew cask index is not parseable")?;
            anyhow::ensure!(!casks.is_empty(), "Homebrew cask index is empty");
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct HomebrewApiEnvelope {
    payload: String,
}

/// Which kind of Homebrew package a name refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrewKind {
    Formula,
    Cask,
}

impl BrewKind {
    /// The explicit CLI flag brew needs to disambiguate this kind.
    fn flag(self) -> &'static str {
        match self {
            BrewKind::Formula => "--formula",
            BrewKind::Cask => "--cask",
        }
    }
}

/// Resolve the package kind for each name from the formula/cask index.
///
/// A name present as both a formula and a cask resolves to the formula,
/// matching brew's own precedence for bare ambiguous names. Names missing
/// from the index fail explicitly instead of silently guessing a kind.
fn classify_packages(
    formula_map: &HashMap<String, usize>,
    cask_map: &HashMap<String, usize>,
    packages: &[String],
) -> Result<Vec<BrewKind>> {
    packages
        .iter()
        .map(|package| {
            if formula_map.contains_key(package) {
                Ok(BrewKind::Formula)
            } else if cask_map.contains_key(package) {
                Ok(BrewKind::Cask)
            } else {
                bail!(
                    "Cannot determine whether '{package}' is a Homebrew formula or cask: not found in the package index"
                )
            }
        })
        .collect()
}

/// Local package metadata
#[derive(Debug, Clone)]
struct LocalPackage {
    name: String,
    version: String,
    description: String,
    installed_on_request: bool,
}

/// Cached formula index
#[derive(Debug, Clone)]
struct FormulaCache {
    /// All available formulas
    formulas: Vec<FormulaInfo>,
    /// All available casks
    casks: Vec<CaskInfo>,
    /// Fast name lookup
    formula_map: HashMap<String, usize>,
    /// Fast cask lookup
    cask_map: HashMap<String, usize>,
}

/// Homebrew package manager implementation
pub struct HomebrewPackageManager {
    /// Homebrew installation prefix
    prefix: PathBuf,
    /// Cellar directory path
    cellar: PathBuf,
    /// Cached formula index
    cache: Arc<RwLock<Option<FormulaCache>>>,
    /// HTTP client for API requests
    client: reqwest::Client,
}

impl HomebrewPackageManager {
    /// Create a new Homebrew package manager
    #[must_use]
    pub fn new() -> Self {
        let prefix = Self::detect_prefix();
        let repository = if prefix == Path::new(HOMEBREW_PREFIX_INTEL) {
            prefix.join("Homebrew")
        } else {
            prefix.clone()
        };
        let cellar = Self::select_cellar(&prefix, &repository);

        Self {
            prefix,
            cellar,
            cache: Arc::new(RwLock::new(None)),
            // Shared download client: the formula/cask API responses are
            // multi-megabyte JSON, so they need the extended download
            // timeouts and read-stall detection instead of an ad-hoc client
            // that silently fell back to an unconfigured one on failure.
            client: crate::core::http::download_client().clone(),
        }
    }

    /// Paths used by the live backend. Doctor probes these exact paths so a
    /// second Homebrew installation cannot make the selected backend look
    /// healthy while its own package inventory is empty.
    pub(crate) fn prefix(&self) -> &Path {
        &self.prefix
    }

    pub(crate) fn cellar(&self) -> &Path {
        &self.cellar
    }

    pub(crate) fn caskroom(&self) -> PathBuf {
        self.prefix.join(CASKROOM_DIR)
    }

    pub(crate) fn brew_executable(&self) -> PathBuf {
        self.prefix.join("bin").join("brew")
    }

    /// Match Homebrew's Cellar selection: an existing repository Cellar takes
    /// precedence, otherwise the prefix Cellar is the inventory location.
    /// A missing prefix Cellar remains selected before any formula is installed.
    fn select_cellar(prefix: &Path, repository: &Path) -> PathBuf {
        let repository_cellar = repository.join(CELLAR_DIR);
        if repository_cellar.is_dir() {
            repository_cellar
        } else {
            prefix.join(CELLAR_DIR)
        }
    }

    /// Detect Homebrew installation prefix
    ///
    /// Homebrew uses different installation paths based on CPU architecture:
    /// - ARM (Apple Silicon): `/opt/homebrew`
    /// - Intel (`x86_64`): `/usr/local`
    ///
    /// The executable is the installation authority, including before the
    /// first formula creates a Cellar. Prefer the current binary architecture
    /// when both Homebrew installations exist (for example under Rosetta).
    fn detect_prefix() -> PathBuf {
        let arm_path = PathBuf::from(HOMEBREW_PREFIX_ARM);
        let intel_path = PathBuf::from(HOMEBREW_PREFIX_INTEL);
        if cfg!(target_arch = "aarch64") {
            Self::select_prefix(&arm_path, &intel_path)
        } else {
            Self::select_prefix(&intel_path, &arm_path)
        }
    }

    fn select_prefix(preferred: &Path, alternate: &Path) -> PathBuf {
        for path in [preferred, alternate] {
            if path.join("bin").join("brew").is_file() {
                return path.to_path_buf();
            }
        }
        // Preserve access to a damaged installation's inventory for read
        // operations; doctor reports its missing executable as an issue.
        for path in [preferred, alternate] {
            if path.join(CELLAR_DIR).is_dir() {
                return path.to_path_buf();
            }
        }
        preferred.to_path_buf()
    }

    /// Get the cache directory for storing formula index
    fn cache_dir() -> Result<PathBuf> {
        let home = std::env::var("HOME").context("HOME not set")?;
        let cache = PathBuf::from(home)
            .join(".cache")
            .join("omg")
            .join("homebrew");
        Ok(cache)
    }

    /// Get the binary cache file path
    fn binary_cache_path() -> Result<PathBuf> {
        Ok(Self::cache_dir()?.join("formula.rkyv"))
    }

    /// Find Homebrew's native API cache directory.
    fn homebrew_cache_dir() -> Option<PathBuf> {
        if let Some(cache) = std::env::var_os("HOMEBREW_CACHE").filter(|value| !value.is_empty()) {
            let path = PathBuf::from(cache).join("api");
            if path.is_dir() {
                return Some(path);
            }
        }

        let path = dirs::cache_dir()?.join("Homebrew/api");
        path.is_dir().then_some(path)
    }

    fn parse_homebrew_api_payload<T: serde::de::DeserializeOwned>(
        content: &str,
        path: &Path,
    ) -> Result<T> {
        let envelope: HomebrewApiEnvelope = serde_json::from_str(content)
            .with_context(|| format!("Failed to parse {} envelope", path.display()))?;
        serde_json::from_str(&envelope.payload)
            .with_context(|| format!("Failed to parse {} payload", path.display()))
    }

    async fn read_homebrew_api_payload<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
        let content = fs::read_to_string(path)
            .await
            .with_context(|| format!("Failed to read {}", path.display()))?;
        Self::parse_homebrew_api_payload(&content, path)
    }

    async fn homebrew_cache_file_is_fresh(path: &Path) -> bool {
        let Ok(metadata) = fs::metadata(path).await else {
            return false;
        };
        metadata
            .modified()
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|elapsed| elapsed.as_secs() <= HOMEBREW_CACHE_TTL_SECS)
    }

    /// Build `FormulaCache` from raw formula and cask lists
    fn build_cache(formulas: Vec<FormulaInfo>, casks: Vec<CaskInfo>) -> FormulaCache {
        let formula_map = formulas
            .iter()
            .enumerate()
            .map(|(i, f)| (f.name.clone(), i))
            .collect();

        let cask_map = casks
            .iter()
            .enumerate()
            .map(|(i, c)| (c.token.clone(), i))
            .collect();

        FormulaCache {
            formulas,
            casks,
            formula_map,
            cask_map,
        }
    }

    /// Load from Homebrew's native JWS-envelope API cache.
    ///
    /// Homebrew caches API responses locally with a 7-day TTL. Reading these
    /// files is ~20-30x faster than fetching from the network (2-3s → <100ms).
    async fn load_from_homebrew_cache(&self) -> Result<Option<FormulaCache>> {
        let Some(cache_dir) = Self::homebrew_cache_dir() else {
            tracing::debug!("Homebrew cache directory not found");
            return Ok(None);
        };

        let formula_path = cache_dir.join(FORMULA_CACHE_FILE);
        let cask_path = cache_dir.join(CASK_CACHE_FILE);
        if !Self::homebrew_cache_file_is_fresh(&formula_path).await
            || !Self::homebrew_cache_file_is_fresh(&cask_path).await
        {
            tracing::debug!("Homebrew API cache is missing or stale");
            return Ok(None);
        }

        tracing::info!("Loading from Homebrew's local cache: {:?}", cache_dir);

        let (formulas, casks) = tokio::try_join!(
            Self::read_homebrew_api_payload::<Vec<FormulaInfo>>(&formula_path),
            Self::read_homebrew_api_payload::<Vec<CaskInfo>>(&cask_path)
        )?;

        tracing::debug!(
            "Loaded {} formulas and {} casks from Homebrew cache",
            formulas.len(),
            casks.len()
        );

        Ok(Some(Self::build_cache(formulas, casks)))
    }

    /// Load cached formula index from disk
    ///
    /// Uses rkyv for zero-copy deserialization, providing instant loading
    /// of the formula index (~5ms vs ~100ms for JSON parsing).
    ///
    /// Cache is invalidated if:
    /// - File doesn't exist
    /// - File is older than 24 hours
    /// - File cannot be deserialized as the current rkyv schema
    ///
    /// Returns `Ok(None)` if cache is unavailable or stale.
    async fn load_cache_from_disk(&self) -> Result<Option<FormulaCache>> {
        let cache_path = Self::binary_cache_path()?;

        // Check if cache exists and is recent (24 hours)
        let Ok(meta) = fs::metadata(&cache_path).await else {
            return Ok(None);
        };
        if let Ok(modified) = meta.modified()
            && let Ok(elapsed) = modified.elapsed()
            && elapsed.as_secs() > 86400
        {
            return Ok(None);
        }

        // Load and deserialize binary cache
        let data = fs::read(&cache_path).await?;
        let (formulas, casks): (Vec<FormulaInfo>, Vec<CaskInfo>) =
            rkyv::from_bytes::<(Vec<FormulaInfo>, Vec<CaskInfo>), rkyv::rancor::Error>(&data)
                .map_err(|e| anyhow::anyhow!("Invalid rkyv cache: {e}"))?;

        Ok(Some(Self::build_cache(formulas, casks)))
    }

    /// Save formula cache to disk
    async fn save_cache_to_disk(&self, cache: &FormulaCache) -> Result<()> {
        let cache_dir = Self::cache_dir()?;
        fs::create_dir_all(&cache_dir).await?;

        let cache_path = Self::binary_cache_path()?;

        // Serialize using rkyv
        let data =
            rkyv::to_bytes::<rkyv::rancor::Error>(&(cache.formulas.clone(), cache.casks.clone()))
                .context("Failed to serialize cache")?;

        crate::core::safe_ops::atomic_write_file(&cache_path, &data)
            .await
            .with_context(|| format!("Failed to write {}", cache_path.display()))?;

        Ok(())
    }

    /// Fetch and cache formula index from API
    async fn fetch_and_cache_formulas(&self) -> Result<FormulaCache> {
        tracing::debug!("Fetching formula index from Homebrew API");

        let (formulas_result, casks_result) = tokio::join!(
            self.client.get(FORMULA_API).send(),
            self.client.get(CASK_API).send()
        );

        let formulas: Vec<FormulaInfo> = formulas_result?
            .error_for_status()?
            .json()
            .await
            .context("Failed to parse formula API response")?;

        let casks: Vec<CaskInfo> = casks_result?
            .error_for_status()?
            .json()
            .await
            .context("Failed to parse cask API response")?;

        tracing::debug!(
            "Fetched {} formulas and {} casks",
            formulas.len(),
            casks.len()
        );

        let cache = Self::build_cache(formulas, casks);

        if let Err(e) = self.save_cache_to_disk(&cache).await {
            tracing::warn!("Failed to save formula cache: {}", e);
        }

        Ok(cache)
    }

    /// Ensure formula cache is loaded
    ///
    /// Cache loading priority:
    /// 1. In-memory cache (instant)
    /// 2. OMG's rkyv cache (~5ms, zero-copy deserialization)
    /// 3. Homebrew's local JSON cache (~50-100ms, no network)
    /// 4. Homebrew API fetch (2-3s, requires network)
    async fn ensure_cache(&self) -> Result<()> {
        if self
            .cache
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
        {
            return Ok(());
        }

        if let Ok(Some(cache)) = self.load_cache_from_disk().await {
            tracing::debug!("Loaded cache from OMG rkyv store");
            *self
                .cache
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(cache);
            return Ok(());
        }

        if let Ok(Some(cache)) = self.load_from_homebrew_cache().await {
            tracing::debug!("Loaded cache from Homebrew's local cache");
            if let Err(e) = self.save_cache_to_disk(&cache).await {
                tracing::warn!("Failed to persist Homebrew cache to OMG format: {}", e);
            }
            *self
                .cache
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(cache);
            return Ok(());
        }

        tracing::debug!("No local cache available, fetching from Homebrew API");
        let cache = self.fetch_and_cache_formulas().await?;
        *self
            .cache
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(cache);

        Ok(())
    }

    /// Read installed formulas from Cellar and casks from Caskroom.
    async fn read_installed_packages(&self) -> Result<Vec<LocalPackage>> {
        let mut packages = Vec::new();

        if self.cellar.exists() {
            let mut entries = fs::read_dir(&self.cellar).await?;
            while let Some(entry) = entries.next_entry().await? {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with('.') {
                    continue;
                }

                let pkg_path = entry.path();
                match self.read_package_info(&pkg_path, &name).await {
                    Ok(package) => packages.push(package),
                    Err(error) => tracing::warn!(
                        "Skipping unreadable Homebrew formula {}: {error:#}",
                        pkg_path.display()
                    ),
                }
            }
        }

        let caskroom = self.caskroom();
        if caskroom.exists() {
            let mut entries = fs::read_dir(&caskroom).await?;
            while let Some(entry) = entries.next_entry().await? {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with('.') {
                    continue;
                }

                let package_path = entry.path();
                let versions = match Self::read_version_directories(&package_path).await {
                    Ok(versions) => versions,
                    Err(error) => {
                        tracing::warn!(
                            "Skipping unreadable Homebrew cask {}: {error:#}",
                            package_path.display()
                        );
                        continue;
                    }
                };
                if let Some((version, version_path)) = Self::latest_installed_version(versions) {
                    let receipt_path = version_path.join(INSTALL_RECEIPT);
                    let installed_on_request = match fs::read_to_string(&receipt_path).await {
                        Ok(data) => serde_json::from_str::<InstallReceipt>(&data)
                            .ok()
                            .and_then(|receipt| receipt.installed_on_request)
                            .unwrap_or_default(),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                        Err(error) => {
                            return Err(error).with_context(|| {
                                format!("Failed to read {}", receipt_path.display())
                            });
                        }
                    };
                    packages.push(LocalPackage {
                        name,
                        version,
                        description: String::new(),
                        installed_on_request,
                    });
                }
            }
        }

        Ok(packages)
    }

    fn next_version_component(
        chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    ) -> Option<(bool, String)> {
        let first = *chars.peek()?;
        let numeric = first.is_ascii_digit();
        let mut component = String::new();
        while chars
            .peek()
            .is_some_and(|character| character.is_ascii_digit() == numeric)
        {
            if let Some(character) = chars.next() {
                component.push(character);
            }
        }
        Some((numeric, component))
    }

    /// Compare Homebrew version strings by numeric components before
    /// falling back to their textual components.
    fn compare_homebrew_versions(left: &str, right: &str) -> Ordering {
        let mut left = left.chars().peekable();
        let mut right = right.chars().peekable();

        loop {
            let left_component = Self::next_version_component(&mut left);
            let right_component = Self::next_version_component(&mut right);
            match (left_component, right_component) {
                (None, None) => return Ordering::Equal,
                (None, Some(_)) => return Ordering::Less,
                (Some(_), None) => return Ordering::Greater,
                (Some((left_numeric, left_value)), Some((right_numeric, right_value))) => {
                    let ordering = if left_numeric && right_numeric {
                        let left_trimmed = left_value.trim_start_matches('0');
                        let right_trimmed = right_value.trim_start_matches('0');
                        left_trimmed
                            .len()
                            .cmp(&right_trimmed.len())
                            .then_with(|| left_trimmed.cmp(right_trimmed))
                            .then_with(|| left_value.len().cmp(&right_value.len()).reverse())
                    } else {
                        left_numeric
                            .cmp(&right_numeric)
                            .then_with(|| left_value.cmp(&right_value))
                    };
                    if ordering != Ordering::Equal {
                        return ordering;
                    }
                }
            }
        }
    }

    fn latest_installed_version(mut versions: Vec<(String, PathBuf)>) -> Option<(String, PathBuf)> {
        versions.sort_by(|left, right| Self::compare_homebrew_versions(&left.0, &right.0));
        versions.pop()
    }

    async fn read_version_directories(package_path: &Path) -> Result<Vec<(String, PathBuf)>> {
        let mut versions = Vec::new();
        let mut entries = fs::read_dir(package_path).await?;
        while let Some(entry) = entries.next_entry().await? {
            let version = entry.file_name().to_string_lossy().to_string();
            if !version.starts_with('.') && entry.file_type().await?.is_dir() {
                versions.push((version, entry.path()));
            }
        }
        Ok(versions)
    }

    /// Read package information from directory
    async fn read_package_info(&self, pkg_path: &Path, name: &str) -> Result<LocalPackage> {
        let versions = Self::read_version_directories(pkg_path).await?;
        let Some((version, version_path)) = Self::latest_installed_version(versions) else {
            bail!("No versions found for package {name}");
        };

        // Read install receipt
        let receipt_path = version_path.join(INSTALL_RECEIPT);
        let receipt = if receipt_path.exists() {
            let data = fs::read_to_string(&receipt_path).await?;
            serde_json::from_str::<InstallReceipt>(&data).ok()
        } else {
            None
        };

        let installed_on_request = receipt
            .as_ref()
            .and_then(|r| r.installed_on_request)
            .unwrap_or_default();

        // Get description from cache if available
        let description = if let Some(cache) = crate::core::sync::read_cache(&self.cache).as_ref() {
            cache
                .formula_map
                .get(name)
                .and_then(|&idx| cache.formulas.get(idx))
                .map(|f| f.desc.clone())
                .unwrap_or_default()
        } else {
            String::new()
        };

        Ok(LocalPackage {
            name: name.to_string(),
            version: version.clone(),
            description,
            installed_on_request,
        })
    }

    /// Resolve the Homebrew package kind for a batch of names using the
    /// formula/cask index. Loads the index first when it is not in memory.
    async fn resolve_package_kinds(&self, packages: &[String]) -> Result<Vec<BrewKind>> {
        self.ensure_cache().await?;
        let cache = crate::core::sync::read_cache(&self.cache);
        let cache = cache
            .as_ref()
            .context("Homebrew package cache not loaded")?;
        classify_packages(&cache.formula_map, &cache.cask_map, packages)
    }

    fn packages_for_index(cache: &FormulaCache) -> Vec<Package> {
        let mut packages = Vec::with_capacity(cache.formulas.len() + cache.casks.len());
        packages.extend(cache.formulas.iter().map(|formula| Package {
            name: formula.name.clone(),
            version: parse_version_or_zero(formula.versions.stable.as_deref().unwrap_or("0")),
            description: formula.desc.clone(),
            source: PackageSource::Official,
            installed: false,
        }));
        packages.extend(cache.casks.iter().map(|cask| Package {
            name: cask.token.clone(),
            version: parse_version_or_zero(cask.version.as_deref().unwrap_or("0")),
            description: cask.desc.clone().unwrap_or_default(),
            source: PackageSource::Official,
            installed: false,
        }));
        packages
    }

    /// Search packages using fuzzy matching
    ///
    /// Implements intelligent fuzzy search using nucleo-matcher:
    /// - Searches both package names and descriptions
    /// - Scores results by relevance (character proximity, sequential matches)
    /// - Returns top 50 results sorted by score
    ///
    /// Performance: O(n) where n = total packages (~7000), ~30-40ms per search
    fn fuzzy_search(&self, cache: &FormulaCache, query: &str) -> Vec<Package> {
        let mut matcher = Matcher::new(MatcherConfig::DEFAULT);
        let pattern = Pattern::parse(query, CaseMatching::Ignore, Normalization::Smart);
        let mut results = Vec::new();
        let mut buf = Vec::new();

        // Search formulas (CLI tools, libraries)
        for (idx, formula) in cache.formulas.iter().enumerate() {
            // Try matching against name first, then description
            let haystack_name = Utf32Str::new(&formula.name, &mut buf);
            let score = pattern.score(haystack_name, &mut matcher);

            let final_score = score.or_else(|| {
                buf.clear();
                let haystack_desc = Utf32Str::new(&formula.desc, &mut buf);
                pattern.score(haystack_desc, &mut matcher)
            });

            if let Some(score) = final_score {
                results.push((score, idx, true)); // true = formula
            }
            buf.clear();
        }

        // Search casks (GUI applications)
        for (idx, cask) in cache.casks.iter().enumerate() {
            let haystack_name = Utf32Str::new(&cask.token, &mut buf);
            let score = pattern.score(haystack_name, &mut matcher);

            let final_score = score.or_else(|| {
                buf.clear();
                let haystack_desc = Utf32Str::new(cask.desc.as_deref().unwrap_or(""), &mut buf);
                pattern.score(haystack_desc, &mut matcher)
            });

            if let Some(score) = final_score {
                results.push((score, idx, false)); // false = cask
            }
            buf.clear();
        }

        // Sort by score (descending) - highest relevance first
        results.sort_by_key(|entry| std::cmp::Reverse(entry.0));

        // Take top 50 results to avoid overwhelming the user
        results.truncate(50);

        // Convert to Package structs
        results
            .into_iter()
            .map(|(_, idx, is_formula)| {
                if is_formula {
                    let formula = &cache.formulas[idx];
                    Package {
                        name: formula.name.clone(),
                        version: parse_version_or_zero(
                            formula.versions.stable.as_deref().unwrap_or("0"),
                        ),
                        description: formula.desc.clone(),
                        source: PackageSource::Official,
                        installed: self.is_installed_fast(&formula.name).unwrap_or(false),
                    }
                } else {
                    let cask = &cache.casks[idx];
                    Package {
                        name: cask.token.clone(),
                        version: parse_version_or_zero(cask.version.as_deref().unwrap_or("0")),
                        description: cask.desc.clone().unwrap_or_default(),
                        source: PackageSource::Official,
                        installed: self.is_installed_fast(&cask.token).unwrap_or(false),
                    }
                }
            })
            .collect()
    }

    fn list_installed_sync(&self) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for root in [&self.cellar, &self.caskroom()] {
            if !root.exists() {
                continue;
            }
            for entry in std::fs::read_dir(root)? {
                let entry = entry.context("failed to read Homebrew installed entry")?;
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.starts_with('.') {
                    names.push(name);
                }
            }
        }
        names.sort_unstable();
        names.dedup();
        Ok(names)
    }

    fn installed_root_mtimes(&self) -> (Option<SystemTime>, Option<SystemTime>) {
        let cellar_mtime = std::fs::metadata(&self.cellar)
            .ok()
            .and_then(|metadata| metadata.modified().ok());
        let caskroom_mtime = std::fs::metadata(self.caskroom())
            .ok()
            .and_then(|metadata| metadata.modified().ok());
        (cellar_mtime, caskroom_mtime)
    }

    fn refresh_installed_cache(
        &self,
        cellar_mtime: Option<SystemTime>,
        caskroom_mtime: Option<SystemTime>,
    ) -> Result<()> {
        let needs_rebuild = {
            let cache = crate::core::sync::read_cache(&INSTALLED_CACHE);
            installed_cache_requires_rebuild(&cache, cellar_mtime, caskroom_mtime)
        };

        let refreshed_packages = if needs_rebuild {
            Some(self.list_installed_sync()?.into_iter().collect())
        } else {
            None
        };
        let mut cache = crate::core::sync::write_cache(&INSTALLED_CACHE);
        if let Some(packages) = refreshed_packages {
            cache.packages = packages;
            cache.cellar_mtime = cellar_mtime;
            cache.caskroom_mtime = caskroom_mtime;
        }
        // An unchanged but expired cache remains valid; renew its TTL without
        // rewalking the Cellar. Empty package sets are valid on fresh systems.
        cache.last_refreshed = Some(Instant::now());
        Ok(())
    }

    pub fn is_installed_fast(&self, package: &str) -> Result<bool> {
        let (cellar_mtime, caskroom_mtime) = self.installed_root_mtimes();
        {
            let cache = crate::core::sync::read_cache(&INSTALLED_CACHE);
            if let Some(last) = cache.last_refreshed
                && last.elapsed().as_secs() < INSTALLED_CACHE_TTL_SECS
                && cache.cellar_mtime == cellar_mtime
                && cache.caskroom_mtime == caskroom_mtime
            {
                return Ok(cache.packages.contains(package));
            }
        }

        self.refresh_installed_cache(cellar_mtime, caskroom_mtime)?;

        Ok(crate::core::sync::read_cache(&INSTALLED_CACHE)
            .packages
            .contains(package))
    }

    async fn run_brew(&self, args: &[&str]) -> Result<()> {
        if args
            .first()
            .is_some_and(|argument| matches!(*argument, "install" | "upgrade" | "reinstall"))
        {
            crate::core::security::policy::require_native_plan_support("Homebrew")?;
        }
        let targets = args
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect::<Vec<_>>();
        crate::core::security::audit::record_operation("brew", &targets, "attempt")?;
        let brew_path = self.brew_executable();

        let mut cmd = tokio::process::Command::new(&brew_path);
        cmd.args(args);

        let status = cmd.status().await?;
        crate::core::security::audit::record_operation(
            "brew",
            &targets,
            if status.success() {
                "succeeded"
            } else {
                "failed"
            },
        )?;

        if status.success() {
            Ok(())
        } else {
            bail!("brew command failed: {args:?}")
        }
    }
}

impl Default for HomebrewPackageManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PackageManager for HomebrewPackageManager {
    fn name(&self) -> &'static str {
        "brew"
    }

    fn search(
        &self,
        query: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Package>>> + Send + '_>> {
        let query = query.to_string();
        Box::pin(async move {
            self.ensure_cache().await?;

            let cache = crate::core::sync::read_cache(&self.cache);
            let cache = cache.as_ref().context("Cache not loaded")?;

            Ok(self.fuzzy_search(cache, &query))
        })
    }

    fn package_index(&self) -> Pin<Box<dyn Future<Output = Result<Vec<Package>>> + Send + '_>> {
        Box::pin(async move {
            self.ensure_cache().await?;
            let cache = crate::core::sync::read_cache(&self.cache);
            let cache = cache.as_ref().context("Cache not loaded")?;
            Ok(Self::packages_for_index(cache))
        })
    }

    fn install(
        &self,
        packages: &[String],
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let packages = packages.to_vec();
        Box::pin(async move {
            if packages.is_empty() {
                return Ok(());
            }
            crate::core::security::validate_package_names(&packages)?;
            let kinds = self.resolve_package_kinds(&packages).await?;

            // brew accepts one kind flag per invocation, so batch by the
            // resolved kind and pass an explicit flag on every invocation.
            for kind in [BrewKind::Formula, BrewKind::Cask] {
                let pkg_refs: Vec<&str> = packages
                    .iter()
                    .zip(&kinds)
                    .filter(|(_, resolved)| **resolved == kind)
                    .map(|(name, _)| name.as_str())
                    .collect();
                if pkg_refs.is_empty() {
                    continue;
                }
                let mut args = vec!["install", kind.flag()];
                args.extend_from_slice(&pkg_refs);
                self.run_brew(&args).await?;
            }
            Ok(())
        })
    }

    fn remove(&self, packages: &[String]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let packages = packages.to_vec();
        Box::pin(async move {
            if packages.is_empty() {
                return Ok(());
            }
            crate::core::security::validate_package_names(&packages)?;
            let kinds = self.resolve_package_kinds(&packages).await?;

            // brew accepts one kind flag per invocation, so batch by the
            // resolved kind and pass an explicit flag on every invocation.
            for kind in [BrewKind::Formula, BrewKind::Cask] {
                let pkg_refs: Vec<&str> = packages
                    .iter()
                    .zip(&kinds)
                    .filter(|(_, resolved)| **resolved == kind)
                    .map(|(name, _)| name.as_str())
                    .collect();
                if pkg_refs.is_empty() {
                    continue;
                }
                let mut args = vec!["uninstall", kind.flag()];
                args.extend_from_slice(&pkg_refs);
                self.run_brew(&args).await?;
            }
            Ok(())
        })
    }

    fn update(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move { self.run_brew(&["upgrade"]).await })
    }

    fn sync(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            // Sync from API instead of running brew update
            let cache = self.fetch_and_cache_formulas().await?;
            *crate::core::sync::write_cache(&self.cache) = Some(cache);
            Ok(())
        })
    }

    fn info(
        &self,
        package: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Package>>> + Send + '_>> {
        let package = package.to_string();
        Box::pin(async move {
            self.ensure_cache().await?;

            let cache = crate::core::sync::read_cache(&self.cache);
            let cache = cache.as_ref().context("Cache not loaded")?;

            // Check formulas first
            if let Some(&idx) = cache.formula_map.get(&*package) {
                let formula = &cache.formulas[idx];
                return Ok(Some(Package {
                    name: formula.name.clone(),
                    version: parse_version_or_zero(
                        formula.versions.stable.as_deref().unwrap_or("0"),
                    ),
                    description: formula.desc.clone(),
                    source: PackageSource::Official,
                    installed: self.is_installed_fast(&formula.name)?,
                }));
            }

            // Check casks
            if let Some(&idx) = cache.cask_map.get(&*package) {
                let cask = &cache.casks[idx];
                return Ok(Some(Package {
                    name: cask.token.clone(),
                    version: parse_version_or_zero(cask.version.as_deref().unwrap_or("0")),
                    description: cask.desc.clone().unwrap_or_default(),
                    source: PackageSource::Official,
                    installed: self.is_installed_fast(&cask.token)?,
                }));
            }

            Ok(None)
        })
    }

    fn list_installed(&self) -> Pin<Box<dyn Future<Output = Result<Vec<Package>>> + Send + '_>> {
        Box::pin(async move {
            let packages = self.read_installed_packages().await?;

            Ok(packages
                .into_iter()
                .map(|p| Package {
                    name: p.name,
                    version: parse_version_or_zero(&p.version),
                    description: p.description,
                    source: PackageSource::Official,
                    installed: true,
                })
                .collect())
        })
    }

    fn get_status(
        &self,
        _fast: bool,
    ) -> Pin<Box<dyn Future<Output = Result<(usize, usize, usize, usize)>> + Send + '_>> {
        Box::pin(async move {
            let packages = self.read_installed_packages().await?;
            let total = packages.len();
            let explicit = packages.iter().filter(|p| p.installed_on_request).count();

            // Homebrew doesn't have an orphans concept like pacman; report
            // zero rather than guessing.
            let orphans = 0;

            // Real update count from the formula cache — previously hardcoded
            // to 0, which made `omg status` on macOS never report outdated
            // packages.
            let updates = match self.list_updates().await {
                Ok(updates) => updates.len(),
                Err(error) => {
                    tracing::debug!("homebrew update count unavailable: {error:#}");
                    0
                }
            };

            Ok((total, explicit, orphans, updates))
        })
    }

    fn list_explicit(&self) -> Pin<Box<dyn Future<Output = Result<Vec<String>>> + Send + '_>> {
        Box::pin(async move {
            let packages = self.read_installed_packages().await?;

            Ok(packages
                .into_iter()
                .filter(|p| p.installed_on_request)
                .map(|p| p.name)
                .collect())
        })
    }

    fn list_updates(&self) -> Pin<Box<dyn Future<Output = Result<Vec<UpdateInfo>>> + Send + '_>> {
        Box::pin(async move {
            self.ensure_cache().await?;

            let installed = self.read_installed_packages().await?;
            let cache = self
                .cache
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let cache = cache.as_ref().context("Cache not loaded")?;

            let mut updates = Vec::new();

            for pkg in installed {
                let available_version = cache
                    .formula_map
                    .get(&pkg.name)
                    .and_then(|&idx| cache.formulas[idx].versions.stable.clone())
                    .or_else(|| {
                        cache
                            .cask_map
                            .get(&pkg.name)
                            .and_then(|&idx| cache.casks[idx].version.clone())
                    });
                if let Some(available_version) = available_version {
                    let current = parse_version_or_zero(&pkg.version);
                    let available = parse_version_or_zero(&available_version);

                    if available > current {
                        updates.push(UpdateInfo {
                            name: pkg.name.clone(),
                            old_version: pkg.version.clone(),
                            new_version: available_version,
                            repo: "homebrew".to_string(),
                        });
                    }
                }
            }

            Ok(updates)
        })
    }

    fn is_installed(
        &self,
        package: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + '_>> {
        let result = self.is_installed_fast(package);
        Box::pin(async move { result })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_version_selection_uses_numeric_ordering() {
        let directory = tempfile::tempdir().unwrap();
        let older = directory.path().join("1.9");
        let newer = directory.path().join("1.10");

        let selected = HomebrewPackageManager::latest_installed_version(vec![
            ("1.9".to_string(), older),
            ("1.10".to_string(), newer.clone()),
        ])
        .unwrap();

        assert_eq!(selected.0, "1.10");
        assert_eq!(selected.1, newer);
    }

    #[tokio::test]
    async fn test_detect_prefix() {
        let prefix = HomebrewPackageManager::detect_prefix();
        assert!(
            prefix == std::path::Path::new(HOMEBREW_PREFIX_ARM)
                || prefix == std::path::Path::new(HOMEBREW_PREFIX_INTEL)
        );
    }

    #[test]
    fn prefix_selection_prefers_running_architecture_and_existing_brew() -> Result<()> {
        let root = tempfile::tempdir()?;
        let preferred = root.path().join("preferred");
        let alternate = root.path().join("alternate");
        std::fs::create_dir_all(preferred.join("bin"))?;
        std::fs::create_dir_all(alternate.join("bin"))?;

        // A fresh Homebrew install can have an executable before its first
        // formula creates a Cellar.
        std::fs::write(preferred.join("bin/brew"), b"brew")?;
        assert_eq!(
            HomebrewPackageManager::select_prefix(&preferred, &alternate),
            preferred
        );

        // A second architecture's Cellar cannot override the executable for
        // the architecture of the running OMG binary.
        std::fs::create_dir_all(alternate.join(CELLAR_DIR))?;
        std::fs::write(alternate.join("bin/brew"), b"brew")?;
        assert_eq!(
            HomebrewPackageManager::select_prefix(&preferred, &alternate),
            preferred
        );

        std::fs::remove_file(preferred.join("bin/brew"))?;
        assert_eq!(
            HomebrewPackageManager::select_prefix(&preferred, &alternate),
            alternate
        );
        Ok(())
    }

    #[tokio::test]
    async fn repository_cellar_is_the_inventory_the_backend_reads() -> Result<()> {
        let root = tempfile::tempdir()?;
        let prefix = root.path().join("prefix");
        let repository = prefix.join("Homebrew");
        let repository_cellar = repository.join(CELLAR_DIR);
        let prefix_cellar = prefix.join(CELLAR_DIR);
        assert_eq!(
            HomebrewPackageManager::select_cellar(&prefix, &repository),
            prefix_cellar,
            "Homebrew selects the prefix even before either Cellar exists"
        );
        std::fs::create_dir_all(repository_cellar.join("wget/1.0"))?;

        let selected = HomebrewPackageManager::select_cellar(&prefix, &repository);
        assert_eq!(selected, repository_cellar);
        let manager = HomebrewPackageManager {
            prefix: prefix.clone(),
            cellar: selected,
            cache: Arc::new(RwLock::new(None)),
            client: crate::core::http::download_client().clone(),
        };
        let installed = manager.read_installed_packages().await?;
        assert_eq!(installed.len(), 1);
        assert_eq!(installed[0].name, "wget");
        assert_eq!(installed[0].version, "1.0");

        std::fs::create_dir_all(prefix_cellar.join("curl/2.0"))?;
        assert_eq!(
            HomebrewPackageManager::select_cellar(&prefix, &repository),
            repository_cellar,
            "Homebrew prefers the repository Cellar even if the prefix Cellar exists"
        );
        std::fs::remove_dir_all(&repository_cellar)?;
        assert_eq!(
            HomebrewPackageManager::select_cellar(&prefix, &repository),
            prefix_cellar,
            "Homebrew falls back to the prefix when the repository Cellar is absent"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_cache_paths() {
        let binary_cache = HomebrewPackageManager::binary_cache_path();
        assert!(binary_cache.is_ok());
    }

    #[tokio::test]
    #[ignore = "Only run on macOS with Homebrew installed"]
    async fn test_list_installed() {
        let pm = HomebrewPackageManager::new();
        let packages = pm.list_installed().await;
        assert!(packages.is_ok());
    }

    #[tokio::test]
    #[ignore = "Requires network access"]
    async fn test_search() {
        let pm = HomebrewPackageManager::new();
        let results = pm.search("wget").await;
        assert!(results.is_ok());
        let results = results.unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn current_homebrew_jws_cache_is_loaded() -> Result<()> {
        let cache_root = tempfile::tempdir()?;
        let api_dir = cache_root.path().join("api");
        std::fs::create_dir_all(&api_dir)?;
        let formula_payload = serde_json::json!([{
            "name": "wget",
            "desc": "Internet file retriever",
            "homepage": "https://www.gnu.org/software/wget/",
            "versions": {"stable": "1.0"}
        }]);
        let cask_payload = serde_json::json!([{
            "token": "firefox",
            "desc": null,
            "homepage": "https://www.mozilla.org/firefox/",
            "version": "146.0"
        }]);
        for (name, payload) in [
            (FORMULA_CACHE_FILE, formula_payload),
            (CASK_CACHE_FILE, cask_payload),
        ] {
            std::fs::write(
                api_dir.join(name),
                serde_json::json!({
                    "payload": payload.to_string(),
                    "signatures": [{"header": {"kid": "homebrew-1"}}]
                })
                .to_string(),
            )?;
        }

        temp_env::with_var("HOMEBREW_CACHE", Some(cache_root.path()), || {
            let manager = HomebrewPackageManager::new();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let cache = runtime
                .block_on(manager.load_from_homebrew_cache())?
                .context("expected current Homebrew API cache")?;

            assert_eq!(cache.formulas.len(), 1);
            assert_eq!(cache.casks.len(), 1);
            assert!(cache.formula_map.contains_key("wget"));
            assert!(cache.cask_map.contains_key("firefox"));
            Ok(())
        })
    }

    #[test]
    fn package_index_includes_every_formula_and_cask() {
        let cache = HomebrewPackageManager::build_cache(
            vec![FormulaInfo {
                name: "wget".to_string(),
                full_name: "wget".to_string(),
                desc: "Internet file retriever".to_string(),
                homepage: None,
                versions: FormulaVersions {
                    stable: Some("1.0".to_string()),
                    head: None,
                    bottle: None,
                },
                installed: Vec::new(),
            }],
            vec![CaskInfo {
                token: "firefox".to_string(),
                full_token: "homebrew/cask/firefox".to_string(),
                desc: None,
                homepage: None,
                version: Some("146.0".to_string()),
            }],
        );

        let packages = HomebrewPackageManager::packages_for_index(&cache);

        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "wget");
        assert_eq!(packages[1].name, "firefox");
        assert_eq!(packages[1].description, "");
    }

    #[test]
    fn formula_search_uses_local_cellar_for_installed_state() -> Result<()> {
        let root = tempfile::tempdir()?;
        let cellar = root.path().join(CELLAR_DIR);
        std::fs::create_dir_all(cellar.join("wget").join("1.0"))?;
        let manager = HomebrewPackageManager {
            prefix: root.path().to_path_buf(),
            cellar,
            cache: Arc::new(RwLock::new(None)),
            client: crate::core::http::download_client().clone(),
        };
        let cache = HomebrewPackageManager::build_cache(
            vec![FormulaInfo {
                name: "wget".to_string(),
                full_name: "wget".to_string(),
                desc: "Internet file retriever".to_string(),
                homepage: None,
                versions: FormulaVersions {
                    stable: Some("1.0".to_string()),
                    head: None,
                    bottle: None,
                },
                installed: Vec::new(),
            }],
            Vec::new(),
        );

        let packages = manager.fuzzy_search(&cache, "wget");

        assert_eq!(packages.len(), 1);
        assert!(packages[0].installed);
        Ok(())
    }

    #[tokio::test]
    async fn installed_casks_are_included_and_numerically_sorted() -> Result<()> {
        let root = tempfile::tempdir()?;
        let caskroom = root.path().join(CASKROOM_DIR);
        let cask_dir = caskroom.join("example");
        fs::create_dir_all(cask_dir.join("1.9")).await?;
        fs::write(caskroom.join("interrupted-install"), b"not a directory").await?;
        let newest = cask_dir.join("1.10");
        fs::create_dir_all(&newest).await?;
        fs::write(
            newest.join(INSTALL_RECEIPT),
            r#"{"installed_on_request":true}"#,
        )
        .await?;
        let manager = HomebrewPackageManager {
            prefix: root.path().to_path_buf(),
            cellar: root.path().join(CELLAR_DIR),
            cache: Arc::new(RwLock::new(None)),
            client: crate::core::http::download_client().clone(),
        };

        let packages = manager.read_installed_packages().await?;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "example");
        assert_eq!(packages[0].version, "1.10");
        assert!(packages[0].installed_on_request);
        Ok(())
    }

    #[test]
    fn empty_installed_cache_is_valid_after_initial_refresh() {
        let now = SystemTime::now();
        let cache = InstalledCache {
            packages: AHashSet::new(),
            cellar_mtime: Some(now),
            caskroom_mtime: None,
            last_refreshed: Some(Instant::now()),
        };

        assert!(!installed_cache_requires_rebuild(&cache, Some(now), None));
        assert!(installed_cache_requires_rebuild(&cache, None, None));
    }

    #[tokio::test]
    async fn malformed_cellar_entry_does_not_hide_valid_formulas() -> Result<()> {
        let root = tempfile::tempdir()?;
        let cellar = root.path().join(CELLAR_DIR);
        fs::create_dir_all(cellar.join("empty-formula")).await?;
        let valid_formula = cellar.join("valid-formula");
        fs::create_dir_all(valid_formula.join("1.0")).await?;
        fs::write(valid_formula.join("9.9"), b"stray file").await?;
        let manager = HomebrewPackageManager {
            prefix: root.path().to_path_buf(),
            cellar,
            cache: Arc::new(RwLock::new(None)),
            client: crate::core::http::download_client().clone(),
        };

        let packages = manager.read_installed_packages().await?;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "valid-formula");
        Ok(())
    }

    #[test]
    fn homebrew_versions_compare_numeric_components() {
        assert_eq!(
            HomebrewPackageManager::compare_homebrew_versions("1.10", "1.9"),
            Ordering::Greater
        );
        assert_eq!(
            HomebrewPackageManager::compare_homebrew_versions("2.0", "10.0"),
            Ordering::Less
        );
        assert_eq!(
            HomebrewPackageManager::compare_homebrew_versions("1.2_1", "1.2"),
            Ordering::Greater
        );
    }

    #[test]
    fn is_installed_fast_returns_result_for_unknown_package() -> Result<()> {
        let pm = HomebrewPackageManager::new();
        assert!(!pm.is_installed_fast("this-package-definitely-does-not-exist-12345")?);
        Ok(())
    }

    #[test]
    fn cask_with_null_desc_parses_like_the_live_api() -> Result<()> {
        // The live cask API ships an explicit `"desc": null` for ~2,600 casks;
        // `#[serde(default)]` alone does not accept null.
        let cask: CaskInfo = serde_json::from_str(
            r#"{"token":"example","full_token":"example","desc":null,"homepage":"https://example.com","version":"1.0"}"#,
        )?;
        assert_eq!(cask.token, "example");
        assert_eq!(cask.desc, None);
        Ok(())
    }

    #[test]
    fn cask_with_string_desc_parses_like_the_live_api() -> Result<()> {
        let cask: CaskInfo = serde_json::from_str(
            r#"{"token":"example","full_token":"example","desc":"Graphical app","homepage":"https://example.com","version":"1.0"}"#,
        )?;
        assert_eq!(cask.desc.as_deref(), Some("Graphical app"));
        Ok(())
    }

    #[test]
    fn cask_desc_renders_as_empty_for_null_and_verbatim_for_strings() -> Result<()> {
        let root = tempfile::tempdir()?;
        let manager = HomebrewPackageManager {
            prefix: root.path().to_path_buf(),
            cellar: root.path().join(CELLAR_DIR),
            cache: Arc::new(RwLock::new(None)),
            client: crate::core::http::download_client().clone(),
        };
        let cache = HomebrewPackageManager::build_cache(
            Vec::new(),
            vec![
                CaskInfo {
                    token: "null-desc".to_string(),
                    full_token: "null-desc".to_string(),
                    desc: None,
                    homepage: None,
                    version: Some("1.0".to_string()),
                },
                CaskInfo {
                    token: "string-desc".to_string(),
                    full_token: "string-desc".to_string(),
                    desc: Some("Graphical app".to_string()),
                    homepage: None,
                    version: Some("1.0".to_string()),
                },
            ],
        );

        let packages = manager.fuzzy_search(&cache, "desc");

        assert_eq!(packages.len(), 2);
        let by_name = |name: &str| {
            packages
                .iter()
                .find(|package| package.name == name)
                .unwrap_or_else(|| panic!("missing package {name}"))
        };
        assert_eq!(by_name("string-desc").description, "Graphical app");
        assert_eq!(by_name("null-desc").description, "");
        Ok(())
    }

    #[test]
    fn classify_packages_resolves_kind_per_name() -> Result<()> {
        let formula_map = HashMap::from([("wget".to_string(), 0usize)]);
        let cask_map = HashMap::from([("firefox".to_string(), 0usize)]);
        let kinds = classify_packages(
            &formula_map,
            &cask_map,
            &["wget".to_string(), "firefox".to_string()],
        )?;
        assert_eq!(kinds, vec![BrewKind::Formula, BrewKind::Cask]);
        Ok(())
    }

    #[test]
    fn classify_packages_resolves_ambiguous_names_to_formula_kind() {
        let formula_map = HashMap::from([("both".to_string(), 0usize)]);
        let cask_map = HashMap::from([("both".to_string(), 0usize)]);
        let kinds = classify_packages(&formula_map, &cask_map, &["both".to_string()]).unwrap();
        assert_eq!(kinds, vec![BrewKind::Formula]);
    }

    #[test]
    fn classify_packages_fails_explicitly_for_unknown_names() {
        let formula_map = HashMap::from([("wget".to_string(), 0usize)]);
        let cask_map = HashMap::from([("firefox".to_string(), 0usize)]);
        let error = classify_packages(&formula_map, &cask_map, &["unknown".to_string()])
            .expect_err("unknown names must not silently default to a kind");
        assert!(error.to_string().contains("unknown"));
    }

    #[test]
    fn brew_kind_flags_match_the_brew_cli() {
        assert_eq!(BrewKind::Formula.flag(), "--formula");
        assert_eq!(BrewKind::Cask.flag(), "--cask");
    }
}
