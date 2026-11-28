//! Debian/Ubuntu package manager backend
//!
//! This module provides full Debian/Ubuntu support using `rust-apt` FFI bindings.
//! It requires `libapt-pkg-dev` to be installed on the system.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result, anyhow};

use crate::core::is_root;
use crate::core::{Package, PackageSource};
use crate::package_managers::types::{
    LocalPackage, PackageInfo, PackageStatus, SyncPackage, parse_version_or_zero,
};

// Import rust-apt for full package management
use rust_apt::Cache;
use rust_apt::cache::{PackageSort, Upgrade};
use rust_apt::progress::{AcquireProgress, InstallProgress};

// libapt uses process-global configuration and is not thread-safe. A cache
// created on a blocking worker must retain this lease through its final use
// AND destruction; locking only Cache::new still permits concurrent FFI.
static APT_CACHE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Default)]
pub struct AptPackageManager;

impl AptPackageManager {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub async fn sync_databases(&self) -> Result<()> {
        if !is_root() {
            // Native elevation: run apt-get directly instead of re-executing
            // omg (one prompt, no re-dispatch, no double work).
            crate::core::privilege::run_privileged_program("apt-get", &["update"]).await?;
            return Ok(());
        }

        tokio::task::spawn_blocking(sync_databases_blocking)
            .await
            .context("APT sync task failed")??;
        Ok(())
    }
}

impl crate::package_managers::PackageManager for AptPackageManager {
    fn security_inventory(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Vec<crate::package_managers::types::SecurityPackage>>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async {
            tokio::task::spawn_blocking(crate::package_managers::debian_db::db::security_inventory)
                .await?
        })
    }

    fn name(&self) -> &'static str {
        "apt"
    }

    fn search(
        &self,
        query: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Package>>> + Send + '_>> {
        let query = query.to_string();
        Box::pin(async move {
            // The FST finds names quickly, but its version ranking does not
            // model APT pins or backports. Resolve all hits against one native
            // cache so displayed versions match the install candidate.
            let fast_query = query.clone();
            let fast_results =
                tokio::task::spawn_blocking(move || super::debian_db::search_fast(&fast_query))
                    .await
                    .context("Debian search task failed")?;
            if let Ok(results) = fast_results
                && !results.is_empty()
            {
                let candidates =
                    tokio::task::spawn_blocking(move || candidate_packages_for_names(results))
                        .await
                        .context("APT candidate task failed")??;
                if !candidates.is_empty() {
                    return Ok(candidates);
                }
            }

            let results = tokio::task::spawn_blocking(move || search_sync(&query))
                .await
                .context("APT search task failed")??;

            Ok(sync_to_packages(results))
        })
    }

    fn install(
        &self,
        packages: &[String],
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let packages = packages.to_vec();
        Box::pin(async move {
            crate::core::security::validate_debian_package_names_or_files(&packages)?;

            crate::core::security::policy::require_native_plan_support("APT")?;
            if !is_root() {
                let mut args = vec!["install", "--allow-local-file", "-y", "--"];
                args.extend(packages.iter().map(String::as_str));
                return crate::core::privilege::run_privileged_child(&args).await;
            }

            tokio::task::spawn_blocking(move || install_blocking(&packages))
                .await
                .context("APT install task failed")??;
            Ok(())
        })
    }

    fn remove(&self, packages: &[String]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let packages = packages.to_vec();
        Box::pin(async move {
            // SECURITY: Validate package names
            crate::core::security::validate_package_names(&packages)?;

            if !is_root() {
                let mut args = vec!["remove", "-y", "--"];
                args.extend(packages.iter().map(String::as_str));
                crate::core::privilege::run_privileged_program("apt-get", &args).await?;
                return Ok(());
            }

            tokio::task::spawn_blocking(move || remove_blocking(&packages))
                .await
                .context("APT remove task failed")??;
            Ok(())
        })
    }

    fn removal_plan<'a>(
        &'a self,
        packages: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<super::types::RemovalPackage>>> + Send + 'a>> {
        let packages = packages.to_vec();
        Box::pin(async move {
            crate::core::security::validate_package_names(&packages)?;
            tokio::task::spawn_blocking(move || {
                let (_apt_guard, cache) = open_cache_inner(&[], false)?;
                plan_removal_in_cache(&cache, &packages)
            })
            .await
            .context("APT removal simulation task failed")?
        })
    }

    fn update(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            if !is_root() {
                return crate::core::privilege::run_privileged_child(&[
                    "update",
                    "--no-sync",
                    "-y",
                ])
                .await;
            }

            tokio::task::spawn_blocking(update_blocking)
                .await
                .context("APT update task failed")??;
            Ok(())
        })
    }

    fn sync(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move { AptPackageManager::new().sync_databases().await })
    }

    fn info(
        &self,
        package: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Package>>> + Send + '_>> {
        let package = package.to_string();
        Box::pin(async move {
            // SECURITY: Validate package name
            crate::core::security::validate_package_name(&package)?;

            let info = tokio::task::spawn_blocking(move || get_sync_pkg_info(&package))
                .await
                .context("APT info task failed")??;
            Ok(info.map(|info| Package {
                name: info.name,
                version: info.version,
                description: info.description,
                source: PackageSource::Official,
                installed: info.installed,
            }))
        })
    }

    fn list_installed(&self) -> Pin<Box<dyn Future<Output = Result<Vec<Package>>> + Send + '_>> {
        Box::pin(async move {
            // Try fast path first
            if let Ok(installed) =
                tokio::task::spawn_blocking(super::debian_db::list_installed_fast)
                    .await
                    .context("Debian list_installed task failed")?
            {
                return Ok(installed
                    .into_iter()
                    .map(|p| Package {
                        name: p.name,
                        // debian_db entries carry raw version strings; the
                        // cross-backend Package expects the parsed type.
                        version: parse_version_or_zero(&p.version),
                        description: p.description,
                        source: PackageSource::Official,
                        installed: true,
                    })
                    .collect());
            }
            let installed = tokio::task::spawn_blocking(list_installed_fast)
                .await
                .context("APT installed-package task failed")??;
            Ok(local_to_packages(installed))
        })
    }

    fn get_status(
        &self,
        fast: bool,
    ) -> Pin<Box<dyn Future<Output = Result<(usize, usize, usize, usize)>> + Send + '_>> {
        Box::pin(async move {
            self.get_status_details(fast)
                .await
                .map(PackageStatus::into_counts)
        })
    }

    fn get_status_details(
        &self,
        fast: bool,
    ) -> Pin<Box<dyn Future<Output = Result<PackageStatus>> + Send + '_>> {
        Box::pin(async move {
            let fast_counts = tokio::task::spawn_blocking(super::debian_db::get_counts_fast)
                .await
                .unwrap_or_else(|error| {
                    tracing::warn!("Debian status task failed: {error}");
                    Err(anyhow::anyhow!("Debian status task panicked"))
                });
            // The accurate fallback walks the full APT cache via FFI; keep it
            // off the executor thread like every other cache walk.
            tokio::task::spawn_blocking(move || {
                super::debian_db::resolve_status_counts(fast, &fast_counts, get_system_status)
            })
            .await
            .context("APT status task failed")?
        })
    }

    fn list_explicit(&self) -> Pin<Box<dyn Future<Output = Result<Vec<String>>> + Send + '_>> {
        Box::pin(async move {
            if let Ok(explicit) = tokio::task::spawn_blocking(super::debian_db::list_explicit_fast)
                .await
                .context("Debian list_explicit task failed")?
            {
                return Ok(explicit);
            }
            tokio::task::spawn_blocking(list_explicit)
                .await
                .context("APT explicit-package task failed")?
        })
    }

    fn list_updates(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Vec<crate::package_managers::types::UpdateInfo>>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            // The FFI cache walk is blocking work; keep it off the executor
            // thread like the other trait methods.
            let updates = tokio::task::spawn_blocking(list_updates)
                .await
                .context("APT list_updates task failed")??;
            Ok(updates
                .into_iter()
                .map(
                    |(name, old_ver, new_ver)| crate::package_managers::types::UpdateInfo {
                        architecture: None,
                        name,
                        old_version: old_ver,
                        new_version: new_ver,
                        repo: "apt".to_string(),
                    },
                )
                .collect())
        })
    }

    fn is_installed(
        &self,
        package: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + '_>> {
        let package = package.to_string();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || super::debian_db::is_installed_fast(&package))
                .await
                .context("Debian is_installed task failed")?
        })
    }
}
/// Search the APT cache via FFI (fallback when the pure index misses).
///
/// Returns at most 100 matches ordered by package iteration order.
pub fn search_sync(query: &str) -> Result<Vec<SyncPackage>> {
    let (_apt_guard, cache) = open_cache(&[])?;
    let mut results = Vec::with_capacity(64);
    let query_lower = query.to_lowercase();

    for pkg in cache.packages(&PackageSort::default()) {
        let name = pkg.name();
        let matched = name.contains(&query_lower)
            || pkg.candidate().is_some_and(|candidate| {
                selected_summary(&candidate)
                    .to_lowercase()
                    .contains(&query_lower)
            });

        if matched {
            let candidate = pkg.candidate();
            let version = parse_version_or_zero(
                &candidate
                    .as_ref()
                    .map(|c| c.version().to_string())
                    .or_else(|| pkg.installed().map(|i| i.version().to_string()))
                    .unwrap_or_else(|| "unknown".to_string()),
            );

            let download_size = candidate
                .as_ref()
                .map_or(0, |v| i64::try_from(v.size()).unwrap_or(i64::MAX));

            let description = candidate.as_ref().map(selected_summary).unwrap_or_default();

            results.push(SyncPackage {
                name: name.to_string(),
                version,
                description,
                repo: "apt".to_string(),
                download_size,
                installed: pkg.is_installed(),
            });
        }

        if results.len() >= 100 {
            break;
        }
    }

    Ok(results)
}

/// APT's translated description can point at another version when several
/// suites publish the same name. Read the selected version's own Packages
/// record first; its first Description line is the short summary.
fn selected_summary(version: &rust_apt::Version<'_>) -> String {
    version
        .get_record("Description")
        .and_then(|description| {
            description
                .lines()
                .next()
                .map(str::trim)
                .filter(|summary| !summary.is_empty())
                .map(str::to_string)
        })
        .or_else(|| version.summary())
        .unwrap_or_default()
}

/// Detailed metadata for one package from the APT cache, if present.
pub fn get_sync_pkg_info(name: &str) -> Result<Option<PackageInfo>> {
    get_sync_pkg_info_selected(name, None, true)
}

/// Resolve either APT's selected candidate or one explicitly requested
/// version. The caller must never grade a different version from the target
/// passed to apt-get.
pub fn get_sync_pkg_info_for_version(
    name: &str,
    requested_version: Option<&str>,
) -> Result<Option<PackageInfo>> {
    get_sync_pkg_info_selected(name, requested_version, false)
}

fn get_sync_pkg_info_selected(
    name: &str,
    requested_version: Option<&str>,
    allow_installed_fallback: bool,
) -> Result<Option<PackageInfo>> {
    let (_apt_guard, cache) = open_cache(&[])?;
    let Some(pkg) = cache.get(name) else {
        return Ok(None);
    };

    let version = if let Some(requested) = requested_version {
        pkg.get_version(requested)
    } else {
        pkg.candidate().or_else(|| {
            if allow_installed_fallback {
                pkg.installed()
            } else {
                None
            }
        })
    };
    let Some(version) = version else {
        return Ok(None);
    };

    Ok(Some(PackageInfo {
        name: pkg.name().to_string(),
        version: parse_version_or_zero(version.version()),
        description: selected_summary(&version),
        url: None,
        size: version.size(),
        install_size: Some(i64::try_from(version.installed_size()).unwrap_or(i64::MAX)),
        download_size: Some(version.size()),
        repo: "apt".to_string(),
        depends: collect_depends(&version),
        licenses: Vec::new(),
        installed: pkg.is_installed(),
    }))
}

fn candidate_packages_for_names(matches: Vec<Package>) -> Result<Vec<Package>> {
    let (_apt_guard, cache) = open_cache(&[])?;
    Ok(matches
        .into_iter()
        .filter_map(|matched| {
            let pkg = cache.get(&matched.name)?;
            let version = pkg.candidate().or_else(|| pkg.installed())?;
            Some(Package {
                name: pkg.name().to_string(),
                version: parse_version_or_zero(version.version()),
                description: selected_summary(&version),
                source: PackageSource::Official,
                installed: pkg.is_installed(),
            })
        })
        .collect())
}

/// Build the warm daemon catalog from the same APT-selected versions used by
/// live installs. Index-ranked package metadata can belong to another suite,
/// so its dependencies and sizes must not be paired with a native candidate.
pub(crate) fn candidate_index_packages() -> Result<Vec<PackageInfo>> {
    let (_apt_guard, cache) = open_cache(&[])?;
    let mut selected: Vec<_> = cache
        .packages(&PackageSort::default())
        .enumerate()
        .filter_map(|(ordinal, pkg)| {
            let version = pkg.candidate().or_else(|| pkg.installed())?;
            let location = version
                .version_files()
                .next()
                .map(|file| file.record_location());
            Some((location, ordinal, pkg, version))
        })
        .collect();
    // APT restarts compressed-file decoding on a backwards seek. Reading the
    // already selected versions in file order keeps the full catalogue cheap.
    selected.sort_by_key(|(location, ..)| *location);
    let mut packages: Vec<_> = selected
        .into_iter()
        .map(|(_, ordinal, pkg, version)| {
            (
                ordinal,
                PackageInfo {
                    name: pkg.name().to_string(),
                    version: parse_version_or_zero(version.version()),
                    description: selected_summary(&version),
                    url: None,
                    size: version.size(),
                    install_size: Some(i64::try_from(version.installed_size()).unwrap_or(i64::MAX)),
                    download_size: Some(version.size()),
                    repo: "apt".to_string(),
                    depends: collect_depends(&version),
                    licenses: Vec::new(),
                    installed: pkg.is_installed(),
                },
            )
        })
        .collect();
    // Preserve the original native iteration order used by index tie breakers.
    packages.sort_unstable_by_key(|(ordinal, _)| *ordinal);
    let packages: Vec<_> = packages.into_iter().map(|(_, package)| package).collect();
    anyhow::ensure!(!packages.is_empty(), "APT candidate catalog is empty");
    Ok(packages)
}

/// Installed packages from the APT cache (`rust-apt` FFI path).
pub fn list_installed_fast() -> Result<Vec<LocalPackage>> {
    let (_apt_guard, cache) = open_cache(&[])?;
    let mut packages = Vec::with_capacity(512);

    for pkg in cache.packages(&PackageSort::default()) {
        if pkg.is_installed() {
            packages.push(map_local_package(&pkg));
        }
    }

    Ok(packages)
}

/// Explicitly installed (non-auto) packages, sorted alphabetically.
pub fn list_explicit() -> Result<Vec<String>> {
    let (_apt_guard, cache) = open_cache(&[])?;
    let mut explicit = Vec::with_capacity(256);

    for pkg in cache.packages(&PackageSort::default()) {
        if pkg.is_installed() && !pkg.is_auto_installed() {
            explicit.push(pkg.name().to_string());
        }
    }

    explicit.sort();
    Ok(explicit)
}

/// All available package names across configured repositories, sorted and
/// deduplicated.
pub fn list_all_package_names() -> Result<Vec<String>> {
    let (_apt_guard, cache) = open_cache(&[])?;
    let mut names = Vec::with_capacity(4096);

    for pkg in cache.packages(&PackageSort::default()) {
        names.push(pkg.name().to_string());
    }

    names.sort();
    names.dedup();
    Ok(names)
}

/// Auto-installed packages that no longer have dependents
/// (`apt-get autoremove` candidates).
pub fn list_orphans() -> Result<Vec<String>> {
    let (_apt_guard, cache) = open_cache(&[])?;
    let mut orphans = Vec::with_capacity(32);
    for pkg in cache.packages(&PackageSort::default()) {
        if pkg.is_auto_removable() {
            orphans.push(pkg.name().to_string());
        }
    }
    Ok(orphans)
}

/// Remove all auto-removable orphan packages through the normal APT elevation path.
///
/// Returns the count only after a fresh native APT cache confirms that every
/// selected package is absent.
pub async fn remove_orphans() -> Result<usize> {
    let orphans = tokio::task::spawn_blocking(list_orphans)
        .await
        .context("APT orphan listing task failed")??;
    if orphans.is_empty() {
        return Ok(0);
    }
    if is_root() {
        let selected = orphans.clone();
        tokio::task::spawn_blocking(move || remove_blocking(&selected))
            .await
            .context("APT orphan removal task failed")??;
    } else {
        crate::core::privilege::run_privileged_program("apt-get", &["autoremove", "-y"]).await?;
    }

    tokio::task::spawn_blocking(move || {
        let (_apt_guard, cache) = open_cache(&[])?;
        for name in &orphans {
            anyhow::ensure!(
                !cache
                    .get(name)
                    .is_some_and(|package| package.is_installed()),
                "APT reported success but orphan remained installed: {name}"
            );
        }
        Ok(orphans.len())
    })
    .await
    .context("APT orphan verification task failed")?
}

/// Upgradable packages as `(name, installed_version, candidate_version)`.
pub fn list_updates() -> Result<Vec<(String, String, String)>> {
    let (_apt_guard, cache) = open_cache(&[])?;
    let mut updates = Vec::with_capacity(64);

    for pkg in cache.packages(&PackageSort::default()) {
        if pkg.is_upgradable() {
            let name = pkg.name().to_string();
            let old_version = pkg
                .installed()
                .map(|v| v.version().to_string())
                .unwrap_or_default();
            let new_version = pkg
                .candidate()
                .map(|v| v.version().to_string())
                .unwrap_or_default();
            updates.push((name, old_version, new_version));
        }
    }

    Ok(updates)
}

/// Accurate system status:
/// `(installed, explicit, orphans, upgradable)`.
///
/// Walks the full APT cache; pair it with [`crate::package_managers::debian_db::get_counts_fast`]
/// through [`crate::package_managers::debian_db::resolve_status_counts`] so a
/// failed accurate query never masquerades as zero orphans/updates.
pub fn get_system_status() -> Result<(usize, usize, usize, usize)> {
    let (_apt_guard, cache) = open_cache(&[])?;
    let mut installed_count = 0;
    let mut explicit_count = 0;
    let mut orphans_count = 0;
    let mut updates_count = 0;

    for pkg in cache.packages(&PackageSort::default()) {
        if pkg.is_installed() {
            installed_count += 1;
            if !pkg.is_auto_installed() {
                explicit_count += 1;
            }
        }

        if pkg.is_upgradable() {
            updates_count += 1;
        }

        if pkg.is_auto_removable() {
            orphans_count += 1;
        }
    }

    Ok((
        installed_count,
        explicit_count,
        orphans_count,
        updates_count,
    ))
}

fn open_cache(local_files: &[String]) -> Result<(MutexGuard<'static, ()>, Cache)> {
    open_cache_inner(local_files, true)
}

fn open_cache_inner(
    local_files: &[String],
    repair_fetch_dirs: bool,
) -> Result<(MutexGuard<'static, ()>, Cache)> {
    let guard = APT_CACHE_LOCK
        .lock()
        .map_err(|_| anyhow!("APT cache lock poisoned; restart OMG before accessing libapt"))?;
    if repair_fetch_dirs {
        ensure_apt_fetch_dirs();
    }
    let files: Vec<&str> = local_files.iter().map(String::as_str).collect();
    let cache = Cache::new(&files).map_err(|e| anyhow!("APT cache error: {e:?}"))?;
    // Callers bind the guard first and cache second: reverse local drop order
    // destroys the cache before releasing the process-wide lease.
    Ok((guard, cache))
}

/// Staging directories libapt fetches into. The `apt-get` CLI creates these
/// on demand, but libapt's fetcher does not: images that ship package lists
/// without them fail every fetched commit with ENOENT on
/// `.../partial/*.deb`, which libapt surfaces as the cryptic "ordering was
/// unable to handle the media swap".
const APT_FETCH_DIRS: &[&str] = &[
    "/var/cache/apt/archives/partial",
    "/var/lib/apt/lists/partial",
];

/// Best-effort repair of [`APT_FETCH_DIRS`]. Root-only so read-only callers
/// running unprivileged can never fail here; errors are ignored because a
/// missing dir is only fatal if a later fetch actually needs it.
fn ensure_apt_fetch_dirs() {
    if !is_root() {
        return;
    }
    ensure_fetch_dirs(APT_FETCH_DIRS);
}

fn ensure_fetch_dirs(dirs: &[&str]) {
    for dir in dirs {
        let _ = std::fs::create_dir_all(dir);
    }
}

fn run_audited_apt_op(
    operation: &str,
    packages: &[String],
    action: impl FnOnce() -> Result<()>,
) -> Result<()> {
    crate::core::security::audit::record_operation(operation, packages, "attempt")?;
    let result = action();
    let status = if result.is_ok() {
        "succeeded"
    } else {
        "failed"
    };
    if let Err(audit_err) =
        crate::core::security::audit::record_operation(operation, packages, status)
    {
        if result.is_ok() {
            return Err(audit_err);
        }
        tracing::warn!("Failed to record failed {operation} audit event: {audit_err:#}");
    }
    result
}

fn install_blocking(packages: &[String]) -> Result<()> {
    run_audited_apt_op("install_blocking", packages, || {
        install_blocking_inner(packages)
    })
}

fn install_blocking_inner(packages: &[String]) -> Result<()> {
    crate::core::security::policy::require_native_plan_support("APT")?;
    if !packages
        .iter()
        .any(|target| crate::core::security::is_local_debian_package_file(target))
    {
        let (_apt_guard, _native_lock, cache) = open_transaction_cache()?;
        plan_apt_install(&cache, packages)?;
        review_apt_transaction(&cache, "install", packages)?;
        return cache
            .commit(&mut AcquireProgress::apt(), &mut InstallProgress::apt())
            .map_err(|error| anyhow!("APT install error: {error:?}"));
    }
    let staged = crate::core::security::artifact::StagedInputs::prepare(packages)?;
    let packages = staged.targets.as_slice();
    let snapshots = packages
        .iter()
        .filter(|target| crate::core::security::is_local_debian_package_file(target))
        .map(|target| {
            crate::core::security::artifact::ArchiveSnapshot::capture(std::path::Path::new(target))
        })
        .collect::<Result<Vec<_>>>()?;
    let context = serde_json::to_string(&(
        "omg-native-apt-local-v1",
        packages,
        snapshots
            .iter()
            .map(crate::core::security::artifact::ArchiveSnapshot::handoff)
            .collect::<Vec<_>>(),
    ))?;
    let subjects = vec![super::types::SecurityPackage {
        origin: super::types::SecurityOrigin::LocalArchive,
        name: "APT local archive transaction".into(),
        version: "unresolved native solver transaction".into(),
        advisory_source: None,
        architecture: None,
        description: String::new(),
        licenses: Vec::new(),
    }];
    let scanner = crate::core::security::VulnerabilityScanner::new();
    let gaps = vec!["Local Debian archives are sealed, but apt-get's complete proposed dependency versions and artifact identities are not established by this integration. Complete CVE/disclosed-zero-day coverage is unknown. https://manpages.debian.org/apt-get".into()];
    let review =
        crate::core::security::package_review::review(&subjects, &context, &gaps, &scanner)?;
    review.verify(&scanner)?;
    let mut command = crate::core::privilege::system_command("apt-get")?;
    command.args(["install", "-y", "--"]).args(packages);
    // Keep stdout live for progress, but capture stderr: apt's own
    // diagnosis (not just its exit code) is what a bug report needs.
    command.stdout(std::process::Stdio::inherit());
    let output = command
        .output()
        .context("Failed to run apt-get for Debian package installation")?;

    if !output.status.success() {
        return Err(apt_install_error(&output));
    }

    Ok(())
}

fn plan_apt_install(cache: &Cache, requests: &[String]) -> Result<()> {
    crate::core::security::validate_debian_package_specs(requests)?;
    // Select every explicit version before automatic dependencies are marked.
    for request in requests {
        let (name, pin) = request
            .split_once('=')
            .map_or((request.as_str(), None), |(name, version)| {
                (name, Some(version))
            });
        let package = cache
            .get(name)
            .with_context(|| format!("Package not found: {name}"))?;
        if let Some(pin) = pin {
            package
                .get_version(pin)
                .with_context(|| format!("APT version {pin} is not available for {name}"))?
                .set_candidate();
        }
        anyhow::ensure!(package.candidate().is_some(), "No APT candidate for {name}");
    }
    for request in requests {
        let name = request
            .split_once('=')
            .map_or(request.as_str(), |(name, _)| name);
        let package = cache
            .get(name)
            .with_context(|| format!("Package not found: {name}"))?;
        anyhow::ensure!(
            package.mark_install(true, true),
            "APT could not mark {name} for installation"
        );
        package.protect();
    }
    cache
        .resolve(true)
        .map_err(|error| anyhow!("APT resolve error: {error:?}"))?;
    for request in requests {
        if let Some((name, pin)) = request.split_once('=') {
            let selected = cache
                .get(name)
                .and_then(|package| package.install_version())
                .context("APT pinned request lacks resolved installation version")?;
            anyhow::ensure!(
                selected.version() == pin,
                "APT changed the explicitly requested version for {name}"
            );
        }
    }
    Ok(())
}

/// Build the install-failure error, preserving apt's own diagnosis.
/// Pure (no I/O) so the Debian failure path is unit-testable without apt.
fn apt_install_error(output: &std::process::Output) -> anyhow::Error {
    const MAX_TAIL_LINES: usize = 12;
    let code = output.status.code().unwrap_or(1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let lines: Vec<&str> = stderr.lines().collect();
    let tail_lines = if lines.len() > MAX_TAIL_LINES {
        &lines[lines.len() - MAX_TAIL_LINES..]
    } else {
        &lines[..]
    };
    let tail = tail_lines
        .iter()
        .map(|line| crate::cli::style::sanitize_terminal_text(line))
        .collect::<Vec<_>>()
        .join("\n");
    anyhow!(
        "apt-get failed to install Debian packages with exit code {code}; apt reported:\n{tail}"
    )
}

fn remove_blocking(packages: &[String]) -> Result<()> {
    run_audited_apt_op("remove_blocking", packages, || {
        remove_blocking_inner(packages)
    })
}

fn remove_blocking_inner(packages: &[String]) -> Result<()> {
    let (_apt_guard, _native_lock, cache) = open_transaction_cache()?;
    plan_removal_in_cache(&cache, packages)?;

    let mut acquire_progress = AcquireProgress::apt();
    let mut install_progress = InstallProgress::apt();
    cache
        .commit(&mut acquire_progress, &mut install_progress)
        .map_err(|e| anyhow!("APT commit error: {e:?}"))?;

    Ok(())
}

fn plan_removal_in_cache(
    cache: &Cache,
    packages: &[String],
) -> Result<Vec<super::types::RemovalPackage>> {
    for pkg_name in packages {
        let pkg = cache
            .get(pkg_name)
            .with_context(|| format!("Package not found: {pkg_name}"))?;
        anyhow::ensure!(pkg.is_installed(), "Package '{pkg_name}' is not installed");
        anyhow::ensure!(
            pkg.mark_delete(false),
            "APT could not mark package for removal: {pkg_name}"
        );
        pkg.protect();
    }

    cache
        .resolve(true)
        .map_err(|e| anyhow!("APT resolve error: {e:?}"))?;

    cache
        .get_changes(true)
        .map(|pkg| {
            anyhow::ensure!(
                pkg.marked_delete(),
                "APT removal would also change '{}'; inspect the transaction with apt-get",
                pkg.fullname(false)
            );
            let installed = pkg
                .installed()
                .context("APT removal target has no installed version")?;
            Ok(super::types::RemovalPackage {
                name: pkg.fullname(true),
                version: installed.version().to_owned(),
            })
        })
        .collect()
}

fn update_blocking() -> Result<()> {
    run_audited_apt_op("update_blocking", &[], update_blocking_inner)
}

fn update_blocking_inner() -> Result<()> {
    crate::core::security::policy::require_native_plan_support("APT")?;
    let (_apt_guard, _native_lock, cache) = open_transaction_cache()?;
    cache
        .upgrade(Upgrade::SafeUpgrade)
        .map_err(|e| anyhow!("APT upgrade error: {e:?}"))?;
    cache
        .resolve(true)
        .map_err(|e| anyhow!("APT resolve error: {e:?}"))?;

    review_apt_transaction(&cache, "upgrade", &[])?;

    let mut acquire_progress = AcquireProgress::apt();
    let mut install_progress = InstallProgress::apt();
    cache
        .commit(&mut acquire_progress, &mut install_progress)
        .map_err(|e| anyhow!("APT commit error: {e:?}"))?;

    Ok(())
}

struct NativeAptLock;

impl Drop for NativeAptLock {
    fn drop(&mut self) {
        rust_apt::util::apt_unlock();
    }
}

fn open_transaction_cache() -> Result<(MutexGuard<'static, ()>, NativeAptLock, Cache)> {
    let guard = APT_CACHE_LOCK
        .lock()
        .map_err(|_| anyhow!("APT cache lock poisoned"))?;
    rust_apt::util::apt_lock().map_err(|error| anyhow!("APT transaction lock: {error:?}"))?;
    let native_lock = NativeAptLock;
    ensure_apt_fetch_dirs();
    let cache = Cache::new::<&str>(&[]).map_err(|error| anyhow!("APT cache error: {error:?}"))?;
    Ok((guard, native_lock, cache))
}

fn review_apt_transaction(cache: &Cache, operation: &str, requested: &[String]) -> Result<()> {
    let (inventory, actions, gaps) = apt_transaction_evidence(cache)?;
    if inventory.is_empty() {
        return Ok(());
    }
    let context =
        serde_json::to_string(&("omg-native-apt-resolved-v1", operation, requested, actions))?;
    let scanner = crate::core::security::VulnerabilityScanner::new();
    let review =
        crate::core::security::package_review::review(&inventory, &context, &gaps, &scanner)?;
    review.verify(&scanner)
}

type AptTransactionEvidence = (
    Vec<super::types::SecurityPackage>,
    Vec<serde_json::Value>,
    Vec<String>,
);

#[derive(Debug, Clone, serde::Serialize)]
struct AptRepositoryEvidence {
    origin: Option<String>,
    site: Option<String>,
    archive: Option<String>,
    index_path: Option<String>,
    label: Option<String>,
    downloadable: bool,
    native_trusted: Option<bool>,
    archive_uri: Option<String>,
    sha256: Option<String>,
}

fn apt_repository_matches_vendor(expected: &str, record: &AptRepositoryEvidence) -> bool {
    // IsTrusted also permits configured trusted=yes. The publisher transport
    // must be established independently; other mirrors need signer evidence.
    if !record.downloadable
        || record.native_trusted != Some(true)
        || record.origin.as_deref() != Some(expected)
    {
        return false;
    }
    let Some(uri) = record
        .archive_uri
        .as_deref()
        .and_then(|uri| reqwest::Url::parse(uri).ok())
    else {
        return false;
    };
    if uri.scheme() != "https"
        || !uri.username().is_empty()
        || uri.password().is_some()
        || uri.port_or_known_default() != Some(443)
        || uri.query().is_some()
        || uri.fragment().is_some()
        || record.site.as_deref() != uri.host_str()
    {
        return false;
    }
    let path = uri.path();
    let normalized = path.to_ascii_lowercase();
    if normalized.contains("%2f")
        || normalized.contains("%5c")
        || normalized.contains("%2e")
        || std::path::Path::new(path).extension() != Some(std::ffi::OsStr::new("deb"))
    {
        return false;
    }
    match (expected, uri.host_str()) {
        ("Debian", Some("deb.debian.org")) => {
            path.starts_with("/debian/pool/") || path.starts_with("/debian-security/pool/")
        }
        ("Debian", Some("security.debian.org")) => path.starts_with("/debian-security/pool/"),
        ("Ubuntu", Some("archive.ubuntu.com" | "security.ubuntu.com")) => {
            path.starts_with("/ubuntu/pool/")
        }
        ("Ubuntu", Some("ports.ubuntu.com")) => path.starts_with("/ubuntu-ports/pool/"),
        _ => false,
    }
}

fn apt_transaction_evidence(cache: &Cache) -> Result<AptTransactionEvidence> {
    use super::types::{SecurityOrigin, SecurityPackage};
    let mut inventory = Vec::new();
    let mut actions = Vec::new();
    let mut gaps = Vec::new();
    for package in cache.get_changes(true) {
        if package.marked_delete() {
            actions.push(serde_json::json!({"remove":package.fullname(true),"version":package.installed().map(|version| version.version().to_owned())}));
            continue;
        }
        let version = package
            .install_version()
            .context("APT change lacks resolved installation version")?;
        let origins = version
            .version_files()
            .map(|record| {
                let file = record.package_file();
                let downloadable = file.is_downloadable();
                AptRepositoryEvidence {
                    origin: file.origin().map(str::to_owned),
                    site: file.site().map(str::to_owned),
                    archive: file.archive().map(str::to_owned),
                    index_path: file.filename().map(str::to_owned),
                    label: file.label().map(str::to_owned),
                    downloadable,
                    native_trusted: downloadable.then(|| file.index_file().is_trusted()),
                    archive_uri: downloadable
                        .then(|| file.index_file().archive_uri(&record.lookup().filename())),
                    sha256: record.lookup().hash_find("sha256".into()),
                }
            })
            .collect::<Vec<_>>();
        let expected_origin = match crate::core::env::distro::detect_distro() {
            crate::core::env::distro::Distro::Debian => Some("Debian"),
            crate::core::env::distro::Distro::Ubuntu => Some("Ubuntu"),
            _ => None,
        };
        let downloadable = origins
            .iter()
            .filter(|record| record.downloadable)
            .collect::<Vec<_>>();
        let native_origin = expected_origin.is_some_and(|expected| {
            !downloadable.is_empty()
                && downloadable
                    .iter()
                    .all(|record| apt_repository_matches_vendor(expected, record))
        });
        let digest = version.sha256();
        if digest.as_ref().is_none_or(|value| {
            value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        }) {
            gaps.push(format!(
                "APT resolved package {} has no established SHA256 archive identity",
                package.fullname(true)
            ));
        }
        if !native_origin {
            gaps.push(format!(
                "APT publisher identity for {} is unestablished. Release Origin and configured index trust alone are insufficient; signing-key fingerprints are not exposed by this API. Covered distribution mapping requires matching vendor HTTPS archive/site and native index trust. Other mirrors remain Unknown.",
                package.fullname(true)
            ));
        }
        let identity = SecurityPackage {
            origin: if native_origin {
                SecurityOrigin::DistributionPackage
            } else {
                SecurityOrigin::OtherRepository {
                    repository: "APT configured repositories".into(),
                }
            },
            name: package.name().to_owned(),
            version: version.version().to_owned(),
            advisory_source: Some((
                version.source_name().to_owned(),
                version.source_version().to_owned(),
            )),
            architecture: Some(version.arch().to_owned()),
            description: version.summary().unwrap_or_default(),
            licenses: Vec::new(),
        };
        actions.push(serde_json::json!({"install":identity.name,"version":identity.version,"source":identity.advisory_source,"architecture":identity.architecture,"sha256":digest,"uris":origins.iter().filter_map(|record| record.archive_uri.as_ref()).collect::<Vec<_>>(),"repositories":origins}));
        inventory.push(identity);
    }
    Ok((inventory, actions, gaps))
}

fn sync_databases_blocking() -> Result<()> {
    let (_apt_guard, cache) = open_cache(&[])?;
    let mut progress = AcquireProgress::apt();
    cache
        .update(&mut progress)
        .map_err(|e| anyhow!("APT update error: {e:?}"))?;
    Ok(())
}

fn map_local_package(pkg: &rust_apt::Package<'_>) -> LocalPackage {
    let version = pkg
        .installed()
        .or_else(|| pkg.candidate())
        .map_or_else(|| "unknown".to_string(), |ver| ver.version().to_string());
    let summary = pkg
        .installed()
        .and_then(|ver| ver.summary())
        .or_else(|| pkg.candidate().and_then(|v| v.summary()))
        .unwrap_or_default();
    let reason = if pkg.is_auto_installed() {
        "dependency"
    } else {
        "explicit"
    };
    LocalPackage {
        name: pkg.name().to_string(),
        version: parse_version_or_zero(&version),
        description: summary,
        install_size: pkg.installed().map_or(0, |version| {
            i64::try_from(version.installed_size()).unwrap_or(i64::MAX)
        }),
        reason,
        licenses: Vec::new(),
    }
}

fn collect_depends(version: &rust_apt::Version<'_>) -> Vec<String> {
    let mut depends = Vec::new();
    if let Some(deps) = version.dependencies() {
        for dep in deps {
            if dep.is_or() {
                for base in dep.iter() {
                    depends.push(base.name().to_string());
                }
            } else {
                let base = dep.first();
                depends.push(base.name().to_string());
            }
        }
    }
    depends
}

fn sync_to_packages(sync_pkgs: Vec<SyncPackage>) -> Vec<Package> {
    sync_pkgs
        .into_iter()
        .map(|pkg| Package {
            name: pkg.name,
            version: pkg.version,
            description: pkg.description,
            source: PackageSource::Official,
            installed: pkg.installed,
        })
        .collect()
}

fn local_to_packages(local_pkgs: Vec<LocalPackage>) -> Vec<Package> {
    local_pkgs
        .into_iter()
        .map(|pkg| Package {
            name: pkg.name,
            version: pkg.version,
            description: pkg.description,
            source: PackageSource::Official,
            installed: true,
        })
        .collect()
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::{APT_FETCH_DIRS, apt_install_error, ensure_fetch_dirs};

    #[test]
    fn spoofed_release_origin_or_configured_trust_never_establish_vendor_mapping() {
        let official = super::AptRepositoryEvidence {
            origin: Some("Debian".into()),
            site: Some("deb.debian.org".into()),
            archive: Some("stable".into()),
            index_path: Some("/var/lib/apt/lists/controlled_Packages".into()),
            label: Some("Debian".into()),
            downloadable: true,
            native_trusted: Some(true),
            archive_uri: Some(
                "https://deb.debian.org/debian/pool/main/f/fixture/fixture_1-1_amd64.deb".into(),
            ),
            sha256: Some("0".repeat(64)),
        };
        assert!(super::apt_repository_matches_vendor("Debian", &official));
        assert!(!super::apt_repository_matches_vendor("Ubuntu", &official));
        for (site, uri, trusted) in [
            (
                "attacker.invalid",
                "https://attacker.invalid/debian/pool/fixture_1.deb",
                true,
            ),
            (
                "deb.debian.org.attacker.invalid",
                "https://deb.debian.org.attacker.invalid/debian/pool/fixture_1.deb",
                true,
            ),
            (
                "deb.debian.org",
                "https://attacker.invalid/debian/pool/fixture_1.deb",
                true,
            ),
            (
                "deb.debian.org",
                "http://deb.debian.org/debian/pool/fixture_1.deb",
                true,
            ),
            (
                "deb.debian.org",
                "https://deb.debian.org/unestablished/fixture_1.deb",
                true,
            ),
            (
                "deb.debian.org",
                "https://deb.debian.org/debian/pool/fixture_1.deb?source=other",
                true,
            ),
            (
                "deb.debian.org",
                "https://deb.debian.org/debian/pool/fixture_1.deb",
                false,
            ),
            (
                "mirror.invalid",
                "https://mirror.invalid/debian/pool/fixture_1.deb",
                true,
            ),
        ] {
            let record = super::AptRepositoryEvidence {
                site: Some(site.into()),
                archive_uri: Some(uri.into()),
                native_trusted: Some(trusted),
                ..official.clone()
            };
            assert!(
                !super::apt_repository_matches_vendor("Debian", &record),
                "Origin spoof mapped: {record:?}"
            );
        }
    }

    #[test]
    fn native_pinned_install_selects_requested_version_architecture_and_dependencies()
    -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let (_guard, baseline) = super::open_cache_inner(&[], false)?;
        let architecture = baseline
            .get("apt")
            .and_then(|package| package.candidate())
            .map(|version| version.arch().to_owned())
            .expect("native APT architecture");
        drop(baseline);
        let packages = directory.path().join("Packages");
        let record = |name: &str, version: &str, dependency: &str, hash: char| {
            format!(
                "Package: {name}\nVersion: {version}\nArchitecture: {architecture}\n{dependency}Filename: pool/{name}_{version}.deb\nSize: 1\nSHA256: {}\nDescription: controlled pinned solver fixture\n\n",
                hash.to_string().repeat(64)
            )
        };
        std::fs::write(
            &packages,
            [
                record(
                    "omg-pin-fixture-app",
                    "2:1.0~rc1-3",
                    "Depends: omg-pin-fixture-dep (= 2:0.9-1)\n",
                    '0',
                ),
                record(
                    "omg-pin-fixture-app",
                    "3:2.0-1",
                    "Depends: omg-pin-fixture-dep (= 3:1.0-1)\n",
                    '1',
                ),
                record("omg-pin-fixture-dep", "2:0.9-1", "", '2'),
                record("omg-pin-fixture-dep", "3:1.0-1", "", '3'),
            ]
            .join(""),
        )?;
        let cache = rust_apt::Cache::new(&[packages.to_string_lossy().as_ref()])
            .map_err(|error| anyhow::anyhow!("native pinned fixture cache: {error:?}"))?;
        assert_eq!(
            cache
                .get("omg-pin-fixture-app")
                .and_then(|package| package.candidate())
                .unwrap()
                .version(),
            "3:2.0-1"
        );
        let root_request = format!("omg-pin-fixture-app:{architecture}=2:1.0~rc1-3");
        // Native APT will not silently select an older dependency candidate.
        // The CLI simulation also refuses this unresolved root-only request.
        assert!(super::plan_apt_install(&cache, std::slice::from_ref(&root_request)).is_err());
        drop(cache);
        let cache = rust_apt::Cache::new(&[packages.to_string_lossy().as_ref()])
            .map_err(|error| anyhow::anyhow!("fresh pinned fixture cache: {error:?}"))?;
        super::plan_apt_install(
            &cache,
            &[
                root_request,
                format!("omg-pin-fixture-dep:{architecture}=2:0.9-1"),
            ],
        )?;
        let (inventory, actions, gaps) = super::apt_transaction_evidence(&cache)?;
        assert_eq!(inventory.len(), 2);
        assert_eq!(
            (
                &*inventory[0].name,
                &*inventory[0].version,
                inventory[0].architecture.as_deref()
            ),
            (
                "omg-pin-fixture-app",
                "2:1.0~rc1-3",
                Some(architecture.as_str())
            )
        );
        assert_eq!(
            (&*inventory[1].name, &*inventory[1].version),
            ("omg-pin-fixture-dep", "2:0.9-1")
        );
        assert_eq!(actions[0]["sha256"], "0".repeat(64));
        assert!(
            actions[0]["repositories"]
                .as_array()
                .unwrap()
                .iter()
                .all(|record| record.get("native_trusted").is_some()
                    && record.get("archive_uri").is_some())
        );
        assert!(!gaps.is_empty());
        let missing =
            super::plan_apt_install(&cache, &["omg-pin-fixture-app=999.0-1".into()]).unwrap_err();
        assert!(missing.to_string().contains("not available"), "{missing:#}");
        Ok(())
    }

    #[test]
    fn native_solver_admission_includes_dependencies_source_versions_and_archive_hashes()
    -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let packages = directory.path().join("Packages");
        std::fs::write(
            &packages,
            format!(
                "Package: omg-admission-fixture-app\nVersion: 2:1.0~rc1-3\nArchitecture: all\nDepends: omg-admission-fixture-dep (= 2:0.9-1)\nSource: omg-admission-fixture-source (2:0.8-1)\nFilename: pool/app.deb\nSize: 1\nSHA256: {}\nDescription: controlled solver fixture\n\nPackage: omg-admission-fixture-dep\nVersion: 2:0.9-1\nArchitecture: all\nFilename: pool/dep.deb\nSize: 1\nSHA256: {}\nDescription: controlled dependency fixture\n\n",
                "0".repeat(64),
                "1".repeat(64)
            ),
        )?;
        let (_guard, cache) =
            super::open_cache_inner(&[packages.to_string_lossy().into_owned()], false)?;
        let package = cache
            .get("omg-admission-fixture-app")
            .expect("native local package");
        assert!(package.mark_install(true, true));
        package.protect();
        cache
            .resolve(true)
            .map_err(|error| anyhow::anyhow!("native fixture resolve: {error:?}"))?;
        let (inventory, actions, gaps) = super::apt_transaction_evidence(&cache)?;
        assert_eq!(inventory.len(), 2);
        assert_eq!(inventory[0].version, "2:1.0~rc1-3");
        assert_eq!(
            inventory[0].advisory_source,
            Some(("omg-admission-fixture-source".into(), "2:0.8-1".into()))
        );
        assert_eq!(inventory[1].name, "omg-admission-fixture-dep");
        assert_eq!(inventory[1].version, "2:0.9-1");
        assert_eq!(actions[0]["sha256"], "0".repeat(64));
        assert!(
            !gaps.is_empty(),
            "unsigned local Packages fixture must not become distribution coverage"
        );
        assert!(inventory.iter().all(|package| !matches!(
            package.origin,
            super::super::types::SecurityOrigin::DistributionPackage
        )));
        Ok(())
    }

    #[test]
    #[serial_test::serial]
    fn concurrent_native_status_queries_preserve_consistent_counts() {
        let expected = super::get_system_status().expect("baseline native APT status");
        assert!(
            expected.0 > 0,
            "regression requires a real installed APT database"
        );
        let barrier = std::sync::Barrier::new(4);
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    let barrier = &barrier;
                    scope.spawn(move || {
                        barrier.wait();
                        for _ in 0..8 {
                            assert_eq!(
                                super::get_system_status().expect("concurrent APT query"),
                                expected
                            );
                        }
                    })
                })
                .collect();
            for handle in handles {
                handle.join().expect("native APT query worker");
            }
        });
    }

    #[test]
    #[serial_test::serial]
    fn native_cache_retains_exclusive_lease_until_destroyed() {
        let (guard, cache) = super::open_cache(&[]).expect("native cache");
        assert!(super::APT_CACHE_LOCK.try_lock().is_err());
        // Exercise an actual native cache read while the lease is held.
        assert!(
            cache
                .packages(&rust_apt::cache::PackageSort::default())
                .next()
                .is_some()
        );
        drop(cache);
        assert!(super::APT_CACHE_LOCK.try_lock().is_err());
        drop(guard);
        assert!(super::APT_CACHE_LOCK.try_lock().is_ok());
    }

    #[test]
    #[serial_test::serial]
    fn native_removal_plan_includes_reverse_dependencies_without_writing_status()
    -> anyhow::Result<()> {
        let _guard = super::APT_CACHE_LOCK.lock().unwrap();
        let directory = tempfile::tempdir()?;
        let status = directory.path().join("status");
        let original = "Package: application\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.0\nDepends: library\nDescription: application fixture\n\nPackage: library\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\nDescription: library fixture\n";
        std::fs::write(&status, original)?;
        let sources = directory.path().join("sources.list");
        std::fs::write(&sources, "")?;
        let config = rust_apt::config::Config::new();
        let overrides = [
            ("Dir::State::status", status.to_str().unwrap()),
            ("Dir::Etc::sourcelist", sources.to_str().unwrap()),
            ("Dir::Etc::sourceparts", directory.path().to_str().unwrap()),
            ("Dir::Cache::pkgcache", ""),
            ("Dir::Cache::srcpkgcache", ""),
        ];
        struct Restore(Vec<(&'static str, Option<String>)>);
        impl Drop for Restore {
            fn drop(&mut self) {
                let config = rust_apt::config::Config::new();
                for (key, value) in &self.0 {
                    config.clear(key);
                    if let Some(value) = value {
                        config.set(key, value);
                    }
                }
            }
        }
        let _restore = Restore(
            overrides
                .iter()
                .map(|(key, _)| (*key, config.get(key)))
                .collect(),
        );
        for (key, value) in overrides {
            config.set(key, value);
        }
        let cache = rust_apt::Cache::new::<&str>(&[])
            .map_err(|error| anyhow::anyhow!("fixture cache: {error:?}"))?;
        let plan = super::plan_removal_in_cache(&cache, &["library".into()])?;
        assert_eq!(
            plan.iter()
                .map(|package| package.name.as_str())
                .collect::<Vec<_>>(),
            ["application", "library"]
        );
        assert_eq!(std::fs::read_to_string(status)?, original);
        Ok(())
    }

    fn failed_output(stderr: &[u8]) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt as _;
        std::process::Output {
            status: std::process::ExitStatus::from_raw(256),
            stdout: Vec::new(),
            stderr: stderr.to_vec(),
        }
    }

    #[test]
    fn install_error_preserves_apt_diagnosis() {
        let error = apt_install_error(&failed_output(
            b"Err: 2 https://deb.debian.org/debian tree amd64 2.1.0-1\n  Could not open partial file\nError: APT commit error: ordering was unable to handle the media swap\n",
        ));
        let message = format!("{error}");
        for needle in [
            "exit code 1",
            "ordering was unable to handle the media swap",
            "Could not open partial file",
        ] {
            assert!(message.contains(needle), "missing {needle:?} in: {message}");
        }
    }

    #[test]
    fn fetch_dir_repair_creates_nested_partial_dirs_idempotently() {
        assert_eq!(
            APT_FETCH_DIRS,
            [
                "/var/cache/apt/archives/partial",
                "/var/lib/apt/lists/partial"
            ]
        );
        let root = std::env::temp_dir().join(format!("omg-apt-partial-{}", std::process::id()));
        let nested = root.join("archives/partial");
        let target = [nested.to_str().expect("temp path must be UTF-8")];
        ensure_fetch_dirs(&target);
        assert!(nested.is_dir(), "repair must create {nested:?}");
        ensure_fetch_dirs(&target);
        assert!(nested.is_dir(), "repair must be idempotent for {nested:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn install_error_caps_long_stderr_to_a_tail() {
        let mut stderr = Vec::new();
        for index in 0..30 {
            stderr.extend_from_slice(format!("progress line {index}\n").as_bytes());
        }
        stderr.extend_from_slice(b"final diagnosis\n");
        let message = format!(
            "{error}",
            error = apt_install_error(&failed_output(&stderr))
        );
        assert!(message.contains("final diagnosis"));
        assert!(!message.contains("progress line 0"));
        assert!(message.contains("progress line 29"));
    }

    #[test]
    fn install_error_sanitizes_terminal_controls_from_repository_text() {
        let message = apt_install_error(&failed_output(
            b"repository package \x1b]52;c;secret\x07 failed\nnext line\n",
        ))
        .to_string();
        assert!(
            !message
                .chars()
                .any(|character| character != '\n' && character.is_control())
        );
        assert!(message.contains("repository package ]52;c;secret failed"));
        assert!(message.contains("\nnext line"));
    }
}
