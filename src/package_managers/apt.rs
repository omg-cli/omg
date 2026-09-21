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
    LocalPackage, PackageInfo, SyncPackage, parse_version_or_zero,
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
            // Try fast path first (index/mmap loading does disk I/O; keep it
            // off the executor thread)
            let fast_query = query.clone();
            let fast_results =
                tokio::task::spawn_blocking(move || super::debian_db::search_fast(&fast_query))
                    .await
                    .context("Debian search task failed")?;
            if let Ok(results) = fast_results
                && !results.is_empty()
            {
                return Ok(results);
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

    fn update(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            if !is_root() {
                crate::core::privilege::run_privileged_program("apt-get", &["upgrade", "-y"])
                    .await?;
                return Ok(());
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

            // Try fast path first
            let fast_package = package.clone();
            if let Ok(Some(pkg)) =
                tokio::task::spawn_blocking(move || super::debian_db::get_info_fast(&fast_package))
                    .await
                    .context("Debian info task failed")?
            {
                return Ok(Some(pkg));
            }

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
            || pkg
                .candidate()
                .and_then(|c| c.summary())
                .is_some_and(|s| s.to_lowercase().contains(&query_lower));

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

            let description = candidate.and_then(|c| c.summary()).unwrap_or_default();

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

/// Detailed metadata for one package from the APT cache, if present.
pub fn get_sync_pkg_info(name: &str) -> Result<Option<PackageInfo>> {
    let (_apt_guard, cache) = open_cache(&[])?;
    let Some(pkg) = cache.get(name) else {
        return Ok(None);
    };

    let Some(version) = pkg.candidate().or_else(|| pkg.installed()) else {
        return Ok(None);
    };

    Ok(Some(PackageInfo {
        name: pkg.name().to_string(),
        version: parse_version_or_zero(version.version()),
        description: version.summary().unwrap_or_default(),
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

/// Remove all auto-removable orphan packages with the same elevation contract
/// as other mutating APT operations.
pub async fn remove_orphans() -> Result<()> {
    let orphans = tokio::task::spawn_blocking(list_orphans)
        .await
        .context("APT orphan listing task failed")??;
    if orphans.is_empty() {
        return Ok(());
    }
    if !is_root() {
        crate::core::privilege::run_privileged_program("apt-get", &["autoremove", "-y"]).await?;
        return Ok(());
    }
    tokio::task::spawn_blocking(move || remove_blocking(&orphans))
        .await
        .context("APT orphan removal task failed")??;
    Ok(())
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
    let guard = APT_CACHE_LOCK
        .lock()
        .map_err(|_| anyhow!("APT cache lock poisoned; restart OMG before accessing libapt"))?;
    ensure_apt_fetch_dirs();
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

fn install_blocking(packages: &[String]) -> Result<()> {
    crate::core::security::audit::record_operation("install_blocking", packages, "attempt")?;
    let result = install_blocking_inner(packages);
    crate::core::security::audit::record_operation(
        "install_blocking",
        packages,
        if result.is_ok() {
            "succeeded"
        } else {
            "failed"
        },
    )?;
    result
}

fn install_blocking_inner(packages: &[String]) -> Result<()> {
    crate::core::security::policy::require_native_plan_support("APT")?;
    let staged = crate::core::security::artifact::StagedInputs::prepare(packages)?;
    let packages = staged.targets.as_slice();
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
    crate::core::security::audit::record_operation("remove_blocking", packages, "attempt")?;
    let result = remove_blocking_inner(packages);
    crate::core::security::audit::record_operation(
        "remove_blocking",
        packages,
        if result.is_ok() {
            "succeeded"
        } else {
            "failed"
        },
    )?;
    result
}

fn remove_blocking_inner(packages: &[String]) -> Result<()> {
    let (_apt_guard, cache) = open_cache(&[])?;
    for pkg_name in packages {
        let pkg = cache
            .get(pkg_name)
            .with_context(|| format!("Package not found: {pkg_name}"))?;
        anyhow::ensure!(
            pkg.mark_delete(false),
            "APT could not mark package for removal: {pkg_name}"
        );
        pkg.protect();
    }

    cache
        .resolve(true)
        .map_err(|e| anyhow!("APT resolve error: {e:?}"))?;

    let mut acquire_progress = AcquireProgress::apt();
    let mut install_progress = InstallProgress::apt();
    cache
        .commit(&mut acquire_progress, &mut install_progress)
        .map_err(|e| anyhow!("APT commit error: {e:?}"))?;

    Ok(())
}

fn update_blocking() -> Result<()> {
    crate::core::security::audit::record_operation("update_blocking", &[], "attempt")?;
    let result = update_blocking_inner();
    crate::core::security::audit::record_operation(
        "update_blocking",
        &[],
        if result.is_ok() {
            "succeeded"
        } else {
            "failed"
        },
    )?;
    result
}

fn update_blocking_inner() -> Result<()> {
    crate::core::security::policy::require_native_plan_support("APT")?;
    let (_apt_guard, cache) = open_cache(&[])?;
    cache
        .upgrade(Upgrade::SafeUpgrade)
        .map_err(|e| anyhow!("APT upgrade error: {e:?}"))?;
    cache
        .resolve(true)
        .map_err(|e| anyhow!("APT resolve error: {e:?}"))?;

    let mut acquire_progress = AcquireProgress::apt();
    let mut install_progress = InstallProgress::apt();
    cache
        .commit(&mut acquire_progress, &mut install_progress)
        .map_err(|e| anyhow!("APT commit error: {e:?}"))?;

    Ok(())
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
