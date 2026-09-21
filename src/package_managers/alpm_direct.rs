//! Direct ALPM (Arch Linux Package Manager) integration.
//!
//! Queries libalpm through a cached per-thread handle instead of spawning a
//! pacman subprocess for each query.

use alpm::{Alpm, PackageReason};
use anyhow::{Context, Result};

use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::core::paths;
use crate::package_managers::pacman_db;
use crate::package_managers::types::{
    LocalPackage, PackageInfo, SyncPackage, contains_ignore_case, is_orphan_package, parse_version,
};

static CACHE_EPOCH: AtomicU64 = AtomicU64::new(0);

struct CachedAlpm {
    handle: Alpm,
    software_epoch: u64,
    disk_epoch: pacman_db::AlpmCatalogEpoch,
}

thread_local! {
    static ALPM_HANDLE: RefCell<Option<CachedAlpm>> = const { RefCell::new(None) };
}

fn cached_alpm_is_reusable(
    software_loaded: u64,
    software_now: u64,
    disk_loaded: pacman_db::AlpmCatalogEpoch,
    disk_now: pacman_db::AlpmCatalogEpoch,
) -> bool {
    software_loaded == software_now && disk_now == disk_loaded
}

fn create_alpm_handle() -> Result<Alpm> {
    use crate::package_managers::alpm_ops::open_default_alpm;
    let alpm = open_default_alpm().context("Failed to initialize ALPM handle")?;
    let config = crate::core::pacman_conf::PacmanConfig::parse(paths::pacman_conf_path())
        .context("Failed to load repositories from pacman.conf")?;
    crate::package_managers::alpm_ops::configure_signature_policy(&alpm, &config)?;
    crate::package_managers::alpm_ops::register_configured_syncdbs(&alpm, &config)
        .context("Failed to register the complete pacman repository set")?;

    Ok(alpm)
}

fn refresh_cached_handle(cached: &mut Option<CachedAlpm>, current_software: u64) -> Result<()> {
    let disk_now =
        pacman_db::AlpmCatalogEpoch::observe().context("Failed to observe ALPM catalog epoch")?;
    if cached.as_ref().is_some_and(|loaded| {
        cached_alpm_is_reusable(
            loaded.software_epoch,
            current_software,
            loaded.disk_epoch,
            disk_now,
        )
    }) {
        return Ok(());
    }
    let (handle, disk_epoch) = pacman_db::AlpmCatalogEpoch::load_stable(
        pacman_db::AlpmCatalogEpoch::observe,
        create_alpm_handle,
    )
    .context("Failed to load a stable ALPM handle")?;
    *cached = Some(CachedAlpm {
        handle,
        software_epoch: current_software,
        disk_epoch,
    });
    Ok(())
}

/// Get a cached ALPM handle or create a new one for this thread.
pub fn with_handle<F, R>(f: F) -> Result<R>
where
    F: FnOnce(&Alpm) -> Result<R>,
{
    ALPM_HANDLE.with(|cell| {
        let current_epoch = CACHE_EPOCH.load(Ordering::Acquire);
        let mut maybe_handle = cell
            .try_borrow_mut()
            .context("Nested ALPM handle access is not supported")?;
        refresh_cached_handle(&mut maybe_handle, current_epoch)?;

        let handle = &maybe_handle
            .as_ref()
            .context("ALPM handle initialization failed")?
            .handle;
        f(handle)
    })
}

/// Get a mutable cached ALPM handle.
pub fn with_handle_mut<F, R>(f: F) -> Result<R>
where
    F: FnOnce(&mut Alpm) -> Result<R>,
{
    ALPM_HANDLE.with(|cell| {
        let current_epoch = CACHE_EPOCH.load(Ordering::Acquire);
        let mut maybe_handle = cell
            .try_borrow_mut()
            .context("Nested ALPM handle access is not supported")?;
        refresh_cached_handle(&mut maybe_handle, current_epoch)?;

        let handle = &mut maybe_handle
            .as_mut()
            .context("ALPM handle initialization failed")?
            .handle;
        f(handle)
    })
}

/// Invalidate ALPM handles across all threads.
///
/// Increments the global cache epoch, causing all threads to create fresh
/// ALPM handles on their next operation. This is necessary after sync
/// operations that run in a different process (via sudo).
pub fn clear_alpm_cache() {
    CACHE_EPOCH.fetch_add(1, Ordering::Release);
}

/// Search sync databases (available packages) - FAST (<10ms)
pub fn search_sync(query: &str) -> Result<Vec<SyncPackage>> {
    with_handle(|handle| {
        let mut results = Vec::with_capacity(64);

        for db in handle.syncdbs() {
            for pkg in db.pkgs() {
                if contains_ignore_case(pkg.name(), query)
                    || pkg.desc().is_some_and(|d| contains_ignore_case(d, query))
                {
                    let installed = handle.localdb().pkg(pkg.name()).is_ok();

                    // A version that fails the strict parser must not compare
                    // as a fabricated 0 (ARCH-R14); skip the entry visibly.
                    let Some(version) = parse_version(pkg.version()) else {
                        tracing::warn!(
                            "Skipping sync package '{}' with unparseable version '{}'",
                            pkg.name(),
                            pkg.version()
                        );
                        continue;
                    };

                    results.push(SyncPackage {
                        name: pkg.name().to_string(),
                        version,
                        description: pkg.desc().unwrap_or("").to_string(),
                        repo: db.name().to_string(),
                        download_size: pkg.download_size(),
                        installed,
                    });
                }
            }
        }

        Ok(results)
    })
}

/// Get package info - INSTANT (<1ms)
pub fn get_package_info(name: &str) -> Result<Option<PackageInfo>> {
    with_handle(|handle| {
        // Try local first
        if let Ok(pkg) = handle.localdb().pkg(name) {
            let Some(version) = parse_version(pkg.version()) else {
                tracing::warn!(
                    "Ignoring local package '{name}' with unparseable version '{}'",
                    pkg.version()
                );
                return Ok(None);
            };
            return Ok(Some(PackageInfo {
                name: pkg.name().to_string(),
                version,
                description: pkg.desc().unwrap_or("").to_string(),
                url: pkg.url().map(std::string::ToString::to_string),
                size: pkg.isize().try_into().unwrap_or(0),
                install_size: Some(pkg.isize()),
                download_size: None,
                repo: "local".to_string(),
                depends: pkg.depends().iter().map(|d| d.name().to_string()).collect(),
                licenses: pkg
                    .licenses()
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect(),
                installed: true,
            }));
        }

        // Try sync databases
        for db in handle.syncdbs() {
            if let Ok(pkg) = db.pkg(name) {
                let Some(version) = parse_version(pkg.version()) else {
                    tracing::warn!(
                        "Ignoring sync package '{name}' with unparseable version '{}'",
                        pkg.version()
                    );
                    return Ok(None);
                };
                return Ok(Some(PackageInfo {
                    name: pkg.name().to_string(),
                    version,
                    description: pkg.desc().unwrap_or("").to_string(),
                    url: pkg.url().map(std::string::ToString::to_string),
                    size: pkg.isize().try_into().unwrap_or(0),
                    install_size: Some(pkg.isize()),
                    download_size: Some(pkg.download_size().try_into().unwrap_or(0)),
                    repo: db.name().to_string(),
                    depends: pkg.depends().iter().map(|d| d.name().to_string()).collect(),
                    licenses: pkg
                        .licenses()
                        .iter()
                        .map(std::string::ToString::to_string)
                        .collect(),
                    installed: false,
                }));
            }
        }

        Ok(None)
    })
}

/// Preserve native ALPM identities and license metadata for security exports.
pub fn security_inventory() -> Result<Vec<crate::package_managers::types::SecurityPackage>> {
    with_handle(|handle| {
        handle
            .localdb()
            .pkgs()
            .iter()
            .map(|package| {
                let name = package.name().to_owned();
                let version = package.version().to_string();
                let architecture = package
                    .arch()
                    .context("Installed ALPM package lacks architecture")?
                    .to_owned();
                anyhow::ensure!(
                    !name.is_empty() && !version.is_empty() && !architecture.is_empty(),
                    "Incomplete installed ALPM identity"
                );
                Ok(crate::package_managers::types::SecurityPackage {
                    name,
                    version,
                    architecture: Some(architecture),
                    description: package.desc().unwrap_or("").to_owned(),
                    licenses: package.licenses().into_iter().map(str::to_owned).collect(),
                })
            })
            .collect()
    })
}

/// List all installed packages - INSTANT
pub fn list_installed_fast() -> Result<Vec<LocalPackage>> {
    with_handle(|handle| {
        let localdb = handle.localdb();
        let pkg_count = localdb.pkgs().len();

        let mut results = Vec::with_capacity(pkg_count);
        results.extend(localdb.pkgs().iter().filter_map(|pkg| {
            // A version that fails the strict parser must not compare as a
            // fabricated 0 (ARCH-R14); skip the entry visibly.
            let Some(version) = parse_version(pkg.version()) else {
                tracing::warn!(
                    "Skipping installed package '{}' with unparseable version '{}'",
                    pkg.name(),
                    pkg.version()
                );
                return None;
            };
            Some(LocalPackage {
                name: pkg.name().to_string(),
                version,
                description: pkg.desc().unwrap_or("").to_string(),
                install_size: pkg.isize(),
                reason: match pkg.reason() {
                    PackageReason::Explicit => "explicit",
                    PackageReason::Depend => "dependency",
                },
                licenses: pkg.licenses().into_iter().map(str::to_string).collect(),
            })
        }));

        Ok(results)
    })
}

/// List explicitly installed packages - INSTANT
pub fn list_explicit_fast() -> Result<Vec<String>> {
    // Prefer cached local DB parsing for speed (works in normal mode too)
    if let Ok(packages) = pacman_db::list_local_cached() {
        let results: Vec<String> = packages
            .into_iter()
            .filter(|pkg| pkg.explicit)
            .map(|pkg| pkg.name)
            .collect();
        return Ok(results);
    }

    with_handle(|handle| {
        let results: Vec<String> = handle
            .localdb()
            .pkgs()
            .iter()
            .filter(|pkg| pkg.reason() == PackageReason::Explicit)
            .map(|pkg| pkg.name().to_string())
            .collect();

        Ok(results)
    })
}

/// List orphan packages - INSTANT
pub fn list_orphans_fast() -> Result<Vec<String>> {
    with_handle(|handle| {
        let results = handle
            .localdb()
            .pkgs()
            .iter()
            // Canonical orphan rule (`types::is_orphan_package`, `pacman -Qdt` semantics):
            // a dependency that is neither directly required nor optionally required
            // by any currently installed package.
            .filter(|pkg| {
                is_orphan_package(
                    pkg.reason() == PackageReason::Explicit,
                    pkg.required_by().is_empty() && pkg.optional_for().is_empty(),
                )
            })
            .map(|pkg| pkg.name().to_string())
            .collect();

        Ok(results)
    })
}

/// List installed packages with license information - for compliance scanning
pub fn list_installed_with_licenses() -> Result<Vec<(String, String, String)>> {
    with_handle(|handle| {
        let pkgs = handle.localdb().pkgs();
        let mut results = Vec::with_capacity(pkgs.len());
        results.extend(pkgs.iter().map(|pkg| {
            let licenses = pkg.licenses();
            let license_str = if licenses.is_empty() {
                "Unknown".to_string()
            } else {
                licenses
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            (
                pkg.name().to_string(),
                license_str,
                pkg.version().to_string(),
            )
        }));

        Ok(results)
    })
}

/// Check if a package has an available update
pub fn has_update(package: &str) -> Result<bool> {
    with_handle(|handle| {
        // Get local version; an uninstalled package simply has no update.
        let local_pkg = match handle.localdb().pkg(package) {
            Ok(pkg) => pkg,
            Err(alpm::Error::PkgNotFound) => return Ok(false),
            Err(e) => {
                return Err(anyhow::anyhow!(e))
                    .with_context(|| format!("Failed to query local package '{package}'"));
            }
        };
        let local_ver = local_pkg.version();

        // Check sync databases for newer version
        for db in handle.syncdbs() {
            if let Ok(sync_pkg) = db.pkg(package) {
                let sync_ver = sync_pkg.version();
                if alpm::vercmp(sync_ver.as_str(), local_ver.as_str())
                    == std::cmp::Ordering::Greater
                {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    })
}

/// Check if package is installed - FAST (cached local db, no libalpm init)
#[inline]
pub fn is_installed_fast(name: &str) -> Result<bool> {
    pacman_db::get_local_package(name).map(|package| package.is_some())
}

/// Get counts - INSTANT (<1ms, single pass over packages)
pub fn get_counts() -> Result<(usize, usize, usize)> {
    with_handle(|handle| {
        let pkgs = handle.localdb().pkgs();
        let total = pkgs.len();

        // Single-pass counting for cache efficiency; orphans follow the
        // canonical rule (`types::is_orphan_package`, `pacman -Qdt` semantics).
        let (explicit, orphans) = pkgs.iter().fold((0, 0), |(mut exp, mut orp), pkg| {
            if pkg.reason() == PackageReason::Explicit {
                exp += 1;
            } else if is_orphan_package(
                false,
                pkg.required_by().is_empty() && pkg.optional_for().is_empty(),
            ) {
                orp += 1;
            }
            (exp, orp)
        });

        Ok((total, explicit, orphans))
    })
}

/// Get explicit count only - INSTANT (<500µs, optimized for count-only queries)
/// This is faster than `list_explicit_fast` when you only need the count
#[inline]
pub fn get_explicit_count_fast() -> Result<usize> {
    with_handle(|handle| {
        Ok(handle
            .localdb()
            .pkgs()
            .iter()
            .filter(|p| p.reason() == PackageReason::Explicit)
            .count())
    })
}

/// List all known package names (local + sync) for completion - FAST
#[inline]
pub fn list_all_package_names() -> Result<Vec<String>> {
    with_handle(|handle| {
        let localdb = handle.localdb();
        let sync_count: usize = handle.syncdbs().iter().map(|db| db.pkgs().len()).sum();
        let mut names = ahash::AHashSet::with_capacity(localdb.pkgs().len() + sync_count);

        for pkg in localdb.pkgs() {
            names.insert(pkg.name().to_string());
        }

        for db in handle.syncdbs() {
            for pkg in db.pkgs() {
                names.insert(pkg.name().to_string());
            }
        }

        let mut result: Vec<String> = names.into_iter().collect();
        result.sort();
        Ok(result)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_inventory_matches_native_pacman_identities() {
        let output = crate::core::privilege::system_command("pacman")
            .unwrap()
            .env("LC_ALL", "C")
            .arg("-Qi")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let reference = String::from_utf8(output.stdout).unwrap();
        let mut expected: Vec<_> = reference
            .split("\n\n")
            .filter(|paragraph| !paragraph.trim().is_empty())
            .map(|paragraph| {
                let field = |name| {
                    paragraph
                        .lines()
                        .filter_map(|line| line.split_once(':'))
                        .find_map(|(key, value)| (key.trim() == name).then(|| value.trim()))
                        .unwrap_or_else(|| panic!("pacman record lacks {name}"))
                };
                (
                    field("Name").to_owned(),
                    field("Version").to_owned(),
                    field("Architecture").to_owned(),
                )
            })
            .collect();
        let mut actual: Vec<_> = security_inventory()
            .unwrap()
            .into_iter()
            .map(|package| (package.name, package.version, package.architecture.unwrap()))
            .collect();
        expected.sort();
        actual.sort();
        assert!(
            !expected.is_empty(),
            "native pacman fixture must contain installed packages"
        );
        assert_eq!(
            actual, expected,
            "security inventory changed native package identities"
        );
    }

    /// The libalpm-backed queries read the real system database; skip them in
    /// environments without an installed pacman local db (CI containers).
    fn real_pacman_db_available() -> bool {
        paths::pacman_local_dir_result().is_ok_and(|path| path.exists())
    }

    #[test]
    fn cached_handle_rejects_catalog_removal_and_rollback() -> Result<()> {
        let set_mtime = |path: &std::path::Path, seconds: u64| -> Result<()> {
            std::fs::File::open(path)?
                .set_times(std::fs::FileTimes::new().set_modified(
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(seconds),
                ))?;
            Ok(())
        };
        for removed in ["sync", "local"] {
            let directory = tempfile::tempdir()?;
            let sync = directory.path().join("sync");
            let local = directory.path().join("local");
            std::fs::create_dir(&sync)?;
            std::fs::create_dir(&local)?;
            std::fs::write(sync.join("core.db"), b"catalog")?;
            std::fs::write(local.join("ALPM_DB_VERSION"), b"9\n")?;
            set_mtime(&sync, 20)?;
            set_mtime(&sync.join("core.db"), 20)?;
            set_mtime(&local, 20)?;
            let observe = || -> Result<pacman_db::AlpmCatalogEpoch> {
                Ok(pacman_db::AlpmCatalogEpoch {
                    sync: pacman_db::SyncDbEpoch::from_sync_dir(&sync)?,
                    local: pacman_db::LocalDbEpoch::from_local_dir(&local)?,
                })
            };
            let loaded = observe()?;
            assert!(cached_alpm_is_reusable(1, 1, loaded, loaded));
            set_mtime(if removed == "sync" { &sync } else { &local }, 10)?;
            if removed == "sync" {
                set_mtime(&sync.join("core.db"), 10)?;
            }
            let restored = observe()?;
            assert_ne!(restored, loaded);
            assert!(
                !cached_alpm_is_reusable(1, 1, loaded, restored),
                "restoring an older {removed} timestamp must invalidate the cached handle"
            );
            if removed == "sync" {
                std::fs::remove_file(sync.join("core.db"))?;
            } else {
                std::fs::remove_dir_all(&local)?;
            }
            let current = observe()?;
            assert_ne!(current, loaded);
            assert!(
                !cached_alpm_is_reusable(1, 1, loaded, current),
                "removing {removed} must invalidate the cached handle even when its epoch decreases"
            );
        }
        Ok(())
    }

    #[test]
    fn cached_handle_is_dropped_when_sync_db_epoch_changes() {
        let dir = tempfile::tempdir().expect("temp sync dir");
        let older = pacman_db::AlpmCatalogEpoch::UNIX_EPOCH;
        std::fs::write(dir.path().join("core.db"), b"db").expect("sync db file");
        let newer = pacman_db::AlpmCatalogEpoch {
            sync: pacman_db::SyncDbEpoch::from_sync_dir(dir.path()).expect("observe temp sync dir"),
            local: pacman_db::LocalDbEpoch::UNIX_EPOCH,
        };
        assert_ne!(newer, older);
        assert!(!cached_alpm_is_reusable(1, 1, older, newer));
        assert!(cached_alpm_is_reusable(1, 1, newer, newer));
        assert!(!cached_alpm_is_reusable(1, 2, newer, newer));
        assert!(!cached_alpm_is_reusable(3, 3, newer, older));
    }

    #[test]
    fn nested_handle_access_returns_an_error_instead_of_panicking() {
        if !real_pacman_db_available() {
            return;
        }

        let result = with_handle(|_| with_handle(|_| Ok(())));

        let error = result.expect_err("nested ALPM access must fail");
        assert!(error.to_string().contains("Nested ALPM handle access"));
    }

    #[test]
    fn search_sync_returns_results() {
        if !real_pacman_db_available() {
            return;
        }
        let result = search_sync("linux");
        assert!(result.is_ok());
    }

    #[test]
    fn get_package_info_finds_installed_pacman() {
        if !real_pacman_db_available() {
            return;
        }
        let info = get_package_info("pacman").expect("query should succeed");
        let pkg = info.expect("pacman should be installed");
        assert_eq!(pkg.name, "pacman");
    }

    #[test]
    fn get_package_info_returns_none_for_nonexistent() {
        let result = get_package_info("this-package-definitely-does-not-exist-12345");
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn list_installed_fast_includes_pacman() {
        if !real_pacman_db_available() {
            return;
        }
        let packages = list_installed_fast().expect("list should succeed");
        assert!(!packages.is_empty(), "should have installed packages");
        assert!(
            packages.iter().any(|p| p.name == "pacman"),
            "pacman should be installed"
        );
    }

    #[test]
    fn list_explicit_fast_is_nonempty_on_real_systems() {
        if !real_pacman_db_available() {
            return;
        }
        let packages = list_explicit_fast().expect("list should succeed");
        assert!(!packages.is_empty(), "should have explicit packages");
    }

    #[test]
    fn list_orphans_fast_succeeds() {
        let result = list_orphans_fast();
        assert!(result.is_ok());
    }

    #[test]
    fn is_installed_fast_detects_pacman() {
        if !real_pacman_db_available() {
            return;
        }
        assert!(
            is_installed_fast("pacman").expect("query should succeed"),
            "pacman should be installed"
        );
    }

    #[test]
    fn is_installed_fast_rejects_nonexistent() {
        let result = is_installed_fast("this-package-definitely-does-not-exist-12345");
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn counts_are_consistent() {
        if !real_pacman_db_available() {
            return;
        }
        let (total, explicit, _orphans) = get_counts().expect("counts should succeed");
        assert!(total > 0, "should have installed packages");
        assert!(explicit > 0, "should have explicit packages");
        assert!(explicit <= total, "explicit should be <= total");
    }

    #[test]
    fn all_package_names_are_sorted_and_include_pacman() {
        if !real_pacman_db_available() {
            return;
        }
        let names = list_all_package_names().expect("names should succeed");
        assert!(!names.is_empty());
        assert!(names.contains(&"pacman".to_string()));
        let is_sorted = names.windows(2).all(|w| w[0] <= w[1]);
        assert!(is_sorted, "package names should be sorted");
    }

    #[test]
    fn local_packages_have_valid_fields() {
        if !real_pacman_db_available() {
            return;
        }
        let packages = list_installed_fast().expect("list should succeed");

        for pkg in packages.iter().take(5) {
            assert!(!pkg.name.is_empty(), "package name should not be empty");
            assert!(
                pkg.reason == "explicit" || pkg.reason == "dependency",
                "reason should be explicit or dependency"
            );
        }
    }

    #[test]
    fn sync_results_carry_repo_names() {
        if !real_pacman_db_available() {
            return;
        }
        let packages = search_sync("linux").expect("search should succeed");
        for pkg in packages.iter().take(5) {
            assert!(!pkg.repo.is_empty(), "repo should not be empty");
        }
    }
}
