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
    let mut alpm = open_default_alpm().context("Failed to initialize ALPM handle")?;
    let config = crate::core::pacman_conf::PacmanConfig::parse(paths::pacman_conf_path())
        .context("Failed to load repositories from pacman.conf")?;
    crate::package_managers::alpm_ops::configure_signature_policy(&mut alpm, &config)?;
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
            if !db.usage()?.contains(alpm::Usage::SEARCH) {
                continue;
            }
            super::alpm_ops::validate_sync_database(handle, db)?;
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
            if !db.usage()?.contains(alpm::Usage::SEARCH) {
                continue;
            }
            super::alpm_ops::validate_sync_database(handle, db)?;
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
                    origin: crate::package_managers::types::SecurityOrigin::Unknown,
                    name,
                    version,
                    advisory_source: None,
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
    Ok(pacman_db::check_updates_cached()?
        .iter()
        .any(|update| update.name == package))
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
        let mut names = ahash::AHashSet::with_capacity(localdb.pkgs().len());

        for pkg in localdb.pkgs() {
            names.insert(pkg.name().to_string());
        }

        for db in handle.syncdbs() {
            if !db.usage()?.contains(alpm::Usage::SEARCH) {
                continue;
            }
            super::alpm_ops::validate_sync_database(handle, db)?;
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
    #[serial_test::serial]
    fn security_update_eligibility_respects_repository_priority_and_ignore_filters() {
        const NAME: &str = "package_managers::alpm_direct::tests::security_update_eligibility_respects_repository_priority_and_ignore_filters";
        if crate::config::Settings::rerun_test_unprivileged(NAME) {
            return;
        }
        if crate::core::testing::run_isolated_test(NAME) {
            return;
        }
        assert!(!crate::core::is_root(), "fixture must run as ordinary user");
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                crate::core::paths::reset_test_overrides();
                clear_alpm_cache();
            }
        }
        let _restore = Restore;
        for (first_version, filter, expected) in [
            ("1.0-1", "", false),
            ("2.0-1", "IgnorePkg = fixture-*\n", false),
            ("2.0-1", "IgnoreGroup = fixture-group\n", false),
            ("2.0-1", "", true),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().join("root");
            let database = root.join("var/lib/pacman");
            let local = database.join("local");
            std::fs::create_dir_all(local.join("fixture-package-1.0-1")).unwrap();
            std::fs::write(local.join("ALPM_DB_VERSION"), "9\n").unwrap();
            std::fs::write(
                local.join("fixture-package-1.0-1/desc"),
                "%NAME%\nfixture-package\n\n%VERSION%\n1.0-1\n\n%REASON%\n0\n",
            )
            .unwrap();
            let sync = database.join("sync");
            std::fs::create_dir_all(&sync).unwrap();
            for (repository, version) in [("first", first_version), ("second", "3.0-1")] {
                let content = format!(
                    "%NAME%\nfixture-package\n\n%VERSION%\n{version}\n\n%GROUPS%\nfixture-group\n\n%ARCH%\nx86_64\n"
                );
                let encoder = flate2::write::GzEncoder::new(
                    std::fs::File::create(sync.join(format!("{repository}.db"))).unwrap(),
                    flate2::Compression::fast(),
                );
                let mut archive = tar::Builder::new(encoder);
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                archive
                    .append_data(
                        &mut header,
                        format!("fixture-package-{version}/desc"),
                        content.as_bytes(),
                    )
                    .unwrap();
                archive.into_inner().unwrap().finish().unwrap();
            }
            let config = directory.path().join("pacman.conf");
            std::fs::write(&config, format!("[options]\nSigLevel = Never\n{filter}[first]\nServer = https://first.example/$repo/$arch\n[second]\nServer = https://second.example/$repo/$arch\n")).unwrap();
            clear_alpm_cache();
            paths::set_test_overrides(Some(root), Some(database));
            temp_env::with_vars(
                [
                    ("OMG_PACMAN_CONF", Some(config.to_str().unwrap())),
                    ("OMG_PACMAN_LOCAL_DIR", None),
                    ("OMG_PACMAN_SYNC_DIR", None),
                    ("OMG_CONFIG_DIR", Some(directory.path().to_str().unwrap())),
                    ("OMG_CACHE_DIR", Some(directory.path().to_str().unwrap())),
                ],
                || {
                    assert_eq!(
                        has_update("fixture-package").unwrap(),
                        expected,
                        "first={first_version}, filter={filter:?}"
                    );
                },
            );
        }
    }

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

    fn write_sync_fixture(
        database: &std::path::Path,
        repository: &str,
        packages: &[(&str, &str)],
    ) -> Result<()> {
        let encoder = flate2::write::GzEncoder::new(
            std::fs::File::create(database.join("sync").join(format!("{repository}.db")))?,
            flate2::Compression::fast(),
        );
        let mut archive = tar::Builder::new(encoder);
        for (name, version) in packages {
            let content = format!(
                "%NAME%\n{name}\n\n%VERSION%\n{version}\n\n%DESC%\nfixture {name}\n\n%ARCH%\nx86_64\n"
            );
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(
                    &mut header,
                    format!("{name}-{version}/desc"),
                    content.as_bytes(),
                )
                .expect("private sync fixture record is writable");
        }
        archive.into_inner()?.finish()?;
        Ok(())
    }

    fn with_private_alpm(name: &str, run: impl FnOnce()) {
        if crate::config::Settings::rerun_test_unprivileged(name) {
            return;
        }
        if crate::core::testing::run_isolated_test(name) {
            return;
        }
        assert!(!crate::core::is_root(), "fixture must run as ordinary user");

        let directory = tempfile::tempdir().expect("private ALPM fixture");
        let root = directory.path().join("root");
        let database = root.join("var/lib/pacman");
        let local = database.join("local");
        let sync = database.join("sync");
        std::fs::create_dir_all(local.join("pacman-1.0-1")).unwrap();
        std::fs::create_dir_all(&sync).unwrap();
        std::fs::write(local.join("ALPM_DB_VERSION"), "9\n").unwrap();
        std::fs::write(
            local.join("pacman-1.0-1/desc"),
            "%NAME%\npacman\n\n%VERSION%\n1.0-1\n\n%DESC%\nfixture package manager\n\n%ARCH%\nx86_64\n\n%REASON%\n0\n",
        )
        .unwrap();
        write_sync_fixture(&database, "core", &[("linux", "6.1.0-1")]).unwrap();
        let config = directory.path().join("pacman.conf");
        std::fs::write(&config, "[options]\nSigLevel = Never\n[core]\nServer = https://example.invalid/$repo/os/$arch\n").unwrap();
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                ALPM_HANDLE.with(|cell| *cell.borrow_mut() = None);
                paths::reset_test_overrides();
                clear_alpm_cache();
            }
        }
        let _restore = Restore;
        paths::set_test_overrides(Some(root), Some(database));
        temp_env::with_vars(
            [
                ("OMG_PACMAN_CONF", Some(config.as_os_str())),
                ("OMG_PACMAN_LOCAL_DIR", None),
                ("OMG_PACMAN_SYNC_DIR", None),
                ("OMG_CONFIG_DIR", Some(directory.path().as_os_str())),
                ("OMG_CACHE_DIR", Some(directory.path().as_os_str())),
            ],
            run,
        );
    }

    #[test]
    fn search_usage_excludes_repository_from_info_search_and_completion() {
        with_private_alpm(
            concat!(
                "package_managers::alpm_direct::tests::",
                stringify!(search_usage_excludes_repository_from_info_search_and_completion)
            ),
            || {
                let database = paths::pacman_db_dir_result().expect("private database");
                write_sync_fixture(
                    &database,
                    "upgrade-only",
                    &[("linux", "99.0-1"), ("hidden-only", "1.0-1")],
                )
                .unwrap();
                std::fs::write(
                    paths::pacman_conf_path(),
                    "[options]\nSigLevel = Never\n[upgrade-only]\nUsage = Upgrade\nServer = https://example.invalid/$repo/$arch\n[core]\nUsage = Search\nServer = https://example.invalid/$repo/$arch\n",
                )
                .unwrap();
                clear_alpm_cache();

                let info = get_package_info("linux")
                    .unwrap()
                    .expect("searchable kernel");
                assert_eq!(info.repo, "core");
                assert_eq!(info.version.to_string(), "6.1.0-1");
                assert!(!info.installed);
                assert!(get_package_info("hidden-only").unwrap().is_none());
                let search = search_sync("linux").unwrap();
                assert_eq!(search.len(), 1);
                assert_eq!(search[0].repo, "core");
                assert_eq!(search[0].version.to_string(), "6.1.0-1");
                assert!(search_sync("hidden-only").unwrap().is_empty());
                assert_eq!(list_all_package_names().unwrap(), ["linux", "pacman"]);
            },
        );
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
        with_private_alpm(
            concat!(
                "package_managers::alpm_direct::tests::",
                stringify!(nested_handle_access_returns_an_error_instead_of_panicking)
            ),
            || {
                let result = with_handle(|_| with_handle(|_| Ok(())));

                let error = result.expect_err("nested ALPM access must fail");
                assert!(error.to_string().contains("Nested ALPM handle access"));
            },
        );
    }

    #[test]
    fn search_sync_returns_results() {
        with_private_alpm(
            concat!(
                "package_managers::alpm_direct::tests::",
                stringify!(search_sync_returns_results)
            ),
            || {
                let result = search_sync("linux");
                assert!(result.is_ok());
                let packages = result.unwrap();
                assert_eq!(packages.len(), 1);
                assert_eq!(packages[0].name, "linux");
                assert_eq!(packages[0].repo, "core");
            },
        );
    }

    #[test]
    fn get_package_info_finds_installed_pacman() {
        with_private_alpm(
            concat!(
                "package_managers::alpm_direct::tests::",
                stringify!(get_package_info_finds_installed_pacman)
            ),
            || {
                let info = get_package_info("pacman").expect("query should succeed");
                let pkg = info.expect("pacman should be installed");
                assert_eq!(pkg.name, "pacman");
                assert_eq!(pkg.repo, "local");
                assert!(pkg.installed);
            },
        );
    }

    #[test]
    fn get_package_info_returns_none_for_nonexistent() {
        let result = get_package_info("this-package-definitely-does-not-exist-12345");
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn list_installed_fast_includes_pacman() {
        with_private_alpm(
            concat!(
                "package_managers::alpm_direct::tests::",
                stringify!(list_installed_fast_includes_pacman)
            ),
            || {
                let packages = list_installed_fast().expect("list should succeed");
                assert!(!packages.is_empty(), "should have installed packages");
                assert_eq!(packages.len(), 1);
                assert_eq!(packages[0].name, "pacman");
                assert!(
                    packages.iter().any(|p| p.name == "pacman"),
                    "pacman should be installed"
                );
            },
        );
    }

    #[test]
    fn list_explicit_fast_is_nonempty_on_real_systems() {
        with_private_alpm(
            concat!(
                "package_managers::alpm_direct::tests::",
                stringify!(list_explicit_fast_is_nonempty_on_real_systems)
            ),
            || {
                let packages = list_explicit_fast().expect("list should succeed");
                assert!(!packages.is_empty(), "should have explicit packages");
                assert_eq!(packages, ["pacman"]);
            },
        );
    }

    #[test]
    fn list_orphans_fast_succeeds() {
        let result = list_orphans_fast();
        assert!(result.is_ok());
    }

    #[test]
    fn is_installed_fast_detects_pacman() {
        with_private_alpm(
            concat!(
                "package_managers::alpm_direct::tests::",
                stringify!(is_installed_fast_detects_pacman)
            ),
            || {
                assert!(
                    is_installed_fast("pacman").expect("query should succeed"),
                    "pacman should be installed"
                );
                assert!(
                    !is_installed_fast("this-package-definitely-does-not-exist-12345")
                        .expect("query should succeed")
                );
            },
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
        with_private_alpm(
            concat!(
                "package_managers::alpm_direct::tests::",
                stringify!(counts_are_consistent)
            ),
            || {
                let (total, explicit, orphans) = get_counts().expect("counts should succeed");
                assert!(total > 0, "should have installed packages");
                assert!(explicit > 0, "should have explicit packages");
                assert!(explicit <= total, "explicit should be <= total");
                assert_eq!((total, explicit, orphans), (1, 1, 0));
            },
        );
    }

    #[test]
    fn all_package_names_are_sorted_and_include_pacman() {
        with_private_alpm(
            concat!(
                "package_managers::alpm_direct::tests::",
                stringify!(all_package_names_are_sorted_and_include_pacman)
            ),
            || {
                let names = list_all_package_names().expect("names should succeed");
                assert!(!names.is_empty());
                assert!(names.contains(&"pacman".to_string()));
                let is_sorted = names.windows(2).all(|w| w[0] <= w[1]);
                assert!(is_sorted, "package names should be sorted");
                assert_eq!(names, ["linux", "pacman"]);
            },
        );
    }

    #[test]
    fn local_packages_have_valid_fields() {
        with_private_alpm(
            concat!(
                "package_managers::alpm_direct::tests::",
                stringify!(local_packages_have_valid_fields)
            ),
            || {
                let packages = list_installed_fast().expect("list should succeed");
                assert_eq!(packages.len(), 1);
                assert_eq!(packages[0].name, "pacman");
                assert_eq!(packages[0].reason, "explicit");

                for pkg in packages.iter().take(5) {
                    assert!(!pkg.name.is_empty(), "package name should not be empty");
                    assert!(
                        pkg.reason == "explicit" || pkg.reason == "dependency",
                        "reason should be explicit or dependency"
                    );
                }
            },
        );
    }

    fn native_pacman_query(args: &[&str]) -> Result<String> {
        let output = crate::core::privilege::system_command("pacman")?
            .env("LC_ALL", "C")
            .args(args)
            .output()?;
        anyhow::ensure!(
            output.status.success(),
            "pacman {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        anyhow::ensure!(
            output.stdout.len() <= 16 * 1024 * 1024,
            "pacman output exceeds bound"
        );
        Ok(String::from_utf8(output.stdout)?)
    }

    fn parse_pacman_sync_rows(output: &str) -> Result<Vec<(String, String, String)>> {
        let mut rows = Vec::new();
        for line in output.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            anyhow::ensure!(
                fields.len() == 3
                    || (fields.len() == 4 && fields[3] == "[installed]")
                    || (fields.len() == 5
                        && fields[3] == "[installed:"
                        && fields[4]
                            .strip_suffix(']')
                            .is_some_and(|version| !version.is_empty())),
                "malformed pacman sync row: {line}"
            );
            rows.push((
                fields[0].to_owned(),
                fields[1].to_owned(),
                fields[2].to_owned(),
            ));
        }
        rows.sort();
        Ok(rows)
    }

    #[test]
    fn pacman_sync_rows_preserve_available_identity_in_native_output_shapes() -> Result<()> {
        for line in [
            "core pacman 7.0-1",
            "core pacman 7.0-1 [installed]",
            "core pacman 7.0-1 [installed: 6.1-1]",
        ] {
            assert_eq!(
                parse_pacman_sync_rows(line)?,
                vec![("core".to_owned(), "pacman".to_owned(), "7.0-1".to_owned())]
            );
        }
        Ok(())
    }

    #[test]
    fn pacman_sync_rows_reject_incomplete_and_malformed_rows() {
        for line in [
            " ",
            "core pacman",
            "core pacman 7.0-1 [unknown]",
            "core pacman 7.0-1 [installed: ]",
            "core pacman 7.0-1 [installed: 6.1-1",
            "core pacman 7.0-1 [unknown: 6.1-1]",
            "core pacman 7.0-1 [installed: 6.1-1] extra",
        ] {
            let error = parse_pacman_sync_rows(line).expect_err("malformed native row");
            assert_eq!(
                error.to_string(),
                format!("malformed pacman sync row: {line}")
            );
        }
    }

    #[test]
    fn pacman_sync_rows_sort_without_dropping_repository_duplicates() -> Result<()> {
        assert_eq!(
            parse_pacman_sync_rows("extra pacman 7.0-1\ncore pacman 7.0-1\ncore pacman 7.0-1\n")?,
            vec![
                ("core".to_owned(), "pacman".to_owned(), "7.0-1".to_owned()),
                ("core".to_owned(), "pacman".to_owned(), "7.0-1".to_owned()),
                ("extra".to_owned(), "pacman".to_owned(), "7.0-1".to_owned()),
            ]
        );
        Ok(())
    }

    #[test]
    fn native_pacman_query_rejects_real_option_errors_with_stderr() {
        let error = native_pacman_query(&["--omg-invalid-read-only-fixture-option"])
            .expect_err("pacman must reject an unknown option");
        let message = error.to_string();
        assert!(message.contains("pacman ["), "{message}");
        assert!(message.contains("unrecognized option"), "{message}");
        assert!(
            message.contains("--omg-invalid-read-only-fixture-option"),
            "{message}"
        );
    }

    #[test]
    #[ignore = "requires an explicitly selected native Arch host with local and sync databases"]
    fn native_inventory_and_search_match_pacman() -> Result<()> {
        use crate::package_managers::types::VersionDisplay as _;

        anyhow::ensure!(
            !crate::core::paths::test_mode()
                && !std::env::vars_os()
                    .any(|(key, _)| key.to_string_lossy().starts_with("OMG_PACMAN_")),
            "native comparison requires test mode and pacman overrides to be unset"
        );
        anyhow::ensure!(
            paths::pacman_local_dir_result()?
                .join("ALPM_DB_VERSION")
                .is_file()
                && paths::pacman_sync_dir_result()?.is_dir(),
            "native comparison requires existing local and sync databases"
        );
        let local_rows = |args: &[&str]| -> Result<Vec<(String, String)>> {
            let output = native_pacman_query(args)?;
            let mut rows = Vec::new();
            for line in output.lines() {
                let fields: Vec<_> = line.split_whitespace().collect();
                anyhow::ensure!(fields.len() == 2, "malformed pacman local row: {line}");
                rows.push((fields[0].to_owned(), fields[1].to_owned()));
            }
            rows.sort();
            Ok(rows)
        };
        let sync_rows = || -> Result<Vec<(String, String, String)>> {
            parse_pacman_sync_rows(&native_pacman_query(&["-Sl", "--color", "never"])?)
        };
        let installed = local_rows(&["-Q"])?;
        let explicit = local_rows(&["-Qe"])?;
        let sync = sync_rows()?;
        anyhow::ensure!(
            installed.iter().any(|(name, _)| name == "pacman")
                && !explicit.is_empty()
                && !sync.is_empty(),
            "native pacman inventory is incomplete"
        );
        let expected_search: Vec<_> = sync
            .iter()
            .filter(|(_, name, _)| name.contains("linux"))
            .cloned()
            .collect();
        anyhow::ensure!(
            !expected_search.is_empty(),
            "native sync database has no linux-named package"
        );

        let mut actual_installed: Vec<_> = list_installed_fast()?
            .into_iter()
            .map(|package| (package.name, package.version.version_string()))
            .collect();
        actual_installed.sort();
        let mut actual_explicit = list_explicit_fast()?;
        actual_explicit.sort();
        let mut actual_search: Vec<_> = search_sync("linux")?
            .into_iter()
            .filter(|package| package.name.contains("linux"))
            .map(|package| (package.repo, package.name, package.version.version_string()))
            .collect();
        actual_search.sort();
        let expected_explicit: Vec<_> = explicit.iter().map(|(name, _)| name.clone()).collect();
        let mut expected_names: Vec<_> = installed
            .iter()
            .map(|(name, _)| name.clone())
            .chain(sync.iter().map(|(_, name, _)| name.clone()))
            .collect();
        expected_names.sort();
        expected_names.dedup();
        let (total, explicit_count, _) = get_counts()?;
        let info = get_package_info("pacman")?.context("native pacman package missing")?;
        let pacman_version = installed
            .iter()
            .find(|(name, _)| name == "pacman")
            .context("native pacman package missing")?;
        assert_eq!(actual_installed, installed);
        assert_eq!(actual_explicit, expected_explicit);
        assert_eq!(actual_search, expected_search);
        assert_eq!(list_all_package_names()?, expected_names);
        assert_eq!(total, installed.len());
        assert_eq!(explicit_count, explicit.len());
        assert_eq!(info.name, "pacman");
        assert_eq!(info.version.version_string(), pacman_version.1);
        assert_eq!(info.repo, "local");
        assert!(info.installed);
        assert!(is_installed_fast("pacman")?);
        assert_eq!(
            local_rows(&["-Q"])?,
            installed,
            "native inventory changed during comparison"
        );
        assert_eq!(
            local_rows(&["-Qe"])?,
            explicit,
            "explicit inventory changed during comparison"
        );
        assert_eq!(
            sync_rows()?,
            sync,
            "sync inventory changed during comparison"
        );
        Ok(())
    }

    #[test]
    fn sync_results_carry_repo_names() {
        with_private_alpm(
            concat!(
                "package_managers::alpm_direct::tests::",
                stringify!(sync_results_carry_repo_names)
            ),
            || {
                let packages = search_sync("linux").expect("search should succeed");
                assert_eq!(packages.len(), 1);
                assert_eq!(packages[0].name, "linux");
                assert_eq!(packages[0].repo, "core");
                for pkg in packages.iter().take(5) {
                    assert!(!pkg.repo.is_empty(), "repo should not be empty");
                }
            },
        );
    }
}
