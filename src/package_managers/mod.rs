//! Package manager backends for system packages
//!
//! ## Feature Flags for Debian Support
//!
//! - `debian`: Adds rust-apt FFI for all operations (requires libapt-pkg-dev)

use std::sync::Arc;

#[cfg(feature = "arch")]
pub mod alpm_direct;
#[cfg(feature = "arch")]
pub mod alpm_ops;
#[cfg(feature = "arch")]
pub mod alpm_worker;
// apt module is available with debian feature
#[cfg(feature = "debian")]
pub mod apt;
#[cfg(feature = "arch")]
pub mod arch;
#[cfg(feature = "arch")]
pub(crate) mod arch_advisory;
#[cfg(feature = "arch")]
pub mod aur;
#[cfg(feature = "arch")]
pub mod aur_deps;
#[cfg(feature = "arch")]
mod aur_index;
#[cfg(feature = "arch")]
pub mod aur_metadata;
#[cfg(feature = "arch")]
pub mod aur_sources;
#[cfg(any(feature = "debian", feature = "debian-pure"))]
pub mod debian_db;
#[cfg(feature = "debian-pure")]
pub mod debian_pure;
#[cfg(feature = "fedora")]
pub mod dnf;
#[cfg(feature = "fedora")]
mod dnf_advisory;
// macOS Homebrew support - can be enabled via feature or auto-detected on macOS
#[cfg(any(feature = "macos", target_os = "macos"))]
pub mod homebrew;
/// Mock backend used only when the explicit `OMG_TEST_MODE` runtime switch is set.
pub mod mock;
#[cfg(feature = "arch")]
pub mod pacman_db;
#[cfg(feature = "arch")]
pub mod parallel_sync;
#[cfg(feature = "arch")]
pub mod pkgbuild;
mod traits;
pub mod types;

pub(crate) use types::VersionDisplay;
pub use types::{parse_version, parse_version_or_zero, zero_version};

#[cfg(feature = "arch")]
pub fn search_sync(query: &str) -> anyhow::Result<Vec<SyncPackage>> {
    #[cfg(any(feature = "debian", feature = "debian-pure"))]
    if crate::core::env::distro::is_debian_like() {
        return Ok(debian_db::search_fast(query)?
            .into_iter()
            .map(|pkg| SyncPackage {
                name: pkg.name,
                version: pkg.version,
                description: pkg.description,
                repo: "official".to_string(),
                download_size: 0,
                installed: pkg.installed,
            })
            .collect());
    }

    if crate::core::paths::test_mode() {
        let pm = get_package_manager()?;
        let results = futures::executor::block_on(pm.search(query))?;
        return Ok(results
            .into_iter()
            .map(|p| SyncPackage {
                name: p.name,
                version: p.version,
                description: p.description,
                repo: "official".to_string(),
                download_size: 0,
                installed: p.installed,
            })
            .collect());
    }
    alpm_direct::search_sync(query)
}

pub fn list_explicit_fast() -> anyhow::Result<Vec<String>> {
    if crate::core::paths::test_mode() {
        let pm = get_package_manager()?;
        return futures::executor::block_on(pm.list_explicit());
    }

    #[cfg(any(feature = "debian", feature = "debian-pure"))]
    if crate::core::env::distro::is_debian_like() {
        return debian_db::list_explicit_fast();
    }

    #[cfg(feature = "arch")]
    {
        alpm_direct::list_explicit_fast()
    }

    #[cfg(all(
        not(feature = "arch"),
        any(feature = "debian", feature = "debian-pure")
    ))]
    return debian_db::list_explicit_fast();

    #[cfg(not(any(feature = "arch", feature = "debian", feature = "debian-pure")))]
    anyhow::bail!("No package manager backend enabled")
}

#[cfg(any(feature = "debian", feature = "debian-pure"))]
fn local_packages_from_debian_db() -> anyhow::Result<Vec<LocalPackage>> {
    Ok(debian_db::list_installed_fast()?
        .into_iter()
        .map(|pkg| LocalPackage {
            name: pkg.name,
            version: parse_version_or_zero(&pkg.version),
            description: pkg.description,
            install_size: 0,
            reason: if pkg.is_explicit {
                "explicit"
            } else {
                "dependency"
            },
            licenses: Vec::new(),
        })
        .collect())
}

pub fn list_installed_fast() -> anyhow::Result<Vec<LocalPackage>> {
    if crate::core::paths::test_mode() {
        let manager = get_package_manager()?;
        return futures::executor::block_on(manager.list_installed()).map(|packages| {
            packages
                .into_iter()
                .map(|package| LocalPackage {
                    name: package.name,
                    version: package.version,
                    description: package.description,
                    install_size: 0,
                    reason: "explicit",
                    licenses: Vec::new(),
                })
                .collect()
        });
    }

    #[cfg(any(feature = "debian", feature = "debian-pure"))]
    if crate::core::env::distro::is_debian_like() {
        return local_packages_from_debian_db();
    }

    #[cfg(feature = "arch")]
    return alpm_direct::list_installed_fast();

    #[cfg(all(
        not(feature = "arch"),
        any(feature = "debian", feature = "debian-pure")
    ))]
    return local_packages_from_debian_db();

    #[cfg(not(any(feature = "arch", feature = "debian", feature = "debian-pure")))]
    anyhow::bail!("No package manager backend enabled")
}

pub fn is_installed_fast(name: &str) -> anyhow::Result<bool> {
    if crate::core::paths::test_mode() {
        let manager = get_package_manager()?;
        return futures::executor::block_on(manager.is_installed(name));
    }

    #[cfg(any(feature = "debian", feature = "debian-pure"))]
    if crate::core::env::distro::is_debian_like() {
        return debian_db::is_installed_fast(name);
    }

    #[cfg(feature = "fedora")]
    if matches!(
        crate::core::env::distro::detect_distro(),
        crate::core::env::distro::Distro::Fedora
    ) {
        return dnf::DnfPackageManager::new().is_installed_fast(name);
    }

    #[cfg(feature = "arch")]
    return alpm_direct::is_installed_fast(name);

    #[cfg(all(
        not(feature = "arch"),
        any(feature = "debian", feature = "debian-pure")
    ))]
    return debian_db::is_installed_fast(name);

    #[cfg(not(any(feature = "arch", feature = "debian", feature = "debian-pure")))]
    anyhow::bail!("No package manager backend enabled to query {name}")
}

#[cfg(any(feature = "debian", feature = "debian-pure"))]
fn package_info_from_debian_db(name: &str) -> anyhow::Result<Option<types::PackageInfo>> {
    Ok(
        debian_db::get_info_fast(name)?.map(|pkg| types::PackageInfo {
            name: pkg.name,
            version: pkg.version,
            description: pkg.description,
            url: None,
            size: 0,
            install_size: None,
            download_size: None,
            repo: if pkg.installed {
                "local".to_string()
            } else {
                "official".to_string()
            },
            depends: Vec::new(),
            licenses: Vec::new(),
            installed: pkg.installed,
        }),
    )
}

pub fn get_package_info(name: &str) -> anyhow::Result<Option<types::PackageInfo>> {
    if crate::core::paths::test_mode() {
        let manager = get_package_manager()?;
        let package = futures::executor::block_on(manager.info(name))?;
        return Ok(package.map(|package| types::PackageInfo {
            name: package.name,
            version: package.version,
            description: package.description,
            url: None,
            size: 0,
            install_size: None,
            download_size: None,
            repo: match package.source {
                crate::core::PackageSource::Official => "official",
                crate::core::PackageSource::Aur => "aur",
            }
            .to_string(),
            depends: Vec::new(),
            licenses: Vec::new(),
            installed: package.installed,
        }));
    }

    #[cfg(any(feature = "debian", feature = "debian-pure"))]
    if crate::core::env::distro::is_debian_like() {
        return package_info_from_debian_db(name);
    }

    #[cfg(feature = "arch")]
    return alpm_direct::get_package_info(name);

    #[cfg(all(
        not(feature = "arch"),
        any(feature = "debian", feature = "debian-pure")
    ))]
    return package_info_from_debian_db(name);

    #[cfg(not(any(feature = "arch", feature = "debian", feature = "debian-pure")))]
    anyhow::bail!("No package manager backend enabled to query {name}")
}

pub fn list_orphans_fast() -> anyhow::Result<Vec<String>> {
    if crate::core::paths::test_mode() {
        return Ok(Vec::new());
    }

    #[cfg(any(feature = "debian", feature = "debian-pure"))]
    if crate::core::env::distro::is_debian_like() {
        return debian_db::list_orphans_fast();
    }

    #[cfg(feature = "arch")]
    return alpm_direct::list_orphans_fast();

    #[cfg(all(
        not(feature = "arch"),
        any(feature = "debian", feature = "debian-pure")
    ))]
    return debian_db::list_orphans_fast();

    #[cfg(not(any(feature = "arch", feature = "debian", feature = "debian-pure")))]
    anyhow::bail!("No package manager backend enabled")
}

#[cfg(any(feature = "debian", feature = "debian-pure"))]
fn counts_from_debian_db() -> anyhow::Result<(usize, usize, usize)> {
    let installed = debian_db::list_installed_fast()?;
    let total = installed.len();
    let explicit = installed
        .iter()
        .filter(|package| package.is_explicit)
        .count();
    let orphans = debian_db::list_orphans_fast()?.len();
    Ok((total, explicit, orphans))
}

pub fn get_counts() -> anyhow::Result<(usize, usize, usize)> {
    if crate::core::paths::test_mode() {
        let manager = get_package_manager()?;
        let (total, explicit, orphans, _) = futures::executor::block_on(manager.get_status(false))?;
        return Ok((total, explicit, orphans));
    }

    #[cfg(any(feature = "debian", feature = "debian-pure"))]
    if crate::core::env::distro::is_debian_like() {
        return counts_from_debian_db();
    }

    #[cfg(feature = "arch")]
    return alpm_direct::get_counts();

    #[cfg(all(
        not(feature = "arch"),
        any(feature = "debian", feature = "debian-pure")
    ))]
    return counts_from_debian_db();

    #[cfg(not(any(feature = "arch", feature = "debian", feature = "debian-pure")))]
    anyhow::bail!("No package manager backend enabled")
}

pub fn get_system_status() -> anyhow::Result<(usize, usize, usize, usize)> {
    if crate::core::paths::test_mode() {
        let manager = get_package_manager()?;
        return futures::executor::block_on(manager.get_status(false));
    }

    #[cfg(feature = "debian")]
    if crate::core::env::distro::is_debian_like() {
        return apt::get_system_status();
    }

    #[cfg(all(not(feature = "debian"), feature = "debian-pure"))]
    if crate::core::env::distro::is_debian_like() {
        return debian_pure::accurate_status_counts();
    }

    #[cfg(feature = "arch")]
    return alpm_ops::get_system_status();

    #[cfg(all(not(feature = "arch"), feature = "debian"))]
    return apt::get_system_status();

    #[cfg(all(
        not(feature = "arch"),
        not(feature = "debian"),
        feature = "debian-pure"
    ))]
    return debian_pure::accurate_status_counts();

    #[cfg(not(any(feature = "arch", feature = "debian", feature = "debian-pure")))]
    anyhow::bail!("No package manager backend enabled")
}

#[cfg(feature = "arch")]
pub use alpm_direct::clear_alpm_cache;
#[cfg(feature = "arch")]
pub use alpm_ops::{
    TransactionKind, clean_cache, clean_cache_preview, display_pkg_info, execute_transaction,
    get_sync_pkg_info, get_update_list, list_orphans_direct,
};
#[cfg(feature = "arch")]
pub use arch::{ArchPackageManager, is_installed, list_explicit, list_orphans, remove_orphans};
#[cfg(feature = "arch")]
pub use aur::{AurClient, AurPackageDetail, search_detailed};
#[cfg(feature = "arch")]
pub use pacman_db::{
    check_updates_cached, get_local_package, get_potential_aur_packages, invalidate_caches,
};
#[cfg(feature = "arch")]
pub use parallel_sync::sync_databases_parallel;
pub use traits::PackageManager;
pub use types::{LocalPackage, SyncPackage};

/// Get the appropriate package manager for the current distribution
pub fn get_package_manager() -> anyhow::Result<Arc<dyn PackageManager>> {
    #[allow(
        unused_imports,
        reason = "the selected package-backend features use different subsets"
    )]
    use crate::core::env::distro::{Distro, detect_distro};

    // Test mode is an explicit runtime adapter and must behave consistently in
    // debug and release builds; otherwise fast-path helpers can recurse into
    // the real backend when release binaries are exercised in isolation.
    if crate::core::paths::test_mode() {
        let distro = std::env::var("OMG_TEST_DISTRO").unwrap_or_else(|_| "arch".to_string());
        return Ok(Arc::new(mock::MockPackageManager::new(&distro)));
    }

    match detect_distro() {
        #[cfg(feature = "arch")]
        Distro::Arch => Ok(Arc::new(ArchPackageManager::new())),
        // debian provides AptPackageManager
        #[cfg(feature = "debian")]
        Distro::Debian | Distro::Ubuntu => Ok(Arc::new(AptPackageManager::new())),
        // debian-pure is a TEST/INDEXING ENGINE, not a live-system backend:
        // it cannot elevate, overwrites conffiles without dpkg semantics,
        // and its rollback cannot restore overwritten files. Builds without
        // the apt backend must fail explicitly rather than let it mutate a
        // real machine.
        #[cfg(all(not(feature = "debian"), feature = "debian-pure"))]
        Distro::Debian | Distro::Ubuntu => Err(anyhow::anyhow!(
            "This build uses the pure-Rust Debian indexing engine, which must not \
             modify a live system (no privilege boundary or dpkg conffile semantics). \
             Install an apt-backed build of omg for Debian/Ubuntu."
        )),
        // Fedora/RHEL provides DnfPackageManager (pure Rust)
        #[cfg(feature = "fedora")]
        Distro::Fedora => Ok(Arc::new(dnf::DnfPackageManager::new())),
        // macOS provides HomebrewPackageManager
        #[cfg(any(feature = "macos", target_os = "macos"))]
        Distro::MacOS => Ok(Arc::new(homebrew::HomebrewPackageManager::new())),
        _ => {
            // Fallback or default
            #[cfg(feature = "arch")]
            return Ok(Arc::new(ArchPackageManager::new()));

            #[cfg(all(not(feature = "arch"), feature = "debian"))]
            return Ok(Arc::new(AptPackageManager::new()));

            #[cfg(all(
                not(feature = "arch"),
                not(feature = "debian"),
                feature = "debian-pure"
            ))]
            return Err(anyhow::anyhow!(
                "This build only provides the pure-Rust Debian indexing engine; \
                 no live package-manager backend is available for the detected platform."
            ));

            #[cfg(all(
                not(feature = "arch"),
                not(feature = "debian"),
                not(feature = "debian-pure"),
                any(feature = "macos", target_os = "macos")
            ))]
            return Ok(Arc::new(homebrew::HomebrewPackageManager::new()));

            #[cfg(all(
                not(feature = "arch"),
                not(feature = "debian"),
                not(feature = "debian-pure"),
                not(any(feature = "macos", target_os = "macos")),
                feature = "fedora"
            ))]
            return Ok(Arc::new(dnf::DnfPackageManager::new()));

            #[cfg(not(any(
                feature = "arch",
                feature = "debian",
                feature = "debian-pure",
                feature = "fedora"
            )))]
            #[cfg(not(target_os = "macos"))]
            #[allow(
                unreachable_code,
                reason = "additive backend feature returns above make this fallback unreachable"
            )]
            {
                anyhow::bail!(
                    "No package manager backend enabled! Build with --features arch, debian, fedora, or macos"
                );
            }
        }
    }
}

// apt exports are available with debian feature
#[cfg(feature = "debian")]
pub fn apt_search_sync(query: &str) -> anyhow::Result<Vec<SyncPackage>> {
    if crate::core::paths::test_mode() {
        let pm = get_package_manager()?;
        let results = futures::executor::block_on(pm.search(query))?;
        return Ok(results
            .into_iter()
            .map(|p| SyncPackage {
                name: p.name,
                version: p.version,
                description: p.description,
                repo: "main".to_string(),
                download_size: 0,
                installed: p.installed,
            })
            .collect());
    }
    apt::search_sync(query)
}

#[cfg(feature = "debian")]
pub fn apt_list_explicit() -> anyhow::Result<Vec<String>> {
    if crate::core::paths::test_mode() {
        let pm = get_package_manager()?;
        return futures::executor::block_on(pm.list_explicit());
    }
    apt::list_explicit()
}

#[cfg(feature = "debian")]
pub use apt::{
    AptPackageManager, get_sync_pkg_info as apt_get_sync_pkg_info,
    get_system_status as apt_get_system_status,
    list_all_package_names as apt_list_all_package_names,
    list_installed_fast as apt_list_installed_fast, list_updates as apt_list_updates,
    remove_orphans as apt_remove_orphans,
};
#[cfg(any(feature = "debian", feature = "debian-pure"))]
pub use debian_db::{
    get_counts_fast as apt_get_counts_fast, get_info_fast as apt_get_info_fast,
    list_explicit_fast as apt_list_explicit_fast, search_fast as apt_search_fast,
};

#[cfg(all(
    any(feature = "debian", feature = "debian-pure"),
    not(feature = "debian")
))]
pub use debian_db::list_installed_fast as apt_list_installed_fast;

// Homebrew exports are available on macOS
#[cfg(any(feature = "macos", target_os = "macos"))]
pub use homebrew::HomebrewPackageManager;

// DNF/RPM exports are available with fedora feature
#[cfg(feature = "fedora")]
pub use dnf::DnfPackageManager;
