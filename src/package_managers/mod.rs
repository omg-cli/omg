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
#[cfg(all(test, feature = "arch"))]
pub(crate) use aur_index::{AurIndex as TestAurIndex, build_index as build_test_aur_index};
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

/// Synchronous CLI readers still need Tokio when a selected backend performs
/// async subprocess or blocking-worker work. Run it on a separate thread so
/// callers inside an existing runtime cannot nest a second runtime.
fn block_on_live<T: Send>(
    future: impl std::future::Future<Output = anyhow::Result<T>> + Send,
) -> anyhow::Result<T> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(future)
            })
            .join()
            .map_err(|_| anyhow::anyhow!("Package backend worker panicked"))?
    })
}

#[cfg(feature = "arch")]
pub fn search_sync(query: &str) -> anyhow::Result<Vec<SyncPackage>> {
    let backend = resolve_backend()?;
    if backend == Backend::Mock {
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
    if matches!(backend, Backend::Fedora | Backend::MacOS) {
        let manager = get_package_manager()?;
        let results = block_on_live(manager.search(query))?;
        return Ok(results
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
    #[cfg(any(feature = "debian", feature = "debian-pure"))]
    if crate::core::env::distro::is_debian_like() {
        #[cfg(feature = "debian")]
        if !crate::core::paths::test_mode() {
            return apt::search_sync(query);
        }
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

    alpm_direct::search_sync(query)
}

pub fn list_explicit_fast() -> anyhow::Result<Vec<String>> {
    let backend = resolve_backend()?;
    if crate::core::paths::test_mode() {
        let pm = get_package_manager()?;
        return futures::executor::block_on(pm.list_explicit());
    }

    if matches!(backend, Backend::Fedora | Backend::MacOS) {
        let manager = get_package_manager()?;
        return block_on_live(manager.list_explicit());
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
    let backend = resolve_backend()?;
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

    if matches!(backend, Backend::Fedora | Backend::MacOS) {
        let manager = get_package_manager()?;
        return block_on_live(manager.list_installed()).map(|packages| {
            packages
                .into_iter()
                .map(|package| LocalPackage {
                    name: package.name,
                    version: package.version,
                    description: package.description,
                    install_size: 0,
                    reason: "unknown",
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
    let backend = resolve_backend()?;
    if crate::core::paths::test_mode() {
        let manager = get_package_manager()?;
        return futures::executor::block_on(manager.is_installed(name));
    }

    if matches!(backend, Backend::MacOS) {
        let manager = get_package_manager()?;
        return block_on_live(manager.is_installed(name));
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
    let backend = resolve_backend()?;
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

    if matches!(backend, Backend::Fedora | Backend::MacOS) {
        let manager = get_package_manager()?;
        return block_on_live(manager.info(name)).map(|package| {
            package.map(|package| types::PackageInfo {
                name: package.name,
                version: package.version,
                description: package.description,
                url: None,
                size: 0,
                install_size: None,
                download_size: None,
                repo: "official".to_string(),
                depends: Vec::new(),
                licenses: Vec::new(),
                installed: package.installed,
            })
        });
    }

    #[cfg(any(feature = "debian", feature = "debian-pure"))]
    if crate::core::env::distro::is_debian_like() {
        #[cfg(feature = "debian")]
        if !crate::core::paths::test_mode() {
            return apt::get_sync_pkg_info(name);
        }
        return package_info_from_debian_db(name);
    }

    #[cfg(feature = "arch")]
    return alpm_direct::get_package_info(name);

    #[cfg(all(
        not(feature = "arch"),
        any(feature = "debian", feature = "debian-pure")
    ))]
    {
        #[cfg(feature = "debian")]
        return apt::get_sync_pkg_info(name);
        #[cfg(not(feature = "debian"))]
        return package_info_from_debian_db(name);
    }

    #[cfg(not(any(feature = "arch", feature = "debian", feature = "debian-pure")))]
    anyhow::bail!("No package manager backend enabled to query {name}")
}

pub fn list_orphans_fast() -> anyhow::Result<Vec<String>> {
    let backend = resolve_backend()?;
    if crate::core::paths::test_mode() {
        return Ok(Vec::new());
    }

    if backend == Backend::Fedora {
        #[cfg(feature = "fedora")]
        return block_on_live(dnf::DnfPackageManager::orphan_packages());
    }
    if backend == Backend::MacOS {
        anyhow::bail!("Homebrew does not expose an orphan package listing");
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
    let backend = resolve_backend()?;
    if crate::core::paths::test_mode() {
        let manager = get_package_manager()?;
        let (total, explicit, orphans, _) = futures::executor::block_on(manager.get_status(false))?;
        return Ok((total, explicit, orphans));
    }

    if matches!(backend, Backend::Fedora | Backend::MacOS) {
        let manager = get_package_manager()?;
        let (total, explicit, orphans, _) = block_on_live(manager.get_status(false))?;
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
    let backend = resolve_backend()?;
    if crate::core::paths::test_mode() {
        let manager = get_package_manager()?;
        return futures::executor::block_on(manager.get_status(false));
    }

    if matches!(backend, Backend::Fedora | Backend::MacOS) {
        let manager = get_package_manager()?;
        return block_on_live(manager.get_status(false));
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
pub use traits::{InstalledCatalogObservation, PackageManager};
pub use types::{LocalPackage, SyncPackage};

/// Selected live package backend. Mock is available only under explicit test mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Arch,
    Debian,
    Fedora,
    MacOS,
    Mock,
}

/// Search identity semantics selected from the live backend, never from a name alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SearchNameKind {
    Literal,
    RpmIdentity,
}

impl SearchNameKind {
    pub(crate) const fn from_backend(backend: Backend) -> Self {
        match backend {
            Backend::Fedora => Self::RpmIdentity,
            _ => Self::Literal,
        }
    }

    pub(crate) fn for_manager(name: &str, test_mode: bool) -> Self {
        if name == "dnf" && !test_mode {
            Self::RpmIdentity
        } else {
            Self::Literal
        }
    }

    /// Borrow the exact matching key while retaining the qualified display identity.
    pub(crate) fn exact_key<'a>(self, query: &str, name: &'a str) -> Option<&'a str> {
        if name == query {
            return Some(name);
        }
        if self == Self::RpmIdentity {
            let (basename, architecture) = name.rsplit_once('.')?;
            if !basename.is_empty() && !architecture.is_empty() && basename == query {
                return Some(basename);
            }
        }
        None
    }
}

#[derive(Clone, Copy)]
struct CompiledBackends {
    arch: bool,
    debian: bool,
    fedora: bool,
    macos: bool,
    debian_pure: bool,
}

impl CompiledBackends {
    const fn current() -> Self {
        Self {
            arch: cfg!(feature = "arch"),
            debian: cfg!(feature = "debian"),
            fedora: cfg!(feature = "fedora"),
            macos: cfg!(any(feature = "macos", target_os = "macos")),
            debian_pure: cfg!(feature = "debian-pure"),
        }
    }
}

/// Pure selection policy: compiled features never substitute for the host's
/// actual package database. In particular `debian-pure` is an indexer, not a
/// backend that may operate on a live machine.
fn resolve_for(
    distro: crate::core::env::distro::Distro,
    compiled: CompiledBackends,
    test_mode: bool,
) -> anyhow::Result<Backend> {
    use crate::core::env::distro::Distro;
    if test_mode {
        return Ok(Backend::Mock);
    }
    let (backend, available, feature) = match distro {
        Distro::Arch => (Backend::Arch, compiled.arch, "arch"),
        Distro::Debian | Distro::Ubuntu => (Backend::Debian, compiled.debian, "debian"),
        Distro::Fedora => (Backend::Fedora, compiled.fedora, "fedora"),
        Distro::MacOS => (Backend::MacOS, compiled.macos, "macos"),
        Distro::Unknown => {
            anyhow::bail!("Unsupported Linux distribution: no live package backend can be selected")
        }
    };
    if available {
        return Ok(backend);
    }
    if matches!(distro, Distro::Debian | Distro::Ubuntu) && compiled.debian_pure {
        anyhow::bail!(
            "The Debian indexing feature is not a live APT backend. Install the Debian/Ubuntu omg build, or rebuild with --no-default-features --features debian,pgp,license"
        );
    }
    anyhow::bail!(
        "This omg binary lacks the {feature} package backend required by {distro:?}. Install the matching distro build, or rebuild with --no-default-features --features {feature},pgp,license"
    )
}

/// Select the host's compiled live package backend without touching package
/// databases or starting a daemon.
pub fn resolve_backend() -> anyhow::Result<Backend> {
    let test_mode = crate::core::paths::test_mode();
    resolve_for(
        crate::core::env::distro::detect_distro(),
        CompiledBackends::current(),
        test_mode,
    )
}

/// Get the appropriate package manager for the current distribution.
pub fn get_package_manager() -> anyhow::Result<Arc<dyn PackageManager>> {
    match resolve_backend()? {
        Backend::Mock => {
            let distro = std::env::var("OMG_TEST_DISTRO").unwrap_or_else(|_| "arch".to_string());
            Ok(Arc::new(mock::MockPackageManager::new(&distro)))
        }
        #[cfg(feature = "arch")]
        Backend::Arch => Ok(Arc::new(ArchPackageManager::new())),
        #[cfg(feature = "debian")]
        Backend::Debian => Ok(Arc::new(AptPackageManager::new())),
        #[cfg(feature = "fedora")]
        Backend::Fedora => Ok(Arc::new(dnf::DnfPackageManager::new())),
        #[cfg(any(feature = "macos", target_os = "macos"))]
        Backend::MacOS => Ok(Arc::new(homebrew::HomebrewPackageManager::new())),
        other => anyhow::bail!("The selected {other:?} package backend is not compiled in"),
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

#[cfg(test)]
mod backend_selection_tests {
    #[test]
    fn fedora_search_context_selection_and_exact_keys_are_explicit() {
        use super::{Backend, SearchNameKind};
        for backend in [
            Backend::Arch,
            Backend::Debian,
            Backend::MacOS,
            Backend::Mock,
        ] {
            assert_eq!(
                SearchNameKind::from_backend(backend),
                SearchNameKind::Literal
            );
        }
        assert_eq!(
            SearchNameKind::from_backend(Backend::Fedora),
            SearchNameKind::RpmIdentity
        );
        for name in ["dnf", "apt", "pacman", "brew", "homebrew", "mock", "DNF"] {
            for test_mode in [false, true] {
                assert_eq!(
                    SearchNameKind::for_manager(name, test_mode),
                    if name == "dnf" && !test_mode {
                        SearchNameKind::RpmIdentity
                    } else {
                        SearchNameKind::Literal
                    }
                );
            }
        }
        for (query, name, expected) in [
            ("tree", "tree.x86_64", Some("tree")),
            ("python3.13", "python3.13.x86_64", Some("python3.13")),
            ("tree.x86_64", "tree.x86_64", Some("tree.x86_64")),
            ("tree", "tree", Some("tree")),
            ("tree", "tree.", None),
            ("", ".x86_64", None),
            ("tree", "tree2.x86_64", None),
            ("tree", "tree.x86_64.aarch64", None),
        ] {
            assert_eq!(SearchNameKind::RpmIdentity.exact_key(query, name), expected);
            assert_eq!(
                SearchNameKind::Literal.exact_key(query, name),
                if name == query { Some(name) } else { None }
            );
        }
    }

    use super::{Backend, CompiledBackends, resolve_for};
    use crate::core::env::distro::Distro;

    const ARCH: CompiledBackends = CompiledBackends {
        arch: true,
        debian: false,
        fedora: false,
        macos: false,
        debian_pure: false,
    };
    const DEBIAN: CompiledBackends = CompiledBackends {
        arch: false,
        debian: true,
        ..ARCH
    };
    const FEDORA: CompiledBackends = CompiledBackends {
        arch: false,
        fedora: true,
        ..ARCH
    };

    #[test]
    fn only_the_matching_live_backend_is_selected() {
        for (distro, compiled, expected) in [
            (Distro::Arch, ARCH, Backend::Arch),
            (Distro::Debian, DEBIAN, Backend::Debian),
            (Distro::Ubuntu, DEBIAN, Backend::Debian),
            (Distro::Fedora, FEDORA, Backend::Fedora),
            (
                Distro::MacOS,
                CompiledBackends {
                    macos: true,
                    ..ARCH
                },
                Backend::MacOS,
            ),
            (
                Distro::Fedora,
                CompiledBackends {
                    fedora: true,
                    ..ARCH
                },
                Backend::Fedora,
            ),
            (
                Distro::Debian,
                CompiledBackends {
                    debian: true,
                    ..ARCH
                },
                Backend::Debian,
            ),
        ] {
            assert_eq!(resolve_for(distro, compiled, false).unwrap(), expected);
        }
    }

    #[test]
    fn wrong_or_index_only_features_fail_with_build_guidance() {
        for (distro, compiled, required) in [
            (Distro::Debian, ARCH, "debian"),
            (Distro::Ubuntu, ARCH, "debian"),
            (Distro::Fedora, ARCH, "fedora"),
            (Distro::Arch, DEBIAN, "arch"),
            (Distro::Debian, FEDORA, "debian"),
            (
                Distro::Debian,
                CompiledBackends {
                    arch: false,
                    debian_pure: true,
                    ..ARCH
                },
                "debian",
            ),
        ] {
            let message = resolve_for(distro, compiled, false)
                .expect_err("wrong backend must fail")
                .to_string();
            assert!(message.contains(required), "{message}");
            assert!(message.contains("--no-default-features"), "{message}");
        }
        assert!(resolve_for(Distro::Unknown, ARCH, false).is_err());
    }

    #[test]
    fn explicit_test_mode_selects_mock_without_a_live_backend() {
        assert_eq!(
            resolve_for(Distro::Unknown, ARCH, true).unwrap(),
            Backend::Mock
        );
    }

    #[test]
    fn empty_feature_set_refuses_every_live_host_but_allows_explicit_mock() {
        let none = CompiledBackends {
            arch: false,
            debian: false,
            fedora: false,
            macos: false,
            debian_pure: false,
        };
        for (host, feature) in [
            (Distro::Arch, "arch"),
            (Distro::Debian, "debian"),
            (Distro::Ubuntu, "debian"),
            (Distro::Fedora, "fedora"),
            (Distro::MacOS, "macos"),
        ] {
            let message = resolve_for(host, none, false).unwrap_err().to_string();
            assert!(
                message.contains(&format!("lacks the {feature} package backend")),
                "{message}"
            );
            assert!(
                message.contains(&format!(
                    "--no-default-features --features {feature},pgp,license"
                )),
                "{message}"
            );
            assert_eq!(resolve_for(host, none, true).unwrap(), Backend::Mock);
        }
        assert!(resolve_for(Distro::Unknown, none, false).is_err());
        assert_eq!(
            resolve_for(Distro::Unknown, none, true).unwrap(),
            Backend::Mock
        );
    }

    #[test]
    fn mixed_features_keep_host_selection_and_macos_refusal_precise() {
        let mixed = CompiledBackends {
            arch: true,
            debian: true,
            fedora: true,
            macos: true,
            debian_pure: true,
        };
        for (host, expected) in [
            (Distro::Arch, Backend::Arch),
            (Distro::Debian, Backend::Debian),
            (Distro::Ubuntu, Backend::Debian),
            (Distro::Fedora, Backend::Fedora),
            (Distro::MacOS, Backend::MacOS),
        ] {
            assert_eq!(resolve_for(host, mixed, false).unwrap(), expected);
            assert_eq!(resolve_for(host, mixed, true).unwrap(), Backend::Mock);
        }
        let unavailable = CompiledBackends {
            macos: false,
            ..mixed
        };
        let message = resolve_for(Distro::MacOS, unavailable, false)
            .unwrap_err()
            .to_string();
        assert!(
            message.contains("lacks the macos package backend required by MacOS"),
            "{message}"
        );
    }

    #[test]
    fn pure_indexer_refuses_both_debian_hosts_even_with_other_live_features() {
        let indexer = CompiledBackends {
            debian: false,
            debian_pure: true,
            fedora: true,
            macos: true,
            ..ARCH
        };
        for host in [Distro::Debian, Distro::Ubuntu] {
            let message = resolve_for(host, indexer, false).unwrap_err().to_string();
            assert_eq!(
                message,
                "The Debian indexing feature is not a live APT backend. Install the Debian/Ubuntu omg build, or rebuild with --no-default-features --features debian,pgp,license"
            );
            assert_eq!(resolve_for(host, indexer, true).unwrap(), Backend::Mock);
        }
    }
}
