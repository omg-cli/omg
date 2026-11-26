//! Pure Rust Debian/APT Package Parser
//!
//! Direct parsing of /var/lib/dpkg/status and /var/lib/apt/lists/*_Packages
//! without apt-cache. Provides <15ms cached lookups via rkyv memory-mapping.
//!
//! ## Modules
//!
//! - [`db`]: Core package database parsing and caching
//! - [`sources`]: APT sources.list and deb822 sources parser
//! - [`resolver`]: Dependency resolution with version comparison
//! - [`transaction`]: Pure Rust transaction engine for .deb installation
//! - [`validation`]: Pre-flight checks and error validation
//!
//! ## Error-type decision
//!
//! This module intentionally returns `anyhow::Result` throughout: it is an
//! application-internal backend (never consumed as an independent library),
//! every failure is reported with context strings, and callers only branch on
//! success/failure. A typed error enum would add surface without a current
//! consumer; revisit if this module is ever extracted into a crate.

use super::types::PackageStatus;

pub mod db;
pub mod resolver;
pub mod sources;
pub mod transaction;
pub mod validation;

pub use db::{
    DebianMmapIndex, DebianPackage, DebianPackageIndex, DpkgPackageEntry, clean_package_cache,
    cleanup_expired_mmaps, debian_arch, ensure_index_loaded, ensure_mmap_loaded,
    get_all_packages_with_sizes, get_counts_fast, get_detailed_best_candidates,
    get_detailed_packages, get_info_fast, get_installed_info_fast, get_package_dependencies,
    get_package_size, get_package_version, get_updates_from_mmap, is_installed_fast,
    is_mmap_available, is_package_auto_installed, list_explicit_fast, list_installed_fast,
    list_orphans_fast, search_fast,
};

pub use resolver::{DependencyResolver, ResolutionResult, compare_versions};
pub use sources::{
    RepoType, Repository, get_enabled_binary_repos, parse_all_sources, parse_deb822_content,
    parse_sources_list_content,
};
pub use transaction::{PackageAction, Transaction, TransactionState};
pub use validation::{check_disk_space, require_verified_deb};

/// Fast status may omit orphans/updates. A failed accurate query must not
/// look like zero orphans and zero updates.
pub fn resolve_status_counts<E, F>(
    fast: bool,
    fast_counts: &Result<(usize, usize, usize, usize), E>,
    accurate: F,
) -> Result<PackageStatus, E>
where
    F: FnOnce() -> Result<(usize, usize, usize, usize), E>,
{
    if fast && let Ok((total, explicit, _, _)) = fast_counts {
        return Ok(PackageStatus {
            total: *total,
            explicit: *explicit,
            maintenance: None,
        });
    }
    accurate().map(PackageStatus::from)
}

#[cfg(test)]
mod tests {
    use super::resolve_status_counts;

    #[test]
    fn fast_status_uses_counts_and_omits_orphans() {
        let result: Result<super::PackageStatus, &str> =
            resolve_status_counts(true, &Ok((10, 4, 99, 99)), || {
                panic!("accurate status must not run on a successful fast path")
            });
        let status = result.unwrap();
        assert_eq!(status.maintenance, None);
        assert_eq!(status.into_counts(), (10, 4, 0, 0));
    }

    #[test]
    fn accurate_status_failure_is_not_zero_orphans() {
        let result =
            resolve_status_counts(false, &Ok((10, 4, 0, 0)), || Err("apt cache unavailable"));
        assert_eq!(result, Err("apt cache unavailable"));
    }

    #[test]
    fn fast_path_failure_falls_through_to_accurate_status() {
        let result = resolve_status_counts(true, &Err("no dpkg cache"), || Ok((8, 3, 1, 2)));
        let status = result.unwrap();
        assert_eq!(status.maintenance, Some((1, 2)));
        assert_eq!(status.into_counts(), (8, 3, 1, 2));
    }
}
