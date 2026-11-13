//! Pure Rust Pacman Database Parser
//!
//! Direct parsing of /var/lib/pacman/sync/*.db and /var/lib/pacman/local/
//! without libalpm. Provides <1ms cached lookups via rkyv memory-mapping.

mod db;

pub(crate) use db::{
    compile_package_patterns, get_potential_aur_package_records, read_local_package,
};

#[cfg(test)]
pub(crate) use db::check_local_db_health;
pub(crate) use db::{NativeLocalDbHealth, check_native_local_db_health};
pub use db::{UnsatisfiedDependency, unsatisfied_local_dependencies};

pub use db::{
    AlpmCatalogEpoch, CachedUpdate, LocalDbEpoch, LocalDbPackage, SyncDbEpoch, SyncDbPackage,
    check_updates_cached, get_counts_fast, get_detailed_packages, get_explicit_count,
    get_local_package, get_potential_aur_packages, get_sync_package, invalidate_caches,
    list_local_cached,
};
