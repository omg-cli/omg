//! Pacman Database Parser and Cache
//!
//! Direct Rust parsing of `/var/lib/pacman/sync/*.db` and `/var/lib/pacman/local/`
//! with bitcode-serialized disk caching and native libalpm health checks.

mod db;

pub(crate) use db::{
    compile_package_patterns, get_potential_aur_package_records, parse_sync_db_package,
    read_local_package, read_local_package_at,
};

#[cfg(test)]
pub(crate) use db::check_local_db_health;
pub(crate) use db::{NativeLocalDbHealth, check_native_local_db_health};
pub use db::UnsatisfiedDependency;

pub use db::{
    AlpmCatalogEpoch, CachedUpdate, LocalDbEpoch, LocalDbPackage, SyncDbEpoch, SyncDbPackage,
    check_updates_cached, get_counts_fast, get_detailed_packages, get_explicit_count,
    get_local_package, get_sync_package, invalidate_caches, list_local_cached,
};
