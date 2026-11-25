//! In-memory package cache with LRU eviction

use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;

use moka::policy::EvictionPolicy;
use moka::sync::Cache;

use super::protocol::{DetailedPackageInfo, PackageInfo, StatusResult};

use crate::core::fast_status::StatusScope;

fn build_cache<K, V>(max_capacity: u64, ttl: Duration) -> Cache<K, V>
where
    K: Eq + Hash + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    Cache::builder()
        .max_capacity(max_capacity)
        .eviction_policy(EvictionPolicy::lru())
        .time_to_live(ttl)
        .build()
}

const CACHE_BYTES_PER_CONFIGURED_ENTRY: usize = 64 * 1024;

fn weight(bytes: usize) -> u32 {
    u32::try_from(bytes.max(1)).unwrap_or(u32::MAX)
}

fn package_weight(package: &PackageInfo) -> usize {
    package
        .name
        .len()
        .saturating_add(package.version.len())
        .saturating_add(package.description.len())
        .saturating_add(std::mem::size_of::<PackageInfo>())
}

fn search_weight(query: &str, packages: &Arc<Vec<PackageInfo>>) -> u32 {
    weight(
        query.len().saturating_add(
            packages
                .iter()
                .map(package_weight)
                .fold(0usize, usize::saturating_add),
        ),
    )
}

fn detailed_weight(name: &str, info: &Arc<DetailedPackageInfo>) -> u32 {
    let vectors = info
        .depends
        .iter()
        .chain(&info.licenses)
        .map(String::len)
        .fold(0usize, usize::saturating_add);
    weight(
        name.len()
            .saturating_add(info.name.len())
            .saturating_add(info.version.len())
            .saturating_add(info.description.len())
            .saturating_add(info.url.len())
            .saturating_add(info.repo.len())
            .saturating_add(vectors)
            .saturating_add(std::mem::size_of::<DetailedPackageInfo>()),
    )
}

fn build_search_cache(max_bytes: u64, ttl: Duration) -> Cache<String, Arc<Vec<PackageInfo>>> {
    Cache::builder()
        .max_capacity(max_bytes)
        .weigher(|query: &String, packages: &Arc<Vec<PackageInfo>>| search_weight(query, packages))
        .eviction_policy(EvictionPolicy::lru())
        .time_to_live(ttl)
        .build()
}

fn build_detailed_cache(max_bytes: u64, ttl: Duration) -> Cache<String, Arc<DetailedPackageInfo>> {
    Cache::builder()
        .max_capacity(max_bytes)
        .weigher(|name: &String, info: &Arc<DetailedPackageInfo>| detailed_weight(name, info))
        .eviction_policy(EvictionPolicy::lru())
        .time_to_live(ttl)
        .build()
}

/// LRU cache for package search results
pub struct PackageCache {
    /// Search results cache: query -> packages (Arc for cheap cloning)
    cache: Cache<String, Arc<Vec<PackageInfo>>>,
    /// Debian search results cache: query -> package info (Arc for cheap cloning)
    debian_cache: Cache<String, Arc<Vec<PackageInfo>>>,
    /// Detailed info cache: pkgname -> info (Arc for cheap cloning)
    detailed_cache: Cache<String, Arc<DetailedPackageInfo>>,
    /// Negative cache for missing package info
    info_miss_cache: Cache<String, bool>,
    /// Maximum cache size
    max_size: usize,
    status_ttl: Duration,
    /// System status cache keyed by the installed database
    system_status: Cache<StatusScope, Arc<StatusResult>>,
    /// Explicit package list cache keyed by the installed database
    explicit_packages: Cache<StatusScope, Arc<Vec<String>>>,
    /// Explicit package count cache keyed by the installed database
    explicit_count: Cache<StatusScope, usize>,
}

impl PackageCache {
    /// Create a new cache with given size and TTL
    #[must_use]
    pub fn new(max_size: usize, ttl_secs: u64) -> Self {
        Self::new_with_ttls(max_size, ttl_secs, ttl_secs)
    }

    /// Create a new cache with separate TTLs for search and status
    #[must_use]
    pub fn new_with_ttls(max_size: usize, ttl_secs: u64, status_ttl_secs: u64) -> Self {
        let ttl = Duration::from_secs(ttl_secs);
        let status_ttl = Duration::from_secs(status_ttl_secs);
        let capacity = max_size as u64;
        let byte_capacity = u64::try_from(
            max_size
                .max(1)
                .saturating_mul(CACHE_BYTES_PER_CONFIGURED_ENTRY),
        )
        .unwrap_or(u64::MAX);

        Self {
            cache: build_search_cache(byte_capacity, ttl),
            debian_cache: build_search_cache(byte_capacity, ttl),
            detailed_cache: build_detailed_cache(byte_capacity, ttl),
            info_miss_cache: build_cache(capacity, ttl),
            max_size,
            status_ttl,
            system_status: build_cache(1, status_ttl),
            explicit_packages: build_cache(1, status_ttl),
            explicit_count: build_cache(1, status_ttl),
        }
    }

    pub(super) fn status_ttl(&self) -> Duration {
        self.status_ttl
    }

    /// Get system status on a backend with one database.
    #[must_use]
    pub fn get_status(&self) -> Option<Arc<StatusResult>> {
        self.get_scoped_status(StatusScope::UNSCOPED)
    }

    /// Update system status on a backend with one database.
    pub fn update_status(&self, result: Arc<StatusResult>) {
        self.update_scoped_status(StatusScope::UNSCOPED, result);
    }

    /// Get the explicit package list on a backend with one database.
    #[must_use]
    pub fn get_explicit(&self) -> Option<Arc<Vec<String>>> {
        self.get_scoped_explicit(StatusScope::UNSCOPED)
    }

    /// Get the explicit package count on a backend with one database.
    #[must_use]
    pub fn get_explicit_count(&self) -> Option<usize> {
        self.get_scoped_explicit_count(StatusScope::UNSCOPED)
    }

    /// Update the explicit package list on a backend with one database.
    pub fn update_explicit(&self, packages: Vec<String>) {
        self.update_scoped_explicit(StatusScope::UNSCOPED, packages);
    }

    /// Update the shared explicit package list on a backend with one database.
    pub fn update_explicit_arc(&self, packages: Arc<Vec<String>>) {
        self.update_scoped_explicit_arc(StatusScope::UNSCOPED, packages);
    }

    /// Update the explicit package count on a backend with one database.
    pub fn update_explicit_count(&self, count: usize) {
        self.update_scoped_explicit_count(StatusScope::UNSCOPED, count);
    }

    /// Get cached system status (Arc clone is cheap - just pointer copy)
    /// Inlined for hot-path performance (called on every `omg status`)
    #[inline]
    #[must_use]
    pub(crate) fn get_scoped_status(&self, scope: StatusScope) -> Option<Arc<StatusResult>> {
        self.system_status.get(&scope)
    }

    /// Update system status cache (accepts Arc to avoid double-wrapping).
    ///
    /// Also refreshes the explicit-count cache: both values belong to the
    /// same status-refresh epoch and are published together by the worker.
    pub(crate) fn update_scoped_status(&self, scope: StatusScope, result: Arc<StatusResult>) {
        // A status refresh and an explicit-list refresh are separate backend
        // reads. Invalidate the old list before publishing the new count so
        // callers cannot observe values from different refresh epochs.
        self.explicit_packages.invalidate(&scope);
        self.explicit_count.insert(scope, result.explicit_packages);
        self.system_status.insert(scope, result);
    }

    /// Get cached explicit packages (Arc clone is cheap - just pointer copy)
    #[inline]
    #[must_use]
    pub(crate) fn get_scoped_explicit(&self, scope: StatusScope) -> Option<Arc<Vec<String>>> {
        self.explicit_packages.get(&scope)
    }

    /// Get cached explicit package count
    #[inline]
    #[must_use]
    pub(crate) fn get_scoped_explicit_count(&self, scope: StatusScope) -> Option<usize> {
        self.explicit_count.get(&scope)
    }

    /// Update explicit package cache
    pub(crate) fn update_scoped_explicit(&self, scope: StatusScope, packages: Vec<String>) {
        self.update_scoped_explicit_arc(scope, Arc::new(packages));
    }

    pub(crate) fn update_scoped_explicit_arc(
        &self,
        scope: StatusScope,
        packages: Arc<Vec<String>>,
    ) {
        self.explicit_count.insert(scope, packages.len());
        self.explicit_packages.insert(scope, packages);
    }

    /// Update explicit package count cache
    pub(crate) fn update_scoped_explicit_count(&self, scope: StatusScope, count: usize) {
        self.explicit_count.insert(scope, count);
    }

    /// Get cached results for a query (Arc clone is cheap - just pointer copy)
    /// Inlined for hot-path performance (called on every search)
    #[inline]
    #[must_use]
    pub fn get(&self, query: &str) -> Option<Arc<Vec<PackageInfo>>> {
        self.cache.get(query)
    }

    /// Store Arc'd results in cache (avoids double-wrapping)
    pub fn insert_arc(&self, query: String, packages: Arc<Vec<PackageInfo>>) {
        self.cache.insert(query, packages);
    }

    /// Get cached Debian search results (Arc clone is cheap - just pointer copy)
    #[inline]
    #[must_use]
    pub fn get_debian(&self, query: &str) -> Option<Arc<Vec<PackageInfo>>> {
        self.debian_cache.get(query)
    }

    /// Store Arc'd Debian search results in cache (avoids double-wrapping)
    pub fn insert_debian_arc(&self, query: String, packages: Arc<Vec<PackageInfo>>) {
        self.debian_cache.insert(query, packages);
    }

    /// Get cache statistics.
    ///
    /// `size` is the total live entry count across all sub-caches (search,
    /// Debian search, detailed info, negative-info, status, explicit list and
    /// count). `max_size` is the per-sub-cache capacity configured at
    /// construction, not a global budget.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        self.sync();
        let total = self
            .cache
            .entry_count()
            .saturating_add(self.debian_cache.entry_count())
            .saturating_add(self.detailed_cache.entry_count())
            .saturating_add(self.info_miss_cache.entry_count())
            .saturating_add(self.system_status.entry_count())
            .saturating_add(self.explicit_packages.entry_count())
            .saturating_add(self.explicit_count.entry_count());
        CacheStats {
            size: usize::try_from(total).unwrap_or(usize::MAX),
            max_size: self.max_size,
        }
    }

    /// Clear the entire cache
    pub fn clear(&self) {
        self.cache.invalidate_all();
        self.debian_cache.invalidate_all();
        self.detailed_cache.invalidate_all();
        self.info_miss_cache.invalidate_all();
        self.system_status.invalidate_all();
        self.explicit_packages.invalidate_all();
        self.explicit_count.invalidate_all();
        self.sync();
    }

    /// Sync pending cache operations
    /// Moka cache is eventually consistent, this ensures all pending operations complete.
    /// Also used before reporting cache statistics so the returned count
    /// reflects completed writes and invalidations.
    pub fn sync(&self) {
        self.cache.run_pending_tasks();
        self.debian_cache.run_pending_tasks();
        self.detailed_cache.run_pending_tasks();
        self.info_miss_cache.run_pending_tasks();
        self.system_status.run_pending_tasks();
        self.explicit_packages.run_pending_tasks();
        self.explicit_count.run_pending_tasks();
    }

    /// Get detailed info from cache (Arc clone is cheap - just pointer copy)
    /// Inlined for hot-path performance (called on every `omg info`)
    #[inline]
    #[must_use]
    pub fn get_info(&self, name: &str) -> Option<Arc<DetailedPackageInfo>> {
        self.detailed_cache.get(name)
    }

    /// Check if package info is known to be missing (negative cache)
    /// Inlined for hot-path performance (prevents unnecessary lookups)
    #[inline]
    #[must_use]
    pub fn is_info_miss(&self, name: &str) -> bool {
        self.info_miss_cache.get(name).is_some()
    }

    /// Store detailed info in cache (optimized to clone name once)
    pub fn insert_info(&self, info: DetailedPackageInfo) {
        self.insert_info_arc(Arc::new(info));
    }

    /// Store Arc'd detailed info in cache (avoids double-wrapping)
    pub fn insert_info_arc(&self, info: Arc<DetailedPackageInfo>) {
        let name = info.name.clone();
        self.info_miss_cache.invalidate(&name);
        self.detailed_cache.insert(name, info);
    }

    /// Record a missing package info lookup
    pub fn insert_info_miss(&self, name: &str) {
        self.info_miss_cache.insert(name.to_string(), true);
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub size: usize,
    pub max_size: usize,
}

impl Default for PackageCache {
    fn default() -> Self {
        // 1000 entries, 5 minute TTL for search results
        // Status cache: 2 minutes (frequent operations are fast with ALPM caching)
        // This reduces unnecessary status refreshes while still feeling responsive
        Self::new_with_ttls(1000, 300, 120)
    }
}

#[cfg(test)]
#[path = "cache_tests.rs"]
mod tests;
