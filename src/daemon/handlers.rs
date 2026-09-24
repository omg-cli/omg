//! Request handlers for the daemon

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};

use super::cache::PackageCache;
use super::index::PackageIndex;
use super::protocol::{
    DetailedPackageInfo, ExplicitResult, HealthStatus, PackageInfo, Request, RequestId, Response,
    ResponseResult, SearchResult, UpdateEntry, WirePackageSource, error_codes,
};
use crate::core::metrics::GLOBAL_METRICS;
use crate::core::security::{AuditEventType, AuditSeverity, audit_log_nonblocking};
use crate::package_managers::{PackageManager, VersionDisplay, get_package_manager};
#[cfg(feature = "arch")]
use crate::package_managers::{alpm_worker::AlpmWorker, search_detailed};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

const PING_RESPONSE: &str = "pong";
const CACHE_CLEARED_MSG: &str = "cleared";
pub const GLOBAL_RATE_LIMIT_HZ: u32 = 100;
pub const GLOBAL_RATE_LIMIT_BURST: u32 = 200;
const DAEMON_INFO_BACKEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
#[cfg(feature = "arch")]
const DAEMON_INFO_AUR_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);
const REFRESH_DEBOUNCE: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Default)]
struct RefreshDebounce {
    last_completed: std::sync::Mutex<Option<std::time::Instant>>,
}

impl RefreshDebounce {
    fn should_skip(&self, now: std::time::Instant, disk_newer_than_loaded: bool) -> bool {
        if disk_newer_than_loaded {
            return false;
        }
        self.last_completed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .and_then(|completed| now.checked_duration_since(completed))
            .is_some_and(|elapsed| elapsed < REFRESH_DEBOUNCE)
    }

    fn record_completion(&self, completed_at: std::time::Instant) {
        *self
            .last_completed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(completed_at);
    }
}

enum SystemBackendAccess {
    Isolated,
    Production {
        #[cfg(feature = "arch")]
        alpm_worker: std::sync::Arc<AlpmWorker>,
    },
}

impl SystemBackendAccess {
    #[allow(
        clippy::unnecessary_wraps,
        reason = "constructor is fallible when the Arch backend initializes its ALPM worker"
    )]
    fn production() -> anyhow::Result<Self> {
        Ok(Self::Production {
            #[cfg(feature = "arch")]
            alpm_worker: std::sync::Arc::new(AlpmWorker::new()?),
        })
    }

    fn is_production(&self) -> bool {
        matches!(self, Self::Production { .. })
    }
}

/// Index contents and their source observation are one publication unit.
struct PublishedIndex {
    index: Arc<PackageIndex>,
    #[cfg(feature = "arch")]
    epoch: crate::package_managers::pacman_db::AlpmCatalogEpoch,
}

/// Daemon state shared across handlers.
///
/// Fields are visible only to the daemon subtree (`server`, worker tasks);
/// external consumers go through `DaemonState::new` and IPC responses.
pub struct DaemonState {
    pub(super) audit_log_path: PathBuf,
    pub(super) runtime_data_dir: PathBuf,
    pub(super) cache: PackageCache,
    pub(super) persistent: super::db::PersistentCache,
    pub(super) package_manager: Arc<dyn PackageManager>,
    vulnerability_scanner: Arc<dyn crate::core::security::vulnerability::VulnerabilitySource>,
    security_scan_lock: tokio::sync::Mutex<()>,
    pub(super) background_security_scans: bool,
    index: RwLock<PublishedIndex>,
    /// Locked because RefreshIndex must swap in a fresh AlpmWorker: libalpm
    /// caches loaded syncdbs in memory and never revalidates them on disk, so
    /// a worker that predates `omg sync` serves a frozen update list forever.
    system_backends: RwLock<SystemBackendAccess>,
    refresh_lock: tokio::sync::Mutex<()>,
    refresh_debounce: RefreshDebounce,
    index_generation: AtomicU64,
    pub(super) runtime_versions: Arc<RwLock<Vec<(String, String)>>>,
    pub(super) rate_limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    pub(super) start_time: std::time::Instant,
    background_worker_failures: AtomicU64,
}

impl DaemonState {
    /// Clone the current immutable index snapshot without holding the read
    /// lock during searches.
    pub(super) fn index_snapshot(&self) -> Arc<PackageIndex> {
        Arc::clone(
            &self
                .index
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .index,
        )
    }

    /// Run `action` only while `snapshot` is still the published index.
    /// Holding the read lock through the action prevents an old in-flight
    /// search from repopulating cache after a refresh clears it.
    pub(super) fn with_current_index(
        &self,
        snapshot: &Arc<PackageIndex>,
        action: impl FnOnce(),
    ) -> bool {
        let current = self
            .index
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !Arc::ptr_eq(&current.index, snapshot) {
            return false;
        }
        action();
        true
    }

    /// Atomically publish a rebuilt index and invalidate derived caches.
    fn replace_index(
        &self,
        index: PackageIndex,
        #[cfg(feature = "arch")] epoch: crate::package_managers::pacman_db::AlpmCatalogEpoch,
    ) -> usize {
        let package_count = index.len();
        let mut current = self
            .index
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *current = PublishedIndex {
            index: Arc::new(index),
            #[cfg(feature = "arch")]
            epoch,
        };
        self.index_generation.fetch_add(1, Ordering::Release);
        self.cache.clear();
        package_count
    }

    /// Swap in freshly constructed system backends so libalpm reloads the
    /// sync databases from disk. Called by RefreshIndex (after `omg sync`):
    /// without this, a worker created before the sync serves its frozen
    /// in-memory update list until daemon restart.
    fn refresh_system_backends(&self) -> anyhow::Result<()> {
        if !self.uses_production_backends() {
            return Ok(());
        }
        let replacement = SystemBackendAccess::production()?;
        let mut backends = self
            .system_backends
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *backends = replacement;
        Ok(())
    }

    fn uses_production_backends(&self) -> bool {
        self.system_backends
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_production()
    }

    /// Rebuild the published index and reincarnate libalpm. Callers must hold
    /// `refresh_lock`.
    async fn rebuild_production_index(&self) -> anyhow::Result<usize> {
        #[cfg(feature = "arch")]
        let epoch = crate::package_managers::pacman_db::AlpmCatalogEpoch::observe()
            .context("Failed to observe ALPM catalog before index rebuild")?;
        let index = PackageIndex::for_package_manager(Arc::clone(&self.package_manager)).await?;
        self.refresh_system_backends()?;
        #[cfg(feature = "arch")]
        epoch.ensure_unchanged(
            crate::package_managers::pacman_db::AlpmCatalogEpoch::observe()
                .context("Failed to observe ALPM catalog after index and backend rebuild")?,
        )?;
        let packages = self.replace_index(
            index,
            #[cfg(feature = "arch")]
            epoch,
        );
        self.persistent.invalidate_status();
        Ok(packages)
    }

    /// Rebuild catalog state when the observed sync/local identity differs
    /// from the loaded index. Isolated daemons are a no-op.
    #[cfg(feature = "arch")]
    async fn heal_index_if_catalog_changed(&self) -> anyhow::Result<()> {
        if !self.uses_production_backends() {
            return Ok(());
        }
        if !self.catalog_needs_heal() {
            return Ok(());
        }
        let _refresh_guard = self.refresh_lock.lock().await;
        if !self.catalog_needs_heal() {
            return Ok(());
        }
        self.rebuild_production_index().await?;
        Ok(())
    }

    #[cfg(feature = "arch")]
    fn catalog_needs_heal(&self) -> bool {
        match crate::package_managers::pacman_db::AlpmCatalogEpoch::observe() {
            Err(_) => true,
            Ok(disk) => {
                let loaded = self
                    .index
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .epoch;
                disk != loaded
            }
        }
    }

    pub(super) async fn status_counts(&self) -> anyhow::Result<(usize, usize, usize, usize)> {
        self.package_manager.get_status(false).await
    }

    pub(super) async fn explicit_packages(&self) -> anyhow::Result<Vec<String>> {
        self.package_manager.list_explicit().await
    }

    pub fn new() -> anyhow::Result<Self> {
        let data_dir = crate::core::paths::daemon_data_dir();
        let persistent = Self::open_persistent_cache(&data_dir)?;
        let package_manager = get_package_manager()?;
        let load_catalog = || -> anyhow::Result<(PackageIndex, SystemBackendAccess)> {
            let index = PackageIndex::for_package_manager_blocking(Arc::clone(&package_manager))
                .context("Failed to build package index. Ensure package databases are synced (run 'omg sync').")?;
            Ok((index, SystemBackendAccess::production()?))
        };
        #[cfg(feature = "arch")]
        let ((index, system_backends), index_epoch) =
            crate::package_managers::pacman_db::AlpmCatalogEpoch::load_stable(
                crate::package_managers::pacman_db::AlpmCatalogEpoch::observe,
                load_catalog,
            )?;
        #[cfg(not(feature = "arch"))]
        let (index, system_backends) = load_catalog()?;

        Ok(Self::from_index(
            crate::core::paths::data_dir(),
            persistent,
            index,
            package_manager,
            system_backends,
            #[cfg(feature = "arch")]
            index_epoch,
        ))
    }

    /// Initialize daemon handlers with explicit isolated dependencies.
    ///
    /// # Errors
    ///
    /// Returns an error when the persistent cache cannot be opened at `data_dir`.
    pub fn new_isolated(
        data_dir: &Path,
        index: PackageIndex,
        package_manager: Arc<dyn PackageManager>,
    ) -> anyhow::Result<Self> {
        let persistent = Self::open_persistent_cache(data_dir)?;
        Ok(Self::from_index(
            data_dir.to_path_buf(),
            persistent,
            index,
            package_manager,
            SystemBackendAccess::Isolated,
            #[cfg(feature = "arch")]
            crate::package_managers::pacman_db::AlpmCatalogEpoch::UNIX_EPOCH,
        ))
    }

    /// Initialize an isolated daemon with an explicit vulnerability source.
    /// Production construction always uses the configured native source.
    ///
    /// # Errors
    ///
    /// Returns an error when the persistent cache cannot be opened at `data_dir`.
    pub fn new_isolated_with_scanner(
        data_dir: &Path,
        index: PackageIndex,
        package_manager: Arc<dyn PackageManager>,
        scanner: Arc<dyn crate::core::security::vulnerability::VulnerabilitySource>,
    ) -> anyhow::Result<Self> {
        let mut state = Self::new_isolated(data_dir, index, package_manager)?;
        state.vulnerability_scanner = scanner;
        Ok(state)
    }

    fn open_persistent_cache(data_dir: &Path) -> anyhow::Result<super::db::PersistentCache> {
        tracing::info!("Initializing daemon data directory: {:?}", data_dir);

        super::db::PersistentCache::new(data_dir).with_context(|| {
            format!(
                "Failed to initialize persistent cache at {}. \
                 Check permissions and disk space.",
                data_dir.display()
            )
        })
    }

    fn from_index(
        runtime_data_dir: PathBuf,
        persistent: super::db::PersistentCache,
        index: PackageIndex,
        package_manager: Arc<dyn PackageManager>,
        system_backends: SystemBackendAccess,
        #[cfg(feature = "arch")] index_epoch: crate::package_managers::pacman_db::AlpmCatalogEpoch,
    ) -> Self {
        tracing::info!("Package index loaded: {} packages", index.len());

        let cache = PackageCache::default();

        let quota = Quota::per_second(crate::core::safe_ops::nonzero_u32_or_default(
            GLOBAL_RATE_LIMIT_HZ,
            1,
        ))
        .allow_burst(crate::core::safe_ops::nonzero_u32_or_default(
            GLOBAL_RATE_LIMIT_BURST,
            1,
        ));
        let rate_limiter = Arc::new(RateLimiter::direct(quota));

        tracing::info!("Using package manager: {}", package_manager.name());

        // Pre-warm Debian package cache if on Debian/Ubuntu
        #[cfg(any(feature = "debian", feature = "debian-pure"))]
        if system_backends.is_production() {
            tracing::info!("Pre-warming Debian package cache...");
            let start = std::time::Instant::now();

            // Load the full index
            if let Err(error) = crate::package_managers::debian_db::ensure_index_loaded() {
                tracing::warn!("Failed to pre-warm Debian cache: {error}");
            } else {
                tracing::info!("Debian cache pre-warmed in {:?}", start.elapsed());
            }
        }

        let background_security_scans = system_backends.is_production();
        Self {
            audit_log_path: runtime_data_dir.join("audit/audit.jsonl"),
            runtime_data_dir,
            cache,
            persistent,
            package_manager,
            index: RwLock::new(PublishedIndex {
                index: Arc::new(index),
                #[cfg(feature = "arch")]
                epoch: index_epoch,
            }),
            vulnerability_scanner: Arc::new(
                crate::core::security::vulnerability::VulnerabilityScanner::new(),
            ),
            security_scan_lock: tokio::sync::Mutex::new(()),
            background_security_scans,
            system_backends: RwLock::new(system_backends),
            refresh_lock: tokio::sync::Mutex::new(()),
            refresh_debounce: RefreshDebounce::default(),
            index_generation: AtomicU64::new(0),
            runtime_versions: Arc::new(RwLock::new(Vec::new())),
            rate_limiter,
            start_time: std::time::Instant::now(),
            background_worker_failures: AtomicU64::new(0),
        }
    }

    /// Record one unexpected termination of the singleton status worker.
    pub(super) fn inc_background_worker_failures(&self) {
        self.background_worker_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub(super) fn background_worker_failures(&self) -> u64 {
        self.background_worker_failures.load(Ordering::Relaxed)
    }

    pub(super) async fn scan_security(
        &self,
    ) -> anyhow::Result<crate::core::security::scan::SecurityAuditResult> {
        // Serialize background and on-demand scans so warmed package results
        // are available before another scan starts fetching the same inventory.
        let _guard = self.security_scan_lock.lock().await;
        crate::core::security::scan::scan_installed_in(
            self.package_manager.as_ref(),
            self.vulnerability_scanner.as_ref(),
            &self.audit_log_path,
        )
        .await
    }
}

// NOTE: DaemonState does not implement Default because initialization can fail.
// Use DaemonState::new() which returns Result<Self, anyhow::Error> to handle errors properly.

/// Handle an incoming request
#[tracing::instrument(skip(state), fields(request_type = %request.variant_name()))]
pub async fn handle_request(state: Arc<DaemonState>, request: Request) -> Response {
    // METRICS: Track total requests handled
    GLOBAL_METRICS.inc_requests_total();

    // SECURITY: Enforce rate limiting
    if state.rate_limiter.check().is_err() {
        tracing::warn!("Rate limit exceeded for request");
        audit_log_nonblocking(
            AuditEventType::PolicyViolation,
            AuditSeverity::Warning,
            "daemon_handler",
            "Global rate limit exceeded",
        );
        GLOBAL_METRICS.inc_rate_limit_hits();
        GLOBAL_METRICS.inc_requests_failed();
        return Response::Error {
            id: request.id(),
            code: error_codes::RATE_LIMITED,
            message: "Rate limit exceeded. Please slow down.".to_string(),
        };
    }

    #[cfg(feature = "arch")]
    if request.reads_arch_sync_catalog()
        && let Err(error) = state.heal_index_if_catalog_changed().await
    {
        return internal_error(
            request.id(),
            format!("Failed to refresh stale package index: {error:#}"),
        );
    }

    match request {
        Request::Search { id, query, limit } => handle_search(state, id, query, limit).await,
        Request::Info { id, package } => handle_info(state, id, package).await,
        Request::Ping { id } => Response::Success {
            id,
            result: ResponseResult::Ping(PING_RESPONSE.to_string()),
        },
        Request::Status { id } => handle_status(state, id).await,
        Request::Explicit { id } => handle_list_explicit(state, id).await,
        Request::ExplicitCount { id } => handle_explicit_count(state, id).await,
        Request::SecurityAudit { id } => handle_security_audit(state, id).await,
        Request::CacheStats { id } => {
            let stats = state.cache.stats();
            Response::Success {
                id,
                result: ResponseResult::CacheStats {
                    size: stats.size,
                    max_size: stats.max_size,
                },
            }
        }
        Request::CacheClear { id } => {
            state.cache.clear();
            Response::Success {
                id,
                result: ResponseResult::Message(CACHE_CLEARED_MSG.to_string()),
            }
        }
        Request::RefreshIndex { id } => handle_refresh_index(state, id).await,
        Request::Metrics { id } => handle_metrics(id),
        Request::Suggest { id, query, limit } => handle_suggest(state, id, query, limit).await,
        Request::DebianSearch { id, query, limit } => {
            handle_debian_search(state, id, query, limit).await
        }
        Request::Health { id } => handle_health(&state, id),
        Request::ListUpdates { id } => handle_list_updates(state, id).await,
    }
}

/// Rebuild the package index from synchronized system databases and publish
/// it atomically. Existing requests continue using their previous immutable
/// snapshot until the swap completes.
async fn handle_refresh_index(state: Arc<DaemonState>, id: RequestId) -> Response {
    if !state
        .system_backends
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_production()
    {
        return validation_error(id, "Index refresh is unavailable in an isolated daemon");
    }

    let observed_generation = state.index_generation.load(Ordering::Acquire);
    let _refresh_guard = state.refresh_lock.lock().await;
    if state.index_generation.load(Ordering::Acquire) != observed_generation {
        let packages = state.index_snapshot().len();
        tracing::debug!(packages, "Coalesced concurrent package index refresh");
        return Response::Success {
            id,
            result: ResponseResult::IndexRefreshed { packages },
        };
    }
    let disk_newer_than_loaded = {
        #[cfg(feature = "arch")]
        {
            state.catalog_needs_heal()
        }
        #[cfg(not(feature = "arch"))]
        {
            false
        }
    };
    if state
        .refresh_debounce
        .should_skip(std::time::Instant::now(), disk_newer_than_loaded)
    {
        if let Err(error) = state.refresh_system_backends() {
            return internal_error(id, format!("Failed to refresh package backends: {error:#}"));
        }
        let packages = state.index_snapshot().len();
        tracing::debug!(packages, "Debounced recent package index refresh");
        return Response::Success {
            id,
            result: ResponseResult::IndexRefreshed { packages },
        };
    }

    let packages = match state.rebuild_production_index().await {
        Ok(packages) => packages,
        Err(error) => {
            return internal_error(id, format!("Failed to rebuild package index: {error:#}"));
        }
    };
    state
        .refresh_debounce
        .record_completion(std::time::Instant::now());
    tracing::info!(packages, "Daemon package index refreshed");
    Response::Success {
        id,
        result: ResponseResult::IndexRefreshed { packages },
    }
}

/// Run an index search on the blocking pool. Both search handlers share
/// this so heavy scans never stall the async executor.
pub(super) async fn search_index_blocking(
    index: Arc<PackageIndex>,
    query: String,
) -> Result<Vec<PackageInfo>, String> {
    let task_index = Arc::clone(&index);
    tokio::task::spawn_blocking(move || task_index.search(&query, MAX_SEARCH_LIMIT))
        .await
        .map_err(|error| format!("Search task failed: {error}"))
}

/// Handle Debian search request
#[tracing::instrument(skip(state), fields(query_len = query.len()))]
async fn handle_debian_search(
    state: Arc<DaemonState>,
    id: RequestId,
    query: String,
    limit: Option<usize>,
) -> Response {
    // METRICS: Track search requests
    GLOBAL_METRICS.inc_search_requests();

    if query.len() > MAX_QUERY_LENGTH {
        return Response::Error {
            id,
            code: error_codes::INVALID_PARAMS,
            message: format!("Query too long (max {MAX_QUERY_LENGTH} characters)"),
        };
    }

    let limit = limit.unwrap_or(DEFAULT_SEARCH_LIMIT).min(MAX_SEARCH_LIMIT);

    // Check cache first (Arc clone is cheap - just pointer copy)
    if let Some(cached) = state.cache.get_debian(&query) {
        // METRICS: Cache hit
        GLOBAL_METRICS.inc_cache_hits();
        return Response::Success {
            id,
            result: ResponseResult::DebianSearch(cached.iter().take(limit).cloned().collect()),
        };
    }

    // METRICS: Cache miss - will perform search
    GLOBAL_METRICS.inc_cache_misses();

    // The daemon index is the authoritative, already-loaded package catalog.
    // Searching the package database again here duplicated I/O and made request
    // behavior depend on process-global environment state.
    let index = state.index_snapshot();
    let mut results = match search_index_blocking(Arc::clone(&index), query.clone()).await {
        Ok(results) => results,
        Err(error) => return internal_error(id, format!("Debian search task failed: {error}")),
    };
    for package in &mut results {
        package.source = WirePackageSource::Apt;
    }
    let results = Arc::new(results);
    state.with_current_index(&index, || {
        state.cache.insert_debian_arc(query, Arc::clone(&results));
    });
    let response_results = results.iter().take(limit).cloned().collect();
    Response::Success {
        id,
        result: ResponseResult::DebianSearch(response_results),
    }
}

/// Maximum length of search query
const MAX_QUERY_LENGTH: usize = 500;
/// Default search limit
const DEFAULT_SEARCH_LIMIT: usize = 50;
/// Backing cache limit shared by request searches and background prewarming.
pub(super) const MAX_SEARCH_LIMIT: usize = 1000;
/// Default number of suggestions returned
const DEFAULT_SUGGEST_LIMIT: usize = 10;
/// Maximum number of suggestions returned
const MAX_SUGGEST_LIMIT: usize = 50;
/// Cache size threshold for "degraded" health status
const HEALTH_DEGRADED_CACHE_THRESHOLD: usize = 50_000;
/// Cache size threshold for "unhealthy" health status
const HEALTH_UNHEALTHY_CACHE_THRESHOLD: usize = 100_000;
/// Failed request threshold for "unhealthy" health status
const HEALTH_UNHEALTHY_FAILURES_THRESHOLD: u64 = 1000;

/// Handle metrics request
fn handle_metrics(id: RequestId) -> Response {
    let snapshot = GLOBAL_METRICS.snapshot();

    // Map internal metrics snapshot to protocol snapshot
    // This decouples the internal representation from the wire format
    let protocol_snapshot = super::protocol::MetricsSnapshot {
        requests_total: snapshot.requests_total,
        requests_failed: snapshot.requests_failed,
        rate_limit_hits: snapshot.rate_limit_hits,
        validation_failures: snapshot.validation_failures,
        active_connections: snapshot.active_connections,
        security_audit_requests: snapshot.security_audit_requests,
        bytes_received: snapshot.bytes_received,
        bytes_sent: snapshot.bytes_sent,
        cache_hits: snapshot.cache_hits,
        cache_misses: snapshot.cache_misses,
        search_requests: snapshot.search_requests,
        info_requests: snapshot.info_requests,
        status_requests: snapshot.status_requests,
    };

    Response::Success {
        id,
        result: ResponseResult::Metrics(protocol_snapshot),
    }
}

/// Handle suggest request
async fn handle_suggest(
    state: Arc<DaemonState>,
    id: RequestId,
    query: String,
    limit: Option<usize>,
) -> Response {
    // SECURITY: Validate query length
    if query.len() > MAX_QUERY_LENGTH {
        return Response::Error {
            id,
            code: error_codes::INVALID_PARAMS,
            message: "Query too long".to_string(),
        };
    }

    let limit = limit
        .unwrap_or(DEFAULT_SUGGEST_LIMIT)
        .min(MAX_SUGGEST_LIMIT);
    let index = state.index_snapshot();

    // Run fuzzy search in blocking thread
    let suggestions = tokio::task::spawn_blocking(move || index.suggest(&query, limit)).await;

    match suggestions {
        Ok(results) => Response::Success {
            id,
            result: ResponseResult::Suggest(results),
        },
        Err(e) => Response::Error {
            id,
            code: error_codes::INTERNAL_ERROR,
            message: format!("Suggest task failed: {e}"),
        },
    }
}

/// Handle search request
#[tracing::instrument(skip(state), fields(query_len = query.len()))]
async fn handle_search(
    state: Arc<DaemonState>,
    id: RequestId,
    query: String,
    limit: Option<usize>,
) -> Response {
    // METRICS: Track search requests
    GLOBAL_METRICS.inc_search_requests();

    // SECURITY: Validate search query to prevent injection attacks
    // Allow more flexible search queries but limit length
    if query.len() > MAX_QUERY_LENGTH {
        return validation_error(
            id,
            format!("Search query too long (max {MAX_QUERY_LENGTH} characters)"),
        );
    }

    let limit = limit.unwrap_or(DEFAULT_SEARCH_LIMIT).min(MAX_SEARCH_LIMIT); // Cap limit to prevent resource exhaustion

    // Check cache first (Arc clone is cheap - just pointer copy)
    if let Some(cached) = state.cache.get(&query) {
        // METRICS: Cache hit
        GLOBAL_METRICS.inc_cache_hits();
        let total = cached.len();
        let packages: Vec<_> = cached.iter().take(limit).cloned().collect();
        return Response::Success {
            id,
            result: ResponseResult::Search(SearchResult { packages, total }),
        };
    }

    // METRICS: Cache miss - will perform search
    GLOBAL_METRICS.inc_cache_misses();

    // 1. Instant Official Search (Sub-millisecond)
    // Cache the full result set (up to MAX_SEARCH_LIMIT) so subsequent requests
    // with different limits are served correctly from cache.
    let index = state.index_snapshot();
    let official = match search_index_blocking(index.clone(), query.clone()).await {
        Ok(res) => res,
        Err(e) => return internal_error(id, format!("Search task failed: {e}")),
    };

    // Cache the full result set; serve truncated views per request limit
    let official = Arc::new(official);
    let total = official.len();
    state.with_current_index(&index, || {
        state.cache.insert_arc(query, Arc::clone(&official));
    });

    let packages: Vec<_> = official.iter().take(limit).cloned().collect();

    Response::Success {
        id,
        result: ResponseResult::Search(SearchResult { packages, total }),
    }
}

/// Handle info request
#[tracing::instrument(skip(state))]
async fn handle_info(state: Arc<DaemonState>, id: RequestId, package: String) -> Response {
    // METRICS: Track info requests
    GLOBAL_METRICS.inc_info_requests();

    // SECURITY: Validate package name to prevent command injection
    if let Err(e) = crate::core::security::validate_package_name(&package) {
        return validation_error(id, format!("Invalid package name: {e}"));
    }

    // 1. Check cache first (Arc clone is cheap - just pointer copy)
    if let Some(cached) = state.cache.get_info(&package) {
        // METRICS: Cache hit
        GLOBAL_METRICS.inc_cache_hits();
        return Response::Success {
            id,
            result: ResponseResult::Info(Arc::unwrap_or_clone(cached)),
        };
    }

    if state.cache.is_info_miss(&package) {
        return not_found_error(id, format!("Package not found: {package}"));
    }

    // METRICS: Cache miss - will fetch package info
    GLOBAL_METRICS.inc_cache_misses();

    // 2. Try official index (instant hash lookup).
    let index = state.index_snapshot();
    if let Some(pkg) = index.get(&package) {
        // Clone once, then use Arc for cheap sharing. Cache only while this
        // snapshot is still current; a refresh clears all older entries.
        let info = Arc::new(pkg);
        state.with_current_index(&index, || {
            state.cache.insert_info_arc(Arc::clone(&info));
        });
        return Response::Success {
            id,
            result: ResponseResult::Info(Arc::unwrap_or_clone(info)),
        };
    }

    // 3. Try Package Manager Backend. Only a genuine `Ok(None)` falls through
    // to the next source; backend errors and timeouts are reported explicitly
    // instead of being silently converted into "package not found".
    match tokio::time::timeout(
        DAEMON_INFO_BACKEND_TIMEOUT,
        state.package_manager.info(&package),
    )
    .await
    {
        Ok(Ok(Some(info))) => {
            let detailed = Arc::new(DetailedPackageInfo {
                name: info.name,
                version: info.version.version_string(),
                description: info.description,
                url: String::new(), // info.url not in Package struct currently
                size: 0,
                download_size: 0,
                repo: String::new(),
                depends: Vec::new(),
                licenses: Vec::new(),
                source: WirePackageSource::Official,
            });
            state.with_current_index(&index, || {
                state.cache.insert_info_arc(Arc::clone(&detailed));
            });
            return Response::Success {
                id,
                result: ResponseResult::Info(Arc::unwrap_or_clone(detailed)),
            };
        }
        Ok(Ok(None)) => {}
        Ok(Err(error)) => {
            tracing::warn!("Info backend error for {package}: {error:#}");
            return internal_error(id, format!("Info backend failed for {package}: {error}"));
        }
        Err(_) => {
            tracing::warn!(
                "Info backend timed out after {DAEMON_INFO_BACKEND_TIMEOUT:?} for {package}"
            );
            return internal_error(
                id,
                format!(
                    "Info backend timed out after {} seconds",
                    DAEMON_INFO_BACKEND_TIMEOUT.as_secs()
                ),
            );
        }
    }

    // 4. Try AUR (arch only). AUR is best-effort for availability, but a
    // failed or timed-out lookup is surfaced loudly (mirroring step 3's
    // backend semantics) instead of silently masquerading as "not found".
    // Only a genuine miss (empty results or no exact name match) falls
    // through to the negative cache.
    #[cfg(feature = "arch")]
    if state
        .system_backends
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_production()
        && state.package_manager.name() == "pacman"
    {
        match tokio::time::timeout(DAEMON_INFO_AUR_TIMEOUT, search_detailed(&package)).await {
            Ok(Ok(details)) => {
                if let Some(pkg) = details.into_iter().find(|p| p.name == package) {
                    let detailed = Arc::new(DetailedPackageInfo {
                        name: pkg.name,
                        version: pkg.version,
                        description: pkg.description.unwrap_or_default(),
                        url: pkg.url.unwrap_or_default(),
                        size: 0,
                        download_size: 0,
                        repo: "aur".to_string(),
                        depends: pkg.depends.unwrap_or_default(),
                        licenses: pkg.license.unwrap_or_default(),
                        source: WirePackageSource::Aur,
                    });

                    state.with_current_index(&index, || {
                        state.cache.insert_info_arc(Arc::clone(&detailed));
                    });
                    return Response::Success {
                        id,
                        result: ResponseResult::Info(Arc::unwrap_or_clone(detailed)),
                    };
                }
            }
            Ok(Err(error)) => {
                tracing::warn!("AUR lookup failed for {package}: {error:#}");
                return internal_error(id, format!("AUR lookup failed for {package}: {error}"));
            }
            Err(_) => {
                tracing::warn!(
                    "AUR lookup timed out after {DAEMON_INFO_AUR_TIMEOUT:?} for {package}"
                );
                return internal_error(
                    id,
                    format!(
                        "AUR lookup timed out after {} seconds",
                        DAEMON_INFO_AUR_TIMEOUT.as_secs()
                    ),
                );
            }
        }
    }

    state.with_current_index(&index, || {
        state.cache.insert_info_miss(&package);
    });

    not_found_error(id, format!("Package not found: {package}"))
}

/// Handle status request
#[tracing::instrument(skip(state))]
async fn handle_status(state: Arc<DaemonState>, id: RequestId) -> Response {
    // METRICS: Track status requests
    GLOBAL_METRICS.inc_status_requests();

    // 1. Check MEMORY cache first (instant - sub-microsecond, Arc clone is cheap)
    if let Some(cached) = state.cache.get_status() {
        // METRICS: Cache hit (memory)
        GLOBAL_METRICS.inc_cache_hits();
        return Response::Success {
            id,
            result: ResponseResult::Status(Arc::unwrap_or_clone(cached)),
        };
    }

    // 2. Check persistent cache (disk - slower)
    // Runs in blocking thread to avoid stalling async runtime
    let state_clone = Arc::clone(&state);
    let cached_result = tokio::task::spawn_blocking(move || {
        state_clone
            .persistent
            .get_status(state_clone.cache.status_ttl())
    })
    .await;

    match cached_result {
        Ok(Ok(Some(cached))) => {
            // METRICS: Cache hit (persistent)
            GLOBAL_METRICS.inc_cache_hits();
            // Do not restart its lifetime by promoting an old snapshot into
            // the memory cache. Only a new backend refresh starts a new TTL.
            return Response::Success {
                id,
                result: ResponseResult::Status(cached),
            };
        }
        Ok(Ok(None)) => {}
        Ok(Err(error)) => {
            tracing::warn!("Failed to read persisted status cache: {error}");
        }
        Err(error) => {
            tracing::warn!("Status cache task failed: {error}");
        }
    }

    // METRICS: Cache miss - need to query system
    GLOBAL_METRICS.inc_cache_misses();

    // 3. Query the selected backend. Production uses the optimized native
    // status paths; dependency-injected states stay behind the package-manager
    // interface and never access host package databases.
    let status_result = state.status_counts().await;

    match status_result {
        Ok((total, explicit, orphans, updates)) => {
            let (res, cacheable) = super::status_policy::status_snapshot(
                total,
                explicit,
                orphans,
                updates,
                state
                    .runtime_versions
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone(),
                None,
            );
            debug_assert!(
                !cacheable,
                "package-count snapshots without a vulnerability scan must not be cached"
            );

            Response::Success {
                id,
                result: ResponseResult::Status(res),
            }
        }
        Err(error) => internal_error(id, format!("Failed to get system status: {error}")),
    }
}

/// Handle security audit request
/// Parse a vulnerability score string into its numeric CVSS score.
#[cfg(test)]
fn vulnerability_score(score: &str) -> Option<f64> {
    score.parse::<f64>().ok().or_else(|| {
        score
            .parse::<cvss::Cvss>()
            .ok()
            .map(|vector| vector.score())
    })
}

async fn handle_security_audit(state: Arc<DaemonState>, id: RequestId) -> Response {
    GLOBAL_METRICS.inc_security_audit_requests();
    match state.scan_security().await {
        Ok(result) => Response::Success {
            id,
            result: ResponseResult::SecurityAudit(result),
        },
        Err(error) => internal_error(id, error.to_string()),
    }
}

/// Handle list explicit request
async fn handle_list_explicit(state: Arc<DaemonState>, id: RequestId) -> Response {
    // Arc clone is cheap - just pointer copy
    if let Some(cached) = state.cache.get_explicit() {
        return Response::Success {
            id,
            result: ResponseResult::Explicit(ExplicitResult {
                packages: Arc::unwrap_or_clone(cached),
            }),
        };
    }

    let packages_result = state.explicit_packages().await;

    match packages_result {
        Ok(packages) => {
            let packages_arc = Arc::new(packages);
            state.cache.update_explicit_arc(Arc::clone(&packages_arc));
            Response::Success {
                id,
                result: ResponseResult::Explicit(ExplicitResult {
                    packages: Arc::unwrap_or_clone(packages_arc),
                }),
            }
        }
        Err(error) => internal_error(id, format!("Failed to list explicit packages: {error}")),
    }
}

/// Handle explicit package count request
async fn handle_explicit_count(state: Arc<DaemonState>, id: RequestId) -> Response {
    if let Some(cached) = state.cache.get_explicit_count() {
        return Response::Success {
            id,
            result: ResponseResult::ExplicitCount(cached),
        };
    }

    let count_result = state
        .explicit_packages()
        .await
        .map(|packages| packages.len());

    match count_result {
        Ok(count) => {
            state.cache.update_explicit_count(count);
            Response::Success {
                id,
                result: ResponseResult::ExplicitCount(count),
            }
        }
        Err(error) => internal_error(id, format!("Failed to count explicit packages: {error}")),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Handler Dispatch Helpers - Reduce Boilerplate
// ═══════════════════════════════════════════════════════════════════════════════

/// Create a validation error response with logging and metrics
#[cold]
#[inline(never)]
fn validation_error(id: RequestId, message: impl Into<String>) -> Response {
    let msg = message.into();
    audit_log_nonblocking(
        AuditEventType::PolicyViolation,
        AuditSeverity::Warning,
        "daemon_handler",
        &msg,
    );
    GLOBAL_METRICS.inc_validation_failures();
    GLOBAL_METRICS.inc_requests_failed();
    Response::Error {
        id,
        code: error_codes::INVALID_PARAMS,
        message: msg,
    }
}

/// Resident memory of the daemon process in MiB, parsed from procfs.
/// `/proc/self/status` is a kernel virtual file served from memory (no
/// device I/O), so the synchronous read is effectively free.
fn process_rss_mb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb / 1024)
}

fn handle_health(state: &Arc<DaemonState>, id: RequestId) -> Response {
    let uptime_seconds = state.start_time.elapsed().as_secs();
    let cache_size = state.cache.stats().size;
    let metrics = GLOBAL_METRICS.snapshot();
    let active_connections = metrics.active_connections;

    let memory_usage_mb = process_rss_mb().unwrap_or(0);

    let status = if cache_size > HEALTH_UNHEALTHY_CACHE_THRESHOLD
        || metrics.requests_failed > HEALTH_UNHEALTHY_FAILURES_THRESHOLD
    {
        "unhealthy".to_string()
    } else if cache_size > HEALTH_DEGRADED_CACHE_THRESHOLD {
        "degraded".to_string()
    } else {
        "healthy".to_string()
    };

    Response::Success {
        id,
        result: ResponseResult::Health(HealthStatus {
            status,
            uptime_seconds,
            memory_usage_mb,
            cache_size,
            active_connections,
            background_worker_failures: state.background_worker_failures(),
        }),
    }
}

/// Names listed in pacman.conf `IgnorePkg` must never appear in update lists.
///
/// The hot ALPM worker owns a bare `Alpm` handle without
/// `configure_package_filters`, so unlike the CLI path
/// (`alpm_ops::get_update_list`, which relies on `should_ignore()` at the
/// source) it would report ignored packages as updatable. This replicates
/// the name-level filter on the daemon side so both surfaces agree.
/// Group-based ignores (`IgnoreGroup`) need ALPM group membership and are
/// still only applied on the direct CLI path.
#[cfg(feature = "arch")]
fn filter_ignored_updates<T>(
    updates: Vec<T>,
    ignored_pkgs: &[String],
    name: impl Fn(&T) -> &str,
) -> Vec<T> {
    if ignored_pkgs.is_empty() {
        return updates;
    }
    let ignored: std::collections::HashSet<&str> =
        ignored_pkgs.iter().map(String::as_str).collect();
    updates
        .into_iter()
        .filter(|update| !ignored.contains(name(update)))
        .collect()
}

/// Handle list updates request using the hot ALPM worker (zero ALPM init overhead)
async fn handle_list_updates(state: Arc<DaemonState>, id: RequestId) -> Response {
    #[cfg(feature = "arch")]
    let updates_result = {
        // Clone the worker handle under the lock, then release the guard
        // before awaiting (std RwLock guards are not Send).
        let alpm_worker = {
            let backends = state
                .system_backends
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match &*backends {
                SystemBackendAccess::Production { alpm_worker } => {
                    Some(std::sync::Arc::clone(alpm_worker))
                }
                SystemBackendAccess::Isolated => None,
            }
        };
        match alpm_worker {
            Some(worker) => worker.list_updates().await,
            None => state.package_manager.list_updates().await,
        }
    };

    #[cfg(not(feature = "arch"))]
    let updates_result = state.package_manager.list_updates().await;

    // `mut` is only consumed by the arch-gated IgnorePkg filter below.
    #[cfg_attr(not(feature = "arch"), allow(unused_mut))]
    match updates_result {
        Ok(mut updates) => {
            // PARITY: apply the same IgnorePkg filter as the CLI path; a
            // pacman.conf parse failure is an error, mirroring
            // `alpm_ops::get_update_list`.
            #[cfg(feature = "arch")]
            if state
                .system_backends
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_production()
                && state.package_manager.name() == "pacman"
            {
                match crate::core::pacman_conf::PacmanConfig::parse(
                    crate::core::paths::pacman_conf_path(),
                ) {
                    Ok(pacman_config) => {
                        updates =
                            filter_ignored_updates(updates, &pacman_config.ignore_pkg, |update| {
                                update.name.as_str()
                            });
                    }
                    Err(error) => {
                        return internal_error(
                            id,
                            format!("Failed to load update filters from pacman.conf: {error}"),
                        );
                    }
                }
            }

            Response::Success {
                id,
                result: ResponseResult::ListUpdates(
                    updates
                        .into_iter()
                        .map(|update| UpdateEntry {
                            name: update.name,
                            old_version: update.old_version,
                            new_version: update.new_version,
                            repo: update.repo,
                        })
                        .collect(),
                ),
            }
        }
        Err(error) => internal_error(id, format!("Failed to list updates: {error}")),
    }
}

/// Create an internal error response with metrics
#[cold]
#[inline(never)]
fn internal_error(id: RequestId, message: impl Into<String>) -> Response {
    GLOBAL_METRICS.inc_requests_failed();
    Response::Error {
        id,
        code: error_codes::INTERNAL_ERROR,
        message: message.into(),
    }
}

/// Create a not found error response
#[cold]
#[inline(never)]
fn not_found_error(id: RequestId, message: impl Into<String>) -> Response {
    Response::Error {
        id,
        code: error_codes::PACKAGE_NOT_FOUND,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::protocol::PackageInfo;

    fn isolated_state() -> (tempfile::TempDir, Arc<DaemonState>) {
        let directory = tempfile::tempdir().expect("create temporary daemon directory");
        let package_manager: Arc<dyn PackageManager> = Arc::new(
            crate::package_managers::mock::MockPackageManager::new_in("arch", directory.path()),
        );
        let state =
            DaemonState::new_isolated(directory.path(), PackageIndex::empty(), package_manager)
                .expect("create isolated daemon state");
        (directory, Arc::new(state))
    }

    #[tokio::test]
    async fn persisted_status_does_not_restart_memory_ttl() -> anyhow::Result<()> {
        let (directory, initial) = isolated_state();
        let status = super::super::status_policy::status_snapshot(42, 20, 1, 2, vec![], Some(3)).0;
        initial.persistent.set_status(&status)?;
        let state = Arc::new(DaemonState::new_isolated(
            directory.path(),
            PackageIndex::empty(),
            Arc::clone(&initial.package_manager),
        )?);
        assert!(
            state.cache.get_status().is_none(),
            "startup must not reset snapshot age"
        );
        let Response::Success {
            result: ResponseResult::Status(result),
            ..
        } = handle_status(Arc::clone(&state), 81).await
        else {
            panic!("expected cached status")
        };
        assert_eq!(result.total_packages, 42);
        assert!(
            state.cache.get_status().is_none(),
            "disk reads must not reset snapshot age"
        );
        assert!(state.cache.get_explicit_count().is_none());

        std::fs::write(
            directory.path().join("status-cache.json"),
            serde_json::to_vec(&serde_json::json!({"format_version": 1, "status": status}))?,
        )?;
        let Response::Success {
            result: ResponseResult::Status(result),
            ..
        } = handle_status(state, 82).await
        else {
            panic!("expected current backend status")
        };
        assert_eq!(result.total_packages, 0);
        assert!(!result.vulnerabilities_scanned);
        Ok(())
    }

    #[tokio::test]
    async fn persisted_status_honors_configured_zero_ttl() -> anyhow::Result<()> {
        let (_directory, mut state) = isolated_state();
        Arc::get_mut(&mut state).context("unique test state")?.cache =
            PackageCache::new_with_ttls(10, 300, 0);
        let status = super::super::status_policy::status_snapshot(42, 20, 1, 2, vec![], Some(3)).0;
        state.persistent.set_status(&status)?;
        let Response::Success {
            result: ResponseResult::Status(result),
            ..
        } = handle_status(state, 83).await
        else {
            panic!("expected current backend status")
        };
        assert_eq!(result.total_packages, 0);
        assert!(!result.vulnerabilities_scanned);
        Ok(())
    }

    type BackendFuture<'a, T> =
        std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<T>> + Send + 'a>>;

    struct PausedInfoBackend {
        inner: crate::package_managers::mock::MockPackageManager,
        started: tokio::sync::Notify,
        resume: tokio::sync::Notify,
    }

    impl PackageManager for PausedInfoBackend {
        fn name(&self) -> &'static str {
            self.inner.name()
        }
        fn search(&self, query: &str) -> BackendFuture<'_, Vec<crate::core::Package>> {
            self.inner.search(query)
        }
        fn install(&self, packages: &[String]) -> BackendFuture<'_, ()> {
            self.inner.install(packages)
        }
        fn remove(&self, packages: &[String]) -> BackendFuture<'_, ()> {
            self.inner.remove(packages)
        }
        fn update(&self) -> BackendFuture<'_, ()> {
            self.inner.update()
        }
        fn sync(&self) -> BackendFuture<'_, ()> {
            self.inner.sync()
        }
        fn info(&self, package: &str) -> BackendFuture<'_, Option<crate::core::Package>> {
            let lookup = self.inner.info(package);
            Box::pin(async move {
                let result = lookup.await;
                self.started.notify_one();
                self.resume.notified().await;
                result
            })
        }
        fn list_installed(&self) -> BackendFuture<'_, Vec<crate::core::Package>> {
            self.inner.list_installed()
        }
        fn get_status(&self, fast: bool) -> BackendFuture<'_, (usize, usize, usize, usize)> {
            self.inner.get_status(fast)
        }
        fn list_explicit(&self) -> BackendFuture<'_, Vec<String>> {
            self.inner.list_explicit()
        }
        fn list_updates(
            &self,
        ) -> BackendFuture<'_, Vec<crate::package_managers::types::UpdateInfo>> {
            self.inner.list_updates()
        }
        fn is_installed(&self, package: &str) -> BackendFuture<'_, bool> {
            self.inner.is_installed(package)
        }
    }

    #[tokio::test]
    async fn info_fallback_cannot_repopulate_cache_after_index_refresh() {
        for package in ["git", "new-package"] {
            let directory = tempfile::tempdir().expect("temporary daemon directory");
            let backend = Arc::new(PausedInfoBackend {
                inner: crate::package_managers::mock::MockPackageManager::new_in(
                    "arch",
                    directory.path(),
                ),
                started: tokio::sync::Notify::new(),
                resume: tokio::sync::Notify::new(),
            });
            let state = Arc::new(
                DaemonState::new_isolated(directory.path(), PackageIndex::empty(), backend.clone())
                    .expect("isolated daemon"),
            );
            let request_state = state.clone();
            let request = tokio::spawn(async move {
                handle_request(
                    request_state,
                    Request::Info {
                        id: 1,
                        package: package.to_string(),
                    },
                )
                .await
            });
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                backend.started.notified(),
            )
            .await
            .expect("backend lookup started");
            state.replace_index(
                PackageIndex::from_records(&[(package, "99.0", "fresh metadata")]),
                #[cfg(feature = "arch")]
                crate::package_managers::pacman_db::AlpmCatalogEpoch::UNIX_EPOCH,
            );
            backend.resume.notify_one();
            let response = tokio::time::timeout(std::time::Duration::from_secs(5), request)
                .await
                .expect("lookup resumed")
                .expect("lookup task completed");
            if package == "git" {
                assert!(matches!(
                    response,
                    Response::Success {
                        result: ResponseResult::Info(_),
                        ..
                    }
                ));
            } else {
                assert!(matches!(
                    response,
                    Response::Error {
                        code: error_codes::PACKAGE_NOT_FOUND,
                        ..
                    }
                ));
            }
            assert!(
                state.cache.get_info(package).is_none(),
                "stale positive cache for {package}"
            );
            assert!(
                !state.cache.is_info_miss(package),
                "stale negative cache for {package}"
            );
            let current = handle_request(
                state,
                Request::Info {
                    id: 2,
                    package: package.to_string(),
                },
            )
            .await;
            let Response::Success {
                result: ResponseResult::Info(info),
                ..
            } = current
            else {
                panic!("fresh indexed package must be visible, got {current:?}");
            };
            assert_eq!(info.version, "99.0");
        }
    }

    #[test]
    fn refresh_debounce_skips_only_recent_completed_refreshes() {
        let debounce = RefreshDebounce::default();
        let completed_at = std::time::Instant::now();

        assert!(!debounce.should_skip(completed_at, false));
        debounce.record_completion(completed_at);
        assert!(debounce.should_skip(completed_at, false));
        assert!(debounce.should_skip(completed_at + std::time::Duration::from_millis(999), false));
        assert!(!debounce.should_skip(completed_at + REFRESH_DEBOUNCE, false));
        assert!(!debounce.should_skip(completed_at, true));
    }

    #[test]
    fn vulnerability_score_parses_osv_cvss_vectors() {
        assert_eq!(vulnerability_score("7.5"), Some(7.5));
        assert_eq!(
            vulnerability_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Some(9.8)
        );
        assert_eq!(vulnerability_score("not-a-score"), None);
    }

    #[cfg(feature = "arch")]
    #[test]
    fn replacing_index_publishes_its_source_identity() -> anyhow::Result<()> {
        use crate::package_managers::pacman_db::{AlpmCatalogEpoch, LocalDbEpoch, SyncDbEpoch};
        let (directory, state) = isolated_state();
        let epoch = AlpmCatalogEpoch {
            sync: SyncDbEpoch::from_sync_dir(directory.path())?,
            local: LocalDbEpoch::UNIX_EPOCH,
        };
        let previous = state.index.read().expect("snapshot lock");
        let previous_epoch = previous.epoch;
        let previous_index = Arc::clone(&previous.index);
        assert_ne!(previous_epoch, epoch);
        std::thread::scope(|scope| {
            let (ready, started) = std::sync::mpsc::sync_channel(0);
            let state = &state;
            let writer = scope.spawn(move || {
                ready.send(()).expect("reader is waiting");
                state.replace_index(
                    PackageIndex::from_records(&[("fresh", "2", "fresh package")]),
                    epoch,
                )
            });
            started.recv().expect("writer started");
            assert_eq!(previous.epoch, previous_epoch);
            assert!(Arc::ptr_eq(&previous.index, &previous_index));
            drop(previous);
            assert_eq!(writer.join().expect("writer completed"), 1);
        });
        let published = state.index.read().expect("snapshot lock");
        assert!(published.index.get("fresh").is_some());
        assert_eq!(
            published.epoch, epoch,
            "replacement must not expose a new index with the previous identity"
        );
        Ok(())
    }

    #[test]
    fn replacing_index_publishes_snapshot_and_clears_derived_cache() {
        let (_directory, state) = isolated_state();
        state.cache.insert_arc(
            "cached".to_string(),
            Arc::new(vec![PackageInfo {
                name: "stale".to_string(),
                version: "1".to_string(),
                description: String::new(),
                source: WirePackageSource::Official,
            }]),
        );
        assert!(state.cache.get("cached").is_some());
        let stale_snapshot = state.index_snapshot();
        assert_eq!(state.index_generation.load(Ordering::Acquire), 0);

        let replacement = PackageIndex::from_records(&[("fresh", "2", "fresh package")]);
        assert_eq!(
            state.replace_index(
                replacement,
                #[cfg(feature = "arch")]
                crate::package_managers::pacman_db::AlpmCatalogEpoch::UNIX_EPOCH,
            ),
            1
        );
        assert_eq!(state.index_generation.load(Ordering::Acquire), 1);
        let current_snapshot = state.index_snapshot();
        assert!(current_snapshot.get("fresh").is_some());
        assert!(state.cache.get("cached").is_none());
        assert!(!state.with_current_index(&stale_snapshot, || {
            panic!("stale snapshot action must not run");
        }));
        assert!(state.with_current_index(&current_snapshot, || {}));
    }

    #[tokio::test]
    async fn isolated_suggest_uses_the_injected_index() {
        let directory = tempfile::tempdir().expect("create isolated suggest directory");
        let package_manager: Arc<dyn PackageManager> = Arc::new(
            crate::package_managers::mock::MockPackageManager::new_in("arch", directory.path()),
        );
        let index = PackageIndex::from_records(&[("firefox", "1.0", "web browser")]);
        let state = Arc::new(
            DaemonState::new_isolated(directory.path(), index, package_manager)
                .expect("create isolated daemon state"),
        );

        let response = handle_request(
            state,
            Request::Suggest {
                id: 7,
                query: "fire".to_string(),
                limit: Some(5),
            },
        )
        .await;
        let Response::Success {
            result: ResponseResult::Suggest(names),
            ..
        } = response
        else {
            panic!("isolated suggest must succeed, got {response:?}");
        };
        assert!(names.iter().any(|name| name == "firefox"), "got {names:?}");
    }

    #[tokio::test]
    async fn debian_search_cache_preserves_results_for_larger_limits() {
        let directory = tempfile::tempdir().expect("create isolated search directory");
        let package_manager: Arc<dyn PackageManager> = Arc::new(
            crate::package_managers::mock::MockPackageManager::new_in("arch", directory.path()),
        );
        let index = PackageIndex::from_records(&[
            ("pkg-alpha", "1.0", "alpha"),
            ("pkg-beta", "1.0", "beta"),
            ("pkg-gamma", "1.0", "gamma"),
        ]);
        let state = Arc::new(
            DaemonState::new_isolated(directory.path(), index, package_manager)
                .expect("create isolated daemon state"),
        );

        let request = |id, limit| Request::DebianSearch {
            id,
            query: "pkg".to_string(),
            limit: Some(limit),
        };
        let first = handle_request(state.clone(), request(1, 1)).await;
        let second = handle_request(state, request(2, 3)).await;

        let Response::Success {
            result: ResponseResult::DebianSearch(first),
            ..
        } = first
        else {
            panic!("first Debian search must succeed");
        };
        let Response::Success {
            result: ResponseResult::DebianSearch(second),
            ..
        } = second
        else {
            panic!("second Debian search must succeed");
        };

        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 3);
    }

    #[tokio::test]
    async fn refresh_index_rejects_isolated_daemons() {
        let (_directory, state) = isolated_state();
        let response = handle_request(state, Request::RefreshIndex { id: 41 }).await;
        assert!(matches!(
            response,
            Response::Error {
                id: 41,
                code: error_codes::INVALID_PARAMS,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn isolated_queries_use_the_injected_package_manager() {
        let directory = tempfile::tempdir().expect("create temporary package state");
        let package_manager = Arc::new(crate::package_managers::mock::MockPackageManager::new_in(
            "arch",
            directory.path(),
        ));
        package_manager
            .install(&["firefox".to_string()])
            .await
            .expect("seed isolated package state");
        let state =
            DaemonState::new_isolated(directory.path(), PackageIndex::empty(), package_manager)
                .expect("create isolated daemon state");

        assert_eq!(
            state.status_counts().await.expect("status counts"),
            (1, 1, 0, 0)
        );
        assert_eq!(
            state.explicit_packages().await.expect("explicit packages"),
            vec!["firefox".to_string()]
        );
    }

    #[cfg(not(feature = "arch"))]
    #[tokio::test]
    async fn production_queries_use_the_selected_backend() {
        for distro in ["fedora", "macos"] {
            let directory = tempfile::tempdir().unwrap();
            let manager = Arc::new(crate::package_managers::mock::MockPackageManager::new_in(
                distro,
                directory.path(),
            ));
            manager.install(&["git".into()]).await.unwrap();
            let mut state =
                DaemonState::new_isolated(directory.path(), PackageIndex::empty(), manager)
                    .unwrap();
            state.system_backends = RwLock::new(SystemBackendAccess::Production {});
            assert_eq!(state.status_counts().await.unwrap(), (1, 1, 0, 0));
            assert_eq!(state.explicit_packages().await.unwrap(), vec!["git"]);
        }
    }

    #[tokio::test]
    async fn backend_status_errors_do_not_become_healthy_counts() {
        let directory = tempfile::tempdir().unwrap();
        let manager = Arc::new(crate::package_managers::mock::MockPackageManager::new_in(
            "fedora",
            directory.path(),
        ));
        let state =
            DaemonState::new_isolated(directory.path(), PackageIndex::empty(), manager).unwrap();
        std::fs::write(
            directory.path().join("mock_state_dnf.json"),
            b"invalid json",
        )
        .unwrap();
        assert!(state.status_counts().await.is_err());
    }

    #[tokio::test]
    async fn backend_inventory_errors_do_not_become_empty_lists() {
        let directory = tempfile::tempdir().unwrap();
        let manager = Arc::new(crate::package_managers::mock::MockPackageManager::new_in(
            "macos",
            directory.path(),
        ));
        let state =
            DaemonState::new_isolated(directory.path(), PackageIndex::empty(), manager).unwrap();
        std::fs::write(
            directory.path().join("mock_state_homebrew.json"),
            b"invalid json",
        )
        .unwrap();
        assert!(state.explicit_packages().await.is_err());
    }

    #[cfg(feature = "arch")]
    fn update_entry(name: &str) -> UpdateEntry {
        UpdateEntry {
            name: name.to_string(),
            old_version: "1.0".to_string(),
            new_version: "2.0".to_string(),
            repo: "core".to_string(),
        }
    }

    /// PARITY: the daemon's update list must exclude pacman.conf IgnorePkg
    /// names exactly like the CLI path (`should_ignore()` at the ALPM source).
    #[test]
    #[cfg(feature = "arch")]
    fn update_list_filters_ignored_packages_like_the_cli() {
        let ignored = vec!["linux".to_string(), "linux-lts".to_string()];
        let updates = vec![
            update_entry("linux"),
            update_entry("firefox"),
            update_entry("linux-lts"),
            update_entry("git"),
        ];

        let kept = filter_ignored_updates(updates, &ignored, |update| update.name.as_str());
        let names: Vec<&str> = kept.iter().map(|update| update.name.as_str()).collect();
        assert_eq!(names, ["firefox", "git"]);
    }

    #[test]
    #[cfg(feature = "arch")]
    fn update_list_without_ignores_is_passed_through() {
        let updates = vec![update_entry("firefox"), update_entry("linux")];
        let kept = filter_ignored_updates(updates, &[], |update| update.name.as_str());
        assert_eq!(kept.len(), 2);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn health_reports_resident_memory_from_procfs() {
        let rss_mb = process_rss_mb().expect("VmRSS must be readable on Linux");
        assert!(rss_mb > 0, "a running test process has non-zero RSS");
    }
}

#[cfg(all(test, unix))]
#[path = "audit_transport_tests.rs"]
mod audit_transport_tests;
