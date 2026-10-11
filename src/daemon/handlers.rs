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
use crate::package_managers::{
    InstalledCatalogObservation, PackageManager, VersionDisplay, get_package_manager,
};
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
const CATALOG_OBSERVATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

async fn observe_installed_catalog(
    manager: Arc<dyn PackageManager>,
    budget: Arc<tokio::sync::Semaphore>,
) -> anyhow::Result<Option<Arc<dyn InstalledCatalogObservation>>> {
    tokio::time::timeout(CATALOG_OBSERVATION_TIMEOUT, async move {
        let permit = budget.acquire_owned().await?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            manager.installed_catalog_observation()
        })
        .await
        .context("Installed catalog observation task failed")?
    })
    .await
    .context("Installed catalog observation exceeded its deadline")?
}

async fn installed_catalog_is_current(
    observation: Arc<dyn InstalledCatalogObservation>,
    budget: Arc<tokio::sync::Semaphore>,
) -> anyhow::Result<bool> {
    tokio::time::timeout(CATALOG_OBSERVATION_TIMEOUT, async move {
        let permit = budget.acquire_owned().await?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            observation.is_current()
        })
        .await
        .context("Installed catalog check task failed")?
    })
    .await
    .context("Installed catalog check exceeded its deadline")?
}

async fn load_observed_index(
    manager: Arc<dyn PackageManager>,
    budget: Arc<tokio::sync::Semaphore>,
) -> anyhow::Result<(PackageIndex, Option<Arc<dyn InstalledCatalogObservation>>)> {
    for _ in 0..3 {
        let observation =
            observe_installed_catalog(Arc::clone(&manager), Arc::clone(&budget)).await?;
        let index = PackageIndex::for_package_manager(Arc::clone(&manager)).await?;
        if let Some(observation) = &observation
            && !installed_catalog_is_current(Arc::clone(observation), Arc::clone(&budget)).await?
        {
            continue;
        }
        return Ok((index, observation));
    }
    anyhow::bail!("Installed inventory changed during three package index rebuild attempts")
}

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
        alpm_worker: Option<std::sync::Arc<AlpmWorker>>,
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
            alpm_worker: if crate::package_managers::resolve_backend()?
                == crate::package_managers::Backend::Arch
            {
                Some(std::sync::Arc::new(AlpmWorker::new()?))
            } else {
                None
            },
        })
    }

    fn is_production(&self) -> bool {
        matches!(self, Self::Production { .. })
    }

    fn retire(self) {
        #[cfg(feature = "arch")]
        if let Self::Production {
            alpm_worker: Some(alpm_worker),
        } = self
        {
            retire_alpm_worker(alpm_worker, pause_native_retirement);
        }
        #[cfg(not(feature = "arch"))]
        let _ = self;
    }

    #[cfg(feature = "arch")]
    fn has_alpm_worker(&self) -> bool {
        matches!(
            self,
            Self::Production {
                alpm_worker: Some(_)
            }
        )
    }
}

#[cfg(feature = "arch")]
fn pause_native_retirement() {
    std::thread::sleep(std::time::Duration::from_millis(1));
}

#[cfg(feature = "arch")]
fn retire_alpm_worker(alpm_worker: Arc<AlpmWorker>, mut wait_for_lease: impl FnMut()) {
    let mut retained = alpm_worker;
    loop {
        match Arc::try_unwrap(retained) {
            Ok(worker) => {
                drop(worker);
                break;
            }
            Err(shared) => {
                // Retain the final owner so an async request releasing its
                // lease cannot inherit the native thread's blocking join.
                retained = shared;
                wait_for_lease();
            }
        }
    }
}

/// Index contents and their source observation are one publication unit.
struct PublishedIndex {
    index: Arc<PackageIndex>,
    installed_observation: Option<Arc<dyn InstalledCatalogObservation>>,
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
    system_backends: Arc<RwLock<SystemBackendAccess>>,
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
    catalog_observation_budget: Arc<tokio::sync::Semaphore>,
    native_tasks: tokio_util::task::TaskTracker,
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
    #[cfg(test)]
    pub(super) fn replace_index(
        &self,
        index: PackageIndex,
        #[cfg(feature = "arch")] epoch: crate::package_managers::pacman_db::AlpmCatalogEpoch,
    ) -> usize {
        self.replace_observed_index(
            index,
            None,
            #[cfg(feature = "arch")]
            epoch,
        )
    }

    fn replace_observed_index(
        &self,
        index: PackageIndex,
        installed_observation: Option<Arc<dyn InstalledCatalogObservation>>,
        #[cfg(feature = "arch")] epoch: crate::package_managers::pacman_db::AlpmCatalogEpoch,
    ) -> usize {
        let package_count = index.len();
        let mut current = self
            .index
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *current = PublishedIndex {
            index: Arc::new(index),
            installed_observation,
            #[cfg(feature = "arch")]
            epoch,
        };
        self.index_generation.fetch_add(1, Ordering::Release);
        self.cache.clear();
        self.persistent.invalidate_status();
        package_count
    }

    /// Swap in freshly constructed system backends so libalpm reloads the
    /// sync databases from disk. Called by RefreshIndex (after `omg sync`):
    /// without this, a worker created before the sync serves its frozen
    /// in-memory update list until daemon restart.
    async fn refresh_system_backends(
        &self,
        refresh_guard: tokio::sync::OwnedMutexGuard<()>,
        #[cfg(feature = "arch")] expected_epoch: Option<
            crate::package_managers::pacman_db::AlpmCatalogEpoch,
        >,
    ) -> anyhow::Result<tokio::sync::OwnedMutexGuard<()>> {
        anyhow::ensure!(
            !self.native_tasks.is_closed(),
            "Native backends are shutting down"
        );
        if !self.uses_production_backends() {
            return Ok(refresh_guard);
        }
        let backends = Arc::clone(&self.system_backends);
        let lifecycle = self.native_tasks.clone();
        self.native_tasks
            .spawn_blocking(move || {
                // This task owns serialization even if its awaiting request is
                // cancelled during uninterruptible native initialization/retirement.
                let replacement = SystemBackendAccess::production()?;
                anyhow::ensure!(!lifecycle.is_closed(), "Native backends are shutting down");
                #[cfg(feature = "arch")]
                if let Some(epoch) = expected_epoch {
                    epoch.ensure_unchanged(
                        crate::package_managers::pacman_db::AlpmCatalogEpoch::observe()?,
                    )?;
                }
                let retired = {
                    let mut current = backends
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    std::mem::replace(&mut *current, replacement)
                };
                retired.retire();
                Ok(refresh_guard)
            })
            .await
            .context("Native backend refresh task panicked")?
    }

    pub(super) async fn drain_native_backends(
        &self,
        deadline: std::time::Duration,
    ) -> anyhow::Result<()> {
        self.native_tasks.close();
        if !self.uses_production_backends() && self.native_tasks.is_empty() {
            return Ok(());
        }
        tokio::time::timeout(deadline, async {
            let refresh_guard = Arc::clone(&self.refresh_lock).lock_owned().await;
            let backends = Arc::clone(&self.system_backends);
            self.native_tasks.spawn_blocking(move || {
                let retired = {
                    let mut current = backends.write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    std::mem::replace(&mut *current, SystemBackendAccess::Isolated)
                };
                retired.retire();
                drop(refresh_guard);
            }).await.context("Native backend retirement task panicked")?;
            self.native_tasks.wait().await;
            anyhow::Ok(())
        }).await.context(
            "Native backend shutdown exceeded its deadline; uninterruptible native work may still be running"
        )?
    }

    fn uses_production_backends(&self) -> bool {
        self.system_backends
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_production()
    }

    /// Rebuild the published index and reincarnate libalpm while owning refresh
    /// serialization through native work and index publication.
    async fn rebuild_production_index(
        &self,
        refresh_guard: tokio::sync::OwnedMutexGuard<()>,
    ) -> anyhow::Result<usize> {
        #[cfg(feature = "arch")]
        let arch_backend = self
            .system_backends
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .has_alpm_worker();
        #[cfg(feature = "arch")]
        let epoch = if arch_backend {
            crate::package_managers::pacman_db::AlpmCatalogEpoch::observe()
                .context("Failed to observe ALPM catalog before index rebuild")?
        } else {
            crate::package_managers::pacman_db::AlpmCatalogEpoch::UNIX_EPOCH
        };
        let (index, installed_observation) = load_observed_index(
            Arc::clone(&self.package_manager),
            Arc::clone(&self.catalog_observation_budget),
        )
        .await?;
        let _refresh_guard = self
            .refresh_system_backends(
                refresh_guard,
                #[cfg(feature = "arch")]
                arch_backend.then_some(epoch),
            )
            .await?;
        #[cfg(feature = "arch")]
        if arch_backend {
            epoch.ensure_unchanged(
                crate::package_managers::pacman_db::AlpmCatalogEpoch::observe()
                    .context("Failed to observe ALPM catalog after index and backend rebuild")?,
            )?;
        }
        if let Some(observation) = &installed_observation {
            anyhow::ensure!(
                installed_catalog_is_current(
                    Arc::clone(observation),
                    Arc::clone(&self.catalog_observation_budget)
                )
                .await?,
                "Installed inventory changed before package index publication"
            );
        }
        let packages = self.replace_observed_index(
            index,
            installed_observation,
            #[cfg(feature = "arch")]
            epoch,
        );
        Ok(packages)
    }

    async fn installed_catalog_needs_heal(&self) -> anyhow::Result<bool> {
        let observation = self
            .index
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .installed_observation
            .clone();
        match observation {
            Some(observation) => Ok(!installed_catalog_is_current(
                observation,
                Arc::clone(&self.catalog_observation_budget),
            )
            .await?),
            None => Ok(observe_installed_catalog(
                Arc::clone(&self.package_manager),
                Arc::clone(&self.catalog_observation_budget),
            )
            .await?
            .is_some()),
        }
    }

    /// RPM observation covers installed rows. Repository changes are admitted
    /// by explicit refresh, since RPM alone cannot certify repository freshness.
    async fn heal_installed_catalog_if_changed(&self) -> anyhow::Result<()> {
        if !self.uses_production_backends() || self.package_manager.name() != "dnf" {
            return Ok(());
        }
        if !self.installed_catalog_needs_heal().await? {
            return Ok(());
        }
        let guard = Arc::clone(&self.refresh_lock).lock_owned().await;
        if !self.installed_catalog_needs_heal().await? {
            return Ok(());
        }
        self.rebuild_production_index(guard).await?;
        Ok(())
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
        let refresh_guard = Arc::clone(&self.refresh_lock).lock_owned().await;
        if !self.catalog_needs_heal() {
            return Ok(());
        }
        self.rebuild_production_index(refresh_guard).await?;
        Ok(())
    }

    #[cfg(feature = "arch")]
    fn catalog_needs_heal(&self) -> bool {
        if !self
            .system_backends
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .has_alpm_worker()
        {
            return false;
        }
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
        let selected_backend = crate::package_managers::resolve_backend()?;
        let data_dir = crate::core::paths::daemon_data_dir();
        let persistent = Self::open_persistent_cache(&data_dir)?;
        let package_manager = get_package_manager()?;
        let load_catalog = || -> anyhow::Result<_> {
            let (index, observation) = if package_manager.name() == "dnf" {
                let manager = Arc::clone(&package_manager);
                std::thread::Builder::new()
                    .name("omg-catalog-init".into())
                    .spawn(move || {
                        let runtime = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()?;
                        runtime.block_on(load_observed_index(
                            manager,
                            Arc::new(tokio::sync::Semaphore::new(1)),
                        ))
                    })?
                    .join()
                    .map_err(|_| {
                        anyhow::anyhow!("Package catalog initialization worker panicked")
                    })??
            } else {
                (PackageIndex::for_package_manager_blocking(Arc::clone(&package_manager))
                    .context("Failed to build package index. Ensure package databases are synced (run 'omg sync').")?, None)
            };
            Ok((index, SystemBackendAccess::production()?, observation))
        };
        #[cfg(feature = "arch")]
        let ((index, system_backends, installed_observation), index_epoch) =
            if selected_backend == crate::package_managers::Backend::Arch {
                crate::package_managers::pacman_db::AlpmCatalogEpoch::load_stable(
                    crate::package_managers::pacman_db::AlpmCatalogEpoch::observe,
                    load_catalog,
                )?
            } else {
                (
                    load_catalog()?,
                    crate::package_managers::pacman_db::AlpmCatalogEpoch::UNIX_EPOCH,
                )
            };
        #[cfg(not(feature = "arch"))]
        let _ = selected_backend;
        #[cfg(not(feature = "arch"))]
        let (index, system_backends, installed_observation) = load_catalog()?;

        Ok(Self::from_index(
            crate::core::paths::data_dir(),
            persistent,
            index,
            package_manager,
            system_backends,
            installed_observation,
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
            None,
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
        installed_observation: Option<Arc<dyn InstalledCatalogObservation>>,
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
        if system_backends.is_production()
            && !crate::core::paths::test_mode()
            && package_manager.name() == "apt"
        {
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
                installed_observation,
                #[cfg(feature = "arch")]
                epoch: index_epoch,
            }),
            vulnerability_scanner: Arc::new(
                crate::core::security::vulnerability::VulnerabilityScanner::new(),
            ),
            security_scan_lock: tokio::sync::Mutex::new(()),
            background_security_scans,
            system_backends: Arc::new(RwLock::new(system_backends)),
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
            catalog_observation_budget: Arc::new(tokio::sync::Semaphore::new(1)),
            native_tasks: tokio_util::task::TaskTracker::new(),
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

    if let Request::Search { query, .. } | Request::Suggest { query, .. } = &request {
        if query.len() > MAX_QUERY_LENGTH {
            let message = match &request {
                Request::Suggest { .. } => "Query too long".to_string(),
                _ => format!("Query too long (max {MAX_QUERY_LENGTH} characters)"),
            };
            return validation_error(request.id(), message);
        }
        if let Err(error) = state.heal_installed_catalog_if_changed().await {
            return internal_error(
                request.id(),
                format!("Failed to refresh stale installed package index: {error:#}"),
            );
        }
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
    let refresh_guard = Arc::clone(&state.refresh_lock).lock_owned().await;
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
        && state.package_manager.name() != "dnf"
    {
        if let Err(error) = state
            .refresh_system_backends(
                refresh_guard,
                #[cfg(feature = "arch")]
                None,
            )
            .await
        {
            return internal_error(id, format!("Failed to refresh package backends: {error:#}"));
        }
        let packages = state.index_snapshot().len();
        tracing::debug!(packages, "Debounced recent package index refresh");
        return Response::Success {
            id,
            result: ResponseResult::IndexRefreshed { packages },
        };
    }

    let packages = match state.rebuild_production_index(refresh_guard).await {
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
/// Failed request threshold for "unhealthy" health status. Compared against
/// failures in the trailing `FAILURE_HEALTH_WINDOW_MS` window, not the
/// lifetime total, so a long-lived daemon recovers once failures stop.
const HEALTH_UNHEALTHY_FAILURES_THRESHOLD: u64 = 1000;

/// Pure health-status decision, split out from [`handle_health`] so the
/// thresholds are testable without a live daemon.
fn health_status(cache_size: usize, recent_failures: u64) -> &'static str {
    if cache_size > HEALTH_UNHEALTHY_CACHE_THRESHOLD
        || recent_failures > HEALTH_UNHEALTHY_FAILURES_THRESHOLD
    {
        "unhealthy"
    } else if cache_size > HEALTH_DEGRADED_CACHE_THRESHOLD {
        "degraded"
    } else {
        "healthy"
    }
}

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
    let validate_generic =
        || crate::core::security::validate_package_name(&package).map_err(anyhow::Error::from);
    #[cfg(feature = "fedora")]
    let validation = if state.package_manager.name() == "dnf" {
        crate::package_managers::DnfPackageManager::validate_query_selector(&package)
    } else {
        validate_generic()
    };
    #[cfg(not(feature = "fedora"))]
    let validation = validate_generic();
    if let Err(e) = validation {
        return validation_error(id, format!("Invalid package name: {e}"));
    }

    // DNF resolves installed architecture/build ambiguity against its current RPM
    // snapshot. Repository records and name-keyed daemon caches cannot own that
    // selection, including a canonical name cached by a prior full NEVRA query.
    let cache_info = state.package_manager.name() != "dnf";

    // 1. Check cache first (Arc clone is cheap - just pointer copy)
    if cache_info && let Some(cached) = state.cache.get_info(&package) {
        // METRICS: Cache hit
        GLOBAL_METRICS.inc_cache_hits();
        return Response::Success {
            id,
            result: ResponseResult::Info(Arc::unwrap_or_clone(cached)),
        };
    }

    if cache_info && state.cache.is_info_miss(&package) {
        return not_found_error(id, format!("Package not found: {package}"));
    }

    // METRICS: Cache miss - will fetch package info
    GLOBAL_METRICS.inc_cache_misses();

    // 2. Try official index (instant hash lookup).
    let index = state.index_snapshot();
    if cache_info && let Some(pkg) = index.get(&package) {
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
                repo: if cache_info {
                    String::new()
                } else {
                    "official".into()
                },
                depends: Vec::new(),
                licenses: Vec::new(),
                source: WirePackageSource::Official,
            });
            if cache_info {
                state.with_current_index(&index, || {
                    state.cache.insert_info_arc(Arc::clone(&detailed));
                });
            }
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
    if cache_info
        && state
            .system_backends
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .has_alpm_worker()
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

    if cache_info {
        state.with_current_index(&index, || {
            state.cache.insert_info_miss(&package);
        });
    }

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

    let index = state.index_snapshot();
    let packages_result = state.explicit_packages().await;

    match packages_result {
        Ok(packages) => {
            let packages_arc = Arc::new(packages);
            state.with_current_index(&index, || {
                state.cache.update_explicit_arc(Arc::clone(&packages_arc));
            });
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

    let index = state.index_snapshot();
    let count_result = state
        .explicit_packages()
        .await
        .map(|packages| packages.len());

    match count_result {
        Ok(count) => {
            state.with_current_index(&index, || {
                state.cache.update_explicit_count(count);
            });
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
    let recent_failures = GLOBAL_METRICS.recent_request_failures();

    let memory_usage_mb = process_rss_mb().unwrap_or(0);

    let status = health_status(cache_size, recent_failures).to_string();

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
                    alpm_worker.as_ref().map(std::sync::Arc::clone)
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
                .has_alpm_worker()
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
    async fn explicit_cache_survives_backend_failure_until_cleared() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let backend = Arc::new(crate::package_managers::mock::MockPackageManager::new_in(
            "arch",
            directory.path(),
        ));
        backend.set_installed_version("cached-package", "1")?;
        let state = Arc::new(DaemonState::new_isolated(
            directory.path(),
            PackageIndex::empty(),
            backend,
        )?);
        let Response::Success {
            id: 91,
            result: ResponseResult::Explicit(result),
        } = handle_request(Arc::clone(&state), Request::Explicit { id: 91 }).await
        else {
            anyhow::bail!("cold explicit lookup must succeed")
        };
        assert_eq!(result.packages, ["cached-package"]);

        let inventory = directory.path().join("mock_state_pacman.json");
        let broken = b"{invalid mock state";
        std::fs::write(&inventory, broken)?;
        let Response::Success {
            id: 92,
            result: ResponseResult::Explicit(result),
        } = handle_request(Arc::clone(&state), Request::Explicit { id: 92 }).await
        else {
            anyhow::bail!("warm explicit lookup must use the cached snapshot")
        };
        assert_eq!(result.packages, ["cached-package"]);
        assert_eq!(std::fs::read(&inventory)?, broken);

        assert!(matches!(
            handle_request(Arc::clone(&state), Request::CacheClear { id: 93 }).await,
            Response::Success {
                id: 93,
                result: ResponseResult::Message(message),
            } if message == "cleared"
        ));
        let Response::Error {
            id: 94,
            code: error_codes::INTERNAL_ERROR,
            message,
        } = handle_request(state, Request::Explicit { id: 94 }).await
        else {
            anyhow::bail!("cache clear must expose the backend failure")
        };
        assert!(message.contains("Failed to list explicit packages:"));
        assert!(message.contains("failed to parse mock state"));
        assert_eq!(std::fs::read(&inventory)?, broken);
        Ok(())
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

    enum InfoReply {
        Found(crate::core::Package),
        Failed(&'static str),
    }

    struct InfoSelectionBackend {
        inner: crate::package_managers::mock::MockPackageManager,
        backend_name: &'static str,
        replies: std::collections::HashMap<&'static str, InfoReply>,
        catalog_revision: Option<Arc<AtomicU64>>,
        catalog_builds: Arc<AtomicU64>,
        catalog_gate: Option<Arc<(tokio::sync::Notify, tokio::sync::Notify)>>,
        catalog_fault: Arc<AtomicU64>,
    }

    struct MutableCatalogObservation {
        revision: Arc<AtomicU64>,
        observed: u64,
        fault: Arc<AtomicU64>,
    }

    impl InstalledCatalogObservation for MutableCatalogObservation {
        fn is_current(&self) -> anyhow::Result<bool> {
            anyhow::ensure!(
                self.fault.load(Ordering::Acquire) != 1,
                "inventory unreadable"
            );
            Ok(self.revision.load(Ordering::Acquire) == self.observed)
        }
    }

    impl PackageManager for InfoSelectionBackend {
        fn installed_catalog_observation(
            &self,
        ) -> anyhow::Result<Option<Arc<dyn InstalledCatalogObservation>>> {
            anyhow::ensure!(
                self.catalog_fault.load(Ordering::Acquire) != 1,
                "inventory unreadable"
            );
            Ok(self.catalog_revision.as_ref().map(|revision| {
                Arc::new(MutableCatalogObservation {
                    revision: Arc::clone(revision),
                    observed: revision.load(Ordering::Acquire),
                    fault: Arc::clone(&self.catalog_fault),
                }) as Arc<dyn InstalledCatalogObservation>
            }))
        }
        fn name(&self) -> &'static str {
            self.backend_name
        }
        fn search(&self, query: &str) -> BackendFuture<'_, Vec<crate::core::Package>> {
            self.inner.search(query)
        }
        fn package_index(&self) -> BackendFuture<'_, Vec<crate::core::Package>> {
            Box::pin(async move {
                let previous = self.catalog_builds.fetch_add(1, Ordering::AcqRel);
                let packages = self.inner.search("").await?;
                if previous == 0
                    && let Some(gate) = &self.catalog_gate
                {
                    gate.0.notify_one();
                    gate.1.notified().await;
                }
                if self.catalog_fault.load(Ordering::Acquire) == 2
                    && let Some(revision) = &self.catalog_revision
                {
                    revision.fetch_add(1, Ordering::AcqRel);
                }
                Ok(packages)
            })
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
            let result = match self.replies.get(package) {
                Some(InfoReply::Found(info)) => Ok(Some(info.clone())),
                Some(InfoReply::Failed(message)) => Err(anyhow::anyhow!("{message}")),
                None => Ok(None),
            };
            Box::pin(async move { result })
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

    fn installed_info(name: &str, version: &str) -> crate::core::Package {
        crate::core::Package {
            name: name.into(),
            version: crate::package_managers::types::parse_version(version)
                .expect("backend info fixture version must parse"),
            description: "Installed RPM metadata".into(),
            source: crate::core::PackageSource::Official,
            installed: true,
        }
    }

    fn info_selection_state(
        backend_name: &'static str,
        records: &[(&str, &str, &str)],
        replies: impl IntoIterator<Item = (&'static str, InfoReply)>,
    ) -> anyhow::Result<(tempfile::TempDir, Arc<DaemonState>)> {
        for (_, version, _) in records {
            crate::package_managers::types::parse_version(version)
                .expect("index info fixture version must parse");
        }
        let directory = tempfile::tempdir()?;
        let backend = InfoSelectionBackend {
            inner: crate::package_managers::mock::MockPackageManager::new_in(
                "arch",
                directory.path(),
            ),
            backend_name,
            replies: replies.into_iter().collect(),
            catalog_revision: None,
            catalog_builds: Arc::new(AtomicU64::new(0)),
            catalog_gate: None,
            catalog_fault: Arc::new(AtomicU64::new(0)),
        };
        let state = DaemonState::new_isolated(
            directory.path(),
            PackageIndex::from_records(records),
            Arc::new(backend),
        )?;
        Ok((directory, Arc::new(state)))
    }

    #[cfg(feature = "fedora")]
    fn mutable_fedora_catalog(
        observe: bool,
        gate: Option<Arc<(tokio::sync::Notify, tokio::sync::Notify)>>,
    ) -> anyhow::Result<(
        tempfile::TempDir,
        Arc<DaemonState>,
        crate::package_managers::mock::MockPackageDb,
        Arc<AtomicU64>,
        Arc<AtomicU64>,
        Arc<AtomicU64>,
    )> {
        let directory = tempfile::tempdir()?;
        let inner =
            crate::package_managers::mock::MockPackageManager::new_in("fedora", directory.path());
        let database = inner.db.clone();
        database.packages.lock().unwrap().clear();
        database.add_package("retired-tool.x86_64", "1.0-1", "Before", "fedora");
        let revision = Arc::new(AtomicU64::new(0));
        let builds = Arc::new(AtomicU64::new(0));
        let fault = Arc::new(AtomicU64::new(0));
        let backend = InfoSelectionBackend {
            inner,
            backend_name: "dnf",
            replies: std::collections::HashMap::new(),
            catalog_revision: observe.then(|| Arc::clone(&revision)),
            catalog_builds: Arc::clone(&builds),
            catalog_gate: gate,
            catalog_fault: Arc::clone(&fault),
        };
        let state = DaemonState::new_isolated(
            directory.path(),
            PackageIndex::from_records(&[("retired-tool.x86_64", "1.0-1", "Before")]),
            Arc::new(backend),
        )?;
        *state.system_backends.write().unwrap() = SystemBackendAccess::Production {
            #[cfg(feature = "arch")]
            alpm_worker: None,
        };
        Ok((
            directory,
            Arc::new(state),
            database,
            revision,
            builds,
            fault,
        ))
    }

    #[cfg(feature = "fedora")]
    #[tokio::test]
    async fn fedora_catalog_search_observes_external_update_and_removal() -> anyhow::Result<()> {
        let (_directory, state, database, revision, _, _) = mutable_fedora_catalog(true, None)?;
        let search = |query: &str| Request::Search {
            id: 1,
            query: query.into(),
            limit: Some(10),
        };
        let Response::Success {
            result: ResponseResult::Search(before),
            ..
        } = handle_request(Arc::clone(&state), search("retired-tool")).await
        else {
            panic!("initial search failed")
        };
        assert_eq!(
            (
                before.packages[0].name.as_str(),
                before.packages[0].version.as_str()
            ),
            ("retired-tool.x86_64", "1.0-1")
        );
        database.add_package("retired-tool.x86_64", "2.0-1", "After", "fedora");
        revision.fetch_add(1, Ordering::AcqRel);
        let Response::Success {
            result: ResponseResult::Search(updated),
            ..
        } = handle_request(Arc::clone(&state), search("retired-tool")).await
        else {
            panic!("updated search failed")
        };
        assert_eq!(
            (
                updated.packages[0].name.as_str(),
                updated.packages[0].version.as_str(),
                updated.packages[0].description.as_str()
            ),
            ("retired-tool.x86_64", "2.0-1", "After")
        );
        database.packages.lock().unwrap().clear();
        database.add_package("replacement-tool.x86_64", "3.0-1", "Replacement", "fedora");
        revision.fetch_add(1, Ordering::AcqRel);
        let Response::Success {
            result: ResponseResult::Search(removed),
            ..
        } = handle_request(Arc::clone(&state), search("retired-tool")).await
        else {
            panic!("removed search failed")
        };
        assert_eq!(removed.total, 0);
        let Response::Success {
            result: ResponseResult::Search(replacement),
            ..
        } = handle_request(state, search("replacement-tool")).await
        else {
            panic!("replacement search failed")
        };
        assert_eq!(
            (
                replacement.packages[0].name.as_str(),
                replacement.packages[0].version.as_str()
            ),
            ("replacement-tool.x86_64", "3.0-1")
        );
        Ok(())
    }

    #[cfg(feature = "fedora")]
    #[tokio::test]
    async fn fedora_catalog_suggest_observes_external_removal() -> anyhow::Result<()> {
        let (_directory, state, database, revision, _, _) = mutable_fedora_catalog(true, None)?;
        let suggest = |query: &str| Request::Suggest {
            id: 1,
            query: query.into(),
            limit: Some(10),
        };
        let Response::Success {
            result: ResponseResult::Suggest(before),
            ..
        } = handle_request(Arc::clone(&state), suggest("retired-tool")).await
        else {
            panic!("initial suggest failed")
        };
        assert_eq!(before, ["retired-tool.x86_64"]);
        database.packages.lock().unwrap().clear();
        database.add_package("replacement-tool.x86_64", "2.0-1", "Replacement", "fedora");
        revision.fetch_add(1, Ordering::AcqRel);
        let Response::Success {
            result: ResponseResult::Suggest(after),
            ..
        } = handle_request(Arc::clone(&state), suggest("retired-tool")).await
        else {
            panic!("removed suggest failed")
        };
        assert_eq!(after, Vec::<String>::new());
        let Response::Success {
            result: ResponseResult::Suggest(replacement),
            ..
        } = handle_request(state, suggest("replacement-tool")).await
        else {
            panic!("replacement suggest failed")
        };
        assert_eq!(replacement, ["replacement-tool.x86_64"]);
        Ok(())
    }

    #[cfg(feature = "fedora")]
    #[tokio::test]
    async fn fedora_catalog_sequential_refresh_does_not_acknowledge_an_old_catalog()
    -> anyhow::Result<()> {
        for observe in [true, false] {
            let (_directory, state, database, revision, _, _) =
                mutable_fedora_catalog(observe, None)?;
            assert!(matches!(
                handle_request(Arc::clone(&state), Request::RefreshIndex { id: 1 }).await,
                Response::Success {
                    result: ResponseResult::IndexRefreshed { packages: 1 },
                    ..
                }
            ));
            database.packages.lock().unwrap().clear();
            database.add_package("replacement-tool.x86_64", "2.0-1", "Replacement", "fedora");
            database.add_package("new-dependency.noarch", "1.0-1", "Dependency", "fedora");
            revision.fetch_add(1, Ordering::AcqRel);
            let response =
                handle_request(Arc::clone(&state), Request::RefreshIndex { id: 2 }).await;
            assert!(
                matches!(
                    response,
                    Response::Success {
                        result: ResponseResult::IndexRefreshed { packages: 2 },
                        ..
                    }
                ),
                "second sequential refresh must publish both current packages: {response:?}, observation={observe}"
            );
            let Response::Success {
                result: ResponseResult::Search(current),
                ..
            } = handle_request(
                state,
                Request::Search {
                    id: 3,
                    query: "replacement-tool".into(),
                    limit: None,
                },
            )
            .await
            else {
                panic!("refreshed search failed")
            };
            assert_eq!(
                (
                    current.packages[0].name.as_str(),
                    current.packages[0].version.as_str()
                ),
                ("replacement-tool.x86_64", "2.0-1")
            );
        }
        Ok(())
    }

    #[cfg(feature = "fedora")]
    #[tokio::test]
    async fn fedora_catalog_concurrent_refreshes_coalesce_one_publication() -> anyhow::Result<()> {
        let gate = Arc::new((tokio::sync::Notify::new(), tokio::sync::Notify::new()));
        let (_directory, state, database, revision, builds, _) =
            mutable_fedora_catalog(true, Some(Arc::clone(&gate)))?;
        let stale_snapshot = state.index_snapshot();
        state.cache.insert_arc(
            "retired-tool".into(),
            Arc::new(stale_snapshot.search("retired-tool", 10)),
        );
        database.packages.lock().unwrap().clear();
        database.add_package("replacement-tool.x86_64", "2.0-1", "Replacement", "fedora");
        revision.fetch_add(1, Ordering::AcqRel);
        let first = tokio::spawn(handle_request(
            Arc::clone(&state),
            Request::RefreshIndex { id: 1 },
        ));
        gate.0.notified().await;
        let mut second = Box::pin(handle_request(
            Arc::clone(&state),
            Request::RefreshIndex { id: 2 },
        ));
        assert!(futures::poll!(second.as_mut()).is_pending());
        gate.1.notify_one();
        for response in [first.await?, second.await] {
            assert!(matches!(
                response,
                Response::Success {
                    result: ResponseResult::IndexRefreshed { packages: 1 },
                    ..
                }
            ));
        }
        assert_eq!(builds.load(Ordering::Acquire), 1);
        assert!(!state.with_current_index(&stale_snapshot, || {
            state.cache.insert_arc(
                "retired-tool".into(),
                Arc::new(stale_snapshot.search("retired-tool", 10)),
            );
        }));
        let Response::Success {
            result: ResponseResult::Search(removed),
            ..
        } = handle_request(
            Arc::clone(&state),
            Request::Search {
                id: 4,
                query: "retired-tool".into(),
                limit: None,
            },
        )
        .await
        else {
            panic!("removed cache search failed")
        };
        assert_eq!(removed.total, 0);
        let Response::Success {
            result: ResponseResult::Search(current),
            ..
        } = handle_request(
            state,
            Request::Search {
                id: 3,
                query: "replacement-tool".into(),
                limit: None,
            },
        )
        .await
        else {
            panic!("coalesced search failed")
        };
        assert_eq!(
            (
                current.packages[0].name.as_str(),
                current.packages[0].version.as_str()
            ),
            ("replacement-tool.x86_64", "2.0-1")
        );
        Ok(())
    }

    #[cfg(feature = "fedora")]
    #[tokio::test]
    async fn fedora_catalog_queued_refresh_coalesces_then_search_observes_later_change()
    -> anyhow::Result<()> {
        let gate = Arc::new((tokio::sync::Notify::new(), tokio::sync::Notify::new()));
        let (_directory, state, database, revision, _, _) =
            mutable_fedora_catalog(true, Some(Arc::clone(&gate)))?;
        let first = tokio::spawn(handle_request(
            Arc::clone(&state),
            Request::RefreshIndex { id: 1 },
        ));
        gate.0.notified().await;
        let mut second = Box::pin(handle_request(
            Arc::clone(&state),
            Request::RefreshIndex { id: 2 },
        ));
        assert!(futures::poll!(second.as_mut()).is_pending());
        gate.1.notify_one();
        assert!(matches!(
            first.await?,
            Response::Success {
                result: ResponseResult::IndexRefreshed { packages: 1 },
                ..
            }
        ));
        database.packages.lock().unwrap().clear();
        database.add_package("replacement-tool.x86_64", "5.0-1", "Later", "fedora");
        database.add_package("new-dependency.noarch", "1.0-1", "Dependency", "fedora");
        revision.fetch_add(1, Ordering::AcqRel);
        // The second invocation overlaps the first publication, which is a
        // valid linearization point even if RPM changes before its response.
        assert!(matches!(
            second.await,
            Response::Success {
                result: ResponseResult::IndexRefreshed { packages: 1 },
                ..
            }
        ));
        let Response::Success {
            result: ResponseResult::Search(current),
            ..
        } = handle_request(
            state,
            Request::Search {
                id: 3,
                query: "replacement-tool".into(),
                limit: None,
            },
        )
        .await
        else {
            panic!("queued refresh current search failed")
        };
        assert_eq!(
            (current.total, current.packages[0].version.as_str()),
            (1, "5.0-1")
        );
        Ok(())
    }

    #[cfg(feature = "fedora")]
    #[tokio::test]
    async fn fedora_catalog_retries_a_change_during_build_before_publication() -> anyhow::Result<()>
    {
        let gate = Arc::new((tokio::sync::Notify::new(), tokio::sync::Notify::new()));
        let (_directory, state, database, revision, builds, _) =
            mutable_fedora_catalog(true, Some(Arc::clone(&gate)))?;
        let refresh = tokio::spawn(handle_request(
            Arc::clone(&state),
            Request::RefreshIndex { id: 1 },
        ));
        gate.0.notified().await;
        database.packages.lock().unwrap().clear();
        database.add_package("replacement-tool.x86_64", "4.0-1", "Latest", "fedora");
        revision.fetch_add(1, Ordering::AcqRel);
        gate.1.notify_one();
        assert!(matches!(
            refresh.await?,
            Response::Success {
                result: ResponseResult::IndexRefreshed { packages: 1 },
                ..
            }
        ));
        let Response::Success {
            result: ResponseResult::Search(current),
            ..
        } = handle_request(
            state,
            Request::Search {
                id: 2,
                query: "replacement-tool".into(),
                limit: None,
            },
        )
        .await
        else {
            panic!("stable replacement search failed")
        };
        assert_eq!(
            (
                current.total,
                current.packages[0].name.as_str(),
                current.packages[0].version.as_str()
            ),
            (1, "replacement-tool.x86_64", "4.0-1")
        );
        assert_eq!(builds.load(Ordering::Acquire), 2);
        Ok(())
    }

    #[cfg(feature = "fedora")]
    #[tokio::test]
    async fn fedora_catalog_refuses_continuous_changes_without_publishing() -> anyhow::Result<()> {
        let (_directory, state, database, _, builds, fault) = mutable_fedora_catalog(true, None)?;
        let previous = state.index_snapshot();
        database.add_package("replacement-tool.x86_64", "4.0-1", "Latest", "fedora");
        fault.store(2, Ordering::Release);
        let response = handle_request(Arc::clone(&state), Request::RefreshIndex { id: 1 }).await;
        assert!(
            matches!(response, Response::Error { code: error_codes::INTERNAL_ERROR, ref message, .. } if message.contains("three package index rebuild attempts"))
        );
        assert!(Arc::ptr_eq(&previous, &state.index_snapshot()));
        assert_eq!(builds.load(Ordering::Acquire), 3);
        fault.store(0, Ordering::Release);
        let Response::Success {
            result: ResponseResult::Search(recovered),
            ..
        } = handle_request(
            state,
            Request::Search {
                id: 2,
                query: "replacement-tool".into(),
                limit: None,
            },
        )
        .await
        else {
            panic!("stable recovery failed")
        };
        assert_eq!(
            (recovered.total, recovered.packages[0].version.as_str()),
            (1, "4.0-1")
        );
        Ok(())
    }

    #[cfg(feature = "fedora")]
    #[tokio::test]
    async fn fedora_catalog_unreadable_inventory_refuses_stale_rows_after_validation()
    -> anyhow::Result<()> {
        let (_directory, state, _, _, builds, fault) = mutable_fedora_catalog(true, None)?;
        let previous = state.index_snapshot();
        fault.store(1, Ordering::Release);
        let response = handle_request(
            Arc::clone(&state),
            Request::Search {
                id: 1,
                query: "x".repeat(MAX_QUERY_LENGTH + 1),
                limit: None,
            },
        )
        .await;
        assert!(matches!(
            response,
            Response::Error {
                code: error_codes::INVALID_PARAMS,
                ..
            }
        ));
        for request in [
            Request::Search {
                id: 2,
                query: "retired-tool".into(),
                limit: None,
            },
            Request::Suggest {
                id: 3,
                query: "retired".into(),
                limit: None,
            },
            Request::RefreshIndex { id: 4 },
        ] {
            assert!(
                matches!(handle_request(Arc::clone(&state), request).await, Response::Error { code: error_codes::INTERNAL_ERROR, ref message, .. } if message.contains("inventory unreadable"))
            );
        }
        assert!(Arc::ptr_eq(&previous, &state.index_snapshot()));
        assert_eq!(builds.load(Ordering::Acquire), 0);
        fault.store(0, Ordering::Release);
        let Response::Success {
            result: ResponseResult::Search(healthy),
            ..
        } = handle_request(
            state,
            Request::Search {
                id: 5,
                query: "retired-tool".into(),
                limit: None,
            },
        )
        .await
        else {
            panic!("observable inventory recovery failed")
        };
        assert_eq!(
            (healthy.total, healthy.packages[0].version.as_str()),
            (1, "1.0-1")
        );
        Ok(())
    }

    #[tokio::test]
    async fn dnf_info_uses_installed_identity_over_repository_index() -> anyhow::Result<()> {
        for cache_seed in ["none", "positive", "negative"] {
            let (_directory, state) = info_selection_state(
                "dnf",
                &[
                    ("bash", "5.4-1", "Repository candidate"),
                    ("bash.x86_64", "5.2-1", "Stale installed index"),
                ],
                ["bash", "bash.x86_64", "bash-5.3.9-3.x86_64"].map(|query| {
                    (
                        query,
                        InfoReply::Found(installed_info("bash.x86_64", "5.3.9-3")),
                    )
                }),
            )?;
            match cache_seed {
                "positive" => {
                    state
                        .cache
                        .insert_info(state.index_snapshot().get("bash").unwrap());
                    state
                        .cache
                        .insert_info(state.index_snapshot().get("bash.x86_64").unwrap());
                }
                "negative" => {
                    state.cache.insert_info_miss("bash");
                    state.cache.insert_info_miss("bash.x86_64");
                }
                _ => {}
            }
            for query in ["bash", "bash", "bash.x86_64", "bash-5.3.9-3.x86_64"] {
                let Response::Success {
                    result: ResponseResult::Info(info),
                    ..
                } = handle_info(Arc::clone(&state), 1, query.into()).await
                else {
                    panic!("installed info must succeed for {query} with {cache_seed} cache");
                };
                assert_eq!(info.name, "bash.x86_64", "{query}/{cache_seed}");
                assert_eq!(info.version, "5.3.9-3", "{query}/{cache_seed}");
                assert_eq!(info.description, "Installed RPM metadata");
                assert_eq!(info.source, WirePackageSource::Official);
                assert_eq!(info.repo, "official");
            }
        }
        Ok(())
    }

    #[cfg(feature = "fedora")]
    #[tokio::test]
    async fn dnf_info_accepts_native_epoch_selectors_at_request_boundary() -> anyhow::Result<()> {
        for query in [
            "widget-0:2.0-1.fc43.x86_64",
            "widget-1:2.0_git-1.fc43.x86_64",
            "widget-1:2.0^a-1_git.x86_64",
        ] {
            let (_directory, state) = info_selection_state(
                "dnf",
                &[],
                [(
                    query,
                    InfoReply::Found(installed_info("widget.x86_64", "1:2.0-1.fc43")),
                )],
            )?;
            let response = handle_info(state, 1, query.into()).await;
            let Response::Success {
                result: ResponseResult::Info(info),
                ..
            } = response
            else {
                panic!("native selector must reach backend: {query}: {response:?}");
            };
            assert_eq!(
                (info.name.as_str(), info.version.as_str()),
                ("widget.x86_64", "1:2.0-1.fc43")
            );
        }
        Ok(())
    }

    #[cfg(feature = "fedora")]
    #[tokio::test]
    async fn info_native_selector_validation_preserves_other_backends_and_rejects_injection()
    -> anyhow::Result<()> {
        for (backend, query) in [
            ("pacman", "widget-1:2.0-1.x86_64"),
            ("apt", "widget-1:2.0-1.x86_64"),
            ("dnf", "widget-1:2.0;id-1.x86_64"),
            ("dnf", "--config=untrusted"),
            ("dnf", "widget-x:2-1.x86_64"),
        ] {
            let (_directory, state) = info_selection_state(
                backend,
                &[],
                [(
                    query,
                    InfoReply::Found(installed_info("widget.x86_64", "1:2.0-1.fc43")),
                )],
            )?;
            let Response::Error { code, message, .. } = handle_info(state, 1, query.into()).await
            else {
                panic!(
                    "invalid selector must be rejected before backend lookup: {backend}/{query}"
                );
            };
            assert_eq!(code, error_codes::INVALID_PARAMS);
            assert!(message.starts_with("Invalid package name:"), "{message}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn dnf_info_uses_available_backend_metadata_after_installed_miss() -> anyhow::Result<()> {
        let available = crate::core::Package {
            installed: false,
            description: "Current available repository metadata".into(),
            ..installed_info("available-tool", "2.0-2")
        };
        let (_directory, state) = info_selection_state(
            "dnf",
            &[("available-tool", "1.0-1", "Stale repository metadata")],
            [("available-tool", InfoReply::Found(available))],
        )?;
        for _ in 0..2 {
            let Response::Success {
                result: ResponseResult::Info(info),
                ..
            } = handle_info(Arc::clone(&state), 1, "available-tool".into()).await
            else {
                panic!("an available package must succeed after an installed-package miss");
            };
            assert_eq!(info.name, "available-tool");
            assert_eq!(info.version, "2.0-2");
            assert_eq!(info.description, "Current available repository metadata");
            assert_eq!(info.source, WirePackageSource::Official);
            assert_eq!(info.repo, "official");
        }
        Ok(())
    }

    #[tokio::test]
    async fn dnf_info_reports_ambiguity_after_nevra_lookup() -> anyhow::Result<()> {
        let cause = "Package has multiple installed builds; specify the full NEVRA";
        let (_directory, state) = info_selection_state(
            "dnf",
            &[
                ("kernel-core", "6.19-1", "Repository candidate"),
                ("kernel-core.x86_64", "6.18-1", "First installed build"),
            ],
            [
                ("kernel-core", InfoReply::Failed(cause)),
                ("kernel-core.x86_64", InfoReply::Failed(cause)),
                (
                    "kernel-core-6.18-1.x86_64",
                    InfoReply::Found(installed_info("kernel-core.x86_64", "6.18-1")),
                ),
            ],
        )?;
        assert!(matches!(
            handle_info(Arc::clone(&state), 1, "kernel-core-6.18-1.x86_64".into()).await,
            Response::Success {
                result: ResponseResult::Info(_),
                ..
            }
        ));
        for query in ["kernel-core.x86_64", "kernel-core"] {
            let Response::Error { code, message, .. } =
                handle_info(Arc::clone(&state), 2, query.into()).await
            else {
                panic!("ambiguous {query} must refuse after a full NEVRA lookup");
            };
            assert_eq!(code, error_codes::INTERNAL_ERROR);
            assert!(message.contains(cause), "{message}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn dnf_info_preserves_native_errors_and_misses_over_index() -> anyhow::Result<()> {
        for fails in [false, true] {
            let replies = if fails {
                vec![("bash", InfoReply::Failed("RPM database unavailable"))]
            } else {
                Vec::new()
            };
            let (_directory, state) =
                info_selection_state("dnf", &[("bash", "5.3-1", "Old repository index")], replies)?;
            state
                .cache
                .insert_info(state.index_snapshot().get("bash").unwrap());
            let Response::Error { code, message, .. } =
                handle_info(Arc::clone(&state), 1, "bash".into()).await
            else {
                panic!("cached repository metadata must not hide a native error or miss");
            };
            if fails {
                assert_eq!(code, error_codes::INTERNAL_ERROR);
                assert!(message.contains("RPM database unavailable"));
            } else {
                assert_eq!(code, error_codes::PACKAGE_NOT_FOUND);
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn non_dnf_info_retains_index_and_cache_fast_paths() -> anyhow::Result<()> {
        for backend_name in ["pacman", "apt", "brew"] {
            let (_directory, state) = info_selection_state(
                backend_name,
                &[("bash", "5.3", "Repository metadata")],
                [("bash", InfoReply::Failed("Backend should not be queried"))],
            )?;
            let Response::Success {
                result: ResponseResult::Info(info),
                ..
            } = handle_info(Arc::clone(&state), 1, "bash".into()).await
            else {
                panic!("{backend_name} index fast path must remain available");
            };
            assert_eq!(info.name, "bash");
            assert_eq!(info.description, "Repository metadata");
            state.cache.insert_info(DetailedPackageInfo {
                version: "cached-version".into(),
                ..info
            });
            let Response::Success {
                result: ResponseResult::Info(cached),
                ..
            } = handle_info(Arc::clone(&state), 2, "bash".into()).await
            else {
                panic!("{backend_name} cached fast path must remain available");
            };
            assert_eq!(cached.version, "cached-version");
        }
        Ok(())
    }

    #[derive(Clone, Copy)]
    enum PausedLookup {
        Info,
        Explicit,
    }

    struct PausedInfoBackend {
        inner: crate::package_managers::mock::MockPackageManager,
        started: tokio::sync::Notify,
        resume: tokio::sync::Notify,
        lookup: PausedLookup,
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
                if matches!(self.lookup, PausedLookup::Info) {
                    self.started.notify_one();
                    self.resume.notified().await;
                }
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
            Box::pin(async move {
                let result = self.inner.list_explicit().await;
                if matches!(self.lookup, PausedLookup::Explicit) {
                    self.started.notify_one();
                    self.resume.notified().await;
                }
                result
            })
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
                lookup: PausedLookup::Info,
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

    fn paused_explicit_state()
    -> anyhow::Result<(tempfile::TempDir, Arc<DaemonState>, Arc<PausedInfoBackend>)> {
        let directory = tempfile::tempdir()?;
        let backend = Arc::new(PausedInfoBackend {
            inner: crate::package_managers::mock::MockPackageManager::new_in(
                "arch",
                directory.path(),
            ),
            started: tokio::sync::Notify::new(),
            resume: tokio::sync::Notify::new(),
            lookup: PausedLookup::Explicit,
        });
        backend.inner.set_installed_version("old-package", "1")?;
        let state = Arc::new(DaemonState::new_isolated(
            directory.path(),
            PackageIndex::from_records(&[("old-package", "1", "old snapshot")]),
            backend.clone(),
        )?);
        Ok((directory, state, backend))
    }

    #[tokio::test]
    async fn daemon_publication_explicit_list_cannot_resurrect_a_stale_cache() -> anyhow::Result<()>
    {
        let (_directory, state, backend) = paused_explicit_state()?;
        let request_state = Arc::clone(&state);
        let request = tokio::spawn(async move { handle_list_explicit(request_state, 1).await });
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            backend.started.notified(),
        )
        .await?;
        backend.inner.remove(&["old-package".into()]).await?;
        backend.inner.set_installed_version("fresh-package", "2")?;
        state.replace_index(
            PackageIndex::from_records(&[("fresh-package", "2", "fresh snapshot")]),
            #[cfg(feature = "arch")]
            crate::package_managers::pacman_db::AlpmCatalogEpoch::UNIX_EPOCH,
        );
        backend.resume.notify_one();
        let response = request.await?;
        assert!(matches!(response, Response::Success { .. }));
        assert!(
            state.cache.get_explicit().is_none(),
            "old list must not regain a fresh TTL"
        );
        assert!(state.cache.get_explicit_count().is_none());
        backend.resume.notify_one();
        let Response::Success {
            result: ResponseResult::Explicit(result),
            ..
        } = handle_list_explicit(Arc::clone(&state), 2).await
        else {
            panic!("fresh lookup must succeed")
        };
        assert_eq!(result.packages, ["fresh-package"]);
        Ok(())
    }

    #[tokio::test]
    async fn daemon_publication_explicit_count_cannot_resurrect_a_stale_cache() -> anyhow::Result<()>
    {
        let (_directory, state, backend) = paused_explicit_state()?;
        let request_state = Arc::clone(&state);
        let request = tokio::spawn(async move { handle_explicit_count(request_state, 3).await });
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            backend.started.notified(),
        )
        .await?;
        backend.inner.remove(&["old-package".into()]).await?;
        state.replace_index(
            PackageIndex::empty(),
            #[cfg(feature = "arch")]
            crate::package_managers::pacman_db::AlpmCatalogEpoch::UNIX_EPOCH,
        );
        backend.resume.notify_one();
        let response = request.await?;
        assert!(matches!(response, Response::Success { .. }));
        assert!(
            state.cache.get_explicit_count().is_none(),
            "old count must not regain a fresh TTL"
        );
        backend.resume.notify_one();
        let Response::Success {
            result: ResponseResult::ExplicitCount(count),
            ..
        } = handle_explicit_count(Arc::clone(&state), 4).await
        else {
            panic!("fresh count must succeed")
        };
        assert_eq!(count, 0);
        Ok(())
    }

    #[cfg(feature = "arch")]
    fn release_native_configuration_fixture(config: &Path) -> anyhow::Result<()> {
        use std::io::Write;
        // Pair with the blocked native reader first. Publish the same bytes as
        // a regular file before releasing it so later freshness reads need no
        // additional writer. The gate tests executor/lifetime behavior, rather
        // than depending on how many times native initialization reads config.
        let mut gate = std::fs::OpenOptions::new().write(true).open(config)?;
        let mut replacement = tempfile::NamedTempFile::new_in(
            config.parent().context("fixture configuration parent")?,
        )?;
        replacement.write_all(NATIVE_FIXTURE_CONFIG.as_bytes())?;
        replacement.persist(config).map_err(|error| error.error)?;
        gate.write_all(NATIVE_FIXTURE_CONFIG.as_bytes())?;
        Ok(())
    }

    #[test]
    #[cfg(feature = "arch")]
    #[serial_test::serial]
    fn daemon_native_initializer_does_not_block_the_async_executor() -> anyhow::Result<()> {
        if crate::core::testing::run_isolated_test(
            "daemon::handlers::tests::daemon_native_initializer_does_not_block_the_async_executor",
        ) {
            return Ok(());
        }
        if crate::core::is_root() {
            eprintln!("skipped: native path overrides require an unprivileged fixture run");
            return Ok(());
        }
        with_native_backend_fixture(|state, directory| {
            let config = directory.join("pacman.conf");
            std::fs::remove_file(&config)?;
            nix::unistd::mkfifo(&config, nix::sys::stat::Mode::S_IRWXU)?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async move {
                let (tick, ticks) = std::sync::mpsc::channel();
                let controller = std::thread::spawn(move || -> anyhow::Result<bool> {
                    let responsive = ticks
                        .recv_timeout(std::time::Duration::from_secs(2))
                        .is_ok();
                    release_native_configuration_fixture(&config)?;
                    Ok(responsive)
                });
                let ticker = tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    let _ = tick.send(());
                });
                tokio::task::yield_now().await;
                let refresh_guard = Arc::clone(&state.refresh_lock).lock_owned().await;
                let refreshed = state.refresh_system_backends(refresh_guard, None).await;
                let responsive = controller.join().expect("fixture controller completed")?;
                refreshed?;
                ticker.await?;
                assert!(
                    responsive,
                    "native initialization prevented an unrelated timer from running"
                );
                Ok(())
            })
        })
    }

    #[test]
    #[cfg(feature = "arch")]
    #[serial_test::serial]
    fn daemon_native_retirement_releases_backend_lock_and_executor() -> anyhow::Result<()> {
        if crate::core::testing::run_isolated_test(
            "daemon::handlers::tests::daemon_native_retirement_releases_backend_lock_and_executor",
        ) {
            return Ok(());
        }
        if crate::core::is_root() {
            eprintln!("skipped: native path overrides require an unprivileged fixture run");
            return Ok(());
        }
        with_native_backend_fixture(|state, _directory| {
            let (started, shutdown_started) = std::sync::mpsc::channel();
            let notify = Arc::new(tokio::sync::Notify::new());
            let (release, released) = std::sync::mpsc::channel();
            let worker = crate::package_managers::alpm_worker::worker_with_shutdown_gate(
                started,
                Arc::clone(&notify),
                released,
            );
            *state.system_backends.write().expect("fixture backend lock") =
                SystemBackendAccess::Production {
                    alpm_worker: Some(Arc::new(worker)),
                };
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async move {
                let (tick, ticks) = std::sync::mpsc::channel();
                let observed_state = Arc::clone(&state);
                let controller = std::thread::spawn(move || -> anyhow::Result<(bool, bool)> {
                    shutdown_started.recv_timeout(std::time::Duration::from_secs(5))?;
                    let lock_free = observed_state.system_backends.try_read().is_ok();
                    let responsive = ticks
                        .recv_timeout(std::time::Duration::from_secs(2))
                        .is_ok();
                    release.send(())?;
                    Ok((lock_free, responsive))
                });
                let ticker = tokio::spawn(async move {
                    notify.notified().await;
                    let _ = tick.send(());
                });
                let refresh_guard = Arc::clone(&state.refresh_lock).lock_owned().await;
                let refreshed = state.refresh_system_backends(refresh_guard, None).await;
                let (lock_free, responsive) =
                    controller.join().expect("fixture controller completed")?;
                refreshed?;
                ticker.await?;
                assert!(
                    lock_free,
                    "retired worker was destroyed while holding the backend write lock"
                );
                assert!(
                    responsive,
                    "native destruction blocked an unrelated async task"
                );
                Ok(())
            })
        })
    }

    #[cfg(feature = "arch")]
    const NATIVE_FIXTURE_CONFIG: &str = "[options]\nSigLevel = Optional TrustAll\n\n[core]\nServer = https://example.invalid/$repo/os/$arch\n";

    #[test]
    #[cfg(feature = "arch")]
    #[serial_test::serial]
    fn daemon_native_cancelled_request_retains_serialization_until_work_finishes()
    -> anyhow::Result<()> {
        if crate::core::testing::run_isolated_test(
            "daemon::handlers::tests::daemon_native_cancelled_request_retains_serialization_until_work_finishes",
        ) {
            return Ok(());
        }
        if crate::core::is_root() {
            eprintln!("skipped: native path overrides require an unprivileged fixture run");
            return Ok(());
        }
        with_native_backend_fixture(|state, directory| {
            let config = directory.join("pacman.conf");
            std::fs::remove_file(&config)?;
            nix::unistd::mkfifo(&config, nix::sys::stat::Mode::S_IRWXU)?;
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(async {
                    let request_state = Arc::clone(&state);
                    let request = tokio::spawn(async move {
                        let guard = Arc::clone(&request_state.refresh_lock).lock_owned().await;
                        request_state.refresh_system_backends(guard, None).await
                    });
                    tokio::time::timeout(std::time::Duration::from_secs(5), async {
                        while state.native_tasks.is_empty() {
                            tokio::task::yield_now().await;
                        }
                    })
                    .await?;
                    request.abort();
                    assert!(
                        request
                            .await
                            .expect_err("request was cancelled")
                            .is_cancelled()
                    );
                    assert!(
                        state.refresh_lock.try_lock().is_err(),
                        "request cancellation must not admit another native replacement"
                    );
                    let controller = std::thread::spawn(move || -> anyhow::Result<()> {
                        release_native_configuration_fixture(&config)
                    });
                    state
                        .drain_native_backends(std::time::Duration::from_secs(5))
                        .await?;
                    controller.join().expect("fixture writer completed")?;
                    assert!(
                        state.native_tasks.is_empty(),
                        "shutdown must join cancelled request's native work"
                    );
                    Ok(())
                })
        })
    }

    #[test]
    #[cfg(feature = "arch")]
    fn native_retirement_retains_the_owner_while_a_request_lease_is_held() -> anyhow::Result<()> {
        let (started, shutdown_started) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let worker = Arc::new(
            crate::package_managers::alpm_worker::worker_with_shutdown_gate(
                started,
                Arc::new(tokio::sync::Notify::new()),
                released,
            ),
        );
        let retired = Arc::clone(&worker);
        let (waiting, waited) = std::sync::mpsc::channel();
        let (resume, resumed) = std::sync::mpsc::channel();
        let retirement = std::thread::spawn(move || {
            retire_alpm_worker(retired, || {
                waiting.send(()).expect("lease observer is alive");
                resumed
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .expect("request lease is released");
                pause_native_retirement();
            });
        });
        let observed = waited.recv_timeout(std::time::Duration::from_secs(5));
        let owners = Arc::strong_count(&worker);
        let premature_shutdown = shutdown_started.try_recv();
        // Release both gates before asserting, so a broken retirement path can
        // fail without stranding either native thread during fixture cleanup.
        release.send(())?;
        drop(worker);
        let resumed = resume.send(());
        retirement.join().expect("native retirement completed");
        shutdown_started.recv_timeout(std::time::Duration::from_secs(5))?;
        observed?;
        resumed?;
        assert_eq!(
            owners, 2,
            "native retirement must retain its ownership beside the request lease"
        );
        assert!(matches!(
            premature_shutdown,
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        Ok(())
    }

    #[test]
    #[cfg(feature = "arch")]
    #[serial_test::serial]
    fn daemon_native_retirement_keeps_final_join_off_the_request_executor() -> anyhow::Result<()> {
        if crate::core::testing::run_isolated_test(
            "daemon::handlers::tests::daemon_native_retirement_keeps_final_join_off_the_request_executor",
        ) {
            return Ok(());
        }
        if crate::core::is_root() {
            eprintln!("skipped: native path overrides require an unprivileged fixture run");
            return Ok(());
        }
        with_native_backend_fixture(|state, _directory| {
            let (started, shutdown_started) = std::sync::mpsc::channel();
            let notify = Arc::new(tokio::sync::Notify::new());
            let (release, released) = std::sync::mpsc::channel();
            let worker = Arc::new(
                crate::package_managers::alpm_worker::worker_with_shutdown_gate(
                    started,
                    Arc::clone(&notify),
                    released,
                ),
            );
            *state.system_backends.write().expect("fixture backend lock") =
                SystemBackendAccess::Production {
                    alpm_worker: Some(Arc::clone(&worker)),
                };
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(async {
                    let (tick, ticks) = std::sync::mpsc::channel();
                    let controller = std::thread::spawn(move || -> anyhow::Result<bool> {
                        shutdown_started.recv_timeout(std::time::Duration::from_secs(5))?;
                        let responsive = ticks
                            .recv_timeout(std::time::Duration::from_secs(2))
                            .is_ok();
                        release.send(())?;
                        Ok(responsive)
                    });
                    let ticker = tokio::spawn(async move {
                        notify.notified().await;
                        let _ = tick.send(());
                    });
                    let request_state = Arc::clone(&state);
                    let refresh = tokio::spawn(async move {
                        let guard = Arc::clone(&request_state.refresh_lock).lock_owned().await;
                        request_state.refresh_system_backends(guard, None).await
                    });
                    tokio::time::timeout(std::time::Duration::from_secs(5), async {
                        loop {
                            let old_is_published = {
                                let current =
                                    state.system_backends.read().expect("fixture backend lock");
                                matches!(&*current, SystemBackendAccess::Production { alpm_worker: Some(alpm_worker) }
                                if Arc::ptr_eq(alpm_worker, &worker))
                            };
                            if !old_is_published {
                                break;
                            }
                            tokio::task::yield_now().await;
                        }
                    })
                    .await?;
                    drop(worker);
                    drop(refresh.await??);
                    ticker.await?;
                    assert!(
                        controller.join().expect("fixture controller completed")?,
                        "last request lease inherited the native thread's blocking join"
                    );
                    state
                        .drain_native_backends(std::time::Duration::from_secs(5))
                        .await?;
                    Ok(())
                })
        })
    }

    #[cfg(feature = "arch")]
    fn with_native_backend_fixture(
        run: impl FnOnce(Arc<DaemonState>, &Path) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("root");
        let database = directory.path().join("db");
        let config = directory.path().join("pacman.conf");
        std::fs::create_dir(&root)?;
        std::fs::create_dir_all(database.join("local"))?;
        std::fs::create_dir_all(database.join("sync"))?;
        std::fs::write(&config, NATIVE_FIXTURE_CONFIG)?;
        // libalpm creates its database-version marker on first open. Bootstrap
        // this private database before the production epoch-stability bracket.
        drop(alpm::Alpm::new::<&str>(
            root.to_string_lossy().as_ref(),
            database.to_string_lossy().as_ref(),
        )?);
        temp_env::with_vars(
            [
                ("OMG_PACMAN_ROOT", Some(root.as_os_str())),
                ("OMG_PACMAN_DB_DIR", Some(database.as_os_str())),
                ("OMG_PACMAN_CONF", Some(config.as_os_str())),
            ],
            || {
                let state = Arc::new(DaemonState::new_isolated(
                    directory.path(),
                    PackageIndex::empty(),
                    Arc::new(crate::package_managers::mock::MockPackageManager::new_in(
                        "arch",
                        directory.path(),
                    )),
                )?);
                *state.system_backends.write().expect("fixture backend lock") =
                    SystemBackendAccess::production()?;
                run(state, directory.path())
            },
        )
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
    async fn fedora_search_request_ranks_before_cache_limits_and_refresh() {
        let directory = tempfile::tempdir().unwrap();
        let manager: Arc<dyn PackageManager> = Arc::new(
            crate::package_managers::mock::MockPackageManager::new_in("fedora", directory.path()),
        );
        let records = [
            ("tree2.i686", "1", "prefix"),
            ("tree.x86_64", "2", "exact RPM basename"),
        ];
        let index = PackageIndex::from_rpm_records(&records);
        let state = Arc::new(DaemonState::new_isolated(directory.path(), index, manager).unwrap());
        for (id, limit) in [(1, 1), (2, 1), (3, 10)] {
            let response = handle_request(
                Arc::clone(&state),
                Request::Search {
                    id,
                    query: "tree".into(),
                    limit: Some(limit),
                },
            )
            .await;
            let Response::Success {
                result: ResponseResult::Search(results),
                ..
            } = response
            else {
                panic!("search response: {response:?}");
            };
            assert_eq!(results.total, 2);
            assert_eq!(results.packages.len(), limit.min(2));
            assert_eq!(results.packages[0].name, "tree.x86_64");
            assert_eq!(results.packages[0].version, "2");
            assert_eq!(results.packages[0].description, "exact RPM basename");
        }
        let stale = state.index_snapshot();
        let replacement = PackageIndex::from_records(&records);
        state.replace_index(
            replacement,
            #[cfg(feature = "arch")]
            crate::package_managers::pacman_db::AlpmCatalogEpoch::UNIX_EPOCH,
        );
        assert!(state.cache.get("tree").is_none());
        assert!(
            !state.with_current_index(&stale, || panic!("stale index must not repopulate cache"))
        );
        let response = handle_request(
            state,
            Request::Search {
                id: 4,
                query: "tree".into(),
                limit: Some(1),
            },
        )
        .await;
        let Response::Success {
            result: ResponseResult::Search(results),
            ..
        } = response
        else {
            panic!("refresh response: {response:?}");
        };
        assert_eq!(
            results.packages[0].name, "tree2.i686",
            "fresh literal context must replace RPM context"
        );
    }

    #[tokio::test]
    async fn fedora_search_request_preserves_full_identity_priority_in_cache() {
        let directory = tempfile::tempdir().unwrap();
        let manager: Arc<dyn PackageManager> = Arc::new(
            crate::package_managers::mock::MockPackageManager::new_in("fedora", directory.path()),
        );
        let index = PackageIndex::from_rpm_records(&[
            ("tree.x86_64.aarch64", "1", "colliding RPM basename"),
            ("tree.x86_64", "2", "literal full identity"),
            ("tree.x86_64-extra.noarch", "3", "prefix"),
        ]);
        let state = Arc::new(DaemonState::new_isolated(directory.path(), index, manager).unwrap());
        for (id, limit) in [(1, 1), (2, 1), (3, 10)] {
            let response = handle_request(
                Arc::clone(&state),
                Request::Search {
                    id,
                    query: "tree.x86_64".into(),
                    limit: Some(limit),
                },
            )
            .await;
            let Response::Success {
                result: ResponseResult::Search(results),
                ..
            } = response
            else {
                panic!("search response: {response:?}");
            };
            assert_eq!(results.total, 3);
            assert_eq!(results.packages.len(), limit.min(3));
            assert_eq!(results.packages[0].name, "tree.x86_64");
            assert_eq!(results.packages[0].version, "2");
            if limit > 1 {
                assert_eq!(results.packages[1].name, "tree.x86_64.aarch64");
            }
        }
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
            state.system_backends = Arc::new(RwLock::new(SystemBackendAccess::Production {}));
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

    #[test]
    fn windowed_failures_decide_health_not_lifetime_totals() {
        use crate::core::metrics::{FAILURE_HEALTH_WINDOW_MS, Metrics};

        const EPOCH_MS: u64 = 1_700_000_000_000;
        const SMALL_CACHE: usize = 0;

        // 2000 lifetime failures spread over two hours: one every ~3.6s, so
        // far below the threshold inside any single trailing window.
        // record_request_failure_at maintains the window only; the lifetime
        // counter is covered by inc_requests_failed_counts_lifetime_and_opens_the_window.
        let spread = Metrics::new();
        let step_ms = (2 * 3_600_000) / 2000;
        let mut now = EPOCH_MS;
        for _ in 0..2000 {
            spread.record_request_failure_at(now);
            now += step_ms;
        }
        assert_eq!(
            health_status(SMALL_CACHE, spread.request_failures_within_window(now)),
            "healthy",
            "lifetime failures must not latch health unhealthy"
        );

        // 1001 failures inside one window is a genuine burst and stays red.
        let burst = Metrics::new();
        for _ in 0..=HEALTH_UNHEALTHY_FAILURES_THRESHOLD {
            burst.record_request_failure_at(EPOCH_MS);
        }
        assert_eq!(
            health_status(SMALL_CACHE, burst.request_failures_within_window(EPOCH_MS)),
            "unhealthy"
        );

        // Once the burst leaves the trailing window health recovers.
        assert_eq!(
            health_status(
                SMALL_CACHE,
                burst.request_failures_within_window(EPOCH_MS + FAILURE_HEALTH_WINDOW_MS)
            ),
            "healthy"
        );
    }

    #[tokio::test]
    async fn fedora_search_parity_handler_cold_warm_limits_preserve_rows_and_counters() {
        const CHILD: &str = "OMG_SEARCH_PARITY_HANDLER_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "daemon::handlers::tests::fedora_search_parity_handler_cold_warm_limits_preserve_rows_and_counters", "--nocapture", "--test-threads=1"])
                .env(CHILD, "1").stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            loop {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    child.kill().unwrap();
                    let _ = child.wait();
                    panic!("search parity child exceeded deadline");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let output = child.wait_with_output().unwrap();
            println!("{}", String::from_utf8_lossy(&output.stdout));
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        use crate::daemon::index::search_parity_fixture::{EXPECTED, RECORDS};
        let directory = tempfile::tempdir().unwrap();
        let manager: Arc<dyn PackageManager> = Arc::new(
            crate::package_managers::mock::MockPackageManager::new_in("fedora", directory.path()),
        );
        let mut records = RECORDS.to_vec();
        records.reverse();
        let state = Arc::new(
            DaemonState::new_isolated(
                directory.path(),
                PackageIndex::from_rpm_records(&records),
                manager,
            )
            .unwrap(),
        );
        let before = GLOBAL_METRICS.snapshot();
        let mut cached = None;
        for (id, limit) in [(1, 1), (2, 1), (3, 20), (4, MAX_SEARCH_LIMIT)] {
            let response = handle_request(
                Arc::clone(&state),
                Request::Search {
                    id,
                    query: "tree".into(),
                    limit: Some(limit),
                },
            )
            .await;
            let Response::Success {
                id: actual_id,
                result: ResponseResult::Search(result),
            } = response
            else {
                panic!("search response {response:?}");
            };
            assert_eq!(actual_id, id);
            assert_eq!(result.total, RECORDS.len());
            assert_eq!(result.packages.len(), limit.min(RECORDS.len()));
            for (row, &(name, version, description)) in result.packages.iter().zip(EXPECTED) {
                assert_eq!(
                    (&*row.name, &*row.version, &*row.description),
                    (name, version, description),
                    "request{id} limit{limit}"
                );
                assert_eq!(row.source, WirePackageSource::Official);
            }
            let current = state.cache.get("tree").expect("full bounded prefix cached");
            assert_eq!(current.len(), RECORDS.len());
            if let Some(previous) = &cached {
                assert!(
                    Arc::ptr_eq(previous, &current),
                    "warm request rebuilt cache"
                );
            }
            cached = Some(current);
            println!(
                "SEARCH_PARITY_REQUEST id={id} limit={limit} rows={} total={}",
                result.packages.len(),
                result.total
            );
        }
        let after = GLOBAL_METRICS.snapshot();
        assert_eq!(after.cache_misses - before.cache_misses, 1);
        assert_eq!(after.cache_hits - before.cache_hits, 3);
        assert_eq!(after.search_requests - before.search_requests, 4);
        let stale = state.index_snapshot();
        state.replace_index(
            PackageIndex::from_rpm_records(RECORDS),
            #[cfg(feature = "arch")]
            crate::package_managers::pacman_db::AlpmCatalogEpoch::UNIX_EPOCH,
        );
        assert!(state.cache.get("tree").is_none());
        assert!(!state.with_current_index(&stale, || panic!("stale generation must not publish")));
        let response = handle_request(
            state,
            Request::Search {
                id: 5,
                query: "tree".into(),
                limit: Some(20),
            },
        )
        .await;
        let Response::Success {
            result: ResponseResult::Search(result),
            ..
        } = response
        else {
            panic!("refresh response {response:?}");
        };
        assert_eq!(
            result
                .packages
                .iter()
                .map(|row| row.name.as_str())
                .collect::<Vec<_>>(),
            EXPECTED.iter().map(|row| row.0).collect::<Vec<_>>()
        );
        let refreshed = GLOBAL_METRICS.snapshot();
        assert_eq!(refreshed.cache_misses - before.cache_misses, 2);
        assert_eq!(refreshed.cache_hits - before.cache_hits, 3);
        println!("SEARCH_PARITY_CACHE misses=2 hits=3 refresh=1");
    }

    #[tokio::test]
    async fn fedora_search_parity_handler_scores_late_description_before_cached_cap() {
        let directory = tempfile::tempdir().unwrap();
        let manager: Arc<dyn PackageManager> = Arc::new(
            crate::package_managers::mock::MockPackageManager::new_in("fedora", directory.path()),
        );
        let names: Vec<_> = (0..1200)
            .rev()
            .map(|i| format!("zzztree-i18n-aa{i:04}.noarch"))
            .collect();
        let mut records: Vec<_> = names
            .iter()
            .map(|name| (name.as_str(), "1", "name substring"))
            .collect();
        records.push((
            "t-r-e-e.noarch",
            "7:8-9.fc44",
            "tree viewer from description",
        ));
        let state = Arc::new(
            DaemonState::new_isolated(
                directory.path(),
                PackageIndex::from_rpm_records(&records),
                manager,
            )
            .unwrap(),
        );
        for (id, limit) in [(1, 1), (2, 1), (3, 20), (4, MAX_SEARCH_LIMIT)] {
            let response = handle_request(
                Arc::clone(&state),
                Request::Search {
                    id,
                    query: "tree".into(),
                    limit: Some(limit),
                },
            )
            .await;
            let Response::Success {
                result: ResponseResult::Search(result),
                ..
            } = response
            else {
                panic!("search response {response:?}");
            };
            assert_eq!(
                result.total, MAX_SEARCH_LIMIT,
                "protocol retains its existing bounded-prefix total"
            );
            assert_eq!(result.packages.len(), limit);
            assert_eq!(
                (
                    &*result.packages[0].name,
                    &*result.packages[0].version,
                    &*result.packages[0].description
                ),
                (
                    "t-r-e-e.noarch",
                    "7:8-9.fc44",
                    "tree viewer from description"
                )
            );
            assert_eq!(result.packages[0].source, WirePackageSource::Official);
            assert_eq!(state.cache.get("tree").unwrap().len(), MAX_SEARCH_LIMIT);
        }
    }
}

#[cfg(all(test, unix))]
#[path = "audit_transport_tests.rs"]
mod audit_transport_tests;
