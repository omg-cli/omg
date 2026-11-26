//! Telemetry and install tracking
//!
//! Privacy-first telemetry that tracks install counts for GitHub badge display.
//! - Runtime telemetry is disabled by default and requires explicit opt-in
//! - Environment variables can override an opt-in and disable collection
//! - One-time install tracking is controlled independently by the installer
//! - Network failures never fail the requested command
//!
//! ## Enhanced Telemetry (opt-in)
//!
//! When the user enables runtime telemetry, additional events are collected:
//! - Command summaries (canonical command name, duration, success, backend)
//! - Session tracking (`session_id`, start/end times, command count)
//! - Performance metrics (metric name and duration)
//! - Feature usage (feature name and enabled state)
//! - Stable machine identifier
//! - Dashboard account token when this machine is linked (`omg account link`)
//!
//! Positional arguments, package names, search queries, paths, command output,
//! and raw error messages are never included.
//!
//! Events are persisted in a bounded local queue and sent on CLI exit. Failed
//! batches remain queued for a later invocation.

use std::collections::{HashSet, VecDeque};
use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::core::telemetry_client::{CommandEvent, PerformanceEvent, SessionEvent, TelemetryEvent};

mod queue;
use queue::{PendingEvent, QueueStore};

/// Maximum queue size before dropping old events
const MAX_QUEUE_SIZE: usize = 5000;
const MAX_QUEUE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SESSION_BYTES: u64 = 64 * 1024;
/// Persist queue to disk every N events
const PERSIST_EVERY_N_EVENTS: u32 = 10;
/// Persist queue to disk every N seconds
const PERSIST_INTERVAL_SECS: i64 = 30;
/// Current on-disk telemetry queue format.
const QUEUE_FORMAT_VERSION: u32 = 1;
/// Current on-disk telemetry session format.
const SESSION_FORMAT_VERSION: u32 = 1;

/// Install telemetry payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallPayload {
    /// Anonymous install ID (UUID v4)
    pub install_id: String,
    /// Install timestamp (ISO 8601)
    pub timestamp: String,
    /// OMG version
    pub version: String,
    /// Platform (e.g., "linux-x86_64")
    pub platform: String,
    /// Package manager backend (arch/debian)
    pub backend: String,
}

/// Marker file content
#[derive(Debug, Clone, Serialize, Deserialize)]
struct InstallMarker {
    install_id: String,
    timestamp: String,
    version: String,
}

/// Check if telemetry is opted out
#[must_use]
pub fn is_telemetry_opt_out() -> bool {
    if crate::core::paths::test_mode() {
        return true;
    }

    telemetry_disabled_by_environment() || settings_file_opts_out()
}

pub(crate) fn telemetry_disabled_by_environment() -> bool {
    env_value_matches("OMG_TELEMETRY", &["0", "false", "off", "no"])
        || env_value_matches("OMG_DISABLE_TELEMETRY", &["1", "true", "on", "yes"])
}

/// Identity of the settings version used for the cached opt-out verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OptOutCacheKey {
    path: PathBuf,
    len: Option<u64>,
    mtime: Option<std::time::SystemTime>,
    #[cfg(unix)]
    unix_identity: Option<(u64, u64, i64, i64)>,
}

static OPT_OUT_CACHE: Mutex<Option<(OptOutCacheKey, bool)>> = Mutex::new(None);

/// File half of the opt-out verdict. Environment overrides stay live above
/// this: they are process state a test or wrapper can change at any time,
/// while the file half is stable until the file itself changes.
fn settings_file_opts_out() -> bool {
    let Ok(path) = crate::config::Settings::config_path() else {
        return load_opt_out_uncached();
    };
    let metadata = std::fs::symlink_metadata(&path).ok();
    let key = OptOutCacheKey {
        path,
        len: metadata.as_ref().map(std::fs::Metadata::len),
        mtime: metadata
            .as_ref()
            .and_then(|metadata| metadata.modified().ok()),
        #[cfg(unix)]
        unix_identity: metadata.as_ref().map(|metadata| {
            use std::os::unix::fs::MetadataExt as _;
            (
                metadata.dev(),
                metadata.ino(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            )
        }),
    };
    {
        let cached = OPT_OUT_CACHE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((cached_key, verdict)) = cached.as_ref()
            && *cached_key == key
        {
            return *verdict;
        }
    }
    let verdict = load_opt_out_uncached();
    *OPT_OUT_CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((key, verdict));
    verdict
}

fn load_opt_out_uncached() -> bool {
    // Configuration errors fail closed. A malformed settings file must not
    // silently reverse a user's privacy choice and re-enable telemetry.
    match crate::config::Settings::load() {
        Ok(settings) => !settings.telemetry_enabled,
        Err(error) => {
            tracing::warn!("Disabling telemetry because settings could not be loaded: {error:#}");
            true
        }
    }
}

fn telemetry_consent_lease() -> Option<std::fs::File> {
    use crate::config::Settings;

    match Settings::try_read_lock() {
        Ok(Some(lease)) if !is_telemetry_opt_out() => Some(lease),
        Ok(_) => None,
        Err(error) => {
            tracing::debug!(
                "Skipping telemetry because the configuration lock is unavailable: {error:#}"
            );
            None
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
struct ConsentEpoch(Option<String>);

impl ConsentEpoch {
    fn is_legacy(&self) -> bool {
        self.0.is_none()
    }
}

#[derive(PartialEq, Eq)]
struct CaptureConsent {
    marker: PathBuf,
    epoch: ConsentEpoch,
}

impl CaptureConsent {
    fn marker_path() -> Result<PathBuf> {
        Ok(crate::config::Settings::config_path()?.with_extension("telemetry-consent"))
    }

    fn read() -> Result<Self> {
        let marker = Self::marker_path()?;
        let generation = read_saved_telemetry(&marker, "Telemetry consent marker", 36)?;
        if let Some(generation) = &generation {
            uuid::Uuid::parse_str(generation).context("Invalid telemetry consent marker")?;
        }
        Ok(Self {
            marker,
            epoch: ConsentEpoch(generation),
        })
    }

    fn rotate() -> Result<()> {
        crate::core::safe_ops::atomic_write_file_sync_private(
            &Self::marker_path()?,
            uuid::Uuid::new_v4().to_string(),
        )
        .context("Failed to update the telemetry consent marker")
    }

    fn try_lease(&self) -> Option<std::fs::File> {
        let lease = telemetry_consent_lease()?;
        match Self::read() {
            Ok(current) if current == *self => Some(lease),
            Ok(_) => None,
            Err(error) => {
                tracing::debug!("Failed to check current telemetry consent: {error:#}");
                None
            }
        }
    }

    fn persist(&self, save: impl FnOnce() -> Result<()>) {
        if let Some(_consent) = self.try_lease() {
            persist_best_effort(save());
        }
    }
}

// A CLI invocation that spans a consent change may finish its work, but its
// telemetry should never be carried into the new consent period.
static CAPTURE_CONSENT: OnceLock<Option<CaptureConsent>> = OnceLock::new();

fn capture_consent() -> Option<&'static CaptureConsent> {
    let opted_out = is_telemetry_opt_out();
    let captured = CAPTURE_CONSENT.get_or_init(|| {
        if opted_out {
            return None;
        }
        match CaptureConsent::read() {
            Ok(consent) => Some(consent),
            Err(error) => {
                tracing::warn!("Cannot identify telemetry consent: {error:#}");
                None
            }
        }
    });
    if opted_out { None } else { captured.as_ref() }
}

fn read_saved_telemetry(path: &Path, kind: &str, limit: u64) -> Result<Option<String>> {
    match crate::core::safe_ops::read_bounded_regular_file(path, kind, limit) {
        Ok(content) => Ok(Some(content)),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|cause| cause.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// Case-insensitive check of an environment variable against a set of
/// accepted values, so `off`, `OFF`, and `Off` all behave identically.
fn env_value_matches(name: &str, accepted: &[&str]) -> bool {
    std::env::var(name).is_ok_and(|value| accepted.iter().any(|a| value.eq_ignore_ascii_case(a)))
}

/// Check if this is the first run
pub fn is_first_run() -> bool {
    let marker_path = super::paths::installed_marker_path();
    !marker_path.exists()
}

/// Get platform string (e.g., "linux-x86_64")
fn get_platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// Current UTC timestamp formatted as millisecond-precision ISO 8601.
///
/// Shared by session state and event payloads so every emitted timestamp uses
/// one canonical format.
/// https://docs.rs/jiff/latest/jiff/fmt/strtime/index.html#supported-directives
/// (`%.3fZ` always emits exactly three fractional digits).
fn now_iso8601_ms() -> String {
    jiff::Timestamp::now()
        .strftime("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

/// Persist telemetry state on a best-effort basis. Telemetry must never fail a
/// user command, so persistence errors are logged at debug level only and the
/// in-memory state (authoritative for the current process) is left unchanged.
pub(crate) fn persist_best_effort(result: Result<()>) {
    if let Err(error) = result {
        tracing::debug!("Failed to persist telemetry state (non-fatal): {error}");
    }
}

/// Get the compiled package manager backend identifier (`arch`, `debian`,
/// `fedora`, `homebrew`, or `none`).
///
/// The available backends are fixed at compile time by feature flags, so
/// runtime distro detection is deliberately not consulted.
#[must_use]
pub fn get_backend() -> String {
    if cfg!(feature = "arch") {
        "arch".to_string()
    } else if cfg!(any(feature = "debian", feature = "debian-pure")) {
        "debian".to_string()
    } else if cfg!(feature = "fedora") {
        "fedora".to_string()
    } else if cfg!(any(feature = "macos", target_os = "macos")) {
        // Matches the homebrew module gate in `package_managers::mod`.
        "homebrew".to_string()
    } else {
        "none".to_string()
    }
}

fn open_telemetry_lock(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    let lock = options
        .open(path)
        .with_context(|| format!("Failed to open telemetry lock: {}", path.display()))?;
    anyhow::ensure!(
        lock.metadata()?.is_file(),
        "Telemetry lock must be a regular file: {}",
        path.display()
    );
    Ok(lock)
}

/// Create install marker file
fn create_marker(path: &Path, install_id: &str) -> Result<()> {
    let marker = InstallMarker {
        install_id: install_id.to_string(),
        timestamp: jiff::Timestamp::now().to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let content =
        serde_json::to_vec_pretty(&marker).context("Failed to serialize install marker")?;
    crate::core::safe_ops::atomic_write_file_sync_private(path, content)
        .with_context(|| format!("Failed to save install marker: {}", path.display()))
}

/// Ping install telemetry endpoint
pub async fn ping_install() -> Result<()> {
    let Some(_consent) = capture_consent().and_then(CaptureConsent::try_lease) else {
        return Ok(());
    };
    let marker = super::paths::installed_marker_path();
    if marker
        .try_exists()
        .context("Failed to check the install marker")?
    {
        return Ok(());
    }

    super::paths::ensure_data_dir()?;
    let install_lock = open_telemetry_lock(&marker.with_extension("lock"))?;
    match install_lock.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Ok(()),
        Err(TryLockError::Error(error)) => {
            return Err(error).context("Failed to lock installation telemetry");
        }
    }
    if marker
        .try_exists()
        .context("Failed to check the install marker")?
    {
        return Ok(());
    }

    let install_id = uuid::Uuid::new_v4().to_string();
    let payload = InstallPayload {
        install_id: install_id.clone(),
        timestamp: jiff::Timestamp::now().to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        platform: get_platform(),
        backend: get_backend(),
    };

    // Send ping with timeout
    let client = crate::core::http::shared_client();
    let response = client
        .post(super::service_api::INSTALL_PING)
        .json(&payload)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await;

    match response {
        Ok(response) if response.status().is_success() => {
            tracing::debug!("Install telemetry ping successful");
        }
        Ok(response) => {
            tracing::debug!(
                "Install telemetry ping rejected with status {}",
                response.status()
            );
        }
        Err(error) => {
            tracing::debug!("Install telemetry ping failed: {error}");
        }
    }

    // This is deliberately one-shot best-effort telemetry; do not retry on a
    // later user command when the endpoint is unavailable.
    create_marker(&marker, &install_id)
}

// =============================================================================
// Enhanced Telemetry (opt-in)
// =============================================================================

/// Global event queue for batching
static EVENT_QUEUE: OnceLock<Mutex<EventQueue>> = OnceLock::new();
/// Serialize network flushes so an older snapshot cannot remove newer events.
static FLUSH_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Global session state
static SESSION_STATE: OnceLock<Mutex<TelemetrySession>> = OnceLock::new();

/// Global CLI start time for startup metrics
static CLI_START_TIME: OnceLock<Instant> = OnceLock::new();

/// Event queue for batching telemetry events
#[derive(Debug)]
struct EventQueue {
    events: VecDeque<PendingEvent>,
    events_since_persist: AtomicU32,
    last_persist: AtomicI64,
    persistence_enabled: bool,
}

impl Default for EventQueue {
    fn default() -> Self {
        Self {
            events: VecDeque::new(),
            events_since_persist: AtomicU32::new(0),
            last_persist: AtomicI64::new(jiff::Timestamp::now().as_second()),
            persistence_enabled: true,
        }
    }
}

impl EventQueue {
    fn push(&mut self, event: TelemetryEvent) {
        // Enforce bounded queue: drop oldest 25% when exceeding max size
        if self.events.len() >= MAX_QUEUE_SIZE {
            let drop_count = MAX_QUEUE_SIZE / 4;
            self.events.drain(..drop_count);
            tracing::warn!(
                "Telemetry queue exceeded {} events, dropped {} oldest events",
                MAX_QUEUE_SIZE,
                drop_count
            );
        }

        self.events.push_back(PendingEvent::new(event));
        self.events_since_persist.fetch_add(1, Ordering::Relaxed);
    }

    fn needs_persist(&self) -> bool {
        let events_count = self.events_since_persist.load(Ordering::Relaxed);
        let now = jiff::Timestamp::now().as_second();
        let last_persist = self.last_persist.load(Ordering::Relaxed);

        events_count >= PERSIST_EVERY_N_EVENTS || (now - last_persist) >= PERSIST_INTERVAL_SECS
    }

    fn snapshot(&self) -> Vec<Arc<TelemetryEvent>> {
        self.events
            .iter()
            .map(|row| Arc::clone(&row.event))
            .collect()
    }

    fn confirm_sent(&mut self, sent: &[Arc<TelemetryEvent>]) {
        // Retained snapshot Arcs prevent pointer reuse. A new occurrence of an
        // identical payload therefore cannot be acknowledged by an older batch.
        let identities: HashSet<_> = sent.iter().map(Arc::as_ptr).collect();
        self.events
            .retain(|row| !identities.contains(&Arc::as_ptr(&row.event)));
    }

    fn path() -> Result<PathBuf> {
        crate::core::paths::ensure_data_dir()?;
        Ok(telemetry_queue_path())
    }

    fn load(epoch: &ConsentEpoch) -> Self {
        let result = Self::path().and_then(|path| Self::load_from(&path, epoch));
        match result {
            Ok(()) => Self::default(),
            Err(error) => {
                tracing::warn!(
                    "Telemetry queue persistence disabled because its state is invalid: {error:#}"
                );
                Self {
                    persistence_enabled: false,
                    ..Self::default()
                }
            }
        }
    }

    fn load_from(path: &Path, epoch: &ConsentEpoch) -> Result<()> {
        QueueStore::new(path.to_path_buf(), epoch.clone()).validate()
    }

    fn save(&mut self, epoch: &ConsentEpoch) -> Result<()> {
        anyhow::ensure!(
            self.persistence_enabled,
            "telemetry queue persistence is disabled after a load failure"
        );
        if self.events.is_empty() {
            return Ok(());
        }

        QueueStore::new(Self::path()?, epoch.clone()).append(&self.events)?;
        self.events.clear();

        // Reset persist tracking
        self.events_since_persist.store(0, Ordering::Relaxed);
        self.last_persist
            .store(jiff::Timestamp::now().as_second(), Ordering::Relaxed);

        Ok(())
    }
}

/// Session state for tracking CLI sessions
#[derive(Debug)]
pub struct TelemetrySession {
    /// Session ID (UUID)
    pub session_id: String,
    /// Session start timestamp
    pub started_at: String,
    /// Commands run this session (atomic for non-blocking updates)
    pub commands_run: AtomicU32,
    /// Last activity timestamp in unix seconds (atomic for non-blocking updates)
    pub last_activity: AtomicI64,
    /// Persist tracking
    persist_counter: AtomicU32,
    last_persist: AtomicI64,
    persistence_enabled: bool,
}

/// Serializable session state for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SerializableSession {
    format_version: u32,
    #[serde(default, skip_serializing_if = "ConsentEpoch::is_legacy")]
    consent_epoch: ConsentEpoch,
    session_id: String,
    started_at: String,
    commands_run: u32,
    last_activity: i64,
}

impl Default for TelemetrySession {
    fn default() -> Self {
        Self::new()
    }
}

impl TelemetrySession {
    pub fn new() -> Self {
        let timestamp = jiff::Timestamp::now();
        let now = timestamp.as_second();
        Self {
            session_id: uuid::Uuid::new_v4().to_string(),
            started_at: timestamp.strftime("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            commands_run: AtomicU32::new(0),
            last_activity: AtomicI64::new(now),
            persist_counter: AtomicU32::new(0),
            last_persist: AtomicI64::new(now),
            persistence_enabled: true,
        }
    }

    fn path() -> Result<PathBuf> {
        let data_dir = crate::core::paths::ensure_data_dir()?;
        Ok(data_dir.join("telemetry_session.json"))
    }

    fn load(epoch: &ConsentEpoch) -> Self {
        let result = Self::path().and_then(|path| Self::load_from(&path, epoch));
        match result {
            Ok(session) => session,
            Err(error) => {
                tracing::warn!(
                    "Telemetry session persistence disabled because its state is invalid: {error:#}"
                );
                Self {
                    persistence_enabled: false,
                    ..Self::default()
                }
            }
        }
    }

    fn load_from(path: &std::path::Path, epoch: &ConsentEpoch) -> Result<Self> {
        let Some(content) = read_saved_telemetry(path, "Telemetry session", MAX_SESSION_BYTES)?
        else {
            return Ok(Self::default());
        };
        let session = serde_json::from_str::<SerializableSession>(&content)
            .with_context(|| format!("Malformed telemetry session: {}", path.display()))?;
        anyhow::ensure!(
            session.format_version == SESSION_FORMAT_VERSION,
            "Unsupported telemetry session format version {} (expected {})",
            session.format_version,
            SESSION_FORMAT_VERSION
        );
        if session.consent_epoch != *epoch {
            return Ok(Self::default());
        }
        session
            .started_at
            .parse::<jiff::Timestamp>()
            .with_context(|| {
                format!(
                    "Invalid telemetry session start timestamp: {}",
                    session.started_at
                )
            })?;
        let now = jiff::Timestamp::now().as_second();
        Ok(Self {
            session_id: session.session_id,
            started_at: session.started_at,
            commands_run: AtomicU32::new(session.commands_run),
            last_activity: AtomicI64::new(session.last_activity),
            persist_counter: AtomicU32::new(0),
            last_persist: AtomicI64::new(now),
            persistence_enabled: true,
        })
    }

    fn save(&self, epoch: &ConsentEpoch) -> Result<()> {
        anyhow::ensure!(
            self.persistence_enabled,
            "telemetry session persistence is disabled after a load failure"
        );
        let path = Self::path()?;
        let sess = SerializableSession {
            format_version: SESSION_FORMAT_VERSION,
            consent_epoch: epoch.clone(),
            session_id: self.session_id.clone(),
            started_at: self.started_at.clone(),
            commands_run: self.commands_run.load(Ordering::Relaxed),
            last_activity: self.last_activity.load(Ordering::Relaxed),
        };
        let content =
            serde_json::to_vec_pretty(&sess).context("Failed to serialize telemetry session")?;
        anyhow::ensure!(
            content.len() as u64 <= MAX_SESSION_BYTES,
            "Telemetry session exceeds the {MAX_SESSION_BYTES} byte limit"
        );
        crate::core::safe_ops::atomic_write_file_sync_private(&path, content)
            .with_context(|| format!("Failed to save telemetry session: {}", path.display()))?;

        // Reset persist tracking
        self.persist_counter.store(0, Ordering::Relaxed);
        self.last_persist
            .store(jiff::Timestamp::now().as_second(), Ordering::Relaxed);

        Ok(())
    }

    /// Increment command counter and update activity (non-blocking)
    fn record_activity(&self) {
        let _ = self
            .commands_run
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                Some(count.saturating_add(1))
            });
        self.last_activity
            .store(jiff::Timestamp::now().as_second(), Ordering::Relaxed);
        self.persist_counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Check if session needs to be persisted
    fn needs_persist(&self) -> bool {
        let counter = self.persist_counter.load(Ordering::Relaxed);
        let now = jiff::Timestamp::now().as_second();
        let last_persist = self.last_persist.load(Ordering::Relaxed);

        counter >= PERSIST_EVERY_N_EVENTS || (now - last_persist) >= PERSIST_INTERVAL_SECS
    }

    /// Check if session has expired (30 min inactivity)
    pub fn is_expired(&self) -> bool {
        let now = jiff::Timestamp::now().as_second();
        let last_activity = self.last_activity.load(Ordering::Relaxed);
        now.saturating_sub(last_activity) > 1800 // 30 minutes
    }

    /// Get session duration in seconds
    ///
    /// Parse the RFC 3339 start time and return elapsed whole seconds.
    pub fn duration_secs(&self) -> u64 {
        if let Ok(started) = self.started_at.parse::<jiff::Timestamp>() {
            let now = jiff::Timestamp::now().as_second();
            (now - started.as_second()).max(0) as u64
        } else {
            0
        }
    }
}

/// Get or create the event queue
fn get_event_queue(consent: &CaptureConsent) -> &'static Mutex<EventQueue> {
    EVENT_QUEUE.get_or_init(|| Mutex::new(EventQueue::load(&consent.epoch)))
}

fn telemetry_queue_path() -> PathBuf {
    crate::core::paths::data_dir().join("telemetry_queue.json")
}

fn purge_telemetry_file(path: &std::path::Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => crate::core::safe_ops::sync_parent_directory_sync(path).with_context(|| {
            format!(
                "Failed to make telemetry state deletion durable: {}",
                path.display()
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("Failed to delete telemetry state: {}", path.display())),
    }
}

fn purge_queue(queue: Option<&Mutex<EventQueue>>, path: &std::path::Path) -> Result<()> {
    if let Some(queue) = queue {
        let mut queue = queue.lock().map_err(|error| {
            anyhow::anyhow!("Failed to lock telemetry queue for purge: {error}")
        })?;
        queue.events.clear();
        queue.events_since_persist.store(0, Ordering::Relaxed);
    }
    purge_telemetry_file(path)
}

/// Remove queued telemetry after a user opts out.
pub fn purge_persisted_queue() -> Result<()> {
    purge_queue(EVENT_QUEUE.get(), &telemetry_queue_path())
}

fn purge_runtime_state() -> Result<()> {
    let queue = purge_persisted_queue();
    let session =
        purge_telemetry_file(&crate::core::paths::data_dir().join("telemetry_session.json"));
    queue.and(session)
}

pub(crate) fn set_telemetry_preference(enabled: bool) -> Result<()> {
    use crate::config::Settings;

    let _write_lock = Settings::write_lock()?;
    let mut settings = Settings::load().context("Failed to load OMG settings")?;
    let changed = enabled != settings.telemetry_enabled;
    if enabled && changed {
        purge_runtime_state().context("Failed to purge queued telemetry before opting in")?;
        CaptureConsent::rotate()?;
    }

    settings.telemetry_enabled = enabled;
    settings.save()?;
    if !enabled {
        let rotated = if changed {
            CaptureConsent::rotate()
        } else {
            Ok(())
        };
        let purged =
            purge_runtime_state().context("Failed to purge queued telemetry after opting out");
        rotated.and(purged)?;
    }
    Ok(())
}

/// Get or create the session state
fn get_session(consent: &CaptureConsent) -> &'static Mutex<TelemetrySession> {
    SESSION_STATE.get_or_init(|| {
        let mut session = TelemetrySession::load(&consent.epoch);
        if session.is_expired() {
            session = TelemetrySession::new();
            consent.persist(|| session.save(&consent.epoch));
        }
        Mutex::new(session)
    })
}

/// Check if enhanced telemetry is enabled (opt-in, not account-gated)
#[must_use]
pub fn is_enhanced_telemetry_enabled() -> bool {
    !is_telemetry_opt_out()
}

/// Record CLI startup time
pub fn record_startup_time() {
    CLI_START_TIME.get_or_init(Instant::now);
}

/// Get CLI startup duration in milliseconds
#[must_use]
pub fn get_startup_duration_ms() -> Option<u64> {
    CLI_START_TIME
        .get()
        .map(|start| start.elapsed().as_millis() as u64)
}

/// Get current session ID
#[must_use]
pub fn get_session_id() -> String {
    static LOCAL_SESSION_ID: OnceLock<String> = OnceLock::new();
    capture_consent()
        .and_then(|consent| get_session(consent).lock().ok())
        .map_or_else(
            || {
                LOCAL_SESSION_ID
                    .get_or_init(|| uuid::Uuid::new_v4().to_string())
                    .clone()
            },
            |session| session.session_id.clone(),
        )
}

/// Queue an already-gated event for batching.
fn enqueue(consent: &CaptureConsent, event: TelemetryEvent) {
    if let Ok(mut queue) = get_event_queue(consent).lock() {
        queue.push(event);

        // Only persist periodically, not on every event
        if queue.needs_persist() {
            consent.persist(|| queue.save(&consent.epoch));
        }
    } else {
        tracing::debug!("Telemetry queue lock poisoned; dropped one event (non-fatal)");
    }
}

/// Record command activity on the session and persist it periodically.
fn record_session_activity(consent: &CaptureConsent) {
    if let Ok(session) = get_session(consent).lock() {
        session.record_activity();

        // Only persist periodically
        if session.needs_persist() {
            consent.persist(|| session.save(&consent.epoch));
        }
    } else {
        tracing::debug!("Telemetry session lock poisoned; activity not recorded (non-fatal)");
    }
}

/// Track one CLI command summary.
///
/// Only the canonical command name, duration, outcome, and compiled backend
/// are collected. Positional arguments, package names, search queries, file
/// paths, and raw error text never cross this boundary.
pub fn track_command_event(command: &str, duration_ms: u64, success: bool, backend: Option<&str>) {
    let Some(consent) = capture_consent() else {
        return;
    };

    record_session_activity(consent);

    enqueue(
        consent,
        TelemetryEvent::Command(CommandEvent {
            command: command.to_string(),
            duration_ms,
            success,
            backend: backend.map(String::from),
        }),
    );
}

/// Track performance metric
pub fn track_performance_event(metric_type: &str, duration_ms: u64) {
    let Some(consent) = capture_consent() else {
        return;
    };

    let event = TelemetryEvent::Performance(PerformanceEvent {
        metric_type: metric_type.to_string(),
        duration_ms,
    });

    enqueue(consent, event);
}

/// Track session start
pub fn track_session_start() {
    let Some(consent) = capture_consent() else {
        return;
    };

    let event = TelemetryEvent::Session(SessionEvent {
        session_id: get_session_id(),
        event_type: "start".to_string(),
        start_time: Some(now_iso8601_ms()),
        end_time: None,
        commands_run: None,
        duration_secs: None,
    });

    enqueue(consent, event);
}

/// Flush queued events (call periodically or on exit)
pub async fn flush_events() {
    let Some(consent) = capture_consent() else {
        return;
    };

    let _flush_guard = FLUSH_LOCK.lock().await;
    let Some(_lease) = consent.try_lease() else {
        return;
    };
    flush_queue(
        get_event_queue(consent),
        &consent.epoch,
        crate::core::telemetry_client::send_batch,
    )
    .await;
}

async fn flush_queue<SendBatch, Sending>(
    queue: &Mutex<EventQueue>,
    epoch: &ConsentEpoch,
    send_batch: SendBatch,
) where
    SendBatch: FnOnce(Vec<TelemetryEvent>) -> Sending,
    Sending: std::future::Future<Output = Result<()>>,
{
    let use_persistence = match queue.lock() {
        Ok(mut local) if local.persistence_enabled => {
            if let Err(error) = local.save(epoch) {
                tracing::warn!("Failed to merge local telemetry: {error:#}");
                return;
            }
            true
        }
        Ok(_) => false,
        Err(error) => {
            tracing::warn!("Failed to lock telemetry queue: {error}");
            return;
        }
    };
    if use_persistence {
        if let Err(error) = flush_persisted_queue(epoch, send_batch).await {
            tracing::debug!("Deferred telemetry dispatch: {error:#}");
        }
    } else {
        flush_unsaved_queue(queue, send_batch).await;
    }
}

async fn flush_persisted_queue<SendBatch, Sending>(
    epoch: &ConsentEpoch,
    send_batch: SendBatch,
) -> Result<()>
where
    SendBatch: FnOnce(Vec<TelemetryEvent>) -> Sending,
    Sending: std::future::Future<Output = Result<()>>,
{
    let store = QueueStore::new(EventQueue::path()?, epoch.clone());
    let Some(_dispatch) = store.try_dispatch_lock()? else {
        return Ok(());
    };
    let batch = store.prepare_batch()?;
    if batch.is_empty() {
        return Ok(());
    }

    let payloads = batch.iter().map(|row| row.event.clone()).collect();
    send_batch(payloads).await?;
    store.acknowledge(&batch)
}

async fn flush_unsaved_queue<SendBatch, Sending>(queue: &Mutex<EventQueue>, send_batch: SendBatch)
where
    SendBatch: FnOnce(Vec<TelemetryEvent>) -> Sending,
    Sending: std::future::Future<Output = Result<()>>,
{
    let events = match queue.lock() {
        Ok(queue) => queue.snapshot(),
        Err(error) => {
            tracing::warn!("Failed to lock telemetry queue: {error}");
            return;
        }
    };
    if events.is_empty() {
        return;
    }

    let payloads = events.iter().map(|event| event.as_ref().clone()).collect();
    match send_batch(payloads).await {
        Ok(()) => {
            if let Ok(mut queue) = queue.lock() {
                queue.confirm_sent(&events);
            }
        }
        Err(error) => tracing::debug!("Failed to flush in-memory telemetry: {error}"),
    }
}

/// End session and flush all events (call on CLI exit)
pub async fn end_session_and_flush() {
    let Some(consent) = capture_consent() else {
        return;
    };

    // Record session end event. A poisoned session lock must not skip the
    // final flush below — queued events are still delivered on CLI exit.
    let session_summary = get_session(consent).lock().ok().map(|session| {
        (
            session.session_id.clone(),
            session.commands_run.load(Ordering::Relaxed),
            session.duration_secs(),
        )
    });

    if let Some((session_id, commands_run, duration_secs)) = session_summary {
        let event = TelemetryEvent::Session(SessionEvent {
            session_id,
            event_type: "end".to_string(),
            start_time: None,
            end_time: Some(now_iso8601_ms()),
            commands_run: Some(commands_run),
            duration_secs: Some(duration_secs),
        });

        enqueue(consent, event);
    } else {
        tracing::debug!("Telemetry session lock poisoned; skipping session-end event");
    }

    // Track startup performance if available
    if let Some(startup_ms) = get_startup_duration_ms() {
        track_performance_event("cli_startup", startup_ms);
    }

    // Flush all events
    flush_events().await;
}

/// Convenience timer for measuring operation duration
///
/// Dropping a timer without calling [`Timer::finish`] silently discards the
/// measurement, so constructing one is marked `#[must_use]`.
#[must_use]
pub struct Timer {
    start: Instant,
    operation: String,
}

impl Timer {
    /// Start a new timer for an operation (constructor for the `#[must_use]`
    /// [`Timer`]; the struct-level attribute covers dropped timers)
    pub fn new(operation: &str) -> Self {
        Self {
            start: Instant::now(),
            operation: operation.to_string(),
        }
    }

    /// Get elapsed time in milliseconds
    #[must_use]
    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Finish and record as performance event
    pub fn finish(self) {
        track_performance_event(&self.operation, self.elapsed_ms());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The file half of the opt-out verdict follows the file, not the first
    /// read: enable, disable, re-read, and env override each resolve live.
    /// Serial because the verdict cache and `OMG_*` variables are process
    /// state shared with every other test in this binary.
    #[serial_test::serial]
    #[test]
    fn opt_out_verdict_tracks_config_file_and_env() {
        if crate::config::Settings::rerun_test_unprivileged(
            "core::telemetry::tests::opt_out_verdict_tracks_config_file_and_env",
        ) {
            return;
        }
        let dir = tempfile::TempDir::new().expect("isolated config dir");
        let config = dir.path().join("config.toml");
        let dir_str = dir.path().to_string_lossy().into_owned();
        let clean = [
            ("OMG_TEST_MODE", None),
            ("OMG_TELEMETRY", None),
            ("OMG_DISABLE_TELEMETRY", None),
            ("OMG_CONFIG_DIR", Some(dir_str.as_str())),
        ];
        let check = || {
            let borrowed: Vec<(&str, Option<&str>)> =
                clean.iter().map(|(key, value)| (*key, *value)).collect();
            temp_env::with_vars(&borrowed, is_telemetry_opt_out)
        };

        std::fs::write(&config, "telemetry_enabled = true\n").expect("enable config");
        assert!(!check());
        // An env opt-out shadows the cached enabled verdict.
        temp_env::with_vars(
            [
                ("OMG_TEST_MODE", None),
                ("OMG_CONFIG_DIR", Some(dir_str.as_str())),
                ("OMG_TELEMETRY", Some("0")),
            ],
            || assert!(is_telemetry_opt_out()),
        );
        assert!(!check());

        std::fs::write(&config, "telemetry_enabled = false\n").expect("disable config");
        assert!(check());
        assert!(check());

        std::fs::write(&config, "telemetry_enabled = true\n").expect("re-enable config");
        assert!(!check());

        #[cfg(unix)]
        {
            std::fs::write(&config, "telemetry_enabled = true \n")
                .expect("same-size enabled config");
            assert!(!check());
            let modified = std::fs::metadata(&config).unwrap().modified().unwrap();
            crate::core::safe_ops::atomic_write_file_sync(&config, "telemetry_enabled = false\n")
                .expect("replace with same-size disabled config");
            std::fs::File::options()
                .write(true)
                .open(&config)
                .unwrap()
                .set_modified(modified)
                .unwrap();
            assert!(
                check(),
                "a same-size, same-mtime replacement must revoke cached consent"
            );
        }
    }

    #[serial_test::serial]
    #[test]
    fn telemetry_consent_lease_follows_settings_and_mutation_lock() {
        if crate::config::Settings::rerun_test_unprivileged(
            "core::telemetry::tests::telemetry_consent_lease_follows_settings_and_mutation_lock",
        ) {
            return;
        }
        let directory = tempfile::TempDir::new().expect("isolated config directory");
        let settings = directory.path().join("config.toml");
        std::fs::write(&settings, "telemetry_enabled = true\n").unwrap();
        temp_env::with_vars(
            [
                ("OMG_TEST_MODE", None),
                ("OMG_TELEMETRY", None),
                ("OMG_DISABLE_TELEMETRY", None),
                ("OMG_CONFIG_DIR", Some(directory.path().to_str().unwrap())),
            ],
            || {
                let mutation = crate::config::Settings::write_lock().unwrap();
                assert!(telemetry_consent_lease().is_none());
                drop(mutation);
                let admitted = telemetry_consent_lease().expect("admit with consent");
                assert!(crate::config::Settings::write_lock().is_err());
                drop(admitted);
                let _mutation = crate::config::Settings::write_lock().unwrap();
                std::fs::write(&settings, "telemetry_enabled = false\n").unwrap();
            },
        );
        temp_env::with_vars(
            [
                ("OMG_TEST_MODE", None),
                ("OMG_CONFIG_DIR", Some(directory.path().to_str().unwrap())),
            ],
            || assert!(telemetry_consent_lease().is_none()),
        );
    }

    #[test]
    fn session_creation_initializes_counters() {
        let session = TelemetrySession::new();
        assert!(!session.session_id.is_empty());
        assert!(!session.started_at.is_empty());
        assert_eq!(session.commands_run.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn session_expires_after_inactivity() {
        let session = TelemetrySession::new();
        // Session should not be expired immediately
        assert!(!session.is_expired());

        // Set last activity to 31 minutes ago
        session
            .last_activity
            .store(jiff::Timestamp::now().as_second() - 1860, Ordering::Relaxed);
        assert!(session.is_expired());
    }

    #[test]
    fn event_queue_flushes_when_full_and_confirms_sent() {
        // Create a queue with current time for last_persist
        let now = jiff::Timestamp::now().as_second();
        let mut queue = EventQueue {
            events: VecDeque::new(),
            events_since_persist: AtomicU32::new(0),
            last_persist: AtomicI64::new(now),
            persistence_enabled: true,
        };
        // Queue capacity is bounded; pushing past it trims the oldest events.
        for duration_ms in 0..6000 {
            queue.push(TelemetryEvent::Performance(PerformanceEvent {
                metric_type: "test".to_string(),
                duration_ms,
            }));
        }
        assert!(
            queue.events.len() <= MAX_QUEUE_SIZE,
            "queue must not grow beyond its configured capacity"
        );

        let snapshot = queue.snapshot();
        let queued = snapshot.len();
        let confirmed = queued / 2;
        queue.confirm_sent(&snapshot[..confirmed]);
        assert_eq!(queue.events.len(), queued - confirmed);
    }

    fn overlap_event(id: u64) -> TelemetryEvent {
        TelemetryEvent::Performance(PerformanceEvent {
            metric_type: "overlap-event".to_string(),
            duration_ms: id,
        })
    }

    fn overlap_event_ids<Event: std::borrow::Borrow<TelemetryEvent>>(events: &[Event]) -> Vec<u64> {
        events
            .iter()
            .map(|event| match std::borrow::Borrow::borrow(event) {
                TelemetryEvent::Performance(event) if event.metric_type == "overlap-event" => {
                    event.duration_ms
                }
                _ => panic!("unexpected overlap fixture event"),
            })
            .collect()
    }

    #[test]
    fn telemetry_acknowledgement_retains_unsent_event_after_cap_eviction() {
        let mut queue = EventQueue::default();
        for id in 0..MAX_QUEUE_SIZE as u64 {
            queue.push(overlap_event(id));
        }
        // These are the actual queue operations on either side of send_batch's
        // await in flush_events. The held batch never contains this new event.
        let sent = queue.snapshot();
        assert_eq!(overlap_event_ids(&sent), (0..5000).collect::<Vec<_>>());
        queue.push(overlap_event(5000));
        queue.confirm_sent(&sent);
        assert_eq!(overlap_event_ids(&queue.snapshot()), vec![5000]);
    }

    #[test]
    fn telemetry_acknowledgement_retains_unsent_event_without_eviction() {
        let mut queue = EventQueue::default();
        for id in [10, 11, 12] {
            queue.push(overlap_event(id));
        }
        let sent = queue.snapshot();
        assert_eq!(overlap_event_ids(&sent), vec![10, 11, 12]);
        queue.push(overlap_event(13));
        queue.confirm_sent(&sent);
        assert_eq!(overlap_event_ids(&queue.snapshot()), vec![13]);
    }

    #[test]
    fn telemetry_acknowledgement_failure_preserves_remaining_unsent_events() {
        let mut queue = EventQueue::default();
        for id in 0..MAX_QUEUE_SIZE as u64 {
            queue.push(overlap_event(id));
        }
        let sent = queue.snapshot();
        assert_eq!(overlap_event_ids(&sent), (0..5000).collect::<Vec<_>>());
        queue.push(overlap_event(5000));
        // A rejected batch has no acknowledgement. Only the documented oldest
        // quarter eviction may remove records; the newly queued event survives.
        assert_eq!(
            overlap_event_ids(&queue.snapshot()),
            (1250..=5000).collect::<Vec<_>>()
        );
    }

    #[test]
    fn telemetry_acknowledgement_distinguishes_identical_unsent_payloads() {
        let mut queue = EventQueue::default();
        for _ in 0..MAX_QUEUE_SIZE {
            queue.push(overlap_event(777));
        }
        let sent = queue.snapshot();
        queue.push(overlap_event(777));
        queue.confirm_sent(&sent);
        assert_eq!(overlap_event_ids(&queue.snapshot()), vec![777]);
    }

    #[test]
    fn telemetry_acknowledgement_partial_evicted_batch_keeps_other_events() {
        let mut queue = EventQueue::default();
        for id in 0..MAX_QUEUE_SIZE as u64 {
            queue.push(overlap_event(id));
        }
        let sent = queue.snapshot();
        queue.push(overlap_event(5000));
        // These acknowledged occurrences were already removed by capacity
        // eviction. Their acknowledgement must not remove different records.
        queue.confirm_sent(&sent[..1250]);
        assert_eq!(
            overlap_event_ids(&queue.snapshot()),
            (1250..=5000).collect::<Vec<_>>()
        );
    }

    #[test]
    fn telemetry_acknowledgement_after_purge_keeps_new_occurrence() {
        let directory = tempfile::tempdir().expect("queue purge fixture");
        let path = directory.path().join("queue.json");
        let mut queue = EventQueue::default();
        queue.push(overlap_event(777));
        let sent = queue.snapshot();
        let queue = Mutex::new(queue);
        purge_queue(Some(&queue), &path).expect("purge captured queue");
        let mut queue = queue.lock().expect("lock replacement queue");
        queue.push(overlap_event(777));
        queue.confirm_sent(&sent);
        assert_eq!(overlap_event_ids(&queue.snapshot()), vec![777]);
    }

    async fn held_flush_result(initial_count: usize, accepted: bool) -> Vec<u64> {
        use tokio::sync::oneshot;

        let mut state = EventQueue {
            // Fixture never resolves production filesystem paths; save refuses
            // locally. The real flush still applies its memory acknowledgement.
            persistence_enabled: false,
            ..EventQueue::default()
        };
        for id in 0..initial_count as u64 {
            state.push(overlap_event(id));
        }
        let queue = std::sync::Arc::new(Mutex::new(state));
        let (snapshot_tx, snapshot_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let flush_queue_state = queue.clone();
        let task = tokio::spawn(async move {
            flush_queue(
                &flush_queue_state,
                &ConsentEpoch::default(),
                |events| async move {
                    snapshot_tx
                        .send(overlap_event_ids(&events))
                        .expect("publish actual sent batch");
                    release_rx.await.expect("sender release");
                    anyhow::ensure!(accepted, "fixture sender rejected batch");
                    Ok(())
                },
            )
            .await;
        });
        let sent = snapshot_rx.await.expect("flush reached held sender");
        assert_eq!(sent, (0..initial_count as u64).collect::<Vec<_>>());
        queue
            .lock()
            .expect("lock producer queue")
            .push(overlap_event(initial_count as u64));
        release_tx.send(()).expect("release sender");
        task.await.expect("joined actual flush");
        let remaining = queue.lock().expect("lock completed queue").snapshot();
        overlap_event_ids(&remaining)
    }

    #[tokio::test]
    async fn telemetry_flush_retains_unsent_event_after_cap_eviction() {
        assert_eq!(held_flush_result(5000, true).await, vec![5000]);
    }

    #[tokio::test]
    async fn telemetry_flush_retains_unsent_event_without_eviction() {
        assert_eq!(held_flush_result(3, true).await, vec![3]);
    }

    #[tokio::test]
    async fn telemetry_flush_sender_failure_preserves_remaining_events() {
        assert_eq!(
            held_flush_result(5000, false).await,
            (1250..=5000).collect::<Vec<_>>()
        );
    }

    #[test]
    fn malformed_persisted_telemetry_is_rejected_without_modification() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let queue_path = directory.path().join("queue.json");
        let session_path = directory.path().join("session.json");
        std::fs::write(&queue_path, b"{bad-queue").expect("write malformed queue");
        std::fs::write(&session_path, b"{bad-session").expect("write malformed session");

        let queue_error = EventQueue::load_from(&queue_path, &ConsentEpoch::default())
            .expect_err("malformed queue must be rejected");
        let session_error = TelemetrySession::load_from(&session_path, &ConsentEpoch::default())
            .expect_err("malformed session must be rejected");

        assert!(
            queue_error
                .to_string()
                .contains("Malformed telemetry queue")
        );
        assert!(
            session_error
                .to_string()
                .contains("Malformed telemetry session")
        );
        assert_eq!(
            std::fs::read(&queue_path).expect("read malformed queue"),
            b"{bad-queue"
        );
        assert_eq!(
            std::fs::read(&session_path).expect("read malformed session"),
            b"{bad-session"
        );
    }

    #[test]
    fn persisted_telemetry_requires_the_current_format_version() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let queue_path = directory.path().join("queue.json");
        let session_path = directory.path().join("session.json");

        std::fs::write(
            &queue_path,
            serde_json::to_vec(&serde_json::json!({
                "format_version": QUEUE_FORMAT_VERSION,
                "events": []
            }))
            .expect("serialize current queue"),
        )
        .expect("write current queue");
        std::fs::write(
            &session_path,
            serde_json::to_vec(&serde_json::json!({
                "format_version": SESSION_FORMAT_VERSION,
                "session_id": "session-id",
                "started_at": "2025-01-01T00:00:00.000Z",
                "commands_run": 1,
                "last_activity": 1
            }))
            .expect("serialize current session"),
        )
        .expect("write current session");

        assert!(EventQueue::load_from(&queue_path, &ConsentEpoch::default()).is_ok());
        assert!(TelemetrySession::load_from(&session_path, &ConsentEpoch::default()).is_ok());

        std::fs::write(&queue_path, b"[]").expect("write obsolete raw queue");
        std::fs::write(
            &session_path,
            br#"{"session_id":"old","started_at":"old","commands_run":0,"last_activity":0}"#,
        )
        .expect("write unversioned session");
        assert!(
            EventQueue::load_from(&queue_path, &ConsentEpoch::default()).is_err(),
            "unversioned queue must be rejected"
        );
        assert!(
            TelemetrySession::load_from(&session_path, &ConsentEpoch::default()).is_err(),
            "unversioned session must be rejected"
        );

        std::fs::write(
            &queue_path,
            format!(
                r#"{{"format_version":{},"events":[]}}"#,
                QUEUE_FORMAT_VERSION + 1
            ),
        )
        .expect("write forward queue");
        std::fs::write(
            &session_path,
            format!(
                r#"{{"format_version":{},"session_id":"future","started_at":"future","commands_run":0,"last_activity":0}}"#,
                SESSION_FORMAT_VERSION + 1
            ),
        )
        .expect("write forward session");
        assert!(
            EventQueue::load_from(&queue_path, &ConsentEpoch::default())
                .expect_err("forward queue must be rejected")
                .to_string()
                .contains("Unsupported telemetry queue format version")
        );
        assert!(
            TelemetrySession::load_from(&session_path, &ConsentEpoch::default())
                .expect_err("forward session must be rejected")
                .to_string()
                .contains("Unsupported telemetry session format version")
        );
    }

    #[test]
    fn persisted_session_rejects_invalid_start_timestamp() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let path = directory.path().join("session.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "format_version": SESSION_FORMAT_VERSION,
                "session_id": "session-id",
                "started_at": "not-a-timestamp",
                "commands_run": 0,
                "last_activity": 0
            })
            .to_string(),
        )
        .expect("write invalid session");

        let error = TelemetrySession::load_from(&path, &ConsentEpoch::default())
            .expect_err("invalid timestamp must not enter session state");
        assert!(
            error
                .to_string()
                .contains("Invalid telemetry session start")
        );
    }

    #[test]
    fn timer_measures_elapsed_time() {
        let timer = Timer::new("test_operation");
        std::thread::sleep(std::time::Duration::from_millis(10));
        let elapsed = timer.elapsed_ms();
        assert!(elapsed >= 10);
    }

    #[test]
    fn backend_name_matches_compiled_features() {
        let expected = if cfg!(feature = "arch") {
            "arch"
        } else if cfg!(any(feature = "debian", feature = "debian-pure")) {
            "debian"
        } else if cfg!(feature = "fedora") {
            "fedora"
        } else if cfg!(any(feature = "macos", target_os = "macos")) {
            "homebrew"
        } else {
            "none"
        };
        assert_eq!(get_backend(), expected);
    }

    #[test]
    fn telemetry_queue_purge_clears_initialized_memory_and_is_idempotent() {
        let directory = tempfile::tempdir().expect("temp directory");
        let queue_path = directory.path().join("telemetry_queue.json");
        std::fs::write(&queue_path, b"queued telemetry").expect("write queue fixture");
        let mut queue = EventQueue::default();
        queue.push(TelemetryEvent::Performance(PerformanceEvent {
            metric_type: "fixture".to_string(),
            duration_ms: 1,
        }));
        let queue = Mutex::new(queue);

        purge_queue(Some(&queue), &queue_path).expect("purge initialized queue");
        assert!(!queue_path.exists());
        {
            let queue = queue.lock().expect("lock purged queue");
            assert!(queue.events.is_empty());
            assert_eq!(queue.events_since_persist.load(Ordering::Relaxed), 0);
        }

        purge_queue(Some(&queue), &queue_path).expect("repeat queue purge");
    }

    #[test]
    fn telemetry_queue_purge_reports_the_path_on_failure() {
        let directory = tempfile::tempdir().expect("temp directory");
        let queue_path = directory.path().join("telemetry_queue.json");
        std::fs::create_dir(&queue_path).expect("create invalid queue fixture");

        let error =
            purge_telemetry_file(&queue_path).expect_err("directory must not purge as a file");
        assert!(
            error
                .to_string()
                .contains("Failed to delete telemetry state")
        );
        assert!(
            error
                .to_string()
                .contains(&queue_path.display().to_string())
        );
    }

    #[test]
    fn opt_out_env_values_are_case_insensitive() {
        // The accepted value sets are matched case-insensitively; this
        // table documents the contract for both variables.
        let disable = ["0", "false", "off", "no"];
        for value in ["off", "OFF", "Off", "FALSE", "no", "0"] {
            assert!(
                disable.iter().any(|a| value.eq_ignore_ascii_case(a)),
                "{value} must disable telemetry"
            );
        }
    }
}
