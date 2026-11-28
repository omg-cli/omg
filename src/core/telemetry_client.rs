//! Telemetry API client for OMG
//!
//! Sends persisted telemetry batches to the API with a cancellation-safe
//! circuit breaker. Queueing and retry persistence live in `core::telemetry`;
//! this module owns only the network boundary and wire payloads.
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::core::license::get_machine_id;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

// Circuit breaker constants
const CIRCUIT_FAILURE_THRESHOLD: u32 = 5; // Open circuit after 5 consecutive failures
const CIRCUIT_OPEN_DURATION_SECS: u64 = 300; // Stay open for 5 minutes (300s)

/// Circuit breaker states: 0 = Closed, 1 = Open, 2 = Half-Open
static CIRCUIT_STATE: AtomicU32 = AtomicU32::new(0);

/// Consecutive failure count for circuit breaker
static FAILURE_COUNT: AtomicU32 = AtomicU32::new(0);

/// Single-flight flag for half-open probes: only one request may probe the
/// recovering endpoint at a time; all others stay queued while it is in
/// flight (otherwise every queued event would probe concurrently).
static HALF_OPEN_PROBE_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// Timestamp of last failure (Unix epoch seconds as u64)
static LAST_FAILURE: AtomicU64 = AtomicU64::new(0);

/// Command-level telemetry event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandEvent {
    /// Command name (e.g., "install", "search", "update")
    pub command: String,
    /// Duration in milliseconds
    pub duration_ms: u64,
    /// Whether the command succeeded
    pub success: bool,
    /// Compiled package-manager backend.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
}

/// Session tracking event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEvent {
    /// Session ID (UUID)
    pub session_id: String,
    /// Event type: "start", "heartbeat", "end"
    pub event_type: String,
    /// Session start timestamp (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<String>,
    /// Session end timestamp (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<String>,
    /// Commands run in this session
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commands_run: Option<u32>,
    /// Duration in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<u64>,
}

/// Performance metrics event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceEvent {
    /// Metric type: "startup", "search", "install", "sync", etc.
    pub metric_type: String,
    /// Duration in milliseconds
    pub duration_ms: u64,
}

/// Feature usage event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureEvent {
    /// Feature name: "daemon", "parallel", "sbom", "fleet", "aur", etc.
    pub feature: String,
    /// Whether the feature is enabled/used
    pub enabled: bool,
}

/// Unified telemetry event wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TelemetryEvent {
    Command(CommandEvent),
    Session(SessionEvent),
    Performance(PerformanceEvent),
    Feature(FeatureEvent),
}

/// Telemetry event with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryPayload {
    /// The event data
    pub event: TelemetryEvent,
    /// Timestamp (ISO 8601)
    pub timestamp: String,
    /// Machine ID
    pub machine_id: String,
    /// OMG version
    pub version: String,
    /// Platform (e.g., "linux-x86_64")
    pub platform: String,
    /// License key fingerprint (if this machine is linked to the dashboard).
    /// A truncated SHA-256, never the raw key: the raw key is a bearer
    /// credential and must not land in ingestion logs or queues.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_key: Option<String>,
}

/// Batch telemetry payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchPayload {
    /// List of events
    pub events: Vec<TelemetryPayload>,
    /// Batch timestamp
    pub batch_timestamp: String,
    /// Machine ID
    pub machine_id: String,
}

impl TelemetryPayload {
    /// Create a new telemetry payload
    #[must_use]
    pub fn new(event: TelemetryEvent) -> Self {
        let license = crate::core::license::load_license();

        Self {
            event,
            timestamp: jiff::Timestamp::now()
                .strftime("%Y-%m-%dT%H:%M:%S%.3fZ")
                .to_string(),
            machine_id: get_machine_id(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            license_key: license.map(|l| {
                use sha2::Digest as _;
                hex::encode(sha2::Sha256::digest(l.key.as_bytes()))[..16].to_string()
            }),
        }
    }
}

/// Circuit breaker state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitState {
    Closed = 0,
    Open = 1,
    HalfOpen = 2,
}

impl From<u32> for CircuitState {
    fn from(value: u32) -> Self {
        match value {
            1 => CircuitState::Open,
            2 => CircuitState::HalfOpen,
            _ => CircuitState::Closed, // 0 or invalid values default to Closed
        }
    }
}

/// Check circuit breaker state and update if needed
///
/// Returns the observed state plus, when THIS call performed the
/// open→half-open transition, a [`HalfOpenProbeGuard`] claiming the
/// single-flight probe slot. The caller must keep the guard alive for the
/// duration of the probe request: dropping it (including via task
/// cancellation at an await point) releases the slot so the breaker can try
/// again instead of latching Open forever.
fn check_circuit_breaker() -> (CircuitState, Option<HalfOpenProbeGuard>) {
    let current_state = CircuitState::from(CIRCUIT_STATE.load(Ordering::Relaxed));

    match current_state {
        CircuitState::Closed => (CircuitState::Closed, None),
        CircuitState::Open => {
            // Check if enough time has passed to try again (half-open)
            let last_failure = LAST_FAILURE.load(Ordering::Relaxed);
            let now = jiff::Timestamp::now().as_second() as u64;

            if now.saturating_sub(last_failure) >= CIRCUIT_OPEN_DURATION_SECS {
                // Transition to half-open with single-flight semantics: the
                // first caller wins the probe slot; concurrent callers stay
                // queued until the probe resolves (record_success/failure)
                // or is cancelled (guard drop).
                if HALF_OPEN_PROBE_IN_FLIGHT
                    .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    // Relaxed is sufficient here: the latch itself is the
                    // single-flight primitive (the CAS provides the mutual
                    // exclusion); no other data is published through it.
                    CIRCUIT_STATE.store(CircuitState::HalfOpen as u32, Ordering::Relaxed);
                    tracing::debug!("Circuit breaker transitioning to half-open state");
                    (CircuitState::HalfOpen, Some(HalfOpenProbeGuard))
                } else {
                    (CircuitState::Open, None)
                }
            } else {
                (CircuitState::Open, None)
            }
        }
        CircuitState::HalfOpen => (CircuitState::HalfOpen, None),
    }
}

/// RAII claim on the half-open single-flight probe slot.
///
/// Releasing via `Drop` guarantees the slot frees even when the probe future
/// is cancelled or times out, which previously left the breaker latched Open
/// until process exit.
struct HalfOpenProbeGuard;

impl Drop for HalfOpenProbeGuard {
    fn drop(&mut self) {
        HALF_OPEN_PROBE_IN_FLIGHT.store(false, Ordering::Relaxed);
        // If the probe is still unresolved (cancelled at an await point),
        // return the breaker to Open so the cooldown restarts. When the
        // probe completed first, record_success/record_failure already set
        // the final state; dropping the guard afterwards must not clobber it.
        if CircuitState::from(CIRCUIT_STATE.load(Ordering::Relaxed)) == CircuitState::HalfOpen {
            CIRCUIT_STATE.store(CircuitState::Open as u32, Ordering::Relaxed);
        }
    }
}

/// Whether a caller may cross the network boundary in the observed state.
/// A half-open request is allowed only for the caller that owns the single
/// probe slot.
const fn circuit_allows_request(state: CircuitState, owns_probe_slot: bool) -> bool {
    matches!(state, CircuitState::Closed)
        || (matches!(state, CircuitState::HalfOpen) && owns_probe_slot)
}

/// Record a successful request (reset circuit breaker)
fn record_success() {
    FAILURE_COUNT.store(0, Ordering::Relaxed);
    CIRCUIT_STATE.store(CircuitState::Closed as u32, Ordering::Relaxed);
    HALF_OPEN_PROBE_IN_FLIGHT.store(false, Ordering::Relaxed);
    tracing::debug!("Circuit breaker reset to closed state");
}

/// Record a failed request (increment failure count, possibly open circuit)
fn record_failure() {
    let failures = FAILURE_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    let now = jiff::Timestamp::now().as_second() as u64;
    LAST_FAILURE.store(now, Ordering::Relaxed);
    // Any in-flight half-open probe has now resolved (as a failure).
    HALF_OPEN_PROBE_IN_FLIGHT.store(false, Ordering::Relaxed);

    if failures >= CIRCUIT_FAILURE_THRESHOLD {
        CIRCUIT_STATE.store(CircuitState::Open as u32, Ordering::Relaxed);
        tracing::debug!("Circuit breaker opened after {failures} consecutive failures");
    } else {
        tracing::debug!("Circuit breaker failure count: {failures}/{CIRCUIT_FAILURE_THRESHOLD}");
    }
}

/// Send batched telemetry events with circuit breaker support
pub async fn send_batch(events: Vec<TelemetryEvent>) -> Result<()> {
    if !crate::core::telemetry::is_enhanced_telemetry_enabled() || events.is_empty() {
        return Ok(());
    }

    // Check circuit breaker state; hold any won probe-slot guard across the
    // batch request so cancellation cannot leak the latch.
    let (circuit_state, probe_guard) = check_circuit_breaker();

    if !circuit_allows_request(circuit_state, probe_guard.is_some()) {
        anyhow::bail!("Telemetry circuit breaker is {circuit_state:?}");
    }
    // Keep the half-open claim alive across the request. Its Drop releases
    // the single-flight slot if this future is cancelled at the await point.
    let _probe_guard = probe_guard;

    let payloads: Vec<TelemetryPayload> = events.into_iter().map(TelemetryPayload::new).collect();

    let batch = BatchPayload {
        events: payloads,
        batch_timestamp: jiff::Timestamp::now()
            .strftime("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string(),
        machine_id: get_machine_id(),
    };

    let client = crate::core::http::shared_client();

    let response = client
        .post(super::service_api::CLI_BATCH)
        .json(&batch)
        .timeout(REQUEST_TIMEOUT)
        .send()
        .await;

    match response {
        Ok(resp) if resp.status().is_success() => {
            tracing::debug!(
                "Telemetry batch sent successfully ({} events)",
                batch.events.len()
            );
            record_success();
            Ok(())
        }
        Ok(resp) => {
            let status = resp.status();
            tracing::debug!("Telemetry batch failed with status: {status}");
            record_failure();
            anyhow::bail!("Telemetry batch rejected with status {status}")
        }
        Err(error) => {
            tracing::debug!("Telemetry batch send error: {error}");
            record_failure();
            Err(error.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_creation_fills_metadata() {
        let event = TelemetryEvent::Command(CommandEvent {
            command: "install".to_string(),
            duration_ms: 1500,
            success: true,
            backend: Some("arch".to_string()),
        });

        let payload = TelemetryPayload::new(event);
        assert!(!payload.timestamp.is_empty());
        assert!(!payload.machine_id.is_empty());
        assert!(!payload.version.is_empty());
        assert!(!payload.platform.is_empty());
    }

    #[test]
    fn command_event_serializes_payload_fields() {
        let event = CommandEvent {
            command: "search".to_string(),
            duration_ms: 50,
            success: true,
            backend: Some("arch".to_string()),
        };

        let json = serde_json::to_string(&event).expect("serialization should succeed");
        assert!(json.contains("search"));
        assert!(json.contains("arch"));
        assert!(!json.contains("result_count"));
        assert!(!json.contains("packages"));
        assert!(!json.contains("error"));
    }

    #[test]
    fn session_event_serializes_session_fields() {
        let event = SessionEvent {
            session_id: "test-session-123".to_string(),
            event_type: "start".to_string(),
            start_time: Some("2024-01-01T00:00:00.000Z".to_string()),
            end_time: None,
            commands_run: None,
            duration_secs: None,
        };

        let json = serde_json::to_string(&event).expect("serialization should succeed");
        assert!(json.contains("test-session-123"));
        assert!(json.contains("start"));
    }

    #[test]
    fn circuit_permit_requires_ownership_in_half_open_state() {
        assert!(circuit_allows_request(CircuitState::Closed, false));
        assert!(circuit_allows_request(CircuitState::Closed, true));
        assert!(!circuit_allows_request(CircuitState::Open, false));
        assert!(!circuit_allows_request(CircuitState::Open, true));
        assert!(!circuit_allows_request(CircuitState::HalfOpen, false));
        assert!(circuit_allows_request(CircuitState::HalfOpen, true));
    }

    #[test]
    #[serial_test::serial]
    fn circuit_breaker_state_transitions_match_threshold() {
        // Reset state
        CIRCUIT_STATE.store(CircuitState::Closed as u32, Ordering::Relaxed);
        FAILURE_COUNT.store(0, Ordering::Relaxed);

        // Initially closed
        assert_eq!(check_circuit_breaker().0, CircuitState::Closed);

        // Record failures to open circuit
        for i in 1..=CIRCUIT_FAILURE_THRESHOLD {
            record_failure();
            if i < CIRCUIT_FAILURE_THRESHOLD {
                assert_eq!(check_circuit_breaker().0, CircuitState::Closed);
            } else {
                assert_eq!(check_circuit_breaker().0, CircuitState::Open);
            }
        }

        // Circuit should stay open
        assert_eq!(check_circuit_breaker().0, CircuitState::Open);

        // Success should reset circuit
        record_success();
        assert_eq!(check_circuit_breaker().0, CircuitState::Closed);
        assert_eq!(FAILURE_COUNT.load(Ordering::Relaxed), 0);
    }

    #[test]
    #[serial_test::serial]
    fn half_open_probe_slot_is_released_when_the_probe_future_is_cancelled() {
        // Regression for the wave-4 M1 leak: a probe future dropped at the
        // flush-budget timeout used to leave HALF_OPEN_PROBE_IN_FLIGHT set
        // forever, latching the breaker Open until process exit.
        reset_circuit_breaker_for_test();

        // Force the breaker open with a just-expired cooldown.
        CIRCUIT_STATE.store(CircuitState::Open as u32, Ordering::Relaxed);
        FAILURE_COUNT.store(CIRCUIT_FAILURE_THRESHOLD, Ordering::Relaxed);
        LAST_FAILURE.store(
            u64::try_from(jiff::Timestamp::now().as_second())
                .unwrap_or(0)
                .saturating_sub(CIRCUIT_OPEN_DURATION_SECS),
            Ordering::Relaxed,
        );
        HALF_OPEN_PROBE_IN_FLIGHT.store(false, Ordering::Relaxed);

        // The send path wins the single-flight slot and holds the guard.
        let (state, guard) = check_circuit_breaker();
        assert_eq!(state, CircuitState::HalfOpen);
        assert!(guard.is_some(), "transitioning caller must claim the slot");
        assert!(HALF_OPEN_PROBE_IN_FLIGHT.load(Ordering::Relaxed));

        // Simulate cancellation: the probe future is dropped before
        // record_success/record_failure can run. The guard's Drop must clear
        // the latch so the breaker can try again.
        drop(guard);
        assert!(
            !HALF_OPEN_PROBE_IN_FLIGHT.load(Ordering::Relaxed),
            "cancelled probe must release the half-open latch"
        );

        // A subsequent caller can win the slot again instead of seeing Open.
        let (state_after, guard_after) = check_circuit_breaker();
        assert_eq!(state_after, CircuitState::HalfOpen);
        assert!(guard_after.is_some());

        // Clean up for other serial tests.
        reset_circuit_breaker_for_test();
    }

    /// Restore the shared breaker to Closed with an empty failure history.
    fn reset_circuit_breaker_for_test() {
        CIRCUIT_STATE.store(CircuitState::Closed as u32, Ordering::Relaxed);
        FAILURE_COUNT.store(0, Ordering::Relaxed);
        HALF_OPEN_PROBE_IN_FLIGHT.store(false, Ordering::Relaxed);
    }
}
