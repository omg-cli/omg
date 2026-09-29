//! System-wide metrics collection (Prometheus-style)
//!
//! Provides atomic counters and gauges for monitoring system health and security.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Trailing window, in milliseconds, used by the health-oriented failure
/// count. Failures older than this are forgotten, so a long-lived daemon is
/// not latched unhealthy by its lifetime error history.
pub const FAILURE_HEALTH_WINDOW_MS: u64 = 300_000;

/// Sentinel meaning "no failure window has been opened yet". It is larger than
/// any realistic epoch-millisecond value, and is checked explicitly rather
/// than relying on wrapping arithmetic.
const FAILURE_WINDOW_UNSET: u64 = u64::MAX;

/// Wall-clock milliseconds since the Unix epoch, saturating at 0 if the system
/// clock is set before 1970.
fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

/// Snapshot of current metrics state
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub requests_total: u64,
    pub requests_failed: u64,
    pub rate_limit_hits: u64,
    pub validation_failures: u64,
    pub active_connections: i64,
    pub security_audit_requests: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub search_requests: u64,
    pub info_requests: u64,
    pub status_requests: u64,
}

/// Global metrics registry using atomics for high performance
pub struct Metrics {
    requests_total: AtomicU64,
    requests_failed: AtomicU64,
    rate_limit_hits: AtomicU64,
    validation_failures: AtomicU64,
    active_connections: AtomicI64,
    security_audit_requests: AtomicU64,
    bytes_received: AtomicU64,
    bytes_sent: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    search_requests: AtomicU64,
    info_requests: AtomicU64,
    status_requests: AtomicU64,
    /// Start of the current trailing failure window; `FAILURE_WINDOW_UNSET`
    /// until the first failure is recorded.
    failures_window_start_ms: AtomicU64,
    /// Failures recorded inside the current trailing window.
    failures_in_window: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub const fn new() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            requests_failed: AtomicU64::new(0),
            rate_limit_hits: AtomicU64::new(0),
            validation_failures: AtomicU64::new(0),
            active_connections: AtomicI64::new(0),
            security_audit_requests: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            search_requests: AtomicU64::new(0),
            info_requests: AtomicU64::new(0),
            status_requests: AtomicU64::new(0),
            failures_window_start_ms: AtomicU64::new(FAILURE_WINDOW_UNSET),
            failures_in_window: AtomicU64::new(0),
        }
    }

    pub fn inc_requests_total(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_requests_failed(&self) {
        self.requests_failed.fetch_add(1, Ordering::Relaxed);
        self.record_request_failure_at(now_millis());
    }

    /// Records a failed request at an explicit epoch-millisecond timestamp.
    /// Split out from [`Metrics::inc_requests_failed`] so the trailing-window
    /// behaviour can be exercised deterministically without sleeping.
    pub(crate) fn record_request_failure_at(&self, now_ms: u64) {
        let start = self.failures_window_start_ms.load(Ordering::Relaxed);
        if start != FAILURE_WINDOW_UNSET && now_ms.wrapping_sub(start) < FAILURE_HEALTH_WINDOW_MS {
            self.failures_in_window.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // Window unopened or expired: open a fresh one. Concurrent recorders
        // can both land here; the resulting count is approximate, which is
        // acceptable for a health heuristic and never latches permanently.
        self.failures_window_start_ms
            .store(now_ms, Ordering::Relaxed);
        self.failures_in_window.store(1, Ordering::Relaxed);
    }

    /// Failed requests recorded within the trailing
    /// [`FAILURE_HEALTH_WINDOW_MS`] window ending at `now_ms`.
    pub(crate) fn request_failures_within_window(&self, now_ms: u64) -> u64 {
        let start = self.failures_window_start_ms.load(Ordering::Relaxed);
        if start == FAILURE_WINDOW_UNSET || now_ms.wrapping_sub(start) >= FAILURE_HEALTH_WINDOW_MS {
            return 0;
        }
        self.failures_in_window.load(Ordering::Relaxed)
    }

    /// Failed requests inside the trailing window as of now. Unlike the
    /// cumulative `requests_failed` counter this recovers once failures stop,
    /// which keeps health gates from latching red for the daemon's lifetime.
    pub(crate) fn recent_request_failures(&self) -> u64 {
        self.request_failures_within_window(now_millis())
    }

    pub fn inc_rate_limit_hits(&self) {
        self.rate_limit_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_validation_failures(&self) {
        self.validation_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_active_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_active_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn inc_security_audit_requests(&self) {
        self.security_audit_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn inc_cache_hits(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_cache_misses(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_search_requests(&self) {
        self.search_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_info_requests(&self) {
        self.info_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_status_requests(&self) {
        self.status_requests.fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            requests_total: self.requests_total.load(Ordering::Relaxed),
            requests_failed: self.requests_failed.load(Ordering::Relaxed),
            rate_limit_hits: self.rate_limit_hits.load(Ordering::Relaxed),
            validation_failures: self.validation_failures.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            security_audit_requests: self.security_audit_requests.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            search_requests: self.search_requests.load(Ordering::Relaxed),
            info_requests: self.info_requests.load(Ordering::Relaxed),
            status_requests: self.status_requests.load(Ordering::Relaxed),
        }
    }
}

/// Global singleton for metrics
pub static GLOBAL_METRICS: Metrics = Metrics::new();

#[cfg(test)]
mod tests {
    use super::*;

    /// Health reports unhealthy above this many failures, mirroring the
    /// daemon health threshold.
    const UNHEALTHY_THRESHOLD: u64 = 1000;
    const EPOCH_MS: u64 = 1_700_000_000_000;

    #[test]
    fn long_lifetime_failures_do_not_latch_unhealthy() {
        let metrics = Metrics::new();
        // 2000 failures spread across two hours, one every ~3.6 seconds.
        // record_request_failure_at only maintains the trailing window, so the
        // lifetime counter is asserted separately by
        // inc_requests_failed_counts_lifetime_and_opens_the_window.
        let step_ms = (2 * 3_600_000) / 2000;
        let mut now = EPOCH_MS;
        for _ in 0..2000 {
            metrics.record_request_failure_at(now);
            now += step_ms;
        }

        assert!(
            metrics.request_failures_within_window(now) <= UNHEALTHY_THRESHOLD,
            "lifetime failures must not latch the health window, got {}",
            metrics.request_failures_within_window(now)
        );
    }

    #[test]
    fn inc_requests_failed_counts_lifetime_and_opens_the_window() {
        // Production has eleven inc_requests_failed call sites and reaches the
        // window only through this method, so the two must stay hooked
        // together. If they are ever unhooked, health silently reports a
        // failure storm as healthy.
        let metrics = Metrics::new();
        assert_eq!(metrics.snapshot().requests_failed, 0);
        assert_eq!(metrics.request_failures_within_window(now_millis()), 0);

        for _ in 0..5 {
            metrics.inc_requests_failed();
        }

        assert_eq!(
            metrics.snapshot().requests_failed,
            5,
            "lifetime counter must keep counting every failure"
        );
        assert_eq!(
            metrics.recent_request_failures(),
            5,
            "the health window must be fed by the same call"
        );
    }

    #[test]
    fn burst_of_failures_within_one_window_is_counted() {
        let metrics = Metrics::new();
        let now = EPOCH_MS;
        for _ in 0..=UNHEALTHY_THRESHOLD {
            metrics.record_request_failure_at(now);
        }

        assert_eq!(
            metrics.request_failures_within_window(now),
            UNHEALTHY_THRESHOLD + 1
        );
        assert!(metrics.request_failures_within_window(now) > UNHEALTHY_THRESHOLD);
    }

    #[test]
    fn window_expires_and_forgets_old_failures() {
        let metrics = Metrics::new();
        metrics.record_request_failure_at(EPOCH_MS);

        assert_eq!(metrics.request_failures_within_window(EPOCH_MS), 1);
        assert_eq!(
            metrics.request_failures_within_window(EPOCH_MS + FAILURE_HEALTH_WINDOW_MS - 1),
            1
        );
        assert_eq!(
            metrics.request_failures_within_window(EPOCH_MS + FAILURE_HEALTH_WINDOW_MS),
            0
        );

        // A new failure after expiry opens a fresh window.
        metrics.record_request_failure_at(EPOCH_MS + FAILURE_HEALTH_WINDOW_MS);
        assert_eq!(
            metrics.request_failures_within_window(EPOCH_MS + FAILURE_HEALTH_WINDOW_MS),
            1
        );
    }

    #[test]
    fn no_failures_reports_zero_even_at_epoch_zero() {
        let metrics = Metrics::new();
        assert_eq!(metrics.request_failures_within_window(0), 0);
        metrics.record_request_failure_at(0);
        assert_eq!(metrics.request_failures_within_window(0), 1);
    }
}
