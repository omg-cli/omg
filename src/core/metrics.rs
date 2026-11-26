//! System-wide metrics collection (Prometheus-style)
//!
//! Provides atomic counters and gauges for monitoring system health and security.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::Instant;

/// Trailing window, in milliseconds, used by the health-oriented failure
/// count. Failures older than this are forgotten, so a long-lived daemon is
/// not latched unhealthy by its lifetime error history.
pub const FAILURE_HEALTH_WINDOW_MS: u64 = 300_000;

/// Failed requests above this threshold make daemon health unhealthy.
pub(crate) const HEALTH_UNHEALTHY_FAILURES_THRESHOLD: u64 = 1000;
const HEALTH_FAILURE_CAPACITY: usize = HEALTH_UNHEALTHY_FAILURES_THRESHOLD as usize + 1;

fn now_millis() -> u64 {
    static CLOCK_START: OnceLock<Instant> = OnceLock::new();
    CLOCK_START.get_or_init(Instant::now).elapsed().as_millis() as u64
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
    // The newest threshold + 1 timestamps fully determine the health verdict.
    // Keep exact ages without an unbounded log during prolonged failures.
    health_failures: Mutex<VecDeque<u64>>,
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
            health_failures: Mutex::new(VecDeque::new()),
        }
    }

    pub fn inc_requests_total(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_requests_failed(&self) {
        self.requests_failed.fetch_add(1, Ordering::Relaxed);
        let mut failures = self
            .health_failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // Sample inside the lock so concurrent recorders append in time order.
        Self::append_failure(&mut failures, now_millis());
    }

    fn append_failure(failures: &mut VecDeque<u64>, now_ms: u64) {
        if failures.len() == HEALTH_FAILURE_CAPACITY {
            failures.pop_front();
        }
        failures.push_back(now_ms);
    }

    fn count_recent(failures: &VecDeque<u64>, now_ms: u64) -> u64 {
        let expired = failures
            .partition_point(|time| now_ms.saturating_sub(*time) >= FAILURE_HEALTH_WINDOW_MS);
        (failures.len() - expired) as u64
    }

    #[cfg(test)]
    pub(crate) fn record_request_failure_at(&self, now_ms: u64) {
        let mut failures = self
            .health_failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Self::append_failure(&mut failures, now_ms);
    }

    #[cfg(test)]
    pub(crate) fn request_failures_within_window(&self, now_ms: u64) -> u64 {
        let failures = self
            .health_failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Self::count_recent(&failures, now_ms)
    }

    /// Recent failures for daemon health, capped at the unhealthy threshold plus one.
    /// Lifetime counts remain available in the metrics snapshot.
    pub(crate) fn recent_request_failures(&self) -> u64 {
        let failures = self
            .health_failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Self::count_recent(&failures, now_millis())
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
    const UNHEALTHY_THRESHOLD: u64 = HEALTH_UNHEALTHY_FAILURES_THRESHOLD;
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
    fn recent_failures_expire_individually_across_the_original_window() {
        let metrics = Metrics::new();
        metrics.record_request_failure_at(EPOCH_MS);
        metrics.record_request_failure_at(EPOCH_MS + FAILURE_HEALTH_WINDOW_MS - 2);

        assert_eq!(
            metrics.request_failures_within_window(EPOCH_MS + FAILURE_HEALTH_WINDOW_MS),
            1,
            "the newer failure must survive expiry of the oldest failure"
        );
        metrics.record_request_failure_at(EPOCH_MS + FAILURE_HEALTH_WINDOW_MS);
        assert_eq!(
            metrics.request_failures_within_window(EPOCH_MS + FAILURE_HEALTH_WINDOW_MS),
            2
        );
        assert_eq!(
            metrics.request_failures_within_window(EPOCH_MS + 2 * FAILURE_HEALTH_WINDOW_MS - 2),
            1
        );
    }

    #[test]
    fn concurrent_failures_keep_complete_lifetime_and_recent_counts_below_threshold() {
        let metrics = Metrics::new();
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..200 {
                        metrics.inc_requests_failed();
                    }
                });
            }
        });
        assert_eq!(metrics.snapshot().requests_failed, 800);
        assert_eq!(metrics.recent_request_failures(), 800);
    }

    #[test]
    fn health_capacity_retains_the_newest_failures_without_capping_lifetime_metrics() {
        let metrics = Metrics::new();
        for _ in 0..2 * HEALTH_FAILURE_CAPACITY {
            metrics.inc_requests_failed();
        }
        assert_eq!(
            metrics.snapshot().requests_failed,
            (2 * HEALTH_FAILURE_CAPACITY) as u64
        );
        assert_eq!(
            metrics.recent_request_failures(),
            HEALTH_FAILURE_CAPACITY as u64
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
