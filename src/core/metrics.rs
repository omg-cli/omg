//! System-wide metrics collection (Prometheus-style)
//!
//! Provides atomic counters and gauges for monitoring system health and security.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// Trailing window, in milliseconds, used by the health-oriented failure
/// count. Failures older than this are forgotten, so a long-lived daemon is
/// not latched unhealthy by its lifetime error history.
pub const FAILURE_HEALTH_WINDOW_MS: u64 = 300_000;

/// Milliseconds elapsed on a process-local monotonic clock. Wall-clock
/// corrections cannot prematurely clear a recent failure storm.
fn now_millis() -> u64 {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    u64::try_from(ORIGIN.get_or_init(Instant::now).elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// One entry per occupied millisecond, not per request. After pruning there
/// are at most FAILURE_HEALTH_WINDOW_MS entries, regardless of request rate.
/// The mutex serializes pruning, recording and reading as one operation.
struct FailureWindow {
    buckets: VecDeque<(u64, u64)>,
    total: u128,
    last_ms: u64,
}

impl FailureWindow {
    const fn new() -> Self {
        Self {
            buckets: VecDeque::new(),
            total: 0,
            last_ms: 0,
        }
    }

    fn advance(&mut self, now_ms: u64) -> u64 {
        // Clamp backwards or out-of-order samples to the last observed time.
        // Expired history is never resurrected; a late recorder is counted at
        // its serialization time. Production samples use a monotonic clock.
        let now_ms = now_ms.max(self.last_ms);
        self.last_ms = now_ms;
        while let Some(&(timestamp, count)) = self.buckets.front() {
            if now_ms - timestamp < FAILURE_HEALTH_WINDOW_MS {
                break;
            }
            self.buckets.pop_front();
            self.total -= u128::from(count);
        }
        now_ms
    }

    fn record(&mut self, now_ms: u64) {
        let now_ms = self.advance(now_ms);
        if let Some((timestamp, count)) = self.buckets.back_mut()
            && *timestamp == now_ms
        {
            // Saturate only this millisecond's bucket. Keep the wider total
            // exact so expiry still subtracts the correct recorded count.
            if *count < u64::MAX {
                *count += 1;
                self.total += 1;
            }
            return;
        }
        self.buckets.push_back((now_ms, 1));
        self.total += 1;
    }

    fn count(&mut self, now_ms: u64) -> u64 {
        self.advance(now_ms);
        u64::try_from(self.total).unwrap_or(u64::MAX)
    }
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

/// Global metrics registry with atomic lifetime counters and a locked health window
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
    failure_window: Mutex<FailureWindow>,
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
            failure_window: Mutex::new(FailureWindow::new()),
        }
    }

    pub fn inc_requests_total(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_requests_failed(&self) {
        self.requests_failed.fetch_add(1, Ordering::Relaxed);
        self.record_request_failure_at(now_millis());
    }

    /// Records a failed request at an explicit monotonic millisecond timestamp.
    /// Split out for deterministic tests; backwards samples are clamped to the
    /// last observed timestamp under the same lock as expiry and insertion.
    pub(crate) fn record_request_failure_at(&self, now_ms: u64) {
        self.failure_window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record(now_ms);
    }

    /// Failed requests with age strictly less than
    /// [`FAILURE_HEALTH_WINDOW_MS`]. Exactly-boundary failures have expired.
    pub(crate) fn request_failures_within_window(&self, now_ms: u64) -> u64 {
        self.failure_window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .count(now_ms)
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
    #[test]
    fn recent_burst_survives_first_failure_boundary() {
        let metrics = Metrics::new();
        metrics.record_request_failure_at(1_000_000);
        for _ in 0..1001 {
            metrics.record_request_failure_at(1_299_999);
        }
        assert_eq!(metrics.request_failures_within_window(1_300_000), 1001);
        assert_eq!(metrics.request_failures_within_window(1_599_998), 1001);
        assert_eq!(metrics.request_failures_within_window(1_599_999), 0);
    }

    #[test]
    fn exact_boundary_expires_only_the_oldest_millisecond() {
        let metrics = Metrics::new();
        metrics.record_request_failure_at(0);
        metrics.record_request_failure_at(1);
        assert_eq!(
            metrics.request_failures_within_window(FAILURE_HEALTH_WINDOW_MS - 1),
            2
        );
        assert_eq!(
            metrics.request_failures_within_window(FAILURE_HEALTH_WINDOW_MS),
            1
        );
        assert_eq!(
            metrics.request_failures_within_window(FAILURE_HEALTH_WINDOW_MS + 1),
            0
        );
    }

    #[test]
    fn backwards_timestamps_do_not_clear_or_resurrect_failures() {
        let metrics = Metrics::new();
        metrics.record_request_failure_at(100);
        assert_eq!(metrics.request_failures_within_window(99), 1);
        metrics.record_request_failure_at(98);
        assert_eq!(metrics.request_failures_within_window(100), 2);
        assert_eq!(
            metrics.request_failures_within_window(100 + FAILURE_HEALTH_WINDOW_MS),
            0
        );
        assert_eq!(metrics.request_failures_within_window(100), 0);
        metrics.record_request_failure_at(100);
        assert_eq!(
            metrics.request_failures_within_window(100 + FAILURE_HEALTH_WINDOW_MS),
            1
        );
    }

    #[test]
    fn concurrent_recorders_and_readers_do_not_lose_boundary_updates() {
        use std::sync::{Arc, Barrier};
        let metrics = Metrics::new();
        metrics.record_request_failure_at(0);
        for timestamp in [1, FAILURE_HEALTH_WINDOW_MS, 2 * FAILURE_HEALTH_WINDOW_MS] {
            let barrier = Arc::new(Barrier::new(9));
            std::thread::scope(|scope| {
                for _ in 0..8 {
                    let barrier = Arc::clone(&barrier);
                    let metrics = &metrics;
                    scope.spawn(move || {
                        barrier.wait();
                        for _ in 0..1000 {
                            metrics.record_request_failure_at(timestamp);
                            assert!(metrics.request_failures_within_window(timestamp) > 0);
                        }
                    });
                }
                barrier.wait();
            });
            let expected = if timestamp == 1 {
                8001
            } else if timestamp == FAILURE_HEALTH_WINDOW_MS {
                16000
            } else {
                8000
            };
            assert_eq!(metrics.request_failures_within_window(timestamp), expected);
        }
    }

    #[test]
    fn storage_is_bounded_and_same_millisecond_bursts_are_coalesced() {
        let metrics = Metrics::new();
        for timestamp in 0..=FAILURE_HEALTH_WINDOW_MS {
            metrics.record_request_failure_at(timestamp);
        }
        for _ in 0..10000 {
            metrics.record_request_failure_at(FAILURE_HEALTH_WINDOW_MS);
        }
        assert_eq!(
            metrics.request_failures_within_window(FAILURE_HEALTH_WINDOW_MS),
            FAILURE_HEALTH_WINDOW_MS + 10000
        );
        {
            let window = metrics.failure_window.lock().unwrap();
            assert_eq!(window.buckets.len(), FAILURE_HEALTH_WINDOW_MS as usize);
            assert_eq!(
                window.buckets.back(),
                Some(&(FAILURE_HEALTH_WINDOW_MS, 10001))
            );
        }
        assert_eq!(
            metrics.request_failures_within_window(2 * FAILURE_HEALTH_WINDOW_MS),
            0
        );
        assert!(metrics.failure_window.lock().unwrap().buckets.is_empty());
    }

    #[test]
    fn saturated_bucket_expires_without_corrupting_other_counts() {
        let metrics = Metrics::new();
        {
            let mut window = metrics.failure_window.lock().unwrap();
            window.buckets.push_back((0, u64::MAX));
            window.total = u128::from(u64::MAX);
        }
        metrics.record_request_failure_at(0);
        metrics.record_request_failure_at(1);
        assert_eq!(metrics.request_failures_within_window(1), u64::MAX);
        assert_eq!(
            metrics.request_failures_within_window(FAILURE_HEALTH_WINDOW_MS),
            1
        );
    }
}
