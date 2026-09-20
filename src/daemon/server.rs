//! Daemon server implementation with Unix socket IPC
//!
//! Uses `LengthDelimitedCodec` and bitcode for maximum IPC performance.

use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use governor::{Quota, RateLimiter};
use tokio::net::UnixListener;
use tokio_util::codec::{FramedWrite, LengthDelimitedCodec};
use tokio_util::sync::CancellationToken;

use super::handlers::{DaemonState, handle_request};
use super::protocol::{Request, Response, error_codes};
use crate::core::metrics::GLOBAL_METRICS;
use crate::core::security::{
    AuditEventType, AuditSeverity, audit_log_nonblocking, init_audit_logger,
};

/// Request handling timeout (30 seconds should be sufficient for most operations)
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Status refresh interval (5 minutes)
const STATUS_REFRESH_INTERVAL: Duration = Duration::from_mins(5);

/// Memory cleanup interval (30 minutes) - matches mmap TTL
const MEMORY_CLEANUP_INTERVAL: Duration = Duration::from_mins(30);

/// Socket health check interval (60 seconds) - detect deleted socket files
const SOCKET_HEALTH_CHECK_INTERVAL: Duration = Duration::from_mins(1);

/// Close clients that hold a connection without sending a complete frame.
const CLIENT_IDLE_TIMEOUT: Duration = Duration::from_mins(1);

/// Bound response writes so a local client that stops reading cannot retain a
/// connection permit indefinitely.
const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-connection rate limit (requests per second)
const CLIENT_RATE_LIMIT_HZ: u32 = 50;
/// Per-connection burst size
const CLIENT_BURST_SIZE: u32 = 100;

/// Upper bound on concurrently served client connections. Each connection
/// holds framed buffers and a rate limiter; without a cap a local client can
/// exhaust memory/file descriptors before the accept-loop EMFILE backoff
/// ever triggers.
const MAX_CONCURRENT_CONNECTIONS: usize = 128;

#[derive(Debug, PartialEq, Eq)]
enum BackgroundEvent {
    Shutdown,
    Maintenance,
    SocketHealth,
}

/// Own the worker's deadlines independently of the work performed at each tick.
struct BackgroundSchedule {
    maintenance: tokio::time::Interval,
    socket_health: tokio::time::Interval,
}

impl BackgroundSchedule {
    fn new() -> Self {
        let now = tokio::time::Instant::now();
        let mut maintenance =
            tokio::time::interval_at(now + STATUS_REFRESH_INTERVAL, STATUS_REFRESH_INTERVAL);
        maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut socket_health = tokio::time::interval_at(
            now + SOCKET_HEALTH_CHECK_INTERVAL,
            SOCKET_HEALTH_CHECK_INTERVAL,
        );
        socket_health.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        Self {
            maintenance,
            socket_health,
        }
    }

    async fn next(&mut self, shutdown: &CancellationToken) -> BackgroundEvent {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => BackgroundEvent::Shutdown,
            // Interval ticks retain their deadlines when another branch wins.
            _ = self.maintenance.tick() => BackgroundEvent::Maintenance,
            _ = self.socket_health.tick() => BackgroundEvent::SocketHealth,
        }
    }
}

async fn wait_for_termination_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        signal
            .recv()
            .await
            .context("SIGTERM listener closed unexpectedly")?;
        Ok(())
    }

    #[cfg(not(unix))]
    std::future::pending::<Result<()>>().await
}

/// Run the daemon server
pub async fn run(
    listener: UnixListener,
    state: Arc<DaemonState>,
    socket_path: PathBuf,
) -> Result<()> {
    init_audit_logger()?;
    let fast_status_path = socket_path.with_file_name("omg.status");
    run_with_status_path(listener, state, socket_path, fast_status_path).await
}

async fn write_fast_status_async(
    status: crate::core::fast_status::FastStatus,
    path: PathBuf,
) -> Result<()> {
    tokio::task::spawn_blocking(move || status.write_to_file(&path))
        .await
        .context("Fast-status writer panicked")??;
    Ok(())
}

fn validate_signal_result(result: std::io::Result<()>, signal: &str) -> Result<()> {
    result.with_context(|| format!("Failed to listen for {signal}"))
}

fn daemon_shutdown_result(internal_failure: Option<String>) -> Result<()> {
    match internal_failure {
        Some(failure) => anyhow::bail!(failure),
        None => Ok(()),
    }
}

async fn run_with_status_path(
    listener: UnixListener,
    state: Arc<DaemonState>,
    socket_path: PathBuf,
    fast_status_path: PathBuf,
) -> Result<()> {
    let shutdown_token = CancellationToken::new();
    let _cancel_on_drop = shutdown_token.clone().drop_guard();
    let mut workers = tokio::task::JoinSet::new();
    let mut connections = tokio::task::JoinSet::new();
    let (internal_failure_tx, mut internal_failure_rx) =
        tokio::sync::mpsc::unbounded_channel::<String>();

    // Budget for concurrent client connections; permits are released when a
    // connection task ends.
    let connection_permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    // START BACKGROUND WORKER
    let state_worker = Arc::clone(&state);
    let worker_token = shutdown_token.child_token();
    // Clone the parent token so the health check can trigger a full shutdown
    let shutdown_trigger = shutdown_token.clone();
    let health_failure_tx = internal_failure_tx.clone();

    workers.spawn(async move {
        tracing::info!("Background status worker started");

        async fn refresh_status(state: &Arc<DaemonState>, fast_status_path: &std::path::Path) {
            let versions = match tokio::task::spawn_blocking(|| {
                use crate::cli::runtimes::{ensure_active_version, known_runtimes};

                let mut versions = Vec::new();
                match known_runtimes() {
                    Ok(runtimes) => {
                        for runtime in runtimes {
                            match ensure_active_version(&runtime) {
                                Ok(Some(v)) => versions.push((runtime, v)),
                                Ok(None) => {}
                                Err(error) => tracing::warn!(
                                    "Failed to resolve active {runtime} version: {error}"
                                ),
                            }
                        }
                    }
                    Err(error) => tracing::warn!("Failed to list known runtimes: {error}"),
                }
                versions
            })
            .await
            {
                Ok(versions) => versions,
                Err(error) => {
                    tracing::error!("Runtime status task panicked: {error}");
                    return;
                }
            };
            let status = state.status_counts().await;
            state
                .runtime_versions
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone_from(&versions);

            let (total, explicit, orphans, updates) = match status {
                Ok(status) => status,
                Err(error) => {
                    tracing::warn!("Failed to refresh package status: {error}");
                    return;
                }
            };
            let fast_status =
                crate::core::fast_status::FastStatus::new(total, explicit, orphans, updates);
            if let Err(error) =
                write_fast_status_async(fast_status, fast_status_path.to_path_buf()).await
            {
                tracing::warn!("Failed to write fast status file: {error}");
            }

            let scanner = crate::core::security::VulnerabilityScanner::new();
            let previous_vulns = state
                .cache
                .get_status()
                .and_then(|status| status.scanned_vulnerability_count());
            let scan = scanner.scan_system().await;
            if let Err(error) = &scan {
                tracing::warn!("Vulnerability scan failed during status refresh: {error}");
            }
            let Some(vuln_count) =
                super::status_policy::vulnerability_count_from_scan(&scan, previous_vulns)
            else {
                tracing::warn!("No prior vulnerability count; not publishing a zero-vuln status");
                return;
            };
            let res = super::status_policy::status_snapshot(
                total,
                explicit,
                orphans,
                updates,
                versions,
                Some(vuln_count),
            )
            .0;
            let res_arc = Arc::new(res);
            // The in-memory cache is authoritative, so persistence is best-effort.
            if let Err(error) = state.persistent.set_status(&res_arc) {
                tracing::warn!("Failed to persist status cache: {error}");
            }
            state.cache.update_status(res_arc);
        }

        /// Pre-compute caches for instant first queries.
        ///
        /// Deliberately unconditional: it must run even when status
        /// publication was skipped above (structural guarantee against the
        /// early-return regression this replaces).
        async fn prewarm_caches(state: &Arc<DaemonState>) {
            // Pre-compute explicit package list for instant first query.
            // The state owns the backend choice so isolated daemons never
            // fall through to a host package database.
            match state.explicit_packages().await {
                Ok(packages) => {
                    state.cache.update_explicit(packages);
                    tracing::debug!("Pre-warmed explicit package cache");
                }
                Err(error) => {
                    tracing::warn!("Failed to pre-warm explicit package cache: {error}");
                }
            }

            let index = state.index_snapshot();
            for query in ["", "linux", "python", "node", "firefox", "git"] {
                let results = match super::handlers::search_index_blocking(
                    Arc::clone(&index),
                    query.to_string(),
                )
                .await
                {
                    Ok(results) => Arc::new(results),
                    Err(error) => {
                        tracing::warn!("Search cache pre-warm failed: {error}");
                        return;
                    }
                };
                if !state.with_current_index(&index, || {
                    state.cache.insert_arc(query.to_string(), results);
                }) {
                    return;
                }
            }
        }

        // Initial refresh
        refresh_status(&state_worker, &fast_status_path).await;
        prewarm_caches(&state_worker).await;

        // Track last cleanup time for periodic mmap cleanup
        let mut last_cleanup = tokio::time::Instant::now();
        let mut schedule = BackgroundSchedule::new();

        loop {
            match schedule.next(&worker_token).await {
                BackgroundEvent::Shutdown => {
                    tracing::info!("Background worker shutting down");
                    break;
                }
                BackgroundEvent::Maintenance => {
                    tracing::debug!("Refreshing system status cache...");
                    refresh_status(&state_worker, &fast_status_path).await;
                    // Independent of status publication: a failed scan must
                    // not degrade first-query latency for unrelated paths.
                    prewarm_caches(&state_worker).await;
                    tracing::debug!("Status cache refreshed");

                    // Periodic mmap cleanup (every 30 min) to prevent 500MB+ memory leaks
                    if last_cleanup.elapsed() >= MEMORY_CLEANUP_INTERVAL {
                        #[cfg(any(feature = "debian", feature = "debian-pure"))]
                        {
                            crate::package_managers::debian_db::cleanup_expired_mmaps();
                        }
                        last_cleanup = tokio::time::Instant::now();
                    }
                }
                BackgroundEvent::SocketHealth => {
                    if !socket_path.exists() {
                        let failure = format!(
                            "Daemon socket {} was removed externally",
                            socket_path.display()
                        );
                        tracing::error!("{failure}; initiating shutdown");
                        let _ = health_failure_tx.send(failure);
                        // Cancel the parent shutdown token to stop the accept loop.
                        shutdown_trigger.cancel();
                        break;
                    }
                }
            }
        }
    });

    drop(internal_failure_tx);

    tracing::info!("Daemon ready, binary IPC enabled");

    // Register signal listeners once. Recreating them after every accepted
    // connection leaves gaps where process signals can be lost.
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let termination_signal = wait_for_termination_signal();
    tokio::pin!(termination_signal);

    let mut internal_failure = None;
    let intake_result: Result<()> = async {
    loop {
        tokio::select! {
            // biased: always check shutdown signal first to avoid accepting
            // new connections after shutdown was requested
            biased;

            Some(failure) = internal_failure_rx.recv() => {
                internal_failure = Some(failure);
                shutdown_token.cancel();
                break;
            }

            result = &mut ctrl_c => {
                validate_signal_result(result, "SIGINT")?;
                tracing::info!("Interrupt signal received, cleaning up...");
                shutdown_token.cancel();
                break;
            }

            result = &mut termination_signal => {
                result.context("Failed to listen for SIGTERM")?;
                tracing::info!("Termination signal received, cleaning up...");
                shutdown_token.cancel();
                break;
            }

            () = shutdown_token.cancelled() => {
                tracing::info!("Shutdown triggered by health monitor, cleaning up...");
                break;
            }

            Some(result) = workers.join_next() => {
                if let Err(error) = result {
                    state.inc_background_worker_failures();
                    internal_failure = Some(format!("Background status worker failed: {error}"));
                } else if !shutdown_token.is_cancelled() {
                    internal_failure = Some("Background status worker stopped unexpectedly".into());
                }
                break;
            }

            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    tracing::error!("Client task failed: {error}");
                }
            }

            result = listener.accept() => {
                let (stream, _addr) = match result {
                    Ok(conn) => conn,
                    Err(e) => {
                        // Classify the error: transient errors should not kill the server
                        let raw_os_error = e.raw_os_error();
                        match e.kind() {
                            // Transient: client disconnected before accept completed, or signal
                            std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::Interrupted => {
                                tracing::warn!("Transient accept error (continuing): {e}");
                                continue;
                            }
                            _ if raw_os_error == Some(24) || raw_os_error == Some(23) => {
                                // EMFILE (24) = per-process fd limit, ENFILE (23) = system-wide
                                tracing::error!(
                                    "File descriptor limit reached (errno {}), backing off: {e}",
                                    raw_os_error.unwrap_or(0)
                                );
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                continue;
                            }
                            _ => {
                                // Truly fatal: propagate to shut down the server
                                return Err(e.into());
                            }
                        }
                    }
                };
                let state = Arc::clone(&state);
                let client_token = shutdown_token.child_token();

                // Acquire before spawning so the number of live connection
                // tasks stays bounded; on saturation, refuse the connection
                // (dropping the stream closes the socket).
                let Ok(permit) = Arc::clone(&connection_permits).try_acquire_owned() else {
                    tracing::warn!(
                        "Connection limit of {MAX_CONCURRENT_CONNECTIONS} reached; refusing new client"
                    );
                    continue;
                };

                connections.spawn(async move {
                    // Held until the task completes; Drop releases the permit.
                    let _permit = permit;
                    if let Err(error) = handle_client(stream, state, client_token).await {
                        tracing::error!("Client error: {error}");
                    }
                });
            }
        }
    }

    Ok(())
    }.await;
    drop(listener);
    let shutdown_result = drain_daemon_tasks(
        &shutdown_token,
        &mut workers,
        &mut connections,
        Duration::from_secs(30),
    )
    .await;
    if intake_result.is_err()
        && let Err(error) = &shutdown_result
    {
        tracing::error!("Additional daemon shutdown failure: {error:#}");
    }
    intake_result?;
    shutdown_result?;
    if internal_failure.is_none() {
        internal_failure = internal_failure_rx.try_recv().ok();
    }
    daemon_shutdown_result(internal_failure)
}

async fn drain_daemon_tasks(
    cancellation: &CancellationToken,
    workers: &mut tokio::task::JoinSet<()>,
    connections: &mut tokio::task::JoinSet<()>,
    deadline: Duration,
) -> Result<()> {
    cancellation.cancel();
    let drained = tokio::time::timeout(deadline, async {
        let mut failure = None;
        while let Some(result) = workers.join_next().await {
            if let Err(error) = result {
                failure = Some(error);
            }
        }
        while let Some(result) = connections.join_next().await {
            if let Err(error) = result {
                failure = Some(error);
            }
        }
        match failure {
            Some(error) => {
                Err(anyhow::anyhow!(error).context("Daemon task failed during shutdown"))
            }
            None => Ok(()),
        }
    })
    .await;
    if let Ok(result) = drained {
        result
    } else {
        workers.shutdown().await;
        connections.shutdown().await;
        anyhow::bail!(
            "Daemon shutdown exceeded its deadline; nested blocking work may still be running"
        )
    }
}

/// Maximum request size to prevent `DoS` attacks. This also bounds the sole
/// `String` in every `Request` variant: bitcode consumes its bytes directly
/// from the frame before copying them into the decoded value.
/// <https://github.com/SoftbearStudios/bitcode/blob/f41da053c08178189aaee8c62f4c6e738add6eda/src/str.rs>
const MAX_REQUEST_SIZE: usize = 1024 * 1024;

/// Maximum encoded response size (8 MiB). Deliberately distinct from
/// [`MAX_REQUEST_SIZE`] (1 MiB): the two directions carry very different
/// payloads. Requests are small queries, so 1 MiB is a generous cap that
/// also bounds the DoS surface of request parsing; responses may carry up
/// to the daemon's 1000-entry search/audit limits with full descriptions
/// (broad `DebianSearch` or `SecurityAudit` results), which realistically
/// exceeds 1 MiB on large installs.
///
/// The budget sits strictly below the transport ceiling
/// `protocol::MAX_FRAME_SIZE` (10 MiB) that every client-side reader accepts
/// (`read_frame` and the client `Framed` codec). The daemon write codec uses
/// this same budget so an encoded frame can actually leave the socket;
/// inbound frames stay capped at [`MAX_REQUEST_SIZE`]. Responses that overflow
/// it are degraded gracefully by [`encode_bounded_response`] (semantic
/// truncation of list results), never mapped to `INTERNAL_ERROR`.
const MAX_RESPONSE_SIZE: usize = 8 * 1024 * 1024;

// Guard against a future edit raising the response budget past what the
// transport framing and every client-side reader will accept.
const _: () = assert!(MAX_RESPONSE_SIZE < crate::daemon::protocol::MAX_FRAME_SIZE);

/// RAII guard for tracking active connections
struct ConnectionGuard;

impl ConnectionGuard {
    fn new() -> Self {
        GLOBAL_METRICS.inc_active_connections();
        Self
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        GLOBAL_METRICS.dec_active_connections();
    }
}

async fn await_client_write(
    write: impl std::future::Future<Output = std::io::Result<()>>,
    timeout: Duration,
) -> Result<()> {
    tokio::time::timeout(timeout, write)
        .await
        .map_err(|_| anyhow::anyhow!("Daemon client write timed out after {timeout:?}"))??;
    Ok(())
}

fn encode_bounded_response(response: &Response, request_id: u64) -> Result<Vec<u8>> {
    let response_bytes = crate::daemon::protocol::encode_frame(response)?;
    if response_bytes.len() <= MAX_RESPONSE_SIZE {
        return Ok(response_bytes);
    }

    // The protocol has no partial-result marker. A reduced successful result
    // would misrepresent audit findings, inventory, or available updates.
    tracing::error!(
        request_id,
        response_bytes = response_bytes.len(),
        max_response_bytes = MAX_RESPONSE_SIZE,
        "Daemon response exceeded the response budget"
    );
    GLOBAL_METRICS.inc_requests_failed();
    Ok(crate::daemon::protocol::encode_frame(&Response::Error {
        id: request_id,
        code: error_codes::RESPONSE_TOO_LARGE,
        message: format!(
            "Daemon response of {} bytes exceeds the {MAX_RESPONSE_SIZE}-byte response budget",
            response_bytes.len()
        ),
    })?)
}

async fn send_response_frame<W>(
    framed: &mut FramedWrite<W, LengthDelimitedCodec>,
    response_bytes: Vec<u8>,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let response_len = response_bytes.len();
    if let Err(error) =
        await_client_write(framed.send(response_bytes.into()), CLIENT_WRITE_TIMEOUT).await
    {
        GLOBAL_METRICS.inc_requests_failed();
        return Err(error);
    }
    GLOBAL_METRICS.add_bytes_sent(response_len as u64);
    Ok(())
}

/// Handle a single client connection
/// Encode and send one error frame, accounting bytes sent. The shared tail
/// copies is how a future edit forgets the metric.
async fn send_error_response<W>(
    framed: &mut FramedWrite<W, LengthDelimitedCodec>,
    id: u64,
    code: i32,
    message: String,
) where
    W: tokio::io::AsyncWrite + Unpin,
{
    let response = Response::Error { id, code, message };
    if let Ok(response_bytes) = crate::daemon::protocol::encode_frame(&response)
        && let Err(error) = send_response_frame(framed, response_bytes).await
    {
        tracing::warn!("Failed to send daemon error response: {error}");
    }
}

async fn handle_client(
    stream: tokio::net::UnixStream,
    state: Arc<DaemonState>,
    cancellation: CancellationToken,
) -> Result<()> {
    handle_client_with_idle_timeout(stream, state, CLIENT_IDLE_TIMEOUT, cancellation).await
}

async fn handle_client_with_idle_timeout(
    stream: tokio::net::UnixStream,
    state: Arc<DaemonState>,
    idle_timeout: Duration,
    cancellation: CancellationToken,
) -> Result<()> {
    // METRICS: Track active connections using RAII guard
    let _guard = ConnectionGuard::new();

    // LengthDelimitedCodec applies max_frame_length to encode and decode.
    // Keep inbound frames at the request DoS cap; give the write half the
    // response budget so an 8 MiB success frame is not rejected after encode.
    let (read_half, write_half) = tokio::io::split(stream);
    let mut framed_read = LengthDelimitedCodec::builder()
        .max_frame_length(MAX_REQUEST_SIZE)
        .new_read(read_half);
    let mut framed_write = LengthDelimitedCodec::builder()
        .max_frame_length(MAX_RESPONSE_SIZE)
        .new_write(write_half);

    // Rate limit per connection to ensure fairness
    // Const-eval guarantee: the literals above are non-zero; a violation is
    // rejected at compile time, not at runtime.
    const RATE_LIMIT_NZ: NonZeroU32 = NonZeroU32::new(CLIENT_RATE_LIMIT_HZ).unwrap();
    const BURST_SIZE_NZ: NonZeroU32 = NonZeroU32::new(CLIENT_BURST_SIZE).unwrap();
    let quota = Quota::per_second(RATE_LIMIT_NZ).allow_burst(BURST_SIZE_NZ);
    let rate_limiter = RateLimiter::direct(quota);

    tracing::debug!("New binary client connected");

    loop {
        let next_frame = tokio::select! {
            biased;
            () = cancellation.cancelled() => break,
            frame = tokio::time::timeout(idle_timeout, framed_read.next()) => frame,
        };
        let request_bytes = match next_frame {
            Ok(Some(request_bytes)) => request_bytes,
            Ok(None) => break,
            Err(_) => {
                tracing::debug!(?idle_timeout, "Closing idle daemon client");
                break;
            }
        };
        // Transport/frame errors (oversize frame, I/O) tear down the
        // connection: the length-prefix stream may be desynchronized, so
        // answering on it would be unsafe.
        let bytes = match request_bytes {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!("Frame decode failed; closing client connection: {error}");
                GLOBAL_METRICS.inc_requests_failed();
                break;
            }
        };

        // METRICS: Track bytes received
        GLOBAL_METRICS.add_bytes_received(bytes.len() as u64);

        // SECURITY: A malformed payload means we cannot trust anything further
        // from this client. Answer once with the protocol's parse-error code,
        // then close cleanly instead of tearing down silently. Request id 0 is
        // the reserved error-envelope id for requests that never decoded.
        // Reject peers speaking a different protocol version before any
        // decode attempt could silently mis-map same-shaped variants.
        let payload = match crate::daemon::protocol::split_frame(&bytes) {
            Ok((_, payload)) => payload,
            Err(crate::daemon::protocol::FrameError::VersionMismatch { peer, ours }) => {
                tracing::warn!(
                    peer,
                    ours,
                    "rejecting client with mismatched protocol version"
                );
                // Answer once so the client learns WHY instead of hanging for
                // its full timeout, then close — the stream is unusable.
                send_error_response(
                    &mut framed_write,
                    0,
                    error_codes::PARSE_ERROR,
                    format!(
                        "unsupported peer protocol version {peer} (this daemon speaks {ours}); update omg"
                    ),
                )
                .await;
                GLOBAL_METRICS.inc_requests_failed();
                break;
            }
            Err(e) => {
                tracing::warn!("malformed frame header: {e}");
                send_error_response(
                    &mut framed_write,
                    0,
                    error_codes::PARSE_ERROR,
                    format!("malformed frame header: {e}"),
                )
                .await;
                GLOBAL_METRICS.inc_requests_failed();
                break;
            }
        };
        let request: Request = match bitcode::deserialize(payload) {
            Ok(request) => request,
            Err(error) => {
                let msg = format!("Failed to deserialize request: {error}");
                tracing::warn!("{msg}");
                audit_log_nonblocking(
                    AuditEventType::PolicyViolation,
                    AuditSeverity::Warning,
                    "daemon_server",
                    &msg,
                );
                GLOBAL_METRICS.inc_validation_failures();
                GLOBAL_METRICS.inc_requests_failed();
                send_error_response(&mut framed_write, 0, error_codes::PARSE_ERROR, msg).await;
                break;
            }
        };

        let request_id = request.id();

        // SECURITY: Enforce per-connection rate limiting
        if rate_limiter.check().is_err() {
            tracing::warn!("Client rate limit exceeded for request {}", request_id);
            audit_log_nonblocking(
                AuditEventType::PolicyViolation,
                AuditSeverity::Warning,
                "daemon_server",
                "Client rate limit exceeded",
            );
            GLOBAL_METRICS.inc_rate_limit_hits();
            GLOBAL_METRICS.inc_requests_failed();

            send_error_response(
                &mut framed_write,
                request_id,
                error_codes::RATE_LIMITED,
                "Rate limit exceeded. Please slow down.".to_string(),
            )
            .await;
            continue;
        }

        // Handle request with timeout to prevent hung clients
        let response =
            tokio::time::timeout(REQUEST_TIMEOUT, handle_request(Arc::clone(&state), request))
                .await
                .unwrap_or_else(|_| {
                    tracing::warn!(
                        "Request {} timed out after {:?}",
                        request_id,
                        REQUEST_TIMEOUT
                    );
                    GLOBAL_METRICS.inc_requests_failed();
                    Response::Error {
                        id: request_id,
                        code: error_codes::INTERNAL_ERROR,
                        message: format!(
                            "Request timed out after {} seconds",
                            REQUEST_TIMEOUT.as_secs()
                        ),
                    }
                });

        // Encode and send response
        let response_bytes = encode_bounded_response(&response, request_id)?;
        send_response_frame(&mut framed_write, response_bytes).await?;
    }

    tracing::debug!("Client disconnected");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn shutdown_waits_for_owned_work_to_finish() {
        let cancellation = tokio_util::sync::CancellationToken::new();
        let token = cancellation.clone();
        let (release, pending) = tokio::sync::oneshot::channel::<()>();
        let mut workers = tokio::task::JoinSet::new();
        let mut connections = tokio::task::JoinSet::new();
        let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let marker = finished.clone();
        workers.spawn(async move {
            pending.await.unwrap();
            marker.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        connections.spawn(async move { token.cancelled().await });
        let shutdown_token = cancellation.clone();
        let shutdown = tokio::spawn(async move {
            super::drain_daemon_tasks(
                &shutdown_token,
                &mut workers,
                &mut connections,
                std::time::Duration::from_secs(5),
            )
            .await?;
            assert!(workers.is_empty() && connections.is_empty());
            Ok::<_, anyhow::Error>(())
        });
        cancellation.cancelled().await;
        assert!(!shutdown.is_finished());
        release.send(()).unwrap();
        shutdown.await.unwrap().unwrap();
        assert!(finished.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_deadline_is_reported_as_failure() {
        let cancellation = tokio_util::sync::CancellationToken::new();
        let mut workers = tokio::task::JoinSet::new();
        let mut connections = tokio::task::JoinSet::new();
        workers.spawn(std::future::pending::<()>());
        let error = super::drain_daemon_tasks(
            &cancellation,
            &mut workers,
            &mut connections,
            std::time::Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("exceeded its deadline"));
        assert!(workers.is_empty() && connections.is_empty());
    }

    use super::super::protocol::{
        PackageInfo, ResponseResult, SearchResult, SecurityAuditResult, WirePackageSource,
    };
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn maintenance_deadline_survives_health_ticks() {
        let start = tokio::time::Instant::now();
        let mut schedule = BackgroundSchedule::new();
        let cancellation = CancellationToken::new();
        let deadline = start + Duration::from_mins(16);
        let mut refreshes = 0;
        let mut checks = 0;
        loop {
            tokio::select! {
                biased;
                () = tokio::time::sleep_until(deadline) => break,
                event = schedule.next(&cancellation) => match event {
                    BackgroundEvent::Maintenance => { refreshes += 1; }
                    BackgroundEvent::SocketHealth => { checks += 1; }
                    BackgroundEvent::Shutdown => panic!("unexpected cancellation"),
                }
            }
        }
        assert_eq!(refreshes, 3);
        assert_eq!(checks, 15);
    }

    #[test]
    fn oversized_security_audit_is_not_reported_as_complete() {
        let vulnerability = super::super::protocol::Vulnerability {
            id: "CVE-fixture".into(),
            summary: "x".repeat(16_000),
            score: Some("9.8".into()),
        };
        let response = Response::Success {
            id: 91,
            result: ResponseResult::SecurityAudit(SecurityAuditResult {
                total_vulnerabilities: 600,
                high_severity: 600,
                vulnerabilities: (0..600)
                    .map(|index| (format!("package-{index}"), vec![vulnerability.clone()]))
                    .collect(),
            }),
        };
        assert!(
            crate::daemon::protocol::encode_frame(&response)
                .unwrap()
                .len()
                > MAX_RESPONSE_SIZE
        );
        let encoded = encode_bounded_response(&response, 91).unwrap();
        let (_, payload) = crate::daemon::protocol::split_frame(&encoded).unwrap();
        let decoded: Response = bitcode::deserialize(payload).unwrap();
        assert!(matches!(
            decoded,
            Response::Error {
                id: 91,
                code: error_codes::RESPONSE_TOO_LARGE,
                ..
            }
        ));
    }

    #[test]
    fn oversized_explicit_and_update_inventories_are_rejected_without_losing_entries() {
        use super::super::protocol::{ExplicitResult, UpdateEntry};
        let results = [
            ResponseResult::Explicit(ExplicitResult {
                packages: vec!["p".repeat(MAX_RESPONSE_SIZE / 2 + 1024); 2],
            }),
            ResponseResult::ListUpdates(vec![
                UpdateEntry {
                    name: "p".repeat(MAX_RESPONSE_SIZE / 2 + 1024),
                    old_version: "1".into(),
                    new_version: "2".into(),
                    repo: "fixture".into(),
                };
                2
            ]),
        ];
        for result in results {
            let response = Response::Success { id: 91, result };
            assert!(
                crate::daemon::protocol::encode_frame(&response)
                    .unwrap()
                    .len()
                    > MAX_RESPONSE_SIZE
            );
            let encoded = encode_bounded_response(&response, 91).unwrap();
            assert!(encoded.len() <= MAX_RESPONSE_SIZE);
            let (_, payload) = crate::daemon::protocol::split_frame(&encoded).unwrap();
            let decoded: Response = bitcode::deserialize(payload).unwrap();
            assert!(matches!(
                decoded,
                Response::Error {
                    id: 91,
                    code: error_codes::RESPONSE_TOO_LARGE,
                    ..
                }
            ));
        }
    }

    #[test]
    fn exhaustive_responses_within_budget_are_preserved_byte_for_byte() {
        use super::super::protocol::{ExplicitResult, UpdateEntry};
        let results = [
            ResponseResult::SecurityAudit(SecurityAuditResult {
                total_vulnerabilities: 1,
                high_severity: 1,
                vulnerabilities: vec![(
                    "package".into(),
                    vec![super::super::protocol::Vulnerability {
                        id: "CVE-fixture".into(),
                        summary: "fixture".into(),
                        score: Some("9.8".into()),
                    }],
                )],
            }),
            ResponseResult::Explicit(ExplicitResult {
                packages: vec!["package".into()],
            }),
            ResponseResult::ListUpdates(vec![UpdateEntry {
                name: "package".into(),
                old_version: "1".into(),
                new_version: "2".into(),
                repo: "fixture".into(),
            }]),
        ];
        for result in results {
            let response = Response::Success { id: 92, result };
            assert_eq!(
                encode_bounded_response(&response, 92).unwrap(),
                crate::daemon::protocol::encode_frame(&response).unwrap()
            );
        }
    }

    #[test]
    fn untruncatable_oversized_responses_use_a_dedicated_limit_error() {
        // Message results carry no truncatable list: a single payload alone
        // exceeds the budget, so the response degrades to the dedicated
        // limit error — never INTERNAL_ERROR.
        let oversized = Response::Success {
            id: 77,
            result: ResponseResult::Message("x".repeat(MAX_RESPONSE_SIZE + 1024)),
        };

        let encoded = encode_bounded_response(&oversized, 77).expect("bounded response");
        assert!(encoded.len() <= MAX_RESPONSE_SIZE);
        let (_, payload) = crate::daemon::protocol::split_frame(&encoded).expect("frame header");
        let decoded: Response = bitcode::deserialize(payload).expect("response payload");
        match decoded {
            Response::Error { id, code, message } => {
                assert_eq!(id, 77);
                assert_eq!(code, error_codes::RESPONSE_TOO_LARGE);
                assert!(message.contains("response budget"));
            }
            Response::Success { .. } => {
                panic!("untruncatable oversized response must become an error")
            }
        }
    }

    #[test]
    fn oversized_debian_search_results_return_a_limit_error() {
        let entry = PackageInfo {
            name: "pkg".to_string(),
            version: "1.0".to_string(),
            description: "d".repeat(16_000),
            source: WirePackageSource::Official,
        };
        // ~600 entries x ~16 KiB ≈ 9.6 MB encoded: over the 8 MiB budget.
        let count = 600;
        let oversized = Response::Success {
            id: 42,
            result: ResponseResult::DebianSearch(vec![entry; count]),
        };
        let raw = crate::daemon::protocol::encode_frame(&oversized).expect("encode oversized");
        assert!(
            raw.len() > MAX_RESPONSE_SIZE,
            "test setup: payload must exceed the budget"
        );

        let encoded = encode_bounded_response(&oversized, 42).expect("bounded response");
        assert!(encoded.len() <= MAX_RESPONSE_SIZE);
        let (_, payload) = crate::daemon::protocol::split_frame(&encoded).expect("frame header");
        let decoded: Response = bitcode::deserialize(payload).expect("limit frame decodes");
        assert!(matches!(
            decoded,
            Response::Error {
                id: 42,
                code: error_codes::RESPONSE_TOO_LARGE,
                ..
            }
        ));
    }

    #[test]
    fn oversized_search_results_return_a_limit_error() {
        let entry = PackageInfo {
            name: "pkg".to_string(),
            version: "1.0".to_string(),
            description: "d".repeat(16_000),
            source: WirePackageSource::Official,
        };
        let count = 600;
        let oversized = Response::Success {
            id: 43,
            result: ResponseResult::Search(SearchResult {
                packages: vec![entry; count],
                total: count,
            }),
        };

        let encoded = encode_bounded_response(&oversized, 43).expect("bounded response");
        assert!(encoded.len() <= MAX_RESPONSE_SIZE);
        let (_, payload) = crate::daemon::protocol::split_frame(&encoded).expect("frame header");
        let decoded: Response = bitcode::deserialize(payload).expect("limit frame decodes");
        assert!(matches!(
            decoded,
            Response::Error {
                id: 43,
                code: error_codes::RESPONSE_TOO_LARGE,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn response_write_codec_accepts_frames_above_the_request_budget() {
        let (mut client, server) = tokio::net::UnixStream::pair().expect("socket pair");
        let payload_len = MAX_REQUEST_SIZE + 1;
        let writer = tokio::spawn(async move {
            let mut framed_write = LengthDelimitedCodec::builder()
                .max_frame_length(MAX_RESPONSE_SIZE)
                .new_write(server);
            framed_write.send(vec![0u8; payload_len].into()).await
        });
        // Drain so the write cannot stall on a full socket buffer.
        let mut remaining = 4 + payload_len;
        let mut buf = vec![0u8; 64 * 1024];
        while remaining > 0 {
            let n = tokio::io::AsyncReadExt::read(&mut client, &mut buf)
                .await
                .expect("drain response frame");
            assert!(n > 0, "writer closed before the frame was fully sent");
            remaining = remaining.saturating_sub(n);
        }
        writer
            .await
            .expect("write task")
            .expect("write codec must accept a frame larger than the request budget");
    }

    #[tokio::test]
    async fn request_sized_codec_cannot_send_the_response_budget() {
        let (_client, server) = tokio::net::UnixStream::pair().expect("socket pair");
        let mut framed_write = LengthDelimitedCodec::builder()
            .max_frame_length(MAX_REQUEST_SIZE)
            .new_write(server);
        framed_write
            .send(vec![0u8; MAX_REQUEST_SIZE + 1].into())
            .await
            .expect_err("a 1 MiB write cap would reject the new response budget");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fast_status_writes_run_through_the_blocking_adapter() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("status.bin");
        let status = crate::core::fast_status::FastStatus::new(10, 4, 1, 2);

        write_fast_status_async(status, path.clone())
            .await
            .expect("write fast status");

        let persisted =
            crate::core::fast_status::FastStatus::read_from_file(&path).expect("read fast status");
        assert_eq!(persisted.total_packages, 10);
        assert_eq!(persisted.updates_available, 2);
    }

    #[test]
    fn signal_listener_failures_are_not_treated_as_shutdown_signals() {
        validate_signal_result(Ok(()), "SIGINT").expect("received signal");
        let error = validate_signal_result(
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "signals unavailable",
            )),
            "SIGINT",
        )
        .expect_err("listener registration failure must propagate");
        assert!(error.to_string().contains("Failed to listen for SIGINT"));
    }

    #[test]
    fn internal_daemon_failures_produce_unsuccessful_exit_results() {
        assert!(daemon_shutdown_result(None).is_ok());
        let error = daemon_shutdown_result(Some("worker crashed".to_string()))
            .expect_err("internal failure must make daemon exit unsuccessfully");
        assert_eq!(error.to_string(), "worker crashed");
    }

    #[tokio::test]
    async fn daemon_client_writes_have_a_deadline() {
        let stalled = std::future::pending::<std::io::Result<()>>();
        let error = await_client_write(stalled, Duration::from_millis(1))
            .await
            .expect_err("stalled client write must time out");
        assert!(error.to_string().contains("write timed out"));

        await_client_write(std::future::ready(Ok(())), Duration::from_secs(1))
            .await
            .expect("completed write must succeed");
    }

    #[tokio::test(start_paused = true)]
    async fn background_maintenance_survives_intervening_health_ticks() {
        let start = tokio::time::Instant::now();
        let mut schedule = BackgroundSchedule::new();
        let shutdown = CancellationToken::new();

        for minute in 1..5 {
            assert_eq!(
                schedule.next(&shutdown).await,
                BackgroundEvent::SocketHealth
            );
            assert_eq!(start.elapsed(), Duration::from_secs(minute * 60));
        }
        assert_eq!(schedule.next(&shutdown).await, BackgroundEvent::Maintenance);
        assert_eq!(start.elapsed(), STATUS_REFRESH_INTERVAL);

        // A health check due at the same instant must still run afterwards.
        assert_eq!(
            schedule.next(&shutdown).await,
            BackgroundEvent::SocketHealth
        );
        for _ in 6..10 {
            assert_eq!(
                schedule.next(&shutdown).await,
                BackgroundEvent::SocketHealth
            );
        }
        assert_eq!(schedule.next(&shutdown).await, BackgroundEvent::Maintenance);
        assert_eq!(start.elapsed(), STATUS_REFRESH_INTERVAL * 2);
    }

    #[tokio::test(start_paused = true)]
    async fn background_shutdown_takes_priority_over_due_ticks() {
        let mut schedule = BackgroundSchedule::new();
        let shutdown = CancellationToken::new();
        tokio::time::advance(STATUS_REFRESH_INTERVAL).await;
        shutdown.cancel();
        assert_eq!(schedule.next(&shutdown).await, BackgroundEvent::Shutdown);
    }

    #[test]
    fn fast_status_reader_ttl_matches_daemon_writer_cadence() {
        // If the reader TTL is shorter than the writer interval, the
        // zero-IPC fast path rejects every file between daemon refreshes.
        assert_eq!(
            STATUS_REFRESH_INTERVAL.as_secs(),
            crate::core::fast_status::FAST_STATUS_FRESHNESS_SECS,
            "FastStatus TTL must equal the daemon writer interval"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn idle_client_is_closed_and_releases_its_connection_metric() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let data_dir = directory.path().join("data");
        std::fs::create_dir_all(&data_dir)?;
        let state = Arc::new(super::super::handlers::DaemonState::new_isolated(
            &data_dir,
            super::super::index::PackageIndex::empty(),
            Arc::new(crate::package_managers::mock::MockPackageManager::new_in(
                "arch", &data_dir,
            )),
        )?);
        let baseline = GLOBAL_METRICS.snapshot().active_connections;
        let (server, _idle_client) = tokio::net::UnixStream::pair()?;

        let task = tokio::spawn(handle_client_with_idle_timeout(
            server,
            Arc::clone(&state),
            Duration::from_millis(20),
            CancellationToken::new(),
        ));
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .context("idle client did not time out")???;

        assert_eq!(
            GLOBAL_METRICS.snapshot().active_connections,
            baseline,
            "idle timeout must release the active connection guard"
        );

        let (server, _idle_client) = tokio::net::UnixStream::pair()?;
        let cancellation = CancellationToken::new();
        let client_token = cancellation.clone();
        let (started, ready) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            started.send(()).unwrap();
            handle_client(server, state, client_token).await
        });
        ready.await?;
        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .context("shutdown did not close the idle connection")???;
        assert_eq!(GLOBAL_METRICS.snapshot().active_connections, baseline);
        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn startup_prewarms_every_common_search_query() -> Result<()> {
        let names: Vec<_> = (0..120)
            .map(|index| format!("python-package-{index:03}"))
            .collect();
        let records: Vec<_> = names
            .iter()
            .map(|name| (name.as_str(), "1.0", "Python fixture"))
            .collect();
        let index = super::super::index::PackageIndex::from_records(&records);
        let directory = tempfile::tempdir()?;
        let data_dir = directory.path().join("data");
        std::fs::create_dir_all(&data_dir)?;
        let state = Arc::new(super::super::handlers::DaemonState::new_isolated(
            &data_dir,
            index,
            Arc::new(crate::package_managers::mock::MockPackageManager::new_in(
                "arch", &data_dir,
            )),
        )?);
        let socket_path = directory.path().join("prewarm.sock");
        let fast_status_path = directory.path().join("omg.status");
        let listener = UnixListener::bind(&socket_path)?;
        let server = tokio::spawn(run_with_status_path(
            listener,
            Arc::clone(&state),
            socket_path.clone(),
            fast_status_path.clone(),
        ));

        let queries = ["", "linux", "python", "node", "firefox", "git"];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if fast_status_path.is_file()
                && queries.iter().all(|query| state.cache.get(query).is_some())
            {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                server.abort();
                anyhow::bail!("startup did not publish fast status and prewarm all common queries");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        let response = tokio::time::timeout(Duration::from_secs(5), async {
            let stream = tokio::net::UnixStream::connect(&socket_path).await?;
            let mut framed = LengthDelimitedCodec::builder().new_framed(stream);
            let request = Request::Search {
                id: 1,
                query: "python".to_string(),
                limit: Some(100),
            };
            framed
                .send(crate::daemon::protocol::encode_frame(&request)?.into())
                .await?;
            framed
                .next()
                .await
                .context("daemon closed before returning search results")?
                .context("read search response")
        })
        .await;
        server.abort();
        let frame = response.context("timed out waiting for prewarmed IPC search")??;
        let (_, payload) = crate::daemon::protocol::split_frame(&frame)?;
        let response: Response = bitcode::deserialize(payload)?;
        let Response::Success {
            id: 1,
            result: ResponseResult::Search(results),
        } = response
        else {
            anyhow::bail!("prewarmed IPC search must return the matching successful response");
        };
        assert_eq!(
            results.total, 120,
            "IPC search must report the full inventory"
        );
        assert_eq!(
            results.packages.len(),
            100,
            "IPC search must honor its limit"
        );
        for limit in [75, 120] {
            let response = handle_request(
                Arc::clone(&state),
                Request::Search {
                    id: 1,
                    query: "python".to_string(),
                    limit: Some(limit),
                },
            )
            .await;
            let Response::Success {
                result: ResponseResult::Search(results),
                ..
            } = response
            else {
                anyhow::bail!("prewarmed search must succeed");
            };
            assert_eq!(
                results.total, 120,
                "prewarming must retain the backing inventory"
            );
            assert_eq!(
                results.packages.len(),
                limit,
                "request limits apply after cache lookup"
            );
        }
        Ok(())
    }
}
