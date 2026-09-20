#![cfg(feature = "arch")]

//! Coverage 18: contract tests for `handle_client` early-reject paths in
//! `src/daemon/server.rs`, driven end-to-end through the REAL server
//! (`server::run`) over a real Unix socket.
//!
//! Each test pins an observable wire contract:
//! - version mismatch   -> PARSE_ERROR with exact message, id 0, then close
//! - malformed header   -> PARSE_ERROR with exact message, id 0, then close
//! - undecodable body   -> PARSE_ERROR naming the failure, id 0, then close
//!   (+ validation_failures metric)
//! - oversized frame    -> silent teardown: NO response frame, connection EOF
//! - rate-limit burst   -> RATE_LIMITED rejections echoing request ids with
//!   an exact message; connection stays usable after
//!
//! Metric deltas are asserted through the daemon's own Metrics IPC response,
//! so a mutation that drops `inc_requests_failed()` is also caught.

pub mod common;

use anyhow::{Context, Result};
use common::*;
use omg_lib::daemon::handlers::DaemonState;
use omg_lib::daemon::index::PackageIndex;
use omg_lib::daemon::protocol::{
    MetricsSnapshot, PROTOCOL_VERSION, Request, Response, ResponseResult, error_codes,
};
use omg_lib::daemon::server;
use omg_lib::package_managers::mock::MockPackageManager;
use serial_test::serial;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::timeout;

/// Mirror of the private `MAX_REQUEST_SIZE` in `src/daemon/server.rs`
/// (the `LengthDelimitedCodec` cap). If the product raises its real cap past
/// this value, the oversized-frame test below fails loudly instead of
/// passing vacuously against a moved threshold.
const REQUEST_WIRE_CAP: usize = 1024 * 1024;

/// Per-read timeout. Long enough for loaded CI machines, short enough that a
/// "server went silent" regression fails fast.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Burst size sent at the rate limiter (product burst budget is 100).
const RATE_BURST_N: usize = 150;
const RATE_LIMITED_MESSAGE: &str = "Rate limit exceeded. Please slow down.";

// ═══════════════════════════════════════════════════════════════════════════════
// Fixture: the REAL daemon server on a private Unix socket
// ═══════════════════════════════════════════════════════════════════════════════

struct RealServerFixture {
    temp_dir: Option<TempDir>,
    socket_path: PathBuf,
    server: Option<tokio::task::JoinHandle<Result<()>>>,
}

impl RealServerFixture {
    async fn new() -> Result<Self> {
        Self::with_packages(&[], &[]).await
    }

    async fn with_packages(installed: &[(&str, &str)], available: &[(&str, &str)]) -> Result<Self> {
        init_test_env();
        let temp_dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .context("failed to create private fixture temp dir")?;
        let data_dir = temp_dir.path().join("data");
        std::fs::create_dir_all(&data_dir)?;
        let installed: std::collections::BTreeMap<_, _> = installed.iter().copied().collect();
        let available: std::collections::BTreeMap<_, _> = available.iter().copied().collect();
        std::fs::write(
            data_dir.join("mock_state_pacman.json"),
            serde_json::to_vec(&serde_json::json!({
                "installed": installed,
                "available": available,
            }))?,
        )?;

        // Scoped env: audit logger and persistent cache capture their data-dir
        // paths during construction (same isolation pattern as daemon_e2e_ipc).
        let state = Arc::new(temp_env::with_vars(
            [
                ("OMG_DAEMON_DATA_DIR", Some(data_dir.as_os_str())),
                ("OMG_DATA_DIR", Some(data_dir.as_os_str())),
            ],
            || -> anyhow::Result<_> {
                omg_lib::core::security::init_audit_logger()?;
                DaemonState::new_isolated(
                    &data_dir,
                    PackageIndex::empty(),
                    Arc::new(MockPackageManager::new_in("arch", &data_dir)),
                )
            },
        )?);

        let socket_path = temp_dir.path().join("cov18.sock");
        omg_lib::core::paths::validate_socket_parent(&socket_path)
            .context("fixture must satisfy production socket-directory validation")?;
        let listener = UnixListener::bind(&socket_path)?;
        let server = tokio::spawn(server::run(
            listener,
            Arc::clone(&state),
            socket_path.clone(),
        ));

        let fixture = Self {
            temp_dir: Some(temp_dir),
            socket_path,
            server: Some(server),
        };
        // A bound socket alone does not prove the accept loop or signal
        // listeners have been polled. Require a real production response.
        metrics_probe(&fixture).await?;
        Ok(fixture)
    }

    async fn connect(&self) -> Result<UnixStream> {
        UnixStream::connect(&self.socket_path)
            .await
            .with_context(|| format!("connect to {}", self.socket_path.display()))
    }

    async fn shutdown(mut self) -> Result<()> {
        let server = self.server.as_mut().context("missing server task")?;
        anyhow::ensure!(
            !server.is_finished(),
            "server exited before fixture shutdown"
        );
        // These serial tests own the sole server in their test process.
        // Exercise its real SIGTERM drain, rather than detaching the task.
        nix::sys::signal::kill(nix::unistd::Pid::this(), nix::sys::signal::Signal::SIGTERM)?;
        match timeout(Duration::from_secs(35), &mut *server).await {
            Ok(result) => result.context("server task panicked")??,
            Err(error) => {
                server.abort();
                if timeout(Duration::from_secs(5), &mut *server).await.is_err() {
                    eprintln!("server task did not acknowledge cancellation");
                }
                return Err(error).context("server did not drain after SIGTERM");
            }
        }
        drop(self.server.take());
        anyhow::ensure!(
            UnixStream::connect(&self.socket_path).await.is_err(),
            "server still accepts connections after shutdown"
        );
        let directory = self.temp_dir.take().context("missing fixture directory")?;
        let path = directory.path().to_path_buf();
        directory.close().context("fixture directory cleanup")?;
        anyhow::ensure!(!path.exists(), "fixture directory survived cleanup");
        Ok(())
    }
}

impl Drop for RealServerFixture {
    fn drop(&mut self) {
        if let Some(server) = &self.server {
            server.abort();
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Raw-frame client helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Write one length-delimited frame (BE u32 length prefix + payload), exactly
/// what the daemon's `LengthDelimitedCodec` expects.
async fn send_raw_frame(stream: &mut UnixStream, payload: &[u8]) -> Result<()> {
    let len = u32::try_from(payload.len()).context("frame payload exceeds u32 length prefix")?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

/// Read exactly one frame. `Ok(None)` means clean EOF before any byte of a
/// new frame arrived (connection closed by the peer).
async fn try_read_raw_frame(stream: &mut UnixStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    if stream.read(&mut len_buf[..1]).await? == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut len_buf[1..]).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 8 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "response exceeds fixture allocation budget",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

fn decode_response(frame: &[u8]) -> Result<Response> {
    let (_, payload) = omg_lib::daemon::protocol::split_frame(frame)?;
    Ok(bitcode::deserialize(payload)?)
}

/// Read one framed response within [`READ_TIMEOUT`]. Errors if the connection
/// closes first or the peer goes silent.
async fn read_response(stream: &mut UnixStream) -> Result<Response> {
    let fut = try_read_raw_frame(stream);
    let frame = timeout(READ_TIMEOUT, fut)
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for a response frame"))?
        .map_err(|e| anyhow::anyhow!("I/O error reading response frame: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("connection closed before a response frame arrived"))?;
    decode_response(&frame)
}

/// Assert the daemon tears the connection down cleanly: clean EOF within
/// [`READ_TIMEOUT`], and no further frame bytes were pushed onto the wire.
async fn expect_eof(stream: &mut UnixStream, ctx: &str) {
    match timeout(READ_TIMEOUT, try_read_raw_frame(stream)).await {
        Err(error) => panic!(
            "{ctx}: expected the server to close the connection, but it stayed open: {error}"
        ),
        Ok(Err(e)) => panic!("{ctx}: expected clean EOF, got I/O error: {e}"),
        Ok(Ok(None)) => {}
        Ok(Ok(Some(bytes))) => panic!(
            "{ctx}: expected EOF, but the server sent another frame of {} bytes",
            bytes.len()
        ),
    }
}

async fn metrics_probe(fixture: &RealServerFixture) -> Result<MetricsSnapshot> {
    let mut stream = fixture.connect().await?;
    let bytes = omg_lib::daemon::protocol::encode_frame(&Request::Metrics { id: 0xBEEF })?;
    send_raw_frame(&mut stream, &bytes).await?;
    match read_response(&mut stream).await? {
        Response::Success {
            id: 0xBEEF,
            result: ResponseResult::Metrics(snapshot),
        } => Ok(snapshot),
        other => Err(anyhow::anyhow!(
            "expected a Metrics snapshot response, got {other:?}"
        )),
    }
}

/// Read the daemon's own `requests_failed` metric through the Metrics IPC
/// request, so metric-delta assertions exercise the real serving path.
async fn requests_failed_probe(fixture: &RealServerFixture) -> Result<u64> {
    Ok(metrics_probe(fixture).await?.requests_failed)
}

fn ping_wire(id: u64) -> Result<Vec<u8>> {
    let payload = omg_lib::daemon::protocol::encode_frame(&Request::Ping { id })?;
    let mut wire = u32::try_from(payload.len())?.to_be_bytes().to_vec();
    wire.extend_from_slice(&payload);
    Ok(wire)
}

fn assert_pong(response: Response, expected_id: u64) {
    match response {
        Response::Success {
            id,
            result: ResponseResult::Ping(message),
        } => {
            assert_eq!(id, expected_id);
            assert_eq!(message, "pong");
        }
        other => panic!("expected matching pong, got {other:?}"),
    }
}

async fn request_on_wire(fixture: &RealServerFixture, request: Request) -> Result<Response> {
    let mut stream = fixture.connect().await?;
    send_raw_frame(
        &mut stream,
        &omg_lib::daemon::protocol::encode_frame(&request)?,
    )
    .await?;
    read_response(&mut stream).await
}

#[tokio::test]
#[serial]
async fn package_inventory_and_updates_survive_the_production_transport() -> Result<()> {
    // Literal backend state, not expected values computed by another handler.
    // This proves real transport with an injected backend, not native ALPM.
    let fixture = RealServerFixture::with_packages(
        &[("git", "2.0.0"), ("firefox", "122.0.0")],
        &[("git", "2.1.0"), ("firefox", "122.0.0")],
    )
    .await?;
    match request_on_wire(&fixture, Request::Status { id: 721 }).await? {
        Response::Success {
            id: 721,
            result: ResponseResult::Status(status),
        } => {
            assert_eq!(status.total_packages, 2);
            assert_eq!(status.explicit_packages, 2);
            assert_eq!(status.orphan_packages, 0);
            assert_eq!(status.updates_available, 1);
        }
        other => panic!("status returned {other:?}"),
    }
    match request_on_wire(&fixture, Request::Explicit { id: 722 }).await? {
        Response::Success {
            id: 722,
            result: ResponseResult::Explicit(mut result),
        } => {
            result.packages.sort();
            assert_eq!(result.packages, vec!["firefox", "git"]);
        }
        other => panic!("explicit packages returned {other:?}"),
    }
    match request_on_wire(&fixture, Request::ExplicitCount { id: 723 }).await? {
        Response::Success {
            id: 723,
            result: ResponseResult::ExplicitCount(count),
        } => assert_eq!(count, 2),
        other => panic!("explicit count returned {other:?}"),
    }
    match request_on_wire(&fixture, Request::ListUpdates { id: 724 }).await? {
        Response::Success {
            id: 724,
            result: ResponseResult::ListUpdates(updates),
        } => {
            assert_eq!(updates.len(), 1);
            assert_eq!(updates[0].name, "git");
            assert_eq!(updates[0].old_version, "2.0.0");
            assert_eq!(updates[0].new_version, "2.1.0");
            assert_eq!(updates[0].repo, "extra");
        }
        other => panic!("updates returned {other:?}"),
    }
    fixture.shutdown().await
}

#[tokio::test]
#[serial]
async fn clearing_search_cache_forces_a_new_lookup_over_real_ipc() -> Result<()> {
    let fixture = RealServerFixture::new().await?;
    let baseline = metrics_probe(&fixture).await?;
    // An unseeded query avoids interference from the background prewarm list.
    for (id, expected_hits, expected_misses) in [(701, 0, 1), (702, 1, 1), (704, 1, 2)] {
        if id == 704 {
            match request_on_wire(&fixture, Request::CacheClear { id: 703 }).await? {
                Response::Success {
                    id: 703,
                    result: ResponseResult::Message(message),
                } => assert_eq!(message, "cleared"),
                other => panic!("cache clear returned {other:?}"),
            }
        }
        match request_on_wire(
            &fixture,
            Request::Search {
                id,
                query: "cov18-cache-invalidation-unique-query".into(),
                limit: Some(2),
            },
        )
        .await?
        {
            Response::Success {
                id: response_id,
                result: ResponseResult::Search(result),
            } => {
                assert_eq!(response_id, id);
                assert!(result.packages.is_empty());
                assert_eq!(result.total, 0);
            }
            other => panic!("search returned {other:?}"),
        }
        let metrics = metrics_probe(&fixture).await?;
        assert_eq!(metrics.cache_hits - baseline.cache_hits, expected_hits);
        assert_eq!(
            metrics.cache_misses - baseline.cache_misses,
            expected_misses
        );
    }
    fixture.shutdown().await
}

#[tokio::test]
#[serial]
async fn package_info_cache_preserves_metadata_and_missing_package_identity() -> Result<()> {
    let fixture = RealServerFixture::new().await?;
    let baseline = metrics_probe(&fixture).await?;
    // The mock catalog declares git 2.43.0 with this literal description.
    // Repeat both paths to exercise positive and negative cache responses.
    for id in [731, 733] {
        match request_on_wire(
            &fixture,
            Request::Info {
                id,
                package: "git".into(),
            },
        )
        .await?
        {
            Response::Success {
                id: response_id,
                result: ResponseResult::Info(info),
            } => {
                assert_eq!(response_id, id);
                assert_eq!(info.name, "git");
                assert_eq!(info.version, "2.43.0");
                assert_eq!(info.description, "Version control");
                assert_eq!(
                    info.source,
                    omg_lib::daemon::protocol::WirePackageSource::Official
                );
            }
            other => panic!("package info returned {other:?}"),
        }
        match request_on_wire(
            &fixture,
            Request::Info {
                id: id + 1,
                package: "cov18-absent-package".into(),
            },
        )
        .await?
        {
            Response::Error {
                id: response_id,
                code,
                message,
            } => {
                assert_eq!(response_id, id + 1);
                assert_eq!(code, error_codes::PACKAGE_NOT_FOUND);
                assert_eq!(message, "Package not found: cov18-absent-package");
            }
            other @ Response::Success { .. } => panic!("missing package returned {other:?}"),
        }
    }
    let metrics = metrics_probe(&fixture).await?;
    assert_eq!(metrics.cache_hits - baseline.cache_hits, 1);
    assert_eq!(metrics.cache_misses - baseline.cache_misses, 2);
    fixture.shutdown().await
}

#[tokio::test]
#[serial]
async fn isolated_refresh_refusal_preserves_server_liveness() -> Result<()> {
    let fixture = RealServerFixture::new().await?;
    match request_on_wire(&fixture, Request::RefreshIndex { id: 711 }).await? {
        Response::Error { id, code, message } => {
            assert_eq!(id, 711);
            assert_eq!(code, error_codes::INVALID_PARAMS);
            assert_eq!(
                message,
                "Index refresh is unavailable in an isolated daemon"
            );
        }
        other @ Response::Success { .. } => panic!("isolated refresh returned {other:?}"),
    }
    assert_pong(
        request_on_wire(&fixture, Request::Ping { id: 712 }).await?,
        712,
    );
    fixture.shutdown().await
}

#[tokio::test]
#[serial]
async fn custom_socket_publishes_status_in_its_private_directory() -> Result<()> {
    let fixture = RealServerFixture::new().await?;
    let status_path = fixture.socket_path.with_file_name("omg.status");
    let published = timeout(READ_TIMEOUT, async {
        loop {
            if let Some(status) =
                omg_lib::core::fast_status::FastStatus::read_validated(&status_path)
            {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .with_context(|| {
        format!(
            "custom socket never received valid private fast status: file_exists={}, decodable={}",
            status_path.is_file(),
            omg_lib::core::fast_status::FastStatus::read_from_file(&status_path).is_some()
        )
    });
    fixture.shutdown().await?;
    let status = published?;
    assert_eq!(status.total_packages, 0);
    assert_eq!(status.explicit_packages, 0);
    assert_eq!(status.updates_available, 0);
    Ok(())
}

#[tokio::test]
#[serial]
async fn fragmented_then_coalesced_frames_preserve_response_order_and_ids() -> Result<()> {
    let fixture = RealServerFixture::new().await?;
    let mut stream = fixture.connect().await?;
    for byte in ping_wire(901)? {
        stream.write_all(&[byte]).await?;
        tokio::task::yield_now().await;
    }
    assert_pong(read_response(&mut stream).await?, 901);
    let mut coalesced = ping_wire(902)?;
    coalesced.extend_from_slice(&ping_wire(903)?);
    stream.write_all(&coalesced).await?;
    assert_pong(read_response(&mut stream).await?, 902);
    assert_pong(read_response(&mut stream).await?, 903);
    fixture.shutdown().await
}

#[tokio::test]
#[serial]
async fn incomplete_frames_disconnect_without_breaking_a_fresh_client() -> Result<()> {
    let fixture = RealServerFixture::new().await?;
    let wire = ping_wire(910)?;
    for length in [1, 3, 4, wire.len() - 1] {
        let mut interrupted = fixture.connect().await?;
        interrupted.write_all(&wire[..length]).await?;
        interrupted.shutdown().await?;
        drop(interrupted);
        let mut fresh = fixture.connect().await?;
        fresh.write_all(&ping_wire(911 + length as u64)?).await?;
        assert_pong(read_response(&mut fresh).await?, 911 + length as u64);
    }
    fixture.shutdown().await
}

#[tokio::test]
async fn response_reader_rejects_oversized_length_without_allocating_body() -> Result<()> {
    let (mut reader, mut writer) = UnixStream::pair()?;
    writer.write_all(&u32::MAX.to_be_bytes()).await?;
    let error = timeout(READ_TIMEOUT, try_read_raw_frame(&mut reader))
        .await?
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    Ok(())
}

#[tokio::test]
async fn response_reader_distinguishes_clean_eof_from_truncated_frames() -> Result<()> {
    for wire in [vec![0, 0], vec![0, 0, 0, 3, 1]] {
        let (mut reader, mut writer) = UnixStream::pair()?;
        writer.write_all(&wire).await?;
        drop(writer);
        let error = timeout(READ_TIMEOUT, try_read_raw_frame(&mut reader))
            .await?
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }
    let (mut reader, writer) = UnixStream::pair()?;
    drop(writer);
    assert!(try_read_raw_frame(&mut reader).await?.is_none());
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Contract 1: protocol-version mismatch rejection
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[serial]
async fn version_mismatch_gets_exact_parse_error_then_connection_closes() -> Result<()> {
    let fixture = RealServerFixture::new().await?;
    let baseline = requests_failed_probe(&fixture).await?;

    let mut stream = fixture.connect().await?;
    // A well-formed Ping from a peer speaking a future protocol version.
    let ping = Request::Ping { id: 77 };
    let mut frame = Vec::new();
    frame.extend_from_slice(&999_001u32.to_le_bytes());
    frame.extend_from_slice(&bitcode::serialize(&ping)?);
    send_raw_frame(&mut stream, &frame).await?;

    match read_response(&mut stream).await? {
        Response::Error { id, code, message } => {
            assert_eq!(
                id, 0,
                "undecodable requests must be answered on reserved error id 0"
            );
            assert_eq!(
                code,
                error_codes::PARSE_ERROR,
                "version mismatch must surface as PARSE_ERROR"
            );
            assert_eq!(
                message,
                format!(
                    "unsupported peer protocol version 999001 (this daemon speaks {PROTOCOL_VERSION}); update omg"
                ),
                "rejection must tell the client WHY (peer version) and WHAT to do"
            );
        }
        Response::Success { .. } => {
            panic!("a peer speaking protocol version 999001 must not be served");
        }
    }
    // The stream is unusable afterwards: the daemon must close it, not hang.
    expect_eof(&mut stream, "after version-mismatch rejection").await;

    let after = requests_failed_probe(&fixture).await?;
    assert_eq!(
        after,
        baseline + 1,
        "each version-mismatch rejection must count exactly one failed request metric"
    );
    fixture.shutdown().await
}

// ═══════════════════════════════════════════════════════════════════════════════
// Contract 2: frame shorter than the version header
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[serial]
async fn frame_too_short_for_header_gets_parse_error_then_connection_closes() -> Result<()> {
    let fixture = RealServerFixture::new().await?;
    let baseline = requests_failed_probe(&fixture).await?;

    let mut stream = fixture.connect().await?;
    // Two junk bytes cannot contain the 4-byte version header.
    send_raw_frame(&mut stream, &[0xDE, 0xAD]).await?;

    match read_response(&mut stream).await? {
        Response::Error { id, code, message } => {
            assert_eq!(id, 0);
            assert_eq!(
                code,
                error_codes::PARSE_ERROR,
                "short frames must surface as PARSE_ERROR"
            );
            assert_eq!(
                message,
                "malformed frame header: frame too short to contain the protocol version header",
                "the daemon must name the framing failure verbatim"
            );
        }
        Response::Success { .. } => {
            panic!("a frame without a complete version header must not be served");
        }
    }
    expect_eof(&mut stream, "after malformed-header rejection").await;

    let after = requests_failed_probe(&fixture).await?;
    assert_eq!(
        after,
        baseline + 1,
        "malformed header must bump requests_failed"
    );
    fixture.shutdown().await
}

// ═══════════════════════════════════════════════════════════════════════════════
// Contract 3: medium frame reaches protocol parsing
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[serial]
async fn four_kib_frame_reaches_protocol_parser_before_rejection() -> Result<()> {
    let fixture = RealServerFixture::new().await?;
    let baseline = requests_failed_probe(&fixture).await?;
    let mut stream = fixture.connect().await?;

    // Above a mutated 2 KiB cap but comfortably below the documented 1 MiB
    // cap. The zeroed protocol header is malformed, so acceptance is observed
    // as one PARSE_ERROR response followed by connection close.
    send_raw_frame(&mut stream, &vec![0; 4 * 1024]).await?;
    match read_response(&mut stream).await? {
        Response::Error { id, code, message } => {
            assert_eq!(id, 0);
            assert_eq!(code, error_codes::PARSE_ERROR);
            assert!(message.contains("protocol version") || message.contains("frame header"));
        }
        other @ Response::Success { .. } => {
            anyhow::bail!("expected parse-error response, got {other:?}")
        }
    }
    expect_eof(&mut stream, "4 KiB malformed frame").await;

    let after = requests_failed_probe(&fixture).await?;
    assert_eq!(after, baseline + 1);
    fixture.shutdown().await
}

// ═══════════════════════════════════════════════════════════════════════════════
// Contract 4: correct version header, undecodable payload
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[serial]
async fn undecodable_payload_gets_parse_error_validation_failure_then_close() -> Result<()> {
    let fixture = RealServerFixture::new().await?;
    let baseline = requests_failed_probe(&fixture).await?;

    let mut stream = fixture.connect().await?;
    let mut frame = Vec::new();
    frame.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    frame.extend_from_slice(&[0xFFu8; 100]); // garbage payload
    send_raw_frame(&mut stream, &frame).await?;

    match read_response(&mut stream).await? {
        Response::Error { id, code, message } => {
            assert_eq!(id, 0, "requests that never decoded must answer on id 0");
            assert_eq!(code, error_codes::PARSE_ERROR);
            assert!(
                message.starts_with("Failed to deserialize request: "),
                "deserialization failure must name the cause, got: {message}"
            );
        }
        Response::Success { .. } => {
            panic!("an undecodable payload must never be dispatched to a handler");
        }
    }
    expect_eof(&mut stream, "after deserialization failure").await;

    let after = requests_failed_probe(&fixture).await?;
    assert_eq!(after, baseline + 1);

    fixture.shutdown().await
}

// ═══════════════════════════════════════════════════════════════════════════════
// Contract 5: frame exceeding MAX_REQUEST_SIZE tears down WITHOUT a response
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[serial]
async fn oversized_frame_tears_down_silently_without_any_response_frame() -> Result<()> {
    let fixture = RealServerFixture::new().await?;
    let baseline = requests_failed_probe(&fixture).await?;

    let mut stream = fixture.connect().await?;
    // Announce a frame larger than the codec's max, then dribble some body
    // bytes so a codec that ignores its cap would keep waiting (and the test
    // would time out -> fail) rather than see EOF.
    let announced = (REQUEST_WIRE_CAP + 1) as u32;
    stream.write_all(&announced.to_be_bytes()).await?;
    stream.write_all(&[0u8; 4096]).await?;
    stream.flush().await?;

    // Contract: NO response frame, then teardown. A hard reset also proves
    // teardown, so ConnectionReset/ConnectionAborted/BrokenPipe pass too.
    let outcome = timeout(READ_TIMEOUT, try_read_raw_frame(&mut stream)).await;
    match outcome {
        Err(error) => panic!(
            "oversized frame: server neither answered nor closed the connection \
             (codec cap missing?): {error}"
        ),
        Ok(Err(e))
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
            ) => {}
        Ok(Err(e)) => panic!("oversized frame: unexpected I/O error: {e}"),
        Ok(Ok(None)) => {}
        Ok(Ok(Some(bytes))) => panic!(
            "oversized frame must be rejected silently, but the server sent a \
             {}-byte response frame",
            bytes.len()
        ),
    }

    let after = requests_failed_probe(&fixture).await?;
    assert_eq!(
        after,
        baseline + 1,
        "frame-decode failure must bump requests_failed even though nothing is answered"
    );
    fixture.shutdown().await
}

// ═══════════════════════════════════════════════════════════════════════════════
// Contract 6: rate limit rejects bursts with exact envelope, keeps connection
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[serial]
async fn rate_limited_burst_rejects_with_exact_envelope_and_keeps_connection_open() -> Result<()> {
    let fixture = RealServerFixture::new().await?;
    let mut stream = fixture.connect().await?;

    // Fire 150 pings back-to-back inside the ~100-request burst budget.
    let frames: Vec<Vec<u8>> = (0..RATE_BURST_N)
        .map(|i| {
            omg_lib::daemon::protocol::encode_frame(&Request::Ping { id: i as u64 })
                .map_err(anyhow::Error::from)
        })
        .collect::<Result<_>>()?;
    for frame in &frames {
        send_raw_frame(&mut stream, frame).await?;
    }

    let mut responses = Vec::with_capacity(RATE_BURST_N);
    for _ in 0..RATE_BURST_N {
        responses.push(read_response(&mut stream).await?);
    }

    let limited_idx: Vec<usize> = responses
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            matches!(
                r,
                Response::Error { code, .. } if *code == error_codes::RATE_LIMITED
            )
        })
        .map(|(i, _)| i)
        .collect();

    assert!(
        !limited_idx.is_empty(),
        "a burst beyond the per-connection rate budget must produce at least one \
         RATE_LIMITED rejection (limiter removed or burst raised?)"
    );

    // The very first request of a fresh connection must never be rejected:
    // pins the burst allowance against a zero-budget regression.
    assert!(
        matches!(responses[0], Response::Success { .. }),
        "first request on a fresh connection must not be rate-limited"
    );

    for &i in &limited_idx {
        match &responses[i] {
            Response::Error { id, code, message } => {
                assert_eq!(*code, error_codes::RATE_LIMITED);
                assert_eq!(
                    *id, i as u64,
                    "rejection must echo the offending request's id"
                );
                assert_eq!(
                    message, RATE_LIMITED_MESSAGE,
                    "rate-limit rejection must carry the exact operator-facing message"
                );
            }
            Response::Success { .. } => unreachable!("filtered above"),
        }
    }
    // Everything outside the rejections must have been served successfully,
    // with matching ids: the limiter must not corrupt unrelated traffic.
    for (i, response) in responses.iter().enumerate() {
        if limited_idx.contains(&i) {
            continue;
        }
        match response {
            Response::Success { id, .. } => {
                assert_eq!(*id, i as u64, "served response must echo its request id");
            }
            other @ Response::Error { .. } => {
                panic!("request {i} was neither served nor rate-limited, got {other:?}")
            }
        }
    }

    // Rate limiting uses `continue`, not `break`: after tokens refill, the
    // SAME connection must serve again.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let follow_up = omg_lib::daemon::protocol::encode_frame(&Request::Ping { id: 4242 })?;
    send_raw_frame(&mut stream, &follow_up).await?;
    match read_response(&mut stream).await? {
        Response::Success { id, .. } => assert_eq!(id, 4242),
        other @ Response::Error { .. } => {
            panic!("connection must stay usable after a rate-limit rejection, got {other:?}")
        }
    }
    fixture.shutdown().await
}

#[tokio::test]
#[serial]
async fn active_connection_metric_returns_to_baseline_after_disconnect() -> Result<()> {
    let fixture = RealServerFixture::new().await?;
    // The metrics probe itself is the one expected live connection.
    wait_for_active_connections(&fixture, 1).await?;

    let mut stream = fixture.connect().await?;
    let ping = omg_lib::daemon::protocol::encode_frame(&Request::Ping { id: 0xCAFE })?;
    send_raw_frame(&mut stream, &ping).await?;
    assert!(matches!(
        read_response(&mut stream).await?,
        Response::Success { id: 0xCAFE, .. }
    ));
    wait_for_active_connections(&fixture, 2).await?;
    drop(stream);
    wait_for_active_connections(&fixture, 1).await?;
    fixture.shutdown().await
}

async fn wait_for_active_connections(fixture: &RealServerFixture, expected: i64) -> Result<()> {
    let deadline = Instant::now() + READ_TIMEOUT;
    loop {
        let active = metrics_probe(fixture).await?.active_connections;
        if active == expected {
            return Ok(());
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "active connections never reached {expected}; last value was {active}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
