//! Coverage tests #8: `src/core/client.rs`
//!
//! Pins falsifiable contracts for:
//! - `DaemonClient::daemon_disabled()` environment gating (exact acceptance set)
//! - insecure socket-directory validation before any connection attempt
//! - `DaemonClient::call()` framing: round-trip, ID echo/sequence, ID-mismatch,
//!   daemon-error surfacing, wrong-variant rejection, protocol-version rejection,
//!   disconnect detection (transport separation is checked by compile-fail doctests)
//! - `connect_to()` retry behavior: ECONNREFUSED retried with real backoff and
//!   named "after retries"; missing socket fails fast without retry suffix
//! - `SyncDaemonClient::acquire()/call()` via `sync_roundtrip`: payload pinning,
//!   ID validation, error codes, protocol-version rejection
//!
//! Mock daemons speak the real wire format (`write_frame`/`read_frame`, which is
//! byte-compatible with the client's `LengthDelimitedCodec`) over real Unix
//! sockets, so every framing contract is exercised end-to-end.
//!
//! NOTE for maintainers: `TempDir` cleanup races with the mock-server thread, and
//! the server only observes EOF once the *client* drops its connection. Every
//! test must therefore `drop(client)` before joining the captured-request handle.
//!
//! The single `unsafe` usage mirrors `tests/common/mod.rs`: scoped, documented
//! process-environment writes inside an RAII guard, safe because every test
//! touching them is `#[serial]`.

#![cfg(unix)]
#![expect(unsafe_code)]

pub mod common;

use common::*;
use omg_lib::core::client::{DaemonClient, SyncDaemonClient};
use omg_lib::daemon::{protocol, protocol::Request, protocol::Response, protocol::ResponseResult};
use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tempfile::TempDir;

// ═══════════════════════════════════════════════════════════════════════════════
// Environment pinning
// ═══════════════════════════════════════════════════════════════════════════════

/// Pin the three environment variables every client entry point consults.
///
/// Returns prior values and restores them on drop; tests are `#[serial]`, so
/// no other test in this binary observes intermediate state.
struct EnvGuard(Vec<(&'static str, Option<std::ffi::OsString>)>);

fn pin_env(vars: &[(&'static str, Option<&OsStr>)]) -> EnvGuard {
    let mut saved = Vec::new();
    // SAFETY: same justification as tests/common/mod.rs `init_test_env`: every
    // caller runs under #[serial], so no other test thread observes intermediate
    // state, and prior values are restored exactly once on guard drop.
    unsafe {
        for (key, value) in vars {
            saved.push((*key, std::env::var_os(key)));
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
    }
    EnvGuard(saved)
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        // SAFETY: see `pin_env`; drop runs while the #[serial] lock is held.
        unsafe {
            for (key, previous) in &self.0 {
                match previous {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

/// Run `f` with OMG_TEST_MODE / OMG_DISABLE_DAEMON / OMG_SOCKET_PATH pinned.
///
/// `disable_daemon` and `test_mode` are set verbatim (`None` removes the var);
/// `socket_path` overrides every `default_socket_path()` lookup (`None` removes
/// the override). Async work must be driven by a fresh runtime *inside* `f` so
/// the pins hold for its whole lifetime.
fn with_client_env<R>(
    disable_daemon: Option<&str>,
    test_mode: Option<&str>,
    socket_path: Option<&Path>,
    f: impl FnOnce() -> R,
) -> R {
    let _guard = pin_env(&[
        ("OMG_DISABLE_DAEMON", disable_daemon.map(OsStr::new)),
        ("OMG_TEST_MODE", test_mode.map(OsStr::new)),
        (
            "OMG_SOCKET_PATH",
            socket_path.map(std::path::Path::as_os_str),
        ),
        // Keep telemetry quiet for the duration; restore afterwards.
        ("OMG_DISABLE_TELEMETRY", Some(OsStr::new("1"))),
    ]);
    f()
}

/// Drive an async block on a dedicated single-threaded runtime.
fn block(f: impl Future<Output = ()>) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(f);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Mock daemon speaking the real wire format
// ═══════════════════════════════════════════════════════════════════════════════

use std::future::Future;

/// `Result::unwrap_err` without requiring `T: Debug`.
fn expect_err<T>(result: anyhow::Result<T>) -> anyhow::Error {
    result.map(drop).expect_err("expected an Err")
}

type ReplyFn = Box<dyn Fn(&Request) -> Option<Vec<u8>> + Send>;

/// Bind `socket_path`, accept one connection, decode requests frame-by-frame and
/// invoke `reply` for each. `reply` returning `None` closes the connection
/// without responding. The returned handle joins the thread and yields every
/// decoded request, in order.
fn spawn_mock_daemon(socket_path: &std::path::Path, reply: ReplyFn) -> JoinHandle<Vec<Request>> {
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path).expect("mock daemon bind");
    std::thread::spawn(move || {
        let mut captured = Vec::new();
        let Ok((mut stream, _)) = listener.accept() else {
            return captured;
        };
        while let Ok(bytes) = protocol::read_frame(&mut stream) {
            let Ok((_, payload)) = protocol::split_frame(&bytes) else {
                break;
            };
            let Ok(request) = bitcode::deserialize::<Request>(payload) else {
                break;
            };
            captured.push(request.clone());
            match reply(&request) {
                Some(frame) => {
                    if protocol::write_frame(&mut stream, &frame).is_err() {
                        break;
                    }
                }
                None => break,
            }
        }
        captured
    })
}

/// A mock daemon plus its tempdir (which keeps the private 0700 socket parent
/// alive) and the joined capture handle.
struct MockDaemon {
    _dir: TempDir,
    socket_path: PathBuf,
    captured: Option<JoinHandle<Vec<Request>>>,
}

impl MockDaemon {
    fn spawn(reply: ReplyFn) -> Self {
        let dir = TempDir::new().expect("tempdir");
        // The daemon's socket-parent security check requires a private 0700
        // directory; tempfile defaults to 0755 which is correctly rejected.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
                .expect("chmod tempdir to 0700");
        }
        let socket_path = dir.path().join("omg.sock");
        let captured = spawn_mock_daemon(&socket_path, reply);
        Self {
            _dir: dir,
            socket_path,
            captured: Some(captured),
        }
    }

    /// Join the server thread and return the decoded request log. The caller
    /// MUST have dropped its client connection first (the server exits on EOF).
    fn take_requests(&mut self) -> Vec<Request> {
        self.captured
            .take()
            .expect("requests already taken")
            .join()
            .expect("mock daemon thread panicked")
    }
}

/// Frame echoing back the request's own id with a fixed result.
fn echo_frame(request: &Request, result: &ResponseResult) -> Vec<u8> {
    protocol::encode_frame(&Response::Success {
        id: request.id(),
        result: result.clone(),
    })
    .expect("encode response frame")
}

/// Frame with a fixed (possibly wrong) id.
fn fixed_response_frame(response: &Response) -> Vec<u8> {
    protocol::encode_frame(response).expect("encode response frame")
}

/// Well-formed payload behind a foreign protocol-version header.
fn bad_version_frame(version: u32, response: &Response) -> Vec<u8> {
    let payload = bitcode::serialize(response).expect("serialize response");
    let mut frame = version.to_le_bytes().to_vec();
    frame.extend_from_slice(&payload);
    frame
}

fn ping_pong(message: &str) -> ResponseResult {
    ResponseResult::Ping(message.to_string())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Contracts
// ═══════════════════════════════════════════════════════════════════════════════

/// Contract: exactly {"1", "true", "TRUE"} for OMG_DISABLE_DAEMON, or truthy
/// OMG_TEST_MODE, disables all three client entry points with the exact error
/// "Daemon disabled by environment". Any other value must NOT trip the gate.
#[test]
#[serial]
fn daemon_disabled_gate_pins_exact_acceptance_set() {
    // Every truthy spelling of OMG_DISABLE_DAEMON gates all entry points.
    for value in ["1", "true", "TRUE"] {
        let err = with_client_env(Some(value), Some("0"), None, || {
            expect_err(SyncDaemonClient::acquire_with_timeout(
                Duration::from_millis(25),
            ))
        });
        assert_eq!(
            err.to_string(),
            "Daemon disabled by environment",
            "OMG_DISABLE_DAEMON={value} must gate acquire_with_timeout"
        );

        let err = with_client_env(Some(value), Some("0"), None, || {
            expect_err(SyncDaemonClient::acquire())
        });
        assert_eq!(
            err.to_string(),
            "Daemon disabled by environment",
            "OMG_DISABLE_DAEMON={value} must gate SyncDaemonClient::acquire"
        );

        with_client_env(Some(value), Some("0"), None, || {
            block(async {
                let err = expect_err(DaemonClient::connect().await);
                assert_eq!(
                    err.to_string(),
                    "Daemon disabled by environment",
                    "OMG_DISABLE_DAEMON={value} must gate async connect"
                );
            });
        });
    }

    // OMG_TEST_MODE alone (no explicit flag) trips the gate too.
    let err = with_client_env(None, Some("true"), None, || {
        expect_err(SyncDaemonClient::acquire())
    });
    assert_eq!(err.to_string(), "Daemon disabled by environment");

    // Benign values must fall through the gate into real connection logic:
    // pointing the socket path at a missing file yields a connect failure
    // whose message is the connection error, never the disabled message.
    let absent_dir = TempDir::new().expect("tempdir");
    #[cfg(unix)]
    std::fs::set_permissions(absent_dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod");
    let dead_socket = absent_dir.path().join("absent.sock");
    for value in ["0", "false", "False"] {
        let err = with_client_env(Some(value), None, Some(&dead_socket), || {
            expect_err(SyncDaemonClient::acquire())
        });
        let msg = err.to_string();
        assert!(
            msg.starts_with("Failed to connect to daemon at "),
            "OMG_DISABLE_DAEMON={value} leaked into gate: {msg}"
        );
        assert!(
            !msg.contains("disabled"),
            "benign value {value} wrongly disabled the client: {msg}"
        );
    }
    with_client_env(Some("false"), None, Some(&dead_socket), || {
        block(async {
            let err = expect_err(DaemonClient::connect().await);
            let msg = err.to_string();
            assert!(
                msg.starts_with("Failed to connect to daemon at "),
                "async connect bypassed gating fallthrough: {msg}"
            );
        });
    });
}

/// Contract: before ANY connection attempt, a socket whose parent directory is
/// group/world accessible (or symlinked) is rejected with
/// "Refusing insecure daemon socket directory for <path>" by every entry point.
#[test]
#[serial]
fn insecure_socket_parent_rejected_before_connecting() {
    let dir = TempDir::new().expect("tempdir");
    let permissive = dir.path().join("permissive");
    std::fs::create_dir(&permissive).expect("create subdir");
    // tempfile gives us 0700; open the subdir up to 0755 so validate_socket_parent
    // must reject it on the mode check.
    std::fs::set_permissions(&permissive, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let sock = permissive.join("omg.sock");

    let err = with_client_env(None, None, Some(&sock), || {
        expect_err(SyncDaemonClient::acquire_with_timeout(
            Duration::from_millis(25),
        ))
    });
    assert!(
        err.to_string()
            .starts_with("Refusing insecure daemon socket directory for "),
        "acquire_with_timeout connected through a 0755 socket dir: {err}"
    );

    let err = with_client_env(None, None, Some(&sock), || {
        expect_err(SyncDaemonClient::acquire())
    });
    assert!(
        err.to_string()
            .starts_with("Refusing insecure daemon socket directory for "),
        "acquire connected through a 0755 socket dir: {err}",
    );

    with_client_env(None, None, Some(&sock), || {
        block(async {
            let err = expect_err(DaemonClient::connect().await);
            assert!(
                err.to_string()
                    .starts_with("Refusing insecure daemon socket directory for "),
                "async connect ignored insecure socket dir: {err}"
            );
        });
    });

    // Symlinked parent is equally rejected.
    let real = dir.path().join("real");
    std::fs::create_dir(&real).expect("create real dir");
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let sock_through_link = link.join("omg.sock");
    let err = with_client_env(None, None, Some(&sock_through_link), || {
        expect_err(SyncDaemonClient::acquire())
    });
    assert!(
        err.to_string()
            .starts_with("Refusing insecure daemon socket directory for "),
        "client followed a symlinked socket parent: {err}",
    );
}

/// Contract: a successful async round-trip frames the request, decodes the
/// versioned response, echoes the request id, increments the client-side id
/// counter (1, 2), and delivers the exact payload bytes.
#[test]
#[serial]
fn async_ping_roundtrip_pins_framing_ids_and_payloads() {
    let mut daemon = MockDaemon::spawn(Box::new(|request| {
        Some(echo_frame(request, &ping_pong("pong")))
    }));
    let sock = daemon.socket_path.clone();
    with_client_env(None, None, Some(&sock), || {
        block(async {
            let mut client = DaemonClient::connect_to(sock.clone())
                .await
                .expect("connect_to mock daemon");
            assert_eq!(client.ping().await.expect("first ping"), "pong");
            assert_eq!(client.ping().await.expect("second ping"), "pong");
            drop(client);
        });
    });
    let requests = daemon.take_requests();
    assert_eq!(requests.len(), 2, "server must see exactly two requests");
    assert_eq!(requests[0].id(), 1, "first request id must be 1");
    assert_eq!(requests[1].id(), 2, "id counter must increment to 2");
    assert!(
        matches!(requests[0], Request::Ping { .. }),
        "framed request must decode as Ping, got {:?}",
        requests[0]
    );
}

#[test]
#[serial]
fn security_audit_rejects_false_clean_totals_without_losing_the_connection() {
    let mut daemon = MockDaemon::spawn(Box::new(|request| {
        assert!(matches!(request, Request::SecurityAudit { .. }));
        let count = u64::from(request.id() == 2);
        let audit = serde_json::from_value(serde_json::json!({
            "coverage": { "status": "reported", "assessed": [], "unassessed": [], "sources": [] },
            "total_vulnerabilities": count, "high_severity": count,
            "vulnerabilities": [["fixture", [{ "id": "CVE-2026-1234", "summary": "known issue", "score": "9.8" }]]]
        })).expect("valid audit wire shape");
        Some(echo_frame(request, &ResponseResult::SecurityAudit(audit)))
    }));
    let sock = daemon.socket_path.clone();
    with_client_env(None, None, Some(&sock), || {
        block(async {
            let mut client = DaemonClient::connect_to(sock.clone())
                .await
                .expect("connect to audit fixture");
            let error = client
                .security_audit()
                .await
                .expect_err("false clean totals");
            assert!(format!("{error:#}").contains("mismatch"), "{error:#}");
            let audit = client.security_audit().await.expect("next valid audit");
            assert_eq!(audit.total_vulnerabilities, 1);
            assert_eq!(audit.high_severity, 1);
            assert_eq!(audit.vulnerabilities[0].1[0].id, "CVE-2026-1234");
            drop(client);
        });
    });
    let requests = daemon.take_requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].id(), 1);
    assert_eq!(requests[1].id(), 2);
}

#[test]
#[serial]
fn audit_scan_cli_reports_findings_and_refuses_false_clean_daemon_results() {
    use omg_lib::core::security::scan::{
        AdvisorySeverity, FindingApplicability, SecurityAuditResult,
    };
    let _colors = pin_env(&[("NO_COLOR", None)]);
    let findings = serde_json::json!([["fixture\u{1b}]52;c;PKG\u{7}", [
        {"id":"CVE-2026-1234\u{1b}]52;c;ID\u{7}", "summary":"issue\u{1b}]52;c;SUMMARY\u{7}", "score":"9.8", "applicability":FindingApplicability::Applicable},
        {"id":"CVE-2026-1235", "summary":"published severity", "advisory_severity":AdvisorySeverity::Important},
        {"id":"CVE-2026-1236", "summary":"possible issue", "applicability":FindingApplicability::Possible}
    ]]]);
    for colors in ["never", "always"] {
        for case in [
            "findings",
            "fail-on-findings",
            "empty",
            "partial",
            "false-clean",
        ] {
            let partial = case == "partial";
            let has_findings = matches!(case, "findings" | "fail-on-findings" | "false-clean");
            let audit: SecurityAuditResult = serde_json::from_value(serde_json::json!({
                "coverage": { "status":"reported", "assessed":[], "sources":[],
                    "unassessed": if partial { serde_json::json!([{
                        "package":{"name":"custom","version":"1-1","architecture":null},
                        "reason":omg_lib::core::security::vulnerability::UnknownCoverage::OriginUnestablished
                    }]) } else { serde_json::json!([]) }
                },
                "total_vulnerabilities": if has_findings && case != "false-clean" {3} else {0},
                "high_severity": if has_findings && case != "false-clean" {2} else {0},
                "vulnerabilities": if has_findings {findings.clone()} else {serde_json::json!([])}
            })).expect("valid audit wire shape");
            let mut daemon = MockDaemon::spawn(Box::new(move |request| {
                assert!(matches!(request, Request::SecurityAudit { .. }));
                Some(echo_frame(
                    request,
                    &ResponseResult::SecurityAudit(audit.clone()),
                ))
            }));
            let project = TestProject::new();
            let mut args = vec!["audit", "scan"];
            if case == "fail-on-findings" {
                args.push("--fail-on-findings");
            }
            let result = project.run_with_env(
                &args,
                &[
                    ("OMG_TEST_MODE", "0"),
                    ("OMG_DISABLE_DAEMON", "0"),
                    (
                        "OMG_SOCKET_PATH",
                        daemon.socket_path.to_str().expect("UTF-8 fixture path"),
                    ),
                    ("OMG_COLORS", colors),
                ],
            );
            // Wake the private accept loop if the CLI failed before connecting.
            drop(std::os::unix::net::UnixStream::connect(&daemon.socket_path));
            let requests = daemon.take_requests();
            assert_eq!(requests.len(), 1, "case={case}: {result:?}");
            let text = console::strip_ansi_codes(&result.stdout);
            assert_eq!(
                result.success,
                !matches!(case, "fail-on-findings" | "false-clean"),
                "case={case}: {result:?}"
            );
            assert_eq!(
                text.contains("No vulnerabilities found in assessed packages."),
                case == "empty",
                "case={case}: {result:?}"
            );
            if case == "false-clean" {
                assert!(result.stderr.contains("mismatch"), "{result:?}");
            } else if has_findings {
                assert!(text.contains("Found 3 vulnerabilities (2 high severity)"));
                assert!(text.contains("[Score: 9.8]"));
                assert!(text.contains("[Advisory severity: Important]"));
                assert_eq!(
                    text.matches("[possible match; applicability unverified]")
                        .count(),
                    2
                );
                for marker in ["PKG", "ID", "SUMMARY"] {
                    assert!(text.contains(marker));
                }
                assert!(!result.stdout.contains("\u{1b}]"));
                assert!(!result.stdout.contains('\u{7}'));
                assert_eq!(result.stdout.contains('\u{1b}'), colors == "always");
            } else if partial {
                assert!(text.contains("1 package(s) with unknown coverage"));
                assert!(
                    text.contains("No findings were reported; advisory coverage is incomplete.")
                );
            }
            project.close_checked();
        }
    }
}

/// Contract: a Success response carrying a foreign id is rejected with the
/// exact message naming both ids.
#[test]
#[serial]
fn async_call_detects_response_id_mismatch_with_exact_message() {
    let mut daemon = MockDaemon::spawn(Box::new(|_request| {
        Some(fixed_response_frame(&Response::Success {
            id: 999,
            result: ResponseResult::Ping("stale".into()),
        }))
    }));
    let sock = daemon.socket_path.clone();
    with_client_env(None, None, Some(&sock), || {
        block(async {
            let mut client = DaemonClient::connect_to(sock.clone())
                .await
                .expect("connect");
            let err = expect_err(client.ping().await);
            assert_eq!(
                err.to_string(),
                "Request ID mismatch: sent 1, got 999",
                "mismatched response id must be reported verbatim"
            );
            drop(client);
        });
    });
    daemon.take_requests();
}

/// Contract: an Error response carrying a foreign id is rejected before its
/// payload is attributed to the current request.
#[test]
#[serial]
fn async_call_rejects_error_for_a_different_request() {
    let mut daemon = MockDaemon::spawn(Box::new(|_request| {
        Some(fixed_response_frame(&Response::Error {
            id: 999,
            code: -1002,
            message: "stale error".into(),
        }))
    }));
    let sock = daemon.socket_path.clone();
    with_client_env(None, None, Some(&sock), || {
        block(async {
            let mut client = DaemonClient::connect_to(sock.clone())
                .await
                .expect("connect");
            let err = expect_err(client.ping().await);
            assert_eq!(err.to_string(), "Request ID mismatch: sent 1, got 999");
            drop(client);
        });
    });
    daemon.take_requests();
}

/// Contract: a Response::Error surfaces as the exact string
/// "Daemon error (<code>): <message>".
#[test]
#[serial]
fn async_call_surfaces_daemon_error_code_and_message_verbatim() {
    let mut daemon = MockDaemon::spawn(Box::new(|_request| {
        Some(fixed_response_frame(&Response::Error {
            id: 1,
            code: -1002,
            message: "slow down".into(),
        }))
    }));
    let sock = daemon.socket_path.clone();
    with_client_env(None, None, Some(&sock), || {
        block(async {
            let mut client = DaemonClient::connect_to(sock.clone())
                .await
                .expect("connect");
            let err = expect_err(client.ping().await);
            assert_eq!(
                err.to_string(),
                "Daemon error (-1002): slow down",
                "daemon error code/message must survive the round-trip verbatim"
            );
            drop(client);
        });
    });
    daemon.take_requests();
}

/// Contract: a well-formed response of the WRONG variant is rejected by
/// extract_response with the exact message naming the request id.
#[test]
#[serial]
fn async_ping_rejects_wrong_response_variant_for_request_id_1() {
    let mut daemon = MockDaemon::spawn(Box::new(|request| {
        Some(echo_frame(
            request,
            &ResponseResult::Message("not a pong".into()),
        ))
    }));
    let sock = daemon.socket_path.clone();
    with_client_env(None, None, Some(&sock), || {
        block(async {
            let mut client = DaemonClient::connect_to(sock.clone())
                .await
                .expect("connect");
            let err = expect_err(client.ping().await);
            assert_eq!(
                err.to_string(),
                "Invalid response type for request 1",
                "variant mismatch must name the request id"
            );
            drop(client);
        });
    });
    daemon.take_requests();
}

/// Contract: a frame whose embedded version differs is rejected as
/// "Daemon protocol error: <FrameError display>" with the exact peer/ours
/// versions named.
#[test]
#[serial]
fn async_call_reports_protocol_version_mismatch_from_peer() {
    let mut daemon = MockDaemon::spawn(Box::new(|_request| {
        Some(bad_version_frame(
            999,
            &Response::Success {
                id: 1,
                result: ResponseResult::Ping("from the future".into()),
            },
        ))
    }));
    let sock = daemon.socket_path.clone();
    with_client_env(None, None, Some(&sock), || {
        block(async {
            let mut client = DaemonClient::connect_to(sock.clone())
                .await
                .expect("connect");
            let err = expect_err(client.ping().await);
            assert_eq!(
                err.to_string(),
                format!(
                    "Daemon protocol error: {}",
                    protocol::FrameError::VersionMismatch {
                        peer: 999,
                        ours: protocol::PROTOCOL_VERSION
                    }
                ),
                "version mismatch must surface the exact FrameError text"
            );
            drop(client);
        });
    });
    daemon.take_requests();
}

/// Contract: a daemon that accepts and closes without replying produces the
/// exact error "Daemon disconnected" (not an empty-stream unwrap panic).
#[test]
#[serial]
fn async_call_reports_disconnect_when_daemon_closes_without_reply() {
    let mut daemon = MockDaemon::spawn(Box::new(|_request| None));
    let sock = daemon.socket_path.clone();
    with_client_env(None, None, Some(&sock), || {
        block(async {
            let mut client = DaemonClient::connect_to(sock.clone())
                .await
                .expect("connect");
            let err = expect_err(client.call(Request::Ping { id: 1 }).await);
            assert_eq!(
                err.to_string(),
                "Daemon disconnected",
                "EOF from daemon must map to the disconnect error"
            );
            drop(client);
        });
    });
    daemon.take_requests();
}

/// Contract: ECONNREFUSED is retried (two real backoff sleeps totalling >= 70ms)
/// and the final error names the socket path plus "after retries"; a missing
/// socket (ENOENT) fails fast with NO retry suffix.
#[test]
#[serial]
fn connection_refused_is_retried_but_missing_socket_fails_fast() {
    // Dead listener: bind then drop; the stale socket file remains, so connects
    // hit ECONNREFUSED rather than ENOENT.
    let refused_dir = TempDir::new().expect("tempdir");
    #[cfg(unix)]
    std::fs::set_permissions(refused_dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod");
    let dead_socket = refused_dir.path().join("dead.sock");
    drop(UnixListener::bind(&dead_socket).expect("bind dead listener"));

    with_client_env(None, None, Some(&dead_socket), || {
        block(async {
            let started = Instant::now();
            let err = expect_err(DaemonClient::connect_to(dead_socket.clone()).await);
            let elapsed = started.elapsed();
            let msg = err.to_string();
            assert!(
                msg.ends_with("after retries"),
                "exhausted retries must say so: {msg}"
            );
            assert!(
                msg.contains(dead_socket.to_str().expect("utf8 path")),
                "error must name the socket path: {msg}"
            );
            assert!(
                elapsed >= Duration::from_millis(70),
                "retries must actually sleep (25+50ms); completed in {elapsed:?}"
            );
        });
    });

    // A path that was never bound produces ENOENT. Exercise the async retry
    // policy itself and require that this non-retryable error returns at once.
    let missing_socket = refused_dir.path().join("never-existed.sock");
    with_client_env(None, None, Some(&missing_socket), || {
        block(async {
            let fast_start = Instant::now();
            let err = expect_err(DaemonClient::connect_to(missing_socket.clone()).await);
            let fast_elapsed = fast_start.elapsed();
            let msg = err.to_string();
            assert!(
                msg.contains("Failed to connect to daemon at ") && !msg.contains("after retries"),
                "ENOENT must fail fast without the retry suffix: {msg}"
            );
            assert!(
                fast_elapsed < Duration::from_millis(70),
                "non-retryable error must not sleep; took {fast_elapsed:?}"
            );
        });
    });
}

/// Typed sync pings use the same framing and monotonic IDs as other accessors.
#[test]
#[serial]
fn sync_ping_roundtrip_preserves_request_ids_and_payloads() {
    let mut daemon = MockDaemon::spawn(Box::new(|request| {
        Some(echo_frame(request, &ping_pong("pong")))
    }));
    let sock = daemon.socket_path.clone();
    with_client_env(None, None, Some(&sock), || {
        let mut client = SyncDaemonClient::acquire().expect("acquire");
        assert_eq!(client.ping().expect("first ping"), "pong");
        assert_eq!(client.ping().expect("second ping"), "pong");
    });
    let requests = daemon.take_requests();
    assert!(matches!(
        requests.as_slice(),
        [Request::Ping { id: 1 }, Request::Ping { id: 2 }]
    ));
}

/// The info fast path must retain its caller-selected socket timeout.
#[test]
#[serial]
fn sync_client_honors_custom_read_timeout() {
    let (release, wait) = std::sync::mpsc::channel::<()>();
    let mut daemon = MockDaemon::spawn(Box::new(move |_request| {
        // Bound fixture cleanup even if the client-side assertion panics.
        let _ = wait.recv_timeout(Duration::from_secs(3));
        None
    }));
    let sock = daemon.socket_path.clone();
    with_client_env(None, None, Some(&sock), || {
        let mut client = SyncDaemonClient::acquire_with_timeout(Duration::from_millis(25))
            .expect("acquire with custom timeout");
        let error = client
            .info("fixture")
            .expect_err("unanswered info must time out");
        assert!(error.to_string().contains("Failed to read response"));
        let source = error
            .downcast_ref::<std::io::Error>()
            .expect("socket error cause");
        assert!(matches!(
            source.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
        release.send(()).expect("release fixture");
    });
    let requests = daemon.take_requests();
    assert!(
        matches!(requests.as_slice(), [Request::Info { id: 1, package }] if package == "fixture")
    );
}

/// Contract: SyncDaemonClient round-trips multiple generic calls over one
/// connection and preserves the exact response payloads and request IDs.
#[test]
#[serial]
fn sync_client_roundtrip_pins_response_payloads() {
    let mut daemon = MockDaemon::spawn(Box::new(|request| match request.id() {
        1 => Some(echo_frame(request, &ResponseResult::ExplicitCount(42))),
        _ => Some(echo_frame(request, &ping_pong("pong"))),
    }));
    let sock = daemon.socket_path.clone();
    with_client_env(None, None, Some(&sock), || {
        let mut client = SyncDaemonClient::acquire().expect("acquire");
        let explicit = client
            .call(&Request::ExplicitCount { id: 1 })
            .expect("explicit count round-trip");
        assert!(matches!(explicit, ResponseResult::ExplicitCount(42)));
        let response = client
            .call(&Request::Ping { id: 2 })
            .expect("sync ping round-trip");
        assert!(
            matches!(&response, ResponseResult::Ping(m) if m == "pong"),
            "expected Ping(\"pong\"), got {response:?}"
        );
        drop(client);
    });
    let requests = daemon.take_requests();
    assert_eq!(requests.len(), 2, "both sync calls share one connection");
    assert_eq!(requests[0].id(), 1);
    assert_eq!(requests[1].id(), 2);
    assert!(
        matches!(requests[0], Request::ExplicitCount { .. }),
        "first sync call must be ExplicitCount, got {:?}",
        requests[0]
    );
}

/// Contract: the sync path enforces the same id-validation and daemon-error
/// contracts with the same exact messages as the async path.
#[test]
#[serial]
fn sync_client_detects_id_mismatch_and_daemon_errors() {
    // Wrong-id success.
    let mut daemon = MockDaemon::spawn(Box::new(|_request| {
        Some(fixed_response_frame(&Response::Success {
            id: 7,
            result: ResponseResult::Ping("someone else's pong".into()),
        }))
    }));
    let sock = daemon.socket_path.clone();
    with_client_env(None, None, Some(&sock), || {
        let mut client = SyncDaemonClient::acquire().expect("acquire");
        let err = client.call(&Request::ExplicitCount { id: 1 }).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Request ID mismatch: sent 1, got 7",
            "sync path must report mismatched ids exactly like the async path"
        );
        drop(client);
    });
    daemon.take_requests();

    // Error envelope.
    let mut daemon = MockDaemon::spawn(Box::new(|_request| {
        Some(fixed_response_frame(&Response::Error {
            id: 1,
            code: -32603,
            message: "internal".into(),
        }))
    }));
    let sock = daemon.socket_path.clone();
    with_client_env(None, None, Some(&sock), || {
        let mut client = SyncDaemonClient::acquire().expect("acquire");
        let err = client.status().unwrap_err();
        assert_eq!(
            err.to_string(),
            "Daemon error (-32603): internal",
            "sync path must surface daemon errors verbatim"
        );
        drop(client);
    });
    daemon.take_requests();
}

/// Contract: a foreign version header on the sync path is rejected with the
/// same canonical "Daemon protocol error: ..." message as the async path.
#[test]
#[serial]
fn sync_client_rejects_wrong_protocol_version() {
    let mut daemon = MockDaemon::spawn(Box::new(|_request| {
        Some(bad_version_frame(
            0,
            &Response::Success {
                id: 1,
                result: ResponseResult::ExplicitCount(0),
            },
        ))
    }));
    let sock = daemon.socket_path.clone();
    with_client_env(None, None, Some(&sock), || {
        let mut client = SyncDaemonClient::acquire().expect("acquire");
        let err = client.call(&Request::ExplicitCount { id: 1 }).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "Daemon protocol error: {}",
                protocol::FrameError::VersionMismatch {
                    peer: 0,
                    ours: protocol::PROTOCOL_VERSION
                }
            ),
            "sync path must surface version mismatches identically"
        );
        drop(client);
    });
    daemon.take_requests();
}
