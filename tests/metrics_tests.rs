#![expect(clippy::unwrap_used)]
use omg_lib::core::metrics::GLOBAL_METRICS;
use omg_lib::daemon::handlers::{DaemonState, handle_request};
use omg_lib::daemon::index::PackageIndex;
use omg_lib::daemon::protocol::{Request, Response, ResponseResult};
use omg_lib::package_managers::mock::MockPackageManager;
use serial_test::serial;
use std::sync::Arc;
use tempfile::TempDir;

// Metrics dispatch has no dependency on the host package database. Explicit
// dependencies exercise the real handlers and cache under every feature set.
fn isolated_state(temp_dir: &TempDir) -> Arc<DaemonState> {
    let manager = Arc::new(MockPackageManager::new_in("arch", temp_dir.path()));
    Arc::new(
        DaemonState::new_isolated(temp_dir.path(), PackageIndex::empty(), manager)
            .expect("isolated daemon state must initialize"),
    )
}

#[tokio::test]
#[serial]
async fn test_metrics_collection() {
    // Setup
    let temp_dir = TempDir::new().unwrap();

    temp_env::with_var("OMG_DATA_DIR", Some(temp_dir.path()), || {
        omg_lib::core::security::init_audit_logger()
    })
    .expect("audit logger must initialize");
    let state = isolated_state(&temp_dir);

    // Get initial metrics
    let initial = GLOBAL_METRICS.snapshot();

    // 1. Send a successful request
    let req_ping = Request::Ping { id: 1 };
    handle_request(Arc::clone(&state), req_ping).await;

    // Check increment
    let after_ping = GLOBAL_METRICS.snapshot();
    assert_eq!(
        after_ping.requests_total,
        initial.requests_total + 1,
        "Total requests should inc by 1"
    );
    assert_eq!(
        after_ping.requests_failed, initial.requests_failed,
        "Failed requests should stay same"
    );

    // 2. Send an invalid request (validation failure)
    let req_invalid = Request::Info {
        id: 2,
        package: "invalid; bad".to_string(),
    };
    handle_request(Arc::clone(&state), req_invalid).await;

    let after_invalid = GLOBAL_METRICS.snapshot();
    assert_eq!(
        after_invalid.requests_total,
        initial.requests_total + 2,
        "Total requests should inc by 2"
    );
    assert_eq!(
        after_invalid.requests_failed,
        initial.requests_failed + 1,
        "Failed requests should inc by 1"
    );
    assert_eq!(
        after_invalid.validation_failures,
        initial.validation_failures + 1,
        "Validation failures should inc by 1"
    );

    // 3. Request metrics via IPC
    let req_metrics = Request::Metrics { id: 3 };
    let response = handle_request(Arc::clone(&state), req_metrics).await;

    let Response::Success {
        result: ResponseResult::Metrics(snapshot),
        ..
    } = response
    else {
        panic!("Expected Metrics response, got: {response:?}");
    };

    // handle_request increments requests_total before dispatching
    // (src/daemon/handlers.rs:259), so the snapshot inside the response MUST
    // already include the Metrics request itself — exactly one more than the
    // post-invalid-requests baseline.
    assert_eq!(
        snapshot.requests_total,
        after_invalid.requests_total + 1,
        "Metrics snapshot must include its own request (inc happens at dispatch entry)"
    );
}

#[tokio::test]
#[serial]
async fn test_security_audit_metrics() {
    let temp_dir = TempDir::new().unwrap();
    let state = isolated_state(&temp_dir);

    let initial = GLOBAL_METRICS.snapshot();

    // Send security audit request
    let req = Request::SecurityAudit { id: 1 };
    handle_request(Arc::clone(&state), req).await;

    let after = GLOBAL_METRICS.snapshot();
    assert_eq!(
        after.security_audit_requests,
        initial.security_audit_requests + 1
    );
}
