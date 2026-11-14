#![expect(clippy::unwrap_used, clippy::expect_used)]
use common::mocks::{MockPackageDb, MockPackageManager};
use omg_lib::daemon::handlers::{DaemonState, GLOBAL_RATE_LIMIT_BURST, handle_request};
use omg_lib::daemon::index::PackageIndex;
use omg_lib::daemon::protocol::{Request, Response, error_codes};
pub mod common;

use serial_test::serial;
use std::sync::Arc;
use tempfile::TempDir;

/// Initialize daemon handler tests without accessing a system package database.
fn init_state() -> (TempDir, Arc<DaemonState>) {
    let temp_dir = TempDir::new().expect("Failed to create daemon security test directory");
    temp_env::with_vars(
        [
            ("OMG_DAEMON_DATA_DIR", Some(temp_dir.path().as_os_str())),
            ("OMG_DATA_DIR", Some(temp_dir.path().as_os_str())),
        ],
        omg_lib::core::security::init_audit_logger,
    )
    .expect("Failed to initialize audit logger");

    let package_manager = Arc::new(MockPackageManager::new(MockPackageDb::default()));
    let state = Arc::new(
        DaemonState::new_isolated(temp_dir.path(), PackageIndex::empty(), package_manager)
            .expect("Failed to create isolated daemon state"),
    );

    (temp_dir, state)
}

#[tokio::test]
async fn audit_append_failure_marks_the_explicit_daemon_collection_incomplete() -> anyhow::Result<()>
{
    const NAME: &str = "audit_append_failure_marks_the_explicit_daemon_collection_incomplete";
    if common::isolated_fixture::run_isolated_test(NAME) {
        return Ok(());
    }
    use omg_lib::core::security::audit::{
        AuditEventType, AuditLogger, AuditSeverity, audit_log_nonblocking,
        ensure_complete_collection, flush_pending_audit_events,
    };

    let directory = TempDir::new()?;
    let socket = directory.path().join("omg.sock");
    let status = directory.path().join("omg.status");
    let backend = Arc::new(MockPackageManager::new(MockPackageDb::default()));
    let state = Arc::new(DaemonState::new_isolated(
        directory.path(),
        PackageIndex::empty(),
        backend,
    )?);
    let listener = tokio::net::UnixListener::bind(&socket)?;
    let server = tokio::spawn(omg_lib::daemon::server::run(listener, state, socket));
    let startup = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !status.try_exists()? {
            anyhow::ensure!(
                !server.is_finished(),
                "isolated daemon exited before publishing status"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        anyhow::Ok(())
    })
    .await;
    server.abort();
    let stopped = server.await;
    anyhow::ensure!(
        matches!(&stopped, Err(error) if error.is_cancelled()),
        "isolated daemon did not cancel cleanly: {stopped:?}"
    );
    startup??;

    let log = directory.path().join("audit/audit.jsonl");
    let history = directory.path().join("audit/retained.jsonl");
    let marker = directory.path().join("audit/incomplete");
    audit_log_nonblocking(
        AuditEventType::SecurityAudit,
        AuditSeverity::Info,
        "fixture",
        "first retained event",
    );
    flush_pending_audit_events()?;
    let original = std::fs::read(&log)?;
    ensure_complete_collection(&marker)?;
    std::fs::rename(&log, &history)?;
    std::fs::create_dir(&log)?;

    audit_log_nonblocking(
        AuditEventType::SecurityAudit,
        AuditSeverity::Error,
        "fixture",
        "append must fail into an owned directory",
    );
    flush_pending_audit_events()?;
    let error = ensure_complete_collection(&marker)
        .expect_err("failed append must mark this collection incomplete");
    assert!(
        error.to_string().contains("Audit collection is incomplete"),
        "{error:#}"
    );
    assert!(marker.is_file());
    assert_eq!(
        std::fs::read(&history)?,
        original,
        "existing audit history must survive the append failure"
    );
    let report = AuditLogger::new_in(&history)?.verify_integrity()?;
    assert!(report.is_valid());
    assert_eq!(report.total_entries, 1);
    assert!(
        log.is_dir(),
        "refusing the append must preserve the conflicting fixture inode"
    );
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_global_rate_limiting() {
    let (_temp_dir, state) = init_state();

    let req = Request::Ping { id: 1 };

    // The margin covers a small amount of token refill while requests run.
    let request_budget = GLOBAL_RATE_LIMIT_BURST.saturating_add(50);
    let mut limit_hit = false;
    for _ in 0..request_budget {
        let response = handle_request(Arc::clone(&state), req.clone()).await;
        if let Response::Error { code, .. } = response
            && code == error_codes::RATE_LIMITED
        {
            limit_hit = true;
            break;
        }
    }

    assert!(limit_hit, "Should have hit global rate limit");
    omg_lib::core::security::audit::flush_pending_audit_events().unwrap();
}

#[tokio::test]
#[serial]
async fn test_input_validation_audit() {
    let (temp_dir, state) = init_state();

    // Send request with invalid package name to trigger audit log
    let invalid_pkg = "invalid; rm -rf /";
    let req = Request::Info {
        id: 1,
        package: invalid_pkg.to_string(),
    };

    let response = handle_request(Arc::clone(&state), req).await;

    // Verify rejection
    if let Response::Error { message, .. } = response {
        assert!(
            message.contains("Invalid package name"),
            "Should reject invalid package name"
        );
    } else {
        unreachable!("Should have returned error response");
    }

    // Verify audit log entry
    // The audit log is written to OMG_DATA_DIR/audit/audit.jsonl
    let audit_dir = temp_dir.path().join("audit");
    let audit_file = audit_dir.join("audit.jsonl");

    omg_lib::core::security::audit::flush_pending_audit_events().unwrap();
    let content = std::fs::read_to_string(&audit_file)
        .unwrap_or_else(|error| panic!("Audit event was not written to {audit_file:?}: {error}"));

    assert!(content.contains("policy_violation"));
    assert!(content.contains("Invalid package name"));
}

#[tokio::test]
#[serial]
async fn test_health_endpoint_returns_status() {
    let (_temp_dir, state) = init_state();

    let req = Request::Health { id: 42 };
    let response = handle_request(Arc::clone(&state), req).await;

    match response {
        Response::Success { id, result } => {
            assert_eq!(id, 42, "Response ID should match request");
            if let omg_lib::daemon::protocol::ResponseResult::Health(health) = result {
                assert!(
                    health.status == "healthy"
                        || health.status == "degraded"
                        || health.status == "unhealthy",
                    "Status should be one of the valid states, got: {}",
                    health.status
                );
                assert!(
                    health.uptime_seconds < 60,
                    "Uptime should be reasonable for test"
                );
                assert!(
                    health.cache_size < 1_000_000,
                    "Cache size should be reasonable"
                );
            } else {
                unreachable!("Expected Health response result");
            }
        }
        Response::Error { message, .. } => unreachable!("Health endpoint failed: {}", message),
    }
    omg_lib::core::security::audit::flush_pending_audit_events().unwrap();
}

#[tokio::test]
#[serial]
async fn test_ping_returns_pong() {
    let (_temp_dir, state) = init_state();

    let req = Request::Ping { id: 123 };
    let response = handle_request(Arc::clone(&state), req).await;

    match response {
        Response::Success { id, result } => {
            assert_eq!(id, 123);
            if let omg_lib::daemon::protocol::ResponseResult::Ping(msg) = result {
                assert_eq!(msg, "pong");
            } else {
                unreachable!("Expected Ping response");
            }
        }
        Response::Error { message, .. } => unreachable!("Ping failed: {}", message),
    }
    omg_lib::core::security::audit::flush_pending_audit_events().unwrap();
}

#[tokio::test]
#[serial]
async fn test_cache_stats_handler() {
    let (_temp_dir, state) = init_state();

    let req = Request::CacheStats { id: 999 };
    let response = handle_request(Arc::clone(&state), req).await;

    match response {
        Response::Success { id, result } => {
            assert_eq!(id, 999);
            if let omg_lib::daemon::protocol::ResponseResult::CacheStats { size, max_size } = result
            {
                assert!(size <= max_size, "Cache size should not exceed max");
                assert!(max_size > 0, "Max cache size should be positive");
            } else {
                unreachable!("Expected CacheStats response");
            }
        }
        Response::Error { message, .. } => unreachable!("CacheStats failed: {}", message),
    }
    omg_lib::core::security::audit::flush_pending_audit_events().unwrap();
}

#[tokio::test]
#[serial]
async fn test_cache_clear_handler() {
    let (_temp_dir, state) = init_state();

    // Even a search with no matches caches a query result. Repeated reads
    // let Moka run maintenance so its eventually consistent entry count
    // becomes visible through CacheStats before testing invalidation.
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let search = handle_request(
                Arc::clone(&state),
                Request::Search {
                    id: 553,
                    query: "cache-clear-fixture".to_string(),
                    limit: None,
                },
            )
            .await;
            match search {
                Response::Success {
                    id: 553,
                    result: omg_lib::daemon::protocol::ResponseResult::Search(result),
                } => {
                    assert!(result.packages.is_empty());
                    assert_eq!(result.total, 0);
                }
                other => panic!("Expected successful fixture search, got: {other:?}"),
            }
            match handle_request(Arc::clone(&state), Request::CacheStats { id: 554 }).await {
                Response::Success {
                    id: 554,
                    result: omg_lib::daemon::protocol::ResponseResult::CacheStats { size, .. },
                } => {
                    if size > 0 {
                        assert_eq!(size, 1, "Only the fixture query should be cached");
                        break;
                    }
                }
                other => panic!("Expected cache statistics before clear, got: {other:?}"),
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Fixture search must populate the cache before clear");

    let req = Request::CacheClear { id: 555 };
    let response = handle_request(Arc::clone(&state), req).await;

    match response {
        Response::Success { id, result } => {
            assert_eq!(id, 555);
            if let omg_lib::daemon::protocol::ResponseResult::Message(msg) = result {
                assert_eq!(msg, "cleared");
            } else {
                unreachable!("Expected Message response");
            }
        }
        Response::Error { message, .. } => unreachable!("CacheClear failed: {}", message),
    }

    match handle_request(state, Request::CacheStats { id: 556 }).await {
        Response::Success {
            id: 556,
            result: omg_lib::daemon::protocol::ResponseResult::CacheStats { size, .. },
        } => assert_eq!(size, 0, "CacheClear must remove the populated query"),
        other => panic!("Expected cache statistics after clear, got: {other:?}"),
    }
    omg_lib::core::security::audit::flush_pending_audit_events().unwrap();
}

#[tokio::test]
#[serial]
async fn test_explicit_count_handler() {
    let (_temp_dir, state) = init_state();

    let req = Request::ExplicitCount { id: 777 };
    let response = handle_request(Arc::clone(&state), req).await;

    match response {
        Response::Success { id, result } => {
            assert_eq!(id, 777);
            if let omg_lib::daemon::protocol::ResponseResult::ExplicitCount(count) = result {
                assert!(count < 100_000, "Explicit count should be reasonable");
            } else {
                unreachable!("Expected ExplicitCount response");
            }
        }
        Response::Error { message, .. } => unreachable!("ExplicitCount failed: {}", message),
    }
    omg_lib::core::security::audit::flush_pending_audit_events().unwrap();
}
