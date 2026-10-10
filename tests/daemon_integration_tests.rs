#![expect(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]

//! Comprehensive daemon integration tests
//! Tests IPC protocol, caching, concurrency, error handling

use omg_lib::daemon::handlers::{DaemonState, handle_request};
use omg_lib::daemon::index::PackageIndex;
use omg_lib::daemon::protocol::{Request, Response, ResponseResult, error_codes};
use omg_lib::package_managers::mock::MockPackageManager;
use serial_test::serial;
use std::sync::Arc;
use tempfile::TempDir;

fn setup_test_env() -> (TempDir, Arc<DaemonState>) {
    let temp_dir = TempDir::new().unwrap();

    temp_env::with_var("OMG_DATA_DIR", Some(temp_dir.path()), || {
        omg_lib::core::security::init_audit_logger()
    })
    .expect("Failed to init audit logger");

    let package_manager = Arc::new(MockPackageManager::new_in("arch", temp_dir.path()));
    let state = Arc::new(
        DaemonState::new_isolated(temp_dir.path(), PackageIndex::empty(), package_manager)
            .expect("Failed to create hermetic DaemonState"),
    );

    (temp_dir, state)
}

// ============================================================================
// IPC Protocol Tests - Test all request/response variants
// ============================================================================

#[tokio::test]
#[serial]
async fn test_metrics_endpoint_returns_valid_data() {
    let (_temp, state) = setup_test_env();

    let req = Request::Metrics { id: 100 };
    let response = handle_request(Arc::clone(&state), req).await;

    let Response::Success {
        id: 100,
        result: ResponseResult::Metrics(metrics),
    } = response
    else {
        panic!("expected metrics response, got {response:?}");
    };
    assert!(
        metrics.requests_total >= 1,
        "the metrics request itself must be counted"
    );
}

#[tokio::test]
#[serial]
async fn test_suggest_endpoint_handles_empty_query() {
    let (_temp, state) = setup_test_env();

    let req = Request::Suggest {
        id: 200,
        query: "".to_string(),
        limit: Some(10),
    };
    let response = handle_request(Arc::clone(&state), req).await;

    assert!(matches!(
        response,
        Response::Success {
            id: 200,
            result: ResponseResult::Suggest(ref suggestions),
        } if suggestions.is_empty()
    ));
}

#[tokio::test]
#[serial]
async fn test_cache_clear_invalidates_cache() {
    let (_temp, state) = setup_test_env();

    // Populate the search cache through the public IPC seam: `DaemonState`
    // no longer exposes its cache field outside the daemon subtree.
    async fn cache_misses(state: &Arc<DaemonState>, id: u64) -> u64 {
        match handle_request(Arc::clone(state), Request::Metrics { id }).await {
            Response::Success {
                result: ResponseResult::Metrics(m),
                ..
            } => m.cache_misses,
            response => panic!("Metrics request failed: {response:?}"),
        }
    }

    async fn search_git(state: &Arc<DaemonState>, id: u64) {
        let response = handle_request(
            Arc::clone(state),
            Request::Search {
                id,
                query: "git".to_string(),
                limit: Some(10),
            },
        )
        .await;
        assert!(
            matches!(response, Response::Success { .. }),
            "search must succeed, got {response:?}"
        );
    }

    // Populate the search cache through the public IPC seam: `DaemonState`
    // no longer exposes its cache field outside the daemon subtree, and moka
    // stats are eventually consistent — so invalidation is pinned through
    // observable request semantics instead of internal counters.
    let misses_before = cache_misses(&state, 500).await;
    search_git(&state, 498).await;
    let misses_after_first = cache_misses(&state, 499).await;
    assert!(
        misses_after_first > misses_before,
        "first search must be a cache miss"
    );
    search_git(&state, 502).await;
    let misses_after_repeat = cache_misses(&state, 503).await;
    assert_eq!(
        misses_after_repeat, misses_after_first,
        "repeat search must be served from cache"
    );

    let clear_response = handle_request(Arc::clone(&state), Request::CacheClear { id: 501 }).await;
    assert!(matches!(
        clear_response,
        Response::Success {
            id: 501,
            result: ResponseResult::Message(ref message),
        } if message == "cleared"
    ));

    // The same query must be a cache miss again after the clear.
    search_git(&state, 504).await;
    let misses_after_clear = cache_misses(&state, 505).await;
    assert!(
        misses_after_clear > misses_after_repeat,
        "search after CacheClear must be a cache miss again"
    );
}

// ============================================================================
// Error Recovery Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_invalid_package_name_returns_helpful_error() {
    let (_temp, state) = setup_test_env();

    let invalid_names = vec![
        "invalid; rm -rf /",
        "../../../etc/passwd",
        "package\nwith\nnewlines",
        "package\x00with\x00nulls",
    ];

    for invalid in invalid_names {
        let req = Request::Info {
            id: 700,
            package: invalid.to_string(),
        };
        let response = handle_request(Arc::clone(&state), req).await;

        match response {
            Response::Error { id, code, message } => {
                assert_eq!(id, 700);
                assert_eq!(code, error_codes::INVALID_PARAMS);
                assert!(
                    message.contains("Invalid package name"),
                    "Error should mention invalid name"
                );
            }
            Response::Success { .. } => {
                unreachable!("Should reject invalid package name: {}", invalid)
            }
        }
    }
}

#[tokio::test]
#[serial]
async fn test_oversized_query_is_rejected() {
    let (_temp, state) = setup_test_env();

    // Create query > 500 characters (MAX_QUERY_LENGTH)
    let huge_query = "a".repeat(1000);
    let req = Request::Search {
        id: 800,
        query: huge_query,
        limit: Some(10),
    };
    let response = handle_request(Arc::clone(&state), req).await;

    match response {
        Response::Error { id, code, message } => {
            assert_eq!(id, 800);
            assert_eq!(code, error_codes::INVALID_PARAMS);
            // Search rejects oversized queries before backend dispatch.
            assert!(
                message.to_ascii_lowercase().contains("query too long"),
                "error should name the oversized query, got: {message}"
            );
        }
        Response::Success { .. } => unreachable!("Should reject oversized query"),
    }
}

#[tokio::test]
#[serial]
async fn test_state_recovery_after_error() {
    let (_temp, state) = setup_test_env();

    // Trigger an error
    let bad_req = Request::Info {
        id: 900,
        package: "invalid; rm -rf /".to_string(),
    };
    let error_response = handle_request(Arc::clone(&state), bad_req).await;
    assert!(matches!(
        error_response,
        Response::Error {
            id: 900,
            code: error_codes::INVALID_PARAMS,
            ..
        }
    ));

    let response = handle_request(state, Request::Ping { id: 901 }).await;
    assert!(matches!(
        response,
        Response::Success {
            id: 901,
            result: ResponseResult::Ping(ref message),
        } if message == "pong"
    ));
}

// ============================================================================
// State Management Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_health_status_reflects_cache_size() {
    let (_temp, state) = setup_test_env();

    let req = Request::Health { id: 1000 };
    let response = handle_request(Arc::clone(&state), req).await;

    let Response::Success {
        id: 1000,
        result: ResponseResult::Health(health),
    } = response
    else {
        panic!("expected health response, got {response:?}");
    };
    assert_eq!(health.cache_size, 0);
    assert_eq!(health.status, "healthy");
}

#[tokio::test]
#[serial]
async fn test_metrics_increment_on_requests() {
    let (_temp, state) = setup_test_env();

    // Get initial metrics
    let metrics_req = Request::Metrics { id: 1100 };
    let initial = handle_request(Arc::clone(&state), metrics_req.clone()).await;

    let Response::Success {
        id: 1100,
        result: ResponseResult::Metrics(initial_metrics),
    } = initial
    else {
        panic!("expected initial metrics response, got {initial:?}");
    };

    for id in 0..5 {
        let response = handle_request(Arc::clone(&state), Request::Ping { id }).await;
        assert!(matches!(
            response,
            Response::Success {
                id: response_id,
                result: ResponseResult::Ping(ref message),
            } if response_id == id && message == "pong"
        ));
    }

    let updated = handle_request(Arc::clone(&state), metrics_req).await;
    let Response::Success {
        id: 1100,
        result: ResponseResult::Metrics(updated_metrics),
    } = updated
    else {
        panic!("expected updated metrics response, got {updated:?}");
    };
    assert_eq!(
        updated_metrics.requests_total,
        initial_metrics.requests_total + 6,
        "five pings and the final metrics request must be counted"
    );
}
