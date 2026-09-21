#![cfg(unix)]

//! Daemon concurrent clients, request queuing, races, and thread safety.

use anyhow::Result;
use omg_lib::daemon::handlers::handle_request;
use omg_lib::daemon::protocol::{Request, Response, ResponseResult};
use serial_test::serial;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

pub mod common;

use common::DaemonTestFixture as ConcurrencyTestFixture;

// ============================================================================
// Concurrent Read Operations
// ============================================================================

#[tokio::test]
#[serial]
async fn test_concurrent_search_requests() -> Result<()> {
    let fixture = ConcurrencyTestFixture::new()?;

    // Spawn 50 concurrent search requests
    let mut handles = vec![];
    for i in 0..50 {
        let state = Arc::clone(&fixture.state);
        let handle = tokio::spawn(async move {
            let request = Request::Search {
                id: i,
                query: "test".to_string(),
                limit: Some(10),
            };
            let response = handle_request(state, request).await;
            (i, response)
        });
        handles.push(handle);
    }

    // Wait for all requests to complete. Valid short queries are always
    // answerable (handle_search returns Success for them, and the per-state
    // quota is 100/s with burst 200, so every
    // one of the 50 requests must succeed.
    let mut success_count = 0;
    for handle in handles {
        let (id, response) = handle.await?;
        match response {
            Response::Success {
                id: actual_id,
                result: ResponseResult::Search(result),
            } => {
                assert_eq!(actual_id, id);
                assert!(result.packages.is_empty());
                assert_eq!(result.total, 0);
                success_count += 1;
            }
            other => panic!("concurrent search {id} returned {other:?}"),
        }
    }

    assert_eq!(success_count, 50, "every concurrent search should succeed");

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_concurrent_status_requests() -> Result<()> {
    let fixture = ConcurrencyTestFixture::new()?;

    // 20 concurrent status requests
    let mut handles = vec![];
    for i in 0..20 {
        let state = Arc::clone(&fixture.state);
        let handle = tokio::spawn(async move {
            let request = Request::Status { id: i };
            handle_request(state, request).await
        });
        handles.push(handle);
    }

    // The fixture has no installed packages and has never scanned advisories.
    // Matching but incorrect status values must not satisfy this contract.
    for (id, handle) in handles.into_iter().enumerate() {
        common::assert_empty_daemon_status(handle.await?, id as u64);
    }

    Ok(())
}

// ============================================================================
// Concurrent Read + Write Operations
// ============================================================================

#[tokio::test]
#[serial]
async fn test_concurrent_read_and_cache_clear() -> Result<()> {
    let fixture = ConcurrencyTestFixture::new()?;

    // Start continuous read requests
    let mut read_handles = vec![];
    for i in 0..20 {
        let state = Arc::clone(&fixture.state);
        let handle = tokio::spawn(async move {
            let mut completed = 0;
            for j in 0..5 {
                let request = Request::Search {
                    id: (i * 5 + j) as u64,
                    query: "test".to_string(),
                    limit: Some(10),
                };
                match handle_request(Arc::clone(&state), request).await {
                    Response::Success {
                        id,
                        result: ResponseResult::Search(result),
                    } => {
                        assert_eq!(id, (i * 5 + j) as u64);
                        assert!(result.packages.is_empty());
                        assert_eq!(result.total, 0);
                    }
                    other => panic!("concurrent search returned {other:?}"),
                }
                completed += 1;
            }
            completed
        });
        read_handles.push(handle);
    }

    // Interleave cache clear operations
    let mut clear_handles = vec![];
    for i in 0..3 {
        let state = Arc::clone(&fixture.state);
        let handle = tokio::spawn(async move {
            sleep(Duration::from_millis(i * 10)).await;
            let request = Request::CacheClear { id: 1000 + i };
            handle_request(state, request).await
        });
        clear_handles.push(handle);
    }

    // All operations should complete without deadlock.
    let mut completed_reads = 0;
    for handle in read_handles {
        completed_reads += handle.await?;
    }
    assert_eq!(
        completed_reads, 100,
        "Every concurrent read should complete"
    );

    for (index, handle) in clear_handles.into_iter().enumerate() {
        let response = handle.await?;
        match response {
            Response::Success {
                id,
                result: ResponseResult::Message(message),
            } => {
                assert_eq!(id, 1000 + index as u64);
                assert_eq!(message, "cleared");
            }
            other => panic!("concurrent cache clear returned {other:?}"),
        }
    }

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_concurrent_cache_updates() -> Result<()> {
    let fixture = ConcurrencyTestFixture::new()?;

    // Multiple threads updating cache with different queries
    let queries = ["query1", "query2", "query3", "query4", "query5"];

    let mut handles = vec![];
    for (i, query) in queries.iter().enumerate() {
        let state = Arc::clone(&fixture.state);
        let query = query.to_string();
        let handle = tokio::spawn(async move {
            let mut completed = 0;
            for _ in 0..10 {
                let request = Request::Search {
                    id: i as u64,
                    query: query.clone(),
                    limit: Some(10),
                };
                match handle_request(Arc::clone(&state), request).await {
                    Response::Success {
                        id,
                        result: ResponseResult::Search(result),
                    } => {
                        assert_eq!(id, i as u64);
                        assert!(result.packages.is_empty());
                        assert_eq!(result.total, 0);
                    }
                    other => panic!("concurrent cache update returned {other:?}"),
                }
                completed += 1;
            }
            completed
        });
        handles.push(handle);
    }

    // All should complete without race conditions.
    let mut completed = 0;
    for handle in handles {
        completed += handle.await?;
    }
    assert_eq!(
        completed, 50,
        "Every concurrent cache update should complete"
    );

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_no_deadlock_with_recursive_locks() -> Result<()> {
    let fixture = ConcurrencyTestFixture::new()?;

    // Scenario: Status request might internally lock cache, then query system
    // Multiple concurrent status requests should not deadlock

    let mut handles = vec![];
    for i in 0..30 {
        let state = Arc::clone(&fixture.state);
        let handle = tokio::spawn(async move {
            let request = Request::Status { id: i };
            handle_request(state, request).await
        });
        handles.push(handle);
    }

    // Use timeout to detect deadlock
    let timeout_duration = Duration::from_secs(10);
    let result = tokio::time::timeout(timeout_duration, async {
        for (id, handle) in handles.into_iter().enumerate() {
            common::assert_empty_daemon_status(handle.await.unwrap(), id as u64);
        }
    })
    .await;

    assert!(result.is_ok(), "Requests should complete without deadlock");

    Ok(())
}

// ============================================================================
// Race Condition Testing
// ============================================================================

#[tokio::test]
#[serial]
async fn test_no_race_in_cache_updates() -> Result<()> {
    let fixture = ConcurrencyTestFixture::new()?;

    // Multiple threads updating same cache key
    let mut handles = vec![];
    for i in 0..50 {
        let state = Arc::clone(&fixture.state);
        let handle = tokio::spawn(async move {
            let request = Request::Search {
                id: i,
                query: "same-query".to_string(),
                limit: Some(10),
            };
            handle_request(state, request).await
        });
        handles.push(handle);
    }

    // All 50 hits on the same key must succeed AND agree: the cached result
    // set for a given query is immutable once inserted.
    for (expected_id, handle) in handles.into_iter().enumerate() {
        match handle.await? {
            Response::Success {
                id,
                result: ResponseResult::Search(result),
            } => {
                assert_eq!(id, expected_id as u64);
                assert!(result.packages.is_empty());
                assert_eq!(result.total, 0);
            }
            other => panic!("concurrent same-key search returned {other:?}"),
        }
    }

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_no_race_in_metrics_updates() -> Result<()> {
    let fixture = ConcurrencyTestFixture::new()?;
    let baseline = match fixture.send_request(Request::Metrics { id: 1001 }).await {
        Response::Success {
            id: 1001,
            result: ResponseResult::Metrics(metrics),
        } => metrics,
        other => panic!("baseline metrics returned {other:?}"),
    };

    // Submit many requests to increment metrics
    let mut handles = vec![];
    for i in 0..100 {
        let state = Arc::clone(&fixture.state);
        let handle = tokio::spawn(async move {
            let request = Request::Ping { id: i };
            handle_request(state, request).await
        });
        handles.push(handle);
    }

    // Wait for all to complete
    for (index, handle) in handles.into_iter().enumerate() {
        match handle.await? {
            Response::Success {
                id,
                result: ResponseResult::Ping(message),
            } => {
                assert_eq!(id, index as u64);
                assert_eq!(message, "pong");
            }
            other => panic!("concurrent ping returned {other:?}"),
        }
    }

    // Check final metrics
    let metrics_response =
        handle_request(Arc::clone(&fixture.state), Request::Metrics { id: 1000 }).await;

    let metrics = match metrics_response {
        Response::Success {
            id: 1000,
            result: ResponseResult::Metrics(metrics),
        } => metrics,
        response => panic!("Metrics request failed: {response:?}"),
    };
    // Should have processed all 101 requests (100 pings + 1 metrics)
    assert_eq!(metrics.requests_total - baseline.requests_total, 101);
    assert_eq!(metrics.requests_failed, baseline.requests_failed);

    Ok(())
}

// ============================================================================
// Thread Safety Verification
// ============================================================================

#[tokio::test]
#[serial]
async fn test_shared_state_thread_safety() -> Result<()> {
    let fixture = ConcurrencyTestFixture::new()?;
    let baseline = match fixture.send_request(Request::Metrics { id: 1000 }).await {
        Response::Success {
            id: 1000,
            result: ResponseResult::Metrics(metrics),
        } => metrics,
        other => panic!("baseline metrics returned {other:?}"),
    };

    // Mix of different request types accessing shared state
    let mut handles = vec![];

    // Searches (read cache)
    for i in 0..20 {
        let state = Arc::clone(&fixture.state);
        let handle = tokio::spawn(async move {
            let request = Request::Search {
                id: i,
                query: format!("query-{}", i % 5),
                limit: Some(10),
            };
            handle_request(state, request).await
        });
        handles.push(handle);
    }

    // Status requests (read system state)
    for i in 20..40 {
        let state = Arc::clone(&fixture.state);
        let handle = tokio::spawn(async move {
            let request = Request::Status { id: i };
            handle_request(state, request).await
        });
        handles.push(handle);
    }

    // Cache clears (write cache)
    for i in 40..45 {
        let state = Arc::clone(&fixture.state);
        let handle = tokio::spawn(async move {
            let request = Request::CacheClear { id: i };
            handle_request(state, request).await
        });
        handles.push(handle);
    }

    // Metrics (read global state)
    for i in 45..50 {
        let state = Arc::clone(&fixture.state);
        let handle = tokio::spawn(async move {
            let request = Request::Metrics { id: i };
            handle_request(state, request).await
        });
        handles.push(handle);
    }

    // Handles retain request order even when tasks finish out of order.
    // Verify each of the four operation types, not just a success envelope.
    assert_eq!(handles.len(), 50);
    for (expected_id, handle) in handles.into_iter().enumerate() {
        let response = handle.await?;
        let expected_id = expected_id as u64;
        if (20..40).contains(&expected_id) {
            common::assert_empty_daemon_status(response, expected_id);
            continue;
        }
        match response {
            Response::Success { id, result } => {
                assert_eq!(id, expected_id);
                match (expected_id, result) {
                    (0..=19, ResponseResult::Search(result)) => {
                        assert!(result.packages.is_empty());
                        assert_eq!(result.total, 0);
                    }
                    (40..=44, ResponseResult::Message(message)) => {
                        assert_eq!(message, "cleared");
                    }
                    (45..=49, ResponseResult::Metrics(metrics)) => {
                        assert!(
                            (1..=50).contains(&(metrics.requests_total - baseline.requests_total))
                        );
                        assert_eq!(metrics.requests_failed, baseline.requests_failed);
                        assert_eq!(metrics.rate_limit_hits, baseline.rate_limit_hits);
                    }
                    (_, other) => panic!("mixed request {expected_id} returned {other:?}"),
                }
            }
            other => panic!("mixed request {expected_id} returned {other:?}"),
        }
    }

    match fixture.send_request(Request::Metrics { id: 1001 }).await {
        Response::Success {
            id: 1001,
            result: ResponseResult::Metrics(metrics),
        } => {
            assert_eq!(metrics.requests_total - baseline.requests_total, 51);
            assert_eq!(metrics.requests_failed, baseline.requests_failed);
            assert_eq!(metrics.rate_limit_hits, baseline.rate_limit_hits);
        }
        other => panic!("final mixed-workload metrics returned {other:?}"),
    }

    Ok(())
}
