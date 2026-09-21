#![cfg(unix)]

//! Daemon cache hit/miss rates, invalidation, coherency, and memory pressure.

use anyhow::Result;
use omg_lib::daemon::cache::PackageCache;
use omg_lib::daemon::protocol::{
    PackageInfo, Request, Response, ResponseResult, WirePackageSource,
};
use serial_test::serial;
use std::sync::Arc;

pub mod common;

use common::DaemonTestFixture as CacheTestFixture;

async fn clear_cache(fixture: &CacheTestFixture) {
    let response = fixture.send_request(Request::CacheClear { id: 0 }).await;
    match response {
        Response::Success {
            id: 0,
            result: ResponseResult::Message(message),
        } => assert_eq!(message, "cleared"),
        other => panic!("CacheClear returned {other:?}"),
    }
}

async fn empty_search(fixture: &CacheTestFixture, id: u64) {
    match fixture
        .send_request(Request::Search {
            id,
            query: "test".to_string(),
            limit: Some(10),
        })
        .await
    {
        Response::Success {
            id: response_id,
            result: ResponseResult::Search(result),
        } => {
            assert_eq!(response_id, id);
            assert!(result.packages.is_empty());
            assert_eq!(result.total, 0);
        }
        other => panic!("fixture search returned {other:?}"),
    }
}

async fn cache_counts(fixture: &CacheTestFixture, id: u64) -> (u64, u64) {
    match fixture.send_request(Request::Metrics { id }).await {
        Response::Success {
            id: response_id,
            result: ResponseResult::Metrics(metrics),
        } => {
            assert_eq!(response_id, id);
            (metrics.cache_hits, metrics.cache_misses)
        }
        other => panic!("cache metrics returned {other:?}"),
    }
}

// ============================================================================
// Cache Hit/Miss Rates
// ============================================================================

#[tokio::test]
#[serial]
async fn test_cache_hit_rate_tracking() -> Result<()> {
    let fixture = CacheTestFixture::new()?;
    clear_cache(&fixture).await;

    // Get initial metrics
    let metrics1 = fixture.send_request(Request::Metrics { id: 100 }).await;

    let (initial_hits, initial_misses) = match metrics1 {
        Response::Success {
            result: ResponseResult::Metrics(m),
            ..
        } => (m.cache_hits, m.cache_misses),
        response => panic!("Metrics request failed: {response:?}"),
    };

    // Perform a search (cache miss)
    empty_search(&fixture, 1).await;

    // Repeat same search (cache hit)
    empty_search(&fixture, 2).await;

    // Check metrics
    let metrics2 = fixture.send_request(Request::Metrics { id: 101 }).await;

    let metrics = match metrics2 {
        Response::Success {
            result: ResponseResult::Metrics(m),
            ..
        } => m,
        response => panic!("Metrics request failed: {response:?}"),
    };
    let hits_delta = metrics.cache_hits - initial_hits;
    let misses_delta = metrics.cache_misses - initial_misses;

    assert_eq!(misses_delta, 1, "Exactly one uncached search");
    assert_eq!(hits_delta, 1, "Exactly one repeated search");

    let hit_rate = hits_delta as f64 / (hits_delta + misses_delta) as f64;
    println!("Cache hit rate: {:.2}%", hit_rate * 100.0);

    Ok(())
}

// ============================================================================
// Cache Invalidation
// ============================================================================

#[tokio::test]
#[serial]
async fn test_explicit_cache_clear() -> Result<()> {
    let fixture = CacheTestFixture::new()?;

    async fn cache_misses(fixture: &CacheTestFixture, id: u64) -> u64 {
        match fixture.send_request(Request::Metrics { id }).await {
            Response::Success {
                result: ResponseResult::Metrics(m),
                ..
            } => m.cache_misses,
            response => panic!("Metrics request failed: {response:?}"),
        }
    }

    // Populate the cache and observe the miss.
    let misses_before = cache_misses(&fixture, 1).await;
    empty_search(&fixture, 2).await;
    let misses_after_first = cache_misses(&fixture, 3).await;
    assert!(
        misses_after_first > misses_before,
        "first search must be a cache miss"
    );

    // Repeat: served from cache (no new miss).
    empty_search(&fixture, 4).await;
    let misses_after_repeat = cache_misses(&fixture, 5).await;
    assert_eq!(
        misses_after_repeat, misses_after_first,
        "repeat search must be served from cache"
    );

    // Clear cache
    let clear_response = fixture.send_request(Request::CacheClear { id: 6 }).await;
    assert!(
        matches!(clear_response, Response::Success { .. }),
        "Cache clear should succeed"
    );

    // The same query must now be a miss again: invalidation is observable
    // through request semantics, not only through internal stats.
    empty_search(&fixture, 7).await;
    let misses_after_clear = cache_misses(&fixture, 8).await;
    assert!(
        misses_after_clear > misses_after_repeat,
        "search after CacheClear must be a cache miss again"
    );

    Ok(())
}

// ============================================================================
// Repeated Status Consistency
// ============================================================================

#[tokio::test]
#[serial]
async fn test_repeated_status_reads_are_consistent() -> Result<()> {
    let fixture = CacheTestFixture::new()?;

    for id in [1, 2] {
        common::assert_empty_daemon_status(fixture.send_request(Request::Status { id }).await, id);
    }

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_package_info_cache_coherency() -> Result<()> {
    let fixture = CacheTestFixture::new()?;
    let baseline = cache_counts(&fixture, 10).await;

    // The isolated mock catalog contains this exact package. Two errors
    // cannot establish successful metadata caching.
    for id in [1, 2] {
        match fixture
            .send_request(Request::Info {
                id,
                package: "git".to_string(),
            })
            .await
        {
            Response::Success {
                id: response_id,
                result: ResponseResult::Info(info),
            } => {
                assert_eq!(response_id, id);
                assert_eq!(info.name, "git");
                assert_eq!(info.version, "2.43.0");
                assert_eq!(info.description, "Version control");
                assert_eq!(info.source, WirePackageSource::Official);
            }
            other => panic!("known package info returned {other:?}"),
        }
        let current = cache_counts(&fixture, 10 + id).await;
        assert_eq!(
            (current.0 - baseline.0, current.1 - baseline.1),
            (id - 1, 1)
        );
    }

    Ok(())
}

// ============================================================================
// Missing Package Errors
// ============================================================================

#[tokio::test]
#[serial]
async fn test_missing_package_returns_error_consistently() -> Result<()> {
    let fixture = CacheTestFixture::new()?;
    let nonexistent_package = "this-package-definitely-does-not-exist-12345";

    for id in [1, 2] {
        match fixture
            .send_request(Request::Info {
                id,
                package: nonexistent_package.to_string(),
            })
            .await
        {
            Response::Error {
                id: response_id,
                code,
                message,
            } => {
                assert_eq!(response_id, id);
                assert_eq!(
                    code,
                    omg_lib::daemon::protocol::error_codes::PACKAGE_NOT_FOUND
                );
                assert_eq!(message, format!("Package not found: {nonexistent_package}"));
            }
            other => panic!("missing package info returned {other:?}"),
        }
    }

    Ok(())
}

// ============================================================================
// Memory Pressure Handling
// ============================================================================

#[tokio::test]
#[serial]
async fn test_lru_eviction_behavior() -> Result<()> {
    // Create small cache (3 entries max)
    let cache = PackageCache::new(3, 300);

    // PackageCache budgets about 64 KiB per configured entry; 60 KiB payloads
    // make three entries fit while a fourth forces one LRU eviction.
    let result = |name: &str| {
        Arc::new(vec![PackageInfo {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            description: "x".repeat(60_000),
            source: WirePackageSource::Official,
        }])
    };

    // Three weighted entries fit within the configured byte budget.
    cache.insert_arc("query-1".to_string(), result("one"));
    cache.insert_arc("query-2".to_string(), result("two"));
    cache.insert_arc("query-3".to_string(), result("three"));
    cache.sync();

    // Access query-1 to mark it as recently used
    let _ = cache.get("query-1");
    cache.sync();

    // Insert query-4 (should evict LRU, which is query-2)
    cache.insert_arc("query-4".to_string(), result("four"));
    cache.sync();

    // query-1 should still be cached (recently accessed), while query-2 is the LRU entry.
    assert!(
        cache.get("query-1").is_some(),
        "Recently accessed entry should not be evicted"
    );
    assert!(
        cache.get("query-2").is_none(),
        "Least-recently-used entry should be evicted"
    );

    Ok(())
}
