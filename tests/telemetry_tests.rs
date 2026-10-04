#![cfg(feature = "arch")]

//! S-tier Integration Tests: Telemetry System
//!
//! Comprehensive tests for privacy-first telemetry including:
//! - Event batching and queue management structures
//! - Session tracking with 30-minute timeout
//! - Privacy guarantees of serialized events
//!
//! Run: cargo test --features arch telemetry
//!
//! Note: These tests verify the data structures and logic without
//! requiring actual network calls or environment manipulation.

use anyhow::Result;
use tokio::time::Duration;

use omg_lib::core::telemetry::{TelemetrySession, Timer};

// =============================================================================
// AUDIT NOTE (tst-08)
// =============================================================================
// The former `TelemetryTestFixture`-based tests (queue/session persistence,
// corrupted-queue recovery, empty queue, queue path location, file permissions)
// were DELETED as VACUOUS: they only wrote JSON with `serde_json` and read it
// back through the fixture's own helpers, exercising zero product code. The
// real queue/session persistence paths (`EventQueue::load`,
// `TelemetrySession::load_from/save`) are private to the `omg_lib` telemetry
// module and are covered by unit tests inside that module.

// =============================================================================
// SESSION TRACKING TESTS
// =============================================================================

#[tokio::test]
async fn test_session_creation() -> Result<()> {
    use std::sync::atomic::Ordering;

    let session = TelemetrySession::new();

    assert!(!session.session_id.is_empty());
    assert!(!session.started_at.is_empty());
    assert_eq!(session.commands_run.load(Ordering::Relaxed), 0);
    assert!(session.last_activity.load(Ordering::Relaxed) > 0);

    Ok(())
}

#[tokio::test]
async fn test_session_expiry_30_minutes() -> Result<()> {
    use std::sync::atomic::Ordering;

    let session = TelemetrySession::new();

    // Session should not be expired immediately
    assert!(!session.is_expired());

    // Set last activity to 31 minutes ago
    let now = jiff::Timestamp::now().as_second();
    session.last_activity.store(now - 1860, Ordering::Relaxed); // 31 minutes in seconds

    assert!(
        session.is_expired(),
        "Session should be expired after 30 min"
    );

    Ok(())
}

#[tokio::test]
async fn test_session_not_expired_within_30_minutes() -> Result<()> {
    use std::sync::atomic::Ordering;

    let session = TelemetrySession::new();

    // Set last activity to 15 minutes ago
    let now = jiff::Timestamp::now().as_second();
    session.last_activity.store(now - 900, Ordering::Relaxed); // 15 minutes

    assert!(!session.is_expired(), "Session should NOT be expired");

    Ok(())
}

#[tokio::test]
async fn test_session_duration_calculation() -> Result<()> {
    let session = TelemetrySession::new();

    // Just created, duration should be very small
    let duration = session.duration_secs();
    assert!(duration < 5, "Fresh session duration should be near 0");

    Ok(())
}

#[tokio::test]
async fn test_session_serialization() -> Result<()> {
    use std::sync::atomic::Ordering;

    // TelemetrySession uses atomics internally and isn't directly serializable.
    // Instead, we test that the session can be created and its values accessed.
    let session = TelemetrySession::new();

    // Verify session fields are accessible
    assert!(!session.session_id.is_empty());
    assert!(!session.started_at.is_empty());
    assert_eq!(session.commands_run.load(Ordering::Relaxed), 0);

    // Create a second session and verify they have different IDs
    let session2 = TelemetrySession::new();
    assert_ne!(session.session_id, session2.session_id);

    Ok(())
}

// =============================================================================
// EVENT SERIALIZATION TESTS
// =============================================================================

#[tokio::test]
async fn test_command_event_serialization() -> Result<()> {
    use omg_lib::core::telemetry_client::CommandEvent;

    let event = CommandEvent {
        command: "install".to_string(),
        duration_ms: 2500,
        success: true,
        backend: None,
    };

    let json = serde_json::to_string(&event)?;
    assert!(json.contains("install"));
    assert!(json.contains("2500"));
    assert!(!json.contains("\"packages\":"));
    assert!(!json.contains("\"error\":"));

    Ok(())
}

#[tokio::test]
async fn test_session_event_serialization() -> Result<()> {
    use omg_lib::core::telemetry_client::SessionEvent;

    let event = SessionEvent {
        session_id: "test-session-123".to_string(),
        event_type: "start".to_string(),
        start_time: Some("2024-01-01T00:00:00.000Z".to_string()),
        end_time: None,
        commands_run: None,
        duration_secs: None,
    };

    let json = serde_json::to_string(&event)?;
    assert!(json.contains("test-session-123"));
    assert!(json.contains("start"));

    Ok(())
}

#[tokio::test]
async fn test_feature_event_serialization() -> Result<()> {
    use omg_lib::core::telemetry_client::FeatureEvent;

    let event = FeatureEvent {
        feature: "daemon".to_string(),
        enabled: true,
    };

    let json = serde_json::to_string(&event)?;
    assert!(json.contains("daemon"));
    assert!(json.contains("true"));
    assert!(!json.contains("metadata"));

    Ok(())
}

#[tokio::test]
async fn test_telemetry_payload_creation() -> Result<()> {
    use omg_lib::core::telemetry_client::{CommandEvent, TelemetryEvent, TelemetryPayload};

    let event = TelemetryEvent::Command(CommandEvent {
        command: "search".to_string(),
        duration_ms: 50,
        success: true,
        backend: None,
    });

    let payload = TelemetryPayload::new(event);

    assert!(!payload.timestamp.is_empty());
    assert!(!payload.machine_id.is_empty());
    assert!(!payload.version.is_empty());
    assert!(!payload.platform.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_batch_payload_structure() -> Result<()> {
    use omg_lib::core::telemetry_client::{
        BatchPayload, PerformanceEvent, TelemetryEvent, TelemetryPayload,
    };

    let events = vec![
        TelemetryPayload::new(TelemetryEvent::Performance(PerformanceEvent {
            metric_type: "test1".to_string(),
            duration_ms: 100,
        })),
        TelemetryPayload::new(TelemetryEvent::Performance(PerformanceEvent {
            metric_type: "test2".to_string(),
            duration_ms: 200,
        })),
    ];

    let machine_id = omg_lib::core::license::get_machine_id();
    let batch = BatchPayload {
        events,
        batch_timestamp: jiff::Timestamp::now()
            .strftime("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string(),
        machine_id,
    };

    assert_eq!(batch.events.len(), 2);
    assert!(!batch.batch_timestamp.is_empty());
    assert!(!batch.machine_id.is_empty());

    Ok(())
}

// =============================================================================
// TIMER HELPER TESTS
// =============================================================================

#[tokio::test]
async fn test_timer_helper() -> Result<()> {
    let timer = Timer::new("test_operation");

    tokio::time::sleep(Duration::from_millis(10)).await;

    let elapsed = timer.elapsed_ms();
    assert!(elapsed >= 10, "Timer should record at least 10ms");

    Ok(())
}

#[tokio::test]
async fn test_timer_multiple_operations() -> Result<()> {
    let timer1 = Timer::new("operation_1");
    tokio::time::sleep(Duration::from_millis(5)).await;

    let timer2 = Timer::new("operation_2");
    tokio::time::sleep(Duration::from_millis(15)).await;
    let elapsed2 = timer2.elapsed_ms();
    let elapsed1 = timer1.elapsed_ms();

    assert!(elapsed1 >= 5);
    assert!(elapsed2 >= 15);
    assert!(elapsed1 >= elapsed2);

    Ok(())
}

// =============================================================================
// PRIVACY CONTRACT TESTS (EVENT TYPES)
// =============================================================================

#[tokio::test]
async fn test_positional_values_are_absent_from_events() -> Result<()> {
    use omg_lib::core::telemetry_client::{CommandEvent, TelemetryEvent};

    let event = TelemetryEvent::Command(CommandEvent {
        command: "search".to_string(),
        duration_ms: 100,
        success: true,
        backend: None,
    });

    let json = serde_json::to_string(&event)?;
    assert!(!json.contains("lib++"));
    assert!(!json.contains("g++"));
    assert!(!json.contains("packages"));

    Ok(())
}

#[tokio::test]
async fn test_failed_event_does_not_contain_error_text() -> Result<()> {
    use omg_lib::core::telemetry_client::{CommandEvent, TelemetryEvent};

    let event = TelemetryEvent::Command(CommandEvent {
        command: "install".to_string(),
        duration_ms: 150,
        success: false,
        backend: None,
    });

    let json = serde_json::to_value(&event)?;
    assert_eq!(json["success"].as_bool(), Some(false));
    assert!(json.get("error").is_none());

    Ok(())
}

#[tokio::test]
async fn test_search_event_contains_no_query_details() -> Result<()> {
    use omg_lib::core::telemetry_client::{CommandEvent, TelemetryEvent};

    let event = TelemetryEvent::Command(CommandEvent {
        command: "search".to_string(),
        duration_ms: 35,
        success: true,
        backend: None,
    });

    let json = serde_json::to_value(&event)?;
    assert_eq!(json["duration_ms"].as_u64(), Some(35));
    assert!(json.get("query").is_none());
    assert!(json.get("result_count").is_none());

    Ok(())
}

#[tokio::test]
async fn test_update_event_contains_no_package_details() -> Result<()> {
    use omg_lib::core::telemetry_client::{CommandEvent, TelemetryEvent};

    let event = TelemetryEvent::Command(CommandEvent {
        command: "update".to_string(),
        duration_ms: 45000,
        success: true,
        backend: None,
    });

    let json = serde_json::to_value(&event)?;
    assert_eq!(json["duration_ms"].as_u64(), Some(45000));
    assert!(json.get("updated_count").is_none());

    Ok(())
}

// =============================================================================
// LICENSE AND OPT-OUT DETECTION TESTS
// =============================================================================

#[tokio::test]
async fn test_machine_id_generation() -> Result<()> {
    let machine_id = omg_lib::core::license::get_machine_id();

    assert!(!machine_id.is_empty());
    assert!(machine_id.len() > 10, "Machine ID should be substantial");

    // Should be stable across calls
    let machine_id2 = omg_lib::core::license::get_machine_id();
    assert_eq!(machine_id, machine_id2);

    Ok(())
}

// =============================================================================
// DATA STRUCTURE TESTS
// =============================================================================

#[tokio::test]
async fn test_session_id_format() -> Result<()> {
    let session = TelemetrySession::new();

    // Verify UUID v4 format (8-4-4-4-12 hex chars)
    assert_eq!(session.session_id.len(), 36);
    assert_eq!(session.session_id.chars().filter(|c| *c == '-').count(), 4);

    Ok(())
}

#[tokio::test]
async fn test_timestamp_format() -> Result<()> {
    use omg_lib::core::telemetry_client::{PerformanceEvent, TelemetryEvent, TelemetryPayload};

    let event = TelemetryEvent::Performance(PerformanceEvent {
        metric_type: "test".to_string(),
        duration_ms: 100,
    });

    let payload = TelemetryPayload::new(event);

    // Verify ISO 8601 format with milliseconds
    assert!(payload.timestamp.contains('T'));
    assert!(payload.timestamp.contains('Z'));
    assert!(payload.timestamp.len() >= 24); // ISO 8601 with millis

    Ok(())
}

#[tokio::test]
async fn test_platform_string_format() -> Result<()> {
    use omg_lib::core::telemetry_client::{PerformanceEvent, TelemetryEvent, TelemetryPayload};

    let event = TelemetryEvent::Performance(PerformanceEvent {
        metric_type: "test".to_string(),
        duration_ms: 100,
    });

    let payload = TelemetryPayload::new(event);

    // Platform should be "os-arch"
    assert!(payload.platform.contains('-'));
    assert_eq!(payload.platform.split('-').count(), 2);

    Ok(())
}
