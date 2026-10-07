#![expect(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]
//! End-to-End Tests for OMG CLI
//!
//! Comprehensive E2E test infrastructure validating the complete user journey:
//! - CLI installation simulation (self-update)
//! - License activation flow (JWT/EdDSA validation)
//! - Usage reporting flow (telemetry)
//! - Daemon communication (Unix socket IPC)
//!
//! ## Test Philosophy (TDD)
//! - Tests are written FIRST, before any production code changes
//! - Each test has a clear purpose documented with `///` comments
//! - Tests are deterministic - no flaky tests allowed
//! - Network calls are mocked to avoid external dependencies
//! - All error paths are explicitly tested

pub mod common;

use common::{serial, with_test_env};

use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

// ═══════════════════════════════════════════════════════════════════════════════
// TEST INFRASTRUCTURE
// ═══════════════════════════════════════════════════════════════════════════════

/// Test environment with isolated filesystem
struct E2ETestEnv {
    /// Temporary directory for test data (simulates ~/.local/share/omg)
    data_dir: TempDir,
}

impl E2ETestEnv {
    /// Create a new isolated test environment
    fn new() -> Result<Self> {
        Ok(Self {
            data_dir: TempDir::new()?,
        })
    }

    /// Get the data directory path
    fn data_path(&self) -> &Path {
        self.data_dir.path()
    }

    /// Create a file in the data directory
    fn create_data_file(&self, name: &str, content: &str) -> Result<PathBuf> {
        let path = self.data_dir.path().join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, content)?;
        Ok(path)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 2: LICENSE ACTIVATION FLOW
// ═══════════════════════════════════════════════════════════════════════════════

/// Tests for license activation and validation.
///
/// The former inline license-key format validation tests were removed in
/// wave 2: they re-implemented the validation rules inside the tests and
/// asserted the copy, so no omg regression could fail them. Format rules are
/// owned by `omg_lib::core::license` and must be pinned there.
mod license_tests {
    use super::*;

    /// Verify tier hierarchy is correctly ordered
    #[test]
    fn test_tier_hierarchy() {
        use omg_lib::core::license::Tier;

        // Given: All tier levels
        let free = Tier::Free;
        let pro = Tier::Pro;
        let team = Tier::Team;
        let enterprise = Tier::Enterprise;

        // Then: Hierarchy should be correct
        assert!(free < pro, "Free should be less than Pro");
        assert!(pro < team, "Pro should be less than Team");
        assert!(team < enterprise, "Team should be less than Enterprise");
        assert!(free < enterprise, "Free should be less than Enterprise");
    }

    /// Verify feature gating based on tier
    #[test]
    fn test_feature_gating_by_tier() {
        use omg_lib::core::license::{Feature, Tier};

        // Given: Features and their required tiers
        let test_cases = [
            (Feature::Packages, Tier::Free),
            (Feature::Runtimes, Tier::Free),
            (Feature::Sbom, Tier::Pro),
            (Feature::Audit, Tier::Pro),
            (Feature::TeamSync, Tier::Team),
            (Feature::Fleet, Tier::Team),
            (Feature::Policy, Tier::Enterprise),
            (Feature::Slsa, Tier::Enterprise),
        ];

        for (feature, expected_tier) in test_cases {
            // When: We check the required tier
            let required = feature.required_tier();

            // Then: It should match expected
            assert_eq!(
                required, expected_tier,
                "Feature {feature:?} should require {expected_tier:?} tier"
            );
        }
    }

    /// Verify machine ID generation is deterministic
    #[test]
    fn test_machine_id_is_deterministic() {
        use omg_lib::core::license::get_machine_id;

        // When: We generate machine ID twice
        let id1 = get_machine_id();
        let id2 = get_machine_id();

        // Then: Should get the same ID
        assert_eq!(id1, id2, "Machine ID should be deterministic");

        // And: Should be 16 characters (first 16 chars of SHA256)
        assert_eq!(id1.len(), 16, "Machine ID should be 16 characters");

        // And: Should be hex-encoded
        assert!(
            id1.chars().all(|c| c.is_ascii_hexdigit()),
            "Machine ID should be hex-encoded"
        );
    }

    /// Verify license JSON serialization/deserialization
    #[test]
    fn test_license_json_roundtrip() -> Result<()> {
        use omg_lib::core::license::StoredLicense;

        // Given: A stored license
        let license = StoredLicense {
            key: "TEST-KEY-123".to_string(),
            tier: "pro".to_string(),
            features: vec!["sbom".to_string(), "audit".to_string()],
            customer: Some("Test Customer".to_string()),
            expires_at: Some("2025-12-31".to_string()),
            validated_at: 1_700_000_000,
            token: Some("test.jwt.token".to_string()),
            machine_id: Some("abc123def456".to_string()),
        };

        // When: We serialize and deserialize
        let json = serde_json::to_string(&license)?;
        let deserialized: StoredLicense = serde_json::from_str(&json)?;

        // Then: All fields should match
        assert_eq!(deserialized.key, license.key);
        assert_eq!(deserialized.tier, license.tier);
        assert_eq!(deserialized.features, license.features);
        assert_eq!(deserialized.customer, license.customer);
        assert_eq!(deserialized.expires_at, license.expires_at);
        assert_eq!(deserialized.validated_at, license.validated_at);
        assert_eq!(deserialized.token, license.token);
        assert_eq!(deserialized.machine_id, license.machine_id);

        Ok(())
    }

    /// Verify license API response parsing
    #[test]
    fn test_license_api_response_parsing() -> Result<()> {
        use omg_lib::core::license::LicenseResponse;

        // Given: A valid API response JSON
        let json = r#"{
            "valid": true,
            "tier": "pro",
            "features": ["sbom", "audit", "secrets"],
            "customer": "Acme Corp",
            "expires_at": "2025-12-31T23:59:59Z",
            "token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9..."
        }"#;

        // When: We parse the response
        let response: LicenseResponse = serde_json::from_str(json)?;

        // Then: All fields should be correctly parsed
        assert!(response.valid, "Response should be valid");
        assert_eq!(response.tier, Some("pro".to_string()));
        assert_eq!(response.features.as_ref().unwrap().len(), 3);
        assert_eq!(response.customer, Some("Acme Corp".to_string()));

        Ok(())
    }

    /// Verify license API error response parsing
    #[test]
    fn test_license_api_error_response_parsing() -> Result<()> {
        use omg_lib::core::license::LicenseResponse;

        // Given: An invalid license response
        let json = r#"{
            "valid": false,
            "error": "License key not found or expired"
        }"#;

        // When: We parse the response
        let response: LicenseResponse = serde_json::from_str(json)?;

        // Then: Should indicate invalid with error message
        assert!(!response.valid, "Response should be invalid");
        assert!(response.tier.is_none(), "Tier should be absent");
        assert_eq!(
            response.error,
            Some("License key not found or expired".to_string())
        );

        Ok(())
    }

    /// Verify a cached license written to the data dir loads via the product
    /// loader (`load_license`), which reads `<OMG_DATA_DIR>/license.json`.
    /// Contract pinned at src/core/license.rs:494.
    #[test]
    #[serial]
    fn test_offline_license_validation_with_cached_token() -> Result<()> {
        use omg_lib::core::license::load_license;

        // Given: An isolated data dir containing a cached license
        let env = E2ETestEnv::new()?;
        let license_json = r#"{
            "key": "OMG-PRO-TEST",
            "tier": "pro",
            "features": ["sbom", "audit"],
            "customer": "Test User",
            "validated_at": 1700000000,
            "token": "mock.jwt.token",
            "machine_id": "abc123"
        }"#;
        env.create_data_file("license.json", license_json)?;
        let data_dir = env.data_path().to_string_lossy().into_owned();

        // When: The product loader reads the cache offline
        let loaded = with_test_env(&[("OMG_DATA_DIR", &data_dir)], load_license);

        // Then: The stored license must round-trip its identity fields
        let license = loaded.expect("cached pro license must load offline");
        assert_eq!(license.key, "OMG-PRO-TEST");
        assert_eq!(license.tier, "pro");
        assert_eq!(license.features, vec!["sbom", "audit"]);

        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 3: USAGE REPORTING FLOW
// ═══════════════════════════════════════════════════════════════════════════════

/// Tests for usage tracking and reporting
mod usage_tests {
    use super::*;
    use omg_lib::core::usage::{Achievement, UsageStats};

    /// Verify usage stats initialization with default values
    #[test]
    fn test_usage_stats_default_values() {
        // When: We create default usage stats
        let stats = UsageStats::default();

        // Then: All counters should be zero
        assert_eq!(stats.total_commands, 0, "Total commands should start at 0");
        assert_eq!(stats.time_saved_ms, 0, "Time saved should start at 0");
        assert_eq!(stats.queries_today, 0, "Queries today should start at 0");
        assert!(stats.commands.is_empty(), "Commands map should be empty");
        assert!(
            stats.achievements.is_empty(),
            "Achievements should be empty"
        );
    }

    /// Verify command recording increments counters correctly.
    ///
    /// `record_command` also persists best-effort to `<OMG_DATA_DIR>/usage.json`,
    /// so it runs against an isolated data dir instead of the developer's real
    /// one (src/core/usage.rs:230).
    #[test]
    #[serial]
    fn test_record_command_increments_counters() {
        // Given: Empty usage stats in an isolated data dir
        let env = E2ETestEnv::new().unwrap();
        let data_dir = env.data_path().to_string_lossy().into_owned();
        let mut stats = UsageStats::default();

        // When: We record commands through the public API
        with_test_env(&[("OMG_DATA_DIR", &data_dir)], || {
            stats.record_command("search", 127);
            stats.record_command("search", 127);
            stats.record_command("info", 132);
        });

        // Then: Counters should be updated
        assert_eq!(stats.total_commands, 3, "Total should be 3");
        assert_eq!(
            stats.commands.get("search"),
            Some(&2),
            "Search count should be 2"
        );
        assert_eq!(
            stats.commands.get("info"),
            Some(&1),
            "Info count should be 1"
        );
        assert_eq!(
            stats.time_saved_ms,
            127 + 127 + 132,
            "Time saved should be sum"
        );
    }

    /// Verify `installed_packages` counting through the product tracking path:
    /// `track_install` increments per-package counters under the cross-process
    /// lock and persists to `<OMG_DATA_DIR>/usage.json` (src/core/usage.rs:554).
    #[test]
    #[serial]
    fn test_installed_packages_tracking() -> Result<()> {
        use omg_lib::core::usage::track_install;

        // Given: An isolated data dir
        let env = E2ETestEnv::new()?;
        let data_dir = env.data_path().to_string_lossy().into_owned();

        // When: Installs are tracked through the product API
        with_test_env(&[("OMG_DATA_DIR", &data_dir)], || {
            track_install(&["firefox".to_string(), "vim".to_string()]);
            track_install(&["firefox".to_string()]);
        });

        // Then: Reloaded stats must show the accumulated per-package counts
        let stats = with_test_env(&[("OMG_DATA_DIR", &data_dir)], UsageStats::load)?;
        assert_eq!(
            stats.installed_packages.get("firefox"),
            Some(&2),
            "Firefox should be installed 2 times"
        );
        assert_eq!(
            stats.installed_packages.get("vim"),
            Some(&1),
            "Vim should be installed 1 time"
        );

        Ok(())
    }

    /// Successful installs persist per-package estimates but one command event.
    #[test]
    #[serial]
    fn install_estimates_scale_with_tracked_packages() -> Result<()> {
        use omg_lib::core::usage::{track_install_result, track_search};

        for (count, expected_credit) in [(50, 75_000), (1, 1_500), (0, 0)] {
            let env = E2ETestEnv::new()?;
            let data_dir = env.data_path().to_string_lossy().into_owned();
            let packages: Vec<String> = (0..count).map(|i| format!("package-{i}")).collect();
            with_test_env(
                &[("OMG_DATA_DIR", &data_dir), ("OMG_TEST_MODE", "1")],
                || {
                    track_search();
                    track_install_result(&packages, true);
                },
            );

            let stats = with_test_env(
                &[("OMG_DATA_DIR", &data_dir), ("OMG_TEST_MODE", "1")],
                UsageStats::load,
            )?;
            assert_eq!(stats.time_saved_ms, 127 + expected_credit, "count={count}");
            assert_eq!(
                stats.time_saved_today_ms,
                127 + expected_credit,
                "count={count}"
            );
            assert_eq!(stats.total_commands, 2);
            assert_eq!(stats.queries_today, 2);
            assert_eq!(stats.queries_this_month, 2);
            assert_eq!(stats.installs_today, 1);
            assert_eq!(stats.commands.get("install"), Some(&1));
            assert_eq!(stats.installed_packages.len(), count);
            for package in &packages {
                assert_eq!(stats.installed_packages.get(package), Some(&1));
            }
        }
        Ok(())
    }

    /// Failed installs neither create usage state nor change existing credit.
    #[test]
    #[serial]
    fn failed_installs_preserve_usage_credit() -> Result<()> {
        use omg_lib::core::usage::track_install_result;

        let env = E2ETestEnv::new()?;
        let data_dir = env.data_path().to_string_lossy().into_owned();
        let packages = ["firefox".to_string(), "vim".to_string()];
        let path = env.data_path().join("usage.json");
        with_test_env(
            &[("OMG_DATA_DIR", &data_dir), ("OMG_TEST_MODE", "1")],
            || {
                track_install_result(&packages, false);
            },
        );
        assert!(!path.exists());

        with_test_env(
            &[("OMG_DATA_DIR", &data_dir), ("OMG_TEST_MODE", "1")],
            || {
                track_install_result(&packages[..1], true);
            },
        );
        let before = fs::read(&path)?;
        with_test_env(
            &[("OMG_DATA_DIR", &data_dir), ("OMG_TEST_MODE", "1")],
            || {
                track_install_result(&packages, false);
            },
        );
        assert_eq!(fs::read(&path)?, before);
        Ok(())
    }

    /// Verify `runtime_usage_counts` tracking through the product path:
    /// `track_runtime_switch` increments counters and persists them
    /// (src/core/usage.rs:573).
    #[test]
    #[serial]
    fn test_runtime_usage_tracking() -> Result<()> {
        use omg_lib::core::usage::track_runtime_switch;

        // Given: An isolated data dir
        let env = E2ETestEnv::new()?;
        let data_dir = env.data_path().to_string_lossy().into_owned();

        // When: Runtime switches are tracked through the product API
        with_test_env(&[("OMG_DATA_DIR", &data_dir)], || {
            track_runtime_switch("node");
            track_runtime_switch("node");
            track_runtime_switch("python");
        });

        // Then: Reloaded stats must show the accumulated switch counts
        let stats = with_test_env(&[("OMG_DATA_DIR", &data_dir)], UsageStats::load)?;
        assert_eq!(
            stats.runtime_usage_counts.get("node"),
            Some(&2),
            "Node usage should be 2"
        );
        assert_eq!(
            stats.runtime_usage_counts.get("python"),
            Some(&1),
            "Python usage should be 1"
        );

        Ok(())
    }

    /// Verify time saved calculation is accurate
    #[test]
    fn test_time_saved_calculation() {
        use omg_lib::core::usage::time_saved;

        // Given: Expected time savings per operation
        // Then: Values should match documented benchmarks
        assert_eq!(
            time_saved::SEARCH_MS,
            127,
            "Search should save 127ms (133ms - 6ms)"
        );
        assert_eq!(
            time_saved::INFO_MS,
            132,
            "Info should save 132ms (138ms - 6.5ms)"
        );
        assert_eq!(
            time_saved::RUNTIME_SWITCH_MS,
            148,
            "Runtime switch should save 148ms (150ms - 1.8ms)"
        );
    }

    /// Verify human-readable time format
    #[test]
    fn test_time_saved_human_format() {
        // Given: Various time values
        let test_cases = [
            (500, "500ms"),
            (5000, "5.0s"),
            (60_000, "1.0min"),
            (120_000, "2.0min"),
            (3_600_000, "1.0hr"),
            (7_200_000, "2.0hr"),
        ];

        for (ms, expected) in test_cases {
            // When: We format the time
            let stats = UsageStats {
                time_saved_ms: ms,
                ..Default::default()
            };
            let formatted = stats.time_saved_human();

            // Then: Format should be correct
            assert_eq!(formatted, expected, "{ms}ms should format as '{expected}'");
        }
    }

    /// Verify achievement unlocking is driven by real command recording.
    ///
    /// `check_achievements` runs inside every `record_command`
    /// (src/core/usage.rs:273), so thresholds must unlock through the public
    /// API: 100 commands at 600ms each = Centurion + MinuteSaver, but NOT
    /// Legend (10k commands) or HourSaver (3.6M ms).
    #[test]
    #[serial]
    fn test_achievement_unlocking() {
        // Given: An isolated data dir and empty stats
        let env = E2ETestEnv::new().unwrap();
        let data_dir = env.data_path().to_string_lossy().into_owned();
        let mut stats = UsageStats::default();

        // When: Exactly 100 commands are recorded totalling 60_000ms saved
        with_test_env(&[("OMG_DATA_DIR", &data_dir)], || {
            for _ in 0..100 {
                stats.record_command("bench", 600);
            }
        });

        // Then: The earned achievements are unlocked...
        assert!(
            stats.achievements.contains(&Achievement::FirstStep),
            "Should have FirstStep achievement"
        );
        assert!(
            stats.achievements.contains(&Achievement::Centurion),
            "Should have Centurion (100 commands) achievement"
        );
        assert!(
            stats.achievements.contains(&Achievement::MinuteSaver),
            "Should have MinuteSaver (1 minute saved) achievement"
        );

        // ...and the unmet thresholds stay locked
        assert!(
            !stats.achievements.contains(&Achievement::Legend),
            "Legend requires 10_000 commands, must not unlock at 100"
        );
        assert!(
            !stats.achievements.contains(&Achievement::HourSaver),
            "HourSaver requires 3_600_000ms saved, must not unlock at 60_000ms"
        );
    }

    /// Verify usage stats JSON serialization for API sync
    #[test]
    fn test_usage_stats_json_serialization() -> Result<()> {
        // Given: Usage stats with data
        let mut stats = UsageStats {
            total_commands: 50,
            time_saved_ms: 10000,
            ..Default::default()
        };
        stats.installed_packages.insert("git".to_string(), 1);
        stats.runtime_usage_counts.insert("node".to_string(), 5);

        // When: We serialize to JSON
        let json = serde_json::to_string(&stats)?;

        // Then: JSON should contain expected fields
        assert!(
            json.contains("\"total_commands\":50"),
            "JSON should contain total_commands"
        );
        assert!(
            json.contains("\"time_saved_ms\":10000"),
            "JSON should contain time_saved_ms"
        );
        assert!(
            json.contains("\"git\""),
            "JSON should contain installed package"
        );
        assert!(
            json.contains("\"node\""),
            "JSON should contain runtime usage"
        );

        Ok(())
    }

    /// Verify usage file persistence through the product save/load cycle
    /// (`UsageStats::save` / `UsageStats::load`, src/core/usage.rs:198/218).
    #[test]
    #[serial]
    fn test_usage_stats_persistence() -> Result<()> {
        // Given: An isolated data dir with stats saved via the product API
        let env = E2ETestEnv::new()?;
        let data_dir = env.data_path().to_string_lossy().into_owned();

        let stats = UsageStats {
            total_commands: 42,
            time_saved_ms: 5000,
            ..Default::default()
        };
        with_test_env(&[("OMG_DATA_DIR", &data_dir)], || {
            stats.save().expect("usage stats save must succeed");
        });

        // When: A fresh load reads the persisted file back
        let loaded = with_test_env(&[("OMG_DATA_DIR", &data_dir)], UsageStats::load)?;

        // Then: Stats should round-trip exactly
        assert_eq!(loaded.total_commands, 42);
        assert_eq!(loaded.time_saved_ms, 5000);

        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 4: DAEMON COMMUNICATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Tests for daemon IPC protocol and communication
mod daemon_tests {
    use super::*;
    use omg_lib::daemon::protocol::{
        PackageInfo, Request, Response, ResponseResult, SearchResult, WirePackageSource,
    };

    /// Verify request serialization with bitcode
    #[test]
    fn test_request_bitcode_serialization() -> Result<()> {
        // Given: A search request
        let request = Request::Search {
            id: 1,
            query: "firefox".to_string(),
            limit: Some(10),
        };

        // When: We serialize with bitcode
        let bytes = bitcode::serialize(&request)?;

        // Then: Should produce non-empty bytes
        assert!(!bytes.is_empty(), "Serialized request should not be empty");

        // And: Should deserialize back correctly
        let deserialized: Request = bitcode::deserialize(&bytes)?;
        match deserialized {
            Request::Search { id, query, limit } => {
                assert_eq!(id, 1);
                assert_eq!(query, "firefox");
                assert_eq!(limit, Some(10));
            }
            _ => unreachable!("Wrong request type after deserialization"),
        }

        Ok(())
    }

    /// Verify response serialization with bitcode
    #[test]
    fn test_response_bitcode_serialization() -> Result<()> {
        // Given: A search response
        let response = Response::Success {
            id: 1,
            result: ResponseResult::Search(SearchResult {
                packages: vec![PackageInfo {
                    name: "firefox".to_string(),
                    version: "122.0".to_string(),
                    description: "Web browser".to_string(),
                    source: WirePackageSource::Official,
                }],
                total: 1,
            }),
        };

        // When: We serialize with bitcode
        let bytes = bitcode::serialize(&response)?;

        // Then: Should produce non-empty bytes
        assert!(!bytes.is_empty(), "Serialized response should not be empty");

        // And: Should deserialize back correctly
        let deserialized: Response = bitcode::deserialize(&bytes)?;
        match deserialized {
            Response::Success { id, result } => {
                assert_eq!(id, 1);
                match result {
                    ResponseResult::Search(sr) => {
                        assert_eq!(sr.packages.len(), 1);
                        assert_eq!(sr.packages[0].name, "firefox");
                    }
                    _ => unreachable!("Wrong result type"),
                }
            }
            Response::Error { .. } => unreachable!("Expected success response"),
        }

        Ok(())
    }

    /// Verify error response format
    #[test]
    fn test_error_response_format() -> Result<()> {
        use omg_lib::daemon::protocol::error_codes;

        // Given: An error response
        let response = Response::Error {
            id: 1,
            code: error_codes::PACKAGE_NOT_FOUND,
            message: "Package 'nonexistent' not found".to_string(),
        };

        // When: We serialize and deserialize
        let bytes = bitcode::serialize(&response)?;
        let deserialized: Response = bitcode::deserialize(&bytes)?;

        // Then: Error details should be preserved
        match deserialized {
            Response::Error { id, code, message } => {
                assert_eq!(id, 1);
                assert_eq!(code, error_codes::PACKAGE_NOT_FOUND);
                assert!(message.contains("nonexistent"));
            }
            Response::Success { .. } => unreachable!("Expected error response"),
        }

        Ok(())
    }

    /// Verify the product length-delimited framing round-trips payloads.
    ///
    /// `write_frame` prefixes a big-endian `u32` length; `read_frame` reads it
    /// back and rejects frames over [`MAX_FRAME_SIZE`]
    /// (src/daemon/protocol.rs:380/399).
    #[test]
    fn test_length_delimited_framing() -> Result<()> {
        use omg_lib::daemon::protocol::{MAX_FRAME_SIZE, read_frame, write_frame};
        use std::io::Cursor;

        // Given: A message framed through the product writer
        let message = b"test message content";
        let mut wire = Cursor::new(Vec::new());
        write_frame(&mut wire, message)?;

        // Then: The frame is 4-byte prefix + payload, and reading it back
        // yields the exact payload
        let buf = wire.into_inner();
        assert_eq!(buf.len(), 4 + message.len());
        let decoded = read_frame(&mut Cursor::new(&buf))?;
        assert_eq!(decoded, message.to_vec(), "frame payload must round-trip");

        // And: An oversized announced length must be rejected as invalid data
        let hostile_prefix = (MAX_FRAME_SIZE as u32 + 1).to_be_bytes();
        let hostile: Vec<u8> = hostile_prefix
            .iter()
            .copied()
            .chain(b"x".repeat(8))
            .collect();
        let err = read_frame(&mut Cursor::new(&hostile)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        Ok(())
    }

    /// Verify request ID matching in responses
    #[test]
    fn test_request_id_matching() {
        // Given: Requests with different IDs
        let requests = [
            Request::Ping { id: 1 },
            Request::Ping { id: 42 },
            Request::Ping { id: 999 },
        ];

        // Then: Each request should have its correct ID
        assert_eq!(requests[0].id(), 1);
        assert_eq!(requests[1].id(), 42);
        assert_eq!(requests[2].id(), 999);
    }

    /// Verify all request types have proper ID extraction
    #[test]
    fn test_all_request_types_have_id() {
        // Given: All request types
        let requests: Vec<Request> = vec![
            Request::Search {
                id: 1,
                query: "test".to_string(),
                limit: None,
            },
            Request::Info {
                id: 2,
                package: "test".to_string(),
            },
            Request::Status { id: 3 },
            Request::Explicit { id: 4 },
            Request::ExplicitCount { id: 5 },
            Request::SecurityAudit { id: 6 },
            Request::Ping { id: 7 },
            Request::CacheStats { id: 8 },
            Request::CacheClear { id: 9 },
            Request::Metrics { id: 10 },
            Request::Suggest {
                id: 11,
                query: "test".to_string(),
                limit: None,
            },
        ];

        // Then: Each should return its ID
        for (idx, request) in requests.iter().enumerate() {
            assert_eq!(
                request.id(),
                (idx + 1) as u64,
                "Request type {request:?} should return correct ID"
            );
        }
    }

    /// Verify socket path resolution honours its documented override order:
    /// `OMG_SOCKET_PATH` first, then a name ending in `omg.sock`
    /// (src/core/paths.rs:278).
    #[test]
    #[serial]
    fn test_socket_path_generation() {
        use omg_lib::core::paths::socket_path;

        // Default resolution must still name the omg socket file
        let default_path = socket_path();
        assert!(
            default_path.ends_with("omg.sock"),
            "Socket path should end with omg.sock, got {default_path:?}"
        );

        // An explicit OMG_SOCKET_PATH override must win verbatim
        let overridden = with_test_env(
            &[("OMG_SOCKET_PATH", "/tmp-test-dir/custom.sock")],
            socket_path,
        );
        assert_eq!(
            overridden,
            PathBuf::from("/tmp-test-dir/custom.sock"),
            "OMG_SOCKET_PATH must override the socket path"
        );
    }

    /// Verify test-mode detection matches the documented accepted values:
    /// only "1", "true", or "TRUE" enable test mode (src/core/paths.rs:401).
    #[test]
    #[serial]
    fn test_daemon_disabled_check() {
        use omg_lib::core::paths::test_mode;

        assert!(
            with_test_env(&[("OMG_TEST_MODE", "1")], test_mode),
            "OMG_TEST_MODE=1 must enable test mode"
        );
        assert!(
            !with_test_env(&[("OMG_TEST_MODE", "0")], test_mode),
            "OMG_TEST_MODE=0 must not enable test mode"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 5: INTEGRATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Integration tests combining multiple components
mod integration_tests {
    use super::*;

    /// Verify the license activation flow end-to-end without network.
    ///
    /// Product intent is FAIL-CLOSED: `tier_enum()` trusts only a JWT that
    /// verifies against the production Ed25519 key, so an offline cached pro
    /// license without a token keeps its stored identity but degrades to Free.
    #[test]
    #[serial]
    fn test_license_activation_flow_mocked() -> Result<()> {
        use omg_lib::core::license::{Tier, current_tier, load_license, require_feature};

        // Given: An isolated data dir with an activated pro license
        let env = E2ETestEnv::new()?;

        // Simulate successful activation by creating license file
        let license = r#"{
            "key": "OMG-PRO-TEST-1234",
            "tier": "pro",
            "features": ["sbom", "audit", "secrets"],
            "customer": "Test User",
            "expires_at": "2025-12-31",
            "validated_at": 1700000000,
            "machine_id": "test123"
        }"#;
        env.create_data_file("license.json", license)?;
        let data_dir = env.data_path().to_string_lossy().into_owned();

        // Then: The stored identity round-trips...
        let stored = with_test_env(&[("OMG_DATA_DIR", &data_dir)], load_license)
            .expect("cached pro license must be readable");
        assert_eq!(stored.key, "OMG-PRO-TEST-1234");
        assert_eq!(stored.tier, "pro");

        // Unverifiable tokens are not a dashboard identity, but they do not
        // paywall local features.
        let tier = with_test_env(&[("OMG_DATA_DIR", &data_dir)], current_tier);
        assert_eq!(
            tier,
            Tier::Free,
            "an unverifiable token is not a linked dashboard identity"
        );
        with_test_env(&[("OMG_DATA_DIR", &data_dir)], || {
            require_feature("sbom").expect("sbom must work without a verified token")
        });

        Ok(())
    }

    /// Verify usage tracking accumulates across sessions through the product
    /// load → record → persist cycle (src/core/usage.rs:198/230).
    #[test]
    #[serial]
    fn test_usage_tracking_persistence() -> Result<()> {
        use omg_lib::core::usage::UsageStats;

        // Given: A data dir with an existing session's stats on disk
        let env = E2ETestEnv::new()?;

        // Initial usage
        let initial_usage = r#"{
            "total_commands": 100,
            "time_saved_ms": 12700,
            "commands": {"search": 50, "info": 30, "install": 20},
            "installed_packages": {"vim": 1, "git": 1},
            "runtime_usage_counts": {"node": 5},
            "queries_today": 10,
            "queries_this_month": 100,
            "last_query_date": "2024-01-15",
            "last_month": "2024-01",
            "last_sync": 1700000000
        }"#;
        env.create_data_file("usage.json", initial_usage)?;
        let data_dir = env.data_path().to_string_lossy().into_owned();

        // When: A new session records five searches via the product API
        // (record_command persists best-effort after each record)
        with_test_env(&[("OMG_DATA_DIR", &data_dir)], || {
            let mut stats = UsageStats::load().expect("existing stats must load");
            for _ in 0..5 {
                stats.record_command("search", 127);
            }
        });

        // Then: The next session sees the accumulated totals persisted
        let final_stats = with_test_env(&[("OMG_DATA_DIR", &data_dir)], UsageStats::load)?;
        assert_eq!(
            final_stats.total_commands, 105,
            "Commands should accumulate"
        );
        assert_eq!(
            final_stats.time_saved_ms, 13_335,
            "Time saved should accumulate"
        );
        assert_eq!(final_stats.commands.get("search"), Some(&55));

        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 6: ERROR HANDLING TESTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Tests for error handling and edge cases
mod error_handling_tests {
    use super::*;

    /// Verify graceful handling of a corrupted license file: the product
    /// loader must treat it as no license (`None`) instead of panicking or
    /// inventing a default (src/core/license.rs:489-507).
    #[test]
    #[serial]
    fn test_corrupted_license_file_handling() -> Result<()> {
        use omg_lib::core::license::load_license;

        // Given: A data dir whose license.json is malformed
        let env = E2ETestEnv::new()?;
        env.create_data_file("license.json", "{ invalid json }")?;
        let data_dir = env.data_path().to_string_lossy().into_owned();

        // When: The product loader reads the corrupt cache
        // Then: It degrades to "no license", never a panic or fabricated tier
        let loaded = with_test_env(&[("OMG_DATA_DIR", &data_dir)], load_license);
        assert!(loaded.is_none(), "corrupt license must load as None");

        Ok(())
    }

    /// Verify graceful handling of a missing license file: the documented
    /// no-license state is `None`, silently (src/core/license.rs:495).
    #[test]
    #[serial]
    fn test_missing_license_file_handling() -> Result<()> {
        use omg_lib::core::license::load_license;

        // Given: An isolated data dir without license.json
        let env = E2ETestEnv::new()?;
        let data_dir = env.data_path().to_string_lossy().into_owned();

        // When/Then: The loader reports the no-license state
        let loaded = with_test_env(&[("OMG_DATA_DIR", &data_dir)], load_license);
        assert!(loaded.is_none(), "missing license must load as None");

        Ok(())
    }

    /// Verify graceful handling of a corrupted usage file: `UsageStats::load`
    /// must fail with its integrity context instead of silently resetting the
    /// user's counters (src/core/usage.rs:214).
    #[test]
    #[serial]
    fn test_corrupted_usage_file_handling() -> Result<()> {
        use omg_lib::core::usage::UsageStats;

        // Given: A data dir whose usage.json is not JSON at all
        let env = E2ETestEnv::new()?;
        env.create_data_file("usage.json", "not valid json at all")?;
        let data_dir = env.data_path().to_string_lossy().into_owned();

        // When/Then: Loading fails loudly, naming the malformed state
        let error = with_test_env(&[("OMG_DATA_DIR", &data_dir)], UsageStats::load)
            .expect_err("corrupt usage stats must fail to load");
        assert!(
            format!("{error:#}").contains("Malformed usage stats"),
            "error must name the malformed usage stats, got: {error:#}"
        );

        Ok(())
    }

    /// Verify empty response handling
    #[test]
    fn test_empty_response_handling() -> Result<()> {
        // Given: An empty search result
        let response = omg_lib::daemon::protocol::SearchResult {
            packages: vec![],
            total: 0,
        };

        // When: We serialize it
        let bytes = bitcode::serialize(&response)?;

        // Then: Should deserialize correctly
        let deserialized: omg_lib::daemon::protocol::SearchResult = bitcode::deserialize(&bytes)?;
        assert!(
            deserialized.packages.is_empty(),
            "Empty packages should deserialize"
        );
        assert_eq!(deserialized.total, 0, "Total should be 0");

        Ok(())
    }
}
