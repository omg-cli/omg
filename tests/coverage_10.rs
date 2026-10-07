//! Contract tests for `src/core/telemetry.rs` (agent cov-10).
//!
//! Each test pins an observable, falsifiable contract of the post-cleanup
//! telemetry surface: opt-out gating, install-marker lifecycle, the
//! enhanced-telemetry privacy gate's on-disk behavior, session state
//! semantics, and timing utilities.
//!
//! Known limitation (documented, not theater): the *enabled* side of the
//! enhanced pipeline (`enqueue` → `save` → network flush) cannot be driven
//! end-to-end in tests because `license::verify_jwt` verifies against the
//! production Ed25519 public key and its private key is not a test fixture, so
//! `is_enhanced_telemetry_enabled()` cannot be true in a test process.
//! The gate itself IS tested below from the disabled side.

#[path = "../src/core/testing/isolated.rs"]
mod isolated_fixture;

pub mod common;
use common::*;

use std::fs;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

#[cfg(feature = "arch")]
use omg_lib::core::telemetry::get_backend;
use omg_lib::core::telemetry::{
    TelemetrySession, Timer, end_session_and_flush, flush_events, get_session_id,
    get_startup_duration_ms, is_first_run, is_telemetry_opt_out, ping_install, record_startup_time,
    track_command_event, track_performance_event, track_session_start,
};
use tempfile::TempDir;

#[test]
fn config_and_telemetry_mutations_respect_the_config_lock() -> anyhow::Result<()> {
    let project = TestProject::new();
    let config = project.config_dir.path().join("config.toml");
    let original =
        b"# preserve comments\ntelemetry_enabled = false\n[aur]\nenable_ccache = false\n";
    fs::write(&config, original)?;
    let lock = fs::File::create(project.config_dir.path().join("config.lock"))?;
    lock.lock()?;
    for args in [
        vec!["config", "set", "aur.enable_ccache", "true"],
        vec!["privacy", "opt-in"],
        vec!["privacy", "opt-out"],
        vec!["config", "reset", "--yes"],
    ] {
        let result = project.run_with_env(&args, &[("OMG_TEST_COMMAND_TIMEOUT_SECS", "5")]);
        result.assert_failure();
        assert!(
            result
                .combined_output()
                .contains("Another configuration mutation is running"),
            "{args:?}: {}",
            result.combined_output()
        );
        assert_eq!(fs::read(&config)?, original);
    }
    drop(lock);
    project
        .run(&["config", "set", "aur.enable_ccache", "true"])
        .assert_success();
    project.run(&["privacy", "opt-out"]).assert_success();
    let content = fs::read_to_string(&config)?;
    assert!(content.contains("# preserve comments"));
    let settings: toml::Value = toml::from_str(&content)?;
    assert_eq!(settings["telemetry_enabled"].as_bool(), Some(false));
    assert_eq!(settings["aur"]["enable_ccache"].as_bool(), Some(true));
    project.run(&["config", "reset", "--yes"]).assert_success();
    assert_eq!(
        fs::read_to_string(config.with_extension("toml.backup"))?,
        content
    );
    let reset: toml::Value = toml::from_str(&fs::read_to_string(&config)?)?;
    assert_eq!(reset["aur"]["enable_ccache"].as_bool(), Some(false));
    Ok(())
}

const QUEUE_FILE: &str = "telemetry_queue.json";
const SESSION_FILE: &str = "telemetry_session.json";

/// Assert `value` is a syntactically valid UUIDv4 string (the only kind the
/// telemetry module ever mints).
fn assert_uuid_v4(value: &str) {
    assert_eq!(value.len(), 36, "UUID must be 36 chars, got {value:?}");
    let bytes = value.as_bytes();
    for &dash_at in &[8, 13, 18, 23] {
        assert_eq!(
            bytes[dash_at], b'-',
            "expected dash at position {dash_at} in {value:?}"
        );
    }
    for (i, b) in bytes.iter().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            continue;
        }
        assert!(
            b.is_ascii_hexdigit(),
            "non-hex byte {b:?} at position {i} in {value:?}"
        );
    }
    assert_eq!(
        &value[14..15],
        "4",
        "version nibble must be '4' (UUIDv4) in {value:?}"
    );
    assert!(
        matches!(&value[19..20], "8" | "9" | "a" | "b"),
        "variant nibble must be RFC-4122 in {value:?}"
    );
}

/// Run `f` with a hermetic environment: telemetry env overrides cleared,
/// config/data isolated into fresh temp directories.
struct HermeticEnv {
    vars: Vec<(&'static str, Option<String>)>,
    _config_dir: TempDir,
}

impl HermeticEnv {
    /// Isolate `data` (and optionally `config`) plus force HTTP through a
    /// dead local proxy so any accidental network attempt fails fast
    /// instead of reaching the real telemetry endpoint.
    fn offline(data: &TempDir) -> Self {
        let proxy = "http://127.0.0.1:9".to_string();
        let config_dir = TempDir::new().expect("isolated telemetry config dir");
        let vars = vec![
            ("OMG_TEST_MODE", None),
            ("OMG_TELEMETRY", None),
            ("OMG_DISABLE_TELEMETRY", None),
            (
                "OMG_CONFIG_DIR",
                Some(config_dir.path().to_string_lossy().into_owned()),
            ),
            (
                "OMG_DATA_DIR",
                Some(data.path().to_string_lossy().into_owned()),
            ),
            ("HTTP_PROXY", Some(proxy.clone())),
            ("HTTPS_PROXY", Some(proxy.clone())),
            ("ALL_PROXY", Some(proxy)),
            ("NO_PROXY", Some(String::new())),
        ];
        Self {
            vars,
            _config_dir: config_dir,
        }
    }

    fn run<R>(&self, f: impl FnOnce() -> R) -> R {
        let borrowed: Vec<(&str, Option<&str>)> =
            self.vars.iter().map(|(k, v)| (*k, v.as_deref())).collect();
        temp_env::with_vars(&borrowed, f)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Opt-out gating contract
// ═══════════════════════════════════════════════════════════════════════

/// Tracing diagnostics use stderr, leaving configuration stdout safe for
/// command substitution and other machine-readable consumers.
#[test]
fn tracing_diagnostics_do_not_contaminate_config_stdout() {
    let config = TempDir::new().expect("temporary config directory");
    fs::write(config.path().join("config.toml"), "[general]\n").expect("deprecated config fixture");

    let result = run_omg_with_options(
        &["config", "get", "telemetry.enabled"],
        None,
        &[
            ("OMG_CONFIG_DIR", config.path().to_str().unwrap()),
            ("RUST_LOG", "warn"),
        ],
    );
    result.assert_success();
    result.assert_stderr_contains("config section 'general' is deprecated");
    assert_eq!(
        result.stdout, "false\n",
        "diagnostics must never be mixed into configuration stdout"
    );
}

#[test]
#[serial]
fn opt_out_env_values_and_settings_file_gate_telemetry() {
    if isolated_fixture::run_isolated_test("opt_out_env_values_and_settings_file_gate_telemetry") {
        return;
    }
    let config_dir = TempDir::new().expect("temp config dir");
    let config_str = config_dir.path().to_string_lossy().into_owned();

    fs::write(
        config_dir.path().join("config.toml"),
        "telemetry_enabled = true\n",
    )
    .expect("write enabling config");

    // Explicit opt-in, no env override, no test mode ⇒ telemetry allowed.
    HermeticEnv::offline(&TempDir::new().unwrap()).run(|| {
        temp_env::with_var("OMG_CONFIG_DIR", Some(config_str.as_str()), || {
            assert!(!is_telemetry_opt_out());
        });
    });

    // Every accepted OMG_TELEMETRY value opts out, case-insensitively.
    for value in ["0", "false", "off", "no", "OFF", "False", "No"] {
        HermeticEnv::offline(&TempDir::new().unwrap()).run(|| {
            temp_env::with_vars(
                [
                    ("OMG_CONFIG_DIR", Some(config_str.as_str())),
                    ("OMG_TELEMETRY", Some(value)),
                ],
                || assert!(is_telemetry_opt_out(), "OMG_TELEMETRY={value} must opt out"),
            );
        });
    }

    // Every accepted OMG_DISABLE_TELEMETRY value opts out, case-insensitively.
    for value in ["1", "true", "on", "yes", "YES", "On"] {
        HermeticEnv::offline(&TempDir::new().unwrap()).run(|| {
            temp_env::with_vars(
                [
                    ("OMG_CONFIG_DIR", Some(config_str.as_str())),
                    ("OMG_DISABLE_TELEMETRY", Some(value)),
                ],
                || {
                    assert!(
                        is_telemetry_opt_out(),
                        "OMG_DISABLE_TELEMETRY={value} must opt out"
                    );
                },
            );
        });
    }

    // Non-opt-out values must NOT disable an explicit opt-in (env parsing is
    // a set-membership check, not a truthiness check).
    HermeticEnv::offline(&TempDir::new().unwrap()).run(|| {
        temp_env::with_var("OMG_CONFIG_DIR", Some(config_str.as_str()), || {
            temp_env::with_var("OMG_TELEMETRY", Some("1"), || {
                assert!(
                    !is_telemetry_opt_out(),
                    "OMG_TELEMETRY=1 must keep telemetry on"
                );
            });
            temp_env::with_var("OMG_DISABLE_TELEMETRY", Some("0"), || {
                assert!(
                    !is_telemetry_opt_out(),
                    "OMG_DISABLE_TELEMETRY=0 must keep telemetry on"
                );
            });
        });
    });

    // Settings file with telemetry_enabled = false opts out even with no
    // environment override present.
    fs::write(
        config_dir.path().join("config.toml"),
        "telemetry_enabled = false\n",
    )
    .expect("write disabling config");
    HermeticEnv::offline(&TempDir::new().unwrap()).run(|| {
        temp_env::with_var("OMG_CONFIG_DIR", Some(config_str.as_str()), || {
            assert!(
                is_telemetry_opt_out(),
                "settings telemetry_enabled=false must opt out"
            );
        });
    });

    // And an explicit settings-enabled config keeps telemetry on.
    fs::write(
        config_dir.path().join("config.toml"),
        "telemetry_enabled = true\n",
    )
    .expect("write enabling config");
    HermeticEnv::offline(&TempDir::new().unwrap()).run(|| {
        temp_env::with_var("OMG_CONFIG_DIR", Some(config_str.as_str()), || {
            assert!(
                !is_telemetry_opt_out(),
                "settings telemetry_enabled=true must keep telemetry on"
            );
        });
    });

    // A malformed settings file must fail closed. Configuration errors must
    // never silently reverse a persisted privacy choice.
    fs::write(
        config_dir.path().join("config.toml"),
        "telemetry_enabled = false\nunknown_privacy_setting = true\n",
    )
    .expect("write malformed config");
    HermeticEnv::offline(&TempDir::new().unwrap()).run(|| {
        temp_env::with_var("OMG_CONFIG_DIR", Some(config_str.as_str()), || {
            assert!(
                is_telemetry_opt_out(),
                "invalid settings must disable telemetry until the configuration is repaired"
            );
        });
    });

    // Sanity: the compiled backend identifier under the arch feature.
    #[cfg(feature = "arch")]
    assert_eq!(get_backend(), "arch");
}

// ═══════════════════════════════════════════════════════════════════════
// Install-marker lifecycle (first-run detection + ping persistence)
// ═══════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn install_marker_round_trips_id_through_ping_even_when_endpoint_unreachable() {
    if isolated_fixture::run_isolated_test(
        "install_marker_round_trips_id_through_ping_even_when_endpoint_unreachable",
    ) {
        return;
    }
    let data_dir = TempDir::new().expect("temp data dir");
    let marker_path = data_dir.path().join(".installed");

    HermeticEnv::offline(&data_dir).run(|| {
        // Fresh data dir ⇒ this counts as the first run.
        assert!(marker_does_not_exist(&marker_path));
        assert!(is_first_run(), "empty data dir must look like a first run");

        // ping_install must succeed (its network leg fails silently) and
        // persist the install marker regardless of endpoint reachability.
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(ping_install())
            .expect("ping_install must persist the marker even when offline");

        assert!(
            marker_path.exists(),
            "install marker must exist after ping_install"
        );
        assert!(
            !is_first_run(),
            "marker presence must clear first-run status"
        );

        let marker_json = fs::read_to_string(&marker_path).expect("read marker");
        let parsed: serde_json::Value =
            serde_json::from_str(&marker_json).expect("marker must be valid JSON");
        let first_id = parsed["install_id"]
            .as_str()
            .expect("marker install_id string")
            .to_string();
        assert_uuid_v4(&first_id);
        assert_eq!(
            parsed["version"].as_str(),
            Some(env!("CARGO_PKG_VERSION")),
            "marker version must equal the crate version"
        );
        let timestamp = parsed["timestamp"]
            .as_str()
            .expect("marker timestamp string");
        assert!(!timestamp.is_empty(), "marker timestamp must be recorded");
        assert!(
            timestamp.parse::<jiff::Timestamp>().is_ok(),
            "marker timestamp must parse as ISO 8601, got {timestamp:?}"
        );

        // A second ping on an existing installation must REUSE the stored
        // id (generate-or-load contract), not mint a fresh identity.
        rt.block_on(ping_install()).expect("second ping_install");
        let reparsed: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&marker_path).expect("reread"))
                .expect("marker still valid JSON");
        assert_eq!(
            reparsed["install_id"].as_str(),
            Some(first_id.as_str()),
            "install id must be stable across pings"
        );
    });
}

fn marker_does_not_exist(path: &Path) -> bool {
    !path.exists()
}

// ═══════════════════════════════════════════════════════════════════════
// Enhanced-telemetry privacy gate (disabled side)
// ═══════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn gated_out_telemetry_api_never_persists_queue_or_session_state() {
    if isolated_fixture::run_isolated_test(
        "gated_out_telemetry_api_never_persists_queue_or_session_state",
    ) {
        return;
    }
    // Session ids must be stable within the process and well-formed UUIDs.
    let first = get_session_id();
    let second = get_session_id();
    assert_eq!(first, second, "session id must be stable within a process");
    assert_uuid_v4(&first);

    let data_dir = TempDir::new().expect("temp data dir");
    HermeticEnv::offline(&data_dir).run(|| {
        temp_env::with_var("OMG_TEST_MODE", Some("1"), || {
            // Far more activity than PERSIST_EVERY_N_EVENTS (=10): if the
            // gate were broken anywhere below, periodic persistence would
            // materialize files inside this data dir.
            for i in 0..15u64 {
                track_command_event("install", i * 100, true, Some("arch"));
                track_performance_event("cli_startup", i);
            }
            track_session_start();
            Timer::new("gated_operation").finish();

            let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
            rt.block_on(async {
                flush_events().await;
                end_session_and_flush().await;
            });

            assert!(
                !data_dir.path().join(QUEUE_FILE).exists(),
                "telemetry queue file must NOT be written while telemetry is gated off"
            );
            assert!(
                !data_dir.path().join(SESSION_FILE).exists(),
                "telemetry session file must NOT be written while telemetry is gated off"
            );
        });
    });
}

// ═══════════════════════════════════════════════════════════════════════
// TelemetrySession public state contract
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn session_state_expires_only_after_30_minutes_of_inactivity() {
    let session = TelemetrySession::new();
    assert_uuid_v4(&session.session_id);
    assert_eq!(
        session.commands_run.load(Ordering::Relaxed),
        0,
        "fresh session must start with zero commands"
    );
    assert!(!session.is_expired(), "fresh session must not be expired");

    // Boundary: exactly 1800s idle is NOT expired (contract is strict >).
    let now = jiff::Timestamp::now().as_second();
    session.last_activity.store(now - 1800, Ordering::Relaxed);
    assert!(
        !session.is_expired(),
        "exactly 30 minutes idle must not count as expired"
    );
    session.last_activity.store(now - 1801, Ordering::Relaxed);
    assert!(
        session.is_expired(),
        "more than 30 minutes idle must count as expired"
    );
}

#[test]
fn duration_secs_reports_elapsed_time_for_valid_started_at() {
    use jiff::Timestamp;

    let mut session = TelemetrySession::new();
    // A start exactly 61 seconds ago yields a ~61s duration (±1s scheduling).
    let shifted = Timestamp::now() - jiff::Span::new().seconds(61);
    session.started_at = shifted.strftime("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let duration = session.duration_secs();
    assert!(
        (60..=62).contains(&duration),
        "61s-old start must yield ~61s duration, got {duration}"
    );
}

#[test]
fn session_started_at_wire_format_is_rfc3339_and_falls_back_to_zero() {
    use jiff::Timestamp;

    let mut session = TelemetrySession::new();

    // Pin the exact wire format TelemetrySession::new emits: millisecond
    // precision, Zulu designator, valid RFC 3339 timestamp.
    let started = session.started_at.clone();
    assert_eq!(started.len(), 24, "started_at must be millisecond ISO form");
    assert!(started.ends_with('Z'), "started_at must end in Z");
    assert_eq!(&started[10..11], "T", "date and time must be T-separated");
    started
        .parse::<Timestamp>()
        .expect("started_at emitted by new() must be a valid RFC 3339 timestamp");

    // Unparseable started_at degrades to 0 rather than panicking.
    session.started_at = "definitely-not-a-timestamp".to_string();
    assert_eq!(
        session.duration_secs(),
        0,
        "unparseable started_at must fall back to zero duration"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Startup time + Timer utilities
// ═══════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn startup_duration_is_observable_monotonic_elapsed_time() {
    record_startup_time();
    let before = get_startup_duration_ms()
        .expect("record_startup_time must make the startup duration observable");
    thread::sleep(Duration::from_millis(25));
    let after =
        get_startup_duration_ms().expect("startup duration must remain observable after recording");
    assert!(
        after >= 25,
        "after a 25ms sleep the reported duration must be >= 25ms, got {after}"
    );
    assert!(
        after >= before,
        "reported startup duration must be monotonic ({before} -> {after})"
    );
    assert!(
        after < 120_000,
        "startup duration must reflect elapsed wall time, got {after}ms"
    );
}

#[test]
#[serial]
fn timer_reports_at_least_the_slept_duration_in_milliseconds() {
    let timer = Timer::new("cov10_probe");
    thread::sleep(Duration::from_millis(30));
    let ms = timer.elapsed_ms();
    assert!(
        ms >= 30,
        "Timer must report at least the slept 30ms, got {ms}ms"
    );
    assert!(ms < 5000, "Timer must not wildly overshoot, got {ms}ms");

    // finish() routes into the gated performance tracker; it must be safe
    // to call unconditionally (no license, no panic, no output).
    Timer::new("cov10_finish").finish();
}

#[test]
fn telemetry_fixture_isolation_preserves_parent_test_mode() {
    common::init_test_env();
    assert!(omg_lib::core::paths::test_mode());
    assert!(isolated_fixture::run_isolated_test(
        "opt_out_env_values_and_settings_file_gate_telemetry"
    ));
    assert!(omg_lib::core::paths::test_mode());
}
