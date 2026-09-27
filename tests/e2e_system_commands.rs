//! End-to-End Tests for System Commands
//!
//! Comprehensive e2e tests for system management and utility commands:
//! - doctor: System diagnostics
//! - config: Configuration management
//! - daemon: Daemon operations
//! - history: Transaction history
//! - stats/metrics: Usage statistics
//! - completions: Shell completion generation
//!
//! These tests validate the complete user experience for system operations.

#![expect(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]

pub mod common;

use common::*;

// ═══════════════════════════════════════════════════════════════════════════════
// DOCTOR COMMAND E2E TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// In test mode, Doctor prints the health banner and a Git capability verdict.
#[test]
fn test_doctor_runs_diagnostics() {
    init_test_env();

    let result = run_omg(&["doctor"]);

    result.assert_success();

    let output = result.stdout;
    assert!(
        output.contains("OMG Doctor"),
        "Missing doctor header: {output}"
    );
    assert!(
        output.contains("Checking system health"),
        "Missing health-check banner: {output}"
    );
}

// Git is an optional capability. Host curl and tar are not OMG dependencies.
#[test]
fn test_doctor_checks_environment() {
    init_test_env();

    let result = run_omg(&["doctor"]);

    result.assert_success();

    let output = result.stdout;
    assert!(output.contains("Optional tool available: git"), "{output}");
    for unused in ["dependency: curl", "dependency: tar"] {
        assert!(
            !output.contains(unused),
            "Doctor invented {unused}: {output}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIG COMMAND E2E TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// Contract pinned at src/cli/config.rs:138-160: `config list` always prints the
// "OMG Configuration" header followed by key/value lines including
// "telemetry.enabled = <bool>".
#[test]
fn test_config_list_shows_settings() {
    init_test_env();

    let result = run_omg(&["config", "list"]);

    result.assert_success();

    let output = result.stdout;
    assert!(
        output.contains("OMG Configuration"),
        "Missing config header: {output}"
    );
    assert!(
        output.contains("telemetry.enabled ="),
        "Config list must show telemetry.enabled: {output}"
    );
}

#[test]
fn test_config_get_specific_value() {
    init_test_env();

    let result = run_omg(&["config", "get", "some.key"]);

    let output = result.combined_output();
    assert!(!result.success, "Unknown keys must fail");
    assert!(
        output.contains("Unknown config key"),
        "Should identify the invalid key: {output}"
    );
}

// Contract pinned at src/cli/config.rs:43-136 and 13-39: `config set` accepts
// the whitelisted key `telemetry.enabled`, persists it via Settings::save, and
// `config get telemetry.enabled` prints exactly the stored boolean. Use true
// rather than the default false so a lost write cannot pass. The runner keeps
// telemetry transport disabled separately with OMG_DISABLE_TELEMETRY=1.
#[test]
fn test_config_set_and_get() {
    init_test_env();

    let project = TestProject::new();

    let default_result = project.run(&["config", "get", "telemetry.enabled"]);
    default_result.assert_success();
    assert_eq!(default_result.stdout.trim(), "false");

    let set_result = project.run(&["config", "set", "telemetry.enabled", "true"]);
    set_result.assert_success();

    let get_result = project.run(&["config", "get", "telemetry.enabled"]);
    get_result.assert_success();
    assert_eq!(
        get_result.stdout.trim(),
        "true",
        "config get must return the persisted non-default value"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// DAEMON COMMAND E2E TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// Contract pinned at src/cli/daemon_status.rs:17-90: on Unix, `daemon-status`
// always exits 0, prints the "OMG Daemon Status" header, and reports one of the
// concrete socket states (socket not found / failed to connect / running).
#[test]
fn test_daemon_status_shows_state() {
    init_test_env();

    let result = run_omg(&["daemon-status"]);

    result.assert_success();
    result.assert_stdout_contains("Daemon");
    let output = result.stdout;
    assert!(
        output.contains("socket not found")
            || output.contains("Failed to connect")
            || output.contains("Daemon is running"),
        "Must report a concrete daemon state: {output}"
    );
}

#[test]
fn test_daemon_help() {
    init_test_env();

    let result = run_omg(&["daemon", "--help"]);

    result.assert_success();
    result.assert_stdout_contains("daemon");
}

// ═══════════════════════════════════════════════════════════════════════════════
// HISTORY COMMAND E2E TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// Contract pinned at src/cli/commands.rs:845-857: `history` always exits 0 and
// prints the header "Transaction History (last <limit>)"; each run uses a fresh
// isolated data dir, so the empty-state line must follow.
#[test]
fn test_history_shows_transactions() {
    init_test_env();

    let result = run_omg(&["history"]);

    result.assert_success();
    let output = result.stdout;
    assert!(
        output.contains("Transaction History (last 20)"),
        "Missing default header: {output}"
    );
    assert!(
        output.contains("No matching transactions found"),
        "Fresh data dir must show empty state: {output}"
    );
}

// The --limit flag must be reflected verbatim in the rendered header.
#[test]
fn test_history_with_limit() {
    init_test_env();

    let result = run_omg(&["history", "--limit", "10"]);

    result.assert_success();
    result.assert_stdout_contains("Transaction History (last 10)");
}

// --json must emit machine-readable output: a syntactically valid JSON array.
#[test]
fn test_history_json_output() {
    init_test_env();

    let result = run_omg(&["history", "--json"]);

    result.assert_success();
    let parsed: serde_json::Value =
        serde_json::from_str(result.stdout.trim()).expect("history --json must emit valid JSON");
    assert!(
        parsed.is_array(),
        "history --json must emit a JSON array, got: {parsed}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// ROLLBACK COMMAND E2E TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_rollback_help() {
    init_test_env();

    let result = run_omg(&["rollback", "--help"]);

    result.assert_success();
    result.assert_stdout_contains("rollback");
}

// Contract pinned at src/cli/commands.rs:1055-1060: interactive rollback with
// an empty transaction log bails with "No history entries available for rollback"
// instead of prompting. Fresh isolated data dir guarantees the empty case.
#[test]
fn test_rollback_without_history() {
    init_test_env();

    let result = run_omg(&["rollback"]);

    result.assert_failure();
    result.assert_stderr_contains("No history entries available for rollback");
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATS AND METRICS E2E TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// Contract pinned at src/cli/commands.rs:1277-1315: `stats` always exits 0 and
// prints the "OMG Usage Statistics" header plus the "Total Commands:" counter.
#[test]
fn test_stats_shows_usage() {
    init_test_env();

    let result = run_omg(&["stats"]);

    result.assert_success();
    let output = result.stdout;
    assert!(
        output.contains("OMG Usage Statistics"),
        "Missing stats header: {output}"
    );
    assert!(
        output.contains("Total Commands:"),
        "Missing command counter: {output}"
    );
}

// --json must emit machine-readable usage statistics with the documented fields.
#[test]
fn test_stats_json_output() {
    init_test_env();

    let result = run_omg(&["stats", "--json"]);

    result.assert_success();
    let parsed: serde_json::Value =
        serde_json::from_str(result.stdout.trim()).expect("stats --json must emit valid JSON");
    assert!(
        parsed
            .get("total_commands")
            .is_some_and(serde_json::Value::is_u64),
        "stats --json must expose total_commands as a number, got: {parsed}"
    );
}

#[test]
fn test_metrics_command_exists() {
    init_test_env();

    let result = run_omg(&["metrics", "--help"]);

    // Should have metrics command
    result.assert_success();
    result.assert_stdout_contains("metric");
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPLETIONS E2E TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_completions_bash() {
    init_test_env();

    // --stdout prints the script instead of installing into the real home
    // directory; contract is the embedded script's entry point
    // (src/hooks/completions/bash.sh:1).
    let result = run_omg(&["completions", "bash", "--stdout"]);

    result.assert_success();
    result.assert_stdout_contains("_omg_completions()");
}

#[test]
fn test_completions_zsh() {
    init_test_env();

    // --stdout prints the script (src/hooks/completions/zsh.zsh:1 starts
    // with the #compdef directive).
    let result = run_omg(&["completions", "zsh", "--stdout"]);

    result.assert_success();
    result.assert_stdout_contains("#compdef omg");
}

#[test]
fn test_completions_fish() {
    init_test_env();

    // --stdout prints the script (src/hooks/completions/fish.fish:1 defines
    // __omg_dynamic_complete).
    let result = run_omg(&["completions", "fish", "--stdout"]);

    result.assert_success();
    result.assert_stdout_contains("__omg_dynamic_complete");
}

#[test]
fn test_completions_powershell() {
    init_test_env();

    // --stdout prints the clap_complete-generated PowerShell registration.
    let result = run_omg(&["completions", "powershell", "--stdout"]);

    result.assert_success();
    result.assert_stdout_contains("Register-ArgumentCompleter");
    result.assert_stdout_contains("'omg'");
}

#[test]
fn test_completions_invalid_shell() {
    init_test_env();

    let result = run_omg(&["completions", "invalid-shell"]);

    result.assert_failure();

    let output = result.combined_output();
    assert!(
        output.contains("invalid") || output.contains("value"),
        "Should reject invalid shell"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// VERSION AND HELP E2E TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_version_flag() {
    init_test_env();

    let result = run_omg(&["--version"]);

    result.assert_success();

    let output = result.stdout;
    assert!(
        output.contains("omg") && output.contains("0.1"),
        "Should show version"
    );
}

#[test]
fn test_help_flag() {
    init_test_env();

    let result = run_omg(&["--help"]);

    result.assert_success();

    let output = result.stdout;
    assert!(
        output.contains("Usage") || output.contains("COMMANDS"),
        "Should show help"
    );
}

#[test]
fn test_help_for_subcommand() {
    init_test_env();

    let result = run_omg(&["install", "--help"]);

    result.assert_success();
    result.assert_stdout_contains("install");
}

// ═══════════════════════════════════════════════════════════════════════════════
// SELF-UPDATE E2E TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// WRONG-CONTRACT FIX: `self-update` has no `--check` flag (src/cli/args.rs:484-491:
// only --force/--version), so the old invocation was rejected by clap before any
// network call. Replacement pins a real, network-free guarantee from
// src/cli/self_update.rs:53-62: requesting an older version must be refused by
// downgrade protection without downloading anything.
#[test]
fn test_self_update_downgrade_protection() {
    init_test_env();

    let result = run_omg(&["self-update", "--version", "0.0.1"]);

    result.assert_failure();
    result.assert_stderr_contains("Refusing to downgrade");
}

#[test]
fn test_self_update_help() {
    init_test_env();

    let result = run_omg(&["self-update", "--help"]);

    result.assert_success();
    result.assert_stdout_contains("update");
}

// ═══════════════════════════════════════════════════════════════════════════════
// INIT COMMAND E2E TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_init_help() {
    init_test_env();

    let result = run_omg(&["init", "--help"]);

    result.assert_success();
    result.assert_stdout_contains("init");
}

#[test]
fn test_init_in_project() {
    init_test_env();

    let project = TestProject::new();

    let shell_config = project.home_dir.path().join(".bashrc");
    assert!(
        !shell_config.exists(),
        "Test home must start without a bashrc"
    );

    let result = project.run_with_env(&["init"], &[("SHELL", "/bin/bash")]);

    // Null stdin selects run_defaults without prompting or touching host HOME.
    result.assert_success();
    result.assert_stdout_contains("Setup complete!");
    let content = std::fs::read_to_string(&shell_config)
        .expect("init must write shell configuration inside the isolated HOME");
    assert!(content.contains(r#"eval "$(omg hook bash)""#), "{content}");
    assert!(!project.path().join(".bashrc").exists());

    // A second invocation must see the same home and leave the hook unchanged.
    let repeated = project.run_with_env(&["init"], &[("SHELL", "/bin/bash")]);
    repeated.assert_success();
    repeated.assert_stdout_contains("already installed");
    assert_eq!(std::fs::read_to_string(&shell_config).unwrap(), content);
}

// ═══════════════════════════════════════════════════════════════════════════════
// GENERATE-MAN E2E TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_generate_man_produces_pages() {
    init_test_env();

    let project = TestProject::new();
    let output_dir = project.create_dir("man");

    let result = project.run(&["generate-man", "--output", output_dir.to_str().unwrap()]);

    // FALSIFIABLE: man pages must actually be written to the target dir.
    // The old `success || contains("man")` passed whenever the word "man"
    // appeared anywhere in any output.
    result.assert_success();
    let generated: Vec<_> = std::fs::read_dir(&output_dir)
        .expect("man output dir must exist")
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        !generated.is_empty(),
        "generate-man must write at least one file"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATUS COMMAND E2E TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_status_shows_system_state() {
    init_test_env();

    let result = run_omg(&["status"]);

    result.assert_success();

    let output = result.stdout.to_lowercase();
    assert!(
        output.lines().any(|line| line.trim() == "status"),
        "Status must render its heading: {output}"
    );
    assert!(output.contains("packages installed"), "{output}");
    assert!(!output.contains("tip:"), "{output}");
}

#[test]
fn test_status_json_output() {
    init_test_env();

    let result = run_omg(&["status", "--json"]);

    // Contract pinned at src/cli/packages/status.rs:48-100: --json must succeed
    // and emit the StatusJson schema on every run.
    result.assert_success();
    let parsed: serde_json::Value =
        serde_json::from_str(result.stdout.trim()).expect("status --json must emit valid JSON");
    for field in [
        "total_packages",
        "explicit_packages",
        "orphan_packages",
        "updates_available",
        "query_time_ms",
    ] {
        assert!(
            parsed.get(field).is_some(),
            "status --json must expose '{field}', got: {parsed}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MIGRATE COMMAND E2E TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_migrate_help() {
    init_test_env();

    let result = run_omg(&["migrate", "--help"]);

    result.assert_success();
    result.assert_stdout_contains("migrate");
}

// WRONG-CONTRACT FIX: there is no `brew` subcommand — MigrateCommands only has
// Export/Import (src/cli/args.rs:1200-1215). Pin the clap rejection explicitly.
#[test]
fn test_migrate_rejects_unknown_subcommand() {
    init_test_env();

    let result = run_omg(&["migrate", "brew", "--dry-run"]);

    result.assert_failure();
    let output = result.combined_output();
    assert!(
        output.contains("unrecognized subcommand 'brew'"),
        "Unknown migrate subcommand must be named in the error: {output}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// ERROR HANDLING E2E TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_no_command_shows_help() {
    init_test_env();

    let result = run_omg(&[]);

    // clap requires a subcommand: bare `omg` prints help text and exits 2
    // (observed contract of the derive config in src/cli/args.rs).
    result.assert_failure();
    let output = result.combined_output();
    assert!(
        output.contains("Usage:"),
        "No-command run must print usage help: {output}"
    );
}

#[test]
fn test_invalid_command() {
    init_test_env();

    let result = run_omg(&["invalid-command-xyz"]);

    result.assert_failure();

    let output = result.combined_output();
    assert!(
        output.contains("unrecognized") || output.contains("invalid"),
        "Should show error for invalid command"
    );
}

#[test]
fn test_invalid_global_flag() {
    init_test_env();

    let result = run_omg(&["--invalid-flag", "search", "test"]);

    result.assert_failure();

    let output = result.combined_output();
    assert!(
        output.contains("unexpected") || output.contains("invalid"),
        "Should show error for invalid flag"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// INTEGRATED WORKFLOW TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_workflow_doctor_then_status() {
    init_test_env();

    // Run doctor to check system
    let doctor_result = run_omg(&["doctor"]);
    doctor_result.assert_success();

    // Then check status
    let status_result = run_omg(&["status"]);
    status_result.assert_success();
}

#[test]
fn test_workflow_config_set_and_list() {
    init_test_env();

    let project = TestProject::new();

    // Persist a non-default value; transport remains disabled by the runner.
    let set_result = project.run(&["config", "set", "telemetry.enabled", "true"]);
    set_result.assert_success();

    let list_result = project.run(&["config", "list"]);
    list_result.assert_success();

    assert!(
        list_result.stdout.contains("telemetry.enabled = true"),
        "Config list must reflect the persisted value: {}",
        list_result.stdout
    );
}

#[test]
fn test_workflow_history_and_stats() {
    init_test_env();

    let history_result = run_omg(&["history"]);
    history_result.assert_success();
    history_result.assert_stdout_contains("Transaction History");

    let stats_result = run_omg(&["stats"]);
    stats_result.assert_success();
    stats_result.assert_stdout_contains("OMG Usage Statistics");
}
