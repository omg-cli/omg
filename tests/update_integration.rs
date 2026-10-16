//! Update Command Integration Tests
//!
//! End-to-end integration tests for the update command,
//! testing the full Elm Architecture workflow.
//!
//! Run: cargo test --test update_integration --features arch
//!
//! Commands use the shared isolated mock backend. Check mode is read-only.

#![expect(clippy::unwrap_used)]
#![expect(clippy::pedantic)]

pub mod common;

use common::*;

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK MODE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod check_mode_tests {
    use super::*;

    #[test]
    fn test_check_flag_is_recognized() {
        let result = run_omg(&["update", "--check"]);
        // --check is read-only: it must succeed in a working environment or
        // fail naming the privilege problem — never prompt, never dangle.
        assert_no_password_prompt(&result);
        if !result.success {
            let combined = result.combined_output();
            assert!(
                combined.contains("sudo")
                    || combined.contains("permission")
                    || combined.contains("root")
                    || combined.contains("turbo"),
                "--check failure must name its cause. Got:\n{combined}"
            );
        }
    }

    #[test]
    fn test_check_mode_succeeds() {
        let result = run_omg(&["update", "--check"]);
        assert_no_password_prompt(&result);

        assert!(
            result.success,
            "Check mode should succeed. Output:\n{}",
            result.combined_output()
        );
    }

    #[test]
    fn test_check_mode_reports_status() {
        let result = run_omg(&["update", "--check"]);
        assert_no_password_prompt(&result);

        let combined = result.combined_output();

        // Should report update status
        assert!(
            combined.contains("update")
                || combined.contains("up to date")
                || combined.contains("Found")
                || combined.contains("System")
                || combined.contains("✓"),
            "Check mode should report status. Got:\n{}",
            combined
        );
    }

    #[test]
    fn test_check_mode_with_yes_flag() {
        let result = run_omg(&["update", "--check", "--yes"]);
        assert_no_password_prompt(&result);

        assert!(
            result.success,
            "Check with --yes should succeed. Output:\n{}",
            result.combined_output()
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// NON-INTERACTIVE MODE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod non_interactive_tests {
    use super::*;

    #[test]
    fn test_yes_flag_without_tty() {
        let result = run_omg_with_env(&["update", "--yes"], &[("CI", "1")]);
        assert_runs_without_panic(&result);
        // --yes opts into non-interactive operation; complaining about
        // interactive terminals defeats its purpose.
        let combined = result.combined_output();
        assert!(
            !combined.contains("requires an interactive terminal"),
            "--yes must not demand a TTY. Got:\n{combined}"
        );
    }

    #[test]
    fn test_short_y_flag() {
        let result = run_omg(&["update", "-y"]);
        if result.success {
            assert!(!result.stdout.is_empty(), "-y success shows its work");
        } else {
            let combined = result.combined_output().to_lowercase();
            assert!(
                combined.contains("sudo")
                    || combined.contains("permission")
                    || combined.contains("root")
                    || combined.contains("development"),
                "-y failure must name the blocker. Got:\n{combined}"
            );
        }
    }

    #[test]
    fn test_ci_mode_with_yes() {
        let result = run_omg_with_env(
            &["update", "--yes"],
            &[("CI", "1"), ("OMG_NON_INTERACTIVE", "1")],
        );

        assert_runs_without_panic(&result);
        if !result.success {
            let combined = result.combined_output().to_lowercase();
            assert!(
                combined.contains("sudo")
                    || combined.contains("permission")
                    || combined.contains("root")
                    || combined.contains("development"),
                "CI --yes failure must name the blocker. Got:\n{combined}"
            );
        }
    }

    #[test]
    fn test_ci_mode_without_yes_fails_gracefully() {
        let result = run_omg_with_env(&["update"], &[("CI", "1")]);
        assert_no_password_prompt(&result);

        let combined = result.combined_output();

        if !result.success {
            // Pending updates + non-attended stdin must bail with the --yes
            // blocker (src/cli/packages/common.rs update_official_only:
            // `anyhow::bail!("Use --yes for non-interactive updates")`).
            assert!(
                combined.contains("--yes"),
                "non-interactive failure must name the --yes blocker. Got:\n{combined}"
            );
        } else {
            // Nothing to upgrade: the command must report the checked status
            // (print_up_to_date / "Found N update(s)") rather than exiting
            // silently.
            assert!(
                combined.contains("up to date") || combined.contains("Found"),
                "successful no-op update must report its status. Got:\n{combined}"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUDO INTEGRATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod sudo_integration_tests {
    use super::*;

    #[test]
    fn test_update_without_privileges_shows_helpful_error() {
        let result = run_omg(&["update", "--yes"]);
        assert_no_password_prompt(&result);

        let combined = result.combined_output();

        if !result.success {
            // Privilege/sync failure must name the blocker.
            assert!(
                combined.contains("sudo")
                    || combined.contains("root")
                    || combined.contains("privilege")
                    || combined.contains("permission")
                    || combined.contains("Elevating"),
                "failure must name the privilege blocker. Got:\n{combined}"
            );
        } else {
            // A successful run must still show the outcome of the check:
            // up-to-date notice, found-updates summary, or upgrade result.
            assert!(
                combined.contains("up to date")
                    || combined.contains("Found")
                    || combined.contains("Upgraded"),
                "successful update must report what happened. Got:\n{combined}"
            );
        }
    }

    #[test]
    fn test_check_mode_never_prompts_for_password() {
        // CRITICAL TEST: Check mode should NEVER prompt for password
        let result = run_omg(&["update", "--check"]);

        assert_no_password_prompt(&result);

        // Check for specific password prompt patterns
        let combined = result.combined_output();
        assert!(
            !combined.contains("[sudo]")
                && !combined.to_lowercase().contains("password for")
                && !combined.contains("Password:"),
            "Check mode should never prompt. Got:\n{combined}",
        );
    }

    #[test]
    fn test_n_flag_fallback_in_ci() {
        // CI-style environment: sudo -n fallback either succeeds and shows
        // its work, or fails naming the automation blocker — never dangles.
        let result = run_omg_with_env(&["update", "--yes"], &[("CI", "1")]);
        assert_no_password_prompt(&result);

        let combined = result.combined_output();

        if !result.success {
            assert!(
                combined.contains("NOPASSWD")
                    || combined.contains("automation")
                    || combined.contains("CI")
                    || combined.contains("sudo")
                    || combined.contains("root"),
                "CI failure must name the automation blocker. Got:\n{combined}"
            );
        } else {
            assert!(
                combined.contains("up to date")
                    || combined.contains("Found")
                    || combined.contains("Upgraded"),
                "CI success must report the update outcome. Got:\n{combined}"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ELM ARCHITECTURE WORKFLOW TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod elm_workflow_tests {
    use super::*;

    #[test]
    fn test_elm_model_initialization() {
        // Test that Elm model initializes correctly
        let result = run_omg(&["update", "--check"]);
        assert_runs_without_panic(&result);
    }

    #[test]
    fn test_elm_update_cycle() {
        // The Model-Update-View cycle completes and the View renders its
        // outcome on stdout (phase header, up-to-date notice, or findings).
        let result = run_omg(&["update", "--check"]);
        assert_runs_without_panic(&result);

        let combined = result.combined_output();
        assert!(
            !combined.contains("unwrap") && !combined.contains("expect"),
            "Elm cycle should not leak debug helpers into output. Got:\n{combined}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ERROR HANDLING TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod error_handling_tests {
    use super::*;

    #[test]
    fn test_invalid_flag_rejected() {
        let result = run_omg(&["update", "--invalid-flag-xyz"]);

        assert!(!result.success, "Invalid flag should fail");

        let combined = result.combined_output();
        assert!(
            combined.contains("error")
                || combined.contains("unrecognized")
                || combined.contains("unknown"),
            "Should report error for invalid flag. Got:\n{}",
            combined
        );
    }

    #[test]
    fn test_extra_positional_arguments_rejected() {
        // clap pins Update as option-only (src/cli/args.rs:91-108 has no
        // positionals), so stray words after flags are a usage error with a
        // named offender — never silently ignored.
        let result = run_omg(&["update", "--check", "extra", "args"]);

        assert!(!result.success, "stray positional args must be rejected");
        assert!(
            result.stderr.contains("unexpected argument"),
            "clap should name the unexpected argument. stderr:\n{}",
            result.stderr
        );
    }

    #[test]
    fn test_missing_daemon_fallback() {
        // We set OMG_DISABLE_DAEMON=1 in run_omg
        let result = run_omg(&["update", "--check"]);
        assert_runs_without_panic(&result);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// OUTPUT FORMAT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod output_format_tests {
    use super::*;
    use std::env;

    #[test]
    fn test_check_mode_writes_status_to_stdout() {
        // Check mode renders its human-readable status on stdout, not only
        // diagnostics on stderr.
        let result = run_omg(&["update", "--check"]);
        assert_runs_without_panic(&result);

        assert!(
            !result.stdout.is_empty(),
            "--check must write its status to stdout\nstderr: {}",
            result.stderr
        );
    }

    #[test]
    fn test_output_does_not_leak_paths() {
        let result = run_omg(&["update", "--check"]);

        let combined = result.combined_output();

        // Should not expose sensitive paths
        assert!(
            !combined.contains("/home/")
                && !combined.contains(env::var("HOME").unwrap_or_default().as_str()),
            "Should not expose home directory path"
        );
    }

    // test_error_messages_are_user_friendly was merged into
    // error_handling_tests::test_invalid_flag_rejected (identical contract).
}

// ═══════════════════════════════════════════════════════════════════════════════
// REGRESSION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod regression_tests {
    use super::*;

    #[test]
    fn regression_sudo_password_prompt_bug() {
        // Regression test for the sudo password prompt bug
        // The bug was: update would prompt for password even in check mode
        let result = run_omg(&["update", "--check"]);

        assert_no_password_prompt(&result);
    }

    // regression_n_flag_fallback_detection was merged into
    // sudo_integration_tests::test_n_flag_fallback_in_ci (same command and
    // contract, now asserted on both paths).

    #[test]
    fn regression_elm_fallback_on_error() {
        // Test that Elm UI falls back gracefully on error
        let result = run_omg(&["update", "--check"]);
        assert_runs_without_panic(&result);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONCURRENT ACCESS TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod concurrency_tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_concurrent_check_commands() {
        // Test that multiple check commands don't interfere
        let handles: Vec<_> = (0..5)
            .map(|_| thread::spawn(|| run_omg(&["update", "--check"])))
            .collect();

        for handle in handles {
            let result = handle.join().unwrap();
            assert_runs_without_panic(&result);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod security_tests {
    use super::*;

    #[test]
    fn test_no_command_injection() {
        let result = run_omg(&["update", "--check", ";", "rm", "-rf", "/"]);
        assert_runs_without_panic(&result);
    }

    #[test]
    fn test_no_path_traversal_in_args() {
        let result = run_omg(&["update", "--check", "../../../etc/passwd"]);

        // Should not expose system files
        let combined = result.combined_output();
        assert!(
            !combined.contains("root:") && !combined.contains("/bin/bash"),
            "Should not expose system files"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn completion_oracle_rejects_abnormal_process_results() {
    let cases = [
        ("timeout", -1, "", "[test harness timeout]"),
        ("signal", -1, "terminated", ""),
        ("panic exit", 101, "failed", ""),
        ("stdout panic", 0, "panicked at fixture", ""),
        ("stderr panic", 1, "", "panicked at fixture"),
        ("success", 0, "completed", ""),
        ("reported failure", 1, "", "package not found"),
        ("usage error", 2, "", "Usage: omg update"),
        ("empty output", 0, "", ""),
        ("timeout with zero status", 0, "", "[test harness timeout]"),
    ];
    let observed: Vec<_> = cases
        .into_iter()
        .map(|(name, exit_code, stdout, stderr)| {
            let result = CommandResult {
                success: exit_code == 0,
                exit_code,
                stdout: stdout.to_string(),
                stderr: stderr.to_string(),
            };
            let accepted = std::panic::catch_unwind(|| assert_runs_without_panic(&result)).is_ok();
            (name, accepted)
        })
        .collect();
    assert_eq!(
        observed,
        vec![
            ("timeout", false),
            ("signal", false),
            ("panic exit", false),
            ("stdout panic", false),
            ("stderr panic", false),
            ("success", true),
            ("reported failure", true),
            ("usage error", true),
            ("empty output", false),
            ("timeout with zero status", false),
        ]
    );
}

fn assert_runs_without_panic(result: &CommandResult) {
    common::assertions::assert_process_completed(result);
    assert!(
        !result.stdout.is_empty() || !result.stderr.is_empty(),
        "command produced no output at all"
    );
}

fn assert_no_password_prompt(result: &CommandResult) {
    common::assertions::assert_process_completed(result);
    let combined = result.combined_output();
    assert!(
        !combined.contains("[sudo]")
            && !combined.contains("password for")
            && !combined.contains("Password:"),
        "Should not prompt for password. Got:\n{}",
        combined
    );
}
