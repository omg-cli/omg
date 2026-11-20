#![cfg(feature = "arch")]
#![expect(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]
//! Comprehensive Arch Linux Integration Tests
//!
//! Enterprise-grade test coverage for Arch Linux package management.
//!
//! Run: cargo test --test `arch_tests` --features arch
//! With system tests: `OMG_RUN_SYSTEM_TESTS=1` cargo test --test `arch_tests` --features arch
//!
//! Note: System tests require real package operations and will modify your system!
//! Only run these tests in disposable containers or development environments.

pub mod common;
pub mod platform_semantics;

use common::assertions::*;
use common::fixtures::*;
use common::*;
use platform_semantics::{assert_no_debian_terms, assert_no_fedora_terms, assert_no_macos_terms};

fn assert_arch_platform_purity(result: &CommandResult, context: &str) {
    let output = result.combined_output();
    assert_no_debian_terms(&output, context);
    assert_no_fedora_terms(&output, context);
    assert_no_macos_terms(&output, context);
}

// ═══════════════════════════════════════════════════════════════════════════════
// PACMAN INTEGRATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod pacman_integration {
    use super::*;

    #[test]
    fn test_search_official_repos() {
        require_system_tests!();
        require_arch!();

        let result = run_omg(&["search", "firefox"]);
        result.assert_success();
        assert_search_results(&result, &["firefox"]);
        assert_arch_platform_purity(&result, "Arch search official repos");
    }

    #[test]
    fn test_search_core_packages() {
        require_system_tests!();
        require_arch!();

        // Core packages should be found
        for pkg in &["linux", "pacman", "glibc", "bash"] {
            let result = run_omg(&["search", pkg]);
            result.assert_success();
            assert!(result.stdout_contains(pkg), "Should find {pkg}");
            assert_arch_platform_purity(&result, "Arch search core packages");
        }
    }

    #[test]
    fn test_search_extra_packages() {
        require_system_tests!();
        require_arch!();

        for pkg in &["git", "vim", "python", "nodejs"] {
            let result = run_omg(&["search", pkg]);
            result.assert_success();
            assert_arch_platform_purity(&result, "Arch search extra packages");
        }
    }

    #[test]
    fn test_search_rejects_regex_metacharacters() {
        require_system_tests!();
        require_arch!();

        let result = run_omg(&["search", "^linux$"]);
        result.assert_failure();
        assert!(
            result.combined_output().contains("shell metacharacters"),
            "regex metacharacters must be rejected at the search boundary"
        );
        assert_arch_platform_purity(&result, "Arch search regex");
    }

    #[test]
    fn test_info_installed_package() {
        require_system_tests!();
        require_arch!();

        let result = run_omg(&["info", "pacman"]);
        result.assert_success();
        assert_package_info(&result, "pacman");
        assert!(
            result.stdout_contains("core") || result.stdout_contains("Repository"),
            "Should show repository"
        );
        assert_arch_platform_purity(&result, "Arch info installed package");
    }

    #[test]
    fn test_info_not_installed_package() {
        require_system_tests!();
        require_arch!();

        // A package that exists but might not be installed.
        let result = run_omg(&["info", "firefox"]);
        result.assert_success();
        assert_package_info(&result, "firefox");
    }

    #[test]
    fn test_info_nonexistent_package() {
        require_system_tests!();
        require_arch!();

        let result = run_omg(&["info", "this-package-definitely-does-not-exist-12345"]);
        result.assert_failure();
        assert!(
            result.combined_output().contains("not found"),
            "missing package failure must name its cause"
        );
    }

    #[test]
    fn test_explicit_packages_list() {
        require_system_tests!();
        require_arch!();

        let result = run_omg(&["explicit"]);
        result.assert_success();
        // On Arch, there should be at least some explicit packages
        assert!(
            !result.stdout.trim().is_empty(),
            "explicit must list at least one package on a system-test host"
        );
        assert_arch_platform_purity(&result, "Arch explicit list");
    }

    #[test]
    fn test_sync_databases() {
        require_system_tests!();
        require_destructive_tests!();
        require_arch!();

        let result = run_omg(&["sync"]);
        // May require root, so check for permission error OR success
        assert!(
            result.success
                || result.stderr_contains("permission")
                || result.stderr_contains("root"),
            "Should sync or report permission issue"
        );
    }

    #[test]
    fn test_update_check() {
        require_system_tests!();
        require_arch!();

        let result = run_omg(&["update", "--check"]);
        result.assert_success();
        assert_arch_platform_purity(&result, "Arch update check");
    }

    #[test]
    fn test_update_check_with_mock_updates() {
        let project = TestProject::new();

        project
            .mock_install("firefox", "122.0")
            .expect("seed installed firefox");
        project
            .mock_available("firefox", "123.0")
            .expect("seed available firefox");

        let result = project.run(&["update", "--check"]);
        result.assert_success();

        assert!(
            result.stdout_contains("firefox"),
            "update check must list firefox, got:\n{}",
            result.stdout
        );
        // print_update_summary lists each update as 'name old → new', so the
        // target version must appear too.
        assert!(
            result.stdout_contains("123.0"),
            "update check must show the available version, got:\n{}",
            result.stdout
        );
        assert_arch_platform_purity(&result, "Arch mock update check");
    }

    #[test]
    fn test_update_check_no_updates_when_current() {
        let project = TestProject::new();
        project.with_security_policy(policies::STRICT_POLICY);

        project
            .mock_install("firefox", "123.0")
            .expect("seed installed firefox");
        project
            .mock_available("firefox", "123.0")
            .expect("seed available firefox");

        let result = project.run(&["update", "--check"]);
        result.assert_success();

        result.assert_stdout_contains("up to date");
        assert_arch_platform_purity(&result, "Arch mock up-to-date check");
    }

    #[test]
    fn test_clean_options() {
        require_arch!();

        // Test help shows all options
        let result = run_omg(&["clean", "--help"]);
        result.assert_success();
        assert!(
            result.stdout_contains("orphans"),
            "Should have orphans option"
        );
        assert!(result.stdout_contains("cache"), "Should have cache option");
        assert_arch_platform_purity(&result, "Arch clean help");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUR INTEGRATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod aur_integration {
    use super::*;

    #[test]
    fn test_search_aur_packages() {
        require_network_tests!();
        require_arch!();

        // yay is a popular AUR package: a match prints its name in the
        // results; if nothing matched anywhere Components::no_results still
        // echoes the query. Either way the command must have processed 'yay'.
        let result = run_omg(&["search", "yay"]);
        result.assert_success();
        assert!(
            result.stdout_contains("yay"),
            "AUR search must process 'yay', got:\n{}",
            result.stdout
        );
    }

    #[test]
    fn test_search_aur_detailed() {
        require_network_tests!();
        require_arch!();

        // --detailed must run the same search successfully and still account
        // for the query (results or echoed no-results message).
        let result = run_omg(&["search", "yay", "--detailed"]);
        result.assert_success();
        assert!(
            result.stdout_contains("yay"),
            "detailed AUR search must process 'yay', got:\n{}",
            result.stdout
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ALPM DIRECT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod alpm_direct {
    use super::*;

    #[test]
    fn test_alpm_database_access() {
        require_system_tests!();
        require_arch!();

        // Status uses ALPM directly for speed
        let result = run_omg(&["status"]);
        result.assert_success();
        assert_arch_platform_purity(&result, "Arch ALPM database access");
    }

    #[test]
    fn test_alpm_local_db_query() {
        require_system_tests!();
        require_arch!();

        // Explicit uses the ALPM local database; --count must print a bare number.
        let result = run_omg(&["explicit", "--count"]);
        result.assert_success();
        let count: Result<u32, _> = result.stdout.trim().parse();
        assert!(
            count.is_ok(),
            "--count must print a number, got:\n{}",
            result.stdout
        );
        assert_arch_platform_purity(&result, "Arch ALPM local db query");
    }

    #[test]
    fn test_alpm_sync_db_query() {
        require_system_tests!();
        require_arch!();

        // Search uses ALPM sync databases
        let result = run_omg(&["search", "pacman"]);
        result.assert_success();
        assert!(result.stdout_contains("pacman"), "Should find pacman");
        assert_arch_platform_purity(&result, "Arch ALPM sync db query");
    }

    #[test]
    fn test_alpm_dependency_resolution() {
        require_system_tests!();
        require_arch!();

        // Why command uses ALPM for dependency tracking.
        let result = run_omg(&["why", "glibc"]);
        result.assert_success();
        assert!(
            result.combined_output().contains("glibc"),
            "dependency report must name glibc"
        );
    }

    #[test]
    fn test_alpm_size_calculation() {
        require_system_tests!();
        require_arch!();

        let result = run_omg(&["size"]);
        result.assert_success();
        // Should show disk usage
        assert!(
            result.stdout_contains("MB")
                || result.stdout_contains("GB")
                || result.stdout_contains("KiB"),
            "Should show sizes"
        );
        assert_arch_platform_purity(&result, "Arch ALPM size calculation");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// NEW FEATURE TESTS (why, pin, outdated, etc.)
// ═══════════════════════════════════════════════════════════════════════════════

mod new_features {
    use super::*;

    #[test]
    fn test_why_command() {
        require_system_tests!();
        require_arch!();

        let result = run_omg(&["why", "bash"]);
        result.assert_success();
        result.assert_stdout_contains("bash");
    }

    #[test]
    fn test_why_reverse_dependencies() {
        require_system_tests!();
        require_arch!();

        let result = run_omg(&["why", "glibc", "--reverse"]);
        result.assert_success();
        assert!(
            result.combined_output().contains("glibc"),
            "reverse dependency report must name glibc"
        );
    }

    #[test]
    fn test_outdated_command() {
        require_system_tests!();
        require_arch!();

        // `cli::outdated` exits successfully unless the backend errors; after
        // success it must report either the up-to-date state or the table.
        let result = run_omg(&["outdated"]);
        result.assert_success();
        let output = result.combined_output();
        assert!(
            output.contains("up to date") || output.contains("Available Updates"),
            "outdated must list updates or report none, got: {output}"
        );
    }

    #[test]
    fn test_outdated_json_output() {
        require_system_tests!();
        require_arch!();

        // `cli::outdated --json` prints `[]` when current and otherwise a JSON
        // array of updates, so stdout must parse as an array on every path.
        let result = run_omg(&["outdated", "--json"]);
        result.assert_success();
        let value: serde_json::Value = serde_json::from_str(result.stdout.trim())
            .expect("outdated --json must print valid JSON");
        assert!(
            value.is_array(),
            "outdated --json must print an array, got: {value}"
        );
    }

    #[test]
    fn test_size_with_limit() {
        require_system_tests!();
        require_arch!();

        let result = run_omg(&["size", "--limit", "10"]);
        result.assert_success();
        assert_arch_platform_purity(&result, "Arch size with limit");
    }

    #[test]
    fn test_size_tree() {
        require_system_tests!();
        require_arch!();

        let result = run_omg(&["size", "--tree", "pacman"]);
        result.assert_success();
        result.assert_stdout_contains("pacman");
    }

    #[test]
    fn test_blame_command() {
        require_system_tests!();
        require_arch!();

        let result = run_omg(&["blame", "pacman"]);
        result.assert_success();
        assert!(
            result.combined_output().contains("pacman"),
            "package history report must name pacman"
        );
    }

    #[test]
    fn test_diff_command() {
        let project = TestProject::new();
        project.run(&["env", "capture"]).assert_success();

        let result = project.run(&["diff", "omg.lock"]);
        result.assert_success();
        assert!(
            result.combined_output().contains("Environment"),
            "environment diff must render its report"
        );
    }

    #[test]
    fn test_snapshot_create() {
        let project = TestProject::new();
        let result = project.run(&["snapshot", "create"]);
        result.assert_success();
        assert!(
            project
                .data_dir
                .path()
                .join("snapshots/index.json")
                .exists(),
            "snapshot create must update the snapshot index"
        );
    }

    #[test]
    fn test_snapshot_list() {
        let project = TestProject::new();
        let result = project.run(&["snapshot", "list"]);
        result.assert_success();
    }

    #[test]
    fn test_ci_init_github() {
        let project = TestProject::new();
        let result = project.run(&["ci", "init", "github"]);
        result.assert_success();
        // The GitHub branch of `cli::ci::write_config_file` writes this path.
        assert!(
            project.file_exists(".github/workflows/ci.yml"),
            "ci init github must generate the workflow file",
        );
    }

    #[test]
    fn test_migrate_export() {
        let project = TestProject::new();
        let result = project.run(&["migrate", "export", "--output", "manifest.json"]);
        result.assert_success();
        // Export atomically writes the requested path as JSON.
        let content = project
            .read_file("manifest.json")
            .expect("migrate export must write its output file on success");
        let manifest: serde_json::Value =
            serde_json::from_str(&content).expect("migration manifest must be valid JSON");
        assert!(
            manifest.get("version").is_some(),
            "manifest must carry a format version, got: {manifest}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod security {
    use super::*;

    #[test]
    fn test_audit_scan() {
        require_system_tests!();
        require_arch!();

        let result = run_omg(&["audit", "scan"]);
        assert_audit_scan_completed(&result);
    }

    #[test]
    fn test_audit_sbom_generation() {
        let project = TestProject::new();
        project
            .mock_install("omg-sbom-fixture", "1.2.3")
            .expect("seed the installed package inventory");
        project
            .run(&["audit", "sbom", "--inventory-only", "--output", "sbom.json"])
            .assert_success();
        let content = project
            .read_file("sbom.json")
            .expect("audit sbom must write its output file");
        let sbom: serde_json::Value = serde_json::from_str(&content).expect("valid CycloneDX JSON");
        assert_eq!(sbom["bomFormat"], "CycloneDX");
        assert_eq!(sbom["specVersion"], "1.5");
        assert!(
            sbom["components"]
                .as_array()
                .is_some_and(|components| components.iter().any(|component| {
                    component["name"] == "omg-sbom-fixture" && component["version"] == "1.2.3"
                })),
            "SBOM must contain the seeded package and version"
        );
        assert!(
            sbom["metadata"]["component"]["properties"]
                .as_array()
                .is_some_and(|properties| properties.iter().any(|property| {
                    property["name"] == "omg:advisory-scan" && property["value"] == "not-performed"
                })),
            "inventory-only SBOM must disclose skipped advisory matching"
        );
    }

    #[test]
    fn test_audit_secrets_scan() {
        let secret = "fixture-secret-value";
        let project = TestProject::new();
        project.create_file("config.txt", &format!("password={secret}\n"));

        let result = project.run(&["audit", "secrets"]);
        result.assert_success();
        assert!(result.stdout_contains("Found 1 potential secrets"));
        assert!(result.stdout_contains("config.txt:1"));
        assert!(
            !result.contains(secret),
            "the finding must redact the fixture value"
        );
    }

    #[test]
    fn test_audit_policy_enforcement() {
        let project = TestProject::new();
        project.with_security_policy(policies::STRICT_POLICY);

        // The helper now writes to the real load path
        // (`$OMG_CONFIG_DIR/policy.toml`), so `audit policy` must reflect the
        // injected policy, not the built-in default: strict disables AUR,
        // requires PGP, and bans telnet/ftp.
        let result = project.run(&["audit", "policy"]);
        result.assert_success();
        assert!(
            result.stdout_contains("Security Policy Status")
                && result.stdout_contains("Minimum Grade:")
                && result.stdout_contains("VERIFIED")
                && result.stdout_contains("AUR Allowed:")
                && result.stdout_contains("No")
                && result.stdout_contains("PGP Required:")
                && result.stdout_contains("Yes")
                && result.stdout_contains("Banned Packages:")
                && result.stdout_contains("telnet")
                && result.stdout_contains("ftp"),
            "policy audit must reflect the injected STRICT_POLICY, got:\n{}",
            result.stdout
        );
    }

    #[test]
    fn test_injection_prevention_search() {
        for input in validation::INJECTION_ATTEMPTS {
            let result = run_omg(&["search", input]);
            // Should not execute injected commands
            assert!(
                !result.stdout_contains("pwned"),
                "Should prevent injection: {input}"
            );
            assert!(
                !result.stdout_contains("/etc/passwd"),
                "Should prevent path traversal"
            );
        }
    }

    #[test]
    fn test_injection_prevention_info() {
        for input in validation::INJECTION_ATTEMPTS {
            let result = run_omg(&["info", input]);
            // The key test: shell commands should NOT be executed
            // "pwned" appearing in error message quoting the input is OK
            // "pwned" appearing as actual command output is NOT OK
            // Check for actual command execution indicators
            assert!(
                !result.stdout_contains("root:x:0:0"),
                "Should prevent /etc/passwd leak: {input}"
            );
            assert!(
                !result.stdout_contains("/bin/bash"),
                "Should prevent passwd content leak: {input}"
            );
            // Should not panic
            assert!(
                !result.stderr_contains("panicked at"),
                "Should not panic on: {input}"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════════

mod edge_cases {
    use super::*;

    #[test]
    fn test_unicode_package_names() {
        for input in validation::UNICODE_INPUTS {
            let result = run_omg(&["search", input]);
            // Should handle gracefully (not crash)
            assert!(
                !result.stderr_contains("panicked at"),
                "Should handle unicode: {input}"
            );
        }
    }

    #[test]
    fn test_very_long_query() {
        let long_query = validation::very_long_input(10000);
        let result = run_omg(&["search", &long_query]);
        // Should handle without crashing
        assert!(
            !result.stderr_contains("panicked at"),
            "Should handle long input"
        );
    }

    #[test]
    fn test_empty_inputs() {
        for input in validation::EMPTY_INPUTS {
            let result = run_omg(&["search", input]);
            // Should handle gracefully
            assert!(
                !result.stderr_contains("panicked at"),
                "Should handle empty input"
            );
        }
    }

    #[test]
    fn test_concurrent_operations() {
        use std::thread;

        let handles: Vec<_> = (0..10)
            .map(|_| thread::spawn(|| run_omg(&["status"])))
            .collect();

        for handle in handles {
            let result = handle.join().unwrap();
            result.assert_success();
        }
    }

    #[test]
    fn test_missing_home_directory() {
        // Test with HOME unset
        let result = run_omg_with_env(&["status"], &[("HOME", "")]);
        // Should handle gracefully
        assert!(
            !result.stderr_contains("panicked at"),
            "Should handle missing HOME"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// INTEGRATION SCENARIOS
// ═══════════════════════════════════════════════════════════════════════════════

mod integration_scenarios {
    use super::*;

    #[test]
    fn scenario_full_workflow() {
        let project = TestProject::new();
        project.with_tool_versions(&[("nodejs", "20.10.0"), ("python", "3.11.0")]);
        project
            .mock_install("nodejs", "20.10.0")
            .expect("seed nodejs state");
        project
            .mock_install("python", "3.11.0")
            .expect("seed python state");

        // 1. Check status
        let result = project.run(&["status"]);
        result.assert_success();

        // 2. Capture environment
        let result = project.run(&["env", "capture"]);
        result.assert_success();
        assert!(project.file_exists("omg.lock"), "Should create omg.lock");

        // 3. The unchanged captured environment must be in sync.
        let result = project.run(&["env", "check"]);
        result.assert_success();
        result.assert_stdout_contains("in sync");

        // 4. Create snapshot and register it in the snapshot index.
        let result = project.run(&["snapshot", "create", "--message", "Initial"]);
        result.assert_success();
        assert!(
            project
                .data_dir
                .path()
                .join("snapshots/index.json")
                .exists(),
            "snapshot create must write the snapshot index",
        );
    }

    #[test]
    fn scenario_team_collaboration() {
        let dev1 = TestProject::new();
        let dev2 = TestProject::new();

        // Dev1 sets up project and captures its lockfile
        dev1.with_tool_versions(&[("nodejs", "20.10.0")]);
        dev1.mock_install("nodejs", "20.10.0")
            .expect("seed dev1 nodejs state");
        let captured = dev1.run(&["env", "capture"]);
        captured.assert_success();
        let lock = dev1
            .read_file("omg.lock")
            .expect("env capture must produce omg.lock");

        // Dev2 receives the lock and sets up the same tools
        dev2.create_file("omg.lock", &lock);
        dev2.with_tool_versions(&[("nodejs", "20.10.0")]);
        dev2.mock_install("nodejs", "20.10.0")
            .expect("seed dev2 nodejs state");

        // Dev2 has the same package and runtime state as the captured lock.
        let result = dev2.run(&["env", "check"]);
        result.assert_success();
        result.assert_stdout_contains("in sync");
    }

    #[test]
    fn scenario_security_audit() {
        require_system_tests!();
        require_arch!();

        // Bare 'audit' defaults to Scan; it must complete with report output.
        let scan = run_omg(&["audit"]);
        assert_audit_scan_completed(&scan);

        // Policy audit must print the status header.
        let policy = run_omg(&["audit", "policy"]);
        policy.assert_success();
        assert!(
            policy.stdout_contains("Security Policy Status"),
            "audit policy must show status, got:\n{}",
            policy.stdout
        );
    }
}
