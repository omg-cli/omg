#![cfg(feature = "arch")]
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::pedantic,
    clippy::nursery
)]
//! Comprehensive Integration Tests for omg install and omg update
//!
//! Tests every aspect of the install and update commands:
//! - CLI argument parsing and validation
//! - Official package operations
//! - AUR package operations
//! - Parallel build and error recovery
//! - Non-interactive mode (CI/CD)
//! - Dry-run mode
//! - Error messages and user experience
//!
//! Harness contract: `run_omg` sets `OMG_TEST_MODE=1`, which routes the
//! package-manager trait to the mock backend seeded with pacman/firefox/git
//! (src/package_managers/mock.rs `MockPackageDb::arch_defaults`). Official
//! package info and previews use that isolated index. Local archive previews
//! read real package metadata against a private ALPM root.
//!
//! Run: cargo test --test install_update_comprehensive --features arch
//!
//! Environment variables:
//!   OMG_RUN_SYSTEM_TESTS=1      - Enable tests requiring real system access
//!   OMG_RUN_NETWORK_TESTS=1     - Enable tests requiring AUR RPC access
//!   OMG_RUN_DESTRUCTIVE_TESTS=1 - Enable tests that modify the system

use std::env;
use std::process::Command;

pub mod common;

// ═══════════════════════════════════════════════════════════════════════════════
// TEST INFRASTRUCTURE
// ═══════════════════════════════════════════════════════════════════════════════

struct TestResult {
    success: bool,
    stdout: String,
    stderr: String,
    exit_code: i32,
}

impl TestResult {
    fn combined(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }

    fn assert_success(&self) -> &Self {
        assert!(
            self.success,
            "Command should succeed. Exit code: {}. Output:\n{}",
            self.exit_code,
            self.combined()
        );
        self
    }

    fn assert_failure(&self) -> &Self {
        assert!(
            !self.success,
            "Command should fail but succeeded. Output:\n{}",
            self.combined()
        );
        self
    }

    fn assert_contains(&self, pattern: &str) -> &Self {
        assert!(
            self.combined().contains(pattern),
            "Output should contain '{}'. Got:\n{}",
            pattern,
            self.combined()
        );
        self
    }

    fn assert_no_panic(&self) -> &Self {
        let combined = self.combined();
        assert!(
            !combined.contains("panicked") && !combined.contains("RUST_BACKTRACE"),
            "Command panicked. Output:\n{}",
            combined
        );
        self
    }

    fn assert_no_password_prompt(&self) -> &Self {
        let combined = self.combined();
        assert!(
            !combined.contains("[sudo]")
                && !combined.contains("password for")
                && !combined.contains("Password:"),
            "Should not prompt for password. Output:\n{}",
            combined
        );
        self
    }

    /// Pinned from src/cli/packages/update/arch.rs: an update check must name
    /// either pending updates ("Found N update(s)") or a clean system
    /// ("System is up to date").
    fn assert_reports_update_status(&self) -> &Self {
        let combined = self.combined();
        assert!(
            combined.contains("up to date") || combined.contains("Found"),
            "update check must report pending updates or 'up to date'. Got:\n{}",
            combined
        );
        self
    }
}

fn run_omg(args: &[&str]) -> TestResult {
    run_omg_with_env(args, &[])
}

/// Delegate to the shared isolated runner so every invocation gets unique
/// `OMG_DATA_DIR` / `OMG_CONFIG_DIR` / `OMG_CACHE_DIR` instead of writing
/// mock state into the real user data directory.
fn run_omg_with_env(args: &[&str], env_vars: &[(&str, &str)]) -> TestResult {
    let result = common::run_omg_with_options(args, None, env_vars);
    TestResult {
        success: result.success,
        stdout: result.stdout,
        stderr: result.stderr,
        exit_code: result.exit_code,
    }
}

fn run_in_project(project: &common::TestProject, args: &[&str]) -> TestResult {
    let result = project.run_with_env(args, &[("NO_COLOR", "1")]);
    TestResult {
        success: result.success,
        stdout: result.stdout,
        stderr: result.stderr,
        exit_code: result.exit_code,
    }
}

fn assert_preview_rows(result: &TestResult, expected: &[(&str, &str, &str)]) {
    result.assert_success();
    result.assert_contains("Install Preview");
    result.assert_contains("No changes will be made (dry run)");
    let rows: Vec<_> = result
        .stdout
        .lines()
        .filter_map(|line| {
            let cells: Vec<_> = line.split(['│', '┆']).map(str::trim).collect();
            if cells.len() == 6 && cells[1] != "Package" {
                Some((cells[1], cells[2], cells[4].trim_start_matches('✓').trim()))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(rows, expected, "preview package/version/source rows");
}

fn assert_no_installed_packages(project: &common::TestProject) {
    let inventory = project.run(&["explicit", "--json"]);
    inventory.assert_success();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&inventory.stdout).unwrap(),
        serde_json::json!({"packages": [], "count": 0})
    );
    assert!(!project.data_dir.path().join("history.json").exists());
}

fn write_preview_package(path: &std::path::Path) {
    let pkginfo = b"pkgname = vim\npkgbase = vim\nxdata = pkgtype=pkg\npkgver = 9.1.0001-1\npkgdesc = preview fixture\nurl = https://example.invalid/\nbuilddate = 1700000000\npackager = fixture\nsize = 4096\narch = x86_64\nlicense = MIT\n";
    let file = std::fs::File::create(path).unwrap();
    let mut encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    {
        let mut archive = tar::Builder::new(&mut encoder);
        let mut header = tar::Header::new_gnu();
        header.set_path(".PKGINFO").unwrap();
        header.set_size(pkginfo.len() as u64);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append(&header, pkginfo.as_slice()).unwrap();
        archive.finish().unwrap();
    }
    encoder.finish().unwrap().sync_all().unwrap();
}

fn system_tests_enabled() -> bool {
    matches!(env::var("OMG_RUN_SYSTEM_TESTS"), Ok(v) if v == "1")
}

fn network_tests_enabled() -> bool {
    matches!(env::var("OMG_RUN_NETWORK_TESTS"), Ok(v) if v == "1")
}

fn destructive_tests_enabled() -> bool {
    matches!(env::var("OMG_RUN_DESTRUCTIVE_TESTS"), Ok(v) if v == "1")
}

fn is_package_installed(pkg: &str) -> bool {
    Command::new("pacman")
        .args(["-Q", pkg])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

// ═══════════════════════════════════════════════════════════════════════════════
// INSTALL COMMAND - CLI ARGUMENT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod install_cli_tests {
    use super::*;

    #[test]
    fn test_install_no_packages_shows_error() {
        let result = run_omg(&["install"]);
        result.assert_failure();
        // Bare install prompts in a terminal; a noninteractive run fails with
        // guidance instead of a clap contract error (src/cli/packages/install.rs).
        result.assert_contains("No packages specified");
    }

    #[test]
    fn test_install_help_flag() {
        let result = run_omg(&["install", "--help"]);
        result.assert_success();
        result.assert_contains("Usage");
        // Documented flags must appear in help (src/cli/args.rs Install).
        result.assert_contains("--dry-run");
        result.assert_contains("--yes");
    }

    #[test]
    fn test_install_yes_flag_auto_confirms() {
        // OMG_TEST_MODE routes installs to the mock backend whose arch
        // defaults include firefox, so `-y` must complete end-to-end without
        // any confirmation prompt.
        let result = run_omg(&["install", "-y", "firefox"]);
        result.assert_no_password_prompt();
        result.assert_success();
        result.assert_contains("Install");
        assert!(
            !result.stdout.contains("Installed 1 package"),
            "{}",
            result.combined()
        );
    }

    #[test]
    fn test_install_dry_run_flag() {
        let result = run_omg(&["install", "--dry-run", "firefox"]);
        result.assert_success();
        // Pinned footer: src/cli/packages/install/arch.rs install_dry_run.
        result.assert_contains("(dry run)");
        result.assert_contains("No changes will be made");
    }

    #[test]
    fn test_install_multiple_packages() {
        let result = run_omg(&["install", "--dry-run", "firefox", "pacman", "git"]);
        result.assert_success();
        // The preview table must list every requested package.
        result.assert_contains("firefox");
        result.assert_contains("pacman");
        result.assert_contains("git");
    }

    #[test]
    fn test_install_invalid_flag() {
        let result = run_omg(&["install", "--invalid-flag-xyz"]);
        result.assert_failure();
        result.assert_contains("unexpected argument");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// INSTALL COMMAND - PACKAGE RESOLUTION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod install_resolution_tests {
    use super::*;

    #[test]
    fn test_install_nonexistent_package() {
        let result = run_omg(&["install", "-y", "this-package-does-not-exist-xyz-12345"]);
        result.assert_failure();
        let combined = result.combined();
        assert!(
            combined.contains("not found") || combined.contains("error"),
            "Should show not found error. Got: {}",
            combined
        );
    }

    #[test]
    fn test_install_dry_run_shows_packages() {
        let project = common::TestProject::for_distro("arch");
        project.mock_available("vim", "9.1.0001").unwrap();
        assert_no_installed_packages(&project);
        let result = run_in_project(&project, &["install", "--dry-run", "vim"]);
        assert_preview_rows(&result, &[("vim", "9.1.0001", "Official")]);
        assert_no_installed_packages(&project);
        project.close_checked();
    }

    #[test]
    fn test_install_detects_aur_package() {
        if !network_tests_enabled() {
            return;
        }
        // yay-bin lives in the AUR only; dry-run resolves it through the AUR
        // RPC (src/cli/packages/install/arch.rs install_dry_run) and tags the
        // table row with an AUR source.
        let result = run_omg(&["install", "--dry-run", "yay-bin"]);
        result.assert_success();
        result.assert_contains("yay-bin");
        result.assert_contains("AUR");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// INSTALL COMMAND - ERROR HANDLING TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod install_error_tests {
    use super::*;

    #[test]
    fn test_install_helpful_error_messages() {
        let result = run_omg(&["install", "--yes", "nonexistent-pkg-xyz"]);
        result.assert_failure();
        // Missing packages must be reported with an explicit not-found error
        // plus recovery advice, never silently ignored.
        result.assert_contains("not found");
        result.assert_contains("Suggestion");
    }

    #[test]
    fn test_install_no_panic_on_error() {
        let result = run_omg(&["install", "-y", "definitely-fake-package"]);
        result.assert_failure();
        result.assert_no_panic();
    }

    #[test]
    fn test_install_package_missing_from_mock_index_fails_cleanly() {
        // vim is not in the mock arch defaults; the install flow must fail
        // with the repository-level not-found diagnostic instead of
        // attempting elevation or panicking.
        let result = run_omg(&["install", "-y", "vim"]);
        result.assert_failure();
        result.assert_no_password_prompt();
        result.assert_contains("not found");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// UPDATE COMMAND - CLI ARGUMENT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod update_cli_tests {
    use super::*;

    #[test]
    fn test_update_help_flag() {
        let result = run_omg(&["update", "--help"]);
        result.assert_success();
        result.assert_contains("Usage");
        // Documented flags must appear in help (src/cli/args.rs Update).
        result.assert_contains("--check");
        result.assert_contains("--dry-run");
        result.assert_contains("--aur-only");
        result.assert_contains("--fast");
        result.assert_contains("--turbo");
    }

    #[test]
    fn test_update_check_flag() {
        let result = run_omg(&["update", "--check"]);
        result.assert_success();
        result.assert_reports_update_status();
    }

    #[test]
    fn test_update_yes_flag() {
        let result = run_omg(&["update", "-y", "--check"]);
        result.assert_success();
        result.assert_reports_update_status();
    }

    #[test]
    fn test_update_dry_run_flag() {
        let result = run_omg(&["update", "--dry-run"]);
        result.assert_success();
        // Pinned header: src/cli/packages/update/arch.rs update().
        result.assert_contains("Dry run");
        result.assert_reports_update_status();
    }

    #[test]
    fn test_update_aur_only_flag() {
        let result = run_omg(&["update", "--check", "--aur-only"]);
        result.assert_success();
        result.assert_contains("AUR only");
        result.assert_reports_update_status();
    }

    #[test]
    fn test_update_aur_only_rejects_fast_paths() {
        for flag in ["--fast", "--turbo"] {
            let result = run_omg(&["update", "--aur-only", flag]);
            result.assert_failure();
            result.assert_contains("cannot be used with");
        }
    }

    #[test]
    fn test_update_invalid_flag() {
        let result = run_omg(&["update", "--invalid-xyz"]);
        result.assert_failure();
        result.assert_contains("unexpected argument");
    }

    #[test]
    fn test_update_fast_flag_never_prompts_and_fails_with_cause() {
        // --fast delegates to a privileged full upgrade. As an unprivileged
        // user in a development build it must refuse cleanly, naming the
        // elevation block (src/core/privilege.rs / arch.rs
        // run_privileged_operation); as a privileged caller it runs the fast
        // update header. Either way: no password prompt, no panic.
        let result = run_omg(&["update", "--fast"]);
        result.assert_no_password_prompt();
        result.assert_no_panic();
        result.assert_contains("Fast System Update");
        if !result.success {
            let combined = result.combined();
            assert!(
                combined.contains("Privilege elevation not supported")
                    || combined.contains("sudo")
                    || combined.contains("Elevating"),
                "failed fast update must cite the privilege boundary. Got:\n{}",
                combined
            );
        }
    }

    #[test]
    fn test_update_turbo_flag_reports_status() {
        // Turbo's unprivileged arm performs the cached check-only pass and
        // reports update status without elevating.
        let result = run_omg(&["update", "--turbo"]);
        result.assert_no_password_prompt();
        result.assert_no_panic();
        result.assert_contains("TURBO");
        result.assert_reports_update_status();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// UPDATE COMMAND - CHECK MODE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod update_check_tests {
    use super::*;

    #[test]
    fn test_check_mode_no_password_prompt() {
        let result = run_omg(&["update", "--check"]);
        result.assert_no_password_prompt();
        result.assert_success();
        result.assert_reports_update_status();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// UPDATE COMMAND - NON-INTERACTIVE MODE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod update_ci_tests {
    use super::*;

    #[test]
    fn test_ci_mode_with_yes() {
        let result = run_omg_with_env(&["update", "--check", "-y"], &[("CI", "1")]);
        result.assert_success();
        result.assert_reports_update_status();
    }

    #[test]
    fn test_non_interactive_env_var() {
        let result = run_omg_with_env(&["update", "--check"], &[("OMG_NON_INTERACTIVE", "1")]);
        result.assert_success();
        result.assert_reports_update_status();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUR-SPECIFIC TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod aur_tests {
    use super::*;

    #[test]
    fn test_search_degrades_gracefully_for_unindexed_names() {
        // Search runs against the mock official index under OMG_TEST_MODE;
        // AUR-only names are absent there and must produce an explicit,
        // successful "no results" report rather than an error.
        let result = run_omg(&["search", "yay-bin"]);
        result.assert_success();
        result.assert_contains("No results found");
    }

    #[test]
    fn test_aur_info_works() {
        if !network_tests_enabled() {
            return;
        }
        // info falls back to the AUR RPC for names missing from official
        // repos (src/cli/packages/info.rs).
        let result = run_omg(&["info", "yay-bin"]);
        result.assert_success();
        result.assert_contains("yay-bin");
        result.assert_contains("Description");
    }

    #[test]
    fn test_aur_dry_run() {
        if !network_tests_enabled() {
            return;
        }
        let result = run_omg(&["install", "--dry-run", "yay-bin"]);
        result.assert_success();
        result.assert_contains("AUR");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// PARALLEL BUILD TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod parallel_build_tests {
    #[test]
    fn test_build_job_creation() {
        use omg_lib::package_managers::aur::BuildJob;
        let job = BuildJob::new("test-pkg".to_string(), vec!["dep1".to_string()]);
        assert_eq!(job.package, "test-pkg");
        assert_eq!(job.dependencies.len(), 1);
    }

    #[test]
    fn test_dependency_graph() {
        use omg_lib::package_managers::aur::{BuildJob, ParallelBuilder};

        let jobs = vec![
            BuildJob::new("a".to_string(), vec![]),
            BuildJob::new("b".to_string(), vec!["a".to_string()]),
            BuildJob::new("c".to_string(), vec!["a".to_string()]),
        ];

        let graph = ParallelBuilder::build_dependency_graph(&jobs);
        assert_eq!(graph.len(), 3);
        assert!(graph.get("a").unwrap().is_empty());
        assert!(graph.get("b").unwrap().contains("a"));
    }

    #[test]
    fn test_topological_sort() {
        use omg_lib::package_managers::aur::ParallelBuilder;
        use std::collections::{HashMap, HashSet};

        let mut graph = HashMap::new();
        graph.insert("a".to_string(), HashSet::new());
        graph.insert("b".to_string(), ["a".to_string()].into_iter().collect());
        graph.insert("c".to_string(), ["b".to_string()].into_iter().collect());

        let levels = ParallelBuilder::topological_levels(&graph).unwrap();
        assert_eq!(levels.len(), 3);
        assert_eq!(levels[0], vec!["a"]);
        assert_eq!(levels[1], vec!["b"]);
        assert_eq!(levels[2], vec!["c"]);
    }

    #[test]
    fn test_circular_dependency_detection() {
        use omg_lib::package_managers::aur::ParallelBuilder;
        use std::collections::HashMap;

        let mut graph = HashMap::new();
        graph.insert("a".to_string(), ["b".to_string()].into_iter().collect());
        graph.insert("b".to_string(), ["a".to_string()].into_iter().collect());

        let result = ParallelBuilder::topological_levels(&graph);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Circular"));
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BATCH ALPM QUERY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// `batch_query_tests` was removed in wave 2: the underlying
// `alpm_direct::get_package_info_batch` API no longer exists upstream, and
// per RUST-CODING-STANDARDS §9 tests must not pin removed surfaces. If a
// batch query returns, pin it here again with behavioral assertions.

// ═══════════════════════════════════════════════════════════════════════════════
// DESTRUCTIVE TESTS (REQUIRE OMG_RUN_DESTRUCTIVE_TESTS=1)
// ═══════════════════════════════════════════════════════════════════════════════

mod destructive_tests {
    use super::*;

    fn cleanup_package(pkg: &str) {
        let _ = Command::new("sudo")
            .args(["pacman", "-Rdd", "--noconfirm", pkg])
            .output();
    }

    #[test]
    #[ignore = "performs a real package installation; requires OMG_RUN_DESTRUCTIVE_TESTS=1"]
    fn test_real_install_official_package() {
        assert!(
            destructive_tests_enabled(),
            "Set OMG_RUN_DESTRUCTIVE_TESTS=1 to run destructive tests"
        );

        let test_pkg = "cowsay";
        let was_installed = is_package_installed(test_pkg);

        if was_installed {
            println!("Package already installed, skipping");
            return;
        }

        let result = Command::new("sudo")
            .args([env!("CARGO_BIN_EXE_omg"), "install", "-y", test_pkg])
            .output()
            .expect("Failed to run install");

        let success = result.status.success();

        if is_package_installed(test_pkg) && !was_installed {
            cleanup_package(test_pkg);
        }

        assert!(success, "Install should succeed");
    }

    #[test]
    #[ignore = "runs a privileged real-system update check; requires OMG_RUN_DESTRUCTIVE_TESTS=1"]
    fn test_real_update_check() {
        assert!(
            destructive_tests_enabled(),
            "Set OMG_RUN_DESTRUCTIVE_TESTS=1 to run destructive tests"
        );

        let result = Command::new("sudo")
            .args([env!("CARGO_BIN_EXE_omg"), "update", "--check"])
            .output()
            .expect("Failed to run update check");

        assert!(result.status.success());
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod security_tests {
    use super::*;

    #[test]
    fn test_no_secrets_in_output() {
        let result = run_omg(&["--help"]);
        let combined = result.combined();
        assert!(!combined.contains("password"));
        assert!(!combined.contains("secret"));
        assert!(!combined.contains("token"));
    }

    #[test]
    fn test_command_injection_prevented() {
        // Shell metacharacters are rejected by package-name validation
        // (src/core/security/validation.rs), so the command must fail with
        // the allowlist diagnostic instead of ever reaching a subprocess.
        let result = run_omg(&["install", "pkg; rm -rf /"]);
        result.assert_failure();
        result.assert_contains("Invalid character");
        result.assert_no_panic();
    }

    #[test]
    fn test_path_traversal_prevented() {
        // Dot-leading names are rejected before resolution
        // (PackageNameStartsWithDot in src/core/security/validation.rs).
        let result = run_omg(&["install", "../../../etc/passwd"]);
        result.assert_failure();
        result.assert_contains("cannot start with '.'");
        result.assert_no_panic();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// USER EXPERIENCE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod ux_tests {
    use super::*;

    #[test]
    fn test_top_level_help_lists_core_commands() {
        let result = run_omg(&["--help"]);
        result.assert_success();
        result.assert_contains("Usage");
        result.assert_contains("install");
        result.assert_contains("update");
    }

    #[test]
    fn test_unicode_characters_work() {
        if !system_tests_enabled() {
            return;
        }
        let result = run_omg(&["search", "日本語テスト"]);
        result.assert_success();
        result.assert_no_panic();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPREHENSIVE E2E WORKFLOW TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod e2e_workflow_tests {
    use super::*;

    #[test]
    fn test_full_install_workflow_dry_run() {
        let project = common::TestProject::for_distro("arch");
        project.mock_available("vim", "9.1.0001").unwrap();
        assert_no_installed_packages(&project);
        let search = run_in_project(&project, &["search", "git"]);
        search.assert_success();
        search.assert_contains("git");
        let info = run_in_project(&project, &["info", "pacman"]);
        info.assert_success();
        info.assert_contains("Description");
        let install = run_in_project(&project, &["install", "--dry-run", "vim"]);
        assert_preview_rows(&install, &[("vim", "9.1.0001", "Official")]);
        assert_no_installed_packages(&project);
        project.close_checked();
    }

    #[test]
    fn test_full_update_workflow() {
        if !system_tests_enabled() {
            return;
        }

        // Complete update workflow: check -> status -> update --dry-run
        let check = run_omg(&["update", "--check"]);
        check.assert_success();
        check.assert_reports_update_status();

        let status = run_omg(&["status"]);
        status.assert_success();
        status.assert_contains("packages installed");

        let update = run_omg(&["update", "--dry-run"]);
        update.assert_success();
        update.assert_contains("Dry run");
        update.assert_reports_update_status();
    }

    #[test]
    fn test_install_multiple_packages_mixed_sources() {
        let project = common::TestProject::for_distro("arch");
        project.mock_available("vim", "9.1.0001").unwrap();
        for directory in ["var/lib/pacman/local", "var/lib/pacman/sync"] {
            std::fs::create_dir_all(project.pacman_root.path().join(directory)).unwrap();
        }
        let archive = project.path().join("decoy-1.0-1-x86_64.pkg.tar.gz");
        write_preview_package(&archive);
        assert_no_installed_packages(&project);
        let result = run_in_project(
            &project,
            &[
                "install",
                "--dry-run",
                "--allow-local-file",
                "firefox",
                archive.to_str().unwrap(),
                "git",
            ],
        );
        assert_preview_rows(
            &result,
            &[
                ("firefox", "122.0", "Official"),
                ("vim", "9.1.0001-1", "Local archive"),
                ("git", "2.43.0", "Official"),
            ],
        );
        assert_no_installed_packages(&project);
        project.close_checked();
    }

    #[test]
    fn test_install_dry_run_shows_dependency_information() {
        if !system_tests_enabled() {
            return;
        }

        let result = run_omg(&["install", "--dry-run", "firefox"]);
        result.assert_success();
        result.assert_contains("firefox");
        // The preview reports the aggregate download size for the resolved
        // dependency set (src/cli/packages/install/arch.rs).
        result.assert_contains("Total download size");
    }

    #[test]
    fn test_update_rejects_positional_packages() {
        // Update takes no positional package list (src/cli/args.rs Update);
        // passing one must be a clap argument error, never a silent ignore.
        let result = run_omg(&["update", "vim", "--dry-run"]);
        result.assert_failure();
        result.assert_contains("unexpected argument");
    }

    #[test]
    fn test_install_dry_run_lists_available_official_package() {
        if !system_tests_enabled() {
            return;
        }

        // pacman exists in every Arch repository set; dry-run must list it
        // as an available Official package.
        let result = run_omg(&["install", "--dry-run", "pacman"]);
        result.assert_success();
        result.assert_contains("pacman");
        result.assert_contains("Official");
    }

    #[test]
    fn test_search_then_install_pipeline() {
        if !system_tests_enabled() {
            return;
        }

        // Realistic user workflow against the seeded mock index; the final
        // dry-run reads real repository metadata.
        let search = run_omg(&["search", "firefox"]);
        search.assert_success();
        search.assert_contains("firefox");

        let install = run_omg(&["install", "--dry-run", "firefox"]);
        install.assert_success();
        install.assert_contains("firefox");
    }

    #[test]
    fn test_info_shows_provided_details() {
        let result = run_omg(&["info", "pacman"]);
        result.assert_success();
        result.assert_contains("Description");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// EDGE CASE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod edge_case_tests {
    use super::*;

    #[test]
    fn test_install_empty_package_name() {
        let result = run_omg(&["install", ""]);
        result.assert_failure();
        // Pinned: ValidationError::PackageNameEmpty.
        result.assert_contains("cannot be empty");
    }

    #[test]
    fn test_install_package_name_with_spaces() {
        let result = run_omg(&["install", "package with spaces"]);
        result.assert_failure();
        result.assert_contains("Invalid character");
        result.assert_no_panic();
    }

    #[test]
    fn test_install_very_long_package_name() {
        let long_name = "a".repeat(1000);
        let result = run_omg(&["install", "--dry-run", &long_name]);
        result.assert_failure();
        // Pinned: MAX_PACKAGE_NAME_LENGTH = 255.
        result.assert_contains("too long");
        result.assert_no_panic();
    }

    #[test]
    fn test_install_unicode_package_name() {
        let result = run_omg(&["install", "--dry-run", "🦀-package"]);
        result.assert_failure();
        result.assert_contains("Invalid character");
        result.assert_no_panic();
    }

    #[test]
    fn test_install_with_special_chars() {
        // '@' is on the package-name allowlist, so pkg@123 passes validation
        // and must fail later with an explicit not-found; true metacharacters
        // are rejected upfront by validation.
        let cases: [(&str, &str); 4] = [
            ("pkg@123", "was not found"),
            ("pkg#hash", "Invalid character"),
            ("pkg!", "Invalid character"),
            ("pkg?", "Invalid character"),
        ];
        for (payload, expected) in cases {
            let result = run_omg(&["install", "--dry-run", payload]);
            result.assert_failure();
            result.assert_contains(expected);
            result.assert_no_panic();
        }
    }

    #[test]
    fn test_install_case_insensitive_search() {
        // The backend lowercases queries before matching
        // (src/package_managers/mock.rs MockPackageManager::search), so both
        // spellings must surface the same seeded package.
        let lower = run_omg(&["search", "firefox"]);
        lower.assert_success();
        lower.assert_contains("firefox");

        let upper = run_omg(&["search", "FIREFOX"]);
        upper.assert_success();
        upper.assert_contains("firefox");
    }

    #[test]
    fn test_search_partial_prefix_query() {
        // Trailing-hyphen queries match nothing in the index but must still
        // exit 0 with an explicit result summary.
        let result = run_omg(&["search", "python-"]);
        result.assert_success();
        let combined = result.combined();
        assert!(
            combined.contains("Search Results") || combined.contains("No results found"),
            "search must print a result summary. Got:\n{}",
            combined
        );
    }

    #[test]
    fn test_multiple_flags_combination() {
        if !system_tests_enabled() {
            return;
        }

        // -y and --dry-run compose: the dry-run preview wins and nothing is
        // installed or prompted.
        let result = run_omg(&["install", "-y", "--dry-run", "firefox"]);
        result.assert_success();
        result.assert_contains("(dry run)");
        result.assert_no_password_prompt();
    }

    #[test]
    fn test_conflicting_flags() {
        // Install has no --fast/--turbo modes (those belong to update);
        // passing them must be rejected by clap.
        let result = run_omg(&["install", "--fast", "firefox"]);
        result.assert_failure();
        result.assert_contains("unexpected argument '--fast'");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// REAL SYSTEM STATE TESTS (SAFE, NON-DESTRUCTIVE)
// ═══════════════════════════════════════════════════════════════════════════════

mod system_state_tests {
    use super::*;

    #[test]
    fn test_list_runtime_versions() {
        // `list` reports installed runtime versions
        // (src/cli/args.rs List); it takes no --installed flag.
        let result = run_omg(&["list"]);
        result.assert_success();
        result.assert_contains("Installed runtime versions");
    }

    #[test]
    fn test_search_returns_seeded_results() {
        let result = run_omg(&["search", "firefox"]);
        result.assert_success();
        result.assert_contains("firefox");
        result.assert_contains("Official");
    }

    #[test]
    fn test_info_shows_package_details() {
        if !system_tests_enabled() {
            return;
        }

        let result = run_omg(&["info", "pacman"]);
        result.assert_success();
        // Official-package info renders the version inline next to the name
        // and labels Description/Repository sections
        // (src/cli/packages/info.rs).
        result.assert_contains("Description");
        result.assert_contains("Repository");
    }

    #[test]
    fn test_update_check_shows_available_updates() {
        if !system_tests_enabled() {
            return;
        }

        let result = run_omg(&["update", "--check"]);
        result.assert_success();
        result.assert_reports_update_status();
    }

    #[test]
    fn test_status_shows_system_info() {
        if !system_tests_enabled() {
            return;
        }

        let result = run_omg(&["status"]);
        result.assert_success();
        result.assert_contains("packages installed");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// INTEGRATION WITH OTHER COMMANDS
// ═══════════════════════════════════════════════════════════════════════════════

mod command_integration_tests {
    use super::*;

    #[test]
    fn test_install_then_remove_workflow() {
        if !destructive_tests_enabled() {
            return;
        }

        // Preview workflow: both sides must show their dry-run contract.
        let install = run_omg(&["install", "--dry-run", "firefox"]);
        install.assert_success();
        install.assert_contains("(dry run)");

        let remove = run_omg(&["remove", "--dry-run", "firefox"]);
        remove.assert_success();
        remove.assert_contains("No changes made (dry run)");
    }

    #[test]
    fn test_update_then_install_workflow() {
        if !system_tests_enabled() {
            return;
        }

        let update = run_omg(&["update", "--check"]);
        update.assert_success();
        update.assert_reports_update_status();

        let install = run_omg(&["install", "--dry-run", "firefox"]);
        install.assert_success();
        install.assert_contains("firefox");
    }

    #[test]
    fn test_search_info_install_pipeline() {
        if !system_tests_enabled() {
            return;
        }

        // Complete user journey across the three read/preview surfaces.
        let search = run_omg(&["search", "firefox"]);
        search.assert_success();
        search.assert_contains("firefox");

        let info = run_omg(&["info", "firefox"]);
        info.assert_success();
        info.assert_contains("Description");

        let install = run_omg(&["install", "--dry-run", "firefox"]);
        install.assert_success();
        install.assert_contains("firefox");
    }

    #[test]
    fn test_status_after_failed_install() {
        let project = common::TestProject::new();
        project.run(&["install", "-y", "git"]).assert_success();

        let before = project.run(&["explicit", "--json"]);
        before.assert_success();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&before.stdout).unwrap(),
            serde_json::json!({ "packages": ["git"], "count": 1 }),
            "The initial CLI install must persist a nonempty inventory"
        );
        let state_path = project.data_dir.path().join("mock_state_pacman.json");
        let before_state = std::fs::read(&state_path).unwrap();

        // A real policy rejection is deterministic offline, unlike a missing
        // package lookup that falls through to the live AUR service.
        let policy_path = project.config_dir.path().join("policy.toml");
        std::fs::write(&policy_path, "banned_packages = [\"firefox\"]\n").unwrap();
        let bad_install = project.run(&["install", "-y", "firefox"]);
        bad_install.assert_failure();
        let error = bad_install.combined_output();
        assert!(
            error.contains("firefox") && error.contains("banned"),
            "Expected the injected policy rejection, got: {error}"
        );

        assert_eq!(
            std::fs::read(&state_path).unwrap(),
            before_state,
            "Policy rejection must preserve the persisted inventory"
        );

        let status = project.run(&["status"]);
        status.assert_success();
        status.assert_stdout_contains("1 packages installed · 1 explicit");
        assert_eq!(
            std::fs::read(&state_path).unwrap(),
            before_state,
            "The failed install and subsequent status must preserve persisted state"
        );
        let after_failure = project.run(&["explicit", "--json"]);
        after_failure.assert_success();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&after_failure.stdout).unwrap(),
            serde_json::json!({ "packages": ["git"], "count": 1 }),
            "The same project must retain git and must not install banned firefox"
        );

        assert_eq!(
            std::fs::read(&state_path).unwrap(),
            before_state,
            "Recovery reads must not rewrite the persisted inventory"
        );
        std::fs::remove_file(policy_path).unwrap();
        project.run(&["install", "-y", "firefox"]).assert_success();
        let recovered = project.run(&["explicit", "--json"]);
        recovered.assert_success();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&recovered.stdout).unwrap(),
            serde_json::json!({ "packages": ["firefox", "git"], "count": 2 }),
            "Lifting the ban must permit a new install without losing the old one"
        );
    }

    #[test]
    fn test_multiple_commands_in_sequence() {
        let project = common::TestProject::for_distro("arch");
        project.mock_available("vim", "9.1.0001").unwrap();
        assert_no_installed_packages(&project);
        let status = run_in_project(&project, &["status"]);
        status.assert_success();
        status.assert_contains("0 packages installed");
        let search = run_in_project(&project, &["search", "firefox"]);
        search.assert_success();
        search.assert_contains("firefox");
        let info = run_in_project(&project, &["info", "pacman"]);
        info.assert_success();
        info.assert_contains("Description");
        let install = run_in_project(&project, &["install", "--dry-run", "vim"]);
        assert_preview_rows(&install, &[("vim", "9.1.0001", "Official")]);
        let update = run_in_project(&project, &["update", "--check"]);
        update.assert_success();
        update.assert_reports_update_status();
        assert_no_installed_packages(&project);
        project.close_checked();
    }
}
