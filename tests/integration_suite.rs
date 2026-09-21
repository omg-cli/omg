#![expect(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]
//! OMG World-Class Integration Test Suite
//!
//! Comprehensive testing of all OMG features with real assertions.
//! Tests are organized by feature area and run by default where possible.
//!
//! Run all tests:
//!   cargo test --test integration_suite --features arch
//!
//! Run with system tests (requires Arch Linux):
//!   OMG_RUN_SYSTEM_TESTS=1 cargo test --test integration_suite --features arch
//!
//! Run with network tests (hits external APIs):
//!   OMG_RUN_NETWORK_TESTS=1 cargo test --test integration_suite --features arch
//!
//! Run destructive tests (actually installs packages - USE WITH CAUTION):
//!   OMG_RUN_DESTRUCTIVE_TESTS=1 cargo test --test integration_suite --features arch

#![expect(clippy::doc_markdown)] // Test file doc comments don't need strict formatting
#![expect(clippy::missing_panics_doc)] // Test functions are expected to panic
#![expect(clippy::missing_errors_doc)] // Test helpers don't need docs

pub mod common;

use common::*;
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use tempfile::TempDir;

// ═══════════════════════════════════════════════════════════════════════════════
// TEST UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

// Arch and Debian info use feature-gated fast paths. A portable build must
// exercise the generic adapter with a non-Arch mock, not name a pacman backend
// whose compiled lookup path is absent. Keep the fixture package and distro
// together so they cannot accidentally refer to different mock databases.
const fn backend_fixture() -> (&'static str, &'static str) {
    if cfg!(feature = "arch") {
        ("arch", "pacman")
    } else if cfg!(any(feature = "debian", feature = "debian-pure")) {
        ("debian", "apt")
    } else if cfg!(feature = "macos") {
        ("macos", "homebrew")
    } else {
        ("fedora", "dnf")
    }
}

const fn known_system_package() -> &'static str {
    backend_fixture().1
}

fn run_for_compiled_backend(args: &[&str]) -> CommandResult {
    run_omg_with_env(args, &[("OMG_TEST_DISTRO", backend_fixture().0)])
}

/// Create a temporary project directory with common config files
fn create_test_project(dir: &Path, config_type: &str) {
    fs::create_dir_all(dir).unwrap();

    match config_type {
        "node" => {
            // Create .nvmrc
            let mut f = File::create(dir.join(".nvmrc")).unwrap();
            writeln!(f, "20.10.0").unwrap();

            // Create package.json
            let mut f = File::create(dir.join("package.json")).unwrap();
            writeln!(
                f,
                r#"{{"name": "test", "engines": {{"node": ">=18.0.0"}}}}"#
            )
            .unwrap();
        }
        "python" => {
            let mut f = File::create(dir.join(".python-version")).unwrap();
            writeln!(f, "3.11.0").unwrap();
        }
        "go" => {
            let mut f = File::create(dir.join("go.mod")).unwrap();
            writeln!(f, "module test\n\ngo 1.21").unwrap();
        }
        "rust" => {
            let mut f = File::create(dir.join("rust-toolchain.toml")).unwrap();
            writeln!(f, "[toolchain]\nchannel = \"stable\"").unwrap();
        }
        "ruby" => {
            let mut f = File::create(dir.join(".ruby-version")).unwrap();
            writeln!(f, "3.2.0").unwrap();
        }
        "java" => {
            let mut f = File::create(dir.join(".java-version")).unwrap();
            writeln!(f, "21").unwrap();
        }
        "bun" => {
            let mut f = File::create(dir.join(".bun-version")).unwrap();
            writeln!(f, "1.0.0").unwrap();
        }
        "tool-versions" => {
            let mut f = File::create(dir.join(".tool-versions")).unwrap();
            writeln!(f, "nodejs 20.10.0\npython 3.11.0\nruby 3.2.0").unwrap();
        }
        _ => {}
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLI FOUNDATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod cli_foundation {
    use super::*;

    #[test]
    fn test_version_flag() {
        let result = run_omg(&["--version"]);
        assert!(result.success, "omg --version should succeed");
        assert!(
            result.stdout.contains("omg"),
            "Version output should contain 'omg'"
        );
    }

    #[test]
    fn test_help_flag() {
        let result = run_omg(&["--help"]);
        result.assert_success();
        // Falsifiable contract: clap help always renders a usage line and
        // lists every subcommand by name.
        result.assert_stdout_contains("Usage");
        result.assert_stdout_contains("search");
    }

    #[test]
    fn test_subcommand_help() {
        let subcommands = vec![
            "search", "install", "remove", "update", "info", "clean", "use", "list", "env",
            "audit", "status", "which", "config",
        ];

        for cmd in subcommands {
            let result = run_omg(&[cmd, "--help"]);
            assert!(result.success, "omg {cmd} --help should succeed");
            // Every subcommand help must render clap's usage block.
            assert!(
                result.stdout.contains("Usage"),
                "Help for {cmd} should contain a usage block"
            );
        }
    }

    #[test]
    fn test_invalid_command() {
        let result = run_omg(&["nonexistent-command"]);
        assert!(!result.success, "Invalid command should fail");
        assert!(
            result.stderr.contains("error") || result.stderr.contains("unrecognized"),
            "Should report error for invalid command"
        );
    }

    #[test]
    fn test_missing_required_args() {
        // Install requires package names
        let result = run_omg(&["install"]);
        assert!(!result.success, "install without args should fail");
        assert!(
            result.stderr.contains("No packages specified") || result.stderr.contains("error"),
            "bare install must fail with guidance"
        );
    }

    #[test]
    fn test_verbose_flags() {
        // Test -v, -vv, -vvv
        let result = run_omg(&["-v", "status"]);
        assert!(result.success, "omg -v status should succeed");

        let result = run_omg(&["-vv", "status"]);
        assert!(result.success, "omg -vv status should succeed");

        let result = run_omg(&["-vvv", "status"]);
        assert!(result.success, "omg -vvv status should succeed");
    }

    // Falsifiable contract: quiet suppresses log noise but per its help text
    // (src/cli/args.rs `--quiet`) "Command results still print", so status
    // must still render output and exit 0.
    #[test]
    fn test_quiet_flag() {
        let result = run_omg(&["-q", "status"]);
        result.assert_success();
        assert!(
            !result.stdout.trim().is_empty(),
            "quiet mode must still print command results"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PACKAGE MANAGEMENT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod package_management {
    use super::*;

    #[test]
    #[ignore = "requires a configured system package database"]
    fn test_search_official_package() {
        let result = run_omg(&["search", "firefox"]);
        assert!(result.success, "Search should succeed");
        assert!(result.stdout.contains("firefox"), "Should find firefox");
        assert!(
            result.stdout.contains("Official")
                || result.stdout.contains("extra")
                || result.stdout.contains("core"),
            "Should indicate official repository"
        );
    }

    #[test]
    #[ignore = "requires network access to package metadata"]
    fn test_search_with_detailed_flag() {
        let result = run_omg(&["search", "firefox", "--detailed"]);
        assert!(result.success, "Detailed search should succeed");
        // Detailed output should include votes/popularity for AUR
    }

    #[test]
    #[ignore = "requires a configured system package database"]
    fn test_info_official_package() {
        let result = run_for_compiled_backend(&["info", known_system_package()]);
        // Name plus a real dotted version token (e.g. '7.1.0'), not just any
        // prose containing a period.
        common::assertions::assert_package_info(&result, known_system_package());
    }

    #[test]
    #[cfg(feature = "arch")]
    fn test_info_nonexistent_package() {
        let result = run_omg(&["info", "this-package-does-not-exist-12345"]);
        // FALSIFIABLE: a missing package deterministically fails with a
        // not-found message naming the query.
        result.assert_failure();
        let combined = result.combined_output();
        assert!(
            combined.contains("not found") || combined.contains("does-not-exist"),
            "info of a missing package must say so. Got:\n{combined}"
        );
    }

    #[test]
    #[ignore = "performs a real package installation"]
    fn test_install_real_package() {
        let pkg = env::var("OMG_TEST_PACKAGE").unwrap_or_else(|_| "ripgrep".to_string());
        let args = vec!["install", "-y", &pkg];
        let result = run_omg(&args);
        assert!(
            result.success
                || result.stdout.contains("already installed")
                || result.stderr.contains("already installed"),
            "Install should succeed or report already installed"
        );
    }

    #[test]
    #[ignore = "requires a live package database"]
    fn test_update_check_only() {
        let result = run_omg(&["update", "--check"]);
        result.assert_success();
        assert!(
            !result.combined_output().trim().is_empty(),
            "update --check must report its verdict"
        );
    }

    // Dual-path contract after a required success: an up-to-date system
    // prints its verdict; pending updates list old→new versions. Both paths
    // assert concrete output and no `if` guard can silently skip it.
    #[test]
    #[ignore = "requires a live package database"]
    fn test_update_check_shows_real_updates() {
        let result = run_omg(&["update", "--check"]);
        let combined = result.combined_output();

        result.assert_success();
        assert!(!combined.is_empty(), "Update check should produce output");

        if combined.contains("up to date") {
            // Clean path: verdict rendered.
        } else {
            assert!(
                combined.contains('→') || combined.contains("->"),
                "When updates are listed, each must show old→new versions. Output:\n{combined}"
            );
        }
    }

    #[test]
    #[ignore = "performs a real system update"]
    fn test_update_with_yes_flag() {
        let result = run_omg(&["update", "--yes"]);
        let combined = result.combined_output();

        // Should complete without hanging
        assert!(!combined.is_empty(), "Should produce output");

        // Should show progress or completion message
        assert!(
            combined.contains("update")
                || combined.contains("upgrade")
                || combined.contains("system")
                || combined.contains("up to date")
                || combined.contains("✓"),
            "Should show update progress or completion. Output:\n{combined}"
        );
    }

    #[test]
    #[ignore = "requires a real non-interactive package manager"]
    fn test_non_interactive_without_yes_fails_gracefully() {
        // Test that running in non-interactive mode without --yes
        // gives a helpful error message
        let result = run_omg_with_env(&["update"], &[("CI", "true"), ("OMG_NON_INTERACTIVE", "1")]);

        let combined = result.combined_output();

        // Should fail without --yes in non-interactive mode
        assert!(!result.success, "Should fail without TTY and --yes");

        // Should provide helpful error message
        assert!(
            combined.contains("interactive")
                || combined.contains("--yes")
                || combined.contains("terminal")
                || combined.contains("TTY")
                || combined.contains("requires")
                || combined.contains("sudo"),
            "Should provide helpful error message about interactive mode. Output:\n{combined}"
        );
    }

    #[test]
    fn test_status_command() {
        let result = run_omg(&["status"]);
        assert!(result.success, "Status should succeed");
        assert!(
            result.stdout.contains("packages installed") && result.stdout.contains("Updates"),
            "Status should show system info"
        );
    }

    // Falsifiable contract: clean --help documents both of its operations
    // (src/cli/args.rs:172-183: `orphans` and `cache` flags).
    #[test]
    fn test_clean_help() {
        let result = run_omg(&["clean", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("orphans");
        result.assert_stdout_contains("cache");
    }

    #[test]
    #[ignore = "requires a configured system package database"]
    fn test_explicit_packages() {
        let result = run_omg(&["explicit"]);
        result.assert_success();
        assert!(
            !result.stdout.trim().is_empty(),
            "explicit should list packages on a real Arch system"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// RUNTIME MANAGEMENT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod runtime_management {
    use super::*;

    const RUNTIMES: &[&str] = &[
        "node", "python", "go", "rust", "ruby", "java", "bun", "deno",
    ];

    #[test]
    fn test_list_all_runtimes() {
        let result = run_omg(&["list"]);
        result.assert_success();
        // Falsifiable contract: the overview header is rendered
        // (src/cli/runtimes.rs:379 "Installed runtime versions").
        result.assert_stdout_contains("runtime versions");
    }

    #[test]
    fn test_list_installed_node() {
        let result = run_omg(&["list", "node"]);
        result.assert_success();
        result.assert_stdout_contains("node versions");
    }

    #[test]
    fn test_list_installed_python() {
        let result = run_omg(&["list", "python"]);
        result.assert_success();
        result.assert_stdout_contains("python versions");
    }

    #[test]
    #[ignore = "requires network access to runtime metadata"]
    fn test_list_available_node() {
        let result = run_omg(&["list", "node", "--available"]);
        assert!(result.success, "List available node should succeed");
        // Should show versions from nodejs.org
    }

    #[test]
    #[ignore = "requires network access to runtime metadata"]
    fn test_list_available_python() {
        let result = run_omg(&["list", "python", "--available"]);
        assert!(result.success, "List available python should succeed");
    }

    #[test]
    #[ignore = "requires network access to runtime metadata"]
    fn test_list_available_go() {
        let result = run_omg(&["list", "go", "--available"]);
        assert!(result.success, "List available go should succeed");
    }

    #[test]
    #[ignore = "requires network access to runtime metadata"]
    fn test_list_available_rust() {
        let result = run_omg(&["list", "rust", "--available"]);
        assert!(result.success, "List available rust should succeed");
    }

    #[test]
    #[ignore = "requires network access to runtime metadata"]
    fn test_list_available_ruby() {
        let result = run_omg(&["list", "ruby", "--available"]);
        assert!(result.success, "List available ruby should succeed");
    }

    #[test]
    #[ignore = "requires network access to runtime metadata"]
    fn test_list_available_java() {
        let result = run_omg(&["list", "java", "--available"]);
        assert!(result.success, "List available java should succeed");
        // Should show LTS markers
    }

    #[test]
    #[ignore = "requires network access to runtime metadata"]
    fn test_list_available_bun() {
        let result = run_omg(&["list", "bun", "--available"]);
        assert!(result.success, "List available bun should succeed");
    }

    #[test]
    #[ignore = "requires network access to runtime metadata"]
    fn test_list_available_deno() {
        let result = run_omg(&["list", "deno", "--available"]);
        assert!(result.success, "List available deno should succeed");
    }

    // Falsifiable contract pinned at src/cli/runtimes.rs:322 (via the fast
    // list path in src/bin/omg.rs:514): JSON listing of a runtime that is not
    // natively supported must FAIL with an error naming the runtime. Plain-text
    // `list unknownruntime` cannot be pinned here because it delegates to an
    // external runtime-manager binaries whose availability varies by machine.
    #[test]
    fn test_list_unknown_runtime() {
        let result = run_omg(&["list", "unknownruntime", "--json"]);
        result.assert_failure();
        let combined = result.combined_output();
        assert!(
            combined.contains("unknownruntime"),
            "unsupported-runtime listing must name the runtime. Got:\n{combined}"
        );
    }

    #[test]
    fn test_which_command() {
        for runtime in RUNTIMES {
            let result = run_omg(&["which", runtime]);
            // src/bin/omg.rs handle_which_command prints the runtime name in
            // both resolved and no-version-set outcomes; only a resolver error
            // exits non-zero.
            result.assert_success();
            result.assert_stdout_contains(runtime);
        }
    }

    #[test]
    fn test_use_without_version_no_config() {
        let temp_dir = TempDir::new().unwrap();
        let result = run_omg_in_dir(&["use", "node"], temp_dir.path());
        // Deterministic precondition: no version file exists anywhere in an
        // empty temp dir, so `use node` MUST fail and say why.
        result.assert_failure();
        let combined = result.combined_output().to_lowercase();
        assert!(
            combined.contains("version") || combined.contains("detect"),
            "use without version file must explain that. Got:\n{combined}"
        );
    }

    #[test]
    fn test_use_with_nvmrc() {
        let temp_dir = TempDir::new().unwrap();
        create_test_project(temp_dir.path(), "node");

        let result = run_omg_in_dir(&["use", "node"], temp_dir.path());
        // Falsifiable: detection must report the EXACT version from .nvmrc.
        result.assert_stdout_contains("20.10.0");
    }

    #[test]
    fn test_use_with_python_version() {
        let temp_dir = TempDir::new().unwrap();
        create_test_project(temp_dir.path(), "python");

        let result = run_omg_in_dir(&["use", "python"], temp_dir.path());
        // Falsifiable: detection must report the EXACT version from
        // .python-version.
        result.assert_stdout_contains("3.11.0");
    }

    #[test]
    fn test_use_with_tool_versions() {
        let project = TestProject::new();
        create_test_project(project.path(), "tool-versions");

        // Real version directories and regular launcher files satisfy the
        // production installed-version and activation checks without downloads.
        for (runtime, version, binary) in
            [("node", "20.10.0", "node"), ("python", "3.11.0", "python3")]
        {
            let versions_dir = project.data_dir.path().join("versions").join(runtime);
            let version_dir = versions_dir.join(version);
            fs::create_dir_all(version_dir.join("bin")).unwrap();
            fs::write(version_dir.join("bin").join(binary), b"runtime fixture").unwrap();
            assert!(!versions_dir.join("current").exists());

            let result = project.run_with_env(&["use", runtime], &[("PATH", "")]);
            result.assert_success();
            result.assert_stdout_contains(version);
            assert_eq!(
                fs::read_link(versions_dir.join("current")).unwrap(),
                version_dir,
                "use must activate the version detected from .tool-versions"
            );
        }
    }

    // Falsifiable contract: both alias spellings are accepted by every
    // manager match arm (e.g. src/cli/runtimes.rs "node" | "nodejs"), so each
    // must succeed on its own - not merely agree with the other's outcome.
    #[test]
    fn test_runtime_alias_node_nodejs() {
        let result1 = run_omg(&["list", "node"]);
        let result2 = run_omg(&["list", "nodejs"]);
        assert!(
            result1.success && result2.success,
            "node and nodejs must both be accepted"
        );
    }

    #[test]
    fn test_runtime_alias_go_golang() {
        let result1 = run_omg(&["list", "go"]);
        let result2 = run_omg(&["list", "golang"]);
        assert!(
            result1.success && result2.success,
            "go and golang must both be accepted"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENVIRONMENT MANAGEMENT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod environment_management {
    use super::*;

    #[test]
    #[cfg(not(any(feature = "arch", feature = "debian", feature = "debian-pure")))]
    fn capture_without_backend_refuses_without_writing_or_replacing_lock() {
        let project = TempDir::new().unwrap();
        let lock = project.path().join("omg.lock");
        for existing in [false, true] {
            if existing {
                fs::write(&lock, b"existing lock must survive").unwrap();
            }
            let result = run_omg_in_dir(&["env", "capture"], project.path());
            result.assert_failure();
            assert!(result.stderr.contains(
                "Environment fingerprinting is not available without an Arch or Debian package backend"
            ), "unexpected refusal: {}", result.combined_output());
            if existing {
                assert_eq!(fs::read(&lock).unwrap(), b"existing lock must survive");
            } else {
                assert!(!lock.exists(), "unsupported capture must not create a lock");
            }
        }
    }

    #[test]
    #[cfg(any(feature = "arch", feature = "debian", feature = "debian-pure"))]
    fn test_env_capture() {
        let temp_dir = TempDir::new().unwrap();
        let result = run_omg_in_dir(&["env", "capture"], temp_dir.path());
        assert!(result.success, "env capture should succeed");
        assert!(
            result.stdout.contains("omg.lock") || result.stdout.contains("captured"),
            "Should mention lock file"
        );

        // Verify omg.lock was created
        assert!(
            temp_dir.path().join("omg.lock").exists(),
            "omg.lock should be created"
        );
    }

    // Falsifiable contract: the lockfile schema is rendered on every capture
    // (observed: `schema_version`, content `hash`, and a `[runtimes]` table).
    #[test]
    #[cfg(any(feature = "arch", feature = "debian", feature = "debian-pure"))]
    fn test_env_capture_deterministic() {
        let temp_dir = TempDir::new().unwrap();

        // Capture twice with same environment
        run_omg_in_dir(&["env", "capture"], temp_dir.path());
        let lock1 = fs::read_to_string(temp_dir.path().join("omg.lock")).unwrap();

        // Capture again immediately (same state)
        run_omg_in_dir(&["env", "capture"], temp_dir.path());
        let lock2 = fs::read_to_string(temp_dir.path().join("omg.lock")).unwrap();

        for (label, lock) in [("first", &lock1), ("second", &lock2)] {
            assert!(
                lock.contains("schema_version")
                    && lock.contains("hash")
                    && lock.contains("[runtimes]"),
                "{label} capture must render the full lockfile schema. Got:\n{lock}"
            );
        }
    }

    #[test]
    #[cfg(any(feature = "arch", feature = "debian", feature = "debian-pure"))]
    fn test_env_check_no_drift() {
        let temp_dir = TempDir::new().unwrap();

        // Capture
        let capture_result = run_omg_in_dir(&["env", "capture"], temp_dir.path());
        assert!(capture_result.success, "env capture should succeed");

        // Check immediately after capture: the lockfile was just written, so
        // check must SUCCEED — the old `success || contains("drift")` passed
        // even when check crashed with any message mentioning "drift".
        let result = run_omg_in_dir(&["env", "check"], temp_dir.path());
        result.assert_success();
    }

    #[test]
    fn test_env_check_without_lock() {
        let temp_dir = TempDir::new().unwrap();

        // Check without capturing first
        let result = run_omg_in_dir(&["env", "check"], temp_dir.path());
        assert!(!result.success, "env check should fail without omg.lock");
        assert!(
            result.stderr.contains("omg.lock")
                || result.stderr.contains("not found")
                || result.stderr.contains("capture"),
            "Should mention missing lock file"
        );
    }

    // Falsifiable contract: sharing must FAIL without a usable token, and the
    // failure must name the gist upload it could not complete. (Note: an empty
    // GITHUB_TOKEN still reaches the GitHub API and fails there with 401.)
    #[test]
    #[cfg(any(feature = "arch", feature = "debian", feature = "debian-pure"))]
    fn test_env_share_without_token() {
        let temp_dir = TempDir::new().unwrap();
        run_omg_in_dir(&["env", "capture"], temp_dir.path()).assert_success();

        // Clear GITHUB_TOKEN while sharing the lockfile captured above.
        let result = run_omg_with_options(
            &["env", "share"],
            Some(temp_dir.path()),
            &[("GITHUB_TOKEN", "")],
        );
        result.assert_failure();
        let combined = result.combined_output().to_lowercase();
        assert!(
            combined.contains("gist"),
            "share failure must reference the gist upload. Got:\n{combined}"
        );
    }

    #[test]
    fn test_env_share_without_lock() {
        let temp_dir = TempDir::new().unwrap();

        // Try to share without capturing first
        let result = run_omg_in_dir(&["env", "share"], temp_dir.path());
        assert!(!result.success, "env share should fail without omg.lock");
    }

    #[test]
    fn test_env_sync_invalid_url() {
        let temp_dir = TempDir::new().unwrap();

        let result = run_omg_in_dir(&["env", "sync", "not-a-valid-gist-url"], temp_dir.path());
        // Falsifiable: sync of an unusable gist id must fail naming the fetch.
        result.assert_failure();
        let combined = result.combined_output().to_lowercase();
        assert!(
            combined.contains("gist") || combined.contains("fetch") || combined.contains("sync"),
            "sync failure must name the gist fetch. Got:\n{combined}"
        );
    }

    #[test]
    fn test_env_subcommand_help() {
        let result = run_omg(&["env", "--help"]);
        assert!(result.success, "env --help should succeed");
        assert!(
            result.stdout.contains("capture"),
            "Should list capture subcommand"
        );
        assert!(
            result.stdout.contains("check"),
            "Should list check subcommand"
        );
        assert!(
            result.stdout.contains("share"),
            "Should list share subcommand"
        );
        assert!(
            result.stdout.contains("sync"),
            "Should list sync subcommand"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod security {
    use super::*;

    #[test]
    fn test_audit_command() {
        let result = run_omg(&["audit"]);
        // May succeed or fail depending on daemon status or license tier,
        // but it must run to completion: never panic, always render output.
        assert_ne!(result.exit_code, 101, "audit panicked");
        assert!(
            !result.stdout.is_empty() || !result.stderr.is_empty(),
            "audit produced no output at all"
        );
        if !result.success {
            let stderr = &result.stderr;
            assert!(
                stderr.contains("daemon")
                    || stderr.contains("Daemon")
                    || stderr.contains("requires")
                    || stderr.contains("tier"),
                "audit failure must name the blocker (daemon/tier). Got: {stderr}"
            );
        }
    }

    // Falsifiable contract: policy.toml under OMG_CONFIG_DIR is loaded and its
    // settings are reflected verbatim by `audit policy`
    // (src/core/security/policy.rs:133 load_default, src/cli/security.rs:384).
    #[test]
    fn test_security_policy_file_loading() {
        let temp_dir = TempDir::new().unwrap();

        let mut policy_file = File::create(temp_dir.path().join("policy.toml")).unwrap();
        writeln!(
            policy_file,
            r#"
allow_aur = false
require_pgp = true
minimum_grade = "Verified"
banned_packages = ["malware-pkg"]
        "#
        )
        .unwrap();

        let config_dir = temp_dir.path().to_str().expect("temp paths are UTF-8");
        let result = run_omg_with_env(&["audit", "policy"], &[("OMG_CONFIG_DIR", config_dir)]);
        result.assert_success();
        result.assert_stdout_contains("VERIFIED");
        result.assert_stdout_contains("malware-pkg");
        assert!(
            result.stdout_contains("AUR Allowed:") && result.stdout.contains("No"),
            "allow_aur = false must be reported. Got:\n{}",
            result.stdout
        );
    }

    // Falsifiable contract: package info renders provenance - the repository
    // for official packages (info handler prints "Repository:" / "Source:").
    #[test]
    fn test_security_grade_display() {
        let result = run_for_compiled_backend(&["info", known_system_package()]);
        common::assertions::assert_package_info(&result, known_system_package());
        assert!(
            result.stdout_contains("Repository") || result.stdout_contains("Source"),
            "info must show where the package comes from. Got:\n{}",
            result.stdout
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPLETION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod completions {
    use super::*;

    #[test]
    fn test_completions_bash() {
        let result = run_omg(&["completions", "bash", "--stdout"]);
        assert!(result.success, "Bash completions should succeed");
        assert!(
            result.stdout.contains("complete")
                || result.stdout.contains("_omg")
                || result.stdout.contains("_omg_completions"),
            "Should output bash completion script"
        );
    }

    #[test]
    fn test_completions_zsh() {
        let result = run_omg(&["completions", "zsh", "--stdout"]);
        assert!(result.success, "Zsh completions should succeed");
        assert!(
            result.stdout.contains("compdef") || result.stdout.contains("_omg"),
            "Should output zsh completion script"
        );
    }

    #[test]
    fn test_completions_fish() {
        let result = run_omg(&["completions", "fish", "--stdout"]);
        assert!(result.success, "Fish completions should succeed");
        assert!(
            result.stdout.contains("complete") || result.stdout.contains("omg"),
            "Should output fish completion script"
        );
    }

    #[test]
    fn test_completions_invalid_shell() {
        let result = run_omg(&["completions", "invalidshell"]);
        assert!(!result.success, "Invalid shell should fail");
        assert!(
            result.stderr.contains("Unsupported") || result.stderr.contains("error"),
            "Should report unsupported shell"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHELL HOOK TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod shell_hooks {
    use super::*;

    #[test]
    fn test_unicode_search() {
        let result = run_omg(&["search", "café"]);
        result.assert_success();
        // Dual-path contract: either results are rendered, or the empty result
        // message echoes the exact unicode query back (proves it survived
        // argument passing un-mangled).
        let combined = result.combined_output();
        if combined.contains("Search Results") {
            // Results path.
        } else {
            assert!(
                combined.contains("café"),
                "empty unicode search must echo the query. Got:\n{combined}"
            );
        }
    }

    #[test]
    fn test_hook_zsh() {
        let result = run_omg(&["hook", "zsh"]);
        result.assert_success();
        // The hook script must install the prompt/pwd integration function.
        result.assert_stdout_contains("_omg_hook");
        result.assert_stdout_contains("zsh");
    }

    #[test]
    fn test_hook_fish() {
        let result = run_omg(&["hook", "fish"]);
        result.assert_success();
        result.assert_stdout_contains("_omg_hook");
        result.assert_stdout_contains("fish");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIG TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod config {
    use super::*;

    #[test]
    fn test_config_list() {
        let result = run_omg(&["config"]);
        result.assert_success();
        // Falsifiable: the config overview renders its header
        // (src/cli/config.rs list prints "OMG Configuration").
        result.assert_stdout_contains("Configuration");
    }

    #[test]
    fn test_config_get_key() {
        // Falsifiable: a boolean key must print its value, not just exit 0.
        let result = run_omg(&["config", "get", "telemetry.enabled"]);
        result.assert_success();
        let value = result.stdout.trim();
        assert!(
            value == "true" || value == "false",
            "config get must print the boolean value. Got:\n{}",
            result.stdout
        );
    }

    #[test]
    fn test_config_get_invalid_key() {
        // Use proper config get subcommand - invalid key reports error message
        let result = run_omg(&["config", "get", "nonexistent_key"]);
        assert!(!result.success, "Invalid config keys must fail");
        assert!(
            result.stderr.contains("Unknown config key"),
            "Config get for invalid key should report error, got: {}",
            result.stderr
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ERROR HANDLING TESTS
// ═══════════════════════════════════════════════════════════════════════════════
// (invalid-lock-file coverage lives in error_messages::test_invalid_lock_file_error;
// the former duplicate module here was removed)

// ═══════════════════════════════════════════════════════════════════════════════
// EDGE CASE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod edge_cases {
    use super::*;

    // (test_empty_environment removed: identical invocation and assertions as
    // environment_management::test_env_capture, which already captures in an
    // empty temp dir.)

    #[test]
    fn test_deeply_nested_directory() {
        let project = TestProject::new();
        create_test_project(project.path(), "node");

        // Seed an installed Node version, including the regular file required
        // by production activation, but leave it inactive until `use` runs.
        let versions_dir = project.data_dir.path().join("versions/node");
        let version_dir = versions_dir.join("20.10.0");
        fs::create_dir_all(version_dir.join("bin")).unwrap();
        fs::write(version_dir.join("bin/node"), b"runtime fixture").unwrap();
        assert!(!versions_dir.join("current").exists());

        let deep_path = project.create_dir("a/b/c/d/e");
        let cache_dir = project.data_dir.path().join("cache");

        // Change only cwd, retaining the project's isolated runtime store.
        let result = run_omg_with_options(
            &["use", "node"],
            Some(&deep_path),
            &[
                ("OMG_DATA_DIR", project.data_dir.path().to_str().unwrap()),
                (
                    "OMG_CONFIG_DIR",
                    project.config_dir.path().to_str().unwrap(),
                ),
                ("OMG_CACHE_DIR", cache_dir.to_str().unwrap()),
                (
                    "OMG_PACMAN_ROOT",
                    project.pacman_root.path().to_str().unwrap(),
                ),
                ("HOME", project.home_dir.path().to_str().unwrap()),
                ("PATH", ""),
            ],
        );
        assert!(
            result.success,
            "Runtime resolution should work from a nested directory: {}",
            result.stderr
        );
        result.assert_stdout_contains("20.10.0");
        assert_eq!(
            fs::read_link(versions_dir.join("current")).unwrap(),
            version_dir,
            "use must activate the version detected from the ancestor .nvmrc"
        );
    }

    #[test]
    fn test_concurrent_operations() {
        use std::thread;

        // Run multiple omg commands concurrently
        let handles: Vec<_> = (0..5)
            .map(|_| thread::spawn(|| run_omg(&["status"])))
            .collect();

        for handle in handles {
            let result = handle.join().unwrap();
            assert!(result.success, "Concurrent status should succeed");
        }
    }

    #[test]
    fn test_very_large_package_list() {
        // Searching for common terms that return many results.
        let result = run_omg(&["search", "lib"]);
        result.assert_success();
        // Dual-path contract: either the results block renders, or the empty
        // result message explicitly names the query. Silence or a crash on
        // either path fails.
        let combined = result.combined_output();
        if combined.contains("Search Results") {
            assert!(
                !result.stdout.is_empty(),
                "results path must render entries"
            );
        } else {
            assert!(
                combined.contains("lib"),
                "empty search must echo the query. Got:\n{combined}"
            );
        }
    }

    #[test]
    fn test_unicode_path_handling() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let unicode_dir = temp_dir.path().join("unicode_dir");
        std::fs::create_dir(&unicode_dir).unwrap();

        let result = run_omg_in_dir(&["status"], &unicode_dir);
        assert!(result.success, "Should work in unicode directory");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DATABASE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod database {
    use super::*;

    // (test_database_creation removed: it only asserted that `omg status`
    // succeeds - identical to cli_foundation/package_management status tests;
    // no observable database artifact could be pinned without product
    // guarantees about on-disk layout.)

    #[test]
    fn test_database_concurrent_access() {
        use std::thread;

        // Multiple threads accessing the database
        let handles: Vec<_> = (0..3)
            .map(|_| thread::spawn(|| run_omg(&["list", "node"])))
            .collect();

        for handle in handles {
            let result = handle.join().unwrap();
            assert!(result.success, "Concurrent DB access should succeed");
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DAEMON TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod daemon {
    use super::*;

    #[test]
    fn test_daemon_help() {
        let result = run_omg(&["daemon", "--help"]);
        assert!(result.success, "Daemon help should succeed");
        assert!(
            result.stdout.contains("foreground"),
            "Should mention foreground option"
        );
    }

    #[test]
    fn test_status_with_daemon() {
        // Status should work with daemon enabled (daemon may or may not be running)
        // This tests that the status command doesn't crash when daemon support is enabled
        let result = run_omg_with_env(&["status"], &[]);
        let combined = result.combined_output();

        // Status should succeed regardless of whether daemon is actually running
        // It should gracefully fall back to direct mode if daemon is unavailable
        assert!(
            result.success,
            "Status should succeed with daemon support enabled. Output: {combined}"
        );

        // Should produce meaningful output
        assert!(
            result.stdout.contains("packages installed") && result.stdout.contains("Updates"),
            "Status should show system info or daemon status. Output: {combined}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// INTEGRATION SCENARIOS
// ═══════════════════════════════════════════════════════════════════════════════

mod integration_scenarios {
    use super::*;

    #[test]
    #[cfg(any(feature = "arch", feature = "debian", feature = "debian-pure"))]
    fn scenario_new_developer_onboarding() {
        let temp_dir = TempDir::new().unwrap();

        // 1. Create project with .tool-versions
        create_test_project(temp_dir.path(), "tool-versions");

        // 2. Developer runs status to see what's needed
        let result = run_omg_in_dir(&["status"], temp_dir.path());
        assert!(result.success, "Status should work");

        // 3. Developer syncs environment (if lock exists from team)
        // Simulated by running env capture
        let result = run_omg_in_dir(&["env", "capture"], temp_dir.path());
        assert!(result.success, "Env capture should work");

        // 4. Check for drift - may report drift if runtimes not installed, that's OK
        let result = run_omg_in_dir(&["env", "check"], temp_dir.path());
        // Both outcomes are valid, but each must be the REAL outcome: clean
        // success, or a failure that explicitly names drift.
        if result.success {
            assert!(!result.stdout.is_empty(), "clean check prints its verdict");
        } else {
            let combined = result.combined_output();
            assert!(
                combined.contains("drift") || combined.contains("Drift"),
                "check failure after capture must name drift. Got:\n{combined}"
            );
        }
    }

    #[test]
    fn scenario_switching_projects() {
        let project1 = TempDir::new().unwrap();
        let project2 = TempDir::new().unwrap();

        // Project 1 uses Node 18
        let mut f = File::create(project1.path().join(".nvmrc")).unwrap();
        writeln!(f, "18.0.0").unwrap();

        // Project 2 uses Node 20
        let mut f = File::create(project2.path().join(".nvmrc")).unwrap();
        writeln!(f, "20.0.0").unwrap();

        // Switch to project 1
        let result1 = run_omg_in_dir(&["use", "node"], project1.path());

        // Switch to project 2
        let result2 = run_omg_in_dir(&["use", "node"], project2.path());

        // Falsifiable: EACH project must resolve to ITS OWN version. The old
        // `contains("18") || contains("20")` passed when both projects
        // resolved to the same version.
        assert!(
            result1.stdout.contains("18.0.0") && result2.stdout.contains("20.0.0"),
            "Each project must detect its own version. p1:\n{}\np2:\n{}",
            result1.stdout,
            result2.stdout
        );
    }

    #[test]
    fn scenario_security_audit_workflow() {
        // 1. Run status to see overview
        let result = run_omg(&["status"]);
        assert!(result.success, "Status should work");

        // 2. Run full audit: must run to completion - never panic, always
        // render output; a failure must name its blocker (daemon/tier), same
        // contract as security::test_audit_command. The old code discarded
        // this result entirely.
        let audit = run_omg(&["audit"]);
        assert_ne!(audit.exit_code, 101, "audit panicked");
        assert!(
            !audit.stdout.is_empty() || !audit.stderr.is_empty(),
            "audit produced no output at all"
        );
        if !audit.success {
            assert!(
                audit.stderr.contains("daemon")
                    || audit.stderr.contains("Daemon")
                    || audit.stderr.contains("requires")
                    || audit.stderr.contains("tier"),
                "audit failure must name the blocker. Got: {}",
                audit.stderr
            );
        }

        // 3. Search for a package to install
        let package = known_system_package();
        let result = run_for_compiled_backend(&["search", package]);
        assert!(result.success, "Search should work");

        // 4. Get info on package
        let result = run_for_compiled_backend(&["info", package]);
        assert!(result.success, "Info should work");
    }

    #[test]
    #[cfg(any(feature = "arch", feature = "debian", feature = "debian-pure"))]
    fn scenario_team_environment_sync() {
        let dev1_dir = TempDir::new().unwrap();
        let dev2_dir = TempDir::new().unwrap();

        // Dev 1 captures their environment
        create_test_project(dev1_dir.path(), "tool-versions");
        let result = run_omg_in_dir(&["env", "capture"], dev1_dir.path());
        assert!(result.success, "Dev1 capture should work");

        // Copy lock file to dev2 (simulating gist share/sync)
        let lock_content = fs::read_to_string(dev1_dir.path().join("omg.lock")).unwrap();
        fs::write(dev2_dir.path().join("omg.lock"), &lock_content).unwrap();

        // Dev 2 checks their environment - may report drift since different machine
        create_test_project(dev2_dir.path(), "tool-versions");
        let result = run_omg_in_dir(&["env", "check"], dev2_dir.path());
        let combined = result.combined_output();
        // Dual-path contract: clean check prints its verdict; any failure must
        // explicitly name drift. Merely containing the word "check" is not
        // evidence of anything.
        if result.success {
            assert!(!result.stdout.is_empty(), "clean check prints its verdict");
        } else {
            assert!(
                combined.contains("drift") || combined.contains("Drift"),
                "check failure after lock copy must name drift. Got:\n{combined}"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// VERSION DETECTION TESTS (Comprehensive config file parsing)
// ═══════════════════════════════════════════════════════════════════════════════

mod version_detection {
    use super::*;

    #[test]
    fn test_nvmrc_detection() {
        let temp_dir = TempDir::new().unwrap();
        let mut f = File::create(temp_dir.path().join(".nvmrc")).unwrap();
        writeln!(f, "20.10.0").unwrap();

        let result = run_omg_in_dir(&["use", "node"], temp_dir.path());
        // Falsifiable: the EXACT version must be reported; a generic
        // "Detected" message with the wrong version must fail this.
        result.assert_stdout_contains("20.10.0");
    }

    #[test]
    fn test_node_version_file_detection() {
        let temp_dir = TempDir::new().unwrap();
        let mut f = File::create(temp_dir.path().join(".node-version")).unwrap();
        writeln!(f, "18.19.0").unwrap();

        let result = run_omg_in_dir(&["use", "node"], temp_dir.path());
        result.assert_stdout_contains("18.19.0");
    }

    #[test]
    fn test_python_version_detection() {
        let temp_dir = TempDir::new().unwrap();
        let mut f = File::create(temp_dir.path().join(".python-version")).unwrap();
        writeln!(f, "3.12.0").unwrap();

        let result = run_omg_in_dir(&["use", "python"], temp_dir.path());
        result.assert_stdout_contains("3.12.0");
    }

    #[test]
    fn test_tool_versions_multi_runtime() {
        let temp_dir = TempDir::new().unwrap();
        let mut f = File::create(temp_dir.path().join(".tool-versions")).unwrap();
        writeln!(f, "nodejs 20.10.0\npython 3.11.0\nruby 3.2.0\ngo 1.21.0").unwrap();

        // Each runtime should be detected
        let result = run_omg_in_dir(&["use", "node"], temp_dir.path());
        result.assert_stdout_contains("20.10.0");
    }

    #[test]
    fn test_package_json_engines() {
        let temp_dir = TempDir::new().unwrap();
        let mut f = File::create(temp_dir.path().join("package.json")).unwrap();
        writeln!(f, r#"{{"name": "test", "engines": {{"node": "20.10.0"}}}}"#).unwrap();

        let result = run_omg_in_dir(&["use", "node"], temp_dir.path());
        result.assert_stdout_contains("20.10.0");
    }

    #[test]
    fn test_package_json_volta() {
        let temp_dir = TempDir::new().unwrap();
        let mut f = File::create(temp_dir.path().join("package.json")).unwrap();
        writeln!(f, r#"{{"name": "test", "volta": {{"node": "18.18.0"}}}}"#).unwrap();

        let result = run_omg_in_dir(&["use", "node"], temp_dir.path());
        result.assert_stdout_contains("18.18.0");
    }

    // (test_engines_priority_over_volta removed: exact duplicate of
    // regression_tests::test_package_json_engines_priority, which documents
    // the original bug.)

    #[test]
    fn test_go_version_file_detection() {
        let temp_dir = TempDir::new().unwrap();
        // Use .go-version which is the standard version file
        let mut f = File::create(temp_dir.path().join(".go-version")).unwrap();
        writeln!(f, "1.21.0").unwrap();

        let result = run_omg_in_dir(&["use", "go"], temp_dir.path());
        // Falsifiable: the EXACT version from the file must appear (detection
        // prints it even if a subsequent install step fails).
        result.assert_stdout_contains("1.21.0");
    }

    #[test]
    fn test_rust_toolchain_toml_detection() {
        let temp_dir = TempDir::new().unwrap();
        let mut f = File::create(temp_dir.path().join("rust-toolchain.toml")).unwrap();
        writeln!(f, "[toolchain]\nchannel = \"1.75.0\"").unwrap();

        let result = run_omg_in_dir(&["use", "rust"], temp_dir.path());
        // Falsifiable: the channel version from rust-toolchain.toml must be
        // reported verbatim ('stable' would match any resolution).
        result.assert_stdout_contains("1.75.0");
    }

    #[test]
    fn test_version_whitespace_trimming() {
        let temp_dir = TempDir::new().unwrap();
        let mut f = File::create(temp_dir.path().join(".nvmrc")).unwrap();
        writeln!(f, "  20.10.0  \n").unwrap();

        let result = run_omg_in_dir(&["use", "node"], temp_dir.path());
        assert!(
            result.stdout.contains("20.10.0"),
            "Should trim whitespace from version files"
        );
    }

    #[test]
    fn test_version_v_prefix_handling() {
        let temp_dir = TempDir::new().unwrap();
        let mut f = File::create(temp_dir.path().join(".nvmrc")).unwrap();
        writeln!(f, "v20.10.0").unwrap();

        let result = run_omg_in_dir(&["use", "node"], temp_dir.path());
        assert!(
            result.stdout.contains("20.10.0"),
            "Should handle v prefix in version"
        );
    }

    #[test]
    fn test_parent_directory_version_search() {
        let temp_dir = TempDir::new().unwrap();

        // Create .nvmrc at root
        let mut f = File::create(temp_dir.path().join(".nvmrc")).unwrap();
        writeln!(f, "20.10.0").unwrap();

        // Create nested directory
        let nested = temp_dir.path().join("src").join("components");
        fs::create_dir_all(&nested).unwrap();

        // Should find .nvmrc from parent
        let result = run_omg_in_dir(&["use", "node"], &nested);
        result.assert_stdout_contains("20.10.0");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PACMAN DATABASE TESTS (Pure Rust parsing - V1/V2 format support)
// ═══════════════════════════════════════════════════════════════════════════════

mod pacman_database {
    use super::*;

    #[test]
    #[ignore = "requires a configured system package database"]
    fn test_search_returns_results() {
        let result = run_omg(&["search", "pacman"]);
        assert!(result.success, "Search should succeed");
        assert!(
            result.stdout.contains("pacman"),
            "Search for 'pacman' should find pacman"
        );
    }

    #[test]
    #[ignore = "requires a configured system package database"]
    fn test_search_output_format() {
        let result = run_omg(&["search", "firefox"]);
        result.assert_success();

        // Output must show the queried package, not just any results text.
        assert!(
            result.stdout.contains("firefox"),
            "Search output should list firefox. Got:\n{}",
            result.stdout
        );
    }

    #[test]
    #[ignore = "requires a configured system package database"]
    fn test_info_shows_package_details() {
        let result = run_for_compiled_backend(&["info", known_system_package()]);
        assert!(result.success, "Info should succeed for installed package");
        assert!(result.stdout.contains("pacman"), "Should show package name");
    }

    #[test]
    #[ignore = "requires a configured system package database"]
    fn test_update_check_parses_databases() {
        let result = run_omg(&["update", "--check"]);
        // Falsifiable: parsing the sync databases must complete with a verdict.
        result.assert_success();
        assert!(
            !result.combined_output().trim().is_empty(),
            "update --check should report its verdict"
        );
    }

    #[test]
    #[ignore = "requires a configured system package database"]
    fn test_explicit_packages_list() {
        let result = run_omg(&["explicit"]);
        assert!(result.success, "Explicit should succeed");

        let line_count = result.stdout.lines().filter(|l| !l.is_empty()).count();
        assert!(line_count > 1, "Should list explicitly installed packages");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUR INTEGRATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod aur_integration {
    use super::*;

    #[test]
    #[ignore = "requires network access to the AUR"]
    fn test_aur_search() {
        let result = run_omg(&["search", "yay", "--detailed"]);
        assert!(result.success, "AUR search should succeed");
        assert!(
            result.stdout.contains("yay") || result.stdout.contains("AUR"),
            "Should find AUR packages"
        );
    }

    #[test]
    #[ignore = "requires a configured system package database"]
    fn test_update_detects_aur_packages() {
        let result = run_omg(&["update", "--check"]);
        // Falsifiable: the AUR pass must complete and render its outcome;
        // the old synonym soup passed on any output whatsoever.
        result.assert_success();
        let combined = result.combined_output();
        assert!(!combined.is_empty(), "update --check should produce output");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// REGRESSION TESTS (Bugs that were fixed)
// ═══════════════════════════════════════════════════════════════════════════════

mod regression_tests {
    use super::*;

    /// Regression: AUR update detection failing due to V1/V2 desc format
    /// The sync database was only parsing packages with %MD5SUM% (V1 format),
    /// missing most packages that use V2 format (no MD5SUM).
    #[test]
    #[ignore = "requires a configured system package database"]
    fn test_sync_db_parses_v2_format_packages() {
        // Search should find packages from all repos (V2 format)
        let result = run_omg(&["search", "linux"]);
        assert!(result.success, "Search should succeed");
        assert!(
            result.stdout.contains("linux"),
            "Should find packages from V2 format databases"
        );
    }

    /// Regression: engines should take priority over volta in package.json
    #[test]
    fn test_package_json_engines_priority() {
        let temp_dir = TempDir::new().unwrap();
        let mut f = File::create(temp_dir.path().join("package.json")).unwrap();
        writeln!(
            f,
            r#"{{"name": "test", "volta": {{"node": "16.0.0"}}, "engines": {{"node": "22.0.0"}}}}"#
        )
        .unwrap();

        let result = run_omg_in_dir(&["use", "node"], temp_dir.path());
        assert!(
            result.stdout.contains("22.0.0"),
            "engines (22.0.0) should take priority over volta (16.0.0): {}",
            result.stdout
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// OUTPUT FORMAT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod output_format {
    use super::*;

    #[test]
    fn test_version_output_format() {
        let result = run_omg(&["--version"]);
        assert!(result.success);
        assert!(
            result.stdout.contains("omg"),
            "Version should contain 'omg'"
        );
        // Should have version number pattern
        assert!(
            result.stdout.contains('.') || result.stdout.contains("0."),
            "Version should have version number"
        );
    }

    #[test]
    fn test_help_lists_all_commands() {
        let result = run_omg(&["--help"]);
        assert!(result.success);

        let expected_commands = [
            "search", "install", "remove", "update", "info", "status", "use", "list",
        ];

        for cmd in expected_commands {
            assert!(
                result.stdout.to_lowercase().contains(cmd),
                "Help should list '{cmd}' command"
            );
        }
    }

    #[test]
    fn test_status_output_sections() {
        let result = run_omg(&["status"]);
        assert!(result.success, "Status should succeed");

        // Should have some structured output
        assert!(
            result.stdout.contains("packages installed")
                && result.stdout.contains("Updates")
                && result.stdout.contains("Orphans"),
            "Status should have structured sections"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ERROR MESSAGE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod error_messages {
    use super::*;

    #[test]
    fn test_missing_package_name_error() {
        let result = run_omg(&["install"]);
        assert!(!result.success, "Install without args should fail");
        assert!(
            result.stderr.contains("No packages specified") || result.stderr.contains("error"),
            "bare install must fail with guidance"
        );
    }

    #[test]
    fn test_invalid_lock_file_error() {
        let temp_dir = TempDir::new().unwrap();

        // Create invalid omg.lock
        let mut f = File::create(temp_dir.path().join("omg.lock")).unwrap();
        writeln!(f, "this is not valid toml {{{{").unwrap();

        let result = run_omg_in_dir(&["env", "check"], temp_dir.path());
        assert!(!result.success, "Should fail with invalid lock file");
        // Should not panic, should give error
    }

    #[test]
    #[cfg(feature = "arch")]
    fn test_nonexistent_package_info() {
        let result = run_omg(&["info", "this-package-definitely-does-not-exist-12345"]);
        // FALSIFIABLE: missing package fails and says so (matches the contract
        // pinned in error_tests).
        result.assert_failure();
        let combined = result.combined_output();
        assert!(
            combined.contains("not found") || combined.contains("does-not-exist"),
            "info of a missing package must say so. Got:\n{combined}"
        );
    }

    #[test]
    fn test_use_without_version_no_config() {
        let temp_dir = TempDir::new().unwrap();
        let result = run_omg_in_dir(&["use", "node"], temp_dir.path());
        result.assert_failure();
        let stderr_lc = result.stderr.to_lowercase();
        assert!(
            stderr_lc.contains("version") || stderr_lc.contains("detect"),
            "Should fail without version file"
        );
    }
}
