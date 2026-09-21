#![expect(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]
//! OMG Exhaustive CLI Matrix Test Suite
//!
//! This suite verifies every single CLI command across all supported OS flavors
//! using a high-fidelity synthetic mock environment.
//!
//! Goal: Test "absolute everything" without needing real root or real distros.

pub mod common;

use common::*;
use serial_test::serial;
use tempfile::TempDir;

#[cfg(feature = "arch")]
fn run_arch(args: &[&str]) -> CommandResult {
    run_omg_with_env(args, &[("OMG_TEST_DISTRO", "arch"), ("OMG_TEST_MODE", "1")])
}

#[cfg(any(feature = "debian", feature = "debian-pure"))]
fn run_debian(args: &[&str]) -> CommandResult {
    run_omg_with_env(
        args,
        &[("OMG_TEST_DISTRO", "debian"), ("OMG_TEST_MODE", "1")],
    )
}

// ═══════════════════════════════════════════════════════════════════════════════
// ARCH LINUX MATRIX
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "arch")]
mod arch_matrix {
    use super::*;

    #[test]
    #[serial]
    fn test_search() {
        let res = run_arch(&["search", "firefox"]);
        res.assert_success();
        res.assert_stdout_contains("firefox");
        // "Official" vs "official" depends on UI components
        assert!(
            res.stdout.to_lowercase().contains("official"),
            "stdout does not contain 'official' (case-insensitive)\nstdout: {}",
            res.stdout
        );
    }

    #[test]
    #[serial]
    fn test_info() {
        // Test mode resolves through the hermetic Arch mock and renders the
        // same key-value fields as the real sync-database path.
        let res = run_arch(&["info", "pacman"]);
        res.assert_success();
        res.assert_stdout_contains("pacman");
        res.assert_stdout_contains("Description:");
        res.assert_stdout_contains("Source:");
        res.assert_stdout_contains("Official repository");
    }

    #[test]
    #[serial]
    fn test_list() {
        // `list` is the runtime listing command; its header is part of the
        // rendered output on every path.
        let res = run_arch(&["list"]);
        res.assert_success();
        res.assert_stdout_contains("runtime versions");
    }

    #[test]
    #[serial]
    fn test_status() {
        let res = run_arch(&["status"]);
        res.assert_success();
        res.assert_stdout_contains("packages installed");
    }

    #[test]
    #[serial]
    fn test_explicit() {
        let res = run_arch(&["explicit"]);
        res.assert_success();
        res.assert_stdout_contains("Explicit Packages");
    }

    #[test]
    #[serial]
    fn test_install_remove_cycle() {
        let data_dir = TempDir::new().unwrap();
        let data_path = data_dir.path().to_str().unwrap();
        let envs = &[
            ("OMG_TEST_DISTRO", "arch"),
            ("OMG_TEST_MODE", "1"),
            ("OMG_DATA_DIR", data_path),
        ];

        // Test install
        let res = run_omg_with_env(&["install", "-y", "firefox"], envs);
        println!("Install stderr: {}", res.stderr);
        res.assert_success();

        // Test explicit now contains firefox
        let res = run_omg_with_env(&["explicit"], envs);
        println!("Explicit stderr: {}", res.stderr);
        res.assert_stdout_contains("firefox");

        // Test remove
        let res = run_omg_with_env(&["remove", "-y", "firefox"], envs);
        println!("Remove stderr: {}", res.stderr);
        res.assert_success();

        // Test explicit no longer contains firefox
        let res = run_omg_with_env(&["explicit"], envs);
        println!("Explicit after remove stderr: {}", res.stderr);
        assert!(!res.stdout.contains("firefox"));
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEBIAN MATRIX
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(any(feature = "debian", feature = "debian-pure"))]
mod debian_matrix {
    use super::*;

    #[test]
    #[serial]
    fn test_search() {
        let res = run_debian(&["search", "apt"]);
        res.assert_success();
        res.assert_stdout_contains("apt");
        // "Official" vs "official" depends on UI components
        assert!(
            res.stdout.to_lowercase().contains("official"),
            "stdout does not contain 'official' (case-insensitive)\nstdout: {}",
            res.stdout
        );
    }

    #[test]
    #[serial]
    fn test_info() {
        // Dual-path contract: success must display the resolved package,
        // failure must name the package as not found
        // (src/cli/packages/info.rs info_fallback bails with
        // "Package '{package}' not found").
        let res = run_debian(&["info", "apt"]);
        if res.success {
            res.assert_stdout_contains("apt");
        } else {
            res.assert_stderr_contains("not found");
        }
    }

    #[test]
    #[serial]
    fn test_status() {
        let res = run_debian(&["status"]);
        res.assert_success();
        res.assert_stdout_contains("packages installed");
    }

    #[test]
    #[serial]
    fn test_install_remove_cycle() {
        let data_dir = TempDir::new().unwrap();
        let data_path = data_dir.path().to_str().unwrap();
        let envs = &[
            ("OMG_TEST_DISTRO", "debian"),
            ("OMG_TEST_MODE", "1"),
            ("OMG_DATA_DIR", data_path),
        ];

        run_omg_with_env(&["install", "-y", "git"], envs).assert_success();
        run_omg_with_env(&["explicit"], envs).assert_stdout_contains("git");
        run_omg_with_env(&["remove", "-y", "git"], envs).assert_success();
        let res = run_omg_with_env(&["explicit"], envs);
        assert!(!res.stdout.contains("git"));
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// RUNTIME MATRIX (OS-Agnostic)
// ═══════════════════════════════════════════════════════════════════════════════

mod runtime_matrix {
    use super::*;

    #[test]
    #[serial]
    fn test_use_node_detection() {
        require_network_tests!();

        let project = TestProject::new();
        project.create_file(".nvmrc", "20.0.0");
        let res = project.run(&["use", "node"]);
        res.assert_success();
        res.assert_stdout_contains("20.0.0");
    }

    #[test]
    #[serial]
    fn test_use_python_detection() {
        require_network_tests!();

        let project = TestProject::new();
        project.create_file(".python-version", "3.12.0");
        let res = project.run(&["use", "python"]);
        res.assert_success();
        res.assert_stdout_contains("3.12.0");
    }

    #[test]
    #[serial]
    fn test_which_all_runtimes() {
        let runtimes = [
            "node", "python", "go", "rust", "ruby", "java", "bun", "deno",
        ];
        for rt in runtimes {
            let res = run_omg(&["which", rt]);
            res.assert_success();
            // Both outcomes mention the runtime: either the pinned version or
            // the "<rt>: no version set (...)" hint (src/bin/omg.rs:1022).
            res.assert_stdout_contains(rt);
        }
    }

    #[test]
    #[serial]
    #[cfg(any(feature = "arch", feature = "debian", feature = "debian-pure"))]
    fn test_env_workflow() {
        let project = TestProject::new();
        let data_dir = TempDir::new().unwrap();
        let data_path = data_dir.path().to_str().unwrap();
        let envs = &[
            ("OMG_TEST_DISTRO", "arch"),
            ("OMG_TEST_MODE", "1"),
            ("OMG_DATA_DIR", data_path),
        ];

        // Verify project path exists
        assert!(project.path().exists());

        // Capture
        let res = project.run_with_env(&["env", "capture"], envs);
        res.assert_success();

        // Print directory contents for debugging
        let entries = std::fs::read_dir(project.path())
            .unwrap()
            .map(|res| res.map(|e| e.file_name().into_string().unwrap()))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        println!("Project dir content: {entries:?}");

        assert!(project.file_exists("omg.lock"));

        // Check
        project
            .run_with_env(&["env", "check"], envs)
            .assert_success();
    }

    #[test]
    #[serial]
    fn test_doctor_command() {
        let res = run_omg(&["doctor"]);
        res.assert_success();
        res.assert_stdout_contains("Checking system health");
    }

    #[test]
    #[serial]
    fn test_config_workflow() {
        // List config: renders the configuration overview
        let listing = run_omg(&["config"]);
        listing.assert_success();
        listing.assert_stdout_contains("Configuration");

        // The harness disables telemetry explicitly for every child process.
        let get = run_omg(&["config", "get", "telemetry.enabled"]);
        get.assert_success();
        get.assert_stdout_contains("false");
    }

    #[test]
    #[serial]
    fn test_audit_command() {
        // Audit is not paywalled. Isolated runs typically fail because the
        // daemon is not running; they must never mention a paid tier.
        let res = run_omg(&["audit"]);
        let output = res.combined_output();
        assert!(
            !output.contains("requires Pro tier") && !output.contains("/pricing"),
            "audit must not be paywalled, got:\n{output}"
        );
    }

    #[test]
    #[serial]
    fn test_new_and_run_scaffolding() {
        let project = TestProject::new();

        // Scaffolding must succeed AND create the target project directory.
        let res = project.run(&["new", "rust", "my-app"]);
        res.assert_success();
        assert!(
            project.path().join("my-app").exists(),
            "`omg new rust my-app` must create my-app/"
        );
        res.assert_stdout_contains("my-app");

        // A Makefile task must execute through make and produce its output.
        project.create_file("Makefile", "test:\n\techo 'running tests'");
        let res = project.run(&["run", "test"]);
        res.assert_success();
        res.assert_stdout_contains("running tests");
        res.assert_no_ansi();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ERROR & BOUNDARY MATRIX
// ═══════════════════════════════════════════════════════════════════════════════

mod boundary_matrix {
    use super::*;

    #[test]
    #[serial]
    fn test_nonexistent_command() {
        let res = run_omg(&["unknown-cmd"]);
        res.assert_failure();
    }

    #[test]
    #[serial]
    fn test_invalid_package_name() {
        let res = run_omg(&["install", "invalid; name"]);
        res.assert_failure();
        res.assert_stderr_contains("Invalid character");
    }

    #[cfg(feature = "arch")]
    #[test]
    #[serial]
    fn test_empty_search() {
        // An empty query must not crash and must render the results view with
        // the mock catalog (src/package_managers/mock.rs arch_defaults).
        let res = run_arch(&["search", ""]);
        res.assert_success();
        res.assert_stdout_contains("| Search");
        res.assert_stdout_contains("pacman");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TEAM MATRIX
// ═══════════════════════════════════════════════════════════════════════════════

mod team_matrix {
    use super::*;

    #[test]
    #[serial]
    fn test_team_status() {
        // Local team status does not require a dashboard account.
        let project = TestProject::new();
        let res = project.run(&["team", "status"]);
        res.assert_failure();
        assert!(
            res.contains("Not a team workspace"),
            "expected workspace error, got:\n{}",
            res.combined_output()
        );
    }

    #[test]
    #[serial]
    fn test_team_init() {
        let project = TestProject::new();
        let res = project.run(&["team", "init", "test-team-id"]);
        res.assert_success();
        res.assert_stdout_contains("Team workspace initialized!");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// FLEET MATRIX
// ═══════════════════════════════════════════════════════════════════════════════

mod fleet_matrix {
    use super::*;

    #[test]
    #[serial]
    fn test_fleet_status() {
        // Fleet roster is a dashboard API; without a linked account it fails
        // with a link hint, not a paid-tier gate.
        let res = run_omg(&["fleet", "status"]);
        res.assert_failure();
        res.assert_stderr_contains("No dashboard account linked");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONTAINER MATRIX
// ═══════════════════════════════════════════════════════════════════════════════

mod container_matrix {
    use super::*;

    #[test]
    #[serial]
    fn test_container_status() {
        let empty_path = TempDir::new().unwrap();
        let path = empty_path.path().to_str().unwrap();
        let res = run_omg_with_env(&["container", "status"], &[("PATH", path)]);
        res.assert_failure();
        res.assert_stderr_contains("No container runtime detected");
    }

    #[test]
    #[serial]
    fn test_container_list_without_runtime_reports_actionable_error() {
        // Hide host Docker/Podman binaries so this contract does not depend on
        // whether the developer machine has a daemon or socket permission.
        let empty_path = TempDir::new().unwrap();
        let path = empty_path.path().to_str().unwrap();
        let res = run_omg_with_env(&["container", "list"], &[("PATH", path)]);
        res.assert_failure();
        res.assert_stderr_contains("No container runtime found");
    }
}
