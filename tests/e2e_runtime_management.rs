//! End-to-End Tests for Runtime Management
//!
//! Contracts under test (each assertion pins observable CLI behavior):
//! - `use`: switch runtime versions, resolve aliases (`latest`, `lts`),
//!   detect versions from project files (.nvmrc, .python-version, ...)
//! - `list`: installed and remote-available versions
//! - `hook`: per-shell integration scripts, rejection of unknown shells
//! - `which`: active-version reporting and required runtime argument
//!
//! Node/Python/Go version-file tests seed executable installed fixtures and
//! require successful activation, exact current paths and executable output.
//! These prove selection, not download/extraction.
//! Tests that genuinely download runtimes are gated behind
//! `require_network_tests!`; failures never count as successful downloads.

#![expect(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]

pub mod common;

use common::*;

/// Bound local selection and activation; a timeout is not a successful result.
const DETECTION_TIMEOUT_SECS: &str = "15";

/// Command cap for gated end-to-end installs (download + extract + switch).
const INSTALL_TIMEOUT_SECS: &str = "600";

fn run_capped(args: &[&str], timeout_secs: &str) -> CommandResult {
    run_omg_with_env(args, &[("OMG_TEST_COMMAND_TIMEOUT_SECS", timeout_secs)])
}

/// Assert the documented detection contract: `omg use <runtime>` without an
/// explicit version prints "Detected version <v> from file" for the pin found
/// in the project directory (src/cli/runtimes.rs:126).
///
/// The value and the phrase are matched separately because the CLI colorizes
/// the version string in place.
fn assert_detected(result: &CommandResult, version: &str) {
    let output = result.combined_output();
    assert!(
        !output.contains("panicked at"),
        "`omg use` must not panic:\n{output}"
    );
    assert!(
        output.contains("Detected version") && output.contains(version),
        "expected \"Detected version {version} from file\", got:\n{output}"
    );
}

fn seed_installed_runtime(project: &TestProject, runtime: &str, version: &str, executable: &str) {
    let binary = project
        .data_dir
        .path()
        .join(format!("versions/{runtime}/{version}/bin/{executable}"));
    std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
    std::fs::write(
        &binary,
        format!("#!/bin/sh\nprintf '%s\\n' 'fixture-{runtime}-{version}'\n"),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(binary, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

fn assert_active_runtime(
    project: &TestProject,
    result: &CommandResult,
    runtime: &str,
    version: &str,
    executable: &str,
) {
    result.assert_success();
    assert_detected(result, version);
    let base = project.data_dir.path().join(format!("versions/{runtime}"));
    let current = base.join(format!("current/bin/{executable}"));
    assert_eq!(
        std::fs::canonicalize(&current).unwrap(),
        std::fs::canonicalize(base.join(format!("{version}/bin/{executable}"))).unwrap(),
        "Detected version must become the active runtime"
    );
    #[cfg(unix)]
    {
        let output = std::process::Command::new(current).output().unwrap();
        assert!(output.status.success());
        assert_eq!(
            output.stdout,
            format!("fixture-{runtime}-{version}\n").as_bytes()
        );
    }
}

/// This proves an executable installation, not independent latest/LTS selection.
fn assert_downloaded_runtime(
    project: &TestProject,
    runtime: &str,
    requested: &str,
    executable: &str,
) {
    let base = project.data_dir.path().join(format!("versions/{runtime}"));
    let active = std::fs::canonicalize(base.join("current")).unwrap();
    assert_eq!(
        active.parent().unwrap(),
        std::fs::canonicalize(&base).unwrap()
    );
    let resolved = active.file_name().unwrap().to_str().unwrap();
    if !matches!(requested, "latest" | "lts") {
        assert_eq!(resolved, requested);
    }
    assert!(resolved.split('.').count() >= 3 && resolved.chars().next().unwrap().is_ascii_digit());
    let output = std::process::Command::new(active.join("bin").join(executable))
        .arg("--version")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "installed executable failed: {output:?}"
    );
    let expected = if runtime == "node" {
        format!("v{resolved}")
    } else {
        format!("Python {resolved}")
    };
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), expected);
    let listed = project.run(&["list", runtime]);
    listed.assert_success();
    assert!(listed.stdout.contains(resolved));
}

// ═══════════════════════════════════════════════════════════════════════════════
// USE COMMAND E2E TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_use_shows_help_when_no_args() {
    init_test_env();

    let result = run_omg(&["use", "--help"]);
    result.assert_success();
    result.assert_stdout_contains("Usage: omg use");
    result.assert_stdout_contains("Instantly switch runtime versions");
}

#[test]
fn every_supported_runtime_has_uninstall_dispatch() {
    init_test_env();

    let project = TestProject::new();
    for runtime in omg_lib::cli::runtimes::known_runtimes().unwrap() {
        let version = match runtime.as_str() {
            "rust" => "stable",
            "java" => "999",
            _ => "999.999.999",
        };
        let result = project.run(&["use", &runtime, version, "--uninstall"]);
        result.assert_failure();
        let output = result.combined_output();
        assert!(
            output.contains("not installed") && !output.contains("Unsupported runtime"),
            "{runtime} must reach its uninstall implementation, got:\n{output}"
        );
    }
}

#[test]
#[cfg(unix)]
fn rust_mutations_respect_another_process_lock() -> anyhow::Result<()> {
    let project = TestProject::new();
    let version = "1.93.1-x86_64-unknown-linux-gnu";
    let versions = project.data_dir.path().join("versions/rust");
    let toolchain = versions.join(version);
    std::fs::create_dir_all(toolchain.join("bin"))?;
    std::fs::write(toolchain.join("bin/rustc"), b"fixture, never executed")?;
    std::fs::write(
        toolchain.join(".omg-toolchain.toml"),
        "release = \"1.93.1\"\ncomponents = [\"rustc\"]\ntargets = []\n",
    )?;
    let lock = std::fs::File::create(versions.join(".mutation.lock"))?;
    lock.lock()?;

    for args in [
        vec!["use", "rust", version, "--uninstall"],
        vec!["use", "rust", version],
    ] {
        let result = project.run_with_env(&args, &[("OMG_TEST_COMMAND_TIMEOUT_SECS", "5")]);
        println!("{args:?}\n{}", result.combined_output());
        result.assert_failure();
        assert!(
            result
                .combined_output()
                .contains("Another Rust toolchain operation is running")
        );
        assert_eq!(
            std::fs::read(toolchain.join("bin/rustc"))?,
            b"fixture, never executed"
        );
        assert!(std::fs::symlink_metadata(versions.join("current")).is_err());
    }

    drop(lock);
    project.run(&["use", "rust", version]).assert_success();
    assert_eq!(std::fs::read_link(versions.join("current"))?, toolchain);
    Ok(())
}

#[test]
fn test_use_invalid_runtime() {
    init_test_env();

    let result = run_omg(&["use", "invalid-runtime-xyz", "1.0.0"]);
    result.assert_failure();

    // Unknown runtimes fail explicitly and never install a fallback manager.
    let output = result.combined_output();
    assert!(
        !output.contains("panicked at"),
        "`omg use <unknown>` must not panic:\n{output}"
    );
    assert!(
        output.contains("Unsupported runtime 'invalid-runtime-xyz'"),
        "failure must name the unsupported runtime:\n{output}"
    );
}

#[test]
fn test_use_node_with_version() {
    init_test_env();
    require_network_tests!();
    let project = TestProject::new();
    let result = project.run_with_env(
        &["use", "node", "20.10.0"],
        &[
            ("OMG_TEST_COMMAND_TIMEOUT_SECS", INSTALL_TIMEOUT_SECS),
            ("OMG_TEST_MODE", "0"),
        ],
    );
    result.assert_success();
    assert_downloaded_runtime(&project, "node", "20.10.0", "node");
    project.close_checked();
}

#[cfg(unix)]
#[test]
fn successful_runtime_switch_is_visible_at_default_verbosity() {
    let project = TestProject::new();
    let binary = project
        .data_dir
        .path()
        .join("versions/node/20.10.0/bin/node");
    std::fs::create_dir_all(binary.parent().expect("runtime bin directory"))
        .expect("create runtime version");
    std::fs::write(&binary, b"#!/bin/sh\n").expect("write runtime binary");

    let result = project.run(&["use", "node", "20.10.0"]);

    result.assert_success();
    result.assert_stdout_contains("Now using");
    result.assert_stdout_contains("Node.js");
    result.assert_stdout_contains("20.10.0");
    result.assert_stdout_contains("PATH:");
}

#[test]
fn test_use_python_with_version() {
    init_test_env();
    require_network_tests!();
    let project = TestProject::new();
    let result = project.run_with_env(
        // Match the published QEMU fixture; PBS 20260901 supplies this asset.
        // The former 3.11.0 fixture returned "not found", which used to pass.
        &["use", "python", "3.12.14"],
        &[
            ("OMG_TEST_COMMAND_TIMEOUT_SECS", INSTALL_TIMEOUT_SECS),
            ("OMG_TEST_MODE", "0"),
        ],
    );
    result.assert_success();
    assert_downloaded_runtime(&project, "python", "3.12.14", "python3");
    project.close_checked();
}

#[test]
fn test_use_node_latest() {
    init_test_env();
    require_network_tests!();
    let project = TestProject::new();
    let result = project.run_with_env(
        &["use", "node", "latest"],
        &[
            ("OMG_TEST_COMMAND_TIMEOUT_SECS", INSTALL_TIMEOUT_SECS),
            ("OMG_TEST_MODE", "0"),
        ],
    );
    result.assert_success();
    assert_downloaded_runtime(&project, "node", "latest", "node");
    project.close_checked();
}

#[test]
fn test_use_node_lts() {
    init_test_env();
    require_network_tests!();
    let project = TestProject::new();
    let result = project.run_with_env(
        &["use", "node", "lts"],
        &[
            ("OMG_TEST_COMMAND_TIMEOUT_SECS", INSTALL_TIMEOUT_SECS),
            ("OMG_TEST_MODE", "0"),
        ],
    );
    result.assert_success();
    assert_downloaded_runtime(&project, "node", "lts", "node");
    project.close_checked();
}

// ═══════════════════════════════════════════════════════════════════════════════
// LIST COMMAND E2E TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_list_all_runtimes() {
    init_test_env();

    let result = run_omg(&["list"]);
    result.assert_success();
    // The summary always renders the "Installed runtime versions" header,
    // even when no runtime is installed.
    result.assert_stdout_contains("runtime");
}

#[test]
fn test_list_specific_runtime() {
    init_test_env();

    let result = run_omg(&["list", "node"]);

    // Listing a known runtime always succeeds and renders the per-runtime
    // "<runtime> versions" header (list_versions_sync in src/cli/runtimes.rs).
    result.assert_success();
    result.assert_stdout_contains("node versions");
}

#[test]
fn test_list_available_versions() {
    init_test_env();
    require_network_tests!();

    let result = run_capped(&["list", "node", "--available"], INSTALL_TIMEOUT_SECS);

    result.assert_success();
    result.assert_stdout_contains("Available remote versions");
}

#[test]
fn test_list_invalid_runtime() {
    init_test_env();

    let result = run_omg(&["list", "invalid-runtime-xyz"]);

    result.assert_failure();
    let output = result.combined_output();
    assert!(
        output.contains("Unsupported runtime 'invalid-runtime-xyz'"),
        "failure must name the unknown runtime:\n{output}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// VERSION FILE DETECTION E2E TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_detect_nvmrc() {
    init_test_env();

    let project = TestProject::new();
    project.create_file(".nvmrc", "20.10.0");
    seed_installed_runtime(&project, "node", "20.10.0", "node");

    let result = project.run_with_env(
        &["use", "node"],
        &[("OMG_TEST_COMMAND_TIMEOUT_SECS", DETECTION_TIMEOUT_SECS)],
    );
    assert_active_runtime(&project, &result, "node", "20.10.0", "node");
    project.close_checked();
}

#[test]
fn test_detect_python_version() {
    init_test_env();

    let project = TestProject::new();
    project.create_file(".python-version", "3.11.0");
    seed_installed_runtime(&project, "python", "3.11.0", "python3");

    let result = project.run_with_env(
        &["use", "python"],
        &[("OMG_TEST_COMMAND_TIMEOUT_SECS", DETECTION_TIMEOUT_SECS)],
    );
    assert_active_runtime(&project, &result, "python", "3.11.0", "python3");
    project.close_checked();
}

#[test]
fn test_detect_tool_versions() {
    init_test_env();

    let project = TestProject::new();
    project.with_tool_versions(&[("node", "20.10.0"), ("python", "3.11.0")]);
    seed_installed_runtime(&project, "node", "20.10.0", "node");

    let result = project.run_with_env(
        &["use", "node"],
        &[("OMG_TEST_COMMAND_TIMEOUT_SECS", DETECTION_TIMEOUT_SECS)],
    );
    assert_active_runtime(&project, &result, "node", "20.10.0", "node");
    project.close_checked();
}

#[test]
fn test_package_json_engines() {
    init_test_env();

    let project = TestProject::new();
    project.create_file(
        "package.json",
        r#"{"name": "test", "engines": {"node": ">=18.0.0"}}"#,
    );

    // engines ranges are echoed verbatim as the detected pin; the subsequent
    // strict version validation rejects the range, but detection itself must
    // have happened first.
    let result = project.run_with_env(
        &["use", "node"],
        &[("OMG_TEST_COMMAND_TIMEOUT_SECS", DETECTION_TIMEOUT_SECS)],
    );
    assert_detected(&result, ">=18.0.0");
    result.assert_failure();
    assert!(
        result
            .combined_output()
            .contains("Invalid character '>' in version string")
    );
    assert!(
        !project
            .data_dir
            .path()
            .join("versions/node/current")
            .exists()
    );
    project.close_checked();
}

#[test]
fn test_rust_toolchain_toml() {
    init_test_env();

    let project = TestProject::new();
    let host_os = match std::env::consts::OS {
        "macos" => "apple-darwin",
        "linux" => "unknown-linux-gnu",
        other => panic!("missing Rust fixture host for {other}"),
    };
    let toolchain = format!("1.93.1-{}-{host_os}", std::env::consts::ARCH);
    project.create_file("rust-toolchain.toml", "[toolchain]\nchannel = \"1.93.1\"");
    seed_installed_runtime(&project, "rust", &toolchain, "rustc");

    let result = project.run_with_env(
        &["use", "rust"],
        &[("OMG_TEST_COMMAND_TIMEOUT_SECS", DETECTION_TIMEOUT_SECS)],
    );
    result.assert_success();
    assert_detected(&result, "1.93.1");
    let current = project
        .data_dir
        .path()
        .join("versions/rust/current/bin/rustc");
    assert_eq!(
        std::fs::canonicalize(&current).unwrap(),
        std::fs::canonicalize(
            project
                .data_dir
                .path()
                .join(format!("versions/rust/{toolchain}/bin/rustc"))
        )
        .unwrap()
    );
    let output = std::process::Command::new(current).output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        output.stdout,
        format!("fixture-rust-{toolchain}\n").as_bytes()
    );
    project.close_checked();
}

#[test]
#[cfg(unix)]
fn rust_stable_pin_refuses_a_concurrent_mutation_without_activation() {
    let project = TestProject::new();
    project.create_file("rust-toolchain.toml", "[toolchain]\nchannel = \"stable\"");
    let versions = project.data_dir.path().join("versions/rust");
    std::fs::create_dir_all(&versions).unwrap();
    let lock = std::fs::File::create(versions.join(".mutation.lock")).unwrap();
    lock.lock().unwrap();
    let result = project.run_with_env(&["use", "rust"], &[("OMG_TEST_COMMAND_TIMEOUT_SECS", "5")]);
    result.assert_failure();
    assert_detected(&result, "stable");
    assert!(
        result
            .combined_output()
            .contains("Another Rust toolchain operation is running")
    );
    assert!(std::fs::symlink_metadata(versions.join("current")).is_err());
    assert_eq!(std::fs::read_dir(&versions).unwrap().count(), 1);
    drop(lock);
    project.close_checked();
}

#[test]
fn test_go_mod_version() {
    init_test_env();

    let project = TestProject::new();
    project.create_file("go.mod", "module test\n\ngo 1.21");
    seed_installed_runtime(&project, "go", "1.21", "go");

    let result = project.run_with_env(
        &["use", "go"],
        &[("OMG_TEST_COMMAND_TIMEOUT_SECS", DETECTION_TIMEOUT_SECS)],
    );
    assert_active_runtime(&project, &result, "go", "1.21", "go");
    project.close_checked();
}

// ═══════════════════════════════════════════════════════════════════════════════
// MULTI-RUNTIME PROJECT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_multi_runtime_detection() {
    init_test_env();

    let project = TestProject::new();
    project.with_tool_versions(&[("node", "20.10.0"), ("python", "3.11.0"), ("go", "1.21")]);
    for (runtime, version, executable) in [
        ("node", "20.10.0", "node"),
        ("python", "3.11.0", "python3"),
        ("go", "1.21", "go"),
    ] {
        seed_installed_runtime(&project, runtime, version, executable);
    }

    let env = [("OMG_TEST_COMMAND_TIMEOUT_SECS", DETECTION_TIMEOUT_SECS)];
    let node_result = project.run_with_env(&["use", "node"], &env);
    assert_active_runtime(&project, &node_result, "node", "20.10.0", "node");

    let python_result = project.run_with_env(&["use", "python"], &env);
    assert_active_runtime(&project, &python_result, "python", "3.11.0", "python3");

    let go_result = project.run_with_env(&["use", "go"], &env);
    assert_active_runtime(&project, &go_result, "go", "1.21", "go");
    project.close_checked();
}

#[test]
fn test_conflicting_version_files() {
    init_test_env();

    let project = TestProject::new();
    project.create_file(".nvmrc", "18.0.0");
    project.with_tool_versions(&[("node", "20.10.0")]);
    seed_installed_runtime(&project, "node", "18.0.0", "node");
    seed_installed_runtime(&project, "node", "20.10.0", "node");

    // Precedence contract: within a directory, VERSION_FILES order wins —
    // .nvmrc is listed before .tool-versions and detect_versions keeps the
    // first hit per runtime (src/hooks/mod.rs VERSION_FILES / detect_versions),
    // so 18.0.0 (.nvmrc) must be detected, never 20.10.0.
    let result = project.run_with_env(
        &["use", "node"],
        &[("OMG_TEST_COMMAND_TIMEOUT_SECS", DETECTION_TIMEOUT_SECS)],
    );
    assert_active_runtime(&project, &result, "node", "18.0.0", "node");

    let output = result.combined_output();
    assert!(
        !output.contains("20.10.0"),
        ".nvmrc must take precedence over .tool-versions, got:\n{output}"
    );
    project.close_checked();
}

// ═══════════════════════════════════════════════════════════════════════════════
// ERROR HANDLING
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_error_use_without_version_or_file() {
    init_test_env();

    let project = TestProject::new();
    // No version file in empty project.

    let result = project.run(&["use", "node"]);

    result.assert_failure();
    let output = result.combined_output();
    assert!(
        output.contains("No version specified"),
        "`omg use <runtime>` with no argument and no pin must fail naming the \
         missing version (src/cli/runtimes.rs):\n{output}"
    );
}

#[test]
fn test_error_invalid_version_format() {
    init_test_env();

    let result = run_omg(&["use", "node", "invalid.version.xyz"]);

    result.assert_failure();
    // The bogus version must never succeed: the failure either names the
    // rejected version (404 from the dist manifest embeds it in the URL) or,
    // offline, names the failed lookup itself.
    let output = result.combined_output();
    assert!(
        !output.contains("panicked at"),
        "invalid version handling must not panic:\n{output}"
    );
    assert!(
        output.contains("invalid.version.xyz") || output.contains("internet connection"),
        "failure must name the rejected version or the failed upstream lookup:\n{output}"
    );
}

#[test]
fn test_error_unsupported_runtime() {
    init_test_env();

    let result = run_omg(&["use", "unsupported-runtime", "1.0.0"]);

    result.assert_failure();
    let output = result.combined_output();
    assert!(
        !output.contains("panicked at"),
        "`omg use <unsupported>` must not panic:\n{output}"
    );
    assert!(
        output.contains("Unsupported runtime 'unsupported-runtime'"),
        "failure must name the unsupported runtime:\n{output}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHELL INTEGRATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_hook_bash_generates_script() {
    init_test_env();

    let result = run_omg(&["hook", "bash"]);

    result.assert_success();
    // Bash-specific wiring from BASH_HOOK (src/hooks/mod.rs): the hook
    // function plus PROMPT_COMMAND registration.
    result.assert_stdout_contains("_omg_hook");
    result.assert_stdout_contains("PROMPT_COMMAND");
    result.assert_stdout_contains("_OMG_PATH_BASE");
}

#[test]
fn test_hook_zsh_generates_script() {
    init_test_env();

    let result = run_omg(&["hook", "zsh"]);

    result.assert_success();
    // Zsh-specific wiring from ZSH_HOOK (src/hooks/mod.rs).
    result.assert_stdout_contains("_omg_hook");
    result.assert_stdout_contains("precmd_functions");
    result.assert_stdout_contains("_omg_refresh_cache");
    result.assert_stdout_contains("zmodload zsh/datetime");
}

#[test]
fn test_hook_fish_generates_script() {
    init_test_env();

    let result = run_omg(&["hook", "fish"]);

    result.assert_success();
    // Fish uses function definitions with event handlers, not eval hooks.
    result.assert_stdout_contains("function _omg_hook");
    result.assert_stdout_contains("set -gx PATH $_OMG_PATH_BASE");
}

#[test]
fn test_hook_invalid_shell() {
    init_test_env();

    let result = run_omg(&["hook", "invalid-shell-xyz"]);

    result.assert_failure();
    // Shell is a clap value enum: invalid shells are rejected at parse time
    // with the offending value echoed back.
    result.assert_stderr_contains("invalid value 'invalid-shell-xyz'");
}

// ═══════════════════════════════════════════════════════════════════════════════
// WHICH COMMAND TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_which_shows_active_runtime() {
    let project = TestProject::new();
    let empty = project.run(&["which", "node"]);
    empty.assert_success();
    empty.assert_stdout_contains("node: no version set");
    seed_installed_runtime(&project, "node", "20.10.0", "node");
    project.run(&["use", "node", "20.10.0"]).assert_success();
    let selected = project.run(&["which", "node"]);
    selected.assert_success();
    assert_eq!(selected.stdout.trim(), "node 20.10.0");
    project.close_checked();
}

#[test]
fn test_which_requires_runtime_argument() {
    init_test_env();

    // `Which` declares `runtime` as a required positional (src/cli/args.rs);
    // omitting it is a clap usage error, not a silent success.
    let result = run_omg(&["which"]);

    result.assert_failure();
    result.assert_stderr_contains("required arguments were not provided");
}
