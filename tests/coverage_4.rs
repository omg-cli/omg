//! cov-4: contract tests for `src/core/task_runner.rs`.
//!
//! Target surfaces:
//! - `run_task_advanced` task-name validation, manifest fallback table, and
//!   unknown-command passthrough
//! - `with_arg_separator` wiring (`--` insertion for flag-swallowing managers)
//! - `execute_process` argument validation and child exit-code propagation
//! - `ensure_*_runtime` fail-closed behavior when a runtime/package manager is
//!   missing and the interactive prompt cannot be answered
//!
//! Strategy: every test drives the real `omg` binary inside an isolated
//! project whose `PATH` contains ONLY hand-written fake executables ("shims")
//! that print their argv. That makes the spawned command line directly
//! observable and keeps the tests hermetic w.r.t. the host machine.

#![cfg(unix)]

pub mod common;
use common::*;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Write an executable shell script into `dir`.
fn write_shim(dir: &Path, name: &str, body: &str) {
    let path = dir.join(name);
    fs::write(&path, body).expect("failed to write shim script");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
        .expect("failed to chmod shim script");
}

/// A shim that prints its full argv behind `PREFIX: ` so tests can pin the
/// exact command line task_runner built.
fn echo_shim_body(prefix: &str) -> String {
    format!("#!/bin/sh\nprintf '{prefix}: %s\\n' \"$*\"\n")
}

fn path_env(dir: &Path) -> (&'static str, &str) {
    (
        "PATH",
        dir.to_str().expect("invariant: shim paths must be UTF-8"),
    )
}

// ═══════════════════════════════════════════════════════════════════════════════
// Fixtures
// ═══════════════════════════════════════════════════════════════════════════════

fn write_npm_project(project: &TestProject, scripts: &[(&str, &str)]) {
    let scripts_json: Vec<String> = scripts
        .iter()
        .map(|(name, body)| format!("\"{name}\": \"{body}\""))
        .collect();
    project.create_file(
        "package.json",
        &format!(
            "{{\"name\": \"t\", \"version\": \"1.0.0\", \"scripts\": {{{}}}}}",
            scripts_json.join(", ")
        ),
    );
    // Lockfile pins detection to npm (otherwise the detector defaults to bun).
    project.create_file("package-lock.json", "{}");
}

fn write_pnpm_project(project: &TestProject) {
    project.create_file(
        "package.json",
        "{\"name\": \"t\", \"version\": \"1.0.0\", \"scripts\": {\"build\": \"webpack\"}}",
    );
    project.create_file("pnpm-lock.yaml", "lockfileVersion: 6.0\n");
}

fn write_cargo_project(project: &TestProject) {
    project.create_file(
        "Cargo.toml",
        "[package]\nname = \"t\"\nversion = \"0.1.0\"\n",
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// with_arg_separator end-to-end
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn inherited_nvm_directory_does_not_leak_into_task_fixtures() {
    // Reproduce hosted runners' NVM_DIR without modifying this test process's
    // environment (other tests run concurrently).
    let nvm = tempfile::tempdir().expect("external nvm directory");
    fs::create_dir_all(nvm.path().join("alias/lts")).expect("external alias directory");
    let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "npm_extra_args_get_double_dash_separator_before_user_flags",
            "--nocapture",
        ])
        .env("NVM_DIR", nvm.path())
        .output()
        .expect("spawn isolated regression probe");
    assert!(
        output.status.success(),
        "host NVM state leaked into fixture:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
}

#[test]
fn npm_extra_args_get_double_dash_separator_before_user_flags() {
    // Contract: for npm-detected tasks, user extra args must be preceded by a
    // `--` separator in the spawned argv (`npm run build -- <extra>`), because
    // npm otherwise consumes script flags itself.
    let project = TestProject::new();
    write_npm_project(&project, &[("build", "webpack")]);

    let shims = tempfile::tempdir().expect("shim dir");
    write_shim(shims.path(), "npm", &echo_shim_body("ARGS"));
    write_shim(shims.path(), "node", "#!/bin/sh\nexit 0\n");

    let result = project.run_with_env(
        &["run", "build", "--", "--minify"],
        &[path_env(shims.path())],
    );

    result.assert_success();
    // Exact argv: task args (`run build`) then separator then user arg.
    result.assert_stdout_contains("ARGS: run build -- --minify");
}

#[test]
fn cargo_extra_args_pass_through_without_double_dash() {
    // Contract: managers that do NOT swallow flags (cargo) must receive user
    // extra args directly, with NO `--` inserted into their argv.
    let project = TestProject::new();
    write_cargo_project(&project);

    let shims = tempfile::tempdir().expect("shim dir");
    write_shim(shims.path(), "cargo", &echo_shim_body("ARGS"));

    let result = project.run_with_env(
        &["run", "build", "--", "--release"],
        &[path_env(shims.path())],
    );

    result.assert_success();
    result.assert_stdout_contains("ARGS: build --release");
    assert!(
        !result.stdout.contains("build -- --release"),
        "cargo must not receive a `--` separator; got: {}",
        result.stdout
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Task-name validation
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn invalid_task_name_is_rejected_with_exact_error() {
    // Contract: task names outside [A-Za-z0-9._-] are rejected up front with
    // "Invalid task name: <name>" and nothing is executed.
    let project = TestProject::new();

    let result = project.run_with_env(&["run", "bad$name"], &[]);

    result.assert_failure();
    result.assert_stderr_contains("Invalid task name: bad$name");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Manifest fallback table
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn unlisted_task_falls_back_to_npm_run_prefix_from_marker_file() {
    // Contract: when the requested task matches no detected task but a
    // `package.json` marker exists, task_runner announces and executes
    // `npm run <task>` (prefix args preserved).
    let project = TestProject::new();
    write_npm_project(&project, &[("build", "webpack")]);

    let shims = tempfile::tempdir().expect("shim dir");
    write_shim(shims.path(), "npm", &echo_shim_body("ARGS"));
    write_shim(shims.path(), "node", "#!/bin/sh\nexit 0\n");

    let result = project.run_with_env(&["run", "lint"], &[path_env(shims.path())]);

    result.assert_success();
    result.assert_stdout_contains("Task 'lint' not found, trying 'npm run lint'");
    result.assert_stdout_contains("ARGS: run lint");
}

#[test]
fn unlisted_js_task_uses_the_detected_package_manager() {
    let project = TestProject::new();
    write_npm_project(&project, &[("build", "webpack")]);
    std::fs::write(
        project.path().join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\n",
    )
    .expect("pnpm lockfile");

    let shims = tempfile::tempdir().expect("shim dir");
    write_shim(shims.path(), "pnpm", &echo_shim_body("ARGS"));
    write_shim(shims.path(), "node", "#!/bin/sh\necho v20.11.1\n");

    let result = project.run_with_env(&["run", "lint"], &[path_env(shims.path())]);

    result.assert_success();
    result.assert_stdout_contains("Task 'lint' not found, trying 'pnpm run lint'");
    result.assert_stdout_contains("ARGS: run lint");
}

#[test]
fn unknown_command_executes_as_passthrough_from_path() {
    // Contract: with no manifests and no matching fallback marker, the task
    // name itself is executed argv-directly from PATH with its extra args.
    let project = TestProject::new(); // empty directory: no manifests at all

    let shims = tempfile::tempdir().expect("shim dir");
    write_shim(shims.path(), "mytool", &echo_shim_body("TOOL-RAN"));

    let result = project.run_with_env(&["run", "mytool", "--", "hello"], &[path_env(shims.path())]);

    result.assert_success();
    result.assert_stdout_contains("TOOL-RAN: hello");
}

// ═══════════════════════════════════════════════════════════════════════════════
// execute_process argument validation and exit codes
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn shell_metacharacters_in_extra_args_are_passed_verbatim() {
    let project = TestProject::new();
    let shims = tempfile::tempdir().expect("shim dir");
    write_shim(shims.path(), "mytool", &echo_shim_body("ARGS"));

    let result = project.run_with_env(
        &["run", "mytool", "--", "a;b|$HOME", "x&y"],
        &[path_env(shims.path())],
    );

    result.assert_success();
    result.assert_stdout_contains("ARGS: a;b|$HOME x&y");
}

#[test]
fn child_nonzero_exit_code_propagates_as_task_failure() {
    // Contract: when the spawned manager exits nonzero with no signal, omg
    // reports "Task failed with exit code: Some(<code>)" and exits nonzero.
    let project = TestProject::new();
    write_npm_project(&project, &[("build", "webpack")]);

    let shims = tempfile::tempdir().expect("shim dir");
    write_shim(
        shims.path(),
        "npm",
        "#!/bin/sh\nif [ \"$2\" = \"build\" ]; then exit 3; fi\nprintf 'ARGS: %s\\n' \"$@\"\n",
    );
    write_shim(shims.path(), "node", "#!/bin/sh\nexit 0\n");

    let result = project.run_with_env(&["run", "build"], &[path_env(shims.path())]);

    result.assert_failure();
    assert_eq!(result.exit_code, 1);
    result.assert_stderr_contains("Task failed with exit code: Some(3)");
}

// ═══════════════════════════════════════════════════════════════════════════════
// ensure_*_runtime / ensure_js_package_manager fail-closed paths
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn missing_node_runtime_fails_closed_when_install_prompt_unavailable() {
    // Contract: with node absent from PATH, absent from OMG-managed versions,
    // and absent from nvm, running an npm task must NOT silently execute; the
    // install confirmation cannot be answered in a non-TTY session, so omg
    // fails closed with an actionable non-interactive remedy.
    //
    // Hermeticity: PATH points at an empty dir, OMG_DATA_DIR isolates the
    // managed-version listing, NVM_DIR isolates the nvm lookup.
    let project = TestProject::new();
    write_npm_project(&project, &[("build", "webpack")]);

    let empty_path = tempfile::tempdir().expect("empty PATH dir");
    let empty_nvm = tempfile::tempdir().expect("empty NVM_DIR");

    let result = project.run_with_env(
        &["run", "build"],
        &[
            path_env(empty_path.path()),
            (
                "NVM_DIR",
                empty_nvm
                    .path()
                    .to_str()
                    .expect("invariant: nvm dir must be UTF-8"),
            ),
        ],
    );

    result.assert_failure();
    result.assert_stderr_contains("Interactive confirmation required");
    result.assert_stderr_contains("Install the dependency manually");
    assert!(
        !result.stdout.contains("ARGS:"),
        "no task may be executed when runtime resolution fails; got: {}",
        result.stdout
    );
}

#[test]
fn pnpm_missing_without_corepack_fails_closed_with_remedy_message() {
    // Contract: a pnpm-managed project run where neither pnpm nor corepack is
    // resolvable must fail with the exact remedy-bearing error naming both
    // cause and fix.
    let project = TestProject::new();
    write_pnpm_project(&project);

    let empty_path = tempfile::tempdir().expect("empty PATH dir");

    let result = project.run_with_env(&["run", "build"], &[path_env(empty_path.path())]);

    result.assert_failure();
    result.assert_stderr_contains(
        "pnpm is missing and corepack is unavailable. Install pnpm or enable corepack.",
    );
}
