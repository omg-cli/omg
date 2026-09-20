#![cfg(unix)]

pub mod common;

use common::{CommandResult, TestProject};

const HOOK_NAMES: &[&str] = &["pre-commit", "post-checkout", "post-merge"];

fn run_fixture_hook(name: &str, completion: &str) -> CommandResult {
    use std::os::unix::fs::PermissionsExt as _;

    let project = TestProject::new();
    let initialized = std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(project.path())
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("initialize hook fixture");
    assert!(initialized.status.success());
    let hook = project.create_file(
        &format!(".git/hooks/{name}"),
        &format!("#!/bin/sh\nprintf 'executed' > hook.receipt\nprintf 'fixture hook reached\\n' >&2\n{completion}\n"),
    );
    std::fs::set_permissions(hook, std::fs::Permissions::from_mode(0o700))
        .expect("make fixture hook executable");
    let result = project.run_with_env(
        &["hooks", "run", name],
        &[
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_CONFIG_NOSYSTEM", "1"),
        ],
    );
    assert_eq!(
        std::fs::read_to_string(project.path().join("hook.receipt"))
            .expect("hook execution receipt"),
        "executed",
        "the actual hook must run before testing failure propagation"
    );
    result.assert_stderr_contains("fixture hook reached");
    result
}

#[test]
fn git_hook_run_propagates_child_failure() {
    for name in HOOK_NAMES {
        let result = run_fixture_hook(name, "exit 23");
        assert!(
            !result.success,
            "failed {name} hook reported success: {}",
            result.stdout
        );
        result.assert_stderr_contains("23");
    }
}

#[test]
fn git_hook_run_preserves_child_success() {
    for name in HOOK_NAMES {
        let result = run_fixture_hook(name, "exit 0");
        result.assert_success();
        result.assert_stdout_contains("Hook completed successfully");
    }
}

#[test]
fn git_hook_run_reports_signal_termination() {
    for name in HOOK_NAMES {
        let result = run_fixture_hook(name, "kill -TERM $$");
        assert!(!result.success, "terminated {name} hook reported success");
        result.assert_stderr_contains("signal");
    }
}
