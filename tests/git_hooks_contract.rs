#![cfg(unix)]

pub mod common;

use common::{CommandResult, TestProject};

const HOOK_NAMES: &[&str] = &["pre-commit", "post-checkout", "post-merge"];

#[test]
fn hook_install_force_and_uninstall_preserve_user_owned_content() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    for directory in [".git/hooks", "custom hooks"] {
        let project = TestProject::new();
        git(&project, &["init", "-q"]);
        git(&project, &["config", "core.hooksPath", directory]);
        let env = [
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_CONFIG_NOSYSTEM", "1"),
        ];
        project
            .run_with_env(&["hooks", "install"], &env)
            .assert_success();
        let originals: Vec<_> = HOOK_NAMES
            .iter()
            .map(|name| {
                let path = project.path().join(directory).join(name);
                let metadata = std::fs::metadata(&path).unwrap();
                (
                    path.clone(),
                    std::fs::read(&path).unwrap(),
                    metadata.ino(),
                    metadata.mode(),
                )
            })
            .collect();
        let repeated = project.run_with_env(&["hooks", "install"], &env);
        repeated.assert_success();
        assert_eq!(repeated.stdout.matches("already installed").count(), 3);
        for (path, content, inode, mode) in &originals {
            assert_eq!(std::fs::read(path).unwrap(), *content);
            assert_eq!(std::fs::metadata(path).unwrap().ino(), *inode);
            assert_eq!(std::fs::metadata(path).unwrap().mode(), *mode);
        }
        let custom = b"#!/bin/sh\n# OMG user-owned integration\nexit 23\n";
        for (path, _, _, _) in &originals {
            std::fs::write(path, custom).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640)).unwrap();
        }
        let preserve = project.run_with_env(&["hooks", "install"], &env);
        preserve.assert_success();
        assert_eq!(
            preserve
                .stdout
                .matches("exists, use --force to overwrite")
                .count(),
            3
        );
        let status = project.run_with_env(&["hooks", "status"], &env);
        status.assert_success();
        assert_eq!(status.stdout.matches("unrecognized or modified").count(), 3);
        project
            .run_with_env(&["hooks", "uninstall"], &env)
            .assert_success();
        for (path, _, inode, _) in &originals {
            assert_eq!(std::fs::read(path).unwrap(), custom);
            assert_eq!(std::fs::metadata(path).unwrap().ino(), *inode);
            assert_eq!(std::fs::metadata(path).unwrap().mode() & 0o777, 0o640);
        }
        project
            .run_with_env(&["hooks", "install", "--force"], &env)
            .assert_success();
        for (path, content, _, _) in &originals {
            assert_eq!(std::fs::read(path).unwrap(), *content);
            assert_ne!(std::fs::metadata(path).unwrap().mode() & 0o111, 0);
        }
        let status = project.run_with_env(&["hooks", "status"], &env);
        status.assert_success();
        assert_eq!(status.stdout.matches("installed (OMG)").count(), 3);
        project
            .run_with_env(&["hooks", "uninstall"], &env)
            .assert_success();
        for (path, _, _, _) in &originals {
            assert!(!path.exists());
        }
        let repeated = project.run_with_env(&["hooks", "uninstall"], &env);
        repeated.assert_success();
        repeated.assert_stdout_contains("No OMG hooks to remove");
        project.close_checked();
    }
}

fn git(project: &TestProject, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .args([
            "-c",
            "user.name=OMG fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .current_dir(project.path())
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("run fixture Git operation");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "git {args:?}: {text}");
    text
}

fn installed_repository() -> TestProject {
    let project = TestProject::new();
    git(&project, &["init", "-q", "-b", "baseline"]);
    project.create_file("omg.lock", "baseline\n");
    git(&project, &["add", "omg.lock"]);
    git(&project, &["commit", "-qm", "baseline"]);
    project
        .run_with_env(
            &["hooks", "install"],
            &[
                ("GIT_CONFIG_GLOBAL", "/dev/null"),
                ("GIT_CONFIG_NOSYSTEM", "1"),
            ],
        )
        .assert_success();
    project
}

#[test]
fn generated_pre_commit_warns_only_for_unstaged_lock_changes() {
    let project = installed_repository();
    project.create_file("omg.lock", "changed\n");
    let warning = git(&project, &["commit", "--allow-empty", "-m", "unstaged"]);
    assert!(
        warning.contains("omg.lock has unstaged changes"),
        "{warning}"
    );
    // A warning must not prevent the commit or silently stage the lockfile.
    assert_eq!(git(&project, &["show", "HEAD:omg.lock"]), "baseline\n");
    git(&project, &["add", "omg.lock"]);
    let staged = git(&project, &["commit", "-m", "staged"]);
    assert!(
        !staged.contains("omg.lock has unstaged changes"),
        "{staged}"
    );
    assert_eq!(git(&project, &["show", "HEAD:omg.lock"]), "changed\n");
}

#[test]
fn generated_checkout_and_merge_hooks_observe_real_git_transitions() {
    let project = installed_repository();
    git(&project, &["checkout", "-qb", "changed"]);
    project.create_file("omg.lock", "changed\n");
    git(&project, &["add", "omg.lock"]);
    git(&project, &["commit", "-qm", "change lock"]);
    let checkout = git(&project, &["checkout", "baseline"]);
    assert!(
        checkout.contains("Environment changed on branch switch"),
        "{checkout}"
    );
    let same = git(&project, &["checkout", "baseline"]);
    assert!(
        !same.contains("Environment changed on branch switch"),
        "{same}"
    );
    project.create_file("omg.lock", "working tree edit\n");
    let file_checkout = git(&project, &["checkout", "--", "omg.lock"]);
    assert!(
        !file_checkout.contains("Environment changed on branch switch"),
        "{file_checkout}"
    );
    let merge = git(&project, &["merge", "--ff-only", "changed"]);
    assert!(merge.contains("Environment changed after merge"), "{merge}");
    assert_eq!(
        std::fs::read_to_string(project.path().join("omg.lock")).unwrap(),
        "changed\n"
    );
    let noop = git(&project, &["merge", "--ff-only", "changed"]);
    assert!(!noop.contains("Environment changed after merge"), "{noop}");
}

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
