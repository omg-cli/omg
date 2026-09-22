//! Container CLI commands

use anyhow::{Context, Result};
use std::io::Write as _;

use crate::cli::components::Components;
use crate::cli::tea::Cmd;

use crate::core::container::{
    ContainerConfig, ContainerManager, ContainerRuntime, InstallerDigests, detect_runtime,
    dev_container_config, ensure_dockerignore, normalized_base_image,
};

/// Parse environment variables from strict `KEY=VALUE` entries.
///
/// Malformed entries are rejected instead of being silently dropped.
fn parse_env_vars(env: &[String]) -> Result<Vec<(String, String)>> {
    env.iter()
        .map(|e| {
            let (key, value) = e.split_once('=').ok_or_else(|| {
                anyhow::anyhow!("Invalid environment variable '{e}': expected KEY=VALUE")
            })?;
            if key.is_empty() {
                anyhow::bail!("Invalid environment variable '{e}': empty KEY");
            }
            Ok((key.to_string(), value.to_string()))
        })
        .collect()
}

/// Parse volume mounts from `host:container` entries.
///
/// Suffix modes such as `host:container:ro` are NOT supported and are
/// rejected explicitly instead of being silently truncated to read-write.
fn parse_volumes(volumes: &[String]) -> Result<Vec<(String, String)>> {
    volumes
        .iter()
        .map(|v| {
            let parts: Vec<&str> = v.split(':').collect();
            match parts.as_slice() {
                [host, container] if !host.is_empty() && !container.is_empty() => {
                    Ok(((*host).to_string(), (*container).to_string()))
                }
                [_, _, mode, ..] => Err(anyhow::anyhow!(
                    "Volume mount options ('{mode}') are not supported in '{v}'"
                )),
                _ => Err(anyhow::anyhow!(
                    "Invalid volume mount '{v}': expected HOST:CONTAINER"
                )),
            }
        })
        .collect()
}

/// Validate a container image reference or user-provided container name
/// through the shared security allowlists. One allowlist everywhere: image
/// refs use the image grammar, container names use the package-name grammar.
fn validate_container_ref(kind: &str, value: &str) -> Result<()> {
    use crate::cli::packages::execute_cmd;

    let valid = match kind {
        "image" => crate::core::security::validate_image_ref(value).is_ok(),
        _ => crate::core::security::validate_package_name(value).is_ok(),
    };
    if !valid {
        execute_cmd(crate::cli::components::Components::error_with_suggestion(
            format!("Invalid {kind} name"),
            "Names must match the expected character allowlist",
        ))?;
        anyhow::bail!("Invalid {kind} name");
    }
    Ok(())
}

/// Resolve the SHA-256 digest for one installer URL.
///
/// Scripts are fetched over the shared bounded TLS client and hashed; the
/// Go tarball digest is looked up in go.dev's published release metadata
/// instead of downloading the (hundreds-of-MB) artifact.
async fn resolve_installer_digest(url: &str) -> Result<String> {
    use crate::core::http::BoundedResponseExt;
    use sha2::Digest as _;

    let response = installer_digest_request(url)
        .send()
        .await
        .with_context(|| format!("Failed to fetch {url} for digest pinning"))?;
    anyhow::ensure!(
        response.status().is_success(),
        "Failed to fetch {url} for digest pinning: HTTP {}",
        response.status()
    );
    if url.starts_with("https://go.dev/dl/") {
        let metadata: serde_json::Value = response.bounded_json().await?;
        return go_tarball_digest(&metadata, url)
            .with_context(|| format!("go.dev does not publish a digest for {url}"));
    }
    let body = response.bounded_text().await?;
    use std::fmt::Write as _;
    let mut digest = String::with_capacity(64);
    for byte in sha2::Sha256::digest(body.as_bytes()) {
        let _ = write!(digest, "{byte:02x}");
    }
    Ok(digest)
}

fn installer_digest_request(url: &str) -> reqwest::RequestBuilder {
    // Include archived releases: a project's pinned Go version need not be
    // one of the currently supported releases returned by the default feed.
    let metadata_url = if url.starts_with("https://go.dev/dl/") {
        "https://go.dev/dl/?mode=json&include=all"
    } else {
        url
    };
    crate::core::http::shared_client().get(metadata_url)
}

/// Look up one Go tarball digest in go.dev's release metadata JSON.
fn go_tarball_digest(metadata: &serde_json::Value, tarball_url: &str) -> Result<String> {
    const EMPTY: &[serde_json::Value] = &[];
    let filename = tarball_url
        .rsplit('/')
        .next()
        .context("Tarball URL has no file component")?;
    for release in metadata
        .as_array()
        .context("go.dev release metadata is not a JSON array")?
    {
        for file in release
            .get("files")
            .and_then(serde_json::Value::as_array)
            .map_or(EMPTY, Vec::as_slice)
        {
            if file.get("filename").and_then(serde_json::Value::as_str) == Some(filename)
                && let Some(digest) = file.get("sha256").and_then(serde_json::Value::as_str)
            {
                return Ok(digest.to_string());
            }
        }
    }
    anyhow::bail!("no matching release file")
}

/// Generate the Dockerfile with every remote installer pinned to a digest
/// captured over TLS now, so root build steps verify the bytes they
/// execute instead of trusting whatever the network returns at build time.
fn pinned_dockerfile(
    manager: &ContainerManager,
    base: &str,
    runtime_refs: &[(&str, &str)],
) -> Result<String> {
    let draft = manager.generate_dockerfile(base, runtime_refs, &InstallerDigests::new());
    if draft.unpinned_urls.is_empty() {
        return Ok(draft.content);
    }

    let urls = draft.unpinned_urls;
    let digests = crate::cli::tea::run_blocking_future(async move {
        let mut digests = InstallerDigests::new();
        for url in &urls {
            let digest = resolve_installer_digest(url)
                .await
                .with_context(|| format!("Failed to pin {url} for verification"))?;
            digests.insert(url.clone(), digest);
        }
        Ok::<InstallerDigests, anyhow::Error>(digests)
    })??;

    let verified = manager.generate_dockerfile(base, runtime_refs, &digests);
    anyhow::ensure!(
        verified.unpinned_urls.is_empty(),
        "Could not pin digests for {} (refusing to generate a Dockerfile that runs unverified downloads as root)",
        verified.unpinned_urls.join(", ")
    );
    Ok(verified.content)
}

/// Show container runtime status
pub fn status() -> Result<()> {
    use crate::cli::packages::execute_cmd;

    let output = if let Some(runtime) = detect_runtime() {
        let runtime_str = runtime.to_string();
        let manager = ContainerManager::with_runtime(runtime);

        // List running containers
        match manager.list_running() {
            Ok(containers) if !containers.is_empty() => {
                let container_list: Vec<String> = containers
                    .iter()
                    .map(|c| format!("{} {} ({})", "•", c.name, c.image))
                    .collect();

                Cmd::batch([
                    Cmd::header("Container Status", format!("Runtime: {runtime_str}")),
                    Cmd::spacer(),
                    Cmd::card("Running Containers", container_list),
                    Components::complete("Container status retrieved"),
                ])
            }
            Ok(_) => Cmd::batch([
                Cmd::header("Container Status", format!("Runtime: {runtime_str}")),
                Cmd::spacer(),
                Cmd::info("No running containers"),
            ]),
            Err(e) => return Err(e).context("Failed to list containers"),
        }
    } else {
        anyhow::bail!(
            "No container runtime detected. Install Docker or Podman to use container features."
        );
    };

    execute_cmd(output)?;
    Ok(())
}

/// Run a command in a container
#[expect(clippy::too_many_arguments)] // Container config has many options
pub fn run(
    image: &str,
    command: &[String],
    name: Option<String>,
    detach: bool,
    interactive: bool,
    env: &[String],
    volumes: &[String],
    workdir: Option<String>,
) -> Result<()> {
    use crate::cli::packages::execute_cmd;

    // SECURITY: Validate image name and container name
    validate_container_ref("image", image)?;
    if let Some(ref n) = name
        && n.chars()
            .any(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
    {
        execute_cmd(Components::error_with_suggestion(
            "Invalid container name",
            "Container names must be alphanumeric with hyphens or underscores only",
        ))?;
        anyhow::bail!("Invalid container name");
    }

    // Parse user inputs before emitting any UI so malformed env/volume
    // entries fail fast without a dangling loading message.
    let env_pairs = parse_env_vars(env)?;
    let volume_pairs = parse_volumes(volumes)?;

    let manager = ContainerManager::new()?;

    execute_cmd(Components::loading(format!(
        "Running in {image} container..."
    )))?;

    let config = ContainerConfig {
        image: image.to_string(),
        name,
        interactive: interactive || !detach,
        rm: !detach,
        env: env_pairs,
        volumes: volume_pairs,
        workdir,
    };

    let cmd_refs: Vec<&str> = command.iter().map(String::as_str).collect();
    // Detached runs must actually pass --detach; previously the flag only
    // disabled --rm/-it and the container still blocked the terminal.
    let exit_code = if detach {
        manager.run_detached(&config, &cmd_refs)?
    } else {
        manager.run(&config, &cmd_refs)?
    };

    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}

/// Start an interactive shell in a container
pub fn shell(
    image: Option<String>,
    workdir: Option<String>,
    env: &[String],
    volumes: &[String],
) -> Result<()> {
    use crate::cli::packages::execute_cmd;

    let manager = ContainerManager::new()?;
    let cwd = std::env::current_dir()?;

    let mut env_pairs = parse_env_vars(env)?;
    let mut volume_pairs = parse_volumes(volumes)?;

    let mut config = if let Some(img) = image {
        ContainerConfig {
            image: img,
            ..dev_container_config(&cwd)
        }
    } else {
        dev_container_config(&cwd)
    };

    // Merge env and volumes
    config.env.append(&mut env_pairs);
    config.volumes.append(&mut volume_pairs);

    // Override workdir if specified
    if workdir.is_some() {
        config.workdir = workdir;
    }

    let mut details = vec![
        format!("Image: {}", config.image),
        format!("Mount: {} → /app", cwd.display()),
    ];

    if !config.env.is_empty() {
        details.push(format!("Environment: {} variable(s)", config.env.len()));
    }
    if config.volumes.len() > 1 {
        details.push(format!("Additional mounts: {}", config.volumes.len() - 1));
    }

    execute_cmd(Cmd::batch([
        Components::loading(format!("Starting shell in {} container...", config.image)),
        Cmd::card("Container Configuration", details),
    ]))?;

    let exit_code = manager.shell(&config)?;

    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}

/// Build a container image
pub fn build(
    dockerfile: Option<String>,
    tag: &str,
    no_cache: bool,
    build_args: &[String],
    target: &Option<String>,
) -> Result<()> {
    use crate::cli::packages::execute_cmd;

    // SECURITY: Validate tag and paths
    if tag.chars().any(|c| c.is_control() || c == ';') {
        execute_cmd(Components::error_with_suggestion(
            "Invalid tag name",
            "Tags must not contain control characters or semicolons",
        ))?;
        anyhow::bail!("Invalid tag name");
    }
    if let Some(ref df) = dockerfile
        && let Err(e) = crate::core::security::validate_relative_path(df)
    {
        execute_cmd(Components::error_with_suggestion(
            "Invalid Dockerfile path",
            format!("Path validation failed: {e}"),
        ))?;
        return Err(e.into());
    }

    let manager = ContainerManager::new()?;
    let cwd = std::env::current_dir()?;

    let dockerfile_path = dockerfile.map_or_else(
        || std::path::PathBuf::from("Dockerfile"),
        std::path::PathBuf::from,
    );

    if !dockerfile_path.exists() {
        let error_msg = format!("Dockerfile not found: {}", dockerfile_path.display());
        execute_cmd(Components::error_with_suggestion(
            &error_msg,
            "Use -f/--dockerfile to specify a path",
        ))?;
        anyhow::bail!("{error_msg}");
    }

    let mut build_details = vec![
        format!("Tag: {}", tag),
        format!("Dockerfile: {}", dockerfile_path.display()),
    ];

    if no_cache {
        build_details.push("Cache: Disabled".to_string());
    }

    if let Some(t) = target {
        build_details.push(format!("Target: {t}"));
    }

    execute_cmd(Cmd::batch([
        Components::loading(format!("Building image: {tag}")),
        Cmd::card("Build Configuration", build_details),
    ]))?;

    manager.build_with_options(
        &dockerfile_path,
        tag,
        &cwd,
        no_cache,
        build_args,
        target.as_deref(),
    )?;

    execute_cmd(Components::complete(format!(
        "Image {tag} built successfully"
    )))?;

    Ok(())
}

/// List running containers
pub fn list() -> Result<()> {
    use crate::cli::packages::execute_cmd;

    let manager = ContainerManager::new()?;

    let containers = manager.list_running()?;

    if containers.is_empty() {
        execute_cmd(Cmd::batch([
            Cmd::header("Running Containers", "No active containers"),
            Cmd::spacer(),
        ]))?;
        return Ok(());
    }

    let container_list: Vec<String> = containers
        .iter()
        .map(|c| {
            format!(
                "{:<12} {:<20} {:<25} {}",
                &c.id[..12.min(c.id.len())],
                c.name,
                c.image,
                c.status
            )
        })
        .collect();

    execute_cmd(Cmd::batch([
        Cmd::header(
            "Running Containers",
            format!("{} container(s) running", containers.len()),
        ),
        Cmd::spacer(),
        Cmd::card("Active Containers", container_list),
    ]))?;

    Ok(())
}

/// List container images
pub fn images() -> Result<()> {
    use crate::cli::packages::execute_cmd;

    let manager = ContainerManager::new()?;

    let images = manager.list_images()?;

    if images.is_empty() {
        execute_cmd(Cmd::batch([
            Cmd::header("Container Images", "No images found"),
            Cmd::spacer(),
        ]))?;
        return Ok(());
    }

    let image_list: Vec<String> = images
        .iter()
        .map(|img| {
            format!(
                "{:<30} {:<15} {:<12} {}",
                img.repository,
                img.tag,
                &img.id[..12.min(img.id.len())],
                img.size
            )
        })
        .collect();

    execute_cmd(Cmd::batch([
        Cmd::header(
            "Container Images",
            format!("{} image(s) available", images.len()),
        ),
        Cmd::spacer(),
        Cmd::card("Available Images", image_list),
    ]))?;

    Ok(())
}

/// Pull a container image
pub fn pull(image: &str) -> Result<()> {
    use crate::cli::packages::execute_cmd;

    validate_container_ref("image", image)?;

    let manager = ContainerManager::new()?;

    execute_cmd(Components::loading(format!("Pulling image: {image}")))?;

    manager.pull(image)?;

    execute_cmd(Components::complete(format!(
        "Image {image} pulled successfully"
    )))?;

    Ok(())
}

/// Stop a running container
pub fn stop(container: &str) -> Result<()> {
    use crate::cli::packages::execute_cmd;

    validate_container_ref("container", container)?;

    let manager = ContainerManager::new()?;

    execute_cmd(Components::loading(format!(
        "Stopping container: {container}"
    )))?;

    manager.stop(container)?;

    execute_cmd(Components::complete(format!(
        "Container {container} stopped"
    )))?;

    Ok(())
}

/// Execute a command in a running container
pub fn exec(container: &str, command: &[String]) -> Result<()> {
    validate_container_ref("container", container)?;

    let manager = ContainerManager::new()?;

    let cmd_refs: Vec<&str> = command.iter().map(String::as_str).collect();
    let exit_code = manager.exec(container, &cmd_refs, true)?;

    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}

/// Generate a Dockerfile for the current project
pub fn init(base_image: Option<String>) -> Result<()> {
    use crate::cli::packages::execute_cmd;

    let cwd = std::env::current_dir()?;
    let dockerfile_path = cwd.join("Dockerfile.omg");

    if dockerfile_path.exists() {
        execute_cmd(Components::error_with_suggestion(
            "Dockerfile.omg already exists",
            "Remove it first or use a different name",
        ))?;
        anyhow::bail!("Dockerfile.omg already exists");
    }

    let requested_base = base_image.unwrap_or_else(|| "ubuntu:24.04".to_string());
    let base = normalized_base_image(&requested_base).to_string();

    // Detect runtimes from project
    let mut runtimes: Vec<(&str, String)> = Vec::new();

    if cwd.join("package.json").exists() {
        runtimes.push(("node", "lts".to_string()));
    }
    if cwd.join("Cargo.toml").exists() {
        runtimes.push(("rust", "stable".to_string()));
    }
    if cwd.join("go.mod").exists() {
        runtimes.push(("go", "latest".to_string()));
    }
    if cwd.join("pyproject.toml").exists() || cwd.join("requirements.txt").exists() {
        runtimes.push(("python", "3.12".to_string()));
    }

    let manager = ContainerManager::new()
        .unwrap_or_else(|_| ContainerManager::with_runtime(ContainerRuntime::Docker));

    let runtime_refs: Vec<(&str, &str)> = runtimes.iter().map(|(r, v)| (*r, v.as_str())).collect();

    let dockerfile = pinned_dockerfile(&manager, &base, &runtime_refs)?;

    // `COPY . .` must never embed untracked credentials or repository data.
    ensure_dockerignore(&cwd)?;

    create_new_dockerfile(&dockerfile_path, dockerfile.as_bytes())?;

    let mut details = vec![format!("Base image: {}", base)];
    if !runtimes.is_empty() {
        details.push("Detected runtimes:".to_string());
        for (rt, ver) in &runtimes {
            details.push(format!("  • {rt}: {ver}"));
        }
    }

    execute_cmd(Cmd::batch([
        Cmd::success("Created Dockerfile.omg"),
        Cmd::card("Configuration", details),
        Cmd::println("\n  Build with:"),
        Cmd::println("    omg container build -f Dockerfile.omg -t myapp"),
    ]))?;

    Ok(())
}

fn create_new_dockerfile(path: &std::path::Path, contents: &[u8]) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("Refusing to overwrite existing {}", path.display()))?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn dockerfile_creation_refuses_a_dangling_symlink() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temp directory");
        let outside = directory.path().join("outside");
        let destination = directory.path().join("Dockerfile.omg");
        symlink(&outside, &destination).expect("dangling destination symlink");

        create_new_dockerfile(&destination, b"FROM malicious")
            .expect_err("existing symlink must be refused");
        assert!(!outside.exists(), "writer must not follow the symlink");
        assert!(destination.is_symlink());
    }

    #[test]
    fn env_vars_parse_strict_key_value_pairs() {
        let parsed = parse_env_vars(&["A=1".to_string(), "B=".to_string()])
            .expect("valid entries must parse");
        assert_eq!(
            parsed,
            vec![
                ("A".to_string(), "1".to_string()),
                ("B".to_string(), String::new())
            ]
        );

        let err = parse_env_vars(&["NO_SEPARATOR".to_string()])
            .expect_err("malformed entries must be rejected, not dropped");
        assert!(err.to_string().contains("expected KEY=VALUE"), "got: {err}");

        let err =
            parse_env_vars(&["=novalue".to_string()]).expect_err("empty keys must be rejected");
        assert!(err.to_string().contains("empty KEY"), "got: {err}");
    }

    #[test]
    fn volumes_reject_mode_suffixes_instead_of_truncating() {
        let parsed = parse_volumes(&["/tmp:/data".to_string()]).expect("plain mount must parse");
        assert_eq!(parsed, vec![("/tmp".to_string(), "/data".to_string())]);

        // A ':ro' suffix must never be silently truncated into a read-write mount.
        let err = parse_volumes(&["/tmp:/data:ro".to_string()])
            .expect_err("mount options are unsupported and must fail loudly");
        assert!(err.to_string().contains("not supported"), "got: {err}");

        let err = parse_volumes(&["just-a-path".to_string()])
            .expect_err("malformed mounts must be rejected, not dropped");
        assert!(
            err.to_string().contains("expected HOST:CONTAINER"),
            "got: {err}"
        );
    }

    #[test]
    fn container_refs_reject_shell_operators_and_control_chars() {
        assert!(validate_container_ref("image", "ubuntu:24.04").is_ok());
        assert!(validate_container_ref("container", "my-app_1").is_ok());
        assert!(validate_container_ref("image", "evil;rm").is_err());
        assert!(validate_container_ref("container", "a|b").is_err());
        assert!(validate_container_ref("image", "a&b").is_err());
        assert!(validate_container_ref("image", "a\u{0}b").is_err());
    }

    /// Go tarball digests come from go.dev's published release metadata,
    /// matched by exact filename.
    #[test]
    fn go_tarball_digest_matches_the_release_file() {
        let metadata: serde_json::Value = serde_json::from_str(
            r#"[
                {
                    "version": "go1.22.5",
                    "files": [
                        {
                            "filename": "go1.22.5.src.tar.gz",
                            "sha256": "baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        },
                        {
                            "filename": "go1.22.5.linux-amd64.tar.gz",
                            "sha256": "caaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        }
                    ]
                }
            ]"#,
        )
        .expect("fixture json");

        let digest = go_tarball_digest(&metadata, "https://go.dev/dl/go1.22.5.linux-amd64.tar.gz")
            .expect("digest found");
        assert!(digest.starts_with("ca"), "{digest}");

        let error = go_tarball_digest(&metadata, "https://go.dev/dl/go9.9.9.linux-amd64.tar.gz")
            .expect_err("unknown version must fail");
        assert!(
            error.to_string().contains("no matching release file"),
            "{error}"
        );
    }

    #[test]
    fn go_digest_request_fetches_release_metadata_instead_of_the_tarball() {
        let go_url = "https://go.dev/dl/go1.22.5.linux-amd64.tar.gz";
        let request = installer_digest_request(go_url)
            .build()
            .expect("Go request");
        assert_eq!(
            request.url().as_str(),
            "https://go.dev/dl/?mode=json&include=all"
        );
        assert_eq!(request.method(), reqwest::Method::GET);

        let script_url = "https://sh.rustup.rs";
        let request = installer_digest_request(script_url)
            .build()
            .expect("script request");
        assert_eq!(request.url().as_str(), "https://sh.rustup.rs/");
    }
}
