//! Native Rust toolchain manager - PURE RUST, NO RUSTUP
//!
//! Downloads Rust toolchains directly from static.rust-lang.org
//!
//! Features:
//! - Full toolchain management (stable, beta, nightly, dated)
//! - Component installation (rustfmt, clippy, rust-src, etc.)
//! - Cross-compilation target support
//! - Profile-based installation (minimal or default)
//! - rust-toolchain.toml support

use crate::core::http::BoundedResponseExt;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::common::{
    MAX_DECOMPRESSED_BYTES, activate_version_with_lease, begin_staged_install,
    complete_staged_install_with_lease, copy_regular_tree, download_with_progress,
    extract_component_tar_gz, extract_component_tar_xz, is_valid_version_dir, parse_sha256_digest,
    print_already_installed, print_installed, print_using, replace_staged_install_with_lease,
    validate_download_filename,
};
use crate::cli::style;
use crate::core::archive::stripped_archive_path;
use crate::core::http::download_client;

const RUST_DIST_URL: &str = "https://static.rust-lang.org/dist";
const RUST_MANIFEST_PREFIX: &str = "channel-rust";
const RUST_METADATA_FILE: &str = ".omg-toolchain.toml";

/// Rust version info
#[derive(Debug, Clone)]
pub(crate) struct RustVersion {
    pub(crate) version: String,
    pub(crate) channel: String,
}

fn is_date_parts(year: &str, month: &str, day: &str) -> bool {
    year.len() == 4
        && month.len() == 2
        && day.len() == 2
        && year.chars().all(|c| c.is_ascii_digit())
        && month.chars().all(|c| c.is_ascii_digit())
        && day.chars().all(|c| c.is_ascii_digit())
}

#[derive(Debug, Clone)]
pub(crate) struct RustToolchainSpec {
    pub(crate) channel: String,
    pub(crate) date: Option<String>,
    pub(crate) host: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RustToolchainRequest {
    pub(crate) channel: String,
    pub(crate) profile: Option<String>,
    pub(crate) components: Vec<String>,
    pub(crate) targets: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct RustToolchainStatus {
    pub(crate) name: String,
    pub(crate) needs_install: bool,
    pub(crate) missing_components: Vec<String>,
    pub(crate) missing_targets: Vec<String>,
}

#[derive(Clone, Copy)]
enum ToolchainPublication {
    Create,
    Replace,
}

// Wire types for rust-toolchain.toml; internal to `parse_toolchain_file`.
#[derive(Debug, Deserialize)]
struct RustToolchainFile {
    toolchain: RustToolchainSection,
}

#[derive(Debug, Deserialize)]
struct RustToolchainSection {
    channel: String,
    components: Option<Vec<String>>,
    targets: Option<Vec<String>>,
    profile: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct RustToolchainMetadata {
    #[serde(default)]
    release: Option<String>,
    components: BTreeSet<String>,
    targets: BTreeSet<String>,
}

pub(crate) struct RustManager {
    versions_dir: PathBuf,
    client: &'static reqwest::Client,
}

impl RustManager {
    pub fn new() -> Self {
        Self {
            versions_dir: super::DATA_DIR.join("versions/rust"),
            client: download_client(),
        }
    }

    /// List the stable version and the rolling beta and nightly channels.
    pub async fn list_available(&self) -> Result<Vec<RustVersion>> {
        let mut versions = Vec::new();

        let manifest = self
            .fetch_manifest("stable", None)
            .await
            .context("Failed to fetch the stable Rust channel manifest")?;
        let version = manifest_version(&manifest).ok_or_else(|| {
            anyhow::anyhow!("Stable Rust channel manifest is missing a rustc version")
        })?;
        versions.push(RustVersion {
            version,
            channel: "stable".to_string(),
        });

        // Add rolling channel aliases. The concrete stable version above
        // already represents the stable channel, so do not emit it twice.
        versions.push(RustVersion {
            version: "beta".to_string(),
            channel: "beta".to_string(),
        });
        versions.push(RustVersion {
            version: "nightly".to_string(),
            channel: "nightly".to_string(),
        });

        Ok(versions)
    }

    /// Install Rust - PURE RUST, NO SUBPROCESS
    pub async fn install(&self, version: &str) -> Result<()> {
        let toolchain = RustToolchainSpec::parse(version)?;
        let mutation_lock = self.lock_mutations()?;
        let version_dir = self.toolchain_dir(&toolchain);

        Self::reject_invalid_toolchain_path(&version_dir)?;
        if is_valid_version_dir(&version_dir) {
            match self
                .refresh_rolling_toolchain(&toolchain, &mutation_lock)
                .await
            {
                Ok(true) => {}
                Ok(false) => print_already_installed("Rust", &toolchain.name()),
                Err(error) => {
                    tracing::warn!("Could not refresh Rust {}: {error}", toolchain.name());
                    print_already_installed("Rust", &toolchain.name());
                }
            }
            return self.activate_toolchain(&toolchain, &mutation_lock);
        }

        let prefix = style::runtime("OMG");
        let toolchain_name = style::caution(&toolchain.name());
        tracing::info!("{prefix} Installing Rust {toolchain_name}...\n");

        self.install_with_profile(&toolchain, "default", &[], &[], &mutation_lock)
            .await?;
        self.activate_toolchain(&toolchain, &mutation_lock)?;

        Ok(())
    }

    /// Remove an installed toolchain. Refuses the active toolchain.
    pub fn uninstall(&self, version: &str) -> Result<()> {
        let toolchain = RustToolchainSpec::parse(version)?;
        let mutation_lock = self.lock_mutations()?;
        super::common::uninstall_version_with_lease(
            &self.versions_dir,
            &toolchain.name(),
            &mutation_lock,
        )
    }

    pub fn toolchain_status(&self, request: &RustToolchainRequest) -> Result<RustToolchainStatus> {
        let toolchain = RustToolchainSpec::parse(&request.channel)?;
        let version_dir = self.toolchain_dir(&toolchain);
        Self::reject_invalid_toolchain_path(&version_dir)?;
        let metadata = Self::read_metadata(&version_dir)?;
        let missing_components = request
            .components
            .iter()
            .filter(|component| !metadata.components.contains(*component))
            .cloned()
            .collect();
        let missing_targets = request
            .targets
            .iter()
            .filter(|target| !metadata.targets.contains(*target))
            .cloned()
            .collect();

        Ok(RustToolchainStatus {
            name: toolchain.name(),
            needs_install: !is_valid_version_dir(&version_dir),
            missing_components,
            missing_targets,
        })
    }

    pub async fn ensure_toolchain(&self, request: &RustToolchainRequest) -> Result<()> {
        let toolchain = RustToolchainSpec::parse(&request.channel)?;
        let mutation_lock = self.lock_mutations()?;
        if is_valid_version_dir(&self.toolchain_dir(&toolchain)) {
            self.refresh_rolling_toolchain(&toolchain, &mutation_lock)
                .await?;
        }

        let status = self.toolchain_status(request)?;
        if !status.needs_install
            && status.missing_components.is_empty()
            && status.missing_targets.is_empty()
        {
            return Ok(());
        }

        if status.needs_install {
            self.install_with_profile(
                &toolchain,
                request.profile.as_deref().unwrap_or("default"),
                &request.components,
                &request.targets,
                &mutation_lock,
            )
            .await
        } else {
            self.apply_incremental_updates(
                &toolchain,
                &status.missing_components,
                &status.missing_targets,
                &mutation_lock,
            )
            .await
        }
    }

    /// The root-wide lease protects toolchain snapshots and the shared current pointer.
    /// Acquisition never waits, so holding it across downloads cannot block the executor.
    /// Keep the lock file in place; unlinking it would permit locks on different inodes.
    fn lock_mutations(&self) -> Result<fs::File> {
        fs::create_dir_all(&self.versions_dir)?;
        let path = self.versions_dir.join(".mutation.lock");
        let mut options = fs::OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
        }
        let lock = options
            .open(&path)
            .with_context(|| format!("Failed to open Rust mutation lock: {}", path.display()))?;
        match lock.try_lock() {
            Ok(()) => Ok(lock),
            Err(fs::TryLockError::WouldBlock) => {
                anyhow::bail!("Another Rust toolchain operation is running; retry when it finishes")
            }
            Err(fs::TryLockError::Error(error)) => {
                Err(error).context("Failed to acquire Rust toolchain mutation lock")
            }
        }
    }

    fn toolchain_dir(&self, toolchain: &RustToolchainSpec) -> PathBuf {
        self.versions_dir.join(toolchain.name())
    }

    async fn refresh_rolling_toolchain(
        &self,
        toolchain: &RustToolchainSpec,
        mutation_lease: &fs::File,
    ) -> Result<bool> {
        if !is_rolling_channel(toolchain) {
            return Ok(false);
        }

        let version_dir = self.toolchain_dir(toolchain);
        let metadata = Self::read_metadata(&version_dir)?;
        let manifest = self
            .fetch_manifest(&toolchain.channel, toolchain.date.as_deref())
            .await?;
        if !channel_release_changed(toolchain, metadata.release.as_deref(), &manifest)? {
            return Ok(false);
        }

        let components = if metadata.components.is_empty() {
            profile_components("default")?
        } else {
            metadata.components.into_iter().collect()
        };
        let targets = metadata.targets.into_iter().collect::<Vec<_>>();
        self.install_from_manifest(
            toolchain,
            &components,
            &targets,
            &manifest,
            ToolchainPublication::Replace,
            mutation_lease,
        )
        .await?;
        Ok(true)
    }

    fn reject_invalid_toolchain_path(path: &Path) -> Result<()> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_dir() => Ok(()),
            Ok(_) => anyhow::bail!(
                "Refusing to use non-directory Rust toolchain path: {}",
                path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| {
                format!("Failed to inspect Rust toolchain path: {}", path.display())
            }),
        }
    }

    fn extract_component(archive_path: &Path, dest_dir: &Path) -> Result<()> {
        let is_xz = archive_path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("xz"));

        if is_xz {
            extract_component_tar_xz(
                archive_path,
                dest_dir,
                MAX_DECOMPRESSED_BYTES,
                &Self::component_entry_selector,
            )
        } else {
            extract_component_tar_gz(
                archive_path,
                dest_dir,
                MAX_DECOMPRESSED_BYTES,
                &Self::component_entry_selector,
            )
        }
    }

    /// Map one untrusted component-archive path to its toolchain-relative
    /// destination path.
    ///
    /// Only `lib`, `bin`, and `share` payloads are retained; manifest and
    /// installer files at the component root are skipped. The
    /// `component-version-target/component` prefix is stripped so payloads
    /// land directly below the toolchain directory, and unsafe path
    /// components are rejected by the shared archive-path validator.
    fn component_entry_selector(path: &Path) -> Result<Option<PathBuf>> {
        let path_str = path.to_string_lossy();
        if !path_str.contains("/lib/")
            && !path_str.contains("/bin/")
            && !path_str.contains("/share/")
        {
            return Ok(None);
        }
        stripped_archive_path(path, 2)
    }

    fn activate_toolchain(
        &self,
        toolchain: &RustToolchainSpec,
        mutation_lease: &fs::File,
    ) -> Result<()> {
        let toolchain_name = toolchain.name();
        activate_version_with_lease(
            &self.versions_dir,
            &toolchain_name,
            Path::new("bin/rustc"),
            mutation_lease,
        )?;
        let bin_dir = self.versions_dir.join("current/bin");
        print_using("Rust", &toolchain_name, &bin_dir);
        Ok(())
    }
}

// Generate common runtime manager methods (list_installed, current_version)
crate::runtimes::common::impl_runtime_common!(RustManager);

impl RustManager {
    pub(crate) fn parse_toolchain_content(
        path: &Path,
        content: &str,
    ) -> Result<RustToolchainRequest> {
        let is_toml = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == "rust-toolchain.toml");

        if is_toml {
            let parsed: RustToolchainFile = toml::from_str(content)?;
            return Ok(RustToolchainRequest {
                channel: parsed.toolchain.channel,
                profile: parsed.toolchain.profile,
                components: parsed.toolchain.components.unwrap_or_default(),
                targets: parsed.toolchain.targets.unwrap_or_default(),
            });
        }

        Ok(RustToolchainRequest {
            channel: content.trim().to_string(),
            ..Default::default()
        })
    }

    pub fn parse_toolchain_file(path: &Path) -> Result<RustToolchainRequest> {
        let content = fs::read_to_string(path)?;
        Self::parse_toolchain_content(path, &content)
    }

    async fn install_with_profile(
        &self,
        toolchain: &RustToolchainSpec,
        profile: &str,
        components: &[String],
        targets: &[String],
        mutation_lease: &fs::File,
    ) -> Result<()> {
        let mut required_components = profile_components(profile)?;
        required_components.extend_from_slice(components);
        required_components.sort_unstable();
        required_components.dedup();
        let manifest = self
            .fetch_manifest(&toolchain.channel, toolchain.date.as_deref())
            .await?;
        self.install_from_manifest(
            toolchain,
            &required_components,
            targets,
            &manifest,
            ToolchainPublication::Create,
            mutation_lease,
        )
        .await
    }

    async fn install_from_manifest(
        &self,
        toolchain: &RustToolchainSpec,
        required_components: &[String],
        targets: &[String],
        manifest: &toml::Value,
        publication: ToolchainPublication,
        mutation_lease: &fs::File,
    ) -> Result<()> {
        let version_dir = self.toolchain_dir(toolchain);
        let staging = begin_staged_install(&self.versions_dir)?;
        let dest_dir = staging.path();

        for component in required_components {
            self.install_component(dest_dir, component, &toolchain.host, manifest)
                .await?;
        }

        for target in targets {
            if is_additional_target(target, &toolchain.host) {
                self.install_component(dest_dir, "rust-std", target, manifest)
                    .await?;
            }
        }

        let mut metadata = RustToolchainMetadata {
            release: Some(manifest_release(manifest)?),
            ..Default::default()
        };
        metadata
            .components
            .extend(required_components.iter().cloned());
        metadata.targets.extend(targets.iter().cloned());
        Self::write_metadata(dest_dir, &metadata)?;
        match publication {
            ToolchainPublication::Create => {
                complete_staged_install_with_lease(
                    &staging,
                    &version_dir,
                    &toolchain.name(),
                    mutation_lease,
                )?;
            }
            ToolchainPublication::Replace => {
                replace_staged_install_with_lease(
                    &staging,
                    &version_dir,
                    &toolchain.name(),
                    mutation_lease,
                )?;
            }
        }

        print_installed("Rust", &toolchain.name());

        Ok(())
    }

    async fn apply_incremental_updates(
        &self,
        toolchain: &RustToolchainSpec,
        components: &[String],
        targets: &[String],
        mutation_lease: &fs::File,
    ) -> Result<()> {
        let version_dir = self.toolchain_dir(toolchain);
        if !is_valid_version_dir(&version_dir) {
            anyhow::bail!(
                "Rust toolchain is not installed as a valid directory: {}",
                version_dir.display()
            );
        }

        let manifest = self
            .fetch_manifest(&toolchain.channel, toolchain.date.as_deref())
            .await?;
        self.apply_incremental_from_manifest(
            toolchain,
            components,
            targets,
            &manifest,
            mutation_lease,
        )
        .await
    }

    async fn apply_incremental_from_manifest(
        &self,
        toolchain: &RustToolchainSpec,
        components: &[String],
        targets: &[String],
        manifest: &toml::Value,
        mutation_lease: &fs::File,
    ) -> Result<()> {
        let version_dir = self.toolchain_dir(toolchain);
        let mut metadata = Self::read_metadata(&version_dir)?;
        let installed_release = metadata
            .release
            .as_deref()
            .filter(|release| !release.trim().is_empty())
            .context("Rust toolchain has no recorded release identity; a complete reinstall is required before adding components or targets")?;
        anyhow::ensure!(
            installed_release == manifest_release(manifest)?,
            "Rust manifest release identity does not match the installed toolchain; retry setup before adding components or targets"
        );
        let staging = begin_staged_install(&self.versions_dir)?;
        copy_regular_tree(&version_dir, staging.path())?;

        for component in components {
            self.install_component(staging.path(), component, &toolchain.host, manifest)
                .await?;
        }
        for target in targets {
            if is_additional_target(target, &toolchain.host) {
                self.install_component(staging.path(), "rust-std", target, manifest)
                    .await?;
            }
        }

        metadata.components.extend(components.iter().cloned());
        metadata.targets.extend(targets.iter().cloned());
        Self::write_metadata(staging.path(), &metadata)?;
        replace_staged_install_with_lease(&staging, &version_dir, &toolchain.name(), mutation_lease)
    }

    async fn install_component(
        &self,
        dest_dir: &Path,
        component: &str,
        target: &str,
        manifest: &toml::Value,
    ) -> Result<()> {
        tracing::info!("{} Downloading {}...", style::informative("→"), component);
        let url = manifest_component_url(manifest, component, target)?;
        let filename = url
            .rsplit('/')
            .next()
            .ok_or_else(|| anyhow::anyhow!("Invalid download URL for {component}"))?;
        let filename = validate_download_filename(filename)?;
        let checksum = manifest_component_checksum(manifest, component, target, url)?;
        let download_dir = tempfile::Builder::new()
            .prefix(".rust-component-")
            .tempdir_in(&self.versions_dir)
            .context("Failed to create temporary Rust component directory")?;
        let download_path = download_dir.path().join(filename);

        download_with_progress(self.client, url, &download_path, &checksum).await?;
        tracing::info!("{} Extracting {}...", style::informative("→"), component);
        Self::extract_component(&download_path, dest_dir)?;
        Ok(())
    }

    fn read_metadata(toolchain_dir: &Path) -> Result<RustToolchainMetadata> {
        let path = toolchain_dir.join(RUST_METADATA_FILE);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(RustToolchainMetadata::default());
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "Failed to inspect Rust toolchain metadata: {}",
                        path.display()
                    )
                });
            }
            Ok(metadata) if !metadata.is_file() => {
                anyhow::bail!(
                    "Rust toolchain metadata is not a regular file: {}",
                    path.display()
                );
            }
            Ok(_) => {}
        }
        let content = fs::read_to_string(&path).with_context(|| {
            format!("Failed to read Rust toolchain metadata: {}", path.display())
        })?;
        toml::from_str(&content).with_context(|| {
            format!(
                "Failed to parse Rust toolchain metadata: {}",
                path.display()
            )
        })
    }

    fn write_metadata(toolchain_dir: &Path, metadata: &RustToolchainMetadata) -> Result<()> {
        let path = toolchain_dir.join(RUST_METADATA_FILE);
        let content = toml::to_string_pretty(metadata)?;
        let mut file = tempfile::NamedTempFile::new_in(toolchain_dir).with_context(|| {
            format!(
                "Failed to create Rust toolchain metadata in {}",
                toolchain_dir.display()
            )
        })?;
        file.write_all(content.as_bytes())?;
        file.as_file_mut().sync_all()?;
        file.persist(&path)
            .map_err(|error| error.error)
            .with_context(|| {
                format!(
                    "Failed to persist Rust toolchain metadata at {}",
                    path.display()
                )
            })?;
        Ok(())
    }

    async fn fetch_manifest(&self, channel: &str, date: Option<&str>) -> Result<toml::Value> {
        let filename = format!("{RUST_MANIFEST_PREFIX}-{channel}.toml");
        let url = match date {
            Some(d) => format!("{RUST_DIST_URL}/{d}/{filename}"),
            None => format!("{RUST_DIST_URL}/{filename}"),
        };

        let manifest = self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .with_context(|| format!("Failed to fetch Rust manifest from {url}"))?
            .error_for_status()
            .with_context(|| format!("Rust manifest request failed for channel '{channel}'"))?
            .bounded_text()
            .await
            .context("Failed to read Rust version manifest")?;

        toml::from_str(&manifest).map_err(Into::into)
    }
}

impl RustToolchainSpec {
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        crate::core::security::validate_runtime_version(input)?;
        let mut segments: Vec<&str> = input.split('-').collect();
        let mut channel = segments.first().copied().unwrap_or(input).to_string();

        // Handle dated beta releases (e.g., "1.82.0-beta.5")
        if channel.chars().next().is_some_and(|c| c.is_ascii_digit())
            && let Some(beta_part) = segments.get(1)
            && beta_part.starts_with("beta")
        {
            channel = format!("{channel}-{beta_part}");
            segments.drain(0..2);
        } else {
            segments.remove(0);
        }

        // Parse date if present (YYYY-MM-DD)
        let date = match (segments.first(), segments.get(1), segments.get(2)) {
            (Some(&y), Some(&m), Some(&d)) if is_date_parts(y, m, d) => {
                segments.drain(0..3);
                Some(format!("{y}-{m}-{d}"))
            }
            _ => None,
        };

        let host = if segments.is_empty() {
            default_host_triple()?
        } else {
            segments.join("-")
        };

        Ok(Self {
            channel,
            date,
            host,
        })
    }

    pub fn name(&self) -> String {
        match &self.date {
            Some(date) => format!("{}-{}-{}", self.channel, date, self.host),
            None => format!("{}-{}", self.channel, self.host),
        }
    }
}

fn default_host_triple() -> Result<String> {
    match (std::env::consts::ARCH, std::env::consts::OS) {
        ("x86_64", "linux") => Ok("x86_64-unknown-linux-gnu".to_string()),
        ("aarch64", "linux") => Ok("aarch64-unknown-linux-gnu".to_string()),
        ("x86_64", "macos") => Ok("x86_64-apple-darwin".to_string()),
        ("aarch64", "macos") => Ok("aarch64-apple-darwin".to_string()),
        ("x86_64", "windows") => Ok("x86_64-pc-windows-msvc".to_string()),
        ("aarch64", "windows") => Ok("aarch64-pc-windows-msvc".to_string()),
        (arch, os) => anyhow::bail!("Unsupported host platform: {arch}-{os}"),
    }
}

fn is_additional_target(target: &str, host: &str) -> bool {
    target != host
}

fn profile_components(profile: &str) -> Result<Vec<String>> {
    let components = match profile {
        "minimal" => vec!["rustc", "cargo", "rust-std"],
        "default" => vec![
            "rustc",
            "cargo",
            "rust-std",
            "rustfmt",
            "clippy",
            "rust-docs",
        ],
        other => anyhow::bail!("Unknown Rust profile: {other}"),
    };
    Ok(components.into_iter().map(String::from).collect())
}

fn manifest_version(manifest: &toml::Value) -> Option<String> {
    manifest
        .get("pkg")
        .and_then(|pkg| pkg.get("rustc"))
        .and_then(|rustc| rustc.get("version"))
        .and_then(|value| value.as_str())
        .map(|value| value.split_whitespace().next().unwrap_or(value).to_string())
}

fn manifest_release(manifest: &toml::Value) -> Result<String> {
    // Keep the full rustc version string, including the parenthetical
    // commit/date. Nightly (and often beta) keep the same semver token
    // across many manifests; stripping it would make rolling refreshes a no-op.
    manifest
        .get("pkg")
        .and_then(|pkg| pkg.get("rustc"))
        .and_then(|rustc| rustc.get("version"))
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("Rust channel manifest is missing a rustc version"))
}

fn is_rolling_channel(toolchain: &RustToolchainSpec) -> bool {
    toolchain.date.is_none() && matches!(toolchain.channel.as_str(), "stable" | "beta" | "nightly")
}

fn channel_release_changed(
    toolchain: &RustToolchainSpec,
    installed_release: Option<&str>,
    manifest: &toml::Value,
) -> Result<bool> {
    if !is_rolling_channel(toolchain) {
        return Ok(false);
    }
    Ok(installed_release != Some(manifest_release(manifest)?.as_str()))
}

fn manifest_package_name(component: &str) -> &str {
    match component {
        "rustfmt" => "rustfmt-preview",
        "clippy" => "clippy-preview",
        other => other,
    }
}

fn manifest_component_target<'a>(
    manifest: &'a toml::Value,
    component: &str,
    target: &str,
) -> Result<&'a toml::Value> {
    manifest
        .get("pkg")
        .and_then(|pkg| pkg.get(manifest_package_name(component)))
        .and_then(|pkg| pkg.get("target"))
        .and_then(|targets| targets.get(target))
        .ok_or_else(|| anyhow::anyhow!("Target '{target}' not found for component '{component}'"))
}

fn manifest_component_url<'a>(
    manifest: &'a toml::Value,
    component: &str,
    target: &str,
) -> Result<&'a str> {
    let target_info = manifest_component_target(manifest, component, target)?;
    let url = target_info
        .get("xz_url")
        .and_then(toml::Value::as_str)
        .or_else(|| target_info.get("url").and_then(toml::Value::as_str))
        .ok_or_else(|| anyhow::anyhow!("No download URL for {component} on {target}"))?;

    Ok(url)
}

fn manifest_component_checksum(
    manifest: &toml::Value,
    component: &str,
    target: &str,
    url: &str,
) -> Result<String> {
    let target_info = manifest_component_target(manifest, component, target)?;
    let digest = target_info
        .get(
            if Path::new(url)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("xz"))
            {
                "xz_hash"
            } else {
                "hash"
            },
        )
        .and_then(toml::Value::as_str)
        .or_else(|| target_info.get("hash").and_then(toml::Value::as_str))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Missing SHA-256 checksum for Rust component {component} target {target}"
            )
        })?;
    parse_sha256_digest(digest, "Rust distribution manifest")
}

#[cfg(test)]
#[expect(clippy::unwrap_used)] // Idiomatic in tests: panics on failure with clear error context
mod tests {
    use super::*;
    use std::io::Cursor;
    use tar::{Builder, EntryType, Header};
    use tempfile::TempDir;

    fn component_archive(path: &str, entry_type: EntryType, contents: &[u8]) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        {
            let mut builder = Builder::new(&mut bytes);
            let mut header = Header::new_gnu();
            header.set_entry_type(entry_type);
            header.set_mode(0o755);
            header.set_size(contents.len() as u64);
            header.set_cksum();
            builder.append_data(&mut header, path, contents)?;
            builder.finish()?;
        }
        Ok(bytes)
    }

    fn component_symlink_archive(path: &str, target: &str) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        {
            let mut builder = Builder::new(&mut bytes);
            let mut header = Header::new_gnu();
            header.set_entry_type(EntryType::Symlink);
            header.set_mode(0o755);
            header.set_size(0);
            header.set_link_name(target)?;
            header.set_cksum();
            builder.append_data(&mut header, path, std::io::empty())?;
            builder.finish()?;
        }
        Ok(bytes)
    }

    fn gzip_tar(tar: &[u8]) -> Result<Vec<u8>> {
        use flate2::{Compression, write::GzEncoder};
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(tar)?;
        Ok(encoder.finish()?)
    }

    fn xz_tar(tar: Vec<u8>) -> Result<Vec<u8>> {
        let mut compressed = Vec::new();
        lzma_rs::xz_compress(&mut Cursor::new(tar), &mut compressed)?;
        Ok(compressed)
    }

    #[test]
    fn https_manifest_install_verifies_payloads_publication_and_activation() -> Result<()> {
        const CHILD: &str = "OMG_RUST_INSTALL_FIXTURE_CHILD";
        if std::env::var_os(CHILD).is_some() {
            assert!(crate::core::paths::test_mode());
            return tokio::runtime::Runtime::new()?.block_on(async {
                install_fixture(false).await?;
                install_fixture(true).await
            });
        }
        // Isolate the existing debug-only loopback policy to this child process.
        // No process-global environment mutation or production policy changes.
        let output = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "runtimes::rust::tests::https_manifest_install_verifies_payloads_publication_and_activation", "--nocapture"])
            .env(CHILD, "1")
            .env("OMG_TEST_MODE", "1")
            .output()?;
        anyhow::ensure!(
            output.status.success(),
            "isolated install fixture failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    async fn install_fixture(corrupt: bool) -> Result<()> {
        use sha2::{Digest as _, Sha256};
        let toolchain = RustToolchainSpec::parse("1.93.1")?;
        let mut manifest = String::from("[pkg.rustc]\nversion = \"1.93.1\"\n");
        let mut routes = Vec::new();
        for (component, file, payload, xz) in [
            ("cargo", "bin/cargo", b"downloaded cargo".as_slice(), false),
            (
                "rust-std",
                "lib/libstd.rlib",
                b"downloaded standard library".as_slice(),
                true,
            ),
            (
                "rustc",
                "bin/rustc",
                b"downloaded compiler".as_slice(),
                false,
            ),
        ] {
            let tar = component_archive(
                &format!("{component}-1.93.1-target/{component}/{file}"),
                EntryType::Regular,
                payload,
            )?;
            let mut archive = if xz { xz_tar(tar)? } else { gzip_tar(&tar)? };
            let extension = if xz { "xz" } else { "gz" };
            let path = format!("/dist/{component}.tar.{extension}");
            let hash = format!("{:x}", Sha256::digest(&archive));
            if corrupt && component == "cargo" {
                archive.push(0);
            }
            routes.push((path, archive));
            manifest.push_str(&format!("[pkg.{component}.target.{}]\nurl = \"ARCHIVE_BASE/dist/{component}.tar.{extension}\"\nhash = \"{hash}\"\n", toolchain.host));
        }
        if corrupt {
            routes.truncate(1);
        }
        let archives = super::super::test_https::HttpFixture::new(routes).await?;
        let manifest = manifest.replace("ARCHIVE_BASE", &format!("http://{}", archives.address));
        let fixture = super::super::test_https::HttpsFixture::new(
            "static.rust-lang.org",
            vec![(
                "/dist/channel-rust-1.93.1.toml".into(),
                manifest.into_bytes(),
            )],
        )
        .await?;
        let versions = TempDir::new()?;
        let manager = RustManager {
            versions_dir: versions.path().to_path_buf(),
            client: Box::leak(Box::new(fixture.client(true)?)),
        };
        let request = RustToolchainRequest {
            channel: "1.93.1".into(),
            profile: Some("minimal".into()),
            ..Default::default()
        };
        let result = manager.ensure_toolchain(&request).await;
        let directory = manager.toolchain_dir(&toolchain);
        if corrupt {
            let error = result.expect_err("corrupt component must not publish a toolchain");
            assert!(format!("{error:#}").contains("Checksum mismatch"));
            assert!(!directory.exists());
            assert!(!versions.path().join("current").exists());
            let names: Vec<_> = fs::read_dir(versions.path())?
                .map(|entry| entry.map(|item| item.file_name()))
                .collect::<std::io::Result<_>>()?;
            assert_eq!(names, [".mutation.lock"]);
            assert_eq!(
                fixture.finish().await?,
                ["GET /dist/channel-rust-1.93.1.toml HTTP/1.1"]
            );
            assert_eq!(
                archives.finish().await?,
                ["GET /dist/cargo.tar.gz HTTP/1.1"]
            );
            return Ok(());
        }
        result?;
        assert_eq!(
            fs::read(directory.join("bin/rustc"))?,
            b"downloaded compiler"
        );
        assert_eq!(fs::read(directory.join("bin/cargo"))?, b"downloaded cargo");
        assert_eq!(
            fs::read(directory.join("lib/libstd.rlib"))?,
            b"downloaded standard library"
        );
        let metadata = RustManager::read_metadata(&directory)?;
        assert_eq!(metadata.release.as_deref(), Some("1.93.1"));
        assert_eq!(
            metadata.components,
            BTreeSet::from(["cargo".into(), "rust-std".into(), "rustc".into()])
        );
        assert!(metadata.targets.is_empty());
        manager.install("1.93.1").await?;
        assert_eq!(fs::read_link(versions.path().join("current"))?, directory);
        assert_eq!(
            fixture.finish().await?,
            ["GET /dist/channel-rust-1.93.1.toml HTTP/1.1"]
        );
        assert_eq!(
            archives.finish().await?,
            [
                "GET /dist/cargo.tar.gz HTTP/1.1",
                "GET /dist/rust-std.tar.xz HTTP/1.1",
                "GET /dist/rustc.tar.gz HTTP/1.1"
            ]
        );
        let names: BTreeSet<_> = fs::read_dir(versions.path())?
            .map(|entry| entry.map(|item| item.file_name()))
            .collect::<std::io::Result<_>>()?;
        assert_eq!(
            names,
            BTreeSet::from([
                ".mutation.lock".into(),
                "current".into(),
                toolchain.name().into()
            ])
        );
        Ok(())
    }

    #[test]
    fn test_rust_manager_new() {
        let mgr = RustManager::new();
        assert!(mgr.versions_dir.ends_with("rust"));
    }

    #[test]
    fn test_toolchain_spec_parse_stable() {
        let spec = RustToolchainSpec::parse("stable").unwrap();
        assert_eq!(spec.channel, "stable");
        assert!(spec.date.is_none());
    }

    #[test]
    fn test_toolchain_spec_parse_nightly() {
        let spec = RustToolchainSpec::parse("nightly").unwrap();
        assert_eq!(spec.channel, "nightly");
        assert!(spec.date.is_none());
    }

    #[test]
    fn test_toolchain_spec_parse_dated() {
        let spec = RustToolchainSpec::parse("nightly-2024-01-15").unwrap();
        assert_eq!(spec.channel, "nightly");
        assert_eq!(spec.date, Some("2024-01-15".to_string()));
    }

    #[test]
    fn toolchain_specs_reject_unsafe_path_components() {
        for input in ["", ".", "..", "current", "../nightly", "/nightly"] {
            assert!(RustToolchainSpec::parse(input).is_err(), "{input:?}");
        }
    }

    #[test]
    fn test_toolchain_spec_name() {
        let spec = RustToolchainSpec::parse("stable").unwrap();
        let name = spec.name();
        assert!(name.starts_with("stable-"));
        // Platform-agnostic check: should contain any valid OS component
        assert!(name.contains("linux") || name.contains("darwin") || name.contains("windows"));
    }

    #[test]
    fn component_selector_keeps_only_lib_bin_and_share_payloads() -> Result<()> {
        let select = RustManager::component_entry_selector;
        assert_eq!(
            select(Path::new("rustc-1.0.0-target/rustc/bin/rustc"))?,
            Some(PathBuf::from("bin/rustc"))
        );
        assert_eq!(
            select(Path::new(
                "rustc-1.0.0-target/rustc/lib/rustlib/x86_64-unknown-linux-gnu/lib.rlib",
            ))?,
            Some(PathBuf::from(
                "lib/rustlib/x86_64-unknown-linux-gnu/lib.rlib"
            ))
        );
        assert_eq!(
            select(Path::new("rustc-1.0.0-target/rustc/share/man/man1/rustc.1"))?,
            Some(PathBuf::from("share/man/man1/rustc.1"))
        );
        assert_eq!(
            select(Path::new("rustc-1.0.0-target/rustc/components"))?,
            None
        );
        assert_eq!(select(Path::new("rustc-1.0.0-target/rustc/version"))?, None);
        assert_eq!(select(Path::new("rustc-1.0.0-target/rustc/rustc"))?, None);
        // Payload-looking unsafe paths are still rejected, not skipped.
        assert!(select(Path::new("rustc-1.0.0-target/rustc/../../../evil/bin/tool",)).is_err());
        Ok(())
    }

    #[test]
    fn gzip_component_extraction_enforces_decompressed_budget() -> Result<()> {
        let tar = component_archive(
            "rustc-1.0.0-target/rustc/bin/rustc",
            EntryType::Regular,
            &[b'x'; 256],
        )?;
        let directory = TempDir::new()?;
        let archive_path = directory.path().join("rustc.tar.gz");
        fs::write(&archive_path, gzip_tar(&tar)?)?;

        let destination = TempDir::new()?;
        let error = extract_component_tar_gz(
            &archive_path,
            destination.path(),
            128,
            &RustManager::component_entry_selector,
        )
        .expect_err("oversized decompressed archive must fail");

        assert!(error.to_string().contains("decompressed data exceeds"));
        Ok(())
    }

    #[test]
    fn component_extraction_writes_regular_files_inside_the_destination() -> Result<()> {
        let tar = component_archive(
            "rustc-1.0.0-target/rustc/bin/rustc",
            EntryType::Regular,
            b"runtime",
        )?;
        let directory = TempDir::new()?;
        let archive_path = directory.path().join("rustc.tar.gz");
        fs::write(&archive_path, gzip_tar(&tar)?)?;
        let destination = TempDir::new()?;

        extract_component_tar_gz(
            &archive_path,
            destination.path(),
            MAX_DECOMPRESSED_BYTES,
            &RustManager::component_entry_selector,
        )?;

        assert_eq!(fs::read(destination.path().join("bin/rustc"))?, b"runtime");
        Ok(())
    }

    #[test]
    fn component_extraction_rejects_escaping_links() -> Result<()> {
        let tar = component_symlink_archive("rustc-1.0.0-target/rustc/bin/rustc", "../../outside")?;
        let directory = TempDir::new()?;
        let archive_path = directory.path().join("rustc.tar.gz");
        fs::write(&archive_path, gzip_tar(&tar)?)?;
        let destination = TempDir::new()?;

        let error = extract_component_tar_gz(
            &archive_path,
            destination.path(),
            MAX_DECOMPRESSED_BYTES,
            &RustManager::component_entry_selector,
        )
        .expect_err("escaping link entries must be rejected");

        assert!(
            error
                .to_string()
                .contains("escapes the extraction directory")
        );
        assert!(!destination.path().join("bin/rustc").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn component_extraction_accepts_internal_symlinks() -> Result<()> {
        // Component archives are validated by the shared walker: internal,
        // non-escaping links are allowed exactly like whole-runtime extraction.
        let mut bytes = Vec::new();
        {
            let mut builder = Builder::new(&mut bytes);
            let mut file_header = Header::new_gnu();
            file_header.set_entry_type(EntryType::Regular);
            file_header.set_mode(0o755);
            file_header.set_size(4);
            file_header.set_cksum();
            builder.append_data(
                &mut file_header,
                "rustc-1.0.0-target/rustc/lib/tool",
                &b"tool"[..],
            )?;
            let mut link_header = Header::new_gnu();
            link_header.set_entry_type(EntryType::Symlink);
            link_header.set_mode(0o755);
            link_header.set_size(0);
            link_header.set_link_name("../lib/tool")?;
            link_header.set_cksum();
            builder.append_data(
                &mut link_header,
                "rustc-1.0.0-target/rustc/bin/rustc",
                std::io::empty(),
            )?;
            builder.finish()?;
        }
        let directory = TempDir::new()?;
        let archive_path = directory.path().join("rustc.tar.gz");
        fs::write(&archive_path, gzip_tar(&bytes)?)?;
        let destination = TempDir::new()?;

        extract_component_tar_gz(
            &archive_path,
            destination.path(),
            MAX_DECOMPRESSED_BYTES,
            &RustManager::component_entry_selector,
        )?;

        assert_eq!(fs::read(destination.path().join("lib/tool"))?, b"tool");
        assert!(
            fs::symlink_metadata(destination.path().join("bin/rustc"))?
                .file_type()
                .is_symlink()
        );
        Ok(())
    }

    #[test]
    fn xz_component_extraction_succeeds_with_a_small_budget() -> Result<()> {
        let tar = component_archive(
            "rustc-1.0.0-target/rustc/bin/rustc",
            EntryType::Regular,
            b"runtime",
        )?;
        let directory = TempDir::new()?;
        let archive_path = directory.path().join("rustc.tar.xz");
        fs::write(&archive_path, xz_tar(tar.clone())?)?;
        let destination = TempDir::new()?;

        // The budget covers exactly the decompressed tar payload: extraction
        // must succeed without any slack beyond the real payload size.
        let budget = u64::try_from(tar.len()).context("test archive is too large")?;
        extract_component_tar_xz(
            &archive_path,
            destination.path(),
            budget,
            &RustManager::component_entry_selector,
        )?;

        assert_eq!(fs::read(destination.path().join("bin/rustc"))?, b"runtime");
        Ok(())
    }

    #[test]
    fn xz_component_extraction_over_budget_fails_without_publishing_output() -> Result<()> {
        let tar = component_archive(
            "rustc-1.0.0-target/rustc/bin/rustc",
            EntryType::Regular,
            b"runtime",
        )?;
        let directory = TempDir::new()?;
        let archive_path = directory.path().join("rustc.tar.xz");
        fs::write(&archive_path, xz_tar(tar.clone())?)?;
        let destination = TempDir::new()?;

        let budget = u64::try_from(tar.len()).context("test archive is too large")? - 1;
        let error = extract_component_tar_xz(
            &archive_path,
            destination.path(),
            budget,
            &RustManager::component_entry_selector,
        )
        .expect_err("over-budget decompression must fail");

        assert!(format!("{error:#}").contains("exceeds the"));
        let published: Vec<_> =
            fs::read_dir(destination.path())?.collect::<std::io::Result<Vec<_>>>()?;
        assert!(
            published.is_empty(),
            "over-budget extraction must not publish output"
        );
        Ok(())
    }

    #[tokio::test]
    async fn ensure_toolchain_locks_before_reading_and_releases_after_error() -> Result<()> {
        let versions = TempDir::new()?;
        let manager = RustManager {
            versions_dir: versions.path().to_path_buf(),
            client: download_client(),
        };
        let request = RustToolchainRequest {
            channel: "1.93.1".to_string(),
            ..Default::default()
        };
        let version_dir = manager.toolchain_dir(&RustToolchainSpec::parse(&request.channel)?);
        fs::create_dir(&version_dir)?;
        fs::write(version_dir.join(RUST_METADATA_FILE), "[invalid metadata")?;
        let lock = fs::File::create(versions.path().join(".mutation.lock"))?;
        lock.lock()?;

        let busy = manager
            .ensure_toolchain(&request)
            .await
            .expect_err("writer is busy");
        assert!(
            busy.to_string()
                .contains("Another Rust toolchain operation is running")
        );
        drop(lock);

        let malformed = manager
            .ensure_toolchain(&request)
            .await
            .expect_err("metadata is invalid");
        assert!(malformed.downcast_ref::<toml::de::Error>().is_some());
        let _released = manager.lock_mutations()?;
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn mutation_lock_rejects_symlinks_without_changing_the_target() -> Result<()> {
        let versions = TempDir::new()?;
        let manager = RustManager {
            versions_dir: versions.path().to_path_buf(),
            client: download_client(),
        };
        let target = versions.path().join("preserved");
        fs::write(&target, b"unchanged")?;
        std::os::unix::fs::symlink(&target, versions.path().join(".mutation.lock"))?;

        assert!(manager.lock_mutations().is_err());
        assert_eq!(fs::read(target)?, b"unchanged");
        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn incremental_updates_require_matching_release_identity() -> Result<()> {
        use sha2::{Digest as _, Sha256};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        // The fixture downloads a component from a loopback HTTP server.
        // Hermetic test mode is the only context where plain-HTTP loopback
        // download targets are tolerated (release binaries always pin
        // HTTPS); serialize because the switch is process-global.
        struct TestModeGuard;
        impl Drop for TestModeGuard {
            fn drop(&mut self) {
                // SAFETY: Test-only code, serialized by serial_test.
                #[expect(unsafe_code)]
                unsafe {
                    std::env::remove_var("OMG_TEST_MODE");
                }
            }
        }
        // SAFETY: Test-only code, serialized by serial_test; no other test
        // reads OMG_TEST_MODE concurrently.
        #[expect(unsafe_code)]
        unsafe {
            std::env::set_var("OMG_TEST_MODE", "1");
        }
        let _test_mode = TestModeGuard;

        let archive = gzip_tar(&component_archive(
            "clippy/clippy/bin/cargo-clippy",
            EntryType::Regular,
            b"candidate component",
        )?)?;
        let checksum = format!("{:x}", Sha256::digest(&archive));
        for (installed, candidate, compatible) in [
            (
                Some("1.95.0-nightly (aaaa 2026-01-01)"),
                "1.95.0-nightly (bbbb 2026-01-02)",
                false,
            ),
            (Some("1.93.1"), "1.94.0", false),
            (None, "1.93.1", false),
            (Some(""), "", false),
            (Some("1.93.1"), "1.93.1", true),
        ] {
            let versions = TempDir::new()?;
            let manager = RustManager {
                versions_dir: versions.path().to_path_buf(),
                client: download_client(),
            };
            let toolchain = RustToolchainSpec::parse("nightly")?;
            let version_dir = manager.toolchain_dir(&toolchain);
            fs::create_dir_all(version_dir.join("bin"))?;
            fs::write(version_dir.join("bin/rustc"), b"installed compiler")?;
            RustManager::write_metadata(
                &version_dir,
                &RustToolchainMetadata {
                    release: installed.map(str::to_string),
                    components: BTreeSet::from(["rustc".to_string()]),
                    targets: BTreeSet::new(),
                },
            )?;
            let original_metadata = fs::read(version_dir.join(RUST_METADATA_FILE))?;
            let mutation_lock = manager.lock_mutations()?;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            let manifest: toml::Value = toml::from_str(&format!(
                "[pkg.rustc]\nversion = {candidate:?}\n[pkg.clippy-preview.target.{}]\nurl = \"http://{address}/clippy.tar.gz\"\nhash = \"{checksum}\"\n",
                toolchain.host,
            ))?;
            let serve = async {
                let (mut socket, _) = listener.accept().await?;
                let mut request = [0; 2048];
                assert!(
                    socket.read(&mut request).await? > 0,
                    "component request is present"
                );
                socket
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            archive.len()
                        )
                        .as_bytes(),
                    )
                    .await?;
                socket.write_all(&archive).await?;
                Ok::<(), std::io::Error>(())
            };
            let components = ["clippy".to_string()];
            let update = manager.apply_incremental_from_manifest(
                &toolchain,
                &components,
                &[],
                &manifest,
                &mutation_lock,
            );
            tokio::pin!(update);
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                tokio::select! {
                    result = &mut update => result,
                    served = serve => { served?; update.await }
                }
            })
            .await?;
            println!(
                "installed={installed:?} candidate={candidate:?} accepted={} new_component={}",
                result.is_ok(),
                version_dir.join("bin/cargo-clippy").exists()
            );
            assert_eq!(result.is_ok(), compatible, "{result:?}");
            assert_eq!(
                fs::read(version_dir.join("bin/rustc"))?,
                b"installed compiler"
            );
            if compatible {
                assert_eq!(
                    fs::read(version_dir.join("bin/cargo-clippy"))?,
                    b"candidate component"
                );
                let metadata = RustManager::read_metadata(&version_dir)?;
                assert_eq!(metadata.release.as_deref(), installed);
                assert_eq!(
                    metadata.components,
                    BTreeSet::from(["rustc".to_string(), "clippy".to_string()])
                );
            } else {
                assert!(
                    result
                        .expect_err("incompatible identity")
                        .to_string()
                        .contains("release identity")
                );
                assert!(!version_dir.join("bin/cargo-clippy").exists());
                assert_eq!(
                    fs::read(version_dir.join(RUST_METADATA_FILE))?,
                    original_metadata
                );
            }
        }
        Ok(())
    }

    #[test]
    fn write_metadata_replaces_existing_file_atomically() -> Result<()> {
        let destination = TempDir::new()?;
        let first = RustToolchainMetadata {
            release: Some("1.78.0".to_string()),
            components: BTreeSet::from(["rustc".to_string()]),
            targets: BTreeSet::new(),
        };
        let second = RustToolchainMetadata {
            release: Some("1.79.0".to_string()),
            components: BTreeSet::from(["rustc".to_string(), "cargo".to_string()]),
            targets: BTreeSet::from(["x86_64-unknown-linux-gnu".to_string()]),
        };

        RustManager::write_metadata(destination.path(), &first)?;
        RustManager::write_metadata(destination.path(), &second)?;

        let loaded = RustManager::read_metadata(destination.path())?;
        assert_eq!(loaded.release, second.release);
        assert_eq!(loaded.components, second.components);
        assert_eq!(loaded.targets, second.targets);
        Ok(())
    }

    #[test]
    fn legacy_metadata_without_a_release_remains_readable() -> Result<()> {
        let destination = TempDir::new()?;
        fs::write(
            destination.path().join(RUST_METADATA_FILE),
            "components = [\"rustc\"]\ntargets = []\n",
        )?;

        let loaded = RustManager::read_metadata(destination.path())?;
        assert_eq!(loaded.release, None);
        assert!(loaded.components.contains("rustc"));
        Ok(())
    }

    #[test]
    fn first_install_staging_does_not_publish_until_complete() -> Result<()> {
        let versions = TempDir::new()?;
        let version_dir = versions.path().join("stable-x86_64-unknown-linux-gnu");
        let staging = begin_staged_install(versions.path())?;
        fs::write(staging.path().join("bin-placeholder"), b"partial")?;
        RustManager::write_metadata(
            staging.path(),
            &RustToolchainMetadata {
                release: Some("1.78.0".to_string()),
                components: BTreeSet::from(["rustc".to_string()]),
                targets: BTreeSet::new(),
            },
        )?;

        assert!(!version_dir.exists());
        assert!(crate::runtimes::common::list_installed_versions(versions.path())?.is_empty());

        crate::runtimes::common::complete_staged_install(
            &staging,
            &version_dir,
            "stable-x86_64-unknown-linux-gnu",
        )?;
        assert!(version_dir.join(RUST_METADATA_FILE).is_file());
        assert_eq!(
            crate::runtimes::common::list_installed_versions(versions.path())?,
            vec!["stable-x86_64-unknown-linux-gnu".to_string()]
        );
        Ok(())
    }

    #[test]
    fn incremental_replace_keeps_existing_files_and_new_metadata() -> Result<()> {
        let versions = TempDir::new()?;
        let version_dir = versions.path().join("stable-x86_64-unknown-linux-gnu");
        fs::create_dir_all(version_dir.join("bin"))?;
        fs::write(version_dir.join("bin/rustc"), b"old")?;
        RustManager::write_metadata(
            &version_dir,
            &RustToolchainMetadata {
                release: Some("1.78.0".to_string()),
                components: BTreeSet::from(["rustc".to_string()]),
                targets: BTreeSet::new(),
            },
        )?;

        let staging = begin_staged_install(versions.path())?;
        copy_regular_tree(&version_dir, staging.path())?;
        fs::write(staging.path().join("bin/clippy"), b"new")?;
        let mut metadata = RustManager::read_metadata(staging.path())?;
        metadata.components.insert("clippy".to_string());
        RustManager::write_metadata(staging.path(), &metadata)?;
        crate::runtimes::common::replace_staged_install(
            &staging,
            &version_dir,
            "stable-x86_64-unknown-linux-gnu",
        )?;

        assert_eq!(fs::read(version_dir.join("bin/rustc"))?, b"old");
        assert_eq!(fs::read(version_dir.join("bin/clippy"))?, b"new");
        let loaded = RustManager::read_metadata(&version_dir)?;
        assert!(loaded.components.contains("rustc"));
        assert!(loaded.components.contains("clippy"));
        Ok(())
    }

    #[test]
    fn reject_invalid_toolchain_path_blocks_files_and_allows_missing() -> Result<()> {
        let temp = TempDir::new()?;
        let missing = temp.path().join("missing");
        RustManager::reject_invalid_toolchain_path(&missing)?;

        let file_path = temp.path().join("file");
        fs::write(&file_path, b"not a dir")?;
        let error = RustManager::reject_invalid_toolchain_path(&file_path)
            .expect_err("regular files must be rejected");
        assert!(error.to_string().contains("non-directory"));
        Ok(())
    }

    #[tokio::test]
    async fn manifest_component_downloads_cannot_target_private_networks() -> Result<()> {
        let temp = TempDir::new()?;
        let dest = temp.path().join("evil.tar.xz");
        let error = download_with_progress(
            download_client(),
            "http://192.168.1.5/evil.tar.xz",
            &dest,
            &"a".repeat(64),
        )
        .await
        .expect_err("plain-HTTP private-network downloads must be refused");
        assert!(error.to_string().contains("HTTPS"), "{error}");
        assert!(!dest.exists(), "nothing may be written for refused URLs");
        Ok(())
    }

    #[test]
    fn host_target_does_not_require_a_second_standard_library_download() {
        assert!(!is_additional_target(
            "x86_64-unknown-linux-gnu",
            "x86_64-unknown-linux-gnu"
        ));
        assert!(is_additional_target(
            "wasm32-unknown-unknown",
            "x86_64-unknown-linux-gnu"
        ));
    }

    #[test]
    fn test_profile_components() {
        let minimal = profile_components("minimal").unwrap();
        assert!(minimal.contains(&"rustc".to_string()));
        assert!(minimal.contains(&"cargo".to_string()));
        assert!(!minimal.contains(&"clippy".to_string()));

        let default = profile_components("default").unwrap();
        assert!(default.contains(&"clippy".to_string()));
        assert!(default.contains(&"rustfmt".to_string()));
        assert!(profile_components("complete").is_err());
    }

    #[test]
    fn test_default_host_triple() {
        let triple = default_host_triple().unwrap();
        // Platform-agnostic check: should contain any valid OS component
        assert!(
            triple.contains("linux") || triple.contains("darwin") || triple.contains("windows")
        );
    }

    #[test]
    fn manifest_helpers_map_rustfmt_and_clippy_to_preview_packages() -> Result<()> {
        let manifest: toml::Value = toml::from_str(
            r#"
[pkg.rustfmt-preview.target.x86_64-unknown-linux-gnu]
xz_url = "https://example.invalid/rustfmt.tar.xz"
xz_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[pkg.clippy-preview.target.x86_64-unknown-linux-gnu]
xz_url = "https://example.invalid/clippy.tar.xz"
xz_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
"#,
        )?;

        assert_eq!(
            manifest_component_url(&manifest, "rustfmt", "x86_64-unknown-linux-gnu")?,
            "https://example.invalid/rustfmt.tar.xz"
        );
        assert_eq!(
            manifest_component_url(&manifest, "clippy", "x86_64-unknown-linux-gnu")?,
            "https://example.invalid/clippy.tar.xz"
        );
        Ok(())
    }

    /// The manifest is fetched once per install and shared by every
    /// component/target download; this pins the extraction helpers that
    /// consume that single shared manifest.
    #[test]
    fn manifest_helpers_resolve_a_single_shared_manifest() -> Result<()> {
        let hash = "a".repeat(64);
        let manifest_text = format!(
            r#"
[pkg.rustc]
version = "1.78.0 (2024-05-02)"

[pkg.rustc.target.x86_64-unknown-linux-gnu]
xz_url = "https://static.rust-lang.org/dist/2024-05-02/rust-1.78.0-x86_64-unknown-linux-gnu.tar.xz"
xz_hash = "{hash}"
"#
        );
        let manifest: toml::Value = toml::from_str(&manifest_text)?;

        assert_eq!(manifest_version(&manifest).as_deref(), Some("1.78.0"));

        let url = manifest_component_url(&manifest, "rustc", "x86_64-unknown-linux-gnu")?;
        assert!(url.ends_with("rust-1.78.0-x86_64-unknown-linux-gnu.tar.xz"));

        // XZ URLs select the xz_hash field, parsed through the strict digest validator.
        let checksum =
            manifest_component_checksum(&manifest, "rustc", "x86_64-unknown-linux-gnu", url)?;
        assert_eq!(checksum, hash);
        Ok(())
    }

    #[test]
    fn rolling_channel_detects_a_new_manifest_release() -> Result<()> {
        let manifest: toml::Value = toml::from_str(
            r#"
[pkg.rustc]
version = "1.79.0 (2024-06-13)"
"#,
        )?;

        let stable = RustToolchainSpec::parse("stable")?;
        assert!(channel_release_changed(&stable, Some("1.78.0"), &manifest)?);
        assert!(!channel_release_changed(
            &stable,
            Some("1.79.0 (2024-06-13)"),
            &manifest
        )?);
        Ok(())
    }

    #[test]
    fn rolling_nightly_detects_a_new_commit_with_the_same_semver() -> Result<()> {
        let manifest: toml::Value = toml::from_str(
            r#"
[pkg.rustc]
version = "1.80.0-nightly (aaaaaaaaa 2024-06-13)"
"#,
        )?;

        let nightly = RustToolchainSpec::parse("nightly")?;
        assert!(channel_release_changed(
            &nightly,
            Some("1.80.0-nightly (bbbbbbbbb 2024-06-12)"),
            &manifest
        )?);
        assert!(!channel_release_changed(
            &nightly,
            Some("1.80.0-nightly (aaaaaaaaa 2024-06-13)"),
            &manifest
        )?);
        Ok(())
    }

    #[test]
    fn pinned_toolchains_ignore_newer_channel_manifests() -> Result<()> {
        let manifest: toml::Value = toml::from_str(
            r#"
[pkg.rustc]
version = "1.79.0 (2024-06-13)"
"#,
        )?;

        let exact = RustToolchainSpec::parse("1.78.0")?;
        let dated = RustToolchainSpec::parse("nightly-2024-05-02")?;
        assert!(!channel_release_changed(&exact, Some("1.78.0"), &manifest)?);
        assert!(!channel_release_changed(&dated, Some("1.78.0"), &manifest)?);
        Ok(())
    }
}
