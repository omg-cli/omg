//! Native Erlang/OTP manager.
//!
//! Prebuilt binaries with publisher-published checksums on both hosts:
//! - Linux (Ubuntu/Debian): Hex's bob builds at
//!   `https://builds.hex.pm/builds/otp/{arch}/ubuntu-{release}/`. The
//!   `builds.txt` rows contain release, source commit, timestamp, and an
//!   optional archive SHA-256. Only rows with archive checksums are installable;
//!   the source commit is not an archive checksum. The
//!   tarballs are `OTP-<version>.tar.gz` in the same directory. The
//!   [asdf-erlang-prebuilt](https://github.com/kiwi-research/asdf-erlang-prebuilt)
//!   installer documents this layout, including the post-extract
//!   `./Install -minimal <dir>` step Linux builds require.
//! - macOS: [erlef/otp_builds](https://github.com/erlef/otp_builds) GitHub
//!   releases. The `{arch}-apple-darwin.csv` index documents
//!   `{ref_name},{ref},{datetime},{sha256},{openssl},{wx}` rows, and the
//!   README's verify flow checks the tarball against the `sha256` column.
//!
//! Verification is fail-closed against the published archive SHA-256 on
//! both platforms, plus a `bin/erl` smoke run that also catches glibc
//! incompatibility on non-Ubuntu distros (same probe the asdf installer
//! uses before falling back to source).

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use super::common::{
    activate_version_with_linked_binary, begin_staged_install, complete_staged_install,
    download_with_progress, extract_tar_gz, is_valid_version_dir, normalize_version,
    parse_sha256_digest, print_already_installed, print_installed, print_using,
    remove_file_best_effort, uninstall_version, validate_download_filename,
};
use crate::core::http::BoundedResponseExt;
use crate::{cli::style, core::http::download_client};

/// Override the Ubuntu release used for hex.pm URLs
/// (asdf parity: `ASDF_ERLANG_UBUNTU_RELEASE`).
const UBUNTU_RELEASE_OVERRIDE_ENV: &str = "OMG_ERLANG_UBUNTU_RELEASE";

// Hex still serves archived indexes for 18.04 (amd64 only) and 20.04.
const UBUNTU_BUILD_RELEASES: &[&str] = &["18.04", "20.04", "22.04", "24.04", "26.04"];
const UBUNTU_FALLBACK_RELEASE: &str = "24.04";

/// An upstream OTP release with its index checksum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OtpVersion {
    /// Bare version (`27.0`, `24.3.4.10`); the `OTP-` prefix is stripped.
    pub(crate) version: String,
    /// Archive SHA-256 from the publisher index.
    pub(crate) checksum: String,
}

pub(crate) struct ErlangManager {
    security: super::security::RuntimeSecurity,
    versions_dir: PathBuf,
    client: &'static reqwest::Client,
}

/// Host addressing: `(index arch token, tarball arch token)`.
fn host_arch_tokens() -> Result<(&'static str, &'static str)> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok(("amd64", "amd64")),
        ("linux", "aarch64") => Ok(("arm64", "arm64")),
        ("macos", "x86_64") => Ok(("x86_64", "x86_64")),
        ("macos", "aarch64") => Ok(("aarch64", "aarch64")),
        (os, arch) => anyhow::bail!("Unsupported operating system for Erlang/OTP: {os}/{arch}"),
    }
}

/// Map `/etc/os-release` identity to a hex.pm Ubuntu release.
///
/// Ubuntu uses its own `VERSION_ID`; Debian maps to the closest Ubuntu
/// build; anything else (Fedora, Arch, …) takes the latest LTS and relies
/// on the post-install smoke test to reject incompatible builds.
fn map_os_release(distro_id: &str, version_id: &str) -> &'static str {
    match distro_id {
        "ubuntu" => match version_id {
            "20.04" => "20.04",
            "22.04" => "22.04",
            "24.04" => "24.04",
            "26.04" => "26.04",
            _ => UBUNTU_FALLBACK_RELEASE,
        },
        "debian" => match version_id.split('.').next().unwrap_or("") {
            "10" => "18.04",
            "11" => "20.04",
            "12" => "22.04",
            _ => UBUNTU_FALLBACK_RELEASE,
        },
        _ => UBUNTU_FALLBACK_RELEASE,
    }
}

/// Parse one `ID=`/`VERSION_ID=` field out of os-release content.
fn os_release_field(content: &str, key: &str) -> String {
    content
        .lines()
        .filter_map(|line| line.split_once('='))
        .find(|(name, _)| name.trim() == key)
        .map(|(_, value)| value.trim().trim_matches('"').to_string())
        .unwrap_or_default()
}

fn compatible_ubuntu_builds(arch: &str) -> &'static [&'static str] {
    if arch == "arm64" {
        &UBUNTU_BUILD_RELEASES[1..]
    } else {
        UBUNTU_BUILD_RELEASES
    }
}

/// Detect the hex.pm Ubuntu release for this host.
fn ubuntu_release(arch: &str) -> Result<&'static str> {
    match std::env::var(UBUNTU_RELEASE_OVERRIDE_ENV) {
        Ok(pinned) if !pinned.trim().is_empty() => {
            let releases = compatible_ubuntu_builds(arch);
            return releases
                .iter()
                .copied()
                .find(|release| *release == pinned.trim())
                .with_context(|| {
                    format!(
                        "{UBUNTU_RELEASE_OVERRIDE_ENV} must be one of these Hex builds for {arch}: {}",
                        releases.join(", ")
                    )
                });
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("{UBUNTU_RELEASE_OVERRIDE_ENV} must be valid UTF-8");
        }
        _ => {}
    }
    let content = fs::read_to_string("/etc/os-release").unwrap_or_default();
    ubuntu_release_from_os(&content, arch)
}

fn ubuntu_release_from_os(content: &str, arch: &str) -> Result<&'static str> {
    let releases = compatible_ubuntu_builds(arch);
    let mapped = map_os_release(
        &os_release_field(content, "ID"),
        &os_release_field(content, "VERSION_ID"),
    );
    anyhow::ensure!(
        releases.contains(&mapped),
        "No Hex Erlang/OTP build for Ubuntu {mapped} on {arch}. Set {UBUNTU_RELEASE_OVERRIDE_ENV} to a compatible release from: {}",
        releases.join(", ")
    );
    Ok(mapped)
}

/// Version index URL for this host.
fn index_url() -> Result<String> {
    let (arch, _) = host_arch_tokens()?;
    match std::env::consts::OS {
        "linux" => {
            let release = ubuntu_release(arch)?;
            Ok(format!(
                "https://builds.hex.pm/builds/otp/{arch}/ubuntu-{release}/builds.txt"
            ))
        }
        "macos" => Ok(format!(
            "https://raw.githubusercontent.com/erlef/otp_builds/refs/heads/main/builds/{arch}-apple-darwin.csv"
        )),
        os => anyhow::bail!("Unsupported operating system for Erlang/OTP: {os}"),
    }
}

/// asdf parity: hex.pm and erlef name tarballs `OTP-28.2`, so a trailing
/// `.0` patch is dropped for URL construction (`28.2.0` → `28.2`).
fn upstream_version(version: &str) -> &str {
    version.strip_suffix(".0").unwrap_or(version)
}

/// Tarball download URL for one resolved version on this host.
fn tarball_url(version: &str) -> Result<String> {
    let (arch, _) = host_arch_tokens()?;
    let upstream = upstream_version(version);
    match std::env::consts::OS {
        "linux" => {
            let release = ubuntu_release(arch)?;
            Ok(format!(
                "https://builds.hex.pm/builds/otp/{arch}/ubuntu-{release}/OTP-{upstream}.tar.gz"
            ))
        }
        "macos" => Ok(format!(
            "https://github.com/erlef/otp_builds/releases/download/OTP-{upstream}/otp-{arch}-apple-darwin.tar.gz"
        )),
        os => anyhow::bail!("Unsupported operating system for Erlang/OTP: {os}"),
    }
}

/// Whether an upstream `OTP-…` name is a stable release (no release
/// candidates, no branch snapshots like `maint-27`).
fn is_stable_release(name: &str) -> bool {
    name.starts_with("OTP-") && !name.to_ascii_lowercase().contains("-rc")
}

/// Parse checksum-bearing hex.pm rows; legacy source-commit-only rows cannot verify archives.
fn parse_builds_txt(text: &str) -> Result<Vec<OtpVersion>> {
    let mut versions = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(name), Some(hash)) = (fields.next(), fields.next()) else {
            anyhow::bail!("Malformed builds.txt row {}: {line:?}", index + 1);
        };
        if !is_stable_release(name) {
            continue;
        }
        let version = name
            .strip_prefix("OTP-")
            .filter(|bare| {
                bare.chars()
                    .next()
                    .is_some_and(|first| first.is_ascii_digit())
            })
            .with_context(|| format!("Malformed OTP release name: {name:?}"))?;
        anyhow::ensure!(
            hash.len() == 40 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "Malformed OTP source commit on row {}",
            index + 1
        );
        fields.next().context("Missing OTP build timestamp")?;
        let Some(archive_hash) = fields.next() else {
            continue;
        };
        let checksum =
            parse_sha256_digest(archive_hash, "builds.hex.pm builds.txt archive checksum")?;
        versions.push(OtpVersion {
            version: version.to_string(),
            checksum,
        });
    }
    Ok(versions)
}

/// Parse an erlef `*-apple-darwin.csv` index
/// (`ref_name,ref,datetime,sha256,openssl,wxwidgets`, header first).
fn parse_erlef_csv(text: &str) -> Result<Vec<OtpVersion>> {
    let mut versions = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("ref_name,") {
            continue;
        }
        let fields: Vec<&str> = line.split(',').collect();
        let name = fields.first().copied().unwrap_or("").trim();
        let hash = fields.get(3).copied().unwrap_or("").trim();
        if name.is_empty() || !is_stable_release(name) {
            continue;
        }
        if hash.is_empty() {
            anyhow::bail!("CSV row {} ({name}) carries no SHA-256 checksum", index + 1);
        }
        let version = name
            .strip_prefix("OTP-")
            .filter(|bare| {
                bare.chars()
                    .next()
                    .is_some_and(|first| first.is_ascii_digit())
            })
            .with_context(|| format!("Malformed OTP release name: {name:?}"))?;
        let checksum = parse_sha256_digest(hash, "erlef otp_builds CSV")?;
        versions.push(OtpVersion {
            version: version.to_string(),
            checksum,
        });
    }
    Ok(versions)
}

/// Numeric dotted-version comparison (`24.3.4.10` vs `27.0`); non-numeric
/// components compare as zero so a malformed row can never panic sorting.
fn version_parts(version: &str) -> Vec<u64> {
    version
        .split('.')
        .map(|part| part.parse().unwrap_or(0))
        .collect()
}

/// Sort newest-first for `list_available` and `latest` resolution.
fn sort_versions_desc(versions: &mut [OtpVersion]) {
    versions.sort_by(|left, right| {
        version_parts(&right.version)
            .cmp(&version_parts(&left.version))
            .then_with(|| left.version.cmp(&right.version))
    });
}

impl ErlangManager {
    pub fn new() -> Self {
        Self {
            security: super::security::RuntimeSecurity::default(),
            versions_dir: super::DATA_DIR.join("versions/erlang"),
            client: download_client(),
        }
    }

    /// Fetch a publisher version index as text.
    async fn fetch_index(&self, url: &str) -> Result<String> {
        self.client
            .get(url)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .with_context(|| format!("Failed to fetch Erlang/OTP index from {url}"))?
            .error_for_status()
            .with_context(|| format!("Erlang/OTP index request failed: {url}"))?
            .bounded_text()
            .await
            .with_context(|| format!("Failed to read Erlang/OTP index from {url}"))
    }

    /// List available upstream releases (newest first).
    pub async fn list_available(&self) -> Result<Vec<OtpVersion>> {
        let url = index_url()?;
        let text = self.fetch_index(&url).await?;
        let mut versions = match std::env::consts::OS {
            "linux" => parse_builds_txt(&text)?,
            "macos" => parse_erlef_csv(&text)?,
            os => anyhow::bail!("Unsupported operating system for Erlang/OTP: {os}"),
        };
        sort_versions_desc(&mut versions);
        Ok(versions)
    }

    /// Resolve `latest` and partial requests (`27`, `27.0`) against the
    /// upstream list. Exact versions pass through so the installed fast path
    /// and the existing not-found UX are preserved.
    pub async fn resolve_alias(&self, alias: &str) -> Result<String> {
        let alias = normalize_version(alias);
        if alias == "latest" {
            let versions = self.list_available().await?;
            versions
                .first()
                .map(|version| version.version.clone())
                .context("No Erlang/OTP versions found upstream")
        } else {
            Ok(alias)
        }
    }

    /// Resolve a partial version against the upstream list.
    async fn resolve_requested_version(&self, version: &str) -> Result<String> {
        if !super::common::is_partial_version(version) {
            return Ok(version.to_owned());
        }
        let available = self.list_available().await?;
        let names: Vec<String> = available
            .iter()
            .map(|version| version.version.clone())
            .collect();
        Ok(super::resolve_version_request(&names, version))
    }

    /// Find the index checksum for one resolved version.
    async fn checksum_for_version(&self, version: &str) -> Result<String> {
        let available = self.list_available().await?;
        available
            .into_iter()
            .find(|candidate| candidate.version == version)
            .map(|candidate| candidate.checksum)
            .with_context(|| {
                format!(
                    "Version {version} not found for Erlang/OTP. Check available versions with: omg list erlang --available"
                )
            })
    }

    /// Install Erlang/OTP from a publisher prebuilt tarball.
    pub async fn install(&self, version: &str) -> Result<()> {
        let version = self.resolve_alias(version).await?;
        let version = self.resolve_requested_version(&version).await?;
        crate::core::security::validate_runtime_version(&version)?;
        let _install_lease = self.lock_install_destination(&version)?;
        let version_dir = self.versions_dir.join(&version);

        if is_valid_version_dir(&version_dir) {
            print_already_installed("Erlang/OTP", &version);
            return self.use_version(&version);
        }

        println!(
            "{} Installing Erlang/OTP {}...\n",
            style::runtime("OMG"),
            style::caution(&version)
        );

        let checksum = self.checksum_for_version(&version).await?;
        let url = tarball_url(&version)?;
        let filename = url
            .rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .with_context(|| format!("Erlang/OTP URL has no filename: {url}"))?;
        validate_download_filename(filename)?;

        fs::create_dir_all(&self.versions_dir)?;

        println!("{} Downloading {filename}...", style::informative("→"));
        let downloads = tempfile::Builder::new()
            .prefix(".download-")
            .tempdir_in(&self.versions_dir)?;
        let download_path = downloads.path().join(filename);
        download_with_progress(self.client, &url, &download_path, &checksum).await?;

        println!("{} Extracting (pure Rust)...", style::informative("→"));
        self.publish_download(&download_path, &url, &version)
            .await?;

        print_installed("Erlang/OTP", &version);
        self.use_version(&version)?;

        Ok(())
    }

    fn lock_install_destination(&self, version: &str) -> Result<super::common::RuntimeLease> {
        let install_lease = super::common::try_lock_runtime_install(&self.versions_dir, version)?;
        let destination = self.versions_dir.join(version);
        let _mutation_lease =
            super::common::try_lock_runtime_file(&self.versions_dir, ".mutation.lock")?;
        match fs::symlink_metadata(&destination) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(install_lease),
            Err(error) => {
                return Err(error)
                    .with_context(|| super::common::blocked_install_destination(&destination));
            }
            Ok(_) if is_valid_version_dir(&destination) => return Ok(install_lease),
            Ok(_) => {}
        }
        match fs::read_link(self.versions_dir.join("current")) {
            Ok(target) if target.ends_with(version) => {
                anyhow::bail!(
                    "Runtime path {} is still selected; select another installed Erlang version before retrying",
                    destination.display()
                );
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).context(
                    "Cannot verify the current Erlang selection; inspect it before retrying",
                );
            }
        }
        super::security::verify_interrupted_erlang_install(&destination, version)
            .with_context(|| super::common::blocked_install_destination(&destination))?;

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let retained = tempfile::Builder::new()
                .prefix(".interrupted-")
                .tempdir_in(&self.versions_dir)?
                .keep();
            let quarantine = retained.join(version);
            if let Err(error) = rustix::fs::renameat_with(
                rustix::fs::CWD,
                &destination,
                rustix::fs::CWD,
                &quarantine,
                rustix::fs::RenameFlags::NOREPLACE,
            ) {
                let _ = fs::remove_dir(&retained);
                return Err(error)
                    .with_context(|| super::common::blocked_install_destination(&destination));
            }
            println!(
                "Preserved the interrupted Erlang install at {}",
                quarantine.display()
            );
            Ok(install_lease)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        anyhow::bail!("Atomic Erlang recovery is unsupported on this platform")
    }

    async fn publish_download(&self, download_path: &Path, url: &str, version: &str) -> Result<()> {
        let version_dir = self.versions_dir.join(version);
        let publisher =
            super::security::record_download("erlang", version, &version_dir, download_path, url)?;
        let staging = begin_staged_install(&self.versions_dir)?;
        extract_tar_gz(download_path, staging.path(), 1).await?;
        if std::env::consts::OS == "linux" {
            require_staged_install_script(&staging.path().join("Install"))?;
        }
        write_pending_install_marker(staging.path())?;
        let admission =
            self.security
                .prepare_staged("erlang", version, staging.path(), &version_dir)?;
        complete_staged_install(&staging, &version_dir, version)?;
        publisher.commit();
        remove_file_best_effort(download_path, "runtime archive");

        // OTP's `Install` bakes absolute paths, so it runs after publication
        // in the final directory — never in staging, whose path is temporary.
        if std::env::consts::OS == "linux" {
            admission.before_execution(&version_dir)?;
            println!("{} Running OTP Install script...", style::informative("→"));
            if let Err(error) = run_install_script(&version_dir) {
                cleanup_broken_install(&version_dir);
                return Err(error);
            }
        }
        let after_setup =
            self.security
                .prepare_staged("erlang", version, &version_dir, &version_dir)?;
        after_setup.before_execution(&version_dir)?;
        println!("{} Verifying installation...", style::informative("→"));
        if let Err(error) = smoke_erl(&version_dir) {
            cleanup_broken_install(&version_dir);
            return Err(error.context(
                "The prebuilt Erlang/OTP binary does not run here (likely glibc \
                 incompatibility); try OMG_ERLANG_UBUNTU_RELEASE=<release>",
            ));
        }

        make_staged_executable(&version_dir.join("bin/erl"))?;
        let _finished =
            self.security
                .prepare_staged("erlang", version, &version_dir, &version_dir)?;
        fs::remove_file(version_dir.join(super::common::INSTALL_PENDING_MARKER))?;
        Ok(())
    }

    /// Switch to a specific version.
    pub fn use_version(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        crate::core::security::validate_runtime_version(&version)?;
        super::common::require_internal_runtime_binary(
            &self.versions_dir.join(&version),
            Path::new("bin/erl"),
        )?;
        let admission = self.security.installed(
            "erlang",
            &self.versions_dir.join(&version),
            super::security::ReviewMode::FreshAttended,
        )?;
        admission.verify(&self.versions_dir.join(&version))?;
        activate_version_with_linked_binary(&self.versions_dir, &version, Path::new("bin/erl"))?;
        print_using("Erlang/OTP", &version, &self.versions_dir.join("current"));
        Ok(())
    }

    /// Remove an installed version. Refuses the active version.
    pub fn uninstall(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        uninstall_version(&self.versions_dir, &version)
    }
}

// Generate common runtime manager methods (list_installed, current_version)
super::common::impl_runtime_common!(ErlangManager);

/// The staged Linux tree must carry OTP's `Install` script; without it the
/// install can never complete, so fail before publishing.
fn require_staged_install_script(script: &Path) -> Result<()> {
    if script.is_file() {
        Ok(())
    } else {
        anyhow::bail!(
            "Installed Erlang/OTP archive but found no `Install` script inside; \
             refusing to publish an uncompletable install"
        )
    }
}

/// Run OTP's `Install -minimal <dir>` in the published directory. The script
/// travels as argv (never interpolated) and runs under `sh` so a missing
/// executable bit on the script itself cannot break the install.
fn run_install_script(version_dir: &Path) -> Result<()> {
    let mut command = std::process::Command::new("sh");
    super::common::harden_untrusted_runtime_command(&mut command, version_dir);
    command
        .arg("Install")
        .arg("-minimal")
        .arg(version_dir)
        .current_dir(version_dir);
    super::tool_artifacts::run_with_timeout(
        command,
        "OTP Install script",
        std::time::Duration::from_mins(2),
    )?;
    Ok(())
}

/// Smoke-test the installed runtime: `erl` must start and halt cleanly.
/// This is also the glibc-compatibility probe (same check the asdf
/// installer runs before falling back to a source build).
fn smoke_erl(version_dir: &Path) -> Result<()> {
    let erl = version_dir.join("bin/erl");
    let mut command = std::process::Command::new(&erl);
    super::common::harden_untrusted_runtime_command(&mut command, version_dir);
    command.args(["-noshell", "-eval", "halt()."]);
    super::tool_artifacts::run_with_timeout(
        command,
        "Erlang/OTP smoke test",
        std::time::Duration::from_secs(30),
    )?;
    Ok(())
}

/// Remove a published-but-broken install; logs the cleanup failure instead
/// of masking the original install error.
fn cleanup_broken_install(version_dir: &Path) {
    if let Err(error) = fs::remove_dir_all(version_dir) {
        tracing::warn!(
            "Failed to remove broken Erlang/OTP install at {}: {error:#}",
            version_dir.display()
        );
    }
}

fn write_pending_install_marker(version_dir: &Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(version_dir.join(super::common::INSTALL_PENDING_MARKER))?
        .sync_all()?;
    Ok(())
}

/// Ensure the installed `erl` is executable (tarballs may drop modes).
#[cfg(unix)]
fn make_staged_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut permissions = fs::metadata(path)
        .with_context(|| format!("Failed to inspect staged binary: {}", path.display()))?
        .permissions();
    permissions.set_mode(permissions.mode() | 0o755);
    fs::set_permissions(path, permissions).with_context(|| {
        format!(
            "Failed to mark staged binary executable: {}",
            path.display()
        )
    })?;
    Ok(())
}

/// Non-Unix staging cannot produce executable binaries; fail at install time.
#[cfg(not(unix))]
fn make_staged_executable(_path: &Path) -> Result<()> {
    anyhow::bail!("Erlang/OTP installs are unsupported on this platform")
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires the isolated fixed-public TLS native fixture"]
    async fn native_public_install_preserves_authenticated_download_boundary() {
        use super::super::test_archive::{PublicationFixture, tar_gz_entries};
        use sha2::{Digest as _, Sha256};

        let version = "27.0.1";
        let launcher = b"#!/bin/sh\nexit 0\n";
        let archive = tar_gz_entries(
            "otp",
            &[
                ("Install", b"#!/bin/sh\nexit 0\n"),
                ("bin/erl", launcher),
                ("lib/owned.data", b"complete OTP implementation"),
            ],
        )
        .unwrap();
        let metadata = format!(
            "OTP-{version} {} 2026-09-01T00:00:00Z {}\n",
            "a".repeat(40),
            hex::encode(Sha256::digest(&archive))
        );
        let index = reqwest::Url::parse(&index_url().unwrap()).unwrap();
        let url = reqwest::Url::parse(&tarball_url(version).unwrap()).unwrap();
        super::super::test_https::fixed_public_routes(&[
            (index.host_str().unwrap(), index.path(), metadata.as_bytes()),
            (url.host_str().unwrap(), url.path(), &archive),
        ]);

        let fixture = PublicationFixture::new("erlang", "bin/erl");
        let manager = ErlangManager {
            security: super::super::security::RuntimeSecurity::fixture(),
            versions_dir: fixture.versions.clone(),
            client: download_client(),
        };
        seed_interrupted_install(&manager, &fixture, version, url.as_str()).unwrap();
        assert_eq!(manager.list_installed().unwrap(), ["1.0.0"]);
        manager
            .install(version)
            .await
            .expect("complete authenticated public installation");
        let installed = fixture.versions.join(version);
        assert_eq!(
            fs::read(fixture.versions.join("current").join("bin/erl")).unwrap(),
            launcher
        );
        assert_eq!(
            fs::read(installed.join("lib/owned.data")).unwrap(),
            b"complete OTP implementation"
        );
        assert_eq!(
            fs::read(fixture.versions.join("1.0.0/bin/erl")).unwrap(),
            b"previous reviewed runtime"
        );
        assert_interrupted_tree_preserved(&fixture, version);
        super::super::security::admit_installed(
            "erlang",
            &installed,
            super::super::security::ReviewMode::CachedOnly,
        )
        .expect("retain exact authenticated publisher authority")
        .verify(&installed)
        .expect("complete published tree matches its admission");
    }

    use super::*;

    fn seed_interrupted_install(
        manager: &ErlangManager,
        fixture: &super::super::test_archive::PublicationFixture,
        version: &str,
        url: &str,
    ) -> Result<()> {
        let destination = fixture.versions.join(version);
        let staging = begin_staged_install(&fixture.versions)?;
        fs::write(
            staging.path().join("interrupted-payload"),
            b"retained OTP bytes",
        )?;
        write_pending_install_marker(staging.path())?;
        fixture.write(b"controlled previous archive");
        let publisher = super::super::security::record_download(
            "erlang",
            version,
            &destination,
            &fixture.archive,
            url,
        )?;
        manager
            .security
            .prepare_staged("erlang", version, staging.path(), &destination)?;
        complete_staged_install(&staging, &destination, version)?;
        publisher.commit();
        Ok(())
    }

    fn assert_interrupted_tree_preserved(
        fixture: &super::super::test_archive::PublicationFixture,
        version: &str,
    ) {
        let quarantines: Vec<_> = fs::read_dir(&fixture.versions)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".interrupted-")
            })
            .collect();
        assert_eq!(quarantines.len(), 1);
        assert_eq!(
            fs::read(quarantines[0].join(version).join("interrupted-payload")).unwrap(),
            b"retained OTP bytes"
        );
    }

    #[tokio::test]
    async fn interrupted_erlang_install_can_retry_without_moving_ambiguous_paths() -> Result<()> {
        use super::super::test_archive::{PublicationFixture, tar_gz_entries};

        let fixture = PublicationFixture::new("erlang", "bin/erl");
        let manager = ErlangManager {
            security: super::super::security::RuntimeSecurity::fixture(),
            versions_dir: fixture.versions.clone(),
            client: download_client(),
        };
        let version = "27.0.0";
        let url = "https://builds.hex.pm/builds/otp/amd64/ubuntu-24.04/OTP-27.0.0.tar.gz";
        let path = fixture.versions.join(version);
        fs::create_dir(&path)?;
        fs::write(path.join("unowned"), b"untouched")?;
        let error = manager.install(version).await.unwrap_err();
        assert!(error.to_string().contains("if you own it, move it aside"));
        assert_eq!(fs::read(path.join("unowned"))?, b"untouched");
        let moved = fixture.versions.join(".owner-moved");
        fs::rename(&path, &moved)?;
        std::os::unix::fs::symlink(&moved, &path)?;
        let error = manager.install(version).await.unwrap_err();
        assert!(error.to_string().contains("left untouched"));
        assert_eq!(fs::read_link(&path)?, moved);
        fs::remove_file(&path)?;

        seed_interrupted_install(&manager, &fixture, version, url)?;
        let payload = path.join("interrupted-payload");
        fs::write(&payload, b"changed after receipt")?;
        assert!(
            manager
                .lock_install_destination(version)
                .unwrap_err()
                .to_string()
                .contains("left untouched")
        );
        assert_eq!(fs::read(&payload)?, b"changed after receipt");
        fs::write(&payload, b"retained OTP bytes")?;

        let in_use = super::super::common::try_lock_runtime_use(&fixture.versions)?;
        assert!(manager.lock_install_destination(version).is_err());
        assert_eq!(fs::read(&payload)?, b"retained OTP bytes");
        drop(in_use);
        let lease = manager.lock_install_destination(version)?;
        assert!(
            super::super::common::try_lock_runtime_install(&fixture.versions, version).is_err()
        );
        assert!(fs::symlink_metadata(&path).is_err());
        fixture.assert_previous();
        assert_interrupted_tree_preserved(&fixture, version);

        let launcher = b"#!/bin/sh\nexit 0\n";
        fixture.write(&tar_gz_entries(
            "otp",
            &[("Install", launcher), ("bin/erl", launcher)],
        )?);
        manager
            .publish_download(&fixture.archive, url, version)
            .await?;
        fixture.assert_previous();
        assert_eq!(manager.list_installed()?, [version, "1.0.0"]);
        manager.use_version(version)?;
        assert_eq!(manager.current_version().as_deref(), Some(version));
        assert_eq!(fs::read(moved.join("unowned"))?, b"untouched");
        assert_interrupted_tree_preserved(&fixture, version);
        drop(lease);
        Ok(())
    }

    const BUILDS_TXT: &str = "OTP-24.3.4 0863bd30aabd035c83158c78046c5ffda16127e1 2024-04-26T03:41:09Z\n\
         OTP-27.0 2915bea4768308995489fecfed2357dcb1574e6b 2026-09-07T00:50:41Z e077943ada95e593911db5ef9cbacdd60158bca25855bfce1f03fceb052738c6\n\
         OTP-29.0-rc3 332eb243babd06d1ff875853044e93d7b0a4b982c2e7abc4d1e4e9b8e133e3652dec5 2026-04-15T07:16:50Z\n\
         \n";

    const ERLEF_CSV: &str = "ref_name,ref,datetime,sha256,openssl,wxwidgets\n\
         master,bf4d114857f84d60766882c079dc461bc1bb3aba,2026-09-07T00:34:43Z,e017896d2f388be7960120445253fee862d71850c364e5ee18f3d574691d5ea7,openssl-3.5.8,wxwidgets-3.2.10\n\
         OTP-28.5,fc91226e454a9b8499791df7e6ceb867907bf41,2026-04-23T13:07:37Z,ded695f1d49c9e251b2afa0205dfdcb8ee16b4432aa1d5ffb38c6ee155bf7f6f,openssl-3.5.6,wxwidgets-3.2.10\n\
         OTP-29.0-rc2,81379e9b17fad721acae663a83901e44452f1,2026-03-18T10:32:59Z,9f030b550cf79d4564a1dc697f015b4d7b463261df1bcc61314b1a28367f8a03,openssl-3.5.5,wxwidgets-3.2.10\n";

    #[test]
    fn builds_txt_requires_archive_sha256_not_source_commit() {
        let versions = parse_builds_txt(BUILDS_TXT).expect("index parses");
        let names: Vec<&str> = versions
            .iter()
            .map(|version| version.version.as_str())
            .collect();
        // Release candidates are excluded; the `OTP-` prefix is stripped.
        assert_eq!(names, vec!["27.0"]);
        assert_eq!(versions[0].checksum.len(), 64);
        assert_eq!(
            versions[0].checksum,
            "e077943ada95e593911db5ef9cbacdd60158bca25855bfce1f03fceb052738c6"
        );
    }

    #[test]
    fn builds_txt_rejects_malformed_rows() {
        assert!(parse_builds_txt("OTP-27.0 not-a-hash 2026-01-01T00:00:00Z\n").is_err());
        assert!(parse_builds_txt("OTP-27.0\n").is_err());
        assert!(parse_builds_txt("garbage-row\n").is_err());
    }

    #[test]
    fn erlef_csv_parses_stable_with_sha256() {
        let versions = parse_erlef_csv(ERLEF_CSV).expect("CSV parses");
        let names: Vec<&str> = versions
            .iter()
            .map(|version| version.version.as_str())
            .collect();
        // Branches (`master`) and release candidates stay out.
        assert_eq!(names, vec!["28.5"]);
        assert_eq!(versions[0].checksum.len(), 64);
    }

    #[test]
    fn erlef_csv_rejects_missing_checksum() {
        let row = "ref_name,ref,datetime,sha256,openssl,wxwidgets\nOTP-27.0,abc,2024-01-01T00:00:00Z,,openssl-3,wx-3\n";
        assert!(parse_erlef_csv(row).is_err());
    }

    #[test]
    fn os_release_mapping_matches_asdf_behavior() {
        assert_eq!(map_os_release("ubuntu", "26.04"), "26.04");
        assert_eq!(map_os_release("ubuntu", "24.04"), "24.04");
        assert_eq!(map_os_release("ubuntu", "22.04"), "22.04");
        assert_eq!(map_os_release("ubuntu", "25.10"), "24.04");
        assert_eq!(map_os_release("debian", "12"), "22.04");
        assert_eq!(map_os_release("debian", "13"), "24.04");
        assert_eq!(map_os_release("debian", "11"), "20.04");
        assert_eq!(map_os_release("debian", "10"), "18.04");
        assert_eq!(map_os_release("fedora", "42"), "24.04");
        assert_eq!(map_os_release("", ""), "24.04");
        let legacy_debian = "ID=debian\nVERSION_ID=\"10\"\n";
        assert_eq!(
            ubuntu_release_from_os(legacy_debian, "amd64").unwrap(),
            "18.04"
        );
        let error = ubuntu_release_from_os(legacy_debian, "arm64")
            .expect_err("Debian 10 maps to a build that Hex never published for arm64");
        assert!(
            error
                .to_string()
                .contains("No Hex Erlang/OTP build for Ubuntu 18.04 on arm64")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ubuntu_override_uses_only_publisher_build_tokens() {
        const NAME: &str =
            "runtimes::erlang::tests::ubuntu_override_uses_only_publisher_build_tokens";
        if crate::core::testing::run_isolated_test(NAME) {
            return;
        }
        let (arch, _) = host_arch_tokens().expect("supported Linux coverage architecture");
        for release in ["20.04", "22.04", "24.04", "26.04"] {
            temp_env::with_var(UBUNTU_RELEASE_OVERRIDE_ENV, Some(release), || {
                assert_eq!(
                    index_url().expect("supported release resolves a publisher index"),
                    format!("https://builds.hex.pm/builds/otp/{arch}/ubuntu-{release}/builds.txt")
                );
                assert_eq!(
                    tarball_url("28.2.0").expect("supported release resolves a publisher archive"),
                    format!(
                        "https://builds.hex.pm/builds/otp/{arch}/ubuntu-{release}/OTP-28.2.tar.gz"
                    )
                );
            });
        }
        temp_env::with_var(UBUNTU_RELEASE_OVERRIDE_ENV, Some("18.04"), || {
            assert_eq!(ubuntu_release("amd64").unwrap(), "18.04");
            let error = ubuntu_release("arm64").expect_err("Hex has no legacy arm64 build");
            assert!(error.to_string().contains("for arm64"));
        });
        temp_env::with_var(UBUNTU_RELEASE_OVERRIDE_ENV, Some(" 22.04 "), || {
            assert_eq!(ubuntu_release("amd64").unwrap(), "22.04");
        });
        temp_env::with_var(UBUNTU_RELEASE_OVERRIDE_ENV, Some(""), || {
            assert!(UBUNTU_BUILD_RELEASES.contains(&ubuntu_release("amd64").unwrap()));
        });
        use std::os::unix::ffi::OsStrExt as _;
        let non_unicode = std::ffi::OsStr::from_bytes(b"\xff");
        temp_env::with_var(UBUNTU_RELEASE_OVERRIDE_ENV, Some(non_unicode), || {
            let error = index_url().expect_err("non-UTF-8 override must stop URL resolution");
            assert!(error.to_string().contains("must be valid UTF-8"));
        });
        temp_env::with_var(UBUNTU_RELEASE_OVERRIDE_ENV, Some("nobleb"), || {
            for error in [
                index_url().expect_err("invalid override must stop index resolution"),
                tarball_url("28.2.0").expect_err("invalid override must stop archive resolution"),
            ] {
                let diagnostic = error.to_string();
                assert!(
                    diagnostic.contains(UBUNTU_RELEASE_OVERRIDE_ENV),
                    "{diagnostic}"
                );
                assert!(diagnostic.contains("22.04, 24.04, 26.04"), "{diagnostic}");
            }
        });
    }

    #[test]
    fn os_release_fields_parse_quoted_values() {
        let content = "ID=ubuntu\nVERSION_ID=\"24.04\"\n";
        assert_eq!(os_release_field(content, "ID"), "ubuntu");
        assert_eq!(os_release_field(content, "VERSION_ID"), "24.04");
        assert_eq!(os_release_field(content, "MISSING"), "");
    }

    #[test]
    fn upstream_version_drops_one_trailing_zero() {
        assert_eq!(upstream_version("28.2.0"), "28.2");
        assert_eq!(upstream_version("27.1"), "27.1");
        assert_eq!(upstream_version("27.0"), "27");
        assert_eq!(upstream_version("24.3.4.10"), "24.3.4.10");
    }

    #[test]
    fn versions_sort_newest_first_numerically() {
        let mut versions = vec![
            OtpVersion {
                version: "24.3.4.10".to_string(),
                checksum: String::new(),
            },
            OtpVersion {
                version: "27.0".to_string(),
                checksum: String::new(),
            },
            OtpVersion {
                version: "27.0.1".to_string(),
                checksum: String::new(),
            },
        ];
        sort_versions_desc(&mut versions);
        let names: Vec<&str> = versions
            .iter()
            .map(|version| version.version.as_str())
            .collect();
        assert_eq!(names, vec!["27.0.1", "27.0", "24.3.4.10"]);
    }

    #[test]
    fn host_arch_tokens_name_the_platform() {
        const EXPECTED: Option<(&str, &str)> =
            if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
                Some(("amd64", "amd64"))
            } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
                Some(("arm64", "arm64"))
            } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
                Some(("x86_64", "x86_64"))
            } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
                Some(("aarch64", "aarch64"))
            } else {
                None
            };
        let (index, tarball) = host_arch_tokens().expect("host is supported");
        let expected = EXPECTED.expect("unsupported test host");
        assert_eq!((index, tarball), expected);
        assert_eq!(index, tarball);
        match std::env::consts::ARCH {
            "x86_64" => assert!(index.contains("64") || index.contains("amd")),
            "aarch64" => assert!(index.contains("arm") || index.contains("aarch")),
            arch => panic!("unexpected test host arch: {arch}"),
        }
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn downloaded_otp_publication_reviews_setup_and_smoke_phases_without_changing_prior_selection()
     {
        use super::super::test_archive::{PublicationFixture, mutation_security, tar_gz_entries};
        let fixture = PublicationFixture::new("erlang", "bin/erl");
        let mut manager = ErlangManager {
            security: super::super::security::RuntimeSecurity::fixture(),
            versions_dir: fixture.versions.clone(),
            client: download_client(),
        };
        let url = "https://builds.hex.pm/builds/otp/amd64/ubuntu-24.04/OTP-27.0.0.tar.gz";
        assert!(
            manager
                .publish_download(&fixture.archive, url, "27.0.0")
                .await
                .is_err()
        );
        fixture.assert_previous();
        fixture.write(b"invalid compressed OTP archive");
        assert!(
            manager
                .publish_download(&fixture.archive, url, "27.0.0")
                .await
                .is_err()
        );
        fixture.assert_previous();
        let cases = [
            "tamper",
            #[cfg(target_os = "linux")]
            "setup-failure",
            #[cfg(target_os = "linux")]
            "setup-escape",
            "smoke-failure",
            "smoke-escape",
            "success",
        ];
        for case in cases {
            let install = match case {
                "setup-failure" => b"#!/bin/sh\nexit 19\n".as_slice(),
                "setup-escape" => {
                    b"#!/bin/sh\nln -s /bin/sh \"$HOME/escaped-after-setup\"\n".as_slice()
                }
                _ => b"#!/bin/sh\nexit 0\n".as_slice(),
            };
            let launcher = match case {
                "smoke-failure" => b"#!/bin/sh\nexit 23\n".as_slice(),
                "smoke-escape" => {
                    b"#!/bin/sh\nln -s /bin/sh \"$HOME/escaped-after-smoke\"\n".as_slice()
                }
                _ => b"#!/bin/sh\nexit 0\n".as_slice(),
            };
            let bytes = tar_gz_entries("otp", &[("Install", install), ("bin/erl", launcher)])
                .expect("controlled OTP archive with setup and interpreter");
            fixture.write(&bytes);
            manager.security = if case == "tamper" {
                mutation_security(&fixture.versions)
            } else {
                super::super::security::RuntimeSecurity::fixture()
            };
            let result = manager
                .publish_download(&fixture.archive, url, "27.0.0")
                .await;
            if case == "success" {
                result.expect("publish fully reviewed OTP setup and interpreter");
            } else {
                let error = result.expect_err("OTP setup or interpreter must not bypass admission");
                let message = format!("{error:#}");
                if case == "tamper" {
                    assert!(
                        message.contains("Runtime content changed after advisory review"),
                        "{message}"
                    );
                }
                if case == "setup-failure" {
                    assert!(message.contains("Install script failed"), "{message}");
                }
                if case == "smoke-failure" {
                    assert!(message.contains("smoke test failed"), "{message}");
                }
                if case.ends_with("escape") {
                    assert!(
                        message.contains("Runtime advisory inventory contains an escaping link"),
                        "{message}"
                    );
                    let injected =
                        fixture
                            .versions
                            .join("27.0.0")
                            .join(if case == "setup-escape" {
                                "escaped-after-setup"
                            } else {
                                "escaped-after-smoke"
                            });
                    assert_eq!(
                        fs::read_link(injected).expect("intended post-execution escape control"),
                        Path::new("/bin/sh")
                    );
                }
                let failed = fixture.versions.join("27.0.0");
                if failed.exists() {
                    fs::remove_dir_all(failed).expect("retire only the owned failed OTP fixture");
                }
            }
            fixture.assert_previous();
        }
        manager
            .use_version("27.0.0")
            .expect("select fully reviewed OTP runtime");
        fs::remove_file(fixture.versions.join("current")).expect("restore prior OTP selection");
        std::os::unix::fs::symlink("1.0.0", fixture.versions.join("current"))
            .expect("prior OTP selection");
        let launcher = fixture.versions.join("27.0.0/bin/erl");
        let original = fs::read(&launcher).expect("published controlled launcher");
        let permissions = fs::metadata(&launcher)
            .expect("published controlled launcher mode")
            .permissions();
        fs::remove_file(&launcher).expect("remove only the candidate launcher");
        let error = manager
            .use_version("27.0.0")
            .expect_err("a missing candidate launcher must fail before advisory review");
        assert!(format!("{error:#}").contains("Failed to inspect runtime binary"));
        fixture.assert_previous();
        let outside = fixture.versions.join("outside-erlang");
        fs::write(&outside, b"outside controlled runtime bytes")
            .expect("outside candidate payload");
        std::os::unix::fs::symlink(&outside, &launcher).expect("escaping candidate alias");
        let error = manager
            .use_version("27.0.0")
            .expect_err("an escaping candidate launcher must not replace the active runtime");
        assert!(format!("{error:#}").contains("Runtime binary symlink escapes version directory"));
        fixture.assert_previous();
        assert_eq!(
            fs::read(&outside).unwrap(),
            b"outside controlled runtime bytes"
        );
        fs::remove_file(&launcher).expect("remove only the escaping candidate alias");
        fs::write(&launcher, original).expect("restore the controlled launcher");
        fs::set_permissions(&launcher, permissions).expect("restore its exact published mode");
        fixture.corrupt_identity("27.0.0");
        assert!(manager.use_version("27.0.0").is_err());
        fixture.assert_previous();
    }
}
