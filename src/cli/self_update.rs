//! `omg self-update` - Update OMG to the latest version

use anyhow::{Context, Result};
use futures::StreamExt;
use owo_colors::OwoColorize;
use semver::Version;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;

use crate::cli::progress::{Accent, Outcome, ProgressTask, TaskKind, TaskSpec};
use crate::cli::style;
use crate::core::env::distro::{Distro, detect_distro};

const GITHUB_RELEASES_PAGE: &str = "https://github.com/omg-cli/omg/releases";

const RELEASES_BASE_URL: &str = "https://releases.omg.latham.cloud";

// GitHub's latest release cannot replace this pointer because rollback changes
// only the R2 marker.
const LATEST_VERSION_URL: &str = "https://releases.omg.latham.cloud/latest-version";
const MAX_LATEST_VERSION_BYTES: usize = 256;
const MAX_CHECKSUM_BYTES: usize = 1024;

/// Repository used to verify Sigstore build-provenance attestations.
const ATTESTATION_REPO: &str = "omg-cli/omg";

fn attestation_repository(tag: &str) -> Result<&'static str> {
    let version = Version::parse(tag.strip_prefix('v').context("Invalid release tag")?)?;
    // The namespace changed after v0.1.221. Do not fall back to another signer
    // after verification fails: each release has exactly one expected identity.
    Ok(
        if (version.major, version.minor, version.patch) <= (0, 1, 221) {
            "PyRo1121/omg"
        } else {
            ATTESTATION_REPO
        },
    )
}

/// Explicit opt-in that downgrades the provenance gate from fail-closed to
/// warning-only.
///
/// By default `omg self-update` refuses to install when Sigstore provenance
/// cannot be verified (typically because the GitHub CLI is not installed).
/// Setting this variable to `1`, `true`, or `yes` accepts an unverified
/// update deliberately; any other value (including unset) keeps the gate
/// closed.
const ALLOW_UNVERIFIED_PROVENANCE_ENV: &str = "OMG_SELF_UPDATE_ALLOW_UNVERIFIED_PROVENANCE";

/// Hard cap on the update archive download: bounds both `Vec` preallocation
/// driven by the server-reported `Content-Length` and streaming growth, so a
/// hostile release server cannot trigger runaway allocation.
const MAX_DOWNLOAD_BYTES: usize = 256 * 1024 * 1024;

/// Cap on `Vec::with_capacity` preallocation before streaming proves the size.
const MAX_PREALLOC_BYTES: usize = 16 * 1024 * 1024;

/// Update OMG to the latest version.
///
/// The latest version, archive, and checksum come from R2. The archive must
/// also pass GitHub's Sigstore attestation check before installation.
///
/// # Errors
///
/// Returns an error when the update check fails, the target version is not
/// newer (without `--force`), the artifact checksum sidecar is missing or
/// malformed, the download exceeds the size cap or its digest mismatches,
/// the attestation fails to verify, provenance cannot be verified (no `gh`)
/// without the explicit opt-in, or extraction / binary replacement fails.
pub async fn run(force: bool, version: Option<String>) -> Result<()> {
    let current_version = parse_version(env!("CARGO_PKG_VERSION"))
        .context("built-in CARGO_PKG_VERSION is not valid semver")?;
    println!(
        "{} Checking for updates... (current: v{current_version})",
        style::runtime("OMG"),
    );

    #[cfg(feature = "arch")]
    if !force
        && detect_distro() == Distro::Arch
        && let Ok(exe) = env::current_exe()
        && exe.starts_with("/usr/bin")
    {
        println!(
            "  {} Note: OMG is installed in system path ({})",
            style::maybe_color("ℹ", |t| t.blue().to_string()),
            exe.display()
        );
        println!(
            "     Updating via self-update may conflict with system package-managed files.\n\
             Recommended: update via your package manager: {}\n",
            style::command("omg update omg")
        );
    }

    let target_version = match version {
        Some(raw) => parse_version(&raw)
            .with_context(|| format!("`--version {raw}` is not valid semver (e.g. 1.2.3)"))?,
        None => fetch_latest_version().await?,
    };

    // Downgrade protection (audit25 aud-dep-installer): without --force,
    // only strictly newer releases may be installed. Equality and older
    // versions both stop here so a compromised/misconfigured release feed
    // cannot roll a user back to a vulnerable version.
    if !force {
        if target_version == current_version {
            println!(
                "  {} You are already on the latest version.",
                style::maybe_color("✓", |t| t.green().to_string())
            );
            return Ok(());
        }
        if target_version < current_version {
            anyhow::bail!(
                "Refusing to downgrade from {current_version} to {target_version} \
                 (use --force to override)"
            );
        }
    }

    let artifact = release_artifact(&target_version)?;

    println!(
        "  {} Downloading {}...",
        style::maybe_color("⬇", |t| t.blue().to_string()),
        artifact.object_name()
    );

    let bytes = fetch_release_archive(&artifact).await?;

    let archive_name = artifact.object_name();

    // Perform blocking extraction and binary replacement in a separate thread
    // to avoid blocking the tokio async runtime
    let attestation_tag = format!("v{target_version}");
    let probe_version = target_version.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        // Provenance gate: `gh attestation verify` requires a file on disk, so
        // stage the digest-verified bytes for both the verification and the
        // subsequent extraction.
        let attestation_file = tempfile::NamedTempFile::new()
            .context("Failed to stage archive for attestation verification")?;
        fs::write(attestation_file.path(), &bytes)
            .context("Failed to write archive for attestation verification")?;
        if !verify_attestation(attestation_file.path(), &attestation_tag)? {
            refuse_unverified_provenance()?;
        }

        let temp_dir = tempfile::tempdir().context("Failed to create temp directory for update")?;
        let (new_binary, new_daemon) = extract_update_pair(&bytes, temp_dir.path(), &archive_name)?;

        let current_exe = env::current_exe().context("Failed to find current executable path")?;
        tokio::runtime::Handle::current()
            .block_on(install_checked_update_pair(
                &new_binary,
                &new_daemon,
                &current_exe,
                &probe_version,
                std::time::Duration::from_secs(10),
            ))
            .context("Failed to install updated OMG binaries")
    })
    .await??;

    println!(
        "  {} Update successful!",
        style::maybe_color("✓", |t| t.green().to_string())
    );
    println!(
        "  omg and omgd {} are now installed.",
        style::maybe_color(&format!("v{target_version}"), |t| t.cyan().to_string())
    );
    println!(
        "  Restart any running omgd to load the updated daemon: restart its user service, or stop the existing daemon and run 'omg daemon'."
    );

    Ok(())
}

fn stage_update_binary(
    new_binary: &std::path::Path,
    destination: &std::path::Path,
) -> Result<tempfile::NamedTempFile> {
    let parent = destination
        .parent()
        .context("Current executable has no parent directory")?;
    let mut staged = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("Failed to stage update in {}", parent.display()))?;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits());
    }
    let mut source = options
        .open(new_binary)
        .with_context(|| format!("Failed to open update payload {}", new_binary.display()))?;
    anyhow::ensure!(
        source.metadata()?.is_file(),
        "Update payload is not a regular file"
    );
    std::io::copy(&mut source, staged.as_file_mut())
        .context("Failed to copy update payload into executable directory")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        staged
            .as_file_mut()
            .set_permissions(fs::Permissions::from_mode(0o755))
            .context("Failed to set updated binary permissions")?;
    }
    staged
        .as_file_mut()
        .sync_all()
        .context("Failed to sync updated binary")?;
    Ok(staged)
}

fn persist_update_binary(
    staged: tempfile::NamedTempFile,
    destination: &std::path::Path,
) -> Result<()> {
    staged
        .persist(destination)
        .map_err(|error| error.error)
        .with_context(|| format!("Failed to replace {}", destination.display()))?;
    crate::core::safe_ops::sync_parent_directory_sync(destination)?;
    Ok(())
}

#[cfg(test)]
fn install_binary_atomically(
    new_binary: &std::path::Path,
    destination: &std::path::Path,
) -> Result<()> {
    persist_update_binary(stage_update_binary(new_binary, destination)?, destination)
}

fn install_update_pair(
    cli: &std::path::Path,
    daemon: &std::path::Path,
    destination: &std::path::Path,
) -> Result<()> {
    install_update_pair_with(cli, daemon, destination, persist_update_binary)
}

async fn install_checked_update_pair(
    cli: &std::path::Path,
    daemon: &std::path::Path,
    destination: &std::path::Path,
    version: &Version,
    probe_timeout: std::time::Duration,
) -> Result<()> {
    probe_update_binary(cli, "omg", version, probe_timeout).await?;
    probe_update_binary(daemon, "omgd", version, probe_timeout).await?;
    install_update_pair(cli, daemon, destination)
}

async fn probe_update_binary(
    binary: &std::path::Path,
    name: &str,
    version: &Version,
    deadline: std::time::Duration,
) -> Result<()> {
    use std::process::Stdio;
    use tokio::io::AsyncReadExt;

    const OUTPUT_LIMIT: u64 = 4096;
    anyhow::ensure!(
        fs::symlink_metadata(binary)
            .with_context(|| format!("Missing {name} update candidate"))?
            .file_type()
            .is_file(),
        "{name} update candidate is not a regular file"
    );
    let mut command = tokio::process::Command::new(binary);
    command
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command
        .spawn()
        .with_context(|| format!("Failed to execute {name} version probe"))?;
    #[cfg(unix)]
    let probe_group = child.id().context("Version probe has no process ID")?;
    let stdout = child
        .stdout
        .take()
        .context("Missing version probe stdout")?;
    let stderr = child
        .stderr
        .take()
        .context("Missing version probe stderr")?;
    let read_output = |stream: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>| async move {
        let mut bytes = Vec::new();
        stream
            .take(OUTPUT_LIMIT + 1)
            .read_to_end(&mut bytes)
            .await?;
        anyhow::ensure!(
            bytes.len() <= OUTPUT_LIMIT as usize,
            "version probe output exceeds {OUTPUT_LIMIT} bytes"
        );
        Ok::<_, anyhow::Error>(bytes)
    };
    let probe = tokio::time::timeout(deadline, async {
        tokio::try_join!(
            read_output(Box::pin(stdout)),
            read_output(Box::pin(stderr)),
            wait_for_probe_exit_without_reaping(probe_group),
        )
    })
    .await
    .with_context(|| format!("{name} version probe timed out"))
    .and_then(std::convert::identity);
    let (stdout, stderr, ()) = match probe {
        Ok(result) => result,
        Err(error) => {
            // Kill the isolated group before reaping the leader. A candidate
            // may fork a helper which inherits the output pipes and otherwise
            // keeps the timed-out probe alive after its direct child exits.
            #[cfg(unix)]
            if probe_group_has_descendants(probe_group)? {
                kill_probe_group(probe_group)?;
            } else {
                kill_probe_leader(probe_group)?;
            }
            child
                .wait()
                .await
                .with_context(|| format!("Failed to reap {name} version probe after {error:#}"))?;
            return Err(error);
        }
    };
    #[cfg(unix)]
    if probe_group_has_descendants(probe_group)? {
        kill_probe_group(probe_group)?;
        child.wait().await.context("Failed to reap version probe")?;
        anyhow::bail!("{name} version probe left descendant processes running");
    }
    let status = child.wait().await.context("Failed to reap version probe")?;
    anyhow::ensure!(
        status.success(),
        "{name} version probe failed ({status}): {}",
        style::sanitize_terminal_text(&String::from_utf8_lossy(&stderr))
    );
    let expected = format!("{name} {version}");
    anyhow::ensure!(
        std::str::from_utf8(&stdout)?.trim() == expected,
        "Update candidate does not report {expected}"
    );
    Ok(())
}

#[cfg(unix)]
async fn wait_for_probe_exit_without_reaping(group: u32) -> Result<()> {
    use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};

    let pid = i32::try_from(group)
        .ok()
        .and_then(Pid::from_raw)
        .context("Version probe process ID was invalid")?;
    tokio::task::spawn_blocking(move || {
        waitid(
            WaitId::Pid(pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
        )
        .context("Failed to observe version probe exit without reaping")?
        .context("Version probe exit was not reported")?;
        Ok(())
    })
    .await
    .context("Version probe exit observer panicked")?
}

#[cfg(unix)]
fn probe_group_has_descendants(group: u32) -> Result<bool> {
    let ps = if cfg!(target_os = "macos") {
        "/bin/ps"
    } else {
        "/usr/bin/ps"
    };
    let output = std::process::Command::new(ps)
        .args(["-eo", "pid=,pgid="])
        .output()
        .context("Failed to inspect version probe process group")?;
    anyhow::ensure!(
        output.status.success(),
        "Process-group inspection failed with {}",
        output.status
    );
    for line in String::from_utf8(output.stdout)?.lines() {
        let mut fields = line.split_whitespace();
        let Some(pid) = fields.next() else { continue };
        let Some(pgid) = fields.next() else {
            continue;
        };
        let pid = pid.parse::<u32>().context("Invalid PID from ps")?;
        let pgid = pgid.parse::<u32>().context("Invalid PGID from ps")?;
        if pgid == group && pid != group {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(unix)]
fn kill_probe_group(group: u32) -> Result<()> {
    use nix::errno::Errno;
    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::Pid;

    let group = i32::try_from(group).context("Version probe process ID exceeded i32")?;
    let group_pid = Pid::from_raw(group);
    match killpg(group_pid, Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(error).context("Failed to kill version probe group"),
    }
}

#[cfg(unix)]
fn kill_probe_leader(pid: u32) -> Result<()> {
    use nix::errno::Errno;
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    let pid = i32::try_from(pid).context("Version probe process ID exceeded i32")?;
    match kill(Pid::from_raw(pid), Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(error).context("Failed to kill version probe leader"),
    }
}

fn extract_update_pair(
    bytes: &[u8],
    directory: &std::path::Path,
    archive_name: &str,
) -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    let cli = extract_update_binary(bytes, directory, archive_name)?
        .context("Update archive did not contain an 'omg' binary")?;
    let daemon = cli.with_file_name("omgd");
    anyhow::ensure!(
        daemon.is_file(),
        "Update archive did not contain an 'omgd' binary; refusing a partial update"
    );
    Ok((cli, daemon))
}

// Two renames are not an atomic pair. Stage everything first and roll back
// reported I/O failures; never claim success with only one binary installed.
fn install_update_pair_with(
    cli: &std::path::Path,
    daemon: &std::path::Path,
    destination: &std::path::Path,
    mut replace: impl FnMut(tempfile::NamedTempFile, &std::path::Path) -> Result<()>,
) -> Result<()> {
    let parent = destination.parent().context("Executable has no parent")?;
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits());
    }
    let lock = options.open(parent.join(".omg-self-update.lock"))?;
    let metadata = lock.metadata()?;
    anyhow::ensure!(metadata.is_file(), "Unsafe self-update lock");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        anyhow::ensure!(metadata.nlink() == 1, "Unsafe hard-linked self-update lock");
    }
    lock.try_lock()
        .context("Another self-update is in progress; retry when it finishes")?;
    // Keep the lock file: unlinking it would let another updater lock a new inode.
    let destinations = [
        destination.with_file_name("omgd"),
        destination.to_path_buf(),
    ];
    anyhow::ensure!(
        destinations[0] != destinations[1],
        "CLI and daemon destinations overlap"
    );
    let mut backups = Vec::new();
    for (index, path) in destinations.iter().enumerate() {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                anyhow::ensure!(
                    metadata.is_file(),
                    "Refusing non-regular update destination {}",
                    path.display()
                );
                let backup = stage_update_binary(path, path)?;
                backup.as_file().set_permissions(metadata.permissions())?;
                backup.as_file().sync_all()?;
                backups.push(Some(backup));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && index == 0 => {
                backups.push(None);
            }
            Err(error) => {
                return Err(error).with_context(|| format!("Cannot back up {}", path.display()));
            }
        }
    }
    let staged = [
        stage_update_binary(daemon, &destinations[0])?,
        stage_update_binary(cli, &destinations[1])?,
    ];
    for (index, new_binary) in staged.into_iter().enumerate() {
        if let Err(error) = replace(new_binary, &destinations[index]) {
            let mut recovery_errors = Vec::new();
            for (path, backup) in destinations.iter().zip(backups) {
                let restored = match backup {
                    Some(backup) => match backup.persist(path) {
                        Ok(_) => crate::core::safe_ops::sync_parent_directory_sync(path),
                        Err(failed) => {
                            let reason = failed.error.to_string();
                            let retained = failed.file.keep().map(|(_, path)| path);
                            Err(anyhow::anyhow!("{reason}; recovery copy: {retained:?}"))
                        }
                    },
                    None => match fs::remove_file(path) {
                        Ok(()) => crate::core::safe_ops::sync_parent_directory_sync(path),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                        Err(error) => Err(error.into()),
                    },
                };
                if let Err(recovery) = restored {
                    recovery_errors.push(format!("{}: {recovery:#}", path.display()));
                }
            }
            if recovery_errors.is_empty() {
                return Err(error).context("Update failed; previous OMG binaries restored");
            }
            anyhow::bail!(
                "Update failed: {error:#}; rollback needs attention: {}",
                recovery_errors.join("; ")
            );
        }
    }
    Ok(())
}

/// Two bounded binaries plus tar headers and release documentation.
const MAX_UPDATE_DECOMPRESSED_BYTES: u64 = 130 * 1024 * 1024;

/// Cap on entry count: a release archive holds a wrapper dir plus binaries.
const MAX_UPDATE_ARCHIVE_ENTRIES: usize = 16;

/// Cap on a single extracted update binary.
const MAX_UPDATE_BINARY_BYTES: u64 = 64 * 1024 * 1024;

/// Extract only the `omg` and `omgd` binaries from a release archive.
///
/// CI wraps the payload in a directory named after the archive
/// (`omg-v1.2.3-x86_64-linux-debian/omg`); a flat root-level `omg` layout is
/// accepted as a fallback. Unlike a general extractor this allowlists those
/// two layouts and materializes only regular files: symlinks, hard links,
/// and special entries fail closed instead of being created, so a malicious
/// archive cannot stage link-traversal writes or plant entries outside the
/// temp dir, and the decompression budget stops bombs.
fn extract_update_binary(
    bytes: &[u8],
    extract_dir: &std::path::Path,
    archive_name: &str,
) -> Result<Option<std::path::PathBuf>> {
    use std::io::Read as _;

    let wrapper: Option<std::path::PathBuf> = archive_name
        .strip_suffix(".tar.gz")
        .map(|stem| std::path::PathBuf::from(stem).join("omg"));
    let flat = std::path::PathBuf::from("omg");
    let daemon_wrapper = wrapper.as_ref().map(|path| path.with_file_name("omgd"));
    let daemon_flat = std::path::PathBuf::from("omgd");

    let cursor = std::io::Cursor::new(bytes);
    let decoder = flate2::read::GzDecoder::new(cursor);
    let budgeted =
        crate::runtimes::common::BudgetedReader::new(decoder, MAX_UPDATE_DECOMPRESSED_BYTES);
    let mut archive = tar::Archive::new(budgeted);

    let mut found: Option<std::path::PathBuf> = None;
    let mut found_daemon: Option<std::path::PathBuf> = None;
    let mut entries = 0usize;
    for entry in archive.entries().context("Failed to read update archive")? {
        entries += 1;
        anyhow::ensure!(
            entries <= MAX_UPDATE_ARCHIVE_ENTRIES,
            "Update archive contains too many entries"
        );
        let mut entry = entry.context("Failed to read update archive entry")?;
        let path = entry.path().context("Update archive entry has no path")?;
        let Some(relative) = crate::core::archive::stripped_archive_path(&path, 0)
            .context("Unsafe path in update archive")?
        else {
            continue;
        };
        let wanted_cli = Some(&relative) == wrapper.as_ref() || relative == flat;
        let wanted_daemon = Some(&relative) == daemon_wrapper.as_ref() || relative == daemon_flat;
        let wanted = wanted_cli || wanted_daemon;
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() && !wanted {
            continue;
        }
        if !wanted {
            // Documentation is ignored rather than published.
            continue;
        }
        anyhow::ensure!(
            entry_type.is_file(),
            "Update binary entry is not a regular file: {}",
            relative.display()
        );
        anyhow::ensure!(
            if wanted_cli {
                found.is_none()
            } else {
                found_daemon.is_none()
            },
            "Update archive contains a duplicate binary entry: {}",
            relative.display()
        );
        let dest_path = extract_dir.join(&relative);
        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }
        let mut content = Vec::new();
        anyhow::ensure!(
            entry.size() <= MAX_UPDATE_BINARY_BYTES,
            "Update binary exceeds the size bound"
        );
        entry
            .read_to_end(&mut content)
            .context("Failed to read update binary from archive")?;
        anyhow::ensure!(
            u64::try_from(content.len()).is_ok_and(|len| len <= MAX_UPDATE_BINARY_BYTES),
            "Update binary exceeds the size bound"
        );
        fs::write(&dest_path, &content)
            .with_context(|| format!("Failed to stage update binary {}", dest_path.display()))?;
        if wanted_cli {
            found = Some(dest_path);
        } else {
            found_daemon = Some(dest_path);
        }
    }
    if let (Some(cli), Some(daemon)) = (&found, &found_daemon) {
        anyhow::ensure!(
            cli.parent() == daemon.parent(),
            "Update binaries use inconsistent archive layouts"
        );
    }
    Ok(found)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LatestVersion(Version);

impl LatestVersion {
    fn parse(raw: &str) -> Result<Self> {
        if raw.len() > MAX_LATEST_VERSION_BYTES {
            anyhow::bail!(
                "latest-version marker exceeded the {MAX_LATEST_VERSION_BYTES} byte bound"
            );
        }
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            anyhow::bail!("latest-version marker is empty");
        }
        if trimmed.starts_with(['v', 'V']) {
            anyhow::bail!(
                "latest-version marker must be bare semantic version text without a 'v' tag prefix"
            );
        }
        let version =
            Version::parse(trimmed).context("latest-version marker is not valid semantic version");
        Ok(Self(version?))
    }

    fn into_version(self) -> Version {
        self.0
    }
}

#[derive(Debug)]
struct ReleaseArtifact {
    version: Version,
    arch: &'static str,
    target: &'static str,
}

impl ReleaseArtifact {
    fn object_name(&self) -> String {
        format!("omg-v{}-{}-{}.tar.gz", self.version, self.arch, self.target)
    }

    fn archive_url(&self) -> String {
        format!("{RELEASES_BASE_URL}/{}", self.object_name())
    }
}

fn parse_version(raw: &str) -> Result<Version> {
    let trimmed = raw.trim().trim_start_matches('v');
    Version::parse(trimmed).with_context(|| format!("invalid semantic version: {raw:?}"))
}

pub(super) async fn fetch_latest_version() -> Result<Version> {
    let safe_url = crate::core::http::redact_url(LATEST_VERSION_URL);
    let response = send_get(LATEST_VERSION_URL, &safe_url).await?;
    let body = read_bounded_body(response, MAX_LATEST_VERSION_BYTES, &safe_url).await?;
    LatestVersion::parse(&body).map(LatestVersion::into_version)
}

async fn read_bounded_body(
    response: reqwest::Response,
    max: usize,
    safe_url: &str,
) -> Result<String> {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(item) = stream.next().await {
        let chunk =
            item.with_context(|| format!("Failed to read response body from {safe_url}"))?;
        if body.len().saturating_add(chunk.len()) > max {
            anyhow::bail!("response body from {safe_url} exceeded the {max} byte bound");
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body)
        .with_context(|| format!("response body from {safe_url} was not UTF-8 text"))
}

async fn send_get(url: &str, safe_url: &str) -> Result<reqwest::Response> {
    let response = crate::core::http::shared_client()
        .get(url)
        .send()
        .await
        .with_context(|| format!("Failed to fetch {safe_url}"))?;
    if !response.status().is_success() {
        anyhow::bail!("Request failed: {} ({safe_url})", response.status());
    }
    Ok(response)
}

fn apt_release_target(distro: Distro, arch: &str, root: &std::path::Path) -> Option<&'static str> {
    if arch != "x86_64" || !matches!(distro, Distro::Debian | Distro::Ubuntu) {
        return None;
    }
    for major in ["7.0", "6.0"] {
        for directory in ["usr/lib/x86_64-linux-gnu", "lib/x86_64-linux-gnu"] {
            if root
                .join(directory)
                .join(format!("libapt-pkg.so.{major}"))
                .is_file()
            {
                return Some(match (major, distro) {
                    ("7.0", _) => "linux-debian-trixie",
                    (_, Distro::Debian) => "linux-debian",
                    _ => "linux-ubuntu",
                });
            }
        }
    }
    None
}

fn release_target(
    distro: Distro,
    arch: &str,
    root: &std::path::Path,
) -> Option<(&'static str, &'static str)> {
    let arch = match arch {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        _ => return None,
    };
    match distro {
        Distro::Arch if arch == "x86_64" => Some((arch, "linux-arch")),
        Distro::Debian | Distro::Ubuntu => Some((arch, apt_release_target(distro, arch, root)?)),
        Distro::Fedora if arch == "x86_64" => Some((arch, "linux-fedora")),
        Distro::MacOS => Some(("aarch64", "darwin")),
        Distro::Arch | Distro::Fedora | Distro::Unknown => None,
    }
}

fn release_artifact(version: &Version) -> Result<ReleaseArtifact> {
    let distro = detect_distro();
    let Some((release_arch, target)) =
        release_target(distro, std::env::consts::ARCH, std::path::Path::new("/"))
    else {
        if matches!(distro, Distro::Debian | Distro::Ubuntu) {
            anyhow::bail!(
                "No compatible native APT release: require a published architecture and libapt-pkg.so.6.0 or .7.0"
            );
        }
        anyhow::bail!(
            "self-update has no release artifact for this platform; \
             download the archive manually from {GITHUB_RELEASES_PAGE}"
        );
    };
    let host_arch = std::env::consts::ARCH;
    if host_arch != release_arch {
        anyhow::bail!(
            "self-update publishes no {target} artifact for {host_arch}; \
             download the archive manually from {GITHUB_RELEASES_PAGE}"
        );
    }
    Ok(ReleaseArtifact {
        version: version.clone(),
        arch: release_arch,
        target,
    })
}

async fn fetch_release_archive(artifact: &ReleaseArtifact) -> Result<Vec<u8>> {
    let archive_url = artifact.archive_url();
    let checksum_url = format!("{archive_url}.sha256");
    let expected_digest = fetch_checksum(&checksum_url).await?;
    download_verified(&archive_url, artifact.object_name(), &expected_digest).await
}

async fn fetch_checksum(url: &str) -> Result<String> {
    let safe_url = crate::core::http::redact_url(url);
    let response = send_get(url, &safe_url).await?;
    let body = read_bounded_body(response, MAX_CHECKSUM_BYTES, &safe_url).await?;
    parse_checksum(&body)
}

fn parse_checksum(body: &str) -> Result<String> {
    let line = body
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| anyhow::anyhow!("checksum sidecar is empty"))?;
    let digest = line
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow::anyhow!("checksum sidecar has no digest field"))?;
    if digest.len() != 64 || hex::decode(digest).is_err() {
        anyhow::bail!("checksum sidecar does not contain a valid SHA-256 digest");
    }
    Ok(digest.to_ascii_lowercase())
}

fn check_download_size(streamed: usize, chunk: usize) -> Result<()> {
    if streamed.saturating_add(chunk) > MAX_DOWNLOAD_BYTES {
        anyhow::bail!(
            "Update download exceeded the {} MiB size cap",
            MAX_DOWNLOAD_BYTES / (1024 * 1024)
        );
    }
    Ok(())
}

async fn download_verified(
    url: &str,
    archive_name: String,
    expected_digest: &str,
) -> Result<Vec<u8>> {
    let safe_url = crate::core::http::redact_url(url);
    let response = crate::core::http::download_client()
        .get(url)
        .send()
        .await
        .with_context(|| format!("Failed to download update archive from {safe_url}"))?;
    if !response.status().is_success() {
        anyhow::bail!("Update download failed: {} ({safe_url})", response.status());
    }

    let prealloc = response
        .content_length()
        .and_then(|len| usize::try_from(len).ok())
        .map_or(0, |len| len.min(MAX_PREALLOC_BYTES));

    let task = ProgressTask::start(&TaskSpec {
        label: archive_name,
        kind: TaskKind::Bytes {
            total: response.content_length().filter(|len| *len > 0),
        },
        accent: Accent::Network,
    });

    let mut bytes = Vec::with_capacity(prealloc);
    let mut hasher = Sha256::new();

    let mut stream = response.bytes_stream();
    while let Some(item) = stream.next().await {
        let chunk = item.context("Failed to read update download chunk")?;
        check_download_size(bytes.len(), chunk.len())?;
        hasher.update(&chunk);
        bytes.extend_from_slice(&chunk);
        task.inc(chunk.len() as u64);
    }
    task.finish(Outcome::Done);

    let actual_digest = hex::encode(hasher.finalize());
    if actual_digest != expected_digest {
        anyhow::bail!(
            "Update archive failed integrity verification: \
             expected SHA-256 {expected_digest}, got {actual_digest}"
        );
    }
    Ok(bytes)
}

/// Verify the Sigstore build-provenance attestation of `archive_path` using
/// the GitHub CLI (`gh attestation verify`).
///
/// Release archives carry SLSA provenance attestations generated by GitHub
/// Actions (see `release.yml`); verifying them proves the archive was built
/// by this repository's CI at the pinned commit — closing the trust gap where
/// a compromise of the release bucket could rewrite both binaries and
/// checksum sidecars together.
///
/// Returns `Ok(true)` when the attestation verified, `Ok(false)` when no
/// attestation-capable tool (`gh`) is installed locally, and an error when an
/// attestation tool IS present but rejects the archive (fail closed).
///
/// # Errors
///
/// Returns an error when `gh` is installed and the attestation does not
/// verify (tampered or non-CI-built archive), or when `gh` itself fails to
/// execute the verification.
/// Absolute system locations where the GitHub CLI is conventionally
/// installed.
///
/// The attestation gate trusts whatever binary `gh` resolves to, so it must
/// never be resolved through PATH: a project-controlled directory earlier in
/// PATH could ship an impostor `gh` whose only job is to approve a tampered
/// archive. Only well-known absolute install locations are consulted.
#[cfg(unix)]
const GH_CANDIDATES: &[&str] = &["/usr/bin/gh", "/usr/local/bin/gh", "/opt/homebrew/bin/gh"];

#[cfg(not(unix))]
const GH_CANDIDATES: &[&str] = &[];

/// Resolve the attestation helper by absolute path only.
///
/// Returns `None` when no attestation-capable tool is installed, which maps
/// to the existing fail-closed "no `gh`" provenance outcome.
fn locate_gh() -> Option<std::path::PathBuf> {
    GH_CANDIDATES
        .iter()
        .find_map(|path| trusted_attestation_helper(std::path::Path::new(path)))
}

fn trusted_attestation_helper(path: &std::path::Path) -> Option<std::path::PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let owner = nix::unistd::geteuid().as_raw();
        let trusted_namespace = |path: &std::path::Path| {
            path.is_absolute()
                && path.ancestors().all(|entry| {
                    let Ok(metadata) = fs::symlink_metadata(entry) else {
                        return false;
                    };
                    let trusted_owner = metadata.uid() == 0 || metadata.uid() == owner;
                    // A root-owned sticky directory protects each owned child
                    // from replacement by other users (e.g. /tmp).
                    let sticky_root_directory =
                        metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
                    trusted_owner
                        && (metadata.file_type().is_symlink()
                            || metadata.mode() & 0o022 == 0
                            || sticky_root_directory)
                })
        };
        // Validate the original name too: an attacker-owned symlink to a
        // root-owned program such as `true` is not an attestation verifier.
        if !trusted_namespace(path) {
            return None;
        }
        let resolved = fs::canonicalize(path).ok()?;
        let metadata = fs::metadata(&resolved).ok()?;
        (metadata.is_file() && metadata.mode() & 0o111 != 0 && trusted_namespace(&resolved))
            .then_some(resolved)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

fn verify_attestation(archive_path: &std::path::Path, tag: &str) -> Result<bool> {
    let repository = attestation_repository(tag)?;
    let signer_workflow = format!("{repository}/.github/workflows/release.yml");
    let Some(gh) = locate_gh() else {
        return Ok(false);
    };
    let output = std::process::Command::new(gh)
        .args(["attestation", "verify"])
        .arg(archive_path)
        .args([
            "-R",
            repository,
            "--source-ref",
            &format!("refs/tags/{tag}"),
            "--signer-workflow",
            &signer_workflow,
        ])
        .stdin(std::process::Stdio::null())
        .output();

    let output = match output {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("Failed to execute GitHub CLI attestation check"),
    };

    if output.status.success() {
        println!(
            "  {} build provenance verified",
            style::maybe_color("🔒", |t| t.green().to_string())
        );
        Ok(true)
    } else {
        Err(anyhow::anyhow!(
            "Sigstore attestation verification FAILED for {}. Possible \\
             supply-chain tampering. Run manually to inspect:\n                 gh attestation verify {} -R {repository}",
            archive_path.display(),
            archive_path.display(),
        ))
    }
}

/// Decide what to do when Sigstore provenance could not be verified.
///
/// Fails closed by default: the update is refused with instructions for
/// verifying the artifact manually. The only way past the gate is the
/// explicit `OMG_SELF_UPDATE_ALLOW_UNVERIFIED_PROVENANCE` opt-in, which
/// downgrades the refusal to a loud warning.
///
/// # Errors
///
/// Returns an error (refusal) unless `allow_unverified` is set.
fn decide_unverified_provenance(allow_unverified: bool) -> Result<()> {
    if allow_unverified {
        println!(
            "  {} PROVENANCE NOT VERIFIED: continuing because \
             {ALLOW_UNVERIFIED_PROVENANCE_ENV} is set",
            style::maybe_color("⚠", |t| t.yellow().to_string())
        );
        return Ok(());
    }
    anyhow::bail!(
        "Refusing to install: Sigstore build provenance could not be verified \
         because no attestation tool (the GitHub CLI, `gh`) is installed. \
         The checksum gate alone cannot detect a compromised release origin \
         that rewrites binaries and sidecars together.\n\
         \nVerify the artifact manually, then retry:\n\
         \x20 1. Install the GitHub CLI (https://cli.github.com)\n\
         \x20 2. Re-run `omg self-update`, or verify by hand:\n\
         \x20    gh attestation verify <archive.tar.gz> -R {ATTESTATION_REPO}\n\
         \nTo accept an unverified update deliberately, re-run with:\n\
         \x20 {ALLOW_UNVERIFIED_PROVENANCE_ENV}=1 omg self-update"
    )
}

/// Evaluate the opt-in escape hatch from the environment only. `--force`
/// no longer bypasses provenance: it governs version and downgrade policy,
/// never trust.
fn refuse_unverified_provenance() -> Result<()> {
    let raw = env::var(ALLOW_UNVERIFIED_PROVENANCE_ENV).ok();
    decide_unverified_provenance(parse_allow_unverified(raw.as_deref()))
}

/// Parse the escape-hatch environment variable.
///
/// Only `1`, `true`, and `yes` (case-sensitive, matching common CI idiom)
/// count as explicit opt-in; unset, empty, misspelled, or falsy values all
/// keep the gate closed.
fn parse_allow_unverified(value: Option<&str>) -> bool {
    matches!(value, Some("1" | "true" | "yes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn apt_release_selection_matches_installer_filesystem_cases() {
        #[derive(serde::Deserialize)]
        struct Case {
            name: String,
            arch: String,
            libraries: std::collections::BTreeMap<String, String>,
            suffix: Option<String>,
        }
        let cases: Vec<Case> = serde_json::from_str(include_str!(
            "../../tests/fixtures/apt-release-selection.json"
        ))
        .unwrap();
        for distro in [Distro::Debian, Distro::Ubuntu] {
            for case in &cases {
                let root = tempfile::tempdir().unwrap();
                let library_dir = root.path().join("usr/lib/x86_64-linux-gnu");
                fs::create_dir_all(&library_dir).unwrap();
                for (major, kind) in &case.libraries {
                    let library = library_dir.join(format!("libapt-pkg.so.{major}"));
                    match kind.as_str() {
                        "file" => fs::write(&library, b"library fixture").unwrap(),
                        "directory" => fs::create_dir(&library).unwrap(),
                        "symlink" | "dangling" => {
                            let target = format!("libapt-pkg.so.{major}.0");
                            if kind == "symlink" {
                                fs::write(library_dir.join(&target), b"library fixture").unwrap();
                            }
                            std::os::unix::fs::symlink(target, &library).unwrap();
                        }
                        _ => panic!("unknown fixture kind {kind}"),
                    }
                }
                let expected = match case.suffix.as_deref() {
                    Some("legacy") if distro == Distro::Debian => Some("linux-debian"),
                    Some("legacy") => Some("linux-ubuntu"),
                    Some("debian-trixie") => Some("linux-debian-trixie"),
                    None => None,
                    Some(other) => panic!("unknown expected suffix {other}"),
                };
                assert_eq!(
                    release_target(distro, &case.arch, root.path()).map(|(_, target)| target),
                    expected,
                    "{} on {distro:?}",
                    case.name
                );
            }
        }
    }

    #[cfg(unix)]
    fn write_version_probe(path: &std::path::Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn update_preflight_preserves_pair_on_candidate_failure() {
        for (cli_body, daemon_body, expected) in [
            (
                "echo 'missing libapt-pkg.so.6.0' >&2; exit 127",
                "echo 'omgd 1.2.3'",
                "missing libapt-pkg.so.6.0",
            ),
            (
                "echo 'omg 1.2.3'",
                "echo 'daemon loader failure' >&2; exit 127",
                "daemon loader failure",
            ),
            (
                "echo 'omg 1.2.2'",
                "echo 'omgd 1.2.3'",
                "does not report omg 1.2.3",
            ),
            (
                "echo 'omg 1.2.3'",
                "echo 'omgd 1.2.2'",
                "does not report omgd 1.2.3",
            ),
            (
                "printf '%5000s' x",
                "echo 'omgd 1.2.3'",
                "version probe output exceeds",
            ),
        ] {
            let root = tempfile::tempdir().unwrap();
            let candidates = root.path().join("candidates");
            let installed = root.path().join("installed");
            fs::create_dir(&candidates).unwrap();
            fs::create_dir(&installed).unwrap();
            let cli = candidates.join("omg");
            let daemon = candidates.join("omgd");
            write_version_probe(&cli, cli_body);
            write_version_probe(&daemon, daemon_body);
            fs::write(installed.join("omg"), b"previous cli").unwrap();
            fs::write(installed.join("omgd"), b"previous daemon").unwrap();
            let error = install_checked_update_pair(
                &cli,
                &daemon,
                &installed.join("omg"),
                &Version::new(1, 2, 3),
                std::time::Duration::from_secs(2),
            )
            .await
            .expect_err("unusable pair must not be installed");
            assert!(format!("{error:#}").contains(expected), "{error:#}");
            assert_eq!(fs::read(installed.join("omg")).unwrap(), b"previous cli");
            assert_eq!(
                fs::read(installed.join("omgd")).unwrap(),
                b"previous daemon"
            );
            assert!(!installed.join(".omg-self-update.lock").exists());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn update_preflight_installs_matching_pair() {
        let root = tempfile::tempdir().unwrap();
        let cli = root.path().join("candidate-cli");
        let daemon = root.path().join("candidate-daemon");
        write_version_probe(&cli, "echo 'omg 1.2.3'");
        write_version_probe(&daemon, "echo 'omgd 1.2.3'");
        let installed = root.path().join("omg");
        fs::write(&installed, b"previous cli").unwrap();
        fs::write(root.path().join("omgd"), b"previous daemon").unwrap();
        // Match production: extraction/replacement runs on a blocking worker
        // while the active runtime drives the bounded asynchronous probes.
        let (candidate_cli, candidate_daemon, destination) =
            (cli.clone(), daemon.clone(), installed.clone());
        tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(install_checked_update_pair(
                &candidate_cli,
                &candidate_daemon,
                &destination,
                &Version::new(1, 2, 3),
                std::time::Duration::from_secs(2),
            ))
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(fs::read(&installed).unwrap(), fs::read(&cli).unwrap());
        assert_eq!(
            fs::read(root.path().join("omgd")).unwrap(),
            fs::read(&daemon).unwrap()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn update_preflight_rejects_missing_linked_and_unexecutable_candidates() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        for case in [
            "missing",
            "directory",
            "symlink",
            "permission",
            "invalid-format",
        ] {
            let root = tempfile::tempdir().unwrap();
            let cli = root.path().join("candidate-cli");
            let daemon = root.path().join("candidate-daemon");
            write_version_probe(&cli, "echo 'omg 1.2.3'");
            let expected = match case {
                "missing" => "Missing omgd update candidate",
                "directory" => {
                    fs::create_dir(&daemon).unwrap();
                    "omgd update candidate is not a regular file"
                }
                "symlink" => {
                    symlink(&cli, &daemon).unwrap();
                    "omgd update candidate is not a regular file"
                }
                "permission" => {
                    write_version_probe(&daemon, "echo 'omgd 1.2.3'");
                    fs::set_permissions(&daemon, fs::Permissions::from_mode(0o644)).unwrap();
                    "Failed to execute omgd version probe"
                }
                "invalid-format" => {
                    fs::write(&daemon, b"not an executable format").unwrap();
                    fs::set_permissions(&daemon, fs::Permissions::from_mode(0o755)).unwrap();
                    // Linux rejects the spawn with ENOEXEC; macOS may invoke
                    // the text through /bin/sh and return exit 127 instead.
                    "omgd version probe"
                }
                _ => unreachable!(),
            };
            let installed = root.path().join("omg");
            fs::write(&installed, b"previous cli").unwrap();
            fs::write(root.path().join("omgd"), b"previous daemon").unwrap();
            let error = install_checked_update_pair(
                &cli,
                &daemon,
                &installed,
                &Version::new(1, 2, 3),
                std::time::Duration::from_secs(2),
            )
            .await
            .expect_err("invalid candidate must preserve the installed pair");
            assert!(format!("{error:#}").contains(expected), "{case}: {error:#}");
            assert_eq!(fs::read(&installed).unwrap(), b"previous cli");
            assert_eq!(
                fs::read(root.path().join("omgd")).unwrap(),
                b"previous daemon"
            );
            assert!(!root.path().join(".omg-self-update.lock").exists());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn update_preflight_timeout_reaps_child_before_returning() {
        let root = tempfile::tempdir().unwrap();
        let cli = root.path().join("candidate-cli");
        let daemon = root.path().join("candidate-daemon");
        let pid_file = root.path().join("probe.pid");
        write_version_probe(
            &cli,
            &format!("echo $$ > '{}'; exec sleep 30", pid_file.display()),
        );
        write_version_probe(&daemon, "echo 'omgd 1.2.3'");
        let installed = root.path().join("omg");
        fs::write(&installed, b"previous cli").unwrap();
        fs::write(root.path().join("omgd"), b"previous daemon").unwrap();
        let error = install_checked_update_pair(
            &cli,
            &daemon,
            &installed,
            &Version::new(1, 2, 3),
            std::time::Duration::from_secs(1),
        )
        .await
        .expect_err("hung probe must refuse installation");
        assert!(
            format!("{error:#}").contains("omg version probe timed out"),
            "{error:#}"
        );
        let pid = fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse::<i32>()
            .unwrap();
        assert_eq!(
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None),
            Err(nix::errno::Errno::ESRCH)
        );
        assert_eq!(fs::read(&installed).unwrap(), b"previous cli");
        assert_eq!(
            fs::read(root.path().join("omgd")).unwrap(),
            b"previous daemon"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn update_preflight_rejects_and_reaps_forked_descendant() {
        let root = tempfile::tempdir().unwrap();
        let cli = root.path().join("candidate-cli");
        let daemon = root.path().join("candidate-daemon");
        let pid_file = root.path().join("descendant.pid");
        let heartbeat = root.path().join("descendant.heartbeat");
        write_version_probe(
            &cli,
            &format!(
                "(while :; do printf x >> '{}'; sleep 0.01; done) >/dev/null 2>&1 & \
                 echo $! > '{}'; while [ ! -s '{}' ]; do :; done; echo 'omg 1.2.3'",
                heartbeat.display(),
                pid_file.display(),
                heartbeat.display()
            ),
        );
        write_version_probe(&daemon, "echo 'omgd 1.2.3'");
        let installed = root.path().join("omg");
        fs::write(&installed, b"previous cli").unwrap();
        fs::write(root.path().join("omgd"), b"previous daemon").unwrap();

        let error = install_checked_update_pair(
            &cli,
            &daemon,
            &installed,
            &Version::new(1, 2, 3),
            std::time::Duration::from_secs(2),
        )
        .await
        .expect_err("a probe that leaves descendants must refuse installation");
        assert!(
            format!("{error:#}").contains("omg version probe left descendant processes running"),
            "{error:#}"
        );
        let pid = fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse::<i32>()
            .unwrap();
        let before = fs::metadata(&heartbeat).unwrap().len();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let after = fs::metadata(&heartbeat).unwrap().len();
        if after != before {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        assert_eq!(
            after, before,
            "forked descendant kept running after its process group was killed"
        );
        assert_eq!(fs::read(&installed).unwrap(), b"previous cli");
        assert_eq!(
            fs::read(root.path().join("omgd")).unwrap(),
            b"previous daemon"
        );
    }

    #[test]
    fn release_signer_cutover_has_no_cross_namespace_fallback() {
        for tag in ["v0.1.220", "v0.1.221"] {
            assert_eq!(attestation_repository(tag).unwrap(), "PyRo1121/omg");
        }
        for tag in ["v0.1.222", "v0.1.222-rc.1", "v0.2.0", "v1.0.0"] {
            assert_eq!(attestation_repository(tag).unwrap(), "omg-cli/omg");
        }
        for tag in ["0.1.221", "v0.1.221/other", "v01.1.221", "v0.1.221\n"] {
            assert!(attestation_repository(tag).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn attestation_helper_rejects_writable_files_and_symlink_namespaces() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let helper = root.join("gh");
        fs::write(&helper, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(trusted_attestation_helper(&helper), Some(helper.clone()));
        let link = root.join("gh-link");
        symlink(&helper, &link).unwrap();
        assert_eq!(trusted_attestation_helper(&link), Some(helper.clone()));
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(trusted_attestation_helper(&helper).is_none());
        assert!(trusted_attestation_helper(&link).is_none());
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(trusted_attestation_helper(&helper).is_none());
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
        let shared = root.join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        symlink(&helper, shared.join("gh")).unwrap();
        assert!(trusted_attestation_helper(&shared.join("gh")).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn elevated_verifier_rejects_another_users_helper() {
        if !crate::core::is_root() {
            eprintln!("[omg-skip] elevated verifier ownership test requires root");
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let helper = temp.path().canonicalize().unwrap().join("gh");
        fs::write(&helper, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
        nix::unistd::chown(&helper, Some(nix::unistd::Uid::from_raw(65534)), None).unwrap();
        assert!(trusted_attestation_helper(&helper).is_none());
    }

    #[test]
    fn parse_version_accepts_v_prefix_and_surrounding_whitespace() {
        let expected = Version::new(1, 2, 3);
        assert_eq!(
            parse_version("1.2.3").expect("bare semver must parse"),
            expected
        );
        assert_eq!(
            parse_version("v1.2.3").expect("v-prefixed semver must parse"),
            expected
        );
        assert_eq!(
            parse_version("  1.2.3\n").expect("whitespace must be trimmed"),
            expected
        );
        assert_eq!(
            parse_version("v1.2.3-rc.1+b5").expect("pre-release must parse"),
            Version::parse("1.2.3-rc.1+b5").expect("baseline pre-release")
        );
    }

    #[test]
    fn parse_version_rejects_malformed_and_hostile_input() {
        for raw in [
            "",
            "v",
            "not-a-version",
            "1.2",
            "1.2.3.4",
            "1.2.3/../../evil",
            "1.2.3?redirect=x",
            "https://evil.example/1.2.3",
        ] {
            assert!(
                parse_version(raw).is_err(),
                "input {raw:?} must not parse as a version"
            );
        }
    }

    #[test]
    fn latest_version_parses_bare_semver_marker_text() {
        let expected = Version::new(1, 2, 3);
        assert_eq!(
            LatestVersion::parse("1.2.3")
                .expect("bare semver must parse")
                .into_version(),
            expected
        );
        assert_eq!(
            LatestVersion::parse("  1.2.3\n")
                .expect("surrounding whitespace must be tolerated")
                .into_version(),
            expected
        );
        assert_eq!(
            LatestVersion::parse("1.2.3-rc.1+b5")
                .expect("pre-release must parse")
                .into_version(),
            Version::parse("1.2.3-rc.1+b5").expect("baseline pre-release")
        );
    }

    #[test]
    fn latest_version_rejects_malformed_and_hostile_marker_bodies() {
        for raw in [
            "",
            "   \n\n",
            "v1.2.3",
            "V1.2.3",
            "not-a-version",
            "1.2",
            "1.2.3.4",
            "1.2.3/../../evil",
            "https://evil.example/1.2.3",
        ] {
            assert!(
                LatestVersion::parse(raw).is_err(),
                "marker body {raw:?} must be rejected"
            );
        }
    }

    #[test]
    fn latest_version_rejects_marker_bodies_beyond_the_byte_bound() {
        let padded = format!("1.2.3\n{}", " ".repeat(MAX_LATEST_VERSION_BYTES));
        assert!(padded.len() > MAX_LATEST_VERSION_BYTES);
        assert!(LatestVersion::parse(&padded).is_err());
    }

    #[test]
    fn release_artifact_names_match_the_github_release_asset_contract() {
        let artifact = ReleaseArtifact {
            version: Version::parse("1.2.3").expect("baseline version"),
            arch: "x86_64",
            target: "linux-arch",
        };
        assert_eq!(
            artifact.object_name(),
            "omg-v1.2.3-x86_64-linux-arch.tar.gz"
        );
        assert_eq!(
            artifact.archive_url(),
            "https://releases.omg.latham.cloud/omg-v1.2.3-x86_64-linux-arch.tar.gz"
        );
    }

    #[test]
    fn release_artifact_names_include_pre_release_and_build_metadata() {
        let artifact = ReleaseArtifact {
            version: Version::parse("1.2.3-rc.1+b5").expect("baseline pre-release"),
            arch: "aarch64",
            target: "darwin",
        };
        assert_eq!(
            artifact.object_name(),
            "omg-v1.2.3-rc.1+b5-aarch64-darwin.tar.gz"
        );
    }

    #[test]
    fn parse_checksum_accepts_sha256sum_sidecar_format() {
        let digest = "a".repeat(64);
        let body = format!("{digest}  omg-v1.2.3-x86_64-linux-arch.tar.gz\n");
        assert_eq!(
            parse_checksum(&body).expect("sha256sum format must parse"),
            digest
        );
    }

    #[test]
    fn parse_checksum_accepts_crlf_and_uppercase_hex() {
        let body = format!(
            "{}  omg-v1.2.3-x86_64-linux-arch.tar.gz.sha256...\r\n",
            "B".repeat(64)
        );
        assert_eq!(
            parse_checksum(&body).expect("Get-FileHash format must parse"),
            "b".repeat(64)
        );
    }

    #[test]
    fn parse_checksum_skips_leading_blank_lines() {
        let digest = "c".repeat(64);
        let body = format!("\n\n  \n{digest}  omg.tar.gz\n");
        assert_eq!(
            parse_checksum(&body).expect("blank lines must be skipped"),
            digest
        );
    }

    #[test]
    fn parse_checksum_rejects_invalid_payloads() {
        for body in ["", "   \n\n", "no digest field long enough to matter here"] {
            assert!(
                parse_checksum(body).is_err(),
                "sidecar body {body:?} must be rejected"
            );
        }
        assert!(
            parse_checksum(&"g".repeat(64)).is_err(),
            "non-hex characters must be rejected"
        );
        assert!(
            parse_checksum(&format!("{}  omg.tar.gz", "a".repeat(63))).is_err(),
            "truncated digests must be rejected"
        );
    }

    #[test]
    fn download_size_accepts_the_limit_and_rejects_larger_payloads() {
        assert!(check_download_size(MAX_DOWNLOAD_BYTES, 0).is_ok());
        assert!(check_download_size(MAX_DOWNLOAD_BYTES - 1, 1).is_ok());
        assert!(check_download_size(MAX_DOWNLOAD_BYTES, 1).is_err());
        assert!(check_download_size(usize::MAX, 1).is_err());
    }

    #[test]
    fn release_target_matches_ci_artifact_names() {
        let linux_arch = "x86_64";
        let root = tempfile::tempdir().unwrap();
        let library_dir = root.path().join("usr/lib/x86_64-linux-gnu");
        fs::create_dir_all(&library_dir).unwrap();
        fs::write(library_dir.join("libapt-pkg.so.6.0"), b"library fixture").unwrap();
        let select = |distro| release_target(distro, linux_arch, root.path());
        assert_eq!(select(Distro::Arch), Some((linux_arch, "linux-arch")));
        assert_eq!(select(Distro::Debian), Some((linux_arch, "linux-debian")));
        assert_eq!(select(Distro::Ubuntu), Some((linux_arch, "linux-ubuntu")));
        assert_eq!(select(Distro::Fedora), Some((linux_arch, "linux-fedora")));
        assert_eq!(select(Distro::MacOS), Some(("aarch64", "darwin")));
        assert_eq!(select(Distro::Unknown), None);
        assert_eq!(release_target(Distro::Arch, "aarch64", root.path()), None);
        assert_eq!(release_target(Distro::Fedora, "aarch64", root.path()), None);
    }

    #[test]
    fn install_binary_stages_replacement_in_destination_directory() {
        let temp = tempfile::tempdir().expect("temp dir");
        let source_dir = temp.path().join("download");
        let destination_dir = temp.path().join("bin");
        std::fs::create_dir_all(&source_dir).expect("source dir");
        std::fs::create_dir_all(&destination_dir).expect("destination dir");
        let source = source_dir.join("omg");
        let destination = destination_dir.join("omg");
        std::fs::write(&source, b"new binary").expect("source");
        std::fs::write(&destination, b"old binary").expect("destination");

        install_binary_atomically(&source, &destination).expect("install binary");

        assert_eq!(
            std::fs::read(&destination).expect("installed"),
            b"new binary"
        );
        assert_eq!(
            std::fs::read(&source).expect("source remains"),
            b"new binary"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(destination)
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o755
            );
        }
    }

    fn update_test_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, content) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, name, *content)
                .expect("append tar entry");
        }
        builder.into_inner().expect("finish tar")
    }

    fn gzip_bytes(raw: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(raw).expect("gzip tar");
        encoder.finish().expect("finish gzip")
    }

    fn update_test_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        gzip_bytes(&update_test_tar(entries))
    }

    /// Rewrite the first entry name of a raw tar archive, recomputing the
    /// header checksum. The safe builder API refuses `..` names, but hostile
    /// archives in the wild are not built with it.
    fn retarget_first_entry(raw: &mut [u8], name: &[u8]) {
        assert!(name.len() < 100, "entry name must fit the tar name field");
        raw[0..100].fill(0);
        raw[0..name.len()].copy_from_slice(name);
        raw[148..156].fill(b' ');
        let checksum: u32 = raw[0..512].iter().map(|byte| u32::from(*byte)).sum();
        let encoded = format!("{checksum:06o}\0 ");
        raw[148..156].copy_from_slice(encoded.as_bytes());
    }

    #[test]
    fn update_extraction_stages_daemon_from_same_archive() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let bytes = update_test_archive(&[("omg", b"new cli"), ("omgd", b"new daemon")]);
        extract_update_binary(&bytes, tmp.path(), "omg-v1.2.3-x86_64-linux-arch.tar.gz")
            .expect("extract pair");
        assert_eq!(
            fs::read(tmp.path().join("omgd")).expect("daemon staged"),
            b"new daemon"
        );
    }

    #[test]
    fn update_pair_requires_both_binaries_before_installation() {
        for entries in [
            vec![("omg", b"cli".as_slice())],
            vec![("omgd", b"daemon".as_slice())],
        ] {
            let tmp = tempfile::tempdir().expect("temp dir");
            let bytes = update_test_archive(&entries);
            assert!(extract_update_pair(&bytes, tmp.path(), "release.tar.gz").is_err());
        }
    }

    #[test]
    fn update_pair_accepts_matching_flat_and_wrapped_layouts() {
        for prefix in ["", "release/"] {
            let tmp = tempfile::tempdir().expect("temp dir");
            let cli_name = format!("{prefix}omg");
            let daemon_name = format!("{prefix}omgd");
            let bytes = update_test_archive(&[(&cli_name, b"cli"), (&daemon_name, b"daemon")]);
            let (cli, daemon) =
                extract_update_pair(&bytes, tmp.path(), "release.tar.gz").expect("pair");
            assert_eq!(fs::read(cli).expect("cli"), b"cli");
            assert_eq!(fs::read(daemon).expect("daemon"), b"daemon");
        }
    }

    #[test]
    fn update_pair_rejects_duplicate_daemon_and_mixed_layouts() {
        for entries in [
            vec![
                ("omg", b"cli".as_slice()),
                ("omgd", b"one".as_slice()),
                ("omgd", b"two".as_slice()),
            ],
            vec![
                ("omg", b"cli".as_slice()),
                ("release/omgd", b"daemon".as_slice()),
            ],
            vec![
                ("omg", b"cli".as_slice()),
                ("omgd", b"daemon".as_slice()),
                ("release/omg", b"other".as_slice()),
            ],
        ] {
            let tmp = tempfile::tempdir().expect("temp dir");
            assert!(
                extract_update_pair(&update_test_archive(&entries), tmp.path(), "release.tar.gz")
                    .is_err()
            );
        }
    }

    #[test]
    fn update_pair_rejects_daemon_link_and_directory_entries() {
        for entry_type in [
            tar::EntryType::Symlink,
            tar::EntryType::Link,
            tar::EntryType::Directory,
        ] {
            let mut builder = tar::Builder::new(Vec::new());
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(entry_type);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_link_name("omg").expect("link name");
            header.set_cksum();
            builder
                .append_data(&mut header, "omgd", std::io::empty())
                .expect("entry");
            let bytes = gzip_bytes(&builder.into_inner().expect("tar"));
            let tmp = tempfile::tempdir().expect("temp dir");
            assert!(extract_update_binary(&bytes, tmp.path(), "release.tar.gz").is_err());
        }
    }

    #[cfg(unix)]
    fn pair_fixture(
        old_daemon: bool,
    ) -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cli = tmp.path().join("new-omg");
        let daemon = tmp.path().join("new-omgd");
        let bin = tmp.path().join("bin");
        fs::create_dir(&bin).expect("bin");
        fs::write(&cli, b"new cli").expect("cli");
        fs::write(&daemon, b"new daemon").expect("daemon");
        fs::write(bin.join("omg"), b"old cli").expect("old cli");
        if old_daemon {
            fs::write(bin.join("omgd"), b"old daemon").expect("old daemon");
        }
        (tmp, cli, daemon, bin.join("omg"))
    }

    #[test]
    #[cfg(unix)]
    fn update_pair_installs_both_including_previously_missing_daemon() {
        use std::os::unix::fs::PermissionsExt;
        for old_daemon in [true, false] {
            let (_tmp, cli, daemon, destination) = pair_fixture(old_daemon);
            install_update_pair(&cli, &daemon, &destination).expect("update pair");
            assert_eq!(fs::read(&destination).expect("installed cli"), b"new cli");
            let daemon = destination.with_file_name("omgd");
            assert_eq!(fs::read(&daemon).expect("installed daemon"), b"new daemon");
            for path in [&destination, &daemon] {
                assert_eq!(
                    fs::metadata(path).expect("metadata").permissions().mode() & 0o777,
                    0o755
                );
            }
        }
    }

    #[test]
    #[cfg(unix)]
    fn update_pair_staging_failure_preserves_both_installed_files() {
        let (_tmp, cli, daemon, destination) = pair_fixture(true);
        fs::remove_file(&cli).expect("missing CLI payload");
        assert!(install_update_pair(&cli, &daemon, &destination).is_err());
        assert_eq!(fs::read(&destination).expect("cli"), b"old cli");
        assert_eq!(
            fs::read(destination.with_file_name("omgd")).expect("daemon"),
            b"old daemon"
        );
    }

    #[test]
    #[cfg(unix)]
    fn update_pair_restores_both_after_second_replace_or_sync_failure() {
        for old_daemon in [true, false] {
            for fail_after_rename in [true, false] {
                let (_tmp, cli, daemon, destination) = pair_fixture(old_daemon);
                let mut count = 0;
                let result =
                    install_update_pair_with(&cli, &daemon, &destination, |staged, path| {
                        count += 1;
                        if count == 2 {
                            if fail_after_rename {
                                persist_update_binary(staged, path)?;
                            }
                            anyhow::bail!("injected replacement/sync failure");
                        }
                        persist_update_binary(staged, path)
                    });
                assert!(
                    format!("{:#}", result.expect_err("must fail"))
                        .contains("previous OMG binaries restored")
                );
                assert_eq!(fs::read(&destination).expect("cli restored"), b"old cli");
                let path = destination.with_file_name("omgd");
                if old_daemon {
                    assert_eq!(fs::read(path).expect("daemon restored"), b"old daemon");
                } else {
                    assert!(!path.exists());
                }
            }
        }
    }

    #[test]
    #[cfg(unix)]
    fn update_pair_rejects_concurrent_updater_and_symlink_destination() {
        let (tmp, cli, daemon, destination) = pair_fixture(true);
        let lock =
            fs::File::create(destination.with_file_name(".omg-self-update.lock")).expect("lock");
        lock.try_lock().expect("hold lock");
        assert!(
            format!(
                "{:#}",
                install_update_pair(&cli, &daemon, &destination).expect_err("locked")
            )
            .contains("Another self-update")
        );
        drop(lock);
        let target = tmp.path().join("unrelated");
        fs::write(&target, b"untouched").expect("target");
        fs::remove_file(destination.with_file_name("omgd")).expect("remove daemon");
        std::os::unix::fs::symlink(&target, destination.with_file_name("omgd")).expect("symlink");
        assert!(install_update_pair(&cli, &daemon, &destination).is_err());
        assert_eq!(fs::read(&target).expect("target"), b"untouched");
        assert_eq!(fs::read(&destination).expect("cli"), b"old cli");
    }

    #[test]
    fn update_extraction_finds_wrapped_ci_layout() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let bytes = update_test_archive(&[("omg-v1.2.3-x86_64-linux-arch/omg", b"#!/bin/sh\n")]);
        let found =
            extract_update_binary(&bytes, tmp.path(), "omg-v1.2.3-x86_64-linux-arch.tar.gz")
                .expect("extraction must succeed");
        let expected = tmp.path().join("omg-v1.2.3-x86_64-linux-arch/omg");
        assert_eq!(found, Some(expected.clone()));
        assert_eq!(std::fs::read(&expected).expect("binary"), b"#!/bin/sh\n");
    }

    #[test]
    fn update_extraction_finds_flat_layout_fallback() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let bytes = update_test_archive(&[("omg", b"#!/bin/sh\n")]);
        let found =
            extract_update_binary(&bytes, tmp.path(), "omg-v1.2.3-x86_64-linux-arch.tar.gz")
                .expect("extraction must succeed");
        let expected = tmp.path().join("omg");
        assert_eq!(found, Some(expected.clone()));
        assert_eq!(std::fs::read(&expected).expect("binary"), b"#!/bin/sh\n");
    }

    #[test]
    fn update_extraction_returns_none_when_archive_has_no_binary() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let bytes = update_test_archive(&[("omg-v1.2.3-x86_64-linux-arch/README", b"docs")]);
        assert_eq!(
            extract_update_binary(&bytes, tmp.path(), "omg-v1.2.3-x86_64-linux-arch.tar.gz",)
                .expect("extraction must succeed"),
            None
        );
    }

    #[test]
    fn update_extraction_refuses_traversal_entry() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let mut raw = update_test_tar(&[("omg-v1.2.3-x86_64-linux-arch/omg", b"pwned")]);
        retarget_first_entry(&mut raw, b"omg-v1.2.3-x86_64-linux-arch/../../evil");
        let bytes = gzip_bytes(&raw);
        extract_update_binary(&bytes, tmp.path(), "omg-v1.2.3-x86_64-linux-arch.tar.gz")
            .expect_err("traversal entry must fail closed");
        assert!(!tmp.path().join("evil").exists());
    }

    #[test]
    fn update_extraction_refuses_symlink_binary() {
        use std::io::Write as _;
        let raw = {
            let mut builder = tar::Builder::new(Vec::new());
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_cksum();
            builder
                .append_link(
                    &mut header,
                    "omg-v1.2.3-x86_64-linux-arch/omg",
                    "/etc/hostname",
                )
                .expect("append symlink");
            builder.into_inner().expect("finish tar")
        };
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&raw).expect("gzip tar");
        let bytes = encoder.finish().expect("finish gzip");
        let tmp = tempfile::tempdir().expect("temp dir");
        extract_update_binary(&bytes, tmp.path(), "omg-v1.2.3-x86_64-linux-arch.tar.gz")
            .expect_err("symlink binary must fail closed");
    }

    /// A PATH-hijacked `gh` must never be the tool that approves an
    /// update: resolution is restricted to absolute system paths, so a
    /// project-controlled impostor is ignored (and the gate fails closed
    /// to the "no gh" outcome).
    #[test]
    #[serial_test::serial]
    fn attestation_ignores_path_hijacked_gh() {
        if locate_gh().is_some() {
            // A real GitHub CLI is installed at a trusted absolute path in
            // this environment; running the impostor scenario would invoke
            // it against a synthetic archive. The impostor-ignoring behavior
            // is still covered on environments without a system `gh`.
            eprintln!("[omg-skip] PATH impostor test requires a host without a trusted gh binary");
            return;
        }
        let impostor_dir = tempfile::tempdir().expect("impostor directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let impostor = impostor_dir.path().join("gh");
            std::fs::write(&impostor, "#!/bin/sh\ntouch gh-impostor-marker\nexit 0\n")
                .expect("impostor script");
            std::fs::set_permissions(&impostor, std::fs::Permissions::from_mode(0o755))
                .expect("impostor permissions");
        }

        let archive = tempfile::tempdir().expect("archive directory");
        let archive_path = archive.path().join("archive.tar.gz");
        std::fs::write(&archive_path, b"unverified archive").expect("archive fixture");

        let previous_path = env::var("PATH").ok();
        #[cfg(unix)]
        {
            // SAFETY: Test-only code, serialized by serial_test; no other
            // thread reads PATH concurrently.
            #[expect(unsafe_code)]
            unsafe {
                env::set_var(
                    "PATH",
                    format!(
                        "{}:{}",
                        impostor_dir.path().display(),
                        previous_path.as_deref().unwrap_or("/usr/bin")
                    ),
                );
            }
        }
        let verified = verify_attestation(&archive_path, "v0.0.0-test");
        if let Some(path) = previous_path {
            // SAFETY: see above.
            #[expect(unsafe_code)]
            unsafe {
                env::set_var("PATH", path);
            }
        }

        // A PATH impostor is not an attestation tool: fail closed to the
        // same "no gh" outcome instead of executing it.
        assert!(!verified.expect("impostor must not error"));
        assert!(
            !archive.path().join("gh-impostor-marker").exists(),
            "a PATH-hijacked gh must never run"
        );
    }

    #[test]
    fn unverified_provenance_refuses_by_default() {
        // SEC-R1-02: without `gh` and without the opt-in, self-update must
        // refuse rather than downgrade to a warning.
        let err = decide_unverified_provenance(false)
            .expect_err("unverified provenance must refuse by default");
        let message = format!("{err:#}");
        assert!(
            message.contains("Refusing to install"),
            "refusal must state it is refusing, got: {message}"
        );
        assert!(
            message.contains("gh attestation verify"),
            "refusal must explain manual verification, got: {message}"
        );
        assert!(
            message.contains(ALLOW_UNVERIFIED_PROVENANCE_ENV),
            "refusal must name the explicit opt-in, got: {message}"
        );
    }

    #[test]
    fn unverified_provenance_proceeds_only_with_explicit_opt_in() {
        decide_unverified_provenance(true)
            .expect("explicit opt-in must be the only path past the gate");
    }

    #[test]
    fn allow_unverified_opt_in_requires_explicit_truthy_value() {
        for value in [
            None,
            Some(""),
            Some("0"),
            Some("false"),
            Some("no"),
            Some("yes "),
            Some("TRUE"),
            Some("on"),
        ] {
            assert!(
                !parse_allow_unverified(value),
                "value {value:?} must not open the escape hatch"
            );
        }
        for value in [Some("1"), Some("true"), Some("yes")] {
            assert!(
                parse_allow_unverified(value),
                "value {value:?} must be an explicit opt-in"
            );
        }
    }
}
