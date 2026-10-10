//! Native Node.js runtime manager
//!
//! Downloads and extracts Node.js in Rust, then verifies candidate execution.
//!
//! Features:
//! - Automatic LTS detection
//! - Checksum verification (SHASUMS256.txt)
//! - Pure Rust XZ extraction
//! - Version aliasing (latest, lts, lts/iron, etc.)

use crate::core::http::BoundedResponseExt;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

use super::common::{
    activate_version_with_lease, begin_download, begin_staged_install, complete_staged_install,
    download_with_progress, extract_tar_xz, normalize_version, parse_sha256_digest,
    print_already_installed, print_installed, print_using,
};
use crate::{cli::style, core::http::download_client};

const NODE_DIST_URL: &str = "https://nodejs.org/dist";

/// Node.js version info from nodejs.org.
///
/// Parsed once at the network boundary; `lts` is decoded into [`LtsStatus`]
/// instead of leaking the vendor's bool-or-string JSON shape.
#[derive(Debug, Deserialize)]
pub(crate) struct NodeVersion {
    pub(crate) version: String,
    lts: LtsStatus,
}

/// The `lts` field of a nodejs.org index entry: a codename string for LTS
/// releases, or `false` otherwise. Parsed explicitly so the vendor's
/// bool-or-string shape never leaks past the boundary.
#[derive(Debug)]
enum LtsStatus {
    Lts(String),
    NotLts,
}

impl<'de> Deserialize<'de> for LtsStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct LtsVisitor;

        impl serde::de::Visitor<'_> for LtsVisitor {
            type Value = LtsStatus;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an LTS codename string or false")
            }

            fn visit_bool<E: serde::de::Error>(self, _flag: bool) -> Result<Self::Value, E> {
                Ok(LtsStatus::NotLts)
            }

            fn visit_str<E: serde::de::Error>(self, name: &str) -> Result<Self::Value, E> {
                Ok(LtsStatus::Lts(name.to_owned()))
            }
        }

        deserializer.deserialize_any(LtsVisitor)
    }
}

impl LtsStatus {
    fn codename(&self) -> Option<&str> {
        match self {
            LtsStatus::Lts(name) => Some(name),
            LtsStatus::NotLts => None,
        }
    }
}

/// Node.js runtime manager
pub(crate) struct NodeManager {
    versions_dir: PathBuf,
    client: &'static reqwest::Client,
}

impl NodeManager {
    pub fn new() -> Self {
        Self {
            versions_dir: super::DATA_DIR.join("versions/node"),
            client: download_client(),
        }
    }

    pub async fn list_available(&self) -> Result<Vec<NodeVersion>> {
        let url = format!("{NODE_DIST_URL}/index.json");

        self.client
            .get(&url)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .context("Failed to fetch Node.js version list. Check your internet connection.")?
            .error_for_status()
            .context("Node.js version list request failed")?
            .bounded_json()
            .await
            .context("Failed to parse Node.js version list from nodejs.org")
    }

    /// Resolve version alias (latest, lts, lts/<codename>) to an actual
    /// version number
    pub async fn resolve_alias(&self, alias: &str) -> Result<String> {
        let alias = normalize_version(alias);

        let result = match alias.as_str() {
            "latest" => {
                let versions = self.list_available().await?;
                versions
                    .first()
                    .map(|v| v.version.trim_start_matches('v').to_string())
                    .ok_or_else(|| anyhow::anyhow!("No Node.js versions found upstream"))?
            }
            "lts" => {
                let versions = self.list_available().await?;
                versions
                    .iter()
                    .find(|v| v.lts.codename().is_some())
                    .map(|v| v.version.trim_start_matches('v').to_string())
                    .ok_or_else(|| anyhow::anyhow!("No LTS version found"))?
            }
            _ => match alias.strip_prefix("lts/") {
                Some(codename) => {
                    let versions = self.list_available().await?;
                    find_lts_codename(&versions, codename)
                        .map(str::to_owned)
                        .ok_or_else(|| {
                            anyhow::anyhow!("No Node.js LTS release with codename '{codename}'")
                        })?
                }
                None => alias,
            },
        };

        Ok(result)
    }

    /// Download, verify, extract, and execution-test Node.js before publication.
    pub async fn install(&self, version: &str) -> Result<()> {
        let version = self.resolve_alias(version).await?;
        let version = self.resolve_requested_version(&version).await?;
        crate::core::security::validate_runtime_version(&version)?;
        let version_dir = self.versions_dir.join(&version);

        if crate::runtimes::common::is_valid_version_dir(&version_dir) {
            print_already_installed("Node.js", &version);
            return self.use_version(&version);
        }

        println!(
            "{} Installing Node.js {}...\n",
            style::runtime("OMG"),
            style::caution(&version)
        );

        let filename = format!("node-v{version}-{}.tar.xz", node_platform()?);
        let url = format!("{NODE_DIST_URL}/v{version}/{filename}");

        fs::create_dir_all(&self.versions_dir)?;

        // A vendor checksum is required before installing a downloaded runtime.
        let checksum = self.fetch_checksum(&version, &filename).await?;

        println!("{} Downloading {}...", style::informative("→"), filename);
        let download = begin_download(&self.versions_dir)?;
        let download_path = download.path().join(&filename);
        download_with_progress(self.client, &url, &download_path, &checksum).await?;

        println!("{} Extracting (pure Rust)...", style::informative("→"));
        let staging = begin_staged_install(&self.versions_dir)?;
        extract_tar_xz(&download_path, staging.path(), 1).await?;
        self.publish_install(&staging, &version)?;

        print_installed("Node.js", &version);
        self.use_version(&version)?;

        Ok(())
    }

    fn publish_install(&self, staging: &tempfile::TempDir, version: &str) -> Result<()> {
        super::common::require_regular_file(&staging.path().join("bin/node"))?;
        smoke_node(staging.path(), version)?;
        complete_staged_install(staging, &self.versions_dir.join(version), version)
    }

    /// Resolve a partial version request (`20`, `20.1`) to the newest matching
    /// nodejs.org release. This must happen before any download URL is built;
    /// the interpolation is exact-string, so an unresolved partial would 404.
    /// Exact and non-numeric requests pass through unchanged, preserving the
    /// already-installed fast path and the existing not-found UX.
    async fn resolve_requested_version(&self, version: &str) -> Result<String> {
        if !crate::runtimes::common::is_partial_version(version) {
            return Ok(version.to_owned());
        }
        let available = self.list_available().await?;
        Ok(crate::runtimes::resolve_version_request(
            &available_version_names(&available),
            version,
        ))
    }

    /// Fetch SHA256 checksum from nodejs.org
    async fn fetch_checksum(&self, version: &str, filename: &str) -> Result<String> {
        let url = format!("{NODE_DIST_URL}/v{version}/SHASUMS256.txt");
        let text = crate::core::http::fetch_metadata_text(self.client, &url)
            .await
            .context("Failed to fetch Node.js checksum manifest")?;
        let digest_line = text
            .lines()
            .find(|line| line.split_whitespace().nth(1) == Some(filename))
            .ok_or_else(|| anyhow::anyhow!("Checksum not found for {filename}"))?;
        parse_sha256_digest(digest_line, &url)
    }

    /// Switch to a specific version
    pub fn use_version(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        crate::core::security::validate_runtime_version(&version)?;
        let lease = super::common::try_lock_runtime_file(&self.versions_dir, ".mutation.lock")?;
        let version_dir = self.versions_dir.join(&version);
        anyhow::ensure!(
            super::common::is_valid_version_dir(&version_dir),
            "Node.js version {version} is not installed as a valid directory"
        );
        super::common::require_regular_file(&version_dir.join("bin/node"))?;
        smoke_node(&version_dir, &version)?;
        activate_version_with_lease(&self.versions_dir, &version, Path::new("bin/node"), &lease)?;
        print_using("Node.js", &version, &self.versions_dir.join("current/bin"));
        Ok(())
    }

    /// Remove an installed version. Refuses the active version.
    pub fn uninstall(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        super::common::uninstall_version(&self.versions_dir, &version)
    }
}

fn smoke_node(version_dir: &Path, expected: &str) -> Result<()> {
    let directory = fs::canonicalize(version_dir).context("Failed to resolve Node.js candidate")?;
    let expected = expected.to_owned();
    crate::cli::tea::run_blocking_future(async move {
        probe_node(&directory, &expected, std::time::Duration::from_secs(5)).await
    })?
}

async fn probe_node(directory: &Path, expected: &str, deadline: std::time::Duration) -> Result<()> {
    use std::process::Stdio;
    use tokio::io::AsyncReadExt as _;

    const OUTPUT_LIMIT: u64 = 4096;
    let binary = directory.join("bin/node");
    let mut command = std::process::Command::new(&binary);
    super::common::harden_untrusted_runtime_command(&mut command, directory);
    command
        .arg("--version")
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut command = tokio::process::Command::from(command);
    command.process_group(0).kill_on_drop(true);
    let mut child = command
        .spawn()
        .context("Failed to execute Node.js version probe")?;
    let Some(id) = child.id() else {
        child
            .wait()
            .await
            .context("Failed to reap Node.js version probe")?;
        anyhow::bail!("Node.js version probe has no process ID");
    };
    let group = match i32::try_from(id) {
        Ok(group) => nix::unistd::Pid::from_raw(group),
        Err(error) => {
            child
                .kill()
                .await
                .context("Failed to terminate invalid Node.js probe process")?;
            return Err(error).context("Node.js probe process ID exceeded i32");
        }
    };
    // Keep the leader unreaped until group cleanup. Its PID then cannot be
    // recycled while a descendant still holds a probe output pipe open.
    let mut exit_observer = tokio::task::spawn_blocking(move || {
        use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};
        let pid = Pid::from_raw(group.as_raw()).context("Invalid Node.js probe process ID")?;
        waitid(
            WaitId::Pid(pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
        )
        .context("Failed to observe Node.js probe exit")?
        .context("Node.js probe exit was not reported")?;
        Ok::<_, anyhow::Error>(())
    });
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let read_output = |stream: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>| async move {
        let mut bytes = Vec::new();
        stream
            .take(OUTPUT_LIMIT + 1)
            .read_to_end(&mut bytes)
            .await?;
        anyhow::ensure!(
            bytes.len() <= OUTPUT_LIMIT as usize,
            "Node.js version probe output exceeds {OUTPUT_LIMIT} bytes"
        );
        Ok::<_, anyhow::Error>(bytes)
    };
    let mut exit_observed = false;
    let capture = tokio::time::timeout(deadline, async {
        let stdout = stdout.context("Missing Node.js version probe stdout")?;
        let stderr = stderr.context("Missing Node.js version probe stderr")?;
        tokio::try_join!(
            read_output(Box::pin(stdout)),
            read_output(Box::pin(stderr)),
            async {
                let result = (&mut exit_observer).await;
                exit_observed = true;
                result.context("Node.js probe exit observer panicked")?
            }
        )
    })
    .await
    .context("Node.js version probe timed out")
    .and_then(std::convert::identity);

    // Every post-spawn path terminates the isolated group before reaping the
    // leader, including bounded-read failures and inherited-pipe timeouts.
    let group_cleanup = match nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(error) => Err(error).context("Failed to terminate Node.js probe process group"),
    };
    let leader_cleanup = if group_cleanup.is_err() {
        child.start_kill()
    } else {
        Ok(())
    };
    let observer_cleanup = if exit_observed {
        Ok(())
    } else {
        exit_observer
            .await
            .context("Node.js probe exit observer panicked")
            .and_then(std::convert::identity)
    };
    let status = child
        .wait()
        .await
        .context("Failed to reap Node.js version probe");
    group_cleanup?;
    leader_cleanup.context("Failed to terminate Node.js probe leader")?;
    observer_cleanup?;
    let status = status?;
    let (stdout, stderr, ()) = capture?;
    anyhow::ensure!(
        status.success(),
        "Node.js version probe failed ({status}): {}",
        style::sanitize_terminal_text(&String::from_utf8_lossy(&stderr))
    );
    let actual = std::str::from_utf8(&stdout)
        .context("Node.js version output is not UTF-8")?
        .trim();
    anyhow::ensure!(
        actual == format!("v{expected}"),
        "Node.js artifact version {actual:?} does not match requested v{expected}"
    );
    Ok(())
}

// Generate common runtime manager methods (list_installed, current_version)
crate::runtimes::common::impl_runtime_common!(NodeManager);

fn node_platform() -> Result<String> {
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        other => anyhow::bail!("Unsupported operating system for Node.js: {other}"),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        arch => anyhow::bail!("Unsupported architecture for Node.js: {arch}"),
    };
    Ok(format!("{os}-{arch}"))
}

/// Flatten a nodejs.org index into unprefixed version numbers.
fn available_version_names(versions: &[NodeVersion]) -> Vec<String> {
    versions
        .iter()
        .map(|version| version.version.trim_start_matches('v').to_owned())
        .collect()
}

/// Find the newest release carrying an LTS codename matching `codename`
/// (case-insensitive), returning its unprefixed version number.
fn find_lts_codename<'a>(versions: &'a [NodeVersion], codename: &str) -> Option<&'a str> {
    versions
        .iter()
        .find(|v| {
            v.lts
                .codename()
                .is_some_and(|name| name.eq_ignore_ascii_case(codename))
        })
        .map(|v| v.version.trim_start_matches('v'))
}

/// Get LTS version name if applicable
#[must_use]
pub(crate) fn get_lts_name(version: &NodeVersion) -> Option<&str> {
    version.lts.codename()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn metadata_retry_recovers_node_checksum_without_skipping_integrity() -> Result<()> {
        let filename = "node-v24.21.0-linux-x64.tar.xz";
        let digest = "a".repeat(64);
        let path = "/dist/v24.21.0/SHASUMS256.txt";
        let fixture = super::super::test_https::HttpsFixture::new_with_statuses(
            "nodejs.org",
            vec![
                (path.into(), 503, b"temporarily unavailable".to_vec()),
                (
                    path.into(),
                    200,
                    format!("{digest}  {filename}\n").into_bytes(),
                ),
            ],
        )
        .await?;
        let directory = tempfile::tempdir()?;
        let client = fixture.client(true)?;
        let manager = NodeManager {
            versions_dir: directory.path().to_path_buf(),
            client: Box::leak(Box::new(client)),
        };
        assert_eq!(manager.fetch_checksum("24.21.0", filename).await?, digest);
        assert_eq!(
            fixture.finish().await?,
            vec![format!("GET {path} HTTP/1.1"); 2]
        );
        assert_eq!(fs::read_dir(directory.path())?.count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn metadata_retry_does_not_retry_invalid_node_checksum() -> Result<()> {
        let path = "/dist/v24.21.0/SHASUMS256.txt";
        let fixture = super::super::test_https::HttpsFixture::new(
            "nodejs.org",
            vec![(
                path.into(),
                b"invalid node-v24.21.0-linux-x64.tar.xz\n".to_vec(),
            )],
        )
        .await?;
        let directory = tempfile::tempdir()?;
        let manager = NodeManager {
            versions_dir: directory.path().to_path_buf(),
            client: Box::leak(Box::new(fixture.client(true)?)),
        };
        assert!(
            manager
                .fetch_checksum("24.21.0", "node-v24.21.0-linux-x64.tar.xz")
                .await
                .is_err()
        );
        assert_eq!(fixture.finish().await?.len(), 1);
        assert_eq!(fs::read_dir(directory.path())?.count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn metadata_retry_recovers_real_connection_interruption() -> Result<()> {
        let path = "/dist/v24.21.0/SHASUMS256.txt";
        let interrupted = super::super::test_https::HttpsFixture::new_with_statuses(
            "nodejs.org",
            vec![(path.into(), 0, vec![])],
        )
        .await?;
        let error = interrupted
            .client(true)?
            .get(format!("https://nodejs.org{path}"))
            .send()
            .await
            .unwrap_err();
        assert!(
            error.is_connect(),
            "expected actual connection failure: {error}"
        );
        assert_eq!(
            interrupted.finish().await?,
            ["CONNECT nodejs.org:443 HTTP/1.1"]
        );

        let filename = "node-v24.21.0-linux-x64.tar.xz";
        let digest = "b".repeat(64);
        let fixture = super::super::test_https::HttpsFixture::new_with_statuses(
            "nodejs.org",
            vec![
                (path.into(), 0, vec![]),
                (
                    path.into(),
                    200,
                    format!("{digest}  {filename}\n").into_bytes(),
                ),
            ],
        )
        .await?;
        let directory = tempfile::tempdir()?;
        let manager = NodeManager {
            versions_dir: directory.path().to_path_buf(),
            client: Box::leak(Box::new(fixture.client(true)?)),
        };
        assert_eq!(manager.fetch_checksum("24.21.0", filename).await?, digest);
        assert_eq!(
            fixture.finish().await?,
            [
                "CONNECT nodejs.org:443 HTTP/1.1".to_owned(),
                format!("GET {path} HTTP/1.1"),
            ]
        );
        assert_eq!(fs::read_dir(directory.path())?.count(), 0);
        Ok(())
    }

    #[test]
    fn incomplete_node_install_is_not_published_and_can_be_retried() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let manager = NodeManager {
            versions_dir: directory.path().to_path_buf(),
            client: download_client(),
        };
        let staging = begin_staged_install(directory.path())?;
        assert!(manager.publish_install(&staging, "22.0.0").is_err());
        assert!(!directory.path().join("22.0.0").exists());
        assert!(manager.list_installed()?.is_empty());
        drop(staging);

        let staging = begin_staged_install(directory.path())?;
        fs::create_dir(staging.path().join("bin"))?;
        write_node_probe(staging.path(), "printf 'v22.0.0\\n'", true)?;
        manager.publish_install(&staging, "22.0.0")?;
        assert_eq!(manager.list_installed()?, vec!["22.0.0"]);
        Ok(())
    }

    #[cfg(unix)]
    fn write_node_probe(directory: &Path, body: &str, executable: bool) -> Result<()> {
        use std::os::unix::fs::PermissionsExt as _;
        fs::create_dir_all(directory.join("bin"))?;
        let binary = directory.join("bin/node");
        fs::write(&binary, format!("#!/bin/sh\n{body}\n"))?;
        fs::set_permissions(
            binary,
            fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }),
        )?;
        Ok(())
    }

    #[cfg(unix)]
    fn assert_node_candidate_refused(
        body: &str,
        executable: bool,
        publication: bool,
        expected_error: &str,
    ) -> Result<()> {
        #[cfg(target_os = "linux")]
        if body.contains("(/bin/sleep 30)") && run_node_descendant_test_in_child()? {
            return Ok(());
        }
        let directory = tempfile::tempdir()?;
        let manager = NodeManager {
            versions_dir: directory.path().to_path_buf(),
            client: download_client(),
        };
        let previous = directory.path().join("20.0.0");
        write_node_probe(&previous, "printf 'v20.0.0\\n'", true)?;
        manager.use_version("20.0.0")?;
        let original = fs::read(previous.join("bin/node"))?;
        let staging = begin_staged_install(directory.path())?;
        let candidate = if publication {
            staging.path().to_path_buf()
        } else {
            directory.path().join("22.0.0")
        };
        write_node_probe(&candidate, body, executable)?;
        let candidate_bytes = fs::read(candidate.join("bin/node"))?;
        let result = if publication {
            manager.publish_install(&staging, "22.0.0")
        } else {
            manager.use_version("22.0.0")
        };
        assert!(
            result.is_err(),
            "accepted unusable candidate; publication={publication}"
        );
        let error = result.unwrap_err();
        assert!(
            format!("{error:#}").contains(expected_error),
            "wrong refusal: {error:#}"
        );
        if body.contains("exit 127") {
            assert!(
                format!("{error:#}").contains("exit status: 127"),
                "loader exit was not retained: {error:#}"
            );
        }
        if body.contains("probe.pid") {
            assert!(
                candidate.join("probe.pid").is_file(),
                "probe did not execute"
            );
        }
        if publication {
            assert!(!directory.path().join("22.0.0").exists());
            assert!(!staging.path().join(".omg-install-complete").exists());
        }
        assert_eq!(manager.current_version(), Some("20.0.0".to_owned()));
        assert_eq!(fs::read(previous.join("bin/node"))?, original);
        assert_eq!(fs::read(candidate.join("bin/node"))?, candidate_bytes);
        assert_probe_dead(&candidate, body.contains("(/bin/sleep 30)"))?;
        if publication {
            drop(staging);
            assert!(!candidate.exists());
            assert!(!directory.path().join("22.0.0").exists());
            assert_eq!(manager.current_version(), Some("20.0.0".to_owned()));
        }
        Ok(())
    }

    #[cfg(unix)]
    macro_rules! node_refusal_tests {
        ($publish:ident, $activate:ident, $body:expr, $executable:expr, $error:expr) => {
            #[test]
            fn $publish() -> Result<()> {
                assert_node_candidate_refused(&$body, $executable, true, $error)
            }
            #[test]
            fn $activate() -> Result<()> {
                assert_node_candidate_refused(&$body, $executable, false, $error)
            }
        };
    }

    #[cfg(unix)]
    node_refusal_tests!(
        node_publication_rejects_loader_failure,
        node_activation_rejects_loader_failure,
        "printf 'libatomic.so.1: cannot open shared object file\\n' >&2; exit 127",
        true,
        "libatomic.so.1"
    );
    #[cfg(unix)]
    node_refusal_tests!(
        node_publication_rejects_version_mismatch,
        node_activation_rejects_version_mismatch,
        "printf 'v21.0.0\\n'",
        true,
        "does not match requested"
    );
    #[cfg(unix)]
    node_refusal_tests!(
        node_publication_rejects_nonexecutable,
        node_activation_rejects_nonexecutable,
        "printf 'v22.0.0\\n'",
        false,
        "Failed to execute"
    );
    #[cfg(unix)]
    node_refusal_tests!(
        node_publication_rejects_timeout,
        node_activation_rejects_timeout,
        "printf '%s\\n' \"$$\" > probe.pid; exec /bin/sleep 30",
        true,
        "timed out"
    );
    #[cfg(unix)]
    node_refusal_tests!(
        node_publication_rejects_oversize,
        node_activation_rejects_oversize,
        format!("printf '%s' '{}'", "x".repeat(5000)),
        true,
        "exceeds 4096"
    );
    #[cfg(unix)]
    node_refusal_tests!(
        node_publication_rejects_pipe_holding_descendant,
        node_activation_rejects_pipe_holding_descendant,
        "printf '%s\\n' \"$$\" > probe-leader.pid; (/bin/sleep 30) & printf '%s\\n' \"$!\" > probe.pid; printf 'v22.0.0\\n'",
        true,
        "timed out"
    );

    #[cfg(target_os = "linux")]
    fn run_node_descendant_test_in_child() -> Result<bool> {
        let test = std::thread::current()
            .name()
            .context("Node descendant fixture requires its exact test name")?
            .to_owned();
        if std::env::var_os("OMG_NODE_DESCENDANT_CHILD").as_deref()
            == Some(std::ffi::OsStr::new(&test))
        {
            nix::sys::prctl::set_child_subreaper(true)?;
            return Ok(false);
        }
        // This supervisor bounds the direct harness child. The controlled probe
        // descendant is cleaned up by its adopted-PID guard inside that child.
        let output = crate::cli::tea::run_blocking_future(async move {
            use tokio::io::AsyncReadExt as _;
            let mut child = tokio::process::Command::new(std::env::current_exe()?)
                .args(["--exact", &test, "--nocapture"])
                .env("OMG_NODE_DESCENDANT_CHILD", &test)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn()?;
            let mut stdout = child.stdout.take().context("Missing fixture stdout")?;
            let mut stderr = child.stderr.take().context("Missing fixture stderr")?;
            let mut out = Vec::new();
            let mut err = Vec::new();
            let result = tokio::time::timeout(std::time::Duration::from_secs(20), async {
                tokio::try_join!(
                    child.wait(),
                    stdout.read_to_end(&mut out),
                    stderr.read_to_end(&mut err)
                )
            })
            .await;
            match result {
                Ok(Ok((status, _, _))) => Ok((status, out, err)),
                failure => {
                    let kill = child.start_kill();
                    let wait = child.wait().await;
                    kill.context("Failed to terminate descendant fixture")?;
                    wait.context("Failed to reap descendant fixture")?;
                    anyhow::bail!("Node descendant fixture failed its bound: {failure:?}")
                }
            }
        })??;
        println!("{}", String::from_utf8_lossy(&output.1));
        eprintln!("{}", String::from_utf8_lossy(&output.2));
        anyhow::ensure!(output.0.success(), "Owned Node descendant fixture failed");
        let stdout = String::from_utf8_lossy(&output.1);
        anyhow::ensure!(
            stdout.contains("NODE_DESCENDANT_OWNED_REAP_ESRCH")
                && stdout.contains("NODE_LEADER_REAP_ESRCH")
                && stdout.contains("test result: ok. 1 passed;"),
            "Owned Node descendant inner test did not execute its proof"
        );
        Ok(true)
    }

    // The child harness alone adopts this fixture orphan. Its cleanup is armed
    // only after PPID, process identity, group and wait ownership are proven.
    #[cfg(target_os = "linux")]
    fn reap_owned_node_descendant(pid: nix::unistd::Pid, leader: nix::unistd::Pid) -> Result<()> {
        use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
        use std::time::{Duration, Instant};
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
        println!("NODE_DESCENDANT_BEFORE_REAP {stat}");
        let fields = stat
            .rsplit_once(')')
            .context("Malformed descendant stat")?
            .1
            .split_whitespace()
            .collect::<Vec<_>>();
        anyhow::ensure!(fields.len() > 19, "Incomplete descendant stat");
        anyhow::ensure!(
            fields[1].parse::<u32>()? == std::process::id(),
            "Descendant is not adopted by this fixture"
        );
        anyhow::ensure!(
            fields[2].parse::<i32>()? == leader.as_raw(),
            "Descendant left the expected probe group"
        );
        let starttime = fields[19].to_owned();
        rustix::process::waitid(
            rustix::process::WaitId::Pid(
                rustix::process::Pid::from_raw(pid.as_raw()).context("Invalid descendant PID")?,
            ),
            rustix::process::WaitIdOptions::EXITED
                | rustix::process::WaitIdOptions::NOHANG
                | rustix::process::WaitIdOptions::NOWAIT,
        )
        .context("Descendant is not waitable by this fixture")?;
        let reaped = std::cell::Cell::new(false);
        let _cleanup = scopeguard::guard(pid, |pid| {
            if !reaped.get() {
                let owned = fs::read_to_string(format!("/proc/{pid}/stat"))
                    .ok()
                    .and_then(|stat| {
                        let fields = stat
                            .rsplit_once(')')?
                            .1
                            .split_whitespace()
                            .collect::<Vec<_>>();
                        Some(
                            fields.len() > 19
                                && fields[1] == std::process::id().to_string()
                                && fields[19] == starttime,
                        )
                    })
                    .unwrap_or(false);
                if !owned {
                    eprintln!("NODE_DESCENDANT_FAILED_PROOF_CLEANUP_REFUSED_UNOWNED {pid}");
                    return;
                }
                let kill = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
                println!("NODE_DESCENDANT_FAILED_PROOF_CLEANUP kill={kill:?}");
                let deadline = Instant::now() + Duration::from_secs(2);
                loop {
                    let result = waitpid(pid, Some(WaitPidFlag::WNOHANG));
                    println!("NODE_DESCENDANT_FAILED_PROOF_REAP {result:?}");
                    if result != Ok(WaitStatus::StillAlive) || Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let status = waitpid(pid, Some(WaitPidFlag::WNOHANG))?;
            match status {
                WaitStatus::StillAlive => {
                    anyhow::ensure!(
                        Instant::now() < deadline,
                        "Node descendant remained alive before fixture cleanup"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                terminal @ (WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _)) => {
                    reaped.set(true);
                    println!("NODE_DESCENDANT_PRODUCTION_STATUS {terminal:?}");
                    assert_eq!(
                        terminal,
                        WaitStatus::Signaled(pid, nix::sys::signal::Signal::SIGKILL, false)
                    );
                    assert_eq!(
                        nix::sys::signal::kill(pid, None),
                        Err(nix::errno::Errno::ESRCH)
                    );
                    println!("NODE_DESCENDANT_OWNED_REAP_ESRCH {pid}");
                    return Ok(());
                }
                unexpected => anyhow::bail!("Unexpected owned descendant state: {unexpected:?}"),
            }
        }
    }

    #[cfg(unix)]
    fn assert_probe_dead(directory: &Path, descendant: bool) -> Result<()> {
        if directory.join("probe.pid").try_exists()? {
            let pid = fs::read_to_string(directory.join("probe.pid"))?;
            let pid = nix::unistd::Pid::from_raw(pid.trim().parse()?);
            #[cfg(target_os = "linux")]
            if descendant {
                let leader = fs::read_to_string(directory.join("probe-leader.pid"))?;
                let leader = nix::unistd::Pid::from_raw(leader.trim().parse()?);
                assert_eq!(
                    nix::sys::signal::kill(leader, None),
                    Err(nix::errno::Errno::ESRCH)
                );
                println!("NODE_LEADER_REAP_ESRCH {leader}");
                return reap_owned_node_descendant(pid, leader);
            }
            #[cfg(not(target_os = "linux"))]
            let _ = descendant;
            assert_eq!(
                nix::sys::signal::kill(pid, None),
                Err(nix::errno::Errno::ESRCH),
                "probe survived refusal"
            );
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn node_activation_holds_the_mutation_lease_during_execution_validation() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let manager = NodeManager {
            versions_dir: directory.path().to_path_buf(),
            client: download_client(),
        };
        let previous = directory.path().join("20.0.0");
        write_node_probe(&previous, "printf 'v20.0.0\\n'", true)?;
        manager.use_version("20.0.0")?;
        let candidate = directory.path().join("22.0.0");
        write_node_probe(
            &candidate,
            "printf ready > ready; while [ ! -f release ]; do /bin/sleep 0.01; done; printf 'v22.0.0\\n'",
            true,
        )?;
        let worker = std::thread::spawn(move || manager.use_version("22.0.0"));
        let start = std::time::Instant::now();
        while !candidate.join("ready").try_exists()?
            && start.elapsed() < std::time::Duration::from_secs(2)
        {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let ready = candidate.join("ready").is_file();
        let refusal = super::super::common::uninstall_version(directory.path(), "22.0.0");
        fs::write(candidate.join("release"), "continue")?;
        let activation = worker.join().expect("activation worker panicked");
        assert!(ready, "candidate execution never reached held probe");
        assert!(format!("{:#}", refusal.unwrap_err()).contains("Another runtime mutation"));
        activation?;
        assert_eq!(
            super::super::common::get_current_version(directory.path()),
            Some("22.0.0".to_owned())
        );
        assert!(candidate.join("bin/node").is_file());
        assert!(previous.join("bin/node").is_file());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn node_activation_rejects_unsafe_version_before_executing_and_preserves_selection()
    -> Result<()> {
        let directory = tempfile::tempdir()?;
        let manager = NodeManager {
            versions_dir: directory.path().to_path_buf(),
            client: download_client(),
        };
        write_node_probe(
            &directory.path().join("20.0.0"),
            "printf 'v20.0.0\\n'",
            true,
        )?;
        manager.use_version("20.0.0")?;
        let outside = tempfile::tempdir()?;
        write_node_probe(
            outside.path(),
            "printf 'executed' > invoked; printf 'v22.0.0\\n'",
            true,
        )?;
        std::os::unix::fs::symlink(outside.path(), directory.path().join("22.0.0"))?;
        for version in ["22.0.0", "../22.0.0", "bad;version", "missing"] {
            assert!(manager.use_version(version).is_err());
            assert_eq!(manager.current_version(), Some("20.0.0".to_owned()));
            assert!(!outside.path().join("invoked").exists());
        }
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn node_sync_activation_works_inside_current_thread_runtime() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let manager = NodeManager {
            versions_dir: directory.path().to_path_buf(),
            client: download_client(),
        };
        let staging = begin_staged_install(directory.path())?;
        write_node_probe(staging.path(), "printf 'v22.0.0\\n'", true)?;
        manager.publish_install(&staging, "22.0.0")?;
        manager.use_version("22.0.0")?;
        assert_eq!(manager.current_version(), Some("22.0.0".to_owned()));
        Ok(())
    }

    #[test]
    fn test_node_manager_new() {
        let mgr = NodeManager::new();
        assert!(mgr.versions_dir.ends_with("node"));
    }

    #[test]
    fn test_get_lts_name() {
        let lts_version = NodeVersion {
            version: "v20.0.0".to_string(),
            lts: LtsStatus::Lts("Iron".to_string()),
        };
        assert_eq!(get_lts_name(&lts_version), Some("Iron"));

        let non_lts = NodeVersion {
            version: "v21.0.0".to_string(),
            lts: LtsStatus::NotLts,
        };
        assert_eq!(get_lts_name(&non_lts), None);
    }

    #[test]
    fn lts_codename_alias_resolves_case_insensitively() {
        let versions = vec![
            NodeVersion {
                version: "v21.0.0".to_string(),
                lts: LtsStatus::NotLts,
            },
            NodeVersion {
                version: "v20.1.0".to_string(),
                lts: LtsStatus::Lts("Iron".to_string()),
            },
            NodeVersion {
                version: "v20.0.0".to_string(),
                lts: LtsStatus::Lts("Iron".to_string()),
            },
            NodeVersion {
                version: "v18.19.0".to_string(),
                lts: LtsStatus::Lts("Hydrogen".to_string()),
            },
        ];

        // Newest matching release wins; matching is case-insensitive.
        assert_eq!(find_lts_codename(&versions, "iron"), Some("20.1.0"));
        assert_eq!(find_lts_codename(&versions, "IRON"), Some("20.1.0"));
        assert_eq!(find_lts_codename(&versions, "hydrogen"), Some("18.19.0"));
        assert_eq!(find_lts_codename(&versions, "unknown"), None);
    }

    #[test]
    fn lts_field_parses_vendor_json_shapes() {
        #[derive(Deserialize)]
        struct Wire {
            lts: LtsStatus,
        }

        let named: Wire = serde_json::from_str(r#"{ "lts": "Iron" }"#).unwrap();
        assert_eq!(named.lts.codename(), Some("Iron"));

        let not_lts: Wire = serde_json::from_str(r#"{ "lts": false }"#).unwrap();
        assert_eq!(not_lts.lts.codename(), None);

        // Anything else is rejected at the boundary instead of leaking through.
        assert!(serde_json::from_str::<Wire>(r#"{ "lts": 42 }"#).is_err());
    }

    #[tokio::test]
    async fn https_alias_resolution_requires_the_exact_release_identity() -> Result<()> {
        let body = br#"[{"version":"v21.0.0","lts":false},{"version":"v20.10.0","lts":"Iron"},{"version":"v18.19.0","lts":"Hydrogen"}]"#;
        let fixture = super::super::test_https::HttpsFixture::new(
            "nodejs.org",
            (0..4)
                .map(|_| ("/dist/index.json".into(), body.to_vec()))
                .collect(),
        )
        .await?;
        let versions = tempfile::TempDir::new()?;
        let manager = NodeManager {
            versions_dir: versions.path().to_path_buf(),
            client: Box::leak(Box::new(fixture.client(true)?)),
        };
        assert_eq!(manager.resolve_alias("latest").await?, "21.0.0");
        assert_eq!(manager.resolve_alias("lts").await?, "20.10.0");
        assert_eq!(manager.resolve_alias("lts/iron").await?, "20.10.0");
        assert!(manager.resolve_alias("lts/missing").await.is_err());
        assert_eq!(manager.resolve_alias("v20.10.0").await?, "20.10.0");
        assert_eq!(
            fixture.finish().await?,
            vec!["GET /dist/index.json HTTP/1.1"; 4]
        );
        assert_eq!(std::fs::read_dir(versions.path())?.count(), 0);
        Ok(())
    }

    fn fixture_versions() -> Vec<NodeVersion> {
        vec![
            NodeVersion {
                version: "v21.0.0".to_string(),
                lts: LtsStatus::NotLts,
            },
            NodeVersion {
                version: "v20.10.0".to_string(),
                lts: LtsStatus::Lts("Iron".to_string()),
            },
            NodeVersion {
                version: "v20.1.0".to_string(),
                lts: LtsStatus::Lts("Iron".to_string()),
            },
            NodeVersion {
                version: "v18.19.0".to_string(),
                lts: LtsStatus::Lts("Hydrogen".to_string()),
            },
        ]
    }

    #[test]
    fn partial_major_resolves_to_the_newest_matching_fixture() {
        let names = available_version_names(&fixture_versions());
        assert_eq!(
            crate::runtimes::common::resolve_partial_version(&names, "20").as_deref(),
            Some("20.10.0")
        );
    }

    #[test]
    fn partial_minor_resolves_within_the_fixture_family() {
        let names = available_version_names(&fixture_versions());
        assert_eq!(
            crate::runtimes::common::resolve_partial_version(&names, "20.1").as_deref(),
            Some("20.1.0")
        );
    }

    #[test]
    fn exact_fixture_version_passes_through() {
        let names = available_version_names(&fixture_versions());
        assert_eq!(
            crate::runtimes::common::resolve_partial_version(&names, "20.10.0").as_deref(),
            Some("20.10.0")
        );
    }

    #[test]
    fn unknown_partial_has_no_resolution_and_falls_back_to_the_request() {
        let names = available_version_names(&fixture_versions());
        assert_eq!(
            crate::runtimes::common::resolve_partial_version(&names, "22"),
            None
        );
        // Garbage never reaches the vendor list: it is not partial, so the
        // manager passes it through to the existing not-found UX.
        assert!(!crate::runtimes::common::is_partial_version("garbage"));
    }

    #[test]
    fn node_platform_uses_host_os_and_arch() {
        let platform = node_platform().expect("host platform should be supported");
        assert!(platform.contains('-'));
        assert!(!platform.starts_with("linux-") || std::env::consts::OS == "linux");
    }

    #[cfg(target_os = "macos")]
    mod native_zombie_cause {
        use anyhow::{Context, Result, ensure};
        use nix::{
            errno::Errno,
            libc,
            sys::signal::{Signal, killpg},
            unistd::Pid,
        };
        use std::{
            mem::{MaybeUninit, size_of},
            os::unix::process::CommandExt,
            process::{Child, Command, Stdio},
            time::{Duration, Instant},
        };

        #[derive(Debug, PartialEq, Eq)]
        struct Identity {
            pid: u32,
            pgid: u32,
            ppid: u32,
            status: u32,
            uid: u32,
            ruid: u32,
            start_sec: u64,
            start_usec: u64,
        }

        // Direct child ownership is armed immediately. This helper never signals a
        // process group after releasing the leader's waitid(NOWAIT) identity pin.
        struct OwnedLeader(Option<Child>);
        impl Drop for OwnedLeader {
            fn drop(&mut self) {
                if self.0.is_some() {
                    eprintln!("MAC_CAUSE_FIXTURE_FAILURE_CLEANUP fallback=true");
                    if let Err(error) = self.cleanup(true) {
                        // Drop cannot return an error. Explicit cleanup is mandatory
                        // before a normal test return; this fallback accompanies an
                        // existing proof failure/unwind, never a successful result.
                        eprintln!("MAC_CAUSE_INCONCLUSIVE_CLEANUP {error:#}");
                    }
                }
            }
        }
        impl OwnedLeader {
            fn cleanup(&mut self, terminate: bool) -> Result<()> {
                let child = self.0.as_mut().context("missing owned leader")?;
                let end = Instant::now() + Duration::from_secs(2);
                if terminate {
                    // Exact still-owned direct Child only. No released process group
                    // is signaled by this cleanup path. A kill error still permits
                    // bounded try_wait to determine that it has already exited.
                    let killed = child.kill();
                    eprintln!(
                        "MAC_CAUSE_EXACT_CHILD_KILL pid={} result={killed:?}",
                        child.id()
                    );
                }
                loop {
                    match child
                        .try_wait()
                        .context("MAC_CAUSE_INCONCLUSIVE_CLEANUP owned causal leader try_wait")?
                    {
                        Some(status) => {
                            self.0.take();
                            eprintln!(
                                "MAC_CAUSE_OWNED_LEADER_REAP {status:?} terminate={terminate}"
                            );
                            ensure!(
                                terminate || status.success(),
                                "MAC_CAUSE_INCONCLUSIVE_CLEANUP causal leader exited abnormally"
                            );
                            return Ok(());
                        }
                        None => {
                            ensure!(
                                Instant::now() < end,
                                "MAC_CAUSE_INCONCLUSIVE_CLEANUP owned-child reap deadline exceeded"
                            );
                            std::thread::sleep(Duration::from_millis(2));
                        }
                    }
                }
            }
        }

        fn snapshot(pgid: i32) -> Result<Vec<Identity>> {
            // Controlled fixture has ONE direct child and no descendants. A small
            // 16-PID bound is below the pinned kernel's nprocs+20 internal bound;
            // count < caller capacity alone is insufficient for arbitrarily large
            // buffers if the kernel independently caps its allocation.
            let mut pids = [0_i32; 16];
            let bytes = i32::try_from(size_of::<[i32; 16]>())?;
            // SAFETY: valid initialized writable array; capacity parameter is BYTES.
            let count = unsafe { libc::proc_listpgrppids(pgid, pids.as_mut_ptr().cast(), bytes) };
            eprintln!(
                "MAC_CAUSE_GROUP_COUNT pgid={pgid} pid_count={count} capacity=16 bytes={bytes}"
            );
            ensure!(
                count > 0 && count < 16,
                "empty/error/truncated group enumeration"
            );
            let ids = &mut pids[..usize::try_from(count)?];
            ids.sort_unstable();
            ensure!(ids.iter().all(|pid| *pid > 0), "invalid group PID");
            ensure!(
                ids.windows(2).all(|pair| pair[0] != pair[1]),
                "duplicate PID"
            );
            let mut rows = Vec::new();
            for pid in ids.iter().copied() {
                let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
                let size = i32::try_from(size_of::<libc::proc_bsdinfo>())?;
                // SAFETY: locked libc's typed buffer, exact capacity. arg=1 requests
                // zombie lookup; never assume_init after an error/partial response.
                let got = unsafe {
                    libc::proc_pidinfo(
                        pid,
                        libc::PROC_PIDTBSDINFO,
                        1,
                        info.as_mut_ptr().cast(),
                        size,
                    )
                };
                ensure!(
                    got == size,
                    "BSDINFO incomplete: pid={pid} got={got} required={size}"
                );
                // SAFETY: the preceding exact-size response initialized this buffer.
                let info = unsafe { info.assume_init() };
                let row = Identity {
                    pid: info.pbi_pid,
                    pgid: info.pbi_pgid,
                    ppid: info.pbi_ppid,
                    status: info.pbi_status,
                    uid: info.pbi_uid,
                    ruid: info.pbi_ruid,
                    start_sec: info.pbi_start_tvsec,
                    start_usec: info.pbi_start_tvusec,
                };
                ensure!(
                    row.pid == u32::try_from(pid)? && row.pgid == u32::try_from(pgid)?,
                    "PID/group identity changed"
                );
                eprintln!("MAC_CAUSE_MEMBER {row:?}");
                rows.push(row);
            }
            Ok(rows)
        }

        pub(super) fn emit_harness_identity() -> Result<()> {
            use sha2::Digest as _;
            use std::io::Read as _;
            let exe =
                std::env::current_exe().context("MAC_CAUSE_INCONCLUSIVE_HARNESS current_exe")?;
            let mut file = std::fs::File::open(&exe)
                .context("MAC_CAUSE_INCONCLUSIVE_HARNESS open current executable")?;
            ensure!(
                file.metadata()?.is_file(),
                "MAC_CAUSE_INCONCLUSIVE_HARNESS nonregular executable"
            );
            let mut hash = sha2::Sha256::new();
            let mut buffer = [0_u8; 64 * 1024];
            let mut observed_bytes = 0_u64;
            loop {
                let count = file
                    .read(&mut buffer)
                    .context("MAC_CAUSE_INCONCLUSIVE_HARNESS read current executable")?;
                if count == 0 {
                    break;
                }
                hash.update(&buffer[..count]);
                observed_bytes = observed_bytes
                    .checked_add(u64::try_from(count)?)
                    .context("MAC_CAUSE_INCONCLUSIVE_HARNESS byte count overflow")?;
            }
            ensure!(
                observed_bytes == file.metadata()?.len(),
                "MAC_CAUSE_INCONCLUSIVE_HARNESS executable length changed"
            );
            eprintln!(
                "MAC_CAUSE_HARNESS_IDENTITY sha256={:x} bytes={observed_bytes} os={} arch={} path={exe:?}",
                hash.finalize(),
                std::env::consts::OS,
                std::env::consts::ARCH
            );
            Ok(())
        }

        pub(super) fn prove_owned_native_cause() -> Result<()> {
            let child = Command::new("/bin/sh")
                .args(["-c", "exit 0"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0)
                .spawn()
                .context("spawn owned causal fixture")?;
            let mut owner = OwnedLeader(Some(child));
            let pgid = i32::try_from(owner.0.as_ref().context("missing leader")?.id())?;
            let proof = (|| -> Result<()> {
                use rustix::process::{Pid as WaitPid, WaitId, WaitIdOptions, waitid};
                let pid = WaitPid::from_raw(pgid).context("invalid owned leader PID")?;
                let end = Instant::now() + Duration::from_secs(2);
                loop {
                    if waitid(
                        WaitId::Pid(pid),
                        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
                    )?
                    .is_some()
                    {
                        break;
                    }
                    ensure!(
                        Instant::now() < end,
                        "fixture exit observation exceeded deadline"
                    );
                    std::thread::sleep(Duration::from_millis(2));
                }
                // SAFETY: getuid/geteuid have no pointer or ownership requirements.
                let (uid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
                let caller = std::process::id();
                eprintln!(
                    "MAC_CAUSE_ACTOR uid={uid} euid={euid} ppid={caller} pgid={pgid} waitid_nowait=true"
                );
                ensure!(uid != 0 && uid == euid, "ordinary caller required");
                let before = snapshot(pgid)?;
                ensure!(before.len() == 1, "controlled one-member group changed");
                for row in &before {
                    ensure!(
                        row.pid == u32::try_from(pgid)?
                            && row.ppid == caller
                            && row.status == libc::SZOMB
                            && row.uid == euid
                            && row.ruid == uid
                            && row.start_sec > 0,
                        "owned zombie leader proof failed"
                    );
                }
                let raw = killpg(Pid::from_raw(pgid), Signal::SIGKILL);
                eprintln!("MAC_CAUSE_RAW_GROUP_SIGKILL pgid={pgid} result={raw:?}");
                let after = snapshot(pgid)?;
                ensure!(
                    before == after,
                    "group identity/state changed across raw syscall"
                );
                eprintln!("MAC_CAUSE_GROUP_STABLE before_equals_after=true leader_pin_held=true");
                ensure!(
                    raw == Err(Errno::EPERM),
                    "native zombie-only EPERM precondition absent"
                );
                Ok(())
            })();
            // Proof errors use the guard's exact owned-child cleanup; successful
            // proof performs ordinary wait only after every group observation.
            let cleaned = owner.cleanup(proof.is_err());
            cleaned?;
            proof?;
            Ok(())
        }
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn node_accepts_valid_candidate_after_native_zombie_group_cause_proof() -> Result<()> {
        native_zombie_cause::emit_harness_identity()?;
        native_zombie_cause::prove_owned_native_cause()?;
        let directory = tempfile::tempdir()?;
        write_node_probe(directory.path(), "printf 'v22.0.0\\n'", true)?;
        let actual = probe_node(directory.path(), "22.0.0", Duration::from_secs(5)).await;
        eprintln!("MAC_CAUSE_ACTUAL_NODE_PROBE {actual:?}");
        if let Err(error) = &actual {
            let exact_context = error.chain().any(|cause| {
                cause.to_string() == "Failed to terminate Node.js probe process group"
            });
            let typed_eperm = error.chain().any(|cause| {
                cause.downcast_ref::<nix::errno::Errno>() == Some(&nix::errno::Errno::EPERM)
            });
            if !exact_context || !typed_eperm {
                anyhow::bail!(
                    "MAC_CAUSE_INCONCLUSIVE_PRODUCTION_ERROR unexpected probe failure: {error:#}"
                );
            }
            eprintln!("MAC_CAUSE_ACTUAL_PROBE_CLASSIFICATION EXPECTED_BASELINE_EPERM {error:#}");
        } else {
            eprintln!("MAC_CAUSE_ACTUAL_PROBE_CLASSIFICATION VALID_PROBE_ACCEPTED");
        }
        assert!(
            actual.is_ok(),
            "valid candidate refused after paired native cause proof: {actual:?}"
        );
        Ok(())
    }
}
