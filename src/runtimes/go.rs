//! Native Go runtime manager - PURE RUST
//!
//! Downloads and manages Go versions from go.dev.
//!
//! Features:
//! - Official binaries from go.dev
//! - Checksum verification (SHA256)
//! - GOROOT auto-configuration

use crate::core::http::BoundedResponseExt;
use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::Deserialize;

use super::common::{
    activate_version, begin_download, begin_staged_install, complete_staged_install,
    download_with_progress, extract_tar_gz, normalize_version, parse_sha256_digest,
    print_already_installed, print_installed,
};
use crate::{cli::style, core::http::download_client};

const GO_DOWNLOAD_URL: &str = "https://go.dev/dl";
const GO_VERSIONS_URL: &str = "https://go.dev/dl/?mode=json&include=all";

/// Go version info from go.dev
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct GoVersion {
    version: String,
    stable: bool,
    #[serde(default)]
    files: Vec<GoVersionFile>,
}

#[derive(Debug, Clone, Deserialize)]
struct GoVersionFile {
    filename: String,
    sha256: String,
}

impl GoVersion {
    /// Get the version string without the "go" prefix
    #[must_use]
    pub fn version(&self) -> &str {
        self.version.trim_start_matches("go")
    }

    #[must_use]
    pub const fn stable(&self) -> bool {
        self.stable
    }
}

pub(crate) struct GoManager {
    versions_dir: PathBuf,
    client: &'static reqwest::Client,
}

impl GoManager {
    pub fn new() -> Self {
        Self {
            versions_dir: super::DATA_DIR.join("versions/go"),
            client: download_client(),
        }
    }

    /// List available Go versions from go.dev
    pub async fn list_available(&self) -> Result<Vec<GoVersion>> {
        self.client
            .get(GO_VERSIONS_URL)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .context("Failed to fetch Go version list. Check your internet connection.")?
            .error_for_status()
            .context("Go version-list request failed")?
            .bounded_json()
            .await
            .context("Failed to parse Go version list from go.dev")
    }

    /// Install Go - PURE RUST, NO SUBPROCESS
    pub async fn install(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        let version = self.resolve_requested_version(&version).await?;
        crate::core::security::validate_runtime_version(&version)?;
        let version_dir = self.versions_dir.join(&version);

        if crate::runtimes::common::is_valid_version_dir(&version_dir) {
            print_already_installed("Go", &version);
            return self.use_version(&version);
        }

        println!(
            "{} Installing Go {}...\n",
            style::runtime("OMG"),
            style::caution(&version)
        );

        let filename = format!("go{version}.{}.tar.gz", go_platform()?);
        let url = format!("{GO_DOWNLOAD_URL}/{filename}");

        fs::create_dir_all(&self.versions_dir)?;

        // A vendor checksum is required before installing a downloaded runtime.
        let releases = self.list_available().await?;
        let checksum = checksum_for_file(&releases, &filename)?;

        println!("{} Downloading {filename}...", style::informative("→"));
        let download = begin_download(&self.versions_dir)?;
        let download_path = download.path().join(&filename);
        download_with_progress(self.client, &url, &download_path, &checksum).await?;

        println!("{} Extracting (pure Rust)...", style::informative("→"));
        let staging = begin_staged_install(&self.versions_dir)?;
        extract_tar_gz(&download_path, staging.path(), 1).await?;
        self.publish_install(&staging, &version)?;

        print_installed("Go", &version);
        self.use_version(&version)
    }

    fn publish_install(&self, staging: &tempfile::TempDir, version: &str) -> Result<()> {
        complete_staged_install(staging, &self.versions_dir.join(version), version)
    }

    /// Resolve a partial version request (`1`, `1.21`) to the newest matching
    /// stable go.dev release before any download URL is built; the filename
    /// interpolation is exact-string, so an unresolved partial would 404.
    /// Only stable releases participate: `include=all` also lists RC tags such
    /// as `go1.22rc1`, and a partial request must never resolve into one.
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

    /// Switch to a specific version
    pub fn use_version(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        let version_dir = self.versions_dir.join(&version);
        activate_version(&self.versions_dir, &version, Path::new("bin/go"))?;

        let bin_dir = self.versions_dir.join("current/bin");
        Self::print_version_info(&version, &version_dir, &bin_dir);
        Ok(())
    }

    /// Remove an installed version. Refuses the active version.
    pub fn uninstall(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        super::common::uninstall_version(&self.versions_dir, &version)
    }

    fn print_version_info(version: &str, goroot: &Path, bin_dir: &Path) {
        println!("{} Now using Go {version}", style::positive("✓"));
        println!("  {} {}", style::dim("GOROOT:"), goroot.display());
        println!("  {} {}", style::dim("PATH:"), bin_dir.display());
    }
}

// Generate common runtime manager methods (list_installed, current_version)
crate::runtimes::common::impl_runtime_common!(GoManager);

/// Flatten a go.dev manifest into unprefixed stable version numbers.
fn available_version_names(versions: &[GoVersion]) -> Vec<String> {
    versions
        .iter()
        .filter(|release| release.stable())
        .map(|release| release.version().to_owned())
        .collect()
}

fn checksum_for_file(releases: &[GoVersion], filename: &str) -> Result<String> {
    let checksum = releases
        .iter()
        .flat_map(|release| &release.files)
        .find(|file| file.filename == filename)
        .with_context(|| format!("Go release manifest has no checksum for {filename}"))?;
    parse_sha256_digest(&checksum.sha256, GO_VERSIONS_URL)
}

fn go_platform() -> Result<String> {
    let os = super::common::host_os_tag("Go", "linux", "darwin")?;
    let arch = super::common::host_arch_tag("Go", "amd64", "arm64")?;
    Ok(format!("{os}-{arch}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn incomplete_go_archive_is_not_published_and_can_be_retried() -> Result<()> {
        check_archive_publication(super::super::test_archive::Launcher::Missing).await
    }

    #[tokio::test]
    async fn directory_go_launcher_is_not_published_and_can_be_retried() -> Result<()> {
        check_archive_publication(super::super::test_archive::Launcher::Directory).await
    }

    async fn check_archive_publication(
        invalid: super::super::test_archive::Launcher,
    ) -> Result<()> {
        use super::super::test_archive::{Launcher, tar_gz};
        let versions = tempfile::tempdir()?;
        let manager = GoManager {
            versions_dir: versions.path().to_path_buf(),
            client: download_client(),
        };
        let downloads = tempfile::tempdir()?;
        let archive_path = downloads.path().join("runtime.tar.gz");
        let staging = begin_staged_install(versions.path())?;
        fs::write(&archive_path, tar_gz("runtime", "bin/go", invalid)?)?;
        extract_tar_gz(&archive_path, staging.path(), 1).await?;
        let result = manager.publish_install(&staging, "1.27.0");
        assert!(
            !versions.path().join("1.27.0").exists(),
            "invalid go archive must not be published: {result:?}"
        );
        assert!(result.is_err(), "invalid launcher must be refused");
        assert!(manager.list_installed()?.is_empty());
        assert!(!versions.path().join("current").exists());
        assert_eq!(manager.current_version(), None);
        drop(staging);

        let staging = begin_staged_install(versions.path())?;
        fs::write(
            &archive_path,
            tar_gz("runtime", "bin/go", Launcher::Regular)?,
        )?;
        extract_tar_gz(&archive_path, staging.path(), 1).await?;
        manager.publish_install(&staging, "1.27.0")?;
        manager.use_version("1.27.0")?;
        assert_eq!(manager.list_installed()?, vec!["1.27.0"]);
        assert_eq!(manager.current_version().as_deref(), Some("1.27.0"));
        assert_eq!(
            fs::read(versions.path().join("current/bin/go"))?,
            b"fixture launcher"
        );
        Ok(())
    }

    #[test]
    fn test_go_manager_new() {
        let mgr = GoManager::new();
        assert!(mgr.versions_dir.ends_with("go"));
    }

    #[test]
    fn available_versions_request_includes_historical_releases() {
        assert!(GO_VERSIONS_URL.contains("include=all"));
    }

    #[test]
    fn checksum_comes_from_the_matching_release_manifest_file() {
        let releases = vec![GoVersion {
            version: "go1.27.0".to_string(),
            stable: true,
            files: vec![GoVersionFile {
                filename: "go1.27.0.linux-amd64.tar.gz".to_string(),
                sha256: "a".repeat(64),
            }],
        }];

        assert_eq!(
            checksum_for_file(&releases, "go1.27.0.linux-amd64.tar.gz").unwrap(),
            "a".repeat(64)
        );
        assert!(checksum_for_file(&releases, "go1.27.0.darwin-amd64.tar.gz").is_err());
    }

    #[tokio::test]
    async fn install_rejects_parent_directory_versions_before_network_access() -> Result<()> {
        let manager = GoManager::new();
        assert!(manager.install("..").await.is_err());
        Ok(())
    }

    #[test]
    fn partial_request_resolves_to_the_newest_stable_go_fixture() {
        let releases = vec![
            GoVersion {
                version: "go1.22rc1".to_string(),
                stable: false,
                files: Vec::new(),
            },
            GoVersion {
                version: "go1.21.5".to_string(),
                stable: true,
                files: Vec::new(),
            },
            GoVersion {
                version: "go1.21.0".to_string(),
                stable: true,
                files: Vec::new(),
            },
            GoVersion {
                version: "go1.20".to_string(),
                stable: true,
                files: Vec::new(),
            },
        ];
        let names = available_version_names(&releases);
        // RC tags never participate in partial resolution.
        assert_eq!(
            crate::runtimes::common::resolve_partial_version(&names, "1").as_deref(),
            Some("1.21.5")
        );
        assert_eq!(
            crate::runtimes::common::resolve_partial_version(&names, "1.21").as_deref(),
            Some("1.21.5")
        );
        assert_eq!(
            crate::runtimes::common::resolve_partial_version(&names, "1.20").as_deref(),
            Some("1.20")
        );
        assert_eq!(
            crate::runtimes::common::resolve_partial_version(&names, "1.22"),
            None
        );
    }

    #[test]
    fn go_platform_uses_host_os_and_arch() {
        let platform = go_platform().expect("host platform should be supported");
        if std::env::consts::OS == "linux" {
            assert!(platform.starts_with("linux-"));
        } else {
            assert!(!platform.starts_with("linux-"));
        }
    }
}
