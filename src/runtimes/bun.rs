//! Native Bun runtime manager - PURE RUST
//!
//! Downloads and manages Bun versions from GitHub.
//!
//! Features:
//! - Fast JavaScript/TypeScript runtime
//! - Pre-built binaries from GitHub releases
//! - Version aliasing (latest)

use crate::core::http::BoundedResponseExt;
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use super::common::{
    GITHUB_USER_AGENT, GithubRelease, activate_version, begin_download, begin_staged_install,
    complete_staged_install, download_with_progress, extract_zip, normalize_version,
    parse_sha256_digest, print_already_installed, print_installed, print_using, version_cmp,
};
use crate::{cli::style, core::http::download_client};

const BUN_RELEASES_URL: &str = "https://github.com/oven-sh/bun/releases/download";
const BUN_API_URL: &str = "https://api.github.com/repos/oven-sh/bun/releases";

/// Bun version info
#[derive(Debug, Clone)]
pub(crate) struct BunVersion {
    pub(crate) version: String,
    pub(crate) prerelease: bool,
}

pub(crate) struct BunManager {
    versions_dir: PathBuf,
    client: &'static reqwest::Client,
}

impl BunManager {
    pub fn new() -> Self {
        Self {
            versions_dir: super::DATA_DIR.join("versions/bun"),
            client: download_client(),
        }
    }

    /// List available Bun versions from GitHub releases
    pub async fn list_available(&self) -> Result<Vec<BunVersion>> {
        let releases: Vec<GithubRelease> = self
            .client
            .get(format!("{BUN_API_URL}?per_page=20"))
            .header("User-Agent", GITHUB_USER_AGENT)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .context("Failed to fetch Bun releases from GitHub")?
            .error_for_status()
            .context("Bun releases request failed")?
            .bounded_json()
            .await
            .context("Failed to parse Bun release data")?;

        Ok(parse_bun_versions(releases))
    }

    /// Resolve Bun alias (latest) to a concrete version
    pub async fn resolve_alias(&self, alias: &str) -> Result<String> {
        let alias = normalize_version(alias);
        if alias == "latest" {
            let versions = self.list_available().await?;
            pick_latest_stable(versions).context("No Bun versions found upstream")
        } else {
            Ok(alias)
        }
    }

    /// Install Bun - PURE RUST, NO SUBPROCESS
    pub async fn install(&self, version: &str) -> Result<()> {
        let version = self.resolve_alias(version).await?;
        let version = self.resolve_requested_version(&version).await?;
        crate::core::security::validate_runtime_version(&version)?;
        let version_dir = self.versions_dir.join(&version);

        if crate::runtimes::common::is_valid_version_dir(&version_dir) {
            print_already_installed("Bun", &version);
            return self.use_version(&version);
        }

        println!(
            "{} Installing Bun {}...\n",
            style::runtime("OMG"),
            style::caution(&version)
        );

        let filename = format!("bun-{}.zip", bun_platform()?);
        let url = format!("{BUN_RELEASES_URL}/bun-v{version}/{filename}");
        let checksum = self.fetch_checksum(&version, &filename).await?;

        fs::create_dir_all(&self.versions_dir)?;

        println!(
            "{} Downloading Bun v{}...",
            style::informative("→"),
            version
        );
        let download = begin_download(&self.versions_dir)?;
        let download_path = download.path().join(&filename);
        download_with_progress(self.client, &url, &download_path, &checksum).await?;

        println!("{} Extracting (pure Rust)...", style::informative("→"));
        let staging = begin_staged_install(&self.versions_dir)?;
        extract_zip(&download_path, staging.path(), 1).await?;
        complete_staged_install(&staging, &version_dir, &version)?;

        print_installed("Bun", &version);
        self.use_version(&version)?;

        Ok(())
    }

    /// Resolve a partial version request (`1`, `1.0`) to the newest matching
    /// stable Bun release before any download URL is built; the release-tag
    /// lookup is exact-string, so an unresolved partial would 404. Like
    /// `latest`, partial resolution never picks a prerelease. Exact and
    /// non-numeric requests pass through unchanged, preserving the
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

    async fn fetch_checksum(&self, version: &str, filename: &str) -> Result<String> {
        let release: GithubRelease = self
            .client
            .get(format!("{BUN_API_URL}/tags/bun-v{version}"))
            .header("User-Agent", GITHUB_USER_AGENT)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .context("Failed to fetch Bun release metadata")?
            .error_for_status()
            .context("Bun release metadata request failed")?
            .bounded_json()
            .await
            .context("Failed to parse Bun release metadata")?;

        let asset = release
            .assets
            .iter()
            .find(|asset| asset.name == filename)
            .ok_or_else(|| anyhow::anyhow!("Bun release asset not found: {filename}"))?;
        let digest = asset.digest.as_deref().ok_or_else(|| {
            anyhow::anyhow!("Bun release asset has no SHA-256 digest: {filename}")
        })?;
        parse_sha256_digest(digest, "GitHub Bun release")
    }

    /// Switch to a specific version
    pub fn use_version(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        activate_version(&self.versions_dir, &version, Path::new("bun"))?;
        print_using("Bun", &version, &self.versions_dir.join("current"));
        Ok(())
    }

    /// Remove an installed version. Refuses the active version.
    pub fn uninstall(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        super::common::uninstall_version(&self.versions_dir, &version)
    }
}

// Generate common runtime manager methods (list_installed, current_version)
crate::runtimes::common::impl_runtime_common!(BunManager);

/// Parse GitHub releases into deterministic newest-first Bun versions.
fn parse_bun_versions(releases: Vec<GithubRelease>) -> Vec<BunVersion> {
    let mut versions: Vec<BunVersion> = releases
        .into_iter()
        .filter_map(|r| {
            // Tags are like "bun-v1.0.0"
            let version = r
                .tag_name
                .strip_prefix("bun-v")
                .or_else(|| r.tag_name.strip_prefix('v'))
                .unwrap_or(&r.tag_name);

            (!version.is_empty()).then(|| BunVersion {
                version: version.to_owned(),
                prerelease: r.prerelease,
            })
        })
        .collect();
    // The GitHub API orders rows by creation date, not by version; sort so
    // "latest" and listing output are deterministic.
    versions.sort_by(|a, b| version_cmp(&b.version, &a.version));
    versions
}

/// Pick the newest non-prerelease version, so `latest` never pins an RC.
fn pick_latest_stable(versions: Vec<BunVersion>) -> Option<String> {
    versions
        .into_iter()
        .find(|version| !version.prerelease)
        .map(|version| version.version)
}

/// Flatten Bun releases into stable version numbers for partial resolution.
fn available_version_names(versions: &[BunVersion]) -> Vec<String> {
    versions
        .iter()
        .filter(|version| !version.prerelease)
        .map(|version| version.version.clone())
        .collect()
}

fn bun_platform() -> Result<String> {
    let os = super::common::host_os_tag("Bun", "linux", "darwin")?;
    let arch = super::common::host_arch_tag("Bun", "x64", "aarch64")?;
    Ok(format!("{os}-{arch}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn incomplete_bun_archive_is_not_published_and_can_be_retried() -> Result<()> {
        check_archive_publication(super::super::test_archive::Launcher::Missing).await
    }

    #[tokio::test]
    async fn directory_bun_launcher_is_not_published_and_can_be_retried() -> Result<()> {
        check_archive_publication(super::super::test_archive::Launcher::Directory).await
    }

    async fn check_archive_publication(
        invalid: super::super::test_archive::Launcher,
    ) -> Result<()> {
        use super::super::test_archive::{Launcher, zip};
        use sha2::{Digest as _, Sha256};
        let root = format!("bun-{}", bun_platform()?);
        let filename = format!("{root}.zip");
        let manifest_path = "/repos/oven-sh/bun/releases/tags/bun-v1.4.0";
        let archive_path = format!("/oven-sh/bun/releases/download/bun-v1.4.0/{filename}");
        let mut routes = Vec::new();
        for kind in [invalid, Launcher::Regular] {
            let archive = zip(&root, "bun", kind)?;
            let manifest = serde_json::json!({
                "tag_name": "bun-v1.4.0", "prerelease": false,
                "assets": [{"name": filename,
                    "browser_download_url": format!("https://github.com{archive_path}"),
                    "digest": format!("sha256:{:x}", Sha256::digest(&archive))}]
            });
            routes.push((
                "api.github.com".to_owned(),
                manifest_path.to_owned(),
                serde_json::to_vec(&manifest)?,
            ));
            routes.push(("github.com".to_owned(), archive_path.clone(), archive));
        }
        let fixture = super::super::test_https::HttpsFixture::new_for_authorities(routes).await?;
        let versions = tempfile::tempdir()?;
        let manager = BunManager {
            versions_dir: versions.path().to_path_buf(),
            client: Box::leak(Box::new(fixture.client(true)?)),
        };
        manager
            .install("1.4.0")
            .await
            .expect_err("incomplete launcher refusal");
        assert!(
            !versions.path().join("1.4.0").exists(),
            "invalid Bun archive must not be published"
        );
        assert!(manager.list_installed()?.is_empty());
        assert!(!versions.path().join("current").exists());
        assert_eq!(manager.current_version(), None);
        manager.install("1.4.0").await?;
        assert_eq!(manager.list_installed()?, vec!["1.4.0"]);
        assert_eq!(manager.current_version().as_deref(), Some("1.4.0"));
        assert_eq!(
            fs::read(versions.path().join("current/bun"))?,
            b"fixture launcher"
        );
        assert_eq!(
            fixture.finish().await?,
            vec![
                format!("GET {manifest_path} HTTP/1.1"),
                format!("GET {archive_path} HTTP/1.1"),
                format!("GET {manifest_path} HTTP/1.1"),
                format!("GET {archive_path} HTTP/1.1"),
            ]
        );
        Ok(())
    }

    #[test]
    fn test_bun_manager_new() {
        let mgr = BunManager::new();
        assert!(mgr.versions_dir.ends_with("bun"));
    }

    #[test]
    fn partial_request_resolves_to_the_newest_stable_bun_fixture() {
        let fixtures = [
            ver("1.2.0", true),
            ver("1.0.18", false),
            ver("1.0.4", false),
            ver("0.8.0", false),
        ];
        let names = available_version_names(&fixtures);
        // Prereleases never participate in partial resolution.
        assert_eq!(
            crate::runtimes::common::resolve_partial_version(&names, "1.0").as_deref(),
            Some("1.0.18")
        );
        assert_eq!(
            crate::runtimes::common::resolve_partial_version(&names, "1").as_deref(),
            Some("1.0.18")
        );
        assert_eq!(
            crate::runtimes::common::resolve_partial_version(&names, "0").as_deref(),
            Some("0.8.0")
        );
        assert_eq!(
            crate::runtimes::common::resolve_partial_version(&names, "2"),
            None
        );
    }

    #[test]
    fn bun_platform_is_host_specific() {
        let platform = bun_platform().expect("host platform should be supported");
        if std::env::consts::OS == "linux" {
            assert!(platform.starts_with("linux-"));
        } else {
            assert!(!platform.starts_with("linux-"));
        }
    }

    fn ver(version: &str, prerelease: bool) -> BunVersion {
        BunVersion {
            version: version.to_string(),
            prerelease,
        }
    }

    fn release(tag: &str, prerelease: bool) -> GithubRelease {
        GithubRelease {
            tag_name: tag.to_string(),
            prerelease,
            assets: Vec::new(),
        }
    }

    #[test]
    fn bun_versions_are_sorted_newest_first() {
        let versions = parse_bun_versions(vec![
            release("bun-v1.1.5", false),
            release("bun-v1.0.0", false),
            release("bun-v1.2.0", true),
            release("bun-v1.1.18", false),
        ]);

        let names: Vec<&str> = versions.iter().map(|v| v.version.as_str()).collect();
        assert_eq!(names, vec!["1.2.0", "1.1.18", "1.1.5", "1.0.0"]);
    }

    #[test]
    fn latest_alias_never_picks_a_prerelease() {
        let versions = parse_bun_versions(vec![
            release("bun-v1.2.0", true),
            release("bun-v1.1.5", false),
            release("bun-v1.0.0", false),
        ]);

        assert_eq!(pick_latest_stable(versions), Some("1.1.5".to_string()));
        assert_eq!(pick_latest_stable(Vec::new()), None);
        assert_eq!(pick_latest_stable(vec![ver("1.2.0-rc.1", true)]), None);
    }
}
