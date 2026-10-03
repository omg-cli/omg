//! Native Ruby runtime manager - PURE RUST
//!
//! Downloads pre-built Ruby binaries from ruby-builder.
//!
//! Features:
//! - Pre-built binaries (no compilation required)
//! - Compatible with Ubuntu/Debian glibc

use crate::core::http::BoundedResponseExt;
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use super::common::{
    GITHUB_USER_AGENT, GithubRelease, activate_version, begin_download, begin_staged_install,
    complete_staged_install, download_with_progress, extract_tar_gz, normalize_version,
    parse_sha256_digest, print_already_installed, print_installed, print_using,
    validate_download_filename, version_cmp,
};
use crate::{cli::style, core::http::download_client};

const RUBY_VERSIONS_URL: &str = "https://api.github.com/repos/ruby/ruby-builder/releases";

/// Ruby version info
#[derive(Debug, Clone)]
pub(crate) struct RubyVersion {
    pub version: String,
}

pub(crate) struct RubyManager {
    versions_dir: PathBuf,
    client: &'static reqwest::Client,
}

impl RubyManager {
    pub fn new() -> Self {
        Self {
            versions_dir: super::DATA_DIR.join("versions/ruby"),
            client: download_client(),
        }
    }

    /// List available Ruby versions from ruby-builder releases
    pub async fn list_available(&self) -> Result<Vec<RubyVersion>> {
        let releases: Vec<GithubRelease> = self
            .client
            .get(format!("{RUBY_VERSIONS_URL}?per_page=100"))
            .header("User-Agent", GITHUB_USER_AGENT)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .context("Failed to fetch Ruby releases from GitHub")?
            .error_for_status()
            .context("GitHub Ruby release-list request failed")?
            .bounded_json()
            .await
            .context("Failed to parse Ruby release data")?;

        // Tags are `ruby-X.Y.Z`, plus engine tags such as `jruby-*` and `toolcache`.
        let versions: std::collections::HashSet<_> = releases
            .iter()
            .filter_map(|release| parse_ruby_release_version(&release.tag_name))
            .collect();
        if versions.is_empty() {
            anyhow::bail!("No MRI Ruby releases found. Try again later or specify a version.");
        }

        let mut result: Vec<_> = versions
            .into_iter()
            .map(|version| RubyVersion { version })
            .collect();

        result.sort_by(|a, b| version_cmp(&b.version, &a.version));
        Ok(result)
    }

    /// Install Ruby - PURE RUST, NO SUBPROCESS
    pub async fn install(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        let version = self.resolve_requested_version(&version).await?;
        crate::core::security::validate_runtime_version(&version)?;
        let version_dir = self.versions_dir.join(&version);

        if crate::runtimes::common::is_valid_version_dir(&version_dir) {
            print_already_installed("Ruby", &version);
            return self.use_version(&version);
        }

        println!(
            "{} Installing Ruby {}...\n",
            style::runtime("OMG"),
            style::caution(&version)
        );

        // Use the release-specific, pre-built Ruby from GitHub ruby-builder.
        let arch = match std::env::consts::ARCH {
            "x86_64" => "x64",
            "aarch64" => "arm64",
            arch => anyhow::bail!("Unsupported architecture: {arch}"),
        };
        let release: GithubRelease = self
            .client
            .get(format!("{RUBY_VERSIONS_URL}/tags/ruby-{version}"))
            .header("User-Agent", GITHUB_USER_AGENT)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .context("Failed to fetch Ruby release metadata")?
            .error_for_status()
            .with_context(|| format!("Ruby {version} release metadata was not found"))?
            .bounded_json()
            .await
            .context("Failed to parse Ruby release metadata")?;
        let expected_name = format!("ruby-{version}-{}-{arch}.tar.gz", ruby_platform()?);
        let asset = release
            .assets
            .iter()
            .find(|asset| asset.name == expected_name)
            .ok_or_else(|| anyhow::anyhow!("Ruby release asset not found: {expected_name}"))?;
        let checksum = asset
            .digest
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Ruby release asset has no SHA-256 digest"))
            .and_then(|digest| parse_sha256_digest(digest, "GitHub Ruby release"))?;

        fs::create_dir_all(&self.versions_dir)?;

        println!(
            "{} Downloading pre-built Ruby {version}...",
            style::informative("→")
        );
        let archive_name = validate_download_filename(&asset.name)?;
        let download = begin_download(&self.versions_dir)?;
        let download_path = download.path().join(archive_name);

        let download_url = asset
            .browser_download_url
            .as_deref()
            .context("Ruby release asset has no browser download URL")?;
        download_with_progress(self.client, download_url, &download_path, &checksum)
            .await
            .with_context(|| {
                eprintln!(
                    "{} Pre-built Ruby {version} not available",
                    style::caution("!")
                );
                eprintln!("  Try: omg list ruby --available");
                format!("Failed to download Ruby {version}")
            })?;

        println!("{} Extracting (pure Rust)...", style::informative("→"));
        let staging = begin_staged_install(&self.versions_dir)?;
        extract_tar_gz(&download_path, staging.path(), 1).await?;
        complete_staged_install(&staging, &version_dir, &version)?;

        print_installed("Ruby", &version);
        self.use_version(&version)?;

        Ok(())
    }

    /// Resolve a partial version request (`3`, `3.2`) to the newest matching
    /// ruby-builder release before any download URL is built; the tag lookup
    /// is exact-string, so an unresolved partial would 404. Exact and
    /// non-numeric requests pass through unchanged, preserving the
    /// already-installed fast path and the existing not-found UX.
    async fn resolve_requested_version(&self, version: &str) -> Result<String> {
        if !crate::runtimes::common::is_partial_version(version) {
            return Ok(version.to_owned());
        }
        let available = self.list_available().await?;
        let names: Vec<String> = available.into_iter().map(|entry| entry.version).collect();
        Ok(crate::runtimes::resolve_version_request(&names, version))
    }

    /// Switch to a specific version
    pub fn use_version(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        activate_version(&self.versions_dir, &version, Path::new("bin/ruby"))?;
        print_using("Ruby", &version, &self.versions_dir.join("current/bin"));
        Ok(())
    }

    /// Remove an installed version. Refuses the active version.
    pub fn uninstall(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        super::common::uninstall_version(&self.versions_dir, &version)
    }
}

// Generate common runtime manager methods (list_installed, current_version)
crate::runtimes::common::impl_runtime_common!(RubyManager);

fn parse_ruby_release_version(tag_name: &str) -> Option<String> {
    tag_name
        .strip_prefix("ruby-")
        .filter(|version| {
            let mut parts = version.split('.');
            match (parts.next(), parts.next(), parts.next(), parts.next()) {
                (Some(major), Some(minor), Some(patch), None) => [major, minor, patch]
                    .iter()
                    .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit())),
                _ => false,
            }
        })
        .map(str::to_owned)
}

fn ruby_platform() -> Result<&'static str> {
    match std::env::consts::OS {
        "linux" => Ok("ubuntu-22.04"),
        "macos" => Ok("darwin"),
        other => anyhow::bail!("Unsupported operating system for pre-built Ruby: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn incomplete_ruby_archive_is_not_published_and_can_be_retried() -> Result<()> {
        check_archive_publication(super::super::test_archive::Launcher::Missing).await
    }

    #[tokio::test]
    async fn directory_ruby_launcher_is_not_published_and_can_be_retried() -> Result<()> {
        check_archive_publication(super::super::test_archive::Launcher::Directory).await
    }

    async fn check_archive_publication(
        invalid: super::super::test_archive::Launcher,
    ) -> Result<()> {
        use super::super::test_archive::{Launcher, tar_gz};
        use sha2::{Digest as _, Sha256};
        let arch = match std::env::consts::ARCH {
            "x86_64" => "x64",
            "aarch64" => "arm64",
            other => anyhow::bail!("unsupported fixture architecture: {other}"),
        };
        let filename = format!("ruby-3.4.10-{}-{arch}.tar.gz", ruby_platform()?);
        let manifest_path = "/repos/ruby/ruby-builder/releases/tags/ruby-3.4.10";
        let archive_path = format!("/fixture/{filename}");
        let mut routes = Vec::new();
        for kind in [invalid, Launcher::Regular] {
            let archive = tar_gz("ruby", "bin/ruby", kind)?;
            let manifest = serde_json::json!({
                "tag_name": "ruby-3.4.10", "prerelease": false,
                "assets": [{"name": filename,
                    "browser_download_url": format!("https://api.github.com{archive_path}"),
                    "digest": format!("sha256:{:x}", Sha256::digest(&archive))}]
            });
            routes.push((manifest_path.to_owned(), serde_json::to_vec(&manifest)?));
            routes.push((archive_path.clone(), archive));
        }
        let fixture = super::super::test_https::HttpsFixture::new("api.github.com", routes).await?;
        let versions = tempfile::tempdir()?;
        let manager = RubyManager {
            versions_dir: versions.path().to_path_buf(),
            client: Box::leak(Box::new(fixture.client(true)?)),
        };
        manager
            .install("3.4.10")
            .await
            .expect_err("incomplete launcher refusal");
        assert!(
            !versions.path().join("3.4.10").exists(),
            "invalid Ruby archive must not be published"
        );
        assert!(manager.list_installed()?.is_empty());
        assert!(!versions.path().join("current").exists());
        assert_eq!(manager.current_version(), None);
        manager.install("3.4.10").await?;
        assert_eq!(manager.list_installed()?, vec!["3.4.10"]);
        assert_eq!(manager.current_version().as_deref(), Some("3.4.10"));
        assert_eq!(
            fs::read(versions.path().join("current/bin/ruby"))?,
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
    fn test_ruby_manager_new() {
        let mgr = RubyManager::new();
        assert!(mgr.versions_dir.ends_with("ruby"));
    }

    #[test]
    fn ruby_release_tags_parse_mri_versions_only() {
        assert_eq!(
            parse_ruby_release_version("ruby-3.4.10").as_deref(),
            Some("3.4.10")
        );
        assert_eq!(parse_ruby_release_version("3.4.10"), None);
        assert_eq!(parse_ruby_release_version("toolcache"), None);
        assert_eq!(parse_ruby_release_version("jruby-10.0.6.0"), None);
        assert_eq!(parse_ruby_release_version("ruby-3.4"), None);
    }

    #[test]
    fn partial_request_resolves_to_the_newest_matching_ruby_fixture() {
        let names = ["3.4.10", "3.2.2", "3.2.0"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            crate::runtimes::common::resolve_partial_version(&names, "3.2").as_deref(),
            Some("3.2.2")
        );
        assert_eq!(
            crate::runtimes::common::resolve_partial_version(&names, "3").as_deref(),
            Some("3.4.10")
        );
        assert_eq!(
            crate::runtimes::common::resolve_partial_version(&names, "2.7"),
            None
        );
    }

    #[test]
    fn ruby_platform_is_host_specific() {
        let platform = ruby_platform().expect("host platform should be supported");
        if std::env::consts::OS == "linux" {
            assert_eq!(platform, "ubuntu-22.04");
        } else {
            assert_ne!(platform, "ubuntu-22.04");
        }
    }
}
