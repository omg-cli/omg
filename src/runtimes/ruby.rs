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
    security: super::security::RuntimeSecurity,
    versions_dir: PathBuf,
    client: &'static reqwest::Client,
}

impl RubyManager {
    pub fn new() -> Self {
        Self {
            security: super::security::RuntimeSecurity::default(),
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
        self.publish_download(&download_path, download_url, &version)
            .await?;

        print_installed("Ruby", &version);
        self.use_version(&version)?;

        Ok(())
    }

    async fn publish_download(&self, download_path: &Path, url: &str, version: &str) -> Result<()> {
        let version_dir = self.versions_dir.join(version);
        let publisher =
            super::security::record_download("ruby", version, &version_dir, download_path, url)?;
        let staging = begin_staged_install(&self.versions_dir)?;
        extract_tar_gz(download_path, staging.path(), 1).await?;
        self.publish_install(&staging, version)?;
        publisher.commit();
        Ok(())
    }

    fn publish_install(&self, staging: &tempfile::TempDir, version: &str) -> Result<()> {
        super::common::require_regular_file(&staging.path().join("bin/ruby"))?;
        let _admission = self.security.prepare_staged(
            "ruby",
            version,
            staging.path(),
            &self.versions_dir.join(version),
        )?;
        complete_staged_install(staging, &self.versions_dir.join(version), version)
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
        crate::core::security::validate_runtime_version(&version)?;
        super::common::require_regular_file(&self.versions_dir.join(&version).join("bin/ruby"))?;
        let admission = self.security.installed(
            "ruby",
            &self.versions_dir.join(&version),
            super::security::ReviewMode::FreshAttended,
        )?;
        admission.verify(&self.versions_dir.join(&version))?;
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
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires the isolated fixed-public TLS native fixture"]
    async fn native_public_install_preserves_authenticated_download_boundary() {
        use super::super::test_archive::{PublicationFixture, tar_gz_entries};
        use sha2::{Digest as _, Sha256};

        let version = "3.4.2";
        let archive = tar_gz_entries(
            "ruby",
            &[
                ("bin/ruby", b"fixture launcher"),
                ("lib/owned.data", b"complete Ruby implementation"),
            ],
        )
        .unwrap();
        let arch = [("x86_64", "x64"), ("aarch64", "arm64")]
            .into_iter()
            .find(|(host, _)| *host == std::env::consts::ARCH)
            .expect("supported native fixture architecture")
            .1;
        let filename = format!("ruby-{version}-{}-{arch}.tar.gz", ruby_platform().unwrap());
        let path = format!("/ruby/ruby-builder/releases/download/ruby-{version}/{filename}");
        let metadata = serde_json::to_vec(&serde_json::json!({
            "tag_name":format!("ruby-{version}"), "prerelease":false,
            "assets":[{"name":filename,"browser_download_url":format!("https://github.com{path}"),"digest":format!("sha256:{}",hex::encode(Sha256::digest(&archive)))}]
        })).unwrap();
        super::super::test_https::fixed_public_routes(&[
            (
                "api.github.com",
                "/repos/ruby/ruby-builder/releases/tags/ruby-3.4.2",
                &metadata,
            ),
            ("github.com", &path, &archive),
        ]);

        let fixture = PublicationFixture::new("ruby", "bin/ruby");
        let manager = RubyManager {
            security: super::super::security::RuntimeSecurity::fixture(),
            versions_dir: fixture.versions.clone(),
            client: download_client(),
        };
        manager
            .install(version)
            .await
            .expect("complete authenticated public installation");
        let installed = fixture.versions.join(version);
        assert_eq!(
            fs::read(fixture.versions.join("current").join("bin/ruby")).unwrap(),
            b"fixture launcher"
        );
        assert_eq!(
            fs::read(installed.join("lib/owned.data")).unwrap(),
            b"complete Ruby implementation"
        );
        assert_eq!(
            fs::read(fixture.versions.join("1.0.0/bin/ruby")).unwrap(),
            b"previous reviewed runtime"
        );
        super::super::security::admit_installed(
            "ruby",
            &installed,
            super::super::security::ReviewMode::CachedOnly,
        )
        .expect("retain exact authenticated publisher authority")
        .verify(&installed)
        .expect("complete published tree matches its admission");
    }

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
        let versions = tempfile::tempdir()?;
        let manager = RubyManager {
            security: crate::runtimes::security::RuntimeSecurity::fixture(),
            versions_dir: versions.path().to_path_buf(),
            client: download_client(),
        };
        let downloads = tempfile::tempdir()?;
        let archive_path = downloads.path().join("runtime.tar.gz");
        let staging = begin_staged_install(versions.path())?;
        fs::write(&archive_path, tar_gz("runtime", "bin/ruby", invalid)?)?;
        extract_tar_gz(&archive_path, staging.path(), 1).await?;
        let result = manager.publish_install(&staging, "3.4.10");
        assert!(
            !versions.path().join("3.4.10").exists(),
            "invalid ruby archive must not be published: {result:?}"
        );
        assert!(result.is_err(), "invalid launcher must be refused");
        assert!(manager.list_installed()?.is_empty());
        assert!(!versions.path().join("current").exists());
        assert_eq!(manager.current_version(), None);
        drop(staging);

        let staging = begin_staged_install(versions.path())?;
        fs::write(
            &archive_path,
            tar_gz("runtime", "bin/ruby", Launcher::Regular)?,
        )?;
        extract_tar_gz(&archive_path, staging.path(), 1).await?;
        crate::runtimes::security::fixture_bind_candidate(
            "ruby",
            "3.4.10",
            staging.path(),
            &manager.versions_dir.join("3.4.10"),
        )
        .expect("seed controlled publisher authority");
        manager.publish_install(&staging, "3.4.10")?;
        crate::runtimes::security::fixture_bind_candidate(
            "ruby",
            "3.4.10",
            &manager.versions_dir.join("3.4.10"),
            &manager.versions_dir.join("3.4.10"),
        )
        .expect("seed controlled publisher authority");
        manager.use_version("3.4.10")?;
        assert_eq!(manager.list_installed()?, vec!["3.4.10"]);
        assert_eq!(manager.current_version().as_deref(), Some("3.4.10"));
        assert_eq!(
            fs::read(versions.path().join("current/bin/ruby"))?,
            b"fixture launcher"
        );
        Ok(())
    }

    #[test]
    fn test_ruby_manager_new() -> Result<()> {
        #[cfg(not(debug_assertions))]
        if crate::core::is_root() {
            let mgr = RubyManager::new();
            assert_eq!(
                mgr.versions_dir,
                std::path::PathBuf::from("/var/lib/omg/versions/ruby")
            );
            return Ok(());
        }

        super::super::common::assert_constructor_inventory(
            "ruby",
            "runtimes::ruby::tests::test_ruby_manager_new",
            || {
                let mgr = RubyManager::new();
                assert!(mgr.versions_dir.ends_with("ruby"));
                Ok((mgr.list_installed()?, mgr.current_version()))
            },
        )
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
        const EXPECTED: Option<&str> = if cfg!(target_os = "linux") {
            Some("ubuntu-22.04")
        } else if cfg!(target_os = "macos") {
            Some("darwin")
        } else {
            None
        };
        let platform = ruby_platform().expect("host platform should be supported");
        let expected = EXPECTED.expect("unsupported test host");
        assert_eq!(platform, expected);
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn downloaded_publication_preserves_prior_authority_and_rejects_changed_reviewed_content()
    {
        use super::super::test_archive::{Launcher, tar_gz};
        use super::super::test_archive::{PublicationFixture, mutation_security};
        let fixture = PublicationFixture::new("ruby", "bin/ruby");
        let mut manager = RubyManager {
            security: super::super::security::RuntimeSecurity::fixture(),
            versions_dir: fixture.versions.clone(),
            client: download_client(),
        };
        let url = "https://github.com/ruby/ruby-builder/releases/download/ruby-3.4.2/ruby.tar.gz";
        assert!(
            manager
                .publish_download(&fixture.archive, url, "3.4.2")
                .await
                .is_err()
        );
        fixture.assert_previous();
        fixture.write(b"not an archive");
        assert!(
            manager
                .publish_download(&fixture.archive, url, "3.4.2")
                .await
                .is_err()
        );
        fixture.assert_previous();
        let bytes =
            tar_gz("runtime", "bin/ruby", Launcher::Regular).expect("controlled publisher archive");
        fixture.write(&bytes);
        manager.security = mutation_security(&fixture.versions);
        let error = manager
            .publish_download(&fixture.archive, url, "3.4.2")
            .await
            .expect_err("changed reviewed payload must not publish");
        assert!(
            format!("{error:#}").contains("Runtime content changed after advisory review"),
            "{error:#}"
        );
        assert!(!fixture.versions.join("3.4.2").exists());
        fixture.assert_previous();
        manager.security = super::super::security::RuntimeSecurity::fixture();
        manager
            .publish_download(&fixture.archive, url, "3.4.2")
            .await
            .expect("publish complete reviewed publisher tree");
        fixture.assert_previous();
        manager
            .use_version("3.4.2")
            .expect("activate admitted publisher tree");
        assert_eq!(
            fs::read(fixture.versions.join("current/bin/ruby"))
                .expect("selected reviewed launcher"),
            b"fixture launcher"
        );
        fs::remove_file(fixture.versions.join("current"))
            .expect("restore controlled prior selection");
        std::os::unix::fs::symlink("1.0.0", fixture.versions.join("current"))
            .expect("restore prior selection");
        fixture.corrupt_identity("3.4.2");
        assert!(manager.use_version("3.4.2").is_err());
        fixture.assert_previous();
    }
}
