//! Native Ruby runtime manager for ruby-builder releases.
//!
//! Rust selects the archive, verifies its checksum and stages its contents.
//! A bounded version probe must succeed before the staged runtime is published.

use anyhow::{Context, Result};
#[cfg(test)]
use std::fs;
use std::path::{Path, PathBuf};

use super::common::{
    GithubRelease, activate_version, begin_download, begin_staged_install, complete_staged_install,
    download_with_progress, extract_tar_gz, fetch_github_release_json, normalize_version,
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

    async fn release_catalog(&self) -> Result<Vec<GithubRelease>> {
        fetch_github_release_json(self.client, &format!("{RUBY_VERSIONS_URL}?per_page=100"))
            .await
            .context("Failed to fetch Ruby releases from GitHub")
    }

    /// List available Ruby versions from ruby-builder releases.
    pub async fn list_available(&self) -> Result<Vec<RubyVersion>> {
        let releases = self.release_catalog().await?;
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

        result.sort_by(|a, b| {
            version_cmp(&b.version, &a.version).then_with(|| a.version.cmp(&b.version))
        });
        Ok(result)
    }

    /// Install Ruby from a checksummed publisher release.
    pub async fn install(&self, version: &str) -> Result<()> {
        let requested = normalize_version(version);
        crate::core::security::validate_runtime_version(&requested)?;
        let (version, catalog) = if requested == "latest"
            || super::common::is_partial_version(&requested)
        {
            let releases = self.release_catalog().await?;
            let version = if requested == "latest" {
                releases
                    .iter()
                    .filter(|release| !release.prerelease)
                    .filter_map(|release| parse_ruby_release_version(&release.tag_name))
                    .max_by(|left, right| version_cmp(left, right).then_with(|| right.cmp(left)))
                    .context("No stable MRI Ruby releases found in the publisher catalog")?
            } else {
                let names: Vec<_> = releases
                    .iter()
                    .filter_map(|release| parse_ruby_release_version(&release.tag_name))
                    .collect();
                anyhow::ensure!(
                    !names.is_empty(),
                    "No MRI Ruby releases found. Try again later or specify a version."
                );
                super::resolve_version_request(&names, &requested)
            };
            (version, Some(releases))
        } else {
            (requested, None)
        };
        crate::core::security::validate_runtime_version(&version)?;
        let _install_lease = super::common::try_lock_runtime_install(&self.versions_dir, &version)?;
        let version_dir = self.versions_dir.join(&version);

        if crate::runtimes::common::is_valid_version_dir(&version_dir) {
            print_already_installed("Ruby", &version);
            return self.use_version(&version);
        }
        super::common::require_unoccupied_install_destination(&version_dir)?;

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
        let expected_name = format!("ruby-{version}-{}-{arch}.tar.gz", ruby_platform()?);
        let tag = format!("ruby-{version}");
        let release: GithubRelease = if let Some(catalog) = catalog {
            catalog
                .into_iter()
                .find(|release| release.tag_name == tag)
                .with_context(|| format!("Ruby {version} release metadata was not found"))?
        } else {
            fetch_github_release_json(self.client, &format!("{RUBY_VERSIONS_URL}/tags/{tag}"))
                .await
                .with_context(|| format!("Failed to fetch Ruby {version} release metadata"))?
        };
        anyhow::ensure!(
            release.tag_name == tag,
            "GitHub release tag {} does not match requested Ruby tag {tag}",
            release.tag_name
        );
        let mut matching = release
            .assets
            .iter()
            .filter(|asset| asset.name == expected_name);
        let asset = matching
            .next()
            .with_context(|| format!("Ruby release asset not found: {expected_name}"))?;
        anyhow::ensure!(
            matching.next().is_none(),
            "GitHub release lists multiple matching Ruby assets named {expected_name}"
        );
        let checksum = asset
            .digest
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Ruby release asset has no SHA-256 digest"))
            .and_then(|digest| parse_sha256_digest(digest, "GitHub Ruby release"))?;

        let download_url = asset
            .browser_download_url
            .as_deref()
            .context("Ruby release asset has no browser download URL")?;
        println!(
            "{} Downloading pre-built Ruby {version}...",
            style::informative("→")
        );
        let archive_name = validate_download_filename(&asset.name)?;
        let download = begin_download(&self.versions_dir)?;
        let download_path = download.path().join(archive_name);

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
        self.publish_install(&staging, version).await?;
        publisher.commit();
        Ok(())
    }

    async fn publish_install(&self, staging: &tempfile::TempDir, version: &str) -> Result<()> {
        super::common::require_regular_file(&staging.path().join("bin/ruby"))?;
        let version_dir = self.versions_dir.join(version);
        let admission =
            self.security
                .prepare_staged("ruby", version, staging.path(), &version_dir)?;
        admission.before_execution(staging.path())?;
        let tree = staging.path().to_path_buf();
        tokio::task::spawn_blocking(move || {
            let mut command = std::process::Command::new(tree.join("bin/ruby"));
            super::common::harden_untrusted_runtime_command(&mut command, &tree);
            command.args(["--disable=gems", "--version"]);
            super::tool_artifacts::run_with_timeout(
                command,
                "Ruby smoke test",
                std::time::Duration::from_secs(30),
            )
        })
        .await
        .context("Ruby smoke test worker stopped")??;
        complete_staged_install(staging, &version_dir, version)
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
        let launcher = b"#!/bin/sh\nprintf 'ruby 3.4.2\\n'\n";
        let archive = tar_gz_entries(
            "ruby",
            &[
                ("bin/ruby", launcher),
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
        let metadata = serde_json::to_vec(&serde_json::json!([{
            "tag_name":format!("ruby-{version}"), "prerelease":false,
            "assets":[{"name":filename,"browser_download_url":format!("https://github.com{path}"),"digest":format!("sha256:{}",hex::encode(Sha256::digest(&archive)))}]
        }])).unwrap();
        super::super::test_https::fixed_public_routes(&[
            (
                "api.github.com",
                "/repos/ruby/ruby-builder/releases?per_page=100",
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
            .install("3.4")
            .await
            .expect("complete authenticated installation using one catalog request");
        let installed = fixture.versions.join(version);
        assert_eq!(
            fs::read(fixture.versions.join("current").join("bin/ruby")).unwrap(),
            launcher
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
        use super::super::test_archive::tar_gz;
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
        let result = manager.publish_install(&staging, "3.4.10").await;
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
        let launcher = b"#!/bin/sh\nprintf 'ruby 3.4.10\\n'\n";
        fs::write(
            &archive_path,
            super::super::test_archive::tar_gz_entries("runtime", &[("bin/ruby", launcher)])?,
        )?;
        extract_tar_gz(&archive_path, staging.path(), 1).await?;
        crate::runtimes::security::fixture_bind_candidate(
            "ruby",
            "3.4.10",
            staging.path(),
            &manager.versions_dir.join("3.4.10"),
        )
        .expect("seed controlled publisher authority");
        manager.publish_install(&staging, "3.4.10").await?;
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
            launcher
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn direct_install_requires_complete_metadata_for_the_exact_tag() -> Result<()> {
        let path = "/repos/ruby/ruby-builder/releases/tags/ruby-3.4.2";
        let arch = match std::env::consts::ARCH {
            "x86_64" => "x64",
            "aarch64" => "arm64",
            other => anyhow::bail!("Unsupported native Ruby test architecture: {other}"),
        };
        let asset = serde_json::json!({
            "name": format!("ruby-3.4.2-ubuntu-22.04-{arch}.tar.gz"),
            "digest": format!("sha256:{}", "c".repeat(64))
        });
        let payload = |tag, assets| {
            serde_json::to_vec(&serde_json::json!({
                "tag_name": tag,
                "assets": assets
            }))
        };
        let fixture = super::super::test_https::HttpsFixture::new_with_statuses(
            "api.github.com",
            vec![
                (path.to_owned(), 206, payload("ruby-3.4.2", vec![&asset])?),
                (path.to_owned(), 200, payload("ruby-3.4.3", vec![&asset])?),
                (
                    path.to_owned(),
                    200,
                    payload("ruby-3.4.2", vec![&asset, &asset])?,
                ),
            ],
        )
        .await?;
        let private = tempfile::tempdir()?;
        let manager = RubyManager {
            versions_dir: private.path().join("versions"),
            client: Box::leak(Box::new(fixture.client(true)?)),
            ..RubyManager::new()
        };
        let partial = manager.install("3.4.2").await;
        let wrong_tag = manager.install("3.4.2").await;
        let duplicate = manager.install("3.4.2").await;
        assert_eq!(
            fixture.finish().await?,
            vec![format!("GET {path} HTTP/1.1"); 3]
        );
        for (result, expected) in [
            (partial, "HTTP 206"),
            (wrong_tag, "does not match requested Ruby tag"),
            (duplicate, "multiple matching Ruby assets"),
        ] {
            let error = result.expect_err("invalid publisher metadata must stop before download");
            assert!(format!("{error:#}").contains(expected), "{error:#}");
        }
        assert!(manager.list_installed()?.is_empty());
        assert_eq!(manager.current_version(), None);
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
        let error = manager
            .publish_download(&fixture.archive, url, "3.4.2")
            .await
            .expect_err("a reviewed archive with a non-runnable interpreter must not publish");
        assert!(
            format!("{error:#}").contains("Ruby smoke test"),
            "{error:#}"
        );
        assert!(!fixture.versions.join("3.4.2").exists());
        fixture.assert_previous();
        let launcher = b"#!/bin/sh\nprintf 'ruby 3.4.2\\n'\n";
        fixture.write(
            &super::super::test_archive::tar_gz_entries("runtime", &[("bin/ruby", launcher)])
                .expect("controlled executable publisher archive"),
        );
        manager
            .publish_download(&fixture.archive, url, "3.4.2")
            .await
            .expect("publish complete runnable publisher tree");
        fixture.assert_previous();
        manager
            .use_version("3.4.2")
            .expect("activate admitted publisher tree");
        assert_eq!(
            fs::read(fixture.versions.join("current/bin/ruby"))
                .expect("selected reviewed launcher"),
            launcher
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
