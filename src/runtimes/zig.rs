//! Native Zig runtime manager - PURE RUST
//!
//! Downloads and manages Zig versions from the official release index.
//!
//! Features:
//! - Official tarballs from ziglang.org (`download/index.json`)
//! - Inline SHA-256 verification (the index carries per-target shasums)
//! - Normalized `bin/zig` layout shared with the registry tools

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use super::common::{
    activate_version, begin_staged_install, complete_staged_install, download_with_progress,
    extract_tar_xz, normalize_version, parse_sha256_digest, print_already_installed,
    print_installed, print_using, remove_file_best_effort,
};
use crate::core::http::BoundedResponseExt;
use crate::{cli::style, core::http::download_client};

const ZIG_INDEX_URL: &str = "https://ziglang.org/download/index.json";

type ZigIndex = serde_json::Map<String, serde_json::Value>;

/// Zig release version info (tarball URL and checksum come from the index).
#[derive(Debug, Clone)]
pub(crate) struct ZigVersion {
    pub(crate) version: String,
}

pub(crate) struct ZigManager {
    security: super::security::RuntimeSecurity,
    versions_dir: PathBuf,
    client: &'static reqwest::Client,
}

impl ZigManager {
    pub fn new() -> Self {
        Self {
            security: super::security::RuntimeSecurity::default(),
            versions_dir: super::DATA_DIR.join("versions/zig"),
            client: download_client(),
        }
    }

    async fn fetch_index(&self) -> Result<ZigIndex> {
        let response = self
            .client
            .get(ZIG_INDEX_URL)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .context("Failed to fetch Zig release index. Check your internet connection.")?
            .error_for_status()
            .context("Zig release-index request failed")?;
        anyhow::ensure!(
            response.status() == reqwest::StatusCode::OK,
            "Zig release index returned HTTP {}",
            response.status()
        );
        response
            .bounded_json()
            .await
            .context("Failed to parse Zig release index from ziglang.org")
    }

    /// List stable releases with a tarball entry for this host, newest first.
    pub async fn list_available(&self) -> Result<Vec<ZigVersion>> {
        let target = zig_target()?;
        Ok(parse_zig_versions(&self.fetch_index().await?, target))
    }

    /// Install Zig - PURE RUST, NO SUBPROCESS
    pub async fn install(&self, version: &str) -> Result<()> {
        let requested = normalize_version(version);
        crate::core::security::validate_runtime_version(&requested)?;
        let (version, index) =
            if requested == "latest" || super::common::is_partial_version(&requested) {
                let target = zig_target()?;
                let index = self.fetch_index().await?;
                let versions = parse_zig_versions(&index, target);
                let version = if requested == "latest" {
                    versions
                        .into_iter()
                        .next()
                        .map(|release| release.version)
                        .with_context(|| format!("No Zig versions found upstream for {target}"))?
                } else {
                    let names: Vec<_> = versions
                        .into_iter()
                        .map(|release| release.version)
                        .collect();
                    super::resolve_version_request(&names, &requested)
                };
                (version, Some(index))
            } else {
                (requested, None)
            };
        let _install_lease = super::common::try_lock_runtime_install(&self.versions_dir, &version)?;
        let version_dir = self.versions_dir.join(&version);

        if super::common::is_valid_version_dir(&version_dir) {
            print_already_installed("Zig", &version);
            return self.use_version(&version);
        }
        super::common::require_unoccupied_install_destination(&version_dir)?;

        println!(
            "{} Installing Zig {}...\n",
            style::runtime("OMG"),
            style::caution(&version)
        );

        let target = zig_target()?;
        let index = if let Some(index) = index {
            index
        } else {
            self.fetch_index().await?
        };
        let (url, checksum) = index_artifact(&index, &version, target)?;

        let filename = url
            .path_segments()
            .and_then(|mut segments| segments.next_back())
            .filter(|name| !name.is_empty())
            .with_context(|| format!("Zig tarball URL has no filename: {url}"))?;
        super::common::validate_download_filename(filename)?;

        println!("{} Downloading {filename}...", style::informative("→"));
        let downloads = tempfile::Builder::new()
            .prefix(".download-")
            .tempdir_in(&self.versions_dir)?;
        let download_path = downloads.path().join(filename);
        download_with_progress(self.client, url.as_str(), &download_path, &checksum).await?;

        println!("{} Extracting (pure Rust)...", style::informative("→"));
        self.publish_download(&download_path, url.as_str(), &version)
            .await?;

        remove_file_best_effort(&download_path, "runtime archive");

        print_installed("Zig", &version);
        self.use_version(&version)?;

        Ok(())
    }

    async fn publish_download(&self, download_path: &Path, url: &str, version: &str) -> Result<()> {
        let version_dir = self.versions_dir.join(version);
        let publisher =
            super::security::record_download("zig", version, &version_dir, download_path, url)?;
        let staging = begin_staged_install(&self.versions_dir)?;
        stage_zig_tree(download_path, staging.path()).await?;
        let _admission =
            self.security
                .prepare_staged("zig", version, staging.path(), &version_dir)?;
        complete_staged_install(&staging, &version_dir, version)?;
        publisher.commit();
        Ok(())
    }

    /// Switch to a specific version
    pub fn use_version(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        crate::core::security::validate_runtime_version(&version)?;
        super::common::require_regular_file(&self.versions_dir.join(&version).join("bin/zig"))?;
        let admission = self.security.installed(
            "zig",
            &self.versions_dir.join(&version),
            super::security::ReviewMode::FreshAttended,
        )?;
        admission.verify(&self.versions_dir.join(&version))?;
        activate_version(&self.versions_dir, &version, Path::new("bin/zig"))?;
        print_using("Zig", &version, &self.versions_dir.join("current/bin"));
        Ok(())
    }

    /// Remove an installed version. Refuses the active version.
    pub fn uninstall(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        super::common::uninstall_version(&self.versions_dir, &version)
    }
}

// Generate common runtime manager methods (list_installed, current_version)
super::common::impl_runtime_common!(ZigManager);

/// Host target triple as named by the Zig release index.
fn zig_target() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("x86_64-linux"),
        ("linux", "aarch64") => Ok("aarch64-linux"),
        ("macos", "x86_64") => Ok("x86_64-macos"),
        ("macos", "aarch64") => Ok("aarch64-macos"),
        (os, arch) => anyhow::bail!("Unsupported operating system for Zig: {os}/{arch}"),
    }
}

/// The publisher's stable version keys identify the downloadable releases.
fn parse_zig_versions(index: &ZigIndex, target: &str) -> Vec<ZigVersion> {
    let mut versions: Vec<ZigVersion> = index
        .iter()
        .filter(|(key, entry)| {
            entry.get(target).is_some()
                && semver::Version::parse(key)
                    .is_ok_and(|version| version.pre.is_empty() && version.build.is_empty())
        })
        .map(|(key, _)| ZigVersion {
            version: key.clone(),
        })
        .collect();
    versions.sort_by(|a, b| super::common::version_cmp(&b.version, &a.version));
    versions
}

/// Resolve the tarball URL and validated SHA-256 for one index version.
fn index_artifact(index: &ZigIndex, version: &str, target: &str) -> Result<(reqwest::Url, String)> {
    let entry = index.get(version).with_context(|| {
        format!("Zig version {version} not found in the release index. Check available versions with: omg list zig --available")
    })?;
    if let Some(declared) = entry.get("version").filter(|_| version != "master") {
        anyhow::ensure!(
            declared.as_str() == Some(version),
            "Index entry version {declared} does not match Zig release {version}"
        );
    }
    let artifact = entry
        .get(target)
        .with_context(|| format!("Zig {version} has no {target} tarball in the release index"))?;
    let url = artifact
        .get("tarball")
        .and_then(serde_json::Value::as_str)
        .with_context(|| format!("Zig {version} {target} entry has no tarball URL"))?;
    let url = reqwest::Url::parse(url).context("Invalid Zig publisher URL")?;
    anyhow::ensure!(
        url.scheme() == "https"
            && url.host_str() == Some("ziglang.org")
            && url.port_or_known_default() == Some(443)
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "Zig publisher URL must use the official ziglang.org HTTPS origin"
    );
    let digest = artifact
        .get("shasum")
        .and_then(serde_json::Value::as_str)
        .with_context(|| format!("Zig {version} {target} entry has no shasum"))?;
    Ok((url, parse_sha256_digest(digest, "Zig release index")?))
}

/// Extract a Zig tarball into staging and normalize the layout to
/// `bin/zig`, keeping the sibling `lib/` tree the compiler resolves its
/// standard library from.
async fn stage_zig_tree(download_path: &Path, staging: &Path) -> Result<()> {
    for strip in [1_usize, 0] {
        if strip == 0 {
            super::common::clear_dir_contents(staging)?;
        }
        extract_tar_xz(download_path, staging, strip).await?;
        if staging.join("zig").is_file() {
            break;
        }
        if strip == 0 {
            anyhow::bail!("Installed Zig archive but found no `zig` binary inside");
        }
    }
    let binary = staging.join("zig");
    super::common::require_regular_file(&binary)?;
    make_staged_executable(&binary)?;
    let bin_dir = staging.join("bin");
    fs::create_dir_all(&bin_dir)?;
    fs::rename(&binary, bin_dir.join("zig")).context("Failed to stage Zig binary into bin dir")?;
    Ok(())
}

/// Ensure a staged binary is executable (archives may drop modes).
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
    anyhow::bail!("Zig installs are unsupported on this platform")
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires the isolated fixed-public TLS native fixture"]
    async fn native_public_install_preserves_authenticated_download_boundary() {
        use super::super::test_archive::{PublicationFixture, tar_xz_entries};
        use sha2::{Digest as _, Sha256};

        let version = "0.15.0";
        let archive = tar_xz_entries(
            "zig",
            &[
                ("zig", b"fixture launcher"),
                ("lib/owned.data", b"complete Zig implementation"),
            ],
        )
        .unwrap();
        let target = zig_target().unwrap();
        let path = format!("/download/{version}/zig-{target}-{version}.tar.xz");
        let metadata = serde_json::to_vec(&serde_json::json!({version:{target:{
            "tarball":format!("https://ziglang.org{path}"),"shasum":hex::encode(Sha256::digest(&archive))
        }}})).unwrap();
        super::super::test_https::fixed_public_routes(&[
            ("ziglang.org", "/download/index.json", &metadata),
            ("ziglang.org", &path, &archive),
        ]);

        let fixture = PublicationFixture::new("zig", "bin/zig");
        let manager = ZigManager {
            security: super::super::security::RuntimeSecurity::fixture(),
            versions_dir: fixture.versions.clone(),
            client: download_client(),
        };
        manager
            .install("0.15")
            .await
            .expect("complete authenticated public installation from one catalog");
        let installed = fixture.versions.join(version);
        assert_eq!(
            fs::read(fixture.versions.join("current").join("bin/zig")).unwrap(),
            b"fixture launcher"
        );
        assert_eq!(
            fs::read(installed.join("lib/owned.data")).unwrap(),
            b"complete Zig implementation"
        );
        assert_eq!(
            fs::read(fixture.versions.join("1.0.0/bin/zig")).unwrap(),
            b"previous reviewed runtime"
        );
        super::super::security::admit_installed(
            "zig",
            &installed,
            super::super::security::ReviewMode::CachedOnly,
        )
        .expect("retain exact authenticated publisher authority")
        .verify(&installed)
        .expect("complete published tree matches its admission");
    }

    use super::*;
    use serde_json::json;

    fn fixture_index() -> ZigIndex {
        serde_json::from_value(json!({
            "master": {"version": "0.18.0-dev.1+abc", "x86_64-linux": {"tarball": "https://ziglang.org/builds/zig-x86_64-linux-master.tar.xz", "shasum": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
            "0.16.0": {"version": "0.16.0", "x86_64-linux": {"tarball": "https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz", "shasum": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},
            "0.15.2": {"version": "0.15.2", "x86_64-linux": {"tarball": "https://ziglang.org/download/0.15.2/zig-x86_64-linux-0.15.2.tar.xz", "shasum": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}},
        })).expect("fixture index is an object")
    }

    #[test]
    fn index_parsing_skips_master_and_sorts_newest_first() {
        let versions = parse_zig_versions(&fixture_index(), "x86_64-linux");
        let names: Vec<&str> = versions
            .iter()
            .map(|version| version.version.as_str())
            .collect();
        assert_eq!(names, vec!["0.16.0", "0.15.2"]);
    }

    #[tokio::test]
    async fn release_index_rejects_partial_success_and_non_object_responses() -> Result<()> {
        let path = "/download/index.json";
        let fixture = super::super::test_https::HttpsFixture::new_with_statuses(
            "ziglang.org",
            vec![
                (path.to_owned(), 206, serde_json::to_vec(&fixture_index())?),
                (path.to_owned(), 200, b"[]".to_vec()),
            ],
        )
        .await?;
        let manager = ZigManager {
            client: Box::leak(Box::new(fixture.client(true)?)),
            ..ZigManager::new()
        };
        let partial = manager.list_available().await;
        let array = manager.list_available().await;
        assert_eq!(
            fixture.finish().await?,
            vec![format!("GET {path} HTTP/1.1"); 2]
        );
        for (result, expected) in [(partial, "HTTP 206"), (array, "Zig release index")] {
            let error = result.expect_err("invalid release index must fail");
            assert!(format!("{error:#}").contains(expected), "{error:#}");
        }
        Ok(())
    }

    #[test]
    fn index_artifact_requires_the_published_release_and_origin() {
        let mut index = fixture_index();
        index.get_mut("0.16.0").unwrap()["version"] = json!("0.16.1");
        let error = index_artifact(&index, "0.16.0", "x86_64-linux")
            .expect_err("conflicting release identity");
        assert!(
            format!("{error:#}").contains("does not match Zig release 0.16.0"),
            "{error:#}"
        );

        let mut index = fixture_index();
        index.get_mut("0.16.0").unwrap()["x86_64-linux"]["tarball"] =
            json!("https://example.com/download/zig.tar.xz");
        let error = index_artifact(&index, "0.16.0", "x86_64-linux")
            .expect_err("archive origin must be Zig's publisher");
        assert!(
            format!("{error:#}").contains("Zig publisher URL"),
            "{error:#}"
        );
    }

    #[test]
    fn index_artifact_resolves_url_and_validates_shasum() {
        let (url, checksum) =
            index_artifact(&fixture_index(), "0.16.0", "x86_64-linux").expect("fixture artifact");
        assert!(
            url.path().ends_with("zig-x86_64-linux-0.16.0.tar.xz"),
            "{url}"
        );
        assert_eq!(
            checksum,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
    }

    #[test]
    fn index_artifact_fails_closed_on_unknown_version_or_target() {
        let index = fixture_index();
        assert!(index_artifact(&index, "9.9.9", "x86_64-linux").is_err());
        assert!(index_artifact(&index, "0.16.0", "mips-linux").is_err());
    }

    #[test]
    fn zig_target_uses_host_os_and_arch() {
        let target = zig_target().expect("host platform should be supported");
        assert!(target.contains(std::env::consts::ARCH), "{target}");
        assert!(
            target.contains(std::env::consts::OS),
            "{target} should name the host OS"
        );
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn downloaded_publication_preserves_prior_authority_and_rejects_changed_reviewed_content()
    {
        use super::super::test_archive::tar_xz_entries;
        use super::super::test_archive::{PublicationFixture, mutation_security};
        let fixture = PublicationFixture::new("zig", "bin/zig");
        let mut manager = ZigManager {
            security: super::super::security::RuntimeSecurity::fixture(),
            versions_dir: fixture.versions.clone(),
            client: download_client(),
        };
        let url = "https://ziglang.org/download/0.15.0/zig.tar.xz";
        assert!(
            manager
                .publish_download(&fixture.archive, url, "0.15.0")
                .await
                .is_err()
        );
        fixture.assert_previous();
        fixture.write(b"not an archive");
        assert!(
            manager
                .publish_download(&fixture.archive, url, "0.15.0")
                .await
                .is_err()
        );
        fixture.assert_previous();
        let bytes = tar_xz_entries("runtime", &[("zig", b"fixture launcher")])
            .expect("controlled publisher archive");
        fixture.write(&bytes);
        manager.security = mutation_security(&fixture.versions);
        let error = manager
            .publish_download(&fixture.archive, url, "0.15.0")
            .await
            .expect_err("changed reviewed payload must not publish");
        assert!(
            format!("{error:#}").contains("Runtime content changed after advisory review"),
            "{error:#}"
        );
        assert!(!fixture.versions.join("0.15.0").exists());
        fixture.assert_previous();
        manager.security = super::super::security::RuntimeSecurity::fixture();
        manager
            .publish_download(&fixture.archive, url, "0.15.0")
            .await
            .expect("publish complete reviewed publisher tree");
        fixture.assert_previous();
        manager
            .use_version("0.15.0")
            .expect("activate admitted publisher tree");
        assert_eq!(
            fs::read(fixture.versions.join("current/bin/zig")).expect("selected reviewed launcher"),
            b"fixture launcher"
        );
        fs::remove_file(fixture.versions.join("current"))
            .expect("restore controlled prior selection");
        std::os::unix::fs::symlink("1.0.0", fixture.versions.join("current"))
            .expect("restore prior selection");
        fixture.corrupt_identity("0.15.0");
        assert!(manager.use_version("0.15.0").is_err());
        fixture.assert_previous();
    }
}
