//! Native .NET SDK manager - PURE RUST
//!
//! Downloads and manages .NET SDK versions from Microsoft's official release
//! metadata ([`releases-index.json`](https://builds.dotnet.microsoft.com/dotnet/release-metadata/releases-index.json)).
//!
//! Features:
//! - Channels discovered from the index; end-of-life channels excluded
//! - SHA-512 verification (hashes ship inline in the release metadata)
//! - Flat SDK layout with a root `dotnet` binary (Bun-style activation)

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use super::common::{
    activate_version, begin_staged_install, complete_staged_install, download_with_progress_sha512,
    extract_tar_gz, normalize_version, parse_sha512_digest, print_already_installed,
    print_installed, print_using, remove_file_best_effort,
};
use crate::core::http::BoundedResponseExt;
use crate::{cli::style, core::http::download_client};

const DOTNET_RELEASE_INDEX_URL: &str =
    "https://builds.dotnet.microsoft.com/dotnet/release-metadata/releases-index.json";

/// Support phases OMG installs from; `eol` channels are never listed.
const SUPPORTED_PHASES: &[&str] = &["active", "maintenance", "preview", "rc", "go-live"];

/// .NET SDK version info.
#[derive(Debug, Clone)]
pub(crate) struct DotnetVersion {
    pub(crate) version: String,
    pub(crate) prerelease: bool,
}

pub(crate) struct DotnetManager {
    versions_dir: PathBuf,
    client: &'static reqwest::Client,
}

impl DotnetManager {
    pub fn new() -> Self {
        Self {
            versions_dir: super::DATA_DIR.join("versions/dotnet"),
            client: download_client(),
        }
    }

    /// Fetch a release-metadata JSON document.
    async fn fetch_metadata(&self, url: &str) -> Result<serde_json::Value> {
        let source = crate::core::http::redact_url(url);
        crate::core::http::fetch_public_download_with_timeout(
            url,
            "omg-package-manager",
            Some(std::time::Duration::from_secs(30)),
        )
        .await
        .with_context(|| format!("Failed to fetch .NET release metadata from {source}"))?
        .error_for_status()
        .map_err(reqwest::Error::without_url)
        .with_context(|| format!(".NET release-metadata request failed: {source}"))?
        .bounded_json()
        .await
        .with_context(|| format!("Failed to parse .NET release metadata from {source}"))
    }

    /// List available SDK versions across supported channels (newest first).
    pub async fn list_available(&self) -> Result<Vec<DotnetVersion>> {
        let index = self.fetch_metadata(DOTNET_RELEASE_INDEX_URL).await?;
        let Some(channels) = index
            .get("releases-index")
            .and_then(serde_json::Value::as_array)
        else {
            anyhow::bail!("Unexpected .NET release index shape from {DOTNET_RELEASE_INDEX_URL}");
        };
        let mut versions = Vec::new();
        for channel in channels {
            let phase = channel
                .get("support-phase")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            if !SUPPORTED_PHASES.contains(&phase) {
                continue;
            }
            let Some(channel_url) = channel
                .get("releases.json")
                .and_then(serde_json::Value::as_str)
            else {
                continue;
            };
            let prerelease = matches!(phase, "preview" | "rc" | "go-live");
            let releases = self.fetch_metadata(channel_url).await?;
            versions.extend(parse_channel_sdks(&releases, prerelease));
        }
        versions.sort_by(|a, b| super::common::version_cmp(&b.version, &a.version));
        versions.dedup_by(|a, b| a.version == b.version);
        Ok(versions)
    }

    /// Resolve `latest` and partial requests. Exact versions pass through so
    /// the installed fast path and the existing not-found UX are preserved.
    pub async fn resolve_alias(&self, alias: &str) -> Result<String> {
        let alias = normalize_version(alias);
        if alias == "latest" {
            let versions = self.list_available().await?;
            versions
                .iter()
                .find(|version| !version.prerelease)
                .map(|version| version.version.clone())
                .context("No .NET SDK versions found upstream")
        } else {
            Ok(alias)
        }
    }

    /// Resolve a partial version request (`9`, `9.0`) to the newest matching
    /// SDK before any tarball URL is built.
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

    /// Install .NET SDK - PURE RUST, NO SUBPROCESS
    pub async fn install(&self, version: &str) -> Result<()> {
        let version = self.resolve_alias(version).await?;
        let version = self.resolve_requested_version(&version).await?;
        crate::core::security::validate_runtime_version(&version)?;
        let version_dir = self.versions_dir.join(&version);

        if super::common::is_valid_version_dir(&version_dir) {
            print_already_installed(".NET", &version);
            return self.use_version(&version);
        }

        println!(
            "{} Installing .NET SDK {}...\n",
            style::runtime("OMG"),
            style::caution(&version)
        );

        let (url, checksum) = self.sdk_artifact(&version).await?;
        let filename = url
            .rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .with_context(|| format!(".NET SDK URL has no filename: {url}"))?;
        super::common::validate_download_filename(filename)?;

        fs::create_dir_all(&self.versions_dir)?;

        println!("{} Downloading {filename}...", style::informative("→"));
        let downloads = tempfile::Builder::new()
            .prefix(".download-")
            .tempdir_in(&self.versions_dir)?;
        let download_path = downloads.path().join(filename);
        download_with_progress_sha512(self.client, &url, &download_path, &checksum).await?;

        println!("{} Extracting (pure Rust)...", style::informative("→"));
        let staging = begin_staged_install(&self.versions_dir)?;
        // SDK tarballs extract flat (no top-level directory).
        extract_tar_gz(&download_path, staging.path(), 0).await?;
        let binary = staging.path().join("dotnet");
        require_staged_dotnet(&binary)?;
        make_staged_executable(&binary)?;
        complete_staged_install(&staging, &version_dir, &version)?;

        remove_file_best_effort(&download_path, "runtime archive");

        print_installed(".NET", &version);
        self.use_version(&version)?;

        Ok(())
    }

    /// Locate the SDK tarball URL and validated SHA-512 for one version.
    async fn sdk_artifact(&self, version: &str) -> Result<(String, String)> {
        let index = self.fetch_metadata(DOTNET_RELEASE_INDEX_URL).await?;
        let channels = index
            .get("releases-index")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        for channel in channels {
            let phase = channel
                .get("support-phase")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            if !SUPPORTED_PHASES.contains(&phase) {
                continue;
            }
            let Some(channel_url) = channel
                .get("releases.json")
                .and_then(serde_json::Value::as_str)
            else {
                continue;
            };
            let releases = self.fetch_metadata(channel_url).await?;
            let Some(matching) = channel_sdks(&releases).find(|sdk| {
                sdk.get("version").and_then(serde_json::Value::as_str) == Some(version)
            }) else {
                continue;
            };
            let files = matching
                .get("files")
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default();
            if let Some((url, checksum)) = select_sdk_file(&files, dotnet_rid()?) {
                return Ok((url, checksum));
            }
        }
        anyhow::bail!(
            ".NET SDK {version} not found in supported channels. Check available versions with: omg list dotnet --available"
        )
    }

    /// Switch to a specific version
    pub fn use_version(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        activate_version(&self.versions_dir, &version, Path::new("dotnet"))?;
        print_using(".NET", &version, &self.versions_dir.join("current"));
        Ok(())
    }

    /// Remove an installed version. Refuses the active version.
    pub fn uninstall(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        super::common::uninstall_version(&self.versions_dir, &version)
    }
}

// Generate common runtime manager methods (list_installed, current_version)
super::common::impl_runtime_common!(DotnetManager);

/// Host runtime identifier as named by the .NET release metadata.
fn dotnet_rid() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("linux-x64"),
        ("linux", "aarch64") => Ok("linux-arm64"),
        ("macos", "x86_64") => Ok("osx-x64"),
        ("macos", "aarch64") => Ok("osx-arm64"),
        (os, arch) => anyhow::bail!("Unsupported operating system for .NET: {os}/{arch}"),
    }
}

fn channel_sdks(channel: &serde_json::Value) -> impl Iterator<Item = &serde_json::Value> {
    channel
        .get("releases")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|release| {
            release.get("sdk").into_iter().chain(
                release
                    .get("sdks")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten(),
            )
        })
}

/// Collect every SDK feature band from one channel document.
fn parse_channel_sdks(channel: &serde_json::Value, prerelease: bool) -> Vec<DotnetVersion> {
    let mut versions: Vec<_> = channel_sdks(channel)
        .filter_map(|sdk| {
            sdk.get("version")
                .and_then(serde_json::Value::as_str)
                .filter(|version| !version.is_empty())
                .map(|version| DotnetVersion {
                    version: version.to_owned(),
                    prerelease,
                })
        })
        .collect();
    versions.sort_by(|a, b| super::common::version_cmp(&b.version, &a.version));
    versions.dedup_by(|a, b| a.version == b.version);
    versions
}

/// Pick the SDK tarball for this host: exact RID match, preferring the
/// `dotnet-sdk-` payload over adjacent files (symbols, installers).
fn select_sdk_file(files: &[serde_json::Value], rid: &str) -> Option<(String, String)> {
    let file = files.iter().find(|file| {
        file.get("rid").and_then(serde_json::Value::as_str) == Some(rid)
            && file
                .get("name")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|name| name.starts_with("dotnet-sdk-") && name.ends_with(".tar.gz"))
    })?;
    let url = file
        .get("url")
        .and_then(serde_json::Value::as_str)?
        .to_owned();
    let hash = file.get("hash").and_then(serde_json::Value::as_str)?;
    let checksum = parse_sha512_digest(hash, ".NET release metadata").ok()?;
    Some((url, checksum))
}

/// The extracted tree must expose the `dotnet` host binary at its root.
fn require_staged_dotnet(binary: &Path) -> Result<()> {
    if binary.is_file() {
        Ok(())
    } else {
        anyhow::bail!("Installed .NET SDK archive but found no `dotnet` binary inside")
    }
}

/// Ensure the staged host binary is executable (tarballs may drop modes).
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
    anyhow::bail!(".NET installs are unsupported on this platform")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn release_metadata_refuses_private_target_before_connecting() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind metadata connection observer");
        let url = format!("https://{}/releases.json", listener.local_addr().unwrap());
        let manager = DotnetManager::new();
        let (result, connection) = tokio::join!(manager.fetch_metadata(&url), async {
            tokio::time::timeout(std::time::Duration::from_millis(200), listener.accept())
                .await
                .map(|connection| connection.map(|(stream, _)| drop(stream)))
        });
        let error = result.expect_err("private release metadata must be refused");
        assert!(
            connection.is_err(),
            "metadata-selected private address received a connection"
        );
        assert!(format!("{error:#}").contains("private or local address"));
    }
    use serde_json::json;

    fn fixture_channel() -> serde_json::Value {
        json!({
            "releases": [
                {"release-version": "9.0.19", "sdk": {
                    "version": "9.0.317",
                    "files": [
                        {"name": "dotnet-sdk-linux-x64.tar.gz", "rid": "linux-x64",
                         "url": "https://example.com/dotnet-sdk-9.0.317-linux-x64.tar.gz",
                         "hash": "ab".repeat(64)},
                        {"name": "dotnet-sdk-osx-arm64.tar.gz", "rid": "osx-arm64",
                         "url": "https://example.com/dotnet-sdk-9.0.317-osx-arm64.tar.gz",
                         "hash": "cd".repeat(64)},
                    ],
                }},
                {"release-version": "9.0.18", "sdk": {"version": "9.0.316", "files": []}},
            ],
        })
    }

    #[test]
    fn channel_sdks_parse_newest_first_without_prerelease_flag() {
        let versions = parse_channel_sdks(&fixture_channel(), false);
        let names: Vec<&str> = versions
            .iter()
            .map(|version| version.version.as_str())
            .collect();
        assert_eq!(names, vec!["9.0.317", "9.0.316"]);
        assert!(versions.iter().all(|version| !version.prerelease));
    }

    #[test]
    fn channel_sdks_flag_preview_releases() {
        let versions = parse_channel_sdks(&fixture_channel(), true);
        assert!(versions.iter().all(|version| version.prerelease));
    }

    #[test]
    fn sdk_file_selection_prefers_host_rid_and_sdk_payload() {
        let files = fixture_channel()["releases"][0]["sdk"]["files"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let (url, checksum) =
            select_sdk_file(&files, "linux-x64").expect("linux SDK must be selectable");
        assert!(
            url.ends_with("dotnet-sdk-9.0.317-linux-x64.tar.gz"),
            "{url}"
        );
        assert_eq!(checksum.len(), 128);
        assert!(select_sdk_file(&files, "linux-arm64").is_none());
    }

    #[test]
    fn sdk_file_selection_skips_macos_installer() {
        let files = vec![
            serde_json::json!({"rid":"osx-arm64", "name":"dotnet-sdk-osx-arm64.pkg", "url":"https://example.com/sdk.pkg", "hash":"a".repeat(128)}),
            serde_json::json!({"rid":"osx-arm64", "name":"dotnet-sdk-osx-arm64.tar.gz", "url":"https://example.com/sdk.tar.gz", "hash":"b".repeat(128)}),
        ];
        assert_eq!(
            select_sdk_file(&files, "osx-arm64").expect("tarball").0,
            "https://example.com/sdk.tar.gz"
        );
    }

    #[test]
    fn secondary_sdk_feature_bands_are_listed_and_resolvable() {
        let channel = serde_json::json!({"releases":[{
            "sdk":{"version":"9.0.317"},
            "sdks":[{"version":"9.0.317"},{"version":"9.0.120","files":[]}]
        }]});
        let versions = parse_channel_sdks(&channel, false);
        assert_eq!(
            versions
                .iter()
                .map(|sdk| sdk.version.as_str())
                .collect::<Vec<_>>(),
            vec!["9.0.317", "9.0.120"]
        );
        assert!(channel_sdks(&channel).any(|sdk| sdk["version"] == "9.0.120"));
    }

    #[test]
    fn sdk_file_selection_rejects_bad_hashes() {
        let files = vec![json!({
            "name": "dotnet-sdk-linux-x64.tar.gz",
            "rid": "linux-x64",
            "url": "https://example.com/dotnet.tar.gz",
            "hash": "not-a-hash",
        })];
        assert!(select_sdk_file(&files, "linux-x64").is_none());
    }

    #[test]
    fn dotnet_rid_names_the_host_platform() {
        let rid = dotnet_rid().expect("host platform should be supported");
        match std::env::consts::ARCH {
            "x86_64" => assert!(rid.contains("x64"), "{rid}"),
            "aarch64" => assert!(rid.contains("arm64"), "{rid}"),
            arch => panic!("unexpected test host arch: {arch}"),
        }
    }
}
