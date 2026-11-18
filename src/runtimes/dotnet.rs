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
use std::collections::BTreeMap;
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
    security: super::security::RuntimeSecurity,
    versions_dir: PathBuf,
    client: &'static reqwest::Client,
}

impl DotnetManager {
    pub fn new() -> Self {
        Self {
            security: super::security::RuntimeSecurity::default(),
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

        let (url, checksum, components) = self.sdk_artifact(&version).await?;
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
        let publisher = super::security::record_download(
            "dotnet",
            &version,
            &version_dir,
            &download_path,
            &url,
        )?;
        super::security::record_exact_release(&version_dir, &version, &version, components)?;
        let staging = begin_staged_install(&self.versions_dir)?;
        // SDK tarballs extract flat (no top-level directory).
        extract_tar_gz(&download_path, staging.path(), 0).await?;
        let binary = staging.path().join("dotnet");
        require_staged_dotnet(&binary)?;
        make_staged_executable(&binary)?;
        let _admission =
            self.security
                .prepare_staged("dotnet", &version, staging.path(), &version_dir)?;
        complete_staged_install(&staging, &version_dir, &version)?;
        publisher.commit();

        remove_file_best_effort(&download_path, "runtime archive");

        print_installed(".NET", &version);
        self.use_version(&version)?;

        Ok(())
    }

    /// Locate the SDK tarball URL and validated SHA-512 for one version.
    async fn sdk_artifact(
        &self,
        version: &str,
    ) -> Result<(String, String, BTreeMap<String, String>)> {
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
                let mut components = BTreeMap::from([("sdk".to_owned(), version.to_owned())]);
                if let Some(release) = releases
                    .get("releases")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                    .find(|release| {
                        std::iter::once(release.get("sdk"))
                            .flatten()
                            .chain(
                                release
                                    .get("sdks")
                                    .and_then(serde_json::Value::as_array)
                                    .into_iter()
                                    .flatten(),
                            )
                            .any(|sdk| {
                                sdk.get("version").and_then(serde_json::Value::as_str)
                                    == Some(version)
                            })
                    })
                {
                    for (key, component) in [
                        ("runtime", "runtime"),
                        ("aspnetcore", "aspnetcore-runtime"),
                        ("windowsdesktop", "windowsdesktop"),
                    ] {
                        if let Some(value) = release
                            .get(key)
                            .and_then(|value| value.get("version"))
                            .and_then(serde_json::Value::as_str)
                        {
                            components.insert(component.to_owned(), value.to_owned());
                        }
                    }
                }
                return Ok((url, checksum, components));
            }
        }
        anyhow::bail!(
            ".NET SDK {version} not found in supported channels. Check available versions with: omg list dotnet --available"
        )
    }

    /// Switch to a specific version
    pub fn use_version(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        crate::core::security::validate_runtime_version(&version)?;
        super::common::require_regular_file(&self.versions_dir.join(&version).join("dotnet"))?;
        let admission = self.security.installed(
            "dotnet",
            &self.versions_dir.join(&version),
            super::security::ReviewMode::FreshAttended,
        )?;
        admission.verify(&self.versions_dir.join(&version))?;
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

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires the isolated fixed-public TLS native fixture"]
    async fn native_public_install_preserves_authenticated_download_boundary() -> Result<()> {
        use super::super::security::{
            ReviewMode, RuntimeEvidenceSource, RuntimeQuery, RuntimeSecurity, admit_installed,
            fixture_runtime_report,
        };
        use super::super::test_archive::{PublicationFixture, tar_gz_entries};
        use sha2::{Digest as _, Sha512};

        const HOST: &str = "builds.dotnet.microsoft.com";
        const INDEX: &str = "/dotnet/release-metadata/releases-index.json";
        const CHANNEL: &str = "/dotnet/release-metadata/9.0/releases.json";
        const AFFECTED_SDK: &str = "9.0.315";
        const CVE: &str = "CVE-2099-9000";
        const ADVISORY: &str = "https://www.cve.org/CVERecord?id=CVE-2099-9000";
        struct Advisories;
        impl RuntimeEvidenceSource for Advisories {
            fn read(&self, query: &RuntimeQuery) -> Result<Vec<u8>> {
                let mut report: serde_json::Value =
                    serde_json::from_slice(&fixture_runtime_report(query)?)?;
                if query.version == AFFECTED_SDK {
                    report["findings"] = json!([{
                        "id": CVE, "summary": "Controlled .NET advisory",
                        "applicability": "applicable", "severity": "high", "urls": [ADVISORY]
                    }]);
                }
                Ok(serde_json::to_vec(&report)?)
            }
        }
        let archive = tar_gz_entries(
            ".",
            &[
                ("dotnet", b"fixture .NET launcher"),
                ("sdk/payload", b"fixture SDK"),
            ],
        )?;
        let artifact_path = |version| format!("/dotnet/Sdk/{version}/dotnet-sdk.tar.gz");
        let rid = dotnet_rid()?;
        let sdk = |version, digest| {
            json!({
                "version": version,
                "files": [{
                    "name": format!("dotnet-sdk-{rid}.tar.gz"),
                    "rid": rid,
                    "url": format!("https://{HOST}{}", artifact_path(version)),
                    "hash": digest,
                }]
            })
        };
        let index = serde_json::to_vec(&json!({
            "releases-index": [{
                "support-phase": "active",
                "releases.json": format!("https://{HOST}{CHANNEL}"),
            }]
        }))?;
        let installed_sdk = "9.0.317";
        let rejected_sdk = "9.0.316";
        let channel = serde_json::to_vec(&json!({
            "channel-version": "9.0",
            "releases": [
                {
                    "sdk": {"version": "9.0.318"},
                    "sdks": [sdk(installed_sdk, hex::encode(Sha512::digest(&archive)))],
                    "runtime": {"version": "9.0.19"},
                    "aspnetcore": {"version": "9.0.18"},
                },
                {
                    "sdk": sdk(rejected_sdk, hex::encode(Sha512::digest(b"different bytes"))),
                    "runtime": {"version": "9.0.17"},
                },
                {
                    "sdk": sdk(AFFECTED_SDK, hex::encode(Sha512::digest(&archive))),
                    "runtime": {"version": "9.0.16"},
                },
            ]
        }))?;
        super::super::test_https::fixed_public_routes(&[
            (HOST, INDEX, &index),
            (HOST, CHANNEL, &channel),
            (HOST, &artifact_path(installed_sdk), &archive),
            (HOST, INDEX, &index),
            (HOST, CHANNEL, &channel),
            (HOST, &artifact_path(rejected_sdk), &archive),
            (HOST, INDEX, &index),
            (HOST, CHANNEL, &channel),
            (HOST, &artifact_path(AFFECTED_SDK), &archive),
            (HOST, INDEX, &index),
            (HOST, CHANNEL, &channel),
            (HOST, &artifact_path(AFFECTED_SDK), &archive),
        ]);

        let fixture = PublicationFixture::new("dotnet", "dotnet");
        let manager = DotnetManager {
            security: RuntimeSecurity::with_source(std::sync::Arc::new(Advisories)),
            versions_dir: fixture.versions.clone(),
            client: download_client(),
        };
        manager.install(installed_sdk).await?;
        let installed = fixture.versions.join(installed_sdk);
        assert_eq!(
            fs::read(fixture.versions.join("current/dotnet"))?,
            b"fixture .NET launcher"
        );
        assert_eq!(fs::read(installed.join("sdk/payload"))?, b"fixture SDK");

        let error = manager
            .install(rejected_sdk)
            .await
            .expect_err("a checksum mismatch must refuse publication");
        assert!(
            format!("{error:#}").contains("Checksum mismatch"),
            "{error:#}"
        );
        assert!(!fixture.versions.join(rejected_sdk).exists());
        let publisher_state = || -> std::io::Result<BTreeMap<_, _>> {
            fs::read_dir(fixture.versions.join(".security"))?
                .map(|entry| {
                    let entry = entry?;
                    Ok((entry.file_name(), fs::read(entry.path())?))
                })
                .collect()
        };
        let previous_state = publisher_state()?;
        let lease = super::super::common::try_lock_runtime_file(
            &fixture.versions,
            &format!(".admission-{AFFECTED_SDK}.lock"),
        )?;
        let error = manager
            .install(AFFECTED_SDK)
            .await
            .expect_err("a competing publication must refuse the authenticated download");
        assert!(
            format!("{error:#}").contains("Another runtime mutation or active use conflicts"),
            "{error:#}"
        );
        assert!(!fixture.versions.join(AFFECTED_SDK).exists());
        assert_eq!(publisher_state()?, previous_state);
        assert_eq!(fs::read_link(fixture.versions.join("current"))?, installed);
        drop(lease);
        let error = manager
            .install(AFFECTED_SDK)
            .await
            .expect_err("unattended install must refuse the reported CVE");
        let warning = format!("{error:#}");
        assert!(
            warning.contains(CVE) && warning.contains(ADVISORY),
            "{warning}"
        );
        assert!(
            warning.contains("requires an attended controlling terminal"),
            "{warning}"
        );
        assert!(!fixture.versions.join(AFFECTED_SDK).exists());
        assert_eq!(publisher_state()?, previous_state);
        assert_eq!(fs::read_link(fixture.versions.join("current"))?, installed);
        let admission = admit_installed("dotnet", &installed, ReviewMode::CachedOnly)?;
        admission.verify(&installed)?;
        let identity: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture.identity_path(installed_sdk))?)?;
        assert_eq!(
            identity["components"],
            json!({
                "sdk": installed_sdk, "runtime": "9.0.19", "aspnetcore-runtime": "9.0.18"
            })
        );
        Ok(())
    }

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
        let actual: Vec<_> = versions
            .iter()
            .map(|version| (version.version.as_str(), version.prerelease))
            .collect();
        assert_eq!(actual, vec![("9.0.317", true), ("9.0.316", true)]);
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
        #[cfg(all(
            any(target_os = "linux", target_os = "macos"),
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            let expected = "linux-x64";
            #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
            let expected = "linux-arm64";
            #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
            let expected = "osx-x64";
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            let expected = "osx-arm64";

            let rid = dotnet_rid().expect("host platform should be supported");
            assert_eq!(
                rid, expected,
                ".NET SDK RID must match host operating system and architecture"
            );
        }
        #[cfg(not(all(
            any(target_os = "linux", target_os = "macos"),
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        {
            let _ = dotnet_rid().expect("host platform should be supported");
            panic!(
                "unexpected test host platform: {}/{}",
                std::env::consts::OS,
                std::env::consts::ARCH
            );
        }
    }
}
