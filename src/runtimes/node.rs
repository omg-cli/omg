//! Native Node.js runtime manager
//!
//! Downloads and manages Node.js versions - PURE RUST, NO SUBPROCESS.
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
    activate_version, begin_staged_install, complete_staged_install, download_with_progress,
    extract_tar_xz, normalize_version, parse_sha256_digest, print_already_installed,
    print_installed, print_using, remove_file_best_effort,
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

    /// Install Node.js - PURE RUST, NO SUBPROCESS
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
        let download_path = self.versions_dir.join(&filename);
        download_with_progress(self.client, &url, &download_path, &checksum).await?;

        println!("{} Extracting (pure Rust)...", style::informative("→"));
        let staging = begin_staged_install(&self.versions_dir)?;
        extract_tar_xz(&download_path, staging.path(), 1).await?;
        self.publish_install(&staging, &version)?;

        remove_file_best_effort(&download_path, "runtime archive");

        print_installed("Node.js", &version);
        self.use_version(&version)?;

        Ok(())
    }

    fn publish_install(&self, staging: &tempfile::TempDir, version: &str) -> Result<()> {
        super::common::require_regular_file(&staging.path().join("bin/node"))?;
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
        let text = self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await?
            .error_for_status()
            .context("Failed to fetch Node.js checksum manifest")?
            .bounded_text()
            .await?;
        let digest_line = text
            .lines()
            .find(|line| line.split_whitespace().nth(1) == Some(filename))
            .ok_or_else(|| anyhow::anyhow!("Checksum not found for {filename}"))?;
        parse_sha256_digest(digest_line, &url)
    }

    /// Switch to a specific version
    pub fn use_version(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        activate_version(&self.versions_dir, &version, Path::new("bin/node"))?;
        print_using("Node.js", &version, &self.versions_dir.join("current/bin"));
        Ok(())
    }

    /// Remove an installed version. Refuses the active version.
    pub fn uninstall(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        super::common::uninstall_version(&self.versions_dir, &version)
    }
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
        fs::write(staging.path().join("bin/node"), "fixture")?;
        manager.publish_install(&staging, "22.0.0")?;
        assert_eq!(manager.list_installed()?, vec!["22.0.0"]);
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
}
