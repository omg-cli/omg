//! Native Python runtime manager - PURE RUST
//!
//! Downloads pre-built Python binaries from python-build-standalone.
//!
//! Features:
//! - Pre-built binaries (no compilation required)
//! - Automatic version detection
//! - Virtual environment support

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

mod catalog;

use super::common::{
    GithubRelease, activate_version_with_linked_binary, begin_staged_install,
    complete_staged_install, download_with_progress, extract_tar_gz, fetch_github_releases,
    normalize_version, parse_sha256_digest, print_already_installed, print_installed, print_using,
    remove_file_best_effort, validate_download_filename, version_cmp,
};
use crate::{cli::style, core::http::download_client};

const PBS_RELEASES_URL: &str =
    "https://api.github.com/repos/indygreg/python-build-standalone/releases";
/// Release metadata grew past the 16MiB control-plane bound at 10
/// releases per page (~1.9MB per release with ~1000 assets each), so pages
/// stay at 5 (~9.5MB worst case) and the install walk runs twice as many
/// pages to keep the same 200-release history depth.
const PBS_INSTALL_PER_PAGE: u32 = 5;
const PBS_INSTALL_MAX_PAGES: u32 = 40;

/// Python version info for available versions
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PythonVersion {
    pub version: String,
    pub prerelease: bool,
}

pub(crate) struct PythonManager {
    versions_dir: PathBuf,
    client: &'static reqwest::Client,
}

impl PythonManager {
    pub fn new() -> Self {
        Self {
            versions_dir: super::DATA_DIR.join("versions/python"),
            client: download_client(),
        }
    }

    /// List available Python versions from python-build-standalone
    pub async fn list_available(&self) -> Result<Vec<PythonVersion>> {
        if crate::core::paths::test_mode() {
            return Ok(vec![
                PythonVersion {
                    version: "3.12.0".to_string(),
                    prerelease: false,
                },
                PythonVersion {
                    version: "3.11.0".to_string(),
                    prerelease: false,
                },
            ]);
        }
        let target = python_target()?;
        Ok(Self::catalog_versions(
            &catalog::fetch(self.client, &target).await?,
        ))
    }

    fn catalog_versions(downloads: &[catalog::Download]) -> Vec<PythonVersion> {
        downloads
            .iter()
            .map(|download| PythonVersion {
                version: download.version.clone(),
                prerelease: Self::parse_python_version(&download.version)
                    .is_some_and(|(_, prerelease)| prerelease.is_some()),
            })
            .collect()
    }

    /// Build the newest-first version list from standard gzip assets for the
    /// host target. Duplicate versions across release pages collapse to one
    /// entry.
    fn parse_python_versions(releases: &[GithubRelease], target: &str) -> Vec<PythonVersion> {
        let suffix = format!("{target}-install_only.tar.gz");
        let mut seen = std::collections::HashSet::new();
        for release in releases {
            for asset in &release.assets {
                let Some(version) = Self::parse_cpython_version(&asset.name) else {
                    continue;
                };
                if asset.name.ends_with(&suffix) {
                    seen.insert(version);
                }
            }
        }

        let mut result: Vec<PythonVersion> = seen
            .into_iter()
            .map(|version| PythonVersion {
                prerelease: Self::parse_python_version(&version)
                    .is_some_and(|(_, prerelease)| prerelease.is_some()),
                version,
            })
            .collect();
        result.sort_by(|a, b| Self::python_version_cmp(&b.version, &a.version));
        result
    }

    /// Parse a PBS asset version only from the text after `cpython-` and
    /// before the required build-stamp `+`, e.g. `3.14.7` or `3.15.0rc2`.
    fn parse_cpython_version(asset_name: &str) -> Option<String> {
        let (_, tail) = asset_name.split_once("cpython-")?;
        let (raw, _) = tail.split_once('+')?;
        Self::is_python_version(raw).then(|| raw.to_owned())
    }

    fn is_python_version(raw: &str) -> bool {
        Self::parse_python_version(raw).is_some()
    }

    /// Split a raw CPython version into its numeric base and prerelease suffix.
    /// The prerelease rank is `a`=0, `b`=1, `rc`=2. Freethreaded `t` tags and
    /// malformed suffixes are rejected.
    fn parse_python_version(raw: &str) -> Option<(&str, Option<(u8, u32)>)> {
        let (base, suffix) = raw.split_at(
            raw.find(|c: char| c.is_ascii_alphabetic())
                .unwrap_or(raw.len()),
        );
        let prerelease = if suffix.is_empty() {
            None
        } else {
            let (rank, number) = if let Some(rest) = suffix.strip_prefix("rc") {
                (2u8, rest)
            } else if let Some(rest) = suffix.strip_prefix('b') {
                (1u8, rest)
            } else if let Some(rest) = suffix.strip_prefix('a') {
                (0u8, rest)
            } else {
                return None;
            };
            Some((rank, number.parse::<u32>().ok()?))
        };
        let mut parts = base.split('.');
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(major), Some(minor), Some(patch), None)
                if [major, minor, patch]
                    .iter()
                    .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit())) => {}
            _ => return None,
        }
        Some((base, prerelease))
    }

    /// Order CPython versions by numeric precedence with `a` < `b` < `rc`
    /// and every prerelease below its own stable version (`3.15.0rc2` <
    /// `3.15.0`). Unparsable inputs fall back to the shared version order.
    fn python_version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        match (Self::parse_python_version(a), Self::parse_python_version(b)) {
            (Some((base_a, pre_a)), Some((base_b, pre_b))) => {
                let base = Self::numeric_component_cmp(base_a, base_b);
                if base != Ordering::Equal {
                    return base;
                }
                match (pre_a, pre_b) {
                    (None, None) => Ordering::Equal,
                    (None, Some(_)) => Ordering::Greater,
                    (Some(_), None) => Ordering::Less,
                    (Some((rank_a, serial_a)), Some((rank_b, serial_b))) => {
                        rank_a.cmp(&rank_b).then(serial_a.cmp(&serial_b))
                    }
                }
            }
            _ => version_cmp(a, b),
        }
    }

    fn numeric_component_cmp(a: &str, b: &str) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        let mut left = a.split('.');
        let mut right = b.split('.');
        loop {
            match (left.next(), right.next()) {
                (None, None) => return Ordering::Equal,
                (l, r) => {
                    let l = l.unwrap_or("0").parse::<u64>().unwrap_or(0);
                    let r = r.unwrap_or("0").parse::<u64>().unwrap_or(0);
                    if l != r {
                        return l.cmp(&r);
                    }
                }
            }
        }
    }

    /// Match only the exact standard gzip suffix `{target}-install_only.tar.gz`
    /// so freethreaded, stripped, and alternate-compression variants never win.
    fn asset_matches_version(name: &str, version: &str, target: &str) -> bool {
        Self::parse_cpython_version(name).as_deref() == Some(version)
            && name.ends_with(&format!("{target}-install_only.tar.gz"))
    }

    /// Install Python - PURE RUST, NO SUBPROCESS
    pub async fn install(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        // A partial request needs the catalog for resolution. Keep that same
        // response for installation so the selected version and artifact agree.
        let mut downloads =
            if super::common::is_partial_version(&version) && !crate::core::paths::test_mode() {
                Some(catalog::fetch(self.client, &python_target()?).await?)
            } else {
                None
            };
        let version = self
            .resolve_requested_version(&version, downloads.as_deref())
            .await?;
        crate::core::security::validate_runtime_version(&version)?;
        let version_dir = self.versions_dir.join(&version);

        if crate::runtimes::common::is_valid_version_dir(&version_dir) {
            print_already_installed("Python", &version);
            return self.use_version(&version);
        }

        if crate::core::paths::test_mode() {
            fs::create_dir_all(version_dir.join("bin"))?;
            fs::write(version_dir.join("bin/python3.12"), "mock")?;
            #[cfg(unix)]
            std::os::unix::fs::symlink("python3.12", version_dir.join("bin/python3"))?;
            #[cfg(not(unix))]
            fs::copy(
                version_dir.join("bin/python3.12"),
                version_dir.join("bin/python3"),
            )?;
            fs::write(
                version_dir.join(super::common::TEST_RUNTIME_MARKER),
                "debug-only synthetic runtime\n",
            )?;
            println!(
                "{} OMG_TEST_MODE active — synthetic Python runtime was not activated",
                style::caution("⚠")
            );
            print_installed("Python", &version);
            return Ok(());
        }

        println!(
            "{} Installing Python {}...\n",
            style::runtime("OMG"),
            style::caution(&version)
        );

        let target = python_target()?;

        println!(
            "{} Finding Python {} release...",
            style::informative("→"),
            version
        );

        let downloads = match downloads.take() {
            Some(downloads) => downloads,
            None => catalog::fetch(self.client, &target).await?,
        };
        let download = match downloads.into_iter().find(|entry| entry.version == version) {
            Some(download) => download,
            None => self.historical_download(&version, &target).await?,
        };
        let asset_name = validate_download_filename(&download.filename)?;
        fs::create_dir_all(&self.versions_dir)?;

        println!("{} Downloading {}...", style::informative("→"), asset_name);
        let download_path = self.versions_dir.join(asset_name);
        download_with_progress(
            self.client,
            &download.url,
            &download_path,
            &download.checksum,
        )
        .await?;

        println!("{} Extracting (pure Rust)...", style::informative("→"));
        let staging = begin_staged_install(&self.versions_dir)?;
        extract_tar_gz(&download_path, staging.path(), 1).await?;
        self.publish_install(&staging, &version)?;

        remove_file_best_effort(&download_path, "runtime archive");

        print_installed("Python", &version);
        self.use_version(&version)?;

        Ok(())
    }

    /// Exact historical versions absent from the supported catalog may still
    /// exist in the bounded release history. Provider errors never reach here.
    async fn historical_download(&self, version: &str, target: &str) -> Result<catalog::Download> {
        let releases = fetch_github_releases(
            self.client,
            PBS_RELEASES_URL,
            PBS_INSTALL_PER_PAGE,
            PBS_INSTALL_MAX_PAGES,
            |release| {
                release
                    .assets
                    .iter()
                    .any(|asset| Self::asset_matches_version(&asset.name, version, target))
            },
        )
        .await
        .context("Failed to fetch Python releases")?;

        anyhow::ensure!(
            Self::parse_python_versions(&releases, target)
                .iter()
                .any(|entry| entry.version == version),
            "Python {version} not found. Try: omg list python --available"
        );

        let asset = releases
            .iter()
            .flat_map(|release| &release.assets)
            .find(|asset| Self::asset_matches_version(&asset.name, version, target))
            .ok_or_else(|| {
                anyhow::anyhow!("Python {version} not found. Try: omg list python --available")
            })?;

        let url = asset
            .browser_download_url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Python release asset has no browser download URL"))?;
        let asset_name = validate_download_filename(&asset.name)?;
        let checksum = asset
            .digest
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Python release asset has no SHA-256 digest"))
            .and_then(|digest| parse_sha256_digest(digest, "GitHub Python release"))?;

        Ok(catalog::Download {
            version: version.to_owned(),
            url: url.to_owned(),
            filename: asset_name.to_owned(),
            checksum,
        })
    }

    fn publish_install(&self, staging: &tempfile::TempDir, version: &str) -> Result<()> {
        super::common::require_internal_runtime_binary(staging.path(), Path::new("bin/python3"))?;
        complete_staged_install(staging, &self.versions_dir.join(version), version)
    }

    /// Resolve a partial version request (`3`, `3.12`) to the newest matching
    /// stable python-build-standalone version before any download URL is
    /// built; `asset_matches_version` requires exact string equality, so an
    /// unresolved partial would never match an asset. Prerelease entries are
    /// ignored, exact and non-numeric requests pass through unchanged, and
    /// exact prerelease requests may install.
    async fn resolve_requested_version(
        &self,
        version: &str,
        downloads: Option<&[catalog::Download]>,
    ) -> Result<String> {
        if !crate::runtimes::common::is_partial_version(version) {
            return Ok(version.to_owned());
        }
        let available = match downloads {
            Some(downloads) => Self::catalog_versions(downloads),
            None => self.list_available().await?,
        };
        let names: Vec<String> = available
            .into_iter()
            .filter(|entry| !entry.prerelease)
            .map(|entry| entry.version)
            .collect();
        let resolved = crate::runtimes::resolve_version_request(&names, version);
        anyhow::ensure!(
            Self::is_python_version(&resolved),
            "No stable Python version matches {version}. Try: omg list python --available"
        );
        Ok(resolved)
    }

    /// Switch to a specific version
    pub fn use_version(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        activate_version_with_linked_binary(
            &self.versions_dir,
            &version,
            Path::new("bin/python3"),
        )?;
        print_using("Python", &version, &self.versions_dir.join("current/bin"));
        Ok(())
    }

    /// Remove an installed version. Refuses the active version.
    pub fn uninstall(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        super::common::uninstall_version(&self.versions_dir, &version)
    }
}

// Generate common runtime manager methods (list_installed, current_version)
crate::runtimes::common::impl_runtime_common!(PythonManager);

fn python_target() -> Result<String> {
    let arch = match std::env::consts::ARCH {
        "x86_64" | "aarch64" => std::env::consts::ARCH,
        arch => anyhow::bail!("Unsupported architecture for Python: {arch}"),
    };
    match std::env::consts::OS {
        "linux" => Ok(format!("{arch}-unknown-linux-gnu")),
        "macos" => Ok(format!("{arch}-apple-darwin")),
        other => anyhow::bail!("Unsupported operating system for Python: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn catalog_resolution_reuses_entries_and_refuses_missing_partial_versions() -> Result<()>
    {
        let manager = PythonManager::new();
        let downloads: Vec<_> = ["3.15.0rc2", "3.14.7", "3.12.14", "3.12.13"]
            .into_iter()
            .map(|version| catalog::Download {
                version: version.to_owned(),
                url: String::new(),
                filename: String::new(),
                checksum: String::new(),
            })
            .collect();
        assert_eq!(
            manager
                .resolve_requested_version("3", Some(&downloads))
                .await?,
            "3.14.7"
        );
        assert_eq!(
            manager
                .resolve_requested_version("3.12", Some(&downloads))
                .await?,
            "3.12.14"
        );
        assert_eq!(
            manager.resolve_requested_version("3.15.0rc2", None).await?,
            "3.15.0rc2"
        );
        assert!(
            manager
                .resolve_requested_version("3.99", Some(&downloads))
                .await
                .is_err(),
            "an unresolved partial request must not start the exact-version GitHub history fallback"
        );
        Ok(())
    }

    #[tokio::test]
    async fn install_discovery_uses_small_pages_without_shortening_history() -> Result<()> {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/releases", listener.local_addr()?);
        let client = reqwest::Client::builder().no_proxy().build()?;
        let server = async {
            let mut requests = 0;
            loop {
                let (mut stream, _) = listener.accept().await?;
                let request = {
                    let mut reader = BufReader::new(&mut stream).take(8192);
                    let mut first = String::new();
                    reader.read_line(&mut first).await?;
                    loop {
                        let mut line = String::new();
                        anyhow::ensure!(
                            reader.read_line(&mut line).await? > 0,
                            "Incomplete fixture request"
                        );
                        if line == "\r\n" {
                            break;
                        }
                    }
                    first
                };
                let target = request
                    .split_whitespace()
                    .nth(1)
                    .context("Missing request target")?;
                let parsed = reqwest::Url::parse(&format!("http://localhost{target}"))?;
                let query: std::collections::HashMap<_, _> =
                    parsed.query_pairs().into_owned().collect();
                let size: usize = query
                    .get("per_page")
                    .context("Missing page size")?
                    .parse()?;
                let page: usize = query.get("page").context("Missing page number")?.parse()?;
                requests += 1;
                if size > 10 {
                    stream.write_all(b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
                    return Ok::<_, anyhow::Error>(requests);
                }
                anyhow::ensure!(
                    size > 0 && page > 0 && page <= 200,
                    "Invalid pagination request"
                );
                let end = (page * size).min(200);
                let releases: Vec<_> = ((page - 1) * size..end).map(|index| {
                    let assets = if index == 199 {
                        vec![serde_json::json!({"name": "cpython-3.12.14+20260901-x86_64-unknown-linux-gnu-install_only.tar.gz"})]
                    } else { Vec::new() };
                    serde_json::json!({"tag_name": index.to_string(), "assets": assets})
                }).collect();
                let body = serde_json::to_vec(&releases)?;
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await?;
                stream.write_all(&body).await?;
                if end == 200 {
                    return Ok(requests);
                }
            }
        };
        let discovery = fetch_github_releases(
            &client,
            &url,
            PBS_INSTALL_PER_PAGE,
            PBS_INSTALL_MAX_PAGES,
            |release| {
                release.assets.iter().any(|asset| {
                    PythonManager::asset_matches_version(
                        &asset.name,
                        "3.12.14",
                        "x86_64-unknown-linux-gnu",
                    )
                })
            },
        );
        let (fetched, served) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(discovery, server)
        })
        .await
        .context("Release discovery did not finish within its fixture deadline")?;
        let releases = fetched.context("Bounded release discovery must succeed")?;
        // Same 200-release history as before, reached in twice as many
        // half-size pages now that one 10-release page exceeds the 16MiB
        // control-plane bound.
        assert_eq!(served?, 40);
        assert_eq!(releases.len(), 200);
        assert!(
            releases
                .last()
                .is_some_and(|release| release.tag_name == "199")
        );
        Ok(())
    }

    /// python-build-standalone releases carry ~1000 assets each (~1.9MB of
    /// release metadata per release), so a 10-release page no longer fits
    /// the 16MiB control-plane bound and `use python` fails before any
    /// download. Discovery pages must stay small enough that one fat page
    /// fits the bound while still reaching deep history.
    #[tokio::test]
    async fn install_discovery_survives_realistic_asset_counts() -> Result<()> {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        const RELEASES: usize = 50;
        const FILLER_ASSETS: usize = 1000;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/releases", listener.local_addr()?);
        let client = reqwest::Client::builder().no_proxy().build()?;
        let server = async {
            let mut requests = 0;
            loop {
                let (mut stream, _) = listener.accept().await?;
                let request = {
                    let mut reader = BufReader::new(&mut stream).take(8192);
                    let mut first = String::new();
                    reader.read_line(&mut first).await?;
                    loop {
                        let mut line = String::new();
                        anyhow::ensure!(
                            reader.read_line(&mut line).await? > 0,
                            "Incomplete fixture request"
                        );
                        if line == "\r\n" {
                            break;
                        }
                    }
                    first
                };
                let target = request
                    .split_whitespace()
                    .nth(1)
                    .context("Missing request target")?;
                let parsed = reqwest::Url::parse(&format!("http://localhost{target}"))?;
                let query: std::collections::HashMap<_, _> =
                    parsed.query_pairs().into_owned().collect();
                let size: usize = query
                    .get("per_page")
                    .context("Missing page size")?
                    .parse()?;
                let page: usize = query.get("page").context("Missing page number")?.parse()?;
                requests += 1;
                anyhow::ensure!(size > 0 && page > 0, "Invalid pagination request");
                let end = (page * size).min(RELEASES);
                let releases: Vec<_> = ((page - 1) * size..end)
                    .map(|index| {
                        let mut assets: Vec<_> = (0..FILLER_ASSETS)
                            .map(|filler| {
                                serde_json::json!({"name": format!("bulk-filler-{filler:06}-{:-<1900}", "")})
                            })
                            .collect();
                        if index == RELEASES - 1 {
                            assets.push(serde_json::json!({"name": "cpython-3.12.0+20231002-x86_64-unknown-linux-gnu-install_only.tar.gz"}));
                        }
                        serde_json::json!({"tag_name": index.to_string(), "assets": assets})
                    })
                    .collect();
                let body = serde_json::to_vec(&releases)?;
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await?;
                stream.write_all(&body).await?;
                if end == RELEASES {
                    return Ok::<_, anyhow::Error>(requests);
                }
            }
        };
        let discovery = fetch_github_releases(
            &client,
            &url,
            PBS_INSTALL_PER_PAGE,
            PBS_INSTALL_MAX_PAGES,
            |release| {
                release.assets.iter().any(|asset| {
                    PythonManager::asset_matches_version(
                        &asset.name,
                        "3.12.0",
                        "x86_64-unknown-linux-gnu",
                    )
                })
            },
        );
        let (fetched, served) = tokio::time::timeout(std::time::Duration::from_mins(1), async {
            tokio::join!(discovery, server)
        })
        .await
        .context("Release discovery did not finish within its fixture deadline")?;
        let releases = fetched.context("Fat-page discovery must stay under the metadata bound")?;
        assert_eq!(served?, RELEASES / PBS_INSTALL_PER_PAGE as usize);
        assert!(
            releases
                .iter()
                .any(|release| release.tag_name == (RELEASES - 1).to_string()),
            "deep history must still be reachable with small pages"
        );
        Ok(())
    }

    #[test]
    fn test_python_manager_new() {
        let mgr = PythonManager::new();
        assert!(mgr.versions_dir.ends_with("python"));
    }

    #[test]
    fn test_extract_cpython_version() {
        assert_eq!(
            PythonManager::parse_cpython_version(
                "cpython-3.12.0+20231002-x86_64-unknown-linux-gnu-install_only.tar.gz"
            ),
            Some("3.12.0".to_string())
        );
        assert_eq!(
            PythonManager::parse_cpython_version(
                "cpython-3.15.0rc2+20250708-x86_64-unknown-linux-gnu-install_only.tar.gz"
            ),
            Some("3.15.0rc2".to_string())
        );
        // A `+` build stamp is required.
        assert_eq!(
            PythonManager::parse_cpython_version("cpython-3.11.5-x86_64.tar.gz"),
            None
        );
    }

    #[test]
    fn rc_and_stable_prerelease_forms_parse() {
        assert!(PythonManager::is_python_version("3.14.7"));
        assert!(PythonManager::is_python_version("3.15.0rc2"));
        assert!(PythonManager::is_python_version("3.15.0rc10"));
        assert!(PythonManager::is_python_version("3.15.0b1"));
        assert!(PythonManager::is_python_version("3.15.0a4"));
        assert!(PythonManager::is_python_version("3.14.0rc1"));
    }

    #[test]
    fn malformed_and_variant_version_forms_are_rejected() {
        for malformed in [
            "3.14",
            "3",
            "",
            "3..7",
            ".3.14.7",
            "3.14.7.",
            "3.14.7+extra",
            "3.14.7rc",
            "3.14.7rcx",
            "3.14.7c1",
            "3.14.7r1",
            "3.13.0t",
            "3.14.7a-1",
            "3.14.7-x86_64",
        ] {
            assert!(
                !PythonManager::is_python_version(malformed),
                "malformed version {malformed:?} must be rejected"
            );
        }
    }

    #[test]
    fn asset_variants_other_than_the_standard_gzip_suffix_are_rejected() {
        let target = "x86_64-unknown-linux-gnu";
        let matching = "cpython-3.14.7+20260825-x86_64-unknown-linux-gnu-install_only.tar.gz";
        assert!(PythonManager::asset_matches_version(
            matching, "3.14.7", target
        ));

        for (name, requested) in [
            (
                "cpython-3.14.7t+20260825-x86_64-unknown-linux-gnu-freethreaded-install_only.tar.gz",
                "3.14.7",
            ),
            (
                "cpython-3.14.7+20260825-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz",
                "3.14.7",
            ),
            (
                "cpython-3.14.7+20260825-x86_64-unknown-linux-gnu-install_only.tar.zst",
                "3.14.7",
            ),
            (
                "cpython-3.14.7+20260825-x86_64-unknown-linux-gnu.tar.gz",
                "3.14.7",
            ),
        ] {
            assert!(
                !PythonManager::asset_matches_version(name, requested, target),
                "variant asset {name:?} must not match"
            );
        }
    }

    fn single_asset_release(tag: &str, prerelease: bool, asset: &str) -> GithubRelease {
        GithubRelease {
            tag_name: tag.to_string(),
            prerelease,
            assets: vec![super::super::common::GithubAsset {
                name: asset.to_string(),
                browser_download_url: None,
                digest: None,
            }],
        }
    }

    fn stable_release(tag: &str, asset: &str) -> GithubRelease {
        single_asset_release(tag, false, asset)
    }

    fn prerelease_release(tag: &str, asset: &str) -> GithubRelease {
        single_asset_release(tag, true, asset)
    }

    #[test]
    fn versions_dedupe_and_sort_newest_first_with_prerelease_precedence() {
        let versions = PythonManager::parse_python_versions(
            &[
                stable_release(
                    "20260825",
                    "cpython-3.14.7+20260825-x86_64-unknown-linux-gnu-install_only.tar.gz",
                ),
                prerelease_release(
                    "20260710",
                    "cpython-3.15.0rc2+20260710-x86_64-unknown-linux-gnu-install_only.tar.gz",
                ),
                stable_release(
                    "20260701",
                    "cpython-3.14.7+20260701-x86_64-unknown-linux-gnu-install_only.tar.gz",
                ),
                stable_release(
                    "20260620",
                    "cpython-3.15.0+20260620-x86_64-unknown-linux-gnu-install_only.tar.gz",
                ),
                prerelease_release(
                    "20260601",
                    "cpython-3.15.0rc1+20260601-x86_64-unknown-linux-gnu-install_only.tar.gz",
                ),
                stable_release(
                    "20260501",
                    "cpython-3.13.9+20260501-x86_64-unknown-linux-gnu-install_only.tar.gz",
                ),
            ],
            "x86_64-unknown-linux-gnu",
        );

        assert_eq!(
            versions,
            vec![
                PythonVersion {
                    version: "3.15.0".to_string(),
                    prerelease: false
                },
                PythonVersion {
                    version: "3.15.0rc2".to_string(),
                    prerelease: true
                },
                PythonVersion {
                    version: "3.15.0rc1".to_string(),
                    prerelease: true
                },
                PythonVersion {
                    version: "3.14.7".to_string(),
                    prerelease: false
                },
                PythonVersion {
                    version: "3.13.9".to_string(),
                    prerelease: false
                },
            ]
        );
    }

    #[test]
    fn duplicate_assets_dedupe_independent_of_the_github_release_flag() {
        for releases in [
            vec![
                prerelease_release(
                    "a",
                    "cpython-3.14.0+20260101-x86_64-unknown-linux-gnu-install_only.tar.gz",
                ),
                stable_release(
                    "b",
                    "cpython-3.14.0+20260201-x86_64-unknown-linux-gnu-install_only.tar.gz",
                ),
            ],
            vec![
                stable_release(
                    "b",
                    "cpython-3.14.0+20260201-x86_64-unknown-linux-gnu-install_only.tar.gz",
                ),
                prerelease_release(
                    "a",
                    "cpython-3.14.0+20260101-x86_64-unknown-linux-gnu-install_only.tar.gz",
                ),
            ],
        ] {
            let versions =
                PythonManager::parse_python_versions(&releases, "x86_64-unknown-linux-gnu");
            assert_eq!(
                versions,
                vec![PythonVersion {
                    version: "3.14.0".to_string(),
                    prerelease: false
                }]
            );
        }
    }

    #[test]
    fn python_version_cmp_orders_prerelease_serials_numerically() {
        use std::cmp::Ordering;
        assert_eq!(
            PythonManager::python_version_cmp("3.15.0rc2", "3.15.0rc10"),
            Ordering::Less
        );
        assert_eq!(
            PythonManager::python_version_cmp("3.15.0", "3.15.0rc2"),
            Ordering::Greater
        );
        assert_eq!(
            PythonManager::python_version_cmp("3.15.0a1", "3.15.0b1"),
            Ordering::Less
        );
        assert_eq!(
            PythonManager::python_version_cmp("3.14.7", "3.15.0rc2"),
            Ordering::Less
        );
    }

    #[test]
    fn stable_only_versions_exclude_prereleases_for_partial_resolution() {
        let available = [
            PythonVersion {
                version: "3.15.0rc2".to_string(),
                prerelease: true,
            },
            PythonVersion {
                version: "3.14.7".to_string(),
                prerelease: false,
            },
            PythonVersion {
                version: "3.14.0".to_string(),
                prerelease: false,
            },
        ];
        let stable: Vec<String> = available
            .iter()
            .filter(|entry| !entry.prerelease)
            .map(|entry| entry.version.clone())
            .collect();
        assert_eq!(
            crate::runtimes::common::resolve_partial_version(&stable, "3.14").as_deref(),
            Some("3.14.7")
        );
        assert_eq!(
            crate::runtimes::common::resolve_partial_version(&stable, "3.15").as_deref(),
            None,
            "a prerelease-only line must not satisfy a partial request"
        );
    }

    #[test]
    fn asset_version_matching_is_component_bounded() {
        let name = "cpython-3.10.21+20260825-x86_64-unknown-linux-gnu-install_only.tar.gz";
        assert!(PythonManager::asset_matches_version(
            name,
            "3.10.21",
            "x86_64-unknown-linux-gnu"
        ));
        assert!(!PythonManager::asset_matches_version(
            name,
            "3.1",
            "x86_64-unknown-linux-gnu"
        ));
        assert!(!PythonManager::asset_matches_version(
            name,
            "3.10",
            "x86_64-unknown-linux-gnu"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn python_publication_rejects_missing_and_external_launchers() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let manager = PythonManager {
            versions_dir: directory.path().to_path_buf(),
            client: download_client(),
        };
        let staging = begin_staged_install(directory.path())?;
        assert!(manager.publish_install(&staging, "3.12.0").is_err());
        assert!(!directory.path().join("3.12.0").exists());
        assert!(manager.list_installed()?.is_empty());

        fs::create_dir(staging.path().join("bin"))?;
        let outside = directory.path().join("outside-python");
        fs::write(&outside, "fixture")?;
        let launcher = staging.path().join("bin/python3");
        std::os::unix::fs::symlink(&outside, &launcher)?;
        assert!(manager.publish_install(&staging, "3.12.0").is_err());
        assert!(!directory.path().join("3.12.0").exists());

        fs::remove_file(&launcher)?;
        fs::write(staging.path().join("bin/python3.12"), "fixture")?;
        std::os::unix::fs::symlink("python3.12", &launcher)?;
        manager.publish_install(&staging, "3.12.0")?;
        manager.use_version("3.12.0")?;
        assert_eq!(manager.list_installed()?, vec!["3.12.0"]);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn python_manager_activates_vendor_symlink_layout() {
        let temp = tempfile::tempdir().expect("temp dir");
        let version_dir = temp.path().join("3.12.0");
        fs::create_dir_all(version_dir.join("bin")).expect("bin dir");
        fs::write(version_dir.join("bin/python3.12"), b"python").expect("python binary");
        std::os::unix::fs::symlink("python3.12", version_dir.join("bin/python3"))
            .expect("vendor launcher link");
        let manager = PythonManager {
            versions_dir: temp.path().to_path_buf(),
            client: download_client(),
        };

        manager
            .use_version("3.12.0")
            .expect("vendor layout must activate");

        assert_eq!(
            fs::read_link(temp.path().join("current")).expect("current link"),
            version_dir
        );
    }

    #[test]
    fn partial_request_resolves_to_the_newest_matching_python_fixture() {
        let names = ["3.12.0", "3.12.8", "3.11.0"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            crate::runtimes::common::resolve_partial_version(&names, "3.12").as_deref(),
            Some("3.12.8")
        );
        assert_eq!(
            crate::runtimes::common::resolve_partial_version(&names, "3").as_deref(),
            Some("3.12.8")
        );
    }

    #[test]
    fn python_target_uses_host_os_and_arch() {
        let target = python_target().expect("host platform should be supported");
        if std::env::consts::OS == "linux" {
            assert!(target.contains("linux-gnu"));
        } else {
            assert!(!target.contains("linux-gnu"));
        }
    }
}
