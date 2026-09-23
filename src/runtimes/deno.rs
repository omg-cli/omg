//! Deno runtime manager.
//!
//! Installs official `denoland/deno` release ZIPs. Activation exposes the
//! complete `<version>/bin` directory without command shims.

use crate::core::http::BoundedResponseExt;
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use super::common::{
    GITHUB_USER_AGENT, GithubAsset, GithubRelease, activate_version, begin_download,
    begin_staged_install, complete_staged_install, download_with_progress, extract_zip,
    fetch_github_releases, normalize_version, parse_sha256_digest, print_already_installed,
    print_installed, print_using, require_regular_file, validate_download_filename, version_cmp,
};
use crate::{cli::style, core::http::download_client};

const DENO_API_URL: &str = "https://api.github.com/repos/denoland/deno/releases";

/// Bounded listing window: one page of the 30 newest releases is far more
/// than any `latest` or partial-version resolution needs.
const DENO_LIST_PER_PAGE: u32 = 30;
const DENO_LIST_MAX_PAGES: u32 = 1;

/// Upper bound for the official checksum sidecar text asset.
const MAX_CHECKSUM_SIDECAR_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct DenoVersion {
    pub(crate) version: String,
    pub(crate) prerelease: bool,
}

pub(crate) struct DenoManager {
    versions_dir: PathBuf,
    client: &'static reqwest::Client,
}

impl DenoManager {
    pub fn new() -> Self {
        Self {
            versions_dir: super::DATA_DIR.join("versions/deno"),
            client: download_client(),
        }
    }

    #[cfg(test)]
    fn with_paths(versions_dir: PathBuf) -> Self {
        Self {
            versions_dir,
            client: download_client(),
        }
    }

    pub async fn list_available(&self) -> Result<Vec<DenoVersion>> {
        let releases = fetch_github_releases(
            self.client,
            DENO_API_URL,
            DENO_LIST_PER_PAGE,
            DENO_LIST_MAX_PAGES,
            |_| false,
        )
        .await
        .context("Failed to fetch Deno releases from GitHub")?;

        Ok(parse_deno_versions(releases))
    }

    /// Resolve Deno aliases. `latest` maps to the newest stable release;
    /// everything else — including an exact prerelease tag — passes through.
    pub async fn resolve_alias(&self, alias: &str) -> Result<String> {
        let alias = normalize_version(alias);
        if alias == "latest" {
            let versions = self.list_available().await?;
            pick_latest_stable(versions).context("No Deno versions found upstream")
        } else {
            Ok(alias)
        }
    }

    pub async fn install(&self, version: &str) -> Result<()> {
        let version = self.resolve_alias(version).await?;
        let version = self.resolve_requested_version(&version).await?;
        crate::core::security::validate_runtime_version(&version)?;
        let version_dir = self.versions_dir.join(&version);

        if crate::runtimes::common::is_valid_version_dir(&version_dir) {
            print_already_installed("Deno", &version);
            return self.use_version(&version);
        }

        println!(
            "{} Installing Deno {}...\n",
            style::runtime("OMG"),
            style::caution(&version)
        );

        let filename = format!("deno-{}.zip", deno_target()?);

        fs::create_dir_all(&self.versions_dir)?;

        println!(
            "{} Fetching Deno v{} release metadata...",
            style::informative("→"),
            version
        );
        let release = self.release_metadata(&version).await?;
        let zip_asset = select_deno_asset(&release.assets, &filename)?;
        validate_download_filename(&zip_asset.name)?;
        let url = zip_asset
            .browser_download_url
            .clone()
            .context("Deno vendor ZIP has no browser download URL")?;
        let checksum = self.checksum_for_asset(&release, &filename).await?;

        println!(
            "{} Downloading Deno v{}...",
            style::informative("→"),
            version
        );
        let download = begin_download(&self.versions_dir)?;
        let download_path = download.path().join(&filename);
        download_with_progress(self.client, &url, &download_path, &checksum).await?;

        println!("{} Extracting...", style::informative("→"));
        let staging = begin_staged_install(&self.versions_dir)?;
        // Vendor ZIPs carry `deno` at the archive root, so strip 0 lands it
        // at `<version>/bin/deno` and any future sibling tools beside it.
        let staging_bin = staging.path().join("bin");
        extract_zip(&download_path, &staging_bin, 0).await?;
        // Publish only a complete vendor tree: the native command must be a
        // real regular file before the version directory can exist at all.
        require_regular_file(&staging.path().join("bin").join("deno"))?;
        complete_staged_install(&staging, &version_dir, &version)?;

        print_installed("Deno", &version);
        self.use_version(&version)?;

        Ok(())
    }

    /// Fetch the exact release metadata for one Deno tag.
    async fn release_metadata(&self, version: &str) -> Result<GithubRelease> {
        self.client
            .get(format!("{DENO_API_URL}/tags/v{version}"))
            .header("User-Agent", GITHUB_USER_AGENT)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .context("Failed to fetch Deno release metadata")?
            .error_for_status()
            .context("Deno release metadata request failed")?
            .bounded_json()
            .await
            .context("Failed to parse Deno release metadata")
    }

    /// Resolve the SHA-256 checksum for the vendor ZIP: prefer the GitHub
    /// asset digest, falling back (bounded) to the official
    /// `{filename}.sha256sum` asset for older releases without digests.
    async fn checksum_for_asset(&self, release: &GithubRelease, filename: &str) -> Result<String> {
        let asset = select_deno_asset(&release.assets, filename)?;
        if let Some(digest) = asset.digest.as_deref() {
            return parse_sha256_digest(digest, "GitHub Deno release");
        }

        let sidecar = select_deno_asset(&release.assets, &format!("{filename}.sha256sum"))
            .context("Deno release has neither an asset digest nor a checksum sidecar")?;
        let url = sidecar
            .browser_download_url
            .as_deref()
            .context("Deno checksum sidecar has no browser download URL")?;
        fetch_checksum_sidecar(self.client, url, filename).await
    }

    /// Resolve a partial version request (`2`, `2.9`) to the newest matching
    /// stable Deno release before any release metadata is fetched; the
    /// release-tag lookup is exact-string, so an unresolved partial would
    /// 404. Like `latest`, partial resolution never picks a prerelease.
    /// Exact requests — including exact prerelease tags — pass through
    /// unchanged, preserving the already-installed fast path and the
    /// existing not-found UX.
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

    pub fn use_version(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        // Activation requires `<version>/bin/deno` to be a regular file and
        // then exposes the whole `<version>/bin` directory through the
        // current link, so sibling tools pass through without shims.
        activate_version(&self.versions_dir, &version, Path::new("bin/deno"))?;
        print_using("Deno", &version, &self.versions_dir.join("current/bin"));
        Ok(())
    }

    pub fn uninstall(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        super::common::uninstall_version(&self.versions_dir, &version)
    }
}

// Generate common runtime manager methods (list_installed, current_version)
crate::runtimes::common::impl_runtime_common!(DenoManager);

/// Map a host OS/architecture pair to an official Deno release triple.
///
/// Deno publishes `x86_64`/`aarch64` builds for Linux (gnu) and macOS; a
/// `None` result means the host combination has no official vendor ZIP.
#[must_use]
fn deno_triple(os: &str, arch: &str) -> Option<&'static str> {
    match (os, arch) {
        ("linux", "x86_64") => Some("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-gnu"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        _ => None,
    }
}

fn deno_target() -> Result<&'static str> {
    let os = super::common::host_os_tag("Deno", "linux", "macos")?;
    let arch = super::common::host_arch_tag("Deno", "x86_64", "aarch64")?;
    deno_triple(os, arch)
        .ok_or_else(|| anyhow::anyhow!("Unsupported Deno target for this host: {os}-{arch}"))
}

/// Fetch a bounded checksum sidecar and pin the digest for `filename`.
///
/// The sidecar is a `sha256sum`-style manifest (`<hex>  <filename>`); only
/// the line naming the vendor ZIP may contribute a digest.
async fn fetch_checksum_sidecar(
    _client: &reqwest::Client,
    url: &str,
    filename: &str,
) -> Result<String> {
    let response = crate::core::http::fetch_public_download_with_timeout(
        url,
        GITHUB_USER_AGENT,
        Some(std::time::Duration::from_secs(30)),
    )
    .await
    .with_context(|| format!("Failed to fetch Deno checksum sidecar from {url}"))?
    .error_for_status()
    .with_context(|| format!("Deno checksum sidecar request failed: {url}"))?;

    let length = response.content_length().unwrap_or(0);
    anyhow::ensure!(
        length <= MAX_CHECKSUM_SIDECAR_BYTES,
        "Deno checksum sidecar declares {length} bytes, exceeding the \
         {MAX_CHECKSUM_SIDECAR_BYTES}-byte limit"
    );

    use futures::StreamExt as _;

    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.with_context(|| format!("Failed to read Deno checksum sidecar: {url}"))?;
        let next_len = body
            .len()
            .checked_add(chunk.len())
            .context("Deno checksum sidecar size overflow")?;
        anyhow::ensure!(
            u64::try_from(next_len).context("Deno checksum sidecar length is unsupported")?
                <= MAX_CHECKSUM_SIDECAR_BYTES,
            "Deno checksum sidecar exceeds the {MAX_CHECKSUM_SIDECAR_BYTES}-byte limit"
        );
        body.extend_from_slice(&chunk);
    }
    let text = std::str::from_utf8(&body)
        .with_context(|| format!("Deno checksum sidecar is not UTF-8: {url}"))?;
    let digest_line = text
        .lines()
        .find(|line| line.split_whitespace().nth(1) == Some(filename))
        .ok_or_else(|| {
            anyhow::anyhow!("Checksum not found for {filename} in the official sidecar")
        })?;
    parse_sha256_digest(digest_line, url)
}

/// Select one release asset by exact vendor filename.
///
/// An exact match is the only accepted form, so `denort-*.zip`,
/// `*.bsdiff` delta patches, `*.sha256sum` sidecars, and source archives
/// can never be selected for the runtime ZIP.
fn select_deno_asset<'a>(assets: &'a [GithubAsset], filename: &str) -> Result<&'a GithubAsset> {
    assets
        .iter()
        .find(|asset| asset.name == filename)
        .ok_or_else(|| anyhow::anyhow!("Deno release asset not found: {filename}"))
}

/// Parse GitHub releases into deterministic newest-first Deno versions.
///
/// Tags are `v`-prefixed (`v2.9.6`); a single leading `v` is normalized and
/// empty tags are dropped.
fn parse_deno_versions(releases: Vec<GithubRelease>) -> Vec<DenoVersion> {
    let mut versions: Vec<DenoVersion> = releases
        .into_iter()
        .filter_map(|release| {
            let version = normalize_version(&release.tag_name);
            semver::Version::parse(&version)
                .is_ok()
                .then_some(DenoVersion {
                    version,
                    prerelease: release.prerelease,
                })
        })
        .collect();
    // The GitHub API orders rows by creation date, not by version; sort so
    // "latest" and listing output are deterministic.
    versions.sort_by(|a, b| version_cmp(&b.version, &a.version));
    versions
}

/// Pick the newest non-prerelease version, so `latest` never pins an RC.
fn pick_latest_stable(versions: Vec<DenoVersion>) -> Option<String> {
    versions
        .into_iter()
        .find(|version| !version.prerelease)
        .map(|version| version.version)
}

/// Flatten Deno releases into stable version numbers for partial resolution.
fn available_version_names(versions: &[DenoVersion]) -> Vec<String> {
    versions
        .iter()
        .filter(|version| !version.prerelease)
        .map(|version| version.version.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn checksum_sidecar_rejects_plain_http_before_request() {
        let error = fetch_checksum_sidecar(
            download_client(),
            "http://192.0.2.1/checksums.sha256sum",
            "deno.zip",
        )
        .await
        .expect_err("plain HTTP sidecar must be rejected");
        assert!(format!("{error:#}").contains("HTTPS"));
    }

    fn ver(version: &str, prerelease: bool) -> DenoVersion {
        DenoVersion {
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

    fn asset(name: &str) -> GithubAsset {
        GithubAsset {
            name: name.to_string(),
            browser_download_url: None,
            digest: None,
        }
    }

    #[test]
    fn deno_versions_are_parsed_and_sorted_newest_first() {
        let versions = parse_deno_versions(vec![
            release("v2.1.4", false),
            release("v2.1.0", false),
            release("v2.2.0-rc.1", true),
            release("v2.1.7", false),
        ]);

        let names: Vec<&str> = versions.iter().map(|v| v.version.as_str()).collect();
        assert_eq!(names, vec!["2.2.0-rc.1", "2.1.7", "2.1.4", "2.1.0"]);
        assert!(versions[0].prerelease, "prerelease flags must survive");
        assert!(!versions[1].prerelease);
    }

    #[test]
    fn leading_v_is_normalized_and_empty_tags_are_dropped() {
        let versions = parse_deno_versions(vec![
            release("v2.1.4", false),
            release("", false),
            release("canary", false),
        ]);

        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, "2.1.4");
    }

    #[test]
    fn latest_alias_never_picks_a_prerelease() {
        let versions = parse_deno_versions(vec![
            release("v2.2.0-rc.1", true),
            release("v2.1.4", false),
            release("v2.1.0", false),
        ]);

        assert_eq!(pick_latest_stable(versions), Some("2.1.4".to_string()));
        assert_eq!(pick_latest_stable(Vec::new()), None);
        assert_eq!(pick_latest_stable(vec![ver("2.2.0-rc.1", true)]), None);
    }

    #[test]
    fn partial_requests_resolve_to_the_newest_stable_deno() {
        let fixtures = [
            ver("2.2.0-rc.1", true),
            ver("2.1.7", false),
            ver("2.1.4", false),
            ver("2.0.0", false),
        ];
        let names = available_version_names(&fixtures);
        // Prereleases never participate in partial resolution.
        assert_eq!(
            crate::runtimes::common::resolve_partial_version(&names, "2.1").as_deref(),
            Some("2.1.7")
        );
        assert_eq!(
            crate::runtimes::common::resolve_partial_version(&names, "2").as_deref(),
            Some("2.1.7")
        );
        assert_eq!(
            crate::runtimes::common::resolve_partial_version(&names, "2.0").as_deref(),
            Some("2.0.0")
        );
        assert_eq!(
            crate::runtimes::common::resolve_partial_version(&names, "3"),
            None
        );
    }

    #[test]
    fn exact_prerelease_requests_pass_through_alias_resolution() {
        // `resolve_alias` rewrites only `latest`; every other request — exact
        // stable or exact prerelease — is normalized and returned unchanged.
        assert_eq!(normalize_version("v2.2.0-rc.1"), "2.2.0-rc.1");
        assert_eq!(normalize_version("2.2.0-rc.1"), "2.2.0-rc.1");
        assert_eq!(normalize_version("v2.1.4"), "2.1.4");
    }

    #[test]
    fn official_deno_triples_map_exactly() {
        assert_eq!(
            deno_triple("linux", "x86_64"),
            Some("x86_64-unknown-linux-gnu")
        );
        assert_eq!(
            deno_triple("linux", "aarch64"),
            Some("aarch64-unknown-linux-gnu")
        );
        assert_eq!(deno_triple("macos", "x86_64"), Some("x86_64-apple-darwin"));
        assert_eq!(
            deno_triple("macos", "aarch64"),
            Some("aarch64-apple-darwin")
        );
    }

    #[test]
    fn unsupported_host_combinations_have_no_vendor_triple() {
        assert_eq!(deno_triple("windows", "x86_64"), None);
        assert_eq!(deno_triple("freebsd", "x86_64"), None);
        assert_eq!(deno_triple("linux", "riscv64"), None);
        assert_eq!(deno_triple("", ""), None);
    }

    #[test]
    fn only_the_exact_vendor_zip_asset_is_selected() {
        let filename = "deno-x86_64-unknown-linux-gnu.zip";
        let sidecar = format!("{filename}.sha256sum");
        let assets = vec![
            asset("deno-x86_64-unknown-linux-gnu.from-2.9.5.bsdiff"),
            asset("deno-x86_64-unknown-linux-gnu.from-2.9.5.bsdiff.sha256sum"),
            asset("denort-x86_64-unknown-linux-gnu.zip"),
            asset("denort-x86_64-unknown-linux-gnu.zip.sha256sum"),
            asset("lib.deno.d.ts"),
            asset("deno_src.tar.gz"),
            asset(filename),
            asset(&sidecar),
        ];

        let selected = select_deno_asset(&assets, filename).unwrap();
        assert_eq!(selected.name, filename);

        let selected_sidecar = select_deno_asset(&assets, &sidecar).unwrap();
        assert_eq!(selected_sidecar.name, sidecar);
    }

    #[test]
    fn asset_selection_never_matches_decoy_prefixes() {
        let assets = vec![
            asset("denort-x86_64-unknown-linux-gnu.zip"),
            asset("deno-x86_64-unknown-linux-gnu.from-2.9.5.bsdiff"),
            asset("deno-x86_64-unknown-linux-gnu.zip.sha256sum"),
        ];
        assert!(select_deno_asset(&assets, "deno-x86_64-unknown-linux-gnu.zip").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn activation_keeps_sibling_files_in_bin_reachable() {
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let versions_dir = temp.path().join("versions/deno");
        let version_dir = versions_dir.join("2.9.6");
        fs::create_dir_all(version_dir.join("bin")).unwrap();
        fs::write(version_dir.join("bin/deno"), b"#!/bin/sh\n").unwrap();
        fs::write(version_dir.join("bin/deno-lsp"), b"#!/bin/sh\n").unwrap();

        let manager = DenoManager::with_paths(versions_dir.clone());
        manager
            .use_version("2.9.6")
            .expect("activation must succeed");

        assert_eq!(manager.current_version().as_deref(), Some("2.9.6"));
        let current_bin = versions_dir.join("current/bin");
        assert!(current_bin.join("deno").is_file(), "deno must resolve");
        assert!(
            current_bin.join("deno-lsp").is_file(),
            "sibling tools in bin must stay reachable without shims"
        );
    }

    #[cfg(unix)]
    #[test]
    fn activation_fails_closed_without_a_regular_deno_binary() {
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let versions_dir = temp.path().join("versions/deno");
        let version_dir = versions_dir.join("2.9.6");
        fs::create_dir_all(version_dir.join("bin")).unwrap();

        let manager = DenoManager::with_paths(versions_dir);
        let error = manager
            .use_version("2.9.6")
            .expect_err("missing binary must fail activation");

        assert!(
            error
                .to_string()
                .contains("Missing required runtime binary"),
            "activation must name the missing binary, got: {error:#}"
        );
        assert!(manager.current_version().is_none());
    }
}
