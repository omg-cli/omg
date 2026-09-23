//! Generic GitHub-release tool manager (mise `github:`/`ubi` backend parity).
//!
//! The bespoke managers (`node`, `python`, …) each speak a vendor-specific
//! release API. The fifty [`super::tool_registry`] tools instead share one
//! installer: pick the release asset matching the host OS/arch, verify its
//! SHA-256 (GitHub asset digest or a `.sha256` sidecar, fail closed when
//! neither exists), extract it, and normalize the layout to
//! `<versions>/<tool>/<version>/bin/<binary>` so hooks, shims, and `omg use`
//! work exactly like the bespoke managers.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use super::common::{
    GITHUB_USER_AGENT, GithubAsset, GithubRelease, activate_version_with_linked_binary,
    begin_staged_install, complete_staged_install, download_with_progress, extract_tar_gz,
    extract_tar_xz, extract_zip, fetch_github_releases, normalize_version, parse_sha256_digest,
    print_already_installed, print_installed, print_using, remove_file_best_effort,
    require_regular_file, validate_download_filename,
};
use super::tool_registry::RegistryTool;
use crate::{
    cli::style,
    core::http::{BoundedResponseExt, download_client},
};

/// How far below the staging root the primary binary may live.
const MAX_BINARY_SEARCH_DEPTH: usize = 4;

/// Releases scanned per `list_available` (30 newest × 3 pages).
const LIST_PER_PAGE: u32 = 30;
const LIST_MAX_PAGES: u32 = 3;

/// A registry tool version derived from a GitHub release tag.
#[derive(Debug, Clone)]
pub(crate) struct RegistryVersion {
    pub(crate) version: String,
    pub(crate) prerelease: bool,
}

/// Derive the directory version from a release tag.
///
/// Strips a single leading `v` and, for monorepo-style tags such as
/// `kustomize/v5.4.1`, keeps the segment after the last `/`. Rolling tags
/// that are not version numbers (Elixir's `main-latest`) are rejected: a
/// version directory must start with a digit.
fn version_from_tag(tag: &str) -> Option<String> {
    let leaf = tag.rsplit('/').next().unwrap_or(tag);
    let version = normalize_version(leaf);
    let numbered = version
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_digit());
    (numbered && !version.is_empty()).then_some(version)
}

fn version_for_tool(tag: &str, tool: &str) -> Option<String> {
    if let Some((namespace, _)) = tag.rsplit_once('/')
        && namespace != tool
    {
        return None;
    }
    version_from_tag(tag)
}

/// Parse releases into deterministic newest-first versions.
fn parse_registry_versions(releases: Vec<GithubRelease>, tool: &str) -> Vec<RegistryVersion> {
    releases
        .into_iter()
        .filter_map(|release| {
            version_for_tool(&release.tag_name, tool).map(|version| RegistryVersion {
                version,
                prerelease: release.prerelease,
            })
        })
        .collect()
}

/// Pick the newest stable version (GitHub lists newest first).
fn pick_latest_stable(versions: Vec<RegistryVersion>) -> Option<String> {
    versions
        .into_iter()
        .filter(|version| !version.prerelease)
        .max_by(|a, b| super::common::version_cmp(&a.version, &b.version))
        .map(|version| version.version)
}

/// Host OS token candidates, most specific first.
fn host_os_tokens() -> &'static [&'static str] {
    match std::env::consts::OS {
        "linux" => &["linux"],
        "macos" => &["apple", "darwin", "macos", "osx"],
        _ => &[],
    }
}

/// Host arch token candidates, most specific first.
fn host_arch_tokens() -> &'static [&'static str] {
    match std::env::consts::ARCH {
        "x86_64" => &["x86_64", "amd64", "x64"],
        "aarch64" => &["aarch64", "arm64"],
        _ => &[],
    }
}

/// Asset names that are never installable payloads.
fn is_sidecar_or_packaging(name: &str) -> bool {
    const SUFFIXES: &[&str] = &[
        ".sha256",
        ".sha256sum",
        ".sha512",
        ".md5",
        ".sig",
        ".asc",
        ".pem",
        ".sbom",
        ".json",
        ".txt",
        ".md",
        ".deb",
        ".rpm",
        ".apk",
        ".msi",
        ".exe",
        ".dmg",
        ".pkg",
    ];
    SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
}

/// Match a whole dash/underscore/dot-separated segment inside an asset name.
///
/// Segment equality (rather than substring search) keeps short tokens honest:
/// `doc` matches `Docs.zip` but not `asciidoc`, and `386` matches `tool-386`
/// but not the `13864` in a build number.
fn has_token(name: &str, needle: &str) -> bool {
    name.split(['-', '_', '.']).any(|segment| segment == needle)
}

/// Asset names that cannot run on this host.
fn is_excluded_platform(name: &str) -> bool {
    const WINDOWS: &[&str] = &["windows", "win64", "win32", "msvc", "mingw"];
    const OTHER_ARCH: &[&str] = &[
        "armv7", "armv6", "armhf", "i386", "i686", "386", "32-bit", "ppc64", "s390x", "riscv",
        "mips", "loong64",
    ];
    // Source and documentation archives are never installable payloads
    // (e.g. `otp_src_27.0.tar.gz`, `scala-docs-*.tgz`).
    const NOT_A_BINARY: &[&str] = &[
        "src", "source", "sources", "doc", "docs", "javadoc", "manual", "manuals",
    ];
    const OTHER_OS: &[&str] = &[
        "freebsd",
        "openbsd",
        "netbsd",
        "dragonfly",
        "solaris",
        "illumos",
        "android",
    ];
    OTHER_OS.iter().any(|token| has_token(name, token))
        || WINDOWS.iter().any(|token| name.contains(token))
        || OTHER_ARCH.iter().any(|token| has_token(name, token))
        || NOT_A_BINARY.iter().any(|token| has_token(name, token))
}

/// Archive handling supported by [`super::common`] extractors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveKind {
    TarGz,
    Zip,
    TarXz,
    BareBinary,
}

impl ArchiveKind {
    /// Rank for asset preference: real archives beat bare binaries because
    /// they carry the conventional top-level directory layout.
    fn rank(self) -> u8 {
        match self {
            Self::TarGz => 0,
            Self::Zip => 1,
            Self::TarXz => 2,
            Self::BareBinary => 3,
        }
    }
}

/// Classify an asset filename, or `None` when OMG cannot extract it.
///
/// Extension matching is case-insensitive (vendors mix `ZIP`/`Zip`); unknown
/// containers (`.tar.bz2`, `.7z`, …) have no extractor and map to `None`.
fn classify_archive(name: &str) -> Option<ArchiveKind> {
    // Dot-separated tail, reversed: `["gz", "tar", …]`, `["zip", …]`, or the
    // whole name when there is no dot (a bare binary).
    let lowered = name.to_ascii_lowercase();
    let tail: Vec<&str> = lowered.rsplit('.').collect();
    match tail.as_slice() {
        ["gz", "tar", ..] | ["tgz", ..] => Some(ArchiveKind::TarGz),
        ["zip", ..] => Some(ArchiveKind::Zip),
        ["xz", "tar", ..] | ["txz", ..] => Some(ArchiveKind::TarXz),
        [_] => Some(ArchiveKind::BareBinary),
        _ if lowered.split('.').skip(1).all(|part| {
            let digits = part.bytes().take_while(u8::is_ascii_digit).count();
            digits > 0 && (digits == part.len() || part[digits..].starts_with(['-', '_']))
        }) =>
        {
            Some(ArchiveKind::BareBinary)
        }
        _ => None,
    }
}

/// Score an asset for this host. Higher wins; `None` means unusable.
fn score_asset(asset_name: &str) -> Option<i64> {
    let name = asset_name.to_ascii_lowercase();
    if is_sidecar_or_packaging(&name) || is_excluded_platform(&name) {
        return None;
    }
    let kind = classify_archive(asset_name)?;
    let os_tokens = host_os_tokens();
    if os_tokens.is_empty() {
        return None;
    }
    // Bare binaries without any OS token (e.g. `kind-linux-amd64` always has
    // one, but `jq-1.7` style names may not) are usable only when nothing
    // else claims the host — handled by the fallback pass, not here.
    if !os_tokens.iter().any(|token| name.contains(token)) {
        return None;
    }
    let arch_tokens = host_arch_tokens();
    let arch_rank = arch_tokens
        .iter()
        .position(|token| {
            name.contains(&format!("-{token}"))
                || name.contains(&format!("_{token}"))
                || name.contains(&format!(".{token}"))
                || name.contains(token)
        })
        .unwrap_or(arch_tokens.len());
    if arch_rank >= arch_tokens.len() {
        return None;
    }
    // Prefer gnu over musl on Linux (glibc hosts), archives over bare
    // binaries, and exact-arch matches over genus matches.
    let musl_penalty = i64::from(name.contains("musl"));
    let arch_rank = i64::try_from(arch_rank).unwrap_or(i64::MAX);
    Some(1_000_000 - i64::from(kind.rank()) * 10_000 - arch_rank * 100 - musl_penalty)
}

/// Select the best release asset for this host.
///
/// `must_contain`/`must_not_contain` come from the registry entry and steer
/// past same-release decoys (native images, documentation archives). The
/// first pass requires an OS token; the fallback pass accepts bare,
/// platform-neutral binaries (no OS token, still arch-compatible and
/// extractable) so single-asset tools stay installable.
fn select_asset<'a>(
    assets: &'a [GithubAsset],
    must_contain: Option<&str>,
    must_not_contain: Option<&str>,
) -> Option<(&'a GithubAsset, ArchiveKind)> {
    let allowed = |asset: &GithubAsset| {
        must_contain.is_none_or(|needle| asset.name.contains(needle))
            && must_not_contain.is_none_or(|needle| !asset.name.contains(needle))
    };
    let mut best: Option<(&GithubAsset, ArchiveKind, i64)> = None;
    for asset in assets.iter().filter(|asset| allowed(asset)) {
        if let Some(score) = score_asset(&asset.name)
            && let Some(kind) = classify_archive(&asset.name)
            && best.is_none_or(|(_, _, best_score)| score > best_score)
        {
            best = Some((asset, kind, score));
        }
    }
    if let Some((asset, kind, _)) = best {
        return Some((asset, kind));
    }
    // Fallback for platform-neutral payloads (Elixir's `elixir-otp-27.zip`):
    // keep only viable assets, prefer the host arch, and break remaining
    // ties by smallest name so multi-variant releases (per-OTP zips) resolve
    // deterministically — the lowest variant has the widest compatibility.
    let mut fallback: Vec<(&GithubAsset, ArchiveKind)> = assets
        .iter()
        .filter(|asset| allowed(asset))
        .filter_map(|asset| {
            let name = asset.name.to_ascii_lowercase();
            if is_sidecar_or_packaging(&name)
                || is_excluded_platform(&name)
                || names_foreign_os(&name)
                || names_foreign_arch(&name)
            {
                return None;
            }
            classify_archive(&asset.name).map(|kind| (asset, kind))
        })
        .collect();
    fallback.sort_by(|a, b| {
        let arch_match = |asset: &GithubAsset| {
            host_arch_tokens()
                .iter()
                .any(|token| asset.name.contains(*token))
        };
        arch_match(b.0)
            .cmp(&arch_match(a.0))
            .then_with(|| a.0.name.cmp(&b.0.name))
    });
    fallback.into_iter().next()
}

/// Whether a bare asset name claims a foreign OS (used by the fallback pass
/// so a `linux` binary is never installed on macOS and vice versa).
fn names_foreign_os(name: &str) -> bool {
    const LINUX: &[&str] = &["linux"];
    const MACOS: &[&str] = &["apple", "darwin", "macos", "osx"];
    match std::env::consts::OS {
        "linux" => MACOS.iter().any(|token| name.contains(token)),
        "macos" => LINUX.iter().any(|token| name.contains(token)),
        _ => true,
    }
}

/// Whether an asset names an architecture other than the host's.
///
/// Substring matching is deliberate here: it catches variants the segment
/// matcher cannot enumerate (`armv7l` via `armv7`). The host's own tokens
/// are excluded first, so `amd64` never rejects an x86_64 asset.
fn names_foreign_arch(name: &str) -> bool {
    const ALL_ARCH: &[&str] = &[
        "x86_64", "amd64", "x64", "aarch64", "arm64", "armv7", "armv6", "i386", "i686", "armhf",
        "ppc64", "s390x", "riscv", "mips", "loong64",
    ];
    ALL_ARCH
        .iter()
        .any(|token| !host_arch_tokens().contains(token) && name.contains(token))
}

/// Generic manager for one [`RegistryTool`].
pub(crate) struct GenericToolManager {
    spec: &'static RegistryTool,
    versions_dir: PathBuf,
    client: &'static reqwest::Client,
}

impl GenericToolManager {
    /// Build a manager for a registry spec.
    pub fn for_spec(spec: &'static RegistryTool) -> Self {
        let versions_dir = super::DATA_DIR.join("versions").join(spec.name);
        Self {
            spec,
            versions_dir,
            client: download_client(),
        }
    }

    /// Build a manager by tool name, or `None` for bespoke runtimes.
    pub fn for_name(name: &str) -> Option<Self> {
        super::tool_registry::find_tool(name).map(Self::for_spec)
    }

    fn releases_url(&self) -> String {
        format!("https://api.github.com/repos/{}/releases", self.spec.repo)
    }

    /// Registry description for listings.
    pub fn description(&self) -> &'static str {
        self.spec.description
    }

    /// Display name for install output.
    fn display(&self) -> String {
        let mut name = self.spec.name.to_owned();
        if let Some(first) = name.get_mut(..1) {
            first.make_ascii_uppercase();
        }
        name
    }

    /// List available upstream versions (newest first).
    pub async fn list_available(&self) -> Result<Vec<RegistryVersion>> {
        let releases = fetch_github_releases(
            self.client,
            &self.releases_url(),
            LIST_PER_PAGE,
            LIST_MAX_PAGES,
            |_| false,
        )
        .await
        .with_context(|| format!("Failed to fetch {} releases from GitHub", self.spec.name))?;
        Ok(parse_registry_versions(releases, self.spec.name))
    }

    /// Resolve `latest` and partial requests (`1`, `1.2`) against the
    /// upstream list. Exact versions pass through so the installed fast path
    /// and the existing not-found UX are preserved.
    pub async fn resolve_alias(&self, alias: &str) -> Result<String> {
        let alias = normalize_version(alias);
        if alias == "latest" {
            let versions = self.list_available().await?;
            pick_latest_stable(versions)
                .with_context(|| format!("No {} versions found upstream", self.spec.name))
        } else {
            Ok(alias)
        }
    }

    /// Resolve a partial version against the upstream list.
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

    /// Fetch the release whose derived version equals `version`.
    async fn release_for_version(&self, version: &str) -> Result<GithubRelease> {
        let releases = fetch_github_releases(
            self.client,
            &self.releases_url(),
            LIST_PER_PAGE,
            LIST_MAX_PAGES,
            |release| {
                version_for_tool(&release.tag_name, self.spec.name).as_deref() == Some(version)
            },
        )
        .await
        .with_context(|| format!("Failed to fetch {} releases from GitHub", self.spec.name))?;
        releases
            .into_iter()
            .find(|release| version_for_tool(&release.tag_name, self.spec.name).as_deref() == Some(version))
            .with_context(|| {
                format!(
                    "Version {version} not found for {}. Check available versions with: omg list {0} --available",
                    self.spec.name
                )
            })
    }

    /// Resolve the SHA-256 for an asset: GitHub's asset digest first, then a
    /// checksum sidecar (`.sha256`, `.sha256sum`, `.sha256.txt` in preference
    /// order). Fail closed when neither exists — an unverified binary must
    /// never reach `PATH`.
    async fn checksum_for_asset(
        &self,
        release: &GithubRelease,
        asset: &GithubAsset,
    ) -> Result<String> {
        if let Some(digest) = asset.digest.as_deref() {
            return parse_sha256_digest(digest, "GitHub release asset digest");
        }
        // Vendors disagree on the sidecar suffix (`.sha256`, `.sha256sum`,
        // `.sha256.txt`); accept the common spellings in preference order.
        let sidecar = ["sha256", "sha256sum", "sha256.txt"]
            .into_iter()
            .map(|suffix| format!("{}.{suffix}", asset.name))
            .find_map(|sidecar_name| release.assets.iter().find(|a| a.name == sidecar_name));
        let asset_specific = sidecar.is_some();
        let sidecar = sidecar.or_else(|| {
            release.assets.iter().find(|candidate| {
                let name = candidate.name.to_ascii_lowercase();
                name == "checksums.txt"
                    || name.ends_with("_checksums.txt")
                    || name == "sha256sums"
                    || name == "sha256sums.txt"
                    || name.ends_with("_sha256sums")
            })
        });
        let Some(sidecar) = sidecar else {
            anyhow::bail!(
                "No SHA-256 checksum for {} {} (asset {}); refusing to install an unverified binary",
                self.spec.name,
                release.tag_name,
                asset.name
            );
        };
        let sidecar_name = sidecar.name.clone();
        let url = sidecar
            .browser_download_url
            .clone()
            .with_context(|| format!("Checksum sidecar has no download URL: {sidecar_name}"))?;
        let text = crate::core::http::fetch_public_download_with_timeout(
            &url,
            GITHUB_USER_AGENT,
            Some(std::time::Duration::from_secs(30)),
        )
        .await
        .with_context(|| format!("Failed to fetch checksum sidecar {sidecar_name}"))?
        .error_for_status()
        .with_context(|| format!("Checksum sidecar request failed: {sidecar_name}"))?
        .bounded_text()
        .await
        .with_context(|| format!("Failed to read checksum sidecar {sidecar_name}"))?;
        checksum_document(&text, &asset.name, asset_specific)
    }

    /// Install a version: resolve, download, verify, extract, activate.
    pub async fn install(&self, version: &str) -> Result<()> {
        let version = self.resolve_alias(version).await?;
        let version = self.resolve_requested_version(&version).await?;
        crate::core::security::validate_runtime_version(&version)?;
        let version_dir = self.versions_dir.join(&version);

        if super::common::is_valid_version_dir(&version_dir) {
            print_already_installed(&self.display(), &version);
            return self.use_version(&version);
        }

        println!(
            "{} Installing {} {}...\n",
            style::runtime("OMG"),
            self.display(),
            style::caution(&version)
        );

        println!(
            "{} Fetching {} {} release metadata...",
            style::informative("→"),
            self.display(),
            version
        );
        let mut release = self.release_for_version(&version).await?;
        if let Some(assets) = publisher_assets(
            self.spec.name,
            &version,
            std::env::consts::OS,
            std::env::consts::ARCH,
        )? {
            release.assets = assets;
        }
        let (asset, kind) = select_asset(
            &release.assets,
            self.spec.asset_must_contain,
            self.spec.asset_must_not_contain,
        )
        .with_context(|| {
            format!(
                "No installable {} {} asset for {} {}",
                self.spec.name,
                version,
                std::env::consts::OS,
                std::env::consts::ARCH
            )
        })?;
        validate_download_filename(&asset.name)?;
        let url = asset.browser_download_url.clone().with_context(|| {
            format!(
                "{} vendor asset has no download URL: {}",
                self.spec.name, asset.name
            )
        })?;
        let checksum = self.checksum_for_asset(&release, asset).await?;

        fs::create_dir_all(&self.versions_dir)?;
        println!("{} Downloading {}...", style::informative("→"), asset.name);
        let downloads = tempfile::Builder::new()
            .prefix(".download-")
            .tempdir_in(&self.versions_dir)?;
        let download_path = downloads.path().join(&asset.name);
        download_with_progress(self.client, &url, &download_path, &checksum).await?;

        println!("{} Extracting (pure Rust)...", style::informative("→"));
        let staging = begin_staged_install(&self.versions_dir)?;
        self.populate_staging(&download_path, kind, staging.path())
            .await?;
        complete_staged_install(&staging, &version_dir, &version)?;

        remove_file_best_effort(&download_path, "tool archive");

        print_installed(&self.display(), &version);
        self.use_version(&version)?;
        Ok(())
    }

    /// Extract the download into staging and normalize the layout to
    /// `<staging>/bin/<binary>` (symlinked when the archive carries a wider
    /// tree, e.g. editor runtimes that need sibling files).
    async fn populate_staging(
        &self,
        download_path: &Path,
        kind: ArchiveKind,
        staging: &Path,
    ) -> Result<()> {
        if kind == ArchiveKind::BareBinary {
            let bin_dir = staging.join("bin");
            fs::create_dir_all(&bin_dir)?;
            let dest = bin_dir.join(self.spec.binary);
            fs::copy(download_path, &dest).with_context(|| {
                format!("Failed to stage downloaded binary: {}", dest.display())
            })?;
            make_executable(&dest)?;
            return Ok(());
        }
        self.extract_and_link(download_path, kind, staging).await
    }

    /// Extract once and link the discovered binary into `staging/bin`.
    async fn extract_and_link(
        &self,
        download_path: &Path,
        kind: ArchiveKind,
        staging: &Path,
    ) -> Result<()> {
        match kind {
            ArchiveKind::TarGz => extract_tar_gz(download_path, staging, 0).await,
            ArchiveKind::Zip => extract_zip(download_path, staging, 0).await,
            ArchiveKind::TarXz => extract_tar_xz(download_path, staging, 0).await,
            ArchiveKind::BareBinary => Ok(()),
        }?;
        let found = self.find_binary(staging).with_context(|| {
            format!(
                "Installed {} archive but found no `{}` binary inside",
                self.spec.name, self.spec.binary
            )
        })?;
        make_executable(&found)?;
        let bin_dir = staging.join("bin");
        // The binary already lives exactly at `bin/<binary>`: nothing to do.
        if found.parent() == Some(bin_dir.as_path())
            && found.file_name().and_then(|name| name.to_str()) == Some(self.spec.binary)
        {
            return Ok(());
        }
        fs::create_dir_all(&bin_dir)?;
        let link = bin_dir.join(self.spec.binary);
        if link.exists() {
            require_regular_file(&link)?;
            return Ok(());
        }
        let target = pathdiff_relative(&found, &bin_dir);
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).with_context(|| {
            format!(
                "Failed to link {} binary into staging bin dir",
                self.spec.name
            )
        })?;
        #[cfg(not(unix))]
        {
            let _ = target;
            anyhow::bail!("Registry tool installs are unsupported on this platform");
        }
        Ok(())
    }

    /// Find the primary binary below `staging` (shallowest match wins).
    fn find_binary(&self, staging: &Path) -> Option<PathBuf> {
        let mut candidates = Vec::new();
        let mut stack = vec![(staging.to_path_buf(), 0)];
        while let Some((dir, depth)) = stack.pop() {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_symlink() {
                    continue;
                }
                if path.is_dir() {
                    if depth < MAX_BINARY_SEARCH_DEPTH {
                        stack.push((path, depth + 1));
                    }
                } else if path.file_name().and_then(|name| name.to_str()) == Some(self.spec.binary)
                {
                    candidates.push((depth, path));
                }
            }
        }
        candidates.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        candidates.into_iter().next().map(|(_, path)| path)
    }

    /// Switch to an installed version.
    pub fn use_version(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        let expected = Path::new("bin").join(self.spec.binary);
        activate_version_with_linked_binary(&self.versions_dir, &version, &expected)?;
        print_using(
            &self.display(),
            &version,
            &self.versions_dir.join("current").join("bin"),
        );
        Ok(())
    }

    /// Remove an installed version. Refuses the active version.
    pub fn uninstall(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        super::common::uninstall_version(&self.versions_dir, &version)
    }
}

// Generate common manager methods (list_installed, current_version)
super::common::impl_runtime_common!(GenericToolManager);

/// Ensure a staged binary is executable (ZIP archives may drop modes).
#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
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

/// Non-Unix staging cannot produce executable shims; fail at install time.
#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    anyhow::bail!("Registry tool installs are unsupported on this platform")
}

fn publisher_assets(
    tool: &str,
    version: &str,
    os: &str,
    arch: &str,
) -> Result<Option<Vec<GithubAsset>>> {
    if !matches!(tool, "helm" | "terraform") {
        return Ok(None);
    }
    crate::core::security::validate_runtime_version(version)?;
    let os = match os {
        "linux" => "linux",
        "macos" => "darwin",
        _ => anyhow::bail!("Unsupported publisher platform: {os}"),
    };
    let arch = match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => anyhow::bail!("Unsupported publisher architecture: {arch}"),
    };
    // These publishers host payloads outside GitHub releases.
    // https://get.helm.sh/ and https://releases.hashicorp.com/terraform/
    let (base, payload, checksum) = if tool == "helm" {
        let payload = format!("helm-v{version}-{os}-{arch}.tar.gz");
        (
            "https://get.helm.sh".to_string(),
            payload.clone(),
            format!("{payload}.sha256sum"),
        )
    } else {
        (
            format!("https://releases.hashicorp.com/terraform/{version}"),
            format!("terraform_{version}_{os}_{arch}.zip"),
            format!("terraform_{version}_SHA256SUMS"),
        )
    };
    Ok(Some(
        [payload, checksum]
            .into_iter()
            .map(|name| GithubAsset {
                browser_download_url: Some(format!("{base}/{name}")),
                name,
                digest: None,
            })
            .collect(),
    ))
}

fn checksum_document(text: &str, asset: &str, asset_specific: bool) -> Result<String> {
    if asset_specific && text.split_whitespace().count() == 1 {
        return parse_sha256_digest(text, "asset checksum sidecar");
    }
    let mut found = None;
    for line in text.lines() {
        let line = line.trim();
        let digest = if let Some(rest) = line.strip_prefix("SHA256 (") {
            rest.split_once(") = ")
                .and_then(|(name, digest)| (name == asset).then_some(digest))
        } else {
            line.split_once(char::is_whitespace)
                .and_then(|(digest, name)| {
                    (name.trim().trim_start_matches('*') == asset).then_some(digest)
                })
        };
        if let Some(digest) = digest {
            let digest = parse_sha256_digest(digest, "release checksum manifest")?;
            if let Some(previous) = &found {
                anyhow::ensure!(previous == &digest, "Conflicting checksums for {asset}");
            }
            found = Some(digest);
        }
    }
    found.with_context(|| format!("Checksum document has no exact entry for {asset}"))
}

/// Relative path from `base` to `target` for an internal staging symlink.
fn pathdiff_relative(target: &Path, base: &Path) -> PathBuf {
    let mut target = target.components().peekable();
    let mut base = base.components().peekable();
    // Skip the shared prefix.
    loop {
        match (target.peek(), base.peek()) {
            (Some(a), Some(b)) if a == b => {
                target.next();
                base.next();
            }
            _ => break,
        }
    }
    let mut relative = PathBuf::new();
    for _ in base {
        relative.push("..");
    }
    for component in target {
        relative.push(component.as_os_str());
    }
    relative
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(name: &str) -> GithubAsset {
        GithubAsset {
            name: name.to_owned(),
            browser_download_url: Some(format!("https://example.com/{name}")),
            digest: None,
        }
    }

    #[tokio::test]
    async fn flat_archive_preserves_binary_and_library_directories() -> anyhow::Result<()> {
        use std::io::Write;
        let dir = tempfile::tempdir()?;
        let archive_path = dir.path().join("elixir.zip");
        let mut archive = zip::ZipWriter::new(fs::File::create(&archive_path)?);
        let options = zip::write::SimpleFileOptions::default().unix_permissions(0o755);
        archive.start_file("bin/elixir", options)?;
        archive.write_all(b"#!/bin/sh\nexit 0\n")?;
        archive.add_directory("lib/elixir/ebin/", options)?;
        archive.start_file("lib/elixir/ebin/module.beam", options)?;
        archive.write_all(b"library")?;
        archive.finish()?;
        let staging = dir.path().join("staging");
        fs::create_dir(&staging)?;
        let manager = GenericToolManager::for_name("elixir").expect("registered");
        manager
            .populate_staging(&archive_path, ArchiveKind::Zip, &staging)
            .await?;
        assert!(staging.join("bin/elixir").is_file());
        assert_eq!(
            fs::read(staging.join("lib/elixir/ebin/module.beam"))?,
            b"library"
        );
        Ok(())
    }

    #[test]
    fn external_publishers_use_their_payload_and_checksum_endpoints() {
        let helm = publisher_assets("helm", "4.2.4", "linux", "x86_64")
            .unwrap()
            .unwrap();
        assert_eq!(
            helm[0].browser_download_url.as_deref(),
            Some("https://get.helm.sh/helm-v4.2.4-linux-amd64.tar.gz")
        );
        assert_eq!(helm[1].name, "helm-v4.2.4-linux-amd64.tar.gz.sha256sum");
        let terraform = publisher_assets("terraform", "1.16.1", "macos", "aarch64")
            .unwrap()
            .unwrap();
        assert_eq!(terraform[0].name, "terraform_1.16.1_darwin_arm64.zip");
        assert_eq!(
            terraform[1].browser_download_url.as_deref(),
            Some("https://releases.hashicorp.com/terraform/1.16.1/terraform_1.16.1_SHA256SUMS")
        );
    }

    #[test]
    fn checksum_manifests_match_exact_asset_names() {
        let digest = "a".repeat(64);
        let text = format!("{}  other.tar.gz\n{digest} *tool.tar.gz\n", "b".repeat(64));
        assert_eq!(
            checksum_document(&text, "tool.tar.gz", false).unwrap(),
            digest
        );
        assert!(checksum_document(&text, "tool.tar", false).is_err());
        assert!(checksum_document(&digest, "tool.tar.gz", false).is_err());
        assert_eq!(
            checksum_document(&digest, "tool.tar.gz", true).unwrap(),
            digest
        );
        assert_eq!(
            checksum_document(
                &format!("SHA256 (tool.tar.gz) = {digest}"),
                "tool.tar.gz",
                false
            )
            .unwrap(),
            digest
        );
        assert!(
            checksum_document(
                &format!("{text}{}  tool.tar.gz", "c".repeat(64)),
                "tool.tar.gz",
                false
            )
            .is_err()
        );
    }

    #[test]
    fn versioned_binaries_and_foreign_platforms_are_classified() {
        for name in ["shfmt_v3.14.1_linux_amd64", "x86_64-linux-ghcup-0.2.6.2"] {
            assert_eq!(classify_archive(name), Some(ArchiveKind::BareBinary));
        }
        for name in ["tool.tar.bz2", "tool.7z", "tool.zst"] {
            assert_eq!(classify_archive(name), None);
        }
        assert!(is_excluded_platform("tool-freebsd-amd64.tar.gz"));
        assert!(is_excluded_platform("tool-openbsd-arm64.tar.gz"));
        assert!(version_for_tool("kyaml/v0.21.1", "kustomize").is_none());
        assert_eq!(
            version_for_tool("kustomize/v5.8.1", "kustomize").as_deref(),
            Some("5.8.1")
        );
        assert_eq!(
            pick_latest_stable(vec![
                RegistryVersion {
                    version: "1.0.9".into(),
                    prerelease: false
                },
                RegistryVersion {
                    version: "2.0.0".into(),
                    prerelease: false
                }
            ])
            .as_deref(),
            Some("2.0.0")
        );
    }

    #[test]
    fn version_from_tag_strips_prefixes() {
        assert_eq!(version_from_tag("v15.2.0").as_deref(), Some("15.2.0"));
        assert_eq!(
            version_from_tag("kustomize/v5.4.1").as_deref(),
            Some("5.4.1")
        );
        assert_eq!(version_from_tag("1.2.3").as_deref(), Some("1.2.3"));
        assert_eq!(version_from_tag(""), None);
        // Rolling tags are not versions and must never become directories.
        assert_eq!(version_from_tag("main-latest"), None);
    }

    #[test]
    fn has_token_matches_segments_not_substrings() {
        assert!(has_token("docs.zip", "docs"));
        assert!(!has_token("asciidoc-1.0-linux.tar.gz", "doc"));
        assert!(has_token("tool-386.tar.gz", "386"));
        assert!(!has_token("tool-13864-linux.tar.gz", "386"));
        assert!(has_token("otp_src_27.0.tar.gz", "src"));
    }

    #[test]
    fn select_asset_prefers_lowest_otp_variant_deterministically() {
        // Mirrors Elixir's per-OTP prebuilt zips: no OS token, so the
        // fallback pass decides; Docs and Windows installers are excluded.
        let assets = vec![
            asset("elixir-otp-27.zip"),
            asset("Docs.zip"),
            asset("elixir-otp-27.exe"),
            asset("elixir-otp-25.zip"),
            asset("elixir-otp-26.zip"),
        ];
        let (selected, kind) = select_asset(&assets, None, None).expect("otp zip must win");
        assert_eq!(selected.name, "elixir-otp-25.zip");
        assert_eq!(kind, ArchiveKind::Zip);
    }

    #[test]
    fn latest_stable_skips_prereleases() {
        let versions = vec![
            RegistryVersion {
                version: "2.0.0-rc1".to_owned(),
                prerelease: true,
            },
            RegistryVersion {
                version: "1.9.0".to_owned(),
                prerelease: false,
            },
        ];
        assert_eq!(pick_latest_stable(versions).as_deref(), Some("1.9.0"));
    }

    #[test]
    fn select_asset_prefers_host_gnu_archive() {
        // Mirrors a real ripgrep release file list (truncated).
        let assets = vec![
            asset("ripgrep-15.2.0-aarch64-apple-darwin.tar.gz"),
            asset("ripgrep-15.2.0-x86_64-apple-darwin.tar.gz"),
            asset("ripgrep-15.2.0-aarch64-unknown-linux-gnu.tar.gz"),
            asset("ripgrep-15.2.0-aarch64-apple-darwin.tar.gz.sha256"),
            asset("ripgrep-15.2.0-x86_64-pc-windows-msvc.zip"),
            asset("ripgrep-15.2.0-x86_64-unknown-linux-musl.tar.gz"),
            asset("ripgrep-15.2.0-x86_64-unknown-linux-gnu.tar.gz"),
        ];
        let (selected, kind) = select_asset(&assets, None, None).expect("must select an asset");
        if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
            assert_eq!(
                selected.name,
                "ripgrep-15.2.0-x86_64-unknown-linux-gnu.tar.gz"
            );
            assert_eq!(kind, ArchiveKind::TarGz);
        } else {
            // Other hosts: still a real payload, never a sidecar or Windows zip.
            assert!(!is_sidecar_or_packaging(
                &selected.name.to_ascii_lowercase()
            ));
        }
    }

    #[test]
    fn select_asset_rejects_sidecars_and_windows_only() {
        let assets = vec![
            asset("tool-1.0.0-x86_64-pc-windows-msvc.zip"),
            asset("tool-1.0.0-x86_64-unknown-linux-gnu.tar.gz.sha256"),
        ];
        if cfg!(target_os = "linux") {
            assert!(select_asset(&assets, None, None).is_none());
        }
    }

    #[test]
    fn select_asset_rejects_source_and_docs_archives() {
        // Erlang-style source tarballs and docs archives are never payloads,
        // even when they carry the host platform token.
        let assets = vec![
            asset("otp_src_27.0-x86_64-unknown-linux-gnu.tar.gz"),
            asset("scala-docs-2.12.21-x86_64-unknown-linux-gnu.tgz"),
        ];
        assert!(select_asset(&assets, None, None).is_none());
    }

    #[test]
    fn select_asset_honors_must_contain_and_must_not_contain() {
        // Mirrors a Kotlin release: the platform-neutral compiler archive
        // must win over the scored native image.
        let assets = vec![
            asset("kotlin-native-image-linux-x86_64-2.4.20.tar.gz"),
            asset("kotlin-compiler-2.4.20.zip"),
        ];
        let (selected, _) = select_asset(&assets, Some("kotlin-compiler"), None)
            .expect("compiler archive must be selectable");
        assert_eq!(selected.name, "kotlin-compiler-2.4.20.zip");
        // A vetoed payload is skipped even when it is the only candidate.
        assert!(select_asset(&assets, None, Some("kotlin")).is_none());
    }

    #[test]
    fn select_asset_accepts_bare_binaries() {
        let assets = vec![asset("kind-linux-amd64"), asset("kind-linux-amd64.sha256")];
        if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            let (selected, kind) =
                select_asset(&assets, None, None).expect("bare binary must be usable");
            assert_eq!(selected.name, "kind-linux-amd64");
            assert_eq!(kind, ArchiveKind::BareBinary);
        } else {
            // A foreign-arch bare binary must never install, even with no
            // better candidate in the release.
            assert!(select_asset(&assets, None, None).is_none());
        }
    }

    #[test]
    fn select_asset_rejects_foreign_arch_without_host_candidate() {
        let assets = vec![
            asset("tool-aarch64-linux.tar.gz"),
            asset("tool-aarch64-linux.tar.gz.sha256"),
        ];
        if cfg!(target_arch = "x86_64") {
            assert!(select_asset(&assets, None, None).is_none());
        }
    }

    #[test]
    fn classify_archive_rejects_unknown_containers() {
        assert_eq!(classify_archive("tool.tar.gz"), Some(ArchiveKind::TarGz));
        assert_eq!(classify_archive("tool.tgz"), Some(ArchiveKind::TarGz));
        assert_eq!(classify_archive("tool.zip"), Some(ArchiveKind::Zip));
        assert_eq!(classify_archive("tool.tar.xz"), Some(ArchiveKind::TarXz));
        assert_eq!(
            classify_archive("tool-linux-amd64"),
            Some(ArchiveKind::BareBinary)
        );
        assert_eq!(classify_archive("tool.tar.bz2"), None);
        assert_eq!(classify_archive("tool.7z"), None);
    }

    #[test]
    fn pathdiff_relative_stays_internal() {
        let base = Path::new("/staging/bin");
        let target = Path::new("/staging/tool-1.0/bin/rg");
        assert_eq!(
            pathdiff_relative(target, base),
            PathBuf::from("../tool-1.0/bin/rg")
        );
    }
}
