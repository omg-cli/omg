//! Native PHP manager (shivammathur/php-builder prebuilts).
//!
//! Upstream publishes one rolling release per PHP minor (`8.5`, `8.6`, …) at
//! `https://github.com/shivammathur/php-builder/releases`. Each release keeps
//! a single build per (distro, arch) pair plus `install.sh`, `build.log`, and
//! a `php<minor>.log` recording the exact patch currently baked in (e.g.
//! `php-8.5.10` for the `8.5` channel). Rebuilds overwrite the previous
//! assets (`--clobber`), and `setup-php` itself truncates every request to
//! `major.minor`, so exact patches cannot be pinned: versions here are the
//! rolling `major.minor` channels, the install directory is the channel, and
//! reinstalling refreshes to the latest patch. The newest channel may bake an
//! in-development snapshot (`8.6` currently bakes `8.6.0-dev` per its
//! `php8.6.log`); pin an explicit stable channel such as `8.5` when that
//! matters.
//!
//! Payloads are Debian/Ubuntu system-root tarballs
//! (`php_<channel>+<distro>[_arm64].tar.xz`, where `<distro>` is `debian11`,
//! `debian12`, `debian13`, `ubuntu22.04`, `ubuntu24.04`, or `ubuntu26.04`).
//! The `.tar.xz` variant is installed in pure Rust; the adjacent `.tar.zst`
//! duplicates, `-zts` thread-safety variants, and `-dbgsym` symbol packages
//! are never selected. Verification is fail-closed: the GitHub asset
//! `digest` SHA-256 is required before any byte reaches disk, the staged tree
//! must contain a PHP binary (found by bounded search, then linked to
//! `bin/php`), and a `php -v` smoke run must succeed or the install is
//! removed.
//!
//! Only Linux on the Debian/Ubuntu family is supported: php-builder publishes
//! no macOS assets, so macOS installs bail with a pointer to Homebrew.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use super::common::{
    GithubAsset, GithubRelease, activate_version_with_linked_binary, begin_staged_install,
    clear_dir_contents, complete_staged_install, download_with_progress, extract_tar_xz,
    fetch_github_releases, is_valid_version_dir, normalize_version, parse_sha256_digest,
    print_installed, print_using, remove_file_best_effort, replace_staged_install,
    uninstall_version, validate_download_filename,
};
use crate::{cli::style, core::http::download_client};

/// php-builder GitHub releases: one rolling tag per PHP minor.
const PHP_BUILDER_RELEASES_URL: &str =
    "https://api.github.com/repos/shivammathur/php-builder/releases";

/// Override the detected distro token (`OMG_PHP_DISTRO=ubuntu24.04`).
const DISTRO_OVERRIDE_ENV: &str = "OMG_PHP_DISTRO";

/// Distro build used when the host is not a known Debian/Ubuntu release.
/// Derivatives fall back to the latest LTS and rely on the post-install
/// smoke test to reject incompatible builds.
const FALLBACK_DISTRO: &str = "ubuntu24.04";

/// Distro build tokens php-builder publishes (observed across the channels).
const KNOWN_DISTROS: &[&str] = &[
    "debian11",
    "debian12",
    "debian13",
    "ubuntu22.04",
    "ubuntu24.04",
    "ubuntu26.04",
];

/// Channel tags fit one releases page; a second page is headroom only.
const LIST_PER_PAGE: u32 = 50;
const LIST_MAX_PAGES: u32 = 2;

/// How far below the staging root the PHP binary may live.
const MAX_BINARY_SEARCH_DEPTH: usize = 4;

/// A rolling upstream PHP channel (`8.5`) with its release metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PhpVersion {
    /// Rolling channel (`8.5`); the directory name and reinstall target.
    pub(crate) version: String,
    /// Release prerelease flag from the GitHub API.
    pub(crate) prerelease: bool,
}

pub(crate) struct PhpManager {
    versions_dir: PathBuf,
    client: &'static reqwest::Client,
}

/// php-builder publishes Debian/Ubuntu tarballs only; macOS has no assets.
fn ensure_linux() -> Result<()> {
    match std::env::consts::OS {
        "linux" => Ok(()),
        os => anyhow::bail!(
            "PHP prebuilt binaries are Linux-only (Debian/Ubuntu) on this backend ({os}); on macOS install PHP with Homebrew: brew install php"
        ),
    }
}

/// Tarball arch suffix: x86_64 builds carry none, aarch64 builds `_arm64`
/// (Debian publishes x86_64 only, so ARM Debian hosts fail later with a
/// no-asset error naming the channel).
fn host_arch_suffix() -> Result<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(""),
        "aarch64" => Ok("_arm64"),
        arch => anyhow::bail!("Unsupported architecture for PHP: {arch}"),
    }
}

/// Map `/etc/os-release` identity to a php-builder distro token.
///
/// Ubuntu uses its own `VERSION_ID` (a bare major from derivatives maps to
/// the matching LTS); Debian maps by major; anything else takes the latest
/// LTS and relies on the post-install smoke test to reject incompatible
/// builds.
fn map_os_release(distro_id: &str, version_id: &str, id_like: &str) -> &'static str {
    let family = match distro_id {
        "ubuntu" | "debian" => distro_id,
        _ => {
            let likes: Vec<&str> = id_like.split_whitespace().collect();
            if likes.contains(&"ubuntu") {
                "ubuntu"
            } else if likes.contains(&"debian") {
                "debian"
            } else {
                "ubuntu"
            }
        }
    };
    match family {
        "debian" => match version_id.split('.').next().unwrap_or("") {
            "11" => "debian11",
            "12" => "debian12",
            "13" => "debian13",
            _ => FALLBACK_DISTRO,
        },
        _ => match version_id {
            "22.04" => "ubuntu22.04",
            "24.04" => "ubuntu24.04",
            "26.04" => "ubuntu26.04",
            _ => match version_id.split('.').next().unwrap_or("") {
                "22" => "ubuntu22.04",
                "24" => "ubuntu24.04",
                "26" => "ubuntu26.04",
                _ => FALLBACK_DISTRO,
            },
        },
    }
}

/// Parse one `ID=`/`VERSION_ID=`/`ID_LIKE=` field out of os-release content.
fn os_release_field(content: &str, key: &str) -> String {
    content
        .lines()
        .filter_map(|line| line.split_once('='))
        .find(|(name, _)| name.trim() == key)
        .map(|(_, value)| value.trim().trim_matches('"').to_string())
        .unwrap_or_default()
}

/// Detect the php-builder distro token for this host.
fn php_distro() -> Result<String> {
    if let Ok(pinned) = std::env::var(DISTRO_OVERRIDE_ENV) {
        let pinned = pinned.trim().to_string();
        if !pinned.is_empty() {
            if !KNOWN_DISTROS.contains(&pinned.as_str()) {
                anyhow::bail!(
                    "{DISTRO_OVERRIDE_ENV}={pinned:?} is not a php-builder distro build; expected one of: {}",
                    KNOWN_DISTROS.join(", ")
                );
            }
            return Ok(pinned);
        }
    }
    let content = fs::read_to_string("/etc/os-release").unwrap_or_default();
    Ok(map_os_release(
        &os_release_field(&content, "ID"),
        &os_release_field(&content, "VERSION_ID"),
        &os_release_field(&content, "ID_LIKE"),
    )
    .to_string())
}

/// Whether a release tag is a rolling `major.minor` channel. Non-channel tags
/// (notably `libraries`, the shared C-library pack) are rejected: a version
/// directory must be a PHP minor.
fn is_channel_tag(tag: &str) -> bool {
    let Some((major, minor)) = tag.split_once('.') else {
        return false;
    };
    !major.is_empty()
        && !minor.is_empty()
        && !minor.contains('.')
        && major.bytes().all(|byte| byte.is_ascii_digit())
        && minor.bytes().all(|byte| byte.is_ascii_digit())
}

/// Collect the rolling channels from release tags, newest first.
fn parse_channel_versions(releases: Vec<GithubRelease>) -> Vec<PhpVersion> {
    let mut versions: Vec<PhpVersion> = releases
        .into_iter()
        .filter(|release| is_channel_tag(&release.tag_name))
        .map(|release| PhpVersion {
            version: release.tag_name,
            prerelease: release.prerelease,
        })
        .collect();
    sort_versions_desc(&mut versions);
    versions
}

/// Numeric dotted-version comparison; non-numeric components compare as zero
/// so a malformed tag can never panic sorting.
fn version_parts(version: &str) -> Vec<u64> {
    version
        .split('.')
        .map(|part| part.parse().unwrap_or(0))
        .collect()
}

/// Sort newest-first for `list_available` and `latest` resolution.
fn sort_versions_desc(versions: &mut [PhpVersion]) {
    versions.sort_by(|left, right| {
        version_parts(&right.version)
            .cmp(&version_parts(&left.version))
            .then_with(|| left.version.cmp(&right.version))
    });
}

/// Exact install payload for this host: the NTS `.tar.xz` archive.
fn asset_name(version: &str, distro: &str, arch_suffix: &str) -> String {
    format!("php_{version}+{distro}{arch_suffix}.tar.xz")
}

/// Select the exact install payload for this host. `-zts` and `-dbgsym`
/// variants, `.tar.zst` duplicates, and foreign distro/arch builds never
/// match, so no decoy can be installed.
fn select_asset<'a>(
    assets: &'a [GithubAsset],
    version: &str,
    distro: &str,
    arch_suffix: &str,
) -> Option<&'a GithubAsset> {
    let expected = asset_name(version, distro, arch_suffix);
    assets.iter().find(|asset| asset.name == expected)
}

/// Resolve the SHA-256 for an asset from the GitHub asset digest. Fail closed
/// when the digest is absent — an unverified binary must never reach `PATH`.
fn checksum_for_asset(asset: &GithubAsset) -> Result<String> {
    let Some(digest) = asset.digest.as_deref() else {
        anyhow::bail!(
            "No SHA-256 checksum for PHP asset {}; refusing to install an unverified binary",
            asset.name
        );
    };
    parse_sha256_digest(digest, "GitHub release asset digest")
}

/// Find the interpreter below `staging` (shallowest match wins): an
/// unversioned `php` first, then the channel binary (`php8.5`). Symlinks are
/// skipped so a link cycle or an escaping link can never be followed.
fn find_php_binary(staging: &Path, channel: &str) -> Option<PathBuf> {
    let expected = format!("php{channel}");
    let mut plain: Vec<(usize, PathBuf)> = Vec::new();
    let mut versioned: Vec<(usize, PathBuf)> = Vec::new();
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
            } else if path.file_name().and_then(|name| name.to_str()) == Some("php") {
                plain.push((depth, path));
            } else if path.file_name().and_then(|name| name.to_str()) == Some(expected.as_str()) {
                versioned.push((depth, path));
            }
        }
    }
    for pool in [&mut plain, &mut versioned] {
        pool.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    }
    plain
        .into_iter()
        .chain(versioned)
        .next()
        .map(|(_, path)| path)
}

/// Link the discovered interpreter to `staging/bin/php` so activation and
/// the smoke test share one stable path.
fn link_staged_php(staging: &Path, found: &Path) -> Result<PathBuf> {
    let bin_dir = staging.join("bin");
    let link = bin_dir.join("php");
    if found == link {
        return Ok(link);
    }
    fs::create_dir_all(&bin_dir).with_context(|| {
        format!(
            "Failed to create staging bin directory: {}",
            bin_dir.display()
        )
    })?;
    if link.exists() || link.is_symlink() {
        anyhow::bail!(
            "Refusing to overwrite unexpected staging path: {}",
            link.display()
        );
    }
    let target = pathdiff_relative(found, &bin_dir);
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, &link).with_context(|| {
        format!(
            "Failed to link PHP binary into staging bin dir: {}",
            link.display()
        )
    })?;
    #[cfg(not(unix))]
    {
        let _ = target;
        anyhow::bail!("PHP installs are unsupported on this platform");
    }
    Ok(link)
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

impl PhpManager {
    pub fn new() -> Self {
        Self {
            versions_dir: super::DATA_DIR.join("versions/php"),
            client: download_client(),
        }
    }

    /// List available upstream channels (newest first).
    pub async fn list_available(&self) -> Result<Vec<PhpVersion>> {
        let releases = fetch_github_releases(
            self.client,
            PHP_BUILDER_RELEASES_URL,
            LIST_PER_PAGE,
            LIST_MAX_PAGES,
            |_| false,
        )
        .await
        .context("Failed to fetch PHP releases from GitHub")?;
        Ok(parse_channel_versions(releases))
    }

    /// Resolve `latest` and partial requests (`8`) against the upstream
    /// channel list. Exact channels pass through so the installed fast path
    /// and the existing not-found UX are preserved.
    pub async fn resolve_alias(&self, alias: &str) -> Result<String> {
        let alias = normalize_version(alias);
        if alias == "latest" {
            let versions = self.list_available().await?;
            versions
                .into_iter()
                .find(|version| !version.prerelease)
                .map(|version| version.version)
                .context("No PHP versions found upstream")
        } else {
            Ok(alias)
        }
    }

    /// Resolve a partial version against the upstream channel list.
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

    /// Fetch the rolling release for one resolved channel.
    async fn release_for_version(&self, version: &str) -> Result<GithubRelease> {
        let releases = fetch_github_releases(
            self.client,
            PHP_BUILDER_RELEASES_URL,
            LIST_PER_PAGE,
            LIST_MAX_PAGES,
            |release| release.tag_name == version,
        )
        .await
        .context("Failed to fetch PHP releases from GitHub")?;
        releases
            .into_iter()
            .find(|release| release.tag_name == version)
            .with_context(|| {
                format!(
                    "PHP version {version} not found: php-builder publishes rolling major.minor channels (never exact patches), so request a channel such as 8.5. Check available versions with: omg list php --available"
                )
            })
    }

    /// Install PHP from a php-builder prebuilt tarball.
    pub async fn install(&self, version: &str) -> Result<()> {
        ensure_linux()?;
        let version = self.resolve_alias(version).await?;
        let version = self.resolve_requested_version(&version).await?;
        crate::core::security::validate_runtime_version(&version)?;
        let version_dir = self.versions_dir.join(&version);

        if version_dir.exists() {
            anyhow::ensure!(
                is_valid_version_dir(&version_dir),
                "Refusing to replace an invalid PHP channel directory: {}",
                version_dir.display()
            );
        }

        println!(
            "{} Installing PHP {}...\n",
            style::runtime("OMG"),
            style::caution(&version)
        );

        let distro = php_distro()?;
        let arch_suffix = host_arch_suffix()?;
        let release = self.release_for_version(&version).await?;
        let asset = select_asset(&release.assets, &version, &distro, arch_suffix).with_context(|| {
            format!(
                "No installable PHP {version} asset for distro {distro} on {} (php-builder publishes Debian/Ubuntu builds only); try OMG_PHP_DISTRO=<distro>",
                std::env::consts::ARCH
            )
        })?;
        validate_download_filename(&asset.name)?;
        let url = asset
            .browser_download_url
            .clone()
            .with_context(|| format!("PHP vendor asset has no download URL: {}", asset.name))?;
        let checksum = checksum_for_asset(asset)?;

        fs::create_dir_all(&self.versions_dir)?;

        println!("{} Downloading {}...", style::informative("→"), asset.name);
        let downloads = tempfile::Builder::new()
            .prefix(".download-")
            .tempdir_in(&self.versions_dir)?;
        let download_path = downloads.path().join(&asset.name);
        download_with_progress(self.client, &url, &download_path, &checksum).await?;

        println!("{} Extracting (pure Rust)...", style::informative("→"));
        let staging = begin_staged_install(&self.versions_dir)?;
        // System-root tarballs unwrap one level (`usr/bin/php8.5` becomes
        // `bin/php8.5`); flat archives fall back to strip 0.
        extract_tar_xz(&download_path, staging.path(), 1).await?;
        let mut found = find_php_binary(staging.path(), &version);
        if found.is_none() {
            clear_dir_contents(staging.path())?;
            extract_tar_xz(&download_path, staging.path(), 0).await?;
            found = find_php_binary(staging.path(), &version);
        }
        let found = found.with_context(|| {
            format!(
                "Installed PHP {version} archive but found no `php` binary inside; refusing to publish a broken install"
            )
        })?;
        make_staged_executable(&found)?;
        link_staged_php(staging.path(), &found)?;
        println!("{} Verifying installation...", style::informative("→"));
        if let Err(error) = smoke_php(staging.path()) {
            return Err(error.context(format!(
                "The prebuilt PHP {version} binary does not run here (likely a foreign distro build); try OMG_PHP_DISTRO=<distro>"
            )));
        }

        if is_valid_version_dir(&version_dir) {
            replace_staged_install(&staging, &version_dir, &version)?;
        } else {
            complete_staged_install(&staging, &version_dir, &version)?;
        }
        remove_file_best_effort(&download_path, "runtime archive");
        print_installed("PHP", &version);
        self.use_version(&version)?;

        Ok(())
    }

    /// Switch to a specific version.
    pub fn use_version(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        activate_version_with_linked_binary(&self.versions_dir, &version, Path::new("bin/php"))?;
        print_using("PHP", &version, &self.versions_dir.join("current"));
        Ok(())
    }

    /// Remove an installed version. Refuses the active version.
    pub fn uninstall(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        uninstall_version(&self.versions_dir, &version)
    }
}

// Generate common runtime manager methods (list_installed, current_version)
super::common::impl_runtime_common!(PhpManager);

/// Smoke-test the installed runtime: the interpreter must start and report
/// its version. This is also the distro-compatibility probe: a build for a
/// foreign distro fails here and the install is removed.
fn smoke_php(version_dir: &Path) -> Result<()> {
    let php = version_dir.join("bin/php");
    let mut command = std::process::Command::new(&php);
    super::common::harden_untrusted_runtime_command(&mut command, version_dir);
    let output = command
        .arg("-v")
        .output()
        .with_context(|| format!("Failed to run smoke test: {}", php.display()))?;
    if output.status.success() {
        return Ok(());
    }
    let detail: String =
        crate::cli::style::sanitize_terminal_text(&String::from_utf8_lossy(&output.stderr))
            .trim()
            .chars()
            .take(300)
            .collect();
    anyhow::bail!(
        "PHP smoke test (`php -v`) failed with status {}: {}{}",
        output.status,
        php.display(),
        if detail.is_empty() {
            String::new()
        } else {
            format!("\n{detail}")
        }
    )
}

/// Ensure the installed `php` is executable (tarballs may drop modes).
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
    anyhow::bail!("PHP installs are unsupported on this platform")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(name: &str, digest: Option<&str>) -> GithubAsset {
        GithubAsset {
            name: name.to_owned(),
            browser_download_url: Some(format!("https://example.com/{name}")),
            digest: digest.map(str::to_owned),
        }
    }

    fn fixture_release(tag: &str) -> GithubRelease {
        GithubRelease {
            tag_name: tag.to_owned(),
            prerelease: false,
            assets: vec![
                asset("install.sh", None),
                asset(&format!("php_{tag}+ubuntu24.04.tar.xz"), None),
            ],
        }
    }

    #[test]
    fn channel_tags_accept_only_numeric_minors() {
        for tag in ["5.6", "7.4", "8.0", "8.5", "8.6"] {
            assert!(is_channel_tag(tag), "{tag}");
        }
        for tag in [
            "libraries",
            "8",
            "8.5.10",
            "v8.5",
            "",
            "8.5-rc1",
            "8.5.10-dev",
            "php-8.5.10",
        ] {
            assert!(!is_channel_tag(tag), "{tag}");
        }
    }

    #[test]
    fn channel_versions_parse_newest_first_without_libraries() {
        let releases = vec![
            fixture_release("libraries"),
            fixture_release("8.5"),
            fixture_release("5.6"),
            fixture_release("8.6"),
            fixture_release("7.4"),
        ];
        let versions = parse_channel_versions(releases);
        let names: Vec<&str> = versions
            .iter()
            .map(|version| version.version.as_str())
            .collect();
        assert_eq!(names, vec!["8.6", "8.5", "7.4", "5.6"]);
        assert!(versions.iter().all(|version| !version.prerelease));
    }

    #[test]
    fn asset_selection_matches_exact_xz_payload_only() {
        let digest = format!("sha256:{}", "ab".repeat(32));
        let assets = vec![
            asset("install.sh", None),
            asset("build.log", None),
            asset("php8.5.log", None),
            asset("php_8.5+ubuntu24.04.tar.zst", Some(&digest)),
            asset("php_8.5+ubuntu24.04_arm64.tar.xz", Some(&digest)),
            asset("php_8.5-zts+ubuntu24.04.tar.xz", Some(&digest)),
            asset("php_8.5-dbgsym+ubuntu24.04.tar.xz", Some(&digest)),
            asset("php_8.5-zts-dbgsym+ubuntu24.04.tar.xz", Some(&digest)),
            asset("php_8.5+debian12.tar.xz", Some(&digest)),
            asset("php_8.5+ubuntu24.04.tar.xz", Some(&digest)),
        ];
        let selected =
            select_asset(&assets, "8.5", "ubuntu24.04", "").expect("xz payload must win");
        assert_eq!(selected.name, "php_8.5+ubuntu24.04.tar.xz");
        let arm = select_asset(&assets, "8.5", "ubuntu24.04", "_arm64")
            .expect("arm64 payload must be selectable");
        assert_eq!(arm.name, "php_8.5+ubuntu24.04_arm64.tar.xz");
        assert!(select_asset(&assets, "8.5", "ubuntu22.04", "").is_none());
        assert!(select_asset(&assets, "8.4", "ubuntu24.04", "").is_none());
    }

    #[test]
    fn asset_name_shapes_match_publisher_layout() {
        assert_eq!(
            asset_name("8.5", "ubuntu24.04", ""),
            "php_8.5+ubuntu24.04.tar.xz"
        );
        assert_eq!(
            asset_name("8.5", "ubuntu24.04", "_arm64"),
            "php_8.5+ubuntu24.04_arm64.tar.xz"
        );
        assert_eq!(asset_name("7.4", "debian11", ""), "php_7.4+debian11.tar.xz");
    }

    #[test]
    fn checksum_requires_github_digest() {
        let digest = format!("sha256:{}", "cd".repeat(32));
        let checksum = checksum_for_asset(&asset("php_8.5+ubuntu24.04.tar.xz", Some(&digest)))
            .expect("digest must verify");
        assert_eq!(
            checksum,
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
        );
        let missing = checksum_for_asset(&asset("php_8.5+ubuntu24.04.tar.xz", None))
            .expect_err("missing digest must fail closed");
        assert!(missing.to_string().contains("unverified"), "{missing:#}");
        assert!(
            checksum_for_asset(&asset("php_8.5+ubuntu24.04.tar.xz", Some("not-a-hash"))).is_err()
        );
    }

    #[test]
    fn os_release_mapping_matches_publisher_distros() {
        assert_eq!(map_os_release("ubuntu", "24.04", ""), "ubuntu24.04");
        assert_eq!(map_os_release("ubuntu", "22.04", ""), "ubuntu22.04");
        assert_eq!(map_os_release("ubuntu", "26.04", ""), "ubuntu26.04");
        assert_eq!(map_os_release("ubuntu", "25.10", ""), "ubuntu24.04");
        assert_eq!(map_os_release("debian", "12", ""), "debian12");
        assert_eq!(map_os_release("debian", "11", ""), "debian11");
        assert_eq!(map_os_release("debian", "13", ""), "debian13");
        assert_eq!(map_os_release("debian", "10", ""), "ubuntu24.04");
        // Derivatives follow ID_LIKE; a bare major still maps to its LTS.
        assert_eq!(map_os_release("linuxmint", "22", "ubuntu"), "ubuntu22.04");
        assert_eq!(map_os_release("raspbian", "12", "debian"), "debian12");
        assert_eq!(map_os_release("fedora", "42", ""), "ubuntu24.04");
        assert_eq!(map_os_release("", "", ""), "ubuntu24.04");
    }

    #[test]
    fn os_release_fields_parse_quoted_values() {
        let content = "ID=ubuntu\nVERSION_ID=\"24.04\"\nID_LIKE=debian\n";
        assert_eq!(os_release_field(content, "ID"), "ubuntu");
        assert_eq!(os_release_field(content, "VERSION_ID"), "24.04");
        assert_eq!(os_release_field(content, "ID_LIKE"), "debian");
        assert_eq!(os_release_field(content, "MISSING"), "");
    }

    #[test]
    fn host_arch_suffix_names_the_tarball_variant() {
        let suffix = host_arch_suffix().expect("host arch should be supported");
        match std::env::consts::ARCH {
            "x86_64" => assert_eq!(suffix, ""),
            "aarch64" => assert_eq!(suffix, "_arm64"),
            arch => panic!("unexpected test host arch: {arch}"),
        }
    }

    #[test]
    fn versions_sort_newest_first_numerically() {
        let mut versions = vec![
            PhpVersion {
                version: "7.4".to_string(),
                prerelease: false,
            },
            PhpVersion {
                version: "8.6".to_string(),
                prerelease: false,
            },
            PhpVersion {
                version: "8.5".to_string(),
                prerelease: false,
            },
            PhpVersion {
                version: "5.6".to_string(),
                prerelease: false,
            },
        ];
        sort_versions_desc(&mut versions);
        let names: Vec<&str> = versions
            .iter()
            .map(|version| version.version.as_str())
            .collect();
        assert_eq!(names, vec!["8.6", "8.5", "7.4", "5.6"]);
    }

    /// The staged sysroot layout unwraps one level (`usr/bin/php8.5` becomes
    /// `bin/php8.5`); the channel binary must be found and linked to
    /// `bin/php`.
    #[cfg(unix)]
    #[test]
    fn staged_sysroot_binary_is_found_and_linked() {
        let staging = tempfile::TempDir::new().expect("staging dir");
        let payload = staging.path().join("bin").join("php8.5");
        fs::create_dir_all(payload.parent().expect("bin dir")).expect("bin dir");
        fs::write(&payload, b"fake").expect("fake binary");

        let found = find_php_binary(staging.path(), "8.5").expect("binary must be found");
        assert_eq!(found, payload);

        let link = link_staged_php(staging.path(), &found).expect("link must be created");
        assert_eq!(link, staging.path().join("bin").join("php"));
        assert_eq!(
            fs::read_link(&link).expect("link target"),
            PathBuf::from("php8.5")
        );
    }

    /// A flat staging tree (strip 0 fallback) still resolves, with `bin/php`
    /// reaching outside `bin/` via a relative link.
    #[cfg(unix)]
    #[test]
    fn staged_flat_tree_binary_links_relatively() {
        let staging = tempfile::TempDir::new().expect("staging dir");
        let payload = staging.path().join("usr").join("bin").join("php8.5");
        fs::create_dir_all(payload.parent().expect("usr bin dir")).expect("usr bin dir");
        fs::write(&payload, b"fake").expect("fake binary");

        let found = find_php_binary(staging.path(), "8.5").expect("binary must be found");
        let link = link_staged_php(staging.path(), &found).expect("link must be created");
        assert_eq!(
            fs::read_link(&link).expect("link target"),
            PathBuf::from("../usr/bin/php8.5")
        );
    }

    #[test]
    fn staged_tree_without_php_fails_closed() {
        let staging = tempfile::TempDir::new().expect("staging dir");
        fs::write(staging.path().join("phpize8.5"), b"fake").expect("decoy file");
        assert!(find_php_binary(staging.path(), "8.5").is_none());
    }

    #[test]
    fn pathdiff_relative_stays_internal() {
        let base = Path::new("/staging/bin");
        let target = Path::new("/staging/usr/bin/php8.5");
        assert_eq!(
            pathdiff_relative(target, base),
            PathBuf::from("../usr/bin/php8.5")
        );
    }
}
