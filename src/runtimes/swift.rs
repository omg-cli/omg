//! Native Swift toolchain manager.
//!
//! Installs official Swift.org Linux tarballs published at
//! `https://download.swift.org` (same source the
//! [swiftly installer](https://www.swift.org/install/linux/swiftly/) and the
//! Docker [official-images](https://github.com/docker-library/official-images)
//! `swift` image consume). The layout for one release is:
//!
//! ```text
//! https://download.swift.org
//!   /swift-<version>-release            # lowercase `-release`, dotless distro dir
//!   /ubuntu2404[-aarch64]               # `ubuntu2404`, aarch64 appends `-aarch64`
//!   /swift-<version>-RELEASE            # UPPERCASE `-RELEASE` tag directory
//!   /swift-<version>-RELEASE-ubuntu24.04[-aarch64].tar.gz  # dotted distro, `.sig` sidecar
//! ```
//!
//! Version discovery uses the `swiftlang/swift` GitHub Releases endpoint
//! (newest first, no snapshot spam — the raw tags endpoint buries stable
//! `swift-<X.Y[.Z]>-RELEASE` tags under thousands of
//! `*-DEVELOPMENT-SNAPSHOT-*` tags). Entries flagged `prerelease` plus any
//! tag that is not exactly `swift-<numeric>-RELEASE` (`PREVIEW`,
//! `GM-CANDIDATE`, snapshots, branch junk) are excluded.
//!
//! Verification is fail-closed GPG: every tarball ships a detached
//! `<tarball>.sig` sidecar verified with Sequoia-OpenPGP against a cached
//! copy of the official release-signing keys at
//! `https://www.swift.org/keys/all-keys.asc` (the same keyring `gpg --import`
//! step the swiftly docs prescribe). No valid signature -> no install; the
//! keyring is refreshed on every install and the previous cache is only a
//! fallback when the refresh itself fails.
//!
//! Layout: tarballs extract to `<top>/usr/bin/swift`, so the `usr/` tree is
//! kept intact (strip 1 removes only the `<top>` directory). The parent must
//! add `<versions>/swift/<version>/usr/bin` to `PATH`
//! (`current/usr/bin` once activated). Scope is Ubuntu-only: Swift.org
//! publishes `ubuntu2204`/`ubuntu2404` builds, so any other host bails with
//! a clear message instead of downloading an incompatible toolchain.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use super::common::{
    GithubRelease, activate_version_with_linked_binary, begin_staged_install,
    complete_staged_install, download_to_temp_for_signature, extract_tar_gz, fetch_github_releases,
    is_valid_version_dir, normalize_version, print_already_installed, print_installed, print_using,
    remove_file_best_effort, uninstall_version, validate_download_filename,
};

// Published at https://www.swift.org/keys/active/. Keep this list explicit so
// replacing the remotely fetched aggregate keyring cannot silently add trust.
#[cfg(feature = "pgp")]
const SWIFT_SIGNING_FINGERPRINTS: &[&str] = &[
    "E813C892820A6FA13755B268F167DF1ACF9CE069", // Automatic signing key #4
    "A62AE125BBBFBB96A6E042EC925CC1CCED3D1561", // Swift 5.x releases
    "52BB7E3DE28A71BE22EC05FFEF80A866B47A981F", // Swift 6.x releases
];
#[cfg(feature = "pgp")]
use crate::core::security::pgp::PgpVerifier;
use crate::{cli::style, core::http::download_client};

/// GitHub Releases endpoint for version discovery (newest first).
const SWIFT_RELEASES_URL: &str = "https://api.github.com/repos/swiftlang/swift/releases";
const SWIFT_LIST_PER_PAGE: u32 = 100;
const SWIFT_LIST_MAX_PAGES: u32 = 5;

/// Official Swift release-signing keyring (same URL the swiftly install docs
/// pipe into `gpg --import`).
const SWIFT_KEYS_URL: &str = "https://www.swift.org/keys/all-keys.asc";

/// Root of the official Swift download archive.
const SWIFT_DOWNLOAD_BASE: &str = "https://download.swift.org";

/// Binary path inside the extracted `usr/` tree, also used as the activation
/// probe and the smoke-test target.
const SWIFT_BINARY: &str = "usr/bin/swift";

/// A stable upstream Swift release. `prerelease` is always false today (the
/// parser drops prerelease entries); the field mirrors sibling managers so a
/// future prerelease channel needs no API change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SwiftVersion {
    /// Bare version (`6.3.3`, `6.0`); the `swift-` prefix and `-RELEASE`
    /// suffix are stripped.
    pub(crate) version: String,
    pub(crate) prerelease: bool,
}

pub(crate) struct SwiftManager {
    versions_dir: PathBuf,
    keyring_path: PathBuf,
    client: &'static reqwest::Client,
}

/// Map `/etc/os-release` identity to a Swift.org Ubuntu build. Swift.org only
/// publishes `ubuntu2204`/`ubuntu2404` toolchains, so anything else —
/// other Ubuntu series, Debian, Fedora, Arch — has no compatible build and
/// maps to `None` instead of a closest guess.
fn map_os_release(distro_id: &str, version_id: &str) -> Option<&'static str> {
    match (distro_id, version_id) {
        ("ubuntu", "22.04") => Some("22.04"),
        ("ubuntu", "24.04") => Some("24.04"),
        _ => None,
    }
}

/// Parse one `ID=`/`VERSION_ID=` field out of os-release content.
fn os_release_field(content: &str, key: &str) -> String {
    content
        .lines()
        .filter_map(|line| line.split_once('='))
        .find(|(name, _)| name.trim() == key)
        .map(|(_, value)| value.trim().trim_matches('"').to_string())
        .unwrap_or_default()
}

/// Detect the Swift.org Ubuntu build for this host, bailing on anything
/// without a published toolchain.
fn ubuntu_release() -> Result<String> {
    if std::env::consts::OS != "linux" {
        anyhow::bail!(
            "Unsupported operating system for Swift: {} (Swift toolchains are Ubuntu 22.04/24.04 Linux builds)",
            std::env::consts::OS
        );
    }
    let content = fs::read_to_string("/etc/os-release").unwrap_or_default();
    let distro = os_release_field(&content, "ID");
    let release = os_release_field(&content, "VERSION_ID");
    map_os_release(&distro, &release).map(str::to_string).with_context(|| {
        format!(
            "Unsupported Linux distribution for Swift: {distro} {release} (Swift.org publishes Ubuntu 22.04 and 24.04 toolchains only)"
        )
    })
}

/// Arch suffix shared by the directory slug (`ubuntu2404-aarch64`) and the
/// file slug (`ubuntu24.04-aarch64`); x86_64 builds carry no suffix.
fn host_arch_suffix() -> Result<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(""),
        "aarch64" => Ok("-aarch64"),
        arch => anyhow::bail!(
            "Unsupported architecture for Swift: {arch} (Swift.org publishes x86_64 and aarch64 toolchains only)"
        ),
    }
}

/// Tarball download URL for one version on this host. Note the slug quirks:
/// the release dir is lowercase (`swift-6.3.3-release`), the tag dir is
/// uppercase (`swift-6.3.3-RELEASE`), the distro dir is dotless
/// (`ubuntu2404`) while the file slug is dotted (`ubuntu24.04`).
fn tarball_url(version: &str, ubuntu: &str, arch_suffix: &str) -> String {
    let compact = ubuntu.replace('.', "");
    format!(
        "{SWIFT_DOWNLOAD_BASE}/swift-{version}-release/ubuntu{compact}{arch_suffix}\
         /swift-{version}-RELEASE/swift-{version}-RELEASE-ubuntu{ubuntu}{arch_suffix}.tar.gz"
    )
}

/// Whether a GitHub release tag is a stable Swift release. Only
/// `swift-<two or three numeric components>-RELEASE` qualifies; snapshots,
/// previews, GM candidates, and branch junk are rejected.
fn parse_release_tag(tag: &str) -> Option<String> {
    let bare = tag.strip_prefix("swift-")?.strip_suffix("-RELEASE")?;
    is_stable_version(bare).then(|| bare.to_string())
}

fn is_stable_version(version: &str) -> bool {
    let parts: Vec<&str> = version.split('.').collect();
    (2..=3).contains(&parts.len())
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Filter GitHub releases down to stable versions, newest first.
fn parse_swift_versions(releases: &[GithubRelease]) -> Vec<SwiftVersion> {
    let mut versions: Vec<SwiftVersion> = releases
        .iter()
        .filter(|release| !release.prerelease)
        .filter_map(|release| {
            parse_release_tag(&release.tag_name).map(|version| SwiftVersion {
                version,
                prerelease: release.prerelease,
            })
        })
        .collect();
    versions.sort_by(|left, right| {
        super::common::version_cmp(&right.version, &left.version)
            .then_with(|| left.version.cmp(&right.version))
    });
    versions
}

/// Download into the install's private staging directory with the common
/// bounded retry and validated range path. Integrity remains the caller's
/// detached GPG verification before extraction.
async fn download_file(client: &reqwest::Client, url: &str, dest: &Path) -> Result<()> {
    download_to_temp_for_signature(client, url, dest)
        .await?
        .persist(dest)
        .map_err(|error| error.error)
        .with_context(|| {
            format!(
                "Failed to finalize Swift staged download: {}",
                dest.display()
            )
        })?;
    Ok(())
}

/// Create an extraction stage only after the detached signature succeeds.
async fn verify_and_extract_tarball(
    keyring: &Path,
    tarball: &Path,
    signature: &Path,
    versions_dir: &Path,
) -> Result<tempfile::TempDir> {
    println!("{} Verifying GPG signature...", style::informative("→"));
    if let Err(error) = verify_tarball_signature(keyring, tarball, signature) {
        remove_file_best_effort(tarball, "runtime archive");
        remove_file_best_effort(signature, "detached signature");
        return Err(error);
    }
    remove_file_best_effort(signature, "detached signature");
    println!("{} Extracting (pure Rust)...", style::informative("→"));
    let staging = begin_staged_install(versions_dir)?;
    // Strip only the vendor's top directory, preserving its usr/ tree.
    extract_tar_gz(tarball, staging.path(), 1).await?;
    Ok(staging)
}

/// Verify a tarball against its detached `.sig` sidecar using the cached
/// Swift.org release-signing keyring. Every failure mode refuses the install.
#[cfg(feature = "pgp")]
fn verify_tarball_signature(keyring: &Path, tarball: &Path, signature: &Path) -> Result<()> {
    crate::core::security::pgp::require_detached_signature_files("Swift", tarball, signature)?;
    let verifier =
        PgpVerifier::from_keyring_with_allowed_fingerprints(keyring, SWIFT_SIGNING_FINGERPRINTS)
            .with_context(|| {
                format!(
                    "Failed to load Swift signing keyring: {}",
                    keyring.display()
                )
            })?;
    verifier
        .verify_detached(tarball, signature)
        .with_context(|| {
            format!(
                "Swift GPG signature verification failed for {}; refusing to install an unverified toolchain",
                tarball.display()
            )
        })?;
    Ok(())
}

/// Without the `pgp` feature there is no verifier, so Swift installs — which
/// are GPG-only by design — must refuse rather than install unverified.
#[cfg(not(feature = "pgp"))]
fn verify_tarball_signature(keyring: &Path, tarball: &Path, signature: &Path) -> Result<()> {
    let _ = (keyring, tarball, signature);
    anyhow::bail!(
        "Swift installs require GPG signature verification, which needs the `pgp` cargo feature"
    )
}

impl SwiftManager {
    pub fn new() -> Self {
        Self {
            versions_dir: super::DATA_DIR.join("versions/swift"),
            keyring_path: super::DATA_DIR.join("swift/all-keys.asc"),
            client: download_client(),
        }
    }

    #[cfg(test)]
    fn with_paths(versions_dir: PathBuf, keyring_path: PathBuf) -> Self {
        Self {
            versions_dir,
            keyring_path,
            client: download_client(),
        }
    }

    /// List available stable upstream releases (newest first).
    pub async fn list_available(&self) -> Result<Vec<SwiftVersion>> {
        let releases = fetch_github_releases(
            self.client,
            SWIFT_RELEASES_URL,
            SWIFT_LIST_PER_PAGE,
            SWIFT_LIST_MAX_PAGES,
            |_| false,
        )
        .await
        .context("Failed to fetch Swift releases from GitHub")?;
        Ok(parse_swift_versions(&releases))
    }

    /// Resolve `latest` against the upstream list. Exact versions pass
    /// through so the installed fast path and the existing not-found UX are
    /// preserved.
    pub async fn resolve_alias(&self, alias: &str) -> Result<String> {
        let alias = normalize_version(alias);
        if alias == "latest" {
            let versions = self.list_available().await?;
            versions
                .first()
                .map(|version| version.version.clone())
                .context("No Swift versions found upstream")
        } else {
            Ok(alias)
        }
    }

    /// Resolve a partial version request (`6`, `6.3`) to the newest matching
    /// upstream release before any tarball URL is built.
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

    /// Refuse versions Swift.org never published before downloading ~1 GiB.
    async fn ensure_known_version(&self, version: &str) -> Result<()> {
        let available = self.list_available().await?;
        if available
            .iter()
            .any(|candidate| candidate.version == version)
        {
            Ok(())
        } else {
            anyhow::bail!(
                "Version {version} not found for Swift. Check available versions with: omg list swift --available"
            )
        }
    }

    /// Fetch the release-signing keyring, refreshing the cache on every
    /// install. A failed refresh falls back to the existing cache with a
    /// warning; with neither cached keys nor a fresh download the install
    /// fails closed.
    async fn ensure_keyring(&self) -> Result<PathBuf> {
        if let Some(parent) = self.keyring_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "Failed to create Swift keyring directory: {}",
                    parent.display()
                )
            })?;
        }
        let parent = self
            .keyring_path
            .parent()
            .context("Swift keyring has no parent")?;
        let candidate_dir = tempfile::Builder::new()
            .prefix(".keys-")
            .tempdir_in(parent)?;
        let candidate = candidate_dir.path().join("keyring.asc");
        let refreshed = async {
            download_file(self.client, SWIFT_KEYS_URL, &candidate).await?;
            publish_keyring(&candidate, &self.keyring_path)
        }
        .await;
        match refreshed {
            Ok(()) => {}
            Err(error) if self.keyring_path.is_file() => {
                validate_keyring(&self.keyring_path)?;
                tracing::warn!(
                    "Failed to refresh Swift signing keys ({error:#}); using the cached keyring"
                );
            }
            Err(error) => {
                return Err(error).context(
                    "Failed to download Swift release-signing keys from https://www.swift.org/keys/all-keys.asc",
                );
            }
        }
        Ok(self.keyring_path.clone())
    }

    /// Install the Swift toolchain from an official Swift.org tarball after
    /// fail-closed GPG verification.
    pub async fn install(&self, version: &str) -> Result<()> {
        let version = self.resolve_alias(version).await?;
        let version = self.resolve_requested_version(&version).await?;
        crate::core::security::validate_runtime_version(&version)?;
        let ubuntu = ubuntu_release()?;
        let arch_suffix = host_arch_suffix()?;
        let _install_lease = super::common::try_lock_runtime_install(&self.versions_dir, &version)?;
        let version_dir = self.versions_dir.join(&version);

        // The fast path additionally requires `usr/bin/swift`: a directory
        // that survived extraction but never verified or published cleanly
        // must reinstall rather than activate.
        if is_valid_version_dir(&version_dir) && version_dir.join(SWIFT_BINARY).is_file() {
            print_already_installed("Swift", &version);
            return self.use_version(&version);
        }
        if version_dir.exists() {
            fs::remove_dir_all(&version_dir).with_context(|| {
                format!(
                    "Failed to clear incomplete Swift install at {}",
                    version_dir.display()
                )
            })?;
        }

        println!(
            "{} Installing Swift {}...\n",
            style::runtime("OMG"),
            style::caution(&version)
        );

        self.ensure_known_version(&version).await?;

        let url = tarball_url(&version, &ubuntu, arch_suffix);
        let sig_url = format!("{url}.sig");
        let filename = url
            .rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .with_context(|| format!("Swift tarball URL has no filename: {url}"))?;
        validate_download_filename(filename)?;
        let sig_filename = format!("{filename}.sig");
        validate_download_filename(&sig_filename)?;

        println!(
            "{} Fetching Swift release-signing keys...",
            style::informative("→")
        );
        let keyring = self.ensure_keyring().await?;

        fs::create_dir_all(&self.versions_dir)?;

        println!("{} Downloading {filename}...", style::informative("→"));
        let downloads = tempfile::Builder::new()
            .prefix(".download-")
            .tempdir_in(&self.versions_dir)?;
        let download_path = downloads.path().join(filename);
        let sig_path = downloads.path().join(&sig_filename);
        download_file(self.client, &url, &download_path).await?;
        if let Err(error) = download_file(self.client, &sig_url, &sig_path).await {
            remove_file_best_effort(&download_path, "runtime archive");
            return Err(error);
        }

        let staging =
            verify_and_extract_tarball(&keyring, &download_path, &sig_path, &self.versions_dir)
                .await?;
        if !staging.path().join(SWIFT_BINARY).is_file() {
            remove_file_best_effort(&download_path, "runtime archive");
            anyhow::bail!(
                "Installed Swift archive but found no `{SWIFT_BINARY}` inside; \
                 refusing to publish an incomplete toolchain"
            );
        }
        make_staged_executable(&staging.path().join(SWIFT_BINARY))?;
        println!("{} Verifying installation...", style::informative("→"));
        smoke_swift(staging.path(), &version)?;
        complete_staged_install(&staging, &version_dir, &version)?;
        remove_file_best_effort(&download_path, "runtime archive");

        print_installed("Swift", &version);
        self.use_version(&version)?;

        Ok(())
    }

    /// Switch to a specific version.
    pub fn use_version(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        activate_version_with_linked_binary(&self.versions_dir, &version, Path::new(SWIFT_BINARY))?;
        print_using(
            "Swift",
            &version,
            &self.versions_dir.join("current/usr/bin"),
        );
        Ok(())
    }

    /// Remove an installed version. Refuses the active version.
    pub fn uninstall(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        uninstall_version(&self.versions_dir, &version)
    }
}

// Generate common runtime manager methods (list_installed, current_version)
super::common::impl_runtime_common!(SwiftManager);

fn publish_keyring(candidate: &Path, destination: &Path) -> Result<()> {
    validate_keyring(candidate)?;
    fs::rename(candidate, destination).context("Failed to publish validated Swift keyring")
}

#[cfg(feature = "pgp")]
fn validate_keyring(path: &Path) -> Result<()> {
    PgpVerifier::from_keyring_with_allowed_fingerprints(path, SWIFT_SIGNING_FINGERPRINTS)?;
    Ok(())
}

#[cfg(not(feature = "pgp"))]
fn validate_keyring(_path: &Path) -> Result<()> {
    anyhow::bail!("Swift signature verification requires the pgp feature")
}

/// Smoke-test the toolchain and bind its reported version to the request.
fn smoke_swift(version_dir: &Path, expected: &str) -> Result<()> {
    let swift = version_dir.join(SWIFT_BINARY);
    let mut command = std::process::Command::new(&swift);
    super::common::harden_untrusted_runtime_command(&mut command, version_dir);
    let output = command
        .arg("--version")
        .output()
        .with_context(|| format!("Failed to run smoke test: {}", swift.display()))?;
    if output.status.success() {
        let text =
            std::str::from_utf8(&output.stdout).context("Swift version output is not UTF-8")?;
        let actual = text
            .lines()
            .find_map(|line| {
                line.split_once("Swift version ")
                    .and_then(|(_, rest)| rest.split_whitespace().next())
            })
            .context("Swift did not report its version")?;
        anyhow::ensure!(
            is_stable_version(actual) && super::common::version_cmp(actual, expected).is_eq(),
            "Swift artifact version {actual} does not match requested {expected}"
        );
        Ok(())
    } else {
        let stderr =
            crate::cli::style::sanitize_terminal_text(&String::from_utf8_lossy(&output.stderr));
        let stderr: String = stderr.chars().take(300).collect();
        anyhow::bail!(
            "Swift smoke test failed with status {}: {}: {}",
            output.status,
            swift.display(),
            stderr.trim()
        )
    }
}

/// Ensure the installed `swift` is executable (tarballs may drop modes).
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
    anyhow::bail!("Swift installs are unsupported on this platform")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swift_download_retries_and_refuses_invalid_transfers() -> Result<()> {
        const CHILD: &str = "OMG_SWIFT_DOWNLOAD_FIXTURE";
        if std::env::var(CHILD).as_deref() == Ok("1") {
            anyhow::ensure!(crate::core::paths::test_mode());
            tokio::runtime::Runtime::new()?.block_on(swift_download_fixture())?;
            println!(
                "[omg-runtime-download-child] test=runtimes::swift::tests::swift_download_retries_and_refuses_invalid_transfers"
            );
            return Ok(());
        }
        let output = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "runtimes::swift::tests::swift_download_retries_and_refuses_invalid_transfers",
                "--nocapture",
            ])
            .env("OMG_TEST_MODE", "1")
            .env(CHILD, "1")
            .output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::ensure!(
            output.status.success()
                && stdout.matches("1 passed; 0 failed; 0 ignored;").count() == 1
                && stdout.lines().filter(|line| *line ==
                    "[omg-runtime-download-child] test=runtimes::swift::tests::swift_download_retries_and_refuses_invalid_transfers"
                ).count() == 1,
            "Swift production download probe failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    async fn swift_download_fixture() -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for scenario in ["resume", "range", "exhausted", "404"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let url = format!("http://{}/archive", listener.local_addr()?);
            let body = b"Swift signed archive transfer fixture";
            let attempts = match scenario {
                "404" => 1,
                "exhausted" => 3,
                _ => 2,
            };
            let directory = tempfile::tempdir()?;
            let dest = directory.path().join("archive.tar.gz");
            fs::write(&dest, b"existing staged artifact")?;
            let server = async {
                async fn wait_for_prefix(directory: &Path, prefix: &[u8]) -> Result<()> {
                    tokio::time::timeout(std::time::Duration::from_secs(2), async {
                        loop {
                            let mut entries = tokio::fs::read_dir(directory).await?;
                            while let Some(entry) = entries.next_entry().await? {
                                if entry
                                    .file_name()
                                    .to_string_lossy()
                                    .starts_with(".download-")
                                    && tokio::fs::read(entry.path()).await? == prefix
                                {
                                    return Ok::<_, anyhow::Error>(());
                                }
                            }
                            tokio::task::yield_now().await;
                        }
                    })
                    .await??;
                    Ok(())
                }
                for step in 0..attempts {
                    let (mut stream, _) = listener.accept().await?;
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") {
                        anyhow::ensure!(request.len() < 4096, "fixture request too large");
                        request.push(stream.read_u8().await?);
                    }
                    let request = String::from_utf8(request)?.to_ascii_lowercase();
                    anyhow::ensure!(request.contains("accept-encoding: identity\r\n"));
                    if scenario == "404" {
                        stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
                    } else if step == 0 || scenario == "exhausted" {
                        // No validator in the exhausted case forces a complete restart.
                        let validator = if scenario == "exhausted" {
                            ""
                        } else {
                            "ETag: \"stable\"\r\n"
                        };
                        anyhow::ensure!(!request.contains("range: bytes="));
                        stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{validator}Connection: close\r\n\r\n", body.len()).as_bytes()).await?;
                        stream.write_all(&body[..8]).await?;
                        if scenario != "exhausted" {
                            // Do not interrupt until the production writer has
                            // actually retained this exact prefix. A TCP write
                            // alone says nothing about the receiver's progress.
                            wait_for_prefix(directory.path(), &body[..8]).await?;
                        }
                    } else {
                        anyhow::ensure!(request.contains("range: bytes=8-\r\n"));
                        anyhow::ensure!(request.contains("if-range: \"stable\"\r\n"));
                        let start = if scenario == "range" { 9 } else { 8 };
                        stream.write_all(format!("HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{}/{}\r\nETag: \"stable\"\r\nConnection: close\r\n\r\n", body.len() - start, body.len() - 1, body.len()).as_bytes()).await?;
                        stream.write_all(&body[start..]).await?;
                    }
                    stream.shutdown().await?;
                }
                // A fatal status/range response and exhausted body budget must not reconnect.
                anyhow::ensure!(
                    tokio::time::timeout(std::time::Duration::from_millis(300), listener.accept())
                        .await
                        .is_err()
                );
                Ok::<_, anyhow::Error>(())
            };
            let client = reqwest::Client::new();
            let download = download_file(&client, &url, &dest);
            let (served, result) =
                tokio::time::timeout(std::time::Duration::from_secs(10), async {
                    tokio::join!(server, download)
                })
                .await?;
            served?;
            if scenario == "resume" {
                result?;
                assert_eq!(fs::read(&dest)?, body);
            } else {
                let error = result.expect_err("invalid transfer must refuse");
                let text = format!("{error:#}");
                match scenario {
                    "range" => assert!(text.contains("range does not match"), "{text}"),
                    "404" => assert!(text.contains("Version not found (404)"), "{text}"),
                    _ => assert!(text.contains("Error downloading chunk"), "{text}"),
                }
                assert_eq!(fs::read(&dest)?, b"existing staged artifact");
            }
            assert_eq!(
                fs::read_dir(directory.path())?.count(),
                1,
                "temporary transfer must be cleaned"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn swift_signature_failure_prevents_extraction() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let tarball = directory.path().join("swift.tar.gz");
        let signature = directory.path().join("swift.tar.gz.sig");
        let keyring = directory.path().join("keys.asc");
        let versions = directory.path().join("versions");
        fs::create_dir(&versions)?;
        fs::write(versions.join("existing"), b"installed version remains")?;
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let data = b"must not extract";
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        archive.append_data(&mut header, "swift/usr/bin/swift", &data[..])?;
        let bytes = archive.into_inner()?.finish()?;
        fs::write(&tarball, &bytes)?;
        #[cfg(feature = "pgp")]
        {
            use sequoia_openpgp::{
                Packet,
                cert::prelude::CertBuilder,
                packet::signature::SignatureBuilder,
                policy::StandardPolicy,
                serialize::Serialize as _,
                types::{HashAlgorithm, SignatureType},
            };
            let (cert, _) = CertBuilder::general_purpose(Some("untrusted@example.invalid"))
                .set_creation_time(
                    std::time::SystemTime::now() - std::time::Duration::from_hours(24),
                )
                .generate()?;
            let mut keys = Vec::new();
            cert.serialize(&mut keys)?;
            fs::write(&keyring, keys)?;
            let policy = StandardPolicy::new();
            let mut signer = cert
                .keys()
                .secret()
                .with_policy(&policy, None)
                .for_signing()
                .next()
                .context("fixture signing key")?
                .key()
                .clone()
                .into_keypair()?;
            let signed = SignatureBuilder::new(SignatureType::Binary)
                .set_hash_algo(HashAlgorithm::SHA256)
                .sign_message(&mut signer, &bytes)?;
            let mut serialized = Vec::new();
            Packet::from(signed).serialize(&mut serialized)?;
            fs::write(&signature, serialized)?;
            // The fixture is cryptographically valid for its own key, but that
            // key is outside Swift's explicit vendor fingerprint allowlist.
            PgpVerifier::from_keyring(&keyring)?.verify_detached(&tarball, &signature)?;
        }
        #[cfg(not(feature = "pgp"))]
        {
            fs::write(&keyring, b"keyring unavailable without pgp")?;
            fs::write(&signature, b"invalid detached signature")?;
        }
        let error = verify_and_extract_tarball(&keyring, &tarball, &signature, &versions)
            .await
            .expect_err("unverified toolchain must refuse before extracting");
        let text = format!("{error:#}");
        #[cfg(feature = "pgp")]
        assert!(
            text.contains("Failed to load Swift signing keyring"),
            "{text}"
        );
        #[cfg(not(feature = "pgp"))]
        assert!(
            text.contains("require GPG signature verification"),
            "{text}"
        );
        assert!(!tarball.exists());
        assert!(!signature.exists());
        assert_eq!(fs::read_dir(&versions)?.count(), 1);
        assert_eq!(
            fs::read(versions.join("existing"))?,
            b"installed version remains"
        );
        #[cfg(feature = "pgp")]
        {
            fs::write(&tarball, bytes)?;
            let error = verify_and_extract_tarball(&keyring, &tarball, &signature, &versions)
                .await
                .expect_err("missing detached signature must refuse");
            assert!(format!("{error:#}").contains("PGP signature missing"));
            assert!(!tarball.exists());
            assert_eq!(fs::read_dir(&versions)?.count(), 1);
        }
        Ok(())
    }

    fn release(tag: &str, prerelease: bool) -> GithubRelease {
        GithubRelease {
            tag_name: tag.to_string(),
            prerelease,
            assets: Vec::new(),
        }
    }

    #[test]
    fn malformed_key_refresh_preserves_cached_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let cached = dir.path().join("cached.asc");
        let candidate = dir.path().join("candidate.asc");
        fs::write(&cached, b"prior cache bytes").unwrap();
        fs::write(&candidate, b"<html>upstream error</html>").unwrap();
        assert!(publish_keyring(&candidate, &cached).is_err());
        assert_eq!(fs::read(&cached).unwrap(), b"prior cache bytes");
    }

    #[cfg(unix)]
    #[test]
    fn smoke_test_rejects_a_different_release() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join(SWIFT_BINARY);
        fs::create_dir_all(binary.parent().unwrap()).unwrap();
        fs::write(
            &binary,
            "#!/bin/sh\nprintf 'Swift version 6.1.2 (release)\\n'\n",
        )
        .unwrap();
        make_staged_executable(&binary).unwrap();
        smoke_swift(dir.path(), "6.1.2").unwrap();
        assert!(smoke_swift(dir.path(), "6.2.0").is_err());
        fs::write(
            &binary,
            "#!/bin/sh\nprintf 'Swift version 6.1-dev (release)\\n'\n",
        )
        .unwrap();
        assert!(smoke_swift(dir.path(), "6.1").is_err());
    }

    #[test]
    fn release_tags_parse_stable_versions_only() {
        assert_eq!(
            parse_release_tag("swift-6.3.3-RELEASE").as_deref(),
            Some("6.3.3")
        );
        assert_eq!(
            parse_release_tag("swift-6.0-RELEASE").as_deref(),
            Some("6.0")
        );
        assert_eq!(
            parse_release_tag("swift-5.10.1-RELEASE").as_deref(),
            Some("5.10.1")
        );
        // Snapshots, previews, candidates, and branch junk stay out.
        assert_eq!(
            parse_release_tag("swift-6.0-DEVELOPMENT-SNAPSHOT-2024-03-21-a"),
            None
        );
        assert_eq!(
            parse_release_tag("swift-DEVELOPMENT-SNAPSHOT-2026-09-05-a"),
            None
        );
        assert_eq!(parse_release_tag("swift-3.0-PREVIEW-1"), None);
        assert_eq!(parse_release_tag("swift-3.0.1-PREVIEW-3"), None);
        assert_eq!(parse_release_tag("swift-3.0-GM-CANDIDATE"), None);
        assert_eq!(parse_release_tag("swift-4.2-CONVERGENCE"), None);
        assert_eq!(parse_release_tag("swift-6.3.3-RC1"), None);
        assert_eq!(parse_release_tag("swift-6.3.3"), None);
        assert_eq!(parse_release_tag("swift-6-RELEASE"), None);
        assert_eq!(parse_release_tag("swift-6.3.3.1-RELEASE"), None);
        assert_eq!(parse_release_tag("swift-6.x-RELEASE"), None);
        assert_eq!(parse_release_tag("swift--RELEASE"), None);
        assert_eq!(parse_release_tag("type-name-lookup-fail"), None);
        assert_eq!(parse_release_tag(""), None);
    }

    #[test]
    fn releases_filter_prereleases_and_sort_newest_first() {
        let releases = vec![
            release("swift-6.0.3-RELEASE", false),
            release("swift-6.3.3-RELEASE", false),
            release("swift-3.0-PREVIEW-1", true),
            release("swift-6.0-DEVELOPMENT-SNAPSHOT-2024-03-21-a", false),
            release("swift-5.10.1-RELEASE", false),
            release("swift-6.0-RELEASE", false),
        ];
        let versions = parse_swift_versions(&releases);
        let names: Vec<&str> = versions
            .iter()
            .map(|version| version.version.as_str())
            .collect();
        assert_eq!(names, vec!["6.3.3", "6.0.3", "6.0", "5.10.1"]);
        assert!(versions.iter().all(|version| !version.prerelease));
    }

    #[test]
    fn tarball_urls_match_swift_org_layout_quirks() {
        // Lowercase `-release` dir, dotless distro dir, uppercase `-RELEASE`
        // tag dir, dotted distro file slug.
        assert_eq!(
            tarball_url("6.0.3", "24.04", ""),
            "https://download.swift.org/swift-6.0.3-release/ubuntu2404\
             /swift-6.0.3-RELEASE/swift-6.0.3-RELEASE-ubuntu24.04.tar.gz"
        );
        assert_eq!(
            tarball_url("6.2.4", "22.04", ""),
            "https://download.swift.org/swift-6.2.4-release/ubuntu2204\
             /swift-6.2.4-RELEASE/swift-6.2.4-RELEASE-ubuntu22.04.tar.gz"
        );
        // aarch64 appends `-aarch64` to both the distro dir and the file slug.
        assert_eq!(
            tarball_url("6.3.3", "24.04", "-aarch64"),
            "https://download.swift.org/swift-6.3.3-release/ubuntu2404-aarch64\
             /swift-6.3.3-RELEASE/swift-6.3.3-RELEASE-ubuntu24.04-aarch64.tar.gz"
        );
        assert_eq!(
            tarball_url("6.2.4", "22.04", "-aarch64"),
            "https://download.swift.org/swift-6.2.4-release/ubuntu2204-aarch64\
             /swift-6.2.4-RELEASE/swift-6.2.4-RELEASE-ubuntu22.04-aarch64.tar.gz"
        );
    }

    #[test]
    fn os_release_mapping_accepts_only_published_builds() {
        assert_eq!(map_os_release("ubuntu", "22.04"), Some("22.04"));
        assert_eq!(map_os_release("ubuntu", "24.04"), Some("24.04"));
        assert_eq!(map_os_release("ubuntu", "20.04"), None);
        assert_eq!(map_os_release("ubuntu", "25.10"), None);
        assert_eq!(map_os_release("debian", "12"), None);
        assert_eq!(map_os_release("fedora", "42"), None);
        assert_eq!(map_os_release("arch", ""), None);
        assert_eq!(map_os_release("", ""), None);
    }

    #[test]
    fn os_release_fields_parse_quoted_values() {
        let content = "ID=ubuntu\nVERSION_ID=\"24.04\"\n";
        assert_eq!(os_release_field(content, "ID"), "ubuntu");
        assert_eq!(os_release_field(content, "VERSION_ID"), "24.04");
        assert_eq!(os_release_field(content, "MISSING"), "");
    }

    #[test]
    fn fresh_manager_reports_no_installed_versions() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let manager = SwiftManager::with_paths(
            temp.path().join("versions"),
            temp.path().join("swift/all-keys.asc"),
        );
        assert!(manager.list_installed().expect("list").is_empty());
        assert_eq!(manager.current_version(), None);
    }

    #[test]
    fn host_arch_suffix_names_the_platform() {
        let suffix = host_arch_suffix().expect("host arch should be supported");
        match std::env::consts::ARCH {
            "x86_64" => assert_eq!(suffix, ""),
            "aarch64" => assert_eq!(suffix, "-aarch64"),
            arch => panic!("unexpected test host arch: {arch}"),
        }
    }
}
