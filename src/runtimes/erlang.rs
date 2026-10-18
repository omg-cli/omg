//! Native Erlang/OTP manager.
//!
//! Prebuilt binaries with publisher-published checksums on both hosts:
//! - Linux (Ubuntu/Debian): Hex's bob builds at
//!   `https://builds.hex.pm/builds/otp/{arch}/ubuntu-{release}/`. The
//!   `builds.txt` rows contain release, source commit, timestamp, and an
//!   optional archive SHA-256. Only rows with archive checksums are installable;
//!   the source commit is not an archive checksum. The
//!   tarballs are `OTP-<version>.tar.gz` in the same directory. The
//!   [asdf-erlang-prebuilt](https://github.com/kiwi-research/asdf-erlang-prebuilt)
//!   installer documents this layout, including the post-extract
//!   `./Install -minimal <dir>` step Linux builds require.
//! - macOS: [erlef/otp_builds](https://github.com/erlef/otp_builds) GitHub
//!   releases. The `{arch}-apple-darwin.csv` index documents
//!   `{ref_name},{ref},{datetime},{sha256},{openssl},{wx}` rows, and the
//!   README's verify flow checks the tarball against the `sha256` column.
//!
//! Verification is fail-closed against the published archive SHA-256 on
//! both platforms, plus a `bin/erl` smoke run that also catches glibc
//! incompatibility on non-Ubuntu distros (same probe the asdf installer
//! uses before falling back to source).

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use super::common::{
    activate_version_with_linked_binary, begin_staged_install, complete_staged_install,
    download_with_progress, extract_tar_gz, is_valid_version_dir, normalize_version,
    parse_sha256_digest, print_already_installed, print_installed, print_using,
    remove_file_best_effort, uninstall_version, validate_download_filename,
};
use crate::core::http::BoundedResponseExt;
use crate::{cli::style, core::http::download_client};

/// Override the Ubuntu release used for hex.pm URLs
/// (asdf parity: `ASDF_ERLANG_UBUNTU_RELEASE`).
const UBUNTU_RELEASE_OVERRIDE_ENV: &str = "OMG_ERLANG_UBUNTU_RELEASE";

/// Hex.pm only publishes these Ubuntu builds; other distros map to the
/// closest compatible one (same mapping asdf-erlang-prebuilt uses).
const UBUNTU_FALLBACK_RELEASE: &str = "24.04";

/// An upstream OTP release with its index checksum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OtpVersion {
    /// Bare version (`27.0`, `24.3.4.10`); the `OTP-` prefix is stripped.
    pub(crate) version: String,
    /// Archive SHA-256 from the publisher index.
    pub(crate) checksum: String,
}

pub(crate) struct ErlangManager {
    versions_dir: PathBuf,
    client: &'static reqwest::Client,
}

/// Host addressing: `(index arch token, tarball arch token)`.
fn host_arch_tokens() -> Result<(&'static str, &'static str)> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok(("amd64", "amd64")),
        ("linux", "aarch64") => Ok(("arm64", "arm64")),
        ("macos", "x86_64") => Ok(("x86_64", "x86_64")),
        ("macos", "aarch64") => Ok(("aarch64", "aarch64")),
        (os, arch) => anyhow::bail!("Unsupported operating system for Erlang/OTP: {os}/{arch}"),
    }
}

/// Map `/etc/os-release` identity to a hex.pm Ubuntu release.
///
/// Ubuntu uses its own `VERSION_ID`; Debian maps to the closest Ubuntu
/// build; anything else (Fedora, Arch, …) takes the latest LTS and relies
/// on the post-install smoke test to reject incompatible builds.
fn map_os_release(distro_id: &str, version_id: &str) -> &'static str {
    match distro_id {
        "ubuntu" => match version_id {
            "20.04" => "20.04",
            "22.04" => "22.04",
            "24.04" => "24.04",
            _ => UBUNTU_FALLBACK_RELEASE,
        },
        "debian" => match version_id.split('.').next().unwrap_or("") {
            "10" => "18.04",
            "11" => "20.04",
            "12" => "22.04",
            _ => UBUNTU_FALLBACK_RELEASE,
        },
        _ => UBUNTU_FALLBACK_RELEASE,
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

/// Detect the hex.pm Ubuntu release for this host.
fn ubuntu_release() -> String {
    if let Ok(pinned) = std::env::var(UBUNTU_RELEASE_OVERRIDE_ENV) {
        let pinned = pinned.trim().to_string();
        if !pinned.is_empty() {
            return pinned;
        }
    }
    let content = fs::read_to_string("/etc/os-release").unwrap_or_default();
    map_os_release(
        &os_release_field(&content, "ID"),
        &os_release_field(&content, "VERSION_ID"),
    )
    .to_string()
}

/// Version index URL for this host.
fn index_url() -> Result<String> {
    let (arch, _) = host_arch_tokens()?;
    match std::env::consts::OS {
        "linux" => Ok(format!(
            "https://builds.hex.pm/builds/otp/{arch}/ubuntu-{}/builds.txt",
            ubuntu_release()
        )),
        "macos" => Ok(format!(
            "https://raw.githubusercontent.com/erlef/otp_builds/refs/heads/main/builds/{arch}-apple-darwin.csv"
        )),
        os => anyhow::bail!("Unsupported operating system for Erlang/OTP: {os}"),
    }
}

/// asdf parity: hex.pm and erlef name tarballs `OTP-28.2`, so a trailing
/// `.0` patch is dropped for URL construction (`28.2.0` → `28.2`).
fn upstream_version(version: &str) -> &str {
    version.strip_suffix(".0").unwrap_or(version)
}

/// Tarball download URL for one resolved version on this host.
fn tarball_url(version: &str) -> Result<String> {
    let (arch, _) = host_arch_tokens()?;
    let upstream = upstream_version(version);
    match std::env::consts::OS {
        "linux" => Ok(format!(
            "https://builds.hex.pm/builds/otp/{arch}/ubuntu-{}/OTP-{upstream}.tar.gz",
            ubuntu_release()
        )),
        "macos" => Ok(format!(
            "https://github.com/erlef/otp_builds/releases/download/OTP-{upstream}/otp-{arch}-apple-darwin.tar.gz"
        )),
        os => anyhow::bail!("Unsupported operating system for Erlang/OTP: {os}"),
    }
}

/// Whether an upstream `OTP-…` name is a stable release (no release
/// candidates, no branch snapshots like `maint-27`).
fn is_stable_release(name: &str) -> bool {
    name.starts_with("OTP-") && !name.to_ascii_lowercase().contains("-rc")
}

/// Parse checksum-bearing hex.pm rows; legacy source-commit-only rows cannot verify archives.
fn parse_builds_txt(text: &str) -> Result<Vec<OtpVersion>> {
    let mut versions = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(name), Some(hash)) = (fields.next(), fields.next()) else {
            anyhow::bail!("Malformed builds.txt row {}: {line:?}", index + 1);
        };
        if !is_stable_release(name) {
            continue;
        }
        let version = name
            .strip_prefix("OTP-")
            .filter(|bare| {
                bare.chars()
                    .next()
                    .is_some_and(|first| first.is_ascii_digit())
            })
            .with_context(|| format!("Malformed OTP release name: {name:?}"))?;
        anyhow::ensure!(
            hash.len() == 40 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "Malformed OTP source commit on row {}",
            index + 1
        );
        fields.next().context("Missing OTP build timestamp")?;
        let Some(archive_hash) = fields.next() else {
            continue;
        };
        let checksum =
            parse_sha256_digest(archive_hash, "builds.hex.pm builds.txt archive checksum")?;
        versions.push(OtpVersion {
            version: version.to_string(),
            checksum,
        });
    }
    Ok(versions)
}

/// Parse an erlef `*-apple-darwin.csv` index
/// (`ref_name,ref,datetime,sha256,openssl,wxwidgets`, header first).
fn parse_erlef_csv(text: &str) -> Result<Vec<OtpVersion>> {
    let mut versions = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("ref_name,") {
            continue;
        }
        let fields: Vec<&str> = line.split(',').collect();
        let name = fields.first().copied().unwrap_or("").trim();
        let hash = fields.get(3).copied().unwrap_or("").trim();
        if name.is_empty() || !is_stable_release(name) {
            continue;
        }
        if hash.is_empty() {
            anyhow::bail!("CSV row {} ({name}) carries no SHA-256 checksum", index + 1);
        }
        let version = name
            .strip_prefix("OTP-")
            .filter(|bare| {
                bare.chars()
                    .next()
                    .is_some_and(|first| first.is_ascii_digit())
            })
            .with_context(|| format!("Malformed OTP release name: {name:?}"))?;
        let checksum = parse_sha256_digest(hash, "erlef otp_builds CSV")?;
        versions.push(OtpVersion {
            version: version.to_string(),
            checksum,
        });
    }
    Ok(versions)
}

/// Numeric dotted-version comparison (`24.3.4.10` vs `27.0`); non-numeric
/// components compare as zero so a malformed row can never panic sorting.
fn version_parts(version: &str) -> Vec<u64> {
    version
        .split('.')
        .map(|part| part.parse().unwrap_or(0))
        .collect()
}

/// Sort newest-first for `list_available` and `latest` resolution.
fn sort_versions_desc(versions: &mut [OtpVersion]) {
    versions.sort_by(|left, right| {
        version_parts(&right.version)
            .cmp(&version_parts(&left.version))
            .then_with(|| left.version.cmp(&right.version))
    });
}

impl ErlangManager {
    pub fn new() -> Self {
        Self {
            versions_dir: super::DATA_DIR.join("versions/erlang"),
            client: download_client(),
        }
    }

    /// Fetch a publisher version index as text.
    async fn fetch_index(&self, url: &str) -> Result<String> {
        self.client
            .get(url)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .with_context(|| format!("Failed to fetch Erlang/OTP index from {url}"))?
            .error_for_status()
            .with_context(|| format!("Erlang/OTP index request failed: {url}"))?
            .bounded_text()
            .await
            .with_context(|| format!("Failed to read Erlang/OTP index from {url}"))
    }

    /// List available upstream releases (newest first).
    pub async fn list_available(&self) -> Result<Vec<OtpVersion>> {
        let url = index_url()?;
        let text = self.fetch_index(&url).await?;
        let mut versions = match std::env::consts::OS {
            "linux" => parse_builds_txt(&text)?,
            "macos" => parse_erlef_csv(&text)?,
            os => anyhow::bail!("Unsupported operating system for Erlang/OTP: {os}"),
        };
        sort_versions_desc(&mut versions);
        Ok(versions)
    }

    /// Resolve `latest` and partial requests (`27`, `27.0`) against the
    /// upstream list. Exact versions pass through so the installed fast path
    /// and the existing not-found UX are preserved.
    pub async fn resolve_alias(&self, alias: &str) -> Result<String> {
        let alias = normalize_version(alias);
        if alias == "latest" {
            let versions = self.list_available().await?;
            versions
                .first()
                .map(|version| version.version.clone())
                .context("No Erlang/OTP versions found upstream")
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

    /// Find the index checksum for one resolved version.
    async fn checksum_for_version(&self, version: &str) -> Result<String> {
        let available = self.list_available().await?;
        available
            .into_iter()
            .find(|candidate| candidate.version == version)
            .map(|candidate| candidate.checksum)
            .with_context(|| {
                format!(
                    "Version {version} not found for Erlang/OTP. Check available versions with: omg list erlang --available"
                )
            })
    }

    /// Install Erlang/OTP from a publisher prebuilt tarball.
    pub async fn install(&self, version: &str) -> Result<()> {
        let version = self.resolve_alias(version).await?;
        let version = self.resolve_requested_version(&version).await?;
        crate::core::security::validate_runtime_version(&version)?;
        // This nonblocking filesystem lease owns final-path initialization and
        // crash recovery. It never blocks an executor thread while awaiting I/O.
        let _install_lease = super::common::try_lock_runtime_install(&self.versions_dir, &version)?;
        let version_dir = self.versions_dir.join(&version);

        // The fast path additionally requires `bin/erl`: a directory that
        // survived extraction but never completed `./Install` is broken and
        // must reinstall rather than activate.
        if is_valid_version_dir(&version_dir) && version_dir.join("bin/erl").is_file() {
            print_already_installed("Erlang/OTP", &version);
            return self.use_version(&version);
        }
        if version_dir.exists() {
            fs::remove_dir_all(&version_dir).with_context(|| {
                format!(
                    "Failed to clear incomplete Erlang/OTP install at {}",
                    version_dir.display()
                )
            })?;
        }

        println!(
            "{} Installing Erlang/OTP {}...\n",
            style::runtime("OMG"),
            style::caution(&version)
        );

        let checksum = self.checksum_for_version(&version).await?;
        let url = tarball_url(&version)?;
        let filename = url
            .rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .with_context(|| format!("Erlang/OTP URL has no filename: {url}"))?;
        validate_download_filename(filename)?;

        fs::create_dir_all(&self.versions_dir)?;

        println!("{} Downloading {filename}...", style::informative("→"));
        let downloads = tempfile::Builder::new()
            .prefix(".download-")
            .tempdir_in(&self.versions_dir)?;
        let download_path = downloads.path().join(filename);
        download_with_progress(self.client, &url, &download_path, &checksum).await?;

        println!("{} Extracting (pure Rust)...", style::informative("→"));
        let staging = begin_staged_install(&self.versions_dir)?;
        extract_tar_gz(&download_path, staging.path(), 1).await?;
        if std::env::consts::OS == "linux" {
            require_staged_install_script(&staging.path().join("Install"))?;
        }
        fs::File::create_new(staging.path().join(super::common::INSTALL_PENDING_MARKER))?
            .sync_all()?;
        complete_staged_install(&staging, &version_dir, &version)?;
        remove_file_best_effort(&download_path, "runtime archive");

        // OTP's `Install` bakes absolute paths, so it runs after publication
        // in the final directory — never in staging, whose path is temporary.
        if std::env::consts::OS == "linux" {
            println!("{} Running OTP Install script...", style::informative("→"));
            if let Err(error) = run_install_script(&version_dir) {
                cleanup_broken_install(&version_dir);
                return Err(error);
            }
        }
        println!("{} Verifying installation...", style::informative("→"));
        if let Err(error) = smoke_erl(&version_dir) {
            cleanup_broken_install(&version_dir);
            return Err(error.context(
                "The prebuilt Erlang/OTP binary does not run here (likely glibc \
                 incompatibility); try OMG_ERLANG_UBUNTU_RELEASE=<release>",
            ));
        }

        make_staged_executable(&version_dir.join("bin/erl"))?;
        fs::remove_file(version_dir.join(super::common::INSTALL_PENDING_MARKER))?;

        print_installed("Erlang/OTP", &version);
        self.use_version(&version)?;

        Ok(())
    }

    /// Switch to a specific version.
    pub fn use_version(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        activate_version_with_linked_binary(&self.versions_dir, &version, Path::new("bin/erl"))?;
        print_using("Erlang/OTP", &version, &self.versions_dir.join("current"));
        Ok(())
    }

    /// Remove an installed version. Refuses the active version.
    pub fn uninstall(&self, version: &str) -> Result<()> {
        let version = normalize_version(version);
        uninstall_version(&self.versions_dir, &version)
    }
}

// Generate common runtime manager methods (list_installed, current_version)
super::common::impl_runtime_common!(ErlangManager);

/// The staged Linux tree must carry OTP's `Install` script; without it the
/// install can never complete, so fail before publishing.
fn require_staged_install_script(script: &Path) -> Result<()> {
    if script.is_file() {
        Ok(())
    } else {
        anyhow::bail!(
            "Installed Erlang/OTP archive but found no `Install` script inside; \
             refusing to publish an uncompletable install"
        )
    }
}

/// Run OTP's `Install -minimal <dir>` in the published directory. The script
/// travels as argv (never interpolated) and runs under `sh` so a missing
/// executable bit on the script itself cannot break the install.
fn run_install_script(version_dir: &Path) -> Result<()> {
    let mut command = std::process::Command::new("sh");
    super::common::harden_untrusted_runtime_command(&mut command, version_dir);
    let status = command
        .arg("Install")
        .arg("-minimal")
        .arg(version_dir)
        .current_dir(version_dir)
        .status()
        .with_context(|| {
            format!(
                "Failed to run OTP Install script in {}",
                version_dir.display()
            )
        })?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!(
            "OTP Install script failed with status {status} in {}",
            version_dir.display()
        )
    }
}

/// Smoke-test the installed runtime: `erl` must start and halt cleanly.
/// This is also the glibc-compatibility probe (same check the asdf
/// installer runs before falling back to a source build).
fn smoke_erl(version_dir: &Path) -> Result<()> {
    let erl = version_dir.join("bin/erl");
    let mut command = std::process::Command::new(&erl);
    super::common::harden_untrusted_runtime_command(&mut command, version_dir);
    let status = command
        .arg("-noshell")
        .arg("-eval")
        .arg("halt().")
        .status()
        .with_context(|| format!("Failed to run smoke test: {}", erl.display()))?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!(
            "Erlang/OTP smoke test failed with status {status}: {}",
            erl.display()
        )
    }
}

/// Remove a published-but-broken install; logs the cleanup failure instead
/// of masking the original install error.
fn cleanup_broken_install(version_dir: &Path) {
    if let Err(error) = fs::remove_dir_all(version_dir) {
        tracing::warn!(
            "Failed to remove broken Erlang/OTP install at {}: {error:#}",
            version_dir.display()
        );
    }
}

/// Ensure the installed `erl` is executable (tarballs may drop modes).
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
    anyhow::bail!("Erlang/OTP installs are unsupported on this platform")
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUILDS_TXT: &str = "OTP-24.3.4 0863bd30aabd035c83158c78046c5ffda16127e1 2024-04-26T03:41:09Z\n\
         OTP-27.0 2915bea4768308995489fecfed2357dcb1574e6b 2026-09-07T00:50:41Z e077943ada95e593911db5ef9cbacdd60158bca25855bfce1f03fceb052738c6\n\
         OTP-29.0-rc3 332eb243babd06d1ff875853044e93d7b0a4b982c2e7abc4d1e4e9b8e133e3652dec5 2026-04-15T07:16:50Z\n\
         \n";

    const ERLEF_CSV: &str = "ref_name,ref,datetime,sha256,openssl,wxwidgets\n\
         master,bf4d114857f84d60766882c079dc461bc1bb3aba,2026-09-07T00:34:43Z,e017896d2f388be7960120445253fee862d71850c364e5ee18f3d574691d5ea7,openssl-3.5.8,wxwidgets-3.2.10\n\
         OTP-28.5,fc91226e454a9b8499791df7e6ceb867907bf41,2026-04-23T13:07:37Z,ded695f1d49c9e251b2afa0205dfdcb8ee16b4432aa1d5ffb38c6ee155bf7f6f,openssl-3.5.6,wxwidgets-3.2.10\n\
         OTP-29.0-rc2,81379e9b17fad721acae663a83901e44452f1,2026-03-18T10:32:59Z,9f030b550cf79d4564a1dc697f015b4d7b463261df1bcc61314b1a28367f8a03,openssl-3.5.5,wxwidgets-3.2.10\n";

    #[test]
    fn builds_txt_requires_archive_sha256_not_source_commit() {
        let versions = parse_builds_txt(BUILDS_TXT).expect("index parses");
        let names: Vec<&str> = versions
            .iter()
            .map(|version| version.version.as_str())
            .collect();
        // Release candidates are excluded; the `OTP-` prefix is stripped.
        assert_eq!(names, vec!["27.0"]);
        assert_eq!(versions[0].checksum.len(), 64);
        assert_eq!(
            versions[0].checksum,
            "e077943ada95e593911db5ef9cbacdd60158bca25855bfce1f03fceb052738c6"
        );
    }

    #[test]
    fn builds_txt_rejects_malformed_rows() {
        assert!(parse_builds_txt("OTP-27.0 not-a-hash 2026-01-01T00:00:00Z\n").is_err());
        assert!(parse_builds_txt("OTP-27.0\n").is_err());
        assert!(parse_builds_txt("garbage-row\n").is_err());
    }

    #[test]
    fn erlef_csv_parses_stable_with_sha256() {
        let versions = parse_erlef_csv(ERLEF_CSV).expect("CSV parses");
        let names: Vec<&str> = versions
            .iter()
            .map(|version| version.version.as_str())
            .collect();
        // Branches (`master`) and release candidates stay out.
        assert_eq!(names, vec!["28.5"]);
        assert_eq!(versions[0].checksum.len(), 64);
    }

    #[test]
    fn erlef_csv_rejects_missing_checksum() {
        let row = "ref_name,ref,datetime,sha256,openssl,wxwidgets\nOTP-27.0,abc,2024-01-01T00:00:00Z,,openssl-3,wx-3\n";
        assert!(parse_erlef_csv(row).is_err());
    }

    #[test]
    fn os_release_mapping_matches_asdf_behavior() {
        assert_eq!(map_os_release("ubuntu", "24.04"), "24.04");
        assert_eq!(map_os_release("ubuntu", "22.04"), "22.04");
        assert_eq!(map_os_release("ubuntu", "25.10"), "24.04");
        assert_eq!(map_os_release("debian", "12"), "22.04");
        assert_eq!(map_os_release("debian", "13"), "24.04");
        assert_eq!(map_os_release("debian", "11"), "20.04");
        assert_eq!(map_os_release("debian", "10"), "18.04");
        assert_eq!(map_os_release("fedora", "42"), "24.04");
        assert_eq!(map_os_release("", ""), "24.04");
    }

    #[test]
    fn os_release_fields_parse_quoted_values() {
        let content = "ID=ubuntu\nVERSION_ID=\"24.04\"\n";
        assert_eq!(os_release_field(content, "ID"), "ubuntu");
        assert_eq!(os_release_field(content, "VERSION_ID"), "24.04");
        assert_eq!(os_release_field(content, "MISSING"), "");
    }

    #[test]
    fn upstream_version_drops_one_trailing_zero() {
        assert_eq!(upstream_version("28.2.0"), "28.2");
        assert_eq!(upstream_version("27.1"), "27.1");
        assert_eq!(upstream_version("27.0"), "27");
        assert_eq!(upstream_version("24.3.4.10"), "24.3.4.10");
    }

    #[test]
    fn versions_sort_newest_first_numerically() {
        let mut versions = vec![
            OtpVersion {
                version: "24.3.4.10".to_string(),
                checksum: String::new(),
            },
            OtpVersion {
                version: "27.0".to_string(),
                checksum: String::new(),
            },
            OtpVersion {
                version: "27.0.1".to_string(),
                checksum: String::new(),
            },
        ];
        sort_versions_desc(&mut versions);
        let names: Vec<&str> = versions
            .iter()
            .map(|version| version.version.as_str())
            .collect();
        assert_eq!(names, vec!["27.0.1", "27.0", "24.3.4.10"]);
    }

    #[test]
    fn host_arch_tokens_name_the_platform() {
        let (index, tarball) = host_arch_tokens().expect("host is supported");
        let expected = match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", "x86_64") => ("amd64", "amd64"),
            ("linux", "aarch64") => ("arm64", "arm64"),
            ("macos", "x86_64") => ("x86_64", "x86_64"),
            ("macos", "aarch64") => ("aarch64", "aarch64"),
            (os, arch) => panic!("unsupported test host: {os}/{arch}"),
        };
        assert_eq!((index, tarball), expected);
        assert_eq!(index, tarball);
        match std::env::consts::ARCH {
            "x86_64" => assert!(index.contains("64") || index.contains("amd")),
            "aarch64" => assert!(index.contains("arm") || index.contains("aarch")),
            arch => panic!("unexpected test host arch: {arch}"),
        }
    }
}
