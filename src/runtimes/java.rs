//! Native Java runtime manager - PURE RUST
//!
//! Downloads JDK from Eclipse Adoptium (Temurin).
//!
//! Features:
//! - Official Eclipse Adoptium builds
//! - LTS version detection
//! - `JAVA_HOME` auto-configuration

use crate::core::http::BoundedResponseExt;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use super::common::{
    activate_version, begin_download, begin_staged_install, complete_staged_install,
    download_with_progress, extract_tar_gz, normalize_version, parse_sha256_digest,
    print_already_installed, print_installed, validate_download_filename,
};
use crate::{cli::style, core::http::download_client};

const ADOPTIUM_API: &str = "https://api.adoptium.net/v3";

#[derive(Debug, Deserialize)]
struct AdoptiumBinary {
    package: AdoptiumPackage,
}

#[derive(Debug, Deserialize)]
struct AdoptiumPackage {
    link: String,
    name: String,
    checksum: String,
}

/// Java version info
#[derive(Debug, Clone)]
pub(crate) struct JavaVersion {
    pub version: String,
    pub lts: bool,
}

pub(crate) struct JavaManager {
    versions_dir: PathBuf,
    client: &'static reqwest::Client,
}

impl JavaManager {
    pub fn new() -> Self {
        Self {
            versions_dir: super::DATA_DIR.join("versions/java"),
            client: download_client(),
        }
    }

    /// List available Java versions from Adoptium
    pub async fn list_available(&self) -> Result<Vec<JavaVersion>> {
        #[derive(Deserialize)]
        struct AvailableReleases {
            available_lts_releases: Vec<u32>,
            available_releases: Vec<u32>,
        }

        let releases: AvailableReleases = self
            .client
            .get(format!("{ADOPTIUM_API}/info/available_releases"))
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .context("Failed to fetch Java versions from Adoptium")?
            .error_for_status()
            .context("Adoptium version-list request failed")?
            .bounded_json()
            .await
            .context("Failed to parse Java version data")?;

        let lts_set: HashSet<u32> = releases.available_lts_releases.into_iter().collect();

        let mut versions: Vec<JavaVersion> = releases
            .available_releases
            .into_iter()
            .map(|v| JavaVersion {
                version: v.to_string(),
                lts: lts_set.contains(&v),
            })
            .collect();

        versions.sort_by_key(|v| std::cmp::Reverse(v.version.parse::<u32>().unwrap_or(0)));

        Ok(versions)
    }

    /// Install Java - PURE RUST, NO SUBPROCESS
    ///
    /// Only Adoptium feature-number requests are accepted; anything else
    /// fails before any network request.
    pub async fn install(&self, version: &str) -> Result<()> {
        let version = java_feature_number(version)?;
        crate::core::security::validate_runtime_version(&version)?;
        let version_dir = self.versions_dir.join(&version);

        if crate::runtimes::common::is_valid_version_dir(&version_dir) {
            print_already_installed("Java", &version);
            return self.use_version(&version);
        }

        println!(
            "{} Installing Java {} (Adoptium)...\n",
            style::runtime("OMG"),
            style::caution(&version)
        );

        let (os, arch) = java_platform()?;

        println!("{} Querying Adoptium API...", style::informative("→"));

        let binaries: Vec<AdoptiumBinary> = self
            .client
            .get(format!(
                "{ADOPTIUM_API}/assets/latest/{version}/hotspot?\
                 architecture={arch}&image_type=jdk&os={os}&vendor=eclipse"
            ))
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .context("Failed to fetch JDK data from Adoptium")?
            .error_for_status()
            .with_context(|| format!("Adoptium has no JDK {version} for {arch}-{os}"))?
            .bounded_json()
            .await
            .context("Failed to parse JDK data")?;

        let binary = binaries.first().ok_or_else(|| {
            anyhow::anyhow!("No JDK {version} found for {arch}. Try: omg list java --available")
        })?;

        fs::create_dir_all(&self.versions_dir)?;

        let archive_name = validate_download_filename(&binary.package.name)?;
        println!(
            "{} Downloading {}...",
            style::informative("→"),
            archive_name
        );
        let download = begin_download(&self.versions_dir)?;
        let download_path = download.path().join(archive_name);
        let checksum = parse_sha256_digest(&binary.package.checksum, "Adoptium")?;
        download_with_progress(self.client, &binary.package.link, &download_path, &checksum)
            .await?;

        println!("{} Extracting (pure Rust)...", style::informative("→"));
        let staging = begin_staged_install(&self.versions_dir)?;
        extract_tar_gz(&download_path, staging.path(), 1).await?;
        self.publish_install(&staging, &version)?;

        print_installed("Java", &version);
        self.use_version(&version)
    }

    fn publish_install(&self, staging: &tempfile::TempDir, version: &str) -> Result<()> {
        normalize_java_home(staging.path())?;
        super::common::require_regular_file(&staging.path().join("bin/java"))?;
        complete_staged_install(staging, &self.versions_dir.join(version), version)
    }

    /// Switch to a specific version
    pub fn use_version(&self, version: &str) -> Result<()> {
        let version = java_feature_number(version)?;
        let version_dir = self.versions_dir.join(&version);
        activate_version(&self.versions_dir, &version, Path::new("bin/java"))?;

        println!("{} Now using Java {version}", style::positive("✓"));
        println!("  {} {}", style::dim("JAVA_HOME:"), version_dir.display());
        println!(
            "  {} {}",
            style::dim("PATH:"),
            self.versions_dir.join("current/bin").display()
        );

        Ok(())
    }

    /// Remove an installed version. Refuses the active version.
    pub fn uninstall(&self, version: &str) -> Result<()> {
        let version = java_feature_number(version)?;
        super::common::uninstall_version(&self.versions_dir, &version)
    }
}

fn normalize_java_home(staging: &Path) -> Result<()> {
    let home = staging.join("Contents/Home");
    match fs::symlink_metadata(&home) {
        Ok(metadata) => anyhow::ensure!(metadata.is_dir(), "Java bundle home must be a directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("Failed to inspect Java bundle home"),
    }

    let canonical_home = home.canonicalize()?;
    anyhow::ensure!(
        canonical_home.starts_with(staging.canonicalize()?),
        "Java bundle home escapes the staging directory"
    );
    // Flattening moves the symlink base. Links must remain inside Home,
    // even when the original archive's larger bundle would contain them.
    let mut directories = vec![home.clone()];
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                directories.push(entry.path());
            } else if file_type.is_symlink() {
                super::common::validate_relative_symlink_target(
                    entry.path().strip_prefix(&home)?,
                    &fs::read_link(entry.path())?,
                )?;
                anyhow::ensure!(
                    entry.path().canonicalize()?.starts_with(&canonical_home),
                    "Java bundle link escapes the runtime home: {}",
                    entry.path().display()
                );
            }
        }
    }

    for entry in fs::read_dir(&home)? {
        let entry = entry?;
        let destination = staging.join(entry.file_name());
        match fs::symlink_metadata(&destination) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => anyhow::bail!("Java bundle home conflicts with {}", destination.display()),
            Err(error) => return Err(error).context("Failed to inspect normalized Java home"),
        }
        fs::rename(entry.path(), &destination).with_context(|| {
            format!(
                "Failed to normalize Java bundle entry at {}",
                destination.display()
            )
        })?;
    }
    fs::remove_dir(home).context("Failed to remove the empty Java bundle home")?;
    Ok(())
}

/// Resolve a Java request to the Adoptium feature number it names.
///
/// Adoptium publishes JDKs by feature: `21` and `21.0` are the same release,
/// while a full update (`21.0.5`), a non-zero minor (`21.1`), a prerelease,
/// or a malformed request names nothing this manager can install.
///
/// Pure and crate-visible so the hook PATH closure can normalize Java pins
/// with the same rule instead of duplicating it.
pub(crate) fn java_feature_number(requested: &str) -> Result<String> {
    let version = normalize_version(requested);
    let is_feature = |component: &str| {
        !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
    };
    let components: Vec<&str> = version.split('.').collect();
    match components.as_slice() {
        [feature] if is_feature(feature) => Ok(version),
        [feature, "0"] if is_feature(feature) => Ok((*feature).to_owned()),
        _ => Err(anyhow::anyhow!(
            "Invalid Java version {requested:?}: Java installs by feature number (for example 21), not updates such as 21.0.5. Run: omg list java --available"
        )),
    }
}

// Generate common runtime manager methods (list_installed, current_version)
crate::runtimes::common::impl_runtime_common!(JavaManager);

fn java_platform() -> Result<(&'static str, &'static str)> {
    Ok((
        super::common::host_os_tag("Java", "linux", "mac")?,
        super::common::host_arch_tag("Java", "x64", "aarch64")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    async fn stage_java_archive(
        versions_dir: &Path,
        runtime_home: &str,
    ) -> Result<tempfile::TempDir> {
        let archive_dir = tempfile::tempdir()?;
        let archive_path = archive_dir.path().join("jdk.tar.gz");
        let encoder = flate2::write::GzEncoder::new(
            fs::File::create(&archive_path)?,
            flate2::Compression::default(),
        );
        let mut archive = tar::Builder::new(encoder);
        for (relative, content) in [("bin/java", b"java".as_slice()), ("bin/javac", b"javac")] {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            archive.append_data(
                &mut header,
                format!("jdk-21/{runtime_home}{relative}"),
                content,
            )?;
        }
        archive.into_inner()?.finish()?;
        let staging = begin_staged_install(versions_dir)?;
        extract_tar_gz(&archive_path, staging.path(), 1).await?;
        Ok(staging)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn publication_normalizes_mac_bundle_home_before_activation() -> Result<()> {
        let versions = tempfile::tempdir()?;
        let manager = JavaManager {
            versions_dir: versions.path().to_path_buf(),
            client: download_client(),
        };
        let staging = stage_java_archive(versions.path(), "Contents/Home/").await?;

        manager.publish_install(&staging, "21")?;
        manager.use_version("21")?;

        assert_eq!(fs::read(versions.path().join("21/bin/java"))?, b"java");
        assert_eq!(
            fs::read(versions.path().join("current/bin/javac"))?,
            b"javac"
        );
        assert_eq!(
            fs::read_link(versions.path().join("current"))?,
            versions.path().join("21")
        );
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn publication_keeps_linux_home_at_the_runtime_root() -> Result<()> {
        let versions = tempfile::tempdir()?;
        let manager = JavaManager {
            versions_dir: versions.path().to_path_buf(),
            client: download_client(),
        };
        let staging = stage_java_archive(versions.path(), "").await?;

        manager.publish_install(&staging, "21")?;
        manager.use_version("21")?;

        assert_eq!(fs::read(versions.path().join("current/bin/java"))?, b"java");
        Ok(())
    }

    #[test]
    fn publication_refuses_a_home_without_java_before_creating_a_version() -> Result<()> {
        let versions = tempfile::tempdir()?;
        let manager = JavaManager {
            versions_dir: versions.path().to_path_buf(),
            client: download_client(),
        };
        let staging = begin_staged_install(versions.path())?;

        assert!(manager.publish_install(&staging, "21").is_err());
        assert!(!versions.path().join("21").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn publication_refuses_bundle_links_that_would_escape_the_normalized_home() -> Result<()> {
        let versions = tempfile::tempdir()?;
        let manager = JavaManager {
            versions_dir: versions.path().to_path_buf(),
            client: download_client(),
        };
        let staging = begin_staged_install(versions.path())?;
        fs::create_dir_all(staging.path().join("Contents/Home/bin"))?;
        fs::create_dir_all(staging.path().join("Contents/Resources"))?;
        fs::write(staging.path().join("Contents/Home/bin/java"), b"java")?;
        fs::write(staging.path().join("Contents/Resources/config"), b"config")?;
        std::os::unix::fs::symlink(
            "../../Resources/config",
            staging.path().join("Contents/Home/bin/config"),
        )?;

        assert!(manager.publish_install(&staging, "21").is_err());
        assert!(!versions.path().join("21").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn publication_preserves_internal_bundle_links_after_normalizing_the_home() -> Result<()> {
        let versions = tempfile::tempdir()?;
        let manager = JavaManager {
            versions_dir: versions.path().to_path_buf(),
            client: download_client(),
        };
        let staging = begin_staged_install(versions.path())?;
        fs::create_dir_all(staging.path().join("Contents/Home/bin"))?;
        fs::create_dir_all(staging.path().join("Contents/Home/lib/server"))?;
        fs::write(staging.path().join("Contents/Home/bin/java"), b"java")?;
        fs::write(staging.path().join("Contents/Home/lib/server/jvm"), b"jvm")?;
        std::os::unix::fs::symlink("server", staging.path().join("Contents/Home/lib/current"))?;

        manager.publish_install(&staging, "21")?;

        assert_eq!(
            fs::read(versions.path().join("21/lib/current/jvm"))?,
            b"jvm"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn publication_refuses_home_links_that_leave_and_reenter_before_flattening() -> Result<()> {
        let versions = tempfile::tempdir()?;
        let manager = JavaManager {
            versions_dir: versions.path().to_path_buf(),
            client: download_client(),
        };
        let staging = begin_staged_install(versions.path())?;
        fs::create_dir_all(staging.path().join("Contents/Home/bin"))?;
        fs::create_dir_all(staging.path().join("Contents/Home/lib"))?;
        fs::write(staging.path().join("Contents/Home/bin/java"), b"java")?;
        fs::write(staging.path().join("Contents/Home/lib/jvm"), b"jvm")?;
        std::os::unix::fs::symlink(
            "../../Home/lib/jvm",
            staging.path().join("Contents/Home/bin/config"),
        )?;

        assert!(manager.publish_install(&staging, "21").is_err());
        assert!(!versions.path().join("21").exists());
        Ok(())
    }

    #[test]
    fn test_java_manager_new() {
        let mgr = JavaManager::new();
        assert!(mgr.versions_dir.ends_with("java"));
    }

    #[cfg(unix)]
    #[test]
    fn java_manager_normalizes_v_prefixed_versions() {
        let temp = tempfile::tempdir().expect("temp dir");
        let version_dir = temp.path().join("17");
        fs::create_dir_all(version_dir.join("bin")).expect("bin dir");
        fs::write(version_dir.join("bin/java"), b"java").expect("java binary");
        let manager = JavaManager {
            versions_dir: temp.path().to_path_buf(),
            client: download_client(),
        };

        manager.use_version("v17").expect("v prefix must normalize");

        assert_eq!(
            fs::read_link(temp.path().join("current")).expect("current link"),
            version_dir
        );
    }

    #[test]
    fn java_uninstall_uses_the_same_feature_number_as_install() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let version_dir = directory.path().join("21");
        fs::create_dir(&version_dir)?;
        let manager = JavaManager {
            versions_dir: directory.path().to_path_buf(),
            client: download_client(),
        };

        assert!(manager.uninstall("21.0.1").is_err());
        assert!(version_dir.exists());
        manager.uninstall("v21.0")?;
        assert!(!version_dir.exists());
        Ok(())
    }

    #[test]
    fn java_requests_resolve_to_their_adoptium_feature_number() {
        assert_eq!(java_feature_number("21").unwrap(), "21");
        assert_eq!(java_feature_number("v21").unwrap(), "21");
        assert_eq!(java_feature_number("V21").unwrap(), "21");
        assert_eq!(java_feature_number("21.0").unwrap(), "21");
        assert_eq!(java_feature_number("v21.0").unwrap(), "21");
        assert_eq!(java_feature_number("17").unwrap(), "17");
    }

    #[test]
    fn non_feature_java_requests_fail_and_point_to_the_available_list() {
        for request in [
            "21.0.5", "21.0.0", "21.1", "21-ea", "21.0-ea", "", "latest", "21.x", "21.", ".21",
            "2.1.2.1",
        ] {
            let error = java_feature_number(request)
                .err()
                .unwrap_or_else(|| panic!("request {request:?} must fail"));
            let message = error.to_string();
            assert!(
                message.contains("omg list java --available"),
                "error for {request:?} must point to the available list: {message}"
            );
        }
    }

    #[tokio::test]
    async fn install_rejects_non_feature_requests_before_network_access() -> Result<()> {
        let manager = JavaManager::new();
        let error = manager.install("21.0.5").await.unwrap_err();
        assert!(error.to_string().contains("omg list java --available"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn activation_keeps_sibling_executables_in_the_runtime_bin_directory() {
        let temp = tempfile::tempdir().expect("temp dir");
        let version_dir = temp.path().join("21");
        fs::create_dir_all(version_dir.join("bin")).expect("bin dir");
        fs::write(version_dir.join("bin/java"), b"java").expect("java binary");
        fs::write(version_dir.join("bin/javac"), b"javac").expect("javac binary");
        let manager = JavaManager {
            versions_dir: temp.path().to_path_buf(),
            client: download_client(),
        };

        manager
            .use_version("21")
            .expect("feature request must activate");

        assert_eq!(
            fs::read_link(temp.path().join("current")).expect("current link"),
            version_dir
        );
        assert_eq!(
            fs::read(temp.path().join("current/bin/javac")).expect("sibling stays reachable"),
            b"javac".to_vec()
        );
    }

    #[test]
    fn java_platform_is_host_specific() {
        let (os, _arch) = java_platform().expect("host platform should be supported");
        if std::env::consts::OS == "linux" {
            assert_eq!(os, "linux");
        } else {
            assert_ne!(os, "linux");
        }
    }
}
