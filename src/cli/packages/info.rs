//! Info/display functionality for packages

use anyhow::{Context, Result};
use std::time::Duration;

use crate::cli::{style, ui};
#[cfg(unix)]
use crate::core::client::SyncDaemonClient;
#[cfg(any(feature = "debian", feature = "debian-pure"))]
use crate::core::env::distro::is_debian_like;
#[cfg(unix)]
use crate::daemon::protocol::WirePackageSource;
#[cfg(any(feature = "debian", feature = "debian-pure"))]
use crate::package_managers::VersionDisplay;
use crate::package_managers::get_package_manager;

#[cfg(feature = "arch")]
use crate::package_managers::search_detailed;

const DAEMON_INFO_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(feature = "arch")]
const AUR_INFO_TIMEOUT: Duration = Duration::from_secs(8);

/// Show package information (Synchronous fast-path)
pub fn info_sync(package: &str) -> Result<bool> {
    // SECURITY: Validate package name
    if let Err(e) = crate::core::security::validate_package_name(package) {
        anyhow::bail!("Invalid package name: {e}");
    }

    #[cfg(any(feature = "debian", feature = "debian-pure"))]
    if is_debian_like() {
        if crate::core::paths::test_mode() {
            return display_debian_fixture_info(package);
        }
        #[cfg(feature = "debian")]
        {
            if let Some(info) = crate::package_managers::apt_get_sync_pkg_info(package)? {
                display_package_info(&info);
                return Ok(true);
            }
            return Ok(false);
        }
        #[cfg(all(not(feature = "debian"), feature = "debian-pure"))]
        {
            return display_debian_fixture_info(package);
        }
    }

    // Try daemon first (ULTRA FAST - <1ms)
    #[cfg(unix)]
    if let Ok(mut client) = SyncDaemonClient::acquire_with_timeout(DAEMON_INFO_TIMEOUT)
        && let Ok(info) = client.info(package)
    {
        display_detailed_info(&info)?;

        // Track usage
        crate::core::usage::track_info();

        return Ok(true);
    }

    let pm = get_package_manager()?;

    if pm.name() == "pacman" {
        #[cfg(feature = "arch")]
        {
            if let Some(info) = crate::package_managers::get_sync_pkg_info(package)
                .with_context(|| format!("Failed to look up {package} in official repositories"))?
            {
                // display_pkg_info already renders the Source row.
                crate::package_managers::display_pkg_info(&info);

                // Track usage
                crate::core::usage::track_info();

                return Ok(true);
            }
        }
    }

    Ok(false)
}

#[cfg(any(feature = "debian", feature = "debian-pure"))]
fn display_debian_fixture_info(package: &str) -> Result<bool> {
    if let Some(pkg) = crate::package_managers::debian_db::get_info_fast(package)? {
        let version = pkg.version.version_string();
        let source = format!("Official repository ({})", style::info("apt"));
        ui::print_package_info(
            &ui::InfoCore {
                name: &pkg.name,
                version: &version,
                source: &source,
                installed: pkg.installed,
                description: &pkg.description,
            },
            &ui::InfoExtras::none(),
        );
        return Ok(true);
    }
    Ok(false)
}

/// Helper to display detailed info from daemon
#[cfg(unix)]
fn display_detailed_info(info: &crate::daemon::protocol::DetailedPackageInfo) -> Result<()> {
    let source_label = if info.source == WirePackageSource::Official {
        format!("Official repository ({})", style::info(&info.repo))
    } else {
        style::warning("AUR (Arch User Repository)")
    };
    #[cfg(not(target_os = "macos"))]
    let installed = crate::package_managers::is_installed_fast(&info.name)
        .context("Failed to query local package installation state")?;
    #[cfg(target_os = "macos")]
    let installed = crate::package_managers::is_installed_fast(&info.name).unwrap_or(false);
    ui::print_package_info(
        &ui::InfoCore {
            name: &info.name,
            version: &info.version,
            source: &source_label,
            installed,
            description: &info.description,
        },
        &ui::InfoExtras {
            url: Some(info.url.as_str()).filter(|url| !url.is_empty()),
            size: Some(info.size),
            download: Some(info.download_size),
            licenses: &info.licenses,
            depends: &info.depends,
            maintainer: None,
            votes: None,
            popularity: None,
            out_of_date: false,
        },
    );
    Ok(())
}

#[cfg(unix)]
fn daemon_info_json(
    info: &crate::daemon::protocol::DetailedPackageInfo,
    installed: bool,
) -> Result<serde_json::Value> {
    let mut value =
        serde_json::to_value(info).context("Failed to serialize daemon package info")?;
    value
        .as_object_mut()
        .context("Daemon package info must serialize as an object")?
        .insert("installed".into(), serde_json::Value::Bool(installed));
    Ok(value)
}

pub async fn info(package: &str) -> Result<()> {
    info_with_json(package, false).await
}

pub async fn info_with_json(package: &str, json: bool) -> Result<()> {
    if let Err(error) = crate::core::security::validate_package_name(package) {
        anyhow::bail!("Invalid package name: {error}");
    }

    if json {
        return info_json(package).await;
    }

    info_fallback(package).await
}

async fn info_json(package: &str) -> Result<()> {
    #[cfg(unix)]
    if let Ok(Ok(info)) = tokio::time::timeout(DAEMON_INFO_TIMEOUT, async {
        let mut client = crate::core::client::DaemonClient::connect().await?;
        client.info(package).await
    })
    .await
    {
        // Installation state belongs to the local package database, not the
        // daemon's warm repository record.
        let installed = get_package_manager()?
            .is_installed(&info.name)
            .await
            .context("Failed to query local package installation state")?;
        let json_str = serde_json::to_string_pretty(&daemon_info_json(&info, installed)?)
            .context("Failed to serialize package info as JSON")?;
        println!("{json_str}");
        return Ok(());
    }

    #[cfg(any(feature = "debian", feature = "debian-pure"))]
    if is_debian_like() {
        #[cfg(feature = "debian")]
        let (name, version, description, installed) = if crate::core::paths::test_mode() {
            let pkg = crate::package_managers::debian_db::get_info_fast(package)?
                .with_context(|| format!("Package '{package}' not found"))?;
            (pkg.name, pkg.version, pkg.description, pkg.installed)
        } else {
            let info = crate::package_managers::apt_get_sync_pkg_info(package)?
                .with_context(|| format!("Package '{package}' not found"))?;
            (info.name, info.version, info.description, info.installed)
        };
        #[cfg(all(not(feature = "debian"), feature = "debian-pure"))]
        let (name, version, description, installed) = {
            let pkg = crate::package_managers::debian_db::get_info_fast(package)?
                .with_context(|| format!("Package '{package}' not found"))?;
            (pkg.name, pkg.version, pkg.description, pkg.installed)
        };
        let json_obj = serde_json::json!({
            "name": name,
            "version": version,
            "description": description,
            "installed": installed,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&json_obj)
                .context("Failed to serialize package info as JSON")?
        );
        return Ok(());
    }

    let pm = get_package_manager()?;
    if pm.name() == "pacman" {
        #[cfg(feature = "arch")]
        if let Some(info) = crate::package_managers::get_sync_pkg_info(package)
            .with_context(|| format!("Failed to look up {package} in official repositories"))?
        {
            let json_obj = serde_json::json!({
                "name": info.name,
                "version": info.version.to_string(),
                "description": info.description,
                "url": info.url,
                "size": info.size,
                "install_size": info.install_size,
                "download_size": info.download_size,
                "repo": info.repo,
                "depends": info.depends,
                "licenses": info.licenses,
                "installed": info.installed,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&json_obj)
                    .context("Failed to serialize package info as JSON")?
            );
            return Ok(());
        }
    }

    if pm.name() != "pacman"
        && let Some(info) = pm.info(package).await?
    {
        println!(
            "{}",
            serde_json::to_string_pretty(&info)
                .context("Failed to serialize package info as JSON")?
        );
        return Ok(());
    }
    anyhow::bail!("Package '{package}' not found")
}

async fn info_fallback(package: &str) -> Result<()> {
    // Try sync path first
    if info_sync(package)? {
        return Ok(());
    }

    #[cfg(any(feature = "debian", feature = "debian-pure"))]
    if is_debian_like() {
        anyhow::bail!("Package '{package}' not found. Try: omg search {package}");
    }

    let pm = get_package_manager()?;
    if pm.name() != "pacman" {
        let info = pm
            .info(package)
            .await?
            .with_context(|| format!("Package '{package}' not found. Try: omg search {package}"))?;
        let version = info.version.to_string();
        let source = format!("Official repository ({})", pm.name());
        ui::print_package_info(
            &ui::InfoCore {
                name: &info.name,
                version: &version,
                source: &source,
                installed: info.installed,
                description: &info.description,
            },
            &ui::InfoExtras::none(),
        );
        return Ok(());
    }

    // Try AUR directly as final fallback (Arch only)
    #[cfg(feature = "arch")]
    {
        let pb = style::spinner("Searching AUR...");
        let details: Vec<crate::package_managers::AurPackageDetail> =
            match tokio::time::timeout(AUR_INFO_TIMEOUT, search_detailed(package)).await {
                Ok(Ok(results)) => results,
                Ok(Err(err)) => {
                    pb.finish_and_clear();
                    return Err(err).context(format!("Failed to look up {package} on the AUR"));
                }
                Err(_) => {
                    pb.finish_and_clear();
                    anyhow::bail!("Timed out looking up {package} on the AUR");
                }
            };
        pb.finish_and_clear();

        let Some(pkg) = details.into_iter().find(|p| p.name == package) else {
            anyhow::bail!("Package '{package}' not found. Try: omg search {package}");
        };

        let description = pkg.description.as_deref().unwrap_or_default();
        let maintainer = pkg.maintainer.as_deref().unwrap_or("orphan");
        let source = style::warning("AUR (Arch User Repository)");
        let installed = crate::package_managers::is_installed_fast(&pkg.name).unwrap_or(false);
        ui::print_package_info(
            &ui::InfoCore {
                name: &pkg.name,
                version: &pkg.version,
                source: &source,
                installed,
                description,
            },
            &ui::InfoExtras {
                url: None,
                size: None,
                download: None,
                licenses: &[],
                depends: &[],
                maintainer: Some(maintainer),
                votes: Some(pkg.num_votes),
                popularity: Some(pkg.popularity),
                out_of_date: pkg.out_of_date.is_some(),
            },
        );
        Ok(())
    }

    #[cfg(not(feature = "arch"))]
    anyhow::bail!("Package '{package}' not found. Try: omg search {package}");
}

/// Display package info (debian only)
#[cfg(feature = "debian")]
fn display_package_info(info: &crate::package_managers::types::PackageInfo) {
    let version = info.version.to_string();
    let source = format!("Official repository ({})", style::info("apt"));
    let size = info.install_size.and_then(|size| u64::try_from(size).ok());
    ui::print_package_info(
        &ui::InfoCore {
            name: &info.name,
            version: &version,
            source: &source,
            installed: info.installed,
            description: &info.description,
        },
        &ui::InfoExtras {
            url: info.url.as_deref(),
            size,
            download: None,
            licenses: &[],
            depends: &info.depends,
            maintainer: None,
            votes: None,
            popularity: None,
            out_of_date: false,
        },
    );
}

#[cfg(test)]
mod tests {
    use super::info_with_json;
    #[cfg(unix)]
    use crate::daemon::protocol::{DetailedPackageInfo, WirePackageSource};

    #[cfg(unix)]
    #[test]
    fn daemon_json_info_reports_local_installation_state() {
        let info = DetailedPackageInfo {
            name: "bash".into(),
            version: "5.3".into(),
            description: "Shell".into(),
            url: String::new(),
            size: 0,
            download_size: 0,
            repo: "core".into(),
            depends: Vec::new(),
            licenses: Vec::new(),
            source: WirePackageSource::Official,
        };
        for installed in [true, false] {
            let value = super::daemon_info_json(&info, installed).expect("daemon JSON info");
            assert_eq!(value["name"], "bash");
            assert_eq!(value["installed"], installed);
        }
    }

    #[tokio::test]
    async fn info_validates_names_before_every_output_path() {
        for json in [false, true] {
            let error = info_with_json("../invalid", json)
                .await
                .expect_err("invalid package names must fail before lookup");
            assert!(error.to_string().contains("Invalid package name"));
        }
    }
}
