use anyhow::{Context, Result};

use crate::cli::{modern_ui, style};
use crate::package_managers::get_package_manager;

use super::enforce_install_policy;

pub async fn install(packages: &[String]) -> Result<()> {
    crate::core::security::validate_debian_package_names_or_files(packages)?;
    let pm = get_package_manager()?;
    let policy =
        crate::core::security::SecurityPolicy::load_default().map_err(anyhow::Error::from)?;
    let vulnerability_scanner = crate::core::security::vulnerability::VulnerabilityScanner::new();
    let mut install_targets = Vec::with_capacity(packages.len());
    for package in packages {
        if crate::core::security::is_local_debian_package_file(package) {
            policy.check_package(
                package,
                false,
                None,
                crate::core::security::SecurityGrade::Community,
            )?;
            install_targets.push(package.clone());
            continue;
        }
        let (name, requested_version) = package
            .split_once('=')
            .map_or((package.as_str(), None), |(name, version)| {
                (name, Some(version))
            });
        #[cfg(feature = "debian")]
        let selected = if crate::core::paths::test_mode() {
            let info = pm
                .info(name)
                .await?
                .with_context(|| format!("Package not found: {name}"))?;
            (info.name, info.version)
        } else {
            let name = name.to_string();
            let requested = requested_version.map(str::to_string);
            let info = tokio::task::spawn_blocking(move || {
                crate::package_managers::apt::get_sync_pkg_info_for_version(
                    &name,
                    requested.as_deref(),
                )
            })
            .await
            .context("APT version lookup task failed")??
            .with_context(|| format!("No installable APT candidate for: {package}"))?;
            (info.name, info.version)
        };
        #[cfg(not(feature = "debian"))]
        let selected = {
            let info = pm
                .info(name)
                .await?
                .with_context(|| format!("Package not found: {name}"))?;
            (info.name, info.version)
        };
        let (selected_name, selected_version) = selected;
        enforce_install_policy(
            &policy,
            &vulnerability_scanner,
            &selected_name,
            &selected_version,
            false,
            None,
        )
        .await?;
        install_targets.push(
            if crate::core::paths::test_mode() || requested_version.is_some() {
                package.clone()
            } else {
                format!("{selected_name}={selected_version}")
            },
        );
    }

    modern_ui::print_phase_header(
        "📦",
        "Install",
        &format!(
            "{} {}",
            packages.len(),
            if packages.len() == 1 {
                "package"
            } else {
                "packages"
            }
        ),
    );

    let pb = modern_ui::modern_spinner("Resolving", "debian packages");
    modern_ui::finish_clear(&pb);

    pm.install(&install_targets).await?;

    let labels = packages
        .iter()
        .map(|package| crate::core::security::artifact::display_target(package).to_owned())
        .collect::<Vec<_>>();
    modern_ui::print_success_with_packages(
        &format!(
            "Installed {} {}",
            packages.len(),
            if packages.len() == 1 {
                "package"
            } else {
                "packages"
            }
        ),
        &labels,
    );
    crate::core::usage::track_install_result(&labels, true);
    Ok(())
}

pub fn install_dry_run(packages: &[String]) -> Result<()> {
    crate::core::security::validate_debian_package_names_or_files(packages)?;
    if crate::core::paths::test_mode() {
        return install_dry_run_fixture(packages);
    }

    // Preview the same APT transaction that the live backend requests. The
    // index resolver cannot reproduce preferences, backports, or custom pins.
    let output = std::process::Command::new("apt-get")
        .args(["-s", "install", "--"])
        .args(packages)
        .output()
        .context("Failed to simulate APT install")?;
    if !output.status.success() {
        anyhow::bail!(
            "APT install simulation failed: {}",
            style::sanitize_terminal_text(&String::from_utf8_lossy(&output.stderr))
        );
    }

    modern_ui::print_phase_header("📋", "Install Preview", "dry run");
    print!("{}", String::from_utf8_lossy(&output.stdout));
    println!(
        "  {} {} No changes will be made (dry run)",
        style::info("ℹ"),
        style::dim("•")
    );
    Ok(())
}

fn install_dry_run_fixture(packages: &[String]) -> Result<()> {
    use comfy_table::{Table, modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL};

    use crate::package_managers::debian_db;
    use crate::package_managers::debian_db::resolver::DependencyResolver;

    modern_ui::print_phase_header("📋", "Install Preview", "dry run");

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec!["Package", "Version", "Size", "Status"]);

    let mut resolver = DependencyResolver::new()?;
    for pkg in packages {
        resolver.add_package(pkg)?;
    }
    let resolution = resolver.resolve()?;

    let upgrade_set: std::collections::HashSet<&str> = resolution
        .to_upgrade
        .iter()
        .map(|(name, _, _)| name.as_str())
        .collect();

    for pkg_name in packages {
        match debian_db::get_info_fast(pkg_name)? {
            Some(info) => {
                let status = if upgrade_set.contains(pkg_name.as_str()) {
                    format!("{} Upgrade", style::caution("↺"))
                } else if debian_db::is_installed_fast(pkg_name)? {
                    format!("{} Installed", style::informative("•"))
                } else {
                    format!("{} Install", style::positive("✓"))
                };

                table.add_row(vec![
                    style::emphasis(&info.name),
                    style::accent(&info.version.to_string()),
                    "--".to_string(),
                    status,
                ]);
            }
            None => {
                table.add_row(vec![
                    style::emphasis(pkg_name),
                    String::new(),
                    String::new(),
                    format!("{} Not found", style::negative("!")),
                ]);
            }
        }
    }

    println!("{table}");
    println!();
    println!(
        "  {} Total download size: {}",
        style::accent("→"),
        style::emphasis(&format!(
            "{:.2} MB",
            resolution.download_size as f64 / 1024.0 / 1024.0
        ))
    );
    if !resolution.to_install.is_empty() || !resolution.to_upgrade.is_empty() {
        println!(
            "  {} Plan: {} install, {} upgrade",
            style::accent("→"),
            resolution.to_install.len(),
            resolution.to_upgrade.len()
        );
    }
    println!();
    println!(
        "  {} {} No changes will be made (dry run)",
        style::info("ℹ"),
        style::dim("•")
    );
    println!();

    Ok(())
}
