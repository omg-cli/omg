use anyhow::Result;

use crate::cli::{style, ui};

/// Preview the native solver's complete removal set.
pub async fn remove_dry_run(packages: &[String]) -> Result<()> {
    preview(packages, true).await?;
    Ok(())
}

pub(super) async fn confirmation_count(packages: &[String]) -> Result<usize> {
    let manager = crate::package_managers::get_package_manager()?;
    if matches!(manager.name(), "apt" | "dnf") {
        preview(packages, false).await
    } else {
        Ok(packages.len())
    }
}

pub(super) async fn preview(packages: &[String], dry_run: bool) -> Result<usize> {
    crate::core::security::validate_package_names(packages)?;
    let manager = crate::package_managers::get_package_manager()?;
    let native = matches!(manager.name(), "apt" | "dnf");
    let selected = if native {
        manager.removal_plan(packages).await?
    } else {
        let installed = manager.list_installed().await?;
        packages
            .iter()
            .map(|name| {
                let package = installed
                    .iter()
                    .find(|package| package.name == *name)
                    .ok_or_else(|| anyhow::anyhow!("Package '{name}' is not installed"))?;
                Ok(crate::package_managers::types::RemovalPackage {
                    name: package.name.clone(),
                    version: package.version.to_string(),
                })
            })
            .collect::<Result<Vec<_>>>()?
    };

    crate::cli::modern_ui::print_phase_header(
        "🗑️",
        if native {
            "Remove Preview"
        } else {
            "Requested Removal Targets"
        },
        if dry_run { "dry run" } else { "confirmation" },
    );
    println!();
    println!(
        "  {} {}:\n",
        style::info("→"),
        if native {
            "The following packages would be removed"
        } else {
            "Requested installed packages"
        }
    );

    for package in &selected {
        println!(
            "    {} {} {}",
            style::error("✗"),
            style::package(&package.name),
            style::version(&package.version)
        );
    }

    ui::print_spacer();
    if !native {
        println!(
            "  Only requested installed packages are shown; this backend does not simulate the transaction."
        );
    }
    println!("  {} Space that would be freed: unknown", style::info("→"));
    if dry_run {
        ui::print_dry_run_footer();
    }
    Ok(selected.len())
}
