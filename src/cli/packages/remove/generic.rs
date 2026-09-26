use anyhow::Result;

use crate::cli::{style, ui};

/// Generic dry run: this backend never cleans orphaned dependencies, so no
/// recursion claim is printed.
pub async fn remove_dry_run(packages: &[String]) -> Result<()> {
    crate::core::security::validate_package_names(packages)?;
    let manager = crate::package_managers::get_package_manager()?;
    let installed = manager.list_installed().await?;
    let mut selected = Vec::with_capacity(packages.len());
    for name in packages {
        let package = installed
            .iter()
            .find(|package| package.name == *name)
            .ok_or_else(|| anyhow::anyhow!("Package '{name}' is not installed"))?;
        selected.push(package);
    }

    crate::cli::modern_ui::print_phase_header("🗑️", "Remove Preview", "dry run");
    println!();
    println!(
        "  {} The following packages would be removed:\n",
        style::info("→")
    );

    for package in selected {
        println!(
            "    {} {} {}",
            style::error("✗"),
            style::package(&package.name),
            style::version(&package.version.to_string())
        );
    }

    ui::print_spacer();
    println!("  {} Space that would be freed: unknown", style::info("→"));
    ui::print_dry_run_footer();
    Ok(())
}
