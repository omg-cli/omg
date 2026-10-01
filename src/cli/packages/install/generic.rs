use anyhow::{Context, Result};

use crate::cli::{modern_ui, style};
use crate::package_managers::get_package_manager;

use super::enforce_install_policy;

pub async fn install(packages: &[String]) -> Result<()> {
    let pm = get_package_manager()?;
    let policy =
        crate::core::security::SecurityPolicy::load_default().map_err(anyhow::Error::from)?;
    let vulnerability_scanner = crate::core::security::vulnerability::VulnerabilityScanner::new();
    for package in packages {
        let info = pm
            .info(package)
            .await?
            .with_context(|| format!("Package not found: {package}"))?;
        enforce_install_policy(
            &policy,
            &vulnerability_scanner,
            &info.name,
            &info.version,
            false,
            None,
        )
        .await?;
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

    let history = crate::core::history::HistoryManager::new()?;
    if let Some(operation) = pm.transact_with_history(
        crate::core::history::TransactionType::Install,
        packages,
        Some(&history),
    ) {
        operation.await?;
    } else {
        pm.install(packages).await?;
    }

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
        packages,
    );
    crate::core::usage::track_install_result(packages, true);
    Ok(())
}

async fn preview_packages(
    pm: &dyn crate::package_managers::PackageManager,
    packages: &[String],
) -> Result<Vec<crate::core::Package>> {
    crate::core::security::validate_package_names(packages)?;
    let mut preview = Vec::with_capacity(packages.len());
    for package in packages {
        let info = pm
            .info(package)
            .await
            .with_context(|| format!("Failed to query package: {package}"))?
            .with_context(|| format!("Package not found: {package}"))?;
        preview.push(info);
    }
    Ok(preview)
}

pub async fn install_dry_run(packages: &[String]) -> Result<()> {
    use comfy_table::{Table, modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL};

    crate::core::security::validate_package_names(packages)?;
    let pm = get_package_manager()?;
    let preview = preview_packages(pm.as_ref(), packages).await?;

    modern_ui::print_phase_header("📋", "Install Preview", "dry run");

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec!["Package", "Version", "Size", "Status"]);

    for package in preview {
        table.add_row(vec![
            style::emphasis(&package.name),
            style::accent(&package.version.to_string()),
            String::new(),
            format!("{} {}", style::positive("✓"), package.source),
        ]);
    }

    println!("{table}");
    println!();
    println!(
        "  {} {} No changes will be made (dry run)",
        style::info("ℹ"),
        style::dim("•")
    );
    println!();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::preview_packages;
    use crate::core::PackageSource;
    use crate::package_managers::mock::MockPackageManager;

    #[tokio::test]
    async fn preview_uses_catalog_metadata_without_mutation() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let pm = MockPackageManager::new_in("arch", directory.path());
        let packages = preview_packages(&pm, &["git".to_string()]).await?;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "git");
        assert_eq!(packages[0].version.to_string(), "2.43.0");
        assert_eq!(packages[0].description, "Version control");
        assert_eq!(packages[0].source, PackageSource::Official);
        assert!(!packages[0].installed);
        assert_eq!(std::fs::read_dir(directory.path())?.count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn preview_refuses_missing_package() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let pm = MockPackageManager::new_in("arch", directory.path());
        let error = preview_packages(&pm, &["missing-fixture-package".to_string()])
            .await
            .expect_err("unknown package must not become a Pending success");
        assert_eq!(
            error.to_string(),
            "Package not found: missing-fixture-package"
        );
        assert_eq!(std::fs::read_dir(directory.path())?.count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn preview_validates_all_names_before_querying() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        std::fs::write(directory.path().join("mock_state_pacman.json"), b"not json")?;
        let pm = MockPackageManager::new_in("arch", directory.path());
        let error = preview_packages(&pm, &["git".to_string(), "invalid\nname".to_string()])
            .await
            .expect_err("validate the whole request before touching the catalog");
        assert!(error.to_string().contains("Invalid"), "{error:#}");
        assert!(!format!("{error:#}").contains("mock state"));
        Ok(())
    }

    #[tokio::test]
    async fn preview_preserves_request_order_and_duplicates() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let pm = MockPackageManager::new_in("arch", directory.path());
        let packages = preview_packages(
            &pm,
            &[
                "firefox".to_string(),
                "git".to_string(),
                "firefox".to_string(),
            ],
        )
        .await?;
        assert_eq!(
            packages
                .iter()
                .map(|package| package.name.as_str())
                .collect::<Vec<_>>(),
            ["firefox", "git", "firefox"]
        );
        Ok(())
    }

    #[tokio::test]
    async fn preview_late_missing_refuses_partial_success() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let pm = MockPackageManager::new_in("arch", directory.path());
        let error = preview_packages(
            &pm,
            &["git".to_string(), "missing-fixture-package".to_string()],
        )
        .await
        .expect_err("a later miss must fail the entire preview before rendering");
        assert_eq!(
            error.to_string(),
            "Package not found: missing-fixture-package"
        );
        Ok(())
    }

    #[tokio::test]
    async fn preview_preserves_query_failure_chain() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("mock_state_pacman.json");
        std::fs::write(&path, b"not json")?;
        let pm = MockPackageManager::new_in("arch", directory.path());
        let error = preview_packages(&pm, &["git".to_string()])
            .await
            .expect_err("catalog failure must not be changed into missing-package success");
        assert_eq!(error.to_string(), "Failed to query package: git");
        assert!(format!("{error:#}").contains("failed to parse mock state"));
        assert!(
            error
                .chain()
                .any(|cause| cause.downcast_ref::<serde_json::Error>().is_some())
        );
        assert_eq!(std::fs::read(path)?, b"not json");
        Ok(())
    }
}
