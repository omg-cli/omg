//! Install functionality for packages

use anyhow::Result;

use super::dispatch_backend;

mod picker;

/// Maximum number of user-selected AUR replacement hops before aborting.
/// Each accepted suggestion re-enters the install flow for one package; the
/// bound turns a pathological suggestion chain into a clean error instead of
/// an unbounded interactive loop.
pub(crate) const MAX_REPLACEMENT_HOPS: u32 = 3;

pub(crate) async fn enforce_install_policy(
    policy: &crate::core::security::SecurityPolicy,
    scanner: &dyn crate::core::security::vulnerability::VulnerabilitySource,
    name: &str,
    version: &crate::package_managers::types::Version,
    is_community_source: bool,
    license: Option<&str>,
) -> Result<()> {
    if crate::core::paths::test_mode() {
        return policy
            .check_source(name, is_community_source, license)
            .map_err(Into::into);
    }

    let grade = match policy
        .assign_grade(scanner, name, version, !is_community_source)
        .await
    {
        Ok(grade) => grade,
        Err(error) if !crate::core::security::policy::explicit_policy_exists() => {
            // The built-in defaults remain usable when a platform has no OSV
            // ecosystem or the evidence service is temporarily unavailable.
            // An explicit policy file is different: its control must fail
            // closed rather than silently degrading.
            tracing::warn!("Vulnerability grading unavailable for {name}: {error}");
            return policy
                .check_source(name, is_community_source, license)
                .map_err(Into::into);
        }
        Err(error) => return Err(error.into()),
    };
    policy
        .check_package(name, is_community_source, license, grade)
        .map_err(Into::into)
}

#[cfg(feature = "arch")]
mod arch;
#[cfg(any(feature = "debian", feature = "debian-pure"))]
mod debian;
mod generic;

/// Install packages from repositories or AUR
///
/// # Arguments
/// * `packages` - Package names to install
/// * `yes` - Skip confirmation prompts
/// * `dry_run` - Show what would be installed without actually installing
/// * `allow_local_file` - Explicit consent for privileged local archive installation
pub async fn install(
    packages: &[String],
    yes: bool,
    dry_run: bool,
    allow_local_file: bool,
) -> Result<()> {
    let packages = if packages.is_empty() {
        use std::io::IsTerminal as _;

        anyhow::ensure!(
            std::io::stdin().is_terminal() && std::io::stdout().is_terminal(),
            "No packages specified; run `omg install` in a terminal to search, or provide package names"
        );
        crate::cli::modern_ui::print_info("Loading package names...");
        let candidates = crate::cli::commands::available_package_names().await?;
        let selected = tokio::task::spawn_blocking(move || picker::choose(candidates)).await??;
        let Some(package) = selected else {
            crate::cli::modern_ui::print_warning("Installation cancelled");
            return Ok(());
        };
        vec![package]
    } else {
        deduplicate_packages(packages)
    };
    install_with_replacement_budget(
        &packages,
        yes,
        dry_run,
        allow_local_file,
        MAX_REPLACEMENT_HOPS,
        MutationConfirmation::Required,
    )
    .await
}

fn deduplicate_packages(packages: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::with_capacity(packages.len());
    packages
        .iter()
        .filter(|package| seen.insert(package.as_str()))
        .cloned()
        .collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MutationConfirmation {
    Required,
    #[cfg(feature = "arch")]
    AlreadyConfirmed,
}

/// Entry point with an explicit interactive-replacement budget.
///
/// Each user-accepted suggestion re-enters the install flow for one package;
/// the budget turns a pathological suggestion chain into a clean error.
async fn install_with_replacement_budget(
    packages: &[String],
    yes: bool,
    dry_run: bool,
    allow_local_file: bool,
    replacement_hops: u32,
    confirmation: MutationConfirmation,
) -> Result<()> {
    if packages.is_empty() {
        anyhow::bail!("No packages specified");
    }

    crate::core::security::ensure_local_archive_consent(packages, allow_local_file)?;
    validate_install_targets(packages)?;

    if dry_run {
        return install_dry_run(packages).await;
    }

    #[cfg(unix)]
    let pinned = crate::core::security::artifact::SnapshotInputs::capture(packages)?;
    #[cfg(unix)]
    let packages = pinned.targets.as_slice();

    if confirmation == MutationConfirmation::Required
        && !super::common::confirm_package_mutation("installation", packages.len(), yes).await?
    {
        crate::cli::modern_ui::print_warning("Installation cancelled");
        return Ok(());
    }

    dispatch_backend! {
        debian: { let _ = (yes, replacement_hops); debian::install(packages).await },
        arch: { arch::install(packages, yes, replacement_hops).await },
        generic: { let _ = (yes, replacement_hops); generic::install(packages).await },
    }
}

fn validate_install_targets(packages: &[String]) -> Result<()> {
    dispatch_backend! {
        debian: {
            crate::core::security::validate_debian_package_names_or_files(packages)?;
            Ok(())
        },
        arch: {
            crate::core::security::validate_package_names_or_files(packages)?;
            Ok(())
        },
        generic: {
            crate::core::security::validate_package_names(packages)?;
            Ok(())
        },
    }
}

async fn install_dry_run(packages: &[String]) -> Result<()> {
    dispatch_backend! {
        debian: { debian::install_dry_run(packages) },
        arch: { arch::install_dry_run(packages).await },
        generic: { generic::install_dry_run(packages) },
    }
}

#[cfg(test)]
mod tests {
    use super::{deduplicate_packages, validate_install_targets};

    #[test]
    fn install_targets_are_validated_before_backend_dispatch() {
        let error = validate_install_targets(&["invalid\nname".to_string()])
            .expect_err("invalid target must fail at the command boundary");
        assert!(error.to_string().contains("Invalid"));
    }

    #[test]
    fn duplicate_install_targets_are_processed_once_in_request_order() {
        let packages = vec!["alpha".to_string(), "beta".to_string(), "alpha".to_string()];
        assert_eq!(deduplicate_packages(&packages), ["alpha", "beta"]);
    }
}
