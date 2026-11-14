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
    origin: crate::package_managers::types::SecurityOrigin,
    license: Option<&str>,
) -> Result<()> {
    use crate::core::security::policy::AdvisoryRequirement;
    use crate::core::security::vulnerability::{
        AssessmentUse, PackageAssessment, UnknownCoverage, validate_assessment_inventory,
    };
    use crate::package_managers::VersionDisplay;
    policy.check_source(name, &origin, license)?;
    let packages = [crate::package_managers::types::SecurityPackage {
        origin,
        name: name.to_owned(),
        version: version.version_string(),
        advisory_source: None,
        architecture: None,
        description: String::new(),
        licenses: license.into_iter().map(str::to_owned).collect(),
    }];
    let prepared_arch_admission = policy.advisory_requirement == AdvisoryRequirement::FreshSnapshot
        && crate::package_managers::resolve_backend()? == crate::package_managers::Backend::Arch;
    let assessments = if policy.advisory_requirement == AdvisoryRequirement::Optional
        || prepared_arch_admission
    {
        vec![PackageAssessment::unknown(
            packages[0].clone(),
            UnknownCoverage::NotRequested,
        )]
    } else {
        scanner
            .assess_packages(&packages, AssessmentUse::Admission)
            .await?
    };
    validate_assessment_inventory(&packages, &assessments)?;
    if prepared_arch_admission {
        // Only the final prepared transaction can bind fresh evidence and
        // acknowledge an exact uncovered artifact through the root terminal.
        policy.check_sources_and_findings(&assessments)?;
    } else {
        policy.check_assessments(&assessments)?;
    }
    Ok(())
}

#[cfg(feature = "arch")]
mod arch;
#[cfg(feature = "debian")]
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

    #[cfg(feature = "arch")]
    if super::mock_arch_backend()? {
        return arch::install(packages, yes, replacement_hops).await;
    }

    dispatch_backend! {
        debian: { let _ = (yes, replacement_hops); debian::install(packages).await },
        arch: { arch::install(packages, yes, replacement_hops).await },
        generic: { let _ = (yes, replacement_hops); generic::install(packages).await },
    }
}

fn validate_install_targets(packages: &[String]) -> Result<()> {
    match crate::core::env::distro::detect_distro() {
        crate::core::env::distro::Distro::Debian | crate::core::env::distro::Distro::Ubuntu => {
            crate::core::security::validate_debian_package_names_or_files(packages)?;
        }
        crate::core::env::distro::Distro::Arch => {
            crate::core::security::validate_package_names_or_files(packages)?;
        }
        _ => {
            crate::core::security::validate_package_names(packages)?;
        }
    }
    crate::package_managers::resolve_backend()?;
    Ok(())
}

async fn install_dry_run(packages: &[String]) -> Result<()> {
    #[cfg(feature = "arch")]
    if super::mock_arch_backend()? {
        return arch::install_dry_run(packages).await;
    }

    dispatch_backend! {
        debian: { debian::install_dry_run(packages) },
        arch: { arch::install_dry_run(packages).await },
        generic: { generic::install_dry_run(packages).await },
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
