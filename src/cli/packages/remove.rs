//! Remove functionality for packages

#[cfg(feature = "fedora")]
use anyhow::Context as _;
use anyhow::Result;

use super::dispatch_backend;

#[cfg(feature = "arch")]
mod arch;
#[cfg(feature = "debian")]
mod debian;
mod generic;

/// Remove packages.
///
/// # Arguments
/// * `packages` - Package names to remove (each is validated)
/// * `recursive` - Also remove unneeded dependencies on backends that support it
/// * `yes` - Skip the package-removal confirmation
/// * `dry_run` - Preview what would be removed without touching the system
pub async fn remove(packages: &[String], recursive: bool, yes: bool, dry_run: bool) -> Result<()> {
    if packages.is_empty() {
        anyhow::bail!("No packages specified");
    }

    #[cfg(feature = "fedora")]
    if crate::package_managers::resolve_backend()
        .is_ok_and(|backend| backend == crate::package_managers::Backend::Fedora)
    {
        crate::package_managers::DnfPackageManager::validate_package_selectors(packages)
            .context("Invalid package name")?;
        validate_removal_mode(recursive)?;
        return remove_fedora(packages, yes, dry_run).await;
    }

    for pkg in packages {
        if let Err(e) = crate::core::security::validate_package_name(pkg) {
            anyhow::bail!("Invalid package name '{pkg}': {e}");
        }
    }

    validate_removal_mode(recursive)?;

    if dry_run {
        return remove_dry_run(
            packages,
            #[cfg(feature = "arch")]
            recursive,
        )
        .await;
    }

    let removal_count = removal_confirmation_count(packages).await?;
    if !super::common::confirm_package_mutation("removal", removal_count, yes).await? {
        crate::cli::modern_ui::print_warning("Removal cancelled");
        return Ok(());
    }

    remove_packages(packages, recursive).await
}

#[cfg(feature = "fedora")]
async fn remove_fedora(packages: &[String], yes: bool, dry_run: bool) -> Result<()> {
    use crate::package_managers::DnfPackageManager;

    if dry_run {
        let preview = DnfPackageManager::preview_removal(packages).await?;
        crate::cli::modern_ui::print_phase_header("🗑️", "Remove Preview", "dry run");
        super::common::print_dnf_preview(&preview);
        crate::cli::ui::print_dry_run_footer();
        return Ok(());
    }
    if !crate::core::is_root() {
        return DnfPackageManager::remove_with_elevation(packages, yes).await;
    }
    let Some(plan) = review_fedora_removal(packages, yes).await? else {
        return Ok(());
    };
    let history = crate::core::history::HistoryManager::new()?;
    let manager = DnfPackageManager::new();
    super::common::report_removal(packages, manager.replay_removal(plan, &history)).await
}

#[cfg(feature = "fedora")]
pub(crate) async fn review_fedora_removal(
    packages: &[String],
    yes: bool,
) -> Result<Option<crate::package_managers::dnf::PreparedDnfRemoval>> {
    use crate::package_managers::DnfPackageManager;

    let Some(plan) = DnfPackageManager::prepare_removal(packages)
        .await?
        .filter(|plan| !plan.packages().is_empty())
    else {
        crate::cli::modern_ui::print_info("DNF reported no packages to remove");
        return Ok(None);
    };
    generic::report_preview(plan.packages(), true, false);
    if !super::common::confirm_package_mutation("removal", plan.packages().len(), yes).await? {
        crate::cli::modern_ui::print_warning("Removal cancelled");
        return Ok(None);
    }
    crate::core::security::SecurityPolicy::load_default()?;
    Ok(Some(plan))
}

async fn removal_confirmation_count(packages: &[String]) -> Result<usize> {
    dispatch_backend! {
        debian: { generic::confirmation_count(packages).await },
        arch: { Ok(packages.len()) },
        generic: { generic::confirmation_count(packages).await },
    }
}

// The Arch-only build cannot fail this check, while Debian/generic builds
// reject unsupported recursion. Keep one cross-feature contract at the call site.
#[cfg_attr(feature = "arch", allow(clippy::unnecessary_wraps))]
fn validate_removal_mode(recursive: bool) -> Result<()> {
    #[cfg(feature = "arch")]
    if super::mock_arch_backend()? {
        return Ok(());
    }
    dispatch_backend! {
        debian: {
            anyhow::ensure!(!recursive, "Recursive removal is not supported by the Debian backend");
            Ok(())
        },
        arch: { let _ = recursive; Ok(()) },
        generic: {
            anyhow::ensure!(!recursive, "Recursive removal is not supported by this package backend");
            Ok(())
        },
    }
}

async fn remove_packages(packages: &[String], recursive: bool) -> Result<()> {
    if crate::core::paths::test_mode() {
        let manager = crate::package_managers::get_package_manager()?;
        return super::common::remove_with_manager(packages, manager).await;
    }

    dispatch_backend! {
        debian: {
            let _ = recursive;
            super::common::remove_via_service(packages).await
        },
        arch: {
            let manager = std::sync::Arc::new(
                crate::package_managers::ArchPackageManager::with_recursive_removal(recursive),
            );
            super::common::remove_with_manager(packages, manager).await
        },
        generic: {
            let _ = recursive;
            super::common::remove_via_service(packages).await
        },
    }
}

async fn remove_dry_run(
    packages: &[String],
    #[cfg(feature = "arch")] recursive: bool,
) -> Result<()> {
    #[cfg(feature = "arch")]
    if super::mock_arch_backend()? {
        return arch::remove_dry_run(packages, recursive).await;
    }
    dispatch_backend! {
        debian: { debian::remove_dry_run(packages).await },
        arch: { arch::remove_dry_run(packages, recursive).await },
        generic: { generic::remove_dry_run(packages).await },
    }
}

#[cfg(test)]
mod tests {
    use super::{remove, validate_removal_mode};

    #[tokio::test]
    async fn removal_targets_are_validated_before_backend_dispatch() {
        for recursive in [false, true] {
            let error = remove(&["invalid\nname".to_string()], recursive, true, true)
                .await
                .expect_err("invalid removal target must fail before backend selection");
            assert!(error.to_string().contains("Invalid package name"));
        }
    }

    #[cfg(feature = "arch")]
    #[test]
    fn arch_accepts_explicit_and_recursive_removal_modes() {
        const NAME: &str =
            "cli::packages::remove::tests::arch_accepts_explicit_and_recursive_removal_modes";
        if crate::core::testing::run_isolated_test(NAME) {
            return;
        }
        temp_env::with_vars(
            [("OMG_TEST_MODE", None::<&str>), ("OMG_TEST_DISTRO", None)],
            || {
                assert_eq!(
                    crate::core::env::distro::detect_distro(),
                    crate::core::env::distro::Distro::Arch,
                    "this test requires a native Arch host"
                );
                validate_removal_mode(false).unwrap();
                validate_removal_mode(true).unwrap();
            },
        );
    }

    #[cfg(not(feature = "arch"))]
    #[test]
    fn unsupported_backends_reject_recursive_removal() {
        if let Err(selection_error) = crate::package_managers::resolve_backend() {
            for recursive in [false, true] {
                let error = validate_removal_mode(recursive)
                    .expect_err("a missing live backend must refuse every removal mode");
                assert_eq!(error.to_string(), selection_error.to_string());
            }
            return;
        }
        validate_removal_mode(false).unwrap();
        let error = validate_removal_mode(true).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Recursive removal is not supported")
        );
    }
}
