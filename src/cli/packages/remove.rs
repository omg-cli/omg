//! Remove functionality for packages

use anyhow::Result;

use super::dispatch_backend;

#[cfg(feature = "arch")]
mod arch;
#[cfg(any(feature = "debian", feature = "debian-pure"))]
mod debian;
#[cfg(all(
    not(feature = "arch"),
    not(any(feature = "debian", feature = "debian-pure"))
))]
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

    for pkg in packages {
        if let Err(e) = crate::core::security::validate_package_name(pkg) {
            anyhow::bail!("Invalid package name '{pkg}': {e}");
        }
    }

    validate_removal_mode(recursive)?;

    if dry_run {
        return remove_dry_run(packages, recursive).await;
    }

    if !super::common::confirm_package_mutation("removal", packages.len(), yes).await? {
        crate::cli::modern_ui::print_warning("Removal cancelled");
        return Ok(());
    }

    remove_packages(packages, recursive).await
}

// The Arch-only build cannot fail this check, while Debian/generic builds
// reject unsupported recursion. Keep one cross-feature contract at the call site.
#[cfg_attr(feature = "arch", allow(clippy::unnecessary_wraps))]
fn validate_removal_mode(recursive: bool) -> Result<()> {
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

#[allow(
    clippy::unnecessary_wraps,
    reason = "backend feature dispatch may select fallible implementations"
)]
#[cfg_attr(
    any(feature = "arch", feature = "debian", feature = "debian-pure"),
    allow(
        clippy::unused_async,
        reason = "the generic backend awaits native package lookup; selected native backends preview synchronously"
    )
)]
#[cfg_attr(
    not(feature = "arch"),
    allow(
        unused_variables,
        reason = "only the Arch dry run states recursion truthfully; other backends never recurse"
    )
)]
async fn remove_dry_run(packages: &[String], recursive: bool) -> Result<()> {
    dispatch_backend! {
        debian: { debian::remove_dry_run(packages); Ok(()) },
        arch: { arch::remove_dry_run(packages, recursive) },
        generic: { generic::remove_dry_run(packages).await },
    }
}

#[cfg(test)]
mod tests {
    use super::validate_removal_mode;

    #[cfg(feature = "arch")]
    #[test]
    fn arch_accepts_explicit_and_recursive_removal_modes() {
        validate_removal_mode(false).unwrap();
        validate_removal_mode(true).unwrap();
    }

    #[cfg(not(feature = "arch"))]
    #[test]
    fn unsupported_backends_reject_recursive_removal() {
        validate_removal_mode(false).unwrap();
        let error = validate_removal_mode(true).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Recursive removal is not supported")
        );
    }
}
