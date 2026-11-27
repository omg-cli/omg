//! Update functionality for packages

use anyhow::Result;

use super::dispatch_backend;

#[cfg(feature = "arch")]
mod arch;

#[cfg(feature = "arch")]
mod omarchy;

#[cfg(feature = "arch")]
#[doc(hidden)]
pub use omarchy::contain_inherited_transport;

pub async fn update_fast() -> Result<()> {
    dispatch_backend! {
        debian: { super::common::update_official_only(false, true, false, false, super::common::UpdateMode::Fast).await },
        arch: { arch::update_fast().await },
        generic: { super::common::update_official_only(false, true, false, false, super::common::UpdateMode::Fast).await },
    }
}

pub async fn update_turbo() -> Result<()> {
    dispatch_backend! {
        debian: { super::common::update_official_only(false, true, false, true, super::common::UpdateMode::Turbo).await },
        arch: { arch::update_turbo().await },
        generic: { super::common::update_official_only(false, true, false, true, super::common::UpdateMode::Turbo).await },
    }
}

#[expect(clippy::fn_params_excessive_bools)] // Maps directly to CLI update flags
pub async fn update(
    check_only: bool,
    yes: bool,
    dry_run: bool,
    no_sync: bool,
    aur_only: bool,
) -> Result<()> {
    #[cfg(feature = "arch")]
    if super::mock_arch_backend()? {
        // Retain Arch orchestration with the isolated mock manager. Its AUR
        // lane is disabled, and development-mode elevation fails closed.
        return arch::update(check_only, yes, dry_run, no_sync, aur_only).await;
    }
    #[cfg(feature = "fedora")]
    if (check_only || dry_run)
        && crate::package_managers::resolve_backend()? == crate::package_managers::Backend::Fedora
    {
        anyhow::ensure!(!aur_only, "--aur-only is supported only on Arch Linux");
        let preview = crate::package_managers::DnfPackageManager::preview_cached_upgrade().await?;
        let detail = if dry_run {
            "Dry run · cached"
        } else {
            "Checking for updates · cached"
        };
        crate::cli::modern_ui::print_phase_header("🔄", "Update", detail);
        super::common::print_dnf_preview(&preview);
        if dry_run {
            crate::cli::ui::print_dry_run_footer();
        } else if preview.has_changes {
            crate::cli::modern_ui::print_info("Run omg update to install updates");
        } else {
            crate::cli::modern_ui::print_up_to_date();
        }
        return Ok(());
    }
    dispatch_backend! {
        debian: {
            if aur_only { anyhow::bail!("--aur-only is supported only on Arch Linux"); }
            super::common::update_official_only(check_only, yes, dry_run, no_sync, super::common::UpdateMode::Standard).await
        },
        arch: { arch::update(check_only, yes, dry_run, no_sync, aur_only).await },
        generic: {
            if aur_only { anyhow::bail!("--aur-only is supported only on Arch Linux"); }
            super::common::update_official_only(check_only, yes, dry_run, no_sync, super::common::UpdateMode::Standard).await
        },
    }
}
