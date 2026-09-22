//! Update functionality for packages

use anyhow::Result;

use super::dispatch_backend;

#[cfg(feature = "arch")]
mod arch;

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
