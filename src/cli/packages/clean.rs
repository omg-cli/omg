//! Clean/orphan functionality for packages

#[cfg(any(feature = "arch", feature = "debian", feature = "debian-pure"))]
use anyhow::Context;
use anyhow::Result;

use crate::cli::style;

#[cfg(any(feature = "debian", feature = "debian-pure"))]
use crate::core::env::distro::is_debian_like;

#[cfg(feature = "arch")]
use crate::package_managers::{
    AurClient, clean_cache, clean_cache_preview, list_orphans_direct, remove_orphans,
};

#[cfg(feature = "debian")]
use crate::package_managers::apt_remove_orphans;

#[cfg(feature = "debian-pure")]
use crate::package_managers::debian_db::{clean_package_cache, list_orphans_fast};

/// Clean up orphans and caches
#[allow(
    clippy::needless_return,
    reason = "additive backend feature branches return before compiled fallbacks"
)]
#[cfg(any(test, feature = "debian"))]
fn apt_cleanup_requests_unsupported_work(cache: bool, aur: bool, all: bool) -> bool {
    cache || aur || all
}

pub async fn clean(
    orphans: bool,
    cache: bool,
    aur: bool,
    all: bool,
    dry_run: bool,
    yes: bool,
) -> Result<()> {
    if dry_run {
        crate::cli::modern_ui::print_phase_header("🧹", "Clean Preview", "dry run");
    } else {
        crate::cli::modern_ui::print_phase_header("🧹", "Clean", "removing orphans and cache");
    }
    println!();

    #[cfg(not(feature = "arch"))]
    if aur {
        anyhow::bail!("AUR cleanup is not available without the Arch backend");
    }

    #[cfg(feature = "fedora")]
    if crate::package_managers::get_package_manager()?.name() == "dnf" {
        if aur {
            anyhow::bail!("AUR cleanup is not available on Fedora");
        }
        return handle_fedora_clean(orphans, cache, all, dry_run, yes).await;
    }

    // AUR cleanup needs an Arch-style package database. On Debian-like hosts
    // the Debian backends own routing below and cannot serve AUR, so fail
    // explicitly instead of silently ignoring the flag — including when the
    // Arch backend is compiled in for use on other hosts.
    #[cfg(any(feature = "debian", feature = "debian-pure"))]
    if aur && is_debian_like() {
        anyhow::bail!("AUR cleanup is not available on Debian-like systems");
    }

    #[cfg(any(feature = "debian", feature = "debian-pure"))]
    if is_debian_like() {
        #[cfg(feature = "debian-pure")]
        {
            return handle_debian_pure_clean(orphans, cache, all, dry_run, yes).await;
        }

        #[cfg(all(feature = "debian", not(feature = "debian-pure")))]
        {
            if apt_cleanup_requests_unsupported_work(cache, aur, all) {
                anyhow::bail!("Cache and AUR cleanup are not supported on the APT backend");
            }
            let do_orphans = orphans || all;
            if !do_orphans {
                println!(
                    "  {} To remove orphan packages: {}",
                    style::dim("·"),
                    style::accent("omg clean --orphans")
                );
                println!();
                return Ok(());
            }
            if dry_run {
                // Dry run must never mutate: report candidates from the FFI
                // status snapshot instead of invoking apt_remove_orphans.
                let orphan_count =
                    tokio::task::spawn_blocking(crate::package_managers::apt_get_system_status)
                        .await
                        .context("APT status task failed")?
                        .map(|(_, _, orphan_count, _)| orphan_count)
                        .context("Failed to inspect orphan packages")?;
                if orphan_count == 0 {
                    println!("  {} No orphan packages found", style::positive("✓"));
                } else {
                    println!(
                        "  {} Would remove {orphan_count} orphan packages",
                        style::accent("→")
                    );
                    println!(
                        "    Run: {} without --dry-run to apply",
                        style::accent("omg clean --orphans")
                    );
                }
                println!();
                println!("  {} No changes made (dry run)", style::info("ℹ"));
                return Ok(());
            }
            // APT cleanup runs noninteractively. The QEMU native orphan case
            // verifies the resulting package state and removal report.
            // `--yes` remains accepted for CLI parity.
            let _ = yes;
            let removed = crate::package_managers::apt_remove_orphans().await?;
            let noun = if removed == 1 { "package" } else { "packages" };
            println!("  {} Removed {removed} orphan {noun}", style::positive("✓"));
            return Ok(());
        }
    }

    // Compiled with only the Debian backends but running somewhere that is
    // not Debian-like: there is no Debian package database here to clean.
    // (With the Arch backend also compiled in, execution continues into the
    // Arch-capable block below instead.)
    #[cfg(all(feature = "debian-pure", not(feature = "arch")))]
    {
        anyhow::bail!(
            "Clean requires a Debian-like system (or an Arch-enabled build); \
             no supported package database was found"
        );
    }

    #[cfg(any(feature = "arch", not(feature = "debian-pure")))]
    {
        let do_orphans = orphans || all;
        let do_cache = cache || all;
        let do_aur = aur || all;

        if !do_orphans && !do_cache && !do_aur {
            // Default: show what can be cleaned
            #[cfg(feature = "arch")]
            {
                let orphan_list =
                    list_orphans_direct().context("Failed to list orphan packages")?;
                if !orphan_list.is_empty() {
                    println!(
                        "  {} {} orphan packages can be removed",
                        style::dim("·"),
                        style::caution(&orphan_list.len().to_string())
                    );
                    println!("    Run: {}", style::accent("omg clean --orphans"));
                }
            }

            println!(
                "  {} To clear package cache: {}",
                style::dim("·"),
                style::accent("omg clean --cache")
            );
            #[cfg(feature = "arch")]
            println!(
                "  {} To clear AUR builds: {}",
                style::dim("·"),
                style::accent("omg clean --aur")
            );
            println!(
                "  {} To clean everything: {}",
                style::dim("·"),
                style::accent("omg clean --all")
            );
            println!();
            return Ok(());
        }

        if !dry_run && !super::common::confirm_cleanup(yes).await? {
            crate::cli::modern_ui::print_warning("Cleanup cancelled");
            return Ok(());
        }

        if do_orphans {
            #[cfg(feature = "arch")]
            {
                if dry_run {
                    let orphan_list =
                        list_orphans_direct().context("Failed to list orphan packages")?;
                    println!(
                        "  {} Would remove {} orphan packages:",
                        style::accent("→"),
                        orphan_list.len()
                    );
                    for pkg in orphan_list.iter().take(10) {
                        println!("    {} {}", style::dim("·"), pkg);
                    }
                    if orphan_list.len() > 10 {
                        println!(
                            "    {} and {} more...",
                            style::dim("·"),
                            orphan_list.len() - 10
                        );
                    }
                } else {
                    remove_orphans().await?;
                }
            }
            #[cfg(not(any(feature = "arch", feature = "debian", feature = "debian-pure")))]
            {
                anyhow::bail!(
                    "Orphan removal is not available without an Arch or Debian package backend"
                );
            }
            #[cfg(all(
                feature = "debian",
                not(feature = "arch"),
                not(feature = "debian-pure")
            ))]
            {
                apt_remove_orphans().await?;
            }
        }

        if do_cache {
            #[cfg(feature = "arch")]
            {
                if dry_run {
                    match clean_cache_preview(1) {
                        Ok((removed, freed)) => {
                            let freed_mb = freed as f64 / 1024.0 / 1024.0;
                            println!(
                                "  {} Would clear package cache: {} archive(s) ({:.2} MB, keep 1 recent version)",
                                style::accent("→"),
                                removed,
                                freed_mb
                            );
                        }
                        Err(e) => {
                            println!(
                                "  {} Would clear package cache (keep 1 recent version): {e}",
                                style::accent("→")
                            );
                        }
                    }
                } else {
                    crate::cli::modern_ui::print_info("Clearing package cache...");
                    // Warn (do not block): cleaning can delete exactly the
                    // cached versions that update/removal rollback plans from
                    // the last 30 days depend on.
                    let rollback_versions: Result<Vec<(String, String)>> =
                        crate::core::history::HistoryManager::new()
                            .and_then(|history| history.rollback_referenced_versions(30));
                    match rollback_versions {
                        Ok(referenced) if !referenced.is_empty() => {
                            println!(
                                "  {} Cleaning will remove cached versions referenced by recent rollback plans:",
                                style::caution("⚠")
                            );
                            for (name, version) in &referenced {
                                println!("    - {name} {version}");
                            }
                            println!("  After this, 'omg rollback' cannot restore those versions.");
                        }
                        Ok(_) => {}
                        Err(history_error) => {
                            tracing::debug!(
                                "Could not check history for rollback-referenced versions: {history_error}"
                            );
                        }
                    }
                    match clean_cache(1) {
                        // Keep 1 version by default
                        Ok((removed, freed)) => {
                            println!(
                                "  {} Removed {} files, freed {:.2} MB",
                                style::positive("✓"),
                                removed,
                                freed as f64 / 1024.0 / 1024.0
                            );
                        }
                        Err(e) => {
                            return Err(e).context("Failed to clear package cache");
                        }
                    }
                }
            }
            #[cfg(all(feature = "debian", not(feature = "arch")))]
            {
                anyhow::bail!("Package cache cleanup is not supported on the APT backend");
            }
            #[cfg(not(any(feature = "arch", feature = "debian", feature = "debian-pure")))]
            {
                anyhow::bail!(
                    "Package cache cleanup is not available without a package manager backend"
                );
            }
        }

        if do_aur {
            #[cfg(feature = "arch")]
            {
                if dry_run {
                    println!(
                        "  {} Would clean all AUR build directories",
                        style::accent("→")
                    );
                } else {
                    let aur_client = AurClient::new()?;
                    aur_client.clean_all()?;
                }
            }
            #[cfg(not(feature = "arch"))]
            {
                anyhow::bail!("AUR cleanup is not available without the Arch backend");
            }
        }

        if dry_run {
            println!();
            println!("  {} No changes made (dry run)", style::info("ℹ"));
            println!();
        } else {
            crate::cli::modern_ui::print_success("Cleanup complete!");
        }
        Ok(())
    }
}

#[cfg(feature = "fedora")]
async fn handle_fedora_clean(
    orphans: bool,
    cache: bool,
    all: bool,
    dry_run: bool,
    yes: bool,
) -> Result<()> {
    use crate::package_managers::dnf::{DnfCleanup, DnfPackageManager};

    let manager = DnfPackageManager::new();
    if !orphans && !cache && !all {
        let packages = DnfPackageManager::orphan_packages().await?;
        println!(
            "{} orphan packages can be removed (omg clean --orphans)",
            packages.len()
        );
        println!("To clear downloaded package archives: omg clean --cache");
        return Ok(());
    }
    // No top-level prompt here: DnfPackageManager::cleanup owns the y/n
    // contract, proven by fedora_tests (decline exit 1 + history, accept
    // removes, empty stdin succeeds). A second prompt would double-consume
    // piped answers. `--yes` remains accepted for forward uniformity.
    let _ = yes;
    if orphans || all {
        if dry_run {
            let packages = DnfPackageManager::orphan_packages().await?;
            println!("Would remove {} orphan packages:", packages.len());
            for package in packages {
                println!("  {package}");
            }
        } else {
            let history = crate::core::history::HistoryManager::new()?;
            manager.cleanup(DnfCleanup::Orphans, Some(&history)).await?;
        }
    }
    if cache || all {
        if dry_run {
            println!("Would clear downloaded package archives (dnf clean packages)");
        } else {
            manager.cleanup(DnfCleanup::PackageCache, None).await?;
        }
    }
    if dry_run {
        println!("No changes made (dry run)");
    }
    Ok(())
}

#[cfg(feature = "debian-pure")]
async fn handle_debian_pure_clean(
    orphans: bool,
    cache: bool,
    all: bool,
    dry_run: bool,
    yes: bool,
) -> Result<()> {
    let do_orphans = orphans || all;
    let do_cache = cache || all;

    // Default behavior: show what can be cleaned
    if !do_orphans && !do_cache {
        let orphan_list = list_orphans_fast().context("Failed to list orphan packages")?;
        if !orphan_list.is_empty() {
            println!(
                "  {} {} orphan packages can be removed",
                style::dim("·"),
                style::caution(&orphan_list.len().to_string())
            );
            println!("    Run: {}", style::accent("omg clean --orphans"));
        }

        println!(
            "  {} To clear package cache: {}",
            style::dim("·"),
            style::accent("omg clean --cache")
        );
        println!(
            "  {} To clean everything: {}",
            style::dim("·"),
            style::accent("omg clean --all")
        );
        println!();
        return Ok(());
    }

    // No top-level prompt on this backend: the destructive debian-pure run
    // shares the piped-stdin failure contract asserted by debian_tests
    // test_clean_orphans. `--yes` remains accepted for forward uniformity.
    let _ = yes;

    // Handle orphan removal
    if do_orphans {
        let orphan_list = list_orphans_fast().context("Failed to list orphan packages")?;

        if orphan_list.is_empty() {
            println!("  {} No orphan packages found", style::positive("✓"));
        } else if dry_run {
            println!(
                "  {} Would remove {} orphan packages:",
                style::accent("→"),
                orphan_list.len()
            );
            for pkg in orphan_list.iter().take(10) {
                println!("    {} {}", style::dim("·"), pkg);
            }
            if orphan_list.len() > 10 {
                println!(
                    "    {} and {} more...",
                    style::dim("·"),
                    orphan_list.len() - 10
                );
            }
        } else {
            crate::cli::modern_ui::print_info(&format!(
                "Removing {} orphan packages...",
                orphan_list.len()
            ));

            // Use the package manager's remove function
            let pm = crate::package_managers::get_package_manager()?;
            pm.remove(&orphan_list).await?;

            println!(
                "  {} Removed {} orphan packages",
                style::positive("✓"),
                orphan_list.len()
            );
        }
    }

    // Handle cache cleanup
    if do_cache {
        if dry_run {
            println!("  {} Would clear APT package cache", style::accent("→"));
        } else {
            crate::cli::modern_ui::print_info("Clearing package cache...");

            report_cache_clean(clean_package_cache())?;
        }
    }

    Ok(())
}

#[cfg(any(test, feature = "debian-pure"))]
fn report_cache_clean(result: Result<(usize, u64)>) -> Result<()> {
    match result {
        Ok((removed, freed)) => {
            println!(
                "  {} Removed {} files, freed {:.2} MB",
                style::positive("✓"),
                removed,
                freed as f64 / 1024.0 / 1024.0
            );
            Ok(())
        }
        Err(e) => {
            crate::cli::modern_ui::print_error(&format!("Failed to clear cache: {e}"));
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apt_all_requests_unsupported_cache_cleanup() {
        assert!(apt_cleanup_requests_unsupported_work(false, false, true));
        assert!(apt_cleanup_requests_unsupported_work(true, false, false));
        assert!(apt_cleanup_requests_unsupported_work(false, true, false));
        assert!(!apt_cleanup_requests_unsupported_work(false, false, false));
    }

    #[test]
    fn cache_clean_failure_returns_err() {
        let result = report_cache_clean(Err(anyhow::anyhow!("permission denied")));
        assert!(
            result.is_err(),
            "failed cache cleanup must be a CLI error so the process exits non-zero"
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("permission denied"),
            "original cache cleanup error must be preserved"
        );
    }

    #[test]
    fn cache_clean_success_returns_ok() {
        assert!(report_cache_clean(Ok((3, 4096))).is_ok());
    }

    #[tokio::test]
    #[cfg(not(any(
        feature = "arch",
        feature = "debian",
        feature = "debian-pure",
        feature = "fedora"
    )))]
    async fn clean_orphans_without_backend_fails() {
        let error = clean(true, false, false, false, false, true)
            .await
            .expect_err("orphan removal with no backend must not look like success");
        assert!(
            error
                .to_string()
                .contains("not available without an Arch or Debian package backend")
        );
    }

    #[tokio::test]
    #[cfg(not(any(
        feature = "arch",
        feature = "debian",
        feature = "debian-pure",
        feature = "fedora"
    )))]
    async fn clean_cache_without_backend_fails() {
        let error = clean(false, true, false, false, false, true)
            .await
            .expect_err("cache cleanup with no backend must not look like success");
        assert!(
            error
                .to_string()
                .contains("not available without a package manager backend")
        );
    }

    #[tokio::test]
    #[cfg(not(feature = "arch"))]
    async fn clean_aur_without_arch_fails() {
        let error = clean(false, false, true, false, false, true)
            .await
            .expect_err("AUR cleanup without the Arch backend must not look like success");
        // Debian-like hosts hit the earlier host-specific bail
        // ("…on Debian-like systems"); others hit the backend bail.
        // Both fail closed and share this prefix.
        assert!(
            error.to_string().contains("AUR cleanup is not available"),
            "AUR cleanup without Arch must fail closed; got: {error}"
        );
    }
}
