use std::future::Future;
use std::pin::Pin;

use anyhow::Result as AnyhowResult;

use crate::core::{Package, PackageSource, can_write_pacman_db, privilege};
use crate::package_managers::{
    TransactionKind, get_system_status, invalidate_caches, traits::PackageManager,
    types::VersionDisplay,
};

/// Arch Linux package manager (ALPM) implementation
pub struct ArchPackageManager {
    recursive_removal: bool,
}

/// Run an ALPM transaction on a blocking thread.
/// Shared by install/remove/update and orphan removal; every caller passes
/// `None` for the ALPM handle (see `execute_transaction`).
async fn run_alpm_transaction(packages: Vec<String>, kind: TransactionKind) -> AnyhowResult<()> {
    tokio::task::spawn_blocking(move || {
        crate::package_managers::execute_transaction(packages, kind, None)
    })
    .await??;
    Ok(())
}

impl ArchPackageManager {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            recursive_removal: false,
        }
    }

    #[must_use]
    pub const fn with_recursive_removal(recursive_removal: bool) -> Self {
        Self { recursive_removal }
    }
}

impl Default for ArchPackageManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper to run a privileged operation, either directly or via sudo.
///
/// Root processes run directly; all non-root callers delegate through sudo.
/// Executable file capabilities are intentionally never an authorization path.
pub async fn run_privileged_operation<F, Fut>(
    command: &str,
    packages: &[String],
    command_options: &[&str],
    operation: F,
) -> AnyhowResult<()>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = AnyhowResult<()>>,
{
    if can_write_pacman_db() {
        tracing::debug!("Using direct ALPM access as root");
        operation().await?;
        after_privileged_alpm_write().await?;
        return Ok(());
    }

    // A live parent spinner redraws over sudo's password prompt and over the
    // elevated child's own progress, which looks like a hung duplicate bar.
    {
        let _quiesce = crate::cli::modern_ui::quiesce_terminal();
        tracing::debug!("Elevating privileges for {command}");
        let mut args = vec![command];
        args.extend_from_slice(command_options);
        args.push("--");
        args.extend(packages.iter().map(String::as_str));
        // For package-mutating delegations the PARENT owns the history record (it
        // has richer change metadata and AUR handling); the child must stay silent
        // to avoid double entries. System-upgrade delegations (fullupdate /
        // turboupdate) carry no packages and the child is their only recorder.
        if matches!(command, "install" | "remove" | "sync") {
            args.push(privilege::FLOW_PARENT_RECORDS);
        }
        privilege::run_privileged_child(&args).await?;
    }
    after_privileged_alpm_write().await?;
    Ok(())
}

async fn after_privileged_alpm_write() -> AnyhowResult<()> {
    invalidate_caches()?;
    crate::core::client::refresh_daemon_after_catalog_write().await
}

impl PackageManager for ArchPackageManager {
    fn security_audit(
        &self,
    ) -> Option<
        Pin<
            Box<
                dyn Future<Output = AnyhowResult<crate::core::security::scan::SecurityAuditResult>>
                    + Send
                    + '_,
            >,
        >,
    > {
        Some(Box::pin(async move {
            use anyhow::Context;
            async {
                let mut before = self.security_inventory().await?;
                let advisories = crate::core::security::vulnerability::VulnerabilityScanner::new()
                    .fetch_alsa_issues()
                    .await?;
                let result = super::arch_advisory::audit_result(&before, &advisories)?;
                let mut after = self.security_inventory().await?;
                let identity = |package: &super::types::SecurityPackage| {
                    (
                        package.name.clone(),
                        package.version.clone(),
                        package.architecture.clone(),
                    )
                };
                before.sort_by_key(identity);
                after.sort_by_key(identity);
                anyhow::ensure!(
                    before == after,
                    "Installed packages changed during native security audit"
                );
                Ok(result)
            }
            .await
            .context("Failed to query native security advisories")
        }))
    }

    fn security_inventory(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = AnyhowResult<Vec<crate::package_managers::types::SecurityPackage>>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async {
            tokio::task::spawn_blocking(super::alpm_direct::security_inventory).await?
        })
    }

    fn name(&self) -> &'static str {
        "pacman"
    }

    #[inline]
    fn search(
        &self,
        query: &str,
    ) -> Pin<Box<dyn Future<Output = AnyhowResult<Vec<Package>>> + Send + '_>> {
        let query = query.to_string();
        Box::pin(async move {
            // Offload ALPM search to blocking thread
            tokio::task::spawn_blocking(move || {
                // Direct ALPM search is handled by search_sync in alpm_direct.rs
                let results = crate::package_managers::search_sync(&query)?;
                Ok(results
                    .into_iter()
                    .map(|p| Package {
                        name: p.name,
                        version: p.version,
                        description: p.description,
                        source: PackageSource::Official,
                        installed: p.installed,
                    })
                    .collect())
            })
            .await?
        })
    }

    fn install(
        &self,
        packages: &[String],
    ) -> Pin<Box<dyn Future<Output = AnyhowResult<()>> + Send + '_>> {
        let packages = packages.to_vec();
        Box::pin(async move {
            if packages.is_empty() {
                return Ok(());
            }
            crate::core::security::validate_package_names_or_files(&packages)?;

            run_privileged_operation("install", &packages, &[], || {
                let pkgs = packages.clone();
                let is_local_artifact = pkgs
                    .iter()
                    .any(|package| crate::core::security::is_local_package_file(package));
                let kind = if is_local_artifact {
                    TransactionKind::InstallAurArtifact
                } else {
                    TransactionKind::Install
                };
                async move { run_alpm_transaction(pkgs, kind).await }
            })
            .await
        })
    }

    fn remove(
        &self,
        packages: &[String],
    ) -> Pin<Box<dyn Future<Output = AnyhowResult<()>> + Send + '_>> {
        let packages = packages.to_vec();
        Box::pin(async move {
            if packages.is_empty() {
                return Ok(());
            }
            crate::core::security::validate_package_names(&packages)?;

            let recursive = self.recursive_removal;
            let command_options = if recursive {
                // The parent already confirmed this exact mutation. `--yes`
                // prevents the privileged full-CLI fallback from prompting a
                // second time after `--recursive` bypasses the minimal path.
                &["--recursive", "--yes"][..]
            } else {
                &[][..]
            };
            run_privileged_operation("remove", &packages, command_options, || {
                let pkgs = packages.clone();
                async move {
                    run_alpm_transaction(pkgs, TransactionKind::Remove { recursive }).await
                }
            })
            .await
        })
    }

    fn update(&self) -> Pin<Box<dyn Future<Output = AnyhowResult<()>> + Send + '_>> {
        Box::pin(async move {
            run_privileged_operation("update", &[], &[], || async {
                tracing::info!(
                    "{} Starting full system upgrade...",
                    crate::cli::style::runtime("OMG")
                );
                run_alpm_transaction(Vec::new(), TransactionKind::SystemUpgrade).await
            })
            .await
        })
    }

    fn sync(&self) -> Pin<Box<dyn Future<Output = AnyhowResult<()>> + Send + '_>> {
        Box::pin(async move {
            let sync_start = std::time::Instant::now();
            run_privileged_operation("sync", &[], &[], || async {
                crate::package_managers::sync_databases_parallel().await?;
                Ok(())
            })
            .await?;
            let repo_count = crate::core::pacman_conf::PacmanConfig::parse(
                crate::core::paths::pacman_conf_path(),
            )
            .map_or(0, |config| config.repos.len());
            let sync_elapsed = sync_start.elapsed();
            let detail = if repo_count > 0 {
                format!(
                    "{repo_count} repositories in {:.2}s",
                    sync_elapsed.as_secs_f64()
                )
            } else {
                format!("in {:.2}s", sync_elapsed.as_secs_f64())
            };
            crate::cli::modern_ui::print_finished_step("Synced", &detail);
            Ok(())
        })
    }

    #[inline]
    fn info(
        &self,
        package: &str,
    ) -> Pin<Box<dyn Future<Output = AnyhowResult<Option<Package>>> + Send + '_>> {
        let package = package.to_string();
        Box::pin(async move {
            // SECURITY: Validate package name
            crate::core::security::validate_package_name(&package)?;

            // Try direct ALPM info
            let info = tokio::task::spawn_blocking(move || {
                crate::package_managers::get_package_info(&package)
            })
            .await??;

            if let Some(info) = info {
                return Ok(Some(Package {
                    name: info.name,
                    version: info.version,
                    description: info.description,
                    source: PackageSource::Official,
                    installed: info.installed,
                }));
            }
            Ok(None)
        })
    }

    #[inline]
    fn list_installed(
        &self,
    ) -> Pin<Box<dyn Future<Output = AnyhowResult<Vec<Package>>> + Send + '_>> {
        Box::pin(async move {
            // Direct ALPM list
            // Offload to blocking thread
            tokio::task::spawn_blocking(move || {
                let pkgs = crate::package_managers::list_installed_fast()?;
                Ok(pkgs
                    .into_iter()
                    .map(|p| Package {
                        name: p.name,
                        version: p.version,
                        description: p.description,
                        source: PackageSource::Official,
                        installed: true,
                    })
                    .collect())
            })
            .await?
        })
    }

    fn get_status(
        &self,
        fast: bool,
    ) -> Pin<Box<dyn Future<Output = AnyhowResult<(usize, usize, usize, usize)>> + Send + '_>> {
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                if fast {
                    let (total, explicit, orphans) = super::pacman_db::get_counts_fast()?;
                    let updates = super::pacman_db::check_updates_cached()?.len();
                    return Ok((total, explicit, orphans, updates));
                }
                get_system_status()
            })
            .await?
        })
    }

    #[inline]
    fn list_explicit(
        &self,
    ) -> Pin<Box<dyn Future<Output = AnyhowResult<Vec<String>>> + Send + '_>> {
        Box::pin(async move {
            tokio::task::spawn_blocking(crate::package_managers::list_explicit_fast).await?
        })
    }

    #[inline]
    fn list_updates(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = AnyhowResult<Vec<crate::package_managers::types::UpdateInfo>>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            tokio::task::spawn_blocking(crate::package_managers::get_update_list).await?
        })
    }

    fn is_installed(
        &self,
        package: &str,
    ) -> Pin<Box<dyn Future<Output = AnyhowResult<bool>> + Send + '_>> {
        let package = package.to_string();
        Box::pin(async move {
            // Keep ALPM access off the executor thread like every other method.
            tokio::task::spawn_blocking(move || {
                crate::package_managers::is_installed_fast(&package)
            })
            .await?
        })
    }
}

pub async fn list_orphans() -> AnyhowResult<Vec<String>> {
    crate::package_managers::list_orphans_direct()
}

fn orphan_history_change(
    name: String,
    old_version: Option<String>,
) -> crate::core::history::PackageChange {
    crate::core::history::PackageChange {
        name,
        old_version,
        new_version: None,
        source: "pacman".to_string(),
    }
}

pub async fn remove_orphans() -> AnyhowResult<()> {
    let orphans = list_orphans().await?;
    if orphans.is_empty() {
        tracing::info!(
            "{} No orphan packages to remove.",
            crate::cli::style::positive("✓")
        );
        return Ok(());
    }

    let count = orphans.len();
    tracing::info!(
        "{} Found {count} orphan package(s):",
        crate::cli::style::runtime("OMG")
    );
    for pkg in &orphans {
        tracing::info!("  {} {}", crate::cli::style::dim("→"), pkg);
    }

    let history = crate::core::history::HistoryManager::new()?;
    let history_packages = orphans.clone();
    let changes = tokio::task::spawn_blocking(move || {
        history_packages
            .into_iter()
            .map(|name| {
                let old_version = crate::package_managers::get_package_info(&name)?
                    .filter(|info| info.installed)
                    .map(|info| info.version.version_string());
                Ok(orphan_history_change(name, old_version))
            })
            .collect::<AnyhowResult<Vec<_>>>()
    })
    .await??;

    // Reuse the standard privileged-operation path so non-root users get the
    // same sudo elevation as install/remove instead of a raw ALPM failure.
    let operation_result = run_privileged_operation("remove", &orphans, &[], || {
        let pkgs = orphans.clone();
        async move {
            run_alpm_transaction(
                pkgs,
                TransactionKind::Remove { recursive: false },
            )
            .await
        }
    })
    .await;

    history.finish_operation(
        crate::core::history::TransactionType::Remove,
        changes,
        operation_result,
    )
}

pub async fn list_explicit() -> AnyhowResult<Vec<String>> {
    tokio::task::spawn_blocking(crate::package_managers::list_explicit_fast).await?
}

pub async fn is_installed(package: &str) -> AnyhowResult<bool> {
    let package = package.to_string();
    tokio::task::spawn_blocking(move || crate::package_managers::is_installed_fast(&package))
        .await?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orphan_removals_have_rollback_history_metadata() {
        let change =
            orphan_history_change("unused-library".to_string(), Some("1.2.3-1".to_string()));

        assert_eq!(change.name, "unused-library");
        assert_eq!(change.old_version.as_deref(), Some("1.2.3-1"));
        assert!(change.new_version.is_none());
        assert_eq!(change.source, "pacman");
    }
}
