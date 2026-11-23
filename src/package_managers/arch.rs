use std::future::Future;
use std::pin::Pin;

use anyhow::Result as AnyhowResult;

use crate::core::{Package, PackageSource, can_write_pacman_db, privilege};
use crate::package_managers::{
    TransactionKind, get_system_status, invalidate_caches, traits::PackageManager,
    types::VersionDisplay,
};

#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeOmarchyOperation {
    PruneCache,
    RefreshKeyrings,
    UpgradeRepositories,
    RemoveOrphans,
    InstallTrayMenuDependency,
    InstallOmnibookAudio,
    InstallMediaViewer,
    RemoveLegacyMediaViewers,
    InstallFacetimeHd,
    InstallPiCodingAgent,
    InstallKmscon,
    InstallPodmanAndCrun,
}

impl NativeOmarchyOperation {
    #[must_use]
    pub fn from_argument(value: &str) -> Option<Self> {
        match value {
            "cache-prune" => Some(Self::PruneCache),
            "keyring-refresh" => Some(Self::RefreshKeyrings),
            "repository-upgrade" => Some(Self::UpgradeRepositories),
            "orphan-remove" => Some(Self::RemoveOrphans),
            "migration-xrandr" => Some(Self::InstallTrayMenuDependency),
            "migration-omnibook-audio" => Some(Self::InstallOmnibookAudio),
            "migration-omaview-install" => Some(Self::InstallMediaViewer),
            "migration-omaview-cleanup" => Some(Self::RemoveLegacyMediaViewers),
            "migration-facetimehd" => Some(Self::InstallFacetimeHd),
            "migration-pi-coding-agent" => Some(Self::InstallPiCodingAgent),
            "migration-kmscon" => Some(Self::InstallKmscon),
            "migration-podman-crun" => Some(Self::InstallPodmanAndCrun),
            _ => None,
        }
    }

    #[must_use]
    pub const fn argument(self) -> &'static str {
        match self {
            Self::PruneCache => "cache-prune",
            Self::RefreshKeyrings => "keyring-refresh",
            Self::UpgradeRepositories => "repository-upgrade",
            Self::RemoveOrphans => "orphan-remove",
            Self::InstallTrayMenuDependency => "migration-xrandr",
            Self::InstallOmnibookAudio => "migration-omnibook-audio",
            Self::InstallMediaViewer => "migration-omaview-install",
            Self::RemoveLegacyMediaViewers => "migration-omaview-cleanup",
            Self::InstallFacetimeHd => "migration-facetimehd",
            Self::InstallPiCodingAgent => "migration-pi-coding-agent",
            Self::InstallKmscon => "migration-kmscon",
            Self::InstallPodmanAndCrun => "migration-podman-crun",
        }
    }
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeOmarchyInteraction {
    Attended,
    Unattended,
}

impl NativeOmarchyInteraction {
    #[must_use]
    pub fn from_argument(value: &str) -> Option<Self> {
        match value {
            "attended" => Some(Self::Attended),
            "unattended" => Some(Self::Unattended),
            _ => None,
        }
    }

    #[must_use]
    pub const fn argument(self) -> &'static str {
        match self {
            Self::Attended => "attended",
            Self::Unattended => "unattended",
        }
    }
}

/// Execute one fixed, already elevated Omarchy package operation.
///
/// # Errors
/// Refuses unprivileged calls, unsupported trust bootstrap and failed native operations.
#[doc(hidden)]
pub fn execute_native_omarchy_operation(
    operation: NativeOmarchyOperation,
    interaction: NativeOmarchyInteraction,
) -> AnyhowResult<()> {
    use crate::core::history::{HistoryManager, PackageChange, TransactionType};
    use anyhow::Context;
    anyhow::ensure!(
        crate::core::is_root(),
        "Native Omarchy package operations require elevation"
    );
    crate::core::privilege::set_yes_flag(interaction == NativeOmarchyInteraction::Unattended);
    let targets = match operation {
        NativeOmarchyOperation::PruneCache => {
            let (files, bytes) = super::alpm_ops::clean_cache(2)?;
            println!(
                "Pruned {files} cache files ({bytes} bytes), retaining two versions per directory and architecture"
            );
            return Ok(());
        }
        NativeOmarchyOperation::RefreshKeyrings => {
            const MAX_KEYRING_LIST_BYTES: usize = 64 * 1024;
            let mut names = vec!["archlinux-keyring".to_owned(), "omarchy-keyring".to_owned()];
            #[cfg(target_arch = "aarch64")]
            if super::is_installed_fast("archlinuxarm-keyring")? {
                names.push("archlinuxarm-keyring".to_owned());
            }
            let path = std::path::Path::new("/usr/share/omarchy-platform/keyrings");
            use std::io::Read;
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            match std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .open(path)
            {
                Ok(file) => {
                    let metadata = file.metadata()?;
                    anyhow::ensure!(
                        metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
                        "Platform keyring list must be a root-controlled regular file"
                    );
                    let mut contents = String::new();
                    file.take(MAX_KEYRING_LIST_BYTES as u64 + 1)
                        .read_to_string(&mut contents)?;
                    anyhow::ensure!(
                        contents.len() <= MAX_KEYRING_LIST_BYTES,
                        "Platform keyring list exceeds its limit"
                    );
                    for line in contents.lines() {
                        let name = line.trim();
                        if name.is_empty() || name.starts_with('#') {
                            continue;
                        }
                        if !name.ends_with("-keyring")
                            || crate::core::security::validate_package_name(name).is_err()
                        {
                            tracing::warn!("Ignoring invalid platform keyring package name");
                            continue;
                        }
                        if !names.iter().any(|existing| existing == name)
                            && super::is_installed_fast(name)?
                        {
                            names.push(name.to_owned());
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("Cannot read platform keyring packages"),
            }
            names
        }
        NativeOmarchyOperation::UpgradeRepositories => Vec::new(),
        NativeOmarchyOperation::RemoveOrphans => super::list_orphans_direct()?,
        NativeOmarchyOperation::InstallTrayMenuDependency
        | NativeOmarchyOperation::InstallOmnibookAudio
        | NativeOmarchyOperation::InstallMediaViewer
        | NativeOmarchyOperation::RemoveLegacyMediaViewers
        | NativeOmarchyOperation::InstallFacetimeHd
        | NativeOmarchyOperation::InstallPiCodingAgent
        | NativeOmarchyOperation::InstallKmscon
        | NativeOmarchyOperation::InstallPodmanAndCrun => {
            resolve_install_targets(operation, super::is_installed_fast)?
        }
    };
    if operation == NativeOmarchyOperation::RefreshKeyrings {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(super::sync_databases_parallel())?;
    }
    if operation != NativeOmarchyOperation::UpgradeRepositories && targets.is_empty() {
        return Ok(());
    }
    let removing = matches!(
        operation,
        NativeOmarchyOperation::RemoveOrphans | NativeOmarchyOperation::RemoveLegacyMediaViewers
    );
    let (kind, changes) = if operation == NativeOmarchyOperation::UpgradeRepositories {
        (
            TransactionType::Update,
            super::get_update_list()?
                .into_iter()
                .map(|item| PackageChange {
                    name: item.name,
                    old_version: Some(item.old_version),
                    new_version: Some(item.new_version),
                    source: item.repo,
                })
                .collect(),
        )
    } else {
        let mut changes = Vec::new();
        for name in &targets {
            let previous = super::get_package_info(name)?;
            let next = if removing {
                None
            } else {
                Some(super::alpm_direct::with_handle(|handle| {
                    let (database, package) =
                        super::alpm_ops::omarchy_install_candidate(handle, name)?;
                    Ok((package.version().to_string(), database.name().to_owned()))
                })?)
            };
            changes.push(PackageChange {
                name: name.clone(),
                old_version: previous
                    .as_ref()
                    .filter(|item| item.installed)
                    .map(|item| item.version.to_string()),
                new_version: next.as_ref().map(|(version, _)| version.clone()),
                source: next.map_or_else(|| "pacman".to_owned(), |(_, repository)| repository),
            });
        }
        (
            if removing {
                TransactionType::Remove
            } else {
                TransactionType::Install
            },
            changes,
        )
    };
    let history = HistoryManager::new()?;
    let result = super::alpm_ops::execute_omarchy_transaction(operation, targets);
    history.finish_operation(kind, changes, result)?;
    invalidate_caches()?;
    println!("Native Omarchy {} completed", operation.argument());
    Ok(())
}

fn missing_package_target(
    name: &str,
    is_installed: &mut impl FnMut(&str) -> AnyhowResult<bool>,
) -> AnyhowResult<Vec<String>> {
    Ok(if is_installed(name)? {
        Vec::new()
    } else {
        vec![name.to_owned()]
    })
}

fn resolve_install_targets(
    operation: NativeOmarchyOperation,
    mut is_installed: impl FnMut(&str) -> AnyhowResult<bool>,
) -> AnyhowResult<Vec<String>> {
    match operation {
        NativeOmarchyOperation::InstallTrayMenuDependency => {
            missing_package_target("xorg-xrandr", &mut is_installed)
        }
        NativeOmarchyOperation::InstallOmnibookAudio => {
            missing_package_target("hp-omnibook-3-audio", &mut is_installed)
        }
        NativeOmarchyOperation::InstallMediaViewer => {
            missing_package_target("omaview", &mut is_installed)
        }
        NativeOmarchyOperation::RemoveLegacyMediaViewers => {
            anyhow::ensure!(
                is_installed("omaview")?,
                "Omaview must be installed before removing its legacy packages"
            );
            let mut names = Vec::new();
            for name in ["imv", "mpv-mpris"] {
                if is_installed(name)? {
                    names.push(name.to_owned());
                }
            }
            Ok(names)
        }
        NativeOmarchyOperation::InstallFacetimeHd => {
            let mut names = Vec::new();
            if !is_installed("facetimehd-dkms")?
                && !is_installed("bcwc-pcie")?
                && !is_installed("bcwc-pcie-dkms")?
            {
                names.push("facetimehd-dkms".to_owned());
            }
            if !is_installed("facetimehd-firmware")?
                && !is_installed("bcwc-pcie-firmware")?
                && !is_installed("facetimehd-firmware-fetcher")?
            {
                names.push("facetimehd-firmware-fetcher".to_owned());
            }
            Ok(names)
        }
        NativeOmarchyOperation::InstallPiCodingAgent => {
            missing_package_target("pi-coding-agent", &mut is_installed)
        }
        NativeOmarchyOperation::InstallKmscon => {
            missing_package_target("kmscon", &mut is_installed)
        }
        NativeOmarchyOperation::InstallPodmanAndCrun => {
            let mut names = Vec::new();
            for name in ["podman", "crun"] {
                if !is_installed(name)? {
                    names.push(name.to_owned());
                }
            }
            Ok(names)
        }
        NativeOmarchyOperation::PruneCache
        | NativeOmarchyOperation::RefreshKeyrings
        | NativeOmarchyOperation::UpgradeRepositories
        | NativeOmarchyOperation::RemoveOrphans => Ok(Vec::new()),
    }
}

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

pub(crate) async fn install_request(
    request: super::arch_install::InstallRequest,
) -> AnyhowResult<()> {
    let descriptor = request.seal()?;
    let handoff = vec![descriptor.handoff()];
    run_privileged_operation(
        super::arch_install::ELEVATED_INSTALL,
        &handoff,
        &[],
        || async move {
            tokio::task::spawn_blocking(move || super::alpm_ops::execute_install_request(&request))
                .await?
        },
    )
    .await
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
        return finish_native_write(operation()).await;
    }

    // A live parent spinner redraws over sudo's password prompt and over the
    // elevated child's own progress, which looks like a hung duplicate bar.
    let operation = async {
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
        if matches!(command, "install" | "install-plan" | "remove" | "sync") {
            args.push(privilege::FLOW_PARENT_RECORDS);
        }
        privilege::run_privileged_child(&args).await
    };
    finish_native_write(operation).await
}

pub(crate) async fn finish_native_write(
    operation: impl Future<Output = AnyhowResult<()>>,
) -> AnyhowResult<()> {
    finish_alpm_write(operation, after_privileged_alpm_write()).await
}

async fn finish_alpm_write(
    operation: impl Future<Output = AnyhowResult<()>>,
    completion: impl Future<Output = AnyhowResult<()>>,
) -> AnyhowResult<()> {
    let operation = operation.await;
    let completion = completion.await;
    combine_write_results(operation, completion)
}

fn combine_write_results(
    operation: AnyhowResult<()>,
    completion: AnyhowResult<()>,
) -> AnyhowResult<()> {
    match (operation, completion) {
        (Ok(()), completion) => completion,
        (Err(operation), Ok(())) => Err(operation),
        (Err(operation), Err(completion)) => {
            Err(operation.context(format!("Catalog completion also failed: {completion:#}")))
        }
    }
}

async fn after_privileged_alpm_write() -> AnyhowResult<()> {
    let invalidation = invalidate_caches();
    let refresh = crate::core::client::refresh_daemon_after_catalog_write().await;
    combine_write_results(invalidation, refresh)
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
                if before.is_empty() {
                    anyhow::ensure!(
                        self.security_inventory().await?.is_empty(),
                        "Installed packages changed during native security audit"
                    );
                    return Ok(
                        crate::core::security::scan::SecurityAuditResult::from_assessments(
                            Vec::new(),
                        ),
                    );
                }
                let operation = crate::core::security::vulnerability::VulnerabilityScanner::new()
                    .assess_arch_operation(
                        &before,
                        crate::core::security::vulnerability::AssessmentUse::Admission,
                    )
                    .await?;
                let result = crate::core::security::scan::SecurityAuditResult::from_assessments(
                    operation.assessments().to_vec(),
                );
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
                operation.validate_now()?;
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

            use super::arch_install::{InstallIntent, InstallItem, InstallRequest, InstallTarget};
            let pinned = crate::core::security::artifact::SnapshotInputs::capture(&packages)?;
            let items = pinned
                .targets
                .iter()
                .map(|package| InstallItem {
                    target: if crate::core::security::artifact::is_handoff(package) {
                        InstallTarget::Archive(package.clone())
                    } else {
                        InstallTarget::Named(package.clone())
                    },
                    intent: InstallIntent::Requested,
                })
                .collect();
            install_request(InstallRequest::new(items)?).await
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
pub(super) mod tests {
    use super::*;

    pub(crate) fn native_audit_verifies_existing_advisory_fixture(
        root: &std::path::Path,
        database: &std::path::Path,
        unavailable: bool,
    ) -> &'static str {
        use crate::core::security::scan::{AuditCoverage, FindingApplicability};
        use crate::core::security::vulnerability::{UnknownCoverage, VulnerabilityError};
        assert!(
            crate::core::is_root()
                && std::env::var("OMG_ARCH_INSTALL_FIXTURE").as_deref() == Ok("isolated-container"),
            "native audit requires the existing isolated HTTPS consent fixture"
        );
        let descriptor = database.join("local/glibc-1-1/desc");
        let original = std::fs::read(&descriptor).expect("real installed fixture metadata");
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                crate::core::paths::reset_test_overrides();
                crate::package_managers::alpm_direct::clear_alpm_cache();
            }
        }
        let _restore = Restore;
        crate::core::paths::set_test_overrides(Some(root.to_owned()), Some(database.to_owned()));
        crate::package_managers::alpm_direct::clear_alpm_cache();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("native audit fixture runtime");
        let status = runtime.block_on(async {
            let manager = ArchPackageManager::new();
            let before = manager
                .security_inventory()
                .await
                .expect("nonempty real installed inventory");
            assert_eq!(before.len(), 1);
            assert_eq!(before[0].name, "glibc");
            assert_eq!(before[0].version, "1-1");
            let result = manager.security_audit().expect("native audit owner").await;
            let status = if unavailable {
                let error = result.expect_err("unavailable evidence cannot become an empty audit");
                assert!(
                    format!("{error:#}").contains("Failed to query native security advisories")
                );
                assert!(matches!(
                    error.downcast_ref::<VulnerabilityError>(),
                    Some(VulnerabilityError::Unavailable { reason })
                        if reason == "Arch snapshot returned an unexpected URL or status"
                ));
                "refused-unavailable"
            } else {
                let result = result.expect("fixed source snapshot must preserve actual findings");
                result.validate().expect("coherent native audit report");
                assert_eq!(result.total_vulnerabilities, 1);
                assert_eq!(result.high_severity, 1);
                assert_eq!(result.vulnerabilities.len(), 1);
                assert_eq!(result.vulnerabilities[0].0, "glibc");
                let findings = &result.vulnerabilities[0].1;
                assert_eq!(findings.len(), 1);
                assert_eq!(findings[0].id, "AVG-OMG-QEMU-616");
                assert_eq!(findings[0].applicability, FindingApplicability::Possible);
                assert!(findings[0].score.is_none());
                let native = findings[0]
                    .native_advisory
                    .as_ref()
                    .expect("native finding retains publisher details");
                assert_eq!(native.published_severity, "Critical");
                assert!(native.references.iter().any(|reference| {
                    reference.id == "CVE-OMG-QEMU-616"
                        && reference.url == "https://security.archlinux.org/CVE-OMG-QEMU-616"
                }));
                assert!(matches!(
                    result.coverage,
                    AuditCoverage::Reported { assessed, unassessed, sources }
                        if assessed.is_empty()
                            && unassessed.len() == 1
                            && unassessed[0].package.name == "glibc"
                            && unassessed[0].reason == UnknownCoverage::OriginUnestablished
                            && sources.len() == 1
                ));
                "reported-findings"
            };
            let after = manager
                .security_inventory()
                .await
                .expect("inventory after read-only native audit");
            assert_eq!(before, after, "audit must not mutate installed inventory");
            status
        });
        assert_eq!(
            std::fs::read(descriptor).expect("installed metadata after native audit"),
            original,
            "native audit must not change durable package metadata"
        );
        status
    }

    #[cfg(debug_assertions)]
    #[test]
    fn empty_native_audit_reports_exact_scope_and_preserves_inventory_failures() -> AnyhowResult<()>
    {
        const NAME: &str = "package_managers::arch::tests::empty_native_audit_reports_exact_scope_and_preserves_inventory_failures";
        if crate::core::testing::run_isolated_test(NAME)
            || crate::config::Settings::rerun_test_unprivileged(NAME)
        {
            return Ok(());
        }
        assert!(!crate::core::is_root());
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("root");
        let database = root.join("var/lib/pacman");
        let local = database.join("local");
        std::fs::create_dir_all(&local)?;
        std::fs::create_dir_all(database.join("sync"))?;
        let version_file = local.join("ALPM_DB_VERSION");
        std::fs::write(&version_file, "9\n")?;
        let config = directory.path().join("pacman.conf");
        let config_bytes = "[options]\nSigLevel = Never\n";
        std::fs::write(&config, config_bytes)?;
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                crate::core::paths::reset_test_overrides();
                crate::package_managers::alpm_direct::clear_alpm_cache();
            }
        }
        let _restore = Restore;
        crate::core::paths::set_test_overrides(Some(root), Some(database));
        crate::package_managers::alpm_direct::clear_alpm_cache();
        temp_env::with_vars(
            [
                ("OMG_PACMAN_CONF", Some(config.as_os_str())),
                ("OMG_PACMAN_LOCAL_DIR", None),
                ("OMG_PACMAN_SYNC_DIR", None),
                ("OMG_CONFIG_DIR", Some(directory.path().as_os_str())),
                ("OMG_CACHE_DIR", Some(directory.path().as_os_str())),
            ],
            || -> AnyhowResult<()> {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                runtime.block_on(async {
                    let manager = ArchPackageManager::new();
                    assert!(manager.security_inventory().await?.is_empty());
                    for round in 0..2 {
                        let result = manager
                            .security_audit()
                            .expect("native audit owner")
                            .await?;
                        assert_eq!(result.total_vulnerabilities, 0);
                        assert_eq!(result.high_severity, 0);
                        assert!(result.vulnerabilities.is_empty());
                        assert!(matches!(result.coverage,
                            crate::core::security::scan::AuditCoverage::Reported {
                                assessed, unassessed, sources,
                            } if assessed.is_empty() && unassessed.is_empty() && sources.is_empty()
                        ));
                        assert_eq!(std::fs::read(&version_file)?, b"9\n");
                        assert_eq!(std::fs::read_dir(&local)?.count(), 1);
                        assert_eq!(std::fs::read(&config)?, config_bytes.as_bytes());
                        if round == 0 {
                            std::fs::remove_file(&config)?;
                            crate::package_managers::alpm_direct::clear_alpm_cache();
                            let error = manager
                                .security_audit()
                                .expect("native audit owner")
                                .await
                                .expect_err("empty database cannot hide an inventory-source error");
                            let message = format!("{error:#}");
                            assert!(
                                message.contains("Failed to query native security advisories"),
                                "{message}"
                            );
                            assert!(message.contains("pacman.conf"), "{message}");
                            std::fs::write(&config, config_bytes)?;
                            crate::package_managers::alpm_direct::clear_alpm_cache();
                        }
                    }
                    Ok(())
                })
            },
        )
    }

    #[tokio::test]
    async fn failed_write_still_completes_once() {
        let completed = std::cell::Cell::new(0);
        let result = finish_alpm_write(
            async { anyhow::bail!("packages committed; audit persistence failed") },
            async {
                completed.set(completed.get() + 1);
                Ok(())
            },
        )
        .await;
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("packages committed")
        );
        assert_eq!(
            completed.get(),
            1,
            "failed write bypassed catalog completion"
        );
    }

    #[tokio::test]
    async fn failed_write_retains_operation_and_completion_errors() {
        let error = finish_alpm_write(
            async { anyhow::bail!("native commit failed; state may have changed") },
            async { anyhow::bail!("daemon refresh failed") },
        )
        .await
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("native commit failed"));
        assert!(message.contains("daemon refresh failed"), "{message}");
    }

    #[tokio::test]
    async fn successful_write_reports_completion_failure() {
        let error = finish_alpm_write(async { Ok(()) }, async {
            anyhow::bail!("catalog refresh failed")
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("catalog refresh failed"));
    }

    #[test]
    fn interrupted_native_write_invalidates_catalog_and_retains_cleanup_error() -> AnyhowResult<()>
    {
        const TEST: &str = "package_managers::arch::tests::interrupted_native_write_invalidates_catalog_and_retains_cleanup_error";
        if crate::core::testing::run_isolated_test(TEST)
            || crate::config::Settings::rerun_test_unprivileged(TEST)
        {
            return Ok(());
        }
        anyhow::ensure!(
            !crate::core::is_root(),
            "catalog fixture needs ordinary UID"
        );
        let directory = tempfile::tempdir()?;
        let catalog = directory.path().join("sync_db.bin");
        let socket = directory.path().join("absent.sock");
        temp_env::with_vars(
            [
                ("OMG_CACHE_DIR", Some(directory.path().as_os_str())),
                ("OMG_SOCKET_PATH", Some(socket.as_os_str())),
            ],
            || -> AnyhowResult<()> {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                let interrupted = || async { anyhow::bail!("package stage wait was interrupted") };

                std::fs::write(&catalog, b"previous catalog")?;
                let error = runtime
                    .block_on(super::finish_native_write(interrupted()))
                    .expect_err("the interruption remains visible after catalog invalidation");
                assert_eq!(error.to_string(), "package stage wait was interrupted");
                assert!(!catalog.exists());

                std::fs::create_dir(&catalog)?;
                let error = runtime
                    .block_on(super::finish_native_write(interrupted()))
                    .expect_err("the interruption and catalog cleanup errors must both be visible");
                let detail = format!("{error:#}");
                assert!(
                    detail.contains("package stage wait was interrupted"),
                    "{detail}"
                );
                assert!(
                    detail.contains("Failed to remove package cache file"),
                    "{detail}"
                );
                assert!(catalog.is_dir());
                Ok(())
            },
        )
    }

    #[test]
    fn orphan_removals_have_rollback_history_metadata() {
        let change =
            orphan_history_change("unused-library".to_string(), Some("1.2.3-1".to_string()));

        assert_eq!(change.name, "unused-library");
        assert_eq!(change.old_version.as_deref(), Some("1.2.3-1"));
        assert!(change.new_version.is_none());
        assert_eq!(change.source, "pacman");
    }

    #[test]
    fn native_omarchy_operations_map_arguments_and_install_targets() {
        let cases = [
            (NativeOmarchyOperation::PruneCache, "cache-prune"),
            (NativeOmarchyOperation::RefreshKeyrings, "keyring-refresh"),
            (
                NativeOmarchyOperation::UpgradeRepositories,
                "repository-upgrade",
            ),
            (NativeOmarchyOperation::RemoveOrphans, "orphan-remove"),
            (
                NativeOmarchyOperation::InstallTrayMenuDependency,
                "migration-xrandr",
            ),
            (
                NativeOmarchyOperation::InstallOmnibookAudio,
                "migration-omnibook-audio",
            ),
            (
                NativeOmarchyOperation::InstallMediaViewer,
                "migration-omaview-install",
            ),
            (
                NativeOmarchyOperation::RemoveLegacyMediaViewers,
                "migration-omaview-cleanup",
            ),
            (
                NativeOmarchyOperation::InstallFacetimeHd,
                "migration-facetimehd",
            ),
            (
                NativeOmarchyOperation::InstallPiCodingAgent,
                "migration-pi-coding-agent",
            ),
            (NativeOmarchyOperation::InstallKmscon, "migration-kmscon"),
            (
                NativeOmarchyOperation::InstallPodmanAndCrun,
                "migration-podman-crun",
            ),
        ];
        for (operation, expected) in cases {
            assert_eq!(operation.argument(), expected);
            assert_eq!(
                NativeOmarchyOperation::from_argument(expected),
                Some(operation)
            );
        }

        assert_eq!(
            resolve_install_targets(NativeOmarchyOperation::InstallTrayMenuDependency, |_| {
                Ok(false)
            })
            .unwrap(),
            vec!["xorg-xrandr"]
        );
        assert_eq!(
            resolve_install_targets(NativeOmarchyOperation::InstallOmnibookAudio, |_| Ok(false))
                .unwrap(),
            vec!["hp-omnibook-3-audio"]
        );
        assert_eq!(
            resolve_install_targets(NativeOmarchyOperation::InstallMediaViewer, |_| Ok(false))
                .unwrap(),
            vec!["omaview"]
        );
        assert_eq!(
            resolve_install_targets(NativeOmarchyOperation::RemoveLegacyMediaViewers, |name| {
                Ok(matches!(name, "omaview" | "imv"))
            })
            .unwrap(),
            vec!["imv"]
        );
        assert!(
            resolve_install_targets(NativeOmarchyOperation::RemoveLegacyMediaViewers, |_| {
                Ok(false)
            })
            .is_err()
        );
        assert_eq!(
            resolve_install_targets(NativeOmarchyOperation::InstallFacetimeHd, |_| Ok(false))
                .unwrap(),
            vec!["facetimehd-dkms", "facetimehd-firmware-fetcher"]
        );
        assert!(
            resolve_install_targets(NativeOmarchyOperation::InstallFacetimeHd, |name| {
                Ok(matches!(name, "bcwc-pcie" | "facetimehd-firmware"))
            })
            .unwrap()
            .is_empty()
        );
        assert_eq!(
            resolve_install_targets(NativeOmarchyOperation::InstallPiCodingAgent, |_| Ok(false))
                .unwrap(),
            vec!["pi-coding-agent"]
        );
        assert_eq!(
            resolve_install_targets(NativeOmarchyOperation::InstallKmscon, |_| Ok(false)).unwrap(),
            vec!["kmscon"]
        );
        assert_eq!(
            resolve_install_targets(NativeOmarchyOperation::InstallPodmanAndCrun, |_| Ok(false))
                .unwrap(),
            vec!["podman", "crun"]
        );
        assert_eq!(
            resolve_install_targets(NativeOmarchyOperation::InstallPodmanAndCrun, |name| {
                Ok(name == "podman")
            })
            .unwrap(),
            vec!["crun"]
        );
        assert!(
            resolve_install_targets(NativeOmarchyOperation::PruneCache, |_| Ok(true))
                .unwrap()
                .is_empty()
        );
    }
}
