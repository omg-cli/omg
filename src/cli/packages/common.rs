//! Common utilities for package operations
//!
//! Also hosts behavior shared verbatim between compiled package-manager
//! backends (cold-path updates, service-backed removal, daemon update
//! probes) so each backend file only carries what genuinely differs.

#[cfg(unix)]
use crate::core::client::DaemonClient;
use crate::package_managers::types::UpdateInfo;
#[cfg(unix)]
use anyhow::Context;
use anyhow::Result;

/// Validate a search query for safety.
///
/// Rejects queries that are too long, contain control characters,
/// path traversal sequences, or shell metacharacters.
pub fn validate_search_query(query: &str) -> Result<()> {
    if query.len() > 100 {
        anyhow::bail!("Search query too long (max 100 characters)");
    }
    if query.chars().any(char::is_control) {
        anyhow::bail!("Search query contains invalid characters");
    }
    if query.contains('/') || query.contains('\\') || query.contains("..") {
        anyhow::bail!("Invalid search query: path traversal detected");
    }
    if query.chars().any(|c| ";|&><$".contains(c)) {
        anyhow::bail!("Invalid search query: shell metacharacters detected");
    }
    Ok(())
}

/// Check if a search query passes validation (returns false on failure).
///
/// Convenience wrapper for sync code paths that return `bool` instead of `Result`.
#[must_use]
pub fn is_valid_search_query(query: &str) -> bool {
    validate_search_query(query).is_ok()
}

/// Probe the daemon for pending official-repository updates.
///
/// Returns `None` when the daemon is unavailable or reports an error so the
/// caller can fall back to querying the package manager directly.
#[cfg(unix)]
pub(crate) async fn try_daemon_list_updates() -> Option<Vec<UpdateInfo>> {
    let mut client = DaemonClient::connect().await.ok()?;
    let entries = client.list_updates().await.ok()?;
    Some(
        entries
            .into_iter()
            .map(|e| UpdateInfo {
                name: e.name,
                old_version: e.old_version,
                new_version: e.new_version,
                repo: e.repo,
            })
            .collect(),
    )
}

/// Non-Unix stub preserving the asynchronous command interface.
#[cfg(not(unix))]
#[allow(
    clippy::unused_async,
    reason = "the non-Unix implementation preserves the asynchronous command interface"
)]
pub(crate) async fn try_daemon_list_updates() -> Option<Vec<UpdateInfo>> {
    None
}

/// Refresh the daemon's package index after a database sync.
///
/// The daemon owns an immutable snapshot of the package databases: a worker
/// created before the sync serves its frozen in-memory update list until an
/// explicit `RefreshIndex` IPC swaps in fresh backends (the stale-index
/// invariant established in `sync_db.rs`). Daemon absence is normal; a
/// connected daemon that rejects the refresh is a consistency failure and is
/// reported.
// Visible to the Arch update lane: after `pm.sync()` the daemon still
// serves its frozen pre-sync snapshot until this refresh swaps it.
#[cfg(unix)]
pub(crate) async fn refresh_daemon_index_after_sync() -> Result<()> {
    match DaemonClient::connect().await {
        Ok(mut client) => {
            let packages = client
                .refresh_index()
                .await
                .context("Package databases synced, but daemon index refresh failed")?;
            tracing::debug!(packages, "Daemon package index refreshed after sync");
        }
        Err(error) => {
            tracing::debug!("Daemon unavailable after package database sync: {error}");
        }
    }
    Ok(())
}

/// Non-Unix stub preserving the asynchronous command interface.
#[cfg(not(unix))]
#[allow(
    clippy::unused_async,
    reason = "the non-Unix implementation preserves the asynchronous command interface"
)]
async fn refresh_daemon_index_after_sync() -> Result<()> {
    Ok(())
}

/// Sequence the post-sync update decision: refresh the daemon index BEFORE
/// probing its update list, falling back to a direct package-manager query
/// when the daemon is unavailable.
///
/// The daemon serves update lists from the backend snapshot it held at
/// startup (or its last `RefreshIndex`), so probing before the refresh would
/// present the user a stale pre-sync list. The injected futures exist so the
/// ordering contract is testable; production passes the real IPC calls.
#[cfg(any(feature = "debian", feature = "debian-pure", not(feature = "arch")))]
async fn official_updates_after_sync<R, P>(
    pm: &dyn crate::package_managers::PackageManager,
    refresh_index: R,
    probe_daemon_updates: P,
) -> Result<Vec<UpdateInfo>>
where
    R: Future<Output = Result<()>>,
    P: Future<Output = Option<Vec<UpdateInfo>>>,
{
    refresh_index.await?;
    match probe_daemon_updates.await {
        Some(updates) => Ok(updates),
        None => pm.list_updates().await,
    }
}

/// Shared cold-path update flow for the Debian and generic backends:
/// optionally sync, list official updates, confirm, and upgrade.
///
/// These backends have no AUR equivalent, so `check_only`, `dry_run`, and the
/// confirmation prompt cover the entire decision tree.
///
/// Compiled exactly when a consumer backend exists: the Debian module (under
/// `debian`/`debian-pure`) or the generic module (when Arch is absent).
#[cfg(any(feature = "debian", feature = "debian-pure", not(feature = "arch")))]
#[expect(clippy::fn_params_excessive_bools)] // Maps to --check / --yes / --dry-run / --no-sync
pub(crate) async fn update_official_only(
    check_only: bool,
    yes: bool,
    dry_run: bool,
    no_sync: bool,
) -> Result<()> {
    let pm = crate::package_managers::get_package_manager()?;

    // Preview modes must not mutate repository metadata or request elevation.
    // Keep this consistent with the Arch update lane.
    let use_cached = no_sync || check_only || dry_run;

    crate::cli::modern_ui::print_phase_header(
        "🔄",
        "Update",
        if dry_run {
            if no_sync {
                "Dry run · cached"
            } else {
                "Dry run · checking for updates"
            }
        } else if use_cached {
            "Checking for updates · cached"
        } else {
            "Checking for updates"
        },
    );

    let check_start = std::time::Instant::now();
    let official_updates = if use_cached {
        match try_daemon_list_updates().await {
            Some(updates) => updates,
            None => pm.list_updates().await?,
        }
    } else {
        let sync_start = std::time::Instant::now();
        pm.sync().await?;
        crate::cli::modern_ui::print_finished_step(
            "Synced",
            &format!("in {:.2}s", sync_start.elapsed().as_secs_f64()),
        );
        official_updates_after_sync(
            pm.as_ref(),
            refresh_daemon_index_after_sync(),
            try_daemon_list_updates(),
        )
        .await?
    };
    crate::cli::modern_ui::print_source_lane(
        "official",
        official_updates.len(),
        check_start.elapsed(),
    );

    println!();
    if official_updates.is_empty() {
        crate::cli::modern_ui::print_up_to_date();
        return Ok(());
    }

    if dry_run {
        return update_official_only_dry_run(&official_updates);
    }

    crate::cli::modern_ui::print_update_summary(&official_updates);

    if check_only {
        println!();
        println!(
            "  {} Run {} to install updates",
            crate::cli::style::dim("→"),
            crate::cli::style::runtime("omg update")
        );
        println!();
        return Ok(());
    }

    if !yes && console::user_attended() {
        println!();
        if !confirm_proceed_with_upgrade().await? {
            println!();
            println!("  {} Upgrade cancelled", crate::cli::style::caution("✗"));
            println!();
            return Ok(());
        }
    } else if !yes {
        anyhow::bail!("Use --yes for non-interactive updates");
    }

    println!();
    crate::cli::modern_ui::print_section("Installing updates");

    let count = official_updates.len();
    let pb =
        crate::cli::modern_ui::modern_spinner("Upgrading", &format!("{count} official packages"));
    let history = crate::core::history::HistoryManager::new()?;
    if let Some(operation) = pm.transact_with_history(
        crate::core::history::TransactionType::Update,
        &[],
        Some(&history),
    ) {
        operation.await?;
    } else {
        pm.update().await?;
    }
    crate::cli::modern_ui::finish_success(&pb, "Upgraded", &format!("{count} packages"));

    crate::core::usage::track_update_result(count, true);
    crate::cli::modern_ui::print_success(&format!("Upgraded {count} packages"));
    Ok(())
}

/// Blocking terminal prompt moved off the async executor thread.
#[cfg(any(feature = "debian", feature = "debian-pure", not(feature = "arch")))]
async fn confirm_proceed_with_upgrade() -> Result<bool> {
    Ok(tokio::task::spawn_blocking(|| {
        dialoguer::Confirm::with_theme(&crate::cli::ui::prompt_theme())
            .with_prompt("Proceed with upgrade?")
            .default(true)
            .interact()
    })
    .await
    .map_err(|error| anyhow::anyhow!("Confirmation prompt task failed: {error}"))??)
}

/// Dry-run preview shared by the Debian and generic backends.
///
/// Download sizes are unknown without resolving dependencies, so none are
/// claimed.
/// Compiled exactly when a consumer backend exists: the Debian module (under
/// `debian`/`debian-pure`) or the generic module (when Arch is absent).
#[cfg(any(feature = "debian", feature = "debian-pure", not(feature = "arch")))]
pub(crate) fn update_official_only_dry_run(updates: &[UpdateInfo]) -> Result<()> {
    updates
        .iter()
        .try_for_each(|update| crate::core::security::validate_package_name(&update.name))?;

    crate::cli::modern_ui::print_phase_header("", "Update", "dry run");
    crate::cli::modern_ui::print_update_summary(updates);
    crate::cli::ui::print_dry_run_footer();
    Ok(())
}

fn confirmation_policy(yes: bool, attended: bool, action: &str) -> Result<bool> {
    if yes {
        return Ok(false);
    }
    anyhow::ensure!(attended, "Use --yes for non-interactive package {action}");
    Ok(true)
}

/// Shared attended-confirmation seam: fail-closed `--yes`/non-TTY policy plus
/// the blocking TTY read off the async executor. Both mutation and cleanup
/// prompts delegate here so the guard cannot drift between call sites.
async fn confirm_attended(prompt: String, yes: bool, action: &'static str) -> Result<bool> {
    if !confirmation_policy(yes, console::user_attended(), action)? {
        return Ok(true);
    }

    tokio::task::spawn_blocking(move || {
        dialoguer::Confirm::with_theme(&crate::cli::ui::prompt_theme())
            .with_prompt(prompt)
            .default(false)
            .interact()
    })
    .await
    .map_err(|error| anyhow::anyhow!("Confirmation prompt task failed: {error}"))?
    .map_err(Into::into)
}

/// Confirm destructive cleanup unless the caller supplied `--yes`.
///
/// Fails closed on non-TTY so scripts must pass `--yes`.
/// Only compiled where the cleanup call site in `clean.rs` is live.
#[cfg(any(feature = "arch", not(feature = "debian-pure")))]
pub(crate) async fn confirm_cleanup(yes: bool) -> Result<bool> {
    confirm_attended("Proceed with cleanup?".to_string(), yes, "cleanup").await
}

/// Confirm a privileged package mutation unless the caller supplied `--yes`.
pub(crate) async fn confirm_package_mutation(
    action: &'static str,
    package_count: usize,
    yes: bool,
) -> Result<bool> {
    confirm_attended(
        format!("Proceed with {action} of {package_count} package(s)?"),
        yes,
        action,
    )
    .await
}

/// Track removal requests around `PackageService::remove`.
#[cfg(any(not(feature = "arch"), feature = "debian", feature = "debian-pure"))]
pub(crate) async fn remove_via_service(packages: &[String]) -> Result<()> {
    let manager = crate::package_managers::get_package_manager()?;
    remove_with_manager(packages, manager).await
}

pub(crate) async fn remove_with_manager(
    packages: &[String],
    manager: std::sync::Arc<dyn crate::package_managers::PackageManager>,
) -> Result<()> {
    use crate::core::packages::PackageService;

    let service = PackageService::new(manager)?;

    crate::cli::modern_ui::print_phase_header(
        "🗑️",
        "Remove",
        &format!("{} package(s)", packages.len()),
    );
    println!();

    let result = service.remove(packages).await;

    crate::core::usage::track_remove_result(result.is_ok());

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Arch update lane calls this after every sync: with no daemon it
    /// must be a quiet no-op, never a failure that aborts the update.
    /// Serial: the daemon-disable switch is process-global environment.
    #[cfg(unix)]
    #[serial_test::serial]
    #[test]
    fn daemon_refresh_without_a_daemon_is_a_quiet_noop() {
        let result = temp_env::with_var("OMG_DISABLE_DAEMON", Some("1"), || {
            futures::executor::block_on(refresh_daemon_index_after_sync())
        });
        assert!(result.is_ok());
    }

    /// Regression test for the stale-index invariant (W12-A-01): after a sync,
    /// the update path must fully refresh the daemon index BEFORE probing its
    /// update list. If the probe ever runs first, a frozen pre-sync daemon
    /// list would be served and the user would act on wrong update data.
    #[tokio::test]
    #[cfg(any(feature = "debian", feature = "debian-pure", not(feature = "arch")))]
    async fn update_path_refreshes_daemon_index_before_probing_its_update_list() {
        use crate::package_managers::PackageManager;
        use std::sync::{Arc, Mutex};

        let pm = crate::package_managers::mock::MockPackageManager::new("arch");
        let order: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));

        let refresh_order = Arc::clone(&order);
        let probe_order = Arc::clone(&order);
        let updates = official_updates_after_sync(
            &pm,
            async move {
                refresh_order.lock().expect("order lock").push("refresh");
                Ok(())
            },
            async move {
                probe_order.lock().expect("order lock").push("probe");
                // Daemon reports nothing; the direct fallback must be used.
                None
            },
        )
        .await
        .expect("post-sync update sequence must succeed");

        let direct = pm.list_updates().await.expect("mock list_updates");
        assert_eq!(
            updates.len(),
            direct.len(),
            "fallback must query the package manager"
        );
        assert_eq!(
            *order.lock().expect("order lock"),
            vec!["refresh", "probe"],
            "daemon index refresh must complete before the update list is probed"
        );
    }

    /// A completed refresh must not be abandoned: when the daemon probe yields
    /// updates they are served directly instead of re-querying the package
    /// manager (freshness achieved, speed path kept).
    #[tokio::test]
    #[cfg(any(feature = "debian", feature = "debian-pure", not(feature = "arch")))]
    async fn post_sync_sequence_serves_daemon_updates_after_refresh() {
        let pm = crate::package_managers::mock::MockPackageManager::new("arch");
        let refreshed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&refreshed);

        let daemon_updates = vec![UpdateInfo {
            name: "curl".to_string(),
            old_version: "1.0".to_string(),
            new_version: "2.0".to_string(),
            repo: "core".to_string(),
        }];
        let expected = daemon_updates.clone();

        let updates = official_updates_after_sync(
            &pm,
            async move {
                flag.store(true, std::sync::atomic::Ordering::Release);
                Ok(())
            },
            async move { Some(expected) },
        )
        .await
        .expect("post-sync update sequence must succeed");

        assert!(refreshed.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(updates.len(), 1, "daemon update must be served");
        let served = &updates[0];
        assert_eq!(served.name, "curl");
        assert_eq!(served.old_version, "1.0");
        assert_eq!(served.new_version, "2.0");
        assert_eq!(served.repo, "core");
    }

    #[test]
    #[cfg(any(feature = "debian", feature = "debian-pure", not(feature = "arch")))]
    fn dry_run_preview_reports_unknown_download_size() {
        // The preview must never fabricate download sizes it did not resolve.
        let updates = vec![crate::package_managers::types::UpdateInfo {
            name: "example".to_string(),
            old_version: "1.0".to_string(),
            new_version: "2.0".to_string(),
            repo: "core".to_string(),
        }];
        assert!(update_official_only_dry_run(&updates).is_ok());
    }

    #[test]
    fn package_mutation_confirmation_is_required_in_non_interactive_sessions() {
        assert!(!confirmation_policy(true, false, "installation").unwrap());
        assert!(confirmation_policy(false, true, "installation").unwrap());
        let error = confirmation_policy(false, false, "installation").unwrap_err();
        assert!(error.to_string().contains("Use --yes"));
    }

    #[cfg(any(feature = "arch", not(feature = "debian-pure")))]
    #[tokio::test]
    async fn cleanup_confirmation_is_skipped_with_yes_without_prompting() {
        // `--yes` must resolve without touching the TTY so scripts and the
        // TUI (which passes yes=true) never block on a prompt.
        assert!(confirm_cleanup(true).await.unwrap());
    }

    #[test]
    fn test_validate_search_query_valid() {
        assert!(validate_search_query("firefox").is_ok());
        assert!(validate_search_query("lib32-mesa").is_ok());
        assert!(validate_search_query("python-numpy").is_ok());
    }

    #[test]
    fn test_validate_search_query_too_long() {
        let long = "a".repeat(101);
        let err = validate_search_query(&long).unwrap_err();
        assert!(err.to_string().contains("too long"));
    }

    #[test]
    fn test_validate_search_query_control_chars() {
        let err = validate_search_query("test\x00query").unwrap_err();
        assert!(err.to_string().contains("invalid characters"));
    }

    #[test]
    fn test_validate_search_query_path_traversal() {
        let err = validate_search_query("../etc/passwd").unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn test_validate_search_query_shell_metacharacters() {
        let err = validate_search_query("test;rm -rf").unwrap_err();
        assert!(err.to_string().contains("shell metacharacters"));
    }

    #[test]
    fn test_is_valid_search_query() {
        assert!(is_valid_search_query("firefox"));
        assert!(!is_valid_search_query("../passwd"));
        assert!(!is_valid_search_query("test;ls"));
    }
}
