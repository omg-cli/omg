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

pub(crate) use crate::core::packages::search::validate_search_query;

pub(crate) const fn dnf_search_label(
    backend: crate::package_managers::Backend,
) -> Option<&'static str> {
    match backend {
        crate::package_managers::Backend::Fedora => Some("DNF"),
        _ => None,
    }
}

#[cfg(feature = "fedora")]
pub(super) fn print_dnf_preview(preview: &crate::package_managers::dnf::DnfTransactionPreview) {
    for line in preview.plan.lines() {
        println!("{}", crate::cli::style::sanitize_terminal_text(line));
    }
    for line in preview.diagnostics.lines() {
        eprintln!("{}", crate::cli::style::sanitize_terminal_text(line));
    }
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
    client.list_updates().await.ok()
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
/// Also used when an additive build selects Fedora or Homebrew.
#[derive(Clone, Copy)]
pub(crate) enum UpdateMode {
    Standard,
    Fast,
    Turbo,
}

fn select_native_update<T>(
    mode: UpdateMode,
    no_sync: bool,
    cached: impl FnOnce() -> Option<T>,
    standard: impl FnOnce() -> Option<T>,
) -> Option<T> {
    match mode {
        UpdateMode::Turbo => cached(),
        UpdateMode::Standard if no_sync => cached().or_else(standard),
        UpdateMode::Standard | UpdateMode::Fast => standard(),
    }
}

#[expect(clippy::fn_params_excessive_bools)] // Maps to --check / --yes / --dry-run / --no-sync
pub(crate) async fn update_official_only(
    check_only: bool,
    yes: bool,
    dry_run: bool,
    no_sync: bool,
    mode: UpdateMode,
) -> Result<()> {
    let pm = crate::package_managers::get_package_manager()?;
    #[cfg(feature = "fedora")]
    let fedora = pm.name() == "dnf";
    #[cfg(feature = "fedora")]
    let cached_fedora_upgrade =
        matches!(mode, UpdateMode::Turbo) || matches!(mode, UpdateMode::Standard) && no_sync;
    let daemon_updates = async {
        // DNF keeps metadata in the caller's cache. Even a same-user daemon
        // can have a different home and therefore a different update list.
        #[cfg(feature = "fedora")]
        if fedora {
            return None;
        }
        try_daemon_list_updates().await
    };

    // Preview modes must not mutate repository metadata or request elevation.
    // Keep this consistent with the Arch update lane.
    let use_cached = no_sync || check_only || dry_run;

    let (icon, title, detail) = match mode {
        UpdateMode::Fast => ("⚡", "Fast System Update", "sync + upgrade"),
        UpdateMode::Turbo => ("🚀", "TURBO System Update", "cached, no sync"),
        UpdateMode::Standard => (
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
        ),
    };
    crate::cli::modern_ui::print_phase_header(icon, title, detail);

    #[cfg(feature = "fedora")]
    if fedora && cached_fedora_upgrade && !check_only && !dry_run && !crate::core::is_root() {
        // The elevated DNF planner uses the system cache, which may have
        // different updates from the caller's read-only preview.
        crate::cli::modern_ui::print_info("DNF will plan the upgrade using the system cache.");
        if confirm_proceed_with_upgrade(yes).await? {
            apply_fedora_upgrade(true, "System DNF cache").await?;
        }
        return Ok(());
    }

    let check_start = std::time::Instant::now();
    let official_updates = if use_cached {
        match daemon_updates.await {
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
            daemon_updates,
        )
        .await?
    };
    #[cfg(feature = "fedora")]
    if fedora && official_updates.is_empty() {
        // The upgrade solver can replace an installed package under a new name
        // even when the same-name upgrade list is empty.
        let preview = crate::package_managers::DnfPackageManager::preview_cached_upgrade().await?;
        if preview.has_changes {
            print_dnf_preview(&preview);
            if confirm_proceed_with_upgrade(yes).await? {
                apply_fedora_upgrade(cached_fedora_upgrade, "DNF upgrade plan").await?;
            }
            return Ok(());
        }
    }
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

    if !confirm_proceed_with_upgrade(yes).await? {
        return Ok(());
    }

    let count = official_updates.len();
    let detail = format!("{count} official packages");
    #[cfg(feature = "fedora")]
    if fedora {
        return apply_fedora_upgrade(cached_fedora_upgrade, &detail).await;
    }

    println!();
    crate::cli::modern_ui::print_section("Installing updates");

    let pb = crate::cli::modern_ui::modern_spinner("Upgrading", &detail);
    let history = crate::core::history::HistoryManager::new()?;

    let native_operation = select_native_update(
        mode,
        no_sync,
        || pm.transact_cached_update_with_history(Some(&history)),
        || {
            pm.transact_with_history(
                crate::core::history::TransactionType::Update,
                &[],
                Some(&history),
            )
        },
    );
    if let Some(operation) = native_operation {
        operation.await?;
    } else {
        pm.update().await?;
    }
    crate::cli::modern_ui::finish_success(&pb, "Upgraded", &format!("{count} packages"));

    crate::core::usage::track_update_result(count, true);
    crate::cli::modern_ui::print_success(&format!("Upgraded {count} packages"));
    Ok(())
}

#[cfg(feature = "fedora")]
async fn apply_fedora_upgrade(cached: bool, detail: &str) -> Result<()> {
    println!();
    crate::cli::modern_ui::print_section("Installing updates");
    let pb = crate::cli::modern_ui::modern_spinner("Upgrading", detail);
    let history = crate::core::history::HistoryManager::new()?;
    let changes = crate::package_managers::DnfPackageManager::new()
        .update_with_history(cached, Some(&history))
        .await;
    pb.finish_and_clear();
    if let Some(changes) = changes?.filter(|&count| count != 0) {
        let label = if changes == 1 { "change" } else { "changes" };
        crate::cli::modern_ui::print_success(&format!(
            "System updated successfully · {changes} package {label}"
        ));
        crate::core::usage::track_update_result(changes, true);
    }
    Ok(())
}

async fn confirm_proceed_with_upgrade(yes: bool) -> Result<bool> {
    if yes {
        return Ok(true);
    }
    anyhow::ensure!(
        console::user_attended(),
        "Use --yes for non-interactive updates"
    );
    println!();
    let confirmed = tokio::task::spawn_blocking(|| {
        dialoguer::Confirm::with_theme(&crate::cli::ui::prompt_theme())
            .with_prompt("Proceed with upgrade?")
            .default(true)
            .interact()
    })
    .await
    .map_err(|error| anyhow::anyhow!("Confirmation prompt task failed: {error}"))??;
    if !confirmed {
        println!();
        println!("  {} Upgrade cancelled", crate::cli::style::caution("✗"));
        println!();
    }
    Ok(confirmed)
}

/// Dry-run preview shared by the Debian and generic backends.
///
/// Download sizes are unknown without resolving dependencies, so none are
/// claimed.
/// Also used by Homebrew when included in an additive build.
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
#[cfg(any(feature = "arch", feature = "debian", not(feature = "debian-pure")))]
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
    report_removal(packages, service.remove(packages)).await
}

pub(crate) async fn report_removal(
    packages: &[String],
    operation: impl Future<Output = Result<()>>,
) -> Result<()> {
    crate::cli::modern_ui::print_phase_header(
        "🗑️",
        "Remove",
        &format!("{} package(s)", packages.len()),
    );
    println!();

    let result = operation.await;

    crate::core::usage::track_remove_result(result.is_ok());

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn daemon_update_probe_preserves_multilib_identity_over_a_private_socket() -> Result<()> {
        use crate::daemon::protocol::{
            Request, Response, ResponseResult, encode_frame, split_frame,
        };
        use anyhow::Context as _;
        use futures::{SinkExt, StreamExt};
        use std::os::unix::fs::PermissionsExt as _;
        use std::time::Duration;
        use tokio_util::codec::{Framed, LengthDelimitedCodec};

        const CASE: &str = "cli::packages::common::tests::daemon_update_probe_preserves_multilib_identity_over_a_private_socket";
        if crate::core::testing::run_isolated_test(CASE) {
            return Ok(());
        }
        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in("/tmp")?;
        let runtime_dir = directory.path().to_str().context("UTF-8 runtime path")?;
        temp_env::with_vars(
            [
                ("XDG_RUNTIME_DIR", Some(runtime_dir)),
                ("OMG_SOCKET_PATH", None),
                ("OMG_TEST_MODE", None),
                ("OMG_DISABLE_DAEMON", None),
            ],
            || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(async {
                        let socket = directory.path().join("omg.sock");
                        assert_eq!(crate::core::client::default_socket_path(), socket);
                        crate::core::client::validate_socket_with_context(&socket)?;
                        let listener = tokio::net::UnixListener::bind(socket)?;
                        let serve = async {
                            let (stream, _) = listener.accept().await?;
                            let mut frames = Framed::new(stream, LengthDelimitedCodec::new());
                            let frame = frames.next().await.context("missing daemon request")??;
                            let (_, payload) = split_frame(&frame)?;
                            let request: Request = bitcode::deserialize(payload)?;
                            assert!(
                                matches!(request, Request::ListUpdates { .. }),
                                "unexpected daemon request {request:?}"
                            );
                            let id = request.id();
                            let result = ResponseResult::ListUpdates(vec![UpdateInfo {
                                name: "lib".into(),
                                architecture: Some("i686".into()),
                                old_version: "1-1".into(),
                                new_version: "2-1".into(),
                                repo: "updates".into(),
                            }]);
                            frames
                                .send(encode_frame(&Response::Success { id, result })?.into())
                                .await?;
                            Ok::<_, anyhow::Error>(())
                        };
                        let probe = async {
                            try_daemon_list_updates()
                                .await
                                .context("private daemon update response")
                        };
                        let ((), updates) = tokio::time::timeout(Duration::from_secs(5), async {
                            tokio::try_join!(serve, probe)
                        })
                        .await??;
                        assert_eq!(updates.len(), 1, "unexpected daemon updates {updates:?}");
                        let update = &updates[0];
                        assert_eq!(update.name, "lib");
                        assert_eq!(update.architecture.as_deref(), Some("i686"));
                        assert_eq!(update.new_version, "2-1");
                        Ok(())
                    })
            },
        )
    }

    #[test]
    fn standard_updates_select_cached_or_refreshable_native_upgrade() {
        for (no_sync, expected) in [(true, "cached plan"), (false, "refreshable plan")] {
            let selected = select_native_update(
                UpdateMode::Standard,
                no_sync,
                || Some("cached plan"),
                || Some("refreshable plan"),
            );
            assert_eq!(selected, Some(expected));
        }
    }

    #[test]
    fn standard_no_sync_keeps_the_native_upgrade_when_cached_admission_is_unavailable() {
        let selected =
            select_native_update(UpdateMode::Standard, true, || None, || Some("native plan"));
        assert_eq!(selected, Some("native plan"));
    }

    #[test]
    fn fast_updates_use_the_standard_plan_and_turbo_keeps_cached_metadata() {
        for (mode, expected) in [
            (UpdateMode::Fast, "native plan"),
            (UpdateMode::Turbo, "cached plan"),
        ] {
            assert_eq!(
                select_native_update(mode, false, || Some("cached plan"), || Some("native plan")),
                Some(expected)
            );
        }
    }

    #[test]
    fn no_sync_official_update_runs_with_a_backend_without_cached_admission() -> Result<()> {
        use crate::package_managers::{Backend, PackageManager, mock::MockPackageManager};
        use anyhow::Context;

        const NAME: &str = "cli::packages::common::tests::no_sync_official_update_runs_with_a_backend_without_cached_admission";
        if crate::core::testing::run_isolated_test(NAME) {
            return Ok(());
        }
        let fixture = tempfile::tempdir()?;
        let data = fixture.path().to_str().context("Mock package directory")?;
        temp_env::with_vars(
            [
                ("OMG_TEST_MODE", Some("1")),
                ("OMG_TEST_DISTRO", Some("debian")),
                ("OMG_DISABLE_DAEMON", Some("1")),
                ("OMG_NATIVE_TEST_DATA_DIR", Some("1")),
                ("OMG_DATA_DIR", Some(data)),
            ],
            || {
                assert_eq!(crate::package_managers::resolve_backend()?, Backend::Mock);
                let manager = MockPackageManager::new_in("debian", fixture.path());
                manager.set_installed_version("curl", "1.0.0")?;
                manager.set_available_version("curl", "2.0.0")?;
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(async {
                        assert_eq!(manager.list_updates().await?.len(), 1);
                        update_official_only(false, true, false, true, UpdateMode::Standard).await
                    })
            },
        )
    }

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
            architecture: None,
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
            architecture: None,
            name: "example".to_string(),
            old_version: "1.0".to_string(),
            new_version: "2.0".to_string(),
            repo: "core".to_string(),
        }];
        assert!(update_official_only_dry_run(&updates).is_ok());

        const CHILD: &str = "OMG_DRY_RUN_PREVIEW_OUTPUT_CHILD";
        const NAME: &str =
            "cli::packages::common::tests::dry_run_preview_reports_unknown_download_size";
        if std::env::var(CHILD).as_deref() == Ok(NAME) {
            crate::cli::modern_ui::configure_output(0, false);
            println!("DRY_RUN_PREVIEW_BEGIN {NAME}");
            assert!(update_official_only_dry_run(&updates).is_ok());
            println!("DRY_RUN_PREVIEW_END {NAME}");
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                NAME,
                "--nocapture",
                "--color",
                "never",
                "--test-threads=1",
            ])
            .env(CHILD, NAME)
            .env("NO_COLOR", "1")
            .output()
            .expect("capture actual dry-run preview");
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 preview output");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stdout.len() + stderr.len() <= 64 * 1024,
            "preview capture exceeded bound:\n{stdout}\n{stderr}"
        );
        assert!(
            output.status.success()
                && stdout
                    .matches("test result: ok. 1 passed; 0 failed; 0 ignored;")
                    .count()
                    == 1,
            "preview child failed ({}):\n{stdout}\n{stderr}",
            output.status
        );
        let begin = format!("DRY_RUN_PREVIEW_BEGIN {NAME}\n");
        let end = format!("DRY_RUN_PREVIEW_END {NAME}\n");
        assert_eq!(stdout.matches(&begin).count(), 1, "{stdout}");
        assert_eq!(stdout.matches(&end).count(), 1, "{stdout}");
        let (_, printed) = stdout.split_once(&begin).expect("preview begin frame");
        let (printed, _) = printed.split_once(&end).expect("preview end frame");
        assert!(printed.contains("example 1.0 → 2.0 (core)"), "{printed}");
        assert!(printed.contains("1 update available"), "{printed}");
        assert!(!printed.contains("Download size:"), "{printed}");
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
