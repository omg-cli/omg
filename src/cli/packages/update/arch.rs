use anyhow::{Context, Result};

use crate::cli::packages::common::try_daemon_list_updates;
use crate::cli::{modern_ui, style, ui};
use crate::core::security::{PolicyError, SecurityPolicy};
use crate::package_managers::{
    get_package_manager,
    types::{UpdateInfo, Version},
};

/// Hard bounds for `OMG_AUR_PARALLEL`: builds are process-heavy (makepkg
/// spawns compilers), so fan-out beyond a handful helps nobody and starves
/// the machine at the top end.
const MIN_AUR_BUILD_CONCURRENCY: usize = 1;
const MAX_AUR_BUILD_CONCURRENCY: usize = 8;

/// Parse the `OMG_AUR_PARALLEL` override, clamping to `[1, 8]` and warning on
/// invalid input instead of silently substituting the default.
fn aur_build_concurrency(raw: Option<&str>, configured_default: usize) -> usize {
    const fn clamp(value: usize) -> usize {
        if value < MIN_AUR_BUILD_CONCURRENCY {
            MIN_AUR_BUILD_CONCURRENCY
        } else if value > MAX_AUR_BUILD_CONCURRENCY {
            MAX_AUR_BUILD_CONCURRENCY
        } else {
            value
        }
    }

    let configured_default = configured_default.max(MIN_AUR_BUILD_CONCURRENCY);
    let Some(raw) = raw else {
        return configured_default;
    };
    match raw.parse::<usize>() {
        Ok(parsed) if (MIN_AUR_BUILD_CONCURRENCY..=MAX_AUR_BUILD_CONCURRENCY).contains(&parsed) => {
            parsed
        }
        Ok(parsed) => {
            let clamped = clamp(parsed);
            tracing::warn!(
                "OMG_AUR_PARALLEL={parsed} is outside {MIN_AUR_BUILD_CONCURRENCY}..={MAX_AUR_BUILD_CONCURRENCY}; clamping to {clamped}"
            );
            clamped
        }
        Err(error) => {
            tracing::warn!(
                "OMG_AUR_PARALLEL={raw:?} is not a valid number ({error}); using {configured_default}"
            );
            configured_default
        }
    }
}

/// Outcome of the AUR check lane, run concurrently with the official
/// check. Policy and client construction failures stay hard errors (the
/// future resolves them through `?`); only a failed update listing degrades
/// to the warn-and-continue path when official updates exist.
enum AurCheck {
    Skipped,
    Ready {
        policy: SecurityPolicy,
        raw: Vec<(String, Version, Version)>,
    },
    Failed(anyhow::Error),
}

/// AUR update candidates split by the user's security policy.
struct ScreenedAurUpdates {
    allowed: Vec<(String, Version, Version)>,
    skipped: Vec<(String, PolicyError)>,
}

/// Screen AUR update candidates against the user's security policy.
///
/// Mirrors the install lane: AUR sources are Community grade, so each
/// candidate goes through [`SecurityPolicy::check_source`]. A violation
/// skips that candidate only (fail closed per candidate), never the whole
/// update run; the caller must surface each skip with the violated rule.
fn screen_aur_updates_against_policy(
    policy: &SecurityPolicy,
    candidates: Vec<(String, Version, Version)>,
) -> ScreenedAurUpdates {
    let mut screened = ScreenedAurUpdates {
        allowed: Vec::with_capacity(candidates.len()),
        skipped: Vec::new(),
    };
    for (name, old_version, new_version) in candidates {
        if let Err(violation) = policy.check_source(&name, true, None) {
            tracing::warn!("Security policy blocks AUR update for {name}: {violation}");
            screened.skipped.push((name, violation));
            continue;
        }
        screened.allowed.push((name, old_version, new_version));
    }
    screened
}

const fn includes_official_updates(aur_only: bool) -> bool {
    !aur_only
}

const fn should_sync_official_databases(
    no_sync: bool,
    check_only: bool,
    dry_run: bool,
    aur_only: bool,
) -> bool {
    includes_official_updates(aur_only) && should_sync(no_sync, check_only, dry_run)
}

const fn update_phase_context(
    check_only: bool,
    dry_run: bool,
    no_sync: bool,
    aur_only: bool,
) -> &'static str {
    if aur_only {
        return if dry_run {
            "Dry run · AUR only"
        } else {
            "AUR only"
        };
    }
    if dry_run {
        if no_sync {
            "Dry run · cached"
        } else {
            "Dry run · checking for updates"
        }
    } else if check_only || no_sync {
        "Checking for updates · cached"
    } else {
        "Refreshing catalogs"
    }
}

const fn should_sync(no_sync: bool, check_only: bool, dry_run: bool) -> bool {
    !no_sync && !check_only && !dry_run
}

pub async fn update_fast() -> Result<()> {
    modern_ui::print_phase_header("⚡", "Fast System Update", "sync + upgrade");
    crate::package_managers::arch::run_privileged_operation(
        "fullupdate",
        &[],
        &[],
        run_full_sysupgrade,
    )
    .await
}

/// Refresh package databases before a root-side fast update.
async fn run_full_sysupgrade() -> anyhow::Result<()> {
    crate::package_managers::sync_databases_parallel().await?;
    run_sysupgrade().await
}

/// Execute a full system upgrade and record it in history.
///
/// Used by the privileged arms of `update --fast` / `--turbo`: previously
/// these closures were no-ops, so an already-privileged invocation claimed
/// success without upgrading anything.
async fn run_sysupgrade() -> anyhow::Result<()> {
    let history = crate::core::history::HistoryManager::new()?;
    let updates = crate::package_managers::get_update_list()?;
    let changes = history_changes(&updates);
    let result = tokio::task::spawn_blocking(|| {
        crate::package_managers::execute_transaction(
            Vec::new(),
            crate::package_managers::TransactionKind::SystemUpgrade,
            None,
        )
    })
    .await
    .context("System upgrade task failed")?;

    history.finish_operation(
        crate::core::history::TransactionType::Update,
        changes,
        result,
    )
}

pub async fn update_turbo() -> Result<()> {
    modern_ui::print_phase_header("🚀", "TURBO System Update", "cached, no sync");
    println!(
        "  {} Checking for updates (cached, no sync)...",
        style::caution("⚡")
    );

    let updates = crate::package_managers::get_update_list()?;
    if updates.is_empty() {
        println!();
        println!("  {} System is up to date!", style::positive("✓"));
        println!();
        return Ok(());
    }

    println!(
        "  {} Found {} update(s) - upgrading now...",
        style::accent("→"),
        style::caution(&updates.len().to_string())
    );
    println!();

    crate::package_managers::arch::run_privileged_operation("turboupdate", &[], &[], run_sysupgrade)
        .await
}

fn history_changes(updates: &[UpdateInfo]) -> Vec<crate::core::history::PackageChange> {
    updates
        .iter()
        .map(|update| crate::core::history::PackageChange {
            name: update.name.clone(),
            old_version: Some(update.old_version.clone()),
            new_version: Some(update.new_version.clone()),
            source: update.repo.clone(),
        })
        .collect()
}

fn enforce_selected_update_scope(
    aur_only: bool,
    official_count: usize,
    updates: &[UpdateInfo],
) -> Result<()> {
    if !aur_only {
        return Ok(());
    }
    anyhow::ensure!(
        official_count == 0
            && updates
                .iter()
                .all(|update| update.repo.eq_ignore_ascii_case("aur")),
        "AUR-only update scope contained an official package; refusing the transaction"
    );
    Ok(())
}

#[expect(clippy::fn_params_excessive_bools)] // Maps directly to CLI update flags
pub async fn update(
    check_only: bool,
    yes: bool,
    dry_run: bool,
    no_sync: bool,
    aur_only: bool,
) -> Result<()> {
    let pm = get_package_manager()?;

    let needs_deferred_sync =
        !aur_only && !check_only && !dry_run && !crate::core::caps::can_write_pacman_db();

    modern_ui::print_phase_header(
        "🔄",
        "Update",
        update_phase_context(check_only, dry_run, no_sync, aur_only),
    );

    if should_sync_official_databases(no_sync, check_only, dry_run, aur_only) {
        // Do not animate here. `pm.sync()` elevates and the child owns the
        // per-repository lanes; a parent spinner hides the sudo prompt and
        // reprints itself as a second "Syncing package databases" bar.
        println!();
        pm.sync().await?;
        // The daemon serves its frozen pre-sync snapshot until told
        // otherwise; refresh it before probing so the update list
        // below reflects the sync that just finished.
        crate::cli::packages::common::refresh_daemon_index_after_sync().await?;
    }

    let mut all_updates: Vec<UpdateInfo> = Vec::with_capacity(32);
    let skip_aur = crate::core::paths::test_mode() || crate::core::env::distro::is_debian_like();
    let check_detail = if aur_only {
        "AUR"
    } else if skip_aur {
        "official repositories"
    } else {
        "official and AUR"
    };
    let check_pb = modern_ui::modern_spinner("Checking", check_detail);
    let check_start = std::time::Instant::now();

    // The official and AUR checks touch independent state (sync databases
    // vs the AUR index or RPC): overlap them instead of paying the sum.
    // Rendering below stays ordered, so output matches the serial run.
    let official_fut = async {
        if !includes_official_updates(aur_only) {
            return Ok(Vec::new());
        }
        match try_daemon_list_updates().await {
            Some(updates) => Ok(updates),
            None => pm.list_updates().await,
        }
    };
    let aur_fut = async {
        if skip_aur {
            return Ok(AurCheck::Skipped);
        }
        // The AUR lane must enforce the user's security policy the same
        // way install does; a corrupt policy file aborts the update
        // rather than silently upgrading off-policy packages.
        let policy =
            crate::core::security::SecurityPolicy::load_default().map_err(anyhow::Error::from)?;
        let client = crate::package_managers::AurClient::new()?;
        match client.get_update_list().await {
            Ok(raw) => Ok(AurCheck::Ready { policy, raw }),
            Err(error) => Ok(AurCheck::Failed(error)),
        }
    };
    let (official_result, aur_result): (Result<Vec<UpdateInfo>>, Result<AurCheck>) =
        tokio::join!(official_fut, aur_fut);

    let official_updates = match official_result {
        Ok(updates) => updates,
        Err(error) => {
            modern_ui::finish_clear(&check_pb);
            return Err(error);
        }
    };
    let check_elapsed = check_start.elapsed();
    modern_ui::finish_clear(&check_pb);
    if !aur_only {
        modern_ui::print_source_lane("official", official_updates.len(), check_elapsed);
    }

    let official_count = official_updates.len();
    all_updates.extend(official_updates);

    let aur_packages = match aur_result {
        Err(error) => return Err(error),
        Ok(AurCheck::Skipped) => Vec::new(),
        Ok(AurCheck::Failed(error)) => {
            if official_count == 0 {
                return Err(error).context("Failed to check AUR updates");
            }
            modern_ui::print_warning(&format!(
                "AUR update check failed; continuing with official updates: {error:#}"
            ));
            Vec::new()
        }
        Ok(AurCheck::Ready { policy, raw }) => {
            let aur_elapsed = check_start.elapsed();
            let count = raw.len();
            let ScreenedAurUpdates { allowed, skipped } =
                screen_aur_updates_against_policy(&policy, raw);
            for (name, old_ver, new_ver) in &allowed {
                all_updates.push(UpdateInfo {
                    name: name.clone(),
                    old_version: old_ver.to_string(),
                    new_version: new_ver.to_string(),
                    repo: "AUR".to_string(),
                });
            }
            modern_ui::print_source_lane("aur", count, aur_elapsed);
            for (name, violation) in &skipped {
                modern_ui::print_warning(&format!(
                    "Skipping AUR update for {}: {violation}",
                    style::package(name)
                ));
            }
            allowed.into_iter().map(|(name, _, _)| name).collect()
        }
    };

    // Fail closed at the transaction boundary as well as at discovery. This
    // prevents a future refactor from feeding an official package into the
    // install phase merely because it bypassed the earlier scope branches.
    enforce_selected_update_scope(aur_only, official_count, &all_updates)?;

    println!();

    if all_updates.is_empty() {
        modern_ui::print_up_to_date();
        return Ok(());
    }

    if dry_run {
        update_dry_run(&all_updates);
        return Ok(());
    }

    modern_ui::print_update_summary(&all_updates);

    if check_only {
        println!();
        println!(
            "  {} Run {} to install updates",
            style::dim("→"),
            style::runtime(if aur_only {
                "omg update --aur-only"
            } else {
                "omg update"
            })
        );
        println!();
        return Ok(());
    }

    if !yes && console::user_attended() {
        println!();
        if !tokio::task::spawn_blocking(|| {
            dialoguer::Confirm::with_theme(&ui::prompt_theme())
                .with_prompt("Proceed with upgrade?")
                .default(true)
                .interact()
        })
        .await
        .map_err(|error| anyhow::anyhow!("Confirmation prompt task failed: {error}"))??
        {
            println!();
            println!("  {} Upgrade cancelled", style::caution("✗"));
            println!();
            return Ok(());
        }
    } else if !yes {
        anyhow::bail!("Use --yes for non-interactive updates");
    }

    println!();
    modern_ui::print_section("Installing updates");

    let history = crate::core::history::HistoryManager::new()?;
    // The elevated child's store is separate; retain every change for the
    // invoking user's history and rollback, including delegated official work.
    let changes = history_changes(&all_updates);
    let mut installed_count = 0;
    let mut failed_count = 0;

    let operation_result: Result<()> = async {
        if official_count > 0 {
            if needs_deferred_sync {
                // Databases were refreshed before the prompt (or skipped via
                // `--no-sync`). The child only commits the upgrade. `fullupdate`
                // would download every repository again.
                println!(
                    "  {} Upgrading {official_count} official packages...",
                    style::community("→")
                );
                crate::package_managers::arch::run_privileged_operation(
                    "update",
                    &[],
                    &[],
                    || async { Ok(()) },
                )
                .await?;
            } else {
                let pb = modern_ui::modern_spinner(
                    "Upgrading",
                    &format!("{official_count} official packages"),
                );
                pm.update().await?;
                modern_ui::finish_success(&pb, "Upgraded", &format!("{official_count} packages"));
            }
            installed_count += official_count;
        }

        if !aur_packages.is_empty() {
            use crate::package_managers::aur::{BuildJob, ParallelBuilder};
            use std::sync::Arc;

            let client = Arc::new(crate::package_managers::AurClient::new()?);
            let max_concurrent = aur_build_concurrency(
                std::env::var("OMG_AUR_PARALLEL").ok().as_deref(),
                client.build_concurrency(),
            );
            println!();
            if max_concurrent == 1 || aur_packages.len() == 1 {
                println!(
                    "  {} Building {} AUR package{}...",
                    style::community("→"),
                    aur_packages.len(),
                    if aur_packages.len() == 1 { "" } else { "s" }
                );
            } else {
                println!(
                    "  {} Building {} AUR packages in parallel...",
                    style::community("→"),
                    aur_packages.len()
                );
            }
            // AUR updates are reported per installed output, but split packages
            // share one PackageBase checkout and must be built together. Resolve
            // the package-base graph only after confirmation so check-only and
            // cancelled updates do not pay an extra network request.
            let jobs: Vec<BuildJob> = client.build_jobs_for_updates(&aur_packages).await?;
            let builder = ParallelBuilder::new(client, max_concurrent);

            let build_summary = builder.build_packages(jobs).await?;
            installed_count += build_summary.succeeded_output_count();
            failed_count +=
                build_summary.failed_output_count() + build_summary.skipped_output_count();
            for (package_base, error) in build_summary.failures() {
                let error = style::sanitize_terminal_text(&format!("{error:#}"));
                println!(
                    "  {} {}: {error}",
                    style::negative("✗"),
                    style::package(package_base)
                );
            }
            if build_summary.skipped_output_count() > 0 {
                modern_ui::print_warning(&format!(
                    "Skipped {} AUR output(s) after prerequisite failures: {}",
                    build_summary.skipped_output_count(),
                    build_summary.skipped_outputs().join(", ")
                ));
            }
        }

        if failed_count > 0 {
            modern_ui::print_warning(&format!(
                "Upgraded {installed_count} packages, {failed_count} failed"
            ));
            anyhow::bail!("{failed_count} package(s) failed to update");
        }
        if installed_count > 0 {
            modern_ui::print_success(&format!("Upgraded {installed_count} packages"));
        } else {
            modern_ui::print_up_to_date();
        }
        Ok(())
    }
    .await;

    crate::core::usage::track_update_result(installed_count, operation_result.is_ok());
    history.finish_operation(
        crate::core::history::TransactionType::Update,
        changes,
        operation_result,
    )
}

fn update_dry_run(updates: &[UpdateInfo]) {
    modern_ui::print_phase_header("", "Update", "dry run");
    modern_ui::print_update_summary(updates);
    ui::print_dry_run_footer();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update_info(name: &str, repo: &str) -> UpdateInfo {
        UpdateInfo {
            name: name.to_string(),
            old_version: "1.0".to_string(),
            new_version: "2.0".to_string(),
            repo: repo.to_string(),
        }
    }

    #[test]
    fn delegated_official_updates_remain_in_the_parent_history() -> Result<()> {
        // The elevated child now writes a separate store, so its record cannot
        // replace the parent entry used by unprivileged history and rollback.
        let all = vec![
            update_info("linux", "core"),
            update_info("firefox", "extra"),
            update_info("paru", "aur"),
        ];
        let recorded = history_changes(&all);
        let expected =
            [("linux", "core"), ("firefox", "extra"), ("paru", "aur")].map(|(name, source)| {
                crate::core::history::PackageChange {
                    name: name.to_string(),
                    old_version: Some("1.0".to_string()),
                    new_version: Some("2.0".to_string()),
                    source: source.to_string(),
                }
            });
        assert_eq!(recorded, expected);

        assert_eq!(
            recorded
                .iter()
                .map(|change| change.name.as_str())
                .collect::<Vec<_>>(),
            ["linux", "firefox", "paru"],
            "delegation must not remove official changes from the parent store"
        );
        let directory = tempfile::tempdir()?;
        let parent = crate::core::history::HistoryManager::new_in(
            directory.path().join("user/history.json"),
        )?;
        let child = crate::core::history::HistoryManager::new_in(
            directory.path().join("root/history.json"),
        )?;
        child.add_transaction(
            crate::core::history::TransactionType::Update,
            history_changes(&all[..2]),
            true,
        )?;
        parent.add_transaction(
            crate::core::history::TransactionType::Update,
            recorded,
            true,
        )?;
        let parent_history = parent.load()?;
        assert_eq!(parent_history.len(), 1);
        assert_eq!(parent_history[0].changes, expected);
        let child_history = child.load()?;
        assert_eq!(child_history.len(), 1);
        assert_eq!(child_history[0].changes, expected[..2]);
        Ok(())
    }

    #[test]
    fn non_delegated_updates_record_every_change_once() {
        let all = vec![update_info("linux", "core"), update_info("paru", "aur")];
        let recorded = history_changes(&all);

        let expected = [("linux", "core"), ("paru", "aur")].map(|(name, source)| {
            crate::core::history::PackageChange {
                name: name.to_string(),
                old_version: Some("1.0".to_string()),
                new_version: Some("2.0".to_string()),
                source: source.to_string(),
            }
        });
        assert_eq!(recorded, expected);
    }

    #[test]
    fn update_phase_context_keeps_check_wording() {
        assert_eq!(
            update_phase_context(false, false, false, false),
            "Refreshing catalogs"
        );
        assert_eq!(
            update_phase_context(false, false, true, false),
            "Checking for updates · cached"
        );
        assert_eq!(
            update_phase_context(false, true, false, false),
            "Dry run · checking for updates"
        );
        assert_eq!(
            update_phase_context(true, false, false, false),
            "Checking for updates · cached"
        );
        assert_eq!(update_phase_context(false, false, false, true), "AUR only");
        assert_eq!(
            update_phase_context(false, true, false, true),
            "Dry run · AUR only"
        );
    }

    #[test]
    fn previews_and_checks_never_refresh_package_databases() {
        assert!(should_sync(false, false, false));
        assert!(!should_sync(false, false, true));
        assert!(!should_sync(false, true, false));
        assert!(!should_sync(true, false, false));
    }

    #[test]
    fn aur_only_excludes_every_official_update_entry_point() {
        assert!(!includes_official_updates(true));
        assert!(!should_sync_official_databases(false, false, false, true));
        assert!(!should_sync_official_databases(true, false, false, true));

        assert!(includes_official_updates(false));
        assert!(should_sync_official_databases(false, false, false, false));
        assert!(!should_sync_official_databases(true, false, false, false));
        assert!(!should_sync_official_databases(false, true, false, false));
        assert!(!should_sync_official_databases(false, false, true, false));
    }

    #[test]
    fn aur_only_transaction_guard_rejects_official_packages() {
        let aur = update_info("paru", "AUR");
        enforce_selected_update_scope(true, 0, std::slice::from_ref(&aur))
            .expect("AUR-only selection must accept AUR packages");

        let official = update_info("linux", "core");
        assert!(enforce_selected_update_scope(true, 1, &[aur, official]).is_err());
        assert!(enforce_selected_update_scope(true, 1, &[]).is_err());
        enforce_selected_update_scope(false, 1, &[])
            .expect("full updates may contain official packages");
    }

    #[test]
    fn aur_parallel_unset_uses_default() {
        assert_eq!(aur_build_concurrency(None, 5), 5);
        assert_eq!(aur_build_concurrency(None, 0), 1);
    }

    #[test]
    fn aur_parallel_in_range_is_honored() {
        assert_eq!(aur_build_concurrency(Some("4"), 6), 4);
        assert_eq!(aur_build_concurrency(Some("1"), 6), 1);
        assert_eq!(aur_build_concurrency(Some("8"), 6), 8);
    }

    #[test]
    fn aur_parallel_out_of_range_is_clamped() {
        assert_eq!(aur_build_concurrency(Some("0"), 5), 1);
        assert_eq!(aur_build_concurrency(Some("1000000"), 5), 8);
    }

    #[test]
    fn aur_parallel_invalid_falls_back_to_default() {
        assert_eq!(aur_build_concurrency(Some("abc"), 5), 5);
        assert_eq!(aur_build_concurrency(Some(""), 5), 5);
        assert_eq!(aur_build_concurrency(Some("-2"), 5), 5);
    }

    #[test]
    fn update_history_preserves_versions_and_sources() {
        let changes = history_changes(&[UpdateInfo {
            name: "example".to_string(),
            old_version: "1.0".to_string(),
            new_version: "2.0".to_string(),
            repo: "core".to_string(),
        }]);

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].name, "example");
        assert_eq!(changes[0].old_version.as_deref(), Some("1.0"));
        assert_eq!(changes[0].new_version.as_deref(), Some("2.0"));
        assert_eq!(changes[0].source, "core");
    }

    fn aur_update(name: &str) -> (String, Version, Version) {
        (
            name.to_string(),
            crate::package_managers::parse_version_or_zero("1.0-1"),
            crate::package_managers::parse_version_or_zero("2.0-1"),
        )
    }

    #[test]
    fn banned_package_is_skipped_while_other_candidates_still_update() {
        let policy = SecurityPolicy {
            banned_packages: vec!["evil".to_string()],
            ..SecurityPolicy::default()
        };

        let ScreenedAurUpdates { allowed, skipped } = screen_aur_updates_against_policy(
            &policy,
            vec![aur_update("evil"), aur_update("good")],
        );

        assert_eq!(
            allowed
                .iter()
                .map(|(name, old, new)| (name.as_str(), old.to_string(), new.to_string()))
                .collect::<Vec<_>>(),
            [("good", "1.0-1".to_string(), "2.0-1".to_string())],
            "only the banned candidate may be skipped"
        );
        assert_eq!(
            skipped
                .iter()
                .map(|(name, violation)| (name.as_str(), violation.to_string()))
                .collect::<Vec<_>>(),
            [(
                "evil",
                "Package 'evil' is banned by security policy".to_string()
            )],
            "the skip report must name the violated policy rule"
        );
    }

    #[test]
    fn allow_aur_false_blocks_every_aur_candidate() {
        let policy = SecurityPolicy {
            allow_aur: false,
            ..SecurityPolicy::default()
        };

        let ScreenedAurUpdates { allowed, skipped } =
            screen_aur_updates_against_policy(&policy, vec![aur_update("paru"), aur_update("yay")]);

        assert!(allowed.is_empty(), "no AUR candidate may survive");
        assert_eq!(
            skipped
                .iter()
                .map(|(name, violation)| (name.as_str(), violation.to_string()))
                .collect::<Vec<_>>(),
            [
                (
                    "paru",
                    "Package 'paru' is from AUR, which is disabled by security policy".to_string()
                ),
                (
                    "yay",
                    "Package 'yay' is from AUR, which is disabled by security policy".to_string()
                ),
            ]
        );
    }

    #[test]
    fn missing_policy_file_leaves_aur_updates_unscreened() {
        let temp = tempfile::TempDir::new().expect("temporary directory");
        // Same fallback path as load_default: an absent policy.toml resolves
        // to the built-in defaults, so the update lane must behave exactly as
        // it did before enforcement existed.
        let policy = SecurityPolicy::load_optional(temp.path().join("policy.toml"))
            .expect("a missing policy file must fall back to the built-in defaults");

        let ScreenedAurUpdates { allowed, skipped } =
            screen_aur_updates_against_policy(&policy, vec![aur_update("paru"), aur_update("yay")]);

        assert_eq!(
            allowed
                .iter()
                .map(|(name, old, new)| (name.as_str(), old.to_string(), new.to_string()))
                .collect::<Vec<_>>(),
            [
                ("paru", "1.0-1".to_string(), "2.0-1".to_string()),
                ("yay", "1.0-1".to_string(), "2.0-1".to_string()),
            ],
            "no policy file means no enforcement and zero behavior change"
        );
        assert!(skipped.is_empty());
    }
}
