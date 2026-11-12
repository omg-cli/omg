/// Setup ALPM callbacks for progress lanes
fn setup_alpm_callbacks(
    alpm: &alpm::Alpm,
    refusals: &Arc<Mutex<AlpmQuestionRefusals>>,
) -> ProgressTask {
    let main_task = ProgressTask::start(&TaskSpec {
        label: "Transaction".to_string(),
        kind: TaskKind::Items { total: 100 },
        accent: Accent::System,
    });

    alpm.set_question_cb(Arc::clone(refusals), |question, refusals| {
        let mut refusals = refusals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match question.question() {
            alpm::Question::InstallIgnorepkg(mut q) => {
                // Pacman installs explicitly requested packages despite
                // IgnorePkg without prompting; keep that answer, logged.
                tracing::warn!(
                    "Installing {} despite IgnorePkg (auto-answered: yes)",
                    q.pkg().name()
                );
                q.set_install(true);
            }
            alpm::Question::Replace(q) => {
                let description = q.oldpkg().name();
                let newdb = q.newdb().name();
                let newpkg = q.newpkg().name();
                let auto_accept = crate::core::privilege::get_yes_flag();
                let confirmed = if auto_accept {
                    true
                } else if console::user_attended() {
                    let _quiesce = crate::cli::modern_ui::quiesce_terminal();
                    dialoguer::Confirm::with_theme(&crate::cli::ui::prompt_theme())
                        .with_prompt(format!("Replace {description} with {newdb}/{newpkg}?"))
                        .default(true)
                        .interact()
                        .unwrap_or(false)
                } else {
                    false
                };

                if confirmed {
                    tracing::info!("Replacing {description} with {newdb}/{newpkg}");
                    q.set_replace(true);
                } else {
                    q.set_replace(false);
                    tracing::error!(
                        "Refusing to replace {description} with {newdb}/{newpkg}: replacing an \
                     installed package requires explicit consent (auto-answered: no)"
                    );
                    refusals.record_refused_replacement(description, newdb, newpkg);
                }
            }
            alpm::Question::Conflict(mut q) => {
                let conflict = q.conflict();
                let pkg1 = conflict.package1().name();
                let pkg2 = conflict.package2().name();
                let reason = conflict.reason().to_string();

                let auto_accept = crate::core::privilege::get_yes_flag();
                let confirmed = if auto_accept {
                    true
                } else if console::user_attended() {
                    let _quiesce = crate::cli::modern_ui::quiesce_terminal();
                    dialoguer::Confirm::with_theme(&crate::cli::ui::prompt_theme())
                        .with_prompt(format!("{pkg1} conflicts with {pkg2} ({reason}). Remove {pkg2}?"))
                        .default(false)
                        .interact()
                        .unwrap_or(false)
                } else {
                    false
                };

                if confirmed {
                    tracing::info!("Removing conflicting package {pkg2} while installing {pkg1}");
                    q.set_remove(true);
                } else {
                    tracing::error!(
                        "Refusing implicit removal of conflicting package {pkg2} while installing {pkg1} ({reason})"
                    );
                    q.set_remove(false);
                }
            }
            alpm::Question::RemovePkgs(mut q) => {
                // Pacman prompts "Do you want to skip the above package(s) for
                // this upgrade? [y/N]"; the interactive default (no) makes libalpm
                // fail with unsatisfied dependencies instead of silently dropping
                // packages from the transaction. Keep that fail-closed answer,
                // logged and surfaced as a clear error.
                let packages: Vec<String> = q
                    .packages()
                    .iter()
                    .map(|package| package.name().to_string())
                    .collect();
                q.set_skip(false);
                tracing::error!(
                    "Refusing to drop unresolvable package(s) {} from the transaction \
                 (auto-answered: no); the transaction will fail with unsatisfied dependencies",
                    packages.join(", ")
                );
                refusals.record_refused_removals(&packages);
            }
            alpm::Question::SelectProvider(mut q) => {
                let providers: Vec<String> = q
                    .providers()
                    .iter()
                    .map(|package| package.name().to_string())
                    .collect();
                if console::user_attended()
                    && !crate::core::privilege::get_yes_flag()
                    && providers.len() > 1
                {
                    let _quiesce = crate::cli::modern_ui::quiesce_terminal();
                    if let Ok(selection) =
                        dialoguer::Select::with_theme(&crate::cli::ui::prompt_theme())
                            .with_prompt(format!("Select a provider for {}", q.depend()))
                            .items(&providers)
                            .default(0)
                            .interact()
                        && let Ok(idx) = i32::try_from(selection)
                    {
                        q.set_index(idx);
                        return;
                    }
                }
                tracing::info!(
                    "{}",
                    provider_selection_message(&providers, &q.depend().to_string())
                );
                q.set_index(0);
            }
            alpm::Question::ImportKey(mut q) => {
                let fingerprint = q.fingerprint();
                let uid = q.uid();
                tracing::info!("PGP key required: {fingerprint} ({uid})");

                let confirmed =
                    if console::user_attended() && !crate::core::privilege::get_yes_flag() {
                        let _quiesce = crate::cli::modern_ui::quiesce_terminal();
                        dialoguer::Confirm::with_theme(&crate::cli::ui::prompt_theme())
                            .with_prompt(format!("Import PGP key {fingerprint} ({uid})?"))
                            .default(false)
                            .interact()
                            .unwrap_or(false)
                    } else {
                        false
                    };

                if confirmed {
                    tracing::info!("Importing PGP key: {fingerprint} ({uid})");
                    q.set_import(true);
                } else {
                    tracing::warn!("PGP key not trusted: {fingerprint} ({uid})");
                    tracing::info!(
                        "Import key manually: pacman-key --recv-keys {fingerprint} && pacman-key --lsign-key {fingerprint}"
                    );
                    q.set_import(false);
                }
            }
            alpm::Question::Corrupted(mut q) => {
                tracing::error!("Corrupted package detected! This may indicate tampering.");
                q.set_remove(false);
            }
        }
    });

    // Progress messages are rendered below, but warnings and errors such as
    // .pacnew/.pacsave notices remain operationally significant.
    alpm.set_log_cb((), |level, message, ()| {
        forward_alpm_log(level, message);
    });

    let main_task_clone = main_task.clone();
    let progress_state = Mutex::new((String::new(), 0_i32));
    let download_lane = Arc::new(Mutex::new(None::<ProgressTask>));
    let download_counts = Arc::new((AtomicU64::new(0), AtomicU64::new(0)));
    let progress_download_lane = Arc::clone(&download_lane);
    alpm.set_progress_cb(progress_state, move |op, name, percent, n, max, state| {
        if is_post_download_progress(op) {
            finish_download_lane(&progress_download_lane);
        }
        if !progress_event_is_due(
            state
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            name,
            percent,
        ) {
            return;
        }
        let verb = match op {
            alpm::Progress::AddStart => "Installing",
            alpm::Progress::UpgradeStart => "Upgrading",
            alpm::Progress::DowngradeStart => "Downgrading",
            alpm::Progress::ReinstallStart => "Reinstalling",
            alpm::Progress::RemoveStart => "Removing",
            alpm::Progress::ConflictsStart => "Conflict check",
            alpm::Progress::DiskspaceStart => "Checking disk space",
            alpm::Progress::IntegrityStart => "Checking integrity",
            alpm::Progress::LoadStart => "Loading",
            alpm::Progress::KeyringStart => "Checking keyring",
        };
        let counts = if max > 0 {
            format!(" ({n}/{max})")
        } else {
            String::new()
        };
        let message = if crate::cli::modern_ui::is_verbose() {
            format!("{verb} {name}{counts}")
        } else {
            format!("{verb}{counts}")
        };
        main_task_clone.set_message(&message);
        main_task_clone.set_position(transaction_overall_percent(percent, n, max));
    });

    let callback_lane = Arc::clone(&download_lane);
    let callback_counts = Arc::clone(&download_counts);
    alpm.set_dl_cb(
        (callback_lane, callback_counts),
        move |_filename, event, (lane, counts)| match event.event() {
            alpm::DownloadEvent::Init(_) => {
                let active = counts.0.fetch_add(1, Ordering::Relaxed) + 1;
                let done = counts.1.load(Ordering::Relaxed);
                let mut lane = lane
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let task = lane.get_or_insert_with(|| {
                    ProgressTask::start(&TaskSpec {
                        label: "Download".to_string(),
                        kind: TaskKind::Spinner,
                        accent: Accent::Network,
                    })
                });
                task.set_message(&download_lane_message(active, done));
            }
            alpm::DownloadEvent::Progress(_) | alpm::DownloadEvent::Retry(_) => {}
            alpm::DownloadEvent::Completed(_) => {
                let active = counts
                    .0
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |active| {
                        Some(active.saturating_sub(1))
                    })
                    .unwrap_or(0)
                    .saturating_sub(1);
                let done = counts.1.fetch_add(1, Ordering::Relaxed) + 1;
                if let Some(task) = lane
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .as_ref()
                {
                    task.set_message(&download_lane_message(active, done));
                }
            }
        },
    );

    main_task
}