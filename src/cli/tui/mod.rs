use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{
        Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode,
        enable_raw_mode,
    },
};
use futures::FutureExt;
use ratatui::{Terminal, backend::CrosstermBackend};
use std::future::Future;
use std::io;
use std::time::{Duration, Instant};

pub mod app;
mod ui;

// Constants for TUI behavior
const POLL_TIMEOUT_MS: u64 = 100;
const REFRESH_INTERVAL_SECS: u64 = 5;
const TEAM_REFRESH_INTERVAL_SECS: u64 = 5 * 60;
/// Minimum idle time after the last keystroke before a search is dispatched,
/// so typing does not fire one daemon/apt query per character.
const SEARCH_DEBOUNCE_MS: u64 = 250;

/// Outcome of a background action: `(label, Ok(summary-or-empty))`.
type ActionResult = (&'static str, anyhow::Result<String>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SearchRequestId(u64);

struct SearchCompletion {
    request_id: SearchRequestId,
    result: Result<Vec<crate::package_managers::SyncPackage>, String>,
}

enum SearchRequest {
    Running {
        request_id: SearchRequestId,
        task: tokio::task::JoinHandle<()>,
    },
    Completed {
        request_id: SearchRequestId,
    },
}

impl SearchRequest {
    const fn request_id(&self) -> SearchRequestId {
        match self {
            Self::Running { request_id, .. } | Self::Completed { request_id } => *request_id,
        }
    }
}

fn should_quit(key: KeyEvent, search_mode: bool) -> bool {
    (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
        || (key.code == KeyCode::Char('q') && key.modifiers.is_empty() && !search_mode)
}

fn should_dispatch_key(key: KeyEvent) -> bool {
    !key.modifiers.contains(KeyModifiers::CONTROL)
}

fn should_refresh_daemon(in_flight: bool, elapsed: Duration) -> bool {
    !in_flight && elapsed >= Duration::from_secs(REFRESH_INTERVAL_SECS)
}

fn should_refresh_team(tab: app::Tab, in_flight: bool, elapsed: Duration) -> bool {
    tab == app::Tab::Team
        && !in_flight
        && elapsed >= Duration::from_secs(TEAM_REFRESH_INTERVAL_SECS)
}

fn shows_package_history(tab: app::Tab) -> bool {
    matches!(tab, app::Tab::Dashboard | app::Tab::Activity)
}

fn search_session_started(was_search_mode: bool, search_mode: bool) -> bool {
    !was_search_mode && search_mode
}

fn search_needs_dispatch(
    query: &str,
    last_search: &str,
    active_request_id: Option<SearchRequestId>,
) -> bool {
    !query.is_empty() && (query != last_search || active_request_id.is_none())
}

pub async fn run() -> Result<()> {
    let app = app::App::new()?;
    run_tui_with_app(app).await
}

pub async fn run_with_tab(tab: app::Tab) -> Result<()> {
    let app = app::App::new_for_tab(tab)?;
    run_tui_with_app(app).await
}

/// Centralized TUI setup and teardown to avoid code duplication
async fn run_tui_with_app(mut app: app::App) -> Result<()> {
    anyhow::ensure!(
        console::user_attended(),
        "Interactive dashboard requires an interactive terminal"
    );

    // Setup terminal. Every fallible step must restore previously-acquired
    // terminal state on failure, or the user's shell is left in raw mode.
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    if let Err(err) = execute!(stdout, EnterAlternateScreen) {
        disable_raw_mode()?;
        return Err(err.into());
    }

    let terminal = match Terminal::new(CrosstermBackend::new(stdout))
        .and_then(|mut terminal| terminal.hide_cursor().map(|()| terminal))
    {
        Ok(terminal) => terminal,
        Err(err) => {
            disable_raw_mode()?;
            execute!(io::stdout(), LeaveAlternateScreen)?;
            return Err(err.into());
        }
    };
    let mut terminal = terminal;

    // Catch panics from the event loop so raw mode and the alternate screen
    // are restored before the panic resumes.
    let app_result = std::panic::AssertUnwindSafe(run_app(&mut terminal, &mut app))
        .catch_unwind()
        .await;
    let cleanup_result = cleanup_terminal(&mut terminal);

    match app_result {
        Ok(result) => result.and(cleanup_result),
        Err(payload) => {
            if let Err(error) = cleanup_result {
                tracing::error!("Failed to restore terminal after TUI panic: {error}");
            }
            std::panic::resume_unwind(payload)
        }
    }
}

/// Cleanup terminal state - extracted to ensure consistent cleanup
fn cleanup_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn suspend_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn resume_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    enable_raw_mode()?;
    redraw_alternate_screen(terminal)
}

fn redraw_alternate_screen(
    terminal: &mut Terminal<CrosstermBackend<impl io::Write>>,
) -> Result<()> {
    execute!(
        terminal.backend_mut(),
        EnterAlternateScreen,
        Clear(ClearType::All)
    )?;
    terminal.hide_cursor()?;
    // Reset both draw buffers to match the cleared alternate screen.
    terminal.current_buffer_mut().reset();
    terminal.swap_buffers();
    Ok(())
}

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut app::App,
) -> Result<()> {
    let (poll_input, input_requests) = std::sync::mpsc::sync_channel::<()>(1);
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(1);
    // Poll and read on one thread. Between requests, package actions own the terminal.
    std::thread::Builder::new()
        .name("omg-terminal-input".to_owned())
        .spawn(move || {
            while input_requests.recv().is_ok() {
                let event = event::poll(Duration::from_millis(POLL_TIMEOUT_MS)).and_then(|ready| {
                    if ready {
                        event::read().map(Some)
                    } else {
                        Ok(None)
                    }
                });
                let _ = event_tx.blocking_send(event);
            }
        })?;
    let mut last_search = String::new();
    let mut next_search_id = 0;
    let mut search_request = None;
    let (action_tx, mut action_rx) = tokio::sync::mpsc::unbounded_channel::<ActionResult>();
    let (search_tx, mut search_rx) = tokio::sync::mpsc::unbounded_channel::<SearchCompletion>();
    let (team_tx, mut team_rx) =
        tokio::sync::mpsc::unbounded_channel::<Option<crate::core::env::team::TeamStatus>>();
    let mut history_refresh = None;
    let mut history_refresh_requested = app.external_refresh_enabled;
    #[cfg(unix)]
    let (daemon_tx, mut daemon_rx) = tokio::sync::mpsc::unbounded_channel::<(
        bool,
        Option<crate::daemon::protocol::StatusResult>,
    )>();
    #[cfg(unix)]
    let mut daemon_refresh_in_flight = false;
    #[cfg(unix)]
    let mut last_daemon_refresh = Instant::now()
        .checked_sub(Duration::from_secs(REFRESH_INTERVAL_SECS))
        .unwrap_or_else(Instant::now);
    let mut team_refresh_in_flight = false;
    let mut last_team_refresh = Instant::now()
        .checked_sub(Duration::from_secs(TEAM_REFRESH_INTERVAL_SECS))
        .unwrap_or_else(Instant::now);

    loop {
        // Apply completed background actions before drawing. Messages arrive
        // FIFO from a single in-flight action, so state updates stay ordered
        // and never race with the render pass.
        while let Ok((label, result)) = action_rx.try_recv() {
            app.action_in_flight = false;
            report_action_result(app, result, label);
        }
        while let Ok(completion) = search_rx.try_recv() {
            let completed_request_id = completion.request_id;
            if apply_search_completion(
                app,
                search_request.as_ref().map(SearchRequest::request_id),
                completion,
            ) {
                search_request = Some(SearchRequest::Completed {
                    request_id: completed_request_id,
                });
            }
        }
        #[cfg(unix)]
        while let Ok((connected, status)) = daemon_rx.try_recv() {
            daemon_refresh_in_flight = false;
            app.apply_daemon_status(connected, status);
        }
        while let Ok(remote_status) = team_rx.try_recv() {
            team_refresh_in_flight = false;
            if let Some(status) = remote_status
                && (app.team_status.is_none() || app.team_status_is_remote)
            {
                app.team_status = Some(status);
                app.team_status_is_remote = true;
            }
        }

        if history_refresh
            .as_ref()
            .is_some_and(std::thread::JoinHandle::is_finished)
            && let Some(task) = history_refresh.take()
            && let Ok(Ok(history)) = task.join()
        {
            app.history = history;
            app.history_loaded = true;
        }
        if history_refresh_requested
            && history_refresh.is_none()
            && shows_package_history(app.current_tab)
        {
            history_refresh_requested = false;
            // Dropping this thread's handle lets the terminal exit even if a
            // package transaction still holds the history lock.
            history_refresh = std::thread::Builder::new()
                .name("omg-history".to_owned())
                .spawn(app::App::read_recent_history)
                .ok();
        }

        // Draw UI
        terminal.draw(|f| ui::draw(f, app))?;

        // Handle events with timeout for animations
        let was_search_mode = app.search_mode;
        let previous_tab = app.current_tab;
        poll_input.send(())?;
        let event = event_rx
            .recv()
            .await
            .context("Terminal input worker stopped")??;
        if let Some(Event::Key(key)) = event {
            // Only process key press events, ignore release
            if key.kind == KeyEventKind::Press {
                if should_quit(key, app.search_mode) {
                    return Ok(());
                }
                // Control-modified characters must never fall through to a
                // destructive single-key action or become search text.
                if !should_dispatch_key(key) {
                    continue;
                }

                // While typing a query, global shortcuts must not fire AND
                // every key must reach App::handle_key's search-input block.
                // handle_special_key_actions is where normal keys are routed
                // to handle_key via its catch-all, so skipping it during a
                // query would freeze all input (audit sec2 F-09).
                let terminal_action = if app.search_mode {
                    app.handle_key(key.code);
                    None
                } else {
                    handle_special_key_actions(app, key.code, &action_tx)
                };

                if search_session_started(was_search_mode, app.search_mode) {
                    last_search.clear();
                    cancel_search(&mut search_request);
                } else if was_search_mode && !app.search_mode && app.search_query.is_empty() {
                    cancel_search(&mut search_request);
                }
                if app.search_mode && app.search_query != last_search {
                    cancel_search(&mut search_request);
                }

                // A query committed with Enter before the debounce elapsed
                // must be fetched immediately so the shown results match the
                // final query. (Esc clears the query, so a cancelled search
                // can never satisfy this condition.)
                let committed = was_search_mode
                    && !app.search_mode
                    && search_needs_dispatch(
                        &app.search_query,
                        &last_search,
                        search_request.as_ref().map(SearchRequest::request_id),
                    );
                if committed {
                    last_search.clone_from(&app.search_query);
                    search_request = Some(dispatch_search(
                        app,
                        &last_search,
                        &search_tx,
                        &mut next_search_id,
                    ));
                }
                if let Some(action) = terminal_action {
                    run_terminal_action(terminal, app, action).await?;
                }
            }
        }

        // Debounce: once typing has paused, fetch even without another key
        // event. This must run on every loop iteration — inside the key-event
        // branch it would never fire after the final keystroke.
        if app.search_mode
            && search_needs_dispatch(
                &app.search_query,
                &last_search,
                search_request.as_ref().map(SearchRequest::request_id),
            )
            && app.last_query_change.elapsed() >= Duration::from_millis(SEARCH_DEBOUNCE_MS)
        {
            last_search.clone_from(&app.search_query);
            search_request = Some(dispatch_search(
                app,
                &last_search,
                &search_tx,
                &mut next_search_id,
            ));
        }

        // Update app state
        let last_refresh = app.last_tick;
        app.tick()?;
        history_refresh_requested |= app.external_refresh_enabled
            && shows_package_history(app.current_tab)
            && (app.last_tick != last_refresh || !shows_package_history(previous_tab));

        #[cfg(unix)]
        if should_refresh_daemon(daemon_refresh_in_flight, last_daemon_refresh.elapsed()) {
            daemon_refresh_in_flight = true;
            last_daemon_refresh = Instant::now();
            let sender = daemon_tx.clone();
            tokio::spawn(async move {
                let status = app::App::fetch_daemon_status().await;
                let _ = sender.send(status);
            });
        }

        if should_refresh_team(
            app.current_tab,
            team_refresh_in_flight,
            last_team_refresh.elapsed(),
        ) {
            team_refresh_in_flight = true;
            last_team_refresh = Instant::now();
            let sender = team_tx.clone();
            tokio::spawn(async move {
                let status = app::App::fetch_remote_team_status().await;
                let _ = sender.send(status);
            });
        }

        tokio::task::yield_now().await;
    }
}

fn dispatch_search(
    app: &mut app::App,
    query: &str,
    sender: &tokio::sync::mpsc::UnboundedSender<SearchCompletion>,
    next_search_id: &mut u64,
) -> SearchRequest {
    app.search_results.clear();
    app.search_error = None;
    app.selected_index = 0;

    *next_search_id = next_search_id.wrapping_add(1);
    let request_id = SearchRequestId(*next_search_id);
    let query = query.to_string();
    let sender = sender.clone();
    let task = tokio::spawn(async move {
        let result = app::App::search_packages(&query)
            .await
            .map_err(|error| crate::cli::style::sanitize_terminal_text(&format!("{error:#}")));
        let _ = sender.send(SearchCompletion { request_id, result });
    });
    SearchRequest::Running { request_id, task }
}

fn cancel_search(search_request: &mut Option<SearchRequest>) {
    if let Some(SearchRequest::Running { task, .. }) = search_request.take() {
        task.abort();
    }
}

fn apply_search_completion(
    app: &mut app::App,
    active_request_id: Option<SearchRequestId>,
    completion: SearchCompletion,
) -> bool {
    if active_request_id != Some(completion.request_id) {
        return false;
    }
    match completion.result {
        Ok(mut packages) => {
            for pkg in &mut packages {
                pkg.name = crate::cli::style::sanitize_terminal_text(&pkg.name);
                pkg.description = crate::cli::style::sanitize_terminal_text(&pkg.description);
            }
            app.search_results = packages;
            app.search_error = None;
        }
        Err(error) => {
            app.search_results.clear();
            app.search_error = Some(error);
        }
    }
    true
}

/// Spawn a long-running package operation on a background task.
///
/// Ordering guarantees: actions are serialized by `App::action_in_flight`
/// (at most one runs at a time), each sends exactly one completion message,
/// and the event loop drains those messages FIFO before the next draw. Model
/// state is therefore only ever mutated from the loop task itself.
fn spawn_action(
    app: &mut app::App,
    label: &'static str,
    action_tx: &tokio::sync::mpsc::UnboundedSender<ActionResult>,
    fut: impl Future<Output = anyhow::Result<String>> + Send + 'static,
) {
    if app.action_in_flight {
        app.action_error = Some("another action is already running".to_string());
        return;
    }
    app.action_in_flight = true;
    let sender = action_tx.clone();
    tokio::spawn(async move {
        let outcome = fut.await;
        let _ = sender.send((label, outcome));
    });
}

fn handle_special_key_actions(
    app: &mut app::App,
    key_code: KeyCode,
    action_tx: &tokio::sync::mpsc::UnboundedSender<ActionResult>,
) -> Option<app::ConfirmationAction> {
    if app.pending_confirmation.is_some() {
        match key_code {
            KeyCode::Enter => return app.take_confirmation(),
            KeyCode::Esc => app.handle_key(KeyCode::Esc),
            _ => {}
        }
        return None;
    }

    match key_code {
        KeyCode::Char('u') if app.current_tab == app::Tab::Dashboard => {
            app.request_confirmation(app::ConfirmationAction::UpdateSystem);
        }
        KeyCode::Char('c') if app.current_tab == app::Tab::Dashboard => {
            app.request_confirmation(app::ConfirmationAction::CleanCache);
        }
        KeyCode::Char('o') if app.current_tab == app::Tab::Dashboard => {
            app.request_confirmation(app::ConfirmationAction::RemoveOrphans);
        }
        KeyCode::Char('a') if app.current_tab == app::Tab::Security => {
            spawn_action(app, "security audit", action_tx, async {
                let vulns = app::App::run_security_audit().await?;
                match vulns {
                    0 => tracing::info!("No vulnerabilities found!"),
                    found => tracing::warn!("Found {found} vulnerabilities"),
                }
                Ok(String::new())
            });
        }
        _ => app.handle_key(key_code),
    }
    None
}

async fn run_terminal_action(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut app::App,
    action: app::ConfirmationAction,
) -> Result<()> {
    app.action_in_flight = true;
    if let Err(error) = suspend_terminal(terminal) {
        app.action_in_flight = false;
        return Err(error);
    }

    let (label, result) = match action {
        app::ConfirmationAction::InstallPackage(package_name) => {
            let result = app::App::install_package(&package_name)
                .await
                .map(|()| format!("installed {package_name}"));
            ("install", result)
        }
        app::ConfirmationAction::UpdateSystem => (
            "update system",
            app::App::update_system().await.map(|()| String::new()),
        ),
        app::ConfirmationAction::CleanCache => (
            "clean cache",
            app::App::clean_cache().await.map(|()| String::new()),
        ),
        app::ConfirmationAction::RemoveOrphans => (
            "remove orphans",
            app::App::remove_orphans().await.map(|()| String::new()),
        ),
    };

    let resume_result = resume_terminal(terminal);
    app.action_in_flight = false;
    report_action_result(app, result, label);
    force_refresh(app);
    resume_result
}

fn report_action_result(app: &mut app::App, result: anyhow::Result<String>, action: &str) {
    match result {
        Ok(summary) => {
            app.action_error = None;
            if !summary.is_empty() {
                tracing::info!("{action}: {summary}");
            }
        }
        Err(e) => {
            tracing::error!("Failed to {action}: {e}");
            app.action_error = Some(format!("{action} failed: {e}"));
        }
    }
}

/// Force a refresh by setting `last_tick` to a past time
fn force_refresh(app: &mut app::App) {
    app.last_tick = std::time::Instant::now()
        .checked_sub(Duration::from_secs(REFRESH_INTERVAL_SECS + 1))
        .unwrap_or_else(std::time::Instant::now);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn failed_alternate_screen_write_preserves_the_dashboard_buffer() -> Result<()> {
        let backend = CrosstermBackend::new(io::Cursor::new(&mut [][..]));
        let options = ratatui::TerminalOptions {
            viewport: ratatui::Viewport::Fixed(ratatui::layout::Rect::new(0, 0, 1, 1)),
        };
        let mut terminal = Terminal::with_options(backend, options)?;
        terminal.current_buffer_mut()[(0, 0)].set_symbol("x");

        let error = redraw_alternate_screen(&mut terminal).unwrap_err();

        assert_eq!(
            error.downcast::<io::Error>()?.kind(),
            io::ErrorKind::WriteZero
        );
        assert_eq!(terminal.current_buffer_mut()[(0, 0)].symbol(), "x");
        Ok(())
    }

    #[test]
    fn daemon_refresh_runs_in_background_only_when_due() {
        let due = Duration::from_secs(REFRESH_INTERVAL_SECS);

        assert!(should_refresh_daemon(false, due));
        assert!(!should_refresh_daemon(true, due));
        assert!(!should_refresh_daemon(
            false,
            due.checked_sub(Duration::from_millis(1))
                .expect("test duration remains positive")
        ));
    }

    #[test]
    fn team_refresh_runs_in_background_only_when_visible_and_due() {
        let due = Duration::from_secs(TEAM_REFRESH_INTERVAL_SECS);

        assert!(should_refresh_team(app::Tab::Team, false, due));
        assert!(!should_refresh_team(app::Tab::Dashboard, false, due));
        assert!(!should_refresh_team(app::Tab::Team, true, due));
        assert!(!should_refresh_team(
            app::Tab::Team,
            false,
            due.checked_sub(Duration::from_secs(1))
                .expect("test duration remains positive")
        ));
    }

    #[test]
    fn entering_search_mode_invalidates_the_previous_dispatch_key() {
        assert!(search_session_started(false, true));
        assert!(!search_session_started(true, true));
        assert!(!search_session_started(true, false));
    }

    #[test]
    fn inactive_query_is_dispatched_even_when_its_text_matches_the_last_search() {
        assert!(search_needs_dispatch("firefox", "firefox", None));
        assert!(!search_needs_dispatch(
            "firefox",
            "firefox",
            Some(SearchRequestId(1))
        ));
    }

    #[test]
    fn completed_search_suppresses_duplicate_dispatch() {
        let request = SearchRequest::Completed {
            request_id: SearchRequestId(1),
        };

        assert!(!search_needs_dispatch(
            "firefox",
            "firefox",
            Some(request.request_id())
        ));
    }

    #[tokio::test]
    async fn dispatch_clears_results_that_are_no_longer_current() {
        let mut app = app::App::new_detached();
        app.search_results
            .push(crate::package_managers::SyncPackage {
                name: "stale".to_string(),
                version: crate::package_managers::parse_version_or_zero("1"),
                description: "stale result".to_string(),
                repo: "official".to_string(),
                download_size: 0,
                installed: false,
            });
        app.search_error = Some("stale error".to_string());
        app.selected_index = 3;
        let (sender, _receiver) = tokio::sync::mpsc::unbounded_channel();
        let mut next_search_id = 0;

        let mut active_search = Some(dispatch_search(&mut app, "", &sender, &mut next_search_id));
        cancel_search(&mut active_search);

        assert!(app.search_results.is_empty());
        assert!(app.search_error.is_none());
        assert_eq!(app.selected_index, 0);
    }

    #[tokio::test]
    async fn cancelling_search_aborts_its_task() {
        let task = tokio::spawn(std::future::pending());
        let abort_handle = task.abort_handle();
        let mut active_search = Some(SearchRequest::Running {
            request_id: SearchRequestId(1),
            task,
        });

        cancel_search(&mut active_search);
        tokio::task::yield_now().await;

        assert!(active_search.is_none());
        assert!(abort_handle.is_finished());
    }

    #[test]
    fn stale_search_completion_cannot_replace_current_results() {
        let mut app = app::App::new_detached();
        app.search_error = Some("current result".to_string());
        let completion = SearchCompletion {
            request_id: SearchRequestId(1),
            result: Ok(Vec::new()),
        };

        assert!(!apply_search_completion(
            &mut app,
            Some(SearchRequestId(2)),
            completion
        ));
        assert_eq!(app.search_error.as_deref(), Some("current result"));
    }

    #[test]
    fn current_search_completion_is_applied() {
        let mut app = app::App::new_detached();
        let completion = SearchCompletion {
            request_id: SearchRequestId(2),
            result: Err("search unavailable".to_string()),
        };

        assert!(apply_search_completion(
            &mut app,
            Some(SearchRequestId(2)),
            completion
        ));
        assert_eq!(app.search_error.as_deref(), Some("search unavailable"));
    }

    #[test]
    fn mutation_shortcuts_require_confirmation_before_dispatch() {
        let (sender, _receiver) = tokio::sync::mpsc::unbounded_channel();

        for (key, expected) in [
            (KeyCode::Char('u'), app::ConfirmationAction::UpdateSystem),
            (KeyCode::Char('c'), app::ConfirmationAction::CleanCache),
            (KeyCode::Char('o'), app::ConfirmationAction::RemoveOrphans),
        ] {
            let mut app = app::App::new_detached();
            assert_eq!(handle_special_key_actions(&mut app, key, &sender), None);
            assert_eq!(app.pending_confirmation, Some(expected.clone()));
            assert_eq!(
                handle_special_key_actions(&mut app, KeyCode::Enter, &sender),
                Some(expected)
            );
            assert!(app.pending_confirmation.is_none());
        }
    }

    #[test]
    fn control_c_quits_instead_of_dispatching_a_dashboard_action() {
        let interrupt = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        let update = KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL);

        assert!(should_quit(interrupt, false));
        assert!(should_quit(interrupt, true));
        assert!(!should_dispatch_key(update));
    }
}
