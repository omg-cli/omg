use anyhow::{Context as _, Result};
use crossterm::{
    event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{
        Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode,
        enable_raw_mode,
    },
};
use futures::StreamExt;
use ratatui::{Terminal, backend::CrosstermBackend};
use std::future::Future;
use std::io;
use std::time::{Duration, Instant};
use tokio_util::task::AbortOnDropHandle;

pub mod app;
mod ui;

// Constants for TUI behavior
const TICK_INTERVAL_MS: u64 = 100;
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

enum BackgroundUpdate {
    Action(ActionResult),
    Search(SearchCompletion),
    Team(Option<crate::core::env::team::TeamStatus>),
    #[cfg(unix)]
    Daemon(bool, Option<crate::daemon::protocol::StatusResult>),
}

enum SearchRequest {
    Running {
        request_id: SearchRequestId,
        _task: AbortOnDropHandle<()>,
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
    let app = app::App::new()?.with_tab(tab);
    run_tui_with_app(app).await
}

/// Centralized TUI setup and teardown to avoid code duplication
async fn run_tui_with_app(mut app: app::App) -> Result<()> {
    anyhow::ensure!(
        console::user_attended(),
        "Interactive dashboard requires an interactive terminal"
    );

    let mut session = TerminalSession::new().context("Failed to enter dashboard terminal")?;
    let result = run_app(&mut session, &mut app).await;
    let restoration = session
        .restore()
        .context("Failed to restore dashboard terminal");
    result.and(restoration)
}

struct TerminalSession {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    active: bool,
}

impl TerminalSession {
    fn new() -> io::Result<Self> {
        let mut session = Self {
            terminal: Terminal::new(CrosstermBackend::new(io::stdout()))?,
            active: false,
        };
        session.enter()?;
        Ok(session)
    }

    fn enter(&mut self) -> io::Result<()> {
        enable_raw_mode()?;
        self.active = true;
        execute!(
            self.terminal.backend_mut(),
            EnterAlternateScreen,
            Clear(ClearType::All)
        )?;
        self.terminal.hide_cursor()
    }

    fn restore(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }

        // Try each restoration even if one fails. Output to the primary
        // screen is limited to restoring the cursor.
        let raw = disable_raw_mode();
        let screen = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let cursor = self.terminal.show_cursor();
        let result = raw.and(screen).and(cursor);
        self.active = result.is_err();
        result
    }

    fn resume(&mut self) -> io::Result<()> {
        // The resumed alternate screen needs fresh drawing buffers.
        self.terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
        self.enter()
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            tracing::error!("Failed to restore dashboard terminal: {error}");
        }
    }
}

async fn run_app(session: &mut TerminalSession, app: &mut app::App) -> Result<()> {
    let mut last_search = String::new();
    let mut next_search_id = 0;
    let mut search_request = None;
    let (background_tx, mut background_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut events = EventStream::new();
    #[cfg(unix)]
    let mut daemon_refresh = None;
    #[cfg(unix)]
    let mut last_daemon_refresh = Instant::now()
        .checked_sub(Duration::from_secs(REFRESH_INTERVAL_SECS))
        .unwrap_or_else(Instant::now);
    let mut team_refresh = None;
    let mut last_team_refresh = Instant::now()
        .checked_sub(Duration::from_secs(TEAM_REFRESH_INTERVAL_SECS))
        .unwrap_or_else(Instant::now);

    loop {
        session.terminal.draw(|f| ui::draw(f, app))?;

        let input = tokio::select! {
            event = events.next() => Some(event.context("Dashboard input closed")??),
            Some(update) = background_rx.recv() => {
                match update {
                    BackgroundUpdate::Action((label, result)) => {
                        app.action_in_flight = false;
                        report_action_result(app, result, label);
                    }
                    BackgroundUpdate::Search(completion) => {
                        let request_id = completion.request_id;
                        if apply_search_completion(
                            app,
                            search_request.as_ref().map(SearchRequest::request_id),
                            completion,
                        ) {
                            search_request = Some(SearchRequest::Completed { request_id });
                        }
                    }
                    BackgroundUpdate::Team(remote_status) => {
                        team_refresh = None;
                        if let Some(status) = remote_status
                            && (app.team_status.is_none() || app.team_status_is_remote)
                        {
                            app.team_status = Some(status);
                            app.team_status_is_remote = true;
                        }
                    }
                    #[cfg(unix)]
                    BackgroundUpdate::Daemon(connected, status) => {
                        daemon_refresh = None;
                        app.daemon_connected = connected;
                        if let Some(status) = status {
                            app.status = Some(status);
                        }
                    }
                }
                None
            }
            () = tokio::time::sleep(Duration::from_millis(TICK_INTERVAL_MS)) => None,
        };
        let was_search_mode = app.search_mode;
        if let Some(Event::Key(key)) = input {
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
                    handle_special_key_actions(app, key.code, &background_tx)
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
                        &background_tx,
                        &mut next_search_id,
                    ));
                }
                if let Some(action) = terminal_action {
                    run_terminal_action(session, app, action).await?;
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
                &background_tx,
                &mut next_search_id,
            ));
        }

        // Update app state
        app.tick()?;

        #[cfg(unix)]
        if should_refresh_daemon(daemon_refresh.is_some(), last_daemon_refresh.elapsed()) {
            last_daemon_refresh = Instant::now();
            let sender = background_tx.clone();
            daemon_refresh = Some(AbortOnDropHandle::new(tokio::spawn(async move {
                let (connected, status) = app::App::fetch_daemon_status().await;
                let _ = sender.send(BackgroundUpdate::Daemon(connected, status));
            })));
        }

        if should_refresh_team(
            app.current_tab,
            team_refresh.is_some(),
            last_team_refresh.elapsed(),
        ) {
            last_team_refresh = Instant::now();
            let sender = background_tx.clone();
            team_refresh = Some(AbortOnDropHandle::new(tokio::spawn(async move {
                let status = app::App::fetch_remote_team_status().await;
                let _ = sender.send(BackgroundUpdate::Team(status));
            })));
        }
    }
}

fn dispatch_search(
    app: &mut app::App,
    query: &str,
    sender: &tokio::sync::mpsc::UnboundedSender<BackgroundUpdate>,
    next_search_id: &mut u64,
) -> SearchRequest {
    app.search_results.clear();
    app.search_error = None;
    app.selected_index = 0;

    *next_search_id = next_search_id
        .checked_add(1)
        .expect("search request identifier exhausted");
    let request_id = SearchRequestId(*next_search_id);
    let query = query.to_string();
    let sender = sender.clone();
    let task = tokio::spawn(async move {
        let result = app::App::search_packages(&query)
            .await
            .map_err(|error| error.to_string());
        let _ = sender.send(BackgroundUpdate::Search(SearchCompletion {
            request_id,
            result,
        }));
    });
    SearchRequest::Running {
        request_id,
        _task: AbortOnDropHandle::new(task),
    }
}

fn cancel_search(search_request: &mut Option<SearchRequest>) {
    *search_request = None;
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
            tracing::error!("Search failed: {error}");
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
    action_tx: &tokio::sync::mpsc::UnboundedSender<BackgroundUpdate>,
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
        let _ = sender.send(BackgroundUpdate::Action((label, outcome)));
    });
}

fn handle_special_key_actions(
    app: &mut app::App,
    key_code: KeyCode,
    action_tx: &tokio::sync::mpsc::UnboundedSender<BackgroundUpdate>,
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
    session: &mut TerminalSession,
    app: &mut app::App,
    action: app::ConfirmationAction,
) -> Result<()> {
    app.action_in_flight = true;
    if let Err(error) = session.restore() {
        app.action_in_flight = false;
        return Err(error).context("Failed to suspend dashboard terminal");
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

    let resume_result = session
        .resume()
        .context("Failed to resume dashboard terminal");
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
    #[cfg(target_os = "linux")]
    #[test]
    fn idle_dashboard_keeps_the_runtime_responsive() {
        use std::fs::File;
        use std::io::Read;
        use std::process::{Command, Stdio};

        const FIXTURE: &str = "OMG_TUI_IDLE_RUNTIME_FIXTURE";
        if std::env::var_os(FIXTURE).is_some() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("dashboard runtime");
            runtime.block_on(async {
                let ticks = std::cell::Cell::new(0);
                let heartbeat = async {
                    loop {
                        tokio::time::sleep(Duration::from_millis(15)).await;
                        ticks.set(ticks.get() + 1);
                    }
                };
                let limit = tokio::time::timeout(
                    Duration::from_millis(700),
                    run_tui_with_app(app::App::new_detached()),
                );
                tokio::select! {
                    () = heartbeat => unreachable!(),
                    outcome = limit => assert!(outcome.is_err(), "{outcome:?}"),
                }
                assert!(
                    ticks.get() >= 16,
                    "only {} scheduled heartbeats ran",
                    ticks.get()
                );
            });
            return;
        }

        let size = nix::pty::Winsize {
            ws_row: 10,
            ws_col: 58,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let pty = nix::pty::openpty(Some(&size), None).expect("private dashboard terminal");
        for descriptor in [&pty.master, &pty.slave] {
            nix::fcntl::fcntl(
                descriptor,
                nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
            )
            .expect("close private terminal descriptors on exec");
        }
        let timeout = crate::core::privilege::root_controlled_program_path("timeout")
            .expect("trusted timeout utility");
        let setsid = crate::core::privilege::root_controlled_program_path("setsid")
            .expect("trusted terminal fixture launcher");
        let mut master = File::from(pty.master);
        let slave = File::from(pty.slave);
        let capture = std::thread::spawn(move || {
            let mut output = Vec::new();
            let closed = master.read_to_end(&mut output);
            assert_eq!(closed.unwrap_err().raw_os_error(), Some(nix::libc::EIO));
            String::from_utf8_lossy(&output).into_owned()
        });

        let status = Command::new(timeout)
            .args(["--foreground", "--kill-after=1s", "10s"])
            .arg(setsid)
            .args(["--ctty", "--"])
            .arg(std::env::current_exe().expect("dashboard test executable"))
            .args([
                "--exact",
                "cli::tui::tests::idle_dashboard_keeps_the_runtime_responsive",
                "--nocapture",
            ])
            .env(FIXTURE, "1")
            .env("TERM", "xterm-256color")
            .env("OMG_DISABLE_DAEMON", "1")
            .stdin(Stdio::from(slave.try_clone().expect("fixture input")))
            .stdout(Stdio::from(slave.try_clone().expect("fixture output")))
            .stderr(Stdio::from(slave))
            .status()
            .expect("run the dashboard on a private terminal");
        let output = capture
            .join()
            .expect("capture the dashboard terminal output");
        assert!(status.success(), "{output}");
    }

    #[tokio::test]
    async fn dropping_the_dashboard_search_closes_its_in_flight_task() {
        let task = tokio::spawn(std::future::pending());
        let handle = task.abort_handle();
        let search = SearchRequest::Running {
            request_id: SearchRequestId(1),
            _task: AbortOnDropHandle::new(task),
        };

        drop(search);
        tokio::task::yield_now().await;

        let stopped = handle.is_finished();
        handle.abort();
        assert!(stopped, "dashboard exit left a search running");
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
            _task: AbortOnDropHandle::new(task),
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
