use crate::core::env::team::TeamStatus;
use crate::core::history::Transaction;
#[cfg(unix)]
use crate::daemon::protocol::StatusResult;
use anyhow::{Context, Result};
use crossterm::event::KeyCode;
use std::time::Instant;

static DIRECT_SEARCH_GATE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard = 0,
    Packages,
    Runtimes,
    Security,
    Activity,
    Team,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmationAction {
    InstallPackage(String),
    UpdateSystem,
    CleanCache,
    RemoveOrphans,
}

impl ConfirmationAction {
    pub fn title(&self) -> &'static str {
        match self {
            Self::InstallPackage(_) => "󰏗 Install Package",
            Self::UpdateSystem => "󰚰 Update System",
            Self::CleanCache => "󰃢 Clean Package Caches",
            Self::RemoveOrphans => "󰆴 Remove Orphans",
        }
    }

    pub fn prompt(&self) -> String {
        match self {
            Self::InstallPackage(package_name) => format!("Install {package_name}?"),
            Self::UpdateSystem => "Install all available package updates?".to_string(),
            Self::CleanCache => "Remove package caches and orphaned packages?".to_string(),
            Self::RemoveOrphans => "Remove every orphaned package?".to_string(),
        }
    }
}

pub struct App {
    #[cfg(unix)]
    pub status: Option<StatusResult>,
    #[cfg(not(unix))]
    pub status: Option<()>,
    pub team_status: Option<TeamStatus>,
    pub(crate) team_status_is_remote: bool,
    pub history: Vec<Transaction>,
    pub last_tick: Instant,
    pub current_tab: Tab,
    pub selected_index: usize,
    pub pending_confirmation: Option<ConfirmationAction>,
    pub search_query: String,
    pub search_mode: bool,
    pub daemon_connected: bool,

    // Search results
    pub search_results: Vec<crate::package_managers::SyncPackage>,
    pub search_error: Option<String>,
    pub action_error: Option<String>,

    // System metrics
    pub system_metrics: SystemMetrics,

    // Last update time
    pub last_update: Instant,

    // Previous cumulative CPU sample (total, idle) used to compute an
    // instantaneous usage percentage instead of a since-boot average.
    pub prev_cpu_sample: Option<(u64, u64)>,

    // Usage stats
    pub usage_stats: crate::core::usage::UsageStats,

    /// True while a long-running action (update/install/clean/audit) is
    /// executing on a background task. Serializes actions so their results
    /// cannot interleave.
    pub action_in_flight: bool,

    /// Last time the search query was modified; used to debounce searches.
    pub last_query_change: Instant,

    /// Whether refresh may consult daemon, history, workspace, and license API
    /// adapters. Detached apps keep state-machine/render tests hermetic.
    pub(crate) external_refresh_enabled: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SystemMetrics {
    pub cpu_usage: f32,
    pub memory_usage: f32,
    pub disk_usage: u64,
    pub disk_free: u64,
    pub network_rx: u64,
    pub network_tx: u64,
}

impl App {
    fn initial(external_refresh_enabled: bool) -> Self {
        Self {
            status: None,
            team_status: None,
            team_status_is_remote: false,
            history: Vec::new(),
            last_tick: Instant::now(),
            current_tab: Tab::Dashboard,
            selected_index: 0,
            pending_confirmation: None,
            search_query: String::new(),
            search_mode: false,
            daemon_connected: false,
            search_results: Vec::new(),
            search_error: None,
            action_error: None,
            system_metrics: SystemMetrics::default(),
            last_update: Instant::now(),
            prev_cpu_sample: None,
            usage_stats: if external_refresh_enabled {
                crate::core::usage::UsageStats::load().unwrap_or_default()
            } else {
                crate::core::usage::UsageStats::default()
            },
            action_in_flight: false,
            last_query_change: Instant::now(),
            external_refresh_enabled,
        }
    }

    pub fn new() -> Result<Self> {
        let mut app = Self::initial(true);
        app.refresh()?;
        Ok(app)
    }

    /// Construct the TUI state machine without reading host state or making
    /// network/daemon calls. A later explicit [`Self::refresh`] remains local.
    #[must_use]
    pub fn new_detached() -> Self {
        Self::initial(false)
    }

    #[must_use]
    pub fn with_tab(mut self, tab: Tab) -> Self {
        self.current_tab = tab;
        self
    }

    pub fn refresh(&mut self) -> Result<()> {
        if !self.external_refresh_enabled {
            return Ok(());
        }

        // 1. Fetch history. Daemon I/O is scheduled separately by the event
        // loop so its request timeout can never freeze input or rendering.
        if let Ok(history_mgr) = crate::core::history::HistoryManager::new()
            && let Ok(entries) = history_mgr.load()
        {
            self.history = entries.into_iter().rev().take(50).collect();
        }

        // 3. Update system metrics
        self.update_system_metrics();

        // 4. Refresh local team state. Remote member data is fetched by the
        // event loop on a background task only while the Team tab is visible.
        self.load_local_team_status();

        Ok(())
    }

    #[cfg(unix)]
    pub(crate) async fn fetch_daemon_status() -> (bool, Option<StatusResult>) {
        let Ok(mut client) = crate::core::client::DaemonClient::connect().await else {
            return (false, None);
        };
        let status = match client
            .call(crate::daemon::protocol::Request::Status { id: 0 })
            .await
        {
            Ok(crate::daemon::protocol::ResponseResult::Status(status)) => Some(status),
            _ => None,
        };
        (true, status)
    }

    fn load_local_team_status(&mut self) {
        if let Ok(cwd) = std::env::current_dir()
            && let Ok(workspace) = crate::core::env::team::TeamWorkspace::new(&cwd)
            && workspace.is_team_workspace()
            && let Ok(status) = workspace.load_status()
        {
            self.team_status = Some(status);
            self.team_status_is_remote = false;
        }
    }

    pub(crate) async fn fetch_remote_team_status() -> Option<TeamStatus> {
        let license = crate::core::license::load_license()?;
        if !license.is_token_valid() {
            return None;
        }
        let members = crate::core::license::fetch_team_members().await.ok()?;
        Some(crate::core::env::team::TeamStatus {
            format_version: crate::core::env::team::TeamStatus::STATUS_FORMAT_VERSION,
            config: crate::core::env::team::TeamConfig {
                team_id: "fleet".to_string(),
                name: format!("{} Fleet", license.customer.as_deref().unwrap_or("Your")),
                ..Default::default()
            },
            lock_hash: String::new(),
            members: members
                .into_iter()
                .map(|member| crate::core::env::team::TeamMember {
                    id: member.machine_id,
                    name: member.hostname.unwrap_or_else(|| "Unknown".to_string()),
                    env_hash: String::new(),
                    last_sync: crate::cli::parse_timestamp_opt(&member.last_seen_at).unwrap_or(0),
                    in_sync: member.is_active,
                    drift_summary: None,
                })
                .collect(),
            updated_at: jiff::Timestamp::now().as_second(),
        })
    }

    fn update_system_metrics(&mut self) {
        // A single /proc/stat read yields a since-boot average, so CPU usage
        // must be derived from consecutive cumulative samples.
        let cpu_usage = Self::cpu_usage_delta(&mut self.prev_cpu_sample);
        let (disk_usage, disk_free) = Self::get_disk_usage_sync();
        let (network_rx, network_tx) = Self::get_network_stats();

        self.system_metrics = SystemMetrics {
            cpu_usage,
            memory_usage: Self::get_memory_usage(),
            disk_usage,
            disk_free,
            network_rx,
            network_tx,
        };
    }

    /// Read the cumulative `cpu` line of `/proc/stat` as `(total, idle)`.
    fn sample_cpu_totals() -> Option<(u64, u64)> {
        let stat = std::fs::read_to_string("/proc/stat").ok()?;
        let line = stat.lines().next()?;
        let mut fields = line.split_whitespace();
        if fields.next()? != "cpu" {
            return None;
        }

        let mut total = 0u64;
        let mut idle = None;
        for (index, field) in fields.enumerate() {
            let value = field.parse::<u64>().ok()?;
            total = total.checked_add(value)?;
            if index == 3 {
                idle = Some(value);
            }
        }
        Some((total, idle?))
    }

    /// Usage percent since the previous sample; the very first sample only
    /// establishes the baseline and reports the previous reading.
    fn cpu_usage_delta(previous: &mut Option<(u64, u64)>) -> f32 {
        let Some(sample) = Self::sample_cpu_totals() else {
            return 0.0;
        };
        let usage = match *previous {
            Some((prev_total, prev_idle)) => {
                let d_total = sample.0.saturating_sub(prev_total);
                let d_idle = sample.1.saturating_sub(prev_idle);
                if d_total > 0 {
                    (d_total - d_idle) as f32 / d_total as f32 * 100.0
                } else {
                    0.0
                }
            }
            None => 0.0,
        };
        *previous = Some(sample);
        usage
    }

    fn get_memory_usage() -> f32 {
        // Read /proc/meminfo for memory usage
        if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
            let mut total = 0u64;
            let mut available = 0u64;

            for line in meminfo.lines() {
                if line.starts_with("MemTotal:") {
                    if let Some(kb) = line.split_whitespace().nth(1) {
                        total = kb.parse().unwrap_or(0);
                    }
                } else if line.starts_with("MemAvailable:")
                    && let Some(kb) = line.split_whitespace().nth(1)
                {
                    available = kb.parse().unwrap_or(0);
                }
            }

            if total > 0 {
                return (total.saturating_sub(available) as f32 / total as f32) * 100.0;
            }
        }
        0.0
    }

    fn get_disk_usage_sync() -> (u64, u64) {
        #[cfg(unix)]
        {
            // Use rustix for safe statvfs
            if let Ok(stat) = rustix::fs::statvfs("/") {
                let block_size = stat.f_frsize;
                let total_blocks = stat.f_blocks;
                let free_blocks = stat.f_bfree;
                let used = total_blocks.saturating_sub(free_blocks) * block_size / 1024; // KB
                let free = free_blocks * block_size / 1024; // KB
                return (used, free);
            }
        }
        (0, 0)
    }

    fn get_network_stats() -> (u64, u64) {
        // Read /proc/net/dev for network stats
        if let Ok(netdev) = std::fs::read_to_string("/proc/net/dev") {
            let mut total_rx = 0u64;
            let mut total_tx = 0u64;

            for line in netdev.lines().skip(2) {
                let mut fields = line.split_whitespace();
                let Some(interface) = fields.next() else {
                    continue;
                };
                if interface.starts_with("lo") {
                    continue;
                }
                let (Some(rx), Some(tx)) = (fields.next(), fields.nth(7)) else {
                    continue;
                };
                if let (Ok(rx), Ok(tx)) = (rx.parse::<u64>(), tx.parse::<u64>()) {
                    total_rx = total_rx.saturating_add(rx);
                    total_tx = total_tx.saturating_add(tx);
                }
            }

            return (total_rx, total_tx);
        }
        (0, 0)
    }

    pub async fn search_packages(query: &str) -> Result<Vec<crate::package_managers::SyncPackage>> {
        if query.is_empty() {
            return Ok(Vec::new());
        }

        #[cfg(unix)]
        if let Ok(mut client) = crate::core::client::DaemonClient::connect().await
            && let Ok(crate::daemon::protocol::ResponseResult::Search(res)) = client
                .call(crate::daemon::protocol::Request::Search {
                    id: 0,
                    query: query.to_string(),
                    limit: Some(50),
                })
                .await
        {
            return Ok(res
                .packages
                .into_iter()
                .map(|package| crate::package_managers::SyncPackage {
                    name: package.name,
                    version: crate::package_managers::parse_version_or_zero(&package.version),
                    description: package.description,
                    repo: "official".to_string(),
                    download_size: 0,
                    installed: false,
                })
                .collect());
        }

        let permit = DIRECT_SEARCH_GATE
            .acquire()
            .await
            .context("direct search gate closed")?;
        let query = query.to_string();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            Self::search_packages_direct(&query)
        })
        .await
        .context("package search worker failed")?
    }

    fn search_packages_direct(query: &str) -> Result<Vec<crate::package_managers::SyncPackage>> {
        #[cfg(not(any(feature = "arch", feature = "debian", feature = "debian-pure")))]
        let _ = query;

        #[cfg(any(feature = "debian", feature = "debian-pure"))]
        if crate::core::env::distro::is_debian_like() {
            return Ok(crate::package_managers::debian_db::search_fast(query)
                .context("Failed to search official packages")?
                .into_iter()
                .map(|package| crate::package_managers::SyncPackage {
                    name: package.name,
                    version: package.version,
                    description: package.description,
                    repo: "official".to_string(),
                    download_size: 0,
                    installed: package.installed,
                })
                .collect());
        }

        #[cfg(feature = "arch")]
        return crate::package_managers::search_sync(query)
            .context("Failed to search official packages");

        #[cfg(all(feature = "debian", not(feature = "arch")))]
        return crate::package_managers::apt_search_sync(query)
            .context("Failed to search official packages");

        #[cfg(all(
            feature = "debian-pure",
            not(feature = "arch"),
            not(feature = "debian")
        ))]
        return Ok(crate::package_managers::apt_search_fast(query)
            .context("Failed to search official packages")?
            .into_iter()
            .map(|package| crate::package_managers::SyncPackage {
                name: package.name,
                version: package.version,
                description: package.description,
                repo: "official".to_string(),
                download_size: 0,
                installed: package.installed,
            })
            .collect());

        #[cfg(not(any(feature = "arch", feature = "debian", feature = "debian-pure")))]
        anyhow::bail!("Failed to search official packages: no package manager backend enabled")
    }

    // Long-running actions are associated functions (they never read model
    // state) so the event loop can spawn them without borrowing the model.
    pub async fn install_package(package_name: &str) -> Result<()> {
        let packages = vec![package_name.to_string()];
        crate::cli::packages::install(&packages, true, false, false).await
    }

    pub async fn update_system() -> Result<()> {
        crate::cli::packages::update(false, true, false, false, false).await
    }

    pub async fn clean_cache() -> Result<()> {
        // TUI button press is the confirmation; skip the CLI prompt.
        crate::cli::packages::clean(true, true, true, false, false, true).await
    }

    #[allow(
        clippy::unused_async,
        reason = "feature-gated implementations await while fallback builds do not"
    )]
    pub async fn remove_orphans() -> Result<()> {
        #[cfg(any(feature = "debian", feature = "debian-pure"))]
        if crate::core::env::distro::is_debian_like() {
            #[cfg(feature = "debian-pure")]
            {
                let orphan_list = crate::package_managers::debian_db::list_orphans_fast()
                    .context("Failed to list orphan packages")?;
                if orphan_list.is_empty() {
                    return Ok(());
                }
                let pm = crate::package_managers::get_package_manager()?;
                return pm.remove(&orphan_list).await;
            }
            #[cfg(all(feature = "debian", not(feature = "debian-pure")))]
            {
                return crate::package_managers::apt_remove_orphans()
                    .await
                    .map(|_| ());
            }
        }

        #[cfg(feature = "arch")]
        {
            crate::package_managers::remove_orphans().await
        }
        #[cfg(all(feature = "debian", not(feature = "arch")))]
        {
            crate::package_managers::apt_remove_orphans()
                .await
                .map(|_| ())
        }
        #[cfg(all(
            feature = "debian-pure",
            not(feature = "arch"),
            not(feature = "debian")
        ))]
        {
            let orphan_list = crate::package_managers::debian_db::list_orphans_fast()
                .context("Failed to list orphan packages")?;
            if orphan_list.is_empty() {
                return Ok(());
            }
            let pm = crate::package_managers::get_package_manager()?;
            pm.remove(&orphan_list).await
        }
        #[cfg(not(any(feature = "arch", feature = "debian", feature = "debian-pure")))]
        {
            anyhow::bail!("Cannot remove orphans: no package manager backend enabled");
        }
    }

    pub async fn run_security_audit() -> Result<usize> {
        Ok(crate::cli::security::security_audit_result()
            .await?
            .total_vulnerabilities)
    }

    /// Whether pressing Enter should open the install-confirmation popup.
    /// Pure decision helper; the event loop performs the actual install only
    /// after the popup is confirmed with a second Enter.
    pub fn enter_requests_confirmation(&self) -> bool {
        !self.search_mode
            && self.current_tab == Tab::Packages
            && !self.search_results.is_empty()
            && self.pending_confirmation.is_none()
    }

    pub fn request_confirmation(&mut self, action: ConfirmationAction) {
        if self.action_in_flight {
            self.action_error = Some("another action is already running".to_string());
            return;
        }
        self.pending_confirmation = Some(action);
    }

    pub fn take_confirmation(&mut self) -> Option<ConfirmationAction> {
        self.pending_confirmation.take()
    }

    /// Switch tabs, resetting transient list/search state so a stale
    /// selection or armed search mode cannot leak across tabs.
    pub fn switch_tab(&mut self, tab: Tab) {
        self.current_tab = tab;
        self.selected_index = 0;
        self.search_mode = false;
        self.pending_confirmation = None;
    }

    /// Record a search-query mutation and invalidate results for the old query.
    pub fn note_query_change(&mut self) {
        self.last_query_change = Instant::now();
        self.search_results.clear();
        self.search_error = None;
        self.selected_index = 0;
    }

    pub fn tick(&mut self) -> Result<()> {
        if self.last_tick.elapsed() >= std::time::Duration::from_secs(5) {
            self.refresh()?;
            self.last_tick = Instant::now();
        }

        // Update metrics more frequently
        if self.external_refresh_enabled
            && self.last_update.elapsed() >= std::time::Duration::from_secs(1)
        {
            self.update_system_metrics();
            self.last_update = Instant::now();
        }

        Ok(())
    }

    pub fn handle_key(&mut self, key: KeyCode) {
        // While typing a query, every key belongs to the search input.
        // Navigation, refresh, and tab shortcuts must not fire mid-typing.
        if self.search_mode {
            match key {
                KeyCode::Esc => {
                    // Cancel: discard the query so the main loop cannot
                    // mistake a cancelled search for a committed one.
                    self.search_mode = false;
                    self.search_query.clear();
                    self.search_results.clear();
                    self.note_query_change();
                }
                KeyCode::Enter => {
                    self.search_mode = false;
                    // Search will be triggered in the main loop
                }
                KeyCode::Backspace if !self.search_query.is_empty() => {
                    self.search_query.pop();
                    self.note_query_change();
                }
                KeyCode::Char(c) => {
                    self.search_query.push(c);
                    self.note_query_change();
                }
                _ => {}
            }
            return;
        }

        match key {
            // Navigation. Quit is handled by the main loop (which restores the
            // terminal); an abrupt `process::exit` here would skip cleanup.
            KeyCode::Char('r') => {
                // Trigger refresh - force it by setting last_tick to a past time
                self.last_tick = Instant::now()
                    .checked_sub(std::time::Duration::from_secs(10))
                    .unwrap_or_else(Instant::now);
            }

            // Tab switching
            KeyCode::Char('1') => self.switch_tab(Tab::Dashboard),
            KeyCode::Char('2') => self.switch_tab(Tab::Packages),
            KeyCode::Char('3') => self.switch_tab(Tab::Runtimes),
            KeyCode::Char('4') => self.switch_tab(Tab::Security),
            KeyCode::Char('5') => self.switch_tab(Tab::Activity),
            KeyCode::Char('6') => self.switch_tab(Tab::Team),

            // List navigation
            KeyCode::Up | KeyCode::Char('k') if self.selected_index > 0 => {
                self.selected_index -= 1;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let max = match self.current_tab {
                    Tab::Packages => self.search_results.len().saturating_sub(1),
                    Tab::Activity => self.history.len().min(20).saturating_sub(1),
                    _ => 0,
                };
                if self.selected_index < max {
                    self.selected_index += 1;
                }
            }

            // Search
            KeyCode::Char('/') if self.current_tab == Tab::Packages => {
                self.search_mode = true;
                self.search_query.clear();
                self.search_results.clear();
                self.search_error = None;
                self.selected_index = 0;
                self.note_query_change();
            }
            KeyCode::Esc => {
                self.pending_confirmation = None;
            }
            KeyCode::Enter => {
                if self.enter_requests_confirmation()
                    && let Some(package) = self.search_results.get(self.selected_index)
                {
                    self.pending_confirmation =
                        Some(ConfirmationAction::InstallPackage(package.name.clone()));
                }
            }

            // Tab switching with arrow keys
            KeyCode::Tab => {
                let next = match self.current_tab {
                    Tab::Dashboard => Tab::Packages,
                    Tab::Packages => Tab::Runtimes,
                    Tab::Runtimes => Tab::Security,
                    Tab::Security => Tab::Activity,
                    Tab::Activity => Tab::Team,
                    Tab::Team => Tab::Dashboard,
                };
                self.switch_tab(next);
            }
            KeyCode::BackTab => {
                let prev = match self.current_tab {
                    Tab::Dashboard => Tab::Team,
                    Tab::Team => Tab::Activity,
                    Tab::Activity => Tab::Security,
                    Tab::Security => Tab::Runtimes,
                    Tab::Runtimes => Tab::Packages,
                    Tab::Packages => Tab::Dashboard,
                };
                self.switch_tab(prev);
            }

            _ => {}
        }
    }

    pub fn get_total_packages(&self) -> usize {
        #[cfg(unix)]
        return self.status.as_ref().map_or(0, |s| s.total_packages);
        #[cfg(not(unix))]
        0
    }

    pub fn get_orphan_packages(&self) -> usize {
        #[cfg(unix)]
        return self.status.as_ref().map_or(0, |s| s.orphan_packages);
        #[cfg(not(unix))]
        0
    }

    pub fn get_updates_available(&self) -> usize {
        #[cfg(unix)]
        return self.status.as_ref().map_or(0, |s| s.updates_available);
        #[cfg(not(unix))]
        0
    }

    pub fn get_security_vulnerabilities(&self) -> Option<usize> {
        #[cfg(unix)]
        return self
            .status
            .as_ref()
            .and_then(crate::daemon::protocol::StatusResult::scanned_vulnerability_count);
        #[cfg(not(unix))]
        None
    }

    pub fn get_runtime_versions(&self) -> &[(String, String)] {
        #[cfg(unix)]
        return self
            .status
            .as_ref()
            .map_or(&[], |status| status.runtime_versions.as_slice());
        #[cfg(not(unix))]
        &[]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_app() -> App {
        let mut app = App::new_detached().with_tab(Tab::Packages);
        app.search_results = vec![crate::package_managers::SyncPackage {
            name: "firefox".to_string(),
            version: crate::package_managers::parse_version_or_zero("1.0"),
            description: "Browser".to_string(),
            repo: "official".to_string(),
            download_size: 0,
            installed: false,
        }];
        app
    }

    #[tokio::test]
    async fn direct_search_gate_serializes_fallback_work() {
        let first = DIRECT_SEARCH_GATE.acquire().await.expect("gate open");

        assert!(DIRECT_SEARCH_GATE.try_acquire().is_err());
        drop(first);
        assert!(DIRECT_SEARCH_GATE.try_acquire().is_ok());
    }

    #[tokio::test]
    async fn detached_refresh_never_enables_external_state() {
        let mut app = App::new_detached();
        let last_update = app.last_update;
        app.refresh().unwrap();

        assert!(!app.external_refresh_enabled);
        assert_eq!(app.last_update, last_update);
        assert!(!app.daemon_connected);
        assert!(app.history.is_empty());
        assert!(app.team_status.is_none());
    }

    #[test]
    fn enter_with_results_opens_confirmation_popup() {
        let mut app = test_app();
        app.handle_key(KeyCode::Enter);
        assert_eq!(
            app.pending_confirmation,
            Some(ConfirmationAction::InstallPackage("firefox".to_string()))
        );
        assert!(
            !app.enter_requests_confirmation(),
            "popup must suppress a second confirmation request"
        );
    }

    #[test]
    fn esc_cancels_popup_without_installing() {
        let mut app = test_app();
        app.pending_confirmation = Some(ConfirmationAction::CleanCache);
        app.handle_key(KeyCode::Esc);
        assert!(app.pending_confirmation.is_none());
    }

    #[test]
    fn running_action_rejects_a_second_confirmation() {
        let mut app = test_app();
        app.action_in_flight = true;

        app.request_confirmation(ConfirmationAction::UpdateSystem);

        assert!(app.pending_confirmation.is_none());
        assert_eq!(
            app.action_error.as_deref(),
            Some("another action is already running")
        );
    }

    #[test]
    fn enter_during_search_ends_search_and_does_not_open_popup() {
        let mut app = test_app();
        app.search_mode = true;
        app.search_query.push_str("fire");
        app.handle_key(KeyCode::Enter);
        assert!(!app.search_mode);
        assert!(
            app.pending_confirmation.is_none(),
            "committing a query must never install the stale selection"
        );
    }

    #[test]
    fn search_mode_treats_reserved_characters_as_query_text() {
        let mut app = test_app();
        app.search_mode = true;

        // Every one of these keys is a global shortcut outside search mode;
        // while typing they must be inserted into the query instead.
        for c in ['r', 'k', 'j', '5', '/'] {
            app.handle_key(KeyCode::Char(c));
        }

        assert_eq!(app.search_query, "rkj5/");
        assert!(app.search_mode);
        assert_eq!(app.current_tab, Tab::Packages);
    }

    #[test]
    fn emptying_search_query_clears_previous_results() {
        let mut app = test_app();
        app.search_mode = true;
        app.search_query.push('f');
        app.search_error = Some("old search failed".to_string());
        app.selected_index = 1;

        app.handle_key(KeyCode::Backspace);

        assert!(app.search_query.is_empty());
        assert!(app.search_results.is_empty());
        assert!(app.search_error.is_none());
        assert_eq!(app.selected_index, 0);
    }

    #[test]
    fn esc_cancels_search_by_discarding_the_query() {
        let mut app = test_app();
        app.search_mode = true;
        app.search_query.push_str("fir");

        app.handle_key(KeyCode::Esc);

        assert!(!app.search_mode);
        assert!(
            app.search_query.is_empty(),
            "a cancelled query must not commit"
        );
        assert!(app.search_results.is_empty());
    }

    #[test]
    fn activity_navigation_stays_within_the_rendered_history_window() {
        let mut app = test_app();
        app.current_tab = Tab::Activity;
        app.history = (0..25)
            .map(|index| crate::core::history::Transaction {
                id: format!("tx-{index}"),
                timestamp: jiff::Timestamp::now(),
                transaction_type: crate::core::history::TransactionType::Install,
                changes: Vec::new(),
                success: true,
            })
            .collect();

        for _ in 0..30 {
            app.handle_key(KeyCode::Down);
        }

        assert_eq!(app.selected_index, 19);
    }

    #[test]
    fn tab_switch_resets_selection_and_search_state() {
        let mut app = test_app();
        app.search_mode = true;
        app.selected_index = 10;
        // Exit search first: while the query is open even digits belong to it.
        app.handle_key(KeyCode::Enter);
        app.handle_key(KeyCode::Char('5')); // Activity
        assert_eq!(app.current_tab, Tab::Activity);
        assert_eq!(app.selected_index, 0);
        assert!(!app.search_mode, "search mode must not leak across tabs");

        // Returning to Packages starts clean.
        app.handle_key(KeyCode::Tab);
        assert_eq!(app.current_tab, Tab::Team);
    }
}
