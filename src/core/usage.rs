//! Usage tracking for OMG
//!
//! Tracks command usage, time saved, and optionally syncs with the dashboard.
//! Local statistics are always recorded. Remote dashboard sync posts only when
//! telemetry is opted in AND this machine has a valid linked account.
//!
//! Local usage statistics and remote telemetry are separate concerns. This
//! module records local operation counts/time-saved estimates and only emits
//! explicit feature toggles through the canonical telemetry boundary.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Time saved per operation (in milliseconds)
/// Based on benchmark comparisons vs traditional tools
pub mod time_saved {
    /// Search: OMG 6ms vs pacman 133ms = 127ms saved
    pub const SEARCH_MS: u64 = 127;
    /// Info: OMG 6.5ms vs pacman 138ms = 131.5ms saved
    pub const INFO_MS: u64 = 132;
    /// Runtime switch: OMG 1.8ms vs nvm 150ms = 148.2ms saved
    pub const RUNTIME_SWITCH_MS: u64 = 148;
    /// Install: OMG parallel vs sequential = ~30% time saved (estimated 5s per package)
    pub const INSTALL_MS: u64 = 1500;
    /// Update: no dedicated benchmark yet; conservatively estimated at the
    /// same per-package saving as install.
    pub const UPDATE_MS: u64 = INSTALL_MS;
    /// Remove: no dedicated benchmark yet; conservatively estimated at the
    /// same per-package saving as install.
    pub const REMOVE_MS: u64 = INSTALL_MS;
}

/// Achievement definitions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Achievement {
    /// First command executed
    FirstStep,
    /// 100 commands executed
    Centurion,
    /// 1,000 commands executed
    PowerUser,
    /// 10,000 commands executed
    Legend,
    /// 1 minute saved
    MinuteSaver,
    /// 1 hour saved
    HourSaver,
    /// 1 day saved (24 hours)
    DaySaver,
    /// 7-day usage streak
    WeekStreak,
    /// 30-day usage streak
    MonthStreak,
    /// Used all 7 runtimes
    Polyglot,
    /// First SBOM generated
    SecurityFirst,
    /// Found and fixed vulnerabilities
    BugHunter,
}

impl Achievement {
    #[must_use]
    pub fn emoji(&self) -> &'static str {
        match self {
            Self::FirstStep => "🚀",
            Self::Centurion => "💯",
            Self::PowerUser => "⚡",
            Self::Legend => "🏆",
            Self::MinuteSaver => "⏱️",
            Self::HourSaver => "⏰",
            Self::DaySaver => "📅",
            Self::WeekStreak => "🔥",
            Self::MonthStreak => "💎",
            Self::Polyglot => "🌐",
            Self::SecurityFirst => "🛡️",
            Self::BugHunter => "🐛",
        }
    }

    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::FirstStep => "First Step",
            Self::Centurion => "Centurion",
            Self::PowerUser => "Power User",
            Self::Legend => "Legend",
            Self::MinuteSaver => "Minute Saver",
            Self::HourSaver => "Hour Saver",
            Self::DaySaver => "Day Saver",
            Self::WeekStreak => "Week Streak",
            Self::MonthStreak => "Month Streak",
            Self::Polyglot => "Polyglot",
            Self::SecurityFirst => "Security First",
            Self::BugHunter => "Bug Hunter",
        }
    }

    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::FirstStep => "Executed your first command",
            Self::Centurion => "Executed 100 commands",
            Self::PowerUser => "Executed 1,000 commands",
            Self::Legend => "Executed 10,000 commands",
            Self::MinuteSaver => "Saved 1 minute of time",
            Self::HourSaver => "Saved 1 hour of time",
            Self::DaySaver => "Saved 24 hours of time",
            Self::WeekStreak => "Used OMG for 7 days straight",
            Self::MonthStreak => "Used OMG for 30 days straight",
            Self::Polyglot => "Used all 7 built-in runtimes",
            Self::SecurityFirst => "Generated your first SBOM",
            Self::BugHunter => "Found and addressed vulnerabilities",
        }
    }
}

/// Usage statistics stored locally
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UsageStats {
    /// Total commands executed
    pub total_commands: u64,
    /// Commands by type
    pub commands: HashMap<String, u64>,
    /// Total time saved in milliseconds
    pub time_saved_ms: u64,
    /// Queries today (resets daily)
    pub queries_today: u64,
    /// Queries this month
    pub queries_this_month: u64,
    /// Last query date (YYYY-MM-DD)
    pub last_query_date: String,
    /// Last month (YYYY-MM)
    pub last_month: String,
    /// SBOMs generated (Pro+)
    #[serde(default)]
    pub sbom_generated: u64,
    /// Vulnerabilities found (Pro+)
    #[serde(default)]
    pub vulnerabilities_found: u64,
    /// Last sync timestamp
    pub last_sync: i64,
    /// Current streak (consecutive days)
    #[serde(default)]
    pub current_streak: u32,
    /// Longest streak ever
    #[serde(default)]
    pub longest_streak: u32,
    /// Unlocked achievements
    #[serde(default)]
    pub achievements: Vec<Achievement>,
    /// Runtimes used (for Polyglot achievement)
    #[serde(default)]
    pub runtimes_used: Vec<String>,
    /// Installed packages (for Global Insights)
    #[serde(default)]
    pub installed_packages: HashMap<String, u64>,
    /// Runtime usage counts (for Global Insights)
    #[serde(default)]
    pub runtime_usage_counts: HashMap<String, u64>,
    /// First use date
    #[serde(default)]
    pub first_use_date: String,
    /// Daily installs (resets daily, same as `queries_today`)
    #[serde(default)]
    pub installs_today: u64,
    /// Daily searches (resets daily)
    #[serde(default)]
    pub searches_today: u64,
    /// Daily runtime switches (resets daily)
    #[serde(default)]
    pub runtimes_today: u64,
    /// Daily time saved in ms (resets daily)
    #[serde(default)]
    pub time_saved_today_ms: u64,
}

#[derive(Clone, Copy)]
enum DailyOperation {
    Install,
    Search,
    RuntimeSwitch,
}

#[derive(Serialize)]
struct UsageSyncPayload<'a> {
    os: &'static str,
    arch: &'static str,
    omg_version: &'static str,
    commands_run: u64,
    packages_installed: u64,
    packages_searched: u64,
    runtimes_switched: u64,
    sbom_generated: u64,
    vulnerabilities_found: u64,
    time_saved_ms: u64,
    current_streak: u32,
    achievements: &'a [Achievement],
}

impl UsageStats {
    /// Get the usage stats file path
    fn path() -> Result<PathBuf> {
        let data_dir = crate::core::paths::ensure_data_dir()?;
        Ok(data_dir.join("usage.json"))
    }

    /// Load usage stats from disk.
    pub fn load() -> Result<Self> {
        Self::load_from(&Self::path()?)
    }

    fn load_from(path: &std::path::Path) -> Result<Self> {
        let content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("Failed to read usage stats: {}", path.display()));
            }
        };
        serde_json::from_str(&content)
            .with_context(|| format!("Malformed usage stats: {}", path.display()))
    }

    /// Save usage stats to disk.
    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        self.save_to(&path)
            .with_context(|| format!("Failed to save usage stats: {}", path.display()))
    }

    fn save_to(&self, path: &std::path::Path) -> Result<()> {
        let content = serde_json::to_vec_pretty(self).context("Failed to serialize usage stats")?;
        crate::core::safe_ops::atomic_write_file_sync(path, content)?;
        Ok(())
    }

    /// Record a command execution.
    pub fn record_command(&mut self, command: &str, time_saved_ms: u64) {
        self.record_command_on(command, time_saved_ms, jiff::Zoned::now().date());
        self.save_best_effort();
    }

    fn record_specialized_command(
        &mut self,
        command: &str,
        time_saved_ms: u64,
        operation: DailyOperation,
    ) {
        self.record_specialized_command_on(
            command,
            time_saved_ms,
            operation,
            jiff::Zoned::now().date(),
        );
        self.save_best_effort();
    }

    fn record_specialized_command_on(
        &mut self,
        command: &str,
        time_saved_ms: u64,
        operation: DailyOperation,
        today: jiff::civil::Date,
    ) {
        self.record_command_on(command, time_saved_ms, today);
        match operation {
            DailyOperation::Install => self.installs_today += 1,
            DailyOperation::Search => self.searches_today += 1,
            DailyOperation::RuntimeSwitch => self.runtimes_today += 1,
        }
    }

    fn record_command_on(&mut self, command: &str, time_saved_ms: u64, today: jiff::civil::Date) {
        self.rollover_for(today);
        self.total_commands += 1;
        self.time_saved_ms += time_saved_ms;
        *self.commands.entry(command.to_string()).or_insert(0) += 1;
        self.queries_today += 1;
        self.time_saved_today_ms += time_saved_ms;
        self.queries_this_month += 1;
        self.check_achievements();
    }

    fn save_best_effort(&self) {
        if let Err(error) = self.save() {
            tracing::warn!("Failed to save usage stats: {error}");
        }
    }

    fn rollover_for(&mut self, today: jiff::civil::Date) {
        let today_string = today.to_string();
        let month = today_string[..7].to_string();

        if self.first_use_date.is_empty() {
            self.first_use_date.clone_from(&today_string);
        }

        if self.last_query_date != today_string {
            if let Ok(last_date) = jiff::civil::Date::strptime("%Y-%m-%d", &self.last_query_date) {
                let elapsed_days = (today - last_date).get_days();
                if elapsed_days == 1 {
                    self.current_streak += 1;
                } else if elapsed_days > 1 {
                    self.current_streak = 1;
                }
            } else {
                self.current_streak = 1;
            }
            self.longest_streak = self.longest_streak.max(self.current_streak);
            self.queries_today = 0;
            self.installs_today = 0;
            self.searches_today = 0;
            self.runtimes_today = 0;
            self.time_saved_today_ms = 0;
            self.last_query_date = today_string;
        }

        if self.last_month != month {
            self.queries_this_month = 0;
            self.last_month = month;
        }
    }

    fn unlock(&mut self, achievement: Achievement, earned: bool) {
        if earned && !self.achievements.contains(&achievement) {
            self.achievements.push(achievement);
        }
    }

    /// Check and unlock achievements.
    fn check_achievements(&mut self) {
        self.unlock(Achievement::FirstStep, self.total_commands >= 1);
        self.unlock(Achievement::Centurion, self.total_commands >= 100);
        self.unlock(Achievement::PowerUser, self.total_commands >= 1_000);
        self.unlock(Achievement::Legend, self.total_commands >= 10_000);
        self.unlock(Achievement::MinuteSaver, self.time_saved_ms >= 60_000);
        self.unlock(Achievement::HourSaver, self.time_saved_ms >= 3_600_000);
        self.unlock(Achievement::DaySaver, self.time_saved_ms >= 86_400_000);
        self.unlock(Achievement::WeekStreak, self.current_streak >= 7);
        self.unlock(Achievement::MonthStreak, self.current_streak >= 30);
        self.unlock(Achievement::SecurityFirst, self.sbom_generated >= 1);
        self.unlock(Achievement::BugHunter, self.vulnerabilities_found >= 1);
        self.unlock(Achievement::Polyglot, self.runtimes_used.len() >= 7);
    }

    /// Register a newly used runtime without persisting; callers batch this
    /// with other mutations under one lock and a single save.
    /// Returns whether the runtime was new (and thus state mutated).
    fn record_runtime_on(&mut self, runtime: &str) -> bool {
        let runtime_lower = runtime.to_lowercase();
        if self.runtimes_used.contains(&runtime_lower) {
            return false;
        }
        self.runtimes_used.push(runtime_lower);
        self.check_achievements();
        true
    }

    /// Get time saved as human-readable string
    #[must_use]
    pub fn time_saved_human(&self) -> String {
        let ms = self.time_saved_ms;
        if ms < 1000 {
            format!("{ms}ms")
        } else if ms < 60_000 {
            format!("{:.1}s", ms as f64 / 1000.0)
        } else if ms < 3_600_000 {
            format!("{:.1}min", ms as f64 / 60_000.0)
        } else {
            format!("{:.1}hr", ms as f64 / 3_600_000.0)
        }
    }

    /// Get most used commands (top 5)
    #[must_use]
    pub fn top_commands(&self) -> Vec<(String, u64)> {
        let mut sorted: Vec<_> = self.commands.iter().map(|(k, v)| (k.clone(), *v)).collect();
        sorted.sort_by_key(|&(_, count)| std::cmp::Reverse(count));
        sorted.truncate(5);
        sorted
    }

    /// Check if sync is needed (every 30 seconds for real-time dashboard)
    #[must_use]
    pub fn needs_sync(&self) -> bool {
        if self.total_commands == 0 {
            return false;
        }
        let now = jiff::Timestamp::now().as_second();
        now - self.last_sync > 30 // 30 seconds for near real-time updates
    }

    /// Check if immediate sync is needed (for important events)
    #[must_use]
    pub fn needs_immediate_sync(&self) -> bool {
        // Sync immediately after first command, achievements, or milestones.
        // An empty stats file must never trigger a sync.
        if self.total_commands == 0 {
            return false;
        }
        self.total_commands == 1
            || self.total_commands.is_multiple_of(100)
            || (self.time_saved_ms >= 60_000 && self.last_sync == 0)
    }

    fn sync_payload(&self) -> UsageSyncPayload<'_> {
        UsageSyncPayload {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            omg_version: env!("CARGO_PKG_VERSION"),
            commands_run: self.queries_today,
            packages_installed: self.installs_today,
            packages_searched: self.searches_today,
            runtimes_switched: self.runtimes_today,
            sbom_generated: self.sbom_generated,
            vulnerabilities_found: self.vulnerabilities_found,
            time_saved_ms: self.time_saved_today_ms,
            current_streak: self.current_streak,
            achievements: &self.achievements,
        }
    }

    pub async fn sync(&mut self) -> Result<()> {
        let payload = self.sync_payload();
        let client = crate::core::http::shared_client();
        client
            .post(super::service_api::REPORT_USAGE)
            .json(&payload)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await?
            .error_for_status()
            .context("Usage sync server rejected the update")?;

        self.last_sync = jiff::Timestamp::now().as_second();
        // Merge only the sync timestamp into freshly-loaded state under the
        // cross-process lock: writing back this task's snapshot would clobber
        // counters recorded by concurrent invocations while the network
        // request was in flight.
        let synced_at = self.last_sync;
        update_locked(&Self::path()?, |stats| stats.last_sync = synced_at)?;

        Ok(())
    }
}

fn load_for_tracking() -> Option<UsageStats> {
    match UsageStats::load() {
        Ok(stats) => Some(stats),
        Err(error) => {
            tracing::warn!("Skipping usage tracking because persisted stats are invalid: {error}");
            None
        }
    }
}

/// Acquire the cross-process usage lock (`usage.lock`) so a full
/// load-modify-save cycle cannot interleave with another omg invocation
/// (which would silently lose counters to last-writer-wins). The lock is
/// released when the returned file is dropped. Same pattern as
/// [`crate::core::history::HistoryManager`].
fn lock_usage_file() -> Option<std::fs::File> {
    lock_file_at(&UsageStats::path().ok()?.with_extension("lock"))
}

fn lock_file_at(lock_path: &std::path::Path) -> Option<std::fs::File> {
    match acquire_usage_lock(lock_path) {
        Ok(lock) => Some(lock),
        Err(error) => {
            tracing::warn!(
                "Failed to acquire usage lock {}: skipping this update ({error:#})",
                lock_path.display()
            );
            None
        }
    }
}

fn acquire_usage_lock(lock_path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;

    use rustix::fs::{Mode, OFlags, open, openat};

    let owner = nix::unistd::geteuid().as_raw();

    let parent = lock_path.parent().context("Usage lock has no parent")?;
    let name = lock_path
        .file_name()
        .context("Usage lock has no filename")?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = open(
        if parent.is_absolute() { "/" } else { "." },
        directory_flags,
        Mode::empty(),
    )?;
    for component in parent.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                directory = openat(&directory, name, directory_flags, Mode::empty())?;
            }
            Component::ParentDir | Component::Prefix(_) => {
                anyhow::bail!("Usage lock path must not traverse parent directories");
            }
        }
    }
    let directory = std::fs::File::from(directory);
    let metadata = directory.metadata()?;
    anyhow::ensure!(
        metadata.uid() == owner && metadata.mode() & 0o022 == 0,
        "Usage lock directory must be owned by the effective user and not writable by others"
    );

    // Keep lookup anchored to the opened directory even if an ancestor is replaced.
    let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let lock = openat(
        &directory,
        name,
        flags | OFlags::CREATE,
        Mode::RUSR | Mode::WUSR,
    );
    #[cfg(target_os = "macos")]
    let lock = lock.or_else(|error| {
        if error == rustix::io::Errno::NOENT {
            // macOS can report ENOENT from concurrent O_CREAT opens even
            // though another creator has installed the regular lock file.
            // Open that existing entry once, without CREATE: never recreate
            // a missing target or retry a removed directory. Keep the same
            // parent fd, NOFOLLOW and all post-open ownership/type checks.
            return openat(&directory, name, flags, Mode::empty());
        }
        Err(error)
    });
    let lock = lock.with_context(|| {
        // Keep the original errno and record descriptor-relative state only
        // on failure. This distinguishes a removed parent from a platform
        // open/create failure without changing the lock target.
        let parent_state = directory
            .metadata()
            .map(|entry| (entry.dev(), entry.ino(), entry.nlink()));
        let entry_state =
            rustix::fs::statat(&directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                .map(|entry| (entry.st_dev, entry.st_ino, entry.st_mode, entry.st_nlink));
        format!(
            "Failed to open anchored usage lock {}; parent (device, inode, links): \
             {parent_state:?}; entry (device, inode, mode, links): {entry_state:?}",
            name.display()
        )
    })?;
    let lock = std::fs::File::from(lock);
    let metadata = lock.metadata()?;
    anyhow::ensure!(metadata.is_file(), "Usage lock is not a regular file");
    anyhow::ensure!(
        metadata.nlink() == 1,
        "Usage lock must have exactly one link"
    );
    anyhow::ensure!(
        metadata.uid() == owner,
        "Usage lock is not owned by the effective user"
    );
    lock.lock().context("Failed to lock usage stats")?;
    Ok(lock)
}

/// Run a load-modify-save cycle while holding the usage file lock.
///
/// Fire-and-forget tracking: when the lockfile cannot be opened or locked the
/// mutation is **skipped** (never performed unlocked) so a lost lock can never
/// degrade into the interleaved last-writer-wins update the lock exists to
/// prevent. `lock_file_at` already logs the reason.
fn with_usage_lock(mutate: impl FnOnce()) {
    if let Some(lock) = lock_usage_file() {
        let _lock_guard = lock;
        mutate();
    }
}

/// Run a mandatory load-modify-save cycle against `path` under the
/// cross-process usage lock. Unlike [`with_usage_lock`] (used by fire-and-
/// forget tracking), a failed lock acquisition is an error here because the
/// caller is about to write persisted state and must not race a concurrent
/// writer.
fn update_locked<T>(path: &Path, f: impl FnOnce(&mut UsageStats) -> T) -> Result<T> {
    let lock_path = path.with_extension("lock");
    let lock = acquire_usage_lock(&lock_path)
        .with_context(|| format!("Failed to acquire usage stats lock {}", lock_path.display()))?;
    let _lock_guard = lock;
    let mut stats = UsageStats::load_from(path)?;
    let out = f(&mut stats);
    stats.save_to(path)?;
    Ok(out)
}

/// Track a command execution (convenience function)
pub fn track(command: &str, time_saved_ms: u64) {
    with_usage_lock(|| {
        let Some(mut stats) = load_for_tracking() else {
            return;
        };
        stats.record_command(command, time_saved_ms);
    });
}

/// Track search command
pub fn track_search() {
    with_usage_lock(|| {
        let Some(mut stats) = load_for_tracking() else {
            return;
        };
        stats.record_specialized_command("search", time_saved::SEARCH_MS, DailyOperation::Search);
    });
}

/// Track info command
pub fn track_info() {
    track("info", time_saved::INFO_MS);
}

/// Track install command
pub fn track_install(packages: &[String]) {
    with_usage_lock(|| {
        let Some(mut stats) = load_for_tracking() else {
            return;
        };

        for pkg in packages {
            *stats.installed_packages.entry(pkg.clone()).or_insert(0) += 1;
        }

        stats.record_specialized_command(
            "install",
            time_saved::INSTALL_MS,
            DailyOperation::Install,
        );
    });
}

/// Track runtime switch
pub fn track_runtime_switch(runtime: &str) {
    with_usage_lock(|| {
        let Some(mut stats) = load_for_tracking() else {
            return;
        };

        *stats
            .runtime_usage_counts
            .entry(runtime.to_string())
            .or_insert(0) += 1;

        // Batched with the specialized-command record below into a single
        // locked save instead of writing usage.json once per mutation.
        let _ = stats.record_runtime_on(runtime);

        stats.record_specialized_command(
            "runtime_switch",
            time_saved::RUNTIME_SWITCH_MS,
            DailyOperation::RuntimeSwitch,
        );
    });
}

// =============================================================================
// Local usage result tracking
// =============================================================================

/// Record a completed install in local usage statistics.
pub fn track_install_result(packages: &[String], success: bool) {
    if success {
        track_install(packages);
    }
    maybe_sync_background();
}

/// Record a completed search in local usage statistics.
pub fn track_search_result(success: bool) {
    if success {
        track_search();
    }
    maybe_sync_background();
}

/// Record a completed update in local usage statistics.
pub fn track_update_result(updated_count: usize, success: bool) {
    if success {
        track(
            "update",
            time_saved::UPDATE_MS.saturating_mul(u64::try_from(updated_count).unwrap_or(0)),
        );
    }
    maybe_sync_background();
}

/// Record a completed removal in local usage statistics.
pub fn track_remove_result(success: bool) {
    if success {
        track("remove", time_saved::REMOVE_MS);
    }
    maybe_sync_background();
}

/// Load the stored account only when its token is valid, so expired or
/// unverifiable tokens stop attributing usage to the dashboard.
fn licensed_for_sync() -> Option<crate::core::license::StoredLicense> {
    crate::core::license::load_license().filter(super::license::StoredLicense::is_token_valid)
}

/// Remote dashboard sync posts only when telemetry is enabled AND an account
/// is linked. Local usage counters are independent of this decision.
fn sync_decision(effective_telemetry_enabled: bool, license_valid: bool) -> bool {
    effective_telemetry_enabled && license_valid
}

fn sync_candidate() -> Option<UsageStats> {
    if crate::core::paths::test_mode() {
        return None;
    }
    if !sync_decision(
        !crate::core::telemetry::is_telemetry_opt_out(),
        licensed_for_sync().is_some(),
    ) {
        return None;
    }
    load_for_tracking()
}

/// Sync usage in background if needed
pub fn maybe_sync_background() {
    let Some(mut stats) = sync_candidate() else {
        return;
    };
    if stats.needs_sync() || stats.needs_immediate_sync() {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::debug!("Deferring usage sync until an async shutdown boundary");
            return;
        };
        runtime.spawn(async move {
            if let Err(e) = stats.sync().await {
                tracing::debug!("Usage sync failed: {e}");
            }
        });
    }
}

/// Sync usage now (awaitable, for end of CLI commands)
pub async fn sync_usage_now() {
    let Some(mut stats) = sync_candidate() else {
        return;
    };
    if stats.total_commands == 0 {
        return;
    }
    if let Err(e) = stats.sync().await {
        tracing::debug!("Usage sync failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires isolated user/mount namespaces with the state fixture mounted at /var/lib"]
    fn elevated_state_roundtrip_preserves_caller_files() -> Result<()> {
        use std::os::unix::fs::MetadataExt;

        anyhow::ensure!(crate::core::is_root(), "Requires namespace UID 0");
        anyhow::ensure!(
            std::fs::read_to_string("/var/lib/.omg-state-isolation-fixture")? == "isolated",
            "Missing isolated mount fixture"
        );
        let caller_dir = PathBuf::from(std::env::var("OMG_DATA_DIR")?);
        let caller_history = caller_dir.join("history.json");
        let caller_usage = caller_dir.join("usage.json");
        let history_before = std::fs::read(&caller_history)?;
        let usage_before = std::fs::read(&caller_usage)?;

        let path = UsageStats::path()?;
        assert_eq!(path, PathBuf::from("/var/lib/omg/usage.json"));
        let _lock = acquire_usage_lock(&path.with_extension("lock"))?;
        let mut stats = UsageStats::default();
        stats.record_command("search", 1);
        stats.save()?;
        assert_eq!(UsageStats::load()?.total_commands, 1);
        assert_eq!(std::fs::metadata(&path)?.uid(), 0);
        let history = crate::core::history::HistoryManager::new()?;
        history.save(&[])?;
        assert!(history.load()?.is_empty());
        assert_eq!(std::fs::metadata("/var/lib/omg/history.json")?.uid(), 0);

        // Exercise storage selection, not entitlement validation, with synthetic records.
        let mut license = crate::core::license::StoredLicense {
            key: "caller-synthetic-only".to_string(),
            tier: "free".to_string(),
            features: Vec::new(),
            customer: None,
            expires_at: None,
            validated_at: 0,
            token: None,
            machine_id: None,
        };
        let caller_license = caller_dir.join("license.json");
        let license_before = serde_json::to_vec(&license)?;
        std::fs::write(&caller_license, &license_before)?;
        assert!(crate::core::license::load_license().is_none());
        license.key = "system-synthetic-only".to_string();
        std::fs::write("/var/lib/omg/license.json", serde_json::to_vec(&license)?)?;
        assert_eq!(
            crate::core::license::load_license()
                .expect("root fixture license")
                .key,
            "system-synthetic-only"
        );
        assert_eq!(std::fs::read(&caller_license)?, license_before);
        assert_eq!(std::fs::read(&caller_history)?, history_before);
        assert_eq!(std::fs::read(&caller_usage)?, usage_before);
        assert!(
            std::fs::symlink_metadata(&caller_history)?
                .file_type()
                .is_symlink()
        );
        Ok(())
    }

    #[test]
    fn usage_lock_rejects_symlink_without_changing_target() {
        use std::os::unix::fs::{MetadataExt, symlink};

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("sentinel");
        let path = directory.path().join("usage.lock");
        std::fs::write(&target, b"unchanged").unwrap();
        let before = std::fs::metadata(&target).unwrap();
        symlink(&target, &path).unwrap();

        assert!(lock_file_at(&path).is_none());
        let after = std::fs::metadata(&target).unwrap();
        assert_eq!((before.uid(), before.gid()), (after.uid(), after.gid()));
        assert_eq!(std::fs::read(&target).unwrap(), b"unchanged");
    }

    #[test]
    fn usage_lock_rejects_symlinked_ancestor() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("state");
        std::fs::create_dir(&target).unwrap();
        let link = directory.path().join("alias");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(lock_file_at(&link.join("usage.lock")).is_none());
        assert!(!target.join("usage.lock").exists());
    }

    #[test]
    fn usage_lock_rejects_hardlinks_and_special_files() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("sentinel");
        let path = directory.path().join("usage.lock");
        std::fs::write(&target, b"unchanged").unwrap();
        std::fs::hard_link(&target, &path).unwrap();
        assert!(lock_file_at(&path).is_none());
        assert_eq!(std::fs::read(&target).unwrap(), b"unchanged");

        let fifo = directory.path().join("fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU).unwrap();
        assert!(lock_file_at(&fifo).is_none());
        assert!(lock_file_at(directory.path()).is_none());
    }

    /// Lock fixtures need a parent directory the anchored `O_NOFOLLOW` walk
    /// can reach. macOS system temp dirs live behind `/var` -> `private/var`,
    /// so prefer a directory under the real home path (no symlinked
    /// ancestors) and fall back to the platform default.
    fn lock_fixture_tempdir() -> tempfile::TempDir {
        let base = home::home_dir().filter(|home| home.is_dir());
        match base {
            Some(home) => tempfile::Builder::new()
                .tempdir_in(home)
                .unwrap_or_else(|_| tempfile::tempdir().unwrap()),
            None => tempfile::tempdir().unwrap(),
        }
    }

    #[test]
    fn usage_lock_reopens_without_truncation() {
        let directory = lock_fixture_tempdir();
        let path = directory.path().join("usage.lock");
        drop(lock_file_at(&path).expect("new usage lock"));
        std::fs::write(&path, b"unchanged").unwrap();
        let lock = lock_file_at(&path).expect("existing usage lock");
        assert_eq!(std::fs::read(&path).unwrap(), b"unchanged");
        drop(lock);
    }

    #[test]
    fn usage_sync_refuses_to_post_when_telemetry_is_disabled() {
        // W8-B-02 regression: a valid account must not bypass the telemetry
        // opt-out; dashboard usage sync posts only when BOTH conditions hold.
        assert!(!sync_decision(false, true));
        assert!(!sync_decision(false, false));
    }

    #[test]
    fn usage_sync_requires_both_telemetry_and_linked_account() {
        assert!(!sync_decision(true, false));
        assert!(sync_decision(true, true));
    }

    #[test]
    fn empty_usage_never_requests_a_sync() {
        let stats = UsageStats {
            last_sync: 0,
            ..Default::default()
        };
        assert!(!stats.needs_sync());
        assert!(!stats.needs_immediate_sync());
    }

    #[test]
    fn time_saved_human_formats_units() {
        let stats = UsageStats {
            time_saved_ms: 500,
            ..Default::default()
        };
        assert_eq!(stats.time_saved_human(), "500ms");

        let stats = UsageStats {
            time_saved_ms: 5000,
            ..Default::default()
        };
        assert_eq!(stats.time_saved_human(), "5.0s");

        let stats = UsageStats {
            time_saved_ms: 120_000,
            ..Default::default()
        };
        assert_eq!(stats.time_saved_human(), "2.0min");

        let stats = UsageStats {
            time_saved_ms: 7_200_000,
            ..Default::default()
        };
        assert_eq!(stats.time_saved_human(), "2.0hr");
    }

    #[test]
    fn first_specialized_operation_after_daily_rollover_is_counted() {
        let today =
            jiff::civil::Date::strptime("%Y-%m-%d", "2025-04-10").expect("valid fixture date");
        let mut stats = UsageStats {
            last_query_date: "2025-04-09".to_string(),
            last_month: "2025-04".to_string(),
            searches_today: 9,
            ..Default::default()
        };

        stats.record_specialized_command_on(
            "search",
            time_saved::SEARCH_MS,
            DailyOperation::Search,
            today,
        );

        assert_eq!(stats.searches_today, 1);
        assert_eq!(stats.queries_today, 1);
        assert_eq!(stats.commands.get("search"), Some(&1));
    }

    #[test]
    fn malformed_usage_stats_are_rejected_without_modification() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let path = directory.path().join("usage.json");
        std::fs::write(&path, b"{not-json").expect("write malformed fixture");

        let error = UsageStats::load_from(&path).expect_err("malformed stats must be rejected");

        assert!(error.to_string().contains("Malformed usage stats"));
        assert_eq!(std::fs::read(&path).expect("read fixture"), b"{not-json");
    }

    #[cfg(unix)]
    #[test]
    fn saving_usage_replaces_symlink_without_changing_its_target() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let path = directory.path().join("usage.json");
        std::fs::write(&target, b"untouched").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        UsageStats::default().save_to(&path).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
        assert!(!std::fs::symlink_metadata(&path).unwrap().is_symlink());
        UsageStats::load_from(&path).unwrap();
    }

    #[test]
    fn saved_usage_stats_roundtrip_and_keep_owner() {
        // #290 wiring: save_to must persist through the ownership-restore
        // step. Non-root the restore is a no-op, so the roundtrip and the
        // file owner must be unaffected by its presence.
        let directory = tempfile::tempdir().expect("create temporary directory");
        let path = directory.path().join("usage.json");
        let stats = UsageStats {
            total_commands: 7,
            ..UsageStats::default()
        };
        stats.save_to(&path).expect("save must succeed");
        let loaded = UsageStats::load_from(&path).expect("saved stats must load");
        assert_eq!(loaded.total_commands, 7);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let owner = std::fs::metadata(&path).expect("stat saved file").uid();
            assert_eq!(owner, rustix::process::geteuid().as_raw());
        }
    }

    #[test]
    fn missing_usage_stats_load_as_empty() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let stats = UsageStats::load_from(&directory.path().join("missing.json"))
            .expect("missing stats are the initial state");
        assert_eq!(stats.total_commands, 0);
    }

    #[test]
    fn concurrent_locked_updates_do_not_lose_counters() {
        // Regression: usage.json load-modify-save cycles used to run without
        // a cross-process lock, so concurrent omg invocations clobbered each
        // other's counters (last-writer-wins).
        const WRITERS: usize = 8;
        const UPDATES_PER_WRITER: usize = 5;
        let directory = lock_fixture_tempdir();
        let path = directory.path().join("usage.json");

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(WRITERS));
        let mut writers = Vec::new();
        for writer_index in 0..WRITERS {
            let path = path.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            writers.push(std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..UPDATES_PER_WRITER {
                    // Same lock + load-modify-save shape as the public track* functions.
                    let _lock = match acquire_usage_lock(&path.with_extension("lock")) {
                        Ok(lock) => lock,
                        Err(error) => panic!("writer must acquire lock: {error:#}"),
                    };
                    let mut stats = UsageStats::load_from(&path).expect("valid usage stats");
                    stats.record_command_on(
                        "search",
                        1,
                        jiff::civil::Date::strptime("%Y-%m-%d", "2025-04-10")
                            .expect("valid fixture date"),
                    );
                    stats.save_to(&path).expect("locked save must succeed");
                }
                writer_index
            }));
        }
        for writer in writers {
            writer.join().expect("usage writer panicked");
        }

        let stats = UsageStats::load_from(&path).expect("final stats must be valid");
        assert_eq!(stats.total_commands, (WRITERS * UPDATES_PER_WRITER) as u64);
    }

    #[test]
    fn simultaneous_first_usage_locks_share_one_inode() {
        use std::os::unix::fs::MetadataExt;

        // Repeated fresh directories exercise concurrent first creation,
        // separately from the JSON merge and save paths. Do not retry failures.
        for round in 0..32 {
            let directory = lock_fixture_tempdir();
            let path = directory.path().join("usage.lock");
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
            let mut workers = Vec::new();
            for _ in 0..4 {
                let path = path.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                workers.push(std::thread::spawn(move || -> Result<(u64, u64)> {
                    barrier.wait();
                    let lock = acquire_usage_lock(&path)?;
                    let entry = lock.metadata()?;
                    Ok((entry.dev(), entry.ino()))
                }));
            }
            // Join every worker before reporting an error, keeping the fixture
            // alive even if one worker fails so cleanup cannot mask the cause.
            let results: Vec<_> = workers
                .into_iter()
                .map(std::thread::JoinHandle::join)
                .collect();
            let identities: Vec<_> = results
                .into_iter()
                .map(|result| {
                    result
                        .expect("first-lock worker panicked")
                        .unwrap_or_else(|error| {
                            panic!("first-lock round {round} failed: {error:#}")
                        })
                })
                .collect();
            let expected = std::fs::metadata(&path).expect("created usage lock");
            for identity in identities {
                assert_eq!(identity, (expected.dev(), expected.ino()));
            }
        }
    }

    #[test]
    fn outbound_usage_contains_only_aggregate_data() {
        let stats = UsageStats {
            queries_today: 4,
            installs_today: 2,
            searches_today: 1,
            runtimes_today: 1,
            installed_packages: HashMap::from([("private-package-name".to_string(), 2)]),
            runtime_usage_counts: HashMap::from([("node".to_string(), 1)]),
            ..Default::default()
        };

        let payload =
            serde_json::to_value(stats.sync_payload()).expect("usage payload must serialize");
        let object = payload
            .as_object()
            .expect("usage payload must be an object");
        let serialized = payload.to_string();

        assert_eq!(object.get("commands_run"), Some(&serde_json::json!(4)));
        assert_eq!(
            object.get("packages_installed"),
            Some(&serde_json::json!(2))
        );
        assert_eq!(object.get("packages_searched"), Some(&serde_json::json!(1)));
        assert_eq!(object.get("runtimes_switched"), Some(&serde_json::json!(1)));
        assert!(!serialized.contains("private-package-name"));
        assert!(!serialized.contains("private-license-key"));
        assert!(!object.contains_key("installed_packages"));
        assert!(!object.contains_key("runtime_usage_counts"));
        assert!(!object.contains_key("license_key"));
        assert!(!object.contains_key("machine_id"));
        assert!(!object.contains_key("hostname"));
    }

    #[test]
    fn record_command_accumulates_counts() {
        let today =
            jiff::civil::Date::strptime("%Y-%m-%d", "2025-04-10").expect("valid fixture date");
        let mut stats = UsageStats::default();
        stats.record_command_on("search", 127, today);
        stats.record_command_on("search", 127, today);
        stats.record_command_on("info", 132, today);

        assert_eq!(stats.total_commands, 3);
        assert_eq!(stats.commands.get("search"), Some(&2));
        assert_eq!(stats.commands.get("info"), Some(&1));
        assert_eq!(stats.time_saved_ms, 127 + 127 + 132);
    }

    #[test]
    fn locked_sync_timestamp_merge_does_not_lose_concurrent_counters() {
        // Regression for the background-sync race: UsageStats::sync used to
        // write its stale snapshot back without the cross-process lock,
        // clobbering counters recorded while the network request was in
        // flight. The timestamp-only merge must preserve them.
        const WRITERS: usize = 4;
        let directory = lock_fixture_tempdir();
        let path = directory.path().join("usage.json");

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(WRITERS));
        let mut writers = Vec::new();
        for writer_index in 0..WRITERS {
            let path = path.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            writers.push(std::thread::spawn(move || {
                barrier.wait();
                if writer_index == 0 {
                    // Background-sync side: merge only the timestamp.
                    update_locked(&path, |stats| stats.last_sync = 42)
                        .expect("timestamp merge must succeed");
                } else {
                    // Tracking side: record a full command.
                    update_locked(&path, |stats| {
                        stats.record_command_on(
                            "search",
                            1,
                            jiff::civil::Date::strptime("%Y-%m-%d", "2025-04-10")
                                .expect("valid fixture date"),
                        );
                    })
                    .expect("counter write must succeed");
                }
            }));
        }
        for writer in writers {
            writer.join().expect("usage writer panicked");
        }

        let stats = UsageStats::load_from(&path).expect("final stats must be valid");
        assert_eq!(stats.total_commands, (WRITERS - 1) as u64);
        assert_eq!(stats.last_sync, 42);
    }

    #[test]
    fn mandatory_usage_update_preserves_lock_failure_cause_without_mutating() {
        let directory = lock_fixture_tempdir();
        let path = directory.path().join("usage.json");
        let lock_path = path.with_extension("lock");
        std::fs::write(&lock_path, b"unchanged").unwrap();
        std::fs::hard_link(&lock_path, directory.path().join("lock-alias")).unwrap();
        let mut mutated = false;

        let error = update_locked(&path, |_| mutated = true)
            .expect_err("a hardlinked lock must reject the update");

        assert!(!mutated, "lock failure must prevent the mutation");
        assert!(!path.exists(), "lock failure must not write usage stats");
        assert!(error.to_string().contains(&lock_path.display().to_string()));
        assert!(format!("{error:#}").contains("Usage lock must have exactly one link"));
        assert_eq!(std::fs::read(&lock_path).unwrap(), b"unchanged");
    }
}
