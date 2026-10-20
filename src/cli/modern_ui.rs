//! Streaming print CLI chrome.
//!
//! Density follows Clack (one rail, one accent, no boxes). Colors follow the
//! current Omarchy `colors.toml` when present. Phase words are gradients, not
//! a Charm pink bar.

use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use owo_colors::OwoColorize;
use std::io::IsTerminal;
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

/// Rendering policy for long-running commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OutputMode {
    /// Suppress progress decoration while preserving results and errors.
    Quiet,
    /// Emit stable, non-animated status lines for redirected output.
    Plain,
    /// Render animated progress in an attended terminal.
    Interactive,
    /// Stream subprocess output live in addition to writing its log.
    Verbose,
}

static OUTPUT_MODE: AtomicU8 = AtomicU8::new(1);
/// Process-wide registry for every live progress lane. Attaching lanes here
/// (instead of leaving them standalone) lets [`quiesce_terminal`] hide the
/// whole family at once when an interactive prompt such as a PKGBUILD review
/// or an ALPM dialog must own the terminal.
static PROGRESS_REGISTRY: OnceLock<MultiProgress> = OnceLock::new();
/// Refcount of active [`TerminalQuiesceGuard`]s; transitions run under the
/// lock so the draw target flips exactly once per 0->1 and N->0 boundary.
static QUIESCE_COUNT: Mutex<usize> = Mutex::new(0);
/// Final lines rendered while quiesced, replayed in FIFO order when the last
/// guard drops.
static DEFERRED_LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn lock_quiesce_count() -> MutexGuard<'static, usize> {
    QUIESCE_COUNT.lock().unwrap_or_else(PoisonError::into_inner)
}

fn lock_deferred_lines() -> MutexGuard<'static, Vec<String>> {
    DEFERRED_LINES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

fn quiesce_active() -> bool {
    *lock_quiesce_count() > 0
}

fn hide_progress(progress: &MultiProgress) {
    let _ = progress.clear();
    progress.set_draw_target(ProgressDrawTarget::hidden());
}

/// Hide leftover live bar rows after a finished parallel batch, then restore
/// stderr drawing in interactive mode so later Checking spinners can attach.
#[cfg_attr(not(feature = "arch"), allow(dead_code))]
pub(crate) fn clear_live_progress() {
    let progress = progress_registry();
    hide_progress(progress);
    if output_mode() == OutputMode::Interactive {
        progress.set_draw_target(ProgressDrawTarget::stderr());
    }
}

/// Suppress live progress drawing while an interactive prompt owns the
/// terminal.
///
/// Final result lines raised during the quiesce are buffered and printed once
/// the last guard drops, so multi-line output cannot be overwritten by a
/// redrawn spinner.
#[must_use]
pub fn quiesce_terminal() -> TerminalQuiesceGuard {
    let mut count = lock_quiesce_count();
    *count += 1;
    if *count == 1 {
        hide_progress(progress_registry());
    }
    TerminalQuiesceGuard { _private: () }
}

/// RAII handle from [`quiesce_terminal`]; restores progress drawing and
/// flushes deferred lines when the final guard drops.
pub struct TerminalQuiesceGuard {
    _private: (),
}

impl Drop for TerminalQuiesceGuard {
    fn drop(&mut self) {
        let mut count = lock_quiesce_count();
        *count -= 1;
        if *count == 0 {
            progress_registry().set_draw_target(ProgressDrawTarget::stderr());
            let mut deferred = lock_deferred_lines();
            for line in deferred.drain(..) {
                println!("{line}");
            }
        }
    }
}

fn progress_registry() -> &'static MultiProgress {
    PROGRESS_REGISTRY.get_or_init(MultiProgress::new)
}

/// Attach a lane to the process-wide progress registry so quiescing can hide
/// it together with every other live lane.
///
/// Lanes are visible only in [`OutputMode::Interactive`]; every other mode
/// receives an invisible bar so callers drive one code path regardless of
/// policy while redirected or quiet output stays free of animation and ANSI.
///
/// The incoming bar is detached from its constructor draw target before it
/// joins the registry. Leaving stderr attached draws one copy of the spinner
/// as a standalone bar and a second copy through `MultiProgress`.
pub(crate) fn register_spinner(bar: ProgressBar) -> ProgressBar {
    if output_mode() != OutputMode::Interactive {
        return ProgressBar::hidden();
    }
    bar.set_draw_target(ProgressDrawTarget::hidden());
    progress_registry().add(bar)
}

/// Print `line`, or buffer it while a terminal quiesce is active.
///
/// In interactive mode the line goes through the shared `MultiProgress`,
/// which suspends live spinners for the write; raw `println!` would splice
/// mid-frame and read as spinner spam under parallel builds.
pub(crate) fn emit_or_defer(line: String) {
    if quiesce_active() {
        lock_deferred_lines().push(line);
        return;
    }
    if output_mode() == OutputMode::Interactive {
        let _ = progress_registry().println(&line);
    } else {
        println!("{line}");
    }
}

/// Buffer `line` for replay when the terminal quiesce ends.
fn defer_line(line: String) {
    lock_deferred_lines().push(line);
}

const fn output_mode_for(verbose: u8, quiet: bool, terminal: bool) -> OutputMode {
    if quiet {
        OutputMode::Quiet
    } else if verbose > 0 {
        OutputMode::Verbose
    } else if terminal {
        OutputMode::Interactive
    } else {
        OutputMode::Plain
    }
}

/// Configure process-wide rendering before command dispatch.
pub fn configure_output(verbose: u8, quiet: bool) {
    let mode = output_mode_for(verbose, quiet, std::io::stderr().is_terminal());
    OUTPUT_MODE.store(mode as u8, Ordering::Relaxed);

    let colors_enabled = crate::cli::style::colors_enabled();
    console::set_colors_enabled(colors_enabled);
    console::set_colors_enabled_stderr(colors_enabled);
}

/// Current rendering policy.
#[must_use]
pub fn output_mode() -> OutputMode {
    match OUTPUT_MODE.load(Ordering::Relaxed) {
        0 => OutputMode::Quiet,
        2 => OutputMode::Interactive,
        3 => OutputMode::Verbose,
        _ => OutputMode::Plain,
    }
}

/// Progress display for one long-running AUR build.
pub struct AurBuildProgress {
    progress: Option<ProgressBar>,
    package: String,
    started: Instant,
    mode: OutputMode,
}

impl AurBuildProgress {
    /// Replace the live build indicator with a concise terminal result.
    pub fn finish(mut self, success: bool) {
        if let Some(progress) = self.progress.take() {
            progress.finish_and_clear();
        }

        if self.mode == OutputMode::Quiet {
            return;
        }

        let elapsed = format_duration(self.started.elapsed());
        let line = if success {
            if crate::cli::style::colors_enabled() {
                format!(
                    "  {} {} {}",
                    "◆".green().bold(),
                    format!("Built {}", self.package).cyan().bold(),
                    format!("in {elapsed}").dimmed()
                )
            } else {
                format!("  OK Built {} in {elapsed}", self.package)
            }
        } else if crate::cli::style::colors_enabled() {
            format!(
                "  {} {} {}",
                "◆".red().bold(),
                format!("Build failed {}", self.package).red(),
                format!("after {elapsed}").dimmed()
            )
        } else {
            format!("  X Build failed {} after {elapsed}", self.package)
        };
        emit_or_defer(line);
    }
}

impl Drop for AurBuildProgress {
    fn drop(&mut self) {
        if let Some(progress) = self.progress.take() {
            progress.finish_and_clear();
        }
    }
}

/// Start a compact, multi-build-safe AUR "forge" indicator.
#[must_use]
#[expect(clippy::expect_used)]
pub fn aur_build_progress(package: &str, log_path: &Path) -> AurBuildProgress {
    // Package names reach lane prefixes rendered raw onto the terminal.
    let package = crate::cli::style::sanitize_terminal_text(package);
    let package = package.as_str();
    let mode = output_mode();
    let progress = match mode {
        OutputMode::Interactive => {
            let progress = register_spinner(ProgressBar::new_spinner());
            let template = if crate::cli::style::colors_enabled() {
                "  {spinner:.magenta.bold} {prefix:.cyan.bold}  {msg:.dim}  {elapsed_precise:.blue}"
            } else {
                "  {spinner} {prefix}  {msg}  {elapsed_precise}"
            };
            progress.set_style(
                ProgressStyle::default_spinner()
                    .template(template)
                    .expect("static AUR build template")
                    .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
            );
            progress.set_prefix(package.to_string());
            progress.set_message("compiling source package");
            progress.enable_steady_tick(Duration::from_millis(80));
            Some(progress)
        }
        OutputMode::Verbose => {
            println!(
                "  Building {package} (verbose output; log: {})",
                log_path.display()
            );
            None
        }
        OutputMode::Plain => {
            println!(
                "  + Building {package} from AUR (log: {})",
                log_path.display()
            );
            None
        }
        OutputMode::Quiet => None,
    };

    AurBuildProgress {
        progress,
        package: package.to_string(),
        started: Instant::now(),
        mode,
    }
}

pub(crate) fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3_600 {
        format!("{}m {:02}s", seconds / 60, seconds % 60)
    } else {
        let hours = seconds / 3_600;
        let minutes = (seconds % 3_600) / 60;
        format!("{hours}h {minutes:02}m {:02}s", seconds % 60)
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// MODERN PROGRESS INDICATORS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Modern spinner with contextual message (bun-style)
#[must_use]
#[expect(clippy::expect_used, clippy::literal_string_with_formatting_args)]
pub fn modern_spinner(phase: &str, action: &str) -> ProgressBar {
    if output_mode() == OutputMode::Quiet {
        return ProgressBar::hidden();
    }

    let pb = register_spinner(ProgressBar::new_spinner());

    // Bun-style dots spinner
    let template = if crate::cli::style::colors_enabled() {
        "{spinner:.blue.bold} {msg}"
    } else {
        "{spinner} {msg}"
    };

    pb.set_style(
        ProgressStyle::default_spinner()
            .template(template)
            .expect("static template")
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
    );

    let msg = if crate::cli::style::colors_enabled() {
        format!("{} {}", phase.dimmed(), action)
    } else {
        format!("{phase} {action}")
    };

    pb.set_message(msg);
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

/// Finish spinner with success
pub fn finish_success(pb: &ProgressBar, phase: &str, result: &str) {
    // Animation is transient terminal state. Clear it before writing the
    // completed status as a durable line; a visible finished bar is redrawn
    // whenever a prompt or subprocess suspends the shared MultiProgress.
    pb.finish_and_clear();
    print_finished_step(phase, result);
}

/// Durable completion line for a phase that had no parent spinner, or whose
/// spinner already cleared.
pub fn print_finished_step(phase: &str, result: &str) {
    if output_mode() == OutputMode::Quiet {
        return;
    }
    let message = if crate::cli::style::colors_enabled() {
        format!("{} {} {}", "✓".green().bold(), phase.dimmed(), result)
    } else {
        format!("✓ {phase} {result}")
    };
    emit_or_defer(message);
}

/// Finish spinner with info message
pub fn finish_info(pb: &ProgressBar, msg: &str) {
    let message = if crate::cli::style::colors_enabled() {
        format!("{} {}", "·".blue(), msg.dimmed())
    } else {
        format!("· {msg}")
    };
    pb.finish_and_clear();
    if output_mode() != OutputMode::Quiet {
        emit_or_defer(message);
    }
}

/// Finish spinner and clear (for phases that don't need final status)
pub fn finish_clear(pb: &ProgressBar) {
    pb.finish_and_clear();
}

/// One check-lane result: `official  3  0.41s` or `aur  up to date`.
pub fn print_source_lane(lane: &str, count: usize, elapsed: std::time::Duration) {
    if output_mode() == OutputMode::Quiet {
        return;
    }
    let elapsed_text = format!("{:.2}s", elapsed.as_secs_f64());
    let line = if crate::cli::style::colors_enabled() {
        let palette = crate::cli::chrome::palette();
        let lane_rgb = if lane.eq_ignore_ascii_case("aur") {
            palette.magenta
        } else {
            palette.cyan
        };
        let detail = if count == 0 {
            "up to date"
                .truecolor(palette.muted.r, palette.muted.g, palette.muted.b)
                .to_string()
        } else {
            format!(
                "{}  {}",
                count
                    .to_string()
                    .truecolor(lane_rgb.r, lane_rgb.g, lane_rgb.b)
                    .bold(),
                elapsed_text.dimmed()
            )
        };
        format!(
            "  {}  {:<10}  {detail}",
            crate::cli::chrome::rail(),
            lane.truecolor(lane_rgb.r, lane_rgb.g, lane_rgb.b)
        )
    } else if count == 0 {
        format!("  |  {lane:<10}  up to date")
    } else {
        format!("  |  {lane:<10}  {count}  {elapsed_text}")
    };
    emit_or_defer(line);
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// HEADERS & SECTIONS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub(crate) fn accent_bar() -> String {
    crate::cli::chrome::accent_rail()
}

pub(crate) fn phase_header_text(phase: &str, context: &str) -> String {
    if crate::cli::style::colors_enabled() {
        format!(
            "\n  {} {}\n    {}",
            accent_bar(),
            crate::cli::chrome::gradient_text(phase),
            context.dimmed()
        )
    } else {
        format!("\n  | {phase}\n    {context}")
    }
}

/// Max packages listed before a remainder count, shared by update/search.
pub(crate) const SUMMARY_LIST_CAP: usize = 15;

#[must_use]
pub fn is_verbose() -> bool {
    output_mode() == OutputMode::Verbose
}

/// Print a phase header (install, update, etc.).
///
/// The `icon` argument is kept so call sites stay stable. Headers use a
/// vertical rail and a gradient phase word.
pub fn print_phase_header(_icon: &str, phase: &str, context: &str) {
    if output_mode() == OutputMode::Quiet {
        return;
    }
    emit_or_defer(phase_header_text(phase, context));
}

/// Print a minimal section divider
pub fn print_section(label: &str) {
    if output_mode() == OutputMode::Quiet {
        return;
    }
    println!();
    if crate::cli::style::colors_enabled() {
        println!("  {} {}", accent_bar(), label.bold());
    } else {
        println!("  | {label}");
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// STATUS MESSAGES
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Success state - clean checkmark with message
pub fn print_success(msg: &str) {
    if output_mode() == OutputMode::Quiet {
        return;
    }
    let line = if crate::cli::style::colors_enabled() {
        format!("  {} {}", "✓".green().bold(), msg.bold())
    } else {
        format!("  ✓ {msg}")
    };
    if quiesce_active() {
        defer_line(line);
        return;
    }
    println!();
    println!("{line}");
    println!();
}

/// Success with package list
pub fn print_success_with_packages(msg: &str, packages: &[String]) {
    if output_mode() == OutputMode::Quiet {
        return;
    }
    println!();
    if crate::cli::style::colors_enabled() {
        println!("  {} {}", "✓".green().bold(), msg.bold());
    } else {
        println!("  ✓ {msg}");
    }

    // Show up to 10 packages, then summarize
    let show_limit = 10;
    for pkg in packages.iter().take(show_limit) {
        if crate::cli::style::colors_enabled() {
            println!("    {} {}", "·".dimmed(), pkg.cyan());
        } else {
            println!("    · {pkg}");
        }
    }

    if packages.len() > show_limit {
        if crate::cli::style::colors_enabled() {
            println!(
                "    {} {} more packages",
                "·".dimmed(),
                (packages.len() - show_limit).to_string().dimmed()
            );
        } else {
            println!("    · {} more packages", packages.len() - show_limit);
        }
    }
    println!();
}

/// Error state - clean X with message
pub fn print_error(msg: &str) {
    let line = if crate::cli::style::colors_enabled() {
        format!("\n  {} {}\n", "✗".red().bold(), msg)
    } else {
        format!("\n  ✗ {msg}\n")
    };
    emit_or_defer(line);
}

/// Warning state - subtle warning indicator
pub fn print_warning(msg: &str) {
    let line = if crate::cli::style::colors_enabled() {
        format!("\n  {} {}\n", "!".yellow().bold(), msg)
    } else {
        format!("\n  ! {msg}\n")
    };
    emit_or_defer(line);
}

/// Info message - neutral informational
pub fn print_info(msg: &str) {
    if output_mode() == OutputMode::Quiet {
        return;
    }
    let line = if crate::cli::style::colors_enabled() {
        format!("  {} {}", "·".blue(), msg.dimmed())
    } else {
        format!("  · {msg}")
    };
    emit_or_defer(line);
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PACKAGE OPERATIONS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// UPDATE OPERATIONS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Print update summary (pnpm-style)
pub fn print_update_summary(updates: &[crate::package_managers::types::UpdateInfo]) {
    if output_mode() == OutputMode::Quiet {
        return;
    }
    println!();

    let total = updates.len();
    if crate::cli::style::colors_enabled() {
        println!(
            "  {} {} {}",
            accent_bar(),
            total.to_string().bold(),
            if total == 1 {
                "update available"
            } else {
                "updates available"
            }
            .dimmed()
        );
    } else {
        println!(
            "  | {total} {}",
            if total == 1 {
                "update available"
            } else {
                "updates available"
            }
        );
    }

    println!();

    // Group by source
    let official_count = updates.iter().filter(|u| u.repo != "AUR").count();
    let aur_count = updates.iter().filter(|u| u.repo == "AUR").count();

    if official_count > 0 {
        if crate::cli::style::colors_enabled() {
            println!(
                "    {} official packages",
                official_count.to_string().cyan()
            );
        } else {
            println!("    {official_count} official packages");
        }
    }

    if aur_count > 0 {
        if crate::cli::style::colors_enabled() {
            println!("    {} AUR packages", aur_count.to_string().magenta());
        } else {
            println!("    {aur_count} AUR packages");
        }
    }

    println!();

    // Show sample of updates (up to 15), one line each with the source
    // badge inline so long update lists stay scannable.
    let display_limit = SUMMARY_LIST_CAP;
    for update in updates.iter().take(display_limit) {
        let name = crate::cli::style::sanitize_terminal_text(&update.name);
        let old_version = crate::cli::style::sanitize_terminal_text(&update.old_version);
        let new_version = crate::cli::style::sanitize_terminal_text(&update.new_version);
        let repo = crate::cli::style::sanitize_terminal_text(&update.repo);

        if crate::cli::style::colors_enabled() {
            let repo_badge = if update.repo == "AUR" {
                "aur".magenta().to_string()
            } else {
                repo.as_str().dimmed().to_string()
            };

            println!(
                "    {} {} {} {} {}",
                name.cyan(),
                old_version.dimmed(),
                "→".dimmed(),
                new_version.green(),
                repo_badge
            );
        } else {
            println!("    {name} {old_version} → {new_version} ({repo})");
        }
    }

    if updates.len() > display_limit {
        println!();
        if crate::cli::style::colors_enabled() {
            println!(
                "    {} and {} more",
                "·".dimmed(),
                (updates.len() - display_limit).to_string().dimmed()
            );
        } else {
            println!("    · and {} more", updates.len() - display_limit);
        }
    }

    println!();
}

/// Print "up to date" status
pub fn print_up_to_date() {
    println!();
    if crate::cli::style::colors_enabled() {
        println!(
            "  {} {}",
            crate::cli::chrome::accent_rail(),
            "System is up to date".green().bold()
        );
    } else {
        println!("  | System is up to date");
    }
    println!();
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// AUR-SPECIFIC
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// One-line AUR identity. The PKGBUILD itself is opt-in at review time.
pub fn print_aur_package_info(name: &str, version: &str, _description: &str) {
    if output_mode() == OutputMode::Quiet {
        return;
    }
    emit_or_defer(aur_package_info_line(name, version));
}

pub(crate) fn aur_package_info_line(name: &str, version: &str) -> String {
    let name = crate::cli::style::sanitize_terminal_text(name);
    let version = crate::cli::style::sanitize_terminal_text(version);
    if crate::cli::style::colors_enabled() {
        format!(
            "  {}  {}  {}  {}",
            crate::cli::chrome::accent_rail(),
            "AUR".bold(),
            name.cyan().bold(),
            version.green()
        )
    } else {
        format!("  |  AUR  {name}  {version}")
    }
}

/// Print AUR build progress phase
pub fn print_aur_build_phase(phase: &str, package: &str) {
    if output_mode() == OutputMode::Quiet {
        return;
    }
    let package = crate::cli::style::sanitize_terminal_text(package);
    if crate::cli::style::colors_enabled() {
        println!("  {} {} {}", "·".magenta(), phase.dimmed(), package.cyan());
    } else {
        println!("  · {phase} {package}");
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// TIMING & STATS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use indicatif::{ProgressDrawTarget, ProgressStyle, TermLike};
    use std::io;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Debug, Default)]
    pub(crate) struct RecordingTerm {
        events: Arc<Mutex<Vec<String>>>,
    }

    impl RecordingTerm {
        fn record(&self, event: impl Into<String>) {
            self.events
                .lock()
                .expect("recording terminal lock")
                .push(event.into());
        }

        fn events(&self) -> Vec<String> {
            self.events.lock().expect("recording terminal lock").clone()
        }
    }

    impl RecordingTerm {
        pub(crate) fn writes(&self) -> Vec<String> {
            self.events()
                .iter()
                .filter_map(|event| {
                    event
                        .strip_prefix("write:")
                        .or_else(|| event.strip_prefix("line:"))
                })
                .map(|text| console::strip_ansi_codes(text).into_owned())
                .filter(|text| !text.trim().is_empty())
                .collect()
        }
    }

    pub(crate) fn recording_completion_terminal() -> RecordingTerm {
        let terminal = RecordingTerm::default();
        progress_registry()
            .set_draw_target(ProgressDrawTarget::term_like(Box::new(terminal.clone())));
        OUTPUT_MODE.store(OutputMode::Interactive as u8, Ordering::Relaxed);
        terminal
    }

    impl TermLike for RecordingTerm {
        fn width(&self) -> u16 {
            120
        }

        fn move_cursor_up(&self, lines: usize) -> io::Result<()> {
            self.record(format!("up:{lines}"));
            Ok(())
        }

        fn move_cursor_down(&self, lines: usize) -> io::Result<()> {
            self.record(format!("down:{lines}"));
            Ok(())
        }

        fn move_cursor_right(&self, columns: usize) -> io::Result<()> {
            self.record(format!("right:{columns}"));
            Ok(())
        }

        fn move_cursor_left(&self, columns: usize) -> io::Result<()> {
            self.record(format!("left:{columns}"));
            Ok(())
        }

        fn write_line(&self, text: &str) -> io::Result<()> {
            self.record(format!("line:{text}"));
            Ok(())
        }

        fn write_str(&self, text: &str) -> io::Result<()> {
            self.record(format!("write:{text}"));
            Ok(())
        }

        fn clear_line(&self) -> io::Result<()> {
            self.record("clear");
            Ok(())
        }

        fn flush(&self) -> io::Result<()> {
            self.record("flush");
            Ok(())
        }
    }

    fn recording_spinner(message: &str) -> (ProgressBar, RecordingTerm) {
        configure_output(0, false);
        let terminal = RecordingTerm::default();
        let progress = ProgressBar::with_draw_target(
            None,
            ProgressDrawTarget::term_like(Box::new(terminal.clone())),
        );
        progress.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner} {msg}")
                .expect("static progress template"),
        );
        progress.set_message(message.to_string());
        progress.tick();
        (progress, terminal)
    }

    #[test]
    fn hiding_progress_clears_existing_rows_before_a_prompt() {
        let terminal = RecordingTerm::default();
        let progress = MultiProgress::with_draw_target(ProgressDrawTarget::term_like(Box::new(
            terminal.clone(),
        )));
        let spinner = progress.add(ProgressBar::new_spinner());
        spinner.set_message("active build");
        spinner.tick();
        let event_count = terminal.events().len();

        hide_progress(&progress);

        assert!(
            terminal.events()[event_count..]
                .iter()
                .any(|event| event == "clear"),
            "an existing progress row must be erased before prompt rendering"
        );
    }

    #[test]
    #[serial_test::serial]
    fn register_spinner_detaches_the_incoming_draw_target() {
        OUTPUT_MODE.store(OutputMode::Interactive as u8, Ordering::Relaxed);
        let terminal = RecordingTerm::default();
        let bar = ProgressBar::with_draw_target(
            None,
            ProgressDrawTarget::term_like(Box::new(terminal.clone())),
        );
        bar.set_message("Syncing package databases");
        bar.tick();
        assert!(
            !terminal.events().is_empty(),
            "fixture bar must draw before registration"
        );
        let registered = register_spinner(bar);
        let after_register = terminal.events().len();
        registered.tick();
        registered.finish_and_clear();
        OUTPUT_MODE.store(OutputMode::Plain as u8, Ordering::Relaxed);
        assert_eq!(
            terminal.events().len(),
            after_register,
            "ticks after registration must not keep drawing on the orphan target"
        );
    }

    #[test]
    #[serial_test::serial]
    fn finished_spinner_clears_its_animated_lane() {
        if crate::core::testing::run_isolated_test(
            "cli::modern_ui::tests::finished_spinner_clears_its_animated_lane",
        ) {
            return;
        }
        let (progress, terminal) = recording_spinner("Checking package sources");
        let completion = recording_completion_terminal();

        finish_success(&progress, "Checked", "package sources");
        assert!(progress.is_finished());
        assert_eq!(completion.writes(), ["✓ Checked package sources"]);

        let events = terminal.events();
        assert!(
            !events
                .iter()
                .any(|event| event.contains("Checked package sources")),
            "completed status must be durable output, not a retained animation lane: {events:?}"
        );
    }

    #[test]
    #[serial_test::serial]
    fn finished_info_spinner_clears_its_animated_lane() {
        if crate::core::testing::run_isolated_test(
            "cli::modern_ui::tests::finished_info_spinner_clears_its_animated_lane",
        ) {
            return;
        }
        let (progress, terminal) = recording_spinner("Checking official repositories");
        let completion = recording_completion_terminal();

        finish_info(&progress, "No updates in official repositories");
        assert!(progress.is_finished());
        assert_eq!(
            completion.writes(),
            ["· No updates in official repositories"]
        );

        let events = terminal.events();
        assert!(
            !events.iter().any(|event| event.contains("No updates")),
            "completed status must be durable output, not a retained animation lane: {events:?}"
        );
    }

    #[test]
    #[serial_test::serial]
    fn quiet_spinners_are_hidden() {
        configure_output(0, true);
        assert_eq!(output_mode(), OutputMode::Quiet);
        let progress = modern_spinner("phase", "action");
        assert!(progress.is_hidden());
        configure_output(0, false);
    }

    #[test]
    fn output_policy_prioritizes_quiet_and_verbose() {
        assert_eq!(output_mode_for(0, true, true), OutputMode::Quiet);
        assert_eq!(output_mode_for(1, false, true), OutputMode::Verbose);
        assert_eq!(output_mode_for(0, false, true), OutputMode::Interactive);
        assert_eq!(output_mode_for(0, false, false), OutputMode::Plain);
    }

    #[test]
    fn elapsed_time_stays_compact() {
        assert_eq!(format_duration(Duration::from_secs(9)), "9s");
        assert_eq!(format_duration(Duration::from_secs(125)), "2m 05s");
        assert_eq!(format_duration(Duration::from_secs(3_725)), "1h 02m 05s");
    }

    #[test]
    fn phase_header_uses_a_bar_instead_of_emoji() {
        let text = phase_header_text("Install", "3 packages");
        assert!(!text.contains('📦'));
        assert!(text.contains("Install"));
        assert!(text.contains("3 packages"));
        assert!(text.contains('|') || text.contains('│') || text.contains('┃'));
    }

    #[test]
    fn update_check_header_still_says_checking_for_updates() {
        let text = phase_header_text("Update", "Checking for updates");
        assert!(text.contains("Checking for updates"));
    }

    #[test]
    #[serial_test::serial]
    fn aur_package_info_is_one_line() {
        temp_env::with_var("NO_COLOR", Some("1"), || {
            let line = aur_package_info_line("foo\x1b]0;pwn", "1.0-1");
            assert_eq!(line, "  |  AUR  foo]0;pwn  1.0-1");
            assert!(!line.contains('\n'));
            assert!(!line.contains("User-submitted"));
        });
    }
}
