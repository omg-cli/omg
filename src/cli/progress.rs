//! Typed, Charm-inspired progress lanes.
//!
//! Every unit of work is a [`ProgressTask`] created from a [`TaskSpec`]. Lanes
//! join the process-wide registry owned by [`crate::cli::modern_ui`], so an
//! interactive prompt can quiesce them all at once. Animation draws to stderr;
//! the durable result line printed by [`ProgressTask::finish`] goes to stdout
//! and defers while the terminal is quiesced. Raw indicatif types stay inside
//! this module.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use owo_colors::OwoColorize;

use crate::cli::modern_ui::{self, OutputMode};
use crate::cli::style;

/// Shape of work one lane renders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TaskKind {
    /// Indeterminate work with no figures beyond the label and message.
    #[cfg_attr(
        not(feature = "arch"),
        allow(dead_code, reason = "ALPM download lane is Arch-only")
    )]
    Spinner,
    /// Byte-oriented work. The total may arrive after the lane starts, so a
    /// pending lane renders as a spinner until the total is known.
    Bytes { total: Option<u64> },
    /// Countable steps.
    Items { total: u64 },
}

/// Restrained accent palette for lane glyphs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Accent {
    Network,
    #[cfg_attr(
        not(feature = "arch"),
        allow(dead_code, reason = "constructed by the Arch database-sync lane")
    )]
    Database,
    System,
}

/// Description of one unit of work.
#[derive(Debug, Clone)]
pub(crate) struct TaskSpec {
    pub(crate) label: String,
    pub(crate) kind: TaskKind,
    pub(crate) accent: Accent,
}

/// Terminal state of one lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    Done,
    Failed,
}

const TICKS_UNICODE: &str = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏";
const TICKS_ASCII: &str = "-\\|/";
const BAR_CHARS_UNICODE: &str = "█▓▒░ ";
const BAR_CHARS_ASCII: &str = "=>- ";
const BYTES_FIGURES: &str = "{bytes}/{total_bytes} {eta}";
const ITEMS_FIGURES: &str = "{pos}/{len}";
const STEADY_TICK: Duration = Duration::from_millis(80);

fn accent_color(accent: Accent) -> &'static str {
    match accent {
        Accent::Network => "cyan",
        Accent::Database => "blue",
        Accent::System => "green",
    }
}

fn visible(mode: OutputMode) -> bool {
    mode == OutputMode::Interactive
}

fn spinner_template(accent: Accent, colored: bool) -> String {
    if colored {
        format!(
            "  {{spinner:.{c}.bold}} {{prefix:.bold}} {{msg:.dim}}",
            c = accent_color(accent)
        )
    } else {
        "  {spinner} {prefix} {msg}".to_string()
    }
}

fn pending_bytes_template(accent: Accent, colored: bool) -> String {
    if colored {
        format!(
            "  {{spinner:.{c}.bold}} {{prefix:.bold}} {{bytes:.dim}} {{msg:.dim}}",
            c = accent_color(accent)
        )
    } else {
        "  {spinner} {prefix} {bytes} {msg}".to_string()
    }
}

fn meter_template(accent: Accent, figures: &str, colored: bool) -> String {
    if colored {
        format!(
            "  {{spinner:.{c}.bold}} {{prefix:.bold}} [{{bar:24.{c}}}] {figures} {{msg:.dim}}",
            c = accent_color(accent)
        )
    } else {
        format!("  {{spinner}} {{prefix}} [{{bar:24}}] {figures} {{msg}}")
    }
}

fn spinner_style(accent: Accent) -> ProgressStyle {
    spinner_base(&spinner_template(accent, style::colors_enabled()))
}

fn pending_bytes_style(accent: Accent) -> ProgressStyle {
    spinner_base(&pending_bytes_template(accent, style::colors_enabled()))
}

fn meter_style(accent: Accent, figures: &str) -> ProgressStyle {
    #[expect(clippy::expect_used, reason = "lane templates are static constants")]
    let style = ProgressStyle::default_bar()
        .template(&meter_template(accent, figures, style::colors_enabled()))
        .expect("static lane template")
        .progress_chars(if style::use_unicode() {
            BAR_CHARS_UNICODE
        } else {
            BAR_CHARS_ASCII
        });
    style
}

#[expect(clippy::expect_used, reason = "static lane templates are constants")]
fn spinner_base(template: &str) -> ProgressStyle {
    ProgressStyle::default_spinner()
        .template(template)
        .expect("static lane template")
        .tick_chars(if style::use_unicode() {
            TICKS_UNICODE
        } else {
            TICKS_ASCII
        })
}

#[derive(Debug)]
struct Inner {
    bar: Mutex<Option<ProgressBar>>,
    label: Mutex<String>,
    accent: Accent,
    mode: OutputMode,
    started: Instant,
}

/// Opaque handle over one task lifecycle.
///
/// Clones share the same lane. The lane is finished exactly once: the first
/// [`finish`](ProgressTask::finish) wins, later calls are no-ops, and dropping
/// the last unfinished clone clears the bar so error paths never leave stale
/// animation behind.
#[derive(Clone, Debug)]
pub(crate) struct ProgressTask {
    inner: Arc<Inner>,
}

fn lock_bar(inner: &Inner) -> MutexGuard<'_, Option<ProgressBar>> {
    inner.bar.lock().unwrap_or_else(PoisonError::into_inner)
}

fn sanitize_label(label: &str) -> String {
    style::sanitize_terminal_text(label)
}

fn hidden_spinner() -> ProgressBar {
    ProgressBar::with_draw_target(None, ProgressDrawTarget::hidden())
}

fn hidden_bar(total: u64) -> ProgressBar {
    ProgressBar::with_draw_target(Some(total), ProgressDrawTarget::hidden())
}

impl ProgressTask {
    /// Start a lane according to the current rendering policy.
    ///
    /// Only [`OutputMode::Interactive`] attaches a visible lane; every other
    /// mode drives an invisible bar so callers keep one code path.
    #[must_use]
    pub(crate) fn start(spec: &TaskSpec) -> Self {
        let mode = modern_ui::output_mode();
        let label = sanitize_label(&spec.label);
        let bar = match &spec.kind {
            TaskKind::Spinner => {
                let bar = hidden_spinner();
                bar.set_style(spinner_style(spec.accent));
                bar
            }
            TaskKind::Bytes { total } => match total {
                Some(total) if *total > 0 => {
                    let bar = hidden_bar(*total);
                    bar.set_style(meter_style(spec.accent, BYTES_FIGURES));
                    bar
                }
                _ => {
                    let bar = hidden_spinner();
                    bar.set_style(pending_bytes_style(spec.accent));
                    bar
                }
            },
            TaskKind::Items { total } => {
                let bar = hidden_bar(*total);
                bar.set_style(meter_style(spec.accent, ITEMS_FIGURES));
                bar
            }
        };
        bar.set_prefix(label.clone());
        let bar = modern_ui::register_spinner(bar);
        if visible(mode) {
            bar.enable_steady_tick(STEADY_TICK);
        }
        Self {
            inner: Arc::new(Inner {
                bar: Mutex::new(Some(bar)),
                label: Mutex::new(label),
                accent: spec.accent,
                mode,
                started: Instant::now(),
            }),
        }
    }

    /// Replace the lane's dynamic detail text.
    pub(crate) fn set_message(&self, message: &str) {
        let message = sanitize_label(message);
        let bar_guard = lock_bar(&self.inner);
        if let Some(bar) = bar_guard.as_ref() {
            bar.set_message(message);
        }
    }

    /// Set or promote the total of a byte lane. A lane created without a total
    /// switches from the pending spinner to a determinate meter here.
    pub(crate) fn set_total(&self, total: Option<u64>) {
        let Some(total) = total else { return };
        let bar_guard = lock_bar(&self.inner);
        let Some(bar) = bar_guard.as_ref() else {
            return;
        };
        if bar.length().is_none() {
            bar.set_style(meter_style(self.inner.accent, BYTES_FIGURES));
        }
        bar.set_length(total);
    }

    pub(crate) fn set_position(&self, position: u64) {
        let bar_guard = lock_bar(&self.inner);
        if let Some(bar) = bar_guard.as_ref() {
            bar.set_position(position);
        }
    }

    pub(crate) fn inc(&self, delta: u64) {
        let bar_guard = lock_bar(&self.inner);
        if let Some(bar) = bar_guard.as_ref() {
            bar.inc(delta);
        }
    }

    /// Clear the lane without printing a durable result line, for callers that
    /// report the outcome through their own summary lines.
    pub(crate) fn clear(&self) {
        let taken = lock_bar(&self.inner).take();
        if let Some(bar) = taken {
            bar.finish_and_clear();
        }
    }

    /// Finish the lane exactly once and print its durable result line on
    /// stdout (deferred while the terminal is quiesced, suppressed when
    /// quiet). Later calls on any clone are no-ops.
    pub(crate) fn finish(&self, outcome: Outcome) {
        let mut bar_guard = lock_bar(&self.inner);
        let Some(bar) = bar_guard.take() else {
            return;
        };
        bar.finish_and_clear();
        if self.inner.mode == OutputMode::Quiet {
            return;
        }
        let label = self.lock_label().clone();
        let elapsed = modern_ui::format_duration(self.inner.started.elapsed());
        modern_ui::emit_or_defer(result_line(outcome, &label, &elapsed));
    }

    fn lock_label(&self) -> MutexGuard<'_, String> {
        self.inner
            .label
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl Drop for ProgressTask {
    fn drop(&mut self) {
        // Only the last surviving clone clears the lane; earlier drops belong
        // to workers that handed the lane off.
        if Arc::strong_count(&self.inner) != 1 {
            return;
        }
        let taken = lock_bar(&self.inner).take();
        if let Some(bar) = taken {
            bar.finish_and_clear();
        }
    }
}

fn result_line(outcome: Outcome, label: &str, elapsed: &str) -> String {
    if style::colors_enabled() {
        match outcome {
            Outcome::Done => {
                format!(
                    "  {} {} {}",
                    "✓".green().bold(),
                    label,
                    format!("· {elapsed}").dimmed()
                )
            }
            Outcome::Failed => {
                format!(
                    "  {} {} {}",
                    "✗".red().bold(),
                    label,
                    format!("· {elapsed}").dimmed()
                )
            }
        }
    } else {
        match outcome {
            Outcome::Done => format!("  ✓ {label} · {elapsed}"),
            Outcome::Failed => format!("  ✗ {label} · {elapsed}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn spec(label: &str, kind: TaskKind) -> TaskSpec {
        TaskSpec {
            label: label.to_string(),
            kind,
            accent: Accent::Network,
        }
    }

    #[test]
    fn only_interactive_modes_show_lanes() {
        assert!(visible(OutputMode::Interactive));
        assert!(!visible(OutputMode::Quiet));
        assert!(!visible(OutputMode::Plain));
        assert!(!visible(OutputMode::Verbose));
    }

    #[test]
    #[serial]
    fn quiet_lanes_are_invisible() {
        modern_ui::configure_output(0, true);
        let task = ProgressTask::start(&spec("db", TaskKind::Bytes { total: Some(10) }));
        let bar = lock_bar(&task.inner).clone().expect("lane exists");
        assert!(bar.is_hidden());
        modern_ui::configure_output(0, false);
    }

    #[test]
    #[serial]
    fn labels_are_sanitized_inside_the_handle() {
        modern_ui::configure_output(0, false);
        let task = ProgressTask::start(&spec(
            "core\x1b]0;pwn\u{202e}db",
            TaskKind::Bytes { total: None },
        ));
        let label = task.lock_label().clone();
        assert_eq!(
            label,
            style::sanitize_terminal_text("core\x1b]0;pwn\u{202e}db")
        );
        assert!(!label.contains('\u{1b}'));

        task.set_message("retry \u{2066}2\u{2069}");
        let bar = lock_bar(&task.inner).clone().expect("lane exists");
        assert_eq!(
            bar.message(),
            style::sanitize_terminal_text("retry \u{2066}2\u{2069}")
        );
        modern_ui::configure_output(0, false);
    }

    #[test]
    #[serial]
    fn late_total_promotes_a_pending_bytes_lane() {
        modern_ui::configure_output(0, false);
        let task = ProgressTask::start(&spec("dl", TaskKind::Bytes { total: None }));
        let bar = lock_bar(&task.inner).clone().expect("lane exists");
        assert!(bar.length().is_none());

        task.set_total(Some(100));
        assert_eq!(bar.length(), Some(100));
        task.set_position(40);
        assert_eq!(bar.position(), 40);
        task.inc(10);
        assert_eq!(bar.position(), 50);
        modern_ui::configure_output(0, false);
    }

    #[test]
    #[serial]
    fn finish_is_once_across_clones() {
        modern_ui::configure_output(0, false);
        let task = ProgressTask::start(&spec("db", TaskKind::Items { total: 3 }));
        let clone = task.clone();
        let bar = lock_bar(&task.inner).clone().expect("lane exists");

        task.finish(Outcome::Done);
        assert!(lock_bar(&task.inner).is_none());
        assert!(bar.is_finished());

        // A second finish through another clone must not re-print or re-finish.
        clone.finish(Outcome::Failed);
        assert!(lock_bar(&task.inner).is_none());
        modern_ui::configure_output(0, false);
    }

    #[test]
    #[serial]
    fn dropping_the_last_unfinished_clone_clears_the_lane() {
        modern_ui::configure_output(0, false);
        let task = ProgressTask::start(&spec("db", TaskKind::Items { total: 3 }));
        let clone = task.clone();
        let bar = lock_bar(&task.inner).clone().expect("lane exists");

        drop(clone);
        assert!(!bar.is_finished(), "a surviving clone keeps the lane alive");

        drop(task);
        assert!(bar.is_finished(), "the last drop clears the lane");
        modern_ui::configure_output(0, false);
    }

    #[test]
    fn all_lane_templates_are_valid_indicatif_templates() {
        let accents = [Accent::Network, Accent::Database, Accent::System];
        for accent in accents {
            for colored in [true, false] {
                ProgressStyle::with_template(&spinner_template(accent, colored))
                    .expect("spinner template");
                ProgressStyle::with_template(&pending_bytes_template(accent, colored))
                    .expect("pending bytes template");
                for figures in [BYTES_FIGURES, ITEMS_FIGURES] {
                    ProgressStyle::with_template(&meter_template(accent, figures, colored))
                        .expect("meter template");
                }
            }
        }
    }
}
