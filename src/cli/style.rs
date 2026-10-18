//! Consistent styling utilities for OMG CLI output
//!
//! All output should use these helpers for consistent UX.
//!
//! ## Features
//! - **`NO_COLOR` support**: Respects the [NO_COLOR standard](https://no-color.org/)
//! - **TTY detection**: Auto-detects terminal capabilities
//! - **Accessibility**: WCAG AA compliant contrast ratios

use std::env;
#[cfg(not(test))]
use std::sync::OnceLock;

use indicatif::{ProgressBar, ProgressStyle};
use owo_colors::OwoColorize;
use supports_color::Stream;

// ═══════════════════════════════════════════════════════════════════════════
// COLOR DETECTION & CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(not(test))]
static COLORS_ENABLED_CACHE: OnceLock<bool> = OnceLock::new();
#[cfg(not(test))]
static USE_UNICODE_CACHE: OnceLock<bool> = OnceLock::new();

/// Detect if colors should be enabled
///
/// Follows the [NO_COLOR standard](https://no-color.org/) and detects TTY support.
#[must_use]
pub fn colors_enabled() -> bool {
    #[cfg(test)]
    {
        detect_colors_enabled()
    }

    #[cfg(not(test))]
    {
        *COLORS_ENABLED_CACHE.get_or_init(detect_colors_enabled)
    }
}

fn detect_colors_enabled() -> bool {
    if env::var("NO_COLOR").is_ok() {
        return false;
    }

    // 2. Check if OMG_COLORS is explicitly disabled
    if let Ok(val) = env::var("OMG_COLORS") {
        if matches!(val.as_str(), "never" | "0" | "false") {
            return false;
        }
        if matches!(val.as_str(), "always" | "1" | "true") {
            return true;
        }
    }

    // 3. Check terminal capabilities via supports-color crate
    supports_color::on(Stream::Stdout).is_some_and(|level| level.has_basic)
}

/// Check if unicode icons should be used
#[must_use]
pub fn use_unicode() -> bool {
    #[cfg(test)]
    {
        detect_use_unicode()
    }

    #[cfg(not(test))]
    {
        *USE_UNICODE_CACHE.get_or_init(detect_use_unicode)
    }
}

fn detect_use_unicode() -> bool {
    if let Ok(val) = env::var("OMG_UNICODE") {
        return val != "0" && val != "false";
    }

    colors_enabled()
}

// ═══════════════════════════════════════════════════════════════════════════
// CONDITIONAL STYLING HELPERS
// ═══════════════════════════════════════════════════════════════════════════

/// Apply color only if colors are enabled
#[inline]
#[must_use]
pub fn maybe_color(text: &str, f: impl Fn(&str) -> String) -> String {
    if colors_enabled() {
        f(text)
    } else {
        text.to_string()
    }
}

/// Get an icon (unicode or ASCII fallback)
#[inline]
#[must_use]
fn icon(unicode: &str, ascii: &str) -> String {
    if use_unicode() {
        unicode.to_string()
    } else {
        ascii.to_string()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TEXT FORMATTING
// ═══════════════════════════════════════════════════════════════════════════

/// Header with arrow prefix (e.g., "==> Installing packages")
#[must_use]
pub fn header(msg: &str) -> String {
    maybe_color(msg, |m| format!("{} {}", "==>".magenta().bold(), m.bold()))
}

fn strip_status_prefix<'a>(message: &'a str, unicode: &str) -> &'a str {
    message
        .strip_prefix(unicode)
        .map_or(message, str::trim_start)
}

/// Success message with checkmark
#[must_use]
pub fn success(msg: &str) -> String {
    maybe_color(msg, |message| {
        let message = strip_status_prefix(message, "✓");
        let icon = icon("✓", "OK").green().bold().to_string();
        if message.is_empty() {
            icon
        } else {
            format!("{icon} {message}")
        }
    })
}

/// Error message with X
#[must_use]
pub fn error(msg: &str) -> String {
    maybe_color(msg, |message| {
        let message = strip_status_prefix(message, "✗");
        let icon = icon("✗", "X").red().bold().to_string();
        if message.is_empty() {
            icon
        } else {
            format!("{icon} {message}")
        }
    })
}

/// Info message with i
#[must_use]
pub fn info(msg: &str) -> String {
    maybe_color(msg, |message| {
        let message = strip_status_prefix(message, "ℹ");
        let icon = icon("ℹ", "i").blue().bold().to_string();
        if message.is_empty() {
            icon
        } else {
            format!("{icon} {message}")
        }
    })
}

/// Warning message with triangle
#[must_use]
pub fn warning(msg: &str) -> String {
    maybe_color(msg, |message| {
        let message = strip_status_prefix(message, "⚠");
        let icon = icon("⚠", "!").yellow().bold().to_string();
        if message.is_empty() {
            icon
        } else {
            format!("{icon} {message}")
        }
    })
}

/// Arrow prefix for sub-items
#[must_use]
pub fn arrow(msg: &str) -> String {
    maybe_color(msg, |m| format!("{} {}", icon("→", ">").cyan().bold(), m))
}

/// Bold text for labels and totals.
#[must_use]
pub fn emphasis(msg: &str) -> String {
    maybe_color(msg, |message| message.bold().to_string())
}

/// Cyan accent text for identifiers and directional markers.
#[must_use]
pub fn accent(msg: &str) -> String {
    maybe_color(msg, |message| message.cyan().to_string())
}

/// Green text for positive state without adding an icon.
#[must_use]
pub fn positive(msg: &str) -> String {
    maybe_color(msg, |message| message.green().to_string())
}

/// Red text for negative state without adding an icon.
#[must_use]
pub fn negative(msg: &str) -> String {
    maybe_color(msg, |message| message.red().to_string())
}

/// Yellow text for caution state without adding an icon.
#[must_use]
pub fn caution(msg: &str) -> String {
    maybe_color(msg, |message| message.yellow().to_string())
}

/// Magenta accent text for community-provided values.
#[must_use]
pub fn community(msg: &str) -> String {
    maybe_color(msg, |message| message.magenta().to_string())
}

/// Blue informational text without adding a status icon.
#[must_use]
pub fn informative(msg: &str) -> String {
    maybe_color(msg, |message| message.blue().to_string())
}

/// Dimmed/muted text.
#[must_use]
pub fn dim(msg: &str) -> String {
    maybe_color(msg, |m| m.dimmed().to_string())
}

/// Inline code/command formatting
#[must_use]
pub fn command(cmd: &str) -> String {
    maybe_color(cmd, |c| format!("`{}`", c.cyan()))
}

/// Remove terminal-control and bidi-override characters from remote text.
///
/// Package metadata is untrusted and must not move the cursor, set terminal
/// state, create hidden OSC links, reorder the visible command line, or
/// smuggle invisible characters that spoof visible content.
#[must_use]
pub fn sanitize_terminal_text(text: &str) -> String {
    text.chars()
        .filter(|character| {
            !character.is_control()
                && !matches!(
                    character,
                    // Bidi embedding/override/isolate (Trojan Source class)
                    '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                        // Zero-width + invisible formatting (LRM/RLM/ZWJ/WJ)
                        | '\u{200b}'..='\u{200f}'
                        | '\u{2060}'..='\u{2064}'
                        // Unicode line/paragraph separator (breaks single-line layout)
                        | '\u{2028}' | '\u{2029}'
                        // Zero-width no-break space / BOM in the middle of text
                        | '\u{feff}'
                )
        })
        .collect()
}

/// URL formatting (underlined blue)
#[must_use]
pub fn url(link: &str) -> String {
    maybe_color(link, |l| l.underline().blue().to_string())
}

/// Package name (bold white)
#[must_use]
pub fn package(name: &str) -> String {
    maybe_color(name, |n| n.white().bold().to_string())
}

/// Version string (green)
#[must_use]
pub fn version(ver: &str) -> String {
    maybe_color(ver, |v| v.green().to_string())
}

/// Runtime name (cyan)
#[must_use]
pub fn runtime(name: &str) -> String {
    maybe_color(name, |n| n.cyan().bold().to_string())
}

/// File path (yellow)
#[must_use]
pub fn path(p: &str) -> String {
    maybe_color(p, |path| path.yellow().to_string())
}

/// Size formatting (e.g., "1.5 MB")
#[must_use]
pub fn size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / 1024.0 / 1024.0)
    } else {
        format!("{:.2} GB", bytes as f64 / 1024.0 / 1024.0 / 1024.0)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PROGRESS INDICATORS
// ═══════════════════════════════════════════════════════════════════════════

/// Create a spinner for indeterminate progress
#[must_use]
#[expect(clippy::expect_used, clippy::literal_string_with_formatting_args)] // Static indicatif templates are always valid; braces are template syntax not Rust format args
pub fn spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();

    // Use appropriate spinner style based on terminal capabilities
    let tick_chars = if use_unicode() {
        "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    } else {
        "-\\|/"
    };

    let template = if colors_enabled() {
        "{spinner:.cyan} {msg}"
    } else {
        "{spinner} {msg}"
    };

    pb.set_style(
        ProgressStyle::default_spinner()
            .template(template)
            .expect("static template")
            .tick_chars(tick_chars),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(std::time::Duration::from_millis(80));
    pb
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use temp_env;

    #[test]
    #[serial]
    fn test_no_color_disables_colors() {
        temp_env::with_var("NO_COLOR", Some("1"), || {
            assert!(!colors_enabled());
        });
    }

    #[test]
    #[serial]
    fn test_omg_colors_always_enables() {
        temp_env::with_vars([("NO_COLOR", None), ("OMG_COLORS", Some("always"))], || {
            assert!(colors_enabled());
        });
        for alias in ["1", "true"] {
            temp_env::with_vars([("NO_COLOR", None), ("OMG_COLORS", Some(alias))], || {
                assert!(colors_enabled(), "OMG_COLORS={alias}");
            });
        }
    }

    #[test]
    #[serial]
    fn test_omg_colors_never_disables() {
        temp_env::with_var("OMG_COLORS", Some("never"), || {
            assert!(!colors_enabled());
        });
        for alias in ["0", "false"] {
            temp_env::with_vars([("NO_COLOR", None), ("OMG_COLORS", Some(alias))], || {
                assert!(!colors_enabled(), "OMG_COLORS={alias}");
            });
        }
    }

    #[test]
    #[serial]
    fn semantic_text_styles_are_plain_when_colors_are_disabled() {
        temp_env::with_var("NO_COLOR", Some("1"), || {
            for (rendered, expected) in [
                (emphasis("label"), "label"),
                (accent("accent"), "accent"),
                (positive("positive"), "positive"),
                (negative("negative"), "negative"),
                (caution("caution"), "caution"),
                (community("community"), "community"),
                (informative("informative"), "informative"),
            ] {
                assert!(!rendered.contains("\u{1b}["), "{rendered:?}");
                assert_eq!(rendered, expected);
            }
        });
    }

    #[test]
    #[serial]
    fn semantic_text_styles_honor_forced_color() {
        temp_env::with_vars([("NO_COLOR", None), ("OMG_COLORS", Some("always"))], || {
            for (rendered, expected) in [
                (emphasis("label"), "label"),
                (accent("accent"), "accent"),
                (positive("positive"), "positive"),
                (negative("negative"), "negative"),
                (caution("caution"), "caution"),
                (community("community"), "community"),
                (informative("informative"), "informative"),
            ] {
                assert!(rendered.contains("\u{1b}["), "{rendered:?}");
                assert_eq!(console::strip_ansi_codes(&rendered), expected);
            }
        });
    }

    #[test]
    #[serial]
    fn status_helpers_do_not_duplicate_existing_icons() {
        temp_env::with_vars(
            [
                ("NO_COLOR", None),
                ("OMG_COLORS", Some("always")),
                ("OMG_UNICODE", Some("1")),
            ],
            || {
                for (rendered, expected) in [
                    (success("completed"), "✓ completed"),
                    (error("failed"), "✗ failed"),
                    (warning("check this"), "⚠ check this"),
                    (info("details"), "ℹ details"),
                ] {
                    assert_eq!(console::strip_ansi_codes(&rendered), expected);
                }
                for (rendered, icon) in [
                    (success("✓"), '✓'),
                    (success("✓ completed"), '✓'),
                    (error("✗"), '✗'),
                    (warning("⚠"), '⚠'),
                    (info("ℹ"), 'ℹ'),
                ] {
                    assert_eq!(rendered.matches(icon).count(), 1, "{rendered:?}");
                }
            },
        );
        temp_env::with_vars(
            [
                ("NO_COLOR", None),
                ("OMG_COLORS", Some("always")),
                ("OMG_UNICODE", Some("0")),
            ],
            || {
                let rendered = success("✓ completed");
                assert!(!rendered.contains('✓'), "{rendered:?}");
                assert_eq!(rendered.matches("OK").count(), 1, "{rendered:?}");
            },
        );
    }

    #[test]
    fn test_sanitize_strips_terminal_control_and_osc_bytes() {
        let cleaned = sanitize_terminal_text("core\u{1b}]0;pwn\u{202e}db\u{7}");
        assert_eq!(cleaned, "core]0;pwndb");
        assert!(!cleaned.chars().any(char::is_control));
    }

    #[test]
    fn test_sanitize_strips_bidi_overrides_and_isolates() {
        let cleaned = sanitize_terminal_text("a\u{202a}b\u{202c}c\u{2066}d\u{2069}e");
        assert_eq!(cleaned, "abcde");
    }

    #[test]
    fn test_sanitize_strips_invisible_characters() {
        let cleaned = sanitize_terminal_text(
            "x\u{200b}y\u{200c}z\u{200d}w\u{200e}v\u{200f}u\u{2060}t\u{2061}s\u{2064}r\u{feff}q",
        );
        assert_eq!(cleaned, "xyzwvutsrq");
    }

    #[test]
    fn test_sanitize_strips_line_and_paragraph_separators() {
        let cleaned = sanitize_terminal_text("one\u{2028}two\u{2029}three");
        assert_eq!(cleaned, "onetwothree");
    }

    #[test]
    fn test_sanitize_preserves_visible_multibyte_text() {
        let cleaned = sanitize_terminal_text("v1.2.3 — ✓ 日本語 emoji 🎉 width →");
        assert_eq!(cleaned, "v1.2.3 — ✓ 日本語 emoji 🎉 width →");
    }

    #[test]
    fn test_unicode_icons() {
        temp_env::with_var("OMG_UNICODE", Some("1"), || {
            assert_eq!(icon("✓", "OK"), "✓");
        });

        temp_env::with_var("OMG_UNICODE", Some("0"), || {
            assert_eq!(icon("✓", "OK"), "OK");
        });
    }

    #[test]
    fn untrusted_terminal_text_cannot_emit_controls_or_bidi_overrides() {
        assert_eq!(
            sanitize_terminal_text("safe\x1b]52;c;secret\x07\ntext\u{202e}txt"),
            "safe]52;c;secrettexttxt"
        );
    }

    #[test]
    fn test_size_formatting() {
        assert_eq!(size(500), "500 B");
        assert_eq!(size(1024), "1.0 KB");
        assert_eq!(size(1024 * 1024), "1.0 MB");
        assert_eq!(size(1024 * 1024 * 1024), "1.00 GB");
    }
}
