//! Charm-inspired UI primitives for OMG CLI
//!
//! Provides high-polish components like cards, tips, and contextual headers.
//! Implements a "Lip Gloss" compatible API using owo-colors for the Bubble Tea feel.

use owo_colors::OwoColorize;
use std::fmt::Display;

/// Color palette matching Charm/Lipgloss true-color TUI needs.
/// Semantic variants resolve dynamically against the active Omarchy/Tokyo Night palette.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    Red,
    Green,
    Blue,
    Cyan,
    Yellow,
    Magenta,
    White,
    Black,
    Gray,
    Accent,
    Muted,
    Rgb(u8, u8, u8),
}

impl Color {
    fn to_rgb(self) -> (u8, u8, u8) {
        let p = crate::cli::chrome::palette();
        match self {
            Self::Red => (p.red.r, p.red.g, p.red.b),
            Self::Green => (p.green.r, p.green.g, p.green.b),
            Self::Blue => (p.blue.r, p.blue.g, p.blue.b),
            Self::Cyan => (p.cyan.r, p.cyan.g, p.cyan.b),
            Self::Yellow => (p.yellow.r, p.yellow.g, p.yellow.b),
            Self::Magenta => (p.magenta.r, p.magenta.g, p.magenta.b),
            Self::Accent => (p.accent.r, p.accent.g, p.accent.b),
            Self::Muted => (p.muted.r, p.muted.g, p.muted.b),
            Self::White => (0xf8, 0xf8, 0xf2),
            Self::Black => (0x1a, 0x1b, 0x26),
            Self::Gray => (0x79, 0x82, 0xa9),
            Self::Rgb(r, g, b) => (r, g, b),
        }
    }
}

/// A builder-pattern style struct mimicking Charm's Lipgloss.
#[derive(Debug, Clone, Default)]
pub struct Style {
    fg: Option<Color>,
    bg: Option<Color>,
    is_bold: bool,
    is_italic: bool,
    is_underline: bool,
    is_dim: bool,
    padding_left: usize,
    padding_right: usize,
}

impl Style {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn foreground(mut self, color: Color) -> Self {
        self.fg = Some(color);
        self
    }

    #[must_use]
    pub fn background(mut self, color: Color) -> Self {
        self.bg = Some(color);
        self
    }

    #[must_use]
    pub fn bold(mut self, yes: bool) -> Self {
        self.is_bold = yes;
        self
    }

    #[must_use]
    pub fn italic(mut self, yes: bool) -> Self {
        self.is_italic = yes;
        self
    }

    #[must_use]
    pub fn underline(mut self, yes: bool) -> Self {
        self.is_underline = yes;
        self
    }

    #[must_use]
    pub fn dim(mut self, yes: bool) -> Self {
        self.is_dim = yes;
        self
    }

    #[must_use]
    pub fn padding_left(mut self, n: usize) -> Self {
        self.padding_left = n;
        self
    }

    #[must_use]
    pub fn padding_right(mut self, n: usize) -> Self {
        self.padding_right = n;
        self
    }

    pub fn render<S: Display>(&self, text: S) -> String {
        let s = format!(
            "{}{}{}",
            " ".repeat(self.padding_left),
            text,
            " ".repeat(self.padding_right)
        );
        if !crate::cli::style::colors_enabled() {
            return s;
        }

        // Apply true-color RGB and styles to the padded payload so background
        // pills cover the full component width like Charm's Lipgloss.
        let mut styled = match self.fg {
            Some(color) => {
                let (r, g, b) = color.to_rgb();
                s.truecolor(r, g, b).to_string()
            }
            None => s,
        };

        if let Some(bg) = self.bg {
            let (r, g, b) = bg.to_rgb();
            styled = styled.on_truecolor(r, g, b).to_string();
        }

        if self.is_bold {
            styled = styled.bold().to_string();
        }
        if self.is_italic {
            styled = styled.italic().to_string();
        }
        if self.is_underline {
            styled = styled.underline().to_string();
        }
        if self.is_dim {
            styled = styled.dimmed().to_string();
        }

        styled
    }
}

/// A professional instructional tip to guide the user.
pub fn print_tip(msg: &str) {
    let icon = Style::new()
        .foreground(Color::Accent)
        .bold(true)
        .render("✦");
    let label_style = Style::new().foreground(Color::Accent).bold(true);
    let body_style = Style::new().foreground(Color::Gray).italic(true);
    println!(
        "\n  {} {} {}",
        icon,
        label_style.render("Tip:"),
        body_style.render(msg)
    );
}

/// Print a blank line for "airy" spacing (consistent 1-line margin).
pub fn print_spacer() {
    println!();
}

/// A list item with a "Charm-style" bullet.
pub fn print_list_item(item: &str, metadata: Option<&str>) {
    let bullet = Style::new()
        .foreground(Color::Accent)
        .bold(true)
        .render("•");
    if let Some(meta) = metadata {
        let meta_style = Style::new().foreground(Color::Gray);
        println!("  {} {} {}", bullet, item, meta_style.render(meta));
    } else {
        println!("  {bullet} {item}");
    }
}

/// A high-contrast Lipgloss contextual header with a true-color pill badge.
/// Degrades to `[context] title` when colors are disabled.
pub fn print_header(context: &str, title: &str) {
    if !crate::cli::style::colors_enabled() {
        println!("\n[{context}] {title}");
        return;
    }

    let ctx_style = Style::new()
        .background(Color::Accent)
        .foreground(Color::Black)
        .bold(true)
        .padding_left(1)
        .padding_right(1);

    let title_style = Style::new().foreground(Color::White).bold(true);

    println!(
        "\n{} {}",
        ctx_style.render(context),
        title_style.render(title)
    );
}

/// A standard info message with a Charm-styled icon.
pub fn print_info(msg: impl Display) {
    let icon_style = Style::new().foreground(Color::Cyan).bold(true);
    println!("  {} {}", icon_style.render("ℹ"), msg);
}

/// A standard success message with an emerald Lipgloss icon.
pub fn print_success(msg: impl Display) {
    let icon_style = Style::new().foreground(Color::Green).bold(true);
    println!("  {} {}", icon_style.render("✓"), msg);
}

/// A standard warning message with an amber Lipgloss icon.
pub fn print_warning(msg: impl Display) {
    let icon_style = Style::new().foreground(Color::Yellow).bold(true);
    let text_style = Style::new().foreground(Color::Yellow);
    println!("  {} {}", icon_style.render("⚠"), text_style.render(msg));
}

/// A standard error message with a vivid crimson Lipgloss icon.
pub fn print_error(msg: impl Display) {
    let icon_style = Style::new().foreground(Color::Red).bold(true);
    let text_style = Style::new().foreground(Color::Red).bold(true);
    println!("  {} {}", icon_style.render("✗"), text_style.render(msg));
}

/// Dry-run footer: confirms no mutations occurred.
pub fn print_dry_run_footer() {
    println!(
        "\n  {} No changes made (dry run)",
        crate::cli::style::dim("ℹ")
    );
}

fn format_kv_key(key: &str) -> String {
    let padded = format!("{key:>12}");
    Style::new().foreground(Color::Gray).render(padded)
}

/// Print a key-value pair with consistent formatting.
pub fn print_kv(key: &str, value: &str) {
    println!("  {}: {}", format_kv_key(key), value);
}

/// Default `omg info` rows. Extra metadata is a separate struct so verbose
/// output cannot leak into the compact view by accident.
pub struct InfoCore<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub source: &'a str,
    pub installed: bool,
    pub description: &'a str,
}

/// Fields shown only with global `-v` / `--verbose`.
pub struct InfoExtras<'a> {
    pub url: Option<&'a str>,
    pub size: Option<u64>,
    pub download: Option<u64>,
    pub licenses: &'a [String],
    pub depends: &'a [String],
    pub maintainer: Option<&'a str>,
    pub votes: Option<i32>,
    pub popularity: Option<f64>,
    pub out_of_date: bool,
}

impl InfoExtras<'static> {
    #[must_use]
    pub fn none() -> Self {
        Self {
            url: None,
            size: None,
            download: None,
            licenses: &[],
            depends: &[],
            maintainer: None,
            votes: None,
            popularity: None,
            out_of_date: false,
        }
    }
}

/// Compact Charm-style package info. Extra rows require verbose mode.
pub fn print_package_info(core: &InfoCore<'_>, extras: &InfoExtras<'_>) {
    use crate::cli::{modern_ui, style};

    modern_ui::print_phase_header("", "Info", &style::sanitize_terminal_text(core.name));
    print_kv(
        "Name",
        &style::package(&style::sanitize_terminal_text(core.name)),
    );
    print_kv(
        "Version",
        &style::version(&style::sanitize_terminal_text(core.version)),
    );
    print_kv("Source", core.source);
    print_kv("Installed", if core.installed { "yes" } else { "no" });
    print_kv(
        "Description",
        &style::sanitize_terminal_text(core.description),
    );
    if extras.out_of_date {
        print_kv("Status", &style::error("OUT OF DATE"));
    }
    if !modern_ui::is_verbose() {
        return;
    }
    if let Some(url) = extras.url.filter(|url| !url.is_empty()) {
        print_kv("URL", &style::url(&style::sanitize_terminal_text(url)));
    }
    if let Some(size) = extras.size {
        print_kv("Size", &style::size(size));
    }
    if let Some(download) = extras.download {
        print_kv("Download", &style::size(download));
    }
    if !extras.licenses.is_empty() {
        print_kv(
            "License",
            &extras
                .licenses
                .iter()
                .map(|license| style::sanitize_terminal_text(license))
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    if !extras.depends.is_empty() {
        print_kv(
            "Depends",
            &extras
                .depends
                .iter()
                .map(|depend| style::sanitize_terminal_text(depend))
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    if let Some(maintainer) = extras.maintainer {
        print_kv("Maintainer", &style::sanitize_terminal_text(maintainer));
    }
    if let Some(votes) = extras.votes {
        print_kv("Votes", &votes.to_string());
    }
    if let Some(popularity) = extras.popularity {
        print_kv("Popularity", &format!("{popularity:.2}%"));
    }
}

/// Semantic tone for Charm/Lipgloss pills and rounded panels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadgeTone {
    Critical,
    Warning,
    Info,
    Success,
    Malware,
    Eol,
    Neutral,
}

impl BadgeTone {
    const fn border_color(self) -> Color {
        match self {
            Self::Critical => Color::Red,
            Self::Malware => Color::Rgb(0xff, 0x33, 0x66),
            Self::Warning | Self::Eol => Color::Yellow,
            Self::Info => Color::Accent,
            Self::Success => Color::Green,
            Self::Neutral => Color::Muted,
        }
    }

    const fn title_color(self) -> Color {
        match self {
            Self::Critical => Color::Red,
            Self::Malware => Color::Rgb(0xff, 0x4d, 0x79),
            Self::Warning | Self::Eol => Color::Yellow,
            Self::Info => Color::Accent,
            Self::Success => Color::Green,
            Self::Neutral => Color::White,
        }
    }

    const fn pill_colors(self) -> (Color, Color) {
        match self {
            Self::Critical => (Color::Rgb(0xd9, 0x38, 0x55), Color::White),
            Self::Malware => (Color::Rgb(0xe1, 0x1d, 0x48), Color::White),
            Self::Warning | Self::Eol => (Color::Yellow, Color::Black),
            Self::Info => (Color::Cyan, Color::Black),
            Self::Success => (Color::Green, Color::Black),
            Self::Neutral => (Color::Muted, Color::White),
        }
    }
}

/// Render a high-contrast Charm/Lipgloss pill badge (e.g., ` 0-DAY / KEV `).
/// Degrades cleanly to `[LABEL]` when `NO_COLOR` is set.
#[must_use]
pub fn render_badge(tone: BadgeTone, label: &str) -> String {
    if !crate::cli::style::colors_enabled() {
        return format!("[{label}]");
    }
    let (bg, fg) = tone.pill_colors();
    Style::new()
        .background(bg)
        .foreground(fg)
        .bold(true)
        .padding_left(1)
        .padding_right(1)
        .render(label)
}

fn clamp_panel_width(term_cols: usize, content_max: usize) -> usize {
    let max_inner = if term_cols >= 64 {
        term_cols.saturating_sub(4).clamp(60, 88)
    } else {
        72
    };
    content_max.saturating_add(2).clamp(60, max_inner)
}

fn panel_inner_width(lines: &[String], header_width: usize, footer_width: usize) -> usize {
    let term_cols = usize::from(console::Term::stdout().size().1);
    let content_max = lines
        .iter()
        .map(|line| console::measure_text_width(line))
        .max()
        .unwrap_or(0)
        .max(header_width)
        .max(footer_width);
    clamp_panel_width(term_cols, content_max)
}

fn pad_panel_row(content: &str, inner_width: usize, left_v: &str, right_v: &str) -> String {
    let visible = console::measure_text_width(content);
    let used = visible.saturating_add(2); // leading space + trailing space
    if used <= inner_width {
        let pad = inner_width - used;
        format!("{left_v} {content}{} {right_v}", " ".repeat(pad))
    } else {
        // Long unbreakable token (e.g., advisory URL): keep intact so terminals
        // can click it without truncating or corrupting the URL.
        format!("{left_v} {content}")
    }
}

/// Render a fast, full-box Lipgloss rounded panel with a semantic true-color
/// border accent and ANSI-aware right-border alignment.
#[must_use]
pub fn render_panel(
    tone: BadgeTone,
    badge_label: &str,
    title: &str,
    body: &str,
    footer: Option<&str>,
) -> String {
    use std::fmt::Write as _;

    let unicode = crate::cli::style::use_unicode();
    let colors = crate::cli::style::colors_enabled();
    let (tl, tr, bl, br, ml, mr, h, v) = if unicode {
        ("╭", "╮", "╰", "╯", "├", "┤", "─", "│")
    } else {
        ("+", "+", "+", "+", "+", "+", "-", "|")
    };
    let border_color = tone.border_color();
    let paint_border = |text: &str| -> String {
        if colors {
            Style::new().foreground(border_color).render(text)
        } else {
            text.to_owned()
        }
    };

    let styled_title = if colors {
        Style::new()
            .foreground(tone.title_color())
            .bold(true)
            .render(title)
    } else {
        title.to_owned()
    };
    let header_line = if badge_label.is_empty() {
        styled_title
    } else {
        format!("{} {styled_title}", render_badge(tone, badge_label))
    };
    let body_lines: Vec<String> = body.lines().map(ToOwned::to_owned).collect();
    let styled_footer = footer.map(|foot| {
        if colors {
            Style::new().foreground(Color::Gray).render(foot)
        } else {
            foot.to_owned()
        }
    });

    let inner_width = panel_inner_width(
        &body_lines,
        console::measure_text_width(&header_line),
        styled_footer
            .as_deref()
            .map_or(0, console::measure_text_width),
    );
    let bar = h.repeat(inner_width);
    let painted_bar = paint_border(&bar);
    let painted_v = paint_border(v);

    let mut out = String::with_capacity(body.len() + 512);
    let _ = writeln!(
        out,
        "\n{}{}{}",
        paint_border(tl),
        painted_bar,
        paint_border(tr)
    );
    let _ = writeln!(
        out,
        "{}",
        pad_panel_row(&header_line, inner_width, &painted_v, &painted_v)
    );
    let _ = writeln!(
        out,
        "{}{}{}",
        paint_border(ml),
        painted_bar,
        paint_border(mr)
    );
    for line in &body_lines {
        let _ = writeln!(
            out,
            "{}",
            pad_panel_row(line, inner_width, &painted_v, &painted_v)
        );
    }
    if let Some(foot) = styled_footer.as_deref() {
        let _ = writeln!(
            out,
            "{}{}{}",
            paint_border(ml),
            painted_bar,
            paint_border(mr)
        );
        let _ = writeln!(
            out,
            "{}",
            pad_panel_row(foot, inner_width, &painted_v, &painted_v)
        );
    }
    let _ = writeln!(
        out,
        "{}{}{}",
        paint_border(bl),
        painted_bar,
        paint_border(br)
    );
    out
}

fn highlight_security_token(token: &str, critical: bool) -> String {
    let trimmed =
        token.trim_matches(|c: char| matches!(c, '(' | ')' | '[' | ']' | ',' | ';' | ':'));
    let upper = trimmed.to_ascii_uppercase();
    if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
        return Style::new()
            .foreground(Color::Cyan)
            .underline(true)
            .render(token);
    }
    if upper.starts_with("CVE-")
        || upper.starts_with("MAL-")
        || upper.starts_with("GHSA-")
        || upper.starts_with("AVG-")
        || upper.starts_with("ASA-")
    {
        let color = if critical || upper.starts_with("MAL-") {
            Color::Red
        } else {
            Color::Yellow
        };
        return Style::new().foreground(color).bold(true).render(token);
    }
    if matches!(
        upper.as_str(),
        "KEV" | "0-DAY" | "ZERO-DAY" | "CRITICAL" | "MALWARE" | "EXPLOITED"
    ) {
        return Style::new().foreground(Color::Red).bold(true).render(token);
    }
    if matches!(upper.as_str(), "HIGH" | "WARNING" | "EOL" | "DEPRECATED") {
        return Style::new()
            .foreground(Color::Yellow)
            .bold(true)
            .render(token);
    }
    token.to_owned()
}

fn highlight_security_details(details: &str, critical: bool) -> String {
    if !crate::cli::style::colors_enabled() {
        return details.to_owned();
    }
    details
        .lines()
        .map(|line| {
            line.split(' ')
                .map(|token| highlight_security_token(token, critical))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Render the interactive review for an advisory or coverage gap.
#[must_use]
pub(crate) fn render_security_review_card(
    details: &str,
    short_id: &str,
    kind: crate::core::security::advisory_review::AdvisoryReviewKind,
) -> String {
    use crate::core::security::advisory_review::AdvisoryReviewKind;
    let (tone, badge, title) = match kind {
        AdvisoryReviewKind::CriticalAdvisory => (
            BadgeTone::Critical,
            "CRITICAL ADVISORY",
            "Review Before Installing",
        ),
        AdvisoryReviewKind::Advisory => (
            BadgeTone::Warning,
            "SECURITY ADVISORY",
            "Warning — Review Before Installing",
        ),
        AdvisoryReviewKind::AdvisoryWithUnknownCoverage => (
            BadgeTone::Warning,
            "SECURITY ADVISORY",
            "Findings and Incomplete Coverage",
        ),
        AdvisoryReviewKind::CoverageUnknown => (
            BadgeTone::Warning,
            "COVERAGE UNKNOWN",
            "Review the Coverage Gap",
        ),
    };
    let critical = kind == AdvisoryReviewKind::CriticalAdvisory;
    let phrase = kind.confirmation_phrase();
    let footer = format!("Review ID: {short_id}  •  Enter cancels safely  •  --yes cannot bypass");
    let highlighted_details = highlight_security_details(details, critical);
    let mut card = render_panel(tone, badge, title, &highlighted_details, Some(&footer));

    let colors = crate::cli::style::colors_enabled();
    let accent_color = if critical { Color::Red } else { Color::Yellow };
    let pointer_glyph = if crate::cli::style::use_unicode() {
        "❯"
    } else {
        ">"
    };
    let pointer = if colors {
        Style::new()
            .foreground(accent_color)
            .bold(true)
            .render(pointer_glyph)
    } else {
        pointer_glyph.to_owned()
    };
    let phrase_styled = if colors {
        Style::new()
            .foreground(accent_color)
            .bold(true)
            .render(phrase)
    } else {
        phrase.to_owned()
    };
    let cancel_hint = if colors {
        Style::new()
            .foreground(Color::Gray)
            .render("(default: cancel): ")
    } else {
        "(default: cancel): ".to_owned()
    };
    use std::fmt::Write as _;
    let _ = write!(
        card,
        "{pointer} Type '{phrase_styled}' within 60s to continue, or press Enter to cancel {cancel_hint}"
    );
    card
}

/// Print a vivid amber Lipgloss warning callout card.
pub fn print_warning_card(title: &str, body: &str) {
    print!(
        "{}",
        render_panel(BadgeTone::Warning, "WARNING", title, body, None)
    );
}

/// Print a vivid crimson Lipgloss critical alert callout card.
pub fn print_critical_card(title: &str, body: &str) {
    print!(
        "{}",
        render_panel(BadgeTone::Critical, "CRITICAL", title, body, None)
    );
}

/// Get a themed `ColorfulTheme` for dialoguer prompts.
/// Keeps using console/dialoguer themes as they are specific to that library.
pub fn prompt_theme() -> dialoguer::theme::ColorfulTheme {
    use dialoguer::theme::ColorfulTheme;
    let accent = crate::cli::chrome::palette().accent;
    ColorfulTheme {
        defaults_style: console::Style::new().dim(),
        prompt_style: console::Style::new().bold(),
        prompt_prefix: console::style("  ?".to_string())
            .true_color(accent.r, accent.g, accent.b)
            .bold(),
        success_prefix: console::style("  ✓".to_string()).green().bold(),
        error_prefix: console::style("  ✗".to_string()).red().bold(),
        active_item_style: console::Style::new()
            .true_color(accent.r, accent.g, accent.b)
            .bold(),
        active_item_prefix: console::style("  ❯".to_string())
            .true_color(accent.r, accent.g, accent.b)
            .bold(),
        inactive_item_prefix: console::style("   ".to_string()),
        values_style: console::Style::new().true_color(accent.r, accent.g, accent.b),
        ..ColorfulTheme::default()
    }
}

/// Wrap a block of text in a fast Lipgloss rounded bordered card.
pub fn print_card(title: &str, content: &[String]) {
    let body = content.join("\n");
    print!(
        "{}",
        render_panel(BadgeTone::Neutral, "", title, &body, None)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colored_background_covers_component_padding() {
        temp_env::with_vars(
            [("NO_COLOR", None::<&str>), ("OMG_COLORS", Some("always"))],
            || {
                let rendered = Style::new()
                    .background(Color::Cyan)
                    .padding_left(1)
                    .padding_right(1)
                    .render("ok");
                assert!(rendered.starts_with('\u{1b}'), "{rendered:?}");
                assert!(rendered.contains(" ok "), "{rendered:?}");
                assert!(!rendered.ends_with(' '), "{rendered:?}");
            },
        );
    }

    #[test]
    fn colored_key_value_labels_keep_plain_text_alignment() {
        temp_env::with_vars(
            [("NO_COLOR", None::<&str>), ("OMG_COLORS", Some("always"))],
            || {
                let rendered = format_kv_key("Name");
                assert!(rendered.contains("        Name"), "{rendered:?}");
            },
        );
    }

    #[test]
    fn styles_are_plain_when_no_color_is_set() {
        temp_env::with_var("NO_COLOR", Some("1"), || {
            let rendered = Style::new()
                .foreground(Color::Green)
                .bold(true)
                .padding_left(1)
                .padding_right(1)
                .render("ok");
            assert_eq!(rendered, " ok ");
            assert!(!rendered.contains('\u{1b}'));
        });
    }

    #[test]
    fn charm_security_review_card_renders_cleanly_in_plain_and_color_modes() {
        use crate::core::security::advisory_review::AdvisoryReviewKind;
        temp_env::with_var("NO_COLOR", Some("1"), || {
            let card = render_security_review_card(
                "pkg 1.0 has CVE-2026-0001 (KEV)",
                "abcdef12",
                AdvisoryReviewKind::CriticalAdvisory,
            );
            assert!(!card.contains('\u{1b}'));
            assert!(card.contains("[CRITICAL ADVISORY]"));
            assert!(card.contains("Review ID: abcdef12"));
            assert!(card.contains("Type 'install-unsafe' within 60s to continue"));
            assert!(card.contains("(default: cancel): "));
            let unknown = render_security_review_card(
                "Advisory coverage is unknown, including zero-day coverage.",
                "87654321",
                AdvisoryReviewKind::CoverageUnknown,
            );
            assert!(unknown.contains("[COVERAGE UNKNOWN]"));
            assert!(unknown.contains("Type 'install-unsafe' within 60s to continue"));
            assert!(!unknown.contains("[CRITICAL ADVISORY]"));
            let mixed = render_security_review_card(
                "A disclosed finding and incomplete advisory coverage",
                "87654321",
                AdvisoryReviewKind::AdvisoryWithUnknownCoverage,
            );
            assert!(mixed.contains("[SECURITY ADVISORY]"));
            assert!(mixed.contains("Findings and Incomplete Coverage"));
            assert!(mixed.contains("Type 'install-unsafe' within 60s to continue"));
        });
        temp_env::with_vars(
            [("NO_COLOR", None::<&str>), ("OMG_COLORS", Some("always"))],
            || {
                let card = render_security_review_card(
                    "pkg 1.0 has CVE-2026-0002 https://www.cve.org/CVERecord?id=CVE-2026-0002",
                    "12345678",
                    AdvisoryReviewKind::Advisory,
                );
                assert!(
                    card.contains("\u{1b}[38;2;"),
                    "expected truecolor fg: {card:?}"
                );
                assert!(
                    card.contains("\u{1b}[48;2;"),
                    "expected truecolor bg pill: {card:?}"
                );
                assert!(card.contains("SECURITY ADVISORY"));
                assert!(card.contains("proceed"));
                assert!(card.contains("(default: cancel): "));
                assert!(card.contains('╭') && card.contains('╯'));

                let crit = render_security_review_card(
                    "MAL-2026-0001 KEV HIGH https://osv.dev/vulnerability/MAL-2026-0001/very/long/url/that/exceeds/standard/panel/width/for/overflow/coverage",
                    "deadbeef",
                    AdvisoryReviewKind::CriticalAdvisory,
                );
                assert!(crit.contains("CRITICAL ADVISORY"));
                assert!(crit.contains("install-unsafe"));
            },
        );
        temp_env::with_vars(
            [
                ("NO_COLOR", None::<&str>),
                ("OMG_COLORS", Some("always")),
                ("OMG_UNICODE", Some("0")),
            ],
            || {
                let ascii = render_security_review_card(
                    "pkg 1.0 warning",
                    "11223344",
                    AdvisoryReviewKind::Advisory,
                );
                let plain_ascii = console::strip_ansi_codes(&ascii);
                assert!(plain_ascii.contains("+---"));
                assert!(plain_ascii.contains("> Type"));
            },
        );
    }

    #[test]
    fn lipgloss_colors_badges_panels_and_printers_cover_all_tones() {
        temp_env::with_vars(
            [("NO_COLOR", None::<&str>), ("OMG_COLORS", Some("always"))],
            || {
                for color in [
                    Color::Red,
                    Color::Green,
                    Color::Blue,
                    Color::Cyan,
                    Color::Yellow,
                    Color::Magenta,
                    Color::White,
                    Color::Black,
                    Color::Gray,
                    Color::Accent,
                    Color::Muted,
                    Color::Rgb(0x12, 0x34, 0x56),
                ] {
                    let rendered = Style::new()
                        .foreground(color)
                        .background(color)
                        .bold(true)
                        .italic(true)
                        .underline(true)
                        .dim(true)
                        .render("x");
                    assert!(rendered.contains("\u{1b}[38;2;"));
                    assert!(rendered.contains("\u{1b}[48;2;"));
                }

                for tone in [
                    BadgeTone::Critical,
                    BadgeTone::Malware,
                    BadgeTone::Warning,
                    BadgeTone::Eol,
                    BadgeTone::Info,
                    BadgeTone::Success,
                    BadgeTone::Neutral,
                ] {
                    let badge = render_badge(tone, "TAG");
                    assert!(badge.contains("TAG"));
                    let panel = render_panel(tone, "TAG", "Title", "Body line", Some("Footer"));
                    assert!(panel.contains("Title"));
                    assert!(panel.contains("Body line"));
                    assert!(panel.contains("Footer"));
                }

                print_tip("use omg doctor");
                print_list_item("node", Some("22.0.0"));
                print_list_item("bun", None);
                print_header("OMG", "Test");
                print_info("info");
                print_success("ok");
                print_warning("warn");
                print_error("err");
                print_warning_card("Warn", "Details");
                print_critical_card("Crit", "Details");
                print_card("Card", &["Row 1".to_owned()]);
                assert_eq!(clamp_panel_width(40, 20), 60);
                assert_eq!(clamp_panel_width(120, 70), 72);
                let _theme = prompt_theme();
            },
        );
    }
}
