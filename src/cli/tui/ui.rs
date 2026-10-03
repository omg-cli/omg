//! TUI for OMG Package Manager
//!
//! Inspired by bottom, lazygit, and k9s - modern, beautiful, and functional.

use crate::cli::tui::app::{App, Tab};
use crate::core::format::format_bytes;
use crate::core::history::TransactionType;
use crate::package_managers::VersionDisplay;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Cell, Clear, Gauge, List, ListItem, ListState, Paragraph, Row,
        Table, TableState, Tabs,
    },
};
use std::borrow::Cow;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Strip terminal control characters and bidirectional overrides before text
/// enters ratatui's span renderer.
fn sanitize_control_chars(text: &str) -> Cow<'_, str> {
    let clean = crate::cli::style::sanitize_terminal_text(text);
    if clean == text {
        Cow::Borrowed(text)
    } else {
        Cow::Owned(clean)
    }
}

/// Truncate `text` to at most `max_width` display columns (wide glyphs count
/// as 2), appending an ellipsis when truncation occurs.
#[must_use]
fn truncate_width(text: &str, max_width: usize) -> Cow<'_, str> {
    let sanitized = sanitize_control_chars(text);
    let sanitized_text: &str = &sanitized;
    if sanitized_text.width() <= max_width {
        return sanitized;
    }
    if max_width == 0 {
        // Nothing fits, and the ellipsis alone would already exceed the
        // budget; an empty cell is the only honest rendering.
        return Cow::Borrowed("");
    }
    // Reserve one column for the ellipsis.
    let budget = max_width - 1;
    let mut out = String::new();
    let mut used = 0usize;
    for ch in sanitized_text.chars() {
        let w = ch.width().unwrap_or(0);
        if used + w > budget {
            break;
        }
        out.push(ch);
        used += w;
    }
    out.push('\u{2026}');
    Cow::Owned(out)
}

/// Right-pad/truncate `text` to exactly `min_width` display columns.
#[must_use]
fn pad_display_width(text: &str, min_width: usize) -> Cow<'_, str> {
    let width = text.width();
    if width >= min_width {
        truncate_width(text, min_width)
    } else {
        Cow::Owned(format!("{}{}", text, " ".repeat(min_width - width)))
    }
}

// Modern color palette (inspired by Catppuccin/Tokyo Night)
mod colors {
    use ratatui::style::Color;

    pub const BG_DARK: Color = Color::Rgb(26, 27, 38);
    pub const BG_MEDIUM: Color = Color::Rgb(36, 40, 59);
    pub const BG_LIGHT: Color = Color::Rgb(52, 59, 88);
    pub const BG_HIGHLIGHT: Color = Color::Rgb(41, 46, 66);

    pub const FG_PRIMARY: Color = Color::Rgb(192, 202, 245);
    pub const FG_SECONDARY: Color = Color::Rgb(130, 139, 184);
    pub const FG_MUTED: Color = Color::Rgb(86, 95, 137);

    pub const ACCENT_BLUE: Color = Color::Rgb(122, 162, 247);
    pub const ACCENT_CYAN: Color = Color::Rgb(125, 207, 255);
    pub const ACCENT_GREEN: Color = Color::Rgb(158, 206, 106);
    pub const ACCENT_YELLOW: Color = Color::Rgb(224, 175, 104);
    pub const ACCENT_ORANGE: Color = Color::Rgb(255, 158, 100);
    pub const ACCENT_RED: Color = Color::Rgb(247, 118, 142);
    pub const ACCENT_MAGENTA: Color = Color::Rgb(187, 154, 247);

    pub const BORDER_NORMAL: Color = Color::Rgb(61, 66, 91);
}

/// Accent color for a transaction kind. Shared by the dashboard activity
/// feed and the full Activity log so they stay visually consistent.
fn transaction_color(t: TransactionType) -> ratatui::style::Color {
    match t {
        TransactionType::Install => colors::ACCENT_GREEN,
        TransactionType::Remove => colors::ACCENT_RED,
        TransactionType::Update => colors::ACCENT_YELLOW,
        TransactionType::Sync => colors::ACCENT_CYAN,
    }
}

/// Icon glyph for a transaction kind. Exhaustive over the enum, so adding a
/// variant forces a decision here instead of silently hitting a
/// string-compare fallback arm that could never fire (`Display` only emits
/// these exact strings).
fn transaction_icon(t: TransactionType) -> &'static str {
    match t {
        TransactionType::Install | TransactionType::Remove | TransactionType::Update => "",
        TransactionType::Sync => "󰓦",
    }
}

pub fn draw(f: &mut Frame, app: &App) {
    // Fill background
    let bg_block = Block::default().style(Style::default().bg(colors::BG_DARK));
    f.render_widget(bg_block, f.area());

    // Main layout with header, body, and footer
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header with tabs
            Constraint::Min(0),    // Body
            Constraint::Length(2), // Status bar
        ])
        .split(f.area());

    let (Some(header), Some(body), Some(footer)) =
        (main_chunks.first(), main_chunks.get(1), main_chunks.get(2))
    else {
        return;
    };
    let (header, body, footer) = (*header, *body, *footer);

    draw_header(f, header, app);

    match app.current_tab {
        Tab::Dashboard => draw_dashboard(f, body, app),
        Tab::Packages => draw_packages(f, body, app),
        Tab::Runtimes => draw_runtimes(f, body, app),
        Tab::Security => draw_security(f, body, app),
        Tab::Activity => draw_activity(f, body, app),
        Tab::Team => draw_team(f, body, app),
    }

    draw_status_bar(f, footer, app);

    // Draw popup if active
    if app.pending_confirmation.is_some() {
        draw_popup(f, app);
    }
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let header_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(12), // Logo
            Constraint::Min(0),     // Tabs
            Constraint::Length(20), // Status indicators
        ])
        .split(area);

    let (Some(logo_area), Some(tabs_area), Some(status_area)) = (
        header_chunks.first(),
        header_chunks.get(1),
        header_chunks.get(2),
    ) else {
        return;
    };

    // Logo
    let logo = Paragraph::new(Line::from(vec![
        Span::styled(" ", Style::default()),
        Span::styled(
            "◆",
            Style::default()
                .fg(colors::ACCENT_CYAN)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            " OMG",
            Style::default()
                .fg(colors::FG_PRIMARY)
                .add_modifier(Modifier::BOLD),
        ),
    ]))
    .style(Style::default().bg(colors::BG_MEDIUM))
    .alignment(Alignment::Center)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(colors::BORDER_NORMAL)),
    );
    f.render_widget(logo, *logo_area);

    // Tabs
    let tab_titles = vec![
        "󰕮 Dashboard",
        " Packages",
        " Runtimes",
        "󰒃 Security",
        " Activity",
        "󰃐 Team",
    ];
    let tabs = Tabs::new(tab_titles)
        .select(app.current_tab as usize)
        .style(Style::default().fg(colors::FG_MUTED))
        .highlight_style(
            Style::default()
                .fg(colors::ACCENT_CYAN)
                .add_modifier(Modifier::BOLD),
        )
        .divider(Span::styled(
            " │ ",
            Style::default().fg(colors::BORDER_NORMAL),
        ))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(colors::BORDER_NORMAL))
                .style(Style::default().bg(colors::BG_MEDIUM)),
        );
    f.render_widget(tabs, *tabs_area);

    // Status indicators
    let status = Paragraph::new(Line::from(vec![
        if app.daemon_connected {
            Span::styled("● ", Style::default().fg(colors::ACCENT_GREEN))
        } else {
            Span::styled("● ", Style::default().fg(colors::ACCENT_RED))
        },
        Span::styled(
            format!("v{}", env!("CARGO_PKG_VERSION")),
            Style::default().fg(colors::FG_MUTED),
        ),
    ]))
    .alignment(Alignment::Right)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(colors::BORDER_NORMAL))
            .style(Style::default().bg(colors::BG_MEDIUM)),
    );
    f.render_widget(status, *status_area);
}

fn draw_dashboard(f: &mut Frame, area: Rect, app: &App) {
    // Two-column layout for dashboard
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
        .split(area);

    let (Some(left), Some(right)) = (main_chunks.first(), main_chunks.get(1)) else {
        return;
    };

    // Left side: System stats and metrics
    let left_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),  // System health cards
            Constraint::Length(10), // CPU/Memory gauges
            Constraint::Min(0),     // Network & Disk
        ])
        .split(*left);

    let (Some(l0), Some(l1), Some(l2)) =
        (left_chunks.first(), left_chunks.get(1), left_chunks.get(2))
    else {
        return;
    };

    draw_health_cards(f, *l0, app);
    draw_system_gauges(f, *l1, app);
    draw_system_info(f, *l2, app);

    // Right side: Usage stats, quick actions and activity
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),  // Usage stats
            Constraint::Min(0),     // Quick actions
            Constraint::Length(10), // Recent activity
        ])
        .split(*right);

    let (Some(r0), Some(r1), Some(r2)) = (
        right_chunks.first(),
        right_chunks.get(1),
        right_chunks.get(2),
    ) else {
        return;
    };

    draw_usage_stats(f, *r0, app);
    draw_quick_actions(f, *r1, app);
    draw_recent_activity(f, *r2, app);
}

fn draw_usage_stats(f: &mut Frame, area: Rect, app: &App) {
    let stats = &app.usage_stats;

    let usage_lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Time Saved: ", Style::default().fg(colors::FG_MUTED)),
            Span::styled(
                stats.time_saved_human(),
                Style::default()
                    .fg(colors::ACCENT_GREEN)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Commands: ", Style::default().fg(colors::FG_MUTED)),
            Span::styled(
                stats.total_commands.to_string(),
                Style::default().fg(colors::ACCENT_CYAN),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Today: ", Style::default().fg(colors::FG_MUTED)),
            Span::styled(
                stats.queries_today.to_string(),
                Style::default().fg(colors::ACCENT_BLUE),
            ),
            Span::styled(" │ Month: ", Style::default().fg(colors::FG_MUTED)),
            Span::styled(
                stats.queries_this_month.to_string(),
                Style::default().fg(colors::ACCENT_BLUE),
            ),
        ]),
    ];

    let usage_widget = Paragraph::new(usage_lines)
        .block(styled_block("󰄉 Usage Stats"))
        .style(Style::default().bg(colors::BG_MEDIUM));
    f.render_widget(usage_widget, area);
}

// The returned block owns its title (formatted into a `String`), so it does
// not actually borrow `title`; returning `Block<'static>` lets this compose
// with other owned widget constructors below. C-MUSTUSE:
// https://rust-lang.github.io/api-guidelines/checklist.html#c-mustuse
#[must_use]
fn styled_block(title: &str) -> Block<'static> {
    Block::default()
        .title(format!(" {title} "))
        .title_style(
            Style::default()
                .fg(colors::FG_PRIMARY)
                .add_modifier(Modifier::BOLD),
        )
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(colors::BORDER_NORMAL))
        .style(Style::default().bg(colors::BG_MEDIUM))
}

/// Builds one dashboard stat card: a bold icon+value line followed by a
/// muted caption, centered inside a [`styled_block`] panel.
#[must_use]
fn stat_card<'a>(
    title: &'a str,
    icon: &'a str,
    icon_color: ratatui::style::Color,
    value: impl Into<Cow<'a, str>>,
    value_color: ratatui::style::Color,
    caption: &'a str,
) -> Paragraph<'a> {
    Paragraph::new(vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(format!("{icon} "), Style::default().fg(icon_color)),
            Span::styled(
                value.into(),
                Style::default()
                    .fg(value_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(Span::styled(caption, Style::default().fg(colors::FG_MUTED))),
    ])
    .alignment(Alignment::Center)
    .block(styled_block(title))
}

fn draw_health_cards(f: &mut Frame, area: Rect, app: &App) {
    let cards = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(area);

    let total_packages = app.get_total_packages();
    let updates = app.get_updates_available();
    let orphans = app.get_orphan_packages();
    let vulns = app.get_security_vulnerabilities();

    // Packages card
    if let Some(c) = cards.first() {
        f.render_widget(
            stat_card(
                "Inventory",
                "󰏗",
                colors::ACCENT_BLUE,
                total_packages.to_string(),
                colors::FG_PRIMARY,
                "System Packages",
            ),
            *c,
        );
    }

    // Updates card
    if let Some(c) = cards.get(1) {
        let color = if updates > 0 {
            colors::ACCENT_YELLOW
        } else {
            colors::ACCENT_GREEN
        };
        f.render_widget(
            stat_card(
                "Maintainability",
                if updates > 0 { "󰚰" } else { "󰄬" },
                color,
                updates.to_string(),
                color,
                if updates > 0 {
                    "Updates Available"
                } else {
                    "System Up-to-date"
                },
            ),
            *c,
        );
    }

    // Orphans card
    if let Some(c) = cards.get(2) {
        let color = if orphans > 0 {
            colors::ACCENT_ORANGE
        } else {
            colors::ACCENT_GREEN
        };
        f.render_widget(
            stat_card(
                "Hygiene",
                if orphans > 0 { "󰃤" } else { "󰄬" },
                color,
                orphans.to_string(),
                color,
                "Orphan Packages",
            ),
            *c,
        );
    }

    // Security card
    if let Some(c) = cards.get(3) {
        let (color, status_icon, label) = match vulns {
            Some(0) => (colors::ACCENT_GREEN, "󰒃", Cow::Borrowed("Secure")),
            Some(count) => (colors::ACCENT_RED, "󰀦", Cow::Owned(format!("{count} CVEs"))),
            None => (colors::FG_MUTED, "󰀦", Cow::Borrowed("Not scanned")),
        };
        f.render_widget(
            stat_card(
                "Security",
                status_icon,
                color,
                label,
                color,
                "Compliance Status",
            ),
            *c,
        );
    }
}

/// Renders a labeled utilization gauge whose fill escalates from green
/// through yellow to red at the given thresholds. Percentages outside
/// `[0, 100]` are clamped so bad sensor readings cannot corrupt rendering.
#[must_use]
fn utilization_gauge(title: &str, percent: f32, warn_at: f32, critical_at: f32) -> Gauge<'static> {
    let clamped = percent.clamp(0.0, 100.0);
    let color = if clamped <= warn_at {
        colors::ACCENT_GREEN
    } else if clamped <= critical_at {
        colors::ACCENT_YELLOW
    } else {
        colors::ACCENT_RED
    };

    Gauge::default()
        .block(styled_block(title))
        .gauge_style(Style::default().fg(color).bg(colors::BG_LIGHT))
        .percent(clamped as u16)
        // The label shows the true reading; only the fill is clamped.
        .label(format!("{percent:.1}%"))
}

fn draw_system_gauges(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let (Some(cpu_area), Some(mem_area)) = (chunks.first(), chunks.get(1)) else {
        return;
    };

    f.render_widget(
        utilization_gauge(" CPU", app.system_metrics.cpu_usage, 50.0, 80.0),
        *cpu_area,
    );
    f.render_widget(
        utilization_gauge(" Memory", app.system_metrics.memory_usage, 60.0, 85.0),
        *mem_area,
    );
}

fn draw_system_info(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let (Some(disk_area), Some(net_area)) = (chunks.first(), chunks.get(1)) else {
        return;
    };

    // Disk info
    let disk_used_gb = app.system_metrics.disk_usage / 1024 / 1024;
    let disk_free_gb = app.system_metrics.disk_free / 1024 / 1024;
    let disk_total = disk_used_gb + disk_free_gb;
    let disk_percent = (disk_used_gb * 100).checked_div(disk_total).unwrap_or(0) as u16;

    let disk_lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("Used: ", Style::default().fg(colors::FG_MUTED)),
            Span::styled(
                format!("{disk_used_gb} GB"),
                Style::default()
                    .fg(colors::ACCENT_BLUE)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Free: ", Style::default().fg(colors::FG_MUTED)),
            Span::styled(
                format!("{disk_free_gb} GB"),
                Style::default().fg(colors::ACCENT_GREEN),
            ),
        ]),
        Line::from(vec![
            Span::styled("Usage: ", Style::default().fg(colors::FG_MUTED)),
            Span::styled(
                format!("{disk_percent}%"),
                Style::default().fg(if disk_percent > 90 {
                    colors::ACCENT_RED
                } else {
                    colors::FG_PRIMARY
                }),
            ),
        ]),
    ];

    let disk_widget = Paragraph::new(disk_lines).block(styled_block(" Disk"));
    f.render_widget(disk_widget, *disk_area);

    // Network info
    let net_lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("↓ RX: ", Style::default().fg(colors::ACCENT_GREEN)),
            Span::styled(
                format_bytes(app.system_metrics.network_rx),
                Style::default().fg(colors::FG_PRIMARY),
            ),
        ]),
        Line::from(vec![
            Span::styled("↑ TX: ", Style::default().fg(colors::ACCENT_BLUE)),
            Span::styled(
                format_bytes(app.system_metrics.network_tx),
                Style::default().fg(colors::FG_PRIMARY),
            ),
        ]),
        Line::from(vec![
            Span::styled("Daemon: ", Style::default().fg(colors::FG_MUTED)),
            if app.daemon_connected {
                Span::styled("Connected", Style::default().fg(colors::ACCENT_GREEN))
            } else {
                Span::styled("Offline", Style::default().fg(colors::ACCENT_RED))
            },
        ]),
    ];

    let net_widget = Paragraph::new(net_lines).block(styled_block("󰛳 Network"));
    f.render_widget(net_widget, *net_area);
}

fn draw_quick_actions(f: &mut Frame, area: Rect, app: &App) {
    let updates = app.get_updates_available();
    let orphans = app.get_orphan_packages();

    let actions = vec![
        ListItem::new(Line::from(vec![
            Span::styled(
                " u ",
                Style::default()
                    .bg(colors::BG_LIGHT)
                    .fg(colors::ACCENT_YELLOW),
            ),
            Span::styled(" Update System", Style::default().fg(colors::FG_PRIMARY)),
            if updates > 0 {
                Span::styled(
                    format!(" ({updates})"),
                    Style::default()
                        .fg(colors::ACCENT_YELLOW)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled(" ✓", Style::default().fg(colors::ACCENT_GREEN))
            },
        ])),
        ListItem::new(Line::from(vec![
            Span::styled(
                " 2 ",
                Style::default()
                    .bg(colors::BG_LIGHT)
                    .fg(colors::ACCENT_CYAN),
            ),
            Span::styled(" Search Packages", Style::default().fg(colors::FG_PRIMARY)),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled(
                " c ",
                Style::default()
                    .bg(colors::BG_LIGHT)
                    .fg(colors::ACCENT_MAGENTA),
            ),
            Span::styled(" Clean Cache", Style::default().fg(colors::FG_PRIMARY)),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled(
                " o ",
                Style::default()
                    .bg(colors::BG_LIGHT)
                    .fg(colors::ACCENT_ORANGE),
            ),
            Span::styled(" Remove Orphans", Style::default().fg(colors::FG_PRIMARY)),
            if orphans > 0 {
                Span::styled(
                    format!(" ({orphans})"),
                    Style::default().fg(colors::ACCENT_ORANGE),
                )
            } else {
                Span::styled(" ✓", Style::default().fg(colors::ACCENT_GREEN))
            },
        ])),
        ListItem::new(Line::from(vec![
            Span::styled(
                " r ",
                Style::default()
                    .bg(colors::BG_LIGHT)
                    .fg(colors::ACCENT_BLUE),
            ),
            Span::styled(" Refresh", Style::default().fg(colors::FG_PRIMARY)),
        ])),
    ];

    let actions_list = List::new(actions)
        .block(styled_block("󰌌 Quick Actions"))
        .style(Style::default().bg(colors::BG_MEDIUM));

    f.render_widget(actions_list, area);
}

fn draw_recent_activity(f: &mut Frame, area: Rect, app: &App) {
    let items: Vec<ListItem> = app
        .history
        .iter()
        .take(5)
        .map(|t| {
            let time = t.timestamp.strftime("%H:%M").to_string();
            let type_color = transaction_color(t.transaction_type);

            ListItem::new(Line::from(vec![
                Span::styled(format!("{time} "), Style::default().fg(colors::FG_MUTED)),
                Span::styled(
                    format!("{} ", transaction_icon(t.transaction_type)),
                    Style::default().fg(type_color),
                ),
                Span::styled(
                    t.transaction_type.to_string(),
                    Style::default().fg(type_color).add_modifier(Modifier::BOLD),
                ),
                if t.success {
                    Span::styled(" ✓", Style::default().fg(colors::ACCENT_GREEN))
                } else {
                    Span::styled(" ✗", Style::default().fg(colors::ACCENT_RED))
                },
            ]))
        })
        .collect();

    let activity_list = if items.is_empty() {
        List::new(vec![ListItem::new(Line::from(Span::styled(
            "No recent activity",
            Style::default().fg(colors::FG_MUTED),
        )))])
    } else {
        List::new(items)
    }
    .block(styled_block(" Recent"))
    .style(Style::default().bg(colors::BG_MEDIUM));

    f.render_widget(activity_list, area);
}

fn draw_packages(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Search bar
            Constraint::Min(0),    // Package list
        ])
        .split(area);

    let (Some(search_area), Some(list_area)) = (chunks.first(), chunks.get(1)) else {
        return;
    };

    // Search bar with modern styling
    let search_text = if app.search_mode {
        format!("  {}▏", app.search_query)
    } else if app.search_query.is_empty() {
        "  Type / to search packages...".to_string()
    } else {
        format!("  {}", app.search_query)
    };

    let search_bar = Paragraph::new(Line::from(vec![Span::styled(
        search_text,
        Style::default().fg(if app.search_mode {
            colors::FG_PRIMARY
        } else {
            colors::FG_MUTED
        }),
    )]))
    .block(
        Block::default()
            .title(" 󰍉 Search ")
            .title_style(Style::default().fg(colors::FG_PRIMARY))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(if app.search_mode {
                colors::ACCENT_CYAN
            } else {
                colors::BORDER_NORMAL
            }))
            .style(Style::default().bg(colors::BG_MEDIUM)),
    );
    f.render_widget(search_bar, *search_area);

    if let Some(error) = &app.search_error {
        let error_panel = Paragraph::new(Line::from(Span::styled(
            format!(" Search failed: {error}"),
            Style::default().fg(colors::ACCENT_RED),
        )))
        .block(styled_block(" Packages"))
        .style(Style::default().bg(colors::BG_MEDIUM));
        f.render_widget(error_panel, *list_area);
        return;
    }

    // Package table with modern styling
    let rows: Vec<Row> = app
        .search_results
        .iter()
        .enumerate()
        .map(|(i, pkg)| {
            let is_selected = i == app.selected_index;
            let base_style = if is_selected {
                Style::default().bg(colors::BG_HIGHLIGHT)
            } else {
                Style::default()
            };

            let source_color = if pkg.repo == "AUR" {
                colors::ACCENT_MAGENTA
            } else {
                colors::ACCENT_BLUE
            };

            Row::new(vec![
                Cell::from(Span::styled(
                    pkg.name.as_str(),
                    base_style
                        .fg(colors::FG_PRIMARY)
                        .add_modifier(if is_selected {
                            Modifier::BOLD
                        } else {
                            Modifier::empty()
                        }),
                )),
                Cell::from(Span::styled(
                    sanitize_control_chars(&pkg.version.version_string()).into_owned(),
                    base_style.fg(colors::ACCENT_GREEN),
                )),
                Cell::from(Span::styled(pkg.repo.as_str(), base_style.fg(source_color))),
                Cell::from(Span::styled(
                    truncate_width(&pkg.description, 50),
                    base_style.fg(colors::FG_MUTED),
                )),
            ])
            .style(base_style)
        })
        .collect();

    let header = Row::new(vec![
        Cell::from(Span::styled(
            "Name",
            Style::default()
                .fg(colors::ACCENT_CYAN)
                .add_modifier(Modifier::BOLD),
        )),
        Cell::from(Span::styled(
            "Version",
            Style::default()
                .fg(colors::ACCENT_CYAN)
                .add_modifier(Modifier::BOLD),
        )),
        Cell::from(Span::styled(
            "Source",
            Style::default()
                .fg(colors::ACCENT_CYAN)
                .add_modifier(Modifier::BOLD),
        )),
        Cell::from(Span::styled(
            "Description",
            Style::default()
                .fg(colors::ACCENT_CYAN)
                .add_modifier(Modifier::BOLD),
        )),
    ])
    .style(Style::default().bg(colors::BG_LIGHT));

    let table = Table::new(
        rows,
        [
            Constraint::Min(25),
            Constraint::Length(15),
            Constraint::Length(12),
            Constraint::Min(30),
        ],
    )
    .header(header)
    .block(styled_block(" Packages"));

    let mut state = TableState::default().with_selected(Some(app.selected_index));
    f.render_stateful_widget(table, *list_area, &mut state);
}

fn draw_runtimes(f: &mut Frame, area: Rect, app: &App) {
    let items: Vec<ListItem> = app
        .get_runtime_versions()
        .iter()
        .map(|(name, version)| {
            let icon = if name.eq_ignore_ascii_case("bun") {
                "󰟈"
            } else if name.eq_ignore_ascii_case("deno") {
                "󰛦"
            } else if [
                "node", "python", "rust", "go", "ruby", "java", "zig", "dotnet", "erlang", "php",
                "swift",
            ]
            .iter()
            .any(|runtime| name.eq_ignore_ascii_case(runtime))
            {
                ""
            } else {
                "󰏗"
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!(" {icon} "),
                    Style::default().fg(colors::ACCENT_CYAN),
                ),
                Span::styled(
                    pad_display_width(name, 12),
                    Style::default()
                        .fg(colors::FG_PRIMARY)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{version:<15}"),
                    Style::default().fg(colors::ACCENT_GREEN),
                ),
                Span::styled("● Active", Style::default().fg(colors::ACCENT_GREEN)),
            ]))
        })
        .collect();

    let runtime_list = if items.is_empty() {
        List::new(vec![ListItem::new(Line::from(Span::styled(
            "No runtimes detected. Use 'omg use <runtime> <version>' to install.",
            Style::default().fg(colors::FG_MUTED),
        )))])
    } else {
        List::new(items)
    }
    .block(styled_block(" Runtimes"))
    .style(Style::default().bg(colors::BG_MEDIUM));

    f.render_widget(runtime_list, area);
}

fn draw_security(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let (Some(left), Some(right)) = (chunks.first(), chunks.get(1)) else {
        return;
    };

    let vulnerabilities = app.get_security_vulnerabilities();
    let (status_color, status_icon, status_text) = match vulnerabilities {
        Some(0) => (colors::ACCENT_GREEN, "󰒃", "SECURE"),
        Some(_) => (colors::ACCENT_RED, "󰀦", "VULNERABLE"),
        None => (colors::FG_MUTED, "󰀦", "NOT SCANNED"),
    };

    // Security Overview
    let security_lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(
                format!(" {status_icon} "),
                Style::default().fg(status_color),
            ),
            Span::styled("Status: ", Style::default().fg(colors::FG_MUTED)),
            Span::styled(
                status_text,
                Style::default()
                    .fg(status_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("   CVEs Found: ", Style::default().fg(colors::FG_MUTED)),
            Span::styled(
                match vulnerabilities {
                    Some(count) => count.to_string(),
                    None => "n/a".to_string(),
                },
                Style::default()
                    .fg(match vulnerabilities {
                        Some(0) | None => colors::FG_MUTED,
                        Some(_) => colors::ACCENT_RED,
                    })
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "   Policy:",
            Style::default()
                .fg(colors::FG_PRIMARY)
                .add_modifier(Modifier::BOLD),
        )),
        // These are the built-in DEFAULTS, not live configuration; label them
        // as such so they cannot be mistaken for actual policy state.
        Line::from(vec![
            Span::styled("   ├─ Min Grade: ", Style::default().fg(colors::FG_MUTED)),
            Span::styled(
                "VERIFIED (default)",
                Style::default().fg(colors::ACCENT_GREEN),
            ),
        ]),
        Line::from(vec![
            Span::styled("   ├─ AUR: ", Style::default().fg(colors::FG_MUTED)),
            Span::styled("Allowed", Style::default().fg(colors::ACCENT_YELLOW)),
        ]),
        Line::from(vec![
            Span::styled("   └─ PGP: ", Style::default().fg(colors::FG_MUTED)),
            Span::styled("Required", Style::default().fg(colors::ACCENT_GREEN)),
        ]),
    ];

    let security_widget = Paragraph::new(security_lines)
        .block(styled_block("󰒃 Security Status"))
        .style(Style::default().bg(colors::BG_MEDIUM));
    f.render_widget(security_widget, *left);

    // Actions panel
    let action_lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(
                " a ",
                Style::default().bg(colors::BG_LIGHT).fg(colors::ACCENT_RED),
            ),
            Span::styled(
                " Run Security Audit",
                Style::default().fg(colors::FG_PRIMARY),
            ),
        ]),
        Line::from(""),
        Line::from(""),
        Line::from(Span::styled(
            "Press 'a' to scan for vulnerabilities",
            Style::default().fg(colors::FG_MUTED),
        )),
    ];

    let actions_widget = Paragraph::new(action_lines)
        .block(styled_block("󰌌 Actions"))
        .style(Style::default().bg(colors::BG_MEDIUM));
    f.render_widget(actions_widget, *right);
}

fn draw_activity(f: &mut Frame, area: Rect, app: &App) {
    let items: Vec<ListItem> = app
        .history
        .iter()
        .take(20)
        .enumerate()
        .map(|(index, t)| {
            let time = t.timestamp.strftime("%H:%M:%S").to_string();
            let type_color = transaction_color(t.transaction_type);

            let header = Line::from(vec![
                Span::styled(format!(" {time} "), Style::default().fg(colors::FG_MUTED)),
                Span::styled(
                    format!("{} ", transaction_icon(t.transaction_type)),
                    Style::default().fg(type_color),
                ),
                Span::styled(
                    format!("{:<8}", t.transaction_type.to_string()),
                    Style::default().fg(type_color).add_modifier(Modifier::BOLD),
                ),
                if t.success {
                    Span::styled(" ✓", Style::default().fg(colors::ACCENT_GREEN))
                } else {
                    Span::styled(" ✗", Style::default().fg(colors::ACCENT_RED))
                },
            ]);

            let mut changes = String::new();
            for (j, c) in t.changes.iter().enumerate() {
                if j > 3 {
                    changes.push_str(", ...");
                    break;
                }
                if j > 0 {
                    changes.push_str(", ");
                }
                changes.push_str(&c.name);
            }

            let style = if index == app.selected_index {
                Style::default().bg(colors::BG_HIGHLIGHT)
            } else {
                Style::default()
            };
            ListItem::new(vec![
                header,
                Line::from(Span::styled(
                    format!("    {changes}"),
                    Style::default().fg(colors::FG_SECONDARY),
                )),
            ])
            .style(style)
        })
        .collect();

    let activity_list = if items.is_empty() {
        List::new(vec![ListItem::new(Line::from(Span::styled(
            "No activity recorded yet",
            Style::default().fg(colors::FG_MUTED),
        )))])
    } else {
        List::new(items)
    }
    .block(styled_block(" Activity Log"))
    .style(Style::default().bg(colors::BG_MEDIUM));

    let mut state = ListState::default().with_selected(Some(app.selected_index));
    f.render_stateful_widget(activity_list, area, &mut state);
}

fn draw_team(f: &mut Frame, area: Rect, app: &App) {
    if let Some(status) = &app.team_status {
        let all_in_sync = status.in_sync_count() == status.members.len();
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
            .split(area);

        let (Some(left), Some(right)) = (chunks.first(), chunks.get(1)) else {
            return;
        };

        // Team Info
        let info_lines = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  Team: ", Style::default().fg(colors::FG_MUTED)),
                Span::styled(
                    sanitize_control_chars(&status.config.name),
                    Style::default()
                        .fg(colors::ACCENT_CYAN)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("  ID: ", Style::default().fg(colors::FG_MUTED)),
                Span::styled(
                    sanitize_control_chars(&status.config.team_id),
                    Style::default().fg(colors::FG_PRIMARY),
                ),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Remote: ", Style::default().fg(colors::FG_MUTED)),
                Span::styled(
                    sanitize_control_chars(status.config.remote_url.as_deref().unwrap_or("None")),
                    Style::default().fg(colors::ACCENT_BLUE),
                ),
            ]),
            Line::from(vec![
                Span::styled("  Lock Hash: ", Style::default().fg(colors::FG_MUTED)),
                Span::styled(
                    // Boundary-safe: never panic on short or multibyte hashes.
                    if status.lock_hash.is_empty() {
                        "none".to_string()
                    } else {
                        status.lock_hash.chars().take(8).collect::<String>()
                    },
                    Style::default().fg(colors::FG_PRIMARY),
                ),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Status: ", Style::default().fg(colors::FG_MUTED)),
                Span::styled(
                    if all_in_sync {
                        "All Systems Operational"
                    } else {
                        "Drift Detected"
                    },
                    Style::default().fg(if all_in_sync {
                        colors::ACCENT_GREEN
                    } else {
                        colors::ACCENT_YELLOW
                    }),
                ),
            ]),
        ];

        let info_widget = Paragraph::new(info_lines)
            .block(styled_block("󰃐 Team Info"))
            .style(Style::default().bg(colors::BG_MEDIUM));
        f.render_widget(info_widget, *left);

        // Members List
        let rows: Vec<Row> = status
            .members
            .iter()
            .map(|member| {
                let status_color = if member.in_sync {
                    colors::ACCENT_GREEN
                } else {
                    colors::ACCENT_YELLOW
                };
                let member_status = if member.in_sync {
                    "Synced"
                } else {
                    member.drift_summary.as_deref().unwrap_or_default()
                };
                let member_status = sanitize_control_chars(member_status);

                Row::new(vec![
                    Cell::from(Span::styled(
                        if member.in_sync { "✓" } else { "⚠" },
                        Style::default().fg(status_color),
                    )),
                    Cell::from(Span::styled(
                        sanitize_control_chars(&member.name),
                        Style::default()
                            .fg(colors::FG_PRIMARY)
                            .add_modifier(Modifier::BOLD),
                    )),
                    Cell::from(Span::styled(
                        sanitize_control_chars(&member.id),
                        Style::default().fg(colors::FG_MUTED),
                    )),
                    Cell::from(Span::styled(
                        member_status,
                        Style::default().fg(status_color),
                    )),
                ])
                .style(Style::default().bg(colors::BG_MEDIUM))
            })
            .collect();

        let header = Row::new(vec![
            Cell::from(""),
            Cell::from(Span::styled(
                "Name",
                Style::default()
                    .fg(colors::ACCENT_CYAN)
                    .add_modifier(Modifier::BOLD),
            )),
            Cell::from(Span::styled(
                "ID",
                Style::default()
                    .fg(colors::ACCENT_CYAN)
                    .add_modifier(Modifier::BOLD),
            )),
            Cell::from(Span::styled(
                "Status",
                Style::default()
                    .fg(colors::ACCENT_CYAN)
                    .add_modifier(Modifier::BOLD),
            )),
        ])
        .style(Style::default().bg(colors::BG_LIGHT));

        let table = Table::new(
            rows,
            [
                Constraint::Length(3),
                Constraint::Percentage(30),
                Constraint::Percentage(20),
                Constraint::Percentage(40),
            ],
        )
        .header(header)
        .block(styled_block(" Members"));

        f.render_widget(table, *right);
    } else {
        // No team workspace
        let lines = vec![
            Line::from(""),
            Line::from(Span::styled(
                "Not in a team workspace",
                Style::default()
                    .fg(colors::ACCENT_RED)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("Run ", Style::default().fg(colors::FG_MUTED)),
                Span::styled(
                    "omg team init <team-id>",
                    Style::default().fg(colors::ACCENT_CYAN),
                ),
                Span::styled(" to get started.", Style::default().fg(colors::FG_MUTED)),
            ]),
        ];

        let widget = Paragraph::new(lines)
            .alignment(Alignment::Center)
            .block(styled_block("󰃐 Team Dashboard"))
            .style(Style::default().bg(colors::BG_MEDIUM));
        f.render_widget(widget, area);
    }
}

fn draw_status_bar(f: &mut Frame, area: Rect, app: &App) {
    // Key hints based on current tab
    let hints: &[(&str, &str)] = match app.current_tab {
        Tab::Dashboard => &[
            ("q", "Quit"),
            ("u", "Update"),
            ("c", "Clean"),
            ("o", "Orphans"),
            ("r", "Refresh"),
            ("1-6", "Tabs"),
        ],
        Tab::Packages => &[
            ("q", "Quit"),
            ("/", "Search"),
            ("↑↓", "Navigate"),
            ("Enter", "Install"),
            ("Esc", "Cancel search"),
        ],
        // Hints list only keys with real handlers; dead advertised shortcuts
        // erode trust (see audit shard 19). Wire a handler before re-adding.
        Tab::Runtimes | Tab::Activity | Tab::Team => &[("q", "Quit"), ("r", "Refresh")],
        Tab::Security => &[("q", "Quit"), ("a", "Audit")],
    };

    let mut spans = vec![Span::styled(" ", Style::default())];
    if let Some(error) = &app.action_error {
        spans.push(Span::styled(
            format!("{error} "),
            Style::default().fg(colors::ACCENT_RED),
        ));
        spans.push(Span::styled(
            "│ ",
            Style::default().fg(colors::BORDER_NORMAL),
        ));
    }
    for (i, (key, action)) in hints.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(
                " │ ",
                Style::default().fg(colors::BORDER_NORMAL),
            ));
        }
        spans.push(Span::styled(
            format!(" {key} "),
            Style::default()
                .bg(colors::BG_LIGHT)
                .fg(colors::ACCENT_CYAN),
        ));
        spans.push(Span::styled(
            format!(" {action}"),
            Style::default().fg(colors::FG_MUTED),
        ));
    }

    let status_bar = Paragraph::new(Line::from(spans)).style(Style::default().bg(colors::BG_DARK));

    f.render_widget(status_bar, area);
}

fn draw_popup(f: &mut Frame, app: &App) {
    let popup_width = 50.min(f.area().width.saturating_sub(4));
    let popup_height = 10.min(f.area().height.saturating_sub(4));
    let popup_area = Rect {
        x: (f.area().width.saturating_sub(popup_width)) / 2,
        y: (f.area().height.saturating_sub(popup_height)) / 2,
        width: popup_width,
        height: popup_height,
    };

    f.render_widget(Clear, popup_area);

    let Some(action) = app.pending_confirmation.as_ref() else {
        return;
    };
    let title = action.title();
    let content = vec![
        Line::from(""),
        Line::from(Span::styled(
            action.prompt(),
            Style::default()
                .fg(colors::ACCENT_CYAN)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                " Enter ",
                Style::default()
                    .bg(colors::ACCENT_GREEN)
                    .fg(colors::BG_DARK),
            ),
            Span::styled(" Confirm  ", Style::default().fg(colors::FG_MUTED)),
            Span::styled(
                " Esc ",
                Style::default().bg(colors::ACCENT_RED).fg(colors::BG_DARK),
            ),
            Span::styled(" Cancel", Style::default().fg(colors::FG_MUTED)),
        ]),
    ];

    let popup = Paragraph::new(content).alignment(Alignment::Center).block(
        Block::default()
            .title(format!(" {title} "))
            .title_style(
                Style::default()
                    .fg(colors::ACCENT_YELLOW)
                    .add_modifier(Modifier::BOLD),
            )
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(colors::ACCENT_YELLOW))
            .style(Style::default().bg(colors::BG_MEDIUM)),
    );

    f.render_widget(popup, popup_area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    fn app_on(tab: Tab) -> App {
        App::new_detached().with_tab(tab)
    }

    fn render(tab: Tab, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
        let app = app_on(tab);
        terminal.draw(|frame| draw(frame, &app)).expect("draw tab");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect()
    }

    /// Builds a backend version from raw metadata text. The strict parser
    /// rejects poisoned strings, so this goes through the domain type's serde
    /// path the way cached/remote metadata does.
    fn poisoned_version(raw: &str) -> crate::package_managers::types::Version {
        #[cfg(feature = "arch")]
        {
            serde_json::from_str(&format!(
                r#"{{"pkgver":{},"epoch":null,"pkgrel":{{"major":1,"minor":null}}}}"#,
                serde_json::to_string(raw).expect("json version string")
            ))
            .expect("serde constructs versions without strict validation")
        }
        #[cfg(not(feature = "arch"))]
        {
            let _ = raw;
            crate::package_managers::types::DebVersion::new(raw)
        }
    }

    fn package_app() -> App {
        let mut app = app_on(Tab::Packages);
        app.search_results = (0..50)
            .map(|index| crate::package_managers::SyncPackage {
                name: format!("pkg-{index:02}"),
                version: poisoned_version("1.0"),
                description: "viewport fixture".to_string(),
                repo: "core".to_string(),
                download_size: 0,
                installed: false,
            })
            .collect();
        app
    }

    fn visible_name_cells<'a>(
        terminal: &'a Terminal<TestBackend>,
        name: &str,
    ) -> &'a [ratatui::buffer::Cell] {
        terminal
            .backend()
            .buffer()
            .content()
            .windows(name.len())
            .find(|cells| {
                cells
                    .iter()
                    .map(ratatui::buffer::Cell::symbol)
                    .collect::<String>()
                    == name
            })
            .expect("selected entry must be visible")
    }

    fn assert_visible_selection(terminal: &Terminal<TestBackend>, name: &str) {
        for cell in visible_name_cells(terminal, name) {
            assert_eq!(cell.bg, colors::BG_HIGHLIGHT);
            assert!(cell.modifier.contains(Modifier::BOLD));
        }
    }

    #[test]
    fn package_selection_stays_visible_after_navigation_and_resize() {
        use crate::cli::tui::app::ConfirmationAction;
        use crossterm::event::KeyCode;
        let mut app = package_app();
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).expect("test terminal");
        for _ in 0..40 {
            app.handle_key(KeyCode::Char('j'));
        }
        terminal
            .draw(|frame| draw(frame, &app))
            .expect("draw selection");
        assert_visible_selection(&terminal, "pkg-40");
        app.handle_key(KeyCode::Enter);
        assert_eq!(
            app.pending_confirmation,
            Some(ConfirmationAction::InstallPackage("pkg-40".to_string()))
        );
        app.handle_key(KeyCode::Esc);
        terminal.backend_mut().resize(100, 18);
        terminal
            .draw(|frame| draw(frame, &app))
            .expect("draw resized selection");
        assert_visible_selection(&terminal, "pkg-40");
        app.handle_key(KeyCode::Up);
        terminal
            .draw(|frame| draw(frame, &app))
            .expect("draw previous selection");
        assert_visible_selection(&terminal, "pkg-39");
        app.handle_key(KeyCode::Enter);
        assert_eq!(
            app.pending_confirmation,
            Some(ConfirmationAction::InstallPackage("pkg-39".to_string()))
        );
    }

    #[test]
    fn package_viewport_keeps_bounded_first_and_last_selections_visible() {
        use crossterm::event::KeyCode;
        let mut app = package_app();
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).expect("test terminal");
        terminal
            .draw(|frame| draw(frame, &app))
            .expect("draw first selection");
        assert_visible_selection(&terminal, "pkg-00");
        for _ in 0..100 {
            app.handle_key(KeyCode::Down);
        }
        assert_eq!(app.selected_index, 49);
        terminal
            .draw(|frame| draw(frame, &app))
            .expect("draw last selection");
        assert_visible_selection(&terminal, "pkg-49");
        for _ in 0..100 {
            app.handle_key(KeyCode::Char('k'));
        }
        assert_eq!(app.selected_index, 0);
        terminal
            .draw(|frame| draw(frame, &app))
            .expect("draw returned selection");
        assert_visible_selection(&terminal, "pkg-00");
    }

    #[test]
    fn activity_selection_stays_visible_after_navigation_and_resize() {
        use crate::core::history::{PackageChange, Transaction};
        use crossterm::event::KeyCode;
        let mut app = app_on(Tab::Activity);
        app.history = (0..25)
            .map(|index| Transaction {
                id: format!("tx-{index}"),
                timestamp: jiff::Timestamp::from_second(0).expect("fixture timestamp"),
                transaction_type: TransactionType::Install,
                changes: vec![PackageChange {
                    name: format!("history-{index:02}"),
                    old_version: None,
                    new_version: Some("1.0".to_string()),
                    source: "core".to_string(),
                }],
                success: true,
            })
            .collect();
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).expect("test terminal");
        for _ in 0..30 {
            app.handle_key(KeyCode::Down);
        }
        assert_eq!(app.selected_index, 19);
        terminal
            .draw(|frame| draw(frame, &app))
            .expect("draw activity selection");
        for cell in visible_name_cells(&terminal, "history-19") {
            assert_eq!(cell.bg, colors::BG_HIGHLIGHT);
        }
        terminal.backend_mut().resize(100, 18);
        terminal
            .draw(|frame| draw(frame, &app))
            .expect("draw resized activity");
        for cell in visible_name_cells(&terminal, "history-19") {
            assert_eq!(cell.bg, colors::BG_HIGHLIGHT);
        }
        for _ in 0..30 {
            app.handle_key(KeyCode::Up);
        }
        assert_eq!(app.selected_index, 0);
        terminal
            .draw(|frame| draw(frame, &app))
            .expect("draw first activity");
        for cell in visible_name_cells(&terminal, "history-00") {
            assert_eq!(cell.bg, colors::BG_HIGHLIGHT);
        }
    }

    #[test]
    fn packages_rows_render_sanitized_version_strings() {
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).expect("test terminal");
        let mut app = app_on(Tab::Packages);
        app.search_results = vec![crate::package_managers::SyncPackage {
            name: "evil".to_string(),
            version: poisoned_version("1.0\u{1b}[31m\u{202e}evil"),
            description: "browser".to_string(),
            repo: "AUR".to_string(),
            download_size: 0,
            installed: false,
        }];

        terminal
            .draw(|frame| draw(frame, &app))
            .expect("draw packages");
        let rendered: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect();

        assert!(
            !rendered.chars().any(char::is_control),
            "package version controls must not reach the TUI buffer"
        );
        assert!(
            !rendered.contains('\u{202e}'),
            "package version bidi overrides must not reach the TUI buffer"
        );
        assert!(
            rendered.contains("1.0[31mevil"),
            "sanitized version text must stay visible"
        );
    }

    #[test]
    fn team_tab_renders_sanitized_team_and_member_names() {
        let mut terminal = Terminal::new(TestBackend::new(200, 40)).expect("test terminal");
        let mut app = app_on(Tab::Team);
        app.team_status = Some(crate::core::env::team::TeamStatus {
            format_version: crate::core::env::team::TeamStatus::STATUS_FORMAT_VERSION,
            config: crate::core::env::team::TeamConfig {
                team_id: "fleet\u{202e}id".to_string(),
                name: "Core\u{1b}[31m\u{202e}Team".to_string(),
                member_id: "me".to_string(),
                remote_url: Some("https://gist\u{202e}example.com/team.git".to_string()),
                auto_push: false,
            },
            lock_hash: String::new(),
            members: vec![crate::core::env::team::TeamMember {
                id: "m\u{202e}1".to_string(),
                name: "\u{202e}nhoj\u{1b}[0m".to_string(),
                env_hash: String::new(),
                last_sync: 0,
                in_sync: false,
                drift_summary: Some("\u{202e}3 files drift".to_string()),
            }],
            updated_at: 0,
        });

        terminal.draw(|frame| draw(frame, &app)).expect("draw team");
        let rendered: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect();

        assert!(
            !rendered.chars().any(char::is_control),
            "team name controls must not reach the TUI buffer"
        );
        assert!(
            !rendered.contains('\u{202e}'),
            "team name bidi overrides must not reach the TUI buffer"
        );
        assert!(
            rendered.contains("Core[31mTeam"),
            "sanitized team name must stay visible"
        );
        assert!(
            rendered.contains("nhoj[0m"),
            "sanitized member name must stay visible"
        );
        assert!(
            rendered.contains("fleetid"),
            "sanitized team id must stay visible"
        );
        assert!(
            rendered.contains("https://gistexample.com/team.git"),
            "sanitized remote url must stay visible"
        );
        assert!(
            rendered.contains("m1"),
            "sanitized member id must stay visible"
        );
        assert!(
            rendered.contains("3 files drift"),
            "sanitized drift summary must stay visible"
        );
    }

    #[test]
    fn width_helpers_replace_terminal_controls_before_rendering() {
        let rendered = truncate_width("safe\x1b[31m\ntext", 40);

        assert_eq!(rendered, "safe[31mtext");
        assert!(!rendered.chars().any(char::is_control));
    }

    #[test]
    fn width_helpers_respect_zero_and_wide_character_boundaries() {
        assert_eq!(truncate_width("anything", 0), "");
        assert_eq!(truncate_width("幅幅幅", 3), "幅…");
        assert_eq!(truncate_width("e\u{301}x", 2), "e\u{301}x");
        assert_eq!(pad_display_width("幅", 3), "幅 ");
    }

    #[test]
    fn every_tab_renders_its_state_contract() {
        for (tab, expected) in [
            (Tab::Dashboard, "Usage Stats"),
            (Tab::Packages, "Type / to search packages"),
            (Tab::Runtimes, "Runtimes"),
            (Tab::Security, "NOT SCANNED"),
            (Tab::Activity, "Activity Log"),
            (Tab::Team, "Not in a team workspace"),
        ] {
            let rendered = render(tab, 120, 40);
            assert!(
                rendered.contains(expected),
                "{tab:?} must render {expected:?}"
            );
        }
    }

    #[test]
    fn mutation_confirmation_renders_the_exact_destructive_action() {
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).expect("test terminal");
        let mut app = app_on(Tab::Dashboard);
        app.pending_confirmation = Some(crate::cli::tui::app::ConfirmationAction::RemoveOrphans);

        terminal
            .draw(|frame| draw(frame, &app))
            .expect("draw confirmation");
        let rendered: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect();

        assert!(rendered.contains("Remove Orphans"));
        assert!(rendered.contains("Remove every orphaned package?"));
        assert!(rendered.contains("Confirm"));
        assert!(rendered.contains("Cancel"));
    }

    #[test]
    fn security_tab_advertises_only_implemented_actions() {
        let rendered = render(Tab::Security, 120, 40);
        assert!(rendered.contains("Run Security Audit"));
        assert!(!rendered.contains("Fix Vulnerabilities"));
        assert!(!rendered.contains("Edit Policy"));
    }

    #[test]
    fn every_tab_handles_a_small_terminal_without_panicking() {
        for tab in [
            Tab::Dashboard,
            Tab::Packages,
            Tab::Runtimes,
            Tab::Security,
            Tab::Activity,
            Tab::Team,
        ] {
            let rendered = render(tab, 24, 8);
            assert!(!rendered.is_empty(), "{tab:?} must produce a frame");
        }
    }
}
