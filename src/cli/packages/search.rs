use std::io::Write;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::cli::packages::common::validate_search_query;
use crate::cli::{style, ui};
use crate::core::{Package, PackageSource};
use crate::package_managers::{VersionDisplay, get_package_manager};
use nucleo_matcher::{
    Config, Matcher, Utf32String,
    pattern::{CaseMatching, Normalization, Pattern},
};

/// Display tier for one search hit. Lower sorts first. A single table owns
/// result ordering for the daemon, native, and AUR paths together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum MatchTier {
    Exact,
    Prefix,
    WordBoundary,
    Fuzzy,
    Substring,
}

pub(crate) const DEFAULT_SEARCH_LIMIT: usize = crate::cli::modern_ui::SUMMARY_LIST_CAP;

/// Language packs flood generic queries (`firefox` matches hundreds of
/// `firefox-*-i18n-*`). They sort after real packages in every tier and
/// collapse into one group row unless the query names them directly.
fn is_langpack(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("-i18n-")
        || lower.ends_with("-i18n")
        || lower.ends_with("-l10n")
        || lower.ends_with("-lang")
        || lower.ends_with("-locale")
}

/// Base name for grouping: `firefox-developer-edition-i18n-ach` groups
/// under `firefox-developer-edition-i18n`.
fn group_base(name: &str) -> Option<&str> {
    name.find("-i18n-")
        .map(|index| &name[..index + "-i18n-".len() - 1])
}

fn match_tier(query: &str, name: &str) -> MatchTier {
    if name == query {
        return MatchTier::Exact;
    }
    if name.starts_with(query) {
        return MatchTier::Prefix;
    }
    if name.split(['-', '_', ' ']).any(|word| word == query) {
        return MatchTier::WordBoundary;
    }
    MatchTier::Substring
}

/// Order display packages so the user sees intent first: exact name, name
/// prefix, whole-word hits, fuzzy hits, then plain substring hits.
/// Language packs sink below same-tier real packages.
fn rank_display_packages(query: &str, packages: &mut Vec<DisplayPackage>) {
    let query_lower = query.to_lowercase();
    let pattern = Pattern::parse(&query_lower, CaseMatching::Ignore, Normalization::Smart);
    let mut matcher = Matcher::new(Config::DEFAULT);
    let owned = std::mem::take(packages);
    let mut scored: Vec<((MatchTier, bool, u32), DisplayPackage)> = owned
        .into_iter()
        .map(|pkg| {
            let name_lower = pkg.name.to_lowercase();
            let mut tier = match_tier(&query_lower, &name_lower);
            let haystack = Utf32String::from(name_lower.as_str());
            let fuzzy = pattern.score(haystack.slice(..), &mut matcher).unwrap_or(0);
            if tier == MatchTier::Substring && fuzzy > 0 {
                tier = MatchTier::Fuzzy;
            }
            ((tier, is_langpack(&name_lower), fuzzy), pkg)
        })
        .collect();
    scored.sort_by(|a, b| {
        a.0.0
            .cmp(&b.0.0)
            .then_with(|| a.0.1.cmp(&b.0.1))
            .then_with(|| b.0.2.cmp(&a.0.2))
            .then_with(|| a.1.name.cmp(&b.1.name))
    });
    packages.extend(scored.into_iter().map(|(_, pkg)| pkg));
}

/// Collapse language-pack floods into one row per base package. The row
/// keeps the first hit's version and source and reports the pack count.
/// An explicit langpack query is never grouped: asking for a pack by name
/// must show that pack, not its base row.
fn group_langpacks(query: &str, packages: Vec<DisplayPackage>) -> Vec<DisplayPackage> {
    let query_lower = query.to_lowercase();
    let mut grouped: Vec<DisplayPackage> = Vec::with_capacity(packages.len());
    let mut pending: Option<(String, DisplayPackage, usize)> = None;
    let flush = |grouped: &mut Vec<DisplayPackage>,
                 pending: &mut Option<(String, DisplayPackage, usize)>| {
        if let Some((_, mut first, count)) = pending.take() {
            if count > 1 {
                first.name = format!("{} (+{} language packs)", first.name, count - 1);
            }
            grouped.push(first);
        }
    };
    for pkg in packages {
        // The user named this exact pack: leave its row alone.
        if pkg.name.to_lowercase() == query_lower {
            flush(&mut grouped, &mut pending);
            grouped.push(pkg);
            continue;
        }
        let base = group_base(&pkg.name).map(str::to_string);
        let matches = match (&pending, &base) {
            (Some((pending_base, _, _)), Some(base)) => pending_base == base,
            _ => false,
        };
        if matches {
            if let Some((_, _, count)) = pending.as_mut() {
                *count += 1;
            }
            continue;
        }
        flush(&mut grouped, &mut pending);
        match base {
            Some(base) => pending = Some((base, pkg, 1)),
            None => grouped.push(pkg),
        }
    }
    flush(&mut grouped, &mut pending);
    grouped
}

/// Rank every path the same way. Collapse language-pack floods only for
/// human output — `--json` keeps real installable names and full rows.
fn present_search_results(
    query: &str,
    mut packages: Vec<DisplayPackage>,
    json: bool,
    limit: usize,
) -> Vec<DisplayPackage> {
    rank_display_packages(query, &mut packages);
    if !json {
        packages = group_langpacks(query, packages);
    }
    truncate_search_results(&mut packages, limit);
    packages
}

#[cfg(unix)]
use crate::core::client::{DaemonClient, SyncDaemonClient};

#[cfg(feature = "arch")]
use crate::package_managers::AurClient;

#[derive(Serialize)]
struct DisplayPackage {
    name: String,
    version: String,
    description: String,
    source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    votes: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    popularity: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    maintainer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    out_of_date: Option<bool>,
}

impl DisplayPackage {
    fn from_package(p: Package) -> Self {
        Self {
            name: p.name,
            version: p.version.version_string(),
            description: p.description,
            source: p.source.to_string(),
            votes: None,
            popularity: None,
            maintainer: None,
            out_of_date: None,
        }
    }

    #[cfg(feature = "arch")]
    fn from_aur_detail(p: crate::package_managers::AurPackageDetail) -> Self {
        Self {
            name: p.name,
            version: p.version,
            description: p.description.unwrap_or_default(),
            source: "AUR".to_string(),
            votes: Some(p.num_votes),
            popularity: Some(p.popularity),
            maintainer: p.maintainer,
            out_of_date: Some(p.out_of_date.is_some()),
        }
    }
}

pub async fn search(query: &str, detailed: bool, no_aur: bool) -> Result<()> {
    search_internal(query, detailed, false, no_aur, DEFAULT_SEARCH_LIMIT).await
}

pub async fn search_with_json(
    query: &str,
    detailed: bool,
    json: bool,
    no_aur: bool,
    limit: usize,
) -> Result<()> {
    search_internal(query, detailed, json, no_aur, limit).await
}

async fn search_internal(
    query: &str,
    detailed: bool,
    json: bool,
    no_aur: bool,
    limit: usize,
) -> Result<()> {
    validate_search_query(query)?;

    let official_search = async { search_official_packages(query, limit).await };

    // Skip AUR search if --no-aur flag is set (for benchmarks/official-only searches)
    let aur_search = async {
        if no_aur {
            return Ok(Vec::new());
        }
        tokio::time::timeout(
            std::time::Duration::from_secs(4),
            search_aur_packages(query, detailed),
        )
        .await
        .context("AUR search timed out")?
    };

    // Official results are authoritative and remain useful when optional AUR
    // enrichment is unavailable. Run both concurrently, but bound AUR latency.
    let (official_result, aur_result) = tokio::join!(official_search, aur_search);
    let (mut display_packages, official_total) = official_result?;
    let aur_packages = match aur_result {
        Ok(packages) => packages,
        Err(error) if !display_packages.is_empty() => {
            tracing::debug!("AUR search unavailable; returning official results: {error}");
            Vec::new()
        }
        Err(error) => return Err(error).context("Failed to search AUR packages"),
    };
    // Deduplicate: skip AUR packages already present in official results.
    // Borrow the names instead of cloning them; this runs on every search.
    let official_names: std::collections::HashSet<&str> =
        display_packages.iter().map(|p| p.name.as_str()).collect();
    let deduped_aur: Vec<DisplayPackage> = aur_packages
        .into_iter()
        .filter(|p| !official_names.contains(p.name.as_str()))
        .collect();
    let aur_count = deduped_aur.len();
    display_packages.extend(deduped_aur);
    let total_matches = official_total.saturating_add(aur_count);

    crate::core::usage::track_search_result(true);
    display_packages = present_search_results(query, display_packages, json, limit);

    if json {
        let json_str = serde_json::to_string_pretty(&display_packages)
            .context("Failed to serialize search results as JSON")?;
        println!("{json_str}");
        return Ok(());
    }

    if display_packages.is_empty() {
        use crate::cli::components::Components;
        use crate::cli::packages::execute_cmd;
        execute_cmd(Components::no_results(query))?;
        return Ok(());
    }

    let mut stdout = std::io::BufWriter::new(std::io::stdout());
    writeln!(
        stdout,
        "{}",
        crate::cli::modern_ui::phase_header_text("Search", query)
    )?;

    for pkg in display_packages.iter().take(limit) {
        write_package_line(&mut stdout, pkg)?;
    }

    if total_matches > limit {
        writeln!(
            stdout,
            "  {}",
            style::dim(&format!("(+{} more packages...)", total_matches - limit))
        )?;
    }

    writeln!(stdout)?;
    stdout.flush()?;
    drop(stdout);

    if should_offer_picker(json) {
        // The picker performs blocking TTY reads; keep it off the async
        // executor the same way the install suggestion picker does.
        let entries: Vec<(String, String)> = display_packages
            .iter()
            .take(limit)
            .map(|pkg| (pkg.name.clone(), picker_label(pkg)))
            .collect();
        let picked = tokio::task::spawn_blocking(move || pick_package(&entries))
            .await
            .unwrap_or(None);
        if let Some(name) = picked {
            super::info_with_json(&name, false).await?;
        }
    }

    Ok(())
}

/// Interactive detail picker: TTY sessions with human-readable output get
/// one keystroke from list to detail. Piped, JSON, and empty output stay
/// exactly as before.
fn should_offer_picker(json: bool) -> bool {
    !json && console::user_attended()
}

fn picker_label(pkg: &DisplayPackage) -> String {
    format!("{} {} ({})", pkg.name, pkg.version, pkg.source)
}

/// Blocking TTY selection over preformatted `(name, label)` entries.
/// Returns the chosen package name, or `None` on Esc, error, or empty input.
fn pick_package(entries: &[(String, String)]) -> Option<String> {
    if entries.is_empty() {
        return None;
    }
    let labels: Vec<&str> = entries.iter().map(|(_, label)| label.as_str()).collect();
    dialoguer::Select::with_theme(&ui::prompt_theme())
        .with_prompt("Select a package for details")
        .default(0)
        .items(&labels)
        .interact_opt()
        .ok()
        .flatten()
        .and_then(|index| entries.get(index).map(|(name, _)| name.clone()))
}

fn truncate_search_results(packages: &mut Vec<DisplayPackage>, limit: usize) {
    packages.truncate(limit);
}

async fn search_official_packages(
    query: &str,
    limit: usize,
) -> Result<(Vec<DisplayPackage>, usize)> {
    #[cfg(unix)]
    if let Ok(mut client) = DaemonClient::connect().await {
        match client.search(query, Some(limit)).await {
            Ok(res) => {
                return Ok((
                    res.packages
                        .into_iter()
                        .map(|pkg| DisplayPackage {
                            name: pkg.name,
                            version: pkg.version,
                            description: pkg.description,
                            source: pkg.source.label().to_string(),
                            votes: None,
                            popularity: None,
                            maintainer: None,
                            out_of_date: None,
                        })
                        .collect(),
                    res.total,
                ));
            }
            Err(error) => {
                tracing::debug!("Daemon search failed for {query}: {error}");
            }
        }
    }

    let pm = get_package_manager().context("Failed to initialize package manager for search")?;
    let packages = pm
        .search(query)
        .await
        .with_context(|| format!("Failed to search official repositories for {query}"))?;
    let total = packages.len();
    Ok((
        packages
            .into_iter()
            .map(DisplayPackage::from_package)
            .collect(),
        total,
    ))
}

#[cfg(feature = "arch")]
async fn search_aur_packages(query: &str, detailed: bool) -> Result<Vec<DisplayPackage>> {
    if crate::package_managers::resolve_backend()? != crate::package_managers::Backend::Arch {
        return Ok(Vec::new());
    }

    if detailed {
        return crate::package_managers::search_detailed(query)
            .await
            .map(|pkgs| {
                pkgs.into_iter()
                    .map(DisplayPackage::from_aur_detail)
                    .collect()
            })
            .with_context(|| format!("Failed to search AUR for {query}"));
    }
    let aur = AurClient::new()?;
    aur.search(query)
        .await
        .map(|pkgs| pkgs.into_iter().map(DisplayPackage::from_package).collect())
        .with_context(|| format!("Failed to search AUR for {query}"))
}

#[cfg(not(feature = "arch"))]
fn search_aur_packages(
    _query: &str,
    _detailed: bool,
) -> std::future::Ready<Result<Vec<DisplayPackage>>> {
    std::future::ready(Ok(Vec::new()))
}

pub fn search_sync_cli(query: &str, detailed: bool, no_aur: bool) -> Result<bool> {
    search_sync_cli_with_limit(query, detailed, no_aur, DEFAULT_SEARCH_LIMIT)
}
pub fn search_sync_cli_with_limit(
    query: &str,
    detailed: bool,
    no_aur: bool,
    limit: usize,
) -> Result<bool> {
    if !crate::cli::packages::common::is_valid_search_query(query) {
        return Ok(false);
    }
    let backend = crate::package_managers::resolve_backend()?;

    // Fast path: official-only search via sync client (zero runtime overhead).
    #[cfg(any(feature = "debian", feature = "debian-pure"))]
    if crate::core::env::distro::is_debian_like() {
        return search_sync_official_only(query, limit);
    }

    if no_aur || backend != crate::package_managers::Backend::Arch {
        return search_sync_official_only(query, limit);
    }

    // AUR path requires async — create a minimal runtime only when necessary
    if tokio::runtime::Handle::try_current().is_ok() {
        return Ok(false);
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        search_internal(query, detailed, false, no_aur, limit).await?;
        // This runtime is about to be dropped, so a fire-and-forget usage
        // task would be cancelled. Flush at this owned shutdown boundary.
        crate::core::usage::sync_usage_now().await;
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(true)
}

/// Sync-only search: daemon IPC via `SyncDaemonClient`, no tokio runtime.
fn search_sync_official_only(query: &str, limit: usize) -> Result<bool> {
    #[cfg(not(unix))]
    {
        return Ok(false); // Daemon not supported on Windows
    }

    #[cfg(unix)]
    {
        let Ok(mut client) = SyncDaemonClient::acquire() else {
            return Ok(false); // Daemon not running; caller falls back to async
        };

        let Ok(res) = client.search(query, Some(limit)) else {
            return Ok(false);
        };

        if res.packages.is_empty() {
            use crate::cli::components::Components;
            use crate::cli::packages::execute_cmd;
            execute_cmd(Components::no_results(query))?;
            return Ok(true);
        }

        let mut packages: Vec<DisplayPackage> = res
            .packages
            .into_iter()
            .map(|pkg| DisplayPackage {
                name: pkg.name,
                version: pkg.version,
                description: pkg.description,
                source: pkg.source.label().to_string(),
                votes: None,
                popularity: None,
                maintainer: None,
                out_of_date: None,
            })
            .collect();
        packages = present_search_results(query, packages, false, limit);

        let mut stdout = std::io::BufWriter::new(std::io::stdout());
        writeln!(
            stdout,
            "{}",
            crate::cli::modern_ui::phase_header_text("Search", query)
        )?;

        for pkg in packages.iter().take(limit) {
            write_package_line(&mut stdout, pkg)?;
        }

        if res.total > limit {
            writeln!(
                stdout,
                "  {}",
                style::dim(&format!("(+{} more packages...)", res.total - limit))
            )?;
        }

        writeln!(stdout)?;
        stdout.flush()?;
        drop(stdout);

        // Pre-clap fast path: no async runtime exists here, so the blocking
        // picker runs inline and detail goes through the sync info entry.
        if should_offer_picker(false) {
            let entries: Vec<(String, String)> = packages
                .iter()
                .take(limit)
                .map(|pkg| (pkg.name.clone(), picker_label(pkg)))
                .collect();
            if let Some(name) = pick_package(&entries) {
                let _ = super::info_sync(&name);
            }
        }
        Ok(true)
    }
}

fn styled_source(source: &str) -> String {
    if PackageSource::from_label(source) == Some(PackageSource::Aur) {
        style::warning(source)
    } else {
        style::info(source)
    }
}

#[inline]
fn write_package_line<W: Write>(w: &mut W, pkg: &DisplayPackage) -> std::io::Result<()> {
    let source_style = styled_source(&pkg.source);

    write!(
        w,
        "  {} {}  {}",
        style::package(&style::sanitize_terminal_text(&pkg.name)),
        style::version(&style::sanitize_terminal_text(&pkg.version)),
        source_style,
    )?;

    if let Some(votes) = pkg.votes {
        write!(
            w,
            " {} {}",
            style::info(&format!("↑{votes}")),
            style::info(&format!("{:.1}", pkg.popularity.unwrap_or(0.0)))
        )?;
    }
    if pkg.out_of_date == Some(true) {
        write!(w, " {}", style::error("[OUT OF DATE]"))?;
    }

    writeln!(w)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Format a package through the real production writer so the tests
    /// assert the exact output users see instead of a duplicated format
    /// string.
    fn format_package(pkg: &super::DisplayPackage) -> String {
        let mut buf = Vec::new();
        write_package_line(&mut buf, pkg).expect("in-memory writer cannot fail");
        String::from_utf8(buf).expect("writer only emits UTF-8")
    }

    fn display(name: &str) -> DisplayPackage {
        DisplayPackage {
            name: name.to_string(),
            version: "1".to_string(),
            description: String::new(),
            source: "Official".to_string(),
            votes: None,
            popularity: None,
            maintainer: None,
            out_of_date: None,
        }
    }

    #[test]
    fn output_limit_applies_before_json_serialization() {
        let mut packages = (0..3)
            .map(|index| DisplayPackage {
                name: format!("package-{index}"),
                version: "1".to_string(),
                description: String::new(),
                source: "official".to_string(),
                votes: None,
                popularity: None,
                maintainer: None,
                out_of_date: None,
            })
            .collect::<Vec<_>>();

        truncate_search_results(&mut packages, 2);
        let json = serde_json::to_value(&packages).expect("serialize search results");
        assert_eq!(json.as_array().map(Vec::len), Some(2));
    }

    #[test]
    fn package_writer_strips_terminal_control_sequences() {
        let package = DisplayPackage {
            name: "safe\x1b]52;c;secret\x07".to_string(),
            version: "1\nforged".to_string(),
            description: "not rendered".to_string(),
            source: "official".to_string(),
            votes: None,
            popularity: None,
            maintainer: None,
            out_of_date: None,
        };

        let output = format_package(&package);
        assert!(!output.contains('\x1b'));
        assert!(!output.contains('\x07'));
        assert!(!output.contains("\nforged"));
        assert!(!output.contains("not rendered"));
    }

    #[test]
    fn firefox_exact_match_sorts_first() {
        let mut packages = vec![
            display("browserpass-firefox"),
            display("firefox-developer-edition-i18n-af"),
            display("firefox"),
            display("firefox-adblock-plus"),
            display("curl-impersonate"),
        ];
        rank_display_packages("firefox", &mut packages);
        let names: Vec<&str> = packages.iter().map(|pkg| pkg.name.as_str()).collect();
        assert_eq!(names[0], "firefox");
        assert!(names.contains(&"firefox-adblock-plus"));
        assert_eq!(names.last(), Some(&"curl-impersonate"));
    }

    #[test]
    fn langpacks_sink_below_real_packages() {
        let mut packages = vec![
            display("firefox-developer-edition-i18n-af"),
            display("firefox-developer-edition"),
        ];
        rank_display_packages("firefox", &mut packages);
        assert_eq!(packages[0].name, "firefox-developer-edition");
    }

    #[test]
    fn picker_is_json_and_pipe_safe() {
        assert!(!should_offer_picker(true));
        assert_eq!(should_offer_picker(false), console::user_attended());
    }

    #[test]
    fn picker_labels_carry_name_version_source() {
        assert_eq!(picker_label(&display("firefox")), "firefox 1 (Official)");
    }

    #[test]
    fn picker_returns_none_without_a_terminal() {
        let entries = vec![("firefox".to_string(), "firefox 1 (Official)".to_string())];
        assert_eq!(pick_package(&[]), None);
        if !console::user_attended() {
            assert_eq!(pick_package(&entries), None);
        }
    }

    #[test]
    fn langpacks_collapse_into_one_group_row() {
        let packages = vec![
            display("firefox"),
            display("firefox-developer-edition-i18n-af"),
            display("firefox-developer-edition-i18n-an"),
            display("firefox-developer-edition-i18n-ar"),
        ];
        let grouped = group_langpacks("firefox", packages);
        assert_eq!(grouped.len(), 2);
        assert_eq!(
            grouped[1].name,
            "firefox-developer-edition-i18n-af (+2 language packs)"
        );
    }

    #[test]
    fn explicit_langpack_query_keeps_its_row() {
        let packages = vec![
            display("firefox"),
            display("firefox-i18n-af"),
            display("firefox-i18n-an"),
        ];
        let grouped = group_langpacks("firefox-i18n-af", packages);
        let names: Vec<&str> = grouped.iter().map(|pkg| pkg.name.as_str()).collect();
        assert!(names.contains(&"firefox-i18n-af"));
        assert!(names.iter().all(|name| !name.contains("language packs")));
    }

    #[test]
    fn json_presentation_keeps_real_package_names() {
        let packages = vec![
            display("firefox"),
            display("firefox-developer-edition-i18n-af"),
            display("firefox-developer-edition-i18n-an"),
            display("firefox-developer-edition-i18n-ar"),
        ];
        let json = present_search_results("firefox", packages, true, 50);
        let names: Vec<&str> = json.iter().map(|pkg| pkg.name.as_str()).collect();
        assert_eq!(names[0], "firefox");
        assert!(names.contains(&"firefox-developer-edition-i18n-af"));
        assert!(names.contains(&"firefox-developer-edition-i18n-an"));
        assert!(names.iter().all(|name| !name.contains("language packs")));

        let human = present_search_results(
            "firefox",
            vec![
                display("firefox"),
                display("firefox-developer-edition-i18n-af"),
                display("firefox-developer-edition-i18n-an"),
                display("firefox-developer-edition-i18n-ar"),
            ],
            false,
            50,
        );
        assert_eq!(human.len(), 2);
        assert_eq!(
            human[1].name,
            "firefox-developer-edition-i18n-af (+2 language packs)"
        );
    }

    #[test]
    #[cfg(feature = "arch")]
    fn test_display_package_from_package() {
        let pkg = Package {
            name: "firefox".to_string(),
            version: alpm_types::Version::from(
                "123.0-1".parse::<alpm_types::FullVersion>().unwrap(),
            ),
            description: "Fast web browser".to_string(),
            source: crate::core::PackageSource::Official,
            installed: false,
        };

        let display = DisplayPackage::from_package(pkg);
        assert_eq!(display.name, "firefox");
        assert_eq!(display.version, "123.0-1");
        assert_eq!(display.description, "Fast web browser");
        assert_eq!(display.source, "Official");
    }

    #[test]
    fn test_format_package_aur() {
        let pkg = DisplayPackage {
            name: "yay".to_string(),
            version: "12.0.0".to_string(),
            description: "AUR helper".to_string(),
            source: "AUR".to_string(),
            votes: None,
            popularity: None,
            maintainer: None,
            out_of_date: None,
        };

        let formatted = format_package(&pkg);
        assert!(formatted.contains("yay"));
        assert!(formatted.contains("12.0.0"));
        assert!(formatted.contains("AUR"));
    }

    #[test]
    fn aur_popularity_is_not_rendered_as_a_percentage() {
        let package = DisplayPackage {
            name: "yay".to_string(),
            version: "12.0.0".to_string(),
            description: "AUR helper".to_string(),
            source: "AUR".to_string(),
            votes: Some(10),
            popularity: Some(0.73),
            maintainer: None,
            out_of_date: None,
        };
        let formatted = format_package(&package);
        assert!(formatted.contains("0.7"));
        assert!(!formatted.contains("0.7%"));
    }

    #[test]
    fn test_format_package_official() {
        let pkg = DisplayPackage {
            name: "pacman".to_string(),
            version: "6.0.0".to_string(),
            description: "Package manager".to_string(),
            source: "core".to_string(),
            votes: None,
            popularity: None,
            maintainer: None,
            out_of_date: None,
        };

        let formatted = format_package(&pkg);
        assert!(formatted.contains("pacman"));
        assert!(formatted.contains("6.0.0"));
        assert!(formatted.contains("core"));
    }

    #[tokio::test]
    async fn test_search_query_too_long() {
        let long_query = "a".repeat(101);
        let result = search_internal(&long_query, false, false, false, 50).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Search query too long")
        );
    }

    #[tokio::test]
    async fn test_search_query_control_chars() {
        let result = search_internal("test\x00query", false, false, false, 50).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid characters")
        );
    }

    #[tokio::test]
    async fn test_search_query_path_traversal() {
        let result = search_internal("../etc/passwd", false, false, false, 50).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("path traversal"));
    }

    #[tokio::test]
    async fn test_search_query_shell_metacharacters() {
        let result = search_internal("test;rm -rf", false, false, false, 50).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("shell metacharacters")
        );
    }

    #[test]
    fn test_search_sync_cli_validation() {
        assert!(!search_sync_cli("a".repeat(101).as_str(), false, true).unwrap());

        assert!(!search_sync_cli("test\x00query", false, true).unwrap());

        assert!(!search_sync_cli("../passwd", false, true).unwrap());

        assert!(!search_sync_cli("test;ls", false, true).unwrap());
    }
}
