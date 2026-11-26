//! `omg diff` - Compare two environment lock files

use anyhow::Result;
use owo_colors::OwoColorize;
use std::collections::{BTreeMap, HashSet};

use crate::cli::style;
use crate::core::env::fingerprint::EnvironmentState;

/// Compare two environment states
pub async fn run(from: Option<&str>, to: &str) -> Result<()> {
    if let Some(path) = from {
        crate::core::safe_ops::validate_path_syntax(path)?;
    }
    crate::core::safe_ops::validate_path_syntax(to)?;

    println!("{} Environment Comparison\n", style::runtime("OMG"));

    // Load the "from" state (current env or specified file)
    let from_state = if let Some(from_path) = from {
        println!(
            "  From: {}",
            style::maybe_color(from_path, |t| t.cyan().to_string())
        );
        EnvironmentState::load(from_path)?
    } else {
        println!(
            "  From: {} (current)",
            style::maybe_color("live environment", |t| t.cyan().to_string())
        );
        EnvironmentState::capture().await?
    };

    // Load the "to" state
    println!(
        "  To:   {}",
        style::maybe_color(to, |t| t.cyan().to_string())
    );
    let to_state = EnvironmentState::load(to)?;

    println!();

    if from_state.matches_inventory(&to_state) {
        println!(
            "  {} Environments are identical!",
            style::maybe_color("✓", |t| t.green().to_string())
        );
        return Ok(());
    }

    // Compare runtimes
    let runtime_diff = diff_runtimes(&from_state.runtimes, &to_state.runtimes);
    if !runtime_diff.is_empty() {
        println!(
            "  {}",
            style::maybe_color("Runtime differences:", |t| t.bold().to_string())
        );
        for change in &runtime_diff {
            println!("    {change}");
        }
        println!();
    }

    // Compare packages
    let package_diff = diff_packages(&from_state.packages, &to_state.packages);
    if !package_diff.added.is_empty() || !package_diff.removed.is_empty() {
        println!(
            "  {}",
            style::maybe_color("Package differences:", |t| t.bold().to_string())
        );

        if !package_diff.added.is_empty() {
            println!(
                "    {} {} packages added:",
                style::maybe_color("+", |t| t.green().to_string()),
                package_diff.added.len()
            );
            for pkg in package_diff.added.iter().take(10) {
                println!(
                    "      {} {}",
                    style::maybe_color("+", |t| t.green().to_string()),
                    style::sanitize_terminal_text(pkg)
                );
            }
            if package_diff.added.len() > 10 {
                println!("      ... and {} more", package_diff.added.len() - 10);
            }
        }

        if !package_diff.removed.is_empty() {
            println!(
                "    {} {} packages removed:",
                style::maybe_color("-", |t| t.red().to_string()),
                package_diff.removed.len()
            );
            for pkg in package_diff.removed.iter().take(10) {
                println!(
                    "      {} {}",
                    style::maybe_color("-", |t| t.red().to_string()),
                    style::sanitize_terminal_text(pkg)
                );
            }
            if package_diff.removed.len() > 10 {
                println!("      ... and {} more", package_diff.removed.len() - 10);
            }
        }

        println!();
    }

    // Summary
    let total_changes = runtime_diff.len() + package_diff.added.len() + package_diff.removed.len();

    println!(
        "  {}",
        style::maybe_color("Summary:", |t| t.bold().to_string())
    );
    println!(
        "    Runtimes:  {} changes",
        if runtime_diff.is_empty() {
            style::version("0")
        } else {
            style::maybe_color(&runtime_diff.len().to_string(), |t| t.yellow().to_string())
        }
    );
    println!(
        "    Packages:  +{} -{}",
        style::version(&package_diff.added.len().to_string()),
        style::maybe_color(&package_diff.removed.len().to_string(), |t| {
            t.red().to_string()
        })
    );
    println!();

    if total_changes > 0 {
        println!("  {} {}", style::dim("Hint:"), target_lockfile_hint(to));
    }

    Ok(())
}

fn target_lockfile_hint(target: &str) -> String {
    format!(
        "Apply the runtime and package changes listed above to match {target}; local lockfiles are comparison inputs, not sync remotes."
    )
}

fn diff_runtimes(from: &BTreeMap<String, String>, to: &BTreeMap<String, String>) -> Vec<String> {
    let mut changes = Vec::new();
    let clean = style::sanitize_terminal_text;

    let all_runtimes: HashSet<_> = from.keys().chain(to.keys()).collect();

    for runtime in all_runtimes {
        let runtime = runtime.as_str();
        match (from.get(runtime), to.get(runtime)) {
            (Some(from_ver), Some(to_ver)) if from_ver != to_ver => {
                changes.push(format!(
                    "{} {} → {}",
                    style::path(&clean(runtime)),
                    style::dim(&clean(from_ver)),
                    style::version(&clean(to_ver))
                ));
            }
            (Some(from_ver), None) => {
                changes.push(format!(
                    "{} {} → {}",
                    style::maybe_color("-", |t| t.red().to_string()),
                    clean(runtime),
                    style::dim(&format!("(removed, was {})", clean(from_ver)))
                ));
            }
            (None, Some(to_ver)) => {
                changes.push(format!(
                    "{} {} {}",
                    style::maybe_color("+", |t| t.green().to_string()),
                    clean(runtime),
                    style::version(&format!("(added @ {})", clean(to_ver)))
                ));
            }
            _ => {}
        }
    }

    changes.sort_unstable();
    changes
}

struct PackageDiff {
    added: Vec<String>,
    removed: Vec<String>,
}

fn diff_packages(from: &[String], to: &[String]) -> PackageDiff {
    // Lock files record package names only, so a name-set difference is the
    // entire honest comparison; per-package version changes cannot be derived.
    let from_set: HashSet<&str> = from.iter().map(String::as_str).collect();
    let to_set: HashSet<&str> = to.iter().map(String::as_str).collect();

    let added: Vec<String> = to_set
        .difference(&from_set)
        .map(std::string::ToString::to_string)
        .collect();

    let removed: Vec<String> = from_set
        .difference(&to_set)
        .map(std::string::ToString::to_string)
        .collect();

    let mut added = added;
    let mut removed = removed;
    added.sort_unstable();
    removed.sort_unstable();

    PackageDiff { added, removed }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_lockfile_hint_does_not_suggest_remote_sync_command() {
        let hint = target_lockfile_hint("target.lock");
        assert!(!hint.contains("env sync"));
        assert!(hint.contains("target.lock"));
    }

    #[test]
    fn diff_output_is_sorted_for_reproducible_reports() {
        let from = BTreeMap::from([
            ("zsh".to_string(), "5".to_string()),
            ("bash".to_string(), "4".to_string()),
        ]);
        let to = BTreeMap::from([
            ("fish".to_string(), "3".to_string()),
            ("bash".to_string(), "5".to_string()),
        ]);
        assert_eq!(
            diff_runtimes(&from, &to),
            vec![
                "+ fish (added @ 3)".to_string(),
                "- zsh → (removed, was 5)".to_string(),
                "bash 4 → 5".to_string(),
            ]
        );

        let packages = diff_packages(
            &["z".to_string(), "a".to_string()],
            &["c".to_string(), "b".to_string()],
        );
        assert_eq!(packages.added, ["b", "c"]);
        assert_eq!(packages.removed, ["a", "z"]);
    }
}
