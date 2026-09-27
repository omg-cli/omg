//! `omg size` - Show disk usage by packages

use anyhow::Result;

#[cfg(any(
    feature = "arch",
    feature = "debian",
    feature = "debian-pure",
    feature = "fedora"
))]
use crate::cli::tea::Cmd;

/// Show disk usage analysis
#[allow(
    clippy::needless_return,
    reason = "additive backend feature branches return before compiled fallbacks"
)]
#[cfg_attr(
    not(feature = "fedora"),
    expect(
        clippy::unused_async,
        reason = "Shared async entry point for the Fedora backend"
    )
)]
pub async fn run(tree: Option<&str>, limit: usize) -> Result<()> {
    anyhow::ensure!(
        crate::package_managers::resolve_backend()? != crate::package_managers::Backend::MacOS,
        "Package size analysis is not implemented for Homebrew"
    );
    if let Some(package) = tree {
        crate::core::security::validate_package_name(package)?;
    }

    #[cfg(feature = "fedora")]
    if matches!(
        crate::core::env::distro::detect_distro(),
        crate::core::env::distro::Distro::Fedora
    ) {
        crate::cli::tea::run_report(show_sizes_fedora(tree, limit).await?)?;
        return Ok(());
    }

    #[cfg(any(feature = "debian", feature = "debian-pure"))]
    if crate::core::env::distro::is_debian_like() {
        let cmd = if let Some(package) = tree {
            show_package_tree_debian(package)?
        } else {
            show_top_packages_debian(limit)?
        };
        crate::cli::tea::run_report(cmd)?;
        return Ok(());
    }

    #[cfg(feature = "arch")]
    {
        let cmd = if let Some(package) = tree {
            show_package_tree(package)?
        } else {
            show_top_packages(limit)?
        };
        crate::cli::tea::run_report(cmd)?;
        return Ok(());
    }

    #[cfg(not(feature = "arch"))]
    {
        let _ = (tree, limit);
        anyhow::bail!("Size analysis requires a supported package backend");
    }
}

#[cfg(feature = "fedora")]
async fn show_sizes_fedora(tree: Option<&str>, limit: usize) -> Result<Cmd<()>> {
    use crate::cli::components::Components;
    use crate::package_managers::dnf::{DnfPackageManager, InstalledSizeQuery};

    let (mut packages, root_description) = if let Some(package) = tree {
        let mut selected =
            DnfPackageManager::installed_package_sizes(InstalledSizeQuery::Package(package))
                .await?;
        anyhow::ensure!(!selected.is_empty(), "Package '{package}' is not installed");
        anyhow::ensure!(
            selected.len() == 1,
            "Package '{package}' matches multiple installed builds; specify a version and architecture"
        );
        let root = selected.remove(0);
        let mut providers = DnfPackageManager::installed_package_sizes(
            InstalledSizeQuery::RequirementProviders(package),
        )
        .await?;
        providers.retain(|(identity, _)| identity != &root.0);
        let description = format!("Package: {} ({})", root.0, format_size(root.1));
        providers.push(root);
        (providers, Some(description))
    } else {
        (
            DnfPackageManager::installed_package_sizes(InstalledSizeQuery::All).await?,
            None,
        )
    };
    packages.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    let total = packages.iter().try_fold(0_i64, |total, (_, size)| {
        total
            .checked_add(*size)
            .ok_or_else(|| anyhow::anyhow!("Installed package size total overflow"))
    })?;
    let mut commands = if let Some(description) = root_description {
        vec![
            Cmd::header("Installed Requirement Providers", description),
            Cmd::info(
                "Includes installed providers of direct requirements, not a minimal dependency closure.",
            ),
        ]
    } else {
        vec![Cmd::header("Disk Usage Analysis", "by installed size")]
    };
    commands.push(Cmd::spacer());
    commands.push(Cmd::card(
        format!("Top {limit} Packages"),
        top_packages_content(&packages, limit),
    ));
    commands.push(Components::kv_list(
        Some("Summary"),
        vec![
            ("Total Installed Size", format_size(total)),
            ("Number of Packages", packages.len().to_string()),
        ],
    ));
    Ok(Cmd::batch(commands))
}

#[cfg(feature = "arch")]
fn show_top_packages(limit: usize) -> Result<Cmd<()>> {
    use crate::cli::components::Components;

    let handle = crate::cli::open_local_alpm()?;

    let localdb = handle.localdb();
    let mut packages: Vec<(String, i64)> = localdb
        .pkgs()
        .into_iter()
        .map(|p: &alpm::Package| (p.name().to_string(), p.isize()))
        .collect();

    packages.sort_by_key(|&(_, size)| std::cmp::Reverse(size));

    let total: i64 = packages.iter().map(|(_, s)| s).sum();

    let mut commands = vec![
        Cmd::header("Disk Usage Analysis", "by installed size"),
        Cmd::spacer(),
        Cmd::card(
            format!("Top {limit} Packages"),
            top_packages_content(&packages, limit),
        ),
        Cmd::spacer(),
        Components::kv_list(
            Some("Summary"),
            vec![
                ("Total Disk Usage", &format_size(total)),
                ("Number of Packages", &packages.len().to_string()),
            ],
        ),
    ];

    // Show cache size
    if let Ok(cache_size) = get_cache_size() {
        commands.push(Cmd::spacer());
        commands.push(Cmd::info(format!(
            "Cache: {} (run 'omg clean --cache' to clear)",
            format_size(cache_size)
        )));
    }

    Ok(Cmd::batch(commands))
}

#[cfg(feature = "arch")]
fn show_package_tree(package: &str) -> Result<Cmd<()>> {
    use crate::cli::components::Components;
    use std::collections::HashSet;

    let handle = crate::cli::open_local_alpm()?;

    let localdb = handle.localdb();

    let pkg = localdb
        .pkg(package)
        .map_err(|_| anyhow::anyhow!("Package '{package}' not installed"))?;

    let pkg_size = pkg.isize();

    // Get dependencies and their sizes
    let mut visited = HashSet::new();
    visited.insert(package.to_string());

    let mut dep_sizes: Vec<(String, i64)> = Vec::new();
    let mut total_dep_size: i64 = 0;

    for dep in pkg.depends() {
        let dep_name = dep.name();
        if visited.contains(dep_name) {
            continue;
        }
        visited.insert(dep_name.to_string());

        if let Ok(dep_pkg) = localdb.pkg(dep_name) {
            let size = dep_pkg.isize();
            dep_sizes.push((dep_name.to_string(), size));
            total_dep_size += size;
        }
    }

    dep_sizes.sort_by_key(|&(_, size)| std::cmp::Reverse(size));

    let mut commands = vec![Cmd::header("Package Size Tree", package), Cmd::spacer()];

    // Package info
    commands.push(Components::kv_list(
        Some("Package Size"),
        vec![
            (package, format_size(pkg_size)),
            ("Type", "installed package".to_string()),
        ],
    ));

    // Dependencies
    if !dep_sizes.is_empty() {
        let dep_content: Vec<String> = dep_sizes
            .iter()
            .take(10)
            .map(|(name, size)| format!("├─ {} {}", name, format_size(*size)))
            .collect();

        commands.push(Cmd::spacer());
        commands.push(Cmd::card(
            format!("Dependencies ({} total)", dep_sizes.len()),
            dep_content,
        ));

        if dep_sizes.len() > 10 {
            use crate::cli::tea::{StyledTextConfig, TextStyle};
            commands.push(Cmd::styled_text(StyledTextConfig {
                text: format!("... and {} more dependencies", dep_sizes.len() - 10),
                style: TextStyle::Muted,
            }));
        }
    }

    // Total footprint
    let total = pkg_size + total_dep_size;
    commands.push(Cmd::spacer());
    commands.push(Components::kv_list(
        Some("Total Footprint"),
        vec![
            ("Combined Total", &format_size(total)),
            ("Package Size", &format_size(pkg_size)),
            ("Dependencies", &format_size(total_dep_size)),
        ],
    ));

    Ok(Cmd::batch(commands))
}

#[cfg(any(
    feature = "arch",
    feature = "debian",
    feature = "debian-pure",
    feature = "fedora"
))]
fn top_packages_content(packages: &[(String, i64)], limit: usize) -> Vec<String> {
    // An empty package list must render an empty card, not panic on [0].
    let max_size = packages.first().map_or(0, |&(_, size)| size);
    packages
        .iter()
        .take(limit)
        .enumerate()
        .map(|(i, (name, size))| {
            let size_str = format_size(*size);
            let bar = generate_bar(*size, max_size, 20);
            format!("{:>3}. {} {:>10}  {}", i + 1, bar, size_str, name)
        })
        .collect()
}

#[cfg(any(feature = "debian", feature = "debian-pure"))]
fn show_top_packages_debian(limit: usize) -> Result<Cmd<()>> {
    use crate::cli::components::Components;
    use crate::package_managers::debian_db;

    let mut packages = debian_db::get_all_packages_with_sizes()?;

    packages.sort_by_key(|(_, size)| std::cmp::Reverse(*size));

    let total: i64 = packages.iter().map(|(_, s)| s).sum();

    Ok(Cmd::batch(vec![
        Cmd::header("Disk Usage Analysis", "by installed size"),
        Cmd::spacer(),
        Cmd::card(
            format!("Top {limit} Packages"),
            top_packages_content(&packages, limit),
        ),
        Cmd::spacer(),
        Components::kv_list(
            Some("Summary"),
            vec![
                ("Total Disk Usage", &format_size(total)),
                ("Number of Packages", &packages.len().to_string()),
            ],
        ),
    ]))
}

#[cfg(any(feature = "debian", feature = "debian-pure"))]
fn show_package_tree_debian(package: &str) -> Result<Cmd<()>> {
    use crate::cli::components::Components;
    use crate::package_managers::debian_db;

    let size = debian_db::get_package_size(package)?
        .ok_or_else(|| anyhow::anyhow!("Package '{package}' is not installed"))?;

    let (dependencies, _) = debian_db::get_package_dependencies(package)?;

    let mut dep_sizes: Vec<(String, i64)> = Vec::new();
    for dep_name in dependencies {
        if let Some(dep_size) = debian_db::get_package_size(&dep_name)? {
            dep_sizes.push((dep_name, dep_size));
        }
    }

    dep_sizes.sort_by_key(|(_, size)| std::cmp::Reverse(*size));
    let total_deps: i64 = dep_sizes.iter().map(|(_, s)| s).sum();

    let mut commands = vec![
        Cmd::header("Package Size Tree", package),
        Cmd::spacer(),
        Components::kv_list(
            Some("Package Size"),
            vec![
                (package, format_size(size)),
                ("Type", "installed package".to_string()),
            ],
        ),
    ];

    if !dep_sizes.is_empty() {
        let dep_content: Vec<String> = dep_sizes
            .iter()
            .take(10)
            .map(|(name, dep_size)| format!("├─ {} {}", name, format_size(*dep_size)))
            .collect();

        commands.push(Cmd::spacer());
        commands.push(Cmd::card(
            format!("Dependencies ({} total)", dep_sizes.len()),
            dep_content,
        ));
    }

    let total = size + total_deps;
    commands.push(Cmd::spacer());
    commands.push(Components::kv_list(
        Some("Total Footprint"),
        vec![
            ("Combined Total", &format_size(total)),
            ("Package Size", &format_size(size)),
            ("Dependencies", &format_size(total_deps)),
        ],
    ));

    Ok(Cmd::batch(commands))
}

#[cfg(any(
    feature = "arch",
    feature = "debian",
    feature = "debian-pure",
    feature = "fedora"
))]
fn format_size(bytes: i64) -> String {
    const KB: i64 = 1024;
    const MB: i64 = KB * 1024;
    const GB: i64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.0} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(any(
    feature = "arch",
    feature = "debian",
    feature = "debian-pure",
    feature = "fedora"
))]
fn generate_bar(value: i64, max: i64, width: usize) -> String {
    let ratio = if max > 0 {
        (value as f64 / max as f64).min(1.0)
    } else {
        0.0
    };
    let filled = (ratio * width as f64) as usize;
    let empty = width - filled;
    format!("{}{}", "█".repeat(filled), "░".repeat(empty))
}

#[cfg(feature = "arch")]
fn get_cache_size() -> Result<i64> {
    use std::fs;

    let mut total: i64 = 0;
    for cache_dir in crate::core::paths::pacman_cache_dirs_result()? {
        if !cache_dir.exists() {
            continue;
        }
        for entry in fs::read_dir(&cache_dir)? {
            if let Ok(entry) = entry
                && let Ok(metadata) = entry.metadata()
            {
                // Use saturating_add to prevent overflow on extremely large caches
                total = total.saturating_add(metadata.len().try_into().unwrap_or(i64::MAX));
            }
        }
    }

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(any(
        feature = "arch",
        feature = "debian",
        feature = "debian-pure",
        feature = "fedora"
    )))]
    #[tokio::test]
    async fn size_without_backend_is_an_error() {
        let error = run(None, 20).await.expect_err("size requires a backend");
        assert!(
            error
                .to_string()
                .contains("requires a supported package backend")
        );
    }

    #[cfg(any(
        feature = "arch",
        feature = "debian",
        feature = "debian-pure",
        feature = "fedora"
    ))]
    #[test]
    fn empty_package_list_renders_empty_content_instead_of_panicking() {
        let content = top_packages_content(&[], 20);
        assert!(
            content.is_empty(),
            "no packages must not index out of bounds"
        );
    }

    #[cfg(any(
        feature = "arch",
        feature = "debian",
        feature = "debian-pure",
        feature = "fedora"
    ))]
    #[test]
    fn top_packages_content_ranks_and_truncates() {
        let packages = vec![
            ("a".to_string(), 3_000_000_000_i64),
            ("b".to_string(), 2_000),
        ];
        let content = top_packages_content(&packages, 1);
        assert_eq!(content.len(), 1, "limit must truncate the listing");
        assert!(
            content[0].contains('a'),
            "largest package first, got {content:?}"
        );
    }
}
