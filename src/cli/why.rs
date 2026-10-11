//! `omg why` - Explain why a package is installed (dependency chain)

use anyhow::Result;
#[cfg(feature = "arch")]
use std::collections::{HashMap, HashSet, VecDeque};

#[cfg(any(
    feature = "arch",
    feature = "debian",
    feature = "debian-pure",
    feature = "fedora"
))]
use crate::cli::tea::Cmd;

#[cfg(feature = "arch")]
const REVERSE_DEPENDENCY_DISPLAY_LIMIT: usize = 20;

/// Explain why a package is installed
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
pub async fn run(package: &str, reverse: bool) -> Result<()> {
    let backend = crate::package_managers::resolve_backend()?;
    anyhow::ensure!(
        backend != crate::package_managers::Backend::MacOS,
        "Package dependency analysis is not implemented for Homebrew"
    );
    anyhow::ensure!(
        backend != crate::package_managers::Backend::Mock,
        "Package dependency analysis is not implemented for the mock backend"
    );
    crate::core::security::validate_package_name(package)?;

    #[cfg(feature = "fedora")]
    if backend == crate::package_managers::Backend::Fedora {
        crate::cli::tea::run_report(show_reason_fedora(package, reverse).await?)?;
        return Ok(());
    }

    #[cfg(any(feature = "debian", feature = "debian-pure"))]
    if crate::core::env::distro::is_debian_like() {
        let cmd = if reverse {
            show_reverse_deps_debian(package)
        } else {
            show_deps_debian(package)
        };
        crate::cli::tea::run_report(cmd)?;
        return Ok(());
    }

    #[cfg(feature = "arch")]
    {
        let cmd = if reverse {
            show_reverse_deps(package)?
        } else {
            show_dependency_chain(package)?
        };
        crate::cli::tea::run_report(cmd)?;
        Ok(())
    }

    #[cfg(all(
        any(feature = "debian", feature = "debian-pure"),
        not(feature = "arch")
    ))]
    {
        let cmd = if reverse {
            show_reverse_deps_debian(package)
        } else {
            show_deps_debian(package)
        };
        crate::cli::tea::run_report(cmd)?;
        return Ok(());
    }

    #[cfg(not(any(feature = "arch", feature = "debian", feature = "debian-pure")))]
    {
        let _ = reverse;
        why_requires_backend()
    }
}

#[cfg(feature = "fedora")]
async fn show_reason_fedora(package: &str, reverse: bool) -> Result<Cmd<()>> {
    use crate::cli::components::Components;
    use crate::package_managers::dnf::{DnfPackageManager, InstalledReasonQuery};

    let mut selected =
        DnfPackageManager::installed_package_reasons(InstalledReasonQuery::Package(package))
            .await?;
    anyhow::ensure!(!selected.is_empty(), "Package '{package}' is not installed");
    anyhow::ensure!(
        selected.len() == 1,
        "Package '{package}' matches multiple installed builds; specify a version and architecture"
    );
    let root = selected.remove(0);
    if !reverse {
        return Ok(Cmd::batch(vec![
            Cmd::header("Recorded Install Reason", &root.identity),
            Components::kv_list(Some("DNF metadata"), vec![("Reason", root.reason)]),
            Cmd::info(format!(
                "Use 'omg why --reverse {package}' for current direct requiring packages."
            )),
        ]));
    }
    let mut dependents =
        DnfPackageManager::installed_package_reasons(InstalledReasonQuery::RequiredBy(package))
            .await?;
    dependents.retain(|entry| entry.identity != root.identity);
    dependents.sort_by(|left, right| left.identity.cmp(&right.identity));
    let count = dependents.len();
    let mut commands = vec![Cmd::header(
        "Reverse Dependencies",
        format!("current direct requirements on {}", root.identity),
    )];
    if dependents.is_empty() {
        commands.push(Cmd::info(
            "No other installed packages directly require this package.",
        ));
    } else {
        commands.push(Components::kv_list(
            Some(format!("Dependents ({count})")),
            dependents
                .into_iter()
                .map(|entry| (entry.identity, entry.reason))
                .collect(),
        ));
    }
    commands.push(Cmd::info(
        "Current requirements do not prove historical cause or removal safety.",
    ));
    Ok(Cmd::batch(commands))
}

#[cfg(feature = "arch")]
fn show_dependency_chain(package: &str) -> Result<Cmd<()>> {
    let handle = crate::cli::open_local_alpm()?;

    let localdb = handle.localdb();

    // Check if package is installed
    match localdb.pkg(package) {
        Ok(pkg) => Ok(show_dependency_chain_for_pkg(&handle, pkg, package)),
        Err(alpm::Error::PkgNotFound) => Ok(not_installed(package)),
        Err(error) => Err(anyhow::anyhow!(
            "Failed to look up '{package}' in the local database: {error}"
        )),
    }
}

#[cfg(feature = "arch")]
fn not_installed(package: &str) -> Cmd<()> {
    use crate::cli::components::Components;
    Components::error_with_suggestion(
        format!("Package '{package}' is not installed"),
        "Try 'omg search' to find available packages",
    )
}

#[cfg(feature = "arch")]
fn show_dependency_chain_for_pkg(
    handle: &alpm::Alpm,
    pkg: &alpm::Package,
    package: &str,
) -> Cmd<()> {
    use crate::cli::components::Components;

    let localdb = handle.localdb();

    // Check install reason
    let reason = pkg.reason();
    let reason_str = match reason {
        alpm::PackageReason::Explicit => "explicitly installed",
        alpm::PackageReason::Depend => "installed as a dependency",
    };

    let mut commands = vec![
        Cmd::header("Package Analysis", format!("for {package}")),
        Cmd::spacer(),
        Components::kv_list(
            Some("Package Information"),
            vec![
                ("Name", package),
                ("Version", pkg.version().as_str()),
                ("Reason", reason_str),
            ],
        ),
        Cmd::spacer(),
    ];

    // Single shared scan of the local DB for both the "Required by" card and
    // the safety assessment below.
    let required_by = crate::cli::local_reverse_deps(handle, package);

    if matches!(reason, alpm::PackageReason::Depend) {
        if required_by.is_empty() {
            commands.push(Cmd::info("Required by: (orphan - can be removed)"));
            commands.push(Cmd::success("This package is safe to remove"));
        } else {
            commands.push(Components::limited_card(
                format!("Required by ({} packages)", required_by.len()),
                required_by.clone(),
                REVERSE_DEPENDENCY_DISPLAY_LIMIT,
            ));

            // Show one dependency chain
            if let Some(first_req) = required_by.first()
                && let Some(path) = build_dependency_path(handle, first_req, package)
            {
                commands.push(Cmd::spacer());
                commands.push(Components::kv_list(Some("Dependency Path Example"), path));
            }
        }
    } else {
        // Show what this package depends on
        let deps: Vec<_> = pkg.depends().into_iter().collect();
        if deps.is_empty() {
            commands.push(Cmd::info("Dependencies: (no dependencies)"));
        } else {
            let dep_list: Vec<(String, String)> = deps
                .iter()
                .take(10)
                .map(|dep| {
                    let installed = localdb.pkgs().find_satisfier(dep.to_string()).is_some();
                    let status = if installed {
                        "✓ installed"
                    } else {
                        "✗ not installed"
                    };
                    (dep.name().to_string(), status.to_string())
                })
                .collect();

            commands.push(Components::kv_list(Some("Dependencies"), dep_list));

            if deps.len() > 10 {
                use crate::cli::tea::{StyledTextConfig, TextStyle};
                commands.push(Cmd::styled_text(StyledTextConfig {
                    text: format!("... and {} more dependencies", deps.len() - 10),
                    style: TextStyle::Muted,
                }));
            }
        }
    }

    // Safety assessment (reuses the shared scan above)
    commands.push(Cmd::spacer());
    let safety = if !required_by.is_empty() {
        Safety::Unsafe(format!("NO - {} packages depend on it", required_by.len()))
    } else if matches!(reason, alpm::PackageReason::Depend) {
        Safety::Safe("YES - orphan dependency".to_string())
    } else {
        Safety::UserDecision("User decision - explicitly installed".to_string())
    };

    match safety {
        Safety::Safe(msg) => commands.push(Cmd::success(format!("Safe to remove: {msg}"))),
        Safety::Unsafe(msg) => commands.push(Cmd::warning(format!("Safe to remove: {msg}"))),
        Safety::UserDecision(msg) => commands.push(Cmd::info(format!("Safe to remove: {msg}"))),
    }

    Cmd::batch(commands)
}

/// Whether a package is safe to remove, as rendered by `omg why`.
#[cfg(feature = "arch")]
enum Safety {
    Safe(String),
    Unsafe(String),
    UserDecision(String),
}

#[cfg(feature = "arch")]
fn build_dependency_path(
    handle: &alpm::Alpm,
    from: &str,
    to: &str,
) -> Option<Vec<(String, String)>> {
    // BFS to find shortest path
    let localdb = handle.localdb();
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    let mut parent: HashMap<String, String> = HashMap::new();

    queue.push_back(from.to_string());
    visited.insert(from.to_string());

    while let Some(current) = queue.pop_front() {
        if current == to {
            // Reconstruct path
            let mut path = vec![to.to_string()];
            let mut current_node = to;
            while let Some(p) = parent.get(current_node) {
                path.push(p.clone());
                current_node = p;
            }
            path.reverse();

            let mut result = Vec::new();
            for (i, p) in path.iter().enumerate() {
                if i == 0 {
                    result.push((format!("└─ {p}"), "explicit".to_string()));
                } else if i == path.len() - 1 {
                    result.push((format!("└─ {p}"), "target package".to_string()));
                } else {
                    result.push((format!("└─ {p}"), "dependency".to_string()));
                }
            }
            return Some(result);
        }

        if let Ok(pkg) = localdb.pkg(current.as_bytes()) {
            for dep in pkg.depends() {
                let Some(satisfier) = localdb.pkgs().find_satisfier(dep.to_string()) else {
                    continue;
                };
                let dep_name = satisfier.name().to_string();
                if !visited.contains(&dep_name) {
                    visited.insert(dep_name.clone());
                    parent.insert(dep_name.clone(), current.clone());
                    queue.push_back(dep_name);
                }
            }
        }
    }

    None
}

#[cfg(feature = "arch")]
fn show_reverse_deps(package: &str) -> Result<Cmd<()>> {
    use crate::cli::components::Components;

    let handle = crate::cli::open_local_alpm()?;

    let localdb = handle.localdb();

    // Check if package is installed
    if let Err(error) = localdb.pkg(package) {
        return if error == alpm::Error::PkgNotFound {
            Ok(not_installed(package))
        } else {
            Err(anyhow::anyhow!(
                "Failed to look up '{package}' in the local database: {error}"
            ))
        };
    }

    let mut dependents: Vec<(String, bool)> = crate::cli::local_reverse_deps(&handle, package)
        .into_iter()
        .filter_map(|name| {
            localdb.pkg(name.as_bytes()).ok().map(|pkg| {
                let is_explicit = matches!(pkg.reason(), alpm::PackageReason::Explicit);
                (name, is_explicit)
            })
        })
        .collect();

    let mut commands = vec![
        Cmd::header(
            "Reverse Dependencies",
            format!("packages that depend on {package}"),
        ),
        Cmd::spacer(),
    ];

    if dependents.is_empty() {
        commands.push(Cmd::success("Nothing depends on this package"));
        commands.push(Cmd::info("Safe to remove: YES (if not needed)"));
    } else {
        dependents.sort_by_key(|&(_, is_explicit)| std::cmp::Reverse(is_explicit)); // Explicit first

        let explicit_count = dependents.iter().filter(|(_, e)| *e).count();
        let dep_count = dependents.len() - explicit_count;

        commands.push(Components::limited_card(
            format!("Dependents ({} total)", dependents.len()),
            dependents
                .iter()
                .map(|(name, is_explicit)| {
                    let marker = if *is_explicit {
                        "explicit"
                    } else {
                        "dependency"
                    };
                    format!("{name}: {marker}")
                })
                .collect(),
            REVERSE_DEPENDENCY_DISPLAY_LIMIT,
        ));

        commands.push(Cmd::spacer());
        commands.push(Cmd::warning(format!(
            "Safe to remove: NO (would break {} dependents: {} explicit, {} dependencies)",
            dependents.len(),
            explicit_count,
            dep_count
        )));
    }

    Ok(Cmd::batch(commands))
}

#[cfg(any(feature = "debian", feature = "debian-pure"))]
fn show_deps_debian(package: &str) -> Cmd<()> {
    use crate::cli::components::Components;
    use crate::package_managers::debian_db;

    let Ok((deps, _)) = debian_db::get_package_dependencies(package) else {
        return Components::error_with_suggestion(
            format!("Package '{package}' not found"),
            "Try 'omg search' to find available packages",
        );
    };

    if deps.is_empty() {
        Cmd::batch(vec![
            Cmd::header("Package Analysis", package),
            Cmd::spacer(),
            Cmd::info("No dependencies found"),
        ])
    } else {
        Cmd::batch(vec![
            Cmd::header("Package Analysis", package),
            Cmd::spacer(),
            Cmd::card(format!("Dependencies ({})", deps.len()), deps),
        ])
    }
}

#[cfg(any(feature = "debian", feature = "debian-pure"))]
fn show_reverse_deps_debian(package: &str) -> Cmd<()> {
    use crate::cli::components::Components;
    use crate::package_managers::debian_db;

    let Ok((_, deps)) = debian_db::get_package_dependencies(package) else {
        return Components::error_with_suggestion(
            format!("Package '{package}' not found"),
            "Try 'omg search' to find available packages",
        );
    };

    Cmd::batch(vec![
        Cmd::header(
            "Reverse Dependencies",
            format!("packages that depend on {package}"),
        ),
        Cmd::spacer(),
        Components::kv_list(
            Some(format!("Dependents ({})", deps.len())),
            deps.into_iter().map(|d| (d, String::new())).collect(),
        ),
    ])
}

#[cfg(not(any(feature = "arch", feature = "debian", feature = "debian-pure")))]
fn why_requires_backend() -> Result<()> {
    anyhow::bail!("Package dependency analysis requires a supported package backend")
}

#[cfg(all(
    test,
    not(any(
        feature = "arch",
        feature = "debian",
        feature = "debian-pure",
        feature = "fedora"
    ))
))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn why_without_backend_is_an_error() {
        let error = run("tree", false)
            .await
            .expect_err("why requires a backend");
        let expected = match crate::package_managers::resolve_backend() {
            Ok(crate::package_managers::Backend::MacOS) => {
                "Package dependency analysis is not implemented for Homebrew".to_string()
            }
            Err(error) => error.to_string(),
            Ok(_) => "requires a supported package backend".to_string(),
        };
        assert!(
            error.to_string().contains(&expected),
            "selected backend must fail with its own unsupported-operation cause: {error}"
        );
    }
}
