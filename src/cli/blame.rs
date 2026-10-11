//! `omg blame` - Show when and why a package was installed

use anyhow::Result;

use crate::cli::tea::Cmd;
use crate::core::history::{HistoryManager, TransactionType};

#[cfg(any(feature = "arch", feature = "debian", feature = "debian-pure"))]
const REVERSE_DEPENDENCY_DISPLAY_LIMIT: usize = 20;

/// Show package installation history
#[cfg_attr(
    not(feature = "fedora"),
    expect(
        clippy::unused_async,
        reason = "Shared async entry point for the Fedora backend"
    )
)]
pub async fn run(package: &str) -> Result<()> {
    let backend = crate::package_managers::resolve_backend()?;
    anyhow::ensure!(
        backend != crate::package_managers::Backend::MacOS,
        "Package installation history is not implemented for Homebrew"
    );
    anyhow::ensure!(
        backend != crate::package_managers::Backend::Mock,
        "Package installation history is not implemented for the mock backend"
    );
    crate::core::security::validate_package_name(package)?;

    #[cfg(feature = "fedora")]
    if backend == crate::package_managers::Backend::Fedora {
        crate::cli::tea::run_report(build_blame_fedora(package).await?)?;
        return Ok(());
    }

    let cmd = build_blame_output(package)?;
    // Fails (non-zero exit) when the command tree contains Cmd::Error.
    crate::cli::tea::run_report(cmd)?;

    Ok(())
}

#[cfg(feature = "fedora")]
async fn build_blame_fedora(package: &str) -> Result<Cmd<()>> {
    use crate::cli::components::Components;
    use crate::package_managers::dnf::{DnfPackageManager, InstalledReasonQuery};

    let mut selected = DnfPackageManager::installed_package_details(package).await?;
    anyhow::ensure!(!selected.is_empty(), "Package '{package}' is not installed");
    anyhow::ensure!(
        selected.len() == 1,
        "Package '{package}' matches multiple installed builds; specify a version and architecture"
    );
    let root = selected.remove(0);
    let mut dependents =
        DnfPackageManager::installed_package_reasons(InstalledReasonQuery::RequiredBy(package))
            .await?;
    dependents.retain(|entry| entry.identity != root.identity);
    dependents.sort_by(|left, right| left.identity.cmp(&right.identity));
    let mut commands = vec![
        Cmd::header("Package History", root.identity),
        Components::kv_list(
            Some("Native Package Information"),
            vec![
                ("Name", root.name.as_str()),
                ("Version", root.version.as_str()),
                ("Install Reason", root.reason.as_str()),
            ],
        ),
    ];
    commands.extend(transaction_history(&root.name)?);
    commands.push(Cmd::info(
        "OMG history is matched by package name, not by installed build or architecture.",
    ));
    if dependents.is_empty() {
        commands.push(Cmd::info(
            "No other installed packages directly require this package.",
        ));
    } else {
        commands.push(Cmd::card(
            format!("Currently required by ({} packages)", dependents.len()),
            dependents.into_iter().map(|entry| entry.identity).collect(),
        ));
    }
    Ok(Cmd::batch(commands))
}

fn newest_transactions_for_package<'a>(
    transactions: &'a [crate::core::history::Transaction],
    package: &str,
) -> Vec<&'a crate::core::history::Transaction> {
    let mut relevant: Vec<_> = transactions
        .iter()
        .filter(|transaction| {
            transaction
                .changes
                .iter()
                .any(|change| change.name == package)
        })
        .collect();
    relevant.sort_by_key(|entry| std::cmp::Reverse(entry.timestamp));
    relevant
}

fn build_blame_output(package: &str) -> Result<Cmd<()>> {
    // First check if package is installed
    let Some((version, install_reason)) = get_package_info(package)? else {
        use crate::cli::components::Components;
        return Ok(Components::error_with_suggestion(
            format!("Package '{package}' is not installed"),
            "Try 'omg search' to find available packages",
        ));
    };

    let mut commands = vec![Cmd::header("Package History", package), Cmd::spacer()];

    use crate::cli::components::Components;
    commands.push(Components::kv_list(
        Some("Package Information"),
        vec![
            ("Name", package),
            ("Version", &version),
            ("Install Reason", &install_reason),
        ],
    ));

    commands.extend(transaction_history(package)?);
    commands.push(Cmd::spacer());
    commands.push(show_required_by(package)?);
    Ok(Cmd::batch(commands))
}

fn transaction_history(package: &str) -> Result<Vec<Cmd<()>>> {
    let mut commands = Vec::new();
    let history = HistoryManager::new()?;
    let transactions = history.load()?;

    let relevant = newest_transactions_for_package(&transactions, package);

    if relevant.is_empty() {
        use crate::cli::tea::{StyledTextConfig, TextStyle};
        commands.push(Cmd::spacer());
        commands.push(Cmd::styled_text(StyledTextConfig {
            text: "No OMG transaction history found for this package".to_string(),
            style: TextStyle::Muted,
        }));
    } else {
        let txn_content: Vec<String> = relevant
            .iter()
            .take(10)
            .filter_map(|txn| {
                // Safe: we filtered for transactions containing this package above
                let change = txn.changes.iter().find(|c| c.name == package)?;

                let action = match (txn.transaction_type, txn.success) {
                    (TransactionType::Install, true) => "installed",
                    (TransactionType::Remove, true) => "removed",
                    (TransactionType::Update, true) => "updated",
                    (TransactionType::Sync, true) => "synced",
                    (TransactionType::Install, false) => "failed to install",
                    (TransactionType::Remove, false) => "failed to remove",
                    (TransactionType::Update, false) => "failed to update",
                    (TransactionType::Sync, false) => "failed to sync",
                };

                let version_info = match (&change.old_version, &change.new_version) {
                    (None, Some(new)) => format!("→ {new}"),
                    (Some(old), Some(new)) => format!("{old} → {new}"),
                    (Some(old), None) => format!("{old} → (removed)"),
                    (None, None) => String::new(),
                };

                let time = format_timestamp(txn.timestamp.as_second());
                Some(format!(
                    "{} {} {} ({})",
                    time, action, version_info, change.source
                ))
            })
            .collect();

        commands.push(Cmd::spacer());
        commands.push(Cmd::card(
            format!("OMG Transaction History ({})", relevant.len()),
            txn_content,
        ));

        if relevant.len() > 10 {
            use crate::cli::tea::{StyledTextConfig, TextStyle};
            commands.push(Cmd::styled_text(StyledTextConfig {
                text: format!("... and {} more transactions", relevant.len() - 10),
                style: TextStyle::Muted,
            }));
        }
    }

    Ok(commands)
}

#[cfg(feature = "arch")]
fn get_package_info(package: &str) -> Result<Option<(String, String)>> {
    #[cfg(any(feature = "debian", feature = "debian-pure"))]
    if crate::core::env::distro::is_debian_like() {
        return get_package_info_debian(package);
    }

    use crate::cli::style;

    let handle = crate::cli::open_local_alpm()?;

    let localdb = handle.localdb();

    match localdb.pkg(package) {
        Ok(pkg) => {
            let reason = match pkg.reason() {
                alpm::PackageReason::Explicit => style::version("explicit (user installed)"),
                alpm::PackageReason::Depend => style::path("dependency"),
            };
            Ok(Some((pkg.version().to_string(), reason)))
        }
        Err(alpm::Error::PkgNotFound) => Ok(None),
        Err(error) => Err(anyhow::anyhow!(
            "Failed to look up '{package}' in the local database: {error}"
        )),
    }
}

#[cfg(any(feature = "debian", feature = "debian-pure"))]
fn get_package_info_debian(package: &str) -> Result<Option<(String, String)>> {
    use crate::cli::style;
    use crate::package_managers::debian_db;

    match debian_db::get_package_version(package)? {
        Some(version) => {
            let is_auto = debian_db::is_package_auto_installed(package)?;

            let reason = if is_auto {
                style::path("dependency (auto-installed)")
            } else {
                style::version("explicit (user installed)")
            };

            Ok(Some((version, reason)))
        }
        None => Ok(None),
    }
}

#[cfg(all(
    any(feature = "debian", feature = "debian-pure"),
    not(feature = "arch")
))]
fn get_package_info(package: &str) -> Result<Option<(String, String)>> {
    get_package_info_debian(package)
}

#[cfg(not(any(feature = "arch", feature = "debian", feature = "debian-pure")))]
fn get_package_info(_package: &str) -> Result<Option<(String, String)>> {
    anyhow::bail!("Package information is not available without an Arch or Debian package backend");
}

#[cfg(feature = "arch")]
fn show_required_by(package: &str) -> Result<Cmd<()>> {
    #[cfg(any(feature = "debian", feature = "debian-pure"))]
    if crate::core::env::distro::is_debian_like() {
        return show_required_by_debian(package);
    }

    let handle = crate::cli::open_local_alpm()?;
    let required_by = crate::cli::local_reverse_deps(&handle, package);

    if required_by.is_empty() {
        Ok(Cmd::info("Nothing depends on this package"))
    } else {
        Ok(crate::cli::components::Components::limited_card(
            format!("Required by ({} packages)", required_by.len()),
            required_by,
            REVERSE_DEPENDENCY_DISPLAY_LIMIT,
        ))
    }
}

#[cfg(any(feature = "debian", feature = "debian-pure"))]
fn show_required_by_debian(package: &str) -> Result<Cmd<()>> {
    use crate::package_managers::debian_db;

    let (_, reverse_deps) = debian_db::get_package_dependencies(package)?;

    let deps: Vec<_> = reverse_deps.into_iter().filter(|d| !d.is_empty()).collect();

    if deps.is_empty() {
        Ok(Cmd::info("Nothing depends on this package"))
    } else {
        Ok(crate::cli::components::Components::limited_card(
            format!("Required by ({} packages)", deps.len()),
            deps,
            REVERSE_DEPENDENCY_DISPLAY_LIMIT,
        ))
    }
}

#[cfg(all(
    any(feature = "debian", feature = "debian-pure"),
    not(feature = "arch")
))]
fn show_required_by(package: &str) -> Result<Cmd<()>> {
    show_required_by_debian(package)
}

#[cfg(not(any(feature = "arch", feature = "debian", feature = "debian-pure")))]
fn show_required_by(_package: &str) -> Result<Cmd<()>> {
    anyhow::bail!(
        "Dependency information is not available without an Arch or Debian package backend"
    );
}

fn format_timestamp(ts: i64) -> String {
    crate::cli::format_short_timestamp(ts)
}

#[cfg(test)]
mod ordering_tests {
    use super::*;
    use crate::core::history::{PackageChange, Transaction};

    fn transaction(id: &str, timestamp: &str, package: &str) -> Transaction {
        Transaction {
            id: id.to_string(),
            timestamp: timestamp.parse().expect("timestamp"),
            transaction_type: TransactionType::Install,
            changes: vec![PackageChange {
                name: package.to_string(),
                old_version: None,
                new_version: Some("1.0".to_string()),
                source: "test".to_string(),
            }],
            success: true,
        }
    }

    #[test]
    fn package_history_is_sorted_by_timestamp_not_storage_order() {
        let history = vec![
            transaction("new", "2026-01-02T00:00:00Z", "vim"),
            transaction("other", "2026-01-03T00:00:00Z", "bash"),
            transaction("old", "2026-01-01T00:00:00Z", "vim"),
        ];

        let relevant = newest_transactions_for_package(&history, "vim");
        assert_eq!(
            relevant
                .iter()
                .map(|entry| entry.id.as_str())
                .collect::<Vec<_>>(),
            ["new", "old"]
        );
    }
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
    async fn blame_without_backend_does_not_pretend_the_package_is_missing() {
        let error = run("bash")
            .await
            .expect_err("blame with no backend must not look like not-installed");
        let expected = match crate::package_managers::resolve_backend() {
            Ok(crate::package_managers::Backend::MacOS) => {
                "Package installation history is not implemented for Homebrew".to_string()
            }
            Err(error) => error.to_string(),
            Ok(_) => "not available without an Arch or Debian package backend".to_string(),
        };
        assert!(
            error.to_string().contains(&expected),
            "selected backend must fail with its own unsupported-operation cause: {error}"
        );
    }

    #[test]
    fn required_by_without_backend_is_an_error() {
        let error = show_required_by("bash")
            .expect_err("dependency lookup with no backend must not look like success");
        assert!(
            error
                .to_string()
                .contains("not available without an Arch or Debian package backend")
        );
    }
}
