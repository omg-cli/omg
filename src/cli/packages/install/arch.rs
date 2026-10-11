use anyhow::{Context, Result};
use dialoguer::Select;
use futures::future::BoxFuture;

use crate::cli::{modern_ui, style, ui};
#[cfg(unix)]
use crate::core::client::DaemonClient;
#[cfg(unix)]
use crate::core::client::SyncDaemonClient;
use crate::core::security::is_local_package_file;
#[cfg(unix)]
use crate::daemon::protocol::WirePackageSource;
use crate::package_managers::alpm_ops::MISSING_FROM_REPOS_MARKER;
use crate::package_managers::{AurClient, get_package_manager};

use super::{MAX_REPLACEMENT_HOPS, enforce_install_policy};

pub async fn install(packages: &[String], yes: bool, replacement_hops: u32) -> Result<()> {
    let pm = get_package_manager()?;
    let policy =
        crate::core::security::SecurityPolicy::load_default().map_err(anyhow::Error::from)?;
    let vulnerability_scanner = crate::core::security::vulnerability::VulnerabilityScanner::new();

    modern_ui::print_phase_header(
        "📦",
        "Install",
        &format!(
            "{} {}",
            packages.len(),
            if packages.len() == 1 {
                "package"
            } else {
                "packages"
            }
        ),
    );

    let pb = modern_ui::modern_spinner("Resolving", "package sources");

    #[cfg(unix)]
    let mut daemon_client = if permits_live_lookup(crate::package_managers::resolve_backend()?) {
        DaemonClient::connect().await.ok()
    } else {
        None
    };

    let mut missing_packages = Vec::new();
    for pkg in packages {
        if is_local_package_file(pkg) {
            // A local archive has no repository-signature evidence at this
            // boundary. Keep it Community so require_pgp/minimum-grade policy
            // cannot mistake a path for a verified official package.
            policy.check_package(
                pkg,
                false,
                None,
                crate::core::security::SecurityGrade::Community,
            )?;
            modern_ui::finish_info(
                &pb,
                &format!(
                    "Local package: {}",
                    crate::core::security::artifact::display_target(pkg)
                ),
            );
            continue;
        }

        let is_official = lookup_official_package(
            #[cfg(unix)]
            daemon_client.as_mut(),
            pkg,
        )
        .await?;

        if is_official {
            let info = get_official_package_info(pkg)?
                .with_context(|| format!("Official package metadata disappeared for {pkg}"))?;
            enforce_install_policy(
                &policy,
                &vulnerability_scanner,
                pkg,
                &info.version,
                false,
                crate::core::security::policy::combined_license_expression(
                    info.licenses.iter().map(String::as_str),
                )
                .as_deref(),
            )
            .await?;
        } else {
            missing_packages.push(pkg.clone());
        }
    }

    let official = packages_excluding(packages, &missing_packages);
    modern_ui::finish_success(
        &pb,
        "Resolved",
        &format!(
            "{} official · {} AUR",
            official.len(),
            missing_packages.len()
        ),
    );

    // Officially-resolvable packages must be installed even when other
    // requested names need the AUR fallback. Previously a request with
    // exactly one unresolved name skipped `pm.install` entirely, silently
    // dropping its official siblings from the transaction while still
    // reporting success for them.
    let operation_result = if official.len() == packages.len() {
        match pm.install(packages).await {
            Ok(()) => Ok(()),
            Err(error) => {
                let message = error.to_string();
                if let Some(package_name) = extract_missing_package(&message, packages) {
                    missing_packages.push(package_name.clone());
                    let retry_official = packages_excluding(packages, &missing_packages);
                    async {
                        // ALPM transactions are atomic: the failed transaction
                        // installed none of its siblings. Install those siblings
                        // explicitly before routing the missing name to AUR.
                        if !retry_official.is_empty() {
                            pm.install(&retry_official).await?;
                        }
                        handle_missing_package(package_name, error, yes, replacement_hops).await
                    }
                    .await
                } else {
                    Err(error)
                }
            }
        }
    } else {
        async {
            if !official.is_empty() {
                pm.install(&official).await?;
            }

            for missing_pkg in &missing_packages {
                handle_missing_package(
                    missing_pkg.clone(),
                    anyhow::anyhow!("Package not found in official repos"),
                    yes,
                    replacement_hops,
                )
                .await?;
            }
            Ok(())
        }
        .await
    };

    record_install_history(packages, &missing_packages, operation_result)?;

    let completed_requests = packages_excluding(packages, &missing_packages);
    if !completed_requests.is_empty() {
        crate::core::usage::track_install_result(&completed_requests, true);
    }
    Ok(())
}

fn packages_excluding(packages: &[String], excluded: &[String]) -> Vec<String> {
    packages
        .iter()
        .filter(|package| !excluded.contains(*package))
        .cloned()
        .collect()
}

fn record_install_history(
    packages: &[String],
    aur_packages: &[String],
    operation_result: Result<()>,
) -> Result<()> {
    use crate::core::history::{HistoryManager, TransactionType};

    let changes = parent_install_changes(packages, aur_packages);
    if changes.is_empty() {
        return operation_result;
    }

    HistoryManager::new()?.finish_operation(TransactionType::Install, changes, operation_result)
}

fn parent_install_changes(
    packages: &[String],
    aur_packages: &[String],
) -> Vec<crate::core::history::PackageChange> {
    use crate::core::history::PackageChange;

    // Packages handled by the dedicated AUR path record their own entries
    // with the actual installed identity; skip them here to avoid doubles.
    packages
        .iter()
        .filter(|package| !aur_packages.contains(*package))
        .map(|package| PackageChange {
            name: history_package_name(package),
            old_version: None,
            new_version: None,
            // AUR candidates never reach this recorder: they are
            // handled (and recorded) by record_aur_history.
            source: if is_local_package_file(package) {
                "local"
            } else {
                "pacman"
            }
            .to_string(),
        })
        .collect()
}

fn history_package_name(package: &str) -> String {
    if !is_local_package_file(package) {
        return package.to_string();
    }

    try_local_package_name(package).unwrap_or_else(|error| {
        // History must retain the package operation's original error even when
        // an invalid local archive has no readable metadata.
        tracing::warn!("Could not read local package name for history: {error}");
        crate::core::security::artifact::handoff_original(package)
            .unwrap_or(package)
            .to_string()
    })
}

fn try_local_package_name(package: &str) -> Result<String> {
    Ok(crate::package_managers::alpm_ops::load_local_package_metadata(package)?.name)
}

fn local_archive_preview(
    package: &str,
) -> Result<Option<crate::package_managers::alpm_ops::LocalPackageMetadata>> {
    if !is_local_package_file(package) {
        return Ok(None);
    }

    crate::package_managers::alpm_ops::load_local_package_metadata(package).map(Some)
}

pub async fn install_dry_run(packages: &[String]) -> Result<()> {
    use comfy_table::{Table, modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL};

    modern_ui::print_phase_header("📋", "Install Preview", "dry run");

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec!["Package", "Version", "Size", "Status"]);

    let mut total_size: u64 = 0;
    #[cfg(unix)]
    let mut daemon_client = if permits_live_lookup(crate::package_managers::resolve_backend()?) {
        SyncDaemonClient::acquire().ok()
    } else {
        None
    };

    for pkg_name in packages {
        if let Some(info) = local_archive_preview(pkg_name)? {
            let size_mb = info.installed_size as f64 / 1024.0 / 1024.0;
            table.add_row(vec![
                style::emphasis(&info.name),
                style::accent(&info.version.to_string()),
                format!("{size_mb:.2} MB installed"),
                format!("{} Local archive", style::positive("✓")),
            ]);
            continue;
        }

        #[cfg(unix)]
        {
            if let Some(client) = daemon_client.as_mut() {
                let search_result = client.search(pkg_name, Some(8));
                match search_result {
                    Ok(search_result) => {
                        let is_official = search_result.packages.iter().any(|pkg| {
                            pkg.name == pkg_name.as_str()
                                && pkg.source == WirePackageSource::Official
                        });

                        if is_official
                            && let Ok(info) = client.info(pkg_name)
                            && info.source == WirePackageSource::Official
                        {
                            let size_mb = info.download_size as f64 / 1024.0 / 1024.0;
                            total_size += info.download_size;

                            table.add_row(vec![
                                style::emphasis(&info.name),
                                style::accent(&info.version),
                                format!("{size_mb:.2} MB"),
                                format!("{} Official", style::positive("✓")),
                            ]);
                            continue;
                        }

                        // Unknown official packages fall through to an AUR
                        // lookup instead of being reported as a successful guess.
                    }
                    Err(_) => {
                        daemon_client = None;
                    }
                }
            }
        }

        match crate::package_managers::get_sync_pkg_info(pkg_name) {
            Ok(Some(info)) => {
                let size_mb = info.download_size.unwrap_or(0) as f64 / 1024.0 / 1024.0;
                total_size += info.download_size.unwrap_or(0);

                table.add_row(vec![
                    style::emphasis(&info.name),
                    style::accent(&info.version.to_string()),
                    format!("{size_mb:.2} MB"),
                    format!("{} Official", style::positive("✓")),
                ]);
            }
            Ok(None) => {
                if !permits_live_lookup(crate::package_managers::resolve_backend()?) {
                    anyhow::bail!("Package '{pkg_name}' was not found");
                }
                let (info, _) = resolve_aur_package(pkg_name)
                    .await
                    .with_context(|| format!("Package '{pkg_name}' was not found"))?;
                table.add_row(vec![
                    style::emphasis(&info.name),
                    style::community(&info.version.to_string()),
                    String::new(),
                    format!("{} AUR", style::positive("✓")),
                ]);
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("Failed to look up {pkg_name} in official repositories")
                });
            }
        }
    }

    println!("{table}");
    println!();
    println!(
        "  {} Total download size: {}",
        style::accent("→"),
        style::emphasis(&format!("{:.2} MB", total_size as f64 / 1024.0 / 1024.0))
    );
    println!();
    println!(
        "  {} {} No changes will be made (dry run)",
        style::info("ℹ"),
        style::dim("•")
    );
    println!();

    Ok(())
}

/// Identify which requested package caused a transaction failure.
///
/// Only the transaction layer's canonical missing-package diagnostic
/// ([`MISSING_FROM_REPOS_MARKER`]) may redirect an install into the AUR
/// fallback. The package name is extracted from the quoted diagnostic and
/// matched exactly against the request, so unrelated failures that merely
/// mention a package name (conflicts, commit errors, disk-full) are never
/// misrouted.
fn extract_missing_package(msg: &str, packages: &[String]) -> Option<String> {
    let line = msg
        .lines()
        .find(|l| l.contains(MISSING_FROM_REPOS_MARKER))?;
    let reported = line.split("Package '").nth(1)?;
    let reported = reported.split("' not found").next()?;
    packages.iter().find(|p| p.as_str() == reported).cloned()
}

#[cfg(unix)]
async fn daemon_has_official_package(client: &mut DaemonClient, package: &str) -> Result<bool> {
    let result = client.search(package, Some(8)).await?;
    Ok(result
        .packages
        .iter()
        .any(|pkg| pkg.name == package && pkg.source == WirePackageSource::Official))
}

async fn lookup_official_package(
    #[cfg(unix)] daemon_client: Option<&mut DaemonClient>,
    package: &str,
) -> Result<bool> {
    #[cfg(unix)]
    if let Some(client) = daemon_client {
        match daemon_has_official_package(client, package).await {
            Ok(found) => return Ok(found),
            Err(error) => {
                tracing::debug!("Daemon official-package lookup failed for {package}: {error}");
            }
        }
    }

    get_official_package_info(package)
        .map(|info| info.is_some())
        .with_context(|| format!("Failed to look up {package} in official repositories"))
}

fn get_official_package_info(
    package: &str,
) -> Result<Option<crate::package_managers::types::PackageInfo>> {
    if crate::core::paths::test_mode() {
        crate::package_managers::get_package_info(package)
    } else {
        crate::package_managers::get_sync_pkg_info(package)
    }
}

/// Handle a package that could not be resolved in the official repositories:
/// try the AUR (preferring `-bin` builds), offer suggestions, or fail with the
/// original error.
///
/// Returns a boxed future because accepting a suggestion recurses back into
/// [`install`] through the public entry point; the box breaks the otherwise
/// infinitely-sized future type.
fn handle_missing_package(
    pkg_name: String,
    original_error: anyhow::Error,
    yes: bool,
    replacement_hops: u32,
) -> BoxFuture<'static, Result<()>> {
    Box::pin(async move {
        if !permits_live_lookup(crate::package_managers::resolve_backend()?) {
            return Err(mock_missing_error(&pkg_name, original_error));
        }
        match try_aur_package(&pkg_name).await {
            Ok(aur_pkg) => return handle_aur_package(aur_pkg, yes).await,
            Err(error) if is_aur_not_found(&error) => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("Failed to look up {pkg_name} on the AUR after official lookup missed")
                });
            }
        }

        let suggestions = try_get_suggestions(&pkg_name).await;
        if suggestions.is_empty() {
            return Err(original_error);
        }

        modern_ui::print_error(&format!("Package '{pkg_name}' not found"));
        modern_ui::print_info("Did you mean one of these?");
        println!();

        if !yes && console::user_attended() {
            // The interactive picker performs blocking TTY reads; run it on a
            // blocking thread so the async executor is never stalled.
            let (selection, suggestions) = tokio::task::spawn_blocking(move || {
                let selection = Select::with_theme(&ui::prompt_theme())
                    .with_prompt("Select a replacement (or Esc to abort)")
                    .default(0)
                    .items(&suggestions)
                    .interact_opt();
                (selection, suggestions)
            })
            .await
            .map_err(|error| anyhow::anyhow!("Suggestion prompt task failed: {error}"))?;

            if let Some(index) = selection? {
                let new_pkg = suggestions[index].clone();
                println!();
                println!(
                    "  {} Replacing {} with {}",
                    style::accent("→"),
                    style::emphasis(&pkg_name),
                    style::positive(&new_pkg)
                );
                println!();
                let remaining_hops = consume_replacement_hop(replacement_hops, &new_pkg)?;
                return super::install_with_replacement_budget(
                    &[new_pkg],
                    yes,
                    false,
                    false,
                    remaining_hops,
                    super::MutationConfirmation::AlreadyConfirmed,
                )
                .await;
            }
        } else {
            for (i, suggestion) in suggestions.iter().enumerate().take(5) {
                println!(
                    "    {}. {}",
                    style::accent(&(i + 1).to_string()),
                    style::emphasis(suggestion)
                );
            }
            println!();
        }

        Err(original_error)
    })
}

fn permits_live_lookup(backend: crate::package_managers::Backend) -> bool {
    backend != crate::package_managers::Backend::Mock
}

fn mock_missing_error(package: &str, original_error: anyhow::Error) -> anyhow::Error {
    original_error.context(format!(
        "Package '{package}' not found. Suggestion: use 'omg search' to check available package names"
    ))
}

fn consume_replacement_hop(remaining_hops: u32, replacement: &str) -> Result<u32> {
    remaining_hops.checked_sub(1).ok_or_else(|| {
        anyhow::anyhow!(
            "Aborting after {MAX_REPLACEMENT_HOPS} replacement attempts; install '{replacement}' explicitly if intended"
        )
    })
}

async fn try_get_suggestions(query: &str) -> Vec<String> {
    #[cfg(unix)]
    if let Ok(mut client) = DaemonClient::connect().await
        && let Ok(suggestions) = client.suggest(query, Some(15)).await
        && !suggestions.is_empty()
    {
        return suggestions;
    }
    let Ok(names) = crate::cli::commands::available_package_names().await else {
        return Vec::new();
    };
    crate::core::completion::CompletionEngine::new()
        .fuzzy_match(query, names)
        .into_iter()
        .take(15)
        .collect()
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
enum AurLookupError {
    #[error("Package not found in AUR")]
    NotFound,
}

fn is_aur_not_found(error: &anyhow::Error) -> bool {
    error.downcast_ref::<AurLookupError>() == Some(&AurLookupError::NotFound)
}

fn select_aur_candidate(
    results: &[crate::core::Package],
    pkg_name: &str,
) -> Option<(crate::core::Package, bool)> {
    let exact_match = results.iter().find(|package| package.name == pkg_name);
    let bin_name = format!("{pkg_name}-bin");
    let bin_match = results.iter().find(|package| package.name == bin_name);

    bin_match
        .map(|package| (package.clone(), exact_match.is_some()))
        .or_else(|| exact_match.cloned().map(|package| (package, false)))
}

async fn resolve_aur_package(pkg_name: &str) -> Result<(crate::core::Package, bool)> {
    let aur = AurClient::new()?;
    let results = aur.search(pkg_name).await?;
    select_aur_candidate(&results, pkg_name).ok_or_else(|| AurLookupError::NotFound.into())
}

async fn try_aur_package(pkg_name: &str) -> Result<crate::core::Package> {
    let (package, preferred_binary) = resolve_aur_package(pkg_name).await?;

    if preferred_binary {
        println!();
        println!(
            "  {} Found pre-built binary package: {}",
            style::accent("→"),
            style::positive(&package.name)
        );
        println!(
            "  {} This installs in seconds instead of compiling from source",
            style::info("ℹ")
        );
    }

    Ok(package)
}

async fn handle_aur_package(aur_pkg: crate::core::Package, yes: bool) -> Result<()> {
    let policy =
        crate::core::security::SecurityPolicy::load_default().map_err(anyhow::Error::from)?;
    let vulnerability_scanner = crate::core::security::vulnerability::VulnerabilityScanner::new();
    enforce_install_policy(
        &policy,
        &vulnerability_scanner,
        &aur_pkg.name,
        &aur_pkg.version,
        true,
        None,
    )
    .await?;
    modern_ui::print_aur_package_info(
        &aur_pkg.name,
        &aur_pkg.version.to_string(),
        &aur_pkg.description,
    );

    // The confirmation prompt performs blocking TTY reads; run it on a
    // blocking thread so the async executor is never stalled.
    let should_install = if yes {
        modern_ui::print_info("Auto-accepting (--yes flag)");
        true
    } else if console::user_attended() {
        let prompt = format!("Install {} from AUR?", aur_pkg.name);
        tokio::task::spawn_blocking(move || {
            dialoguer::Confirm::with_theme(&ui::prompt_theme())
                .with_prompt(prompt)
                .default(false)
                .interact()
        })
        .await
        .map_err(|error| anyhow::anyhow!("Confirmation prompt task failed: {error}"))??
    } else {
        false
    };

    if !should_install {
        // Record the aborted attempt once. The parent recorder skips its empty
        // official-package change set, so this remains the sole history entry.
        modern_ui::print_error("Installation cancelled");
        return record_aur_history(
            &aur_pkg.name,
            None,
            Err(anyhow::anyhow!("Installation cancelled by user")),
        );
    }

    modern_ui::print_aur_build_phase("Building", &aur_pkg.name);

    let aur_client = AurClient::new()?;
    let outcome = aur_client.install(&aur_pkg.name).await;
    // Record with the identity actually present in the local database: AUR
    // builds can produce package names/versions that differ from the AUR
    // metadata the user requested.
    let installed_version = if outcome.is_ok() {
        installed_package_version(&aur_pkg.name)
    } else {
        None
    };
    // Success output and usage tracking must reflect the actual outcome:
    // record_aur_history persists the attempt and returns the install result.
    record_aur_history(&aur_pkg.name, installed_version, outcome)?;

    modern_ui::print_success(&format!("Built and installed {} from AUR", aur_pkg.name));
    crate::core::usage::track_install(std::slice::from_ref(&aur_pkg.name));
    Ok(())
}

/// Record one AUR install attempt in package history.
///
/// `installed_version` comes from the local pacman database after a
/// successful build so split-package renames are captured accurately.
fn record_aur_history(
    name: &str,
    installed_version: Option<String>,
    outcome: Result<()>,
) -> Result<()> {
    use crate::core::history::{HistoryManager, PackageChange, TransactionType};
    let change = PackageChange {
        name: name.to_string(),
        old_version: None,
        new_version: installed_version,
        source: "aur".to_string(),
    };
    HistoryManager::new()?.finish_operation(TransactionType::Install, vec![change], outcome)
}

/// Version of `name` in the local pacman database, if installed.
fn installed_package_version(name: &str) -> Option<String> {
    // installed_package_version returns Option: an unusable ALPM handle
    // simply means "cannot determine" -> no version.
    let Ok(alpm) = crate::package_managers::alpm_ops::open_default_alpm() else {
        return None;
    };
    let pkg = alpm.localdb().pkg(name).ok()?;
    Some(pkg.version().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;

    #[test]
    fn selected_mock_cannot_enter_live_lookup() {
        use crate::package_managers::Backend;
        assert!(!permits_live_lookup(Backend::Mock));
        for backend in [
            Backend::Arch,
            Backend::Debian,
            Backend::Fedora,
            Backend::MacOS,
        ] {
            assert!(permits_live_lookup(backend));
        }
    }

    #[test]
    fn mock_missing_keeps_original_operation_error() {
        let original =
            std::io::Error::new(std::io::ErrorKind::NotFound, "official fixture missing");
        let error = mock_missing_error("missing-fixture-package", original.into());
        assert_eq!(
            error.to_string(),
            "Package 'missing-fixture-package' not found. Suggestion: use 'omg search' to check available package names"
        );
        assert!(
            error
                .chain()
                .any(|cause| cause.downcast_ref::<std::io::Error>().is_some())
        );
        assert!(format!("{error:#}").contains("official fixture missing"));
    }

    struct VulnerableSource;

    impl crate::core::security::vulnerability::VulnerabilitySource for VulnerableSource {
        fn scan_package<'a>(
            &'a self,
            _name: &'a str,
            _version: &'a crate::package_managers::types::Version,
        ) -> Pin<
            Box<
                dyn Future<
                        Output = std::result::Result<
                            Vec<crate::core::security::vulnerability::VulnerabilityReport>,
                            crate::core::security::vulnerability::VulnerabilityError,
                        >,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async {
                Ok(vec![
                    crate::core::security::vulnerability::VulnerabilityReport {
                        id: "CVE-test".to_string(),
                        summary: "known vulnerability".to_string(),
                        score: None,
                    },
                ])
            })
        }
    }

    #[tokio::test]
    async fn install_policy_rejects_known_vulnerabilities() {
        let policy = crate::core::security::SecurityPolicy::default();
        let version = crate::package_managers::parse_version_or_zero("1.0-1");

        let error = enforce_install_policy(
            &policy,
            &VulnerableSource,
            "example",
            &version,
            false,
            Some("MIT"),
        )
        .await
        .expect_err("vulnerable packages must be below the default Community grade");

        assert!(error.to_string().contains("below required minimum"));
    }

    #[test]
    fn dry_run_rejects_unreadable_local_archive_metadata() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let archive = directory.path().join("fixture.pkg.tar.zst");
        std::fs::write(&archive, b"not a package archive").expect("write archive fixture");

        let error = local_archive_preview(archive.to_str().expect("UTF-8 path"))
            .expect_err("preview must parse the embedded package identity");
        assert!(
            error
                .to_string()
                .contains("Failed to read local package metadata")
                || error.to_string().contains("Failed to initialize ALPM")
        );
    }

    fn aur_package(name: &str) -> crate::core::Package {
        crate::core::Package {
            name: name.to_string(),
            version: crate::package_managers::parse_version_or_zero("1.0-1"),
            description: String::new(),
            source: crate::core::PackageSource::Aur,
            installed: false,
        }
    }

    #[test]
    fn aur_not_found_classification_is_typed() {
        let not_found = anyhow::Error::new(AurLookupError::NotFound);
        assert!(is_aur_not_found(&not_found));
        assert!(!is_aur_not_found(&anyhow::anyhow!(
            "Package not found in AUR"
        )));
    }

    #[cfg(unix)]
    #[test]
    #[serial_test::serial]
    fn aur_install_resolution_preserves_exact_candidates_beyond_cached_search_cap() -> Result<()> {
        use std::io::Write as _;
        use std::os::unix::fs::MetadataExt as _;
        const NAME: &str = "cli::packages::install::arch::tests::aur_install_resolution_preserves_exact_candidates_beyond_cached_search_cap";
        if crate::core::testing::run_isolated_test(NAME) {
            return Ok(());
        }
        if crate::config::Settings::rerun_test_unprivileged(NAME) {
            return Ok(());
        }
        anyhow::ensure!(
            !crate::core::is_root(),
            "fixture must use ordinary cache overrides"
        );
        #[derive(Debug, PartialEq, Eq)]
        struct FixtureFileState {
            bytes: Vec<u8>,
            device: u64,
            inode: u64,
            mode: u32,
            uid: u32,
            gid: u32,
            modified: (i64, i64),
            changed: (i64, i64),
        }
        fn file_state(path: &std::path::Path) -> Result<FixtureFileState> {
            let meta = std::fs::symlink_metadata(path)?;
            anyhow::ensure!(meta.is_file(), "fixture remains a regular file");
            Ok(FixtureFileState {
                bytes: std::fs::read(path)?,
                device: meta.dev(),
                inode: meta.ino(),
                mode: meta.mode(),
                uid: meta.uid(),
                gid: meta.gid(),
                modified: (meta.mtime(), meta.mtime_nsec()),
                changed: (meta.ctime(), meta.ctime_nsec()),
            })
        }
        for (decoy_count, source_version, binary_version, expected) in [
            (50, None, None, None),
            (
                50,
                Some("1.0-1"),
                Some("2.0-1"),
                Some(("ztool-bin", "2.0-1", true)),
            ),
            (50, Some("1.0-1"), None, Some(("ztool", "1.0-1", false))),
            (50, None, Some("2.0-1"), Some(("ztool-bin", "2.0-1", false))),
            (
                50,
                Some("1.0-1"),
                Some("not a version"),
                Some(("ztool", "1.0-1", false)),
            ),
            (
                3,
                Some("1.0-1"),
                Some("2.0-1"),
                Some(("ztool-bin", "2.0-1", true)),
            ),
        ] {
            let directory = tempfile::tempdir()?;
            let cache = directory.path().join("cache");
            let meta_dir = cache.join("aur/_meta");
            let config = directory.path().join("config");
            std::fs::create_dir_all(&meta_dir)?;
            std::fs::create_dir_all(&config)?;
            let config_path = config.join("config.toml");
            std::fs::write(
                &config_path,
                "[aur]\nuse_metadata_archive = true\nmetadata_cache_ttl_secs = 300\n",
            )?;
            let archive_path = meta_dir.join("packages-meta-ext-v1.json.gz");
            let index_path = meta_dir.join("packages-meta-ext-v1.rkyv");
            let mut records: Vec<_> = (0..decoy_count).map(|index| serde_json::json!({
                "Name": format!("aaa-{index:03}"), "Version": "1.0-1",
                "Description": "description mentions ztool", "Maintainer": null, "LastModified": 1
            })).collect();
            for (name, version) in [("ztool", source_version), ("ztool-bin", binary_version)] {
                if let Some(version) = version {
                    records.push(serde_json::json!({"Name":name,"Version":version,
                        "Description":"exact install fixture","Maintainer":null,"LastModified":1}));
                }
            }
            let mut gzip = flate2::write::GzEncoder::new(
                std::fs::File::create(&archive_path)?,
                flate2::Compression::fast(),
            );
            gzip.write_all(&serde_json::to_vec(&records)?)?;
            gzip.finish()?;
            crate::package_managers::build_test_aur_index(&archive_path, &index_path)?;
            let index = crate::package_managers::TestAurIndex::open(&index_path)?;
            // Independent producer/legacy-order controls: exact records exist,
            // while the generic capped substring API has fifty earlier matches.
            assert_eq!(index.get("ztool")?.is_some(), source_version.is_some());
            assert_eq!(index.get("ztool-bin")?.is_some(), binary_version.is_some());
            let decoys = index.search("ztool", 50)?;
            let visible = if decoy_count == 50 { 50 } else { 5 };
            assert_eq!(decoys.len(), visible);
            for (number, entry) in decoys.iter().take(decoy_count).enumerate() {
                assert_eq!(entry.name.as_str(), format!("aaa-{number:03}"));
            }
            let before_archive = file_state(&archive_path)?;
            let before_index = file_state(&index_path)?;
            let before_config = file_state(&config_path)?;
            temp_env::with_vars(
                [
                    ("OMG_CACHE_DIR", Some(cache.as_os_str())),
                    ("OMG_CONFIG_DIR", Some(config.as_os_str())),
                    ("OMG_TEST_MODE", None),
                    ("OMG_TEST_DISTRO", None),
                    ("SUDO_USER", None),
                    ("SUDO_HOME", None),
                    ("DOAS_USER", None),
                ],
                || -> Result<()> {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    runtime.block_on(async {
                        anyhow::ensure!(!crate::core::paths::test_mode());
                        let client = AurClient::new()?;
                        let results = tokio::time::timeout(
                            std::time::Duration::from_secs(2),
                            client.search("ztool"),
                        )
                        .await??;
                        assert!(
                            !results.is_empty() && results.len() <= 50,
                            "search remains bounded"
                        );
                        if decoy_count == 3 {
                            assert_eq!(
                                results.len(),
                                5,
                                "uncapped exact entries must not be duplicated"
                            );
                        }
                        let result = tokio::time::timeout(
                            std::time::Duration::from_secs(2),
                            resolve_aur_package("ztool"),
                        )
                        .await?;
                        if let Some((name, version, preferred)) = expected {
                            let (package, preferred_binary) = result?;
                            assert_eq!(
                                (
                                    package.name.as_str(),
                                    package.version.to_string(),
                                    preferred_binary
                                ),
                                (name, version.to_string(), preferred)
                            );
                            assert_eq!(
                                results
                                    .iter()
                                    .filter(|package| package.name == name)
                                    .count(),
                                1
                            );
                        } else {
                            let error = result.expect_err(
                                "decoys must not masquerade as exact install candidates",
                            );
                            assert!(is_aur_not_found(&error), "literal typed absence: {error:#}");
                        }
                        Ok::<_, anyhow::Error>(())
                    })
                },
            )?;
            assert_eq!(file_state(&archive_path)?, before_archive);
            assert_eq!(file_state(&index_path)?, before_index);
            assert_eq!(file_state(&config_path)?, before_config);
            eprintln!(
                "[aur-cap-fixture] uid={} source={source_version:?} binary={binary_version:?} expected={expected:?} metadata_unchanged=true",
                nix::unistd::geteuid()
            );
            directory.close()?;
        }
        Ok(())
    }

    #[test]
    fn dry_run_and_install_share_aur_binary_preference() {
        let packages = vec![aur_package("example"), aur_package("example-bin")];
        let (selected, preferred_binary) =
            select_aur_candidate(&packages, "example").expect("candidate");
        assert_eq!(selected.name, "example-bin");
        assert!(preferred_binary);

        let only_binary = vec![aur_package("binary-only-bin")];
        let (selected, preferred_binary) =
            select_aur_candidate(&only_binary, "binary-only").expect("binary candidate");
        assert_eq!(selected.name, "binary-only-bin");
        assert!(!preferred_binary);
    }

    #[test]
    fn missing_target_is_extracted_from_canonical_diagnostic() {
        let error = "✗ Package 'firefox' not found in any configured repository.\n  \
                     → Run 'omg sync' to update package databases";
        assert_eq!(
            extract_missing_package(error, &["firefox".to_string()]).as_deref(),
            Some("firefox")
        );
    }

    #[test]
    fn parent_outcome_excludes_packages_recorded_by_the_aur_path() {
        let requested = vec!["aur-only".to_string()];
        assert!(parent_install_changes(&requested, &requested).is_empty());
        assert!(packages_excluding(&requested, &requested).is_empty());
    }

    #[test]
    fn retry_plan_keeps_official_siblings_after_a_missing_package() {
        let packages = vec![
            "official-a".to_string(),
            "missing".to_string(),
            "official-b".to_string(),
        ];
        assert_eq!(
            packages_excluding(&packages, &["missing".to_string()]),
            ["official-a".to_string(), "official-b".to_string()]
        );
    }

    #[test]
    fn unrelated_failure_mentioning_a_package_never_triggers_aur_fallback() {
        // Regression: previously ANY error containing a requested name was
        // misrouted into the AUR/suggestion flow.
        let error = "✗ Transaction preparation failed: conflicting files for firefox\n  \
                     → Try running: omg update && omg install <package>";
        assert_eq!(
            extract_missing_package(error, &["firefox".to_string()]),
            None
        );
    }

    #[test]
    fn diagnostic_naming_a_different_package_does_not_match() {
        let error = "✗ Package 'firefox-esr' not found in any configured repository.";
        assert_eq!(
            extract_missing_package(error, &["firefox".to_string()]),
            None
        );
    }

    #[test]
    fn empty_or_unrelated_errors_yield_none() {
        assert_eq!(extract_missing_package("", &["vim".to_string()]), None);
        assert_eq!(
            extract_missing_package(
                "Failed to initialize ALPM (are you root?)",
                &["vim".to_string()]
            ),
            None
        );
    }

    #[test]
    fn replacement_budget_bounds_interactive_recursion() {
        assert_eq!(consume_replacement_hop(2, "next").unwrap(), 1);
        assert_eq!(consume_replacement_hop(1, "next").unwrap(), 0);
        let error = consume_replacement_hop(0, "next").unwrap_err();
        assert!(error.to_string().contains("replacement attempts"));
        assert!(error.to_string().contains("install 'next' explicitly"));
    }
}
