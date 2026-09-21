//! Pure Rust Debian/Ubuntu package manager backend
//!
//! Uses `debian_db` for ultra-fast searches and info, and spawns `apt`
//! command for transactions. This allows Debian support without C dependencies.

use std::future::Future;
use std::pin::Pin;

use anyhow::{Context, Result};

use crate::core::{Package, PackageSource};
use crate::package_managers::PackageManager;
use crate::package_managers::debian_db;
use crate::package_managers::types::UpdateInfo;

#[derive(Debug, Default)]
pub struct PureDebianPackageManager;

/// Publish authenticated package lists through APT's native trust engine.
async fn update_apt_lists(program: &std::path::Path, needs_elevation: bool) -> Result<()> {
    let program_text = program
        .to_str()
        .context("apt-get executable path is not valid UTF-8")?;
    if needs_elevation {
        crate::core::privilege::run_privileged_program(program_text, &["update"]).await?;
        return Ok(());
    }

    let status = tokio::process::Command::new(program)
        .arg("update")
        .status()
        .await
        .context("Failed to run apt-get update")?;
    anyhow::ensure!(status.success(), "apt-get update failed with {status}");
    Ok(())
}

impl PureDebianPackageManager {
    pub fn new() -> Self {
        Self
    }
}

fn validate_pure_mutation_with_privileges(packages: &[String], has_privileges: bool) -> Result<()> {
    anyhow::ensure!(!packages.is_empty(), "No packages specified");
    crate::core::security::validate_package_names(packages)?;
    anyhow::ensure!(
        has_privileges,
        "Pure Debian package transactions require root privileges"
    );
    Ok(())
}

fn validate_pure_mutation(packages: &[String]) -> Result<()> {
    anyhow::ensure!(
        cfg!(test),
        "Pure Debian mutations are unsupported: use the native APT backend; the user cache is not installation authority"
    );
    validate_pure_mutation_with_privileges(packages, crate::core::is_root() || cfg!(test))
}

impl PackageManager for PureDebianPackageManager {
    fn security_inventory(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Vec<crate::package_managers::types::SecurityPackage>>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async {
            tokio::task::spawn_blocking(crate::package_managers::debian_db::db::security_inventory)
                .await?
        })
    }

    fn name(&self) -> &'static str {
        "apt-pure"
    }

    fn search(
        &self,
        query: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Package>>> + Send + '_>> {
        let query = query.to_string();
        Box::pin(async move {
            // Index/mmap loading performs disk I/O; keep it off the executor.
            tokio::task::spawn_blocking(move || debian_db::search_fast(&query))
                .await
                .context("Debian search task failed")?
        })
    }

    fn install(
        &self,
        packages: &[String],
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let packages = packages.to_vec();
        Box::pin(async move {
            use std::time::Instant;

            validate_pure_mutation(&packages)?;
            let start = Instant::now();
            tracing::info!("Starting pure Rust install for {} packages", packages.len());

            // 1-3. Resolve, pre-flight, and URL population are all blocking
            // work (index/mmap loads, statvfs, full index reads); run the
            // whole preparation stage on the blocking pool and only the
            // download/unpack/configure pipeline stays async.
            let package_count = packages.len();
            let mut tx =
                tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
                    let mut resolver = debian_db::DependencyResolver::new().context(
                        "Failed to initialize dependency resolver. Try: omg sync",
                    )?;

                    for pkg in &packages {
                        resolver.add_package(pkg).with_context(|| {
                            format!(
                                "Package '{pkg}' not found in repositories.\n\
                                \u{1f4a1} Try:\n\
                                - omg search {pkg} (find similar packages)\n\
                                - omg sync (refresh package database)\n\
                                - Check package name spelling"
                            )
                        })?;
                    }

                    let resolution = resolver.resolve().context(
                        "Dependency resolution failed. Some required dependencies may not be available.",
                    )?;

                    tracing::debug!(
                        "Dependency resolution complete in {:.2}ms: {} to install, {} to upgrade",
                        start.elapsed().as_secs_f64() * 1000.0,
                        resolution.to_install.len(),
                        resolution.to_upgrade.len()
                    );

                    // Check disk space before starting
                    tracing::debug!(
                        "Pre-flight checks: download={} bytes, installed={} bytes",
                        resolution.download_size,
                        resolution.installed_size
                    );
                    debian_db::check_disk_space(
                        resolution.download_size,
                        resolution.installed_size,
                        &std::env::temp_dir(),
                    )
                    .context("Insufficient disk space for installation")?;

                    // Create transaction and populate URLs; a missing URL/SHA256
                    // is fatal here rather than a silent skip downstream.
                    let mut tx = debian_db::Transaction::from_resolution(resolution);
                    populate_package_urls(&mut tx).context(
                        "Failed to resolve package URLs. Repository configuration may be invalid.",
                    )?;
                    Ok(tx)
                })
                .await
                .context("Debian transaction preparation task failed")??;

            // 5. Execute transaction (downloads, unpacks, configures)
            tx.execute().await
                .context("Transaction failed. System may be inconsistent. Repair with: sudo apt-get install -f")?;

            let elapsed = start.elapsed();
            tracing::info!(
                "Pure Rust install completed in {:.2}s ({} packages)",
                elapsed.as_secs_f64(),
                package_count
            );

            Ok(())
        })
    }

    fn remove(&self, packages: &[String]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let packages = packages.to_vec();
        Box::pin(async move {
            use std::time::Instant;

            validate_pure_mutation(&packages)?;
            let start = Instant::now();
            tracing::info!(
                "Starting pure Rust package removal for {} packages",
                packages.len()
            );

            // Validate packages are installed
            for pkg in &packages {
                let pkg_name = pkg.clone();
                let installed =
                    tokio::task::spawn_blocking(move || debian_db::is_installed_fast(&pkg_name))
                        .await
                        .context("Debian is_installed task failed")??;
                if !installed {
                    anyhow::bail!(
                        "Package '{pkg}' is not installed.\n\
                        \u{1f4a1} Use 'omg list' to see installed packages"
                    );
                }
            }

            let mut tx = debian_db::Transaction::new();
            for pkg in &packages {
                tx.add_remove(pkg.clone());
            }

            // Execute removal
            tx.execute_removal()
                .await
                .context("Package removal failed")?;

            let elapsed = start.elapsed();
            tracing::info!(
                "Pure Rust removal completed in {:.2}s ({} packages)",
                elapsed.as_secs_f64(),
                packages.len()
            );

            Ok(())
        })
    }

    fn update(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            use std::time::Instant;

            anyhow::ensure!(
                crate::core::paths::test_mode() || crate::core::is_root(),
                "Pure Debian package transactions require root privileges"
            );
            anyhow::ensure!(
                cfg!(test),
                "Pure Debian mutations are unsupported; use native APT"
            );
            let start = Instant::now();
            tracing::info!("Starting pure Rust system upgrade");

            // Get list of packages to upgrade
            let updates = self
                .list_updates()
                .await
                .context("Failed to list available updates. Try: omg sync")?;

            if updates.is_empty() {
                tracing::info!("System is already up to date");
                return Ok(());
            }

            tracing::info!("Found {} packages to upgrade", updates.len());

            // Resolution + URL population are blocking index work; keep them
            // off the executor thread.
            let update_count = updates.len();
            let mut tx =
                tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
                    let mut resolver = debian_db::DependencyResolver::new()
                        .context("Failed to initialize dependency resolver")?;

                    for update in &updates {
                        resolver.add_package(&update.name).with_context(|| {
                            format!(
                                "Package '{}' not found during upgrade resolution.\n\
                                \u{1f4a1} The package may have been removed from repositories.\n\
                                Try: omg sync to refresh package database",
                                update.name
                            )
                        })?;
                    }

                    let resolution = resolver.resolve().context(
                        "Failed to resolve upgrade dependencies. Some packages may have unmet dependencies.",
                    )?;

                    tracing::debug!(
                        "Upgrade resolution complete in {:.2}ms: {} packages",
                        start.elapsed().as_secs_f64() * 1000.0,
                        resolution.to_upgrade.len()
                    );

                    debian_db::check_disk_space(
                        resolution.download_size,
                        resolution.installed_size,
                        &std::env::temp_dir(),
                    )
                    .context("Insufficient disk space for upgrade")?;

                    let mut tx = debian_db::Transaction::from_resolution(resolution);
                    populate_package_urls(&mut tx)
                        .context("Failed to resolve package URLs for upgrade")?;
                    Ok(tx)
                })
                .await
                .context("Debian upgrade preparation task failed")??;

            tx.execute().await.context(
                "Upgrade transaction failed. System may be inconsistent. Repair with: sudo apt-get install -f",
            )?;

            let elapsed = start.elapsed();
            tracing::info!(
                "Pure Rust upgrade completed in {:.2}s ({} packages)",
                elapsed.as_secs_f64(),
                update_count
            );

            Ok(())
        })
    }

    fn sync(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            // APT owns repository authentication and publication into
            // /var/lib/apt/lists. The removed custom downloader wrote a
            // separate user cache that the Debian index never consumed and,
            // critically, did not authenticate Packages indexes against the
            // signed InRelease checksum table.
            update_apt_lists(std::path::Path::new("apt-get"), !crate::core::is_root()).await
        })
    }

    fn info(
        &self,
        package: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Package>>> + Send + '_>> {
        let package = package.to_string();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || debian_db::get_info_fast(&package))
                .await
                .context("Debian info task failed")?
        })
    }

    fn list_installed(&self) -> Pin<Box<dyn Future<Output = Result<Vec<Package>>> + Send + '_>> {
        Box::pin(async move {
            let installed = tokio::task::spawn_blocking(debian_db::list_installed_fast)
                .await
                .context("Debian list_installed task failed")??;
            Ok(installed
                .into_iter()
                .map(|p| Package {
                    name: p.name,
                    version: crate::package_managers::types::parse_version_or_zero(&p.version),
                    description: p.description,
                    source: PackageSource::Official,
                    installed: true,
                })
                .collect())
        })
    }

    fn get_status(
        &self,
        fast: bool,
    ) -> Pin<Box<dyn Future<Output = Result<(usize, usize, usize, usize)>> + Send + '_>> {
        Box::pin(async move {
            let fast_counts = tokio::task::spawn_blocking(debian_db::get_counts_fast)
                .await
                .unwrap_or_else(|error| {
                    tracing::warn!("Debian status task failed: {error}");
                    Err(anyhow::anyhow!("Debian status task panicked"))
                });
            tokio::task::spawn_blocking(move || {
                debian_db::resolve_status_counts(fast, &fast_counts, accurate_status_counts)
            })
            .await
            .context("Debian status task failed")?
        })
    }

    fn list_explicit(&self) -> Pin<Box<dyn Future<Output = Result<Vec<String>>> + Send + '_>> {
        Box::pin(async move {
            tokio::task::spawn_blocking(debian_db::list_explicit_fast)
                .await
                .context("Debian list_explicit task failed")?
        })
    }

    fn list_updates(&self) -> Pin<Box<dyn Future<Output = Result<Vec<UpdateInfo>>> + Send + '_>> {
        Box::pin(async move {
            // Index/mmap loading plus rayon comparisons are blocking work;
            // run the whole computation on the blocking pool.
            tokio::task::spawn_blocking(compute_updates)
                .await
                .context("Debian list_updates task failed")?
        })
    }

    fn is_installed(
        &self,
        package: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + '_>> {
        let package = package.to_string();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || debian_db::is_installed_fast(&package))
                .await
                .context("Debian is_installed task failed")?
        })
    }
}

/// Accurate status counts with real orphan and update numbers. The fast path
/// (`debian_db::get_counts_fast`) omits both rather than reporting fake zeros;
/// this is the fallback [`debian_db::resolve_status_counts`] uses when callers
/// ask for accurate values.
pub(crate) fn accurate_status_counts() -> Result<(usize, usize, usize, usize)> {
    let installed = debian_db::list_installed_fast()?;
    let total = installed.len();
    let explicit = installed.iter().filter(|p| p.is_explicit).count();
    let orphans = debian_db::list_orphans_fast()?.len();
    let updates = compute_updates()?.len();
    Ok((total, explicit, orphans, updates))
}

/// Packages with an available version newer than the installed one.
///
/// Uses the zero-copy mmap index when loaded, falling back to the full
/// in-memory index; mmap failures are logged instead of silently swallowed.
fn compute_updates() -> Result<Vec<UpdateInfo>> {
    use std::collections::HashMap;

    // OPTIMIZATION: Get installed packages first (fast, from dpkg status)
    let installed = debian_db::list_installed_fast()?;
    if installed.is_empty() {
        return Ok(Vec::new());
    }

    // Build an architecture-qualified map so foreign-architecture packages
    // cannot be compared against the host package with the same name.
    let installed_map: HashMap<String, &str> = installed
        .iter()
        .map(|pkg| {
            (
                format!("{}:{}", pkg.name, pkg.architecture),
                pkg.version.as_str(),
            )
        })
        .collect();

    // ULTRA-FAST PATH: mmap index (zero-copy, no full index load)
    let _preload_result = debian_db::ensure_mmap_loaded();
    if debian_db::is_mmap_available() {
        match debian_db::get_updates_from_mmap(&installed_map) {
            Ok(updates) => {
                return Ok(updates
                    .into_iter()
                    .map(|(name, old_version, new_version)| UpdateInfo {
                        name,
                        old_version,
                        new_version,
                        repo: "official".to_string(),
                    })
                    .collect());
            }
            Err(error) => {
                tracing::debug!(
                    "mmap update comparison failed, falling back to full index: {error}"
                );
            }
        }
    }

    // Fallback: Load full index and use parallel comparison
    use rayon::prelude::*;

    debian_db::ensure_index_loaded()?;
    let index_pkgs = debian_db::get_detailed_packages()?;

    // Parallel version comparisons using Debian's ordering regardless of
    // which other package-manager features are enabled in this build.
    let candidates: Vec<_> = index_pkgs
        .par_iter()
        .filter_map(|pkg| {
            let installed_ver = debian_db::db::installed_version_for_arch(
                &installed_map,
                &pkg.name,
                &pkg.architecture,
                debian_db::debian_arch(),
            )?;
            (crate::package_managers::types::compare_deb_versions(&pkg.version, installed_ver)
                == std::cmp::Ordering::Greater)
                .then(|| {
                    (
                        pkg.name.clone(),
                        (*installed_ver).to_string(),
                        pkg.version.clone(),
                    )
                })
        })
        .collect();

    Ok(debian_db::db::best_update_versions(candidates)
        .into_iter()
        .map(|(name, old_version, new_version)| UpdateInfo {
            name,
            old_version,
            new_version,
            repo: "official".to_string(),
        })
        .collect())
}

/// Populate package URLs in a transaction by looking up package info from the
/// database.
///
/// Each package is matched against the repository that actually publishes it
/// (suite + component recorded per index entry), so security/custom mirrors
/// are not silently rewritten to the first enabled repo. Failures are fatal:
/// an action without URL/SHA256 would be skipped by the downloader and the
/// package would silently never be installed.
fn populate_package_urls(tx: &mut debian_db::Transaction) -> Result<()> {
    let repos = debian_db::get_enabled_binary_repos()?;
    if repos.is_empty() {
        anyhow::bail!("No enabled repositories found");
    }

    // URL resolution must use the same deterministic name candidate as the
    // dependency resolver. Re-keying raw index entries here would reintroduce
    // first/last-wins behavior across suites and architectures.
    let package_map: std::collections::HashMap<_, _> = debian_db::get_detailed_best_candidates()?
        .into_iter()
        .map(|package| (package.name.clone(), package))
        .collect();

    for action in &mut tx.to_install {
        populate_action_url(action, &package_map, &repos)
            .with_context(|| format!("resolving download URL for {}", action.name))?;
        tracing::debug!(
            "Package {name} v{version}: {size} bytes from {url}",
            name = action.name,
            version = action.version,
            size = action.size,
            url = crate::core::http::redact_url(action.url.as_deref().unwrap_or(""))
        );
    }

    for action in &mut tx.to_upgrade {
        populate_action_url(action, &package_map, &repos)
            .with_context(|| format!("resolving download URL for upgrade {}", action.name))?;
        tracing::debug!(
            "Upgrade {} to v{}: {} bytes from {}",
            action.name,
            action.version,
            action.size,
            crate::core::http::redact_url(action.url.as_deref().unwrap_or(""))
        );
    }

    Ok(())
}

fn apt_lists_suite_key(suite: &str) -> String {
    suite
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn repository_suite_matches(repo_suite: &str, package_suite: &str) -> bool {
    !package_suite.is_empty() && apt_lists_suite_key(repo_suite) == package_suite
}

fn apt_lists_source_key(uri: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(uri).ok()?;
    let host = parsed.host_str()?;
    let mut source = host.to_string();
    if let Some(port) = parsed.port() {
        source.push(':');
        source.push_str(&port.to_string());
    }
    let path = parsed.path().trim_matches('/');
    if !path.is_empty() {
        source.push('/');
        source.push_str(path);
    }
    Some(apt_lists_suite_key(&source))
}

fn repository_source_matches(repo_uri: &str, package_source_key: &str) -> bool {
    package_source_key.is_empty()
        || apt_lists_source_key(repo_uri).as_deref() == Some(package_source_key)
}

/// Resolve one action's `version`/`size`/`sha256`/`url`.
///
/// Repository selection requires the package's recorded suite, preferring an
/// exact suite+component match and allowing suite-only fallback for flat or
/// componentless entries. Component-only matching is unsafe because distinct
/// suites may use different mirror roots.
fn populate_action_url(
    action: &mut debian_db::PackageAction,
    package_map: &std::collections::HashMap<String, debian_db::DebianPackage>,
    repos: &[debian_db::Repository],
) -> Result<()> {
    let Some(pkg) = package_map.get(&action.name) else {
        anyhow::bail!("package {} not found in database", action.name);
    };
    if pkg.sha256.is_empty() {
        anyhow::bail!(
            "package {} has no SHA256 in repository metadata; refusing unverified install",
            action.name
        );
    }
    if pkg.filename.is_empty() {
        anyhow::bail!(
            "package {} has no Filename in repository metadata",
            action.name
        );
    }
    anyhow::ensure!(
        action.version.is_empty() || action.version == pkg.version,
        "resolved version {} for package {} does not match download candidate {}",
        action.version,
        action.name,
        pkg.version
    );

    let repo = repos
        .iter()
        .find(|repo| {
            repository_source_matches(&repo.uri, &pkg.source_key)
                && repository_suite_matches(&repo.suite, &pkg.suite)
                && repo
                    .components
                    .iter()
                    .any(|component| component == &pkg.component)
        })
        .or_else(|| {
            repos.iter().find(|repo| {
                repository_source_matches(&repo.uri, &pkg.source_key)
                    && repository_suite_matches(&repo.suite, &pkg.suite)
            })
        });
    let Some(repo) = repo else {
        anyhow::bail!(
            "no enabled repository provides suite {:?} / component {:?} for package {}",
            pkg.suite,
            pkg.component,
            action.name
        );
    };

    // Upgrades already carry their target version; installs get the index's.
    if action.version.is_empty() {
        action.version.clone_from(&pkg.version);
    }
    action.size = pkg.size;
    action.sha256 = Some(pkg.sha256.clone());
    // filename is relative to the repo root:
    // "pool/main/v/vim/vim_9.0.1234-1_amd64.deb"
    if pkg
        .filename
        .split('/')
        .any(|part| part == ".." || part.is_empty())
    {
        anyhow::bail!("Refusing package filename with traversal: {}", pkg.filename);
    }
    action.url = Some(format!(
        "{}/{}",
        repo.uri.trim_end_matches('/'),
        pkg.filename
    ));
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::{populate_action_url, update_apt_lists, validate_pure_mutation_with_privileges};
    use crate::package_managers::debian_db::{DebianPackage, PackageAction, RepoType, Repository};
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn fake_apt_script(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempfile::tempdir().expect("temporary fake apt directory");
        let program = directory.path().join("apt-get");
        std::fs::write(&program, format!("#!/bin/sh\n{body}\n")).expect("write fake apt-get");
        let mut permissions = std::fs::metadata(&program)
            .expect("fake apt metadata")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&program, permissions).expect("make fake apt executable");
        (directory, program)
    }

    #[test]
    fn pure_mutations_validate_inputs_and_privileges_before_work() {
        let package = vec!["demo".to_string()];
        validate_pure_mutation_with_privileges(&package, true).expect("valid privileged request");

        let error = validate_pure_mutation_with_privileges(&package, false)
            .expect_err("unprivileged mutation must fail");
        assert!(error.to_string().contains("root privileges"), "{error:#}");

        let invalid = vec!["../demo".to_string()];
        let error = validate_pure_mutation_with_privileges(&invalid, true)
            .expect_err("invalid package name must fail");
        assert!(error.to_string().contains("cannot start"), "{error:#}");

        let empty = validate_pure_mutation_with_privileges(&[], true)
            .expect_err("empty package request must fail");
        assert!(empty.to_string().contains("No packages"), "{empty:#}");
    }

    #[test]
    fn package_url_does_not_cross_repository_suites_by_component() {
        let package = DebianPackage {
            name: "example".to_string(),
            version: "1.0".to_string(),
            description: String::new(),
            section: "utils".to_string(),
            priority: "optional".to_string(),
            installed_size: 1,
            maintainer: String::new(),
            architecture: "amd64".to_string(),
            depends: Vec::new(),
            filename: "pool/main/e/example/example_1.0_amd64.deb".to_string(),
            size: 1,
            sha256: "a".repeat(64),
            homepage: String::new(),
            component: "main".to_string(),
            suite: "bookworm-security".to_string(),
            source_key: "security.example_debian".to_string(),
        };
        let packages = HashMap::from([(package.name.clone(), package)]);
        let repos = vec![Repository {
            repo_type: RepoType::Binary,
            uri: "https://deb.example/debian".to_string(),
            suite: "bookworm".to_string(),
            components: vec!["main".to_string()],
            arch: None,
            signed_by: None,
            enabled: true,
            source_file: PathBuf::from("sources.list"),
            options: HashMap::new(),
        }];
        let mut action = PackageAction {
            name: "example".to_string(),
            version: String::new(),
            deb_path: None,
            url: None,
            size: 0,
            sha256: None,
        };

        let error = populate_action_url(&mut action, &packages, &repos)
            .expect_err("a component match from another suite must not select its mirror root");
        assert!(error.to_string().contains("bookworm-security"), "{error}");
        assert!(action.url.is_none());
    }

    #[test]
    fn package_url_uses_the_repository_that_published_the_index() {
        let package = DebianPackage {
            name: "example".to_string(),
            version: "1.0".to_string(),
            description: String::new(),
            section: "utils".to_string(),
            priority: "optional".to_string(),
            installed_size: 1,
            maintainer: String::new(),
            architecture: "amd64".to_string(),
            depends: Vec::new(),
            filename: "pool/example_1.0_amd64.deb".to_string(),
            size: 1,
            sha256: "a".repeat(64),
            homepage: String::new(),
            component: "main".to_string(),
            suite: "stable".to_string(),
            source_key: "trusted.example_debian".to_string(),
        };
        let packages = HashMap::from([(package.name.clone(), package)]);
        let repository = |uri: &str| Repository {
            repo_type: RepoType::Binary,
            uri: uri.to_string(),
            suite: "stable".to_string(),
            components: vec!["main".to_string()],
            arch: None,
            signed_by: None,
            enabled: true,
            source_file: PathBuf::from("sources.list"),
            options: HashMap::new(),
        };
        let repos = vec![
            repository("https://other.example/debian"),
            repository("https://trusted.example/debian"),
        ];
        let mut action = PackageAction {
            name: "example".to_string(),
            version: String::new(),
            deb_path: None,
            url: None,
            size: 0,
            sha256: None,
        };

        populate_action_url(&mut action, &packages, &repos)
            .expect("publishing repository must be selected");
        assert_eq!(
            action.url.as_deref(),
            Some("https://trusted.example/debian/pool/example_1.0_amd64.deb")
        );
    }

    #[test]
    fn package_url_matches_path_like_suites_encoded_by_apt() {
        let package = DebianPackage {
            name: "example".to_string(),
            version: "1.0".to_string(),
            description: String::new(),
            section: "utils".to_string(),
            priority: "optional".to_string(),
            installed_size: 1,
            maintainer: String::new(),
            architecture: "amd64".to_string(),
            depends: Vec::new(),
            filename: "pool/example_1.0_amd64.deb".to_string(),
            size: 1,
            sha256: "a".repeat(64),
            homepage: String::new(),
            component: "main".to_string(),
            suite: "stable_updates".to_string(),
            source_key: "deb.example_debian".to_string(),
        };
        let packages = HashMap::from([(package.name.clone(), package)]);
        let repos = vec![Repository {
            repo_type: RepoType::Binary,
            uri: "https://deb.example/debian".to_string(),
            suite: "stable/updates".to_string(),
            components: vec!["main".to_string()],
            arch: None,
            signed_by: None,
            enabled: true,
            source_file: PathBuf::from("sources.list"),
            options: HashMap::new(),
        }];
        let mut action = PackageAction {
            name: "example".to_string(),
            version: String::new(),
            deb_path: None,
            url: None,
            size: 0,
            sha256: None,
        };

        populate_action_url(&mut action, &packages, &repos)
            .expect("apt-encoded suite must match its source entry");
        assert_eq!(
            action.url.as_deref(),
            Some("https://deb.example/debian/pool/example_1.0_amd64.deb")
        );
    }

    #[test]
    fn package_url_rejects_a_candidate_version_mismatch() {
        let package = DebianPackage {
            name: "example".to_string(),
            version: "2.0".to_string(),
            description: String::new(),
            section: "utils".to_string(),
            priority: "optional".to_string(),
            installed_size: 1,
            maintainer: String::new(),
            architecture: "amd64".to_string(),
            depends: Vec::new(),
            filename: "pool/example_2.0_amd64.deb".to_string(),
            size: 1,
            sha256: "a".repeat(64),
            homepage: String::new(),
            component: "main".to_string(),
            suite: "stable".to_string(),
            source_key: "deb.example_debian".to_string(),
        };
        let packages = HashMap::from([(package.name.clone(), package)]);
        let repos = vec![Repository {
            repo_type: RepoType::Binary,
            uri: "https://deb.example/debian".to_string(),
            suite: "stable".to_string(),
            components: vec!["main".to_string()],
            arch: None,
            signed_by: None,
            enabled: true,
            source_file: PathBuf::from("sources.list"),
            options: HashMap::new(),
        }];
        let mut action = PackageAction {
            name: "example".to_string(),
            version: "1.0".to_string(),
            deb_path: None,
            url: None,
            size: 0,
            sha256: None,
        };

        let error = populate_action_url(&mut action, &packages, &repos)
            .expect_err("download metadata must match the resolved version");
        assert!(error.to_string().contains("resolved version"), "{error:#}");
        assert!(action.url.is_none());
    }

    #[tokio::test]
    async fn native_sync_executes_exact_apt_update_command() {
        let (_directory, program) = fake_apt_script("[ \"$#\" -eq 1 ] && [ \"$1\" = update ]");

        update_apt_lists(&program, false)
            .await
            .expect("apt update command must succeed");
    }

    #[tokio::test]
    async fn native_sync_propagates_apt_failure() {
        let (_directory, program) = fake_apt_script("exit 23");

        let error = update_apt_lists(&program, false)
            .await
            .expect_err("apt failure must fail sync");
        let chain = format!("{error:#}");
        assert!(
            chain.contains("exit status: 23"),
            "unexpected apt failure: {chain}"
        );
    }
}
