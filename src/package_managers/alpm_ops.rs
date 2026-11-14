//! Direct libalpm operations.
//!
//! Rust metadata queries with native signature validation and transactions.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use anyhow::{Context, Result};
use regex::Regex;

use crate::cli::progress::{Accent, Outcome, ProgressTask, TaskKind, TaskSpec};
use crate::core::paths;

/// Regex for parsing mirror server lines from /etc/pacman.d/mirrorlist
/// Compiled once at first use, then reused for all subsequent calls.
static MIRRORLIST_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^Server\s*=\s*([^#]+)").expect("valid regex pattern"));
/// Stable cross-layer marker for a requested package absent from every sync repository.
pub const MISSING_FROM_REPOS_MARKER: &str = "not found in any configured repository";
const PARALLEL_DOWNLOADS: u32 = 5;
use crate::package_managers::types::{PackageInfo, UpdateInfo, contains_ignore_case};

/// Get comprehensive system status (counts + updates) in a single pass - FAST
pub fn get_system_status() -> Result<(usize, usize, usize, usize)> {
    let (total, explicit, orphans) = crate::package_managers::get_counts()?;
    let updates = crate::package_managers::check_updates_cached()?.len();
    Ok((total, explicit, orphans, updates))
}

/// Get detailed list of updates - FAST
/// Open a libalpm handle against the configured pacman root/db with a
/// canonical error context (audit typ01 C1: seven divergent inline copies).
#[cfg(feature = "arch")]
#[derive(Debug)]
pub(crate) struct LocalPackageMetadata {
    pub(crate) name: String,
    pub(crate) version: crate::package_managers::types::Version,
    pub(crate) installed_size: u64,
    pub(crate) license: Option<String>,
}

#[cfg(feature = "arch")]
pub(crate) fn load_local_package_metadata(path: &str) -> Result<LocalPackageMetadata> {
    let snapshot =
        crate::core::security::artifact::ArchiveSnapshot::capture(std::path::Path::new(path))?;
    let pinned = snapshot.path();
    let canonical = pinned
        .to_str()
        .context("Local package path contains invalid UTF-8")?;
    let alpm = open_default_alpm()?;
    let package = alpm
        .pkg_load(canonical, false, alpm::SigLevel::NONE)
        .with_context(|| format!("Failed to read local package metadata from {path}"))?;
    let licenses: Vec<String> = package
        .licenses()
        .iter()
        .map(std::string::ToString::to_string)
        .collect();

    Ok(LocalPackageMetadata {
        name: package.name().to_string(),
        // Package-file metadata is an untrusted boundary: a version that
        // fails the strict parser must fail the load with a typed error
        // instead of comparing as a fabricated 0 (ARCH-R14).
        version: crate::package_managers::parse_version(package.version().as_str()).with_context(
            || {
                format!(
                    "Package file '{}' has an unparseable version '{}'",
                    path,
                    package.version()
                )
            },
        )?,
        installed_size: u64::try_from(package.isize()).unwrap_or(0),
        license: crate::core::security::policy::combined_license_expression(
            licenses.iter().map(String::as_str),
        ),
    })
}

#[cfg(feature = "arch")]
pub fn open_default_alpm() -> anyhow::Result<alpm::Alpm> {
    let root = crate::core::paths::pacman_root_result()?;
    let db_path = crate::core::paths::pacman_db_dir_result()?;
    open_alpm_at(&root, &db_path)
}

#[cfg(feature = "arch")]
pub(crate) fn open_alpm_at(
    root: &std::path::Path,
    db_path: &std::path::Path,
) -> anyhow::Result<alpm::Alpm> {
    let root = root
        .to_str()
        .context("ALPM root path must be valid UTF-8")?;
    let db_path = db_path
        .to_str()
        .context("ALPM database path must be valid UTF-8")?;
    anyhow::ensure!(!root.contains('\0'), "ALPM root path contains a NUL byte");
    anyhow::ensure!(
        !db_path.contains('\0'),
        "ALPM database path contains a NUL byte"
    );
    alpm::Alpm::new(root, db_path).context("Failed to initialize ALPM")
}

pub(crate) fn validate_sync_database(alpm: &alpm::Alpm, database: &alpm::Db) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = std::path::Path::new(alpm.dbpath())
        .join("sync")
        .join(format!("{}.db", database.name()));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(&path)
        .with_context(|| {
            format!(
                "Repository '{}' is unavailable at {}; run 'omg sync'",
                database.name(),
                path.display()
            )
        })?;
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "Repository '{}' is not a regular database",
        database.name()
    );
    // libalpm loads catalogs lazily. A parse failure invalidates the database,
    // while pkgs() alone represents both failure and a valid empty catalog as [].
    let _ = database.pkgs();
    database
        .is_valid()
        .with_context(|| format!("Repository '{}' failed native validation", database.name()))
}

pub fn get_update_list() -> Result<Vec<UpdateInfo>> {
    if crate::core::paths::test_mode() {
        let updates = crate::package_managers::pacman_db::check_updates_cached()?;
        return Ok(updates
            .into_iter()
            .map(|update| UpdateInfo {
                name: update.name,
                old_version: update.old_version.to_string(),
                new_version: update.new_version.to_string(),
                repo: update.repo,
            })
            .collect());
    }

    let pacman_config = crate::core::pacman_conf::PacmanConfig::parse(paths::pacman_conf_path())
        .context("Failed to load update filters from pacman.conf")?;

    crate::package_managers::alpm_direct::with_handle_mut(|alpm| {
        configure_package_filters(alpm, &pacman_config)?;
        collect_updates(alpm)
    })
}

/// Collect available updates from an ALPM handle whose ignore filters are
/// already configured.
///
/// Single authoritative update-collection implementation: shared by the CLI
/// (`get_update_list`) and the daemon worker (`alpm_worker`) so both honor
/// installed and selected packages' `IgnorePkg`/`IgnoreGroup` policy identically.
pub(crate) fn collect_updates(alpm: &alpm::Alpm) -> Result<Vec<UpdateInfo>> {
    let localdb = alpm.localdb();
    let syncdbs = alpm.syncdbs();
    let local_pkg_count = localdb.pkgs().len();

    // Build HashMap of sync packages: name -> (package, repo_name)
    // This converts O(n×m) lookups to O(n+m) with single HashMap lookup per package
    let mut sync_map: ahash::AHashMap<&str, (&alpm::Package, &str)> =
        ahash::AHashMap::with_capacity(local_pkg_count);

    for db in syncdbs {
        if !db.usage()?.contains(alpm::Usage::UPGRADE) {
            continue;
        }
        validate_sync_database(alpm, db)?;
        let repo_name = db.name();
        for pkg in db.pkgs() {
            // First repo wins (core > extra > multilib priority)
            sync_map.entry(pkg.name()).or_insert((pkg, repo_name));
        }
    }

    let mut updates = Vec::with_capacity(local_pkg_count / 20); // ~5% typically have updates

    for pkg in localdb.pkgs() {
        if pkg.should_ignore() {
            continue;
        }
        let name = pkg.name();
        let local_ver_str = pkg.version().as_str();

        if let Some(&(sync_pkg, repo)) = sync_map.get(name)
            && !sync_pkg.should_ignore()
            && alpm::vercmp(sync_pkg.version().as_str(), local_ver_str)
                == std::cmp::Ordering::Greater
        {
            updates.push(UpdateInfo {
                name: name.to_string(),
                old_version: local_ver_str.to_string(),
                new_version: sync_pkg.version().to_string(),
                repo: repo.to_string(),
            });
        }
    }

    Ok(updates)
}

/// Read sync package-info under the configured native repository policy.
pub fn get_sync_pkg_info(name: &str) -> Result<Option<PackageInfo>> {
    if paths::test_mode() {
        let manager = crate::package_managers::get_package_manager()?;
        let package = futures::executor::block_on(manager.info(name))?;
        if let Some(pkg) = package {
            return Ok(Some(PackageInfo {
                name: pkg.name,
                version: pkg.version,
                description: pkg.description,
                url: None,
                size: 0,
                install_size: None,
                download_size: None,
                repo: match pkg.source {
                    crate::core::PackageSource::Official => "official",
                    crate::core::PackageSource::Aur => "aur",
                }
                .to_string(),
                depends: Vec::new(),
                licenses: Vec::new(),
                installed: pkg.installed,
            }));
        }
        return Ok(None);
    }

    let epoch = super::pacman_db::SyncDbEpoch::observe()?;
    let package =
        crate::package_managers::alpm_direct::with_handle(|alpm| get_pkg_info_from_db(alpm, name))?;
    anyhow::ensure!(
        epoch == super::pacman_db::SyncDbEpoch::observe()?,
        "Package databases or configuration changed while querying; retry the operation"
    );
    Ok(package)
}

/// Read Rust metadata within a caller-supplied native handle's repository scope.
pub fn get_pkg_info_from_db(alpm: &alpm::Alpm, name: &str) -> Result<Option<PackageInfo>> {
    let sync_dir = std::path::Path::new(alpm.dbpath()).join("sync");
    let epoch = super::pacman_db::SyncDbEpoch::from_sync_dir(&sync_dir)?;
    // A fresh verifier binds current source reads to current signature checks,
    // rather than trusting package/validation caches in the caller's handle.
    let mut verifier = alpm::Alpm::new(alpm.root(), alpm.dbpath())
        .context("Failed to initialize scoped repository signature verification")?;
    verifier.set_default_siglevel(alpm.default_siglevel())?;
    if let Some(gpgdir) = alpm.gpgdir() {
        verifier.set_gpgdir(gpgdir)?;
    }
    let mut selected = None;
    for db in alpm.syncdbs() {
        if !db.usage()?.contains(alpm::Usage::SEARCH) {
            continue;
        }
        let verified = verifier.register_syncdb(db.name(), db.siglevel())?;
        validate_sync_database(&verifier, verified)?;
        let path = sync_dir.join(format!("{}.db", db.name()));
        if let Some(pkg) = super::pacman_db::parse_sync_db(&path, db.name())?.remove(name) {
            let installed = super::pacman_db::read_local_package_at(
                &std::path::Path::new(alpm.dbpath()).join("local"),
                &pkg.name,
            )?
            .is_some();
            let install_size = i64::try_from(pkg.isize)
                .context("Repository package size exceeds the supported range")?;
            selected = Some(PackageInfo {
                name: pkg.name,
                version: pkg.version,
                description: pkg.desc,
                url: (!pkg.url.is_empty()).then_some(pkg.url),
                size: pkg.isize,
                install_size: Some(install_size),
                download_size: Some(pkg.csize),
                repo: pkg.repo,
                depends: pkg.depends,
                licenses: pkg.licenses,
                installed,
            });
            break;
        }
    }
    anyhow::ensure!(
        epoch == super::pacman_db::SyncDbEpoch::from_sync_dir(&sync_dir)?,
        "Repository sources changed while querying; retry the operation"
    );
    Ok(selected)
}

/// Extract the package name, full version, and architecture from a cache filename.
///
/// Cache files are named `{pkgname}-{version}-{release}-{arch}.pkg.tar.{zst,xz,gz,bz2}`.
/// Neither `version` nor `release` may contain a dash (Arch packaging rules),
/// so exactly the last three dash-separated components are stripped; any
/// dashes inside the package name survive. Returns `None` for files without
/// the expected shape.
fn package_cache_info(filename: &str) -> Option<(&str, &str, &str)> {
    let stem = filename
        .strip_suffix(".pkg.tar.zst")
        .or_else(|| filename.strip_suffix(".pkg.tar.xz"))
        .or_else(|| filename.strip_suffix(".pkg.tar.gz"))
        .or_else(|| filename.strip_suffix(".pkg.tar.bz2"))?;
    // Strip exactly the trailing -arch, -release, -version components;
    // everything to the left (including any dashes in the pkgbase) stays.
    let (rest, architecture) = stem.rsplit_once('-')?;
    let (rest, release) = rest.rsplit_once('-')?;
    let (name, version) = rest.rsplit_once('-')?;
    if name.is_empty() || version.is_empty() || release.is_empty() || architecture.is_empty() {
        return None;
    }
    let full_version_start = name.len() + 1;
    let full_version_end = full_version_start + version.len() + 1 + release.len();
    let full_version = &stem[full_version_start..full_version_end];
    Some((name, full_version, architecture))
}

#[cfg(test)]
fn package_base_name(filename: &str) -> Option<&str> {
    package_cache_info(filename).map(|(name, _, _)| name)
}

/// Preview package cache cleaning without mutating the filesystem
pub fn clean_cache_preview(keep_versions: usize) -> Result<(usize, u64)> {
    clean_cache_internal(keep_versions, true)
}

/// Clean package cache using direct file system operations - FAST
///
/// Retains distinct ALPM versions per cache directory and architecture,
/// including every archive and signature belonging to a retained version.
pub fn clean_cache(keep_versions: usize) -> Result<(usize, u64)> {
    clean_cache_internal(keep_versions, false)
}

#[derive(Hash, PartialEq, Eq)]
struct CacheArchiveGroup {
    directory: std::path::PathBuf,
    name: String,
    architecture: String,
}

fn clean_cache_internal(keep_versions: usize, dry_run: bool) -> Result<(usize, u64)> {
    let mut packages: ahash::AHashMap<CacheArchiveGroup, Vec<(std::path::PathBuf, String)>> =
        ahash::AHashMap::new();
    let mut cache_dirs = std::collections::HashSet::new();

    for cache_dir in paths::pacman_cache_dirs_result()? {
        let cache_dir = match std::fs::canonicalize(&cache_dir) {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("Failed to resolve pacman cache at {}", cache_dir.display())
                });
            }
        };
        if !cache_dirs.insert(cache_dir.clone()) {
            continue;
        }
        for entry in std::fs::read_dir(&cache_dir)
            .with_context(|| format!("Failed to read pacman cache at {}", cache_dir.display()))?
        {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let path = entry.path();

            let Some(filename) = path
                .file_name()
                .and_then(|name| name.to_str())
                .map(ToString::to_string)
            else {
                continue;
            };

            if let Some((base, ver, architecture)) = package_cache_info(&filename) {
                packages
                    .entry(CacheArchiveGroup {
                        directory: cache_dir.clone(),
                        name: base.to_owned(),
                        architecture: architecture.to_owned(),
                    })
                    .or_default()
                    .push((path, ver.to_string()));
            }
        }
    }

    let mut removed = 0;
    let mut freed = 0u64;

    for (_, mut versions) in packages {
        versions.sort_by(|(_, a), (_, b)| alpm::vercmp(b.as_str(), a.as_str()));
        let mut distinct_versions = 0;
        let mut previous: Option<String> = None;
        for (old, version) in versions {
            if previous.as_ref().is_none_or(|previous| {
                alpm::vercmp(previous.as_str(), version.as_str()) != std::cmp::Ordering::Equal
            }) {
                distinct_versions += 1;
            }
            previous = Some(version);
            if distinct_versions <= keep_versions {
                continue;
            }
            if dry_run {
                removed += 1;
                let archive_len = std::fs::metadata(&old).map_or(0, |metadata| metadata.len());
                freed = freed.saturating_add(archive_len);
                let signature = old.with_added_extension("sig");
                let signature_len =
                    std::fs::metadata(signature).map_or(0, |metadata| metadata.len());
                freed = freed.saturating_add(signature_len);
            } else {
                // Only credit bytes that were actually freed; failures are
                // logged with their cause so callers are not told space was
                // reclaimed when it was not.
                freed += remove_cache_file_and_signature(&old, &mut removed);
            }
        }
    }

    Ok((removed, freed))
}

/// Remove one cache archive plus its `.sig` companion, returning the bytes
/// actually freed. The detached signature is optional: its absence is normal
/// for unsigned custom packages and is not an error.
fn remove_cache_file_and_signature(archive: &std::path::Path, removed: &mut usize) -> u64 {
    let mut freed = 0u64;

    let archive_len = std::fs::metadata(archive)
        .map(|metadata| metadata.len())
        .ok();
    match std::fs::remove_file(archive) {
        Ok(()) => {
            *removed += 1;
            freed = freed.saturating_add(archive_len.unwrap_or(0));
        }
        Err(error) => {
            tracing::warn!("Failed to remove cache file {}: {error}", archive.display());
            return freed;
        }
    }

    let signature = archive.with_added_extension("sig");
    let sig_len = std::fs::metadata(&signature)
        .map(|metadata| metadata.len())
        .ok();
    match std::fs::remove_file(&signature) {
        Ok(()) => {
            *removed += 1;
            freed = freed.saturating_add(sig_len.unwrap_or(0));
        }
        Err(error) if signature.exists() => {
            tracing::warn!(
                "Failed to remove cache signature {}: {error}",
                signature.display()
            );
        }
        Err(_) => {}
    }

    freed
}

/// List orphaned packages - INSTANT
pub use crate::package_managers::alpm_direct::list_orphans_fast as list_orphans_direct;

/// Display package info through the shared key-value renderer.
///
/// The sync-DB path matches the daemon path field for field. Package
/// metadata can carry terminal escape sequences, so every displayed field
/// is sanitized the same way search results are.
pub fn display_pkg_info(info: &PackageInfo) {
    use crate::cli::{style, ui};
    let version = info.version.to_string();
    let source = format!(
        "Official repository ({})",
        style::sanitize_terminal_text(&info.repo)
    );
    ui::print_package_info(
        &ui::InfoCore {
            name: &info.name,
            version: &version,
            source: &source,
            installed: info.installed,
            description: &info.description,
        },
        &ui::InfoExtras {
            url: info.url.as_deref().filter(|url| !url.is_empty()),
            size: Some(info.size),
            download: info.download_size,
            licenses: &info.licenses,
            depends: &info.depends,
            maintainer: None,
            votes: None,
            popularity: None,
            out_of_date: false,
        },
    );
}

type PreparedArchiveInspections = std::collections::BTreeMap<
    std::path::PathBuf,
    crate::package_managers::aur::artifact_inspector::ArtifactInspection,
>;

/// RAII Guard for ALPM transactions to ensure release
#[must_use]
struct AlpmTransaction<'a>(
    &'a mut alpm::Alpm,
    PreparedArchiveInspections,
    Option<AdmissionSignals>,
);

impl Drop for AlpmTransaction<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.0.trans_release() {
            tracing::warn!("Failed to release ALPM transaction: {e}");
        }
    }
}

/// Requested ALPM transaction behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionKind {
    Install,
    /// Install archives produced by OMG's AUR build pipeline. AUR artifacts
    /// are normally unsigned, so verify a detached signature when present but
    /// do not require one, matching pacman's default local-file policy.
    InstallAurArtifact,
    Remove {
        recursive: bool,
    },
    SystemUpgrade,
}

/// Execute a libalpm transaction.
///
/// A supplied handle must already have its sync databases registered. Passing
/// [`None`] opens a fresh handle and registers the configured repositories.
pub fn execute_transaction(
    packages: Vec<String>,
    kind: TransactionKind,
    handle: Option<&mut alpm::Alpm>,
) -> Result<()> {
    execute_transaction_with_intents(packages, kind, handle, None, &[])
}

#[derive(Clone, Copy, Default)]
enum TransactionPolicy {
    #[default]
    Standard,
    Omarchy,
}

pub(crate) fn execute_omarchy_transaction(
    operation: super::arch::NativeOmarchyOperation,
    packages: Vec<String>,
) -> Result<()> {
    use super::arch::NativeOmarchyOperation;
    let kind = match operation {
        NativeOmarchyOperation::RefreshKeyrings => TransactionKind::Install,
        NativeOmarchyOperation::UpgradeRepositories => TransactionKind::SystemUpgrade,
        NativeOmarchyOperation::RemoveOrphans => TransactionKind::Remove { recursive: true },
        NativeOmarchyOperation::PruneCache => anyhow::bail!("Cache pruning is not a transaction"),
    };
    execute_transaction_in(packages, kind, None, None, &[], TransactionPolicy::Omarchy)
}

pub(crate) fn execute_install_request(request: &super::arch_install::InstallRequest) -> Result<()> {
    let kind = request.kind();
    let packages = request
        .items()
        .iter()
        .map(|item| item.target.argument())
        .collect();
    let intents = request
        .items()
        .iter()
        .map(|item| item.intent)
        .collect::<Vec<_>>();
    let selections = request
        .items()
        .iter()
        .filter_map(|item| {
            if let super::arch_install::InstallTarget::Resolved(target) = &item.target {
                Some(target.clone())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    execute_transaction_with_intents(packages, kind, None, Some(&intents), &selections)
}

fn execute_transaction_with_intents(
    packages: Vec<String>,
    kind: TransactionKind,
    handle: Option<&mut alpm::Alpm>,
    intents: Option<&[super::arch_install::InstallIntent]>,
    selections: &[super::arch_install::OfficialTarget],
) -> Result<()> {
    execute_transaction_in(
        packages,
        kind,
        handle,
        intents,
        selections,
        TransactionPolicy::Standard,
    )
}

fn execute_transaction_in(
    packages: Vec<String>,
    kind: TransactionKind,
    handle: Option<&mut alpm::Alpm>,
    intents: Option<&[super::arch_install::InstallIntent]>,
    selections: &[super::arch_install::OfficialTarget],
    policy: TransactionPolicy,
) -> Result<()> {
    validate_aur_artifact_handoffs(kind, &packages)?;
    let initial_policy = crate::core::security::SecurityPolicy::load_current()?;
    let staged = if matches!(
        kind,
        TransactionKind::Install | TransactionKind::InstallAurArtifact
    ) {
        Some(crate::core::security::artifact::StagedInputs::prepare(
            &packages,
        )?)
    } else {
        None
    };
    let packages = staged
        .as_ref()
        .map_or(packages, |inputs| inputs.targets.clone());
    let pacman_config = crate::core::pacman_conf::PacmanConfig::parse(paths::pacman_conf_path())
        .context("Failed to load transaction options from pacman.conf")?;

    let mut owned;
    let alpm = if let Some(alpm) = handle {
        configure_transaction_options(alpm, &pacman_config)?;
        alpm
    } else {
        owned = open_default_alpm()?;
        configure_transaction_options(&mut owned, &pacman_config)?;
        anyhow::ensure!(
            !pacman_config.repos.is_empty(),
            "pacman configuration contains no repositories"
        );
        register_configured_syncdbs(&owned, &pacman_config)?;
        &mut owned
    };

    configure_mirrors(alpm)?;
    if matches!(policy, TransactionPolicy::Omarchy) && kind == TransactionKind::Install {
        for name in &packages {
            let mut trusted_repository = None;
            for database in alpm.syncdbs() {
                if !database.usage()?.contains(alpm::Usage::INSTALL) {
                    continue;
                }
                validate_sync_database(alpm, database)?;
                if database.pkg(name.as_str()).is_ok() {
                    trusted_repository = Some(database.siglevel());
                    break;
                }
            }
            let level = trusted_repository.context("Signing-key package is unavailable")?;
            anyhow::ensure!(
                level.contains(alpm::SigLevel::PACKAGE)
                    && !level.intersects(
                        alpm::SigLevel::PACKAGE_OPTIONAL
                            | alpm::SigLevel::PACKAGE_UNKNOWN_OK
                            | alpm::SigLevel::PACKAGE_MARGINAL_OK
                    ),
                "Native signing-key refresh requires mandatory trusted package signatures; trust bootstrap is unavailable"
            );
        }
    }
    if matches!(policy, TransactionPolicy::Omarchy) && kind == TransactionKind::SystemUpgrade {
        alpm.add_overwrite_file("usr/share/omarchy/*")
            .context("Cannot configure the Omarchy-owned overwrite scope")?;
    }

    let refusals = Arc::new(Mutex::new(AlpmQuestionRefusals::default()));
    let main_task = setup_alpm_callbacks_in(alpm, &refusals, policy);
    let mut tx_guard =
        prepare_alpm_transaction_in(alpm, packages.clone(), kind, &pacman_config, policy)
            .map_err(|error| question_refusal_error(&refusals).unwrap_or(error))?;
    let reasons = installation_reasons(tx_guard.0, &packages, intents)?;
    // Declined replacement questions make libalpm skip the replacement
    // silently, so a successful prepare can still hide a refused mutation.
    if let Some(error) = question_refusal_error(&refusals) {
        return Err(error);
    }
    commit_alpm_transaction(
        tx_guard.0,
        &main_task,
        kind,
        &pacman_config.hold_pkg,
        &reasons,
        selections,
        &packages,
        &initial_policy,
        &tx_guard.1,
        &mut tx_guard.2,
    )
    .map_err(|error| question_refusal_error(&refusals).unwrap_or(error))?;

    Ok(())
}

fn installation_reasons(
    alpm: &alpm::Alpm,
    packages: &[String],
    intents: Option<&[super::arch_install::InstallIntent]>,
) -> Result<Vec<(String, alpm::PackageReason)>> {
    use super::arch_install::InstallIntent;
    let Some(intents) = intents else {
        return Ok(Vec::new());
    };
    anyhow::ensure!(
        packages.len() == intents.len(),
        "Installation intent count mismatch"
    );
    let mut reasons = Vec::with_capacity(packages.len());
    let mut names = std::collections::HashSet::with_capacity(packages.len());
    for (target, intent) in packages.iter().zip(intents) {
        let name = if crate::core::security::is_local_package_file(target) {
            alpm.pkg_load(target.as_str(), false, alpm::SigLevel::NONE)?
                .name()
                .to_owned()
        } else {
            target
                .rsplit('/')
                .next()
                .context("Missing installation target name")?
                .to_owned()
        };
        anyhow::ensure!(
            names.insert(name.clone()),
            "Multiple installation targets resolve to '{name}'"
        );
        let previous = alpm
            .localdb()
            .pkg(name.as_str())
            .ok()
            .map(|package| package.reason());
        let reason = match (intent, previous) {
            (InstallIntent::Requested, _) | (_, Some(alpm::PackageReason::Explicit)) => {
                alpm::PackageReason::Explicit
            }
            (InstallIntent::Automatic, _) => alpm::PackageReason::Depend,
        };
        reasons.push((name, reason));
    }
    Ok(reasons)
}

fn persist_installation_reasons(
    alpm: &alpm::Alpm,
    reasons: &[(String, alpm::PackageReason)],
) -> Result<()> {
    for (name, reason) in reasons {
        let package = alpm.localdb().pkg(name.as_str()).with_context(|| {
            format!("Transaction completed, but installed package '{name}' could not be found while preserving installation intent; inspect installed state before retrying")
        })?;
        if package.reason() != *reason {
            package.set_reason(*reason).with_context(|| {
                format!("Transaction completed, but installation reason for '{name}' could not be persisted; inspect installed state before retrying")
            })?;
        }
    }
    Ok(())
}

fn validate_prepared_selections(
    alpm: &alpm::Alpm,
    selections: &[super::arch_install::OfficialTarget],
) -> Result<()> {
    for selection in selections {
        let database = alpm
            .syncdbs()
            .into_iter()
            .find(|database| database.name() == selection.repository)
            .with_context(|| {
                format!(
                    "Selected repository '{}' is no longer configured",
                    selection.repository
                )
            })?;
        anyhow::ensure!(
            database.usage()?.contains(alpm::Usage::INSTALL),
            "Selected repository '{}' no longer allows dependency installation",
            selection.repository
        );
        validate_sync_database(alpm, database)?;
        let selected = database.pkg(selection.name.as_str()).with_context(|| {
            format!(
                "Selected package '{}/{}' is no longer available",
                selection.repository, selection.name
            )
        })?;
        let prepared = alpm
            .trans_add()
            .into_iter()
            .find(|package| package.name() == selection.name);
        let candidate = if let Some(package) = prepared {
            anyhow::ensure!(
                package
                    .db()
                    .is_some_and(|database| database.name() == selection.repository),
                "Prepared package '{}' differs from its selected repository",
                selection.name
            );
            package
        } else {
            alpm.localdb()
                .pkg(selection.name.as_str())
                .context("Selected dependency was neither prepared nor already installed")?
        };
        for package in [selected, candidate] {
            for relation in &selection.relations {
                let dependency = alpm::Depend::new(relation.as_str());
                let direct = package.name() == dependency.name()
                    && super::types::dependency_version_satisfies(
                        relation,
                        package.version().as_str(),
                    );
                let provided = package.provides().into_iter().any(|provided| {
                    super::types::provision_satisfies(relation, &provided.to_string())
                });
                anyhow::ensure!(
                    direct || provided,
                    "Selected dependency '{}/{}' no longer satisfies '{relation}'; resolve dependencies again",
                    selection.repository,
                    selection.name
                );
            }
        }
    }
    Ok(())
}

fn validate_aur_artifact_handoffs(kind: TransactionKind, packages: &[String]) -> Result<()> {
    if kind == TransactionKind::InstallAurArtifact {
        // Linux sealing prevents mutation after review and closes the privileged
        // check/use race: https://man7.org/linux/man-pages/man2/memfd_create.2.html
        anyhow::ensure!(
            packages
                .iter()
                .all(|package| crate::core::security::artifact::is_handoff(package)),
            "AUR artifacts must arrive through an immutable sealed handoff"
        );
    }
    Ok(())
}

pub(crate) fn register_configured_syncdbs(
    alpm: &alpm::Alpm,
    pacman_config: &crate::core::pacman_conf::PacmanConfig,
) -> Result<()> {
    let policy = signature_policy(pacman_config)?;
    let require_pgp = crate::core::security::policy::SecurityPolicy::load_default()?.require_pgp;
    for repo in &pacman_config.repos {
        let siglevel = repository_siglevel(policy.default, repo.sig_level.as_deref())?;
        let siglevel = enforce_required_package_signature(siglevel, require_pgp);
        let database = alpm.register_syncdb(repo.name.as_str(), siglevel)
            .with_context(|| {
                format!(
                    "Failed to register configured sync database '{}'; refusing a partial repository set",
                    repo.name
                )
            })?;
        database.set_usage(repo.usage.to_alpm())?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForwardedAlpmLogLevel {
    Error,
    Warning,
    Debug,
    Trace,
}

fn classify_alpm_log_level(level: alpm::LogLevel) -> ForwardedAlpmLogLevel {
    if level.contains(alpm::LogLevel::ERROR) {
        ForwardedAlpmLogLevel::Error
    } else if level.contains(alpm::LogLevel::WARNING) {
        ForwardedAlpmLogLevel::Warning
    } else if level.contains(alpm::LogLevel::DEBUG) {
        ForwardedAlpmLogLevel::Debug
    } else {
        ForwardedAlpmLogLevel::Trace
    }
}

fn forward_alpm_log(level: alpm::LogLevel, message: &str) {
    let message = crate::cli::style::sanitize_terminal_text(message.trim());
    if message.is_empty() {
        return;
    }
    match classify_alpm_log_level(level) {
        ForwardedAlpmLogLevel::Error => tracing::error!(target: "libalpm", "{message}"),
        ForwardedAlpmLogLevel::Warning => tracing::warn!(target: "libalpm", "{message}"),
        ForwardedAlpmLogLevel::Debug => tracing::debug!(target: "libalpm", "{message}"),
        ForwardedAlpmLogLevel::Trace => tracing::trace!(target: "libalpm", "{message}"),
    }
}

/// Package mutations the ALPM question callback refused because they need
/// explicit consent that the synchronous, ALPM-thread callback cannot collect
/// (the CLI's `confirm_package_mutation` consent covers the requested targets,
/// not collateral mutations of other installed packages, and there is no
/// channel to forward it into libalpm callbacks).
///
/// Replace and RemovePkgs questions are answered with pacman's fail-closed
/// default and recorded here, then the transaction is failed with an explicit
/// error naming each conflict instead of silently mutating installed packages.
#[derive(Debug, Default)]
struct AlpmQuestionRefusals {
    /// Declined replacements, as "oldpkg with newdb/newpkg" descriptions.
    replacements: Vec<String>,
    /// Declined removals: unresolvable packages libalpm offered to drop from
    /// the transaction.
    removals: Vec<String>,
    key_import_refused: bool,
}

impl AlpmQuestionRefusals {
    fn is_empty(&self) -> bool {
        self.replacements.is_empty() && self.removals.is_empty() && !self.key_import_refused
    }

    fn record_refused_replacement(&mut self, oldpkg: &str, newdb: &str, newpkg: &str) {
        self.replacements
            .push(format!("{oldpkg} with {newdb}/{newpkg}"));
    }

    fn record_refused_removals(&mut self, packages: &[String]) {
        self.removals.push(packages.join(", "));
    }

    fn record_refused_key_import(&mut self) {
        self.key_import_refused = true;
    }
}

/// Build the explicit error for declined ALPM questions, naming every
/// conflict; `None` when no question was answered conservatively.
fn question_refusal_error(refusals: &Mutex<AlpmQuestionRefusals>) -> Option<anyhow::Error> {
    let refusals = refusals
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if refusals.is_empty() {
        return None;
    }
    let mut details = Vec::new();
    for replacement in &refusals.replacements {
        details.push(format!("replace {replacement}"));
    }
    for removal in &refusals.removals {
        details.push(format!(
            "drop unresolvable package(s) from the transaction: {removal}"
        ));
    }
    if refusals.key_import_refused {
        details.push("import an untrusted signing key".to_owned());
    }
    Some(anyhow::anyhow!(
        "ALPM transaction aborted: it requires an unconfirmed package mutation or signing-key import ({}) \
         the required consent was not granted; resolve the conflict explicitly and retry",
        details.join("; ")
    ))
}

/// Pacman's provider prompt ("Enter a number (default=1)") defaults to the
/// first listed provider; keep that answer, but log exactly which provider
/// was chosen so the auto-answer is auditable.
fn provider_selection_message(providers: &[String], depend: &str) -> String {
    let count = providers.len();
    let chosen = providers.first().map_or("unknown", String::as_str);
    format!(
        "Auto-selected provider {chosen} (1 of {count}) for dependency {depend} (pacman's provider prompt default)"
    )
}

fn progress_event_is_due(last: &mut (String, i32), name: &str, percent: i32) -> bool {
    let name_changed = last.0.as_str() != name;
    if name_changed {
        last.0.clear();
        last.0.push_str(name);
        last.1 = percent;
        return true;
    }
    if percent >= last.1 + 5 || percent >= 100 || percent == 0 {
        last.1 = percent;
        true
    } else {
        false
    }
}

fn transaction_overall_percent(percent: i32, n: usize, max: usize) -> u64 {
    if max == 0 {
        return u64::try_from(percent.max(0)).unwrap_or(0).min(100);
    }
    let completed = n.saturating_sub(1);
    let increment = usize::try_from(percent.max(0)).unwrap_or(0);
    let overall = completed.saturating_mul(100).saturating_add(increment) / max;
    u64::try_from(overall.min(100)).unwrap_or(100)
}

fn download_lane_message(active: u64, done: u64) -> String {
    format!("{active} in flight · {done} done")
}

fn finish_download_lane(lane: &Mutex<Option<ProgressTask>>) {
    let mut guard = lane
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(task) = guard.take() {
        task.finish(Outcome::Done);
    }
}

const fn is_post_download_progress(op: alpm::Progress) -> bool {
    matches!(
        op,
        alpm::Progress::IntegrityStart
            | alpm::Progress::LoadStart
            | alpm::Progress::KeyringStart
            | alpm::Progress::DiskspaceStart
            | alpm::Progress::ConflictsStart
            | alpm::Progress::AddStart
            | alpm::Progress::UpgradeStart
            | alpm::Progress::DowngradeStart
            | alpm::Progress::ReinstallStart
            | alpm::Progress::RemoveStart
    )
}

/// Setup ALPM callbacks for progress lanes
#[cfg(test)]
fn setup_alpm_callbacks(
    alpm: &alpm::Alpm,
    refusals: &Arc<Mutex<AlpmQuestionRefusals>>,
) -> ProgressTask {
    setup_alpm_callbacks_in(alpm, refusals, TransactionPolicy::Standard)
}

fn setup_alpm_callbacks_in(
    alpm: &alpm::Alpm,
    refusals: &Arc<Mutex<AlpmQuestionRefusals>>,
    policy: TransactionPolicy,
) -> ProgressTask {
    let main_task = ProgressTask::start(&TaskSpec {
        label: "Transaction".to_string(),
        kind: TaskKind::Items { total: 100 },
        accent: Accent::System,
    });

    alpm.set_question_cb((Arc::clone(refusals), policy), |question, (refusals, policy)| {
        let mut refusals = refusals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match question.question() {
            alpm::Question::InstallIgnorepkg(mut q) => {
                // Pacman installs explicitly requested packages despite
                // IgnorePkg without prompting; keep that answer, logged.
                tracing::warn!(
                    "Installing {} despite IgnorePkg (auto-answered: yes)",
                    q.pkg().name()
                );
                q.set_install(true);
            }
            alpm::Question::Replace(q) => {
                let description = q.oldpkg().name();
                let newdb = q.newdb().name();
                let newpkg = q.newpkg().name();
                let auto_accept = matches!(policy, TransactionPolicy::Omarchy)
                    || crate::core::privilege::get_yes_flag();
                let confirmed = if auto_accept {
                    true
                } else if console::user_attended() && !crate::core::privilege::get_yes_flag() {
                    let _quiesce = crate::cli::modern_ui::quiesce_terminal();
                    dialoguer::Confirm::with_theme(&crate::cli::ui::prompt_theme())
                        .with_prompt(format!("Replace {description} with {newdb}/{newpkg}?"))
                        .default(true)
                        .interact()
                        .unwrap_or(false)
                } else {
                    false
                };

                if confirmed {
                    tracing::info!("Replacing {description} with {newdb}/{newpkg}");
                    q.set_replace(true);
                } else {
                    q.set_replace(false);
                    tracing::error!(
                        "Refusing to replace {description} with {newdb}/{newpkg}: replacing an \
                     installed package requires explicit consent (auto-answered: no)"
                    );
                    refusals.record_refused_replacement(description, newdb, newpkg);
                }
            }
            alpm::Question::Conflict(mut q) => {
                let conflict = q.conflict();
                let pkg1 = conflict.package1().name();
                let pkg2 = conflict.package2().name();
                let reason = conflict.reason().to_string();

                let auto_accept = matches!(policy, TransactionPolicy::Standard)
                    && crate::core::privilege::get_yes_flag();
                let confirmed = if auto_accept {
                    true
                } else if console::user_attended() && !crate::core::privilege::get_yes_flag() {
                    let _quiesce = crate::cli::modern_ui::quiesce_terminal();
                    dialoguer::Confirm::with_theme(&crate::cli::ui::prompt_theme())
                        .with_prompt(format!("{pkg1} conflicts with {pkg2} ({reason}). Remove {pkg2}?"))
                        .default(false)
                        .interact()
                        .unwrap_or(false)
                } else {
                    false
                };

                if confirmed {
                    tracing::info!("Removing conflicting package {pkg2} while installing {pkg1}");
                    q.set_remove(true);
                } else {
                    tracing::error!(
                        "Refusing implicit removal of conflicting package {pkg2} while installing {pkg1} ({reason})"
                    );
                    q.set_remove(false);
                }
            }
            alpm::Question::RemovePkgs(mut q) => {
                // Pacman prompts "Do you want to skip the above package(s) for
                // this upgrade? [y/N]"; the interactive default (no) makes libalpm
                // fail with unsatisfied dependencies instead of silently dropping
                // packages from the transaction. Keep that fail-closed answer,
                // logged and surfaced as a clear error.
                let packages: Vec<String> = q
                    .packages()
                    .iter()
                    .map(|package| package.name().to_string())
                    .collect();
                q.set_skip(false);
                tracing::error!(
                    "Refusing to drop unresolvable package(s) {} from the transaction \
                 (auto-answered: no); the transaction will fail with unsatisfied dependencies",
                    packages.join(", ")
                );
                refusals.record_refused_removals(&packages);
            }
            alpm::Question::SelectProvider(mut q) => {
                let providers: Vec<String> = q
                    .providers()
                    .iter()
                    .map(|package| package.name().to_string())
                    .collect();
                if console::user_attended()
                    && !crate::core::privilege::get_yes_flag()
                    && providers.len() > 1
                {
                    let _quiesce = crate::cli::modern_ui::quiesce_terminal();
                    if let Ok(selection) =
                        dialoguer::Select::with_theme(&crate::cli::ui::prompt_theme())
                            .with_prompt(format!("Select a provider for {}", q.depend()))
                            .items(&providers)
                            .default(0)
                            .interact()
                        && let Ok(idx) = i32::try_from(selection)
                    {
                        q.set_index(idx);
                        return;
                    }
                }
                tracing::info!(
                    "{}",
                    provider_selection_message(&providers, &q.depend().to_string())
                );
                q.set_index(0);
            }
            alpm::Question::ImportKey(mut q) => {
                q.set_import(false);
                if matches!(policy, TransactionPolicy::Standard)
                    && console::user_attended()
                    && !crate::core::privilege::get_yes_flag()
                {
                    let fingerprint = crate::cli::style::sanitize_terminal_text(q.fingerprint());
                    let _quiesce = crate::cli::modern_ui::quiesce_terminal();
                    let confirmed = dialoguer::Confirm::with_theme(&crate::cli::ui::prompt_theme())
                        .with_prompt(format!("Import PGP key {fingerprint}?"))
                        .default(false)
                        .interact()
                        .unwrap_or(false);
                    q.set_import(confirmed);
                    if !confirmed { refusals.record_refused_key_import(); }
                } else {
                    refusals.record_refused_key_import();
                    if matches!(policy, TransactionPolicy::Omarchy) {
                        tracing::error!("Native Omarchy updates require existing trusted signing keys; trust bootstrap is unavailable");
                    } else {
                        tracing::warn!("Unknown signing key refused; an attended trust decision is required");
                    }
                }
            }
            alpm::Question::Corrupted(mut q) => {
                tracing::error!("Corrupted package detected! This may indicate tampering.");
                q.set_remove(false);
            }
        }
    });

    // Progress messages are rendered below, but warnings and errors such as
    // .pacnew/.pacsave notices remain operationally significant.
    alpm.set_log_cb((), |level, message, ()| {
        forward_alpm_log(level, message);
    });

    let main_task_clone = main_task.clone();
    let progress_state = Mutex::new((String::new(), 0_i32));
    let download_lane = Arc::new(Mutex::new(None::<ProgressTask>));
    let download_counts = Arc::new((AtomicU64::new(0), AtomicU64::new(0)));
    let progress_download_lane = Arc::clone(&download_lane);
    alpm.set_progress_cb(progress_state, move |op, name, percent, n, max, state| {
        if is_post_download_progress(op) {
            finish_download_lane(&progress_download_lane);
        }
        if !progress_event_is_due(
            state
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            name,
            percent,
        ) {
            return;
        }
        let verb = match op {
            alpm::Progress::AddStart => "Installing",
            alpm::Progress::UpgradeStart => "Upgrading",
            alpm::Progress::DowngradeStart => "Downgrading",
            alpm::Progress::ReinstallStart => "Reinstalling",
            alpm::Progress::RemoveStart => "Removing",
            alpm::Progress::ConflictsStart => "Conflict check",
            alpm::Progress::DiskspaceStart => "Checking disk space",
            alpm::Progress::IntegrityStart => "Checking integrity",
            alpm::Progress::LoadStart => "Loading",
            alpm::Progress::KeyringStart => "Checking keyring",
        };
        let counts = if max > 0 {
            format!(" ({n}/{max})")
        } else {
            String::new()
        };
        let message = if crate::cli::modern_ui::is_verbose() {
            format!("{verb} {name}{counts}")
        } else {
            format!("{verb}{counts}")
        };
        main_task_clone.set_message(&message);
        main_task_clone.set_position(transaction_overall_percent(percent, n, max));
    });

    let callback_lane = Arc::clone(&download_lane);
    let callback_counts = Arc::clone(&download_counts);
    alpm.set_dl_cb(
        (callback_lane, callback_counts),
        move |_filename, event, (lane, counts)| match event.event() {
            alpm::DownloadEvent::Init(_) => {
                let active = counts.0.fetch_add(1, Ordering::Relaxed) + 1;
                let done = counts.1.load(Ordering::Relaxed);
                let mut lane = lane
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let task = lane.get_or_insert_with(|| {
                    ProgressTask::start(&TaskSpec {
                        label: "Download".to_string(),
                        kind: TaskKind::Spinner,
                        accent: Accent::Network,
                    })
                });
                task.set_message(&download_lane_message(active, done));
            }
            alpm::DownloadEvent::Progress(_) | alpm::DownloadEvent::Retry(_) => {}
            alpm::DownloadEvent::Completed(_) => {
                let active = counts
                    .0
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |active| {
                        Some(active.saturating_sub(1))
                    })
                    .unwrap_or(0)
                    .saturating_sub(1);
                let done = counts.1.fetch_add(1, Ordering::Relaxed) + 1;
                if let Some(task) = lane
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .as_ref()
                {
                    task.set_message(&download_lane_message(active, done));
                }
            }
        },
    );

    main_task
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SignaturePolicy {
    pub(crate) default: alpm::SigLevel,
    pub(crate) local_file: alpm::SigLevel,
    pub(crate) remote_file: alpm::SigLevel,
}

#[derive(Debug, Clone, Copy)]
struct ParsedSignatureLevel {
    level: alpm::SigLevel,
    mask: alpm::SigLevel,
}

#[test]
fn explicit_pgp_requirement_overrides_optional_and_disabled_package_signatures() {
    for level in [
        alpm::SigLevel::NONE,
        alpm::SigLevel::PACKAGE | alpm::SigLevel::PACKAGE_OPTIONAL,
    ] {
        let enforced = enforce_required_package_signature(level, true);
        assert!(enforced.contains(alpm::SigLevel::PACKAGE));
        assert!(!enforced.contains(alpm::SigLevel::PACKAGE_OPTIONAL));
        assert_eq!(enforce_required_package_signature(level, false), level);
    }
}

fn set_signature_flags(parsed: &mut ParsedSignatureLevel, flags: alpm::SigLevel) {
    parsed.level.insert(flags);
    parsed.mask.insert(flags);
}

fn unset_signature_flags(parsed: &mut ParsedSignatureLevel, flags: alpm::SigLevel) {
    parsed.level.remove(flags);
    parsed.mask.insert(flags);
}

fn parse_signature_level(
    value: Option<&str>,
    initial: alpm::SigLevel,
) -> Result<ParsedSignatureLevel> {
    let mut parsed = ParsedSignatureLevel {
        level: initial,
        mask: alpm::SigLevel::NONE,
    };
    let Some(value) = value else {
        return Ok(parsed);
    };

    for original in value.split_whitespace() {
        let (package, database, directive) = if let Some(value) = original.strip_prefix("Package") {
            (true, false, value)
        } else if let Some(value) = original.strip_prefix("Database") {
            (false, true, value)
        } else {
            (true, true, original)
        };

        let package_required = alpm::SigLevel::PACKAGE;
        let package_optional = alpm::SigLevel::PACKAGE_OPTIONAL;
        let package_trust =
            alpm::SigLevel::PACKAGE_MARGINAL_OK | alpm::SigLevel::PACKAGE_UNKNOWN_OK;
        let database_required = alpm::SigLevel::DATABASE;
        let database_optional = alpm::SigLevel::DATABASE_OPTIONAL;
        let database_trust =
            alpm::SigLevel::DATABASE_MARGINAL_OK | alpm::SigLevel::DATABASE_UNKNOWN_OK;

        match directive {
            "Never" => {
                if package {
                    unset_signature_flags(&mut parsed, package_required);
                }
                if database {
                    unset_signature_flags(&mut parsed, database_required);
                }
            }
            "Optional" => {
                if package {
                    set_signature_flags(&mut parsed, package_required | package_optional);
                }
                if database {
                    set_signature_flags(&mut parsed, database_required | database_optional);
                }
            }
            "Required" => {
                if package {
                    set_signature_flags(&mut parsed, package_required);
                    unset_signature_flags(&mut parsed, package_optional);
                }
                if database {
                    set_signature_flags(&mut parsed, database_required);
                    unset_signature_flags(&mut parsed, database_optional);
                }
            }
            "TrustedOnly" => {
                if package {
                    unset_signature_flags(&mut parsed, package_trust);
                }
                if database {
                    unset_signature_flags(&mut parsed, database_trust);
                }
            }
            "TrustAll" => {
                if package {
                    set_signature_flags(&mut parsed, package_trust);
                }
                if database {
                    set_signature_flags(&mut parsed, database_trust);
                }
            }
            _ => anyhow::bail!("Invalid pacman SigLevel directive '{original}'"),
        }
        parsed.level.remove(alpm::SigLevel::USE_DEFAULT);
    }
    Ok(parsed)
}

fn merge_signature_level(
    base: alpm::SigLevel,
    override_level: ParsedSignatureLevel,
) -> alpm::SigLevel {
    if override_level.mask.is_empty() {
        if override_level.level.contains(alpm::SigLevel::USE_DEFAULT) {
            base
        } else {
            override_level.level
        }
    } else {
        (override_level.level & override_level.mask) | (base & !override_level.mask)
    }
}

pub(crate) fn signature_policy(
    config: &crate::core::pacman_conf::PacmanConfig,
) -> Result<SignaturePolicy> {
    let default = parse_signature_level(
        config.sig_level.as_deref(),
        alpm::SigLevel::PACKAGE | alpm::SigLevel::DATABASE,
    )?
    .level;
    let local_file = merge_signature_level(
        default,
        parse_signature_level(
            config.local_file_sig_level.as_deref(),
            alpm::SigLevel::USE_DEFAULT,
        )?,
    );
    let remote_file = merge_signature_level(
        default,
        parse_signature_level(
            config.remote_file_sig_level.as_deref(),
            alpm::SigLevel::USE_DEFAULT,
        )?,
    );
    Ok(SignaturePolicy {
        default,
        local_file,
        remote_file,
    })
}

pub(crate) fn repository_siglevel(
    default: alpm::SigLevel,
    configured: Option<&str>,
) -> Result<alpm::SigLevel> {
    Ok(merge_signature_level(
        default,
        parse_signature_level(configured, alpm::SigLevel::USE_DEFAULT)?,
    ))
}

fn enforce_required_package_signature(mut level: alpm::SigLevel, required: bool) -> alpm::SigLevel {
    if required {
        level.insert(alpm::SigLevel::PACKAGE);
        level.remove(alpm::SigLevel::PACKAGE_OPTIONAL | alpm::SigLevel::USE_DEFAULT);
    }
    level
}

pub(crate) fn configure_signature_policy(
    alpm: &mut alpm::Alpm,
    config: &crate::core::pacman_conf::PacmanConfig,
) -> Result<SignaturePolicy> {
    let mut signatures = signature_policy(config)?;
    let require_pgp = crate::core::security::policy::SecurityPolicy::load_default()?.require_pgp;
    signatures.default = enforce_required_package_signature(signatures.default, require_pgp);
    signatures.local_file = enforce_required_package_signature(signatures.local_file, require_pgp);
    signatures.remote_file =
        enforce_required_package_signature(signatures.remote_file, require_pgp);
    alpm.set_default_siglevel(signatures.default)
        .context("Failed to configure default package signature policy")?;
    alpm.set_local_file_siglevel(signatures.local_file)
        .context("Failed to configure local package signature policy")?;
    alpm.set_remote_file_siglevel(signatures.remote_file)
        .context("Failed to configure remote package signature policy")?;
    let root = paths::pacman_root_result()?;
    let keyring = pacman_option_path(&root, config.gpg_dir.as_deref(), "etc/pacman.d/gnupg");
    let keyring = keyring
        .to_str()
        .context("Pacman keyring path contains invalid UTF-8")?;
    anyhow::ensure!(
        !keyring.as_bytes().contains(&0),
        "Pacman keyring path contains NUL"
    );
    alpm.set_gpgdir(keyring)
        .context("Failed to configure pacman keyring")?;
    Ok(signatures)
}

fn local_package_siglevel(kind: TransactionKind, configured: alpm::SigLevel) -> alpm::SigLevel {
    if kind == TransactionKind::InstallAurArtifact {
        configured & (alpm::SigLevel::PACKAGE_MARGINAL_OK | alpm::SigLevel::PACKAGE_UNKNOWN_OK)
            | alpm::SigLevel::PACKAGE
            | alpm::SigLevel::PACKAGE_OPTIONAL
    } else {
        configured
    }
}

fn validate_transaction_targets(kind: TransactionKind, packages: &[String]) -> Result<()> {
    anyhow::ensure!(
        kind != TransactionKind::SystemUpgrade || packages.is_empty(),
        "System upgrade transactions do not accept explicit package targets"
    );
    Ok(())
}

fn transaction_flags(kind: TransactionKind) -> alpm::TransFlag {
    let mut flags = alpm::TransFlag::NEEDED;
    if matches!(kind, TransactionKind::Remove { recursive: true }) {
        // Match `pacman -Rs`: recurse into dependencies that become unneeded,
        // but do not set `UNNEEDED` (`pacman -Ru`), which would silently drop
        // still-required explicit targets from the transaction.
        flags |= alpm::TransFlag::RECURSE;
    }
    flags
}

/// Diagnose an unheld database lock without changing native lock ownership.
///
/// A process-holder scan is only a snapshot. Unlinking the pathname afterward
/// could remove a lock newly acquired by another package manager. Existing live
/// locks remain subject to libalpm's atomic transaction-init refusal.
pub(crate) fn check_database_lock(database_root: &std::path::Path) -> Result<()> {
    let lock = database_root.join("db.lck");
    match std::fs::symlink_metadata(&lock) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("Failed to inspect package database lock {}", lock.display())
            });
        }
        Ok(_) => {}
    }
    if database_lock_has_open_holder(&lock)? {
        return Ok(());
    }
    Err(alpm::Error::HandleLock).with_context(|| {
        format!(
            "Package database lock {} exists without an observed open holder; refusing automatic removal. \
             Stop all package managers and verify their transactions have ended before explicitly recovering the lock. \
             Run `omg doctor` for lock diagnostics.",
            lock.display()
        )
    })
}

fn database_lock_has_open_holder(lock: &std::path::Path) -> Result<bool> {
    database_lock_has_open_holder_in_proc(lock, std::path::Path::new("/proc"))
}

fn database_lock_has_open_holder_in_proc(
    lock: &std::path::Path,
    proc_root: &std::path::Path,
) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let lock_meta = match std::fs::metadata(lock) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("Failed to inspect package database lock {}", lock.display())
            });
        }
    };
    let lock_dev = lock_meta.dev();
    let lock_ino = lock_meta.ino();
    let Ok(proc) = std::fs::read_dir(proc_root) else {
        return Ok(true);
    };
    for entry in proc.flatten() {
        let name = entry.file_name();
        if !name
            .to_str()
            .is_some_and(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
        {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(fd_meta) = std::fs::metadata(fd.path()) else {
                continue;
            };
            if fd_meta.dev() == lock_dev && fd_meta.ino() == lock_ino {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Prepare an ALPM transaction for execution
#[cfg(test)]
fn prepare_alpm_transaction<'a>(
    alpm: &'a mut alpm::Alpm,
    packages: Vec<String>,
    kind: TransactionKind,
    pacman_config: &crate::core::pacman_conf::PacmanConfig,
) -> Result<AlpmTransaction<'a>> {
    prepare_alpm_transaction_in(
        alpm,
        packages,
        kind,
        pacman_config,
        TransactionPolicy::Standard,
    )
}

fn prepare_alpm_transaction_in<'a>(
    alpm: &'a mut alpm::Alpm,
    packages: Vec<String>,
    kind: TransactionKind,
    pacman_config: &crate::core::pacman_conf::PacmanConfig,
    policy: TransactionPolicy,
) -> Result<AlpmTransaction<'a>> {
    validate_transaction_targets(kind, &packages)?;
    let mut admissions = std::collections::BTreeMap::new();
    if kind == TransactionKind::InstallAurArtifact {
        for target in &packages {
            if crate::core::security::is_local_package_file(target) {
                let path = crate::core::security::validate_local_package_file(target)?;
                let admission =
                    crate::package_managers::aur::artifact_inspector::inspect_archive(&path)?;
                admissions.insert(path, admission);
            }
        }
    }
    check_database_lock(std::path::Path::new(alpm.dbpath().trim_end_matches('/')))?;
    let mut flags = transaction_flags(kind);
    if matches!(policy, TransactionPolicy::Omarchy)
        && matches!(kind, TransactionKind::Remove { .. })
    {
        flags |= alpm::TransFlag::NO_SAVE;
    }
    alpm.trans_init(flags)
        .map_err(|e| match e {
            alpm::Error::HandleLock => {
                anyhow::anyhow!(
                    "✗ Database is locked by another process.\n  \
                 → Check holders with: pgrep -a '^(pacman|yay|paru|pikaur|omg|omgd|makepkg)$'\n  \
                 → If a manager is mid-transaction, wait for it and retry.\n  \
                 → Only when no manager is running, clear the stale lock: sudo rm /var/lib/pacman/db.lck\n  \
                 → Then re-run; `omg doctor` reports stale vs live locks"
                )
            }
            _ => anyhow::anyhow!("Failed to initialize transaction: {e}"),
        })?;

    let mut tx_guard = AlpmTransaction(alpm, PreparedArchiveInspections::new(), None);

    if kind == TransactionKind::SystemUpgrade {
        tx_guard
            .0
            .sync_sysupgrade(false)
            .context("Failed to setup sysupgrade")?;
    } else {
        for pkg_name in packages {
            if matches!(kind, TransactionKind::Remove { .. }) {
                ensure_removals_not_held(
                    std::iter::once(pkg_name.as_str()),
                    &pacman_config.hold_pkg,
                )?;
                if let Ok(pkg) = tx_guard.0.localdb().pkg(pkg_name.as_str()) {
                    tx_guard.0.trans_remove_pkg(pkg).map_err(|e| {
                        anyhow::anyhow!("Failed to add {pkg_name} to removal list: {e}")
                    })?;
                } else {
                    tracing::warn!("Package '{pkg_name}' is not installed; skipping removal");
                }
            } else {
                if crate::core::security::is_local_package_file(&pkg_name) {
                    let canonical_path =
                        crate::core::security::validate_local_package_file(&pkg_name)?;
                    let canonical_str = canonical_path
                        .to_str()
                        .context("Package path contains invalid UTF-8")?;

                    let admission = admissions.remove(&canonical_path);

                    let pkg = tx_guard
                        .0
                        .pkg_load(
                            canonical_str.to_string(),
                            true,
                            local_package_siglevel(
                                kind,
                                signature_policy(pacman_config)?.local_file,
                            ),
                        )
                        .map_err(|e| {
                            anyhow::anyhow!("Failed to load local package {pkg_name}: {e}")
                        })?;
                    if let Some(admission) = admission {
                        admission.verify_native_inventory(pkg.files())?;
                        tx_guard
                            .1
                            .insert(canonical_path.clone(), admission.into_inspection());
                    }
                    tx_guard.0.trans_add_pkg(pkg).map_err(|e| {
                        anyhow::anyhow!(
                            "Failed to add local package {pkg_name} to transaction: {e}"
                        )
                    })?;
                    continue;
                }

                let mut found = false;
                let (repository, target) = pkg_name
                    .split_once('/')
                    .map_or((None, pkg_name.as_str()), |(repository, target)| {
                        (Some(repository), target)
                    });
                for db in tx_guard.0.syncdbs() {
                    if repository.is_some_and(|repository| repository != db.name())
                        || (repository.is_none() && !db.usage()?.contains(alpm::Usage::INSTALL))
                    {
                        continue;
                    }
                    validate_sync_database(tx_guard.0, db)?;
                    if let Ok(pkg) = db.pkg(target) {
                        tx_guard.0.trans_add_pkg(pkg).map_err(|e| {
                            anyhow::anyhow!("Failed to add {pkg_name} to installation list: {e}")
                        })?;
                        found = true;
                        break;
                    }
                }
                if !found {
                    anyhow::bail!(
                        "✗ Package '{pkg_name}' {MISSING_FROM_REPOS_MARKER}.\n  \
                         → Run 'omg sync' to update package databases\n  \
                         → Search AUR: omg search {pkg_name}\n  \
                         → Check package name at: https://archlinux.org/packages/"
                    );
                }
            }
        }
    }

    Ok(tx_guard)
}

/// Commit an ALPM transaction
fn pacman_option_path(
    root: &std::path::Path,
    configured: Option<&str>,
    default: &str,
) -> std::path::PathBuf {
    let path = configured.map_or_else(
        || std::path::PathBuf::from(default),
        std::path::PathBuf::from,
    );
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

pub(crate) fn configure_signature_verification(
    alpm: &mut alpm::Alpm,
    pacman_config: &crate::core::pacman_conf::PacmanConfig,
) -> Result<()> {
    configure_signature_policy(alpm, pacman_config)?;
    let keyring = alpm
        .gpgdir()
        .context("Pacman keyring path is not configured")?;
    anyhow::ensure!(
        std::path::Path::new(keyring).is_dir(),
        "Pacman keyring is unavailable at {keyring}. Initialize it before installing packages."
    );
    Ok(())
}

fn configure_transaction_options(
    alpm: &mut alpm::Alpm,
    pacman_config: &crate::core::pacman_conf::PacmanConfig,
) -> Result<()> {
    // `Alpm::new` leaves transaction-critical pacman options empty. Configure
    // them explicitly so downloads, signature verification, architecture
    // checks, logging, and package hooks behave like a normal Arch transaction.
    let root = paths::pacman_root_result()?;
    configure_signature_verification(alpm, pacman_config)?;
    let cache_dirs = paths::pacman_cache_dirs_result()?;
    for cache_dir in &cache_dirs {
        std::fs::create_dir_all(cache_dir).with_context(|| {
            format!(
                "Failed to create pacman package cache at {}",
                cache_dir.display()
            )
        })?;
    }
    let cache_dirs = cache_dirs
        .iter()
        .map(|cache_dir| {
            cache_dir
                .to_str()
                .context("Pacman package cache path contains invalid UTF-8")
        })
        .collect::<Result<Vec<_>>>()?;
    alpm.set_cachedirs(cache_dirs.into_iter())
        .context("Failed to configure pacman package caches")?;

    let log_path = pacman_option_path(
        &root,
        pacman_config.log_file.as_deref(),
        "var/log/pacman.log",
    );
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create pacman log directory at {}",
                parent.display()
            )
        })?;
    }
    let log_path = log_path
        .to_str()
        .context("Pacman log path contains invalid UTF-8")?;
    alpm.set_logfile(log_path)
        .context("Failed to configure pacman transaction log")?;

    // libalpm gives later hook directories precedence for duplicate hook
    // names. Distribution hooks come first, followed by configured overrides.
    let mut hook_dirs = vec![root.join("usr/share/libalpm/hooks")];
    hook_dirs.extend(
        pacman_config
            .hook_dirs
            .iter()
            .map(|path| pacman_option_path(&root, Some(path), path)),
    );
    let hook_dirs = hook_dirs
        .iter()
        .filter(|path| path.is_dir())
        .map(|path| {
            path.to_str()
                .context("Pacman hook path contains invalid UTF-8")
        })
        .collect::<Result<Vec<_>>>()?;
    alpm.set_hookdirs(hook_dirs.into_iter())
        .context("Failed to configure pacman hooks")?;

    let architectures = pacman_config
        .architecture
        .as_deref()
        .unwrap_or("auto")
        .split_whitespace()
        .map(|architecture| {
            if architecture == "auto" {
                std::env::consts::ARCH
            } else {
                architecture
            }
        });
    alpm.set_architectures(architectures)
        .context("Failed to configure package architecture validation")?;
    alpm.set_check_space(true);
    alpm.set_parallel_downloads(
        pacman_config
            .parallel_downloads
            .unwrap_or(PARALLEL_DOWNLOADS),
    );
    configure_package_filters(alpm, pacman_config)?;
    alpm.set_noupgrades(pacman_config.no_upgrade.iter())
        .context("Failed to configure protected upgrade paths")?;
    alpm.set_noextracts(pacman_config.no_extract.iter())
        .context("Failed to configure excluded extraction paths")?;

    Ok(())
}

pub(crate) fn configure_package_filters(
    alpm: &mut alpm::Alpm,
    pacman_config: &crate::core::pacman_conf::PacmanConfig,
) -> Result<()> {
    alpm.set_ignorepkgs(pacman_config.ignore_pkg.iter())
        .context("Failed to configure ignored packages")?;
    alpm.set_ignoregroups(pacman_config.ignore_group.iter())
        .context("Failed to configure ignored package groups")
}

fn ensure_removals_not_held<'a>(
    package_names: impl IntoIterator<Item = &'a str>,
    hold_pkg: &[String],
) -> Result<()> {
    let matchers = super::pacman_db::compile_package_patterns(hold_pkg, "HoldPkg")?;
    for package_name in package_names {
        if let Some(pattern) = matchers.matching_pattern(package_name) {
            anyhow::bail!(
                "Package '{package_name}' is protected by HoldPkg pattern '{pattern}' in pacman.conf and cannot be removed"
            );
        }
    }
    Ok(())
}

#[derive(Debug)]
enum MutationCompletion {
    CommitFailed(anyhow::Error),
    Committed { reasons: Result<()> },
}

impl MutationCompletion {
    fn audit_outcome(&self) -> &'static str {
        match self {
            Self::Committed { reasons: Ok(()) } => "succeeded",
            Self::CommitFailed(_) | Self::Committed { reasons: Err(_) } => "failed",
        }
    }

    fn finish(self, audit: Result<()>) -> Result<()> {
        match (self, audit) {
            (Self::CommitFailed(error), Ok(())) => Err(error),
            (Self::CommitFailed(error), Err(audit)) => {
                Err(error.context(format!("Audit persistence also failed: {audit:#}")))
            }
            (Self::Committed { reasons }, Ok(())) => reasons,
            (Self::Committed { reasons }, Err(audit)) => {
                let error = audit.context("Packages committed, but audit persistence failed; inspect installed state before retrying");
                match reasons {
                    Ok(()) => Err(error),
                    Err(reason) => Err(error.context(format!(
                        "Installation reason persistence also failed: {reason:#}"
                    ))),
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreparedAdvisoryPackage {
    package: super::types::SecurityPackage,
    sha256: Option<String>,
    archive: Option<(std::path::PathBuf, u64, u64, u64)>,
}

fn prepared_repository_origin(
    repository: &str,
    policy: &crate::core::security::SecurityPolicy,
) -> Result<super::types::SecurityOrigin> {
    use crate::core::security::policy::AdvisoryRequirement;
    if policy.arch_advisory_repositories.contains(repository) {
        return Ok(super::types::SecurityOrigin::ArchRepository {
            repository: repository.to_owned(),
        });
    }
    anyhow::ensure!(
        policy.advisory_requirement != AdvisoryRequirement::FreshSnapshot,
        "FreshSnapshot has no declared Arch advisory coordinates for repository '{}'; configure arch_advisory_repositories or use Optional/Review deliberately",
        crate::cli::style::sanitize_terminal_text(repository)
    );
    Ok(super::types::SecurityOrigin::OtherRepository {
        repository: repository.to_owned(),
    })
}

fn prepared_advisory_packages(
    alpm: &alpm::Alpm,
    kind: TransactionKind,
    policy: &crate::core::security::SecurityPolicy,
    staged_targets: &[String],
    signals: Option<&AdmissionSignals>,
) -> Result<Vec<PreparedAdvisoryPackage>> {
    use super::types::{SecurityOrigin, SecurityPackage};
    use std::os::unix::fs::MetadataExt;
    let additions = alpm.trans_add();
    anyhow::ensure!(
        additions.len() <= 4096,
        "Prepared advisory batch exceeds 4096 packages"
    );
    additions
        .into_iter()
        .map(|package| {
            if let Some(signals) = signals {
                signals.check()?;
            }
            let name = package.name().to_owned();
            let version = package.version().as_str().to_owned();
            let display_name = crate::cli::style::sanitize_terminal_text(&name);
            super::parse_version(&version).context("Invalid prepared package version")?;
            let architecture = package
                .arch()
                .context("Prepared package lacks architecture")?
                .to_owned();
            anyhow::ensure!(
                !name.is_empty()
                    && name.len() <= 256
                    && version.len() <= 256
                    && !architecture.is_empty()
                    && architecture.len() <= 64,
                "Prepared advisory identity exceeds limits"
            );
            let (origin, sha256, archive) = if package.origin() == alpm::PackageFrom::SyncDb {
                let repository = package
                    .db()
                    .context("Prepared repository package lacks database")?
                    .name()
                    .to_owned();
                let origin = prepared_repository_origin(&repository, policy)?;
                anyhow::ensure!(
                    package.packager().is_some_and(|packager| !packager.trim().is_empty()),
                    "Prepared repository package {display_name} lacks PACKAGER metadata required for native signing-key checks"
                );
                (origin, package.sha256sum().map(str::to_owned), None)
            } else {
                let path = package
                    .filename()
                    .context("Prepared local archive lacks filename")?;
                anyhow::ensure!(
                    staged_targets
                        .iter()
                        .filter(|target| crate::core::security::is_local_package_file(target))
                        .any(|target| std::fs::canonicalize(target)
                            .is_ok_and(|candidate| candidate == std::path::Path::new(path))),
                    "Prepared local archive is outside the private staged inputs"
                );
                let mut options = std::fs::OpenOptions::new();
                use std::os::unix::fs::OpenOptionsExt;
                options.read(true).custom_flags(
                    nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK,
                );
                let file = options
                    .open(path)
                    .context("Cannot inspect prepared private archive")?;
                let metadata = file.metadata()?;
                anyhow::ensure!(
                    metadata.is_file() && metadata.len() <= 8 * 1024 * 1024 * 1024,
                    "Prepared archive is not a bounded regular file"
                );
                use sha2::{Digest, Sha256};
                use std::io::Read;
                let mut hash = Sha256::new();
                let mut bytes = 0_u64;
                let mut reader = file;
                let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
                loop {
                    if let Some(signals) = signals {
                        signals.check()?;
                    }
                    let count = reader.read(&mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    bytes += count as u64;
                    anyhow::ensure!(
                        bytes <= 8 * 1024 * 1024 * 1024,
                        "Prepared archive exceeds its byte budget"
                    );
                    hash.update(&buffer[..count]);
                }
                anyhow::ensure!(
                    bytes == metadata.len(),
                    "Prepared archive changed while hashing"
                );
                let origin = if kind == TransactionKind::InstallAurArtifact {
                    SecurityOrigin::AurArchive
                } else {
                    SecurityOrigin::LocalArchive
                };
                (
                    origin,
                    Some(hex::encode(hash.finalize())),
                    Some((path.into(), metadata.dev(), metadata.ino(), metadata.len())),
                )
            };
            if policy.advisory_requirement
                == crate::core::security::policy::AdvisoryRequirement::FreshSnapshot
            {
                anyhow::ensure!(
                    sha256.as_deref().is_some_and(|hash| hash.len() == 64
                        && hash.bytes().all(|byte| byte.is_ascii_hexdigit())),
                    "FreshSnapshot requires a SHA-256 binding for prepared package '{display_name}'"
                );
            }
            Ok(PreparedAdvisoryPackage {
                package: SecurityPackage {
                    name,
                    version,
                    architecture: Some(architecture),
                    origin,
                    advisory_source: None,
                    description: String::new(),
                    licenses: package.licenses().into_iter().map(str::to_owned).collect(),
                },
                sha256,
                archive,
            })
        })
        .collect()
}

fn advisory_batch_digest(
    packages: &[PreparedAdvisoryPackage],
    policy: &crate::core::security::SecurityPolicy,
    profile: &[u8],
    invoking_uid: u32,
) -> Result<String> {
    use sha2::{Digest, Sha256};
    let identities = packages
        .iter()
        .map(|item| {
            serde_json::json!({
                "name": item.package.name, "version": item.package.version,
                "architecture": item.package.architecture, "origin": item.package.origin,
                "licenses": item.package.licenses, "sha256": item.sha256, "archive": item.archive,
            })
        })
        .collect::<Vec<_>>();
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&(
        identities,
        policy,
        profile,
        invoking_uid,
    ))?)))
}

static ADMISSION_SIGNAL_OWNER: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static ADMISSION_CANCELLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(target_os = "linux")]
extern "C" fn cancel_admission(_signal: nix::libc::c_int) {
    ADMISSION_CANCELLED.store(true, std::sync::atomic::Ordering::Release);
}

#[cfg(target_os = "linux")]
fn admission_signal_action(
    signal: i32,
    replacement: Option<&nix::libc::sigaction>,
) -> std::io::Result<nix::libc::sigaction> {
    let mut previous = std::mem::MaybeUninit::uninit();
    // SAFETY: sigaction reads the optional valid action and initializes the valid output buffer on success.
    #[expect(
        unsafe_code,
        reason = "the native CLI must temporarily own only default signal dispositions"
    )]
    unsafe {
        if nix::libc::sigaction(
            signal,
            replacement.map_or(std::ptr::null(), std::ptr::from_ref),
            previous.as_mut_ptr(),
        ) == -1
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(previous.assume_init())
    }
}

struct AdmissionSignals {
    #[cfg(target_os = "linux")]
    previous: Vec<(i32, nix::libc::sigaction)>,
    active: bool,
}

impl AdmissionSignals {
    #[cfg(target_os = "linux")]
    fn begin_in(owner: &mut Option<Self>) -> Result<()> {
        use std::sync::atomic::Ordering;
        anyhow::ensure!(
            owner.is_none(),
            "Transaction already owns admission cancellation"
        );
        anyhow::ensure!(
            ADMISSION_SIGNAL_OWNER
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            "Another FreshSnapshot admission owns signal cancellation"
        );
        ADMISSION_CANCELLED.store(false, Ordering::Release);
        let guard = owner.insert(Self {
            previous: Vec::with_capacity(3),
            active: true,
        });
        for signal in [nix::libc::SIGINT, nix::libc::SIGTERM, nix::libc::SIGHUP] {
            let mut action = admission_signal_action(signal, None)?;
            anyhow::ensure!(
                action.sa_sigaction == nix::libc::SIG_DFL,
                "FreshSnapshot cannot take signal ownership from an existing handler; use the ordinary native CLI in a fresh process"
            );
            action.sa_sigaction = cancel_admission as *const () as usize;
            action.sa_flags = 0;
            // SAFETY: action.sa_mask is an initialized sigset_t whose address remains valid for this call.
            #[expect(
                unsafe_code,
                reason = "the scoped cancellation handler must not inherit unrelated signal masks"
            )]
            if unsafe { nix::libc::sigemptyset(&raw mut action.sa_mask) } == -1 {
                return Err(std::io::Error::last_os_error())
                    .context("Cannot configure admission signal mask");
            }
            let previous = admission_signal_action(signal, Some(&action))?;
            let default = previous.sa_sigaction == nix::libc::SIG_DFL;
            guard.previous.push((signal, previous));
            anyhow::ensure!(
                default,
                "FreshSnapshot signal ownership changed during setup; transaction refused"
            );
        }
        guard.check()
    }

    #[cfg(all(test, target_os = "linux"))]
    fn begin() -> Result<Self> {
        let mut owner = None;
        Self::begin_in(&mut owner)?;
        owner.context("Admission signal owner was not acquired")
    }

    #[cfg(not(target_os = "linux"))]
    fn begin_in(_owner: &mut Option<Self>) -> Result<()> {
        anyhow::bail!("FreshSnapshot signal ownership requires the Linux native CLI")
    }

    fn check(&self) -> Result<()> {
        anyhow::ensure!(
            !ADMISSION_CANCELLED.load(std::sync::atomic::Ordering::Acquire),
            "FreshSnapshot admission interrupted before commit"
        );
        #[cfg(target_os = "linux")]
        for (signal, _) in &self.previous {
            anyhow::ensure!(
                admission_signal_action(*signal, None)?.sa_sigaction
                    == cancel_admission as *const () as usize,
                "FreshSnapshot lost signal-handler ownership; transaction refused"
            );
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        let mut error: Option<anyhow::Error> = None;
        #[cfg(target_os = "linux")]
        for (signal, previous) in self.previous.drain(..).rev() {
            let restored = (|| -> Result<()> {
                let current = admission_signal_action(signal, None)?;
                anyhow::ensure!(
                    current.sa_sigaction == cancel_admission as *const () as usize,
                    "FreshSnapshot lost signal-handler ownership; external handler was left unchanged"
                );
                let replaced = admission_signal_action(signal, Some(&previous))?;
                anyhow::ensure!(
                    replaced.sa_sigaction == cancel_admission as *const () as usize,
                    "FreshSnapshot observed concurrent signal-handler replacement; this native CLI context is unsupported"
                );
                Ok(())
            })();
            if let Err(failure) = restored {
                error.get_or_insert(failure);
            }
        }
        let cancelled = ADMISSION_CANCELLED.load(std::sync::atomic::Ordering::Acquire);
        self.active = false;
        ADMISSION_SIGNAL_OWNER.store(false, std::sync::atomic::Ordering::Release);
        if let Some(error) = error {
            return Err(error);
        }
        anyhow::ensure!(
            !cancelled,
            "FreshSnapshot admission interrupted before commit"
        );
        Ok(())
    }
}

impl Drop for AdmissionSignals {
    fn drop(&mut self) {
        if self.active
            && let Err(error) = self.finish()
        {
            tracing::warn!("FreshSnapshot admission signal cleanup: {error:#}");
        }
    }
}

struct UnknownArchiveAcknowledgement {
    batch_digest: String,
    invoking_uid: u32,
}

#[cfg(target_os = "linux")]
fn confirm_unknown_archives(
    packages: &[PreparedAdvisoryPackage],
    digest: &str,
    invoking_uid: u32,
    signals: &AdmissionSignals,
) -> Result<UnknownArchiveAcknowledgement> {
    use std::fmt::Write as _;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
    anyhow::ensure!(
        crate::core::is_root(),
        "FreshSnapshot archive acknowledgement requires the privileged transaction owner"
    );
    let unknown = packages
        .iter()
        .filter(|item| {
            matches!(
                item.package.origin,
                super::types::SecurityOrigin::AurArchive
                    | super::types::SecurityOrigin::LocalArchive
            )
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(
        unknown.len() <= 64,
        "Split FreshSnapshot archive acknowledgements into batches of at most 64 archives"
    );
    let mut tty = std::fs::OpenOptions::new().read(true).write(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK | nix::libc::O_NOCTTY)
        .open("/dev/tty").context("FreshSnapshot unknown archives require an attended controlling terminal; --yes cannot acknowledge unknown coverage")?;
    anyhow::ensure!(
        nix::unistd::tcgetpgrp(&tty)? == nix::unistd::getpgrp(),
        "FreshSnapshot acknowledgement must run in the terminal foreground"
    );
    let mut session: nix::libc::pid_t = 0;
    // SAFETY: TIOCGSID writes one session identifier into this valid stack value.
    #[expect(
        unsafe_code,
        reason = "the acknowledgement must use this process's controlling terminal session"
    )]
    let status =
        unsafe { nix::libc::ioctl(tty.as_raw_fd(), nix::libc::TIOCGSID, &raw mut session) };
    if status == -1 {
        return Err(std::io::Error::last_os_error())
            .context("Cannot establish acknowledgement terminal session");
    }
    anyhow::ensure!(
        nix::unistd::getsid(None)?.as_raw() == session,
        "FreshSnapshot acknowledgement terminal belongs to another session"
    );
    let mut device: nix::libc::c_uint = 0;
    // SAFETY: TIOCGDEV writes one kernel device number into this valid stack value.
    #[expect(
        unsafe_code,
        reason = "kernel terminal identity must be resolved independently of the /dev/tty alias"
    )]
    let status = unsafe { nix::libc::ioctl(tty.as_raw_fd(), nix::libc::TIOCGDEV, &raw mut device) };
    if status == -1 {
        return Err(std::io::Error::last_os_error())
            .context("Cannot establish acknowledgement terminal identity");
    }
    let major = (device >> 8) & 0xfff;
    let minor = (device & 0xff) | ((device >> 12) & 0xfff00);
    let path = if (136..=143).contains(&major) {
        format!("/dev/pts/{minor}")
    } else if major == 4 && (1..=63).contains(&minor) {
        format!("/dev/tty{minor}")
    } else {
        anyhow::bail!("Unsupported terminal identity for FreshSnapshot acknowledgement");
    };
    let metadata = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.file_type().is_char_device()
            && metadata.rdev() == u64::from(device)
            && (metadata.uid() == invoking_uid || metadata.uid() == 0),
        "FreshSnapshot acknowledgement terminal is not owned by root or the invoking user"
    );
    let mut prompt = format!(
        "\nArch advisory applicability is UNKNOWN for these exact archives. This acknowledgement does not establish coverage.\nInvoking UID: {invoking_uid}\nFull prepared batch SHA-256: {digest}\n"
    );
    for item in unknown {
        prompt.push_str(&serde_json::to_string(&(
            &item.package.name,
            &item.package.version,
            &item.package.architecture,
            &item.package.origin,
            &item.sha256,
        ))?);
        prompt.push('\n');
    }
    write!(
        prompt,
        "Type accept {digest} within 60 seconds to continue: "
    )?;
    anyhow::ensure!(
        prompt.len() <= 64 * 1024,
        "FreshSnapshot acknowledgement display exceeds limit"
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_mins(1);
    fn ready(
        tty: &std::fs::File,
        events: rustix::event::PollFlags,
        deadline: std::time::Instant,
        signals: &AdmissionSignals,
    ) -> Result<()> {
        use rustix::event::{PollFd, PollFlags, Timespec, poll};
        loop {
            signals.check()?;
            let remaining = deadline
                .checked_duration_since(std::time::Instant::now())
                .context("FreshSnapshot acknowledgement timed out")?;
            let timeout = Timespec::try_from(remaining.min(std::time::Duration::from_millis(100)))
                .context("Invalid acknowledgement timeout")?;
            let mut items = [PollFd::new(tty, events)];
            let result = poll(&mut items, Some(&timeout))
                .context("FreshSnapshot acknowledgement interrupted")?;
            signals.check()?;
            if result == 0 {
                continue;
            }
            anyhow::ensure!(
                !items[0]
                    .revents()
                    .intersects(PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL),
                "FreshSnapshot acknowledgement terminal disconnected"
            );
            anyhow::ensure!(
                items[0].revents().contains(events),
                "FreshSnapshot acknowledgement terminal is not ready"
            );
            return Ok(());
        }
    }
    let mut remaining = prompt.as_bytes();
    while !remaining.is_empty() {
        ready(&tty, rustix::event::PollFlags::OUT, deadline, signals)?;
        match tty.write(remaining) {
            Ok(0) => anyhow::bail!("FreshSnapshot acknowledgement terminal closed"),
            Ok(count) => remaining = &remaining[count..],
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock) => {}
            Err(error) => return Err(error.into()),
        }
    }
    let mut answer = Vec::new();
    loop {
        ready(&tty, rustix::event::PollFlags::IN, deadline, signals)?;
        let mut buffer = [0_u8; 128];
        let count = match tty.read(&mut buffer) {
            Ok(0) => anyhow::bail!("FreshSnapshot acknowledgement terminal closed"),
            Ok(count) => count,
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock) => {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        answer.extend_from_slice(&buffer[..count]);
        anyhow::ensure!(
            answer.len() <= 96,
            "FreshSnapshot acknowledgement input exceeds limit"
        );
        if answer.contains(&b'\n') {
            break;
        }
    }
    anyhow::ensure!(
        nix::unistd::tcgetpgrp(&tty)? == nix::unistd::getpgrp(),
        "FreshSnapshot terminal foreground changed during acknowledgement"
    );
    anyhow::ensure!(
        answer == format!("accept {digest}\n").as_bytes()
            || answer == format!("accept {digest}\r\n").as_bytes(),
        "FreshSnapshot unknown-coverage acknowledgement declined"
    );
    signals.check()?;
    Ok(UnknownArchiveAcknowledgement {
        batch_digest: digest.to_owned(),
        invoking_uid,
    })
}

#[cfg(not(target_os = "linux"))]
fn confirm_unknown_archives(
    _packages: &[PreparedAdvisoryPackage],
    _digest: &str,
    _invoking_uid: u32,
    _signals: &AdmissionSignals,
) -> Result<UnknownArchiveAcknowledgement> {
    anyhow::bail!("FreshSnapshot archive acknowledgement requires Linux terminal ownership checks")
}

struct PreparedAdvisoryAdmission {
    packages: Vec<PreparedAdvisoryPackage>,
    policy: crate::core::security::SecurityPolicy,
    profile: Vec<u8>,
    invoking_uid: u32,
    acknowledgement: Option<UnknownArchiveAcknowledgement>,
    operation: Option<crate::core::security::vulnerability::ArchOperationAssessment>,
}

impl PreparedAdvisoryAdmission {
    fn new(
        alpm: &alpm::Alpm,
        kind: TransactionKind,
        staged_targets: &[String],
        initial_policy: &crate::core::security::SecurityPolicy,
        inspections: &PreparedArchiveInspections,
        signals: &mut Option<AdmissionSignals>,
    ) -> Result<Self> {
        use crate::core::security::policy::{AdvisoryRequirement, SecurityPolicy};
        use crate::core::security::vulnerability::{AssessmentUse, VulnerabilityScanner};
        if initial_policy.advisory_requirement == AdvisoryRequirement::FreshSnapshot
            && !alpm.trans_add().is_empty()
        {
            AdmissionSignals::begin_in(signals)?;
        }
        let policy = SecurityPolicy::load_current()?;
        anyhow::ensure!(
            &policy == initial_policy,
            "Security policy changed during native transaction preparation; retry the operation"
        );
        policy.validate_advisory_scope()?;
        let settings = crate::config::Settings::load()?;
        let profile = serde_json::to_vec(&settings.aur)?;
        let invoking_uid = crate::core::privilege::invoking_uid()?;
        let packages =
            prepared_advisory_packages(alpm, kind, &policy, staged_targets, signals.as_ref())?;
        for item in &packages {
            if matches!(
                item.package.origin,
                super::types::SecurityOrigin::AurArchive
            ) {
                let path = &item
                    .archive
                    .as_ref()
                    .context("AUR admission lacks an exact archive")?
                    .0;
                let inspection = inspections
                    .get(path)
                    .context("AUR admission lacks its pre-lock archive inspection")?;
                anyhow::ensure!(
                    item.sha256.as_deref() == Some(inspection.archive_sha256.as_str()),
                    "AUR archive changed before current-profile inspection"
                );
                inspection.enforce_profile(settings.aur.security_profile)?;
            }
            let is_aur = matches!(
                item.package.origin,
                super::types::SecurityOrigin::AurArchive
            );
            let license = crate::core::security::policy::combined_license_expression(
                item.package.licenses.iter().map(String::as_str),
            );
            policy.check_package(
                &item.package.name,
                is_aur,
                license.as_deref(),
                SecurityPolicy::source_grade(&item.package.origin),
            )?;
        }
        let acknowledgement = if policy.advisory_requirement == AdvisoryRequirement::FreshSnapshot
            && packages.iter().any(|item| item.archive.is_some())
        {
            Some(confirm_unknown_archives(
                &packages,
                &advisory_batch_digest(&packages, &policy, &profile, invoking_uid)?,
                invoking_uid,
                signals
                    .as_ref()
                    .context("FreshSnapshot signal owner is missing")?,
            )?)
        } else {
            None
        };
        let operation = if packages.is_empty()
            || policy.advisory_requirement == AdvisoryRequirement::Optional
        {
            None
        } else {
            let subjects = packages
                .iter()
                .map(|item| item.package.clone())
                .collect::<Vec<_>>();
            let use_case = if policy.advisory_requirement == AdvisoryRequirement::FreshSnapshot {
                AssessmentUse::Admission
            } else {
                AssessmentUse::Review
            };
            let operation = std::thread::spawn(move || -> Result<_> {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(
                        VulnerabilityScanner::new().assess_arch_operation(&subjects, use_case),
                    )
                    .map_err(Into::into)
            })
            .join()
            .map_err(|_| anyhow::anyhow!("Prepared Arch advisory worker failed"))??;
            anyhow::ensure!(
                operation.assessments().len() == packages.len()
                    && operation
                        .assessments()
                        .iter()
                        .zip(&packages)
                        .all(|(assessment, item)| assessment.package == item.package),
                "Prepared Arch assessment identity mismatch"
            );
            policy.check_sources_and_findings(operation.assessments())?;
            if policy.advisory_requirement == AdvisoryRequirement::FreshSnapshot {
                for assessment in operation.assessments() {
                    anyhow::ensure!(
                        assessment.coverage.is_assessed()
                            || matches!(
                                assessment.package.origin,
                                super::types::SecurityOrigin::AurArchive
                                    | super::types::SecurityOrigin::LocalArchive
                            ) && acknowledgement.is_some(),
                        "FreshSnapshot requires assessed coordinates or an exact private archive acknowledgement"
                    );
                }
            }
            Some(operation)
        };
        if let Some(signals) = signals.as_ref() {
            signals.check()?;
        }
        Ok(Self {
            packages,
            policy,
            profile,
            invoking_uid,
            acknowledgement,
            operation,
        })
    }

    fn validate(
        &self,
        alpm: &alpm::Alpm,
        kind: TransactionKind,
        staged_targets: &[String],
        signals: &mut Option<AdmissionSignals>,
    ) -> Result<()> {
        if let Some(signals) = signals.as_ref() {
            signals.check()?;
        }
        let policy = crate::core::security::SecurityPolicy::load_current()?;
        let profile = serde_json::to_vec(&crate::config::Settings::load()?.aur)?;
        let invoking_uid = crate::core::privilege::invoking_uid()?;
        anyhow::ensure!(
            policy == self.policy && profile == self.profile && invoking_uid == self.invoking_uid,
            "Effective policy, AUR profile or invoking identity changed before commit"
        );
        let current =
            prepared_advisory_packages(alpm, kind, &policy, staged_targets, signals.as_ref())?;
        anyhow::ensure!(
            current == self.packages,
            "Prepared package identity or archive changed after advisory admission"
        );
        if let Some(acknowledgement) = &self.acknowledgement {
            anyhow::ensure!(
                acknowledgement.invoking_uid == invoking_uid
                    && acknowledgement.batch_digest
                        == advisory_batch_digest(&current, &policy, &profile, invoking_uid)?,
                "FreshSnapshot archive acknowledgement no longer matches the prepared batch"
            );
        }
        if let Some(operation) = &self.operation {
            operation.validate_now()?;
        }
        if let Some(signals) = signals.as_mut() {
            signals.check()?;
            signals.finish()?;
        }
        Ok(())
    }
}

fn commit_alpm_transaction(
    alpm: &mut alpm::Alpm,
    main_task: &ProgressTask,
    kind: TransactionKind,
    hold_pkg: &[String],
    reasons: &[(String, alpm::PackageReason)],
    selections: &[super::arch_install::OfficialTarget],
    staged_targets: &[String],
    initial_policy: &crate::core::security::SecurityPolicy,
    inspections: &PreparedArchiveInspections,
    signals: &mut Option<AdmissionSignals>,
) -> Result<()> {
    main_task.set_message("Preparing transaction...");

    alpm.trans_prepare()
        .map_err(|e| anyhow::anyhow!(format_trans_prepare_error(&e.to_string())))?;

    validate_prepared_selections(alpm, selections)?;

    let advisory_admission = PreparedAdvisoryAdmission::new(
        alpm,
        kind,
        staged_targets,
        initial_policy,
        inspections,
        signals,
    )?;

    // RECURSE expands the removal set during preparation. Validate the final
    // set, not only the user's explicit targets, so dependencies protected by
    // HoldPkg cannot be removed as a cascade.
    if matches!(kind, TransactionKind::Remove { .. }) {
        ensure_removals_not_held(
            alpm.trans_remove()
                .into_iter()
                .map(|package| package.name()),
            hold_pkg,
        )?;
    }

    let no_package_changes = alpm.trans_add().is_empty() && alpm.trans_remove().is_empty();
    let reason_changes = reasons.iter().any(|(name, reason)| {
        alpm.localdb()
            .pkg(name.as_str())
            .map_or(true, |package| package.reason() != *reason)
    });
    if no_package_changes && !reason_changes {
        main_task.clear();
        println!();
        // Deliberately neutral wording: this also fires when every requested
        // removal target was already absent, where "system is up to date"
        // would be misleading.
        println!("  {} Nothing to do", crate::cli::style::positive("✓"));
        println!();
        return Ok(());
    }

    main_task.set_message("Finalizing...");
    let targets = alpm
        .trans_add()
        .into_iter()
        .chain(alpm.trans_remove())
        .map(|package| package.name().to_owned())
        .chain(reasons.iter().map(|(name, _)| name.clone()))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let operation = match kind {
        TransactionKind::Install | TransactionKind::InstallAurArtifact => "install",
        TransactionKind::Remove { .. } => "remove",
        TransactionKind::SystemUpgrade => "upgrade",
    };
    crate::core::security::audit::record_operation(operation, &targets, "attempt")?;
    let result = advisory_admission
        .validate(alpm, kind, staged_targets, signals)
        .and_then(|()| {
            if no_package_changes {
                Ok(())
            } else {
                alpm.trans_commit().map_err(|error| {
                    anyhow::anyhow!(
                        "Transaction failed to commit; package state may have changed: {error}"
                    )
                })
            }
        });
    let completion = match result {
        Ok(()) => MutationCompletion::Committed {
            reasons: persist_installation_reasons(alpm, reasons),
        },
        Err(error) => MutationCompletion::CommitFailed(error),
    };
    let audit = crate::core::security::audit::record_operation(
        operation,
        &targets,
        completion.audit_outcome(),
    );
    completion.finish(audit)?;

    main_task.finish(Outcome::Done);

    Ok(())
}

fn is_keyring_related_error(err: &str) -> bool {
    ["keyring", "signature", "pgp", "corrupt"]
        .iter()
        .any(|keyword| contains_ignore_case(err, keyword))
}

fn format_trans_prepare_error(err: &str) -> String {
    if is_keyring_related_error(err) {
        return format!(
            "✗ Transaction preparation failed: {err}\n  \
             → Arch keyring/signature validation appears unhealthy.\n  \
             → Repair: omg update archlinux-keyring\n  \
             → Reinitialize keys: sudo pacman-key --init && sudo pacman-key --populate archlinux\n  \
             → Retry: omg sync && omg install <package>"
        );
    }

    format!(
        "✗ Transaction preparation failed: {err}\n  \
         → This may be due to conflicting packages or missing dependencies.\n  \
         → Try running: omg update && omg install <package>\n  \
         → For more details: omg info <package>"
    )
}

/// Configure ALPM servers for all repos (official + custom)
fn configure_mirrors(alpm: &mut alpm::Alpm) -> Result<()> {
    let conf_path = paths::pacman_conf_path();
    let arch = std::env::consts::ARCH;

    if let Ok(config) = crate::core::pacman_conf::PacmanConfig::parse(&conf_path) {
        for repo in &config.repos {
            match config.resolve_servers(repo, arch) {
                Ok(servers) => {
                    // AlpmListMut is an IntoIterator, not an Iterator.
                    let target_db = alpm
                        .syncdbs_mut()
                        .into_iter()
                        .find(|db| db.name() == repo.name);
                    if let Some(db) = target_db {
                        for server in servers {
                            if let Err(e) = db.add_server(server.clone()) {
                                tracing::debug!(
                                    "Failed to add server '{server}' to repo '{}': {e}",
                                    db.name()
                                );
                            }
                        }
                    } else {
                        tracing::debug!(
                            "Repository '{}' from pacman.conf has no registered sync database",
                            repo.name
                        );
                    }
                }
                Err(error) => tracing::debug!(
                    "Failed to resolve mirrors for repository '{}': {error}",
                    repo.name
                ),
            }
        }
        return ensure_mirror_servers(alpm);
    }

    let mirrorlist = paths::pacman_mirrorlist_path();
    if !mirrorlist.exists() {
        return ensure_mirror_servers(alpm);
    }

    let content = std::fs::read_to_string(mirrorlist)?;
    let mut servers = Vec::with_capacity(16);

    for line in content.lines() {
        let line = line.trim();
        if let Some(url) = MIRRORLIST_REGEX.captures(line).and_then(|caps| caps.get(1)) {
            servers.push(url.as_str().trim().to_string());
        }
    }

    for db in alpm.syncdbs_mut() {
        let db_name = db.name();
        for server in &servers {
            let url = server.replace("$repo", db_name).replace("$arch", arch);
            if let Err(e) = db.add_server(url.clone()) {
                tracing::debug!(
                    "Failed to add server '{}' to repo '{db_name}': {e}",
                    crate::core::http::redact_url(&url)
                );
            }
        }
    }
    ensure_mirror_servers(alpm)
}

fn ensure_mirror_servers(alpm: &alpm::Alpm) -> Result<()> {
    anyhow::ensure!(
        alpm.syncdbs()
            .into_iter()
            .any(|database| !database.servers().is_empty()),
        "No usable pacman mirror servers are configured"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[test]
    fn fresh_admission_signal_ownership_is_scoped_and_refuses_handler_conflicts()
    -> anyhow::Result<()> {
        const NAME: &str = "package_managers::alpm_ops::tests::fresh_admission_signal_ownership_is_scoped_and_refuses_handler_conflicts";
        if crate::core::testing::run_isolated_test(NAME) {
            return Ok(());
        }
        let mut guard = super::AdmissionSignals::begin()?;
        assert!(super::AdmissionSignals::begin().is_err());
        assert!(
            !nix::sys::signal::SigSet::thread_get_mask()?
                .contains(nix::sys::signal::Signal::SIGINT),
            "the isolated signal fixture requires SIGINT unblocked on its receiving thread"
        );
        nix::sys::signal::raise(nix::sys::signal::Signal::SIGINT)?;
        assert!(
            guard.check().is_err(),
            "synchronous current-thread SIGINT must cancel admission"
        );
        assert!(guard.finish().is_err());
        for signal in [nix::libc::SIGINT, nix::libc::SIGTERM, nix::libc::SIGHUP] {
            assert_eq!(
                super::admission_signal_action(signal, None)?.sa_sigaction,
                nix::libc::SIG_DFL
            );
        }
        let default = super::admission_signal_action(nix::libc::SIGTERM, None)?;
        let mut ignored = super::admission_signal_action(nix::libc::SIGTERM, None)?;
        ignored.sa_sigaction = nix::libc::SIG_IGN;
        super::admission_signal_action(nix::libc::SIGTERM, Some(&ignored))?;
        assert!(super::AdmissionSignals::begin().is_err());
        assert_eq!(
            super::admission_signal_action(nix::libc::SIGINT, None)?.sa_sigaction,
            nix::libc::SIG_DFL,
            "partial acquisition rolls back the earlier default handler"
        );
        assert_eq!(
            super::admission_signal_action(nix::libc::SIGTERM, None)?.sa_sigaction,
            nix::libc::SIG_IGN,
            "preexisting owner remains untouched"
        );
        super::admission_signal_action(nix::libc::SIGTERM, Some(&default))?;
        let mut guard = super::AdmissionSignals::begin()?;
        super::admission_signal_action(nix::libc::SIGTERM, Some(&ignored))?;
        assert!(guard.check().is_err());
        assert!(guard.finish().is_err());
        assert_eq!(
            super::admission_signal_action(nix::libc::SIGTERM, None)?.sa_sigaction,
            nix::libc::SIG_IGN,
            "new external owner remains untouched on cleanup"
        );
        super::admission_signal_action(nix::libc::SIGTERM, Some(&default))?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_admission_setup_error_keeps_signal_owner_until_transaction_release()
    -> anyhow::Result<()> {
        const NAME: &str = "package_managers::alpm_ops::tests::native_admission_setup_error_keeps_signal_owner_until_transaction_release";
        if crate::core::testing::run_isolated_test(NAME) {
            return Ok(());
        }
        let fixture = RepositoryFixture::new()?;
        let mut alpm = fixture.open();
        alpm.trans_init(alpm::TransFlag::empty())?;
        let lock = fixture.database().join("db.lck");
        assert!(lock.exists(), "native transaction created its private lock");
        let mut transaction =
            super::AlpmTransaction(&mut alpm, super::PreparedArchiveInspections::new(), None);
        let default = super::admission_signal_action(nix::libc::SIGTERM, None)?;
        let mut ignored = default;
        ignored.sa_sigaction = nix::libc::SIG_IGN;
        super::admission_signal_action(nix::libc::SIGTERM, Some(&ignored))?;
        assert!(super::AdmissionSignals::begin_in(&mut transaction.2).is_err());
        assert!(
            transaction.2.is_some(),
            "partial acquisition belongs to the outer transaction even on error"
        );
        assert!(lock.exists());
        assert_eq!(
            super::admission_signal_action(nix::libc::SIGINT, None)?.sa_sigaction,
            super::cancel_admission as *const () as usize
        );
        drop(transaction);
        assert!(
            !lock.exists(),
            "native release removes the lock during error cleanup"
        );
        assert_eq!(
            super::admission_signal_action(nix::libc::SIGINT, None)?.sa_sigaction,
            nix::libc::SIG_DFL
        );
        assert_eq!(
            super::admission_signal_action(nix::libc::SIGTERM, None)?.sa_sigaction,
            nix::libc::SIG_IGN
        );
        super::admission_signal_action(nix::libc::SIGTERM, Some(&default))?;
        Ok(())
    }

    #[test]
    fn fresh_admission_requires_declared_repository_coordinates_even_for_core() -> anyhow::Result<()>
    {
        use crate::core::security::policy::{AdvisoryRequirement, SecurityPolicy};
        use crate::package_managers::types::SecurityOrigin;
        let mut policy = SecurityPolicy::default();
        assert!(matches!(
            super::prepared_repository_origin("core", &policy)?,
            SecurityOrigin::OtherRepository { .. }
        ));
        policy.advisory_requirement = AdvisoryRequirement::FreshSnapshot;
        assert!(super::prepared_repository_origin("core", &policy).is_err());
        policy.arch_advisory_repositories.insert("core".into());
        assert!(
            matches!(super::prepared_repository_origin("core", &policy)?, SecurityOrigin::ArchRepository { repository } if repository == "core")
        );
        assert!(super::prepared_repository_origin("new-custom-dependency", &policy).is_err());
        Ok(())
    }

    #[test]
    fn archive_acknowledgement_digest_binds_every_prepared_authority_axis() -> anyhow::Result<()> {
        use crate::package_managers::types::{SecurityOrigin, SecurityPackage};
        let package = super::PreparedAdvisoryPackage {
            package: SecurityPackage {
                name: "fixture".into(),
                version: "1-1".into(),
                architecture: Some("x86_64".into()),
                origin: SecurityOrigin::AurArchive,
                advisory_source: None,
                description: String::new(),
                licenses: vec!["MIT".into()],
            },
            sha256: Some("a".repeat(64)),
            archive: Some(("/var/tmp/private/pkg.tar.zst".into(), 1, 2, 3)),
        };
        let policy = crate::core::security::SecurityPolicy::default();
        let digest = super::advisory_batch_digest(
            std::slice::from_ref(&package),
            &policy,
            b"profile",
            1000,
        )?;
        let mut variants = Vec::new();
        let mut changed = package.clone();
        changed.package.name = "other".into();
        variants.push(changed);
        let mut changed = package.clone();
        changed.package.version = "2-1".into();
        variants.push(changed);
        let mut changed = package.clone();
        changed.package.architecture = Some("aarch64".into());
        variants.push(changed);
        let mut changed = package.clone();
        changed.package.origin = SecurityOrigin::LocalArchive;
        variants.push(changed);
        let mut changed = package.clone();
        changed.sha256 = Some("b".repeat(64));
        variants.push(changed);
        let mut changed = package.clone();
        changed.archive.as_mut().expect("archive").2 = 4;
        variants.push(changed);
        for changed in variants {
            assert_ne!(
                super::advisory_batch_digest(&[changed], &policy, b"profile", 1000)?,
                digest
            );
        }
        let mut changed = policy.clone();
        changed.advisory_requirement =
            crate::core::security::policy::AdvisoryRequirement::FreshSnapshot;
        assert_ne!(
            super::advisory_batch_digest(
                std::slice::from_ref(&package),
                &changed,
                b"profile",
                1000
            )?,
            digest
        );
        assert_ne!(
            super::advisory_batch_digest(
                std::slice::from_ref(&package),
                &policy,
                b"changed-profile",
                1000
            )?,
            digest
        );
        assert_ne!(
            super::advisory_batch_digest(&[package], &policy, b"profile", 1001)?,
            digest
        );
        Ok(())
    }

    #[test]
    fn mutation_completion_preserves_outcomes_and_primary_causes() {
        use super::MutationCompletion::{CommitFailed, Committed};

        struct Case {
            label: &'static str,
            completion: super::MutationCompletion,
            audit: anyhow::Result<()>,
            outcome: &'static str,
            primary: Option<&'static str>,
            diagnostics: &'static [&'static str],
        }

        let cause = |label| anyhow::Error::from(std::io::Error::other(label));
        let commit_error = || {
            cause("commit cause")
                .context("Transaction failed to commit; package state may have changed")
        };
        let reason_error = || {
            cause("reason cause").context(
                "Transaction completed, but installation reason could not be persisted; inspect installed state before retrying",
            )
        };
        let cases = [
            Case {
                label: "mutation, reasons and audit succeeded",
                completion: Committed { reasons: Ok(()) },
                audit: Ok(()),
                outcome: "succeeded",
                primary: None,
                diagnostics: &[],
            },
            Case {
                label: "committed mutation with audit failure",
                completion: Committed { reasons: Ok(()) },
                audit: Err(cause("audit cause")),
                outcome: "succeeded",
                primary: Some("audit cause"),
                diagnostics: &[
                    "Packages committed, but audit persistence failed",
                    "inspect installed state before retrying",
                ],
            },
            Case {
                label: "committed mutation with reason failure",
                completion: Committed {
                    reasons: Err(reason_error()),
                },
                audit: Ok(()),
                outcome: "failed",
                primary: Some("reason cause"),
                diagnostics: &[
                    "installation reason could not be persisted",
                    "inspect installed state before retrying",
                ],
            },
            Case {
                label: "committed mutation with reason and audit failures",
                completion: Committed {
                    reasons: Err(reason_error()),
                },
                audit: Err(cause("audit cause")),
                outcome: "failed",
                primary: Some("audit cause"),
                diagnostics: &[
                    "Installation reason persistence also failed",
                    "reason cause",
                    "Packages committed, but audit persistence failed",
                    "inspect installed state before retrying",
                ],
            },
            Case {
                label: "commit failure with persisted audit",
                completion: CommitFailed(commit_error()),
                audit: Ok(()),
                outcome: "failed",
                primary: Some("commit cause"),
                diagnostics: &["Transaction failed to commit; package state may have changed"],
            },
            Case {
                label: "commit and audit failures",
                completion: CommitFailed(commit_error()),
                audit: Err(cause("audit cause")),
                outcome: "failed",
                primary: Some("commit cause"),
                diagnostics: &[
                    "Transaction failed to commit; package state may have changed",
                    "Audit persistence also failed",
                    "audit cause",
                ],
            },
        ];
        for case in cases {
            assert_eq!(
                case.completion.audit_outcome(),
                case.outcome,
                "{}",
                case.label
            );
            let result = case.completion.finish(case.audit);
            let Some(primary) = case.primary else {
                assert!(result.is_ok(), "{}: {result:?}", case.label);
                continue;
            };
            let error = result.expect_err(case.label);
            let diagnostic = format!("{error:#}");
            assert_eq!(
                error.root_cause().to_string(),
                primary,
                "{}: {diagnostic}",
                case.label
            );
            assert!(
                error.downcast_ref::<std::io::Error>().is_some(),
                "{} must preserve its primary typed cause: {diagnostic}",
                case.label
            );
            for expected in case.diagnostics {
                assert!(
                    diagnostic.contains(expected),
                    "{} must preserve {expected:?}: {diagnostic}",
                    case.label
                );
            }
        }
    }

    struct RepositoryFixture {
        directory: tempfile::TempDir,
    }

    impl RepositoryFixture {
        fn new() -> anyhow::Result<Self> {
            let directory = tempfile::tempdir()?;
            std::fs::create_dir(directory.path().join("root"))?;
            std::fs::create_dir_all(directory.path().join("db/local"))?;
            std::fs::create_dir(directory.path().join("db/sync"))?;
            std::fs::write(directory.path().join("db/local/ALPM_DB_VERSION"), "9\n")?;
            Ok(Self { directory })
        }

        fn database(&self) -> std::path::PathBuf {
            self.directory.path().join("db")
        }

        fn write_sync(
            &self,
            repository: &str,
            packages: &[(&str, &str, &str)],
        ) -> anyhow::Result<()> {
            let file =
                std::fs::File::create(self.database().join(format!("sync/{repository}.db")))?;
            let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
                file,
                flate2::Compression::fast(),
            ));
            for (name, version, extra) in packages {
                let content = format!(
                    "%NAME%\n{name}\n\n%VERSION%\n{version}\n\n%FILENAME%\n{name}-{version}-any.pkg.tar.zst\n\n%ARCH%\nany\n\n%CSIZE%\n1\n\n%ISIZE%\n1\n\n%PACKAGER%\nFixture Maintainer <fixture@example.invalid>\n\n{extra}"
                );
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                archive
                    .append_data(
                        &mut header,
                        format!("{name}-{version}/desc"),
                        content.as_bytes(),
                    )
                    .expect("private repository fixture record is writable");
            }
            archive.into_inner()?.finish()?;
            Ok(())
        }

        fn write_local(&self, name: &str, version: &str) -> anyhow::Result<()> {
            let package = self.database().join(format!("local/{name}-{version}"));
            std::fs::create_dir(&package)?;
            std::fs::write(
                package.join("desc"),
                format!("%NAME%\n{name}\n\n%VERSION%\n{version}\n\n%ARCH%\nany\n\n%REASON%\n0\n\n"),
            )
            .expect("private local package fixture descriptor is writable");
            Ok(())
        }

        fn open(&self) -> alpm::Alpm {
            alpm::Alpm::new(
                self.directory
                    .path()
                    .join("root")
                    .to_str()
                    .expect("UTF-8 root"),
                self.database().to_str().expect("UTF-8 database"),
            )
            .expect("private repository fixture opens in native ALPM")
        }
    }

    #[test]
    #[ignore = "requires an explicitly provisioned isolated Arch container or QEMU guest"]
    fn native_reason_write_failure_preserves_durable_reason() -> anyhow::Result<()> {
        use anyhow::Context as _;
        use std::fs;

        anyhow::ensure!(
            std::env::var("OMG_ARCH_INSTALL_FIXTURE").as_deref() == Ok("isolated-container")
                && crate::core::is_root(),
            "reason-write fixture requires the disposable native root environment"
        );
        let fixture = RepositoryFixture::new()?;
        let name = "omg-fixture-reason-failure";
        fixture.write_local(name, "1-1")?;
        let desc = fixture.database().join(format!("local/{name}-1-1/desc"));
        let original = fs::read_to_string(&desc)?.replace("%REASON%\n0\n", "%REASON%\n1\n");
        fs::write(&desc, &original)?;
        let mut alpm = fixture.open();
        assert_eq!(
            alpm.localdb().pkg(name)?.reason(),
            alpm::PackageReason::Depend
        );
        let saved = desc.with_extension("saved");
        fs::rename(&desc, &saved)?;
        fs::create_dir(&desc)?;

        let audit_path = std::path::Path::new("/var/lib/omg/audit/audit.jsonl");
        let audit_before = crate::core::security::AuditLogger::new_in(audit_path)
            .expect("initialize disposable fixture audit state")
            .get_recent(usize::MAX)
            .expect("read a valid disposable fixture audit baseline")
            .len();
        alpm.trans_init(alpm::TransFlag::empty())?;
        let mut transaction =
            super::AlpmTransaction(&mut alpm, super::PreparedArchiveInspections::new(), None);
        let task = super::ProgressTask::start(&super::TaskSpec {
            label: "Reason persistence fixture".to_owned(),
            kind: super::TaskKind::Items { total: 1 },
            accent: super::Accent::System,
        });
        let error = super::commit_alpm_transaction(
            transaction.0,
            &task,
            super::TransactionKind::InstallAurArtifact,
            &[],
            &[(name.to_owned(), alpm::PackageReason::Explicit)],
            &[],
            &[],
            &crate::core::security::SecurityPolicy::load_current()?,
            &super::PreparedArchiveInspections::new(),
            &mut transaction.2,
        )
        .expect_err("a directory in place of desc must refuse durable reason persistence");
        drop(transaction);
        let diagnostic = format!("{error:#}");
        assert!(
            diagnostic.contains(name)
                && diagnostic.contains("could not be persisted")
                && diagnostic.contains("inspect installed state before retrying"),
            "reason-write failure must identify the package and require inspection: {diagnostic}"
        );
        assert_eq!(
            error.downcast_ref::<alpm::Error>(),
            Some(&alpm::Error::DbWrite),
            "the native reason-write cause must remain available: {diagnostic}"
        );
        fs::remove_dir(&desc)?;
        fs::rename(&saved, &desc)?;
        assert_eq!(fs::read_to_string(&desc)?, original);
        drop(alpm);
        let reopened = fixture.open();
        assert_eq!(
            reopened.localdb().pkg(name)?.reason(),
            alpm::PackageReason::Depend,
            "a reopened database must retain the original durable reason after failed write"
        );
        assert!(
            !fixture.database().join("db.lck").exists(),
            "reason persistence failure must release the native transaction lock"
        );
        let audit = fs::read_to_string(audit_path)?;
        let entries = audit
            .lines()
            .skip(audit_before)
            .map(serde_json::from_str::<serde_json::Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert_eq!(entries.len(), 2, "one attempt and one terminal audit");
        for (entry, outcome) in entries.iter().zip(["attempt", "failed"]) {
            assert_eq!(entry["resource"].as_str(), Some(name));
            assert!(
                entry["description"]
                    .as_str()
                    .context("audit description")?
                    .contains(&format!("Package operation install: {outcome};")),
                "reason-write audit must report {outcome}: {entry}"
            );
        }
        Ok(())
    }

    #[test]
    fn repository_usage_controls_info_and_update_candidates() -> anyhow::Result<()> {
        let fixture = RepositoryFixture::new()?;
        fixture.write_local("helper", "1-1")?;
        fixture.write_sync("excluded", &[("helper", "9-1", "")])?;
        fixture.write_sync("eligible", &[("helper", "2-1", "")])?;
        let alpm = fixture.open();
        let excluded = alpm.register_syncdb("excluded", alpm::SigLevel::NONE)?;
        excluded.set_usage(alpm::Usage::UPGRADE)?;
        alpm.register_syncdb("eligible", alpm::SigLevel::NONE)?
            .set_usage(alpm::Usage::SEARCH | alpm::Usage::UPGRADE)?;

        let info = super::get_pkg_info_from_db(&alpm, "helper")?.expect("eligible package");
        assert_eq!(info.repo, "eligible");
        assert_eq!(info.version.to_string(), "2-1");
        assert!(
            info.installed,
            "the selected package is installed at version 1"
        );

        excluded.set_usage(alpm::Usage::SEARCH)?;
        let updates = super::collect_updates(&alpm)?;
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].name, "helper");
        assert_eq!(updates[0].old_version, "1-1");
        assert_eq!(updates[0].new_version, "2-1");
        assert_eq!(updates[0].repo, "eligible");
        Ok(())
    }

    #[test]
    fn updates_ignore_installed_group_when_upgrade_drops_group() -> anyhow::Result<()> {
        use std::io::Write as _;

        let fixture = RepositoryFixture::new()?;
        fixture.write_local("helper", "1-1")?;
        std::fs::OpenOptions::new()
            .append(true)
            .open(fixture.database().join("local/helper-1-1/desc"))?
            .write_all(b"%GROUPS%\nheld\n\n")?;
        fixture.write_sync("preferred", &[("helper", "2-1", "")])?;
        let mut alpm = fixture.open();
        alpm.register_syncdb("preferred", alpm::SigLevel::NONE)?
            .set_usage(alpm::Usage::UPGRADE)?;
        alpm.set_ignoregroups(std::iter::once("held"))?;

        assert!(alpm.localdb().pkg("helper")?.should_ignore());
        assert!(
            !alpm
                .syncdbs()
                .iter()
                .next()
                .expect("preferred repository")
                .pkg("helper")?
                .should_ignore(),
            "the upgrade must have dropped the ignored group"
        );
        alpm.trans_init(alpm::TransFlag::NO_LOCK)?;
        alpm.sync_sysupgrade(false)?;
        assert!(
            alpm.trans_add().is_empty(),
            "native sysupgrade must retain the installed package's ignored group"
        );
        alpm.trans_release()?;

        alpm.set_ignoregroups(std::iter::empty::<&str>())?;
        let control = super::collect_updates(&alpm)?;
        assert_eq!(control.len(), 1, "the unignored upgrade must be visible");
        assert_eq!(control[0].name, "helper");
        assert_eq!(control[0].old_version, "1-1");
        assert_eq!(control[0].new_version, "2-1");
        assert_eq!(control[0].repo, "preferred");

        alpm.set_ignoregroups(std::iter::once("held"))?;
        let updates = super::collect_updates(&alpm)?;
        assert!(
            updates.is_empty(),
            "updates must match native sysupgrade when the installed package alone is ignored: {updates:?}"
        );
        Ok(())
    }

    #[test]
    fn updates_do_not_fall_through_ignored_preferred_repository() -> anyhow::Result<()> {
        let fixture = RepositoryFixture::new()?;
        fixture.write_local("helper", "1-1")?;
        fixture.write_sync("preferred", &[("helper", "2-1", "%GROUPS%\nheld\n\n")])?;
        fixture.write_sync("lower", &[("helper", "9-1", "")])?;
        let mut alpm = fixture.open();
        alpm.register_syncdb("preferred", alpm::SigLevel::NONE)?
            .set_usage(alpm::Usage::UPGRADE)?;
        alpm.register_syncdb("lower", alpm::SigLevel::NONE)?
            .set_usage(alpm::Usage::UPGRADE)?;
        alpm.set_ignoregroups(std::iter::once("held"))?;

        assert!(!alpm.localdb().pkg("helper")?.should_ignore());
        assert!(
            alpm.syncdbs()
                .iter()
                .next()
                .expect("preferred repository")
                .pkg("helper")?
                .should_ignore(),
            "the preferred repository candidate must belong to the ignored group"
        );
        alpm.trans_init(alpm::TransFlag::NO_LOCK)?;
        alpm.sync_sysupgrade(false)?;
        assert!(
            alpm.trans_add().is_empty(),
            "native sysupgrade must not fall through an ignored preferred repository candidate"
        );
        alpm.trans_release()?;

        alpm.set_ignoregroups(std::iter::empty::<&str>())?;
        let control = super::collect_updates(&alpm)?;
        assert_eq!(control.len(), 1, "the unignored upgrade must be visible");
        assert_eq!(control[0].name, "helper");
        assert_eq!(control[0].old_version, "1-1");
        assert_eq!(control[0].new_version, "2-1");
        assert_eq!(control[0].repo, "preferred");

        alpm.set_ignoregroups(std::iter::once("held"))?;
        let updates = super::collect_updates(&alpm)?;
        assert!(
            updates.is_empty(),
            "updates must match native sysupgrade instead of selecting the lower repository: {updates:?}"
        );
        Ok(())
    }

    #[test]
    fn scoped_info_reads_current_metadata_after_native_cache_is_primed() -> anyhow::Result<()> {
        let fixture = RepositoryFixture::new()?;
        fixture.write_sync("core", &[("helper", "1-1", "")])?;
        let alpm = fixture.open();
        alpm.register_syncdb("core", alpm::SigLevel::NONE)?;
        assert_eq!(
            super::get_pkg_info_from_db(&alpm, "helper")?
                .unwrap()
                .version
                .to_string(),
            "1-1"
        );
        fixture.write_sync("core", &[("helper", "2-1", "")])?;
        assert_eq!(
            super::get_pkg_info_from_db(&alpm, "helper")?
                .unwrap()
                .version
                .to_string(),
            "2-1"
        );
        Ok(())
    }

    #[test]
    fn scoped_info_reads_current_installed_state_after_native_cache_is_primed() -> anyhow::Result<()>
    {
        let fixture = RepositoryFixture::new()?;
        fixture.write_sync("core", &[("helper", "2-1", "")])?;
        let alpm = fixture.open();
        alpm.register_syncdb("core", alpm::SigLevel::NONE)?;
        assert!(
            !super::get_pkg_info_from_db(&alpm, "helper")?
                .unwrap()
                .installed
        );
        fixture.write_local("helper", "1-1")?;
        assert!(
            super::get_pkg_info_from_db(&alpm, "helper")?
                .unwrap()
                .installed,
            "newly installed package must not retain an earlier missing-package cache result"
        );
        std::fs::remove_dir_all(fixture.database().join("local/helper-1-1"))?;
        assert!(
            !super::get_pkg_info_from_db(&alpm, "helper")?
                .unwrap()
                .installed
        );
        Ok(())
    }

    #[test]
    fn scoped_info_revalidates_present_signatures_after_native_cache_is_primed()
    -> anyhow::Result<()> {
        let fixture = RepositoryFixture::new()?;
        let keyring = fixture.directory.path().join("keyring");
        std::fs::create_dir(&keyring)?;
        fixture.write_sync("core", &[("helper", "1-1", "")])?;
        let mut alpm = fixture.open();
        alpm.set_gpgdir(keyring.to_str().unwrap())?;
        alpm.register_syncdb(
            "core",
            alpm::SigLevel::DATABASE | alpm::SigLevel::DATABASE_OPTIONAL,
        )?;
        assert!(super::get_pkg_info_from_db(&alpm, "helper")?.is_some());
        fixture.write_sync("core", &[("helper", "2-1", "")])?;
        std::fs::write(
            fixture.database().join("sync/core.db.sig"),
            b"invalid signature",
        )?;
        let error = super::get_pkg_info_from_db(&alpm, "helper").expect_err(
            "current metadata must not reuse an earlier native signature-validation result",
        );
        assert!(error.downcast_ref::<alpm::Error>().is_some());
        Ok(())
    }

    #[test]
    fn info_refuses_unavailable_eligible_repositories() -> anyhow::Result<()> {
        for corrupt in [false, true] {
            let fixture = RepositoryFixture::new()?;
            fixture.write_sync("healthy", &[("helper", "2-1", "")])?;
            if corrupt {
                std::fs::write(
                    fixture.database().join("sync/unavailable.db"),
                    b"invalid database",
                )
                .expect("private malformed repository fixture is writable");
            }
            let alpm = fixture.open();
            alpm.register_syncdb("healthy", alpm::SigLevel::NONE)?;
            alpm.register_syncdb("unavailable", alpm::SigLevel::NONE)?
                .set_usage(alpm::Usage::SEARCH)?;
            let error = super::get_pkg_info_from_db(&alpm, "absent").expect_err(if corrupt {
                "a corrupt eligible catalog cannot establish absence"
            } else {
                "a missing eligible catalog cannot establish absence"
            });
            let message = error.to_string();
            assert!(message.contains("Repository 'unavailable'"), "{error:#}");
            assert!(
                message.contains(if corrupt {
                    "failed native validation"
                } else {
                    "is unavailable"
                }),
                "{error:#}"
            );
        }
        Ok(())
    }

    #[test]
    fn native_database_validation_refuses_a_directory() -> anyhow::Result<()> {
        let fixture = RepositoryFixture::new()?;
        let path = fixture.database().join("sync/nonregular.db");
        std::fs::create_dir(&path)?;
        let alpm = fixture.open();
        let database = alpm.register_syncdb("nonregular", alpm::SigLevel::NONE)?;
        let error = super::validate_sync_database(&alpm, database)
            .expect_err("a database path must be a regular file");
        assert!(
            error
                .to_string()
                .contains("Repository 'nonregular' is not a regular database"),
            "{error:#}"
        );
        assert!(
            path.is_dir(),
            "validation must preserve the rejected object"
        );
        Ok(())
    }

    #[test]
    fn prepared_dependency_refuses_a_missing_repository_or_package() -> anyhow::Result<()> {
        use crate::package_managers::arch_install::OfficialTarget;
        let original = RepositoryFixture::new()?;
        original.write_sync("selected", &[("helper", "2-1", "")])?;
        let selected = {
            let alpm = original.open();
            let database = alpm.register_syncdb("selected", alpm::SigLevel::NONE)?;
            let package = database.pkg("helper")?;
            OfficialTarget {
                repository: database.name().to_owned(),
                name: package.name().to_owned(),
                relations: vec!["helper>=2".to_owned()],
            }
        };
        let changed = RepositoryFixture::new()?;
        changed.write_sync("selected", &[("other", "2-1", "")])?;
        let alpm = changed.open();
        let error = super::validate_prepared_selections(&alpm, std::slice::from_ref(&selected))
            .expect_err("a removed selected repository cannot be substituted");
        assert!(
            error
                .to_string()
                .contains("Selected repository 'selected' is no longer configured"),
            "{error:#}"
        );
        alpm.register_syncdb("selected", alpm::SigLevel::NONE)?;
        let error = super::validate_prepared_selections(&alpm, &[selected])
            .expect_err("a removed selected package cannot be substituted");
        assert!(
            error
                .to_string()
                .contains("Selected package 'selected/helper' is no longer available"),
            "{error:#}"
        );
        Ok(())
    }

    #[test]
    fn selected_dependency_uses_installed_state_only_when_present() -> anyhow::Result<()> {
        use crate::package_managers::arch_install::OfficialTarget;
        for installed in [false, true] {
            let fixture = RepositoryFixture::new()?;
            fixture.write_sync("selected", &[("helper", "2-1", "")])?;
            if installed {
                fixture.write_local("helper", "2-1")?;
            }
            let mut alpm = fixture.open();
            alpm.register_syncdb("selected", alpm::SigLevel::NONE)?;
            let targets = if installed {
                vec!["selected/helper".to_owned()]
            } else {
                Vec::new()
            };
            let prepared = super::prepare_alpm_transaction(
                &mut alpm,
                targets,
                super::TransactionKind::Install,
                &crate::core::pacman_conf::PacmanConfig::default(),
            )
            .expect("private installed-state fixture transaction initializes");
            prepared
                .0
                .trans_prepare()
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            assert!(
                prepared.0.trans_add().is_empty(),
                "the fixture must prepare no package changes"
            );
            let selection = OfficialTarget {
                repository: "selected".to_owned(),
                name: "helper".to_owned(),
                relations: vec!["helper>=2".to_owned(), "helper<3".to_owned()],
            };
            let result = super::validate_prepared_selections(prepared.0, &[selection]);
            if installed {
                result?;
                assert_eq!(
                    prepared.0.localdb().pkg("helper")?.reason(),
                    alpm::PackageReason::Explicit
                );
            } else {
                let error =
                    result.expect_err("a selected dependency must be prepared or installed");
                assert!(
                    error
                        .to_string()
                        .contains("neither prepared nor already installed"),
                    "{error:#}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn selected_virtual_dependency_preserves_provision_constraints() -> anyhow::Result<()> {
        use crate::package_managers::arch_install::OfficialTarget;
        let fixture = RepositoryFixture::new()?;
        fixture
            .write_sync(
                "selected",
                &[("provider", "7-1", "%PROVIDES%\nvirtual-helper=2\n\n")],
            )
            .expect("private virtual-provider repository is writable");
        let mut alpm = fixture.open();
        alpm.register_syncdb("selected", alpm::SigLevel::NONE)?;
        let prepared = super::prepare_alpm_transaction(
            &mut alpm,
            vec!["selected/provider".to_owned()],
            super::TransactionKind::Install,
            &crate::core::pacman_conf::PacmanConfig::default(),
        )
        .expect("private virtual-provider fixture transaction initializes");
        prepared
            .0
            .trans_prepare()
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        assert_eq!(
            prepared
                .0
                .trans_add()
                .first()
                .expect("prepared provider")
                .name(),
            "provider"
        );
        let selection = OfficialTarget {
            repository: "selected".to_owned(),
            name: "provider".to_owned(),
            relations: vec![
                "virtual-helper>=2".to_owned(),
                "virtual-helper<3".to_owned(),
            ],
        };
        super::validate_prepared_selections(prepared.0, std::slice::from_ref(&selection))?;
        let stale = OfficialTarget {
            relations: vec!["virtual-helper>=3".to_owned()],
            ..selection
        };
        let error = super::validate_prepared_selections(prepared.0, &[stale])
            .expect_err("the provider package version must not replace its provision version");
        assert!(
            error
                .to_string()
                .contains("no longer satisfies 'virtual-helper>=3'"),
            "{error:#}"
        );
        Ok(())
    }

    #[test]
    fn reason_persistence_reports_a_missing_installed_package() -> anyhow::Result<()> {
        let fixture = RepositoryFixture::new()?;
        fixture.write_local("unrelated", "1-1")?;
        let description = fixture.database().join("local/unrelated-1-1/desc");
        let before = std::fs::read(&description)?;
        let alpm = fixture.open();
        let error = super::persist_installation_reasons(
            &alpm,
            &[("absent".to_owned(), alpm::PackageReason::Depend)],
        )
        .expect_err("missing postcommit state must require inspection before retry");
        assert!(
            error
                .to_string()
                .contains("installed package 'absent' could not be found"),
            "{error:#}"
        );
        assert!(
            error
                .to_string()
                .contains("inspect installed state before retrying"),
            "{error:#}"
        );
        assert_eq!(std::fs::read(description)?, before);
        assert_eq!(
            alpm.localdb().pkg("unrelated")?.reason(),
            alpm::PackageReason::Explicit
        );
        Ok(())
    }

    #[test]
    fn prepared_dependency_keeps_selected_repository_and_constraints() -> anyhow::Result<()> {
        use crate::package_managers::arch_install::OfficialTarget;
        let fixture = RepositoryFixture::new()?;
        fixture.write_sync("high", &[("helper", "1-1", "")])?;
        fixture.write_sync("low", &[("helper", "2-1", "")])?;
        let mut alpm = fixture.open();
        alpm.register_syncdb("high", alpm::SigLevel::NONE)?;
        alpm.register_syncdb("low", alpm::SigLevel::NONE)?;
        let selected = OfficialTarget {
            repository: "low".to_owned(),
            name: "helper".to_owned(),
            relations: vec!["helper>=2".to_owned(), "helper<3".to_owned()],
        };
        let config = crate::core::pacman_conf::PacmanConfig::default();
        {
            let prepared = super::prepare_alpm_transaction(
                &mut alpm,
                vec!["low/helper".to_owned()],
                super::TransactionKind::Install,
                &config,
            )
            .expect("selected-repository fixture transaction initializes");
            prepared
                .0
                .trans_prepare()
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            super::validate_prepared_selections(prepared.0, std::slice::from_ref(&selected))?;
            assert_eq!(
                prepared.0.trans_add().first().unwrap().version().as_str(),
                "2-1"
            );
            let stale = OfficialTarget {
                relations: vec!["helper>=3".to_owned()],
                ..selected.clone()
            };
            let error = super::validate_prepared_selections(prepared.0, &[stale]).unwrap_err();
            assert!(
                error.to_string().contains("no longer satisfies"),
                "{error:#}"
            );
        }
        {
            let prepared = super::prepare_alpm_transaction(
                &mut alpm,
                vec!["helper".to_owned()],
                super::TransactionKind::Install,
                &config,
            )
            .expect("unqualified fixture transaction initializes");
            prepared
                .0
                .trans_prepare()
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            let error =
                super::validate_prepared_selections(prepared.0, std::slice::from_ref(&selected))
                    .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("differs from its selected repository"),
                "{error:#}"
            );
        }
        alpm.syncdbs()
            .into_iter()
            .find(|db| db.name() == "low")
            .unwrap()
            .set_usage(alpm::Usage::SEARCH)?;
        let prepared = super::prepare_alpm_transaction(
            &mut alpm,
            vec!["low/helper".to_owned()],
            super::TransactionKind::Install,
            &config,
        )
        .expect("disabled-repository fixture transaction initializes");
        prepared
            .0
            .trans_prepare()
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        let error = super::validate_prepared_selections(prepared.0, &[selected]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("no longer allows dependency installation"),
            "{error:#}"
        );
        Ok(())
    }

    use std::sync::Mutex;

    use super::{
        AlpmQuestionRefusals, ForwardedAlpmLogLevel, TransactionKind, check_database_lock,
        classify_alpm_log_level, clean_cache, clean_cache_preview, configure_signature_policy,
        download_lane_message, ensure_mirror_servers, ensure_removals_not_held,
        format_trans_prepare_error, is_keyring_related_error, local_package_siglevel,
        package_base_name, provider_selection_message, question_refusal_error,
        register_configured_syncdbs, repository_siglevel, setup_alpm_callbacks, signature_policy,
        transaction_flags, transaction_overall_percent, validate_aur_artifact_handoffs,
        validate_transaction_targets,
    };
    use crate::core::paths;

    #[test]
    fn lock_scan_skips_a_vanished_descriptor() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let lock = directory.path().join("db.lck");
        std::fs::write(&lock, b"")?;
        let proc_root = directory.path().join("proc");
        let descriptors = proc_root.join("123/fd");
        std::fs::create_dir_all(&descriptors)?;
        std::os::unix::fs::symlink(directory.path().join("vanished"), descriptors.join("3"))?;
        assert!(!super::database_lock_has_open_holder_in_proc(
            &lock, &proc_root
        )?);
        assert!(lock.exists(), "holder inspection must not remove the lock");
        Ok(())
    }

    #[test]
    fn lock_scan_does_not_hide_a_holder_after_an_unavailable_descriptor() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let lock = directory.path().join("db.lck");
        std::fs::write(&lock, b"")?;
        let proc_root = directory.path().join("proc");
        let descriptors = proc_root.join("123/fd");
        std::fs::create_dir_all(&descriptors)?;
        std::os::unix::fs::symlink(directory.path().join("vanished"), descriptors.join("3"))?;
        std::os::unix::fs::symlink(&lock, descriptors.join("4"))?;
        assert!(super::database_lock_has_open_holder_in_proc(
            &lock, &proc_root
        )?);
        assert!(lock.exists(), "live holder must retain its lock");
        Ok(())
    }

    #[test]
    fn lock_scan_keeps_a_lock_when_process_inspection_is_unavailable() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let lock = directory.path().join("db.lck");
        std::fs::write(&lock, b"")?;
        assert!(super::database_lock_has_open_holder_in_proc(
            &lock,
            &directory.path().join("missing-proc")
        )?);
        assert!(
            lock.exists(),
            "unavailable process data must not reclaim a lock"
        );
        Ok(())
    }

    #[test]
    fn transaction_preparation_preserves_unheld_database_lock() -> anyhow::Result<()> {
        use std::os::unix::fs::MetadataExt;

        let directory = tempfile::tempdir()?;
        let lock = directory.path().join("db.lck");
        std::fs::write(&lock, b"unheld-lock-evidence")?;
        let inode = std::fs::metadata(&lock)?.ino();
        let mut alpm = alpm::Alpm::new("/", directory.path().to_str().expect("utf-8 path"))?;
        let result = super::prepare_alpm_transaction(
            &mut alpm,
            vec![],
            TransactionKind::Install,
            &crate::core::pacman_conf::PacmanConfig::default(),
        );
        let Err(error) = result else {
            anyhow::bail!("transaction must refuse an existing unheld database lock")
        };
        assert!(error.to_string().contains("lock"));
        assert_eq!(std::fs::read(&lock)?, b"unheld-lock-evidence");
        assert_eq!(std::fs::metadata(&lock)?.ino(), inode);
        Ok(())
    }

    #[test]
    fn database_lock_check_preserves_an_unheld_file() {
        let directory = tempfile::tempdir().expect("database root");
        let lock = directory.path().join("db.lck");
        std::fs::write(&lock, b"").expect("stale lock");
        let error = check_database_lock(directory.path())
            .expect_err("unheld lock requires deliberate recovery");
        assert_eq!(
            error.downcast_ref::<alpm::Error>(),
            Some(&alpm::Error::HandleLock)
        );
        assert!(error.to_string().contains("refusing automatic removal"));
        assert_eq!(std::fs::read(&lock).expect("preserved lock"), b"");
    }

    #[test]
    fn database_lock_check_keeps_a_live_lease() {
        let directory = tempfile::tempdir().expect("database root");
        let lease = alpm::Alpm::new("/", directory.path().to_str().expect("utf-8 path"))
            .expect("ALPM handle");
        lease
            .trans_init(alpm::TransFlag::empty())
            .expect("live lease");
        check_database_lock(directory.path()).expect("live lock must be left in place");
        assert!(
            directory.path().join("db.lck").exists(),
            "held lock must survive inspection"
        );
        let contender = alpm::Alpm::new("/", directory.path().to_str().expect("utf-8 path"))
            .expect("second ALPM handle");
        assert_eq!(
            contender.trans_init(alpm::TransFlag::empty()),
            Err(alpm::Error::HandleLock),
            "native lease must exclude another transaction"
        );
        drop(lease);
        check_database_lock(directory.path()).expect("released lock permits another transaction");
        contender
            .trans_init(alpm::TransFlag::empty())
            .expect("second transaction acquires after legitimate release");
    }

    #[test]
    fn transaction_percent_spans_the_whole_set() {
        assert_eq!(transaction_overall_percent(50, 1, 9), 5);
        assert_eq!(transaction_overall_percent(100, 9, 9), 100);
        assert_eq!(transaction_overall_percent(40, 0, 0), 40);
        assert_eq!(transaction_overall_percent(-1, 0, 0), 0);
        assert_eq!(transaction_overall_percent(140, 0, 0), 100);
    }

    #[test]
    fn download_lane_names_in_flight_and_completed_counts() {
        assert_eq!(download_lane_message(5, 3), "5 in flight · 3 done");
        assert_eq!(download_lane_message(0, 18), "0 in flight · 18 done");
    }

    #[test]
    fn refused_replacements_fail_the_transaction_naming_the_conflict() {
        let refusals = Mutex::new(AlpmQuestionRefusals::default());
        assert!(question_refusal_error(&refusals).is_none());

        refusals
            .lock()
            .expect("unpoisoned")
            .record_refused_replacement("bar", "core", "foo");
        let error = question_refusal_error(&refusals)
            .expect("a recorded refusal must fail the transaction");
        let message = error.to_string();
        assert!(message.contains("replace bar with core/foo"), "{message}");
        assert!(
            message.contains("unconfirmed package mutation"),
            "{message}"
        );
        assert!(
            message.contains("resolve the conflict explicitly"),
            "{message}"
        );
    }

    #[test]
    fn refused_signing_key_import_is_reported_with_other_refused_changes() {
        let refusals = Mutex::new(AlpmQuestionRefusals::default());
        assert!(question_refusal_error(&refusals).is_none());
        {
            let mut recorded = refusals.lock().expect("unpoisoned");
            recorded.record_refused_key_import();
            recorded.record_refused_replacement("old", "core", "new");
        }
        let error = question_refusal_error(&refusals)
            .expect("unconfirmed trust cannot disappear behind a generic native error");
        let message = error.to_string();
        assert!(message.contains("untrusted signing key"), "{message}");
        assert!(message.contains("replace old with core/new"), "{message}");
    }

    #[test]
    fn refused_removals_fail_the_transaction_listing_the_packages() {
        let refusals = Mutex::new(AlpmQuestionRefusals::default());
        refusals
            .lock()
            .expect("unpoisoned")
            .record_refused_removals(&["dep-a".to_string(), "dep-b".to_string()]);
        let error = question_refusal_error(&refusals)
            .expect("a recorded removal refusal must fail the transaction");
        let message = error.to_string();
        assert!(
            message.contains("drop unresolvable package(s)"),
            "{message}"
        );
        assert!(message.contains("dep-a, dep-b"), "{message}");
    }

    #[test]
    #[serial_test::serial]
    fn replace_question_is_declined_instead_of_auto_accepted() {
        crate::core::privilege::set_yes_flag(false);
        // Real libalpm sysupgrade against an isolated database: a sync package
        // that replaces an installed package must NOT be auto-accepted. The
        // callback declines (libalpm skips the replacement) and records the
        // refusal so the transaction fails with a named error instead of
        // silently replacing (or silently skipping) an installed package.
        let temp = tempfile::tempdir().expect("temporary alpm root");
        let root = temp.path().join("root");
        let db_path = temp.path().join("db");
        std::fs::create_dir_all(&root).expect("root dir");
        std::fs::create_dir_all(db_path.join("local/bar-1.0-1")).expect("local pkg dir");
        std::fs::create_dir_all(db_path.join("sync")).expect("sync db dir");
        std::fs::write(db_path.join("local/ALPM_DB_VERSION"), "9\n")
            .expect("write ALPM_DB_VERSION");

        std::fs::write(
            db_path.join("local/bar-1.0-1/desc"),
            "%NAME%\nbar\n\n%VERSION%\n1.0-1\n\n",
        )
        .expect("write local desc");

        let sync_desc = "%NAME%\nfoo\n\n%VERSION%\n2.0-1\n\n%REPLACES%\nbar\n\n%ARCH%\nx86_64\n\n";
        let sync_content = format!(
            "%FILENAME%\nfoo-2.0-1-x86_64.pkg.tar.zst\n\n%CSIZE%\n1\n\n%ISIZE%\n1\n\n%PACKAGER%\nFixture Maintainer <fixture@example.invalid>\n\n{sync_desc}"
        );
        let db_file = std::fs::File::create(db_path.join("sync/core.db")).expect("core.db");
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            db_file,
            flate2::Compression::fast(),
        ));
        let mut header = tar::Header::new_gnu();
        header.set_path("foo-2.0-1/desc").expect("header path");
        header.set_size(sync_content.len() as u64);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append(&header, sync_content.as_bytes())
            .expect("append sync desc");
        builder
            .into_inner()
            .expect("finish core.db")
            .finish()
            .expect("flush gzip");

        let alpm = alpm::Alpm::new(
            root.to_str().expect("utf-8 root"),
            db_path.to_str().expect("utf-8 db path"),
        )
        .expect("ALPM handle");
        alpm.register_syncdb("core", alpm::SigLevel::NONE)
            .expect("register core");

        let refusals = std::sync::Arc::new(Mutex::new(AlpmQuestionRefusals::default()));
        let _progress = setup_alpm_callbacks(&alpm, &refusals);

        alpm.trans_init(alpm::TransFlag::NEEDED)
            .expect("init transaction");
        alpm.sync_sysupgrade(false).expect("compute sysupgrade");

        assert!(
            alpm.trans_add().is_empty(),
            "declined replacement must not add the replacing package"
        );
        let error = question_refusal_error(&refusals)
            .expect("replace question must be recorded as refused");
        assert!(error.to_string().contains("replace bar with core/foo"));
    }

    #[test]
    #[serial_test::serial]
    fn omarchy_replacements_keep_vendor_defaults_but_unattended_conflicts_refuse() {
        for (policy, yes, relationship, accepted) in [
            (super::TransactionPolicy::Standard, true, "REPLACES", true),
            (super::TransactionPolicy::Omarchy, false, "REPLACES", true),
            (super::TransactionPolicy::Omarchy, true, "CONFLICTS", false),
        ] {
            let temp = tempfile::tempdir().expect("temporary alpm root");
            let root = temp.path().join("root");
            let db_path = temp.path().join("db");
            std::fs::create_dir_all(&root).expect("root dir");
            std::fs::create_dir_all(db_path.join("local/bar-1.0-1")).expect("local pkg dir");
            std::fs::create_dir_all(db_path.join("sync")).expect("sync db dir");
            std::fs::write(db_path.join("local/ALPM_DB_VERSION"), "9\n")
                .expect("write ALPM_DB_VERSION");

            std::fs::write(
                db_path.join("local/bar-1.0-1/desc"),
                "%NAME%\nbar\n\n%VERSION%\n1.0-1\n\n",
            )
            .expect("write local desc");

            std::fs::write(
                db_path.join("local/bar-1.0-1/files"),
                "%FILES%\nusr/bin/bar\n\n",
            )
            .expect("installed file inventory");

            let sync_desc = format!(
                "%NAME%\nfoo\n\n%VERSION%\n2.0-1\n\n%{relationship}%\nbar\n\n%ARCH%\nx86_64\n\n"
            );
            let sync_content = format!(
                "%FILENAME%\nfoo-2.0-1-x86_64.pkg.tar.zst\n\n%CSIZE%\n1\n\n%ISIZE%\n1\n\n%PACKAGER%\nFixture Maintainer <fixture@example.invalid>\n\n{sync_desc}"
            );
            let db_file = std::fs::File::create(db_path.join("sync/core.db")).expect("core.db");
            let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
                db_file,
                flate2::Compression::fast(),
            ));
            let mut header = tar::Header::new_gnu();
            header.set_path("foo-2.0-1/desc").expect("header path");
            header.set_size(sync_content.len() as u64);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append(&header, sync_content.as_bytes())
                .expect("append sync desc");
            builder
                .into_inner()
                .expect("finish core.db")
                .finish()
                .expect("flush gzip");

            let mut alpm = alpm::Alpm::new(
                root.to_str().expect("utf-8 root"),
                db_path.to_str().expect("utf-8 db path"),
            )
            .expect("ALPM handle");
            alpm.register_syncdb("core", alpm::SigLevel::NONE)
                .expect("register core");

            let refusals = std::sync::Arc::new(Mutex::new(AlpmQuestionRefusals::default()));
            let _progress = super::setup_alpm_callbacks_in(&alpm, &refusals, policy);

            crate::core::privilege::set_yes_flag(yes);
            alpm.trans_init(alpm::TransFlag::NEEDED)
                .expect("init transaction");
            if relationship == "REPLACES" {
                let result = alpm.sync_sysupgrade(false);
                crate::core::privilege::set_yes_flag(false);
                result.expect("compute sysupgrade");
                assert_eq!(
                    alpm.trans_add().len(),
                    1,
                    "accepted replacement is scheduled"
                );
                assert!(question_refusal_error(&refusals).is_none());
            } else {
                let package = alpm
                    .syncdbs()
                    .iter()
                    .next()
                    .expect("core")
                    .pkg("foo")
                    .expect("sync package");
                assert!(
                    package
                        .conflicts()
                        .iter()
                        .any(|dependency| dependency.name() == "bar"),
                    "fixture declares the real package conflict"
                );
                assert!(
                    alpm.localdb().pkg("bar").is_ok(),
                    "conflicting package is installed"
                );
                alpm.trans_add_pkg(package)
                    .expect("add conflicting package");
                let prepared = alpm.trans_prepare().is_ok();
                crate::core::privilege::set_yes_flag(false);
                assert_eq!(
                    prepared, accepted,
                    "unattended conflict must not remove an installed package"
                );
                assert!(
                    alpm.trans_remove().is_empty(),
                    "refused conflict preserves the installed package"
                );
            }
        }
    }

    #[test]
    fn provider_selection_defaults_to_the_first_provider_and_names_it() {
        let message = provider_selection_message(
            &["provider-a".to_string(), "provider-b".to_string()],
            "provider-virtual",
        );
        assert!(
            message.contains("Auto-selected provider provider-a"),
            "{message}"
        );
        assert!(message.contains("1 of 2"), "{message}");
        assert!(message.contains("dependency provider-virtual"), "{message}");

        // Pacman's provider prompt lists providers sorted and defaults to the
        // first one; the auto-answer must never pick a different index.
        let single = provider_selection_message(&["only".to_string()], "dep");
        assert!(single.contains("provider only (1 of 1)"), "{single}");
    }

    #[test]
    fn alpm_warnings_and_errors_are_not_classified_as_debug_output() {
        assert_eq!(
            classify_alpm_log_level(alpm::LogLevel::ERROR | alpm::LogLevel::WARNING),
            ForwardedAlpmLogLevel::Error
        );
        assert_eq!(
            classify_alpm_log_level(alpm::LogLevel::WARNING),
            ForwardedAlpmLogLevel::Warning
        );
        assert_eq!(
            classify_alpm_log_level(alpm::LogLevel::DEBUG),
            ForwardedAlpmLogLevel::Debug
        );
        assert_eq!(
            classify_alpm_log_level(alpm::LogLevel::FUNCTION),
            ForwardedAlpmLogLevel::Trace
        );
    }

    #[test]
    fn transaction_registration_rejects_partial_repository_sets() {
        let database_path = tempfile::tempdir().expect("temporary database path");
        let database_path = database_path.path().to_string_lossy();
        let alpm = alpm::Alpm::new("/", database_path.as_ref()).expect("ALPM handle");
        alpm.register_syncdb("core", alpm::SigLevel::NONE)
            .expect("initial sync database");
        let config = crate::core::pacman_conf::PacmanConfig {
            repos: vec![crate::core::pacman_conf::RepoConfig {
                name: "core".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };

        let error = register_configured_syncdbs(&alpm, &config)
            .expect_err("a failed configured repository must abort registration");
        assert!(
            error
                .to_string()
                .contains("refusing a partial repository set")
        );
    }

    #[test]
    fn mirror_configuration_requires_at_least_one_usable_server() {
        let database_path = tempfile::tempdir().expect("temporary database path");
        let database_path = database_path.path().to_string_lossy();
        let mut alpm = alpm::Alpm::new("/", database_path.as_ref()).expect("ALPM handle");
        alpm.register_syncdb_mut("core", alpm::SigLevel::NONE)
            .expect("register sync database");

        assert!(ensure_mirror_servers(&alpm).is_err());
        alpm.syncdbs_mut()
            .into_iter()
            .next()
            .expect("registered sync database")
            .add_server("https://mirror.example/$repo/os/$arch")
            .expect("add test mirror");
        assert!(ensure_mirror_servers(&alpm).is_ok());
    }

    #[test]
    fn mirror_configuration_preserves_the_registered_repository_set() -> anyhow::Result<()> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        const TEST: &str = "package_managers::alpm_ops::tests::mirror_configuration_preserves_the_registered_repository_set";
        if crate::core::testing::run_isolated_test(TEST)
            || crate::config::Settings::rerun_test_unprivileged(TEST)
        {
            return Ok(());
        }
        assert!(
            !crate::core::is_root(),
            "mirror configuration overrides require an ordinary UID"
        );
        let owner = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let root = owner.path().join("root");
        let database = owner.path().join("db");
        for directory in [&root, &database] {
            std::fs::DirBuilder::new().mode(0o700).create(directory)?;
        }
        let mirror = owner.path().join("mirror");
        let configuration = owner.path().join("pacman.conf");
        std::fs::write(
            &configuration,
            format!(
                "[options]\n[core]\nServer = file://{}/$repo/os/$arch\n\n[configured-only]\nServer = file://{}/$repo/os/$arch\n",
                mirror.display(),
                mirror.display()
            ),
        )
        .expect("write private mirror configuration");
        let mut alpm = alpm::Alpm::new(
            root.to_str().expect("private root path"),
            database.to_str().expect("private database path"),
        )
        .expect("open the private mirror fixture database");
        alpm.register_syncdb_mut("core", alpm::SigLevel::NONE)?;
        assert!(ensure_mirror_servers(&alpm).is_err());
        temp_env::with_var("OMG_PACMAN_CONF", Some(&configuration), || {
            super::configure_mirrors(&mut alpm)
        })?;

        let databases: Vec<_> = alpm.syncdbs().into_iter().collect();
        assert_eq!(
            databases.len(),
            1,
            "configuring mirrors must not register an additional database"
        );
        let core = databases.first().expect("registered core database");
        assert_eq!(core.name(), "core");
        let expected = format!(
            "file://{}/core/os/{}",
            mirror.display(),
            std::env::consts::ARCH
        );
        assert_eq!(
            core.servers().into_iter().collect::<Vec<_>>(),
            vec![expected.as_str()]
        );
        ensure_mirror_servers(&alpm)?;
        Ok(())
    }

    #[test]
    fn pacman_signature_policy_is_applied_to_handle_and_repositories() {
        let config = crate::core::pacman_conf::PacmanConfig::parse_str(
            "[options]\nSigLevel = Required DatabaseOptional\nLocalFileSigLevel = PackageOptional\nRemoteFileSigLevel = PackageNever\n\n[core]\nSigLevel = PackageOptional DatabaseNever\n",
        )
        .expect("signature configuration");
        let policy = signature_policy(&config).expect("parsed signature policy");

        assert!(policy.default.contains(alpm::SigLevel::PACKAGE));
        assert!(policy.default.contains(alpm::SigLevel::DATABASE));
        assert!(policy.default.contains(alpm::SigLevel::DATABASE_OPTIONAL));
        assert!(policy.local_file.contains(alpm::SigLevel::PACKAGE));
        assert!(policy.local_file.contains(alpm::SigLevel::PACKAGE_OPTIONAL));
        assert!(!policy.remote_file.contains(alpm::SigLevel::PACKAGE));

        let repository = repository_siglevel(policy.default, config.repos[0].sig_level.as_deref())
            .expect("repository signature policy");
        assert!(repository.contains(alpm::SigLevel::PACKAGE));
        assert!(repository.contains(alpm::SigLevel::PACKAGE_OPTIONAL));
        assert!(!repository.contains(alpm::SigLevel::DATABASE));

        let database_path = tempfile::tempdir().expect("temporary database path");
        let database_path = database_path.path().to_string_lossy();
        let mut alpm = alpm::Alpm::new("/", database_path.as_ref()).expect("ALPM handle");
        configure_signature_policy(&mut alpm, &config).expect("configure ALPM policy");
        assert_eq!(alpm.default_siglevel(), policy.default);
        assert_eq!(alpm.local_file_siglevel(), policy.local_file);
        assert_eq!(alpm.remote_file_siglevel(), policy.remote_file);
    }

    #[test]
    fn invalid_pacman_signature_policy_fails_closed() {
        let config = crate::core::pacman_conf::PacmanConfig::parse_str(
            "[options]\nSigLevel = PackageSometimes\n",
        )
        .expect("syntax parser preserves policy text");
        let error = signature_policy(&config).expect_err("unknown policy must fail");
        assert!(error.to_string().contains("PackageSometimes"), "{error:#}");
    }

    #[test]
    fn aur_artifacts_allow_missing_signatures_but_verify_present_ones() {
        let configured = alpm::SigLevel::PACKAGE | alpm::SigLevel::PACKAGE_UNKNOWN_OK;
        let regular = local_package_siglevel(TransactionKind::Install, configured);
        assert_eq!(regular, configured);

        let aur = local_package_siglevel(TransactionKind::InstallAurArtifact, configured);
        assert!(aur.contains(alpm::SigLevel::PACKAGE));
        assert!(aur.contains(alpm::SigLevel::PACKAGE_OPTIONAL));
    }

    #[test]
    fn hold_pkg_patterns_cover_explicit_and_cascade_removals() {
        let patterns = vec!["linux".to_string(), "kde-*".to_string()];

        ensure_removals_not_held(["bash"], &patterns).expect("unheld package");
        let explicit = ensure_removals_not_held(["linux"], &patterns)
            .expect_err("explicit HoldPkg entry must be rejected");
        assert!(explicit.to_string().contains("HoldPkg pattern 'linux'"));
        let cascade = ensure_removals_not_held(["kde-libs"], &patterns)
            .expect_err("glob-protected cascade must be rejected");
        assert!(cascade.to_string().contains("HoldPkg pattern 'kde-*'"));
    }

    #[test]
    fn hold_pkg_patterns_follow_pacman_literal_braces_and_brackets() {
        ensure_removals_not_held(["widget-git"], &["widget{,-git}".to_owned()])
            .expect("pacman does not expand brace alternatives");
        let error = ensure_removals_not_held(["widget["], &["widget[".to_owned()])
            .expect_err("unmatched bracket is a literal protected name");
        assert!(
            error
                .to_string()
                .starts_with("Package 'widget[' is protected by HoldPkg pattern 'widget['")
        );
    }

    #[test]
    fn installable_repository_fixture_passes_native_metadata_admission() -> anyhow::Result<()> {
        let fixture = RepositoryFixture::new()?;
        fixture.write_sync("core", &[("fixture", "1-1", "")])?;
        let root = fixture.directory.path().join("root");
        let mut alpm = super::open_alpm_at(&root, &fixture.database())?;
        let repository = alpm.register_syncdb("core", alpm::SigLevel::NONE)?;
        alpm.trans_init(alpm::TransFlag::NEEDED)?;
        alpm.trans_add_pkg(repository.pkg("fixture")?)
            .map_err(|error| anyhow::anyhow!("Cannot select fixture package: {error}"))?;
        let prepared = super::prepared_advisory_packages(
            &alpm,
            TransactionKind::Install,
            &crate::core::security::SecurityPolicy::default(),
            &[],
            None,
        );
        alpm.trans_release()?;
        assert_eq!(
            prepared?.len(),
            1,
            "installable fixtures satisfy signing metadata checks"
        );
        Ok(())
    }

    #[test]
    fn prepared_repository_metadata_requires_a_packager_before_native_key_import()
    -> anyhow::Result<()> {
        for packager in [None, Some("Fixture Maintainer <fixture@example.invalid>")] {
            let owner = tempfile::tempdir()?;
            let root = owner.path().join("root");
            let database = owner.path().join("db");
            std::fs::create_dir(&root)?;
            std::fs::create_dir_all(database.join("local"))?;
            std::fs::create_dir(database.join("sync"))?;
            std::fs::write(database.join("local/ALPM_DB_VERSION"), "9\n")?;
            let mut content = "%NAME%\nfixture\n\n%VERSION%\n1-1\n\n%ARCH%\nany\n\n%FILENAME%\nfixture-1-1-any.pkg.tar.gz\n\n%CSIZE%\n1\n\n%ISIZE%\n1\n\n".to_owned();
            if let Some(packager) = packager {
                content.push_str("%PACKAGER%\n");
                content.push_str(packager);
                content.push_str("\n\n");
            }
            let compressed = flate2::write::GzEncoder::new(
                std::fs::File::create(database.join("sync/core.db"))?,
                flate2::Compression::fast(),
            );
            let mut archive = tar::Builder::new(compressed);
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(&mut header, "fixture-1-1/desc", content.as_bytes())?;
            archive.into_inner()?.finish()?;
            let mut alpm = super::open_alpm_at(&root, &database)?;
            let repository = alpm.register_syncdb("core", alpm::SigLevel::NONE)?;
            alpm.trans_init(alpm::TransFlag::NEEDED)?;
            alpm.trans_add_pkg(repository.pkg("fixture")?)
                .map_err(|error| anyhow::anyhow!("Cannot add fixture package: {error}"))?;
            let result = super::prepared_advisory_packages(
                &alpm,
                TransactionKind::Install,
                &crate::core::security::SecurityPolicy::default(),
                &[],
                None,
            );
            alpm.trans_release()?;
            if packager.is_some() {
                assert_eq!(result?.len(), 1, "complete repository record is accepted");
            } else {
                let error =
                    result.expect_err("Missing PACKAGER must fail before C key-import code");
                assert!(error.to_string().contains("PACKAGER"), "{error:#}");
            }
            assert!(
                !database.join("db.lck").exists(),
                "validation releases the private transaction lock"
            );
        }
        Ok(())
    }

    #[test]
    fn signature_readers_use_the_configured_keyring() -> anyhow::Result<()> {
        let owner = tempfile::tempdir()?;
        let root = owner.path().join("root");
        let database = owner.path().join("db");
        let keyring = owner.path().join("configured-keys");
        for path in [&root, &database, &keyring] {
            std::fs::create_dir(path)?;
        }
        let mut alpm = super::open_alpm_at(&root, &database)?;
        let config = crate::core::pacman_conf::PacmanConfig {
            gpg_dir: Some(keyring.to_str().expect("fixture UTF-8").to_owned()),
            ..Default::default()
        };
        configure_signature_policy(&mut alpm, &config)?;
        assert_eq!(
            alpm.gpgdir().map(std::path::Path::new),
            Some(keyring.as_path()),
            "Read-only validation must use the same configured trust store as transactions"
        );
        Ok(())
    }

    #[test]
    fn signature_readers_reject_nul_keyring_paths_without_panicking() -> anyhow::Result<()> {
        let owner = tempfile::tempdir()?;
        let mut alpm = super::open_alpm_at(owner.path(), owner.path())?;
        let config = crate::core::pacman_conf::PacmanConfig {
            gpg_dir: Some("/configured/keyring\0alias".to_owned()),
            ..Default::default()
        };
        let error = configure_signature_policy(&mut alpm, &config)
            .expect_err("NUL keyring paths cannot reach the C-string boundary");
        assert!(error.to_string().contains("NUL"), "{error:#}");
        Ok(())
    }

    #[test]
    fn invalid_hold_pkg_patterns_fail_closed() {
        let error = ensure_removals_not_held(["anything"], &["held\0".to_string()])
            .expect_err("invalid HoldPkg patterns must not be ignored");
        assert!(error.to_string().contains("Invalid HoldPkg pattern"));
    }

    #[test]
    fn system_upgrade_rejects_targets_instead_of_discarding_them() {
        validate_transaction_targets(TransactionKind::SystemUpgrade, &[])
            .expect("targetless system upgrade");
        let error = validate_transaction_targets(
            TransactionKind::SystemUpgrade,
            &["explicit-target".to_string()],
        )
        .expect_err("explicit target must not be silently discarded");
        assert!(error.to_string().contains("explicit package targets"));
        validate_transaction_targets(TransactionKind::Install, &["package".to_string()])
            .expect("install accepts targets");
    }

    #[test]
    fn recursive_removal_matches_pacman_rs_flags() {
        let explicit = transaction_flags(TransactionKind::Remove { recursive: false });
        assert!(!explicit.contains(alpm::TransFlag::RECURSE));
        assert!(!explicit.contains(alpm::TransFlag::UNNEEDED));

        let recursive = transaction_flags(TransactionKind::Remove { recursive: true });
        assert!(recursive.contains(alpm::TransFlag::RECURSE));
        assert!(!recursive.contains(alpm::TransFlag::UNNEEDED));
    }

    #[test]
    fn base_name_parses_simple_and_dash_containing_pkgbases() {
        assert_eq!(
            package_base_name("linux-6.7.0-1-x86_64.pkg.tar.zst"),
            Some("linux")
        );
        // Regression: pkgbases containing dashes must stay one group.
        assert_eq!(
            package_base_name("python-pip-24.0-1-any.pkg.tar.zst"),
            Some("python-pip")
        );
        assert_eq!(
            package_base_name("haskell-aeson-2.1.2.1-269-x86_64.pkg.tar.zst"),
            Some("haskell-aeson")
        );
        assert_eq!(
            package_base_name("foo-1.2-2-x86_64.pkg.tar.xz"),
            Some("foo")
        );
        assert_eq!(
            package_base_name("linux-6.7.0-1-x86_64.pkg.tar.gz"),
            Some("linux")
        );
        assert_eq!(
            package_base_name("foo-1.2-2-x86_64.pkg.tar.bz2"),
            Some("foo")
        );
        assert_eq!(
            package_base_name("lib32-mesa-1:24.0.1-1-x86_64.pkg.tar.zst"),
            Some("lib32-mesa")
        );
    }

    #[test]
    fn base_name_rejects_unexpected_shapes() {
        assert_eq!(package_base_name("not-a-package-file.tar.zst"), None);
        assert_eq!(package_base_name("linux-6.7.0-1-x86_64.zip"), None);
        assert_eq!(package_base_name("-1-2-x86_64.pkg.tar.zst"), None);
    }

    #[test]
    fn clean_cache_keeps_two_distinct_versions_per_architecture_across_cache_copies()
    -> anyhow::Result<()> {
        const NAME: &str = "package_managers::alpm_ops::tests::clean_cache_keeps_two_distinct_versions_per_architecture_across_cache_copies";
        if crate::core::testing::run_isolated_test(NAME)
            || crate::config::Settings::rerun_test_unprivileged(NAME)
        {
            return Ok(());
        }
        assert!(!crate::core::is_root());
        let owner = tempfile::tempdir()?;
        let first = owner.path().join("first");
        let second = owner.path().join("second");
        std::fs::create_dir(&first)?;
        std::fs::create_dir(&second)?;
        let alias = owner.path().join("first-alias");
        std::os::unix::fs::symlink(&first, &alias)?;
        let mut archives = Vec::new();
        for architecture in ["x86_64", "aarch64", "any"] {
            for (directory, version, suffix, group) in [
                (&first, "1.10.0-1", "zst", "newest"),
                (&first, "1.10.0-1", "xz", "newest"),
                (&second, "1.10.0-1", "zst", "newest"),
                (&second, "1.10.0-01", "bz2", "newest"),
                (&first, "1.2.0-1", "gz", "spare"),
                (&first, "1.0.0-1", "zst", "obsolete"),
                (&second, "1.0.0-1", "xz", "spare"),
                (&second, "0.9.0-1", "zst", "obsolete"),
            ] {
                let path =
                    directory.join(format!("testpkg-{version}-{architecture}.pkg.tar.{suffix}"));
                let data = format!("inert {architecture} {version} {suffix}").into_bytes();
                let signature =
                    format!("inert signature {architecture} {version} {suffix}").into_bytes();
                std::fs::write(&path, &data)?;
                std::fs::write(path.with_added_extension("sig"), &signature)?;
                archives.push((path, architecture, group, data, signature));
            }
        }
        assert_eq!(
            alpm::vercmp("1.10.0-1", "1.10.0-01"),
            std::cmp::Ordering::Equal
        );
        let config = owner.path().join("pacman.conf");
        std::fs::write(
            &config,
            format!(
                "[options]\nCacheDir = {} {} {}\n",
                first.display(),
                second.display(),
                alias.display()
            ),
        )?;
        temp_env::with_vars(
            [
                ("OMG_PACMAN_CONF", Some(config.as_os_str())),
                ("OMG_PACMAN_CACHE_DIR", None),
                ("OMG_PACMAN_ROOT", None),
            ],
            || -> anyhow::Result<()> {
                paths::reset_test_overrides();
                let preview = clean_cache_preview(2)?;
                for (path, _, _, data, signature) in &archives {
                    assert_eq!(std::fs::read(path)?, *data, "preview changed archive bytes");
                    assert_eq!(
                        std::fs::read(path.with_added_extension("sig"))?,
                        *signature,
                        "preview changed signature bytes"
                    );
                }
                let cleaned = clean_cache(2)?;
                for architecture in ["x86_64", "aarch64", "any"] {
                    let retained = archives
                        .iter()
                        .filter(|(path, arch, _, _, _)| *arch == architecture && path.is_file())
                        .map(|(_, _, group, _, _)| *group)
                        .collect::<std::collections::BTreeSet<_>>();
                    assert_eq!(
                        retained,
                        std::collections::BTreeSet::from(["newest", "spare"]),
                        "keep=2 must retain two distinct ALPM versions for {architecture}, despite duplicate files/formats/cache directories"
                    );
                }
                let mut removed = 0;
                let mut freed = 0;
                for (path, _, group, data, signature) in &archives {
                    assert_eq!(
                        path.is_file(),
                        *group != "obsolete",
                        "every archive of a retained version must survive: {}",
                        path.display()
                    );
                    if path.is_file() {
                        assert_ne!(*group, "obsolete");
                        assert_eq!(std::fs::read(path)?, *data);
                        assert_eq!(std::fs::read(path.with_added_extension("sig"))?, *signature);
                    } else {
                        assert!(
                            !path.with_added_extension("sig").exists(),
                            "removed archive left its signature"
                        );
                        removed += 1;
                        freed += (data.len() + signature.len()) as u64;
                    }
                }
                assert_eq!(preview, (removed, freed));
                assert_eq!(
                    cleaned,
                    (removed * 2, freed),
                    "cleanup counts archives and their signatures; preview counts archives"
                );
                assert_eq!(clean_cache_preview(2)?, (0, 0));
                assert_eq!(clean_cache(2)?, (0, 0));
                Ok(())
            },
        )
    }

    #[test]
    fn native_factory_rejects_non_utf8_paths_instead_of_opening_lossy_aliases() -> anyhow::Result<()>
    {
        use std::os::unix::ffi::OsStringExt;

        const NAME: &str = "package_managers::alpm_ops::tests::native_factory_rejects_non_utf8_paths_instead_of_opening_lossy_aliases";
        if crate::core::testing::run_isolated_test(NAME)
            || crate::config::Settings::rerun_test_unprivileged(NAME)
        {
            return Ok(());
        }
        assert!(!crate::core::is_root());
        let owner = tempfile::tempdir()?;
        let root = owner.path().join("root");
        let database = owner.path().join("database");
        let byte_root = owner
            .path()
            .join(std::ffi::OsString::from_vec(b"root-\xff".to_vec()));
        let byte_database = owner
            .path()
            .join(std::ffi::OsString::from_vec(b"database-\xff".to_vec()));
        let alias_root = owner.path().join("root-\u{fffd}");
        let alias_database = owner.path().join("database-\u{fffd}");
        for path in [&root, &byte_root, &alias_root] {
            std::fs::create_dir(path)?;
        }
        for path in [&database, &byte_database, &alias_database] {
            std::fs::create_dir_all(path.join("local"))?;
            std::fs::create_dir(path.join("sync"))?;
            std::fs::write(path.join("local/ALPM_DB_VERSION"), b"9\n")?;
        }
        let sentinel = alias_database.join("local/alias-only-99-1/desc");
        std::fs::create_dir(sentinel.parent().expect("private sentinel parent"))?;
        let sentinel_bytes = b"%NAME%\nalias-only\n\n%VERSION%\n99-1\n\n%REASON%\n0\n\n";
        std::fs::write(&sentinel, sentinel_bytes)?;
        let config = owner.path().join("pacman.conf");
        std::fs::write(&config, "[options]\nSigLevel = Never\n")?;
        temp_env::with_vars(
            [
                ("OMG_PACMAN_CONF", Some(config.as_os_str())),
                ("OMG_PACMAN_ROOT", Some(root.as_os_str())),
                ("OMG_PACMAN_DB_DIR", Some(database.as_os_str())),
            ],
            || -> anyhow::Result<()> {
                paths::reset_test_overrides();
                assert!(super::open_default_alpm()?.localdb().pkgs().is_empty());
                let mut outcomes = Vec::new();
                for (field, selected_root, selected_database) in [
                    ("root", &byte_root, &database),
                    ("database", &root, &byte_database),
                ] {
                    let outcome = temp_env::with_vars(
                        [
                            ("OMG_PACMAN_ROOT", Some(selected_root.as_os_str())),
                            ("OMG_PACMAN_DB_DIR", Some(selected_database.as_os_str())),
                        ],
                        || match super::open_default_alpm() {
                            Ok(handle) => Err(handle
                                .localdb()
                                .pkgs()
                                .iter()
                                .map(|package| package.name().to_owned())
                                .collect::<Vec<_>>()),
                            Err(error) => Ok(format!("{error:#}")),
                        },
                    );
                    outcomes.push((field, outcome));
                }
                assert_eq!(std::fs::read(&sentinel)?, sentinel_bytes);
                assert!(!alias_database.join("db.lck").exists());
                for (field, outcome) in outcomes {
                    let diagnostic = outcome.unwrap_or_else(|packages| panic!("non-UTF8 {field} must refuse instead of opening a replacement-character alias; native packages: {packages:?}"));
                    assert!(
                        diagnostic.to_ascii_lowercase().contains("utf-8"),
                        "{field}: {diagnostic}"
                    );
                }
                Ok(())
            },
        )
    }

    #[test]
    fn native_factory_rejects_nul_config_paths_without_unwinding() -> anyhow::Result<()> {
        const NAME: &str = "package_managers::alpm_ops::tests::native_factory_rejects_nul_config_paths_without_unwinding";
        if crate::core::testing::run_isolated_test(NAME)
            || crate::config::Settings::rerun_test_unprivileged(NAME)
        {
            return Ok(());
        }
        assert!(!crate::core::is_root());
        let owner = tempfile::tempdir()?;
        let root = owner.path().join("root");
        let database = owner.path().join("database");
        std::fs::create_dir(&root)?;
        std::fs::create_dir_all(database.join("local"))?;
        std::fs::create_dir(database.join("sync"))?;
        std::fs::write(database.join("local/ALPM_DB_VERSION"), b"9\n")?;
        let config = owner.path().join("pacman.conf");
        temp_env::with_vars(
            [
                ("OMG_PACMAN_CONF", Some(config.as_os_str())),
                ("OMG_PACMAN_ROOT", None),
                ("OMG_PACMAN_DB_DIR", None),
            ],
            || -> anyhow::Result<()> {
                paths::reset_test_overrides();
                let valid = format!(
                    "[options]\nRootDir = {}\nDBPath = {}\nSigLevel = Never\n",
                    root.display(),
                    database.display()
                );
                std::fs::write(&config, &valid)?;
                assert!(super::open_default_alpm()?.localdb().pkgs().is_empty());
                let mut outcomes = Vec::new();
                for (field, bad) in [
                    ("RootDir", format!("{}\0invalid", root.display())),
                    ("DBPath", format!("{}\0invalid", database.display())),
                ] {
                    let contents = valid
                        .lines()
                        .map(|line| {
                            if line.starts_with(field) {
                                format!("{field} = {bad}")
                            } else {
                                line.to_owned()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                        + "\n";
                    std::fs::write(&config, contents)?;
                    let result = std::panic::catch_unwind(super::open_default_alpm);
                    let (panicked, diagnostic) = match result {
                        Ok(Err(error)) => (false, Some(format!("{error:#}"))),
                        Ok(Ok(_)) => (false, None),
                        Err(_) => (true, None),
                    };
                    outcomes.push((field, panicked, diagnostic));
                }
                for (field, panicked, diagnostic) in outcomes {
                    assert!(
                        !panicked,
                        "NUL-bearing {field} configuration must return an error instead of unwinding in the native constructor"
                    );
                    let diagnostic = diagnostic.expect("NUL-bearing configuration must refuse");
                    assert!(
                        diagnostic.to_ascii_lowercase().contains("nul"),
                        "{field}: {diagnostic}"
                    );
                }
                Ok(())
            },
        )
    }

    #[test]
    fn clean_cache_keeps_the_newest_archive_with_duplicate_directory_aliases() {
        const TEST: &str = "package_managers::alpm_ops::tests::clean_cache_keeps_the_newest_archive_with_duplicate_directory_aliases";
        if crate::core::testing::run_isolated_test(TEST)
            || crate::config::Settings::rerun_test_unprivileged(TEST)
        {
            return;
        }
        assert!(
            !crate::core::is_root(),
            "cache configuration overrides require an unprivileged caller"
        );
        let owner = tempfile::tempdir().expect("private cache owner");
        let cache = owner.path().join("cache");
        std::fs::create_dir(&cache).expect("private cache");
        let alias = owner.path().join("cache-alias");
        std::os::unix::fs::symlink(&cache, &alias).expect("private cache alias");
        let old = cache.join("demo-1.0-1-x86_64.pkg.tar.zst");
        let current = cache.join("demo-2.0-1-x86_64.pkg.tar.zst");
        std::fs::write(&old, b"old").expect("old archive");
        std::fs::write(&current, b"new").expect("current archive");
        let config = owner.path().join("pacman.conf");
        std::fs::write(
            &config,
            format!(
                "[options]\nCacheDir = {} {} {} {}\n",
                cache.display(),
                cache.display(),
                cache.join(".").display(),
                alias.display()
            ),
        )
        .expect("private cache configuration");
        temp_env::with_vars(
            [
                (
                    "OMG_PACMAN_CONF",
                    Some(config.to_str().expect("configuration path")),
                ),
                ("OMG_PACMAN_CACHE_DIR", None),
                ("OMG_PACMAN_ROOT", None),
            ],
            || {
                paths::reset_test_overrides();
                assert_eq!(clean_cache_preview(1).expect("preview"), (1, 3));
                assert!(
                    old.is_file() && current.is_file(),
                    "preview mutated the cache"
                );
                assert_eq!(clean_cache(1).expect("cleanup"), (1, 3));
                assert!(!old.exists());
                assert_eq!(std::fs::read(&current).expect("retained archive"), b"new");
            },
        );
    }

    #[test]
    fn clean_cache_distinguishes_missing_and_inaccessible_directories() {
        use std::os::unix::fs::PermissionsExt;

        const TEST: &str = "package_managers::alpm_ops::tests::clean_cache_distinguishes_missing_and_inaccessible_directories";
        if crate::core::testing::run_isolated_test(TEST)
            || crate::config::Settings::rerun_test_unprivileged(TEST)
        {
            return;
        }
        assert!(
            !crate::core::is_root(),
            "permission checks require an ordinary UID"
        );
        let owner = tempfile::tempdir().expect("private cache owner");
        let cache = owner.path().join("cache");
        let blocked = owner.path().join("blocked");
        let hidden = blocked.join("cache");
        let missing = owner.path().join("missing");
        std::fs::create_dir(&cache).expect("private healthy cache");
        std::fs::create_dir_all(&hidden).expect("private inaccessible cache");
        let old = cache.join("demo-1.0-1-x86_64.pkg.tar.zst");
        let current = cache.join("demo-2.0-1-x86_64.pkg.tar.zst");
        let signature = old.with_added_extension("sig");
        std::fs::write(&old, b"old").expect("old archive");
        std::fs::write(&current, b"new").expect("current archive");
        let config = owner.path().join("pacman.conf");
        temp_env::with_vars(
            [
                (
                    "OMG_PACMAN_CONF",
                    Some(config.to_str().expect("private config path")),
                ),
                ("OMG_PACMAN_CACHE_DIR", None),
                ("OMG_PACMAN_ROOT", None),
            ],
            || {
                paths::reset_test_overrides();
                std::fs::write(
                    &config,
                    format!(
                        "[options]\nCacheDir = {} {}\n",
                        cache.display(),
                        missing.display()
                    ),
                )
                .expect("missing cache configuration");
                assert_eq!(
                    clean_cache(1).expect("missing directories are harmless"),
                    (1, 3)
                );
                assert!(!old.exists());
                assert_eq!(std::fs::read(&current).expect("retained archive"), b"new");
                std::fs::write(&old, b"old").expect("restore private old archive");
                std::fs::write(&signature, b"sig").expect("private signature");
                std::fs::write(
                    &config,
                    format!(
                        "[options]\nCacheDir = {} {}\n",
                        cache.display(),
                        hidden.display()
                    ),
                )
                .expect("inaccessible cache configuration");
                let restore = scopeguard::guard(blocked.clone(), |path| {
                    let result =
                        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
                    eprintln!("Private cache permission restoration: {result:?}");
                });
                std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o0))
                    .expect("private permission fault");
                let result = clean_cache(1);
                drop(restore);
                let error = result.expect_err(
                    "an unreadable configured cache must abort before deleting archives",
                );
                assert!(
                    error.chain().any(|cause| cause
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|cause| cause.kind() == std::io::ErrorKind::PermissionDenied)),
                    "{error:#}"
                );
                assert_eq!(std::fs::read(&old).expect("preserved old archive"), b"old");
                assert_eq!(
                    std::fs::read(&signature).expect("preserved signature"),
                    b"sig"
                );
                assert_eq!(
                    std::fs::read(&current).expect("preserved current archive"),
                    b"new"
                );
            },
        );
    }

    #[test]
    fn clean_cache_preserves_non_regular_entries_and_their_signatures() {
        if crate::core::testing::run_isolated_test(
            "package_managers::alpm_ops::tests::clean_cache_preserves_non_regular_entries_and_their_signatures",
        ) {
            return;
        }
        temp_env::with_var_unset("OMG_PACMAN_CACHE_DIR", || {
            let owner = tempfile::tempdir().expect("private cache owner");
            let cache = owner.path().join("var/cache/pacman/pkg");
            std::fs::create_dir_all(&cache).expect("private cache");
            let old = cache.join("demo-1.0-1-x86_64.pkg.tar.zst");
            let current = cache.join("demo-2.0-1-x86_64.pkg.tar.zst");
            let directory = cache.join("demo-99.0-1-x86_64.pkg.tar.zst");
            let link = cache.join("demo-100.0-1-x86_64.pkg.tar.zst");
            let external = owner.path().join("outside-cache");
            std::fs::write(&old, b"old").expect("old archive");
            std::fs::write(&current, b"new").expect("current archive");
            std::fs::write(&external, b"owner data").expect("private symlink target");
            std::fs::create_dir(&directory).expect("package-shaped directory");
            std::fs::write(directory.with_added_extension("sig"), b"keep-signature")
                .expect("directory companion");
            std::os::unix::fs::symlink(&external, &link).expect("package-shaped symlink");
            paths::set_test_overrides(Some(owner.path().to_path_buf()), None);
            assert_eq!(clean_cache_preview(1).expect("preview"), (1, 3));
            assert_eq!(clean_cache(1).expect("cleanup"), (1, 3));
            paths::reset_test_overrides();
            assert!(!old.exists());
            assert_eq!(std::fs::read(&current).expect("retained archive"), b"new");
            assert!(directory.is_dir());
            assert!(link.is_symlink());
            assert_eq!(std::fs::read(external).expect("owner data"), b"owner data");
            assert_eq!(
                std::fs::read(directory.with_added_extension("sig")).expect("directory companion"),
                b"keep-signature"
            );
        });
    }

    #[test]
    fn failed_cache_archive_removal_preserves_its_signature() {
        let owner = tempfile::tempdir().expect("private removal owner");
        let archive = owner.path().join("demo-1.0-1-x86_64.pkg.tar.zst");
        std::fs::create_dir(&archive).expect("archive unlink failure fixture");
        let signature = archive.with_added_extension("sig");
        std::fs::write(&signature, b"preserve").expect("signature fixture");
        let mut removed = 0;
        assert_eq!(
            super::remove_cache_file_and_signature(&archive, &mut removed),
            0
        );
        assert_eq!(removed, 0);
        assert_eq!(
            std::fs::read(signature).expect("preserved signature"),
            b"preserve"
        );
        assert!(archive.is_dir());
    }

    #[test]
    fn clean_cache_preview_counts_detached_signature_bytes() {
        if crate::core::testing::run_isolated_test(
            "package_managers::alpm_ops::tests::clean_cache_preview_counts_detached_signature_bytes",
        ) {
            return;
        }
        temp_env::with_var_unset("OMG_PACMAN_CACHE_DIR", || {
            let temp = tempfile::tempdir().expect("private cache fixture");
            let cache = temp.path().join("var/cache/pacman/pkg");
            std::fs::create_dir_all(&cache).expect("create cache");
            let old = cache.join("demo-1.0-1-x86_64.pkg.tar.zst");
            let old_signature = old.with_added_extension("sig");
            let current = cache.join("demo-2.0-1-x86_64.pkg.tar.zst");
            let current_signature = current.with_added_extension("sig");
            std::fs::write(&old, b"old").expect("old archive");
            std::fs::write(&old_signature, b"sig").expect("old signature");
            std::fs::write(&current, b"current").expect("current archive");
            std::fs::write(&current_signature, b"current-signature").expect("current signature");
            paths::set_test_overrides(Some(temp.path().to_path_buf()), None);

            let preview = clean_cache_preview(1).expect("preview");
            assert_eq!(std::fs::read(&old).unwrap(), b"old");
            assert_eq!(std::fs::read(&old_signature).unwrap(), b"sig");
            assert_eq!(std::fs::read(&current).unwrap(), b"current");
            assert_eq!(
                std::fs::read(&current_signature).unwrap(),
                b"current-signature"
            );
            assert_eq!(preview, (1, 6), "preview must include companion bytes");

            let cleaned = clean_cache(1).expect("cleanup");
            paths::reset_test_overrides();
            assert_eq!(cleaned, (2, 6));
            assert!(!old.exists());
            assert!(!old_signature.exists());
            assert_eq!(std::fs::read(&current).unwrap(), b"current");
            assert_eq!(
                std::fs::read(&current_signature).unwrap(),
                b"current-signature"
            );
        });
    }

    #[test]
    fn clean_cache_sorts_by_alpm_vercmp_and_keeps_newest_version() {
        if crate::core::testing::run_isolated_test(
            "package_managers::alpm_ops::tests::clean_cache_sorts_by_alpm_vercmp_and_keeps_newest_version",
        ) {
            return;
        }
        temp_env::with_var_unset("OMG_PACMAN_CACHE_DIR", || {
            let temp = tempfile::tempdir().expect("tempdir");
            let cache_dir = temp.path().join("var/cache/pacman/pkg");
            std::fs::create_dir_all(&cache_dir).expect("create cache dir");

            // Write packages with version numbers where alphabetical/mtime sorting differs from vercmp:
            // 1.10.0-1 is newer than 1.2.0-1 and 1.0.0-1
            let v1_0 = cache_dir.join("testpkg-1.0.0-1-x86_64.pkg.tar.zst");
            let v1_2 = cache_dir.join("testpkg-1.2.0-1-x86_64.pkg.tar.zst");
            let v1_10 = cache_dir.join("testpkg-1.10.0-1-x86_64.pkg.tar.zst");

            std::fs::write(&v1_0, b"content-1.0").expect("write v1.0");
            std::fs::write(&v1_2, b"content-1.2").expect("write v1.2");
            std::fs::write(&v1_10, b"content-1.10").expect("write v1.10");

            paths::set_test_overrides(Some(temp.path().to_path_buf()), None);

            let (preview_removed, preview_freed) =
                clean_cache_preview(1).expect("preview succeeds");
            assert_eq!(
                preview_removed, 2,
                "preview should identify 2 older versions"
            );
            assert_eq!(
                preview_freed, 22,
                "preview should count freed bytes accurately"
            );
            assert!(v1_0.exists());
            assert!(v1_2.exists());
            assert!(v1_10.exists());

            let (removed, freed) = clean_cache(1).expect("clean succeeds");
            paths::reset_test_overrides();

            assert_eq!(removed, 2, "clean should remove 2 older versions");
            assert_eq!(freed, 22);
            // ALPM vercmp ensures the highest version (1.10.0-1) is kept, NOT deleted!
            assert!(v1_10.exists(), "newest version 1.10.0-1 must be kept");
            assert!(!v1_0.exists(), "older version 1.0.0-1 must be removed");
            assert!(!v1_2.exists(), "older version 1.2.0-1 must be removed");
        });
    }

    #[test]
    fn keyring_error_detection_matches_expected_keywords() {
        assert!(is_keyring_related_error(
            "invalid or corrupted package (PGP signature)"
        ));
        assert!(is_keyring_related_error("KEYRING is not writable"));
        assert!(is_keyring_related_error("SIGNATURE validation failed"));
        assert!(is_keyring_related_error("PGP validation failed"));
        assert!(is_keyring_related_error("package is CORRUPT"));
        assert!(!is_keyring_related_error("conflicting dependencies"));
    }

    #[test]
    fn keyring_prepare_errors_include_repair_commands() {
        let msg = format_trans_prepare_error("invalid or corrupted package");
        assert!(msg.contains("archlinux-keyring"));
        assert!(msg.contains("pacman-key --init"));
        assert!(msg.contains("omg sync && omg install <package>"));
    }

    #[test]
    fn generic_prepare_errors_keep_dependency_guidance() {
        let msg = format_trans_prepare_error("unresolvable package conflicts detected");
        assert!(msg.contains("conflicting packages or missing dependencies"));
        assert!(msg.contains("omg update && omg install <package>"));
    }

    #[test]
    fn progress_events_throttle_percent_and_publish_on_name_change() {
        let mut last = (String::new(), 0_i32);
        assert!(super::progress_event_is_due(&mut last, "foo", 1));
        assert!(!super::progress_event_is_due(&mut last, "foo", 3));
        assert!(super::progress_event_is_due(&mut last, "foo", 6));
        assert!(super::progress_event_is_due(&mut last, "bar", 7));
        assert_eq!(last.0, "bar");
        assert!(super::progress_event_is_due(&mut last, "bar", 0));
        assert_eq!(last, ("bar".to_string(), 0));
        assert!(super::progress_event_is_due(&mut last, "bar", 100));
        assert!(super::progress_event_is_due(&mut last, "bar", 100));
        assert_eq!(last, ("bar".to_string(), 100));
    }

    #[test]
    fn aur_transactions_require_sealed_handoff_targets() {
        let sealed = "/__omg_archive/sealed-descriptor".to_owned();
        let unsealed = "/tmp/package.pkg.tar.zst".to_owned();
        for packages in [
            vec![sealed.clone(), unsealed.clone()],
            vec![unsealed, sealed.clone()],
        ] {
            let error =
                validate_aur_artifact_handoffs(TransactionKind::InstallAurArtifact, &packages)
                    .expect_err("every artifact must use a sealed handoff");
            assert_eq!(
                error.to_string(),
                "AUR artifacts must arrive through an immutable sealed handoff"
            );
        }
        validate_aur_artifact_handoffs(
            TransactionKind::InstallAurArtifact,
            &[sealed.clone(), sealed],
        )
        .expect("multiple sealed handoffs are accepted");
        assert!(
            validate_aur_artifact_handoffs(
                TransactionKind::InstallAurArtifact,
                &["/tmp/package.pkg.tar.zst".to_owned()]
            )
            .is_err()
        );
        assert!(
            validate_aur_artifact_handoffs(
                TransactionKind::InstallAurArtifact,
                &["/__omg_archive/sealed-descriptor".to_owned()]
            )
            .is_ok()
        );
        assert!(
            validate_aur_artifact_handoffs(
                TransactionKind::Install,
                &["/tmp/package.pkg.tar.zst".to_owned()]
            )
            .is_ok()
        );
    }
}
