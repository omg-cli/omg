//! Direct libalpm operations.
//!
//! Rust metadata queries with native signature validation and transactions.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};

use crate::cli::progress::{Accent, Outcome, ProgressTask, TaskKind, TaskSpec};
use crate::core::paths;

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

fn validate_sync_signature(alpm: &alpm::Alpm, database: &alpm::Db) -> Result<()> {
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
    database
        .is_valid()
        .with_context(|| format!("Repository '{}' failed native validation", database.name()))
}

pub(crate) fn validate_sync_database(alpm: &alpm::Alpm, database: &alpm::Db) -> Result<()> {
    validate_sync_signature(alpm, database)?;
    // libalpm loads catalogs lazily. A parse failure invalidates the database,
    // while pkgs() alone represents both failure and a valid empty catalog as [].
    let _ = database.pkgs();
    database
        .is_valid()
        .with_context(|| format!("Repository '{}' failed native validation", database.name()))
}

pub(crate) fn omarchy_install_candidate<'a>(
    alpm: &'a alpm::Alpm,
    name: &str,
) -> Result<(&'a alpm::Db, &'a alpm::Package)> {
    for database in alpm.syncdbs() {
        if !database.usage()?.contains(alpm::Usage::INSTALL) {
            continue;
        }
        validate_sync_database(alpm, database)?;
        if let Ok(package) = database.pkg(name) {
            return Ok((database, package));
        }
    }
    anyhow::bail!("Omarchy package {name} is unavailable from configured install repositories")
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

    crate::package_managers::alpm_direct::with_handle(collect_updates)
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

    // Validate upgrade-eligible sync DBs once; probe libalpm's internal pkghash
    // directly per installed package instead of copying all ~15k sync entries
    // into a temporary HashMap.
    let mut upgrade_dbs = Vec::with_capacity(syncdbs.len());
    for db in syncdbs {
        if !db.usage()?.contains(alpm::Usage::UPGRADE) {
            continue;
        }
        validate_sync_database(alpm, db)?;
        upgrade_dbs.push(db);
    }

    let mut updates = Vec::with_capacity(local_pkg_count / 20); // ~5% typically have updates

    for pkg in localdb.pkgs() {
        if pkg.should_ignore() {
            continue;
        }
        let name = pkg.name();
        let local_ver_str = pkg.version().as_str();

        // First repo wins (core > extra > multilib priority)
        let selected = upgrade_dbs
            .iter()
            .find_map(|db| db.pkg(name).ok().map(|sync_pkg| (sync_pkg, db.name())));
        if let Some((sync_pkg, repo)) = selected
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
    query_sync_pkg_info(name, alpm::Usage::SEARCH)
}

pub(crate) fn get_install_pkg_info(name: &str) -> Result<Option<PackageInfo>> {
    query_sync_pkg_info(name, alpm::Usage::INSTALL)
}

fn query_sync_pkg_info(name: &str, usage: alpm::Usage) -> Result<Option<PackageInfo>> {
    if paths::test_mode() {
        let manager = crate::package_managers::get_package_manager()?;
        let package = futures::executor::block_on(manager.info(name))?;
        if let Some(pkg) = package.filter(|pkg| {
            usage != alpm::Usage::INSTALL || pkg.source == crate::core::PackageSource::Official
        }) {
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
    let alpm = crate::package_managers::alpm_direct::create_alpm_handle()?;
    let package = get_pkg_info_in_scope(&alpm, name, usage)?;
    anyhow::ensure!(
        epoch == super::pacman_db::SyncDbEpoch::observe()?,
        "Package databases or configuration changed while querying; retry the operation"
    );
    Ok(package)
}

/// Read Rust metadata within a caller-supplied native handle's repository scope.
pub fn get_pkg_info_from_db(alpm: &alpm::Alpm, name: &str) -> Result<Option<PackageInfo>> {
    get_pkg_info_in_scope(alpm, name, alpm::Usage::SEARCH)
}

fn get_pkg_info_in_scope(
    alpm: &alpm::Alpm,
    name: &str,
    usage: alpm::Usage,
) -> Result<Option<PackageInfo>> {
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
        if !db.usage()?.contains(usage) {
            continue;
        }
        let verified = verifier.register_syncdb(db.name(), db.siglevel())?;
        validate_sync_signature(&verifier, verified)?;
        let path = sync_dir.join(format!("{}.db", db.name()));
        let package = super::pacman_db::parse_sync_db_package(&path, db.name(), name)
            .with_context(|| {
                format!("Repository '{}' failed Rust metadata validation", db.name())
            })?;
        if let Some(pkg) = package {
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
        NativeOmarchyOperation::RefreshKeyrings
        | NativeOmarchyOperation::InstallTrayMenuDependency
        | NativeOmarchyOperation::InstallOmnibookAudio
        | NativeOmarchyOperation::InstallMediaViewer
        | NativeOmarchyOperation::InstallFacetimeHd
        | NativeOmarchyOperation::InstallPiCodingAgent
        | NativeOmarchyOperation::InstallKmscon
        | NativeOmarchyOperation::InstallPodmanAndCrun => TransactionKind::Install,
        NativeOmarchyOperation::UpgradeRepositories => TransactionKind::SystemUpgrade,
        NativeOmarchyOperation::RemoveOrphans
        | NativeOmarchyOperation::RemoveLegacyMediaViewers => {
            TransactionKind::Remove { recursive: true }
        }
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

    configure_mirrors(alpm, &pacman_config)?;
    if matches!(policy, TransactionPolicy::Omarchy) && kind == TransactionKind::Install {
        for name in &packages {
            let (database, _) = omarchy_install_candidate(alpm, name)?;
            let level = database.siglevel();
            anyhow::ensure!(
                level.contains(alpm::SigLevel::PACKAGE)
                    && !level.intersects(
                        alpm::SigLevel::PACKAGE_OPTIONAL
                            | alpm::SigLevel::PACKAGE_UNKNOWN_OK
                            | alpm::SigLevel::PACKAGE_MARGINAL_OK
                    ),
                "Native Omarchy package installation requires mandatory trusted package signatures; trust bootstrap is unavailable"
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
            let path = crate::core::security::validate_local_package_file(target)?;
            let admission =
                crate::package_managers::aur::artifact_inspector::inspect_archive(&path)?;
            admissions.insert(path, admission);
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
                let pkg = tx_guard
                    .0
                    .localdb()
                    .pkg(pkg_name.as_str())
                    .with_context(|| {
                        format!("Cannot remove '{pkg_name}' from the installed package database")
                    })?;
                tx_guard
                    .0
                    .trans_remove_pkg(pkg)
                    .with_context(|| format!("Failed to add {pkg_name} to removal list"))?;
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
    let download_user = pacman_config.download_user.as_deref();
    if let Some(user) = download_user {
        nix::unistd::User::from_name(user)
            .context("Failed to resolve pacman DownloadUser")?
            .with_context(|| format!("Pacman DownloadUser account '{user}' does not exist"))?;
    }
    alpm.set_sandbox_user(download_user)
        .context("Failed to configure pacman DownloadUser")?;
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
    if pacman_config.hook_dirs.is_empty() {
        hook_dirs.push(root.join("etc/pacman.d/hooks"));
    }
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

    let architectures = pacman_config.package_architectures()?;
    alpm.set_architectures(architectures.iter().map(String::as_str))
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
    let origin = policy.arch_repository_origin(repository);
    anyhow::ensure!(
        matches!(origin, super::types::SecurityOrigin::ArchRepository { .. })
            || policy.advisory_requirement != AdvisoryRequirement::FreshSnapshot,
        "FreshSnapshot has no declared Arch advisory coordinates for repository '{}'; configure arch_advisory_repositories or use Optional/Review deliberately",
        crate::cli::style::sanitize_terminal_text(repository)
    );
    Ok(origin)
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
            action.sa_mask = *nix::sys::signal::SigSet::empty().as_ref();
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
fn confirm_advisory_prompt(
    details: &str,
    digest: &str,
    invoking_uid: u32,
    signals: &AdmissionSignals,
) -> Result<()> {
    anyhow::ensure!(
        crate::core::is_root(),
        "Security acknowledgement requires the privileged transaction owner"
    );
    let details = format!(
        "{details}\nArch advisory source: {}\n",
        crate::core::security::vulnerability::ARCH_UPSTREAM_URL
    );
    crate::core::privilege::confirm_security_review(&details, digest, invoking_uid, &|| {
        signals.check()
    })
}

#[cfg(not(target_os = "linux"))]
fn confirm_advisory_prompt(
    _details: &str,
    _digest: &str,
    _invoking_uid: u32,
    _signals: &AdmissionSignals,
) -> Result<()> {
    anyhow::bail!("Security acknowledgement requires Linux terminal ownership checks")
}

fn unknown_archives_prompt(
    packages: &[PreparedAdvisoryPackage],
    digest: &str,
    invoking_uid: u32,
) -> Result<String> {
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
    let mut prompt = format!(
        "\nArch advisory applicability is UNKNOWN for these exact archives. This acknowledgement does not establish coverage.\nInvoking UID: {invoking_uid}\nFull prepared batch SHA-256: {digest}\n"
    );
    for item in unknown {
        let identity = (
            &item.package.name,
            &item.package.version,
            &item.package.architecture,
            &item.package.origin,
            &item.sha256,
        );
        prompt.push_str(&serde_json::to_string(&identity)?);
        prompt.push('\n');
    }
    Ok(prompt)
}

fn confirm_unknown_archives(
    packages: &[PreparedAdvisoryPackage],
    digest: &str,
    invoking_uid: u32,
    signals: &AdmissionSignals,
) -> Result<UnknownArchiveAcknowledgement> {
    let prompt = unknown_archives_prompt(packages, digest, invoking_uid)?;
    confirm_advisory_prompt(&prompt, digest, invoking_uid, signals)?;
    Ok(UnknownArchiveAcknowledgement {
        batch_digest: digest.to_owned(),
        invoking_uid,
    })
}

struct PreparedAdvisoryAdmission {
    packages: Vec<PreparedAdvisoryPackage>,
    policy: crate::core::security::SecurityPolicy,
    profile: Vec<u8>,
    invoking_uid: u32,
    acknowledgement: Option<UnknownArchiveAcknowledgement>,
    risk_acceptance: Option<crate::core::security::advisory_review::AdvisoryRiskAcceptance>,
    operation: Option<crate::core::security::vulnerability::ArchOperationAssessment>,
    assessments: Vec<crate::core::security::vulnerability::PackageAssessment>,
}

fn prepared_risk_review(
    assessments: &[crate::core::security::vulnerability::PackageAssessment],
    context: &str,
    requirement: crate::core::security::policy::AdvisoryRequirement,
) -> Result<Option<crate::core::security::advisory_review::AdvisoryRiskReview>> {
    use crate::core::security::advisory_review::AdvisoryRiskReview;
    if requirement == crate::core::security::policy::AdvisoryRequirement::FreshSnapshot {
        // FreshSnapshot already owns the separate exact-archive gap acknowledgement.
        AdvisoryRiskReview::new(assessments, context)
    } else {
        AdvisoryRiskReview::new_with_unknown(assessments, context)
    }
}

fn require_fresh_arch_coverage(
    assessment: &crate::core::security::vulnerability::PackageAssessment,
    archive_acknowledged: bool,
) -> Result<()> {
    use super::types::SecurityOrigin;
    let private_archive = matches!(
        assessment.package.origin,
        SecurityOrigin::AurArchive | SecurityOrigin::LocalArchive
    );
    anyhow::ensure!(
        assessment.coverage.is_assessed() || private_archive && archive_acknowledged,
        "FreshSnapshot requires assessed coordinates or an exact private archive acknowledgement"
    );
    Ok(())
}

fn ensure_prepared_review_signals(
    signals: &mut Option<AdmissionSignals>,
    details: &str,
) -> Result<()> {
    if let Some(owner) = signals.as_ref() {
        return owner.check();
    }
    AdmissionSignals::begin_in(signals).with_context(|| {
        format!("{details}\nAdvisory risk review requires an attended native OMG CLI")
    })
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
        use crate::core::security::vulnerability::{
            AssessmentUse, PackageAssessment, UnknownCoverage, VulnerabilityScanner,
        };
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
        let mut risk_acceptance = None;
        let operation = if packages.is_empty() {
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
            .map_err(|_| anyhow::anyhow!("Prepared Arch advisory worker failed"))?;
            let operation = match operation {
                Ok(operation) => Some(operation),
                Err(error) if policy.advisory_requirement == AdvisoryRequirement::Optional => {
                    eprintln!(
                        "Warning: advisory coverage is UNKNOWN; no clean result was established: {}",
                        crate::cli::style::sanitize_terminal_text(&error.to_string())
                    );
                    None
                }
                Err(error) => return Err(error),
            };
            if let Some(operation) = &operation {
                anyhow::ensure!(
                    operation.assessments().len() == packages.len()
                        && operation
                            .assessments()
                            .iter()
                            .zip(&packages)
                            .all(|(assessment, item)| assessment.package == item.package),
                    "Prepared Arch assessment identity mismatch"
                );
                if policy.advisory_requirement == AdvisoryRequirement::FreshSnapshot {
                    for assessment in operation.assessments() {
                        require_fresh_arch_coverage(assessment, acknowledgement.is_some())?;
                    }
                }
            }
            operation
        };
        let assessments = operation.as_ref().map_or_else(
            || {
                packages
                    .iter()
                    .map(|item| {
                        PackageAssessment::unknown(
                            item.package.clone(),
                            UnknownCoverage::EvidenceUnavailable,
                        )
                    })
                    .collect::<Vec<_>>()
            },
            |operation| operation.assessments().to_vec(),
        );
        let digest = advisory_batch_digest(&packages, &policy, &profile, invoking_uid)?;
        let review = prepared_risk_review(&assessments, &digest, policy.advisory_requirement)?;
        if let Some(review) = review {
            ensure_prepared_review_signals(signals, review.details())?;
            confirm_advisory_prompt(
                review.details(),
                review.id(),
                invoking_uid,
                signals
                    .as_ref()
                    .context("Advisory risk signal owner is missing")?,
            )?;
            risk_acceptance = Some(review.accept(&format!("accept {}", review.id()))?);
        }
        if let Some(signals) = signals.as_ref() {
            signals.check()?;
        }
        Ok(Self {
            packages,
            policy,
            profile,
            invoking_uid,
            acknowledgement,
            risk_acceptance,
            operation,
            assessments,
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
        let digest = advisory_batch_digest(&current, &policy, &profile, invoking_uid)?;
        let review = prepared_risk_review(&self.assessments, &digest, policy.advisory_requirement)?;
        if let Some(review) = review {
            anyhow::ensure!(
                self.risk_acceptance
                    .as_ref()
                    .is_some_and(|accepted| accepted.matches(&review)),
                "Advisory risk acceptance no longer matches this transaction; review again"
            );
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

/// Apply the same repository configuration used to set transaction policy.
fn configure_mirrors(
    alpm: &mut alpm::Alpm,
    config: &crate::core::pacman_conf::PacmanConfig,
) -> Result<()> {
    let arch = config.primary_package_architecture()?;
    let mut configured = Vec::new();
    for database in alpm.syncdbs_mut() {
        let repo = config
            .repos
            .iter()
            .find(|repo| repo.name == database.name())
            .with_context(|| {
                format!(
                    "Registered repository '{}' is absent from pacman.conf",
                    database.name()
                )
            })?;
        let servers = config.resolve_servers(repo, &arch)?;
        configured.push((database, servers));
    }
    for (database, servers) in configured {
        let result = database.set_servers(servers.iter().map(String::as_str));
        mirror_configuration_result(database.name(), result)?;
    }
    ensure_mirror_servers(alpm)
}

fn mirror_configuration_result(repository: &str, result: alpm::Result<()>) -> Result<()> {
    result.with_context(|| format!("Failed to set mirrors for repository '{repository}'"))
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
#[path = "alpm_ops_tests.rs"]
mod tests;
