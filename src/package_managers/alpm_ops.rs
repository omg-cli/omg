//! Direct libalpm operations.
//!
//! Pure libalpm queries and transactions without spawning a pacman subprocess.

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
    use anyhow::Context as _;

    let root = crate::core::paths::pacman_root_result()?
        .to_string_lossy()
        .into_owned();
    let db_path = crate::core::paths::pacman_db_dir_result()?
        .to_string_lossy()
        .into_owned();
    alpm::Alpm::new(root, db_path).context("Failed to initialize ALPM")
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
        Ok(collect_updates(alpm))
    })
}

/// Collect available updates from an ALPM handle whose ignore filters are
/// already configured.
///
/// Single authoritative update-collection implementation: shared by the CLI
/// (`get_update_list`) and the daemon worker (`alpm_worker`) so both honor
/// `IgnorePkg`/`IgnoreGroup`/`Replacement` handling identically.
pub(crate) fn collect_updates(alpm: &alpm::Alpm) -> Vec<UpdateInfo> {
    let localdb = alpm.localdb();
    let syncdbs = alpm.syncdbs();
    let local_pkg_count = localdb.pkgs().len();

    // Build HashMap of sync packages: name -> (version_str, repo_name)
    // This converts O(n×m) lookups to O(n+m) with single HashMap lookup per package
    let mut sync_map: ahash::AHashMap<&str, (&str, &str)> =
        ahash::AHashMap::with_capacity(local_pkg_count);

    for db in syncdbs {
        let repo_name = db.name();
        for pkg in db.pkgs() {
            if pkg.should_ignore() {
                continue;
            }
            // First repo wins (core > extra > multilib priority)
            sync_map
                .entry(pkg.name())
                .or_insert_with(|| (pkg.version().as_str(), repo_name));
        }
    }

    let mut updates = Vec::with_capacity(local_pkg_count / 20); // ~5% typically have updates

    for pkg in localdb.pkgs() {
        let name = pkg.name();
        let local_ver_str = pkg.version().as_str();

        if let Some(&(sync_ver_str, repo)) = sync_map.get(name)
            && alpm::vercmp(sync_ver_str, local_ver_str) == std::cmp::Ordering::Greater
        {
            updates.push(UpdateInfo {
                name: name.to_string(),
                old_version: local_ver_str.to_string(),
                new_version: sync_ver_str.to_string(),
                repo: repo.to_string(),
            });
        }
    }

    updates
}

/// Get package info from sync DBs - INSTANT (<1ms)
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

    crate::package_managers::alpm_direct::with_handle(|alpm| get_pkg_info_from_db(alpm, name))
}

/// Get package info using an existing ALPM handle - ULTRA FAST
pub fn get_pkg_info_from_db(alpm: &alpm::Alpm, name: &str) -> Result<Option<PackageInfo>> {
    for db in alpm.syncdbs() {
        if let Ok(pkg) = db.pkg(name) {
            // A version that fails the strict parser must not compare as a
            // fabricated 0 (ARCH-R14); skip the entry visibly.
            let Some(version) = crate::package_managers::parse_version(pkg.version()) else {
                tracing::warn!(
                    "Ignoring sync package '{name}' with unparseable version '{}'",
                    pkg.version()
                );
                return Ok(None);
            };
            return Ok(Some(PackageInfo {
                name: pkg.name().to_string(),
                version,
                description: pkg.desc().unwrap_or("").to_string(),
                url: pkg.url().map(std::string::ToString::to_string),
                // libalpm's size fields are i64; negative values from a
                // corrupt database must not wrap into huge u64 values.
                // https://doc.rust-lang.org/reference/expressions/operator-expr.html#numeric-cast
                size: u64::try_from(pkg.isize()).unwrap_or(0),
                install_size: Some(pkg.isize()),
                download_size: Some(u64::try_from(pkg.size()).unwrap_or(0)),
                repo: db.name().to_string(),
                depends: pkg.depends().iter().map(|d| d.name().to_string()).collect(),
                licenses: pkg
                    .licenses()
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect(),
                installed: alpm.localdb().pkg(pkg.name()).is_ok(),
            }));
        }
    }

    Ok(None)
}

/// Extract the package base name and full version from a pacman cache filename.
///
/// Cache files are named `{pkgname}-{version}-{release}-{arch}.pkg.tar.{zst,xz,gz,bz2}`.
/// Neither `version` nor `release` may contain a dash (Arch packaging rules),
/// so exactly the last three dash-separated components are stripped; any
/// dashes inside the package name survive. Returns `None` for files without
/// the expected shape.
fn package_cache_info(filename: &str) -> Option<(&str, &str)> {
    let stem = filename
        .strip_suffix(".pkg.tar.zst")
        .or_else(|| filename.strip_suffix(".pkg.tar.xz"))
        .or_else(|| filename.strip_suffix(".pkg.tar.gz"))
        .or_else(|| filename.strip_suffix(".pkg.tar.bz2"))?;
    // Strip exactly the trailing -arch, -release, -version components;
    // everything to the left (including any dashes in the pkgbase) stays.
    let (rest, _arch) = stem.rsplit_once('-')?;
    let (rest, release) = rest.rsplit_once('-')?;
    let (name, version) = rest.rsplit_once('-')?;
    if name.is_empty() || version.is_empty() || release.is_empty() {
        return None;
    }
    let full_version_start = name.len() + 1;
    let full_version_end = full_version_start + version.len() + 1 + release.len();
    let full_version = &stem[full_version_start..full_version_end];
    Some((name, full_version))
}

#[cfg(test)]
fn package_base_name(filename: &str) -> Option<&str> {
    package_cache_info(filename).map(|(name, _)| name)
}

/// Preview package cache cleaning without mutating the filesystem
pub fn clean_cache_preview(keep_versions: usize) -> Result<(usize, u64)> {
    clean_cache_internal(keep_versions, true)
}

/// Clean package cache using direct file system operations - FAST
///
/// Following ALPM standards, package versions are compared using `alpm::vercmp`
/// rather than filesystem modification time, with mtime used only to break ties.
pub fn clean_cache(keep_versions: usize) -> Result<(usize, u64)> {
    clean_cache_internal(keep_versions, false)
}

fn clean_cache_internal(keep_versions: usize, dry_run: bool) -> Result<(usize, u64)> {
    let mut packages: ahash::AHashMap<String, Vec<(std::path::PathBuf, String)>> =
        ahash::AHashMap::new();

    for cache_dir in paths::pacman_cache_dirs_result()? {
        if !cache_dir.exists() {
            continue;
        }
        for entry in std::fs::read_dir(&cache_dir)
            .with_context(|| format!("Failed to read pacman cache at {}", cache_dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();

            let Some(filename) = path
                .file_name()
                .and_then(|name| name.to_str())
                .map(ToString::to_string)
            else {
                continue;
            };

            if let Some((base, ver)) = package_cache_info(&filename) {
                packages
                    .entry(base.to_string())
                    .or_default()
                    .push((path, ver.to_string()));
            }
        }
    }

    let mut removed = 0;
    let mut freed = 0u64;

    for (_, mut versions) in packages {
        // Sort newest version first by ALPM vercmp, breaking ties by mtime
        versions.sort_by(|(a_path, a_ver), (b_path, b_ver)| {
            let cmp = alpm::vercmp(b_ver.as_str(), a_ver.as_str());
            if cmp != std::cmp::Ordering::Equal {
                return cmp;
            }
            let a_time = a_path
                .metadata()
                .and_then(|metadata| metadata.modified())
                .ok();
            let b_time = b_path
                .metadata()
                .and_then(|metadata| metadata.modified())
                .ok();
            b_time.cmp(&a_time)
        });

        for (old, _) in versions.into_iter().skip(keep_versions) {
            if dry_run {
                removed += 1;
                let archive_len = std::fs::metadata(&old).map_or(0, |metadata| metadata.len());
                freed = freed.saturating_add(archive_len);
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
        Err(error) => tracing::warn!("Failed to remove cache file {}: {error}", archive.display()),
    }

    let signature = std::path::PathBuf::from(format!("{}.sig", archive.display()));
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

/// RAII Guard for ALPM transactions to ensure release
#[must_use]
struct AlpmTransaction<'a>(&'a mut alpm::Alpm);

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
/// The `handle` parameter exists for callers that already own a configured
/// ALPM handle (e.g. an elevated fast path); every current caller passes
/// [`None`], which creates and configures a fresh handle. NOTE(wave2): the
/// `Some(handle)` branch skips repository registration that the `None`
/// branch performs — if you ever pass a handle, it must already have sync
/// databases registered.
pub fn execute_transaction(
    packages: Vec<String>,
    kind: TransactionKind,
    handle: Option<&mut alpm::Alpm>,
) -> Result<()> {
    validate_aur_artifact_handoffs(kind, &packages)?;
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
    if kind == TransactionKind::InstallAurArtifact {
        for package in &packages {
            crate::package_managers::aur::artifact_inspector::inspect_archive(
                std::path::Path::new(package),
            )?;
        }
    }
    let pacman_config = crate::core::pacman_conf::PacmanConfig::parse(paths::pacman_conf_path())
        .context("Failed to load transaction options from pacman.conf")?;

    if let Some(alpm) = handle {
        configure_transaction_options(alpm, &pacman_config)?;
        configure_mirrors(alpm)?;
        let refusals = Arc::new(Mutex::new(AlpmQuestionRefusals::default()));
        let main_task = setup_alpm_callbacks(alpm, &refusals);
        let tx_guard = prepare_alpm_transaction(alpm, packages, kind, &pacman_config)
            .map_err(|error| question_refusal_error(&refusals).unwrap_or(error))?;
        // Declined replacement questions make libalpm skip the replacement
        // silently, so a successful prepare can still hide a refused mutation.
        if let Some(error) = question_refusal_error(&refusals) {
            return Err(error);
        }
        commit_alpm_transaction(tx_guard.0, &main_task, kind, &pacman_config.hold_pkg)
            .map_err(|error| question_refusal_error(&refusals).unwrap_or(error))?;
        return Ok(());
    }

    let mut alpm = open_default_alpm()?;
    configure_transaction_options(&mut alpm, &pacman_config)?;

    if pacman_config.repos.is_empty() {
        anyhow::bail!("pacman configuration contains no repositories");
    }

    register_configured_syncdbs(&alpm, &pacman_config)?;

    configure_mirrors(&mut alpm)?;

    let refusals = Arc::new(Mutex::new(AlpmQuestionRefusals::default()));
    let main_task = setup_alpm_callbacks(&alpm, &refusals);
    let tx_guard = prepare_alpm_transaction(&mut alpm, packages, kind, &pacman_config)
        .map_err(|error| question_refusal_error(&refusals).unwrap_or(error))?;
    if let Some(error) = question_refusal_error(&refusals) {
        return Err(error);
    }
    commit_alpm_transaction(tx_guard.0, &main_task, kind, &pacman_config.hold_pkg)
        .map_err(|error| question_refusal_error(&refusals).unwrap_or(error))?;

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
        alpm.register_syncdb(repo.name.as_str(), siglevel)
            .with_context(|| {
                format!(
                    "Failed to register configured sync database '{}'; refusing a partial repository set",
                    repo.name
                )
            })?;
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
}

impl AlpmQuestionRefusals {
    fn is_empty(&self) -> bool {
        self.replacements.is_empty() && self.removals.is_empty()
    }

    fn record_refused_replacement(&mut self, oldpkg: &str, newdb: &str, newpkg: &str) {
        self.replacements
            .push(format!("{oldpkg} with {newdb}/{newpkg}"));
    }

    fn record_refused_removals(&mut self, packages: &[String]) {
        self.removals.push(packages.join(", "));
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
    Some(anyhow::anyhow!(
        "ALPM transaction aborted: it requires an unconfirmed package mutation ({}) \
         the question callback cannot prompt interactively, so resolve the conflict explicitly and retry",
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
fn setup_alpm_callbacks(
    alpm: &alpm::Alpm,
    refusals: &Arc<Mutex<AlpmQuestionRefusals>>,
) -> ProgressTask {
    let main_task = ProgressTask::start(&TaskSpec {
        label: "Transaction".to_string(),
        kind: TaskKind::Items { total: 100 },
        accent: Accent::System,
    });

    alpm.set_question_cb(Arc::clone(refusals), |question, refusals| {
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
                let auto_accept = crate::core::privilege::get_yes_flag();
                let confirmed = if auto_accept {
                    true
                } else if console::user_attended() {
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

                let auto_accept = crate::core::privilege::get_yes_flag();
                let confirmed = if auto_accept {
                    true
                } else if console::user_attended() {
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
                let fingerprint = q.fingerprint();
                let uid = q.uid();
                tracing::info!("PGP key required: {fingerprint} ({uid})");

                let confirmed =
                    if console::user_attended() && !crate::core::privilege::get_yes_flag() {
                        let _quiesce = crate::cli::modern_ui::quiesce_terminal();
                        dialoguer::Confirm::with_theme(&crate::cli::ui::prompt_theme())
                            .with_prompt(format!("Import PGP key {fingerprint} ({uid})?"))
                            .default(false)
                            .interact()
                            .unwrap_or(false)
                    } else {
                        false
                    };

                if confirmed {
                    tracing::info!("Importing PGP key: {fingerprint} ({uid})");
                    q.set_import(true);
                } else {
                    tracing::warn!("PGP key not trusted: {fingerprint} ({uid})");
                    tracing::info!(
                        "Import key manually: pacman-key --recv-keys {fingerprint} && pacman-key --lsign-key {fingerprint}"
                    );
                    q.set_import(false);
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
    alpm: &alpm::Alpm,
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
fn prepare_alpm_transaction<'a>(
    alpm: &'a mut alpm::Alpm,
    packages: Vec<String>,
    kind: TransactionKind,
    pacman_config: &crate::core::pacman_conf::PacmanConfig,
) -> Result<AlpmTransaction<'a>> {
    validate_transaction_targets(kind, &packages)?;
    check_database_lock(std::path::Path::new(alpm.dbpath().trim_end_matches('/')))?;
    alpm.trans_init(transaction_flags(kind))
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

    let tx_guard = AlpmTransaction(alpm);

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
                    tx_guard.0.trans_add_pkg(pkg).map_err(|e| {
                        anyhow::anyhow!(
                            "Failed to add local package {pkg_name} to transaction: {e}"
                        )
                    })?;
                    continue;
                }

                let mut found = false;
                for db in tx_guard.0.syncdbs() {
                    if let Ok(pkg) = db.pkg(pkg_name.as_str()) {
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
    let root = paths::pacman_root_result()?;
    let gpg_dir = pacman_option_path(
        &root,
        pacman_config.gpg_dir.as_deref(),
        "etc/pacman.d/gnupg",
    );
    anyhow::ensure!(
        gpg_dir.is_dir(),
        "Pacman keyring is unavailable at {}. Initialize it before installing packages.",
        gpg_dir.display()
    );
    let gpg_dir = gpg_dir
        .to_str()
        .context("Pacman keyring path contains invalid UTF-8")?;
    alpm.set_gpgdir(gpg_dir)
        .context("Failed to configure pacman keyring")
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
    let matchers = hold_pkg
        .iter()
        .map(|pattern| {
            globset::Glob::new(pattern)
                .with_context(|| format!("Invalid HoldPkg pattern '{pattern}' in pacman.conf"))
                .map(|glob| (pattern, glob.compile_matcher()))
        })
        .collect::<Result<Vec<_>>>()?;

    for package_name in package_names {
        if let Some((pattern, _)) = matchers
            .iter()
            .find(|(_, matcher)| matcher.is_match(package_name))
        {
            anyhow::bail!(
                "Package '{package_name}' is protected by HoldPkg pattern '{pattern}' in pacman.conf and cannot be removed"
            );
        }
    }
    Ok(())
}

fn commit_alpm_transaction(
    alpm: &mut alpm::Alpm,
    main_task: &ProgressTask,
    kind: TransactionKind,
    hold_pkg: &[String],
) -> Result<()> {
    main_task.set_message("Preparing transaction...");

    alpm.trans_prepare()
        .map_err(|e| anyhow::anyhow!(format_trans_prepare_error(&e.to_string())))?;

    let candidates = alpm
        .trans_add()
        .into_iter()
        .map(|package| {
            Ok((
                package.name().to_owned(),
                crate::package_managers::parse_version(package.version().as_str())
                    .context("Invalid prepared package version")?,
                package.origin() != alpm::PackageFrom::SyncDb,
                crate::core::security::policy::combined_license_expression(
                    package.licenses().iter(),
                ),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    crate::core::security::policy::check_prepared_packages(candidates)?;

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

    if alpm.trans_add().is_empty() && alpm.trans_remove().is_empty() {
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
        .collect::<Vec<_>>();
    let operation = match kind {
        TransactionKind::Install | TransactionKind::InstallAurArtifact => "install",
        TransactionKind::Remove { .. } => "remove",
        TransactionKind::SystemUpgrade => "upgrade",
    };
    crate::core::security::audit::record_operation(operation, &targets, "attempt")?;
    let result = alpm
        .trans_commit()
        .map_err(|error| anyhow::anyhow!("Transaction failed to commit: {error}"));
    crate::core::security::audit::record_operation(
        operation,
        &targets,
        if result.is_ok() {
            "succeeded"
        } else {
            "failed"
        },
    )
    .context("Package transaction finished but audit persistence failed")?;
    result?;

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
            "%FILENAME%\nfoo-2.0-1-x86_64.pkg.tar.zst\n\n%CSIZE%\n1\n\n%ISIZE%\n1\n\n{sync_desc}"
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
    fn replace_question_is_accepted_when_yes_flag_is_set() {
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
            "%FILENAME%\nfoo-2.0-1-x86_64.pkg.tar.zst\n\n%CSIZE%\n1\n\n%ISIZE%\n1\n\n{sync_desc}"
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

        crate::core::privilege::set_yes_flag(true);
        let init_result = alpm.trans_init(alpm::TransFlag::NEEDED);
        let upgrade_result = alpm.sync_sysupgrade(false);
        let trans_add_len = alpm.trans_add().len();
        crate::core::privilege::set_yes_flag(false);

        init_result.expect("init transaction");
        upgrade_result.expect("compute sysupgrade");
        assert_eq!(
            trans_add_len, 1,
            "accepted replacement must add replacing package to transaction"
        );
        assert!(question_refusal_error(&refusals).is_none());
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
        let alpm = alpm::Alpm::new("/", database_path.as_ref()).expect("ALPM handle");
        configure_signature_policy(&alpm, &config).expect("configure ALPM policy");
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
    fn invalid_hold_pkg_patterns_fail_closed() {
        let error = ensure_removals_not_held(["anything"], &["[".to_string()])
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
    fn clean_cache_sorts_by_alpm_vercmp_and_keeps_newest_version() {
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

        let (preview_removed, preview_freed) = clean_cache_preview(1).expect("preview succeeds");
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
    }

    #[test]
    fn keyring_error_detection_matches_expected_keywords() {
        assert!(is_keyring_related_error(
            "invalid or corrupted package (PGP signature)"
        ));
        assert!(is_keyring_related_error("keyring is not writable"));
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
    }

    #[test]
    fn aur_transactions_require_sealed_handoff_targets() {
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
