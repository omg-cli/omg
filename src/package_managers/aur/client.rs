//! AUR (Arch User Repository) client with build support

use ahash::AHashSet;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use alpm_types::Version;
use anyhow::{Context, Result};
use dialoguer::Confirm;
use futures::{FutureExt, StreamExt, future::BoxFuture};
use owo_colors::OwoColorize;
use serde::{Deserialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tracing::{instrument, warn};

use super::error::AurError;
#[cfg(test)]
use super::history::historical_version_not_found_message;
use super::history::srcinfo_version;
use super::parallel_build::BuildJob;
use super::utils::{
    BuildLifecycleLease, build_user, create_dir_as_user, create_dir_as_user_sync,
    has_word_boundary_match, is_symlink, original_user, original_user_home, remove_dir_as_user,
    sudo_as_user_program, validate_build_dir,
};
use super::{approval, artifact_inspector};

use super::super::aur_deps::{check_dependencies_from_metadata, dependency_name};
use super::super::aur_index::AurIndex;
use super::super::aur_metadata::{AurJsonPackage, open_fresh_metadata_index};
use super::super::aur_sources::{
    download_sources, http_sources, prefetch_vcs_sources, vcs_sources,
};
#[cfg(feature = "pgp")]
use super::super::pkgbuild::PkgBuild;
use crate::config::{AurBuildMethod, AurSecurityProfile, Settings};
use crate::core::http::shared_client;
use crate::core::packages::search::validate_aur_search_query;
use crate::core::{Package, PackageSource, paths};
use crate::package_managers::arch_install::{
    InstallIntent, InstallItem, InstallRequest, InstallTarget, OfficialTarget,
};
use crate::package_managers::pacman_db;
use crate::runtimes::common::MAX_DECOMPRESSED_BYTES;

use crate::core::security::artifact::ArchiveSnapshot;
pub(crate) const AUR_RPC_URL: &str = "https://aur.archlinux.org/rpc";
// makepkg records BUILDDIR in .BUILDINFO; physical invocation storage stays private.
const SANDBOX_BUILD_ROOT: &str = "/omg-build";

fn sandbox_build_root(mount_destinations: &[&Path]) -> Result<PathBuf> {
    (0..=mount_destinations.len())
        .map(|index| {
            if index == 0 {
                PathBuf::from(SANDBOX_BUILD_ROOT)
            } else {
                PathBuf::from(format!("{SANDBOX_BUILD_ROOT}-{index}"))
            }
        })
        .find(|candidate| {
            mount_destinations.iter().all(|destination| {
                !destination.starts_with(candidate) && !candidate.starts_with(destination)
            })
        })
        .context("Sandbox build root overlaps an existing mount")
}

const AUR_GIT_URL: &str = "https://aur.archlinux.org";
const AUR_RPC_MAX_URI: usize = 4400;

/// Process-wide lock around ALPM database mutations so parallel AUR builds never race.
/// ALPM serializes installs on `/var/lib/pacman/db.lck`, so concurrent installs — e.g. parallel AUR build
/// waves finishing together — either fail spuriously on the lock or race the
/// ALPM database. Builds stay parallel; installs are applied one at a time.
static INSTALL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static REVIEW_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static PAIRED_BUILD_CACHE: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
const MAX_PKGBUILD_REVIEW_BYTES: usize = 1024 * 1024;
const SANDBOX_FAKEROOT_ENV: (&str, &str) = ("FAKEROOTDONTTRYCHOWN", "1");
const MAX_PKGINFO_BYTES: u64 = 128 * 1024;
const MAX_AUR_BUILD_LOG_BYTES: u64 = 64 * 1024 * 1024;
const MAX_AUR_BUILD_DURATION: Duration = Duration::from_hours(2);
/// Pre-computed length of the AUR RPC info base URL (47 bytes)
const AUR_RPC_INFO_BASE_LEN: usize = 47;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PGP Key ID Validation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Result of PGP key ID validation
#[cfg(any(feature = "pgp", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgpKeyIdStatus {
    /// Full 40-char fingerprint - most secure
    FullFingerprint,
    /// 16-char long key ID - acceptable
    LongKeyId,
    /// 8-char short key ID - INSECURE (vulnerable to collision attacks)
    ShortKeyId,
    /// Empty key ID
    Empty,
    /// Key ID too long (> 64 chars)
    TooLong,
    /// Contains non-hexadecimal characters
    InvalidChars,
    /// Non-standard length (not 8, 16, or 40 chars)
    NonStandardLength,
}

/// Validate a PGP key ID for security.
///
/// # Security
/// - **Short key IDs (8 chars)** are vulnerable to collision attacks where
///   an attacker generates a key with the same short ID as a trusted key.
/// - **Long key IDs (16 chars)** are acceptable but not ideal.
/// - **Full fingerprints (40 chars)** are strongly recommended.
///
/// # Returns
/// - `PgpKeyIdStatus` indicating the validation result:
///   - `"ABCDEF1234567890ABCDEF1234567890ABCDEF12"` → `FullFingerprint`
///   - `"ABCDEF1234567890"` → `LongKeyId`
///   - `"ABCDEF12"` or any 1-15 hex chars → `ShortKeyId` (rejected)
///   - `""` → `Empty`, `>64 chars` → `TooLong`, non-hex → `InvalidChars`,
///     other hex lengths → `NonStandardLength`
#[inline]
#[cfg(any(feature = "pgp", test))]
#[must_use]
pub fn validate_pgp_key_id(key_id: &str) -> PgpKeyIdStatus {
    if key_id.is_empty() {
        return PgpKeyIdStatus::Empty;
    }
    if key_id.len() > 64 {
        return PgpKeyIdStatus::TooLong;
    }
    if !key_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return PgpKeyIdStatus::InvalidChars;
    }

    match key_id.len() {
        40 => PgpKeyIdStatus::FullFingerprint,
        16 => PgpKeyIdStatus::LongKeyId,
        8 => PgpKeyIdStatus::ShortKeyId,
        _ if key_id.len() < 16 => PgpKeyIdStatus::ShortKeyId,
        _ => PgpKeyIdStatus::NonStandardLength,
    }
}

#[cfg(any(feature = "pgp", test))]
fn require_fetchable_pgp_key_id(key_id: &str) -> Result<()> {
    match validate_pgp_key_id(key_id) {
        PgpKeyIdStatus::FullFingerprint | PgpKeyIdStatus::LongKeyId => Ok(()),
        PgpKeyIdStatus::NonStandardLength => {
            tracing::debug!(
                "PGP key ID '{key_id}' is {} chars (40-char fingerprint recommended)",
                key_id.len()
            );
            Ok(())
        }
        PgpKeyIdStatus::ShortKeyId => anyhow::bail!(
            "Rejecting short PGP key ID '{key_id}' (vulnerable to collision attacks). \
             Use full fingerprint (40 chars) or long key ID (16 chars)."
        ),
        PgpKeyIdStatus::Empty | PgpKeyIdStatus::TooLong => {
            anyhow::bail!("Invalid PGP key ID (bad length): {key_id}")
        }
        PgpKeyIdStatus::InvalidChars => {
            anyhow::bail!("Invalid PGP key ID (non-hex chars): {key_id}")
        }
    }
}

#[cfg(feature = "pgp")]
fn create_scoped_pgp_home(
    valid_keys: &[String],
    source_home: &Path,
    cache_dir: &Path,
) -> Result<tempfile::TempDir> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    use crate::core::security::keyserver;

    std::fs::create_dir_all(cache_dir).with_context(|| {
        format!(
            "Failed to create AUR cache directory: {}",
            cache_dir.display()
        )
    })?;
    let build_keyring = tempfile::Builder::new()
        .prefix("aur-pgp-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(cache_dir)
        .context("Failed to create package-scoped AUR PGP keyring")?;
    let gpg = crate::core::privilege::root_controlled_program_path("gpg")?;
    let exported = std::process::Command::new(&gpg)
        .arg("--no-options")
        .arg("--batch")
        .arg("--homedir")
        .arg(source_home)
        .arg("--export")
        .args(valid_keys)
        .output()
        .context("Failed to export AUR PGP keys")?;
    let export_stderr =
        crate::cli::style::sanitize_terminal_text(&String::from_utf8_lossy(&exported.stderr));
    anyhow::ensure!(
        exported.status.success() && !exported.stdout.is_empty(),
        "Failed to export AUR PGP keys: {}",
        export_stderr.trim()
    );
    let key_bundle = build_keyring.path().join("trusted-keys.pgp");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&key_bundle)?
        .write_all(&exported.stdout)
        .context("Failed to stage AUR PGP keys")?;
    let imported = std::process::Command::new(&gpg)
        .arg("--no-options")
        .arg("--batch")
        .arg("--homedir")
        .arg(build_keyring.path())
        .arg("--import")
        .arg(&key_bundle)
        .output()
        .context("Failed to initialize package-scoped AUR PGP keyring")?;
    let import_stderr =
        crate::cli::style::sanitize_terminal_text(&String::from_utf8_lossy(&imported.stderr));
    anyhow::ensure!(
        imported.status.success(),
        "Failed to initialize package-scoped AUR PGP keyring: {}",
        import_stderr.trim()
    );
    for key_id in valid_keys {
        anyhow::ensure!(
            keyserver::is_key_in_gnupg(key_id, build_keyring.path())?,
            "Package-scoped AUR PGP keyring is missing {key_id}"
        );
    }
    Ok(build_keyring)
}

fn require_unprivileged_builder(package: &str, is_root: bool) -> Result<()> {
    if is_root {
        anyhow::bail!(
            "AUR packages must not be built as root.\n  \
             → Run omg as your regular user; it will request sudo only for dependency and package installation.\n  \
             → Retry without sudo: omg install {package}"
        );
    }
    Ok(())
}

/// AUR API client with build support
#[derive(Clone)]
pub struct AurClient {
    build_dir: PathBuf,
    settings: Settings,
    package_base_locks: Arc<dashmap::DashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl std::fmt::Debug for AurClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately excludes settings; they may carry user-specific paths.
        f.debug_struct("AurClient")
            .field("build_dir", &self.build_dir)
            // `settings` deliberately omitted: may carry user-specific paths.
            .finish_non_exhaustive()
    }
}

struct MakepkgEnv {
    // Own the private invocation tree until archives have been sealed.
    _invocation: tempfile::TempDir,
    makeflags: String,
    pkgdest: PathBuf,
    srcdest: PathBuf,
    builddir: PathBuf,
    compiler_cache_dirs: Vec<PathBuf>,
    extra_env: Vec<(String, String)>,
    pgp_home: Option<tempfile::TempDir>,
}

fn reproducible_source_epoch(source_digest: &str) -> Result<String> {
    let prefix = source_digest
        .get(..16)
        .context("Reviewed AUR source digest is truncated")?;
    let value = u64::from_str_radix(prefix, 16).context("Reviewed AUR source digest is invalid")?;
    // SOURCE_DATE_EPOCH is the reproducible-build ecosystem's standard input
    // for timestamps that would otherwise vary between builds. Deriving it
    // solely from the reviewed source preserves that invariant without trusting
    // repository-controlled Git metadata.
    // https://reproducible-builds.org/specs/source-date-epoch/
    // Arch makepkg unifies source/package mtimes and package metadata when this
    // variable is set: https://man.archlinux.org/man/makepkg.8#REPRODUCIBILITY
    Ok((946_684_800_u64 + value % 1_577_923_200).to_string())
}

fn set_reproducible_source_epoch(env: &mut MakepkgEnv, source: &ReviewedSource) -> Result<()> {
    env.extra_env.retain(|(key, _)| key != "SOURCE_DATE_EPOCH");
    env.extra_env.push((
        "SOURCE_DATE_EPOCH".to_owned(),
        reproducible_source_epoch(&source.digest)?,
    ));
    Ok(())
}

/// Change only the newly created invocation directory, using its open handle.
/// Children must be created after this succeeds when setup was elevated.
fn prepare_invocation_directory(
    path: &Path,
    owner: Option<(nix::unistd::Uid, nix::unistd::Gid)>,
) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let metadata = directory.metadata()?;
    anyhow::ensure!(
        metadata.is_dir()
            && metadata.uid() == nix::unistd::geteuid().as_raw()
            && metadata.mode() & 0o777 == 0o700,
        "AUR invocation must be a private directory owned by its creator"
    );
    if let Some((uid, gid)) = owner {
        nix::unistd::fchown(&directory, Some(uid), Some(gid))
            .context("Failed to assign the private AUR invocation to the build user")?;
        let metadata = directory.metadata()?;
        anyhow::ensure!(
            metadata.uid() == uid.as_raw()
                && metadata.gid() == gid.as_raw()
                && metadata.mode() & 0o777 == 0o700,
            "AUR invocation ownership or permissions did not match the build user"
        );
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct AuthorizedBuild {
    // Keep cleanup excluded across the review-to-build handoff and dependency work.
    lifecycle_guard: BuildLifecycleLease,
    package: String,
    requested_outputs: Vec<String>,
    reviewed_digest: ReviewedSource,
}

/// Sealed outputs admitted under the build's actual security profile.
#[derive(Debug)]
pub(crate) struct BuiltPackages {
    archives: Vec<ArchiveSnapshot>,
    profile: AurSecurityProfile,
    requested_outputs: BTreeSet<String>,
}

impl BuiltPackages {
    pub(crate) fn len(&self) -> usize {
        self.archives.len()
    }

    fn require_profile(&self, current: AurSecurityProfile) -> Result<()> {
        anyhow::ensure!(
            current != AurSecurityProfile::Hardened || self.profile == AurSecurityProfile::Hardened,
            "Packages built under the Standard AUR profile cannot be installed under the current Hardened profile; rebuild them under Hardened settings"
        );
        Ok(())
    }
}

/// The exact local source files approved before any build command runs.
#[derive(Debug)]
struct ReviewedSource {
    files: std::collections::BTreeMap<PathBuf, Vec<u8>>,
    digest: String,
    parsed_srcinfo: OnceLock<Arc<alpm_srcinfo::SourceInfoV1>>,
}

impl ReviewedSource {
    fn read_source_file(path: &Path) -> Result<Vec<u8>> {
        super::source_file::read_regular(path)
    }
    fn capture(directory: &Path) -> Result<Self> {
        fn visit(
            root: &Path,
            directory: &Path,
            files: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>,
            budget: &mut usize,
            entries: &mut usize,
            depth: usize,
        ) -> Result<()> {
            anyhow::ensure!(depth <= 64, "AUR source nesting exceeds limit");
            for entry in std::fs::read_dir(directory)? {
                let entry = entry?;
                *entries += 1;
                anyhow::ensure!(*entries <= 10_000, "AUR source entry count exceeds limit");
                if entry.file_name() == ".git" {
                    continue;
                }
                let path = entry.path();
                let metadata = std::fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink() {
                    let relative = path.strip_prefix(root)?.to_owned();
                    anyhow::ensure!(
                        relative.as_path() != Path::new("PKGBUILD")
                            && relative.as_path() != Path::new(".SRCINFO"),
                        "AUR {} must be a regular file, not a symlink",
                        review_path(&relative)
                    );
                    let target = std::fs::read_link(&path)?;
                    contained_aur_symlink_target(root, &path, &target)?;
                    let bytes = encode_symlink_manifest(&target);
                    *budget = budget
                        .checked_add(bytes.len())
                        .context("AUR source size overflow")?;
                    anyhow::ensure!(
                        *budget <= 64 * 1024 * 1024 && files.len() < 10_000,
                        "AUR source manifest exceeds file/count limits"
                    );
                    files.insert(relative, bytes);
                    continue;
                }
                if metadata.is_dir() {
                    visit(root, &path, files, budget, entries, depth + 1)?;
                } else {
                    anyhow::ensure!(
                        metadata.is_file()
                            && metadata.len() <= super::source_file::MAX_SOURCE_FILE_BYTES
                            && files.len() < 10_000,
                        "AUR source manifest exceeds file/count limits"
                    );
                    let bytes = ReviewedSource::read_source_file(&path)?;
                    *budget = budget
                        .checked_add(bytes.len())
                        .context("AUR source size overflow")?;
                    anyhow::ensure!(
                        *budget <= 64 * 1024 * 1024,
                        "AUR source manifest exceeds 64 MiB"
                    );
                    files.insert(path.strip_prefix(root)?.to_owned(), bytes);
                }
            }
            Ok(())
        }
        let mut files = std::collections::BTreeMap::new();
        visit(directory, directory, &mut files, &mut 0, &mut 0, 0)?;
        anyhow::ensure!(
            files.contains_key(Path::new("PKGBUILD")) && files.contains_key(Path::new(".SRCINFO")),
            "AUR review requires PKGBUILD and .SRCINFO"
        );
        let mut hash = Sha256::new();
        for (path, bytes) in &files {
            let path = path.to_str().context("AUR source path is not UTF-8")?;
            use std::os::unix::fs::PermissionsExt;
            hash.update(
                std::fs::symlink_metadata(directory.join(path))?
                    .permissions()
                    .mode()
                    .to_le_bytes(),
            );
            hash.update((path.len() as u64).to_le_bytes());
            hash.update(path.as_bytes());
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
        }
        Ok(Self {
            files,
            digest: hex::encode(hash.finalize()),
            parsed_srcinfo: OnceLock::new(),
        })
    }

    fn optional_srcinfo(&self) -> Result<Option<Arc<alpm_srcinfo::SourceInfoV1>>> {
        if let Some(parsed) = self.parsed_srcinfo.get() {
            return Ok(Some(Arc::clone(parsed)));
        }
        let Some(bytes) = self.files.get(Path::new(".SRCINFO")) else {
            return Ok(None);
        };
        let content = std::str::from_utf8(bytes).context("Failed to read .SRCINFO")?;
        let parsed = Arc::new(
            alpm_srcinfo::SourceInfoV1::from_string(content).context("Failed to parse .SRCINFO")?,
        );
        let _ = self.parsed_srcinfo.set(Arc::clone(&parsed));
        Ok(Some(Arc::clone(
            self.parsed_srcinfo.get().unwrap_or(&parsed),
        )))
    }

    fn required_srcinfo(&self, package: &str) -> Result<Arc<alpm_srcinfo::SourceInfoV1>> {
        self.optional_srcinfo()
            .with_context(|| format!("Failed to inspect dependencies for '{package}'"))?
            .with_context(|| format!(
            "AUR package '{package}' has no regular .SRCINFO; refusing to source its PKGBUILD to discover dependencies"
        ))
    }

    fn verify(&self, directory: &Path) -> Result<()> {
        let current = Self::capture(directory)?;
        anyhow::ensure!(
            current.digest == self.digest,
            "AUR source manifest changed after review"
        );
        Ok(())
    }
    fn text(&self, path: &Path) -> Result<&str> {
        let bytes = self
            .files
            .get(path)
            .with_context(|| format!("Unreviewed AUR input: {}", review_path(path)))?;
        Ok(std::str::from_utf8(bytes)?)
    }

    fn recomputes_version(&self) -> Result<bool> {
        Ok(self.text(Path::new("PKGBUILD"))?.lines().any(|line| {
            line.trim_start().starts_with("pkgver()") || line.trim_start().starts_with("pkgver ()")
        }))
    }
}

fn encode_symlink_manifest(target: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    let mut bytes = Vec::from(&b"symlink\0"[..]);
    bytes.extend_from_slice(target.as_os_str().as_bytes());
    bytes
}

/// Require both lexical and resolved containment; intermediate symlinks can
/// otherwise change the meaning of parent components.
fn contained_aur_symlink_target(root: &Path, link_path: &Path, target: &Path) -> Result<()> {
    let link_display = review_path(link_path);
    let target_display = review_path(target);
    let mut resolved = link_path
        .parent()
        .map_or_else(|| root.to_path_buf(), Path::to_path_buf);
    for component in target.components() {
        match component {
            std::path::Component::Normal(part) => resolved.push(part),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                anyhow::ensure!(
                    resolved.starts_with(root) && resolved != root && resolved.pop(),
                    "AUR source symlink escapes the checkout: {link_display} -> {target_display}"
                );
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                anyhow::bail!(
                    "AUR source symlink must be relative: {link_display} -> {target_display}"
                );
            }
        }
    }
    anyhow::ensure!(
        resolved.starts_with(root) && resolved != root,
        "AUR source symlink escapes the checkout: {link_display} -> {target_display}"
    );
    let canonical_root = root.canonicalize()?;
    let canonical_target = link_path
        .canonicalize()
        .context("AUR source symlink must resolve to a reviewed checkout entry")?;
    anyhow::ensure!(
        canonical_target.starts_with(&canonical_root) && canonical_target != canonical_root,
        "AUR source symlink escapes the checkout: {link_display} -> {target_display}"
    );
    Ok(())
}

#[derive(Debug)]
struct AurDependencyPlan {
    aur_dependencies: Vec<String>,
    official_dependencies: Vec<OfficialTarget>,
    package_outputs: Vec<String>,
}

fn resolve_official_dependency(
    alpm: &alpm::Alpm,
    relation: &str,
) -> Result<Option<OfficialTarget>> {
    for database in alpm.syncdbs() {
        if database.usage()?.contains(alpm::Usage::INSTALL) {
            crate::package_managers::alpm_ops::validate_sync_database(alpm, database)?;
        }
    }
    alpm.syncdbs()
        .find_satisfier(relation)
        .map(|package| {
            Ok(OfficialTarget {
                repository: package
                    .db()
                    .context("Official satisfier has no repository")?
                    .name()
                    .to_owned(),
                name: package.name().to_owned(),
                relations: vec![relation.to_owned()],
            })
        })
        .transpose()
}

fn optional_official_package<T>(
    repository: &str,
    package: &str,
    lookup: alpm::Result<T>,
) -> Result<Option<T>> {
    match lookup {
        Ok(package) => Ok(Some(package)),
        Err(alpm::Error::PkgNotFound) => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("Failed to inspect '{repository}/{package}'"))
        }
    }
}

fn reconcile_official_dependency(alpm: &alpm::Alpm, selected: &mut OfficialTarget) -> Result<()> {
    use crate::package_managers::types::{dependency_version_satisfies, provision_satisfies};

    for database in alpm.syncdbs() {
        if !database.usage()?.contains(alpm::Usage::INSTALL) {
            continue;
        }
        let lookup = database.pkg(selected.name.as_str());
        let candidate = optional_official_package(database.name(), &selected.name, lookup)?;
        let Some(candidate) = candidate else {
            continue;
        };
        if selected.relations.iter().all(|relation| {
            let direct = candidate.name() == dependency_name(relation)
                && dependency_version_satisfies(relation, candidate.version().as_str());
            let provided = candidate
                .provides()
                .into_iter()
                .any(|provided| provision_satisfies(relation, &provided.to_string()));
            direct || provided
        }) {
            database.name().clone_into(&mut selected.repository);
            return Ok(());
        }
    }
    anyhow::bail!(
        "No install-eligible version of '{}' satisfies all required relations: {}",
        selected.name,
        selected.relations.join(", ")
    )
}

/// Identity and .INSTALL payload extracted from one package archive
/// (SEC-R2-01 cached-artifact provenance verification).
struct CachedArchiveIdentity {
    name: String,
    version: String,
    base: String,
    install_script: Option<String>,
    architecture: Option<String>,
}

#[derive(Clone, Copy)]
enum BuildOutputStream {
    Stdout,
    Stderr,
}

/// Route auxiliary command output to inherited stdio in verbose mode or `/dev/null` otherwise.
fn configure_auxiliary_output(command: &mut Command) {
    if crate::cli::modern_ui::output_mode() == crate::cli::modern_ui::OutputMode::Verbose {
        command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    } else {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }
}

/// Give PKGBUILD-driven processes a minimal deterministic environment.
/// Credentials, agent sockets, language injection paths, and caller-specific
/// tokens are absent because the command starts from `env_clear`.
fn configure_build_environment(command: &mut Command, home: &Path, user: &str) {
    command
        .env_clear()
        .env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/bin")
        .env("HOME", home)
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("USER", user)
        .env("LOGNAME", user)
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8");
}

fn native_build_command() -> Result<Command> {
    let mut command = Command::new(crate::core::privilege::root_controlled_program_path(
        "setpriv",
    )?);
    command
        .args(["--no-new-privs", "--"])
        .arg(crate::core::privilege::root_controlled_program_path(
            "setsid",
        )?)
        .args(["-w", "makepkg"]);
    Ok(command)
}

fn chroot_build_command(
    secure_makepkg: bool,
    resolve_program: impl Fn(&str) -> Result<PathBuf>,
) -> Result<Command> {
    let mut command = Command::new(resolve_program("setsid")?);
    command.args(["-w", "--"]).stdin(Stdio::null());
    if let Ok(pkgctl) = resolve_program("pkgctl") {
        command.arg(pkgctl).arg("build");
        if secure_makepkg {
            command.arg("--clean");
        }
    } else if let Ok(makechrootpkg) = resolve_program("makechrootpkg") {
        command
            .arg(makechrootpkg)
            .args(["-r", "/var/lib/archbuild", "--"]);
    } else {
        anyhow::bail!(
            "Chroot build requires devtools (pkgctl/makechrootpkg). Install devtools or choose bubblewrap/native."
        );
    }
    Ok(command)
}

fn sandbox_command(home: &Path, user: &str) -> Result<Command> {
    sandbox_command_with(
        home,
        user,
        crate::core::privilege::root_controlled_program_path,
    )
}

fn sandbox_command_with(
    home: &Path,
    user: &str,
    resolve: impl FnOnce(&str) -> Result<PathBuf>,
) -> Result<Command> {
    let mut command = Command::new(resolve("bwrap")?);
    configure_build_environment(&mut command, home, user);
    command.args([
        "--clearenv",
        "--share-net",
        "--unshare-pid",
        "--unshare-ipc",
        "--new-session",
        "--die-with-parent",
    ]);
    Ok(command)
}

/// Make `/etc/resolv.conf` usable when it points outside the read-only `/etc`
/// mount, as systemd-resolved and NetworkManager commonly do under `/run`.
fn configure_sandbox_resolver(command: &mut Command) -> Result<()> {
    configure_sandbox_resolver_at(command, "/etc/resolv.conf".as_ref())
}

fn configure_sandbox_resolver_at(command: &mut Command, resolver_config: &Path) -> Result<()> {
    let resolver = match resolver_config.canonicalize() {
        Ok(resolved) => resolved,
        // A host without a resolver (container, offline chroot, dangling
        // symlink to an unmounted /run) has nothing to bind; skipping keeps
        // the sandbox identical to the host instead of failing every build.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "Failed to resolve {} for the AUR sandbox",
                    resolver_config.display()
                )
            });
        }
    };
    if resolver.starts_with("/etc") {
        return Ok(());
    }
    anyhow::ensure!(
        resolver.is_file(),
        "AUR sandbox resolver target is not a file: {}",
        resolver.display()
    );

    let mut parents: Vec<_> = resolver
        .parent()
        .into_iter()
        .flat_map(Path::ancestors)
        .filter(|path| *path != Path::new("/"))
        .collect();
    parents.reverse();
    for parent in parents {
        command.arg("--dir").arg(parent);
    }
    command.arg("--ro-bind").arg(&resolver).arg(&resolver);
    Ok(())
}

fn build_identity() -> (String, PathBuf) {
    let user =
        build_user().unwrap_or_else(|| whoami::username().unwrap_or_else(|_| "nobody".into()));
    let home = std::env::var_os("SUDO_HOME")
        .map(PathBuf::from)
        .or_else(home::home_dir)
        .unwrap_or_else(|| PathBuf::from(format!("/home/{user}")));
    (user, home)
}

fn pkgbuild_review_text(bytes: &[u8]) -> Result<String> {
    anyhow::ensure!(
        bytes.len() <= MAX_PKGBUILD_REVIEW_BYTES,
        "PKGBUILD exceeds the {MAX_PKGBUILD_REVIEW_BYTES} byte review limit"
    );
    let text = String::from_utf8_lossy(bytes);
    Ok(text
        .chars()
        .filter(|character| {
            matches!(character, '\n' | '\t')
                || (!character.is_control()
                    && !matches!(
                        character,
                        '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
                    ))
        })
        .collect())
}

/// SHA-256 hex digest of raw PKGBUILD bytes.
fn pkgbuild_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Re-read `pkgbuild_path` and confirm its bytes still hash to the digest the
/// user reviewed. A mismatch means the PKGBUILD changed between review and
/// build and the reviewed script is not the one about to run.
#[cfg(test)]
fn verify_reviewed_pkgbuild(pkgbuild_path: &Path, reviewed_digest: &str) -> Result<()> {
    let bytes = std::fs::read(pkgbuild_path)
        .with_context(|| format!("Failed to re-read PKGBUILD: {}", pkgbuild_path.display()))?;
    anyhow::ensure!(
        pkgbuild_digest(&bytes) == reviewed_digest,
        "PKGBUILD changed after review: {} (refusing to build a script the user did not review)",
        pkgbuild_path.display()
    );
    Ok(())
}

/// Diagnostic preview: threat-relevant assignments first, then fill. The
/// SHA-256 still covers every byte of every reviewed file.
const MAX_PKGBUILD_PREVIEW_LINES: usize = 8;
const PREVIEW_LINE_CHARS: usize = 96;
const PREVIEW_ASSIGNMENTS: &[&str] = &[
    "source",
    "sha256sums",
    "sha512sums",
    "b2sums",
    "install",
    "url",
    "depends",
    "pkgver",
];

fn assignment_name(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let name = trimmed.split(['=', '(']).next()?.trim();
    if name.is_empty() {
        return None;
    }
    name.chars()
        .all(|character| character == '_' || character.is_ascii_alphanumeric())
        .then_some(name)
}

fn pkgbuild_maintainer(text: &str) -> Option<String> {
    for line in text.lines().take(30) {
        let trimmed = line.trim();
        let Some(rest) = trimmed
            .strip_prefix("# Maintainer:")
            .or_else(|| trimmed.strip_prefix("# Contributor:"))
        else {
            continue;
        };
        let cleaned = crate::cli::style::sanitize_terminal_text(rest.trim());
        if !cleaned.is_empty() {
            return Some(cleaned);
        }
    }
    None
}

fn preview_pkgbuild_lines(text: &str, limit: usize) -> Vec<(usize, String)> {
    let numbered: Vec<(usize, &str)> = text
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line))
        .collect();
    let mut picked = Vec::new();
    let mut used = std::collections::HashSet::new();
    for (number, line) in &numbered {
        let Some(name) = assignment_name(line) else {
            continue;
        };
        if !PREVIEW_ASSIGNMENTS.contains(&name) {
            continue;
        }
        if used.insert(*number) {
            picked.push((*number, (*line).to_string()));
        }
        if picked.len() >= limit {
            return picked;
        }
    }
    for (number, line) in numbered {
        if used.contains(&number) {
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        picked.push((number, line.to_string()));
        if picked.len() >= limit {
            break;
        }
    }
    picked
}

fn join_limited(values: &[String], cap: usize) -> String {
    if values.len() <= cap {
        values
            .iter()
            .map(|value| crate::cli::style::sanitize_terminal_text(value))
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        let shown = values[..cap]
            .iter()
            .map(|value| crate::cli::style::sanitize_terminal_text(value))
            .collect::<Vec<_>>()
            .join(", ");
        format!("{shown}, +{} more", values.len() - cap)
    }
}

struct AurReviewFiles<'a> {
    relative: &'a Path,
    bytes: usize,
    digest: String,
}

/// Keep untrusted source names visible as single-line data, including literal
/// backslashes, controls and invisible Unicode. Filesystem and hash inputs
/// retain their original bytes.
fn review_path(path: &Path) -> String {
    path.to_string_lossy().escape_debug().to_string()
}

fn pkgbuild_review_panel(
    package: &str,
    digest: &str,
    review: &str,
    pkgbuild_path: &Path,
    extra_files: &[AurReviewFiles<'_>],
    install_hooks: &[(String, String)],
    verbose: bool,
) -> String {
    use crate::cli::chrome;

    let package = crate::cli::style::sanitize_terminal_text(package);
    let trimmed = review.trim_end();
    let total_lines = trimmed.lines().count();
    let meta = crate::package_managers::pkgbuild::PkgBuild::parse_content(trimmed).ok();
    let version = meta.as_ref().map(|pkg| {
        format!(
            "{}-{}",
            crate::cli::style::sanitize_terminal_text(&pkg.version.to_string()),
            crate::cli::style::sanitize_terminal_text(&pkg.release)
        )
    });
    let url = meta.as_ref().and_then(|pkg| {
        let url = crate::cli::style::sanitize_terminal_text(&pkg.url);
        (!url.is_empty()).then_some(url)
    });
    let depends = meta
        .as_ref()
        .filter(|pkg| !pkg.depends.is_empty())
        .map(|pkg| join_limited(&pkg.depends, 5));
    let maintainer = pkgbuild_maintainer(trimmed);

    let mut lines = Vec::new();
    lines.push(String::new());
    if crate::cli::style::colors_enabled() {
        lines.push(format!(
            "  {}  {}  {}",
            chrome::accent_rail(),
            "AUR".bold(),
            package.bold()
        ));
    } else {
        lines.push(format!("  {}  AUR  {package}", chrome::accent_rail()));
    }
    lines.push(chrome::rail_line(""));
    lines.push(chrome::rail_line(&chrome::digest_stripe(digest)));
    lines.push(chrome::rail_line(""));

    let package_value = match version {
        Some(version) => format!("{package}  {version}"),
        None => package,
    };
    lines.push(chrome::kv("package", &package_value));
    if let Some(url) = url {
        lines.push(chrome::kv("url", &chrome::osc8_http(&url, &url)));
    }
    if let Some(depends) = depends {
        lines.push(chrome::kv("depends", &depends));
    }
    if let Some(maintainer) = maintainer {
        lines.push(chrome::kv("maint", &maintainer));
    }

    let mut file_names = vec!["PKGBUILD".to_string()];
    file_names.extend(extra_files.iter().map(|file| review_path(file.relative)));
    lines.push(chrome::kv("files", &file_names.join("  ")));
    lines.push(chrome::kv("sha-256", digest));
    lines.push(chrome::kv(
        "open",
        &chrome::osc8_file(pkgbuild_path, &review_path(pkgbuild_path)),
    ));
    lines.push(chrome::rail_line(""));

    if verbose {
        for (number, line) in trimmed.lines().enumerate() {
            lines.push(chrome::snippet_line(number + 1, line));
        }
        for file in extra_files {
            lines.push(chrome::rail_line(""));
            lines.push(chrome::kv(
                "file",
                &format!(
                    "{}  {} B  {}",
                    review_path(file.relative),
                    file.bytes,
                    file.digest
                ),
            ));
        }
    } else {
        let preview = preview_pkgbuild_lines(trimmed, MAX_PKGBUILD_PREVIEW_LINES);
        for (number, line) in preview {
            lines.push(chrome::snippet_line(
                number,
                &chrome::truncate_chars(&line, PREVIEW_LINE_CHARS),
            ));
        }
        lines.push(chrome::rail_line(""));
        lines.push(chrome::rail_line(&format!(
            "{} of {total_lines} lines · remaining source hashed, not printed",
            MAX_PKGBUILD_PREVIEW_LINES.min(total_lines)
        )));
        lines.push(chrome::rail_line("omg -v dumps the full PKGBUILD"));
        lines.push(chrome::rail_line(
            "user-submitted · digest seals every reviewed file",
        ));
    }

    // Pacman executes declared install hooks as root after the unprivileged
    // build, so their contents belong in the approval decision, not just
    // their digests. The archived .INSTALL is later byte-checked against
    // these reviewed bytes before any root installation.
    for (name, contents) in install_hooks {
        lines.push(chrome::rail_line(""));
        lines.push(chrome::kv("hook", &review_path(Path::new(name))));
        for (number, line) in contents.lines().enumerate() {
            lines.push(chrome::snippet_line(number + 1, line));
        }
    }

    lines.join("\n")
}

fn pkgbuild_review_prompt(package: &str) -> String {
    let package = crate::cli::style::sanitize_terminal_text(package);
    format!("Build {package} from this PKGBUILD?")
}

/// Every `.SRCINFO`-declared install script with its reviewed contents,
/// rendered for the approval panel. These hooks run as root during the
/// privileged install, so approval must cover their bytes (csf_b6e85633),
/// and the archived `.INSTALL` is byte-checked against the same reviewed
/// bytes before installation.
fn declared_install_hook_previews(source: &ReviewedSource) -> Result<Vec<(String, String)>> {
    let mut names: Vec<String> = Vec::new();
    {
        let srcinfo = source.text(Path::new(".SRCINFO"))?;
        for line in srcinfo.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim();
            if key.trim() == "install"
                && !value.is_empty()
                && !names.iter().any(|name| name == value)
            {
                names.push(value.to_owned());
            }
        }
    }
    names
        .into_iter()
        .map(|name| {
            let display_name = review_path(Path::new(&name));
            let bytes = source
                .files
                .get(Path::new(&name))
                .with_context(|| format!("Declared install hook is absent: {display_name}"))?;
            anyhow::ensure!(
                bytes.len() <= MAX_PKGBUILD_REVIEW_BYTES,
                "Install hook {display_name} exceeds the review limit"
            );
            let text = std::str::from_utf8(bytes)
                .with_context(|| format!("Install hook {display_name} is not UTF-8"))?;
            // Make control/bidi bytes visible instead of silently removing them.
            let contents = text
                .chars()
                .map(|character| {
                    if character != '\n'
                        && (character.is_control()
                            || matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'))
                    {
                        character.escape_default().to_string()
                    } else {
                        character.to_string()
                    }
                })
                .collect::<String>();
            Ok((name, contents))
        })
        .collect()
}

#[cfg(test)]
fn pkgbuild_review_summary(package: &str, digest: &str, file_count: usize) -> String {
    use crate::cli::chrome;
    let package = crate::cli::style::sanitize_terminal_text(package);
    let short = if digest.len() > 12 {
        format!("{}…", &digest[..12])
    } else {
        digest.to_string()
    };
    let files = if file_count == 1 {
        "1 file".to_string()
    } else {
        format!("{file_count} files")
    };
    if crate::cli::style::colors_enabled() {
        format!(
            "  {}  {}  {package}  {}  {files}",
            chrome::accent_rail(),
            "AUR".bold(),
            short.dimmed()
        )
    } else {
        format!("  |  AUR  {package}  {short}  {files}")
    }
}

async fn confirm_prompt(prompt: String, default: bool) -> Result<bool> {
    Ok(tokio::task::spawn_blocking(move || {
        Confirm::with_theme(&crate::cli::ui::prompt_theme())
            .with_prompt(prompt)
            .default(default)
            .interact()
    })
    .await
    .context("PKGBUILD review prompt task failed")??)
}

struct BuildLog {
    file: tokio::fs::File,
    bytes: u64,
    limit: u64,
}

#[derive(Clone, Copy)]
enum BuildIsolation {
    ProcessGroup,
    NativeSession,
}

struct BuildProcess {
    child: Option<tokio::process::Child>,
    group: u32,
    reaper: tokio::runtime::Handle,
}

impl BuildProcess {
    fn terminate(&mut self) -> Result<()> {
        // Stop the launcher first: setsid may not have established the
        // session yet. Once killed, it cannot create descendants after killpg.
        let launcher_result = self.child.as_mut().map_or(Ok(()), |child| {
            child
                .start_kill()
                .context("Failed to stop AUR build launcher")
        });
        let group_result = terminate_build_group(self.group);
        launcher_result?;
        group_result
    }

    async fn terminate_and_reap(&mut self) -> Result<()> {
        self.terminate()?;
        if let Some(child) = &mut self.child {
            child.wait().await.context("Failed to reap AUR build")?;
        }
        self.child = None;
        Ok(())
    }
}

impl Drop for BuildProcess {
    fn drop(&mut self) {
        if self.child.is_none() {
            return;
        }
        if let Err(error) = self.terminate() {
            tracing::warn!(%error, "Failed to terminate cancelled AUR build");
        }
        if let Some(mut child) = self.child.take() {
            // Caller cancellation cannot await here. Keep the Child owned by a
            // reap task instead of relying only on Tokio's best-effort Drop.
            self.reaper.spawn(async move {
                if let Err(error) = child.wait().await {
                    tracing::warn!(%error, "Failed to reap cancelled AUR build");
                }
            });
        }
    }
}

fn terminate_build_group(group: u32) -> Result<()> {
    use nix::errno::Errno;
    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::Pid;

    let group = i32::try_from(group).context("AUR build process ID exceeded i32")?;
    match killpg(Pid::from_raw(group), Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(error).context("Failed to terminate AUR build process group"),
    }
}

async fn drain_build_output<R>(
    mut reader: R,
    log: Arc<tokio::sync::Mutex<BuildLog>>,
    stream: BuildOutputStream,
    verbose: bool,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = [0_u8; 16 * 1024];
    let mut terminal_writable = verbose;
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();

    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let chunk = &buffer[..read];

        {
            let mut log = log.lock().await;
            let next = log
                .bytes
                .checked_add(read as u64)
                .ok_or_else(|| std::io::Error::other("AUR build log byte count overflowed"))?;
            if next > log.limit {
                return Err(std::io::Error::other(
                    "AUR build log exceeded its byte limit",
                ));
            }
            log.file.write_all(chunk).await?;
            log.bytes = next;
        }

        if terminal_writable {
            let result = match stream {
                BuildOutputStream::Stdout => stdout.write_all(chunk).await,
                BuildOutputStream::Stderr => stderr.write_all(chunk).await,
            };
            if result.is_err() {
                // A closed output consumer must not stop us draining the child.
                terminal_writable = false;
            }
        }
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct AurResponse {
    results: Vec<AurJsonPackage>,
}

/// Request diagnostics safe to retain without remote text or transport URLs.
#[derive(Debug, thiserror::Error)]
enum AurRpcRequestError {
    #[error("AUR RPC request to {AUR_RPC_URL} returned HTTP {0}")]
    Http(reqwest::StatusCode),
    #[error("AUR RPC transport failed. Check your internet connection.")]
    Transport,
}

fn ensure_aur_rpc_success(status: reqwest::StatusCode) -> Result<()> {
    anyhow::ensure!(status.is_success(), AurRpcRequestError::Http(status));
    Ok(())
}

pub(crate) fn update_source_unavailable(error: &anyhow::Error) -> bool {
    match error.downcast_ref::<AurRpcRequestError>() {
        Some(AurRpcRequestError::Transport) => true,
        Some(AurRpcRequestError::Http(status)) => crate::core::http::is_retryable_status(*status),
        None => false,
    }
}

fn decode_aur_rpc_body<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    let value: serde_json::Value =
        serde_json::from_slice(body).context("Failed to parse AUR RPC response")?;
    if value.get("type").and_then(serde_json::Value::as_str) == Some("error") {
        let detail = value
            .get("error")
            .and_then(serde_json::Value::as_str)
            .filter(|message| !message.trim().is_empty())
            .unwrap_or("unknown AUR RPC error");
        anyhow::bail!("AUR RPC returned an error: {detail}");
    }

    serde_json::from_value(value).context("Failed to parse AUR RPC response")
}

async fn decode_aur_rpc_response<T: DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    ensure_aur_rpc_success(response.status())?;
    let body = crate::core::http::bounded_metadata_body(response)
        .await
        .map_err(|error| match error.downcast::<reqwest::Error>() {
            Ok(error) => redact_aur_transport_error(error),
            Err(error) => error,
        })?;
    decode_aur_rpc_body(&body)
}

fn redact_aur_transport_error(_: reqwest::Error) -> anyhow::Error {
    AurRpcRequestError::Transport.into()
}

async fn finish_metadata_read(
    worker: tokio::task::JoinHandle<Result<Option<AurIndex>>>,
) -> Option<AurIndex> {
    match worker.await {
        Ok(Ok(index)) => index,
        Ok(Err(error)) => {
            warn!("Failed to open fresh AUR metadata: {error:#}");
            None
        }
        Err(error) => {
            warn!("AUR metadata freshness worker failed: {error}");
            None
        }
    }
}

impl AurClient {
    pub fn new() -> Result<Self> {
        let settings = Settings::load().context("Failed to load OMG settings for AUR")?;
        let build_dir = paths::cache_dir().join("aur");

        Ok(Self {
            build_dir,
            settings,
            package_base_locks: Arc::new(dashmap::DashMap::new()),
        })
    }

    fn open_lifecycle_lock(&self) -> Result<File> {
        super::utils::open_build_lifecycle_lock(&self.build_dir)
    }

    /// File ownership spans async build work intentionally. Acquisition never
    /// waits, and cleanup never waits for builders, so this cannot block an
    /// executor thread behind a task holding the same lifecycle lock.
    async fn acquire_build_lifecycle(&self) -> Result<BuildLifecycleLease> {
        let client = self.clone();
        tokio::task::spawn_blocking(move || {
            let file = client.open_lifecycle_lock()?;
            BuildLifecycleLease::try_shared(file)
                .context("Failed to acquire AUR build ownership; cleanup may be active")
        })
        .await
        .context("AUR lifecycle lock worker failed")?
    }

    fn package_base_lock(&self, package_base: &str) -> Arc<tokio::sync::Mutex<()>> {
        Arc::clone(
            self.package_base_locks
                .entry(package_base.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .value(),
        )
    }

    fn package_base_marker(package_base: &str) -> String {
        format!("pkgbase:{package_base}")
    }

    async fn acquire_package_base_file_lock(&self, package_base: &str) -> Result<File> {
        let lock_dir = self.build_dir.join("_locks");
        create_dir_as_user(&lock_dir).await?;
        let lock_path = lock_dir.join(format!("{package_base}.lock"));
        self.blocking_build_work(move || -> Result<File> {
            let file = super::utils::open_effective_user_lock(&lock_path)?;
            file.lock().with_context(|| {
                format!("Failed to acquire AUR build lock {}", lock_path.display())
            })?;
            Ok(file)
        })
        .await
        .context("AUR build lock worker failed")
    }

    async fn blocking_build_work<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let lease = self.acquire_build_lifecycle().await?;
        tokio::task::spawn_blocking(move || {
            let _lease = lease;
            work()
        })
        .await
        .context("AUR blocking worker failed")?
    }

    #[must_use]
    pub fn build_concurrency(&self) -> usize {
        self.settings.aur.build_concurrency.max(1)
    }

    async fn fresh_metadata_index(&self) -> Option<AurIndex> {
        if !self.settings.aur.use_metadata_archive {
            return None;
        }

        let ttl = Duration::from_secs(self.settings.aur.metadata_cache_ttl_secs);
        finish_metadata_read(tokio::task::spawn_blocking(move || {
            open_fresh_metadata_index(ttl)
        }))
        .await
    }

    /// Search AUR packages
    pub async fn search(&self, query: &str) -> Result<Vec<Package>> {
        validate_aur_search_query(query)?;

        // Try the binary index only while its source archive is within the
        // configured TTL. Stale indexes fall through to the live RPC.
        if let Some(index) = self.fresh_metadata_index().await {
            let query_owned = query.to_string();
            let packages = tokio::task::spawn_blocking(move || -> Vec<Package> {
                // Install resolution consumes this bounded search: reserve its
                // exact source/binary identities before substring matches fill it.
                let binary_name = format!("{query_owned}-bin");
                let mut entries = Vec::with_capacity(50);
                for name in [query_owned.as_str(), binary_name.as_str()] {
                    if let Some(entry) = index.get(name) {
                        entries.push(entry);
                    }
                }
                for entry in index.search(&query_owned, 50) {
                    if entries.len() == 50 {
                        break;
                    }
                    if !entries
                        .iter()
                        .any(|selected| selected.name.as_str() == entry.name.as_str())
                    {
                        entries.push(entry);
                    }
                }
                entries
                    .into_iter()
                    .filter_map(|entry| {
                        let name = entry.name.as_str();
                        if let Err(error) = validate_index_entry_name(name, None) {
                            warn!("Rejecting AUR index entry '{name}': {error}");
                            return None;
                        }
                        // AUR metadata is an untrusted boundary: a version
                        // that fails the strict parser must not compare as a
                        // fabricated 0 (ARCH-R14); reject the entry visibly.
                        let Some(version) =
                            crate::package_managers::parse_version(entry.version.as_str())
                        else {
                            warn!(
                                "Rejecting AUR index entry '{name}': unparseable version '{}'",
                                entry.version.as_str()
                            );
                            return None;
                        };
                        Some(Package {
                            name: name.to_string(),
                            version,
                            description: entry
                                .description
                                .as_ref()
                                .map(|description| description.as_str().to_string())
                                .unwrap_or_default(),
                            source: PackageSource::Aur,
                            installed: false,
                        })
                    })
                    .collect()
            })
            .await?;

            if !packages.is_empty() {
                return Ok(packages);
            }
        }

        let url = format!(
            "{AUR_RPC_URL}?v=5&type=search&arg={}",
            urlencoding::encode(query)
        );

        let response = shared_client().get(&url).send().await.map_err(|error| {
            let error = redact_aur_transport_error(error);
            tracing::warn!("AUR search network error: {error}");
            error
        })?;
        let response: AurResponse = decode_aur_rpc_response(response).await?;

        let mut packages: Vec<Package> = response
            .results
            .into_iter()
            .filter(|p| {
                crate::core::security::validate_package_name(&p.name)
                    .inspect_err(|e| {
                        tracing::warn!(
                            "Rejecting invalid package name from AUR search: {} ({})",
                            p.name,
                            e
                        );
                    })
                    .is_ok()
            })
            .filter_map(|p| {
                // AUR RPC metadata is an untrusted boundary: a version that
                // fails the strict parser must not compare as a fabricated 0
                // (ARCH-R14); reject the entry visibly.
                let Some(version) = crate::package_managers::parse_version(&p.version) else {
                    tracing::warn!(
                        "Rejecting AUR search result '{}' with unparseable version '{}'",
                        p.name,
                        p.version
                    );
                    return None;
                };
                Some(Package {
                    name: p.name,
                    version,
                    description: p.description.unwrap_or_default(),
                    source: PackageSource::Aur,
                    installed: false,
                })
            })
            .collect();

        // Rank exact, prefix, and word-boundary matches before shorter names.
        // Pre-compute lowercased names to avoid O(n log n) allocations during sort
        let query_lower = query.to_ascii_lowercase();

        // Precompute sort keys: (exact, prefix, word_boundary, name_len, name_lower, original_idx)
        let mut keyed: Vec<_> = packages
            .into_iter()
            .map(|pkg| {
                let name_lower = pkg.name.to_ascii_lowercase();
                let exact = name_lower == query_lower;
                let prefix = name_lower.starts_with(&query_lower);
                let word = has_word_boundary_match(&name_lower, &query_lower);
                (exact, prefix, word, pkg.name.len(), name_lower, pkg)
            })
            .collect();

        // Sort using precomputed keys - no allocations during comparison
        keyed.sort_by(|a, b| {
            // Exact matches first
            if a.0 != b.0 {
                return b.0.cmp(&a.0);
            }
            // Prefix matches second
            if a.1 != b.1 {
                return b.1.cmp(&a.1);
            }
            // Word boundary matches third
            if a.2 != b.2 {
                return b.2.cmp(&a.2);
            }
            // Shorter names (more specific) fourth
            match a.3.cmp(&b.3) {
                std::cmp::Ordering::Equal => a.4.cmp(&b.4), // Alphabetical by lowercase
                other => other,
            }
        });

        // Extract sorted packages
        packages = keyed.into_iter().map(|(_, _, _, _, _, pkg)| pkg).collect();

        Ok(packages)
    }

    /// Get info for a specific AUR package
    pub async fn info(&self, package: &str) -> Result<Option<Package>> {
        // SECURITY: Validate package name
        crate::core::security::validate_package_name(package)?;

        // Try the binary index only while its source archive is fresh.
        if let Some(index) = self.fresh_metadata_index().await {
            let package_owned = package.to_string();
            let result = tokio::task::spawn_blocking(move || -> Result<Option<Package>> {
                if let Some(entry) = index.get(&package_owned) {
                    validate_index_entry_name(entry.name.as_str(), Some(&package_owned))?;
                    // A corrupt index version must not compare as a fabricated
                    // 0 (ARCH-R14); surface a typed error so the caller falls
                    // back to the live RPC for this package.
                    let version = crate::package_managers::parse_version(entry.version.as_str())
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "AUR index entry '{}' has an unparseable version '{}'",
                                entry.name.as_str(),
                                entry.version.as_str()
                            )
                        })?;
                    return Ok(Some(Package {
                        name: entry.name.as_str().to_string(),
                        version,
                        description: entry
                            .description
                            .as_ref()
                            .map(|s| s.as_str().to_string())
                            .unwrap_or_default(),
                        source: PackageSource::Aur,
                        installed: false,
                    }));
                }
                Ok(None)
            })
            .await?;

            match result {
                Ok(Some(package)) => return Ok(Some(package)),
                Ok(None) => {}
                Err(error) => warn!("AUR index lookup failed; falling back to RPC: {error}"),
            }
        }

        let url = format!(
            "{AUR_RPC_URL}?v=5&type=info&arg={}",
            urlencoding::encode(package)
        );

        let response = shared_client().get(&url).send().await.map_err(|error| {
            let error = redact_aur_transport_error(error);
            tracing::warn!("AUR info network error: {error}");
            error
        })?;
        let response: AurResponse = decode_aur_rpc_response(response).await?;

        let Some(p) = response.results.into_iter().next() else {
            return Ok(None);
        };
        crate::core::security::validate_package_name(&p.name)
            .context("AUR returned an invalid package name")?;
        if p.name != package {
            anyhow::bail!(
                "AUR returned unexpected package '{0}' for '{package}'",
                p.name
            );
        }

        // AUR RPC metadata is an untrusted boundary: a version that fails the
        // strict parser must fail the lookup with a typed error instead of
        // comparing as a fabricated 0 (ARCH-R14).
        let version = crate::package_managers::parse_version(&p.version).with_context(|| {
            format!(
                "AUR returned an unparseable version '{}' for '{}'",
                p.version, p.name
            )
        })?;

        Ok(Some(Package {
            name: p.name,
            version,
            description: p.description.unwrap_or_default(),
            source: PackageSource::Aur,
            installed: false,
        }))
    }

    /// Get list of upgradable AUR packages
    /// Queries AUR directly for all non-official packages (like yay/paru)
    #[instrument(skip(self))]
    pub async fn get_update_list(&self) -> Result<Vec<(String, Version, Version)>> {
        // 1. Get all packages not in official repos
        let (foreign_packages, installed) = tokio::task::spawn_blocking(|| -> Result<_> {
            let packages = pacman_db::get_potential_aur_package_records()?;
            if packages.is_empty() {
                return Ok((Vec::new(), Arc::new(HashMap::new())));
            }
            let config = crate::core::pacman_conf::PacmanConfig::parse(paths::pacman_conf_path())
                .context("Failed to load AUR update filters from pacman.conf")?;
            let ignored = pacman_db::compile_package_patterns(&config.ignore_pkg, "IgnorePkg")?;
            let ignored_groups =
                pacman_db::compile_package_patterns(&config.ignore_group, "IgnoreGroup")?;
            let mut retained = Vec::with_capacity(packages.len());
            let mut installed = HashMap::with_capacity(packages.len());
            for package in packages {
                if ignored.is_match(&package.name) {
                    continue;
                }
                if !package
                    .groups
                    .iter()
                    .any(|group| ignored_groups.is_match(group))
                {
                    retained.push(package.name.clone());
                    installed.insert(package.name, package.version);
                }
            }
            Ok((retained, Arc::new(installed)))
        })
        .await
        .context("AUR foreign-package scan task failed")??;

        if foreign_packages.is_empty() {
            return Ok(Vec::new());
        }

        // 2. Try the binary index only while its source archive is fresh.
        // Update discovery never synchronously refreshes global metadata: if
        // the index is stale, absent, or unreadable, fall straight
        // through to the AUR RPC instead.
        if let Some(index) = self.fresh_metadata_index().await {
            let local_names = foreign_packages.clone();
            let local_installed = Arc::clone(&installed);
            let (mut updates, missing) = tokio::task::spawn_blocking(move || {
                let mut local_pkgs = Vec::with_capacity(local_names.len());
                for name in local_names {
                    if let Some(version) = local_installed.get(&name) {
                        local_pkgs.push((name, version.clone()));
                    }
                }

                index.updates_for(&local_pkgs)
            })
            .await?;

            if missing.is_empty() {
                tracing::debug!("AUR update check completed via binary index");
                return Ok(updates);
            }
            // The index is partially stale: query the RPC for exactly the
            // names it lacks instead of silently treating them as current.
            tracing::debug!(
                "Binary index missing {} package(s); querying RPC for those",
                missing.len()
            );
            let rpc_updates = self
                .query_aur_updates_at(AUR_RPC_URL, &missing, installed)
                .await?;
            updates.extend(rpc_updates);
            return Ok(updates);
        }

        // 3. Fallback: Query AUR RPC directly for all foreign packages.
        self.query_aur_updates_at(AUR_RPC_URL, &foreign_packages, installed)
            .await
    }

    /// Query the AUR RPC `type=info` endpoint for one chunk of package names,
    /// retrying transient failures with exponential backoff.
    async fn rpc_info_chunk(chunk: &[String]) -> Result<AurResponse> {
        Self::rpc_info_chunk_at(AUR_RPC_URL, chunk).await
    }

    async fn rpc_info_chunk_at(endpoint: &str, chunk: &[String]) -> Result<AurResponse> {
        let mut url = format!("{endpoint}?v=5&type=info");
        for name in chunk {
            url.push_str("&arg[]=");
            url.push_str(&urlencoding::encode(name));
        }

        let mut last_error = None;
        for retry in 0..3u32 {
            if retry > 0 {
                tokio::time::sleep(crate::core::http::retry_backoff(
                    Duration::from_millis(100),
                    retry - 1,
                ))
                .await;
            }

            match shared_client().get(&url).send().await {
                Ok(response) => {
                    if crate::core::http::is_retryable_status(response.status()) {
                        last_error = ensure_aur_rpc_success(response.status()).err();
                        continue;
                    }
                    ensure_aur_rpc_success(response.status())?;
                    match crate::core::http::bounded_metadata_body(response).await {
                        Ok(body) => {
                            let response: AurResponse = decode_aur_rpc_body(&body)?;
                            let requested: HashSet<&str> =
                                chunk.iter().map(String::as_str).collect();
                            let mut seen = HashSet::new();
                            for package in &response.results {
                                anyhow::ensure!(
                                    requested.contains(package.name.as_str()),
                                    "AUR RPC info response contained an unrequested package"
                                );
                                anyhow::ensure!(
                                    seen.insert(package.name.as_str()),
                                    "AUR RPC info response contained a duplicate package"
                                );
                            }
                            return Ok(response);
                        }
                        Err(error) => match error.downcast::<reqwest::Error>() {
                            Ok(error) => last_error = Some(redact_aur_transport_error(error)),
                            Err(error) => return Err(error),
                        },
                    }
                }
                Err(error) if crate::core::http::is_retryable_error(&error) => {
                    last_error = Some(redact_aur_transport_error(error));
                }
                Err(error) => return Err(redact_aur_transport_error(error)),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("AUR request failed after retries")))
    }

    async fn query_aur_updates_at(
        &self,
        endpoint: &str,
        packages: &[String],
        installed: Arc<HashMap<String, Version>>,
    ) -> Result<Vec<(String, Version, Version)>> {
        let mut updates = Vec::with_capacity(packages.len() / 10 + 1);
        let chunked_names = Self::chunk_aur_names(packages);
        // Network I/O bound - use higher concurrency
        let concurrency = self.settings.aur.build_concurrency.clamp(4, 16);

        let mut stream = futures::stream::iter(chunked_names)
            .map(|chunk| async move { Self::rpc_info_chunk_at(endpoint, &chunk).await })
            .buffer_unordered(concurrency);

        while let Some(res) = stream.next().await {
            let response = res.map_err(|e| {
                // Decoder errors can contain arbitrary server-provided strings.
                // Retain only request causes constructed from safe local data.
                let error = if e.is::<AurRpcRequestError>() {
                    e
                } else {
                    anyhow::anyhow!("AUR RPC response was invalid or reported an error")
                };
                tracing::warn!("AUR update check failed: {}", error);
                error.context("Failed to check AUR updates")
            })?;
            let installed = Arc::clone(&installed);
            let chunk_updates = tokio::task::spawn_blocking(move || -> Result<Vec<_>> {
                let mut updates = Vec::new();
                for package in response.results {
                    if let Err(error) = crate::core::security::validate_package_name(&package.name)
                    {
                        tracing::warn!(
                            "Rejecting invalid package name from AUR update check: {} ({})",
                            package.name,
                            error
                        );
                        continue;
                    }

                    if let Some(local_version) = installed.get(&package.name) {
                        let Some(remote_version) =
                            crate::package_managers::parse_version(&package.version)
                        else {
                            tracing::warn!(
                                "Skipping AUR package '{}' with unparseable version '{}'",
                                package.name,
                                package.version
                            );
                            continue;
                        };
                        if crate::package_managers::types::compare_versions(
                            &remote_version,
                            local_version,
                        ) == std::cmp::Ordering::Greater
                        {
                            updates.push((package.name, local_version.clone(), remote_version));
                        }
                    }
                }
                Ok(updates)
            })
            .await
            .context("AUR local-version comparison task failed")??;
            updates.extend(chunk_updates);
        }

        Ok(updates)
    }

    #[must_use]
    fn chunk_aur_names(names: &[String]) -> Vec<Vec<String>> {
        let mut chunks: Vec<Vec<String>> = Vec::with_capacity((names.len() / 100) + 1);
        let mut current: Vec<String> = Vec::with_capacity(100);
        let mut current_len = AUR_RPC_INFO_BASE_LEN;

        for name in names {
            // `rpc_info_chunk` percent-encodes every name before appending it
            // to the query string. Account for the wire length, not UTF-8
            // source bytes, or names containing valid `+`/`@` characters can
            // push a supposedly bounded request over the URI limit.
            let arg_len = "&arg[]=".len() + urlencoding::encode(name).len();
            if !current.is_empty() && current_len + arg_len > AUR_RPC_MAX_URI {
                chunks.push(current);
                current = Vec::with_capacity(100);
                current_len = AUR_RPC_INFO_BASE_LEN;
            }
            current_len += arg_len;
            current.push(name.clone());
        }

        if !current.is_empty() {
            chunks.push(current);
        }

        chunks
    }

    pub(crate) async fn build_jobs_for_updates(
        &self,
        packages: &[String],
    ) -> Result<Vec<BuildJob>> {
        if packages.is_empty() {
            return Ok(Vec::new());
        }
        for package in packages {
            crate::core::security::validate_package_name(package)?;
        }

        let mut package_info = Vec::with_capacity(packages.len());
        for chunk in Self::chunk_aur_names(packages) {
            package_info.extend(Self::rpc_info_chunk(&chunk).await?.results);
        }
        Self::build_jobs_from_package_info(packages, &package_info)
    }

    fn build_jobs_from_package_info(
        packages: &[String],
        package_info: &[AurJsonPackage],
    ) -> Result<Vec<BuildJob>> {
        let requested: BTreeSet<&str> = packages.iter().map(String::as_str).collect();
        let mut info_by_name = BTreeMap::new();
        let mut base_by_output = BTreeMap::new();

        for info in package_info {
            crate::core::security::validate_package_name(&info.name)
                .context("AUR returned an invalid split-package name")?;
            let package_base = info.package_base.as_deref().unwrap_or(&info.name);
            crate::core::security::validate_package_name(package_base)
                .context("AUR returned an invalid package base")?;
            info_by_name.insert(info.name.as_str(), info);
            base_by_output.insert(info.name.as_str(), package_base);
        }

        let mut outputs_by_base: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
        let mut dependencies_by_base: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();

        for package in packages {
            let info = info_by_name
                .get(package.as_str())
                .with_context(|| format!("AUR returned no package information for '{package}'"))?;
            let package_base = base_by_output[info.name.as_str()];
            outputs_by_base
                .entry(package_base)
                .or_default()
                .insert(info.name.clone());

            for dependency in info
                .depends
                .iter()
                .chain(info.make_depends.iter())
                .chain(info.check_depends.iter())
                .flatten()
            {
                let dependency = dependency_name(dependency);
                if !requested.contains(dependency) {
                    continue;
                }
                let dependency_base = base_by_output.get(dependency).with_context(|| {
                    format!("AUR returned no package information for dependency '{dependency}'")
                })?;
                if *dependency_base != package_base {
                    dependencies_by_base
                        .entry(package_base)
                        .or_default()
                        .insert((*dependency_base).to_string());
                }
            }
        }

        Ok(outputs_by_base
            .into_iter()
            .map(|(package_base, outputs)| {
                let dependencies = dependencies_by_base
                    .remove(package_base)
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                BuildJob::for_package_base(
                    package_base.to_string(),
                    outputs.into_iter().collect(),
                    dependencies,
                )
            })
            .collect())
    }

    fn begin_rollback_worktree(work: &Path, base: &str) -> Result<tempfile::TempDir> {
        use std::os::unix::fs::PermissionsExt;

        crate::core::security::validate_package_name(base)?;
        tempfile::Builder::new()
            .prefix(&format!("{base}-"))
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(work)
            .context("Failed to create owned AUR rollback checkout")
    }

    fn historical_build_failure_message(package: &str, version: &str, log_path: &Path) -> String {
        format!(
            "Historical build of {package} {version} failed; check {}\n  → The AUR may no longer support building this version (changed sources/dependencies)",
            log_path.display()
        )
    }

    fn check_rebuilt_rollback_version(
        package: &str,
        version: &str,
        installed: Option<&Version>,
    ) -> Result<()> {
        let rebuilt = crate::package_managers::types::parse_version(version)
            .context("Historical AUR rebuild reported an invalid package version")?;
        if let Some(installed) = installed {
            anyhow::ensure!(
                crate::package_managers::types::compare_versions(&rebuilt, installed).is_lt(),
                "Historical AUR recipe for {package} rebuilt as {rebuilt}, which is not older than installed {installed}"
            );
        }
        Ok(())
    }

    /// Rebuild `package` at historical `version` from the AUR repository's
    /// git history and install the resulting archive.
    ///
    /// Used by rollback: officials restore from the pacman cache, but AUR
    /// serves only latest builds, so downgrading requires checking out the
    /// commit whose `.SRCINFO` recorded the old version. The clone is fully
    /// isolated under `_rollback/` so the user's cached checkout is never
    /// touched, and no build-cache key is written (this is not the latest
    /// build). Returns the version installed from the reviewed archive.
    pub async fn downgrade_from_history(&self, package: &str, version: &str) -> Result<String> {
        self.rebuild_from_history_with_install(package, version, Self::install_built_packages)
            .await
    }

    async fn rebuild_from_history_with_install(
        &self,
        package: &str,
        version: &str,
        install: impl AsyncFn(&[BuiltPackages], Option<&crate::core::sudoloop::SudoLoop>) -> Result<()>,
    ) -> Result<String> {
        crate::core::security::validate_package_name(package)?;
        crate::core::security::validate_version(version)?;
        require_unprivileged_builder(package, crate::core::is_root())?;

        Self::preacquire_install_privileges(package, "AUR rollback").await?;
        let sudoloop = if crate::core::sudoloop::can_use_sudoloop() {
            Some(crate::core::sudoloop::SudoLoop::start())
        } else {
            None
        };

        let base = self.resolve_package_base(package).await?;

        let _lifecycle_guard = self.acquire_build_lifecycle().await?;

        // The owner removes this unique checkout on every early return or
        // cancellation, not just after a successful install. Logs live outside it.
        let work = self.build_dir.join("_rollback");
        create_dir_as_user(&work).await?;
        let checkout_owner = Self::begin_rollback_worktree(&work, &base)?;
        let repo_dir = checkout_owner.path().to_path_buf();

        let url = format!("{AUR_GIT_URL}/{base}.git");
        super::history::checkout_version(&url, &repo_dir, &base, version).await?;

        // Use the same hardened validation, environment, and sandboxing
        // pipeline as regular installs.
        let pkg_dir = validate_build_dir(
            repo_dir
                .parent()
                .context("rollback work dir must have a parent")?,
            repo_dir
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .context("rollback work dir name must be valid UTF-8")?,
        )?;

        let mut env = self.makepkg_env(&pkg_dir).await?;
        // SECURITY (audit F-03, second wave): a force-pushed history commit
        // is exactly as untrusted as a fresh build, and the version match
        // alone does not prove the PKGBUILD is the one originally installed.
        // ALWAYS show the review prompt during rollback rebuilds,
        // independent of the user's day-to-day review preference.
        let pkgbuild_path = pkg_dir.join("PKGBUILD");
        let reviewed_digest =
            Self::review_pkgbuild(package, &pkgbuild_path, self.settings.aur.security_profile)
                .await?;
        set_reproducible_source_epoch(&mut env, &reviewed_digest)?;
        env.pgp_home = Self::fetch_missing_pgp_keys(&pkgbuild_path).await?;
        println!(
            "  {} Building {package} {version} from history...",
            crate::cli::style::informative("→")
        );
        reviewed_digest.verify(&pkg_dir)?;
        let status = self
            .run_build(&pkg_dir, &env, package, &reviewed_digest)
            .await
            .with_context(|| format!("Failed to run makepkg for '{package}'"))?;
        if !status.success() {
            anyhow::bail!(
                "{}",
                Self::historical_build_failure_message(
                    package,
                    version,
                    &self.build_dir.join("_logs"),
                )
            );
        }

        let mut archives =
            Self::find_built_packages(&pkg_dir, &env.pkgdest, &[package.to_string()])
                .await
                .map_err(|_| AurError::PackageArchiveNotFound(package.to_string()))?;
        let Some(archive) = archives.pop() else {
            return Err(AurError::PackageArchiveNotFound(package.to_string()).into());
        };

        // makepkg can rewrite PKGBUILD after pkgver() and records the checkout
        // path in .BUILDINFO. Restore verified inputs at the same path so the
        // independent build can reproduce the archive with private outputs.
        if reviewed_digest.recomputes_version()? && reviewed_digest.verify(&pkg_dir).is_err() {
            let checkout = Self::begin_rollback_worktree(&work, &base)?;
            super::history::checkout_version(&url, checkout.path(), &base, version).await?;
            reviewed_digest.verify(checkout.path())?;
            rustix::fs::renameat_with(
                rustix::fs::CWD,
                checkout.path(),
                rustix::fs::CWD,
                &pkg_dir,
                rustix::fs::RenameFlags::EXCHANGE,
            )
            .context("Failed to restore the reviewed checkout for the independent AUR build")?;
        }
        let archives = self
            .authorize_with_paired_build(
                &[archive],
                &reviewed_digest,
                &base,
                &[package.to_owned()],
                &[package.to_owned()],
                true,
                &pkg_dir,
                &env,
            )
            .await?;
        let archive = archives
            .archives
            .first()
            .context("Rollback build produced no archive")?;
        let rebuilt = Self::cached_archive_identity(Path::new(&archive.handoff()))?
            .context("Reviewed rollback archive lacks package identity")?
            .version;
        if rebuilt != version {
            let installed = pacman_db::read_local_package(package)?;
            let installed_version = installed.as_ref().map(|record| &record.version);
            Self::check_rebuilt_rollback_version(package, &rebuilt, installed_version)?;
            crate::cli::modern_ui::print_info(&format!(
                "Historical recipe for {package} {version} built version {rebuilt}"
            ));
        }
        crate::cli::modern_ui::print_info(&format!("Installing {package} {rebuilt}"));
        install(std::slice::from_ref(&archives), sudoloop.as_ref()).await?;
        crate::cli::modern_ui::print_success(&format!("Installed {package} {rebuilt}"));
        // Use async cleanup on success and report failures. The owner also
        // attempts cleanup on error/cancellation; logs remain outside this tree.
        if let Err(error) = tokio::fs::remove_dir_all(&repo_dir).await {
            tracing::warn!(
                "Rollback of '{package}' succeeded but its worktree {} could not be removed: {error:#}",
                repo_dir.display()
            );
        }
        Ok(rebuilt)
    }

    pub async fn install(&self, package: &str) -> Result<()> {
        crate::core::security::validate_package_name(package)?;
        // Build the package *base* (split packages share one PKGBUILD and one
        // checkout), but install only the output the user asked for. Installing
        // every sibling output of the base would mutate the system beyond the
        // request.
        let requested = vec![package.to_string()];
        let mut jobs = self.build_jobs_for_updates(&requested).await?;
        let job = jobs
            .pop()
            .context("AUR returned no build plan for the requested package")?;
        self.install_package_outputs(&job.package, &[package.to_string()])
            .await
    }

    pub(crate) async fn preacquire_install_privileges(package: &str, purpose: &str) -> Result<()> {
        if crate::core::caps::can_write_pacman_db() {
            return Ok(());
        }

        if !console::user_attended() {
            let true_program = crate::core::privilege::root_controlled_program_path("true")?;
            let status = crate::core::privilege::sudo_command()?
                .args(["-n", "--"])
                .arg(true_program)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .await
                .context("Failed to check non-interactive sudo availability")?;
            if !status.success() {
                anyhow::bail!(
                    "{purpose} for '{package}' needs sudo, but this non-interactive session does not have passwordless sudo"
                );
            }
        }

        let status = crate::core::privilege::sudo_command()?
            .arg("-v")
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .status()
            .await
            .with_context(|| format!("Failed to acquire sudo credentials for {purpose}"))?;
        if !status.success() {
            anyhow::bail!("Failed to acquire sudo credentials for {purpose} of '{package}'");
        }
        Ok(())
    }

    pub(crate) async fn authorize_package_outputs(
        &self,
        package: &str,
        requested_outputs: &[String],
    ) -> Result<AuthorizedBuild> {
        crate::core::security::validate_package_name(package)?;
        if requested_outputs.is_empty() {
            anyhow::bail!("AUR build plan for '{package}' has no package outputs");
        }
        for output in requested_outputs {
            crate::core::security::validate_package_name(output)?;
        }
        require_unprivileged_builder(package, crate::core::is_root())?;

        let lifecycle_guard = self.acquire_build_lifecycle().await?;
        let package_lock = self.package_base_lock(package);
        let _package_checkout_guard = package_lock.lock().await;
        create_dir_as_user(&self.build_dir).await?;
        let _package_checkout_file_guard = self.acquire_package_base_file_lock(package).await?;
        let pkg_dir = validate_build_dir(&self.build_dir, package)?;

        if pkg_dir.exists() {
            let pull_pb =
                crate::cli::modern_ui::modern_spinner("Updating", &format!("{package} source"));
            if let Err(error) = self.git_pull(&pkg_dir).await {
                crate::cli::modern_ui::finish_clear(&pull_pb);
                tracing::warn!(
                    "Git pull failed for {package}: {error}. Recovering by recloning package repository."
                );
                remove_dir_as_user(&pkg_dir)
                    .await
                    .map_err(|cleanup_error| {
                        tracing::warn!(
                            "Failed to remove stale AUR cache for {package}: {cleanup_error}"
                        );
                        AurError::GitPullFailed(package.to_string())
                    })?;
                let recover_pb = crate::cli::modern_ui::modern_spinner(
                    "Recovering",
                    &format!("{package} source checkout"),
                );
                self.git_clone(package).await.map_err(|clone_error| {
                    crate::cli::modern_ui::finish_clear(&recover_pb);
                    tracing::warn!("Recovery clone failed for {package}: {clone_error}");
                    AurError::GitPullFailed(package.to_string())
                })?;
                crate::cli::modern_ui::finish_success(&recover_pb, "Recovered", "source checkout");
            } else {
                crate::cli::modern_ui::finish_success(
                    &pull_pb,
                    "Updated",
                    &format!("{package} source"),
                );
            }
        } else {
            let clone_pb =
                crate::cli::modern_ui::modern_spinner("Cloning", &format!("{package} from AUR"));
            self.git_clone(package).await.map_err(|error| {
                crate::cli::modern_ui::finish_clear(&clone_pb);
                tracing::warn!("Git clone failed for {package}: {error}");
                AurError::GitCloneFailed(package.to_string())
            })?;
            crate::cli::modern_ui::finish_success(
                &clone_pb,
                "Cloned",
                &format!("{package} repository"),
            );
        }

        let pkgbuild_path = pkg_dir.join("PKGBUILD");
        if !pkgbuild_path.exists() {
            return Err(AurError::PkgbuildNotFound(package.to_string()).into());
        }
        let reviewed_digest = if self.settings.aur.review_pkgbuild {
            Self::review_pkgbuild(package, &pkgbuild_path, self.settings.aur.security_profile)
                .await?
        } else {
            ReviewedSource::capture(&pkg_dir)?
        };

        Ok(AuthorizedBuild {
            lifecycle_guard,
            package: package.to_string(),
            requested_outputs: requested_outputs.to_vec(),
            reviewed_digest,
        })
    }

    pub(crate) async fn install_package_outputs(
        &self,
        package: &str,
        requested_outputs: &[String],
    ) -> Result<()> {
        let authorized = self
            .authorize_package_outputs(package, requested_outputs)
            .await?;
        Self::preacquire_install_privileges(&authorized.package, "AUR build").await?;
        let sudoloop = if crate::core::sudoloop::can_use_sudoloop() {
            tracing::debug!("Starting sudoloop for AUR build");
            Some(crate::core::sudoloop::SudoLoop::start())
        } else {
            None
        };
        let output_names = authorized.requested_outputs.join(", ");
        let archives = self
            .install_authorized_package_outputs(authorized, sudoloop.as_ref())
            .await?;
        crate::cli::modern_ui::print_info(&format!("Installing {output_names}"));
        Self::install_built_packages(std::slice::from_ref(&archives), sudoloop.as_ref()).await?;
        crate::cli::modern_ui::print_success(&format!("Installed {output_names}"));
        Ok(())
    }

    pub(crate) async fn install_authorized_package_outputs(
        &self,
        authorized: AuthorizedBuild,
        sudoloop: Option<&crate::core::sudoloop::SudoLoop>,
    ) -> Result<BuiltPackages> {
        let AuthorizedBuild {
            lifecycle_guard: _lifecycle_guard,
            package,
            requested_outputs,
            reviewed_digest,
        } = authorized;
        let package_lock = self.package_base_lock(&package);
        let package_checkout_guard = package_lock.lock().await;
        let package_checkout_file_guard = self.acquire_package_base_file_lock(&package).await?;
        let pkg_dir = validate_build_dir(&self.build_dir, &package)?;
        let pkgbuild_path = pkg_dir.join("PKGBUILD");
        if !pkgbuild_path.exists() {
            return Err(AurError::PkgbuildNotFound(package).into());
        }
        reviewed_digest.verify(&pkg_dir)?;

        let pgp_home = Self::fetch_missing_pgp_keys(&pkgbuild_path).await?;

        let mut env = self.makepkg_env(&pkg_dir).await?;
        set_reproducible_source_epoch(&mut env, &reviewed_digest)?;
        env.pgp_home = pgp_home;

        let dependency_plan = self
            .aur_dependency_plan(&reviewed_digest, &package, &requested_outputs)
            .await?;
        let package_outputs = dependency_plan.package_outputs;
        let mut dependency_builds =
            AHashSet::from_iter([package.clone(), Self::package_base_marker(&package)]);
        drop(package_checkout_file_guard);
        drop(package_checkout_guard);
        Self::install_official_dependencies(&dependency_plan.official_dependencies).await?;
        for dep in dependency_plan.aur_dependencies {
            crate::cli::modern_ui::print_info(&format!(
                "Installing AUR dependency for {package}: {dep}"
            ));
            let dep_packages = self
                .build_only(&dep, &mut dependency_builds, sudoloop)
                .await?;
            Self::install_built_packages(std::slice::from_ref(&dep_packages), sudoloop).await?;
            crate::cli::modern_ui::print_success(&format!("Installed dependency: {dep}"));
        }
        self.ensure_dependencies_satisfied(&reviewed_digest, &package_outputs)
            .await?;

        let _package_build_guard = package_lock.lock().await;
        let _package_build_file_guard = self.acquire_package_base_file_lock(&package).await?;

        // Best-effort pre-download: makepkg still fetches anything we miss.
        match reviewed_digest
            .optional_srcinfo()
            .map(|metadata| metadata.map_or_else(Vec::new, |info| http_sources(&info)))
        {
            Ok(sources) if sources.is_empty() => {}
            Ok(sources) => {
                let summary = download_sources(sources, &env.srcdest).await;
                if summary.failed > 0 {
                    tracing::warn!(
                        "Pre-downloaded {}/{} AUR sources for {package}; makepkg will retry the rest",
                        summary.succeeded,
                        summary.succeeded + summary.failed
                    );
                }
            }
            Err(error) => {
                tracing::warn!(
                    "Failed to parse AUR sources for {package}: {error}; makepkg will fetch them"
                );
            }
        }

        // Best-effort VCS mirroring: it warms SRCDEST for a later offline
        // rebuild, but a failure here is not fatal when networking is allowed.
        match reviewed_digest
            .optional_srcinfo()
            .map(|metadata| metadata.map_or_else(Vec::new, |info| vcs_sources(&info)))
        {
            Ok(vcs_sources) if !vcs_sources.is_empty() => {
                let summary = prefetch_vcs_sources(&vcs_sources, &env.srcdest).await;
                if !summary.needs_network.is_empty() {
                    tracing::debug!(
                        "VCS sources for {package} still need network at build time: {}",
                        summary.needs_network.join(", ")
                    );
                }
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!("Failed to parse AUR VCS sources for {package}: {error}");
            }
        }

        reviewed_digest.verify(&pkg_dir)?;
        let log_path = self.build_log_path(&package);
        let status = self
            .run_build(&pkg_dir, &env, &package, &reviewed_digest)
            .await
            .with_context(|| format!("Failed to run makepkg for '{package}'"))?;
        if !status.success() {
            return Err(AurError::BuildFailed {
                package: package.clone(),
                log_path: log_path.display().to_string(),
            }
            .into());
        }

        let pkg_files = Self::find_built_packages(&pkg_dir, &env.pkgdest, &package_outputs)
            .await
            .map_err(|_| AurError::PackageArchiveNotFound(package.clone()))?;

        self.authorize_with_paired_build(
            &pkg_files,
            &reviewed_digest,
            &package,
            &package_outputs,
            &requested_outputs,
            true,
            &pkg_dir,
            &env,
        )
        .await
    }

    fn build_only<'a>(
        &'a self,
        package: &'a str,
        in_flight: &'a mut AHashSet<String>,
        sudoloop: Option<&'a crate::core::sudoloop::SudoLoop>,
    ) -> BoxFuture<'a, Result<BuiltPackages>> {
        async move {
            Self::enter_dependency_build(in_flight, package)?;
            let package_base = match self.resolve_package_base(package).await {
                Ok(package_base) => package_base,
                Err(error) => {
                    in_flight.remove(package);
                    return Err(error);
                }
            };
            let base_marker = Self::package_base_marker(&package_base);
            if let Err(error) = Self::enter_package_base(in_flight, &package_base) {
                in_flight.remove(package);
                return Err(error);
            }

            let result = self
                .build_only_inner(package, &package_base, in_flight, sudoloop)
                .await;
            in_flight.remove(&base_marker);
            in_flight.remove(package);
            result
        }
        .boxed()
    }

    fn enter_dependency_build(in_flight: &mut AHashSet<String>, package: &str) -> Result<()> {
        if !in_flight.insert(package.to_string()) {
            anyhow::bail!("Circular AUR dependency detected while resolving '{package}'");
        }
        Ok(())
    }

    fn enter_package_base(in_flight: &mut AHashSet<String>, package_base: &str) -> Result<()> {
        if !in_flight.insert(Self::package_base_marker(package_base)) {
            anyhow::bail!(
                "Circular AUR package-base dependency detected while resolving '{package_base}'"
            );
        }
        Ok(())
    }

    #[instrument(skip(self, in_flight, sudoloop))]
    async fn build_only_inner(
        &self,
        package: &str,
        package_base: &str,
        in_flight: &mut AHashSet<String>,
        sudoloop: Option<&crate::core::sudoloop::SudoLoop>,
    ) -> Result<BuiltPackages> {
        crate::core::security::validate_package_name(package)?;
        let package_lock = self.package_base_lock(package_base);
        let package_checkout_guard = package_lock.lock().await;

        // A dependency may be a split-package OUTPUT whose AUR repository is
        // named after its package base (e.g. `postgresql18-libs` lives in
        // `postgresql18.git`). Clone/build the base; cache and artifact
        // lookups stay scoped to the requested output.
        create_dir_as_user(&self.build_dir).await?;
        let package_checkout_file_guard = self.acquire_package_base_file_lock(package_base).await?;

        // SECURITY: Validate package directory is safe (prevents symlink attacks)
        let pkg_dir = validate_build_dir(&self.build_dir, package_base)?;
        let pkgbuild_path = pkg_dir.join("PKGBUILD");

        if pkg_dir.exists() && pkgbuild_path.exists() {
            if let Err(e) = self.git_pull(&pkg_dir).await {
                tracing::warn!(
                    "Git pull failed for {}: {}. Recovering by recloning package repository.",
                    package_base,
                    e
                );
                remove_dir_as_user(&pkg_dir).await.map_err(|cleanup_err| {
                    tracing::warn!(
                        "Failed to remove stale AUR cache for {}: {}",
                        package_base,
                        cleanup_err
                    );
                    AurError::GitPullFailed(package_base.to_string())
                })?;
                self.git_clone(package_base).await.map_err(|clone_err| {
                    tracing::warn!("Recovery clone failed for {}: {}", package_base, clone_err);
                    AurError::GitPullFailed(package_base.to_string())
                })?;
            }
        } else {
            if pkg_dir.exists() {
                // Surface cleanup failures: otherwise a stale directory that
                // cannot be removed surfaces as a confusing clone failure.
                if let Err(error) = remove_dir_as_user(&pkg_dir).await {
                    tracing::warn!(
                        "Failed to remove stale AUR directory {} before re-cloning: {}",
                        pkg_dir.display(),
                        error
                    );
                }
            }
            self.git_clone(package_base).await.map_err(|e| {
                tracing::warn!("Git clone failed for {}: {}", package_base, e);
                AurError::GitCloneFailed(package_base.to_string())
            })?;
        }

        if !pkgbuild_path.exists() {
            return Err(AurError::PkgbuildNotFound(package.to_string()).into());
        }

        // Same hash seal as install_package_outputs: re-verify the reviewed
        // PKGBUILD right before this dependency build runs.
        let reviewed_digest = if self.settings.aur.review_pkgbuild {
            Self::review_pkgbuild(
                package_base,
                &pkgbuild_path,
                self.settings.aur.security_profile,
            )
            .await?
        } else {
            ReviewedSource::capture(&pkg_dir)?
        };
        let pgp_home = Self::fetch_missing_pgp_keys(&pkgbuild_path).await?;

        let dependency_plan = self
            .aur_dependency_plan(&reviewed_digest, package, &[package.to_string()])
            .await?;
        let package_outputs = dependency_plan.package_outputs;
        drop(package_checkout_file_guard);
        drop(package_checkout_guard);
        Self::install_official_dependencies(&dependency_plan.official_dependencies).await?;
        for dependency in dependency_plan.aur_dependencies {
            crate::cli::modern_ui::print_info(&format!(
                "Installing AUR dependency for {package}: {dependency}"
            ));
            let archives = self.build_only(&dependency, in_flight, sudoloop).await?;
            Self::install_built_packages(std::slice::from_ref(&archives), sudoloop).await?;
            crate::cli::modern_ui::print_success(&format!("Installed dependency: {dependency}"));
        }
        self.ensure_dependencies_satisfied(&reviewed_digest, &package_outputs)
            .await?;

        let _package_build_guard = package_lock.lock().await;
        let _package_build_file_guard = self.acquire_package_base_file_lock(package_base).await?;
        let mut env = self.makepkg_env(&pkg_dir).await?;
        set_reproducible_source_epoch(&mut env, &reviewed_digest)?;
        env.pgp_home = pgp_home;
        reviewed_digest.verify(&pkg_dir)?;
        let log_path = self.build_log_path(package);
        let status = self
            .run_build(&pkg_dir, &env, package, &reviewed_digest)
            .await
            .with_context(|| format!("Failed to run makepkg for '{package}'"))?;

        if !status.success() {
            return Err(AurError::BuildFailed {
                package: package.to_string(),
                log_path: log_path.display().to_string(),
            }
            .into());
        }

        let pkg_files = Self::find_built_packages(&pkg_dir, &env.pkgdest, &package_outputs)
            .await
            .map_err(|_| AurError::PackageArchiveNotFound(package.to_string()))?;
        self.authorize_with_paired_build(
            &pkg_files,
            &reviewed_digest,
            package_base,
            &package_outputs,
            &[],
            true,
            &pkg_dir,
            &env,
        )
        .await
    }

    /// Resolve an AUR name (output or base) to its package base via one RPC
    /// lookup. Falls back to the input on any failure so offline callers keep
    /// their previous behavior instead of hard-failing.
    async fn resolve_package_base(&self, name: &str) -> Result<String> {
        match Self::rpc_info_chunk(std::slice::from_ref(&name.to_string())).await {
            Ok(response) => {
                let candidate = response
                    .results
                    .iter()
                    .find(|info| info.name == name)
                    .and_then(|info| info.package_base.as_deref());
                Self::validated_package_base(name, candidate)
            }
            Err(error) => {
                tracing::debug!(
                    "Could not resolve package base for {name}: {error}; using name as base"
                );
                Ok(name.to_string())
            }
        }
    }

    fn validated_package_base(name: &str, candidate: Option<&str>) -> Result<String> {
        let package_base = candidate.unwrap_or(name);
        crate::core::security::validate_package_name(package_base)
            .context("AUR returned an invalid package base")?;
        Ok(package_base.to_string())
    }

    async fn find_built_packages(
        _pkg_dir: &Path,
        pkgdest: &Path,
        expected_names: &[String],
    ) -> Result<Vec<PathBuf>> {
        let pkgdest = pkgdest.to_path_buf();
        let expected_names = expected_names.to_vec();

        tokio::task::spawn_blocking(move || {
            let mut packages = Vec::with_capacity(expected_names.len());
            for expected_name in &expected_names {
                let names = [expected_name.clone()];
                let package = Self::find_package_in_dir(&pkgdest, &names).with_context(|| {
                    format!("No package archive found for split-package output '{expected_name}'")
                })?;
                packages.push(package);
            }
            Ok(packages)
        })
        .await?
    }

    fn find_package_in_dir(path: &Path, expected_names: &[String]) -> Option<PathBuf> {
        let entries = std::fs::read_dir(path).ok()?;
        let mut best_match: Option<PathBuf> = None;
        let mut best_mtime = std::time::SystemTime::UNIX_EPOCH;

        for entry in entries.flatten() {
            // A recipe can leave a symlink that resolves only on the host.
            // Never follow it while discovering candidate build outputs.
            if !entry.file_type().ok().is_some_and(|kind| kind.is_file()) {
                continue;
            }
            let filename = entry.file_name().to_string_lossy().into_owned();
            if (filename.ends_with(".pkg.tar.zst") || filename.ends_with(".pkg.tar.xz"))
                && expected_names.iter().any(|name| {
                    filename.starts_with(name) && filename.chars().nth(name.len()) == Some('-')
                })
            {
                // Filename matching is only a candidate filter. The archive's
                // embedded identity is authoritative; unreadable or absent
                // metadata must never select an artifact for installation.
                let Ok(Some(parsed_name)) = Self::pkg_name_from_archive(&entry.path()) else {
                    continue;
                };
                if !expected_names.iter().any(|name| name == &parsed_name) {
                    continue;
                }

                // If multiple matches (shouldn't happen), take newest by mtime
                if let Ok(meta) = entry.metadata() {
                    if let Ok(mtime) = meta.modified()
                        && mtime > best_mtime
                    {
                        best_mtime = mtime;
                        best_match = Some(entry.path());
                    }
                } else if best_match.is_none() {
                    best_match = Some(entry.path());
                }
            }
        }
        best_match
    }

    fn pkg_name_from_archive(path: &Path) -> Result<Option<String>> {
        Self::pkg_name_and_version_from_archive_result(path)
            .map(|identity| identity.map(|(name, _)| name))
    }

    /// Extract `(pkgname, full-version)` from `.PKGINFO` content.
    fn parse_pkginfo_name_version(content: &str) -> Option<(String, String)> {
        // Tolerant line parser: alpm-pkginfo's schema requires a dozen
        // mandatory fields; rollback/cache identity checks only need these
        // two keys and must work even when other metadata is absent.
        let mut name: Option<String> = None;
        let mut version: Option<String> = None;
        for line in content.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key.trim() {
                "pkgname" => {
                    if name.is_some() {
                        return None;
                    }
                    name = Some(value.trim().to_string());
                }
                "pkgver" => {
                    if version.is_some() {
                        return None;
                    }
                    version = Some(value.trim().to_string());
                }
                _ => {}
            }
        }
        Some((name?, version?))
    }

    /// Accept a complete, ordered set of cached outputs only when every
    /// archive's identity, version, package base, architecture, and install hook match the
    /// checkout. A matching cache key alone is not proof: both the key and
    /// archives live in a user-writable directory.
    #[cfg(test)]
    fn select_cached_artifacts(
        archives: Vec<PathBuf>,
        outputs: &[String],
        pkg_dir: &Path,
        package_base: &str,
    ) -> Option<Vec<PathBuf>> {
        if outputs.is_empty()
            || archives.len() != outputs.len()
            || !archives.iter().zip(outputs).all(|(archive, output)| {
                Self::cached_artifact_provenance_ok(archive, pkg_dir, package_base, output)
            })
        {
            tracing::warn!(
                "Rejecting cached build for {package_base}: incomplete outputs or archive identity/provenance mismatch"
            );
            return None;
        }
        Some(archives)
    }

    fn archive_architecture_approved(
        srcinfo: &alpm_srcinfo::SourceInfoV1,
        output: &str,
        architecture: &str,
    ) -> bool {
        if !super::utils::package_architecture_matches(std::env::consts::ARCH, architecture) {
            return false;
        }
        let Some(package) = srcinfo
            .packages
            .iter()
            .find(|package| package.name.to_string() == output)
        else {
            return false;
        };
        let architectures = package
            .architectures
            .as_ref()
            .unwrap_or(&srcinfo.base.architectures);
        match architectures {
            alpm_types::Architectures::Any => architecture == "any",
            alpm_types::Architectures::Some(architectures) => architectures
                .iter()
                .any(|candidate| candidate.to_string() == architecture),
        }
    }

    fn authorize_archives(
        paths: &[PathBuf],
        source: &ReviewedSource,
        base: &str,
        outputs: &[String],
        fresh: bool,
    ) -> Result<Vec<ArchiveSnapshot>> {
        let srcinfo = source.text(Path::new(".SRCINFO"))?;
        let expected_version =
            srcinfo_version(srcinfo).context("Missing reviewed package version")?;
        anyhow::ensure!(
            Self::srcinfo_pkgbase(srcinfo) == Some(base)
                && paths.len() == outputs.len()
                && !paths.is_empty(),
            "AUR output set/base does not match reviewed source"
        );
        // VCS recipes intentionally calculate pkgver during build. A changed
        // version still cannot change output names/base or approved root hooks.
        let dynamic_version = source.recomputes_version()? && fresh;
        let architecture_metadata = alpm_srcinfo::SourceInfoV1::from_string(srcinfo);
        paths
            .iter()
            .zip(outputs)
            .map(|(path, output)| {
                let snapshot = ArchiveSnapshot::capture(path)?;
                let admission = artifact_inspector::inspect_archive(&snapshot.path())?;
                let inspection = admission.inspection();
                snapshot.verify_sha256(&inspection.archive_sha256)?;
                let identity = Self::cached_archive_identity(Path::new(&snapshot.handoff()))?
                    .context("Archive lacks package identity")?;
                anyhow::ensure!(
                    identity.name == *output
                        && identity.base == base
                        && (identity.version == expected_version || dynamic_version),
                    "AUR archive identity/version differs from reviewed source: {output}"
                );
                anyhow::ensure!(
                    inspection.package_name == identity.name
                        && inspection.package_base == identity.base
                        && inspection.package_version == identity.version,
                    "AUR inspection identity differs from package metadata: {output}"
                );
                let architecture = identity
                    .architecture
                    .as_deref()
                    .context("Archive lacks architecture")?;
                anyhow::ensure!(
                    architecture_metadata.as_ref().is_ok_and(|metadata| {
                        Self::archive_architecture_approved(metadata, output, architecture)
                    }),
                    "AUR archive architecture is not approved for this host"
                );
                let declared = Self::srcinfo_install_script(srcinfo, output);
                let expected_hook = declared
                    .as_deref()
                    .map(|path| source.text(Path::new(path)))
                    .transpose()?;
                anyhow::ensure!(
                    identity.install_script.as_deref() == expected_hook,
                    "AUR archive contains an undeclared or changed installation hook: {output}"
                );
                crate::core::security::audit::record_operation(
                    "aur_inspection",
                    &[
                        format!("source_manifest_sha256={}", source.digest),
                        inspection.audit_summary(),
                    ],
                    "succeeded",
                )?;
                Ok(snapshot)
            })
            .collect()
    }

    fn paired_build_cache_key(
        &self,
        source: &ReviewedSource,
        env: &MakepkgEnv,
        inspections: &[artifact_inspector::ArtifactInspection],
    ) -> String {
        let mut ordered = inspections.iter().collect::<Vec<_>>();
        ordered.sort_by(|left, right| left.package_name.cmp(&right.package_name));
        let method = format!("{:?}", self.settings.aur.build_method);
        let makepkg_args = self.makepkg_args().join("\0");
        let mut build_environment = env.extra_env.clone();
        build_environment.sort();
        let mut hash = Sha256::new();
        hash.update(b"omg-aur-paired-build-v1\0");
        for value in [
            source.digest.as_str(),
            env.makeflags.as_str(),
            method.as_str(),
            self.settings.aur.security_profile.as_str(),
            makepkg_args.as_str(),
            if self.settings.aur.secure_makepkg {
                "secure-makepkg"
            } else {
                "standard-makepkg"
            },
            if self.settings.aur.allow_network {
                "network-enabled"
            } else {
                "network-disabled"
            },
        ] {
            hash.update((value.len() as u64).to_le_bytes());
            hash.update(value.as_bytes());
        }
        for (key, value) in build_environment {
            hash.update((key.len() as u64).to_le_bytes());
            hash.update(key.as_bytes());
            hash.update((value.len() as u64).to_le_bytes());
            hash.update(value.as_bytes());
        }
        for inspection in ordered {
            for value in [
                inspection.package_name.as_str(),
                inspection.package_version.as_str(),
                inspection.archive_sha256.as_str(),
            ] {
                hash.update((value.len() as u64).to_le_bytes());
                hash.update(value.as_bytes());
            }
            hash.update(inspection.policy_version.to_le_bytes());
        }
        hex::encode(hash.finalize())
    }

    fn verify_paired_outputs(
        primary: &[artifact_inspector::ArtifactInspection],
        secondary: &[artifact_inspector::ArtifactInspection],
    ) -> Result<()> {
        let canonical = |items: &[artifact_inspector::ArtifactInspection]| {
            let mut values = items
                .iter()
                .map(|item| {
                    (
                        item.package_name.clone(),
                        item.package_version.clone(),
                        item.archive_sha256.clone(),
                    )
                })
                .collect::<Vec<_>>();
            values.sort_unstable();
            values
        };
        anyhow::ensure!(
            canonical(primary) == canonical(secondary),
            "High-risk AUR package did not reproduce byte-for-byte in an independent build"
        );
        Ok(())
    }

    async fn authorize_with_paired_build(
        &self,
        paths: &[PathBuf],
        source: &ReviewedSource,
        base: &str,
        outputs: &[String],
        requested_outputs: &[String],
        fresh: bool,
        pkg_dir: &Path,
        primary_env: &MakepkgEnv,
    ) -> Result<BuiltPackages> {
        anyhow::ensure!(
            requested_outputs
                .iter()
                .all(|output| outputs.contains(output)),
            "Requested AUR outputs must belong to the authorized build output set"
        );
        let primary = Self::authorize_archives(paths, source, base, outputs, fresh)?;
        let primary_inspections = primary
            .iter()
            .map(|archive| {
                artifact_inspector::inspect_archive(&archive.path())
                    .map(artifact_inspector::ArchiveAdmission::into_inspection)
            })
            .collect::<Result<Vec<_>>>()?;
        let profile = self.settings.aur.security_profile;
        self.settings.aur.validate_security_profile()?;
        for inspection in &primary_inspections {
            inspection.enforce_profile(profile)?;
        }
        if !primary_inspections
            .iter()
            .any(|inspection| inspection.requires_paired_build_for(profile))
        {
            return Ok(BuiltPackages {
                archives: primary,
                profile,
                requested_outputs: requested_outputs.iter().cloned().collect(),
            });
        }

        let cache_key = self.paired_build_cache_key(source, primary_env, &primary_inspections);
        let cache = PAIRED_BUILD_CACHE.get_or_init(|| Mutex::new(HashSet::new()));
        if cache
            .lock()
            .map_err(|_| anyhow::anyhow!("AUR paired-build cache lock was poisoned"))?
            .contains(&cache_key)
        {
            crate::core::security::audit::record_operation(
                "aur_paired_build",
                &[
                    format!("cache_key={cache_key}"),
                    "result=verified-cache".to_owned(),
                ],
                "succeeded",
            )?;
            return Ok(BuiltPackages {
                archives: primary,
                profile,
                requested_outputs: requested_outputs.iter().cloned().collect(),
            });
        }

        crate::cli::modern_ui::print_info(&format!(
            "Rebuilding AUR package {base} with separate output storage for exact comparison"
        ));
        source.verify(pkg_dir)?;
        let mut secondary_env = self.makepkg_env(pkg_dir).await?;
        set_reproducible_source_epoch(&mut secondary_env, source)?;
        secondary_env.pgp_home = Self::fetch_missing_pgp_keys(&pkg_dir.join("PKGBUILD")).await?;
        let status = self
            .run_build(pkg_dir, &secondary_env, base, source)
            .await?;
        anyhow::ensure!(
            status.success(),
            "Independent verification build failed for high-risk AUR package {base}"
        );
        let secondary_paths = Self::find_built_packages(pkg_dir, &secondary_env.pkgdest, outputs)
            .await
            .map_err(|_| AurError::PackageArchiveNotFound(base.to_owned()))?;
        let secondary = Self::authorize_archives(&secondary_paths, source, base, outputs, fresh)?;
        let secondary_inspections = secondary
            .iter()
            .map(|archive| {
                artifact_inspector::inspect_archive(&archive.path())
                    .map(artifact_inspector::ArchiveAdmission::into_inspection)
            })
            .collect::<Result<Vec<_>>>()?;

        // Reproducible Builds recommends rebuilding independently and comparing
        // the outputs; accepting only identical archive hashes makes the check
        // cover metadata, hooks, modes, and payload bytes together.
        // https://reproducible-builds.org/docs/plans/
        Self::verify_paired_outputs(&primary_inspections, &secondary_inspections)?;
        cache
            .lock()
            .map_err(|_| anyhow::anyhow!("AUR paired-build cache lock was poisoned"))?
            .insert(cache_key.clone());
        crate::core::security::audit::record_operation(
            "aur_paired_build",
            &[
                format!("source_manifest_sha256={}", source.digest),
                format!("cache_key={cache_key}"),
                format!("outputs={}", outputs.join(",")),
                "result=exact-match".to_owned(),
            ],
            "succeeded",
        )?;
        Ok(BuiltPackages {
            archives: primary,
            profile,
            requested_outputs: requested_outputs.iter().cloned().collect(),
        })
    }

    /// Retained metadata/hook regression checks. These are necessary but
    /// insufficient to establish provenance of the rest of an archive;
    /// production therefore never reuses these legacy cached archives.
    #[cfg(test)]
    fn cached_artifact_provenance_ok(
        archive: &Path,
        pkg_dir: &Path,
        package_base: &str,
        output: &str,
    ) -> bool {
        let srcinfo = match std::fs::read_to_string(pkg_dir.join(".SRCINFO")) {
            Ok(srcinfo) => srcinfo,
            Err(error) => {
                tracing::warn!(
                    "Cached artifact provenance for {output}: unreadable .SRCINFO in {}: {error}; rejecting cache hit",
                    pkg_dir.display()
                );
                return false;
            }
        };
        let Some(expected_version) = srcinfo_version(&srcinfo) else {
            tracing::warn!(
                "Cached artifact provenance for {output}: .SRCINFO has no usable version; rejecting cache hit"
            );
            return false;
        };
        let Some(expected_base) = Self::srcinfo_pkgbase(&srcinfo) else {
            tracing::warn!(
                "Cached artifact provenance for {output}: .SRCINFO declares no pkgbase; rejecting cache hit"
            );
            return false;
        };
        if expected_base != package_base {
            tracing::warn!(
                "Cached artifact provenance for {output}: .SRCINFO pkgbase '{expected_base}' does not match package base '{package_base}'; rejecting cache hit"
            );
            return false;
        }

        let Some(identity) = (match Self::cached_archive_identity(archive) {
            Ok(identity) => identity,
            Err(error) => {
                tracing::warn!(
                    "Cached artifact provenance for {output}: cannot read metadata from {}: {error}; rejecting cache hit",
                    archive.display()
                );
                return false;
            }
        }) else {
            tracing::warn!(
                "Cached artifact provenance for {output}: {} has no readable .PKGINFO; rejecting cache hit",
                archive.display()
            );
            return false;
        };

        if identity.name != output
            || identity.version != expected_version
            || identity.base != package_base
        {
            tracing::warn!(
                "Cached artifact provenance for {output}: {} claims '{}' '{}' in base '{}', expected '{}' in base '{package_base}' from .SRCINFO; rejecting cache hit",
                archive.display(),
                identity.name,
                identity.version,
                identity.base,
                expected_version
            );
            return false;
        }

        let architecture_metadata = alpm_srcinfo::SourceInfoV1::from_string(&srcinfo);
        if !identity
            .architecture
            .as_deref()
            .is_some_and(|architecture| {
                architecture_metadata.as_ref().is_ok_and(|metadata| {
                    Self::archive_architecture_approved(metadata, output, architecture)
                })
            })
        {
            tracing::warn!(
                "Cached artifact provenance for {output}: architecture missing or not approved for this host; rejecting cache hit"
            );
            return false;
        }

        match Self::srcinfo_install_script(&srcinfo, output) {
            Some(install_file) => {
                let Some(embedded) = identity.install_script.as_deref() else {
                    tracing::warn!(
                        "Cached artifact provenance for {output}: reviewed PKGBUILD declares install script '{install_file}' but {} embeds no .INSTALL; rejecting cache hit",
                        archive.display()
                    );
                    return false;
                };
                let expected = match std::fs::read_to_string(pkg_dir.join(&install_file)) {
                    Ok(expected) => expected,
                    Err(error) => {
                        tracing::warn!(
                            "Cached artifact provenance for {output}: cannot read declared install script {install_file}: {error}; rejecting cache hit"
                        );
                        return false;
                    }
                };
                if embedded != expected {
                    tracing::warn!(
                        "Cached artifact provenance for {output}: .INSTALL hook in {} does not match the reviewed install script '{install_file}'; rejecting cache hit",
                        archive.display()
                    );
                    return false;
                }
            }
            None if identity.install_script.is_some() => {
                tracing::warn!(
                    "Cached artifact provenance for {output}: reviewed PKGBUILD declares no install script but {} embeds a .INSTALL hook; rejecting cache hit",
                    archive.display()
                );
                return false;
            }
            None => {}
        }

        true
    }

    /// Read `.PKGINFO` (and `.INSTALL` when present) from a package archive
    /// in a single bounded pass. Returns `Ok(None)` when the archive carries
    /// no `.PKGINFO` member at all.
    fn cached_archive_identity(archive: &Path) -> Result<Option<CachedArchiveIdentity>> {
        let reader = Self::package_archive_reader(archive, MAX_DECOMPRESSED_BYTES)?;
        let mut tar_archive = tar::Archive::new(reader);
        let mut pkginfo: Option<String> = None;
        let mut install_script: Option<String> = None;
        for entry in tar_archive.entries()? {
            let entry = entry?;
            let entry_path = entry.path()?.into_owned();
            let normalized = crate::core::archive::stripped_archive_path(&entry_path, 0)?;
            match normalized.as_deref().and_then(Path::to_str) {
                Some(".PKGINFO") => {
                    anyhow::ensure!(
                        pkginfo.is_none() && entry.header().entry_type().is_file(),
                        "Duplicate or non-regular .PKGINFO"
                    );
                    pkginfo = Some(Self::read_bounded_archive_member(entry)?);
                }
                Some(".INSTALL") => {
                    anyhow::ensure!(
                        install_script.is_none() && entry.header().entry_type().is_file(),
                        "Duplicate or non-regular .INSTALL"
                    );
                    install_script = Some(Self::read_bounded_archive_member(entry)?);
                }
                _ => {}
            }
        }
        let Some(pkginfo) = pkginfo else {
            return Ok(None);
        };
        let architecture = pkginfo
            .lines()
            .filter_map(|line| {
                line.split_once('=').and_then(|(key, value)| {
                    (key.trim() == "arch").then(|| value.trim().to_owned())
                })
            })
            .collect::<Vec<_>>();
        anyhow::ensure!(
            architecture.len() <= 1,
            "Archive has duplicate architecture fields"
        );
        Ok(
            Self::parse_pkginfo_identity(&pkginfo).map(|(name, version, base)| {
                CachedArchiveIdentity {
                    name,
                    version,
                    base,
                    install_script,
                    architecture: architecture.into_iter().next(),
                }
            }),
        )
    }

    /// Read one archive member with the same size cap as `.PKGINFO` reads.
    fn read_bounded_archive_member<R: std::io::Read>(entry: tar::Entry<R>) -> Result<String> {
        if entry.size() > MAX_PKGINFO_BYTES {
            anyhow::bail!("Package metadata member exceeds the {MAX_PKGINFO_BYTES} byte limit");
        }
        let mut content = String::with_capacity(entry.size() as usize);
        entry
            .take(MAX_PKGINFO_BYTES + 1)
            .read_to_string(&mut content)?;
        if content.len() as u64 > MAX_PKGINFO_BYTES {
            anyhow::bail!("Package metadata member exceeds the {MAX_PKGINFO_BYTES} byte limit");
        }
        Ok(content)
    }

    /// Extract `(pkgname, full-version, pkgbase)` from `.PKGINFO` content.
    /// `pkgbase` is mandatory for provenance: makepkg always emits it, so an
    /// archive without one is not a makepkg product and must not be trusted.
    fn parse_pkginfo_identity(content: &str) -> Option<(String, String, String)> {
        let mut name: Option<String> = None;
        let mut version: Option<String> = None;
        let mut base: Option<String> = None;
        for line in content.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key.trim() {
                "pkgname" => {
                    if name.is_some() {
                        return None;
                    }
                    name = Some(value.trim().to_string());
                }
                "pkgver" => {
                    if version.is_some() {
                        return None;
                    }
                    version = Some(value.trim().to_string());
                }
                "pkgbase" => {
                    if base.is_some() {
                        return None;
                    }
                    base = Some(value.trim().to_string());
                }
                _ => {}
            }
        }
        Some((name?, version?, base?))
    }

    /// Extract the `pkgbase` value from `.SRCINFO` text (first occurrence).
    fn srcinfo_pkgbase(content: &str) -> Option<&str> {
        content.lines().find_map(|line| {
            let (key, value) = line.split_once('=')?;
            let value = value.trim();
            (key.trim() == "pkgbase" && !value.is_empty()).then_some(value)
        })
    }

    /// Extract the install script declared for one split-package output in
    /// `.SRCINFO` text. The `install =` key appears inside the block of the
    /// `pkgname =` it belongs to; returns `None` when that output declares
    /// no install script.
    fn srcinfo_install_script(content: &str, pkgname: &str) -> Option<String> {
        let mut block: Option<&str> = None;
        let mut common: Option<String> = None;
        let mut selected: Option<String> = None;
        for line in content.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim();
            match key.trim() {
                "pkgname" => block = Some(value),
                "install" if !value.is_empty() => {
                    if block.is_none() {
                        common = Some(value.to_owned());
                    } else if block == Some(pkgname) {
                        selected = Some(value.to_owned());
                    }
                }
                _ => {}
            }
        }
        selected.or(common)
    }

    pub(crate) fn pkg_name_and_version_from_archive(path: &Path) -> Option<(String, String)> {
        Self::pkg_name_and_version_from_archive_result(path)
            .ok()
            .flatten()
    }

    fn package_archive_reader(path: &Path, budget: u64) -> Result<Box<dyn Read>> {
        let pinned = ArchiveSnapshot::from_handoff(&path.to_string_lossy())?;
        let file = match &pinned {
            Some(snapshot) => snapshot.reader()?,
            None => File::open(path)?,
        };
        super::archive_reader::decode(file, budget)
    }

    fn pkg_name_and_version_from_archive_result(path: &Path) -> Result<Option<(String, String)>> {
        let reader = Self::package_archive_reader(path, MAX_DECOMPRESSED_BYTES)?;
        let mut archive = tar::Archive::new(reader);
        for entry in archive.entries()? {
            let entry = entry?;
            let entry_path = entry.path()?;
            if entry_path.components().count() <= 2
                && let Some(file_name) = entry_path.file_name().and_then(|name| name.to_str())
                && matches!(file_name, ".PKGINFO" | "PKGINFO")
            {
                if entry.size() > MAX_PKGINFO_BYTES {
                    anyhow::bail!(
                        "Package metadata in {} exceeds the {} byte limit",
                        path.display(),
                        MAX_PKGINFO_BYTES
                    );
                }
                let mut content = String::with_capacity(entry.size() as usize);
                entry
                    .take(MAX_PKGINFO_BYTES + 1)
                    .read_to_string(&mut content)?;
                if content.len() as u64 > MAX_PKGINFO_BYTES {
                    anyhow::bail!(
                        "Package metadata in {} exceeds the {} byte limit",
                        path.display(),
                        MAX_PKGINFO_BYTES
                    );
                }
                return Ok(Self::parse_pkginfo_name_version(&content));
            }
        }
        Ok(None)
    }

    async fn aur_dependency_plan(
        &self,
        source: &ReviewedSource,
        package: &str,
        requested_outputs: &[String],
    ) -> Result<AurDependencyPlan> {
        let srcinfo = source.required_srcinfo(package)?;
        let requested_outputs = requested_outputs.to_vec();
        let dep_info = tokio::task::spawn_blocking(move || {
            check_dependencies_from_metadata(&srcinfo, &requested_outputs)
        })
        .await
        .context("AUR dependency inspection task failed")?
        .with_context(|| format!("Failed to inspect dependencies for '{package}'"))?;

        let package_outputs = dep_info.package_outputs;
        let missing_dependencies = dep_info
            .missing
            .into_iter()
            .filter(|dependency| {
                let name = dependency_name(dependency);
                !name.is_empty() && name != package
            })
            .collect::<Vec<_>>();
        let (official_dependencies, other_dependencies) = tokio::task::spawn_blocking(move || {
            crate::package_managers::alpm_direct::with_handle(|alpm| {
                let mut official: BTreeMap<String, OfficialTarget> = BTreeMap::new();
                let mut other = Vec::new();
                for dependency in missing_dependencies {
                    if let Some(selected) = resolve_official_dependency(alpm, &dependency)? {
                        if let Some(existing) = official.get_mut(&selected.name) {
                            existing.relations.extend(selected.relations);
                        } else {
                            official.insert(selected.name.clone(), selected);
                        }
                    } else {
                        other.push(dependency);
                    }
                }
                for selected in official.values_mut() {
                    reconcile_official_dependency(alpm, selected)?;
                }
                Ok((official.into_values().collect(), other))
            })
        })
        .await
        .context("Official dependency classification task failed")??;

        let mut aur_dependencies = Vec::new();
        let mut unresolved = Vec::new();
        for dependency in other_dependencies {
            let name = dependency_name(&dependency);
            if self.info(name).await?.is_some() {
                aur_dependencies.push(name.to_string());
            } else {
                unresolved.push(dependency);
            }
        }

        anyhow::ensure!(
            unresolved.is_empty(),
            "Unresolvable dependencies for '{package}': {}",
            unresolved.join(", ")
        );
        aur_dependencies.sort();
        aur_dependencies.dedup();
        Ok(AurDependencyPlan {
            aur_dependencies,
            official_dependencies,
            package_outputs,
        })
    }

    async fn install_official_dependencies(packages: &[OfficialTarget]) -> Result<()> {
        if packages.is_empty() {
            return Ok(());
        }

        let _install_guard = INSTALL_LOCK.lock().await;
        crate::cli::modern_ui::print_info(&format!(
            "Installing official build dependencies: {}",
            packages
                .iter()
                .map(|package| format!("{}/{}", package.repository, package.name))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        let request = InstallRequest::new(
            packages
                .iter()
                .map(|package| InstallItem {
                    target: InstallTarget::Resolved(package.clone()),
                    intent: InstallIntent::Automatic,
                })
                .collect(),
        )?;
        crate::package_managers::arch::install_request(request)
            .await
            .context("Failed to install official AUR build dependencies")
    }

    async fn ensure_dependencies_satisfied(
        &self,
        source: &ReviewedSource,
        package_outputs: &[String],
    ) -> Result<()> {
        let srcinfo = source
            .optional_srcinfo()?
            .context("AUR build has no .SRCINFO")?;
        let package_outputs = package_outputs.to_vec();
        self.blocking_build_work(move || {
            let remaining = check_dependencies_from_metadata(&srcinfo, &package_outputs)
                .context("Failed to verify AUR build dependencies")?
                .missing;
            anyhow::ensure!(
                remaining.is_empty(),
                "AUR build dependencies remain unsatisfied after installation: {}",
                remaining.join(", ")
            );
            Ok(())
        })
        .await
        .context("AUR dependency verification task failed")
    }

    async fn git_clone(&self, package: &str) -> Result<()> {
        self.git_clone_from(package, &format!("{AUR_GIT_URL}/{package}.git"))
            .await
    }

    async fn git_clone_from(&self, package: &str, url: &str) -> Result<()> {
        let safe_url = crate::core::http::redact_url(url);
        let dest = self.build_dir.join(package);

        if let Some(user) = original_user() {
            let home = original_user_home()?;
            let dest_str = dest.to_string_lossy();

            let mut cmd = Command::from(sudo_as_user_program(&user, "git")?);

            if let Some(ref home_path) = home {
                cmd.env("HOME", home_path);
            }

            cmd.args([
                "clone",
                "--depth=1",
                "--filter=blob:none",
                "--",
                url,
                dest_str.as_ref(),
            ]);

            cmd.env("GIT_TERMINAL_PROMPT", "0");
            configure_auxiliary_output(&mut cmd);

            let status = cmd
                .stdin(std::process::Stdio::null())
                .status()
                .await
                .with_context(|| format!("Failed to run git clone as user '{user}'"))?;

            if !status.success() {
                anyhow::bail!("git clone failed for {safe_url}");
            }
        } else {
            let mut command = Command::new("git");
            command
                .args(["clone", "--depth=1", "--filter=blob:none", "--"])
                .arg(url)
                .arg(&dest)
                .env("GIT_TERMINAL_PROMPT", "0")
                .stdin(std::process::Stdio::null());
            configure_auxiliary_output(&mut command);
            let status = command
                .status()
                .await
                .with_context(|| format!("Failed to run git clone for {safe_url}"))?;
            if !status.success() {
                anyhow::bail!("git clone failed for {safe_url}");
            }
        }
        Ok(())
    }

    async fn git_pull(&self, pkg_dir: &Path) -> Result<()> {
        let package = pkg_dir
            .file_name()
            .and_then(|name| name.to_str())
            .context("Invalid AUR source directory")?;
        crate::core::security::validate_package_name(package)?;
        self.refresh_checkout_from(pkg_dir, &format!("{AUR_GIT_URL}/{package}.git"))
            .await
    }

    /// Discard a previously built checkout and clone it again.
    ///
    /// Any checkout a sandboxed PKGBUILD could write is untrusted input:
    /// `.git/config` and `.git/info/attributes` survive `git clean`, and both
    /// can name a filter or hook that Git would then run on the host during an
    /// in-place refresh. Cloning from the remote again is what guarantees the
    /// refresh never executes attacker-controlled Git configuration
    /// (csf_63f859d75634568213c96858).
    async fn refresh_checkout_from(&self, pkg_dir: &Path, url: &str) -> Result<()> {
        let package = pkg_dir
            .file_name()
            .and_then(|name| name.to_str())
            .context("Invalid AUR source directory")?;
        crate::core::security::validate_package_name(package)?;
        remove_dir_as_user(pkg_dir).await?;
        self.git_clone_from(package, url).await
    }

    async fn run_build(
        &self,
        pkg_dir: &Path,
        env: &MakepkgEnv,
        package: &str,
        source: &ReviewedSource,
    ) -> Result<std::process::ExitStatus> {
        self.settings.aur.validate_security_profile()?;
        if !self.settings.aur.allow_network {
            let metadata = source.optional_srcinfo()?;
            let sources = metadata.as_deref().map_or_else(Vec::new, http_sources);
            let summary = download_sources(sources, &env.srcdest).await;
            anyhow::ensure!(
                summary.failed == 0,
                "AUR source prefetch failed; build networking is disabled. Cache the declared sources before retrying."
            );

            // VCS sources (git+, svn+, …) are fetched by makepkg with a VCS
            // client, which cannot reach the network inside the sandbox. Mirror
            // the ones omg can reproduce into SRCDEST, and fail with an
            // actionable message for the rest instead of letting makepkg
            // surface a bare DNS failure from inside the namespace.
            let vcs_sources = metadata.as_deref().map_or_else(Vec::new, vcs_sources);
            if !vcs_sources.is_empty() {
                let vcs = prefetch_vcs_sources(&vcs_sources, &env.srcdest).await;
                anyhow::ensure!(
                    vcs.needs_network.is_empty(),
                    "AUR package '{package}' declares VCS sources that must be fetched while building, \
                     but build networking is disabled and no cached copy exists in SRCDEST: {}. \
                     Set 'aur.allow_network = true' (or pre-populate SRCDEST) and retry.",
                    vcs.needs_network.join(", ")
                );
            }
        }
        match self.settings.aur.build_method {
            AurBuildMethod::Bubblewrap => self.run_sandboxed_makepkg(pkg_dir, env, package).await,
            AurBuildMethod::Chroot => self.run_chroot_build(pkg_dir, env, package).await,
            AurBuildMethod::Native => {
                if !self.settings.aur.allow_unsafe_builds {
                    anyhow::bail!(
                        "Native AUR builds are disabled. Enable 'aur.allow_unsafe_builds' or use bubblewrap/chroot."
                    );
                }
                self.run_native_makepkg(pkg_dir, env, package).await
            }
        }
    }

    /// Run makepkg with bubblewrap sandboxing if available
    /// Falls back to regular makepkg if bwrap is not installed and unsafe builds are allowed
    async fn run_sandboxed_makepkg(
        &self,
        pkg_dir: &Path,
        env: &MakepkgEnv,
        package: &str,
    ) -> Result<std::process::ExitStatus> {
        let bwrap_available = crate::core::privilege::root_controlled_program_path("bwrap").is_ok();

        if bwrap_available {
            tracing::info!("Using bubblewrap sandbox for secure AUR build");

            // Repository dependencies were installed before entering the
            // sandbox; the untrusted build itself receives no sudo-capable TTY.

            // - Read-only bind: /usr, /etc, /lib, /lib64
            // - Writable: Build directory, /tmp
            // - Minimal device access

            // Security: Canonicalize all writable paths to prevent symlink-based sandbox escapes
            // An attacker could create symlink: ~/.cache/omg/aur/evil -> /etc
            // Without this check, we'd bind /etc as writable inside the sandbox
            use super::utils::validate_path_inside;

            // Validate pkg_dir isn't a symlink and is inside build_dir.
            // Fails closed: an uninspectable path is rejected, not trusted.
            if is_symlink(pkg_dir)
                .context("Security: Cannot inspect package directory (potential sandbox escape)")?
            {
                anyhow::bail!(
                    "Security: Package directory is a symlink (potential sandbox escape): {}",
                    pkg_dir.display()
                );
            }
            validate_path_inside(&self.build_dir, pkg_dir)?;

            // Canonicalize all writable bind mount paths
            let pkg_dir_canonical = pkg_dir
                .canonicalize()
                .with_context(|| format!("Failed to canonicalize: {}", pkg_dir.display()))?;
            let pkgdest_canonical = env.pkgdest.canonicalize().with_context(|| {
                format!("Failed to canonicalize pkgdest: {}", env.pkgdest.display())
            })?;
            let srcdest_canonical = env.srcdest.canonicalize().with_context(|| {
                format!("Failed to canonicalize srcdest: {}", env.srcdest.display())
            })?;
            let builddir_canonical = env.builddir.canonicalize().with_context(|| {
                format!(
                    "Failed to canonicalize builddir: {}",
                    env.builddir.display()
                )
            })?;

            // Verify all writable paths are inside user's cache directory (not /etc, /root, etc.)
            let cache_base = paths::cache_dir().canonicalize().with_context(|| {
                format!(
                    "Failed to canonicalize cache directory: {}",
                    paths::cache_dir().display()
                )
            })?;
            for (name, path) in [
                ("pkgdest", &pkgdest_canonical),
                ("srcdest", &srcdest_canonical),
                ("builddir", &builddir_canonical),
            ] {
                if !path.starts_with(&cache_base) {
                    anyhow::bail!(
                        "Security: {} escapes cache directory!\n  Path: {}\n  Allowed: {}/*",
                        name,
                        path.display(),
                        cache_base.display()
                    );
                }
            }
            let compiler_cache_mounts =
                Self::sandbox_cache_mounts(&cache_base, &env.compiler_cache_dirs)?;
            let pgp_home = env
                .pgp_home
                .as_ref()
                .map(|home| {
                    home.path().canonicalize().with_context(|| {
                        format!(
                            "Failed to canonicalize package-scoped PGP keyring: {}",
                            home.path().display()
                        )
                    })
                })
                .transpose()?;
            if let Some(path) = &pgp_home {
                anyhow::ensure!(
                    path.starts_with(&cache_base),
                    "Security: package-scoped PGP keyring escapes cache directory: {}",
                    path.display()
                );
            }

            let pkg_dir_str = pkg_dir_canonical.to_string_lossy();
            let (build_user_name, home) = build_identity();

            let pkgdest_str = pkgdest_canonical.to_string_lossy();
            let srcdest_str = srcdest_canonical.to_string_lossy();
            let builddir_str = builddir_canonical.to_string_lossy();
            let pacman_db_dir = paths::pacman_db_dir_result()?;
            let pacman_db_dir_str = pacman_db_dir.to_string_lossy();
            let pacman_cache_root = paths::pacman_cache_root_dir_result()?;
            let pacman_cache_root_str = pacman_cache_root.to_string_lossy();
            let home_str = home.to_string_lossy();
            let mut mount_destinations = vec![
                home.as_path(),
                pkg_dir_canonical.as_path(),
                pkgdest_canonical.as_path(),
                srcdest_canonical.as_path(),
                pacman_db_dir.as_path(),
                pacman_cache_root.as_path(),
            ];
            mount_destinations.extend(compiler_cache_mounts.iter().map(PathBuf::as_path));
            mount_destinations.extend(pgp_home.as_deref());
            let build_root = sandbox_build_root(&mount_destinations)?;

            // Keep bwrap as omg's direct child for parent-death handling.
            // Its PID namespace makes cancellation kill compiler descendants
            // too; --die-with-parent alone only kills the direct command.
            // --new-session blocks reuse of tty-scoped sudo credentials.
            let mut cmd = sandbox_command(&home, &build_user_name)?;
            if self.settings.aur.allow_network {
                crate::cli::modern_ui::print_warning(
                    "AUR build networking is enabled: untrusted build code can reach host-local and private services.",
                );
            } else {
                cmd.arg("--unshare-net");
            }
            cmd.args([
                "--ro-bind",
                "/usr",
                "/usr",
                "--ro-bind",
                "/etc",
                "/etc",
                "--ro-bind",
                "/lib",
                "/lib",
                "--ro-bind",
                "/lib64",
                "/lib64",
                "--symlink",
                "/usr/bin",
                "/bin",
                "--symlink",
                "/usr/sbin",
                "/sbin",
                "--tmpfs",
            ]);
            cmd.arg(&*home_str);
            configure_sandbox_resolver(&mut cmd)?;

            cmd.args(["--bind"]);
            cmd.arg(&*pkg_dir_str);
            cmd.arg(&*pkg_dir_str);
            cmd.args(["--bind"]);
            cmd.arg(&*pkgdest_str);
            cmd.arg(&*pkgdest_str);
            cmd.args(["--bind"]);
            cmd.arg(&*srcdest_str);
            cmd.arg(&*srcdest_str);
            cmd.args(["--bind"]);
            cmd.arg(&*builddir_str);
            cmd.arg(&build_root);
            for cache_dir in &compiler_cache_mounts {
                cmd.args(["--bind"]);
                cmd.arg(cache_dir);
                cmd.arg(cache_dir);
            }
            if let Some(path) = &pgp_home {
                cmd.args(["--bind"]);
                cmd.arg(path);
                cmd.arg(path);
            }
            cmd.args([
                "--tmpfs",
                "/tmp",
                "--dev",
                "/dev",
                "--proc",
                "/proc",
                "--ro-bind",
            ]);
            cmd.arg(&*pacman_db_dir_str);
            cmd.arg(&*pacman_db_dir_str);
            cmd.args(["--ro-bind"]);
            cmd.arg(&*pacman_cache_root_str);
            cmd.arg(&*pacman_cache_root_str);
            cmd.arg("--chdir");
            cmd.arg(&*pkg_dir_str);
            for (key, value) in [
                ("HOME", home_str.as_ref()),
                ("XDG_CACHE_HOME", "/tmp/.cache"),
                ("USER", build_user_name.as_str()),
                ("LOGNAME", build_user_name.as_str()),
                ("PATH", "/usr/local/sbin:/usr/local/bin:/usr/bin"),
                ("LANG", "C.UTF-8"),
                ("LC_ALL", "C.UTF-8"),
                SANDBOX_FAKEROOT_ENV,
            ] {
                cmd.args(["--setenv", key, value]);
            }
            cmd.args(["--setenv", "MAKEFLAGS"]);
            cmd.arg(&env.makeflags);
            cmd.args(["--setenv", "PKGDEST"]);
            cmd.arg(&*pkgdest_str);
            cmd.args(["--setenv", "SRCDEST"]);
            cmd.arg(&*srcdest_str);
            cmd.args(["--setenv", "BUILDDIR"]);
            cmd.arg(&build_root);
            if let Some(path) = &pgp_home {
                cmd.args(["--setenv", "GNUPGHOME"]);
                cmd.arg(path);
            }

            for (key, value) in &env.extra_env {
                cmd.args(["--setenv", key, value]);
            }

            // Use sandbox-safe args (no -s since deps installed above)
            let makepkg_args = self.makepkg_args_sandbox();
            cmd.args(["--", "makepkg"]);
            cmd.args(makepkg_args);

            cmd.stdin(Stdio::null());
            self.run_logged_build_command(&mut cmd, package, BuildIsolation::ProcessGroup)
                .await
                .context("Failed to run sandboxed makepkg")
        } else {
            if !self.settings.aur.allow_unsafe_builds {
                return Err(AurError::SandboxUnavailable.into());
            }

            tracing::debug!("bubblewrap not found, using regular makepkg");
            println!(
                "{} Building without sandbox (install 'bubblewrap' for isolation)...",
                crate::cli::style::dim("→")
            );
            self.run_native_makepkg(pkg_dir, env, package).await
        }
    }

    async fn run_native_makepkg(
        &self,
        pkg_dir: &Path,
        env: &MakepkgEnv,
        package: &str,
    ) -> Result<std::process::ExitStatus> {
        let (build_user, build_home) = build_identity();

        // Install and rollback reject root before reaching the build path.
        // Untrusted PKGBUILDs still need an allowlisted environment.
        let mut cmd = native_build_command()?;
        configure_build_environment(&mut cmd, &build_home, &build_user);
        if let Some(pgp_home) = &env.pgp_home {
            cmd.env("GNUPGHOME", pgp_home.path());
        }

        // no_new_privs blocks privilege gains even with global sudo tickets.
        // setsid detaches the authentication TTY and propagates the build status.

        cmd.args(self.makepkg_args())
            .env("MAKEFLAGS", &env.makeflags)
            .env("PKGDEST", &env.pkgdest)
            .env("SRCDEST", &env.srcdest)
            .env("BUILDDIR", &env.builddir);

        for (key, value) in &env.extra_env {
            cmd.env(key, value);
        }

        cmd.current_dir(pkg_dir).stdin(Stdio::null());
        self.run_logged_build_command(&mut cmd, package, BuildIsolation::NativeSession)
            .await
            .context("Failed to run makepkg")
    }

    async fn run_chroot_build(
        &self,
        pkg_dir: &Path,
        env: &MakepkgEnv,
        package: &str,
    ) -> Result<std::process::ExitStatus> {
        self.run_chroot_build_with(
            pkg_dir,
            env,
            package,
            crate::core::privilege::root_controlled_program_path,
        )
        .await
    }

    async fn run_chroot_build_with(
        &self,
        pkg_dir: &Path,
        env: &MakepkgEnv,
        package: &str,
        resolve_program: impl Fn(&str) -> Result<PathBuf>,
    ) -> Result<std::process::ExitStatus> {
        anyhow::ensure!(
            self.settings.aur.allow_unsafe_builds,
            "Chroot devtools execute AUR recipe code on the host before isolation. Use bubblewrap, or explicitly enable aur.allow_unsafe_builds to accept host code execution."
        );
        crate::cli::modern_ui::print_warning(
            "AUR chroot devtools will execute recipe code on the host as your user before entering the chroot; private build storage does not isolate that host code.",
        );
        anyhow::ensure!(
            self.settings.aur.allow_network,
            "Chroot devtools cannot enforce offline builds; choose bubblewrap or explicitly enable aur.allow_network"
        );
        let mut cmd = chroot_build_command(self.settings.aur.secure_makepkg, resolve_program)?;

        let (build_user, build_home) = build_identity();
        configure_build_environment(&mut cmd, &build_home, &build_user);
        if let Some(pgp_home) = &env.pgp_home {
            cmd.env("GNUPGHOME", pgp_home.path());
        }
        cmd.current_dir(pkg_dir)
            .env("MAKEFLAGS", &env.makeflags)
            .env("PKGDEST", &env.pkgdest)
            .env("SRCDEST", &env.srcdest)
            .env("BUILDDIR", &env.builddir);
        for (key, value) in &env.extra_env {
            cmd.env(key, value);
        }

        self.run_logged_build_command(&mut cmd, package, BuildIsolation::NativeSession)
            .await
            .context("Failed to run chroot build")
    }

    fn build_log_path(&self, package: &str) -> PathBuf {
        self.build_dir.join("_logs").join(format!("{package}.log"))
    }

    async fn run_logged_build_command(
        &self,
        command: &mut Command,
        package: &str,
        isolation: BuildIsolation,
    ) -> Result<std::process::ExitStatus> {
        self.run_logged_build_command_with_limits(
            command,
            package,
            MAX_AUR_BUILD_LOG_BYTES,
            MAX_AUR_BUILD_DURATION,
            isolation,
        )
        .await
    }

    async fn run_logged_build_command_with_limits(
        &self,
        command: &mut Command,
        package: &str,
        max_log_bytes: u64,
        max_duration: Duration,
        isolation: BuildIsolation,
    ) -> Result<std::process::ExitStatus> {
        let log_path = self.build_log_path(package);
        let log_dir = log_path
            .parent()
            .context("AUR build log path must have a parent directory")?;
        tokio::fs::create_dir_all(log_dir).await.with_context(|| {
            format!(
                "Failed to create build log directory: {}",
                log_dir.display()
            )
        })?;
        let log = tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&log_path)
            .await
            .with_context(|| format!("Failed to create build log: {}", log_path.display()))?;
        let log = Arc::new(tokio::sync::Mutex::new(BuildLog {
            file: log,
            bytes: 0,
            limit: max_log_bytes,
        }));

        let progress = crate::cli::modern_ui::aur_build_progress(package, &log_path);
        let verbose =
            crate::cli::modern_ui::output_mode() == crate::cli::modern_ui::OutputMode::Verbose;

        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        match isolation {
            BuildIsolation::ProcessGroup => {
                command.process_group(0);
            }
            BuildIsolation::NativeSession => {
                // A group leader makes util-linux setsid fork, losing the PID
                // tracked below. Inherit our group so setsid execs in-place;
                // the build then owns a detached session whose PGID is child.id().
                let parent_group = nix::unistd::getpgrp().as_raw();
                // Zero can denote a group outside our PID namespace. Passing
                // it to setpgid creates a child group instead of inheriting it.
                if parent_group != 0 {
                    command.process_group(parent_group);
                }
            }
        }
        let child = command
            .spawn()
            .with_context(|| format!("Failed to start AUR build for '{package}'"))?;
        let process_group = child.id().context("AUR build has no process ID")?;
        let mut build = BuildProcess {
            child: Some(child),
            group: process_group,
            reaper: tokio::runtime::Handle::current(),
        };
        let child = build
            .child
            .as_mut()
            .context("AUR build child was not available")?;
        let stdout = child
            .stdout
            .take()
            .context("AUR build stdout pipe was not available")?;
        let stderr = child
            .stderr
            .take()
            .context("AUR build stderr pipe was not available")?;

        let stdout_capture = Box::pin(drain_build_output(
            stdout,
            Arc::clone(&log),
            BuildOutputStream::Stdout,
            verbose,
        ));
        let stderr_capture = Box::pin(drain_build_output(
            stderr,
            Arc::clone(&log),
            BuildOutputStream::Stderr,
            verbose,
        ));
        let result = tokio::time::timeout(max_duration, async {
            tokio::try_join!(child.wait(), stdout_capture, stderr_capture)
        })
        .await;

        let status = match result {
            Ok(Ok((status, (), ()))) => status,
            Ok(Err(error)) => {
                build.terminate_and_reap().await?;
                progress.finish(false);
                return Err(error).context("AUR build output capture failed");
            }
            Err(_) => {
                build.terminate_and_reap().await?;
                progress.finish(false);
                anyhow::bail!(
                    "AUR build exceeded the {}-second duration limit",
                    max_duration.as_secs()
                );
            }
        };
        build.child = None;
        let capture_result = log
            .lock()
            .await
            .file
            .flush()
            .await
            .context("Failed to flush AUR build log");

        progress.finish(status.success() && capture_result.is_ok());
        capture_result?;
        Ok(status)
    }

    fn makepkg_args(&self) -> Vec<&'static str> {
        let mut args = vec!["--noconfirm", "-f", "--needed"];
        if self.settings.aur.secure_makepkg {
            args.push("--cleanbuild");
        }
        args
    }

    /// Makepkg args for sandboxed builds (omits `--needed` for clean sandbox rebuilds).
    fn makepkg_args_sandbox(&self) -> Vec<&'static str> {
        let mut args = vec!["--noconfirm", "-f"];
        if self.settings.aur.secure_makepkg {
            args.push("--cleanbuild");
        }
        args
    }

    /// Display and confirm a PKGBUILD before any script-driven side effect.
    ///
    /// Captures all local build inputs and their manifest digest so the caller
    /// can reject additions, removals, permission changes and modified content
    /// immediately before building.
    async fn review_pkgbuild(
        package: &str,
        pkgbuild_path: &Path,
        profile: crate::config::AurSecurityProfile,
    ) -> Result<ReviewedSource> {
        // Quiesce before joining the review queue: a queued review should
        // hold one continuous quiesce across the wait and confirm, so
        // concurrent spinners neither flicker nor overwrite review output.
        let _quiesce_guard = crate::cli::modern_ui::quiesce_terminal();
        // Parallel build waves may discover several independent packages at
        // once. One review owns the terminal at a time so prompts and source
        // text cannot interleave.
        let _review_guard = REVIEW_LOCK.lock().await;
        if !console::user_attended() {
            anyhow::bail!(
                "PKGBUILD review requires an interactive terminal. Run in an interactive terminal to review each PKGBUILD, or set aur.review_pkgbuild=false if you accept unreviewed AUR code."
            );
        }

        let source_dir = pkgbuild_path.parent().context("Missing source directory")?;
        let source = ReviewedSource::capture(source_dir)?;
        let pkgbuild_bytes = source
            .files
            .get(Path::new("PKGBUILD"))
            .context("AUR review captured no PKGBUILD")?;
        let review = pkgbuild_review_text(pkgbuild_bytes)?;
        let extra_files: Vec<AurReviewFiles<'_>> = source
            .files
            .iter()
            .filter(|(path, _)| path.as_path() != Path::new("PKGBUILD"))
            .map(|(path, bytes)| AurReviewFiles {
                relative: path.as_path(),
                bytes: bytes.len(),
                digest: pkgbuild_digest(bytes),
            })
            .collect();
        let verbose = crate::cli::modern_ui::is_verbose();
        let install_hooks = declared_install_hook_previews(&source)?;
        println!(
            "{}",
            pkgbuild_review_panel(
                package,
                &source.digest,
                &review,
                pkgbuild_path,
                &extra_files,
                &install_hooks,
                verbose,
            )
        );

        if profile == crate::config::AurSecurityProfile::Hardened
            || !crate::core::privilege::get_yes_flag()
        {
            let proceed = confirm_prompt(pkgbuild_review_prompt(package), true).await?;
            if !proceed {
                anyhow::bail!("Build aborted by user after PKGBUILD review.");
            }
        }
        Ok(source)
    }

    /// Whether AUR builds will demand interactive PKGBUILD review. The
    /// settings field is private; parallel build orchestration needs this to
    /// bail before cloning when no terminal is available for the review.
    pub(crate) fn requires_interactive_review(&self) -> bool {
        self.settings.aur.review_pkgbuild
    }

    #[cfg(feature = "pgp")]
    async fn fetch_missing_pgp_keys(pkgbuild_path: &Path) -> Result<Option<tempfile::TempDir>> {
        use crate::core::security::keyserver;

        let pkgbuild_path = pkgbuild_path.to_path_buf();
        let keyring_state = tokio::task::spawn_blocking(move || {
            let pkgbuild = PkgBuild::parse(&pkgbuild_path).with_context(|| {
                format!(
                    "Failed to parse PKGBUILD at {} for PGP keys",
                    pkgbuild_path.display()
                )
            })?;
            if pkgbuild.validpgpkeys.is_empty() {
                return Ok(None);
            }
            let gnupg_home = std::env::var_os("GNUPGHOME")
                .map(PathBuf::from)
                .or_else(|| dirs::home_dir().map(|home| home.join(".gnupg")))
                .context("Cannot determine home directory for GnuPG keyring")?;
            let mut missing_keys = Vec::with_capacity(pkgbuild.validpgpkeys.len());
            for key_id in &pkgbuild.validpgpkeys {
                require_fetchable_pgp_key_id(key_id)?;
                match keyserver::is_key_in_gnupg(key_id, &gnupg_home) {
                    Ok(true) => {}
                    Ok(false) => missing_keys.push(key_id.clone()),
                    Err(error) => {
                        anyhow::bail!("Failed to read PGP keyring while checking {key_id}: {error}")
                    }
                }
            }
            Ok::<_, anyhow::Error>(Some((pkgbuild.validpgpkeys, missing_keys, gnupg_home)))
        })
        .await
        .context("AUR PGP keyring inspection task failed")??;
        let Some((valid_keys, missing_keys, gnupg_home)) = keyring_state else {
            return Ok(None);
        };

        let fetched_keys = if missing_keys.is_empty() {
            Vec::new()
        } else {
            tracing::info!("Fetching {} missing PGP key(s)...", missing_keys.len());
            keyserver::fetch_keys(&missing_keys)
                .await
                .into_iter()
                .map(|(key_id, result)| match result {
                    Ok(certificate) => Ok((key_id, certificate)),
                    Err(error) => Err(anyhow::anyhow!("Failed to fetch PGP key {key_id}: {error}")),
                })
                .collect::<Result<Vec<_>>>()?
        };
        let cache_dir = paths::cache_dir();

        tokio::task::spawn_blocking(move || {
            for (key_id, certificate) in fetched_keys {
                let info = keyserver::get_key_info(&certificate);
                tracing::debug!("Fetched PGP key: {info}");
                keyserver::import_key_into_gnupg(&certificate, &gnupg_home)
                    .with_context(|| format!("Failed to import key {key_id} into GnuPG"))?;
            }

            create_scoped_pgp_home(&valid_keys, &gnupg_home, &cache_dir).map(Some)
        })
        .await
        .context("AUR PGP key import task failed")?
    }

    #[cfg(not(feature = "pgp"))]
    #[expect(clippy::unused_async)]
    async fn fetch_missing_pgp_keys(_pkgbuild_path: &Path) -> Result<Option<tempfile::TempDir>> {
        tracing::debug!("PGP feature disabled, skipping key fetch");
        Ok(None)
    }

    fn sandbox_cache_mounts(cache_base: &Path, cache_dirs: &[PathBuf]) -> Result<Vec<PathBuf>> {
        let cache_base = cache_base.canonicalize().with_context(|| {
            format!(
                "Failed to canonicalize cache directory: {}",
                cache_base.display()
            )
        })?;
        let mut mounts = Vec::with_capacity(cache_dirs.len());

        for cache_dir in cache_dirs {
            let canonical = cache_dir.canonicalize().with_context(|| {
                format!(
                    "Failed to canonicalize compiler cache directory: {}",
                    cache_dir.display()
                )
            })?;
            anyhow::ensure!(
                canonical.starts_with(&cache_base),
                "Security: compiler cache directory escapes cache directory: {}",
                canonical.display()
            );
            if !mounts.contains(&canonical) {
                mounts.push(canonical);
            }
        }

        Ok(mounts)
    }

    async fn makepkg_env(&self, pkg_dir: &Path) -> Result<MakepkgEnv> {
        let client = self.clone();
        let pkg_dir = pkg_dir.to_path_buf();
        self.blocking_build_work(move || client.makepkg_env_sync(&pkg_dir))
            .await
            .context("AUR build environment task failed")
    }

    fn makepkg_env_sync(&self, pkg_dir: &Path) -> Result<MakepkgEnv> {
        let jobs = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        let concurrent = self.settings.aur.build_concurrency.max(1);
        let makeflags = compiler_job_flags(
            self.settings.aur.makeflags.as_deref(),
            std::env::var("MAKEFLAGS").ok().as_deref(),
            jobs,
            concurrent,
        );

        // No recipe receives a shared writable cache. A failed or concurrent
        // build must never leave selectable outputs for a different invocation.
        let invocation_base = paths::cache_dir().join("_aur-invocations");
        create_dir_as_user_sync(&invocation_base)?;
        use std::os::unix::fs::PermissionsExt;
        // tempfile's directory default follows the process umask. Request
        // private permissions at creation, before any ownership handoff.
        let invocation = tempfile::Builder::new()
            .prefix("build-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(&invocation_base)?;
        let owner = original_user()
            .map(|name| {
                let account = nix::unistd::User::from_name(&name)?
                    .with_context(|| format!("Original user '{name}' has no system account"))?;
                Ok::<_, anyhow::Error>((account.uid, account.gid))
            })
            .transpose()?;
        prepare_invocation_directory(invocation.path(), owner)?;
        let invocation_path = invocation.path().canonicalize()?;
        let checkout = pkg_dir.canonicalize()?;
        anyhow::ensure!(
            !invocation_path.starts_with(&checkout) && !checkout.starts_with(&invocation_path),
            "AUR checkout overlaps private invocation storage"
        );
        let pkgdest = invocation_path.join("packages");
        let srcdest = invocation_path.join("sources");
        let builddir = invocation_path
            .join("build")
            .join(pkg_dir.file_name().context("Missing AUR checkout name")?);
        create_dir_as_user_sync(&pkgdest)?;
        create_dir_as_user_sync(&srcdest)?;
        create_dir_as_user_sync(&builddir)?;
        if self.settings.aur.cache_builds
            || self.settings.aur.pkgdest.is_some()
            || self.settings.aur.srcdest.is_some()
            || self.settings.aur.ccache_dir.is_some()
            || self.settings.aur.sccache_dir.is_some()
        {
            tracing::warn!(
                "AUR builds use private invocation storage; persistent build/source/compiler caches and custom cache destinations are disabled"
            );
        }

        let mut compiler_cache_dirs = Vec::new();
        let mut extra_env = Vec::new();

        if self.settings.aur.enable_ccache {
            let ccache_dir = invocation_path.join("ccache");
            create_dir_as_user_sync(&ccache_dir)?;
            let ccache_dir = ccache_dir.canonicalize().with_context(|| {
                format!(
                    "Failed to canonicalize ccache directory: {}",
                    ccache_dir.display()
                )
            })?;
            compiler_cache_dirs.push(ccache_dir.clone());
            extra_env.push((
                "CCACHE_DIR".to_string(),
                ccache_dir.to_string_lossy().into_owned(),
            ));
            extra_env.push((
                "CCACHE_BASEDIR".to_string(),
                pkg_dir.to_string_lossy().into_owned(),
            ));
        }

        if self.settings.aur.enable_sccache {
            let sccache_dir = invocation_path.join("sccache");
            create_dir_as_user_sync(&sccache_dir)?;
            let sccache_dir = sccache_dir.canonicalize().with_context(|| {
                format!(
                    "Failed to canonicalize sccache directory: {}",
                    sccache_dir.display()
                )
            })?;
            if !compiler_cache_dirs.contains(&sccache_dir) {
                compiler_cache_dirs.push(sccache_dir.clone());
            }
            extra_env.push(("RUSTC_WRAPPER".to_string(), "sccache".to_string()));
            extra_env.push((
                "SCCACHE_DIR".to_string(),
                sccache_dir.to_string_lossy().into_owned(),
            ));
        }

        Ok(MakepkgEnv {
            _invocation: invocation,
            makeflags,
            pkgdest,
            srcdest,
            builddir,
            compiler_cache_dirs,
            extra_env,
            pgp_home: None,
        })
    }

    #[cfg(test)]
    fn cache_path(&self, package: &str) -> PathBuf {
        self.build_dir
            .join("_buildcache")
            .join(format!("{package}.hash"))
    }

    /// Legacy hash markers bind source text only, not the complete archive.
    /// Do not promote recipe-writable payloads into trusted cache entries.
    /// Reuse stays disabled until controller-owned archive provenance exists.
    #[cfg(test)]
    fn cached_artifacts(
        _cache_name: &str,
        _artifacts: &[String],
        _pkg_dir: &Path,
        _pkgdest: &Path,
        _cache_key: &str,
    ) -> Option<Vec<PathBuf>> {
        None
    }

    /// Install the built package via direct ALPM or elevated OMG transaction.
    pub(crate) async fn install_built_packages(
        batches: &[BuiltPackages],
        sudoloop: Option<&crate::core::sudoloop::SudoLoop>,
    ) -> Result<()> {
        if batches.is_empty() || batches.iter().any(|batch| batch.archives.is_empty()) {
            anyhow::bail!("AUR build produced no package archives to install");
        }

        let settings = Settings::load()?;
        settings.aur.validate_security_profile()?;
        let profile = settings.aur.security_profile;
        let mut inspections = Vec::new();
        let mut items = Vec::new();
        for batch in batches {
            batch.require_profile(profile)?;
            for snapshot in &batch.archives {
                let inspection =
                    artifact_inspector::inspect_archive(&snapshot.path())?.into_inspection();
                snapshot.verify_sha256(&inspection.archive_sha256)?;
                inspection.enforce_profile(profile)?;
                items.push(InstallItem {
                    target: InstallTarget::Archive(snapshot.handoff()),
                    intent: if batch.requested_outputs.contains(&inspection.package_name) {
                        InstallIntent::Requested
                    } else {
                        InstallIntent::Automatic
                    },
                });
                inspections.push(inspection);
            }
        }
        if let Some(prompt) = approval::exception_prompt(&inspections)? {
            let evidence = inspections
                .iter()
                .flat_map(artifact_inspector::ArtifactInspection::audit_details)
                .collect::<Vec<_>>();
            if !console::user_attended() {
                crate::core::security::audit::record_operation(
                    "aur_privilege_approval",
                    &evidence,
                    "rejected_unattended",
                )?;
                anyhow::bail!(
                    "AUR archive requests privileged system integration, an install hook, setuid/setgid mode, or file capability; attended approval is required"
                );
            }
            if !confirm_prompt(prompt, false).await? {
                crate::core::security::audit::record_operation(
                    "aur_privilege_approval",
                    &evidence,
                    "rejected",
                )?;
                anyhow::bail!("AUR exceptional privilege request was not approved");
            }
            crate::core::security::audit::record_operation(
                "aur_privilege_approval",
                &evidence,
                "approved",
            )?;
        }

        // Serialize database mutations across all concurrent builds.
        let _install_guard = INSTALL_LOCK.lock().await;

        if let Some(sl) = sudoloop {
            sl.refresh_now().await;
        }
        let settings = Settings::load()?;
        settings.aur.validate_security_profile()?;
        let current_profile = settings.aur.security_profile;
        for batch in batches {
            batch.require_profile(current_profile)?;
        }
        for inspection in &inspections {
            inspection.enforce_profile(current_profile)?;
        }
        crate::package_managers::arch::install_request(InstallRequest::new(items)?).await?;

        Ok(())
    }

    pub fn clean_all(&self) -> Result<()> {
        // Never unlink the coordination inode. Fail fast rather than wait for
        // a build that may be awaiting user input or resolving dependencies.
        let _lifecycle_guard = BuildLifecycleLease::try_exclusive(self.open_lifecycle_lock()?)
            .context("Cannot clean AUR cache: a build or another cleanup may be active")?;
        if self.build_dir.exists() {
            if let Some(user) = original_user() {
                let status = sudo_as_user_program(&user, "rm")?
                    .args(["-rf", "--"])
                    .arg(&self.build_dir)
                    .status()?;
                if !status.success() {
                    anyhow::bail!("Failed to clean directory as user '{user}'");
                }
            } else {
                std::fs::remove_dir_all(&self.build_dir)?;
            }
            create_dir_as_user_sync(&self.build_dir)?;
            println!(
                "{} Cleaned all AUR build directories",
                crate::cli::style::positive("✓")
            );
        }
        Ok(())
    }
}

fn validate_index_entry_name(name: &str, expected: Option<&str>) -> Result<()> {
    crate::core::security::validate_package_name(name)
        .context("AUR index contains an invalid package name")?;
    if let Some(expected) = expected {
        anyhow::ensure!(
            name == expected,
            "AUR index returned unexpected package '{name}' for '{expected}'"
        );
    }
    Ok(())
}

/// Search AUR with detailed info
pub async fn search_detailed(query: &str) -> Result<Vec<AurPackageDetail>> {
    validate_aur_search_query(query)?;

    let url = format!(
        "{AUR_RPC_URL}?v=5&type=search&arg={}",
        urlencoding::encode(query)
    );

    let response = shared_client()
        .get(&url)
        .send()
        .await
        .map_err(redact_aur_transport_error)?;
    let response: AurDetailedResponse = decode_aur_rpc_response(response).await?;

    // SECURITY: Validate all names in response and precompute match tier once.
    let query_lower = query.to_ascii_lowercase();
    let mut ranked: Vec<(u8, AurPackageDetail)> = response
        .results
        .into_iter()
        .filter(|p| {
            if let Err(e) = crate::core::security::validate_package_name(&p.name) {
                tracing::warn!(
                    "Rejecting invalid package name from AUR search_detailed: {} ({})",
                    p.name,
                    e
                );
                false
            } else {
                true
            }
        })
        .map(|pkg| {
            let name_lower = pkg.name.to_ascii_lowercase();
            let tier = if name_lower == query_lower {
                0
            } else if name_lower.starts_with(&query_lower) {
                1
            } else if has_word_boundary_match(&name_lower, &query_lower) {
                2
            } else {
                3
            };
            (tier, pkg)
        })
        .collect();
    ranked.sort_by(|(a_tier, a), (b_tier, b)| {
        a_tier.cmp(b_tier).then_with(|| {
            b.popularity
                .partial_cmp(&a.popularity)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    });
    let results: Vec<AurPackageDetail> = ranked.into_iter().map(|(_, pkg)| pkg).collect();

    Ok(results)
}

pub(crate) async fn info_detailed_at(
    endpoint: &str,
    package: &str,
) -> Result<Option<AurPackageDetail>> {
    crate::core::security::validate_package_name(package)?;
    let url = format!(
        "{endpoint}?v=5&type=info&arg[]={}",
        urlencoding::encode(package)
    );
    let response = shared_client()
        .get(url)
        .send()
        .await
        .map_err(redact_aur_transport_error)?;
    let mut response: AurDetailedResponse = decode_aur_rpc_response(response).await?;
    anyhow::ensure!(
        response.results.iter().all(|row| row.name == package),
        "AUR RPC info response contained an unrequested package"
    );
    anyhow::ensure!(
        response.results.len() <= 1,
        "AUR RPC info response contained a duplicate package"
    );
    Ok(response.results.pop())
}

#[derive(Debug, Deserialize)]
struct AurDetailedResponse {
    results: Vec<AurPackageDetail>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AurPackageDetail {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Description")]
    pub description: Option<String>,
    #[serde(rename = "Maintainer")]
    pub maintainer: Option<String>,
    #[serde(rename = "NumVotes")]
    pub num_votes: i32,
    #[serde(rename = "Popularity")]
    pub popularity: f64,
    #[serde(rename = "OutOfDate")]
    pub out_of_date: Option<i64>,
    #[serde(rename = "FirstSubmitted")]
    pub first_submitted: i64,
    #[serde(rename = "LastModified")]
    pub last_modified: i64,
    #[serde(rename = "URL")]
    pub url: Option<String>,
    #[serde(rename = "Depends")]
    pub depends: Option<Vec<String>>,
    #[serde(rename = "License")]
    pub license: Option<Vec<String>>,
}

fn compiler_job_flags(
    configured: Option<&str>,
    env_makeflags: Option<&str>,
    cpu_jobs: usize,
    concurrent_builds: usize,
) -> String {
    if let Some(flags) = configured.filter(|flags| !flags.is_empty()) {
        return flags.to_string();
    }
    if let Some(flags) = env_makeflags.filter(|flags| !flags.is_empty()) {
        return flags.to_string();
    }
    let per_build = cpu_jobs.saturating_div(concurrent_builds.max(1)).max(1);
    if per_build > 1 {
        format!("-j{per_build}")
    } else {
        String::new()
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used)] // Idiomatic in tests: panics on failure with clear error context
mod tests;

#[cfg(test)]
mod empty_rpc_result_tests;

#[cfg(test)]
mod update_error_tests;
