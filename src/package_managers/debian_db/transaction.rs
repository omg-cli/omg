//! Pure Rust Transaction Engine for Debian/Ubuntu
//!
//! Handles package installation, removal, and upgrades using pure Rust:
//! - .deb archive extraction (ar + tar.xz/tar.gz)
//! - dpkg database updates (atomic rewrite; pre-transaction backup)
//! - Pre/post-install script execution
//! - Rollback of newly installed files, directories, and dpkg status
//!
//! Known limitation: files that a package *overwrites* are removed on
//! rollback but not restored from backup; the dpkg status database is
//! backed up and restored, but prior file contents are not.

#![cfg(any(feature = "debian", feature = "debian-pure"))]

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use tempfile::TempDir;

use super::resolver::ResolutionResult;
use super::validation::require_verified_deb;
use crate::cli::progress::{Accent, Outcome, ProgressTask, TaskKind, TaskSpec};
use crate::runtimes::common::{BudgetedReader, BudgetedSink, BudgetedWriter, decode_xz_to};

/// Transaction state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    /// Transaction created but not started
    Pending,
    /// Downloading packages
    Downloading,
    /// Configuring packages
    Configuring,
    /// Transaction completed successfully
    Completed,
    /// Transaction failed and rolled back
    RolledBack,
}

/// Maximum concurrent package downloads (pipelined architecture)
const MAX_CONCURRENT_PACKAGE_DOWNLOADS: usize = 48;

/// Maximum concurrent package unpacks (parallel extraction with rayon)
const MAX_CONCURRENT_UNPACKS: usize = 16;

/// Maximum retries per download
const MAX_DOWNLOAD_RETRIES: u32 = 3;

/// Upper bound for one ar member inside a `.deb` (control.tar/data.tar as
/// stored, before decompression). The decompressed payload has its own
/// streaming budget ([`crate::runtimes::common::MAX_DECOMPRESSED_BYTES`]);
/// this bounds raw buffering of untrusted archive members.
const MAX_DEB_MEMBER_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Initial backoff for retries (doubles each retry)
const INITIAL_BACKOFF_MS: u64 = 200;

const DPKG_FRONTEND_LOCK_PATH: &str = "/var/lib/dpkg/lock-frontend";
const DPKG_DATABASE_LOCK_PATH: &str = "/var/lib/dpkg/lock";
const DPKG_UPDATES_PATH: &str = "/var/lib/dpkg/updates";
/// Journal of an in-flight omg dpkg transaction. If this file exists at
/// transaction start, an earlier run was killed mid-mutation (flock is
/// released on kill but unpacked files and dpkg state may be torn), so the
/// next transaction refuses to proceed until the operator completes dpkg
/// recovery and removes the file.
const DPKG_TRANSACTION_JOURNAL_PATH: &str = "/var/lib/dpkg/omg-transaction-journal.json";
const MAINTAINER_SCRIPT_TIMEOUT: Duration = Duration::from_mins(15);
static DPKG_TRANSACTION_LOCK: LazyLock<Arc<tokio::sync::Mutex<()>>> =
    LazyLock::new(|| Arc::new(tokio::sync::Mutex::new(())));

struct DpkgLockGuard {
    frontend: File,
    database: File,
}

impl Drop for DpkgLockGuard {
    fn drop(&mut self) {
        for file in [&self.database, &self.frontend] {
            let unlock = nix::libc::flock {
                l_type: nix::libc::F_UNLCK as _,
                l_whence: nix::libc::SEEK_SET as _,
                l_start: 0,
                l_len: 0,
                l_pid: 0,
            };
            if let Err(error) = nix::fcntl::fcntl(file, nix::fcntl::FcntlArg::F_SETLK(&unlock)) {
                tracing::warn!("Failed to release dpkg transaction lock: {error}");
            }
        }
    }
}

fn ensure_no_pending_dpkg_updates_at(updates_path: &Path) -> Result<()> {
    let entries = match fs::read_dir(updates_path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "Failed to inspect pending dpkg updates in {}",
                    updates_path.display()
                )
            });
        }
    };

    let pending = entries.into_iter().next().transpose().with_context(|| {
        format!(
            "Failed to inspect pending dpkg updates in {}",
            updates_path.display()
        )
    })?;
    if let Some(entry) = pending {
        anyhow::bail!(
            "Pending dpkg database update {} must be recovered before this transaction; run 'sudo dpkg --configure -a' and retry",
            entry.path().display()
        );
    }
    Ok(())
}

/// Transaction workspace for privileged runs. Anchored beneath dpkg's own
/// root-owned state directory because `$TMPDIR` is caller-controlled: an
/// attacker-writable parent (preserved through sudo) lets its owner unlink
/// or swap the workspace between steps, and the workspace holds predictable
/// package and rollback filenames while running as root. Non-root callers
/// keep the default honored-TMPDIR behavior (no privilege to abuse).
fn create_transaction_workspace() -> Result<TempDir> {
    if !crate::core::privilege::is_root() {
        return TempDir::new().context("Failed to create transaction temp directory");
    }
    let anchored = Path::new("/var/lib/dpkg/omg-tmp");
    fs::create_dir_all(anchored).with_context(|| {
        format!(
            "Failed to create privileged transaction temp directory {}",
            anchored.display()
        )
    })?;
    fs::set_permissions(anchored, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("Failed to restrict permissions on {}", anchored.display()))?;
    tempfile::Builder::new()
        .prefix("omg-txn-")
        .tempdir_in(anchored)
        .context("Failed to create anchored transaction temp directory")
}

fn acquire_dpkg_locks_at(frontend_path: &Path, database_path: &Path) -> Result<DpkgLockGuard> {
    fn acquire(path: &Path) -> Result<File> {
        let file = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("Failed to open dpkg lock {}", path.display()))?;
        let lock = nix::libc::flock {
            l_type: nix::libc::F_WRLCK as _,
            l_whence: nix::libc::SEEK_SET as _,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        };
        nix::fcntl::fcntl(&file, nix::fcntl::FcntlArg::F_SETLKW(&lock))
            .with_context(|| format!("Failed to acquire dpkg lock {}", path.display()))?;
        Ok(file)
    }

    let frontend = acquire(frontend_path)?;
    let database = acquire(database_path)?;
    Ok(DpkgLockGuard { frontend, database })
}

async fn acquire_dpkg_locks() -> Result<DpkgLockGuard> {
    tokio::task::spawn_blocking(|| {
        let guard = acquire_dpkg_locks_at(
            Path::new(DPKG_FRONTEND_LOCK_PATH),
            Path::new(DPKG_DATABASE_LOCK_PATH),
        )?;
        ensure_no_pending_dpkg_updates_at(Path::new(DPKG_UPDATES_PATH))?;
        Ok(guard)
    })
    .await
    .context("dpkg lock worker failed")?
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct TransactionJournal {
    started_at_unix: u64,
    pid: u32,
    action: String,
    packages: Vec<String>,
}

fn transaction_journal_path() -> PathBuf {
    Path::new(DPKG_TRANSACTION_JOURNAL_PATH).to_path_buf()
}

/// Write the in-flight marker; returns a guard that removes it on drop.
/// The marker survives a SIGKILL (drop does not run), which is exactly the
/// detection signal the next transaction start needs.
fn write_transaction_journal_at(path: &Path, action: &str, packages: &[String]) -> Result<()> {
    let journal = TransactionJournal {
        started_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs()),
        pid: std::process::id(),
        action: action.to_string(),
        packages: packages.to_vec(),
    };
    crate::core::safe_ops::atomic_write_file_sync(
        path,
        serde_json::to_vec(&journal).context("Failed to serialize dpkg transaction journal")?,
    )?;
    Ok(())
}

/// `Some(remediation_message)` when a previous transaction marker exists
/// (including a corrupt one — never proceed on unknown state).
fn stale_transaction_journal(path: &Path) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    let parsed: Option<TransactionJournal> = serde_json::from_str(&content)
        .map_err(|error| {
            tracing::warn!(
                error = %error,
                "Corrupt dpkg transaction journal; treating as interrupted"
            );
        })
        .ok();
    let summary = match parsed {
        Some(journal) => format!(
            "{} of {} package(s), started pid {} at unix epoch {}",
            journal.action,
            journal.packages.len(),
            journal.pid,
            journal.started_at_unix
        ),
        None => "unreadable transaction marker".to_string(),
    };
    Some(format!(
        "An earlier omg dpkg transaction was interrupted mid-run ({summary}). \n\
         Package state may be inconsistent. Complete dpkg recovery first, e.g.:\n\
             sudo dpkg --configure -a\n\
         then remove {} to allow new omg transactions.",
        path.display()
    ))
}

/// RAII journal marker: written at acquire, removed on drop (normal or
/// error path). Survives process kill by design — that residue is the point.
#[derive(Debug)]
struct DpkgTransactionJournalGuard {
    path: PathBuf,
}

impl DpkgTransactionJournalGuard {
    fn acquire_at(path: &Path, action: &str, packages: &[String]) -> Result<Self> {
        if let Some(remediation) = stale_transaction_journal(path) {
            anyhow::bail!("{remediation}");
        }
        write_transaction_journal_at(path, action, packages)?;
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    async fn acquire(action: &str, packages: &[String]) -> Result<Self> {
        let journal_path = transaction_journal_path();
        let packages = packages.to_vec();
        let action = action.to_string();
        tokio::task::spawn_blocking(move || Self::acquire_at(&journal_path, &action, &packages))
            .await
            .context("Transaction journal worker failed")?
    }
}

impl Drop for DpkgTransactionJournalGuard {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_file(&self.path) {
            tracing::warn!(
                error = %error,
                journal = %self.path.display(),
                "Failed to clear dpkg transaction journal"
            );
        }
    }
}

/// A package transaction
pub struct Transaction {
    /// Current state
    pub state: TransactionState,
    /// Packages to install
    pub to_install: Vec<PackageAction>,
    /// Packages to remove
    pub to_remove: Vec<PackageAction>,
    /// Packages to upgrade
    pub to_upgrade: Vec<PackageAction>,
    /// Temporary directory for downloads
    temp_dir: Option<TempDir>,
    /// Backup of files for rollback
    backups: HashMap<PathBuf, PathBuf>,
    /// Files installed by this transaction
    installed_files: Vec<PathBuf>,
    /// Extracted paths grouped by package for dpkg `.list` manifests.
    installed_files_by_package: HashMap<String, Vec<PathBuf>>,
}

impl Default for Transaction {
    fn default() -> Self {
        Self::new()
    }
}

/// Action to perform on a package
#[derive(Debug, Clone)]
pub struct PackageAction {
    /// Package name
    pub name: String,
    /// Version
    pub version: String,
    /// Local .deb file path (after download)
    pub deb_path: Option<PathBuf>,
    /// Download URL
    pub url: Option<String>,
    /// Size in bytes
    pub size: u64,
    /// SHA256 hash (if known from repository metadata)
    pub sha256: Option<String>,
}

impl Transaction {
    /// Create a new transaction from a resolution result.
    #[must_use]
    pub fn from_resolution(result: ResolutionResult) -> Self {
        let to_install: Vec<PackageAction> = result
            .to_install
            .into_iter()
            .map(|name| PackageAction {
                name,
                version: String::new(),
                deb_path: None,
                url: None,
                size: 0,
                sha256: None,
            })
            .collect();

        let to_upgrade: Vec<PackageAction> = result
            .to_upgrade
            .into_iter()
            .map(|(name, _old, new)| PackageAction {
                name,
                version: new,
                deb_path: None,
                url: None,
                size: 0,
                sha256: None,
            })
            .collect();

        let to_remove: Vec<PackageAction> = result
            .to_remove
            .into_iter()
            .map(|name| PackageAction {
                name,
                version: String::new(),
                deb_path: None,
                url: None,
                size: 0,
                sha256: None,
            })
            .collect();

        Self {
            state: TransactionState::Pending,
            to_install,
            to_remove,
            to_upgrade,
            temp_dir: None,
            backups: HashMap::new(),
            installed_files: Vec::new(),
            installed_files_by_package: HashMap::new(),
        }
    }

    /// Create an empty transaction.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: TransactionState::Pending,
            to_install: Vec::new(),
            to_remove: Vec::new(),
            to_upgrade: Vec::new(),
            temp_dir: None,
            backups: HashMap::new(),
            installed_files: Vec::new(),
            installed_files_by_package: HashMap::new(),
        }
    }

    /// Return the private transaction workspace after `execute` initializes it.
    ///
    /// Transaction steps must never fall back to a shared directory: they may
    /// write predictable package and rollback filenames while running as root.
    fn transaction_temp_dir(&self) -> Result<PathBuf> {
        self.temp_dir
            .as_ref()
            .map(|temp_dir| temp_dir.path().to_path_buf())
            .context("Transaction temporary directory is not initialized")
    }

    /// Add a package to remove
    pub fn add_remove(&mut self, name: String) {
        self.to_remove.push(PackageAction {
            name,
            version: String::new(),
            deb_path: None,
            url: None,
            size: 0,
            sha256: None,
        });
    }

    fn validate_action_identifiers(&self) -> Result<()> {
        for action in self
            .to_install
            .iter()
            .chain(&self.to_upgrade)
            .chain(&self.to_remove)
        {
            crate::core::security::validate_package_name(&action.name)
                .with_context(|| format!("Invalid Debian package name: {:?}", action.name))?;
            anyhow::ensure!(
                !action.name.contains(['/', '\\']),
                "Invalid Debian package name contains a path separator: {:?}",
                action.name
            );
            if !action.version.is_empty() {
                crate::core::security::validate_version(&action.version).with_context(|| {
                    format!(
                        "Invalid Debian package version for {}: {:?}",
                        action.name, action.version
                    )
                })?;
            }
        }
        Ok(())
    }

    /// Execute the transaction with pipelined download+unpack
    ///
    /// OPTIMIZATION: Downloads and unpacks run concurrently. As soon as a package
    /// finishes downloading, it's queued for unpacking while other packages continue
    /// downloading. This overlaps I/O-bound (download) and CPU-bound (decompress) work.
    pub async fn execute(&mut self) -> Result<()> {
        anyhow::ensure!(
            cfg!(test),
            "Pure Debian mutations are disabled until repository authority is verified; use the native APT backend"
        );
        self.validate_action_identifiers()?;
        // POSIX record locks interoperate with apt/dpkg but are process-wide,
        // so pair them with a Tokio mutex to serialize transactions inside
        // this process as well. Keep both locks through rollback/completion.
        let process_lock = Arc::clone(&DPKG_TRANSACTION_LOCK).lock_owned().await;
        let dpkg_locks = acquire_dpkg_locks().await?;
        // Journal before any mutation; a SIGKILL leaves it behind as the
        // recovery signal for the next transaction (see journal const doc).
        let package_names: Vec<String> = self
            .to_install
            .iter()
            .chain(self.to_upgrade.iter())
            .map(|action| action.name.clone())
            .collect();
        let _journal =
            DpkgTransactionJournalGuard::acquire("install-upgrade", &package_names).await?;
        tracing::info!(
            "Starting pipelined transaction with {} packages",
            self.package_count()
        );

        // Create temp directory
        self.temp_dir = Some(create_transaction_workspace()?);

        // Use pipelined execution for better performance
        self.state = TransactionState::Downloading;
        if let Err(e) = self.download_and_unpack_pipelined().await {
            tracing::error!("Pipelined execution failed: {}", e);
            self.rollback()?;
            return Err(e).context("Failed during pipelined download/unpack");
        }

        // Configure packages (must be sequential after all unpacking)
        self.state = TransactionState::Configuring;
        if let Err(e) = self
            .configure_packages_on_blocking_pool(process_lock, dpkg_locks)
            .await
        {
            tracing::error!("Configuration failed: {}", e);
            return Err(e).context("Failed during package configuration");
        }

        self.state = TransactionState::Completed;
        tracing::info!("Transaction completed successfully");
        Ok(())
    }

    /// Pipelined download and unpack - starts unpacking while still downloading
    ///
    /// OPTIMIZATION: Uses batched parallel unpacking with rayon for CPU-bound decompression.
    /// Downloads complete packages are collected and unpacked in parallel batches.
    async fn download_and_unpack_pipelined(&mut self) -> Result<()> {
        use tokio::sync::mpsc;

        // Reuse the canonical large-download client so timeout, TLS, pooling,
        // and User-Agent policy cannot drift between package backends.
        let client = crate::core::http::download_client().clone();

        let temp_dir = self.transaction_temp_dir()?;

        // Collect all packages that need downloading
        let packages_to_download: Vec<(usize, String, String, String, Option<String>, u64)> = self
            .to_install
            .iter()
            .chain(self.to_upgrade.iter())
            .enumerate()
            .filter_map(|(idx, action)| {
                action.url.as_ref().map(|url| {
                    (
                        idx,
                        action.name.clone(),
                        action.version.clone(),
                        url.clone(),
                        action.sha256.clone(),
                        action.size,
                    )
                })
            })
            .collect();

        if packages_to_download.is_empty() {
            return Ok(());
        }

        // OPTIMIZATION: Pre-warm connections to the mirror (fire and forget)
        // Extract unique hosts and make HEAD requests to establish connections
        if let Some((_, _, _, first_url, _, _)) = packages_to_download.first()
            && let Ok(url) = reqwest::Url::parse(first_url)
        {
            let warm_url = format!("{}://{}/", url.scheme(), url.host_str().unwrap_or(""));
            // Fire off HEAD requests to warm up connection pool (no waiting)
            for _ in 0..2 {
                let client = client.clone();
                let warm_url = warm_url.clone();
                tokio::spawn(async move {
                    let _ = client.head(&warm_url).send().await;
                });
            }
        }

        let total_packages = packages_to_download.len();
        tracing::info!(
            "Pipelined processing {} packages (download: {}, unpack: {} concurrent)",
            total_packages,
            MAX_CONCURRENT_PACKAGE_DOWNLOADS,
            MAX_CONCURRENT_UNPACKS
        );

        // Setup progress lanes
        let overall = ProgressTask::start(&TaskSpec {
            label: "Processing".to_string(),
            kind: TaskKind::Items {
                total: total_packages as u64,
            },
            accent: Accent::System,
        });

        // Channel for passing downloaded packages to unpack workers
        // Small buffer to reduce memory pressure
        let (tx, mut rx) = mpsc::channel::<(PathBuf, String)>(MAX_CONCURRENT_UNPACKS);

        // Pre-create the download task futures with their own sender clones
        let download_futures: Vec<_> = packages_to_download
            .into_iter()
            .map(|(idx, name, version, url, sha256, expected_size)| {
                let client = client.clone();
                let temp_dir = temp_dir.clone();
                let tx = tx.clone();
                let task = ProgressTask::start(&TaskSpec {
                    label: name.clone(),
                    kind: TaskKind::Bytes { total: None },
                    accent: Accent::Network,
                });

                async move {
                    let result = download_package_streaming(
                        &client,
                        &name,
                        &version,
                        &url,
                        &temp_dir,
                        &task,
                        sha256.as_deref(),
                        expected_size,
                    )
                    .await;

                    match result {
                        Ok(path) => {
                            task.finish(Outcome::Done);

                            // Fail loudly if the unpack worker is gone; a silent
                            // send failure would count the package as downloaded
                            // while it is never unpacked or configured.
                            tx.send((path.clone(), name.clone()))
                                .await
                                .map_err(|_| {
                                    anyhow::anyhow!(
                                        "unpack worker exited before receiving '{name}'; transaction aborted"
                                    )
                                })?;
                            Ok((idx, path))
                        }
                        Err(e) => {
                            task.set_message(&format!("{e}"));
                            task.finish(Outcome::Failed);
                            Err(e)
                        }
                    }
                }
            })
            .collect();

        // Drop our sender so the channel closes when all downloads complete
        drop(tx);

        // Spawn unpack worker thread
        let temp_dir_unpack = temp_dir.clone();
        let unpack_handle = tokio::task::spawn_blocking(move || {
            let rt = tokio::runtime::Handle::current();
            let mut installed_files = Vec::new();
            let mut installed_files_by_package = HashMap::new();
            let mut unpack_errors = Vec::new();

            // OPTIMIZATION: Process packages immediately instead of batching
            // This reduces memory pressure from holding multiple .deb files in memory
            while let Some((deb_path, name)) = rt.block_on(rx.recv()) {
                tracing::debug!("Unpacking {} immediately", name);
                match unpack_deb_standalone(&deb_path, &name, &temp_dir_unpack) {
                    Ok(files) => {
                        installed_files.extend(files.iter().cloned());
                        installed_files_by_package.insert(name.clone(), files);
                        tracing::debug!("Unpacked {} successfully", name);
                    }
                    Err(e) => {
                        // Recover the partial manifest so already-written
                        // files stay tracked for rollback (audit A2).
                        if let Some(partial) = e
                            .downcast_ref::<PartialExtractionError>()
                            .map(|pe| pe.installed_files.clone())
                        {
                            installed_files.extend(partial);
                        }
                        tracing::error!("Failed to unpack {}: {}", name, e);
                        unpack_errors.push((name.clone(), e));
                    }
                }

                // OPTIMIZATION: Delete .deb file immediately after unpacking
                // This reduces disk I/O and frees up temp space quickly
                if let Err(e) = remove_file_if_present(&deb_path) {
                    tracing::error!("Failed to delete unpacked {}: {}", deb_path.display(), e);
                    unpack_errors.push((name.clone(), e));
                }
            }

            (installed_files, installed_files_by_package, unpack_errors)
        });

        // Run downloads concurrently
        let results: Vec<_> = stream::iter(download_futures)
            .buffer_unordered(MAX_CONCURRENT_PACKAGE_DOWNLOADS)
            .inspect(|_| overall.inc(1))
            .collect()
            .await;

        // The lane reports through the unpack summary below, so clear it
        // without printing a durable line (there is no `finish_and_clear`
        // on the lane handle by design).
        overall.clear();

        // Wait for unpacking to complete
        let (installed_files, installed_files_by_package, unpack_errors) = unpack_handle.await?;
        self.installed_files = installed_files;
        self.installed_files_by_package = installed_files_by_package;

        // Check for download failures
        let mut downloaded_paths: HashMap<usize, PathBuf> = HashMap::new();
        let mut download_failures = Vec::new();

        for result in results {
            match result {
                Ok((idx, path)) => {
                    downloaded_paths.insert(idx, path);
                }
                Err(e) => {
                    download_failures.push(e);
                }
            }
        }

        if !download_failures.is_empty() {
            let error_msg = download_failures
                .iter()
                .map(|e| format!("  - {e}"))
                .collect::<Vec<_>>()
                .join("\n");
            anyhow::bail!(
                "Failed to download {} packages:\n{}",
                download_failures.len(),
                error_msg
            );
        }

        if !unpack_errors.is_empty() {
            let error_msg = unpack_errors
                .iter()
                .map(|(name, e)| format!("  - {name}: {e}"))
                .collect::<Vec<_>>()
                .join("\n");
            anyhow::bail!(
                "Failed to unpack {} packages:\n{}",
                unpack_errors.len(),
                error_msg
            );
        }

        // Update package actions with downloaded paths
        for (idx, action) in self
            .to_install
            .iter_mut()
            .chain(self.to_upgrade.iter_mut())
            .enumerate()
        {
            if let Some(path) = downloaded_paths.get(&idx) {
                action.deb_path = Some(path.clone());
            }
        }

        tracing::info!(
            "Pipelined processing complete: {} packages downloaded and unpacked",
            downloaded_paths.len()
        );
        Ok(())
    }

    async fn configure_packages_on_blocking_pool(
        &mut self,
        process_lock: tokio::sync::OwnedMutexGuard<()>,
        dpkg_locks: DpkgLockGuard,
    ) -> Result<()> {
        let slot = Arc::new(std::sync::Mutex::new(std::mem::take(self)));
        let worker_slot = Arc::clone(&slot);
        let join_result = tokio::task::spawn_blocking(move || {
            let _process_lock = process_lock;
            let _dpkg_locks = dpkg_locks;
            let mut transaction = worker_slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                transaction.configure_packages()
            }))
            .unwrap_or_else(|_| Err(anyhow::anyhow!("package configuration worker panicked")));
            if let Err(error) = result {
                return match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    transaction.rollback()
                })) {
                    Ok(Ok(())) => Err(error),
                    Ok(Err(rollback_error)) => {
                        Err(error.context(format!("rollback also failed: {rollback_error:#}")))
                    }
                    Err(_) => Err(error.context("package configuration rollback panicked")),
                };
            }
            Ok(())
        })
        .await;
        *self = Arc::into_inner(slot)
            .context("package configuration worker still holds the transaction")?
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        join_result.context("package configuration worker failed")?
    }

    /// Configure all unpacked packages
    ///
    /// dpkg status updates are merged and written atomically: existing
    /// paragraphs for the same package are *replaced* (an upgrade must not
    /// leave two entries), and a pre-transaction copy of the status file is
    /// recorded for rollback before the first write.
    fn configure_packages(&mut self) -> Result<()> {
        let temp_dir = self.transaction_temp_dir()?;

        // Collect status and dpkg metadata before running postinst. Maintainer
        // scripts may query their own status or conffile registration.
        let mut status_entries: Vec<(String, String)> = Vec::new();
        let mut control_files_to_copy = Vec::new();
        let mut postinst_scripts = Vec::new();

        for action in self.to_install.iter().chain(self.to_upgrade.iter()) {
            let extract_dir = temp_dir.join(&action.name);
            let control_dir = extract_dir.join("DEBIAN");

            let control_file = control_dir.join("control");
            let entry = prepare_status_entry(&control_file)
                .with_context(|| format!("preparing dpkg status entry for {}", action.name))?;
            status_entries.push((action.name.clone(), entry));

            for extension in [
                "conffiles",
                "md5sums",
                "preinst",
                "postinst",
                "prerm",
                "postrm",
                "triggers",
                "shlibs",
            ] {
                let source = control_dir.join(extension);
                if source.exists() {
                    let destination =
                        Path::new(DPKG_INFO_DIR).join(format!("{}.{}", action.name, extension));
                    control_files_to_copy.push((source, destination));
                }
            }

            let postinst = control_dir.join("postinst");
            if postinst.exists() {
                postinst_scripts.push((postinst, action.name.clone()));
            }
        }

        let package_names: Vec<String> = self
            .to_install
            .iter()
            .chain(self.to_upgrade.iter())
            .map(|action| action.name.clone())
            .collect();
        for package_name in package_names {
            let package_files = self
                .installed_files_by_package
                .get(&package_name)
                .with_context(|| format!("missing extracted file list for {package_name}"))?;
            let list_path =
                write_dpkg_file_list(Path::new(DPKG_INFO_DIR), &package_name, package_files)?;
            self.installed_files.push(list_path);
        }

        for (source, destination) in control_files_to_copy {
            copy_control_file(&source, &destination)?;
            self.installed_files.push(destination);
        }

        if !status_entries.is_empty() {
            self.record_dpkg_status_entries(&status_entries, &temp_dir)?;
        }

        for (postinst, package_name) in postinst_scripts {
            run_maintainer_script(&postinst, &package_name, "configure")?;
        }

        Ok(())
    }

    /// Merge `entries` into `/var/lib/dpkg/status` atomically.
    ///
    /// Takes a rollback backup first (registered in `self.backups`), replaces
    /// any existing paragraph for the same package, and persists via
    /// temp-file + rename so a crash cannot truncate the database.
    fn record_dpkg_status_entries(
        &mut self,
        entries: &[(String, String)],
        temp_dir: &Path,
    ) -> Result<()> {
        let status_path = Path::new("/var/lib/dpkg/status");
        let current = match fs::read_to_string(status_path) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => {
                return Err(error).context("Failed to read dpkg status file");
            }
        };

        // Integrity-bound persisted data: snapshot for rollback before the
        // first mutation of this transaction.
        let backup_path = temp_dir.join("dpkg-status.pre-transaction");
        fs::write(&backup_path, &current).with_context(|| {
            format!("Failed to back up dpkg status to {}", backup_path.display())
        })?;
        self.backups.insert(status_path.to_path_buf(), backup_path);

        let updated = merge_status_entries(&current, entries);
        crate::core::safe_ops::atomic_write_file_sync(status_path, updated.as_bytes())
            .context("Failed to persist updated dpkg status")?;

        tracing::debug!("Merged {} dpkg status entries atomically", entries.len());
        Ok(())
    }

    /// Rollback the transaction
    ///
    /// Removes files/directories installed by this transaction and restores
    /// the pre-transaction dpkg status database. Removal problems are
    /// collected: rollback always attempts the integrity-critical status
    /// restore before reporting a combined failure, instead of aborting on
    /// the first stuck path and leaving the package database permanently
    /// inconsistent. Files that a package *overwrote* are removed but their
    /// previous contents are not restored; see the module docs for the full
    /// contract.
    pub fn rollback(&mut self) -> Result<()> {
        tracing::warn!(
            "Rolling back transaction ({} files installed)",
            self.installed_files.len()
        );

        // Reverse order: children were recorded before their parent
        // directories, so unwinding backwards removes files first and then
        // the (now empty) directories created for them.
        let mut removal_failures: Vec<(PathBuf, anyhow::Error)> = Vec::new();
        for file in self.installed_files.iter().rev() {
            if let Err(error) = remove_file_if_present(file) {
                tracing::error!("Rollback could not remove {}: {error:#}", file.display());
                removal_failures.push((file.clone(), error));
            }
        }

        // The dpkg status snapshot is integrity-bound persisted data: its
        // restore must be attempted even when path cleanup got stuck.
        let mut restore_failures: Vec<(PathBuf, anyhow::Error)> = Vec::new();
        for (original, backup) in &self.backups {
            if let Err(error) = restore_backup(backup, original) {
                tracing::error!(
                    "Rollback could not restore {} from {}: {error:#}",
                    original.display(),
                    backup.display()
                );
                restore_failures.push((original.clone(), error));
            }
        }

        self.state = TransactionState::RolledBack;

        if removal_failures.is_empty() && restore_failures.is_empty() {
            tracing::info!("Transaction rolled back successfully");
            return Ok(());
        }

        anyhow::bail!(
            "Rollback incomplete: {} installed path(s) could not be removed, \
             {} backup(s) could not be restored; system may need manual repair. \
             First removal failure: {}; first restore failure: {}",
            removal_failures.len(),
            restore_failures.len(),
            removal_failures
                .first()
                .map_or_else(String::new, |(_, error)| error.to_string()),
            restore_failures
                .first()
                .map_or_else(String::new, |(_, error)| error.to_string()),
        )
    }

    /// Get the total download size.
    ///
    /// Exposed for transaction reporting and integration verification.
    pub fn total_download_size(&self) -> u64 {
        self.to_install.iter().map(|a| a.size).sum::<u64>()
            + self.to_upgrade.iter().map(|a| a.size).sum::<u64>()
    }

    /// Get the number of packages to process
    pub fn package_count(&self) -> usize {
        self.to_install.len() + self.to_upgrade.len() + self.to_remove.len()
    }

    /// Installed packages must have a version in dpkg status; an empty string is not a version.
    fn require_installed_version(name: &str, version: Option<String>) -> Result<String> {
        match version {
            Some(version) if !version.is_empty() => Ok(version),
            Some(_) | None => {
                anyhow::bail!("installed package {name} has no version in dpkg status")
            }
        }
    }

    fn require_package_installed(name: &str, installed: bool) -> Result<()> {
        if installed {
            Ok(())
        } else {
            anyhow::bail!("package {name} is not installed")
        }
    }

    /// Execute package removal
    ///
    /// The whole removal loop (maintainer scripts via `Command`, dpkg status
    /// rewrites with fsync, filesystem walks) is synchronous and unbounded in
    /// wall time, so it runs on the blocking pool instead of the executor.
    /// `indicatif` progress bars are thread-safe and keep drawing from the
    /// blocking thread.
    pub async fn execute_removal(&mut self) -> Result<()> {
        anyhow::ensure!(
            cfg!(test),
            "Pure Debian mutations are disabled; use the native APT backend"
        );
        self.validate_action_identifiers()?;
        if self.to_remove.is_empty() {
            return Ok(());
        }

        let package_names: Vec<String> = self.to_remove.iter().map(|a| a.name.clone()).collect();
        let names_to_validate = package_names.clone();
        tokio::task::spawn_blocking(move || {
            for name in names_to_validate {
                Self::require_package_installed(&name, super::is_installed_fast(&name)?)?;
            }
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("Debian removal validation task failed")??;

        let _process_lock = DPKG_TRANSACTION_LOCK.lock().await;
        let _dpkg_locks = acquire_dpkg_locks().await?;
        let _journal = DpkgTransactionJournalGuard::acquire("remove", &package_names).await?;
        tokio::task::spawn_blocking(move || execute_removal_blocking(&package_names))
            .await
            .context("Package removal task failed")?
    }
}
/// Synchronous body of [`Transaction::execute_removal`], executed on the
/// blocking pool so maintainer scripts and fsync-heavy status rewrites never
/// stall the async executor.
fn execute_removal_blocking(packages_to_remove: &[String]) -> Result<()> {
    tracing::info!("Starting removal of {} packages", packages_to_remove.len());
    let status = fs::read_to_string("/var/lib/dpkg/status")
        .context("Failed to read dpkg status before package removal")?;
    let removal_order = plan_debian_removal(&status, packages_to_remove)?;

    // Setup progress display
    let overall = ProgressTask::start(&TaskSpec {
        label: "Removing".to_string(),
        kind: TaskKind::Items {
            total: packages_to_remove.len() as u64,
        },
        accent: Accent::System,
    });

    remove_packages_sequentially(&removal_order, &overall)?;

    overall.finish(Outcome::Done);
    tracing::info!("Successfully removed {} packages", removal_order.len());
    Ok(())
}

#[derive(Default)]
struct InstalledRemovalPackage {
    essential: bool,
    protected: bool,
    dependency_groups: Vec<Vec<String>>,
}

fn append_removal_dependency_groups(value: &str, groups: &mut Vec<Vec<String>>) {
    for group in value.split(',') {
        let alternatives: Vec<String> = group
            .split('|')
            .filter_map(|alternative| {
                alternative
                    .split_whitespace()
                    .next()
                    .map(|name| name.split(':').next().unwrap_or(name).to_string())
            })
            .filter(|name| !name.is_empty())
            .collect();
        if !alternatives.is_empty() {
            groups.push(alternatives);
        }
    }
}

fn plan_debian_removal(status: &str, requested: &[String]) -> Result<Vec<String>> {
    use std::collections::{BTreeSet, HashSet};

    let mut installed = HashMap::<String, InstalledRemovalPackage>::new();
    for paragraph in status.split("\n\n") {
        if !paragraph
            .lines()
            .any(|line| line == "Status: install ok installed")
        {
            continue;
        }
        let mut name = None;
        let mut info = InstalledRemovalPackage::default();
        let mut reading_dependencies = false;
        for line in paragraph.lines() {
            if line.starts_with(' ') || line.starts_with('\t') {
                if reading_dependencies {
                    append_removal_dependency_groups(line.trim(), &mut info.dependency_groups);
                }
                continue;
            }
            reading_dependencies = false;
            if let Some(value) = line.strip_prefix("Package:") {
                name = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("Essential:") {
                info.essential = value.trim().eq_ignore_ascii_case("yes");
            } else if let Some(value) = line.strip_prefix("Protected:") {
                info.protected = value.trim().eq_ignore_ascii_case("yes");
            } else if let Some(value) = line
                .strip_prefix("Depends:")
                .or_else(|| line.strip_prefix("Pre-Depends:"))
            {
                reading_dependencies = true;
                append_removal_dependency_groups(value.trim(), &mut info.dependency_groups);
            }
        }
        if let Some(name) = name {
            installed.insert(name, info);
        }
    }

    let requested: HashSet<String> = requested.iter().cloned().collect();
    for name in &requested {
        let info = installed
            .get(name)
            .with_context(|| format!("{name} is not installed"))?;
        anyhow::ensure!(
            !info.essential && !info.protected,
            "Refusing to remove protected Debian package '{name}'"
        );
    }

    let installed_names: HashSet<&str> = installed.keys().map(String::as_str).collect();
    let mut blockers = BTreeSet::new();
    for (dependent, info) in &installed {
        if requested.contains(dependent) {
            continue;
        }
        for alternatives in &info.dependency_groups {
            let removes_satisfier = alternatives.iter().any(|name| requested.contains(name));
            let has_remaining_satisfier = alternatives
                .iter()
                .any(|name| installed_names.contains(name.as_str()) && !requested.contains(name));
            if removes_satisfier && !has_remaining_satisfier {
                blockers.insert(dependent.clone());
            }
        }
    }
    anyhow::ensure!(
        blockers.is_empty(),
        "Cannot remove requested packages because these installed packages depend on them: {}",
        blockers.into_iter().collect::<Vec<_>>().join(", ")
    );

    let mut in_degree: HashMap<&str, usize> =
        requested.iter().map(|name| (name.as_str(), 0)).collect();
    let mut dependencies: HashMap<&str, BTreeSet<&str>> = HashMap::new();
    for dependent in &requested {
        let Some(info) = installed.get(dependent) else {
            continue;
        };
        for dependency in info
            .dependency_groups
            .iter()
            .flatten()
            .filter(|name| requested.contains(*name))
        {
            if dependencies
                .entry(dependent)
                .or_default()
                .insert(dependency)
            {
                *in_degree.entry(dependency).or_default() += 1;
            }
        }
    }

    let mut ready: BTreeSet<&str> = in_degree
        .iter()
        .filter_map(|(name, degree)| (*degree == 0).then_some(*name))
        .collect();
    let mut ordered = Vec::with_capacity(requested.len());
    while let Some(name) = ready.pop_first() {
        ordered.push(name.to_string());
        if let Some(package_dependencies) = dependencies.get(name) {
            for dependency in package_dependencies {
                if let Some(degree) = in_degree.get_mut(dependency) {
                    *degree -= 1;
                    if *degree == 0 {
                        ready.insert(dependency);
                    }
                }
            }
        }
    }
    if ordered.len() != requested.len() {
        let already_ordered: HashSet<&str> = ordered.iter().map(String::as_str).collect();
        let mut cycle: Vec<&str> = requested
            .iter()
            .map(String::as_str)
            .filter(|name| !already_ordered.contains(name))
            .collect();
        cycle.sort_unstable();
        tracing::warn!(packages = ?cycle, "Breaking Debian removal dependency cycle");
        ordered.extend(cycle.into_iter().map(str::to_string));
    }
    Ok(ordered)
}

/// Remove `packages_to_remove` one at a time, driving the per-package and
/// overall lanes. Split from [`execute_removal_blocking`] so tests can
/// exercise the removal step sequence without lane setup.
fn remove_packages_sequentially(
    packages_to_remove: &[String],
    overall: &ProgressTask,
) -> Result<()> {
    // Process packages in dependency order (leaves first).
    for package_name in packages_to_remove {
        let task = ProgressTask::start(&TaskSpec {
            label: package_name.clone(),
            kind: TaskKind::Items { total: 6 },
            accent: Accent::System,
        });

        task.set_message("validating");
        task.inc(1);
        Transaction::require_package_installed(
            package_name,
            super::is_installed_fast(package_name)?,
        )?;

        let version = Transaction::require_installed_version(
            package_name,
            super::get_package_version(package_name)?,
        )?;

        task.set_message("prerm");
        task.inc(1);
        run_removal_maintainer_script(package_name, "prerm").map_err(|error| {
            removal_step_failed(&task, overall, package_name, "prerm script", error)
        })?;

        task.set_message("removing files");
        task.inc(1);
        remove_package_files(package_name).map_err(|error| {
            removal_step_failed(&task, overall, package_name, "file removal", error)
        })?;

        task.set_message("postrm");
        task.inc(1);
        run_removal_maintainer_script(package_name, "postrm").map_err(|error| {
            removal_step_failed(&task, overall, package_name, "postrm script", error)
        })?;

        task.set_message("updating status");
        task.inc(1);
        update_dpkg_status_for_removal(package_name).map_err(|error| {
            removal_step_failed(&task, overall, package_name, "status update", error)
        })?;

        task.set_message("cleanup");
        task.inc(1);
        cleanup_dpkg_info_files(package_name)
            .map_err(|error| removal_step_failed(&task, overall, package_name, "cleanup", error))?;

        task.finish(Outcome::Done);
        overall.inc(1);
        tracing::info!("Removed {} v{}", package_name, version);
    }

    Ok(())
}
/// Merge new dpkg status paragraphs into `current`.
///
/// Existing paragraphs whose `Package:` name appears in `entries` are
/// replaced by the new entry; all other paragraphs are preserved verbatim.
/// New entries are appended in the given order. The result keeps dpkg's
/// one-blank-line paragraph separation and a trailing newline.
fn merge_status_entries(current: &str, entries: &[(String, String)]) -> String {
    let mut pending: std::collections::HashMap<&str, &str> = entries
        .iter()
        .map(|(name, entry)| (name.as_str(), entry.as_str()))
        .collect();

    let mut out = String::with_capacity(current.len() + 512);
    for paragraph in current.split("\n\n") {
        if paragraph.trim().is_empty() {
            continue;
        }
        let name = paragraph
            .lines()
            .find_map(|line| line.strip_prefix("Package: "))
            .map(str::trim);
        let replaced = name.and_then(|name| pending.remove(name));
        if let Some(entry) = replaced {
            out.push_str(entry);
        } else {
            out.push_str(paragraph);
            out.push('\n');
        }
        out.push('\n');
    }

    for (name, entry) in entries {
        if pending.remove(name.as_str()).is_some() {
            out.push_str(entry);
            out.push('\n');
        }
    }

    out
}

fn remove_file_if_present(path: &Path) -> Result<()> {
    // Rollback walks `installed_files` in reverse so children are removed
    // before the directories created for them. A directory that still has
    // content pre-dates this transaction and must not be deleted; surfacing
    // that as an error keeps rollback honest instead of destroying foreign
    // files.
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => fs::remove_dir(path)
            .with_context(|| format!("Failed to remove directory {}", path.display())),
        Ok(_) => match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => {
                Err(error).with_context(|| format!("Failed to remove {}", path.display()))
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("Failed to inspect {} for removal", path.display()))
        }
    }
}

fn restore_backup(backup: &Path, original: &Path) -> Result<()> {
    let contents = fs::read(backup).with_context(|| {
        format!(
            "Failed to restore backup {} -> {}",
            backup.display(),
            original.display()
        )
    })?;
    crate::core::safe_ops::atomic_write_file_sync(original, &contents).with_context(|| {
        format!(
            "Failed to restore backup {} -> {}",
            backup.display(),
            original.display()
        )
    })
}

fn copy_control_file(src: &Path, dest: &Path) -> Result<()> {
    fs::copy(src, dest).with_context(|| {
        format!(
            "Failed to copy dpkg control file {} -> {}",
            src.display(),
            dest.display()
        )
    })?;
    fs::File::open(dest)
        .with_context(|| format!("Failed to reopen copied control file {}", dest.display()))?
        .sync_all()
        .with_context(|| format!("Failed to sync copied control file {}", dest.display()))?;
    crate::core::safe_ops::sync_parent_directory_sync(dest).with_context(|| {
        format!(
            "Failed to sync dpkg control directory after copying {}",
            dest.display()
        )
    })
}

fn with_decompressed_tar<R, T>(
    reader: R,
    member_name: &str,
    temp_dir: &Path,
    consume: impl FnOnce(&mut dyn Read) -> Result<T>,
) -> Result<T>
where
    R: Read,
{
    let budget = BudgetedSink::max_budget();
    if member_name.ends_with(".tar.zst") || member_name.ends_with(".tar.zstd") {
        let decoder = ruzstd::decoding::StreamingDecoder::new(reader)
            .map_err(|error| anyhow::anyhow!("Failed to create zstd decoder: {error}"))?;
        let mut bounded = BudgetedReader::new(decoder, budget);
        return consume(&mut bounded);
    }
    if member_name.ends_with(".tar.gz") {
        let decoder = flate2::read::GzDecoder::new(reader);
        let mut bounded = BudgetedReader::new(decoder, budget);
        return consume(&mut bounded);
    }
    if member_name.ends_with(".tar.xz") {
        // Verify the full XZ stream into an anonymous file under the
        // transaction directory, bounding writes before tar parsing.
        let output = tempfile::tempfile_in(temp_dir).with_context(|| {
            format!(
                "Failed to create temporary XZ output in {}",
                temp_dir.display()
            )
        })?;
        let mut output = BudgetedWriter::new(output, budget);
        decode_xz_to(BufReader::new(reader), &mut output)
            .map_err(|error| anyhow::anyhow!("Failed to decompress XZ payload: {error}"))?;
        let mut output = output.into_inner();
        output.seek(SeekFrom::Start(0))?;
        return consume(&mut output);
    }
    if Path::new(member_name)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("tar"))
    {
        let mut bounded = BudgetedReader::new(reader, budget);
        return consume(&mut bounded);
    }
    anyhow::bail!("Unsupported Debian archive member compression: {member_name}")
}

/// Standalone function to unpack a .deb file (for use in pipelined processing)
///
/// This is separate from the Transaction method to allow concurrent unpacking
/// without holding a mutable borrow on the transaction.
fn unpack_deb_standalone(
    deb_path: &Path,
    package_name: &str,
    temp_dir: &Path,
) -> Result<Vec<PathBuf>> {
    tracing::debug!("Unpacking .deb: {} ({})", package_name, deb_path.display());

    let extract_dir = temp_dir.join(package_name);
    fs::create_dir_all(&extract_dir)
        .with_context(|| format!("Failed to create extraction directory for {package_name}"))?;

    // Extract the .deb (ar archive)
    let deb_file = File::open(deb_path)
        .with_context(|| format!("Failed to open .deb file: {}", deb_path.display()))?;
    let mut archive = ar::Archive::new(deb_file);

    let mut control_seen = false;
    let mut data_seen = false;
    let mut installed_files = Vec::new();

    while let Some(entry) = archive.next_entry() {
        let entry = entry?;
        let name = String::from_utf8_lossy(entry.header().identifier())
            .trim_end_matches('/')
            .to_string();
        anyhow::ensure!(
            entry.header().size() <= MAX_DEB_MEMBER_BYTES,
            "Archive member {name} exceeds the {MAX_DEB_MEMBER_BYTES} byte limit"
        );

        if name.starts_with("control.tar") {
            anyhow::ensure!(
                !control_seen,
                "Debian archive contains multiple control members"
            );
            anyhow::ensure!(
                !data_seen,
                "Debian archive control member follows data member"
            );
            control_seen = true;

            let control_dir = extract_dir.join("DEBIAN");
            fs::create_dir_all(&control_dir)?;
            with_decompressed_tar(entry, &name, temp_dir, |reader| {
                extract_tar_stream(reader, &control_dir)
            })?;

            let preinst = control_dir.join("preinst");
            if preinst.exists() {
                run_maintainer_script(&preinst, package_name, "install")?;
            }
        } else if name.starts_with("data.tar") {
            anyhow::ensure!(control_seen, "Debian archive is missing its control member");
            anyhow::ensure!(!data_seen, "Debian archive contains multiple data members");
            data_seen = true;
            installed_files = with_decompressed_tar(entry, &name, temp_dir, |reader| {
                extract_tar_stream_to_root_at(Path::new("/"), reader)
            })?;
        }
    }

    anyhow::ensure!(control_seen, "Debian archive is missing its control member");
    anyhow::ensure!(data_seen, "Debian archive is missing its data member");
    Ok(installed_files)
}

/// Map a data.tar entry path onto an absolute path under `root`, rejecting
/// anything that is not a plain relative path.
///
/// Debian data.tar entries are conventionally `./usr/bin/tool`; this accepts
/// that form (and plain `usr/bin/tool`) while explicitly rejecting parent
/// components and other non-normal components instead of letting the kernel
/// resolve them at extraction time.
fn data_tar_entry_path(root: &Path, entry_path: &Path) -> Result<PathBuf> {
    let text = entry_path.to_string_lossy();
    let rel = text.strip_prefix("./").unwrap_or(&text);

    let mut resolved = root.to_path_buf();
    for component in Path::new(rel).components() {
        match component {
            Component::Normal(part) => resolved.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                anyhow::bail!(
                    "Unsafe data.tar entry (parent component): {}",
                    entry_path.display()
                )
            }
            Component::RootDir | Component::Prefix(_) => {
                anyhow::bail!(
                    "Unsafe data.tar entry (absolute or prefixed): {}",
                    entry_path.display()
                )
            }
        }
    }

    if resolved == root {
        anyhow::bail!("data.tar entry resolves to the filesystem root");
    }
    Ok(resolved)
}

/// Validate a symlink target and return the target to store, rewriting
/// absolute targets onto the extraction root per dpkg's chroot semantics.
///
/// The link's parent directory is expressed relative to `root`, then the
/// target's components are applied with a depth counter: a `..` at depth zero
/// is rejected. dpkg treats an absolute target inside a package as relative
/// to the target filesystem root, so `/etc/bar` is re-rooted onto the
/// extraction root instead of rejecting the package; the same depth guard is
/// applied to the rewritten path so it can never escape. This treats the
/// extraction root as the containment boundary regardless of where it lives
/// on disk — for the production root of `/` the two coincide, but tests and
/// future non-root extraction must not be able to pop above their own root.
fn validate_root_relative_link_target(
    root: &Path,
    link_path: &Path,
    target: &Path,
) -> Result<PathBuf> {
    let rel_parent = link_path.strip_prefix(root).unwrap_or(link_path);
    let mut depth = rel_parent
        .components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .count();

    let mut components = target.components();
    match components.next() {
        Some(Component::RootDir) => {
            // Absolute paths resolve from the filesystem root, so the depth
            // guard restarts at zero instead of the link's parent depth.
            depth = 0;
            let mut rebased = root.to_path_buf();
            for component in components {
                match component {
                    Component::Normal(part) => {
                        rebased.push(part);
                        depth += 1;
                    }
                    Component::ParentDir => {
                        anyhow::ensure!(
                            depth > 0,
                            "Archive symlink escapes the extraction directory: {} -> {}",
                            link_path.display(),
                            target.display()
                        );
                        depth -= 1;
                        rebased.pop();
                    }
                    Component::CurDir => {}
                    Component::RootDir | Component::Prefix(_) => {
                        anyhow::bail!(
                            "Archive symlink target must be relative: {} -> {}",
                            link_path.display(),
                            target.display()
                        )
                    }
                }
            }
            anyhow::ensure!(
                rebased != root,
                "Archive symlink target resolves to the extraction root: {} -> {}",
                link_path.display(),
                target.display()
            );
            Ok(rebased)
        }
        Some(Component::Prefix(_)) => {
            anyhow::bail!(
                "Archive symlink target must be relative: {} -> {}",
                link_path.display(),
                target.display()
            )
        }
        _ => {
            for component in target.components() {
                match component {
                    Component::Normal(_) => depth += 1,
                    Component::CurDir => {}
                    Component::ParentDir => {
                        anyhow::ensure!(
                            depth > 0,
                            "Archive symlink escapes the extraction directory: {} -> {}",
                            link_path.display(),
                            target.display()
                        );
                        depth -= 1;
                    }
                    Component::RootDir | Component::Prefix(_) => {
                        anyhow::bail!(
                            "Archive symlink target must be relative: {} -> {}",
                            link_path.display(),
                            target.display()
                        )
                    }
                }
            }
            Ok(target.to_path_buf())
        }
    }
}

/// A link whose creation is deferred until every regular file has been
/// written, so no regular-file write can traverse a link from the archive.
enum PendingRootLink {
    Symbolic { path: PathBuf, target: PathBuf },
    Hard { path: PathBuf, target: PathBuf },
}

fn create_root_links(
    links: Vec<PendingRootLink>,
    extracted_regular_files: &std::collections::HashSet<PathBuf>,
) -> Result<()> {
    for link in links {
        match link {
            PendingRootLink::Symbolic { path, target } => {
                std::os::unix::fs::symlink(&target, &path).with_context(|| {
                    format!(
                        "Failed to create archive symlink {} -> {}",
                        path.display(),
                        target.display()
                    )
                })?;
            }
            PendingRootLink::Hard { path, target } => {
                anyhow::ensure!(
                    extracted_regular_files.contains(&target),
                    "Archive hard-link target was not extracted from this archive: {} -> {}",
                    path.display(),
                    target.display()
                );
                fs::hard_link(&target, &path).with_context(|| {
                    format!(
                        "Failed to create archive hard link {} -> {}",
                        path.display(),
                        target.display()
                    )
                })?;
            }
        }
    }
    Ok(())
}

/// Extract a tar stream to a directory, normalizing every entry through
/// [`data_tar_entry_path`] like the data.tar path does.
fn extract_tar_stream(reader: &mut dyn Read, dest: &Path) -> Result<()> {
    let mut archive = tar::Archive::new(reader);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let dest_path = data_tar_entry_path(dest, &entry.path()?)?;

        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)?;
        }

        entry.unpack(&dest_path)?;
    }

    Ok(())
}

/// Detect the compression format of a `.tar.<ext>` payload and return a
/// reader over the decompressed tar bytes. Every decoder is wrapped so the
/// decompressed-size budget is enforced while bytes are produced; a bomb
/// aborts mid-stream instead of exhausting memory.
#[cfg(test)]
fn tar_payload_reader(data: &[u8]) -> Result<Box<dyn Read + '_>> {
    tar_payload_reader_with_budget(data, BudgetedSink::max_budget())
}

/// [`tar_payload_reader`] with an explicit budget; tests use a small budget
/// so the abort path is exercisable without gigabyte allocations.
#[cfg(test)]
fn tar_payload_reader_with_budget(data: &[u8], budget: u64) -> Result<Box<dyn Read + '_>> {
    if data.len() > 4 && data.starts_with(b"\x28\xb5\x2f\xfd") {
        // Zstd: Fast decompression, good compression
        let decoder = ruzstd::decoding::StreamingDecoder::new(std::io::Cursor::new(data))
            .map_err(|e| anyhow::anyhow!("Failed to create zstd decoder: {e}"))?;
        return Ok(Box::new(BudgetedReader::new(decoder, budget)));
    }

    if data.len() > 6 && data.starts_with(b"\xfd7zXZ\x00") {
        // Bound output while the shared decoder verifies the full stream.
        let mut sink = BudgetedSink::with_budget(budget);
        decode_xz_to(std::io::Cursor::new(data), &mut sink)
            .map_err(|e| anyhow::anyhow!("Failed to decompress XZ payload: {e}"))?;
        return Ok(Box::new(std::io::Cursor::new(sink.into_inner())));
    }

    if data.len() > 2 && data[0] == 0x1f && data[1] == 0x8b {
        // Gzip: legacy packages
        let decoder = flate2::read::GzDecoder::new(data);
        return Ok(Box::new(BudgetedReader::new(decoder, budget)));
    }

    // Uncompressed tar
    Ok(Box::new(std::io::Cursor::new(data)))
}

/// Create any missing ancestor directories between `root` and `path`,
/// recording each newly created directory in `installed_files` so rollback can
/// remove the full chain instead of leaving empty residue behind. Ancestors
/// already handled for this archive are skipped.
fn ensure_parent_dirs_recorded(
    path: &Path,
    root: &Path,
    seen: &mut std::collections::HashSet<PathBuf>,
    installed_files: &mut Vec<PathBuf>,
) -> Result<()> {
    let mut missing = Vec::new();
    for ancestor in path.ancestors().skip(1) {
        if ancestor == root || seen.contains(ancestor) {
            break;
        }
        seen.insert(ancestor.to_path_buf());
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => {
                anyhow::bail!(
                    "Extraction parent {} is not a directory",
                    ancestor.display()
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(ancestor.to_path_buf());
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("Failed to inspect {} for extraction", ancestor.display())
                });
            }
        }
    }

    // Ancestors arrive nearest-first; create outermost first so each single
    // level `create_dir` sees an existing parent.
    for dir in missing.into_iter().rev() {
        fs::create_dir(&dir)
            .with_context(|| format!("Failed to create directory {}", dir.display()))?;
        installed_files.push(dir);
    }
    Ok(())
}

/// Extract a data.tar payload into the filesystem root with dpkg-like
/// semantics and hardened handling of untrusted entries:
///
/// - regular files are written directly (streaming); their paths are
///   normalized through [`data_tar_entry_path`], which rejects parent and
///   absolute components;
/// - directories are created and recorded so rollback can remove them;
/// - symbolic links are validated (absolute targets re-rooted onto the
///   extraction root per dpkg chroot semantics; relative and rewritten
///   targets must stay inside the extraction root) and created only after
///   every regular file has been written, so a file entry can never traverse
///   a link defined by the same archive;
/// - hard links are re-created against the already-extracted tree after all
///   files exist;
/// - any other entry type (devices, FIFOs) fails the install explicitly.
///
/// Error wrapper carrying the files already written before a mid-extraction
/// failure, so the caller can merge them into rollback tracking instead of
/// leaving untracked residue under `/`.
#[derive(Debug)]
struct PartialExtractionError {
    source: anyhow::Error,
    installed_files: Vec<PathBuf>,
}

impl std::fmt::Display for PartialExtractionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.source)
    }
}

impl std::error::Error for PartialExtractionError {}

fn track_partial_extraction<F>(extract: F) -> Result<Vec<PathBuf>>
where
    F: FnOnce(&mut Vec<PathBuf>) -> Result<()>,
{
    let mut installed_files = Vec::new();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        extract(&mut installed_files)
    }));
    match outcome {
        Ok(Ok(())) => Ok(installed_files),
        Ok(Err(source)) => Err(PartialExtractionError {
            source,
            installed_files,
        }
        .into()),
        Err(_) => Err(PartialExtractionError {
            source: anyhow::anyhow!("Archive extraction panicked"),
            installed_files,
        }
        .into()),
    }
}

fn write_archive_regular_file(entry: &mut dyn Read, entry_path: &Path, mode: u32) -> Result<()> {
    let parent = entry_path
        .parent()
        .context("Archive file path has no parent directory")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).with_context(|| {
        format!(
            "Failed to create temporary archive file beside {}",
            entry_path.display()
        )
    })?;
    std::io::copy(entry, temporary.as_file_mut())
        .with_context(|| format!("Failed to write archive file: {}", entry_path.display()))?;
    temporary
        .as_file_mut()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    temporary
        .persist(entry_path)
        .map_err(|error| error.error)
        .with_context(|| format!("Failed to publish archive file: {}", entry_path.display()))?;
    Ok(())
}

#[cfg(test)]
fn extract_tar_to_root_at(root: &Path, data: &[u8]) -> Result<Vec<PathBuf>> {
    let mut reader = tar_payload_reader(data)?;
    extract_tar_stream_to_root_at(root, reader.as_mut())
}

fn extract_tar_stream_to_root_at(root: &Path, reader: &mut dyn Read) -> Result<Vec<PathBuf>> {
    // Inner scope owns the manifest so ANY failure can carry the files
    // already written back to the caller (audit A2): without this, a
    // mid-extraction error left untracked residue under `/` that rollback
    // could never see.
    let inner = |installed_files: &mut Vec<PathBuf>| -> anyhow::Result<()> {
        let mut archive = tar::Archive::new(reader);

        tracing::debug!("Extracting data.tar into {}", root.display());

        let mut pending_links = Vec::new();
        let mut seen_dirs: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
        let mut extracted_regular_files = std::collections::HashSet::new();

        for entry in archive.entries()? {
            let mut entry = entry?;
            let entry_path = data_tar_entry_path(root, &entry.path()?)?;
            let entry_type = entry.header().entry_type();

            if entry_type.is_dir() {
                ensure_parent_dirs_recorded(&entry_path, root, &mut seen_dirs, installed_files)?;
                if let Err(error) = fs::create_dir(&entry_path)
                    && error.kind() != std::io::ErrorKind::AlreadyExists
                {
                    return Err(error).with_context(|| {
                        format!("Failed to create directory {}", entry_path.display())
                    });
                }
                let mode = entry.header().mode()?;
                fs::set_permissions(&entry_path, fs::Permissions::from_mode(mode)).with_context(
                    || format!("Failed to apply directory mode to {}", entry_path.display()),
                )?;
                installed_files.push(entry_path);
                continue;
            }

            if entry_type.is_symlink() {
                let target = entry
                    .link_name()?
                    .context("Archive symlink is missing its target")?
                    .into_owned();
                let target = validate_root_relative_link_target(root, &entry_path, &target)?;
                installed_files.push(entry_path.clone());
                pending_links.push(PendingRootLink::Symbolic {
                    path: entry_path,
                    target,
                });
                continue;
            }

            if entry_type.is_hard_link() {
                let target = entry
                    .link_name()?
                    .context("Archive hard link is missing its target")?
                    .into_owned();
                let target = data_tar_entry_path(root, &target)?;
                installed_files.push(entry_path.clone());
                pending_links.push(PendingRootLink::Hard {
                    path: entry_path,
                    target,
                });
                continue;
            }

            if !entry_type.is_file() {
                anyhow::bail!(
                    "Unsupported special entry in package data.tar: {} ({entry_type:?})",
                    entry_path.display()
                );
            }

            ensure_parent_dirs_recorded(&entry_path, root, &mut seen_dirs, installed_files)?;

            let mode = entry.header().mode()?;
            write_archive_regular_file(&mut entry, &entry_path, mode)?;
            extracted_regular_files.insert(entry_path.clone());
            installed_files.push(entry_path);
        }

        create_root_links(pending_links, &extracted_regular_files)?;
        Ok(())
    };

    track_partial_extraction(inner)
}

fn maintainer_script_name(script: &Path) -> Result<&str> {
    let filename = script
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .context("Maintainer script path has no UTF-8 filename")?;
    let name = filename.rsplit_once('.').map_or(filename, |(_, name)| name);
    anyhow::ensure!(
        matches!(name, "preinst" | "postinst" | "prerm" | "postrm"),
        "Unsupported maintainer script name: {name}"
    );
    Ok(name)
}

fn run_maintainer_script_with_timeout(
    script: &Path,
    package_name: &str,
    arg: &str,
    timeout: Duration,
) -> Result<()> {
    use std::os::unix::process::CommandExt;

    let script_name = maintainer_script_name(script)?;
    let mut permissions = fs::metadata(script)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(script, permissions)?;

    let mut command = Command::new(script);
    command
        // Maintainer scripts are package-controlled code. Do not expose the
        // caller's credentials, agent sockets, proxy secrets, or language
        // injection variables to them merely because omg was invoked from a
        // privileged administrative shell.
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("HOME", "/root")
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8")
        .arg(arg)
        .env("DPKG_ROOT", "")
        .env("DPKG_ADMINDIR", "/var/lib/dpkg")
        .env("DPKG_MAINTSCRIPT_PACKAGE", package_name)
        .env("DPKG_MAINTSCRIPT_ARCH", super::debian_arch())
        .env("DPKG_MAINTSCRIPT_NAME", script_name)
        .env("DPKG_MAINTSCRIPT_DEBUG", "0")
        .process_group(0);
    let mut child = command
        .spawn()
        .with_context(|| format!("Failed to run {}", script.display()))?;
    let process_group = nix::unistd::Pid::from_raw(
        i32::try_from(child.id()).context("Maintainer script process ID exceeds i32")?,
    );
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("Failed to wait for {}", script.display()))?
        {
            break status;
        }
        if started.elapsed() >= timeout {
            if let Err(error) =
                nix::sys::signal::killpg(process_group, nix::sys::signal::Signal::SIGKILL)
            {
                tracing::warn!(%error, script = %script.display(), "Failed to kill timed-out maintainer script process group");
                let _ = child.kill();
            }
            let _ = child.wait();
            anyhow::bail!(
                "Maintainer script {} timed out after {} seconds",
                script.display(),
                timeout.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    if !status.success() {
        anyhow::bail!(
            "Maintainer script {} failed with exit code {:?}",
            script.display(),
            status.code()
        );
    }
    Ok(())
}

/// Run a maintainer script (preinst, postinst, prerm, postrm).
fn run_maintainer_script(script: &Path, package_name: &str, arg: &str) -> Result<()> {
    run_maintainer_script_with_timeout(script, package_name, arg, MAINTAINER_SCRIPT_TIMEOUT)
}

/// Prepare a status entry from a control file (for batched writing)
fn prepare_status_entry(control_file: &Path) -> Result<String> {
    let control_content = fs::read_to_string(control_file)?;
    let has_status = control_content
        .lines()
        .any(|line| line.starts_with("Status:"));
    let mut result = String::new();

    for line in control_content.lines() {
        if line.starts_with("Status:") {
            result.push_str("Status: install ok installed\n");
        } else {
            result.push_str(line);
            result.push('\n');
            if !has_status && line.starts_with("Package:") {
                result.push_str("Status: install ok installed\n");
            }
        }
    }
    Ok(result)
}

/// Download a package with streaming to disk (lower memory usage)
///
/// OPTIMIZATION: Streams response directly to disk instead of buffering in memory.
/// This reduces memory pressure and allows the OS to optimize disk writes.
async fn download_package_streaming(
    client: &reqwest::Client,
    name: &str,
    version: &str,
    url: &str,
    temp_dir: &Path,
    progress: &ProgressTask,
    sha256: Option<&str>,
    expected_size: u64,
) -> Result<PathBuf> {
    // A compromised mirror must not be able to fill the disk: abort once the
    // response doubles the metadata-declared size plus a 1 MiB slack.
    let max_bytes = if expected_size > 0 {
        Some(expected_size.saturating_mul(2).saturating_add(1024 * 1024))
    } else {
        None
    };

    let filename = format!("{name}_{version}.deb");
    let dest = temp_dir.join(&filename);

    // OPTIMIZATION: Fast path - download without retry overhead.
    match download_streaming_once(client, url, &dest, progress, max_bytes).await {
        Ok(()) => {
            tracing::debug!("Successfully downloaded {} to {}", name, dest.display());
            require_verified_deb(&dest, name, sha256)?;
            return Ok(dest);
        }
        Err(e) => {
            tracing::debug!("First download attempt failed for {}: {}", name, e);
        }
    }

    // Retry path (only if first attempt failed)
    let mut last_error = None;
    for attempt in 1..MAX_DOWNLOAD_RETRIES {
        let backoff =
            crate::core::http::retry_backoff(Duration::from_millis(INITIAL_BACKOFF_MS), attempt);
        progress.set_message(&format!("retry {}/{}", attempt + 1, MAX_DOWNLOAD_RETRIES));
        tokio::time::sleep(backoff).await;

        match download_streaming_once(client, url, &dest, progress, max_bytes).await {
            Ok(()) => {
                tracing::debug!("Retry succeeded for {}", name);
                require_verified_deb(&dest, name, sha256)?;
                return Ok(dest);
            }
            Err(e) => {
                tracing::warn!(
                    "Download attempt {} failed for {}: {}",
                    attempt + 1,
                    name,
                    e
                );
                last_error = Some(e);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        anyhow::anyhow!("Failed to download {name} after {MAX_DOWNLOAD_RETRIES} retries")
    }))
}

/// Abort a download once it grows past the metadata-derived ceiling.
fn enforce_download_cap(downloaded: u64, max_bytes: Option<u64>, url: &str) -> Result<()> {
    if let Some(max) = max_bytes
        && downloaded > max
    {
        anyhow::bail!(
            "Download from {} reached {downloaded} bytes, exceeding the \
             expected maximum of {max} bytes; refusing to fill the disk",
            crate::core::http::redact_url(url)
        );
    }
    Ok(())
}

/// Stream download directly to disk
async fn download_streaming_once(
    client: &reqwest::Client,
    url: &str,
    dest: &Path,
    progress: &ProgressTask,
    max_bytes: Option<u64>,
) -> Result<()> {
    use futures::StreamExt;
    use tokio::io::AsyncWriteExt;

    let safe_url = crate::core::http::redact_url(url);
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("Failed to request {safe_url}"))?;

    if !response.status().is_success() {
        anyhow::bail!("HTTP {} for {safe_url}", response.status());
    }

    // Set total size for progress bar
    let total_size = response.content_length().unwrap_or(0);
    if total_size > 0 {
        progress.set_total(Some(total_size));
    }

    // OPTIMIZATION: Stream to file with larger buffer (64KB) to reduce syscalls
    let mut file = tokio::fs::File::create(dest)
        .await
        .with_context(|| format!("Failed to create file: {}", dest.display()))?;

    let mut stream = response.bytes_stream();
    let mut downloaded: u64 = 0;

    // OPTIMIZATION: Smaller write buffer (8KB) to reduce memory pressure
    // Modern filesystems handle small writes efficiently
    let mut write_buffer = Vec::with_capacity(8192); // 8KB buffer

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.with_context(|| format!("Failed to read chunk from {safe_url}"))?;

        // OPTIMIZATION: Batch small chunks into 8KB writes
        write_buffer.extend_from_slice(&chunk);

        // Flush buffer when it reaches 8KB (good balance of memory and syscall efficiency)
        if write_buffer.len() >= 8192 {
            file.write_all(&write_buffer)
                .await
                .with_context(|| format!("Failed to write to {}", dest.display()))?;
            downloaded += write_buffer.len() as u64;
            enforce_download_cap(downloaded, max_bytes, url)?;
            progress.set_position(downloaded);
            write_buffer.clear();
        }
    }

    // Write remaining buffered data
    if !write_buffer.is_empty() {
        file.write_all(&write_buffer)
            .await
            .with_context(|| format!("Failed to write final chunk to {}", dest.display()))?;
        downloaded += write_buffer.len() as u64;
        enforce_download_cap(downloaded, max_bytes, url)?;
        progress.set_position(downloaded);
    }

    // Clear buffer explicitly to release memory immediately
    drop(write_buffer);

    // Flush but don't fsync (unsafe-io optimization - OS handles durability)
    file.flush().await?;

    Ok(())
}

fn removal_step_failed(
    task: &ProgressTask,
    overall: &ProgressTask,
    package_name: &str,
    step: &str,
    error: anyhow::Error,
) -> anyhow::Error {
    task.set_message(&format!("{step} failed: {error}"));
    task.finish(Outcome::Failed);
    overall.inc(1);
    // Debug-level here: the propagated chain below carries the full detail to
    // the single boundary that owns user-facing error reporting.
    tracing::debug!(
        target: "pkg_removal",
        package_name = %package_name,
        step = %step,
        "removal step failed: {error:#}"
    );
    error.context(format!(
        "package removal failed during {step} for {package_name}"
    ))
}

const DPKG_INFO_DIR: &str = "/var/lib/dpkg/info";

fn write_dpkg_file_list(
    info_dir: &Path,
    package_name: &str,
    installed_files: &[PathBuf],
) -> Result<PathBuf> {
    fs::create_dir_all(info_dir).with_context(|| {
        format!(
            "Failed to create dpkg info directory {}",
            info_dir.display()
        )
    })?;
    let mut lines = Vec::with_capacity(installed_files.len());
    for path in installed_files {
        let mut line = path
            .to_str()
            .context("Installed package path contains invalid UTF-8")?
            .to_string();
        anyhow::ensure!(
            !line.contains(['\n', '\r']),
            "Installed package path contains a line break"
        );
        if fs::symlink_metadata(path)?.file_type().is_dir() && !line.ends_with('/') {
            line.push('/');
        }
        lines.push(line);
    }
    lines.sort_unstable();
    lines.dedup();
    let contents = if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    };
    let destination = info_dir.join(format!("{package_name}.list"));
    crate::core::safe_ops::atomic_write_file_sync(&destination, contents.as_bytes())?;
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o644))?;
    Ok(destination)
}

fn dpkg_info_candidates(package_name: &str, extension: &str) -> [PathBuf; 3] {
    // Probe the canonical Debian architecture first, then the raw Rust ARCH
    // for compatibility with old local state, then the unqualified fallback.
    let arch = super::debian_arch();
    [
        Path::new(DPKG_INFO_DIR).join(format!("{package_name}:{arch}.{extension}")),
        Path::new(DPKG_INFO_DIR).join(format!(
            "{package_name}:{}.{extension}",
            std::env::consts::ARCH
        )),
        Path::new(DPKG_INFO_DIR).join(format!("{package_name}.{extension}")),
    ]
}

fn existing_dpkg_info_file(package_name: &str, extension: &str) -> Option<PathBuf> {
    dpkg_info_candidates(package_name, extension)
        .into_iter()
        .find(|path| path.exists())
}

fn run_removal_maintainer_script(package_name: &str, kind: &str) -> Result<()> {
    let Some(script) = existing_dpkg_info_file(package_name, kind) else {
        tracing::debug!("No {kind} script found for {package_name}");
        return Ok(());
    };
    run_maintainer_script(&script, package_name, "remove")
}

/// Remove package files from the filesystem
fn path_exists_without_following_symlinks(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("Failed to inspect {}", path.display())),
    }
}

fn remove_package_files(package_name: &str) -> Result<()> {
    let list_path = existing_dpkg_info_file(package_name, "list")
        .ok_or_else(|| anyhow::anyhow!("No .list file found for {package_name}"))?;

    // Read file list
    let list_content = fs::read_to_string(&list_path)
        .with_context(|| format!("Failed to read {}", list_path.display()))?;

    // Parse file paths - collect files and directories separately
    let mut files_to_remove = Vec::new();
    let mut dirs_to_remove = Vec::new();

    for line in list_content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let path = PathBuf::from(line);
        if line.ends_with('/') {
            dirs_to_remove.push(path);
        } else {
            files_to_remove.push(path);
        }
    }

    files_to_remove.reverse();

    let mut removed_count = 0;

    for file_path in &files_to_remove {
        if !path_exists_without_following_symlinks(file_path)? {
            continue;
        }

        if is_conffile(package_name, file_path)? {
            tracing::debug!("Skipping conffile: {}", file_path.display());
            continue;
        }

        fs::remove_file(file_path)
            .with_context(|| format!("Failed to remove {}", file_path.display()))?;
        removed_count += 1;
        tracing::trace!("Removed: {}", file_path.display());
    }

    // Try to remove empty directories deepest-first, independent of the
    // ordering used by the package's `.list` file.
    dirs_to_remove.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for dir_path in &dirs_to_remove {
        if fs::symlink_metadata(dir_path).is_ok_and(|metadata| metadata.file_type().is_dir())
            && let Ok(mut entries) = fs::read_dir(dir_path)
            && entries.next().is_none()
            && let Err(e) = fs::remove_dir(dir_path)
        {
            tracing::trace!("Could not remove directory {}: {}", dir_path.display(), e);
        }
    }

    tracing::debug!("Removed {removed_count} files from {package_name}");

    Ok(())
}

/// Check if a file path is a conffile for the given package
fn is_conffile(package_name: &str, file_path: &Path) -> Result<bool> {
    let Some(conffiles_path) = existing_dpkg_info_file(package_name, "conffiles") else {
        return Ok(false);
    };
    let content = fs::read_to_string(&conffiles_path)
        .with_context(|| format!("Failed to read {}", conffiles_path.display()))?;
    Ok(content
        .lines()
        .any(|line| Path::new(line.trim()) == file_path))
}

/// Update /var/lib/dpkg/status to mark package as removed (config-files state)
fn update_dpkg_status_for_removal(package_name: &str) -> Result<()> {
    let status_path = Path::new("/var/lib/dpkg/status");
    if !status_path.exists() {
        anyhow::bail!("dpkg status file not found: {}", status_path.display());
    }

    // Read entire status file
    let status_content =
        fs::read_to_string(status_path).context("Failed to read dpkg status file")?;

    // Parse and update the package paragraph
    let mut updated_content = String::with_capacity(status_content.len());
    let mut in_target_package = false;
    let mut found_package = false;

    for line in status_content.lines() {
        if line.is_empty() {
            // End of paragraph
            in_target_package = false;
            updated_content.push('\n');
        } else if let Some(pkg) = line.strip_prefix("Package: ") {
            in_target_package = pkg.trim() == package_name;
            if in_target_package {
                found_package = true;
            }
            updated_content.push_str(line);
            updated_content.push('\n');
        } else if in_target_package && line.starts_with("Status: ") {
            // Update status from "install ok installed" to "deinstall ok config-files"
            updated_content.push_str("Status: deinstall ok config-files\n");
        } else {
            updated_content.push_str(line);
            updated_content.push('\n');
        }
    }

    if !found_package {
        anyhow::bail!("Package {package_name} not found in dpkg status");
    }

    crate::core::safe_ops::atomic_write_file_sync(status_path, updated_content.as_bytes())
        .context("Failed to persist updated status file")?;

    tracing::debug!(
        "Updated dpkg status for {} to config-files state",
        package_name
    );
    Ok(())
}

/// Clean up dpkg info files after removal
fn cleanup_dpkg_info_files(package_name: &str) -> Result<()> {
    let extensions_to_remove = [
        "list", "md5sums", "prerm", "postinst", "preinst", "postrm", "triggers", "shlibs",
        "symbols",
    ];

    let mut removed_count = 0;

    for ext in &extensions_to_remove {
        for file_path in dpkg_info_candidates(package_name, ext) {
            if !file_path.exists() {
                continue;
            }
            fs::remove_file(&file_path)
                .with_context(|| format!("Failed to remove {}", file_path.display()))?;
            removed_count += 1;
            tracing::trace!("Removed: {}", file_path.display());
        }
    }

    tracing::debug!("Cleaned up {removed_count} info files for {package_name} (kept conffiles)");
    Ok(())
}

/// Render a transaction plan without applying it.
///
/// This is also the public integration and benchmark seam.
pub fn dry_run(result: &ResolutionResult) -> String {
    let mut output = String::new();

    if !result.to_install.is_empty() {
        output.push_str("The following NEW packages will be installed:\n  ");
        output.push_str(&result.to_install.join(" "));
        output.push('\n');
    }

    if !result.to_upgrade.is_empty() {
        output.push_str("The following packages will be upgraded:\n  ");
        let names: Vec<_> = result
            .to_upgrade
            .iter()
            .map(|(n, _, _)| n.as_str())
            .collect();
        output.push_str(&names.join(" "));
        output.push('\n');
    }

    if !result.to_remove.is_empty() {
        output.push_str("The following packages will be REMOVED:\n  ");
        output.push_str(&result.to_remove.join(" "));
        output.push('\n');
    }

    use std::fmt::Write;
    let _ = write!(
        output,
        "\n{} to upgrade, {} newly installed, {} to remove.\n",
        result.to_upgrade.len(),
        result.to_install.len(),
        result.to_remove.len()
    );

    let _ = writeln!(
        output,
        "Need to download {} bytes of archives.",
        result.download_size
    );

    let _ = writeln!(
        output,
        "After this operation, {} bytes of additional disk space will be used.",
        result.installed_size
    );

    output
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::OpenOptionsExt;

    use super::*;

    async fn configure_on_test_locks(transaction: &mut Transaction) -> Result<()> {
        let lock_directory = tempfile::tempdir().expect("lock directory");
        let process_lock = Arc::clone(&DPKG_TRANSACTION_LOCK).lock_owned().await;
        let dpkg_locks = acquire_dpkg_locks_at(
            &lock_directory.path().join("frontend.lock"),
            &lock_directory.path().join("database.lock"),
        )?;
        transaction
            .configure_packages_on_blocking_pool(process_lock, dpkg_locks)
            .await
    }

    /// Wave-8 durability fix: an interrupted transaction leaves a recovery
    /// marker; the next transaction must refuse until the operator resolves.
    #[test]
    fn journal_acquire_blocks_until_cleared_and_round_trips() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("omg-transaction-journal.json");

        // Fresh directory: acquire writes the marker.
        let guard = DpkgTransactionJournalGuard::acquire_at(
            &path,
            "install-upgrade",
            &["vim".to_string(), "curl".to_string()],
        )
        .expect("acquire on clean state");
        assert!(path.exists());

        // While the marker exists, a second transaction is refused with a
        // remediation hint.
        let refusal = DpkgTransactionJournalGuard::acquire_at(
            &path,
            "install-upgrade",
            &["other".to_string()],
        );
        let message = refusal.expect_err("stale journal must block").to_string();
        assert!(message.contains("interrupted"), "got: {message}");
        assert!(message.contains("dpkg --configure -a"), "got: {message}");

        // Dropping the guard clears the marker and unblocks the next run.
        drop(guard);
        assert!(!path.exists());
        assert!(
            DpkgTransactionJournalGuard::acquire_at(&path, "remove", &["vim".to_string()]).is_ok()
        );
    }

    /// A corrupt journal means unknown state: the next transaction must still
    /// refuse (fail-safe), with a message pointing at the file.
    #[test]
    fn journal_corrupt_marker_blocks_with_remediation() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("omg-transaction-journal.json");
        std::fs::write(&path, b"{ not valid json").unwrap();
        let refusal =
            DpkgTransactionJournalGuard::acquire_at(&path, "install-upgrade", &["vim".to_string()]);
        assert!(refusal.is_err(), "corrupt marker must block");
    }

    #[test]
    fn maintainer_scripts_receive_the_dpkg_environment_contract() {
        let directory = tempfile::tempdir().expect("tempdir");
        let script = directory.path().join("demo.postinst");
        let body = format!(
            "#!/bin/sh\n\
             [ \"$DPKG_ROOT\" = \"\" ] || exit 10\n\
             [ \"$DPKG_ADMINDIR\" = \"/var/lib/dpkg\" ] || exit 11\n\
             [ \"$DPKG_MAINTSCRIPT_PACKAGE\" = \"demo\" ] || exit 12\n\
             [ \"$DPKG_MAINTSCRIPT_ARCH\" = \"{}\" ] || exit 13\n\
             [ \"$DPKG_MAINTSCRIPT_NAME\" = \"postinst\" ] || exit 14\n\
             [ \"$DPKG_MAINTSCRIPT_DEBUG\" = \"0\" ] || exit 15\n\
             [ \"$1\" = \"configure\" ] || exit 16\n",
            super::super::debian_arch()
        );
        fs::write(&script, body).expect("write maintainer script");

        run_maintainer_script_with_timeout(&script, "demo", "configure", Duration::from_secs(2))
            .expect("maintainer script contract");
    }

    #[test]
    fn timed_out_maintainer_script_is_terminated() {
        let directory = tempfile::tempdir().expect("tempdir");
        let script = directory.path().join("demo.postinst");
        fs::write(&script, "#!/bin/sh\nexec sleep 5\n").expect("write maintainer script");

        let error = run_maintainer_script_with_timeout(
            &script,
            "demo",
            "configure",
            Duration::from_millis(100),
        )
        .expect_err("hung maintainer script must time out");

        assert!(error.to_string().contains("timed out"), "{error:#}");
    }

    #[test]
    fn dpkg_file_list_records_files_and_directories_for_removal() {
        let temp = tempfile::tempdir().expect("tempdir");
        let info_dir = temp.path().join("info");
        let installed_dir = temp.path().join("usr/share/example");
        let installed_file = installed_dir.join("payload");
        fs::create_dir_all(&installed_dir).expect("installed dir");
        fs::write(&installed_file, b"payload").expect("installed file");

        let list_path = write_dpkg_file_list(
            &info_dir,
            "example",
            &[installed_dir.clone(), installed_file.clone()],
        )
        .expect("write dpkg file list");
        let contents = fs::read_to_string(list_path).expect("read file list");

        assert!(contents.contains(&format!("{}/\n", installed_dir.display())));
        assert!(contents.contains(&format!("{}\n", installed_file.display())));
    }

    #[test]
    fn test_transaction_new() {
        let tx = Transaction::new();
        assert_eq!(tx.state, TransactionState::Pending);
        assert!(tx.to_install.is_empty());
        assert!(tx.to_remove.is_empty());
    }

    #[test]
    fn transaction_steps_reject_missing_private_workspace() {
        let mut transaction = Transaction::new();

        let error = transaction
            .configure_packages()
            .expect_err("uninitialized transaction must fail closed");
        assert!(
            error
                .to_string()
                .contains("temporary directory is not initialized"),
            "unexpected error: {error:#}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn configuration_returns_the_complete_transaction_from_the_blocking_pool() {
        let mut transaction = Transaction::new();
        transaction.state = TransactionState::Configuring;
        transaction.temp_dir = Some(TempDir::new().expect("workspace"));

        configure_on_test_locks(&mut transaction)
            .await
            .expect("empty configuration");

        assert_eq!(transaction.state, TransactionState::Configuring);
        assert!(transaction.temp_dir.is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn configure_rejects_packages_without_control_metadata() {
        let workspace = TempDir::new().expect("workspace");
        fs::create_dir_all(workspace.path().join("broken/DEBIAN")).expect("control dir");
        let mut transaction = Transaction {
            state: TransactionState::Configuring,
            to_install: vec![PackageAction {
                name: "broken".to_string(),
                version: "1.0".to_string(),
                deb_path: None,
                url: None,
                size: 0,
                sha256: None,
            }],
            to_remove: Vec::new(),
            to_upgrade: Vec::new(),
            temp_dir: Some(workspace),
            backups: HashMap::new(),
            installed_files: Vec::new(),
            installed_files_by_package: HashMap::from([("broken".to_string(), Vec::new())]),
        };

        let error = configure_on_test_locks(&mut transaction)
            .await
            .expect_err("missing control metadata must fail the transaction");

        assert!(
            error.to_string().contains("preparing dpkg status entry"),
            "{error}"
        );
        assert_eq!(transaction.to_install[0].name, "broken");
        assert!(transaction.temp_dir.is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_configuration_keeps_locks_until_rollback_finishes() {
        let workspace = TempDir::new().expect("workspace");
        let control_dir = workspace.path().join("broken/DEBIAN");
        fs::create_dir_all(&control_dir).expect("control dir");
        let control_path = control_dir.join("control");
        nix::unistd::mkfifo(
            &control_path,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .expect("control fifo");
        let installed_file = workspace.path().join("installed-by-transaction");
        fs::write(&installed_file, b"payload").expect("installed file");
        let transaction = Transaction {
            state: TransactionState::Configuring,
            to_install: vec![PackageAction {
                name: "broken".to_string(),
                version: "1.0".to_string(),
                deb_path: None,
                url: None,
                size: 0,
                sha256: None,
            }],
            to_remove: Vec::new(),
            to_upgrade: Vec::new(),
            temp_dir: Some(workspace),
            backups: HashMap::new(),
            installed_files: vec![installed_file.clone()],
            installed_files_by_package: HashMap::from([("broken".to_string(), Vec::new())]),
        };
        let lock_directory = tempfile::tempdir().expect("lock directory");
        let process_lock = Arc::clone(&DPKG_TRANSACTION_LOCK).lock_owned().await;
        let dpkg_locks = acquire_dpkg_locks_at(
            &lock_directory.path().join("frontend.lock"),
            &lock_directory.path().join("database.lock"),
        )
        .expect("dpkg locks");
        let task = tokio::spawn(async move {
            let mut transaction = transaction;
            transaction
                .configure_packages_on_blocking_pool(process_lock, dpkg_locks)
                .await
        });

        let fifo_writer = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(nix::libc::O_NONBLOCK)
                    .open(&control_path)
                {
                    Ok(writer) => break writer,
                    Err(error) if error.raw_os_error() == Some(nix::libc::ENXIO) => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("opening control fifo failed: {error}"),
                }
            }
        })
        .await
        .expect("configuration worker did not read control metadata");

        task.abort();
        task.await
            .expect_err("configuration waiter must be cancelled");
        assert!(DPKG_TRANSACTION_LOCK.try_lock().is_err());
        drop(fifo_writer);

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if !installed_file.exists() && DPKG_TRANSACTION_LOCK.try_lock().is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("blocking worker did not roll back before releasing locks");
    }

    #[test]
    fn test_transaction_sizes() {
        let mut tx = Transaction::new();
        tx.to_install = vec![
            PackageAction {
                name: "pkg1".to_string(),
                version: "1.0".to_string(),
                deb_path: None,
                url: Some("https://example.invalid/pkg1.deb".to_string()),
                size: 1000,
                sha256: Some("0".repeat(64)),
            },
            PackageAction {
                name: "pkg2".to_string(),
                version: "1.0".to_string(),
                deb_path: None,
                url: Some("https://example.invalid/pkg2.deb".to_string()),
                size: 2000,
                sha256: Some("1".repeat(64)),
            },
        ];
        assert_eq!(tx.total_download_size(), 3000);
        assert_eq!(tx.package_count(), 2);
    }

    #[test]
    fn test_require_installed_version_rejects_missing_and_empty() {
        assert_eq!(
            Transaction::require_installed_version("vim", Some("9.0".into())).unwrap(),
            "9.0"
        );
        let missing = Transaction::require_installed_version("vim", None).unwrap_err();
        assert!(
            missing.to_string().contains("no version in dpkg status"),
            "got: {missing}"
        );
        let empty = Transaction::require_installed_version("vim", Some(String::new())).unwrap_err();
        assert!(
            empty.to_string().contains("no version in dpkg status"),
            "got: {empty}"
        );
    }

    #[test]
    fn test_require_package_installed_rejects_missing() {
        Transaction::require_package_installed("vim", true).expect("installed package is valid");
        let error = Transaction::require_package_installed("vim", false)
            .expect_err("not-installed removal must not succeed");
        assert!(
            error.to_string().contains("package vim is not installed"),
            "got: {error}"
        );
    }

    #[test]
    fn test_dpkg_info_candidates_prefer_arch_qualified_name() {
        let [debian_arch, rust_arch, unqualified] = dpkg_info_candidates("curl", "list");
        assert!(debian_arch.ends_with(format!(
            "curl:{}.list",
            crate::package_managers::debian_db::debian_arch()
        )));
        assert!(rust_arch.ends_with(format!("curl:{}.list", std::env::consts::ARCH)));
        assert!(unqualified.ends_with("curl.list"));
    }

    #[test]
    fn test_dry_run() {
        let result = ResolutionResult {
            to_install: vec!["vim".to_string(), "git".to_string()],
            to_upgrade: vec![("curl".to_string(), "1.0".to_string(), "2.0".to_string())],
            to_remove: Vec::new(),
            download_size: 10240,
            installed_size: 51200,
        };

        let output = dry_run(&result);
        assert!(output.contains("vim"));
        assert!(output.contains("git"));
        assert!(output.contains("curl"));
        assert!(output.contains("10240"));
    }

    #[test]
    fn remove_file_if_present_allows_missing() {
        remove_file_if_present(Path::new("/no/such/rollback/file"))
            .expect("missing installed file is already gone");
    }

    #[test]
    fn remove_file_if_present_deletes_existing() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("installed");
        std::fs::write(&path, b"pkg").expect("installed file");
        remove_file_if_present(&path).expect("rollback remove");
        assert!(!path.exists());
    }

    #[test]
    fn dangling_symlinks_are_present_for_package_removal() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let link = dir.path().join("dangling-link");
        std::os::unix::fs::symlink(dir.path().join("missing-target"), &link)
            .expect("create dangling symlink");

        assert!(!link.exists(), "Path::exists follows the missing target");
        assert!(
            path_exists_without_following_symlinks(&link).expect("inspect symlink"),
            "package removal must still unlink dangling symlinks"
        );
    }

    #[test]
    fn restore_backup_copies_file() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let backup = dir.path().join("backup");
        let original = dir.path().join("original");
        std::fs::write(&backup, b"old").expect("backup");
        restore_backup(&backup, &original).expect("restore");
        assert_eq!(std::fs::read(&original).expect("restored"), b"old");
    }

    #[test]
    fn dpkg_lock_files_are_created_and_locked() {
        let directory = tempfile::tempdir().expect("temp dir");
        let frontend = directory.path().join("lock-frontend");
        let database = directory.path().join("lock");

        let guard = acquire_dpkg_locks_at(&frontend, &database).expect("dpkg locks");

        assert!(frontend.is_file());
        assert!(database.is_file());
        drop(guard);
    }

    #[test]
    fn pending_dpkg_update_fragments_block_transactions() {
        let directory = tempfile::tempdir().expect("temp dir");
        std::fs::write(directory.path().join("0000"), b"Package: pending\n")
            .expect("pending update fragment");

        let error = ensure_no_pending_dpkg_updates_at(directory.path())
            .expect_err("pending dpkg updates must block a transaction");
        assert!(error.to_string().contains("dpkg --configure -a"));
    }

    #[test]
    fn empty_or_missing_dpkg_updates_directories_are_clean() {
        let directory = tempfile::tempdir().expect("temp dir");
        ensure_no_pending_dpkg_updates_at(directory.path()).expect("empty updates directory");
        ensure_no_pending_dpkg_updates_at(&directory.path().join("missing"))
            .expect("missing updates directory");
    }

    #[test]
    fn restore_backup_rejects_missing() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let error = restore_backup(
            &dir.path().join("missing-backup"),
            &dir.path().join("original"),
        )
        .expect_err("missing backup must not look restored");
        assert!(
            error.to_string().contains("Failed to restore backup"),
            "got: {error}"
        );
    }

    #[test]
    fn copy_control_file_rejects_missing_source() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let error = copy_control_file(&dir.path().join("src"), &dir.path().join("dest"))
            .expect_err("missing control file must not look copied");
        assert!(
            error
                .to_string()
                .contains("Failed to copy dpkg control file"),
            "got: {error}"
        );
    }

    #[test]
    fn copy_control_file_writes_destination() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let src = dir.path().join("src");
        let dest = dir.path().join("dest");
        std::fs::write(&src, b"/etc/foo.conf\n").expect("conffiles");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o755))
                .expect("source permissions");
        }

        copy_control_file(&src, &dest).expect("copy");

        assert_eq!(std::fs::read(&dest).expect("copied"), b"/etc/foo.conf\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
    }

    // ─── data.tar extraction hardening ───

    /// Build an uncompressed tar with a callback so tests can append
    /// arbitrary entries (files, links, special types).
    fn build_tar(
        append: impl FnOnce(&mut tar::Builder<Vec<u8>>) -> std::io::Result<()>,
    ) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        append(&mut builder).expect("tar fixture");
        builder.into_inner().expect("tar finish")
    }

    fn append_regular_file(builder: &mut tar::Builder<Vec<u8>>, name: &str, body: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, name, body)
            .expect("append file");
    }

    #[test]
    fn absolute_symlink_target_is_rerooted_onto_extraction_root() {
        // dpkg semantics: an absolute target inside a package is relative to
        // the target filesystem root, so `/usr/share/foo -> /etc/bar` must
        // install and resolve to <root>/etc/bar (in production root == `/`,
        // which is exactly dpkg's behavior).
        let temp = tempfile::tempdir().expect("tempdir");

        let data = build_tar(|builder| {
            let mut dir_header = tar::Header::new_gnu();
            dir_header.set_entry_type(tar::EntryType::Directory);
            dir_header.set_size(0);
            dir_header.set_mode(0o755);
            dir_header.set_cksum();
            builder.append_data(&mut dir_header, "./usr/share", std::io::empty())?;

            let mut link_header = tar::Header::new_gnu();
            link_header.set_entry_type(tar::EntryType::Symlink);
            link_header.set_size(0);
            link_header.set_cksum();
            builder.append_link(&mut link_header, "./usr/share/foo", "/etc/bar")
        });

        extract_tar_to_root_at(temp.path(), &data)
            .expect("absolute symlink target must be re-rooted, not rejected");

        let link = temp.path().join("usr/share/foo");
        let link_metadata = fs::symlink_metadata(&link).expect("symlink exists");
        assert!(
            link_metadata.file_type().is_symlink(),
            "recreated as symlink"
        );
        assert_eq!(
            std::fs::read_link(&link).expect("read link"),
            temp.path().join("etc/bar"),
            "absolute target must be re-rooted onto the extraction root"
        );
    }

    #[test]
    fn absolute_symlink_target_escaping_the_root_is_rejected() {
        // `/../outside` re-roots onto the extraction root and then pops above
        // it; the same escape guard that rejects relative `..` must apply.
        let temp = tempfile::tempdir().expect("tempdir");

        let data = build_tar(|builder| {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_cksum();
            builder.append_link(&mut header, "./out", "/../outside")
        });

        let error = extract_tar_to_root_at(temp.path(), &data)
            .expect_err("escaping absolute symlink target must be rejected");

        assert!(
            error.to_string().contains("escapes the extraction"),
            "{error}"
        );
        assert!(!temp.path().join("out").exists());
    }

    #[test]
    fn absolute_symlink_target_resolving_to_extraction_root_is_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");

        for target in ["/", "/usr/.."] {
            let data = build_tar(|builder| {
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_size(0);
                header.set_cksum();
                builder.append_link(&mut header, "./out", target)
            });

            let error = extract_tar_to_root_at(temp.path(), &data).expect_err(
                "absolute target that re-roots onto the extraction root must be rejected",
            );
            assert!(
                error
                    .to_string()
                    .contains("resolves to the extraction root"),
                "{error}"
            );
            assert!(!temp.path().join("out").exists());
        }
    }

    #[test]
    fn relative_symlink_escaping_the_root_is_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");

        // Link sits one directory below the root, so three `..` steps escape
        // the extraction root even though every component is relative.
        let data = build_tar(|builder| {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_cksum();
            builder.append_link(&mut header, "./out", "../../../outside")
        });

        let error = extract_tar_to_root_at(temp.path(), &data)
            .expect_err("escaping symlink must be rejected");

        assert!(
            error.to_string().contains("escapes the extraction"),
            "{error}"
        );
        assert!(!temp.path().join("outside").exists());
        // Nothing was created outside the root either.
        let outside = temp
            .path()
            .parent()
            .expect("tempdir parent")
            .join("outside");
        assert!(!outside.exists());
    }

    #[test]
    fn file_written_after_symlink_cannot_traverse_it() {
        // The attack: ship `./lib -> <relative escape>` and `./lib/secret`.
        // The escaping link is rejected during the scan, so nothing is
        // written anywhere; a regular-file write can never traverse a link
        // defined by the same archive because links are only created after
        // every regular file exists.
        let temp = tempfile::tempdir().expect("tempdir");

        let data = build_tar(|builder| {
            let mut link_header = tar::Header::new_gnu();
            link_header.set_entry_type(tar::EntryType::Symlink);
            link_header.set_size(0);
            link_header.set_cksum();
            // Relative target that resolves outside the extraction root:
            // the link lives at <root>/lib, so two `..` steps leave the root.
            builder.append_link(&mut link_header, "./lib", "../../pwned")?;

            append_regular_file(builder, "./lib/secret", b"pwned");
            Ok(())
        });

        let error = extract_tar_to_root_at(temp.path(), &data)
            .expect_err("escaping symlink must fail the install loudly");

        assert!(
            error.to_string().contains("escapes the extraction"),
            "{error}"
        );
        // Neither the escaped location nor the in-root payload exists.
        let escaped = temp.path().parent().expect("tempdir parent").join("pwned");
        assert!(!escaped.exists(), "nothing may land outside the root");
        assert!(!temp.path().join("lib").exists());
    }

    #[cfg(unix)]
    #[test]
    fn archive_directory_modes_are_applied() {
        let temp = tempfile::tempdir().expect("tempdir");
        let data = build_tar(|builder| {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o750);
            header.set_cksum();
            builder.append_data(&mut header, "./private", std::io::empty())
        });

        extract_tar_to_root_at(temp.path(), &data).expect("directory extraction");

        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(temp.path().join("private"))
            .expect("directory metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o750);
    }

    #[cfg(unix)]
    #[test]
    fn regular_file_replaces_preexisting_leaf_symlink_without_writing_through() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("root");
        fs::create_dir(&root).expect("root");
        let victim = temp.path().join("victim");
        fs::write(&victim, b"sentinel").expect("victim");
        std::os::unix::fs::symlink(&victim, root.join("tool")).expect("leaf symlink");
        let data = build_tar(|builder| {
            append_regular_file(builder, "./tool", b"package payload");
            Ok(())
        });

        extract_tar_to_root_at(&root, &data).expect("regular file extraction");

        assert_eq!(fs::read(&victim).expect("victim readable"), b"sentinel");
        assert!(
            fs::symlink_metadata(root.join("tool"))
                .expect("installed file")
                .is_file()
        );
        assert_eq!(
            fs::read(root.join("tool")).expect("payload"),
            b"package payload"
        );
    }

    #[cfg(unix)]
    #[test]
    fn preexisting_parent_symlink_cannot_escape_the_extraction_root() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        fs::create_dir(&root).expect("root");
        fs::create_dir(&outside).expect("outside");
        std::os::unix::fs::symlink(&outside, root.join("usr")).expect("parent symlink");
        let data = build_tar(|builder| {
            append_regular_file(builder, "./usr/payload", b"must remain confined");
            Ok(())
        });

        let error = extract_tar_to_root_at(&root, &data)
            .expect_err("preexisting parent symlinks must be rejected");

        assert!(error.to_string().contains("not a directory"), "{error}");
        assert!(!outside.join("payload").exists());
    }

    #[test]
    fn hard_link_target_must_be_a_regular_file_from_the_same_archive() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(temp.path().join("etc")).expect("etc");
        fs::write(temp.path().join("etc/shadow"), b"preexisting").expect("preexisting target");
        let data = build_tar(|builder| {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Link);
            header.set_size(0);
            header.set_cksum();
            builder.append_link(&mut header, "./copy", "./etc/shadow")
        });

        let error = extract_tar_to_root_at(temp.path(), &data)
            .expect_err("hard links may not target preexisting files");

        assert!(
            error
                .to_string()
                .contains("not extracted from this archive"),
            "{error}"
        );
        assert!(!temp.path().join("copy").exists());
    }

    #[test]
    fn benign_links_are_recreated_and_recorded_for_rollback() {
        let temp = tempfile::tempdir().expect("tempdir");

        let data = build_tar(|builder| {
            append_regular_file(builder, "./usr/share/doc/pkg/readme", b"hello");

            let mut sym_header = tar::Header::new_gnu();
            sym_header.set_entry_type(tar::EntryType::Symlink);
            sym_header.set_size(0);
            sym_header.set_cksum();
            builder.append_link(&mut sym_header, "./usr/share/doc/pkg/latest", "readme")?;

            let mut hard_header = tar::Header::new_gnu();
            hard_header.set_entry_type(tar::EntryType::Link);
            hard_header.set_size(0);
            hard_header.set_cksum();
            builder.append_link(
                &mut hard_header,
                "./usr/share/doc/pkg/dup",
                "./usr/share/doc/pkg/readme",
            )
        });

        let installed =
            extract_tar_to_root_at(temp.path(), &data).expect("benign archive must extract");

        let readme = temp.path().join("usr/share/doc/pkg/readme");
        let latest = temp.path().join("usr/share/doc/pkg/latest");
        let dup = temp.path().join("usr/share/doc/pkg/dup");

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let link_metadata = std::fs::symlink_metadata(&latest).expect("symlink exists");
            assert!(
                link_metadata.file_type().is_symlink(),
                "recreated as symlink"
            );
            assert_eq!(
                std::fs::read_link(&latest).expect("link target"),
                Path::new("readme")
            );

            // Hard link shares the inode of its target.
            let meta = std::fs::metadata(&readme).expect("readme");
            let dup_meta = std::fs::metadata(&dup).expect("dup");
            assert_eq!((meta.dev(), meta.ino()), (dup_meta.dev(), dup_meta.ino()));
        }

        for path in [&readme, &latest, &dup] {
            assert!(
                installed.contains(path),
                "{} must be recorded for rollback",
                path.display()
            );
        }
    }

    #[test]
    fn parent_component_in_data_tar_path_is_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");

        // The tar Builder validates paths, so craft the hostile entry through
        // a raw ustar header: an entry literally named `./share/../evil`.
        let data = build_tar(|builder| {
            let mut header = tar::Header::new_gnu();
            {
                // Bypass Builder path validation: this fixture needs an entry
                // whose NAME carries a `..` component, which is exactly what
                // the extractor must reject.
                let old = header.as_old_mut();
                let mut name = [0u8; 100];
                let hostile = b"./share/../evil";
                name[..hostile.len()].copy_from_slice(hostile);
                old.name = name;
            }
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(4);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, &b"nope"[..])
        });

        let error = extract_tar_to_root_at(temp.path(), &data)
            .expect_err("parent components must be rejected");

        assert!(error.to_string().contains("parent component"), "{error}");
        assert!(!temp.path().join("evil").exists());
    }

    #[test]
    fn special_entries_fail_the_install_explicitly() {
        let temp = tempfile::tempdir().expect("tempdir");

        let data = build_tar(|builder| {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Fifo);
            header.set_size(0);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, "./run/pipe", std::io::empty())
        });

        let error = extract_tar_to_root_at(temp.path(), &data).expect_err("FIFO must be rejected");

        assert!(
            error.to_string().contains("Unsupported special entry"),
            "{error}"
        );
    }

    #[test]
    fn rollback_removal_handles_dirs_and_links() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dir = temp.path().join("usr");
        let nested = dir.join("bin");
        std::fs::create_dir_all(&nested).expect("dirs");
        let file = nested.join("tool");
        std::fs::write(&file, b"x").expect("file");
        #[cfg(unix)]
        std::os::unix::fs::symlink("tool", nested.join("tool-link")).expect("link");

        // Recorded order mirrors real archive entry order (parents appear
        // before children in data.tar); removal walks in reverse so the
        // deepest entries go first.
        let mut recorded = vec![dir.clone(), nested.clone(), file.clone()];
        #[cfg(unix)]
        recorded.push(nested.join("tool-link"));

        for path in recorded.iter().rev() {
            remove_file_if_present(path).expect("reverse-order removal");
        }

        assert!(!nested.exists(), "nested dir removed after its children");
        assert!(!dir.exists(), "top dir removed last");
        // Re-running removal is a no-op (rollback idempotence).
        remove_file_if_present(&file).expect("missing path tolerated");
    }

    #[test]
    fn uncompressed_deb_member_is_consumed_lazily() {
        let mut payload = std::io::Cursor::new(vec![0_u8; 4096]);
        let temp = tempfile::tempdir().expect("temp dir");

        let byte = with_decompressed_tar(&mut payload, "data.tar", temp.path(), |reader| {
            let mut byte = [0_u8; 1];
            reader.read_exact(&mut byte)?;
            Ok(byte[0])
        })
        .expect("consume first byte");

        assert_eq!(byte, 0);
        assert_eq!(payload.position(), 1, "member must not be buffered eagerly");
    }

    #[test]
    fn deb_tar_member_accepts_sha256_checked_xz() {
        let fixture = include_bytes!("../../../tests/data/xz-subset/single-block-sha256.tar.xz");
        let temp = tempfile::tempdir().expect("temp dir");
        let files = with_decompressed_tar(
            std::io::Cursor::new(fixture),
            "data.tar.xz",
            temp.path(),
            |reader| {
                let mut archive = tar::Archive::new(reader);
                let mut files = 0;
                for entry in archive.entries()? {
                    let mut entry = entry?;
                    if entry.header().entry_type().is_file() {
                        let mut content = String::new();
                        entry.read_to_string(&mut content)?;
                        anyhow::ensure!(content.starts_with("omg xz fixture file"));
                        files += 1;
                    }
                }
                Ok(files)
            },
        )
        .expect("verified XZ data member");
        assert_eq!(files, 3);
    }

    #[test]
    fn budgeted_writer_rejects_output_before_exceeding_limit() {
        use std::io::Write as _;

        let mut writer = BudgetedWriter::new(Vec::new(), 4);
        writer.write_all(b"1234").expect("write within budget");
        let error = writer
            .write_all(b"5")
            .expect_err("write beyond budget must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert_eq!(writer.into_inner(), b"1234");
    }

    #[test]
    fn gzipped_payload_bomb_is_bounded_during_streaming() {
        use flate2::write::GzEncoder;

        // 64 MiB of zeros compresses to ~60 KiB.
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::best());
        std::io::copy(
            &mut std::io::repeat(0u8).take(64 * 1024 * 1024),
            &mut encoder,
        )
        .expect("compress");
        let bomb = encoder.finish().expect("finish");

        // A 1 MiB budget: far below the 64 MiB expansion, so the abort must
        // fire mid-stream, long before the full payload is produced.
        const TEST_BUDGET_BYTES: u64 = 1024 * 1024;
        let mut reader =
            tar_payload_reader_with_budget(&bomb, TEST_BUDGET_BYTES).expect("gzip detection");
        let mut sink = Vec::new();
        let error = reader
            .read_to_end(&mut sink)
            .expect_err("budget must abort the stream mid-decompression");

        assert!(error.to_string().contains("exceeds"), "{error}");
        assert!(
            error
                .to_string()
                .contains("configured limit of 1048576 bytes"),
            "{error}"
        );
        // The sink stopped at the budget instead of expanding to 64 MiB.
        assert!(
            sink.len() as u64 <= TEST_BUDGET_BYTES,
            "sink grew to {} bytes, past the {TEST_BUDGET_BYTES}-byte budget",
            sink.len()
        );
    }
    #[test]
    fn merge_status_entries_replaces_existing_paragraph() {
        let current = "Package: vim\nStatus: install ok installed\nVersion: 1.0\n\nPackage: git\nStatus: install ok installed\nVersion: 2.0\n";
        let entries = vec![(
            "vim".to_string(),
            "Package: vim\nStatus: install ok installed\nVersion: 9.9\n".to_string(),
        )];

        let merged = merge_status_entries(current, &entries);

        assert!(merged.contains("Version: 9.9"), "{merged}");
        assert!(
            !merged.contains("Version: 1.0\n"),
            "old paragraph must be replaced: {merged}"
        );
        // Untouched package survives exactly once.
        assert_eq!(merged.matches("Package: git").count(), 1);
        assert_eq!(merged.matches("Package: vim").count(), 1);
        assert!(merged.ends_with('\n'));
    }

    #[test]
    fn merge_status_entries_appends_new_packages() {
        let current = "Package: git\nStatus: install ok installed\nVersion: 2.0\n";
        let entries = vec![(
            "curl".to_string(),
            "Package: curl\nStatus: install ok installed\nVersion: 8.0\n".to_string(),
        )];

        let merged = merge_status_entries(current, &entries);

        assert!(merged.contains("Package: curl"), "{merged}");
        assert!(merged.contains("Package: git"), "{merged}");
        assert_eq!(merged.matches("Package: ").count(), 2);
    }

    #[test]
    fn merge_status_entries_into_empty_status_writes_only_new_entries() {
        let entries = vec![(
            "curl".to_string(),
            "Package: curl\nStatus: install ok installed\nVersion: 8.0\n".to_string(),
        )];

        let merged = merge_status_entries("", &entries);
        assert_eq!(
            merged,
            "Package: curl\nStatus: install ok installed\nVersion: 8.0\n\n"
        );
    }

    // ─── wave-3 fixes ───

    #[tokio::test]
    async fn transaction_rejects_hostile_repository_identifiers_before_side_effects() {
        let mut install = Transaction::new();
        install.to_install.push(PackageAction {
            name: "../../escape".to_string(),
            version: "1.0".to_string(),
            deb_path: None,
            url: Some("https://example.invalid/package.deb".to_string()),
            size: 1,
            sha256: Some("0".repeat(64)),
        });
        let error = install
            .execute()
            .await
            .expect_err("hostile package names must fail before download");
        assert!(
            error.to_string().contains("Invalid Debian package name"),
            "{error}"
        );
        assert!(
            install.temp_dir.is_none(),
            "validation must precede temp-dir creation"
        );

        let mut removal = Transaction::new();
        removal.add_remove("../outside".to_string());
        let error = removal
            .execute_removal()
            .await
            .expect_err("hostile removal names must fail before dpkg paths are built");
        assert!(
            error.to_string().contains("Invalid Debian package name"),
            "{error}"
        );
    }

    #[test]
    fn removal_plan_rejects_protected_and_required_packages() {
        let status = "Package: core\nStatus: install ok installed\nEssential: yes\n\nPackage: client\nStatus: install ok installed\nDepends: core\n";

        let protected = plan_debian_removal(status, &["core".to_string()])
            .expect_err("essential package removal must fail");
        assert!(protected.to_string().contains("protected"), "{protected:#}");

        let required = plan_debian_removal(status, &["client".to_string(), "core".to_string()])
            .expect_err("essential packages remain protected even with dependents selected");
        assert!(required.to_string().contains("protected"), "{required:#}");
    }

    #[test]
    fn removal_plan_blocks_live_reverse_dependencies_and_honors_alternatives() {
        let blocked = "Package: library\nStatus: install ok installed\n\nPackage: client\nStatus: install ok installed\nDepends: library\n";
        let error = plan_debian_removal(blocked, &["library".to_string()])
            .expect_err("live reverse dependency must block removal");
        assert!(error.to_string().contains("client"), "{error:#}");

        let alternative = "Package: library\nStatus: install ok installed\n\nPackage: replacement\nStatus: install ok installed\n\nPackage: client\nStatus: install ok installed\nDepends: library | replacement\n";
        assert_eq!(
            plan_debian_removal(alternative, &["library".to_string()]).unwrap(),
            ["library"]
        );
    }

    #[test]
    fn removal_plan_orders_dependents_before_dependencies() {
        let status = "Package: library\nStatus: install ok installed\n\nPackage: client\nStatus: install ok installed\nDepends: library\n";

        let order = plan_debian_removal(status, &["library".to_string(), "client".to_string()])
            .expect("complete dependent set can be removed");

        assert_eq!(order, ["client", "library"]);
    }

    #[tokio::test]
    async fn execute_removal_completes_for_empty_transaction() {
        let mut tx = Transaction::new();
        tx.execute_removal()
            .await
            .expect("removing nothing must succeed");
    }

    #[tokio::test]
    async fn execute_removal_reports_unknown_package_as_failure() {
        // The blocking-pool route must still propagate per-package validation
        // failures instead of silently completing.
        let mut tx = Transaction::new();
        tx.add_remove("omg-wave3-definitely-not-installed".to_string());
        let error = tx
            .execute_removal()
            .await
            .expect_err("unknown package must fail loudly");
        assert!(
            error
                .to_string()
                .contains("omg-wave3-definitely-not-installed is not installed"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn extraction_panic_preserves_partial_rollback_manifest() {
        let written = PathBuf::from("/already-written");
        let error = track_partial_extraction(|installed_files| {
            installed_files.push(written.clone());
            panic!("decoder panic");
        })
        .expect_err("extraction panics must become tracked failures");

        let partial = error
            .downcast_ref::<PartialExtractionError>()
            .expect("partial extraction error");
        assert_eq!(partial.installed_files, vec![written]);
        assert!(partial.source.to_string().contains("panicked"));
    }

    #[test]
    fn rollback_restores_dpkg_status_even_when_a_path_cannot_be_removed() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let original = dir.path().join("status");
        std::fs::write(&original, b"after-transaction").expect("post-tx status");
        let backup = dir.path().join("status.pre-transaction");
        std::fs::write(&backup, b"pre-transaction").expect("backup status");

        // A directory that still holds foreign content cannot be removed by
        // rollback; that must not prevent the integrity-critical restore.
        let stuck = dir.path().join("shared");
        std::fs::create_dir_all(stuck.join("foreign")).expect("stubborn dir");

        let mut tx = Transaction {
            state: TransactionState::Configuring,
            to_install: Vec::new(),
            to_remove: Vec::new(),
            to_upgrade: Vec::new(),
            temp_dir: None,
            backups: HashMap::from([(original.clone(), backup)]),
            installed_files: vec![stuck],
            installed_files_by_package: HashMap::new(),
        };

        let error = tx
            .rollback()
            .expect_err("stuck path must be reported as incomplete rollback");
        assert!(error.to_string().contains("Rollback incomplete"), "{error}");
        assert_eq!(
            std::fs::read(&original).expect("restored status"),
            b"pre-transaction",
            "dpkg status must be restored despite the removal failure"
        );
    }

    #[test]
    fn implicit_parent_directories_are_recorded_for_rollback() {
        let temp = tempfile::tempdir().expect("tempdir");

        let data = build_tar(|builder| {
            append_regular_file(builder, "./n1/n2/file", b"payload");
            Ok(())
        });

        let installed =
            extract_tar_to_root_at(temp.path(), &data).expect("extraction must succeed");

        let n1 = temp.path().join("n1");
        let n2 = n1.join("n2");
        let file = n2.join("file");
        for path in [&n1, &n2, &file] {
            assert!(
                installed.contains(path),
                "{} must be recorded",
                path.display()
            );
        }

        // Reverse-order removal (as rollback does) unwinds the whole chain.
        for path in installed.iter().rev() {
            remove_file_if_present(path).expect("reverse removal");
        }
        assert!(!n1.exists(), "implicit parent chain fully removed");
    }
}
