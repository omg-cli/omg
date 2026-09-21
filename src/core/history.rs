//! Package transaction history
//!
//! Records package outcomes in a bounded live JSON file and a JSONL archive.
//! Live-file replacements are atomic. A sibling lock coordinates reads and
//! writes across processes.

use anyhow::{Context, Result};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Maximum number of transactions to retain in the live file
const MAX_HISTORY_TRANSACTIONS: usize = 1000;

/// Kind of package operation recorded in the history.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum TransactionType {
    Install,
    Remove,
    Update,
    Sync,
}

impl std::fmt::Display for TransactionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Install => write!(f, "Install"),
            Self::Remove => write!(f, "Remove"),
            Self::Update => write!(f, "Update"),
            Self::Sync => write!(f, "Sync"),
        }
    }
}

/// One package affected by a transaction.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PackageChange {
    pub name: String,
    pub old_version: Option<String>,
    pub new_version: Option<String>,
    pub source: String,
}

impl PackageChange {
    /// Whether the system package manager can restore this change.
    /// Official repository names vary (`core`, `extra`, `apt`, `pacman`), so
    /// only sources that require a separate installation path are excluded.
    #[must_use]
    pub fn is_official_source(&self) -> bool {
        !self.source.eq_ignore_ascii_case("aur") && !self.source.eq_ignore_ascii_case("local")
    }
}

/// A completed transaction: what changed, when, and whether it succeeded.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub id: String,
    pub timestamp: Timestamp,
    pub transaction_type: TransactionType,
    pub changes: Vec<PackageChange>,
    pub success: bool,
}

/// Loads and appends package transactions under a cross-process file lock.
///
/// The log file is capped at [`MAX_HISTORY_TRANSACTIONS`] entries; retired
/// entries move to a sibling `.archive.jsonl` file instead of being
/// dropped. Live-file writes use a temporary file and rename; archive
/// appends run under the same lock.
pub struct HistoryManager {
    log_path: PathBuf,
}

impl HistoryManager {
    /// Creates a manager backed by the default history file in the data
    /// directory.
    pub fn new() -> Result<Self> {
        Self::new_in(crate::core::paths::data_dir().join("history.json"))
    }

    /// Creates a manager backed by an explicit history file path (tests,
    /// alternative stores).
    pub fn new_in(log_path: impl AsRef<Path>) -> Result<Self> {
        let log_path = log_path.as_ref().to_path_buf();
        let parent = log_path
            .parent()
            .context("Package history path must have a parent directory")?;
        crate::core::paths::create_private_data_directory(parent).with_context(|| {
            format!(
                "Failed to create package history directory: {}",
                parent.display()
            )
        })?;
        Ok(Self { log_path })
    }

    /// Collect deduplicated `(package, version)` pairs whose `old_version`
    /// appears in successful Remove/Update transactions within the last
    /// `days` days. Used to warn before cache cleaning destroys the archives
    /// those rollback plans depend on.
    pub fn rollback_referenced_versions(&self, days: i64) -> Result<Vec<(String, String)>> {
        let entries = self.load()?;
        let cutoff = Timestamp::now()
            .as_second()
            .saturating_sub(days.saturating_mul(24 * 60 * 60));

        let mut referenced = std::collections::BTreeSet::new();
        for entry in entries {
            if !entry.success {
                continue;
            }
            if !matches!(
                entry.transaction_type,
                TransactionType::Remove | TransactionType::Update
            ) {
                continue;
            }
            if entry.timestamp.as_second() < cutoff {
                continue;
            }
            for change in &entry.changes {
                if let Some(version) = &change.old_version {
                    referenced.insert((change.name.clone(), version.clone()));
                }
            }
        }

        Ok(referenced.into_iter().collect())
    }

    /// Loads archived and live transactions without modifying either file.
    /// Identical records from interrupted retirement are returned once;
    /// conflicting IDs or malformed data fail rather than choosing a version.
    pub fn load(&self) -> Result<Vec<Transaction>> {
        self.with_history_lock(|| {
            let live = self.load_locked()?;
            let archive_path = self.archive_path();
            let mut options = fs::OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
            }
            let archive = match options.open(&archive_path) {
                Ok(file) => {
                    anyhow::ensure!(file.metadata()?.is_file(), "History archive must be a regular file: {}", archive_path.display());
                    Some(file)
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(error).with_context(|| format!("Failed to read history archive: {}", archive_path.display())),
            };
            let archived = archive.into_iter().flat_map(|file| {
                serde_json::Deserializer::from_reader(std::io::BufReader::new(file))
                    .into_iter::<Transaction>()
            });
            let mut history: Vec<Transaction> = Vec::new();
            let mut positions = std::collections::HashMap::new();
            for record in archived.chain(live.into_iter().map(Ok)) {
                let transaction = record.with_context(|| format!("Failed to read history archive at {}; original file retained for recovery", archive_path.display()))?;
                if let Some(&position) = positions.get(&transaction.id) {
                    anyhow::ensure!(history[position] == transaction, "Conflicting history records for transaction {}; original files retained for recovery", transaction.id);
                    continue;
                }
                positions.insert(transaction.id.clone(), history.len());
                history.push(transaction);
            }
            Ok(history)
        })
    }

    fn load_locked(&self) -> Result<Vec<Transaction>> {
        // Refuse symlinks before reading, mirroring the audit log discipline.
        let is_symlink = std::fs::symlink_metadata(&self.log_path)
            .is_ok_and(|meta| meta.file_type().is_symlink());
        if is_symlink {
            anyhow::bail!(
                "Refusing to read history that is a symlink: {}",
                self.log_path.display()
            );
        }
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
        }
        let mut file = match options.open(&self.log_path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("Failed to read history file: {}", self.log_path.display())
                });
            }
        };
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "History file must be a regular file: {}",
                    self.log_path.display()
                ),
            )
            .into());
        }
        let mut content = String::new();
        std::io::Read::read_to_string(&mut file, &mut content)
            .with_context(|| format!("Failed to read history file: {}", self.log_path.display()))?;

        serde_json::from_str(&content).with_context(|| {
            format!(
                "Malformed package history at {}; original file retained for recovery",
                self.log_path.display()
            )
        })
    }

    /// Renames a malformed history file to `<name>.corrupt-<timestamp>` so it
    /// is preserved for manual recovery, then leaves the original path free
    /// for a fresh history. Never deletes the file: if the rename fails the
    /// error propagates instead of losing the user's transaction log.
    fn quarantine_corrupt_file(&self, parse_error: &serde_json::Error) -> Result<PathBuf> {
        let parent = self
            .log_path
            .parent()
            .context("Package history path must have a parent directory")?;
        let file_name = self
            .log_path
            .file_name()
            .context("Package history path must have a file name")?
            .to_string_lossy()
            .into_owned();
        let stamp = Timestamp::now().strftime("%Y%m%dT%H%M%S%.6fZ").to_string();

        let mut quarantined = parent.join(format!("{file_name}.corrupt-{stamp}"));
        let mut counter = 1u32;
        while quarantined.exists() {
            quarantined = parent.join(format!("{file_name}.corrupt-{stamp}-{counter}"));
            counter += 1;
        }

        fs::rename(&self.log_path, &quarantined).with_context(|| {
            format!(
                "Malformed history file {} ({parse_error}); quarantining it to {} also failed",
                self.log_path.display(),
                quarantined.display()
            )
        })?;
        Ok(quarantined)
    }

    /// Atomically replaces the whole history with `history`.
    pub fn save(&self, history: &[Transaction]) -> Result<()> {
        let mut content =
            serde_json::to_vec_pretty(history).context("Failed to serialize history")?;
        content.push(b'\n');
        crate::core::safe_ops::atomic_write_file_sync(&self.log_path, content)?;
        Ok(())
    }

    /// Persist the outcome of a package mutation without hiding either the
    /// operation error or a history persistence failure.
    pub fn finish_operation(
        &self,
        transaction_type: TransactionType,
        changes: Vec<PackageChange>,
        operation_result: Result<()>,
    ) -> Result<()> {
        crate::core::security::audit::record_operation(
            &transaction_type.to_string(),
            &changes
                .iter()
                .map(|change| change.name.clone())
                .collect::<Vec<_>>(),
            if operation_result.is_ok() {
                "succeeded"
            } else {
                "failed"
            },
        )
        .context("Package operation finished but audit persistence failed")?;
        if crate::core::privilege::parent_owns_history() {
            return operation_result;
        }
        let history_result = self
            .add_transaction(transaction_type, changes, operation_result.is_ok())
            .context("Failed to persist package operation history");

        match (operation_result, history_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(operation_error), Ok(())) => Err(operation_error),
            (Ok(()), Err(history_error)) => Err(history_error
                .context("Package operation succeeded but its history could not be persisted")),
            (Err(operation_error), Err(history_error)) => Err(anyhow::anyhow!(
                "Package operation failed: {operation_error}; history persistence also failed: {history_error}"
            )),
        }
    }

    /// Appends one transaction, holding the cross-process lock for the
    /// full load-modify-save cycle.
    pub fn add_transaction(
        &self,
        transaction_type: TransactionType,
        changes: Vec<PackageChange>,
        success: bool,
    ) -> Result<()> {
        self.with_history_lock(|| self.add_transaction_locked(transaction_type, changes, success))
    }

    fn add_transaction_locked(
        &self,
        transaction_type: TransactionType,
        changes: Vec<PackageChange>,
        success: bool,
    ) -> Result<()> {
        let mut history = match self.load_locked() {
            Ok(history) => history,
            Err(error) => {
                let Some(parse_error) = error.downcast_ref::<serde_json::Error>() else {
                    return Err(error);
                };
                let quarantined = self.quarantine_corrupt_file(parse_error)?;
                tracing::warn!(
                    original = %self.log_path.display(),
                    quarantined = %quarantined.display(),
                    "Malformed history preserved before starting a new transaction log: {parse_error}"
                );
                Vec::new()
            }
        };
        history.push(Transaction {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Timestamp::now(),
            transaction_type,
            changes,
            success,
        });

        let excess = history.len().saturating_sub(MAX_HISTORY_TRANSACTIONS);
        if excess > 0 {
            // Retired entries move to a sibling JSONL archive instead of
            // vanishing: rollback plans and audits can still read them,
            // and a full history is never silently truncated.
            self.archive_drained(&history.drain(0..excess).collect::<Vec<_>>())?;
        }
        self.save(&history)
    }

    /// Append retired transactions to the `<log>.archive.jsonl` file, one
    /// JSON object per line. Runs inside the history lock, so the archive
    /// preserves global append order.
    fn archive_drained(&self, drained: &[Transaction]) -> Result<()> {
        if drained.is_empty() {
            return Ok(());
        }
        let archive_path = self.archive_path();
        let mut content = Vec::new();
        for transaction in drained {
            serde_json::to_writer(&mut content, transaction)
                .context("Failed to serialize archived transaction")?;
            content.push(b'\n');
        }
        let mut options = fs::OpenOptions::new();
        options.create(true).read(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options
                .mode(0o600)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
        }
        use std::io::{Read as _, Seek as _, Write as _};
        let mut archive = options.open(&archive_path).with_context(|| {
            format!("Failed to open history archive: {}", archive_path.display())
        })?;
        let metadata = archive.metadata()?;
        anyhow::ensure!(
            metadata.is_file(),
            "History archive must be a regular file: {}",
            archive_path.display()
        );
        for transaction in serde_json::Deserializer::from_reader(std::io::BufReader::new(&archive))
            .into_iter::<Transaction>()
        {
            transaction.with_context(|| {
                format!(
                    "Failed to validate history archive at {}; original file retained for recovery",
                    archive_path.display()
                )
            })?;
        }
        if metadata.len() > 0 {
            let mut last_byte = [0];
            archive
                .seek(std::io::SeekFrom::End(-1))
                .and_then(|_| archive.read_exact(&mut last_byte))
                .with_context(|| {
                    format!(
                        "Failed to inspect history archive boundary: {}",
                        archive_path.display()
                    )
                })?;
            if last_byte != [b'\n'] {
                content.insert(0, b'\n');
            }
        }
        if let Err(error) = archive.write_all(&content) {
            let error = anyhow::Error::new(error).context(format!(
                "Failed to append history archive: {}",
                archive_path.display()
            ));
            if let Err(recovery_error) = archive
                .set_len(metadata.len())
                .and_then(|()| archive.sync_all())
            {
                return Err(error.context(format!(
                    "Failed to restore history archive at {} after append failure: {recovery_error}",
                    archive_path.display()
                )));
            }
            return Err(error);
        }
        archive
            .sync_all()
            .context("Failed to sync retired history before replacing the live log")?;
        crate::core::safe_ops::sync_parent_directory_sync(&archive_path)?;
        Ok(())
    }

    /// Sibling of the live history file holding every retired transaction.
    fn archive_path(&self) -> PathBuf {
        let file_name = self.log_path.file_name().map_or_else(
            || "history.json".to_string(),
            |name| name.to_string_lossy().into_owned(),
        );
        match self.log_path.parent() {
            Some(parent) => parent.join(format!("{file_name}.archive.jsonl")),
            None => PathBuf::from(format!("{file_name}.archive.jsonl")),
        }
    }

    fn with_history_lock<T>(&self, op: impl FnOnce() -> Result<T>) -> Result<T> {
        let lock_path = self.log_path.with_extension("lock");
        let mut options = fs::OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
        }
        let lock = options
            .open(&lock_path)
            .with_context(|| format!("Failed to open history lock: {}", lock_path.display()))?;
        lock.lock()
            .with_context(|| format!("Failed to lock package history: {}", lock_path.display()))?;

        let result = op();
        if let Err(error) = lock.unlock() {
            return match result {
                Ok(_) => Err(error).context("Failed to unlock package history"),
                Err(operation_error) => Err(operation_error.context(format!(
                    "Package history operation also failed to unlock its lock: {error}"
                ))),
            };
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn fresh_history_store_creates_private_data_ancestors() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir()?;
        let data = root.path().join("data");
        let store = data.join("history");
        let _manager = HistoryManager::new_in(store.join("history.json"))?;
        for path in [&data, &store] {
            assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o700);
        }
        Ok(())
    }

    #[test]
    fn history_read_errors_do_not_quarantine_live_data() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let manager = HistoryManager::new_in(directory.path().join("history.json"))?;
        fs::write(&manager.log_path, [0xff])?;

        for result in [
            manager.load().map(|_| ()),
            manager.add_transaction(TransactionType::Sync, Vec::new(), true),
        ] {
            let error = result.expect_err("invalid UTF-8 must remain a read error");
            assert_eq!(
                error
                    .downcast_ref::<std::io::Error>()
                    .expect("I/O error")
                    .kind(),
                std::io::ErrorKind::InvalidData,
            );
        }
        assert_eq!(fs::read(&manager.log_path)?, [0xff]);
        assert!(!fs::read_dir(directory.path())?.any(|entry| {
            entry
                .expect("history directory entry")
                .file_name()
                .to_string_lossy()
                .contains(".corrupt-")
        }));
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn history_reads_reject_dangling_live_symlinks() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let manager = HistoryManager::new_in(directory.path().join("history.json"))?;
        let target = directory.path().join("missing-history.json");
        std::os::unix::fs::symlink(&target, &manager.log_path)?;

        let error = manager
            .load()
            .expect_err("a live symlink must not look like missing history");
        assert!(error.to_string().contains("symlink"));
        assert_eq!(fs::read_link(&manager.log_path)?, target);
        assert!(!target.exists());
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn failed_archive_append_restores_its_original_bytes() -> Result<()> {
        const CHILD: &str = "OMG_TEST_PARTIAL_ARCHIVE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new("bash")
                .args([
                    "--noprofile",
                    "--norc",
                    "-c",
                    "trap '' XFSZ; ulimit -f 1 || exit; exec \"$@\"",
                    "archive-size-limit",
                ])
                .arg(std::env::current_exe()?)
                .args([
                    "--exact",
                    "core::history::tests::failed_archive_append_restores_its_original_bytes",
                    "--nocapture",
                ])
                .env_remove("BASH_ENV")
                // The intentional file limit must not truncate an inherited coverage profile.
                .env("LLVM_PROFILE_FILE", "/dev/null")
                .env(CHILD, "1")
                .output()?;
            print!("{}", String::from_utf8_lossy(&output.stdout));
            assert!(
                output.status.success(),
                "limited archive child failed:\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return Ok(());
        }

        let transaction = Transaction {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Timestamp::now(),
            transaction_type: TransactionType::Sync,
            changes: Vec::new(),
            success: true,
        };
        let encoded = serde_json::to_vec(&transaction)?;
        let mut terminated = encoded.clone();
        terminated.push(b'\n');
        for original in [terminated.as_slice(), encoded.as_slice(), &[]] {
            let directory = tempfile::tempdir()?;
            let manager = HistoryManager::new_in(directory.path().join("history.json"))?;
            manager.save(std::slice::from_ref(&transaction))?;
            let live = fs::read(&manager.log_path)?;
            fs::write(manager.archive_path(), original)?;
            let error = manager
                .with_history_lock(|| manager.archive_drained(&vec![transaction.clone(); 16]))
                .expect_err("the file-size limit must interrupt the append");
            assert_eq!(
                error
                    .downcast_ref::<std::io::Error>()
                    .and_then(std::io::Error::raw_os_error),
                Some(nix::libc::EFBIG)
            );
            let after = fs::read(manager.archive_path())?;
            println!(
                "partial append original={} after={}",
                original.len(),
                after.len()
            );
            assert!(after.starts_with(original));
            assert_eq!(fs::read(&manager.log_path)?, live);
            assert!(
                error
                    .to_string()
                    .starts_with("Failed to append history archive:"),
                "{error:#}"
            );
            assert_eq!(
                after, original,
                "failed append must restore the original archive"
            );
            assert_eq!(manager.load()?, vec![transaction.clone()]);
            manager.with_history_lock(|| {
                manager.archive_drained(std::slice::from_ref(&transaction))
            })?;
            assert_eq!(manager.load()?, vec![transaction.clone()]);
        }
        Ok(())
    }

    #[test]
    fn archive_append_separates_an_unterminated_final_record() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let manager = HistoryManager::new_in(directory.path().join("history.json"))?;
        let transaction = Transaction {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Timestamp::now(),
            transaction_type: TransactionType::Sync,
            changes: Vec::new(),
            success: true,
        };
        let original = serde_json::to_vec(&transaction)?;
        fs::write(manager.archive_path(), &original)?;

        manager.archive_drained(std::slice::from_ref(&transaction))?;
        let archive = fs::read_to_string(manager.archive_path())?;
        assert!(archive.as_bytes().starts_with(&original));
        assert_eq!(
            archive.lines().count(),
            2,
            "append must separate JSONL records"
        );
        for line in archive.lines() {
            assert_eq!(serde_json::from_str::<Transaction>(line)?, transaction);
        }
        Ok(())
    }

    #[test]
    fn retirement_refuses_malformed_archive_without_changing_either_log() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let manager = HistoryManager::new_in(directory.path().join("history.json"))?;
        let history = (0..MAX_HISTORY_TRANSACTIONS)
            .map(|_| Transaction {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: Timestamp::now(),
                transaction_type: TransactionType::Sync,
                changes: Vec::new(),
                success: true,
            })
            .collect::<Vec<_>>();
        manager.save(&history)?;
        let original_live = fs::read(&manager.log_path)?;
        let original_archive = b"{\"id\":\"incomplete";
        fs::write(manager.archive_path(), original_archive)?;

        let error = manager
            .add_transaction(TransactionType::Sync, Vec::new(), true)
            .expect_err("retirement must refuse a malformed archive");
        assert!(
            error
                .to_string()
                .contains("Failed to validate history archive")
        );
        assert_eq!(fs::read(&manager.log_path)?, original_live);
        assert_eq!(fs::read(manager.archive_path())?, original_archive);
        Ok(())
    }

    /// Retired transactions land in the sibling archive instead of
    /// vanishing: over-cap histories keep every entry across both files.
    #[test]
    fn retired_transactions_are_archived_not_dropped() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let manager = HistoryManager::new_in(directory.path().join("history.json"))?;
        for index in 0..(MAX_HISTORY_TRANSACTIONS + 5) {
            manager.add_transaction(
                TransactionType::Install,
                vec![PackageChange {
                    name: format!("pkg-{index}"),
                    old_version: None,
                    new_version: Some("1.0".to_string()),
                    source: "official".to_string(),
                }],
                true,
            )?;
        }
        let live: Vec<Transaction> = serde_json::from_slice(&fs::read(&manager.log_path)?)?;
        assert_eq!(live.len(), MAX_HISTORY_TRANSACTIONS);
        assert_eq!(manager.load()?.len(), MAX_HISTORY_TRANSACTIONS + 5);
        let archive = std::fs::read_to_string(directory.path().join("history.json.archive.jsonl"))?;
        let archived: Vec<Transaction> = archive
            .lines()
            .map(serde_json::from_str)
            .collect::<serde_json::Result<_>>()?;
        assert_eq!(archived.len(), 5);
        assert_eq!(archived[0].changes[0].name, "pkg-0");
        Ok(())
    }

    #[test]
    fn archive_reads_deduplicate_identical_records_and_reject_conflicts() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let manager = HistoryManager::new_in(directory.path().join("history.json"))?;
        manager.add_transaction(
            TransactionType::Update,
            vec![PackageChange {
                name: "archived-package".into(),
                old_version: Some("1".into()),
                new_version: Some("2".into()),
                source: "core".into(),
            }],
            true,
        )?;
        let mut transaction = manager.load()?.remove(0);
        let record = serde_json::to_string(&transaction)?;
        fs::write(manager.archive_path(), format!("{record}\n{record}\n"))?;
        assert_eq!(manager.load()?.len(), 1);
        fs::remove_file(&manager.log_path)?;
        assert_eq!(
            manager.load()?.len(),
            1,
            "archive must remain readable without a live file"
        );
        assert_eq!(
            manager.rollback_referenced_versions(1)?,
            vec![("archived-package".into(), "1".into())]
        );
        transaction.success = false;
        manager.save(std::slice::from_ref(&transaction))?;
        assert!(
            manager
                .load()
                .expect_err("conflicting ID")
                .to_string()
                .contains("Conflicting")
        );
        manager.save(&[])?;
        let malformed = format!("{record}\n{{truncated");
        fs::write(manager.archive_path(), &malformed)?;
        assert!(manager.load().is_err());
        assert_eq!(fs::read_to_string(manager.archive_path())?, malformed);
        fs::remove_file(manager.archive_path())?;
        #[cfg(unix)]
        {
            let target = directory.path().join("valid-archive");
            fs::write(&target, &record)?;
            std::os::unix::fs::symlink(&target, manager.archive_path())?;
            assert!(manager.load().is_err(), "archive symlink must be refused");
            assert!(
                manager
                    .archive_drained(std::slice::from_ref(&transaction))
                    .is_err(),
                "archive writes must refuse symlinks too"
            );
            assert_eq!(fs::read_to_string(&target)?, record);
            fs::remove_file(manager.archive_path())?;
        }
        fs::create_dir(manager.archive_path())?;
        assert!(manager.load().is_err(), "archive directory must be refused");
        Ok(())
    }

    #[test]
    fn history_reads_report_corruption_without_moving_the_file() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("history.json");
        let original = b"[{\"id\":\"preserve-me\", not-valid-json]";
        fs::write(&path, original)?;
        let manager = HistoryManager::new_in(&path)?;

        for _ in 0..2 {
            let error = manager
                .load()
                .expect_err("corrupt history is not empty history");
            assert!(error.downcast_ref::<serde_json::Error>().is_some());
            assert_eq!(fs::read(&path)?, original);
            assert!(!fs::read_dir(directory.path())?.any(|entry| {
                entry.is_ok_and(|entry| entry.file_name().to_string_lossy().contains(".corrupt-"))
            }));
        }
        Ok(())
    }

    #[test]
    fn official_repository_names_are_restorable() {
        for source in ["official", "core", "extra", "apt", "pacman"] {
            let change = PackageChange {
                name: "example".to_string(),
                old_version: Some("1.0".to_string()),
                new_version: Some("2.0".to_string()),
                source: source.to_string(),
            };
            assert!(change.is_official_source(), "source {source}");
        }
        for source in ["aur", "AUR", "local"] {
            let change = PackageChange {
                name: "example".to_string(),
                old_version: Some("1.0".to_string()),
                new_version: Some("2.0".to_string()),
                source: source.to_string(),
            };
            assert!(!change.is_official_source(), "source {source}");
        }
    }

    #[test]
    #[serial_test::serial(history_ownership)]
    fn finish_operation_persists_failed_mutations_and_returns_the_operation_error() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let manager = HistoryManager::new_in(directory.path().join("history.json"))?;

        let error = manager
            .finish_operation(
                TransactionType::Install,
                vec![PackageChange {
                    name: "example".to_string(),
                    old_version: None,
                    new_version: Some("1.0".to_string()),
                    source: "official".to_string(),
                }],
                Err(anyhow::anyhow!("backend failed")),
            )
            .expect_err("operation failure must be returned");

        assert!(error.to_string().contains("backend failed"));
        let history = manager.load()?;
        assert_eq!(history.len(), 1);
        assert!(!history[0].success);
        Ok(())
    }

    #[test]
    #[serial_test::serial(history_ownership)]
    fn elevated_child_skips_history_owned_by_its_parent() -> Result<()> {
        struct OwnershipReset;
        impl Drop for OwnershipReset {
            fn drop(&mut self) {
                crate::core::privilege::set_parent_owns_history(false);
            }
        }

        let _reset = OwnershipReset;
        crate::core::privilege::set_parent_owns_history(true);
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("history.json");
        let manager = HistoryManager::new_in(&path)?;

        manager.finish_operation(
            TransactionType::Remove,
            vec![PackageChange {
                name: "example".to_string(),
                old_version: Some("1.0".to_string()),
                new_version: None,
                source: "official".to_string(),
            }],
            Ok(()),
        )?;

        assert!(!path.exists(), "elevated child must not duplicate history");
        Ok(())
    }

    #[test]
    #[serial_test::serial(history_ownership)]
    fn history_io_errors_are_not_treated_as_corruption() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("history.json");
        fs::create_dir(&path)?;
        fs::write(path.join("retained"), b"retained")?;
        let manager = HistoryManager::new_in(&path)?;

        let read_error = manager
            .load()
            .expect_err("a directory is not a history file");
        assert!(read_error.downcast_ref::<std::io::Error>().is_some());
        let append_error = manager
            .finish_operation(TransactionType::Install, Vec::new(), Ok(()))
            .expect_err("I/O failure must not start fresh history");
        assert!(append_error.downcast_ref::<std::io::Error>().is_some());
        assert!(path.is_dir());
        assert_eq!(fs::read(path.join("retained"))?, b"retained");
        assert!(!fs::read_dir(directory.path())?.any(|entry| {
            entry.is_ok_and(|entry| entry.file_name().to_string_lossy().contains(".corrupt-"))
        }));
        Ok(())
    }

    #[test]
    #[serial_test::serial(history_ownership)]
    fn corrupt_history_no_longer_wedges_finish_operation() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("history.json");
        fs::write(&path, "[not valid JSON")?;
        let manager = HistoryManager::new_in(&path)?;

        manager
            .finish_operation(
                TransactionType::Install,
                vec![PackageChange {
                    name: "example".to_string(),
                    old_version: None,
                    new_version: Some("1.0".to_string()),
                    source: "official".to_string(),
                }],
                Ok(()),
            )
            .expect("a corrupt history file must not fail a successful operation");

        let history = manager.load()?;
        assert_eq!(history.len(), 1);
        assert!(history[0].success);
        let quarantined: Vec<_> = fs::read_dir(directory.path())?
            .collect::<std::io::Result<Vec<_>>>()?
            .into_iter()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("history.json.corrupt-")
            })
            .collect();
        assert_eq!(quarantined.len(), 1);
        assert_eq!(
            fs::read_to_string(quarantined[0].path())?,
            "[not valid JSON"
        );
        Ok(())
    }

    #[test]
    fn concurrent_corrupt_loads_do_not_rename_a_fresh_history() -> Result<()> {
        use std::sync::{Arc, Barrier};

        const WORKERS: usize = 8;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("history.json");
        fs::write(&path, "not valid JSON")?;
        let barrier = Arc::new(Barrier::new(WORKERS));
        let mut workers = Vec::new();
        for index in 0..WORKERS {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || -> Result<()> {
                let manager = HistoryManager::new_in(&path)?;
                barrier.wait();
                if index == 0 {
                    manager.add_transaction(
                        TransactionType::Install,
                        vec![PackageChange {
                            name: "example".to_string(),
                            old_version: None,
                            new_version: Some("1.0".to_string()),
                            source: "official".to_string(),
                        }],
                        true,
                    )
                } else {
                    match manager.load() {
                        Ok(history) => assert_eq!(history.len(), 1),
                        Err(error) => assert!(error.downcast_ref::<serde_json::Error>().is_some()),
                    }
                    Ok(())
                }
            }));
        }
        for worker in workers {
            worker.join().expect("history worker panicked")?;
        }

        let history = HistoryManager::new_in(&path)?.load()?;
        assert_eq!(
            history.len(),
            1,
            "a concurrent load must not quarantine a freshly written history"
        );
        assert_eq!(history[0].changes[0].name, "example");
        Ok(())
    }

    #[test]
    fn concurrent_transactions_are_not_lost() -> Result<()> {
        use std::sync::{Arc, Barrier};

        const WRITERS: usize = 8;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("history.json");
        let barrier = Arc::new(Barrier::new(WRITERS));
        let mut writers = Vec::new();
        for index in 0..WRITERS {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            writers.push(std::thread::spawn(move || -> Result<()> {
                let manager = HistoryManager::new_in(path)?;
                barrier.wait();
                manager.add_transaction(
                    TransactionType::Install,
                    vec![PackageChange {
                        name: format!("package-{index}"),
                        old_version: None,
                        new_version: Some("1.0.0".to_string()),
                        source: "test".to_string(),
                    }],
                    true,
                )
            }));
        }
        for writer in writers {
            writer.join().expect("history writer panicked")?;
        }

        let history = HistoryManager::new_in(path)?.load()?;
        assert_eq!(history.len(), WRITERS);
        Ok(())
    }

    #[test]
    fn save_replaces_history_atomically_and_loads_it() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("history.json");
        let manager = HistoryManager::new_in(&path)?;
        let transaction = Transaction {
            id: "transaction-1".to_string(),
            timestamp: Timestamp::now(),
            transaction_type: TransactionType::Install,
            changes: vec![PackageChange {
                name: "example".to_string(),
                old_version: None,
                new_version: Some("1.0.0".to_string()),
                source: "official".to_string(),
            }],
            success: true,
        };

        manager.save(std::slice::from_ref(&transaction))?;
        let loaded = manager.load()?;

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, transaction.id);
        assert_eq!(loaded[0].changes[0].name, "example");
        assert!(loaded[0].success);
        Ok(())
    }
}
