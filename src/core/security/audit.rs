//! Tamper-evident audit logging with cryptographic integrity verification.
//!
//! Provides append-only audit logs with SHA-256 chain verification to detect
//! modification of retained entries. The local chain alone cannot prove that
//! an attacker with filesystem access did not truncate, delete, or rewrite and
//! rehash the entire history. It is not authenticity or completeness evidence.

#[cfg(unix)]
use nix::libc;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::core::paths;

const DEFAULT_MAX_AUDIT_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_AUDIT_ARCHIVES: usize = 5;
const MAX_AUDIT_FIELD_BYTES: usize = 4096;
/// Audit entries contain two bounded user-controlled fields plus fixed-size
/// metadata. Refuse an unexpectedly large trailing line instead of restoring
/// the former full-log scan on every append.
const MAX_AUDIT_ENTRY_BYTES: usize = 128 * 1024;

/// Failures creating, reading, or appending the integrity-bound audit log.
#[derive(Debug, Error)]
pub enum AuditError {
    #[error("Failed to create audit directory '{path}'")]
    CreateDir {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("Failed to open audit log '{path}'")]
    Open {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("Failed to read audit log '{path}'")]
    Read {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("Failed to write audit log '{path}'")]
    Write {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("Failed to serialize audit entry")]
    Serialize {
        #[source]
        source: serde_json::Error,
    },
    #[error("Corrupt audit log '{path}' at line {line}")]
    CorruptLine {
        path: String,
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("Corrupt audit log '{path}' at line {line}: missing hash")]
    MissingHash { path: String, line: usize },
    #[error("Global audit logger state is poisoned")]
    LoggerPoisoned,
    #[error("Audit entry invariant failed: {message}")]
    EntryInvariant { message: &'static str },
    #[error("Failed to unlock audit log '{path}'")]
    Unlock {
        path: String,
        #[source]
        source: io::Error,
    },
}

impl AuditError {
    /// True when the underlying IO failure is a missing path.
    pub fn is_not_found(&self) -> bool {
        match self {
            Self::CreateDir { source, .. }
            | Self::Open { source, .. }
            | Self::Read { source, .. }
            | Self::Write { source, .. } => source.kind() == io::ErrorKind::NotFound,
            Self::Serialize { .. }
            | Self::CorruptLine { .. }
            | Self::MissingHash { .. }
            | Self::LoggerPoisoned
            | Self::EntryInvariant { .. }
            | Self::Unlock { .. } => false,
        }
    }
}

/// Audit event types for security logging
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    // Package operations
    PackageInstall,
    PackageRemove,
    PackageUpgrade,
    PackageDowngrade,

    // Security operations
    SecurityAudit,
    VulnerabilityDetected,
    SignatureVerified,
    SignatureFailed,
    PolicyViolation,

    // Configuration changes
    PolicyChanged,
    ConfigChanged,

    // Authentication/Authorization
    DaemonStarted,
    DaemonStopped,

    // SBOM operations
    SbomGenerated,
    SbomExported,
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PackageInstall => write!(f, "PACKAGE_INSTALL"),
            Self::PackageRemove => write!(f, "PACKAGE_REMOVE"),
            Self::PackageUpgrade => write!(f, "PACKAGE_UPGRADE"),
            Self::PackageDowngrade => write!(f, "PACKAGE_DOWNGRADE"),
            Self::SecurityAudit => write!(f, "SECURITY_AUDIT"),
            Self::VulnerabilityDetected => write!(f, "VULNERABILITY_DETECTED"),
            Self::SignatureVerified => write!(f, "SIGNATURE_VERIFIED"),
            Self::SignatureFailed => write!(f, "SIGNATURE_FAILED"),
            Self::PolicyViolation => write!(f, "POLICY_VIOLATION"),
            Self::PolicyChanged => write!(f, "POLICY_CHANGED"),
            Self::ConfigChanged => write!(f, "CONFIG_CHANGED"),
            Self::DaemonStarted => write!(f, "DAEMON_STARTED"),
            Self::DaemonStopped => write!(f, "DAEMON_STOPPED"),
            Self::SbomGenerated => write!(f, "SBOM_GENERATED"),
            Self::SbomExported => write!(f, "SBOM_EXPORTED"),
        }
    }
}

/// Severity levels for audit events
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    Debug = 0,
    Info = 1,
    Warning = 2,
    Error = 3,
    Critical = 4,
}

impl std::fmt::Display for AuditSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Debug => write!(f, "DEBUG"),
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARNING"),
            Self::Error => write!(f, "ERROR"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A single audit log entry with tamper detection
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEntry {
    /// Unique entry ID
    pub id: String,
    /// Timestamp in ISO 8601 format
    pub timestamp: String,
    /// Event type
    pub event_type: AuditEventType,
    /// Severity level
    pub severity: AuditSeverity,
    /// User who performed the action
    pub user: String,
    /// Affected resource (package name, config file, etc.)
    pub resource: String,
    /// Human-readable description
    pub description: String,
    /// Additional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// Hash of previous entry (for chain integrity)
    pub prev_hash: String,
    /// Hash of this entry (computed from all fields except this one)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

impl AuditEntry {
    /// Compute the hash of this entry (excluding the hash field itself)
    #[must_use]
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.id.as_bytes());
        hasher.update(self.timestamp.as_bytes());
        hasher.update(format!("{:?}", self.event_type).as_bytes());
        hasher.update(format!("{:?}", self.severity).as_bytes());
        hasher.update(self.user.as_bytes());
        hasher.update(self.resource.as_bytes());
        hasher.update(self.description.as_bytes());
        if let Some(meta) = &self.metadata {
            hasher.update(meta.to_string().as_bytes());
        }
        hasher.update(self.prev_hash.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Verify the integrity of this entry
    #[must_use]
    pub fn verify(&self) -> bool {
        if let Some(hash) = &self.hash {
            &self.compute_hash() == hash
        } else {
            false
        }
    }
}

/// Enterprise-grade audit logger with tamper detection
pub struct AuditLogger {
    log_path: PathBuf,
    /// Diagnostic mirror of the on-disk tail hash captured at creation and
    /// after each successful append. `log_locked` always re-reads the
    /// authoritative tail under the lock.
    last_hash: String,
    max_bytes: u64,
    max_archives: usize,
}

impl AuditLogger {
    /// Create a new audit logger writing to `<data dir>/audit/audit.jsonl`.
    pub fn new() -> Result<Self, AuditError> {
        Self::new_in(paths::data_dir().join("audit/audit.jsonl"))
    }

    /// Create an audit logger at an explicit path.
    pub fn new_in(log_path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let log_path = log_path.as_ref().to_path_buf();
        let log_dir = log_path.parent().ok_or_else(|| AuditError::CreateDir {
            path: log_path.display().to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "audit log path must have a parent directory",
            ),
        })?;
        paths::create_private_data_directory(log_dir).map_err(|source| AuditError::CreateDir {
            path: log_dir.display().to_string(),
            source,
        })?;

        Self::new_in_with_limits(log_path, DEFAULT_MAX_AUDIT_BYTES, DEFAULT_AUDIT_ARCHIVES)
    }

    fn new_in_with_limits(
        log_path: PathBuf,
        max_bytes: u64,
        max_archives: usize,
    ) -> Result<Self, AuditError> {
        let last_hash = get_last_hash(&log_path)?;
        Ok(Self {
            log_path,
            last_hash,
            max_bytes,
            max_archives,
        })
    }

    /// Log an audit event.
    ///
    /// Appends are serialized across processes and the previous hash is read
    /// under the lock, so concurrent writers cannot fork the integrity chain.
    pub fn log(
        &mut self,
        event: AuditEventType,
        severity: AuditSeverity,
        resource: &str,
        description: &str,
    ) -> Result<(), AuditError> {
        let lock_path = self.log_path.with_extension("lock");
        let lock = open_lock_file(&lock_path)?;
        lock.lock().map_err(|source| AuditError::Open {
            path: lock_path.display().to_string(),
            source,
        })?;

        let result = self.log_locked(event, severity, resource, description);
        if let Err(source) = lock.unlock() {
            return match result {
                Ok(()) => Err(AuditError::Unlock {
                    path: self.log_path.display().to_string(),
                    source,
                }),
                Err(operation_error) => Err(operation_error),
            };
        }
        result
    }

    fn log_locked(
        &mut self,
        event: AuditEventType,
        severity: AuditSeverity,
        resource: &str,
        description: &str,
    ) -> Result<(), AuditError> {
        self.rotate_if_needed()?;
        // Re-read the on-disk tail hash while holding the lock so entries
        // written by another process since this logger was created chain
        // correctly instead of sharing our stale prev_hash.
        let prev_hash = get_last_hash(&self.log_path)?;
        let timestamp = jiff::Timestamp::now()
            .strftime("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        let id = uuid::Uuid::new_v4().to_string();
        let user =
            bounded_audit_field(&std::env::var("USER").unwrap_or_else(|_| "unknown".to_string()));
        let path_str = self.log_path.display().to_string();

        let mut entry = AuditEntry {
            id,
            timestamp,
            event_type: event,
            severity,
            user,
            resource: bounded_audit_field(resource),
            description: bounded_audit_field(description),
            metadata: None,
            prev_hash,
            hash: None,
        };

        let hash = entry.compute_hash();
        entry.hash = Some(hash);

        let mut file = open_append_file(&self.log_path)?;
        ensure_trailing_newline(&mut file).map_err(|source| AuditError::Write {
            path: path_str.clone(),
            source,
        })?;

        let json =
            serde_json::to_string(&entry).map_err(|source| AuditError::Serialize { source })?;
        writeln!(file, "{json}").map_err(|source| AuditError::Write {
            path: path_str.clone(),
            source,
        })?;
        file.flush().map_err(|source| AuditError::Write {
            path: path_str.clone(),
            source,
        })?;
        file.sync_all().map_err(|source| AuditError::Write {
            path: path_str,
            source,
        })?;
        self.last_hash = entry.hash.take().ok_or(AuditError::EntryInvariant {
            message: "computed hash disappeared before publication",
        })?;

        // Structured fields keep the tracing output queryable (event_type,
        // severity, hash-chain linkage) without touching the on-disk JSONL
        // format. Per-level macro calls are required because `event!` needs a
        // constant level path.
        match severity {
            AuditSeverity::Debug => {
                tracing::debug!(
                    target: "audit",
                    event_type = %entry.event_type,
                    severity = ?severity,
                    chain_hash = %self.last_hash,
                    "{description}"
                );
            }
            AuditSeverity::Info => {
                tracing::info!(
                    target: "audit",
                    event_type = %entry.event_type,
                    severity = ?severity,
                    chain_hash = %self.last_hash,
                    "{description}"
                );
            }
            AuditSeverity::Warning => {
                tracing::warn!(
                    target: "audit",
                    event_type = %entry.event_type,
                    severity = ?severity,
                    chain_hash = %self.last_hash,
                    "{description}"
                );
            }
            AuditSeverity::Error => {
                tracing::error!(
                    target: "audit",
                    event_type = %entry.event_type,
                    severity = ?severity,
                    chain_hash = %self.last_hash,
                    "{description}"
                );
            }
            AuditSeverity::Critical => {
                tracing::error!(
                    target: "audit",
                    event_type = %entry.event_type,
                    severity = ?severity,
                    chain_hash = %self.last_hash,
                    critical = true,
                    "{description}"
                );
            }
        }

        Ok(())
    }

    fn rotate_if_needed(&mut self) -> Result<(), AuditError> {
        let metadata = match std::fs::symlink_metadata(&self.log_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(AuditError::Open {
                    path: self.log_path.display().to_string(),
                    source,
                });
            }
        };
        if !metadata.file_type().is_file() {
            return Err(AuditError::Open {
                path: self.log_path.display().to_string(),
                source: io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "audit log must be a regular file and not a symlink",
                ),
            });
        }
        if metadata.len() < self.max_bytes {
            return Ok(());
        }

        if self.max_archives == 0 {
            std::fs::remove_file(&self.log_path).map_err(|source| AuditError::Write {
                path: self.log_path.display().to_string(),
                source,
            })?;
        } else {
            let oldest = rotated_path(&self.log_path, self.max_archives);
            match std::fs::remove_file(&oldest) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(AuditError::Write {
                        path: oldest.display().to_string(),
                        source,
                    });
                }
            }
            for index in (1..self.max_archives).rev() {
                let from = rotated_path(&self.log_path, index);
                let to = rotated_path(&self.log_path, index + 1);
                match std::fs::rename(&from, &to) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(source) => {
                        return Err(AuditError::Write {
                            path: from.display().to_string(),
                            source,
                        });
                    }
                }
            }
            let first = rotated_path(&self.log_path, 1);
            std::fs::rename(&self.log_path, &first).map_err(|source| AuditError::Write {
                path: self.log_path.display().to_string(),
                source,
            })?;
        }
        self.last_hash = "genesis".to_string();
        Ok(())
    }

    /// Verify the integrity of the entire audit log.
    pub fn verify_integrity(&self) -> Result<AuditIntegrityReport, AuditError> {
        with_audit_read_lock(&self.log_path, || self.verify_integrity_unlocked())
    }

    fn verify_integrity_unlocked(&self) -> Result<AuditIntegrityReport, AuditError> {
        let path_str = self.log_path.display().to_string();
        let file = open_read_file(&self.log_path)?;
        let reader = BufReader::new(file);

        let mut total_entries = 0;
        let mut valid_entries = 0;
        let mut chain_valid = true;
        let mut expected_prev_hash = "genesis".to_string();
        let mut first_invalid: Option<String> = None;

        for line in reader.lines() {
            let line = line.map_err(|source| AuditError::Read {
                path: path_str.clone(),
                source,
            })?;
            total_entries += 1;

            if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) {
                if entry.verify() {
                    valid_entries += 1;
                } else if first_invalid.is_none() {
                    first_invalid = Some(entry.id.clone());
                }

                if entry.prev_hash != expected_prev_hash {
                    chain_valid = false;
                    if first_invalid.is_none() {
                        first_invalid = Some(entry.id.clone());
                    }
                }

                if let Some(hash) = entry.hash {
                    expected_prev_hash = hash;
                }
            } else {
                chain_valid = false;
                if first_invalid.is_none() {
                    first_invalid = Some(format!("line_{total_entries}"));
                }
            }
        }

        Ok(AuditIntegrityReport {
            total_entries,
            valid_entries,
            chain_valid,
            first_invalid_entry: first_invalid,
            log_path: self.log_path.clone(),
        })
    }

    /// Get recent audit entries. A missing log is empty; a corrupt line is an error.
    pub fn get_recent(&self, limit: usize) -> Result<Vec<AuditEntry>, AuditError> {
        let mut entries = read_all_entries(&self.log_path)?;
        entries.reverse();
        entries.truncate(limit);
        Ok(entries)
    }

    /// Filter entries by severity (and above)
    pub fn filter_by_severity(
        &self,
        min_severity: AuditSeverity,
    ) -> Result<Vec<AuditEntry>, AuditError> {
        let entries = read_all_entries(&self.log_path)?;
        Ok(entries
            .into_iter()
            .filter(|e| e.severity >= min_severity)
            .collect())
    }
}

fn bounded_audit_field(value: &str) -> String {
    if value.len() <= MAX_AUDIT_FIELD_BYTES {
        return value.to_string();
    }
    let mut end = MAX_AUDIT_FIELD_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

fn rotated_path(path: &Path, index: usize) -> PathBuf {
    PathBuf::from(format!("{}.{index}", path.display()))
}

fn open_read_file(path: &Path) -> Result<File, AuditError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    options.open(path).map_err(|source| AuditError::Open {
        path: path.display().to_string(),
        source,
    })
}

fn open_lock_file(path: &Path) -> Result<File, AuditError> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    options.open(path).map_err(|source| AuditError::Open {
        path: path.display().to_string(),
        source,
    })
}

fn open_append_file(path: &Path) -> Result<File, AuditError> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).append(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    options.open(path).map_err(|source| AuditError::Open {
        path: path.display().to_string(),
        source,
    })
}

fn ensure_trailing_newline(file: &mut File) -> io::Result<()> {
    let len = file.metadata()?.len();
    if len > 0 {
        file.seek(SeekFrom::End(-1))?;
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte)?;
        if byte[0] != b'\n' {
            file.seek(SeekFrom::End(0))?;
            writeln!(file)?;
        }
    }
    Ok(())
}

fn quarantine_corrupt_audit_log(path: &Path) -> Result<PathBuf, AuditError> {
    let parent = path.parent().ok_or_else(|| AuditError::CreateDir {
        path: path.display().to_string(),
        source: io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"),
    })?;
    let file_name = path.file_name().map_or_else(
        || "audit.jsonl".to_string(),
        |f| f.to_string_lossy().into_owned(),
    );
    let stamp = jiff::Timestamp::now()
        .strftime("%Y%m%dT%H%M%S%.6fZ")
        .to_string();

    let mut quarantined = parent.join(format!("{file_name}.corrupt-{stamp}"));
    let mut counter = 1u32;
    while quarantined.exists() {
        quarantined = parent.join(format!("{file_name}.corrupt-{stamp}-{counter}"));
        counter += 1;
    }

    std::fs::rename(path, &quarantined).map_err(|source| AuditError::Write {
        path: quarantined.display().to_string(),
        source,
    })?;
    Ok(quarantined)
}

fn with_audit_read_lock<T>(
    path: &Path,
    operation: impl FnOnce() -> Result<T, AuditError>,
) -> Result<T, AuditError> {
    let lock_path = path.with_extension("lock");
    let lock = open_lock_file(&lock_path)?;
    lock.lock_shared().map_err(|source| AuditError::Open {
        path: lock_path.display().to_string(),
        source,
    })?;
    let result = operation();
    let unlock_result = lock.unlock().map_err(|source| AuditError::Unlock {
        path: lock_path.display().to_string(),
        source,
    });
    match result {
        Ok(value) => {
            unlock_result?;
            Ok(value)
        }
        Err(error) => {
            if let Err(unlock_error) = unlock_result {
                tracing::warn!("Failed to unlock audit log after read error: {unlock_error}");
            }
            Err(error)
        }
    }
}

/// Read every JSONL entry. Missing files are empty; IO and parse failures are errors.
fn read_all_entries(path: &Path) -> Result<Vec<AuditEntry>, AuditError> {
    with_audit_read_lock(path, || read_all_entries_unlocked(path))
}

fn read_all_entries_unlocked(path: &Path) -> Result<Vec<AuditEntry>, AuditError> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let path_str = path.display().to_string();
    let file = open_read_file(path)?;
    let mut entries = Vec::new();
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|source| AuditError::Read {
            path: path_str.clone(),
            source,
        })?;
        if line.is_empty() {
            continue;
        }
        let entry = serde_json::from_str::<AuditEntry>(&line).map_err(|source| {
            AuditError::CorruptLine {
                path: path_str.clone(),
                line: index + 1,
                source,
            }
        })?;
        entries.push(entry);
    }
    Ok(entries)
}

fn get_last_hash(path: &Path) -> Result<String, AuditError> {
    let mut file = match open_read_file(path) {
        Ok(file) => file,
        Err(AuditError::Open { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            return Ok("genesis".to_string());
        }
        Err(error) => return Err(error),
    };
    let length = file
        .metadata()
        .map_err(|source| AuditError::Read {
            path: path.display().to_string(),
            source,
        })?
        .len();
    if length == 0 {
        return Ok("genesis".to_string());
    }

    let max_tail_bytes = u64::try_from(MAX_AUDIT_ENTRY_BYTES + 2).unwrap_or(u64::MAX);
    let tail_start = length.saturating_sub(max_tail_bytes);
    file.seek(SeekFrom::Start(tail_start))
        .map_err(|source| AuditError::Read {
            path: path.display().to_string(),
            source,
        })?;
    let mut tail = Vec::with_capacity(usize::try_from(length - tail_start).unwrap_or(0));
    file.read_to_end(&mut tail)
        .map_err(|source| AuditError::Read {
            path: path.display().to_string(),
            source,
        })?;

    while tail
        .last()
        .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
    {
        tail.pop();
    }
    if tail.is_empty() {
        return Ok("genesis".to_string());
    }
    let line_start = tail
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    if tail_start > 0 && line_start == 0 {
        return Err(AuditError::Read {
            path: path.display().to_string(),
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                format!("trailing audit entry exceeds {MAX_AUDIT_ENTRY_BYTES} bytes"),
            ),
        });
    }
    let line_number = if tail_start == 0 {
        memchr::memchr_iter(b'\n', &tail[..line_start]).count() + 1
    } else {
        0
    };
    let line = std::str::from_utf8(&tail[line_start..]).map_err(|source| AuditError::Read {
        path: path.display().to_string(),
        source: io::Error::new(io::ErrorKind::InvalidData, source),
    })?;
    let entry =
        serde_json::from_str::<AuditEntry>(line).map_err(|source| AuditError::CorruptLine {
            path: path.display().to_string(),
            line: line_number,
            source,
        })?;
    entry.hash.ok_or_else(|| AuditError::MissingHash {
        path: path.display().to_string(),
        line: line_number,
    })
}

/// Report from audit log integrity verification
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditIntegrityReport {
    pub total_entries: usize,
    pub valid_entries: usize,
    pub chain_valid: bool,
    pub first_invalid_entry: Option<String>,
    pub log_path: PathBuf,
}

impl AuditIntegrityReport {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.chain_valid && self.total_entries == self.valid_entries
    }
}

/// Global audit logger instance
static AUDIT_LOGGER: std::sync::LazyLock<std::sync::Mutex<Option<AuditLogger>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(None));
// Queue overflow must find the active collection without waiting for the
// writer's logger mutex, which can be held through file locking and fsync.
static AUDIT_INCOMPLETE_MARKER: std::sync::LazyLock<std::sync::RwLock<Option<PathBuf>>> =
    std::sync::LazyLock::new(|| std::sync::RwLock::new(None));

const AUDIT_QUEUE_CAPACITY: usize = 1024;

struct QueuedAuditEvent {
    event: AuditEventType,
    severity: AuditSeverity,
    resource: String,
    description: String,
}

/// Daemon callers enqueue owned events so filesystem locking, serialization,
/// and durability syncs run on one dedicated blocking writer thread rather
/// than a Tokio executor thread.
static AUDIT_QUEUE: std::sync::LazyLock<std::sync::mpsc::SyncSender<QueuedAuditEvent>> =
    std::sync::LazyLock::new(|| {
        let (sender, receiver) =
            std::sync::mpsc::sync_channel::<QueuedAuditEvent>(AUDIT_QUEUE_CAPACITY);
        if let Err(error) = std::thread::Builder::new()
            .name("omg-audit-writer".to_string())
            .spawn(move || {
                while let Ok(message) = receiver.recv() {
                    record_global(
                        message.event,
                        message.severity,
                        &message.resource,
                        &message.description,
                    );
                }
            })
        {
            tracing::error!("Failed to start audit writer thread: {error}");
        }
        sender
    });

/// Open the global audit logger before accepting daemon requests.
///
/// Quarantines corrupt audit logs rather than permanently wedging daemon startup.
pub fn init_audit_logger() -> Result<(), AuditError> {
    init_audit_logger_in(paths::data_dir().join("audit/audit.jsonl"))
}

/// Initialize the global audit logger at a daemon state's explicit location.
/// Isolated daemon state must not recover an ambient process data directory.
pub(crate) fn init_audit_logger_in(log_path: impl AsRef<Path>) -> Result<(), AuditError> {
    let log_path = log_path.as_ref();
    let logger = match AuditLogger::new_in(log_path) {
        Ok(l) => l,
        Err(AuditError::CorruptLine { .. } | AuditError::MissingHash { .. }) => {
            let quarantined = quarantine_corrupt_audit_log(log_path)?;
            tracing::warn!(
                "Audit log was corrupt; quarantined to {} and started fresh log",
                quarantined.display()
            );
            AuditLogger::new_in(log_path)?
        }
        Err(e) => return Err(e),
    };
    let marker = logger.log_path.with_file_name("incomplete");
    *AUDIT_LOGGER
        .lock()
        .map_err(|_| AuditError::LoggerPoisoned)? = Some(logger);
    *AUDIT_INCOMPLETE_MARKER
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(marker);
    Ok(())
}

/// Persist one event through the global audit logger.
///
/// The global is lazily created on first use: daemon code paths call this
/// without a prior `init_audit_logger`, and security events must reach the
/// tamper-evident log rather than silently degrade to `tracing` output.
fn record_global(
    event: AuditEventType,
    severity: AuditSeverity,
    resource: &str,
    description: &str,
) {
    let Ok(mut guard) = AUDIT_LOGGER.lock() else {
        mark_audit_incomplete();
        tracing::error!("Audit logger state is poisoned; dropping event {event} for {resource}");
        return;
    };
    if guard.is_none() {
        match AuditLogger::new() {
            Ok(logger) => {
                remember_audit_marker(&logger);
                *guard = Some(logger);
            }
            Err(AuditError::CorruptLine { .. } | AuditError::MissingHash { .. }) => {
                let log_path = paths::data_dir().join("audit/audit.jsonl");
                if let Ok(quarantined) = quarantine_corrupt_audit_log(&log_path) {
                    tracing::warn!(
                        "Audit log was corrupt; quarantined to {} and started fresh log",
                        quarantined.display()
                    );
                    if let Ok(logger) = AuditLogger::new() {
                        remember_audit_marker(&logger);
                        *guard = Some(logger);
                    }
                }
            }
            Err(error) => {
                mark_audit_incomplete_at_or_log(&paths::data_dir().join("audit/incomplete"));
                tracing::warn!(
                    "Audit logger unavailable, dropping event {event} for {resource}: {error}"
                );
                return;
            }
        }
    }
    let Some(logger) = guard.as_mut() else {
        mark_audit_incomplete_at_or_log(&paths::data_dir().join("audit/incomplete"));
        return;
    };
    if let Err(error) = logger.log(event, severity, resource, description) {
        mark_audit_incomplete_at_or_log(&logger.log_path.with_file_name("incomplete"));
        tracing::warn!("Failed to persist audit event {event} for {resource}: {error}");
    }
}

/// Queue an audit event without performing filesystem I/O on the caller.
///
/// The bounded queue deliberately drops events after emitting a tracing error
/// when saturated: untrusted daemon clients cannot create unbounded memory or
/// blocked-task growth by flooding the audit path.
pub fn audit_log_nonblocking(
    event: AuditEventType,
    severity: AuditSeverity,
    resource: &str,
    description: &str,
) {
    let message = QueuedAuditEvent {
        event,
        severity,
        resource: bounded_audit_field(resource),
        description: bounded_audit_field(description),
    };
    match AUDIT_QUEUE.try_send(message) {
        Ok(()) => {}
        Err(std::sync::mpsc::TrySendError::Full(message)) => {
            mark_audit_incomplete();
            tracing::error!(
                "Audit queue is full; dropping event {} for {}",
                message.event,
                message.resource
            );
        }
        Err(std::sync::mpsc::TrySendError::Disconnected(message)) => {
            mark_audit_incomplete();
            tracing::error!(
                "Audit writer is unavailable; dropping event {} for {}",
                message.event,
                message.resource
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn fresh_audit_store_creates_private_data_ancestors() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir()?;
        let data = root.path().join("data");
        let store = data.join("audit");
        let _logger = super::AuditLogger::new_in(store.join("audit.jsonl"))?;
        for path in [&data, &store] {
            assert_eq!(std::fs::metadata(path)?.permissions().mode() & 0o777, 0o700);
        }
        Ok(())
    }
    use super::*;

    #[cfg(target_os = "linux")]
    mod system_directory {
        use super::*;
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

        #[test]
        fn fresh_install_uses_private_storage_without_changing_syslog_permissions()
        -> anyhow::Result<()> {
            let parent = tempfile::tempdir()?;
            let syslog = tempfile::tempdir()?;
            std::fs::set_permissions(syslog.path(), std::fs::Permissions::from_mode(0o775))?;
            let directory = prepare_system_audit_directory(parent.path(), syslog.path())?;
            assert_eq!(std::fs::metadata(&directory)?.mode() & 0o777, 0o700);
            assert_eq!(
                std::fs::metadata(&directory)?.uid(),
                rustix::process::geteuid().as_raw()
            );
            assert_eq!(std::fs::metadata(syslog.path())?.mode() & 0o777, 0o775);
            assert!(!syslog.path().join("omg").exists());
            Ok(())
        }

        #[test]
        fn world_writable_parent_is_rejected_before_creation() -> anyhow::Result<()> {
            let parent = tempfile::tempdir()?;
            let legacy = tempfile::tempdir()?;
            std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o777))?;
            assert!(prepare_system_audit_directory(parent.path(), legacy.path()).is_err());
            assert_eq!(std::fs::read_dir(parent.path())?.count(), 0);
            Ok(())
        }

        #[test]
        fn writable_existing_audit_directory_is_not_adopted() -> anyhow::Result<()> {
            let parent = tempfile::tempdir()?;
            let legacy = tempfile::tempdir()?;
            let child = parent.path().join("audit");
            std::fs::create_dir(&child)?;
            for mode in [0o770, 0o777] {
                std::fs::set_permissions(&child, std::fs::Permissions::from_mode(mode))?;
                assert!(prepare_system_audit_directory(parent.path(), legacy.path()).is_err());
                assert_eq!(std::fs::metadata(&child)?.mode() & 0o777, mode);
            }
            Ok(())
        }

        #[test]
        fn symlink_parent_and_child_are_rejected() -> anyhow::Result<()> {
            let parent = tempfile::tempdir()?;
            let target = tempfile::tempdir()?;
            let legacy = tempfile::tempdir()?;
            let link = parent.path().join("link");
            symlink(target.path(), &link)?;
            assert!(prepare_system_audit_directory(&link, legacy.path()).is_err());
            symlink(target.path(), legacy.path().join("omg"))?;
            assert!(prepare_system_audit_directory(parent.path(), legacy.path()).is_err());
            assert_eq!(std::fs::read_dir(target.path())?.count(), 0);
            Ok(())
        }

        #[test]
        fn migration_preserves_history_archives_and_chain_continuity() -> anyhow::Result<()> {
            let parent = tempfile::tempdir()?;
            let legacy = tempfile::tempdir()?;
            let original = legacy.path().join("omg");
            std::fs::create_dir(&original)?;
            std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o755))?;
            AuditLogger::new_in(original.join("audit.jsonl"))?.log(
                AuditEventType::PackageInstall,
                AuditSeverity::Info,
                "tree",
                "existing history",
            )?;
            let original_bytes = std::fs::read(original.join("audit.jsonl"))?;
            std::fs::write(original.join("audit.jsonl.1"), &original_bytes)?;
            let directory = prepare_system_audit_directory(parent.path(), legacy.path())?;
            assert!(!original.exists());
            assert_eq!(
                std::fs::read(directory.join("audit.jsonl.1"))?,
                original_bytes
            );
            AuditLogger::new_in(directory.join("audit.jsonl"))?.log(
                AuditEventType::PackageRemove,
                AuditSeverity::Info,
                "tree",
                "after migration",
            )?;
            assert!(std::fs::read(directory.join("audit.jsonl"))?.starts_with(&original_bytes));
            let report = AuditLogger::new_in(directory.join("audit.jsonl"))?.verify_integrity()?;
            assert!(report.is_valid());
            assert_eq!(report.total_entries, 2);
            assert_eq!(
                prepare_system_audit_directory(parent.path(), legacy.path())?,
                directory
            );
            Ok(())
        }

        #[test]
        fn untrusted_legacy_data_is_not_discarded() -> anyhow::Result<()> {
            let parent = tempfile::tempdir()?;
            let legacy = tempfile::tempdir()?;
            std::fs::create_dir(legacy.path().join("omg"))?;
            let history = legacy.path().join("omg/audit.jsonl");
            std::fs::write(&history, b"retained history")?;
            std::fs::set_permissions(legacy.path(), std::fs::Permissions::from_mode(0o775))?;
            assert!(prepare_system_audit_directory(parent.path(), legacy.path()).is_err());
            assert_eq!(std::fs::read(history)?, b"retained history");
            assert!(!parent.path().join("audit").exists());
            Ok(())
        }

        #[test]
        fn cross_filesystem_migration_copies_history_byte_for_byte() -> anyhow::Result<()> {
            let parent = tempfile::tempdir()?;
            let legacy = tempfile::tempdir_in("/dev/shm")?;
            assert_ne!(
                std::fs::metadata(parent.path())?.dev(),
                std::fs::metadata(legacy.path())?.dev()
            );
            let original = legacy.path().join("omg");
            std::fs::create_dir(&original)?;
            AuditLogger::new_in(original.join("audit.jsonl"))?.log(
                AuditEventType::PackageInstall,
                AuditSeverity::Info,
                "tree",
                "existing history",
            )?;
            let original_bytes = std::fs::read(original.join("audit.jsonl"))?;
            std::fs::write(original.join("audit.jsonl.1"), &original_bytes)?;
            std::fs::set_permissions(
                original.join("audit.jsonl.1"),
                std::fs::Permissions::from_mode(0o640),
            )?;
            let nested = original.join("archives");
            std::fs::create_dir(&nested)?;
            std::fs::write(nested.join("segment"), b"archived segment")?;
            let directory = prepare_system_audit_directory(parent.path(), legacy.path())?;
            assert!(!original.exists());
            assert_eq!(
                std::fs::read(directory.join("audit.jsonl.1"))?,
                original_bytes
            );
            assert_eq!(
                std::fs::metadata(directory.join("audit.jsonl.1"))?.mode() & 0o777,
                0o640
            );
            assert_eq!(
                std::fs::read(directory.join("archives/segment"))?,
                b"archived segment"
            );
            AuditLogger::new_in(directory.join("audit.jsonl"))?.log(
                AuditEventType::PackageRemove,
                AuditSeverity::Info,
                "tree",
                "after migration",
            )?;
            let report = AuditLogger::new_in(directory.join("audit.jsonl"))?.verify_integrity()?;
            assert!(report.is_valid());
            assert_eq!(report.total_entries, 2);
            assert_eq!(
                prepare_system_audit_directory(parent.path(), legacy.path())?,
                directory
            );
            Ok(())
        }

        #[test]
        fn cross_filesystem_migration_refuses_symlinks_without_touching_legacy()
        -> anyhow::Result<()> {
            let parent = tempfile::tempdir()?;
            let legacy = tempfile::tempdir_in("/dev/shm")?;
            assert_ne!(
                std::fs::metadata(parent.path())?.dev(),
                std::fs::metadata(legacy.path())?.dev()
            );
            let original = legacy.path().join("omg");
            std::fs::create_dir(&original)?;
            let history = original.join("audit.jsonl");
            std::fs::write(&history, b"retained history")?;
            symlink(&history, original.join("alias"))?;
            assert!(prepare_system_audit_directory(parent.path(), legacy.path()).is_err());
            assert_eq!(std::fs::read(&history)?, b"retained history");
            assert!(!parent.path().join("audit").exists());
            Ok(())
        }

        #[test]
        fn concurrent_migrations_select_the_same_history() -> anyhow::Result<()> {
            let parent = tempfile::tempdir()?;
            let legacy = tempfile::tempdir()?;
            std::fs::create_dir(legacy.path().join("omg"))?;
            std::fs::write(legacy.path().join("omg/audit.jsonl"), b"retained history")?;
            let barrier = std::sync::Barrier::new(2);
            std::thread::scope(|scope| -> anyhow::Result<()> {
                let run = || {
                    barrier.wait();
                    prepare_system_audit_directory(parent.path(), legacy.path())
                };
                let first = scope.spawn(run);
                let second = scope.spawn(run);
                assert_eq!(
                    first.join().expect("migration thread panicked")?,
                    second.join().expect("migration thread panicked")?
                );
                Ok(())
            })?;
            assert_eq!(
                std::fs::read(parent.path().join("audit/audit.jsonl"))?,
                b"retained history"
            );
            Ok(())
        }

        #[test]
        fn competing_histories_require_explicit_reconciliation() -> anyhow::Result<()> {
            let parent = tempfile::tempdir()?;
            let legacy = tempfile::tempdir()?;
            let current = prepare_system_audit_directory(parent.path(), legacy.path())?;
            std::fs::write(current.join("audit.jsonl"), b"current history")?;
            std::fs::create_dir(legacy.path().join("omg"))?;
            let old = legacy.path().join("omg/audit.jsonl");
            std::fs::write(&old, b"legacy history")?;
            assert!(prepare_system_audit_directory(parent.path(), legacy.path()).is_err());
            assert_eq!(std::fs::read(old)?, b"legacy history");
            assert_eq!(
                std::fs::read(current.join("audit.jsonl"))?,
                b"current history"
            );
            Ok(())
        }
    }

    #[test]
    fn failed_audit_write_does_not_advance_the_chain() {
        let temp = tempfile::TempDir::new().unwrap();
        let log_path = temp.path().join("audit.jsonl");
        let mut logger = AuditLogger::new_in(log_path.clone()).unwrap();

        logger
            .log(
                AuditEventType::PackageInstall,
                AuditSeverity::Info,
                "firefox",
                "Installed firefox",
            )
            .unwrap();
        let hash_after_first = logger.last_hash.clone();
        assert_ne!(hash_after_first, "genesis");

        std::fs::remove_file(&log_path).unwrap();
        std::fs::create_dir(&log_path).unwrap();

        let error = logger
            .log(
                AuditEventType::PackageRemove,
                AuditSeverity::Info,
                "firefox",
                "Removed firefox",
            )
            .expect_err("appending over a directory must fail");
        // The failure surfaces either at the locked tail re-read (Read) or
        // at the append open (Open); both must abort before the chain moves.
        assert!(
            matches!(error, AuditError::Open { .. } | AuditError::Read { .. }),
            "got: {error}"
        );
        assert_eq!(logger.last_hash, hash_after_first);
    }

    fn expect_audit_err<T>(result: Result<T, AuditError>, what: &str) -> AuditError {
        match result {
            Ok(_) => panic!("{what}"),
            Err(err) => err,
        }
    }

    #[test]
    fn corrupt_line_is_not_used_as_chain_head() {
        let temp = tempfile::TempDir::new().unwrap();
        let log_path = temp.path().join("audit.jsonl");
        std::fs::write(&log_path, "not-json\n").unwrap();
        let err = expect_audit_err(
            AuditLogger::new_in(log_path),
            "corrupt log must not initialize a chain",
        );
        assert!(
            matches!(err, AuditError::CorruptLine { line: 1, .. }),
            "got: {err}"
        );
    }

    #[test]
    #[serial_test::serial]
    fn init_quarantines_corrupt_log_before_fresh_append() {
        if crate::core::is_root() {
            // Elevated processes resolve data paths to real system
            // directories regardless of OMG_DATA_DIR, so concurrent fixture
            // processes would collide on the real audit log. Unprivileged
            // CI (portable job) covers this test.
            eprintln!("skipped: elevated processes ignore caller path overrides");
            return;
        }
        let temp = tempfile::TempDir::new().unwrap();
        let audit_dir = temp.path().join("audit");
        let log_path = audit_dir.join("audit.jsonl");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::write(&log_path, "{\"id\":\"interrupted").unwrap();

        temp_env::with_var("OMG_DATA_DIR", Some(temp.path()), || {
            *AUDIT_LOGGER.lock().unwrap() = None;
            init_audit_logger().expect("production initialization must recover the corrupt log");
            record_global(
                AuditEventType::PackageInstall,
                AuditSeverity::Info,
                "firefox",
                "Installed firefox",
            );
            *AUDIT_LOGGER.lock().unwrap() = None;
        });

        let quarantined = std::fs::read_dir(&audit_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("audit.jsonl.corrupt-"))
            })
            .expect("corrupt log must be quarantined");
        assert_eq!(
            std::fs::read_to_string(quarantined).unwrap(),
            "{\"id\":\"interrupted"
        );

        let logger = AuditLogger::new_in(&log_path).unwrap();
        let report = logger.verify_integrity().unwrap();
        assert_eq!(report.total_entries, 1);
        assert!(report.is_valid());
        assert_eq!(
            logger.get_recent(1).unwrap()[0].description,
            "Installed firefox"
        );
    }

    #[test]
    fn append_restores_missing_record_separator() {
        let temp = tempfile::TempDir::new().unwrap();
        let log_path = temp.path().join("audit.jsonl");
        let mut logger = AuditLogger::new_in(&log_path).unwrap();
        logger
            .log(
                AuditEventType::PackageInstall,
                AuditSeverity::Info,
                "firefox",
                "Installed firefox",
            )
            .unwrap();

        let mut first_entry = std::fs::read(&log_path).unwrap();
        assert_eq!(first_entry.pop(), Some(b'\n'));
        std::fs::write(&log_path, first_entry).unwrap();

        logger
            .log(
                AuditEventType::PackageRemove,
                AuditSeverity::Info,
                "firefox",
                "Removed firefox",
            )
            .unwrap();
        let contents = std::fs::read_to_string(&log_path).unwrap();
        assert_eq!(contents.lines().count(), 2);
        assert!(logger.verify_integrity().unwrap().is_valid());
    }

    #[test]
    fn missing_hash_is_not_used_as_chain_head() {
        let temp = tempfile::TempDir::new().unwrap();
        let log_path = temp.path().join("audit.jsonl");
        std::fs::write(
            &log_path,
            r#"{"id":"x","timestamp":"2026-01-16T00:00:00Z","event_type":"package_install","severity":"info","user":"test","resource":"firefox","description":"Installed firefox","prev_hash":"genesis"}
"#,
        )
        .unwrap();
        let err = expect_audit_err(
            AuditLogger::new_in(log_path),
            "entry without a hash must not initialize a chain",
        );
        assert!(
            matches!(err, AuditError::MissingHash { line: 1, .. }),
            "got: {err}"
        );
    }

    #[test]
    fn get_recent_rejects_corrupt_lines() {
        let temp = tempfile::TempDir::new().unwrap();
        let log_path = temp.path().join("audit.jsonl");
        let mut logger = AuditLogger::new_in(log_path.clone()).unwrap();
        logger
            .log(
                AuditEventType::PackageInstall,
                AuditSeverity::Info,
                "firefox",
                "Installed firefox",
            )
            .unwrap();
        std::fs::write(&log_path, "not-json\n").unwrap();
        let err = logger
            .get_recent(10)
            .expect_err("viewing a corrupt log must fail closed");
        assert!(
            matches!(err, AuditError::CorruptLine { line: 1, .. }),
            "got: {err}"
        );
    }

    #[test]
    fn verify_integrity_reports_corrupt_json() {
        let temp = tempfile::TempDir::new().unwrap();
        let log_path = temp.path().join("audit.jsonl");
        std::fs::write(&log_path, "not-json\n").unwrap();
        let logger = AuditLogger {
            log_path,
            last_hash: "genesis".to_string(),
            max_bytes: DEFAULT_MAX_AUDIT_BYTES,
            max_archives: DEFAULT_AUDIT_ARCHIVES,
        };
        let report = logger.verify_integrity().unwrap();
        assert!(!report.is_valid());
        assert_eq!(report.total_entries, 1);
        assert_eq!(report.valid_entries, 0);
        assert!(!report.chain_valid);
    }

    #[test]
    fn test_audit_entry_hash() {
        let entry = AuditEntry {
            id: "test-id".to_string(),
            timestamp: "2026-01-16T00:00:00Z".to_string(),
            event_type: AuditEventType::PackageInstall,
            severity: AuditSeverity::Info,
            user: "test".to_string(),
            resource: "firefox".to_string(),
            description: "Installed firefox".to_string(),
            metadata: None,
            prev_hash: "genesis".to_string(),
            hash: None,
        };

        let hash = entry.compute_hash();
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_audit_entry_verify() {
        let mut entry = AuditEntry {
            id: "test-id".to_string(),
            timestamp: "2026-01-16T00:00:00Z".to_string(),
            event_type: AuditEventType::PackageInstall,
            severity: AuditSeverity::Info,
            user: "test".to_string(),
            resource: "firefox".to_string(),
            description: "Installed firefox".to_string(),
            metadata: None,
            prev_hash: "genesis".to_string(),
            hash: None,
        };

        entry.hash = Some(entry.compute_hash());
        assert!(entry.verify());

        // Tamper with the entry
        entry.description = "Tampered".to_string();
        assert!(!entry.verify());
    }

    #[test]
    fn concurrent_writers_keep_the_integrity_chain_valid() {
        // Regression: each writer used to cache the tail hash at logger
        // creation, so concurrent CLI + daemon writers forked the chain.
        const WRITERS: usize = 8;
        const EVENTS_PER_WRITER: usize = 4;
        let temp = tempfile::TempDir::new().unwrap();
        let log_path = temp.path().join("audit.jsonl");

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(WRITERS));
        let mut writers = Vec::new();
        for writer_index in 0..WRITERS {
            let log_path = log_path.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            writers.push(std::thread::spawn(move || {
                let mut logger = AuditLogger::new_in(log_path).unwrap();
                barrier.wait();
                for event_index in 0..EVENTS_PER_WRITER {
                    logger
                        .log(
                            AuditEventType::PackageInstall,
                            AuditSeverity::Info,
                            "firefox",
                            &format!("concurrent writer {writer_index} event {event_index}"),
                        )
                        .unwrap();
                }
            }));
        }
        for writer in writers {
            writer.join().expect("audit writer panicked");
        }

        let report = AuditLogger::new_in(log_path)
            .unwrap()
            .verify_integrity()
            .unwrap();
        assert_eq!(report.total_entries, WRITERS * EVENTS_PER_WRITER);
        assert!(
            report.is_valid(),
            "chain broke under concurrency: {report:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn audit_log_rotates_with_valid_chains_and_restrictive_modes() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("temporary audit directory");
        let log_path = temp.path().join("audit.jsonl");
        let mut logger =
            AuditLogger::new_in_with_limits(log_path.clone(), 1, 2).expect("create bounded logger");

        logger
            .log(
                AuditEventType::DaemonStarted,
                AuditSeverity::Info,
                "daemon",
                "first",
            )
            .expect("write first event");
        logger
            .log(
                AuditEventType::DaemonStopped,
                AuditSeverity::Info,
                "daemon",
                "second",
            )
            .expect("rotate and write second event");

        let archive_path = rotated_path(&log_path, 1);
        assert!(archive_path.is_file());
        assert!(
            AuditLogger::new_in(&archive_path)
                .expect("open archive")
                .verify_integrity()
                .expect("verify archive")
                .is_valid()
        );
        assert!(logger.verify_integrity().expect("verify active").is_valid());
        assert_eq!(
            std::fs::metadata(&log_path)
                .expect("active mode")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(log_path.with_extension("lock"))
                .expect("lock mode")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn audit_logger_refuses_symlink_log_paths() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("temporary audit directory");
        let target = temp.path().join("target");
        std::fs::write(&target, b"").expect("create target");
        let link = temp.path().join("audit.jsonl");
        symlink(&target, &link).expect("create symlink");

        let Err(error) = AuditLogger::new_in(&link) else {
            panic!("symlink must fail closed");
        };
        assert!(matches!(error, AuditError::Open { .. }));
    }

    #[test]
    #[serial_test::serial]
    fn global_writer_lazy_initializes_and_persists_events() {
        if crate::core::is_root() {
            // Same elevated-path isolation as
            // init_quarantines_corrupt_log_before_fresh_append.
            eprintln!("skipped: elevated processes ignore caller path overrides");
            return;
        }
        // The writer must initialize lazily so daemon events do not degrade to
        // tracing warnings when startup has not opened the log yet.
        let temp = tempfile::TempDir::new().unwrap();
        // SAFETY: test-only environment override, serialized via #[serial]
        #[expect(unsafe_code)]
        unsafe {
            std::env::set_var("OMG_DATA_DIR", temp.path());
        }

        record_global(
            AuditEventType::PolicyViolation,
            AuditSeverity::Warning,
            "daemon_handler",
            "lazy-init regression event",
        );

        // SAFETY: test cleanup, serialized
        #[expect(unsafe_code)]
        unsafe {
            std::env::remove_var("OMG_DATA_DIR");
        }

        let log_path = temp.path().join("audit/audit.jsonl");
        let report = AuditLogger::new_in(&log_path)
            .expect("global writer must have created the audit log")
            .verify_integrity()
            .unwrap();
        assert_eq!(report.total_entries, 1, "event must be persisted");
        assert!(report.is_valid(), "persisted event must chain: {report:?}");
        let entries = AuditLogger::new_in(&log_path)
            .unwrap()
            .get_recent(10)
            .unwrap();
        assert_eq!(entries[0].description, "lazy-init regression event");
        assert_eq!(entries[0].event_type, AuditEventType::PolicyViolation);
    }
}

#[cfg(target_os = "linux")]
fn check_audit_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("Untrusted system audit directory: {}", path.display()),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn create_audit_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => File::open(path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "audit directory has no parent")
        })?)?
        .sync_all()?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    check_audit_directory(path)
}

/// Snapshot an audit history tree as sorted `(relative path, content digest)`
/// pairs.
///
/// Used to verify a cross-filesystem migration copied every entry unchanged
/// (paths and file contents) before the source is removed. Directories digest
/// as empty content. Anything that is not a regular file or directory fails
/// the migration instead of being silently skipped.
#[cfg(target_os = "linux")]
fn snapshot_audit_tree(root: &Path) -> io::Result<Vec<(PathBuf, [u8; 32])>> {
    let mut entries = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(&path)? {
            let entry_path = entry?.path();
            let metadata = std::fs::symlink_metadata(&entry_path)?;
            if metadata.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Refusing to migrate symlink at {}", entry_path.display()),
                ));
            }
            let relative = entry_path.strip_prefix(root).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Path escapes audit tree: {}", entry_path.display()),
                )
            })?;
            if metadata.is_dir() {
                stack.push(entry_path.clone());
                entries.push((relative.to_path_buf(), [0_u8; 32]));
            } else if metadata.is_file() {
                let digest = Sha256::digest(std::fs::read(&entry_path)?);
                entries.push((relative.to_path_buf(), digest.into()));
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "Refusing to migrate special file at {}",
                        entry_path.display()
                    ),
                ));
            }
        }
    }
    entries.sort();
    Ok(entries)
}

/// Copy an audit history tree byte-for-byte across filesystems.
///
/// Fallback when `rename` fails with EXDEV because the legacy (`/var/log/omg`)
/// and current (`/var/lib/omg/audit`) locations live on different mounts (for
/// example btrfs subvolumes). The caller must hold both the migration lock and
/// the legacy lock, so no writer can change the source mid-copy. Content is
/// staged under a temporary sibling and renamed into place, so a crash cannot
/// leave a half-written history at the destination; a stale staging directory
/// from a previous crash is removed on entry. Ownership and permission bits
/// are preserved from the source, and every copied file is fsynced before the
/// copy is verified and the staging directory is renamed into place.
#[cfg(target_os = "linux")]
fn copy_audit_history(legacy: &Path, directory: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let parent = directory
        .parent()
        .ok_or_else(|| anyhow::anyhow!("audit directory has no parent"))?;
    let staging = parent.join(".audit-migrating");
    match std::fs::symlink_metadata(&staging) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            std::fs::remove_dir_all(&staging)?;
        }
        Ok(_) => anyhow::bail!(
            "Refusing cross-filesystem audit migration over non-directory at {}",
            staging.display()
        ),
        Err(error) => return Err(error.into()),
    }
    let expected = snapshot_audit_tree(legacy)?;
    std::fs::create_dir(&staging)?;
    let root_metadata = std::fs::symlink_metadata(legacy)?;
    // fchown the exact node we created; a path-based chown here could be
    // raced into following a symlink (csf_5eef98bc).
    crate::core::safe_ops::fchown_path_no_follow(
        &staging,
        Some(root_metadata.uid()),
        Some(root_metadata.gid()),
    )?;
    std::fs::set_permissions(&staging, root_metadata.permissions())?;
    let mut stack = vec![(legacy.to_path_buf(), staging.clone())];
    while let Some((source, dest)) = stack.pop() {
        for entry in std::fs::read_dir(&source)? {
            let entry = entry?;
            let metadata = std::fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() || !(metadata.is_dir() || metadata.is_file()) {
                anyhow::bail!(
                    "Refusing cross-filesystem audit migration at {}; move the history while OMG is stopped",
                    entry.path().display()
                );
            }
            let target = dest.join(entry.file_name());
            if metadata.is_dir() {
                std::fs::create_dir(&target)?;
                crate::core::safe_ops::fchown_path_no_follow(
                    &target,
                    Some(metadata.uid()),
                    Some(metadata.gid()),
                )?;
                std::fs::set_permissions(&target, metadata.permissions())?;
                stack.push((entry.path(), target));
            } else {
                std::fs::copy(entry.path(), &target)?;
                crate::core::safe_ops::fchown_path_no_follow(
                    &target,
                    Some(metadata.uid()),
                    Some(metadata.gid()),
                )?;
                std::fs::set_permissions(&target, metadata.permissions())?;
                File::open(&target)?.sync_all()?;
            }
        }
        File::open(&dest)?.sync_all()?;
    }
    if snapshot_audit_tree(&staging)? != expected {
        let _ = std::fs::remove_dir_all(&staging);
        anyhow::bail!(
            "Cross-filesystem audit copy of {} does not match the source; move the history while OMG is stopped",
            legacy.display()
        );
    }
    File::open(parent)?.sync_all()?;
    std::fs::rename(&staging, directory)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn prepare_system_audit_directory(parent: &Path, legacy_parent: &Path) -> anyhow::Result<PathBuf> {
    use anyhow::Context;

    check_audit_directory(parent)?;
    let migration_lock = open_lock_file(&parent.join("audit-migration.lock"))?;
    migration_lock.lock()?;
    let directory = parent.join("audit");
    let legacy = legacy_parent.join("omg");
    match std::fs::symlink_metadata(&legacy) {
        Ok(_) => {
            check_audit_directory(legacy_parent)?;
            check_audit_directory(&legacy)?;
            match std::fs::symlink_metadata(&directory) {
                Ok(_) => anyhow::bail!(
                    "Both system audit locations exist; reconcile {} and {} while OMG is stopped",
                    legacy.display(),
                    directory.display()
                ),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            // Serialize with old writers and move the entire history unchanged.
            let legacy_lock = open_lock_file(&legacy.join("audit.lock"))?;
            legacy_lock.lock()?;
            match std::fs::rename(&legacy, &directory) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::CrossesDevices => {
                    // The legacy and current locations can live on different
                    // mounts (for example btrfs subvolumes), where rename(2)
                    // fails with EXDEV. Copy the tree byte-for-byte instead of
                    // failing every privileged operation until an operator
                    // intervenes.
                    copy_audit_history(&legacy, &directory).with_context(|| {
                        format!(
                            "Cannot copy audit history {} to {}; move the history while OMG is stopped",
                            legacy.display(),
                            directory.display()
                        )
                    })?;
                    std::fs::remove_dir_all(&legacy)?;
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "Cannot atomically migrate {} to {}; move the history while OMG is stopped",
                            legacy.display(),
                            directory.display()
                        )
                    });
                }
            }
            File::open(parent)?.sync_all()?;
            File::open(legacy_parent)?.sync_all()?;
            check_audit_directory(&directory)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            create_audit_directory(&directory)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(directory)
}

/// Durable operation records are not subject to the daemon's best-effort queue.
pub fn record_operation(operation: &str, targets: &[String], outcome: &str) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    let system_directory = crate::core::privilege::is_root()
        .then(|| -> anyhow::Result<PathBuf> {
            for path in Path::new("/var/lib").ancestors() {
                check_audit_directory(path)?;
            }
            let parent = Path::new("/var/lib/omg");
            create_audit_directory(parent)?;
            prepare_system_audit_directory(parent, Path::new("/var/log"))
        })
        .transpose()?;
    #[cfg(target_os = "linux")]
    let mut logger = match system_directory.as_ref() {
        Some(directory) => AuditLogger::new_in(directory.join("audit.jsonl"))?,
        None => AuditLogger::new()?,
    };
    #[cfg(not(target_os = "linux"))]
    let mut logger = if crate::core::privilege::is_root() {
        use std::os::unix::fs::MetadataExt;
        let directory = Path::new("/var/log/omg");
        paths::create_private_data_directory(directory)?;
        for path in directory.ancestors() {
            let metadata = std::fs::symlink_metadata(path)?;
            anyhow::ensure!(
                metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
                "Untrusted system audit directory"
            );
        }
        AuditLogger::new_in(directory.join("audit.jsonl"))?
    } else {
        AuditLogger::new()?
    };
    let actor = crate::core::privilege::invoking_uid()?.to_string();
    let event = match operation.to_ascii_lowercase().as_str() {
        "install" | "install_blocking" => AuditEventType::PackageInstall,
        "remove" | "remove_blocking" => AuditEventType::PackageRemove,
        "update" | "upgrade" | "update_blocking" => AuditEventType::PackageUpgrade,
        "downgrade" => AuditEventType::PackageDowngrade,
        _ => AuditEventType::SecurityAudit,
    };
    logger.log(
        event,
        AuditSeverity::Info,
        &bounded_audit_field(&targets.join(", ")),
        &bounded_audit_field(&format!(
            "Package operation {operation}: {outcome}; invoking uid={actor}"
        )),
    )?;
    Ok(())
}

pub fn ensure_complete_collection(marker: &Path) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(marker) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => anyhow::bail!(
            "Audit collection is incomplete: events were lost; chain consistency cannot establish completeness"
        ),
    }
}

fn mark_audit_incomplete() {
    let marker = AUDIT_INCOMPLETE_MARKER
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let marker = marker
        .as_ref()
        .cloned()
        .unwrap_or_else(|| paths::data_dir().join("audit/incomplete"));
    mark_audit_incomplete_at_or_log(&marker);
}

fn remember_audit_marker(logger: &AuditLogger) {
    *AUDIT_INCOMPLETE_MARKER
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        Some(logger.log_path.with_file_name("incomplete"));
}

fn mark_audit_incomplete_at_or_log(path: &Path) {
    if let Err(error) = mark_audit_incomplete_at(path) {
        tracing::error!("Cannot persist audit incompleteness marker: {error}");
    }
}

fn mark_audit_incomplete_at(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        paths::create_private_data_directory(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(b"Audit events were lost; this collection is incomplete.\n")?;
            file.sync_all()
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod completeness_tests {
    #[test]
    #[serial_test::serial]
    fn failed_global_append_marks_its_explicit_collection_incomplete() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let log_path = directory.path().join("audit/audit.jsonl");
        super::init_audit_logger_in(&log_path)?;
        std::fs::create_dir(&log_path)?;
        super::record_global(
            super::AuditEventType::SecurityAudit,
            super::AuditSeverity::Error,
            "isolated-daemon",
            "forced append failure",
        );
        let marker = log_path.with_file_name("incomplete");
        assert!(super::ensure_complete_collection(&marker).is_err());
        *super::AUDIT_LOGGER.lock().unwrap() = None;
        *super::AUDIT_INCOMPLETE_MARKER.write().unwrap() = None;
        Ok(())
    }

    #[test]
    #[serial_test::serial]
    fn incomplete_marker_does_not_wait_for_audit_writer_lock() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let log_path = directory.path().join("audit/audit.jsonl");
        super::init_audit_logger_in(&log_path)?;
        let logger_guard = super::AUDIT_LOGGER.lock().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            super::mark_audit_incomplete();
            let _ = sender.send(());
        });
        let completed = receiver.recv_timeout(std::time::Duration::from_secs(2));
        drop(logger_guard);
        worker.join().expect("marker writer thread must finish");
        completed.expect("incomplete marker must not wait for the audit writer lock");
        assert!(super::ensure_complete_collection(&log_path.with_file_name("incomplete")).is_err());
        *super::AUDIT_LOGGER.lock().unwrap() = None;
        *super::AUDIT_INCOMPLETE_MARKER.write().unwrap() = None;
        Ok(())
    }

    #[test]
    fn loss_marker_survives_repeated_failures_and_refuses_verification() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("audit/incomplete");
        super::ensure_complete_collection(&path)?;
        super::mark_audit_incomplete_at(&path)?;
        super::mark_audit_incomplete_at(&path)?;
        assert!(super::ensure_complete_collection(&path).is_err());
        #[cfg(unix)]
        {
            let dangling = directory.path().join("dangling");
            std::os::unix::fs::symlink("missing", &dangling)?;
            assert!(super::ensure_complete_collection(&dangling).is_err());
        }
        Ok(())
    }
}
