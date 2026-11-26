//! Persistent metadata cache for the daemon.
//!
//! Stores the system status snapshot as a single atomically-replaced JSON
//! file so it survives daemon restarts. A single-key snapshot does not
//! justify an embedded transactional database; [`crate::core::safe_ops`]
//! provides the same crash-safety (no truncated files, owner-only mode).
//! Snapshots bind counts to an installed database and publication age.
//! Older snapshots with a timestamp remain readable by unscoped callers.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use super::protocol::StatusResult;
use crate::core::fast_status::{StatusScope, open_status_snapshot};

/// Current on-disk status snapshot format.
const STATUS_FORMAT_VERSION: u32 = 3;
const MAX_STATUS_CACHE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Deserialize)]
struct StatusVersion {
    format_version: u32,
}

#[derive(Deserialize)]
struct LegacyStatusV1 {
    status: StatusResult,
}

#[derive(Serialize, Deserialize)]
struct PersistedStatus {
    format_version: u32,
    published_at: SystemTime,
    status: StatusResult,
    scope: StatusScope,
}

#[derive(Deserialize)]
struct LegacyStatusV2 {
    published_at: SystemTime,
    status: StatusResult,
}

pub(crate) struct PersistentCache {
    path: PathBuf,
}

impl PersistentCache {
    pub(crate) fn new(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        Ok(Self {
            path: dir.join("status-cache.json"),
        })
    }

    #[cfg(test)]
    pub(crate) fn get_status(&self, max_age: Duration) -> Result<Option<StatusResult>> {
        self.get_scoped_status(StatusScope::UNSCOPED, max_age)
    }

    pub(crate) fn get_scoped_status(
        &self,
        scope: StatusScope,
        max_age: Duration,
    ) -> Result<Option<StatusResult>> {
        self.get_status_at(scope, max_age, SystemTime::now())
    }

    fn get_status_at(
        &self,
        scope: StatusScope,
        max_age: Duration,
        now: SystemTime,
    ) -> Result<Option<StatusResult>> {
        Ok(self
            .read_snapshot()?
            .filter(|snapshot| {
                snapshot.scope == scope
                    && now
                        .duration_since(snapshot.published_at)
                        .is_ok_and(|age| age < max_age)
            })
            .map(|snapshot| snapshot.status))
    }

    /// Validate known versions without rewriting legacy or forward-version files.
    fn read_snapshot(&self) -> Result<Option<PersistedStatus>> {
        let (file, size) = match open_status_snapshot(&self.path) {
            Ok(snapshot) => snapshot,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).context(format!(
                    "Failed to read daemon status cache {}",
                    self.path.display()
                ));
            }
        };
        let maximum = MAX_STATUS_CACHE_BYTES as u64;
        anyhow::ensure!(
            size <= maximum,
            "Daemon status cache exceeds {maximum} bytes"
        );
        let mut content = String::new();
        file.take(maximum + 1)
            .read_to_string(&mut content)
            .with_context(|| {
                format!("Failed to read daemon status cache {}", self.path.display())
            })?;
        anyhow::ensure!(
            content.len() <= MAX_STATUS_CACHE_BYTES,
            "Daemon status cache exceeds {maximum} bytes"
        );
        let version: StatusVersion = serde_json::from_str(&content)
            .with_context(|| format!("Malformed daemon status cache: {}", self.path.display()))?;
        match version.format_version {
            1 => {
                let legacy: LegacyStatusV1 = serde_json::from_str(&content)
                    .context("Malformed version-1 daemon status cache")?;
                tracing::debug!(
                    total_packages = legacy.status.total_packages,
                    "Legacy status snapshot has no publication time; refresh required"
                );
                Ok(None)
            }
            2 => {
                let legacy: LegacyStatusV2 = serde_json::from_str(&content)
                    .context("Malformed version-2 daemon status cache")?;
                Ok(Some(PersistedStatus {
                    format_version: version.format_version,
                    published_at: legacy.published_at,
                    status: legacy.status,
                    scope: StatusScope::UNSCOPED,
                }))
            }
            STATUS_FORMAT_VERSION => serde_json::from_str(&content)
                .map(Some)
                .context("Malformed version-3 daemon status cache"),
            unknown => anyhow::bail!("Unsupported daemon status cache format version {unknown}"),
        }
    }

    #[cfg(test)]
    pub(crate) fn set_status(&self, status: &StatusResult) -> Result<()> {
        self.set_scoped_status(StatusScope::UNSCOPED, status)
    }

    pub(crate) fn set_scoped_status(
        &self,
        scope: StatusScope,
        status: &StatusResult,
    ) -> Result<()> {
        // Never replace unknown or malformed data with a guessed current schema.
        let _ = self.read_snapshot()?;
        let persisted = PersistedStatus {
            format_version: STATUS_FORMAT_VERSION,
            published_at: SystemTime::now(),
            status: status.clone(),
            scope,
        };
        let content =
            serde_json::to_vec(&persisted).context("Failed to serialize daemon status cache")?;
        anyhow::ensure!(
            content.len() <= MAX_STATUS_CACHE_BYTES,
            "Daemon status cache exceeds {MAX_STATUS_CACHE_BYTES} bytes"
        );
        crate::core::safe_ops::atomic_write_file_sync(&self.path, content)
            .with_context(|| format!("Failed to write {}", self.path.display()))
    }

    /// Invalidate the persisted snapshot (best-effort).
    ///
    /// Called when the package index is replaced (e.g. after `omg sync`):
    /// without this, disk fallback could serve pre-sync counts within their
    /// remaining TTL. Unknown or malformed formats are left untouched.
    pub(crate) fn invalidate_status(&self) {
        if let Err(error) = self.read_snapshot() {
            tracing::warn!("Refusing to delete unsupported or malformed status cache: {error}");
            return;
        }
        if let Err(error) = std::fs::remove_file(&self.path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::debug!(
                "Could not remove stale daemon status cache {}: {error}",
                self.path.display()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_cache_matches_the_publishing_database_and_ignores_legacy_status() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let cache = PersistentCache::new(directory.path())?;
        let host = StatusScope([1; 32]);
        let alternate = StatusScope([2; 32]);
        let ttl = Duration::from_mins(5);
        let unbound = serde_json::json!({
            "format_version": 2,
            "published_at": SystemTime::now(),
            "status": status(),
        });
        std::fs::write(&cache.path, unbound.to_string())?;
        assert!(cache.get_scoped_status(host, ttl)?.is_none());
        assert_eq!(
            cache
                .get_status(ttl)?
                .context("unscoped version-2 status")?
                .total_packages,
            42
        );

        cache.set_scoped_status(host, &status())?;
        assert_eq!(
            cache
                .get_scoped_status(host, ttl)?
                .context("same scope status")?
                .total_packages,
            42
        );
        assert!(cache.get_scoped_status(alternate, ttl)?.is_none());
        assert!(cache.get_status(ttl)?.is_none());
        Ok(())
    }

    fn status() -> StatusResult {
        StatusResult {
            total_packages: 42,
            explicit_packages: 20,
            orphan_packages: 1,
            updates_available: 2,
            security_vulnerabilities: 3,
            vulnerabilities_scanned: true,
            security_unknown_packages: Some(0),
            runtime_versions: Vec::new(),
        }
    }

    #[test]
    fn legacy_status_without_a_timestamp_is_not_fresh() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let cache = PersistentCache::new(directory.path())?;
        let bytes = serde_json::to_vec(&serde_json::json!({
            "format_version": 1,
            "status": status(),
        }))?;
        std::fs::write(&cache.path, &bytes)?;
        assert!(
            cache.get_status(Duration::from_mins(2))?.is_none(),
            "legacy status has no freshness evidence"
        );
        assert_eq!(std::fs::read(&cache.path)?, bytes);
        cache.set_status(&status())?;
        let current = cache.read_snapshot()?.context("new timestamped snapshot")?;
        assert_eq!(current.format_version, 3);
        assert_eq!(current.status.total_packages, 42);
        Ok(())
    }

    #[test]
    fn persisted_status_obeys_original_publication_deadline() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let cache = PersistentCache::new(directory.path())?;
        let snapshot = PersistedStatus {
            format_version: STATUS_FORMAT_VERSION,
            published_at: SystemTime::UNIX_EPOCH + Duration::from_secs(100),
            status: status(),
            scope: StatusScope::UNSCOPED,
        };
        let bytes = serde_json::to_vec(&snapshot)?;
        std::fs::write(&cache.path, &bytes)?;
        for (now, ttl, fresh) in [
            (100, 120, true),
            (219, 120, true),
            (220, 120, false),
            (221, 120, false),
            (99, 120, false),
            (100, 0, false),
        ] {
            let result = cache.get_status_at(
                StatusScope::UNSCOPED,
                Duration::from_secs(ttl),
                SystemTime::UNIX_EPOCH + Duration::from_secs(now),
            )?;
            assert_eq!(result.is_some(), fresh, "now={now}, ttl={ttl}");
        }
        assert_eq!(std::fs::read(&cache.path)?, bytes);
        Ok(())
    }

    #[test]
    fn unknown_and_malformed_snapshots_are_never_overwritten_or_deleted() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let cache = PersistentCache::new(directory.path())?;
        for bytes in [
            serde_json::to_vec(&serde_json::json!({"format_version": 4}))?,
            serde_json::to_vec(&serde_json::json!({"format_version": 3}))?,
            serde_json::to_vec(&serde_json::json!({"format_version": 2, "status": status()}))?,
            b"not json".to_vec(),
        ] {
            std::fs::write(&cache.path, &bytes)?;
            assert!(cache.get_status(Duration::from_mins(2)).is_err());
            assert!(cache.set_status(&status()).is_err());
            cache.invalidate_status();
            assert_eq!(std::fs::read(&cache.path)?, bytes);
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn linked_status_is_neither_read_nor_replaced() -> Result<()> {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let cache = PersistentCache::new(directory.path())?;
        cache.set_status(&status())?;
        let backing = directory.path().join("saved-status.json");
        std::fs::rename(&cache.path, &backing)?;
        let original = std::fs::read(&backing)?;
        symlink(&backing, &cache.path)?;
        assert!(cache.get_status(Duration::from_mins(2)).is_err());
        assert!(cache.set_status(&status()).is_err());
        cache.invalidate_status();
        assert!(std::fs::symlink_metadata(&cache.path)?.is_symlink());
        assert_eq!(std::fs::read(backing)?, original);
        Ok(())
    }

    #[test]
    fn oversized_valid_snapshot_is_neither_used_nor_replaced() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let cache = PersistentCache::new(directory.path())?;
        cache.set_status(&status())?;
        let mut bytes = std::fs::read(&cache.path)?;
        bytes.resize(MAX_STATUS_CACHE_BYTES + 1, b' ');
        std::fs::write(&cache.path, &bytes)?;

        let error = cache
            .get_status(Duration::from_mins(2))
            .expect_err("an oversized valid snapshot must be refused");
        assert!(format!("{error:#}").contains("status cache exceeds"));
        assert!(cache.set_status(&status()).is_err());
        cache.invalidate_status();
        assert_eq!(std::fs::metadata(&cache.path)?.len(), bytes.len() as u64);
        Ok(())
    }

    #[test]
    fn current_status_round_trips_and_invalidation_removes_known_data() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let cache = PersistentCache::new(directory.path())?;
        let ttl = Duration::from_mins(2);
        assert!(cache.get_status(ttl)?.is_none());
        cache.set_status(&status())?;
        assert_eq!(
            cache
                .get_status(ttl)?
                .context("fresh snapshot")?
                .total_packages,
            42
        );
        cache.invalidate_status();
        assert!(cache.get_status(ttl)?.is_none());
        Ok(())
    }
}
