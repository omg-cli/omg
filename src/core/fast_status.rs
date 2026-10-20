//! Zero-IPC fast status for sub-millisecond reads
//!
//! The daemon writes a binary status file that CLI reads directly,
//! bypassing socket connection and IPC serialization overhead.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::core::paths;

/// Fast status structure - fixed size for mmap-friendly reads
///
/// Uses zerocopy for safe serialization without unsafe transmute.
///
/// # Invariants
/// [`magic`](FastStatus::magic) and [`version`](FastStatus::version) are set
/// only by [`FastStatus::new`]; readers reject any file whose header does
/// not match. Fields stay public because CLI callers read the counters of a
/// value obtained from [`FastStatus::read_from_file`], which has already
/// validated the header.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct FastStatus {
    /// Magic number for validation (0x4F4D4753 = "OMGS")
    pub magic: u32,
    /// Version of the format
    pub version: u8,
    /// Padding for alignment
    pub pad: [u8; 3],
    /// Total installed packages
    pub total_packages: u32,
    /// Explicitly installed packages
    pub explicit_packages: u32,
    /// Orphan packages
    pub orphan_packages: u32,
    /// Available updates
    pub updates_available: u32,
    /// Timestamp (unix seconds)
    pub timestamp: u64,
}

const MAGIC: u32 = 0x4F4D_4753; // "OMGS"
const VERSION: u8 = 1;

/// Maximum age of the status file before readers reject it as stale.
///
/// Must stay in sync with the daemon writer cadence (`STATUS_REFRESH_INTERVAL`
/// in `daemon/server.rs`): if the reader TTL is shorter than the writer
/// interval, the zero-IPC fast path is dead between refreshes; a pinned test
/// in `daemon/server.rs` enforces the relationship.
pub const FAST_STATUS_FRESHNESS_SECS: u64 = 300;

impl FastStatus {
    /// Create a new fast status
    #[must_use]
    pub fn new(total: usize, explicit: usize, orphans: usize, updates: usize) -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            pad: [0; 3],
            total_packages: total.min(u32::MAX as usize) as u32,
            explicit_packages: explicit.min(u32::MAX as usize) as u32,
            orphan_packages: orphans.min(u32::MAX as usize) as u32,
            updates_available: updates.min(u32::MAX as usize) as u32,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        }
    }

    /// Write status to file (atomic via temp file + rename)
    pub fn write_to_file(&self, path: &Path) -> std::io::Result<()> {
        // A unique temporary file per writer avoids two processes writing
        // through a shared fixed ".tmp" name and renaming interleaved bytes.
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;

        // Safe serialization using zerocopy - no unsafe needed
        temporary.as_file_mut().write_all(self.as_bytes())?;
        temporary.as_file_mut().sync_all()?;

        // Atomic rename; keep the io::ErrorKind so callers matching on
        // NotFound vs PermissionDenied still work, but name the target path
        // in the message instead of silently pointing at the vanished temp
        // file. https://docs.rs/tempfile/latest/tempfile/struct.NamedTempFile.html#method.persist
        temporary.persist(path).map_err(|error| {
            std::io::Error::new(
                error.error.kind(),
                format!(
                    "failed to persist fast status to {}: {}",
                    path.display(),
                    error.error
                ),
            )
        })?;
        crate::core::safe_ops::sync_parent_directory_sync(path).map_err(|error| {
            std::io::Error::other(format!(
                "failed to sync fast status parent directory for {}: {error:#}",
                path.display()
            ))
        })?;
        Ok(())
    }

    /// Read status from file (sub-millisecond)
    #[must_use]
    pub fn read_from_file(path: &Path) -> Option<Self> {
        let mut file = File::open(path).ok()?;
        let mut bytes = [0u8; std::mem::size_of::<Self>()];
        file.read_exact(&mut bytes).ok()?;

        // Safe deserialization using zerocopy - no unsafe needed
        let status = Self::read_from_bytes(&bytes).ok()?;
        if status.magic != MAGIC || status.version != VERSION {
            return None;
        }

        // Check freshness against the shared TTL (aligned with the daemon's
        // STATUS_REFRESH_INTERVAL so the zero-IPC path stays live).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        if status.timestamp > now || now - status.timestamp > FAST_STATUS_FRESHNESS_SECS {
            return None;
        }

        Some(status)
    }

    /// Read the default status file with full validation.
    pub fn read_default() -> Option<Self> {
        Self::read_validated(&paths::fast_status_path())
    }

    /// Read a status file only when its parent directory passes the same
    /// runtime-directory validation the daemon applies before binding
    /// (real, current-uid-owned, owner-only). The status path is selected by
    /// environment, so an unvalidated read would accept a foreign or
    /// symlinked cache file (csf_fdd4999c).
    pub fn read_validated(path: &Path) -> Option<Self> {
        #[cfg(unix)]
        paths::validate_socket_parent(path).ok()?;
        Self::read_from_file(path)
    }

    /// Read explicit count directly (fastest path)
    #[must_use]
    pub fn read_explicit_count() -> Option<usize> {
        Self::read_default().map(|status| status.explicit_packages as usize)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used)] // Idiomatic in tests: panics on failure with clear error context
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn fast_status_roundtrips_through_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("status.bin");

        let status = FastStatus::new(1000, 200, 10, 5);
        status.write_to_file(&path).unwrap();

        let read = FastStatus::read_from_file(&path).unwrap();
        assert_eq!(read.total_packages, 1000);
        assert_eq!(read.explicit_packages, 200);
        assert_eq!(read.orphan_packages, 10);
        assert_eq!(read.updates_available, 5);
        assert_eq!(read.magic, MAGIC);
        assert_eq!(read.version, VERSION);
    }

    #[test]
    fn invalid_magic_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("invalid.bin");

        let mut status = FastStatus::new(100, 50, 0, 0);
        status.write_to_file(&path).unwrap();
        let read = FastStatus::read_from_file(&path).expect("fresh valid status must be readable");
        assert_eq!(read.total_packages, 100);
        status.magic = 0xDEAD_BEEF;
        status.write_to_file(&path).unwrap();

        assert!(FastStatus::read_from_file(&path).is_none());
    }

    #[test]
    fn future_status_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("future.bin");

        let mut status = FastStatus::new(100, 50, 0, 0);
        status.write_to_file(&path).unwrap();
        let read = FastStatus::read_from_file(&path).expect("fresh valid status must be readable");
        assert_eq!(read.total_packages, 100);
        status.timestamp = u64::MAX;
        status.write_to_file(&path).unwrap();

        assert!(FastStatus::read_from_file(&path).is_none());
    }

    #[test]
    fn stale_status_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("stale.bin");

        let mut status = FastStatus::new(100, 50, 0, 0);
        status.write_to_file(&path).unwrap();
        let read = FastStatus::read_from_file(&path).expect("fresh valid status must be readable");
        assert_eq!(read.total_packages, 100);
        status.timestamp = 0; // Way in the past
        status.write_to_file(&path).unwrap();

        assert!(FastStatus::read_from_file(&path).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn validated_reads_reject_unsafe_status_parents() {
        use std::os::unix::fs::PermissionsExt;

        if crate::core::is_root() {
            eprintln!("skipped: elevated processes bypass caller path overrides");
            return;
        }
        let dir = tempdir().unwrap();
        let runtime = dir.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        // create_dir applies the umask (typically 0755); the fixture must
        // start from the owner-only mode the daemon would establish.
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        let status = FastStatus::new(100, 50, 0, 0);
        let path = runtime.join("omg.status");
        status.write_to_file(&path).unwrap();
        assert!(FastStatus::read_validated(&path).is_some());

        // Group-accessible runtime directory: the daemon would refuse to bind
        // here, so the CLI must refuse to trust the cache either.
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(FastStatus::read_validated(&path).is_none());
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(FastStatus::read_validated(&path).is_some());

        // A symlinked runtime directory is never trusted, even when its
        // permissions look private.
        let linked = dir.path().join("linked");
        std::os::unix::fs::symlink(&runtime, &linked).unwrap();
        let linked_status = linked.join("omg.status");
        assert!(FastStatus::read_validated(&linked_status).is_none());
    }
}
