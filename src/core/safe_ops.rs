//! Safe operations library for OMG
//!
//! Provides safe constructors and utilities for common operations that would otherwise
//! require `unwrap()` or `expect()`. This module helps eliminate panic-prone patterns
//! throughout the codebase while maintaining performance and ergonomics.

use anyhow::{Context, Result};
use std::io::Write;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
/// Create a `NonZeroU32` with a default fallback value.
///
/// If both `value` and `default` are zero, falls back to `NonZeroU32::MIN` (1).
pub fn nonzero_u32_or_default(value: u32, default: u32) -> NonZeroU32 {
    NonZeroU32::new(value)
        .or_else(|| NonZeroU32::new(default))
        .unwrap_or(NonZeroU32::MIN)
}

/// Validate only the basic string syntax of a path.
///
/// This rejects empty, non-UTF-8, and NUL-containing paths. It deliberately
/// does not claim symlink, traversal, ownership, or containment safety;
/// callers crossing those boundaries must apply a domain-specific validator.
pub fn validate_path_syntax<P: AsRef<Path>>(path: P) -> Result<PathBuf> {
    let path = path.as_ref();

    // Check for empty path
    if path.as_os_str().is_empty() {
        return Err(anyhow::anyhow!("Path cannot be empty"));
    }

    // Check for null bytes
    let Some(path_str) = path.to_str() else {
        return Err(anyhow::anyhow!("Path contains invalid UTF-8"));
    };
    if path_str.contains('\0') {
        return Err(anyhow::anyhow!("Path contains null byte"));
    }

    // Return the path as-is (canonicalize() fails for non-existent paths)
    Ok(path.to_path_buf())
}

/// Create an executable file without following or racing a pre-existing path.
///
/// Returns `false` when `overwrite` is disabled and any filesystem entry is
/// already present. Forced replacement uses a same-directory atomic rename,
/// which replaces a destination symlink rather than writing through it.
/// Contents are written and synced before publication. A parent-directory sync
/// error after publication can leave a complete file at the destination.
#[cfg(unix)]
pub fn write_executable(path: &Path, contents: &[u8], overwrite: bool) -> Result<bool> {
    use std::os::unix::fs::PermissionsExt;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("Failed to create parent directory: {}", parent.display()))?;

    if !overwrite {
        return write_noclobber(path, contents, 0o755);
    }

    let mut temporary = tempfile::NamedTempFile::new_in(parent).with_context(|| {
        format!(
            "Failed to create temporary executable in {}",
            parent.display()
        )
    })?;
    temporary
        .as_file_mut()
        .set_permissions(std::fs::Permissions::from_mode(0o755))?;
    temporary.as_file_mut().write_all(contents)?;
    temporary.as_file_mut().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("Failed to replace executable {}", path.display()))?;
    sync_parent_directory_sync(path)?;
    Ok(true)
}

/// Atomically claim a private marker path without following an existing entry.
///
/// Write and file-sync failures leave the destination absent. A directory-sync
/// error after publication can leave a complete marker at the destination.
#[cfg(unix)]
pub fn create_private_marker(path: &Path, contents: &[u8]) -> Result<bool> {
    write_noclobber(path, contents, 0o600)
}

#[cfg(unix)]
fn write_noclobber(path: &Path, contents: &[u8], mode: u32) -> Result<bool> {
    use std::os::unix::fs::PermissionsExt;

    // Preserve the existing-entry result even when staging would fail. The
    // publication below still checks atomically for entries created later.
    match std::fs::symlink_metadata(path) {
        Ok(_) => return Ok(false),
        Err(error) => {
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(error).with_context(|| format!("Failed to inspect {}", path.display()));
            }
        }
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    // Create with the requested mode (subject to umask), just like create_new.
    // A failed write or file sync only leaves a temporary owned by this guard;
    // never unlink the destination, which could belong to another writer.
    let mut temporary = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(mode))
        .tempfile_in(parent)
        .with_context(|| format!("Failed to stage {}", path.display()))?;
    temporary.as_file_mut().write_all(contents)?;
    temporary.as_file_mut().sync_all()?;
    match temporary.persist_noclobber(path) {
        Ok(_) => {
            sync_parent_directory_sync(path)?;
            Ok(true)
        }
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => {
            Err(error.error).with_context(|| format!("Failed to create {}", path.display()))
        }
    }
}

/// Change ownership of a file or directory without following a final symlink.
///
/// A path-based `chown` can be raced into following a symlink swapped into
/// place between a privileged metadata read and the ownership change, which
/// transfers ownership of an unrelated inode (csf_5eef98bc). Opening with
/// `O_NOFOLLOW` and applying `fchown` to the descriptor pins the operation to
/// the exact node at `path`: a swapped-in symlink fails the open instead of
/// redirecting the ownership change.
///
/// # Errors
/// Returns an error when the path is a symlink, cannot be opened, or the
/// ownership change fails.
#[cfg(unix)]
pub fn fchown_path_no_follow(path: &Path, uid: Option<u32>, gid: Option<u32>) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = std::fs::OpenOptions::new();
    options.read(true).custom_flags(nix::libc::O_NOFOLLOW);
    let file = options.open(path).with_context(|| {
        format!(
            "Failed to open {} without following symlinks",
            path.display()
        )
    })?;
    nix::unistd::fchown(
        &file,
        uid.map(nix::unistd::Uid::from_raw),
        gid.map(nix::unistd::Gid::from_raw),
    )
    .with_context(|| format!("Failed to change ownership of {}", path.display()))?;
    Ok(())
}

/// Make a persisted file replacement durable by syncing its parent directory.
pub(crate) fn sync_parent_directory_sync(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("Failed to sync parent directory: {}", parent.display()))
}

/// Async bridge for [`sync_parent_directory_sync`].
#[cfg(feature = "arch")]
pub(crate) async fn sync_parent_directory(path: PathBuf) -> Result<()> {
    tokio::task::spawn_blocking(move || sync_parent_directory_sync(&path))
        .await
        .context("Parent-directory sync task failed")?
}

/// Safe file write with atomic operations
pub async fn atomic_write_file<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> Result<()> {
    let path = path.as_ref().to_path_buf();
    let contents = contents.as_ref().to_vec();
    tokio::task::spawn_blocking(move || atomic_write_file_sync(path, contents))
        .await
        .context("Atomic file writer task failed")?
}

/// Safe synchronous file write with atomic operations: tmp + fsync + rename,
/// preserving the existing file mode when the file already exists.
///
/// # Errors
/// Returns an error when the path cannot be validated, staged, written,
/// synced, or atomically replaced.
pub fn atomic_write_file_sync<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> Result<()> {
    atomic_write_file_sync_inner(path, contents, false)
}

/// Atomic write that forces the result to owner-only (0o600).
///
/// Regardless of pre-existing mode: security exports (audit logs, credential
/// material) must never inherit a previously permissive mode through the
/// replace.
///
/// # Errors
/// Returns an error when the path cannot be validated, staged, written,
/// synced, or atomically replaced.
pub fn atomic_write_file_sync_private<P: AsRef<Path>, C: AsRef<[u8]>>(
    path: P,
    contents: C,
) -> Result<()> {
    atomic_write_file_sync_inner(path, contents, true)
}

fn atomic_write_file_sync_inner<P: AsRef<Path>, C: AsRef<[u8]>>(
    path: P,
    contents: C,
    private: bool,
) -> Result<()> {
    let path = validate_path_syntax(path)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("Failed to create parent directory: {}", parent.display()))?;

    let existing_permissions = if private {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            Some(std::fs::Permissions::from_mode(0o600))
        }
        #[cfg(not(unix))]
        None
    } else {
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {
                // Preserve only the nine permission bits. Reapplying the raw
                // `st_mode` would carry set-user-ID, set-group-ID and sticky
                // bits onto the replacement, so a caller that can pre-create
                // the destination could turn a privileged write into a
                // set-user-ID, world-writable executable (csf_5eef98bc
                // family).
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    Some(std::fs::Permissions::from_mode(
                        metadata.permissions().mode() & 0o777,
                    ))
                }
                #[cfg(not(unix))]
                {
                    Some(metadata.permissions())
                }
            }
            Ok(_) => None,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("Failed to inspect existing file: {}", path.display())
                });
            }
        }
    };

    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("Failed to create temporary file in {}", parent.display()))?;
    if let Some(permissions) = existing_permissions {
        temporary
            .as_file_mut()
            .set_permissions(permissions)
            .with_context(|| format!("Failed to preserve permissions for {}", path.display()))?;
    }
    temporary
        .as_file_mut()
        .write_all(contents.as_ref())
        .with_context(|| format!("Failed to write temporary file for {}", path.display()))?;
    temporary
        .as_file_mut()
        .sync_all()
        .with_context(|| format!("Failed to sync temporary file for {}", path.display()))?;
    temporary
        .persist(&path)
        .map_err(|error| error.error)
        .with_context(|| format!("Failed to replace {}", path.display()))?;
    // The rename above is only durable once the parent directory entry is
    // synced; without this, a crash can resurrect the previous version of the
    // file. https://lwn.net/Articles/457667/
    sync_parent_directory_sync(&path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::fs;

    #[test]
    fn test_nonzero_u32_or_default() {
        let nz1 = nonzero_u32_or_default(0, 100);
        assert_eq!(nz1.get(), 100);

        let nz2 = nonzero_u32_or_default(50, 100);
        assert_eq!(nz2.get(), 50);
    }

    #[test]
    fn test_validate_path_syntax_valid() {
        let path = "/tmp";
        let result = validate_path_syntax(path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_path_syntax_empty() {
        let path = "";
        let result = validate_path_syntax(path);
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_preserves_existing_file_mode() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TempDir::new().unwrap();
        let path = directory.path().join("shared-state.json");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        atomic_write_file_sync(&path, b"new").unwrap();

        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_never_carries_set_id_bits_onto_the_replacement() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TempDir::new().unwrap();
        let path = directory.path().join("planted-executable");
        std::fs::write(&path, b"old").unwrap();
        // A caller that can pre-create the destination must not be able to
        // make the privileged replacement set-user-ID/set-group-ID/sticky.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o4777)).unwrap();

        atomic_write_file_sync(&path, b"new").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o7000, 0, "set-id/sticky bits leaked: {mode:o}");
        assert_eq!(mode & 0o777, 0o777, "ordinary permission bits are kept");
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

    #[tokio::test]
    async fn test_atomic_write_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let content = b"Hello, world!";

        let result = atomic_write_file(&file_path, content).await;
        assert!(result.is_ok());

        let read_content = fs::read_to_string(&file_path).await.unwrap();
        assert_eq!(read_content, "Hello, world!");
    }

    #[cfg(unix)]
    #[test]
    fn executable_writer_never_follows_destination_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let target = temp.path().join("target");
        std::fs::write(&target, b"keep").unwrap();
        let link = temp.path().join("hook");
        symlink(&target, &link).unwrap();

        assert!(!write_executable(&link, b"new", false).unwrap());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        assert!(write_executable(&link, b"new", true).unwrap());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        assert_eq!(std::fs::read(&link).unwrap(), b"new");
    }

    #[cfg(unix)]
    #[test]
    fn fchown_applies_to_regular_files() {
        use std::os::unix::fs::MetadataExt as _;

        let directory = TempDir::new().unwrap();
        let file = directory.path().join("owned");
        std::fs::write(&file, b"data").unwrap();
        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();

        fchown_path_no_follow(&file, Some(uid), Some(gid)).expect("fchown regular file");
        assert_eq!(
            std::fs::metadata(&file).unwrap().uid(),
            uid,
            "ownership must be preserved on the exact node"
        );
        assert_eq!(
            std::fs::metadata(&file).unwrap().gid(),
            gid,
            "group ownership must match the caller's group"
        );
    }

    #[cfg(unix)]
    #[test]
    fn fchown_refuses_to_follow_final_symlinks() {
        use std::os::unix::fs::MetadataExt as _;
        use std::os::unix::fs::symlink;

        let directory = TempDir::new().unwrap();
        let target = directory.path().join("target");
        std::fs::write(&target, b"keep").unwrap();
        let link = directory.path().join("link");
        symlink(&target, &link).unwrap();
        let uid = std::fs::metadata(&target).unwrap().uid();

        // O_NOFOLLOW fails the open with ELOOP before any ownership change,
        // regardless of privilege, so the symlink target keeps its owner.
        assert!(fchown_path_no_follow(&link, Some(0), Some(0)).is_err());
        assert_eq!(std::fs::metadata(&target).unwrap().uid(), uid);
    }

    #[cfg(unix)]
    #[test]
    fn private_marker_refuses_dangling_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let target = temp.path().join("target");
        let marker = temp.path().join("marker");
        symlink(&target, &marker).unwrap();

        assert!(!create_private_marker(&marker, b"1").unwrap());
        assert!(!target.exists());
    }

    #[test]
    fn test_atomic_write_file_sync() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let content = b"Hello, world!";

        let result = atomic_write_file_sync(&file_path, content);
        assert!(result.is_ok());

        let read_content = std::fs::read_to_string(&file_path).unwrap();
        assert_eq!(read_content, "Hello, world!");
    }
}
