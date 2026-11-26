pub mod distro;
pub mod fingerprint;
pub mod portable;
pub mod team;

use anyhow::{Context as _, Result, ensure};
use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::path::Path;

pub(crate) fn lock_regular_file(path: &Path) -> Result<File> {
    let check_type = |metadata: fs::Metadata| {
        ensure!(
            metadata.is_file(),
            "Lock path must be a regular file: {}",
            path.display()
        );
        Ok(())
    };
    match fs::symlink_metadata(path) {
        Ok(metadata) => check_type(metadata)?,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            #[cfg(unix)]
            create_lock_file(path)?;
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Failed to inspect lock {}", path.display()));
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(not(unix))]
    options.create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_NOCTTY);
    }
    let file = options
        .open(path)
        .with_context(|| format!("Failed to open lock {}", path.display()))?;
    check_type(file.metadata()?)?;
    file.lock()
        .with_context(|| format!("Failed to acquire lock {}", path.display()))?;
    Ok(file)
}

#[cfg(unix)]
fn create_lock_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("Failed to stage lock {}", path.display()))?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .with_context(|| format!("Failed to set lock permissions {}", path.display()))?;
    match temporary.persist_noclobber(path) {
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == ErrorKind::AlreadyExists => Ok(()),
        Err(error) => {
            Err(error.error).with_context(|| format!("Failed to create lock {}", path.display()))
        }
    }
}
