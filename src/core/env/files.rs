use anyhow::{Context, Result};
use std::fs::{self, OpenOptions};
use std::io::Read as _;
use std::path::Path;

const MAX_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy)]
pub(crate) enum Symlinks {
    Follow,
    Refuse,
}

pub(crate) fn ensure_size(size: u64, kind: &str, path: &Path) -> Result<()> {
    anyhow::ensure!(
        size <= MAX_BYTES,
        "{kind} exceeds the {MAX_BYTES} byte limit: {}",
        path.display()
    );
    Ok(())
}

pub(crate) fn read_utf8(path: &Path, kind: &str, symlinks: Symlinks) -> Result<String> {
    let metadata = match symlinks {
        Symlinks::Follow => fs::metadata(path),
        Symlinks::Refuse => fs::symlink_metadata(path),
    }
    .with_context(|| format!("Failed to inspect {kind} {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file(),
        "Refusing to read {kind} that is not a regular file: {} (symlink or special file)",
        path.display()
    );

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let flags = match symlinks {
            Symlinks::Follow => nix::libc::O_NONBLOCK,
            Symlinks::Refuse => nix::libc::O_NONBLOCK | nix::libc::O_NOFOLLOW,
        };
        options.custom_flags(flags);
    }
    let file = options
        .open(path)
        .with_context(|| format!("Failed to open {kind} {} safely", path.display()))?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file(),
        "Refusing to read {kind} that is not a regular file: {}",
        path.display()
    );
    ensure_size(metadata.len(), kind, path)?;

    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("Failed to read {kind} {}", path.display()))?;
    ensure_size(bytes.len() as u64, kind, path)?;
    String::from_utf8(bytes).with_context(|| format!("{kind} is not UTF-8: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_directories_and_invalid_text() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let error = read_utf8(directory.path(), "snapshot file", Symlinks::Refuse)
            .expect_err("a directory is not a snapshot");
        assert!(error.to_string().contains("not a regular file"));

        let path = directory.path().join("state.json");
        fs::write(&path, [0xff])?;
        let error = read_utf8(&path, "snapshot file", Symlinks::Refuse)
            .expect_err("snapshot files must be UTF-8");
        assert!(error.to_string().contains("not UTF-8"));
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn follows_symlinks_only_for_explicit_imports() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let manifest = directory.path().join("manifest.json");
        let link = directory.path().join("linked.json");
        fs::write(&manifest, "{}")?;
        std::os::unix::fs::symlink(&manifest, &link)?;

        assert_eq!(
            read_utf8(&link, "migration manifest", Symlinks::Follow)?,
            "{}"
        );
        let error = read_utf8(&link, "snapshot index", Symlinks::Refuse)
            .expect_err("managed snapshot index must not follow the final link");
        assert!(error.to_string().contains("symlink"));
        Ok(())
    }
}
