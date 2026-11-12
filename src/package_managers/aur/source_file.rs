use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use alpm_srcinfo::SourceInfoV1;
use anyhow::{Context, Result};

pub(crate) const MAX_SOURCE_FILE_BYTES: u64 = 16 * 1024 * 1024;

pub(crate) fn read_regular(path: &Path) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "AUR source must be a regular file"
    );
    let mut bytes = Vec::new();
    file.take(MAX_SOURCE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_SOURCE_FILE_BYTES,
        "AUR source file exceeds limit"
    );
    Ok(bytes)
}

pub(crate) fn read_srcinfo(directory: &Path) -> Result<Option<SourceInfoV1>> {
    let path = directory.join(".SRCINFO");
    let bytes = match read_regular(&path) {
        Ok(bytes) => bytes,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Failed to read .SRCINFO at {}", path.display()));
        }
    };
    let content = std::str::from_utf8(&bytes).context("AUR .SRCINFO is not UTF-8")?;
    SourceInfoV1::from_string(content)
        .context("Failed to parse .SRCINFO")
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_file_reads_require_regular_bounded_bytes() {
        let directory = tempfile::tempdir().expect("private source directory");
        let file = directory.path().join("input");
        std::fs::write(&file, b"source").expect("private source file");
        assert_eq!(read_regular(&file).expect("regular source"), b"source");
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&file, &link).expect("private source symlink");
        assert!(
            read_regular(&link).is_err(),
            "source reads must not follow symlinks"
        );
        let fifo = directory.path().join("fifo");
        nix::unistd::mkfifo(
            &fifo,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .expect("private source FIFO");
        let error =
            read_regular(&fifo).expect_err("nonblocking FIFO admission must refuse before reading");
        assert!(error.to_string().contains("regular file"));
        assert!(
            read_regular(directory.path()).is_err(),
            "directories are not source files"
        );
        let file_handle = OpenOptions::new()
            .write(true)
            .open(&file)
            .expect("private source descriptor");
        file_handle
            .set_len(MAX_SOURCE_FILE_BYTES)
            .expect("bounded sparse source");
        assert_eq!(
            read_regular(&file).expect("source at byte limit").len() as u64,
            MAX_SOURCE_FILE_BYTES
        );
        file_handle
            .set_len(MAX_SOURCE_FILE_BYTES + 1)
            .expect("one-byte-over sparse source");
        let error = read_regular(&file).expect_err("source over byte limit");
        assert!(error.to_string().contains("source file exceeds limit"));
    }

    #[test]
    fn fresh_metadata_acquisition_distinguishes_absence_from_invalid_inputs() {
        let directory = tempfile::tempdir().expect("private metadata directory");
        assert!(
            read_srcinfo(directory.path())
                .expect("genuine absence")
                .is_none()
        );
        let file = directory.path().join(".SRCINFO");
        std::fs::write(&file, "invalid metadata").expect("private malformed metadata");
        assert!(read_srcinfo(directory.path()).is_err());
        std::fs::remove_file(&file).expect("private fixture reset");
        std::os::unix::fs::symlink(directory.path().join("absent"), &file)
            .expect("private dangling metadata symlink");
        assert!(
            read_srcinfo(directory.path()).is_err(),
            "dangling symlinks cannot masquerade as absent metadata"
        );
    }
}
