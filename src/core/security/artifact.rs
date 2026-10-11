//! Immutable local package inputs and the unprivileged-to-root handoff.
//!
//! A pathname or an open ordinary file is insufficient: the owner can rewrite
//! it during sudo authentication. Linux sealed memfds pin the reviewed bytes;
//! the root consumer copies those bytes into its own private staging directory.
//! File sealing semantics: https://man7.org/linux/man-pages/man2/memfd_create.2.html

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

const PREFIX: &str = "/__omg_archive/";
const MAX_ARCHIVE_BYTES: u64 = 8 * 1024 * 1024 * 1024;

#[derive(Debug)]
pub struct ArchiveSnapshot {
    file: File,
    name: String,
    digest: String,
    signature: Option<(File, String)>,
    original: String,
}

/// Keep the internal descriptor transport out of user-facing package labels.
pub fn display_target(path: &str) -> &str {
    if is_handoff(path) {
        path.rsplit('/').next().unwrap_or(path)
    } else {
        path
    }
}

pub fn is_handoff(path: &str) -> bool {
    path.starts_with(PREFIX)
}

fn digest(file: &mut File) -> Result<String> {
    file.rewind()?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    file.rewind()?;
    Ok(hex::encode(hash.finalize()))
}

#[cfg(target_os = "linux")]
fn sealed_copy(mut source: File) -> Result<(File, String)> {
    use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};
    anyhow::ensure!(
        source.metadata()?.is_file(),
        "Package input must be a regular file"
    );
    let mut file = File::from(memfd_create(
        "omg-package",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )?);
    let bytes = std::io::copy(&mut (&mut source).take(MAX_ARCHIVE_BYTES + 1), &mut file)?;
    anyhow::ensure!(
        bytes <= MAX_ARCHIVE_BYTES,
        "Package exceeds snapshot size limit"
    );
    file.flush()?;
    fcntl_add_seals(
        &file,
        SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
    )?;
    let hash = digest(&mut file)?;
    Ok((file, hash))
}

#[cfg(not(target_os = "linux"))]
fn sealed_copy(_source: File) -> Result<(File, String)> {
    anyhow::bail!("Immutable local package installation requires Linux")
}

impl ArchiveSnapshot {
    pub fn capture(path: &Path) -> Result<Self> {
        if let Some(mut snapshot) = Self::from_handoff(&path.to_string_lossy())? {
            snapshot.file.rewind()?;
            return Ok(snapshot);
        }
        let text = path.to_str().context("Package path is not UTF-8")?;
        let canonical = if super::is_local_debian_package_file(text) {
            super::validate_local_debian_package_file(text)?
        } else {
            super::validate_local_package_file(text)?
        };
        let name = canonical
            .file_name()
            .and_then(|name| name.to_str())
            .context("Invalid package filename")?
            .to_owned();
        // Validate the opened file, not just an earlier stat of its pathname.
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let source = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&canonical)?;
        let metadata = source.metadata()?;
        let invoking_uid = crate::core::privilege::invoking_uid()?;
        anyhow::ensure!(
            (metadata.uid() == 0 || metadata.uid() == invoking_uid) && metadata.mode() & 0o022 == 0,
            "Untrusted package file ownership or permissions"
        );
        let (file, digest) = sealed_copy(source)?;
        let signature_path = PathBuf::from(format!("{}.sig", canonical.display()));
        let signature = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&signature_path)
        {
            Ok(source) => Some(sealed_copy(source)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            file,
            name,
            digest,
            signature,
            original: canonical.to_string_lossy().into_owned(),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn path(&self) -> PathBuf {
        use std::os::fd::AsRawFd;
        PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            self.file.as_raw_fd()
        ))
    }

    pub fn reader(&self) -> Result<File> {
        Ok(File::open(self.path())?)
    }

    /// Re-hash the sealed descriptor so callers can bind parsed metadata to
    /// the exact bytes retained across elevation.
    pub fn verify_sha256(&self, expected: &str) -> Result<()> {
        let mut reader = self.reader()?;
        let actual = digest(&mut reader)?;
        anyhow::ensure!(
            actual.eq_ignore_ascii_case(expected),
            "sealed archive hash mismatch"
        );
        Ok(())
    }

    pub fn handoff(&self) -> String {
        use std::os::fd::AsRawFd;
        let signature = self.signature.as_ref().map_or_else(
            || "none".to_owned(),
            |(file, hash)| format!("{}-{hash}", file.as_raw_fd()),
        );
        format!(
            "{PREFIX}{}/{}/{}/{}/{}/{}",
            std::process::id(),
            self.file.as_raw_fd(),
            self.digest,
            signature,
            self.name,
            self.original
        )
    }

    pub fn from_handoff(value: &str) -> Result<Option<Self>> {
        let Some(rest) = value.strip_prefix(PREFIX) else {
            return Ok(None);
        };
        let fields: Vec<_> = rest.splitn(6, '/').collect();
        anyhow::ensure!(
            fields.len() == 5 || fields.len() == 6,
            "Malformed package handoff"
        );
        let pid: u32 = fields[0].parse()?;
        let fd: u32 = fields[1].parse()?;
        anyhow::ensure!(
            pid > 0 && !fields[4].is_empty() && fields[4] != "." && fields[4] != "..",
            "Invalid package handoff"
        );
        let file = open_sealed(pid, fd, fields[2])?;
        let signature = if fields[3] == "none" {
            None
        } else {
            let (fd, hash) = fields[3]
                .split_once('-')
                .context("Malformed signature handoff")?;
            Some((open_sealed(pid, fd.parse()?, hash)?, hash.to_owned()))
        };
        Ok(Some(Self {
            file,
            name: fields[4].to_owned(),
            digest: fields[2].to_owned(),
            signature,
            original: handoff_original(value).unwrap_or(fields[4]).to_owned(),
        }))
    }
}

/// The caller's requested path as recorded in the descriptor's last field.
///
/// History records what the user asked for even when the archive metadata is
/// unreadable. Returns the original path when present, else the basename.
pub fn handoff_original(value: &str) -> Option<&str> {
    let rest = value.strip_prefix(PREFIX)?;
    let fields: Vec<_> = rest.splitn(6, '/').collect();
    if fields.len() == 6 && !fields[5].is_empty() && fields[5] != "." && fields[5] != ".." {
        Some(fields[5])
    } else {
        fields.get(4).copied()
    }
}

fn open_sealed(pid: u32, fd: u32, expected: &str) -> Result<File> {
    anyhow::ensure!(
        expected.len() == 64 && expected.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid package digest"
    );
    let mut file = File::open(format!("/proc/{pid}/fd/{fd}"))?;
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{SealFlags, fcntl_get_seals};
        let seals = fcntl_get_seals(&file)?;
        anyhow::ensure!(
            seals
                .contains(SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL),
            "Package handoff is not immutable"
        );
    }
    anyhow::ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() <= MAX_ARCHIVE_BYTES,
        "Package handoff exceeds size limit"
    );
    anyhow::ensure!(
        digest(&mut file)? == expected,
        "Package changed after approval"
    );
    Ok(file)
}

fn is_archive_input(target: &str) -> bool {
    let debian_backend = cfg!(any(feature = "debian", feature = "debian-pure"))
        && (!cfg!(feature = "arch") || crate::core::env::distro::is_debian_like());
    is_handoff(target)
        || super::is_local_package_file(target)
        || (debian_backend && super::is_local_debian_package_file(target))
}

/// Retain all snapshots until the caller's operation (including sudo) finishes.
pub struct SnapshotInputs {
    pub targets: Vec<String>,
    _snapshots: Vec<ArchiveSnapshot>,
}

impl SnapshotInputs {
    pub fn capture(targets: &[String]) -> Result<Self> {
        let mut snapshots = Vec::new();
        let mut result = Vec::with_capacity(targets.len());
        for target in targets {
            if is_archive_input(target) {
                let snapshot = ArchiveSnapshot::capture(Path::new(target))?;
                result.push(snapshot.handoff());
                snapshots.push(snapshot);
            } else {
                result.push(target.clone());
            }
        }
        Ok(Self {
            targets: result,
            _snapshots: snapshots,
        })
    }
}

/// Stage once before metadata validation and keep the directory through commit.
pub struct StagedInputs {
    pub targets: Vec<String>,
    _directories: Vec<tempfile::TempDir>,
}

impl StagedInputs {
    pub fn prepare(targets: &[String]) -> Result<Self> {
        let mut result = Vec::new();
        let mut directories = Vec::new();
        for target in targets {
            if is_archive_input(target) {
                anyhow::ensure!(
                    crate::core::privilege::is_root() || cfg!(test),
                    "Local archive staging requires the privileged consumer"
                );
                let snapshot = ArchiveSnapshot::capture(Path::new(target))?;
                // Ignore caller TMPDIR. /var/tmp is a system-owned sticky directory.
                let directory = tempfile::Builder::new()
                    .prefix("omg-package-")
                    .tempdir_in("/var/tmp")?;
                let path = directory.path().join(snapshot.name());
                let mut output = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)?;
                std::io::copy(&mut snapshot.reader()?, &mut output)?;
                if let Some((signature, _)) = &snapshot.signature {
                    let mut input = signature.try_clone()?;
                    input.rewind()?;
                    let mut output = File::create(format!("{}.sig", path.display()))?;
                    std::io::copy(&mut input, &mut output)?;
                }
                result.push(path.to_str().context("Invalid staged path")?.to_owned());
                directories.push(directory);
            } else {
                result.push(target.clone());
            }
        }
        Ok(Self {
            targets: result,
            _directories: directories,
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    #[test]
    fn snapshot_survives_replacement_and_in_place_writes() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("example.pkg.tar.zst");
        std::fs::write(&path, b"approved")?;
        let snapshot = ArchiveSnapshot::capture(&path)?;
        snapshot.verify_sha256(&snapshot.digest)?;
        assert!(snapshot.verify_sha256(&"0".repeat(64)).is_err());
        std::fs::write(&path, b"hostile")?;
        let replacement = dir.path().join("replacement");
        std::fs::write(&replacement, b"replaced")?;
        std::fs::rename(replacement, &path)?;
        let recovered = ArchiveSnapshot::from_handoff(&snapshot.handoff())?.unwrap();
        let mut content = String::new();
        recovered.reader()?.read_to_string(&mut content)?;
        assert_eq!(content, "approved");
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .open(snapshot.path())?
                .write_all(b"bad")
                .is_err()
        );
        let staged = StagedInputs::prepare(&[snapshot.handoff()])?;
        assert_eq!(std::fs::read(&staged.targets[0])?, b"approved");
        Ok(())
    }

    #[test]
    fn handoff_descriptor_round_trips_the_requested_path() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("example.pkg.tar.zst");
        std::fs::write(&path, b"approved")?;
        let snapshot = ArchiveSnapshot::capture(&path)?;
        let descriptor = snapshot.handoff();
        assert_eq!(
            handoff_original(&descriptor),
            Some(path.to_string_lossy().as_ref()),
            "the descriptor must carry the caller's requested path"
        );
        let recovered = ArchiveSnapshot::from_handoff(&descriptor)?.unwrap();
        assert_eq!(recovered.original, path.to_string_lossy());
        Ok(())
    }

    #[test]
    fn legacy_five_field_descriptor_keeps_the_basename_label() {
        let legacy = format!("{PREFIX}123/4/{}/none/example.pkg.tar.zst", "a".repeat(64));
        assert_eq!(handoff_original(&legacy), Some("example.pkg.tar.zst"));
        assert_eq!(display_target(&legacy), "example.pkg.tar.zst");
    }
    #[test]
    fn forged_unsealed_handoff_is_rejected() -> Result<()> {
        use rustix::fs::{MemfdFlags, memfd_create};
        use std::os::fd::AsRawFd;
        let mut file = File::from(memfd_create(
            "omg-unsealed-test",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )?);
        file.write_all(b"approved")?;
        let token = format!(
            "{PREFIX}{}/{}/{}/none/test.pkg.tar.zst",
            std::process::id(),
            file.as_raw_fd(),
            "2687f86ed6784b8a5fca36e6c468e12aa44dc3c7e8137e3160d1a95079bdcd02"
        );
        let error = ArchiveSnapshot::from_handoff(&token)
            .expect_err("an unsealed handoff must be rejected even with the correct digest");
        assert_eq!(error.to_string(), "Package handoff is not immutable");
        Ok(())
    }

    #[test]
    fn display_target_hides_handoff_prefix() {
        assert_eq!(
            display_target("/__omg_archive/1/3/deadbeef/none/foo.pkg.tar.zst"),
            "foo.pkg.tar.zst"
        );
        assert_eq!(display_target("foo.pkg.tar.zst"), "foo.pkg.tar.zst");
    }
}
