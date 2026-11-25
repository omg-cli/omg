use std::fs::OpenOptions;
use std::io::{self, Read as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use nix::libc;
use sha2::{Digest, Sha256};

use super::MAX_QUERY_BYTES;
use super::repository_observation::DirectCatalogScope;

const MAGIC: &[u8; 8] = b"OMGRPM01";
const DIGEST_LEN: usize = 32;
const HEADER_LEN: usize = MAGIC.len() + 2 * DIGEST_LEN;

pub(super) struct CatalogCache {
    path: PathBuf,
    scope: DirectCatalogScope,
    key: [u8; DIGEST_LEN],
}

impl CatalogCache {
    pub(super) fn open((scope, key): (DirectCatalogScope, [u8; DIGEST_LEN])) -> Result<Self> {
        let directory = crate::core::paths::cache_dir();
        ensure!(
            directory.is_absolute(),
            "DNF query cache requires an absolute directory"
        );
        Ok(Self {
            path: directory.join("dnf-search-v1.bin"),
            scope,
            key,
        })
    }

    pub(super) fn read(&self) -> Result<Option<Vec<u8>>> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let stat = file.metadata()?;
        ensure!(
            stat.is_file()
                && stat.uid() == nix::unistd::geteuid().as_raw()
                && stat.mode() & 0o777 == 0o600
                && stat.nlink() == 1
                && stat.len() <= MAX_QUERY_BYTES + HEADER_LEN as u64,
            "Invalid DNF search cache file"
        );

        let mut file = file.take(MAX_QUERY_BYTES + HEADER_LEN as u64 + 1);
        let mut header = [0u8; HEADER_LEN];
        file.read_exact(&mut header)?;
        let (magic, rest) = header.split_at(MAGIC.len());
        let (key, digest) = rest.split_at(DIGEST_LEN);
        if magic != MAGIC || key != self.key {
            return Ok(None);
        }
        let mut rows = Vec::with_capacity(stat.len().saturating_sub(HEADER_LEN as u64) as usize);
        file.read_to_end(&mut rows)?;
        ensure!(
            rows.len() as u64 <= MAX_QUERY_BYTES,
            "DNF search cache exceeds size limit"
        );
        ensure!(
            &Sha256::digest(&rows)[..] == digest,
            "DNF search cache checksum mismatch"
        );
        Ok((self.scope.key()? == self.key).then_some(rows))
    }

    pub(super) fn publish(&self, rows: &[u8]) -> Result<()> {
        ensure!(
            rows.len() as u64 <= MAX_QUERY_BYTES,
            "DNF search cache exceeds size limit"
        );
        if self.scope.key()? != self.key {
            return Ok(());
        }
        let mut encoded = Vec::with_capacity(HEADER_LEN + rows.len());
        encoded.extend_from_slice(MAGIC);
        encoded.extend_from_slice(&self.key);
        encoded.extend_from_slice(&Sha256::digest(rows));
        encoded.extend_from_slice(rows);
        crate::core::safe_ops::atomic_write_file_sync_private(&self.path, &encoded)
            .context("Cannot publish DNF search cache")
    }
}
