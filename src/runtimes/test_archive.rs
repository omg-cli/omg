//! Checksum-valid archive inputs for the real runtime installer tests.
use anyhow::Result;
use std::io::{Cursor, Write as _};

#[derive(Clone, Copy)]
pub(super) enum Launcher {
    Missing,
    Directory,
    Regular,
}

pub(super) fn tar_gz(root: &str, launcher: &str, kind: Launcher) -> Result<Vec<u8>> {
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let mut archive = tar::Builder::new(encoder);
    let (path, entry_type, contents) = match kind {
        Launcher::Missing => (
            "README",
            tar::EntryType::Regular,
            b"archive documentation".as_slice(),
        ),
        Launcher::Directory => (launcher, tar::EntryType::Directory, b"".as_slice()),
        Launcher::Regular => (
            launcher,
            tar::EntryType::Regular,
            b"fixture launcher".as_slice(),
        ),
    };
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(entry_type);
    header.set_mode(0o755);
    header.set_size(contents.len() as u64);
    header.set_cksum();
    archive.append_data(&mut header, format!("{root}/{path}"), contents)?;
    Ok(archive.into_inner()?.finish()?)
}

pub(super) fn zip(root: &str, launcher: &str, kind: Launcher) -> Result<Vec<u8>> {
    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default().unix_permissions(0o755);
    match kind {
        Launcher::Missing => {
            archive.start_file(format!("{root}/README"), options)?;
            archive.write_all(b"archive documentation")?;
        }
        Launcher::Directory => archive.add_directory(format!("{root}/{launcher}/"), options)?,
        Launcher::Regular => {
            archive.start_file(format!("{root}/{launcher}"), options)?;
            archive.write_all(b"fixture launcher")?;
        }
    }
    Ok(archive.finish()?.into_inner())
}
