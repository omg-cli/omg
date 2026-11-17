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

fn tar_entries(root: &str, entries: &[(&str, &[u8])]) -> Result<Vec<u8>> {
    let mut archive = tar::Builder::new(Vec::new());
    for (name, bytes) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o755);
        header.set_size(bytes.len() as u64);
        header.set_cksum();
        archive.append_data(&mut header, format!("{root}/{name}"), *bytes)?;
    }
    Ok(archive
        .into_inner()
        .expect("finish controlled in-memory tar fixture"))
}

pub(super) fn tar_gz_entries(root: &str, entries: &[(&str, &[u8])]) -> Result<Vec<u8>> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder
        .write_all(&tar_entries(root, entries)?)
        .expect("encode controlled in-memory gzip fixture");
    Ok(encoder.finish().expect("finish controlled gzip fixture"))
}

pub(super) fn tar_xz_entries(root: &str, entries: &[(&str, &[u8])]) -> Result<Vec<u8>> {
    let mut compressed = Vec::new();
    lzma_rs::xz_compress(
        &mut Cursor::new(tar_entries(root, entries)?),
        &mut compressed,
    )
    .expect("encode controlled in-memory XZ fixture");
    Ok(compressed)
}

pub(super) struct PublicationFixture {
    pub(super) owner: tempfile::TempDir,
    pub(super) versions: std::path::PathBuf,
    pub(super) archive: std::path::PathBuf,
    launcher: std::path::PathBuf,
    runtime: String,
}

impl PublicationFixture {
    pub(super) fn new(runtime: &str, launcher: &str) -> Self {
        use std::{fs, os::unix::fs::symlink};
        let owner = tempfile::tempdir().expect("private archive publication fixture");
        let versions = owner.path().join("versions").join(runtime);
        let previous = versions.join("1.0.0");
        let binary = previous.join(launcher);
        fs::create_dir_all(binary.parent().expect("controlled launcher parent"))
            .expect("previous runtime directory");
        fs::write(&binary, b"previous reviewed runtime").expect("previous runtime bytes");
        super::security::fixture_prepare(runtime, "1.0.0", &previous, &previous)
            .expect("admit the previous owned runtime");
        symlink("1.0.0", versions.join("current")).expect("select previous runtime");
        let archive = owner.path().join("runtime.archive");
        Self {
            owner,
            versions,
            archive,
            launcher: launcher.into(),
            runtime: runtime.into(),
        }
    }

    pub(super) fn write(&self, bytes: &[u8]) {
        std::fs::write(&self.archive, bytes)
            .expect("write private authenticated-archive phase input");
    }

    pub(super) fn assert_previous(&self) {
        assert_eq!(
            std::fs::read_link(self.versions.join("current")).expect("prior selection"),
            std::path::Path::new("1.0.0")
        );
        let previous = self.versions.join("1.0.0");
        assert_eq!(
            std::fs::read(previous.join(&self.launcher)).expect("prior launcher"),
            b"previous reviewed runtime"
        );
        super::security::admit_installed(
            &self.runtime,
            &previous,
            super::security::ReviewMode::CachedOnly,
        )
        .expect("prior admission survives failed publication")
        .verify(&previous)
        .expect("prior content remains bound");
        assert!(
            !std::fs::read_dir(&self.versions)
                .expect("fixture versions")
                .any(|entry| {
                    let entry = entry.expect("owned fixture entry");
                    entry.file_name().to_string_lossy().starts_with(".install-")
                        && entry.path().is_dir()
                }),
            "temporary publication trees must be retired by their owner"
        );
    }

    pub(super) fn corrupt_identity(&self, version: &str) {
        use sha2::{Digest as _, Sha256};
        let root = self
            .versions
            .join(version)
            .canonicalize()
            .expect("published runtime root");
        let key = hex::encode(Sha256::digest(
            serde_json::to_vec(&root).expect("exact fixture destination"),
        ));
        std::fs::write(
            self.versions
                .join(".security")
                .join(format!("{key}.identity.json")),
            b"invalid publisher identity",
        )
        .expect("controlled publisher corruption");
    }
}

pub(super) fn mutation_security(versions: &std::path::Path) -> super::security::RuntimeSecurity {
    struct Mutation(std::path::PathBuf);
    impl super::security::RuntimeEvidenceSource for Mutation {
        fn read(&self, query: &super::security::RuntimeQuery) -> Result<Vec<u8>> {
            let stage = std::fs::read_dir(&self.0)
                .expect("inspect controlled mutation source root")
                .map(|entry| entry.expect("inspect only the controlled publication fixture"))
                .find(|entry| {
                    entry.file_name().to_string_lossy().starts_with(".install-")
                        && entry.path().is_dir()
                })
                .expect("mutation source may target only its owned staging directory");
            std::fs::write(
                stage.path().join("changed-after-content-review"),
                b"controlled concurrent change",
            )
            .expect("mutate only the controlled owned staging tree");
            Ok(super::security::fixture_runtime_report(query)
                .expect("encode controlled exact runtime evidence"))
        }
    }
    super::security::RuntimeSecurity::with_source(std::sync::Arc::new(Mutation(
        versions.to_path_buf(),
    )))
}

#[test]
fn publication_fixture_archives_reject_escaping_member_paths() {
    for (root, member) in [("runtime", "../outside"), ("", "absolute")] {
        assert!(tar_gz_entries(root, &[(member, b"controlled")]).is_err());
        assert!(tar_xz_entries(root, &[(member, b"controlled")]).is_err());
    }
}
