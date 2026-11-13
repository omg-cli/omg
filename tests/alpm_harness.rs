//! ALPM Test Harness
//!
//! Provides a fully isolated pacman/alpm environment for testing.
//!
//! # Note
//! This module is used across multiple test files. The `dead_code` warnings
//! are suppressed because the harness is only used in integration tests.

#![cfg(feature = "arch")]
#![allow(clippy::doc_markdown)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use alpm::Alpm;
use anyhow::Result;
use flate2::Compression;
use flate2::write::GzEncoder;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use tar::{Builder, EntryType, Header};
use tempfile::{TempDir, tempdir};

#[derive(Clone)]
pub struct HarnessPkg {
    pub name: String,
    pub version: String,
    pub desc: String,
}

impl HarnessPkg {
    pub fn new(name: &str, version: &str) -> Self {
        Self {
            name: name.to_string(),
            version: version.to_string(),
            desc: generate_desc(name, version),
        }
    }
}

pub struct AlpmHarness {
    _temp_dir: TempDir,
    root_path: PathBuf,
    db_path: PathBuf,
}

impl AlpmHarness {
    pub fn new() -> Result<Self> {
        let temp_dir = tempdir()?;
        let root = temp_dir.path();

        let harness = Self {
            root_path: root.to_path_buf(),
            db_path: root.join("var/lib/pacman"),
            _temp_dir: temp_dir,
        };

        harness.create_fs_layout()?;
        Ok(harness)
    }

    fn create_fs_layout(&self) -> Result<()> {
        fs::create_dir_all(&self.db_path)?;
        fs::create_dir_all(self.root_path.join("var/cache/pacman/pkg"))?;
        fs::create_dir_all(self.root_path.join("etc/pacman.d/gnupg"))?;
        fs::create_dir_all(self.db_path.join("local"))?;
        fs::create_dir_all(self.db_path.join("sync"))?;
        fs::write(self.db_path.join("local/ALPM_DB_VERSION"), "9\n")?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn alpm(&self) -> Result<Alpm> {
        let alpm = Alpm::new(
            self.root_path.to_str().unwrap(),
            self.db_path.to_str().unwrap(),
        )?;
        Ok(alpm)
    }

    pub fn add_sync_pkg(&self, db_name: &str, pkg: &HarnessPkg) -> Result<()> {
        self.add_sync_pkgs(db_name, std::slice::from_ref(pkg))
    }

    pub fn add_sync_pkgs(&self, db_name: &str, pkgs: &[HarnessPkg]) -> Result<()> {
        let db_path = self.db_path.join("sync").join(format!("{}.db", db_name));
        anyhow::ensure!(
            !db_path.exists(),
            "Sync database '{db_name}' already exists; add all of its packages in one call"
        );
        let file = File::create(&db_path)?;
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = Builder::new(encoder);

        for pkg in pkgs {
            let pkg_dir = format!("{}-{}/", pkg.name, pkg.version);

            let mut dir_header = Header::new_gnu();
            dir_header.set_path(&pkg_dir)?;
            dir_header.set_size(0);
            dir_header.set_entry_type(EntryType::Directory);
            dir_header.set_mode(0o755);
            dir_header.set_mtime(0);
            dir_header.set_uid(0);
            dir_header.set_gid(0);
            dir_header.set_cksum();
            builder.append(&dir_header, &mut std::io::empty())?;

            let filename = format!("{}-{}-x86_64.pkg.tar.zst", pkg.name, pkg.version);
            let package_desc = if pkg.desc.starts_with('%') {
                pkg.desc.clone()
            } else {
                generate_desc(&pkg.name, &pkg.version).replace("A test package", &pkg.desc)
            };
            let packager = if package_desc.contains("%PACKAGER%\n") {
                ""
            } else {
                "%PACKAGER%\nFixture Maintainer <fixture@example.invalid>\n\n"
            };
            let desc = format!(
                "%FILENAME%\n{filename}\n\n%CSIZE%\n1\n\n%ISIZE%\n1\n\n{packager}{package_desc}"
            );
            let mut file_header = Header::new_gnu();
            file_header.set_path(format!("{}desc", pkg_dir))?;
            file_header.set_size(desc.len() as u64);
            file_header.set_entry_type(EntryType::Regular);
            file_header.set_mode(0o644);
            file_header.set_mtime(0);
            file_header.set_uid(0);
            file_header.set_gid(0);
            file_header.set_cksum();
            builder.append(&file_header, desc.as_bytes())?;
        }

        builder.into_inner()?.finish()?;
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root_path
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Add a sync package backed by a placeholder payload in the harness
    /// cache, with `%CSIZE%` and `%ISIZE%` matching that payload. Both this and
    /// [`Self::add_sync_pkg`] support transaction preparation; use this form
    /// when a test also depends on a cached package artifact or realistic sizes.
    /// Commit still needs a configured sync server, which the harness does not
    /// provide.
    pub fn add_installable_sync_pkg(&self, db_name: &str, pkg: &HarnessPkg) -> Result<()> {
        let filename = format!("{}-{}-x86_64.pkg.tar.gz", pkg.name, pkg.version);
        let pkg_path = self.root_path.join("var/cache/pacman/pkg").join(&filename);
        let csize = write_placeholder_package(&pkg_path, &pkg.name, &pkg.version)?;
        let isize_ = csize + 4096;

        let desc = format!(
            "%FILENAME%\n{filename}\n\n%NAME%\n{}\n\n%VERSION%\n{}\n\n%DESC%\n{}\n\n%ARCH%\nx86_64\n\n%PACKAGER%\nFixture Maintainer <fixture@example.invalid>\n\n%CSIZE%\n{csize}\n\n%ISIZE%\n{isize_}\n\n",
            pkg.name, pkg.version, pkg.desc
        );

        let db_file = self.db_path.join("sync").join(format!("{db_name}.db"));
        let file = File::create(db_file)?;
        let mut encoder = GzEncoder::new(file, Compression::default());
        {
            let mut builder = Builder::new(&mut encoder);
            let dir = format!("{}-{}/", pkg.name, pkg.version);
            let mut header = Header::new_gnu();
            header.set_path(&dir)?;
            header.set_size(0);
            header.set_entry_type(EntryType::Directory);
            header.set_mode(0o755);
            header.set_mtime(0);
            header.set_uid(0);
            header.set_gid(0);
            header.set_cksum();
            builder.append(&header, &mut std::io::empty())?;

            let mut header = Header::new_gnu();
            header.set_path(format!("{dir}desc"))?;
            header.set_size(desc.len() as u64);
            header.set_entry_type(EntryType::Regular);
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_uid(0);
            header.set_gid(0);
            header.set_cksum();
            builder.append(&header, desc.as_bytes())?;
            builder.finish()?;
        }
        encoder.finish()?;
        Ok(())
    }
}

/// Write a minimal gzip-compressed tar with one placeholder binary and return
/// its compressed size on disk.
fn write_placeholder_package(path: &Path, name: &str, version: &str) -> std::io::Result<u64> {
    let file = File::create(path)?;
    let mut encoder = GzEncoder::new(file, Compression::default());
    {
        let mut builder = Builder::new(&mut encoder);
        for dir in ["usr/", "usr/bin/"] {
            let mut header = Header::new_gnu();
            header.set_path(dir)?;
            header.set_size(0);
            header.set_entry_type(EntryType::Directory);
            header.set_mode(0o755);
            header.set_mtime(0);
            header.set_cksum();
            builder.append(&header, &mut std::io::empty())?;
        }
        let content = format!("#!/bin/sh\necho {name}-{version}\n");
        let mut header = Header::new_gnu();
        header.set_path(format!("usr/bin/{name}"))?;
        header.set_size(content.len() as u64);
        header.set_mode(0o755);
        header.set_mtime(0);
        header.set_cksum();
        builder.append(&header, content.as_bytes())?;
        builder.finish()?;
    }
    let file = encoder.finish()?;
    Ok(file.metadata()?.len())
}

pub fn generate_desc(name: &str, version: &str) -> String {
    format!(
        "%NAME%\n{}\n\n%VERSION%\n{}\n\n%DESC%\nA test package\n\n%ARCH%\nx86_64\n\n%PACKAGER%\nFixture Maintainer <fixture@example.invalid>\n\n",
        name, version
    )
}
