//! Static inspection of AUR package outputs before privilege elevation.
//!
//! Arch documents that PKGBUILDs are directly sourced and executed and that
//! package install scripts run around file extraction. Treat both the build
//! and the resulting archive as executable input:
//! https://man.archlinux.org/man/PKGBUILD.5
//! Package identity is cross-checked against Arch's documented BUILDINFO
//! fields: https://man.archlinux.org/man/BUILDINFO.5

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Component, Path};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::archive_metadata;

mod mtree;

const MAX_DECLARED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_MEMBERS: u64 = 100_000;
// Tar headers, padding, and extended metadata need room beyond member data.
const MAX_ARCHIVE_STREAM_BYTES: u64 = MAX_DECLARED_BYTES + MAX_MEMBERS * 1024;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PRIVILEGED_FILES: usize = 256;
const MAX_CAPABILITY_BYTES: usize = 8 * 1024;
const MAX_PRIVILEGE_METADATA_BYTES: usize = 64 * 1024;

pub(crate) const INSPECTION_POLICY_VERSION: u32 = 6;

// Loader roots include local administrator and volatile runtime locations.
// https://man.archlinux.org/man/systemd.generator.7
// https://man.archlinux.org/man/udev.7
// https://man.archlinux.org/man/tmpfiles.d.5
// https://man.archlinux.org/man/sysusers.d.5
// https://man.archlinux.org/man/modules-load.d.5
// https://man.archlinux.org/man/polkit.8
// https://man.archlinux.org/man/dbus-daemon.1
// https://man.archlinux.org/man/kernel-install.8
const PRIVILEGED_PATH_PREFIXES: &[(&str, &[&str])] = &[
    ("system-configuration", &["etc/"]),
    (
        "systemd-unit",
        &[
            "usr/lib/systemd/",
            "usr/local/lib/systemd/",
            "run/systemd/",
            "etc/systemd/",
        ],
    ),
    ("kernel-module", &["usr/lib/modules/", "lib/modules/"]),
    (
        "package-manager-hook",
        &["usr/share/libalpm/hooks/", "usr/share/libalpm/scripts/"],
    ),
    (
        "privileged-system-integration",
        &[
            "usr/lib/udev/rules.d/",
            "usr/local/lib/udev/rules.d/",
            "run/udev/rules.d/",
            "usr/lib/tmpfiles.d/",
            "usr/local/lib/tmpfiles.d/",
            "run/tmpfiles.d/",
            "usr/lib/sysusers.d/",
            "usr/local/lib/sysusers.d/",
            "run/sysusers.d/",
            "usr/lib/modules-load.d/",
            "usr/local/lib/modules-load.d/",
            "run/modules-load.d/",
            "usr/share/polkit-1/",
            "usr/local/share/polkit-1/",
            "run/polkit-1/",
            "usr/share/dbus-1/system-services/",
            "usr/local/share/dbus-1/system-services/",
            "run/dbus-1/system-services/",
            "lib/dbus-1/system-services/",
            "usr/share/dbus-1/system.d/",
            "usr/lib/kernel/install.d/",
            "usr/lib/kernel/install.conf.d/",
            "usr/local/lib/kernel/install.conf.d/",
            "run/kernel/install.conf.d/",
            "usr/lib/initcpio/",
            "usr/share/mkinitcpio/",
            "usr/lib/dracut/",
            "usr/lib/NetworkManager/dispatcher.d/",
        ],
    ),
];

const PRIVILEGED_EXACT_PATHS: &[(&str, &[&str])] = &[(
    "privileged-system-integration",
    &[
        "usr/lib/kernel/install.conf",
        "usr/local/lib/kernel/install.conf",
        "run/kernel/install.conf",
    ],
)];

#[derive(Debug, Default)]
struct PrivilegeMetadataBudget(usize);

impl PrivilegeMetadataBudget {
    fn reserve(&mut self, bytes: usize) -> Result<()> {
        let total = self
            .0
            .checked_add(bytes)
            .context("AUR privilege metadata size overflow")?;
        anyhow::ensure!(
            total <= MAX_PRIVILEGE_METADATA_BYTES,
            "AUR privilege metadata exceeds retained byte limit"
        );
        self.0 = total;
        Ok(())
    }

    fn encode_capability(&mut self, bytes: &[u8]) -> Result<String> {
        anyhow::ensure!(
            bytes.len() <= MAX_CAPABILITY_BYTES,
            "AUR privilege capability metadata exceeds per-attribute byte limit"
        );
        self.reserve(
            bytes
                .len()
                .checked_mul(2)
                .context("AUR privilege capability size overflow")?,
        )?;
        Ok(hex::encode(bytes))
    }
}

#[derive(Debug)]
pub(crate) struct ArchiveAdmission {
    inspection: ArtifactInspection,
    inventory: mtree::NativeInventory,
}

impl ArchiveAdmission {
    pub(crate) fn inspection(&self) -> &ArtifactInspection {
        &self.inspection
    }

    pub(crate) fn into_inspection(self) -> ArtifactInspection {
        self.inspection
    }

    pub(crate) fn verify_native_inventory(&self, files: &alpm::FileList<'_>) -> Result<()> {
        self.inventory.verify(files)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PrivilegedFile {
    pub path: String,
    pub mode: u32,
    pub capability: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ArtifactInspection {
    pub policy_version: u32,
    pub archive_sha256: String,
    pub package_name: String,
    pub package_version: String,
    pub package_base: String,
    pub architecture: String,
    pub member_count: u64,
    pub executable_files: Vec<String>,
    pub privileged_files: Vec<PrivilegedFile>,
    pub install_hook: Option<String>,
    pub paired_build_reasons: Vec<String>,
}

impl ArtifactInspection {
    pub(crate) fn enforce_profile(&self, profile: crate::config::AurSecurityProfile) -> Result<()> {
        if profile == crate::config::AurSecurityProfile::Hardened {
            anyhow::ensure!(
                !self.requires_paired_build(),
                "Hardened AUR profile rejects install hooks, set-ID files, capabilities, system configuration and privileged system integration in {}",
                crate::cli::style::sanitize_terminal_text(&self.package_name)
            );
        }
        Ok(())
    }

    pub(crate) fn requires_paired_build_for(
        &self,
        profile: crate::config::AurSecurityProfile,
    ) -> bool {
        profile == crate::config::AurSecurityProfile::Hardened || self.requires_paired_build()
    }

    pub(crate) fn requires_exception(&self) -> bool {
        self.install_hook.is_some() || !self.privileged_files.is_empty()
    }

    pub(crate) fn requires_paired_build(&self) -> bool {
        self.requires_exception() || !self.paired_build_reasons.is_empty()
    }

    pub(crate) fn audit_summary(&self) -> String {
        format!(
            "{} {} archive_sha256={} policy={} members={} hook={} privileged_files={} paired_build_reasons={}",
            self.package_name,
            self.package_version,
            self.archive_sha256,
            self.policy_version,
            self.member_count,
            self.install_hook.as_deref().unwrap_or("none"),
            self.privileged_files.len(),
            self.paired_build_reasons.join(",")
        )
    }

    pub(crate) fn audit_details(&self) -> Vec<String> {
        let mut details = vec![self.audit_summary()];
        for file in &self.privileged_files {
            details.push(format!(
                "privileged_path={} mode={:04o} capability={}",
                file.path,
                file.mode & 0o7777,
                file.capability.as_deref().unwrap_or("none")
            ));
        }
        details
    }
}

fn normalize_member_path(path: &Path, directory: bool) -> Result<String> {
    mtree::canonical_path(
        path.to_str()
            .context("non-UTF-8 path in AUR package archive")?,
        directory,
    )
}

fn archive_sha256(path: &Path) -> Result<String> {
    let mut input = BufReader::new(File::open(path)?);
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hex::encode(hash.finalize()))
}

fn archive_reader(path: &Path) -> Result<Box<dyn Read>> {
    archive_reader_with_limit(path, MAX_ARCHIVE_STREAM_BYTES)
}

fn archive_reader_with_limit(path: &Path, limit: u64) -> Result<Box<dyn Read>> {
    super::archive_reader::decode(File::open(path)?, limit)
}

fn validate_relative_link(member: &str, target: &Path, hard_link: bool) -> Result<()> {
    anyhow::ensure!(target.is_relative(), "absolute link target in AUR archive");
    let mut depth = if hard_link {
        0
    } else {
        Path::new(member)
            .parent()
            .map_or(0, |parent| parent.components().count())
    };
    for component in target.components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir if depth > 0 => depth -= 1,
            _ => anyhow::bail!("escaping link target in AUR archive: {member}"),
        }
    }
    anyhow::ensure!(depth > 0, "empty link target in AUR archive: {member}");
    Ok(())
}

fn parse_pkginfo(content: &str) -> Result<(String, String, String, String)> {
    let field = |name: &str| {
        content.lines().find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key.trim() == name).then(|| value.trim().to_owned())
        })
    };
    let name = field("pkgname").context("AUR archive .PKGINFO is missing pkgname")?;
    let version = field("pkgver").context("AUR archive .PKGINFO is missing pkgver")?;
    let base = field("pkgbase").unwrap_or_else(|| name.clone());
    let architecture = field("arch").context("AUR archive .PKGINFO is missing arch")?;
    crate::core::security::validate_package_name(&name)?;
    crate::core::security::validate_package_name(&base)?;
    crate::core::security::validate_version(&version)?;
    anyhow::ensure!(!architecture.is_empty(), "empty AUR package architecture");
    Ok((name, version, base, architecture))
}

fn parse_buildinfo(content: &str) -> Result<(String, String, String, String)> {
    let exactly_one = |name: &str| -> Result<String> {
        let values = content
            .lines()
            .filter_map(|line| {
                let (key, value) = line.split_once('=')?;
                (key.trim() == name).then(|| value.trim().to_owned())
            })
            .collect::<Vec<_>>();
        anyhow::ensure!(
            values.len() == 1,
            "AUR archive .BUILDINFO must contain one {name}"
        );
        Ok(values.into_iter().next().expect("length checked"))
    };
    let format = exactly_one("format")?;
    anyhow::ensure!(
        format.parse::<u32>().is_ok_and(|value| value > 0),
        "invalid AUR archive .BUILDINFO format"
    );
    Ok((
        exactly_one("pkgname")?,
        exactly_one("pkgver")?,
        exactly_one("pkgbase")?,
        exactly_one("pkgarch")?,
    ))
}

pub(crate) fn inspect_archive(path: &Path) -> Result<ArchiveAdmission> {
    let archive_sha256 = archive_sha256(path)?;
    archive_metadata::validate(archive_reader(path)?)?;
    let mut archive = tar::Archive::new(archive_reader(path)?);
    let mut member_count = 0_u64;
    let mut declared_bytes = 0_u64;
    let mut executable_files = Vec::new();
    let mut privileged_files = Vec::new();
    let mut privilege_metadata = PrivilegeMetadataBudget::default();
    let mut paired_build_reasons = BTreeSet::new();
    let mut install_hook = None;
    let mut pkginfo = None;
    let mut buildinfo = None;
    let mut mtree_bytes = None;
    let mut inventory = mtree::ArchiveInventory::default();

    for entry in archive.entries()? {
        let mut entry = entry?;
        member_count += 1;
        anyhow::ensure!(
            member_count <= MAX_MEMBERS,
            "AUR archive has too many members"
        );
        declared_bytes = declared_bytes
            .checked_add(entry.size())
            .context("AUR archive declared-size overflow")?;
        anyhow::ensure!(
            declared_bytes <= MAX_DECLARED_BYTES,
            "AUR archive exceeds declared-size limit"
        );

        let raw_path = entry.path()?;
        anyhow::ensure!(
            raw_path.as_os_str().len() <= MAX_PATH_BYTES,
            "AUR archive member path is too long"
        );
        let kind = entry.header().entry_type();
        let member = normalize_member_path(&raw_path, kind.is_dir())?;
        for (reason, prefixes) in PRIVILEGED_PATH_PREFIXES {
            if prefixes.iter().any(|prefix| member.starts_with(prefix)) {
                paired_build_reasons.insert((*reason).to_owned());
            }
        }
        for (reason, paths) in PRIVILEGED_EXACT_PATHS {
            if paths.contains(&member.as_str()) {
                paired_build_reasons.insert((*reason).to_owned());
            }
        }

        anyhow::ensure!(
            kind.is_file() || kind.is_dir() || kind.is_symlink() || kind.is_hard_link(),
            "special file in AUR archive: {member}"
        );
        let target = if kind.is_symlink() || kind.is_hard_link() {
            let target = entry
                .link_name()?
                .context("link without target in AUR archive")?;
            anyhow::ensure!(
                target.as_os_str().len() <= MAX_PATH_BYTES,
                "AUR archive link target is too long"
            );
            validate_relative_link(&member, &target, kind.is_hard_link())?;
            Some(target.into_owned())
        } else {
            None
        };

        let mode = entry.header().mode()?;
        let node = if kind.is_file() {
            mtree::TarNode::File {
                mode,
                size: entry.size(),
            }
        } else if kind.is_dir() {
            mtree::TarNode::Directory { mode }
        } else {
            let target = target
                .as_ref()
                .context("AUR archive link target is missing")?;
            let target = target
                .to_str()
                .context("non-UTF-8 AUR archive link target")?;
            if kind.is_symlink() {
                mtree::TarNode::Symlink {
                    mode,
                    target: target.to_owned(),
                }
            } else {
                mtree::TarNode::HardLink {
                    mode,
                    target: mtree::canonical_path(target, false)?,
                }
            }
        };
        inventory.add(member.clone(), node)?;
        let mut capability = None;
        if let Some(extensions) = entry.pax_extensions()? {
            for extension in extensions {
                let extension = extension?;
                if archive_metadata::attribute_name(extension.key_bytes()).as_deref()
                    == Some(b"security.capability".as_slice())
                {
                    capability =
                        Some(privilege_metadata.encode_capability(extension.value_bytes())?);
                }
            }
        }
        if kind.is_file() && mode & 0o111 != 0 {
            executable_files.push(member.clone());
        }
        if (kind.is_file() || kind.is_hard_link()) && mode & 0o6000 != 0 || capability.is_some() {
            // Linux documents set-ID and file capabilities as privilege-bearing
            // mechanisms: https://man7.org/linux/man-pages/man7/capabilities.7.html
            anyhow::ensure!(
                privileged_files.len() < MAX_PRIVILEGED_FILES,
                "AUR archive has too many privileged files"
            );
            privilege_metadata.reserve(member.len())?;
            privileged_files.push(PrivilegedFile {
                path: member.clone(),
                mode,
                capability,
            });
            paired_build_reasons.insert("privilege-bearing-file".to_owned());
        }

        if matches!(
            member.as_str(),
            ".PKGINFO" | ".BUILDINFO" | ".MTREE" | ".INSTALL"
        ) {
            anyhow::ensure!(
                kind.is_file(),
                "AUR metadata member is not a regular file: {member}"
            );
            anyhow::ensure!(
                entry.size() <= MAX_METADATA_BYTES,
                "AUR metadata member is too large"
            );
            let mut bytes = Vec::with_capacity(usize::try_from(entry.size())?);
            entry.take(MAX_METADATA_BYTES + 1).read_to_end(&mut bytes)?;
            anyhow::ensure!(
                bytes.len() as u64 <= MAX_METADATA_BYTES,
                "AUR metadata member is too large"
            );
            match member.as_str() {
                ".PKGINFO" => {
                    let content =
                        std::str::from_utf8(&bytes).context("AUR archive .PKGINFO is not UTF-8")?;
                    pkginfo = Some(parse_pkginfo(content)?);
                }
                ".BUILDINFO" => {
                    let content = std::str::from_utf8(&bytes)
                        .context("AUR archive .BUILDINFO is not UTF-8")?;
                    buildinfo = Some(parse_buildinfo(content)?);
                }
                ".MTREE" => mtree_bytes = Some(bytes),
                ".INSTALL" => {
                    install_hook = Some(hex::encode(Sha256::digest(&bytes)));
                    paired_build_reasons.insert("install-hook".to_owned());
                }
                _ => unreachable!(),
            }
        }
    }

    let (package_name, package_version, package_base, architecture) =
        pkginfo.context("AUR archive is missing .PKGINFO")?;
    let buildinfo = buildinfo.context("AUR archive is missing .BUILDINFO")?;
    anyhow::ensure!(
        buildinfo
            == (
                package_name.clone(),
                package_version.clone(),
                package_base.clone(),
                architecture.clone(),
            ),
        "AUR archive .BUILDINFO identity differs from .PKGINFO"
    );
    let inventory = inventory.agree(&mtree_bytes.context("AUR archive is missing .MTREE")?)?;
    executable_files.sort();
    privileged_files.sort_by(|left, right| left.path.cmp(&right.path));
    let inspection = ArtifactInspection {
        policy_version: INSPECTION_POLICY_VERSION,
        archive_sha256,
        package_name,
        package_version,
        package_base,
        architecture,
        member_count,
        executable_files,
        privileged_files,
        install_hook,
        paired_build_reasons: paired_build_reasons.into_iter().collect(),
    };
    Ok(ArchiveAdmission {
        inspection,
        inventory,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aur_archive_reader_accepts_sha256_checked_xz() -> Result<()> {
        let compressed = include_bytes!("../../../tests/data/xz-subset/single-block-sha256.tar.xz");
        let file = tempfile::NamedTempFile::new()?;
        std::fs::write(file.path(), compressed)?;
        let reader = archive_reader_with_limit(file.path(), 51200)?;
        let mut archive = tar::Archive::new(reader);
        let mut files = 0;
        for entry in archive.entries()? {
            let mut entry = entry?;
            if entry.header().entry_type().is_file() {
                let mut content = String::new();
                entry.read_to_string(&mut content)?;
                assert!(content.starts_with("omg xz fixture file"));
                files += 1;
            }
        }
        assert_eq!(files, 3);
        Ok(())
    }

    #[test]
    fn archive_reader_bounds_expansion_for_each_compression_format() -> Result<()> {
        let raw = vec![b'x'; 4096];
        let mut xz = Vec::new();
        lzma_rs::xz_compress(&mut std::io::Cursor::new(&raw), &mut xz)?;
        let mut gzip = Vec::new();
        {
            use std::io::Write as _;
            let mut encoder = flate2::write::GzEncoder::new(&mut gzip, flate2::Compression::fast());
            encoder.write_all(&raw)?;
            encoder.finish()?;
        }
        let zstd = zstd::stream::encode_all(&raw[..], 1)?;
        for (kind, compressed) in [
            ("xz", xz),
            ("gzip", gzip),
            ("zstd", zstd),
            ("raw", raw.clone()),
        ] {
            let file = tempfile::NamedTempFile::new()?;
            std::fs::write(file.path(), compressed)?;
            let rejected = archive_reader_with_limit(file.path(), 1024);
            let error = match rejected {
                Err(error) => format!("{error:#}"),
                Ok(mut reader) => {
                    let mut output = Vec::new();
                    reader
                        .read_to_end(&mut output)
                        .expect_err("expansion must be bounded")
                        .to_string()
                }
            };
            let expected = if kind == "xz" {
                "decompressed archive exceeds the 1024 byte limit"
            } else {
                "decompressed data exceeds the configured limit of 1024 bytes"
            };
            assert!(error.contains(expected), "{kind}: {error}");
            let mut accepted = Vec::new();
            archive_reader_with_limit(file.path(), 4096)?.read_to_end(&mut accepted)?;
            assert_eq!(accepted, raw, "{kind} ordinary archive stream must survive");
        }
        Ok(())
    }

    fn append_file(
        builder: &mut tar::Builder<flate2::write::GzEncoder<File>>,
        path: &str,
        bytes: &[u8],
        mode: u32,
    ) -> Result<()> {
        let mut header = tar::Header::new_gnu();
        header.set_path(path)?;
        header.set_size(bytes.len() as u64);
        header.set_mode(mode);
        header.set_cksum();
        builder.append(&header, bytes)?;
        Ok(())
    }

    fn fixture_archive(
        extra: impl FnOnce(&mut tar::Builder<flate2::write::GzEncoder<File>>) -> Result<()>,
    ) -> Result<tempfile::NamedTempFile> {
        fixture_archive_with_mtree(b"#mtree\n", extra)
    }

    fn fixture_archive_with_mtree(
        mtree: &[u8],
        extra: impl FnOnce(&mut tar::Builder<flate2::write::GzEncoder<File>>) -> Result<()>,
    ) -> Result<tempfile::NamedTempFile> {
        let file = tempfile::Builder::new().suffix(".pkg.tar.gz").tempfile()?;
        let output = file.reopen()?;
        let encoder = flate2::write::GzEncoder::new(output, flate2::Compression::fast());
        let mut builder = tar::Builder::new(encoder);
        append_file(
            &mut builder,
            ".PKGINFO",
            b"pkgname = demo\npkgbase = demo\npkgver = 1.0-1\narch = x86_64\n",
            0o644,
        )?;
        append_file(
            &mut builder,
            ".BUILDINFO",
            b"format = 2\npkgname = demo\npkgbase = demo\npkgver = 1.0-1\npkgarch = x86_64\n",
            0o644,
        )?;
        append_file(&mut builder, ".MTREE", mtree, 0o644)?;
        extra(&mut builder)?;
        builder.finish()?;
        Ok(file)
    }

    fn fixture_file_mtree(files: &[(&str, u32, usize)]) -> Vec<u8> {
        use std::fmt::Write as _;

        let mut text = "#mtree\n/set uid=0 gid=0 type=file\n".to_owned();
        for (path, mode, size) in files {
            writeln!(
                text,
                "./{path} mode={mode:o} size={size} time=0.0 sha256digest={}",
                "0".repeat(64)
            )
            .expect("writing fixture MTREE to a String cannot fail");
        }
        text.into_bytes()
    }

    #[test]
    fn archive_admission_rejects_mtree_inventory_disagreement() -> Result<()> {
        let digest = "0".repeat(64);
        for (case, declaration) in [
            ("missing", String::new()),
            (
                "ghost",
                format!("./usr/share/ghost type=file mode=644 size=4 sha256digest={digest}"),
            ),
            (
                "size",
                format!("./usr/share/marker type=file mode=644 size=5 sha256digest={digest}"),
            ),
            (
                "mode",
                format!("./usr/share/marker type=file mode=600 size=4 sha256digest={digest}"),
            ),
            ("type", "./usr/share/marker type=dir mode=644".to_owned()),
        ] {
            let mtree = if declaration.is_empty() {
                "#mtree\n".to_owned()
            } else {
                format!("#mtree\n/set uid=0 gid=0\n{declaration} time=0.0\n")
            };
            let file = fixture_archive_with_mtree(mtree.as_bytes(), |builder| {
                append_file(builder, "usr/share/marker", b"test", 0o644)
            })?;
            let result = inspect_archive(file.path());
            assert!(
                result.is_err(),
                "{case} MTREE inventory disagreement must be refused"
            );
        }
        Ok(())
    }

    #[test]
    fn archive_admission_accepts_complete_payload_inventory() -> Result<()> {
        let mtree = format!(
            "#mtree\n/set uid=0 gid=0\n./usr/share/marker type=file mode=644 size=4 time=0.0 sha256digest={}\n",
            "0".repeat(64)
        );
        let file = fixture_archive_with_mtree(mtree.as_bytes(), |builder| {
            append_file(builder, "usr/share/marker", b"test", 0o644)
        })?;
        inspect_archive(file.path())?;
        Ok(())
    }

    #[test]
    fn archive_admission_accepts_genuine_makepkg_links_and_native_inventory() -> Result<()> {
        let file = tempfile::Builder::new().suffix(".pkg.tar").tempfile()?;
        std::fs::write(
            file.path(),
            include_bytes!("../../../tests/data/mtree/makepkg-links.pkg.tar"),
        )
        .expect("genuine makepkg fixture is writable to the private archive");
        let admission = inspect_archive(file.path())?;
        assert_eq!(admission.inspection().package_name, "omg-mtree-probe");
        let root = tempfile::TempDir::new()?;
        let db = root.path().join("db");
        std::fs::create_dir(&db)?;
        let alpm = alpm::Alpm::new(
            root.path().to_str().context("fixture root is UTF-8")?,
            db.to_str().context("fixture database is UTF-8")?,
        )
        .expect("private native fixture database opens");
        let package = alpm
            .pkg_load(
                file.path().to_str().context("fixture archive is UTF-8")?,
                true,
                alpm::SigLevel::NONE,
            )
            .expect("native ALPM loads the genuine makepkg fixture");
        admission.verify_native_inventory(package.files())?;
        assert!(
            package
                .files()
                .files()
                .iter()
                .any(|file| file.name() == b"usr/share/omg-mtree-probe/hard-b")
        );
        assert!(
            package
                .files()
                .files()
                .iter()
                .any(|file| file.name() == b"usr/share/omg-mtree-probe/empty/")
        );
        Ok(())
    }

    #[test]
    fn member_paths_reject_absolute_parent_and_empty_paths() {
        assert!(normalize_member_path(Path::new("../../etc/shadow"), false).is_err());
        assert!(normalize_member_path(Path::new("/etc/shadow"), false).is_err());
        assert!(normalize_member_path(Path::new("."), false).is_err());
        assert!(normalize_member_path(Path::new("./usr/bin/demo"), false).is_err());
        assert!(normalize_member_path(Path::new("usr//bin/demo"), false).is_err());
        assert!(normalize_member_path(Path::new("usr/./bin/demo"), false).is_err());
        assert_eq!(
            normalize_member_path(Path::new("usr/bin/demo"), false).unwrap(),
            "usr/bin/demo"
        );
    }

    #[test]
    fn links_cannot_escape_the_archive_root() {
        assert!(validate_relative_link("usr/bin/demo", Path::new("../lib/demo"), false).is_ok());
        assert!(
            validate_relative_link("usr/bin/demo", Path::new("../../../etc/shadow"), false)
                .is_err()
        );
        assert!(validate_relative_link("usr/bin/demo", Path::new("/etc/shadow"), false).is_err());
        assert!(
            validate_relative_link("usr/bin/demo", Path::new("../../etc/shadow"), true).is_err()
        );
    }

    #[test]
    fn ambiguous_pax_metadata_is_rejected_before_native_installation() -> Result<()> {
        for attributes in [
            vec![
                ("path", b"usr/share/marker".as_slice()),
                ("path", b".INSTALL".as_slice()),
            ],
            vec![("path", b".INSTALL\0suffix".as_slice())],
            vec![("size", b"4".as_slice()), ("size", b"4".as_slice())],
            vec![("GNU.sparse.name", b".INSTALL".as_slice())],
        ] {
            let file = fixture_archive(|builder| {
                builder.append_pax_extensions(attributes.iter().copied())?;
                append_file(builder, "usr/share/marker", b"test", 0o644)
            })?;
            assert!(
                inspect_archive(file.path()).is_err(),
                "ambiguous attributes: {attributes:?}"
            );
        }
        let file = fixture_archive(|builder| {
            builder.append_pax_extensions([
                ("linkpath", b"usr/share/marker".as_slice()),
                ("linkpath", b"../../outside".as_slice()),
            ])?;
            let mut header = tar::Header::new_gnu();
            header.set_path("usr/share/alias")?;
            header.set_link_name("usr/share/marker")?;
            header.set_entry_type(tar::EntryType::Link);
            header.set_size(0);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, std::io::empty())?;
            Ok(())
        })?;
        assert!(inspect_archive(file.path()).is_err());
        Ok(())
    }

    #[test]
    fn mixed_gnu_and_pax_paths_cannot_hide_an_install_hook() -> Result<()> {
        let file = fixture_archive(|builder| {
            let bytes = b"usr/share/marker\0";
            let mut header = tar::Header::new_gnu();
            header.set_path("././@LongLink")?;
            header.set_entry_type(tar::EntryType::GNULongName);
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, bytes.as_slice())?;
            builder.append_pax_extensions([("path", b".INSTALL".as_slice())])?;
            append_file(builder, "usr/share/marker", b"test", 0o644)
        })?;
        assert!(inspect_archive(file.path()).is_err());
        Ok(())
    }

    #[test]
    fn gnu_longlinks_are_inspected_and_cannot_mix_with_pax() -> Result<()> {
        for mixed in [false, true] {
            let mtree = fixture_file_mtree(&[
                ("usr/share/marker", 0o644, b"inert marker".len()),
                ("usr/share/alias", 0o644, b"inert marker".len()),
            ]);
            let file = fixture_archive_with_mtree(&mtree, |builder| {
                append_file(builder, "usr/share/marker", b"inert marker", 0o644)?;
                let target = b"usr/share/marker\0";
                let mut extension = tar::Header::new_gnu();
                extension.set_path("././@LongLink")?;
                extension.set_entry_type(tar::EntryType::GNULongLink);
                extension.set_size(target.len() as u64);
                extension.set_mode(0o644);
                extension.set_cksum();
                builder.append(&extension, target.as_slice())?;
                if mixed {
                    builder
                        .append_pax_extensions([("linkpath", b"usr/share/marker".as_slice())])?;
                }
                let mut link = tar::Header::new_gnu();
                link.set_path("usr/share/alias")?;
                link.set_link_name("placeholder")?;
                link.set_entry_type(tar::EntryType::Link);
                link.set_size(0);
                link.set_mode(0o644);
                link.set_cksum();
                builder.append(&link, std::io::empty())?;
                Ok(())
            })?;
            let inspection = inspect_archive(file.path());
            if mixed {
                let error = inspection.expect_err("mixed GNU/PAX link metadata must be refused");
                assert!(
                    error.to_string().contains("Duplicate or mixed GNU/PAX"),
                    "{error}"
                );
            } else {
                let inspection = inspection?.into_inspection();
                assert_eq!(inspection.member_count, 5);
                assert!(!inspection.requires_exception());
            }
        }
        Ok(())
    }

    #[test]
    fn hardlinks_cannot_carry_data_or_unclassified_privilege_metadata() -> Result<()> {
        for data in [b"".as_slice(), b"harmless marker data".as_slice()] {
            let mtree = fixture_file_mtree(&[
                ("usr/share/marker", 0o4755, 4),
                ("usr/share/alias", 0o4755, 4),
            ]);
            let file = fixture_archive_with_mtree(&mtree, |builder| {
                append_file(builder, "usr/share/marker", b"test", 0o4755)?;
                builder.append_pax_extensions([("comment", b"inert".as_slice())])?;
                let mut header = tar::Header::new_gnu();
                header.set_path("usr/share/alias")?;
                header.set_link_name("usr/share/marker")?;
                header.set_entry_type(tar::EntryType::Link);
                header.set_size(data.len() as u64);
                header.set_mode(0o4755);
                header.set_cksum();
                builder.append(&header, data)?;
                Ok(())
            })?;
            if data.is_empty() {
                assert!(
                    inspect_archive(file.path())?
                        .inspection()
                        .requires_exception(),
                    "link privilege metadata must be classified"
                );
            } else {
                assert!(
                    inspect_archive(file.path()).is_err(),
                    "hardlink data must be refused"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn oversized_capability_metadata_is_refused_before_retention() {
        assert_capability_metadata_refused(1, 65_537);
    }

    #[test]
    fn aggregate_capability_metadata_is_refused_before_retention() {
        assert_capability_metadata_refused(256, 256);
    }

    #[test]
    fn capability_retention_limits_include_exact_boundary_and_path_bytes() {
        let single = fixture_file_mtree(&[("usr/bin/marker", 0o755, 4)]);
        let raw = vec![b'x'; MAX_CAPABILITY_BYTES];
        let file = fixture_archive_with_mtree(&single, |builder| {
            builder
                .append_pax_extensions([("SCHILY.xattr.security.capability", raw.as_slice())])
                .expect("private capability fixture");
            append_file(builder, "usr/bin/marker", b"data", 0o755)
        })
        .expect("private capability archive");
        let inspection = inspect_archive(file.path())
            .expect("capability at per-attribute limit")
            .into_inspection();
        assert_eq!(
            inspection.privileged_files[0].capability.as_deref(),
            Some(hex::encode(&raw).as_str())
        );
        assert_capability_metadata_refused(1, MAX_CAPABILITY_BYTES + 1);

        for extra_path_byte in [false, true] {
            let mut names = (0..4)
                .map(|i| format!("usr/bin/marker-{i}"))
                .collect::<Vec<_>>();
            let path_bytes = names.iter().map(String::len).sum::<usize>();
            let last_size =
                (MAX_PRIVILEGE_METADATA_BYTES - path_bytes - 6 * MAX_CAPABILITY_BYTES) / 2;
            assert_eq!(
                path_bytes + 6 * MAX_CAPABILITY_BYTES + 2 * last_size,
                MAX_PRIVILEGE_METADATA_BYTES
            );
            if extra_path_byte {
                names[3].push('x');
            }
            let records = names
                .iter()
                .map(|name| (name.as_str(), 0o755, 4))
                .collect::<Vec<_>>();
            let mtree = fixture_file_mtree(&records);
            let file = fixture_archive_with_mtree(&mtree, |builder| {
                for (index, name) in names.iter().enumerate() {
                    let capability = vec![
                        b'x';
                        if index == 3 {
                            last_size
                        } else {
                            MAX_CAPABILITY_BYTES
                        }
                    ];
                    builder
                        .append_pax_extensions([(
                            "SCHILY.xattr.security.capability",
                            capability.as_slice(),
                        )])
                        .expect("private aggregate capability fixture");
                    append_file(builder, name, b"data", 0o755)
                        .expect("private aggregate fixture payload");
                }
                Ok(())
            })
            .expect("private aggregate capability archive");
            let admitted = inspect_archive(file.path());
            if extra_path_byte {
                let error = admitted.expect_err("one retained path byte over the aggregate limit");
                assert!(
                    error
                        .to_string()
                        .contains("privilege metadata exceeds retained byte limit")
                );
            } else {
                let inspection = admitted
                    .expect("exact retained metadata byte limit")
                    .into_inspection();
                assert_eq!(inspection.privileged_files.len(), 4);
                let bytes = inspection
                    .privileged_files
                    .iter()
                    .map(|file| {
                        file.path.len()
                            + file.capability.as_ref().expect("fixture capability").len()
                    })
                    .sum::<usize>();
                assert_eq!(bytes, MAX_PRIVILEGE_METADATA_BYTES);
            }
        }
    }

    fn assert_capability_metadata_refused(file_count: usize, capability_bytes: usize) {
        let names = (0..file_count)
            .map(|index| format!("usr/bin/marker-{index}"))
            .collect::<Vec<_>>();
        let records = names
            .iter()
            .map(|name| (name.as_str(), 0o755, 4))
            .collect::<Vec<_>>();
        let mtree = fixture_file_mtree(&records);
        let capability = vec![b'x'; capability_bytes];
        let file = fixture_archive_with_mtree(&mtree, |builder| {
            for name in &names {
                builder
                    .append_pax_extensions([(
                        "SCHILY.xattr.security.capability",
                        capability.as_slice(),
                    )])
                    .expect("private fixture capability metadata is writable");
                append_file(builder, name, b"data", 0o755)
                    .expect("private fixture payload is writable");
            }
            Ok(())
        })
        .expect("bounded inert privilege metadata fixture is writable");
        match inspect_archive(file.path()) {
            Err(error) => {
                let diagnostic = format!("{error:#}");
                assert!(
                    diagnostic.contains("privilege")
                        && (diagnostic.contains("limit") || diagnostic.contains("budget")),
                    "refusal must reach the privilege metadata budget: {diagnostic}"
                );
            }
            Ok(admission) => {
                let retained = admission
                    .inspection()
                    .privileged_files
                    .iter()
                    .filter_map(|file| file.capability.as_ref())
                    .map(String::len)
                    .sum::<usize>();
                panic!(
                    "accepted {retained} encoded capability bytes across {file_count} privileged files"
                );
            }
        }
    }

    #[test]
    fn native_capability_attribute_encodings_cannot_bypass_classification() -> Result<()> {
        for key in [
            "SCHILY.xattr.security.capability",
            "LIBARCHIVE.xattr.security.capability",
            "LIBARCHIVE.xattr.security%2Ecapability",
            "LIBARCHIVE.xattr.security.%63apability",
        ] {
            let mtree = fixture_file_mtree(&[("usr/bin/marker", 0o755, 5)]);
            let file = fixture_archive_with_mtree(&mtree, |builder| {
                builder.append_pax_extensions([(key, b"AQAAAA==".as_slice())])?;
                append_file(builder, "usr/bin/marker", b"inert", 0o755)
            })?;
            assert!(
                inspect_archive(file.path())?
                    .inspection()
                    .requires_exception(),
                "{key}"
            );
        }
        for key in [
            "SCHILY.xattr.security.capability\0suffix",
            "LIBARCHIVE.xattr.security.capability%00suffix",
        ] {
            let file = fixture_archive(|builder| {
                builder.append_pax_extensions([(key, b"AQAAAA==".as_slice())])?;
                append_file(builder, "usr/bin/marker", b"inert", 0o755)
            })?;
            assert!(inspect_archive(file.path()).is_err());
        }
        Ok(())
    }

    #[test]
    fn ordinary_pax_metadata_and_literal_attributes_remain_accepted() -> Result<()> {
        let mtree = fixture_file_mtree(&[("usr/share/marker", 0o644, 5)]);
        let file = fixture_archive_with_mtree(&mtree, |builder| {
            builder.append_pax_extensions([
                ("path", b"usr/share/marker".as_slice()),
                ("size", b"5".as_slice()),
                ("SCHILY.xattr.user.note", b"inert".as_slice()),
            ])?;
            append_file(builder, "marker", b"inert", 0o644)
        })?;
        let inspection = inspect_archive(file.path())?.into_inspection();
        assert!(!inspection.requires_exception());
        assert_eq!(inspection.member_count, 4);
        Ok(())
    }

    #[test]
    fn attribute_aliases_and_inconsistent_sizes_are_rejected() -> Result<()> {
        for attributes in [
            vec![
                ("SCHILY.xattr.user.note", b"inert".as_slice()),
                ("LIBARCHIVE.xattr.user.note", b"inert".as_slice()),
            ],
            vec![("size", b"4".as_slice())],
        ] {
            let file = fixture_archive(|builder| {
                builder.append_pax_extensions(attributes.iter().copied())?;
                append_file(builder, "usr/share/marker", b"inert", 0o644)
            })?;
            assert!(inspect_archive(file.path()).is_err());
        }
        Ok(())
    }

    fn inspect_concatenated_compression_frames(kind: &str) -> Result<()> {
        let mtree = fixture_file_mtree(&[
            ("usr/share/first-marker", 0o644, 5),
            ("usr/share/second-marker", 0o644, 5),
        ]);
        let prefix = fixture_archive_with_mtree(&mtree, |builder| {
            append_file(builder, "usr/share/first-marker", b"inert", 0o644)
        })?;
        let mut raw = Vec::new();
        flate2::read::MultiGzDecoder::new(prefix.reopen()?).read_to_end(&mut raw)?;
        while raw.ends_with(&[0; 512]) {
            raw.truncate(raw.len() - 512);
        }
        let mut suffix = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_path("usr/share/second-marker")?;
        header.set_mode(0o644);
        header.set_size(5);
        header.set_cksum();
        suffix.append(&header, b"inert".as_slice())?;
        let suffix = suffix.into_inner()?;
        let mut compressed = Vec::new();
        for frame in [raw.as_slice(), suffix.as_slice()] {
            if kind == "zstd" {
                compressed.extend(zstd::stream::encode_all(frame, 1)?);
            } else {
                use std::io::Write as _;
                let mut encoder =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
                encoder.write_all(frame)?;
                compressed.extend(encoder.finish()?);
            }
        }
        let file = tempfile::NamedTempFile::new()?;
        std::fs::write(file.path(), compressed)?;
        assert_eq!(
            inspect_archive(file.path())?.inspection().member_count,
            5,
            "{kind}: every frame must be inspected"
        );
        Ok(())
    }

    #[test]
    fn every_zstd_frame_is_inspected() -> Result<()> {
        inspect_concatenated_compression_frames("zstd")
    }

    #[test]
    fn every_gzip_member_is_inspected() -> Result<()> {
        inspect_concatenated_compression_frames("gzip")
    }

    #[test]
    fn buildinfo_requires_one_complete_identity() {
        let valid =
            "format = 2\npkgname = demo\npkgbase = demo\npkgver = 1.0-1\npkgarch = x86_64\n";
        assert_eq!(
            parse_buildinfo(valid).unwrap(),
            (
                "demo".to_owned(),
                "1.0-1".to_owned(),
                "demo".to_owned(),
                "x86_64".to_owned()
            )
        );
        assert!(parse_buildinfo(&format!("{valid}pkgname = substitute\n")).is_err());
        assert!(parse_buildinfo("format = 2\npkgname = demo\n").is_err());
        for (field, value) in [
            ("format", "2"),
            ("pkgname", "demo"),
            ("pkgver", "1.0-1"),
            ("pkgbase", "demo"),
            ("pkgarch", "x86_64"),
        ] {
            let error = parse_buildinfo(&format!("{valid}{field} = {value}\n"))
                .expect_err("duplicate identity field must be rejected");
            assert_eq!(
                error.to_string(),
                format!("AUR archive .BUILDINFO must contain one {field}")
            );
        }
    }

    #[test]
    fn hardened_profile_refuses_every_system_generator_search_root() -> Result<()> {
        use crate::config::AurSecurityProfile::{Hardened, Standard};
        let mut admitted = Vec::new();
        for root in ["usr/lib", "usr/local/lib", "run", "etc"] {
            let path = format!("{root}/systemd/system-generators/omg-inert-marker");
            let mtree = fixture_file_mtree(&[(&path, 0o755, 5)]);
            let file = fixture_archive_with_mtree(&mtree, |builder| {
                append_file(builder, &path, b"inert", 0o755)
            })?;
            let inspection = inspect_archive(file.path())?.into_inspection();
            assert!(inspection.executable_files.contains(&path));
            assert!(inspection.enforce_profile(Standard).is_ok());
            if inspection.enforce_profile(Hardened).is_ok() {
                admitted.push(path);
            }
        }
        assert!(
            admitted.is_empty(),
            "Hardened accepted system generator paths: {admitted:?}"
        );
        Ok(())
    }

    #[test]
    fn hardened_profile_refuses_local_and_runtime_privileged_loader_aliases() -> Result<()> {
        use crate::config::AurSecurityProfile::{Hardened, Standard};
        let mut admitted = Vec::new();
        for path in [
            "usr/local/lib/udev/rules.d/marker.rules",
            "run/udev/rules.d/marker.rules",
            "usr/local/lib/tmpfiles.d/marker.conf",
            "run/tmpfiles.d/marker.conf",
            "usr/local/lib/sysusers.d/marker.conf",
            "run/sysusers.d/marker.conf",
            "usr/local/lib/modules-load.d/marker.conf",
            "run/modules-load.d/marker.conf",
            "usr/local/share/polkit-1/actions/marker.policy",
            "run/polkit-1/rules.d/marker.rules",
            "usr/local/share/dbus-1/system-services/marker.service",
            "run/dbus-1/system-services/marker.service",
            "lib/dbus-1/system-services/marker.service",
            "usr/lib/kernel/install.conf",
            "usr/local/lib/kernel/install.conf",
            "run/kernel/install.conf",
            "usr/lib/kernel/install.conf.d/marker.conf",
            "usr/local/lib/kernel/install.conf.d/marker.conf",
            "run/kernel/install.conf.d/marker.conf",
        ] {
            let mtree = fixture_file_mtree(&[(path, 0o644, 5)]);
            let file = fixture_archive_with_mtree(&mtree, |builder| {
                append_file(builder, path, b"inert", 0o644)
            })?;
            let inspection = inspect_archive(file.path())?.into_inspection();
            assert!(inspection.enforce_profile(Standard).is_ok());
            if inspection.enforce_profile(Hardened).is_ok() {
                admitted.push(path);
            }
        }
        assert!(
            admitted.is_empty(),
            "Hardened accepted privileged loader aliases: {admitted:?}"
        );
        Ok(())
    }

    #[test]
    fn hardened_profile_keeps_ordinary_local_paths_and_prefix_neighbors_eligible() -> Result<()> {
        use crate::config::AurSecurityProfile::{Hardened, Standard};
        for path in [
            "usr/local/bin/marker",
            "usr/local/lib/example/marker",
            "run/example/marker",
            "usr/local/lib/systemd-neighbor/marker",
            "run/systemd-neighbor/marker",
            "usr/local/share/polkit-10/marker",
            "usr/local/share/dbus-1/system-services-backup/marker",
            "usr/lib/kernel/install.conf.keep",
        ] {
            let mtree = fixture_file_mtree(&[(path, 0o644, 5)]);
            let file = fixture_archive_with_mtree(&mtree, |builder| {
                append_file(builder, path, b"inert", 0o644)
            })?;
            let inspection = inspect_archive(file.path())?.into_inspection();
            assert!(inspection.enforce_profile(Hardened).is_ok(), "{path}");
            assert!(!inspection.requires_paired_build_for(Standard), "{path}");
        }
        Ok(())
    }

    #[test]
    fn hardened_profile_refuses_privileged_integration_and_pairs_ordinary_outputs() -> Result<()> {
        use crate::config::AurSecurityProfile::{Hardened, Standard};
        for path in [
            "usr/bin/demo",
            "etc/demo.conf",
            "usr/lib/systemd/system/demo.service",
            "usr/share/libalpm/hooks/demo.hook",
            "usr/share/polkit-1/actions/demo.policy",
            ".INSTALL",
        ] {
            let mtree = fixture_file_mtree(&[(path, 0o644, 5)]);
            let file = fixture_archive_with_mtree(&mtree, |builder| {
                append_file(builder, path, b"inert", 0o644)
            })?;
            let inspection = inspect_archive(file.path())?.into_inspection();
            assert!(inspection.enforce_profile(Standard).is_ok());
            assert_eq!(
                inspection.enforce_profile(Hardened).is_ok(),
                path == "usr/bin/demo",
                "{path}"
            );
            assert!(inspection.requires_paired_build_for(Hardened));
        }
        Ok(())
    }

    #[test]
    fn exceptional_contents_require_separate_approval() {
        let ordinary = ArtifactInspection {
            policy_version: INSPECTION_POLICY_VERSION,
            archive_sha256: "0".repeat(64),
            package_name: "demo".into(),
            package_version: "1-1".into(),
            package_base: "demo".into(),
            architecture: "x86_64".into(),
            member_count: 1,
            executable_files: Vec::new(),
            privileged_files: Vec::new(),
            install_hook: None,
            paired_build_reasons: Vec::new(),
        };
        assert!(!ordinary.requires_exception());

        let mut privileged = ordinary;
        privileged.privileged_files.push(PrivilegedFile {
            path: "usr/bin/demo".into(),
            mode: 0o4755,
            capability: None,
        });
        assert!(privileged.requires_exception());
        assert!(privileged.requires_paired_build());
        assert!(
            privileged
                .audit_details()
                .iter()
                .any(|detail| detail.contains("privileged_path=usr/bin/demo mode=4755"))
        );
    }

    #[test]
    fn inspector_classifies_install_hook_and_setuid_file() -> Result<()> {
        let mtree = fixture_file_mtree(&[("usr/bin/demo", 0o4755, 6)]);
        let archive = fixture_archive_with_mtree(&mtree, |builder| {
            append_file(builder, ".INSTALL", b"post_install() { :; }\n", 0o644)?;
            append_file(builder, "usr/bin/demo", b"binary", 0o4755)
        })?;
        let inspection = inspect_archive(archive.path())?.into_inspection();
        assert_eq!(inspection.package_name, "demo");
        assert!(inspection.install_hook.is_some());
        assert_eq!(inspection.privileged_files.len(), 1);
        assert_eq!(inspection.privileged_files[0].path, "usr/bin/demo");
        assert!(inspection.requires_exception());
        assert!(inspection.requires_paired_build());
        Ok(())
    }

    #[test]
    fn inspector_requires_paired_build_for_system_integration_payloads() -> Result<()> {
        for (path, reason) in [
            ("etc/demo.conf", "system-configuration"),
            ("usr/lib/systemd/system/demo.service", "systemd-unit"),
            ("usr/lib/modules/6.0/extra/demo.ko", "kernel-module"),
            ("usr/share/libalpm/hooks/demo.hook", "package-manager-hook"),
            (
                "usr/lib/udev/rules.d/50-demo.rules",
                "privileged-system-integration",
            ),
        ] {
            let mtree = fixture_file_mtree(&[(path, 0o644, 7)]);
            let archive = fixture_archive_with_mtree(&mtree, |builder| {
                append_file(builder, path, b"payload", 0o644)
            })?;
            let inspection = inspect_archive(archive.path())?.into_inspection();
            assert!(inspection.requires_paired_build());
            assert!(
                inspection
                    .paired_build_reasons
                    .iter()
                    .any(|item| item == reason)
            );
        }
        Ok(())
    }

    #[test]
    fn inspector_rejects_special_files_and_duplicate_paths() -> Result<()> {
        let special = fixture_archive(|builder| {
            let mut header = tar::Header::new_gnu();
            header.set_path("dev/evil")?;
            header.set_size(0);
            header.set_mode(0o600);
            header.set_entry_type(tar::EntryType::Char);
            header.set_cksum();
            builder.append(&header, std::io::empty())?;
            Ok(())
        })?;
        assert!(
            inspect_archive(special.path())
                .expect_err("device entry must be rejected")
                .to_string()
                .contains("special file")
        );

        let duplicate = fixture_archive(|builder| {
            append_file(builder, "usr/share/demo", b"one", 0o644)?;
            append_file(builder, "usr/share/demo", b"two", 0o644)
        })?;
        assert!(
            inspect_archive(duplicate.path())
                .expect_err("duplicate path must be rejected")
                .to_string()
                .contains("duplicate normalized path")
        );
        Ok(())
    }
}
