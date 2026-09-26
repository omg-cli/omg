//! Static inspection of AUR package outputs before privilege elevation.
//!
//! Arch documents that PKGBUILDs are directly sourced and executed and that
//! package install scripts run around file extraction. Treat both the build
//! and the resulting archive as executable input:
//! https://man.archlinux.org/man/PKGBUILD.5
//! Package identity is cross-checked against Arch's documented BUILDINFO
//! fields: https://man.archlinux.org/man/BUILDINFO.5

use std::collections::{BTreeSet, HashSet};
use std::fs::File;
use std::io::{BufReader, Read, Seek};
use std::path::{Component, Path};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::runtimes::common::{BudgetedReader, BudgetedWriter, decode_xz_to};

const MAX_DECLARED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_MEMBERS: u64 = 100_000;
// Tar headers, padding, and extended metadata need room beyond member data.
const MAX_ARCHIVE_STREAM_BYTES: u64 = MAX_DECLARED_BYTES + MAX_MEMBERS * 1024;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PRIVILEGED_FILES: usize = 256;

pub(crate) const INSPECTION_POLICY_VERSION: u32 = 2;

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

fn normalize_member_path(path: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(
                part.to_str()
                    .context("non-UTF-8 path in AUR package archive")?,
            ),
            Component::CurDir => {}
            _ => anyhow::bail!("unsafe path in AUR package archive: {}", path.display()),
        }
    }
    anyhow::ensure!(!parts.is_empty(), "empty path in AUR package archive");
    Ok(parts.join("/"))
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
    let mut file = File::open(path)?;
    let mut magic = [0_u8; 6];
    let magic_len = file.read(&mut magic)?;
    file.rewind()?;
    let magic = &magic[..magic_len];
    if magic.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        let decoder = ruzstd::decoding::StreamingDecoder::new(file)
            .map_err(|error| anyhow::anyhow!("invalid zstd AUR archive: {error}"))?;
        Ok(Box::new(BudgetedReader::new(decoder, limit)))
    } else if magic.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        let temporary = tempfile::tempfile()?;
        let mut output = BudgetedWriter::new(std::io::BufWriter::new(temporary), limit);
        decode_xz_to(BufReader::new(file), &mut output)
            .map_err(|error| anyhow::anyhow!("invalid or oversized xz AUR archive: {error}"))?;
        let mut output = output.into_inner().into_inner()?;
        output.rewind()?;
        Ok(Box::new(output))
    } else if magic.starts_with(&[0x1f, 0x8b]) {
        Ok(Box::new(BudgetedReader::new(
            flate2::read::GzDecoder::new(file),
            limit,
        )))
    } else {
        Ok(Box::new(BudgetedReader::new(file, limit)))
    }
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

pub(crate) fn inspect_archive(path: &Path) -> Result<ArtifactInspection> {
    let archive_sha256 = archive_sha256(path)?;
    let mut archive = tar::Archive::new(archive_reader(path)?);
    let mut seen = HashSet::new();
    let mut member_count = 0_u64;
    let mut declared_bytes = 0_u64;
    let mut executable_files = Vec::new();
    let mut privileged_files = Vec::new();
    let mut paired_build_reasons = BTreeSet::new();
    let mut install_hook = None;
    let mut pkginfo = None;
    let mut buildinfo = None;
    let mut mtree_seen = false;

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
        let member = normalize_member_path(&raw_path)?;
        anyhow::ensure!(
            seen.insert(member.clone()),
            "duplicate normalized path in AUR archive: {member}"
        );
        if member.starts_with("etc/") {
            paired_build_reasons.insert("system-configuration".to_owned());
        }
        // These package locations are consumed by privileged system managers
        // or execute during later root-owned transactions:
        // https://man.archlinux.org/man/alpm-hooks.5
        // https://man.archlinux.org/man/systemd.generator.7
        // https://man.archlinux.org/man/tmpfiles.d.5
        // https://man.archlinux.org/man/sysusers.d.5
        if member.starts_with("usr/lib/systemd/") || member.starts_with("etc/systemd/") {
            paired_build_reasons.insert("systemd-unit".to_owned());
        }
        if member.starts_with("usr/lib/modules/") || member.starts_with("lib/modules/") {
            paired_build_reasons.insert("kernel-module".to_owned());
        }
        if member.starts_with("usr/share/libalpm/hooks/")
            || member.starts_with("usr/share/libalpm/scripts/")
        {
            paired_build_reasons.insert("package-manager-hook".to_owned());
        }
        if member.starts_with("usr/lib/udev/rules.d/")
            || member.starts_with("usr/lib/tmpfiles.d/")
            || member.starts_with("usr/lib/sysusers.d/")
            || member.starts_with("usr/lib/modules-load.d/")
            || member.starts_with("usr/share/polkit-1/")
            || member.starts_with("usr/share/dbus-1/system-services/")
            || member.starts_with("usr/share/dbus-1/system.d/")
            || member.starts_with("usr/lib/kernel/install.d/")
            || member.starts_with("usr/lib/initcpio/")
            || member.starts_with("usr/share/mkinitcpio/")
            || member.starts_with("usr/lib/dracut/")
            || member.starts_with("usr/lib/NetworkManager/dispatcher.d/")
        {
            paired_build_reasons.insert("privileged-system-integration".to_owned());
        }

        let kind = entry.header().entry_type();
        anyhow::ensure!(
            kind.is_file() || kind.is_dir() || kind.is_symlink() || kind.is_hard_link(),
            "special file in AUR archive: {member}"
        );
        if kind.is_symlink() || kind.is_hard_link() {
            let target = entry
                .link_name()?
                .context("link without target in AUR archive")?;
            validate_relative_link(&member, &target, kind.is_hard_link())?;
        }

        let mode = entry.header().mode()?;
        let mut capability = None;
        if let Some(extensions) = entry.pax_extensions()? {
            for extension in extensions {
                let extension = extension?;
                if matches!(
                    extension.key_bytes(),
                    b"SCHILY.xattr.security.capability" | b"LIBARCHIVE.xattr.security.capability"
                ) {
                    capability = Some(hex::encode(extension.value_bytes()));
                }
            }
        }
        if kind.is_file() && mode & 0o111 != 0 {
            executable_files.push(member.clone());
        }
        if kind.is_file() && (mode & 0o6000 != 0 || capability.is_some()) {
            // Linux documents set-ID and file capabilities as privilege-bearing
            // mechanisms: https://man7.org/linux/man-pages/man7/capabilities.7.html
            anyhow::ensure!(
                privileged_files.len() < MAX_PRIVILEGED_FILES,
                "AUR archive has too many privileged files"
            );
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
                ".MTREE" => mtree_seen = true,
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
    anyhow::ensure!(mtree_seen, "AUR archive is missing .MTREE");
    executable_files.sort();
    privileged_files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(ArtifactInspection {
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
            match rejected {
                Err(_) => {}
                Ok(mut reader) => {
                    let mut output = Vec::new();
                    assert!(
                        reader.read_to_end(&mut output).is_err(),
                        "{kind} expansion must be bounded"
                    );
                }
            }
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
        append_file(&mut builder, ".MTREE", b"#mtree\n", 0o644)?;
        extra(&mut builder)?;
        builder.finish()?;
        Ok(file)
    }

    #[test]
    fn member_paths_reject_absolute_parent_and_empty_paths() {
        assert!(normalize_member_path(Path::new("../../etc/shadow")).is_err());
        assert!(normalize_member_path(Path::new("/etc/shadow")).is_err());
        assert!(normalize_member_path(Path::new(".")).is_err());
        assert_eq!(
            normalize_member_path(Path::new("./usr/bin/demo")).unwrap(),
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
        let archive = fixture_archive(|builder| {
            append_file(builder, ".INSTALL", b"post_install() { :; }\n", 0o644)?;
            append_file(builder, "usr/bin/demo", b"binary", 0o4755)
        })?;
        let inspection = inspect_archive(archive.path())?;
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
            let archive = fixture_archive(|builder| append_file(builder, path, b"payload", 0o644))?;
            let inspection = inspect_archive(archive.path())?;
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
