//! Bounded ALPM MTREE interpretation and agreement with the complete archive inventory.

use std::collections::{BTreeMap, HashSet};
use std::io::Read;

use alpm_mtree::{mtree::v2::Path as MtreePath, parser::Statement};
use anyhow::{Context, Result};

use super::{MAX_MEMBERS, MAX_METADATA_BYTES, MAX_PATH_BYTES};

/// Bounds both the decoded MTREE text and retained archive path and target bytes.
const MAX_INVENTORY_BYTES: usize = 16 * 1024 * 1024;
/// Bounds parser allocation even for text consisting only of comments or defaults.
const MAX_STATEMENTS: usize = 200_000;
/// MTREE has nine recognized per-path property kinds.
const MAX_PATH_PROPERTIES: usize = 9;
/// MTREE defaults have four recognized property kinds.
const MAX_DEFAULT_PROPERTIES: usize = 4;
/// POSIX permission bits, including set-ID and sticky bits, without file-type bits.
const PERMISSION_MASK: u32 = 0o7777;
/// POSIX file-type bits in the native ALPM inventory.
const TYPE_MASK: u32 = 0o170_000;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum TarNode {
    File { mode: u32, size: u64 },
    Directory { mode: u32 },
    Symlink { mode: u32, target: String },
    HardLink { mode: u32, target: String },
}

#[derive(Debug, PartialEq, Eq)]
enum LogicalNode {
    File { mode: u32, size: u64 },
    Directory { mode: u32 },
    Symlink { mode: u32, target: String },
}

#[derive(Debug, PartialEq, Eq)]
enum NativeNode {
    File { mode: u32, size: u64 },
    Directory { mode: u32 },
    Symlink { mode: u32 },
}

#[derive(Debug, Default)]
pub(super) struct ArchiveInventory {
    members: BTreeMap<String, TarNode>,
    retained_bytes: usize,
}

#[derive(Debug)]
pub(super) struct NativeInventory(BTreeMap<String, NativeNode>);

pub(super) fn canonical_path(raw: &str, directory: bool) -> Result<String> {
    anyhow::ensure!(
        raw.len() <= MAX_PATH_BYTES,
        "AUR inventory path is too long"
    );
    let path = if directory {
        raw.strip_suffix('/').unwrap_or(raw)
    } else {
        raw
    };
    anyhow::ensure!(
        !path.is_empty()
            && !path.contains('\0')
            && path.split('/').all(|part| !matches!(part, "" | "." | "..")),
        "noncanonical path in AUR archive inventory"
    );
    Ok(path.to_owned())
}

fn reserved(path: &str) -> bool {
    path.starts_with('.')
}

impl ArchiveInventory {
    pub(super) fn add(&mut self, path: String, node: TarNode) -> Result<()> {
        let target = match &node {
            TarNode::Symlink { target, .. } | TarNode::HardLink { target, .. } => target,
            _ => "",
        };
        anyhow::ensure!(
            target.len() <= MAX_PATH_BYTES && !target.contains('\0'),
            "AUR inventory link target is too long or contains NUL"
        );
        self.retained_bytes = self
            .retained_bytes
            .checked_add(path.len())
            .and_then(|sum| sum.checked_add(target.len()))
            .context("AUR inventory path-size overflow")?;
        anyhow::ensure!(
            self.retained_bytes <= MAX_INVENTORY_BYTES,
            "AUR inventory exceeds retained path and target byte limit"
        );
        if let TarNode::HardLink { mode, target } = &node {
            anyhow::ensure!(
                !reserved(&path) && !reserved(target),
                "AUR hard link refers to reserved metadata"
            );
            let Some(TarNode::File {
                mode: target_mode, ..
            }) = self.members.get(target)
            else {
                anyhow::bail!(
                    "AUR hard link must refer directly to an earlier regular payload file"
                );
            };
            anyhow::ensure!(
                mode & PERMISSION_MASK == target_mode & PERMISSION_MASK,
                "AUR hard link permissions differ from its target"
            );
        }
        anyhow::ensure!(
            self.members.insert(path, node).is_none(),
            "duplicate normalized path in AUR archive inventory"
        );
        Ok(())
    }

    pub(super) fn agree(self, bytes: &[u8]) -> Result<NativeInventory> {
        let mut declared = parse(bytes)?;
        let mut expected = BTreeMap::new();
        for (path, node) in &self.members {
            let logical = match node {
                TarNode::File { mode, size } => LogicalNode::File {
                    mode: mode & PERMISSION_MASK,
                    size: *size,
                },
                TarNode::Directory { mode } => LogicalNode::Directory {
                    mode: mode & PERMISSION_MASK,
                },
                TarNode::Symlink { mode, target } => LogicalNode::Symlink {
                    mode: mode & PERMISSION_MASK,
                    target: target.clone(),
                },
                TarNode::HardLink { mode, target } => {
                    let Some(TarNode::File { size, .. }) = self.members.get(target) else {
                        anyhow::bail!("AUR hard link target is not a regular payload file");
                    };
                    LogicalNode::File {
                        mode: mode & PERMISSION_MASK,
                        size: *size,
                    }
                }
            };
            let record = declared.remove(path);
            if reserved(path) {
                if let Some(record) = record {
                    anyhow::ensure!(
                        record == logical,
                        "reserved MTREE entry differs from archive"
                    );
                }
                continue;
            }
            anyhow::ensure!(
                record.as_ref() == Some(&logical),
                "MTREE payload inventory differs from archive at {}",
                crate::cli::style::sanitize_terminal_text(path)
            );
            let (name, native) = match logical {
                LogicalNode::File { mode, size } => {
                    i64::try_from(size).context("MTREE file size exceeds native ALPM range")?;
                    (path.clone(), NativeNode::File { mode, size })
                }
                LogicalNode::Directory { mode } => {
                    (format!("{path}/"), NativeNode::Directory { mode })
                }
                LogicalNode::Symlink { mode, .. } => (path.clone(), NativeNode::Symlink { mode }),
            };
            expected.insert(name, native);
        }
        anyhow::ensure!(
            declared.is_empty(),
            "MTREE declares entries absent from the archive"
        );
        Ok(NativeInventory(expected))
    }
}

impl NativeInventory {
    pub(super) fn verify(&self, files: &alpm::FileList<'_>) -> Result<()> {
        anyhow::ensure!(
            files.files().len() == self.0.len(),
            "native ALPM file count differs from inspected archive inventory"
        );
        let mut seen = HashSet::new();
        for file in files.files() {
            let name = std::str::from_utf8(file.name())
                .context("native ALPM inventory path is not UTF-8")?;
            anyhow::ensure!(seen.insert(name), "duplicate native ALPM inventory path");
            let mode = file.mode() & PERMISSION_MASK;
            let native = match file.mode() & TYPE_MASK {
                0o100_000 => NativeNode::File {
                    mode,
                    size: u64::try_from(file.size()).context("negative native ALPM file size")?,
                },
                0o040_000 => NativeNode::Directory { mode },
                0o120_000 => NativeNode::Symlink { mode },
                _ => anyhow::bail!("unsupported native ALPM inventory file type"),
            };
            anyhow::ensure!(
                self.0.get(name) == Some(&native),
                "native ALPM inventory differs from inspected archive at {}",
                crate::cli::style::sanitize_terminal_text(name)
            );
        }
        Ok(())
    }
}

fn decode(bytes: &[u8], limit: usize) -> Result<String> {
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_METADATA_BYTES,
        "encoded AUR MTREE exceeds metadata limit"
    );
    let text = if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut decoder = flate2::bufread::GzDecoder::new(bytes);
        let mut decoded = Vec::new();
        decoder
            .by_ref()
            .take(
                u64::try_from(limit)?
                    .checked_add(1)
                    .context("MTREE decode limit overflow")?,
            )
            .read_to_end(&mut decoded)
            .context("decoding AUR MTREE gzip member")?;
        anyhow::ensure!(
            decoded.len() <= limit,
            "decoded AUR MTREE exceeds text limit"
        );
        anyhow::ensure!(
            decoder.into_inner().is_empty(),
            "AUR MTREE contains trailing bytes or another gzip member"
        );
        decoded
    } else {
        anyhow::ensure!(bytes.len() <= limit, "decoded AUR MTREE exceeds text limit");
        bytes.to_vec()
    };
    String::from_utf8(text).context("AUR MTREE is not UTF-8")
}

fn preflight(text: &str) -> Result<()> {
    let mut records = 0_u64;
    for (index, line) in text.lines().enumerate() {
        anyhow::ensure!(index < MAX_STATEMENTS, "AUR MTREE has too many statements");
        let mut tokens = line.split_ascii_whitespace();
        let Some(first) = tokens.next() else { continue };
        if first.starts_with('#') {
            continue;
        }
        let limit = if matches!(first, "/set" | "/unset") {
            MAX_DEFAULT_PROPERTIES
        } else {
            records += 1;
            anyhow::ensure!(
                records <= MAX_MEMBERS,
                "AUR MTREE has too many path records"
            );
            MAX_PATH_PROPERTIES
        };
        anyhow::ensure!(
            tokens.take(limit + 1).count() <= limit,
            "AUR MTREE statement has too many properties"
        );
    }
    let mut input = text;
    let statements = alpm_mtree::parser::mtree(&mut input)
        .map_err(|error| anyhow::anyhow!("invalid AUR MTREE syntax: {error}"))?;
    anyhow::ensure!(input.is_empty(), "AUR MTREE parser left unconsumed input");
    for statement in statements {
        let unique = match statement {
            Statement::Ignored => true,
            Statement::Set(properties) => {
                let mut seen = HashSet::new();
                properties
                    .iter()
                    .all(|property| seen.insert(std::mem::discriminant(property)))
            }
            Statement::Unset(properties) => {
                let mut seen = HashSet::new();
                properties
                    .iter()
                    .all(|property| seen.insert(std::mem::discriminant(property)))
            }
            Statement::Path { properties, .. } => {
                let mut seen = HashSet::new();
                properties
                    .iter()
                    .all(|property| seen.insert(std::mem::discriminant(property)))
            }
        };
        anyhow::ensure!(unique, "duplicate AUR MTREE property key");
    }
    Ok(())
}

fn parse(bytes: &[u8]) -> Result<BTreeMap<String, LogicalNode>> {
    let text = decode(bytes, MAX_INVENTORY_BYTES)?;
    preflight(&text)?;
    let paths = alpm_mtree::parse_mtree_v2(text).context("interpreting official ALPM MTREE")?;
    let mut result = BTreeMap::new();
    let mut retained_bytes = 0_usize;
    let mut root_directory_seen = false;
    for path in paths {
        let raw = path
            .as_path()
            .to_str()
            .context("decoded MTREE path is not UTF-8")?;
        if raw == "." && matches!(path, MtreePath::Directory(_)) {
            anyhow::ensure!(!root_directory_seen, "duplicate decoded MTREE path");
            root_directory_seen = true;
            continue;
        }
        anyhow::ensure!(
            raw.len() <= MAX_PATH_BYTES,
            "decoded MTREE path is too long"
        );
        let name = raw
            .strip_prefix("./")
            .context("MTREE path lacks conventional ./ prefix")?;
        let name = canonical_path(name, matches!(path, MtreePath::Directory(_)))?;
        anyhow::ensure!(name != ".MTREE", "MTREE must not declare itself");
        let node = match path {
            MtreePath::File(file) => LogicalNode::File {
                mode: parse_mode(&file.mode)?,
                size: file.size,
            },
            MtreePath::Directory(directory) => LogicalNode::Directory {
                mode: parse_mode(&directory.mode)?,
            },
            MtreePath::Link(link) => {
                let target = link
                    .link_path
                    .to_str()
                    .context("MTREE link target is not UTF-8")?;
                anyhow::ensure!(
                    target.len() <= MAX_PATH_BYTES && !target.contains('\0'),
                    "MTREE link target is too long or contains NUL"
                );
                retained_bytes = retained_bytes
                    .checked_add(target.len())
                    .context("MTREE path-size overflow")?;
                LogicalNode::Symlink {
                    mode: parse_mode(&link.mode)?,
                    target: target.to_owned(),
                }
            }
        };
        retained_bytes = retained_bytes
            .checked_add(name.len())
            .context("MTREE path-size overflow")?;
        anyhow::ensure!(
            retained_bytes <= MAX_INVENTORY_BYTES,
            "MTREE exceeds retained path and target byte limit"
        );
        anyhow::ensure!(
            result.insert(name, node).is_none(),
            "duplicate decoded MTREE path"
        );
    }
    Ok(result)
}

fn parse_mode(raw: &str) -> Result<u32> {
    let mode = u32::from_str_radix(raw, 8).context("invalid MTREE permission mode")?;
    anyhow::ensure!(
        mode & !PERMISSION_MASK == 0,
        "MTREE permission mode has unsupported bits"
    );
    Ok(mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        use std::io::Write as _;

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder
            .write_all(bytes)
            .expect("fixture gzip write succeeds");
        encoder.finish().expect("fixture gzip trailer succeeds")
    }

    #[test]
    fn mtree_decode_requires_complete_single_member_with_bounded_text() -> Result<()> {
        let text = b"#mtree\n";
        let compressed = gzip(text);
        assert_eq!(decode(text, text.len())?, "#mtree\n");
        assert_eq!(decode(&compressed, text.len())?, "#mtree\n");
        assert!(decode(text, text.len() - 1).is_err(), "plain overflow");
        assert!(
            decode(&compressed, text.len() - 1).is_err(),
            "gzip overflow"
        );
        let mut corrupt = compressed.clone();
        let trailer = corrupt.len() - 8;
        corrupt[trailer] ^= 1;
        assert!(decode(&corrupt, 64).is_err(), "corrupt gzip CRC");
        assert!(
            decode(&compressed[..compressed.len() - 1], 64).is_err(),
            "truncated gzip trailer"
        );
        let mut concatenated = compressed.clone();
        concatenated.extend(&compressed);
        assert!(decode(&concatenated, 64).is_err(), "second gzip member");
        let mut trailing = compressed;
        trailing.push(b'x');
        assert!(decode(&trailing, 64).is_err(), "unexamined trailing input");
        assert!(decode(&gzip(&[0xff]), 64).is_err(), "decoded invalid UTF-8");
        assert!(decode(&[0xff], 64).is_err(), "plain invalid UTF-8");
        Ok(())
    }

    #[test]
    fn mtree_duplicate_defaults_and_path_properties_are_refused() {
        for text in [
            "/set uid=0 uid=1\n",
            "/unset mode mode\n",
            "./payload uid=0 gid=0 mode=644 type=file time=0.0 size=4 size=5\n",
        ] {
            let error =
                preflight(text).expect_err("duplicate keys must fail before interpretation");
            assert!(
                error
                    .to_string()
                    .contains("duplicate AUR MTREE property key"),
                "{error:#}"
            );
        }
        assert!(
            preflight("/set uid=0\n/set uid=1\n").is_ok(),
            "successive defaults remain valid"
        );
    }

    #[test]
    fn mtree_parser_bounds_statement_and_property_allocation() {
        let comments = "#\n".repeat(MAX_STATEMENTS + 1);
        let error = preflight(&comments).expect_err("comments count toward the statement budget");
        assert!(
            error.to_string().contains("too many statements"),
            "{error:#}"
        );
        let properties = format!("./payload {}\n", "size=0 ".repeat(MAX_PATH_PROPERTIES + 1));
        let error =
            preflight(&properties).expect_err("path properties must be bounded before parsing");
        assert!(
            error.to_string().contains("too many properties"),
            "{error:#}"
        );
    }

    #[test]
    fn mtree_duplicate_root_directory_declarations_are_refused() {
        let root = ". type=dir uid=0 gid=0 mode=755 time=0.0\n";
        let error = parse(root.repeat(2).as_bytes())
            .expect_err("the neutral root directory remains subject to duplicate refusal");
        assert!(
            error.to_string().contains("duplicate decoded MTREE path"),
            "{error:#}"
        );
    }

    #[test]
    fn mtree_aliases_self_declarations_and_reserved_ghosts_are_refused() {
        let record = "uid=0 gid=0 mode=755 type=dir time=0.0";
        for text in [
            format!("./usr {record}\n./usr/ {record}\n"),
            format!("./.MTREE {record}\n"),
            format!("./usr//share {record}\n"),
            format!("./usr/./share {record}\n"),
            format!("./../escape {record}\n"),
        ] {
            assert!(parse(text.as_bytes()).is_err(), "{text}");
        }
        let ghost = format!("./.reserved {record}\n");
        assert!(
            ArchiveInventory::default().agree(ghost.as_bytes()).is_err(),
            "reserved declarations need real members"
        );
        assert!(
            ArchiveInventory::default().agree(b"#mtree\n").is_ok(),
            "metadata-only packages may have no payload"
        );
    }

    #[test]
    fn hardlinks_require_an_earlier_regular_payload_with_coherent_permissions() -> Result<()> {
        let mut inventory = ArchiveInventory::default();
        inventory.add(
            "usr/file".to_owned(),
            TarNode::File {
                mode: 0o644,
                size: 4,
            },
        )?;
        inventory.add(
            "usr/alias".to_owned(),
            TarNode::HardLink {
                mode: 0o644,
                target: "usr/file".to_owned(),
            },
        )?;
        for (path, target, mode) in [
            ("usr/chain", "usr/alias", 0o644),
            ("usr/missing", "usr/future", 0o644),
            ("usr/mode", "usr/file", 0o600),
            ("usr/reserved", ".PKGINFO", 0o644),
        ] {
            assert!(
                inventory
                    .add(
                        path.to_owned(),
                        TarNode::HardLink {
                            mode,
                            target: target.to_owned()
                        }
                    )
                    .is_err(),
                "unsupported hard link {path} -> {target}"
            );
        }
        Ok(())
    }

    #[test]
    fn symlink_target_and_reserved_metadata_must_agree() -> Result<()> {
        let mut inventory = ArchiveInventory::default();
        inventory.add(
            "usr/link".to_owned(),
            TarNode::Symlink {
                mode: 0o777,
                target: "target".to_owned(),
            },
        )?;
        let mismatch = b"./usr/link uid=0 gid=0 mode=777 type=link time=0.0 link=other\n";
        assert!(
            inventory.agree(mismatch).is_err(),
            "symlink targets are checked in Rust"
        );
        let mut inventory = ArchiveInventory::default();
        inventory.add(".reserved".to_owned(), TarNode::Directory { mode: 0o755 })?;
        assert!(
            inventory
                .agree(b"./.reserved uid=0 gid=0 mode=700 type=dir time=0.0\n")
                .is_err(),
            "optional reserved records must match"
        );
        Ok(())
    }
}
