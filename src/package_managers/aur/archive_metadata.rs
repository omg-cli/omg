//! Reject archive encodings that Rust tar and native libarchive interpret
//! differently before either interpretation can authorize a package.

use std::borrow::Cow;
use std::collections::HashSet;
use std::io::Read;

use anyhow::{Context, Result, ensure};

const MAX_HEADERS: usize = 100_000;
const MAX_EXTENSION_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PATH_BYTES: u64 = 4_096;

/// libarchive percent-decodes LIBARCHIVE attribute names, while SCHILY names
/// are literal. Keep this interpretation shared with privilege classification.
pub(super) fn attribute_name(key: &[u8]) -> Option<Cow<'_, [u8]>> {
    if let Some(name) = key.strip_prefix(b"LIBARCHIVE.xattr.") {
        Some(urlencoding::decode_binary(name))
    } else {
        key.strip_prefix(b"SCHILY.xattr.").map(Cow::Borrowed)
    }
}

#[derive(Default, PartialEq, Eq)]
enum PathEncoding {
    #[default]
    Header,
    Gnu,
    Pax,
}

impl PathEncoding {
    fn set(&mut self, encoding: Self) -> Result<()> {
        ensure!(
            *self == Self::Header,
            "Duplicate or mixed GNU/PAX path metadata in AUR archive"
        );
        *self = encoding;
        Ok(())
    }
}

#[derive(Default)]
struct PendingExtensions {
    keys: HashSet<Vec<u8>>,
    path: PathEncoding,
    link: PathEncoding,
    size: Option<u64>,
    headers: usize,
}

impl PendingExtensions {
    fn field(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        ensure!(!key.contains(&0), "NUL in AUR archive PAX key");
        let canonical = if let Some(name) = attribute_name(key) {
            ensure!(
                !name.is_empty() && !name.contains(&0),
                "Invalid AUR archive attribute name"
            );
            [b"xattr:".as_slice(), name.as_ref()].concat()
        } else {
            ensure!(
                matches!(
                    key,
                    b"path"
                        | b"linkpath"
                        | b"size"
                        | b"uid"
                        | b"gid"
                        | b"uname"
                        | b"gname"
                        | b"mtime"
                        | b"atime"
                        | b"ctime"
                        | b"charset"
                        | b"hdrcharset"
                        | b"comment"
                ),
                "Unsupported AUR archive PAX extension"
            );
            key.to_vec()
        };
        ensure!(
            self.keys.insert(canonical),
            "Duplicate AUR archive PAX key or attribute alias"
        );
        match key {
            b"path" | b"linkpath" => {
                ensure!(
                    !value.is_empty()
                        && value.len() as u64 <= MAX_PATH_BYTES
                        && !value.contains(&0),
                    "Invalid AUR archive PAX path"
                );
                if key == b"path" {
                    self.path.set(PathEncoding::Pax)?;
                } else {
                    self.link.set(PathEncoding::Pax)?;
                }
            }
            b"size" => {
                ensure!(
                    !value.is_empty() && value.iter().all(u8::is_ascii_digit),
                    "Invalid AUR archive PAX size"
                );
                self.size = Some(
                    std::str::from_utf8(value)?
                        .parse()
                        .context("Invalid AUR archive PAX size")?,
                );
            }
            _ => {}
        }
        Ok(())
    }
}

pub(super) fn validate(reader: impl Read) -> Result<()> {
    let mut archive = tar::Archive::new(reader);
    let mut pending = PendingExtensions::default();
    // Raw entries expose extension headers that an interpreted iterator hides.
    // Requiring equal raw/PAX sizes keeps this pass on the same file boundaries
    // as the later interpreted pass and the native installer.
    for (index, entry) in archive.entries()?.raw(true).enumerate() {
        ensure!(index < MAX_HEADERS, "AUR archive has too many raw headers");
        let mut entry = entry?;
        let kind = entry.header().entry_type();
        ensure!(
            !kind.is_pax_global_extensions(),
            "Global PAX headers are unsupported in AUR archives"
        );
        if kind.is_pax_local_extensions() {
            ensure!(
                entry.size() <= MAX_EXTENSION_BYTES,
                "AUR archive PAX metadata exceeds limit"
            );
            pending.headers += 1;
            let fields = entry
                .pax_extensions()?
                .context("AUR archive PAX header has no extension fields")?;
            for field in fields {
                let field = field?;
                pending.field(field.key_bytes(), field.value_bytes())?;
            }
        } else if kind.is_gnu_longname() || kind.is_gnu_longlink() {
            ensure!(
                entry.size() <= MAX_PATH_BYTES + 1,
                "AUR archive GNU path exceeds limit"
            );
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            let path = bytes.strip_suffix(&[0]).unwrap_or(&bytes);
            ensure!(
                !path.is_empty() && !path.contains(&0),
                "Invalid AUR archive GNU path"
            );
            let encoding = if kind.is_gnu_longname() {
                &mut pending.path
            } else {
                &mut pending.link
            };
            encoding.set(PathEncoding::Gnu)?;
            pending.headers += 1;
        } else {
            ensure!(
                pending.size.is_none_or(|size| size == entry.size()),
                "AUR archive raw and PAX sizes disagree"
            );
            ensure!(
                kind.is_file() || entry.size() == 0,
                "Non-regular AUR archive member carries data"
            );
            pending = PendingExtensions::default();
        }
    }
    ensure!(
        pending.headers == 0,
        "AUR archive ends with unapplied extension metadata"
    );
    Ok(())
}
