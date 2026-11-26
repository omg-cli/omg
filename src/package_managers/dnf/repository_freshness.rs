use std::fs::{self, OpenOptions};
use std::io::{self, Read as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use nix::libc;
use sha2::{Digest, Sha256};

use super::rpm_database::reported_setting;

const REPOMD_NAMESPACE: &str = "http://linux.duke.edu/metadata/repo";
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct RepositoryAgePolicy {
    repository: PathBuf,
    interval_seconds: i64,
    prefer_zchunk: bool,
}

impl RepositoryAgePolicy {
    pub(super) fn from_dnf(
        id: &str,
        settings: &str,
        cache: &Path,
        prefer_zchunk: bool,
    ) -> Result<Option<Self>> {
        let interval_seconds: i64 = reported_setting(settings, "metadata_expire")?.parse()?;
        ensure!(
            interval_seconds >= -1,
            "Invalid DNF metadata expiration interval"
        );
        if interval_seconds == -1 {
            return Ok(None);
        }
        let reported_url = |key| {
            if settings.lines().any(|line| line == key) {
                Ok("")
            } else {
                reported_setting(settings, key)
            }
        };
        let metalink = reported_url("metalink")?;
        let mirrorlist = reported_url("mirrorlist")?;
        let baseurl = reported_url("baseurl")?;
        // DNF5 uses the first configured source to scope its metadata cache.
        let source = [metalink, mirrorlist]
            .into_iter()
            .find(|value| !value.is_empty())
            .unwrap_or_else(|| {
                baseurl
                    .split(',')
                    .next()
                    .filter(|url| !url.is_empty())
                    .unwrap_or(id)
            });
        ensure!(
            !source.contains('\\'),
            "Unsupported escaped DNF repository source"
        );
        let suffix = hex::encode(&Sha256::digest(source.as_bytes())[..8]);
        Ok(Some(Self {
            repository: cache.join(format!("{id}-{suffix}")),
            interval_seconds,
            prefer_zchunk,
        }))
    }

    pub(super) fn directory(&self) -> &Path {
        &self.repository
    }

    pub(super) fn refreshes_every_query(&self) -> bool {
        self.interval_seconds == 0
    }

    pub(super) fn read(&self) -> Result<RepositoryAge> {
        self.read_primary(false)
    }

    pub(super) fn read_for_cache(&self) -> Result<RepositoryAge> {
        self.read_primary(true)
    }

    fn read_primary(&self, without_modules: bool) -> Result<RepositoryAge> {
        let manifest = self.repository.join("repodata/repomd.xml");
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&manifest)
            .context("Cannot open DNF repository manifest")?;
        ensure!(
            file.metadata()?.is_file(),
            "DNF manifest is not a regular file"
        );
        let mut text = String::new();
        file.take(MAX_MANIFEST_BYTES + 1)
            .read_to_string(&mut text)?;
        ensure!(
            text.len() as u64 <= MAX_MANIFEST_BYTES,
            "DNF manifest exceeds size limit"
        );
        let xml = roxmltree::Document::parse_with_options(
            &text,
            roxmltree::ParsingOptions {
                nodes_limit: 50_000,
                ..Default::default()
            },
        )?;
        if without_modules {
            ensure!(
                !xml.root_element().children().any(|node| {
                    node.has_tag_name((REPOMD_NAMESPACE, "data"))
                        && node
                            .attribute("type")
                            .is_some_and(|kind| kind.starts_with("modules"))
                }),
                "DNF module metadata requires native catalog loading"
            );
        }
        let (plain, zchunk) = primary_files(&xml)?;
        let primary = [zchunk.filter(|_| self.prefer_zchunk), plain]
            .into_iter()
            .flatten()
            .map(|relative| self.repository.join(relative))
            .find_map(|path| match metadata_timestamp(&path) {
                Ok(Some(_)) => Some(Ok(path)),
                Ok(None) => None,
                Err(error) => Some(Err(error)),
            })
            .transpose()?
            .context("Current primary RPM metadata is absent")?;
        Ok(RepositoryAge {
            primary,
            interval_seconds: self.interval_seconds,
        })
    }
}

fn primary_files<'a>(
    xml: &'a roxmltree::Document<'_>,
) -> Result<(Option<&'a Path>, Option<&'a Path>)> {
    let root = xml.root_element();
    ensure!(
        root.has_tag_name((REPOMD_NAMESPACE, "repomd")),
        "Invalid DNF repository manifest root"
    );
    let (mut plain, mut zchunk) = (None, None);
    for entry in root
        .children()
        .filter(|node| node.has_tag_name((REPOMD_NAMESPACE, "data")))
    {
        let target = match entry.attribute("type") {
            Some("primary") => &mut plain,
            Some("primary_zck") => &mut zchunk,
            _ => continue,
        };
        let mut locations = entry
            .children()
            .filter(|node| node.has_tag_name((REPOMD_NAMESPACE, "location")));
        let href = locations
            .next()
            .and_then(|node| node.attribute("href"))
            .context("Missing DNF primary metadata location")?;
        ensure!(
            locations.next().is_none() && target.is_none(),
            "Ambiguous DNF primary metadata location"
        );
        let path = Path::new(href);
        let mut parts = path.components();
        ensure!(
            parts.next() == Some(Component::Normal("repodata".as_ref()))
                && matches!(parts.next(), Some(Component::Normal(_)))
                && parts.next().is_none(),
            "Unsupported DNF primary metadata location"
        );
        *target = Some(path);
    }
    Ok((plain, zchunk))
}

fn metadata_timestamp(path: &Path) -> Result<Option<i64>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(Some(metadata.mtime())),
        Ok(_) => anyhow::bail!("DNF primary metadata is not a regular file"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("Cannot read DNF primary metadata timestamp"),
    }
}

pub(super) struct RepositoryAge {
    primary: PathBuf,
    interval_seconds: i64,
}

impl RepositoryAge {
    pub(super) fn is_fresh(&self, now: i64) -> Result<bool> {
        Ok(self.interval_seconds > 0
            && metadata_timestamp(&self.primary)?
                .is_some_and(|mtime| now.saturating_sub(mtime) < self.interval_seconds))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn chooses_the_native_primary_and_rechecks_its_age_on_reuse() -> Result<()> {
        let cache = tempfile::tempdir()?;
        let settings = "metadata_expire = 30\nmetalink\nmirrorlist\nbaseurl = file:///fixture";
        let mut policy = RepositoryAgePolicy::from_dnf("fixture", settings, cache.path(), true)?
            .context("finite repository policy")?;
        let repodata = policy.repository.join("repodata");
        fs::create_dir_all(&repodata)?;
        fs::write(
            repodata.join("repomd.xml"),
            r#"<repomd xmlns="http://linux.duke.edu/metadata/repo">
               <data type="primary"><location href="repodata/regular.xml.gz"/></data>
               <data type="primary_zck"><location href="repodata/alternate.xml.zck"/></data>
               </repomd>"#,
        )?;
        let primary = fs::File::create(repodata.join("regular.xml.gz"))?;
        let compressed = fs::File::create(repodata.join("alternate.xml.zck"))?;
        primary.set_modified(UNIX_EPOCH + Duration::from_secs(1_020))?;
        compressed.set_modified(UNIX_EPOCH + Duration::from_secs(1_000))?;
        let age = policy.read()?;
        assert!(age.is_fresh(1_029)?);
        assert!(!age.is_fresh(1_030)?);
        compressed.set_modified(UNIX_EPOCH + Duration::from_secs(1_006))?;
        assert!(age.is_fresh(1_035)?);
        policy.prefer_zchunk = false;
        assert!(policy.read()?.is_fresh(1_049)?);
        assert!(!policy.read()?.is_fresh(1_050)?);
        policy.interval_seconds = 0;
        assert!(
            !policy.read()?.is_fresh(1_019)?,
            "a future timestamp cannot override zero expiry"
        );
        Ok(())
    }
}
