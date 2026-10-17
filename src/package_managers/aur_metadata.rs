//! AUR Metadata Synchronization
//!
//! Handles downloading, caching, and indexing of the AUR metadata archive
//! (packages-meta-ext-v1.json.gz).

use std::fs::File;
#[cfg(test)]
use std::io::BufReader;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
#[cfg(test)]
use flate2::read::GzDecoder;
use futures::StreamExt;
use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use serde::{Deserialize, Serialize};
use tokio::fs as tokio_fs;
use tracing::{info, instrument};

use crate::config::Settings;
use crate::core::paths;
use crate::package_managers::aur_index::build_index;

const AUR_META_URL: &str = "https://aur.archlinux.org/packages-meta-ext-v1.json.gz";
const MAX_AUR_METADATA_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Default, Deserialize, Serialize)]
struct AurMetaCache {
    etag: Option<String>,
    last_modified: Option<String>,
}

/// Raw package entry from the AUR JSON dump
#[derive(Debug, Deserialize)]
pub struct AurJsonPackage {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(default, rename = "PackageBase")]
    pub package_base: Option<String>,
    #[serde(default, rename = "Depends")]
    pub depends: Option<Vec<String>>,
    #[serde(default, rename = "MakeDepends")]
    pub make_depends: Option<Vec<String>>,
    #[serde(default, rename = "CheckDepends")]
    pub check_depends: Option<Vec<String>>,
    #[serde(rename = "Description")]
    pub description: Option<String>,
    #[serde(rename = "Maintainer")]
    pub maintainer: Option<String>,
    #[serde(rename = "NumVotes")]
    pub num_votes: Option<i32>,
    #[serde(rename = "Popularity")]
    pub popularity: Option<f64>,
    #[serde(rename = "OutOfDate")]
    pub out_of_date: Option<i64>,
    #[serde(rename = "LastModified")]
    pub last_modified: Option<i64>,
}

fn modified_within_ttl(modified: SystemTime, ttl: Duration) -> bool {
    modified.elapsed().is_ok_and(|age| age < ttl)
}

fn metadata_generation_is_coherent(archive_path: &Path, index_path: &Path) -> bool {
    let archive_modified = std::fs::metadata(archive_path).and_then(|meta| meta.modified());
    let index_modified = std::fs::metadata(index_path).and_then(|meta| meta.modified());
    matches!((archive_modified, index_modified), (Ok(archive), Ok(index)) if index >= archive)
}

pub(crate) fn metadata_index_is_fresh(
    archive_path: &Path,
    index_path: &Path,
    ttl: Duration,
) -> bool {
    metadata_generation_is_coherent(archive_path, index_path)
        && std::fs::metadata(archive_path)
            .and_then(|metadata| metadata.modified())
            .is_ok_and(|modified| modified_within_ttl(modified, ttl))
}

fn metadata_request(
    client: &reqwest::Client,
    meta_cache: &AurMetaCache,
    cache_exists: bool,
) -> reqwest::RequestBuilder {
    let mut request = client.get(AUR_META_URL);
    if cache_exists {
        if let Some(etag) = &meta_cache.etag {
            request = request.header(IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = &meta_cache.last_modified {
            request = request.header(IF_MODIFIED_SINCE, last_modified);
        }
    }
    request
}

/// Sync AUR metadata: Download if newer, update cache, rebuild index
#[instrument(skip(client, settings))]
pub async fn sync_aur_metadata(
    client: &reqwest::Client,
    settings: &Settings,
    force: bool,
) -> Result<()> {
    if !settings.aur.use_metadata_archive {
        return Ok(());
    }

    let cache_path = metadata_path();
    let meta_path = cache_path.with_extension("gz.meta");
    let index_path = index_path();

    // Check TTL if not forced
    if !force && cache_path.is_file() {
        let ttl = settings.aur.metadata_cache_ttl_secs;
        let cache_path_clone = cache_path.clone();
        let is_fresh = tokio::task::spawn_blocking(move || {
            std::fs::metadata(&cache_path_clone)
                .and_then(|m| m.modified())
                .is_ok_and(|modified| modified_within_ttl(modified, Duration::from_secs(ttl)))
        })
        .await?;

        if is_fresh {
            if !metadata_generation_is_coherent(&cache_path, &index_path) {
                info!("AUR cache is fresh but its index is stale. Rebuilding index...");
                rebuild_index(&cache_path, &index_path).await?;
            }
            return Ok(());
        }
    }

    // Load ETags/Last-Modified
    let meta_cache = tokio_fs::read(&meta_path)
        .await
        .ok()
        .and_then(|bytes| serde_json::from_slice::<AurMetaCache>(&bytes).ok())
        .unwrap_or_default();

    if let Some(parent) = cache_path.parent() {
        tokio_fs::create_dir_all(parent).await?;
    }

    // Prepare a conditional request only when the body it validates is present.
    let response = metadata_request(client, &meta_cache, cache_path.is_file())
        .send()
        .await?;

    if response.status() == reqwest::StatusCode::NOT_MODIFIED {
        anyhow::ensure!(
            cache_path.is_file(),
            "AUR metadata server returned 304 but the cached archive is missing"
        );
        if !metadata_generation_is_coherent(&cache_path, &index_path) {
            info!("Rebuilding stale AUR index...");
            rebuild_index(&cache_path, &index_path).await?;
        }
        let cache_path_clone = cache_path.clone();
        let index_path_clone = index_path.clone();
        tokio::task::spawn_blocking(move || {
            let modified = SystemTime::now();
            File::options()
                .write(true)
                .open(cache_path_clone)?
                .set_modified(modified)?;
            File::options()
                .write(true)
                .open(index_path_clone)?
                .set_modified(modified)
        })
        .await??;

        return Ok(());
    }

    let response = response.error_for_status()?;

    // Capture headers before consuming body
    let etag = response
        .headers()
        .get(ETAG)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let last_modified = response
        .headers()
        .get(LAST_MODIFIED)
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    if let Some(length) = response.content_length() {
        anyhow::ensure!(
            length <= MAX_AUR_METADATA_BYTES,
            "AUR metadata declares {length} bytes, exceeding the {MAX_AUR_METADATA_BYTES}-byte limit"
        );
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("Failed to read AUR metadata")?;
        let next_len = bytes
            .len()
            .checked_add(chunk.len())
            .context("AUR metadata byte count overflowed")?;
        anyhow::ensure!(
            u64::try_from(next_len).unwrap_or(u64::MAX) <= MAX_AUR_METADATA_BYTES,
            "AUR metadata exceeded the {MAX_AUR_METADATA_BYTES}-byte limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    {
        let cache_path = cache_path.clone();
        let index_path = index_path.clone();
        tokio::task::spawn_blocking(move || {
            validate_and_publish_metadata(&cache_path, &index_path, &bytes)
        })
        .await??;
    }

    let new_meta = AurMetaCache {
        etag,
        last_modified,
    };
    match serde_json::to_vec(&new_meta) {
        Ok(meta_bytes) => {
            let result = tokio::task::spawn_blocking(move || {
                persist_file_atomically(&meta_path, &meta_bytes)
            })
            .await;
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::warn!("Failed to persist AUR metadata sidecar: {error}");
                }
                Err(error) => {
                    tracing::warn!("AUR metadata sidecar task failed: {error}");
                }
            }
        }
        Err(error) => tracing::warn!("Failed to serialize AUR metadata sidecar: {error}"),
    }

    info!("AUR metadata synced and indexed");
    Ok(())
}

/// Read and parse the metadata archive (if you need the raw JSON)
/// Note: prefer using `AurIndex` for lookups
#[cfg(test)]
pub fn read_metadata_archive(path: &Path) -> Result<Vec<AurJsonPackage>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let decoder = GzDecoder::new(reader);
    serde_json::from_reader(decoder).map_err(Into::into)
}

pub fn metadata_path() -> PathBuf {
    paths::cache_dir()
        .join("aur")
        .join("_meta")
        .join("packages-meta-ext-v1.json.gz")
}

pub fn index_path() -> PathBuf {
    paths::cache_dir()
        .join("aur")
        .join("_meta")
        .join("packages-meta-ext-v1.rkyv")
}

fn validate_and_publish_metadata(
    archive_path: &Path,
    index_path: &Path,
    bytes: &[u8],
) -> Result<()> {
    let parent = archive_path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;

    let mut staged_archive = tempfile::NamedTempFile::new_in(parent)?;
    staged_archive.write_all(bytes)?;
    staged_archive.as_file_mut().sync_all()?;

    let staged_index = tempfile::NamedTempFile::new_in(parent)?.into_temp_path();
    std::fs::remove_file(&staged_index)?;
    build_index(staged_archive.path(), &staged_index)?;

    // Reusing the staged file preserves the mtime ordering used for coherence.
    staged_archive
        .persist(archive_path)
        .map_err(|error| error.error)
        .with_context(|| {
            format!(
                "Failed to persist AUR metadata at {}",
                archive_path.display()
            )
        })?;
    crate::core::safe_ops::sync_parent_directory_sync(archive_path)?;
    std::fs::rename(&staged_index, index_path)
        .with_context(|| format!("Failed to publish AUR index at {}", index_path.display()))?;
    crate::core::safe_ops::sync_parent_directory_sync(index_path)?;
    Ok(())
}

async fn rebuild_index(archive_path: &Path, index_path: &Path) -> Result<()> {
    let archive_path = archive_path.to_owned();
    let index_path = index_path.to_owned();
    tokio::task::spawn_blocking(move || build_index(&archive_path, &index_path)).await?
}

fn persist_file_atomically(dest: &Path, data: &[u8]) -> Result<()> {
    let parent = dest.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).with_context(|| {
        format!(
            "Failed to create AUR metadata directory: {}",
            parent.display()
        )
    })?;
    let mut file = tempfile::NamedTempFile::new_in(parent).with_context(|| {
        format!(
            "Failed to create temporary AUR metadata in {}",
            parent.display()
        )
    })?;
    file.write_all(data)?;
    file.as_file_mut().sync_all()?;
    file.persist(dest)
        .map_err(|error| error.error)
        .with_context(|| format!("Failed to persist AUR metadata at {}", dest.display()))?;
    crate::core::safe_ops::sync_parent_directory_sync(dest)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn future_cache_timestamp_is_not_fresh() {
        let future = SystemTime::now() + Duration::from_hours(1);
        assert!(!modified_within_ttl(future, Duration::from_hours(2)));
    }

    #[test]
    fn binary_index_freshness_follows_the_archive_ttl() {
        let directory = tempfile::tempdir().unwrap();
        let archive = directory.path().join("metadata.json.gz");
        let index = directory.path().join("metadata.rkyv");
        std::fs::write(&archive, b"archive").unwrap();
        std::fs::write(&index, b"index").unwrap();

        assert!(metadata_index_is_fresh(
            &archive,
            &index,
            Duration::from_mins(1)
        ));
        assert!(!metadata_index_is_fresh(&archive, &index, Duration::ZERO));
        std::fs::remove_file(&archive).unwrap();
        assert!(!metadata_index_is_fresh(
            &archive,
            &index,
            Duration::from_mins(1)
        ));
    }

    #[test]
    fn stale_index_is_not_a_fresh_metadata_generation() {
        use std::fs::FileTimes;

        let directory = tempfile::tempdir().unwrap();
        let archive = directory.path().join("metadata.json.gz");
        let index = directory.path().join("metadata.rkyv");
        std::fs::write(&archive, b"new archive").unwrap();
        std::fs::write(&index, b"old index").unwrap();
        File::options()
            .write(true)
            .open(&index)
            .unwrap()
            .set_times(FileTimes::new().set_modified(SystemTime::UNIX_EPOCH))
            .unwrap();

        assert!(!metadata_index_is_fresh(
            &archive,
            &index,
            Duration::from_mins(1)
        ));
    }

    #[test]
    fn published_metadata_generation_is_coherent_and_fresh() {
        let directory = tempfile::tempdir().unwrap();
        let archive = directory.path().join("metadata.json.gz");
        let index = directory.path().join("metadata.rkyv");

        let mut json = Vec::new();
        let mut encoder = flate2::write::GzEncoder::new(&mut json, flate2::Compression::default());
        serde_json::to_writer(
            &mut encoder,
            &serde_json::json!([{"Name": "aur-helper", "Version": "1.2.3-1"}]),
        )
        .unwrap();
        encoder.finish().unwrap();

        validate_and_publish_metadata(&archive, &index, &json).unwrap();

        assert_eq!(
            read_metadata_archive(&archive).unwrap()[0].name,
            "aur-helper",
            "the published archive must be the validated bytes"
        );
        assert!(
            metadata_index_is_fresh(&archive, &index, Duration::from_mins(1)),
            "a just-published generation must be coherent and fresh"
        );

        let published_index = crate::package_managers::aur_index::AurIndex::open(&index);
        assert!(
            published_index.is_ok(),
            "the published binary index must be queryable"
        );
        let published_index = published_index.unwrap();
        assert_eq!(
            published_index
                .search("", 2)
                .unwrap()
                .iter()
                .map(|entry| (entry.name.as_str(), entry.version.as_str()))
                .collect::<Vec<_>>(),
            vec![("aur-helper", "1.2.3-1")],
            "the published binary index must contain exactly the literal package and version"
        );
        let entry = published_index.get("aur-helper").unwrap().unwrap();
        assert!(entry.maintainer.is_none());
        assert!(entry.last_modified.is_none());
        assert!(entry.description.is_none());
        assert_eq!(entry.num_votes, 0);
        assert_eq!(entry.popularity, 0.0);
        assert!(entry.out_of_date.is_none());
    }

    #[test]
    fn invalid_metadata_does_not_replace_a_valid_generation() {
        let directory = tempfile::tempdir().unwrap();
        let archive = directory.path().join("metadata.json.gz");
        let index = directory.path().join("metadata.rkyv");
        let sidecar = directory.path().join("metadata.gz.meta");
        std::fs::write(&archive, b"old archive").unwrap();
        std::fs::write(&index, b"old index").unwrap();
        std::fs::write(&sidecar, b"old validators").unwrap();

        let error = validate_and_publish_metadata(&archive, &index, b"invalid gzip")
            .expect_err("invalid metadata must fail validation");
        assert!(!error.to_string().is_empty());
        assert_eq!(std::fs::read(&archive).unwrap(), b"old archive");
        assert_eq!(std::fs::read(&index).unwrap(), b"old index");
        assert_eq!(std::fs::read(&sidecar).unwrap(), b"old validators");
    }

    #[test]
    fn metadata_request_uses_validators_only_with_cached_archive() {
        let client = reqwest::Client::new();
        let meta = AurMetaCache {
            etag: Some("\"etag-value\"".to_string()),
            last_modified: Some("Wed, 21 Oct 2015 07:28:00 GMT".to_string()),
        };

        let with_archive = metadata_request(&client, &meta, true).build().unwrap();
        assert_eq!(
            with_archive.headers().get(IF_NONE_MATCH).unwrap(),
            "\"etag-value\""
        );
        assert_eq!(
            with_archive.headers().get(IF_MODIFIED_SINCE).unwrap(),
            "Wed, 21 Oct 2015 07:28:00 GMT"
        );

        let without_archive = metadata_request(&client, &meta, false).build().unwrap();
        assert!(without_archive.headers().get(IF_NONE_MATCH).is_none());
        assert!(without_archive.headers().get(IF_MODIFIED_SINCE).is_none());
    }

    #[test]
    fn aur_metadata_persist_round_trips() {
        let temp = tempfile::TempDir::new().unwrap();
        let dest = temp
            .path()
            .join("_meta")
            .join("packages-meta-ext-v1.json.gz");
        persist_file_atomically(&dest, b"archive").unwrap();
        assert_eq!(std::fs::read(dest).unwrap(), b"archive");
    }

    #[test]
    fn aur_metadata_persist_refuses_to_clobber_a_directory() {
        let temp = tempfile::TempDir::new().unwrap();
        let dest = temp.path().join("packages-meta-ext-v1.json.gz");
        std::fs::create_dir(&dest).unwrap();
        let error = persist_file_atomically(&dest, b"archive")
            .expect_err("must refuse to persist over a directory");
        assert!(
            error.to_string().contains("persist"),
            "error must name the persist failure, got: {error}"
        );
        assert!(
            dest.is_dir(),
            "the existing directory must not have been clobbered"
        );
    }
}
