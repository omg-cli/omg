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
use tracing::{info, instrument};

use crate::config::Settings;
use crate::core::paths;
use crate::package_managers::aur_index::{AurIndex, build_index};

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

#[derive(Debug, Deserialize, Serialize)]
struct Manifest {
    generation: String,
    validators: AurMetaCache,
}

#[derive(Clone)]
struct MetadataRoot {
    build_dir: PathBuf,
}

impl MetadataRoot {
    const fn new(build_dir: PathBuf) -> Self {
        Self { build_dir }
    }

    fn path(&self) -> PathBuf {
        self.build_dir.join("_meta")
    }
}

#[derive(Clone, Copy, Debug)]
enum MetadataAccess {
    Shared,
    Exclusive,
}

struct MetadataLock {
    _publication: File,
    _lifecycle: File,
}

fn metadata_root() -> MetadataRoot {
    MetadataRoot::new(paths::cache_dir().join("aur"))
}

fn generation_paths(root: &Path, manifest: &Manifest) -> Result<(PathBuf, PathBuf)> {
    anyhow::ensure!(
        manifest.generation.starts_with("gen-")
            && manifest
                .generation
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-'),
        "invalid AUR metadata generation name"
    );
    let generation = root.join(&manifest.generation);
    Ok((generation.join("archive.gz"), generation.join("index.rkyv")))
}

fn lock_metadata(location: &MetadataRoot, access: MetadataAccess) -> Result<MetadataLock> {
    use std::os::unix::fs::DirBuilderExt;

    use crate::package_managers::aur::utils::{
        open_build_lifecycle_lock, open_effective_user_lock,
    };

    let lifecycle = open_build_lifecycle_lock(&location.build_dir)?;
    lifecycle
        .try_lock_shared()
        .context("Failed to acquire AUR metadata ownership; cleanup may be active")?;
    let root = location.path();
    match access {
        MetadataAccess::Exclusive => std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&root)?,
        MetadataAccess::Shared => anyhow::ensure!(
            std::fs::metadata(&root)?.is_dir(),
            "AUR metadata root is not a directory"
        ),
    }
    let publication = open_effective_user_lock(&root.join("publication.lock"))?;
    match access {
        MetadataAccess::Shared => publication.lock_shared()?,
        MetadataAccess::Exclusive => publication.lock()?,
    }
    Ok(MetadataLock {
        _publication: publication,
        _lifecycle: lifecycle,
    })
}

fn current_generation(root: &Path) -> Result<Option<(Manifest, AurIndex)>> {
    let bytes = match std::fs::read(root.join("manifest.json")) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let manifest: Manifest =
        serde_json::from_slice(&bytes).context("Invalid AUR metadata manifest")?;
    let (archive, index) = generation_paths(root, &manifest)?;
    anyhow::ensure!(
        std::fs::metadata(archive)?.is_file(),
        "AUR metadata archive is missing"
    );
    Ok(Some((manifest, AurIndex::open(&index)?)))
}

fn open_fresh_metadata_index_at(
    location: &MetadataRoot,
    ttl: Duration,
) -> Result<Option<AurIndex>> {
    let root = location.path();
    if !root.is_dir() {
        return Ok(None);
    }
    let _lock = match lock_metadata(location, MetadataAccess::Shared) {
        Ok(lock) => lock,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let manifest = root.join("manifest.json");
    let fresh = std::fs::metadata(manifest)
        .and_then(|m| m.modified())
        .is_ok_and(|modified| modified_within_ttl(modified, ttl));
    if !fresh {
        return Ok(None);
    }
    Ok(current_generation(&root)?.map(|(_, index)| index))
}

/// Open an owned snapshot of the currently published, fresh metadata generation.
pub(crate) fn open_fresh_metadata_index(ttl: Duration) -> Result<Option<AurIndex>> {
    open_fresh_metadata_index_at(&metadata_root(), ttl)
}

fn metadata_request(
    client: &reqwest::Client,
    endpoint: &str,
    meta_cache: &AurMetaCache,
    cache_exists: bool,
) -> reqwest::RequestBuilder {
    let mut request = client.get(endpoint);
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
    sync_aur_metadata_at(client, settings, force, metadata_root(), AUR_META_URL).await
}

async fn sync_aur_metadata_at(
    client: &reqwest::Client,
    settings: &Settings,
    force: bool,
    location: MetadataRoot,
    endpoint: &str,
) -> Result<()> {
    if !settings.aur.use_metadata_archive {
        return Ok(());
    }

    let root = location.path();
    let publication_lock =
        tokio::task::spawn_blocking(move || lock_metadata(&location, MetadataAccess::Exclusive))
            .await??;
    let current = current_generation(&root).unwrap_or_else(|error| {
        tracing::warn!("Ignoring incomplete AUR metadata generation: {error}");
        None
    });
    if !force && current.is_some() {
        let fresh = std::fs::metadata(root.join("manifest.json"))
            .and_then(|metadata| metadata.modified())
            .is_ok_and(|modified| {
                modified_within_ttl(
                    modified,
                    Duration::from_secs(settings.aur.metadata_cache_ttl_secs),
                )
            });
        if fresh {
            return Ok(());
        }
    }
    if current.is_none() && !force {
        let legacy = root.join("packages-meta-ext-v1.json.gz");
        let fresh = std::fs::metadata(&legacy)
            .and_then(|m| m.modified())
            .is_ok_and(|modified| {
                modified_within_ttl(
                    modified,
                    Duration::from_secs(settings.aur.metadata_cache_ttl_secs),
                )
            });
        if fresh {
            let root = root.clone();
            tokio::task::spawn_blocking(move || {
                let _publication_lock = publication_lock;
                anyhow::ensure!(
                    std::fs::metadata(&legacy)?.len() <= MAX_AUR_METADATA_BYTES,
                    "legacy AUR metadata exceeds size limit"
                );
                let bytes = std::fs::read(legacy)?;
                publish_generation(&root, &bytes, AurMetaCache::default())
            })
            .await??;
            return Ok(());
        }
    }
    let validators = current.as_ref().map(|(manifest, _)| &manifest.validators);
    let empty = AurMetaCache::default();
    let response = metadata_request(
        client,
        endpoint,
        validators.unwrap_or(&empty),
        current.is_some(),
    )
    .send()
    .await?;
    if response.status() == reqwest::StatusCode::NOT_MODIFIED {
        let (manifest, _) =
            current.context("AUR metadata server returned 304 without a complete generation")?;
        let root = root.clone();
        tokio::task::spawn_blocking(move || {
            let _publication_lock = publication_lock;
            commit_manifest(&root, &manifest)
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
    let validators = AurMetaCache {
        etag,
        last_modified,
    };
    tokio::task::spawn_blocking(move || {
        let _publication_lock = publication_lock;
        publish_generation(&root, &bytes, validators)
    })
    .await??;

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

fn commit_manifest(root: &Path, manifest: &Manifest) -> Result<()> {
    persist_file_atomically(&root.join("manifest.json"), &serde_json::to_vec(manifest)?)
}

fn publish_generation(root: &Path, bytes: &[u8], validators: AurMetaCache) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    std::fs::create_dir_all(root)?;
    let generation = tempfile::Builder::new()
        .prefix("gen-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(root)?;
    let archive = generation.path().join("archive.gz");
    let index = generation.path().join("index.rkyv");
    let mut file = File::options()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&archive)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    build_index(&archive, &index)?;
    File::open(generation.path())?.sync_all()?;
    let name = generation
        .path()
        .file_name()
        .context("missing generation name")?
        .to_str()
        .context("invalid generation name")?
        .to_owned();
    let _persisted = generation.keep();
    File::open(root)?.sync_all()?;
    commit_manifest(
        root,
        &Manifest {
            generation: name,
            validators,
        },
    )
}

#[cfg(test)]
pub(crate) fn publish_test_metadata(archive: &Path) -> Result<()> {
    let location = metadata_root();
    let _lock = lock_metadata(&location, MetadataAccess::Exclusive)?;
    publish_generation(
        &location.path(),
        &std::fs::read(archive)?,
        AurMetaCache::default(),
    )
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

    fn metadata_client() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
    }

    async fn metadata_server(
        status: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> (String, tokio::task::JoinHandle<String>) {
        use std::fmt::Write as _;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/metadata.gz", listener.local_addr().unwrap());
        let mut response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        for (name, value) in headers {
            write!(response, "{name}: {value}\r\n").unwrap();
        }
        response.push_str("\r\n");
        let mut response = response.into_bytes();
        response.extend_from_slice(body);
        let server = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut bytes = [0_u8; 1024];
                    let count = stream.read(&mut bytes).await.unwrap();
                    assert_ne!(count, 0, "request ended before its headers");
                    request.extend_from_slice(&bytes[..count]);
                    assert!(request.len() <= 16 * 1024, "request headers are too large");
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                stream.write_all(&response).await.unwrap();
                String::from_utf8(request).unwrap()
            })
            .await
            .expect("metadata request and response must finish within five seconds")
        });
        (endpoint, server)
    }

    fn unused_metadata_endpoint() -> (String, std::net::TcpListener) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}/metadata.gz", listener.local_addr().unwrap());
        (endpoint, listener)
    }

    fn assert_no_metadata_request(listener: &std::net::TcpListener) {
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "metadata reuse must not connect to the endpoint"
        );
    }

    fn catalogue(name: &str) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        serde_json::to_writer(
            &mut encoder,
            &serde_json::json!([{ "Name": name, "Version": "1-1" }]),
        )
        .unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn public_disabled_sync_does_not_create_cache_or_connect() -> Result<()> {
        const TEST: &str = "package_managers::aur_metadata::tests::public_disabled_sync_does_not_create_cache_or_connect";
        if Settings::rerun_test_unprivileged(TEST) || crate::core::testing::run_isolated_test(TEST)
        {
            return Ok(());
        }
        let directory = tempfile::tempdir()?;
        let cache = directory.path().join("unused-cache");
        let (endpoint, listener) = unused_metadata_endpoint();
        let client = reqwest::Client::builder()
            .no_proxy()
            .proxy(reqwest::Proxy::all(endpoint)?)
            .timeout(Duration::from_millis(250))
            .build()?;
        let mut settings = Settings::default();
        settings.aur.use_metadata_archive = false;
        temp_env::with_var("OMG_CACHE_DIR", Some(&cache), || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(sync_aur_metadata(&client, &settings, true))
        })?;
        assert!(!cache.exists());
        assert_no_metadata_request(&listener);
        Ok(())
    }

    #[tokio::test]
    async fn sync_disabled_metadata_does_not_create_cache_or_request() {
        let directory = tempfile::tempdir().unwrap();
        let location = MetadataRoot::new(directory.path().join("unused-cache"));
        let root = location.path();
        let mut settings = Settings::default();
        settings.aur.use_metadata_archive = false;
        let (endpoint, listener) = unused_metadata_endpoint();

        sync_aur_metadata_at(&metadata_client(), &settings, true, location, &endpoint)
            .await
            .unwrap();

        assert!(!root.exists());
        assert_no_metadata_request(&listener);
    }

    #[tokio::test]
    async fn sync_fresh_complete_generation_does_not_request_or_republish() {
        let directory = tempfile::tempdir().unwrap();
        let location = MetadataRoot::new(directory.path().join("aur"));
        let root_path = location.path();
        let root = root_path.as_path();
        std::fs::create_dir_all(root).unwrap();
        publish_generation(root, &catalogue("cached"), AurMetaCache::default()).unwrap();
        let manifest_before = std::fs::read(root.join("manifest.json")).unwrap();
        let (endpoint, listener) = unused_metadata_endpoint();

        sync_aur_metadata_at(
            &metadata_client(),
            &Settings::default(),
            false,
            location,
            &endpoint,
        )
        .await
        .unwrap();

        assert_no_metadata_request(&listener);
        assert_eq!(
            std::fs::read(root.join("manifest.json")).unwrap(),
            manifest_before
        );
        let (_, index) = current_generation(root).unwrap().unwrap();
        assert!(index.get("cached").unwrap().is_some());
    }

    #[tokio::test]
    async fn sync_fresh_legacy_archive_migrates_without_request() {
        let directory = tempfile::tempdir().unwrap();
        let location = MetadataRoot::new(directory.path().join("aur"));
        let root_path = location.path();
        let root = root_path.as_path();
        std::fs::create_dir_all(root).unwrap();
        let archive = catalogue("legacy");
        let legacy = root.join("packages-meta-ext-v1.json.gz");
        std::fs::write(&legacy, &archive).unwrap();
        let (endpoint, listener) = unused_metadata_endpoint();

        sync_aur_metadata_at(
            &metadata_client(),
            &Settings::default(),
            false,
            location,
            &endpoint,
        )
        .await
        .unwrap();

        assert_no_metadata_request(&listener);
        let (manifest, index) = current_generation(root).unwrap().unwrap();
        let (published_archive, _) = generation_paths(root, &manifest).unwrap();
        assert_eq!(std::fs::read(published_archive).unwrap(), archive);
        assert_eq!(std::fs::read(legacy).unwrap(), archive);
        assert!(index.get("legacy").unwrap().is_some());
        assert!(manifest.validators.etag.is_none());
        assert!(manifest.validators.last_modified.is_none());
    }

    #[tokio::test]
    async fn sync_200_publishes_archive_index_and_validators_together() {
        let directory = tempfile::tempdir().unwrap();
        let location = MetadataRoot::new(directory.path().join("aur"));
        let root_path = location.path();
        let root = root_path.as_path();
        std::fs::create_dir_all(root).unwrap();
        publish_generation(root, &catalogue("old"), AurMetaCache::default()).unwrap();
        let (old_manifest, snapshot) = current_generation(root).unwrap().unwrap();
        let archive = catalogue("new");
        let modified = "Wed, 11 Nov 2026 12:00:00 GMT";
        let (endpoint, server) = metadata_server(
            "200 OK",
            &[("ETag", "\"new-etag\""), ("Last-Modified", modified)],
            &archive,
        )
        .await;

        sync_aur_metadata_at(
            &metadata_client(),
            &Settings::default(),
            true,
            location,
            &endpoint,
        )
        .await
        .unwrap();

        let request = server.await.unwrap();
        assert!(request.starts_with("GET /metadata.gz HTTP/1.1\r\n"));
        let (manifest, index) = current_generation(root).unwrap().unwrap();
        assert_ne!(manifest.generation, old_manifest.generation);
        assert_eq!(manifest.validators.etag.as_deref(), Some("\"new-etag\""));
        assert_eq!(manifest.validators.last_modified.as_deref(), Some(modified));
        let (published_archive, _) = generation_paths(root, &manifest).unwrap();
        assert_eq!(std::fs::read(&published_archive).unwrap(), archive);
        assert_eq!(
            read_metadata_archive(&published_archive).unwrap()[0].name,
            "new"
        );
        assert!(index.get("new").unwrap().is_some());
        assert!(index.get("old").unwrap().is_none());
        assert!(snapshot.get("old").unwrap().is_some());
        assert!(snapshot.get("new").unwrap().is_none());
    }

    #[tokio::test]
    async fn sync_304_reuses_complete_generation_and_refreshes_manifest() {
        let directory = tempfile::tempdir().unwrap();
        let location = MetadataRoot::new(directory.path().join("aur"));
        let root_path = location.path();
        let root = root_path.as_path();
        std::fs::create_dir_all(root).unwrap();
        let modified = "Wed, 11 Nov 2026 12:00:00 GMT";
        publish_generation(
            root,
            &catalogue("cached"),
            AurMetaCache {
                etag: Some("\"cached-etag\"".into()),
                last_modified: Some(modified.into()),
            },
        )
        .unwrap();
        let manifest_path = root.join("manifest.json");
        File::options()
            .write(true)
            .open(&manifest_path)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_hours(24))
            .unwrap();
        let manifest_before = std::fs::read(&manifest_path).unwrap();
        let (manifest, _) = current_generation(root).unwrap().unwrap();
        let (archive, index) = generation_paths(root, &manifest).unwrap();
        let archive_before = std::fs::read(&archive).unwrap();
        let index_before = std::fs::read(&index).unwrap();
        let (endpoint, server) = metadata_server("304 Not Modified", &[], &[]).await;

        sync_aur_metadata_at(
            &metadata_client(),
            &Settings::default(),
            false,
            location.clone(),
            &endpoint,
        )
        .await
        .unwrap();

        let request = server.await.unwrap().to_ascii_lowercase();
        assert!(request.contains("\r\nif-none-match: \"cached-etag\"\r\n"));
        assert!(request.contains(&format!(
            "\r\nif-modified-since: {}\r\n",
            modified.to_ascii_lowercase()
        )));
        assert_eq!(std::fs::read(&manifest_path).unwrap(), manifest_before);
        assert_eq!(std::fs::read(archive).unwrap(), archive_before);
        assert_eq!(std::fs::read(index).unwrap(), index_before);
        assert!(
            open_fresh_metadata_index_at(&location, Duration::from_mins(1))
                .unwrap()
                .unwrap()
                .get("cached")
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn sync_incomplete_or_corrupt_generation_recovers_without_validators() {
        #[derive(Debug)]
        enum Damage {
            MissingArchive,
            CorruptIndex,
            CorruptManifest,
        }

        for damage in [
            Damage::MissingArchive,
            Damage::CorruptIndex,
            Damage::CorruptManifest,
        ] {
            let directory = tempfile::tempdir().unwrap();
            let location = MetadataRoot::new(directory.path().join("aur"));
            let root_path = location.path();
            let root = root_path.as_path();
            std::fs::create_dir_all(root).unwrap();
            publish_generation(
                root,
                &catalogue("old"),
                AurMetaCache {
                    etag: Some("\"unusable\"".into()),
                    last_modified: Some("Wed, 11 Nov 2026 12:00:00 GMT".into()),
                },
            )
            .unwrap();
            let (manifest, _) = current_generation(root).unwrap().unwrap();
            let (archive, index) = generation_paths(root, &manifest).unwrap();
            match damage {
                Damage::MissingArchive => std::fs::remove_file(archive).unwrap(),
                Damage::CorruptIndex => std::fs::write(index, b"invalid index").unwrap(),
                Damage::CorruptManifest => {
                    std::fs::write(root.join("manifest.json"), b"{").unwrap();
                }
            }
            assert!(current_generation(root).is_err(), "{damage:?}");
            let recovered = catalogue("recovered");
            let (endpoint, server) = metadata_server("200 OK", &[], &recovered).await;

            sync_aur_metadata_at(
                &metadata_client(),
                &Settings::default(),
                false,
                location,
                &endpoint,
            )
            .await
            .unwrap();

            let request = server.await.unwrap().to_ascii_lowercase();
            assert!(!request.contains("\r\nif-none-match:"), "{damage:?}");
            assert!(!request.contains("\r\nif-modified-since:"), "{damage:?}");
            let (manifest, index) = current_generation(root).unwrap().unwrap();
            assert!(index.get("recovered").unwrap().is_some(), "{damage:?}");
            assert!(index.get("old").unwrap().is_none(), "{damage:?}");
            assert_eq!(
                std::fs::read(generation_paths(root, &manifest).unwrap().0).unwrap(),
                recovered,
                "{damage:?}"
            );
        }
    }

    #[tokio::test]
    async fn sync_304_without_complete_generation_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let location = MetadataRoot::new(directory.path().join("aur"));
        let root_path = location.path();
        let root = root_path.as_path();
        std::fs::create_dir_all(root).unwrap();
        let (endpoint, server) = metadata_server("304 Not Modified", &[], &[]).await;

        let error = sync_aur_metadata_at(
            &metadata_client(),
            &Settings::default(),
            true,
            location,
            &endpoint,
        )
        .await
        .unwrap_err();

        let request = server.await.unwrap().to_ascii_lowercase();
        assert!(!request.contains("\r\nif-none-match:"));
        assert!(!request.contains("\r\nif-modified-since:"));
        assert!(
            error
                .to_string()
                .contains("304 without a complete generation")
        );
        assert!(current_generation(root).unwrap().is_none());
    }

    #[tokio::test]
    async fn sync_invalid_200_preserves_published_generation_and_validators() {
        let directory = tempfile::tempdir().unwrap();
        let location = MetadataRoot::new(directory.path().join("aur"));
        let root_path = location.path();
        let root = root_path.as_path();
        std::fs::create_dir_all(root).unwrap();
        publish_generation(
            root,
            &catalogue("cached"),
            AurMetaCache {
                etag: Some("\"cached-etag\"".into()),
                last_modified: None,
            },
        )
        .unwrap();
        let manifest_before = std::fs::read(root.join("manifest.json")).unwrap();
        let (endpoint, server) =
            metadata_server("200 OK", &[("ETag", "\"invalid-etag\"")], b"invalid gzip").await;

        assert!(
            sync_aur_metadata_at(
                &metadata_client(),
                &Settings::default(),
                true,
                location,
                &endpoint,
            )
            .await
            .is_err()
        );

        server.await.unwrap();
        assert_eq!(
            std::fs::read(root.join("manifest.json")).unwrap(),
            manifest_before
        );
        let (manifest, index) = current_generation(root).unwrap().unwrap();
        assert_eq!(manifest.validators.etag.as_deref(), Some("\"cached-etag\""));
        assert!(index.get("cached").unwrap().is_some());
    }

    #[test]
    fn current_generation_distinguishes_absent_manifest_from_read_failure() {
        let directory = tempfile::tempdir().unwrap();
        assert!(current_generation(directory.path()).unwrap().is_none());
        std::fs::create_dir(directory.path().join("manifest.json")).unwrap();

        let error = current_generation(directory.path()).err().unwrap();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::IsADirectory
        );
    }

    #[test]
    fn mismatched_archive_and_index_are_not_a_fresh_generation() {
        let directory = tempfile::tempdir().unwrap();
        let location = MetadataRoot::new(directory.path().join("aur"));
        let root_path = location.path();
        let root = root_path.as_path();
        std::fs::create_dir_all(root).unwrap();
        let archive = root.join("metadata.json.gz");
        let index = root.join("metadata.rkyv");
        std::fs::write(&archive, catalogue("package-a")).unwrap();
        build_index(&archive, &index).unwrap();
        std::fs::write(&archive, catalogue("package-b")).unwrap();
        let now = SystemTime::now();
        File::options()
            .write(true)
            .open(&archive)
            .unwrap()
            .set_modified(now - Duration::from_secs(2))
            .unwrap();
        File::options()
            .write(true)
            .open(&index)
            .unwrap()
            .set_modified(now - Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            read_metadata_archive(&archive).unwrap()[0].name,
            "package-b"
        );
        assert!(
            AurIndex::open(&index)
                .unwrap()
                .get("package-a")
                .unwrap()
                .is_some()
        );
        assert!(
            open_fresh_metadata_index_at(&location, Duration::from_mins(1))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn published_generation_survives_failed_publication_and_304() {
        let directory = tempfile::tempdir().unwrap();
        let location = MetadataRoot::new(directory.path().join("aur"));
        let root_path = location.path();
        let root = root_path.as_path();
        std::fs::create_dir_all(root).unwrap();
        publish_generation(
            root,
            &catalogue("old"),
            AurMetaCache {
                etag: Some("etag".into()),
                last_modified: None,
            },
        )
        .unwrap();
        let snapshot = open_fresh_metadata_index_at(&location, Duration::from_mins(1))
            .unwrap()
            .unwrap();
        assert!(publish_generation(root, b"invalid gzip", AurMetaCache::default()).is_err());
        let (manifest, _) = current_generation(root).unwrap().unwrap();
        assert_eq!(manifest.validators.etag.as_deref(), Some("etag"));
        commit_manifest(root, &manifest).unwrap();
        publish_generation(root, &catalogue("new"), AurMetaCache::default()).unwrap();
        assert!(snapshot.get("old").unwrap().is_some());
        let current = open_fresh_metadata_index_at(&location, Duration::from_mins(1))
            .unwrap()
            .unwrap();
        assert!(current.get("new").unwrap().is_some());
        assert!(current.get("old").unwrap().is_none());
    }

    #[test]
    fn metadata_request_requires_complete_generation_for_validators() {
        let client = reqwest::Client::new();
        let modified = "Wed, 11 Nov 2026 12:00:00 GMT";
        let validators = AurMetaCache {
            etag: Some("etag".into()),
            last_modified: Some(modified.into()),
        };
        let incomplete = metadata_request(&client, AUR_META_URL, &validators, false)
            .build()
            .unwrap();
        assert!(incomplete.headers().get(IF_NONE_MATCH).is_none());
        assert!(incomplete.headers().get(IF_MODIFIED_SINCE).is_none());
        let complete = metadata_request(&client, AUR_META_URL, &validators, true)
            .build()
            .unwrap();
        assert_eq!(complete.url().as_str(), AUR_META_URL);
        assert_eq!(complete.headers().get(IF_NONE_MATCH).unwrap(), "etag");
        assert_eq!(complete.headers().get(IF_MODIFIED_SINCE).unwrap(), modified);
    }
    #[test]
    fn future_cache_timestamp_is_not_fresh() {
        assert!(!modified_within_ttl(
            SystemTime::now() + Duration::from_hours(1),
            Duration::from_hours(2)
        ));
        assert!(modified_within_ttl(
            SystemTime::now() - Duration::from_secs(1),
            Duration::from_hours(2)
        ));
    }

    #[test]
    fn binary_index_freshness_follows_the_archive_ttl() {
        let directory = tempfile::tempdir().unwrap();
        let location = MetadataRoot::new(directory.path().join("aur"));
        let root = location.path();
        publish_generation(&root, &catalogue("one"), AurMetaCache::default()).unwrap();
        assert!(
            open_fresh_metadata_index_at(&location, Duration::from_mins(1))
                .unwrap()
                .is_some()
        );
        assert!(
            open_fresh_metadata_index_at(&location, Duration::ZERO)
                .unwrap()
                .is_none()
        );
        let (manifest, _) = current_generation(&root).unwrap().unwrap();
        std::fs::remove_file(generation_paths(&root, &manifest).unwrap().0).unwrap();
        assert!(open_fresh_metadata_index_at(&location, Duration::from_mins(1)).is_err());
    }

    #[test]
    fn missing_metadata_root_does_not_create_a_cache_or_lock() {
        let directory = tempfile::tempdir().expect("private metadata owner");
        let location = MetadataRoot::new(directory.path().join("absent"));
        let root = location.path();
        assert!(
            open_fresh_metadata_index_at(&location, Duration::from_mins(1))
                .expect("missing metadata root is a cache miss")
                .is_none()
        );
        assert!(
            !root.exists(),
            "a read must not create the absent metadata root"
        );
        assert_eq!(
            directory.path().read_dir().expect("private owner").count(),
            0
        );
    }

    #[test]
    fn stale_index_is_not_a_fresh_metadata_generation() {
        let directory = tempfile::tempdir().unwrap();
        let location = MetadataRoot::new(directory.path().join("aur"));
        let root = location.path();
        publish_generation(&root, &catalogue("one"), AurMetaCache::default()).unwrap();
        let (manifest, _) = current_generation(&root).unwrap().unwrap();
        std::fs::remove_file(generation_paths(&root, &manifest).unwrap().1).unwrap();
        assert!(open_fresh_metadata_index_at(&location, Duration::from_mins(1)).is_err());
    }

    #[test]
    fn published_metadata_generation_is_coherent_and_fresh() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let data = catalogue("aur-helper");
        publish_generation(directory.path(), &data, AurMetaCache::default()).unwrap();
        let (manifest, index) = current_generation(directory.path()).unwrap().unwrap();
        let (archive_path, index_path) = generation_paths(directory.path(), &manifest).unwrap();
        assert_eq!(
            std::fs::metadata(archive_path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "published generations must remain private"
        );
        for path in [&archive_path, &index_path] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600,
                "published metadata files must remain private"
            );
        }
        assert_eq!(
            std::fs::read(generation_paths(directory.path(), &manifest).unwrap().0).unwrap(),
            data
        );
        let entry = index.get("aur-helper").unwrap().unwrap();
        assert_eq!(entry.version.as_str(), "1-1");
        assert!(entry.maintainer.is_none());
        assert!(entry.last_modified.is_none());
        assert!(entry.description.is_none());
        assert_eq!(entry.num_votes, 0);
        assert_eq!(entry.popularity, 0.0);
        assert!(entry.out_of_date.is_none());
    }

    #[test]
    fn aur_metadata_persist_round_trips() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nested").join("manifest");
        persist_file_atomically(&path, b"data").unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"data");
    }

    #[test]
    fn aur_metadata_persist_refuses_to_clobber_a_directory() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("manifest");
        std::fs::create_dir(&path).unwrap();
        assert!(persist_file_atomically(&path, b"data").is_err());
        assert!(path.is_dir());
    }

    #[test]
    fn metadata_lock_preserves_generation_during_cache_cleanup() -> Result<()> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        const TEST: &str = "package_managers::aur_metadata::tests::metadata_lock_preserves_generation_during_cache_cleanup";
        if Settings::rerun_test_unprivileged(TEST) || crate::core::testing::run_isolated_test(TEST)
        {
            return Ok(());
        }
        assert!(
            !crate::core::is_root(),
            "cache fixture requires an ordinary UID"
        );
        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let configuration = directory.path().join("config");
        let data = directory.path().join("data");
        let cache = directory.path().join("cache");
        for path in [&configuration, &data, &cache] {
            std::fs::DirBuilder::new().mode(0o700).create(path)?;
        }
        std::fs::write(
            configuration.join("config.toml"),
            "[aur]\nsecurity_profile = 'standard'\n",
        )?;
        temp_env::with_vars(
            [
                ("OMG_CONFIG_DIR", Some(configuration.as_path())),
                ("OMG_DATA_DIR", Some(data.as_path())),
                ("OMG_CACHE_DIR", Some(cache.as_path())),
            ],
            || -> Result<()> {
                let client = crate::package_managers::aur::AurClient::new()?;
                let location = metadata_root();
                let root = location.path();
                assert_eq!(root, cache.join("aur/_meta"));
                let expected = catalogue("held-generation");
                for access in [MetadataAccess::Shared, MetadataAccess::Exclusive] {
                    publish_generation(&root, &expected, AurMetaCache::default())?;
                    let (manifest, _) =
                        current_generation(&root)?.context("published generation")?;
                    let (archive, _) = generation_paths(&root, &manifest)?;
                    let lease = lock_metadata(&location, access)?;
                    assert!(
                        client.clean_all().is_err(),
                        "cache cleanup must refuse an active metadata lease, access={access:?}"
                    );
                    assert_eq!(std::fs::read(&archive)?, expected);
                    assert_eq!(
                        current_generation(&root)?
                            .context("retained generation")?
                            .0
                            .generation,
                        manifest.generation
                    );
                    drop(lease);
                    client.clean_all()?;
                    assert!(!root.exists(), "released metadata may be cleaned");
                }
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(async {
                        let (started, started_rx) = tokio::sync::oneshot::channel();
                        let (release, release_rx) = std::sync::mpsc::channel();
                        let (finished, finished_rx) = tokio::sync::oneshot::channel();
                        let worker_location = location.clone();
                        let waiting = tokio::spawn(async move {
                            tokio::task::spawn_blocking(move || {
                                let result = (|| -> Result<()> {
                                    let _lease =
                                        lock_metadata(&worker_location, MetadataAccess::Exclusive)?;
                                    started.send(()).map_err(|()| {
                                        anyhow::anyhow!("metadata observer dropped")
                                    })?;
                                    release_rx.recv()?;
                                    publish_generation(
                                        &worker_location.path(),
                                        &catalogue("worker-generation"),
                                        AurMetaCache::default(),
                                    )
                                })();
                                let delivered = finished.send(result);
                                assert!(delivered.is_ok(), "metadata completion observer dropped");
                            })
                            .await
                        });
                        tokio::time::timeout(Duration::from_secs(5), started_rx).await??;
                        waiting.abort();
                        assert!(waiting.await.expect_err("cancelled waiter").is_cancelled());
                        assert!(
                            client.clean_all().is_err(),
                            "a detached metadata worker must retain cleanup protection"
                        );
                        release.send(())?;
                        tokio::time::timeout(Duration::from_secs(5), finished_rx).await???;
                        let (manifest, index) =
                            current_generation(&root)?.context("worker generation")?;
                        assert!(index.get("worker-generation")?.is_some());
                        assert_eq!(
                            std::fs::read(generation_paths(&root, &manifest)?.0)?,
                            catalogue("worker-generation")
                        );
                        client.clean_all()?;
                        assert!(!root.exists(), "completed metadata work may be cleaned");
                        Ok::<_, anyhow::Error>(())
                    })?;
                Ok(())
            },
        )
    }

    #[test]
    fn metadata_locks_reject_symlinks_and_hardlinks() -> Result<()> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let location = MetadataRoot::new(directory.path().join("aur"));
        let root = location.path();
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&root)?;
        let ordinary = lock_metadata(&location, MetadataAccess::Shared)?;
        drop(ordinary);
        let lock_path = root.join("publication.lock");
        std::fs::remove_file(&lock_path)?;
        let target = directory.path().join("unrelated");
        std::fs::write(&target, b"unrelated inode")?;
        std::os::unix::fs::symlink(&target, &lock_path)?;
        assert!(
            lock_metadata(&location, MetadataAccess::Shared).is_err(),
            "a metadata lock must not follow a symlink to an unrelated inode"
        );
        std::fs::remove_file(&lock_path)?;
        std::fs::hard_link(&target, &lock_path)?;
        assert!(
            lock_metadata(&location, MetadataAccess::Exclusive).is_err(),
            "a metadata lock must not share an unrelated hardlinked inode"
        );
        assert_eq!(std::fs::read(target)?, b"unrelated inode");
        Ok(())
    }

    #[test]
    fn metadata_locks_are_private_at_creation() -> Result<()> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let location = MetadataRoot::new(directory.path().join("aur"));
        let root = location.path();
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&root)?;
        let lease = lock_metadata(&location, MetadataAccess::Shared)?;
        assert_eq!(
            std::fs::metadata(root.join("publication.lock"))?
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "metadata coordination files must be private at creation"
        );
        drop(lease);
        Ok(())
    }

    #[test]
    #[ignore = "invoked as a separate process by metadata_lock_is_cross_process"]
    fn metadata_lock_child() {
        use std::io::{BufRead, Write};
        let root = PathBuf::from(std::env::var_os("OMG_METADATA_LOCK_TEST_ROOT").unwrap());
        let file = File::options()
            .read(true)
            .write(true)
            .open(root.join("publication.lock"))
            .unwrap();
        assert!(
            file.try_lock().is_err(),
            "exclusive lock must be blocked by another process's shared lock"
        );
        println!("METADATA_LOCK_BLOCKED");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line).unwrap();
        file.lock().unwrap();
        println!("METADATA_LOCK_ACQUIRED");
        std::io::stdout().flush().unwrap();
    }

    #[test]
    fn metadata_lock_is_cross_process() {
        use std::io::{BufRead, BufReader, Write};
        use std::process::{Command, Stdio};
        let directory = tempfile::tempdir().unwrap();
        let location = MetadataRoot::new(directory.path().join("aur"));
        let root = location.path();
        std::fs::create_dir_all(&root).unwrap();
        let shared = lock_metadata(&location, MetadataAccess::Shared).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["metadata_lock_child", "--ignored", "--nocapture"])
            .env("OMG_METADATA_LOCK_TEST_ROOT", &root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(
                output.read_line(&mut line).unwrap(),
                0,
                "child exited before lock check"
            );
            if line.contains("METADATA_LOCK_BLOCKED") {
                break;
            }
        }
        drop(shared);
        writeln!(child.stdin.take().unwrap(), "continue").unwrap();
        loop {
            line.clear();
            assert_ne!(
                output.read_line(&mut line).unwrap(),
                0,
                "child exited before acquiring lock"
            );
            if line.contains("METADATA_LOCK_ACQUIRED") {
                break;
            }
        }
        assert!(child.wait().unwrap().success());
    }
}
