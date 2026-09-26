//! Common utilities for runtime managers
//!
//! Shared functionality for downloading, extracting, and managing runtime versions.

use crate::core::http::BoundedResponseExt;
use std::cmp::Ordering;
use std::fs::{self, File};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256, Sha512};

use crate::cli::{
    progress::{Accent, Outcome, ProgressTask, TaskKind, TaskSpec},
    style,
};
use crate::core::archive::stripped_archive_path;

pub(crate) const GITHUB_USER_AGENT: &str = "omg-package-manager/0.1";
const MAX_RUNTIME_DOWNLOAD_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub(crate) struct GithubRelease {
    pub(crate) tag_name: String,
    #[serde(default)]
    pub(crate) prerelease: bool,
    #[serde(default)]
    pub(crate) assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GithubAsset {
    pub(crate) name: String,
    pub(crate) browser_download_url: Option<String>,
    pub(crate) digest: Option<String>,
}

/// Diagnostic message when a GitHub response indicates the API rate limit is
/// exhausted, so callers surface specific remediation instead of a bare 403.
fn github_rate_limit_diagnostic(
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
) -> Option<String> {
    if !matches!(status.as_u16(), 403 | 429) {
        return None;
    }
    let remaining = headers.get("x-ratelimit-remaining")?;
    if remaining.to_str().ok()? != "0" {
        return None;
    }
    let reset = headers
        .get("x-ratelimit-reset")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown");
    Some(format!(
        "GitHub API rate limit exhausted (HTTP {status}, X-RateLimit-Remaining: 0, \
         X-RateLimit-Reset: {reset}); wait for the limit window to reset"
    ))
}

/// Fetch GitHub releases with explicit pagination bounds.
///
/// Pages are requested in order until a page is short, `stop_when` matches a
/// release, or `max_pages` is reached. HTTP and parse failures identify the
/// source URL.
pub(crate) async fn fetch_github_releases<F>(
    client: &reqwest::Client,
    releases_url: &str,
    per_page: u32,
    max_pages: u32,
    stop_when: F,
) -> Result<Vec<GithubRelease>>
where
    F: Fn(&GithubRelease) -> bool,
{
    let mut releases = Vec::new();
    for page in 1..=max_pages {
        let response = client
            .get(format!("{releases_url}?per_page={per_page}&page={page}"))
            .header("User-Agent", GITHUB_USER_AGENT)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .with_context(|| format!("Failed to fetch GitHub releases from {releases_url}"))?;

        if let Some(diagnostic) =
            github_rate_limit_diagnostic(response.status(), response.headers())
        {
            anyhow::bail!("{diagnostic}");
        }

        let page_releases: Vec<GithubRelease> = response
            .error_for_status()
            .with_context(|| format!("GitHub releases request failed: {releases_url}"))?
            .bounded_json()
            .await
            .with_context(|| format!("Failed to parse GitHub releases payload: {releases_url}"))?;
        let short = page_releases.len() < per_page as usize;
        let stop = page_releases.iter().any(&stop_when);
        releases.extend(page_releases);
        if short || stop {
            break;
        }
    }
    Ok(releases)
}

pub(crate) fn host_os_tag(
    runtime: &str,
    linux: &'static str,
    macos: &'static str,
) -> Result<&'static str> {
    match std::env::consts::OS {
        "linux" => Ok(linux),
        "macos" => Ok(macos),
        other => anyhow::bail!("Unsupported operating system for {runtime}: {other}"),
    }
}

pub(crate) fn host_arch_tag(
    runtime: &str,
    x86_64: &'static str,
    aarch64: &'static str,
) -> Result<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(x86_64),
        "aarch64" => Ok(aarch64),
        other => anyhow::bail!("Unsupported architecture for {runtime}: {other}"),
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Bounded decompression
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Maximum accepted decompressed size for untrusted archive payloads (2 GiB).
///
/// The bound is enforced *while* bytes are produced, so a decompression bomb
/// aborts with an error instead of exhausting memory before a post-hoc size
/// check can run.
pub(crate) const MAX_DECOMPRESSED_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Reader that enforces a decompressed-size budget while streaming.
///
/// Every read that would push the cumulative output past `budget` fails with
/// [`ErrorKind::InvalidData`], so downstream consumers never buffer more than
/// the budget.
pub(crate) struct BudgetedReader<R> {
    inner: R,
    remaining: u64,
    limit: u64,
}

impl<R> BudgetedReader<R> {
    /// Explicit budget: production callers pass [`MAX_DECOMPRESSED_BYTES`],
    /// tests pass a small budget so the abort path is exercisable without
    /// gigabyte allocations.
    pub(crate) fn new(inner: R, budget: u64) -> Self {
        Self {
            inner,
            remaining: budget,
            limit: budget,
        }
    }
}

impl<R: Read> Read for BudgetedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        let read = u64::try_from(read).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "impossible read size while decompressing",
            )
        })?;
        if read > self.remaining {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "decompressed data exceeds the configured limit of {} bytes",
                    self.limit
                ),
            ));
        }
        self.remaining -= read;
        Ok(read as usize)
    }
}

/// In-memory sink that refuses to grow past a decompressed-size budget.
///
/// Used with compressors that only expose a `Read -> Write` API (xz), where a
/// budgeted reader is not available: the sink errors as soon as the budget is
/// exhausted, so the backing buffer stops growing at the cap instead of after
/// decompression has completed.
pub(crate) struct BudgetedWriter<W> {
    inner: W,
    written: u64,
    budget: u64,
}

impl<W> BudgetedWriter<W> {
    pub(crate) fn new(inner: W, budget: u64) -> Self {
        Self {
            inner,
            written: 0,
            budget,
        }
    }

    pub(crate) fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for BudgetedWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let remaining = self.budget.saturating_sub(self.written);
        if u64::try_from(buffer.len()).unwrap_or(u64::MAX) > remaining {
            return Err(std::io::Error::other(format!(
                "decompressed archive exceeds the {} byte limit",
                self.budget
            )));
        }
        let written = self.inner.write(buffer)?;
        self.written = self
            .written
            .saturating_add(u64::try_from(written).unwrap_or(u64::MAX));
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg_attr(
    not(any(feature = "arch", feature = "debian", feature = "debian-pure")),
    allow(dead_code, reason = "used by platform package database readers")
)]
pub(crate) struct BudgetedSink {
    buf: Vec<u8>,
    remaining: u64,
}

impl BudgetedSink {
    /// The configured maximum budget, for callers that delegate the choice.
    /// Only Debian-side extraction delegates today.
    #[cfg(any(feature = "arch", feature = "debian", feature = "debian-pure"))]
    pub(crate) fn max_budget() -> u64 {
        MAX_DECOMPRESSED_BYTES
    }

    /// Explicit budget: production callers pass [`MAX_DECOMPRESSED_BYTES`],
    /// tests pass a small budget so the abort path is exercisable without
    /// gigabyte allocations.
    #[cfg(test)]
    pub(crate) fn with_budget(budget: u64) -> Self {
        Self {
            buf: Vec::new(),
            remaining: budget,
        }
    }

    /// Test-only: exposes the accumulated buffer for size assertions.
    #[cfg(test)]
    pub(crate) fn into_inner(self) -> Vec<u8> {
        self.buf
    }
}

struct BorrowedBudgetedWriter<'a, W> {
    inner: W,
    remaining: &'a mut u64,
}

impl<W: Write> Write for BorrowedBudgetedWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let length = u64::try_from(buf.len()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "impossible write size")
        })?;
        if length > *self.remaining {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "decompressed data exceeds the maximum supported size of {MAX_DECOMPRESSED_BYTES} bytes"
                ),
            ));
        }
        let written = self.inner.write(buf)?;
        *self.remaining -= u64::try_from(written).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "impossible write size")
        })?;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn copy_with_budget<R: Read, W: Write>(
    reader: &mut R,
    writer: W,
    remaining: &mut u64,
) -> std::io::Result<u64> {
    std::io::copy(
        reader,
        &mut BorrowedBudgetedWriter {
            inner: writer,
            remaining,
        },
    )
}

impl Write for BudgetedSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let len = buf.len() as u64;
        if len > self.remaining {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "decompressed data exceeds the maximum supported size of {MAX_DECOMPRESSED_BYTES} bytes"
                ),
            ));
        }
        self.remaining -= len;
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Validate that an upstream-supplied archive name is exactly one ordinary
/// filename component before it is joined beneath a local download directory.
pub(crate) fn validate_download_filename(filename: &str) -> Result<&str> {
    let mut components = Path::new(filename).components();
    anyhow::ensure!(
        matches!(components.next(), Some(std::path::Component::Normal(_)))
            && components.next().is_none()
            && !filename.contains('\\')
            && !filename.contains('\0'),
        "Invalid vendor download filename: {filename:?}"
    );
    Ok(filename)
}

// Callers validate the vendor URL before entering this helper. Only the GET
// before response headers is retried; no partial file or checksum is reused.
async fn request_runtime_download(
    _client: &reqwest::Client,
    url: &str,
) -> Result<reqwest::Response> {
    retry_runtime_request(url, || {
        crate::core::http::fetch_public_download(url, GITHUB_USER_AGENT)
    })
    .await
}

async fn retry_runtime_request<F, Fut>(url: &str, mut request: F) -> Result<reqwest::Response>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<reqwest::Response>>,
{
    let parsed_url = reqwest::Url::parse(url).ok();
    let host = parsed_url
        .as_ref()
        .and_then(reqwest::Url::host_str)
        .unwrap_or("unknown");
    for attempt in 0..3 {
        match request().await {
            Err(error)
                if attempt < 2
                    && error
                        .downcast_ref::<reqwest::Error>()
                        .is_some_and(crate::core::http::is_retryable_error) =>
            {
                tracing::warn!(
                    attempt = attempt + 1,
                    host,
                    "Runtime download connection failed; retrying bounded GET request"
                );
                tokio::time::sleep(crate::core::http::retry_backoff(
                    std::time::Duration::from_millis(100),
                    attempt,
                ))
                .await;
            }
            result => return result,
        }
    }
    unreachable!("final request attempt always returns")
}

/// Number of attempts for one runtime artifact download: the initial try plus
/// two bounded retries cover transient mid-stream stalls without turning a
/// persistent failure into an unbounded loop.
const MAX_DOWNLOAD_ATTEMPTS: usize = 3;

/// Mid-stream failures that are safe to retry: read stalls, incomplete bodies,
/// decode faults, and retryable transport errors. HTTP status errors and
/// checksum mismatches are never retried here.
fn is_retryable_download_stream_error(error: &reqwest::Error) -> bool {
    error.is_timeout()
        || error.is_body()
        || error.is_decode()
        || crate::core::http::is_retryable_error(error)
}

/// Connect-phase failures that are safe to retry.
///
/// The download URL is resolved with our own deadline (`tokio::time::timeout`,
/// which returns `Elapsed` when the deadline elapses:
/// "Requires a Future to complete before the specified duration has elapsed. If
/// the future completes before the duration has elapsed, then the completed
/// value is returned. Otherwise, an error is returned and the future is
/// canceled", <https://docs.rs/tokio/latest/tokio/time/fn.timeout.html>). A
/// resolution that runs past that deadline on a loaded host must not consume the
/// whole row: the request is an idempotent GET for an immutable archive, so it
/// shares the body retry budget.
///
/// Local validation failures (for example a resolved address that is not
/// public) carry none of the retryable types and stay fatal, so a retry can
/// never mask a refusal.
fn is_retryable_connect_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        if cause.is::<tokio::time::error::Elapsed>() {
            return true;
        }
        if let Some(http) = cause.downcast_ref::<reqwest::Error>() {
            return http.is_timeout()
                || http.is_connect()
                || http.is_body()
                || crate::core::http::is_retryable_error(http);
        }
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::TimedOut)
    })
}

/// Stream a runtime artifact body into a same-filesystem temporary file with
/// bounded retry for transient mid-stream failures.
///
/// Each attempt performs its own request so a broken body is replaced instead
/// of resumed, the digest is computed over the bytes that actually landed, and
/// the caller verifies that digest before persisting `dest`.
async fn stream_runtime_download_to_temp<D, F, Fut>(
    host: &str,
    mut request: F,
    dest: &Path,
) -> Result<(tempfile::TempPath, String)>
where
    D: Digest + Default,
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<reqwest::Response>>,
{
    use futures::StreamExt;
    use tokio::io::AsyncWriteExt;

    let parent = dest.parent().unwrap_or_else(|| Path::new("."));
    tokio::fs::create_dir_all(parent)
        .await
        .with_context(|| format!("Failed to create parent directory: {}", parent.display()))?;
    let label = dest.file_name().map_or_else(
        || "download".to_string(),
        |name| name.to_string_lossy().into_owned(),
    );

    for attempt in 0..MAX_DOWNLOAD_ATTEMPTS {
        let response = match request().await {
            Ok(response) => response,
            Err(error) => {
                if attempt + 1 < MAX_DOWNLOAD_ATTEMPTS && is_retryable_connect_error(&error) {
                    // Local Debian sweep lane (run-mfY0GF) failed the Go row with
                    // "Failed to connect to go.dev: deadline has elapsed" while the
                    // host was loaded: our DNS deadline expired before any byte
                    // moved. Retry inside the same bounded budget the body uses.
                    tracing::warn!(
                        attempt = attempt + 1,
                        host,
                        "Runtime download connection failed; retrying bounded download"
                    );
                    tokio::time::sleep(crate::core::http::retry_backoff(
                        std::time::Duration::from_millis(100),
                        u32::try_from(attempt).unwrap_or(u32::MAX),
                    ))
                    .await;
                    continue;
                }
                return Err(error).with_context(|| format!("Failed to connect to {host}"));
            }
        };

        if !response.status().is_success() {
            let status = response.status();
            if status.as_u16() == 404 {
                anyhow::bail!(
                    "Version not found (404). Check available versions with: omg list --available"
                );
            }
            anyhow::bail!("Download failed: HTTP {status}");
        }

        let total_size = response.content_length().unwrap_or(0);
        anyhow::ensure!(
            total_size <= MAX_RUNTIME_DOWNLOAD_BYTES,
            "Runtime download declares {total_size} bytes, exceeding the {MAX_RUNTIME_DOWNLOAD_BYTES}-byte limit"
        );
        let task = ProgressTask::start(&TaskSpec {
            label: label.clone(),
            kind: TaskKind::Bytes {
                total: (total_size > 0).then_some(total_size),
            },
            accent: Accent::Network,
        });

        // Stream into a same-filesystem temporary file so a failed, aborted, or
        // checksum-mismatched download never leaves a partial artifact at `dest`.
        let temporary = tempfile::Builder::new()
            .prefix(".download-")
            .tempfile_in(parent)
            .with_context(|| {
                format!("Failed to create temporary download for {}", dest.display())
            })?;
        let (std_file, temporary_path) = temporary.into_parts();
        let mut file = tokio::fs::File::from_std(std_file);
        let mut stream = response.bytes_stream();
        let mut downloaded: u64 = 0;
        let mut hasher = D::default();
        let mut failure: Option<reqwest::Error> = None;

        while let Some(item) = stream.next().await {
            let chunk = match item {
                Ok(chunk) => chunk,
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            };
            file.write_all(&chunk)
                .await
                .context("Error writing to file")?;

            hasher.update(&chunk);

            downloaded = bounded_download_size(downloaded, chunk.len())?;
            task.set_position(downloaded);
        }

        if let Some(error) = failure {
            drop(file);
            drop(temporary_path);
            if attempt + 1 < MAX_DOWNLOAD_ATTEMPTS && is_retryable_download_stream_error(&error) {
                tracing::warn!(
                    attempt = attempt + 1,
                    host,
                    "Runtime download body failed; retrying bounded download"
                );
                tokio::time::sleep(crate::core::http::retry_backoff(
                    std::time::Duration::from_millis(100),
                    u32::try_from(attempt).unwrap_or(u32::MAX),
                ))
                .await;
                continue;
            }
            return Err(error).context("Error downloading chunk");
        }

        file.flush()
            .await
            .with_context(|| format!("Failed to flush download to: {}", dest.display()))?;
        file.sync_all()
            .await
            .with_context(|| format!("Failed to sync download to: {}", dest.display()))?;
        drop(file);

        let digest = hex::encode(hasher.finalize());
        task.finish(Outcome::Done);
        return Ok((temporary_path, digest));
    }
    unreachable!("final download attempt always returns")
}

/// Download a file with progress bar and checksum verification.
pub async fn download_with_progress(
    client: &reqwest::Client,
    url: &str,
    dest: &Path,
    expected_sha256: &str,
) -> Result<()> {
    // Vendor metadata supplies this URL: pin it to TLS on routable hosts so
    // tampered metadata cannot aim downloads at plain HTTP or private
    // network services.
    crate::core::http::validate_download_url(url)?;

    let (temporary_path, actual) = stream_runtime_download_to_temp::<Sha256, _, _>(
        extract_domain(url),
        || request_runtime_download(client, url),
        dest,
    )
    .await?;

    // Verify checksum before publishing the download to its final path.
    let expected = expected_sha256.trim();
    if !actual.eq_ignore_ascii_case(expected) {
        anyhow::bail!(
            "Checksum mismatch!\n  Expected: {expected}\n  Got: {actual}\n\nThis could indicate a corrupted download or security issue."
        );
    }

    temporary_path
        .persist(dest)
        .map_err(|error| error.error)
        .with_context(|| format!("Failed to finalize download: {}", dest.display()))?;
    Ok(())
}

/// Download a file with progress bar and SHA-512 verification.
///
/// Structural mirror of [`download_with_progress`] for vendors that publish
/// SHA-512 hashes (Microsoft's .NET release metadata).
pub async fn download_with_progress_sha512(
    client: &reqwest::Client,
    url: &str,
    dest: &Path,
    expected_sha512: &str,
) -> Result<()> {
    // Same metadata-supplied-URL pinning as the SHA-256 hot path.
    crate::core::http::validate_download_url(url)?;

    let (temporary_path, actual) = stream_runtime_download_to_temp::<Sha512, _, _>(
        extract_domain(url),
        || request_runtime_download(client, url),
        dest,
    )
    .await?;

    // Verify checksum before publishing the download to its final path.
    let expected = expected_sha512.trim();
    if !actual.eq_ignore_ascii_case(expected) {
        anyhow::bail!(
            "Checksum mismatch!\n  Expected: {expected}\n  Got: {actual}\n\nThis could indicate a corrupted download or security issue."
        );
    }

    temporary_path
        .persist(dest)
        .map_err(|error| error.error)
        .with_context(|| format!("Failed to finalize download: {}", dest.display()))?;
    Ok(())
}

fn bounded_download_size(downloaded: u64, chunk_size: usize) -> Result<u64> {
    let next = downloaded
        .checked_add(u64::try_from(chunk_size).context("Download chunk size does not fit u64")?)
        .context("Runtime download byte count overflowed")?;
    anyhow::ensure!(
        next <= MAX_RUNTIME_DOWNLOAD_BYTES,
        "Runtime download exceeded the {MAX_RUNTIME_DOWNLOAD_BYTES}-byte limit"
    );
    Ok(next)
}

enum PendingArchiveLink {
    Symbolic { path: PathBuf, target: PathBuf },
    Hard { path: PathBuf, target: PathBuf },
}

fn validate_relative_symlink_target(link_path: &Path, target: &Path) -> Result<()> {
    let mut resolved = link_path
        .parent()
        .map_or_else(PathBuf::new, Path::to_path_buf);
    for component in target.components() {
        match component {
            std::path::Component::Normal(part) => resolved.push(part),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                anyhow::ensure!(
                    resolved.pop(),
                    "Archive symlink escapes the extraction directory: {} -> {}",
                    link_path.display(),
                    target.display()
                );
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                anyhow::bail!(
                    "Archive symlink target must be relative: {} -> {}",
                    link_path.display(),
                    target.display()
                );
            }
        }
    }
    Ok(())
}

fn create_archive_links(links: Vec<PendingArchiveLink>, dest_dir: &Path) -> Result<()> {
    let root = dest_dir.canonicalize()?;
    let mut symbolic_paths = Vec::new();
    for link in links {
        match link {
            PendingArchiveLink::Symbolic { path, target } => {
                symbolic_paths.push(path.clone());
                #[cfg(unix)]
                std::os::unix::fs::symlink(&target, &path).with_context(|| {
                    format!(
                        "Failed to create archive symlink {} -> {}",
                        path.display(),
                        target.display()
                    )
                })?;
                #[cfg(not(unix))]
                anyhow::bail!(
                    "Runtime archive contains a symbolic link unsupported on this platform: {}",
                    path.display()
                );
            }
            PendingArchiveLink::Hard { path, target } => {
                let target = target
                    .canonicalize()
                    .context("Invalid archive hard link target")?;
                anyhow::ensure!(
                    target.starts_with(&root),
                    "Archive hard link escapes the extraction directory"
                );
                fs::hard_link(&target, &path).with_context(|| {
                    format!(
                        "Failed to create archive hard link {} -> {}",
                        path.display(),
                        target.display()
                    )
                })?;
            }
        }
    }
    for path in symbolic_paths {
        let resolved = path
            .canonicalize()
            .with_context(|| format!("Unresolvable archive symlink: {}", path.display()))?;
        anyhow::ensure!(
            resolved.starts_with(&root),
            "Archive symlink escapes the extraction directory: {}",
            path.display()
        );
    }
    Ok(())
}

/// Selector that maps one untrusted archive entry path to its
/// destination-relative path.
///
/// `None` skips the entry; `Some(relative)` extracts it below the
/// destination directory. Selectors must reject unsafe path components
/// (absolute roots, `..`) with an error instead of mapping them.
pub(crate) type TarEntrySelector<'a> = &'a (dyn Fn(&Path) -> Result<Option<PathBuf>> + 'a);

/// Process every tar entry selected by `select` into `dest_dir`, deferring
/// symlink/hard-link creation until all regular content exists.
///
/// `select` decides which entries are extracted and where they land below
/// `dest_dir`; entries mapping to `None` are skipped. Shared by the
/// whole-runtime extractors and the component extractors so the path, link,
/// and entry-type safety rules cannot drift between them.
fn extract_tar_entries<R: std::io::Read>(
    archive: &mut tar::Archive<R>,
    dest_dir: &Path,
    select: TarEntrySelector<'_>,
    task: &ProgressTask,
) -> Result<()> {
    task.set_message("Extracting...");
    let mut pending_links = Vec::new();

    let mut entry_budget = ArchiveEntryBudget::default();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        entry_budget.charge(&path)?;
        let Some(stripped) = select(&path)? else {
            continue;
        };

        let dest_path = dest_dir.join(&stripped);
        task.set_message(&format!("Extracting: {}", stripped.display()));

        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            fs::create_dir_all(&dest_path)?;
        } else if entry_type.is_file() {
            entry.unpack(&dest_path)?;
        } else if entry_type.is_symlink() {
            let target = entry
                .link_name()?
                .context("Archive symlink is missing its target")?
                .into_owned();
            validate_relative_symlink_target(&stripped, &target)?;
            pending_links.push(PendingArchiveLink::Symbolic {
                path: dest_path,
                target,
            });
        } else if entry_type.is_hard_link() {
            let target = entry
                .link_name()?
                .context("Archive hard link is missing its target")?;
            let target_relative = select(&target)?
                .context("Archive hard link target was excluded by the entry selector")?;
            pending_links.push(PendingArchiveLink::Hard {
                path: dest_path,
                target: dest_dir.join(target_relative),
            });
        } else {
            anyhow::bail!(
                "Unsupported special entry in runtime archive: {}",
                path.display()
            );
        }
    }
    create_archive_links(pending_links, dest_dir)
}

/// Synchronously extract selected entries from a .tar.gz component archive
/// with a bounded decompression budget.
///
/// Also backs whole-runtime extraction: [`extract_tar_gz`] calls this with the
/// default strip selector and [`MAX_DECOMPRESSED_BYTES`].
pub(crate) fn extract_component_tar_gz(
    archive_path: &Path,
    dest_dir: &Path,
    budget: u64,
    select: TarEntrySelector<'_>,
) -> Result<()> {
    let file = File::open(archive_path)
        .with_context(|| format!("Failed to open archive: {}", archive_path.display()))?;

    let decoder = flate2::read::GzDecoder::new(BufReader::new(file));
    let bounded = BudgetedReader::new(decoder, budget);
    let mut archive = tar::Archive::new(bounded);

    let task = extract_task(archive_path);

    fs::create_dir_all(dest_dir)?;
    extract_tar_entries(&mut archive, dest_dir, select, &task)?;

    task.finish(Outcome::Done);
    Ok(())
}

/// Extract a .tar.gz archive with progress
pub(crate) async fn extract_tar_gz(
    archive_path: &Path,
    dest_dir: &Path,
    strip_components: usize,
) -> Result<()> {
    let archive_path = archive_path.to_path_buf();
    let dest_dir = dest_dir.to_path_buf();

    tokio::task::spawn_blocking(move || {
        let select = |path: &Path| -> Result<Option<PathBuf>> {
            stripped_archive_path(path, strip_components)
        };
        let task = extract_task(&archive_path);
        let result =
            extract_component_tar_gz(&archive_path, &dest_dir, MAX_DECOMPRESSED_BYTES, &select);
        task.finish(Outcome::Done);
        result
    })
    .await?
}

/// Report an archive's byte size and SHA-256 for failure diagnostics.
///
/// Used only on the decompression failure path, where the archive was already
/// checksum-verified at download time; the identity makes "bytes changed after
/// verification" distinguishable from "the decoder rejects this input". The
/// digest streams through a fixed buffer because a runtime archive may be up
/// to [`MAX_RUNTIME_DOWNLOAD_BYTES`], which must not be buffered in a guest.
fn archive_identity(archive_path: &Path) -> (u64, String) {
    use std::io::Read as _;

    let mut file = match File::open(archive_path) {
        Ok(file) => file,
        Err(error) => return (0, format!("unreadable: {error}")),
    };
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                hasher.update(&buffer[..read]);
                total = total.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
            }
            Err(error) => {
                return (total, format!("unreadable after {total} bytes: {error}"));
            }
        }
    }
    (total, hex::encode(hasher.finalize()))
}

/// Synchronously extract selected entries from a .tar.xz component archive
/// with a bounded decompression budget.
///
/// lzma-rs exposes a `Read -> Write` API rather than a streaming decoder, so
/// the bounded output is kept in a same-filesystem temporary file: a valid
/// archive never needs its whole decompressed tar payload on the heap, and an
/// over-budget archive aborts before any output is published. Also backs
/// whole-runtime extraction: [`extract_tar_xz`] calls this with the default
/// strip selector and [`MAX_DECOMPRESSED_BYTES`].
pub(crate) fn extract_component_tar_xz(
    archive_path: &Path,
    dest_dir: &Path,
    budget: u64,
    select: TarEntrySelector<'_>,
) -> Result<()> {
    let file = File::open(archive_path)
        .with_context(|| format!("Failed to open archive: {}", archive_path.display()))?;

    let task = extract_task(archive_path);
    task.set_message("Decompressing XZ...");

    fs::create_dir_all(dest_dir)?;
    let output = tempfile::tempfile_in(dest_dir).with_context(|| {
        format!(
            "Failed to create temporary XZ output in {}",
            dest_dir.display()
        )
    })?;
    let mut output = BudgetedWriter::new(output, budget);
    if let Err(error) = lzma_rs::xz_decompress(&mut BufReader::new(file), &mut output) {
        // A digest-verified archive that later fails to decode means either the
        // bytes changed after verification or the decoder hit input it cannot
        // represent. Sizes and digests make that decidable from the log alone;
        // see the intermittent Fedora runtime-node-install failure where the
        // download verified but the decode reported a bogus LZ distance.
        let (bytes, digest) = archive_identity(archive_path);
        return Err(anyhow::Error::new(error).context(format!(
            "Failed to decompress XZ archive (archive={} bytes={bytes} sha256={digest})",
            archive_path.display()
        )));
    }
    let mut output = output.into_inner();
    output.seek(SeekFrom::Start(0))?;

    let mut archive = tar::Archive::new(output);
    extract_tar_entries(&mut archive, dest_dir, select, &task)?;

    task.finish(Outcome::Done);
    Ok(())
}

/// Extract a .tar.xz archive with progress (pure Rust)
pub(crate) async fn extract_tar_xz(
    archive_path: &Path,
    dest_dir: &Path,
    strip_components: usize,
) -> Result<()> {
    let archive_path = archive_path.to_path_buf();
    let dest_dir = dest_dir.to_path_buf();

    tokio::task::spawn_blocking(move || {
        let select = |path: &Path| -> Result<Option<PathBuf>> {
            stripped_archive_path(path, strip_components)
        };
        let task = extract_task(&archive_path);
        task.set_message("Decompressing XZ...");
        let result =
            extract_component_tar_xz(&archive_path, &dest_dir, MAX_DECOMPRESSED_BYTES, &select);
        task.finish(Outcome::Done);
        result
    })
    .await?
}

/// Extract a .zip archive with progress
pub(crate) async fn extract_zip(
    archive_path: &Path,
    dest_dir: &Path,
    strip_components: usize,
) -> Result<()> {
    let archive_path = archive_path.to_path_buf();
    let dest_dir = dest_dir.to_path_buf();

    tokio::task::spawn_blocking(move || {
        let file = File::open(&archive_path)
            .with_context(|| format!("Failed to open archive: {}", archive_path.display()))?;

        let mut archive = zip::ZipArchive::new(file).context("Failed to read ZIP archive")?;

        let task = extract_task(&archive_path);
        task.set_message("Extracting...");

        fs::create_dir_all(&dest_dir)?;
        let mut remaining_budget = MAX_DECOMPRESSED_BYTES;

        let mut entry_budget = ArchiveEntryBudget::default();
        anyhow::ensure!(archive.len() <= MAX_ARCHIVE_ENTRIES, "Archive contains too many entries");
        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let path = file.enclosed_name().ok_or_else(|| {
                anyhow::anyhow!("Unsafe path in runtime ZIP archive: {}", file.name())
            })?;
            entry_budget.charge(&path)?;
            let Some(stripped) = stripped_archive_path(&path, strip_components)? else {
                continue;
            };
            if file.is_symlink() {
                anyhow::bail!(
                    "Unsupported symlink entry in runtime ZIP archive: {}",
                    path.display()
                );
            }

            let dest_path = dest_dir.join(&stripped);
            task.set_message(&format!("Extracting: {}", stripped.display()));

            if file.is_dir() {
                fs::create_dir_all(&dest_path)?;
            } else {
                if let Some(parent) = dest_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                anyhow::ensure!(
                    file.size() <= remaining_budget,
                    "decompressed ZIP data exceeds the maximum supported size of {MAX_DECOMPRESSED_BYTES} bytes"
                );
                let mut outfile = File::create(&dest_path)?;
                if let Err(error) = copy_with_budget(&mut file, &mut outfile, &mut remaining_budget) {
                    drop(outfile);
                    let _ = fs::remove_file(&dest_path);
                    return Err(error).context("Runtime ZIP exceeded decompression budget");
                }

                // Preserve ordinary permission bits on Unix; never restore
                // setuid, setgid, or sticky bits from an untrusted archive.
                #[cfg(unix)]
                if let Some(mode) = file.unix_mode() {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&dest_path, fs::Permissions::from_mode(mode & 0o777))?;
                }
            }
        }

        task.finish(Outcome::Done);
        Ok(())
    })
    .await?
}

/// One shared spinner lane for archive extraction work.
fn extract_task(archive_path: &Path) -> ProgressTask {
    ProgressTask::start(&TaskSpec {
        label: archive_path.file_name().map_or_else(
            || "archive".to_string(),
            |name| name.to_string_lossy().into_owned(),
        ),
        kind: TaskKind::Spinner,
        accent: Accent::System,
    })
}

const INSTALL_MARKER: &str = ".omg-install-complete";

/// Best-effort file removal for leftover archives and stale current links.
/// Failure only wastes cache space or leaves a dangling symlink; the next
/// successful install or activation repairs it.
pub(crate) fn remove_file_best_effort(path: &Path, kind: &str) {
    if let Err(error) = fs::remove_file(path) {
        tracing::debug!("Failed to remove {kind} {}: {error}", path.display());
    }
}

/// Own download files until verification and extraction finish.
///
/// The versions directory must already exist. The private directory is removed
/// on ordinary return, error, or task cancellation; concurrent installs never
/// share an archive path even when vendors reuse the same asset filename.
pub(crate) fn begin_download(versions_dir: &Path) -> Result<tempfile::TempDir> {
    tempfile::Builder::new()
        .prefix(".download-")
        .tempdir_in(versions_dir)
        .context("Failed to create private runtime download directory")
}

/// Remove all contents of `dir` without removing `dir` itself.
///
/// Used when a staged extraction must be retried with a different layout:
/// the staging directory stays put so its same-filesystem atomic publish
/// still holds.
pub(crate) fn clear_dir_contents(dir: &Path) -> Result<()> {
    for entry in
        fs::read_dir(dir).with_context(|| format!("Failed to re-stage {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_symlink() || path.is_file() {
            fs::remove_file(&path)?;
        } else {
            fs::remove_dir_all(&path)?;
        }
    }
    Ok(())
}

/// Begin a same-filesystem staged runtime install.
///
/// Extraction writes into the returned staging directory, which only becomes
/// the final version directory when [`complete_staged_install`] publishes it
/// after a successful extraction. An interrupted install therefore never
/// leaves a version directory that looks installed.
pub(crate) fn begin_staged_install(versions_dir: &Path) -> Result<tempfile::TempDir> {
    crate::core::paths::create_private_data_directory(versions_dir).with_context(|| {
        format!(
            "Failed to create runtime versions directory: {}",
            versions_dir.display()
        )
    })?;
    tempfile::Builder::new()
        .prefix(".install-")
        .tempdir_in(versions_dir)
        .with_context(|| {
            format!(
                "Failed to create runtime staging directory in {}",
                versions_dir.display()
            )
        })
}

/// Atomically publish a staged runtime installation.
///
/// Writes the completion marker, then renames the staging directory into its
/// final path on the same filesystem. Fails if the final path appeared during
/// staging (for example, a concurrent install).
pub(crate) fn complete_staged_install(
    staging: &tempfile::TempDir,
    version_dir: &Path,
    version: &str,
) -> Result<()> {
    let mutation_lease = try_lock_runtime_file(
        version_dir
            .parent()
            .context("Runtime version has no parent")?,
        ".mutation.lock",
    )?;
    complete_staged_install_with_lease(staging, version_dir, version, &mutation_lease)
}

/// [`complete_staged_install`] for a caller that already holds the versions
/// directory mutation lease. Rust toolchain operations hold one lease across
/// the whole mutation; nested publication must reuse it because flock is not
/// re-entrant within a process.
pub(crate) fn complete_staged_install_with_lease(
    staging: &tempfile::TempDir,
    version_dir: &Path,
    version: &str,
    _mutation_lease: &fs::File,
) -> Result<()> {
    write_install_marker(staging.path(), version)?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            staging.path(),
            rustix::fs::CWD,
            version_dir,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .with_context(|| {
            format!(
                "Failed to publish runtime installation at {}",
                version_dir.display()
            )
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    anyhow::bail!("Atomic runtime publication is unsupported on this platform")
}

/// Atomically replace a published runtime directory with a staged successor.
///
/// The staging guard owns the retired tree after the exchange. Publication
/// never removes the version path, even if the process exits before cleanup.
/// This does not guarantee durability across power loss.
pub(crate) fn replace_staged_install(
    staging: &tempfile::TempDir,
    version_dir: &Path,
    version: &str,
) -> Result<()> {
    let mutation_lease = try_lock_runtime_file(
        version_dir
            .parent()
            .context("Runtime version has no parent")?,
        ".mutation.lock",
    )?;
    replace_staged_install_with_lease(staging, version_dir, version, &mutation_lease)
}

/// [`replace_staged_install`] for a caller that already holds the mutation
/// lease (see [`complete_staged_install_with_lease`]).
pub(crate) fn replace_staged_install_with_lease(
    staging: &tempfile::TempDir,
    version_dir: &Path,
    version: &str,
    _mutation_lease: &fs::File,
) -> Result<()> {
    write_install_marker(staging.path(), version)?;
    if !is_valid_version_dir(version_dir) {
        anyhow::bail!(
            "Cannot replace missing or invalid runtime version: {}",
            version_dir.display()
        );
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            staging.path(),
            rustix::fs::CWD,
            version_dir,
            rustix::fs::RenameFlags::EXCHANGE,
        )
        .with_context(|| {
            format!(
                "Failed to atomically replace runtime version at {}",
                version_dir.display()
            )
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    anyhow::bail!("Atomic runtime replacement is unsupported on this platform")
}

/// Copy a directory tree of regular files and directories only.
///
/// Symlinks and special files are rejected so a staged replacement cannot
/// inherit a link that later escapes the published version directory.
pub(crate) fn copy_regular_tree(src: &Path, dest: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(src)
        .with_context(|| format!("Failed to inspect source path: {}", src.display()))?;
    if !metadata.is_dir() {
        anyhow::bail!("Source is not a regular directory: {}", src.display());
    }
    fs::create_dir_all(dest)
        .with_context(|| format!("Failed to create destination directory: {}", dest.display()))?;
    copy_regular_tree_contents(src, dest)
}

fn copy_regular_tree_contents(src: &Path, dest: &Path) -> Result<()> {
    for entry in
        fs::read_dir(src).with_context(|| format!("Failed to read directory: {}", src.display()))?
    {
        let entry = entry
            .with_context(|| format!("Failed to read directory entry in {}", src.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("Failed to inspect {}", entry.path().display()))?;
        let dest_path = dest.join(entry.file_name());
        if file_type.is_dir() {
            fs::create_dir_all(&dest_path)
                .with_context(|| format!("Failed to create directory: {}", dest_path.display()))?;
            copy_regular_tree_contents(&entry.path(), &dest_path)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), &dest_path).with_context(|| {
                format!(
                    "Failed to copy {} to {}",
                    entry.path().display(),
                    dest_path.display()
                )
            })?;
        } else {
            anyhow::bail!(
                "Refusing to copy symlink or special file: {}",
                entry.path().display()
            );
        }
    }
    Ok(())
}

fn write_install_marker(version_dir: &Path, version: &str) -> Result<()> {
    let mut marker = tempfile::NamedTempFile::new_in(version_dir).with_context(|| {
        format!(
            "Failed to create install marker in {}",
            version_dir.display()
        )
    })?;
    writeln!(marker, "{version}")?;
    marker.as_file_mut().sync_all()?;
    marker
        .persist(version_dir.join(INSTALL_MARKER))
        .map_err(|error| error.error)
        .with_context(|| {
            format!(
                "Failed to persist install marker in {}",
                version_dir.display()
            )
        })?;
    Ok(())
}

pub(crate) const TEST_RUNTIME_MARKER: &str = ".omg-test-mock";
pub(crate) const INSTALL_PENDING_MARKER: &str = ".omg-installing";

pub(crate) fn try_lock_runtime_install(versions_dir: &Path, version: &str) -> Result<File> {
    crate::core::security::validate_runtime_version(version)?;
    try_lock_runtime_file(versions_dir, &format!(".install-{version}.lock"))
}

fn try_lock_runtime_file(versions_dir: &Path, name: &str) -> Result<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    crate::core::paths::create_private_data_directory(versions_dir)?;
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(versions_dir.join(name))?;
    let metadata = lock.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.nlink() == 1,
        "Unsafe runtime install lock"
    );
    lock.try_lock()
        .context("Another runtime mutation is in progress; retry when it finishes")?;
    Ok(lock)
}

/// Return whether a runtime version path is a real production directory.
///
/// Debug-only synthetic runtimes are marked and never considered installed or
/// eligible for activation after the test-mode process exits.
#[must_use]
pub(crate) fn is_valid_version_dir(version_dir: &Path) -> bool {
    fs::symlink_metadata(version_dir).is_ok_and(|metadata| metadata.is_dir())
        && !version_dir.join(TEST_RUNTIME_MARKER).exists()
        && matches!(fs::symlink_metadata(version_dir.join(INSTALL_PENDING_MARKER)), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
}

/// Return whether a runtime binary directory is safe to prepend to `PATH`.
///
/// It must be a real directory owned by the current user (or root) and not
/// writable by group/other users. This prevents a repository pin from making
/// an attacker-writable runtime tree shadow ordinary commands.
#[must_use]
fn is_trusted_runtime_dir_chain(path: &Path, boundary: &Path) -> bool {
    if !path.starts_with(boundary) {
        return false;
    }
    for directory in path.ancestors() {
        let Ok(metadata) = fs::symlink_metadata(directory) else {
            return false;
        };
        if !metadata.file_type().is_dir() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let current_uid = nix::unistd::geteuid().as_raw();
            if (metadata.uid() != 0 && metadata.uid() != current_uid)
                || metadata.mode() & 0o022 != 0
            {
                return false;
            }
        }
        if directory == boundary {
            return true;
        }
    }
    false
}

#[must_use]
pub(crate) fn is_trusted_runtime_bin_dir(path: &Path) -> bool {
    let data_dir = crate::core::paths::data_dir();
    if path.starts_with(&data_dir) {
        return is_trusted_runtime_dir_chain(path, &data_dir);
    }
    if let Some(home) = home::home_dir()
        && path.starts_with(&home)
    {
        return is_trusted_runtime_dir_chain(path, &home);
    }
    // Non-standard roots have no trustworthy ownership boundary. Keep the
    // leaf-only fallback for system-managed paths such as `/opt`, while all
    // user-controlled runtime layouts above validate their full chain.
    is_trusted_runtime_dir_chain(path, path)
}

/// Require a regular file at `path`. Symlinks, directories, and missing paths fail closed.
pub(crate) fn require_regular_file(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => anyhow::bail!(
            "Expected a regular file at {}, found a symlink or special path",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!("Missing required runtime binary: {}", path.display())
        }
        Err(error) => Err(error)
            .with_context(|| format!("Failed to inspect runtime binary: {}", path.display())),
    }
}

/// Activate a runtime version only after its expected binary is a regular file.
pub(crate) fn activate_version(
    versions_dir: &Path,
    version: &str,
    expected_binary: &Path,
) -> Result<()> {
    let mutation_lease = try_lock_runtime_file(versions_dir, ".mutation.lock")?;
    activate_version_with_lease(versions_dir, version, expected_binary, &mutation_lease)
}

/// [`activate_version`] for a caller that already holds the mutation lease.
pub(crate) fn activate_version_with_lease(
    versions_dir: &Path,
    version: &str,
    expected_binary: &Path,
    mutation_lease: &fs::File,
) -> Result<()> {
    require_regular_file(&versions_dir.join(version).join(expected_binary))?;
    set_current_version_with_lease(versions_dir, version, mutation_lease)
}

/// Activate a runtime whose vendor launcher may be an internal symlink.
///
/// The resolved launcher must remain inside the real version directory and end
/// at a regular file. Absolute or relative links that escape the version tree
/// fail closed.
pub(crate) fn activate_version_with_linked_binary(
    versions_dir: &Path,
    version: &str,
    expected_binary: &Path,
) -> Result<()> {
    let mutation_lease = try_lock_runtime_file(versions_dir, ".mutation.lock")?;
    activate_version_with_linked_binary_with_lease(
        versions_dir,
        version,
        expected_binary,
        &mutation_lease,
    )
}

/// [`activate_version_with_linked_binary`] for a caller that already holds
/// the mutation lease.
pub(crate) fn activate_version_with_linked_binary_with_lease(
    versions_dir: &Path,
    version: &str,
    expected_binary: &Path,
    mutation_lease: &fs::File,
) -> Result<()> {
    require_internal_runtime_binary(&versions_dir.join(version), expected_binary)?;
    set_current_version_with_lease(versions_dir, version, mutation_lease)
}

pub(crate) fn require_internal_runtime_binary(
    version_dir: &Path,
    expected_binary: &Path,
) -> Result<()> {
    let candidate = version_dir.join(expected_binary);
    let metadata = fs::symlink_metadata(&candidate)
        .with_context(|| format!("Failed to inspect runtime binary: {}", candidate.display()))?;
    if metadata.is_file() {
        return Ok(());
    }
    if !metadata.file_type().is_symlink() {
        anyhow::bail!(
            "Expected a regular file or internal symlink at {}, found a special path",
            candidate.display()
        );
    }

    let canonical_version = fs::canonicalize(version_dir).with_context(|| {
        format!(
            "Failed to resolve runtime version directory: {}",
            version_dir.display()
        )
    })?;
    let canonical_binary = fs::canonicalize(&candidate)
        .with_context(|| format!("Failed to resolve runtime binary: {}", candidate.display()))?;
    if !canonical_binary.starts_with(&canonical_version) {
        anyhow::bail!(
            "Runtime binary symlink escapes version directory: {}",
            candidate.display()
        );
    }
    require_regular_file(&canonical_binary)
}

/// Remove an installed runtime version directory.
///
/// Refuses when the version is active (switch first), when the version is
/// not installed, and when the version path is not a real directory:
/// following a symlink here could delete outside the versions tree.
/// Mirrors the validation `set_current_version` applies on the way in.
pub(crate) fn uninstall_version(versions_dir: &Path, version: &str) -> Result<()> {
    crate::core::security::validate_runtime_version(version)?;
    let mutation_lease = try_lock_runtime_file(versions_dir, ".mutation.lock")?;
    uninstall_version_with_lease(versions_dir, version, &mutation_lease)
}

/// [`uninstall_version`] for a caller that already holds the mutation lease.
pub(crate) fn uninstall_version_with_lease(
    versions_dir: &Path,
    version: &str,
    _mutation_lease: &fs::File,
) -> Result<()> {
    crate::core::security::validate_runtime_version(version)?;

    // is_valid_version_dir rejects symlinks, so the removal below cannot
    // escape the versions tree through a linked version path.
    let version_dir = versions_dir.join(version);
    if !is_valid_version_dir(&version_dir) {
        anyhow::bail!("Version {version} is not installed; nothing to remove");
    }
    if fs::read_link(versions_dir.join("current"))
        .ok()
        .is_some_and(|target| target.ends_with(version))
    {
        anyhow::bail!("Version {version} is active; switch to another version before removing it");
    }
    fs::remove_dir_all(&version_dir).with_context(|| {
        format!(
            "Failed to remove runtime version directory: {}",
            version_dir.display()
        )
    })?;
    Ok(())
}

/// Create or update the "current" symlink
pub(crate) fn set_current_version(versions_dir: &Path, version: &str) -> Result<()> {
    crate::core::security::validate_runtime_version(version)?;
    let mutation_lease = try_lock_runtime_file(versions_dir, ".mutation.lock")?;
    set_current_version_with_lease(versions_dir, version, &mutation_lease)
}

/// [`set_current_version`] for a caller that already holds the mutation lease.
pub(crate) fn set_current_version_with_lease(
    versions_dir: &Path,
    version: &str,
    _mutation_lease: &fs::File,
) -> Result<()> {
    crate::core::security::validate_runtime_version(version)?;

    let current_link = versions_dir.join("current");
    let version_dir = versions_dir.join(version);

    if !is_valid_version_dir(&version_dir) {
        anyhow::bail!(
            "Version {version} is not installed as a valid directory. Install it first with: omg use <runtime>@{version}"
        );
    }

    #[cfg(not(unix))]
    anyhow::bail!("Runtime version switching is unsupported on this platform");

    #[cfg(unix)]
    {
        match fs::symlink_metadata(&current_link) {
            Ok(metadata) if !metadata.file_type().is_symlink() => {
                anyhow::bail!(
                    "Refusing to replace non-symlink current runtime path: {}",
                    current_link.display()
                );
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "Failed to inspect current runtime path: {}",
                        current_link.display()
                    )
                });
            }
        }

        let temp_link = tempfile::Builder::new()
            .prefix(".current-")
            .tempfile_in(versions_dir)
            .with_context(|| {
                format!(
                    "Failed to create temporary runtime link in {}",
                    versions_dir.display()
                )
            })?
            .into_temp_path();
        fs::remove_file(&temp_link).with_context(|| {
            format!(
                "Failed to prepare temporary runtime link: {}",
                temp_link.display()
            )
        })?;
        std::os::unix::fs::symlink(&version_dir, &temp_link).with_context(|| {
            format!(
                "Failed to create temporary runtime link: {}",
                temp_link.display()
            )
        })?;
        fs::rename(&temp_link, &current_link).with_context(|| {
            format!(
                "Failed to activate runtime version {version} at {}",
                current_link.display()
            )
        })?;

        Ok(())
    }
}

/// Get the current version from the "current" symlink
pub(crate) fn get_current_version(versions_dir: &Path) -> Option<String> {
    let current_link = versions_dir.join("current");
    let target = fs::read_link(&current_link).ok()?;
    let version = target.file_name()?.to_string_lossy().into_owned();
    let expected = versions_dir.join(&version);
    if !is_valid_version_dir(&expected) {
        return None;
    }

    let target = if target.is_absolute() {
        target
    } else {
        current_link.parent()?.join(target)
    };
    let target = fs::canonicalize(target).ok()?;
    let expected = fs::canonicalize(expected).ok()?;
    (target == expected).then_some(version)
}

/// List installed versions in a directory
pub(crate) fn list_installed_versions(versions_dir: &Path) -> Result<Vec<String>> {
    // Query once and preserve access errors: Path::exists() would turn an
    // unreadable parent into a false, successful empty installation inventory.
    let entries = match fs::read_dir(versions_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };

    let mut versions = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        // Skip the "current" symlink and dot-prefixed entries (e.g. staging
        // directories left by an interrupted install, which must never be
        // reported as installed versions).
        if name.starts_with('.') || name == "current" || !is_valid_version_dir(&entry.path()) {
            continue;
        }
        versions.push(name);
    }

    versions.sort_by(|a, b| version_cmp(b, a).then_with(|| b.cmp(a)));
    Ok(versions)
}

/// Compare version strings in ascending order.
///
/// Semantic versions use SemVer precedence, including pre-release ordering.
/// Other vendor formats fall back to unbounded numeric component comparison.
#[must_use]
pub(crate) fn version_cmp(a: &str, b: &str) -> Ordering {
    if let (Ok(a), Ok(b)) = (
        semver::Version::parse(a.trim_start_matches(['v', 'V'])),
        semver::Version::parse(b.trim_start_matches(['v', 'V'])),
    ) {
        return a.cmp(&b);
    }

    fn numeric_parts(version: &str) -> Vec<&str> {
        version
            .split(|character: char| !character.is_ascii_digit())
            .filter(|part| !part.is_empty())
            .collect()
    }

    fn compare_numeric_parts(left: &str, right: &str) -> Ordering {
        let left = left.trim_start_matches('0');
        let right = right.trim_start_matches('0');
        let left = if left.is_empty() { "0" } else { left };
        let right = if right.is_empty() { "0" } else { right };
        left.len().cmp(&right.len()).then_with(|| left.cmp(right))
    }

    let a_parts = numeric_parts(a);
    let b_parts = numeric_parts(b);
    let max_len = a_parts.len().max(b_parts.len());

    (0..max_len)
        .map(|index| {
            compare_numeric_parts(
                a_parts.get(index).copied().unwrap_or("0"),
                b_parts.get(index).copied().unwrap_or("0"),
            )
        })
        .find(|&ordering| ordering != Ordering::Equal)
        .unwrap_or(Ordering::Equal)
}

/// Normalize version string (remove leading 'v' if present)
/// Normalize a version string by stripping a single leading 'v' prefix.
#[must_use]
pub(crate) fn normalize_version(version: &str) -> String {
    let bytes = version.as_bytes();
    if matches!(bytes.first(), Some(b'v' | b'V')) && bytes.get(1).is_some_and(u8::is_ascii_digit) {
        version[1..].to_owned()
    } else {
        version.to_owned()
    }
}

/// Return whether a requested version is a partial semver request — one or
/// two all-numeric dot-separated components such as `20` or `3.12`.
///
/// Only partial requests need vendor-list resolution; exact versions and
/// aliases (`latest`, `lts/iron`, `1.22rc1`) pass through untouched.
#[must_use]
pub(crate) fn is_partial_version(requested: &str) -> bool {
    let requested = normalize_version(requested);
    let parts: Vec<&str> = requested.split('.').collect();
    (1..=2).contains(&parts.len())
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Resolve a partial version request against a vendor's available list.
///
/// A request is resolvable when it is one to three dot-separated numeric
/// components. A partial request (`20`, `3.12`) resolves to the newest
/// available version extending it at a component boundary (`3.12` matches
/// `3.12.7` but never `3.120.0`). A fully-specified request passes through
/// only when present in `available`. Anything else — including garbage —
/// returns `None`, and callers fall back to the requested string so the
/// existing not-found UX applies unchanged.
#[must_use]
pub(crate) fn resolve_partial_version(available: &[String], requested: &str) -> Option<String> {
    let requested = normalize_version(requested);
    let parts: Vec<&str> = requested.split('.').collect();
    if parts.len() > 3
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    let extends_request = |candidate: &str| -> bool {
        let candidate = candidate.trim_start_matches(['v', 'V']);
        let candidate_parts: Vec<&str> = candidate.split('.').collect();
        candidate_parts.len() >= parts.len() && candidate_parts[..parts.len()] == parts[..]
    };
    available
        .iter()
        .filter(|candidate| extends_request(candidate))
        .max_by(|a, b| version_cmp(a, b))
        .map(|newest| newest.trim_start_matches(['v', 'V']).to_owned())
}

/// Parse and validate a SHA-256 digest returned by a runtime vendor.
///
/// Vendors may serve the digest alone or as `"<hex>  <filename>"`; only the
/// digest is returned. Rejects anything that is not exactly 64 hex characters.
pub(crate) fn parse_sha256_digest(value: &str, source: &str) -> Result<String> {
    let digest = value
        .split_whitespace()
        .next()
        .and_then(|digest| digest.strip_prefix("sha256:").or(Some(digest)))
        .filter(|digest| digest.len() == 64 && digest.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| anyhow::anyhow!("Invalid SHA-256 digest returned by {source}"))?;
    Ok(digest.to_ascii_lowercase())
}

/// Validate a vendor-supplied SHA-512 checksum (128 lowercase hex digits),
/// accepting an optional `sha512:` prefix and manifest-style trailing text.
pub(crate) fn parse_sha512_digest(value: &str, source: &str) -> Result<String> {
    let digest = value
        .split_whitespace()
        .next()
        .and_then(|digest| digest.strip_prefix("sha512:").or(Some(digest)))
        .filter(|digest| digest.len() == 128 && digest.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| anyhow::anyhow!("Invalid SHA-512 digest returned by {source}"))?;
    Ok(digest.to_ascii_lowercase())
}

/// Extract domain from URL for error messages
fn extract_domain(url: &str) -> &str {
    url.split("://")
        .nth(1)
        .and_then(|s| s.split('/').next())
        .unwrap_or(url)
}

/// Print installation success message
pub(crate) fn print_installed(runtime: &str, version: &str) {
    println!(
        "\n{} {} {} installed successfully!",
        style::positive("✓"),
        style::runtime(runtime),
        style::caution(version)
    );
}

/// Print version switch message
pub(crate) fn print_using(runtime: &str, version: &str, bin_path: &Path) {
    println!(
        "{} Now using {} {}",
        style::positive("✓"),
        style::runtime(runtime),
        style::caution(version)
    );
    println!("  {} {}", style::dim("PATH:"), bin_path.display());
}

/// Print already installed message
pub(crate) fn print_already_installed(runtime: &str, version: &str) {
    println!(
        "{} {} {} is already installed",
        style::positive("✓"),
        style::runtime(runtime),
        style::caution(version)
    );
}

/// Implement the shared runtime-manager methods for a manager with a
/// `versions_dir` field.
macro_rules! impl_runtime_common {
    ($manager_type:ty) => {
        impl $manager_type {
            /// List all installed versions of this runtime
            pub fn list_installed(&self) -> Result<Vec<String>> {
                $crate::runtimes::common::list_installed_versions(&self.versions_dir)
            }

            /// Get the currently active version
            #[must_use]
            pub fn current_version(&self) -> Option<String> {
                $crate::runtimes::common::get_current_version(&self.versions_dir)
            }
        }
    };
}
pub(crate) use impl_runtime_common;

/// Run newly downloaded runtime code without exposing the caller's credentials,
/// agents, language hooks, or package-manager configuration.
pub(crate) fn harden_untrusted_runtime_command(
    command: &mut std::process::Command,
    isolated_home: &Path,
) {
    command
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("HOME", isolated_home)
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8");
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::expect_used)] // Idiomatic in tests: panics on failure with clear error context
mod tests {
    #[tokio::test]
    async fn runtime_download_request_recovers_once_and_preserves_http_refusals()
    -> anyhow::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        for (stall_first, status, expected_requests) in [
            (true, "200 OK", 2),
            (false, "404 Not Found", 1),
            (false, "403 Forbidden", 1),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let url = format!("http://{}/archive", listener.local_addr()?);
            let client = reqwest::Client::builder()
                .no_proxy()
                .timeout(std::time::Duration::from_millis(100))
                .build()?;
            let server = async {
                let mut held = Vec::new();
                for attempt in 1..=expected_requests {
                    let (mut stream, _) = listener.accept().await?;
                    let mut request = [0; 4096];
                    let length = stream.read(&mut request).await?;
                    anyhow::ensure!(request[..length].starts_with(b"GET /archive HTTP/1.1\r\n"));
                    if stall_first && attempt == 1 {
                        held.push(stream); // Keep the first request pending until its client deadline.
                    } else {
                        stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 7\r\nConnection: close\r\n\r\nfixture").as_bytes()).await?;
                    }
                }
                Ok::<_, anyhow::Error>(held)
            };
            let request = async {
                let response = super::retry_runtime_request(&url, || {
                    let client = &client;
                    let url = &url;
                    async move { Ok(client.get(url).send().await?) }
                })
                .await?;
                assert_eq!(response.status().as_u16(), status[..3].parse::<u16>()?);
                assert_eq!(response.text().await?, "fixture");
                Ok::<_, anyhow::Error>(())
            };
            let (server, request) =
                tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    tokio::join!(server, request)
                })
                .await?;
            drop(server?);
            request?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn runtime_download_retries_a_truncated_body_before_verifying() -> anyhow::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/archive", listener.local_addr()?);
        let body = b"runtime archive fixture bytes".to_vec();
        let digest = hex::encode(Sha256::digest(&body));
        let server = async {
            let mut request = [0; 4096];
            // Attempt 1: advertise more bytes than the body contains and close
            // the connection, which surfaces as a mid-stream body error.
            let (mut stream, _) = listener.accept().await?;
            let _ = stream.read(&mut request).await?;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\nConnection: close\r\n\r\ntruncated",
                )
                .await?;
            drop(stream);
            // Attempt 2: the complete body.
            let (mut stream, _) = listener.accept().await?;
            let _ = stream.read(&mut request).await?;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await?;
            stream.write_all(&body).await?;
            Ok::<_, anyhow::Error>(())
        };
        let directory = tempfile::tempdir()?;
        let dest = directory.path().join("archive.tar.gz");
        let client = reqwest::Client::builder().no_proxy().build()?;
        let download = stream_runtime_download_to_temp::<Sha256, _, _>(
            "127.0.0.1",
            || {
                let client = client.clone();
                let url = url.clone();
                async move { Ok(client.get(url).send().await?) }
            },
            &dest,
        );
        let (server, download) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(server, download)
        })
        .await?;
        server?;
        let (temporary_path, actual) = download?;
        assert_eq!(actual, digest);
        temporary_path.persist(&dest).map_err(|error| error.error)?;
        assert_eq!(std::fs::read(&dest)?, body);
        Ok(())
    }

    #[tokio::test]
    async fn runtime_download_retries_a_connect_deadline_before_giving_up() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/archive", listener.local_addr()?);
        let body = b"runtime archive fixture bytes".to_vec();
        let digest = hex::encode(Sha256::digest(&body));
        let server = async {
            let mut request = [0; 4096];
            let (mut stream, _) = listener.accept().await?;
            let _ = stream.read(&mut request).await?;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await?;
            stream.write_all(&body).await?;
            Ok::<_, anyhow::Error>(())
        };
        let directory = tempfile::tempdir()?;
        let dest = directory.path().join("archive.tar.gz");
        let client = reqwest::Client::builder().no_proxy().build()?;
        let attempts = AtomicUsize::new(0);
        let download = stream_runtime_download_to_temp::<Sha256, _, _>(
            "127.0.0.1",
            || {
                let client = client.clone();
                let url = url.clone();
                let attempts = &attempts;
                async move {
                    // First attempt: our DNS deadline elapses before any request
                    // leaves the process, exactly like the Go row in the Debian
                    // sweep lane. The retry must still finish the download.
                    if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        let elapsed = tokio::time::timeout(
                            std::time::Duration::ZERO,
                            std::future::pending::<()>(),
                        )
                        .await
                        .expect_err("zero-duration deadline must elapse");
                        return Err(anyhow::Error::from(elapsed));
                    }
                    Ok(client.get(url).send().await?)
                }
            },
            &dest,
        );
        let (server, download) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(server, download)
        })
        .await?;
        server?;
        let (temporary_path, actual) = download?;
        assert_eq!(actual, digest);
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            2,
            "exactly one deadline retry must be used"
        );
        temporary_path.persist(&dest).map_err(|error| error.error)?;
        assert_eq!(std::fs::read(&dest)?, body);
        Ok(())
    }

    #[tokio::test]
    async fn runtime_download_connect_retry_keeps_local_refusals_fatal() {
        let elapsed = tokio::time::timeout(std::time::Duration::ZERO, std::future::pending::<()>())
            .await
            .expect_err("zero-duration deadline must elapse");
        assert!(is_retryable_connect_error(&anyhow::Error::from(elapsed)));
        let timed_out = std::io::Error::new(std::io::ErrorKind::TimedOut, "connect deadline");
        assert!(is_retryable_connect_error(&anyhow::Error::from(timed_out)));
        for permanent in [
            anyhow::anyhow!("Download resolves to a non-public address"),
            anyhow::anyhow!("Download URL must not contain credentials"),
            anyhow::anyhow!("Too many download redirects"),
        ] {
            assert!(
                !is_retryable_connect_error(&permanent),
                "{permanent} must stay fatal instead of being retried"
            );
        }
    }

    #[tokio::test]
    async fn runtime_download_request_ignores_caller_proxy_and_rejects_private_target()
    -> anyhow::Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let proxy = reqwest::Proxy::all(format!("http://{}", listener.local_addr()?))?;
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .timeout(std::time::Duration::from_secs(1))
            .build()?;
        let error = super::request_runtime_download(&client, "https://127.0.0.1/archive")
            .await
            .expect_err("private target must be rejected before any connection");
        assert!(format!("{error:#}").contains("private or local"));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "the caller's proxy must never see the request"
        );
        Ok(())
    }
    use super::*;
    use tempfile::TempDir;

    /// Uninstall removes the version directory, refuses the active
    /// version and missing versions, and never follows a symlinked
    /// version path outside the versions tree.
    #[cfg(unix)]
    #[test]
    fn uninstall_removes_only_inactive_real_version_dirs() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;
        let temp = TempDir::new()?;
        let versions = temp.path();
        for version in ["20.10.0", "22.0.0"] {
            let dir = versions.join(version);
            fs::create_dir_all(dir.join("bin"))?;
            fs::write(dir.join("bin").join("node"), b"fake")?;
        }
        symlink(versions.join("20.10.0"), versions.join("current"))?;

        assert!(uninstall_version(versions, "22.0.0").is_ok());
        assert!(!versions.join("22.0.0").exists());
        assert!(versions.join("20.10.0").exists());

        let active = uninstall_version(versions, "20.10.0").expect_err("active refusal");
        assert!(active.to_string().contains("active"), "{active:#}");
        assert!(versions.join("20.10.0").exists());

        let missing = uninstall_version(versions, "99.99.99").expect_err("missing refusal");
        assert!(missing.to_string().contains("not installed"), "{missing:#}");

        symlink(versions.join("20.10.0"), versions.join("9.9.9"))?;
        let linked = uninstall_version(versions, "9.9.9").expect_err("symlink refusal");
        assert!(linked.to_string().contains("not installed"), "{linked:#}");
        assert!(versions.join("20.10.0").exists());
        Ok(())
    }

    fn tar_archive(entry_type: tar::EntryType) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut builder = tar::Builder::new(&mut bytes);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(entry_type);
        header.set_mode(0o755);
        header.set_size(if entry_type.is_file() { 4 } else { 0 });
        header.set_cksum();
        builder
            .append_data(&mut header, "runtime/bin/tool", &b"tool"[..])
            .unwrap();
        builder.finish().unwrap();
        drop(builder);
        bytes
    }

    #[test]
    fn github_release_decodes_runtime_specific_payload_subsets() {
        let minimal: GithubRelease = serde_json::from_str(
            r#"{"tag_name":"v1.2.3","assets":[{"name":"runtime.zip","digest":"sha256:abc"}]}"#,
        )
        .unwrap();
        assert!(!minimal.prerelease);
        assert!(minimal.assets[0].browser_download_url.is_none());

        let downloadable: GithubRelease = serde_json::from_str(
            r#"{"tag_name":"v1.2.3","prerelease":true,"assets":[{"name":"runtime.tgz","browser_download_url":"https://example.invalid/runtime.tgz"}]}"#,
        )
        .unwrap();
        assert!(downloadable.prerelease);
        assert_eq!(
            downloadable.assets[0].browser_download_url.as_deref(),
            Some("https://example.invalid/runtime.tgz")
        );
    }

    #[test]
    fn github_rate_limit_diagnostic_fires_only_on_exhaustion() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "x-ratelimit-remaining",
            reqwest::header::HeaderValue::from_static("0"),
        );
        headers.insert(
            "x-ratelimit-reset",
            reqwest::header::HeaderValue::from_static("1893456000"),
        );
        let message =
            github_rate_limit_diagnostic(reqwest::StatusCode::FORBIDDEN, &headers).unwrap();
        assert!(message.contains("rate limit exhausted"));
        assert!(message.contains("1893456000"));

        *headers.get_mut("x-ratelimit-remaining").unwrap() =
            reqwest::header::HeaderValue::from_static("4999");
        assert!(
            github_rate_limit_diagnostic(reqwest::StatusCode::FORBIDDEN, &headers).is_none(),
            "remaining quota must not read as exhaustion"
        );
        *headers.get_mut("x-ratelimit-remaining").unwrap() =
            reqwest::header::HeaderValue::from_static("0");
        assert!(
            github_rate_limit_diagnostic(reqwest::StatusCode::OK, &headers).is_none(),
            "a successful final request must remain usable"
        );
    }

    #[tokio::test]
    async fn github_release_http_failures_never_return_partial_catalogs() -> Result<()> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpListener;

        // The first page is valid. A later failure must invalidate the entire
        // discovery, rather than presenting an incomplete version catalog.
        for (status, headers, body, expected) in [
            (
                "403 Forbidden",
                "X-RateLimit-Remaining: 0\r\nX-RateLimit-Reset: 1893456000\r\n",
                "{}",
                "rate limit exhausted",
            ),
            (
                "429 Too Many Requests",
                "X-RateLimit-Remaining: 0\r\nX-RateLimit-Reset: 1893456000\r\n",
                "{}",
                "rate limit exhausted",
            ),
            (
                "403 Forbidden",
                "X-RateLimit-Remaining: 4999\r\n",
                "{}",
                "403 Forbidden",
            ),
            (
                "500 Internal Server Error",
                "",
                "{}",
                "500 Internal Server Error",
            ),
            (
                "200 OK",
                "",
                "not-json",
                "Failed to parse GitHub releases payload",
            ),
            (
                "200 OK",
                "",
                "{\"message\":\"not a release list\"}",
                "Failed to parse GitHub releases payload",
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let url = format!("http://{}/releases", listener.local_addr()?);
            let client = reqwest::Client::builder().no_proxy().build()?;
            let server = async {
                for page in 1..=2 {
                    let (mut stream, _) = listener.accept().await?;
                    let mut reader = BufReader::new(&mut stream);
                    let mut request = String::new();
                    reader.read_line(&mut request).await?;
                    anyhow::ensure!(
                        request == format!("GET /releases?per_page=1&page={page} HTTP/1.1\r\n"),
                        "Unexpected release request: {request}"
                    );
                    let mut user_agent = false;
                    loop {
                        let mut line = String::new();
                        anyhow::ensure!(
                            reader.read_line(&mut line).await? > 0,
                            "Incomplete request"
                        );
                        if line == "\r\n" {
                            break;
                        }
                        if line.to_ascii_lowercase().starts_with("user-agent:") {
                            user_agent = line.trim().ends_with(GITHUB_USER_AGENT);
                        }
                    }
                    anyhow::ensure!(user_agent, "Missing runtime discovery user agent");
                    let (response_status, response_headers, payload) = if page == 1 {
                        ("200 OK", "", "[{\"tag_name\":\"v1.0.0\"}]")
                    } else {
                        (status, headers, body)
                    };
                    stream.write_all(format!(
                        "HTTP/1.1 {response_status}\r\n{response_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                        payload.len()
                    ).as_bytes()).await?;
                }
                Ok::<_, anyhow::Error>(())
            };
            let (result, served) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                tokio::join!(
                    fetch_github_releases(&client, &url, 1, 4, |_| false),
                    server
                )
            })
            .await
            .context("Release failure fixture timed out")?;
            served?;
            let error = format!(
                "{:#}",
                result.expect_err("A failed page must not return partial releases")
            );
            assert!(error.contains(expected), "{status}: {error}");
            if headers.contains("Remaining: 0") {
                assert!(
                    error.contains("1893456000"),
                    "Reset diagnostic missing: {error}"
                );
            } else {
                assert!(
                    !error.contains("rate limit exhausted"),
                    "Misclassified failure: {error}"
                );
                assert!(error.contains(&url), "Missing source context: {error}");
            }
        }
        Ok(())
    }

    #[test]
    fn normalize_version_accepts_common_v_prefix_case() {
        assert_eq!(normalize_version("v1.2.3"), "1.2.3");
        assert_eq!(normalize_version("V1.2.3"), "1.2.3");
        assert_eq!(normalize_version("version1"), "version1");
    }

    #[test]
    fn test_version_cmp() {
        assert_eq!(version_cmp("1.0.0", "1.0.0"), Ordering::Equal);
        assert_eq!(version_cmp("1.0.1", "1.0.0"), Ordering::Greater);
        assert_eq!(version_cmp("1.0.0", "1.0.1"), Ordering::Less);
        assert_eq!(version_cmp("2.0.0", "1.9.9"), Ordering::Greater);
        assert_eq!(version_cmp("22.0.0", "20.10.0"), Ordering::Greater);
        assert_eq!(version_cmp("1.0.0-beta.2", "1.0.0"), Ordering::Less);
        assert_eq!(version_cmp("1.0.0-rc.10", "1.0.0-rc.2"), Ordering::Greater);
    }

    #[test]
    fn equal_runtime_versions_have_a_deterministic_directory_order() {
        let mut versions = ["1.0".to_string(), "1.0.0".to_string()];
        versions.sort_by(|a, b| version_cmp(b, a).then_with(|| b.cmp(a)));
        assert_eq!(versions, ["1.0.0", "1.0"]);
    }

    #[test]
    fn version_cmp_preserves_oversized_numeric_components() {
        assert_eq!(version_cmp("1.42949672960.0", "1.9.0"), Ordering::Greater);
        assert_eq!(
            version_cmp("1.00000000000000000010", "1.9"),
            Ordering::Greater
        );
    }

    #[test]
    fn test_version_cmp_partial() {
        assert_eq!(version_cmp("1.0", "1.0.0"), Ordering::Equal);
        assert_eq!(version_cmp("1", "1.0.0"), Ordering::Equal);
        assert_eq!(version_cmp("2", "1.9.9"), Ordering::Greater);
    }

    #[test]
    fn runtime_download_size_is_bounded_even_without_content_length() {
        assert_eq!(bounded_download_size(10, 5).unwrap(), 15);
        assert!(bounded_download_size(MAX_RUNTIME_DOWNLOAD_BYTES, 1).is_err());
    }

    #[test]
    fn vendor_download_filename_must_be_one_component() {
        assert_eq!(
            validate_download_filename("runtime.tar.gz").unwrap(),
            "runtime.tar.gz"
        );
        for hostile in [
            "",
            ".",
            "..",
            "../runtime.tar.gz",
            "nested/runtime.tar.gz",
            "nested\\runtime.tar.gz",
            "/runtime.tar.gz",
            "runtime\0.tar.gz",
        ] {
            assert!(
                validate_download_filename(hostile).is_err(),
                "hostile vendor filename must fail: {hostile:?}"
            );
        }
    }

    #[test]
    fn test_normalize_version() {
        assert_eq!(normalize_version("v1.0.0"), "1.0.0");
        assert_eq!(normalize_version("1.0.0"), "1.0.0");
        assert_eq!(normalize_version("v22.0.0"), "22.0.0");
        assert_eq!(normalize_version("latest"), "latest");
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            extract_domain("https://nodejs.org/dist/v20.0.0/node.tar.gz"),
            "nodejs.org"
        );
        assert_eq!(extract_domain("https://github.com/foo/bar"), "github.com");
        // Invalid URLs return the original string (no :// separator)
        assert_eq!(extract_domain("invalid-url"), "invalid-url");
    }

    #[test]
    fn parse_sha256_digest_accepts_a_vendor_manifest_line() -> Result<()> {
        let digest = "A".repeat(64);
        assert_eq!(
            parse_sha256_digest(
                &format!("{digest}  node-v20.0.0-linux-x64.tar.xz"),
                "nodejs.org"
            )?,
            digest.to_lowercase()
        );
        // Digest-only payloads (go.dev style) are also accepted.
        assert_eq!(
            parse_sha256_digest(&digest, "go.dev")?,
            digest.to_lowercase()
        );
        assert_eq!(
            parse_sha256_digest(&format!("sha256:{digest}"), "GitHub")?,
            digest.to_lowercase()
        );
        Ok(())
    }

    #[test]
    fn parse_sha512_digest_accepts_dotnet_metadata_hashes() -> Result<()> {
        let digest = "B".repeat(128);
        assert_eq!(
            parse_sha512_digest(&digest, "builds.dotnet.microsoft.com")?,
            digest.to_lowercase()
        );
        assert_eq!(
            parse_sha512_digest(&format!("sha512:{digest}"), "builds.dotnet.microsoft.com")?,
            digest.to_lowercase()
        );
        assert!(parse_sha512_digest(&"C".repeat(64), "builds.dotnet.microsoft.com").is_err());
        assert!(parse_sha512_digest("not-a-hash", "builds.dotnet.microsoft.com").is_err());
        Ok(())
    }

    #[test]
    fn is_partial_version_accepts_only_numeric_prefixes() {
        assert!(is_partial_version("20"));
        assert!(is_partial_version("3.12"));
        assert!(is_partial_version("v20"));
        assert!(!is_partial_version("20.10.0"));
        assert!(!is_partial_version("latest"));
        assert!(!is_partial_version("1.22rc1"));
        assert!(!is_partial_version("garbage"));
        assert!(!is_partial_version(""));
        assert!(!is_partial_version("20."));
        assert!(!is_partial_version("1.2.3.4"));
    }

    #[test]
    fn resolve_partial_version_major_only_picks_the_newest_match() {
        let available = ["19.0.0", "20.10.0", "20.1.0", "20.0.0"]
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            resolve_partial_version(&available, "20").as_deref(),
            Some("20.10.0")
        );
    }

    #[test]
    fn resolve_partial_version_minor_picks_the_newest_patch() {
        let available = ["3.12.0", "3.12.7", "3.11.9"]
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            resolve_partial_version(&available, "3.12").as_deref(),
            Some("3.12.7")
        );
    }

    #[test]
    fn resolve_partial_version_passes_exact_versions_through() {
        let available = ["20.10.0", "20.11.0"]
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            resolve_partial_version(&available, "20.10.0").as_deref(),
            Some("20.10.0")
        );
    }

    #[test]
    fn resolve_partial_version_returns_none_without_a_match() {
        let available = vec!["19.0.0".to_string()];
        assert_eq!(resolve_partial_version(&available, "20"), None);
        // An exact request missing from the vendor list also misses.
        assert_eq!(resolve_partial_version(&available, "20.0.0"), None);
    }

    #[test]
    fn resolve_partial_version_matches_on_component_boundaries() {
        let available = ["3.120.0", "3.12.1"]
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            resolve_partial_version(&available, "3.12").as_deref(),
            Some("3.12.1")
        );
    }

    #[test]
    fn resolve_partial_version_rejects_garbage_input() {
        let available = vec!["20.10.0".to_string()];
        for garbage in ["", "garbage", "20.x", "1.2.3.4", "20-rc"] {
            assert_eq!(
                resolve_partial_version(&available, garbage),
                None,
                "garbage request {garbage:?} must not resolve"
            );
        }
    }

    #[test]
    fn resolve_partial_version_is_order_independent() {
        let ascending = ["20.0.0", "20.10.0"]
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let mut descending = ascending.clone();
        descending.reverse();
        assert_eq!(
            resolve_partial_version(&ascending, "20"),
            resolve_partial_version(&descending, "20")
        );
    }

    #[test]
    fn parse_sha256_digest_rejects_malformed_values() {
        assert!(parse_sha256_digest("not-a-digest", "nodejs.org").is_err());
        assert!(parse_sha256_digest(&"a".repeat(63), "nodejs.org").is_err());
        assert!(parse_sha256_digest(&"z".repeat(64), "nodejs.org").is_err());
    }

    #[test]
    fn pending_runtime_is_neither_listed_activated_nor_removed() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let version = temp.path().join("1.0.0");
        fs::create_dir_all(version.join("bin"))?;
        fs::write(version.join("bin/tool"), b"fixture")?;
        fs::write(version.join(INSTALL_PENDING_MARKER), b"")?;
        assert!(!is_valid_version_dir(&version));
        assert!(list_installed_versions(temp.path())?.is_empty());
        assert!(activate_version(temp.path(), "1.0.0", Path::new("bin/tool")).is_err());
        assert!(uninstall_version(temp.path(), "1.0.0").is_err());
        assert!(version.exists());
        fs::remove_file(version.join(INSTALL_PENDING_MARKER))?;
        assert!(is_valid_version_dir(&version));
        assert_eq!(list_installed_versions(temp.path())?, vec!["1.0.0"]);
        Ok(())
    }

    #[test]
    fn activation_and_removal_share_a_mutation_lease() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let version = temp.path().join("1.0.0");
        fs::create_dir(&version)?;
        let lease = try_lock_runtime_file(temp.path(), ".mutation.lock")?;
        assert!(set_current_version(temp.path(), "1.0.0").is_err());
        assert!(uninstall_version(temp.path(), "1.0.0").is_err());
        assert!(version.exists());
        drop(lease);
        set_current_version(temp.path(), "1.0.0")?;
        assert!(uninstall_version(temp.path(), "1.0.0").is_err());
        assert!(version.exists());
        Ok(())
    }

    #[test]
    fn runtime_install_lease_excludes_concurrent_recovery() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let lease = try_lock_runtime_install(temp.path(), "1.0.0")?;
        assert!(try_lock_runtime_install(temp.path(), "1.0.0").is_err());
        drop(lease);
        let _next = try_lock_runtime_install(temp.path(), "1.0.0")?;
        Ok(())
    }

    fn tar_archive_with_symlink(target: &str) -> anyhow::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut builder = tar::Builder::new(&mut bytes);

        let mut file_header = tar::Header::new_gnu();
        file_header.set_entry_type(tar::EntryType::Regular);
        file_header.set_mode(0o755);
        file_header.set_size(4);
        file_header.set_cksum();
        builder.append_data(&mut file_header, "runtime/lib/tool", &b"tool"[..])?;

        let mut link_header = tar::Header::new_gnu();
        link_header.set_entry_type(tar::EntryType::Symlink);
        link_header.set_mode(0o755);
        link_header.set_size(0);
        link_header.set_link_name(target)?;
        link_header.set_cksum();
        builder.append_data(&mut link_header, "runtime/bin/tool", std::io::empty())?;
        builder.finish()?;
        drop(builder);
        Ok(bytes)
    }

    #[tokio::test]
    async fn tar_gz_extraction_rejects_escaping_symlinks() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let archive_path = temp.path().join("runtime.tar.gz");
        let gz = {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            std::io::Write::write_all(&mut encoder, &tar_archive_with_symlink("../../outside")?)?;
            encoder.finish()?
        };
        fs::write(&archive_path, gz)?;

        let error = extract_tar_gz(&archive_path, temp.path().join("out").as_path(), 1)
            .await
            .expect_err("escaping symlink entries must be rejected");
        assert!(
            error
                .to_string()
                .contains("escapes the extraction directory")
        );
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tar_gz_extraction_rejects_composed_symlink_escape() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        fs::write(temp.path().join("victim"), b"untouched")?;
        let archive_path = temp.path().join("runtime.tar.gz");
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        for (name, target) in [
            ("runtime/a", "."),
            ("runtime/usr/bin/swift", "../../a/../victim"),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_mode(0o777);
            header.set_size(0);
            header.set_link_name(target)?;
            header.set_cksum();
            builder.append_data(&mut header, name, std::io::empty())?;
        }
        fs::write(&archive_path, builder.into_inner()?.finish()?)?;
        let error = extract_tar_gz(&archive_path, &temp.path().join("out"), 1)
            .await
            .expect_err("composed escape must fail");
        assert!(
            error
                .to_string()
                .contains("escapes the extraction directory")
        );
        assert_eq!(fs::read(temp.path().join("victim"))?, b"untouched");
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tar_gz_extraction_accepts_internal_symlinks() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let archive_path = temp.path().join("runtime.tar.gz");
        let gz = {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            std::io::Write::write_all(&mut encoder, &tar_archive_with_symlink("../lib/tool")?)?;
            encoder.finish()?
        };
        fs::write(&archive_path, gz)?;

        let output = temp.path().join("out");
        extract_tar_gz(&archive_path, &output, 1).await?;
        assert_eq!(fs::read(output.join("bin/tool"))?, b"tool");
        assert!(
            fs::symlink_metadata(output.join("bin/tool"))?
                .file_type()
                .is_symlink()
        );
        Ok(())
    }

    #[tokio::test]
    async fn tar_xz_extraction_accepts_regular_files() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let archive_path = temp.path().join("runtime.tar.xz");
        let mut compressed = Vec::new();
        lzma_rs::xz_compress(
            &mut std::io::Cursor::new(tar_archive(tar::EntryType::Regular)),
            &mut compressed,
        )?;
        fs::write(&archive_path, compressed)?;

        extract_tar_xz(&archive_path, temp.path().join("out").as_path(), 1).await?;
        assert_eq!(fs::read(temp.path().join("out/bin/tool"))?, b"tool");
        Ok(())
    }

    #[test]
    fn archive_identity_reports_size_and_digest() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let path = temp.path().join("artifact.bin");
        fs::write(&path, b"abc")?;
        let (bytes, digest) = archive_identity(&path);
        assert_eq!(bytes, 3);
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        Ok(())
    }

    #[tokio::test]
    async fn decompression_failure_reports_the_archive_identity() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let archive_path = temp.path().join("runtime.tar.xz");
        fs::write(
            &archive_path,
            b"not an xz stream, but long enough to attempt decoding",
        )?;
        let error = extract_tar_xz(&archive_path, temp.path().join("out").as_path(), 1)
            .await
            .expect_err("garbage archive must fail");
        let message = format!("{error:#}");
        assert!(
            message.contains("Failed to decompress XZ archive"),
            "{message}"
        );
        assert!(message.contains("bytes="), "{message}");
        assert!(message.contains("sha256="), "{message}");
        assert!(message.contains("runtime.tar.xz"), "{message}");
        Ok(())
    }

    #[test]
    fn concurrent_downloads_with_identical_names_keep_independent_contents() -> anyhow::Result<()> {
        let versions = TempDir::new()?;
        for filename in ["bun-linux-x64.zip", "deno-x86_64-unknown-linux-gnu.zip"] {
            let first = begin_download(versions.path())?;
            let second = begin_download(versions.path())?;
            let first_path = first.path().join(filename);
            let second_path = second.path().join(filename);
            fs::write(&first_path, b"verified first version")?;
            fs::write(&second_path, b"verified second version")?;

            assert_ne!(first_path, second_path);
            assert_eq!(fs::read(&first_path)?, b"verified first version");
            assert!(list_installed_versions(versions.path())?.is_empty());
            drop(first);
            assert!(!first_path.exists());
            assert_eq!(fs::read(&second_path)?, b"verified second version");
            drop(second);
            assert!(!second_path.exists());
        }
        assert_eq!(fs::read_dir(versions.path())?.count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_download_removes_only_its_own_directory() -> anyhow::Result<()> {
        let versions = TempDir::new()?;
        let surviving = begin_download(versions.path())?;
        let cancelled = begin_download(versions.path())?;
        let cancelled_path = cancelled.path().to_path_buf();
        let survivor_path = surviving.path().join("runtime.zip");
        fs::write(&survivor_path, b"verified")?;
        fs::write(cancelled.path().join("runtime.zip"), b"partial")?;
        let (ready, started) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _owner = cancelled;
            let _ = ready.send(());
            std::future::pending::<()>().await;
        });
        started.await?;
        task.abort();
        assert!(
            task.await
                .expect_err("task must be cancelled")
                .is_cancelled()
        );
        assert!(!cancelled_path.exists());
        assert_eq!(fs::read(&survivor_path)?, b"verified");
        Ok(())
    }

    #[test]
    fn staged_install_publishes_marker_on_success() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let versions_dir = temp.path().join("versions");
        let version_dir = versions_dir.join("1.0.0");

        let staging = begin_staged_install(&versions_dir)?;
        fs::write(staging.path().join("bin"), "binary")?;
        complete_staged_install(&staging, &version_dir, "1.0.0")?;

        assert!(version_dir.join("bin").is_file());
        assert_eq!(
            fs::read_to_string(version_dir.join(INSTALL_MARKER))?,
            "1.0.0\n"
        );
        assert_eq!(
            list_installed_versions(&versions_dir)?,
            vec!["1.0.0".to_string()]
        );
        Ok(())
    }

    #[test]
    fn interrupted_staged_install_leaves_no_version_or_staging_entry() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let versions_dir = temp.path().join("versions");
        let version_dir = versions_dir.join("1.0.0");

        {
            let staging = begin_staged_install(&versions_dir)?;
            fs::write(staging.path().join("bin"), "partial")?;
            // Simulate an interrupted install: staging drops without publishing.
        }

        assert!(!version_dir.exists());
        assert!(list_installed_versions(&versions_dir)?.is_empty());
        Ok(())
    }

    #[test]
    fn staged_install_refuses_to_clobber_an_existing_version() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let versions_dir = temp.path().join("versions");
        let version_dir = versions_dir.join("1.0.0");
        fs::create_dir_all(&version_dir)?;

        let staging = begin_staged_install(&versions_dir)?;
        let error = complete_staged_install(&staging, &version_dir, "1.0.0")
            .expect_err("must refuse to publish over an existing version");
        assert_eq!(
            error.downcast_ref::<rustix::io::Errno>(),
            Some(&rustix::io::Errno::EXIST)
        );
        assert!(version_dir.is_dir());
        assert!(fs::read_dir(&version_dir)?.next().is_none());
        assert!(staging.path().join(INSTALL_MARKER).is_file());
        Ok(())
    }

    #[test]
    fn replace_staged_install_swaps_the_published_directory() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let versions_dir = temp.path().join("versions");
        let version_dir = versions_dir.join("1.0.0");
        fs::create_dir_all(&version_dir)?;
        fs::write(version_dir.join("bin"), "old")?;

        let staging = begin_staged_install(&versions_dir)?;
        fs::write(staging.path().join("bin"), "new")?;
        replace_staged_install(&staging, &version_dir, "1.0.0")?;

        assert_eq!(fs::read_to_string(staging.path().join("bin"))?, "old");
        assert_eq!(fs::read_to_string(version_dir.join("bin"))?, "new");
        assert_eq!(
            fs::read_to_string(version_dir.join(INSTALL_MARKER))?,
            "1.0.0\n"
        );
        assert_eq!(
            list_installed_versions(&versions_dir)?,
            vec!["1.0.0".to_string()]
        );
        let retired_path = staging.path().to_path_buf();
        drop(staging);
        assert!(!retired_path.exists());
        assert_eq!(fs::read_to_string(version_dir.join("bin"))?, "new");
        Ok(())
    }

    #[test]
    fn replace_staged_install_preserves_trees_when_exchange_fails() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let version_dir = temp.path().join("1.0.0");
        fs::create_dir(&version_dir)?;
        fs::write(version_dir.join("bin"), "old")?;
        let staging = begin_staged_install(&version_dir)?;
        fs::write(staging.path().join("bin"), "new")?;

        replace_staged_install(&staging, &version_dir, "1.0.0")
            .expect_err("cannot exchange a directory with its descendant");

        assert_eq!(fs::read_to_string(version_dir.join("bin"))?, "old");
        assert_eq!(fs::read_to_string(staging.path().join("bin"))?, "new");
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn copy_regular_tree_rejects_symlinks() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let src = temp.path().join("src");
        let dest = temp.path().join("dest");
        fs::create_dir_all(&src)?;
        std::os::unix::fs::symlink("/tmp", src.join("link"))?;

        let error = copy_regular_tree(&src, &dest).expect_err("symlinks must be rejected");
        assert!(error.to_string().contains("symlink or special file"));
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn zip_extraction_strips_special_permission_bits() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = TempDir::new()?;
        let archive_path = temp.path().join("runtime.zip");
        let file = File::create(&archive_path)?;
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default().unix_permissions(0o6755);
        archive.start_file("runtime/bin/tool", options)?;
        archive.write_all(b"tool")?;
        archive.finish()?;

        let destination = temp.path().join("destination");
        extract_zip(&archive_path, &destination, 1).await?;
        let mode = fs::metadata(destination.join("bin/tool"))?
            .permissions()
            .mode();
        assert_eq!(mode & 0o7000, 0, "special mode bits must be stripped");
        assert_eq!(mode & 0o777, 0o755);
        Ok(())
    }

    #[test]
    fn test_list_installed_versions_empty() {
        let temp = TempDir::new().unwrap();
        let versions = list_installed_versions(temp.path()).unwrap();
        assert!(versions.is_empty());
    }

    #[test]
    fn test_list_installed_versions() {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join("1.0.0")).unwrap();
        fs::create_dir(temp.path().join("2.0.0")).unwrap();
        fs::create_dir(temp.path().join("current")).unwrap(); // Should be excluded

        let versions = list_installed_versions(temp.path()).unwrap();
        assert_eq!(versions.len(), 2);
        assert!(versions.contains(&"1.0.0".to_string()));
        assert!(versions.contains(&"2.0.0".to_string()));
        assert!(!versions.contains(&"current".to_string()));
    }

    #[test]
    fn synthetic_test_runtime_is_not_installed_or_activatable() {
        let temp = TempDir::new().unwrap();
        let synthetic = temp.path().join("3.12.0");
        fs::create_dir(&synthetic).unwrap();
        fs::write(synthetic.join(TEST_RUNTIME_MARKER), "synthetic\n").unwrap();

        assert!(list_installed_versions(temp.path()).unwrap().is_empty());
        let error = set_current_version(temp.path(), "3.12.0").unwrap_err();
        assert!(error.to_string().contains("valid directory"));
    }

    #[test]
    #[cfg(unix)]
    fn version_listing_and_activation_reject_symlinked_version_dirs() {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join("real")).unwrap();
        std::os::unix::fs::symlink("real", temp.path().join("1.0.0")).unwrap();
        fs::write(temp.path().join("2.0.0"), b"not a directory").unwrap();

        let versions = list_installed_versions(temp.path()).unwrap();
        assert_eq!(versions, vec!["real".to_string()]);

        let error = set_current_version(temp.path(), "1.0.0").unwrap_err();
        assert!(error.to_string().contains("valid directory"));
    }

    #[test]
    fn test_get_current_version_none() {
        let temp = TempDir::new().unwrap();
        assert!(get_current_version(temp.path()).is_none());
    }

    #[test]
    #[cfg(unix)]
    fn current_version_rejects_missing_or_external_targets() {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join("1.0.0")).unwrap();
        let current = temp.path().join("current");

        std::os::unix::fs::symlink("missing", &current).unwrap();
        assert!(get_current_version(temp.path()).is_none());
        fs::remove_file(&current).unwrap();

        let outside_root = TempDir::new().unwrap();
        let outside = outside_root.path().join("1.0.0");
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &current).unwrap();
        assert!(get_current_version(temp.path()).is_none());
    }

    #[test]
    #[cfg(unix)]
    fn switching_current_version_replaces_the_existing_link() {
        let temp = TempDir::new().unwrap();
        let first_version = temp.path().join("1.0.0");
        let second_version = temp.path().join("2.0.0");
        fs::create_dir(&first_version).unwrap();
        fs::create_dir(&second_version).unwrap();

        set_current_version(temp.path(), "1.0.0").unwrap();
        set_current_version(temp.path(), "2.0.0").unwrap();

        assert_eq!(
            fs::read_link(temp.path().join("current")).unwrap(),
            second_version
        );
        assert_eq!(get_current_version(temp.path()), Some("2.0.0".to_string()));
        assert!(first_version.is_dir());
    }

    #[test]
    #[cfg(unix)]
    fn missing_version_preserves_the_current_link() {
        let temp = TempDir::new().unwrap();
        let installed_version = temp.path().join("1.0.0");
        fs::create_dir(&installed_version).unwrap();
        set_current_version(temp.path(), "1.0.0").unwrap();

        let error = set_current_version(temp.path(), "2.0.0").unwrap_err();

        assert!(error.to_string().contains("is not installed"));
        assert_eq!(
            fs::read_link(temp.path().join("current")).unwrap(),
            installed_version
        );
    }

    #[test]
    #[cfg(unix)]
    fn activation_refuses_to_replace_a_regular_file() {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join("1.0.0")).unwrap();
        let current_path = temp.path().join("current");
        fs::write(&current_path, "sentinel").unwrap();

        let error = set_current_version(temp.path(), "1.0.0").unwrap_err();

        assert!(
            error
                .to_string()
                .contains("Refusing to replace non-symlink")
        );
        assert_eq!(fs::read_to_string(current_path).unwrap(), "sentinel");
    }

    #[test]
    fn set_current_version_rejects_missing_versions() {
        let temp = TempDir::new().unwrap();
        let error = set_current_version(temp.path(), "1.0.0").unwrap_err();
        assert!(error.to_string().contains("is not installed"));
    }

    #[cfg(unix)]
    #[test]
    fn runtime_path_rejects_group_writable_directories() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let bin = temp.path().join("bin");
        fs::create_dir(&bin).unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o775)).unwrap();

        assert!(!is_trusted_runtime_dir_chain(&bin, temp.path()));
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(is_trusted_runtime_dir_chain(&bin, temp.path()));

        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o775)).unwrap();
        assert!(
            !is_trusted_runtime_dir_chain(&bin, temp.path()),
            "a writable ancestor must invalidate the runtime path"
        );
    }

    #[test]
    fn activate_version_requires_a_regular_expected_binary() {
        let temp = TempDir::new().unwrap();
        let version_dir = temp.path().join("1.0.0");
        fs::create_dir_all(version_dir.join("bin")).unwrap();

        let missing = activate_version(temp.path(), "1.0.0", Path::new("bin/node")).unwrap_err();
        assert!(
            missing
                .to_string()
                .contains("Missing required runtime binary")
        );
        assert!(!temp.path().join("current").exists());

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("elsewhere", version_dir.join("bin/node")).unwrap();
            let linked = activate_version(temp.path(), "1.0.0", Path::new("bin/node")).unwrap_err();
            assert!(linked.to_string().contains("regular file"));
            assert!(!temp.path().join("current").exists());
            fs::remove_file(version_dir.join("bin/node")).unwrap();
        }

        fs::write(version_dir.join("bin/node"), b"node").unwrap();
        activate_version(temp.path(), "1.0.0", Path::new("bin/node")).unwrap();
        #[cfg(unix)]
        assert_eq!(
            fs::read_link(temp.path().join("current")).unwrap(),
            version_dir
        );
    }

    #[cfg(unix)]
    #[test]
    fn linked_runtime_binary_must_resolve_inside_the_version_directory() {
        let temp = TempDir::new().unwrap();
        let version_dir = temp.path().join("3.12.0");
        fs::create_dir_all(version_dir.join("bin")).unwrap();
        fs::write(version_dir.join("bin/python3.12"), b"python").unwrap();
        std::os::unix::fs::symlink("python3.12", version_dir.join("bin/python3")).unwrap();

        activate_version_with_linked_binary(temp.path(), "3.12.0", Path::new("bin/python3"))
            .expect("an internal vendor symlink is safe");
        assert_eq!(
            fs::read_link(temp.path().join("current")).unwrap(),
            version_dir
        );

        fs::remove_file(temp.path().join("current")).unwrap();
        fs::remove_file(temp.path().join("3.12.0/bin/python3")).unwrap();
        let outside = temp.path().join("outside-python");
        fs::write(&outside, b"outside").unwrap();
        std::os::unix::fs::symlink(&outside, temp.path().join("3.12.0/bin/python3")).unwrap();

        let error =
            activate_version_with_linked_binary(temp.path(), "3.12.0", Path::new("bin/python3"))
                .expect_err("a vendor link may not escape the version directory");
        assert!(
            error.to_string().contains("escapes version directory"),
            "{error}"
        );
        assert!(!temp.path().join("current").exists());
    }

    #[test]
    #[cfg(not(unix))]
    fn activation_fails_explicitly_on_unsupported_platforms() {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join("1.0.0")).unwrap();

        let error = set_current_version(temp.path(), "1.0.0").unwrap_err();

        assert!(error.to_string().contains("unsupported on this platform"));
        assert!(!temp.path().join("current").exists());
    }

    /// Build a gzip bomb: `expanded` bytes of zeros compress to a few KiB.
    fn gzip_bomb(expanded: usize) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Read as _;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        std::io::copy(
            &mut std::io::repeat(0u8).take(expanded as u64),
            &mut encoder,
        )
        .unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn budgeted_reader_aborts_a_decompression_bomb_during_streaming() {
        let bomb = gzip_bomb(64 * 1024 * 1024); // 64 MiB of zeros compresses to ~60 KiB
        let decoder = flate2::read::GzDecoder::new(bomb.as_slice());
        let mut reader = BudgetedReader::new(decoder, 1024 * 1024); // 1 MiB budget

        let mut sink = Vec::new();
        let error = reader
            .read_to_end(&mut sink)
            .expect_err("budget must abort the stream");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            error
                .to_string()
                .contains("configured limit of 1048576 bytes")
        );
        // Allocation stopped at the budget instead of expanding to 64 MiB.
        assert!(sink.len() <= 1024 * 1024 + 64 * 1024);
    }

    #[test]
    fn budgeted_writer_stops_before_exceeding_cumulative_budget() {
        let mut remaining = 16;
        let mut output = Vec::new();
        let error = copy_with_budget(
            &mut std::io::Cursor::new(vec![0_u8; 17]),
            &mut output,
            &mut remaining,
        )
        .expect_err("budget must abort before writing excess bytes");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(output.len() <= 16);
    }

    #[test]
    fn budgeted_sink_stops_growing_at_the_budget() {
        let mut sink = BudgetedSink::with_budget(16);

        let ok = sink.write(&[0u8; 10]).unwrap();
        let error = sink.write(&[0u8; 32]).expect_err("budget must abort");

        assert_eq!(ok, 10);
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(sink.into_inner().len(), 10);
    }
}

const MAX_ARCHIVE_ENTRIES: usize = 250_000;
#[derive(Default)]
struct ArchiveEntryBudget {
    entries: usize,
    path_bytes: usize,
}
impl ArchiveEntryBudget {
    fn charge(&mut self, path: &Path) -> Result<()> {
        self.entries += 1;
        self.path_bytes = self
            .path_bytes
            .checked_add(path.as_os_str().len())
            .context("Archive path budget overflow")?;
        anyhow::ensure!(
            self.entries <= MAX_ARCHIVE_ENTRIES
                && path.components().count() <= 64
                && self.path_bytes <= 32 * 1024 * 1024,
            "Archive exceeds entry count, depth, or pathname budget"
        );
        Ok(())
    }
}
#[cfg(test)]
mod entry_budget_tests {
    use super::*;
    #[tokio::test]
    async fn empty_tar_entry_flood_is_rejected_even_when_selection_skips_everything() -> Result<()>
    {
        let directory = tempfile::tempdir()?;
        let archive_path = directory.path().join("empty-flood.tar.gz");
        let encoder = flate2::write::GzEncoder::new(
            File::create(&archive_path)?,
            flate2::Compression::fast(),
        );
        let mut builder = tar::Builder::new(encoder);
        for _ in 0..=MAX_ARCHIVE_ENTRIES {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_size(0);
            header.set_cksum();
            builder.append_data(&mut header, "runtime/empty", std::io::empty())?;
        }
        builder.into_inner()?.finish()?;
        let decoder = flate2::read::GzDecoder::new(File::open(&archive_path)?);
        let mut archive = tar::Archive::new(decoder);
        let output = directory.path().join("out");
        let error = extract_tar_entries(
            &mut archive,
            &output,
            &|_| Ok(None),
            &extract_task(&archive_path),
        )
        .unwrap_err();
        assert!(error.to_string().contains("entry count"), "{error}");
        assert!(!output.exists());
        Ok(())
    }

    #[test]
    fn empty_entries_and_deep_paths_are_bounded() {
        let mut budget = ArchiveEntryBudget {
            entries: MAX_ARCHIVE_ENTRIES,
            path_bytes: 0,
        };
        assert!(budget.charge(Path::new("empty")).is_err());
        let deep = std::iter::repeat_n("x", 65).collect::<Vec<_>>().join("/");
        assert!(
            ArchiveEntryBudget::default()
                .charge(Path::new(&deep))
                .is_err()
        );
        assert!(
            ArchiveEntryBudget::default()
                .charge(Path::new("runtime/bin/node"))
                .is_ok()
        );
    }
}
