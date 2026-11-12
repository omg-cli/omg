//! Parallel source downloading for AUR packages
//!
//! Parses `.SRCINFO` and downloads HTTP sources concurrently before makepkg runs.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

const MAX_AUR_SOURCE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_GIT_MIRROR_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_GIT_MIRROR_ENTRIES: usize = 200_000;
const MAX_GIT_STDERR_BYTES: u64 = 1024 * 1024;
const MAX_GIT_CLONE_DURATION: Duration = Duration::from_mins(15);

use alpm_srcinfo::SourceInfoV1;
use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tracing::{debug, warn};

use super::aur::git_process::{GitLimits, run_bounded_git};
use crate::cli::progress::{Accent, Outcome, ProgressTask, TaskKind, TaskSpec};

/// Represents a source file that can be downloaded
#[derive(Debug, Clone)]
pub struct SourceFile {
    /// Full URL to download from
    pub url: String,
    /// Base filename (may be renamed via :: syntax)
    pub filename: String,
}

/// Acquires a bounded regular .SRCINFO file and extracts its HTTP/HTTPS sources.
pub fn parse_sources(pkg_dir: &Path) -> Result<Vec<SourceFile>> {
    Ok(super::aur::source_file::read_srcinfo(pkg_dir)?
        .as_ref()
        .map_or_else(Vec::new, http_sources))
}

/// Extract HTTP/HTTPS source URLs from captured, parsed metadata.
///
/// Returns a list of downloadable sources that makepkg would normally fetch.
/// Only includes http:// and https:// URLs, skipping local files and git repos.
pub(crate) fn http_sources(srcinfo: &SourceInfoV1) -> Vec<SourceFile> {
    let sources = source_entries(srcinfo)
        .iter()
        .filter_map(|source| extract_http_source(source))
        .collect::<Vec<_>>();

    debug!("Parsed {} HTTP/HTTPS sources from .SRCINFO", sources.len());
    sources
}

/// Every declared source string, including architecture-specific entries.
///
/// Both the HTTP and the VCS prefetch paths work from this list so they can
/// never disagree about which sources a PKGBUILD declares.
fn source_entries(srcinfo: &SourceInfoV1) -> Vec<String> {
    let mut entries = srcinfo
        .base
        .sources
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();

    if let Some(arch) = super::aur::utils::current_arch()
        && let Some(arch_props) = srcinfo.base.architecture_properties.get(&arch)
    {
        entries.extend(arch_props.sources.iter().map(ToString::to_string));
    }

    entries
}

/// VCS clients makepkg can delegate to. Mirrors makepkg's `get_protocol`.
const VCS_PROTOCOLS: [&str; 5] = ["git", "svn", "hg", "bzr", "fossil"];

/// A source that makepkg fetches with a VCS client rather than over plain HTTP.
///
/// The offline build sandbox (`bwrap --unshare-net`) makes these sources
/// unfetchable during the build, so they must be mirrored into SRCDEST first.
/// `filename` and `url` reproduce makepkg's own `get_filename`/`get_url`
/// helpers so a prefetched copy lands exactly where makepkg looks for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VcsSource {
    /// makepkg protocol name: `git`, `svn`, `hg`, `bzr`, or `fossil`.
    pub protocol: String,
    /// URL handed to the VCS client: the `proto+` prefix and any `?query` /
    /// `#fragment` removed, matching makepkg's `download_<proto>`.
    pub url: String,
    /// SRCDEST entry name, matching makepkg's `get_filename`.
    pub filename: String,
    /// The `.SRCINFO` entry as written, for diagnostics.
    pub raw: String,
}

/// Acquires a bounded regular .SRCINFO file and extracts its VCS sources.
pub fn parse_vcs_sources(pkg_dir: &Path) -> Result<Vec<VcsSource>> {
    Ok(super::aur::source_file::read_srcinfo(pkg_dir)?
        .as_ref()
        .map_or_else(Vec::new, vcs_sources))
}

/// Extract VCS sources from captured, parsed metadata.
pub(crate) fn vcs_sources(srcinfo: &SourceInfoV1) -> Vec<VcsSource> {
    let sources = source_entries(srcinfo)
        .iter()
        .filter_map(|source| extract_vcs_source(source))
        .collect::<Vec<_>>();

    debug!("Parsed {} VCS sources from .SRCINFO", sources.len());
    sources
}

/// Extract a VCS source from a `.SRCINFO` source entry.
///
/// Reproduces makepkg's `get_protocol`, `get_url` and `get_filename` so the
/// prefetched mirror is found by makepkg without any special casing.
fn extract_vcs_source(source_url: &str) -> Option<VcsSource> {
    // PKGBUILD rename syntax: `newname::url`
    // https://man.archlinux.org/PKGBUILD.5#sources_and_checksums
    let (custom_filename, netfile) = match source_url.split_once("::") {
        Some((name, rest)) => (Some(name), rest),
        None => (None, source_url),
    };

    // makepkg's get_protocol: text before "://", then before any '+'.
    let (before_scheme, _) = netfile.split_once("://")?;
    let protocol = before_scheme.split('+').next().unwrap_or(before_scheme);
    if !VCS_PROTOCOLS.contains(&protocol) {
        return None;
    }

    let filename = custom_filename.map_or_else(
        || makepkg_vcs_filename(netfile, protocol),
        ToString::to_string,
    );

    // makepkg's download_<proto> strips the `proto+` prefix, then the fragment,
    // then the query string, before handing the URL to the VCS client.
    let url = netfile
        .strip_prefix(&format!("{protocol}+"))
        .unwrap_or(netfile)
        .split('#')
        .next()
        .unwrap_or_default()
        .split('?')
        .next()
        .unwrap_or_default()
        .to_string();

    Some(VcsSource {
        protocol: protocol.to_string(),
        url,
        filename,
        raw: source_url.to_string(),
    })
}

/// Reproduce makepkg's `get_filename` for a VCS source entry.
fn makepkg_vcs_filename(netfile: &str, protocol: &str) -> String {
    // ${filename%%#*} then ${filename%%\?*} then ${filename%/} then ${filename##*/}
    let without_fragment = netfile.split('#').next().unwrap_or_default();
    let without_query = without_fragment.split('?').next().unwrap_or_default();
    let base = without_query
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or_default();

    match protocol {
        // ${filename%%.git*} — strips from the first `.git` occurrence.
        "git" => base
            .find(".git")
            .map_or_else(|| base.to_string(), |index| base[..index].to_string()),
        // ${filename#*lp:}
        "bzr" => base
            .split_once("lp:")
            .map_or_else(|| base.to_string(), |(_, rest)| rest.to_string()),
        // ${filename}.fossil
        "fossil" => format!("{base}.fossil"),
        _ => base.to_string(),
    }
}

/// Outcome of the VCS prefetch pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VcsPrefetchSummary {
    /// SRCDEST entries that were already populated.
    pub cached: Vec<String>,
    /// Sources newly mirrored by omg.
    pub prefetched: Vec<String>,
    /// Sources that still require network during the build because no cached
    /// copy exists. omg can only mirror `git`; other VCS clients (and git URLs
    /// on unauthenticated transports) stay listed here.
    pub needs_network: Vec<String>,
}

/// Reject SRCDEST entry names that are not a single plain path component.
fn validate_source_filename(filename: &str) -> Result<()> {
    anyhow::ensure!(
        !filename.is_empty()
            && filename != "."
            && filename != ".."
            && !filename.contains('/')
            && !filename.contains('\\')
            && !Path::new(filename).is_absolute(),
        "unsafe source filename: {filename:?}"
    );
    Ok(())
}

/// Mirror every VCS source into `srcdest` so the network-less sandbox can build.
///
/// makepkg's `extract_git` creates the working copy with a *local* `git clone`
/// from `$SRCDEST` whenever `--cleanbuild` cleared `$SRCDIR`, and its
/// `download_git` only warns when the mirror's `git fetch` fails offline. A
/// populated mirror is therefore sufficient for a fully offline git build.
///
/// Non-git sources are reported in [`VcsPrefetchSummary::needs_network`]: omg
/// cannot reproduce `svn`/`hg`/`bzr`/`fossil` fetches, so those still need
/// `aur.allow_network = true` or a pre-populated SRCDEST.
pub async fn prefetch_vcs_sources(sources: &[VcsSource], srcdest: &Path) -> VcsPrefetchSummary {
    let mut summary = VcsPrefetchSummary::default();

    for source in sources {
        if validate_source_filename(&source.filename).is_err() {
            warn!(
                "Rejecting VCS source with an unsafe SRCDEST filename: {:?}",
                source.raw
            );
            summary.needs_network.push(source.raw.clone());
            continue;
        }

        let destination = srcdest.join(&source.filename);
        // Reusing an existing mirror never invokes the unsandboxed host fetch.
        if source.protocol == "git" && is_populated_directory(&destination).await {
            summary.cached.push(source.raw.clone());
            continue;
        }
        if source.protocol != "git" || !is_prefetchable_git_url(&source.url) {
            summary.needs_network.push(source.raw.clone());
            continue;
        }

        match mirror_git_repository(&source.url, &destination).await {
            Ok(()) => {
                debug!("Mirrored VCS source {} into SRCDEST", source.url);
                summary.prefetched.push(source.raw.clone());
            }
            Err(error) => {
                // A concurrent prefetch may have won the race; treat a now
                // populated destination as success rather than failing the
                // build for an already-satisfied source.
                if is_populated_directory(&destination).await {
                    summary.cached.push(source.raw.clone());
                } else {
                    warn!("Failed to mirror VCS source {}: {error:#}", source.url);
                    summary.needs_network.push(source.raw.clone());
                }
            }
        }
    }

    summary
}

/// True when `path` is a directory holding at least one entry.
///
/// Symlinks are deliberately not followed: an SRCDEST entry planted as a
/// symlink must never be treated as a valid cache.
async fn is_populated_directory(path: &Path) -> bool {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.is_dir() => {
            std::fs::read_dir(path).is_ok_and(|mut entries| entries.next().is_some())
        }
        _ => false,
    }
}

/// Schemes omg is willing to mirror on its own.
///
/// Only public HTTPS sources may be fetched by the unsandboxed host helper.
/// Other transports require the explicit build-network opt-in.
fn is_prefetchable_git_url(url: &str) -> bool {
    reqwest::Url::parse(url).is_ok_and(|parsed| {
        parsed.scheme() == "https"
            && parsed.host_str().is_some()
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && !crate::core::http::is_private_or_local_host(parsed.host_str())
    })
}

/// `git clone --mirror` a source into its SRCDEST entry, atomically.
async fn mirror_git_repository(url: &str, destination: &Path) -> Result<()> {
    anyhow::ensure!(
        is_prefetchable_git_url(url),
        "AUR VCS prefetch requires a public HTTPS URL"
    );
    let parsed = reqwest::Url::parse(url)?;
    let host = parsed
        .host_str()
        .context("AUR Git URL has no host")?
        .to_owned();
    let port = parsed
        .port_or_known_default()
        .context("AUR Git URL has no port")?;
    let addresses: Vec<_> = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await??
    .collect();
    anyhow::ensure!(
        !addresses.is_empty()
            && addresses
                .iter()
                .all(|address| crate::core::http::is_public_address(address.ip())),
        "AUR Git source resolves to a non-public address"
    );
    let address = match addresses[0].ip() {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
    };
    let pinned_address = format!("{host}:{port}:{address}");
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    tokio::fs::create_dir_all(parent).await.ok();

    // Clear a stale non-directory or empty-directory occupant, but never a
    // symlink: a planted link could redirect the mirror outside SRCDEST.
    match tokio::fs::symlink_metadata(destination).await {
        Ok(metadata) => {
            anyhow::ensure!(
                !metadata.file_type().is_symlink(),
                "refusing to mirror into a symlinked SRCDEST entry: {}",
                destination.display()
            );
            if metadata.is_dir() {
                tokio::fs::remove_dir(destination)
                    .await
                    .with_context(|| format!("Failed to clear {}", destination.display()))?;
            } else {
                tokio::fs::remove_file(destination)
                    .await
                    .with_context(|| format!("Failed to clear {}", destination.display()))?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Failed to inspect {}", destination.display()));
        }
    }

    // Clone into a same-filesystem staging path so an interrupted clone never
    // leaves a half-populated mirror that makepkg would accept as a cache.
    let staging = tempfile::Builder::new()
        .prefix(".vcs-")
        .tempdir_in(parent)
        .with_context(|| format!("Failed to stage a mirror in {}", parent.display()))?;
    let staging_path = staging.path().join("mirror");

    let mut command = tokio::process::Command::new("git");
    command
        .arg("-c")
        .arg(format!("http.curloptResolve={pinned_address}"))
        .arg("-c")
        .arg("http.followRedirects=false")
        .arg("-c")
        .arg("http.proxy=")
        .arg("-c")
        .arg("protocol.file.allow=never")
        .arg("-c")
        .arg("protocol.ssh.allow=never")
        .arg("-c")
        .arg("protocol.git.allow=never")
        .arg("-c")
        .arg("protocol.ext.allow=never")
        .arg("clone")
        .arg("--mirror")
        .arg("--origin=origin")
        .arg("--")
        .arg(url)
        .arg(&staging_path)
        // The URL comes from an untrusted PKGBUILD: never read ambient or
        // repository configuration and never prompt for credentials.
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null");

    let output = run_bounded_git(
        &mut command,
        &staging_path,
        GitLimits {
            stdout_bytes: MAX_GIT_STDERR_BYTES,
            stderr_bytes: MAX_GIT_STDERR_BYTES,
            staging_bytes: MAX_GIT_MIRROR_BYTES,
            staging_entries: MAX_GIT_MIRROR_ENTRIES,
            poll_interval: Duration::from_millis(250),
        },
        tokio::time::Instant::now() + MAX_GIT_CLONE_DURATION,
    )
    .await?;
    let stderr =
        crate::cli::style::sanitize_terminal_text(&String::from_utf8_lossy(&output.stderr));
    anyhow::ensure!(
        output.status.success(),
        "git clone --mirror failed for {url}: {}",
        stderr.trim()
    );

    tokio::fs::rename(&staging_path, destination)
        .await
        .with_context(|| format!("Failed to publish mirror at {}", destination.display()))?;
    Ok(())
}

/// Extract HTTP/HTTPS source from a source URL string
///
/// Handles PKGBUILD rename syntax: `newname::https://url/oldname.tar.gz`
/// Returns None for local files, git repos, or other non-downloadable sources.
fn extract_http_source(source_url: &str) -> Option<SourceFile> {
    // Handle PKGBUILD rename syntax: "newname::url".
    // https://man.archlinux.org/PKGBUILD.5#sources_and_checksums
    let (custom_filename, url) = match source_url.split_once("::") {
        Some((name, url)) => (Some(name.to_string()), url),
        None => (None, source_url),
    };

    // Plain HTTP sources are rejected: checksums are verified at build
    // time, but transport must still be authenticated (defense in depth).
    if !url.starts_with("https://") {
        return None;
    }

    // makepkg's plain HTTP get_filename uses the literal suffix after the last '/'.
    let filename =
        custom_filename.unwrap_or_else(|| url.rsplit('/').next().unwrap_or_default().to_string());

    Some(SourceFile {
        url: url.to_string(),
        filename,
    })
}

/// Result of a best-effort AUR source pre-download.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceDownloadSummary {
    pub succeeded: usize,
    pub failed: usize,
}

fn validate_unique_destinations(sources: &[SourceFile]) -> Result<()> {
    let mut urls_by_filename = HashMap::with_capacity(sources.len());
    for source in sources {
        if let Some(previous_url) = urls_by_filename.insert(&source.filename, &source.url) {
            anyhow::ensure!(
                previous_url == &source.url,
                "AUR sources map filename {:?} to multiple URLs",
                source.filename
            );
        }
    }
    Ok(())
}

/// Download sources concurrently (up to 8 at a time)
///
/// Downloads are skipped if a regular file already exists in SRCDEST.
/// Failures are counted and logged; makepkg still retries on build.
pub async fn download_sources(sources: Vec<SourceFile>, srcdest: &Path) -> SourceDownloadSummary {
    if sources.is_empty() {
        return SourceDownloadSummary {
            succeeded: 0,
            failed: 0,
        };
    }
    if let Err(error) = validate_unique_destinations(&sources) {
        warn!("Skipping ambiguous AUR source pre-download: {error}");
        return SourceDownloadSummary {
            succeeded: 0,
            failed: sources.len(),
        };
    }
    let mut seen = HashSet::with_capacity(sources.len());
    let sources: Vec<SourceFile> = sources
        .into_iter()
        .filter(|source| seen.insert(source.filename.clone()))
        .collect();

    // Ensure SRCDEST exists
    if let Err(e) = tokio::fs::create_dir_all(srcdest).await {
        warn!("Failed to create SRCDEST directory: {e}");
        return SourceDownloadSummary {
            succeeded: 0,
            failed: sources.len(),
        };
    }

    let download_futures = sources.into_iter().map(|source| {
        // Filename captured for the security check inside the async block.
        let filename = source.filename.clone();
        let dest_path = srcdest.join(&source.filename);

        async move {
            // SECURITY (audit ADV-23-01): the filename may come from a
            // hostile PKGBUILD's `name::url` rename syntax. Reject anything
            // that is not a plain filename — separators, parent components,
            // absolute paths — so downloads can never escape SRCDEST.
            if validate_source_filename(&filename).is_err() {
                warn!("Rejecting unsafe source filename from PKGBUILD: {filename:?}");
                return Err(anyhow::anyhow!("unsafe source filename: {filename:?}"));
            }
            match tokio::fs::symlink_metadata(&dest_path).await {
                Ok(metadata) if metadata.is_file() => {
                    return Ok(());
                }
                Ok(_) => {
                    return Err(anyhow::anyhow!(
                        "SRCDEST path is not a regular file: {}",
                        dest_path.display()
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("Failed to inspect SRCDEST path {}", dest_path.display())
                    });
                }
            }

            let task = ProgressTask::start(&TaskSpec {
                label: source.filename.clone(),
                kind: TaskKind::Bytes { total: None },
                accent: Accent::Network,
            });

            download_file(&source.url, &dest_path, task).await
        }
    });

    // Download up to 8 files concurrently (network I/O bound, safe to parallelize)
    let results: Vec<Result<()>> = stream::iter(download_futures)
        .buffer_unordered(8)
        .collect()
        .await;

    let mut succeeded = 0;
    let mut failed = 0;
    for result in results {
        match result {
            Ok(()) => succeeded += 1,
            Err(error) => {
                failed += 1;
                warn!("Failed to pre-download AUR source: {error}");
            }
        }
    }
    SourceDownloadSummary { succeeded, failed }
}

fn public_source_client(host: &str, addresses: &[std::net::SocketAddr]) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .read_timeout(std::time::Duration::from_mins(1))
        .resolve_to_addrs(host, addresses)
        .build()?)
}

/// Resolve and pin public addresses on every hop. Disable ambient proxies and
/// automatic redirects so neither DNS rebinding nor a redirect reaches the LAN.
async fn fetch_public_source(value: &str) -> Result<reqwest::Response> {
    let mut url = reqwest::Url::parse(value)?;
    for _ in 0..=10 {
        anyhow::ensure!(
            url.scheme() == "https" && url.username().is_empty() && url.password().is_none(),
            "AUR sources require HTTPS without URL credentials"
        );
        let host = url.host_str().context("Source URL has no host")?.to_owned();
        let port = url
            .port_or_known_default()
            .context("Source URL has no port")?;
        let addresses: Vec<_> = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tokio::net::lookup_host((host.as_str(), port)),
        )
        .await??
        .collect();
        anyhow::ensure!(
            !addresses.is_empty()
                && addresses
                    .iter()
                    .all(|address| crate::core::http::is_public_address(address.ip())),
            "AUR source resolves to a non-public address"
        );
        // Redirects stay manual (Policy::none): each hop must re-resolve and
        // re-validate as public-only for SSRF protection, which reqwest's
        // automatic redirect policy cannot do. Total `.timeout()` is avoided
        // here because it covers the whole body download and aborts large
        // files; `.read_timeout()` only fires on stalled reads, matching
        // core::http::download_client.
        let client = public_source_client(&host, &addresses)?;
        let response = client.get(url.clone()).send().await?;
        if !response.status().is_redirection() {
            return Ok(response);
        }
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .context("Source redirect has no location")?
            .to_str()?;
        url = url.join(location)?;
    }
    anyhow::bail!("Too many AUR source redirects")
}

/// Download a single file with progress tracking
async fn download_file(url: &str, dest_path: &Path, task: ProgressTask) -> Result<()> {
    let response = fetch_public_source(url).await?;

    if !response.status().is_success() {
        task.set_message(&format!("HTTP {}", response.status()));
        task.finish(Outcome::Failed);
        return Err(anyhow::anyhow!("HTTP error: {}", response.status()));
    }

    // Get content length for progress bar and reject an oversized response
    // before creating a large temporary file.
    let expected_length = response.content_length();
    if let Some(total) = expected_length {
        anyhow::ensure!(
            total <= MAX_AUR_SOURCE_BYTES,
            "AUR source declares {total} bytes, exceeding the {MAX_AUR_SOURCE_BYTES}-byte limit"
        );
        task.set_total(Some(total));
    }

    let parent = dest_path.parent().unwrap_or_else(|| Path::new("."));
    let temporary = tempfile::Builder::new()
        .prefix(".src-")
        .tempfile_in(parent)
        .with_context(|| {
            format!(
                "Failed to create temporary AUR source in {}",
                parent.display()
            )
        })?;
    let (std_file, temporary_path) = temporary.into_parts();

    download_to_file(
        std_file,
        temporary_path,
        dest_path,
        &task,
        expected_length,
        response,
    )
    .await
}

/// Stream the response into a same-directory temp file, then persist it.
async fn download_to_file(
    std_file: std::fs::File,
    temporary_path: tempfile::TempPath,
    dest_path: &Path,
    task: &ProgressTask,
    expected_length: Option<u64>,
    response: reqwest::Response,
) -> Result<()> {
    let mut file = File::from_std(std_file);

    // Stream download with progress updates
    let mut downloaded = 0u64;
    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("Failed to read download chunk")?;

        tokio::io::copy(&mut chunk.as_ref(), &mut file)
            .await
            .context("Failed to write chunk to file")?;

        downloaded = downloaded
            .checked_add(u64::try_from(chunk.len()).context("AUR source chunk is too large")?)
            .context("AUR source byte count overflowed")?;
        anyhow::ensure!(
            downloaded <= MAX_AUR_SOURCE_BYTES,
            "AUR source exceeded the {MAX_AUR_SOURCE_BYTES}-byte limit"
        );
        task.set_position(downloaded);
    }

    file.flush().await.context("Failed to flush file")?;
    file.sync_all()
        .await
        .context("Failed to sync AUR source download")?;
    drop(file);

    // Validate download size if Content-Length was provided
    if let Some(expected) = expected_length
        && downloaded != expected
    {
        task.finish(Outcome::Failed);
        return Err(anyhow::anyhow!(
            "Download incomplete: got {downloaded} bytes, expected {expected}"
        ));
    }

    temporary_path
        .persist(dest_path)
        .map_err(|error| error.error)
        .with_context(|| format!("Failed to persist AUR source at {}", dest_path.display()))?;

    task.finish(Outcome::Done);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conflicting_source_destinations_are_rejected() {
        let sources = vec![
            SourceFile {
                url: "https://example.com/base.tar.gz".to_string(),
                filename: "source.tar.gz".to_string(),
            },
            SourceFile {
                url: "https://arch.example.com/arch.tar.gz".to_string(),
                filename: "source.tar.gz".to_string(),
            },
        ];

        let error = validate_unique_destinations(&sources)
            .expect_err("different URLs must not race for one destination");
        assert!(error.to_string().contains("multiple URLs"), "{error}");

        let identical = vec![sources[0].clone(), sources[0].clone()];
        validate_unique_destinations(&identical)
            .expect("repeated identical sources are not a destination conflict");
        let distinct = vec![
            sources[0].clone(),
            SourceFile {
                url: sources[1].url.clone(),
                filename: "other.tar.gz".to_string(),
            },
        ];
        validate_unique_destinations(&distinct)
            .expect("different destinations are not a destination conflict");
    }

    #[test]
    fn test_extract_http_source_simple() {
        let result = extract_http_source("https://example.com/file.tar.gz");
        assert!(result.is_some());
        let source = result.unwrap();
        assert_eq!(source.url, "https://example.com/file.tar.gz");
        assert_eq!(source.filename, "file.tar.gz");
    }

    #[test]
    fn test_extract_http_source_with_query_string() {
        let result = extract_http_source("https://example.com/file.tar.gz?token=abc");
        assert!(result.is_some());
        let source = result.unwrap();
        assert_eq!(source.url, "https://example.com/file.tar.gz?token=abc");
        assert_eq!(source.filename, "file.tar.gz?token=abc");
    }

    #[test]
    fn test_extract_http_source_with_fragment() {
        let result = extract_http_source("https://example.com/file.tar.gz#hash");
        assert!(result.is_some());
        let source = result.unwrap();
        assert_eq!(source.url, "https://example.com/file.tar.gz#hash");
        assert_eq!(source.filename, "file.tar.gz#hash");
    }

    #[test]
    fn test_extract_http_source_filename_after_query_or_fragment_slash() {
        for (url, filename) in [
            (
                "https://example.com/file.tar.gz?path=release/query-archive.tar.gz",
                "query-archive.tar.gz",
            ),
            (
                "https://example.com/file.tar.gz#release/fragment-archive.tar.gz",
                "fragment-archive.tar.gz",
            ),
        ] {
            let source = extract_http_source(url).expect("HTTPS source must be recognized");
            assert_eq!(source.url, url, "input {url:?}");
            assert_eq!(source.filename, filename, "input {url:?}");
        }
    }

    #[test]
    fn test_extract_http_source_with_rename() {
        let result = extract_http_source("custom-name.tar.gz::https://example.com/original.tar.gz");
        assert!(result.is_some());
        let source = result.unwrap();
        assert_eq!(source.url, "https://example.com/original.tar.gz");
        assert_eq!(source.filename, "custom-name.tar.gz");
    }

    #[test]
    fn test_extract_http_source_rename_uses_first_separator() {
        let result = extract_http_source(
            "archive.tar.gz::https://example.com/releases/tag::v1/archive.tar.gz",
        )
        .map(|source| (source.url, source.filename));

        assert_eq!(
            result,
            Some((
                "https://example.com/releases/tag::v1/archive.tar.gz".to_string(),
                "archive.tar.gz".to_string(),
            )),
            "a separator inside the URL must not discard a renamed HTTPS source",
        );
    }

    #[test]
    fn test_extract_http_source_git_ignored() {
        let result = extract_http_source("git+https://github.com/user/repo.git");
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_http_source_local_ignored() {
        let result = extract_http_source("local-file.patch");
        assert!(result.is_none());
    }
}

#[cfg(test)]
mod public_source_tests {
    use super::*;

    #[test]
    fn mirror_command_publishes_only_successful_hardened_staging() -> Result<()> {
        use std::os::unix::fs::{PermissionsExt, symlink};

        const TEST: &str = "package_managers::aur_sources::public_source_tests::mirror_command_publishes_only_successful_hardened_staging";
        if crate::core::testing::run_isolated_test(TEST) {
            return Ok(());
        }
        let directory = tempfile::tempdir()?;
        let bin = directory.path().join("bin");
        let srcdest = directory.path().join("srcdest");
        std::fs::create_dir(&bin)?;
        std::fs::create_dir(&srcdest)?;
        let program = bin.join("git");
        let destination = srcdest.join("mirror");
        let prefix = "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$@\" > \"$0.argv\"\nprintf '%s\\n' \"PATH=$PATH\" \"GIT_TERMINAL_PROMPT=$GIT_TERMINAL_PROMPT\" \"GIT_CONFIG_NOSYSTEM=$GIT_CONFIG_NOSYSTEM\" \"GIT_CONFIG_GLOBAL=$GIT_CONFIG_GLOBAL\" \"GIT_CONFIG_SYSTEM=$GIT_CONFIG_SYSTEM\" > \"$0.env\"\n[ \"${HTTP_PROXY+x}\" != x ]\n[ \"${GIT_CONFIG_COUNT+x}\" != x ]\n[ \"${GIT_SSH_COMMAND+x}\" != x ]\nfor destination do :; done\n";
        temp_env::with_vars(
            [
                ("PATH", Some(bin.as_os_str())),
                (
                    "HTTP_PROXY",
                    Some(std::ffi::OsStr::new("http://127.0.0.1:9")),
                ),
                ("GIT_CONFIG_COUNT", Some(std::ffi::OsStr::new("1"))),
                (
                    "GIT_SSH_COMMAND",
                    Some(std::ffi::OsStr::new("must-not-run")),
                ),
            ],
            || -> Result<()> {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                for success in [false, true] {
                    let body = if success {
                        "/usr/bin/mkdir -p \"$destination/objects\"\nprintf inert > \"$destination/HEAD\"\n"
                    } else {
                        "/usr/bin/mkdir -p \"$destination\"\nprintf partial > \"$destination/HEAD\"\nprintf '\\033[31mprivate failure\\033[0m' >&2\nexit 7\n"
                    };
                    std::fs::write(&program, format!("{prefix}{body}"))?;
                    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))?;
                    std::fs::write(&destination, b"stale occupant")?;
                    let result = runtime.block_on(mirror_git_repository(
                        "https://1.1.1.1/omg-inert.git",
                        &destination,
                    ));
                    let arguments = std::fs::read_to_string(bin.join("git.argv"))?;
                    let arguments: Vec<_> = arguments.lines().collect();
                    assert_eq!(arguments.len(), 20);
                    assert_eq!(
                        &arguments[..19],
                        [
                            "-c",
                            "http.curloptResolve=1.1.1.1:443:1.1.1.1",
                            "-c",
                            "http.followRedirects=false",
                            "-c",
                            "http.proxy=",
                            "-c",
                            "protocol.file.allow=never",
                            "-c",
                            "protocol.ssh.allow=never",
                            "-c",
                            "protocol.git.allow=never",
                            "-c",
                            "protocol.ext.allow=never",
                            "clone",
                            "--mirror",
                            "--origin=origin",
                            "--",
                            "https://1.1.1.1/omg-inert.git",
                        ]
                    );
                    let staged = std::path::Path::new(arguments[19]);
                    assert_eq!(staged.file_name(), Some(std::ffi::OsStr::new("mirror")));
                    let staging_owner = staged.parent().expect("staged clone owner");
                    assert_eq!(staging_owner.parent(), Some(srcdest.as_path()));
                    assert!(
                        staging_owner
                            .file_name()
                            .expect("staging name")
                            .as_encoded_bytes()
                            .starts_with(b".vcs-")
                    );
                    assert!(
                        !staging_owner.exists(),
                        "the staging owner must be retired on either result"
                    );
                    let environment = std::fs::read_to_string(bin.join("git.env"))?;
                    assert_eq!(
                        environment,
                        format!(
                            "PATH={}\nGIT_TERMINAL_PROMPT=0\nGIT_CONFIG_NOSYSTEM=1\nGIT_CONFIG_GLOBAL=/dev/null\nGIT_CONFIG_SYSTEM=/dev/null\n",
                            bin.display()
                        )
                    );
                    if success {
                        result?;
                        assert_eq!(std::fs::read(destination.join("HEAD"))?, b"inert");
                        assert!(destination.join("objects").is_dir());
                    } else {
                        let error =
                            result.expect_err("nonzero clone must never publish partial output");
                        let message = format!("{error:#}");
                        assert!(message.contains("git clone --mirror failed"), "{message}");
                        assert!(message.contains("private failure"), "{message}");
                        assert!(!message.contains('\u{1b}'), "{message:?}");
                        assert!(!destination.exists());
                        assert_eq!(srcdest.read_dir()?.count(), 0);
                    }
                }
                std::fs::remove_dir_all(&destination)?;
                let untouched = directory.path().join("untouched");
                std::fs::write(&untouched, b"keep")?;
                symlink(&untouched, &destination)?;
                std::fs::remove_file(bin.join("git.argv"))?;
                let error = runtime
                    .block_on(mirror_git_repository(
                        "https://1.1.1.1/omg-inert.git",
                        &destination,
                    ))
                    .expect_err("a symlink cannot select the clone destination");
                assert!(error.to_string().contains("symlinked SRCDEST"));
                assert!(
                    !bin.join("git.argv").exists(),
                    "refusal precedes Git execution"
                );
                assert_eq!(std::fs::read(&untouched)?, b"keep");
                assert!(destination.is_symlink());
                Ok(())
            },
        )
    }

    #[test]
    fn private_and_transition_destinations_are_rejected() {
        for value in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "2002:7f00:1::",
            "2001:db8::1",
        ] {
            assert!(
                !crate::core::http::is_public_address(value.parse().unwrap()),
                "{value}"
            );
        }
        for value in ["1.1.1.1", "2606:4700:4700::1111"] {
            assert!(
                crate::core::http::is_public_address(value.parse().unwrap()),
                "{value}"
            );
        }
    }
    #[tokio::test]
    async fn prefetch_refuses_loopback_before_connecting() {
        assert!(
            fetch_public_source("https://127.0.0.1/source")
                .await
                .unwrap_err()
                .to_string()
                .contains("non-public")
        );
        assert!(
            fetch_public_source("http://example.org/source")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn source_transport_refuses_http_without_connecting() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let client = public_source_client("source.invalid", &[address]).unwrap();
        let url = format!("http://source.invalid:{}/source", address.port());
        let error = tokio::time::timeout(Duration::from_secs(1), client.get(&url).send())
            .await
            .expect("HTTP scheme refusal must precede network I/O")
            .unwrap_err();
        assert!(error.is_builder(), "{error}");
        assert_eq!(
            std::error::Error::source(&error).unwrap().to_string(),
            "URL scheme is not allowed"
        );
        assert_eq!(error.url().unwrap().as_str(), url);
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    // --- VCS sources ---------------------------------------------------

    #[test]
    fn git_source_matches_makepkg_filename_and_url() {
        // The exact shape reported in the field: `?signed` plus a `#tag=`
        // fragment must not change the SRCDEST entry name, and the URL handed
        // to git must drop both, because makepkg compares the mirror's
        // `remote.origin.url` against the stripped form.
        let source = extract_vcs_source(
            "git+https://gitlab.freedesktop.org/gstreamer/orc.git?signed#tag=0.4.44",
        )
        .expect("git+ sources must be recognised");

        assert_eq!(source.protocol, "git");
        assert_eq!(source.filename, "orc");
        assert_eq!(
            source.url,
            "https://gitlab.freedesktop.org/gstreamer/orc.git"
        );
    }

    #[test]
    fn vcs_source_honours_rename_syntax() {
        let source = extract_vcs_source("custom::git+https://example.com/real-repo.git#tag=v1")
            .expect("renamed git+ sources must be recognised");

        assert_eq!(source.filename, "custom");
        assert_eq!(source.url, "https://example.com/real-repo.git");
    }

    #[test]
    fn other_vcs_protocols_are_recognised_without_a_git_suffix() {
        for (entry, protocol, filename) in [
            ("svn+https://svn.example.com/project/trunk", "svn", "trunk"),
            ("hg+https://hg.example.com/repo", "hg", "repo"),
            (
                "bzr+https://launchpad.net/bzr-project",
                "bzr",
                "bzr-project",
            ),
            (
                "fossil+https://fossil.example.com/repo",
                "fossil",
                "repo.fossil",
            ),
        ] {
            let source = extract_vcs_source(entry).expect("VCS entry must be recognised");
            assert_eq!(source.protocol, protocol, "{entry}");
            assert_eq!(source.filename, filename, "{entry}");
        }
    }

    #[test]
    fn plain_https_and_local_sources_are_not_vcs() {
        assert!(extract_vcs_source("https://example.com/file.tar.gz").is_none());
        assert!(extract_vcs_source("local-file.patch").is_none());
        assert!(extract_vcs_source("https://example.com/repo.git").is_none());
    }

    #[test]
    fn only_public_https_git_urls_are_eligible_for_host_prefetch() {
        assert!(is_prefetchable_git_url("https://example.com/repo.git"));
        assert!(!is_prefetchable_git_url("ssh://git@example.com/repo.git"));
        assert!(!is_prefetchable_git_url("file:///srv/repo.git"));
        assert!(!is_prefetchable_git_url("https://127.0.0.1/repo.git"));
        assert!(!is_prefetchable_git_url(
            "https://user:secret@example.com/repo.git"
        ));
        assert!(!is_prefetchable_git_url("http://example.com/repo.git"));
        assert!(!is_prefetchable_git_url("git://example.com/repo.git"));
    }

    #[test]
    fn source_filenames_may_not_escape_srcdest() {
        for rejected in ["", ".", "..", "a/b", "a\\b", "/absolute"] {
            assert!(
                validate_source_filename(rejected).is_err(),
                "{rejected:?} must be rejected"
            );
        }
        for accepted in ["orc", "source.tar.gz", ".hidden"] {
            assert!(
                validate_source_filename(accepted).is_ok(),
                "{accepted:?} must be accepted"
            );
        }
    }

    #[tokio::test]
    async fn prepopulated_git_mirror_is_reused_without_network_for_any_transport() {
        let temp = tempfile::tempdir().expect("tempdir");
        let origin = temp.path().join("origin");
        std::fs::create_dir_all(&origin).expect("create origin");

        // Build the fixture with a single shell invocation so this test forks
        // the test process once instead of once per Git command. Other suites
        // rely on `flock` timing, and every fork in this process briefly
        // duplicates the whole descriptor table.
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(
                "set -e\n\
                 git init --quiet --initial-branch=main\n\
                 printf hello > README\n\
                 git add README\n\
                 git commit --quiet -m init\n\
                 git tag v1\n",
            )
            .current_dir(&origin)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.com")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.com")
            .status()
            .expect("git available");
        assert!(status.success(), "failed to build the origin fixture");

        let srcdest = temp.path().join("srcdest");
        std::fs::create_dir_all(&srcdest).expect("create srcdest");
        let status = std::process::Command::new("git")
            .args(["clone", "--mirror", "--"])
            .arg(format!("file://{}", origin.display()))
            .arg(srcdest.join("mirror"))
            .status()
            .expect("git clone fixture");
        assert!(status.success());
        for url in [
            "https://example.com/repo.git",
            "ssh://git@example.com/repo.git",
            "file:///srv/private.git",
        ] {
            let source = VcsSource {
                protocol: "git".to_string(),
                url: url.to_string(),
                filename: "mirror".to_string(),
                raw: format!("git+{url}#tag=v1"),
            };
            let summary = prefetch_vcs_sources(std::slice::from_ref(&source), &srcdest).await;
            assert_eq!(
                summary.cached.len(),
                1,
                "mirror must be reused: {summary:?}"
            );
            assert!(summary.prefetched.is_empty(), "{summary:?}");
            assert!(summary.needs_network.is_empty(), "{summary:?}");
        }
        assert!(srcdest.join("mirror").join("objects").is_dir());
    }

    #[tokio::test]
    async fn host_git_clone_has_output_duration_and_staging_budgets() {
        let temp = tempfile::tempdir().expect("isolated Git staging");
        let staging = temp.path().join("mirror");
        std::fs::create_dir(&staging).expect("staging directory");
        let limits = GitLimits {
            stdout_bytes: 64,
            stderr_bytes: 64,
            staging_bytes: 64,
            staging_entries: 32,
            poll_interval: Duration::from_millis(10),
        };

        let mut noisy = tokio::process::Command::new("sh");
        noisy.args(["-c", "head -c 4096 /dev/zero >&2"]);
        let error = run_bounded_git(
            &mut noisy,
            &staging,
            limits,
            tokio::time::Instant::now() + Duration::from_millis(500),
        )
        .await
        .expect_err("excessive Git output must fail");
        assert!(format!("{error:#}").contains("captured-output limit"));

        let mut stalled = tokio::process::Command::new("sh");
        stalled.args(["-c", "sleep 10"]);
        let error = run_bounded_git(
            &mut stalled,
            &staging,
            limits,
            tokio::time::Instant::now() + Duration::from_millis(500),
        )
        .await
        .expect_err("stalled Git clone must fail");
        assert!(format!("{error:#}").contains("duration limit"));

        let mut oversized = tokio::process::Command::new("sh");
        oversized
            .current_dir(&staging)
            .args(["-c", "head -c 4096 /dev/zero > payload; sleep 10"]);
        let error = run_bounded_git(
            &mut oversized,
            &staging,
            limits,
            tokio::time::Instant::now() + Duration::from_millis(500),
        )
        .await
        .expect_err("oversized Git mirror must fail");
        assert!(format!("{error:#}").contains("staged-byte limit"));

        let normal_staging = temp.path().join("normal");
        std::fs::create_dir(&normal_staging).expect("normal staging directory");
        let mut normal = tokio::process::Command::new("sh");
        normal
            .current_dir(&normal_staging)
            .args(["-c", "printf ok >&2; printf x > payload"]);
        let output = run_bounded_git(
            &mut normal,
            &normal_staging,
            limits,
            tokio::time::Instant::now() + Duration::from_millis(500),
        )
        .await
        .expect("small Git output and mirror must be accepted");
        assert!(output.status.success());
        assert_eq!(output.stderr, b"ok");
    }

    struct OwnedGitHelper {
        identity_file: std::path::PathBuf,
    }

    impl OwnedGitHelper {
        fn identity(stat: &str) -> Option<(i32, &str, &str)> {
            let (pid, _) = stat.split_once(' ')?;
            let (_, fields) = stat.rsplit_once(')')?;
            let mut fields = fields.split_whitespace();
            let state = fields.next()?;
            let start_time = fields.nth(18)?;
            Some((pid.parse().ok()?, start_time, state))
        }

        fn running_pid(&self) -> Option<i32> {
            let recorded = std::fs::read_to_string(&self.identity_file).ok()?;
            let (pid, start_time, _) = Self::identity(&recorded)?;
            let current = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            let (_, current_start, state) = Self::identity(&current)?;
            (start_time == current_start && state != "Z" && state != "X").then_some(pid)
        }

        fn terminate(&self) {
            if let Some(pid) = self.running_pid() {
                let result = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGKILL,
                );
                eprintln!("Owned inert Git helper {pid} cleanup attempt: {result:?}");
            }
        }

        async fn wait_until_stopped(&self, budget: Duration) -> bool {
            tokio::time::timeout(budget, async {
                while self.running_pid().is_some() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .is_ok()
        }

        async fn stopped_before_cleanup(&self) -> bool {
            let recorded = std::fs::read_to_string(&self.identity_file)
                .expect("helper identity must be recorded");
            let (pid, _, state) = Self::identity(&recorded)
                .expect("recorded helper identity must contain PID and start time");
            assert!(pid > 0, "recorded helper PID must be positive");
            assert!(
                state != "Z" && state != "X",
                "fixture helper must start alive"
            );
            let stopped = self.wait_until_stopped(Duration::from_millis(250)).await;
            self.terminate();
            assert!(
                self.wait_until_stopped(Duration::from_secs(1)).await,
                "owned inert helper must stop before the assertion"
            );
            stopped
        }
    }

    impl Drop for OwnedGitHelper {
        fn drop(&mut self) {
            self.terminate();
        }
    }

    #[tokio::test]
    async fn owned_git_helper_cleanup_stops_a_live_child_after_timeout() -> Result<()> {
        use std::os::unix::process::ExitStatusExt;

        let staging = tempfile::tempdir()?;
        let mut child = tokio::process::Command::new("sleep")
            .arg("30")
            .kill_on_drop(true)
            .spawn()?;
        let pid = child.id().expect("inert helper was spawned");
        let helper = OwnedGitHelper {
            identity_file: staging.path().join("helper.stat"),
        };
        let identity = std::fs::read(format!("/proc/{pid}/stat"))?;
        std::fs::write(&helper.identity_file, identity)?;
        assert_eq!(helper.running_pid(), i32::try_from(pid).ok());
        let stopped_without_cleanup = helper.stopped_before_cleanup().await;
        let status = tokio::time::timeout(Duration::from_secs(1), child.wait()).await??;
        assert!(
            !stopped_without_cleanup,
            "the live child must exercise fallback cleanup"
        );
        assert_eq!(status.signal(), Some(nix::libc::SIGKILL));
        assert!(helper.running_pid().is_none());
        Ok(())
    }

    #[tokio::test]
    async fn successful_host_git_clone_terminates_descendants_with_closed_pipes() {
        let staging = tempfile::tempdir().expect("isolated Git staging");
        let helper = OwnedGitHelper {
            identity_file: staging.path().join("helper.stat"),
        };
        let mut command = tokio::process::Command::new("sh");
        command.current_dir(staging.path()).args([
            "-c",
            "sleep 60 </dev/null >/dev/null 2>&1 & helper=$!; cat /proc/$helper/stat > helper.stat",
        ]);
        let result = run_bounded_git(
            &mut command,
            staging.path(),
            GitLimits {
                stdout_bytes: 1024,
                stderr_bytes: 1024,
                staging_bytes: 4096,
                staging_entries: 32,
                poll_interval: Duration::from_millis(10),
            },
            tokio::time::Instant::now() + Duration::from_secs(2),
        )
        .await;
        let output = result.expect("direct Git fixture child must succeed");
        assert!(output.status.success());
        assert!(
            helper.stopped_before_cleanup().await,
            "successful Git clone left its owned helper alive after the direct child exited"
        );
    }

    #[tokio::test]
    async fn successful_git_command_closes_pipes_inherited_by_surviving_helper() {
        let staging = tempfile::tempdir().expect("isolated Git staging");
        let helper = OwnedGitHelper {
            identity_file: staging.path().join("helper.stat"),
        };
        let mut command = tokio::process::Command::new("sh");
        command.current_dir(staging.path()).args([
            "-c",
            "sleep 60 & helper=$!; cat /proc/$helper/stat > helper.stat; printf completed",
        ]);
        let result = run_bounded_git(
            &mut command,
            staging.path(),
            GitLimits {
                stdout_bytes: 1024,
                stderr_bytes: 1024,
                staging_bytes: 4096,
                staging_entries: 32,
                poll_interval: Duration::from_millis(10),
            },
            tokio::time::Instant::now() + Duration::from_secs(2),
        )
        .await;
        let stopped = helper.stopped_before_cleanup().await;
        let output = result.expect("inherited pipes must close after the direct child exits");
        assert!(output.status.success());
        assert_eq!(output.stdout, b"completed");
        assert!(stopped, "successful Git command must terminate its helper");
    }

    #[tokio::test]
    async fn git_output_refusal_terminates_its_owned_helper() {
        let staging = tempfile::tempdir().expect("isolated Git staging");
        let helper = OwnedGitHelper {
            identity_file: staging.path().join("helper.stat"),
        };
        let mut command = tokio::process::Command::new("sh");
        command.current_dir(staging.path()).args([
            "-c",
            "sleep 60 </dev/null >/dev/null 2>&1 & helper=$!; cat /proc/$helper/stat > helper.stat; head -c 65 /dev/zero; wait",
        ]);
        let result = run_bounded_git(
            &mut command,
            staging.path(),
            GitLimits {
                stdout_bytes: 64,
                stderr_bytes: 64,
                staging_bytes: 4096,
                staging_entries: 32,
                poll_interval: Duration::from_millis(10),
            },
            tokio::time::Instant::now() + Duration::from_secs(2),
        )
        .await;
        let stopped = helper.stopped_before_cleanup().await;
        let error = result.expect_err("finite output overrun must refuse");
        assert!(
            error
                .to_string()
                .contains("stdout exceeded its captured-output limit"),
            "{error:#}"
        );
        assert!(stopped, "Git output refusal must terminate its helper");
    }

    #[tokio::test]
    async fn cancelling_host_git_clone_terminates_descendants() {
        let temp = tempfile::tempdir().expect("isolated Git staging");
        let staging = temp.path().join("mirror");
        std::fs::create_dir(&staging).expect("staging directory");
        let ready = staging.join("ready");
        let survived = staging.join("survived");
        let task_staging = staging.clone();
        let worker = tokio::spawn(async move {
            let mut command = tokio::process::Command::new("sh");
            command.current_dir(&task_staging).args([
                "-c",
                "printf ready > ready; (sleep 1; printf survived > survived) & wait",
            ]);
            run_bounded_git(
                &mut command,
                &task_staging,
                GitLimits {
                    stdout_bytes: 64,
                    stderr_bytes: 64,
                    staging_bytes: 1024,
                    staging_entries: 32,
                    poll_interval: Duration::from_millis(10),
                },
                tokio::time::Instant::now() + Duration::from_secs(10),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while !ready.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("clone fixture started");
        worker.abort();
        let _ = worker.await;
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(!survived.exists(), "cancelled Git descendants must not run");
    }

    #[tokio::test]
    async fn unprefetchable_vcs_sources_are_reported_not_silently_skipped() {
        let temp = tempfile::tempdir().expect("tempdir");
        let srcdest = temp.path().join("srcdest");
        std::fs::create_dir_all(&srcdest).expect("create srcdest");

        let sources = vec![
            VcsSource {
                protocol: "svn".to_string(),
                url: "https://svn.example.com/project/trunk".to_string(),
                filename: "trunk".to_string(),
                raw: "svn+https://svn.example.com/project/trunk".to_string(),
            },
            VcsSource {
                protocol: "git".to_string(),
                url: "http://example.com/repo.git".to_string(),
                filename: "repo".to_string(),
                raw: "git+http://example.com/repo.git".to_string(),
            },
            VcsSource {
                protocol: "git".to_string(),
                url: "file:///srv/private.git".to_string(),
                filename: "private".to_string(),
                raw: "git+file:///srv/private.git".to_string(),
            },
        ];

        let summary = prefetch_vcs_sources(&sources, &srcdest).await;
        assert_eq!(summary.needs_network.len(), 3, "{summary:?}");
        assert!(summary.prefetched.is_empty(), "{summary:?}");
    }
}
