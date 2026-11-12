#![cfg(feature = "arch")]

//! Contract tests for `src/package_managers/aur_sources.rs`.
//!
//! Pins:
//! - `parse_sources`: .SRCINFO source extraction (missing file, filtering,
//!   rename syntax, arch-specific sources, parse-error reporting)
//! - `download_sources`: hostile filename rejection, cache skip,
//!   non-regular destination failure, unreachable URL failure, empty input
//!
//! Every test pins an exact observable contract; each one has been mutation
//! verified to fail when the guarded product logic is broken.

pub mod common;

use std::fs;
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use omg_lib::package_managers::aur_sources::{
    SourceFile, download_sources, parse_sources, parse_vcs_sources,
};

/// Local HTTP server with observable requests and deterministic shutdown.
struct LocalHttpServer {
    base_url: String,
    requests: Arc<AtomicUsize>,
    shutdown: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl LocalHttpServer {
    fn start(max_requests: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind localhost");
        listener
            .set_nonblocking(true)
            .expect("set listener nonblocking");
        let addr = listener.local_addr().expect("local addr");
        let requests = Arc::new(AtomicUsize::new(0));
        let thread_requests = Arc::clone(&requests);
        let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            while thread_requests.load(Ordering::Relaxed) < max_requests {
                if shutdown_rx.try_recv().is_ok() {
                    break;
                }
                match listener.accept() {
                    Ok((mut conn, _)) => {
                        thread_requests.fetch_add(1, Ordering::Relaxed);
                        let mut buf = [0u8; 1024];
                        let _ = conn.read(&mut buf);
                        let body = "hello";
                        let _ = write!(
                            conn,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            base_url: format!("http://{addr}"),
            requests,
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
        }
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::Relaxed)
    }
}

impl Drop for LocalHttpServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().expect("local HTTP server thread panicked");
        }
    }
}

/// Minimal valid .SRCINFO body with the given extra lines appended to the
/// pkgbase section.
fn srcinfo_body<S: AsRef<str>>(extra: &[S]) -> String {
    let mut content = String::from("pkgbase = example\n");
    content.push_str("\tpkgver = 1.0.0\n");
    content.push_str("\tpkgrel = 1\n");
    content.push_str("\tpkgdesc = test package\n");
    for line in extra {
        content.push('\t');
        content.push_str(line.as_ref());
        content.push('\n');
    }
    content.push('\n');
    content.push_str("pkgname = example\n");
    content
}

fn write_srcinfo(dir: &Path, content: &str) {
    fs::write(dir.join(".SRCINFO"), content).expect("write .SRCINFO");
}

// ---------------------------------------------------------------------------
// parse_sources
// ---------------------------------------------------------------------------

/// Missing .SRCINFO is not an error: it must yield an empty list so builds of
/// packages without sources proceed.
#[test]
fn parse_sources_missing_file_yields_empty() {
    let dir = tempfile::tempdir().unwrap();
    let sources = parse_sources(dir.path()).expect("missing .SRCINFO must be Ok");
    assert!(sources.is_empty(), "expected no sources, got {sources:?}");
}

/// Only http:// and https:// sources are extracted; local files and git repos
/// are skipped. The surviving entry must carry its exact URL and filename.
#[test]
fn parse_sources_filters_to_http_and_pins_exact_fields() {
    let dir = tempfile::tempdir().unwrap();
    write_srcinfo(
        dir.path(),
        &srcinfo_body(&[
            "arch = x86_64",
            "source = https://example.com/tarball-1.2.tar.gz",
            "source = local-file.patch",
            "source = git+https://github.com/user/repo.git#branch=main",
        ]),
    );

    let sources = parse_sources(dir.path()).expect("parse must succeed");

    assert_eq!(
        sources.len(),
        1,
        "only the https source survives: {sources:?}"
    );
    assert_eq!(sources[0].url, "https://example.com/tarball-1.2.tar.gz");
    assert_eq!(sources[0].filename, "tarball-1.2.tar.gz");
}

/// PKGBUILD rename syntax (`name::url`) must rename the download while
/// stripping the prefix from the URL.
#[test]
fn parse_sources_rename_syntax_rewrites_filename_only() {
    let dir = tempfile::tempdir().unwrap();
    write_srcinfo(
        dir.path(),
        &srcinfo_body(&[
            "arch = x86_64",
            "source = renamed-output.tar.gz::https://example.com/weird-upstream-name-v3.tar.xz",
        ]),
    );

    let sources = parse_sources(dir.path()).expect("parse must succeed");
    assert_eq!(sources.len(), 1);
    assert_eq!(
        sources[0].url,
        "https://example.com/weird-upstream-name-v3.tar.xz"
    );
    assert_eq!(sources[0].filename, "renamed-output.tar.gz");
}

#[test]
fn parse_sources_preserves_makepkg_query_filename_and_url() {
    let dir = tempfile::tempdir().unwrap();
    write_srcinfo(
        dir.path(),
        &srcinfo_body(&[
            "arch = x86_64",
            "source = https://example.com/f.tar.gz?token=abc",
        ]),
    );

    let sources = parse_sources(dir.path()).expect("parse must succeed");
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].url, "https://example.com/f.tar.gz?token=abc");
    assert_eq!(sources[0].filename, "f.tar.gz?token=abc");
}

/// Architecture-specific `source_<arch>` entries are merged in for the running
/// architecture and never for foreign ones. Mirrors the host-arch switch used
/// by the product code so this stays valid on any build host.
#[test]
fn parse_sources_includes_current_arch_specific_sources_only() {
    let current = match std::env::consts::ARCH {
        "x86_64" => Some("x86_64"),
        "aarch64" => Some("aarch64"),
        "arm" => Some("arm"),
        "i686" => Some("i686"),
        _ => None,
    };
    let mut extra = vec![
        "arch = x86_64".to_string(),
        "source = https://common.example.com/c.tgz".to_string(),
    ];
    if let Some(arch) = current {
        extra.push(format!("source_{arch} = https://arch.example.com/a.tgz"));
    }
    // A foreign-architecture entry that must be ignored on any host.
    let foreign = if current == Some("x86_64") {
        "aarch64"
    } else {
        "x86_64"
    };
    extra.push(format!(
        "source_{foreign} = https://foreign.example.com/f.tgz"
    ));

    let dir = tempfile::tempdir().unwrap();
    write_srcinfo(dir.path(), &srcinfo_body(&extra));

    let sources = parse_sources(dir.path()).expect("parse must succeed");
    let names: Vec<String> = sources.iter().map(|s| s.filename.clone()).collect();

    if current.is_some() {
        assert!(
            names.contains(&"a.tgz".to_string()),
            "current-arch source missing from {names:?}"
        );
    }
    assert!(
        !names.iter().any(|f| f == "f.tgz"),
        "foreign-arch source leaked into {names:?}"
    );
    assert!(
        names.contains(&"c.tgz".to_string()),
        "common source missing from {names:?}"
    );
    assert_eq!(names.len(), if current.is_some() { 2 } else { 1 });
}

/// Unparsable .SRCINFO must surface as an explicit error naming the failure —
/// not silently degrade to an empty source list.
#[test]
fn parse_sources_invalid_content_is_error_naming_cause() {
    let dir = tempfile::tempdir().unwrap();
    // No pkgbase/pkgver/pkgrel at all: structurally invalid SRCINFO.
    write_srcinfo(dir.path(), "\tnonsense-key with no value structure\n");

    let error = parse_sources(dir.path()).expect_err("garbage .SRCINFO must be an Err");
    let message = format!("{error:#}");
    assert!(
        message.contains("Failed to parse .SRCINFO"),
        "error must name the parsing stage, got: {message}"
    );
}

#[test]
fn source_path_apis_refuse_oversized_regular_metadata() {
    let directory = tempfile::tempdir().expect("isolated metadata fixture");
    let metadata = fs::File::create(directory.path().join(".SRCINFO")).expect("metadata file");
    metadata
        .set_len(16 * 1024 * 1024 + 1)
        .expect("bounded sparse metadata fixture");
    let http_error =
        parse_sources(directory.path()).expect_err("oversized HTTP metadata must fail");
    let vcs_error =
        parse_vcs_sources(directory.path()).expect_err("oversized VCS metadata must fail");
    for error in [http_error, vcs_error] {
        assert!(
            format!("{error:#}").contains("source file exceeds limit"),
            "{error:#}"
        );
    }
}

#[test]
fn source_path_apis_refuse_symlinked_metadata_and_preserve_missing_vcs() {
    let directory = tempfile::tempdir().expect("isolated metadata fixture");
    assert!(
        parse_vcs_sources(directory.path())
            .expect("absent VCS metadata")
            .is_empty()
    );
    let target = directory.path().join("metadata");
    fs::write(
        &target,
        srcinfo_body(&["source = git+https://example.com/repo.git"]),
    )
    .expect("valid metadata target");
    std::os::unix::fs::symlink(&target, directory.path().join(".SRCINFO"))
        .expect("symlinked metadata fixture");
    assert!(
        parse_sources(directory.path()).is_err(),
        "HTTP metadata must not follow a symlink"
    );
    assert!(
        parse_vcs_sources(directory.path()).is_err(),
        "VCS metadata must not follow a symlink"
    );
}

// ---------------------------------------------------------------------------
// download_sources (offline contracts only: no real network required)
// ---------------------------------------------------------------------------

/// Empty input short-circuits to an all-zero summary.
#[tokio::test]
async fn download_sources_empty_input_zero_summary() {
    let srcdest = tempfile::tempdir().unwrap();
    let summary = download_sources(Vec::new(), srcdest.path()).await;
    assert_eq!(summary.succeeded, 0);
    assert_eq!(summary.failed, 0);
}

/// Hostile filenames from a malicious PKGBUILD's rename syntax must be
/// rejected before any network request and without writing anywhere —
/// especially outside SRCDEST. A live local HTTP server proves the requests
/// are never made: if rejection were removed, `../escape.txt` would be
/// fetched from the server and materialize OUTSIDE SRCDEST.
#[tokio::test]
async fn download_sources_rejects_hostile_filenames_without_writes() {
    let parent = tempfile::tempdir().unwrap();
    let srcdest = parent.path().join("srcdest");
    let hostile = [
        "../escape.txt",
        "sub/dir.txt",
        "..\\backslash.txt",
        "..",
        "",
    ];
    let server = LocalHttpServer::start(hostile.len());

    let sources: Vec<SourceFile> = hostile
        .iter()
        .map(|name| SourceFile {
            url: format!("{}/payload", server.base_url),
            filename: (*name).to_string(),
        })
        .collect();

    let summary = download_sources(sources, &srcdest).await;

    assert_eq!(
        summary.failed,
        hostile.len(),
        "every hostile name must count as failed"
    );
    assert_eq!(summary.succeeded, 0);
    assert_eq!(
        server.request_count(),
        0,
        "hostile filenames must be rejected before network access"
    );

    // Nothing may exist next to (or above) SRCDEST: the escape target
    // `parent/escape.txt` would appear here if path traversal were allowed.
    let leaked: Vec<_> = fs::read_dir(parent.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n != "srcdest")
        .collect();
    assert!(
        leaked.is_empty(),
        "hostile filenames escaped SRCDEST, created: {leaked:?}"
    );
    // And no nested directories were created inside SRCDEST either.
    if let Ok(entries) = fs::read_dir(&srcdest) {
        assert!(
            entries.count() == 0,
            "SRCDEST should stay empty after rejections"
        );
    }
}

/// An already-present regular file in SRCDEST counts as success WITHOUT any
/// network access — proven by using a guaranteed-unreachable URL.
#[tokio::test]
async fn download_sources_cached_file_succeeds_without_network() {
    let srcdest = tempfile::tempdir().unwrap();
    fs::write(srcdest.path().join("cached.tgz"), b"pretend-content").unwrap();

    let summary = download_sources(
        vec![SourceFile {
            // RFC 6761 reserved TLD: resolution can never succeed.
            url: "https://unreachable.invalid/cached.tgz".to_string(),
            filename: "cached.tgz".to_string(),
        }],
        srcdest.path(),
    )
    .await;

    assert_eq!(summary.succeeded, 1, "cached file must report success");
    assert_eq!(summary.failed, 0);
    assert_eq!(
        fs::read(srcdest.path().join("cached.tgz")).unwrap(),
        b"pretend-content",
        "cache must be left untouched"
    );
}

#[tokio::test]
async fn download_sources_dedups_identical_filenames() {
    let srcdest = tempfile::tempdir().unwrap();
    fs::write(srcdest.path().join("same.deb"), b"cached").unwrap();

    let summary = download_sources(
        vec![
            SourceFile {
                url: "https://unreachable.invalid/same.deb".to_string(),
                filename: "same.deb".to_string(),
            },
            SourceFile {
                url: "https://unreachable.invalid/same.deb".to_string(),
                filename: "same.deb".to_string(),
            },
        ],
        srcdest.path(),
    )
    .await;

    assert_eq!(summary.succeeded, 1);
    assert_eq!(summary.failed, 0);
}

/// A non-regular file occupying the destination path (here: a directory) must
/// be reported as a failure, never clobbered or downloaded over.
#[tokio::test]
async fn download_sources_non_regular_dest_path_fails() {
    let srcdest = tempfile::tempdir().unwrap();
    fs::create_dir(srcdest.path().join("occupied.tgz")).unwrap();

    let summary = download_sources(
        vec![SourceFile {
            url: "https://unreachable.invalid/occupied.tgz".to_string(),
            filename: "occupied.tgz".to_string(),
        }],
        srcdest.path(),
    )
    .await;

    assert_eq!(summary.failed, 1, "directory at dest path must fail");
    assert_eq!(summary.succeeded, 0);
    // The occupant must still be there, untouched.
    let meta = fs::symlink_metadata(srcdest.path().join("occupied.tgz")).unwrap();
    assert!(
        meta.is_dir(),
        "existing directory must not have been replaced"
    );
}

/// An unreachable URL must land in the failed bucket and leave no partial or
/// placeholder file behind.
#[tokio::test]
async fn download_sources_unreachable_url_fails_cleanly() {
    let srcdest = tempfile::tempdir().unwrap();

    let summary = download_sources(
        vec![SourceFile {
            url: "https://definitely-not-a-host.invalid/x.tgz".to_string(),
            filename: "x.tgz".to_string(),
        }],
        srcdest.path(),
    )
    .await;

    assert_eq!(summary.failed, 1);
    assert_eq!(summary.succeeded, 0);
    let leftovers: Vec<_> = fs::read_dir(srcdest.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        leftovers.is_empty(),
        "failed download left files: {leftovers:?}"
    );
}
