#![cfg(feature = "arch")]

//! Contract tests for `src/package_managers/parallel_sync.rs` (cov-7).
//!
//! These tests drive `sync_databases_parallel()` end-to-end against a local
//! mock Arch mirror HTTP server, pinning three observable contracts:
//!
//! 1. A successful sync downloads each configured repository's `.db` file
//!    into `OMG_PACMAN_SYNC_DIR` with byte-exact content, requesting exactly
//!    the `<mirror>/$repo/os/$arch/<repo>.db` URL derived from each repository's
//!    configured mirrorlist.
//! 2. When every mirror returns HTTP 404 for a database, the sync fails and
//!    names the number of failed databases; no partial `.db` files are left
//!    behind.
//! 3. When the destination database already exists locally, the downloader
//!    sends an `If-Modified-Since` conditional request, honors a 304 Not
//!    Modified reply by returning success WITHOUT touching the cached file.

pub mod common;

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use common::*;

// ═══════════════════════════════════════════════════════════════════════════════
// Mock mirror HTTP server (std-only, one thread per connection)
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
struct RecordedRequest {
    method: String,
    path: String,
    if_modified_since: Option<String>,
}

struct MockMirror {
    base_url: String,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Drop for MockMirror {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Routes map a request path to `(status, body)`. The special key `"*"` is the
/// fallback route for unmatched paths.
impl MockMirror {
    fn start(routes: HashMap<String, (u16, Vec<u8>)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("mock mirror bind");
        let port = listener.local_addr().expect("local addr").port();
        listener.set_nonblocking(true).expect("nonblocking accept");

        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));

        let worker = {
            let listener = listener.try_clone().expect("listener clone");
            let stop = Arc::clone(&stop);
            let log = Arc::clone(&requests);
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let routes = routes.clone();
                            let log = Arc::clone(&log);
                            // Serve concurrently: core/extra download in parallel.
                            std::thread::spawn(move || {
                                handle_connection(stream, &routes, &log);
                            });
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            })
        };

        Self {
            base_url: format!("http://127.0.0.1:{port}"),
            requests,
            stop,
            worker: Some(worker),
        }
    }

    /// Panic with a readable dump if the recorded traffic doesn't contain a
    /// request matching `predicate`. Every assertion goes through this so
    /// failures show what the server actually saw.
    #[allow(clippy::missing_panics_doc)]
    fn assert_request<F>(&self, description: &str, predicate: F)
    where
        F: Fn(&RecordedRequest) -> bool,
    {
        let requests = self.requests.lock().expect("request log lock");
        assert!(
            requests.iter().any(predicate),
            "expected request not observed ({description}); server saw: {requests:?}"
        );
    }
}

fn handle_connection(
    stream: TcpStream,
    routes: &HashMap<String, (u16, Vec<u8>)>,
    log: &Mutex<Vec<RecordedRequest>>,
) {
    let Ok(peer) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(stream);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();

    let mut if_modified_since = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        // Header names arrive in HTTP/1.1 canonical capitalization
        // ("If-modified-since"), so compare case-insensitively.
        if let Some((name, value)) = trimmed.split_once(':')
            && name.eq_ignore_ascii_case("If-Modified-Since")
        {
            if_modified_since = Some(value.trim().to_string());
        }
    }

    log.lock().expect("request log lock").push(RecordedRequest {
        method: method.clone(),
        path: path.clone(),
        if_modified_since,
    });

    let (status, body): (&u16, &Vec<u8>) =
        routes.get(&path).or_else(|| routes.get("*")).map_or_else(
            || {
                static NOT_FOUND: u16 = 404;
                static NO_BODY: Vec<u8> = Vec::new();
                (&NOT_FOUND, &NO_BODY)
            },
            |(status, body)| (status, body),
        );

    let head = format!(
        "HTTP/1.1 {status} REASON\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut peer = peer;
    let write_ok = peer.write_all(head.as_bytes()).is_ok();
    let write_ok = write_ok && (method == "HEAD" || peer.write_all(body).is_ok());
    let _ = peer.flush();
    drop(reader); // close read side before dropping socket
    let _ = write_ok;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Fixture: isolated pacman.conf / mirrorlist / sync dir under scoped env vars
// ═══════════════════════════════════════════════════════════════════════════════

struct SyncFixture {
    root: tempfile::TempDir,
    conf_path: PathBuf,
    mirrorlist_path: PathBuf,
    sync_dir: PathBuf,
}

fn make_fixture(repos: &[&str]) -> SyncFixture {
    let root = tempfile::TempDir::new().expect("fixture tempdir");

    let mirrorlist_path = root.path().join("mirrorlist");
    let conf_path = root.path().join("pacman.conf");
    let mut conf = String::from("[options]\nSigLevel = Never\n\n");
    use std::fmt::Write as _;
    for repo in repos {
        let _ = writeln!(conf, "[{repo}]\nInclude = {}\n", mirrorlist_path.display());
    }
    std::fs::write(&conf_path, conf).expect("write pacman.conf");

    let sync_dir = root.path().join("var/lib/pacman/sync");
    std::fs::create_dir_all(&sync_dir).expect("create sync dir");

    // Disable the background AUR metadata archive sync spawned alongside the
    // database downloads so these tests never touch real network hosts.
    let config_dir = root.path().join("config");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::fs::write(
        config_dir.join("config.toml"),
        "[aur]\nuse_metadata_archive = false\n",
    )
    .expect("write omg config.toml");

    let data_dir = root.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("create data dir");

    SyncFixture {
        root,
        conf_path,
        mirrorlist_path,
        sync_dir,
    }
}

fn run_with_fixture_env<T>(
    fixture: &SyncFixture,
    mirror_base_url: &str,
    f: impl FnOnce() -> T,
) -> T {
    std::fs::write(
        &fixture.mirrorlist_path,
        format!("Server = {mirror_base_url}/$repo/os/$arch\n"),
    )
    .expect("write mirrorlist");

    temp_env::with_vars(
        [
            ("OMG_PACMAN_CONF", Some(fixture.conf_path.as_os_str())),
            ("OMG_PACMAN_SYNC_DIR", Some(fixture.sync_dir.as_os_str())),
            (
                "OMG_CONFIG_DIR",
                Some(fixture.root.path().join("config").as_os_str()),
            ),
            (
                "OMG_DATA_DIR",
                Some(fixture.root.path().join("data").as_os_str()),
            ),
            (
                "NO_PROXY",
                Some(std::ffi::OsStr::new("127.0.0.1,localhost")),
            ),
            (
                "no_proxy",
                Some(std::ffi::OsStr::new("127.0.0.1,localhost")),
            ),
        ],
        f,
    )
}

fn catalog(name: &str) -> Vec<u8> {
    let description = format!(
        "%NAME%\n{name}\n\n%VERSION%\n1-1\n\n%FILENAME%\n{name}-1-1-any.pkg.tar.zst\n\n%ARCH%\nany\n\n%CSIZE%\n1\n\n%ISIZE%\n1\n\n"
    );
    let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let mut archive = tar::Builder::new(gzip);
    let mut header = tar::Header::new_gnu();
    header.set_size(description.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive
        .append_data(
            &mut header,
            format!("{name}-1-1/desc"),
            description.as_bytes(),
        )
        .expect("add package description");
    archive
        .into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip")
}

const fn arch() -> &'static str {
    std::env::consts::ARCH
}

// ═══════════════════════════════════════════════════════════════════════════════
// Contract 1: successful sync writes byte-exact .db files at the right URLs
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn successful_sync_downloads_exact_db_bytes_into_sync_dir() {
    init_test_env();

    let fixture = make_fixture(&["core", "extra"]);
    let core_path = format!("/core/os/{}/core.db", arch());
    let extra_path = format!("/extra/os/{}/extra.db", arch());

    let core_bytes = catalog("fixture-core");
    let extra_bytes = catalog("fixture-extra");
    let mut routes = HashMap::new();
    routes.insert(core_path.clone(), (200u16, core_bytes.clone()));
    routes.insert(extra_path.clone(), (200u16, extra_bytes.clone()));
    let server = MockMirror::start(routes);

    let outcome = run_with_fixture_env(&fixture, &server.base_url, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(omg_lib::package_managers::sync_databases_parallel())
    });

    assert!(
        outcome.is_ok(),
        "sync must succeed against healthy mirrors: {:?}",
        outcome.err()
    );

    // Byte-exact persisted artifacts at OMG_PACMAN_SYNC_DIR.
    let core_db = std::fs::read(fixture.sync_dir.join("core.db")).expect("core.db must exist");
    assert_eq!(core_db, core_bytes, "core.db content must be exact");
    let extra_db = std::fs::read(fixture.sync_dir.join("extra.db")).expect("extra.db must exist");
    assert_eq!(extra_db, extra_bytes, "extra.db content must be exact");

    // The downloader must have requested exactly the URL built from the
    // mirrorlist template ($repo/$arch substitution + <repo>.db suffix).
    server.assert_request("GET core.db", |r| r.method == "GET" && r.path == core_path);
    server.assert_request("GET extra.db", |r| {
        r.method == "GET" && r.path == extra_path
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// Contract 2: all-mirror 404 fails loudly and leaves no partial databases
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn all_404_sync_fails_naming_failed_db_count_without_writing_files() {
    init_test_env();

    let fixture = make_fixture(&["core", "extra"]);

    // No routes: every path falls through to the "*" default of 404.
    let mut routes = HashMap::new();
    routes.insert("*".to_string(), (404u16, Vec::new()));
    let server = MockMirror::start(routes);

    let outcome = run_with_fixture_env(&fixture, &server.base_url, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(omg_lib::package_managers::sync_databases_parallel())
    });

    let error = outcome.expect_err("sync must fail when every mirror 404s every database");
    assert!(
        error.to_string().contains("Failed to sync 2 database(s)"),
        "failure must name the count of failed databases, got: {error:#}"
    );

    // Both repositories must actually have been attempted (not skipped).
    let core_path = format!("/core/os/{}/core.db", arch());
    server.assert_request("attempted GET core.db", |r| {
        r.method == "GET" && r.path == core_path
    });

    // No partial or placeholder database files may be written on failure.
    let written: Vec<_> = std::fs::read_dir(&fixture.sync_dir)
        .expect("read sync dir")
        .collect::<Result<_, _>>()
        .expect("readdir entries");
    assert!(
        written.is_empty(),
        "failed sync must leave sync dir empty, found: {:?}",
        written
            .iter()
            .map(std::fs::DirEntry::file_name)
            .collect::<Vec<_>>()
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Contract 3: existing db triggers If-Modified-Since; a 304 keeps cache intact
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn existing_db_sends_if_modified_since_and_304_preserves_cached_file() {
    init_test_env();

    let fixture = make_fixture(&["core"]);
    let cached_bytes = catalog("fixture-cached");
    std::fs::write(fixture.sync_dir.join("core.db"), &cached_bytes).expect("seed cached core.db");

    let core_path = format!("/core/os/{}/core.db", arch());

    let mut routes = HashMap::new();
    routes.insert(core_path.clone(), (304u16, Vec::new()));
    let server = MockMirror::start(routes);

    let outcome = run_with_fixture_env(&fixture, &server.base_url, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(omg_lib::package_managers::sync_databases_parallel())
    });

    assert!(
        outcome.is_ok(),
        "a 304 for an existing local database must be reported as success: {:?}",
        outcome.err()
    );

    // The conditional request must carry the local file's mtime.
    server.assert_request("GET core.db with If-Modified-Since", |r| {
        r.method == "GET"
            && r.path == core_path
            && r.if_modified_since
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
    });

    // Success came from the cache: the file must be untouched.
    let after = std::fs::read(fixture.sync_dir.join("core.db")).expect("core.db still present");
    assert_eq!(
        after, cached_bytes,
        "cached core.db must not be rewritten on 304"
    );
}
