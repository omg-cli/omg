//! OMG Daemon Binary
//!
//! Persistent daemon with Unix socket IPC for fast package operations.

// Use mimalloc as global allocator for 10-20% faster allocations
#[cfg(unix)]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(unix)]
use anyhow::{Context, Result};
#[cfg(unix)]
use clap::Parser;
#[cfg(unix)]
use futures::FutureExt;
#[cfg(unix)]
use sentry_tracing::EventFilter;
#[cfg(unix)]
use std::{fs, io::Write as _, path::PathBuf};
#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(unix)]
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[cfg(unix)]
use omg_lib::core::paths;
#[cfg(unix)]
use omg_lib::daemon::server;

/// OMG Daemon - Background service for fast package operations
#[cfg(unix)]
#[derive(Parser, Debug)]
#[command(name = "omgd")]
#[command(author = "OMG Team")]
#[command(version)]
#[command(about = "OMG Daemon for fast package operations")]
struct Args {
    /// Socket path (default: $`XDG_RUNTIME_DIR/omg.sock`)
    #[arg(short, long)]
    socket: Option<PathBuf>,
}

#[cfg(unix)]
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize Sentry (opt-in via OMG_SENTRY_DSN; no-op when unset)
    let _guard = sentry::init((
        std::env::var("OMG_SENTRY_DSN").ok(),
        sentry::ClientOptions::new()
            .maybe_release(sentry::release_name!())
            .attach_stacktrace(true)
            // A daemon must not stall shutdown waiting for the telemetry
            // transport; events that cannot flush in 200ms are dropped.
            .shutdown_timeout(std::time::Duration::from_millis(200)),
    ));

    // Initialize tracing with Sentry integration
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let sentry_layer = sentry_tracing::layer().event_filter(|md| match md.level() {
        &tracing::Level::ERROR => EventFilter::Event,
        _ => EventFilter::Breadcrumb,
    });

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .with(sentry_layer)
        .init();

    // Determine socket path and establish a private, user-owned runtime directory.
    let socket_path = args.socket.unwrap_or_else(paths::socket_path);
    paths::prepare_socket_parent(&socket_path).with_context(|| {
        format!(
            "Refusing insecure daemon socket directory for {}",
            socket_path.display()
        )
    })?;

    tracing::info!("Starting OMG daemon (omgd) v{}", env!("CARGO_PKG_VERSION"));

    tracing::info!("Initializing daemon state...");
    let state = match omg_lib::daemon::handlers::DaemonState::new() {
        Ok(s) => std::sync::Arc::new(s),
        Err(e) => {
            tracing::error!("Failed to initialize daemon state: {:#}", e);
            tracing::error!("Troubleshooting:");
            tracing::error!("  1. Ensure package databases are synced: sudo omg sync");
            tracing::error!("  2. Check if another daemon is running: pgrep omgd");
            tracing::error!(
                "  3. Check permissions and free disk space for ~/.local/share/omg/daemon"
            );
            return Err(e);
        }
    };

    // Claim the daemon singleton via an exclusive flock before touching the
    // socket file. A live daemon holds this lock for its whole lifetime, so
    // acquiring it proves any previous owner exited and makes the stale-socket
    // unlink below safe (no TOCTOU where a second start deletes a live
    // daemon's socket).
    let _daemon_claim = match claim_daemon_lock(&socket_path) {
        Ok(claim) => claim,
        Err(e) => {
            tracing::error!("{:#}", e);
            return Err(e);
        }
    };

    // Check if daemon is already responding on the socket. The ping is kept
    // for compatibility with daemons from versions that did not take the lock;
    // once every daemon holds the claim, the lock alone decides.
    if socket_path.exists() {
        if let Ok(mut client) =
            omg_lib::core::client::DaemonClient::connect_to(socket_path.clone()).await
            && client.ping().await.is_ok()
        {
            anyhow::bail!(
                "Daemon is already running and responding on {}",
                socket_path.display()
            );
        }
        remove_stale_socket(&socket_path)?;
    }

    // Create Unix socket listener. The node is created owner-only
    // (umask tightened around bind) so there is no window where the socket
    // accepts connections from other users before the explicit 0600 below.
    let listener = {
        use nix::sys::stat::{Mode, umask};
        let previous = umask(Mode::S_IRWXG | Mode::S_IRWXO);
        let listener = UnixListener::bind(&socket_path);
        umask(previous);
        listener?
    };
    // RAII cleanup: removes the socket file on every exit path from here on
    // (graceful shutdown, fatal accept error, or panic caught below), so a
    // dead daemon never leaves a stale socket behind.
    let _socket_guard = SocketCleanup::new(socket_path.clone())?;
    tracing::info!("Listening on {:?}", socket_path);

    // Set socket permissions (user only)
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&socket_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&socket_path, perms)?;
    }

    // Run server
    // Capture panics in Sentry
    let result = std::panic::AssertUnwindSafe(async {
        server::run(listener, state, socket_path.clone()).await
    })
    .catch_unwind()
    .await;

    match result {
        Ok(run_result) => run_result?,
        Err(e) => {
            let panic_message = e
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| e.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("unknown error");
            let msg = format!("Daemon panicked: {panic_message}");

            tracing::error!("{msg}");
            anyhow::bail!(msg);
        }
    }

    Ok(()) // `_socket_guard` removes the socket file on drop
}

fn remove_stale_socket(socket_path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let metadata = std::fs::symlink_metadata(socket_path)
        .with_context(|| format!("Failed to inspect stale socket {}", socket_path.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_socket(),
        "Refusing to remove {}: stale daemon path is not a socket",
        socket_path.display()
    );
    let uid = metadata.uid();
    anyhow::ensure!(
        uid == nix::unistd::getuid().as_raw() || uid == 0,
        "Refusing to remove {}: not a socket we own (uid {uid})",
        socket_path.display()
    );

    tracing::debug!("Removing stale socket at {:?}", socket_path);
    std::fs::remove_file(socket_path)
        .with_context(|| format!("Failed to remove stale socket {}", socket_path.display()))
}

/// RAII guard that removes the daemon socket file when dropped.
///
/// Rust API Guidelines C-MUST_USE: dropping a guard immediately is almost
/// always an accident (it would delete the live listener's socket node).
/// https://rust-lang.github.io/api-guidelines/necessities.html#c-must-use-must-use
#[must_use = "the socket file is removed when this guard drops; discard the binding only at shutdown"]
struct SocketCleanup {
    socket_path: PathBuf,
    device: u64,
    inode: u64,
}

impl SocketCleanup {
    fn new(socket_path: PathBuf) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(&socket_path)?;
        Ok(Self {
            socket_path,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        if paths::validate_socket_parent(&self.socket_path).is_err() {
            tracing::warn!("Skipping cleanup of an insecure daemon socket path");
            return;
        }
        let Ok(metadata) = fs::symlink_metadata(&self.socket_path) else {
            return;
        };
        if !metadata.file_type().is_socket()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
        {
            return;
        }
        if let Err(error) = std::fs::remove_file(&self.socket_path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                "Failed to remove daemon socket {}: {error}",
                self.socket_path.display()
            );
        }
    }
}

/// Exclusive-lifetime handle on the daemon singleton claim.
///
/// Dropping it releases the flock, allowing the next daemon start to proceed.
/// Rust API Guidelines C-MUST_USE: an unbound (immediately dropped) claim
/// would let a second daemon start concurrently.
/// https://rust-lang.github.io/api-guidelines/necessities.html#c-must-use-must-use
#[must_use = "dropping this claim releases the daemon singleton lock"]
struct DaemonClaim {
    /// Held open (and locked) for the lifetime of the daemon.
    _lock_file: fs::File,
}

fn daemon_lock_path(socket_path: &std::path::Path) -> PathBuf {
    let mut lock_name = socket_path.as_os_str().to_os_string();
    lock_name.push(".lock");
    PathBuf::from(lock_name)
}

fn claim_daemon_lock(socket_path: &std::path::Path) -> Result<DaemonClaim> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    paths::validate_socket_parent(socket_path)?;

    let lock_path = daemon_lock_path(socket_path);
    let mut lock_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(&lock_path)
        .with_context(|| format!("Failed to open daemon lock file {}", lock_path.display()))?;

    let metadata = lock_file.metadata()?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.uid() == nix::unistd::getuid().as_raw()
            && metadata.nlink() == 1,
        "Daemon lock must be an owned regular file with one link"
    );

    use std::os::unix::io::AsFd as _;

    rustix::fs::flock(
        lock_file.as_fd(),
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .map_err(|error| {
        anyhow::anyhow!(
            "Another omgd daemon owns {} (lock: {}): {error}",
            socket_path.display(),
            lock_path.display()
        )
    })?;

    // Record the owning pid for operators inspecting the runtime directory.
    lock_file.set_len(0).with_context(|| {
        format!(
            "Failed to truncate daemon lock file {}",
            lock_path.display()
        )
    })?;
    writeln!(lock_file, "{}", std::process::id())
        .with_context(|| format!("Failed to record daemon pid in {}", lock_path.display()))?;

    Ok(DaemonClaim {
        _lock_file: lock_file,
    })
}

#[cfg(all(test, unix))]
#[path = "../../tests/support/cli_surface.rs"]
mod cli_surface;

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn export_omgd_surface() {
        use clap::CommandFactory;
        let document = cli_surface::surface(Args::command());
        let root = document["commands"]
            .as_array()
            .expect("commands")
            .iter()
            .find(|entry| entry["path"] == "omgd")
            .expect("daemon root");
        let socket = root["arguments"]
            .as_array()
            .expect("arguments")
            .iter()
            .find(|entry| entry["id"] == "socket")
            .expect("socket argument");
        assert_eq!(socket["short"], "s");
        assert_eq!(socket["long"], "socket");
        cli_surface::write_artifact("omgd", document);
    }

    #[test]
    fn socket_parser_preserves_literal_paths_and_rejects_conflicting_repeats() {
        use clap::error::ErrorKind;
        for option in ["-s", "--socket"] {
            let args = Args::try_parse_from(["omgd", option, "/tmp/a space/omg.sock"]).unwrap();
            assert_eq!(args.socket, Some(PathBuf::from("/tmp/a space/omg.sock")));
        }
        assert!(Args::try_parse_from(["omgd"]).unwrap().socket.is_none());
        assert_eq!(
            Args::try_parse_from(["omgd", "--socket"])
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidValue
        );
        assert_eq!(
            Args::try_parse_from(["omgd", "-s", "one", "--socket", "two"])
                .unwrap_err()
                .kind(),
            ErrorKind::ArgumentConflict
        );
        assert_eq!(
            Args::try_parse_from(["omgd", "--foreground"])
                .unwrap_err()
                .kind(),
            ErrorKind::UnknownArgument
        );
    }

    #[test]
    fn lock_claim_rejects_symlink_and_preserves_target() {
        let directory = tempfile::tempdir().expect("directory");
        let socket = directory.path().join("omg.sock");
        let target = directory.path().join("target");
        fs::write(&target, "preserved").expect("target");
        std::os::unix::fs::symlink(&target, daemon_lock_path(&socket)).expect("link");
        assert!(claim_daemon_lock(&socket).is_err());
        assert_eq!(fs::read_to_string(target).expect("read"), "preserved");
    }

    #[test]
    fn custom_socket_rejects_replaceable_ancestor() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().expect("directory");
        let shared = directory.path().join("shared");
        fs::create_dir(&shared).expect("shared");
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).expect("mode");
        let private = shared.join("private");
        fs::create_dir(&private).expect("private");
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).expect("mode");
        assert!(paths::validate_socket_parent(&private.join("omg.sock")).is_err());
    }

    #[test]
    fn cleanup_preserves_replacement_node() {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("omg.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("socket");
        let guard = SocketCleanup::new(path.clone()).expect("guard");
        fs::remove_file(&path).expect("remove original");
        fs::write(&path, "replacement").expect("replacement");
        drop(guard);
        assert_eq!(fs::read_to_string(path).expect("read"), "replacement");
        drop(listener);
    }

    #[test]
    fn socket_parent_rejects_hidden_replaceable_symlink_target() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let directory = tempfile::tempdir().expect("directory");
        let safe = directory.path().join("safe");
        let shared = directory.path().join("shared");
        fs::create_dir_all(safe.join("private")).expect("safe");
        fs::set_permissions(safe.join("private"), fs::Permissions::from_mode(0o700)).expect("mode");
        fs::create_dir(&shared).expect("shared");
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).expect("mode");
        symlink(&safe, shared.join("jump")).expect("jump");
        symlink(shared.join("jump"), directory.path().join("link")).expect("link");
        let socket = directory.path().join("link/private/omg.sock");
        assert!(paths::validate_socket_parent(&socket).is_err());
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o700)).expect("mode");
        assert!(paths::validate_socket_parent(&socket).is_ok());
    }

    #[test]
    fn stale_socket_cleanup_rejects_non_socket_paths() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("omg.sock");
        std::fs::write(&path, b"foreign data").expect("foreign path");

        let error = remove_stale_socket(&path).expect_err("regular files must be preserved");
        assert!(error.to_string().contains("is not a socket"), "{error}");
        assert!(path.exists());
    }

    #[test]
    fn stale_socket_cleanup_removes_owned_socket() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("omg.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("socket");

        remove_stale_socket(&path).expect("owned socket cleanup");
        assert!(!path.exists());
        drop(listener);
    }

    #[test]
    fn removed_foreground_flag_is_rejected() {
        assert!(Args::try_parse_from(["omgd", "--foreground"]).is_err());
    }
}

// Windows stub - daemon not supported
#[cfg(not(unix))]
fn main() {
    eprintln!("Error: omgd daemon is only supported on Unix-like systems");
    std::process::exit(1);
}
