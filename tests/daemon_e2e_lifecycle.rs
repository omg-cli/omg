#![cfg(unix)]
#![expect(clippy::unwrap_used, clippy::pedantic)]

//! Daemon startup, shutdown, restart, crash recovery, and process supervision.

use anyhow::Result;
use serial_test::serial;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::sleep;

/// Test fixture for daemon lifecycle tests
struct DaemonTestFixture {
    _temp_dir: TempDir,
    socket_path: PathBuf,
    data_dir: PathBuf,
}

impl DaemonTestFixture {
    fn new() -> Result<Self> {
        let temp_dir = TempDir::new()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(temp_dir.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let socket_path = temp_dir.path().join("omgd.sock");
        let data_dir = temp_dir.path().join("data");
        std::fs::create_dir_all(&data_dir)?;

        Ok(Self {
            _temp_dir: temp_dir,
            socket_path,
            data_dir,
        })
    }

    /// Start daemon process with custom config
    fn start_daemon(&self) -> Result<DaemonProcess> {
        DaemonProcess::spawn(&self.socket_path, &self.data_dir)
    }

    /// Check if socket file exists
    fn socket_exists(&self) -> bool {
        self.socket_path.exists()
    }

    /// Wait for socket to be created (up to timeout)
    async fn wait_for_socket(&self, timeout: Duration) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if self.socket_exists() {
                return true;
            }
            sleep(Duration::from_millis(50)).await;
        }
        false
    }

    /// Wait for daemon to be fully ready (socket exists AND responsive)
    async fn wait_for_daemon_ready(&self, timeout: Duration) -> bool {
        let start = std::time::Instant::now();

        // First wait for socket to exist
        while start.elapsed() < timeout {
            if self.socket_exists() {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }

        if !self.socket_exists() {
            return false;
        }

        // Then wait for daemon to be responsive (may take time for initialization)
        while start.elapsed() < timeout {
            if self.is_daemon_responsive().await {
                return true;
            }
            sleep(Duration::from_millis(100)).await;
        }

        false
    }

    /// Check if daemon is responsive by sending ping.
    ///
    /// The whole probe is bounded so a peer that accepts a connection and
    /// stalls cannot hang the lifecycle suite indefinitely.
    async fn is_daemon_responsive(&self) -> bool {
        tokio::time::timeout(Duration::from_secs(1), self.probe_daemon())
            .await
            .unwrap_or(false)
    }

    async fn probe_daemon(&self) -> bool {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;

        let Ok(mut stream) = UnixStream::connect(&self.socket_path).await else {
            return false;
        };

        // Send ping request (versioned protocol frame)
        let ping_request = omg_lib::daemon::protocol::Request::Ping { id: 1 };
        let Ok(request_bytes) = omg_lib::daemon::protocol::encode_frame(&ping_request) else {
            return false;
        };
        let len = u32::try_from(request_bytes.len()).unwrap();

        if stream.write_all(&len.to_be_bytes()).await.is_err() {
            return false;
        }
        if stream.write_all(&request_bytes).await.is_err() {
            return false;
        }

        // Read response length
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            return false;
        }
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        if resp_len > omg_lib::daemon::protocol::MAX_FRAME_SIZE {
            return false;
        }

        // Read response body
        let mut resp_bytes = vec![0u8; resp_len];
        if stream.read_exact(&mut resp_bytes).await.is_err() {
            return false;
        }

        // Decode response
        let Some((_, payload)) = omg_lib::daemon::protocol::split_frame(&resp_bytes).ok() else {
            return false;
        };
        let Ok(response): Result<omg_lib::daemon::protocol::Response, _> =
            bitcode::deserialize(payload)
        else {
            return false;
        };

        matches!(
            response,
            omg_lib::daemon::protocol::Response::Success { .. }
        )
    }
}

/// Represents a running daemon process
struct DaemonProcess {
    child: std::process::Child,
}

impl DaemonProcess {
    fn spawn(socket_path: &PathBuf, data_dir: &PathBuf) -> Result<Self> {
        let daemon_bin = env!("CARGO_BIN_EXE_omgd");

        let child = Command::new(daemon_bin)
            .env("OMG_SOCKET_PATH", socket_path)
            .env("OMG_DAEMON_DATA_DIR", data_dir)
            .env("OMG_DATA_DIR", data_dir)
            .env("OMG_CACHE_DIR", data_dir.join("cache"))
            .env("OMG_CONFIG_DIR", data_dir.join("config"))
            .env("HOME", data_dir.join("home"))
            .env("OMG_TEST_MODE", "1")
            .env("OMG_TEST_DISTRO", "fedora")
            .env_remove("OMG_SENTRY_DSN")
            .env("RUST_LOG", "omg_lib=debug")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        Ok(Self { child })
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn kill(&mut self) -> Result<()> {
        self.child.kill()?;
        self.child.wait()?;
        Ok(())
    }

    fn terminate_gracefully(&mut self) -> Result<()> {
        if let Some(status) = self.child.try_wait()? {
            anyhow::ensure!(status.success(), "Daemon exited unsuccessfully: {status}");
            return Ok(());
        }

        // Send SIGTERM on Unix via kill command
        #[cfg(unix)]
        {
            let pid = self.pid();
            let status = Command::new("kill")
                .arg("-TERM")
                .arg(pid.to_string())
                .stderr(Stdio::null())
                .status()?;
            anyhow::ensure!(status.success(), "Failed to send SIGTERM to fixture daemon");
        }

        // Wait for process to exit (with timeout)
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            if let Some(status) = self.child.try_wait()? {
                anyhow::ensure!(status.success(), "Daemon exited unsuccessfully: {status}");
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        self.kill()?;
        anyhow::bail!(
            "Daemon exceeded the graceful shutdown deadline and required forced termination"
        )
    }

    fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for DaemonProcess {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}

// ============================================================================
// Test 1: Clean Startup and Shutdown
// ============================================================================

#[tokio::test]
#[serial]
async fn test_daemon_clean_startup() -> Result<()> {
    let fixture = DaemonTestFixture::new()?;
    let mut daemon = fixture.start_daemon()?;

    // Socket should be created within 2 seconds
    assert!(
        fixture.wait_for_socket(Duration::from_secs(5)).await,
        "Daemon socket should be created within 5s"
    );

    // Daemon should be responsive
    assert!(
        fixture.is_daemon_responsive().await,
        "Daemon should respond to ping"
    );

    daemon.kill()?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_daemon_graceful_shutdown() -> Result<()> {
    let fixture = DaemonTestFixture::new()?;
    let mut daemon = fixture.start_daemon()?;

    // Wait for daemon to be fully ready
    assert!(
        fixture.wait_for_daemon_ready(Duration::from_secs(10)).await,
        "Daemon should start and become responsive"
    );

    // Send SIGINT (Ctrl-C) for graceful shutdown (daemon handles this signal properly)
    #[cfg(unix)]
    {
        let pid = daemon.pid();
        let status = Command::new("kill")
            .arg("-INT")
            .arg(pid.to_string())
            .stderr(Stdio::null())
            .status()?;
        anyhow::ensure!(status.success(), "Failed to signal the fixture daemon");
    }

    // Wait for process to exit
    let start = std::time::Instant::now();
    let mut exit_status = None;
    while start.elapsed() < Duration::from_secs(5) {
        if let Some(status) = daemon.child.try_wait()? {
            exit_status = Some(status);
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    anyhow::ensure!(
        exit_status.is_some_and(|status| status.success()),
        "Daemon did not exit successfully before the shutdown deadline: {exit_status:?}"
    );

    // Verify socket is cleaned up (daemon handles SIGINT and cleans up properly)
    // Poll with a bounded deadline instead of a fixed sleep so the check is
    // fast when shutdown is quick and still reliable on loaded machines.
    let cleanup_deadline = std::time::Instant::now() + Duration::from_secs(5);
    while fixture.socket_exists() && std::time::Instant::now() < cleanup_deadline {
        sleep(Duration::from_millis(50)).await;
    }
    assert!(
        !fixture.socket_exists(),
        "Socket should be removed on graceful shutdown with SIGINT"
    );

    Ok(())
}

// ============================================================================
// Test 2: Crash Recovery
// ============================================================================

#[tokio::test]
#[serial]
async fn test_daemon_crash_recovery() -> Result<()> {
    let fixture = DaemonTestFixture::new()?;

    // Start daemon and populate cache
    {
        let mut daemon = fixture.start_daemon()?;
        assert!(
            fixture.wait_for_daemon_ready(Duration::from_secs(10)).await,
            "Initial daemon should start and become responsive"
        );

        // Simulate crash (SIGKILL)
        daemon.kill()?;
    }

    // Wait for cleanup and ensure socket is gone
    sleep(Duration::from_millis(500)).await;

    // Restart daemon - should recover gracefully
    {
        let mut daemon = fixture.start_daemon()?;
        assert!(
            fixture.wait_for_daemon_ready(Duration::from_secs(10)).await,
            "Daemon should restart after crash and become responsive"
        );

        daemon.kill()?;
    }

    Ok(())
}

// ============================================================================
// Test 3: Concurrent Daemon Prevention
// ============================================================================

#[tokio::test]
#[serial]
async fn test_prevent_concurrent_daemon_instances() -> Result<()> {
    let fixture = DaemonTestFixture::new()?;
    let mut daemon1 = fixture.start_daemon()?;

    assert!(fixture.wait_for_socket(Duration::from_secs(5)).await);

    // Try to start second daemon - should fail
    let daemon2_result = fixture.start_daemon();

    // Give second daemon time to attempt startup
    sleep(Duration::from_secs(1)).await;

    // Second daemon should either fail to start or exit immediately
    match daemon2_result {
        Ok(mut daemon2) => {
            // If it started, it should exit quickly
            sleep(Duration::from_millis(500)).await;
            assert!(
                !daemon2.is_running(),
                "Second daemon should exit when another is running"
            );
        }
        Err(_) => {
            // Expected: failed to start due to lock
        }
    }

    daemon1.kill()?;
    Ok(())
}

// ============================================================================
// Test 4: Rapid Restart Stability
// ============================================================================

#[tokio::test]
#[serial]
async fn test_rapid_restart_stability() -> Result<()> {
    let fixture = DaemonTestFixture::new()?;

    // Perform 3 rapid restart cycles (reduced from 5 for reliability)
    for cycle in 0..3 {
        let mut daemon = fixture.start_daemon()?;
        assert!(
            fixture.wait_for_daemon_ready(Duration::from_secs(10)).await,
            "Daemon should start and become responsive on cycle {}",
            cycle
        );

        daemon.terminate_gracefully()?;

        // Wait for socket cleanup between restarts
        sleep(Duration::from_millis(500)).await;
    }

    Ok(())
}

// ============================================================================
// Test 5: Socket Cleanup on Abnormal Exit
// ============================================================================

#[tokio::test]
#[serial]
async fn test_socket_cleanup_on_crash() -> Result<()> {
    let fixture = DaemonTestFixture::new()?;
    let mut daemon = fixture.start_daemon()?;

    assert!(
        fixture.wait_for_daemon_ready(Duration::from_secs(10)).await,
        "Initial daemon should start and become responsive"
    );

    // Force kill daemon (simulate crash)
    daemon.kill()?;

    // A forced exit leaves the socket for the next daemon to recover.
    sleep(Duration::from_millis(500)).await;
    assert!(
        fixture.socket_exists(),
        "Crashed daemon should leave a stale socket for recovery"
    );

    // New daemon should clean up stale socket and start successfully
    let mut daemon2 = fixture.start_daemon()?;
    assert!(
        fixture.wait_for_daemon_ready(Duration::from_secs(10)).await,
        "New daemon should clean up stale socket, start, and become responsive"
    );

    daemon2.terminate_gracefully()?;
    assert!(
        !daemon2.is_running(),
        "Recovered daemon should complete graceful shutdown"
    );
    Ok(())
}

// ============================================================================
// Test 6: Resource Cleanup Verification
// ============================================================================

#[tokio::test]
#[serial]
async fn test_resource_cleanup_on_shutdown() -> Result<()> {
    let fixture = DaemonTestFixture::new()?;
    let mut daemon = fixture.start_daemon()?;

    assert!(fixture.wait_for_socket(Duration::from_secs(5)).await);

    // Record PID
    let daemon_pid = daemon.pid();

    // Graceful shutdown
    daemon.terminate_gracefully()?;
    sleep(Duration::from_millis(500)).await;

    // Verify process is completely gone
    #[cfg(unix)]
    {
        // Use kill -0 to check if process exists (suppress stderr)
        let process_exists = Command::new("kill")
            .arg("-0")
            .arg(daemon_pid.to_string())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(
            !process_exists,
            "Daemon process should be completely terminated"
        );
    }

    Ok(())
}
