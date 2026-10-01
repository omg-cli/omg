//! Sudoloop: Keep sudo credentials alive during long operations
//!
//! Similar to yay's --sudoloop, this runs a background task that
//! periodically runs `sudo -v` to refresh the sudo timestamp.
//!
//! ## How it works
//!
//! 1. When started, the loop waits 30 seconds before the first refresh
//!    (since sudo timestamp is typically 5 minutes by default)
//! 2. Every 30 seconds thereafter, it runs `sudo -v` to extend the timestamp
//! 3. The loop automatically stops when dropped (RAII pattern)
//! 4. `refresh_now()` can be called for an immediate refresh before critical operations
//!
//! ## Example
//!
//! ```no_run
//! use omg_lib::core::sudoloop::{can_use_sudoloop, SudoLoop};
//!
//! if can_use_sudoloop() {
//!     let _sudoloop = SudoLoop::start();
//!     // ... long operation that needs sudo ...
//!     // sudoloop automatically stops when _sudoloop is dropped
//! }
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::time::sleep;

/// Interval between sudo credential refreshes (30 seconds)
///
/// We use an aggressive 30s interval because AUR builds can take many minutes
/// and the default sudo timestamp is 5 minutes. Refreshing every 30s ensures
/// credentials never expire during long build+install cycles.
const REFRESH_INTERVAL_SECS: u64 = 30;

/// Handle for a running sudoloop
///
/// The loop runs in a background task and will be stopped when this
/// handle is dropped.
pub struct SudoLoop {
    running: Arc<AtomicBool>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl SudoLoop {
    /// Start a sudoloop that refreshes sudo credentials periodically
    ///
    /// The loop waits 30 seconds before the first refresh, then runs
    /// `sudo -v` every 30 seconds to keep credentials alive.
    pub fn start() -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        let handle = tokio::spawn(async move {
            tracing::debug!("Sudoloop started");

            // Wait before first refresh (sudo timestamp is ~5 minutes by default)
            sleep(Duration::from_secs(REFRESH_INTERVAL_SECS)).await;

            while running_clone.load(Ordering::SeqCst) {
                // Refresh sudo timestamp with -v (validate, extend timeout).
                // kill_on_drop ensures an aborted loop cannot leave a detached
                // sudo child behind.
                let result = async {
                    let output = crate::core::privilege::sudo_command()?
                        .arg("-v")
                        .kill_on_drop(true)
                        .arg("-n")
                        .output()
                        .await?;
                    Ok::<_, anyhow::Error>(output)
                }
                .await;

                match result {
                    Ok(output) if output.status.success() => {
                        tracing::debug!("Sudoloop: credentials refreshed");
                    }
                    Ok(output) => {
                        let stderr = crate::cli::style::sanitize_terminal_text(
                            &String::from_utf8_lossy(&output.stderr),
                        );
                        tracing::warn!(
                            "Sudoloop: failed to refresh credentials: {}",
                            stderr.trim()
                        );
                        // Continue anyway - user might have NOPASSWD configured
                    }
                    Err(e) => {
                        tracing::warn!("Sudoloop: error running sudo -v: {e}");
                    }
                }

                // Wait before next refresh
                sleep(Duration::from_secs(REFRESH_INTERVAL_SECS)).await;
            }

            tracing::debug!("Sudoloop stopped");
        });

        Self {
            running,
            handle: Some(handle),
        }
    }

    /// Stop the sudoloop
    ///
    /// This signals the background task to stop and aborts it if needed.
    /// Called automatically when the `SudoLoop` is dropped.
    pub fn stop(&mut self) {
        // Signal the loop to stop
        self.running.store(false, Ordering::SeqCst);

        // Abort the task to ensure immediate cleanup
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }

    /// Check if the sudoloop is still running
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Immediately refresh sudo credentials
    ///
    /// Call this before operations that require sudo (e.g., package install)
    /// to ensure credentials are fresh, regardless of the periodic loop timing.
    /// Returns `true` if credentials were successfully refreshed, `false` if
    /// the refresh failed or the sudoloop was stopped. Callers can use this
    /// to detect expired credentials and re-prompt the user.
    pub async fn refresh_now(&self) -> bool {
        if !self.is_running() {
            return false;
        }

        tracing::debug!("Sudoloop: immediate credential refresh requested");

        let result = async {
            let output = crate::core::privilege::sudo_command()?
                .arg("-v")
                .stdin(std::process::Stdio::inherit())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::inherit())
                .arg("-n")
                .status()
                .await?;
            Ok::<_, anyhow::Error>(output)
        }
        .await;

        match result {
            Ok(status) if status.success() => {
                tracing::debug!("Sudoloop: credentials refreshed (immediate)");
                true
            }
            Ok(status) => {
                tracing::warn!(
                    "Sudoloop: immediate refresh failed with exit code {:?}",
                    status.code()
                );
                false
            }
            Err(e) => {
                tracing::warn!("Sudoloop: error during immediate refresh: {e}");
                false
            }
        }
    }
}

impl Drop for SudoLoop {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Check if we can use sudoloop (sudo is available and we're not root)
///
/// Returns `false` if:
/// - Already running as root (no need for sudo)
/// - sudo is not installed
#[must_use]
pub fn can_use_sudoloop() -> bool {
    !crate::core::is_root() && crate::core::privilege::root_controlled_program_path("sudo").is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sudoloop_start_stop() {
        let mut loop_handle = SudoLoop::start();

        // Should be running after start
        assert!(loop_handle.is_running());

        // Stop should set running to false
        loop_handle.stop();
        assert!(!loop_handle.is_running());
    }

    #[tokio::test]
    async fn test_sudoloop_drop_stops() {
        let running_flag;

        {
            let loop_handle = SudoLoop::start();
            running_flag = loop_handle.running.clone();
            assert!(running_flag.load(Ordering::SeqCst));
        }
        // After drop, should be stopped
        assert!(!running_flag.load(Ordering::SeqCst));
    }
}
