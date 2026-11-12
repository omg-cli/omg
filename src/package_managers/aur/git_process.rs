//! Bounded Git subprocess capture and process-group cleanup.

use std::convert::Infallible;
use std::path::Path;
use std::process::{ExitStatus, Output, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::time::Instant;

#[derive(Clone, Copy, Debug)]
pub(in crate::package_managers) struct GitLimits {
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub staging_bytes: u64,
    pub staging_entries: usize,
    pub poll_interval: Duration,
}

fn check_git_staging_budget(path: &Path, limits: GitLimits) -> Result<()> {
    let mut pending = vec![path.to_path_buf()];
    let mut entries = 1usize;
    let mut total = 0u64;
    while let Some(path) = pending.pop() {
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("Inspecting {}", path.display()));
            }
        };
        anyhow::ensure!(
            entries <= limits.staging_entries,
            "AUR Git operation exceeded its staged-entry limit ({})",
            limits.staging_entries
        );
        if metadata.is_dir() {
            for entry in std::fs::read_dir(&path)? {
                entries = entries
                    .checked_add(1)
                    .context("AUR Git entry count overflowed")?;
                anyhow::ensure!(
                    entries <= limits.staging_entries,
                    "AUR Git operation exceeded its staged-entry limit ({})",
                    limits.staging_entries
                );
                pending.push(entry?.path());
            }
        } else {
            total = total
                .checked_add(metadata.len())
                .context("AUR Git staged size overflowed")?;
            anyhow::ensure!(
                total <= limits.staging_bytes,
                "AUR Git operation exceeded its staged-byte limit ({})",
                limits.staging_bytes
            );
        }
    }
    Ok(())
}

async fn inspect_git_staging(path: &Path, limits: GitLimits) -> Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || check_git_staging_budget(&path, limits))
        .await
        .context("AUR Git staging inspection failed")?
}

async fn monitor_git_staging(path: &Path, limits: GitLimits) -> Result<Infallible> {
    loop {
        inspect_git_staging(path, limits).await?;
        tokio::time::sleep(limits.poll_interval).await;
    }
}

fn terminate_git_group(process_group: Pid) -> std::result::Result<(), Errno> {
    use nix::sys::signal::{Signal, killpg};
    killpg(process_group, Signal::SIGKILL)
}

struct GitGroupGuard<S: FnMut(Pid) -> std::result::Result<(), Errno>> {
    process_group: Option<Pid>,
    signal: S,
}

impl<S: FnMut(Pid) -> std::result::Result<(), Errno>> GitGroupGuard<S> {
    fn new(process_group: u32, signal: S) -> Result<Self> {
        let process_group = i32::try_from(process_group).context("Git process ID exceeded i32")?;
        anyhow::ensure!(process_group > 0, "Git process ID must be positive");
        Ok(Self {
            process_group: Some(Pid::from_raw(process_group)),
            signal,
        })
    }

    fn terminate(&mut self) -> Result<()> {
        if let Some(process_group) = self.process_group {
            match (self.signal)(process_group) {
                Ok(()) | Err(Errno::ESRCH) => {}
                Err(error) => {
                    return Err(error).context("Failed to terminate AUR Git process group");
                }
            }
            self.disarm();
        }
        Ok(())
    }

    const fn disarm(&mut self) {
        self.process_group = None;
    }
}

#[derive(Debug, PartialEq, Eq)]
enum GitExitObservation {
    Pending,
    Interrupted,
    Exited,
}

fn classify_git_exit(status: std::result::Result<WaitStatus, Errno>) -> Result<GitExitObservation> {
    match status {
        Ok(WaitStatus::StillAlive) => Ok(GitExitObservation::Pending),
        Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) => Ok(GitExitObservation::Exited),
        Ok(status) => anyhow::bail!("Unexpected AUR Git child status: {status:?}"),
        Err(Errno::EINTR) => Ok(GitExitObservation::Interrupted),
        Err(error) => Err(error).context("Failed to observe AUR Git child without reaping"),
    }
}

async fn observe_git_exit(process_id: u32) -> Result<()> {
    use nix::sys::wait::{Id, WaitPidFlag, waitid};

    observe_git_exit_with(process_id, |process_id| {
        // WNOWAIT keeps the leader's identity reserved until group termination.
        waitid(
            Id::Pid(process_id),
            WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT | WaitPidFlag::WNOHANG,
        )
    })
    .await
}

async fn observe_git_exit_with(
    process_id: u32,
    mut observe: impl FnMut(Pid) -> std::result::Result<WaitStatus, Errno>,
) -> Result<()> {
    let process_id =
        Pid::from_raw(i32::try_from(process_id).context("Git process ID exceeded i32")?);
    let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child())
        .context("Failed to observe AUR Git child exit")?;
    loop {
        match classify_git_exit(observe(process_id))? {
            GitExitObservation::Pending => {
                signal
                    .recv()
                    .await
                    .context("AUR Git child-exit signal closed")?;
            }
            GitExitObservation::Exited => return Ok(()),
            GitExitObservation::Interrupted => tokio::task::yield_now().await,
        }
    }
}

impl<S: FnMut(Pid) -> std::result::Result<(), Errno>> Drop for GitGroupGuard<S> {
    fn drop(&mut self) {
        if let Err(error) = self.terminate() {
            tracing::warn!(%error, "Failed to terminate cancelled AUR Git process group");
        }
    }
}

trait GitCleanupChild {
    fn start_kill(&mut self) -> std::io::Result<()>;
    fn wait(&mut self) -> impl std::future::Future<Output = std::io::Result<ExitStatus>> + Send;
}

impl GitCleanupChild for tokio::process::Child {
    fn start_kill(&mut self) -> std::io::Result<()> {
        Self::start_kill(self)
    }

    async fn wait(&mut self) -> std::io::Result<ExitStatus> {
        Self::wait(self).await
    }
}

async fn cleanup_git_child<S: FnMut(Pid) -> std::result::Result<(), Errno>>(
    group_guard: &mut GitGroupGuard<S>,
    child: &mut impl GitCleanupChild,
) -> Result<ExitStatus> {
    let terminated = group_guard
        .terminate()
        .map_err(|primary| match child.start_kill() {
            Ok(()) => primary,
            Err(error) => {
                tracing::warn!(%error, "Failed to terminate direct AUR Git child during cleanup");
                primary.context(format!(
                    "Failed to terminate direct AUR Git child during cleanup: {error}"
                ))
            }
        });
    group_guard.disarm();
    let reaped = match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
        Ok(status) => status.context("Failed to reap AUR Git command during cleanup"),
        Err(error) => Err(anyhow::Error::new(error)
            .context("AUR Git cleanup exceeded its five-second reap grace")),
    };
    match (terminated, reaped) {
        (Err(primary), Err(reap)) => {
            Err(primary.context(format!("Git command reap also failed: {reap:#}")))
        }
        (Err(primary), Ok(_)) => Err(primary),
        (Ok(()), reaped) => reaped,
    }
}

fn finish_git_output(
    result: Result<(Vec<u8>, Vec<u8>)>,
    cleanup: Result<ExitStatus>,
) -> Result<Output> {
    match (result, cleanup) {
        (Err(primary), Err(cleanup)) => {
            let context = format!("{primary}; Git cleanup also failed: {cleanup:#}");
            Err(primary.context(context))
        }
        (Err(primary), Ok(_)) => Err(primary),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Ok((stdout, stderr)), Ok(status)) => Ok(Output {
            status,
            stdout,
            stderr,
        }),
    }
}

async fn capture_git_pipe(
    pipe: impl AsyncRead + Unpin,
    limit: u64,
    stream: &str,
) -> Result<Vec<u8>> {
    let detection_limit = limit
        .checked_add(1)
        .context("AUR Git output limit overflowed")?;
    let mut output = Vec::new();
    pipe.take(detection_limit)
        .read_to_end(&mut output)
        .await
        .with_context(|| format!("Failed to capture AUR Git {stream}"))?;
    anyhow::ensure!(
        u64::try_from(output.len()).context("AUR Git output length overflowed")? <= limit,
        "AUR Git {stream} exceeded its captured-output limit ({limit} bytes)"
    );
    Ok(output)
}

/// Applies capture, elapsed-time and sampled staging limits without changing Git configuration.
///
/// Staging checks permit growth between samples. They are not a filesystem quota.
/// Cancellation kills the process group before the caller can remove its staging owner;
/// Tokio's kill-on-drop child retains responsibility for reaping the direct child.
pub(in crate::package_managers) async fn run_bounded_git(
    command: &mut Command,
    staging_path: &Path,
    limits: GitLimits,
    absolute_deadline: Instant,
) -> Result<Output> {
    anyhow::ensure!(
        Instant::now() < absolute_deadline,
        "AUR Git operation exceeded its duration limit"
    );
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    let mut child = command.spawn().context("Failed to run AUR Git command")?;
    let process_group = child.id().context("Git command has no process ID")?;
    let mut group_guard = GitGroupGuard::new(process_group, terminate_git_group)?;
    let stdout = child
        .stdout
        .take()
        .context("Git command has no stdout pipe")?;
    let stderr = child
        .stderr
        .take()
        .context("Git command has no stderr pipe")?;
    let result = tokio::time::timeout_at(absolute_deadline, async {
        tokio::select! {
            completed = async {
                let wait = async {
                    observe_git_exit(process_group).await?;
                    group_guard.terminate()?;
                    Ok::<_, anyhow::Error>(())
                };
                let ((), stdout, stderr) = tokio::try_join!(
                    wait,
                    capture_git_pipe(stdout, limits.stdout_bytes, "stdout"),
                    capture_git_pipe(stderr, limits.stderr_bytes, "stderr"),
                )?;
                inspect_git_staging(staging_path, limits).await?;
                Ok((stdout, stderr))
            } => completed,
            monitored = monitor_git_staging(staging_path, limits) => match monitored? {},
        }
    })
    .await
    .unwrap_or_else(|_| {
        Err(anyhow::anyhow!(
            "AUR Git operation exceeded its duration limit"
        ))
    });

    let cleanup = cleanup_git_child(&mut group_guard, &mut child).await;
    finish_git_output(result, cleanup)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn interrupted_observation_yields_and_retries_before_accepting_exit() {
        let mut observed = Vec::new();
        let mut outcomes = [
            Err(Errno::EINTR),
            Ok(WaitStatus::Exited(Pid::from_raw(123), 0)),
        ]
        .into_iter();
        let yielded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let witness = yielded.clone();
        let peer = tokio::spawn(async move {
            witness.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        tokio::time::timeout(
            Duration::from_secs(2),
            observe_git_exit_with(123, |pid| {
                observed.push(pid.as_raw());
                if observed.len() == 2 {
                    assert!(
                        yielded.load(std::sync::atomic::Ordering::SeqCst),
                        "EINTR retry must yield to other runtime work"
                    );
                }
                outcomes.next().expect("interruption then exit")
            }),
        )
        .await
        .expect("interrupted observation deadline")
        .expect("EINTR must not become terminal failure");
        peer.await.expect("yield witness task");
        assert_eq!(observed, [123, 123]);
    }

    #[tokio::test]
    async fn native_child_cleanup_adapter_kills_and_reaps_its_owned_child() {
        use std::os::unix::process::ExitStatusExt;
        let mut child = Command::new("sleep")
            .arg("30")
            .kill_on_drop(true)
            .spawn()
            .expect("owned cleanup adapter fixture");
        GitCleanupChild::start_kill(&mut child).expect("kill only this owned child");
        let status =
            tokio::time::timeout(Duration::from_secs(2), GitCleanupChild::wait(&mut child))
                .await
                .expect("owned child reap deadline")
                .expect("reap owned child");
        assert_eq!(status.signal(), Some(nix::libc::SIGKILL));
        assert!(
            child.id().is_none(),
            "reaped child cannot retain a live process identity"
        );
    }

    #[test]
    fn native_exit_observations_distinguish_retry_exit_and_invalid_status() {
        use nix::errno::Errno;
        use nix::sys::signal::Signal;
        use nix::sys::wait::WaitStatus;
        use nix::unistd::Pid;

        let pid = Pid::from_raw(123);
        assert_eq!(
            classify_git_exit(Ok(WaitStatus::StillAlive)).unwrap(),
            GitExitObservation::Pending
        );
        assert_eq!(
            classify_git_exit(Err(Errno::EINTR)).unwrap(),
            GitExitObservation::Interrupted
        );
        for status in [
            WaitStatus::Exited(pid, 7),
            WaitStatus::Signaled(pid, Signal::SIGKILL, false),
        ] {
            assert_eq!(
                classify_git_exit(Ok(status)).unwrap(),
                GitExitObservation::Exited
            );
        }
        let error = classify_git_exit(Ok(WaitStatus::Stopped(pid, Signal::SIGSTOP))).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Unexpected AUR Git child status")
        );
        let error = classify_git_exit(Err(Errno::ECHILD)).unwrap_err();
        assert_eq!(error.downcast_ref::<Errno>(), Some(&Errno::ECHILD));
    }

    #[test]
    fn signal_authority_is_consumed_only_after_success_or_absence() {
        use nix::errno::Errno;
        let calls = std::cell::RefCell::new(Vec::new());
        let mut outcomes = [Err(Errno::EPERM), Err(Errno::ESRCH)].into_iter();
        let mut guard = GitGroupGuard::new(123, |pid| {
            calls.borrow_mut().push(pid.as_raw());
            outcomes.next().expect("exactly two signal attempts")
        })
        .unwrap();
        let error = guard
            .terminate()
            .expect_err("signal denial must retain cleanup authority");
        assert_eq!(error.downcast_ref::<Errno>(), Some(&Errno::EPERM));
        assert!(guard.process_group.is_some());
        guard
            .terminate()
            .expect("an absent group needs no further cleanup");
        guard
            .terminate()
            .expect("consumed signal authority is idempotent");
        drop(guard);
        assert_eq!(*calls.borrow(), [123, 123]);
    }

    #[test]
    fn group_authority_refuses_unrepresentable_or_broadcast_identity() {
        let calls = std::cell::Cell::new(0);
        let signal = |_| {
            calls.set(calls.get() + 1);
            Ok(())
        };
        for process_group in [0, u32::MAX] {
            let guard = GitGroupGuard::new(process_group, signal);
            assert!(
                guard.is_err(),
                "invalid group {process_group} acquired signal authority"
            );
        }
        assert_eq!(
            calls.get(),
            0,
            "invalid identities must never reach the signal boundary"
        );
        let mut valid = GitGroupGuard::new(123, signal).expect("positive identity control");
        valid.terminate().expect("signal capability control");
        drop(valid);
        assert_eq!(
            calls.get(),
            1,
            "a valid identity invokes the same signal capability once"
        );
    }

    #[derive(Clone, Default)]
    struct WarningCapture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for WarningCapture {
        type Writer = tracing_subscriber::fmt::writer::MutexGuardWriter<'a, Vec<u8>>;

        fn make_writer(&'a self) -> Self::Writer {
            tracing_subscriber::fmt::MakeWriter::make_writer(self.0.as_ref())
        }
    }

    #[test]
    fn cancellation_reports_failed_group_termination_without_panicking() {
        let capture = WarningCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(capture.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let guard = GitGroupGuard::new(123, |_| Err(nix::errno::Errno::EPERM)).unwrap();
            drop(guard);
        });
        let bytes = capture.0.lock().expect("warning capture lock");
        let warning = String::from_utf8_lossy(&bytes);
        assert!(
            warning.contains("Failed to terminate cancelled AUR Git process group"),
            "{warning}"
        );
    }

    enum CleanupWait {
        Exited,
        Denied,
        Pending,
    }

    struct CleanupChild {
        events: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
        kill_fails: bool,
        wait: CleanupWait,
    }

    impl GitCleanupChild for CleanupChild {
        fn start_kill(&mut self) -> std::io::Result<()> {
            self.events
                .lock()
                .expect("cleanup events")
                .push("child kill");
            if self.kill_fails {
                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            } else {
                Ok(())
            }
        }
        async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
            use std::os::unix::process::ExitStatusExt;
            self.events.lock().expect("cleanup events").push("reap");
            match self.wait {
                CleanupWait::Pending => std::future::pending().await,
                CleanupWait::Denied => {
                    Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
                }
                CleanupWait::Exited => Ok(std::process::ExitStatus::from_raw(0)),
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cleanup_tries_child_after_group_failure_and_bounds_reaping() {
        use nix::errno::Errno;
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let signal_events = events.clone();
        let mut guard = GitGroupGuard::new(123, move |_| {
            signal_events
                .lock()
                .expect("cleanup events")
                .push("group kill");
            Err(Errno::EPERM)
        })
        .unwrap();
        let mut child = CleanupChild {
            events: events.clone(),
            kill_fails: true,
            wait: CleanupWait::Pending,
        };
        let started = Instant::now();
        let error = cleanup_git_child(&mut guard, &mut child).await.unwrap_err();
        assert_eq!(Instant::now() - started, Duration::from_secs(5));
        assert_eq!(error.downcast_ref::<Errno>(), Some(&Errno::EPERM));
        let diagnostic = format!("{error:#}");
        assert!(
            diagnostic.contains("five-second reap grace"),
            "the reap deadline was lost from the combined cleanup failure: {diagnostic}"
        );
        assert!(
            diagnostic.contains("direct AUR Git child"),
            "the failed fallback kill was lost from the cleanup failure: {diagnostic}"
        );
        assert!(
            diagnostic.contains("Failed to terminate AUR Git process group"),
            "the primary group failure was lost: {diagnostic}"
        );
        let operation_error =
            anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::InvalidData));
        let combined = finish_git_output(Err(operation_error), Err(error)).unwrap_err();
        assert_eq!(
            combined
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::InvalidData),
            "cleanup context must preserve the operation's primary cause"
        );
        let diagnostic = format!("{combined:#}");
        for context in [
            "process group",
            "direct AUR Git child",
            "five-second reap grace",
        ] {
            assert!(diagnostic.contains(context), "lost {context}: {diagnostic}");
        }
        assert!(
            guard.process_group.is_none(),
            "identity authority ends before reaping"
        );
        drop(guard);
        assert_eq!(
            *events.lock().expect("cleanup events"),
            ["group kill", "child kill", "reap"]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cleanup_reap_deadline_preserves_elapsed_cause() {
        let mut guard = GitGroupGuard::new(123, |_| Ok(())).unwrap();
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut child = CleanupChild {
            events: events.clone(),
            kill_fails: false,
            wait: CleanupWait::Pending,
        };
        let error = cleanup_git_child(&mut guard, &mut child).await.unwrap_err();
        assert!(error.to_string().contains("five-second reap grace"));
        assert!(
            error
                .downcast_ref::<tokio::time::error::Elapsed>()
                .is_some()
        );
        assert_eq!(*events.lock().expect("cleanup events"), ["reap"]);
    }

    #[tokio::test]
    async fn cleanup_preserves_wait_errors_and_group_errors_after_successful_fallback() {
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut child = CleanupChild {
            events: events.clone(),
            kill_fails: false,
            wait: CleanupWait::Denied,
        };
        let mut guard = GitGroupGuard::new(123, |_| Ok(())).unwrap();
        let error = cleanup_git_child(&mut guard, &mut child).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Failed to reap AUR Git command during cleanup")
        );
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::PermissionDenied)
        );

        child.wait = CleanupWait::Exited;
        let mut guard = GitGroupGuard::new(123, |_| Err(nix::errno::Errno::EPERM)).unwrap();
        let error = cleanup_git_child(&mut guard, &mut child).await.unwrap_err();
        assert_eq!(
            error.downcast_ref::<nix::errno::Errno>(),
            Some(&nix::errno::Errno::EPERM)
        );
        assert_eq!(
            *events.lock().expect("cleanup events"),
            ["reap", "child kill", "reap"]
        );
    }

    #[test]
    fn completion_preserves_primary_cause_and_cleanup_context() {
        use std::os::unix::process::ExitStatusExt;
        let status = || std::process::ExitStatus::from_raw(7 << 8);
        let primary = || anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::InvalidData));
        let error =
            finish_git_output(Err(primary()), Err(anyhow::anyhow!("signal denied"))).unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::InvalidData)
        );
        assert!(
            error
                .to_string()
                .contains("Git cleanup also failed: signal denied")
        );
        let error = finish_git_output(Err(primary()), Ok(status())).unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::InvalidData)
        );
        let error = finish_git_output(
            Ok((b"out".to_vec(), b"err".to_vec())),
            Err(anyhow::anyhow!("reap failed")),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "reap failed");
        let output =
            finish_git_output(Ok((b"out".to_vec(), b"err".to_vec())), Ok(status())).unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout, b"out");
        assert_eq!(output.stderr, b"err");
    }

    const fn limits() -> GitLimits {
        GitLimits {
            stdout_bytes: 4096,
            stderr_bytes: 4096,
            staging_bytes: 4096,
            staging_entries: 16,
            poll_interval: Duration::from_millis(5),
        }
    }

    #[tokio::test]
    async fn staging_inspection_preserves_filesystem_errors() {
        let staging = tempfile::tempdir().expect("private Git staging fixture");
        let file = staging.path().join("file");
        std::fs::write(&file, b"inert").expect("private non-directory ancestor");
        let path = file.join("child");
        let error = inspect_git_staging(&path, limits())
            .await
            .expect_err("a non-directory ancestor must not become absent staging");
        assert!(format!("{error:#}").contains(&path.display().to_string()));
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::NotADirectory)
        );
        assert_eq!(std::fs::read(&file).expect("unchanged ancestor"), b"inert");
        let monitored =
            tokio::time::timeout(Duration::from_secs(2), monitor_git_staging(&path, limits()))
                .await
                .expect("staging observation must propagate its filesystem error")
                .expect_err("a failed monitor cannot authorize continued Git execution");
        assert_eq!(
            monitored
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::NotADirectory)
        );
    }

    #[tokio::test]
    async fn exit_observation_refuses_a_process_that_is_not_our_child() {
        let error =
            tokio::time::timeout(Duration::from_secs(2), observe_git_exit(std::process::id()))
                .await
                .expect("non-child observation must not wait for a signal")
                .expect_err("the caller cannot reserve its own child identity");
        assert!(format!("{error:#}").contains("without reaping"));
        assert_eq!(
            error.downcast_ref::<nix::errno::Errno>(),
            Some(&nix::errno::Errno::ECHILD)
        );
    }

    #[tokio::test]
    async fn capture_preserves_read_failures_and_refuses_overflowing_limits() {
        let directory = tempfile::tempdir().expect("private capture fixture");
        let input = tokio::fs::File::open(directory.path())
            .await
            .expect("Linux permits opening a directory before refusing reads");
        let error = capture_git_pipe(input, 16, "stderr")
            .await
            .expect_err("an input read failure must not become empty diagnostics");
        assert!(format!("{error:#}").contains("Failed to capture AUR Git stderr"));
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::IsADirectory)
        );
        let error = capture_git_pipe(tokio::io::empty(), u64::MAX, "stdout")
            .await
            .expect_err("the extra detection byte must not wrap the configured limit");
        assert!(error.to_string().contains("output limit overflowed"));
    }

    #[tokio::test]
    async fn missing_program_preserves_the_spawn_error_without_creating_staging() {
        let owner = tempfile::tempdir().expect("private missing-command fixture");
        let staging = owner.path().join("not-created");
        let mut command = Command::new(owner.path().join("missing-git"));
        let error = run_bounded_git(
            &mut command,
            &staging,
            limits(),
            Instant::now() + Duration::from_secs(2),
        )
        .await
        .expect_err("a missing executable must preserve its cause");
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::NotFound)
        );
        assert!(!staging.exists());
    }

    #[tokio::test]
    async fn exited_leader_remains_waitable_until_group_termination() {
        use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};
        use nix::unistd::Pid;

        let mut command = Command::new("sh");
        command
            .args(["-c", "exit 0"])
            .process_group(0)
            .kill_on_drop(true);
        let mut child = command.spawn().expect("private Git exit fixture");
        let process_id = child.id().expect("private fixture process ID");
        let mut guard = GitGroupGuard::new(process_id, terminate_git_group)
            .expect("private fixture process group");
        tokio::time::timeout(Duration::from_secs(2), observe_git_exit(process_id))
            .await
            .expect("exit observation deadline")
            .expect("exit observation");
        let status = waitid(
            Id::Pid(Pid::from_raw(
                i32::try_from(process_id).expect("fixture PID fits"),
            )),
            WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT | WaitPidFlag::WNOHANG,
        )
        .expect("observed leader must still belong to this parent");
        assert!(matches!(status, WaitStatus::Exited(_, 0)), "{status:?}");
        guard
            .terminate()
            .expect("terminate while leader identity remains reserved");
        assert!(
            guard.process_group.is_none(),
            "termination consumes the signal authority"
        );
        let status = tokio::time::timeout(Duration::from_secs(2), child.wait())
            .await
            .expect("fixture reap deadline")
            .expect("fixture reap");
        assert!(status.success());
        guard
            .terminate()
            .expect("a consumed guard performs no second signal");
    }

    #[tokio::test]
    async fn both_output_streams_accept_exact_limits_and_refuse_one_more_byte() {
        let staging = tempfile::tempdir().expect("Git staging");
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "head -c 4096 /dev/zero & head -c 4096 /dev/zero >&2; wait",
        ]);
        let output = run_bounded_git(
            &mut command,
            staging.path(),
            limits(),
            Instant::now() + Duration::from_secs(2),
        )
        .await
        .expect("both bounded pipes must drain concurrently");
        assert!(output.status.success());
        assert_eq!(output.stdout, vec![0; 4096]);
        assert_eq!(output.stderr, vec![0; 4096]);

        for (script, stream) in [
            ("head -c 4097 /dev/zero", "stdout"),
            ("head -c 4097 /dev/zero >&2", "stderr"),
        ] {
            let mut command = Command::new("sh");
            command.args(["-c", script]);
            let error = run_bounded_git(
                &mut command,
                staging.path(),
                limits(),
                Instant::now() + Duration::from_secs(2),
            )
            .await
            .expect_err("one additional byte must exceed the stream budget");
            assert!(
                format!("{error:#}")
                    .contains(&format!("{stream} exceeded its captured-output limit")),
                "{error:#}"
            );
        }
    }

    #[tokio::test]
    async fn staging_entry_budget_accepts_boundary_and_refuses_next_entry() {
        let staging = tempfile::tempdir().expect("Git staging");
        let limits = GitLimits {
            staging_entries: 3,
            ..limits()
        };
        let mut command = Command::new("sh");
        command
            .current_dir(staging.path())
            .args(["-c", "touch one two"]);
        let output = run_bounded_git(
            &mut command,
            staging.path(),
            limits,
            Instant::now() + Duration::from_secs(2),
        )
        .await
        .expect("staging root plus two entries fits");
        assert!(output.status.success());
        let mut command = Command::new("sh");
        command
            .current_dir(staging.path())
            .args(["-c", "touch three"]);
        let error = run_bounded_git(
            &mut command,
            staging.path(),
            limits,
            Instant::now() + Duration::from_secs(2),
        )
        .await
        .expect_err("the next staged entry must fail");
        assert!(
            format!("{error:#}").contains("staged-entry limit"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn expired_shared_deadline_refuses_to_start_another_command() {
        let staging = tempfile::tempdir().expect("Git staging");
        let mut command = Command::new("sh");
        command
            .current_dir(staging.path())
            .args(["-c", "touch started"]);
        let error = run_bounded_git(&mut command, staging.path(), limits(), Instant::now())
            .await
            .expect_err("an exhausted operation budget must not reset");
        assert!(error.to_string().contains("duration limit"), "{error:#}");
        assert!(!staging.path().join("started").exists());
    }

    #[tokio::test]
    async fn nonzero_status_preserves_bounded_diagnostics() {
        let staging = tempfile::tempdir().expect("Git staging");
        let mut command = Command::new("sh");
        command.args(["-c", "printf normal; printf missing >&2; exit 7"]);
        let output = run_bounded_git(
            &mut command,
            staging.path(),
            limits(),
            Instant::now() + Duration::from_secs(2),
        )
        .await
        .expect("exit status belongs to the caller's policy");
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout, b"normal");
        assert_eq!(output.stderr, b"missing");
    }
}
