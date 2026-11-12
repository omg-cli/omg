//! Bounded Git subprocess capture and process-group cleanup.

use std::path::Path;
use std::process::{Output, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
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

async fn monitor_git_staging(path: &Path, limits: GitLimits) -> Result<()> {
    loop {
        inspect_git_staging(path, limits).await?;
        tokio::time::sleep(limits.poll_interval).await;
    }
}

fn terminate_git_group(process_group: u32) -> Result<()> {
    use nix::errno::Errno;
    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::Pid;

    let process_group = i32::try_from(process_group).context("Git process ID exceeded i32")?;
    match killpg(Pid::from_raw(process_group), Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(error).context("Failed to terminate AUR Git process group"),
    }
}

struct GitGroupGuard(Option<u32>);

impl GitGroupGuard {
    fn terminate(&mut self) -> Result<()> {
        if let Some(process_group) = self.0 {
            terminate_git_group(process_group)?;
            self.disarm();
        }
        Ok(())
    }

    const fn disarm(&mut self) {
        self.0 = None;
    }
}

async fn observe_git_exit(process_id: u32) -> Result<()> {
    use nix::errno::Errno;
    use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};
    use nix::unistd::Pid;

    let process_id =
        Pid::from_raw(i32::try_from(process_id).context("Git process ID exceeded i32")?);
    let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child())
        .context("Failed to observe AUR Git child exit")?;
    loop {
        // WNOWAIT keeps the leader's identity reserved until group termination.
        match waitid(
            Id::Pid(process_id),
            WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT | WaitPidFlag::WNOHANG,
        ) {
            Ok(WaitStatus::StillAlive) => {
                signal
                    .recv()
                    .await
                    .context("AUR Git child-exit signal closed")?;
            }
            Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) => return Ok(()),
            Ok(status) => anyhow::bail!("Unexpected AUR Git child status: {status:?}"),
            Err(Errno::EINTR) => tokio::task::yield_now().await,
            Err(error) => {
                return Err(error).context("Failed to observe AUR Git child without reaping");
            }
        }
    }
}

impl Drop for GitGroupGuard {
    fn drop(&mut self) {
        if let Some(process_group) = self.0
            && let Err(error) = terminate_git_group(process_group)
        {
            tracing::warn!(%error, "Failed to terminate cancelled AUR Git process group");
        }
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
    let mut group_guard = GitGroupGuard(Some(process_group));
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
            monitored = monitor_git_staging(staging_path, limits) => {
                monitored?;
                anyhow::bail!("AUR Git staging monitor stopped unexpectedly")
            },
        }
    })
    .await
    .unwrap_or_else(|_| {
        Err(anyhow::anyhow!(
            "AUR Git operation exceeded its duration limit"
        ))
    });

    let terminated = group_guard.terminate();
    if terminated.is_err()
        && let Err(error) = child.start_kill()
    {
        tracing::warn!(%error, "Failed to terminate direct AUR Git child during cleanup");
    }
    group_guard.disarm();
    let reaped = match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
        Ok(status) => status.context("Failed to reap AUR Git command during cleanup"),
        Err(error) => Err(anyhow::Error::new(error)
            .context("AUR Git cleanup exceeded its five-second reap grace")),
    };
    let cleanup = terminated.and(reaped);
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut guard = GitGroupGuard(Some(process_id));
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
            guard.0.is_none(),
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
