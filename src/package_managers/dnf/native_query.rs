use std::os::fd::AsFd as _;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, ensure};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::{Errno, read};

const MAX_DIAGNOSTIC_BYTES: usize = 64 * 1024;
pub(super) const SETTINGS_TIMEOUT: Duration = Duration::from_secs(3);
pub(super) const INVENTORY_TIMEOUT: Duration = Duration::from_secs(15);

pub(super) fn capture(command: Command, deadline: Instant) -> Result<Output> {
    capture_limited(
        command,
        deadline,
        usize::try_from(super::MAX_QUERY_BYTES)?,
        MAX_DIAGNOSTIC_BYTES,
    )
}

fn capture_limited(
    mut command: Command,
    deadline: Instant,
    stdout_limit: usize,
    stderr_limit: usize,
) -> Result<Output> {
    remaining(deadline)?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Could not start native package query")?;
    let result = collect(&mut child, deadline, [stdout_limit, stderr_limit]);
    if result.is_err() {
        if let Err(error) = child.kill() {
            tracing::debug!(%error, "Native package query may have already exited");
        }
        if let Err(error) = child.wait() {
            tracing::debug!(%error, "Could not reap native package query");
        }
    }
    result
}

fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|time| !time.is_zero())
        .context("Native package query timed out")
}

fn collect(child: &mut Child, deadline: Instant, limits: [usize; 2]) -> Result<Output> {
    let stdout = child
        .stdout
        .take()
        .context("Native query stdout was not captured")?;
    let stderr = child
        .stderr
        .take()
        .context("Native query stderr was not captured")?;
    let mut readers = [Some(stdout.as_fd()), Some(stderr.as_fd())];
    let mut bytes = [Vec::new(), Vec::new()];
    let mut descriptors = Vec::with_capacity(readers.len());
    let mut buffer = [0_u8; 16 * 1024];

    while readers.iter().any(Option::is_some) {
        let timeout = Timespec::try_from(remaining(deadline)?)?;
        descriptors.clear();
        descriptors.extend(
            readers
                .iter()
                .flatten()
                .map(|fd| PollFd::from_borrowed_fd(*fd, PollFlags::IN)),
        );
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => anyhow::bail!("Native package query timed out"),
            Ok(_) => {}
            Err(Errno::INTR) => continue,
            Err(error) => return Err(error).context("Could not wait for native query output"),
        }
        for ((index, reader), descriptor) in readers
            .iter_mut()
            .enumerate()
            .filter(|(_, reader)| reader.is_some())
            .zip(&descriptors)
        {
            if descriptor.revents().is_empty() {
                continue;
            }
            match read(descriptor, &mut buffer[..]) {
                Ok(0) => *reader = None,
                Ok(count) => {
                    let limit = limits[index];
                    let stream = ["stdout", "stderr"][index];
                    ensure!(
                        count <= limit.saturating_sub(bytes[index].len()),
                        "Native query {stream} exceeds {limit} bytes"
                    );
                    bytes[index].extend_from_slice(&buffer[..count]);
                }
                Err(Errno::INTR) => {}
                Err(error) => return Err(error).context("Could not read native query output"),
            }
        }
    }

    // The child can close both streams before exiting.
    let status = loop {
        let time = remaining(deadline)?;
        if let Some(status) = child
            .try_wait()
            .context("Could not reap native package query")?
        {
            break status;
        }
        std::thread::sleep(time.min(Duration::from_millis(2)));
    };
    let [stdout, stderr] = bytes;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn shell(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", script]);
        command
    }

    #[test]
    fn captures_both_streams_and_preserves_exit_status() -> Result<()> {
        let output = capture_limited(
            shell("printf stdout; printf stderr >&2; exit 7"),
            Instant::now() + Duration::from_secs(2),
            6,
            6,
        )?;
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout, b"stdout");
        assert_eq!(output.stderr, b"stderr");
        Ok(())
    }

    #[test]
    fn rejects_output_beyond_either_stream_limit() {
        for (script, stream) in [
            ("printf oversized", "stdout"),
            ("printf oversized >&2", "stderr"),
        ] {
            let error =
                capture_limited(shell(script), Instant::now() + Duration::from_secs(2), 6, 6)
                    .expect_err("oversized native report must fail");
            assert!(error.to_string().contains(stream), "{error:#}");
        }
    }

    #[test]
    fn deadline_covers_both_pipe_read_and_wait_after_eof() {
        for script in ["exec sleep 0.4", "exec 1>&- 2>&-; exec sleep 0.4"] {
            let start = Instant::now();
            let error = capture_limited(shell(script), start + Duration::from_millis(40), 6, 6)
                .expect_err("native report past its deadline must fail");
            assert!(error.to_string().contains("timed out"), "{error:#}");
        }
    }
}
