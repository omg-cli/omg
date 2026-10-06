//! Test infrastructure and utilities for TDD
//!
//! This module provides fixture builders and a package-manager test double.

pub mod fixtures;
pub mod mocks;

pub use fixtures::{PackageFixture, UpdateFixture};
pub use mocks::TestPackageManager;

/// Runs process-wide fixture mutations outside the parallel parent harness.
#[cfg(test)]
pub(crate) fn run_isolated_test(name: &str) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const CHILD: &str = "OMG_ISOLATED_FIXTURE_TEST";
    const LIMIT: u64 = 128 * 1024;
    if std::env::var(CHILD).as_deref() == Ok(name) {
        return false;
    }
    // TMPDIR itself can be under mutation in the parent harness.
    #[cfg(unix)]
    let mut output = tempfile::tempfile_in("/var/tmp").expect("isolated test capture");
    #[cfg(not(unix))]
    let mut output = tempfile::tempfile().expect("isolated test capture");
    let mut child = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            name,
            "--nocapture",
            "--color",
            "never",
            "--test-threads=1",
        ])
        .env(CHILD, name)
        .stdout(Stdio::from(output.try_clone().expect("capture stdout")))
        .stderr(Stdio::from(output.try_clone().expect("capture stderr")))
        .spawn()
        .expect("spawn isolated fixture test");
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                if let Err(kill_error) = child.kill() {
                    eprintln!("isolated test {name} stop failed: {kill_error}");
                }
                child.wait().expect("reap isolated test after wait error");
                panic!("isolated test {name} wait failed: {error}");
            }
        }
        let within_capture_limit = output.metadata().is_ok_and(|meta| meta.len() <= LIMIT);
        if started.elapsed() >= Duration::from_secs(20) || !within_capture_limit {
            child.kill().expect("stop bounded isolated fixture test");
            child.wait().expect("reap bounded isolated fixture test");
            panic!("isolated test {name} exceeded its time or capture bound");
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    output.seek(SeekFrom::Start(0)).expect("rewind capture");
    let mut captured = String::new();
    output
        .take(LIMIT + 1)
        .read_to_string(&mut captured)
        .expect("read capture");
    assert!(
        captured.len() as u64 <= LIMIT,
        "isolated test capture overflow"
    );
    assert!(
        status.success() && captured.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
        "isolated test {name} failed ({status}):\n{captured}"
    );
    true
}
