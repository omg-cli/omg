#![cfg(unix)]

use anyhow::Result;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::Command;

#[test]
fn occupied_socket_claim_is_rejected_before_opening_daemon_state() -> Result<()> {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let socket = directory.path().join("omg.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket)?;
    let inode = fs::symlink_metadata(&socket)?.ino();
    let lock = directory.path().join("omg.sock.lock");
    fs::write(&lock, "existing owner\n")?;
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600))?;
    let held = fs::OpenOptions::new().read(true).write(true).open(&lock)?;
    rustix::fs::flock(&held, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
    let data = directory.path().join("invalid-data");
    fs::write(&data, "preserved state blocker\n")?;

    let output = Command::new(env!("CARGO_BIN_EXE_omgd"))
        .arg("--socket")
        .arg(&socket)
        .env("OMG_TEST_MODE", "1")
        .env("OMG_DAEMON_DATA_DIR", &data)
        .env("OMG_DATA_DIR", &data)
        .env("HOME", directory.path())
        .env("NO_COLOR", "1")
        .env_remove("OMG_SENTRY_DSN")
        .output()?;
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success(), "duplicate daemon started");
    assert!(
        diagnostic.contains("Another omgd daemon owns"),
        "duplicate must refuse its occupied claim before reading state: {diagnostic}"
    );
    assert!(
        !diagnostic.contains("Initializing daemon state"),
        "duplicate initialized state before claiming the socket: {diagnostic}"
    );
    assert_eq!(fs::read_to_string(&data)?, "preserved state blocker\n");
    assert_eq!(fs::read_to_string(&lock)?, "existing owner\n");
    assert_eq!(fs::symlink_metadata(&socket)?.ino(), inode);
    drop(listener);
    Ok(())
}
