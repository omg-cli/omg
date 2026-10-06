#![cfg(unix)]

//! Compiled init reporting with disposable executable and IPC fixtures.

use anyhow::Result;
use omg_lib::daemon::protocol::{Request, Response, ResponseResult, encode_frame, split_frame};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

struct Fixture {
    directory: tempfile::TempDir,
}

impl Fixture {
    fn new(script: &str) -> Result<Self> {
        anyhow::ensure!(
            !omg_lib::core::is_root(),
            "init fixture requires an unprivileged runner to honor isolated state paths"
        );
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        std::fs::copy(env!("CARGO_BIN_EXE_omg"), directory.path().join("omg"))?;
        let daemon = directory.path().join("omgd");
        std::fs::write(&daemon, script)?;
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700))?;
        Ok(Self { directory })
    }

    fn run(&self) -> Result<Output> {
        let path = self.directory.path();
        let mut child = Command::new(path.join("omg"))
            .args(["init", "--defaults", "--skip-shell"])
            .env_clear()
            // Keep instrumented child profiles outside the disposable state
            // directory so llvm-cov can include the actual CLI execution.
            .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|path| ("LLVM_PROFILE_FILE", path)))
            .env("PATH", "/usr/bin:/bin")
            .current_dir(path)
            .env("HOME", path)
            .env("XDG_CONFIG_HOME", path.join("config"))
            .env("XDG_DATA_HOME", path.join("data"))
            .env("XDG_CACHE_HOME", path.join("cache"))
            .env("OMG_SOCKET_PATH", path.join("omg.sock"))
            .env("OMG_CONFIG_DIR", path.join("config/omg"))
            .env("OMG_DATA_DIR", path.join("data/omg"))
            .env("OMG_CACHE_DIR", path.join("cache/omg"))
            .env("OMG_NO_TELEMETRY", "1")
            .env_remove("OMG_TEST_MODE")
            .env_remove("OMG_DISABLE_DAEMON")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let deadline = Instant::now() + Duration::from_secs(15);
        while child.try_wait()?.is_none() {
            if Instant::now() >= deadline {
                child.kill()?;
                child.wait()?;
                anyhow::bail!("init fixture exceeded 15 seconds");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(child.wait_with_output()?)
    }
}

#[test]
fn init_reports_child_failure_and_continues_setup() -> Result<()> {
    let fixture = Fixture::new("#!/bin/sh\nprintf executed > child-marker\nexit 37\n")?;
    let marker = fixture.directory.path().join("child-marker");
    let control = Command::new(fixture.directory.path().join("omgd"))
        .current_dir(fixture.directory.path())
        .env_clear()
        .status()?;
    assert_eq!(control.code(), Some(37));
    std::fs::remove_file(&marker)?;
    let output = fixture.run()?;
    let stdout = String::from_utf8(output.stdout)?;
    assert!(output.status.success(), "{stdout}");
    assert_eq!(std::fs::read_to_string(marker)?, "executed");
    assert!(stdout.contains("not started:"), "{stdout}");
    assert!(stdout.contains("37"), "{stdout}");
    assert!(stdout.contains("continuing setup"), "{stdout}");
    assert!(stdout.contains("Setup complete!"), "{stdout}");
    assert!(!stdout.contains("(started)"), "{stdout}");
    Ok(())
}

#[test]
fn init_reports_synchronous_spawn_failure_and_continues() -> Result<()> {
    // ENOEXEC may fall back to a shell on macOS. A non-executable sibling
    // fails at spawn on every unprivileged Unix runner.
    let fixture = Fixture::new("#!/bin/sh\nexit 0\n")?;
    let daemon = fixture.directory.path().join("omgd");
    std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o600))?;
    assert_eq!(
        Command::new(&daemon)
            .spawn()
            .expect_err("fixture must refuse execution")
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    let output = fixture.run()?;
    let stdout = String::from_utf8(output.stdout)?;
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("not started: Failed to start"), "{stdout}");
    assert!(stdout.contains("Setup complete!"), "{stdout}");
    assert!(!stdout.contains("(started)"), "{stdout}");
    Ok(())
}

struct Server {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<Result<usize>>>,
}

impl Server {
    fn start(fixture: &Fixture, delay: Duration, respond: bool) -> Result<Self> {
        let socket = fixture.directory.path().join("omg.sock");
        // Bind immediately for the existing-daemon and stalled-ping controls.
        let listener = if delay.is_zero() {
            Some(UnixListener::bind(&socket)?)
        } else {
            None
        };
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let thread = std::thread::spawn(move || -> Result<usize> {
            std::thread::sleep(delay);
            let listener = match listener {
                Some(listener) => listener,
                None => UnixListener::bind(socket)?,
            };
            listener.set_nonblocking(true)?;
            let mut pings = 0;
            while !stopped.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                if !respond {
                    while !stopped.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    break;
                }
                stream.set_read_timeout(Some(Duration::from_secs(1)))?;
                let mut length = [0; 4];
                stream.read_exact(&mut length)?;
                let mut frame = vec![0; u32::from_be_bytes(length) as usize];
                stream.read_exact(&mut frame)?;
                let request: Request = bitcode::deserialize(split_frame(&frame)?.1)?;
                let Request::Ping { id } = request else {
                    anyhow::bail!("expected readiness ping")
                };
                let response = encode_frame(&Response::Success {
                    id,
                    result: ResponseResult::Ping("ready".into()),
                })?;
                // A healthy daemon need not answer within one polling interval.
                std::thread::sleep(Duration::from_millis(250));
                stream.write_all(&u32::try_from(response.len())?.to_be_bytes())?;
                stream.write_all(&response)?;
                pings += 1;
            }
            Ok(pings)
        });
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }

    fn finish(mut self) -> Result<usize> {
        self.stop.store(true, Ordering::SeqCst);
        self.thread
            .take()
            .expect("server thread")
            .join()
            .expect("server panic")
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take()
            && let Err(error) = thread.join().expect("server panic")
        {
            eprintln!("fixture server cleanup: {error}");
        }
    }
}

#[test]
fn init_accepts_healthy_existing_daemon_despite_redundant_child_exit() -> Result<()> {
    let fixture = Fixture::new("#!/bin/sh\nexit 37\n")?;
    let server = Server::start(&fixture, Duration::ZERO, true)?;
    let output = fixture.run()?;
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("(started)"), "{stdout}");
    assert!(
        server.finish()? > 0,
        "init did not complete a readiness ping"
    );
    assert!(output.status.success(), "{stdout}");
    assert!(!stdout.contains("not started:"), "{stdout}");
    Ok(())
}

#[test]
fn init_waits_for_readiness_after_spawn() -> Result<()> {
    let fixture = Fixture::new("#!/bin/sh\nexec sleep 5\n")?;
    let server = Server::start(&fixture, Duration::from_millis(300), true)?;
    let output = fixture.run()?;
    assert!(
        server.finish()? > 0,
        "init did not complete a readiness ping"
    );
    let stdout = String::from_utf8(output.stdout)?;
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("(started)"), "{stdout}");
    assert!(!stdout.contains("not started:"), "{stdout}");
    Ok(())
}

#[test]
fn init_bounds_stalled_ping_and_continues_setup() -> Result<()> {
    let fixture = Fixture::new("#!/bin/sh\nexec sleep 5\n")?;
    let server = Server::start(&fixture, Duration::ZERO, false)?;
    let started = Instant::now();
    let output = fixture.run()?;
    let elapsed = started.elapsed();
    server.finish()?;
    let stdout = String::from_utf8(output.stdout)?;
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("not started:"), "{stdout}");
    assert!(stdout.contains("readiness"), "{stdout}");
    assert!(stdout.contains("Setup complete!"), "{stdout}");
    assert!(!stdout.contains("(started)"), "{stdout}");
    assert!(elapsed < Duration::from_secs(10), "init took {elapsed:?}");
    Ok(())
}
