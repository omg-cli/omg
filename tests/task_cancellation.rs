//! Real CLI cancellation regressions. Each fixture owns a separate process group.
#![cfg(target_os = "linux")]

use nix::sys::signal::{Signal, kill, killpg};
use nix::unistd::{Pid, getpgid};
use std::fs;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct TaskFixture {
    child: Child,
    directory: tempfile::TempDir,
    task_pids: Vec<Pid>,
}

impl TaskFixture {
    fn spawn(script: &str, watch: bool) -> Self {
        let mut args = vec!["run"];
        if watch {
            args.push("--watch");
        }
        args.extend(["sh", "--", "-c", script]);
        Self::spawn_args(&args, None)
    }

    fn spawn_args(args: &[&str], configuration: Option<&str>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        if let Some(configuration) = configuration {
            fs::write(directory.path().join("mise.toml"), configuration).unwrap();
        }
        let mut command = Command::new(env!("CARGO_BIN_EXE_omg"));
        command.args(args);
        command
            .env_clear()
            .env("HOME", directory.path())
            .env("PATH", "/usr/bin:/bin")
            .env("OMG_DISABLE_TELEMETRY", "1")
            .current_dir(directory.path())
            .stdin(Stdio::null())
            .stdout(fs::File::create(directory.path().join("stdout")).unwrap())
            .stderr(fs::File::create(directory.path().join("stderr")).unwrap())
            .process_group(0);
        let child = command.spawn().unwrap();
        let pid = Pid::from_raw(i32::try_from(child.id()).unwrap());
        assert_eq!(getpgid(Some(pid)).unwrap(), pid);
        Self {
            child,
            directory,
            task_pids: Vec::new(),
        }
    }

    fn ready(&mut self) -> Pid {
        self.ready_at("pids")
    }

    fn ready_at(&mut self, name: &str) -> Pid {
        let path = self.directory.path().join(name);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(text) = fs::read_to_string(&path) {
                let pids: Vec<i32> = text
                    .split_whitespace()
                    .filter_map(|s| s.parse().ok())
                    .collect();
                if let [task, descendant] = pids.as_slice() {
                    self.task_pids.push(Pid::from_raw(*task));
                    let pid = Pid::from_raw(*descendant);
                    assert!(
                        is_live(pid),
                        "fixture descendant must be alive before cancellation"
                    );
                    return pid;
                }
            }
            assert!(
                Instant::now() < deadline,
                "fixture failed to start: {}",
                self.output()
            );
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "CLI exited before readiness: {}",
                self.output()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn output(&self) -> String {
        format!(
            "stdout={} stderr={}",
            fs::read_to_string(self.directory.path().join("stdout")).unwrap(),
            fs::read_to_string(self.directory.path().join("stderr")).unwrap()
        )
    }

    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "CLI did not exit after cancellation: {}",
                self.output()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for TaskFixture {
    fn drop(&mut self) {
        // Only the fixture's initial group and the task leader's own group are
        // eligible. Never signal the test harness's foreground group.
        let runner = Pid::from_raw(i32::try_from(self.child.id()).unwrap());
        for &task in &self.task_pids {
            if getpgid(Some(task)).ok() == Some(task) {
                let _ = killpg(task, Signal::SIGKILL);
            }
        }
        let _ = killpg(runner, Signal::SIGKILL);
        let _ = self.child.wait();
    }
}

fn is_live(pid: Pid) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(") ")
            .is_some_and(|(_, fields)| !fields.starts_with('Z'))
    })
}

const BACKGROUND: &str = "sleep 40 & printf '%s %s\\n' $$ $! > pids; wait";

fn assert_cancellation(watch: bool, group: bool, script: &str) {
    assert_signal_cancellation(watch, group, script, Signal::SIGINT);
}

fn assert_signal_cancellation(watch: bool, group: bool, script: &str, signal: Signal) {
    let mut fixture = TaskFixture::spawn(script, watch);
    let descendant = fixture.ready();
    let runner = Pid::from_raw(i32::try_from(fixture.child.id()).unwrap());
    if group {
        killpg(runner, signal).unwrap();
    } else {
        kill(runner, signal).unwrap();
    }
    assert!(
        !fixture.wait().success(),
        "cancellation must report failure"
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    while is_live(descendant) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !is_live(descendant),
        "background descendant {descendant} survived cancellation: {}",
        fixture.output()
    );
}

#[test]
fn parent_sigint_stops_background_descendant() {
    assert_cancellation(false, false, BACKGROUND);
}

#[test]
fn parent_sigterm_stops_background_descendant() {
    assert_signal_cancellation(false, false, BACKGROUND, Signal::SIGTERM);
}

#[test]
fn parent_sighup_stops_background_descendant() {
    assert_signal_cancellation(false, false, BACKGROUND, Signal::SIGHUP);
}

#[test]
fn task_group_sigint_stops_ignored_descendant_after_leader_exits() {
    let mut fixture = TaskFixture::spawn(BACKGROUND, false);
    let descendant = fixture.ready();
    let task = fixture.task_pids[0];
    assert_eq!(getpgid(Some(task)).unwrap(), task);
    killpg(task, Signal::SIGINT).unwrap();
    assert!(!fixture.wait().success());
    assert!(
        !is_live(descendant),
        "group cancellation left a live descendant"
    );
}

#[test]
fn parallel_cancellation_stops_both_owned_task_groups() {
    let mut fixture = TaskFixture::spawn_args(
        &["run", "first,second", "--parallel"],
        Some(
            "[tasks]\nfirst = \"sleep 40 & echo $$ $! > first.pids; wait\"\nsecond = \"sleep 40 & echo $$ $! > second.pids; wait\"\n",
        ),
    );
    let first = fixture.ready_at("first.pids");
    let second = fixture.ready_at("second.pids");
    let runner = Pid::from_raw(i32::try_from(fixture.child.id()).unwrap());
    kill(runner, Signal::SIGINT).unwrap();
    assert!(!fixture.wait().success());
    assert!(
        !is_live(first),
        "first parallel task left a live descendant"
    );
    assert!(
        !is_live(second),
        "second parallel task left a live descendant"
    );
}

#[test]
fn cancellation_escalates_when_task_ignores_int_and_term() {
    assert_cancellation(
        false,
        false,
        "trap '' INT TERM; sleep 40 & printf '%s %s\\n' $$ $! > pids; wait",
    );
}

#[test]
fn parent_sigint_preserves_unrelated_foreground_group_peer() {
    let mut fixture = TaskFixture::spawn(BACKGROUND, false);
    fixture.ready();
    let runner = Pid::from_raw(i32::try_from(fixture.child.id()).unwrap());
    let mut peer = Command::new("sleep")
        .arg("40")
        .process_group(runner.as_raw())
        .spawn()
        .unwrap();
    kill(runner, Signal::SIGINT).unwrap();
    fixture.wait();
    let peer_survived = peer.try_wait().unwrap().is_none();
    peer.kill().unwrap();
    peer.wait().unwrap();
    assert!(
        peer_survived,
        "cancellation signalled an unrelated peer in the caller group"
    );
}

#[test]
fn idle_watch_stops_on_parent_sigint() {
    let mut fixture = TaskFixture::spawn("printf '%s %s\\n' $$ $$ > pids; exit 0", true);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !fixture.output().contains("Watching for changes") {
        assert!(
            Instant::now() < deadline,
            "watch did not become idle: {}",
            fixture.output()
        );
        thread::sleep(Duration::from_millis(20));
    }
    let runner = Pid::from_raw(i32::try_from(fixture.child.id()).unwrap());
    kill(runner, Signal::SIGINT).unwrap();
    assert!(
        !fixture.wait().success(),
        "watch cancellation must report failure"
    );
}

#[test]
fn foreground_group_sigint_stops_background_descendant() {
    assert_cancellation(false, true, BACKGROUND);
}

#[test]
fn watch_sigint_stops_background_descendant() {
    assert_cancellation(true, false, BACKGROUND);
}

#[test]
fn foreground_responsive_task_still_stops() {
    assert_cancellation(false, true, "printf '%s %s\\n' $$ $$ > pids; exec sleep 40");
}

#[test]
fn successful_task_preserves_literal_arguments() {
    let mut fixture = TaskFixture::spawn("printf '%s' 'literal;$HOME'; exit 0", false);
    assert!(fixture.wait().success(), "{}", fixture.output());
    assert!(fixture.output().contains("literal;$HOME"));
}

#[test]
fn nonzero_task_retains_exit_code_report() {
    let mut fixture = TaskFixture::spawn("exit 23", false);
    assert!(!fixture.wait().success());
    assert!(
        fixture
            .output()
            .contains("Task failed with exit code: Some(23)"),
        "{}",
        fixture.output()
    );
}

#[test]
fn unrelated_child_signal_retains_failure_report() {
    let mut fixture = TaskFixture::spawn("kill -USR1 $$", false);
    assert!(!fixture.wait().success());
    assert!(
        fixture
            .output()
            .contains("Task failed with exit code: None"),
        "{}",
        fixture.output()
    );
}

#[test]
fn controlling_terminal_input_and_interrupt_work() {
    let output = Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/task_terminal.py"
        ))
        .arg(env!("CARGO_BIN_EXE_omg"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "PTY checks failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
