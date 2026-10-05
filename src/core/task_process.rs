//! Unix task ownership. A retained group leader prevents PGID reuse while
//! cancellation escalates; only the direct child is reaped by this runner.

use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::sys::signal::{SigSet, SigmaskHow, Signal, killpg, pthread_sigmask};
use nix::unistd::{Pid, getpgrp, tcgetpgrp, tcsetpgrp};
use rustix::process::{WaitId, WaitIdOptions, WaitIdStatus, waitid};
use std::fs::{File, OpenOptions};
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::thread;
use std::time::Duration;

static SIGNALS: Mutex<Option<SignalState>> = Mutex::new(None);
static TERMINAL: Mutex<()> = Mutex::new(());
const POLL: Duration = Duration::from_millis(20);

struct SignalState {
    received: Arc<AtomicUsize>,
    idle: Arc<AtomicBool>,
    users: usize,
}

impl SignalState {
    fn new() -> Result<Self> {
        let state = Self {
            received: Arc::new(AtomicUsize::new(0)),
            idle: Arc::new(AtomicBool::new(true)),
            users: 0,
        };
        for signal in [Signal::SIGINT, Signal::SIGTERM, Signal::SIGHUP] {
            // Registrations live for the process lifetime. Unregistering the
            // last signal-hook action would leave the signal ignored. Instead
            // keep the default termination action enabled outside task scopes.
            signal_hook::flag::register_conditional_default(
                signal as i32,
                Arc::clone(&state.idle),
            )?;
            signal_hook::flag::register_usize(
                signal as i32,
                Arc::clone(&state.received),
                usize::try_from(signal as i32)?,
            )?;
        }
        Ok(state)
    }
}

/// A shared cancellation scope for nested, sequential and parallel tasks.
pub(super) struct Cancellation {
    received: Arc<AtomicUsize>,
}

impl Cancellation {
    pub(super) fn enter() -> Result<Self> {
        let mut slot = SIGNALS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_none() {
            *slot =
                Some(SignalState::new().context("Failed to register task cancellation signals")?);
        }
        let state = slot.as_mut().context("Task signal state is missing")?;
        if state.users == 0 {
            state.received.store(0, Ordering::SeqCst);
            state.idle.store(false, Ordering::SeqCst);
        }
        state.users += 1;
        Ok(Self {
            received: Arc::clone(&state.received),
        })
    }

    pub(super) fn signal(&self) -> Option<Signal> {
        i32::try_from(self.received.load(Ordering::SeqCst))
            .ok()
            .and_then(|value| Signal::try_from(value).ok())
    }

    fn cancel(&self, signal: Signal) {
        self.received.store(signal as usize, Ordering::SeqCst);
    }

    pub(super) fn check(&self) -> Result<()> {
        if let Some(signal) = self.signal() {
            anyhow::bail!("Task cancelled by {signal}");
        }
        Ok(())
    }
}

impl Drop for Cancellation {
    fn drop(&mut self) {
        let mut slot = SIGNALS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(state) = slot.as_mut() {
            state.users -= 1;
            if state.users == 0 {
                state.idle.store(true, Ordering::SeqCst);
            }
        }
    }
}

struct OwnedTask {
    child: Child,
    group: Pid,
    reaped: bool,
}

impl OwnedTask {
    fn observe_exit(&self) -> Result<Option<WaitIdStatus>> {
        let pid =
            rustix::process::Pid::from_raw(self.group.as_raw()).context("Invalid task PID")?;
        match waitid(
            WaitId::Pid(pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        ) {
            Ok(status) => Ok(status),
            Err(rustix::io::Errno::INTR) => Ok(None),
            Err(error) => Err(error).context("Failed to observe task exit"),
        }
    }

    fn signal_group(&self, signal: Signal) -> Result<()> {
        // process_group(0) made this child's PID its PGID. Keep its PID
        // unreaped until the last group signal, so another task cannot reuse it.
        match killpg(self.group, signal) {
            Ok(()) | Err(Errno::ESRCH) => Ok(()),
            Err(error) => Err(error).context("Failed to signal owned task group"),
        }
    }

    fn shutdown(&mut self, signal: Signal) -> Result<()> {
        self.signal_group(signal)?;
        // A job-control-stopped task must be resumed to handle termination.
        self.signal_group(Signal::SIGCONT)?;
        thread::sleep(Duration::from_millis(250));
        self.signal_group(Signal::SIGTERM)?;
        thread::sleep(Duration::from_millis(750));
        self.signal_group(Signal::SIGKILL)?;
        self.reap()?;
        Ok(())
    }

    fn reap(&mut self) -> Result<ExitStatus> {
        let status = self.child.wait().context("Failed to reap task child")?;
        self.reaped = true;
        Ok(status)
    }
}

impl Drop for OwnedTask {
    fn drop(&mut self) {
        if !self.reaped {
            if let Err(error) = self.signal_group(Signal::SIGKILL) {
                eprintln!("Failed to clean up task group: {error:#}");
            }
            if let Err(error) = self.reap() {
                eprintln!("Failed to reap task child during cleanup: {error:#}");
            }
        }
    }
}

struct Foreground {
    terminal: File,
    original: Pid,
    task: Pid,
    _lease: MutexGuard<'static, ()>,
}

fn set_foreground(terminal: &File, group: Pid) -> Result<()> {
    let mut blocked = SigSet::empty();
    blocked.add(Signal::SIGTTOU);
    let mut previous = SigSet::empty();
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&blocked), Some(&mut previous))?;
    let result = tcsetpgrp(terminal, group);
    let restored = pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&previous), None);
    result.context("Failed to set task terminal foreground group")?;
    restored.context("Failed to restore task thread signal mask")
}

impl Foreground {
    fn acquire(task: Pid) -> Result<Option<Self>> {
        let lease = match TERMINAL.try_lock() {
            Ok(lease) => lease,
            Err(TryLockError::Poisoned(error)) => error.into_inner(),
            Err(TryLockError::WouldBlock) => return Ok(None),
        };
        let terminal = match OpenOptions::new().read(true).write(true).open("/dev/tty") {
            Ok(terminal) => terminal,
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(nix::libc::ENXIO | nix::libc::ENODEV | nix::libc::ENOENT)
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error).context("Failed to open task controlling terminal"),
        };
        let original = tcgetpgrp(&terminal)?;
        if original != getpgrp() {
            return Ok(None);
        }
        set_foreground(&terminal, task)?;
        Ok(Some(Self {
            terminal,
            original,
            task,
            _lease: lease,
        }))
    }
}

impl Drop for Foreground {
    fn drop(&mut self) {
        // Do not steal the terminal if another owner has taken foreground.
        if tcgetpgrp(&self.terminal).ok() == Some(self.task)
            && let Err(error) = set_foreground(&self.terminal, self.original)
        {
            eprintln!("Failed to restore task terminal: {error:#}");
        }
    }
}

pub(super) fn run(command: &mut Command, cancellation: &Cancellation) -> Result<ExitStatus> {
    cancellation.check()?;
    command.process_group(0);
    let child = command.spawn()?;
    let group = Pid::from_raw(i32::try_from(child.id())?);
    let mut task = OwnedTask {
        child,
        group,
        reaped: false,
    };
    anyhow::ensure!(
        group.as_raw() > 1 && group != getpgrp(),
        "Task group is not isolated"
    );
    let _foreground = Foreground::acquire(group)?;
    task.signal_group(Signal::SIGCONT)?;
    loop {
        if let Some(signal) = cancellation.signal() {
            task.shutdown(signal)?;
            cancellation.check()?;
        }
        if let Some(status) = task.observe_exit()? {
            // Terminal Ctrl+C can reach only the foreground task group. A
            // signalled leader must still trigger cleanup of ignoring siblings.
            if let Some(signal) = status
                .terminating_signal()
                .and_then(|value| Signal::try_from(value).ok())
                .filter(|signal| {
                    matches!(signal, Signal::SIGINT | Signal::SIGTERM | Signal::SIGHUP)
                })
            {
                cancellation.cancel(signal);
                task.shutdown(signal)?;
                cancellation.check()?;
            }
            cancellation.check()?;
            return task.reap();
        }
        thread::sleep(POLL);
    }
}
