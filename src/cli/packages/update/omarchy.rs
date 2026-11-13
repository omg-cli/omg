//! Omarchy's update lifecycle, with AUR builds owned by OMG.

use std::fs::File;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use tokio::process::Command;

const LOG_PATH: &str = "/tmp/omarchy-update.log";
const LOCK_FD: &str = "OMG_OMARCHY_LOCK_FD";
const LOG_FD: &str = "OMG_OMARCHY_LOG_FD";
const AUTHORIZATION_INTERVAL: Duration = Duration::from_mins(1);
const TERMINATION_GRACE: Duration = Duration::from_secs(10);
const MAX_MIGRATIONS: usize = 4096;
const MAX_MIGRATION_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArchFlavor {
    Arch,
    Omarchy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum UpdateIntent {
    Check,
    DryRun,
    AurOnly,
    Standard { yes: bool, no_sync: bool },
    Fast,
    Turbo,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UpdatePlan {
    Native,
    Omarchy { yes: bool },
}

fn plan(flavor: ArchFlavor, intent: UpdateIntent) -> Result<UpdatePlan> {
    if flavor == ArchFlavor::Arch
        || matches!(
            intent,
            UpdateIntent::Check | UpdateIntent::DryRun | UpdateIntent::AurOnly
        )
    {
        return Ok(UpdatePlan::Native);
    }
    match intent {
        UpdateIntent::Standard {
            yes,
            no_sync: false,
        } => Ok(UpdatePlan::Omarchy { yes }),
        _ => anyhow::bail!(
            "Omarchy requires its complete update lifecycle; --fast, --turbo and mutating --no-sync cannot preserve that scope. Use omg update, or --check/--dry-run/--aur-only for a scoped operation."
        ),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Preflight,
    Confirm,
    Authorize,
    Prune,
    Snapshot,
    InhibitSleep,
    DevelopmentCheckout,
    Keyrings,
    OfficialPackages,
    MigrationPreflight,
    MigrationsPending,
    RestartShell,
    Migrations,
    Orphans,
    AnalyzeLog,
    ClearIndicator,
    RestartServices,
    PostUpdateHooks,
    Mise,
    NativeAur,
    VerifyBoot,
    ReleaseAuthorization,
    ReleaseInhibitor,
    RebootPrompt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    Success,
    Declined,
    Unavailable,
}

trait StageExecutor {
    async fn execute(&mut self, stage: Stage) -> Result<Outcome>;
}

async fn workflow(executor: &mut impl StageExecutor, yes: bool) -> Result<()> {
    executor.execute(Stage::Preflight).await?;
    executor.execute(Stage::MigrationPreflight).await?;
    if !yes && executor.execute(Stage::Confirm).await? == Outcome::Declined {
        return Ok(());
    }
    let mut authorization_attempted = false;
    let mut inhibitor_attempted = false;
    let update = async {
        authorization_attempted = true;
        executor.execute(Stage::Authorize).await?;
        executor.execute(Stage::Prune).await?;
        if let Err(error) = executor.execute(Stage::Snapshot).await {
            crate::cli::modern_ui::print_warning(&format!(
                "Continuing the Omarchy update without a snapshot: {error:#}"
            ));
        }
        inhibitor_attempted = true;
        executor.execute(Stage::InhibitSleep).await?;
        for stage in [
            Stage::DevelopmentCheckout,
            Stage::Keyrings,
            Stage::OfficialPackages,
        ] {
            executor.execute(stage).await?;
        }
        executor.execute(Stage::MigrationPreflight).await?;
        if executor.execute(Stage::MigrationsPending).await? == Outcome::Success
            && let Err(error) = executor.execute(Stage::RestartShell).await
        {
            tracing::warn!("Omarchy shell restart before migration failed: {error:#}");
        }
        for stage in [
            Stage::Migrations,
            Stage::Orphans,
            Stage::AnalyzeLog,
            Stage::ClearIndicator,
            Stage::RestartServices,
            Stage::PostUpdateHooks,
        ] {
            executor.execute(stage).await?;
        }
        let mise_result = executor.execute(Stage::Mise).await;
        if let Err(error) = mise_result {
            crate::cli::modern_ui::print_warning(&format!(
                "Some mise tools could not be updated; retry with omarchy update mise: {error:#}"
            ));
        }
        executor.execute(Stage::NativeAur).await?;
        executor.execute(Stage::VerifyBoot).await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let mut cleanup_error = None;
    for (attempted, stage) in [
        (authorization_attempted, Stage::ReleaseAuthorization),
        (inhibitor_attempted, Stage::ReleaseInhibitor),
    ] {
        if attempted && let Err(error) = executor.execute(stage).await {
            tracing::error!("Omarchy cleanup {stage:?} failed: {error:#}");
            cleanup_error.get_or_insert(error);
        }
    }
    update.context("Omarchy update did not complete; inspect its update log before rebooting")?;
    if let Some(error) = cleanup_error {
        return Err(error).context("Omarchy update cleanup did not complete");
    }
    executor.execute(Stage::RebootPrompt).await?;
    Ok(())
}

fn stage_command(stage: Stage) -> Option<(&'static str, &'static [&'static str])> {
    Some(match stage {
        Stage::Preflight => ("omarchy-update-requires-free-space", &[]),
        Stage::Confirm => ("omarchy-update-confirm", &[]),
        Stage::Authorize => ("sudo", &["true"]),
        Stage::Prune => ("omarchy-update-pkg-prune", &[]),
        Stage::Snapshot => ("omarchy-snapshot", &["create"]),
        Stage::InhibitSleep => ("omarchy-update-stay-awake", &["start"]),
        Stage::DevelopmentCheckout => ("omarchy-update-dev", &[]),
        Stage::Keyrings => ("omarchy-update-keyring", &[]),
        Stage::OfficialPackages => ("omarchy-update-system-pkgs", &[]),
        Stage::MigrationsPending => ("omarchy-migrate", &["--pending"]),
        Stage::RestartShell => ("omarchy-restart-shell", &[]),
        Stage::Migrations => ("omarchy-migrate", &[]),
        Stage::Orphans => ("omarchy-update-orphan-pkgs", &["-y"]),
        Stage::AnalyzeLog => ("omarchy-update-analyze-logs", &[]),
        Stage::ClearIndicator => ("omarchy-shell", &["-q", "omarchy.system-update", "clear"]),
        Stage::RestartServices => ("omarchy-update-restart", &["--services-only"]),
        Stage::PostUpdateHooks => ("omarchy-hook", &["post-update"]),
        Stage::Mise => ("omarchy-update-mise", &[]),
        Stage::VerifyBoot => ("omarchy-update-boot", &[]),
        Stage::ReleaseInhibitor => ("omarchy-update-stay-awake", &["stop"]),
        Stage::RebootPrompt => ("omarchy-update-restart", &["--reboot-only"]),
        Stage::MigrationPreflight | Stage::NativeAur | Stage::ReleaseAuthorization => return None,
    })
}

struct Commands {
    yes: bool,
    authorization: Option<tokio::task::JoinHandle<()>>,
    inhibitor_attempted: bool,
    active: Option<tokio::process::Child>,
    foreground: Option<nix::unistd::Pid>,
}

fn foreground_group() -> Result<Option<nix::unistd::Pid>> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return Ok(None);
    }
    nix::unistd::tcgetpgrp(std::io::stdin())
        .map(Some)
        .context("Cannot read the update terminal foreground group")
}

fn set_foreground(group: nix::unistd::Pid) -> Result<()> {
    use nix::sys::signal::{SigSet, SigmaskHow, Signal, pthread_sigmask};
    let mut blocked = SigSet::empty();
    blocked.add(Signal::SIGTTOU);
    let mut previous = SigSet::empty();
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&blocked), Some(&mut previous))?;
    let result = nix::unistd::tcsetpgrp(std::io::stdin(), group);
    let restored = previous.thread_set_mask();
    result.context("Cannot assign the update terminal foreground group")?;
    restored.context("Cannot restore the update terminal signal mask")?;
    Ok(())
}

impl Commands {
    const fn new(yes: bool) -> Self {
        Self {
            yes,
            authorization: None,
            inhibitor_attempted: false,
            active: None,
            foreground: None,
        }
    }

    async fn run_program(&mut self, program: &Path, args: &[&str]) -> Result<ExitStatus> {
        anyhow::ensure!(self.active.is_none(), "An Omarchy stage is already running");
        let mut command = Command::new(program);
        command.args(args).kill_on_drop(true).process_group(0).env(
            "OMARCHY_PATH",
            std::env::var_os("OMARCHY_PATH").unwrap_or_else(|| "/usr/share/omarchy".into()),
        );
        if self.yes {
            command.env("OMARCHY_UPDATE_UNATTENDED", "1");
        }
        self.start(&mut command)
            .await
            .with_context(|| format!("Failed to start Omarchy stage {}", program.display()))?;
        let result = self
            .active
            .as_mut()
            .context("Missing owned stage child")?
            .wait()
            .await;
        match result {
            Ok(status) => {
                self.active = None;
                self.restore_foreground()?;
                Ok(status)
            }
            Err(error) => {
                self.stop_active().await?;
                Err(error).with_context(|| format!("Failed to wait for {}", program.display()))
            }
        }
    }

    async fn start(&mut self, command: &mut Command) -> Result<()> {
        self.foreground = foreground_group()?;
        self.active = Some(command.spawn()?);
        if self.foreground.is_some() {
            let pid = self
                .active
                .as_ref()
                .and_then(tokio::process::Child::id)
                .context("Missing owned terminal child")?;
            let group = nix::unistd::Pid::from_raw(
                i32::try_from(pid).context("Invalid owned terminal group")?,
            );
            let assigned = set_foreground(group).and_then(|()| {
                nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGCONT)
                    .context("Cannot resume the owned foreground stage")
            });
            if let Err(error) = assigned {
                self.stop_active().await?;
                return Err(error);
            }
        }
        Ok(())
    }

    fn restore_foreground(&mut self) -> Result<()> {
        if let Some(group) = self.foreground.take() {
            match set_foreground(group) {
                Err(error)
                    if matches!(
                        error.downcast_ref::<nix::errno::Errno>(),
                        Some(nix::errno::Errno::ENOTTY | nix::errno::Errno::EIO)
                    ) =>
                {
                    tracing::debug!("Update terminal detached before foreground restoration");
                }
                result => result?,
            }
        }
        Ok(())
    }

    async fn stop_active(&mut self) -> Result<()> {
        let Some(mut child) = self.active.take() else {
            return self.restore_foreground();
        };
        let result: Result<()> = async {
            if let Some(pid) = child.id() {
                let pid = i32::try_from(pid).context("Invalid owned Omarchy process group")?;
                let result = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGTERM,
                );
                if let Err(error) = result
                    && error != nix::errno::Errno::ESRCH
                {
                    tracing::warn!("Unable to stop owned Omarchy stage group: {error}");
                }
                if let Ok(result) = tokio::time::timeout(TERMINATION_GRACE, child.wait()).await {
                    result.context("Failed to reap interrupted Omarchy stage")?;
                }
                let result = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGKILL,
                );
                if let Err(error) = result
                    && error != nix::errno::Errno::ESRCH
                {
                    tracing::warn!("Unable to kill owned Omarchy stage group: {error}");
                }
            }
            child
                .wait()
                .await
                .context("Failed to reap owned Omarchy stage")?;
            Ok(())
        }
        .await;
        let restored = self.restore_foreground();
        result?;
        restored
    }

    async fn release_authorization(&mut self) {
        if let Some(task) = self.authorization.take() {
            task.abort();
            if let Err(error) = task.await
                && !error.is_cancelled()
            {
                tracing::warn!("Omarchy authorization worker failed: {error}");
            }
        }
    }

    async fn cleanup(&mut self) -> Result<()> {
        let active = self.stop_active().await;
        self.release_authorization().await;
        let inhibition = if self.inhibitor_attempted {
            self.execute(Stage::ReleaseInhibitor).await.map(|_| ())
        } else {
            Ok(())
        };
        active?;
        inhibition
    }
}

impl StageExecutor for Commands {
    async fn execute(&mut self, stage: Stage) -> Result<Outcome> {
        match stage {
            Stage::NativeAur => {
                super::arch::update_omarchy_aur(self.yes).await?;
                return Ok(Outcome::Success);
            }
            Stage::MigrationPreflight => {
                check_pending_migrations()?;
                return Ok(Outcome::Success);
            }
            Stage::ReleaseAuthorization => {
                self.release_authorization().await;
                return Ok(Outcome::Success);
            }
            _ => {}
        }
        let (program, args) = stage_command(stage).context("Missing Omarchy stage command")?;
        let executable = match crate::core::privilege::root_controlled_program_path(program) {
            Ok(path) => path,
            Err(error) if stage == Stage::Snapshot => {
                tracing::warn!("Omarchy snapshot helper is unavailable: {error:#}");
                return Ok(Outcome::Unavailable);
            }
            Err(error) => return Err(error),
        };
        if stage == Stage::InhibitSleep {
            self.inhibitor_attempted = true;
        }
        let status = self.run_program(&executable, args).await?;
        if stage == Stage::ReleaseInhibitor && status.success() {
            self.inhibitor_attempted = false;
        }
        if status.success() {
            if stage == Stage::Authorize {
                self.authorization = Some(tokio::spawn(async {
                    loop {
                        tokio::time::sleep(AUTHORIZATION_INTERVAL).await;
                        let result = async {
                            let mut command = crate::core::privilege::sudo_command()?;
                            command.args(["-n", "true"]).kill_on_drop(true);
                            command.stdout(Stdio::null()).stderr(Stdio::null());
                            Ok::<_, anyhow::Error>(command.status().await?.success())
                        }
                        .await;
                        if !matches!(result, Ok(true)) {
                            tracing::warn!("Omarchy update authorization refresh stopped");
                            break;
                        }
                    }
                }));
            }
            return Ok(Outcome::Success);
        }
        if matches!(stage, Stage::Confirm | Stage::MigrationsPending) && status.code() == Some(1) {
            return Ok(Outcome::Declined);
        }
        if stage == Stage::Snapshot && status.code() == Some(127) {
            return Ok(Outcome::Unavailable);
        }
        anyhow::bail!("Omarchy stage {program} did not complete: {status}")
    }
}

fn check_pending_migrations() -> Result<()> {
    let root = std::env::var_os("OMARCHY_PATH")
        .map_or_else(|| PathBuf::from("/usr/share/omarchy"), PathBuf::from);
    let state = match std::env::var_os("OMARCHY_MIGRATION_STATE") {
        Some(path) => PathBuf::from(path),
        None => dirs::home_dir()
            .context("Omarchy update requires the session user's home")?
            .join(".local/state/omarchy/migrations"),
    };
    anyhow::ensure!(
        !root.as_os_str().is_empty(),
        "OMARCHY_PATH must be non-empty"
    );
    anyhow::ensure!(
        !state.as_os_str().is_empty(),
        "OMARCHY_MIGRATION_STATE must be non-empty"
    );
    ensure_migrations_use_native_aur(&root.join("migrations"), &state)?;
    Ok(())
}

fn ensure_migrations_use_native_aur(migrations: &Path, state: &Path) -> Result<()> {
    let entries = match std::fs::read_dir(migrations) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("Cannot inspect pending Omarchy migrations"),
    };
    for (index, entry) in entries.enumerate() {
        anyhow::ensure!(
            index < MAX_MIGRATIONS,
            "Omarchy migration inventory exceeds its limit"
        );
        let path = entry?.path();
        if path.extension().is_none_or(|extension| extension != "sh") {
            continue;
        }
        let name = path.file_name().context("Invalid Omarchy migration name")?;
        if state.join(name).is_file() {
            continue;
        }
        let metadata = std::fs::metadata(&path)?;
        anyhow::ensure!(
            metadata.is_file() && metadata.len() <= MAX_MIGRATION_BYTES,
            "Invalid or oversized Omarchy migration {}",
            path.display()
        );
        let contents = std::fs::read_to_string(&path)?;
        let known_external_aur = ["omarchy-pkg-aur-", "yay ", "yay\n", "aura ", "paru "];
        anyhow::ensure!(
            !known_external_aur
                .iter()
                .any(|command| contents.contains(command)),
            "Native AUR integration refuses pending Omarchy migration {} because it invokes an external AUR helper. A native migration equivalent is required before continuing.",
            path.display()
        );
    }
    Ok(())
}

fn lock_path() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map_or_else(|| PathBuf::from("/tmp"), PathBuf::from)
        .join("omarchy-update.lock")
}

fn open_owned_file(path: &Path) -> Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    let file = match options.create_new(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            options.create_new(false).open(path)?
        }
        Err(error) => return Err(error).with_context(|| format!("Cannot open {}", path.display())),
    };
    validate_file(&file, path)?;
    Ok(file)
}

fn validate_file(file: &File, path: &Path) -> Result<()> {
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == nix::unistd::geteuid().as_raw()
            && metadata.mode() & 0o022 == 0,
        "Omarchy coordination file must be single-link, owned by the current user and not group/other writable: {}",
        path.display()
    );
    let named = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        !named.file_type().is_symlink()
            && named.dev() == metadata.dev()
            && named.ino() == metadata.ino(),
        "Omarchy coordination pathname changed: {}",
        path.display()
    );
    Ok(())
}

fn inherit(file: &File, enabled: bool) -> Result<()> {
    let flags = FdFlag::from_bits_truncate(fcntl(file, FcntlArg::F_GETFD)?);
    let updated = if enabled {
        flags & !FdFlag::FD_CLOEXEC
    } else {
        flags | FdFlag::FD_CLOEXEC
    };
    fcntl(file, FcntlArg::F_SETFD(updated))?;
    Ok(())
}

fn duplicate_inherited(value: &str, expected: &Path) -> Result<File> {
    let raw: i32 = value
        .parse()
        .context("Invalid Omarchy transport descriptor")?;
    anyhow::ensure!(
        raw >= 3,
        "Omarchy transport cannot use standard descriptors"
    );
    let proc_path = PathBuf::from(format!("/proc/self/fd/{raw}"));
    let metadata =
        std::fs::metadata(&proc_path).context("Omarchy transport descriptor is closed")?;
    let named = std::fs::symlink_metadata(expected)?;
    anyhow::ensure!(
        metadata.is_file()
            && !named.file_type().is_symlink()
            && metadata.dev() == named.dev()
            && metadata.ino() == named.ino(),
        "Omarchy transport descriptor does not match its coordination file"
    );
    // SAFETY: the inherited descriptor was just verified open against the
    // fixed coordination inode. No Rust owner in this process closes it.
    #[expect(
        unsafe_code,
        reason = "inherited descriptors have no Rust owner to borrow from"
    )]
    let borrowed = unsafe { BorrowedFd::borrow_raw(raw) };
    let duplicate = nix::unistd::dup(borrowed)?;
    let file = File::from(duplicate);
    validate_file(&file, expected)?;
    inherit(&file, false)?;
    fcntl(borrowed, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
    Ok(file)
}

fn inherited_lock(value: &str, path: &Path) -> Result<File> {
    let inherited = duplicate_inherited(value, path)?;
    let independent = open_owned_file(path)?;
    match independent.try_lock() {
        Err(std::fs::TryLockError::WouldBlock) => {}
        result => {
            result.context("Cannot verify the inherited Omarchy lock")?;
            anyhow::bail!("Omarchy transport has no existing lock lease");
        }
    }
    inherited
        .try_lock()
        .context("Omarchy transport does not own its lock")?;
    Ok(inherited)
}

struct Interruptions {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
    hangup: tokio::signal::unix::Signal,
}

impl Interruptions {
    fn new() -> Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
            hangup: signal(SignalKind::hangup())?,
        })
    }

    async fn receive(&mut self) -> Result<()> {
        let received = tokio::select! {
            value = self.interrupt.recv() => value,
            value = self.terminate.recv() => value,
            value = self.hangup.recv() => value,
        };
        received.context("Update interruption stream closed")
    }
}

async fn interrupt() -> Result<()> {
    Interruptions::new()?.receive().await
}

struct TerminalMode {
    file: File,
    saved: nix::sys::termios::Termios,
}

impl Drop for TerminalMode {
    fn drop(&mut self) {
        if let Err(error) = nix::sys::termios::tcsetattr(
            &self.file,
            nix::sys::termios::SetArg::TCSANOW,
            &self.saved,
        ) && !matches!(error, nix::errno::Errno::ENOTTY | nix::errno::Errno::EIO)
        {
            tracing::warn!("Cannot restore update terminal settings: {error}");
        }
    }
}

enum PtyInput {
    Pollable(tokio::io::unix::AsyncFd<File>),
    Regular(tokio::fs::File),
    Closed,
}

impl PtyInput {
    async fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        use tokio::io::AsyncReadExt;
        match self {
            Self::Pollable(input) => read_pty(input, buffer).await,
            Self::Regular(input) => input.read(buffer).await,
            Self::Closed => std::future::pending().await,
        }
    }
}

fn register_file(file: File) -> Result<tokio::io::unix::AsyncFd<File>> {
    // SAFETY: AsyncFd owns this File. Its descriptor is never closed or replaced
    // independently, and no mutable reference to the owned File escapes.
    #[expect(
        unsafe_code,
        reason = "Tokio requires an explicit owned descriptor proof"
    )]
    let registered = unsafe { tokio::io::unix::AsyncFd::register(file) };
    Ok(registered?)
}

fn terminal_input() -> Result<(PtyInput, Option<TerminalMode>)> {
    use std::io::IsTerminal;
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOCTTY | nix::libc::O_CLOEXEC)
        .open("/proc/self/fd/0")
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((PtyInput::Closed, None));
        }
        Err(error) => return Err(error).context("Cannot open update input"),
    };
    if file.is_terminal() {
        let saved = nix::sys::termios::tcgetattr(&file)?;
        let mut raw = saved.clone();
        nix::sys::termios::cfmakeraw(&mut raw);
        let restoration = TerminalMode {
            file: file.try_clone()?,
            saved,
        };
        nix::sys::termios::tcsetattr(&file, nix::sys::termios::SetArg::TCSANOW, &raw)?;
        return Ok((PtyInput::Pollable(register_file(file)?), Some(restoration)));
    }
    let metadata = file.metadata()?;
    if metadata.is_file() || metadata.rdev() == std::fs::metadata("/dev/null")?.rdev() {
        return Ok((PtyInput::Regular(tokio::fs::File::from_std(file)), None));
    }
    Ok((PtyInput::Pollable(register_file(file)?), None))
}

async fn read_pty(
    file: &tokio::io::unix::AsyncFd<File>,
    buffer: &mut [u8],
) -> std::io::Result<usize> {
    loop {
        let mut ready = file.readable().await?;
        match ready
            .try_io(|file| nix::unistd::read(file.get_ref(), buffer).map_err(std::io::Error::from))
        {
            Ok(Err(error)) if error.raw_os_error() == Some(nix::libc::EIO) => return Ok(0),
            Ok(result) => return result,
            Err(_) => {}
        }
    }
}

async fn write_pty(file: &tokio::io::unix::AsyncFd<File>, buffer: &[u8]) -> std::io::Result<usize> {
    loop {
        let mut ready = file.writable().await?;
        if let Ok(result) = ready
            .try_io(|file| nix::unistd::write(file.get_ref(), buffer).map_err(std::io::Error::from))
        {
            return result;
        }
    }
}

fn interrupt_coordinator(child: &tokio::process::Child) -> Result<()> {
    if let Some(pid) = child.id() {
        let pid =
            nix::unistd::Pid::from_raw(i32::try_from(pid).context("Invalid coordinator PID")?);
        match nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM) {
            Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
            Err(error) => return Err(error).context("Cannot interrupt the owned coordinator"),
        }
    }
    Ok(())
}

async fn drain_interrupted_coordinator(
    child: &mut tokio::process::Child,
    master: tokio::io::unix::AsyncFd<File>,
) -> Result<ExitStatus> {
    let interruption = interrupt_coordinator(child);
    let mut output = vec![0_u8; 4096];
    let mut output_open = true;
    loop {
        tokio::select! {
            status = child.wait() => {
                let status = status.context("Cannot reap interrupted Omarchy coordinator")?;
                interruption?;
                return Ok(status);
            }
            result = read_pty(&master, &mut output), if output_open => {
                match result {
                    Ok(0) => output_open = false,
                    Ok(_) => {},
                    Err(error) => {
                        drop(master);
                        child.wait().await.context("Cannot reap coordinator after terminal failure")?;
                        return Err(error).context("Cannot drain interrupted Omarchy terminal");
                    }
                }
            }
        }
    }
}

async fn drain_completed_coordinator(
    master: &tokio::io::unix::AsyncFd<File>,
    mut transcript: &File,
) -> Result<()> {
    use std::io::Write;
    let drain = async {
        let mut output = vec![0_u8; 4096];
        loop {
            let count = read_pty(master, &mut output).await?;
            if count == 0 {
                return Ok::<_, anyhow::Error>(());
            }
            transcript.write_all(&output[..count])?;
            let _ = std::io::stdout().write_all(&output[..count]);
            tokio::task::yield_now().await;
        }
    };
    tokio::time::timeout(TERMINATION_GRACE, drain)
        .await
        .context("Omarchy terminal remained open after the coordinator exited")?
}

async fn execute_logged(program: &Path, args: &[&str], lock: &File, log: &File) -> Result<()> {
    use std::io::Write;
    let mut interruptions = Interruptions::new()?;
    let (mut input, terminal) = terminal_input()?;
    let pty = nix::pty::openpty(None, terminal.as_ref().map(|terminal| &terminal.saved))?;
    for descriptor in [&pty.master, &pty.slave] {
        fcntl(descriptor, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
    }
    let master = File::from(pty.master);
    let flags = nix::fcntl::OFlag::from_bits_truncate(fcntl(&master, FcntlArg::F_GETFL)?);
    fcntl(
        &master,
        FcntlArg::F_SETFL(flags | nix::fcntl::OFlag::O_NONBLOCK),
    )?;
    if let Some(terminal) = &terminal {
        rustix::termios::tcsetwinsize(&master, rustix::termios::tcgetwinsize(&terminal.file)?)?;
    }
    let resize_terminal = terminal
        .as_ref()
        .map(|terminal| terminal.file.try_clone())
        .transpose()?;
    let master = register_file(master)?;
    let slave = File::from(pty.slave);
    let mut transcript = log;
    transcript.write_all(b"OMG Omarchy update started\n")?;
    let launcher = crate::core::privilege::root_controlled_program_path("setsid")?;
    let mut resized =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())?;
    let mut command = Command::new(launcher);
    command
        .args(["--ctty", "--"])
        .arg(program)
        .args(args)
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave))
        .env(LOCK_FD, lock.as_raw_fd().to_string())
        .env(LOG_FD, log.as_raw_fd().to_string())
        .env(
            "OMARCHY_PATH",
            std::env::var_os("OMARCHY_PATH").unwrap_or_else(|| "/usr/share/omarchy".into()),
        )
        .kill_on_drop(true);
    inherit(lock, true)?;
    if let Err(error) = inherit(log, true) {
        inherit(lock, false)?;
        return Err(error);
    }
    // Inherit the outer process group so setsid can exec directly without
    // forking. Child::id then remains the inner coordinator's session leader.
    let spawned = command.spawn();
    drop(command);
    let lock_flags = inherit(lock, false);
    let log_flags = inherit(log, false);
    let mut child = spawned.context("Cannot start the Omarchy update terminal")?;
    if let Err(error) = lock_flags.and(log_flags) {
        return match drain_interrupted_coordinator(&mut child, master).await {
            Ok(_) => Err(error),
            Err(cleanup) => Err(error).context(format!("Transport cleanup failed: {cleanup:#}")),
        };
    }
    let mut output = vec![0_u8; 4096];
    let mut incoming = vec![0_u8; 4096];
    let mut queued = vec![0_u8; 4096];
    let mut pending = (0, 0);
    let mut output_open = true;
    let mut cancellation = None;
    let relay = async {
        loop {
            tokio::select! {
                status = child.wait() => {
                    let status = status?;
                    drain_completed_coordinator(&master, transcript).await?;
                    return Ok::<_, anyhow::Error>(status);
                }
                result = read_pty(&master, &mut output), if output_open => {
                    let count = result?;
                    if count == 0 {
                        output_open = false;
                    } else {
                        transcript.write_all(&output[..count])?;
                        if let Err(error) = std::io::stdout().write_all(&output[..count])
                            && cancellation.is_none()
                        {
                            cancellation = Some(anyhow::Error::new(error).context("Update output disconnected"));
                            interrupt_coordinator(&child)?;
                        }
                    }
                }
                result = input.read(&mut incoming), if pending.0 == pending.1 && cancellation.is_none() => {
                    let count = result?;
                    if count == 0 {
                        input = PtyInput::Closed;
                        queued[0] = 4;
                        pending = (0, 1);
                    } else {
                        queued[..count].copy_from_slice(&incoming[..count]);
                        pending = (0, count);
                    }
                }
                result = write_pty(&master, &queued[pending.0..pending.1]), if pending.0 < pending.1 && output_open => {
                    pending.0 += result?;
                }
                signal = interruptions.receive(), if cancellation.is_none() => {
                    cancellation = Some(match signal {
                        Ok(()) => anyhow::anyhow!("Omarchy update interrupted; inspect the update log before retrying"),
                        Err(error) => error,
                    });
                    interrupt_coordinator(&child)?;
                }
                _ = resized.recv(), if resize_terminal.is_some() => {
                    if let Some(terminal) = &resize_terminal {
                        rustix::termios::tcsetwinsize(master.get_ref(), rustix::termios::tcgetwinsize(terminal)?)?;
                    }
                }
            }
        }
    }.await;
    let status = match relay {
        Ok(status) => status,
        Err(error) => {
            return match drain_interrupted_coordinator(&mut child, master).await {
                Ok(status) => {
                    if let Err(footer) =
                        writeln!(transcript, "\nOMG Omarchy update finished: {status}")
                    {
                        tracing::warn!("Cannot finish interrupted update transcript: {footer}");
                    }
                    Err(error)
                }
                Err(cleanup) => {
                    Err(error).context(format!("Transport cleanup failed: {cleanup:#}"))
                }
            };
        }
    };
    writeln!(transcript, "\nOMG Omarchy update finished: {status}")?;
    if let Some(error) = cancellation {
        return Err(error);
    }
    anyhow::ensure!(
        status.success(),
        "Omarchy update did not complete: {status}"
    );
    Ok(())
}

fn ensure_mutation_context() -> Result<()> {
    anyhow::ensure!(
        !cfg!(test)
            && !crate::core::paths::test_mode()
            && std::env::var_os("CARGO_PRIMARY_PACKAGE").is_none(),
        "Omarchy update mutation is unavailable in test/development mode"
    );
    anyhow::ensure!(
        !crate::core::is_root(),
        "Run omg update as your session user on Omarchy; it authorizes individual system stages itself"
    );
    Ok(())
}

pub(super) async fn maybe_coordinate(intent: UpdateIntent) -> Result<bool> {
    if cfg!(test) || crate::core::paths::test_mode() || crate::cli::packages::mock_arch_backend()? {
        return Ok(false);
    }
    let flavor = if crate::core::env::distro::is_omarchy() {
        ArchFlavor::Omarchy
    } else {
        ArchFlavor::Arch
    };
    let UpdatePlan::Omarchy { yes } = plan(flavor, intent)? else {
        return Ok(false);
    };
    ensure_mutation_context()?;
    check_pending_migrations()?;
    let lock_transport = std::env::var(LOCK_FD).ok();
    let inherited_log = std::env::var(LOG_FD).ok();
    match (lock_transport, inherited_log) {
        (None, None) => {
            let lock = open_owned_file(&lock_path())?;
            lock.try_lock()
                .context("An Omarchy update is already running")?;
            let log = open_owned_file(Path::new(LOG_PATH))?;
            use std::os::unix::fs::PermissionsExt;
            log.set_permissions(std::fs::Permissions::from_mode(0o600))
                .context("Cannot make the current Omarchy transcript private")?;
            log.set_len(0)
                .context("Cannot start a fresh Omarchy update log")?;
            let executable = std::env::current_exe()?;
            let settings = crate::config::Settings::load()?;
            let mut arguments = vec!["update"];
            if yes {
                arguments.push("--yes");
            }
            if settings.aur.review_pkgbuild {
                arguments.push("--review");
            }
            execute_logged(&executable, &arguments, &lock, &log).await?;
        }
        (Some(lock_descriptor), Some(log_descriptor)) => {
            anyhow::ensure!(
                lock_descriptor != log_descriptor,
                "Omarchy transport descriptors overlap"
            );
            let lock = inherited_lock(&lock_descriptor, &lock_path())?;
            let log = duplicate_inherited(&log_descriptor, Path::new(LOG_PATH))?;
            use std::io::IsTerminal;
            anyhow::ensure!(
                std::io::stdin().is_terminal()
                    && std::io::stdout().is_terminal()
                    && log.metadata()?.len() > 0,
                "Omarchy update transport has no active PTY transcript"
            );
            let mut executor = Commands::new(yes);
            let result = tokio::select! {
                result = workflow(&mut executor, yes) => result,
                signal = interrupt() => {
                    signal?;
                    Err(anyhow::anyhow!("Omarchy update interrupted"))
                }
            };
            let cleanup = executor.cleanup().await;
            result?;
            cleanup?;
            drop((lock, log));
        }
        _ => anyhow::bail!("Incomplete Omarchy update transport"),
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private_directory() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("private Omarchy fixture")
    }

    #[derive(Default)]
    struct ObservedStages {
        stages: Vec<Stage>,
        failure: Option<Stage>,
        decline: Option<Stage>,
        missing_snapshot: bool,
    }

    impl StageExecutor for ObservedStages {
        async fn execute(&mut self, stage: Stage) -> Result<Outcome> {
            self.stages.push(stage);
            if self.failure == Some(stage) {
                anyhow::bail!("inert stage failure {stage:?}");
            }
            Ok(if self.decline == Some(stage) {
                Outcome::Declined
            } else if self.missing_snapshot && stage == Stage::Snapshot {
                Outcome::Unavailable
            } else {
                Outcome::Success
            })
        }
    }

    #[tokio::test]
    async fn lifecycle_preserves_omarchy_order_with_native_aur() {
        let mut observed = ObservedStages::default();
        workflow(&mut observed, false)
            .await
            .expect("complete inert lifecycle");
        assert_eq!(
            observed.stages,
            [
                Stage::Preflight,
                Stage::MigrationPreflight,
                Stage::Confirm,
                Stage::Authorize,
                Stage::Prune,
                Stage::Snapshot,
                Stage::InhibitSleep,
                Stage::DevelopmentCheckout,
                Stage::Keyrings,
                Stage::OfficialPackages,
                Stage::MigrationPreflight,
                Stage::MigrationsPending,
                Stage::RestartShell,
                Stage::Migrations,
                Stage::Orphans,
                Stage::AnalyzeLog,
                Stage::ClearIndicator,
                Stage::RestartServices,
                Stage::PostUpdateHooks,
                Stage::Mise,
                Stage::NativeAur,
                Stage::VerifyBoot,
                Stage::ReleaseAuthorization,
                Stage::ReleaseInhibitor,
                Stage::RebootPrompt,
            ]
        );
        for stage in observed.stages {
            if let Some((program, _)) = stage_command(stage) {
                assert!(
                    ![
                        "yay",
                        "aura",
                        "paru",
                        "omarchy-update-aur-pkgs",
                        "omarchy-update"
                    ]
                    .contains(&program)
                );
            }
        }
        assert_eq!(
            stage_command(Stage::OfficialPackages),
            Some(("omarchy-update-system-pkgs", &[][..]))
        );
        assert!(stage_command(Stage::NativeAur).is_none());
    }

    #[tokio::test]
    async fn failures_never_report_completion_or_leave_lifecycle_cleanup_out() {
        for failure in [
            Stage::Authorize,
            Stage::Prune,
            Stage::InhibitSleep,
            Stage::DevelopmentCheckout,
            Stage::Keyrings,
            Stage::OfficialPackages,
            Stage::MigrationsPending,
            Stage::Migrations,
            Stage::Orphans,
            Stage::AnalyzeLog,
            Stage::ClearIndicator,
            Stage::RestartServices,
            Stage::PostUpdateHooks,
            Stage::NativeAur,
            Stage::VerifyBoot,
            Stage::ReleaseAuthorization,
            Stage::ReleaseInhibitor,
        ] {
            let mut observed = ObservedStages {
                failure: Some(failure),
                ..ObservedStages::default()
            };
            let error = workflow(&mut observed, true)
                .await
                .expect_err("critical stage failure");
            assert!(format!("{error:#}").contains("inert stage failure"));
            assert!(
                observed.stages.contains(&Stage::ReleaseAuthorization),
                "{failure:?}"
            );
            if observed.stages.contains(&Stage::InhibitSleep) {
                assert!(
                    observed.stages.contains(&Stage::ReleaseInhibitor),
                    "{failure:?}"
                );
            }
            assert!(
                !observed.stages.contains(&Stage::RebootPrompt),
                "{failure:?}"
            );
        }
        for failure in [Stage::Preflight, Stage::MigrationPreflight] {
            let mut observed = ObservedStages {
                failure: Some(failure),
                ..ObservedStages::default()
            };
            workflow(&mut observed, false)
                .await
                .expect_err("preflight refusal");
            assert!(!observed.stages.contains(&Stage::Authorize));
        }
    }

    #[tokio::test]
    async fn optional_failures_do_not_skip_native_aur_or_boot_verification() {
        for failure in [Stage::Snapshot, Stage::RestartShell, Stage::Mise] {
            let mut observed = ObservedStages {
                failure: Some(failure),
                ..ObservedStages::default()
            };
            workflow(&mut observed, true)
                .await
                .expect("optional stage permits completion");
            assert!(observed.stages.contains(&Stage::NativeAur));
            assert!(observed.stages.contains(&Stage::VerifyBoot));
            assert_eq!(observed.stages.last(), Some(&Stage::RebootPrompt));
        }
        let mut observed = ObservedStages {
            missing_snapshot: true,
            decline: Some(Stage::MigrationsPending),
            ..ObservedStages::default()
        };
        workflow(&mut observed, true)
            .await
            .expect("no snapshot and no pending migration");
        assert!(!observed.stages.contains(&Stage::RestartShell));
        assert!(!observed.stages.contains(&Stage::Confirm));
    }

    #[tokio::test]
    async fn declined_confirmation_has_no_authorization_or_mutating_stages() {
        let mut observed = ObservedStages {
            decline: Some(Stage::Confirm),
            ..ObservedStages::default()
        };
        workflow(&mut observed, false)
            .await
            .expect("declined update");
        assert_eq!(
            observed.stages,
            [Stage::Preflight, Stage::MigrationPreflight, Stage::Confirm]
        );
    }

    #[test]
    fn standard_migration_fixture() {
        if std::env::var_os("OMG_OMARCHY_MIGRATION_FIXTURE").is_none() {
            return;
        }
        assert_eq!(
            crate::config::Settings::load()
                .expect("private standard settings")
                .aur
                .security_profile,
            crate::config::AurSecurityProfile::Standard
        );
        let error = check_pending_migrations()
            .expect_err("Standard must refuse a known external AUR helper");
        assert!(
            error.to_string().contains("external AUR helper"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn checkout_migration_fixture() {
        let Some(root) = std::env::var_os("OMG_OMARCHY_CHECKOUT_FIXTURE") else {
            return;
        };
        let root = PathBuf::from(root);
        let mut commands = Commands::new(false);
        if let Ok(variable) = std::env::var("OMG_OMARCHY_EMPTY_VARIABLE_FIXTURE") {
            let error = commands
                .execute(Stage::MigrationPreflight)
                .await
                .expect_err("explicitly empty migration paths must fail preflight");
            let diagnostic = error.to_string();
            assert!(
                diagnostic.contains(&variable) && diagnostic.contains("non-empty"),
                "{error:#}"
            );
            assert!(
                !root.join("executed").exists(),
                "invalid migration paths must not execute checkout programs"
            );
            return;
        }
        assert_eq!(
            commands
                .execute(Stage::MigrationPreflight)
                .await
                .expect("user checkout migration data must pass preflight"),
            Outcome::Success
        );
        std::fs::write(
            root.join("migrations/0002.sh"),
            "omarchy-pkg-aur-add brave-origin-bin\n",
        )
        .expect("inert external helper migration");
        let error = commands
            .execute(Stage::MigrationPreflight)
            .await
            .expect_err("user checkout must still refuse external AUR migrations");
        assert!(
            error.to_string().contains("external AUR helper"),
            "{error:#}"
        );
        assert!(
            !root.join("executed").exists(),
            "migration preflight must not execute checkout programs"
        );
    }

    #[test]
    fn user_checkout_migration_data_passes_preflight_without_executing_checkout_programs() {
        use std::os::unix::fs::PermissionsExt;
        let owner = private_directory();
        let root = owner.path().join("omarchy");
        let markers = owner.path().join("markers");
        for path in [root.join("migrations"), root.join("bin"), markers.clone()] {
            std::fs::create_dir_all(path).expect("private checkout directories");
        }
        std::fs::write(
            root.join("migrations/0001.sh"),
            "echo native configuration\n",
        )
        .expect("inert native migration");
        let executable = root.join("bin/omarchy-migrate");
        std::fs::write(
            &executable,
            "#!/bin/sh\nprintf executed > \"$OMARCHY_PATH/executed\"\nexit 88\n",
        )
        .expect("checkout executable sentinel");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
            .expect("user checkout executable permissions");
        let mut failures = Vec::new();
        for empty_variable in [None, Some("OMARCHY_PATH"), Some("OMARCHY_MIGRATION_STATE")] {
            let mut command =
                std::process::Command::new(std::env::current_exe().expect("test executable"));
            command
                .args([
                    "--exact",
                    "cli::packages::update::omarchy::tests::checkout_migration_fixture",
                    "--nocapture",
                ])
                .current_dir(owner.path())
                .env("OMG_OMARCHY_CHECKOUT_FIXTURE", &root)
                .env("OMARCHY_PATH", &root)
                .env("OMARCHY_MIGRATION_STATE", &markers)
                .env_remove("OMG_OMARCHY_EMPTY_VARIABLE_FIXTURE");
            if let Some(variable) = empty_variable {
                command
                    .env("OMG_OMARCHY_EMPTY_VARIABLE_FIXTURE", variable)
                    .env(variable, "");
            }
            let output = command
                .output()
                .expect("isolated checkout migration preflight");
            if !output.status.success() {
                failures.push(format!(
                    "empty variable {empty_variable:?}: {}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "Checkout migration preflight failed: {}",
            failures.join("\n")
        );
    }

    #[test]
    fn standard_updates_refuse_pending_external_aur_helpers() {
        let owner = private_directory();
        let root = owner.path().join("omarchy");
        let migrations = root.join("migrations");
        let markers = owner.path().join("markers");
        let config = owner.path().join("config");
        for path in [&migrations, &markers, &config] {
            std::fs::create_dir_all(path).expect("private migration directories");
        }
        std::fs::write(
            migrations.join("0001.sh"),
            "omarchy-pkg-aur-add brave-origin-bin\n",
        )
        .expect("inert known external helper payload");
        std::fs::write(
            config.join("config.toml"),
            toml::to_string(&crate::config::Settings::default())
                .expect("serialize Standard config"),
        )
        .expect("private Standard config");
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "cli::packages::update::omarchy::tests::standard_migration_fixture",
                "--nocapture",
            ])
            .env("OMG_OMARCHY_MIGRATION_FIXTURE", "1")
            .env("OMG_CONFIG_DIR", config)
            .env("OMARCHY_PATH", root)
            .env("OMARCHY_MIGRATION_STATE", markers)
            .output()
            .expect("isolated Standard migration admission test");
        assert!(
            output.status.success(),
            "Standard migration admission failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn known_external_aur_migrations_are_refused_until_marked_complete() {
        let owner = private_directory();
        let migrations = owner.path().join("migrations");
        let markers = owner.path().join("markers");
        std::fs::create_dir(&migrations).expect("migration directory");
        std::fs::create_dir(&markers).expect("marker directory");
        std::fs::write(migrations.join("0001.sh"), "echo native configuration\n")
            .expect("inert migration");
        ensure_migrations_use_native_aur(&migrations, &markers).expect("ordinary vendor migration");
        for command in [
            "omarchy-pkg-aur-add brave-origin-bin\n",
            "yay -Sua\n",
            "aura -Au\n",
            "paru -Sua\n",
        ] {
            std::fs::write(migrations.join("0002.sh"), command)
                .expect("inert helper-bearing migration");
            let error = ensure_migrations_use_native_aur(&migrations, &markers)
                .expect_err("known external AUR helper");
            assert!(error.to_string().contains("0002.sh"));
        }
        std::fs::write(markers.join("0002.sh"), b"").expect("upstream completion marker");
        ensure_migrations_use_native_aur(&migrations, &markers)
            .expect("completed migration is not rerun");
        ensure_migrations_use_native_aur(&owner.path().join("absent"), &markers)
            .expect("no migrations");
        std::fs::write(
            migrations.join("0003.sh"),
            vec![b'x'; MAX_MIGRATION_BYTES as usize + 1],
        )
        .expect("oversized inert payload");
        assert!(ensure_migrations_use_native_aur(&migrations, &markers).is_err());
    }

    #[test]
    fn coordination_refuses_aliases_writable_files_and_replaced_names() {
        use std::os::unix::fs::PermissionsExt;
        let owner = private_directory();
        let path = owner.path().join("update.lock");
        let original = open_owned_file(&path).expect("owned lock");
        original.try_lock().expect("first updater");
        assert!(
            open_owned_file(&path)
                .expect("same lock inode")
                .try_lock()
                .is_err()
        );
        let displaced = owner.path().join("displaced");
        std::fs::rename(&path, &displaced).expect("private replacement fault");
        std::fs::write(&path, b"replacement").expect("replacement inode");
        assert!(validate_file(&original, &path).is_err());
        std::fs::remove_file(&path).expect("remove replacement");
        std::os::unix::fs::symlink(&displaced, &path).expect("private alias");
        assert!(open_owned_file(&path).is_err());
        std::fs::remove_file(&path).expect("remove symlink");
        std::fs::hard_link(&displaced, &path).expect("private hardlink");
        assert!(open_owned_file(&path).is_err());
        std::fs::remove_file(&path).expect("remove hardlink");
        std::fs::rename(&displaced, &path).expect("restore original name");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
            .expect("private mode fault");
        assert!(open_owned_file(&path).is_err());
        assert!(open_owned_file(&owner.path().join("missing/file")).is_err());
    }

    #[test]
    fn inherited_descriptors_are_bound_to_their_owned_inodes() {
        let owner = private_directory();
        let path = owner.path().join("handoff");
        let file = open_owned_file(&path).expect("owned handoff");
        let raw = file.as_raw_fd().to_string();
        assert!(inherited_lock(&raw, &path).is_err());
        file.try_lock().expect("original inherited lease");
        inherited_lock(&raw, &path).expect("verified existing lock lease");
        let duplicate = duplicate_inherited(&raw, &path).expect("matching inherited inode");
        duplicate
            .try_lock()
            .expect("duplicated open description owns the same lock");
        assert!(
            FdFlag::from_bits_truncate(
                fcntl(&duplicate, FcntlArg::F_GETFD).expect("duplicate flags")
            )
            .contains(FdFlag::FD_CLOEXEC)
        );
        for invalid in ["garbage", "-1", "0", "1", "2", "2147483647"] {
            assert!(duplicate_inherited(invalid, &path).is_err(), "{invalid}");
        }
        let different = owner.path().join("different");
        drop(open_owned_file(&different).expect("different inode"));
        assert!(duplicate_inherited(&raw, &different).is_err());
    }

    #[tokio::test]
    async fn private_commands_preserve_status_and_cancelled_children_are_reaped() {
        let mut commands = Commands::new(false);
        let program =
            crate::core::privilege::root_controlled_program_path("sh").expect("system shell");
        assert_eq!(
            commands
                .run_program(&program, &["-c", "exit 7"])
                .await
                .expect("inert child")
                .code(),
            Some(7)
        );
        assert!(commands.active.is_none());
        let owner = private_directory();
        let ready = owner.path().join("ready");
        let script = "printf ready > \"$1\"; exec sleep 30";
        let arguments = [
            "-c",
            script,
            "omg-fixture",
            ready.to_str().expect("fixture path"),
        ];
        let mut operation = Box::pin(commands.run_program(&program, &arguments));
        let started = async {
            tokio::time::timeout(Duration::from_secs(5), async {
                while !ready.is_file() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("owned child started");
        };
        tokio::select! {
            result = &mut operation => panic!("owned child finished before cancellation: {result:?}"),
            () = started => {},
        }
        drop(operation);
        let pid = commands
            .active
            .as_ref()
            .and_then(tokio::process::Child::id)
            .expect("owned active child");
        commands
            .stop_active()
            .await
            .expect("stop and reap cancellation");
        assert!(commands.active.is_none());
        assert_eq!(
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(i32::try_from(pid).expect("pid")),
                None
            ),
            Err(nix::errno::Errno::ESRCH)
        );
        commands.cleanup().await.expect("idempotent cleanup");
        assert!(
            commands
                .run_program(&owner.path().join("absent"), &[])
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn cancellation_terminates_surviving_descendants() {
        struct KillGroup(nix::unistd::Pid);
        impl Drop for KillGroup {
            fn drop(&mut self) {
                let _ = nix::sys::signal::killpg(self.0, nix::sys::signal::Signal::SIGKILL);
            }
        }
        let owner = private_directory();
        let ready = owner.path().join("descendant");
        let program =
            crate::core::privilege::root_controlled_program_path("sh").expect("system shell");
        let mut commands = Commands::new(false);
        let arguments = [
            "-c",
            r#"sh -c 'trap "" TERM; printf %s "$$" > "$1"; exec sleep 30' fixture "$1" & wait"#,
            "fixture",
            ready.to_str().expect("private descendant path"),
        ];
        let mut operation = Box::pin(commands.run_program(&program, &arguments));
        tokio::select! {
            result = &mut operation => panic!("stage ended before cancellation: {result:?}"),
            () = async {
                tokio::time::timeout(Duration::from_secs(5), async {
                    while std::fs::read_to_string(&ready).unwrap_or_default().is_empty() {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                }).await.expect("descendant installed its TERM handler");
            } => {},
        }
        drop(operation);
        let leader = commands
            .active
            .as_ref()
            .and_then(tokio::process::Child::id)
            .expect("owned leader");
        let _cleanup = KillGroup(nix::unistd::Pid::from_raw(
            i32::try_from(leader).expect("leader PID"),
        ));
        let descendant: i32 = std::fs::read_to_string(&ready)
            .expect("descendant identity")
            .parse()
            .expect("descendant PID");
        commands
            .cleanup()
            .await
            .expect("cancel complete stage group");
        tokio::time::timeout(Duration::from_secs(5), async {
            while std::fs::read_to_string(format!("/proc/{descendant}/stat")).is_ok_and(|stat| {
                stat.rsplit_once(')')
                    .is_some_and(|(_, fields)| !fields.trim_start().starts_with('Z'))
            }) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("TERM-ignoring stage descendant must stop after cleanup");
    }

    #[tokio::test]
    async fn hangup_fixture() {
        if std::env::var_os("OMG_OMARCHY_HANGUP_FIXTURE").is_none() {
            return;
        }
        let mut commands = Commands::new(false);
        commands.authorization = Some(tokio::spawn(std::future::pending()));
        let mut interrupted = Box::pin(interrupt());
        tokio::select! {
            result = &mut interrupted => panic!("signal preceded fixture: {result:?}"),
            () = tokio::task::yield_now() => {},
        }
        nix::sys::signal::kill(nix::unistd::getpid(), nix::sys::signal::Signal::SIGHUP)
            .expect("private subprocess hangup signal");
        tokio::time::timeout(Duration::from_secs(5), interrupted)
            .await
            .expect("hangup reaches graceful cancellation")
            .expect("receive hangup");
        commands.cleanup().await.expect("hangup cleanup");
        assert!(
            commands.authorization.is_none(),
            "hangup stops authorization refresh"
        );
    }

    #[tokio::test]
    async fn terminal_disconnect_fixture() {
        let Some(root) = std::env::var_os("OMG_OMARCHY_DISCONNECT_FIXTURE") else {
            return;
        };
        let root = PathBuf::from(root);
        let mut commands = Commands::new(false);
        commands.foreground = Some(
            foreground_group()
                .expect("attached fixture terminal")
                .expect("controlling PTY"),
        );
        commands.authorization = Some(tokio::spawn(std::future::pending()));
        let mut interrupted = Box::pin(interrupt());
        tokio::select! {
            result = &mut interrupted => panic!("signal preceded disconnect fixture: {result:?}"),
            () = tokio::task::yield_now() => {},
        }
        std::fs::write(
            root.join("ready"),
            nix::unistd::getpid().as_raw().to_string(),
        )
        .expect("private disconnect readiness");
        tokio::time::timeout(Duration::from_secs(5), interrupted)
            .await
            .expect("closed PTY delivers hangup")
            .expect("receive terminal hangup");
        use std::io::IsTerminal;
        assert!(
            !std::io::stdin().is_terminal(),
            "fixture must lose the actual terminal"
        );
        commands
            .cleanup()
            .await
            .expect("cleanup after controlling terminal disconnect");
        assert!(
            commands.authorization.is_none(),
            "disconnect stops authorization refresh"
        );
        std::fs::write(root.join("complete"), b"cleaned")
            .expect("private disconnect cleanup receipt");
    }

    #[tokio::test]
    async fn real_pty_master_disconnect_preserves_cleanup() {
        struct KillGroup(Option<nix::unistd::Pid>);
        impl Drop for KillGroup {
            fn drop(&mut self) {
                if let Some(group) = self.0 {
                    let _ = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL);
                }
            }
        }
        let owner = private_directory();
        let pty = nix::pty::openpty(None, None).expect("private PTY pair");
        fcntl(&pty.master, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .expect("master cannot leak into child");
        fcntl(&pty.slave, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .expect("slave descriptor inheritance");
        let program =
            crate::core::privilege::root_controlled_program_path("setsid").expect("system setsid");
        let mut child = Command::new(program)
            .args(["--ctty", "--fork", "--wait"])
            .arg(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "cli::packages::update::omarchy::tests::terminal_disconnect_fixture",
                "--nocapture",
            ])
            .env("OMG_OMARCHY_DISCONNECT_FIXTURE", owner.path())
            .stdin(Stdio::from(File::from(pty.slave)))
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("private controlling-terminal fixture");
        let mut group = KillGroup(None);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(value) = std::fs::read_to_string(owner.path().join("ready"))
                    && let Ok(pid) = value.parse()
                {
                    group.0 = Some(nix::unistd::Pid::from_raw(pid));
                    break;
                }
                assert!(
                    child.try_wait().expect("fixture status").is_none(),
                    "disconnect fixture exited before readiness"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("private controlling terminal is ready");
        drop(pty.master);
        let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
            .await
            .expect("disconnected fixture exits")
            .expect("fixture exit status");
        assert!(
            output.status.success(),
            "disconnected fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read(owner.path().join("complete")).expect("cleanup receipt survives hangup"),
            b"cleaned"
        );
        group.0 = None;
    }

    #[tokio::test]
    async fn transcript_error_cleanup_fixture() {
        use std::io::Write;
        let Some(root) = std::env::var_os("OMG_OMARCHY_TRANSCRIPT_ERROR_FIXTURE") else {
            return;
        };
        let root = PathBuf::from(root);
        let mut interrupted = Box::pin(interrupt());
        tokio::select! {
            result = &mut interrupted => panic!("signal preceded output readiness: {result:?}"),
            () = tokio::task::yield_now() => {},
        }
        std::fs::write(root.join("ready"), b"ready").expect("private signal readiness");
        tokio::time::timeout(Duration::from_secs(5), async {
            while !root.join("sealed").is_file() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("private transcript sealed");
        println!("trigger the transcript failure");
        interrupted
            .await
            .expect("inner receives transcript cancellation");
        std::io::stdout()
            .write_all(&vec![b'x'; 1024 * 1024])
            .expect("cleanup output drains before coordinator reaping");
        std::fs::write(root.join("complete"), b"cleaned").expect("output cleanup completed");
    }

    #[tokio::test]
    async fn transcript_failure_drains_cleanup_before_returning_original_error() {
        use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};
        fn assert_send<T: Send>(future: T) -> T {
            future
        }
        let owner = private_directory();
        let lock = open_owned_file(&owner.path().join("lock")).expect("private transport lock");
        lock.try_lock().expect("private transport lease");
        let log = File::from(
            memfd_create(
                "omg-test-transcript",
                MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
            )
            .expect("private sealable transcript"),
        );
        let seal = log.try_clone().expect("private transcript sealing handle");
        let trigger = tokio::spawn({
            let root = owner.path().to_owned();
            async move {
                tokio::time::timeout(Duration::from_secs(5), async {
                    while !root.join("ready").is_file() {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .expect("inner signal handler ready");
                fcntl_add_seals(&seal, SealFlags::WRITE).expect("inject real transcript EPERM");
                std::fs::write(root.join("sealed"), b"sealed").expect("release private output");
            }
        });
        let executable = std::env::current_exe().expect("test executable");
        let env = crate::core::privilege::root_controlled_program_path("env").expect("system env");
        let assignment = format!(
            "OMG_OMARCHY_TRANSCRIPT_ERROR_FIXTURE={}",
            owner.path().display()
        );
        let arguments = [
            assignment.as_str(),
            executable.to_str().expect("test executable path"),
            "--exact",
            "cli::packages::update::omarchy::tests::transcript_error_cleanup_fixture",
            "--nocapture",
        ];
        let result = tokio::time::timeout(
            Duration::from_secs(8),
            assert_send(execute_logged(&env, &arguments, &lock, &log)),
        )
        .await
        .expect("transcript failure must drain and reap inner cleanup");
        trigger.await.expect("private transcript failure trigger");
        let error = result.expect_err("retain the original transcript failure");
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .and_then(std::io::Error::raw_os_error),
            Some(nix::libc::EPERM),
            "{error:#}"
        );
        assert_eq!(
            std::fs::read(owner.path().join("complete")).expect("cleanup completed before return"),
            b"cleaned"
        );
    }

    #[tokio::test]
    async fn transport_inner_cleanup_fixture() {
        let Some(root) = std::env::var_os("OMG_OMARCHY_INNER_CLEANUP_FIXTURE") else {
            return;
        };
        let root = PathBuf::from(root);
        let mut interrupted = Box::pin(interrupt());
        tokio::select! {
            result = &mut interrupted => panic!("signal preceded inner readiness: {result:?}"),
            () = tokio::task::yield_now() => {},
        }
        std::fs::write(
            root.join("ready"),
            nix::unistd::getpid().as_raw().to_string(),
        )
        .expect("inner signal handler ready");
        interrupted.await.expect("inner receives cancellation");
        tokio::time::sleep(Duration::from_secs(4)).await;
        std::fs::write(root.join("complete"), b"cleaned").expect("slow cleanup completed");
    }

    #[tokio::test]
    async fn transport_outer_cleanup_fixture() {
        let Some(root) = std::env::var_os("OMG_OMARCHY_OUTER_CLEANUP_FIXTURE") else {
            return;
        };
        let root = PathBuf::from(root);
        let lock = open_owned_file(&root.join("lock")).expect("private transport lock");
        lock.try_lock().expect("private transport lease");
        let log = open_owned_file(&root.join("log")).expect("private transport transcript");
        let trigger = tokio::spawn({
            let root = root.clone();
            async move {
                tokio::time::timeout(Duration::from_secs(5), async {
                    while !root.join("ready").is_file() {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .expect("inner became ready");
                if std::env::var_os("OMG_OMARCHY_OUTER_DISCONNECT_FIXTURE").is_none() {
                    nix::sys::signal::kill(
                        nix::unistd::getpid(),
                        nix::sys::signal::Signal::SIGTERM,
                    )
                    .expect("interrupt isolated outer coordinator");
                }
            }
        });
        let executable = std::env::current_exe().expect("test executable");
        let env = crate::core::privilege::root_controlled_program_path("env").expect("system env");
        let assignment = format!("OMG_OMARCHY_INNER_CLEANUP_FIXTURE={}", root.display());
        let result = execute_logged(
            &env,
            &[
                &assignment,
                executable.to_str().expect("test executable path"),
                "--exact",
                "cli::packages::update::omarchy::tests::transport_inner_cleanup_fixture",
                "--nocapture",
            ],
            &lock,
            &log,
        )
        .await;
        trigger.await.expect("isolated signal trigger");
        assert!(
            result.is_err(),
            "cancellation must retain a failed update result"
        );
        assert_eq!(
            std::fs::read(root.join("complete")).expect("outer must await complete inner cleanup"),
            b"cleaned"
        );
    }

    #[tokio::test]
    async fn outer_transport_waits_for_inner_cleanup() {
        let owner = private_directory();
        let output = tokio::time::timeout(
            Duration::from_secs(15),
            Command::new(std::env::current_exe().expect("test executable"))
                .args([
                    "--exact",
                    "cli::packages::update::omarchy::tests::transport_outer_cleanup_fixture",
                    "--nocapture",
                ])
                .env("OMG_OMARCHY_OUTER_CLEANUP_FIXTURE", owner.path())
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("isolated outer cancellation is bounded")
        .expect("outer fixture runs");
        assert!(
            output.status.success(),
            "outer transport abandoned inner cleanup: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test]
    async fn outer_terminal_disconnect_waits_for_inner_cleanup() {
        struct KillInner(Option<PathBuf>);
        impl Drop for KillInner {
            fn drop(&mut self) {
                if let Some(root) = &self.0
                    && let Ok(value) = std::fs::read_to_string(root.join("ready"))
                    && let Ok(pid) = value.parse()
                {
                    let _ = nix::sys::signal::killpg(
                        nix::unistd::Pid::from_raw(pid),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                }
            }
        }
        let owner = private_directory();
        let mut cleanup = KillInner(Some(owner.path().to_owned()));
        let pty = nix::pty::openpty(None, None).expect("private outer terminal");
        for descriptor in [&pty.master, &pty.slave] {
            fcntl(descriptor, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
                .expect("private terminal descriptors");
        }
        let launcher = crate::core::privilege::root_controlled_program_path("setsid")
            .expect("system session launcher");
        let mut child = Command::new(launcher)
            .args(["--ctty", "--"])
            .arg(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "cli::packages::update::omarchy::tests::transport_outer_cleanup_fixture",
                "--nocapture",
            ])
            .env("OMG_OMARCHY_OUTER_CLEANUP_FIXTURE", owner.path())
            .env("OMG_OMARCHY_OUTER_DISCONNECT_FIXTURE", "1")
            .stdin(Stdio::from(File::from(pty.slave)))
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("isolated outer controlling terminal");
        tokio::time::timeout(Duration::from_secs(5), async {
            while !owner.path().join("ready").is_file() {
                assert!(
                    child.try_wait().expect("outer status").is_none(),
                    "outer exited before terminal disconnect"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("inner ready before physical outer hangup");
        drop(pty.master);
        let output = tokio::time::timeout(Duration::from_secs(15), child.wait_with_output())
            .await
            .expect("physical outer disconnect completes")
            .expect("outer disconnect status");
        assert!(
            output.status.success(),
            "outer terminal hangup abandoned inner cleanup: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read(owner.path().join("complete"))
                .expect("inner cleanup complete before outer exit"),
            b"cleaned"
        );
        let transcript =
            std::fs::read_to_string(owner.path().join("log")).expect("complete native transcript");
        assert!(
            transcript.starts_with("OMG Omarchy update started\n"),
            "{transcript}"
        );
        assert!(
            transcript.contains("\nOMG Omarchy update finished: "),
            "{transcript}"
        );
        cleanup.0 = None;
    }

    #[tokio::test]
    async fn real_pty_hangup_reaches_cleanup() {
        let owner = private_directory();
        let lock = open_owned_file(&owner.path().join("lock")).expect("private PTY lock");
        lock.try_lock().expect("private PTY lease");
        let log = open_owned_file(&owner.path().join("log")).expect("private PTY log");
        let executable = std::env::current_exe().expect("test executable");
        let program =
            crate::core::privilege::root_controlled_program_path("env").expect("system env");
        execute_logged(
            &program,
            &[
                "OMG_OMARCHY_HANGUP_FIXTURE=1",
                executable.to_str().expect("test path"),
                "--exact",
                "cli::packages::update::omarchy::tests::hangup_fixture",
                "--nocapture",
            ],
            &lock,
            &log,
        )
        .await
        .expect("PTY hangup fixture completes graceful cleanup");
        let transcript = std::fs::read_to_string(owner.path().join("log")).expect("PTY transcript");
        assert!(transcript.contains("1 passed"), "{transcript}");
    }

    #[tokio::test]
    async fn completed_coordinator_waits_for_terminal_eof() {
        use std::io::Write;
        let owner = private_directory();
        let transcript = open_owned_file(&owner.path().join("transcript"))
            .expect("private pending-tail transcript");
        let pty = nix::pty::openpty(None, None).expect("private pending-tail PTY");
        let master = File::from(pty.master);
        fcntl(&master, FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK))
            .expect("nonblocking pending-tail master");
        let master = register_file(master).expect("owned pending-tail master");
        let mut slave = File::from(pty.slave);
        slave
            .write_all(b"before-")
            .expect("initial terminal output");
        let pending_output = async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            slave.write_all(b"after").expect("pending terminal tail");
            drop(slave);
        };
        let (drained, ()) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(
                drain_completed_coordinator(&master, &transcript),
                pending_output
            )
        })
        .await
        .expect("terminal tail reaches EOF without hanging");
        drained.expect("complete terminal stream");
        assert_eq!(
            std::fs::read(owner.path().join("transcript")).expect("pending-tail transcript"),
            b"before-after",
            "completion must include output pending before terminal EOF"
        );
    }

    #[tokio::test]
    async fn completed_coordinator_preserves_all_pty_tail_bytes() {
        let owner = private_directory();
        let transcript =
            open_owned_file(&owner.path().join("transcript")).expect("private transcript");
        let program =
            crate::core::privilege::root_controlled_program_path("printf").expect("system printf");
        let payload = "x".repeat(257);
        for attempt in 0..2000 {
            let pty = nix::pty::openpty(None, None).expect("private tail PTY");
            let master = File::from(pty.master);
            fcntl(&master, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
                .expect("tail master cannot leak to writer");
            fcntl(&master, FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK))
                .expect("nonblocking tail master");
            let master = register_file(master).expect("owned tail master");
            transcript.set_len(0).expect("reset private transcript");
            use std::io::{Seek, SeekFrom};
            let mut transcript = &transcript;
            transcript
                .seek(SeekFrom::Start(0))
                .expect("reset transcript position");
            let mut command = std::process::Command::new(&program);
            command
                .arg("%s")
                .arg(&payload)
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .stdout(Stdio::from(File::from(pty.slave)));
            let mut child = command.spawn().expect("private tail writer");
            drop(command);
            assert!(child.wait().expect("tail writer reap").success());
            drain_completed_coordinator(&master, transcript)
                .await
                .expect("drain exited coordinator output");
            assert_eq!(
                std::fs::read(owner.path().join("transcript")).expect("tail transcript"),
                payload.as_bytes(),
                "all child bytes must survive reap on attempt {attempt}"
            );
        }
    }

    #[tokio::test]
    async fn real_pty_transcript_preserves_literal_arguments_and_child_failure() {
        let owner = private_directory();
        let lock = open_owned_file(&owner.path().join("lock")).expect("private transcript lock");
        lock.try_lock().expect("transcript ownership");
        let log = open_owned_file(&owner.path().join("log")).expect("private transcript file");
        let program =
            crate::core::privilege::root_controlled_program_path("sh").expect("system shell");
        let literal = "value; $(printf must-not-execute) 'quoted'";
        execute_logged(
            &program,
            &[
                "-c",
                "test -t 1 && printf '%s\\n' \"$1\"",
                "fixture",
                literal,
            ],
            &lock,
            &log,
        )
        .await
        .expect("inert PTY child");
        let text =
            std::fs::read_to_string(owner.path().join("log")).expect("real current-run transcript");
        assert!(text.contains(literal), "{text}");
        assert!(
            FdFlag::from_bits_truncate(
                fcntl(&lock, FcntlArg::F_GETFD).expect("restored lock flags")
            )
            .contains(FdFlag::FD_CLOEXEC)
        );
        log.set_len(0).expect("new private transcript");
        let error = execute_logged(
            &program,
            &["-c", "printf failed-stage; exit 7"],
            &lock,
            &log,
        )
        .await
        .expect_err("failed PTY command");
        assert!(error.to_string().contains("did not complete"));
        assert!(
            std::fs::read_to_string(owner.path().join("log"))
                .expect("failed-stage transcript")
                .contains("failed-stage")
        );
    }

    #[tokio::test]
    async fn foreground_fixture() {
        if std::env::var_os("OMG_OMARCHY_FOREGROUND_FIXTURE").is_none() {
            return;
        }
        let initial = foreground_group()
            .expect("fixture terminal")
            .expect("PTY foreground");
        let program =
            crate::core::privilege::root_controlled_program_path("sh").expect("system shell");
        let mut commands = Commands::new(false);
        let status = commands
            .run_program(
                &program,
                &[
                    "-c",
                    "test -t 0 && test \"$(ps -o pgid= -p $$)\" = \"$(ps -o tpgid= -p $$)\"",
                ],
            )
            .await
            .expect("foreground fixture child");
        assert!(status.success(), "interactive stage must own the terminal");
        assert_eq!(
            foreground_group().expect("restored foreground"),
            Some(initial)
        );
        let mut operation = Box::pin(commands.run_program(&program, &["-c", "exec sleep 30"]));
        tokio::select! {
            result = &mut operation => panic!("foreground child finished unexpectedly: {result:?}"),
            () = tokio::time::sleep(Duration::from_millis(100)) => {},
        }
        drop(operation);
        assert_ne!(
            foreground_group().expect("active foreground"),
            Some(initial)
        );
        commands
            .cleanup()
            .await
            .expect("foreground cancellation cleanup");
        assert_eq!(
            foreground_group().expect("cancelled foreground"),
            Some(initial)
        );
        assert!(commands.active.is_none());
    }

    #[tokio::test]
    async fn real_pty_stages_restore_foreground_on_completion_and_cancellation() {
        let owner = private_directory();
        let lock = open_owned_file(&owner.path().join("lock")).expect("PTY fixture lock");
        lock.try_lock().expect("PTY fixture lease");
        let log = open_owned_file(&owner.path().join("log")).expect("PTY fixture transcript");
        let executable = std::env::current_exe().expect("test executable");
        let program =
            crate::core::privilege::root_controlled_program_path("env").expect("system env");
        execute_logged(
            &program,
            &[
                "OMG_OMARCHY_FOREGROUND_FIXTURE=1",
                executable.to_str().expect("test executable path"),
                "--exact",
                "cli::packages::update::omarchy::tests::foreground_fixture",
                "--nocapture",
            ],
            &lock,
            &log,
        )
        .await
        .expect("inert foreground PTY workflow");
        let transcript =
            std::fs::read_to_string(owner.path().join("log")).expect("foreground transcript");
        assert!(transcript.contains("1 passed"), "{transcript}");
    }

    #[test]
    fn mutation_context_never_allows_the_test_harness_to_run_host_helpers() {
        let error = ensure_mutation_context().expect_err("unit test mutation guard");
        assert!(error.to_string().contains("test/development mode"));
    }

    #[test]
    fn omarchy_full_updates_include_distro_coordination() {
        for yes in [false, true] {
            assert_eq!(
                plan(
                    ArchFlavor::Omarchy,
                    UpdateIntent::Standard {
                        yes,
                        no_sync: false,
                    },
                )
                .expect("a full Omarchy update is supported"),
                UpdatePlan::Omarchy { yes },
                "full updates must run Omarchy's surrounding update lifecycle"
            );
        }
    }

    #[test]
    fn normal_arch_preserves_native_update_modes() {
        for intent in [
            UpdateIntent::Check,
            UpdateIntent::DryRun,
            UpdateIntent::AurOnly,
            UpdateIntent::Standard {
                yes: false,
                no_sync: false,
            },
            UpdateIntent::Standard {
                yes: true,
                no_sync: true,
            },
            UpdateIntent::Fast,
            UpdateIntent::Turbo,
        ] {
            assert_eq!(
                plan(ArchFlavor::Arch, intent).expect("native Arch update mode"),
                UpdatePlan::Native,
                "normal Arch must retain its existing behavior for {intent:?}"
            );
        }
    }

    #[test]
    fn omarchy_read_only_and_aur_only_requests_never_run_system_stages() {
        for intent in [
            UpdateIntent::Check,
            UpdateIntent::DryRun,
            UpdateIntent::AurOnly,
        ] {
            assert_eq!(
                plan(ArchFlavor::Omarchy, intent).expect("scoped native operation"),
                UpdatePlan::Native,
                "{intent:?} must not invoke the mutating Omarchy coordinator"
            );
        }
    }

    #[test]
    fn omarchy_refuses_cached_and_official_only_modes_before_mutation() {
        for intent in [
            UpdateIntent::Standard {
                yes: false,
                no_sync: true,
            },
            UpdateIntent::Fast,
            UpdateIntent::Turbo,
        ] {
            assert!(
                plan(ArchFlavor::Omarchy, intent).is_err(),
                "{intent:?} cannot silently widen into a refreshing full Omarchy update"
            );
        }
    }
}
