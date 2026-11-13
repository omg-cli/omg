//! Omarchy's update lifecycle, with AUR builds owned by OMG.

use std::fs::File;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
#[cfg(test)]
use nix::fcntl::FdFlag;
use nix::fcntl::{FcntlArg, fcntl};
use tokio::process::Command;

use crate::package_managers::arch::NativeOmarchyOperation;

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
    NativePackage(NativeOmarchyOperation),
    Snapshot,
    InhibitSleep,
    DevelopmentCheckout,
    MigrationPreflight,
    MigrationsPending,
    RestartShell,
    Migrations,
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

fn finish_cleanup<T>(primary: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (primary, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) | (Err(error), Ok(())) => Err(error),
        (Err(error), Err(cleanup)) => {
            Err(error).context(format!("Omarchy cleanup failed: {cleanup:#}"))
        }
    }
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
        executor
            .execute(Stage::NativePackage(NativeOmarchyOperation::PruneCache))
            .await?;
        if let Err(error) = executor.execute(Stage::Snapshot).await {
            crate::cli::modern_ui::print_warning(&format!(
                "Continuing the Omarchy update without a snapshot: {error:#}"
            ));
        }
        inhibitor_attempted = true;
        executor.execute(Stage::InhibitSleep).await?;
        for stage in [
            Stage::DevelopmentCheckout,
            Stage::NativePackage(NativeOmarchyOperation::RefreshKeyrings),
            Stage::NativePackage(NativeOmarchyOperation::UpgradeRepositories),
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
            Stage::NativePackage(NativeOmarchyOperation::RemoveOrphans),
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
    let mut cleanup = Ok(());
    for (attempted, stage) in [
        (authorization_attempted, Stage::ReleaseAuthorization),
        (inhibitor_attempted, Stage::ReleaseInhibitor),
    ] {
        if attempted && let Err(error) = executor.execute(stage).await {
            tracing::error!("Omarchy cleanup {stage:?} failed: {error:#}");
            cleanup = finish_cleanup(
                cleanup,
                Err(error).with_context(|| format!("Omarchy cleanup {stage:?} failed")),
            );
        }
    }
    finish_cleanup(
        update.context("Omarchy update did not complete; inspect its update log before rebooting"),
        cleanup.context("Omarchy update cleanup did not complete"),
    )?;
    executor.execute(Stage::RebootPrompt).await?;
    Ok(())
}

fn stage_command(stage: Stage) -> Option<(&'static str, &'static [&'static str])> {
    Some(match stage {
        Stage::Preflight => ("omarchy-update-requires-free-space", &[]),
        Stage::Confirm => ("omarchy-update-confirm", &[]),
        Stage::Authorize => ("sudo", &["true"]),
        Stage::Snapshot => ("omarchy-snapshot", &["create"]),
        Stage::InhibitSleep => ("omarchy-update-stay-awake", &["start"]),
        Stage::DevelopmentCheckout => ("omarchy-update-dev", &[]),
        Stage::MigrationsPending => ("omarchy-migrate", &["--pending"]),
        Stage::RestartShell => ("omarchy-restart-shell", &[]),
        Stage::Migrations => ("omarchy-migrate", &[]),
        Stage::AnalyzeLog => ("omarchy-update-analyze-logs", &[]),
        Stage::ClearIndicator => ("omarchy-shell", &["-q", "omarchy.system-update", "clear"]),
        Stage::RestartServices => ("omarchy-update-restart", &["--services-only"]),
        Stage::PostUpdateHooks => ("omarchy-hook", &["post-update"]),
        Stage::Mise => ("omarchy-update-mise", &[]),
        Stage::VerifyBoot => ("omarchy-update-boot", &[]),
        Stage::ReleaseInhibitor => ("omarchy-update-stay-awake", &["stop"]),
        Stage::NativePackage(_)
        | Stage::MigrationPreflight
        | Stage::NativeAur
        | Stage::ReleaseAuthorization
        | Stage::RebootPrompt => return None,
    })
}

#[derive(Clone, Debug)]
struct OmarchyRuntime {
    root: PathBuf,
    migration_state: PathBuf,
}

impl OmarchyRuntime {
    fn discover() -> Result<Self> {
        if let Some(requested) = std::env::var_os("OMARCHY_PATH") {
            anyhow::ensure!(!requested.is_empty(), "OMARCHY_PATH must be non-empty");
        }
        let migration_state = Self::migration_state()?;
        let migrate = crate::core::privilege::root_controlled_program_path("omarchy-migrate")?;
        let root = Self::root_for_migrate(&migrate)?;
        Self::validate_root_directory(&root)?;
        let runtime = Self {
            root,
            migration_state,
        };
        runtime.validate_available_helpers()?;
        Ok(runtime)
    }

    fn root_for_migrate(program: &Path) -> Result<PathBuf> {
        if program == Path::new("/usr/bin/omarchy-migrate") {
            return Ok(PathBuf::from("/usr/share/omarchy"));
        }
        let bin = program
            .parent()
            .context("Omarchy migration helper lacks parent")?;
        anyhow::ensure!(
            program.is_absolute()
                && program
                    .file_name()
                    .is_some_and(|name| name == "omarchy-migrate")
                && bin.file_name().is_some_and(|name| name == "bin"),
            "Trusted Omarchy migration helper has an unsupported runtime layout"
        );
        Ok(bin
            .parent()
            .context("Omarchy runtime root is missing")?
            .to_owned())
    }

    fn validate_root_directory(root: &Path) -> Result<()> {
        anyhow::ensure!(
            std::fs::canonicalize(root).context("Cannot resolve selected Omarchy runtime")? == root,
            "Selected Omarchy runtime must be canonical"
        );
        for path in root.ancestors() {
            let metadata = std::fs::metadata(path)?;
            anyhow::ensure!(
                metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
                "Selected Omarchy runtime directory is not root-controlled"
            );
        }
        Ok(())
    }

    fn migration_state() -> Result<PathBuf> {
        let state = match std::env::var_os("OMARCHY_MIGRATION_STATE") {
            Some(path) => PathBuf::from(path),
            None => dirs::home_dir()
                .context("Omarchy update requires the session user's home")?
                .join(".local/state/omarchy/migrations"),
        };
        anyhow::ensure!(
            !state.as_os_str().is_empty(),
            "OMARCHY_MIGRATION_STATE must be non-empty"
        );
        std::path::absolute(state).context("Cannot resolve Omarchy migration state")
    }

    fn check_helper_layout(&self, name: &str, program: &Path) -> Result<()> {
        let packaged = self.root == Path::new("/usr/share/omarchy")
            && program == Path::new("/usr/bin").join(name);
        anyhow::ensure!(
            packaged || program == self.root.join("bin").join(name),
            "Trusted Omarchy helper {name} does not match the selected runtime"
        );
        Ok(())
    }

    fn validate_available_helpers(&self) -> Result<()> {
        for stage in [
            Stage::Preflight,
            Stage::InhibitSleep,
            Stage::DevelopmentCheckout,
            Stage::MigrationsPending,
            Stage::Migrations,
            Stage::AnalyzeLog,
            Stage::ClearIndicator,
            Stage::RestartServices,
            Stage::PostUpdateHooks,
            Stage::VerifyBoot,
            Stage::ReleaseInhibitor,
        ] {
            let (name, _) = stage_command(stage).context("Missing Omarchy helper mapping")?;
            if let Ok(program) = crate::core::privilege::root_controlled_program_path(name) {
                self.check_helper_layout(name, &program)?;
            }
        }
        Ok(())
    }

    fn check_pending_migrations(&self) -> Result<()> {
        anyhow::ensure!(
            !self.root.as_os_str().is_empty(),
            "OMARCHY_PATH must be non-empty"
        );
        anyhow::ensure!(
            !self.migration_state.as_os_str().is_empty(),
            "OMARCHY_MIGRATION_STATE must be non-empty"
        );
        ensure_migrations_use_native_aur(&self.root.join("migrations"), &self.migration_state)
    }

    fn notice_normalization(&self) {
        if std::env::var_os("OMARCHY_PATH")
            .is_some_and(|requested| Path::new(&requested) != self.root)
        {
            crate::cli::modern_ui::print_info(&format!(
                "Using Omarchy runtime {} selected by trusted system helpers.",
                crate::cli::style::sanitize_terminal_text(&self.root.display().to_string())
            ));
        }
    }
}

struct Commands {
    yes: bool,
    runtime: OmarchyRuntime,
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
    const fn new(yes: bool, runtime: OmarchyRuntime) -> Self {
        Self {
            yes,
            runtime,
            authorization: None,
            inhibitor_attempted: false,
            active: None,
            foreground: None,
        }
    }

    async fn run_program(&mut self, program: &Path, args: &[&str]) -> Result<ExitStatus> {
        anyhow::ensure!(self.active.is_none(), "An Omarchy stage is already running");
        let mut command = Command::new(program);
        command
            .args(args)
            .kill_on_drop(true)
            .process_group(0)
            .env("OMARCHY_PATH", &self.runtime.root)
            .env("OMARCHY_MIGRATION_STATE", &self.runtime.migration_state);
        command.env_remove(LOCK_FD).env_remove(LOG_FD);
        if self.yes {
            command.env("OMARCHY_UPDATE_UNATTENDED", "1");
        }
        self.run_command(command, &program.display().to_string())
            .await
    }

    async fn run_command(&mut self, mut command: Command, label: &str) -> Result<ExitStatus> {
        anyhow::ensure!(self.active.is_none(), "An Omarchy stage is already running");
        command.kill_on_drop(true).process_group(0);
        command.env_remove(LOCK_FD).env_remove(LOG_FD);
        self.start(&mut command)
            .await
            .with_context(|| format!("Failed to start Omarchy stage {label}"))?;
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
                let cleanup = self.stop_active().await;
                finish_cleanup(
                    Err(error).with_context(|| format!("Failed to wait for {label}")),
                    cleanup,
                )
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
                let cleanup = self.stop_active().await;
                return finish_cleanup(Err(error), cleanup);
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
        finish_cleanup(result, restored)
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
        finish_cleanup(active, inhibition)
    }
}

impl StageExecutor for Commands {
    async fn execute(&mut self, stage: Stage) -> Result<Outcome> {
        match stage {
            Stage::NativePackage(operation) => {
                use crate::package_managers::arch::NativeOmarchyInteraction;
                let interaction = if self.yes {
                    NativeOmarchyInteraction::Unattended
                } else {
                    NativeOmarchyInteraction::Attended
                };
                let command =
                    crate::core::privilege::native_omarchy_command(operation, interaction)?;
                let status = self.run_command(command, operation.argument()).await?;
                crate::package_managers::arch::complete_native_omarchy_write(status.success())
                    .await?;
                anyhow::ensure!(
                    status.success(),
                    "Native Omarchy {operation:?} failed: {status}"
                );
                return Ok(Outcome::Success);
            }
            Stage::RebootPrompt => {
                if let Some(reason) = native_reboot_reason()? {
                    if self.yes || !console::user_attended() {
                        println!("{reason} Run omarchy-system reboot when ready.");
                    } else {
                        let _quiesce = crate::cli::modern_ui::quiesce_terminal();
                        if dialoguer::Confirm::with_theme(&crate::cli::ui::prompt_theme())
                            .with_prompt(format!("{reason} Reboot now?"))
                            .default(false)
                            .interact()?
                        {
                            let executable = crate::core::privilege::root_controlled_program_path(
                                "omarchy-system",
                            )?;
                            self.runtime
                                .check_helper_layout("omarchy-system", &executable)?;
                            let status = self.run_program(&executable, &["reboot"]).await?;
                            anyhow::ensure!(status.success(), "Omarchy reboot failed: {status}");
                        }
                    }
                }
                return Ok(Outcome::Success);
            }
            Stage::NativeAur => {
                super::arch::update_omarchy_aur(self.yes).await?;
                return Ok(Outcome::Success);
            }
            Stage::MigrationPreflight => {
                OmarchyRuntime::validate_root_directory(&self.runtime.root)?;
                self.runtime.validate_available_helpers()?;
                self.runtime.check_pending_migrations()?;
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
        if program.starts_with("omarchy-") {
            OmarchyRuntime::validate_root_directory(&self.runtime.root)?;
            self.runtime.check_helper_layout(program, &executable)?;
        }
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
        let known_external_aur = [
            "omarchy-pkg-aur-",
            "yay ",
            "yay\n",
            "aura ",
            "paru ",
            "pacman",
            "paccache",
            "omarchy-pkg-add",
            "omarchy-pkg-drop",
            "omarchy-pkg-present",
            "omarchy-pkg-missing",
        ];
        anyhow::ensure!(
            !known_external_aur
                .iter()
                .any(|command| contents.contains(command)),
            "Native AUR integration refuses pending Omarchy migration {} because it references an external package helper. A native migration equivalent is required before continuing.",
            path.display()
        );
    }
    Ok(())
}

fn native_reboot_reason() -> Result<Option<&'static str>> {
    let home = dirs::home_dir();
    let inspection = RebootInspection {
        root: Path::new("/"),
        processes: Path::new("/proc"),
        home: home.as_deref(),
        uid: rustix::process::getuid().as_raw(),
    };
    reboot_reason_at(&inspection, |modules| {
        crate::package_managers::alpm_direct::with_handle(|handle| {
            Ok(handle.localdb().pkgs().iter().any(|package| {
                package
                    .files()
                    .files()
                    .iter()
                    .any(|file| file.name() == modules.as_bytes())
            }))
        })
    })
}

#[derive(Debug)]
struct RebootInspection<'a> {
    root: &'a Path,
    processes: &'a Path,
    home: Option<&'a Path>,
    uid: u32,
}

fn reboot_reason_at(
    inspection: &RebootInspection<'_>,
    owns_modules: impl FnOnce(&str) -> Result<bool>,
) -> Result<Option<&'static str>> {
    let running = std::fs::read_to_string(inspection.processes.join("sys/kernel/osrelease"))
        .context("Cannot inspect the running kernel")?;
    let running = running.trim();
    anyhow::ensure!(
        !running.is_empty() && !running.contains('/'),
        "Invalid running kernel release"
    );
    let modules = format!("usr/lib/modules/{running}/modules.builtin");
    if !owns_modules(&modules)? || !inspection.root.join(&modules).is_file() {
        return Ok(Some(
            "The installed kernel differs from the running kernel.",
        ));
    }
    if inspection
        .home
        .is_some_and(|home| home.join(".local/state/omarchy/reboot-required").is_file())
    {
        return Ok(Some("Omarchy marked this update as requiring a reboot."));
    }
    for entry in std::fs::read_dir(inspection.processes)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .is_none_or(|name| name.parse::<u32>().is_err())
        {
            continue;
        }
        let path = entry.path();
        let Ok(metadata) = std::fs::metadata(&path) else {
            continue;
        };
        if metadata.uid() != inspection.uid {
            continue;
        }
        if std::fs::read_to_string(path.join("comm")).is_ok_and(|name| name.trim() == "Hyprland")
            && std::fs::read_link(path.join("exe")).is_ok_and(|executable| {
                executable
                    .as_os_str()
                    .as_encoded_bytes()
                    .ends_with(b" (deleted)")
            })
        {
            return Ok(Some(
                "The running Hyprland executable was replaced during the update.",
            ));
        }
    }
    Ok(None)
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

#[derive(Clone, Copy, Debug)]
enum DescriptorOperation {
    ReadFlags,
    WriteFlags(i32),
}

fn descriptor_control(raw: i32, operation: DescriptorOperation) -> std::io::Result<i32> {
    let (operation, flags) = match operation {
        DescriptorOperation::ReadFlags => (nix::libc::F_GETFD, 0),
        DescriptorOperation::WriteFlags(flags) => (nix::libc::F_SETFD, flags),
    };
    // SAFETY: fcntl only inspects or changes descriptor flags. It does not
    // borrow, close or adopt the descriptor. This helper also runs after fork,
    // so it uses only async-signal-safe calls and raw OS error capture.
    #[expect(
        unsafe_code,
        reason = "raw descriptor flags are needed before ownership is established"
    )]
    let result = unsafe { nix::libc::fcntl(raw, operation, flags) };
    if result == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn set_descriptor_inheritance(raw: i32, enabled: bool) -> std::io::Result<()> {
    let flags = descriptor_control(raw, DescriptorOperation::ReadFlags)?;
    let updated = if enabled {
        flags & !nix::libc::FD_CLOEXEC
    } else {
        flags | nix::libc::FD_CLOEXEC
    };
    descriptor_control(raw, DescriptorOperation::WriteFlags(updated)).map(|_| ())
}

fn transport_inheritance_action(lock: i32, log: i32) -> impl FnMut() -> std::io::Result<()> {
    move || {
        set_descriptor_inheritance(lock, true)?;
        set_descriptor_inheritance(log, true)
    }
}

fn transport_descriptor(value: &str) -> Result<i32> {
    let raw: i32 = value
        .parse()
        .context("Invalid Omarchy transport descriptor")?;
    anyhow::ensure!(
        raw >= 3,
        "Omarchy transport cannot use standard descriptors"
    );
    Ok(raw)
}

/// Restrict update transport inheritance before CLI initialization can launch helpers.
#[doc(hidden)]
pub fn contain_inherited_transport(args: &[String]) -> Result<()> {
    if args.get(1).map(String::as_str) != Some("update") {
        return Ok(());
    }
    let (lock, log) = match (std::env::var_os(LOCK_FD), std::env::var_os(LOG_FD)) {
        (None, None) => return Ok(()),
        (Some(lock), Some(log)) => (lock, log),
        _ => anyhow::bail!("Incomplete Omarchy update transport"),
    };
    let lock = transport_descriptor(
        lock.to_str()
            .context("Invalid Omarchy lock descriptor encoding")?,
    )?;
    let log = transport_descriptor(
        log.to_str()
            .context("Invalid Omarchy log descriptor encoding")?,
    )?;
    anyhow::ensure!(lock != log, "Omarchy transport descriptors overlap");
    set_descriptor_inheritance(lock, false).context("Cannot contain inherited Omarchy lock")?;
    set_descriptor_inheritance(log, false).context("Cannot contain inherited Omarchy log")?;
    Ok(())
}

fn duplicate_inherited(value: &str, expected: &Path) -> Result<File> {
    let raw = transport_descriptor(value)?;
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
    set_descriptor_inheritance(raw, false)
        .context("Cannot contain inherited Omarchy descriptor")?;
    // SAFETY: the inherited descriptor was just verified open against the
    // fixed coordination inode. No Rust owner in this process closes it.
    #[expect(
        unsafe_code,
        reason = "inherited descriptors have no Rust owner to borrow from"
    )]
    let borrowed = unsafe { BorrowedFd::borrow_raw(raw) };
    let duplicate = borrowed.try_clone_to_owned()?;
    let file = File::from(duplicate);
    validate_file(&file, expected)?;
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

#[cfg(target_os = "linux")]
fn open_transport_pty(saved: Option<&nix::sys::termios::Termios>) -> Result<(File, File)> {
    use rustix::pty::{OpenptFlags, ioctl_tiocgptpeer, openpt, unlockpt};
    let flags = OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC;
    let master = openpt(flags).context("Cannot open update terminal master")?;
    unlockpt(&master).context("Cannot unlock update terminal")?;
    let slave = ioctl_tiocgptpeer(&master, flags).context("Cannot open update terminal peer")?;
    if let Some(saved) = saved {
        nix::sys::termios::tcsetattr(&slave, nix::sys::termios::SetArg::TCSANOW, saved)
            .context("Cannot configure update terminal peer")?;
    }
    Ok((File::from(master), File::from(slave)))
}

#[cfg(not(target_os = "linux"))]
fn open_transport_pty(_saved: Option<&nix::sys::termios::Termios>) -> Result<(File, File)> {
    anyhow::bail!("Omarchy update terminals require Linux")
}

async fn execute_logged(
    program: &Path,
    args: &[&str],
    lock: &File,
    log: &File,
    runtime: &OmarchyRuntime,
) -> Result<()> {
    use std::io::Write;
    let mut interruptions = Interruptions::new()?;
    let (mut input, terminal) = terminal_input()?;
    let (master, slave) = open_transport_pty(terminal.as_ref().map(|terminal| &terminal.saved))?;
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
    let mut transcript = log;
    transcript.write_all(b"OMG Omarchy update started\n")?;
    let launcher = crate::core::privilege::root_controlled_program_path("setsid")?;
    let mut resized =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())?;
    let handoff_lock = lock.try_clone()?;
    let handoff_log = log.try_clone()?;
    let lock_fd = handoff_lock.as_raw_fd();
    let log_fd = handoff_log.as_raw_fd();
    let mut command = Command::new(launcher);
    command
        .args(["--ctty", "--"])
        .arg(program)
        .args(args)
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave))
        .env(LOCK_FD, lock_fd.to_string())
        .env(LOG_FD, log_fd.to_string())
        .env("OMARCHY_PATH", &runtime.root)
        .env("OMARCHY_MIGRATION_STATE", &runtime.migration_state)
        .kill_on_drop(true);
    // SAFETY: only integer descriptor operations run after fork. The local
    // handoff Files remain open through spawn, their clones are above stdio,
    // and this Command is dropped before those Files can be released.
    #[expect(
        unsafe_code,
        reason = "only the coordinator child may inherit its transport"
    )]
    unsafe {
        command.pre_exec(transport_inheritance_action(lock_fd, log_fd));
    }
    // Inherit the outer process group so setsid can exec directly without
    // forking. Child::id then remains the inner coordinator's session leader.
    let spawned = command.spawn();
    drop(command);
    drop((handoff_lock, handoff_log));
    let mut child = spawned.context("Cannot start the Omarchy update terminal")?;
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
    let runtime = OmarchyRuntime::discover()?;
    runtime.check_pending_migrations()?;
    let lock_transport = std::env::var(LOCK_FD).ok();
    let inherited_log = std::env::var(LOG_FD).ok();
    match (lock_transport, inherited_log) {
        (None, None) => {
            runtime.notice_normalization();
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
            execute_logged(&executable, &arguments, &lock, &log, &runtime).await?;
        }
        (Some(lock_descriptor), Some(log_descriptor)) => {
            anyhow::ensure!(
                std::env::var_os("OMARCHY_PATH")
                    .is_some_and(|path| Path::new(&path) == runtime.root)
                    && std::env::var_os("OMARCHY_MIGRATION_STATE")
                        .is_some_and(|path| Path::new(&path) == runtime.migration_state),
                "Omarchy runtime changed during coordinator handoff"
            );
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
            let mut executor = Commands::new(yes, runtime);
            let result = tokio::select! {
                result = workflow(&mut executor, yes) => result,
                signal = interrupt() => {
                    signal?;
                    Err(anyhow::anyhow!("Omarchy update interrupted"))
                }
            };
            let cleanup = executor.cleanup().await;
            finish_cleanup(result, cleanup)?;
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

    fn transport_runtime() -> OmarchyRuntime {
        OmarchyRuntime {
            root: PathBuf::from("/usr/share/omarchy"),
            migration_state: std::path::absolute("markers")
                .expect("private transport migration state"),
        }
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
                Stage::NativePackage(NativeOmarchyOperation::PruneCache),
                Stage::Snapshot,
                Stage::InhibitSleep,
                Stage::DevelopmentCheckout,
                Stage::NativePackage(NativeOmarchyOperation::RefreshKeyrings),
                Stage::NativePackage(NativeOmarchyOperation::UpgradeRepositories),
                Stage::MigrationPreflight,
                Stage::MigrationsPending,
                Stage::RestartShell,
                Stage::Migrations,
                Stage::NativePackage(NativeOmarchyOperation::RemoveOrphans),
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
        for stage in [
            Stage::NativePackage(NativeOmarchyOperation::PruneCache),
            Stage::NativePackage(NativeOmarchyOperation::RefreshKeyrings),
            Stage::NativePackage(NativeOmarchyOperation::UpgradeRepositories),
            Stage::NativePackage(NativeOmarchyOperation::RemoveOrphans),
            Stage::RebootPrompt,
        ] {
            assert!(
                stage_command(stage).is_none(),
                "{stage:?} must execute native ALPM, never a package helper"
            );
        }
        assert!(stage_command(Stage::NativeAur).is_none());
    }

    #[tokio::test]
    async fn failures_never_report_completion_or_leave_lifecycle_cleanup_out() {
        for failure in [
            Stage::Authorize,
            Stage::NativePackage(NativeOmarchyOperation::PruneCache),
            Stage::InhibitSleep,
            Stage::DevelopmentCheckout,
            Stage::NativePackage(NativeOmarchyOperation::RefreshKeyrings),
            Stage::NativePackage(NativeOmarchyOperation::UpgradeRepositories),
            Stage::MigrationsPending,
            Stage::Migrations,
            Stage::NativePackage(NativeOmarchyOperation::RemoveOrphans),
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
    async fn workflow_retains_operation_and_all_cleanup_failures() {
        struct FailingStages {
            events: Vec<Stage>,
        }

        impl StageExecutor for FailingStages {
            async fn execute(&mut self, stage: Stage) -> Result<Outcome> {
                self.events.push(stage);
                match stage {
                    Stage::NativePackage(NativeOmarchyOperation::UpgradeRepositories) => {
                        anyhow::bail!("official package operation failed")
                    }
                    Stage::ReleaseAuthorization => {
                        anyhow::bail!("authorization release failed")
                    }
                    Stage::ReleaseInhibitor => anyhow::bail!("sleep inhibitor release failed"),
                    _ => Ok(Outcome::Success),
                }
            }
        }

        let mut observed = FailingStages { events: Vec::new() };
        let error = workflow(&mut observed, true)
            .await
            .expect_err("operation and both releases fail");
        for stage in [Stage::ReleaseAuthorization, Stage::ReleaseInhibitor] {
            assert_eq!(
                observed
                    .events
                    .iter()
                    .filter(|event| **event == stage)
                    .count(),
                1,
                "{stage:?} must be attempted once despite the other failures"
            );
        }
        assert!(
            !observed.events.contains(&Stage::RebootPrompt),
            "failed operation and cleanup cannot invite reboot"
        );
        let diagnostic = format!("{error:#}");
        for failure in [
            "official package operation failed",
            "authorization release failed",
            "sleep inhibitor release failed",
        ] {
            assert!(
                diagnostic.contains(failure),
                "returned error lost {failure:?}: {diagnostic}"
            );
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
        let runtime = OmarchyRuntime {
            root: PathBuf::from(std::env::var_os("OMARCHY_PATH").expect("private migration root")),
            migration_state: PathBuf::from(
                std::env::var_os("OMARCHY_MIGRATION_STATE").expect("private migration state"),
            ),
        };
        let error = runtime
            .check_pending_migrations()
            .expect_err("Standard must refuse a known external AUR helper");
        assert!(
            error.to_string().contains("external package helper"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn checkout_migration_fixture() {
        let Some(root) = std::env::var_os("OMG_OMARCHY_CHECKOUT_FIXTURE") else {
            return;
        };
        let root = PathBuf::from(root);
        let runtime = OmarchyRuntime {
            root: PathBuf::from(std::env::var_os("OMARCHY_PATH").expect("private checkout root")),
            migration_state: PathBuf::from(
                std::env::var_os("OMARCHY_MIGRATION_STATE").expect("private checkout state"),
            ),
        };
        let commands = Commands::new(false, runtime);
        if let Ok(variable) = std::env::var("OMG_OMARCHY_EMPTY_VARIABLE_FIXTURE") {
            let error = commands
                .runtime
                .check_pending_migrations()
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
        commands
            .runtime
            .check_pending_migrations()
            .expect("user checkout migration data must pass preflight");
        std::fs::write(
            root.join("migrations/0002.sh"),
            "omarchy-pkg-aur-add brave-origin-bin\n",
        )
        .expect("inert external helper migration");
        let error = commands
            .runtime
            .check_pending_migrations()
            .expect_err("user checkout must still refuse external AUR migrations");
        assert!(
            error.to_string().contains("external package helper"),
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
            "sudo pacman -Syu\n",
            "pacman-key --populate\n",
            "paccache -rk2\n",
            "omarchy-pkg-add package\n",
            "omarchy-pkg-drop package\n",
            "omarchy-pkg-present package\n",
            "omarchy-pkg-missing package\n",
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
    fn migration_inventory_errors_cannot_admit_an_uninspected_update() {
        let owner = private_directory();
        let inventory = owner.path().join("inventory");
        let markers = owner.path().join("markers");
        std::fs::write(&inventory, b"not a directory").expect("invalid inventory fixture");
        let error = ensure_migrations_use_native_aur(&inventory, &markers)
            .expect_err("a non-directory inventory must fail closed");
        assert!(
            error
                .to_string()
                .contains("Cannot inspect pending Omarchy migrations")
        );
        assert!(error.downcast_ref::<std::io::Error>().is_some());
    }

    #[test]
    fn migration_preflight_ignores_non_scripts_but_refuses_unreadable_scripts() {
        let owner = private_directory();
        let inventory = owner.path().join("migrations");
        let markers = owner.path().join("markers");
        std::fs::create_dir(&inventory).expect("private migration inventory");
        for name in ["README", "notes.txt", "0001.SH"] {
            std::fs::write(inventory.join(name), b"yay -Sua\n")
                .expect("non-script helper documentation");
        }
        ensure_migrations_use_native_aur(&inventory, &markers)
            .expect("non-shell entries are not pending migrations");
        let script = inventory.join("0002.sh");
        std::fs::create_dir(&script).expect("directory masquerading as a script");
        let error = ensure_migrations_use_native_aur(&inventory, &markers)
            .expect_err("a shell migration must be a regular file");
        assert!(error.to_string().contains("0002.sh"));
        std::fs::remove_dir(&script).expect("retire private directory fixture");
        std::os::unix::fs::symlink(owner.path().join("absent"), &script)
            .expect("dangling migration link");
        let error = ensure_migrations_use_native_aur(&inventory, &markers)
            .expect_err("missing migration contents must fail closed");
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .expect("metadata error")
                .kind(),
            std::io::ErrorKind::NotFound
        );
        std::fs::remove_file(&script).expect("retire dangling link");
        std::fs::write(&script, [0xff, 0xfe]).expect("non-UTF8 shell contents");
        let error = ensure_migrations_use_native_aur(&inventory, &markers)
            .expect_err("uninspectable shell contents must fail closed");
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .expect("decoding error")
                .kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn authorization_worker_failure_does_not_prevent_cleanup_or_reuse() {
        let mut commands = Commands::new(false, transport_runtime());
        let worker = tokio::spawn(async { panic!("isolated authorization worker failure") });
        tokio::time::timeout(Duration::from_secs(5), async {
            while !worker.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("worker failure is observable before cleanup");
        commands.authorization = Some(worker);
        commands
            .cleanup()
            .await
            .expect("panicked worker is released");
        commands
            .cleanup()
            .await
            .expect("cleanup remains idempotent");
        let shell =
            crate::core::privilege::root_controlled_program_path("sh").expect("system shell");
        assert!(
            commands
                .run_program(&shell, &["-c", "exit 0"])
                .await
                .expect("next inert stage can run after worker failure")
                .success()
        );
        assert!(commands.authorization.is_none());
    }

    #[tokio::test]
    async fn auto_reaped_stage_wait_error_fixture() {
        use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};

        if std::env::var_os("OMG_OMARCHY_AUTOREAP_FIXTURE").is_none() {
            return;
        }
        let owner = private_directory();
        let marker = owner.path().join("stage-pid");
        let program =
            crate::core::privilege::root_controlled_program_path("sh").expect("system shell");
        let primer =
            crate::core::privilege::root_controlled_program_path("true").expect("system true");
        assert!(
            Command::new(primer)
                .status()
                .await
                .expect("prime and reap Tokio's process driver")
                .success()
        );

        // SAFETY: this exact-test subprocess has reaped its sole child before
        // changing SIGCHLD. No parent test process changes signal disposition.
        // Keeping Tokio's registered handler lets its signal reaper wake while
        // SA_NOCLDWAIT makes the kernel reap the next inert child automatically.
        #[expect(
            unsafe_code,
            reason = "isolated child exercises real kernel auto-reaping"
        )]
        let previous = unsafe {
            let previous = sigaction(
                Signal::SIGCHLD,
                &SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty()),
            )
            .expect("save isolated fixture SIGCHLD disposition");
            let autoreap = SigAction::new(
                previous.handler(),
                previous.flags() | SaFlags::SA_NOCLDWAIT,
                previous.mask(),
            );
            sigaction(Signal::SIGCHLD, &autoreap).expect("enable kernel auto-reaping");
            previous
        };
        let mut commands = Commands::new(false, transport_runtime());
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            commands.run_program(
                &program,
                &[
                    "-c",
                    "printf '%s\\n' \"$$\" > \"$1\"",
                    "fixture",
                    marker.to_str().expect("private stage marker path"),
                ],
            ),
        )
        .await;
        // SAFETY: previous is the disposition saved in this same isolated
        // process; the owned inert child has exited or remains owned by cleanup.
        #[expect(unsafe_code, reason = "restore isolated fixture SIGCHLD disposition")]
        let restored = unsafe { sigaction(Signal::SIGCHLD, &previous) };
        let cleanup = commands.cleanup().await;

        restored.expect("restore fixture signal disposition before assertions");
        cleanup.expect("cleanup remains reusable after auto-reaping");
        let error = result
            .expect("auto-reaped stage reports its wait failure promptly")
            .expect_err("the kernel already reaped the stage");
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .expect("actual OS wait failure")
                .raw_os_error(),
            Some(nix::libc::ECHILD),
            "{error:#}"
        );
        let pid: i32 = std::fs::read_to_string(&marker)
            .expect("real stage wrote its own PID")
            .trim()
            .parse()
            .expect("owned inert stage PID");
        assert_eq!(
            nix::sys::wait::waitpid(
                nix::unistd::Pid::from_raw(pid),
                Some(nix::sys::wait::WaitPidFlag::WNOHANG)
            ),
            Err(nix::errno::Errno::ECHILD),
            "kernel auto-reaping left no waitable stage"
        );
        assert_eq!(
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None),
            Err(nix::errno::Errno::ESRCH),
            "the inert stage no longer exists"
        );
        assert!(
            commands.active.is_none(),
            "cleanup released child ownership"
        );
        let diagnostic = format!("{error:#}");
        assert!(
            diagnostic.contains(&format!("Failed to wait for {}", program.display())),
            "original stage wait context must survive cleanup failure: {diagnostic}"
        );
        assert!(
            diagnostic.contains("Failed to reap"),
            "cleanup's real reaping failure must remain visible: {diagnostic}"
        );
    }

    #[tokio::test]
    async fn auto_reaped_stage_preserves_wait_and_cleanup_errors() {
        let output = tokio::time::timeout(
            Duration::from_secs(15),
            Command::new(std::env::current_exe().expect("test executable"))
                .args([
                    "--exact",
                    "cli::packages::update::omarchy::tests::auto_reaped_stage_wait_error_fixture",
                    "--nocapture",
                ])
                .env("OMG_OMARCHY_AUTOREAP_FIXTURE", "1")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("isolated auto-reaping fixture finishes within its deadline")
        .expect("isolated auto-reaping fixture status");
        assert!(
            output.status.success(),
            "auto-reaping fixture failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test]
    async fn concurrent_stage_rejection_preserves_the_owned_child() {
        let owner = private_directory();
        let shell =
            crate::core::privilege::root_controlled_program_path("sh").expect("system shell");
        let mut commands = Commands::new(false, transport_runtime());
        let mut first = Command::new(&shell);
        first
            .args(["-c", "exec sleep 30"])
            .process_group(0)
            .kill_on_drop(true);
        commands.start(&mut first).await.expect("owned inert stage");
        let pid = commands
            .active
            .as_ref()
            .and_then(tokio::process::Child::id)
            .expect("owned active child");
        let marker = owner.path().join("unexpected-second-stage");
        let error = commands
            .run_program(
                &shell,
                &[
                    "-c",
                    "printf unexpected > \"$1\"",
                    "fixture",
                    marker.to_str().expect("marker path"),
                ],
            )
            .await
            .expect_err("overlapping stage must be refused");
        assert!(error.to_string().contains("already running"));
        assert!(!marker.exists(), "the rejected stage must never execute");
        assert_eq!(
            commands.active.as_ref().and_then(tokio::process::Child::id),
            Some(pid)
        );
        commands
            .cleanup()
            .await
            .expect("original child still belongs to cleanup");
        assert_eq!(
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(i32::try_from(pid).expect("pid")),
                None
            ),
            Err(nix::errno::Errno::ESRCH)
        );
    }

    #[tokio::test]
    async fn terminal_input_pipe_fixture() {
        let Some(root) = std::env::var_os("OMG_OMARCHY_PIPE_FIXTURE") else {
            return;
        };
        let root = PathBuf::from(root);
        let lock = open_owned_file(&root.join("lock")).expect("private pipe lock");
        lock.try_lock().expect("private pipe lease");
        let log = open_owned_file(&root.join("log")).expect("private pipe transcript");
        let shell =
            crate::core::privilege::root_controlled_program_path("sh").expect("system shell");
        execute_logged(
            &shell,
            &["-c", "IFS= read -r value; printf 'received:<%s>\\n' \"$value\"; if IFS= read -r extra; then exit 19; fi"],
            &lock,
            &log, &transport_runtime()).await.expect("pipe bytes and EOF reach the owned terminal");
        let transcript = std::fs::read_to_string(root.join("log")).expect("pipe transcript");
        assert!(
            transcript.contains("received:<literal; $(not-a-command) \\tail>"),
            "{transcript}"
        );
        assert!(
            transcript.contains("OMG Omarchy update finished: exit status: 0"),
            "{transcript}"
        );
    }

    #[tokio::test]
    async fn real_pipe_input_reaches_the_pty_without_shell_interpretation() {
        use tokio::io::AsyncWriteExt;
        let owner = private_directory();
        let mut child = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "cli::packages::update::omarchy::tests::terminal_input_pipe_fixture",
                "--nocapture",
            ])
            .env("OMG_OMARCHY_PIPE_FIXTURE", owner.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("isolated pipe transport fixture");
        let mut input = child.stdin.take().expect("owned pipe input");
        input
            .write_all(b"literal; $(not-a-command) \\tail\n")
            .await
            .expect("write real pipe bytes");
        drop(input);
        let output = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
            .await
            .expect("pipe EOF must not strand the coordinator")
            .expect("pipe fixture status");
        assert!(
            output.status.success(),
            "pipe fixture failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test]
    async fn terminal_input_socket_fixture() {
        if std::env::var_os("OMG_OMARCHY_SOCKET_FIXTURE").is_none() {
            return;
        }
        let Err(error) = terminal_input() else {
            panic!("socket stdin cannot be reopened as terminal input");
        };
        assert!(error.to_string().contains("Cannot open update input"));
        assert!(error.downcast_ref::<std::io::Error>().is_some());
    }

    #[tokio::test]
    async fn unsupported_socket_input_fails_before_launching_a_coordinator() {
        use std::os::fd::OwnedFd;
        let (input, _peer) = std::os::unix::net::UnixStream::pair().expect("private socket pair");
        let descriptor: OwnedFd = input.into();
        let output = tokio::time::timeout(
            Duration::from_secs(5),
            Command::new(std::env::current_exe().expect("test executable"))
                .args([
                    "--exact",
                    "cli::packages::update::omarchy::tests::terminal_input_socket_fixture",
                    "--nocapture",
                ])
                .env("OMG_OMARCHY_SOCKET_FIXTURE", "1")
                .stdin(Stdio::from(descriptor))
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("socket rejection is bounded")
        .expect("socket fixture status");
        assert!(
            output.status.success(),
            "socket fixture failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn reboot_inspection_distinguishes_kernel_marker_and_replaced_executable() -> Result<()> {
        let owner = private_directory();
        let root = owner.path().join("root");
        let processes = owner.path().join("proc");
        let home = owner.path().join("home");
        std::fs::create_dir_all(processes.join("sys/kernel"))?;
        std::fs::write(processes.join("sys/kernel/osrelease"), "fixture-kernel\n")?;
        let modules = root.join("usr/lib/modules/fixture-kernel/modules.builtin");
        std::fs::create_dir_all(modules.parent().expect("module directory"))?;
        std::fs::write(&modules, "fixture module inventory\n")?;
        let paths = RebootInspection {
            root: &root,
            processes: &processes,
            home: Some(&home),
            uid: rustix::process::getuid().as_raw(),
        };
        assert_eq!(
            reboot_reason_at(&paths, |_| Ok(false))?,
            Some("The installed kernel differs from the running kernel.")
        );
        assert_eq!(reboot_reason_at(&paths, |_| Ok(true))?, None);
        let marker = home.join(".local/state/omarchy/reboot-required");
        std::fs::create_dir_all(marker.parent().expect("marker directory"))?;
        std::fs::write(&marker, "reboot requested\n")?;
        assert_eq!(
            reboot_reason_at(&paths, |_| Ok(true))?,
            Some("Omarchy marked this update as requiring a reboot.")
        );
        std::fs::remove_file(marker)?;
        let hyprland = processes.join("123");
        std::fs::create_dir(&hyprland)?;
        std::fs::write(hyprland.join("comm"), "Hyprland\n")?;
        std::os::unix::fs::symlink("/inert/Hyprland", hyprland.join("exe"))?;
        assert_eq!(reboot_reason_at(&paths, |_| Ok(true))?, None);
        std::fs::remove_file(hyprland.join("exe"))?;
        std::os::unix::fs::symlink("/inert/Hyprland (deleted)", hyprland.join("exe"))?;
        assert_eq!(
            reboot_reason_at(&paths, |_| Ok(true))?,
            Some("The running Hyprland executable was replaced during the update.")
        );
        let other_user = RebootInspection {
            uid: paths.uid.checked_add(1).expect("test uid fits"),
            ..paths
        };
        assert_eq!(reboot_reason_at(&other_user, |_| Ok(true))?, None);
        std::fs::remove_file(modules)?;
        assert_eq!(
            reboot_reason_at(&paths, |_| Ok(true))?,
            Some("The installed kernel differs from the running kernel.")
        );
        Ok(())
    }

    #[test]
    fn reboot_inspection_rejects_invalid_kernel_data_and_tolerates_process_churn() -> Result<()> {
        use std::cell::Cell;
        use std::os::unix::ffi::OsStringExt;
        let owner = private_directory();
        let root = owner.path().join("root");
        let processes = owner.path().join("proc");
        std::fs::create_dir_all(processes.join("sys/kernel"))?;
        let release = processes.join("sys/kernel/osrelease");
        let paths = RebootInspection {
            root: &root,
            processes: &processes,
            home: None,
            uid: rustix::process::getuid().as_raw(),
        };
        let queries = Cell::new(0);
        let owns = |_: &str| {
            queries.set(queries.get() + 1);
            Ok(true)
        };
        assert!(reboot_reason_at(&paths, owns).is_err());
        for invalid in [b"".as_slice(), b"../escape", b"/absolute", b"\xff"] {
            std::fs::write(&release, invalid)?;
            assert!(reboot_reason_at(&paths, owns).is_err());
            assert_eq!(
                queries.get(),
                0,
                "invalid kernel data must not query native ownership"
            );
        }
        std::fs::write(&release, "fixture\n")?;
        let modules = root.join("usr/lib/modules/fixture/modules.builtin");
        std::fs::create_dir_all(modules.parent().expect("module directory"))?;
        std::fs::write(modules, "inert module inventory")?;
        std::fs::write(processes.join("not-a-process"), "ignored")?;
        std::fs::write(
            processes.join(std::ffi::OsString::from_vec(vec![0xff])),
            "ignored",
        )?;
        std::os::unix::fs::symlink(
            owner.path().join("disappeared-process"),
            processes.join("123"),
        )?;
        assert_eq!(reboot_reason_at(&paths, owns)?, None);
        assert_eq!(queries.get(), 1);
        let result = reboot_reason_at(&paths, |_| {
            std::fs::remove_dir_all(&processes)?;
            Ok(true)
        });
        assert_eq!(
            result
                .expect_err("lost process inventory must remain an error")
                .downcast_ref::<std::io::Error>()
                .expect("filesystem cause")
                .kind(),
            std::io::ErrorKind::NotFound
        );
        Ok(())
    }

    #[test]
    fn migration_state_defaults_to_the_session_home() -> Result<()> {
        const CHILD: &str = "OMG_OMARCHY_DEFAULT_STATE_FIXTURE";
        if std::env::var_os(CHILD).is_some() {
            let home = PathBuf::from(std::env::var_os("HOME").context("fixture home")?);
            assert_eq!(
                OmarchyRuntime::migration_state()?,
                home.join(".local/state/omarchy/migrations")
            );
            return Ok(());
        }
        let owner = private_directory();
        let output = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "cli::packages::update::omarchy::tests::migration_state_defaults_to_the_session_home", "--nocapture"])
            .env(CHILD, "1")
            .env("HOME", owner.path())
            .env_remove("OMARCHY_MIGRATION_STATE")
            .output()?;
        let diagnostic = format!(
            "default migration state: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.status.success(), "{diagnostic}");
        Ok(())
    }

    #[test]
    fn transport_inheritance_action_contains_failures_and_preserves_file_identity() -> Result<()> {
        use crate::core::testing::run_isolated_test;
        if run_isolated_test(
            "cli::packages::update::omarchy::tests::transport_inheritance_action_contains_failures_and_preserves_file_identity",
        ) {
            return Ok(());
        }
        let owner = private_directory();
        let lock = open_owned_file(&owner.path().join("lock"))?;
        let log = open_owned_file(&owner.path().join("log"))?;
        let lock_identity = lock.metadata()?.ino();
        let log_identity = log.metadata()?.ino();
        let mut expose = transport_inheritance_action(lock.as_raw_fd(), log.as_raw_fd());
        expose()?;
        for file in [&lock, &log] {
            assert!(
                !FdFlag::from_bits_truncate(fcntl(file, FcntlArg::F_GETFD)?)
                    .contains(FdFlag::FD_CLOEXEC)
            );
            set_descriptor_inheritance(file.as_raw_fd(), false)?;
        }
        assert_eq!(lock.metadata()?.ino(), lock_identity);
        assert_eq!(log.metadata()?.ino(), log_identity);
        for operation in [
            DescriptorOperation::ReadFlags,
            DescriptorOperation::WriteFlags(nix::libc::FD_CLOEXEC),
        ] {
            assert_eq!(
                descriptor_control(-1, operation)
                    .expect_err("invalid descriptor cannot be inspected or changed")
                    .raw_os_error(),
                Some(nix::libc::EBADF)
            );
        }
        for (lock_fd, log_fd) in [(-1, log.as_raw_fd()), (lock.as_raw_fd(), -1)] {
            let result = transport_inheritance_action(lock_fd, log_fd)();
            set_descriptor_inheritance(lock.as_raw_fd(), false)?;
            set_descriptor_inheritance(log.as_raw_fd(), false)?;
            assert_eq!(
                result
                    .expect_err("invalid transport descriptor refuses exec")
                    .raw_os_error(),
                Some(nix::libc::EBADF)
            );
        }
        Ok(())
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
        let mut commands = Commands::new(false, transport_runtime());
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
        let mut commands = Commands::new(false, transport_runtime());
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
        let mut commands = Commands::new(false, transport_runtime());
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
        let mut commands = Commands::new(false, transport_runtime());
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
        let (master, slave) = open_transport_pty(None).expect("private PTY pair");
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
            .stdin(Stdio::from(slave))
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
        drop(master);
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
            assert_send(execute_logged(
                &env,
                &arguments,
                &lock,
                &log,
                &transport_runtime(),
            )),
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
            &transport_runtime(),
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
        let (master, slave) = open_transport_pty(None).expect("private outer terminal");
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
            .stdin(Stdio::from(slave))
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
        drop(master);
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
            &transport_runtime(),
        )
        .await
        .expect("PTY hangup fixture completes graceful cleanup");
        let transcript = std::fs::read_to_string(owner.path().join("log")).expect("PTY transcript");
        assert!(transcript.contains("1 passed"), "{transcript}");
    }

    #[tokio::test]
    async fn completed_coordinator_waits_for_terminal_eof() {
        use std::io::Write;
        struct ReapChild(std::process::Child);
        impl Drop for ReapChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let owner = private_directory();
        let transcript = open_owned_file(&owner.path().join("transcript"))
            .expect("private pending-tail transcript");
        let (master, slave) = open_transport_pty(None).expect("private pending-tail PTY");
        let sleep =
            crate::core::privilege::root_controlled_program_path("sleep").expect("system sleeper");
        let mut unrelated = ReapChild(
            std::process::Command::new(sleep)
                .arg("30")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("owned unrelated child"),
        );
        fcntl(&master, FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK))
            .expect("nonblocking pending-tail master");
        let master = register_file(master).expect("owned pending-tail master");
        let mut slave = slave;
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
        assert!(
            unrelated
                .0
                .try_wait()
                .expect("unrelated child state")
                .is_none(),
            "terminal EOF must not depend on unrelated child termination"
        );
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
            let (master, slave) = open_transport_pty(None).expect("private tail PTY");
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
                .stdout(Stdio::from(slave));
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
    async fn parent_coordination_descriptors_stay_close_on_exec_during_launch() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Barrier};

        let owner = private_directory();
        let lock = Arc::new(open_owned_file(&owner.path().join("lock")).expect("private lease"));
        lock.try_lock().expect("exclusive fixture lease");
        let log = Arc::new(open_owned_file(&owner.path().join("log")).expect("private transcript"));
        let program =
            crate::core::privilege::root_controlled_program_path("sh").expect("system shell");
        for file in [&lock, &log] {
            assert!(
                FdFlag::from_bits_truncate(
                    fcntl(file.as_ref(), FcntlArg::F_GETFD).expect("initial coordination flags")
                )
                .contains(FdFlag::FD_CLOEXEC),
                "parent coordination descriptors start close-on-exec"
            );
        }

        let ready = Arc::new(Barrier::new(2));
        let done = Arc::new(AtomicBool::new(false));
        let observer = {
            let lock = Arc::clone(&lock);
            let log = Arc::clone(&log);
            let ready = Arc::clone(&ready);
            let done = Arc::clone(&done);
            std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + Duration::from_secs(20);
                let mut samples = 0_u64;
                let mut inherited = [0_u64; 2];
                let mut inspection_error = None;
                loop {
                    for (index, file) in [&lock, &log].into_iter().enumerate() {
                        match fcntl(file.as_ref(), FcntlArg::F_GETFD) {
                            Ok(flags) => {
                                if !FdFlag::from_bits_truncate(flags).contains(FdFlag::FD_CLOEXEC) {
                                    inherited[index] += 1;
                                }
                            }
                            Err(error) => {
                                inspection_error.get_or_insert((index, error));
                            }
                        }
                    }
                    samples += 1;
                    if samples == 1 {
                        ready.wait();
                    }
                    if done.load(Ordering::Acquire) {
                        return (samples, inherited, inspection_error, false);
                    }
                    if std::time::Instant::now() >= deadline {
                        return (samples, inherited, inspection_error, true);
                    }
                }
            })
        };
        ready.wait();
        let mut launches = 0;
        let result = tokio::time::timeout(Duration::from_secs(10), async {
            for _ in 0..32 {
                execute_logged(
                    &program,
                    &[
                        "-c",
                        "test -t 0 && test -t 1 && test -f \"/proc/self/fd/$OMG_OMARCHY_LOCK_FD\" && test -f \"/proc/self/fd/$OMG_OMARCHY_LOG_FD\"",
                    ],
                    &lock,
                    &log, &transport_runtime())
                .await?;
                launches += 1;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await;
        done.store(true, Ordering::Release);
        let observation = observer.join();

        let (samples, inherited, inspection_error, expired) =
            observation.expect("descriptor observer joins before checking launch results");
        assert!(
            !expired,
            "descriptor observer exceeded its independent deadline"
        );
        assert_eq!(
            inspection_error, None,
            "owned descriptors remain inspectable"
        );
        assert!(
            samples > 1,
            "observer sampled both descriptors during launches"
        );
        result
            .expect("inert transport launches finish within ten seconds")
            .expect("child receives both genuine coordination descriptors");
        assert_eq!(launches, 32, "every real transport launch completes");
        assert_eq!(
            inherited,
            [0, 0],
            "parent lock/log became inheritable in {inherited:?} of {samples} observations; concurrent exec could retain the update lease or transcript"
        );
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
            &transport_runtime(),
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
            &transport_runtime(),
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
        let mut commands = Commands::new(false, transport_runtime());
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
            &transport_runtime(),
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

    #[test]
    fn cleanup_composition_preserves_values_and_primary_os_cause() {
        assert_eq!(
            finish_cleanup(Ok(17), Ok(())).expect("successful operation"),
            17
        );
        let cleanup = finish_cleanup(Ok(17), Err(anyhow::anyhow!("lease release failed")))
            .expect_err("cleanup failure prevents success");
        assert!(format!("{cleanup:#}").contains("lease release failed"));
        for cleanup in [Ok(()), Err(anyhow::anyhow!("terminal restoration failed"))] {
            let failed_cleanup = cleanup.is_err();
            let primary: Result<usize> =
                Err(std::io::Error::from_raw_os_error(nix::libc::ECHILD).into());
            let error = finish_cleanup(primary, cleanup).expect_err("primary wait failed");
            assert_eq!(
                error
                    .downcast_ref::<std::io::Error>()
                    .expect("original OS error remains the cause")
                    .raw_os_error(),
                Some(nix::libc::ECHILD)
            );
            assert_eq!(
                format!("{error:#}").contains("terminal restoration failed"),
                failed_cleanup
            );
        }
    }

    #[test]
    fn inherited_transport_startup_fixture() {
        let Some(mode) = std::env::var_os("OMG_OMARCHY_CONTAIN_FIXTURE") else {
            return;
        };
        let mode = mode.to_str().expect("fixture mode");
        let command = if mode == "other" { "status" } else { "update" };
        let args = vec!["omg".to_owned(), command.to_owned()];
        let result = contain_inherited_transport(&args);
        if matches!(mode, "valid" | "absent" | "other") {
            result.expect("valid transport or unrelated command is admitted");
        } else {
            result.expect_err("malformed transport is refused before initialization");
            return;
        }
        if mode != "valid" {
            return;
        }
        contain_inherited_transport(&args).expect("containment is idempotent");
        let lock = std::env::var(LOCK_FD).expect("fixture lock descriptor");
        let log = std::env::var(LOG_FD).expect("fixture log descriptor");
        for raw in [&lock, &log] {
            let raw = transport_descriptor(raw).expect("fixture descriptor");
            // SAFETY: F_GETFD observes the inherited integer without adopting ownership.
            #[expect(unsafe_code, reason = "observe isolated startup descriptor flags")]
            let flags = unsafe { nix::libc::fcntl(raw, nix::libc::F_GETFD) };
            assert!(
                flags >= 0 && flags & nix::libc::FD_CLOEXEC != 0,
                "transport is contained before any helper exec"
            );
        }
        let program =
            crate::core::privilege::root_controlled_program_path("sh").expect("system shell");
        let status = std::process::Command::new(program)
            .args([
                "-c",
                "test ! /proc/self/fd/$1 -ef \"$2\" && test ! /proc/self/fd/$3 -ef \"$4\"",
                "fixture",
                &lock,
                &std::env::var("OMG_OMARCHY_CONTAIN_LOCK_PATH").expect("fixture lock path"),
                &log,
                &std::env::var("OMG_OMARCHY_CONTAIN_LOG_PATH").expect("fixture log path"),
            ])
            .status()
            .expect("unrelated real helper runs");
        assert!(
            status.success(),
            "unrelated exec cannot retain either transport inode"
        );
    }

    #[tokio::test]
    async fn startup_contains_only_complete_canonical_update_transports() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let owner = private_directory();
        let lock_path = owner.path().join("startup-lock");
        let log_path = owner.path().join("startup-log");
        let lock = open_owned_file(&lock_path)
            .expect("private startup lock")
            .try_clone()
            .expect("lock above stdio");
        let log = open_owned_file(&log_path)
            .expect("private startup log")
            .try_clone()
            .expect("log above stdio");
        let lock_fd = lock.as_raw_fd();
        let log_fd = log.as_raw_fd();
        for mode in [
            "valid",
            "absent",
            "other",
            "missing-lock",
            "missing-log",
            "malformed",
            "negative",
            "overflow",
            "stdio",
            "overlap",
            "encoding",
            "closed",
        ] {
            let mut command = Command::new(std::env::current_exe().expect("test executable"));
            command
                .args([
                    "--exact",
                    "cli::packages::update::omarchy::tests::inherited_transport_startup_fixture",
                    "--nocapture",
                ])
                .env("OMG_OMARCHY_CONTAIN_FIXTURE", mode)
                .env("OMG_OMARCHY_CONTAIN_LOCK_PATH", &lock_path)
                .env("OMG_OMARCHY_CONTAIN_LOG_PATH", &log_path)
                .env_remove(LOCK_FD)
                .env_remove(LOG_FD)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            if mode != "absent" {
                if mode != "missing-lock" {
                    let value = match mode {
                        "other" | "malformed" => OsString::from("invalid"),
                        "negative" => OsString::from("-3"),
                        "overflow" => OsString::from("2147483648"),
                        "stdio" => OsString::from("0"),
                        "encoding" => OsString::from_vec(vec![0xff]),
                        "closed" => OsString::from(i32::MAX.to_string()),
                        _ => OsString::from(lock_fd.to_string()),
                    };
                    command.env(LOCK_FD, value);
                }
                if mode != "missing-log" && mode != "other" {
                    command.env(
                        LOG_FD,
                        if mode == "overlap" {
                            format!("0{lock_fd}")
                        } else {
                            log_fd.to_string()
                        },
                    );
                }
            }
            // SAFETY: the closure only changes flags in this isolated fork. The
            // parent retains both Files until output has spawned and reaped it.
            #[expect(
                unsafe_code,
                reason = "pass real descriptors to isolated startup fixture"
            )]
            unsafe {
                command.pre_exec(transport_inheritance_action(lock_fd, log_fd));
            }
            let output = tokio::time::timeout(Duration::from_secs(10), command.output())
                .await
                .expect("startup fixture finishes within its deadline")
                .expect("startup fixture output");
            assert!(
                output.status.success(),
                "{mode}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        for file in [&lock, &log] {
            assert!(
                FdFlag::from_bits_truncate(
                    fcntl(file, FcntlArg::F_GETFD).expect("parent descriptor remains open")
                )
                .contains(FdFlag::FD_CLOEXEC),
                "child handoff never changes parent's descriptor flags"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn atomic_transport_pty_retains_terminal_attributes() {
        let (_source_master, source) = open_transport_pty(None).expect("initial private terminal");
        let mut saved = nix::sys::termios::tcgetattr(&source).expect("original terminal settings");
        saved
            .local_flags
            .remove(nix::sys::termios::LocalFlags::ECHO);
        let (master, slave) =
            open_transport_pty(Some(&saved)).expect("configured private terminal");
        for file in [&master, &slave] {
            assert!(
                FdFlag::from_bits_truncate(
                    fcntl(file, FcntlArg::F_GETFD).expect("terminal descriptor flags")
                )
                .contains(FdFlag::FD_CLOEXEC),
                "terminal starts close-on-exec"
            );
        }
        assert_eq!(
            nix::sys::termios::tcgetattr(&slave).expect("configured terminal attributes"),
            saved,
            "new slave receives saved terminal settings"
        );
    }

    #[tokio::test]
    async fn runtime_environment_fixture() -> Result<()> {
        let Some(mode) = std::env::var_os("OMG_OMARCHY_RUNTIME_ENV_FIXTURE") else {
            return Ok(());
        };
        let directory = std::env::current_dir()?;
        let observed = directory.join("observed-environment");
        let shell = crate::core::privilege::root_controlled_program_path("sh")?;
        let runtime = OmarchyRuntime {
            root: PathBuf::from("/usr/share/omarchy"),
            migration_state: OmarchyRuntime::migration_state()?,
        };
        let args = [
            "-c",
            "printf '%s\\n%s\\n' \"$OMARCHY_PATH\" \"$OMARCHY_MIGRATION_STATE\" > \"$1\"",
            "runtime-fixture",
            observed
                .to_str()
                .context("private runtime observation path is UTF8")?,
        ];
        if mode == "stage" {
            let mut commands = Commands::new(false, runtime.clone());
            let status =
                tokio::time::timeout(Duration::from_secs(10), commands.run_program(&shell, &args))
                    .await
                    .context("inert stage environment observation timed out")??;
            anyhow::ensure!(status.success(), "inert stage observation failed");
        } else {
            anyhow::ensure!(mode == "coordinator", "unknown runtime environment fixture");
            let lock = open_owned_file(&directory.join("lock"))?;
            lock.try_lock()?;
            let log = open_owned_file(&directory.join("log"))?;
            tokio::time::timeout(
                Duration::from_secs(10),
                execute_logged(&shell, &args, &lock, &log, &runtime),
            )
            .await
            .context("inert coordinator environment observation timed out")??;
        }
        assert_eq!(
            std::fs::read_to_string(observed)?,
            format!(
                "/usr/share/omarchy\n{}\n",
                directory.join("markers").display()
            ),
            "selected installed runtime and resolved migration state must reach the actual child instead of caller checkout/relative environment"
        );
        Ok(())
    }

    fn check_runtime_environment(mode: &str) {
        use std::os::unix::fs::PermissionsExt;
        let owner = private_directory();
        let checkout = owner.path().join("caller-checkout");
        std::fs::create_dir_all(checkout.join("bin")).expect("private caller checkout");
        std::fs::create_dir(owner.path().join("markers")).expect("private migration markers");
        let sentinel = checkout.join("bin/omarchy-migrate");
        std::fs::write(
            &sentinel,
            "#!/bin/sh\nprintf executed > \"$OMARCHY_PATH/executed\"\nexit 88\n",
        )
        .expect("caller checkout executable sentinel");
        std::fs::set_permissions(&sentinel, std::fs::Permissions::from_mode(0o700))
            .expect("caller sentinel mode");
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "cli::packages::update::omarchy::tests::runtime_environment_fixture",
                "--nocapture",
                "--test-threads=1",
            ])
            .current_dir(owner.path())
            .env("OMG_OMARCHY_RUNTIME_ENV_FIXTURE", mode)
            .env("OMARCHY_PATH", &checkout)
            .env("OMARCHY_MIGRATION_STATE", "markers")
            .stdin(Stdio::null())
            .output()
            .expect("isolated inert runtime observation");
        assert!(
            !checkout.join("executed").exists(),
            "caller checkout executable must never run"
        );
        assert!(
            output.status.success(),
            "{mode} runtime environment observation failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn stage_children_receive_selected_runtime_instead_of_caller_checkout() {
        check_runtime_environment("stage");
    }

    #[test]
    fn coordinator_child_receives_selected_runtime_instead_of_caller_checkout() {
        check_runtime_environment("coordinator");
    }

    #[test]
    fn runtime_layout_binds_packaged_and_trusted_checkout_helpers_without_mixing_roots() {
        let packaged = OmarchyRuntime::root_for_migrate(Path::new("/usr/bin/omarchy-migrate"))
            .expect("packaged migration layout");
        assert_eq!(packaged, Path::new("/usr/share/omarchy"));
        let runtime = OmarchyRuntime {
            root: packaged,
            migration_state: PathBuf::from("/private/markers"),
        };
        runtime
            .check_helper_layout(
                "omarchy-update-stay-awake",
                Path::new("/usr/bin/omarchy-update-stay-awake"),
            )
            .expect("packaged protected helper layout");
        assert!(
            runtime
                .check_helper_layout(
                    "omarchy-update-stay-awake",
                    Path::new("/opt/other/bin/omarchy-update-stay-awake")
                )
                .is_err()
        );
        let checkout =
            OmarchyRuntime::root_for_migrate(Path::new("/opt/trusted-omarchy/bin/omarchy-migrate"))
                .expect("trusted selected executable can define its own checkout layout");
        assert_eq!(checkout, Path::new("/opt/trusted-omarchy"));
        let runtime = OmarchyRuntime {
            root: checkout,
            migration_state: PathBuf::from("/private/markers"),
        };
        runtime
            .check_helper_layout(
                "omarchy-update-stay-awake",
                Path::new("/opt/trusted-omarchy/bin/omarchy-update-stay-awake"),
            )
            .expect("same selected checkout layout");
        assert!(
            runtime
                .check_helper_layout(
                    "omarchy-update-stay-awake",
                    Path::new("/usr/bin/omarchy-update-stay-awake")
                )
                .is_err()
        );
        for invalid in [
            "omarchy-migrate",
            "/opt/omarchy/tools/omarchy-migrate",
            "/opt/omarchy/bin/other",
        ] {
            assert!(
                OmarchyRuntime::root_for_migrate(Path::new(invalid)).is_err(),
                "{invalid}"
            );
        }
        let private = private_directory();
        assert!(
            OmarchyRuntime::validate_root_directory(private.path()).is_err(),
            "a user-writable ancestor cannot become a trusted runtime root"
        );
    }

    #[tokio::test]
    async fn selected_migration_runtime_fixture() -> Result<()> {
        let Some(selected) = std::env::var_os("OMG_OMARCHY_SELECTED_RUNTIME_FIXTURE") else {
            return Ok(());
        };
        if let Ok(variable) = std::env::var("OMG_OMARCHY_EMPTY_VARIABLE_FIXTURE") {
            let error = OmarchyRuntime::discover()
                .expect_err("explicit empty runtime variables refuse before helper discovery");
            assert!(
                error.to_string().contains(&variable) && error.to_string().contains("non-empty"),
                "{error:#}"
            );
            return Ok(());
        }
        let selected = PathBuf::from(selected);
        let runtime = OmarchyRuntime {
            root: selected.clone(),
            migration_state: OmarchyRuntime::migration_state()?,
        };
        assert_eq!(
            runtime.migration_state,
            std::env::current_dir()?.join("markers")
        );
        let mut commands = Commands::new(false, runtime);
        if std::env::var_os("OMG_OMARCHY_SELECTED_FORBIDDEN_FIXTURE").is_some() {
            let error = commands
                .runtime
                .check_pending_migrations()
                .expect_err("selected runtime external AUR migration must refuse");
            assert!(
                error.to_string().contains("external package helper"),
                "{error:#}"
            );
            std::fs::write(
                commands.runtime.migration_state.join("0001.sh"),
                b"complete",
            )?;
            commands.runtime.check_pending_migrations()?;
        } else {
            commands.runtime.check_pending_migrations()?;
        }
        let shell = crate::core::privilege::root_controlled_program_path("sh")?;
        let output = std::env::current_dir()?.join("selected-runtime-observed");
        let status = commands
            .run_program(
                &shell,
                &[
                    "-c",
                    "printf '%s' \"$OMARCHY_PATH\" > \"$1\"",
                    "runtime-fixture",
                    output.to_str().context("private output UTF8")?,
                ],
            )
            .await?;
        assert!(status.success());
        assert_eq!(
            std::fs::read_to_string(output)?,
            selected.to_str().context("selected root UTF8")?
        );
        Ok(())
    }

    #[test]
    fn selected_runtime_migrations_are_scanned_instead_of_the_caller_checkout() {
        for (selected_forbidden, empty) in [
            (false, None),
            (true, None),
            (false, Some("OMARCHY_PATH")),
            (false, Some("OMARCHY_MIGRATION_STATE")),
        ] {
            let owner = private_directory();
            let selected = owner.path().join("selected-runtime");
            let caller = owner.path().join("caller-checkout");
            for path in [
                selected.join("migrations"),
                caller.join("migrations"),
                caller.join("bin"),
                owner.path().join("markers"),
            ] {
                std::fs::create_dir_all(path).expect("private split-runtime directory");
            }
            let (selected_text, caller_text) = if selected_forbidden {
                (
                    "omarchy-pkg-aur-add forbidden-fixture\n",
                    "echo inert migration\n",
                )
            } else {
                (
                    "echo inert migration\n",
                    "omarchy-pkg-aur-add forbidden-caller-fixture\n",
                )
            };
            std::fs::write(selected.join("migrations/0001.sh"), selected_text)
                .expect("selected runtime migration");
            std::fs::write(caller.join("migrations/0001.sh"), caller_text)
                .expect("caller migration");
            std::fs::write(
                caller.join("bin/omarchy-migrate"),
                "#!/bin/sh\nprintf executed > \"$OMARCHY_PATH/executed\"\nexit 88\n",
            )
            .expect("caller executable sentinel");
            let mut command =
                std::process::Command::new(std::env::current_exe().expect("test executable"));
            command
                .args([
                    "--exact",
                    "cli::packages::update::omarchy::tests::selected_migration_runtime_fixture",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .current_dir(owner.path())
                .env("OMG_OMARCHY_SELECTED_RUNTIME_FIXTURE", &selected)
                .env("OMARCHY_PATH", &caller)
                .env("OMARCHY_MIGRATION_STATE", "markers")
                .env_remove("OMG_OMARCHY_SELECTED_FORBIDDEN_FIXTURE")
                .env_remove("OMG_OMARCHY_EMPTY_VARIABLE_FIXTURE");
            if selected_forbidden {
                command.env("OMG_OMARCHY_SELECTED_FORBIDDEN_FIXTURE", "1");
            }
            if let Some(variable) = empty {
                command
                    .env("OMG_OMARCHY_EMPTY_VARIABLE_FIXTURE", variable)
                    .env(variable, "");
            }
            let output = command
                .output()
                .expect("isolated split-runtime migration data check");
            assert!(
                output.status.success(),
                "selected_forbidden={selected_forbidden}, empty={empty:?}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                !caller.join("executed").exists(),
                "caller checkout program must never execute"
            );
        }
    }
}
