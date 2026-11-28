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
const ATTENDED_ENV: &str = "OMG_OMARCHY_ATTENDED";
const AUTHORIZATION_INTERVAL: Duration = Duration::from_mins(1);
const TERMINATION_GRACE: Duration = Duration::from_secs(10);
const DEVELOPMENT_UPDATE_DEADLINE: Duration = Duration::from_mins(2);
const MAX_MIGRATIONS: usize = 4096;
const MAX_MIGRATION_BYTES: u64 = 1024 * 1024;
const OMARCHY_DEV_CONFIG: &str = "/etc/omarchy.conf";
const MAX_DEV_CONFIG_BYTES: u64 = 4096;
const MIN_UPDATE_FREE_BYTES: u128 = 10 * 1024 * 1024 * 1024;
const INCOMPLETE_UPDATE_SCOPE: &str = "Omarchy requires its complete update lifecycle; --fast, --turbo and mutating --no-sync cannot preserve that scope. Use omg update, or --check/--dry-run/--aur-only for a scoped operation.";

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
        _ => anyhow::bail!(INCOMPLETE_UPDATE_SCOPE),
    }
}

fn require_native_scope(flavor: ArchFlavor) -> Result<()> {
    anyhow::ensure!(flavor == ArchFlavor::Arch, INCOMPLETE_UPDATE_SCOPE);
    Ok(())
}

pub(super) fn ensure_native_update_scope() -> Result<()> {
    require_native_scope(update_flavor()?)
}

fn update_flavor() -> Result<ArchFlavor> {
    if cfg!(test) || crate::core::paths::test_mode() || crate::cli::packages::mock_arch_backend()? {
        return Ok(ArchFlavor::Arch);
    }
    Ok(if crate::core::env::distro::is_omarchy() {
        ArchFlavor::Omarchy
    } else {
        ArchFlavor::Arch
    })
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
        if let Err(error) = executor
            .execute(Stage::NativePackage(NativeOmarchyOperation::PruneCache))
            .await
        {
            crate::cli::modern_ui::print_warning(&format!(
                "Continuing the Omarchy update without pruning the package cache: {error:#}"
            ));
        }
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
        #[expect(
            clippy::match_same_arms,
            reason = "keep native preflight/confirm distinct from package stages"
        )]
        Stage::Preflight | Stage::Confirm => return None,
        Stage::NativePackage(_)
        | Stage::MigrationPreflight
        | Stage::NativeAur
        | Stage::ReleaseAuthorization
        | Stage::RebootPrompt => return None,
    })
}

fn check_free_space_bytes(available_bytes: u128, force: bool) -> Result<()> {
    if force || available_bytes >= MIN_UPDATE_FREE_BYTES {
        return Ok(());
    }
    let available_gib = available_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
    anyhow::bail!(
        "At least 10 GiB of free space is required on / before updating ({available_gib:.2} GiB available). Free up space or set OMARCHY_UPDATE_FORCE=1 to bypass this check."
    );
}

const fn statvfs_unit_size(fragment_size: u64, block_size: u64) -> u64 {
    if fragment_size > 0 {
        fragment_size
    } else {
        block_size
    }
}

fn native_preflight_free_space() -> Result<()> {
    if std::env::var("OMARCHY_UPDATE_FORCE").as_deref() == Ok("1") {
        return Ok(());
    }
    let stat =
        nix::sys::statvfs::statvfs("/").context("Failed to check available disk space on /")?;
    let unit = statvfs_unit_size(stat.fragment_size(), stat.block_size());
    let available = u128::from(stat.blocks_available()) * u128::from(unit);
    check_free_space_bytes(available, false)
}

fn coordinator_attended_from(value: Option<&std::ffi::OsStr>, fallback: bool) -> bool {
    match value.and_then(|value| value.to_str()) {
        Some("1") => true,
        Some("0") => false,
        _ => fallback,
    }
}

fn confirm_outcome(accepted: bool) -> Outcome {
    if accepted {
        Outcome::Success
    } else {
        println!("Update cancelled.");
        Outcome::Declined
    }
}

fn native_confirm_update(attended: bool) -> Result<Outcome> {
    println!("Ready to update?");
    println!("  • You cannot stop the update once you start!");
    println!("  • Make sure you're connected to power or have a full battery");
    println!("  What's new: https://github.com/omacom/omarchy/releases/latest\n");
    if !attended {
        println!(
            "Update cancelled (non-interactive terminal; pass -y to proceed without confirmation)."
        );
        return Ok(Outcome::Declined);
    }
    let _quiesce = crate::cli::modern_ui::quiesce_terminal();
    let accepted = dialoguer::Confirm::with_theme(&crate::cli::ui::prompt_theme())
        .with_prompt("Start system update?")
        .default(true)
        .interact()?;
    Ok(confirm_outcome(accepted))
}

#[derive(Clone, Debug)]
struct OmarchyRuntime {
    root: PathBuf,
    migration_state: PathBuf,
}

fn parse_configured_omarchy_root(contents: &str) -> Result<PathBuf> {
    let literal = contents
        .trim_end_matches('\n')
        .strip_prefix("export OMARCHY_PATH=\"")
        .and_then(|value| value.strip_suffix('"'))
        .context("Invalid Omarchy dev-link configuration")?;
    let mut decoded = String::with_capacity(literal.len());
    let mut chars = literal.chars();
    while let Some(character) = chars.next() {
        match character {
            '\\' => {
                let escaped = chars
                    .next()
                    .filter(|character| matches!(character, '\\' | '"' | '$' | '`'))
                    .context("Invalid Omarchy dev-link escape")?;
                decoded.push(escaped);
            }
            '"' | '$' | '`' => anyhow::bail!("Omarchy dev-link path must be literal"),
            character if character.is_control() => {
                anyhow::bail!("Invalid character in Omarchy dev-link path")
            }
            character => decoded.push(character),
        }
    }
    let path = PathBuf::from(decoded);
    anyhow::ensure!(path.is_absolute(), "Omarchy dev-link path must be absolute");
    Ok(path)
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

    fn development_root(&self) -> Result<PathBuf> {
        use std::io::Read;

        let config = match File::options()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(OMARCHY_DEV_CONFIG)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(self.root.clone());
            }
            Err(error) => return Err(error).context("Cannot open Omarchy dev-link configuration"),
        };
        let metadata = config.metadata()?;
        anyhow::ensure!(
            metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
            "Omarchy dev-link configuration must be a root-controlled regular file"
        );
        let mut contents = String::new();
        config
            .take(MAX_DEV_CONFIG_BYTES + 1)
            .read_to_string(&mut contents)?;
        anyhow::ensure!(
            contents.len() as u64 <= MAX_DEV_CONFIG_BYTES,
            "Omarchy dev-link configuration exceeds its size limit"
        );
        let checkout = parse_configured_omarchy_root(&contents)?;
        if checkout == Path::new("/usr/share/omarchy") || checkout == self.root {
            return Ok(self.root.clone());
        }
        anyhow::ensure!(
            std::fs::canonicalize(&checkout).context("Cannot resolve Omarchy dev checkout")?
                == checkout
                && checkout.is_dir(),
            "Omarchy dev checkout must be a canonical directory"
        );
        Ok(checkout)
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
    attended: bool,
    runtime: OmarchyRuntime,
    authorization: Option<tokio::task::JoinHandle<()>>,
    inhibitor_attempted: bool,
    active: Option<tokio::process::Child>,
    foreground: Option<nix::unistd::Pid>,
    #[cfg(test)]
    native_fixture: Option<NativeMigrationFixture>,
    #[cfg(test)]
    migration_overrides: Option<MigrationTestOverrides>,
}

impl Drop for Commands {
    fn drop(&mut self) {
        if let Some(task) = self.authorization.take() {
            task.abort();
        }
        if let Some(group) = self.foreground.take() {
            let _ = set_foreground(group);
        }
    }
}

#[cfg(test)]
struct NativeMigrationFixture {
    operations: Vec<NativeOmarchyOperation>,
    failure: Option<NativeOmarchyOperation>,
    desktop_database_program: &'static str,
}

#[cfg(test)]
#[derive(Default)]
struct MigrationTestOverrides {
    helper_overrides: std::collections::BTreeMap<&'static str, PathBuf>,
    absent_optional_helpers: std::collections::BTreeSet<&'static str>,
    installed_packages: Option<std::collections::BTreeSet<&'static str>>,
    sudo_program: Option<PathBuf>,
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
            attended: false,
            runtime,
            authorization: None,
            inhibitor_attempted: false,
            active: None,
            foreground: None,
            #[cfg(test)]
            migration_overrides: None,
            #[cfg(test)]
            native_fixture: None,
        }
    }

    async fn run_program(&mut self, program: &Path, args: &[&str]) -> Result<ExitStatus> {
        self.run_program_at(program, args, self.runtime.root.clone())
            .await
    }

    const fn with_attended(mut self, attended: bool) -> Self {
        self.attended = attended;
        self
    }

    async fn run_development_checkout(
        &mut self,
        program: &Path,
        args: &[&str],
        checkout: PathBuf,
        deadline: Duration,
    ) -> Result<ExitStatus> {
        let Ok(result) =
            tokio::time::timeout(deadline, self.run_program_at(program, args, checkout)).await
        else {
            let cleanup = self.stop_active().await;
            return finish_cleanup(
                Err(anyhow::anyhow!(
                    "Omarchy dev checkout update timed out after {} seconds. Check GitHub connectivity and checkout credentials before retrying.",
                    deadline.as_secs()
                )),
                cleanup,
            );
        };
        result
    }

    fn build_program_command(
        &self,
        program: &Path,
        args: &[&str],
        omarchy_root: &Path,
    ) -> Result<Command> {
        let path = std::env::join_paths(
            std::iter::once(self.runtime.root.join("bin"))
                .chain(std::env::split_paths(crate::core::privilege::SYSTEM_PATH)),
        )
        .context("Cannot build the selected Omarchy runtime's command path")?;
        let mut command = Command::new(program);
        command
            .args(args)
            .kill_on_drop(true)
            .env("PATH", path)
            .env_remove("BASH_ENV")
            .env_remove("ENV")
            .env("OMARCHY_PATH", omarchy_root)
            .env("OMARCHY_MIGRATION_STATE", &self.runtime.migration_state)
            .env_remove(LOCK_FD)
            .env_remove(LOG_FD)
            .env_remove(ATTENDED_ENV);
        if self.yes {
            command.env("OMARCHY_UPDATE_UNATTENDED", "1");
        }
        Ok(command)
    }

    async fn run_program_at(
        &mut self,
        program: &Path,
        args: &[&str],
        omarchy_root: PathBuf,
    ) -> Result<ExitStatus> {
        anyhow::ensure!(self.active.is_none(), "An Omarchy stage is already running");
        let mut command = self.build_program_command(program, args, &omarchy_root)?;
        command.process_group(0);
        self.run_command(command, &program.display().to_string())
            .await
    }

    async fn capture_program_stdout(
        &self,
        program: &Path,
        args: &[&str],
    ) -> Result<std::process::Output> {
        let mut command = self.build_program_command(program, args, &self.runtime.root)?;
        command
            .output()
            .await
            .with_context(|| format!("Failed to run {}", program.display()))
    }

    #[cfg_attr(
        not(test),
        expect(
            clippy::unused_self,
            reason = "uses self.migration_overrides in unit tests"
        )
    )]
    fn sudo_command(&self) -> Result<Command> {
        #[cfg(test)]
        if let Some(program) = self
            .migration_overrides
            .as_ref()
            .and_then(|overrides| overrides.sudo_program.as_ref())
        {
            return Ok(Command::new(program));
        }
        crate::core::privilege::sudo_command()
    }

    fn resolve_migration_helper(&self, name: &str) -> Result<PathBuf> {
        #[cfg(test)]
        if let Some(path) = self
            .migration_overrides
            .as_ref()
            .and_then(|overrides| overrides.helper_overrides.get(name))
        {
            return Ok(path.clone());
        }
        let helper = crate::core::privilege::root_controlled_program_path(name)?;
        self.runtime.check_helper_layout(name, &helper)?;
        Ok(helper)
    }

    #[cfg_attr(
        not(test),
        expect(
            clippy::unused_self,
            reason = "uses self.migration_overrides in unit tests"
        )
    )]
    fn resolve_optional_helper(&self, name: &str) -> Option<PathBuf> {
        #[cfg(test)]
        if let Some(overrides) = self.migration_overrides.as_ref() {
            if overrides.absent_optional_helpers.contains(name) {
                return None;
            }
            if let Some(path) = overrides.helper_overrides.get(name) {
                return Some(path.clone());
            }
        }
        crate::core::privilege::root_controlled_program_path(name).ok()
    }

    #[cfg_attr(
        not(test),
        expect(
            clippy::unused_self,
            reason = "uses self.migration_overrides in unit tests"
        )
    )]
    fn is_package_installed(&self, name: &str) -> Result<bool> {
        #[cfg(test)]
        if let Some(packages) = self
            .migration_overrides
            .as_ref()
            .and_then(|overrides| overrides.installed_packages.as_ref())
        {
            return Ok(packages.contains(name));
        }
        crate::package_managers::is_installed_fast(name)
    }

    async fn run_sudo(&mut self, args: &[&str], error_context: &str) -> Result<()> {
        let mut command = self.sudo_command()?;
        command.args(args);
        let label = format!("sudo {}", args.join(" "));
        let status = self.run_command(command, &label).await?;
        anyhow::ensure!(status.success(), "{error_context}: {status}");
        Ok(())
    }

    async fn run_command(&mut self, mut command: Command, label: &str) -> Result<ExitStatus> {
        anyhow::ensure!(self.active.is_none(), "An Omarchy stage is already running");
        command.kill_on_drop(true).process_group(0);
        command
            .env_remove(LOCK_FD)
            .env_remove(LOG_FD)
            .env_remove(ATTENDED_ENV);
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

    async fn run_native_package(&mut self, operation: NativeOmarchyOperation) -> Result<()> {
        #[cfg(test)]
        let fixture_result = self.native_fixture.as_mut().map(|fixture| {
            fixture.operations.push(operation);
            anyhow::ensure!(
                fixture.failure != Some(operation),
                "Fixture package operation failed"
            );
            Ok(())
        });
        #[cfg(not(test))]
        let fixture_result = None;
        match fixture_result {
            Some(result) => result,
            None => self.run_native_package_command(operation).await,
        }
    }

    async fn run_native_package_command(
        &mut self,
        operation: NativeOmarchyOperation,
    ) -> Result<()> {
        use crate::package_managers::arch::NativeOmarchyInteraction;
        let interaction = if self.yes {
            NativeOmarchyInteraction::Unattended
        } else {
            NativeOmarchyInteraction::Attended
        };
        let command = crate::core::privilege::native_omarchy_command(operation, interaction)?;
        crate::package_managers::arch::finish_native_write(async {
            let status = self.run_command(command, operation.argument()).await?;
            anyhow::ensure!(
                status.success(),
                "Native Omarchy {operation:?} failed: {status}"
            );
            Ok(())
        })
        .await
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
            Stage::Preflight => {
                tokio::task::spawn_blocking(native_preflight_free_space)
                    .await
                    .context("Omarchy preflight check panicked")??;
                return Ok(Outcome::Success);
            }
            Stage::Confirm => {
                let attended = self.attended;
                return tokio::task::spawn_blocking(move || native_confirm_update(attended))
                    .await
                    .context("Omarchy confirmation prompt panicked")?;
            }
            Stage::NativePackage(operation) => {
                self.run_native_package(operation).await?;
                return Ok(Outcome::Success);
            }
            Stage::RebootPrompt => {
                if let Some(reason) = tokio::task::spawn_blocking(native_reboot_reason)
                    .await
                    .context("Omarchy reboot check panicked")??
                {
                    if self.yes || !self.attended {
                        println!("{reason} Run omarchy-system reboot when ready.");
                    } else {
                        let confirmed = tokio::task::spawn_blocking(move || -> Result<bool> {
                            let _quiesce = crate::cli::modern_ui::quiesce_terminal();
                            Ok(
                                dialoguer::Confirm::with_theme(&crate::cli::ui::prompt_theme())
                                    .with_prompt(format!("{reason} Reboot now?"))
                                    .default(false)
                                    .interact()?,
                            )
                        })
                        .await
                        .context("Omarchy reboot prompt panicked")??;
                        if confirmed {
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
            Stage::Migrations => {
                let plan = pending_migrations(
                    &self.runtime.root.join("migrations"),
                    &self.runtime.migration_state,
                )?;
                if plan.iter().any(|migration| migration.native.is_some()) {
                    let state = self.runtime.migration_state.clone();
                    run_migration_plan(&plan, &state, self).await?;
                    if let Ok(helper) = crate::core::privilege::root_controlled_program_path(
                        "omarchy-notification-dismiss",
                    ) {
                        self.runtime
                            .check_helper_layout("omarchy-notification-dismiss", &helper)?;
                        if let Err(error) = self.run_program(&helper, &["Omarchy Migrations"]).await
                        {
                            tracing::warn!(
                                "Cannot dismiss the Omarchy migration notification: {error:#}"
                            );
                        }
                    }
                    return Ok(Outcome::Success);
                }
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
        let status = if stage == Stage::DevelopmentCheckout {
            // The vendor helper only fast-forwards Git. Its command lookup and
            // every other stage keep using the packaged runtime.
            let checkout = self.runtime.development_root()?;
            self.run_development_checkout(&executable, args, checkout, DEVELOPMENT_UPDATE_DEADLINE)
                .await?
        } else {
            self.run_program(&executable, args).await?
        };
        if stage == Stage::ReleaseInhibitor && status.success() {
            self.inhibitor_attempted = false;
        }
        if status.success() {
            if stage == Stage::Authorize {
                if let Some(previous) = self.authorization.take() {
                    previous.abort();
                }
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
        stage_exit_outcome(stage, status, program)
    }
}

fn stage_exit_outcome(stage: Stage, status: ExitStatus, program: &str) -> Result<Outcome> {
    if stage == Stage::MigrationsPending && status.code() == Some(1) {
        return Ok(Outcome::Declined);
    }
    if stage == Stage::Snapshot && status.code() == Some(127) {
        return Ok(Outcome::Unavailable);
    }
    anyhow::bail!("Omarchy stage {program} did not complete: {status}")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeMigration {
    TrayMenuDependency,
    OmnibookAudio,
    MediaViewer,
    SkipQualcommHardware,
    FacetimeHdCamera,
    PiCodingAgent,
    Kmscon,
    PodmanAndCrun,
}

#[derive(Debug)]
struct PendingMigration {
    path: PathBuf,
    digest: [u8; 32],
    native: Option<NativeMigration>,
}

fn read_migration(path: &Path) -> Result<String> {
    use std::io::Read;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("Cannot inspect Omarchy migration {}", path.display()))?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= MAX_MIGRATION_BYTES,
        "Invalid or oversized Omarchy migration {}",
        path.display()
    );
    let mut contents = String::new();
    file.take(MAX_MIGRATION_BYTES + 1)
        .read_to_string(&mut contents)?;
    anyhow::ensure!(
        contents.len() as u64 <= MAX_MIGRATION_BYTES,
        "Omarchy migration grew beyond its limit"
    );
    Ok(contents)
}

fn migration_digest(contents: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(contents.as_bytes()).into()
}

fn qualcomm_migration_for_machine(
    machine: &std::ffi::OsStr,
    path: &Path,
) -> Result<NativeMigration> {
    anyhow::ensure!(
        machine == "x86_64",
        "Omarchy hardware migration {} requires a native ARM equivalent",
        path.display()
    );
    Ok(NativeMigration::SkipQualcommHardware)
}

fn pending_migrations(migrations: &Path, state: &Path) -> Result<Vec<PendingMigration>> {
    let entries = match std::fs::read_dir(migrations) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).context("Cannot inspect pending Omarchy migrations"),
    };
    let mut pending = Vec::new();
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
        let contents = read_migration(&path)?;
        let digest = migration_digest(&contents);
        // Each equivalent replaces the entire published script, including its guards.
        let native = match (name.to_str(), hex::encode(digest).as_str()) {
            (
                Some("1794518371.sh"),
                "d3652d3d03b33d3d250f0681065dbaee2c17b3baee330be681248cc2139f74ea",
            ) => Some(NativeMigration::TrayMenuDependency),
            (
                Some("1794675791.sh"),
                "51547c19027f82b16bfddc3121fb1c14ff01425322afc0bce0ea207f069d4eac",
            ) => Some(NativeMigration::OmnibookAudio),
            (
                Some("1794774234.sh"),
                "2e4a9686547c5615eceb9c23cb3b079df491d000078da10b7d995ea1caf9a954",
            ) => Some(NativeMigration::MediaViewer),
            (
                Some("1795284903.sh"),
                "28a0c1d32f634efe9c005c42fe4353b8ead88914867abccc7dbb310d4a7c937b",
            ) => Some(NativeMigration::FacetimeHdCamera),
            (
                Some("1795318856.sh"),
                "559ed11ca9d1dcb21b3a2f4cfcc2907cd8ee68e056b60e549f6fed532f152b70",
            ) => Some(NativeMigration::PiCodingAgent),
            (
                Some("1795354955.sh"),
                "c5328f65a8d4afa9157339f4821f0121e911e741f7d9cee581586a6d241e6bfd",
            ) => Some(NativeMigration::Kmscon),
            (
                Some("1795354646.sh"),
                "a40d46ed75d0701a64c72fba2a6dd0a46d8608ef0966b59723cc553e1dc921fe",
            ) => Some(NativeMigration::PodmanAndCrun),
            (
                Some("1794864665.sh"),
                "21a57acd1251ef82766a31004f6b260493917ae0d1890e430f698b01f3ad6373",
            )
            | (
                Some("1794909082.sh"),
                "61102765f4dc278d004a38ecdb91f25f6dca1751ba2e7e34ccbaac5e23a2f084",
            )
            | (
                Some("1795274792.sh"),
                "30bd8bec776d5797f1b08b76ffa3ef17b0d497152828b09a846cd1894594b711",
            )
            | (
                Some("1795337583.sh"),
                "bc0609dfe8064c3ea023ccf834b414e45e9195449f00ee68c53bf043f4d46255",
            ) => {
                let platform = nix::sys::utsname::uname()
                    .context("Cannot read the Omarchy machine architecture")?;
                Some(qualcomm_migration_for_machine(platform.machine(), &path)?)
            }
            (Some("1794864665.sh" | "1794909082.sh" | "1795274792.sh" | "1795337583.sh"), _) => {
                anyhow::bail!(
                    "Omarchy hardware migration {} differs from the reviewed script",
                    path.display()
                )
            }
            _ => None,
        };
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
        let references_external_helper = known_external_aur
            .iter()
            .any(|command| contents.contains(command))
            || contents
                .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                .any(|word| matches!(word, "yay" | "aura" | "paru"));
        anyhow::ensure!(
            native.is_some() || !references_external_helper,
            "Native AUR integration refuses pending Omarchy migration {} because it references an external package helper. A native migration equivalent is required before continuing.",
            path.display()
        );
        pending.push(PendingMigration {
            path,
            digest,
            native,
        });
    }
    pending.sort_by(|left, right| left.path.file_name().cmp(&right.path.file_name()));
    Ok(pending)
}

fn ensure_migrations_use_native_aur(migrations: &Path, state: &Path) -> Result<()> {
    pending_migrations(migrations, state).map(|_| ())
}

trait MigrationExecutor {
    async fn execute_migration(&mut self, migration: &PendingMigration) -> Result<()>;
}

async fn run_migration_plan(
    plan: &[PendingMigration],
    state: &Path,
    executor: &mut impl MigrationExecutor,
) -> Result<()> {
    for migration in plan {
        let marker = state.join(
            migration
                .path
                .file_name()
                .context("Migration name is missing")?,
        );
        if marker.is_file() {
            continue;
        }
        anyhow::ensure!(
            migration_digest(&read_migration(&migration.path)?) == migration.digest,
            "Omarchy migration changed after preflight: {}",
            migration.path.display()
        );
        std::fs::create_dir_all(state)?;
        executor.execute_migration(migration).await?;
        anyhow::ensure!(
            migration_digest(&read_migration(&migration.path)?) == migration.digest,
            "Omarchy migration changed during execution: {}",
            migration.path.display()
        );
        open_owned_file(&marker)?.sync_all()?;
        File::open(state)?.sync_all()?;
    }
    Ok(())
}

impl MigrationExecutor for Commands {
    async fn execute_migration(&mut self, migration: &PendingMigration) -> Result<()> {
        OmarchyRuntime::validate_root_directory(
            migration
                .path
                .parent()
                .context("Migration directory is missing")?,
        )?;
        let metadata = std::fs::symlink_metadata(&migration.path)?;
        anyhow::ensure!(
            metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
            "Omarchy migration must be a root-controlled regular file"
        );
        println!(
            "Running Omarchy migration {}",
            migration
                .path
                .file_stem()
                .context("Migration name")?
                .display()
        );
        let Some(native) = migration.native else {
            let shell = crate::core::privilege::root_controlled_program_path("bash")?;
            let status = self
                .run_program(
                    &shell,
                    &[
                        "-euo",
                        "pipefail",
                        migration
                            .path
                            .to_str()
                            .context("Migration path is not UTF-8")?,
                    ],
                )
                .await?;
            anyhow::ensure!(
                status.success(),
                "Omarchy migration {} failed: {status}",
                migration.path.display()
            );
            return Ok(());
        };
        self.run_native_migration(native, dirs::home_dir()).await
    }
}

impl Commands {
    async fn run_native_migration(
        &mut self,
        native: NativeMigration,
        home: Option<PathBuf>,
    ) -> Result<()> {
        let operation = match native {
            NativeMigration::TrayMenuDependency => {
                NativeOmarchyOperation::InstallTrayMenuDependency
            }
            NativeMigration::OmnibookAudio => {
                for (name, args) in [
                    ("omarchy-hw-aarch64-qualcomm", &[][..]),
                    ("omarchy-hw-match", &["OmniBook 3 Laptop"][..]),
                ] {
                    let helper = self.resolve_migration_helper(name)?;
                    let status = self.run_program(&helper, args).await?;
                    if status.code() == Some(1)
                        || name == "omarchy-hw-match" && status.code() == Some(2)
                    {
                        return Ok(());
                    }
                    anyhow::ensure!(
                        status.success(),
                        "Omarchy hardware detection {name} failed: {status}"
                    );
                }
                if self.is_package_installed("hp-omnibook-3-audio")? {
                    return Ok(());
                }
                NativeOmarchyOperation::InstallOmnibookAudio
            }
            NativeMigration::MediaViewer => return self.replace_media_viewer(home).await,
            NativeMigration::FacetimeHdCamera => return self.install_facetimehd_camera().await,
            NativeMigration::PiCodingAgent => return self.install_pi_coding_agent().await,
            NativeMigration::Kmscon => NativeOmarchyOperation::InstallKmscon,
            NativeMigration::PodmanAndCrun => NativeOmarchyOperation::InstallPodmanAndCrun,
            NativeMigration::SkipQualcommHardware => {
                println!("  Qualcomm hardware migration does not apply on x86_64");
                return Ok(());
            }
        };
        self.run_native_package(operation).await?;
        if native == NativeMigration::OmnibookAudio {
            self.mark_reboot_required(
                "Cannot mark the Omarchy audio migration as requiring a reboot",
            )
            .await?;
        }
        Ok(())
    }

    async fn replace_media_viewer(&mut self, home: Option<PathBuf>) -> Result<()> {
        const SHIPPED_LAUNCHERS: &[&str] = &[
            "120d30326a77e1f23d050e52293d0acf1aeb9499bf9cd47b93996d6e2be99480",
            "a7a75999f161c6a409ff4c5da26ad9c79fc1ffdd4e633aac87f972ad72fc85d4",
            "d105a16b60ecc1c67f6cc37e5bb7831ca8a08d0e602cb64dd4a1386703362385",
            "9844e9d22d1b4b9801965afea1eb250103cfc6f12e6e62e542ac47abd4b8094d",
        ];
        self.run_native_package(NativeOmarchyOperation::InstallMediaViewer)
            .await?;
        let applications = home
            .context("Cannot locate the Omarchy user's home")?
            .join(".local/share/applications");
        if remove_shipped_media_launchers(&applications, SHIPPED_LAUNCHERS)? {
            let program = "update-desktop-database";
            #[cfg(test)]
            let program = self
                .native_fixture
                .as_ref()
                .map_or(program, |fixture| fixture.desktop_database_program);
            let updater = crate::core::privilege::root_controlled_program_path(program)?;
            let path = applications
                .to_str()
                .context("Desktop application directory is not UTF-8")?;
            let status = self.run_program(&updater, &[path]).await?;
            anyhow::ensure!(
                status.success(),
                "Cannot refresh the desktop application database: {status}"
            );
        }
        self.run_native_package(NativeOmarchyOperation::RemoveLegacyMediaViewers)
            .await
    }

    async fn mark_reboot_required(&mut self, error_context: &str) -> Result<()> {
        let helper = self.resolve_migration_helper("omarchy-state")?;
        let status = self
            .run_program(&helper, &["set", "reboot-required"])
            .await?;
        anyhow::ensure!(status.success(), "{error_context}");
        Ok(())
    }

    async fn install_facetimehd_camera(&mut self) -> Result<()> {
        let detector = self.resolve_migration_helper("omarchy-hw-facetimehd")?;
        let status = self.run_program(&detector, &[]).await?;
        if status.code() == Some(1) {
            return Ok(());
        }
        anyhow::ensure!(
            status.success(),
            "Omarchy hardware detection omarchy-hw-facetimehd failed: {status}"
        );
        let missing_driver = !self.is_package_installed("facetimehd-dkms")?
            && !self.is_package_installed("bcwc-pcie")?
            && !self.is_package_installed("bcwc-pcie-dkms")?;
        let missing_firmware = !self.is_package_installed("facetimehd-firmware")?
            && !self.is_package_installed("bcwc-pcie-firmware")?
            && !self.is_package_installed("facetimehd-firmware-fetcher")?;
        if missing_driver || missing_firmware {
            self.run_native_package(NativeOmarchyOperation::InstallFacetimeHd)
                .await?;
            self.mark_reboot_required(
                "Cannot mark the FaceTime HD migration as requiring a reboot",
            )
            .await?;
        }
        if self.is_package_installed("facetimehd-firmware-fetcher")? {
            self.run_sudo(
                &["systemctl", "enable", "facetimehd-firmware-fetcher.service"],
                "Failed to enable facetimehd-firmware-fetcher.service",
            )
            .await?;
            self.run_sudo(
                &[
                    "systemctl",
                    "start",
                    "--no-block",
                    "facetimehd-firmware-fetcher.service",
                ],
                "Failed to start facetimehd-firmware-fetcher.service",
            )
            .await?;
        }
        let source = self
            .runtime
            .root
            .join("default/systemd/system/omarchy-facetimehd-hibernate.conf");
        let source = source
            .to_str()
            .context("FaceTime HD systemd drop-in path is not UTF-8")?;
        for unit in [
            "systemd-hibernate",
            "systemd-hybrid-sleep",
            "systemd-suspend-then-hibernate",
        ] {
            let destination =
                format!("/etc/systemd/system/{unit}.service.d/omarchy-facetimehd.conf");
            self.run_sudo(
                &["install", "-Dm644", source, &destination],
                "Failed to install FaceTime HD hibernation drop-in",
            )
            .await?;
        }
        self.run_sudo(
            &["systemctl", "daemon-reload"],
            "Failed to reload systemd units",
        )
        .await
    }

    async fn install_pi_coding_agent(&mut self) -> Result<()> {
        let helper = self.resolve_migration_helper("omarchy-mise-default-tools")?;
        let output = self.capture_program_stdout(&helper, &["list"]).await?;
        anyhow::ensure!(
            output.status.success(),
            "Failed to check Omarchy default mise tools: {}",
            output.status
        );
        let stdout = std::str::from_utf8(&output.stdout)
            .context("omarchy-mise-default-tools output is not valid UTF-8")?;
        anyhow::ensure!(
            !stdout.lines().any(|line| line == "pi"),
            "Waiting for the omarchy-settings package that drops Pi from the default mise tools"
        );
        self.run_native_package(NativeOmarchyOperation::InstallPiCodingAgent)
            .await?;
        if let Some(mise) = self.resolve_optional_helper("mise") {
            let mise_output = self
                .capture_program_stdout(&mise, &["ls", "pi", "--json"])
                .await?;
            if mise_output.status.success() {
                let items: serde_json::Value = serde_json::from_slice(&mise_output.stdout)
                    .context("Invalid JSON from `mise ls pi --json`")?;
                let user_declared = items.as_array().is_some_and(|entries| {
                    entries.iter().any(|entry| {
                        entry.get("source").is_some_and(|source| {
                            !source.is_null() && *source != serde_json::Value::Bool(false)
                        })
                    })
                });
                if !user_declared {
                    if items.as_array().is_some_and(|entries| !entries.is_empty()) {
                        let status = self
                            .run_program(&mise, &["uninstall", "--all", "pi"])
                            .await?;
                        anyhow::ensure!(status.success(), "Failed to uninstall mise pi: {status}");
                    }
                    let status = self.run_program(&mise, &["reshim"]).await?;
                    anyhow::ensure!(status.success(), "Failed to run mise reshim: {status}");
                }
            }
        }
        Ok(())
    }
}

fn remove_shipped_media_launchers(applications: &Path, shipped_digests: &[&str]) -> Result<bool> {
    use std::io::Read;

    const MAX_LAUNCHER_BYTES: u64 = 64 * 1024;
    let directory = match std::fs::symlink_metadata(applications) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).context("Cannot inspect the desktop application directory");
        }
    };
    if !directory.is_dir() {
        return Ok(false);
    }
    for name in ["imv.desktop", "mpv.desktop"] {
        let path = applications.join(name);
        let file = match File::options()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&path)
        {
            Ok(file) => file,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(nix::libc::ELOOP) =>
            {
                continue;
            }
            Err(error) => return Err(error).with_context(|| format!("Cannot inspect {name}")),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_LAUNCHER_BYTES {
            continue;
        }
        let mut contents = Vec::new();
        file.take(MAX_LAUNCHER_BYTES + 1)
            .read_to_end(&mut contents)?;
        use sha2::{Digest, Sha256};
        let digest = hex::encode(Sha256::digest(&contents));
        if contents.len() as u64 <= MAX_LAUNCHER_BYTES && shipped_digests.contains(&digest.as_str())
        {
            let current = std::fs::symlink_metadata(&path)?;
            anyhow::ensure!(
                current.is_file()
                    && current.dev() == metadata.dev()
                    && current.ino() == metadata.ino()
                    && current.mtime() == metadata.mtime()
                    && current.mtime_nsec() == metadata.mtime_nsec()
                    && current.ctime() == metadata.ctime()
                    && current.ctime_nsec() == metadata.ctime_nsec(),
                "Desktop entry {name} changed while it was being checked"
            );
            std::fs::remove_file(path)
                .with_context(|| format!("Cannot remove the old Omarchy launcher {name}"))?;
        }
    }
    Ok(true)
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
    if !inspection.root.join(&modules).is_file() || !owns_modules(&modules)? {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InheritedTransport {
    lock: i32,
    log: i32,
}

fn inherited_transport(
    lock: Option<std::ffi::OsString>,
    log: Option<std::ffi::OsString>,
) -> Result<Option<InheritedTransport>> {
    let (lock, log) = match (lock, log) {
        (None, None) => return Ok(None),
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
    Ok(Some(InheritedTransport { lock, log }))
}

/// Restrict update transport inheritance before CLI initialization can launch helpers.
#[doc(hidden)]
pub fn contain_inherited_transport(args: &[String]) -> Result<()> {
    use clap::Parser;
    let lock = std::env::var_os(LOCK_FD);
    let log = std::env::var_os(LOG_FD);
    let update = args.get(1).map(String::as_str) == Some("update")
        || ((lock.is_some() || log.is_some())
            && crate::cli::Cli::try_parse_from(args)
                .is_ok_and(|cli| matches!(cli.command, crate::cli::Commands::Update { .. })));
    if update && let Some(transport) = inherited_transport(lock, log)? {
        set_descriptor_inheritance(transport.lock, false)
            .context("Cannot contain inherited Omarchy lock")?;
        set_descriptor_inheritance(transport.log, false)
            .context("Cannot contain inherited Omarchy log")?;
    }
    Ok(())
}

fn duplicate_inherited(raw: i32, expected: &Path) -> Result<File> {
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

fn probe_existing_lock(probe: &File) -> Result<bool> {
    match probe.try_lock() {
        Err(std::fs::TryLockError::WouldBlock) => Ok(true),
        Ok(()) => {
            // A concurrent fork may retain this open description after close.
            probe
                .unlock()
                .context("Cannot release the Omarchy lock probe")?;
            Ok(false)
        }
        Err(std::fs::TryLockError::Error(error)) => {
            Err(error).context("Cannot verify the inherited Omarchy lock")
        }
    }
}

fn inherited_lock(raw: i32, path: &Path) -> Result<File> {
    let inherited = duplicate_inherited(raw, path)?;
    let independent = open_owned_file(path)?;
    anyhow::ensure!(
        probe_existing_lock(&independent)?,
        "Omarchy transport has no existing lock lease"
    );
    inherited
        .try_lock()
        .context("Omarchy transport does not own its lock")?;
    Ok(inherited)
}

struct Interruptions {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
    hangup: tokio::signal::unix::Signal,
    // The CLI restores SIGPIPE's default at startup. Keep pipe writes fallible
    // during an update so the relay can drain the coordinator's cleanup.
    _broken_pipe: tokio::signal::unix::Signal,
}

impl Interruptions {
    fn new() -> Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
            hangup: signal(SignalKind::hangup())?,
            _broken_pipe: signal(SignalKind::pipe())?,
        })
    }

    async fn receive(&mut self) {
        // Tokio's Unix signal streams never close.
        tokio::select! {
            _ = self.interrupt.recv() => {},
            _ = self.terminate.recv() => {},
            _ = self.hangup.recv() => {},
        }
    }
}

async fn interrupt() -> Result<()> {
    Interruptions::new()?.receive().await;
    Ok(())
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
    Eof,
    // EOF has already been forwarded to the coordinator.
    Closed,
}

impl PtyInput {
    async fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        use tokio::io::AsyncReadExt;
        match self {
            Self::Pollable(input) => read_pty(input, buffer).await,
            Self::Regular(input) => input.read(buffer).await,
            Self::Eof => Ok(0),
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
            return Ok((PtyInput::Eof, None));
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
    let deadline = tokio::time::Instant::now() + TERMINATION_GRACE;
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
            () = tokio::time::sleep_until(deadline) => {
                let _ = child.start_kill();
                drop(master);
                let status = child
                    .wait()
                    .await
                    .context("Cannot reap killed Omarchy coordinator")?;
                interruption?;
                return Ok(status);
            }
        }
    }
}

async fn drain_completed_coordinator(
    master: &tokio::io::unix::AsyncFd<File>,
    mut transcript: &File,
    terminal: &mut impl std::io::Write,
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
            let _ = terminal
                .write_all(&output[..count])
                .and_then(|()| terminal.flush());
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
    let outer_attended = terminal.is_some() && console::user_attended();
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
        .env(ATTENDED_ENV, if outer_attended { "1" } else { "0" })
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
    let mut stdout_connected = true;
    let mut cancellation = None;
    let relay = async {
        loop {
            tokio::select! {
                status = child.wait() => {
                    let status = status?;
                    drain_completed_coordinator(&master, transcript, &mut std::io::stdout()).await?;
                    return Ok::<_, anyhow::Error>(status);
                }
                result = read_pty(&master, &mut output), if output_open => {
                    let count = result?;
                    if count == 0 {
                        output_open = false;
                    } else {
                        transcript.write_all(&output[..count])?;
                        if stdout_connected
                            && let Err(error) = std::io::stdout()
                                .write_all(&output[..count])
                                .and_then(|()| std::io::stdout().flush())
                        {
                            stdout_connected = false;
                            if cancellation.is_none() {
                                cancellation = Some(anyhow::Error::new(error).context("Update output disconnected"));
                                interrupt_coordinator(&child)?;
                            }
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
                () = interruptions.receive() => {
                    if cancellation.is_none() {
                        cancellation = Some(anyhow::anyhow!("Omarchy update interrupted; inspect the update log before retrying"));
                        interrupt_coordinator(&child)?;
                    } else {
                        let _ = child.start_kill();
                    }
                }
                Some(terminal) = async { resized.recv().await.and(resize_terminal.as_ref()) }, if resize_terminal.is_some() => {
                    rustix::termios::tcsetwinsize(master.get_ref(), rustix::termios::tcgetwinsize(terminal)?)?;
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
    let UpdatePlan::Omarchy { yes } = plan(update_flavor()?, intent)? else {
        return Ok(false);
    };
    ensure_mutation_context()?;
    let transport = inherited_transport(std::env::var_os(LOCK_FD), std::env::var_os(LOG_FD))?;
    let runtime = OmarchyRuntime::discover()?;
    runtime.check_pending_migrations()?;
    match transport {
        None => {
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
        Some(transport) => {
            anyhow::ensure!(
                std::env::var_os("OMARCHY_PATH")
                    .is_some_and(|path| Path::new(&path) == runtime.root)
                    && std::env::var_os("OMARCHY_MIGRATION_STATE")
                        .is_some_and(|path| Path::new(&path) == runtime.migration_state),
                "Omarchy runtime changed during coordinator handoff"
            );
            let lock = inherited_lock(transport.lock, &lock_path())?;
            let log = duplicate_inherited(transport.log, Path::new(LOG_PATH))?;
            use std::io::IsTerminal;
            anyhow::ensure!(
                std::io::stdin().is_terminal()
                    && std::io::stdout().is_terminal()
                    && log.metadata()?.len() > 0,
                "Omarchy update transport has no active PTY transcript"
            );
            let attended = coordinator_attended_from(
                std::env::var_os(ATTENDED_ENV).as_deref(),
                console::user_attended(),
            );
            let mut executor = Commands::new(yes, runtime).with_attended(attended);
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
    }
    Ok(true)
}

#[cfg(test)]
mod tests;
