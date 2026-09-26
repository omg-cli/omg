//! Privilege elevation utilities
//!
//! Package database writes run as root inside this binary (sudo re-exec), never
//! by spawning pacman or an AUR helper.

use std::sync::atomic::{AtomicBool, Ordering};

/// Privileged command lookup never consults the invoking user's PATH.
pub const SYSTEM_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// Resolve an executable whose file and every ancestor are controlled by root.
/// Canonicalization permits the standard /bin -> /usr/bin merged layout.
pub fn trusted_program(program: &str) -> anyhow::Result<std::path::PathBuf> {
    let input = std::path::Path::new(program);
    let candidates = if input.is_absolute() {
        vec![input.to_path_buf()]
    } else {
        anyhow::ensure!(
            input.components().count() == 1,
            "Invalid system program: {program}"
        );
        SYSTEM_PATH
            .split(':')
            .map(|dir| std::path::Path::new(dir).join(input))
            .collect()
    };
    for candidate in candidates {
        if let Ok(path) = trusted_executable_path(&candidate) {
            return Ok(path);
        }
    }
    anyhow::bail!("No root-controlled system executable found for {program}")
}

fn trusted_executable_path(path: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let path = std::fs::canonicalize(path)?;
        let metadata = std::fs::metadata(&path)?;
        anyhow::ensure!(
            metadata.is_file() && metadata.mode() & 0o111 != 0,
            "Not executable"
        );
        for ancestor in path.ancestors() {
            let metadata = std::fs::metadata(ancestor)?;
            anyhow::ensure!(
                metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
                "Executable path is writable by an unprivileged account: {}",
                ancestor.display()
            );
        }
        Ok(path)
    }
    #[cfg(not(unix))]
    anyhow::bail!(
        "Privilege elevation is unsupported on this platform: {}",
        path.display()
    )
}

pub fn system_command(program: &str) -> anyhow::Result<std::process::Command> {
    let mut command = std::process::Command::new(trusted_program(program)?);
    command.env("PATH", SYSTEM_PATH);
    for name in PRIVILEGED_ENV_SCRUB {
        command.env_remove(name);
    }
    for name in dangerous_prefixed_env_names() {
        command.env_remove(name);
    }
    Ok(command)
}

pub fn sudo_command() -> anyhow::Result<tokio::process::Command> {
    Ok(system_command("sudo")?.into())
}

/// Effective identity of the account that initiated an elevated process.
///
/// Numeric `SUDO_UID` is intentionally ignored: permissive sudoers `SETENV`
/// rules can preserve caller-selected numeric values. `sudo` and `doas`
/// establish an invoking user name; resolving that name through the system
/// account database gives ownership checks and audit records one consistent
/// identity source.
pub fn invoking_uid() -> anyhow::Result<u32> {
    use anyhow::Context;

    let effective_uid = rustix::process::geteuid().as_raw();
    if effective_uid != 0 {
        return Ok(effective_uid);
    }
    let valid_user = |user: &String| {
        !user.is_empty() && !user.starts_with('-') && !user.chars().any(char::is_control)
    };
    let Some(user) = std::env::var("SUDO_USER")
        .ok()
        .filter(valid_user)
        .or_else(|| std::env::var("DOAS_USER").ok().filter(valid_user))
    else {
        return Ok(0);
    };
    let account = nix::unistd::User::from_name(&user)
        .with_context(|| format!("Failed to resolve invoking account '{user}'"))?
        .with_context(|| format!("Invoking account '{user}' does not exist"))?;
    Ok(account.uid.as_raw())
}

#[cfg(target_os = "linux")]
struct ElevationPathEntry {
    owner: u32,
    mode: u32,
    is_file: bool,
    is_directory: bool,
    device: u64,
    inode: u64,
}

/// Validate the namespace from root outward, establishing each trusted parent
/// before looking at its child. Unlike system-program lookup, symlinks are not
/// canonicalized: a candidate must name the running inode in a namespace that
/// an unprivileged account cannot replace. Root-admin replacement remains within
/// the trusted administrative boundary.
#[cfg(target_os = "linux")]
fn root_controlled_elevation_path(
    candidate: &std::path::Path,
    running_identity: (u64, u64),
    mut inspect: impl FnMut(&std::path::Path) -> std::io::Result<ElevationPathEntry>,
) -> bool {
    use std::path::{Component, PathBuf};

    if !candidate.is_absolute() {
        return false;
    }
    let mut prefix = PathBuf::new();
    let mut components = candidate.components().peekable();
    while let Some(component) = components.next() {
        if !matches!(component, Component::RootDir | Component::Normal(_)) {
            return false;
        }
        prefix.push(component);
        let Ok(entry) = inspect(&prefix) else {
            return false;
        };
        if entry.owner != 0 || entry.mode & 0o022 != 0 {
            return false;
        }
        if components.peek().is_none() {
            return entry.is_file
                && entry.mode & 0o111 != 0
                && (entry.device, entry.inode) == running_identity;
        }
        if !entry.is_directory {
            return false;
        }
    }
    false
}

/// Root-controlled Linux installations can re-exec directly in containers that
/// deny cross-UID procfs access. Mutable installations retain the pinned proc
/// inode. Selection happens before sudo, never as a retry after payload failure.
fn elevation_executable() -> anyhow::Result<std::path::PathBuf> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;

        let pinned = std::path::PathBuf::from(format!("/proc/{}/exe", std::process::id()));
        let running = std::fs::metadata(&pinned)?;
        if let Ok(candidate) = std::fs::read_link(&pinned)
            && root_controlled_elevation_path(&candidate, (running.dev(), running.ino()), |path| {
                let metadata = std::fs::symlink_metadata(path)?;
                Ok(ElevationPathEntry {
                    owner: metadata.uid(),
                    mode: metadata.mode(),
                    is_file: metadata.is_file(),
                    is_directory: metadata.is_dir(),
                    device: metadata.dev(),
                    inode: metadata.ino(),
                })
            })
        {
            return Ok(candidate);
        }
        Ok(pinned)
    }
    #[cfg(not(target_os = "linux"))]
    trusted_executable_path(&std::env::current_exe()?)
}

/// Environment variables stripped from every sudo child. One list so a new
/// scrub variable cannot be added in one elevation path and missed in another.
const PRIVILEGED_ENV_SCRUB: &[&str] = &[
    // Package-manager configuration can define root-executed transaction hooks.
    "APT_CONFIG",
    "DPKG_ROOT",
    "DPKG_ADMINDIR",
    "RPM_CONFIGDIR",
    "OMG_PACMAN_CONF",
    "OMG_PACMAN_ROOT",
    "OMG_PACMAN_DB_DIR",
    "OMG_PACMAN_SYNC_DIR",
    "OMG_PACMAN_LOCAL_DIR",
    "OMG_PACMAN_CACHE_DIR",
    "OMG_PACMAN_CACHE_ROOT_DIR",
    "OMG_PACMAN_MIRRORLIST",
    // State and configuration redirection: a root child must resolve its
    // config, policy, data, cache and socket locations itself, never from the
    // caller's environment. `paths::env_path` also refuses these for root, so
    // this list covers paths that read the environment directly.
    "OMG_CONFIG_DIR",
    "OMG_DATA_DIR",
    "OMG_CACHE_DIR",
    "OMG_DAEMON_DATA_DIR",
    "OMG_SOCKET_PATH",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_RUNTIME_DIR",
    // Diagnostic sinks and trust-policy overrides that must not be selectable
    // by the caller of a privileged operation.
    "OMG_SENTRY_DSN",
    "OMG_SELF_UPDATE_ALLOW_UNVERIFIED_PROVENANCE",
    // TLS trust anchors and the egress path. reqwest reads these on its own
    // (rustls-native-certs honours SSL_CERT_FILE/SSL_CERT_DIR; hyper-util reads
    // the proxy variables), so a permissive sudoers env_keep would otherwise
    // let the caller choose which CA root trusts or which proxy it talks to.
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "CURL_CA_BUNDLE",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "https_proxy",
    "http_proxy",
    "all_proxy",
    "no_proxy",
    // Force terminal-based password prompt, never GUI askpass
    "SUDO_ASKPASS",
    "SSH_ASKPASS",
    "SSH_ASKPASS_REQUIRE",
    // Cargo build environment
    "CARGO_PRIMARY_PACKAGE",
    "CARGO_MANIFEST_DIR",
    "CARGO_TARGET_DIR",
    "CARGO_PKG_NAME",
    "CARGO_PKG_VERSION",
    "OUT_DIR",
    // Library injection vectors (Linux)
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_DEBUG",
    // Library injection vectors (macOS dyld; sudo strips these by default,
    // but a permissive sudoers env_keep must not smuggle them into root)
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_FALLBACK_FRAMEWORK_PATH",
    "DYLD_FRAMEWORK_PATH",
    // Script execution vectors
    "PYTHONPATH",
    "PYTHONHOME",
    "RUBYLIB",
    "RUBYOPT",
    "PERL5LIB",
    "PERL5OPT",
    "NODE_PATH",
    "NODE_OPTIONS",
    // Shell startup vectors: sourced by non-interactive sh/bash, which is
    // exactly how package maintainer scripts run as root
    "BASH_ENV",
    "ENV",
    "PS4",
];

/// Strip [`PRIVILEGED_ENV_SCRUB`] from a sudo command builder.
fn scrub_privileged_env(command: &mut tokio::process::Command) {
    command.env("PATH", SYSTEM_PATH);
    for name in PRIVILEGED_ENV_SCRUB {
        command.env_remove(name);
    }
    for name in dangerous_prefixed_env_names() {
        command.env_remove(name);
    }
}

/// DNF repository files may interpolate arbitrary `DNF_VAR_*` names. Remove
/// every inherited instance because an exact-name denylist cannot cover them.
fn dangerous_prefixed_env_names() -> Vec<std::ffi::OsString> {
    std::env::vars_os()
        .filter_map(|(name, _)| {
            name.to_str()
                .is_some_and(|name| name.starts_with("DNF_VAR_"))
                .then_some(name)
        })
        .collect()
}
///
/// Elevation marker traveling through argv.
///
/// sudo's default `env_reset` strips `OMG_ELEVATED` from the child
/// environment. The child (see `src/bin/omg.rs` main) strips this marker
/// and sets `OMG_ELEVATED` itself before any dispatch. A non-root user
/// invoking the marker gains nothing: elevation checks still require
/// effective root.
pub const ELEVATED_MARKER: &str = "__omg_elevated";

/// Reserved argv token: mid-flow delegation whose PARENT owns the history record.
///
/// The parent appends this token because it has richer change metadata and AUR
/// handling; the elevated child strips it and skips its own
/// `record_fast_transaction` so each mutation is recorded exactly once.
/// Whole-command re-execs never carry it, so the child remains their sole
/// recorder.
pub const FLOW_PARENT_RECORDS: &str = "__omg_parent_records";

#[cfg(not(test))]
use std::sync::LazyLock;

#[cfg(not(test))]
use anyhow::Context;
#[cfg(not(test))]
use std::sync::Mutex;

/// Global mutex to serialize privilege elevation attempts
/// Prevents deadlocks when multiple threads try to elevate simultaneously
#[cfg(not(test))]
static ELEVATION_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Global flag to track if --yes was specified for non-interactive mode
static YES_FLAG: AtomicBool = AtomicBool::new(false);

// Set only by the validated root re-exec argv protocol. Full clap dispatches
// use it when flags prevent the minimal elevated path from owning history.
static PARENT_OWNS_HISTORY: AtomicBool = AtomicBool::new(false);

#[doc(hidden)]
pub fn set_parent_owns_history(value: bool) {
    PARENT_OWNS_HISTORY.store(value, Ordering::SeqCst);
}

#[doc(hidden)]
#[must_use]
pub fn parent_owns_history() -> bool {
    PARENT_OWNS_HISTORY.load(Ordering::SeqCst)
}

/// Set the yes flag globally (call this at the start of main if --yes is present)
pub fn set_yes_flag(value: bool) {
    YES_FLAG.store(value, Ordering::SeqCst);
}

/// Run an EXTERNAL program under sudo as one step inside a larger flow.
///
/// Unlike [`run_privileged_child`] this never re-executes omg: the native
/// package manager (apt-get, dnf) runs directly with explicit arguments, so
/// there is exactly one prompt and no re-listing/re-confirming of work the
/// caller already resolved. Credentials are validated with a pre-flight
/// `sudo -n -v`; when that fails and stdin is interactive, one authentication
/// prompt is offered before giving up.
///
/// # Errors
/// Dev/test mode bails without touching sudo. A password requirement in a
/// non-interactive session, or a nonzero child status, is returned as an
/// error.
fn reject_privileged_program_in_dev_mode(
    dev_mode: bool,
    program: &str,
    args: &[&str],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !dev_mode,
        "Privilege elevation not supported in development mode.\n\
         \n\
         Options:\n\
         • Prime sudo credentials: omg doctor --turbo\n\
         • Run directly with sudo: sudo {program} {args:?}"
    );
    Ok(())
}

pub async fn run_privileged_program(program: &str, args: &[&str]) -> anyhow::Result<()> {
    // Detect dev/test mode — identical contract to run_self_sudo.
    reject_privileged_program_in_dev_mode(
        crate::core::paths::test_mode() || std::env::var("CARGO_PRIMARY_PACKAGE").is_ok(),
        program,
        args,
    )?;

    if matches!(
        std::path::Path::new(program)
            .file_name()
            .and_then(|name| name.to_str()),
        Some("apt-get" | "dnf")
    ) && args.first().is_some_and(|arg| {
        matches!(
            *arg,
            "install" | "upgrade" | "dist-upgrade" | "full-upgrade"
        )
    }) {
        crate::core::security::policy::require_native_plan_support(program)?;
    }
    let program_path = trusted_program(program)?;

    // Pre-flight: validate/refresh credentials WITHOUT running the payload,
    // so a password requirement is detected before any partial work.
    let authenticated = sudo_command()?
        .arg("-n")
        .arg("-v")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .is_ok_and(|s| s.success());

    if !authenticated {
        if get_yes_flag() || !console::user_attended() {
            anyhow::bail!(
                "Privilege elevation requires a password but no interactive terminal is available.\n\
                 \n\
                 Run 'omg doctor --turbo' interactively to prime sudo credentials,\n\
                 and use your administrator-approved sudo policy for automation."
            );
        }
        // One interactive authentication prompt with inherited stdio.
        let mut auth_cmd = sudo_command()?;
        scrub_privileged_env(&mut auth_cmd);
        let status = auth_cmd
            .arg("-v")
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to run sudo for credential validation: {e}"))?;
        if !status.success() {
            anyhow::bail!("sudo authentication failed");
        }
    }

    let audit_targets = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    crate::core::security::audit::record_operation(program, &audit_targets, "attempt")?;
    let mut elevated = sudo_command()?;
    scrub_privileged_env(&mut elevated);
    let status = elevated
        .arg("--")
        .arg(program_path)
        .args(args)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to run {program} under sudo: {e}"))?;

    crate::core::security::audit::record_operation(
        program,
        &audit_targets,
        if status.success() {
            "succeeded"
        } else {
            "failed"
        },
    )?;
    if status.success() {
        Ok(())
    } else {
        Err(describe_program_failure(program, &status))
    }
}

/// Report a failed privileged program without losing how it terminated.
///
/// `std::process::ExitStatus::code` returns `None` when a child was terminated
/// by a signal (std 1.98, "On Unix, this will return None if the process was
/// terminated by a signal"), so a killed `dnf`/`apt`/`pacman` must not be
/// reported as a generic exit-code failure: `ExitStatusExt::signal` carries the
/// signal that actually ended it. Evidence: Fedora lane 36204199869 reported
/// only `dnf failed with exit code 1` while the transaction row stayed in
/// libdnf5's `STARTED` state, i.e. the run was interrupted rather than refused.
fn describe_program_failure(program: &str, status: &std::process::ExitStatus) -> anyhow::Error {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return anyhow::anyhow!("{program} was terminated by signal {signal}");
        }
    }
    anyhow::anyhow!(
        "{program} failed with exit code {}",
        status.code().unwrap_or(1)
    )
}

/// Check if the yes flag is set
pub fn get_yes_flag() -> bool {
    YES_FLAG.load(Ordering::SeqCst)
}

/// Trait for privilege checking and elevation (for dependency injection)
pub trait PrivilegeChecker: Send + Sync {
    /// Check if running as root
    fn is_root(&self) -> bool;

    /// Elevate privileges for the given operation and arguments
    fn elevate(&self, operation: &str, args: &[String]) -> std::io::Result<()>;
}

/// Default privilege checker using real system calls
pub struct SystemPrivilegeChecker;

impl PrivilegeChecker for SystemPrivilegeChecker {
    fn is_root(&self) -> bool {
        #[cfg(unix)]
        {
            rustix::process::geteuid().is_root()
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    fn elevate(&self, operation: &str, args: &[String]) -> std::io::Result<()> {
        elevate_for_operation(operation, args)
    }
}

/// Mock privilege checker for testing
#[cfg(test)]
pub struct MockPrivilegeChecker {
    pub is_root_value: bool,
    pub should_elevate: bool,
    pub elevation_log: std::sync::Arc<std::sync::Mutex<Vec<(String, Vec<String>)>>>,
}

#[cfg(test)]
impl Default for MockPrivilegeChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl MockPrivilegeChecker {
    pub fn new() -> Self {
        Self {
            is_root_value: false,
            should_elevate: true,
            elevation_log: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    pub fn set_root(&mut self, is_root: bool) {
        self.is_root_value = is_root;
    }

    pub fn set_elevation_allowed(&mut self, allowed: bool) {
        self.should_elevate = allowed;
    }

    pub fn get_elevation_log(&self) -> Vec<(String, Vec<String>)> {
        self.elevation_log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[cfg(test)]
impl PrivilegeChecker for MockPrivilegeChecker {
    fn is_root(&self) -> bool {
        self.is_root_value
    }

    fn elevate(&self, operation: &str, args: &[String]) -> std::io::Result<()> {
        self.elevation_log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((operation.to_string(), args.to_vec()));

        if self.should_elevate {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Mock elevation denied",
            ))
        }
    }
}

/// Check if we're running as root
#[must_use]
pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        rustix::process::geteuid().is_root()
    }

    #[cfg(not(unix))]
    {
        false
    }
}

/// Re-execute the current command with sudo if not root
/// This replaces the current process - it doesn't return on success
pub fn elevate_if_needed(args: &[String]) -> anyhow::Result<()> {
    if is_root() {
        return Ok(());
    }

    #[cfg(test)]
    {
        let _ = args;
        Ok(())
    }

    #[cfg(not(test))]
    {
        // Acquire lock before elevation to prevent concurrent sudo attempts
        let _guard = ELEVATION_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let yes_mode = YES_FLAG.load(Ordering::Relaxed);
        tracing::debug!(
            "Not running as root, attempting elevation. yes_mode={}",
            yes_mode
        );

        // Skip argv[0] as run_self_sudo adds the executable path itself
        let args_refs: Vec<&str> = args
            .iter()
            .skip(1)
            .map(std::string::String::as_str)
            .collect();

        let run_elevation = |args_refs: &[&str]| -> anyhow::Result<()> {
            tokio::runtime::Runtime::new()
                .context("Failed to create runtime")?
                .block_on(run_self_sudo(args_refs))
        };

        // Creating a runtime and calling block_on panics when invoked from
        // within an existing async runtime. When we are inside one, isolate
        // the elevation on a dedicated thread with its own runtime instead.
        if tokio::runtime::Handle::try_current().is_ok() {
            std::thread::scope(|scope| {
                scope
                    .spawn(|| run_elevation(&args_refs))
                    .join()
                    .map_err(|_| anyhow::anyhow!("elevation thread panicked"))?
            })?;
        } else {
            run_elevation(&args_refs)?;
        }

        // If run_self_sudo returns, it means the command succeeded.
        // We exit here to mimic exec() behavior (process replacement)
        std::process::exit(0);
    }
}

/// Request elevation for a specific operation, checking against a whitelist
pub fn elevate_for_operation(operation: &str, args: &[String]) -> std::io::Result<()> {
    // Security: Only allow elevation for known safe operations
    const ALLOWED_ROOT_OPS: &[&str] = &["install", "remove", "upgrade", "update", "sync", "clean"];

    if !ALLOWED_ROOT_OPS.contains(&operation) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("Operation '{operation}' is not whitelisted for root privileges"),
        ));
    }

    elevate_if_needed(args).map_err(std::io::Error::other)
}

/// Run the current executable with sudo and specific arguments asynchronously
/// Build a scrubbed sudo command that re-executes the current binary.
///
/// Note: We set `OMG_ELEVATED=1` as an environment variable for the child
/// process. This prevents infinite recursion when the elevated process checks
/// this flag.
///
/// CRITICAL: Remove CARGO_* environment variables to prevent the elevated
/// process from writing to the user's target directory as root (causing
/// permission errors).
///
/// SECURITY: Also remove dangerous environment variables that could be used
/// to hijack library loading or script execution in an elevated context.
/// Askpass variables are removed to force the terminal-based prompt.
fn payload_command(
    sudo_program: &std::path::Path,
    exe: &std::path::Path,
    args: &[&str],
    non_interactive: bool,
) -> tokio::process::Command {
    let parent_records = args.last().copied() == Some(FLOW_PARENT_RECORDS);
    let payload_args = if parent_records {
        &args[..args.len() - 1]
    } else {
        args
    };
    let mut command = tokio::process::Command::new(sudo_program);
    if non_interactive {
        // -n fails immediately if a password would be required
        command.arg("-n");
    }
    command
        // Elevation is transmitted via an ARGV MARKER, not the environment:
        // sudo's default env_reset strips OMG_ELEVATED from the child, which
        // made every fast-elevated path dead code. The child strips this
        // marker and sets OMG_ELEVATED itself before any dispatch.
        .env("OMG_ELEVATED", "1");
    scrub_privileged_env(&mut command);
    command
        // Inherit terminal so output and any password prompt stay attached
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .arg("--")
        .arg(exe)
        .arg(crate::core::privilege::ELEVATED_MARKER);
    if parent_records {
        // Internal flow ownership is positional protocol metadata, never a
        // package-list token. The root child accepts it only immediately
        // after the authenticated elevation marker.
        command.arg(FLOW_PARENT_RECORDS);
    }
    command.args(payload_args);
    command
}

/// Run the omg payload under sudo exactly once and return its exit status
/// without terminating this process.
///
/// In-flow callers (composite operations such as "sync then list then
/// upgrade") must use [`run_privileged_child`] so work after the elevated
/// step still runs. Only whole-process re-exec points should use
/// [`run_self_sudo`], which exits to mimic exec() semantics.
async fn sudo_payload_status(args: &[&str]) -> anyhow::Result<std::process::ExitStatus> {
    let exe = elevation_executable()?;

    // Detect if we're running in development/test mode.
    let is_test_mode =
        crate::core::paths::test_mode() || std::env::var("CARGO_PRIMARY_PACKAGE").is_ok();
    let owned_args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    let pinned = snapshot_install_inputs(&owned_args)?;
    let policy = crate::core::security::policy::policy_handoff()?;
    let mut args: Vec<_> = pinned
        .as_ref()
        .map_or(owned_args.as_slice(), |inputs| inputs.targets.as_slice())
        .iter()
        .map(String::as_str)
        .collect();
    if let Some(policy) = &policy {
        args.insert(0, policy);
    }
    sudo_payload_status_in(&trusted_program("sudo")?, exe, is_test_mode, &args).await
}

/// Privileged re-exec verbs that are not clap user commands. `update --fast`
/// and `update --turbo` elevate as `fullupdate` / `turboupdate`; the elevated
/// child also accepts `upgrade`. See `try_fast_elevated` in `src/bin/omg.rs`.
const INTERNAL_PRIVILEGED_ENTRYPOINTS: &[&str] = &["upgrade", "fullupdate", "turboupdate"];

fn snapshot_install_inputs(
    args: &[String],
) -> anyhow::Result<Option<crate::core::security::artifact::SnapshotInputs>> {
    use clap::Parser;

    let payload = if args.last().map(String::as_str) == Some(FLOW_PARENT_RECORDS) {
        &args[..args.len() - 1]
    } else {
        args
    };
    let cli = match crate::cli::Cli::try_parse_from(
        std::iter::once("omg").chain(payload.iter().map(String::as_str)),
    ) {
        Ok(cli) => cli,
        Err(error) => {
            if payload
                .first()
                .is_some_and(|command| INTERNAL_PRIVILEGED_ENTRYPOINTS.contains(&command.as_str()))
            {
                return Ok(None);
            }
            return Err(error.into());
        }
    };
    if matches!(cli.command, crate::cli::Commands::Install { .. }) {
        Ok(Some(
            crate::core::security::artifact::SnapshotInputs::capture(args)?,
        ))
    } else {
        Ok(None)
    }
}

/// Dev-mode-injectable core of [`sudo_payload_status`]: `dev_mode` short-
/// circuits before any sudo invocation so tests never touch real sudo.
async fn sudo_payload_status_in(
    sudo_program: &std::path::Path,
    exe: std::path::PathBuf,
    dev_mode: bool,
    args: &[&str],
) -> anyhow::Result<std::process::ExitStatus> {
    if dev_mode {
        anyhow::bail!(
            "Privilege elevation not supported in development mode.\n\
             \n\
             Options:\n\
             • Prime sudo credentials: omg doctor --turbo\n\
             • Run directly with sudo: sudo {} {:?}",
            exe.display(),
            args
        );
    }

    // Check if --yes flag is set for non-interactive mode
    let yes_flag = get_yes_flag();

    // Correctness: validate sudo authentication BEFORE running the payload.
    // Without this pre-flight, a payload command failing under cached
    // credentials (sudo -n executes it directly) was misattributed to "password
    // required" and the entire privileged operation was silently re-executed,
    // repeating its side effects. The validation only refreshes the sudo
    // timestamp; it never runs the payload.
    let mut preflight = tokio::process::Command::new(sudo_program);
    scrub_privileged_env(&mut preflight);
    let validated = preflight
        .arg("-n")
        .arg("-v")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;

    let authenticated = match validated {
        Ok(status) if status.success() => true,
        Ok(_) => false,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "Failed to run sudo for privilege elevation: {e}\n\
                 \n\
                 Run 'omg doctor --turbo' interactively to prime sudo credentials,\n\
                 and use your administrator-approved sudo policy for automation."
            ));
        }
    };

    if !authenticated {
        // sudo cannot authenticate non-interactively: a password is needed.
        if yes_flag {
            return Err(anyhow::anyhow!(
                "Privilege elevation failed (--yes flag prevents password prompt).\n\
                 \n\
                 Run 'omg doctor --turbo' interactively to prime sudo credentials.\n\
                 For automation, use an administrator-approved authenticated session.\n\
                 \n\
                 Alternative: remove --yes to allow a password prompt.\n\
                 Current user: {user}; omg executable: {exe}",
                user = whoami::username().unwrap_or_else(|_| "username".to_string()),
                exe = exe.display()
            ));
        }

        // Interactive sudo WITHOUT timeout. IMPORTANT: stdin/stdout/stderr are
        // inherited by `payload_command` so the password prompt stays in the
        // terminal instead of spawning a GUI askpass dialog. The user can
        // Ctrl+C if needed. Runs exactly once.
        tracing::debug!("Password required, running interactive sudo");
        return payload_command(sudo_program, &exe, args, false)
            .status()
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to run with sudo privileges: {e}\n\
                 \n\
                 Run 'omg doctor --turbo' interactively to prime sudo credentials\n\
                 before retrying."
                )
            });
    }

    // Authenticated non-interactively: run the payload exactly once and
    // propagate its result. Never retried — a failing elevated command must
    // surface its own error, not trigger a second execution.
    payload_command(sudo_program, &exe, args, true)
        .status()
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to elevate privileges: {e}\n\
             \n\
             Run 'omg doctor --turbo' interactively to prime sudo credentials\n\
             before retrying."
            )
        })
}

/// Re-execute the current command under sudo, replacing this process.
///
/// Does not return on success: the elevated child handles the entire
/// command. Use only where the privileged operation IS the whole command
/// (top-of-main elevation, `elevate_if_needed`). For an elevated step inside
/// a larger flow, use [`run_privileged_child`].
pub async fn run_self_sudo(args: &[&str]) -> anyhow::Result<()> {
    let status = sudo_payload_status(args).await?;
    std::process::exit(status.code().unwrap_or(1));
}

/// Run the current command under sudo as one step inside a larger operation,
/// returning once the elevated child finishes.
///
/// Unlike [`run_self_sudo`] this never terminates the calling process:
/// success returns `Ok(())`, a nonzero child status is returned as an error,
/// and the caller continues with the rest of the flow (listing updates,
/// building AUR packages, recording history, printing summaries).
pub async fn run_privileged_child(args: &[&str]) -> anyhow::Result<()> {
    let status = sudo_payload_status(args).await?;
    if status.success() {
        return Ok(());
    }
    anyhow::bail!("Elevated command failed with exit code: {status}")
}

#[cfg(test)]
mod tests {
    #[test]
    fn install_snapshot_preserves_flow_markers_and_rejects_invalid_argv() {
        for args in [
            vec!["install", "--", "ripgrep", super::FLOW_PARENT_RECORDS],
            vec!["--json", "i", "ripgrep", super::FLOW_PARENT_RECORDS],
        ] {
            let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
            let pinned = super::snapshot_install_inputs(&args).unwrap().unwrap();
            assert_eq!(pinned.targets, args);
        }
        let invalid = vec!["--unknown-global".to_owned(), "install".to_owned()];
        assert!(super::snapshot_install_inputs(&invalid).is_err());
        for args in [
            vec!["remove", "--", "install", super::FLOW_PARENT_RECORDS],
            vec!["sync", "--", super::FLOW_PARENT_RECORDS],
            vec!["update", "--"],
            vec!["fullupdate", "--"],
            vec!["turboupdate", "--"],
            vec!["upgrade", "--"],
        ] {
            let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert!(
                super::snapshot_install_inputs(&args).unwrap().is_none(),
                "{args:?} is not an install and must still elevate"
            );
        }
    }

    #[cfg(any(feature = "arch", feature = "debian", feature = "debian-pure"))]
    #[test]
    fn install_snapshot_follows_global_flags_and_aliases() {
        use crate::core::security::artifact::{ArchiveSnapshot, is_handoff};
        use std::io::Read;

        let directory = tempfile::tempdir().unwrap();
        let archive = directory.path().join(if cfg!(feature = "arch") {
            "example-1-1-any.pkg.tar.zst"
        } else {
            "example.deb"
        });
        let path = archive.to_str().unwrap();
        for flag in [
            "--verbose",
            "-v",
            "-vv",
            "--quiet",
            "-q",
            "--json",
            "--all-commands",
        ] {
            for install in ["install", "i"] {
                for args in [
                    vec![flag, install, "--allow-local-file", path],
                    vec![install, flag, "--allow-local-file", path],
                ] {
                    std::fs::write(&archive, b"approved bytes").unwrap();
                    let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
                    let pinned = super::snapshot_install_inputs(&args)
                        .unwrap()
                        .expect("every install spelling must capture local inputs");
                    let handoff = pinned
                        .targets
                        .iter()
                        .find(|arg| is_handoff(arg))
                        .expect("archive must be sealed before authentication");
                    std::fs::write(&archive, b"replacement bytes").unwrap();
                    let snapshot = ArchiveSnapshot::capture(std::path::Path::new(handoff)).unwrap();
                    let mut contents = Vec::new();
                    snapshot
                        .reader()
                        .unwrap()
                        .read_to_end(&mut contents)
                        .unwrap();
                    assert_eq!(contents, b"approved bytes");
                }
            }
        }
    }

    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fake_sudo(
        validation_exit: i32,
        payload_exit: i32,
    ) -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let directory = tempfile::tempdir().expect("fake sudo tempdir");
        let sudo = directory.path().join("sudo");
        let log = directory.path().join("sudo.log");
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n\
             if [ \"$1\" = '-n' ] && [ \"$2\" = '-v' ]; then exit {validation_exit}; fi\n\
             exit {payload_exit}\n",
            log.display()
        );
        std::fs::write(&sudo, script).expect("write fake sudo");
        let mut permissions = std::fs::metadata(&sudo)
            .expect("fake sudo metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&sudo, permissions).expect("chmod fake sudo");
        (directory, sudo, log)
    }

    struct YesFlagReset;

    impl Drop for YesFlagReset {
        fn drop(&mut self) {
            set_yes_flag(false);
        }
    }

    #[test]
    fn payload_command_transmits_elevation_via_argv_marker() {
        // Regression: OMG_ELEVATED=1 in the child environment is stripped by
        // sudo's env_reset, which killed every fast-elevated path. The marker
        // must be part of argv instead.
        let exe = std::path::PathBuf::from("/usr/bin/omg");
        let command = payload_command(
            std::path::Path::new("sudo"),
            &exe,
            &["fullupdate", "--"],
            true,
        );
        let argv = command.as_std().get_args().collect::<Vec<_>>();
        let marker_pos = argv
            .iter()
            .position(|a| *a == ELEVATED_MARKER)
            .expect("elevation marker missing from sudo payload argv");
        // Layout: sudo … --  <exe>  <MARKER>  <payload args…>
        assert_eq!(argv[marker_pos - 1], "/usr/bin/omg");
        assert_eq!(argv[marker_pos + 1], "fullupdate");
        assert_eq!(argv[marker_pos + 2], "--");
    }

    #[test]
    fn payload_command_moves_history_ownership_out_of_package_arguments() {
        let exe = std::path::PathBuf::from("/usr/bin/omg");
        let command = payload_command(
            std::path::Path::new("sudo"),
            &exe,
            &["install", "--", "ripgrep", FLOW_PARENT_RECORDS],
            true,
        );
        let argv = command
            .as_std()
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let marker = argv
            .iter()
            .position(|argument| argument == ELEVATED_MARKER)
            .expect("elevation marker");

        assert_eq!(
            argv.get(marker + 1).map(String::as_str),
            Some(FLOW_PARENT_RECORDS)
        );
        assert_eq!(argv.get(marker + 2).map(String::as_str), Some("install"));
        assert_eq!(argv.last().map(String::as_str), Some("ripgrep"));
    }

    #[test]
    fn privileged_env_scrub_covers_dyld_and_shell_startup_vectors() {
        // A permissive sudoers env_keep must not smuggle loader or shell
        // startup variables into the root re-exec. Every entry here is a
        // documented code-execution vector for the payload's process tree
        // (dyld for macOS binaries, BASH_ENV/ENV/PS4 for sh/bash maintainer
        // scripts, *OPT for interpreter-based helpers).
        let exe = std::path::PathBuf::from("/usr/bin/omg");
        let command = payload_command(
            std::path::Path::new("sudo"),
            &exe,
            &["install", "--", "ripgrep"],
            true,
        );
        let removed: std::collections::HashSet<String> = command
            .as_std()
            .get_envs()
            .filter(|&(_, value)| value.is_none())
            .map(|(key, _)| key.to_string_lossy().into_owned())
            .collect();
        for name in [
            "APT_CONFIG",
            "OMG_PACMAN_CONF",
            "OMG_PACMAN_ROOT",
            "OMG_PACMAN_DB_DIR",
            "OMG_PACMAN_SYNC_DIR",
            "OMG_PACMAN_LOCAL_DIR",
            "OMG_PACMAN_CACHE_DIR",
            "OMG_PACMAN_CACHE_ROOT_DIR",
            "OMG_PACMAN_MIRRORLIST",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "DYLD_FALLBACK_LIBRARY_PATH",
            "BASH_ENV",
            "ENV",
            "PS4",
            "PERL5OPT",
            "PYTHONHOME",
            "RUBYOPT",
            "NODE_OPTIONS",
        ] {
            assert!(
                removed.contains(name),
                "{name} must be scrubbed from sudo children"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn failed_program_reports_signal_termination_instead_of_a_generic_exit_code() {
        use std::os::unix::process::ExitStatusExt;
        // Wait-status encoding: signal number in the low byte, exit code in the
        // high byte (std::os::unix::process::ExitStatusExt::from_raw).
        let killed = std::process::ExitStatus::from_raw(9);
        assert_eq!(
            super::describe_program_failure("dnf", &killed).to_string(),
            "dnf was terminated by signal 9"
        );
        let failed = std::process::ExitStatus::from_raw(1 << 8);
        assert_eq!(
            super::describe_program_failure("dnf", &failed).to_string(),
            "dnf failed with exit code 1"
        );
    }

    #[test]
    fn system_command_does_not_inherit_apt_config() {
        const CHILD: &str = "OMG_APT_CONFIG_SCRUB_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            assert!(std::env::var_os("APT_CONFIG").is_some());
            let output = super::system_command("printenv")
                .unwrap()
                .arg("APT_CONFIG")
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stdout.is_empty());
            return;
        }
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "core::privilege::tests::system_command_does_not_inherit_apt_config",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("APT_CONFIG", "/untrusted/apt.conf")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "isolated environment regression failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    #[cfg(unix)]
    #[test]
    fn system_command_removes_dynamic_dnf_repository_variables() {
        temp_env::with_var(
            "DNF_VAR_OMG_MIRROR",
            Some("https://attacker.invalid"),
            || {
                let command = super::system_command("printenv").unwrap();
                assert!(
                    command
                        .get_envs()
                        .any(|(name, value)| { name == "DNF_VAR_OMG_MIRROR" && value.is_none() })
                );
            },
        );
    }

    #[tokio::test]
    async fn elevation_bails_in_dev_mode_instead_of_exiting() {
        // Contract: dev-mode elevation surfaces an error and RETURNS rather
        // than terminating the process, so composite flows keep executing.
        // The injectable core guarantees no real sudo invocation occurs.
        let exe = std::env::current_exe().expect("current exe");
        let result =
            sudo_payload_status_in(std::path::Path::new("sudo"), exe, true, &["sync"]).await;
        let err = result.expect_err("dev-mode elevation must fail closed, not exit");
        assert!(err.to_string().contains("development mode"));
    }

    #[tokio::test]
    async fn cached_credentials_run_one_noninteractive_payload() {
        let (_directory, sudo, log) = fake_sudo(0, 7);
        let status = sudo_payload_status_in(
            &sudo,
            std::path::PathBuf::from("/usr/bin/omg"),
            false,
            &["sync"],
        )
        .await
        .expect("fake sudo should execute");

        assert_eq!(status.code(), Some(7), "payload status must propagate");
        let invocations = std::fs::read_to_string(log).expect("read fake sudo log");
        let lines = invocations.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2, "preflight plus exactly one payload");
        assert_eq!(lines[0], "-n -v");
        assert_eq!(
            lines[1],
            format!("-n -- /usr/bin/omg {ELEVATED_MARKER} sync"),
            "cached credentials must keep the payload noninteractive"
        );
    }

    #[tokio::test]
    async fn sudo_shaped_payload_stderr_does_not_authorize_retry() {
        let (_directory, sudo, log) = fake_sudo(0, 1);
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n\
             if [ \"$1\" = '-n' ] && [ \"$2\" = '-v' ]; then exit 0; fi\n\
             printf 'sudo: unable to execute /proc/710/exe: Permission denied\\n' >&2\n\
             exit 1\n",
            log.display()
        );
        std::fs::write(&sudo, script).expect("write sudo-shaped failure fixture");
        let status = sudo_payload_status_in(
            &sudo,
            std::path::PathBuf::from("/proc/710/exe"),
            false,
            &["sync"],
        )
        .await
        .expect("fake sudo executes");
        assert_eq!(status.code(), Some(1));
        let invocations = std::fs::read_to_string(log).expect("read invocation log");
        assert_eq!(
            invocations.lines().collect::<Vec<_>>(),
            vec![
                "-n -v".to_string(),
                format!("-n -- /proc/710/exe {ELEVATED_MARKER} sync")
            ],
            "stderr wording must not trigger a second payload"
        );
    }

    #[test]
    fn privileged_program_dev_mode_rejection_is_actionable() {
        let error = reject_privileged_program_in_dev_mode(true, "apt-get", &["update"])
            .expect_err("development mode must reject external elevation");
        let message = error.to_string();
        assert!(message.contains("development mode"));
        assert!(message.contains("apt-get"));
        assert!(message.contains("sudo"));
    }

    #[tokio::test]
    async fn failed_preflight_with_yes_never_runs_payload() {
        set_yes_flag(true);
        let _reset = YesFlagReset;
        let (_directory, sudo, log) = fake_sudo(1, 0);
        let error = sudo_payload_status_in(
            &sudo,
            std::path::PathBuf::from("/usr/bin/omg"),
            false,
            &["sync"],
        )
        .await
        .expect_err("--yes must reject a password-requiring preflight");

        assert!(
            error
                .to_string()
                .contains("--yes flag prevents password prompt")
        );
        assert_eq!(
            std::fs::read_to_string(log).expect("read fake sudo log"),
            "-n -v\n",
            "failed preflight must not execute the payload"
        );
    }

    #[test]
    fn test_elevate_for_operation_whitelist() {
        let empty_args = Vec::new();
        // Allowed operations
        assert!(elevate_for_operation("install", &empty_args).is_ok()); // Should try to elevate (mocked or skipped in test env)
        assert!(elevate_for_operation("remove", &empty_args).is_ok());
        assert!(elevate_for_operation("upgrade", &empty_args).is_ok());
        assert!(elevate_for_operation("update", &empty_args).is_ok());
        assert!(elevate_for_operation("sync", &empty_args).is_ok());
        assert!(elevate_for_operation("clean", &empty_args).is_ok());

        // Disallowed operations
        assert!(elevate_for_operation("search", &empty_args).is_err());
        assert!(elevate_for_operation("info", &empty_args).is_err());
        assert!(elevate_for_operation("status", &empty_args).is_err());
        assert!(elevate_for_operation("evil_command", &empty_args).is_err());
        assert!(elevate_for_operation("install; rm -rf /", &empty_args).is_err());
    }

    #[test]
    fn test_mock_privilege_checker_not_root() {
        let checker = MockPrivilegeChecker::new();
        assert!(!checker.is_root());
    }

    #[test]
    fn test_mock_privilege_checker_set_root() {
        let mut checker = MockPrivilegeChecker::new();
        checker.set_root(true);
        assert!(checker.is_root());
    }

    #[test]
    fn test_mock_privilege_checker_elevation_allowed() {
        let mut checker = MockPrivilegeChecker::new();
        checker.set_elevation_allowed(true);
        let args = vec!["omg".to_string(), "install".to_string()];
        assert!(checker.elevate("install", &args).is_ok());
    }

    #[test]
    fn test_mock_privilege_checker_elevation_denied() {
        let mut checker = MockPrivilegeChecker::new();
        checker.set_elevation_allowed(false);
        let args = vec!["omg".to_string(), "install".to_string()];
        assert!(checker.elevate("install", &args).is_err());
    }

    #[test]
    fn test_mock_privilege_checker_logging() {
        let checker = MockPrivilegeChecker::new();
        let args = vec![
            "omg".to_string(),
            "install".to_string(),
            "firefox".to_string(),
        ];
        let _ = checker.elevate("install", &args);

        let log = checker.get_elevation_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].0, "install");
        assert_eq!(log[0].1, args);
    }

    #[test]
    fn test_all_allowed_operations_succeed() {
        let checker = MockPrivilegeChecker::new();
        let args = vec!["omg".to_string(), "install".to_string()];

        for op in ["install", "remove", "upgrade", "update", "sync", "clean"] {
            assert!(
                checker.elevate(op, &args).is_ok(),
                "Operation {op} should succeed"
            );
        }
    }

    #[test]
    fn test_security_rejection_for_dangerous_operations() {
        let args = vec!["omg".to_string()];
        // These should be rejected by the whitelist in elevate_for_operation
        for op in ["search", "info", "status", "evil_command", "rm -rf /"] {
            assert!(
                elevate_for_operation(op, &args).is_err(),
                "Operation {op} should be rejected"
            );
        }
    }
}

#[cfg(all(test, unix))]
mod trusted_program_tests {
    use super::*;
    #[test]
    fn lookup_ignores_hostile_path_and_rejects_writable_program() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir()?;
        let fake = directory.path().join("sudo");
        std::fs::write(&fake, "#!/bin/sh\nexit 77\n")?;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755))?;
        assert!(trusted_executable_path(&fake).is_err());
        let command = system_command("sudo")?;
        assert!(std::path::Path::new(command.get_program()).is_absolute());
        assert_eq!(
            command
                .get_envs()
                .find(|(key, _)| *key == "PATH")
                .unwrap()
                .1
                .unwrap(),
            SYSTEM_PATH
        );
        Ok(())
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn elevation_uses_the_running_inode() -> anyhow::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let selected = std::fs::metadata(elevation_executable()?)?;
        let running = std::fs::metadata(format!("/proc/{}/exe", std::process::id()))?;
        assert_eq!(
            (selected.dev(), selected.ino()),
            (running.dev(), running.ino())
        );
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod elevation_path_tests {
    use super::{ElevationPathEntry, root_controlled_elevation_path};
    use std::path::Path;

    const EXECUTABLE: &str = "/usr/local/bin/omg";
    const IDENTITY: (u64, u64) = (12, 34);

    fn trusted_entry(path: &Path) -> std::io::Result<ElevationPathEntry> {
        let is_file = path == Path::new(EXECUTABLE);
        if !is_file
            && !["/", "/usr", "/usr/local", "/usr/local/bin"].contains(&path.to_str().unwrap())
        {
            return Err(std::io::ErrorKind::NotFound.into());
        }
        Ok(ElevationPathEntry {
            owner: 0,
            mode: 0o755,
            is_file,
            is_directory: !is_file,
            device: IDENTITY.0,
            inode: IDENTITY.1,
        })
    }

    #[test]
    fn matching_root_controlled_executable_is_checked_from_root_outward() {
        let mut inspected = Vec::new();
        assert!(root_controlled_elevation_path(
            Path::new(EXECUTABLE),
            IDENTITY,
            |path| {
                inspected.push(path.to_path_buf());
                trusted_entry(path)
            }
        ));
        assert_eq!(
            inspected,
            ["/", "/usr", "/usr/local", "/usr/local/bin", EXECUTABLE].map(std::path::PathBuf::from)
        );
    }

    #[test]
    fn writable_or_nonroot_file_and_ancestors_are_rejected() {
        for target in [EXECUTABLE, "/usr/local", "/"] {
            for (owner, mode) in [(1000, 0o755), (0, 0o775), (0, 0o757), (0, 0o1777)] {
                let mut inspected = Vec::new();
                let accepted =
                    root_controlled_elevation_path(Path::new(EXECUTABLE), IDENTITY, |path| {
                        inspected.push(path.to_path_buf());
                        let mut entry = trusted_entry(path)?;
                        if path == Path::new(target) {
                            entry.owner = owner;
                            entry.mode = mode;
                        }
                        Ok(entry)
                    });
                assert!(
                    !accepted,
                    "accepted {target} owned by {owner} with mode {mode:o}"
                );
                assert_eq!(
                    inspected.last().unwrap(),
                    Path::new(target),
                    "must stop before inspecting children of an untrusted ancestor"
                );
            }
        }
    }

    #[test]
    fn symlink_leaf_and_ancestors_are_rejected_without_following_them() {
        for target in [EXECUTABLE, "/usr/local"] {
            assert!(!root_controlled_elevation_path(
                Path::new(EXECUTABLE),
                IDENTITY,
                |path| {
                    let mut entry = trusted_entry(path)?;
                    if path == Path::new(target) {
                        // symlink_metadata reports neither a regular file nor directory.
                        entry.is_file = false;
                        entry.is_directory = false;
                    }
                    Ok(entry)
                }
            ));
        }
    }

    #[test]
    fn replaced_or_different_device_executable_is_rejected() {
        for identity in [(IDENTITY.0, IDENTITY.1 + 1), (IDENTITY.0 + 1, IDENTITY.1)] {
            assert!(!root_controlled_elevation_path(
                Path::new(EXECUTABLE),
                identity,
                trusted_entry
            ));
        }
    }

    #[test]
    fn missing_deleted_relative_and_parent_paths_are_rejected() {
        for candidate in [
            "/usr/local/bin/missing",
            "/usr/local/bin/omg (deleted)",
            "usr/local/bin/omg",
            "/usr/../usr/local/bin/omg",
        ] {
            assert!(!root_controlled_elevation_path(
                Path::new(candidate),
                IDENTITY,
                trusted_entry
            ));
        }
    }

    #[test]
    fn directories_and_nonexecutable_files_are_rejected() {
        for (is_file, is_directory, mode) in [(false, true, 0o755), (true, false, 0o644)] {
            assert!(!root_controlled_elevation_path(
                Path::new(EXECUTABLE),
                IDENTITY,
                |path| {
                    let mut entry = trusted_entry(path)?;
                    if path == Path::new(EXECUTABLE) {
                        entry.is_file = is_file;
                        entry.is_directory = is_directory;
                        entry.mode = mode;
                    }
                    Ok(entry)
                }
            ));
        }
    }
}
