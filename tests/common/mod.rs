//! OMG Test Infrastructure - Fortune 500 Grade
//!
//! Comprehensive testing utilities, fixtures, mocks, and helpers
//! for enterprise-grade test coverage.
// The single `unsafe` block in `init_test_env` is deliberate and documented
// inline; this module-level expectation keeps the crate-wide
// `unsafe_code = "warn"` lint from flagging it while still erroring if a new
// unreviewed unsafe block appears here.
#![expect(unsafe_code)]

pub mod assertions;
pub mod fixtures;
pub mod mocks;

use anyhow::Result;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Once;
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

// Re-export serial_test for use in test files.
pub use serial_test::serial;

// ═══════════════════════════════════════════════════════════════════════════════
// TEST CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

static INIT: Once = Once::new();

/// Initialize test environment (called once per test run)
///
/// Note: Environment variables are set once at initialization. Tests that need
/// to modify environment variables should use [`with_test_env`] inside a
/// `#[serial]`-marked test instead of mutating the process environment.
pub fn init_test_env() {
    INIT.call_once(|| {
        // SAFETY: This is the suite's single deliberate process-environment
        // mutation outside a scoped guard. The three constants are written
        // once via `Once::call_once` before tests mutate environment state
        // under `#[serial]`. Child processes either receive explicit values
        // from `run_omg_with_options` or inherit these stable constants.
        unsafe {
            std::env::set_var("OMG_TEST_MODE", "1");
            std::env::set_var("OMG_DISABLE_TELEMETRY", "1");
            std::env::set_var("OMG_LOG_LEVEL", "warn");
        }
    });
}

/// Run `f` with scoped process environment variables.
///
/// Thin wrapper over `temp_env::with_vars` so individual tests never need
/// `unsafe` blocks or manual restore logic; variables are restored when `f`
/// returns. Use it within a `#[serial]`-marked test (or while holding the
/// suite's environment lock) so no other thread observes the mutated values.
pub fn with_test_env<R>(vars: &[(&str, &str)], f: impl FnOnce() -> R) -> R {
    let vars: Vec<(&str, Option<&str>)> = vars
        .iter()
        .map(|&(key, value)| (key, Some(value)))
        .collect();
    temp_env::with_vars(vars, f)
}

/// Test configuration flags
#[derive(Debug, Clone)]
pub struct TestConfig {
    pub run_system_tests: bool,
    pub run_network_tests: bool,
    pub run_destructive_tests: bool,
    pub target_distro: Option<String>,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            run_system_tests: env::var("OMG_RUN_SYSTEM_TESTS")
                .map(|v| v == "1")
                .unwrap_or(cfg!(feature = "docker_tests")),
            run_network_tests: env::var("OMG_RUN_NETWORK_TESTS")
                .map(|v| v == "1")
                .unwrap_or(cfg!(feature = "docker_tests")),
            run_destructive_tests: env::var("OMG_RUN_DESTRUCTIVE_TESTS")
                .map(|v| v == "1")
                .unwrap_or(cfg!(feature = "docker_tests")),
            target_distro: env::var("OMG_TEST_DISTRO").ok(),
        }
    }
}

impl TestConfig {
    pub fn skip_if_no_system(&self, test_name: &str) -> bool {
        if self.run_system_tests {
            false
        } else {
            eprintln!("⏭️  Skipping {test_name} (set OMG_RUN_SYSTEM_TESTS=1)");
            true
        }
    }

    pub fn skip_if_no_network(&self, test_name: &str) -> bool {
        if self.run_network_tests {
            false
        } else {
            eprintln!("⏭️  Skipping {test_name} (set OMG_RUN_NETWORK_TESTS=1)");
            true
        }
    }

    pub fn skip_if_no_destructive(&self, test_name: &str) -> bool {
        if self.run_destructive_tests {
            false
        } else {
            eprintln!("⏭️  Skipping {test_name} (set OMG_RUN_DESTRUCTIVE_TESTS=1)");
            true
        }
    }

    pub fn is_arch(&self) -> bool {
        self.target_distro.as_deref() == Some("arch") || Path::new("/etc/arch-release").exists()
    }

    pub fn is_debian(&self) -> bool {
        self.target_distro.as_deref() == Some("debian")
            || (Path::new("/etc/debian_version").exists() && !self.is_ubuntu())
    }

    pub fn is_ubuntu(&self) -> bool {
        self.target_distro.as_deref() == Some("ubuntu")
            || fs::read_to_string("/etc/os-release").is_ok_and(|s| s.contains("Ubuntu"))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMMAND EXECUTION
// ═══════════════════════════════════════════════════════════════════════════════

/// Result from running an OMG command
#[derive(Debug, Clone)]
pub struct CommandResult {
    pub success: bool,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandResult {
    pub fn combined_output(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }

    pub fn contains(&self, needle: &str) -> bool {
        self.stdout.contains(needle) || self.stderr.contains(needle)
    }

    pub fn stdout_contains(&self, needle: &str) -> bool {
        self.stdout.contains(needle)
    }

    pub fn stderr_contains(&self, needle: &str) -> bool {
        self.stderr.contains(needle)
    }

    pub fn assert_success(&self) {
        assert!(
            self.success,
            "Command failed with exit code {}:\nstdout: {}\nstderr: {}",
            self.exit_code, self.stdout, self.stderr
        );
    }

    pub fn assert_failure(&self) {
        assert!(
            !self.success,
            "Command unexpectedly succeeded:\nstdout: {}\nstderr: {}",
            self.stdout, self.stderr
        );
    }

    pub fn assert_stdout_contains(&self, needle: &str) {
        assert!(
            self.stdout.contains(needle),
            "stdout does not contain '{}'\nstdout: {}",
            needle,
            self.stdout
        );
    }

    pub fn assert_stderr_contains(&self, needle: &str) {
        assert!(
            self.stderr.contains(needle),
            "stderr does not contain '{}'\nstderr: {}",
            needle,
            self.stderr
        );
    }

    pub fn assert_no_ansi(&self) {
        assert!(
            !self.combined_output().contains("\u{1b}["),
            "redirected output contains ANSI escapes\nstdout: {}\nstderr: {}",
            self.stdout,
            self.stderr
        );
    }
}

/// Run an OMG command
pub fn run_omg(args: &[&str]) -> CommandResult {
    run_omg_with_options(args, None, &[])
}

/// Run an OMG command in a specific directory
pub fn run_omg_in_dir(args: &[&str], dir: &Path) -> CommandResult {
    run_omg_with_options(args, Some(dir), &[])
}

/// Run an OMG command with environment variables
pub fn run_omg_with_env(args: &[&str], env_vars: &[(&str, &str)]) -> CommandResult {
    run_omg_with_options(args, None, env_vars)
}

/// Run an OMG command with full options
fn command_timeout(env_vars: &[(&str, &str)]) -> Duration {
    let configured = env_vars
        .iter()
        .find(|(key, _)| *key == "OMG_TEST_COMMAND_TIMEOUT_SECS")
        .map(|(_, value)| (*value).to_string())
        .or_else(|| env::var("OMG_TEST_COMMAND_TIMEOUT_SECS").ok());
    configured
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .map_or(Duration::from_mins(1), Duration::from_secs)
}

pub fn run_omg_with_options(
    args: &[&str],
    dir: Option<&Path>,
    env_vars: &[(&str, &str)],
) -> CommandResult {
    let home = TempDir::new().expect("Failed to create isolated home");
    let result = run_omg_with_home(args, dir, env_vars, home.path());
    home.close().expect("Failed to clean isolated CLI home");
    result
}

fn run_omg_with_home(
    args: &[&str],
    dir: Option<&Path>,
    env_vars: &[(&str, &str)],
    home: &Path,
) -> CommandResult {
    #[cfg(not(debug_assertions))]
    panic!("Hermetic CLI tests require the debug profile; release binaries ignore OMG_TEST_MODE");
    let start = Instant::now();
    let command_timeout = command_timeout(env_vars);

    if let Some(expected) = std::env::var_os("OMG_CONTRACT_EXPECTED_CLI") {
        assert_eq!(
            std::fs::canonicalize(env!("CARGO_BIN_EXE_omg")).expect("CLI executable exists"),
            std::fs::canonicalize(expected).expect("Receipt subject exists"),
            "CLI fixture executable differs from the admitted receipt subject"
        );
    }
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_omg"));
    cmd.args(args)
        .env("OMG_TEST_MODE", "1")
        .env("OMG_DISABLE_DAEMON", "1")
        .env("OMG_DISABLE_TELEMETRY", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Never inherit host home/cache paths. Explicit overrides are applied below,
    // including deliberately invalid HOME values used by security tests.
    cmd.env("HOME", home);
    for (key, relative_path) in [
        ("XDG_CONFIG_HOME", ".config"),
        ("XDG_DATA_HOME", ".local/share"),
        ("XDG_CACHE_HOME", ".cache"),
        ("XDG_STATE_HOME", ".local/state"),
        ("XDG_RUNTIME_DIR", ".run"),
        ("XDG_CONFIG_DIRS", ".config"),
        ("XDG_DATA_DIRS", ".local/share"),
        ("OMG_DATA_DIR", ".local/share/omg"),
        ("OMG_CONFIG_DIR", ".config/omg"),
        ("OMG_CACHE_DIR", ".cache/omg"),
        ("NVM_DIR", ".nvm"),
    ] {
        let path = home.join(relative_path);
        fs::create_dir_all(&path).expect("Failed to create isolated CLI directory");
        cmd.env(key, path);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(home.join(".run"), fs::Permissions::from_mode(0o700))
            .expect("Failed to secure isolated runtime directory");
    }
    if !env_vars.iter().any(|(key, _)| *key == "OMG_TEST_DISTRO") {
        cmd.env("OMG_TEST_DISTRO", "arch");
    }

    if let Some(d) = dir {
        cmd.current_dir(d);
    }

    for (key, value) in env_vars {
        cmd.env(key, value);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);
    }
    let mut child = cmd.spawn().expect("Failed to execute omg");
    #[cfg(unix)]
    let terminate_group = {
        let group =
            nix::unistd::Pid::from_raw(i32::try_from(child.id()).expect("child PID fits pid_t"));
        move || match nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL) {
            Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
            Err(error) => panic!("Failed to terminate test process group: {error}"),
        }
    };

    // Drain both pipes on dedicated threads so a chatty child can never fill
    // the OS pipe buffer and block on write while we enforce the timeout.
    let mut stdout_pipe = child.stdout.take().expect("invariant: stdout is piped");
    let mut stderr_pipe = child.stderr.take().expect("invariant: stderr is piped");
    let (stdout_tx, stdout_rx) = std::sync::mpsc::channel();
    let (stderr_tx, stderr_rx) = std::sync::mpsc::channel();
    let stdout_handle = thread::spawn(move || {
        let mut buffer = Vec::new();
        let result = stdout_pipe.read_to_end(&mut buffer).map(|_| buffer);
        let _ = stdout_tx.send(result);
    });
    let stderr_handle = thread::spawn(move || {
        let mut buffer = Vec::new();
        let result = stderr_pipe.read_to_end(&mut buffer).map(|_| buffer);
        let _ = stderr_tx.send(result);
    });

    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() >= command_timeout {
                    timed_out = true;
                    #[cfg(unix)]
                    terminate_group();
                    let _ = child.kill();
                    break;
                }

                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => panic!("Failed waiting for omg process: {error}"),
        }
    }

    #[cfg(unix)]
    terminate_group();
    let output_status = child.wait().expect("Failed to reap omg process");
    let drain_timeout = Duration::from_secs(1);
    let stdout_bytes = stdout_rx
        .recv_timeout(drain_timeout)
        .expect("stdout drain exceeded its deadline after process-group cleanup")
        .expect("Failed reading command stdout");
    let stderr_bytes = stderr_rx
        .recv_timeout(drain_timeout)
        .expect("stderr drain exceeded its deadline after process-group cleanup")
        .expect("Failed reading command stderr");
    stdout_handle.join().expect("stdout reader panicked");
    stderr_handle.join().expect("stderr reader panicked");
    let mut stderr = String::from_utf8_lossy(&stderr_bytes).to_string();
    if timed_out {
        if !stderr.ends_with('\n') && !stderr.is_empty() {
            stderr.push('\n');
        }
        let _ = write!(
            stderr,
            "[test harness timeout] command exceeded {:?}: omg {}",
            command_timeout,
            args.join(" ")
        );
    }

    CommandResult {
        success: output_status.success(),
        exit_code: output_status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&stdout_bytes).to_string(),
        stderr,
    }
}

/// Run a raw shell command
fn run_shell(cmd: &str) -> CommandResult {
    let output = Command::new("sh")
        .args(["-c", cmd])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to execute shell command");

    CommandResult {
        success: output.status.success(),
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TEST PROJECT HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

/// A test project with managed temp directory
pub struct TestProject {
    pub dir: TempDir,
    pub home_dir: TempDir,
    pub data_dir: TempDir,
    pub config_dir: TempDir,
    pub pacman_root: TempDir,
    pub config: TestConfig,
}

impl TestProject {
    /// Successful behavioral receipts require observed cleanup, not silent Drop.
    pub fn close_checked(self) {
        for directory in [
            self.dir,
            self.home_dir,
            self.data_dir,
            self.config_dir,
            self.pacman_root,
        ] {
            let path = directory.path().to_path_buf();
            directory.close().expect("Failed to clean contract fixture");
            assert!(
                !path.exists(),
                "Contract fixture survived cleanup: {}",
                path.display()
            );
        }
    }

    pub fn new() -> Self {
        init_test_env();
        Self {
            dir: TempDir::new().expect("Failed to create temp dir"),
            home_dir: TempDir::new().expect("Failed to create isolated home"),
            data_dir: TempDir::new().expect("Failed to create data dir"),
            config_dir: TempDir::new().expect("Failed to create config dir"),
            pacman_root: TempDir::new().expect("Failed to create pacman root"),
            config: TestConfig::default(),
        }
    }

    pub fn for_distro(distro: &str) -> Self {
        let mut project = Self::new();
        project.config.target_distro = Some(distro.to_string());
        project
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    fn distro(&self) -> &str {
        self.config.target_distro.as_deref().unwrap_or("arch")
    }

    fn utf8_path(path: &Path) -> &str {
        path.to_str()
            .expect("invariant: test temporary paths must be valid UTF-8")
    }

    pub fn run(&self, args: &[&str]) -> CommandResult {
        self.run_with_env(args, &[])
    }

    pub fn run_with_env(&self, args: &[&str], env_vars: &[(&str, &str)]) -> CommandResult {
        let data_dir = Self::utf8_path(self.data_dir.path());
        let config_dir = Self::utf8_path(self.config_dir.path());
        let pacman_root = Self::utf8_path(self.pacman_root.path());
        let cache_dir = self.data_dir.path().join("cache");
        let cache_dir = Self::utf8_path(&cache_dir);
        let mut vars = env_vars.to_vec();
        if !vars.iter().any(|(k, _)| *k == "OMG_DATA_DIR") {
            vars.push(("OMG_DATA_DIR", data_dir));
        }
        if !vars.iter().any(|(k, _)| *k == "OMG_CONFIG_DIR") {
            vars.push(("OMG_CONFIG_DIR", config_dir));
        }
        if !vars.iter().any(|(k, _)| *k == "OMG_CACHE_DIR") {
            vars.push(("OMG_CACHE_DIR", cache_dir));
        }
        if !vars.iter().any(|(k, _)| *k == "OMG_PACMAN_ROOT") {
            vars.push(("OMG_PACMAN_ROOT", pacman_root));
        }
        if !vars.iter().any(|(k, _)| *k == "OMG_TEST_DISTRO") {
            vars.push(("OMG_TEST_DISTRO", self.distro()));
        }
        run_omg_with_home(args, Some(self.path()), &vars, self.home_dir.path())
    }

    pub fn mock_install(&self, package: &str, version: &str) -> Result<()> {
        update_mock_state(self.data_dir.path(), self.distro(), package, version, true)
    }

    pub fn mock_available(&self, package: &str, version: &str) -> Result<()> {
        update_mock_state(self.data_dir.path(), self.distro(), package, version, false)
    }

    /// Create a file in the project
    pub fn create_file(&self, name: &str, content: &str) -> PathBuf {
        let path = self.path().join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, content).unwrap();
        path
    }

    /// Create a directory in the project
    pub fn create_dir(&self, name: &str) -> PathBuf {
        let path = self.path().join(name);
        fs::create_dir_all(&path).unwrap();
        path
    }

    /// Read a file from the project
    pub fn read_file(&self, name: &str) -> Option<String> {
        fs::read_to_string(self.path().join(name)).ok()
    }

    /// Check if a file exists
    pub fn file_exists(&self, name: &str) -> bool {
        self.path().join(name).exists()
    }

    // Project templates

    pub fn with_node_project(&self) -> &Self {
        self.create_file(".nvmrc", "20.10.0");
        self.create_file(
            "package.json",
            r#"{"name": "test", "engines": {"node": ">=18.0.0"}}"#,
        );
        self
    }

    pub fn with_python_project(&self) -> &Self {
        self.create_file(".python-version", "3.11.0");
        self.create_file("requirements.txt", "requests==2.31.0\npytest==7.4.0");
        self
    }

    pub fn with_tool_versions(&self, versions: &[(&str, &str)]) -> &Self {
        let content: String = versions
            .iter()
            .map(|(k, v)| format!("{k} {v}"))
            .collect::<Vec<_>>()
            .join("\n");
        self.create_file(".tool-versions", &content);
        self
    }

    pub fn with_omg_lock(&self, content: &str) -> &Self {
        self.create_file("omg.lock", content);
        self
    }

    pub fn with_security_policy(&self, policy: &str) -> &Self {
        // `SecurityPolicy::load_default` reads `paths::config_dir()` (i.e.
        // `$OMG_CONFIG_DIR` verbatim, which already ends in `omg`) plus
        // `policy.toml`. Writing to a nested `omg/` subdirectory would place
        // the file where the app never looks, so every policy test would
        // silently run against the built-in default.
        let path = self.config_dir.path().join("policy.toml");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, policy).unwrap();
        self
    }
}

impl Default for TestProject {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PACKAGE MANAGER DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

/// Detect the current distro's package manager
fn detect_package_manager() -> Option<&'static str> {
    if Path::new("/usr/bin/pacman").exists() {
        Some("pacman")
    } else if Path::new("/usr/bin/apt").exists() {
        Some("apt")
    } else if Path::new("/usr/bin/dnf").exists() {
        Some("dnf")
    } else {
        None
    }
}

/// Check if a package is installed (distro-agnostic)
pub fn is_package_installed(name: &str) -> bool {
    match detect_package_manager() {
        Some("pacman") => run_shell(&format!("pacman -Q {name} 2>/dev/null")).success,
        Some("apt") => run_shell(&format!("dpkg -l {name} 2>/dev/null | grep -q '^ii'")).success,
        _ => false,
    }
}

fn update_mock_state(
    data_dir: &Path,
    distro: &str,
    package: &str,
    version: &str,
    is_install: bool,
) -> Result<()> {
    let package_manager =
        omg_lib::package_managers::mock::MockPackageManager::new_in(distro, data_dir);
    if is_install {
        package_manager.set_installed_version(package, version)
    } else {
        package_manager.set_available_version(package, version)
    }
}

// ===========================================================================
// SKIP REPORTING
// ===========================================================================

/// Record and announce a runtime skip with its reason. Prefer
/// `#[ignore = "reason"]` for statically-known skips; use this only for
/// conditions discoverable at runtime.
pub fn report_skip(reason: &str) {
    eprintln!("[omg-skip] {reason}");
}

// ═══════════════════════════════════════════════════════════════════════════════
// TEST MACROS
// ═══════════════════════════════════════════════════════════════════════════════

/// Require system tests to be enabled
#[macro_export]
macro_rules! require_system_tests {
    () => {
        let config = $crate::common::TestConfig::default();
        if config.skip_if_no_system(module_path!()) {
            $crate::common::report_skip("system tests disabled (set OMG_RUN_SYSTEM_TESTS=1)");
            return;
        }
    };
}

/// Require network tests to be enabled
#[macro_export]
macro_rules! require_network_tests {
    () => {
        let config = $crate::common::TestConfig::default();
        if config.skip_if_no_network(module_path!()) {
            $crate::common::report_skip("network tests disabled (set OMG_RUN_NETWORK_TESTS=1)");
            return;
        }
    };
}

/// Require destructive tests to be enabled
#[macro_export]
macro_rules! require_destructive_tests {
    () => {
        let config = $crate::common::TestConfig::default();
        if config.skip_if_no_destructive(module_path!()) {
            $crate::common::report_skip(
                "destructive tests disabled (set OMG_RUN_DESTRUCTIVE_TESTS=1)",
            );
            return;
        }
    };
}

/// Require Arch Linux
#[macro_export]
macro_rules! require_arch {
    () => {
        let config = $crate::common::TestConfig::default();
        if !config.is_arch() {
            $crate::common::report_skip("requires Arch Linux");
            return;
        }
    };
}

/// Require Debian
#[macro_export]
macro_rules! require_debian {
    () => {
        let config = $crate::common::TestConfig::default();
        if !config.is_debian() {
            $crate::common::report_skip("requires Debian");
            return;
        }
    };
}

/// Require Ubuntu
#[macro_export]
macro_rules! require_ubuntu {
    () => {
        let config = $crate::common::TestConfig::default();
        if !config.is_ubuntu() {
            $crate::common::report_skip("requires Ubuntu");
            return;
        }
    };
}

/// Isolated daemon state for handler-level tests: temp dirs, mock Arch
/// backend, empty index. Shared so cache, concurrency, and IPC fixtures
/// cannot drift apart.
#[cfg(feature = "arch")]
pub struct DaemonTestFixture {
    _temp_dir: TempDir,
    pub state: std::sync::Arc<omg_lib::daemon::handlers::DaemonState>,
}

#[cfg(feature = "arch")]
impl DaemonTestFixture {
    pub fn new() -> Result<Self> {
        let temp_dir = TempDir::new()?;
        let data_dir = temp_dir.path().join("data");
        let package_manager = std::sync::Arc::new(
            omg_lib::package_managers::mock::MockPackageManager::new_in("arch", &data_dir),
        );
        let state = std::sync::Arc::new(omg_lib::daemon::handlers::DaemonState::new_isolated(
            &data_dir,
            omg_lib::daemon::index::PackageIndex::empty(),
            package_manager,
        )?);
        Ok(Self {
            _temp_dir: temp_dir,
            state,
        })
    }

    pub async fn send_request(
        &self,
        request: omg_lib::daemon::protocol::Request,
    ) -> omg_lib::daemon::protocol::Response {
        omg_lib::daemon::handlers::handle_request(std::sync::Arc::clone(&self.state), request).await
    }
}

#[cfg(test)]
mod tests {
    use super::command_timeout;
    use std::time::Duration;

    #[test]
    fn explicit_timeout_overrides_inherited_timeout() {
        let timeout = command_timeout(&[("OMG_TEST_COMMAND_TIMEOUT_SECS", "2")]);
        assert_eq!(timeout, Duration::from_secs(2));
    }
}
