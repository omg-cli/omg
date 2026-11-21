#![cfg(feature = "arch")]
#![expect(unsafe_code)]

pub mod alpm_harness;
use anyhow::Result;
use omg_lib::cli::run::RunCommand;
use omg_lib::cli::{
    CliContext, EnterpriseCommands, EnterprisePolicyCommands, EnvCommands, FleetCommands,
    LocalCommandRunner, ToolCommands,
};
use serial_test::serial;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

const fn get_ctx() -> CliContext {
    CliContext { json: false }
}

/// RAII guard that sets an environment variable and restores its previous
/// value (or removes it if previously unset) on drop. Every mutation is
/// paired with a restore, so tests can no longer corrupt process state for
/// concurrently running or later tests.
struct EnvGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var(key).ok();
        // SAFETY: guarded tests are #[serial]; the Drop impl restores the
        // previous value, so no mutation outlives the test.
        unsafe { std::env::set_var(key, value) };
        Self { key, previous }
    }

    /// Remove a variable for the guarded scope, restoring any previous value
    /// on drop. Needed when the code under test distinguishes "set but empty"
    /// from "unset".
    fn remove(key: &'static str) -> Self {
        let previous = std::env::var(key).ok();
        // SAFETY: see EnvGuard::set.
        unsafe { std::env::remove_var(key) };
        Self { key, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        // SAFETY: see EnvGuard::set.
        unsafe {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }
}

/// RAII guard restoring the process current directory on drop; the former
/// bare `set_current_dir` calls leaked the temp CWD into sibling tests.
struct CurrentDirGuard {
    previous: PathBuf,
}

impl CurrentDirGuard {
    fn change_to(path: &Path) -> Self {
        let previous = std::env::current_dir().expect("process must have a CWD");
        std::env::set_current_dir(path).expect("change to test CWD");
        Self { previous }
    }
}

impl Drop for CurrentDirGuard {
    fn drop(&mut self) {
        std::env::set_current_dir(&self.previous).expect("restore original CWD");
    }
}

#[tokio::test]
#[serial]
async fn test_env_capture_and_check_success() -> Result<()> {
    let temp = tempdir()?;
    let _cwd = CurrentDirGuard::change_to(temp.path());

    let ctx = get_ctx();
    let capture_cmd = EnvCommands::Capture;

    capture_cmd.execute(&ctx).await?;
    assert!(temp.path().join("omg.lock").exists());

    let check_cmd = EnvCommands::Check;
    check_cmd.execute(&ctx).await?;

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_env_check_fails_without_lock() -> Result<()> {
    let temp = tempdir()?;
    let _cwd = CurrentDirGuard::change_to(temp.path());

    let ctx = get_ctx();
    let check_cmd = EnvCommands::Check;

    let result = check_cmd.execute(&ctx).await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("No omg.lock file found")
    );

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_env_check_rejects_future_schema_lockfile() -> Result<()> {
    let temp = tempdir()?;
    let _cwd = CurrentDirGuard::change_to(temp.path());

    let ctx = get_ctx();

    // A lockfile stamped with a schema version newer than this build must be
    // rejected with an actionable message, not parsed best-effort
    // (contract: EnvironmentState::load, src/core/env/fingerprint.rs:139).
    fs::write(
        temp.path().join("omg.lock"),
        "schema_version = 99\nruntimes = {}\npackages = []\ntimestamp = 0\nhash = 'x'\n",
    )?;

    let check_cmd = EnvCommands::Check;
    let result = check_cmd.execute(&ctx).await;

    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("newer omg"),
        "future-schema lockfile must be rejected with a version-mismatch error"
    );
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_tool_list_empty() -> Result<()> {
    let temp = tempdir()?;
    // The guard restores HOME on drop; the former bare set_var leaked a fake
    // HOME into every sibling test for the rest of the binary's lifetime.
    let _home = EnvGuard::set(
        "HOME",
        temp.path().to_str().expect("temp paths are valid UTF-8"),
    );

    let ctx = get_ctx();
    let list_cmd = ToolCommands::List;
    list_cmd.execute(&ctx).await?;

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_tool_registry_output() -> Result<()> {
    let ctx = get_ctx();
    let reg_cmd = ToolCommands::Registry;
    reg_cmd.execute(&ctx).await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_tool_install_invalid_name_fails() -> Result<()> {
    let data = tempdir()?;
    let _isolated = EnvGuard::set(
        "OMG_DATA_DIR",
        data.path().to_str().expect("temp paths are valid UTF-8"),
    );
    let ctx = get_ctx();
    let install_cmd = ToolCommands::Install {
        name: "../dangerous".to_string(),
    };

    let result = install_cmd.execute(&ctx).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    // validate_package_name checks the leading dot before anything else for
    // "../dangerous", so the hidden-file rule is the deterministic rejection
    // (src/core/security/validation.rs:84-86).
    assert!(
        err.contains("cannot start with '.'"),
        "dot-prefixed name must be rejected by the hidden-file rule, got: {err}"
    );
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_fleet_status_requires_linked_account() -> Result<()> {
    let data = tempdir()?;
    let _isolated = EnvGuard::set(
        "OMG_DATA_DIR",
        data.path().to_str().expect("temp paths are valid UTF-8"),
    );
    let ctx = get_ctx();
    let status_cmd = FleetCommands::Status;

    let result = status_cmd.execute(&ctx).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("No dashboard account linked"),
        "fleet status without an account must hint at linking, got: {err}"
    );
    Ok(())
}

#[tokio::test]
#[serial]
async fn enterprise_policy_requires_linked_account() -> Result<()> {
    let data = tempdir()?;
    let _isolated = EnvGuard::set(
        "OMG_DATA_DIR",
        data.path().to_str().expect("temp paths are valid UTF-8"),
    );
    let ctx = get_ctx();
    let command = EnterpriseCommands::Policy {
        command: EnterprisePolicyCommands::Show { scope: None },
    };
    let error = command
        .execute(&ctx)
        .await
        .expect_err("policy show talks to the dashboard");
    assert!(
        error.to_string().contains("No dashboard account linked"),
        "policy show without an account must hint at linking, got: {error:#}"
    );
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_run_invalid_task_fails() -> Result<()> {
    let ctx = get_ctx();
    let run_cmd = RunCommand {
        task: "dangerous; command".to_string(),
        args: vec![],
        watch: false,
        parallel: false,
        using: None,
        all: false,
    };

    let result = run_cmd.execute(&ctx).await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Invalid task name")
    );
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_run_detect_and_execute_mock_task() -> Result<()> {
    let temp = tempdir()?;
    let _cwd = CurrentDirGuard::change_to(temp.path());

    fs::write(temp.path().join("Makefile"), "test:\n\t@touch ran.marker\n")?;

    let ctx = get_ctx();
    let run_cmd = RunCommand {
        task: "test".to_string(),
        args: vec![],
        watch: false,
        parallel: false,
        using: Some("make".to_string()),
        all: false,
    };

    run_cmd.execute(&ctx).await?;

    // Success alone could mean the command was merely accepted; the marker
    // proves the make recipe actually executed.
    assert!(
        temp.path().join("ran.marker").exists(),
        "make task must have executed its recipe"
    );

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_tool_install_not_in_registry_fails() -> Result<()> {
    // The guard restores the previous OMG_TEST_MODE value on drop instead of
    // removing it unconditionally (the suite-wide init relies on it staying set).
    let _test_mode = EnvGuard::set("OMG_TEST_MODE", "1");
    let ctx = get_ctx();
    let install_cmd = ToolCommands::Install {
        name: "non-existent-tool-xyz-123".to_string(),
    };

    let result = install_cmd.execute(&ctx).await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not in registry"));

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_env_share_missing_token_fails() -> Result<()> {
    let temp = tempdir()?;
    let _cwd = CurrentDirGuard::change_to(temp.path());
    fs::write(temp.path().join("omg.lock"), "{}")?;

    // The guard restores any previously set GITHUB_TOKEN on drop instead of
    // removing it for the rest of the process lifetime. `remove` (not
    // `set("")`) because the code under test distinguishes unset from empty.
    let _token = EnvGuard::remove("GITHUB_TOKEN");

    let ctx = get_ctx();
    let share_cmd = EnvCommands::Share {
        description: "test".to_string(),
        public: false,
    };

    let result = share_cmd.execute(&ctx).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("GITHUB_TOKEN"));

    Ok(())
}
