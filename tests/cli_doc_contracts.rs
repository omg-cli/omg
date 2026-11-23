//! Documentation-backed CLI and machine contract tests.
//!
//! Ensures core documented commands in `docs/cli.md`, `--json` output contracts,
//! `--version`, and `contracts/service-api-v1.json` stay in sync with the
//! compiled `omg` binary without needing VMs or network access.

pub mod common;

use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn omg_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_omg"));
    cmd.env("OMG_TEST_MODE", "1")
        .env("OMG_DISABLE_DAEMON", "1")
        .env("OMG_NO_TELEMETRY", "1")
        .env("OMG_DISABLE_TELEMETRY", "1");
    cmd
}

#[test]
fn documented_cli_commands_match_compiled_help_and_version() -> anyhow::Result<()> {
    let cli_doc = std::fs::read_to_string(repo_root().join("docs/cli.md"))?;

    let version_out = omg_cmd().arg("--version").output()?;
    assert!(
        version_out.status.success(),
        "omg --version failed: {}",
        String::from_utf8_lossy(&version_out.stderr)
    );
    let version_text = String::from_utf8_lossy(&version_out.stdout);
    assert!(
        version_text.contains(env!("CARGO_PKG_VERSION")),
        "omg --version output `{version_text}` omitted crate version {}",
        env!("CARGO_PKG_VERSION")
    );

    let help_out = omg_cmd().args(["--help", "--all-commands"]).output()?;
    assert!(
        help_out.status.success(),
        "omg --help --all-commands failed: {}",
        String::from_utf8_lossy(&help_out.stderr)
    );
    let help_text = String::from_utf8_lossy(&help_out.stdout);

    for cmd_name in [
        "search",
        "info",
        "status",
        "outdated",
        "doctor",
        "list",
        "use",
        "which",
        "env",
        "audit",
        "daemon-status",
    ] {
        let heading = format!("### omg {cmd_name}");
        assert!(
            cli_doc.contains(&heading),
            "docs/cli.md is missing documented section `{heading}`"
        );
        assert!(
            help_text.contains(cmd_name),
            "omg --help omitted documented command `{cmd_name}`"
        );
        let sub_help = omg_cmd().args([cmd_name, "--help"]).output()?;
        assert!(
            sub_help.status.success(),
            "omg {cmd_name} --help failed: {}",
            String::from_utf8_lossy(&sub_help.stderr)
        );
    }

    Ok(())
}

#[test]
fn service_api_contract_schema_is_valid_and_complete() -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(repo_root().join("contracts/service-api-v1.json"))?;
    let contract: Value = serde_json::from_str(&raw)?;
    assert_eq!(contract["schemaVersion"], json!(1));
    let origin = contract["origin"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing origin string"))?;
    assert!(
        origin.starts_with("https://"),
        "service origin must use HTTPS: {origin}"
    );
    let endpoints = contract["cliEndpoints"]
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("missing cliEndpoints object"))?;
    for required in ["validateLicense", "reportUsage", "installPing", "cliBatch"] {
        assert!(
            endpoints.contains_key(required),
            "contracts/service-api-v1.json missing `{required}`"
        );
    }
    Ok(())
}

#[test]
fn json_cli_contracts_emit_valid_json_in_test_mode() -> anyhow::Result<()> {
    let project = common::TestProject::for_distro("debian");
    let state_path = project.data_dir.path().join("mock_state_apt.json");
    let fixture = serde_json::to_vec(&json!({
        "installed": {"bash": "5.2.21"},
        "available": {"bash": "5.2.21"}
    }))?;
    std::fs::write(state_path, fixture)?;

    let outdated = project.run_with_env(
        &["outdated", "--json"],
        &[("OMG_TEST_COMMAND_TIMEOUT_SECS", "10")],
    );
    assert!(
        outdated.success,
        "omg outdated --json failed: {}",
        outdated.combined_output()
    );
    let outdated_json: Value = serde_json::from_str(outdated.stdout.trim())?;
    assert!(
        outdated_json.is_array(),
        "omg outdated --json must return a JSON array: {}",
        outdated.stdout
    );

    let list = project.run_with_env(
        &["list", "--json"],
        &[("OMG_TEST_COMMAND_TIMEOUT_SECS", "10")],
    );
    assert!(
        list.success,
        "omg list --json failed: {}",
        list.combined_output()
    );
    let list_json: Value = serde_json::from_str(list.stdout.trim())?;
    assert!(
        list_json.is_array() || list_json.is_object(),
        "omg list --json must emit valid structured JSON: {}",
        list.stdout
    );

    project.close_checked();
    Ok(())
}
