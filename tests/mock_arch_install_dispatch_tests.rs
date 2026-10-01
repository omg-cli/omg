#![cfg(feature = "arch")]
//! Install-only debug adapter contracts, not native package-system evidence.

pub mod common;

use anyhow::Result;
use common::TestProject;

fn run(project: &TestProject, args: &[&str]) -> common::CommandResult {
    project.run_with_env(args, &[("OMG_TEST_COMMAND_TIMEOUT_SECS", "5")])
}

fn state(project: &TestProject) -> Result<serde_json::Value> {
    Ok(serde_json::from_slice(&std::fs::read(
        project.data_dir.path().join("mock_state_pacman.json"),
    )?)?)
}

#[test]
fn known_install_records_arch_state_and_history_without_generic_summary() -> Result<()> {
    let project = TestProject::for_distro("arch");
    let result = run(&project, &["install", "--yes", "git"]);
    result.assert_success();
    assert!(!result.stdout.contains("Installed 1 package"));
    assert_eq!(state(&project)?["installed"]["git"], "2.43.0");
    let history = run(&project, &["history", "--json"]);
    history.assert_success();
    let records: Vec<omg_lib::core::history::Transaction> = serde_json::from_str(&history.stdout)?;
    assert_eq!(records.len(), 1);
    assert!(records[0].success);
    assert_eq!(
        records[0].transaction_type,
        omg_lib::core::history::TransactionType::Install
    );
    assert_eq!(records[0].changes[0].name, "git");
    assert_eq!(records[0].changes[0].source, "pacman");
    project.close_checked();
    Ok(())
}

#[test]
fn missing_install_fails_without_aur_or_invented_success() {
    let project = TestProject::for_distro("arch");
    let result = run(&project, &["install", "--yes", "missing-fixture-package"]);
    result.assert_failure();
    let output = result.combined_output();
    assert!(output.contains("missing-fixture-package"), "{output}");
    assert!(output.contains("not found"), "{output}");
    assert!(!output.contains("on the AUR"), "{output}");
    assert!(
        !project
            .data_dir
            .path()
            .join("mock_state_pacman.json")
            .exists()
    );
    project.close_checked();
}

#[test]
fn mixed_missing_request_keeps_official_state_and_failed_arch_history() -> Result<()> {
    let project = TestProject::for_distro("arch");
    let result = run(
        &project,
        &["install", "--yes", "git", "missing-fixture-package"],
    );
    result.assert_failure();
    assert!(result.combined_output().contains("missing-fixture-package"));
    assert_eq!(state(&project)?["installed"]["git"], "2.43.0");
    assert!(
        state(&project)?["installed"]
            .get("missing-fixture-package")
            .is_none()
    );
    let history = run(&project, &["history", "--json"]);
    history.assert_success();
    let records: Vec<omg_lib::core::history::Transaction> = serde_json::from_str(&history.stdout)?;
    assert_eq!(records.len(), 1);
    assert!(!records[0].success);
    assert_eq!(records[0].changes.len(), 1);
    assert_eq!(records[0].changes[0].name, "git");
    assert_eq!(records[0].changes[0].source, "pacman");
    project.close_checked();
    Ok(())
}

#[test]
fn previews_use_arch_catalog_and_missing_names_never_mutate() {
    let project = TestProject::for_distro("arch");
    let known = run(&project, &["install", "--dry-run", "git"]);
    known.assert_success();
    assert!(known.stdout.contains("2.43.0"));
    assert!(known.stdout.contains("Official"));
    let missing = run(
        &project,
        &["install", "--dry-run", "missing-fixture-package"],
    );
    missing.assert_failure();
    assert!(missing.combined_output().contains("not found"));
    assert!(
        !project
            .data_dir
            .path()
            .join("mock_state_pacman.json")
            .exists()
    );
    assert!(!project.data_dir.path().join("history.json").exists());
    project.close_checked();
}

#[test]
fn unreadable_archive_reaches_arch_metadata_validation_without_mutation() -> Result<()> {
    let project = TestProject::for_distro("arch");
    let archive = project.path().join("unreadable.pkg.tar.zst");
    std::fs::write(&archive, b"not a package archive")?;
    let target = archive
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("fixture path is not UTF-8"))?;
    let root = project.pacman_root.path().canonicalize()?;
    let database = root.join("var/lib/pacman");
    std::fs::create_dir_all(&database)?;
    assert!(std::fs::symlink_metadata(&database)?.file_type().is_dir());
    assert!(
        !std::fs::symlink_metadata(&database)?
            .file_type()
            .is_symlink()
    );
    assert!(database.is_absolute() && database.canonicalize()?.starts_with(&root));
    let database_path = database
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("fixture database path is not UTF-8"))?;
    let environment = [
        ("OMG_TEST_COMMAND_TIMEOUT_SECS", "5"),
        ("OMG_PACMAN_DB_DIR", database_path),
    ];
    let refusal = project.run_with_env(&["install", "--dry-run", target], &environment);
    refusal.assert_failure();
    let output = refusal.combined_output();
    assert!(
        output.contains("Local package archives require explicit consent: pass --allow-local-file after reviewing the archive source"),
        "{output}"
    );
    assert!(
        !output.contains("Failed to read local package metadata"),
        "{output}"
    );
    assert!(!output.contains("not found"), "{output}");
    assert_eq!(std::fs::read(&archive)?, b"not a package archive");
    assert!(
        !project
            .data_dir
            .path()
            .join("mock_state_pacman.json")
            .exists()
    );
    assert!(!project.data_dir.path().join("history.json").exists());

    let result = project.run_with_env(
        &["install", "--dry-run", "--allow-local-file", target],
        &environment,
    );
    result.assert_failure();
    let output = result.combined_output();
    assert!(
        output.contains("Failed to read local package metadata"),
        "{output}"
    );
    assert!(!output.contains("Invalid package name"), "{output}");
    assert_eq!(std::fs::read(&archive)?, b"not a package archive");
    assert!(
        !project
            .data_dir
            .path()
            .join("mock_state_pacman.json")
            .exists()
    );
    assert!(!project.data_dir.path().join("history.json").exists());
    project.close_checked();
    Ok(())
}

#[test]
fn fedora_mock_keeps_generic_install_dispatch() {
    let project = TestProject::for_distro("fedora");
    let result = run(&project, &["install", "--yes", "git"]);
    result.assert_success();
    assert!(result.stdout.contains("Installed 1 package"));
    assert!(project.data_dir.path().join("mock_state_dnf.json").exists());
    assert!(
        !project
            .data_dir
            .path()
            .join("mock_state_pacman.json")
            .exists()
    );
    project.close_checked();
}
