//! Exercise manifest preview/export through the actual CLI in isolated homes.
pub mod common;

use common::TestProject;
use omg_lib::core::env::fingerprint::EnvironmentState;
use std::collections::BTreeMap;

#[test]
fn export_then_plan_preserves_files_and_reports_missing_target_mapping() {
    let project = TestProject::new();
    let state = EnvironmentState {
        schema_version: EnvironmentState::SCHEMA_VERSION,
        runtimes: BTreeMap::from([("node".into(), "22.1.0".into())]),
        packages: vec!["git".into()],
        timestamp: 0,
        hash: String::new(),
    };
    let lock = project.path().join("omg.lock");
    state.save(&lock).unwrap();
    let original = std::fs::read(&lock).unwrap();
    let exported = project.run(&["env", "export", "--source-target", "arch-x86_64"]);
    exported.assert_success();
    assert!(!project.path().join(".omg.toml").exists());
    project.create_file(".omg.toml", &exported.stdout);
    let planned = project.run(&["env", "plan", "--target", "ubuntu-x86_64"]);
    planned.assert_success();
    let json: serde_json::Value = serde_json::from_str(&planned.stdout).unwrap();
    assert_eq!(json["unmapped_tools"], serde_json::json!(["git"]));
    assert_eq!(json["runtimes"]["node"], "22.1.0");
    assert_eq!(std::fs::read(&lock).unwrap(), original);
    assert_eq!(
        std::fs::read_to_string(project.path().join(".omg.toml")).unwrap(),
        exported.stdout
    );
}

#[test]
fn invalid_inputs_fail_without_leaking_manifest_contents() {
    let project = TestProject::new();
    project.create_file(
        ".omg.toml",
        "[environment]\nprivate_value = 'do-not-echo-this'\n",
    );
    let result = project.run(&["env", "plan", "--target", "ubuntu-x86_64"]);
    assert!(!result.success);
    assert!(
        result
            .combined_output()
            .contains("Invalid .omg.toml environment manifest")
    );
    assert!(!result.combined_output().contains("do-not-echo-this"));
    let exported = project.run(&["env", "export", "--source-target", "arch-x86_64"]);
    assert!(!exported.success);
    assert!(exported.stdout.is_empty());
}

#[cfg(unix)]
#[test]
fn planner_refuses_symlinked_manifest() {
    let project = TestProject::new();
    let source = project.create_file("other.toml", "[environment]\nschema_version = 1\n");
    std::os::unix::fs::symlink(source, project.path().join(".omg.toml")).unwrap();
    let result = project.run(&["env", "plan", "--target", "ubuntu-x86_64"]);
    assert!(!result.success);
    assert!(result.stdout.is_empty());
}
