//! Configuration validation must distinguish errors from advisory warnings.

pub mod common;

use common::TestProject;

fn configured(content: &str) -> TestProject {
    let project = TestProject::new();
    std::fs::write(project.config_dir.path().join("config.toml"), content)
        .expect("write isolated configuration");
    project
}

fn unchanged(project: &TestProject, content: &str) {
    assert_eq!(
        std::fs::read(project.config_dir.path().join("config.toml"))
            .expect("original configuration remains readable"),
        content.as_bytes(),
        "validation must preserve the original configuration"
    );
}

#[test]
fn config_validation_rejects_zero_concurrency_without_breaking_legacy_load() {
    let content = "[aur]\nbuild_concurrency = 0\n";
    let project = configured(content);
    let loaded = project.run(&["config", "get", "aur.build_concurrency"]);
    loaded.assert_success();
    assert_eq!(loaded.stdout.trim(), "0");
    let result = project.run(&["config", "validate"]);
    result.assert_stdout_contains("aur.build_concurrency should be > 0");
    result.assert_stdout_contains("Found 1 issue(s)");
    assert_eq!(result.exit_code, 1, "{result:?}");
    unchanged(&project, content);
    project.close_checked();
}

#[test]
fn config_validation_accepts_missing_defaults_without_creating_a_file() {
    let project = TestProject::new();
    let result = project.run(&["config", "validate"]);
    result.assert_success();
    result.assert_stdout_contains("Configuration is valid (using defaults)");
    assert!(!project.config_dir.path().join("config.toml").exists());
    project.close_checked();
}

#[test]
fn config_validation_accepts_valid_configuration_without_rewriting_it() {
    let content = "[aur]\nbuild_concurrency = 2\n";
    let project = configured(content);
    let result = project.run(&["config", "validate"]);
    result.assert_success();
    result.assert_stdout_contains("Configuration is valid!");
    unchanged(&project, content);
    project.close_checked();
}

#[test]
fn config_validation_keeps_high_concurrency_warning_successful() {
    let content = "[aur]\nbuild_concurrency = 9\n";
    let project = configured(content);
    let result = project.run(&["config", "validate"]);
    result.assert_success();
    result.assert_stdout_contains("aur.build_concurrency is unusually high (9)");
    unchanged(&project, content);
    project.close_checked();
}

#[cfg(unix)]
#[test]
fn config_validation_keeps_loose_permissions_warning_successful() {
    use std::os::unix::fs::PermissionsExt;
    let content = "[aur]\nbuild_concurrency = 2\n";
    let project = configured(content);
    let path = project.config_dir.path().join("config.toml");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .expect("set fixture permissions");
    let result = project.run(&["config", "validate"]);
    result.assert_success();
    result.assert_stdout_contains("Config file has loose permissions (644)");
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o644
    );
    unchanged(&project, content);
    project.close_checked();
}

#[test]
fn config_validation_rejects_invalid_toml_without_rewriting_it() {
    let content = "[aur\nbuild_concurrency = 2\n";
    let project = configured(content);
    let result = project.run(&["config", "validate"]);
    assert_eq!(result.exit_code, 1, "{result:?}");
    result.assert_stdout_contains("TOML syntax error");
    unchanged(&project, content);
    project.close_checked();
}

#[test]
fn config_validation_rejects_invalid_schema_without_rewriting_it() {
    let content = "[aur]\nbuild_concurrency = \"two\"\n";
    let project = configured(content);
    let result = project.run(&["config", "validate"]);
    assert_eq!(result.exit_code, 1, "{result:?}");
    result.assert_stdout_contains("Failed to load configuration");
    unchanged(&project, content);
    project.close_checked();
}
