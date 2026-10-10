//! Available-runtime aliases must reach the same catalog as canonical names.
pub mod common;
#[path = "support/recovery_fixture.rs"]
mod recovery_fixture;

use common::TestProject;
use recovery_fixture::RejectedProxy;

fn assert_available_transport(names: &[&str]) {
    let project = TestProject::new();
    let proxy = RejectedProxy::new();
    let mut environment = proxy.env();
    environment.push(("OMG_TEST_COMMAND_TIMEOUT_SECS", "10"));
    let pin = project.create_file(".node-version", "24.21.0\n");
    let config = project.config_dir.path().join("config.toml");
    std::fs::write(&config, "# preserve private configuration\n").unwrap();
    let runtime = project
        .data_dir
        .path()
        .join("versions/node/24.21.0/bin/node");
    std::fs::create_dir_all(runtime.parent().unwrap()).unwrap();
    std::fs::write(&runtime, "preserve installed runtime\n").unwrap();

    for name in names {
        let before = proxy.requests();
        let result = project.run_with_env(&["list", name, "--available"], &environment);
        assert_eq!(result.exit_code, 1, "{}", result.combined_output());
        assert!(
            proxy.requests() > before,
            "{name} must request its catalog through the private rejecting proxy: {}",
            result.combined_output()
        );
        result.assert_stdout_contains("Available remote versions");
        assert!(!result.combined_output().contains("Unsupported runtime"));
        assert!(!result.stderr.contains("timed out"), "{}", result.stderr);
        assert_eq!(std::fs::read_to_string(&pin).unwrap(), "24.21.0\n");
        assert_eq!(
            std::fs::read_to_string(&config).unwrap(),
            "# preserve private configuration\n"
        );
        assert_eq!(
            std::fs::read_to_string(&runtime).unwrap(),
            "preserve installed runtime\n"
        );
        assert!(!project.data_dir.path().join("history.json").exists());
    }
    project.close_checked();
}

#[test]
fn python_available_alias_uses_the_admitted_catalog() {
    let project = TestProject::new();
    let proxy = RejectedProxy::new();
    for name in ["python", "python3", "PyThOn3"] {
        let result = project.run_with_env(&["list", name, "--available"], &proxy.env());
        result.assert_success();
        result.assert_stdout_contains("Available remote versions (python-build-standalone)");
        result.assert_stdout_contains("3.12.0");
        result.assert_stdout_contains("3.11.0");
        assert!(result.stderr.is_empty(), "{}", result.stderr);
    }
    assert_eq!(
        proxy.requests(),
        0,
        "admitted Python catalog must stay offline"
    );
    project.close_checked();
}

#[test]
fn rust_available_alias_reaches_the_catalog_transport() {
    assert_available_transport(&["rust", "rustlang", "RuStLaNg"]);
}

#[test]
fn java_available_alias_reaches_the_catalog_transport() {
    assert_available_transport(&["java", "openjdk", "OpEnJdK"]);
}

#[test]
fn zig_available_alias_reaches_the_catalog_transport() {
    assert_available_transport(&["zig", "ziglang", "ZiGlAnG"]);
}

#[test]
fn existing_available_aliases_keep_catalog_dispatch() {
    assert_available_transport(&[
        "node", "nodejs", "go", "golang", "java", "jdk", "bun", "bunjs",
    ]);
}

#[test]
fn unknown_available_runtime_and_json_conflict_do_not_fetch() {
    let project = TestProject::new();
    let proxy = RejectedProxy::new();
    let unknown = project.run_with_env(&["list", "not-a-runtime", "--available"], &proxy.env());
    assert_eq!(unknown.exit_code, 1, "{}", unknown.combined_output());
    unknown.assert_stderr_contains("Unsupported runtime 'not-a-runtime'");
    for name in [
        "python3", "rustlang", "openjdk", "ziglang", "nodejs", "golang", "jdk", "bunjs",
    ] {
        let result = project.run_with_env(&["list", name, "--available", "--json"], &proxy.env());
        assert_eq!(result.exit_code, 1, "{}", result.combined_output());
        result.assert_stderr_contains("--json is not supported together with --available");
        assert!(!result.stdout.contains("Available remote versions"));
    }
    assert_eq!(
        proxy.requests(),
        0,
        "invalid requests must fail before fetching"
    );
    project.close_checked();
}
