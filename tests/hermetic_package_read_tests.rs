//! Selected debug mock caller contracts, not native package-system proof.

pub mod common;

fn read(args: &[&str]) -> common::CommandResult {
    common::run_omg_with_env(
        args,
        &[
            ("OMG_TEST_DISTRO", "arch"),
            ("OMG_TEST_COMMAND_TIMEOUT_SECS", "5"),
        ],
    )
}

#[test]
fn hermetic_known_info_uses_catalog_metadata() {
    let result = read(&["info", "git"]);
    result.assert_success();
    assert!(result.stdout.contains("git"));
    assert!(result.stdout.contains("2.43.0"));
    assert!(!result.combined_output().contains("Searching AUR"));
}

#[test]
fn hermetic_json_info_uses_catalog_metadata() {
    let result = read(&["info", "git", "--json"]);
    result.assert_success();
    let info: serde_json::Value = serde_json::from_str(&result.stdout).expect("package JSON");
    assert_eq!(info["name"], "git");
    #[cfg(feature = "arch")]
    assert_eq!(
        info["version"],
        serde_json::json!({"epoch": null, "pkgrel": null, "pkgver": "2.43.0"})
    );
    #[cfg(not(feature = "arch"))]
    assert_eq!(info["version"], "2.43.0");
    assert_eq!(info["description"], "Version control");
    assert_eq!(info["installed"], false);
}

#[test]
fn hermetic_missing_text_info_is_not_found() {
    let name = "missing-fixture-package";
    let result = read(&["info", name]);
    result.assert_failure();
    let output = result.combined_output();
    assert!(output.contains(name));
    assert!(output.contains("not found"));
    assert!(!output.contains("on the AUR"));
}

#[test]
fn hermetic_missing_json_info_is_not_found() {
    let name = "missing-fixture-package";
    let result = read(&["info", name, "--json"]);
    result.assert_failure();
    let output = result.combined_output();
    assert!(output.contains(name));
    assert!(output.contains("not found"));
    assert!(!output.contains("on the AUR"));
}

#[test]
fn hermetic_invalid_info_fails_before_catalog_query() {
    for args in [
        vec!["info", "../invalid"],
        vec!["info", "../invalid", "--json"],
    ] {
        let result = read(&args);
        result.assert_failure();
        let output = result.combined_output();
        assert!(
            output.contains("Package name cannot start with '.' (hidden file protection)"),
            "{output}"
        );
        assert!(!output.contains("not found"), "{output}");
        assert!(!output.contains("on the AUR"), "{output}");
        assert!(!output.contains("Failed to query"), "{output}");
    }
}

#[test]
fn hermetic_sync_finishes_without_privilege_prompt() {
    let result = read(&["sync"]);
    result.assert_success();
    let output = result.combined_output().to_lowercase();
    assert!(!output.contains("privilege elevation"));
    assert!(!output.contains("[sudo]"));
    assert!(!output.contains("password:"));
}
