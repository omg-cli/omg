//! Explicit mock selection must never fall through to live package metadata.

#![cfg(debug_assertions)]

use std::process::Command;

fn assert_mock_metadata_is_unsupported(args: &[&str], expected: &str) {
    let state = tempfile::TempDir::new().expect("isolated mock state");
    for distro in ["fedora", "debian", "arch"] {
        let output = Command::new(env!("CARGO_BIN_EXE_omg"))
            .args(args)
            .env("OMG_TEST_MODE", "1")
            .env("OMG_TEST_DISTRO", distro)
            .env("OMG_DISABLE_DAEMON", "1")
            .env("OMG_DISABLE_TELEMETRY", "1")
            .env("OMG_NO_UPDATE_CHECK", "1")
            .env("OMG_DATA_DIR", state.path())
            .env("OMG_CACHE_DIR", state.path().join("cache"))
            .env("OMG_CONFIG_DIR", state.path().join("config"))
            .output()
            .expect("run metadata command");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{args:?}, {distro}: {stderr}"
        );
        assert!(stderr.contains(expected), "{args:?}, {distro}: {stderr}");
    }
}

#[test]
fn mock_why_reports_unsupported_instead_of_querying_native_reasons() {
    assert_mock_metadata_is_unsupported(
        &["why", "tree"],
        "Package dependency analysis is not implemented for the mock backend",
    );
}

#[test]
fn mock_reverse_why_reports_unsupported_instead_of_querying_native_dependents() {
    assert_mock_metadata_is_unsupported(
        &["why", "--reverse", "tree"],
        "Package dependency analysis is not implemented for the mock backend",
    );
}

#[test]
fn mock_size_reports_unsupported_instead_of_querying_native_inventory() {
    assert_mock_metadata_is_unsupported(
        &["size"],
        "Package size analysis is not implemented for the mock backend",
    );
}

#[test]
fn mock_size_tree_reports_unsupported_instead_of_querying_native_providers() {
    assert_mock_metadata_is_unsupported(
        &["size", "--tree", "tree"],
        "Package size analysis is not implemented for the mock backend",
    );
}

#[test]
fn mock_blame_reports_unsupported_instead_of_querying_native_details() {
    assert_mock_metadata_is_unsupported(
        &["blame", "tree"],
        "Package installation history is not implemented for the mock backend",
    );
}
