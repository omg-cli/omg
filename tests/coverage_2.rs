//! Contract tests for `src/cli/security.rs` — SLSA identity policy surface.
//!
//! SLSA verification is not paywalled. These tests pin clap flags, missing-file
//! errors, and that a forged dashboard token does not block local verification.

pub mod common;

use common::TestProject;

/// Contract: a missing artifact fails at the existence check, not a paywall.
#[test]
fn slsa_check_names_a_missing_file() {
    let project = TestProject::new();
    let result = project.run(&[
        "audit",
        "slsa",
        "--certificate-identity",
        "release@example.invalid",
        "ghost.bin",
    ]);
    result.assert_failure();
    let output = result.combined_output();
    assert!(
        output.contains("File not found: ghost.bin"),
        "missing artifact must be named, got:\n{output}"
    );
    assert!(
        !output.contains("tier") && !output.contains("/pricing"),
        "SLSA must not be paywalled, got:\n{output}"
    );
}

/// Contract: an existing but unreadable artifact reaches the verifier's local
/// read boundary without depending on the live Rekor service.
#[test]
fn slsa_check_rejects_unreadable_artifact_before_network() {
    let project = TestProject::new();
    project.create_dir("artifact.bin");

    let result = project.run(&[
        "audit",
        "slsa",
        "--certificate-identity",
        "release@example.invalid",
        "artifact.bin",
    ]);
    result.assert_failure();
    let output = result.combined_output();
    assert!(
        output.contains("Verifying artifact signature for artifact.bin"),
        "existing artifact must reach verification, got:\n{output}"
    );
    assert!(
        output.contains("Failed to read 'artifact.bin'"),
        "unreadable artifact must fail locally before a Rekor query, got:\n{output}"
    );
    assert!(
        !output.contains("/pricing"),
        "SLSA must not be paywalled, got:\n{output}"
    );
}

/// Contract: a forged dashboard token does not paywall SLSA.
#[test]
fn forged_self_asserted_account_does_not_paywall_slsa() {
    let project = TestProject::new();
    project.create_dir("artifact.bin");

    std::fs::write(
        project.data_dir.path().join("license.json"),
        r#"{
            "key": "FORGED-CI-MOCK-KEY",
            "tier": "enterprise",
            "features": ["sbom", "audit", "secrets", "slsa", "policy"],
            "validated_at": 9999999999,
            "token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmb3JnZWQifQ.Zm9yZ2VkLXNpZw",
            "machine_id": null
        }"#,
    )
    .expect("write forged license fixture");

    let result = project.run(&[
        "audit",
        "slsa",
        "--certificate-identity",
        "release@example.invalid",
        "artifact.bin",
    ]);
    result.assert_failure();
    let out = result.combined_output();
    assert!(
        out.contains("Verifying artifact signature for artifact.bin"),
        "a forged token must fail before any upgrade offer, got:\n{out}"
    );
    assert!(
        out.contains("Failed to read 'artifact.bin'")
            && !out.contains("Artifact signature verified"),
        "a forged token must not turn an unsigned artifact into a verified signature, got:\n{out}"
    );
    assert!(
        !out.contains("/pricing"),
        "SLSA must not be paywalled, got:\n{out}"
    );
}

/// Contract: `--certificate-identity` is part of the CLI contract.
#[test]
fn certificate_identity_flag_is_accepted() {
    let project = TestProject::new();
    let result = project.run(&[
        "audit",
        "slsa",
        "artifact.bin",
        "--certificate-identity",
        "release@example.com",
    ]);
    let out = result.combined_output();
    assert!(
        !out.contains("unexpected argument") && !out.contains("Unrecognized command"),
        "--certificate-identity must be a real CLI flag, got clap rejection:\n{out}"
    );
}

/// Contract: an empty-inventory `audit fix` needs neither daemon nor paid tier.
#[cfg(feature = "arch")]
#[test]
fn audit_fix_is_not_paywalled() {
    let project = TestProject::new();
    let result = project.run(&["audit", "fix"]);
    result.assert_success();
    let out = result.combined_output();
    assert!(
        out.contains("No vulnerabilities found!"),
        "audit fix must complete the empty-inventory scan, got:\n{out}"
    );
    project.close_checked();
}

#[cfg(not(feature = "arch"))]
#[test]
fn audit_fix_rejects_an_unsupported_backend() {
    let project = TestProject::new();
    let result = project.run(&["audit", "fix"]);
    result.assert_failure();
    assert!(
        result
            .combined_output()
            .contains("without the Arch backend"),
        "unsupported backend must fail before scanning: {}",
        result.combined_output()
    );
    project.close_checked();
}
