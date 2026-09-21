//! Real-world security integration tests
//!
//! These tests interact with actual external systems:
//! - Real SLSA Rekor transparency log (sigstore.dev)
//! - Real OSV/ALSA vulnerability databases
//! - Real Arch Linux package cache for PGP verification
//!
//! No mocks, no stubs - only production-ready integration tests.

use omg_lib::core::security::slsa::SlsaVerifier;
use omg_lib::core::security::vulnerability::VulnerabilityScanner;
use omg_lib::package_managers::types::parse_version_or_zero;
use std::time::Duration;

/// Test SLSA verification against real Rekor transparency log
///
/// This test queries the actual Sigstore Rekor instance to verify
/// that our SLSA verification can communicate with production infrastructure.
#[tokio::test]
#[ignore = "Run with --ignored flag to test against real external services"]
async fn test_slsa_rekor_query_real() {
    let verifier = SlsaVerifier::new();

    // Use a known artifact hash from a real signed artifact
    // This is the hash of the empty file (commonly used for testing)
    let test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    // Query real Rekor instance
    let result =
        tokio::time::timeout(Duration::from_secs(10), verifier.query_rekor(test_hash)).await;

    // Should complete without timeout
    assert!(
        result.is_ok(),
        "Rekor query timed out - check network connectivity"
    );

    // Result should be Ok (empty vec is fine if hash not found)
    let entries = result.unwrap();
    assert!(
        entries.is_ok(),
        "Failed to query Rekor: {:?}",
        entries.err()
    );

    println!(
        "✓ Successfully queried Rekor transparency log, found {} entries",
        entries.unwrap().len()
    );
}

/// Test vulnerability scanner against real ALSA database
///
/// Queries the actual Arch Linux Security Advisories API to verify
/// our scanner can fetch and parse real vulnerability data.
#[tokio::test]
#[ignore = "Run with --ignored flag to test against real external services"]
async fn test_vulnerability_scanner_alsa_real() {
    let scanner = VulnerabilityScanner::new();

    // Query real ALSA database
    let result = tokio::time::timeout(Duration::from_secs(15), scanner.fetch_alsa_issues()).await;

    // Should complete without timeout
    assert!(
        result.is_ok(),
        "ALSA query timed out - check network connectivity"
    );

    let issues = result.unwrap();
    assert!(
        issues.is_ok(),
        "Failed to fetch ALSA issues: {:?}",
        issues.err()
    );

    let issues = issues.unwrap();

    assert!(!issues.is_empty(), "Arch advisory feed unexpectedly empty");
    assert!(
        issues.iter().any(|issue| issue.status == "Fixed"),
        "Fixed advisories must remain available for older installed packages"
    );

    // Check the entire feed, not only a sample that can miss schema drift.
    for issue in &issues {
        // Every issue should have a name
        assert!(!issue.name.is_empty(), "Issue missing name");

        // Should have at least one affected package
        assert!(
            !issue.packages.is_empty(),
            "Issue {} has no packages",
            issue.name
        );

        // Preserve upstream status rather than discarding fixed advisories.
        assert!(
            matches!(
                issue.status.as_str(),
                "Unknown" | "Not affected" | "Vulnerable" | "Fixed" | "Testing"
            ),
            "Issue {} has unexpected status: {}",
            issue.name,
            issue.status
        );

        // Should have severity
        assert!(
            !issue.severity.is_empty(),
            "Issue {} missing severity",
            issue.name
        );

        // Should have affected version
        assert!(
            !issue.affected.is_empty(),
            "Issue {} missing affected version",
            issue.name
        );
    }

    println!(
        "✓ Successfully fetched {} ALSA issues from production API",
        issues.len()
    );
}

/// Test OSV database query for real package
///
/// Queries the actual OSV (Open Source Vulnerabilities) database
/// to verify our scanner can look up CVEs for real packages.
#[tokio::test]
#[ignore = "Run with --ignored flag to test against real external services"]
async fn test_vulnerability_scanner_osv_real() {
    let scanner = VulnerabilityScanner::new();

    // Test with a real package version
    // Using a deliberately old version that likely has known CVEs
    let package = "openssl";
    let version = parse_version_or_zero("1.0.0");

    let result = tokio::time::timeout(
        Duration::from_secs(15),
        scanner.scan_package(package, &version),
    )
    .await;

    // Should complete without timeout
    assert!(
        result.is_ok(),
        "OSV query timed out - check network connectivity"
    );

    let vulns = result.unwrap();
    assert!(vulns.is_ok(), "Failed to query OSV: {:?}", vulns.err());

    let vulns = vulns.unwrap();

    // Old OpenSSL version should have vulnerabilities
    // (This is a reasonable assumption for testing against real data)
    println!(
        "✓ Successfully queried OSV database, found {} vulnerabilities for {} {}",
        vulns.len(),
        package,
        version
    );

    // Validate structure of returned vulnerabilities
    for vuln in vulns.iter().take(3) {
        // Should have an ID (CVE or similar)
        assert!(!vuln.id.is_empty(), "Vulnerability missing ID");

        // Should have a summary
        assert!(
            !vuln.summary.is_empty(),
            "Vulnerability {} missing summary",
            vuln.id
        );

        println!("  - {}: {}", vuln.id, vuln.summary);
    }
}

/// Test hash verification with real file data
///
/// Verifies SHA-256 calculation against known test vectors
/// to ensure cryptographic correctness.
#[test]
fn test_hash_verification_test_vectors() {
    let verifier = SlsaVerifier::default();

    // Test vectors from SHA-256 specification
    let test_vectors = vec![
        (
            "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            "abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            "The quick brown fox jumps over the lazy dog",
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        ),
    ];

    for (input, expected_hash) in test_vectors {
        // Create temp file with test data
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut temp = NamedTempFile::new().unwrap();
        write!(temp, "{input}").unwrap();
        temp.flush().unwrap();

        // Verify hash matches
        assert!(
            verifier.verify_hash(temp.path(), expected_hash).unwrap(),
            "Hash mismatch for input: {input:?}"
        );
    }

    println!("✓ SHA-256 hash verification matches standard test vectors");
}

/// Test PGP verification failure contracts hermetically
///
/// The former real-cache test was vacuous: it skipped when /var/cache/pacman
/// was absent and accepted both Ok and Err from the verifier, so it passed
/// regardless of product behavior. These tests pin the fail-closed error
/// paths of [`PgpVerifier`] and [`require_detached_signature_files`] with no
/// external state.
///
/// Gated behind the `pgp` feature because `omg_lib::core::security::pgp` is
/// only compiled when it is enabled.
#[cfg(feature = "pgp")]
#[test]
fn test_pgp_verification_fail_closed_contracts() {
    use omg_lib::core::security::pgp::{
        PgpError, PgpVerifier, SignatureFileError, require_detached_signature_files,
    };
    use std::fs;
    use tempfile::tempdir;

    let temp = tempdir().unwrap();

    // 1. A missing keyring is an error, never an empty trusted set.
    let missing_keyring = temp.path().join("no-such-keyring.gpg");
    let Err(err) = PgpVerifier::from_keyring(&missing_keyring) else {
        panic!("missing keyring must be rejected")
    };
    assert!(
        matches!(err, PgpError::KeyringMissing { .. }),
        "expected KeyringMissing, got: {err:?}"
    );

    // 2. An unparseable keyring file is an error.
    let garbage_keyring = temp.path().join("garbage.gpg");
    fs::write(&garbage_keyring, b"not a keyring").unwrap();
    let Err(err) = PgpVerifier::from_keyring(&garbage_keyring) else {
        panic!("garbage keyring must be rejected")
    };
    assert!(
        matches!(err, PgpError::KeyringParse { .. }),
        "expected KeyringParse, got: {err:?}"
    );

    // 3. Verifying a package whose blob is missing fails with PackageOpen,
    //    not silently with Ok.
    let verifier = PgpVerifier::empty();
    let missing_pkg = temp.path().join("missing-1.0-1-x86_64.pkg.tar.zst");
    let sig = temp.path().join("sig.asc");
    fs::write(&sig, b"fake signature bytes").unwrap();
    let err = verifier
        .verify_detached(&missing_pkg, &sig)
        .expect_err("missing package blob must fail closed");
    assert!(
        matches!(err, PgpError::PackageOpen { .. }),
        "expected PackageOpen, got: {err:?}"
    );

    // 4. An existing package with a malformed detached signature fails with
    //    a parse error, never Ok.
    let pkg = temp.path().join("pkg-1.0-1-x86_64.pkg.tar.zst");
    fs::write(&pkg, b"package payload").unwrap();
    let bad_sig = temp.path().join("bad.asc");
    fs::write(&bad_sig, b"definitely not OpenPGP").unwrap();
    let err = verifier
        .verify_detached(&pkg, &bad_sig)
        .expect_err("malformed signature must fail closed");
    assert!(
        matches!(err, PgpError::SignatureParse { .. }),
        "expected SignatureParse, got: {err:?}"
    );

    // 5. require_detached_signature_files names the missing artifact in its
    //    typed errors (fail-closed on unsigned packages).
    let err = require_detached_signature_files(
        "ripgrep",
        &temp.path().join("ripgrep.pkg.tar.zst"),
        &temp.path().join("ripgrep.pkg.tar.zst.sig"),
    )
    .expect_err("missing package must be reported");
    assert!(
        matches!(err, SignatureFileError::PackageMissing { ref package_name, .. } if package_name == "ripgrep"),
        "expected PackageMissing naming 'ripgrep', got: {err:?}"
    );

    let pkg_path = temp.path().join("present.pkg.tar.zst");
    fs::write(&pkg_path, b"payload").unwrap();
    let err = require_detached_signature_files(
        "tree",
        &pkg_path,
        &temp.path().join("present.pkg.tar.zst.sig"),
    )
    .expect_err("missing signature must be reported");
    assert!(
        matches!(err, SignatureFileError::SignatureMissing { ref package_name, .. } if package_name == "tree"),
        "expected SignatureMissing naming 'tree', got: {err:?}"
    );
}

// NOTE: `test_vulnerability_cache_effectiveness` was deleted as redundant:
// deterministic cache behavior is already pinned by the unit test
// `successful_osv_responses_are_cached` (src/core/security/vulnerability.rs:396),
// and this test's 10x-timing assertion was both network-dependent and flaky.
