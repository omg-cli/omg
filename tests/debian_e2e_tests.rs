//! End-to-End Tests for Pure Rust Debian/Ubuntu Implementation
//!
//! These tests exercise the complete Debian package management stack:
//! - APT sources parsing (both legacy and deb822 formats)
//! - Parallel repository synchronization
//! - Dependency resolution with version comparison
//! - Transaction engine for .deb installation
//!
//! Run with: `cargo test --features debian-pure --test debian_e2e_tests`

#![cfg(any(feature = "debian", feature = "debian-pure"))]

pub mod platform_semantics;

use std::path::Path;

use platform_semantics::assert_no_arch_terms;
use tempfile::TempDir;

// Import modules under test
#[cfg(feature = "docker_tests")]
use omg_lib::package_managers::debian_db::resolver::DependencyResolver;
#[cfg(feature = "docker_tests")]
use omg_lib::package_managers::debian_db::sources::get_enabled_binary_repos;
use omg_lib::package_managers::debian_db::transaction::dry_run;
use omg_lib::package_managers::debian_db::{
    RepoType, Repository, ResolutionResult, Transaction, TransactionState, compare_versions,
    parse_deb822_content, parse_sources_list_content,
};

// ============================================================================
// Sources Parser Tests
// ============================================================================

#[test]
fn test_parse_simple_sources_list() {
    let content = r"
# Main repository
deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
deb-src http://deb.debian.org/debian bookworm main

# Security updates
deb http://security.debian.org/debian-security bookworm-security main contrib non-free
";

    let repos = parse_sources_list_content(content, Path::new("/etc/apt/sources.list")).unwrap();

    assert_eq!(repos.len(), 3, "Should parse 3 repository entries");

    // Check first repo
    assert_eq!(repos[0].repo_type, RepoType::Binary);
    assert_eq!(repos[0].uri, "http://deb.debian.org/debian");
    assert_eq!(repos[0].suite, "bookworm");
    assert_eq!(
        repos[0].components,
        vec!["main", "contrib", "non-free", "non-free-firmware"]
    );
    assert!(repos[0].enabled);

    // Check source repo
    assert_eq!(repos[1].repo_type, RepoType::Source);

    // Check security repo
    assert_eq!(repos[2].suite, "bookworm-security");
}

#[test]
fn test_parse_sources_with_options() {
    let content = r"
deb [arch=amd64 signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] http://deb.debian.org/debian bookworm main
deb [arch=arm64,armhf] https://example.com/repo stable main
";

    let repos = parse_sources_list_content(content, Path::new("/test")).unwrap();

    assert_eq!(repos.len(), 2);

    // Check architecture filter
    assert_eq!(repos[0].arch, Some("amd64".to_string()));
    assert!(
        repos[0]
            .signed_by
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains("debian-archive-keyring.gpg")
    );

    // Check multi-arch
    assert_eq!(repos[1].arch, Some("arm64,armhf".to_string()));
}

#[test]
fn test_parse_disabled_source() {
    let content = r"
deb http://example.com/enabled stable main
# deb http://example.com/disabled unstable main
";

    let repos = parse_sources_list_content(content, Path::new("/test")).unwrap();

    // Configuration tooling retains disabled entries; acquisition must be
    // able to distinguish them from enabled repositories.
    assert_eq!(repos.len(), 2);
    assert_eq!(repos[0].uri, "http://example.com/enabled");
    assert_eq!(repos[0].suite, "stable");
    assert!(repos[0].enabled);
    assert_eq!(repos[1].uri, "http://example.com/disabled");
    assert_eq!(repos[1].suite, "unstable");
    assert!(!repos[1].enabled);
    assert_eq!(repos.iter().filter(|repo| repo.enabled).count(), 1);
}

#[test]
fn test_parse_deb822_format() {
    let content = r"
Types: deb deb-src
URIs: http://deb.debian.org/debian
Suites: bookworm bookworm-updates
Components: main contrib non-free
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
";

    let repos = parse_deb822_content(content, Path::new("/test.sources")).unwrap();

    // 2 types * 1 URI * 2 suites = 4 repository entries
    assert_eq!(repos.len(), 4, "Should expand to 4 combinations");

    // Check first entry (deb + bookworm)
    assert_eq!(repos[0].repo_type, RepoType::Binary);
    assert_eq!(repos[0].suite, "bookworm");
    assert_eq!(repos[0].components, vec!["main", "contrib", "non-free"]);

    // Check that sources are included
    assert!(repos.iter().any(|r| r.repo_type == RepoType::Source));

    // Check bookworm-updates
    assert!(repos.iter().any(|r| r.suite == "bookworm-updates"));
}

#[test]
fn test_parse_deb822_disabled() {
    let content = r"
Types: deb
URIs: http://example.com/repo
Suites: stable
Components: main
Enabled: no
";

    let repos = parse_deb822_content(content, Path::new("/test.sources")).unwrap();

    assert_eq!(repos.len(), 1);
    assert!(!repos[0].enabled, "Should respect Enabled: no");
}

#[test]
fn test_parse_deb822_multiple_stanzas() {
    let content = r"
Types: deb
URIs: http://deb.debian.org/debian
Suites: bookworm
Components: main

Types: deb
URIs: http://security.debian.org/debian-security
Suites: bookworm-security
Components: main
";

    let repos = parse_deb822_content(content, Path::new("/test.sources")).unwrap();

    assert_eq!(repos.len(), 2, "Should parse two separate stanzas");
    assert_eq!(repos[0].uri, "http://deb.debian.org/debian");
    assert_eq!(repos[1].uri, "http://security.debian.org/debian-security");
}

#[test]
fn test_parse_mixed_format_sources() {
    // Test that we handle edge cases like empty lines, comments, malformed lines
    let content = r"

# Comment at the start
deb http://example.com/repo stable main

this is not a valid line

# Another comment
deb-src http://example.com/repo stable main

   # Indented comment
deb [arch=amd64] http://example.com/special testing main

";

    let repos = parse_sources_list_content(content, Path::new("/test")).unwrap();

    assert_eq!(
        repos.len(),
        3,
        "Should parse only valid lines, ignoring malformed"
    );
    assert_eq!(repos[0].suite, "stable");
    assert_eq!(repos[1].repo_type, RepoType::Source);
    assert_eq!(repos[2].suite, "testing");
}

#[test]
fn test_repository_release_url() {
    let repo = Repository {
        repo_type: RepoType::Binary,
        uri: "http://deb.debian.org/debian".to_string(),
        suite: "bookworm".to_string(),
        components: vec!["main".to_string(), "contrib".to_string()],
        arch: None,
        signed_by: None,
        enabled: true,
        source_file: std::path::PathBuf::new(),
        options: std::collections::HashMap::new(),
    };

    let release_url = repo.release_url();
    assert_eq!(
        release_url,
        "http://deb.debian.org/debian/dists/bookworm/InRelease"
    );
}

// ============================================================================
// Version Comparison Tests
// ============================================================================

#[test]
fn test_version_comparison_simple() {
    assert_eq!(
        compare_versions("1.0", "1.0"),
        std::cmp::Ordering::Equal,
        "Equal versions"
    );
    assert_eq!(
        compare_versions("1.0", "2.0"),
        std::cmp::Ordering::Less,
        "1.0 < 2.0"
    );
    assert_eq!(
        compare_versions("2.0", "1.0"),
        std::cmp::Ordering::Greater,
        "2.0 > 1.0"
    );
    assert_eq!(
        compare_versions("1.9", "1.10"),
        std::cmp::Ordering::Less,
        "1.9 < 1.10"
    );
}

#[test]
fn test_version_comparison_with_epoch() {
    // Epoch takes precedence over everything
    assert_eq!(
        compare_versions("1:0.1", "9.9"),
        std::cmp::Ordering::Greater,
        "epoch 1 beats any version without epoch"
    );
    assert_eq!(
        compare_versions("2:1.0", "1:9.9"),
        std::cmp::Ordering::Greater,
        "epoch 2 > epoch 1"
    );
    assert_eq!(
        compare_versions("1:1.0", "1:1.0"),
        std::cmp::Ordering::Equal,
        "Same epoch and version"
    );
}

#[test]
fn test_version_comparison_with_debian_revision() {
    assert_eq!(
        compare_versions("1.0-1", "1.0-2"),
        std::cmp::Ordering::Less,
        "1.0-1 < 1.0-2"
    );
    assert_eq!(
        compare_versions("1.0-10", "1.0-2"),
        std::cmp::Ordering::Greater,
        "1.0-10 > 1.0-2 (numeric comparison)"
    );
    assert_eq!(
        compare_versions("1.0-1ubuntu1", "1.0-1ubuntu2"),
        std::cmp::Ordering::Less,
        "Ubuntu revisions"
    );
}

#[test]
fn test_version_comparison_tilde() {
    // Tilde sorts before anything, even empty string
    assert_eq!(
        compare_versions("1.0~beta", "1.0"),
        std::cmp::Ordering::Less,
        "1.0~beta < 1.0"
    );
    assert_eq!(
        compare_versions("1.0~alpha", "1.0~beta"),
        std::cmp::Ordering::Less,
        "alpha < beta"
    );
    assert_eq!(
        compare_versions("1.0~rc1", "1.0"),
        std::cmp::Ordering::Less,
        "1.0~rc1 < 1.0 (release)"
    );
}

#[test]
fn test_version_comparison_complex() {
    // Real-world Debian version strings
    assert_eq!(
        compare_versions("2:9.0.1499-1", "2:9.0.1500-1"),
        std::cmp::Ordering::Less,
        "Vim versions"
    );
    assert_eq!(
        compare_versions("1:8.5.0-2ubuntu1", "1:8.5.0-2ubuntu2"),
        std::cmp::Ordering::Less,
        "Curl versions"
    );
    assert_eq!(
        compare_versions("2.38-1ubuntu6", "2.38-1ubuntu10"),
        std::cmp::Ordering::Less,
        "libc6 versions"
    );
}

#[test]
fn test_version_comparison_edge_cases() {
    // Empty strings
    assert_eq!(
        compare_versions("", "1.0"),
        std::cmp::Ordering::Less,
        "Empty < version"
    );

    // Very long version strings
    assert_eq!(
        compare_versions("1.2.3.4.5.6.7.8", "1.2.3.4.5.6.7.9"),
        std::cmp::Ordering::Less,
        "Long version strings"
    );

    // Letters in version
    assert_eq!(
        compare_versions("1.0a", "1.0b"),
        std::cmp::Ordering::Less,
        "Letter suffixes"
    );
}

// ============================================================================
// Dependency Resolver Tests
// ============================================================================

// Note: These tests require a populated package database, which may not exist
// in CI environments. They are designed to work with real Debian/Ubuntu systems.

#[test]
#[cfg(feature = "docker_tests")]
fn test_resolver_simple_package() {
    // This test requires a real Debian/Ubuntu system with package database
    let mut resolver = match DependencyResolver::new() {
        Ok(r) => r,
        Err(e) => {
            common::report_skip(&format!(
                "DependencyResolver unavailable in this environment: {e:#}"
            ));
            return;
        }
    };

    // curl must be resolvable on a real Debian database; resolution must
    // produce concrete work (installs and/or upgrades).
    resolver
        .add_package("curl")
        .expect("curl must exist in a populated Debian package database");
    let resolution = resolver
        .resolve()
        .expect("Should resolve curl and its dependencies");
    assert!(
        !resolution.to_install.is_empty() || !resolution.to_upgrade.is_empty(),
        "Should have packages to install or upgrade"
    );
}

#[test]
#[cfg(feature = "docker_tests")]
fn test_resolver_missing_package() {
    let mut resolver = match DependencyResolver::new() {
        Ok(r) => r,
        Err(e) => {
            common::report_skip(&format!(
                "DependencyResolver unavailable in this environment: {e:#}"
            ));
            return;
        }
    };

    let result = resolver.add_package("this-package-definitely-does-not-exist-12345");
    assert!(result.is_err(), "Should fail for nonexistent package");
}

#[test]
#[cfg(feature = "docker_tests")]
fn test_resolver_with_dependencies() {
    let mut resolver = match DependencyResolver::new() {
        Ok(r) => r,
        Err(e) => {
            common::report_skip(&format!(
                "DependencyResolver unavailable in this environment: {e:#}"
            ));
            return;
        }
    };

    // vim has dependencies like libacl, libc6, etc.; both steps must succeed
    // on a real Debian database — silent skips would hide resolver breakage.
    resolver
        .add_package("vim")
        .expect("vim must exist in a populated Debian package database");
    let result = resolver
        .resolve()
        .expect("dependency resolution should succeed");
    assert!(
        result.to_install.len() >= 1,
        "Should resolve at least vim itself"
    );
}

#[test]
#[cfg(feature = "docker_tests")]
fn test_resolver_topological_sort() {
    // Test that dependencies are ordered correctly (dependencies before dependents)
    let mut resolver = match DependencyResolver::new() {
        Ok(r) => r,
        Err(e) => {
            common::report_skip(&format!(
                "DependencyResolver unavailable in this environment: {e:#}"
            ));
            return;
        }
    };

    // git pulls in library dependencies; the resolved install list must be a
    // non-empty plan that actually contains the requested package.
    resolver
        .add_package("git")
        .expect("git must exist in a populated Debian package database");
    let result = resolver
        .resolve()
        .expect("dependency resolution should succeed");
    let install_list = result.to_install;
    assert!(
        !install_list.is_empty(),
        "Resolving 'git' should produce at least one package to install"
    );
    assert!(
        install_list.iter().any(|package| package == "git"),
        "The resolved plan must contain 'git' itself, got: {install_list:?}"
    );
}

// ============================================================================
// Transaction Tests
// ============================================================================

#[test]
fn test_transaction_creation() {
    let result = ResolutionResult {
        to_install: vec!["vim".to_string(), "curl".to_string()],
        to_upgrade: vec![(
            "git".to_string(),
            "2.39.0".to_string(),
            "2.40.0".to_string(),
        )],
        to_remove: vec!["old-package".to_string()],
        download_size: 10_000_000,
        installed_size: 50_000_000,
    };

    let tx = Transaction::from_resolution(result);

    assert_eq!(tx.state, TransactionState::Pending);
    assert_eq!(tx.to_install.len(), 2);
    assert_eq!(tx.to_upgrade.len(), 1);
    assert_eq!(tx.to_remove.len(), 1);
    assert_eq!(tx.package_count(), 4);
}

#[test]
fn test_transaction_dry_run() {
    let result = ResolutionResult {
        to_install: vec!["vim".to_string(), "git".to_string()],
        to_upgrade: vec![("curl".to_string(), "8.0.0".to_string(), "8.5.0".to_string())],
        to_remove: Vec::new(),
        download_size: 5_242_880,   // 5 MB
        installed_size: 20_971_520, // 20 MB
    };

    let output = dry_run(&result);

    assert!(output.contains("vim"));
    assert!(output.contains("git"));
    assert!(output.contains("curl"));
    assert!(output.contains("5242880"));
    assert!(output.contains("20971520"));
    assert!(output.contains("NEW packages"));
    assert!(output.contains("upgraded"));
}

#[test]
fn test_transaction_empty() {
    let tx = Transaction::new();
    assert_eq!(tx.state, TransactionState::Pending);
    assert_eq!(tx.package_count(), 0);
    assert_eq!(tx.total_download_size(), 0);
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_sources_parse_repository_metadata() {
    let content = r"
deb http://deb.debian.org/debian bookworm main
deb http://security.debian.org/debian-security bookworm-security main
";

    let repos = parse_sources_list_content(content, Path::new("/etc/apt/sources.list")).unwrap();

    assert_eq!(repos.len(), 2);
    assert_eq!(repos[0].suite, "bookworm");
    assert_eq!(repos[0].components, ["main"]);
    assert_eq!(repos[1].suite, "bookworm-security");
}

#[test]
#[cfg(feature = "docker_tests")]
fn test_full_workflow_search_resolve_transaction() {
    // This test exercises the full workflow:
    // 1. Parse sources
    // 2. Resolve dependencies
    // 3. Create transaction
    // 4. Dry run

    let repos = match get_enabled_binary_repos() {
        Ok(r) if !r.is_empty() => r,
        _ => {
            common::report_skip("no repositories configured");
            return;
        }
    };

    println!("Found {} repositories", repos.len());

    let mut resolver = match DependencyResolver::new() {
        Ok(r) => r,
        Err(e) => {
            common::report_skip(&format!("cannot create resolver: {e}"));
            return;
        }
    };

    if resolver.add_package("hello").is_err() {
        common::report_skip("'hello' not available in the configured repositories");
        return;
    }

    let result = resolver
        .resolve()
        .expect("dependency resolution should succeed");

    // The dry-run plan must be a non-empty rendering of that resolution.
    let dry_run_output = dry_run(&result);
    assert!(
        !dry_run_output.trim().is_empty(),
        "Dry run should print a transaction plan"
    );

    // ResolutionResult is not Clone: consume it last.
    let tx = Transaction::from_resolution(result);
    assert!(
        tx.package_count() > 0,
        "Resolution should produce work for 'hello'"
    );
    assert_eq!(tx.state, TransactionState::Pending);
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[test]
fn test_sources_parser_handles_malformed_input() {
    let malformed = r"
This is not a valid sources.list file
It has random text
And no valid entries
";

    let repos = parse_sources_list_content(malformed, Path::new("/test")).unwrap();
    assert_eq!(repos.len(), 0, "Should handle malformed input gracefully");
}

#[test]
fn test_deb822_parser_handles_incomplete_stanza() {
    let incomplete = r"
Types: deb
URIs: http://example.com/repo
# Missing Suites and Components
";

    let repos = parse_deb822_content(incomplete, Path::new("/test.sources")).unwrap();
    assert_eq!(repos.len(), 0, "Should skip incomplete stanzas");
}

#[test]
fn test_version_comparison_handles_invalid_input() {
    // Lenient by design: malformed input degrades instead of panicking.
    // Pin determinism (same inputs, same ordering, twice) plus reflexivity.
    for (a, b) in [
        ("invalid", "1.0"),
        ("1.0", "also-invalid"),
        ("", ""),
        ("1.2.3.4.5.6.7.8.9.10", "1:2.0"),
    ] {
        assert_eq!(compare_versions(a, b), compare_versions(a, b));
        assert_eq!(compare_versions(a, a), std::cmp::Ordering::Equal);
    }
}

// ============================================================================
// CLI-LEVEL E2E TESTS FOR DEBIAN
// ============================================================================

pub mod common;

use common::CommandResult;

/// Pin the mock backend to Debian for deterministic behavior on any host,
/// and run through the shared isolated runner (unique `OMG_DATA_DIR`,
/// `OMG_CONFIG_DIR`, `OMG_CACHE_DIR` per invocation). This replaces both the
/// former hand-rolled duplicate runner and the `is_debian_or_ubuntu()`
/// silent skips: the suite now exercises the Debian backend everywhere.
fn run_omg_cli(args: &[&str]) -> CommandResult {
    run_omg_debian(args, &[])
}

fn run_omg_debian(args: &[&str], extra_env: &[(&str, &str)]) -> CommandResult {
    let mut env: Vec<(&str, &str)> = vec![("OMG_TEST_DISTRO", "debian")];
    env.extend_from_slice(extra_env);
    common::run_omg_with_env(args, &env)
}

#[test]
fn command_timeout_terminates_pipe_inheriting_descendants() {
    let directory = TempDir::new().unwrap();
    std::fs::write(
        directory.path().join("mise.toml"),
        "[tasks.hold]\nrun = 'sleep 5 & wait'\n",
    )
    .unwrap();
    let start = std::time::Instant::now();
    let result = common::run_omg_with_options(
        &["run", "hold"],
        Some(directory.path()),
        &[("OMG_TEST_COMMAND_TIMEOUT_SECS", "1")],
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(3),
        "descendant retained output pipes after timeout"
    );
    assert!(!result.success);
    assert!(result.stderr.contains("[test harness timeout]"));
}

#[test]
fn completion_oracle_rejects_signals_and_timeouts() {
    for (exit_code, stderr) in [(-1, ""), (101, ""), (0, "[test harness timeout]")] {
        let result = CommandResult {
            success: exit_code == 0,
            exit_code,
            stdout: String::new(),
            stderr: stderr.into(),
        };
        assert!(
            std::panic::catch_unwind(|| assert_runs_without_panic(&result, "fixture")).is_err()
        );
    }
}

fn assert_runs_without_panic(result: &CommandResult, context: &str) {
    common::assertions::assert_process_completed(result);
    let combined = result.combined_output();
    assert!(
        !combined.contains("panicked"),
        "{context} panicked:\n{combined}"
    );
    assert_ne!(
        result.exit_code, 101,
        "{context} exited with panic code 101:\n{combined}"
    );
}

/// Dual-path contract: depending on the host environment (mock index vs. a
/// populated Debian database) a command may legitimately succeed or fail, but
/// BOTH paths must show concrete work — the documented success marker or a
/// named failure cause. A silent exit on either side is a bug.
fn assert_dual_path_contract(
    result: &CommandResult,
    success_marker: &str,
    failure_marker: &str,
    context: &str,
) {
    assert_runs_without_panic(result, context);
    let output = result.combined_output();
    if result.success {
        assert!(
            output.contains(success_marker),
            "{context}: success must render '{success_marker}', got: {output}"
        );
    } else {
        assert!(
            output.contains(failure_marker),
            "{context}: failure must name its cause ('{failure_marker}'), got: {output}"
        );
    }
}

#[test]
fn test_cli_search_on_debian() {
    // Known mock package: MockPackageDb::debian_defaults always contains
    // `git` (src/package_managers/mock.rs), and search exits 0 either way.
    let hit = run_omg_cli(&["search", "git"]);
    hit.assert_success();
    hit.assert_stdout_contains("| Search");
    hit.assert_stdout_contains("git");

    // Unknown/virtual package: graceful empty result with an explicit notice,
    // not an error and not silence.
    let miss = run_omg_cli(&["search", "this-package-does-not-exist-xyz"]);
    miss.assert_success();
    miss.assert_stdout_contains("No results found");
}

#[test]
fn test_cli_info_debian_package() {
    let result = run_omg_cli(&["info", "apt"]);
    // Dual-path: with a resolvable package the info pane shows details; without
    // one the failure names the missing package.
    assert_runs_without_panic(&result, "info apt");
    let combined = result.combined_output();
    if result.success {
        assert!(
            combined.contains("apt") || combined.contains("Version"),
            "Successful info must show package details: {combined}"
        );
    } else {
        assert!(
            combined.contains("not found"),
            "Failed info must name the missing-package cause: {combined}"
        );
    }
}

#[test]
fn test_cli_install_debian_package_dry_run() {
    let result = run_omg_cli(&["install", "--dry-run", "curl"]);
    // Dual-path: an available index renders the Install Preview table; a
    // missing/unresolvable package fails naming the cause.
    assert_dual_path_contract(
        &result,
        "Install Preview",
        "Error",
        "Debian install dry-run",
    );
    assert_no_arch_terms(&result.combined_output(), "Debian dry-run");
}

#[test]
fn test_cli_update_check_debian() {
    let result = run_omg_cli(&["update", "--check"]);
    assert_runs_without_panic(&result, "update --check");
    assert_no_arch_terms(&result.combined_output(), "Debian update check");

    // Update check is a read-only operation: it must never escalate.
    let combined = result.combined_output();
    assert!(
        !combined.contains("[sudo]") && !combined.contains("Password:"),
        "Update check should not require sudo: {combined}"
    );

    // Success must state one of the documented outcomes.
    result.assert_success();
    assert!(
        combined.contains("up to date")
            || combined.contains("upgraded")
            || combined.contains("update"),
        "Update check must report its outcome: {combined}"
    );
}

#[test]
fn cli_receipt_rejects_a_different_product_executable() {
    const CHILD: &str = "OMG_RECEIPT_IDENTITY_NEGATIVE_CHILD";
    if std::env::var(CHILD).as_deref() == Ok("1") {
        run_omg_cli(&["--version"]).assert_success();
        return;
    }
    let harness = std::env::current_exe().unwrap();
    let output = std::process::Command::new(&harness)
        .args([
            "--exact",
            "cli_receipt_rejects_a_different_product_executable",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .env("OMG_CONTRACT_EXPECTED_CLI", &harness)
        .output()
        .expect("run receipt identity negative control");
    assert!(!output.status.success(), "wrong executable was accepted");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("CLI fixture executable differs from the admitted receipt subject")
    );
}

#[test]
fn test_cli_status_shows_debian_info() {
    let data = TempDir::new().expect("temp data dir");
    let mock = omg_lib::package_managers::mock::MockPackageManager::new_in("debian", data.path());
    mock.set_installed_version("git", "1.0.0").unwrap();
    mock.set_installed_version("curl", "2.0.0").unwrap();
    mock.set_available_version("git", "1.1.0").unwrap();
    let state_path = data.path().join("mock_state_apt.json");
    let before = std::fs::read(&state_path).unwrap();
    let data_env = [("OMG_DATA_DIR", data.path().to_str().unwrap())];

    let result = run_omg_debian(&["status", "--json"], &data_env);
    result.assert_success();
    let status: serde_json::Value = serde_json::from_str(&result.stdout).unwrap();
    assert_eq!(status["total_packages"], 2);
    assert_eq!(status["explicit_packages"], 2);
    assert_eq!(status["orphan_packages"], 0);
    assert_eq!(status["updates_available"], 1);
    assert!(status["query_time_ms"].as_f64().unwrap() >= 0.0);

    let result = run_omg_debian(&["status"], &data_env);
    result.assert_success();
    result.assert_stdout_contains("2 packages installed");
    result.assert_stdout_contains("2 explicit");
    result.assert_stdout_contains("Not scanned");
    let updates = result
        .stdout
        .lines()
        .find(|line| line.split_whitespace().next() == Some("Updates"))
        .expect("status must report updates");
    assert_eq!(
        updates.split_whitespace().collect::<Vec<_>>(),
        ["Updates", "1"]
    );
    assert_no_arch_terms(&result.combined_output(), "Debian status");
    assert_eq!(std::fs::read(&state_path).unwrap(), before);

    // A separate invocation must not inherit this fixture or root-run state.
    let empty = run_omg_cli(&["status", "--json"]);
    empty.assert_success();
    let status: serde_json::Value = serde_json::from_str(&empty.stdout).unwrap();
    assert_eq!(status["total_packages"], 0);
    assert_eq!(status["updates_available"], 0);
    let fixture_path = data.path().to_path_buf();
    drop(mock);
    data.close().expect("status fixture cleanup");
    assert!(!fixture_path.exists());
}

#[test]
fn test_cli_list_installed_debian() {
    // Stateful contract: a mock-installed package shows up as explicitly
    // installed. The installed-package listing command is `explicit`
    // (src/cli/args.rs Explicit); the old `list --installed` invocation was
    // rejected by clap as an unknown argument.
    let data = TempDir::new().expect("temp data dir");
    let data_env = [("OMG_DATA_DIR", data.path().to_str().expect("utf8 path"))];

    let install = run_omg_debian(&["install", "-y", "git"], &data_env);
    install.assert_success();

    let listing = run_omg_debian(&["explicit"], &data_env);
    listing.assert_success();
    let output = listing.combined_output();
    assert!(
        output.contains("Explicit Packages"),
        "Explicit listing must render its header: {output}"
    );
    assert!(
        output.contains("git"),
        "Mock-installed 'git' must appear in the explicit listing: {output}"
    );
}

#[test]
fn test_cli_install_multiple_debian_packages() {
    let result = run_omg_cli(&["install", "--dry-run", "curl", "wget", "git"]);
    assert_dual_path_contract(
        &result,
        "Install Preview",
        "Error",
        "Debian multi-package install dry-run",
    );
    assert_no_arch_terms(
        &result.combined_output(),
        "Debian multi-package install dry-run",
    );
}

// test_cli_handles_debian_version_strings deleted (tst03): redundant duplicate
// of test_cli_info_debian_package (same `info` command, same no-panic contract).

// test_cli_debian_dependency_resolution deleted (tst03): redundant duplicate of
// test_cli_install_debian_package_dry_run (same command family, weaker
// assertion that passed on any successful output).

// test_cli_debian_sources_list_parsing and test_cli_debian_ppa_style_repos
// deleted (tst03): both were bare no-panic probes over `search`, now covered
// with concrete contracts by test_cli_search_on_debian.

// test_cli_debian_security_updates, test_cli_debian_handles_held_packages and
// test_cli_debian_handles_slow_mirrors deleted (tst03): all three ran the same
// `update --check` invocation as test_cli_update_check_debian with only a
// no-panic assertion; the concrete contracts live there.

#[test]
fn test_cli_debian_remove_dry_run() {
    let result = run_omg_cli(&["remove", "--dry-run", "curl"]);
    // Dual-path: a resolvable index renders the Remove Preview; otherwise the
    // failure names its cause.
    assert_dual_path_contract(&result, "Remove Preview", "Error", "Debian remove dry-run");
    assert_no_arch_terms(&result.combined_output(), "Debian remove dry-run");
}

// test_cli_debian_virtual_packages deleted (tst03): its unknown/virtual-package
// search probe is folded into test_cli_search_on_debian with a concrete
// "No results found" contract.

#[test]
fn test_cli_debian_package_not_found() {
    let result = run_omg_cli(&["install", "-y", "this-package-does-not-exist-xyz"]);

    let combined = result.combined_output();
    result.assert_failure();
    assert_no_arch_terms(&combined, "Debian install failure path");
    assert!(
        combined.contains("not found") || combined.contains("Unable"),
        "Should show helpful error message: {combined}"
    );
}

#[test]
fn test_cli_debian_install_with_recommends() {
    // Debian has recommended packages; the dry-run must either render the
    // preview table or name why it could not resolve.
    let result = run_omg_cli(&["install", "--dry-run", "vim"]);
    assert_dual_path_contract(
        &result,
        "Install Preview",
        "Error",
        "Debian vim install dry-run",
    );
}

// test_cli_debian_architecture_handling and test_cli_debian_multi_arch_support
// deleted (tst03): bare no-panic duplicates of the search/info contracts now
// pinned concretely in test_cli_search_on_debian / test_cli_info_debian_package.

#[test]
fn test_cli_debian_error_recovery() {
    // Each nonexistent package must be rejected with a named error — and the
    // CLI must keep working across repeated failures.
    for i in 0..5 {
        let result = run_omg_cli(&["install", "-y", &format!("fake-pkg-{i}")]);
        let context = format!("error recovery iteration {i}");
        assert_runs_without_panic(&result, &context);
        assert_no_arch_terms(&result.combined_output(), "Debian error recovery path");
        result.assert_failure();
        assert!(
            result.combined_output().contains("not found"),
            "{context}: rejection must name the missing package"
        );
    }
}

#[test]
fn test_cli_debian_full_workflow() {
    // Complete user workflow
    let commands = vec![
        vec!["status"],
        vec!["search", "curl"],
        vec!["info", "curl"],
        vec!["install", "--dry-run", "curl"],
        vec!["update", "--check"],
    ];

    for cmd in commands {
        let result = run_omg_cli(&cmd);
        assert_runs_without_panic(&result, &format!("command {cmd:?}"));
        assert_no_arch_terms(&result.combined_output(), "Debian full workflow command");
    }
}

#[test]
fn test_cli_debian_concurrent_operations() {
    use std::thread;

    // Test concurrent CLI invocations
    let handles: Vec<_> = (0..3)
        .map(|i| thread::spawn(move || run_omg_cli(&["search", &format!("pkg-{i}")])))
        .collect();

    for handle in handles {
        let result = handle.join().expect("Thread panicked");
        assert_runs_without_panic(&result, "concurrent operation");
        assert_no_arch_terms(&result.combined_output(), "Debian concurrent operation");
    }
}

// test_cli_debian_handles_slow_mirrors deleted (tst03): identical `update
// --check` no-panic probe as test_cli_update_check_debian, which pins concrete
// contracts for the same invocation.

#[test]
fn test_cli_debian_respects_ci_mode() {
    // CI does not grant installation consent. Refusal must leave the exact
    // fixture unchanged; explicit --yes must install into that same fixture.
    let data = TempDir::new().expect("temp data dir");
    let mock = omg_lib::package_managers::mock::MockPackageManager::new_in("debian", data.path());
    mock.set_installed_version("curl", "2.0.0").unwrap();
    mock.set_available_version("git", "3.2.1").unwrap();
    let state_path = data.path().join("mock_state_apt.json");
    let before = std::fs::read(&state_path).unwrap();
    let data_env = [("CI", "1"), ("OMG_DATA_DIR", data.path().to_str().unwrap())];
    let refused = run_omg_debian(&["install", "git"], &data_env);
    assert_eq!(refused.exit_code, 1);
    assert!(refused.combined_output().contains("Use --yes"));
    assert_eq!(std::fs::read(&state_path).unwrap(), before);

    let result = run_omg_debian(&["install", "git", "--yes"], &data_env);
    assert_runs_without_panic(&result, "CI-mode install");
    result.assert_success();

    let combined = result.combined_output();
    assert!(
        !combined.contains("Continue?")
            && !combined.contains("Press")
            && !combined.contains("Password:"),
        "Should not prompt in CI mode: {combined}"
    );
    assert!(
        combined.contains("Installed"),
        "CI-mode install must confirm the install: {combined}"
    );
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(state_path).unwrap()).unwrap();
    let installed = state["installed"].as_object().unwrap();
    assert_eq!(installed.len(), 2);
    assert_eq!(installed["curl"], "2.0.0");
    assert_eq!(installed["git"], "3.2.1");
    let fixture_path = data.path().to_path_buf();
    drop(mock);
    data.close().expect("consent fixture cleanup");
    assert!(!fixture_path.exists());
}

#[test]
fn test_cli_debian_package_name_validation() {
    // Test various package name formats
    let valid_names = vec!["curl", "python3", "lib-dev", "lib64c", "gcc-12"];

    for name in valid_names {
        let result = run_omg_cli(&["search", name]);
        // Search never fails on unusual-but-valid names: unknown names degrade
        // to the explicit "No results found" notice with exit 0.
        result.assert_success();
        assert_runs_without_panic(&result, &format!("search {name}"));
    }
}
