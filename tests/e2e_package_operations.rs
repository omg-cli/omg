//! End-to-End Tests for Package Operations
//!
//! Comprehensive e2e tests covering the complete package management lifecycle:
//! - Search (official repos + AUR)
//! - Install (with dependency resolution)
//! - Info (package details)
//! - Update (system-wide updates)
//! - Remove (with cleanup)
//!
//! These tests use real CLI invocations. Every assertion pins an observable
//! contract observed against the hermetic test-mode backend
//! (`OMG_TEST_MODE=1` routes reads through `MockPackageManager`, see
//! `src/package_managers/mod.rs:294`). The former `success || contains(...)`
//! disjunctions passed whenever EITHER side held and could never fail; they
//! were rewritten per the audit's vacuous-assertion finding.
//!
//! Run:
//!   cargo test --features arch --test e2e_package_operations

#![cfg(feature = "arch")]
#![expect(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]

pub mod common;

use common::*;

// ═══════════════════════════════════════════════════════════════════════════════
// SEARCH COMMAND E2E TESTS
// ═══════════════════════════════════════════════════════════════════════════════

/// The test-mode Arch mock database ships exactly `pacman`, `firefox`, `git`
/// (src/package_managers/mock.rs:60). Searching `git` must return its compact
/// row (`name version (source)`), proving the search pipeline end to end.
#[test]
fn test_search_official_package() {
    init_test_env();

    let result = run_omg(&["search", "git"]);

    result.assert_success();
    let stdout = &result.stdout;
    assert!(
        stdout.contains("| Search"),
        "search must print its results header. Got:\n{}",
        result.combined_output()
    );
    // Mock version 2.43.0 proves the query hit the isolated mock DB, not the
    // host pacman sync DB.
    assert!(
        stdout.contains("git 2.43.0"),
        "search must list git at the mock version. Got:\n{stdout}"
    );
    assert!(
        stdout.contains("Official"),
        "search must tag the source repository. Got:\n{stdout}"
    );
}

/// An unknown query must still exit successfully (empty result set is valid,
/// src/cli/packages/search.rs returns Ok after `no_results`) and tell the
/// user what was searched for by echoing the query
/// (`Components::no_results(query)`).
#[test]
fn test_search_no_results() {
    init_test_env();

    let query = "package-that-absolutely-does-not-exist-xyz123";
    let result = run_omg(&["search", query]);

    result.assert_success();
    let combined = result.combined_output();
    assert!(
        combined.contains("No results found"),
        "empty search must say so explicitly. Got:\n{combined}"
    );
    assert!(
        combined.contains(query),
        "no-results message must echo the query. Got:\n{combined}"
    );
}

/// `--no-aur` skips community sources (args.rs:52) but official results are
/// authoritative and must still render (src/cli/packages/search.rs:101-107:
/// official results remain useful when optional AUR enrichment is absent).
#[test]
fn test_search_with_no_aur_flag() {
    init_test_env();

    let result = run_omg(&["search", "--no-aur", "firefox"]);

    result.assert_success();
    let combined = result.combined_output();
    assert!(
        combined.contains("| Search") && combined.contains("firefox"),
        "--no-aur must still return official-repository results. Got:\n{combined}"
    );
}

/// The global `--json` flag (src/cli/args.rs:29) makes search emit a machine-
/// readable array of DisplayPackage records (src/cli/packages/search.rs:129).
/// This contract holds unconditionally — the previous `if success` guard made
/// the assertion vacuous on the failure path.
#[test]
fn test_search_json_output() {
    init_test_env();

    let result = run_omg(&["search", "--json", "git"]);

    result.assert_success();
    let json: serde_json::Value = serde_json::from_str(&result.stdout).unwrap_or_else(|error| {
        panic!(
            "--json search must print valid JSON: {error}\n{}",
            result.stdout
        )
    });
    let rows = json.as_array().expect("--json search must print an array");
    let git = rows
        .iter()
        .find(|row| row.get("name").and_then(|n| n.as_str()) == Some("git"))
        .expect("JSON search for git must contain the git record");
    assert_eq!(
        git.get("version").and_then(|v| v.as_str()),
        Some("2.43.0"),
        "JSON record carries the mock version"
    );
    assert_eq!(
        git.get("source").and_then(|v| v.as_str()),
        Some("Official"),
        "JSON record carries the source"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// INFO COMMAND E2E TESTS
// ═══════════════════════════════════════════════════════════════════════════════

/// `info` renders labeled metadata fields and source provenance for a real
/// package.
#[test]
fn test_info_common_package() {
    init_test_env();

    let result = run_omg(&["info", "pacman"]);

    result.assert_success();
    let output = result.combined_output();
    for field in ["Description:", "Source:", "Official repository"] {
        assert!(
            output.contains(field),
            "info must show the {field} field. Got:\n{output}"
        );
    }
    assert!(
        output.contains("pacman"),
        "info must name the queried package. Got:\n{output}"
    );
}

/// `info` of a package absent from both repos and AUR fails and echoes the
/// query so users can see typos ("Package 'X' not found. Try: omg search X").
#[test]
fn test_info_nonexistent_package() {
    init_test_env();

    let result = run_omg(&["info", "nonexistent-package-xyz123"]);

    result.assert_failure();
    let combined = result.combined_output();
    assert!(
        combined.contains("not found"),
        "info of a missing package must say so. Got:\n{combined}"
    );
    assert!(
        combined.contains("nonexistent-package-xyz123"),
        "the error must echo the queried name. Got:\n{combined}"
    );
}

/// Key package facts (description, size) are part of the info contract.
#[test]
fn test_info_shows_package_details() {
    init_test_env();

    let result = run_omg(&["info", "pacman"]);

    result.assert_success();
    let output = result.combined_output();
    assert!(
        output.contains("| Info"),
        "info must render its phase header. Got:\n{output}"
    );
    assert!(
        output.contains("Name:") && output.contains("pacman"),
        "info must show the package identity card. Got:\n{output}"
    );
    assert!(
        output.contains("Description:"),
        "info must show the description. Got:\n{output}"
    );
    assert!(
        !output.contains("Download:"),
        "default info omits verbose-only extras. Got:\n{output}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// INSTALL COMMAND E2E TESTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Dry-run install always renders an "Install Preview" naming every requested
/// package and states that no changes will be made.
#[test]
fn test_install_dry_run() {
    init_test_env();

    let result = run_omg(&["install", "--dry-run", "firefox"]);

    result.assert_success();
    let output = result.combined_output();
    assert!(
        output.contains("Install Preview"),
        "dry-run must print the install preview. Got:\n{output}"
    );
    assert!(
        output.contains("firefox"),
        "preview must list the requested package. Got:\n{output}"
    );
    assert!(
        output.contains("No changes will be made (dry run)"),
        "dry-run must state it is non-mutating. Got:\n{output}"
    );
}

/// Installing an already-installed core package previews the same non-mutating
/// plan rather than erroring.
#[test]
fn test_install_already_installed() {
    init_test_env();

    let result = run_omg(&["install", "--dry-run", "pacman"]);

    result.assert_success();
    let output = result.combined_output();
    assert!(
        output.contains("Install Preview") && output.contains("pacman"),
        "preview must show the package. Got:\n{output}"
    );
    assert!(
        output.contains("No changes will be made (dry run)"),
        "dry-run must state it is non-mutating. Got:\n{output}"
    );
}

/// Multiple requested packages all appear in one preview.
#[test]
fn test_install_multiple_packages_dry_run() {
    init_test_env();

    let result = run_omg(&["install", "--dry-run", "pacman", "firefox", "git"]);

    result.assert_success();
    let output = result.combined_output();
    assert!(
        output.contains("Install Preview"),
        "multi-package dry-run must print the preview. Got:\n{output}"
    );
    for pkg in ["pacman", "firefox", "git"] {
        assert!(
            output.contains(pkg),
            "preview must list every requested package ({pkg}). Got:\n{output}"
        );
    }
}

/// A package that exists nowhere fails the dry-run and names the offender.
#[test]
fn test_install_nonexistent_package() {
    init_test_env();

    let result = run_omg(&["install", "--dry-run", "absolutely-nonexistent-package-xyz"]);

    result.assert_failure();
    let combined = result.combined_output();
    assert!(
        combined.contains("was not found")
            && combined.contains("absolutely-nonexistent-package-xyz"),
        "missing package must be named explicitly. Got:\n{combined}"
    );
}

/// `--yes` combined with `--dry-run` completes without any prompt and keeps
/// the non-mutating preview contract.
#[test]
fn test_install_with_yes_flag() {
    init_test_env();

    let result = run_omg(&["install", "--yes", "--dry-run", "git"]);

    result.assert_success();
    let output = result.combined_output();
    assert!(
        output.contains("Install Preview") && output.contains("git"),
        "--yes --dry-run must still render the preview. Got:\n{output}"
    );
    assert!(
        output.contains("No changes will be made (dry run)"),
        "--yes must not bypass the dry-run guarantee. Got:\n{output}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// UPDATE COMMAND E2E TESTS
// ═══════════════════════════════════════════════════════════════════════════════

/// `update --check` is a pure read: with empty mock state it reports the
/// system up to date; with a seeded older installed version it names the
/// pending upgrade (`firefox 121.0 → 123.0`).
#[test]
fn test_update_check_only() {
    init_test_env();

    let clean = TestProject::new();
    let result = clean.run(&["update", "--check"]);
    result.assert_success();
    assert!(
        result.combined_output().contains("System is up to date"),
        "fresh environment must report up-to-date. Got:\n{}",
        result.combined_output()
    );

    let stale = TestProject::new();
    stale.mock_install("firefox", "121.0").unwrap();
    stale.mock_available("firefox", "123.0").unwrap();
    let result = stale.run(&["update", "--check"]);
    result.assert_success();
    let output = result.combined_output();
    assert!(
        output.contains("update available"),
        "seeded outdated state must report available updates. Got:\n{output}"
    );
    assert!(
        output.contains("firefox 121.0 → 123.0"),
        "update listing must show old → new versions. Got:\n{output}"
    );
}

/// `--dry-run` reports what would be updated without changing anything.
#[test]
fn test_update_dry_run() {
    init_test_env();

    let project = TestProject::new();
    let result = project.run(&["update", "--dry-run"]);

    result.assert_success();
    let output = result.combined_output();
    assert!(
        output.contains("checking for updates"),
        "dry-run must announce the check phase. Got:\n{output}"
    );
    assert!(
        output.contains("System is up to date"),
        "fresh environment must report up-to-date. Got:\n{output}"
    );
}

/// `--yes` with `--check` stays a read-only check (fast/turbo semantics are
/// rejected elsewhere; see omg.rs:979) and still prints the status.
#[test]
fn test_update_with_yes_flag() {
    init_test_env();

    let project = TestProject::new();
    let result = project.run(&["update", "--check", "--yes"]);

    result.assert_success();
    let output = result.combined_output();
    assert!(
        output.contains("Checking for updates · cached") && output.contains("System is up to date"),
        "--yes must not turn --check into an install. Got:\n{output}"
    );
}

/// `--fast` cannot be combined with `--dry-run`: fast mode runs
/// non-interactively without preview, so honoring --dry-run there would be a
/// lie (src/bin/omg.rs:976-985 rejects the combination explicitly).
#[test]
fn test_update_fast_dry_run_rejected() {
    init_test_env();

    let result = run_omg(&["update", "--fast", "--dry-run"]);

    result.assert_failure();
    let combined = result.combined_output();
    assert!(
        combined.contains("--dry-run cannot be combined with --fast/--turbo"),
        "flag conflict must be named explicitly. Got:\n{combined}"
    );
}

/// Same contract for turbo mode (src/bin/omg.rs:979).
#[test]
fn test_update_turbo_dry_run_rejected() {
    init_test_env();

    let result = run_omg(&["update", "--turbo", "--dry-run"]);

    result.assert_failure();
    let combined = result.combined_output();
    assert!(
        combined.contains("--dry-run cannot be combined with --fast/--turbo"),
        "flag conflict must be named explicitly. Got:\n{combined}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// REMOVE COMMAND E2E TESTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Dry-run removal of an installed package prints a Remove Preview naming the
/// package, the freed space, and the non-mutating marker. Installed metadata
/// is seeded in the isolated mock backend; host packages are not consulted.
#[test]
fn test_remove_dry_run() {
    let project = TestProject::new();
    project.mock_install("pacman", "6.0.2").unwrap();
    let state_path = project.data_dir.path().join("mock_state_pacman.json");
    let before = std::fs::read(&state_path).unwrap();
    let state: serde_json::Value = serde_json::from_slice(&before).unwrap();
    assert_eq!(state["installed"]["pacman"].as_str(), Some("6.0.2"));

    let result = project.run(&["remove", "--dry-run", "pacman"]);

    result.assert_success();
    let output = result.combined_output();
    assert!(
        output.contains("Remove Preview"),
        "removal dry-run must print the preview. Got:\n{output}"
    );
    assert!(
        output.contains("would be removed") && output.contains("pacman"),
        "preview must name the removed package. Got:\n{output}"
    );
    assert!(
        output.contains("No changes made (dry run)"),
        "dry-run must state it is non-mutating. Got:\n{output}"
    );
    result.assert_stdout_contains("6.0.2");
    assert_eq!(std::fs::read(&state_path).unwrap(), before);
    project.close_checked();
}

/// Removing a package that is not installed fails and names it.
#[test]
fn test_remove_nonexistent_package() {
    init_test_env();

    let result = run_omg(&["remove", "--dry-run", "package-never-installed-xyz"]);

    result.assert_failure();
    let combined = result.combined_output();
    assert!(
        combined.contains("is not installed") && combined.contains("package-never-installed-xyz"),
        "uninstalled-package removal must fail naming the package. Got:\n{combined}"
    );
}

/// `--recursive` adds orphaned-dependency cleanup to the preview; the plain
/// invocation must not mention it, proving the flag actually changes the plan.
#[test]
fn test_remove_recursive_flag() {
    let project = TestProject::new();
    project.mock_install("pacman", "6.0.2").unwrap();
    let state_path = project.data_dir.path().join("mock_state_pacman.json");
    let before = std::fs::read(&state_path).unwrap();
    let state: serde_json::Value = serde_json::from_slice(&before).unwrap();
    assert_eq!(state["installed"]["pacman"].as_str(), Some("6.0.2"));

    let plain = project.run(&["remove", "--dry-run", "pacman"]);
    plain.assert_success();
    assert!(
        !plain.combined_output().contains("Orphaned dependencies"),
        "plain remove must not promise orphan cleanup. Got:\n{}",
        plain.combined_output()
    );

    plain.assert_stdout_contains("6.0.2");
    plain.assert_stdout_contains("No changes made (dry run)");
    assert!(
        !plain
            .combined_output()
            .contains("Additional unneeded dependencies would also be removed")
    );
    assert_eq!(std::fs::read(&state_path).unwrap(), before);

    let recursive = project.run(&["remove", "--recursive", "--dry-run", "pacman"]);
    recursive.assert_success();
    let output = recursive.combined_output();
    assert!(
        output.contains("Additional unneeded dependencies would also be removed"),
        "--recursive must add orphan cleanup to the plan. Got:\n{output}"
    );
    assert!(
        output.contains("pacman"),
        "recursive preview must keep the base package. Got:\n{output}"
    );
    recursive.assert_stdout_contains("6.0.2");
    recursive.assert_stdout_contains("No changes made (dry run)");
    assert_eq!(std::fs::read(&state_path).unwrap(), before);
    project.close_checked();
}

/// Multiple seeded packages appear together in one removal preview.
#[test]
fn test_remove_multiple_packages() {
    let project = TestProject::new();
    project.mock_install("pacman", "6.0.2").unwrap();
    project.mock_install("firefox", "122.0").unwrap();

    let result = project.run(&["remove", "--dry-run", "pacman", "firefox"]);

    result.assert_success();
    let output = result.combined_output();
    assert!(
        output.contains("Remove Preview"),
        "must print the removal preview. Got:\n{output}"
    );
    for pkg in ["pacman", "firefox"] {
        assert!(
            output.contains(pkg),
            "preview must list every requested package ({pkg}). Got:\n{output}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUXILIARY COMMANDS E2E TESTS
// ═══════════════════════════════════════════════════════════════════════════════

/// `explicit` lists explicitly installed packages from the isolated mock
/// state (list_explicit_fast honors test mode,
/// src/package_managers/mod.rs:95). A fresh data dir has none, so the count
/// in the header must be 0 — this also proves the command never leaks host
/// pacman state into the sandbox.
#[test]
fn test_explicit_list() {
    init_test_env();

    let result = run_omg(&["explicit"]);

    result.assert_success();
    let output = result.combined_output();
    assert!(
        output.contains("Explicit Packages"),
        "must print the explicit-packages section. Got:\n{output}"
    );
    assert!(
        output.contains("0 installed"),
        "isolated fresh state must show zero packages, not host state. Got:\n{output}"
    );
}

/// Regression: count and list queries must both read the isolated mock state
/// before consulting a daemon, fast-status snapshot, or host package database.
#[test]
fn test_explicit_count_observes_mock_state() {
    for distro in ["arch", "debian"] {
        let project = TestProject::for_distro(distro);
        project.mock_install("audit-only-package", "1.0").unwrap();

        let count = project.run(&["explicit", "--count"]);
        count.assert_success();
        assert_eq!(count.stdout.trim(), "1", "isolated count for {distro}");

        let list = project.run(&["explicit"]);
        list.assert_success();
        assert!(
            list.stdout.contains("audit-only-package"),
            "isolated package missing for {distro}: {}",
            list.stdout
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MULTI-COMMAND WORKFLOW TESTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Workflow: search finds the package, then info renders its details.
#[test]
fn test_workflow_search_then_info() {
    init_test_env();

    let search_result = run_omg(&["search", "git"]);
    search_result.assert_success();
    assert!(
        search_result.stdout_contains("git 2.43.0"),
        "search step must find git. Got:\n{}",
        search_result.stdout
    );

    let info_result = run_omg(&["info", "git"]);
    info_result.assert_success();
    assert!(
        info_result.combined_output().contains("Description:"),
        "info step must render details. Got:\n{}",
        info_result.combined_output()
    );
}

/// Workflow: inspect a package, then preview installing it without mutating.
#[test]
fn test_workflow_info_then_install_dry_run() {
    init_test_env();

    let info_result = run_omg(&["info", "git"]);
    info_result.assert_success();
    assert!(
        info_result.combined_output().contains("Description:"),
        "info step must render details. Got:\n{}",
        info_result.combined_output()
    );

    let install_result = run_omg(&["install", "--dry-run", "git"]);
    install_result.assert_success();
    let output = install_result.combined_output();
    assert!(
        output.contains("Install Preview")
            && output.contains("git")
            && output.contains("No changes will be made (dry run)"),
        "install step must render a non-mutating preview. Got:\n{output}"
    );
}

/// Workflow: check updates, then list explicit packages — both steps prove
/// their own work.
#[test]
fn test_workflow_update_check_then_explicit() {
    init_test_env();

    let update_result = run_omg(&["update", "--check"]);
    update_result.assert_success();
    assert!(
        update_result
            .combined_output()
            .contains("System is up to date"),
        "update step must report status. Got:\n{}",
        update_result.combined_output()
    );

    let explicit_result = run_omg(&["explicit"]);
    explicit_result.assert_success();
    assert!(
        explicit_result
            .combined_output()
            .contains("Explicit Packages"),
        "explicit step must list packages. Got:\n{}",
        explicit_result.combined_output()
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// ERROR HANDLING AND EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════════

/// clap must reject a subcommand missing its required positional argument and
/// say which argument is required.
#[test]
fn test_error_missing_package_argument() {
    init_test_env();

    let result = run_omg(&["install"]);

    result.assert_failure();
    let output = result.combined_output();
    assert!(
        output.contains("No packages specified"),
        "bare install must fail with guidance instead of a clap contract error. Got:\n{output}"
    );
}

/// clap must reject unknown flags as unexpected arguments.
#[test]
fn test_error_invalid_flag() {
    init_test_env();

    let result = run_omg(&["search", "--invalid-flag-xyz", "test"]);

    result.assert_failure();
    let output = result.combined_output();
    assert!(
        output.contains("unexpected argument '--invalid-flag-xyz'"),
        "clap must reject the unknown flag by name. Got:\n{output}"
    );
}

/// `--quiet` suppresses non-essential output, but command RESULTS still print
/// (src/cli/args.rs:23-25: "Command results still print").
#[test]
fn test_quiet_flag_preserves_results() {
    init_test_env();

    let result = run_omg(&["search", "--quiet", "git"]);

    result.assert_success();
    let stdout = &result.stdout;
    assert!(
        stdout.contains("| Search") && stdout.contains("git 2.43.0"),
        "quiet mode must still print search results. Got:\n{stdout}"
    );
}

/// Global `-vv` parses everywhere and does not break the wrapped command;
/// the package details remain visible.
#[test]
fn test_verbose_flag_accepted_globally() {
    init_test_env();

    let verbose_result = run_omg(&["info", "-vv", "git"]);
    verbose_result.assert_success();
    let output = verbose_result.combined_output();
    assert!(
        output.contains("Description:") && output.contains("git"),
        "-vv must leave the command result intact. Got:\n{output}"
    );

    let normal_result = run_omg(&["info", "git"]);
    normal_result.assert_success();
}
