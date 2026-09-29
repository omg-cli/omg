//! Integration tests for error recovery in package operations.
//!
//! Covers parallel AUR build error handling and CLI-level recovery.
//! Transaction and retry subsystems were removed as dead weight.

#![cfg(feature = "arch")]

use omg_lib::package_managers::aur::BuildJob;

#[test]
fn test_parallel_builder_dependency_graph() {
    let jobs = vec![
        BuildJob::new("base".to_string(), vec![]),
        BuildJob::new("middle".to_string(), vec!["base".to_string()]),
        BuildJob::new("top".to_string(), vec!["middle".to_string()]),
    ];

    let graph = omg_lib::package_managers::aur::ParallelBuilder::build_dependency_graph(&jobs);

    assert_eq!(graph.get("base").unwrap().len(), 0);
    assert!(graph.get("middle").unwrap().contains("base"));
    assert!(graph.get("top").unwrap().contains("middle"));
}

#[test]
fn test_parallel_builder_independent_packages() {
    let jobs = vec![
        BuildJob::new("pkg-a".to_string(), vec![]),
        BuildJob::new("pkg-b".to_string(), vec![]),
        BuildJob::new("pkg-c".to_string(), vec![]),
    ];

    let graph = omg_lib::package_managers::aur::ParallelBuilder::build_dependency_graph(&jobs);
    let levels =
        omg_lib::package_managers::aur::ParallelBuilder::topological_levels(&graph).unwrap();

    assert_eq!(levels.len(), 1);
    assert_eq!(levels[0].len(), 3);
}

#[test]
fn test_parallel_builder_circular_dependency_detection() {
    use std::collections::{HashMap, HashSet};

    let mut graph = HashMap::new();
    graph.insert(
        "a".to_string(),
        std::iter::once("b".to_string()).collect::<HashSet<_>>(),
    );
    graph.insert(
        "b".to_string(),
        std::iter::once("c".to_string()).collect::<HashSet<_>>(),
    );
    graph.insert(
        "c".to_string(),
        std::iter::once("a".to_string()).collect::<HashSet<_>>(),
    );

    let result = omg_lib::package_managers::aur::ParallelBuilder::topological_levels(&graph);

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Circular dependency")
    );
}

#[test]
fn test_parallel_builder_complex_dependency_tree() {
    use std::collections::{HashMap, HashSet};

    let mut graph = HashMap::new();
    graph.insert("a".to_string(), HashSet::new());
    graph.insert("b".to_string(), std::iter::once("a".to_string()).collect());
    graph.insert("c".to_string(), std::iter::once("a".to_string()).collect());
    graph.insert(
        "d".to_string(),
        ["b".to_string(), "c".to_string()].into_iter().collect(),
    );
    graph.insert("e".to_string(), std::iter::once("d".to_string()).collect());

    let levels =
        omg_lib::package_managers::aur::ParallelBuilder::topological_levels(&graph).unwrap();

    assert_eq!(levels.len(), 4);
    assert_eq!(levels[0], vec!["a"]);
    assert_eq!(levels[1].len(), 2);
    assert!(levels[1].contains(&"b".to_string()));
    assert!(levels[1].contains(&"c".to_string()));
    assert_eq!(levels[2], vec!["d"]);
    assert_eq!(levels[3], vec!["e"]);
}

#[test]
fn test_parallel_builder_empty_jobs() {
    let jobs: Vec<BuildJob> = vec![];

    let graph = omg_lib::package_managers::aur::ParallelBuilder::build_dependency_graph(&jobs);

    assert!(graph.is_empty());
}

#[test]
fn test_parallel_builder_self_dependency_is_rejected_as_circular() {
    // Contract (src/package_managers/aur/parallel_build.rs:104-121):
    // build_dependency_graph keeps only dependencies that are themselves in
    // the job set — a package's own name IS in that set, so a self-edge
    // survives the filter. topological_levels must then refuse to schedule
    // the unsatisfiable node by reporting a circular dependency, never hang
    // or silently skip the package.
    let jobs = vec![BuildJob::new("pkg".to_string(), vec!["pkg".to_string()])];

    let graph = omg_lib::package_managers::aur::ParallelBuilder::build_dependency_graph(&jobs);
    let deps = graph
        .get("pkg")
        .expect("the job's own node must exist in the graph");
    assert!(
        deps.contains("pkg"),
        "the self-edge is within the job set, so it must be kept, got: {deps:?}"
    );

    let err = omg_lib::package_managers::aur::ParallelBuilder::topological_levels(&graph)
        .expect_err("a self-dependency is unschedulable and must be reported");
    assert!(
        err.to_string().contains("Circular dependency"),
        "self-dependency must surface as a circular dependency, got: {err}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// CLI ERROR HANDLING
//
// These tests run the real binary through the shared isolated runner
// (`common::TestProject` for recovery), which retains private HOME, data,
// config, cache and package roots across failure and recovery commands.
// Mock-state proof does not establish native transaction rollback.
//
// Deleted during wave 2 (dishonest surfaces, see review-tests.md M1):
// network-timeout recovery, SIGINT handling, Ctrl-C simulation, disk-full,
// command timeout, permission-denied, corrupted-cache, and AUR build-failure
// "tests" that injected no fault and only grepped for "panicked". Real
// fault-injection for those paths needs injectable failure seams in
// `core/http.rs` / cache layout — tracked as a src-side handoff.
// ═══════════════════════════════════════════════════════════════════════════════

pub mod common;

use common::{RejectedProxy, TestProject, run_omg, run_omg_with_env};

fn missing_dry_run(name: &str) -> common::CommandResult {
    let project = TestProject::for_distro("arch");
    let proxy = RejectedProxy::new();
    project.seed_missing_aur_index(name);
    let result = project.run_with_env(&["install", "--dry-run", name], &proxy.env());
    assert_eq!(result.exit_code, 1, "{}", result.combined_output());
    result.assert_stderr_contains("Package not found in AUR");
    assert!(!result.combined_output().contains("transport failed"));
    assert_eq!(
        proxy.requests(),
        0,
        "missing rejection consulted a live index"
    );
    project.close_checked();
    result
}

#[test]
fn test_dry_run_missing_package_fails_with_reason() {
    let result = missing_dry_run("nonexistent-pkg-xyz-12345");
    let combined = result.combined_output();

    assert!(
        !result.success,
        "dry run of a missing package must fail, got exit {}: {combined}",
        result.exit_code
    );
    assert!(
        combined.contains("not found"),
        "CLI must report the missing package explicitly, got: {combined}"
    );
}

/// Package/config bytes must survive; unresolved lookups create no transaction.
fn assert_failed_install_recovers(seed_index: bool) {
    let project = TestProject::for_distro("arch");
    let proxy = RejectedProxy::new();
    let env = proxy.env();
    project.mock_install("sentinel-package", "1.2.3").unwrap();
    project.mock_available("recovery-package", "4.5.6").unwrap();
    project
        .run_with_env(&["config", "set", "aur.build_concurrency", "2"], &env)
        .assert_success();
    if seed_index {
        project.seed_missing_aur_index("fake-package-xyz");
    }
    let package_state = project.data_dir.path().join("mock_state_pacman.json");
    let config = project.config_dir.path().join("config.toml");
    let before = (
        std::fs::read(&package_state).unwrap(),
        std::fs::read(&config).unwrap(),
    );
    assert!(!project.data_dir.path().join("history.json").exists());
    let result = project.run_with_env(&["install", "-y", "fake-package-xyz", "fake-pkg-2"], &env);
    assert_eq!(result.exit_code, 1, "{}", result.combined_output());
    if seed_index {
        result.assert_stderr_contains("Package not found in official repos");
        assert!(!result.combined_output().contains("transport failed"));
        assert_eq!(proxy.requests(), 0, "cached missing lookup reached network");
    } else {
        result.assert_stderr_contains("AUR RPC transport failed");
        result.assert_stderr_contains("fake-package-xyz");
        assert!(
            !result
                .combined_output()
                .contains("Package not found in official repos")
        );
        assert!(proxy.requests() > 0, "transport fault was not exercised");
    }
    assert_eq!(std::fs::read(&package_state).unwrap(), before.0);
    assert_eq!(std::fs::read(&config).unwrap(), before.1);
    let history = omg_lib::core::history::HistoryManager::new_in(
        project.data_dir.path().join("history.json"),
    )
    .unwrap()
    .load()
    .unwrap();
    assert!(
        history.is_empty(),
        "lookup-only failure must not invent a transaction"
    );
    assert!(!project.data_dir.path().join("history.json").exists());
    // This package exists ONLY in the persisted state, not in the stock mock.
    let recovery = project.run_with_env(&["install", "--dry-run", "recovery-package"], &env);
    recovery.assert_success();
    recovery.assert_stdout_contains("recovery-package");
    recovery.assert_stdout_contains("4.5.6");
    recovery.assert_stdout_contains("No changes will be made (dry run)");
    assert_eq!(std::fs::read(&package_state).unwrap(), before.0);
    assert_eq!(std::fs::read(&config).unwrap(), before.1);
    assert!(!project.data_dir.path().join("history.json").exists());
    project.close_checked();
}

#[test]
fn test_install_missing_packages_fails_without_corrupting_state() {
    assert_failed_install_recovers(true);
}

#[test]
fn test_install_transport_failure_preserves_state_and_recovers() {
    assert_failed_install_recovers(false);
}

#[test]
fn test_malicious_package_names_are_rejected_with_reason() {
    let malicious = [
        "pkg; rm -rf /",
        "pkg && echo evil",
        "pkg | cat /etc/passwd",
        "../../../etc/passwd",
        "pkg`whoami`",
    ];

    for name in malicious {
        let result = run_omg(&["install", "--dry-run", name]);
        let combined = result.combined_output();
        assert!(
            !result.success,
            "malicious package name '{name}' must be rejected"
        );
        assert!(
            combined.contains("Invalid")
                || combined.contains("invalid")
                || combined.contains("not found")
                || combined.contains("cannot start with")
                || combined.contains("path traversal"),
            "rejection of '{name}' must explain why, got: {combined}"
        );
        assert!(
            !combined.contains("panicked at"),
            "validation errors must be graceful, got: {combined}"
        );
    }
}

#[test]
fn test_cli_error_message_names_the_package() {
    let result = missing_dry_run("definitely-nonexistent-package-xyz123");
    let combined = result.combined_output();
    assert!(
        !result.success,
        "a nonexistent package must fail the command, got exit {}: {combined}",
        result.exit_code
    );
    assert!(
        combined.contains("definitely-nonexistent-package-xyz123"),
        "error output must echo the offending package name, got: {combined}"
    );
}

#[test]
fn test_concurrent_dry_runs_are_isolated_and_deterministic() {
    use std::thread;

    // With per-invocation data dirs, concurrent invocations cannot observe
    // each other's mock state; every missing package must fail identically.
    let handles: [_; 3] = std::array::from_fn(|i| {
        thread::spawn(move || missing_dry_run(&format!("isolated-missing-pkg-{i}")))
    });

    for (i, handle) in handles.into_iter().enumerate() {
        let result = handle.join().expect("worker thread panicked");
        let combined = result.combined_output();
        assert!(
            !result.success && combined.contains("not found"),
            "concurrent dry run {i} must deterministically report the missing package: {combined}"
        );
    }
}

#[test]
fn test_update_check_succeeds_in_test_mode() {
    let result = run_omg(&["update", "--check"]);
    assert!(
        result.success,
        "`update --check` should complete against the mock backend: {}{}",
        result.stdout, result.stderr
    );
    assert!(
        !result.stderr.contains("panicked at"),
        "update check must not panic: {}",
        result.stderr
    );
}

#[test]
fn test_ci_mode_dry_run_succeeds_without_prompts() {
    let result = run_omg_with_env(
        &["install", "--dry-run", "firefox"],
        &[("CI", "1"), ("OMG_NON_INTERACTIVE", "1")],
    );
    let combined = result.combined_output();

    assert!(
        result.success,
        "CI dry run of an existing package should succeed: {combined}"
    );
    assert!(
        !combined.contains("Press") && !combined.contains("Continue?"),
        "must not prompt in CI environment: {combined}"
    );
}

#[test]
fn test_dry_run_never_prompts_for_password() {
    let result = run_omg(&["install", "--dry-run", "firefox"]);
    let combined = result.combined_output();
    assert!(
        !combined.contains("[sudo]") && !combined.contains("Password:"),
        "Dry run should never prompt for password: {combined}"
    );
}
