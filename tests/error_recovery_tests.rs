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
// (`common::run_omg`), which provisions unique `OMG_DATA_DIR`,
// `OMG_CONFIG_DIR`, and `OMG_CACHE_DIR` per invocation. Every expectation
// below was verified against actual CLI behavior in test mode; none of them
// rely on panic-string greps alone.
//
// Deleted during wave 2 (dishonest surfaces, see review-tests.md M1):
// network-timeout recovery, SIGINT handling, Ctrl-C simulation, disk-full,
// command timeout, permission-denied, corrupted-cache, and AUR build-failure
// "tests" that injected no fault and only grepped for "panicked". Real
// fault-injection for those paths needs injectable failure seams in
// `core/http.rs` / cache layout — tracked as a src-side handoff.
// ═══════════════════════════════════════════════════════════════════════════════

pub mod common;

use common::{TestProject, fixture_program_hash, run_omg, run_omg_with_env};

#[path = "support/recovery_fixture.rs"]
mod recovery_fixture;
use recovery_fixture::RejectedProxy;

fn run_aur_transport_child(project: &TestProject, proxy: &RejectedProxy) -> std::process::Output {
    let mut command = std::process::Command::new("timeout");
    command
        .args(["--kill-after=2s", "15s"])
        .arg(std::env::current_exe().expect("ordinary AUR adapter test executable"))
        .args([
            "--exact",
            "test_aur_transport_failure_preserves_state_and_mock_install_recovers",
            "--nocapture",
        ])
        .env_clear()
        .env("HOME", project.home_dir.path())
        .env(
            "PATH",
            std::env::var_os("PATH").expect("native fixture PATH"),
        )
        .env("OMG_DATA_DIR", project.data_dir.path())
        .env("OMG_CONFIG_DIR", project.config_dir.path())
        .env("OMG_CACHE_DIR", project.data_dir.path().join("cache"))
        .env("OMG_TEST_MODE", "0")
        .env("OMG_DISABLE_DAEMON", "1")
        .env("OMG_DISABLE_TELEMETRY", "1")
        .env("OMG_AUR_TRANSPORT_CHILD", "adapter");
    for (key, value) in proxy.env() {
        command.env(key, value);
    }
    let output = command.output().expect("execute actual AUR adapter child");
    eprintln!(
        "AUR adapter child exit={:?} proxy_requests={}\n{}\n{}",
        output.status.code(),
        proxy.requests(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn copy_fixture_program(
    directory: &std::path::Path,
    original: &std::path::Path,
    name: &str,
) -> (std::path::PathBuf, String) {
    use std::os::unix::fs::PermissionsExt as _;
    let copy = directory.join(name);
    std::fs::copy(original, &copy).expect("copy admitted fixture program");
    std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o755))
        .expect("ordinary fixture execution");
    let hash = fixture_program_hash(original);
    assert_eq!(
        hash,
        fixture_program_hash(&copy),
        "ordinary fixture copy must preserve admitted program bytes"
    );
    (copy, hash)
}
fn rerun_transport_as_ordinary_user() -> bool {
    if !omg_lib::core::is_root() {
        return false;
    }
    use std::os::unix::fs::PermissionsExt as _;
    let cli = std::fs::symlink_metadata(env!("CARGO_BIN_EXE_omg")).expect("admitted CLI metadata");
    assert!(cli.is_file(), "admitted CLI must be a regular file");
    let account = nix::unistd::User::from_name("nobody")
        .expect("look up ordinary fixture account")
        .expect("root fixture must provide an ordinary account");
    assert_ne!(account.uid.as_raw(), 0);
    let directory =
        tempfile::TempDir::new_in("/var/tmp").expect("ordinary test executable directory");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755))
        .expect("ordinary executable traversal");
    let original = std::env::current_exe().expect("root test executable");
    let original_cli = std::path::Path::new(env!("CARGO_BIN_EXE_omg"));
    if let Some(expected) = std::env::var_os("OMG_CONTRACT_EXPECTED_CLI") {
        assert_eq!(
            original_cli.canonicalize().expect("admitted CLI exists"),
            std::path::Path::new(&expected)
                .canonicalize()
                .expect("expected CLI exists"),
            "root fixture must retain the parent driver subject binding"
        );
    }
    let (copied_cli, cli_hash) = copy_fixture_program(directory.path(), original_cli, "omg");
    let receipt_path = directory.path().join("cli-subject.json");
    std::fs::write(
        &receipt_path,
        serde_json::to_vec(&serde_json::json!({
            "original": original_cli, "copy": copied_cli, "sha256": cli_hash
        }))
        .expect("CLI receipt serialization"),
    )
    .expect("write protected CLI receipt");
    std::fs::set_permissions(&receipt_path, std::fs::Permissions::from_mode(0o644))
        .expect("ordinary receipt read with root-only write");
    let (executable, copied_hash) = copy_fixture_program(directory.path(), &original, "aur-test");
    let output = std::process::Command::new(
        omg_lib::core::privilege::trusted_program("timeout")
            .expect("root-controlled fixture timeout"),
    )
    .args(["--kill-after=2s", "60s"])
    .arg(
        omg_lib::core::privilege::trusted_program("setpriv")
            .expect("root-controlled privilege drop"),
    )
    .args(["--clear-groups", "--no-new-privs"])
    .arg(format!("--reuid={}", account.uid))
    .arg(format!("--regid={}", account.gid))
    .arg(&executable)
    .args([
        "--exact",
        "test_aur_transport_failure_preserves_state_and_mock_install_recovers",
        "--nocapture",
    ])
    .env_clear()
    .env(
        "PATH",
        std::env::var_os("PATH").expect("native fixture PATH"),
    )
    .env("HOME", directory.path())
    .env("TMPDIR", "/var/tmp")
    .env("OMG_CONTRACT_EXPECTED_CLI", env!("CARGO_BIN_EXE_omg"))
    .env("OMG_CONTRACT_CLI_ROOT_FIXTURE", &receipt_path)
    .current_dir(directory.path())
    .output()
    .expect("ordinary root fixture child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("ordinary AUR child executable_sha256={copied_hash}\n{stdout}\n{stderr}");
    assert!(
        output.status.success() && stdout.contains("1 passed; 0 failed; 0 ignored;"),
        "ordinary AUR child failed or did not run: {}\n{stdout}\n{stderr}",
        output.status
    );
    assert_eq!(cli_hash, fixture_program_hash(original_cli));
    assert_eq!(cli_hash, fixture_program_hash(&copied_cli));
    assert_eq!(copied_hash, fixture_program_hash(&executable));
    true
}

fn missing_dry_run(name: &str) -> common::CommandResult {
    let project = TestProject::for_distro("arch");
    let proxy = RejectedProxy::new();
    let result = project.run_with_env(&["install", "--dry-run", name], &proxy.env());
    assert_eq!(result.exit_code, 1, "{}", result.combined_output());
    result.assert_stderr_contains(&format!("Package '{name}' was not found"));
    assert!(!result.combined_output().contains("transport failed"));
    assert_eq!(
        proxy.requests(),
        0,
        "missing rejection consulted a live index"
    );
    project.close_checked();
    result
}

struct PersistentBytes {
    packages: Vec<u8>,
    config: Vec<u8>,
}

impl PersistentBytes {
    fn capture(packages: &std::path::Path, config: &std::path::Path) -> Self {
        Self {
            packages: std::fs::read(packages).unwrap(),
            config: std::fs::read(config).unwrap(),
        }
    }

    fn matches(&self, packages: &std::path::Path, config: &std::path::Path) -> bool {
        std::fs::read(packages).is_ok_and(|bytes| bytes == self.packages)
            && std::fs::read(config).is_ok_and(|bytes| bytes == self.config)
    }
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
enum FailureFixture {
    MockMissing,
    AurTransport,
}

fn assert_failed_install_recovers(fixture: FailureFixture) {
    let project = TestProject::for_distro("arch");
    let proxy = RejectedProxy::new();
    let env = proxy.env();
    project.mock_install("sentinel-package", "1.2.3").unwrap();
    project.mock_available("recovery-package", "4.5.6").unwrap();
    project
        .run_with_env(&["config", "set", "aur.build_concurrency", "2"], &env)
        .assert_success();
    let package_state = project.data_dir.path().join("mock_state_pacman.json");
    let config = project.config_dir.path().join("config.toml");
    let before = PersistentBytes::capture(&package_state, &config);
    assert!(!project.data_dir.path().join("history.json").exists());
    match fixture {
        FailureFixture::MockMissing => {
            let result =
                project.run_with_env(&["install", "-y", "fake-package-xyz", "fake-pkg-2"], &env);
            assert_eq!(result.exit_code, 1, "{}", result.combined_output());
            result.assert_stderr_contains("Package 'fake-package-xyz' not found. Suggestion: use 'omg search' to check available package names");
            assert!(!result.combined_output().contains("transport failed"));
            assert_eq!(proxy.requests(), 0, "mock missing lookup reached network");
        }
        FailureFixture::AurTransport => {
            let result = run_aur_transport_child(&project, &proxy);
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let stdout = String::from_utf8(result.stdout).expect("UTF-8 AUR adapter result");
            assert!(stdout.contains("AUR RPC transport failed. Check your internet connection."));
            assert!(stdout.contains("1 passed; 0 failed; 0 ignored;"));
            assert!(!stdout.contains("not found"));
            assert!(
                proxy.requests() > 0,
                "actual AUR transport fault was not exercised"
            );
        }
    }
    assert!(before.matches(&package_state, &config));
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
    assert!(before.matches(&package_state, &config));
    assert!(!project.data_dir.path().join("history.json").exists());
    project.close_checked();
}

#[test]
fn test_install_missing_packages_fails_without_corrupting_state() {
    assert_failed_install_recovers(FailureFixture::MockMissing);
}

#[test]
fn test_aur_transport_failure_preserves_state_and_mock_install_recovers() {
    if rerun_transport_as_ordinary_user() {
        return;
    }
    if std::env::var("OMG_AUR_TRANSPORT_CHILD").as_deref() == Ok("adapter") {
        assert!(
            !omg_lib::core::is_root(),
            "AUR adapter child must have an ordinary effective UID"
        );
        eprintln!(
            "AUR adapter observed effective_uid={}",
            nix::unistd::geteuid()
        );
        assert!(
            !omg_lib::core::paths::test_mode(),
            "AUR adapter child must not use Mock dispatch"
        );
        for (variable, resolved) in [
            ("OMG_DATA_DIR", omg_lib::core::paths::data_dir()),
            ("OMG_CONFIG_DIR", omg_lib::core::paths::config_dir()),
            ("OMG_CACHE_DIR", omg_lib::core::paths::cache_dir()),
        ] {
            let expected =
                std::path::PathBuf::from(std::env::var_os(variable).expect("private adapter path"));
            assert_eq!(
                resolved, expected,
                "adapter must resolve private {variable}"
            );
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("AUR adapter runtime");
        let error = runtime
            .block_on(async {
                omg_lib::package_managers::aur::AurClient::new()
                    .expect("private AUR settings")
                    .info("fake-package-xyz")
                    .await
            })
            .expect_err("rejecting proxy must fail the actual AUR lookup");
        assert_eq!(
            error.to_string(),
            "AUR RPC transport failed. Check your internet connection."
        );
        println!("{error}");
        return;
    }
    assert_failed_install_recovers(FailureFixture::AurTransport);
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

#[test]
fn test_persistent_bytes_oracle_detects_corruption_and_disappearance() {
    let directory = tempfile::tempdir().unwrap();
    let packages = directory.path().join("packages.json");
    let config = directory.path().join("config.toml");
    std::fs::write(&packages, b"package-state").unwrap();
    std::fs::write(&config, b"config-state").unwrap();
    let before = PersistentBytes::capture(&packages, &config);
    assert!(before.matches(&packages, &config));
    std::fs::write(&packages, b"corrupt").unwrap();
    assert!(!before.matches(&packages, &config));
    std::fs::write(&packages, &before.packages).unwrap();
    std::fs::write(&config, b"corrupt").unwrap();
    assert!(!before.matches(&packages, &config));
    std::fs::remove_file(&config).unwrap();
    assert!(!before.matches(&packages, &config));
    directory.close().unwrap();
}

#[test]
fn test_proxy_policy_overrides_every_inherited_spelling_and_bypass() {
    // Each subprocess inherits a conflicting setting; its real CLI child must
    // still hit the allocated rejecting proxy and recover in the same state.
    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        let value = if key.eq_ignore_ascii_case("no_proxy") {
            "*"
        } else {
            "http://127.0.0.1:1"
        };
        let mut command = assert_cmd::Command::new(std::env::current_exe().unwrap());
        command
            .timeout(std::time::Duration::from_mins(1))
            .args([
                "--exact",
                "test_aur_transport_failure_preserves_state_and_mock_install_recovers",
                "--nocapture",
            ])
            .env(key, value);
        let assertion = command.assert().success();
        let output = String::from_utf8_lossy(&assertion.get_output().stdout);
        assert!(
            output.contains("1 passed; 0 failed; 0 ignored;"),
            "{key}: {output}"
        );
    }
}
