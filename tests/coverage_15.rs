//! cov-15: contract tests for `src/cli/doctor.rs` and `src/cli/init.rs`.
//!
//! Every test pins an observable, falsifiable contract:
//! - `omg doctor` healthy-path output set and summary branch (test mode)
//! - `--eol` / `--network` section wiring
//! - `omg init --defaults` shell-hook installation per detected `$SHELL`,
//!   daemon skip in test mode, idempotency, and omg.lock capture
//!
//! Live-network diagnostics content (per-mirror results) is deliberately NOT
//! pinned: it requires real connectivity; only the section entry + exit-code
//! contracts are asserted there.

pub mod common;

use common::*;

/// The doctor's healthy path under test mode: every check reports success,
/// the dependency list is complete, and the zero-issues summary is chosen.
#[test]
fn doctor_test_mode_healthy_path_pins_full_output() {
    let project = TestProject::new();
    let result = project.run_with_env(&["doctor"], &[("NO_COLOR", "1")]);

    assert_eq!(result.exit_code, 0, "doctor must exit 0 when healthy");
    for line in [
        "Arch Linux detected",
        "Internet connectivity",
        "Found dependency: git",
        "Found dependency: curl",
        "Found dependency: tar",
        "Found dependency: sudo",
        "Daemon is running",
        "PATH configured correctly",
        "Shell hook active",
        "System is healthy! Ready to rock.",
    ] {
        result.assert_stdout_contains(line);
    }
    // No failure markers may leak into the healthy run.
    for forbidden in ["Missing dependency", "No internet connection", "issue(s)"] {
        assert!(
            !result.stdout.contains(forbidden),
            "healthy doctor output must not contain '{forbidden}'\nstdout: {}",
            result.stdout
        );
    }
}

/// `--eol` must enter the Runtime EOL Status section and still exit 0.
/// Per-runtime verdicts depend on the host toolchain, so only the section
/// entry is pinned here.
#[test]
fn doctor_eol_flag_enters_runtime_status_section() {
    let project = TestProject::new();
    let result = project.run_with_env(&["doctor", "--eol"], &[("NO_COLOR", "1")]);

    assert_eq!(result.exit_code, 0);
    result.assert_stdout_contains("Runtime EOL Status");
}

/// `--network` must enter the Network Diagnostics section. Mirror probes
/// require real connectivity, so either verdict is acceptable — but the
/// W3-A-03 exit contract must hold: the exit code is 0 exactly when no
/// issue summary was reported.
#[test]
fn doctor_network_flag_enters_diagnostics_section_and_matches_exit_contract() {
    let project = TestProject::new();
    let result = project.run_with_env(&["doctor", "--network"], &[("NO_COLOR", "1")]);

    let reported_issues = result.stdout.contains("issue(s)");
    let expected_exit = i32::from(reported_issues);
    assert_eq!(
        result.exit_code, expected_exit,
        "doctor exit code must follow the contract (0 healthy / 1 issues)\nstdout: {}",
        result.stdout
    );
    result.assert_stdout_contains("Network Diagnostics");
}

/// W3-A-02: a supported Debian system (mocked via OMG_TEST_DISTRO) must not
/// be reported as an OS issue — doctor is backend-aware and exits 0 on a
/// healthy supported Debian environment.
#[test]
fn doctor_debian_mock_does_not_report_os_as_issue() {
    let project = TestProject::for_distro("debian");
    let result = project.run_with_env(&["doctor"], &[("NO_COLOR", "1")]);

    assert_eq!(
        result.exit_code, 0,
        "healthy mocked Debian environment must exit 0\nstdout: {}\nstderr: {}",
        result.stdout, result.stderr
    );
    result.assert_stdout_contains("Debian/Ubuntu detected");
    assert!(
        !result.stdout.contains("Non-Arch"),
        "debian must not be flagged as a non-Arch issue\nstdout: {}",
        result.stdout
    );
    assert!(result.stdout.contains("Found dependency: apt-get"));
    result.assert_stdout_contains("System is healthy! Ready to rock.");
}

/// init --defaults with SHELL=zsh installs the exact zsh hook into $HOME/.zshrc,
/// skips daemon startup in test mode, does not add the on-shell-init pgrep line,
/// and prints the config path it touched.
#[test]
fn init_defaults_installs_zsh_hook_and_skips_daemon() {
    let project = TestProject::new();
    let home = tempfile::TempDir::new().expect("home tempdir");
    let result = project.run_with_env(
        &["init", "--defaults"],
        &[
            ("NO_COLOR", "1"),
            ("HOME", home.path().to_str().expect("utf8 home")),
            ("SHELL", "/usr/bin/zsh"),
        ],
    );

    result.assert_success();
    result.assert_stdout_contains("Installing zsh hook...");
    // Test mode / OMG_DISABLE_DAEMON=1 must select the Manual daemon path.
    result.assert_stdout_contains("(skipped - run 'omg daemon' when ready)");
    result.assert_stdout_contains("Config updated: ~/.zshrc");

    let rc = std::fs::read_to_string(home.path().join(".zshrc")).expect(".zshrc written by init");
    let hook = r#"eval "$(omg hook zsh)""#;
    assert_eq!(
        rc.matches(hook).count(),
        1,
        "zsh hook must appear exactly once in .zshrc\ncontent: {rc}"
    );
    assert!(
        rc.contains("# OMG shell integration"),
        "hook block marker missing\ncontent: {rc}"
    );
    assert!(
        !rc.contains("pgrep"),
        "defaults flow must not install the daemon-on-shell-init line\ncontent: {rc}"
    );
}

/// SHELL=bash routes to ~/.bashrc with the bash-specific eval hook.
#[test]
fn init_defaults_installs_bash_hook_in_bashrc() {
    let project = TestProject::new();
    let home = tempfile::TempDir::new().expect("home tempdir");
    let result = project.run_with_env(
        &["init", "--defaults"],
        &[
            ("NO_COLOR", "1"),
            ("HOME", home.path().to_str().expect("utf8 home")),
            ("SHELL", "/bin/bash"),
        ],
    );

    result.assert_success();
    result.assert_stdout_contains("Installing bash hook...");
    result.assert_stdout_contains("Config updated: ~/.bashrc");

    let rc = std::fs::read_to_string(home.path().join(".bashrc")).expect(".bashrc written by init");
    let hook = r#"eval "$(omg hook bash)""#;
    assert_eq!(rc.matches(hook).count(), 1, "hook once\ncontent: {rc}");
}

/// SHELL=fish routes to ~/.config/fish/config.fish with the source-based
/// hook and creates the missing config directory.
#[test]
fn init_defaults_installs_fish_hook_in_fish_config() {
    let project = TestProject::new();
    let home = tempfile::TempDir::new().expect("home tempdir");
    std::fs::create_dir_all(home.path().join(".config/fish")).expect("pre-create fish dir");
    let result = project.run_with_env(
        &["init", "--defaults"],
        &[
            ("NO_COLOR", "1"),
            ("HOME", home.path().to_str().expect("utf8 home")),
            ("SHELL", "/usr/bin/fish"),
        ],
    );

    result.assert_success();
    result.assert_stdout_contains("Installing fish hook...");
    result.assert_stdout_contains("Config updated: ~/.config/fish/config.fish");

    let cfg = std::fs::read_to_string(home.path().join(".config/fish/config.fish"))
        .expect("fish config written by init");
    let hook = "omg hook fish | source";
    assert_eq!(
        cfg.matches(hook).count(),
        1,
        "fish hook once\ncontent: {cfg}"
    );
}

/// Regression: a first-run fish setup must create `~/.config/fish/` before
/// appending the hook instead of failing during `omg init --defaults`.
#[test]
fn init_fish_missing_config_dir_is_created() {
    let project = TestProject::new();
    let home = tempfile::TempDir::new().expect("home tempdir");
    // Deliberately do NOT create ~/.config/fish.
    let result = project.run_with_env(
        &["init", "--defaults"],
        &[
            ("NO_COLOR", "1"),
            ("HOME", home.path().to_str().expect("utf8 home")),
            ("SHELL", "/usr/bin/fish"),
        ],
    );

    result.assert_success();
    result.assert_stdout_contains("Installing fish hook...");
    assert!(
        home.path().join(".config/fish/config.fish").is_file(),
        "init must create the missing fish config directory and file"
    );
}

/// A second init run must detect the existing hook and not duplicate it.
#[test]
fn init_is_idempotent_second_run_reports_already_installed() {
    let project = TestProject::new();
    let home = tempfile::TempDir::new().expect("home tempdir");
    let env: &[(&str, &str)] = &[
        ("NO_COLOR", "1"),
        ("HOME", home.path().to_str().expect("utf8 home")),
        ("SHELL", "/usr/bin/zsh"),
    ];

    let first = project.run_with_env(&["init", "--defaults"], env);
    first.assert_success();

    let second = project.run_with_env(&["init", "--defaults"], env);
    second.assert_success();
    second.assert_stdout_contains("(already installed)");

    let rc = std::fs::read_to_string(home.path().join(".zshrc")).unwrap();
    assert_eq!(
        rc.matches(r#"eval "$(omg hook zsh)""#).count(),
        1,
        "second run duplicated the hook\ncontent: {rc}"
    );
}

/// init --defaults captures a fingerprint only when a package backend exists.
#[test]
fn init_defaults_respects_fingerprint_backend_availability() {
    let project = if cfg!(feature = "fedora") {
        TestProject::for_distro("fedora")
    } else {
        TestProject::new()
    };
    let home = tempfile::TempDir::new().expect("home tempdir");
    let result = project.run_with_env(
        &["init", "--defaults"],
        &[
            ("NO_COLOR", "1"),
            ("HOME", home.path().to_str().expect("utf8 home")),
            ("SHELL", "/usr/bin/zsh"),
        ],
    );

    result.assert_success();
    result.assert_stdout_contains("Capturing environment...");

    #[cfg(any(
        feature = "arch",
        feature = "debian",
        feature = "debian-pure",
        feature = "fedora"
    ))]
    {
        let lock = project.read_file("omg.lock").expect("omg.lock captured");
        assert!(
            lock.contains("schema_version"),
            "lockfile must carry schema_version\ncontent: {lock}"
        );
        assert!(
            lock.contains("hash ="),
            "lockfile must carry a state hash\ncontent: {lock}"
        );
    }
    #[cfg(not(any(
        feature = "arch",
        feature = "debian",
        feature = "debian-pure",
        feature = "fedora"
    )))]
    {
        result.assert_stdout_contains(
            "Environment fingerprinting is not available without an Arch, Debian, or Fedora package backend",
        );
        assert!(!project.file_exists("omg.lock"));
    }
}

#[test]
fn init_defaults_respects_skip_shell() {
    let project = TestProject::new();
    let home = tempfile::TempDir::new().expect("home tempdir");
    let result = project.run_with_env(
        &["init", "--defaults", "--skip-shell", "--skip-daemon"],
        &[
            ("HOME", home.path().to_str().expect("utf8 home")),
            ("SHELL", "/usr/bin/zsh"),
        ],
    );

    result.assert_success();
    result.assert_stdout_contains("Shell hook: skipped");
    assert!(
        !result.stdout.contains("Installing zsh hook"),
        "{}",
        result.stdout
    );
    assert!(
        !result.stdout.contains("Restart your shell"),
        "{}",
        result.stdout
    );
    assert!(!home.path().join(".zshrc").exists());
}

#[test]
fn redirected_init_defaults_emits_no_ansi() {
    let project = TestProject::new();
    let home = tempfile::TempDir::new().expect("home tempdir");
    let result = project.run_with_env(
        &["init", "--defaults", "--skip-shell", "--skip-daemon"],
        &[
            ("HOME", home.path().to_str().expect("utf8 home")),
            ("SHELL", "/usr/bin/zsh"),
        ],
    );

    result.assert_success();
    assert!(!result.combined_output().contains("\u{1b}["));
}

/// Bare `omg init` under a non-TTY (piped by the harness) must announce the
/// fallback AND actually run the defaults setup — proving it is a real
/// fallback, not just a printed message.
#[test]
fn init_non_interactive_falls_back_to_defaults_setup() {
    let project = TestProject::new();
    let home = tempfile::TempDir::new().expect("home tempdir");
    let result = project.run_with_env(
        &["init"],
        &[
            ("NO_COLOR", "1"),
            ("HOME", home.path().to_str().expect("utf8 home")),
            ("SHELL", "/usr/bin/zsh"),
        ],
    );

    result.assert_success();
    result.assert_stdout_contains("Non-interactive terminal detected, running with defaults...");
    // Proof the defaults flow actually executed:
    result.assert_stdout_contains("Installing zsh hook...");
    let rc = std::fs::read_to_string(home.path().join(".zshrc"))
        .expect("fallback must still install the shell hook");
    assert!(rc.contains(r#"eval "$(omg hook zsh)""#), "content: {rc}");
}
