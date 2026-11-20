//! Coverage tests #9 — src/cli/runtimes.rs + src/runtimes/mod.rs
//!
//! Contracts under test (each assertion pins observable CLI behavior):
//! - `which`: version-file resolution (project dir, parent walk, case), the
//!   explicit "no version set" notice when no pin exists
//! - `use`: failure when neither explicit version nor pin file is available;
//!   rejection of reserved (`current`) and filesystem-unsafe versions
//! - `list --json`: structured entries for native runtimes (exact payload),
//!   explicit failure naming unsupported runtimes, `--available` conflict
//! - unknown runtimes fail explicitly without installing a fallback manager
//! - dynamic completion covers native runtimes and the bundled tool registry
//!
//! All tests are offline: PATH is cleared (the omg binary itself is spawned
//! by absolute path), and every assertion avoids code paths that download.

#![expect(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]

pub mod common;

use common::*;

const NO_MISE_ENV: &[(&str, &str)] = &[("PATH", "")];

// Pin the public catalog independently of the implementation so additions or
// removals require an explicit update to the CLI contract.
const EXPECTED_RUNTIMES: &[&str] = &[
    "actionlint",
    "bat",
    "bun",
    "consul",
    "delta",
    "delve",
    "deno",
    "dive",
    "dotnet",
    "duf",
    "dust",
    "elixir",
    "erlang",
    "eza",
    "fd",
    "fnm",
    "fzf",
    "gh",
    "ghcup",
    "glow",
    "go",
    "golangci-lint",
    "hadolint",
    "helix",
    "helm",
    "hyperfine",
    "java",
    "jq",
    "just",
    "k9s",
    "kind",
    "kotlin",
    "kustomize",
    "lazydocker",
    "lazygit",
    "minikube",
    "neovim",
    "node",
    "opentofu",
    "packer",
    "pandoc",
    "php",
    "pi",
    "procs",
    "protoc",
    "python",
    "ripgrep",
    "ruby",
    "ruff",
    "rust",
    "scala",
    "shellcheck",
    "shfmt",
    "skaffold",
    "starship",
    "stylua",
    "swift",
    "task",
    "terraform",
    "terragrunt",
    "tilt",
    "tokei",
    "uv",
    "vault",
    "yq",
    "zellij",
    "zig",
    "zoxide",
];

fn data_dir_str(project: &TestProject) -> String {
    project.data_dir.path().display().to_string()
}

fn config_dir_str(project: &TestProject) -> String {
    project.config_dir.path().display().to_string()
}

fn pacman_root_str(project: &TestProject) -> String {
    project.pacman_root.path().display().to_string()
}

/// Run omg inside an arbitrary directory (e.g. a nested project subdir)
/// while keeping the project's isolated data/config directories.
fn run_in_dir(
    project: &TestProject,
    dir: &std::path::Path,
    args: &[&str],
    extra_env: &[(&str, &str)],
) -> CommandResult {
    let mut vars: Vec<(String, String)> = vec![
        ("OMG_DATA_DIR".into(), data_dir_str(project)),
        ("OMG_CONFIG_DIR".into(), config_dir_str(project)),
        (
            "OMG_CACHE_DIR".into(),
            project.data_dir.path().join("cache").display().to_string(),
        ),
        ("OMG_PACMAN_ROOT".into(), pacman_root_str(project)),
        ("OMG_TEST_DISTRO".into(), "arch".to_string()),
    ];
    vars.push(("PATH".into(), String::new()));
    let refs: Vec<(&str, &str)> = vars
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .chain(extra_env.iter().copied())
        .collect();
    run_omg_with_options(args, Some(dir), &refs)
}

// ═══════════════════════════════════════════════════════════════════════════════
// WHICH — version-file resolution (src/cli/runtimes.rs resolve_active_version)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn which_reports_pin_from_nvmrc_in_project_directory() {
    let project = TestProject::new();
    project.create_file(".nvmrc", "20.10.0");

    let result = project.run_with_env(&["which", "node"], NO_MISE_ENV);
    result.assert_success();

    // Contract: the .nvmrc pin is reported verbatim, NOT the "no version
    // set" notice. Both halves matter — dropping either lets a broken
    // resolver (always-None, or always-the-notice) slip through.
    result.assert_stdout_contains("20.10.0");
    assert!(
        !result.stdout.contains("no version set"),
        "`omg which node` with a .nvmrc pin must report the version, got:\n{}",
        result.stdout
    );
}

#[test]
fn which_resolves_pin_from_parent_directory() {
    let project = TestProject::new();
    project.create_file(".ruby-version", "3.2.1");
    let nested = project.create_dir("apps/web");

    // Contract: detection walks up from cwd, so a pin in the repo root is
    // visible from a nested working directory (hooks::detect_versions).
    let result = run_in_dir(&project, &nested, &["which", "ruby"], &[]);
    result.assert_success();
    result.assert_stdout_contains("3.2.1");
    assert!(
        !result.stdout.contains("no version set"),
        "parent-directory pin must be found from nested cwd:\n{}",
        result.stdout
    );
}

#[test]
#[cfg(unix)]
fn which_reports_global_selection_but_prefers_project_pins() {
    let project = TestProject::new();
    let versions = project.data_dir.path().join("versions/python");
    std::fs::create_dir_all(versions.join("3.12.14")).unwrap();
    std::os::unix::fs::symlink("3.12.14", versions.join("current")).unwrap();
    for args in [
        vec!["which", "python"],
        vec!["--verbose", "which", "PYTHON3"],
    ] {
        let result = project.run_with_env(&args, NO_MISE_ENV);
        result.assert_success();
        result.assert_stdout_contains("3.12.14");
        assert!(!result.stdout.contains("no version set"));
    }
    project.create_file(".python-version", "3.11.16");
    let result = project.run_with_env(&["which", "python"], NO_MISE_ENV);
    result.assert_success();
    result.assert_stdout_contains("3.11.16");
    assert!(!result.stdout.contains("3.12.14"));
}

#[test]
#[cfg(unix)]
fn which_rejects_external_global_symlink_targets() {
    let project = TestProject::new();
    let versions = project.data_dir.path().join("versions/python");
    std::fs::create_dir_all(versions.join("3.12.14")).unwrap();
    let external = project.create_dir("3.12.14");
    std::os::unix::fs::symlink(external, versions.join("current")).unwrap();
    let result = project.run_with_env(&["which", "python"], NO_MISE_ENV);
    result.assert_failure();
    assert!(result.stdout.is_empty());
    result.assert_stderr_contains("python: no version set");
}

#[test]
fn which_reports_an_unset_version_on_stderr_and_fails() {
    let project = TestProject::new();

    for args in [
        vec!["which", "python"],
        vec!["--verbose", "which", "python"],
    ] {
        let result = project.run_with_env(&args, NO_MISE_ENV);
        result.assert_failure();
        assert!(result.stdout.is_empty());
        result.assert_stderr_contains("python: no version set");
        result.assert_stderr_contains(".tool-versions");
    }
}

#[test]
fn which_is_case_insensitive_for_runtime_name() {
    let project = TestProject::new();
    project.create_file(".nvmrc", "20.10.0");

    // Contract: resolve_active_version lowercases the lookup key, so
    // "NODE" resolves the same pin stored under "node".
    let result = project.run_with_env(&["which", "NODE"], NO_MISE_ENV);
    result.assert_success();
    result.assert_stdout_contains("20.10.0");
    assert!(
        !result.stdout.contains("no version set"),
        "case-insensitive lookup must find the node pin:\n{}",
        result.stdout
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// USE — argument validation before any install work (offline paths only)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn use_fails_without_pin_or_explicit_version() {
    let project = TestProject::new(); // no version files anywhere below cwd

    let result = project.run_with_env(&["use", "go"], NO_MISE_ENV);

    // Contract (use_version detection arm): fail closed and name both the
    // problem and where pins may live. Must never fall through to an
    // install with an empty/implicit version.
    result.assert_failure();
    result.assert_stderr_contains("No version specified and none detected");
    result.assert_stderr_contains(".tool-versions");
}

#[test]
fn use_rejects_reserved_current_version() {
    let project = TestProject::new();

    let result = project.run_with_env(&["use", "node", "current"], NO_MISE_ENV);

    // Contract: validate_runtime_version reserves "current" for the
    // active-version symlink and says so before any manager dispatch.
    result.assert_failure();
    result.assert_stderr_contains("'current' is reserved");
}

#[test]
fn use_rejects_unsafe_runtime_version_characters() {
    let project = TestProject::new();

    // ':' is legal for package epochs but unsafe as a runtime directory name.
    let result = project.run_with_env(&["use", "rust", "1.5.0:epoch"], NO_MISE_ENV);

    result.assert_failure();
    result.assert_stderr_contains("unsafe for filesystem paths");
}

// ═══════════════════════════════════════════════════════════════════════════════
// LIST --json — structured output contract (list_installed_json /
// runtime_versions_value in src/cli/runtimes.rs)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn list_json_native_runtime_emits_exact_structured_entry() {
    let project = TestProject::new();
    // Seed OMG's own bun store: <data>/versions/bun/<version> plus the
    // `current` symlink, so both fields have real values to pin.
    let bun_dir = project.data_dir.path().join("versions/bun/9.9.9");
    std::fs::create_dir_all(&bun_dir).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        &bun_dir,
        project.data_dir.path().join("versions/bun/current"),
    )
    .unwrap();

    let result = project.run_with_env(&["list", "bun", "--json"], NO_MISE_ENV);
    result.assert_success();

    let actual: serde_json::Value =
        serde_json::from_str(&result.stdout).expect("list --json must emit valid JSON only");
    assert_eq!(
        actual,
        serde_json::json!({
            "runtime": "bun",
            "current": "9.9.9",
            "installed": ["9.9.9"],
        }),
        "listing must contain exactly the seeded runtime entry"
    );
}

#[test]
fn list_json_all_runtimes_emits_catalog_entries_with_required_fields() {
    let project = TestProject::new();

    let result = project.run_with_env(&["list", "--json"], NO_MISE_ENV);
    result.assert_success();

    let actual: serde_json::Value =
        serde_json::from_str(&result.stdout).expect("list --json must emit valid JSON only");
    let expected: Vec<serde_json::Value> = EXPECTED_RUNTIMES
        .iter()
        .map(|runtime| {
            serde_json::json!({
                "runtime": runtime,
                "current": null,
                "installed": [],
            })
        })
        .collect();
    assert_eq!(
        actual,
        serde_json::Value::Array(expected),
        "empty store must list exactly one empty entry per native runtime"
    );
}

#[test]
fn list_json_unsupported_runtime_fails_explicitly() {
    let project = TestProject::new();

    let result = project.run_with_env(
        &["list", "omg-test-unsupported-runtime", "--json"],
        NO_MISE_ENV,
    );

    // Unsupported runtimes fail rather than emitting partial or empty data.
    result.assert_failure();
    result.assert_stderr_contains("Unsupported runtime 'omg-test-unsupported-runtime'");
}

#[test]
fn list_json_conflicts_with_available_flag() {
    let project = TestProject::new();

    let result = project.run_with_env(&["list", "node", "--available", "--json"], NO_MISE_ENV);

    result.assert_failure();
    result.assert_stderr_contains("--json is not supported together with --available");
}

// ═══════════════════════════════════════════════════════════════════════════════
// UNSUPPORTED RUNTIMES — fail explicitly without installing a fallback.
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn list_unknown_runtime_fails_explicitly() {
    let project = TestProject::new();

    let result = project.run_with_env(&["list", "omg-test-unsupported-runtime"], NO_MISE_ENV);

    result.assert_failure();
    result.assert_stderr_contains("Unsupported runtime 'omg-test-unsupported-runtime'");
}

#[test]
fn complete_lists_all_supported_native_runtimes() {
    let project = TestProject::new();

    // Dynamic completion offers every supported runtime, sorted and deduplicated.
    let result = project.run_with_env(
        &[
            "complete",
            "--shell",
            "zsh",
            "--current",
            "",
            "--last",
            "use",
        ],
        NO_MISE_ENV,
    );
    result.assert_success();

    let suggestions: Vec<&str> = result.stdout.lines().map(str::trim).collect();
    assert_eq!(
        suggestions, EXPECTED_RUNTIMES,
        "completion after `use` must offer exactly the sorted supported runtimes:\n{}",
        result.stdout
    );
}
