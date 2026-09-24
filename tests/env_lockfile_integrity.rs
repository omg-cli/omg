//! Lockfile integrity pins (`omg.lock`).
//!
//! Wave-2 addition: the hardened integrity check in
//! `omg_lib::core::env::fingerprint::EnvironmentState::load` (stored-hash vs
//! recomputed-content comparison) previously had no `tests/**` coverage — the
//! only related CLI test accepted any failure text, so a silent regression to
//! unparsed-trust semantics would have gone unnoticed.
//!
//! These tests pin, at both the library seam and through the real binary,
//! that a well-formed but tampered lockfile fails *its integrity check*, not
//! merely "some error".

#![expect(clippy::unwrap_used)]

pub mod common;

use common::TestProject;
use omg_lib::core::env::fingerprint::EnvironmentState;
use std::collections::BTreeMap;

fn sample_state() -> EnvironmentState {
    let mut state = EnvironmentState {
        schema_version: omg_lib::core::env::fingerprint::EnvironmentState::SCHEMA_VERSION,
        runtimes: BTreeMap::new(),
        packages: vec!["curl".to_string(), "git".to_string()],
        timestamp: 1_700_000_000,
        hash: String::new(),
    };
    state.hash = state.calculate_hash();
    state
}

#[test]
fn save_then_load_round_trips_and_recomputes_the_hash() -> anyhow::Result<()> {
    let dir = tempfile::TempDir::new()?;
    let path = dir.path().join("omg.lock");

    let state = sample_state();
    // `save` normalizes and re-computes the stored hash from contents.
    state.save(&path)?;

    let loaded = EnvironmentState::load(&path)?;
    assert_eq!(loaded, state, "round trip must preserve the captured state");
    assert_eq!(loaded.hash, loaded.calculate_hash());
    Ok(())
}

#[test]
fn load_rejects_a_tampered_lockfile_with_an_integrity_error() -> anyhow::Result<()> {
    let dir = tempfile::TempDir::new()?;
    let path = dir.path().join("omg.lock");

    // Persist a valid, self-consistent lockfile first.
    let contents = {
        let state = sample_state();
        toml::to_string_pretty(&state)?
    };
    std::fs::write(&path, &contents)?;

    // Inject an extra package through the TOML value model so the on-disk
    // file is valid TOML with a valid schema but contents that contradict
    // the stored hash — exactly what an attacker editing the lockfile by
    // hand produces.
    let mut value: toml::Value = toml::from_str(&contents)?;
    value["packages"]
        .as_array_mut()
        .expect("packages is an array")
        .push(toml::Value::String("injected-pkg".to_string()));
    std::fs::write(&path, toml::to_string_pretty(&value)?)?;

    let error =
        EnvironmentState::load(&path).expect_err("tampered lockfile must fail its integrity check");
    assert!(
        error.to_string().contains("integrity check failed"),
        "expected integrity failure, got: {error}"
    );
    Ok(())
}

#[test]
fn load_rejects_malformed_toml_instead_of_panicking() -> anyhow::Result<()> {
    let dir = tempfile::TempDir::new()?;
    let path = dir.path().join("omg.lock");
    std::fs::write(&path, "this is not valid toml {{{{")?;

    let result = EnvironmentState::load(&path);
    assert!(result.is_err(), "malformed TOML must be rejected");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Failed to parse lockfile"),
        "parse failures must carry context"
    );
    Ok(())
}

#[test]
fn load_reports_a_missing_lockfile_as_an_inspection_failure() -> anyhow::Result<()> {
    let dir = tempfile::TempDir::new()?;
    let path = dir.path().join("does-not-exist.lock");

    let error =
        EnvironmentState::load(&path).expect_err("missing lockfile must be an explicit error");
    assert!(error.to_string().contains("Failed to inspect lockfile"));
    Ok(())
}

/// Integration pin through the real binary: `omg env check` must reject a
/// tampered lockfile via the integrity path, not silently treat attacker
/// edits as drift to report.
#[test]
fn env_check_fails_on_tampered_lockfile_integrity() {
    let project = TestProject::new();

    // Write a valid-schema lockfile whose contents contradict its stored hash.
    let mut state = EnvironmentState {
        schema_version: omg_lib::core::env::fingerprint::EnvironmentState::SCHEMA_VERSION,
        runtimes: BTreeMap::new(),
        packages: vec![],
        timestamp: 0,
        hash: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
    };
    state.packages.push("tampered-pkg".to_string());
    let contents = toml::to_string_pretty(&state).expect("tampered fixture must serialize");
    project.create_file("omg.lock", &contents);

    let result = project.run(&["env", "check"]);
    let combined = result.combined_output();
    assert!(
        !result.success,
        "`env check` must fail on a tampered lockfile, got:\n{combined}"
    );
    assert!(
        combined.contains("integrity check failed"),
        "`env check` must surface the integrity failure specifically, got:\n{combined}"
    );
}

#[test]
fn env_export_preserves_lock_and_maps_only_the_declared_source_target() {
    let project = TestProject::new();
    let mut state = sample_state();
    state
        .runtimes
        .insert("node".to_string(), "22.1.0".to_string());
    state.save(project.path().join("omg.lock")).unwrap();
    let lock_before = std::fs::read(project.path().join("omg.lock")).unwrap();

    let export = project.run(&["env", "export", "--source-target", "arch-x86_64"]);
    export.assert_success();
    export.assert_no_ansi();
    assert!(
        export.stderr.is_empty(),
        "unexpected export diagnostic: {}",
        export.stderr
    );
    let manifest: toml::Value = toml::from_str(&export.stdout).unwrap();
    let environment = &manifest["environment"];
    assert_eq!(environment["schema_version"].as_integer(), Some(1));
    assert_eq!(
        environment["tools"].as_array().unwrap(),
        &[
            toml::Value::String("curl".into()),
            toml::Value::String("git".into())
        ]
    );
    assert_eq!(environment["runtimes"]["node"].as_str(), Some("22.1.0"));
    assert_eq!(
        environment["packages"]["arch-x86_64"]["curl"].as_str(),
        Some("curl")
    );
    assert_eq!(
        environment["packages"]["arch-x86_64"]["git"].as_str(),
        Some("git")
    );
    assert_eq!(environment["packages"].as_table().unwrap().len(), 1);
    assert!(environment["dotfiles"].as_table().unwrap().is_empty());
    assert!(export.stdout.contains("package versions are not captured"));

    let invalid = project.run(&["env", "export", "--source-target", "unknown-x86_64"]);
    invalid.assert_failure();
    assert!(
        invalid
            .combined_output()
            .contains("invalid value 'unknown-x86_64' for '--source-target <SOURCE_TARGET>'")
    );
    assert_eq!(
        std::fs::read(project.path().join("omg.lock")).unwrap(),
        lock_before,
        "successful export or invalid-target refusal changed the lockfile"
    );
    #[cfg(unix)]
    {
        let external = tempfile::TempDir::new().unwrap();
        let sentinel = external.path().join("omg.lock");
        std::fs::write(&sentinel, &lock_before).unwrap();
        std::fs::remove_file(project.path().join("omg.lock")).unwrap();
        std::os::unix::fs::symlink(&sentinel, project.path().join("omg.lock")).unwrap();
        let linked = project.run(&["env", "export", "--source-target", "arch-x86_64"]);
        linked.assert_failure();
        assert!(linked.combined_output().contains("not a regular file"));
        assert_eq!(std::fs::read(&sentinel).unwrap(), lock_before);
        std::fs::remove_file(project.path().join("omg.lock")).unwrap();
        std::fs::write(project.path().join("omg.lock"), &lock_before).unwrap();
        external.close().unwrap();
    }
    assert_eq!(
        std::fs::read(project.path().join("omg.lock")).unwrap(),
        lock_before
    );
    assert_eq!(std::fs::read_dir(project.path()).unwrap().count(), 1);
    project.close_checked();
}

#[test]
fn env_plan_reports_exact_target_intent_without_writing_or_applying_it() {
    let project = TestProject::new();
    let manifest = r#"[environment]
schema_version = 1
tools = ["curl", "git"]

[environment.runtimes]
node = "22.1.0"

[environment.packages.arch-x86_64]
curl = "curl"

[environment.packages.ubuntu-x86_64]
git = "git"

[environment.dotfiles]
".config/example" = ".config/example"
"#;
    project.create_file(".omg.toml", manifest);
    project.create_file("omg.lock", "existing-lock-sentinel");

    let plan = project.run(&["env", "plan", "--target", "ubuntu-x86_64"]);
    plan.assert_success();
    plan.assert_no_ansi();
    assert!(
        plan.stderr.is_empty(),
        "unexpected plan diagnostic: {}",
        plan.stderr
    );
    let output: serde_json::Value = serde_json::from_str(&plan.stdout).unwrap();
    assert_eq!(output["schema_version"], 1);
    assert_eq!(output["target"], "ubuntu-x86_64");
    assert_eq!(output["packages"], serde_json::json!({"git": "git"}));
    assert_eq!(output["unmapped_tools"], serde_json::json!(["curl"]));
    assert_eq!(output["runtimes"], serde_json::json!({"node": "22.1.0"}));
    assert_eq!(
        output["dotfiles"],
        serde_json::json!({".config/example": ".config/example"})
    );
    assert!(output["notices"].as_array().unwrap().iter().any(|notice| {
        notice
            .as_str()
            .unwrap()
            .contains("no packages installed and no files copied")
    }));
    let other_target = project.run(&["env", "plan", "--target", "arch-x86_64"]);
    other_target.assert_success();
    let other_output: serde_json::Value = serde_json::from_str(&other_target.stdout).unwrap();
    assert_eq!(other_output["target"], "arch-x86_64");
    assert_eq!(
        other_output["packages"],
        serde_json::json!({"curl": "curl"})
    );
    assert_eq!(other_output["unmapped_tools"], serde_json::json!(["git"]));
    assert_eq!(
        std::fs::read_to_string(project.path().join(".omg.toml")).unwrap(),
        manifest
    );
    assert_eq!(
        std::fs::read_to_string(project.path().join("omg.lock")).unwrap(),
        "existing-lock-sentinel"
    );
    assert_eq!(std::fs::read_dir(project.path()).unwrap().count(), 2);

    let invalid = project.run(&["env", "plan", "--target", "unknown-x86_64"]);
    invalid.assert_failure();
    assert!(
        invalid
            .combined_output()
            .contains("invalid value 'unknown-x86_64' for '--target <TARGET>'")
    );
    let traversal = manifest.replace(
        "\".config/example\" = \".config/example\"",
        "\".config/example\" = \"../escape\"",
    );
    project.create_file(".omg.toml", &traversal);
    let invalid = project.run(&["env", "plan", "--target", "ubuntu-x86_64"]);
    invalid.assert_failure();
    assert!(
        invalid
            .combined_output()
            .contains("Dotfile destination must be relative")
    );
    #[cfg(unix)]
    {
        let external = tempfile::TempDir::new().unwrap();
        let sentinel = external.path().join("manifest.toml");
        std::fs::write(&sentinel, manifest).unwrap();
        std::fs::remove_file(project.path().join(".omg.toml")).unwrap();
        std::os::unix::fs::symlink(&sentinel, project.path().join(".omg.toml")).unwrap();
        let linked = project.run(&["env", "plan", "--target", "ubuntu-x86_64"]);
        linked.assert_failure();
        assert!(linked.combined_output().contains("not a regular file"));
        assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), manifest);
        std::fs::remove_file(project.path().join(".omg.toml")).unwrap();
        std::fs::write(project.path().join(".omg.toml"), manifest).unwrap();
        external.close().unwrap();
    }
    assert_eq!(
        std::fs::read_to_string(project.path().join("omg.lock")).unwrap(),
        "existing-lock-sentinel"
    );
    assert_eq!(std::fs::read_dir(project.path()).unwrap().count(), 2);
    project.close_checked();
}

#[test]
#[cfg(all(
    unix,
    any(feature = "arch", feature = "debian", feature = "debian-pure")
))]
fn capture_records_every_registered_runtime_and_check_detects_its_drift() {
    let project = TestProject::new();
    let names = omg_lib::cli::runtimes::known_runtimes().unwrap();
    assert_eq!(
        names.len(),
        68,
        "Review capture fixtures when the runtime registry changes"
    );
    let expected: BTreeMap<_, _> = names
        .iter()
        .map(|name| (name.clone(), "1.2.3".to_owned()))
        .collect();
    for runtime in names
        .iter()
        .map(String::as_str)
        .chain(["unregistered-fixture"])
    {
        let versions = project.data_dir.path().join("versions").join(runtime);
        std::fs::create_dir_all(versions.join("1.2.3")).unwrap();
        std::os::unix::fs::symlink(versions.join("1.2.3"), versions.join("current")).unwrap();
    }
    project.mock_install("git", "2.0.0").unwrap();
    project.mock_install("curl", "8.0.0").unwrap();
    project
        .run(&["init", "--defaults", "--skip-shell", "--skip-daemon"])
        .assert_success();
    assert_eq!(
        EnvironmentState::load(project.path().join("omg.lock"))
            .unwrap()
            .runtimes,
        expected,
        "initial setup must capture the complete registry"
    );
    project.run(&["env", "capture"]).assert_success();
    let path = project.path().join("omg.lock");
    let captured = EnvironmentState::load(&path).unwrap();
    assert_eq!(
        captured.runtimes, expected,
        "capture omitted or invented a managed runtime"
    );
    assert_eq!(captured.packages, ["curl", "git"]);
    let before = std::fs::read(&path).unwrap();
    project.run(&["env", "check"]).assert_success();
    project.run(&["ci", "validate"]).assert_success();
    project.run(&["migrate", "export"]).assert_success();
    let manifest_path = project.path().join("omg-manifest.json");
    let manifest_bytes = std::fs::read(&manifest_path).unwrap();
    let manifest: omg_lib::cli::migrate::MigrationManifest =
        serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(manifest.runtimes, expected);
    let import = project.run(&["migrate", "import", "omg-manifest.json", "--dry-run"]);
    import.assert_success();
    for runtime in &names {
        assert!(
            import
                .combined_output()
                .contains(&format!("{runtime} @ 1.2.3"))
        );
    }
    project.run(&["snapshot", "create"]).assert_success();
    let snapshots = project.data_dir.path().join("snapshots");
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(snapshots.join("index.json")).unwrap()).unwrap();
    let id = index["snapshots"][0]["id"].as_str().unwrap();
    let snapshot_path = snapshots.join(format!("{id}.json"));
    let snapshot_bytes = std::fs::read(&snapshot_path).unwrap();
    let snapshot: omg_lib::cli::snapshot::Snapshot =
        serde_json::from_slice(&snapshot_bytes).unwrap();
    assert_eq!(snapshot.state.runtimes, expected);
    assert_eq!(snapshot.state.hash, captured.hash);
    assert_eq!(std::fs::read(&path).unwrap(), before);

    for runtime in &names {
        let versions = project.data_dir.path().join("versions").join(runtime);
        std::fs::create_dir(versions.join("2.3.4")).unwrap();
        std::fs::remove_file(versions.join("current")).unwrap();
        std::os::unix::fs::symlink(versions.join("2.3.4"), versions.join("current")).unwrap();
        let drift = project.run(&["env", "check"]);
        drift.assert_failure();
        let output = drift.combined_output();
        assert!(
            output.contains("Environment drift detected")
                && output.contains(runtime)
                && output.contains("1.2.3")
                && output.contains("2.3.4"),
            "{runtime}: {output}"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "checking drift must not rewrite the lockfile"
        );
    }
    let validation = project.run(&["ci", "validate"]);
    validation.assert_failure();
    assert!(
        validation
            .combined_output()
            .contains("Environment drift detected")
    );
    let diff = project.run(&["diff", "omg.lock"]);
    diff.assert_success();
    let restore = project.run(&["snapshot", "restore", id, "--dry-run"]);
    restore.assert_success();
    for runtime in &names {
        assert!(diff.combined_output().contains(runtime));
        assert!(
            restore
                .combined_output()
                .contains(&format!("{runtime} 2.3.4 → 1.2.3"))
        );
        let versions = project.data_dir.path().join("versions").join(runtime);
        assert_eq!(
            std::fs::read_link(versions.join("current")).unwrap(),
            versions.join("2.3.4")
        );
    }
    assert_eq!(std::fs::read(&snapshot_path).unwrap(), snapshot_bytes);
    assert_eq!(std::fs::read(&manifest_path).unwrap(), manifest_bytes);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    project.run(&["env", "capture"]).assert_success();
    let recaptured = EnvironmentState::load(&path).unwrap();
    let changed: BTreeMap<_, _> = names
        .into_iter()
        .map(|runtime| (runtime, "2.3.4".to_owned()))
        .collect();
    assert_eq!(recaptured.runtimes, changed);
    assert_ne!(recaptured.hash, captured.hash);
    project.run(&["env", "check"]).assert_success();
    project.close_checked();
}

#[test]
#[cfg(all(
    target_os = "linux",
    any(feature = "arch", feature = "debian", feature = "debian-pure")
))]
fn snapshot_restores_installed_php_offline_without_replacing_its_payload() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let project = TestProject::new();
    let versions = project.data_dir.path().join("versions/php");
    for version in ["8.3", "8.4"] {
        let binary = versions.join(version).join("bin/php");
        std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
        std::fs::write(
            &binary,
            format!("#!/bin/sh\nprintf '%s\\n' 'fixture-php-{version}'\n"),
        )
        .unwrap();
        std::fs::set_permissions(binary, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    symlink(versions.join("8.4"), versions.join("current")).unwrap();
    project.run(&["env", "capture"]).assert_success();
    project.run(&["snapshot", "create"]).assert_success();
    let snapshots = project.data_dir.path().join("snapshots");
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(snapshots.join("index.json")).unwrap()).unwrap();
    let id = index["snapshots"][0]["id"].as_str().unwrap();
    std::fs::remove_file(versions.join("current")).unwrap();
    symlink(versions.join("8.3"), versions.join("current")).unwrap();
    let bytes = std::fs::read(versions.join("8.4/bin/php")).unwrap();
    let restore = project.run_with_env(
        &["snapshot", "restore", id],
        &[
            ("HTTPS_PROXY", "http://127.0.0.1:9"),
            ("HTTP_PROXY", "http://127.0.0.1:9"),
            ("ALL_PROXY", "http://127.0.0.1:9"),
            ("NO_PROXY", ""),
            ("OMG_TEST_COMMAND_TIMEOUT_SECS", "10"),
        ],
    );
    restore.assert_success();
    assert_eq!(
        std::fs::canonicalize(versions.join("current")).unwrap(),
        versions.join("8.4")
    );
    assert_eq!(std::fs::read(versions.join("8.4/bin/php")).unwrap(), bytes);
    let execution = std::process::Command::new(versions.join("current/bin/php"))
        .output()
        .unwrap();
    assert!(execution.status.success());
    assert_eq!(execution.stdout, b"fixture-php-8.4\n");
    project.run(&["env", "check"]).assert_success();
    project.run(&["ci", "validate"]).assert_success();
    std::fs::remove_file(versions.join("current")).unwrap();
    symlink(versions.join("8.3"), versions.join("current")).unwrap();
    std::fs::remove_file(versions.join("8.4/bin/php")).unwrap();
    let broken = project.run(&["snapshot", "restore", id]);
    broken.assert_failure();
    assert!(
        broken
            .combined_output()
            .contains("Failed to inspect runtime binary:")
    );
    assert!(broken.combined_output().contains("8.4/bin/php"));
    assert!(
        !broken
            .combined_output()
            .contains("Snapshot restore complete!")
    );
    assert_eq!(
        std::fs::read_link(versions.join("current")).unwrap(),
        versions.join("8.3")
    );
    project.close_checked();
}

#[test]
#[cfg(not(any(feature = "arch", feature = "debian", feature = "debian-pure")))]
fn capture_without_package_backend_refuses_without_creating_or_overwriting_lockfile() {
    let project = TestProject::new();
    let path = project.path().join("omg.lock");
    let absent = project.run(&["env", "capture"]);
    absent.assert_failure();
    assert!(absent.combined_output().contains(
        "Environment fingerprinting is not available without an Arch or Debian package backend"
    ));
    assert!(
        std::fs::symlink_metadata(&path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    );
    sample_state().save(&path).unwrap();
    let before = std::fs::read(&path).unwrap();
    let existing = project.run(&["env", "capture"]);
    existing.assert_failure();
    assert!(existing.combined_output().contains(
        "Environment fingerprinting is not available without an Arch or Debian package backend"
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    project.close_checked();
}

/// Installed-selection coverage only: executable fixtures are not vendor downloads.
#[test]
#[cfg(all(
    target_os = "linux",
    any(feature = "arch", feature = "debian", feature = "debian-pure")
))]
fn snapshot_restores_all_registered_installed_runtimes_and_executes_selected_payloads() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let project = TestProject::new();
    let names = omg_lib::cli::runtimes::known_runtimes().unwrap();
    assert_eq!(
        names.len(),
        68,
        "Review installed restore fixtures for registry changes"
    );
    let mut fixtures = Vec::new();
    for name in &names {
        let (target, changed) = match name.as_str() {
            "rust" => (
                format!("1.93.1-{}-unknown-linux-gnu", std::env::consts::ARCH),
                format!("1.94.0-{}-unknown-linux-gnu", std::env::consts::ARCH),
            ),
            "java" => ("21".to_owned(), "17".to_owned()),
            "php" => ("8.4".to_owned(), "8.3".to_owned()),
            _ => ("1.2.3".to_owned(), "2.3.4".to_owned()),
        };
        let binary = match name.as_str() {
            "bun" => "bun".to_owned(),
            "dotnet" => "dotnet".to_owned(),
            "swift" => "usr/bin/swift".to_owned(),
            "python" => "bin/python3".to_owned(),
            "rust" => "bin/rustc".to_owned(),
            "erlang" => "bin/erl".to_owned(),
            "ripgrep" => "bin/rg".to_owned(),
            "neovim" => "bin/nvim".to_owned(),
            "helix" => "bin/hx".to_owned(),
            "opentofu" => "bin/tofu".to_owned(),
            "delve" => "bin/dlv".to_owned(),
            "kotlin" => "bin/kotlinc".to_owned(),
            _ => format!("bin/{name}"),
        };
        let versions = project.data_dir.path().join("versions").join(name);
        for version in [&target, &changed] {
            let path = versions.join(version).join(&binary);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(
                &path,
                format!("#!/bin/sh\nprintf '%s\\n' 'fixture-{name}-{version}'\n"),
            )
            .unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
            if name == "pi" {
                let manifest = versions
                    .join(version)
                    .join("lib/node_modules/@earendil-works/pi-coding-agent/package.json");
                std::fs::create_dir_all(manifest.parent().unwrap()).unwrap();
                std::fs::write(manifest, format!("{{\"version\":\"{version}\"}}")).unwrap();
            }
        }
        symlink(versions.join(&target), versions.join("current")).unwrap();
        fixtures.push((name, target, changed, binary));
    }
    project.run(&["env", "capture"]).assert_success();
    project.run(&["snapshot", "create"]).assert_success();
    let snapshots = project.data_dir.path().join("snapshots");
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(snapshots.join("index.json")).unwrap()).unwrap();
    let id = index["snapshots"][0]["id"].as_str().unwrap();
    for (name, _, changed, _) in &fixtures {
        let versions = project.data_dir.path().join("versions").join(name);
        std::fs::remove_file(versions.join("current")).unwrap();
        symlink(versions.join(changed), versions.join("current")).unwrap();
    }
    let restore = project.run_with_env(
        &["snapshot", "restore", id],
        &[
            ("HTTPS_PROXY", "http://127.0.0.1:9"),
            ("HTTP_PROXY", "http://127.0.0.1:9"),
            ("ALL_PROXY", "http://127.0.0.1:9"),
            ("NO_PROXY", ""),
            ("OMG_TEST_COMMAND_TIMEOUT_SECS", "10"),
        ],
    );
    restore.assert_success();
    for (name, target, changed, binary) in &fixtures {
        let versions = project.data_dir.path().join("versions").join(name);
        assert_eq!(
            std::fs::canonicalize(versions.join("current")).unwrap(),
            versions.join(target),
            "{name}"
        );
        for (directory, version) in [("current", target), (changed.as_str(), changed)] {
            let execution = std::process::Command::new(versions.join(directory).join(binary))
                .output()
                .unwrap();
            assert!(execution.status.success(), "{name}: {execution:?}");
            assert_eq!(
                execution.stdout,
                format!("fixture-{name}-{version}\n").as_bytes(),
                "{name}"
            );
        }
    }
    project.run(&["env", "check"]).assert_success();
    project.run(&["ci", "validate"]).assert_success();
    project.close_checked();
}

#[test]
#[cfg(unix)]
fn snapshot_index_access_failures_never_report_empty_or_delete_saved_state() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    for fault in ["dangling-index", "denied-parent"] {
        let project = TestProject::new();
        let missing = project.run_with_env(&["snapshot", "list"], &[("OMG_TEST_MODE", "0")]);
        missing.assert_success();
        assert!(missing.stdout.contains("No snapshots found"));
        let directory = project.data_dir.path().join("snapshots");
        std::fs::create_dir_all(&directory).unwrap();
        let index = directory.join("index.json");
        let snapshot = directory.join("saved.json");
        let snapshot_bytes = serde_json::to_vec(&omg_lib::cli::snapshot::Snapshot {
            id: "saved".into(),
            message: Some("preserve me".into()),
            created_at: 1_700_000_000,
            state: sample_state(),
        })
        .unwrap();
        let index_bytes = serde_json::to_vec(&serde_json::json!({"snapshots":[{
            "id":"saved", "message":"preserve me", "created_at":1_700_000_000,
            "hash":sample_state().hash
        }]}))
        .unwrap();
        std::fs::write(&snapshot, &snapshot_bytes).unwrap();
        std::fs::write(&index, &index_bytes).unwrap();
        let before = project.run_with_env(&["snapshot", "list"], &[("OMG_TEST_MODE", "0")]);
        before.assert_success();
        assert!(before.stdout.contains("saved") && before.stdout.contains("preserve me"));
        let original_mode = std::fs::metadata(&directory).unwrap().permissions();
        let outside = project.dir.path().join("absent-index.json");
        if fault == "denied-parent" {
            assert!(
                !nix::unistd::Uid::effective().is_root(),
                "permission contract requires unprivileged execution"
            );
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o000)).unwrap();
        } else {
            std::fs::remove_file(&index).unwrap();
            symlink(&outside, &index).unwrap();
        }
        let listing = project.run_with_env(&["snapshot", "list"], &[("OMG_TEST_MODE", "0")]);
        let deletion =
            project.run_with_env(&["snapshot", "delete", "saved"], &[("OMG_TEST_MODE", "0")]);
        std::fs::set_permissions(&directory, original_mode).unwrap();
        assert_eq!(
            listing.exit_code,
            1,
            "{fault}: {}",
            listing.combined_output()
        );
        assert!(!listing.stdout.contains("No snapshots found"));
        let expected = if fault == "denied-parent" {
            "Permission denied"
        } else {
            "symlink"
        };
        assert!(
            listing.combined_output().contains(expected),
            "{}",
            listing.combined_output()
        );
        assert_eq!(
            deletion.exit_code,
            1,
            "{fault}: {}",
            deletion.combined_output()
        );
        assert!(
            deletion.combined_output().contains(expected),
            "{}",
            deletion.combined_output()
        );
        assert_eq!(std::fs::read(&snapshot).unwrap(), snapshot_bytes);
        assert!(!outside.exists());
        if fault == "dangling-index" {
            assert_eq!(std::fs::read_link(&index).unwrap(), outside);
            std::fs::remove_file(&index).unwrap();
            std::fs::write(&index, &index_bytes).unwrap();
        } else {
            assert_eq!(std::fs::read(&index).unwrap(), index_bytes);
        }
        project
            .run_with_env(&["snapshot", "delete", "saved"], &[("OMG_TEST_MODE", "0")])
            .assert_success();
        assert!(!snapshot.exists());
        let after: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&index).unwrap()).unwrap();
        assert_eq!(after["snapshots"], serde_json::json!([]));
        let empty = project.run_with_env(&["snapshot", "list"], &[("OMG_TEST_MODE", "0")]);
        empty.assert_success();
        assert!(empty.stdout.contains("No snapshots found"));
        project.close_checked();
    }
}
