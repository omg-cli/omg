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
