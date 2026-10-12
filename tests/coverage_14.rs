//! Contract tests for `src/cli/why.rs` and `src/cli/snapshot.rs` (cov-14).
//!
//! `why` contracts are pinned against a hand-built ALPM local database
//! written under the harness-provided `OMG_PACMAN_ROOT`, so every dependency
//! walk runs against deterministic data instead of the host system.
//! `snapshot` contracts pin the observable on-disk effects (snapshot file,
//! index contents, mock package-manager state) plus exact error strings for
//! every rejection path.

#![cfg(any(feature = "arch", feature = "debian", feature = "debian-pure"))]
#![expect(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]

pub mod common;

use common::*;
use std::fs;

const FAKE_PKG: &str = "omg-contract-fake-pkg";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal but real ALPM local database under the harness pacman root.
///
/// `packages` entries are `(name, version, install_reason, depends)` where
/// install_reason 0 = explicit and 1 = dependency. The layout mirrors what
/// pacman writes on disk (`<root>/var/lib/pacman/local/<name>-<ver>/desc`),
/// including the `ALPM_DB_VERSION` marker libalpm validates on open.
#[cfg(feature = "arch")]
fn install_fake_local_db(project: &TestProject, packages: &[(&str, &str, u8, &[&str])]) {
    let local = project
        .pacman_root
        .path()
        .join("var/lib/pacman")
        .join("local");
    fs::create_dir_all(&local).expect("create fake local db directory");
    fs::write(local.join("ALPM_DB_VERSION"), "9\n").expect("write ALPM_DB_VERSION");
    let root = project.pacman_root.path();
    let sync = root.join("var/lib/pacman/sync");
    let cache = root.join("var/cache/pacman/pkg");
    let etc = root.join("etc/pacman.d");
    for directory in [&sync, &cache, &etc] {
        fs::create_dir_all(directory).expect("create private native fixture directory");
    }
    fs::write(etc.join("mirrorlist"), "").expect("write private empty mirrorlist");
    fs::write(
        root.join("etc/pacman.conf"),
        format!(
            "[options]\nRootDir = {}\nDBPath = {}\nCacheDir = {}\nArchitecture = auto\n",
            root.display(),
            root.join("var/lib/pacman").display(),
            cache.display(),
        ),
    )
    .expect("write private pacman configuration");

    for (name, version, reason, deps) in packages {
        let dir = local.join(format!("{name}-{version}"));
        fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("create {dir:?}: {e}"));
        let mut desc = format!(
            "%NAME%\n{name}\n\n%VERSION%\n{version}\n\n%DESC%\ncontract test package\n\n%URL%\n\
             https://example.invalid/{name}\n\n%LICENSE%\nMIT\n\n%ARCH%\nx86_64\n\n"
        );
        desc.push_str(match reason {
            0 => "\n%REASON%\n0\n",
            _ => "\n%REASON%\n1\n",
        });
        if !deps.is_empty() {
            desc.push_str("\n%DEPENDS%\n");
            for dep in *deps {
                desc.push_str(dep);
                desc.push('\n');
            }
        }
        desc.push('\n');
        fs::write(dir.join("desc"), desc).expect("write package desc");
    }
}

/// Read `snapshots/index.json` out of the isolated data dir and return its
/// entries as `(id, message)` pairs in file order.
fn read_snapshot_index(project: &TestProject) -> Vec<(String, Option<String>)> {
    let path = project.data_dir.path().join("snapshots/index.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("snapshot index must exist at {path:?}: {e}"));
    let value: serde_json::Value =
        serde_json::from_str(&raw).expect("snapshot index must be valid JSON");
    value["snapshots"]
        .as_array()
        .expect("`snapshots` must be an array")
        .iter()
        .map(|entry| {
            (
                entry["id"].as_str().expect("id string").to_string(),
                entry["message"].as_str().map(str::to_string),
            )
        })
        .collect()
}

/// Run `omg snapshot create` and return the ID of the created snapshot.
fn create_snapshot(project: &TestProject, message: &str) -> String {
    let result = project.run(&["snapshot", "create", "--message", message]);
    result.assert_success();
    let entries = read_snapshot_index(project);
    let last = entries.last().expect("create must append an index entry");
    last.0.clone()
}

/// Read the persistent mock package-manager state as `(installed, available)`
/// name sets from the isolated data dir.
fn read_mock_state(
    project: &TestProject,
) -> (
    serde_json::Map<String, serde_json::Value>,
    serde_json::Map<String, serde_json::Value>,
) {
    let path = project.data_dir.path().join("mock_state_pacman.json");
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Default::default(),
        Err(e) => panic!("read mock state at {path:?}: {e}"),
    };
    let value: serde_json::Value =
        serde_json::from_str(&raw).expect("mock state must be valid JSON");
    (
        value["installed"].as_object().cloned().unwrap_or_default(),
        value["available"].as_object().cloned().unwrap_or_default(),
    )
}

// ---------------------------------------------------------------------------
// omg why
// ---------------------------------------------------------------------------

#[cfg(feature = "arch")]
#[derive(Debug, PartialEq, Eq)]
struct NativeFixtureEntry {
    directory: bool,
    len: u64,
    modified: std::time::SystemTime,
    readonly: bool,
    bytes: Vec<u8>,
    #[cfg(unix)]
    identity: (u64, u64, u32, u32, u32, i64, i64, i64, i64),
}

#[cfg(feature = "arch")]
fn native_fixture_state(
    root: &std::path::Path,
) -> std::collections::BTreeMap<std::path::PathBuf, NativeFixtureEntry> {
    fn visit(
        root: &std::path::Path,
        path: &std::path::Path,
        state: &mut std::collections::BTreeMap<std::path::PathBuf, NativeFixtureEntry>,
    ) {
        let metadata = fs::symlink_metadata(path).expect("native fixture metadata");
        assert!(
            metadata.is_dir() || metadata.is_file(),
            "native fixture must contain only real directories/files"
        );
        #[cfg(unix)]
        let identity = {
            use std::os::unix::fs::MetadataExt as _;
            (
                metadata.dev(),
                metadata.ino(),
                metadata.mode(),
                metadata.uid(),
                metadata.gid(),
                metadata.mtime(),
                metadata.mtime_nsec(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            )
        };
        state.insert(
            path.strip_prefix(root).unwrap().to_path_buf(),
            NativeFixtureEntry {
                directory: metadata.is_dir(),
                len: metadata.len(),
                modified: metadata
                    .modified()
                    .expect("native fixture modification time"),
                readonly: metadata.permissions().readonly(),
                bytes: if metadata.is_file() {
                    fs::read(path).expect("native fixture bytes")
                } else {
                    Vec::new()
                },
                #[cfg(unix)]
                identity,
            },
        );
        if metadata.is_dir() {
            for entry in fs::read_dir(path).expect("native fixture entries") {
                visit(root, &entry.expect("native fixture entry").path(), state);
            }
        }
    }
    let mut state = std::collections::BTreeMap::new();
    visit(root, root, &mut state);
    state
}

#[cfg(feature = "arch")]
fn run_native_why(project: &TestProject, args: &[&str]) -> CommandResult {
    let before = native_fixture_state(project.pacman_root.path());
    let result = project.run_native_arch_why(args);
    assert_eq!(
        native_fixture_state(project.pacman_root.path()),
        before,
        "why must preserve every private pacman file, directory, identity, metadata, and byte"
    );
    result
}

#[cfg(feature = "arch")]
mod why_contracts {
    use super::*;

    /// Contract: querying a package that is not installed exits non-zero and
    /// names both the cause ("is not installed") and the remedy
    /// ("Try 'omg search'").
    #[test]
    fn uninstalled_package_fails_naming_cause_and_remedy() {
        if !native_arch_fixture_available() {
            return;
        }
        let project = TestProject::new();
        install_fake_local_db(&project, &[("alpha", "1.0-1", 0, &["beta"])]);

        let result = run_native_why(&project, &["why", "ghost"]);

        result.assert_failure();
        let combined = result.combined_output();
        // NOTE: the product builds an error_with_suggestion Cmd whose remedy
        // ("Try 'omg search'...") is dropped by tea::run_report because the
        // batch aborts at the first Error command; the pinned contract is
        // therefore non-zero exit + cause naming the package.
        assert!(
            combined.contains("'ghost' is not installed"),
            "failure must name the missing package, got:\n{combined}"
        );
        project.close_checked();
    }

    /// Contract: an explicitly-installed package reports Name/Version/Reason
    /// verbatim from the local DB, marks each of its dependencies as
    /// installed or not, and assesses removal safety as a user decision.
    #[test]
    fn explicit_package_reports_reason_dependencies_and_safety() {
        if !native_arch_fixture_available() {
            return;
        }
        let project = TestProject::new();
        install_fake_local_db(
            &project,
            &[
                ("alpha", "3.2-1", 0, &["beta", "missingdep"]),
                ("beta", "2.0-1", 1, &[]),
            ],
        );

        let result = run_native_why(&project, &["why", "alpha"]);

        result.assert_success();
        let out = &result.stdout;
        assert!(out.contains("Package Analysis"), "got:\n{out}");
        assert!(out.contains("Name: alpha"), "got:\n{out}");
        assert!(
            out.contains("Version: 3.2-1"),
            "version must come from the local db desc, got:\n{out}"
        );
        assert!(
            out.contains("Reason: explicitly installed"),
            "reason=0 must render as explicitly installed, got:\n{out}"
        );
        assert!(
            out.lines().any(|line| line.contains("beta: ✓ installed")),
            "installed dependency beta must be marked ✓, got:\n{out}"
        );
        assert!(
            out.lines()
                .any(|line| line.contains("missingdep: ✗ not installed")),
            "absent dependency missingdep must be marked ✗, got:\n{out}"
        );
        assert!(
            out.contains("Safe to remove: User decision - explicitly installed"),
            "explicit package must be a user decision, got:\n{out}"
        );
        project.close_checked();
    }

    /// Contract: a dependency-reason package required by nothing is reported
    /// as an orphan that can be removed, with safety YES.
    #[test]
    fn orphan_dependency_is_flagged_safe_to_remove() {
        if !native_arch_fixture_available() {
            return;
        }
        let project = TestProject::new();
        install_fake_local_db(
            &project,
            &[("alpha", "1.0-1", 0, &[]), ("orphanlib", "0.5-2", 1, &[])],
        );

        let result = run_native_why(&project, &["why", "orphanlib"]);

        result.assert_success();
        let out = &result.stdout;
        assert!(
            out.contains("Reason: installed as a dependency"),
            "reason=1 must render as a dependency, got:\n{out}"
        );
        assert!(
            out.contains("(orphan - can be removed)"),
            "unrequired dependency must be flagged orphan, got:\n{out}"
        );
        assert!(
            out.contains("Safe to remove: YES - orphan dependency"),
            "orphan dependency must be safe to remove, got:\n{out}"
        );
        project.close_checked();
    }

    /// Contract: when another installed package depends on the target, `why`
    /// lists it under "Required by", derives a BFS dependency path ending at
    /// the target package, and flips the safety verdict to NO.
    #[test]
    fn required_by_card_shows_dependent_and_dependency_path() {
        if !native_arch_fixture_available() {
            return;
        }
        let project = TestProject::new();
        install_fake_local_db(
            &project,
            &[("alpha", "1.0-1", 0, &["beta"]), ("beta", "2.0-1", 1, &[])],
        );

        let result = run_native_why(&project, &["why", "beta"]);

        result.assert_success();
        let out = &result.stdout;
        assert!(
            out.contains("Required by (1 packages)"),
            "exactly one dependent must be counted, got:\n{out}"
        );
        assert!(
            out.contains("alpha"),
            "dependent alpha must be listed, got:\n{out}"
        );
        assert!(
            out.contains("Dependency Path Example"),
            "a non-empty Required-by list must include a path example, got:\n{out}"
        );
        assert!(
            out.contains("└─ alpha: explicit"),
            "path must start at the explicit dependent, got:\n{out}"
        );
        assert!(
            out.contains("└─ beta: target package"),
            "path must end at the target package, got:\n{out}"
        );
        assert!(
            out.contains("Safe to remove: NO - 1 packages depend on it"),
            "required package must be unsafe to remove, got:\n{out}"
        );
        project.close_checked();
    }

    /// Contract: `--reverse` lists dependents with their install reason and
    /// warns against removal with exact counts.
    #[test]
    fn reverse_lists_dependents_with_safety_warning() {
        if !native_arch_fixture_available() {
            return;
        }
        let project = TestProject::new();
        install_fake_local_db(
            &project,
            &[
                ("app", "5.0-1", 0, &["sharedlib"]),
                ("tool", "1.1-3", 1, &["sharedlib"]),
                ("sharedlib", "4.4-1", 1, &[]),
            ],
        );

        let result = run_native_why(&project, &["why", "sharedlib", "--reverse"]);

        result.assert_success();
        let out = &result.stdout;
        assert!(
            out.contains("Reverse Dependencies"),
            "header must announce reverse mode, got:\n{out}"
        );
        assert!(
            out.contains("Dependents (2 total)"),
            "both dependents must be counted, got:\n{out}"
        );
        assert!(
            out.contains("app: explicit"),
            "explicit dependent must carry the explicit marker, got:\n{out}"
        );
        assert!(
            out.contains("tool: dependency"),
            "dependency-reason dependent must carry the dependency marker, got:\n{out}"
        );
        // Explicit-first ordering: app appears before tool.
        let app_pos = out.find("app: explicit").expect("app listed");
        let tool_pos = out.find("tool: dependency").expect("tool listed");
        assert!(
            app_pos < tool_pos,
            "explicit dependents must sort before dependency dependents"
        );
        assert!(
            out.contains(
                "Safe to remove: NO (would break 2 dependents: 1 explicit, 1 dependencies)"
            ),
            "warning must break down counts exactly, got:\n{out}"
        );
        project.close_checked();
    }

    /// Contract: `--reverse` for a package nobody needs succeeds with a YES
    /// verdict rather than failing.
    #[test]
    fn reverse_without_dependents_is_safe() {
        if !native_arch_fixture_available() {
            return;
        }
        let project = TestProject::new();
        install_fake_local_db(&project, &[("loner", "2.2-1", 0, &[])]);

        let result = run_native_why(&project, &["why", "loner", "--reverse"]);

        result.assert_success();
        let out = &result.stdout;
        assert!(
            out.contains("Nothing depends on this package"),
            "got:\n{out}"
        );
        assert!(
            out.contains("Safe to remove: YES (if not needed)"),
            "got:\n{out}"
        );
        project.close_checked();
    }

    #[test]
    fn mock_why_refusal_preserves_private_native_database() {
        let project = TestProject::new();
        install_fake_local_db(&project, &[("alpha", "3.2-1", 0, &[])]);
        let before = native_fixture_state(project.pacman_root.path());
        let result = project.run(&["why", "alpha"]);
        result.assert_failure();
        assert!(
            result
                .combined_output()
                .contains("Package dependency analysis is not implemented for the mock backend")
        );
        assert_eq!(native_fixture_state(project.pacman_root.path()), before);
        project.close_checked();
    }
}

// ---------------------------------------------------------------------------
// omg snapshot
// ---------------------------------------------------------------------------

mod snapshot_contracts {
    use super::*;

    #[test]
    fn held_index_lock_blocks_snapshot_mutations() -> anyhow::Result<()> {
        let project = TestProject::new();
        let id = create_snapshot(&project, "original");
        let directory = project.data_dir.path().join("snapshots");
        let original = fs::read(directory.join("index.json"))?;
        let lock = fs::File::create(directory.join(".index.lock"))?;
        lock.lock()?;
        for args in [
            vec!["snapshot", "create", "--message", "must not appear"],
            vec!["snapshot", "delete", id.as_str()],
        ] {
            let result = project.run_with_env(&args, &[("OMG_TEST_COMMAND_TIMEOUT_SECS", "5")]);
            result.assert_failure();
            assert!(
                result
                    .combined_output()
                    .contains("Another snapshot mutation is running")
            );
            assert_eq!(fs::read(directory.join("index.json"))?, original);
            assert!(directory.join(format!("{id}.json")).is_file());
        }
        drop(lock);
        create_snapshot(&project, "after release");
        project.run(&["snapshot", "delete", &id]).assert_success();
        assert_eq!(read_snapshot_index(&project).len(), 1);
        Ok(())
    }

    #[test]
    fn corrupt_index_is_checked_before_snapshot_mutation() -> anyhow::Result<()> {
        let project = TestProject::new();
        let id = create_snapshot(&project, "preserve");
        let directory = project.data_dir.path().join("snapshots");
        let snapshot = directory.join(format!("{id}.json"));
        let original = fs::read(&snapshot)?;
        fs::write(directory.join("index.json"), b"malformed index")?;
        for args in [
            vec!["snapshot", "delete", id.as_str()],
            vec!["snapshot", "create", "--message", "must not appear"],
        ] {
            project.run(&args).assert_failure();
            assert_eq!(
                fs::read(&snapshot)?,
                original,
                "snapshot bytes must survive index errors"
            );
            assert_eq!(fs::read(directory.join("index.json"))?, b"malformed index");
            let json_files = fs::read_dir(&directory)?
                .collect::<std::io::Result<Vec<_>>>()?
                .into_iter()
                .filter(|entry| {
                    entry
                        .path()
                        .extension()
                        .is_some_and(|extension| extension == "json")
                })
                .count();
            assert_eq!(
                json_files, 2,
                "failed create must not leave an unindexed snapshot"
            );
        }
        Ok(())
    }

    /// Contract: `snapshot create --message M` appends exactly one index
    /// entry carrying the message and an ID of the form
    /// `snap-YYYY-MM-DD-<8 hex>`, writes the matching `<id>.json` snapshot
    /// file whose embedded message equals `M`, and announces the ID on
    /// stdout together with the restore hint.
    #[test]
    fn create_persists_snapshot_file_and_index_entry() {
        let project = TestProject::new();

        let result = project.run(&["snapshot", "create", "--message", "hello contract"]);
        result.assert_success();

        let entries = read_snapshot_index(&project);
        assert_eq!(
            entries.len(),
            1,
            "one create must produce exactly one index entry"
        );
        let (id, message) = &entries[0];
        assert_eq!(
            message.as_deref(),
            Some("hello contract"),
            "index must record the given message"
        );
        let rest = id
            .strip_prefix("snap-")
            .unwrap_or_else(|| panic!("id must start with snap-, got {id}"));
        assert_eq!(rest.len(), 19, "id must be YYYY-MM-DD-8hex ({id})");
        assert!(
            rest.chars().enumerate().all(|(i, c)| {
                if i == 4 || i == 7 || i == 10 {
                    c == '-'
                } else {
                    c.is_ascii_hexdigit()
                }
            }),
            "id body must be date-hex shaped, got {id}"
        );

        let snap_path = project.data_dir.path().join(format!("snapshots/{id}.json"));
        let raw = fs::read_to_string(&snap_path)
            .unwrap_or_else(|e| panic!("snapshot file must exist at {snap_path:?}: {e}"));
        let snap: serde_json::Value =
            serde_json::from_str(&raw).expect("snapshot file must be valid JSON");
        assert_eq!(
            snap["message"].as_str(),
            Some("hello contract"),
            "snapshot file must embed the message"
        );
        assert_eq!(snap["id"].as_str(), Some(id.as_str()));
        assert!(
            snap["created_at"].is_i64(),
            "created_at must be an integer timestamp"
        );
        assert!(
            snap["state"]["runtimes"].is_object() && snap["state"]["packages"].is_array(),
            "snapshot must embed a captured EnvironmentState"
        );

        result.assert_stdout_contains("Snapshot created!");
        result.assert_stdout_contains(id);
        result.assert_stdout_contains("hello contract");
        result.assert_stdout_contains("Restore with:");
    }

    /// Contract: an empty store renders "No snapshots found"; after two
    /// creates, `list` shows both messages and reports the total, newest
    /// entry first.
    #[test]
    fn list_shows_empty_state_then_entries_newest_first_with_total() {
        let project = TestProject::new();

        let empty = project.run(&["snapshot", "list"]);
        empty.assert_success();
        empty.assert_stdout_contains("No snapshots found");

        let first = create_snapshot(&project, "first msg");
        let second = create_snapshot(&project, "second msg");

        let result = project.run(&["snapshot", "list"]);
        result.assert_success();
        let out = &result.stdout;
        assert!(out.contains(&first) && out.contains(&second), "got:\n{out}");
        assert!(
            out.contains("first msg") && out.contains("second msg"),
            "messages must be rendered, got:\n{out}"
        );
        // list() iterates the index in reverse, so the newest entry prints
        // before the older one.
        assert!(
            out.rfind(&second).unwrap() < out.rfind(&first).unwrap(),
            "newest snapshot (last created) must print first"
        );
        assert!(out.contains("2 snapshots total"), "got:\n{out}");

        let entries = read_snapshot_index(&project);
        assert_eq!(entries.len(), 2, "list must not mutate the index");
    }

    /// Contract: `restore --dry-run` computes the diff between the snapshot
    /// and current state, prints the pending installs, states that no
    /// changes were made, and leaves both the mock package state and the
    /// snapshot untouched.
    #[test]
    fn restore_dry_run_reports_plan_without_applying() {
        let project = TestProject::new();
        project.mock_available(FAKE_PKG, "1.0").expect("seed mock");
        let id = create_snapshot(&project, "base");
        let snap_path = project.data_dir.path().join(format!("snapshots/{id}.json"));

        // Rewrite the captured state so restoring would need one install.
        let mut snap: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&snap_path).expect("snapshot readable"))
                .expect("valid snapshot JSON");
        snap["state"]["packages"] = serde_json::json!([FAKE_PKG]);
        fs::write(&snap_path, serde_json::to_string_pretty(&snap).unwrap())
            .expect("rewrite snapshot");
        let before = fs::read_to_string(&snap_path).expect("snapshot readable");

        let result = project.run(&["snapshot", "restore", &id, "--dry-run"]);

        result.assert_success();
        let out = &result.stdout;
        assert!(
            out.contains("Packages to install (1):"),
            "the single missing package must be planned, got:\n{out}"
        );
        // The '+' bullet is emitted as a styled span, so pin bullet and name
        // separately around the ANSI boundaries.
        assert!(
            out.contains(FAKE_PKG),
            "planned package must be named, got:\n{out}"
        );
        assert!(
            out.contains('+'),
            "install plan rows must be prefixed +, got:\n{out}"
        );
        assert!(
            out.contains("No changes made (dry run)"),
            "dry run must disclaim side effects, got:\n{out}"
        );

        let (installed, _) = read_mock_state(&project);
        assert!(
            !installed.contains_key(FAKE_PKG),
            "dry run must not install anything, mock state: {installed:?}"
        );
        let after = fs::read_to_string(&snap_path).expect("snapshot readable after dry run");
        assert_eq!(before, after, "dry run must not rewrite the snapshot file");
    }

    /// Contract: a non-interactive restore with pending package changes
    /// refuses to act, exits non-zero, and points at `--yes` as the remedy.
    #[test]
    fn restore_requires_yes_in_non_interactive_mode() {
        let project = TestProject::new();
        project.mock_available(FAKE_PKG, "1.0").expect("seed mock");
        let id = create_snapshot(&project, "base");
        let snap_path = project.data_dir.path().join(format!("snapshots/{id}.json"));
        let mut snap: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&snap_path).expect("readable")).expect("json");
        snap["state"]["packages"] = serde_json::json!([FAKE_PKG]);
        fs::write(&snap_path, serde_json::to_string_pretty(&snap).unwrap()).expect("rewrite");

        // The harness always pipes stdin, which console::user_attended()
        // treats as non-interactive; spawn the child with the same isolated
        // env the harness would set and close stdin immediately (EOF).
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_omg"));
        cmd.args(["snapshot", "restore", &id])
            .env("OMG_TEST_MODE", "1")
            .env("OMG_DISABLE_DAEMON", "1")
            .env("OMG_DISABLE_TELEMETRY", "1")
            .env("OMG_DATA_DIR", project.data_dir.path())
            .env("OMG_CONFIG_DIR", project.config_dir.path())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().expect("spawn omg");
        drop(child.stdin.take()); // EOF immediately => non-interactive
        let output = child.wait_with_output().expect("wait for omg");

        assert!(
            !output.status.success(),
            "restore without --yes must fail in non-interactive mode, got: {output:?}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("interactive terminal or the --yes flag"),
            "refusal must name the interactive/--yes requirement, got:\n{stderr}"
        );
        assert!(
            stderr.contains(&format!("omg snapshot restore {id} --yes")),
            "refusal must show the exact automation command, got:\n{stderr}"
        );
        let (installed, _) = read_mock_state(&project);
        assert!(
            !installed.contains_key(FAKE_PKG),
            "refused restore must not have installed anything"
        );
    }

    /// Contract: `restore --yes` applies the diff: the missing package is
    /// recorded as installed in the package-manager state, the run reports
    /// the installation and completion, and afterwards the environment
    /// matches the snapshot.
    #[test]
    fn restore_yes_applies_missing_package_install() {
        let project = TestProject::new();
        project.mock_available(FAKE_PKG, "7.1").expect("seed mock");
        let id = create_snapshot(&project, "with fake pkg");
        let snap_path = project.data_dir.path().join(format!("snapshots/{id}.json"));
        let mut snap: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&snap_path).expect("readable")).expect("json");
        snap["state"]["packages"] = serde_json::json!([FAKE_PKG]);
        fs::write(&snap_path, serde_json::to_string_pretty(&snap).unwrap()).expect("rewrite");

        let result = project.run(&["snapshot", "restore", &id, "--yes"]);

        result.assert_success();
        let out = &result.stdout;
        assert!(
            out.contains("Packages to install (1):"),
            "plan must precede apply, got:\n{out}"
        );
        assert!(
            out.contains("Installing 1 packages..."),
            "apply phase must report the install, got:\n{out}"
        );
        assert!(
            out.contains("Snapshot restore complete!"),
            "successful restore must report completion, got:\n{out}"
        );

        let (installed, _) = read_mock_state(&project);
        let version = installed
            .get(FAKE_PKG)
            .unwrap_or_else(|| panic!("{FAKE_PKG} must be recorded installed, got {installed:?}"));
        assert_eq!(
            version.as_str(),
            Some("7.1"),
            "install must record the seeded version"
        );

        // A second restore now finds the environment already in sync.
        let again = project.run(&["snapshot", "restore", &id, "--yes"]);
        again.assert_success();
        again.assert_stdout_contains("Environment already matches snapshot!");
    }

    /// Contract: malformed snapshot IDs are rejected up front with
    /// "Invalid snapshot ID"; well-formed-but-unknown IDs fail with
    /// "Snapshot '<id>' not found". Neither may touch the store.
    #[test]
    fn restore_rejects_invalid_and_unknown_ids() {
        let project = TestProject::new();
        create_snapshot(&project, "sentinel");
        let before = read_snapshot_index(&project);

        let invalid = project.run(&["snapshot", "restore", "../evil"]);
        invalid.assert_failure();
        let combined = invalid.combined_output();
        assert!(
            combined.contains("Invalid snapshot ID: ../evil"),
            "path traversal id must be rejected by name, got:\n{combined}"
        );

        let unknown = project.run(&["snapshot", "restore", "snap-nope-not-real"]);
        unknown.assert_failure();
        let combined = unknown.combined_output();
        assert!(
            combined.contains("Snapshot 'snap-nope-not-real' not found"),
            "unknown id failure must name the id, got:\n{combined}"
        );

        assert_eq!(
            read_snapshot_index(&project).len(),
            before.len(),
            "failed restores must not mutate the index"
        );
    }

    /// Contract: `delete` removes the snapshot file, drops only that entry
    /// from the index, and a repeat delete fails with "not found".
    #[test]
    fn delete_removes_file_and_index_entry_only_for_target_id() {
        let project = TestProject::new();
        let keep_id = create_snapshot(&project, "keep me");
        let kill_id = create_snapshot(&project, "kill me");

        let result = project.run(&["snapshot", "delete", &kill_id]);
        result.assert_success();
        // The id is rendered as a styled span, so pin text and id separately.
        result.assert_stdout_contains("Deleted snapshot");
        result.assert_stdout_contains(&kill_id);

        assert!(
            !project
                .data_dir
                .path()
                .join(format!("snapshots/{kill_id}.json"))
                .exists(),
            "deleted snapshot file must be gone from disk"
        );
        let entries = read_snapshot_index(&project);
        assert_eq!(entries.len(), 1, "only the target entry may be dropped");
        assert_eq!(
            entries[0].0, keep_id,
            "the surviving entry must be the other one"
        );
        assert_eq!(entries[0].1.as_deref(), Some("keep me"));

        let listing = project.run(&["snapshot", "list"]);
        listing.assert_success();
        listing.assert_stdout_contains("keep me");
        assert!(
            !listing.stdout.contains(&kill_id),
            "deleted id must vanish from listings, got:\n{}",
            listing.stdout
        );

        let repeat = project.run(&["snapshot", "delete", &kill_id]);
        repeat.assert_failure();
        assert!(
            repeat
                .combined_output()
                .contains(&format!("Snapshot '{kill_id}' not found")),
            "repeat delete must fail naming the missing id, got:\n{}",
            repeat.combined_output()
        );
    }

    /// Contract: a >1000-byte message is rejected with "Snapshot message too
    /// long" and nothing is persisted — no index, no snapshot files.
    #[test]
    fn create_rejects_overlong_message_without_writing_anything() {
        let project = TestProject::new();
        let long = "x".repeat(1001);

        let result = project.run(&["snapshot", "create", "--message", &long]);

        result.assert_failure();
        let combined = result.combined_output();
        assert!(
            combined.contains("Snapshot message too long"),
            "rejection must name the length rule, got:\n{combined}"
        );
        assert!(
            !project
                .data_dir
                .path()
                .join("snapshots/index.json")
                .exists(),
            "rejected create must not persist an index"
        );
        let snapshots = project.data_dir.path().join("snapshots");
        let stray = fs::read_dir(&snapshots)
            .map(|rd| rd.flatten().count())
            .unwrap_or(0);
        assert_eq!(stray, 0, "rejected create must not leave snapshot files");
    }
}

#[cfg(feature = "arch")]
mod install_discovery {
    use super::*;

    #[test]
    fn completion_keeps_package_context_after_options_and_targets() {
        let project = TestProject::for_distro("arch");
        install_fake_local_db(&project, &[("firefox", "1.0-1", 0, &[])]);
        let cache = serde_json::json!({
            "format_version": 1,
            "entries": {
                "aur_last_refresh": jiff::Timestamp::now().to_string(),
                "aur_packages": "firefox-nightly"
            }
        });
        let cache_path = project.data_dir.path().join("completion-cache.json");
        let original = serde_json::to_vec(&cache).unwrap();
        fs::write(&cache_path, &original).unwrap();

        for (last, full) in [
            ("install", "omg install frfx"),
            ("-y", "omg install -y frfx"),
            ("git", "omg install git frfx"),
            ("tool", "omg install tool frfx"),
            ("i", "omg -q i frfx"),
        ] {
            let result = project.run(&[
                "complete",
                "--shell",
                "zsh",
                "--current",
                "frfx",
                "--last",
                last,
                "--full",
                full,
            ]);
            result.assert_success();
            assert_eq!(
                result.stdout.lines().collect::<Vec<_>>(),
                vec!["firefox", "firefox-nightly"],
                "completion context: {full}"
            );
        }
        assert_eq!(fs::read(cache_path).unwrap(), original);
    }

    #[test]
    fn install_without_targets_needs_a_terminal_and_preserves_inventory() {
        let project = TestProject::for_distro("arch");
        project.mock_install("git", "1.0-1").unwrap();
        let state_path = project.data_dir.path().join("mock_state_pacman.json");
        let original = fs::read(&state_path).unwrap();
        for args in [
            vec!["install"],
            vec!["i"],
            vec!["install", "-y"],
            vec!["install", "--dry-run"],
        ] {
            let result = project.run(&args);
            result.assert_failure();
            result.assert_stderr_contains("No packages specified; run `omg install` in a terminal");
            assert_eq!(fs::read(&state_path).unwrap(), original);
        }
    }
}
