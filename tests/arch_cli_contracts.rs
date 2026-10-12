#![cfg(feature = "arch")]

use std::path::Path;

use anyhow::{Context, Result};
use tempfile::TempDir;

pub mod common;

use common::CommandResult;
use std::fmt::Write as _;

/// Run the CLI through the shared isolated runner, pinned to the Arch mock
/// backend and the given working directory. Replaces the former hand-rolled
/// `Command` copy that duplicated the runner's environment contract.
fn run(root: &Path, args: &[&str]) -> CommandResult {
    common::run_omg_with_options(
        args,
        Some(root),
        &[
            ("OMG_TEST_DISTRO", "arch"),
            ("NO_COLOR", "1"),
            ("OMG_DISABLE_TELEMETRY", "1"),
        ],
    )
}

fn output_text(output: &CommandResult) -> String {
    output.combined_output()
}

#[test]
fn explicit_absolute_paths_work_for_portable_files() -> Result<()> {
    let root = TempDir::new()?;
    let manifest = root.path().join("manifest.json");
    let lock = root.path().join("omg.lock");

    let export = run(
        root.path(),
        &["migrate", "export", "--output", &manifest.to_string_lossy()],
    );
    assert!(export.success, "{}", output_text(&export));

    let import = run(
        root.path(),
        &[
            "migrate",
            "import",
            &manifest.to_string_lossy(),
            "--dry-run",
        ],
    );
    assert!(import.success, "{}", output_text(&import));

    let capture = run(root.path(), &["env", "capture"]);
    assert!(capture.success, "{}", output_text(&capture));
    assert!(lock.is_file());

    let diff = run(
        root.path(),
        &[
            "diff",
            "--from",
            &lock.to_string_lossy(),
            &lock.to_string_lossy(),
        ],
    );
    assert!(diff.success, "{}", output_text(&diff));
    Ok(())
}

#[test]
fn unknown_config_keys_fail() -> Result<()> {
    let root = TempDir::new()?;
    let output = run(root.path(), &["config", "get", "not.a.real.key"]);
    assert!(!output.success, "{}", output_text(&output));
    assert!(output_text(&output).contains("Unknown config key"));
    Ok(())
}

#[test]
fn privacy_export_works_without_a_license() -> Result<()> {
    let root = TempDir::new()?;
    let export_path = root.path().join("privacy.json");
    let output = run(
        root.path(),
        &[
            "privacy",
            "export",
            "--output",
            &export_path.to_string_lossy(),
        ],
    );
    assert!(output.success, "{}", output_text(&output));

    let export: serde_json::Value = serde_json::from_slice(&std::fs::read(export_path)?)?;
    assert!(export.get("local").is_some());
    assert!(export["remote"].is_null());
    Ok(())
}

#[test]
fn advertised_json_outputs_are_valid_json() -> Result<()> {
    let root = TempDir::new()?;
    for command in ["history", "stats", "outdated"] {
        let output = run(root.path(), &["--json", command]);
        assert!(output.success, "{}", output_text(&output));
        serde_json::from_str::<serde_json::Value>(&output.stdout)
            .with_context(|| format!("{command} emitted invalid JSON"))?;
        assert!(
            output.stderr.is_empty(),
            "{command} emitted non-error diagnostics in JSON mode: {}",
            output.stderr
        );
    }
    Ok(())
}

#[test]
fn successful_requests_do_not_invent_transaction_summaries() -> Result<()> {
    let root = TempDir::new()?;
    for (args, unsupported_claim) in [
        (["install", "--yes", "firefox"], "Installed 1 package"),
        (
            ["remove", "--yes", "firefox"],
            "Packages removed successfully",
        ),
    ] {
        let output = run(root.path(), &args);
        assert!(output.success, "{}", output_text(&output));
        assert!(
            !output.stdout.contains(unsupported_claim),
            "{}",
            output_text(&output)
        );
    }
    Ok(())
}

#[test]
fn clean_dry_run_never_attempts_privilege_escalation() -> Result<()> {
    let root = TempDir::new()?;
    let output = run(root.path(), &["clean", "--all", "--dry-run"]);
    assert!(output.success, "{}", output_text(&output));
    assert!(!output_text(&output).contains("sudo:"));
    Ok(())
}

#[test]
fn enterprise_license_scan_bounds_large_reports() -> Result<()> {
    let root = TempDir::new()?;
    let output = run(root.path(), &["enterprise", "license-scan"]);

    assert!(output.success, "{}", output_text(&output));
    assert!(
        output.stdout.lines().count() <= 150,
        "license scan printed {} lines\n{}",
        output.stdout.lines().count(),
        output.stdout
    );
    assert!(output.stdout.contains("... and "), "{}", output.stdout);
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct PrivateFixtureEntry {
    directory: bool,
    len: u64,
    modified: std::time::SystemTime,
    readonly: bool,
    bytes: Vec<u8>,
    #[cfg(unix)]
    identity: (u64, u64, u32, u32, u32, i64, i64, i64, i64),
}

fn private_fixture_state(
    root: &Path,
) -> Result<std::collections::BTreeMap<std::path::PathBuf, PrivateFixtureEntry>> {
    fn visit(
        root: &Path,
        path: &Path,
        state: &mut std::collections::BTreeMap<std::path::PathBuf, PrivateFixtureEntry>,
    ) -> Result<()> {
        let metadata = std::fs::symlink_metadata(path)?;
        anyhow::ensure!(
            metadata.is_dir() || metadata.is_file(),
            "private fixture contains a symlink or special file: {}",
            path.display()
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
            path.strip_prefix(root)?.to_path_buf(),
            PrivateFixtureEntry {
                directory: metadata.is_dir(),
                len: metadata.len(),
                modified: metadata.modified()?,
                readonly: metadata.permissions().readonly(),
                bytes: if metadata.is_file() {
                    std::fs::read(path)?
                } else {
                    Vec::new()
                },
                #[cfg(unix)]
                identity,
            },
        );
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path)? {
                visit(root, &entry?.path(), state)?;
            }
        }
        Ok(())
    }
    let mut state = std::collections::BTreeMap::new();
    visit(root, root, &mut state)?;
    Ok(state)
}

fn prepare_large_dependency_fixture(project: &common::TestProject) -> Result<()> {
    let root = project.pacman_root.path();
    let db = root.join("var/lib/pacman");
    let local = db.join("local");
    let sync = db.join("sync");
    let cache = root.join("var/cache/pacman/pkg");
    let etc = root.join("etc/pacman.d");
    for directory in [&local, &sync, &cache, &etc] {
        std::fs::create_dir_all(directory)?;
    }
    std::fs::write(local.join("ALPM_DB_VERSION"), "9\n")?;
    std::fs::write(etc.join("mirrorlist"), "")?;
    std::fs::write(
        root.join("etc/pacman.conf"),
        format!(
            "[options]\nRootDir = {}\nDBPath = {}\nCacheDir = {}\nArchitecture = auto\n",
            root.display(),
            db.display(),
            cache.display()
        ),
    )?;
    fn package(
        local: &Path,
        name: &str,
        version: &str,
        reason: u8,
        dependency: Option<&str>,
    ) -> Result<()> {
        let directory = local.join(format!("{name}-{version}"));
        std::fs::create_dir_all(&directory)?;
        let mut desc = format!(
            "%NAME%\n{name}\n\n%VERSION%\n{version}\n\n%DESC%\nPrivate dependency report fixture\n\n%ARCH%\nx86_64\n\n%SIZE%\n4096\n\n%REASON%\n{reason}\n\n%LICENSE%\nMIT\n\n"
        );
        if let Some(dependency) = dependency {
            write!(desc, "%DEPENDS%\n{dependency}\n\n")?;
        }
        std::fs::write(directory.join("desc"), desc)?;
        Ok(())
    }
    package(&local, "glibc", "2.40-1", 1, None)?;
    for index in 0..25 {
        let name = format!("omg-fixture-dep-{index:02}");
        let reason = u8::from(index % 2 != 0);
        package(&local, &name, "1.0-1", reason, Some("glibc"))?;
    }
    std::fs::write(project.data_dir.path().join("history.json"), "[]\n")?;
    Ok(())
}

#[test]
fn dependency_reports_bound_large_reverse_dependency_lists() -> Result<()> {
    if !common::native_arch_fixture_available() {
        return Ok(());
    }
    let project = common::TestProject::new();
    prepare_large_dependency_fixture(&project)?;
    let before = private_fixture_state(project.pacman_root.path())?;
    let history = project.data_dir.path().join("history.json");
    let history_before = private_fixture_state(&history)?;
    {
        // Literal fixture facts are checked independently of the CLI renderer.
        let db = project.pacman_root.path().join("var/lib/pacman");
        let handle = alpm::Alpm::new(
            project.pacman_root.path().to_string_lossy().into_owned(),
            db.to_string_lossy().into_owned(),
        )?;
        let local = handle.localdb();
        assert_eq!(local.pkgs().len(), 26);
        let glibc = local.pkg("glibc")?;
        assert_eq!(glibc.version().as_str(), "2.40-1");
        assert_eq!(glibc.reason(), alpm::PackageReason::Depend);
        let required = glibc.required_by();
        assert_eq!(required.len(), 25);
        let mut explicit = 0;
        let mut dependency = 0;
        for name in required {
            match local.pkg(name.as_bytes())?.reason() {
                alpm::PackageReason::Explicit => explicit += 1,
                alpm::PackageReason::Depend => dependency += 1,
            }
        }
        assert_eq!((explicit, dependency), (13, 12));
    }
    assert_eq!(private_fixture_state(project.pacman_root.path())?, before);
    eprintln!(
        "[native-dependency-report-fixture] total=26 required=25 explicit=13 dependency=12 glibc=2.40-1"
    );
    for args in [
        ["why", "glibc"].as_slice(),
        ["why", "glibc", "--reverse"].as_slice(),
        ["blame", "glibc"].as_slice(),
    ] {
        let output = project.run_native_arch_dependency_report(args);
        assert_eq!(private_fixture_state(project.pacman_root.path())?, before);
        assert_eq!(private_fixture_state(&history)?, history_before);
        assert!(output.success, "{}", output_text(&output));
        assert_eq!(output.exit_code, 0, "{}", output_text(&output));
        assert!(
            output.stdout.lines().count() <= 120,
            "`omg {}` printed {} lines\n{}",
            args.join(" "),
            output.stdout.lines().count(),
            output.stdout
        );
        let reverse = args.contains(&"--reverse");
        let title = if reverse {
            "Dependents (25 total)"
        } else {
            "Required by (25 packages)"
        };
        let (_, card) = output
            .stdout
            .split_once(title)
            .context("full literal count must survive truncation")?;
        let (visible, _) = card
            .split_once("... and 5 more")
            .context("five omitted dependents must be reported")?;
        assert_eq!(output.stdout.matches("... and 5 more").count(), 1);
        let displayed: Vec<_> = visible
            .lines()
            .filter(|line| line.contains("omg-fixture-dep-"))
            .collect();
        assert_eq!(displayed.len(), 20, "{}", output.stdout);
        if reverse {
            assert!(
                displayed[..13]
                    .iter()
                    .all(|line| line.contains(": explicit"))
            );
            assert!(
                displayed[13..]
                    .iter()
                    .all(|line| line.contains(": dependency"))
            );
            assert!(output.stdout.contains(
                "Safe to remove: NO (would break 25 dependents: 13 explicit, 12 dependencies)"
            ));
        } else {
            assert!(output.stdout.contains("Name: glibc"));
            assert!(output.stdout.contains("Version: 2.40-1"));
            if args[0] == "why" {
                assert!(
                    output
                        .stdout
                        .contains("Safe to remove: NO - 25 packages depend on it")
                );
                assert!(output.stdout.contains("└─ glibc: target package"));
            } else {
                assert!(
                    output
                        .stdout
                        .contains("No OMG transaction history found for this package")
                );
            }
        }
        eprintln!(
            "[native-dependency-report-result] command={} exit=0 listed=20 total=25 omitted=5 private_db_unchanged=true",
            args.join(" ")
        );
    }
    project.close_checked();
    Ok(())
}

fn prepare_native_size_fixture(
    project: &common::TestProject,
    dependencies: &[&str],
    provides: &[&str],
) -> Result<()> {
    let root = project.pacman_root.path();
    let db = root.join("var/lib/pacman");
    let local = db.join("local");
    let cache = root.join("var/cache/pacman/pkg");
    let etc = root.join("etc/pacman.d");
    for directory in [&local, &db.join("sync"), &cache, &etc] {
        std::fs::create_dir_all(directory)?;
    }
    std::fs::write(local.join("ALPM_DB_VERSION"), "9\n")?;
    std::fs::write(etc.join("mirrorlist"), "")?;
    std::fs::write(
        root.join("etc/pacman.conf"),
        format!(
            "[options]\nRootDir = {}\nDBPath = {}\nCacheDir = {}\nArchitecture = auto\n",
            root.display(),
            db.display(),
            cache.display()
        ),
    )?;
    let application = local.join("application-1.0-1");
    let implementation = local.join("implementation-1.0-1");
    std::fs::create_dir_all(&application)?;
    std::fs::create_dir_all(&implementation)?;
    std::fs::write(
        application.join("desc"),
        format!(
            "%NAME%\napplication\n\n%VERSION%\n1.0-1\n\n%DESC%\nPrivate size root\n\n%ARCH%\nx86_64\n\n%SIZE%\n1024\n\n%REASON%\n0\n\n%DEPENDS%\n{}\n\n",
            dependencies.join("\n")
        ),
    )?;
    let mut provider_desc = "%NAME%\nimplementation\n\n%VERSION%\n1.0-1\n\n%DESC%\nPrivate size provider\n\n%ARCH%\nx86_64\n\n%SIZE%\n2048\n\n%REASON%\n1\n\n".to_string();
    if !provides.is_empty() {
        write!(provider_desc, "%PROVIDES%\n{}\n\n", provides.join("\n"))?;
    }
    std::fs::write(implementation.join("desc"), provider_desc)?;
    std::fs::write(project.data_dir.path().join("history.json"), "[]\n")?;

    // Validate native metadata before attributing a later CLI failure to size.
    let handle = alpm::Alpm::new(
        root.to_string_lossy().into_owned(),
        db.to_string_lossy().into_owned(),
    )?;
    let local = handle.localdb();
    assert_eq!(local.pkgs().len(), 2);
    let application = local.pkg("application")?;
    let implementation = local.pkg("implementation")?;
    assert_eq!(application.isize(), 1024);
    assert_eq!(implementation.isize(), 2048);
    let native_dependencies: Vec<_> = application
        .depends()
        .into_iter()
        .map(ToString::to_string)
        .collect();
    let native_provides: Vec<_> = implementation
        .provides()
        .into_iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(native_dependencies.join("\n"), dependencies.join("\n"));
    assert_eq!(native_provides.join("\n"), provides.join("\n"));
    eprintln!(
        "[native-size-fixture] application=1024 implementation=2048 depends={} provides={}",
        dependencies.join(","),
        provides.join(",")
    );
    Ok(())
}

#[test]
fn native_size_tree_includes_installed_virtual_provider() -> Result<()> {
    if !common::native_arch_fixture_available() {
        return Ok(());
    }
    let project = common::TestProject::new();
    prepare_native_size_fixture(&project, &["virtual-api>=1"], &["virtual-api=1"])?;
    let before = private_fixture_state(project.pacman_root.path())?;
    let history = project.data_dir.path().join("history.json");
    let history_before = private_fixture_state(&history)?;

    let output = project.run_native_arch_dependency_report(&["size", "--tree", "application"]);

    assert_eq!(private_fixture_state(project.pacman_root.path())?, before);
    assert_eq!(private_fixture_state(&history)?, history_before);
    assert_eq!(output.exit_code, 0, "{}", output_text(&output));
    assert!(
        output.stdout.contains("Dependencies (1 total)"),
        "{}",
        output.stdout
    );
    assert!(
        output.stdout.contains("├─ implementation 2 KB"),
        "{}",
        output.stdout
    );
    assert!(
        output.stdout.contains("Dependencies: 2 KB"),
        "{}",
        output.stdout
    );
    assert!(
        output.stdout.contains("Combined Total: 3 KB"),
        "{}",
        output.stdout
    );
    eprintln!("[native-size-result] virtual-provider dependencies=2KB combined=3KB unchanged=true");
    project.close_checked();
    Ok(())
}

#[test]
fn native_size_tree_counts_one_provider_for_multiple_virtual_requirements() -> Result<()> {
    if !common::native_arch_fixture_available() {
        return Ok(());
    }
    let project = common::TestProject::new();
    prepare_native_size_fixture(
        &project,
        &["virtual-api>=1", "virtual-storage>=1"],
        &["virtual-api=1", "virtual-storage=1"],
    )?;
    let before = private_fixture_state(project.pacman_root.path())?;
    let history = project.data_dir.path().join("history.json");
    let history_before = private_fixture_state(&history)?;

    let output = project.run_native_arch_dependency_report(&["size", "--tree", "application"]);

    assert_eq!(private_fixture_state(project.pacman_root.path())?, before);
    assert_eq!(private_fixture_state(&history)?, history_before);
    assert_eq!(output.exit_code, 0, "{}", output_text(&output));
    assert_eq!(
        output.stdout.matches("├─ implementation 2 KB").count(),
        1,
        "{}",
        output.stdout
    );
    assert!(
        output.stdout.contains("Dependencies (1 total)"),
        "{}",
        output.stdout
    );
    assert!(
        output.stdout.contains("Dependencies: 2 KB"),
        "{}",
        output.stdout
    );
    assert!(
        output.stdout.contains("Combined Total: 3 KB"),
        "{}",
        output.stdout
    );
    eprintln!(
        "[native-size-result] duplicate-capabilities provider-count=1 combined=3KB unchanged=true"
    );
    project.close_checked();
    Ok(())
}

#[test]
fn native_size_tree_respects_virtual_provider_version_constraints() -> Result<()> {
    if !common::native_arch_fixture_available() {
        return Ok(());
    }
    // Run the incompatible case first so RED also observes that refusal control.
    for (provided, dependency_size, total, listed) in [
        ("virtual-api=1", "0 B", "1 KB", false),
        ("virtual-api=2", "2 KB", "3 KB", true),
    ] {
        let project = common::TestProject::new();
        prepare_native_size_fixture(&project, &["virtual-api>=2"], &[provided])?;
        let before = private_fixture_state(project.pacman_root.path())?;
        let history = project.data_dir.path().join("history.json");
        let history_before = private_fixture_state(&history)?;

        let output = project.run_native_arch_dependency_report(&["size", "--tree", "application"]);

        assert_eq!(private_fixture_state(project.pacman_root.path())?, before);
        assert_eq!(private_fixture_state(&history)?, history_before);
        assert_eq!(output.exit_code, 0, "{}", output_text(&output));
        assert_eq!(
            output.stdout.contains("├─ implementation 2 KB"),
            listed,
            "{}",
            output.stdout
        );
        assert!(
            output
                .stdout
                .contains(&format!("Dependencies: {dependency_size}")),
            "{}",
            output.stdout
        );
        assert!(
            output.stdout.contains(&format!("Combined Total: {total}")),
            "{}",
            output.stdout
        );
        eprintln!(
            "[native-size-result] provides={provided} dependencies={dependency_size} combined={total} unchanged=true"
        );
        project.close_checked();
    }
    Ok(())
}

#[test]
fn native_size_tree_preserves_exact_name_dependency_totals() -> Result<()> {
    if !common::native_arch_fixture_available() {
        return Ok(());
    }
    let project = common::TestProject::new();
    prepare_native_size_fixture(&project, &["implementation"], &[])?;
    let before = private_fixture_state(project.pacman_root.path())?;
    let history = project.data_dir.path().join("history.json");
    let history_before = private_fixture_state(&history)?;

    let output = project.run_native_arch_dependency_report(&["size", "--tree", "application"]);

    assert_eq!(private_fixture_state(project.pacman_root.path())?, before);
    assert_eq!(private_fixture_state(&history)?, history_before);
    assert_eq!(output.exit_code, 0, "{}", output_text(&output));
    assert!(
        output.stdout.contains("├─ implementation 2 KB"),
        "{}",
        output.stdout
    );
    assert!(
        output.stdout.contains("Dependencies: 2 KB"),
        "{}",
        output.stdout
    );
    assert!(
        output.stdout.contains("Combined Total: 3 KB"),
        "{}",
        output.stdout
    );
    eprintln!("[native-size-result] exact-name dependencies=2KB combined=3KB unchanged=true");
    project.close_checked();
    Ok(())
}

#[test]
fn native_size_tree_refuses_absent_root_without_changing_private_data() -> Result<()> {
    if !common::native_arch_fixture_available() {
        return Ok(());
    }
    let project = common::TestProject::new();
    prepare_native_size_fixture(&project, &["implementation"], &[])?;
    let before = private_fixture_state(project.pacman_root.path())?;
    let history = project.data_dir.path().join("history.json");
    let history_before = private_fixture_state(&history)?;

    let installed = project.run_native_arch_dependency_report(&["size", "--tree", "application"]);
    assert_eq!(installed.exit_code, 0, "{}", output_text(&installed));
    assert!(
        installed.stdout.contains("Combined Total: 3 KB"),
        "{}",
        installed.stdout
    );
    let absent = project.run_native_arch_dependency_report(&["size", "--tree", "missing-root"]);

    assert_eq!(private_fixture_state(project.pacman_root.path())?, before);
    assert_eq!(private_fixture_state(&history)?, history_before);
    assert_eq!(absent.exit_code, 1, "{}", output_text(&absent));
    assert!(
        absent
            .stderr
            .contains("Package 'missing-root' not installed"),
        "{}",
        output_text(&absent)
    );
    eprintln!("[native-size-result] installed-exit=0 absent-exit=1 unchanged=true");
    project.close_checked();
    Ok(())
}
