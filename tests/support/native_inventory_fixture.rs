//! Private ALPM data and literal output oracles for the five inventory reports.

use crate::common::{CommandResult, TestProject};
use anyhow::Result;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
pub struct Entry {
    directory: bool,
    len: u64,
    modified: std::time::SystemTime,
    readonly: bool,
    bytes: Vec<u8>,
    identity: (u64, u64, u32, u32, u32, i64, i64, i64, i64),
}

// Reads may update atime; content, identity, ownership, permissions, mtime and ctime must not change.
pub fn snapshot(root: &Path) -> Result<BTreeMap<PathBuf, Entry>> {
    fn visit(root: &Path, path: &Path, state: &mut BTreeMap<PathBuf, Entry>) -> Result<()> {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = std::fs::symlink_metadata(path)?;
        anyhow::ensure!(
            metadata.is_dir() || metadata.is_file(),
            "special fixture file: {}",
            path.display()
        );
        state.insert(
            path.strip_prefix(root)?.to_path_buf(),
            Entry {
                directory: metadata.is_dir(),
                len: metadata.len(),
                modified: metadata.modified()?,
                readonly: metadata.permissions().readonly(),
                bytes: if metadata.is_file() {
                    std::fs::read(path)?
                } else {
                    Vec::new()
                },
                identity: (
                    metadata.dev(),
                    metadata.ino(),
                    metadata.mode(),
                    metadata.uid(),
                    metadata.gid(),
                    metadata.mtime(),
                    metadata.mtime_nsec(),
                    metadata.ctime(),
                    metadata.ctime_nsec(),
                ),
            },
        );
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path)? {
                visit(root, &entry?.path(), state)?;
            }
        }
        Ok(())
    }
    let mut state = BTreeMap::new();
    visit(root, root, &mut state)?;
    Ok(state)
}

pub fn scaffold_state(root: &Path) -> Result<Vec<Option<BTreeMap<PathBuf, Entry>>>> {
    [
        "Dockerfile.omg",
        ".dockerignore",
        "Dockerfile.omg.dockerignore",
        ".containerignore",
    ]
    .iter()
    .map(|name| {
        let path = root.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => snapshot(&path).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    })
    .collect()
}

pub fn is_native_row(id: &str) -> bool {
    matches!(id, "why" | "why-reverse" | "size" | "size-tree" | "blame")
}

pub fn check_argv(id: &str, args: &[&str]) {
    let expected: &[&str] = match id {
        "why" => &["why", "pacman"],
        "why-reverse" => &["why", "--reverse", "pacman"],
        "size" => &["size", "--limit", "3"],
        "size-tree" => &["size", "--tree", "pacman"],
        "blame" => &["blame", "pacman"],
        _ => panic!("not a native inventory row: {id}"),
    };
    assert_eq!(
        args, expected,
        "native oracle must bind its literal inventory argv"
    );
}

pub fn prepare(project: &TestProject) -> Result<()> {
    let root = project.pacman_root.path();
    let db = root.join("var/lib/pacman");
    let local = db.join("local");
    let cache = root.join("var/cache/pacman/pkg");
    for path in [&local, &db.join("sync"), &cache, &root.join("etc/pacman.d")] {
        std::fs::create_dir_all(path)?;
    }
    std::fs::write(local.join("ALPM_DB_VERSION"), "9\n")?;
    std::fs::write(root.join("etc/pacman.d/mirrorlist"), "")?;
    std::fs::write(
        root.join("etc/pacman.conf"),
        format!(
            "[options]\nRootDir = {}\nDBPath = {}\nCacheDir = {}\nArchitecture = auto\n",
            root.display(),
            db.display(),
            cache.display()
        ),
    )?;
    for (name, version, reason, size, dependency) in [
        ("pacman", "7.0.0-1", 0, 4_194_304, Some("omg-inventory-dep")),
        ("omg-inventory-dep", "3.0-1", 1, 2_097_152, None),
        ("omg-inventory-tool", "2.0-1", 0, 1_048_576, Some("pacman")),
        ("omg-inventory-orphan", "0.1-1", 1, 524_288, None),
    ] {
        let path = local.join(format!("{name}-{version}"));
        std::fs::create_dir_all(&path)?;
        let mut desc = format!(
            "%NAME%\n{name}\n\n%VERSION%\n{version}\n\n%DESC%\nPrivate inventory fixture\n\n%ARCH%\nx86_64\n\n%SIZE%\n{size}\n\n%REASON%\n{reason}\n\n%LICENSE%\nMIT\n\n"
        );
        if let Some(dep) = dependency {
            write!(desc, "%DEPENDS%\n{dep}\n\n")?;
        }
        std::fs::write(path.join("desc"), desc)?;
    }
    // Only the private cache file's metadata is read; this is not an installable archive.
    std::fs::write(cache.join("owned-cache.pkg.tar.zst"), [b'x'; 128])?;
    std::fs::write(project.data_dir.path().join("history.json"), "[]\n")?;
    Ok(())
}

pub fn check_alpm(project: &TestProject) -> Result<()> {
    let root = project.pacman_root.path();
    let handle = alpm::Alpm::new(
        root.to_string_lossy().into_owned(),
        root.join("var/lib/pacman").to_string_lossy().into_owned(),
    )?;
    let local = handle.localdb();
    assert_eq!(local.pkgs().len(), 4);
    assert_eq!(
        local.pkgs().into_iter().map(|pkg| pkg.isize()).sum::<i64>(),
        7_864_320
    );
    for (name, version, reason, size, deps, required) in [
        (
            "pacman",
            "7.0.0-1",
            alpm::PackageReason::Explicit,
            4_194_304,
            vec!["omg-inventory-dep"],
            vec!["omg-inventory-tool"],
        ),
        (
            "omg-inventory-dep",
            "3.0-1",
            alpm::PackageReason::Depend,
            2_097_152,
            vec![],
            vec!["pacman"],
        ),
        (
            "omg-inventory-tool",
            "2.0-1",
            alpm::PackageReason::Explicit,
            1_048_576,
            vec!["pacman"],
            vec![],
        ),
        (
            "omg-inventory-orphan",
            "0.1-1",
            alpm::PackageReason::Depend,
            524_288,
            vec![],
            vec![],
        ),
    ] {
        let pkg = local.pkg(name)?;
        assert_eq!(pkg.version().as_str(), version);
        assert_eq!(pkg.reason(), reason);
        assert_eq!(pkg.isize(), size);
        let actual_deps: Vec<_> = pkg
            .depends()
            .into_iter()
            .map(|dep| dep.name().to_string())
            .collect();
        let actual_required: Vec<_> = pkg.required_by().into_iter().collect();
        assert_eq!(actual_deps, deps, "literal dependencies for {name}");
        assert_eq!(
            actual_required, required,
            "literal reverse dependencies for {name}"
        );
    }
    Ok(())
}

pub fn check_output(id: &str, output: &CommandResult, issues: &mut Vec<String>) {
    let expected: &[&str] = match id {
        "why" => &[
            "Package Analysis",
            "Name: pacman",
            "Version: 7.0.0-1",
            "Reason: explicitly installed",
            "omg-inventory-dep: ✓ installed",
            "Safe to remove: NO - 1 packages depend on it",
        ],
        "why-reverse" => &[
            "Reverse Dependencies",
            "Dependents (1 total)",
            "omg-inventory-tool: explicit",
            "Safe to remove: NO (would break 1 dependents: 1 explicit, 0 dependencies)",
        ],
        "blame" => &[
            "Package History",
            "Name: pacman",
            "Version: 7.0.0-1",
            "Install Reason: explicit (user installed)",
            "No OMG transaction history found for this package",
            "Required by (1 packages)",
            "omg-inventory-tool",
        ],
        "size" => &[
            "Disk Usage Analysis",
            "Top 3 Packages",
            "Total Disk Usage: 7.5 MB",
            "Number of Packages: 4",
            "Cache: 128 B (run 'omg clean --cache' to clear)",
        ],
        "size-tree" => &[
            "Package Size Tree",
            "pacman: 4.0 MB",
            "Type: installed package",
            "Dependencies (1 total)",
            "├─ omg-inventory-dep 2.0 MB",
            "Combined Total: 6.0 MB",
            "Package Size: 4.0 MB",
            "Dependencies: 2.0 MB",
        ],
        _ => panic!("not a native inventory row: {id}"),
    };
    for literal in expected {
        if !output.stdout.contains(literal) {
            issues.push(format!("native report omitted {literal:?}"));
        }
    }
    if output.stdout.lines().count() > 120 {
        issues.push("native fixture report exceeded 120 lines".into());
    }
    if output.stdout.contains("omg-inventory-orphan") {
        issues.push(
            "native report leaked an unrelated orphan outside the requested limit/tree".into(),
        );
    }
    if id == "size" {
        let listed: Vec<_> = output
            .stdout
            .lines()
            .filter(|line| {
                line.contains("pacman")
                    || line.contains("omg-inventory-dep")
                    || line.contains("omg-inventory-tool")
            })
            .collect();
        if listed.len() != 3
            || !listed[0].contains("pacman")
            || !listed[0].contains("4.0 MB")
            || !listed[1].contains("omg-inventory-dep")
            || !listed[1].contains("2.0 MB")
            || !listed[2].contains("omg-inventory-tool")
            || !listed[2].contains("1.0 MB")
        {
            issues.push(
                "top-three packages did not retain literal order, names and installed sizes".into(),
            );
        }
    }
}
