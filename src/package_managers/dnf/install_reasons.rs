use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use anyhow::{Context as _, Result, ensure};
use nix::fcntl::{FcntlArg, fcntl};
use nix::libc;
use serde::Deserialize;

use super::rpm_database::{parse_absolute_setting, read_path_settings, rooted_path};
use super::{DnfPackageManager, RpmDatabase};

const MAX_STATE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Deserialize)]
struct Package {
    reason: Reason,
}

#[derive(Deserialize)]
enum Reason {
    None,
    Dependency,
    User,
    Clean,
    #[serde(rename = "Weak Dependency")]
    WeakDependency,
    Group,
    #[serde(rename = "External User")]
    ExternalUser,
}

#[derive(Deserialize)]
struct Group {
    #[serde(rename = "userinstalled")]
    _userinstalled: bool,
    #[serde(default)]
    packages: Vec<String>,
    #[serde(default, rename = "package_types")]
    _package_types: Vec<GroupPackageType>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum GroupPackageType {
    Conditional,
    Default,
    Mandatory,
    Optional,
}

#[derive(Deserialize)]
struct Nevra {
    #[serde(rename = "from_repo")]
    _from_repo: Option<String>,
}

#[derive(Deserialize)]
struct Environment {
    #[serde(default, rename = "groups")]
    _groups: Vec<String>,
}

#[derive(Deserialize)]
struct System {
    #[serde(rename = "rpmdb_cookie")]
    _rpmdb_cookie: String,
}

pub(super) fn explicit_names(location: &RpmDatabase, state: &Path) -> Result<HashSet<String>> {
    installed_and_explicit(location, state).map(|(_, explicit)| explicit)
}

pub(super) fn installed_and_explicit(
    location: &RpmDatabase,
    state: &Path,
) -> Result<(usize, HashSet<String>)> {
    let _system_lock = lock_system_state(state)?;
    for entry in fs::read_dir(state)? {
        ensure!(
            entry?.path().extension().is_none_or(|ext| ext != "new"),
            "DNF system state has an unfinished transaction"
        );
    }

    let nevras: HashMap<String, Nevra> = read_table(state, "nevras")?;
    // DNF5 imports legacy reasons when its installed NEVRA state is empty.
    if nevras.is_empty() {
        require_no_legacy_history(location)?;
    }
    let packages: HashMap<String, Package> = read_table(state, "packages")?;
    let groups: HashMap<String, Group> = read_table(state, "groups")?;
    let _: HashMap<String, Environment> = read_table(state, "environments")?;
    let _: System = read_table(state, "system")?;
    let modules: toml::Table = read_table(state, "modules")?;
    ensure!(
        modules.is_empty(),
        "DNF module state needs native resolution"
    );
    let members: HashSet<_> = groups
        .into_values()
        .flat_map(|group| group.packages)
        .collect();

    let installed = DnfPackageManager::read_rpm_sqlite(&location.sqlite)?;
    let total = installed.len();
    let mut explicit = HashSet::new();
    for package in installed {
        if package.name == "gpg-pubkey" && package.architecture.is_empty() {
            continue;
        }
        ensure!(
            !package.architecture.is_empty()
                && !package
                    .name
                    .chars()
                    .any(|ch| ch.is_control() || ch == '\u{fffd}')
                && !package
                    .architecture
                    .chars()
                    .any(|ch| ch.is_control() || ch == '\u{fffd}'),
            "RPM package has an unsupported identity"
        );
        if packages
            .get(&format!("{}.{}", package.name, package.architecture))
            .is_some_and(|entry| {
                matches!(entry.reason, Reason::Dependency | Reason::WeakDependency)
            })
        {
            // Dotted names can require DNF's version-specific group lookup.
            let prefix = package.name.split('.').next().unwrap_or(&package.name);
            let in_group = members.contains(&package.name);
            ensure!(
                in_group == members.contains(prefix),
                "DNF group membership for a dotted package name needs native resolution"
            );
            if !in_group {
                continue;
            }
        }
        explicit.insert(package.name);
    }
    Ok((total, explicit))
}

fn require_no_legacy_history(location: &RpmDatabase) -> Result<()> {
    let settings = read_path_settings()?;
    ensure!(
        parse_absolute_setting(&settings, "installroot")? == location.root,
        "DNF installroot changed while reading install reasons"
    );
    let persist = parse_absolute_setting(&settings, "persistdir")?;
    let history = rooted_path(&location.root, &persist)?.join("history.sqlite");
    match fs::symlink_metadata(history) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("Cannot inspect legacy DNF history"),
        Ok(_) => anyhow::bail!("Legacy DNF history needs native resolution"),
    }
}

fn lock_system_state(state: &Path) -> Result<File> {
    let file = open_regular(&state.join("system-repo.lock"))?;
    // OFD record locks conflict with DNF5's POSIX record lock and remain
    // held until this descriptor closes, even with concurrent daemon readers.
    let lock = libc::flock {
        l_type: libc::F_RDLCK.try_into()?,
        l_whence: libc::SEEK_SET.try_into()?,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };
    fcntl(&file, FcntlArg::F_OFD_SETLK(&lock)).context("Cannot lock the DNF system repository")?;
    Ok(file)
}

fn open_regular(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("Cannot open DNF state input {}", path.display()))?;
    ensure!(
        file.metadata()?.is_file(),
        "DNF state input must be a regular file: {}",
        path.display()
    );
    Ok(file)
}

pub(super) fn read_table<T: serde::de::DeserializeOwned>(state: &Path, key: &str) -> Result<T> {
    let path = state.join(format!("{key}.toml"));
    let file = open_regular(&path)?;
    let mut text = String::new();
    let bytes = file.take(MAX_STATE_BYTES + 1).read_to_string(&mut text)?;
    ensure!(
        bytes as u64 <= MAX_STATE_BYTES,
        "DNF state file exceeds the size limit"
    );
    let mut document: toml::Table = toml::from_str(&text)
        .with_context(|| format!("Cannot parse DNF state file {}", path.display()))?;
    ensure!(
        document.get("version").and_then(toml::Value::as_str) == Some("1.0"),
        "Unsupported DNF state version in {}",
        path.display()
    );
    document
        .remove(key)
        .with_context(|| format!("Missing DNF state table {key}"))?
        .try_into()
        .with_context(|| format!("Unsupported DNF state table {key}"))
}
