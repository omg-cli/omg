use std::fs;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};

use crate::core::privilege::system_command;

pub(super) const HOST_SQLITE: &str = "/var/lib/rpm/rpmdb.sqlite";
const SYSTEM_STATE_DIR: &str = "/usr/lib/sysimage/libdnf5";

pub(super) const CONFIG_DROP_INS: &[&str] =
    &["/etc/dnf/libdnf5.conf.d", "/usr/share/dnf5/libdnf.conf.d"];
pub(super) const PLUGIN_CONFIGS: &[&str] = &[
    "/etc/dnf/libdnf5-plugins",
    "/usr/share/dnf5/libdnf5-plugins",
    "/usr/share/dnf5/libdnf.plugins.conf.d",
];

#[derive(Debug, PartialEq, Eq)]
pub(super) struct RpmDatabase {
    pub(super) root: PathBuf,
    pub(super) sqlite: PathBuf,
}

impl RpmDatabase {
    pub(super) fn detect(host_sqlite: &Path) -> Result<Self> {
        Self::resolve(host_sqlite, false).map(|(database, _)| database)
    }

    pub(super) fn detect_with_state_dir(host_sqlite: &Path) -> Result<(Self, PathBuf)> {
        let (database, config) = Self::resolve(host_sqlite, true)?;
        let directory = config.as_deref().map_or_else(
            || Ok(PathBuf::from(SYSTEM_STATE_DIR)),
            |config| parse_absolute_setting(config, "system_state_dir"),
        )?;
        let path = rooted_path(&database.root, &directory)?;
        ensure_contained_path(&database.root, &path)?;
        Ok((database, path))
    }

    fn resolve(host_sqlite: &Path, include_state_dir: bool) -> Result<(Self, Option<String>)> {
        #[cfg(test)]
        if host_sqlite != Path::new(HOST_SQLITE) {
            return Ok((
                Self {
                    root: PathBuf::from("/"),
                    sqlite: host_sqlite.to_owned(),
                },
                None,
            ));
        }
        let config = if uses_default_paths(include_state_dir) {
            None
        } else {
            Some(read_path_settings()?)
        };
        let root = config.as_deref().map_or_else(
            || Ok(PathBuf::from("/")),
            |config| parse_absolute_setting(config, "installroot"),
        )?;
        let sqlite = if root == Path::new("/") && !has_custom_rpm_configuration() {
            host_sqlite.to_owned()
        } else {
            let database = rpm_database_directory()?;
            scoped_database_path(&root, &database)?
        };
        Ok((Self { root, sqlite }, config))
    }
}

fn uses_default_paths(include_state_dir: bool) -> bool {
    let mut candidates = CONFIG_DROP_INS.iter().map(Path::new);
    let mut plugin_configs = PLUGIN_CONFIGS.iter().map(Path::new);
    !can_configure_paths(Path::new("/etc/dnf/dnf.conf"), include_state_dir)
        && candidates.all(|dir| {
            !directory_has(dir, |path| {
                path.extension().is_some_and(|ext| ext == "conf")
                    && can_configure_paths(path, include_state_dir)
            })
        })
        && plugin_configs.all(|dir| {
            !directory_has(dir, |path| {
                path.extension().is_some_and(|ext| ext == "conf")
            })
        })
}

fn directory_has(dir: &Path, matches: impl Fn(&Path) -> bool) -> bool {
    match fs::read_dir(dir) {
        Ok(mut entries) => entries.any(|entry| entry.map_or(true, |entry| matches(&entry.path()))),
        Err(error) => error.kind() != io::ErrorKind::NotFound,
    }
}

fn can_configure_paths(path: &Path, include_state_dir: bool) -> bool {
    const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => return error.kind() != io::ErrorKind::NotFound,
    };
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
        return true;
    }
    let mut contents = String::new();
    let bytes = fs::File::open(path).and_then(|file| {
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_string(&mut contents)
    });
    if !matches!(bytes, Ok(bytes) if bytes as u64 <= MAX_CONFIG_BYTES) {
        return true;
    }
    contents.lines().any(|line| {
        let Some((key, _)) = line.split_once('=') else {
            return false;
        };
        let key = key.trim();
        matches!(
            key,
            "installroot"
                | "config_file_path"
                | "pluginpath"
                | "pluginconfpath"
                | "plugin_conf_dir"
        ) || (include_state_dir && key == "system_state_dir")
    })
}

pub(super) fn read_path_settings() -> Result<String> {
    read_dnf_settings(&["--cacheonly"])
}

pub(super) fn read_dnf_settings(options: &[&str]) -> Result<String> {
    let output = system_command("dnf")?
        .env("LC_ALL", "C")
        .arg("--dump-main-config")
        .args(options)
        .stdin(std::process::Stdio::null())
        .output()
        .context("Could not read the effective DNF configuration")?;
    anyhow::ensure!(
        output.status.success(),
        "Could not read the effective DNF configuration: {}",
        output.status
    );
    String::from_utf8(output.stdout).context("DNF configuration is not UTF-8")
}

pub(super) fn reported_setting<'a>(config: &'a str, key: &str) -> Result<&'a str> {
    let mut values = config
        .lines()
        .filter_map(|line| line.strip_prefix(key)?.strip_prefix(" = "));
    let value = values
        .next()
        .with_context(|| format!("DNF did not report {key}"))?;
    anyhow::ensure!(
        values.next().is_none(),
        "DNF reported multiple values for {key}"
    );
    Ok(value)
}

pub(super) fn parse_absolute_setting(config: &str, key: &str) -> Result<PathBuf> {
    let value = reported_setting(config, key)?;
    let path = PathBuf::from(value);
    anyhow::ensure!(
        path.is_absolute() && !value.contains(['\0', '\r']),
        "DNF {key} must be an absolute path"
    );
    Ok(path)
}

fn has_custom_rpm_configuration() -> bool {
    directory_has(Path::new("/etc/rpm"), |_| true)
        || std::env::var_os("HOME").is_some_and(|home| {
            let home = Path::new(&home);
            [".rpmmacros", ".config/rpm/macros"]
                .into_iter()
                .any(|suffix| match fs::metadata(home.join(suffix)) {
                    Ok(_) => true,
                    Err(error) => error.kind() != io::ErrorKind::NotFound,
                })
        })
}

fn rpm_database_directory() -> Result<PathBuf> {
    let output = system_command("rpm")?
        .args(["--eval", "%{_dbpath}"])
        .stdin(std::process::Stdio::null())
        .output()
        .context("Could not identify the active RPM database directory")?;
    anyhow::ensure!(
        output.status.success(),
        "Could not identify the active RPM database directory: {}",
        output.status
    );
    let result =
        std::str::from_utf8(&output.stdout).context("RPM database directory is not UTF-8")?;
    let directory = result.strip_suffix('\n').unwrap_or(result);
    anyhow::ensure!(
        directory.starts_with('/') && !directory.contains(['\0', '\n', '\r']),
        "RPM database directory must be an absolute path"
    );
    Ok(PathBuf::from(directory))
}

fn scoped_database_path(root: &Path, directory: &Path) -> Result<PathBuf> {
    let database = rooted_path(root, directory)?.join("rpmdb.sqlite");
    ensure_contained_path(root, &database)?;
    Ok(database)
}

pub(super) fn rooted_path(root: &Path, path: &Path) -> Result<PathBuf> {
    let relative = path.strip_prefix("/")?;
    anyhow::ensure!(
        relative
            .components()
            .all(|part| !matches!(part, std::path::Component::ParentDir)),
        "DNF path traverses a parent directory"
    );
    Ok(root.join(relative))
}

fn ensure_contained_path(root: &Path, path: &Path) -> Result<()> {
    if root == Path::new("/") {
        return Ok(());
    }
    let canonical_root = root
        .canonicalize()
        .context("Cannot resolve DNF installroot")?;
    // Check the file and the closest existing ancestor for symlink escapes.
    for ancestor in path.ancestors() {
        match ancestor.canonicalize() {
            Ok(resolved) => {
                anyhow::ensure!(
                    resolved.starts_with(&canonical_root),
                    "DNF path escapes the DNF installroot"
                );
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("Cannot resolve DNF path"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_root_scan_detects_configuration_overrides() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let config = fixture.path().join("dnf.conf");
        assert!(!can_configure_paths(&config, false));
        fs::write(
            &config,
            "[main]\n# installroot = /imaginary\nreposdir=/repo\n",
        )?;
        assert!(!can_configure_paths(&config, false));
        for option in [
            "installroot",
            "config_file_path",
            "pluginpath",
            "plugin_conf_dir",
        ] {
            fs::write(&config, format!("[main]\n  {option} = /override\n"))?;
            assert!(can_configure_paths(&config, false), "missing {option}");
        }
        fs::write(&config, "[main]\nsystem_state_dir=/state\n")?;
        assert!(!can_configure_paths(&config, false));
        assert!(can_configure_paths(&config, true));
        fs::write(&config, [0xff])?;
        assert!(can_configure_paths(&config, false));
        Ok(())
    }

    #[test]
    fn installed_root_requires_exactly_one_absolute_native_path() -> Result<()> {
        assert_eq!(
            parse_absolute_setting("other = ignored\ninstallroot = /some root\n", "installroot")?,
            Path::new("/some root")
        );
        for invalid in [
            "installroot=/missing spaces",
            "installroot = relative",
            "installroot = /valid\ninstallroot = /other",
        ] {
            assert!(
                parse_absolute_setting(invalid, "installroot").is_err(),
                "admitted {invalid}"
            );
        }
        Ok(())
    }

    #[test]
    fn alternate_root_refuses_paths_outside_its_rpm_database() -> Result<()> {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let db = Path::new("/var/lib/rpm");
        let inside = root.path().join("var/lib/rpm");
        fs::create_dir_all(&inside)?;
        assert_eq!(
            scoped_database_path(root.path(), db)?,
            inside.join("rpmdb.sqlite")
        );

        let external_file = outside.path().join("external.sqlite");
        fs::File::create(&external_file)?;
        symlink(&external_file, inside.join("rpmdb.sqlite"))?;
        assert!(scoped_database_path(root.path(), db).is_err());
        symlink(outside.path(), root.path().join("elsewhere"))?;
        assert!(scoped_database_path(root.path(), Path::new("/elsewhere")).is_err());
        assert!(scoped_database_path(root.path(), Path::new("/../../outside")).is_err());
        Ok(())
    }
}
