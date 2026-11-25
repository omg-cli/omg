use std::fs;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};

use crate::core::privilege::system_command;

pub(super) const HOST_SQLITE: &str = "/var/lib/rpm/rpmdb.sqlite";

const CONFIG_DROP_INS: &[&str] = &["/etc/dnf/libdnf5.conf.d", "/usr/share/dnf5/libdnf.conf.d"];
const PLUGIN_CONFIGS: &[&str] = &[
    "/etc/dnf/libdnf5-plugins",
    "/usr/share/dnf5/libdnf5-plugins",
];

#[derive(Debug, PartialEq, Eq)]
pub(super) struct RpmDatabase {
    pub(super) root: PathBuf,
    pub(super) sqlite: PathBuf,
}

impl RpmDatabase {
    pub(super) fn detect(host_sqlite: &Path) -> Result<Self> {
        #[cfg(test)]
        if host_sqlite != Path::new(HOST_SQLITE) {
            return Ok(Self {
                root: PathBuf::from("/"),
                sqlite: host_sqlite.to_owned(),
            });
        }
        let root = if default_installroot() {
            PathBuf::from("/")
        } else {
            read_installroot()?
        };
        let sqlite = if root == Path::new("/") && !has_custom_rpm_configuration() {
            host_sqlite.to_owned()
        } else {
            let database = rpm_database_directory()?;
            scoped_database_path(&root, &database)?
        };
        Ok(Self { root, sqlite })
    }
}

fn default_installroot() -> bool {
    let mut candidates = CONFIG_DROP_INS.iter().map(Path::new);
    let mut plugin_configs = PLUGIN_CONFIGS.iter().map(Path::new);
    !can_configure_root(Path::new("/etc/dnf/dnf.conf"))
        && candidates.all(|dir| {
            !directory_has(dir, |path| {
                path.extension().is_some_and(|ext| ext == "conf") && can_configure_root(path)
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

fn can_configure_root(path: &Path) -> bool {
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
        matches!(
            key.trim(),
            "installroot"
                | "config_file_path"
                | "pluginpath"
                | "pluginconfpath"
                | "plugin_conf_dir"
        )
    })
}

fn read_installroot() -> Result<PathBuf> {
    let output = system_command("dnf")?
        .args(["--cacheonly", "--dump-main-config"])
        .stdin(std::process::Stdio::null())
        .output()
        .context("Could not resolve the configured DNF installroot")?;
    anyhow::ensure!(
        output.status.success(),
        "Could not resolve the configured DNF installroot: {}",
        output.status
    );
    let config = std::str::from_utf8(&output.stdout).context("DNF configuration is not UTF-8")?;
    parse_installroot(config)
}

fn parse_installroot(config: &str) -> Result<PathBuf> {
    let mut roots = config
        .lines()
        .filter_map(|line| line.strip_prefix("installroot = "));
    let value = roots.next().context("DNF did not report an installroot")?;
    anyhow::ensure!(roots.next().is_none(), "DNF reported multiple installroots");
    let root = PathBuf::from(value);
    anyhow::ensure!(
        root.is_absolute() && !value.contains(['\0', '\r']),
        "DNF installroot must be an absolute path"
    );
    Ok(root)
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
    let directory = directory.strip_prefix("/")?;
    anyhow::ensure!(
        directory
            .components()
            .all(|part| !matches!(part, std::path::Component::ParentDir)),
        "RPM database directory traverses a parent directory"
    );
    let database = root.join(directory).join("rpmdb.sqlite");
    if root != Path::new("/") {
        let canonical_root = root
            .canonicalize()
            .context("Cannot resolve DNF installroot")?;
        // Check the database file and other existing ancestors when the root
        // has been initialized, including symlinks resolving outside the root.
        for ancestor in database.ancestors() {
            match ancestor.canonicalize() {
                Ok(resolved) => {
                    anyhow::ensure!(
                        resolved.starts_with(&canonical_root),
                        "RPM database path escapes the DNF installroot"
                    );
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("Cannot resolve RPM database directory"),
            }
        }
    }
    Ok(database)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_root_scan_detects_configuration_overrides() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let config = fixture.path().join("dnf.conf");
        assert!(!can_configure_root(&config));
        fs::write(
            &config,
            "[main]\n# installroot = /imaginary\nreposdir=/repo\n",
        )?;
        assert!(!can_configure_root(&config));
        for option in [
            "installroot",
            "config_file_path",
            "pluginpath",
            "plugin_conf_dir",
        ] {
            fs::write(&config, format!("[main]\n  {option} = /override\n"))?;
            assert!(can_configure_root(&config), "missing {option}");
        }
        fs::write(&config, [0xff])?;
        assert!(can_configure_root(&config));
        Ok(())
    }

    #[test]
    fn installed_root_requires_exactly_one_absolute_native_path() -> Result<()> {
        assert_eq!(
            parse_installroot("other = ignored\ninstallroot = /some root\n")?,
            Path::new("/some root")
        );
        for invalid in [
            "installroot=/missing spaces",
            "installroot = relative",
            "installroot = /valid\ninstallroot = /other",
        ] {
            assert!(parse_installroot(invalid).is_err(), "admitted {invalid}");
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
