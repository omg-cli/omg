//! Local DNF inputs used to validate a published package search index.

use super::FileIdentity;
use crate::package_managers::InstalledCatalogObservation;
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAIN_CONFIG: &str = "/etc/dnf/dnf.conf";
const MAX_INPUTS: usize = 16_384;

pub(super) type Stamps = BTreeMap<PathBuf, FileIdentity>;

#[derive(serde::Deserialize, PartialEq, Eq)]
pub(super) struct RepositoryMetadata {
    pub(super) id: String,
    pub(super) available_pkgs: u64,
    timestamp: i64,
    metadata_expire: i64,
    revision: String,
}

impl RepositoryMetadata {
    pub(super) fn refresh_at(repositories: &[Self]) -> Result<Option<SystemTime>> {
        let mut deadline = None;
        for repo in repositories {
            if repo.timestamp < 0 {
                return Ok(Some(UNIX_EPOCH));
            }
            if repo.metadata_expire == -1 {
                continue;
            }
            let expiration = u64::try_from(repo.metadata_expire)
                .context("Invalid DNF metadata expiration interval")?;
            let timestamp =
                u64::try_from(repo.timestamp).context("Invalid DNF metadata timestamp")?;
            let refresh = UNIX_EPOCH
                .checked_add(Duration::from_secs(timestamp.saturating_add(expiration)))
                .context("DNF metadata expiration is outside the system clock range")?;
            deadline = Some(deadline.map_or(refresh, |current: SystemTime| current.min(refresh)));
        }
        Ok(deadline)
    }
}

pub(super) struct RepositoryPaths {
    files: BTreeSet<PathBuf>,
    configuration: BTreeSet<PathBuf>,
    caches: BTreeSet<PathBuf>,
    pub(super) cache_only: bool,
}

impl Default for RepositoryPaths {
    fn default() -> Self {
        Self {
            files: [
                MAIN_CONFIG,
                "/etc/os-release",
                "/usr/lib/os-release",
                "/etc/dnf/versionlock.toml",
            ]
            .into_iter()
            .map(PathBuf::from)
            .collect(),
            configuration: [
                "/etc/dnf/libdnf5.conf.d",
                "/usr/share/dnf5/libdnf.conf.d",
                "/etc/dnf/repos.override.d",
                "/usr/share/dnf5/repos.override.d",
            ]
            .into_iter()
            .map(PathBuf::from)
            .collect(),
            caches: BTreeSet::new(),
            cache_only: false,
        }
    }
}

impl RepositoryPaths {
    pub(super) fn add_effective_paths(&mut self, config: &str) -> Result<()> {
        let option = |key: &str| {
            let mut values = config.lines().filter_map(|line| {
                let (name, value) = line.split_once(" = ")?;
                (name == key).then_some(value.trim())
            });
            let value = values.next();
            ensure!(values.next().is_none(), "Duplicate DNF option {key}");
            Ok::<_, anyhow::Error>(value)
        };
        ensure!(
            option("config_file_path")? == Some(MAIN_CONFIG) && option("installroot")? == Some("/"),
            "Unsupported DNF main configuration or install root"
        );
        self.cache_only = match option("cacheonly")? {
            Some("all" | "metadata") => true,
            None | Some("none") => false,
            Some(_) => anyhow::bail!("Unknown DNF cache-only mode"),
        };
        for key in ["cachedir", "system_cachedir"] {
            let value = option(key)?.with_context(|| format!("Missing DNF option {key}"))?;
            let path = PathBuf::from(value);
            ensure!(
                path.is_absolute(),
                "DNF option {key} must be an absolute path"
            );
            self.caches.insert(path);
        }
        for key in [
            "reposdir",
            "varsdir",
            "plugin_conf_dir",
            "pluginconfpath",
            "pluginpath",
        ] {
            let value = option(key)?;
            ensure!(
                value.is_some() || !matches!(key, "reposdir" | "varsdir"),
                "Missing DNF option {key}"
            );
            for value in value
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|path| !path.is_empty())
            {
                let path = PathBuf::from(value);
                ensure!(
                    path.is_absolute(),
                    "DNF option {key} must contain absolute paths"
                );
                self.configuration.insert(path);
            }
        }
        Ok(())
    }

    fn configuration_snapshot(&self) -> Result<Snapshot> {
        let mut snapshot = Snapshot::default();
        for path in &self.files {
            snapshot.file(path.clone())?;
        }
        for path in &self.configuration {
            snapshot.directory(path, Snapshot::file)?;
        }
        Ok(snapshot)
    }

    pub(super) fn configuration_stamps(&self) -> Result<Stamps> {
        Ok(self.configuration_snapshot()?.stamps)
    }

    pub(super) fn snapshot(&self) -> Result<Stamps> {
        let mut snapshot = self.configuration_snapshot()?;
        for path in &self.caches {
            snapshot.directory(path, |snapshot, repo| {
                snapshot.directory(&repo.join("repodata"), Snapshot::file)?;
                snapshot.file(repo.join("attrs/expired"))
            })?;
        }
        Ok(snapshot.stamps)
    }
}

#[derive(Default)]
struct Snapshot {
    stamps: Stamps,
    visited: usize,
}

impl Snapshot {
    fn file(&mut self, path: PathBuf) -> Result<()> {
        match fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() => {
                self.stamps
                    .insert(path, FileIdentity::from_metadata(&metadata));
            }
            Ok(_) => {}
            Err(error)
                if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {}
            Err(error) => {
                return Err(error).with_context(|| format!("Cannot observe {}", path.display()));
            }
        }
        Ok(())
    }

    fn directory(
        &mut self,
        path: &Path,
        mut visit: impl FnMut(&mut Self, PathBuf) -> Result<()>,
    ) -> Result<()> {
        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error)
                if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) =>
            {
                return Ok(());
            }
            Err(error) => {
                return Err(error).with_context(|| format!("Cannot observe {}", path.display()));
            }
        };
        for entry in entries {
            self.visited += 1;
            ensure!(
                self.visited <= MAX_INPUTS,
                "DNF catalog observation exceeds its input limit"
            );
            visit(self, entry?.path())?;
        }
        Ok(())
    }
}

pub(super) struct PackageCatalog {
    installed: Arc<dyn InstalledCatalogObservation>,
    paths: RepositoryPaths,
    repositories: Stamps,
    refresh_at: Option<SystemTime>,
}

impl PackageCatalog {
    pub(super) fn new(
        installed: Arc<dyn InstalledCatalogObservation>,
        paths: RepositoryPaths,
        refresh_at: Option<SystemTime>,
    ) -> Result<Self> {
        let repositories = paths.snapshot()?;
        Ok(Self {
            installed,
            paths,
            repositories,
            refresh_at,
        })
    }

    pub(super) fn configuration_matches(&self, configuration: &Stamps) -> Result<bool> {
        Ok(self.paths.configuration_stamps()? == *configuration)
    }
}

impl InstalledCatalogObservation for PackageCatalog {
    fn is_current(&self) -> Result<bool> {
        Ok(self.installed.is_current()? && self.paths.snapshot()? == self.repositories)
    }

    fn search_index_expired(&self) -> bool {
        self.refresh_at
            .is_some_and(|deadline| SystemTime::now() >= deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Installed;

    impl InstalledCatalogObservation for Installed {
        fn is_current(&self) -> Result<bool> {
            Ok(true)
        }
    }

    #[test]
    fn timed_search_expiry_keeps_the_observed_generation_valid() -> Result<()> {
        let repositories: Vec<RepositoryMetadata> = serde_json::from_str(
            r#"[
                {"id":"no-expiry","timestamp":1,"metadata_expire":-1,"available_pkgs":1,"revision":"r"},
                {"id":"short","timestamp":100,"metadata_expire":5,"available_pkgs":1,"revision":"s"},
                {"id":"long","timestamp":90,"metadata_expire":60,"available_pkgs":1,"revision":"t"}
            ]"#,
        )?;
        let refresh_at = RepositoryMetadata::refresh_at(&repositories)?;
        assert_eq!(refresh_at, Some(UNIX_EPOCH + Duration::from_secs(105)));
        assert_eq!(RepositoryMetadata::refresh_at(&repositories[..1])?, None);
        let paths = RepositoryPaths {
            files: BTreeSet::new(),
            configuration: BTreeSet::new(),
            caches: BTreeSet::new(),
            cache_only: false,
        };
        let observation = PackageCatalog::new(Arc::new(Installed), paths, refresh_at)?;
        assert!(observation.search_index_expired());
        assert!(observation.is_current()?);
        Ok(())
    }

    #[test]
    fn observes_custom_repository_scope_without_tracking_package_downloads() -> Result<()> {
        let root = tempfile::tempdir()?;
        let main = root.path().join("dnf.conf");
        let repo = root.path().join("custom repos");
        let vars = root.path().join("vars");
        let cache = root.path().join("cache");
        let system = root.path().join("system cache");
        let data = cache.join("fixture-feed/repodata");
        let packages = cache.join("fixture-feed/packages");
        let system_data = system.join("fixture-feed/repodata");
        for path in [&repo, &vars, &data, &packages, &system_data] {
            fs::create_dir_all(path)?;
        }
        fs::write(&main, b"enabled=1")?;
        fs::write(data.join("repomd.xml"), b"first metadata revision")?;
        let paths = || -> Result<RepositoryPaths> {
            let mut paths = RepositoryPaths {
                files: BTreeSet::from([main.clone()]),
                configuration: BTreeSet::new(),
                caches: BTreeSet::new(),
                cache_only: false,
            };
            paths.add_effective_paths(&format!(
                "config_file_path = {MAIN_CONFIG}\ninstallroot = /\nreposdir = {}\nvarsdir = {}\ncachedir = {}\nsystem_cachedir = {}\n",
                repo.display(),
                vars.display(),
                cache.display(),
                system.display(),
            ))?;
            Ok(paths)
        };
        let current = || PackageCatalog::new(Arc::new(Installed), paths()?, None);

        let baseline = current()?;
        fs::write(packages.join("downloaded.rpm"), b"inert")?;
        assert!(baseline.is_current()?);
        fs::write(&main, b"enabled=0")?;
        assert!(!baseline.is_current()?);

        let baseline = current()?;
        fs::write(repo.join("custom.repo"), b"[fixture-feed]")?;
        assert!(!baseline.is_current()?);
        let baseline = current()?;
        fs::write(vars.join("releasever"), b"44")?;
        assert!(!baseline.is_current()?);

        let baseline = current()?;
        fs::write(data.join("next.xml"), b"replacement revision")?;
        fs::rename(data.join("next.xml"), data.join("repomd.xml"))?;
        assert!(!baseline.is_current()?);
        let baseline = current()?;
        fs::write(system_data.join("repomd.xml"), b"system metadata revision")?;
        assert!(!baseline.is_current()?);
        Ok(())
    }
}
