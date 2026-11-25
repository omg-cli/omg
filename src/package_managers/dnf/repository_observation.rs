//! DNF's repository configuration and cached manifests used by the daemon index.

use std::fs;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use super::RpmFileIdentity;
use super::rpm_database::{
    CONFIG_DROP_INS, PLUGIN_CONFIGS, parse_absolute_setting, read_dnf_settings, reported_setting,
    rooted_path,
};

#[derive(Clone, Default, PartialEq, Eq)]
struct RepositoryPaths {
    files: Vec<PathBuf>,
    directories: Vec<(PathBuf, Option<&'static str>)>,
    caches: Vec<PathBuf>,
    observe_expiration: bool,
}

pub(super) struct RepositoryObservation {
    paths: RepositoryPaths,
    fingerprint: [u8; 32],
}

impl RepositoryObservation {
    pub(super) fn capture(root: &Path) -> Result<Self> {
        let mut paths = ResolvedRepositoryPaths::capture(root)?.paths;
        // Package searches use DNF's normal refresh policy. Cache-only
        // status queries still use the present metadata after expiration.
        paths.observe_expiration = true;
        let fingerprint = paths.fingerprint()?;
        Ok(Self { paths, fingerprint })
    }

    pub(super) fn is_current(&self) -> Result<bool> {
        Ok(self.paths.fingerprint()? == self.fingerprint)
    }
}

struct ResolvedRepositoryPaths {
    root: PathBuf,
    control_revision: [u8; 32],
    paths: RepositoryPaths,
}

impl ResolvedRepositoryPaths {
    fn capture(root: &Path) -> Result<Self> {
        let paths = RepositoryPaths::effective(root)?;
        let control_revision = paths.configuration_fingerprint()?;
        // The first native dump discovers custom configuration directories.
        // Resolve again within the observed configuration generation.
        anyhow::ensure!(
            paths == RepositoryPaths::effective(root)?
                && paths.configuration_fingerprint()? == control_revision,
            "DNF configuration changed while resolving repository paths"
        );
        Ok(Self {
            root: root.to_path_buf(),
            control_revision,
            paths,
        })
    }
}

/// Effective paths are resolved on configuration changes, not for every status request.
#[derive(Default)]
pub(crate) struct StatusRepositories {
    paths: Option<ResolvedRepositoryPaths>,
}

impl StatusRepositories {
    pub(super) fn package_revision(&mut self, root: &Path) -> Result<[u8; 32]> {
        if let Some(paths) = &self.paths
            && paths.root == root
        {
            let controls = paths.paths.configuration_fingerprint()?;
            if controls == paths.control_revision {
                return paths.paths.catalog_fingerprint(controls);
            }
        }

        let paths = ResolvedRepositoryPaths::capture(root)?;
        let revision = paths.paths.catalog_fingerprint(paths.control_revision)?;
        self.paths = Some(paths);
        Ok(revision)
    }
}

impl RepositoryPaths {
    fn effective(root: &Path) -> Result<Self> {
        let report = read_dnf_settings(&["--dump-repo-config=*"])?;
        let (main, cache_paths) = repository_cache_paths(&report)?;
        anyhow::ensure!(
            parse_absolute_setting(main, "installroot")? == root,
            "DNF installroot changed while resolving repository paths"
        );
        let mut paths = Self::controls(root)?;
        paths.add_effective_paths(root, main)?;
        paths.caches.extend(cache_paths);
        paths.caches.sort_unstable();
        paths.caches.dedup();
        Ok(paths)
    }

    fn controls(root: &Path) -> Result<Self> {
        let mut paths = Self::default();
        for prefix in [Path::new("/"), root] {
            paths
                .files
                .push(rooted_path(prefix, Path::new("/etc/dnf/dnf.conf"))?);
            for directory in CONFIG_DROP_INS.iter().chain(PLUGIN_CONFIGS) {
                paths
                    .directories
                    .push((rooted_path(prefix, Path::new(directory))?, Some("conf")));
            }
            for directory in [
                "/etc/dnf/repos.override.d",
                "/usr/share/dnf5/repos.override.d",
            ] {
                paths
                    .directories
                    .push((rooted_path(prefix, Path::new(directory))?, Some("repo")));
            }
            for directory in ["/etc/dnf/vars", "/usr/share/dnf5/vars.d"] {
                paths
                    .directories
                    .push((rooted_path(prefix, Path::new(directory))?, None));
            }
        }
        Ok(paths)
    }

    fn add_effective_paths(&mut self, root: &Path, settings: &str) -> Result<()> {
        let config = Path::new(reported_setting(settings, "config_file_path")?);
        self.files.push(config.to_path_buf());
        self.files.push(relative_to_root(root, config));
        let config_root = if settings.lines().any(|line| line == "use_host_config = 1") {
            Path::new("/")
        } else {
            root
        };
        // DNF5 has already applied installroot to reposdir and the cache
        // directories by the time it dumps the main configuration.
        self.directories.extend(
            reported_paths(settings, "reposdir")?
                .into_iter()
                .map(|directory| (directory, Some("repo"))),
        );
        for directory in reported_paths(settings, "varsdir")? {
            self.directories
                .push((relative_to_root(config_root, &directory), None));
        }
        if settings
            .lines()
            .any(|line| line.starts_with("plugin_conf_dir = "))
        {
            self.directories.extend(
                reported_paths(settings, "plugin_conf_dir")?
                    .into_iter()
                    .map(|directory| (directory, Some("conf"))),
            );
        }
        let plugin_directory = PathBuf::from(reported_setting(settings, "pluginconfpath")?);
        self.directories.push((plugin_directory, Some("conf")));

        // DNF may use either the caller's cache or valid system metadata.
        for option in ["cachedir", "system_cachedir"] {
            self.caches.push(parse_absolute_setting(settings, option)?);
        }
        Ok(())
    }

    fn configuration_fingerprint(&self) -> Result<[u8; 32]> {
        let mut files = self.files.clone();
        let mut directories: Vec<_> = self.directories.iter().collect();
        directories.sort_unstable();
        directories.dedup();

        for (directory, extension) in directories {
            for entry in directory_entries(directory)?.into_iter().flatten() {
                let entry = entry?;
                let path = entry.path();
                if !entry.file_type()?.is_dir()
                    && extension
                        .is_none_or(|extension| path.extension() == Some(extension.as_ref()))
                {
                    files.push(path);
                }
            }
        }
        fingerprint_files(files)
    }

    fn catalog_fingerprint(&self, controls: [u8; 32]) -> Result<[u8; 32]> {
        let mut files = Vec::new();
        for directory in &self.caches {
            for repository in cached_repositories(directory)? {
                files.push(repository.join("repodata/repomd.xml"));
                if self.observe_expiration {
                    files.push(repository.join("attrs/expired"));
                }
            }
        }
        let mut hash = Sha256::new();
        hash.update(b"OMG DNF repository catalog v2\\0");
        hash.update(controls);
        hash.update(fingerprint_files(files)?);
        Ok(hash.finalize().into())
    }

    fn fingerprint(&self) -> Result<[u8; 32]> {
        self.catalog_fingerprint(self.configuration_fingerprint()?)
    }
}

fn fingerprint_files(mut files: Vec<PathBuf>) -> Result<[u8; 32]> {
    files.sort_unstable();
    files.dedup();
    let mut hash = Sha256::new();
    hash.update(b"OMG DNF observed inputs v1\\0");
    for path in files {
        match RpmFileIdentity::read(&path) {
            Ok(Some(identity)) => {
                hash.update([1]);
                hash.update(path.as_os_str().as_encoded_bytes());
                hash.update([0]);
                identity.hash_generation(&mut hash, true);
            }
            Ok(None) => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("Cannot observe DNF repository input {}", path.display())
                });
            }
        }
    }
    Ok(hash.finalize().into())
}

fn repository_cache_paths(report: &str) -> Result<(&str, Vec<PathBuf>)> {
    let report = report
        .strip_prefix("======== Main configuration: ========\n")
        .context("DNF did not report the main repository configuration")?;
    let mut sections = report.split("\n======== ");
    let main = sections
        .next()
        .context("DNF main configuration is missing")?;
    let mut caches = Vec::new();
    for section in sections {
        let (header, settings) = section
            .split_once('\n')
            .context("Incomplete DNF repository configuration section")?;
        let id = header
            .strip_prefix('"')
            .and_then(|name| name.strip_suffix("\" repository configuration: ========"))
            .context("Unexpected DNF repository configuration section")?;
        anyhow::ensure!(
            !id.is_empty()
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte)),
            "DNF reported an invalid repository ID"
        );
        match reported_setting(settings, "enabled")? {
            "1" => caches.push(parse_absolute_setting(settings, "cachedir")?),
            "0" => {}
            _ => anyhow::bail!("DNF reported an invalid repository enabled flag"),
        }
    }
    Ok((main, caches))
}

fn cached_repositories(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut repositories = Vec::new();
    for entry in directory_entries(directory)?.into_iter().flatten() {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() || kind.is_symlink() {
            repositories.push(entry.path());
        }
    }
    Ok(repositories)
}

pub(super) fn advisory_revision(cache: &Path) -> Result<[u8; 32]> {
    const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;

    let mut manifests: Vec<_> = cached_repositories(cache)?
        .into_iter()
        .map(|repository| repository.join("repodata/repomd.xml"))
        .collect();
    manifests.sort_unstable();
    let mut hash = Sha256::new();
    hash.update(b"OMG DNF advisory manifests v1\0");
    for path in manifests {
        let Some(observed) = RpmFileIdentity::read(&path)? else {
            continue;
        };
        let mut bytes = Vec::new();
        fs::File::open(&path)?
            .take(MAX_MANIFEST_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() <= MAX_MANIFEST_BYTES && RpmFileIdentity::read(&path)? == Some(observed),
            "DNF advisory manifest changed during observation or exceeds its byte limit"
        );
        // A normal DNF refresh can rewrite a byte-identical, authenticated
        // manifest. It should not prevent publishing a stable advisory scan.
        hash.update([1]);
        hash.update(path.as_os_str().as_encoded_bytes());
        hash.update([0]);
        hash.update(Sha256::digest(bytes));
    }
    Ok(hash.finalize().into())
}

fn directory_entries(path: &Path) -> Result<Option<fs::ReadDir>> {
    match fs::read_dir(path) {
        Ok(entries) => Ok(Some(entries)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("Cannot list DNF repository input {}", path.display())),
    }
}

fn relative_to_root(root: &Path, path: &Path) -> PathBuf {
    root.join(path.strip_prefix("/").unwrap_or(path))
}

fn reported_paths(config: &str, key: &str) -> Result<Vec<PathBuf>> {
    let value = reported_setting(config, key)?;
    let mut paths = Vec::new();
    let mut item = String::new();
    let mut escaped = false;
    for ch in value.chars() {
        if escaped {
            item.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == ',' {
            paths.push(PathBuf::from(std::mem::take(&mut item)));
        } else {
            item.push(ch);
        }
    }
    if !item.is_empty() {
        paths.push(PathBuf::from(item));
    }
    anyhow::ensure!(
        !escaped && paths.iter().all(|path| !path.as_os_str().is_empty()),
        "DNF {key} contains an invalid directory"
    );
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_observation_tracks_policy_and_metadata_without_solver_churn() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let config = fixture.path().join("repos");
        let cache = fixture.path().join("cache");
        let repository = cache.join("fixture-a1");
        let manifest = repository.join("repodata/repomd.xml");
        fs::create_dir_all(manifest.parent().context("manifest parent")?)?;
        fs::create_dir(&config)?;
        let paths = RepositoryPaths {
            directories: vec![(config.clone(), Some("repo"))],
            caches: vec![cache],
            ..RepositoryPaths::default()
        };

        let policy = config.join("fixture.repo");
        fs::write(&policy, "enabled=1")?;
        fs::write(&manifest, "original")?;
        let fingerprint = paths.fingerprint()?;
        let observed = RepositoryObservation { paths, fingerprint };

        fs::create_dir(repository.join("solv"))?;
        fs::write(repository.join("solv/fixture.solv"), "generated")?;
        assert!(observed.is_current()?);

        let mut catalog_paths = observed.paths.clone();
        catalog_paths.observe_expiration = true;
        let catalog = RepositoryObservation {
            fingerprint: catalog_paths.fingerprint()?,
            paths: catalog_paths,
        };
        let expired = repository.join("attrs/expired");
        fs::create_dir(expired.parent().context("expiration marker parent")?)?;
        fs::write(&expired, [])?;
        assert!(!catalog.is_current()?);
        assert!(observed.is_current()?);
        fs::remove_file(expired)?;
        assert!(catalog.is_current()?);

        fs::write(&policy, "enabled=0\n")?;
        assert!(!observed.is_current()?);
        let fingerprint = observed.paths.fingerprint()?;
        let observed = RepositoryObservation {
            paths: observed.paths,
            fingerprint,
        };
        fs::write(&manifest, "updated metadata")?;
        assert!(!observed.is_current()?);
        Ok(())
    }

    #[test]
    fn advisory_revision_changes_with_manifest_bytes() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let manifest = fixture.path().join("repo/repodata/repomd.xml");
        fs::create_dir_all(manifest.parent().context("manifest parent")?)?;
        let absent = advisory_revision(fixture.path())?;
        fs::write(&manifest, b"manifest with advisories")?;
        let original = advisory_revision(fixture.path())?;
        assert_ne!(absent, original);
        fs::write(&manifest, b"manifest with advisories")?;
        assert_eq!(original, advisory_revision(fixture.path())?);
        fs::write(&manifest, b"changed advisory manifest")?;
        assert_ne!(original, advisory_revision(fixture.path())?);
        Ok(())
    }

    #[test]
    fn native_repository_path_lists_keep_escaped_directory_characters() -> Result<()> {
        assert_eq!(
            reported_paths(
                "reposdir = /one,/two\\,more,/three\\ with\\ spaces",
                "reposdir"
            )?,
            [
                PathBuf::from("/one"),
                PathBuf::from("/two,more"),
                PathBuf::from("/three with spaces")
            ]
        );
        assert!(reported_paths("reposdir = ", "reposdir")?.is_empty());
        assert_eq!(
            reported_paths("reposdir = relative", "reposdir")?,
            [PathBuf::from("relative")]
        );
        assert_eq!(
            relative_to_root(Path::new("/installroot"), Path::new("relative")),
            Path::new("/installroot/relative")
        );
        Ok(())
    }
}
