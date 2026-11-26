//! DNF's repository configuration and cached manifests used by the daemon index.

use std::fs;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use super::repository_freshness::{RepositoryAge, RepositoryAgePolicy};
use super::rpm_database::{
    CONFIG_DROP_INS, PLUGIN_CONFIGS, RpmDatabase, parse_absolute_setting, read_dnf_settings,
    reported_setting, rooted_path,
};
use super::{RpmDatabaseIdentity, RpmFileIdentity};

#[derive(Clone, Default, PartialEq, Eq)]
struct RepositoryPaths {
    files: Vec<PathBuf>,
    directories: Vec<(PathBuf, Option<&'static str>)>,
    caches: Vec<PathBuf>,
    observe_expiration: bool,
    age_policies: Option<Vec<RepositoryAgePolicy>>,
    rpm_database: Option<PathBuf>,
}

pub(super) struct RepositoryObservation {
    paths: RepositoryPaths,
    fingerprint: [u8; 32],
    metadata_ages: Option<Vec<RepositoryAge>>,
}

impl RepositoryObservation {
    pub(super) fn capture(root: &Path) -> Result<Self> {
        let paths = ResolvedRepositoryPaths::capture(root, true)?.paths;
        let fingerprint = paths.fingerprint()?;
        let metadata_ages = paths.age_policies.as_ref().and_then(|policies| {
            match policies
                .iter()
                .map(RepositoryAgePolicy::read)
                .collect::<Result<Vec<_>>>()
            {
                Ok(ages) => Some(ages),
                Err(error) => {
                    tracing::debug!(%error, "DNF repository age could not be observed");
                    None
                }
            }
        });
        Ok(Self {
            paths,
            fingerprint,
            metadata_ages,
        })
    }

    pub(super) fn is_current(&self) -> Result<bool> {
        Ok(self.paths.fingerprint()? == self.fingerprint)
    }

    pub(super) fn metadata_is_fresh(&self) -> Result<bool> {
        let Some(ages) = &self.metadata_ages else {
            return Ok(false);
        };
        metadata_is_fresh(ages)
    }
}

fn metadata_is_fresh(ages: &[RepositoryAge]) -> Result<bool> {
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    for age in ages {
        if !age.is_fresh(now)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Witness for reusing read-only search rows across CLI processes.
pub(super) struct DirectCatalogScope {
    paths: RepositoryPaths,
    report_digest: [u8; 32],
    repositories: Vec<(PathBuf, RepositoryAge)>,
}

impl DirectCatalogScope {
    pub(super) fn capture(database: &RpmDatabase) -> Result<(Self, [u8; 32])> {
        anyhow::ensure!(
            database.root == Path::new("/") && !crate::core::is_root(),
            "DNF search cache requires the ordinary host installroot"
        );
        anyhow::ensure!(
            std::env::var_os("DNF5_PLUGINS_DIR").is_none(),
            "Custom DNF plugins require native catalog loading"
        );
        let options = ["--dump-repo-config=*", "--dump-variables"];
        let report = read_dnf_settings(&options)?;
        let at = report
            .find("======== Main configuration: ========\n")
            .context("Missing DNF main configuration")?;
        let config = &report[at..];
        let (main, repos) = reported_repositories(config)?;
        let mut paths = RepositoryPaths::from_report(&database.root, true, config)?;
        anyhow::ensure!(
            reported_setting(main, "cacheonly")? == "none"
                && !repos.is_empty()
                && repos.iter().all(|(_, settings)| matches!(
                    reported_setting(settings, "repo_gpgcheck"),
                    Ok("0")
                )),
            "DNF cache-only or signed repository policy requires native catalog loading"
        );
        observe_native_catalog_controls(&mut paths, main, database)?;
        let inputs_before = paths.fingerprint()?;
        let policies = paths
            .age_policies
            .as_ref()
            .context("Unknown DNF repository age policy")?;
        anyhow::ensure!(
            policies.len() == repos.len(),
            "DNF search cache requires finite repository expiry"
        );
        let repositories = policies
            .iter()
            .map(|policy| Ok((policy.directory().to_path_buf(), policy.read_for_cache()?)))
            .collect::<Result<Vec<_>>>()?;

        let report_digest = native_report_digest(&report);
        let scope = Self {
            paths,
            report_digest,
            repositories,
        };
        let key = scope.key()?;
        // The first native report discovers custom directories. Bind it to
        // the on-disk generation before taking results from a shared cache.
        anyhow::ensure!(
            native_report_digest(&read_dnf_settings(&options)?) == report_digest
                && scope.paths.fingerprint()? == inputs_before
                && scope.key()? == key,
            "DNF inputs changed while observing the search cache"
        );
        Ok((scope, key))
    }

    pub(super) fn key(&self) -> Result<[u8; 32]> {
        let mut inputs = Vec::new();
        let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
        for (repository, age) in &self.repositories {
            anyhow::ensure!(
                age.is_fresh(now)? && !repository.join("attrs/expired").try_exists()?,
                "DNF repository metadata has expired"
            );
            for directory in [repository.join("repodata"), repository.join("solv")] {
                for entry in directory_entries(&directory)?.into_iter().flatten() {
                    let entry = entry?;
                    anyhow::ensure!(
                        entry.file_type()?.is_file(),
                        "DNF catalog cache requires regular metadata inputs"
                    );
                    inputs.push(entry.path());
                }
            }
        }
        let mut key = Sha256::new();
        key.update(b"OMG DNF direct catalog v2\0");
        key.update(std::env::consts::ARCH.as_bytes());
        key.update(self.report_digest);
        key.update(self.paths.fingerprint()?);
        key.update(fingerprint_files(inputs)?);
        for name in ["LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"] {
            key.update([0]);
            if let Some(value) = std::env::var_os(name) {
                key.update(value.as_encoded_bytes());
            }
        }
        Ok(key.finalize().into())
    }
}

fn native_report_digest(report: &str) -> [u8; 32] {
    // DNF can enumerate repository sections in a different order in
    // successive processes. Preserve each section's full configuration.
    let mut sections: Vec<_> = report
        .split("\n======== ")
        .map(|section| section.trim_end_matches('\n'))
        .collect();
    sections.sort_unstable();
    let mut hash = Sha256::new();
    for section in sections {
        hash.update((section.len() as u64).to_le_bytes());
        hash.update(section.as_bytes());
    }
    hash.finalize().into()
}

fn observe_native_catalog_controls(
    paths: &mut RepositoryPaths,
    main: &str,
    database: &RpmDatabase,
) -> Result<()> {
    paths
        .files
        .push(crate::core::privilege::root_controlled_program_path("dnf")?);
    paths.rpm_database = Some(database.sqlite.clone());

    let state = parse_absolute_setting(main, "system_state_dir")?;
    let modules = state.join("modules.toml");
    if modules.try_exists()? {
        anyhow::ensure!(
            super::install_reasons::read_table::<toml::Table>(&state, "modules")?.is_empty(),
            "DNF module state requires native catalog loading"
        );
    }
    paths.files.push(modules);
    paths.files.push(PathBuf::from("/etc/dnf/versionlock.toml"));
    for directory in [
        PathBuf::from("/etc/dnf/modules.d"),
        parse_absolute_setting(main, "persistdir")?.join("modulefailsafe"),
        parse_absolute_setting(main, "pluginpath")?,
    ] {
        anyhow::ensure!(
            directory_entries(&directory)?.is_none_or(|mut files| files.next().is_none()),
            "DNF module or library plugin state requires native catalog loading"
        );
        paths.directories.push((directory, None));
    }

    paths.directories.extend(
        standard_command_plugin_dirs()?
            .into_iter()
            .map(|path| (path, Some("so"))),
    );
    for directory in [
        PathBuf::from("/etc/dnf/dnf5-aliases.d"),
        PathBuf::from("/usr/share/dnf5/aliases.d"),
    ]
    .into_iter()
    .chain(dirs::config_dir().map(|home| home.join("dnf5/aliases.d")))
    {
        paths.directories.push((directory, Some("conf")));
    }
    Ok(())
}

fn standard_command_plugin_dirs() -> Result<[PathBuf; 2]> {
    // These Fedora command plugins register their own commands. Third-party
    // plugins can modify DNF context and must take the native path.
    const FEDORA_COMMAND_PLUGINS: &[&str] = &[
        "builddep_cmd_plugin.so",
        "changelog_cmd_plugin.so",
        "config-manager_cmd_plugin.so",
        "copr_cmd_plugin.so",
        "needs_restarting_cmd_plugin.so",
        "repoclosure_cmd_plugin.so",
        "repomanage_cmd_plugin.so",
        "reposync_cmd_plugin.so",
    ];
    let directories = ["/usr/lib64/dnf5/plugins", "/usr/lib/dnf5/plugins"].map(PathBuf::from);
    for directory in &directories {
        for entry in directory_entries(directory)?.into_iter().flatten() {
            let path = entry?.path();
            if path.extension().is_some_and(|value| value == "so") {
                anyhow::ensure!(
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| FEDORA_COMMAND_PLUGINS.contains(&name)),
                    "Unknown DNF command plugin requires native catalog loading"
                );
            }
        }
    }
    Ok(directories)
}

// Only establish a positive match. With no repository definition, custom
// configuration or unknown plugins, the native repository list decides.
pub(super) fn has_standard_repository() -> bool {
    #[cfg(unix)]
    {
        standard_repository_exists()
            .inspect_err(|error| tracing::debug!("Using native DNF repository scope: {error:#}"))
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    false
}

#[cfg(unix)]
fn standard_repository_exists() -> Result<bool> {
    use std::os::unix::fs::MetadataExt as _;

    if !super::rpm_database::uses_default_repository_paths()
        || std::env::var_os("DNF5_PLUGINS_DIR").is_some()
        || !crate::core::privilege::root_controlled_program_path("dnf")?.ends_with("dnf5")
    {
        return Ok(false);
    }
    standard_command_plugin_dirs()?;
    for path in ["/usr/lib64/libdnf5/plugins", "/usr/lib/libdnf5/plugins"] {
        if let Some(mut entries) = directory_entries(Path::new(path))?
            && entries.next().is_some()
        {
            return Ok(false);
        }
    }

    const MAX_REPO_FILE: u64 = 1024 * 1024;
    'repositories: for directory in [
        "/etc/yum.repos.d",
        "/etc/distro.repos.d",
        "/usr/share/dnf5/repos.d",
    ] {
        let directory = Path::new(directory);
        let Some(entries) = directory_entries(directory)? else {
            continue;
        };
        for dir in directory.ancestors() {
            let meta = fs::symlink_metadata(dir)?;
            if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
                continue 'repositories;
            }
        }

        for entry in entries {
            let path = entry?.path();
            if path.extension().is_none_or(|extension| extension != "repo") {
                continue;
            }
            let meta = fs::symlink_metadata(&path)?;
            if !meta.is_file()
                || meta.uid() != 0
                || meta.mode() & 0o022 != 0
                || meta.len() > MAX_REPO_FILE
            {
                continue;
            }
            let mut config = String::new();
            let bytes = fs::File::open(&path)?
                .take(MAX_REPO_FILE + 1)
                .read_to_string(&mut config)?;
            if bytes as u64 <= MAX_REPO_FILE && has_literal_repository_section(&config) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[cfg(unix)]
fn has_literal_repository_section(config: &str) -> bool {
    config.lines().any(|line| {
        line.trim_ascii_end()
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
            .is_some_and(|id| {
                !id.is_empty()
                    && id != "main"
                    && id
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
            })
    })
}

struct ResolvedRepositoryPaths {
    root: PathBuf,
    control_revision: [u8; 32],
    paths: RepositoryPaths,
}

impl ResolvedRepositoryPaths {
    fn capture(root: &Path, for_search: bool) -> Result<Self> {
        let paths = RepositoryPaths::effective(root, for_search)?;
        let control_revision = paths.configuration_fingerprint()?;
        // The first native dump discovers custom configuration directories.
        // Resolve again within the observed configuration generation.
        anyhow::ensure!(
            paths == RepositoryPaths::effective(root, for_search)?
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

        let paths = ResolvedRepositoryPaths::capture(root, false)?;
        let revision = paths.paths.catalog_fingerprint(paths.control_revision)?;
        self.paths = Some(paths);
        Ok(revision)
    }
}

impl RepositoryPaths {
    fn effective(root: &Path, for_search: bool) -> Result<Self> {
        let options: &[&str] = if for_search {
            &["--dump-repo-config=*"]
        } else {
            &["--cacheonly", "--dump-repo-config=*"]
        };
        let report = read_dnf_settings(options)?;
        Self::from_report(root, for_search, &report)
    }

    fn from_report(root: &Path, for_search: bool, report: &str) -> Result<Self> {
        let (main, repositories) = reported_repositories(report)?;
        anyhow::ensure!(
            parse_absolute_setting(main, "installroot")? == root,
            "DNF installroot changed while resolving repository paths"
        );
        let mut paths = Self::controls(root)?;
        paths.add_effective_paths(root, main)?;
        paths.observe_expiration = for_search;
        let check_age = if for_search {
            match reported_setting(main, "cacheonly")? {
                "none" => true,
                "all" | "metadata" => false,
                _ => anyhow::bail!("Unsupported DNF metadata cache policy"),
            }
        } else {
            false
        };
        let prefer_zchunk = if check_age {
            match reported_setting(main, "zchunk")? {
                "1" => true,
                "0" => false,
                _ => anyhow::bail!("Unsupported DNF zchunk setting"),
            }
        } else {
            false
        };
        let mut policies = Some(Vec::new());
        for (id, settings) in repositories {
            let cache = parse_absolute_setting(settings, "cachedir")?;
            if check_age && let Some(ages) = &mut policies {
                match RepositoryAgePolicy::from_dnf(id, settings, &cache, prefer_zchunk) {
                    Ok(Some(age)) => ages.push(age),
                    Ok(None) => {}
                    Err(error) => {
                        tracing::debug!(%error, repository = id, "Unsupported DNF repository age policy");
                        policies = None;
                    }
                }
            }
            paths.caches.push(cache);
        }
        if let Some(ages) = &mut policies {
            ages.sort_unstable();
        }
        paths.age_policies = policies;
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
        let controls = fingerprint_files(files)?;
        let Some(path) = &self.rpm_database else {
            return Ok(controls);
        };
        let database = RpmDatabaseIdentity::read(path)
            .context("Cannot observe the RPM database for DNF catalog caching")?;
        let mut hash = Sha256::new();
        hash.update(controls);
        hash.update(path.as_os_str().as_encoded_bytes());
        hash.update([0]);
        // An empty journal has no RPM inventory data. Nonempty WAL changes
        // still affect the key, including file identity and ctime.
        database.hash_inventory_generation(&mut hash, true);
        Ok(hash.finalize().into())
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

fn reported_repositories(report: &str) -> Result<(&str, Vec<(&str, &str)>)> {
    let report = report
        .strip_prefix("======== Main configuration: ========\n")
        .context("DNF did not report the main repository configuration")?;
    let mut sections = report.split("\n======== ");
    let main = sections
        .next()
        .context("DNF main configuration is missing")?;
    let mut repositories = Vec::new();
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
            "1" => repositories.push((id, settings)),
            "0" => {}
            _ => anyhow::bail!("DNF reported an invalid repository enabled flag"),
        }
    }
    Ok((main, repositories))
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

    #[cfg(unix)]
    #[test]
    fn literal_repository_sections_skip_comments_main_and_substitutions() {
        for config in [
            "",
            "[main]\nenabled=1",
            "# [fedora]\n; [updates]",
            "baseurl=file:///repo/[fedora]",
            "  [continuation]\n",
            "[fedora-$releasever]\n",
            "[]",
            "[@System]",
            "[incomplete",
        ] {
            assert!(!has_literal_repository_section(config), "{config:?}");
        }
        for config in [
            "[fedora]\nenabled=0\n",
            "# Comment\r\n[updates-testing.x86_64]\r\n",
            "[family:distribution_a] \t\n",
        ] {
            assert!(has_literal_repository_section(config), "{config:?}");
        }
    }

    #[test]
    fn native_report_key_preserves_content_but_ignores_repository_order() {
        let main = "======== Main configuration: ========\ninstallroot = /\n";
        let first = "======== \"one\" repository configuration: ========\ncachedir = /cache/one\n";
        let second = "======== \"two\" repository configuration: ========\ncachedir = /cache/two\n";
        let original = native_report_digest(&format!("{main}{first}{second}"));
        assert_eq!(
            original,
            native_report_digest(&format!("{main}{second}{first}"))
        );
        assert_ne!(
            original,
            native_report_digest(&format!("{main}{first}{second}excludepkgs = bash\n")),
        );
    }

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
        let observed = RepositoryObservation {
            paths,
            fingerprint,
            metadata_ages: None,
        };

        fs::create_dir(repository.join("solv"))?;
        fs::write(repository.join("solv/fixture.solv"), "generated")?;
        assert!(observed.is_current()?);

        let mut catalog_paths = observed.paths.clone();
        catalog_paths.observe_expiration = true;
        let catalog = RepositoryObservation {
            fingerprint: catalog_paths.fingerprint()?,
            paths: catalog_paths,
            metadata_ages: None,
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
            metadata_ages: None,
        };
        fs::write(&manifest, "updated metadata")?;
        assert!(!observed.is_current()?);
        Ok(())
    }

    #[test]
    fn catalog_fingerprint_ignores_empty_wal_and_tracks_nonempty_wal() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let database = fixture.path().join("rpmdb.sqlite");
        let wal = fixture.path().join("rpmdb.sqlite-wal");
        fs::write(&database, b"database generation")?;
        let paths = RepositoryPaths {
            rpm_database: Some(database.clone()),
            ..RepositoryPaths::default()
        };
        let initial = paths.fingerprint()?;

        fs::write(&wal, [])?;
        assert_eq!(paths.fingerprint()?, initial);
        fs::write(&wal, b"nonempty journal generation")?;
        let first_wal = paths.fingerprint()?;
        assert_ne!(first_wal, initial);
        fs::write(&wal, b"new journal generation with a different size")?;
        assert_ne!(paths.fingerprint()?, first_wal);
        fs::write(&wal, [])?;
        assert_eq!(paths.fingerprint()?, initial);
        fs::remove_file(&wal)?;
        assert_eq!(paths.fingerprint()?, initial);

        fs::write(&database, b"new database generation")?;
        assert_ne!(paths.fingerprint()?, initial);
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
