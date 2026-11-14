//! Parser for /etc/pacman.conf to extract repository configuration

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

bitflags::bitflags! {
    /// Operations for which a configured repository may supply package data.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    pub struct RepoUsage: u8 {
        /// Refresh this repository during database synchronization.
        const SYNC = 1;
        /// Include this repository in package searches.
        const SEARCH = 2;
        /// Use this repository for implicit package installation.
        const INSTALL = 4;
        /// Use this repository for system upgrades.
        const UPGRADE = 8;
        /// Enable every repository operation.
        const ALL = Self::SYNC.bits() | Self::SEARCH.bits() | Self::INSTALL.bits() | Self::UPGRADE.bits();
    }
}

impl Default for RepoUsage {
    fn default() -> Self {
        Self::ALL
    }
}

impl std::str::FromStr for RepoUsage {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let mut usage = Self::empty();
        for token in value.split_whitespace() {
            usage |= match token {
                "Sync" => Self::SYNC,
                "Search" => Self::SEARCH,
                "Install" => Self::INSTALL,
                "Upgrade" => Self::UPGRADE,
                "All" => Self::ALL,
                _ => anyhow::bail!("Invalid repository Usage token: {token}"),
            };
        }
        anyhow::ensure!(!usage.is_empty(), "Repository Usage cannot be empty");
        Ok(usage)
    }
}

#[cfg(feature = "arch")]
impl RepoUsage {
    pub(crate) fn to_alpm(self) -> alpm::Usage {
        let mut usage = alpm::Usage::empty();
        for (configured, native) in [
            (Self::SYNC, alpm::Usage::SYNC),
            (Self::SEARCH, alpm::Usage::SEARCH),
            (Self::INSTALL, alpm::Usage::INSTALL),
            (Self::UPGRADE, alpm::Usage::UPGRADE),
        ] {
            if self.contains(configured) {
                usage |= native;
            }
        }
        usage
    }
}

#[derive(Debug, Clone, Default)]
pub struct RepoConfig {
    pub usage: RepoUsage,
    pub name: String,
    pub servers: Vec<String>,
    pub sig_level: Option<String>,
    pub include: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PacmanConfig {
    pub root_dir: Option<String>,
    pub db_path: Option<String>,
    pub cache_dirs: Vec<String>,
    pub log_file: Option<String>,
    pub gpg_dir: Option<String>,
    pub hook_dirs: Vec<String>,
    pub hold_pkg: Vec<String>,
    pub ignore_pkg: Vec<String>,
    pub ignore_group: Vec<String>,
    pub no_upgrade: Vec<String>,
    pub no_extract: Vec<String>,
    pub architecture: Option<String>,
    pub sig_level: Option<String>,
    pub local_file_sig_level: Option<String>,
    pub remote_file_sig_level: Option<String>,
    pub parallel_downloads: Option<u32>,
    pub repos: Vec<RepoConfig>,
}

fn strip_inline_comment(line: &str) -> &str {
    line.split('#').next().unwrap_or_default().trim_end()
}

fn load_config_with_includes(
    path: &Path,
    visited: &mut HashSet<PathBuf>,
    output: &mut String,
) -> Result<()> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("Failed to resolve pacman configuration {}", path.display()))?;
    anyhow::ensure!(
        visited.insert(canonical.clone()),
        "Pacman configuration include cycle at {}",
        canonical.display()
    );

    let content = std::fs::read_to_string(&canonical)
        .with_context(|| format!("Failed to read {}", canonical.display()))?;
    for raw_line in content.lines() {
        let line = strip_inline_comment(raw_line).trim();
        let include = line
            .split_once('=')
            .filter(|(key, _)| key.trim() == "Include")
            .map(|(_, value)| value.trim());
        if let Some(include) = include {
            anyhow::ensure!(!include.is_empty(), "Pacman Include path cannot be empty");
            anyhow::ensure!(
                !include.contains(['*', '?', '[']),
                "Globbed pacman Include paths are not supported: {include}"
            );
            let include_path = Path::new(include);
            let resolved = if include_path.is_absolute() {
                include_path.to_path_buf()
            } else {
                canonical
                    .parent()
                    .context("Pacman configuration has no parent directory")?
                    .join(include_path)
            };
            load_config_with_includes(&resolved, visited, output)?;
        } else {
            output.push_str(raw_line);
            output.push('\n');
        }
    }

    visited.remove(&canonical);
    Ok(())
}

fn validate_repository_name(name: &str) -> Result<()> {
    let mut components = Path::new(name).components();
    anyhow::ensure!(
        matches!(components.next(), Some(std::path::Component::Normal(component)) if component == name)
            && components.next().is_none(),
        "Invalid repository name '{name}': expected one filesystem path component"
    );
    Ok(())
}

impl PacmanConfig {
    /// Identify the ordered configuration consumed by this parser, including
    /// recursively expanded includes. This observes bytes; it does not lock writers.
    pub(crate) fn fingerprint(path: &Path) -> Result<[u8; 32]> {
        use sha2::{Digest, Sha256};

        let canonical = path.canonicalize().with_context(|| {
            format!("Failed to resolve pacman configuration {}", path.display())
        })?;
        let mut content = String::new();
        load_config_with_includes(&canonical, &mut HashSet::new(), &mut content)?;
        let mut hash = Sha256::new();
        hash.update(b"omg-pacman-config-v1");
        let path_bytes = canonical.as_os_str().as_encoded_bytes();
        hash.update((path_bytes.len() as u64).to_le_bytes());
        hash.update(path_bytes);
        hash.update((content.len() as u64).to_le_bytes());
        hash.update(content.as_bytes());
        Ok(hash.finalize().into())
    }

    pub fn parse<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut content = String::new();
        load_config_with_includes(path.as_ref(), &mut HashSet::new(), &mut content)?;
        Self::parse_str(&content)
    }

    pub fn parse_str(content: &str) -> Result<Self> {
        enum Section {
            Preamble,
            Options,
            Repository(RepoConfig),
        }

        let finish = |section: Section, repos: &mut Vec<RepoConfig>| {
            if let Section::Repository(mut repo) = section {
                if repo.usage.is_empty() {
                    repo.usage = RepoUsage::ALL;
                }
                repos.push(repo);
            }
        };
        let mut config = PacmanConfig::default();
        let mut current_section = Section::Preamble;
        let mut repository_names = HashSet::new();

        for line in content.lines() {
            let line = strip_inline_comment(line.trim()).trim();

            if line.is_empty() {
                continue;
            }

            if line.starts_with('[') && line.ends_with(']') {
                finish(
                    std::mem::replace(&mut current_section, Section::Preamble),
                    &mut config.repos,
                );

                let section = &line[1..line.len() - 1];
                current_section = if section == "options" {
                    Section::Options
                } else {
                    validate_repository_name(section)?;
                    anyhow::ensure!(
                        repository_names.insert(section.to_string()),
                        "Duplicate pacman repository section: {section}"
                    );
                    Section::Repository(RepoConfig {
                        name: section.to_string(),
                        usage: RepoUsage::empty(),
                        ..Default::default()
                    })
                };
                continue;
            }

            let (key, value) = if let Some(eq_pos) = line.find('=') {
                let k = line[..eq_pos].trim();
                let v = line[eq_pos + 1..].trim();
                (k, Some(v))
            } else {
                (line, None)
            };

            match &mut current_section {
                Section::Options => {
                    Self::parse_option(&mut config, key, value)?;
                }
                Section::Repository(repo) => {
                    Self::parse_repo_option(repo, key, value)?;
                }
                Section::Preamble => {}
            }
        }

        finish(current_section, &mut config.repos);

        Ok(config)
    }

    fn append_signature_option(option: &mut Option<String>, value: Option<&str>) {
        let Some(value) = value else {
            return;
        };
        match option {
            Some(existing) => {
                existing.push(' ');
                existing.push_str(value);
            }
            None => *option = Some(value.to_string()),
        }
    }

    fn parse_option(config: &mut PacmanConfig, key: &str, value: Option<&str>) -> Result<()> {
        match key {
            "RootDir" => config.root_dir = value.map(String::from),
            "DBPath" => config.db_path = value.map(String::from),
            "CacheDir" => {
                if let Some(value) = value {
                    config
                        .cache_dirs
                        .extend(value.split_whitespace().map(String::from));
                }
            }
            "LogFile" => config.log_file = value.map(String::from),
            "GPGDir" => config.gpg_dir = value.map(String::from),
            "HookDir" => {
                if let Some(value) = value {
                    config
                        .hook_dirs
                        .extend(value.split_whitespace().map(String::from));
                }
            }
            "Architecture" => config.architecture = value.map(String::from),
            "SigLevel" => Self::append_signature_option(&mut config.sig_level, value),
            "LocalFileSigLevel" => {
                Self::append_signature_option(&mut config.local_file_sig_level, value);
            }
            "RemoteFileSigLevel" => {
                Self::append_signature_option(&mut config.remote_file_sig_level, value);
            }
            "HoldPkg" => {
                if let Some(v) = value {
                    config
                        .hold_pkg
                        .extend(v.split_whitespace().map(String::from));
                }
            }
            "IgnorePkg" => {
                if let Some(v) = value {
                    config
                        .ignore_pkg
                        .extend(v.split_whitespace().map(String::from));
                }
            }
            "IgnoreGroup" => {
                if let Some(v) = value {
                    config
                        .ignore_group
                        .extend(v.split_whitespace().map(String::from));
                }
            }
            "NoUpgrade" => {
                if let Some(v) = value {
                    config
                        .no_upgrade
                        .extend(v.split_whitespace().map(String::from));
                }
            }
            "NoExtract" => {
                if let Some(v) = value {
                    config
                        .no_extract
                        .extend(v.split_whitespace().map(String::from));
                }
            }
            "ParallelDownloads" => {
                let value = value.context("ParallelDownloads requires a value")?;
                let count: u32 = value
                    .parse()
                    .with_context(|| format!("Invalid ParallelDownloads value '{value}'"))?;
                anyhow::ensure!(
                    (1..=64).contains(&count),
                    "ParallelDownloads must be between 1 and 64, got {count}"
                );
                config.parallel_downloads = Some(count);
            }
            _ => {}
        }
        Ok(())
    }

    fn parse_repo_option(repo: &mut RepoConfig, key: &str, value: Option<&str>) -> Result<()> {
        match key {
            "Server" => {
                if let Some(v) = value {
                    repo.servers.push(v.to_string());
                }
            }
            "SigLevel" => Self::append_signature_option(&mut repo.sig_level, value),
            "Include" => repo.include = value.map(String::from),
            "Usage" => {
                repo.usage |= value
                    .context("Repository Usage requires a value")?
                    .parse::<RepoUsage>()?;
            }
            _ => {}
        }
        Ok(())
    }

    pub fn get_repo_names(&self) -> Vec<&str> {
        self.repos.iter().map(|r| r.name.as_str()).collect()
    }

    pub fn resolve_servers(&self, repo: &RepoConfig, arch: &str) -> Result<Vec<String>> {
        let mut servers = Vec::new();

        for server in &repo.servers {
            servers.push(server.replace("$repo", &repo.name).replace("$arch", arch));
        }

        if let Some(ref include_path) = repo.include {
            let mirrorlist = std::fs::read_to_string(include_path)
                .with_context(|| format!("Failed to read mirrorlist: {include_path}"))?;

            for line in mirrorlist.lines() {
                let line = strip_inline_comment(line).trim();
                if let Some((key, url)) = line.split_once('=')
                    && key.trim() == "Server"
                {
                    servers.push(
                        url.trim()
                            .replace("$repo", &repo.name)
                            .replace("$arch", arch),
                    );
                }
            }
        }

        Ok(servers)
    }
}

/// Repository names from the system pacman.conf.
///
/// Test-only surface today: no production caller exists, but the
/// missing-config behavior is pinned by the test below, so the function
/// stays for the test to exercise.
#[cfg(test)]
pub fn get_configured_repos() -> Result<Vec<String>> {
    let conf_path = crate::core::paths::pacman_conf_path();
    if !conf_path.exists() {
        anyhow::bail!(
            "pacman configuration does not exist: {}",
            conf_path.display()
        );
    }

    let config = PacmanConfig::parse(&conf_path)?;
    let repos = config
        .repos
        .into_iter()
        .map(|repo| repo.name)
        .collect::<Vec<_>>();
    if repos.is_empty() {
        anyhow::bail!(
            "pacman configuration contains no repositories: {}",
            conf_path.display()
        );
    }
    Ok(repos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directives_before_a_section_do_not_configure_a_later_repository() {
        let config = PacmanConfig::parse_str(
            "Server = https://ignored.invalid\nUsage = Unknown\n[core]\nUsage = Search\n",
        )
        .expect("pre-section directives are ignored");
        assert_eq!(config.repos.len(), 1);
        assert_eq!(config.repos[0].name, "core");
        assert_eq!(config.repos[0].usage, RepoUsage::SEARCH);
        assert!(config.repos[0].servers.is_empty());
    }

    #[test]
    fn section_transitions_keep_repository_and_option_state_separate() {
        let config = PacmanConfig::parse_str(
            "Usage = Invalid\nServer = ignored\n\
             [first]\nServer = https://first.invalid\nUsage = Search\n\
             [options]\nIgnorePkg = first-held\nServer = ignored\n\
             [second]\nServer = https://second.invalid\nIgnorePkg = ignored\n\
             [options]\nIgnorePkg = second-held\n\
             [options]\nIgnorePkg = final-held\n",
        )
        .expect("mixed sections retain their own directives");
        assert_eq!(
            config.ignore_pkg,
            ["first-held", "second-held", "final-held"]
        );
        assert_eq!(config.repos.len(), 2);
        assert_eq!(config.repos[0].name, "first");
        assert_eq!(config.repos[0].servers, ["https://first.invalid"]);
        assert_eq!(config.repos[0].usage, RepoUsage::SEARCH);
        assert_eq!(config.repos[1].name, "second");
        assert_eq!(config.repos[1].servers, ["https://second.invalid"]);
        assert_eq!(config.repos[1].usage, RepoUsage::ALL);
    }

    #[test]
    fn repository_usage_defaults_and_repeated_directives() {
        let config = PacmanConfig::parse_str(
            "[default]\n[restricted]\nUsage = Sync Search\nUsage = Upgrade\n[all]\nUsage = All\n",
        )
        .unwrap();
        assert_eq!(config.repos[0].usage, RepoUsage::ALL);
        assert_eq!(
            config.repos[1].usage,
            RepoUsage::SYNC | RepoUsage::SEARCH | RepoUsage::UPGRADE
        );
        assert_eq!(config.repos[2].usage, RepoUsage::ALL);
    }

    #[test]
    fn batch2_rejects_invalid_repository_usage() {
        for usage in ["Upgarde", "", "Search Unknown"] {
            let result = PacmanConfig::parse_str(&format!("[core]\nUsage = {usage}\n"));
            assert!(
                result.is_err(),
                "invalid Usage {usage:?} was accepted: {result:?}"
            );
        }
    }

    #[test]
    #[serial_test::serial]
    fn missing_pacman_config_is_not_replaced_with_fabricated_repositories() {
        const NAME: &str = "core::pacman_conf::tests::missing_pacman_config_is_not_replaced_with_fabricated_repositories";
        if crate::config::Settings::rerun_test_unprivileged(NAME) {
            return;
        }
        if crate::core::testing::run_isolated_test(NAME) {
            return;
        }
        assert!(!crate::core::is_root(), "fixture must run as ordinary user");
        let directory = tempfile::tempdir().expect("temp dir");
        let missing = directory.path().join("missing-pacman.conf");

        temp_env::with_var("OMG_PACMAN_CONF", Some(missing.as_os_str()), || {
            let error = get_configured_repos()
                .expect_err("missing pacman config must be reported explicitly");
            assert!(error.to_string().contains("does not exist"));
        });
    }

    #[test]
    fn file_parser_applies_includes_in_options_and_repository_sections() {
        let directory = tempfile::tempdir().expect("temp dir");
        let options = directory.path().join("options.conf");
        let mirrors = directory.path().join("mirrors.conf");
        std::fs::write(&options, "HoldPkg = pacman glibc\n").expect("write options");
        std::fs::write(
            &mirrors,
            "Server = https://mirror.example/$repo/$arch # preferred\n",
        )
        .expect("write mirrors");
        let config_path = directory.path().join("pacman.conf");
        std::fs::write(
            &config_path,
            "[options]\nInclude = options.conf\n[core]\nInclude = mirrors.conf\n",
        )
        .expect("write config");

        let config = PacmanConfig::parse(&config_path).expect("parse included config");
        assert_eq!(config.hold_pkg, ["pacman", "glibc"]);
        assert_eq!(
            config.resolve_servers(&config.repos[0], "x86_64").unwrap(),
            ["https://mirror.example/core/x86_64"]
        );
    }

    #[test]
    fn parallel_downloads_option_is_parsed_and_bounded() {
        let config = PacmanConfig::parse_str(
            "[options]\nParallelDownloads = 12\n\n[core]\nServer = https://example.invalid\n",
        )
        .expect("valid ParallelDownloads");
        assert_eq!(config.parallel_downloads, Some(12));

        let error = PacmanConfig::parse_str("[options]\nParallelDownloads = 0\n")
            .expect_err("zero ParallelDownloads must fail");
        assert!(error.to_string().contains("between 1 and 64"), "{error}");
    }

    #[test]
    fn file_parser_rejects_include_cycles() {
        let directory = tempfile::tempdir().expect("temp dir");
        let first = directory.path().join("first.conf");
        let second = directory.path().join("second.conf");
        std::fs::write(&first, "Include = second.conf\n").expect("write first");
        std::fs::write(&second, "Include = first.conf\n").expect("write second");

        let error = PacmanConfig::parse(&first).expect_err("include cycles must fail");
        assert!(error.to_string().contains("include cycle"), "{error}");
    }

    #[test]
    fn repository_names_must_be_single_path_components() {
        for invalid in ["../escape", "nested/repo", ".", "..", ""] {
            let config = format!("[options]\n[{invalid}]\nServer = https://example.invalid\n");
            let error = PacmanConfig::parse_str(&config)
                .expect_err("unsafe repository name must be rejected");
            assert!(error.to_string().contains("Invalid repository name"));
        }
        PacmanConfig::parse_str(
            "[options]\n[custom.repo-name_1]\nServer = https://example.invalid\n",
        )
        .expect("safe path component");
    }

    #[test]
    fn inline_comments_are_removed_from_values() {
        let config = PacmanConfig::parse_str(
            "[options]\nIgnorePkg = linux # keep the kernel pinned\n\n[core]\nServer = https://mirror.example/$repo/$arch # primary\n",
        )
        .expect("valid pacman configuration");

        assert_eq!(config.ignore_pkg, ["linux"]);
        assert_eq!(
            config.repos[0].servers,
            ["https://mirror.example/$repo/$arch"]
        );
    }

    #[test]
    fn signature_policy_directives_are_preserved_in_order() {
        let config = PacmanConfig::parse_str(
            "[options]\nSigLevel = Required DatabaseOptional\nSigLevel = TrustedOnly\nLocalFileSigLevel = PackageOptional\nRemoteFileSigLevel = PackageRequired\n\n[core]\nSigLevel = PackageRequired\nSigLevel = DatabaseNever\n",
        )
        .expect("valid signature policy");

        assert_eq!(
            config.sig_level.as_deref(),
            Some("Required DatabaseOptional TrustedOnly")
        );
        assert_eq!(
            config.local_file_sig_level.as_deref(),
            Some("PackageOptional")
        );
        assert_eq!(
            config.remote_file_sig_level.as_deref(),
            Some("PackageRequired")
        );
        assert_eq!(
            config.repos[0].sig_level.as_deref(),
            Some("PackageRequired DatabaseNever")
        );
    }

    #[test]
    fn test_parse_basic_config() {
        let content = r"
[options]
RootDir = /
DBPath = /var/lib/pacman
CacheDir = /var/cache/pacman/pkg /srv/pacman-cache
CacheDir = relative-cache
HookDir = /usr/local/share/libalpm/hooks
HookDir = etc/pacman.d/hooks
Architecture = auto
HoldPkg = pacman glibc
IgnorePkg = linux linux-lts
IgnoreGroup = modified
NoUpgrade = etc/passwd etc/group
NoExtract = usr/share/help/*

[core]
Include = /etc/pacman.d/mirrorlist

[extra]
Include = /etc/pacman.d/mirrorlist

[multilib]
Include = /etc/pacman.d/mirrorlist
";

        let config = PacmanConfig::parse_str(content).unwrap();
        assert_eq!(config.root_dir, Some("/".to_string()));
        assert_eq!(config.db_path, Some("/var/lib/pacman".to_string()));
        assert_eq!(
            config.cache_dirs,
            [
                "/var/cache/pacman/pkg",
                "/srv/pacman-cache",
                "relative-cache"
            ]
        );
        assert_eq!(
            config.hook_dirs,
            ["/usr/local/share/libalpm/hooks", "etc/pacman.d/hooks"]
        );
        assert_eq!(config.hold_pkg, ["pacman", "glibc"]);
        assert_eq!(config.ignore_pkg, ["linux", "linux-lts"]);
        assert_eq!(config.ignore_group, ["modified"]);
        assert_eq!(config.no_upgrade, ["etc/passwd", "etc/group"]);
        assert_eq!(config.no_extract, ["usr/share/help/*"]);
        assert_eq!(config.repos.len(), 3);
        assert_eq!(config.repos[0].name, "core");
        assert_eq!(config.repos[1].name, "extra");
        assert_eq!(config.repos[2].name, "multilib");
    }

    #[test]
    fn test_parse_custom_repos() {
        let content = r"
[options]
Architecture = x86_64

[core]
Include = /etc/pacman.d/mirrorlist

[extra]
Include = /etc/pacman.d/mirrorlist

[chaotic-aur]
Server = https://cdn-mirror.chaotic.cx/$repo/$arch
Server = https://us-tx-mirror.chaotic.cx/$repo/$arch
";

        let config = PacmanConfig::parse_str(content).unwrap();
        assert_eq!(config.repos.len(), 3);
        assert_eq!(config.repos[2].name, "chaotic-aur");
        assert_eq!(config.repos[2].servers.len(), 2);
    }

    #[test]
    fn duplicate_repository_sections_are_rejected() {
        let error = PacmanConfig::parse_str(
            "[core]\nServer = https://one.invalid\n[extra]\nServer = https://extra.invalid\n[core]\nServer = https://two.invalid\n",
        )
        .expect_err("duplicate repositories must fail before libalpm registration");
        assert!(
            error
                .to_string()
                .contains("Duplicate pacman repository section: core")
        );
    }

    #[test]
    fn test_get_repo_names() {
        let content = r"
[core]
Include = /etc/pacman.d/mirrorlist

[extra]
Include = /etc/pacman.d/mirrorlist

[custom-repo]
Server = https://example.com/$repo/$arch
";

        let config = PacmanConfig::parse_str(content).unwrap();
        let names = config.get_repo_names();
        assert_eq!(names, vec!["core", "extra", "custom-repo"]);
    }
}
