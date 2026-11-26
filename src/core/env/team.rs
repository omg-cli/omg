//! Team collaboration features for shared environment management
//!
//! Provides:
//! - Team workspaces with centralized lock management
//! - Git-based sync with automatic drift detection
//! - Real-time team status dashboard
//! - Conflict resolution for environment changes

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{ErrorKind, Read as _, Write as _};
use std::path::{Path, PathBuf};

use super::fingerprint::EnvironmentState;

/// Check whether a team remote URL is an HTTPS gist.github.com URL.
///
/// Matches the strict validation in `src/cli/team.rs::validate_team_remote`:
/// the URL must parse cleanly and its host must be exactly
/// `gist.github.com` (https scheme). Substring checks would accept
/// attacker-controlled URLs like `https://evil.com/gist.github.com`, and
/// this remote becomes the trust source for team sync.
fn is_gist_remote(remote_url: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(remote_url) else {
        return false;
    };
    url.scheme() == "https" && url.host_str() == Some("gist.github.com")
}

/// Team configuration stored in `.omg/team.toml`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamConfig {
    /// Team identifier (e.g., "mycompany/frontend")
    pub team_id: String,
    /// Display name for the team
    pub name: String,
    /// Current user's identifier
    pub member_id: String,
    /// Remote sync URL (GitHub Gist; full repos are not supported)
    pub remote_url: Option<String>,
    /// Whether to auto-push on env capture
    pub auto_push: bool,
}

impl Default for TeamConfig {
    fn default() -> Self {
        Self {
            team_id: String::new(),
            name: String::new(),
            member_id: current_member_id(),
            remote_url: None,
            auto_push: false,
        }
    }
}

/// Team member status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamMember {
    /// Member identifier (username or email)
    pub id: String,
    /// Display name
    pub name: String,
    /// Current environment hash
    pub env_hash: String,
    /// Last sync timestamp
    pub last_sync: i64,
    /// Whether member is in sync with team lock
    pub in_sync: bool,
    /// Drift details if out of sync
    pub drift_summary: Option<String>,
}

/// Team status snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamStatus {
    /// Status-file format version. Files written by a NEWER omg are rejected
    /// on load instead of best-effort parsed.
    #[serde(default = "default_status_format_version")]
    pub format_version: u32,
    /// Team configuration
    pub config: TeamConfig,
    /// Current team lock hash
    pub lock_hash: String,
    /// All team members and their status
    pub members: Vec<TeamMember>,
    /// Last update timestamp
    pub updated_at: i64,
}

fn default_status_format_version() -> u32 {
    TeamStatus::STATUS_FORMAT_VERSION
}

/// Best-effort display name for the local team member.
fn local_member_name() -> String {
    whoami::realname().unwrap_or_else(|_| "Unknown".to_string())
}

/// Stable fallback identity for local team state.
fn current_member_id() -> String {
    whoami::username().unwrap_or_else(|_| "unknown".to_string())
}

pub(crate) const MAX_TEAM_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Read a bounded snapshot from a regular team file opened without following the final link.
pub(crate) fn read_regular_file(path: &Path, what: &str) -> Result<String> {
    let check_type = |metadata: &std::fs::Metadata| {
        anyhow::ensure!(
            metadata.is_file(),
            "{what} must be a regular file: {}",
            path.display()
        );
        Ok(())
    };
    let inspect = || format!("Failed to inspect {what}: {}", path.display());
    check_type(&std::fs::symlink_metadata(path).with_context(inspect)?)?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_NOCTTY);
    }
    let read_context = || format!("Failed to read {what}: {}", path.display());
    let file = options.open(path).with_context(read_context)?;
    let metadata = file.metadata().with_context(inspect)?;
    check_type(&metadata)?;
    let check_size = |size| {
        anyhow::ensure!(
            size <= MAX_TEAM_FILE_BYTES,
            "{what} exceeds the {MAX_TEAM_FILE_BYTES} byte limit: {}",
            path.display()
        );
        Ok(())
    };
    check_size(metadata.len())?;
    let mut content = String::with_capacity(metadata.len() as usize);
    file.take(MAX_TEAM_FILE_BYTES + 1)
        .read_to_string(&mut content)
        .with_context(read_context)?;
    check_size(content.len() as u64)?;
    Ok(content)
}

impl TeamStatus {
    /// Current team-status file format version.
    pub const STATUS_FORMAT_VERSION: u32 = 1;

    /// Count members in sync
    #[must_use]
    pub fn in_sync_count(&self) -> usize {
        self.members.iter().filter(|m| m.in_sync).count()
    }

    fn record_local(&mut self, environment: &EnvironmentState, lock_hash: String, in_sync: bool) {
        let updated_at = jiff::Timestamp::now().as_second();
        let member = TeamMember {
            id: self.config.member_id.clone(),
            name: local_member_name(),
            env_hash: environment.hash.clone(),
            last_sync: updated_at,
            in_sync,
            drift_summary: (!in_sync).then(|| "Environment differs from team lock".to_owned()),
        };

        if let Some(existing) = self.members.iter_mut().find(|m| m.id == member.id) {
            *existing = member;
        } else {
            self.members.push(member);
        }

        self.lock_hash = lock_hash;
        self.updated_at = updated_at;
    }

    fn bounded_json(&self, path: &Path) -> Result<Vec<u8>> {
        let json = serde_json::to_vec_pretty(self)?;
        anyhow::ensure!(
            json.len() as u64 <= MAX_TEAM_FILE_BYTES,
            "Team status exceeds the {MAX_TEAM_FILE_BYTES} byte limit: {}",
            path.display()
        );
        Ok(json)
    }
}

/// Team workspace manager
pub struct TeamWorkspace {
    /// Root directory of the workspace
    root: PathBuf,
    /// Team configuration
    config: Option<TeamConfig>,
}

impl TeamWorkspace {
    /// Create a new team workspace manager.
    ///
    /// A missing team config means the directory is not initialized. Existing
    /// but unreadable or malformed config is rejected rather than treated as
    /// absent.
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        Self::validate_config_dir(&root)?;
        let config_path = root.join(".omg/team.toml");
        let config = match std::fs::symlink_metadata(&config_path) {
            Ok(metadata) => {
                anyhow::ensure!(
                    !metadata.file_type().is_symlink() && metadata.is_file(),
                    "Team config must be a regular file: {}",
                    config_path.display()
                );
                Some(Self::load_config(&root)?)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("Failed to inspect team config: {}", config_path.display())
                });
            }
        };
        Ok(Self { root, config })
    }

    fn validate_config_dir(root: &Path) -> Result<()> {
        let config_dir = root.join(".omg");
        match std::fs::symlink_metadata(&config_dir) {
            Ok(metadata) => {
                anyhow::ensure!(
                    !metadata.file_type().is_symlink() && metadata.is_dir(),
                    "Team config path must be a real directory: {}",
                    config_dir.display()
                );
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| {
                format!(
                    "Failed to inspect team config directory: {}",
                    config_dir.display()
                )
            }),
        }
    }

    fn ensure_config_dir(&self) -> Result<()> {
        Self::validate_config_dir(&self.root)?;
        std::fs::create_dir_all(self.config_dir())
            .context("Failed to create team config directory")?;
        Self::validate_config_dir(&self.root)
    }

    /// Get the team config directory
    fn config_dir(&self) -> PathBuf {
        self.root.join(".omg")
    }

    /// Get the team config file path
    fn config_path(&self) -> PathBuf {
        self.config_dir().join("team.toml")
    }

    /// Get the team status file path
    fn status_path(&self) -> PathBuf {
        self.config_dir().join("team-status.json")
    }

    /// Check if this is a team workspace
    #[must_use]
    pub fn is_team_workspace(&self) -> bool {
        self.config.is_some()
    }

    /// Get the team configuration
    #[must_use]
    pub fn config(&self) -> Option<&TeamConfig> {
        self.config.as_ref()
    }

    /// Load team configuration from disk
    fn load_config(root: &Path) -> Result<TeamConfig> {
        Self::validate_config_dir(root)?;
        let path = root.join(".omg/team.toml");
        let content = read_regular_file(&path, "Team config")?;
        toml::from_str(&content).context("Failed to parse team config")
    }

    /// Initialize a new team workspace.
    ///
    /// Refuses to run in a directory that is already initialized: the existing
    /// `team.toml` and member status are durable shared state, and silently
    /// resetting them would destroy every teammate's record.
    pub fn init(&mut self, team_id: &str, name: &str) -> Result<()> {
        if let Some(existing) = self.config.as_ref() {
            anyhow::bail!(
                "This directory is already initialized as team '{}' ({}). \
                 Remove .omg/team.toml first if you really want to re-initialize.",
                crate::cli::style::sanitize_terminal_text(&existing.name),
                crate::cli::style::sanitize_terminal_text(&existing.team_id)
            );
        }
        let hooks_dir = self.preflight_git_hooks()?;
        self.ensure_config_dir()?;

        let config = TeamConfig {
            team_id: team_id.to_string(),
            name: name.to_string(),
            member_id: current_member_id(),
            remote_url: None,
            auto_push: false,
        };

        // Create initial status
        let status = TeamStatus {
            format_version: TeamStatus::STATUS_FORMAT_VERSION,
            config: config.clone(),
            lock_hash: String::new(),
            members: vec![TeamMember {
                id: config.member_id.clone(),
                name: local_member_name(),
                env_hash: String::new(),
                last_sync: jiff::Timestamp::now().as_second(),
                in_sync: true,
                drift_summary: None,
            }],
            updated_at: jiff::Timestamp::now().as_second(),
        };

        let status_json = serde_json::to_vec_pretty(&status)?;
        let content = toml::to_string_pretty(&config)?;
        let status_path = self.status_path();
        if !Self::publish_init_file(&status_path, &status_json)? {
            let blocked = || {
                format!(
                    "{} already exists and is not a matching initial status; move it aside to initialize a new team",
                    status_path.display()
                )
            };
            let previous: TeamStatus = read_regular_file(&status_path, "Team status")
                .and_then(|content| {
                    serde_json::from_str(&content).context("Failed to parse team status")
                })
                .with_context(blocked)?;
            anyhow::ensure!(
                previous.format_version == TeamStatus::STATUS_FORMAT_VERSION
                    && previous.config == config
                    && previous.lock_hash.is_empty()
                    && matches!(previous.members.as_slice(), [member]
                        if member.id == config.member_id
                            && member.env_hash.is_empty()
                            && member.in_sync
                            && member.drift_summary.is_none()),
                "{}",
                blocked()
            );
        }
        crate::core::safe_ops::sync_parent_directory_sync(&status_path)?;

        // Publish the config last. Its presence is the initialization marker,
        // so a retry can reuse staged status if this publication fails.
        let config_path = self.config_path();
        anyhow::ensure!(
            Self::publish_init_file(&config_path, content.as_bytes())?,
            "{} already exists; refusing to re-initialize",
            config_path.display()
        );
        self.config = Some(config);
        Self::finish_init(&config_path, hooks_dir.as_deref());
        Ok(())
    }

    fn finish_init(config_path: &Path, hooks_dir: Option<&Path>) {
        let result =
            crate::core::safe_ops::sync_parent_directory_sync(config_path).and_then(|()| {
                match hooks_dir {
                    Some(hooks_dir) => Self::install_git_hooks(hooks_dir),
                    None => Ok(()),
                }
            });
        if let Err(error) = result {
            tracing::warn!(%error, "Team initialized, but post-commit setup failed");
        }
    }

    fn publish_init_file(path: &Path, content: &[u8]) -> Result<bool> {
        let parent = path.parent().context("Team init path has no parent")?;
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(content)?;
        file.as_file().sync_all()?;
        match file.persist_noclobber(path) {
            Ok(_) => Ok(true),
            Err(error) if error.error.kind() == ErrorKind::AlreadyExists => Ok(false),
            Err(error) => {
                Err(error.error).with_context(|| format!("Failed to publish {}", path.display()))
            }
        }
    }

    /// Join an existing team workspace
    pub fn join(&mut self, remote_url: &str) -> Result<()> {
        // Fail before creating anything: joining is only valid in an
        // initialized workspace, and a failed call must not leave an empty
        // `.omg/` directory behind as a side effect.
        anyhow::ensure!(
            self.config.is_some(),
            "Not a team workspace. Run 'omg team init' first."
        );
        let mut config = Self::load_config(&self.root)?;
        self.ensure_config_dir()?;
        config.remote_url = Some(remote_url.to_string());
        let content = toml::to_string_pretty(&config)?;
        crate::core::safe_ops::atomic_write_file_sync(self.config_path(), content)?;
        self.config = Some(config);

        Ok(())
    }

    /// Update local member status
    pub async fn update_status(&self) -> Result<TeamStatus> {
        self.update_status_with_lock(false).await
    }

    async fn update_status_with_lock(&self, require_lock: bool) -> Result<TeamStatus> {
        let root = self.root.clone();
        let (guard, mut status, lock) = tokio::task::spawn_blocking(move || {
            let (guard, status) = Self::lock_status(&root)?;
            let lock_path = root.join("omg.lock");
            let lock = match std::fs::symlink_metadata(&lock_path) {
                Ok(_) => Some(EnvironmentState::load(&lock_path)?),
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    anyhow::ensure!(
                        !require_lock,
                        "No team omg.lock found. Run 'omg team push' or obtain the team's lockfile."
                    );
                    None
                }
                Err(error) => return Err(error).context("Failed to inspect the team omg.lock"),
            };
            Ok::<_, anyhow::Error>((guard, status, lock))
        })
        .await
        .context("Team status read task failed")??;

        let current_env = EnvironmentState::capture().await?;
        let in_sync = lock
            .as_ref()
            .is_none_or(|lock| current_env.matches_inventory(lock));

        let lock_hash = lock.map_or_else(String::new, |lock| lock.hash);
        status.record_local(&current_env, lock_hash, in_sync);

        let status_path = self.status_path();
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            let status_json = status.bounded_json(&status_path)?;
            crate::core::safe_ops::atomic_write_file_sync(status_path, status_json)?;
            Ok(status)
        })
        .await
        .context("Team status write task failed")?
    }

    /// Load member status and project the authoritative configuration from team.toml.
    /// Reading does not rewrite the persisted snapshot or change its update timestamp.
    pub fn load_status(&self) -> Result<TeamStatus> {
        Self::load_status_at(&self.root)
    }

    fn load_status_at(root: &Path) -> Result<TeamStatus> {
        Self::validate_config_dir(root)?;
        let path = root.join(".omg/team-status.json");
        let content = read_regular_file(&path, "Team status")?;
        let mut status: TeamStatus =
            serde_json::from_str(&content).context("Failed to parse team status")?;
        if status.format_version > TeamStatus::STATUS_FORMAT_VERSION {
            anyhow::bail!(
                "Team status {} was written by a newer omg (format version {}). Upgrade omg to read it.",
                path.display(),
                status.format_version
            );
        }
        let config = Self::load_config(root)?;
        anyhow::ensure!(
            status.config.team_id == config.team_id,
            "Team status belongs to a different team; refusing to reinterpret its member records"
        );
        status.config = config;
        Ok(status)
    }

    fn lock_status(root: &Path) -> Result<(std::fs::File, TeamStatus)> {
        Self::validate_config_dir(root)?;
        let guard = super::lock_regular_file(&root.join(".omg/team-status.lock"))?;
        Ok((guard, Self::load_status_at(root)?))
    }

    /// Push local environment to team lock
    pub async fn push(&self) -> Result<()> {
        self.config.as_ref().context("Not a team workspace")?;
        let root = self.root.clone();
        let (guard, mut status) = tokio::task::spawn_blocking(move || Self::lock_status(&root))
            .await
            .context("Team status read task failed")??;

        let state = EnvironmentState::capture().await?;
        status.record_local(&state, state.hash.clone(), true);
        let auto_push = status.config.auto_push;
        let root = self.root.clone();
        let status_path = self.status_path();
        tokio::task::spawn_blocking(move || {
            {
                let _status_guard = guard;
                let status_json = status.bounded_json(&status_path)?;
                let prepared = crate::core::safe_ops::stage_atomic_write_file_sync(
                    &status_path,
                    &status_json,
                )?;
                state.save_then(&root.join("omg.lock"), || prepared.publish())?;
            }

            // Git hooks can run environment commands, so release both guards first.
            if auto_push && Self::is_git_repo(&root) {
                Self::git_commit_lock(&root, "Update omg.lock via team push")?;
            }
            Ok(())
        })
        .await
        .context("Team push publication task failed")?
    }

    /// Pull team lock and check for drift
    pub async fn pull(&self) -> Result<bool> {
        let config = self.config.as_ref().context("Not a team workspace")?;

        // If we have a remote, fetch from it. Anything other than a Gist must
        // fail loudly: silently skipping the fetch and then reporting purely
        // local state as team sync would mislead operators into trusting a
        // comparison that never saw the team's lock.
        if let Some(remote_url) = &config.remote_url {
            if is_gist_remote(remote_url) {
                crate::cli::env::sync_at(remote_url, &self.root).await?;
            } else {
                anyhow::bail!(
                    "Unsupported team remote URL '{}': pull currently supports only HTTPS gist.github.com remotes",
                    crate::core::http::redact_url(remote_url)
                );
            }
        }

        // Update status and return whether we're in sync
        let status = self.update_status_with_lock(true).await?;
        let member = status
            .members
            .iter()
            .find(|m| m.id == status.config.member_id);

        Ok(member.is_some_and(|m| m.in_sync))
    }

    /// Check if we're in a git repository
    fn is_git_repo(root: &Path) -> bool {
        root.join(".git").exists()
    }

    fn git_path_metadata(path: &Path) -> Result<Option<std::fs::Metadata>> {
        match path.symlink_metadata() {
            Ok(metadata) => Ok(Some(metadata)),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => {
                Err(error).with_context(|| format!("Failed to inspect {}", path.display()))
            }
        }
    }

    fn preflight_git_hooks(&self) -> Result<Option<PathBuf>> {
        let git_dir = self.root.join(".git");
        let Some(metadata) = Self::git_path_metadata(&git_dir)? else {
            return Ok(None);
        };
        if !metadata.is_dir() {
            tracing::warn!("Skipping team Git hooks: .git is not a local directory");
            return Ok(None);
        }
        let hooks_dir = git_dir.join("hooks");
        anyhow::ensure!(
            Self::git_path_metadata(&hooks_dir)?.is_none_or(|metadata| metadata.is_dir()),
            "Failed to create hooks dir {}: not a real directory",
            hooks_dir.display()
        );
        Ok(Some(hooks_dir))
    }

    /// Install git hooks for auto-sync
    fn install_git_hooks(hooks_dir: &Path) -> Result<()> {
        // Pin the hook to this executable's absolute path. A bare `omg`
        // from PATH would let an earlier entry shadow the binary on every
        // pull or checkout.
        let omg = std::env::current_exe()
            .map_or_else(|_| "omg".to_string(), |exe| exe.display().to_string());
        let omg = crate::hooks::posix_single_quoted(&omg);

        match std::fs::create_dir(hooks_dir) {
            Ok(()) => {}
            Err(error)
                if error.kind() == ErrorKind::AlreadyExists
                    && hooks_dir.symlink_metadata()?.is_dir() => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("Failed to create hooks dir {}", hooks_dir.display())
                });
            }
        }

        // Never overwrite an existing hook: it may belong to another tool.
        Self::write_hook_if_absent(
            &hooks_dir.join("post-merge"),
            &format!(
                r#"#!/bin/sh
# OMG Team Sync Hook
# Auto-check for environment drift after git pull

if [ -f "omg.lock" ]; then
    echo "🔄 OMG: Checking for environment drift..."
    {omg} env check 2>/dev/null || echo "⚠️  OMG: Environment drift detected! Run 'omg env check' for details."
fi
"#,
            ),
        )?;

        Self::write_hook_if_absent(
            &hooks_dir.join("post-checkout"),
            &format!(
                r#"#!/bin/sh
# OMG Team Sync Hook
# Auto-check for environment drift after git checkout

if [ -f "omg.lock" ]; then
    {omg} env check 2>/dev/null || true
fi
"#,
            ),
        )?;

        Ok(())
    }

    /// Write a hook script and mark it executable, unless any entry already exists.
    fn write_hook_if_absent(path: &Path, content: &str) -> Result<()> {
        #[cfg(unix)]
        {
            crate::core::safe_ops::write_executable(path, content.as_bytes(), false)?;
        }
        #[cfg(not(unix))]
        {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
            {
                Ok(mut file) => {
                    use std::io::Write as _;
                    file.write_all(content.as_bytes())?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    /// Commit only omg.lock using Git's partial-commit index.
    fn git_commit_lock(root: &Path, message: &str) -> Result<()> {
        if !root.join("omg.lock").exists() {
            return Ok(());
        }

        let status = Self::git_command(
            root,
            &[
                "--no-optional-locks",
                "status",
                "--porcelain=v2",
                "--branch",
                "-z",
                "--no-renames",
                "--untracked-files=all",
                "--ignored=matching",
                "--",
                "omg.lock",
            ],
        )
        .output()
        .context("Failed to inspect Git status for omg.lock")?;
        anyhow::ensure!(
            status.status.success(),
            "git status failed: {}",
            String::from_utf8_lossy(&status.stderr).trim()
        );

        let records = status.stdout.split(|byte| *byte == 0);
        let unborn = records
            .clone()
            .any(|record| record == b"# branch.oid (initial)");
        let tracked = records.clone().any(|record| record.starts_with(b"1 "));
        let untracked = records.clone().any(|record| record == b"? omg.lock");
        anyhow::ensure!(
            !records.clone().any(|record| record == b"! omg.lock"),
            "omg.lock is ignored by Git"
        );
        anyhow::ensure!(
            !records.clone().any(|record| record.starts_with(b"u ")),
            "omg.lock has unresolved Git index conflicts"
        );

        if !tracked && !untracked {
            return Ok(());
        }
        if tracked
            && !unborn
            && Self::git_lock_matches_head(
                root,
                records.clone().any(|record| record.starts_with(b"1 D.")),
            )?
        {
            return Ok(());
        }

        if !tracked {
            // Git needs a path to be known for a partial commit. Use an intent
            // entry for a new file so a rejected hook does not stage its contents.
            let add = Self::git_command(root, &["add", "--intent-to-add", "--", "omg.lock"])
                .output()
                .context("Failed to register omg.lock with Git")?;
            anyhow::ensure!(
                add.status.success(),
                "git add failed: {}",
                String::from_utf8_lossy(&add.stderr).trim()
            );
        }

        let commit =
            Self::git_command(root, &["commit", "--only", "-m", message, "--", "omg.lock"])
                .output()
                .context("Failed to run git commit for omg.lock")?;
        if !commit.status.success() {
            let output = format!(
                "{}{}",
                String::from_utf8_lossy(&commit.stdout),
                String::from_utf8_lossy(&commit.stderr)
            );
            anyhow::bail!("git commit failed: {}", output.trim());
        }

        Ok(())
    }

    fn git_command(root: &Path, args: &[&str]) -> std::process::Command {
        let mut git = std::process::Command::new("git");
        git.args(args).current_dir(root);
        git
    }

    fn git_lock_matches_head(root: &Path, staged_deletion: bool) -> Result<bool> {
        let mut diff = Self::git_command(root, &["diff", "--quiet", "HEAD", "--", "omg.lock"]);

        // A staged deletion hides the file from diff, even though a partial
        // commit will read its working-tree copy. Compare via an index from HEAD.
        let comparison = staged_deletion.then(tempfile::tempdir).transpose()?;
        if let Some(directory) = comparison.as_ref() {
            let index = directory.path().join("index");
            let read = Self::git_command(root, &["read-tree", "HEAD"])
                .env("GIT_INDEX_FILE", &index)
                .output()
                .context("Failed to prepare Git comparison for omg.lock")?;
            anyhow::ensure!(
                read.status.success(),
                "git read-tree failed: {}",
                String::from_utf8_lossy(&read.stderr).trim()
            );
            diff.env("GIT_INDEX_FILE", index);
        }

        let changed = diff
            .output()
            .context("Failed to compare omg.lock with Git HEAD")?;
        match changed.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => anyhow::bail!(
                "git diff failed: {}",
                String::from_utf8_lossy(&changed.stderr).trim()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(root: &Path, args: &[&str]) -> Vec<u8> {
        let result = std::process::Command::new("git")
            .current_dir(root)
            .args(args)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        result.stdout
    }

    fn git_workspace() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        git(root, &["init", "--quiet"]);
        git(root, &["config", "user.name", "OMG regression"]);
        git(root, &["config", "user.email", "test@example.invalid"]);
        git(root, &["config", "commit.gpgsign", "false"]);
        git(root, &["config", "core.hooksPath", ".git/hooks"]);
        std::fs::write(root.join("seed"), "initial\n").unwrap();
        git(root, &["add", "--", "seed"]);
        git(root, &["commit", "--quiet", "-m", "Initial fixture"]);
        directory
    }

    #[test]
    fn init_in_linked_worktree_preserves_shared_hooks_and_team_state() -> Result<()> {
        let repository = git_workspace();
        let checkout = tempfile::tempdir()?;
        let root = checkout.path().join("linked worktree");
        git(repository.path(), &["config", "--unset", "core.hooksPath"]);
        let shared_hooks = repository.path().join(".git/hooks");
        std::fs::create_dir_all(&shared_hooks)?;
        std::fs::write(shared_hooks.join("post-merge"), b"existing shared hook")?;
        git(
            repository.path(),
            &["worktree", "add", "--detach", root.to_str().unwrap()],
        );
        let gitfile = root.join(".git");
        let original_gitfile = std::fs::read(&gitfile)?;
        let private_git_dir = String::from_utf8(git(&root, &["rev-parse", "--absolute-git-dir"]))?;

        let mut workspace = TeamWorkspace::new(&root)?;
        assert!(TeamWorkspace::is_git_repo(&root));
        workspace.init("worktree-team", "Worktree Team")?;

        let mut reopened = TeamWorkspace::new(&root)?;
        let status = reopened.load_status()?;
        assert_eq!(status.config.team_id, "worktree-team");
        assert_eq!(status.members.len(), 1);
        assert_eq!(status.members[0].id, status.config.member_id);
        assert!(!repository.path().join(".omg").exists());
        assert_eq!(std::fs::read(&gitfile)?, original_gitfile);
        assert_eq!(
            std::fs::read(shared_hooks.join("post-merge"))?,
            b"existing shared hook"
        );
        assert!(!shared_hooks.join("post-checkout").exists());
        assert!(!Path::new(private_git_dir.trim_end()).join("hooks").exists());

        let config = std::fs::read(reopened.config_path())?;
        let status = std::fs::read(reopened.status_path())?;
        let error = reopened.init("other-team", "Other Team").unwrap_err();
        assert!(error.to_string().contains("already initialized"));
        assert_eq!(std::fs::read(reopened.config_path())?, config);
        assert_eq!(std::fs::read(reopened.status_path())?, status);
        Ok(())
    }

    #[test]
    fn init_can_retry_after_hook_directory_failure() -> Result<()> {
        let repository = git_workspace();
        let root = repository.path();
        let hooks = root.join(".git/hooks");
        let saved_hooks = root.join(".git/saved-hooks");
        std::fs::create_dir_all(&hooks)?;
        std::fs::write(hooks.join("post-merge"), b"existing hook")?;
        std::fs::rename(&hooks, &saved_hooks)?;
        std::fs::write(&hooks, b"not a directory")?;

        let mut workspace = TeamWorkspace::new(root)?;
        let error = workspace.init("retry-team", "Retry Team").unwrap_err();
        assert!(error.to_string().contains("Failed to create hooks dir"));
        assert!(!workspace.is_team_workspace());
        assert!(!workspace.config_path().exists());
        assert!(!workspace.status_path().exists());
        assert!(!TeamWorkspace::new(root)?.is_team_workspace());
        assert_eq!(std::fs::read(&hooks)?, b"not a directory");

        std::fs::remove_file(&hooks)?;
        std::fs::rename(&saved_hooks, &hooks)?;
        workspace.init("retry-team", "Retry Team")?;

        let status = TeamWorkspace::new(root)?.load_status()?;
        assert_eq!(status.config.team_id, "retry-team");
        assert_eq!(std::fs::read(hooks.join("post-merge"))?, b"existing hook");
        let installed = hooks.join("post-checkout");
        assert!(std::fs::read_to_string(&installed)?.contains("OMG Team Sync Hook"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_ne!(installed.metadata()?.permissions().mode() & 0o111, 0);
        }
        Ok(())
    }

    #[test]
    fn init_can_retry_after_status_or_config_publication_fails() -> Result<()> {
        for block_status in [true, false] {
            let repository = git_workspace();
            let root = repository.path();
            let hooks = root.join(".git/hooks");
            std::fs::create_dir_all(&hooks)?;
            let existing_hook = hooks.join("post-merge");
            std::fs::write(&existing_hook, b"original hook")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&existing_hook, std::fs::Permissions::from_mode(0o711))?;
            }

            let mut workspace = TeamWorkspace::new(root)?;
            std::fs::create_dir(workspace.config_dir())?;
            let unrelated = workspace.config_dir().join("unrelated");
            std::fs::write(&unrelated, b"existing workspace data")?;
            let (blocked, unpublished) = if block_status {
                (workspace.status_path(), workspace.config_path())
            } else {
                (workspace.config_path(), workspace.status_path())
            };
            std::fs::create_dir(&blocked)?;
            std::fs::write(blocked.join("keep"), b"existing obstruction data")?;

            let error = workspace.init("retry-team", "Retry Team").unwrap_err();
            assert!(format!("{error:#}").contains(blocked.to_str().unwrap()));
            assert!(!workspace.is_team_workspace());
            assert!(!hooks.join("post-checkout").exists());
            assert_eq!(std::fs::read(&existing_hook)?, b"original hook");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                assert_eq!(
                    existing_hook.metadata()?.permissions().mode() & 0o777,
                    0o711
                );
            }
            assert_eq!(std::fs::read(&unrelated)?, b"existing workspace data");
            assert_eq!(
                std::fs::read(blocked.join("keep"))?,
                b"existing obstruction data"
            );
            let staged = if block_status {
                assert!(!unpublished.exists());
                None
            } else {
                Some(std::fs::read(&unpublished)?)
            };

            std::fs::remove_file(blocked.join("keep"))?;
            std::fs::remove_dir(&blocked)?;
            let mut workspace = TeamWorkspace::new(root)?;
            assert!(!workspace.is_team_workspace());
            workspace.init("retry-team", "Retry Team")?;
            assert_eq!(
                TeamWorkspace::new(root)?.load_status()?.config.team_id,
                "retry-team"
            );
            assert!(hooks.join("post-checkout").is_file());
            assert_eq!(std::fs::read(&existing_hook)?, b"original hook");
            assert_eq!(std::fs::read(&unrelated)?, b"existing workspace data");
            if let Some(staged) = staged {
                assert_eq!(std::fs::read(workspace.status_path())?, staged);
            }
        }
        Ok(())
    }

    #[test]
    fn init_refuses_to_overwrite_status_without_a_team_config() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut workspace = TeamWorkspace::new(directory.path())?;
        std::fs::create_dir(workspace.config_dir())?;
        std::fs::write(workspace.status_path(), b"pre-existing status")?;

        let error = workspace.init("other-team", "Other Team").unwrap_err();
        assert!(error.to_string().contains("already exists"));
        assert_eq!(
            std::fs::read(workspace.status_path())?,
            b"pre-existing status"
        );
        assert!(!workspace.config_path().exists());
        Ok(())
    }

    #[test]
    fn init_preserves_valid_staged_status_when_retried_with_a_different_team() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut workspace = TeamWorkspace::new(directory.path())?;
        std::fs::create_dir(workspace.config_dir())?;
        std::fs::create_dir(workspace.config_path())?;
        assert!(workspace.init("original-team", "Original").is_err());
        let staged = std::fs::read(workspace.status_path())?;
        std::fs::remove_dir(workspace.config_path())?;

        let error = workspace.init("other-team", "Other").unwrap_err();
        assert!(error.to_string().contains("not a matching initial status"));
        assert_eq!(std::fs::read(workspace.status_path())?, staged);
        assert!(!workspace.config_path().exists());

        workspace.init("original-team", "Original")?;
        assert_eq!(std::fs::read(workspace.status_path())?, staged);
        Ok(())
    }

    #[test]
    fn init_preflight_does_not_treat_git_stat_errors_as_absence() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("root");
        let mut workspace = TeamWorkspace::new(&root)?;
        assert!(!TeamWorkspace::is_git_repo(&root));
        std::fs::write(&root, b"not a directory")?;

        let error = workspace.init("team", "Team").unwrap_err();
        assert!(error.to_string().contains("Failed to inspect"));
        assert_eq!(std::fs::read(root)?, b"not a directory");
        assert!(!workspace.is_team_workspace());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn init_publication_errors_other_than_collision_are_reported() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("x".repeat(1024));
        let error = TeamWorkspace::publish_init_file(&path, b"state").unwrap_err();
        assert!(error.to_string().contains("Failed to publish"));
        assert_eq!(std::fs::read_dir(directory.path())?.count(), 0);
        Ok(())
    }

    #[test]
    fn init_post_commit_hook_failure_leaves_committed_state_and_the_obstruction() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut workspace = TeamWorkspace::new(directory.path())?;
        workspace.init("team", "Team")?;
        let config = std::fs::read(workspace.config_path())?;
        let status = std::fs::read(workspace.status_path())?;
        let git = directory.path().join(".git");
        std::fs::create_dir(&git)?;
        let hooks_dir = workspace.preflight_git_hooks()?.unwrap();
        std::fs::write(&hooks_dir, b"existing obstruction")?;

        TeamWorkspace::finish_init(&workspace.config_path(), Some(&hooks_dir));

        assert_eq!(std::fs::read(hooks_dir)?, b"existing obstruction");
        assert_eq!(std::fs::read(workspace.config_path())?, config);
        assert_eq!(std::fs::read(workspace.status_path())?, status);
        assert!(TeamWorkspace::new(directory.path())?.is_team_workspace());
        Ok(())
    }

    #[test]
    fn init_creates_missing_hooks_directory_after_committing() -> Result<()> {
        let repository = tempfile::tempdir()?;
        git(repository.path(), &["init", "--quiet", "--template="]);
        let hooks = repository.path().join(".git/hooks");
        assert!(!hooks.exists());
        TeamWorkspace::new(repository.path())?.init("team", "Team")?;
        assert!(TeamWorkspace::new(repository.path())?.is_team_workspace());
        assert!(hooks.join("post-merge").is_file());
        assert!(hooks.join("post-checkout").is_file());
        Ok(())
    }

    #[test]
    fn team_lock_commit_preserves_unrelated_staged_and_unstaged_changes() {
        let directory = git_workspace();
        let root = directory.path();
        std::fs::write(root.join("other.txt"), "staged secret\n").unwrap();
        git(root, &["add", "--", "other.txt"]);
        std::fs::write(root.join("other.txt"), "unstaged work\n").unwrap();
        std::fs::write(root.join("intent.txt"), "not staged\n").unwrap();
        git(root, &["add", "--intent-to-add", "--", "intent.txt"]);
        let staged = git(
            root,
            &["ls-files", "--stage", "-v", "--", "other.txt", "intent.txt"],
        );

        for contents in ["first lock\n", "updated lock\n"] {
            std::fs::write(root.join("omg.lock"), contents).unwrap();
            TeamWorkspace::git_commit_lock(root, "Team lock update").unwrap();
            assert_eq!(
                git(root, &["show", "--format=", "--name-only", "HEAD"]),
                b"omg.lock\n"
            );
            assert_eq!(git(root, &["show", "HEAD:omg.lock"]), contents.as_bytes());
            assert_eq!(
                git(
                    root,
                    &["ls-files", "--stage", "-v", "--", "other.txt", "intent.txt"]
                ),
                staged
            );
            assert_eq!(
                std::fs::read(root.join("other.txt")).unwrap(),
                b"unstaged work\n"
            );
            let head = git(root, &["rev-parse", "HEAD"]);
            TeamWorkspace::git_commit_lock(root, "Unchanged team lock").unwrap();
            assert_eq!(git(root, &["rev-parse", "HEAD"]), head);
            assert_eq!(
                git(
                    root,
                    &["ls-files", "--stage", "-v", "--", "other.txt", "intent.txt"]
                ),
                staged
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejected_team_lock_commit_preserves_unrelated_index_entries() {
        use std::os::unix::fs::PermissionsExt;

        let directory = git_workspace();
        let root = directory.path();
        std::fs::write(root.join("other.txt"), "staged secret\n").unwrap();
        git(root, &["add", "--", "other.txt"]);
        let staged = git(root, &["ls-files", "--stage", "--", "other.txt"]);
        let head = git(root, &["rev-parse", "HEAD"]);
        std::fs::write(root.join("omg.lock"), "new lock\n").unwrap();
        let hook = root.join(".git/hooks/pre-commit");
        std::fs::write(&hook, "#!/bin/sh\necho 'nothing to commit' >&2\nexit 1\n").unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(TeamWorkspace::git_commit_lock(root, "Rejected update").is_err());
        assert_eq!(git(root, &["rev-parse", "HEAD"]), head);
        assert_eq!(
            git(root, &["ls-files", "--stage", "--", "other.txt"]),
            staged
        );
        assert_eq!(std::fs::read(root.join("omg.lock")).unwrap(), b"new lock\n");
        assert_eq!(
            std::fs::read(root.join("other.txt")).unwrap(),
            b"staged secret\n"
        );
    }

    #[test]
    fn status_uses_current_team_config_without_rewriting_members() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut workspace = TeamWorkspace::new(directory.path())?;
        workspace.init("fixture-team", "Before")?;
        let persisted = std::fs::read(workspace.status_path())?;
        let initial: TeamStatus = serde_json::from_slice(&persisted)?;
        workspace.join("https://gist.github.com/fixture/lock")?;
        let mut config = workspace.config().unwrap().clone();
        config.name = "After".into();
        std::fs::write(workspace.config_path(), toml::to_string(&config)?)?;
        for status in [
            workspace.load_status()?,
            TeamWorkspace::new(directory.path())?.load_status()?,
        ] {
            assert_eq!(status.config.name, "After");
            assert_eq!(
                status.config.remote_url.as_deref(),
                Some("https://gist.github.com/fixture/lock")
            );
            assert_eq!(
                serde_json::to_value(&status.members)?,
                serde_json::to_value(&initial.members)?
            );
        }
        assert_eq!(std::fs::read(workspace.status_path())?, persisted);
        Ok(())
    }

    #[test]
    fn status_rejects_a_different_team_without_rewriting_data() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut workspace = TeamWorkspace::new(directory.path())?;
        workspace.init("original-team", "Fixture")?;
        let persisted = std::fs::read(workspace.status_path())?;
        let mut config = workspace.config().unwrap().clone();
        config.team_id = "different-team".into();
        std::fs::write(workspace.config_path(), toml::to_string(&config)?)?;
        assert!(workspace.load_status().is_err());
        assert_eq!(std::fs::read(workspace.status_path())?, persisted);
        Ok(())
    }

    #[test]
    fn failed_join_does_not_change_in_memory_config() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut workspace = TeamWorkspace::new(directory.path())?;
        workspace.init("fixture-team", "Fixture")?;
        std::fs::remove_file(workspace.config_path())?;
        std::fs::create_dir(workspace.config_path())?;
        assert!(
            workspace
                .join("https://gist.github.com/fixture/lock")
                .is_err()
        );
        assert!(workspace.config().unwrap().remote_url.is_none());
        Ok(())
    }

    #[test]
    fn gist_remote_accepts_https_gist_host() {
        assert!(is_gist_remote("https://gist.github.com/user/abc123"));
        assert!(is_gist_remote("https://gist.github.com/"));
    }

    #[test]
    fn gist_remote_rejects_attacker_urls_embedding_the_host() {
        // Substring checks would accept these; the remote becomes the trust
        // source for team sync.
        assert!(!is_gist_remote("https://evil.com/gist.github.com"));
        assert!(!is_gist_remote(
            "https://gist.github.com.evil.com/user/abc123"
        ));
        assert!(!is_gist_remote("https://evil.com?q=gist.github.com"));
        assert!(!is_gist_remote(
            "https://gist.github.com@evil.com/user/abc123"
        ));
    }

    #[test]
    fn gist_remote_rejects_non_https_schemes() {
        assert!(!is_gist_remote("http://gist.github.com/user/abc123"));
        assert!(!is_gist_remote("ftp://gist.github.com/user/abc123"));
    }

    #[test]
    fn gist_remote_rejects_lookalike_and_repo_hosts() {
        // Only the exact gist host is accepted; repo remotes are not supported.
        assert!(!is_gist_remote("https://gist2.github.com/user/abc123"));
        assert!(!is_gist_remote("https://github.com/example/repo.git"));
        assert!(!is_gist_remote("not a url"));
    }

    #[test]
    fn missing_team_config_is_an_uninitialized_workspace() {
        let directory = tempfile::tempdir().expect("temp dir");
        let workspace = TeamWorkspace::new(directory.path()).expect("create workspace");

        assert!(!workspace.is_team_workspace());
    }

    #[cfg(unix)]
    #[test]
    fn init_rejects_symlinked_team_config_directory() {
        use std::os::unix::fs::symlink;

        let workspace_directory = tempfile::tempdir().expect("workspace temp dir");
        let outside_directory = tempfile::tempdir().expect("outside temp dir");
        let mut workspace =
            TeamWorkspace::new(workspace_directory.path()).expect("create workspace manager");
        symlink(
            outside_directory.path(),
            workspace_directory.path().join(".omg"),
        )
        .expect("create malicious config symlink");

        let error = workspace
            .init("team-id", "Team")
            .expect_err("symlinked config directory must be rejected");

        assert!(error.to_string().contains("must be a real directory"));
        assert!(!outside_directory.path().join("team.toml").exists());
        assert!(!outside_directory.path().join("team-status.json").exists());
    }

    #[test]
    fn malformed_team_config_is_rejected_without_rewriting_it() {
        let directory = tempfile::tempdir().expect("temp dir");
        let config_dir = directory.path().join(".omg");
        std::fs::create_dir(&config_dir).expect("create config dir");
        let config_path = config_dir.join("team.toml");
        std::fs::write(&config_path, "team_id = [").expect("write malformed config");

        let error = TeamWorkspace::new(directory.path())
            .err()
            .expect("malformed config must be rejected");

        assert!(error.to_string().contains("Failed to parse team config"));
        assert_eq!(
            std::fs::read_to_string(config_path).expect("read original config"),
            "team_id = ["
        );
    }

    #[test]
    fn joined_remote_is_visible_without_rewriting_member_status() {
        let directory = tempfile::tempdir().expect("temp dir");
        let mut workspace = TeamWorkspace::new(directory.path()).expect("create workspace");
        workspace.init("team", "Team").expect("initialize team");
        let observer = TeamWorkspace::new(directory.path()).expect("create existing reader");
        let original = std::fs::read(workspace.status_path()).expect("original status");
        let original_status = workspace.load_status().expect("load original status");

        for remote in [
            "https://gist.github.com/example/first",
            "https://gist.github.com/example/second",
        ] {
            workspace.join(remote).expect("join remote");
            for reader in [&workspace, &observer] {
                let status = reader.load_status().expect("load joined status");
                assert_eq!(status.config.remote_url.as_deref(), Some(remote));
                assert_eq!(status.members.len(), original_status.members.len());
                assert_eq!(status.members[0].id, original_status.members[0].id);
                assert_eq!(status.lock_hash, original_status.lock_hash);
                assert_eq!(status.updated_at, original_status.updated_at);
            }
            let reloaded = TeamWorkspace::new(directory.path()).expect("reload workspace");
            assert_eq!(
                reloaded
                    .load_status()
                    .expect("reload status")
                    .config
                    .remote_url
                    .as_deref(),
                Some(remote)
            );
            assert_eq!(
                std::fs::read(workspace.status_path()).expect("preserved status"),
                original
            );
        }
    }

    #[test]
    fn status_projection_rejects_forward_versions_without_rewriting() {
        let directory = tempfile::tempdir().expect("temp dir");
        let mut workspace = TeamWorkspace::new(directory.path()).expect("create workspace");
        workspace.init("team", "Team").expect("initialize team");
        let mut status = workspace.load_status().expect("initial status");
        status.format_version = TeamStatus::STATUS_FORMAT_VERSION + 1;
        let bytes = serde_json::to_vec(&status).expect("serialize future status");
        std::fs::write(workspace.status_path(), &bytes).expect("write future status");
        workspace
            .join("https://gist.github.com/example/remote")
            .expect("join remote");
        assert!(
            workspace
                .load_status()
                .expect_err("reject forward version")
                .to_string()
                .contains("newer omg")
        );
        assert_eq!(
            std::fs::read(workspace.status_path()).expect("original future status"),
            bytes
        );
    }

    #[test]
    fn join_uninitialized_workspace_creates_nothing() {
        let directory = tempfile::tempdir().expect("temp dir");
        let mut workspace = TeamWorkspace::new(directory.path()).expect("create workspace");

        let error = workspace
            .join("https://gist.github.com/example")
            .expect_err("join on uninitialized workspace must fail");

        assert!(error.to_string().contains("Not a team workspace"));
        assert!(
            !directory.path().join(".omg").exists(),
            "a failed join must not create the .omg directory"
        );
    }

    #[tokio::test]
    async fn pull_rejects_non_gist_remote_instead_of_reporting_local_state() {
        let directory = tempfile::tempdir().expect("temp dir");
        let config_dir = directory.path().join(".omg");
        std::fs::create_dir(&config_dir).expect("create config dir");
        std::fs::write(
            config_dir.join("team.toml"),
            "team_id = 't'\nname = 'Team'\nmember_id = 'm'\nremote_url = 'https://github.com/example/repo.git'\nauto_push = false\n",
        )
        .expect("write team config");
        let workspace = TeamWorkspace::new(directory.path()).expect("create workspace");

        let error = workspace
            .pull()
            .await
            .expect_err("non-gist remote must fail loudly, not fake a local-only sync");

        assert!(error.to_string().contains("Unsupported team remote URL"));
    }
}
