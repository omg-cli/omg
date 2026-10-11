//! Team collaboration features for shared environment management
//!
//! Provides:
//! - Team workspaces with centralized lock management
//! - Git-based sync with automatic drift detection
//! - Real-time team status dashboard
//! - Conflict resolution for environment changes

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Read a durable team file after rejecting symlinks and non-regular paths.
fn read_regular_file(path: &Path, what: &str) -> Result<String> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("Failed to inspect {what}: {}", path.display()))?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink() && metadata.is_file(),
        "{what} must be a regular file: {}",
        path.display()
    );
    std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {what}: {}", path.display()))
}

impl TeamStatus {
    /// Current team-status file format version.
    pub const STATUS_FORMAT_VERSION: u32 = 1;

    /// Count members in sync
    #[must_use]
    pub fn in_sync_count(&self) -> usize {
        self.members.iter().filter(|m| m.in_sync).count()
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
                existing.name,
                existing.team_id
            );
        }
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

        // Publish the config last. Its presence is the initialization marker,
        // so a failed status write cannot leave a half-initialized workspace.
        let status_json = serde_json::to_vec_pretty(&status)?;
        crate::core::safe_ops::atomic_write_file_sync(self.status_path(), status_json)?;
        let content = toml::to_string_pretty(&config)?;
        crate::core::safe_ops::atomic_write_file_sync(self.config_path(), content)?;

        self.config = Some(config);

        // Install git hooks if in a git repo
        self.install_git_hooks()?;

        Ok(())
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
        let config = Self::load_config(&self.root)?;

        // Capture current environment
        let current_env = EnvironmentState::capture().await?;

        // Load team lock if exists
        let lock_path = self.root.join("omg.lock");
        let lock_hash = if lock_path.exists() {
            let lock = EnvironmentState::load(&lock_path)?;
            lock.hash
        } else {
            String::new()
        };

        let in_sync = lock_hash.is_empty() || current_env.hash == lock_hash;

        let member = TeamMember {
            id: config.member_id.clone(),
            name: local_member_name(),
            env_hash: current_env.hash,
            last_sync: jiff::Timestamp::now().as_second(),
            in_sync,
            drift_summary: if in_sync {
                None
            } else {
                Some("Environment differs from team lock".to_string())
            },
        };

        // Existing team state is durable data. Reject missing or malformed
        // status instead of replacing it with an empty member set. Hold a
        // cross-process flock across load-modify-save so two concurrent omg
        // invocations cannot drop each other's member updates. Uses the std
        // advisory file-lock API (stable since Rust 1.89):
        // https://doc.rust-lang.org/std/fs/struct.File.html#method.lock
        let lock_path = self.status_path().with_extension("lock");
        let mut options = std::fs::OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
        }
        let lock = options
            .open(&lock_path)
            .with_context(|| format!("Failed to open team status lock {}", lock_path.display()))?;
        lock.lock().context("Failed to acquire team status lock")?;

        let mut status = self.load_status()?;

        // Update or add member
        if let Some(existing) = status.members.iter_mut().find(|m| m.id == member.id) {
            *existing = member;
        } else {
            status.members.push(member);
        }

        status.lock_hash = lock_hash;
        status.updated_at = jiff::Timestamp::now().as_second();

        // Save status through an atomic replacement so an interruption cannot
        // truncate durable team state.
        self.ensure_config_dir()?;
        let status_json = serde_json::to_vec_pretty(&status)?;
        crate::core::safe_ops::atomic_write_file_sync(self.status_path(), status_json)?;

        Ok(status)
    }

    /// Load member status and project the authoritative configuration from team.toml.
    /// Reading does not rewrite the persisted snapshot or change its update timestamp.
    pub fn load_status(&self) -> Result<TeamStatus> {
        Self::validate_config_dir(&self.root)?;
        let path = self.status_path();
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
        let config = Self::load_config(&self.root)?;
        anyhow::ensure!(
            status.config.team_id == config.team_id,
            "Team status belongs to a different team; refusing to reinterpret its member records"
        );
        status.config = config;
        Ok(status)
    }

    /// Push local environment to team lock
    pub async fn push(&self) -> Result<()> {
        let config = self.config.as_ref().context("Not a team workspace")?;

        // Capture and save
        let state = EnvironmentState::capture().await?;
        let lock_path = self.root.join("omg.lock");
        state.save(&lock_path)?;

        // Update status
        self.update_status().await?;

        if config.auto_push && self.is_git_repo() {
            self.git_commit_lock("Update omg.lock via team push")?;
        }

        Ok(())
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
        let status = self.update_status().await?;
        let member = status.members.iter().find(|m| m.id == config.member_id);

        Ok(member.is_some_and(|m| m.in_sync))
    }

    /// Check if we're in a git repository
    fn is_git_repo(&self) -> bool {
        self.root.join(".git").exists()
    }

    /// Install git hooks for auto-sync
    fn install_git_hooks(&self) -> Result<()> {
        if !self.is_git_repo() {
            return Ok(());
        }

        // Pin the hook to this executable's absolute path. A bare `omg`
        // from PATH would let an earlier entry shadow the binary on every
        // pull or checkout.
        let omg = std::env::current_exe()
            .map_or_else(|_| "omg".to_string(), |exe| exe.display().to_string());
        let omg = crate::hooks::posix_single_quoted(&omg);

        let hooks_dir = self.root.join(".git/hooks");
        std::fs::create_dir_all(&hooks_dir)
            .with_context(|| format!("Failed to create hooks dir {}", hooks_dir.display()))?;

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

    /// Commit omg.lock to git
    fn git_commit_lock(&self, message: &str) -> Result<()> {
        use std::process::Command;

        let lock_path = self.root.join("omg.lock");
        if !lock_path.exists() {
            return Ok(());
        }

        let add = Command::new("git")
            .args(["add", "--", "omg.lock"])
            .current_dir(&self.root)
            .output()
            .context("Failed to run git add for omg.lock")?;
        if !add.status.success() {
            anyhow::bail!(
                "git add failed: {}",
                String::from_utf8_lossy(&add.stderr).trim()
            );
        }

        let changed = Command::new("git")
            .args(["diff", "--cached", "--quiet", "--", "omg.lock"])
            .current_dir(&self.root)
            .output()
            .context("Failed to inspect staged omg.lock")?;
        match changed.status.code() {
            Some(0) => return Ok(()),
            Some(1) => {}
            _ => anyhow::bail!(
                "git diff failed: {}",
                String::from_utf8_lossy(&changed.stderr).trim()
            ),
        }

        let commit = Command::new("git")
            .args(["commit", "--only", "-m", message, "--", "omg.lock"])
            .current_dir(&self.root)
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
    fn team_lock_commit_preserves_unrelated_staged_and_unstaged_changes() {
        let directory = git_workspace();
        let root = directory.path();
        let workspace = TeamWorkspace::new(root).unwrap();
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
            workspace.git_commit_lock("Team lock update").unwrap();
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
            workspace.git_commit_lock("Unchanged team lock").unwrap();
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
        let workspace = TeamWorkspace::new(root).unwrap();
        std::fs::write(root.join("other.txt"), "staged secret\n").unwrap();
        git(root, &["add", "--", "other.txt"]);
        let staged = git(root, &["ls-files", "--stage", "--", "other.txt"]);
        let head = git(root, &["rev-parse", "HEAD"]);
        std::fs::write(root.join("omg.lock"), "new lock\n").unwrap();
        let hook = root.join(".git/hooks/pre-commit");
        std::fs::write(&hook, "#!/bin/sh\necho 'nothing to commit' >&2\nexit 1\n").unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(workspace.git_commit_lock("Rejected update").is_err());
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
