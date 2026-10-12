//! Team collaboration CLI commands

use crate::cli::components::Components;
use crate::cli::tea::Cmd;
use crate::cli::{
    CliContext, GoldenPathCommands, LocalCommandRunner, TeamCommands, TeamRoleCommands,
};
use anyhow::{Context, Result};

use crate::cli::packages::execute_cmd;
use crate::core::env::team::TeamWorkspace;
use crate::core::license;

/// Open the team workspace for the current directory, or fail with guidance.
fn open_team_workspace() -> Result<TeamWorkspace> {
    let cwd = std::env::current_dir().context("Failed to determine current directory")?;
    let workspace = TeamWorkspace::new(&cwd)?;
    if !workspace.is_team_workspace() {
        execute_cmd(Components::error_with_suggestion(
            "Not a team workspace",
            "Run 'omg team init <team-id>' first",
        ))?;
        anyhow::bail!("Not a team workspace");
    }
    Ok(workspace)
}

/// Whether a member's last-seen timestamp falls within the active window.
fn recently_active(last_seen_at: &str, now: i64) -> bool {
    const ONE_HOUR: i64 = 3600;
    crate::cli::parse_timestamp_opt(last_seen_at)
        .is_some_and(|ts| now.saturating_sub(ts) < ONE_HOUR)
}

/// First `len` characters of a string, safe on any input (no panics on
/// multi-byte boundaries).
fn prefix(s: &str, len: usize) -> String {
    s.chars().take(len).collect()
}

impl LocalCommandRunner for TeamCommands {
    async fn execute(&self, ctx: &CliContext) -> Result<()> {
        match self {
            TeamCommands::Init { team_id, name } => init(team_id, name.as_deref(), ctx),
            TeamCommands::Join { url } => join(url, ctx).await,
            TeamCommands::Status => status(ctx).await,
            TeamCommands::Push => push(ctx).await,
            TeamCommands::Pull => pull(ctx).await,
            TeamCommands::Members => members(ctx).await,
            TeamCommands::Dashboard => dashboard(ctx).await,
            TeamCommands::Roles { command } => match command {
                TeamRoleCommands::List => roles::list(ctx),
            },
            TeamCommands::GoldenPath { command } => match command {
                GoldenPathCommands::Create {
                    name,
                    node,
                    python,
                    packages,
                } => golden_path::create(
                    name,
                    node.as_deref(),
                    python.as_deref(),
                    packages.as_deref(),
                    ctx,
                ),
                GoldenPathCommands::List => golden_path::list(ctx),
                GoldenPathCommands::Delete { name } => golden_path::delete(name, ctx),
            },
            TeamCommands::Compliance { export, enforce } => {
                compliance(export.as_deref(), *enforce, ctx)
            }
            TeamCommands::Activity { days } => activity(*days, ctx).await,
        }
    }
}

/// Initialize a new team workspace
fn validate_team_id(team_id: &str) -> Result<()> {
    anyhow::ensure!(
        !team_id.is_empty()
            && team_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_')),
        "Invalid team ID: {team_id}"
    );
    Ok(())
}

fn validate_team_remote(remote_url: &str) -> Result<()> {
    let url = reqwest::Url::parse(remote_url).context("Invalid remote URL")?;
    anyhow::ensure!(
        url.scheme() == "https" && url.host_str() == Some("gist.github.com"),
        "Team remotes must be HTTPS gist.github.com URLs"
    );
    anyhow::ensure!(
        url.path_segments()
            .into_iter()
            .flatten()
            .any(|segment| !segment.is_empty()),
        "Team remote URL must include a Gist ID"
    );
    Ok(())
}

/// Initialize a new team workspace.
pub fn init(team_id: &str, name: Option<&str>, _ctx: &CliContext) -> Result<()> {
    // SECURITY: Validate team_id
    if let Err(error) = validate_team_id(team_id) {
        return execute_cmd(Components::error_with_suggestion(
            error.to_string(),
            "Team IDs must be alphanumeric with /, -, or _ allowed",
        ));
    }
    if let Some(n) = name
        && (n.len() > 128 || n.chars().any(char::is_control))
    {
        execute_cmd(Cmd::error(
            "Invalid team name (too long or contains control characters)",
        ))?;
        anyhow::bail!("Invalid team name");
    }

    let cwd = std::env::current_dir()?;
    let mut workspace = TeamWorkspace::new(&cwd)?;

    let display_name = name.unwrap_or(team_id);

    execute_cmd(Components::loading("Initializing team workspace..."))?;

    workspace.init(team_id, display_name)?;

    execute_cmd(Cmd::batch([
        Cmd::success("Team workspace initialized!"),
        Components::kv_list(
            Some("Team Details"),
            vec![("Team ID", team_id), ("Name", display_name)],
        ),
        Cmd::spacer(),
        Cmd::header("Next Steps", ""),
        Cmd::println("  1. Run 'omg env capture' to capture your environment"),
        Cmd::println("  2. Commit 'omg.lock' to your repo"),
        Cmd::println("  3. Teammates run 'omg team pull' to sync"),
    ]))?;

    Ok(())
}

/// Join an existing team by setting remote URL
pub async fn join(remote_url: &str, _ctx: &CliContext) -> Result<()> {
    // SECURITY: Basic URL validation
    if !remote_url.starts_with("https://") {
        execute_cmd(Components::error_with_suggestion(
            "Only HTTPS URLs allowed for security",
            "Use https:// instead of http://",
        ))?;
        anyhow::bail!("Only HTTPS URLs allowed for security");
    }
    if remote_url.len() > 1024 || remote_url.chars().any(char::is_control) {
        execute_cmd(Cmd::error("Invalid remote URL"))?;
        anyhow::bail!("Invalid remote URL");
    }
    validate_team_remote(remote_url)?;

    let cwd = std::env::current_dir()?;
    let mut workspace = TeamWorkspace::new(&cwd)?;

    if !workspace.is_team_workspace() {
        // Auto-init if not a team workspace
        let team_id = extract_team_id(remote_url);
        validate_team_id(&team_id)?;
        workspace.init(&team_id, &team_id)?;
    }

    execute_cmd(Components::loading("Joining team..."))?;

    workspace.join(remote_url)?;

    // Pull the team lock
    let in_sync = workspace.pull().await?;

    if in_sync {
        execute_cmd(Cmd::batch([
            Cmd::success("Joined team successfully!"),
            Components::status_summary(vec![("Status", "In sync")]),
        ]))?;
    } else {
        execute_cmd(Cmd::batch([
            Cmd::success("Joined team successfully!"),
            Cmd::warning("Drift detected"),
            Cmd::info("Run 'omg env check' to see differences"),
        ]))?;
    }

    Ok(())
}

/// Show team status
pub async fn status(_ctx: &CliContext) -> Result<()> {
    let workspace = open_team_workspace()?;

    let team_status = workspace.update_status().await?;

    let mut details = vec![format!(
        "Team: {} ({})",
        team_status.config.name, team_status.config.team_id
    )];

    if let Some(ref url) = team_status.config.remote_url {
        details.push(format!("Remote: {}", crate::core::http::redact_url(url)));
    }

    details.push(format!(
        "Lock hash: {}",
        if team_status.lock_hash.is_empty() {
            "none".to_string()
        } else {
            format!("{}...", prefix(&team_status.lock_hash, 12))
        }
    ));

    let mut member_list = vec![];
    for member in &team_status.members {
        let status_icon = if member.in_sync { "✓" } else { "⚠" };
        member_list.push(format!(
            "{} {} - {}",
            status_icon,
            member.name,
            if member.in_sync {
                "in sync"
            } else {
                "drift detected"
            }
        ));
    }

    execute_cmd(Cmd::batch([
        Cmd::header(
            "Team Status",
            format!(
                "{}/{} members in sync",
                team_status.in_sync_count(),
                team_status.members.len()
            ),
        ),
        Cmd::spacer(),
        Cmd::card("Team Information", details),
        Cmd::spacer(),
        Cmd::card("Members", member_list),
    ]))?;

    Ok(())
}

/// Push local environment to team lock
pub async fn push(_ctx: &CliContext) -> Result<()> {
    let workspace = open_team_workspace()?;

    execute_cmd(Components::loading("Pushing environment to team lock..."))?;

    workspace.push().await?;

    execute_cmd(Cmd::batch([
        Cmd::success("Team lock updated!"),
        Cmd::info("Don't forget to commit and push omg.lock to share with teammates"),
    ]))?;

    Ok(())
}

/// Pull team lock and check for drift
pub async fn pull(_ctx: &CliContext) -> Result<()> {
    let workspace = open_team_workspace()?;

    execute_cmd(Components::loading("Pulling team lock..."))?;

    let in_sync = workspace.pull().await?;

    if in_sync {
        execute_cmd(Components::complete("Environment is in sync with team!"))?;
        Ok(())
    } else {
        execute_cmd(Cmd::batch([
            Cmd::warning("Environment drift detected!"),
            Cmd::info("Run 'omg env check' to see differences"),
        ]))?;
        anyhow::bail!("Environment drift detected")
    }
}

/// List team members
pub async fn members(_ctx: &CliContext) -> Result<()> {
    let members = license::fetch_team_members().await?;

    if members.is_empty() {
        execute_cmd(Cmd::batch([
            Cmd::header("Team Members", "No members found"),
            Cmd::spacer(),
            Cmd::info(
                "Team members appear here after machines link with `omg account link --token-stdin`",
            ),
        ]))?;
        return Ok(());
    }

    let now = jiff::Timestamp::now().as_second();

    let mut member_list = vec![];
    for member in &members {
        let last_seen_ts = crate::cli::parse_timestamp_opt(&member.last_seen_at);
        let is_active = recently_active(&member.last_seen_at, now);

        let activity_icon = if is_active { "●" } else { "○" };
        let hostname = member.hostname.as_deref().unwrap_or(&member.machine_id);
        let last_sync =
            last_seen_ts.map_or_else(|| "unknown".to_string(), crate::cli::format_short_timestamp);
        let platform = format!(
            "{} {}",
            member.os.as_deref().unwrap_or("unknown"),
            member.arch.as_deref().unwrap_or("")
        );

        member_list.push(format!(
            "{} {} ({})",
            activity_icon,
            hostname,
            prefix(&member.machine_id, 8)
        ));
        member_list.push(format!("  Last active: {last_sync}"));
        member_list.push(format!("  Platform: {platform}"));
    }

    let active_count = members
        .iter()
        .filter(|m| recently_active(&m.last_seen_at, now))
        .count();

    execute_cmd(Cmd::batch([
        Cmd::header(
            "Team Members",
            format!(
                "{} member(s), {} active in the last hour",
                members.len(),
                active_count
            ),
        ),
        Cmd::spacer(),
        Cmd::card("Members", member_list),
    ]))?;

    Ok(())
}

fn extract_team_id(url: &str) -> String {
    let Ok(url) = reqwest::Url::parse(url) else {
        return "team".to_string();
    };
    if url.host_str() != Some("gist.github.com") {
        return "team".to_string();
    }
    let id = url
        .path_segments()
        .into_iter()
        .flatten()
        .rev()
        .find(|segment| !segment.is_empty())
        .unwrap_or("team");
    format!("gist-{}", prefix(id, 8))
}

/// Interactive team dashboard (TUI)
pub async fn dashboard(_ctx: &CliContext) -> Result<()> {
    crate::cli::tui::run_with_tab(crate::cli::tui::app::Tab::Team).await
}

/// Manage team roles
pub mod roles {
    use super::{CliContext, Result};
    use crate::cli::packages::execute_cmd;
    use crate::cli::tea::Cmd;

    pub fn list(_ctx: &CliContext) -> Result<()> {
        let role_list = vec![
            "admin - Full access (push, policy, members)".to_string(),
            "lead - Can push to team lock, manage policies".to_string(),
            "developer - Can pull, cannot push without approval".to_string(),
            "readonly - Can only view status".to_string(),
        ];

        execute_cmd(Cmd::batch([
            Cmd::header("Team Roles", "Available roles"),
            Cmd::spacer(),
            Cmd::card("Role Permissions", role_list),
        ]))?;

        Ok(())
    }
}

/// Manage golden path templates
pub mod golden_path {
    use super::{CliContext, Result};
    use crate::cli::components::Components;
    use crate::cli::packages::execute_cmd;
    use crate::cli::tea::Cmd;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    #[derive(Debug, Serialize, Deserialize)]
    pub struct GoldenPathTemplate {
        pub name: String,
        pub runtimes: HashMap<String, String>,
        pub packages: Vec<String>,
        pub created_at: i64,
    }

    #[derive(Debug, Serialize, Deserialize, Default)]
    pub struct GoldenPathConfig {
        pub templates: Vec<GoldenPathTemplate>,
    }

    impl GoldenPathConfig {
        fn path() -> std::path::PathBuf {
            crate::core::paths::config_dir().join("golden-paths.toml")
        }

        pub fn load() -> Result<Self> {
            let path = Self::path();
            if path.exists() {
                let content = std::fs::read_to_string(&path)?;
                Ok(toml::from_str(&content)?)
            } else {
                Ok(Self::default())
            }
        }

        pub fn save(&self) -> Result<()> {
            let path = Self::path();
            // Atomic replacement keeps a crash from truncating the template
            // store, matching the durability of other omg config writes.
            let content = toml::to_string_pretty(self)?;
            crate::core::safe_ops::atomic_write_file_sync(path, content)
        }
    }

    pub fn create(
        name: &str,
        node: Option<&str>,
        python: Option<&str>,
        packages: Option<&str>,
        _ctx: &CliContext,
    ) -> Result<()> {
        // SECURITY: Validate all inputs
        if name.chars().any(|c| !c.is_ascii_alphanumeric() && c != '-') {
            return execute_cmd(Components::error_with_suggestion(
                "Invalid template name (alphanumeric and hyphens only)",
                "Template names must be alphanumeric with hyphens only",
            ));
        }
        if let Some(v) = node
            && let Err(e) = crate::core::security::validate_runtime_version(v)
        {
            execute_cmd(Cmd::error(format!("Invalid Node version: {e}")))?;
            return Err(e.into());
        }
        if let Some(v) = python
            && let Err(e) = crate::core::security::validate_runtime_version(v)
        {
            execute_cmd(Cmd::error(format!("Invalid Python version: {e}")))?;
            return Err(e.into());
        }
        if let Some(p) = packages {
            for pkg in p.split(',') {
                if let Err(e) = crate::core::security::validate_package_name(pkg.trim()) {
                    execute_cmd(Cmd::error(format!("Invalid package name: {e}")))?;
                    return Err(e.into());
                }
            }
        }

        let mut config = GoldenPathConfig::load()?;

        let mut runtimes = HashMap::new();
        if let Some(v) = node {
            runtimes.insert("node".to_string(), v.to_string());
        }
        if let Some(v) = python {
            runtimes.insert("python".to_string(), v.to_string());
        }

        let package_list = packages
            .map(|p| p.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();

        let template = GoldenPathTemplate {
            name: name.to_string(),
            runtimes,
            packages: package_list,
            created_at: jiff::Timestamp::now().as_second(),
        };

        // Remove existing if same name
        config.templates.retain(|t| t.name != name);
        config.templates.push(template);
        config.save()?;

        let mut details = vec![format!("Template: {}", name)];
        if let Some(v) = node {
            details.push(format!("Node: {v}"));
        }
        if let Some(v) = python {
            details.push(format!("Python: {v}"));
        }
        if let Some(p) = packages {
            details.push(format!("Packages: {p}"));
        }

        execute_cmd(Cmd::batch([
            Cmd::success(format!("Golden path '{name}' created!")),
            Cmd::card("Template Details", details),
            Cmd::spacer(),
            Cmd::info(format!(
                "Developers can now use: omg new {name} <project-name>"
            )),
        ]))?;

        Ok(())
    }

    pub fn list(_ctx: &CliContext) -> Result<()> {
        let config = GoldenPathConfig::load()?;

        if config.templates.is_empty() {
            execute_cmd(Cmd::batch([
                Cmd::header("Golden Path Templates", "No custom templates"),
                Cmd::spacer(),
                Cmd::card(
                    "Default Templates",
                    vec![
                        "react-app - Node 20, React, ESLint, Prettier".to_string(),
                        "python-api - Python 3.12, FastAPI, pytest".to_string(),
                        "go-service - Go 1.21, standard layout".to_string(),
                    ],
                ),
                Cmd::spacer(),
                Cmd::info("Create new: omg team golden-path create <name>"),
            ]))?;
        } else {
            let mut template_list = vec![];
            for t in &config.templates {
                let runtimes = t.runtimes.keys().cloned().collect::<Vec<_>>().join(", ");
                template_list.push(format!(
                    "{} - runtimes: [{}], packages: {}",
                    t.name,
                    runtimes,
                    t.packages.len()
                ));
            }

            execute_cmd(Cmd::batch([
                Cmd::header(
                    "Golden Path Templates",
                    format!("{} custom template(s)", config.templates.len()),
                ),
                Cmd::spacer(),
                Cmd::card("Available Templates", template_list),
            ]))?;
        }

        Ok(())
    }

    pub fn delete(name: &str, _ctx: &CliContext) -> Result<()> {
        let mut config = GoldenPathConfig::load()?;
        let original_len = config.templates.len();
        config.templates.retain(|t| t.name != name);

        if config.templates.len() < original_len {
            config.save()?;
            execute_cmd(Cmd::success(format!("Deleted template '{name}'")))?;
        } else {
            execute_cmd(Cmd::warning(format!("Template '{name}' not found")))?;
        }

        Ok(())
    }
}

/// Check compliance status.
///
/// Honest surface: this CLI has no local compliance-evaluation engine, so the
/// command reports exactly that instead of displaying fabricated scores.
pub fn compliance(export: Option<&str>, enforce: bool, _ctx: &CliContext) -> Result<()> {
    if enforce {
        execute_cmd(Cmd::warning(
            "Enforcement mode requested, but no compliance evaluation engine \
             exists locally; nothing can be enforced yet",
        ))?;
    }

    if let Some(path) = export {
        anyhow::bail!(
            "No compliance data is available to export to '{path}'; \
             compliance evidence requires an evaluated report"
        );
    }

    execute_cmd(Cmd::batch([
        Cmd::header("Compliance Status", "No local data"),
        Cmd::spacer(),
        Cmd::info(
            "Compliance scoring is not computed locally; \
             view evaluated results on the dashboard",
        ),
    ]))?;

    Ok(())
}

/// Show team activity stream
pub async fn activity(days: u32, _ctx: &CliContext) -> Result<()> {
    let logs = license::fetch_audit_logs().await?;

    // Apply the requested window honestly: events older than `days` are
    // excluded rather than only relabeling the header.
    let cutoff = jiff::Timestamp::now()
        .as_second()
        .saturating_sub(i64::from(days).saturating_mul(24 * 60 * 60));
    let recent: Vec<_> = logs
        .iter()
        .filter(|log| {
            crate::cli::parse_timestamp_opt(&log.created_at).is_some_and(|ts| ts >= cutoff)
        })
        .collect();

    if recent.is_empty() {
        execute_cmd(Cmd::batch([
            Cmd::header(
                format!("Team Activity (last {days} days)"),
                "No recent activity",
            ),
            Cmd::spacer(),
        ]))?;
        return Ok(());
    }

    let event_count = recent.len();
    let mut activity_list = vec![];
    for log in &recent {
        let timestamp = log.created_at.parse::<jiff::Timestamp>().map_or_else(
            |_| "unknown time".to_string(),
            |ts| ts.strftime("%Y-%m-%d %H:%M").to_string(),
        );
        let resource = log.resource_type.as_deref().unwrap_or("-").to_string();
        activity_list.push(format!("{} {} ({})", timestamp, log.action, resource));
    }

    execute_cmd(Cmd::batch([
        Cmd::header(
            format!("Team Activity (last {days} days)"),
            format!("{event_count} event(s)"),
        ),
        Cmd::spacer(),
        Cmd::card("Recent Activity", activity_list),
    ]))?;

    Ok(())
}
