//! Command-line argument definitions using clap derive macros.

use clap::{Parser, Subcommand};

/// OMG - The fastest unified package manager + runtime manager
///
/// 50-200x faster than traditional multi-tool workflows.
/// Manages system packages and major language runtimes in one CLI.
#[derive(Parser, Debug)]
#[command(name = "omg")]
#[command(author = "OMG Team")]
#[command(version)]
#[command(about = "The fastest unified package manager + runtime manager", long_about = None)]
#[command(propagate_version = true)]
#[command(subcommand_required = true)]
#[command(arg_required_else_help = true)]
pub struct Cli {
    /// Increase verbosity; -v also streams package build output live
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Suppress non-essential output: log messages above errors and
    /// fast-path success banners. Command results still print.
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Output in JSON format (for scripting)
    #[arg(long, global = true)]
    pub json: bool,

    /// Show all commands including advanced ones
    #[arg(long = "all-commands", global = true)]
    pub all: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    // ═══════════════════════════════════════════════════════════════════════
    // PACKAGE MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════
    /// Search for packages across configured repositories (12-24x faster)
    #[command(visible_alias = "s", next_help_heading = "Package Management")]
    Search {
        /// Package name or keyword to search for (e.g., firefox)
        query: String,
        /// Show detailed source metadata (votes, popularity where available)
        #[arg(short, long)]
        detailed: bool,
        /// Search official repositories only (skip community sources)
        #[arg(long)]
        no_aur: bool,
        /// Maximum number of results to display
        #[arg(short, long, default_value = "15")]
        limit: usize,
    },

    /// Install packages with security grading and source auto-detection
    #[command(visible_alias = "i")]
    Install {
        /// Package names to install (omit to search interactively)
        packages: Vec<String>,
        /// Skip confirmation
        #[arg(short = 'y', long)]
        yes: bool,
        /// Show what would be installed without making changes
        #[arg(long)]
        dry_run: bool,
        /// Force PKGBUILD review for each AUR build (on by default; see aur.review_pkgbuild)
        #[arg(long)]
        review: bool,
        /// Explicitly permit installation from local package archives
        #[arg(long)]
        allow_local_file: bool,
    },

    /// Remove packages (with optional dependency cleanup)
    #[command(visible_alias = "r")]
    Remove {
        /// Package names to remove
        #[arg(required = true)]
        packages: Vec<String>,
        /// Also remove unused dependencies (Arch backend only)
        #[arg(short, long)]
        recursive: bool,
        /// Skip confirmation
        #[arg(short = 'y', long)]
        yes: bool,
        /// Show what would be removed without making changes
        #[arg(long)]
        dry_run: bool,
    },

    /// Update all packages (system + runtimes)
    #[command(visible_alias = "u")]
    Update {
        /// Only list updates, don't install
        #[arg(short, long)]
        check: bool,
        /// Skip confirmation
        #[arg(short = 'y', long)]
        yes: bool,
        /// Show what would be updated without making changes
        #[arg(long)]
        dry_run: bool,
        /// Force PKGBUILD review for each AUR build (on by default; see aur.review_pkgbuild)
        #[arg(long)]
        review: bool,
        /// Skip refreshing package databases (use the cached view)
        #[arg(long)]
        no_sync: bool,
        /// Update AUR packages only; skip official database sync and system upgrade (Arch only)
        #[arg(long, conflicts_with_all = ["fast", "turbo"])]
        aur_only: bool,
        /// Fast mode: sync + upgrade in single operation (no preview)
        #[arg(short, long)]
        fast: bool,
        /// Turbo mode: skip sync, use cached data, parallel extraction (fastest)
        #[arg(short = 'T', long)]
        turbo: bool,
    },

    /// Show package information
    Info {
        /// Package name to look up (e.g., firefox)
        package: String,
    },

    /// Explain why a package is installed (dependency chain)
    Why {
        /// Package name to explain
        package: String,
        /// Show reverse dependencies (what depends on this)
        #[arg(short, long)]
        reverse: bool,
    },

    /// Show what packages would be updated
    Outdated,

    /// Show disk usage by packages
    Size {
        /// Show dependency tree for a specific package
        #[arg(short, long)]
        tree: Option<String>,
        /// Number of top packages to show
        #[arg(short, long, default_value = "20")]
        limit: usize,
    },

    /// Show when and why a package was installed
    Blame {
        /// Package name
        package: String,
    },

    /// Compare two environment lock files
    Diff {
        /// First lock file (default: current environment)
        #[arg(short, long)]
        from: Option<String>,
        /// Second lock file to compare against
        to: String,
    },

    /// Create or restore environment snapshots
    Snapshot {
        #[command(subcommand)]
        command: SnapshotCommands,
    },

    /// Generate CI/CD configuration
    Ci {
        #[command(subcommand)]
        command: CiCommands,
    },

    /// Cross-distro migration tools
    Migrate {
        #[command(subcommand)]
        command: MigrateCommands,
    },

    /// Clean up orphan packages and caches
    Clean {
        /// Remove orphan packages (dependencies no longer needed)
        #[arg(short, long)]
        orphans: bool,
        /// Clear package cache
        #[arg(short, long)]
        cache: bool,
        /// Clear build directories for source-based installs
        #[arg(long)]
        aur: bool,
        /// Remove all (orphans + cache + aur)
        #[arg(short = 'a', long)]
        all: bool,
        /// Show what would be cleaned without making changes
        #[arg(long)]
        dry_run: bool,
        /// Skip confirmation
        #[arg(short = 'y', long)]
        yes: bool,
    },

    /// List explicitly installed packages
    Explicit {
        /// Only print the count of explicit packages
        #[arg(short, long)]
        count: bool,
    },

    /// Print the explicitly installed package count
    #[command(name = "ec")]
    ExplicitCount,
    /// Print the total installed package count
    #[command(name = "tc")]
    TotalCount,
    /// Print the orphan package count
    #[command(name = "oc")]
    OrphanCount,
    /// Print the available update count
    #[command(name = "uc")]
    UpdateCount,

    /// Sync package databases from mirrors (parallel, fast)
    #[command(visible_alias = "sy")]
    Sync,

    // ═══════════════════════════════════════════════════════════════════════
    // RUNTIME VERSION MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════
    /// Instantly switch runtime versions (Node, Python, Rust, etc.)
    #[command(disable_version_flag = true, next_help_heading = "Runtime Management")]
    Use {
        /// Runtime to switch (node, python, go, rust, ruby, java, bun, pi,
        /// deno, zig, dotnet, erlang, php, swift)
        runtime: String,
        /// Version to use (e.g., 20.10.0, latest, lts). If omitted, detects from version file.
        version: Option<String>,
        /// Remove the version instead of switching to it
        #[arg(long)]
        uninstall: bool,
    },

    /// List installed versions (or available if --available/-A)
    #[command(visible_alias = "ls")]
    List {
        /// Runtime to list versions for (omit for all)
        runtime: Option<String>,
        /// Show available versions, not just installed
        #[arg(short = 'a', long)]
        available: bool,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // SHELL INTEGRATION
    // ═══════════════════════════════════════════════════════════════════════
    /// Print shell hook for initialization (add to .zshrc/.bashrc)
    ///
    /// Usage: eval "$(omg hook zsh)"
    #[command(next_help_heading = "Shell Integration")]
    Hook {
        /// Shell type
        #[arg(value_enum)]
        shell: ShellKind,
        /// Remove OMG shell integration from the rc file instead of printing it
        #[arg(long)]
        uninstall: bool,
    },

    /// Manage Git hooks for environment synchronization
    Hooks {
        #[command(subcommand)]
        command: HooksCommands,
    },

    /// Workspace management for monorepos
    Workspace {
        #[command(subcommand)]
        command: WorkspaceCommands,
    },

    /// Internal: Called by shell hook on directory change
    #[command(hide = true)]
    HookEnv {
        /// Shell type
        #[arg(short, long, value_enum, default_value_t = ShellKind::Zsh)]
        shell: ShellKind,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // DAEMON & CONFIG
    // ═══════════════════════════════════════════════════════════════════════
    /// Start the OMG daemon
    #[cfg(unix)]
    #[command(next_help_heading = "System & Configuration")]
    Daemon {
        /// Run in foreground (don't daemonize)
        #[arg(short, long)]
        foreground: bool,
    },

    /// Get or set configuration
    Config {
        #[command(subcommand)]
        command: Option<ConfigCommands>,
    },

    /// Manage your privacy settings and data (GDPR/CCPA)
    Privacy {
        #[command(subcommand)]
        command: Option<PrivacyCommands>,
    },

    /// Generate man pages for OMG commands
    GenerateMan {
        /// Output directory for man pages (default: ~/.local/share/man/man1)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Show detailed daemon status
    #[cfg(unix)]
    DaemonStatus,

    /// Generate shell completions
    Completions {
        /// Shell type (bash, zsh, fish, powershell, elvish)
        #[arg(value_enum)]
        shell: ShellKind,
        /// Print to stdout instead of installing
        #[arg(long)]
        stdout: bool,
    },

    /// Show which version of a runtime would be used
    Which {
        /// Runtime name (node, python, go, etc.)
        runtime: String,
    },

    /// Internal: Dynamic shell completions
    #[command(hide = true)]
    Complete {
        /// Shell requesting completions. Suggestions are shell-agnostic word
        /// lists valid for every supported shell; this validates the caller.
        #[arg(short, long, value_enum)]
        shell: ShellKind,
        /// Current word being completed
        #[arg(short, long, allow_hyphen_values = true)]
        current: String,
        /// Last word on the command line
        #[arg(short, long, allow_hyphen_values = true)]
        last: String,
        /// Full command line
        #[arg(short, long)]
        full: Option<String>,
    },

    /// Show system status
    Status {
        /// Use fast path (counts only, skips full dependency scan)
        #[arg(long, short)]
        fast: bool,
    },

    /// Check system health and environment configuration (exit 0: healthy, exit 1: issues found)
    Doctor {
        /// Test network connectivity to package mirrors
        #[arg(long)]
        network: bool,
        /// Check for end-of-life runtime versions
        #[arg(long)]
        eol: bool,
        /// Prime sudo credentials for prompt-light package operations
        #[arg(long, conflicts_with_all = ["network", "eol"])]
        turbo: bool,
    },

    /// Security audit and compliance tools
    Audit {
        #[command(subcommand)]
        command: Option<AuditCommands>,
    },

    /// Run project tasks with auto-detected runtime versions
    #[command(next_help_heading = "Development Tools")]
    Run {
        /// The task to run (e.g., build, test, start)
        #[arg(required = true)]
        task: String,

        /// Arguments to pass to the task
        #[arg(last = true)]
        args: Vec<String>,

        /// Watch mode: re-run task on file changes
        #[arg(short, long, conflicts_with_all = ["parallel", "using", "all"])]
        watch: bool,

        /// Run multiple tasks in parallel (comma-separated)
        #[arg(short, long, conflicts_with_all = ["watch", "using", "all"])]
        parallel: bool,

        /// Ecosystem to use (e.g., node, rust, python, make)
        #[arg(short, long, conflicts_with_all = ["watch", "parallel", "all"])]
        using: Option<String>,

        /// Run task across all detected ecosystems
        #[arg(short, long, conflicts_with_all = ["watch", "parallel", "using"])]
        all: bool,
    },

    /// Create a new project from a template
    #[command(visible_alias = "create")]
    New {
        /// Stack template (rust, react, node, python, go)
        #[arg(required = true, value_enum)]
        stack: ProjectStack,

        /// Project name
        #[arg(required = true)]
        name: String,
    },

    /// Manage cross-ecosystem dev tools (e.g., ripgrep, jq, tldr)
    Tool {
        #[command(subcommand)]
        command: ToolCommands,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // TEAM & ENVIRONMENT
    // ═══════════════════════════════════════════════════════════════════════
    /// Environment management (fingerprinting, drift detection)
    #[command(next_help_heading = "Team & Enterprise")]
    Env {
        #[command(subcommand)]
        command: EnvCommands,
    },

    /// Team collaboration (shared locks, sync, status)
    Team {
        #[command(subcommand)]
        command: TeamCommands,
    },

    /// Container management (Docker/Podman)
    Container {
        #[command(subcommand)]
        command: ContainerCommands,
    },

    /// Optional dashboard account (usage tracking)
    #[cfg(feature = "license")]
    Account {
        #[command(subcommand)]
        command: AccountCommands,
    },

    /// Fleet management for enterprise (multi-machine)
    Fleet {
        #[command(subcommand)]
        command: FleetCommands,
    },

    /// Enterprise features (reports, policies, compliance)
    Enterprise {
        #[command(subcommand)]
        command: EnterpriseCommands,
    },

    /// View package transaction history
    History {
        /// Number of entries to show
        #[arg(short, long, default_value = "20")]
        limit: usize,
        /// Search for a specific package in history
        #[arg(short, long)]
        search: Option<String>,
        /// Filter by transaction type (install, remove, update, sync)
        #[arg(short = 't', long = "type", value_enum)]
        transaction_type: Option<TransactionTypeFilter>,
        /// Filter transactions from this date (YYYY-MM-DD)
        #[arg(long)]
        from: Option<String>,
        /// Filter transactions until this date (YYYY-MM-DD)
        #[arg(long)]
        to: Option<String>,
    },

    /// Roll back to a previous system state
    Rollback {
        /// Transaction ID to roll back to (selects most recent if not specified)
        id: Option<String>,
        /// Auto-confirm without prompting (required in non-interactive mode)
        #[arg(short = 'y', long)]
        yes: bool,
    },

    /// Launch the interactive TUI dashboard for system monitoring and management
    #[command(visible_alias = "d", next_help_heading = "System & Configuration")]
    Dash,

    /// Show usage statistics (time saved, commands used, etc.)
    Stats,

    /// Show system metrics (Prometheus-style)
    #[cfg(unix)]
    Metrics,

    /// Update OMG to the latest version
    #[command(visible_alias = "up", disable_version_flag = true)]
    SelfUpdate {
        /// Force update even if already latest
        #[arg(long)]
        force: bool,
        /// Update to a specific version
        #[arg(long)]
        version: Option<String>,
    },

    /// Interactive first-run setup wizard
    ///
    /// Configures shell hooks, daemon startup, and captures initial environment.
    /// Reduces time from install to first successful command to <2 minutes.
    Init {
        /// Run in non-interactive mode with defaults
        #[arg(long)]
        defaults: bool,
        /// Skip shell hook installation
        #[arg(long)]
        skip_shell: bool,
        /// Skip daemon setup
        #[arg(long)]
        skip_daemon: bool,
    },
}

/// Transaction kinds accepted by `omg history --type`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum TransactionTypeFilter {
    Install,
    Remove,
    Update,
    Sync,
}

/// Shells supported by `omg completions`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum ShellKind {
    Bash,
    Zsh,
    Fish,
    #[value(alias = "pwsh")]
    Powershell,
    Elvish,
}

impl ShellKind {
    /// Canonical shell name understood by `hooks::completions`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ShellKind::Bash => "bash",
            ShellKind::Zsh => "zsh",
            ShellKind::Fish => "fish",
            ShellKind::Powershell => "powershell",
            ShellKind::Elvish => "elvish",
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum ProjectStack {
    Rust,
    React,
    Node,
    Python,
    Go,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum AuditLogSeverity {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum LicenseOutputFormat {
    Table,
    Json,
    Csv,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum VulnerabilitySeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum ComplianceFramework {
    Soc2,
    Iso27001,
    Fedramp,
    Hipaa,
    PciDss,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum CiProvider {
    Github,
    Gitlab,
    Circleci,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum EnterpriseReportType {
    Monthly,
    Quarterly,
    Custom,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum LicenseExportFormat {
    Json,
    Csv,
}

macro_rules! impl_cli_value_name {
    ($type:ty, {$($variant:path => $name:literal),+ $(,)?}) => {
        impl $type {
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $($variant => $name),+
                }
            }
        }

        impl std::fmt::Display for $type {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

impl_cli_value_name!(ProjectStack, {
    ProjectStack::Rust => "rust",
    ProjectStack::React => "react",
    ProjectStack::Node => "node",
    ProjectStack::Python => "python",
    ProjectStack::Go => "go",
});
impl_cli_value_name!(AuditLogSeverity, {
    AuditLogSeverity::Debug => "debug",
    AuditLogSeverity::Info => "info",
    AuditLogSeverity::Warning => "warning",
    AuditLogSeverity::Error => "error",
    AuditLogSeverity::Critical => "critical",
});
impl_cli_value_name!(LicenseOutputFormat, {
    LicenseOutputFormat::Table => "table",
    LicenseOutputFormat::Json => "json",
    LicenseOutputFormat::Csv => "csv",
});
impl_cli_value_name!(VulnerabilitySeverity, {
    VulnerabilitySeverity::Low => "low",
    VulnerabilitySeverity::Medium => "medium",
    VulnerabilitySeverity::High => "high",
    VulnerabilitySeverity::Critical => "critical",
});
impl_cli_value_name!(ComplianceFramework, {
    ComplianceFramework::Soc2 => "soc2",
    ComplianceFramework::Iso27001 => "iso27001",
    ComplianceFramework::Fedramp => "fedramp",
    ComplianceFramework::Hipaa => "hipaa",
    ComplianceFramework::PciDss => "pci-dss",
});
impl_cli_value_name!(CiProvider, {
    CiProvider::Github => "github",
    CiProvider::Gitlab => "gitlab",
    CiProvider::Circleci => "circleci",
});
impl_cli_value_name!(EnterpriseReportType, {
    EnterpriseReportType::Monthly => "monthly",
    EnterpriseReportType::Quarterly => "quarterly",
    EnterpriseReportType::Custom => "custom",
});
impl_cli_value_name!(LicenseExportFormat, {
    LicenseExportFormat::Json => "json",
    LicenseExportFormat::Csv => "csv",
});

#[derive(Subcommand, Debug)]
pub enum HooksCommands {
    /// Install Git hooks for environment synchronization
    Install {
        /// Force overwrite existing hooks
        #[arg(short, long)]
        force: bool,
    },
    /// Uninstall Git hooks
    Uninstall,
    /// Show installed hooks status
    Status,
    /// Run a specific hook manually
    Run {
        /// Hook name (pre-commit, post-checkout, post-merge)
        hook: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum WorkspaceCommands {
    /// Initialize a new workspace
    Init {
        /// Workspace name
        name: String,
    },
    /// Add a project to the workspace
    Add {
        /// Path to project directory
        path: String,
        /// Optional project name (defaults to directory name)
        #[arg(short, long)]
        name: Option<String>,
    },
    /// Remove a project from the workspace
    Remove {
        /// Project name or path
        project: String,
    },
    /// List all projects in the workspace
    List,
    /// Run a command across all projects
    Run {
        /// Command to run (e.g., build, test, lint)
        command: String,
        /// Additional arguments
        #[arg(last = true)]
        args: Vec<String>,
        /// Run in parallel
        #[arg(short, long)]
        parallel: bool,
        /// Only run in projects matching filter
        #[arg(short, long)]
        filter: Option<String>,
        /// Explicitly allow repo-defined commands without an interactive
        /// confirmation (required when no terminal is attached)
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Show environment diff across workspace vs a branch
    Diff {
        /// Branch to compare against (default: main)
        #[arg(default_value = "main")]
        branch: String,
    },
    /// Check all project environments without changing them
    Check,
    /// Show workspace status
    Status,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommands {
    /// Get a configuration value
    Get {
        /// Configuration key to get
        key: String,
    },
    /// Set a configuration value
    Set {
        /// Configuration key to set
        key: String,
        /// Value to set
        value: String,
    },
    /// List all configuration values
    List,
    /// Validate configuration file syntax and values
    Validate,
    /// Reset configuration to defaults
    Reset {
        /// Skip confirmation
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Show configuration file path
    Path,
}

#[derive(Subcommand, Debug)]
pub enum PrivacyCommands {
    /// Show privacy policy summary and your current settings
    Status,
    /// Export local OMG data
    Export {
        /// Output file path (default: omg-data-export-YYYY-MM-DD.json)
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Disable telemetry collection
    #[command(name = "opt-out")]
    OptOut,
    /// Re-enable telemetry collection
    #[command(name = "opt-in")]
    OptIn,
}

#[derive(Subcommand, Debug)]
pub enum EnvCommands {
    /// Preview portable environment requirements without installing or copying files
    Plan {
        /// Target platform and architecture
        #[arg(long, value_parser = ["arch-x86_64", "debian-x86_64", "ubuntu-x86_64", "fedora-x86_64", "macos-aarch64"])]
        target: String,
    },
    /// Capture current environment state to omg.lock
    Capture,
    /// Check for drift against omg.lock
    Check,
    /// Share environment state as a GitHub Gist
    Share {
        /// Description for the Gist
        #[arg(short, long, default_value = "OMG Environment State")]
        description: String,
        /// Make Gist public (default: secret)
        #[arg(long)]
        public: bool,
    },
    /// Sync environment from a Gist URL or ID
    Sync {
        /// Gist URL or ID
        url: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum ToolCommands {
    /// Install a dev tool from any source (Pacman, Cargo, NPM, Pip, Go)
    Install {
        /// Tool name (e.g. ripgrep, jq, tldr)
        name: String,
    },
    /// List installed tools
    List,
    /// Remove a tool
    Remove { name: String },
    /// Update an installed tool to latest version
    Update {
        /// Tool name (or 'all' to update everything)
        name: String,
    },
    /// Search for tools in the registry
    Search {
        /// Search query
        query: String,
    },
    /// Show available tools in the registry
    Registry,
}

#[derive(Subcommand, Debug)]
pub enum TeamCommands {
    /// Initialize a new team workspace
    Init {
        /// Team identifier (e.g., "mycompany/frontend")
        team_id: String,
        /// Display name for the team
        #[arg(short, long)]
        name: Option<String>,
    },
    /// Join an existing team by remote URL
    Join {
        /// GitHub Gist URL or ID
        url: String,
    },
    /// Show team status and member sync state
    Status,
    /// Push local environment to team lock
    Push,
    /// Pull team lock and check for drift
    Pull,
    /// List team members and their sync status
    Members,
    /// Interactive team dashboard (TUI)
    Dashboard,
    /// Manage team roles and permissions
    Roles {
        #[command(subcommand)]
        command: TeamRoleCommands,
    },
    /// Manage golden path templates
    GoldenPath {
        #[command(subcommand)]
        command: GoldenPathCommands,
    },
    /// Check compliance status
    Compliance {
        /// Export compliance report
        #[arg(long)]
        export: Option<String>,
        /// Enforce compliance (block non-compliant operations)
        #[arg(long)]
        enforce: bool,
    },
    /// Show team activity stream
    Activity {
        /// Number of days to show
        #[arg(short, long, default_value = "7")]
        days: u32,
    },
}

#[derive(Subcommand, Debug)]
pub enum TeamRoleCommands {
    /// List all roles
    List,
}

#[derive(Subcommand, Debug)]
pub enum GoldenPathCommands {
    /// Create a new golden path template
    Create {
        /// Template name
        name: String,
        /// Node version requirement
        #[arg(long)]
        node: Option<String>,
        /// Python version requirement
        #[arg(long)]
        python: Option<String>,
        /// Additional packages to include
        #[arg(long)]
        packages: Option<String>,
    },
    /// List available golden path templates
    List,
    /// Delete a golden path template
    Delete {
        /// Template name
        name: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum ContainerCommands {
    /// Show container runtime status (Docker/Podman)
    Status,
    /// Run a command in a container
    Run {
        /// Container image to use
        image: String,
        /// Command to run
        #[arg(last = true)]
        command: Vec<String>,
        /// Container name
        #[arg(short, long)]
        name: Option<String>,
        /// Run in background (detached)
        #[arg(short, long)]
        detach: bool,
        /// Run interactively with TTY
        #[arg(short, long)]
        interactive: bool,
        /// Environment variables (KEY=VALUE)
        #[arg(short, long, value_name = "KEY=VALUE")]
        env: Vec<String>,
        /// Volume mounts (host:container)
        #[arg(long, value_name = "HOST:CONTAINER")]
        volume: Vec<String>,
        /// Working directory inside container
        #[arg(short, long)]
        workdir: Option<String>,
    },
    /// Start an interactive shell in a container
    Shell {
        /// Container image (default: ubuntu:24.04 with project mounted)
        #[arg(short, long)]
        image: Option<String>,
        /// Working directory inside container
        #[arg(short, long)]
        workdir: Option<String>,
        /// Environment variables (KEY=VALUE)
        #[arg(short, long, value_name = "KEY=VALUE")]
        env: Vec<String>,
        /// Additional volume mounts (host:container)
        #[arg(long, value_name = "HOST:CONTAINER")]
        volume: Vec<String>,
    },
    /// Build a container image
    Build {
        /// Path to Dockerfile
        #[arg(short = 'f', long)]
        dockerfile: Option<String>,
        /// Image tag
        #[arg(short, long, default_value = "omg-dev:latest")]
        tag: String,
        /// Disable build cache
        #[arg(long)]
        no_cache: bool,
        /// Build arguments (KEY=VALUE)
        #[arg(long, value_name = "KEY=VALUE")]
        build_arg: Vec<String>,
        /// Target build stage
        #[arg(long)]
        target: Option<String>,
    },
    /// List running containers
    List,
    /// List container images
    Images,
    /// Pull a container image
    Pull {
        /// Image to pull
        image: String,
    },
    /// Stop a running container
    Stop {
        /// Container name or ID
        container: String,
    },
    /// Execute a command in a running container
    Exec {
        /// Container name or ID
        container: String,
        /// Command to execute
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Generate a Dockerfile for the current project
    Init {
        /// Base image to use
        #[arg(short, long)]
        base: Option<String>,
    },
}

#[cfg(feature = "license")]
#[derive(Subcommand, Debug)]
pub enum AccountCommands {
    /// Link this machine to the OMG dashboard
    Link {
        /// Read the dashboard token from stdin instead of OMG_DASHBOARD_TOKEN.
        #[arg(long)]
        token_stdin: bool,
    },
    /// Show whether this machine is linked to the dashboard
    Status,
    /// Unlink this machine from the dashboard
    Unlink,
}

#[derive(Subcommand, Debug)]
pub enum AuditCommands {
    /// Scan for vulnerabilities in installed packages (default)
    Scan,
    /// Generate Software Bill of Materials (SBOM) in `CycloneDX` format
    Sbom {
        /// Output file path (default: ~/.local/share/omg/sbom/sbom-`<timestamp>`.json)
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Scan for leaked secrets and credentials
    Secrets {
        /// Directory to scan (default: current directory)
        #[arg(short, long)]
        path: Option<String>,
    },
    /// View audit log entries
    Log {
        /// Number of entries to show (default: 20 on screen, all when exporting)
        #[arg(short, long)]
        limit: Option<usize>,
        /// Filter by severity (debug, info, warning, error, critical)
        #[arg(short, long, value_enum)]
        severity: Option<AuditLogSeverity>,
        /// Export log to file
        #[arg(short, long)]
        export: Option<String>,
    },
    /// Verify audit log integrity (tamper detection)
    Verify,
    /// Show security policy status
    Policy,
    /// Check SLSA provenance for a package
    Slsa {
        /// Package file to verify
        package: String,
        /// Require the Fulcio certificate SAN to match this identity
        /// (email or OIDC URI). Without it, any Sigstore identity verifies.
        #[arg(long)]
        certificate_identity: Option<String>,
    },
    /// Scan for software license compliance issues
    Licenses {
        /// Output format (table, json, csv)
        #[arg(short, long, value_enum, default_value_t = LicenseOutputFormat::Table)]
        format: LicenseOutputFormat,
        /// Export results to file
        #[arg(short, long)]
        export: Option<String>,
        /// Show only packages with specific license types (comma-separated)
        #[arg(long)]
        filter: Option<String>,
        /// Check against policy (warn on restricted licenses)
        #[arg(long)]
        check_policy: bool,
    },
    /// Auto-fix vulnerabilities by upgrading packages
    Fix {
        /// Show what would be fixed without making changes
        #[arg(long)]
        dry_run: bool,
        /// Skip confirmation
        #[arg(short = 'y', long)]
        yes: bool,
        /// Only fix vulnerabilities with this minimum severity (low, medium, high, critical)
        #[arg(long, value_enum, default_value_t = VulnerabilitySeverity::Medium)]
        min_severity: VulnerabilitySeverity,
    },
    /// Export compliance evidence for audit frameworks
    Export {
        /// Compliance framework (soc2, iso27001, fedramp, hipaa, pci-dss)
        #[arg(short, long, value_enum, default_value_t = ComplianceFramework::Soc2)]
        framework: ComplianceFramework,
        /// Time period (e.g., "2024-Q4", "2024-01" to "2024-03")
        #[arg(short, long)]
        period: Option<String>,
        /// Output directory
        #[arg(short, long, default_value = "audit-evidence")]
        output: String,
    },
    /// Check end-of-life status for installed runtimes
    Eol,
}

#[derive(Subcommand, Debug)]
pub enum SnapshotCommands {
    /// Create a new snapshot
    Create {
        /// Description for the snapshot
        #[arg(short, long)]
        message: Option<String>,
    },
    /// List all snapshots
    List,
    /// Restore a snapshot
    Restore {
        /// Snapshot ID to restore
        id: String,
        /// Dry run - show what would change
        #[arg(long)]
        dry_run: bool,
        /// Skip confirmation
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Delete a snapshot
    Delete {
        /// Snapshot ID to delete
        id: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum CiCommands {
    /// Initialize CI configuration for a provider
    Init {
        /// CI provider (github, gitlab, circleci)
        #[arg(value_enum)]
        provider: CiProvider,
        /// Generate advanced configuration with matrices and security audits
        #[arg(long)]
        advanced: bool,
    },
    /// Validate current environment matches CI expectations
    Validate,
    /// Generate cache manifest for CI
    Cache,
}

#[derive(Subcommand, Debug)]
pub enum MigrateCommands {
    /// Export current environment to a portable manifest
    Export {
        /// Output file path
        #[arg(short, long, default_value = "omg-manifest.json")]
        output: String,
    },
    /// Import environment from a manifest (with package mapping)
    Import {
        /// Manifest file to import
        manifest: String,
        /// Dry run - show what would be installed
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum FleetCommands {
    /// Show fleet status across all machines
    Status,
}

#[derive(Subcommand, Debug)]
pub enum EnterpriseCommands {
    /// Generate executive reports
    Reports {
        /// Report type (monthly, quarterly, custom)
        #[arg(short, long, value_enum, default_value_t = EnterpriseReportType::Monthly)]
        report_type: EnterpriseReportType,
    },
    /// Manage hierarchical policies
    Policy {
        #[command(subcommand)]
        command: EnterprisePolicyCommands,
    },
    /// Export audit evidence for compliance
    AuditExport {
        /// Compliance framework (soc2, iso27001, fedramp, hipaa, pci-dss)
        #[arg(short, long, value_enum, default_value_t = ComplianceFramework::Soc2)]
        framework: ComplianceFramework,
        /// Time period (e.g., "2025-Q4")
        #[arg(short, long)]
        period: Option<String>,
        /// Output directory
        #[arg(short, long, default_value = "audit-evidence")]
        output: String,
    },
    /// Scan for license compliance issues
    LicenseScan {
        /// Export file format (json, csv)
        #[arg(long, value_enum)]
        export: Option<LicenseExportFormat>,
    },
}

#[derive(Subcommand, Debug)]
pub enum EnterprisePolicyCommands {
    /// Show current policies
    Show {
        /// Scope to show
        #[arg(short, long)]
        scope: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }

    #[test]
    fn update_and_install_accept_review_and_no_sync() {
        let update = Cli::try_parse_from(["omg", "update", "--review", "--no-sync", "--check"])
            .expect("update flags must parse");
        match update.command {
            Commands::Update {
                check,
                review,
                no_sync,
                ..
            } => {
                assert!(check);
                assert!(review);
                assert!(no_sync);
            }
            other => panic!("expected Update, got {other:?}"),
        }

        let install = Cli::try_parse_from(["omg", "install", "--review", "firefox"])
            .expect("install --review must parse");
        match install.command {
            Commands::Install {
                review, packages, ..
            } => {
                assert!(review);
                assert_eq!(packages, ["firefox"]);
            }
            other => panic!("expected Install, got {other:?}"),
        }
    }

    #[test]
    fn update_accepts_aur_only_and_rejects_fast_paths() {
        let update = Cli::try_parse_from(["omg", "update", "--aur-only", "--check"])
            .expect("AUR-only checks must parse");
        match update.command {
            Commands::Update {
                aur_only, check, ..
            } => {
                assert!(aur_only);
                assert!(check);
            }
            other => panic!("expected Update, got {other:?}"),
        }

        for fast_flag in ["--fast", "--turbo"] {
            let error = Cli::try_parse_from(["omg", "update", "--aur-only", fast_flag])
                .expect_err(&format!("--aur-only must conflict with {fast_flag}"));
            let message = error.to_string();
            assert!(
                message.contains("cannot be used with") && message.contains(fast_flag),
                "--aur-only vs {fast_flag} must name the clap conflict, got: {message}"
            );
        }
    }

    #[test]
    fn run_modes_cannot_be_combined() {
        for args in [
            ["omg", "run", "build", "--watch", "--parallel"].as_slice(),
            ["omg", "run", "build", "--watch", "--using", "node"].as_slice(),
            ["omg", "run", "build", "--parallel", "--all"].as_slice(),
            ["omg", "run", "build", "--using", "node", "--all"].as_slice(),
        ] {
            assert!(
                Cli::try_parse_from(args.iter().copied()).is_err(),
                "conflicting run modes unexpectedly parsed: {args:?}"
            );
        }
    }

    #[test]
    fn workspace_environment_command_is_truthfully_named() {
        assert!(Cli::try_parse_from(["omg", "workspace", "check"]).is_ok());
        assert!(Cli::try_parse_from(["omg", "workspace", "sync"]).is_err());
    }

    #[test]
    fn environment_plan_requires_an_explicit_supported_target() {
        assert!(Cli::try_parse_from(["omg", "env", "plan", "--target", "ubuntu-x86_64"]).is_ok());
        assert!(Cli::try_parse_from(["omg", "env", "plan"]).is_err());
        assert!(Cli::try_parse_from(["omg", "env", "plan", "--target", "nixos-x86_64"]).is_err());
        assert!(Cli::try_parse_from(["omg", "env", "apply"]).is_err());
    }

    #[test]
    fn enterprise_does_not_advertise_unimplemented_mirroring() {
        assert!(Cli::try_parse_from(["omg", "enterprise", "server", "mirror"]).is_err());
    }

    #[test]
    fn bounded_choices_fail_during_argument_parsing() {
        let invalid: &[&[&str]] = &[
            &["omg", "new", "unknown", "project"],
            &["omg", "audit", "log", "--severity", "unknown"],
            &["omg", "audit", "licenses", "--format", "unknown"],
            &["omg", "audit", "fix", "--min-severity", "unknown"],
            &["omg", "audit", "export", "--framework", "unknown"],
            &["omg", "ci", "init", "unknown"],
            &["omg", "enterprise", "reports", "--report-type", "unknown"],
            &[
                "omg",
                "enterprise",
                "audit-export",
                "--framework",
                "unknown",
            ],
            &["omg", "enterprise", "license-scan", "--export", "unknown"],
        ];

        for args in invalid {
            assert!(
                Cli::try_parse_from(args.iter().copied()).is_err(),
                "bounded invalid choice unexpectedly parsed: {args:?}"
            );
        }
    }

    #[test]
    fn removed_cli_flags_stay_rejected() {
        assert!(
            Cli::try_parse_from([
                "omg",
                "run",
                "test",
                "--runtime-backend",
                "native-then-mise"
            ])
            .is_err()
        );
        assert!(Cli::try_parse_from(["omg", "enterprise", "reports", "--format", "json"]).is_err());
    }

    #[test]
    fn bounded_choices_accept_documented_values() {
        let valid: &[&[&str]] = &[
            &["omg", "new", "rust", "project"],
            &["omg", "audit", "log", "--severity", "critical"],
            &["omg", "audit", "licenses", "--format", "csv"],
            &["omg", "audit", "fix", "--min-severity", "high"],
            &["omg", "audit", "export", "--framework", "pci-dss"],
            &["omg", "ci", "init", "github"],
            &["omg", "enterprise", "reports", "--report-type", "quarterly"],
            &[
                "omg",
                "enterprise",
                "audit-export",
                "--framework",
                "iso27001",
            ],
            &["omg", "enterprise", "license-scan", "--export", "json"],
        ];

        for args in valid {
            assert!(
                Cli::try_parse_from(args.iter().copied()).is_ok(),
                "documented bounded choice failed to parse: {args:?}"
            );
        }
    }
}
