//! CLI module for OMG
//!
//! Handles command-line argument parsing and command definitions.

use anyhow::Result;

mod args;
pub mod blame;
pub mod chrome;
pub mod ci;
pub mod commands;
pub mod components;
pub mod config;
pub mod container;
pub mod daemon_status;
pub mod diff;
pub mod doctor;
pub mod enterprise;
pub mod env;
pub mod fleet;
pub mod git_hooks;
pub mod help;
pub mod init;
#[cfg(feature = "license")]
pub mod license;
pub mod man;
pub mod migrate;
pub mod modern_ui;
pub mod new;
pub mod outdated;
pub mod packages;
/// Progress-lane UI toolkit. Its API only has callers under package-backend
/// features, so backend-less combos would flag every lane constructor as
/// dead code; silence exactly that case instead of sprinkling per-item
/// gates (or per-item allows) across the module. Backend combos lint this
/// module normally.
#[cfg_attr(
    not(any(feature = "arch", feature = "debian", feature = "debian-pure")),
    allow(dead_code)
)]
pub(crate) mod progress;
pub mod run;
pub mod runtimes;
pub mod security;
pub mod self_update;
pub mod size;
pub mod snapshot;
pub mod style;
pub mod tea;
pub mod team;
pub mod telemetry;
pub mod tool;
pub mod tui;
pub mod ui;
pub mod update_notice;
pub mod why;
pub mod workspace;

#[cfg(feature = "license")]
pub use args::AccountCommands;
pub use args::{
    AuditCommands, CiCommands, Cli, Commands, ComplianceFramework, ConfigCommands,
    ContainerCommands, EnterpriseCommands, EnterprisePolicyCommands, EnterpriseReportType,
    EnvCommands, FleetCommands, GoldenPathCommands, HooksCommands, MigrateCommands,
    PrivacyCommands, ShellKind, SnapshotCommands, TeamCommands, TeamRoleCommands, ToolCommands,
    TransactionTypeFilter, WorkspaceCommands,
};

/// Parse an API timestamp string into Unix seconds.
///
/// Returns `None` when the value cannot be parsed so callers can surface the
/// gap explicitly instead of silently treating bad data as "1970-01-01".
pub(crate) fn parse_timestamp_opt(raw: &str) -> Option<i64> {
    use std::str::FromStr;
    jiff::Timestamp::from_str(raw)
        .ok()
        .map(jiff::Timestamp::as_second)
}

/// Format a Unix timestamp as a compact `YYYY-MM-DD HH:MM` string, or
/// `"unknown"` when the value is out of range.
pub(crate) fn format_short_timestamp(ts: i64) -> String {
    jiff::Timestamp::from_second(ts).map_or_else(
        |_| "unknown".to_string(),
        |dt| dt.strftime("%Y-%m-%d %H:%M").to_string(),
    )
}

/// Open an ALPM handle using the pacman root and DB path resolved by
/// `core::paths` (which honors `pacman.conf`), instead of hardcoding
/// `/` and `/var/lib/pacman` at every call site.
#[cfg(feature = "arch")]
pub(crate) fn open_local_alpm() -> Result<alpm::Alpm> {
    // `Alpm::new` takes `S: Into<Vec<u8>>`; own the strings so the owned
    // `PathBuf`s stay available for the error message below.
    let root = crate::core::paths::pacman_root_result()?;
    let db_path = crate::core::paths::pacman_db_dir_result()?;
    alpm::Alpm::new(
        root.to_string_lossy().into_owned(),
        db_path.to_string_lossy().into_owned(),
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "Failed to open ALPM (root: {}, db: {}): {e}",
            root.display(),
            db_path.display()
        )
    })
}

/// Names of locally installed packages that require `package`.
///
/// Delegating to libalpm preserves its dependency semantics, including
/// version constraints and virtual dependencies satisfied through `provides`.
#[cfg(feature = "arch")]
pub(crate) fn local_reverse_deps(handle: &alpm::Alpm, package: &str) -> Vec<String> {
    handle
        .localdb()
        .pkg(package.as_bytes())
        .map(|installed| installed.required_by().into_iter().collect())
        .unwrap_or_default()
}

/// Global context for CLI command execution
pub struct CliContext {
    pub json: bool,
}

/// Execute a CLI command using process-local terminal state.
#[allow(
    async_fn_in_trait,
    reason = "this project owns every implementation and does not expose the trait as a stable library API"
)]
pub trait LocalCommandRunner {
    /// Execute the command
    async fn execute(&self, ctx: &CliContext) -> Result<()>;
}

#[cfg(all(test, feature = "arch"))]
mod tests {
    use super::*;
    use std::fs;

    fn write_local_package(db: &std::path::Path, name: &str, extra: &str) {
        let package_dir = db.join("local").join(format!("{name}-1.0-1"));
        fs::create_dir_all(&package_dir).expect("create local package fixture");
        fs::write(
            package_dir.join("desc"),
            format!("%NAME%\n{name}\n\n%VERSION%\n1.0-1\n\n%ARCH%\nany\n\n%REASON%\n1\n\n{extra}"),
        )
        .expect("write local package metadata");
    }

    #[test]
    fn reverse_dependencies_include_virtual_providers() {
        let directory = tempfile::tempdir().expect("temporary ALPM root");
        let db = directory.path().join("var/lib/pacman");
        fs::create_dir_all(db.join("local")).expect("create local database");
        fs::write(db.join("local/ALPM_DB_VERSION"), "9\n").expect("write database version");
        write_local_package(&db, "provider", "%PROVIDES%\nvirtual-api=1\n\n");
        write_local_package(&db, "consumer", "%DEPENDS%\nvirtual-api>=1\n\n");
        write_local_package(&db, "unrelated", "");

        let handle = alpm::Alpm::new(
            directory.path().to_string_lossy().into_owned(),
            db.to_string_lossy().into_owned(),
        )
        .expect("open isolated ALPM database");

        assert_eq!(local_reverse_deps(&handle, "provider"), ["consumer"]);
        assert!(local_reverse_deps(&handle, "unrelated").is_empty());
        assert!(local_reverse_deps(&handle, "consumer").is_empty());
        assert!(local_reverse_deps(&handle, "not-installed").is_empty());
    }
}
