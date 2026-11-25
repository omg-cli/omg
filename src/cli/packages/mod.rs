//! Package management CLI operations
//!
//! This module provides all package-related CLI functionality:
//! - Search: Find packages in repositories and AUR
//! - Install: Install packages with security grading
//! - Remove: Uninstall packages
//! - Update: System-wide package updates
//! - Info: Display package information
//! - Clean: Remove orphans and clear caches
//! - Explicit: List explicitly installed packages
//! - Sync: Synchronize package databases

mod clean;
pub(crate) mod common;
mod explicit;
mod info;
mod install;
mod remove;
mod search;
mod status;
mod sync_db;
mod update;

// Re-export all public functions
pub use clean::clean;
pub use explicit::{explicit, explicit_sync, explicit_sync_with_json};
#[doc(hidden)]
pub use info::info_after_fast_miss;
pub use info::{info, info_sync, info_with_json};
pub use install::install;
pub use remove::remove;
#[cfg(feature = "fedora")]
pub(crate) use remove::review_fedora_removal;
pub use search::{search, search_sync_cli, search_sync_cli_with_limit, search_with_json};
pub use status::{status, status_with_json};
pub use sync_db::sync_databases as sync;
#[cfg(feature = "arch")]
#[doc(hidden)]
pub use update::contain_inherited_transport;
pub use update::{update, update_fast, update_turbo};

/// Dispatch to the compiled package-manager backend.
///
/// The resolver rejects a binary built without the host distro's backend.
/// Fedora, Homebrew, and explicit test mode use the shared manager path.
///
/// Each body is a block expression. Only the arms enabled by the active
/// feature flags are type-checked, so call sites may reference the backend
/// modules unconditionally.
macro_rules! dispatch_backend {
    (
        debian: $debian_body:block,
        arch: $arch_body:block,
        generic: $generic_body:block $(,)?
    ) => {
        match crate::package_managers::resolve_backend()? {
            #[cfg(feature = "debian")]
            crate::package_managers::Backend::Debian => $debian_body,
            #[cfg(feature = "arch")]
            crate::package_managers::Backend::Arch => $arch_body,
            _ => $generic_body,
        }
    };
}
pub(crate) use dispatch_backend;

#[cfg(feature = "arch")]
fn mock_arch_backend() -> anyhow::Result<bool> {
    Ok(
        crate::package_managers::resolve_backend()? == crate::package_managers::Backend::Mock
            && crate::core::env::distro::detect_distro() == crate::core::env::distro::Distro::Arch,
    )
}

/// Execute a `Cmd<()>` in fallback context (non-Elm mode).
///
/// This provides a simple println-based execution for reliability
/// in CI/non-TTY environments where the Elm UI might not be available.
/// [`Cmd::Error`] is returned without printing so the process-level reporter
/// remains the single owner of user-facing failures.
pub(crate) fn execute_cmd(cmd: crate::cli::tea::Cmd<()>) -> anyhow::Result<()> {
    use crate::cli::tea::{Cmd, View};
    use std::io::Write;

    fn execute_inner(cmd: Cmd<()>) -> anyhow::Result<()> {
        match cmd {
            Cmd::None | Cmd::Msg(()) | Cmd::Exec(_) => {
                // Not supported or applicable in fallback mode
            }
            Cmd::Batch(cmds) => {
                let mut first_error = None;
                for command in cmds {
                    if let Err(error) = execute_inner(command)
                        && first_error.is_none()
                    {
                        first_error = Some(error);
                    }
                }
                if let Some(error) = first_error {
                    return Err(error);
                }
            }
            Cmd::View(View::PrintLn(output)) => {
                println!("{output}");
            }
            Cmd::View(View::Info(msg)) => {
                crate::cli::ui::print_info(msg);
            }
            Cmd::View(View::Success(msg)) => {
                crate::cli::ui::print_success(msg);
            }
            Cmd::View(View::Warning(msg)) => {
                crate::cli::ui::print_warning(msg);
            }
            Cmd::View(View::Error(msg)) => anyhow::bail!("{msg}"),
            Cmd::View(View::Header(title, body)) => {
                crate::cli::ui::print_header(&title, &body);
            }
            Cmd::View(View::Card(title, content)) => {
                crate::cli::ui::print_card(&title, &content);
            }
            Cmd::View(View::StyledText(config)) => {
                use crate::cli::tea::TextStyle;
                use crate::cli::ui::{Color, Style};
                let style = match config.style {
                    TextStyle::Bold => Style::new().foreground(Color::White).bold(true),
                    TextStyle::Success => Style::new().foreground(Color::Green).bold(true),
                    TextStyle::Info => Style::new().foreground(Color::Cyan),
                    TextStyle::Muted => Style::new().foreground(Color::Gray),
                };
                println!("  {}", style.render(&config.text));
            }
            Cmd::View(View::Spacer) => {
                println!();
            }
        }
        Ok(())
    }

    execute_inner(cmd)?;

    // Ensure output is flushed.
    std::io::stdout().flush()?;
    std::io::stderr().flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::execute_cmd;
    use crate::cli::tea::Cmd;

    #[test]
    fn fallback_executor_propagates_cmd_errors() {
        let error = execute_cmd(Cmd::error("package operation failed"))
            .expect_err("fallback Cmd::Error must fail the command");
        assert!(error.to_string().contains("package operation failed"));
    }

    #[test]
    fn fallback_executor_renders_lipgloss_views() {
        use crate::cli::tea::{StyledTextConfig, TextStyle};

        let batch = Cmd::batch([
            Cmd::info("checking packages"),
            Cmd::success("packages updated"),
            Cmd::warning("deprecated runtime"),
            Cmd::header("OMG", "Lipgloss Views"),
            Cmd::card("Summary", vec!["1 package checked".to_owned()]),
            Cmd::styled_text(StyledTextConfig {
                text: "bold".to_owned(),
                style: TextStyle::Bold,
            }),
            Cmd::styled_text(StyledTextConfig {
                text: "ok".to_owned(),
                style: TextStyle::Success,
            }),
            Cmd::styled_text(StyledTextConfig {
                text: "info".to_owned(),
                style: TextStyle::Info,
            }),
            Cmd::styled_text(StyledTextConfig {
                text: "muted".to_owned(),
                style: TextStyle::Muted,
            }),
        ]);
        execute_cmd(batch).expect("Lipgloss view commands should render without error");
    }
}
