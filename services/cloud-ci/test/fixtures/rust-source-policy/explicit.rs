//! Explicit package listing functionality

#[cfg(unix)]
use crate::core::client::SyncDaemonClient;
#[cfg(unix)]
use crate::daemon::protocol::{Request, ResponseResult};
use anyhow::{Context, Result};
use serde::Serialize;

#[derive(Serialize)]
struct ExplicitJson {
    packages: Vec<String>,
    count: usize,
}

pub fn explicit_sync(count: bool) -> Result<()> {
    explicit_sync_with_json(count, false)
}

/// Print a package count as JSON or plain text.
fn print_count(count: usize, json: bool) -> Result<()> {
    if json {
        let value = serde_json::json!({ "count": count });
        let json_str = serde_json::to_string_pretty(&value)
            .context("Failed to serialize explicit package count as JSON")?;
        println!("{json_str}");
    } else {
        println!("{count}");
    }
    Ok(())
}

#[allow(
    clippy::needless_return,
    reason = "additive backend feature branches return before compiled fallbacks"
)]
pub fn explicit_sync_with_json(count: bool, json: bool) -> Result<()> {
    let backend = crate::package_managers::resolve_backend()?;
    if crate::core::paths::test_mode() {
        // Test mode must observe the isolated mock state before consulting a
        // real daemon, fast-status file, or host package database.
        let packages = crate::package_managers::list_explicit_fast()
            .context("Failed to list explicitly installed test packages")?;
        if count {
            print_count(packages.len(), json)?;
        } else {
            display_explicit_list(packages, json)?;
        }
        return Ok(());
    }

    #[cfg(unix)]
    if let Ok(mut client) = SyncDaemonClient::acquire() {
        let request = if count {
            Request::ExplicitCount { id: 0 }
        } else {
            Request::Explicit { id: 0 }
        };

        match client.call(&request) {
            Ok(res) => match res {
                ResponseResult::ExplicitCount(c) => {
                    print_count(c, json)?;
                    return Ok(());
                }
                ResponseResult::Explicit(res) => {
                    display_explicit_list(res.packages, json)?;
                    return Ok(());
                }
                // The daemon answered but not for this request; fall through
                // to the direct backends instead of failing. Enumerated rather
                // than `_` so a newly added response variant forces this
                // decision point to be revisited.
                ResponseResult::Search(_)
                | ResponseResult::Info(_)
                | ResponseResult::Status(_)
                | ResponseResult::SecurityAudit(_)
                | ResponseResult::Ping(_)
                | ResponseResult::CacheStats { .. }
                | ResponseResult::IndexRefreshed { .. }
                | ResponseResult::Metrics(_)
                | ResponseResult::Suggest(_)
                | ResponseResult::Message(_)
                | ResponseResult::DebianSearch(_)
                | ResponseResult::Health(_)
                | ResponseResult::ListUpdates(_) => {}
            },
            Err(error) => {
                tracing::debug!("Daemon explicit-list call failed: {error}");
            }
        }
    } else {
        tracing::debug!("Daemon unavailable for explicit listing; using direct backend");
    }

    if backend == crate::package_managers::Backend::MacOS {
        let packages = crate::package_managers::list_explicit_fast()
            .context("Failed to list explicitly installed Homebrew packages")?;
        return if count {
            print_count(packages.len(), json)
        } else {
            display_explicit_list(packages, json)
        };
    }

    #[cfg(any(feature = "debian", feature = "debian-pure"))]
    if crate::core::env::distro::is_debian_like() {
        let packages = crate::package_managers::debian_db::list_explicit_fast()
            .context("Failed to list explicitly installed packages")?;
        if count {
            print_count(packages.len(), json)?;
        } else {
            display_explicit_list(packages, json)?;
        }
        return Ok(());
    }

    #[cfg(feature = "fedora")]
    if backend == crate::package_managers::Backend::Fedora {
        let packages: Vec<String> =
            crate::package_managers::dnf::DnfPackageManager::read_user_installed_names()
                .context("Failed to list explicitly installed Fedora packages")?
                .into_iter()
                .collect();
        return if count {
            print_count(packages.len(), json)
        } else {
            display_explicit_list(packages, json)
        };
    }

    if count {
        if let Some(c) = crate::core::fast_status::FastStatus::read_explicit_count() {
            print_count(c, json)?;
            return Ok(());
        }

        #[cfg(feature = "arch")]
        {
            let count = crate::package_managers::pacman_db::get_explicit_count()?;
            print_count(count, json)?;
            return Ok(());
        }

        #[cfg(all(
            any(feature = "debian", feature = "debian-pure"),
            not(feature = "arch")
        ))]
        {
            let packages = crate::package_managers::list_explicit_fast()
                .context("Failed to list explicitly installed packages")?;
            print_count(packages.len(), json)?;
            return Ok(());
        }

        #[cfg(not(any(feature = "arch", feature = "debian", feature = "debian-pure")))]
        {
            return explicit_requires_backend();
        }
    }

    #[cfg(feature = "arch")]
    {
        let packages = crate::package_managers::list_explicit_fast()
            .context("Failed to list explicitly installed packages")?;
        display_explicit_list(packages, json)?;
        #[allow(
            clippy::needless_return,
            reason = "required when additive backend features compile later fallback blocks"
        )]
        return Ok(());
    }

    #[cfg(all(
        any(feature = "debian", feature = "debian-pure"),
        not(feature = "arch")
    ))]
    {
        let packages = crate::package_managers::list_explicit_fast()
            .context("Failed to list explicitly installed packages")?;
        display_explicit_list(packages, json)?;
        return Ok(());
    }

    #[cfg(not(any(feature = "arch", feature = "debian", feature = "debian-pure")))]
    explicit_requires_backend()
}

#[cfg(any(
    not(any(feature = "arch", feature = "debian", feature = "debian-pure")),
    test
))]
fn explicit_requires_backend() -> Result<()> {
    anyhow::bail!(
        "Explicit package listing is not available without an Arch or Debian package backend"
    )
}

fn display_explicit_list(mut packages: Vec<String>, json: bool) -> Result<()> {
    packages.sort();

    if json {
        let output = ExplicitJson {
            count: packages.len(),
            packages,
        };
        let json_str = serde_json::to_string_pretty(&output)
            .context("Failed to serialize explicit package list as JSON")?;
        println!("{json_str}");
        return Ok(());
    }

    use owo_colors::OwoColorize;
    use std::io::Write;
    let mut stdout = std::io::BufWriter::new(std::io::stdout());

    // Modern header (written directly; the buffered writer only carries the
    // package lines below and is flushed before the function returns).
    crate::cli::modern_ui::print_phase_header(
        "📦",
        "Explicit Packages",
        &format!("{} installed", packages.len()),
    );
    println!();

    for pkg in &packages {
        if crate::cli::style::colors_enabled() {
            writeln!(stdout, "  {} {}", "·".cyan(), pkg.bold())?;
        } else {
            writeln!(stdout, "  · {pkg}")?;
        }
    }

    println!();
    stdout.flush()?;
    Ok(())
}

/// List explicitly installed packages (async wrapper preserving the
/// asynchronous command interface)
#[allow(clippy::unused_async, reason = "preserves the async command interface")]
pub async fn explicit(count: bool) -> Result<()> {
    explicit_sync(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_without_backend_is_an_error() {
        let error = explicit_requires_backend()
            .expect_err("explicit listing with no backend must not look like success");
        assert!(
            error
                .to_string()
                .contains("not available without an Arch or Debian package backend"),
            "got: {error}"
        );
    }
}
