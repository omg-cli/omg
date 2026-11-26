//! Status command - system-wide package status overview

use anyhow::{Context, Result};
use serde::Serialize;
use std::io::Write;

use crate::cli::tea::{StatusData, run_status_elm};
#[cfg(unix)]
use crate::core::client::DaemonClient;
#[cfg(unix)]
use crate::daemon::protocol::{Request, ResponseResult, StatusResult};
use crate::package_managers::get_package_manager;
use crate::package_managers::types::PackageStatus;

#[derive(Serialize)]
struct StatusJson {
    total_packages: usize,
    explicit_packages: usize,
    orphan_packages: usize,
    updates_available: usize,
    updates_and_orphans_checked: bool,
    query_time_ms: f64,
}

pub async fn status(fast: bool) -> Result<()> {
    status_with_json(fast, false).await
}

pub async fn status_with_json(fast: bool, json: bool) -> Result<()> {
    if json {
        return status_json(fast).await;
    }
    if fast {
        return status_fallback(true).await;
    }
    #[cfg(all(unix, feature = "fedora"))]
    if uses_fedora_status() {
        return status_fallback(false).await;
    }

    if let Err(e) = run_status_elm(false) {
        if e.kind() == std::io::ErrorKind::Other {
            return Err(e.into());
        }
        tracing::warn!("Elm UI failed, falling back to basic mode: {}", e);
        status_fallback(fast).await
    } else {
        Ok(())
    }
}

async fn status_json(fast: bool) -> Result<()> {
    let start = std::time::Instant::now();

    #[cfg(unix)]
    let daemon_counts = query_daemon_status(fast).await.map(|status| {
        PackageStatus::from((
            status.total_packages,
            status.explicit_packages,
            status.orphan_packages,
            status.updates_available,
        ))
    });
    #[cfg(not(unix))]
    let daemon_counts: Option<PackageStatus> = None;

    let counts = match daemon_counts {
        Some(counts) => counts,
        None => get_package_manager()?.get_status_details(fast).await?,
    };
    let updates_and_orphans_checked = counts.maintenance.is_some();
    let (total, explicit, orphans, updates) = counts.into_counts();

    let status = StatusJson {
        total_packages: total,
        explicit_packages: explicit,
        orphan_packages: orphans,
        updates_available: updates,
        updates_and_orphans_checked,
        query_time_ms: start.elapsed().as_secs_f64() * 1000.0,
    };

    let json_str =
        serde_json::to_string_pretty(&status).context("Failed to serialize status as JSON")?;
    println!("{json_str}");

    Ok(())
}

#[cfg(all(unix, feature = "fedora"))]
fn uses_fedora_status() -> bool {
    matches!(
        crate::package_managers::resolve_backend(),
        Ok(crate::package_managers::Backend::Fedora)
    )
}

#[cfg(unix)]
async fn query_daemon_status(fast: bool) -> Option<StatusResult> {
    #[cfg(not(feature = "fedora"))]
    let _ = fast;
    let timeout = std::time::Duration::from_millis(500);
    #[cfg(feature = "fedora")]
    let timeout = if uses_fedora_status() {
        if fast {
            return None;
        }
        // Fedora computes maintenance counts live, even with a warm daemon.
        std::time::Duration::from_secs(2)
    } else {
        timeout
    };
    tokio::time::timeout(timeout, async {
        let mut client = DaemonClient::connect().await.ok()?;
        match client.call(Request::Status { id: 0 }).await.ok()? {
            ResponseResult::Status(status) => Some(status),
            // Any other response means the daemon answered but not for this
            // request; fall back to the direct package manager.
            other => {
                tracing::debug!("Unexpected daemon status response: {other:?}");
                None
            }
        }
    })
    .await
    .unwrap_or(None)
}

async fn status_fallback(fast: bool) -> Result<()> {
    let start = std::time::Instant::now();

    #[cfg(unix)]
    if let Some(status) = query_daemon_status(fast).await {
        #[cfg(feature = "fedora")]
        if uses_fedora_status() {
            crate::cli::commands::print_system_status(
                &StatusData {
                    total_packages: status.total_packages,
                    explicit_packages: status.explicit_packages,
                    orphan_packages: status.orphan_packages,
                    updates_available: status.updates_available,
                    advisory_coverage: status.scanned_vulnerability_summary(),
                    duration_ms: start.elapsed().as_secs_f64() * 1000.0,
                    fast_mode: fast,
                },
                Some(status.runtime_versions),
                true,
            );
            return Ok(());
        }
        display_status_report(
            status.total_packages,
            status.explicit_packages,
            status.orphan_packages,
            status.updates_available,
            start.elapsed(),
            fast,
            status.scanned_vulnerability_summary(),
        )?;
        return Ok(());
    }

    let pm = get_package_manager()?;
    let (total, explicit, orphans, updates) = pm.get_status(fast).await?;
    display_status_report(
        total,
        explicit,
        orphans,
        updates,
        start.elapsed(),
        fast,
        None,
    )
}

fn display_status_report(
    total: usize,
    explicit: usize,
    orphans: usize,
    updates: usize,
    duration: std::time::Duration,
    fast: bool,
    advisory_coverage: Option<(usize, usize)>,
) -> Result<()> {
    let mut stdout = std::io::BufWriter::new(std::io::stdout());

    let report = StatusData {
        total_packages: total,
        explicit_packages: explicit,
        orphan_packages: orphans,
        updates_available: updates,
        duration_ms: duration.as_secs_f64() * 1000.0,
        fast_mode: fast,
        advisory_coverage,
    };
    stdout.write_all(report.render().as_bytes())?;

    stdout.flush()?;
    Ok(())
}
