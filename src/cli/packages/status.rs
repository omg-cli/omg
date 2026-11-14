//! Status command - system-wide package status overview

use anyhow::{Context, Result};
use serde::Serialize;
use std::io::Write;

use crate::cli::tea::{StatusData, run_status_elm};
#[cfg(unix)]
use crate::core::client::DaemonClient;
#[cfg(unix)]
use crate::daemon::protocol::{Request, ResponseResult};
use crate::package_managers::get_package_manager;

#[derive(Serialize)]
struct StatusJson {
    total_packages: usize,
    explicit_packages: usize,
    orphan_packages: usize,
    updates_available: usize,
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
    let (total, explicit, orphans, updates) = {
        let daemon_status = tokio::time::timeout(std::time::Duration::from_millis(500), async {
            let mut client = DaemonClient::connect().await.ok()?;
            match client.call(Request::Status { id: 0 }).await.ok()? {
                ResponseResult::Status(status) => Some(status),
                // Any other response means the daemon answered but not for
                // this request; fall back to the direct package manager.
                other => {
                    tracing::debug!("Unexpected daemon status response: {other:?}");
                    None
                }
            }
        })
        .await
        .unwrap_or(None);

        if let Some(status) = daemon_status {
            (
                status.total_packages,
                status.explicit_packages,
                status.orphan_packages,
                status.updates_available,
            )
        } else {
            let pm = get_package_manager()?;
            pm.get_status(fast).await?
        }
    };

    #[cfg(not(unix))]
    let (total, explicit, orphans, updates) = {
        let pm = get_package_manager()?;
        pm.get_status(fast).await?
    };

    let status = StatusJson {
        total_packages: total,
        explicit_packages: explicit,
        orphan_packages: orphans,
        updates_available: updates,
        query_time_ms: start.elapsed().as_secs_f64() * 1000.0,
    };

    let json_str =
        serde_json::to_string_pretty(&status).context("Failed to serialize status as JSON")?;
    println!("{json_str}");

    Ok(())
}

/// Fallback implementation using original approach
async fn status_fallback(fast: bool) -> Result<()> {
    let start = std::time::Instant::now();

    // 1. Try Daemon first (Hot Path)
    #[cfg(unix)]
    if let Ok(Some(status)) = tokio::time::timeout(std::time::Duration::from_millis(500), async {
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
    {
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

    // 2. Fallback to direct path (Cold Path)
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
