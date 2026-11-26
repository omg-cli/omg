//! Status command - system-wide package status overview

use anyhow::{Context, Result};
use serde::Serialize;
use std::io::Write;

use crate::cli::tea::{StatusData, run_status_elm};
#[cfg(unix)]
use crate::core::client::DaemonClient;
#[cfg(all(unix, feature = "fedora"))]
use crate::daemon::protocol::StatusMetadata;
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
    let daemon_counts = {
        #[cfg(feature = "fedora")]
        let local_counts_only = uses_fedora_status();
        #[cfg(not(feature = "fedora"))]
        let local_counts_only = false;
        if local_counts_only {
            None
        } else {
            query_daemon_status(fast).await.map(|status| {
                PackageStatus::from((
                    status.total_packages,
                    status.explicit_packages,
                    status.orphan_packages,
                    status.updates_available,
                ))
            })
        }
    };
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
pub(crate) fn uses_fedora_status() -> bool {
    matches!(
        crate::package_managers::resolve_backend(),
        Ok(crate::package_managers::Backend::Fedora)
    )
}

#[cfg(unix)]
async fn query_daemon_status(fast: bool) -> Option<StatusResult> {
    #[cfg(not(feature = "fedora"))]
    let _ = fast;
    #[cfg(feature = "fedora")]
    if fast && uses_fedora_status() {
        return None;
    }
    tokio::time::timeout(std::time::Duration::from_millis(500), async {
        let mut client = DaemonClient::connect().await.ok()?;
        match client.call(Request::Status { id: 0 }).await {
            Ok(ResponseResult::Status(status)) => Some(status),
            // Any other response means the daemon answered but not for this
            // request; fall back to the direct package manager.
            other => {
                tracing::debug!("Daemon did not provide usable status: {other:?}");
                None
            }
        }
    })
    .await
    .ok()
    .flatten()
}

#[cfg(all(unix, feature = "fedora"))]
async fn query_daemon_status_metadata() -> Option<StatusMetadata> {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut client = DaemonClient::connect().await.ok()?;
        match client.call(Request::StatusMetadata { id: 0 }).await {
            Ok(ResponseResult::StatusMetadata(metadata)) => Some(metadata),
            other => {
                tracing::debug!("Daemon did not provide usable status metadata: {other:?}");
                None
            }
        }
    })
    .await
    .ok()
    .flatten()
}

#[cfg(all(unix, feature = "fedora"))]
pub(crate) async fn fedora_status_with_daemon() -> (bool, Result<StatusResult>) {
    let manager = match get_package_manager() {
        Ok(manager) => manager,
        Err(error) => return (false, Err(error)),
    };
    // Package counts depend on the caller's DNF cache. Retain the daemon's
    // separately validated advisory observation and runtime versions.
    let (counts, daemon) = tokio::join!(
        manager.get_status_details(false),
        query_daemon_status_metadata()
    );
    let connected = daemon.is_some();
    let status = counts.map(|counts| {
        let (total_packages, explicit_packages, orphan_packages, updates_available) =
            counts.into_counts();
        let advisories = daemon
            .as_ref()
            .and_then(|status| status.rpm_advisories.as_ref())
            .filter(|advisories| advisories.installed_packages == total_packages);
        StatusResult {
            total_packages,
            explicit_packages,
            orphan_packages,
            updates_available,
            security_vulnerabilities: advisories.map_or(0, |advisories| advisories.findings),
            vulnerabilities_scanned: advisories.is_some(),
            security_unknown_packages: advisories.map(|advisories| advisories.unknown_packages),
            runtime_versions: daemon.map_or_else(Vec::new, |status| status.runtime_versions),
        }
    });
    (connected, status)
}

async fn status_fallback(fast: bool) -> Result<()> {
    let start = std::time::Instant::now();

    #[cfg(all(unix, feature = "fedora"))]
    if !fast && uses_fedora_status() {
        let (connected, status) = fedora_status_with_daemon().await;
        let status = status?;
        let report = StatusData {
            total_packages: status.total_packages,
            explicit_packages: status.explicit_packages,
            orphan_packages: status.orphan_packages,
            updates_available: status.updates_available,
            advisory_coverage: status.scanned_vulnerability_summary(),
            duration_ms: start.elapsed().as_secs_f64() * 1000.0,
            fast_mode: false,
        };
        if connected {
            crate::cli::commands::print_system_status(&report, Some(status.runtime_versions), true);
        } else {
            write_status_report(&report)?;
        }
        return Ok(());
    }

    #[cfg(unix)]
    if let Some(status) = query_daemon_status(fast).await {
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
    let report = StatusData {
        total_packages: total,
        explicit_packages: explicit,
        orphan_packages: orphans,
        updates_available: updates,
        duration_ms: duration.as_secs_f64() * 1000.0,
        fast_mode: fast,
        advisory_coverage,
    };
    write_status_report(&report)
}

fn write_status_report(report: &StatusData) -> Result<()> {
    let mut stdout = std::io::BufWriter::new(std::io::stdout());
    stdout.write_all(report.render().as_bytes())?;

    stdout.flush()?;
    Ok(())
}
