//! Status command - system-wide package status overview

use anyhow::{Context, Result};
use serde::Serialize;
use std::io::{self, BufWriter, Write};

use crate::cli::tea::StatusData;

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
    if !json && !fast {
        let loading = StatusData::loading_view();
        let mut stdout = io::stdout().lock();
        writeln!(stdout, "{loading}")?;
        stdout.flush()?;
    }

    let status = StatusData::load(fast)
        .await
        .context("Status check failed")?;
    let mut stdout = BufWriter::new(io::stdout().lock());
    if json {
        let report = StatusJson {
            total_packages: status.total_packages,
            explicit_packages: status.explicit_packages,
            orphan_packages: status.orphan_packages,
            updates_available: status.updates_available,
            query_time_ms: status.duration_ms,
        };
        serde_json::to_writer_pretty(&mut stdout, &report)
            .context("Failed to serialize status as JSON")?;
        writeln!(stdout)?;
    } else {
        stdout.write_all(status.render().as_bytes())?;
        if !fast {
            writeln!(stdout)?;
        }
    }
    stdout.flush().context("Failed to write status report")
}
