//! Shared package audit orchestration for direct CLI and daemon requests.
use anyhow::Result;
use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};

use super::vulnerability::{VulnerabilitySource, parse_severity_score};
use crate::package_managers::PackageManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub summary: String,
    pub score: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAuditResult {
    pub total_vulnerabilities: usize,
    pub high_severity: usize,
    pub vulnerabilities: Vec<(String, Vec<Vulnerability>)>,
}

/// Return a complete audit, never a successful subset after a scan failure.
pub async fn scan_installed(
    manager: &dyn PackageManager,
    scanner: &dyn VulnerabilitySource,
) -> Result<SecurityAuditResult> {
    let installed = manager
        .list_installed()
        .await
        .map_err(|error| anyhow::anyhow!("Failed to list packages: {error}"))?;
    let mut result = SecurityAuditResult {
        total_vulnerabilities: 0,
        high_severity: 0,
        vulnerabilities: Vec::new(),
    };
    let mut pending = stream::iter(installed)
        .map(|package| async move {
            let findings = scanner.scan_package(&package.name, &package.version).await;
            (package.name, findings)
        })
        .buffer_unordered(32);
    while let Some((name, findings)) = pending.next().await {
        let findings = findings.map_err(|error| {
            anyhow::anyhow!("Failed to scan package {name} for vulnerabilities: {error}")
        })?;
        if findings.is_empty() {
            continue;
        }
        let findings: Vec<_> = findings
            .into_iter()
            .map(|finding| {
                if finding
                    .score
                    .as_deref()
                    .and_then(parse_severity_score)
                    .is_some_and(|score| score >= 7.0)
                {
                    result.high_severity += 1;
                }
                Vulnerability {
                    id: finding.id,
                    summary: finding.summary,
                    score: finding.score,
                }
            })
            .collect();
        result.total_vulnerabilities += findings.len();
        result.vulnerabilities.push((name, findings));
    }
    // Completion order must not leak into CLI/daemon result ordering.
    result
        .vulnerabilities
        .sort_by(|left, right| left.0.cmp(&right.0));
    super::audit_log_nonblocking(
        super::AuditEventType::SecurityAudit,
        super::AuditSeverity::Info,
        "security_scan",
        &format!(
            "Security audit completed: {} vulnerabilities found ({} high severity)",
            result.total_vulnerabilities, result.high_severity
        ),
    );
    Ok(result)
}
