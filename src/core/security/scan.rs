//! Shared package audit orchestration for direct CLI and daemon requests.
use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};

use super::vulnerability::{VulnerabilitySource, parse_severity_score};
use crate::package_managers::PackageManager;

/// Published DNF advisory severity; this is not a numeric CVSS score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdvisorySeverity {
    Low,
    Moderate,
    Important,
    Critical,
    Unspecified,
}

#[derive(Debug, Clone, Copy)]
pub enum MinimumSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisoryReference {
    pub id: String,
    pub kind: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeAdvisory {
    pub source: String,
    /// Package version named by the advisory, not the installed version.
    pub advisory_nevra: String,
    pub published_severity: String,
    pub description: String,
    pub references: Vec<AdvisoryReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledIdentity {
    pub name: String,
    pub version: String,
    pub architecture: Option<String>,
}

impl From<&crate::package_managers::types::SecurityPackage> for InstalledIdentity {
    fn from(package: &crate::package_managers::types::SecurityPackage) -> Self {
        Self {
            name: package.name.clone(),
            version: package.version.clone(),
            architecture: package.architecture.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub summary: String,
    pub score: Option<String>,
    #[serde(default)]
    pub advisory_severity: Option<AdvisorySeverity>,
    #[serde(default)]
    pub native_advisory: Option<NativeAdvisory>,
    #[serde(default)]
    pub affected_installed: Vec<InstalledIdentity>,
}

impl Vulnerability {
    #[must_use]
    pub fn meets_minimum(&self, minimum: MinimumSeverity) -> bool {
        if let Some(score) = self.score.as_deref().and_then(parse_severity_score) {
            return score
                >= match minimum {
                    MinimumSeverity::Low => 0.0,
                    MinimumSeverity::Medium => 4.0,
                    MinimumSeverity::High => 7.0,
                    MinimumSeverity::Critical => 9.0,
                };
        }
        matches!(
            (self.advisory_severity, minimum),
            (Some(AdvisorySeverity::Critical), _)
                | (
                    Some(AdvisorySeverity::Important),
                    MinimumSeverity::Low | MinimumSeverity::Medium | MinimumSeverity::High,
                )
                | (
                    Some(AdvisorySeverity::Moderate),
                    MinimumSeverity::Low | MinimumSeverity::Medium
                )
                | (Some(AdvisorySeverity::Low), MinimumSeverity::Low)
        )
    }
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
    if let Some(native) = manager.security_audit() {
        let result = native.await?;
        log_completed_scan(&result).await?;
        return Ok(result);
    }
    let installed = manager
        .security_inventory()
        .await
        .map_err(|error| anyhow::anyhow!("Failed to list packages: {error}"))?;
    let mut result = SecurityAuditResult {
        total_vulnerabilities: 0,
        high_severity: 0,
        vulnerabilities: Vec::new(),
    };
    let mut pending = stream::iter(installed)
        .map(|package| async move {
            let findings = async {
                let version = crate::package_managers::types::parse_version(&package.version)
                    .ok_or_else(|| {
                        anyhow::anyhow!("Unsupported installed version: {}", package.version)
                    })?;
                Ok::<_, anyhow::Error>(scanner.scan_package(&package.name, &version).await?)
            }
            .await;
            (package, findings)
        })
        .buffer_unordered(32);
    while let Some((package, findings)) = pending.next().await {
        let name = package.name.clone();
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
                    advisory_severity: None,
                    native_advisory: None,
                    affected_installed: vec![InstalledIdentity::from(&package)],
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
    log_completed_scan(&result).await?;
    Ok(result)
}

async fn log_completed_scan(result: &SecurityAuditResult) -> Result<()> {
    // A successful CLI/TUI/daemon scan must not outlive its completion record.
    // Capture the destination now and keep filesystem locking/fsync off Tokio.
    let path = crate::core::paths::data_dir().join("audit/audit.jsonl");
    let description = format!(
        "Security audit completed: {} vulnerabilities found ({} high severity)",
        result.total_vulnerabilities, result.high_severity
    );
    tokio::task::spawn_blocking(move || {
        let mut logger = super::AuditLogger::new_in(path)?;
        logger.log(
            super::AuditEventType::SecurityAudit,
            super::AuditSeverity::Info,
            "security_scan",
            &description,
        )
    })
    .await
    .context("Security audit log writer failed")?
    .context("Failed to persist completed security audit")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_severity_filters_without_inventing_a_cvss_score() {
        for (severity, expected) in [
            (AdvisorySeverity::Low, [true, false, false, false]),
            (AdvisorySeverity::Moderate, [true, true, false, false]),
            (AdvisorySeverity::Important, [true, true, true, false]),
            (AdvisorySeverity::Critical, [true, true, true, true]),
            (AdvisorySeverity::Unspecified, [false; 4]),
        ] {
            let finding = Vulnerability {
                id: "FEDORA-fixture".into(),
                summary: "fixture".into(),
                score: None,
                advisory_severity: Some(severity),
                native_advisory: None,
                affected_installed: Vec::new(),
            };
            for (minimum, expected) in [
                MinimumSeverity::Low,
                MinimumSeverity::Medium,
                MinimumSeverity::High,
                MinimumSeverity::Critical,
            ]
            .into_iter()
            .zip(expected)
            {
                assert_eq!(finding.meets_minimum(minimum), expected);
            }
            assert!(finding.score.is_none());
            assert!(serde_json::to_value(&finding).unwrap()["score"].is_null());
        }
    }

    #[test]
    fn actual_cvss_and_unknown_severity_keep_distinct_meanings() {
        let mut finding = Vulnerability {
            id: "CVE-fixture".into(),
            summary: "fixture".into(),
            score: None,
            advisory_severity: None,
            native_advisory: None,
            affected_installed: Vec::new(),
        };
        assert!(!finding.meets_minimum(MinimumSeverity::Low));
        for (score, high, critical) in [
            ("6.9", false, false),
            ("7.0", true, false),
            ("9.0", true, true),
            ("NaN", false, false),
            ("11", false, false),
        ] {
            finding.score = Some(score.into());
            assert_eq!(finding.meets_minimum(MinimumSeverity::High), high);
            assert_eq!(finding.meets_minimum(MinimumSeverity::Critical), critical);
        }
    }
}
