//! Shared package audit orchestration for direct CLI and daemon requests.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::vulnerability::{
    AssessmentUse, PackageAssessment, PackageCoverage, UnknownCoverage, VulnerabilitySource,
    parse_severity_score,
};
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvisoryReference {
    pub id: String,
    pub kind: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAdvisory {
    pub source: String,
    /// Package version named by the advisory, not the installed version.
    pub advisory_nevra: String,
    pub published_severity: String,
    pub description: String,
    pub references: Vec<AdvisoryReference>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

/// An advisory coordinate match does not establish exploitability or code safety.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingApplicability {
    Applicable,
    #[default]
    Possible,
}

/// Source metadata. Arch admission authority remains in its private snapshot owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AdvisoryProvenance {
    ArchSnapshot {
        payload_sha256: String,
        fetched_at: jiff::Timestamp,
        checked_at: jiff::Timestamp,
    },
    Osv {
        ecosystem: String,
    },
    NativeDnf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnassessedPackage {
    pub package: InstalledIdentity,
    pub reason: UnknownCoverage,
}

/// Missing legacy coverage must never become a complete successful scan.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AuditCoverage {
    #[default]
    Unreported,
    Reported {
        assessed: Vec<InstalledIdentity>,
        unassessed: Vec<UnassessedPackage>,
        sources: Vec<AdvisoryProvenance>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vulnerability {
    #[serde(default)]
    pub applicability: FindingApplicability,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityAuditResult {
    #[serde(default)]
    pub coverage: AuditCoverage,
    pub total_vulnerabilities: usize,
    pub high_severity: usize,
    pub vulnerabilities: Vec<(String, Vec<Vulnerability>)>,
}

/// Return a complete audit, never a successful subset after a scan failure.
pub async fn scan_installed(
    manager: &dyn PackageManager,
    scanner: &dyn VulnerabilitySource,
) -> Result<SecurityAuditResult> {
    let log_path = crate::core::paths::data_dir().join("audit/audit.jsonl");
    scan_installed_in(manager, scanner, &log_path).await
}

pub(crate) async fn scan_installed_in(
    manager: &dyn PackageManager,
    scanner: &dyn VulnerabilitySource,
    log_path: &std::path::Path,
) -> Result<SecurityAuditResult> {
    if let Some(native) = manager.security_audit() {
        let result = native.await?;
        log_completed_scan(&result, log_path).await?;
        return Ok(result);
    }
    let installed = manager
        .security_inventory()
        .await
        .map_err(|error| anyhow::anyhow!("Failed to list packages: {error}"))?;
    scan_inventory_in(installed, scanner, log_path).await
}

impl SecurityAuditResult {
    pub(crate) fn from_assessments(assessments: Vec<PackageAssessment>) -> Self {
        let mut assessed = Vec::new();
        let mut unassessed = Vec::new();
        let mut sources = Vec::new();
        let mut vulnerabilities = std::collections::BTreeMap::<String, Vec<Vulnerability>>::new();
        let mut total_vulnerabilities = 0;
        let mut high_severity = 0;
        for assessment in assessments {
            let identity = InstalledIdentity::from(&assessment.package);
            if let Some(source) = assessment.coverage.provenance()
                && !sources.contains(source)
            {
                sources.push(source.clone());
            }
            match assessment.coverage {
                PackageCoverage::Assessed { .. } => assessed.push(identity),
                PackageCoverage::Unknown { reason, .. } => unassessed.push(UnassessedPackage {
                    package: identity,
                    reason,
                }),
            }
            for finding in assessment.findings {
                high_severity += usize::from(finding.meets_minimum(MinimumSeverity::High));
                total_vulnerabilities += 1;
                vulnerabilities
                    .entry(assessment.package.name.clone())
                    .or_default()
                    .push(finding);
            }
        }
        assessed.sort();
        unassessed.sort_by(|a, b| a.package.cmp(&b.package));
        Self {
            coverage: AuditCoverage::Reported {
                assessed,
                unassessed,
                sources,
            },
            total_vulnerabilities,
            high_severity,
            vulnerabilities: vulnerabilities.into_iter().collect(),
        }
    }
}

async fn scan_inventory_in(
    installed: Vec<crate::package_managers::types::SecurityPackage>,
    scanner: &dyn VulnerabilitySource,
    log_path: &std::path::Path,
) -> Result<SecurityAuditResult> {
    let assessments = scanner
        .assess_packages(&installed, AssessmentUse::Review)
        .await?;
    super::vulnerability::validate_assessment_inventory(&installed, &assessments)?;
    let result = SecurityAuditResult::from_assessments(assessments);
    log_completed_scan(&result, log_path).await?;
    Ok(result)
}

async fn log_completed_scan(result: &SecurityAuditResult, path: &std::path::Path) -> Result<()> {
    // A successful CLI/TUI/daemon scan must not outlive its completion record.
    // Capture the destination now and keep filesystem locking/fsync off Tokio.
    let path = path.to_path_buf();
    let coverage = match &result.coverage {
        AuditCoverage::Unreported => "unreported".to_owned(),
        AuditCoverage::Reported {
            assessed,
            unassessed,
            sources,
        } => format!(
            "reported; {} assessed, {} unassessed; sources: {sources:?}",
            assessed.len(),
            unassessed.len(),
        ),
    };
    let description = format!(
        "Security audit completed: {} vulnerabilities found ({} high severity); coverage: {coverage}",
        result.total_vulnerabilities, result.high_severity,
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
    fn coverage17_legacy_audit_payload_does_not_imply_complete_coverage() {
        let result: SecurityAuditResult = serde_json::from_value(serde_json::json!({
            "total_vulnerabilities": 0,
            "high_severity": 0,
            "vulnerabilities": [],
        }))
        .expect("legacy daemon result remains readable");
        let wire = serde_json::to_value(result).expect("public audit result");
        assert_eq!(
            wire["coverage"],
            serde_json::json!({"status": "unreported"})
        );
    }

    #[tokio::test]
    async fn osv_queries_source_identity_but_attributes_findings_to_installed_binary() {
        use crate::core::security::vulnerability::VulnerabilityError;
        use crate::package_managers::types::SecurityPackage;
        use std::future::Future;
        use std::pin::Pin;
        use std::sync::Mutex;

        struct RecordingSource(Mutex<Vec<(String, String)>>);
        impl VulnerabilitySource for RecordingSource {
            fn assess_packages<'a>(
                &'a self,
                packages: &'a [SecurityPackage],
                _evidence_use: AssessmentUse,
            ) -> Pin<
                Box<
                    dyn Future<Output = Result<Vec<PackageAssessment>, VulnerabilityError>>
                        + Send
                        + 'a,
                >,
            > {
                Box::pin(async move {
                    let mut queries = std::collections::BTreeSet::new();
                    let mut assessments = Vec::new();
                    for package in packages {
                        let (name, version) = package.advisory_identity();
                        if queries.insert((name.to_owned(), version.to_owned())) {
                            self.0
                                .lock()
                                .unwrap()
                                .push((name.to_owned(), version.to_owned()));
                        }
                        assessments.push(PackageAssessment {
                            package: package.clone(),
                            coverage: PackageCoverage::Assessed {
                                provenance: AdvisoryProvenance::Osv {
                                    ecosystem: "Debian:fixture".into(),
                                },
                            },
                            findings: vec![Vulnerability {
                                applicability: FindingApplicability::Applicable,
                                id: "CVE-fixture".into(),
                                summary: "source finding".into(),
                                score: Some("8.0".into()),
                                advisory_severity: None,
                                native_advisory: None,
                                affected_installed: vec![InstalledIdentity::from(package)],
                            }],
                        });
                    }
                    Ok(assessments)
                })
            }
        }

        let scanner = RecordingSource(Mutex::new(Vec::new()));
        let package = SecurityPackage {
            origin: crate::package_managers::types::SecurityOrigin::DistributionPackage,
            name: "libacl1".into(),
            version: "2.3.2-2+b1".into(),
            advisory_source: Some(("acl".into(), "2.3.2-2".into())),
            architecture: Some("amd64".into()),
            description: String::new(),
            licenses: Vec::new(),
        };
        let mut second_binary = package.clone();
        second_binary.name = "libacl2".into();
        second_binary.version = "2.3.2-2+b2".into();
        let directory = tempfile::tempdir().unwrap();
        let audit = scan_inventory_in(
            vec![package, second_binary],
            &scanner,
            &directory.path().join("audit.jsonl"),
        )
        .await
        .unwrap();
        assert_eq!(
            scanner.0.into_inner().unwrap(),
            [("acl".into(), "2.3.2-2".into())]
        );
        assert_eq!(audit.total_vulnerabilities, 2);
        assert_eq!(audit.high_severity, 2);
        assert_eq!(audit.vulnerabilities[0].0, "libacl1");
        assert_eq!(audit.vulnerabilities[1].0, "libacl2");
        assert_eq!(
            audit.vulnerabilities[0].1[0].affected_installed[0].name,
            "libacl1"
        );
        assert_eq!(
            audit.vulnerabilities[0].1[0].affected_installed[0].version,
            "2.3.2-2+b1"
        );
        assert_eq!(
            audit.vulnerabilities[1].1[0].affected_installed[0].version,
            "2.3.2-2+b2"
        );
    }

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
                applicability: FindingApplicability::Applicable,
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
            applicability: FindingApplicability::Applicable,
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
