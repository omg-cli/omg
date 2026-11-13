//! Native Arch advisory applicability. A tracker snapshot is not an
//! introduced-version boundary; installed packages remain candidates until
//! the published fix is installed (the arch-audit comparison model).
use anyhow::{Context, Result, ensure};
use std::collections::HashSet;

use super::types::{SecurityOrigin, SecurityPackage, parse_version};

use crate::core::security::scan::{
    AdvisoryProvenance, AdvisoryReference, AdvisorySeverity, FindingApplicability,
    InstalledIdentity, NativeAdvisory, SecurityAuditResult, Vulnerability,
};
use crate::core::security::vulnerability::{
    AlsaIssue, PackageAssessment, PackageCoverage, UnknownCoverage,
};

pub(crate) fn audit_result(
    installed: &[SecurityPackage],
    advisories: &[AlsaIssue],
) -> Result<SecurityAuditResult> {
    Ok(SecurityAuditResult::from_assessments(assess_packages(
        installed, advisories, None,
    )?))
}

pub(crate) fn assess_packages(
    installed: &[SecurityPackage],
    advisories: &[AlsaIssue],
    provenance: Option<&AdvisoryProvenance>,
) -> Result<Vec<PackageAssessment>> {
    ensure!(!advisories.is_empty(), "Arch advisory feed is empty");
    ensure!(
        provenance.is_none_or(|source| matches!(source, AdvisoryProvenance::ArchSnapshot { .. })),
        "Arch advisory applicability requires Arch snapshot provenance"
    );
    for package in installed {
        ensure!(
            !package.name.trim().is_empty() && parse_version(&package.version).is_some(),
            "Incomplete or invalid Arch package advisory identity"
        );
        if let SecurityOrigin::ArchRepository { repository }
        | SecurityOrigin::OtherRepository { repository } = &package.origin
        {
            ensure!(
                !repository.trim().is_empty(),
                "Empty advisory repository identity"
            );
        }
    }
    let mut assessments = installed
        .iter()
        .map(|package| {
            let coverage = match (&package.origin, provenance) {
                (SecurityOrigin::ArchRepository { .. }, Some(source)) => {
                    PackageCoverage::Assessed {
                        provenance: source.clone(),
                    }
                }
                (SecurityOrigin::Unknown, _) => PackageCoverage::Unknown {
                    reason: UnknownCoverage::OriginUnestablished,
                    provenance: provenance.cloned(),
                },
                (SecurityOrigin::ArchRepository { .. }, None) => PackageCoverage::Unknown {
                    reason: UnknownCoverage::EvidenceUnavailable,
                    provenance: None,
                },
                _ => PackageCoverage::Unknown {
                    reason: UnknownCoverage::SourceNotCovered,
                    provenance: provenance.cloned(),
                },
            };
            PackageAssessment {
                package: package.clone(),
                coverage,
                findings: Vec::new(),
            }
        })
        .collect::<Vec<_>>();
    let mut identities = HashSet::new();
    for advisory in advisories {
        ensure!(
            !advisory.name.trim().is_empty()
                && !advisory.packages.is_empty()
                && advisory.packages.iter().all(|name| !name.trim().is_empty())
                && !advisory.issues.is_empty()
                && advisory.issues.iter().all(|id| !id.trim().is_empty()),
            "Incomplete Arch advisory identity"
        );
        ensure!(
            identities.insert(&advisory.name),
            "Duplicate Arch advisory identity: {}",
            advisory.name
        );
        ensure!(
            matches!(
                advisory.status.as_str(),
                "Unknown" | "Not affected" | "Vulnerable" | "Fixed" | "Testing"
            ),
            "Unknown Arch advisory status for {}",
            advisory.name
        );
        if advisory.status == "Not affected" {
            continue;
        }
        let severity = match advisory.severity.as_str() {
            "Critical" => AdvisorySeverity::Critical,
            "High" => AdvisorySeverity::Important,
            "Medium" => AdvisorySeverity::Moderate,
            "Low" => AdvisorySeverity::Low,
            "Unknown" => AdvisorySeverity::Unspecified,
            _ => anyhow::bail!("Unknown Arch advisory severity for {}", advisory.name),
        };
        // Validate independently of installed matches: candidate cache admission
        // calls this with an empty inventory before retaining the whole feed.
        let fixed = advisory
            .fixed
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(|value| parse_version(value).context("Invalid Arch advisory fixed version"))
            .transpose()?;
        for assessment in &mut assessments {
            let package = &assessment.package;
            if !advisory.packages.contains(&package.name) {
                continue;
            }
            let version =
                parse_version(&package.version).context("Invalid installed Arch version")?;
            if let Some(fixed) = &fixed
                && &version >= fixed
            {
                continue;
            }
            let references = advisory
                .issues
                .iter()
                .map(|id| AdvisoryReference {
                    id: id.clone(),
                    kind: "Arch Linux Security Tracker".into(),
                    url: format!("https://security.archlinux.org/{}", urlencoding::encode(id)),
                })
                .collect();
            assessment.findings.push(Vulnerability {
                applicability: if assessment.coverage.is_assessed() {
                    FindingApplicability::Applicable
                } else {
                    FindingApplicability::Possible
                },
                id: advisory.name.clone(),
                summary: format!("{}: {}", advisory.name, advisory.kind),
                score: None,
                advisory_severity: Some(severity),
                native_advisory: Some(NativeAdvisory {
                    source: "Arch Linux Security Tracker".into(),
                    // Arch has no RPM NEVRA. Empty means not applicable.
                    advisory_nevra: String::new(),
                    published_severity: advisory.severity.clone(),
                    description: format!(
                        "Status: {}; affected snapshot: {}; fixed: {}",
                        advisory.status,
                        advisory.affected,
                        advisory.fixed.as_deref().unwrap_or("not published")
                    ),
                    references,
                }),
                affected_installed: vec![InstalledIdentity::from(package)],
            });
        }
    }
    Ok(assessments)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage17_unknown_installed_origin_is_reported_even_without_matches() {
        let package = SecurityPackage {
            origin: SecurityOrigin::Unknown,
            name: "omg-unmapped-audit-fixture".into(),
            version: "1.0-1".into(),
            advisory_source: None,
            architecture: Some("any".into()),
            description: String::new(),
            licenses: vec![],
        };
        let advisory: AlsaIssue = serde_json::from_str(
            r#"{"name":"AVG-fixture","packages":["other-package"],"status":"Not affected","severity":"Low","affected":"1.0-1","fixed":null,"issues":["CVE-fixture"]}"#,
        )
        .expect("complete unrelated advisory fixture");
        let result = audit_result(&[package], &[advisory]).expect("valid native audit");
        assert_eq!(result.total_vulnerabilities, 0);
        let wire = serde_json::to_value(&result).expect("public audit result");
        assert_eq!(wire["coverage"]["status"], "reported");
        assert_eq!(wire["coverage"]["assessed"], serde_json::json!([]));
        let unassessed = wire["coverage"]["unassessed"]
            .as_array()
            .expect("unassessed inventory must be explicit");
        assert_eq!(unassessed.len(), 1);
        assert_eq!(
            unassessed[0]["package"]["name"],
            "omg-unmapped-audit-fixture"
        );
        assert_eq!(unassessed[0]["package"]["version"], "1.0-1");
        assert_eq!(unassessed[0]["package"]["architecture"], "any");
    }

    #[test]
    fn another_distribution_cannot_supply_arch_applicability_provenance() {
        let advisory: AlsaIssue = serde_json::from_str(r#"{"name":"AVG-fixture","packages":["fixture"],"status":"Vulnerable","severity":"High","affected":"1-1","fixed":null,"issues":["CVE-fixture"]}"#).expect("complete advisory");
        for source in [
            AdvisoryProvenance::NativeDnf,
            AdvisoryProvenance::Osv {
                ecosystem: "Debian:12".into(),
            },
        ] {
            assert!(
                assess_packages(&[], std::slice::from_ref(&advisory), Some(&source)).is_err(),
                "another source must not be relabelled as an Arch snapshot"
            );
        }
    }

    #[test]
    fn blank_advisory_identifiers_cannot_be_admitted_as_clean_evidence() {
        let valid: AlsaIssue = serde_json::from_str(r#"{"name":"AVG-test","packages":["fixture"],"status":"Vulnerable","severity":"High","affected":"1.0-1","fixed":null,"issues":["CVE-test"],"type":"code execution"}"#).unwrap();
        for status in ["Vulnerable", "Not affected"] {
            let mut complete = valid.clone();
            complete.status = status.into();
            let result = audit_result(&[], std::slice::from_ref(&complete))
                .expect("complete advisory must be accepted without installed packages");
            assert_eq!(result.total_vulnerabilities, 0);
            assert_eq!(result.high_severity, 0);
            let mut missing_packages = complete.clone();
            missing_packages.packages.clear();
            let mut missing_issues = complete.clone();
            missing_issues.issues.clear();
            for invalid in [missing_packages, missing_issues] {
                let error = audit_result(&[], &[invalid])
                    .expect_err("empty advisory identity lists must be rejected");
                assert_eq!(error.to_string(), "Incomplete Arch advisory identity");
            }
            for field in ["name", "packages", "issues"] {
                let mut invalid = valid.clone();
                invalid.status = status.into();
                match field {
                    "name" => invalid.name = " ".into(),
                    "packages" => invalid.packages.push(String::new()),
                    "issues" => invalid.issues.push(" ".into()),
                    _ => unreachable!(),
                }
                assert!(
                    audit_result(&[], &[invalid]).is_err(),
                    "blank {field} in {status} feed must fail before cache admission"
                );
            }
        }
    }

    #[test]
    fn unknown_severity_and_unpublished_fix_do_not_invent_safety_or_scores() {
        let mut advisory: AlsaIssue = serde_json::from_str(r#"{"name":"AVG-test","packages":["fixture"],"status":"Unknown","severity":"Unknown","affected":"1.0-1","fixed":null,"issues":["CVE-test"]}"#).unwrap();
        let installed = [SecurityPackage {
            origin: SecurityOrigin::Unknown,
            name: "fixture".into(),
            version: "3.0-1".into(),
            advisory_source: None,
            architecture: Some("x86_64".into()),
            description: String::new(),
            licenses: vec![],
        }];
        let result = audit_result(&installed, std::slice::from_ref(&advisory)).unwrap();
        assert_eq!(result.total_vulnerabilities, 1);
        assert_eq!(result.high_severity, 0);
        let finding = &result.vulnerabilities[0].1[0];
        assert!(finding.score.is_none());
        assert_eq!(
            finding.advisory_severity,
            Some(AdvisorySeverity::Unspecified)
        );
        assert_eq!(finding.affected_installed[0].version, "3.0-1");
        advisory.status = "Not affected".into();
        assert_eq!(
            audit_result(&installed, std::slice::from_ref(&advisory))
                .unwrap()
                .total_vulnerabilities,
            0
        );
        advisory.status = "Vulnerable".into();
        advisory.severity = "Unexpected".into();
        assert!(audit_result(&installed, std::slice::from_ref(&advisory)).is_err());
        advisory.severity = "Low".into();
        advisory.packages = vec!["different-package".into()];
        assert_eq!(
            audit_result(&installed, std::slice::from_ref(&advisory))
                .unwrap()
                .total_vulnerabilities,
            0
        );
        advisory.issues.clear();
        assert!(audit_result(&installed, &[advisory]).is_err());
    }

    #[test]
    fn fixed_advisory_binds_only_older_installed_identity() {
        let advisory: AlsaIssue = serde_json::from_str(r#"{"name":"AVG-test","packages":["fixture"],"status":"Fixed","severity":"High","affected":"2.0-1","fixed":"2.0-2","issues":["CVE-test"],"type":"code execution"}"#).unwrap();
        let package = |version: &str| SecurityPackage {
            origin: SecurityOrigin::Unknown,
            name: "fixture".into(),
            version: version.into(),
            advisory_source: None,
            architecture: Some("x86_64".into()),
            description: String::new(),
            licenses: vec![],
        };
        let installed = vec![package("1:1.0-1"), package("2.0-2"), package("1.0-1")];
        assert!(
            audit_result(
                &[package("invalid version")],
                std::slice::from_ref(&advisory)
            )
            .is_err(),
            "malformed installed versions must fail the audit, not silently skip a finding"
        );
        let result = audit_result(&installed, std::slice::from_ref(&advisory)).unwrap();
        assert_eq!(result.total_vulnerabilities, 1);
        assert_eq!(result.high_severity, 1);
        assert!(
            audit_result(&installed, &[advisory.clone(), advisory.clone()]).is_err(),
            "duplicate advisory identities must not inflate findings"
        );
        let finding = &result.vulnerabilities[0].1[0];
        assert_eq!(finding.affected_installed[0].version, "1.0-1");
        assert_eq!(
            finding.affected_installed[0].architecture.as_deref(),
            Some("x86_64")
        );
        assert!(finding.score.is_none());
        assert_eq!(
            finding.native_advisory.as_ref().unwrap().references[0].id,
            "CVE-test"
        );
        let mut invalid = advisory.clone();
        invalid.fixed = Some("invalid version".into());
        assert!(
            audit_result(&[], std::slice::from_ref(&invalid)).is_err(),
            "cache admission must reject malformed fixed versions without installed matches"
        );
        assert!(audit_result(&installed, &[invalid]).is_err());
        let mut unknown = advisory;
        unknown.status = "Unexpected".into();
        assert!(audit_result(&installed, &[unknown]).is_err());
        assert!(audit_result(&installed, &[]).is_err());
    }
}
