//! Native Arch advisory applicability. A tracker snapshot is not an
//! introduced-version boundary; installed packages remain candidates until
//! the published fix is installed (the arch-audit comparison model).
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, HashSet};

use super::types::{SecurityPackage, parse_version};

use crate::core::security::scan::{
    AdvisoryReference, AdvisorySeverity, InstalledIdentity, MinimumSeverity, NativeAdvisory,
    SecurityAuditResult, Vulnerability,
};
use crate::core::security::vulnerability::AlsaIssue;

pub(crate) fn audit_result(
    installed: &[SecurityPackage],
    advisories: &[AlsaIssue],
) -> Result<SecurityAuditResult> {
    ensure!(!advisories.is_empty(), "Arch advisory feed is empty");
    let mut groups: BTreeMap<String, Vec<Vulnerability>> = BTreeMap::new();
    let mut identities = HashSet::new();
    for advisory in advisories {
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
        ensure!(
            !advisory.name.is_empty()
                && !advisory.packages.is_empty()
                && !advisory.issues.is_empty(),
            "Incomplete Arch advisory identity"
        );
        // Validate independently of installed matches: candidate cache admission
        // calls this with an empty inventory before retaining the whole feed.
        let fixed = advisory
            .fixed
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(|value| parse_version(value).context("Invalid Arch advisory fixed version"))
            .transpose()?;
        for package in installed
            .iter()
            .filter(|package| advisory.packages.contains(&package.name))
        {
            let version =
                parse_version(&package.version).context("Invalid installed Arch version")?;
            if let Some(fixed) = &fixed {
                if &version >= fixed {
                    continue;
                }
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
            groups
                .entry(package.name.clone())
                .or_default()
                .push(Vulnerability {
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
    Ok(SecurityAuditResult {
        total_vulnerabilities: groups.values().map(Vec::len).sum(),
        high_severity: groups
            .values()
            .flatten()
            .filter(|finding| finding.meets_minimum(MinimumSeverity::High))
            .count(),
        vulnerabilities: groups.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_severity_and_unpublished_fix_do_not_invent_safety_or_scores() {
        let mut advisory: AlsaIssue = serde_json::from_str(r#"{"name":"AVG-test","packages":["fixture"],"status":"Unknown","severity":"Unknown","affected":"1.0-1","fixed":null,"issues":["CVE-test"]}"#).unwrap();
        let installed = [SecurityPackage {
            name: "fixture".into(),
            version: "3.0-1".into(),
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
            name: "fixture".into(),
            version: version.into(),
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
