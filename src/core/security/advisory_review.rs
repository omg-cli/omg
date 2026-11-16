//! Acknowledgement of disclosed advisory risk never changes its classification.

use super::scan::{AdvisoryProvenance, FindingApplicability};
use super::vulnerability::PackageAssessment;
use sha2::{Digest, Sha256};

pub(crate) struct AdvisoryRiskReview {
    id: String,
    details: String,
}

pub(crate) struct AdvisoryRiskAcceptance {
    review_id: String,
}

impl AdvisoryRiskReview {
    pub(crate) fn new(
        assessments: &[PackageAssessment],
        transaction_context: &str,
    ) -> anyhow::Result<Option<Self>> {
        if assessments.iter().all(|item| item.findings.is_empty()) {
            return Ok(None);
        }
        let mut records = Vec::with_capacity(assessments.len());
        for assessment in assessments {
            let provenance = match assessment.coverage.provenance() {
                Some(AdvisoryProvenance::ArchSnapshot { payload_sha256, .. }) => {
                    serde_json::json!({"arch_snapshot_sha256": payload_sha256})
                }
                other => serde_json::to_value(other)?,
            };
            let mut findings = assessment
                .findings
                .iter()
                .map(serde_json::to_string)
                .collect::<Result<Vec<_>, _>>()?;
            findings.sort();
            let package = &assessment.package;
            let record = serde_json::to_string(&(
                (
                    &package.name,
                    &package.version,
                    &package.origin,
                    &package.architecture,
                    &package.advisory_source,
                    &package.licenses,
                ),
                assessment.coverage.is_assessed(),
                assessment.coverage.unknown_reason(),
                provenance,
                findings,
            ))?;
            records.push(record);
        }
        records.sort();
        let id = hex::encode(Sha256::digest(serde_json::to_vec(&(
            "omg-advisory-risk-v1",
            transaction_context,
            records,
        ))?));
        let mut details = String::from(
            "\nSECURITY WARNING: the selected transaction has disclosed advisory findings.\nAccepting the risk does not mark these versions safe or establish missing coverage.\n",
        );
        for assessment in assessments {
            if assessment.findings.is_empty() {
                continue;
            }
            use std::fmt::Write as _;
            writeln!(
                details,
                "Package: {}",
                serde_json::to_string(&(
                    &assessment.package.name,
                    &assessment.package.version,
                    &assessment.package.architecture,
                ))?
            )?;
            if let Some(reason) = assessment.coverage.unknown_reason() {
                writeln!(details, "Coverage: unknown ({reason:?})")?;
            } else {
                writeln!(details, "Coverage: assessed")?;
            }
            writeln!(
                details,
                "Source: {}",
                serde_json::to_string(&assessment.coverage.provenance())?
            )?;
            for finding in &assessment.findings {
                let confidence = match finding.applicability {
                    FindingApplicability::Applicable => "affected version",
                    FindingApplicability::Possible => "possible match; applicability unconfirmed",
                };
                writeln!(
                    details,
                    "  {} ({confidence})",
                    serde_json::to_string(&finding.id)?
                )?;
                writeln!(details, "  {}", serde_json::to_string(&finding.summary)?)?;
                if let Some(url) = advisory_link(&finding.id) {
                    writeln!(details, "  {url}")?;
                }
                if let Some(native) = &finding.native_advisory {
                    writeln!(
                        details,
                        "  Source: {}",
                        serde_json::to_string(&native.source)?
                    )?;
                    writeln!(
                        details,
                        "  Provider details: {}",
                        serde_json::to_string(&native.description)?
                    )?;
                    for reference in &native.references {
                        if let Some(url) = safe_reference(&reference.url) {
                            writeln!(details, "  {url}")?;
                        }
                    }
                }
            }
        }
        let details = details
            .lines()
            .map(crate::cli::style::sanitize_terminal_text)
            .collect::<Vec<_>>()
            .join("\n");
        anyhow::ensure!(
            details.len() <= 60 * 1024,
            "Advisory review exceeds terminal display limit; split the transaction"
        );
        Ok(Some(Self { id, details }))
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }
    pub(crate) fn details(&self) -> &str {
        &self.details
    }

    pub(crate) fn accept(&self, answer: &str) -> anyhow::Result<AdvisoryRiskAcceptance> {
        anyhow::ensure!(
            answer == format!("accept {}", self.id),
            "Advisory risk was not explicitly accepted; installation cancelled"
        );
        Ok(AdvisoryRiskAcceptance {
            review_id: self.id.clone(),
        })
    }
}

impl AdvisoryRiskAcceptance {
    pub(crate) fn matches(&self, review: &AdvisoryRiskReview) -> bool {
        self.review_id == review.id
    }
}

fn advisory_link(id: &str) -> Option<String> {
    let safe_id = !id.is_empty()
        && id.len() <= 160
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !safe_id {
        return None;
    }
    if let Some(cve) = id.strip_prefix("CVE-") {
        let (year, number) = cve.split_once('-')?;
        if year.len() == 4
            && number.len() >= 4
            && year
                .bytes()
                .chain(number.bytes())
                .all(|byte| byte.is_ascii_digit())
        {
            return Some(format!("https://www.cve.org/CVERecord?id={id}"));
        }
        return None;
    }
    if id.strip_prefix("AVG-").is_some_and(|number| {
        !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
    }) {
        return Some(format!("https://security.archlinux.org/{id}"));
    }
    if ["GHSA-", "RUSTSEC-", "OSV-", "GO-", "PYSEC-"]
        .iter()
        .any(|prefix| id.starts_with(prefix))
    {
        return Some(format!("https://osv.dev/vulnerability/{id}"));
    }
    None
}

fn safe_reference(value: &str) -> Option<String> {
    if value != crate::cli::style::sanitize_terminal_text(value) {
        return None;
    }
    let url = reqwest::Url::parse(value).ok()?;
    (url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none())
    .then(|| url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::security::scan::{FindingApplicability, Vulnerability};
    use crate::core::security::vulnerability::{PackageAssessment, UnknownCoverage};
    use crate::package_managers::types::{SecurityOrigin, SecurityPackage};

    fn package(name: &str) -> PackageAssessment {
        PackageAssessment::unknown(
            SecurityPackage {
                name: name.into(),
                version: "1.0-1".into(),
                origin: SecurityOrigin::DistributionPackage,
                advisory_source: None,
                architecture: None,
                description: String::new(),
                licenses: vec!["MIT".into()],
            },
            UnknownCoverage::EvidenceUnavailable,
        )
    }

    fn finding(id: &str, applicability: FindingApplicability) -> Vulnerability {
        Vulnerability {
            applicability,
            id: id.into(),
            summary: "A disclosed vulnerability".into(),
            score: None,
            advisory_severity: None,
            native_advisory: None,
            affected_installed: Vec::new(),
        }
    }

    #[test]
    fn no_findings_do_not_require_risk_consent() -> anyhow::Result<()> {
        assert!(AdvisoryRiskReview::new(&[package("app")], "transaction")?.is_none());
        Ok(())
    }

    #[test]
    fn large_upgrade_reviews_disclosed_risk_without_listing_unaffected_packages()
    -> anyhow::Result<()> {
        let mut subjects = (0..1000)
            .map(|index| package(&format!("dependency-{index}")))
            .collect::<Vec<_>>();
        let mut app = package("affected-app");
        app.findings = vec![finding("CVE-2026-12345", FindingApplicability::Applicable)];
        subjects.push(app);
        let review = AdvisoryRiskReview::new(&subjects, "large-upgrade")?.unwrap();
        assert!(review.details().contains("affected-app"));
        assert!(!review.details().contains("dependency-"));
        let accepted = review.accept(&format!("accept {}", review.id()))?;
        subjects[0].package.version = "2.0-1".into();
        assert!(!accepted.matches(&AdvisoryRiskReview::new(&subjects, "large-upgrade")?.unwrap()));
        Ok(())
    }

    #[test]
    fn applicable_and_possible_findings_require_distinct_explicit_consent() -> anyhow::Result<()> {
        let mut assessment = package("app");
        for applicability in [
            FindingApplicability::Applicable,
            FindingApplicability::Possible,
        ] {
            assessment.findings = vec![finding("CVE-2026-12345", applicability)];
            let review = AdvisoryRiskReview::new(std::slice::from_ref(&assessment), "batch")?
                .expect("findings require review even with unknown coverage");
            assert!(
                review
                    .details()
                    .contains("https://www.cve.org/CVERecord?id=CVE-2026-12345")
            );
            assert!(review.details().contains("1.0-1"));
            assert!(review.details().contains(match applicability {
                FindingApplicability::Applicable => "affected version",
                FindingApplicability::Possible => "possible match",
            }));
            for answer in ["", "yes", "y", "no", "accept another-review"] {
                assert!(review.accept(answer).is_err());
            }
            let acceptance = review.accept(&format!("accept {}", review.id()))?;
            assert!(acceptance.matches(&review));
        }
        Ok(())
    }

    #[test]
    fn consent_binds_dependencies_evidence_and_transaction_context() -> anyhow::Result<()> {
        let mut app = package("app");
        app.findings = vec![finding(
            "GHSA-2345-6789-abcd",
            FindingApplicability::Possible,
        )];
        let mut subjects = vec![app, package("dependency")];
        let review = AdvisoryRiskReview::new(&subjects, "policy-principal-artifact")?.unwrap();
        let accepted = review.accept(&format!("accept {}", review.id()))?;
        subjects.reverse();
        assert!(
            accepted.matches(
                &AdvisoryRiskReview::new(&subjects, "policy-principal-artifact")?.unwrap()
            )
        );
        subjects[0].package.version = "2.0-1".into();
        assert!(
            !accepted.matches(
                &AdvisoryRiskReview::new(&subjects, "policy-principal-artifact")?.unwrap()
            )
        );
        assert!(
            !accepted.matches(
                &AdvisoryRiskReview::new(&subjects, "changed policy or principal")?.unwrap()
            )
        );
        subjects[1]
            .findings
            .push(finding("CVE-2026-99999", FindingApplicability::Applicable));
        assert!(
            !accepted.matches(
                &AdvisoryRiskReview::new(&subjects, "policy-principal-artifact")?.unwrap()
            )
        );
        Ok(())
    }

    #[test]
    fn provider_text_cannot_inject_terminal_controls_or_unsafe_links() -> anyhow::Result<()> {
        let mut assessment = package("app\u{1b}[2J\nforged prompt");
        assessment.findings = vec![finding("AVG-1234", FindingApplicability::Possible)];
        assessment.findings[0].summary = "\u{1b}]8;;https://evil.test\u{7}click".into();
        let review = AdvisoryRiskReview::new(&[assessment], "batch")?.unwrap();
        assert!(!review.details().contains('\u{1b}'));
        assert!(!review.details().contains('\u{7}'));
        assert!(
            review
                .details()
                .contains("https://security.archlinux.org/AVG-1234")
        );
        assert!(safe_reference("https://vendor.test/advisory/123").is_some());
        for url in [
            "javascript:alert(1)",
            "http://vendor.test/123",
            "https://user:secret@vendor.test/123",
            "https://vendor.test/\nforged",
        ] {
            assert!(safe_reference(url).is_none(), "{url:?}");
        }
        Ok(())
    }

    #[test]
    fn risk_consent_does_not_override_source_policy_or_reclassify_findings() -> anyhow::Result<()> {
        let mut assessment = package("app");
        assessment.findings = vec![finding("CVE-2026-12345", FindingApplicability::Applicable)];
        let review = AdvisoryRiskReview::new(std::slice::from_ref(&assessment), "batch")?.unwrap();
        let accepted = review.accept(&format!("accept {}", review.id()))?;
        assert!(accepted.matches(&review));
        let policy = crate::core::security::SecurityPolicy {
            banned_packages: vec!["app".into()],
            ..crate::core::security::SecurityPolicy::default()
        };
        assert!(matches!(
            policy.check_source("app", &assessment.package.origin, Some("MIT")),
            Err(crate::core::security::PolicyError::Banned { .. })
        ));
        assert_eq!(
            assessment.findings[0].applicability,
            FindingApplicability::Applicable
        );
        assert!(
            crate::core::security::SecurityPolicy::default()
                .check_assessments(&[assessment])
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn evidence_digest_changes_require_new_consent_but_receipt_timestamps_do_not()
    -> anyhow::Result<()> {
        use crate::core::security::vulnerability::PackageCoverage;
        let mut assessment = package("app");
        assessment.findings = vec![finding("CVE-2026-12345", FindingApplicability::Applicable)];
        let evidence = |digest: &str, timestamp: &str| PackageCoverage::Assessed {
            provenance: AdvisoryProvenance::ArchSnapshot {
                payload_sha256: digest.into(),
                fetched_at: timestamp.parse().unwrap(),
                checked_at: timestamp.parse().unwrap(),
            },
        };
        assessment.coverage = evidence("original", "2026-11-16T00:00:00Z");
        let review = AdvisoryRiskReview::new(std::slice::from_ref(&assessment), "batch")?.unwrap();
        let accepted = review.accept(&format!("accept {}", review.id()))?;
        assessment.coverage = evidence("original", "2026-11-16T00:01:00Z");
        assert!(accepted.matches(
            &AdvisoryRiskReview::new(std::slice::from_ref(&assessment), "batch")?.unwrap()
        ));
        assessment.coverage = evidence("changed", "2026-11-16T00:01:00Z");
        assert!(!accepted.matches(&AdvisoryRiskReview::new(&[assessment], "batch")?.unwrap()));
        Ok(())
    }
}
