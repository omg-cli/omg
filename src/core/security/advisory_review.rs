//! Acknowledgement of disclosed advisory risk never changes its classification.

use super::scan::{AdvisoryProvenance, FindingApplicability};
use super::vulnerability::{PackageAssessment, UnknownCoverage};
use crate::package_managers::types::SecurityOrigin;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::Write as _;

pub(crate) struct AdvisoryRiskReview {
    id: String,
    details: String,
    legacy_identity: Option<AdvisoryRiskIdentity>,
}

#[derive(Clone)]
pub(crate) struct AdvisoryRiskIdentity {
    records: Vec<String>,
}

impl AdvisoryRiskIdentity {
    pub(crate) fn id_for_context(&self, transaction_context: &str) -> String {
        hex::encode(Sha256::digest(
            serde_json::json!(("omg-advisory-risk-v1", transaction_context, &self.records,))
                .to_string(),
        ))
    }
}

pub(crate) struct AdvisoryRiskAcceptance {
    review_id: String,
}

impl AdvisoryRiskReview {
    pub(crate) fn new_with_unknown(
        assessments: &[PackageAssessment],
        transaction_context: &str,
    ) -> anyhow::Result<Option<Self>> {
        let risk = Self::new(assessments, transaction_context)?;
        let unknown = assessments
            .iter()
            .filter(|assessment| !assessment.coverage.is_assessed())
            .collect::<Vec<_>>();
        if unknown.is_empty() {
            return Ok(risk);
        }
        let mut records = Vec::with_capacity(unknown.len());
        let mut details = risk.as_ref().map_or_else(
            || String::from("\nSECURITY WARNING: advisory coverage for the selected transaction is unknown.\nNo clean security result was established. Accepting this gap does not mark these versions safe.\n"),
            |review| review.details.clone(),
        );
        let mut displayed_sources = BTreeSet::new();
        let mut standard_arch_untracked = false;
        for assessment in unknown {
            let package = &assessment.package;
            let identity = (
                &package.name,
                &package.version,
                &package.origin,
                &package.architecture,
                &package.advisory_source,
                &package.licenses,
            );
            let provenance = match assessment.coverage.provenance() {
                Some(AdvisoryProvenance::ArchSnapshot { payload_sha256, .. }) => {
                    serde_json::json!({"arch_snapshot_sha256": payload_sha256})
                }
                Some(AdvisoryProvenance::RuntimeSnapshot {
                    runtime,
                    source,
                    payload_sha256,
                    ..
                }) => {
                    serde_json::json!({"runtime":runtime,"source":source,"payload_sha256":payload_sha256})
                }
                other => serde_json::to_value(other)?,
            };
            records.push(serde_json::to_string(&(
                identity,
                assessment.coverage.unknown_reason(),
                &provenance,
            ))?);
            let _ = writeln!(
                details,
                "Package: {}\nCoverage: unknown ({:?})",
                serde_json::to_string(&identity)?,
                assessment.coverage.unknown_reason(),
            );
            let source_line = serde_json::to_string(&assessment.coverage.provenance())?;
            if displayed_sources.insert(source_line.clone()) {
                let _ = writeln!(details, "Source: {source_line}");
            }
            if let SecurityOrigin::OtherRepository { repository } = &package.origin
                && matches!(repository.as_str(), "core" | "extra" | "multilib")
                && assessment.coverage.unknown_reason() == Some(UnknownCoverage::SourceNotCovered)
            {
                standard_arch_untracked = true;
            }
        }
        if standard_arch_untracked {
            details.push_str(
                "Hint: standard Arch repositories (core, extra, multilib) are not declared for advisory tracking.\n\
                 To enable Arch Security Tracker coverage for them, add to ~/.config/omg/policy.toml:\n\
                   advisory_requirement = \"optional\"\n\
                   arch_advisory_repositories = [\"core\", \"extra\", \"multilib\"]\n",
            );
        }
        records.sort();
        let id = hex::encode(Sha256::digest(serde_json::to_vec(&(
            "omg-advisory-risk-with-coverage-v1",
            transaction_context,
            risk.as_ref().map(Self::id),
            records,
        ))?));
        let details = details
            .lines()
            .map(crate::cli::style::sanitize_terminal_text)
            .collect::<Vec<_>>()
            .join("\n");
        anyhow::ensure!(
            details.len() <= 60 * 1024,
            "Advisory review exceeds terminal display limit; split the transaction"
        );
        Ok(Some(Self {
            id,
            details,
            legacy_identity: risk.and_then(|review| review.legacy_identity),
        }))
    }

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
                Some(AdvisoryProvenance::RuntimeSnapshot {
                    runtime,
                    source,
                    payload_sha256,
                    ..
                }) => {
                    serde_json::json!({"runtime":runtime,"source":source,"payload_sha256":payload_sha256})
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
            &records,
        ))?));
        let mut details = String::from(
            "\nSECURITY WARNING: the selected transaction has disclosed advisory findings.\nAccepting the risk does not mark these versions safe or establish missing coverage.\n",
        );
        for assessment in assessments {
            if assessment.findings.is_empty() {
                continue;
            }
            let package = serde_json::to_string(&(
                &assessment.package.name,
                &assessment.package.version,
                &assessment.package.architecture,
            ))?;
            let _ = writeln!(details, "Package: {package}");
            if let Some(reason) = assessment.coverage.unknown_reason() {
                let _ = writeln!(details, "Coverage: unknown ({reason:?})");
            } else {
                details.push_str("Coverage: assessed\n");
            }
            let source = serde_json::to_string(&assessment.coverage.provenance())?;
            let _ = writeln!(details, "Source: {source}");
            let mut displayed_provider_details = std::collections::BTreeSet::new();
            for finding in &assessment.findings {
                let confidence = match finding.applicability {
                    FindingApplicability::Applicable => "affected version",
                    FindingApplicability::Possible => "possible match; applicability unconfirmed",
                };
                let id = serde_json::to_string(&finding.id)?;
                let summary = serde_json::to_string(&finding.summary)?;
                let _ = writeln!(details, "  {id} ({confidence})\n  {summary}");
                if let Some(url) = advisory_link(&finding.id) {
                    let _ = writeln!(details, "  {url}");
                }
                if let Some(native) = &finding.native_advisory {
                    if displayed_provider_details.insert((&native.source, &native.description)) {
                        let source = serde_json::to_string(&native.source)?;
                        let description = serde_json::to_string(&native.description)?;
                        let _ = writeln!(
                            details,
                            "  Source: {source}\n  Provider details: {description}"
                        );
                    }
                    for reference in &native.references {
                        if let Some(url) = safe_reference(&reference.url) {
                            let _ = writeln!(details, "  {url}");
                        }
                    }
                }
            }
        }
        if details.len() > 60 * 1024 {
            details = String::from(
                "\nSECURITY WARNING: the selected transaction has disclosed advisory findings.\nAccepting the risk does not mark these versions safe or establish missing coverage.\nCondensed review: every advisory is listed below. Open its link for the full description.\n",
            );
            for assessment in assessments.iter().filter(|item| !item.findings.is_empty()) {
                let _ = writeln!(
                    details,
                    "Package: {}",
                    serde_json::to_string(&(
                        &assessment.package.name,
                        &assessment.package.version,
                        &assessment.package.architecture,
                    ))?
                );
                let _ = writeln!(
                    details,
                    "Coverage: {}",
                    if assessment.coverage.is_assessed() {
                        "assessed"
                    } else {
                        "unknown"
                    }
                );
                let _ = writeln!(
                    details,
                    "Source: {}",
                    serde_json::to_string(&assessment.coverage.provenance())?
                );
                for finding in &assessment.findings {
                    let confidence = match finding.applicability {
                        FindingApplicability::Applicable => "affected version",
                        FindingApplicability::Possible => {
                            "possible match; applicability unconfirmed"
                        }
                    };
                    let _ = writeln!(
                        details,
                        "  {} ({confidence})",
                        serde_json::to_string(&finding.id)?
                    );
                    let url = advisory_link(&finding.id).or_else(|| {
                        finding
                            .native_advisory
                            .as_ref()?
                            .references
                            .iter()
                            .find_map(|reference| safe_reference(&reference.url))
                    });
                    if let Some(url) = url {
                        let _ = writeln!(details, "  {url}");
                    } else {
                        let _ = writeln!(details, "  {}", serde_json::to_string(&finding.summary)?);
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
        Ok(Some(Self {
            id,
            details,
            legacy_identity: Some(AdvisoryRiskIdentity { records }),
        }))
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }
    pub(crate) fn details(&self) -> &str {
        &self.details
    }

    pub(crate) fn legacy_identity(&self) -> Option<&AdvisoryRiskIdentity> {
        self.legacy_identity.as_ref()
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
    if ["GHSA-", "RUSTSEC-", "OSV-", "GO-", "PYSEC-", "MAL-"]
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
    use anyhow::Context as _;

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
    fn retained_legacy_identity_matches_existing_canonical_ids_across_contexts() {
        use super::super::vulnerability::PackageCoverage;
        let mut assessment = package("quoted-\"package\"-λ");
        assessment.findings = vec![
            finding("CVE-2026-10002", FindingApplicability::Applicable),
            finding("CVE-2026-10001", FindingApplicability::Possible),
        ];
        assessment.findings[0].summary = "Escaped \"publisher\" detail\nUnicode λ".into();
        for coverage in [
            assessment.coverage.clone(),
            PackageCoverage::Assessed {
                provenance: AdvisoryProvenance::Osv {
                    ecosystem: "npm".into(),
                },
            },
        ] {
            assessment.coverage = coverage;
            let original = AdvisoryRiskReview::new(&[assessment.clone()], "original context")
                .expect("existing canonical finding review")
                .expect("disclosed finding identity");
            let wrapped =
                AdvisoryRiskReview::new_with_unknown(&[assessment.clone()], "original context")
                    .expect("validated review with preserved coverage")
                    .expect("finding or Unknown decision");
            let identity = wrapped
                .legacy_identity()
                .expect("finding identity survives the Unknown wrapper")
                .clone();
            assert_eq!(identity.id_for_context("original context"), original.id());
            let destination =
                AdvisoryRiskReview::new(&[assessment.clone()], "actual destination context")
                    .expect("existing destination-bound canonical review")
                    .expect("destination finding identity");
            assert_eq!(
                identity.id_for_context("actual destination context"),
                destination.id()
            );
            assert_ne!(destination.id(), original.id());
            let mut changed = assessment.clone();
            changed.findings[0].summary.push_str(" Changed evidence.");
            let changed = AdvisoryRiskReview::new(&[changed], "actual destination context")
                .expect("changed finding review")
                .expect("changed finding identity");
            assert_ne!(
                identity.id_for_context("actual destination context"),
                changed.id()
            );
        }
        let unknown = package("coverage-only");
        let review = AdvisoryRiskReview::new_with_unknown(
            std::slice::from_ref(&unknown),
            "coverage context",
        )
        .expect("Unknown-only explicit decision")
        .expect("Unknown must remain a decision");
        assert!(review.legacy_identity().is_none());
        let mut clean = unknown;
        clean.coverage = PackageCoverage::Assessed {
            provenance: AdvisoryProvenance::Osv {
                ecosystem: "npm".into(),
            },
        };
        assert!(
            AdvisoryRiskReview::new_with_unknown(&[clean], "clean context")
                .expect("complete clean evidence")
                .is_none()
        );
    }

    #[test]
    fn many_findings_can_be_reviewed_without_repeating_identical_provider_details()
    -> anyhow::Result<()> {
        use super::super::scan::NativeAdvisory;
        let mut assessment = package("dotnet");
        for number in 10000..10132 {
            let mut item = finding(
                &format!("CVE-2026-{number}"),
                FindingApplicability::Applicable,
            );
            item.native_advisory = Some(NativeAdvisory {
                source: "runtime-vendor".to_owned(),
                advisory_nevra: "8.0.100".to_owned(),
                published_severity: "high".to_owned(),
                description: "The vendor component mapping remains incomplete. ".repeat(20),
                references: Vec::new(),
            });
            assessment.findings.push(item);
        }
        let review = AdvisoryRiskReview::new(&[assessment], "single-runtime-selection")?
            .context("All disclosed findings must remain reviewable")?;
        assert!(review.details().len() <= 60 * 1024);
        for number in 10000..10132 {
            assert!(review.details().contains(&format!("CVE-2026-{number}")));
            assert!(review.details().contains(&format!(
                "https://www.cve.org/CVERecord?id=CVE-2026-{number}"
            )));
        }
        Ok(())
    }

    #[test]
    fn long_distinct_advisories_keep_every_link_and_bind_full_descriptions() -> anyhow::Result<()> {
        let mut assessment = package("python");
        for number in 10000..10197 {
            let mut item = finding(
                &format!("CVE-2026-{number}"),
                FindingApplicability::Applicable,
            );
            item.summary = format!(
                "CVE-2026-{number}: {}",
                "Detailed publisher explanation. ".repeat(30)
            );
            assessment.findings.push(item);
        }
        let mut unlinked = finding("vendor:python:issue", FindingApplicability::Possible);
        unlinked.summary = "Publisher identified a possible interpreter memory error".into();
        assessment.findings.push(unlinked);
        let review =
            AdvisoryRiskReview::new_with_unknown(&[assessment.clone()], "python-install")?.unwrap();
        assert!(review.details().len() <= 60 * 1024);
        assert!(review.details().contains("Condensed review"));
        assert!(review.details().contains("Coverage: unknown"));
        assert!(
            review
                .details()
                .contains("Publisher identified a possible interpreter memory error")
        );
        for number in 10000..10197 {
            assert!(review.details().contains(&format!(
                "https://www.cve.org/CVERecord?id=CVE-2026-{number}"
            )));
        }
        let accepted = review.accept(&format!("accept {}", review.id()))?;
        assessment.findings[0]
            .summary
            .push_str(" Changed publisher evidence.");
        let changed =
            AdvisoryRiskReview::new_with_unknown(&[assessment], "python-install")?.unwrap();
        assert!(!accepted.matches(&changed));
        Ok(())
    }

    #[test]
    fn no_findings_do_not_require_risk_consent() -> anyhow::Result<()> {
        assert!(AdvisoryRiskReview::new(&[package("app")], "transaction")?.is_none());
        Ok(())
    }

    #[test]
    fn unresolved_runtime_coverage_requires_its_own_explicit_decision() -> anyhow::Result<()> {
        let assessment = package("runtime:swift");
        let review = AdvisoryRiskReview::new_with_unknown(&[assessment], "runtime-selection")?
            .context("Unknown runtime coverage must require explicit review")?;
        assert!(review.details().contains("Coverage: unknown"));
        assert!(review.accept("yes").is_err());
        assert!(review.accept("").is_err());
        let accepted = review.accept(&format!("accept {}", review.id()))?;
        assert!(accepted.matches(&review));
        Ok(())
    }

    #[test]
    fn unknown_acceptance_is_bound_to_runtime_version_and_source_content() -> anyhow::Result<()> {
        use super::super::vulnerability::PackageCoverage;
        let mut assessment = package("runtime:node");
        assessment.package.origin = SecurityOrigin::RuntimeVendor {
            runtime: "node".into(),
            vendor: "nodejs".into(),
        };
        let source = |digest: &str, checked_at: &str| -> anyhow::Result<_> {
            Ok(PackageCoverage::Unknown {
                reason: UnknownCoverage::EvidenceUnavailable,
                provenance: Some(AdvisoryProvenance::RuntimeSnapshot {
                    runtime: "node".into(),
                    source: "https://advisories.example/node".into(),
                    payload_sha256: digest.repeat(64),
                    checked_at: checked_at.parse()?,
                }),
            })
        };
        assessment.coverage = source("a", "2026-11-16T12:00:00Z")?;
        let review =
            AdvisoryRiskReview::new_with_unknown(&[assessment.clone()], "runtime-selection")?
                .unwrap();
        assert!(!review.details().contains("has disclosed advisory findings"));
        let accepted = review.accept(&format!("accept {}", review.id()))?;
        assessment.coverage = source("a", "2026-11-16T12:01:00Z")?;
        assert!(
            accepted.matches(
                &AdvisoryRiskReview::new_with_unknown(&[assessment.clone()], "runtime-selection")?
                    .unwrap()
            )
        );
        assessment.coverage = source("b", "2026-11-16T12:01:00Z")?;
        assert!(
            !accepted.matches(
                &AdvisoryRiskReview::new_with_unknown(&[assessment.clone()], "runtime-selection")?
                    .unwrap()
            )
        );
        assessment.coverage = source("a", "2026-11-16T12:00:00Z")?;
        assessment.package.version = "24.22.3".into();
        assert!(!accepted.matches(
            &AdvisoryRiskReview::new_with_unknown(&[assessment], "runtime-selection")?.unwrap()
        ));
        Ok(())
    }

    #[test]
    fn assessed_runtime_without_findings_does_not_require_unknown_acceptance() -> anyhow::Result<()>
    {
        let mut assessment = package("runtime:node");
        assessment.coverage = super::super::vulnerability::PackageCoverage::Assessed {
            provenance: AdvisoryProvenance::RuntimeSnapshot {
                runtime: "node".into(),
                source: "https://advisories.example/node".into(),
                payload_sha256: "a".repeat(64),
                checked_at: "2026-11-16T12:00:00Z".parse()?,
            },
        };
        assert!(
            AdvisoryRiskReview::new_with_unknown(&[assessment], "runtime-selection")?.is_none()
        );
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
    fn malware_watch_list_ids_link_to_the_osv_record() {
        assert_eq!(
            advisory_link("MAL-2026-1234").as_deref(),
            Some("https://osv.dev/vulnerability/MAL-2026-1234")
        );
    }

    #[test]
    fn malformed_advisory_ids_do_not_produce_official_looking_links() {
        for id in [
            "",
            "CVE-2026",
            "CVE-26-1234",
            "CVE-202x-1234",
            "CVE-2026-123x",
            "CVE-2026-1",
            "CVE-2026-1234\nforged",
            "AVG-",
            "AVG-not-a-number",
        ] {
            assert_eq!(advisory_link(id), None, "{id:?}");
        }
        assert_eq!(advisory_link(&"x".repeat(161)), None);
    }

    #[test]
    fn native_provider_review_preserves_the_warning_and_omits_unsafe_references()
    -> anyhow::Result<()> {
        use crate::core::security::scan::{AdvisoryReference, NativeAdvisory};
        let mut assessment = package("app");
        let mut item = finding("CVE-2026-12345", FindingApplicability::Applicable);
        item.native_advisory = Some(NativeAdvisory {
            source: "Vendor".into(),
            advisory_nevra: "app-1.0-1".into(),
            published_severity: "Important".into(),
            description: "Provider details".into(),
            references: vec![
                AdvisoryReference {
                    id: "safe".into(),
                    kind: "vendor".into(),
                    url: "https://vendor.test/advisory/123".into(),
                },
                AdvisoryReference {
                    id: "unsafe".into(),
                    kind: "vendor".into(),
                    url: "http://untrusted.test/reference".into(),
                },
            ],
        });
        assessment.findings = vec![item];
        let review = AdvisoryRiskReview::new(&[assessment], "transaction")?.unwrap();
        assert_eq!(
            review.details(),
            concat!(
                "\nSECURITY WARNING: the selected transaction has disclosed advisory findings.\n",
                "Accepting the risk does not mark these versions safe or establish missing coverage.\n",
                "Package: [\"app\",\"1.0-1\",null]\n",
                "Coverage: unknown (EvidenceUnavailable)\nSource: null\n",
                "  \"CVE-2026-12345\" (affected version)\n",
                "  \"A disclosed vulnerability\"\n",
                "  https://www.cve.org/CVERecord?id=CVE-2026-12345\n",
                "  Source: \"Vendor\"\n  Provider details: \"Provider details\"\n",
                "  https://vendor.test/advisory/123"
            )
        );
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

    #[test]
    fn unknown_arch_review_binds_content_without_expiring_on_receipt_refresh() -> anyhow::Result<()>
    {
        use super::super::vulnerability::PackageCoverage;
        let mut assessment = package("arch-unknown");
        let coverage = |digest: &str, time: &str| PackageCoverage::Unknown {
            reason: UnknownCoverage::OriginUnestablished,
            provenance: Some(AdvisoryProvenance::ArchSnapshot {
                payload_sha256: digest.into(),
                fetched_at: time.parse().expect("fixture fetch timestamp"),
                checked_at: time.parse().expect("fixture check timestamp"),
            }),
        };
        assessment.coverage = coverage("original", "2026-11-16T00:00:00Z");
        let original = AdvisoryRiskReview::new_with_unknown(
            std::slice::from_ref(&assessment),
            "arch-private-origin",
        )
        .expect("valid unknown Arch review")
        .unwrap();
        assert!(original.details().contains("Coverage: unknown"));
        let acceptance = original.accept(&format!("accept {}", original.id()))?;
        assessment.coverage = coverage("original", "2026-11-16T00:01:00Z");
        assert!(
            acceptance.matches(
                &AdvisoryRiskReview::new_with_unknown(
                    std::slice::from_ref(&assessment),
                    "arch-private-origin",
                )
                .expect("valid refreshed unknown Arch review")
                .unwrap()
            )
        );
        assessment.coverage = coverage("changed", "2026-11-16T00:01:00Z");
        assert!(!acceptance.matches(
            &AdvisoryRiskReview::new_with_unknown(&[assessment], "arch-private-origin",)?.unwrap()
        ));
        Ok(())
    }

    #[test]
    fn condensed_mixed_coverage_preserves_native_reference_and_possible_applicability()
    -> anyhow::Result<()> {
        use super::super::scan::{AdvisoryReference, NativeAdvisory};
        use super::super::vulnerability::PackageCoverage;
        let mut known = package("assessed-native");
        known.coverage = PackageCoverage::Assessed {
            provenance: AdvisoryProvenance::NativeDnf,
        };
        let mut advisory = finding("vendor:issue-one", FindingApplicability::Possible);
        advisory.summary = "Detailed native publisher evidence. ".repeat(2100);
        advisory.native_advisory = Some(NativeAdvisory {
            source: "native vendor".into(),
            advisory_nevra: "1.0-2".into(),
            published_severity: "high".into(),
            description: "Native package applicability remains possible".into(),
            references: vec![
                AdvisoryReference {
                    id: "unsafe".into(),
                    kind: "vendor".into(),
                    url: "http://example.invalid/unsafe".into(),
                },
                AdvisoryReference {
                    id: "safe".into(),
                    kind: "vendor".into(),
                    url: "https://example.invalid/vendor-advisory".into(),
                },
            ],
        });
        known.findings.push(advisory);
        let mut unknown = package("unassessed-native");
        unknown
            .findings
            .push(finding("CVE-2026-12345", FindingApplicability::Applicable));
        let subjects = vec![known, unknown];
        let original = AdvisoryRiskReview::new(&subjects, "native-mixed")?.unwrap();
        assert!(original.details().contains("Condensed review"));
        assert!(original.details().contains("Coverage: assessed"));
        assert!(original.details().contains("Coverage: unknown"));
        assert!(
            original
                .details()
                .contains("possible match; applicability unconfirmed")
        );
        assert!(
            original
                .details()
                .contains("https://example.invalid/vendor-advisory")
        );
        assert!(!original.details().contains("http://example.invalid/unsafe"));
        let accepted = original.accept(&format!("accept {}", original.id()))?;
        let mut changed = subjects;
        changed[0].findings[0]
            .native_advisory
            .as_mut()
            .unwrap()
            .references[1]
            .url
            .push_str("-changed");
        assert!(!accepted.matches(&AdvisoryRiskReview::new(&changed, "native-mixed")?.unwrap()));
        Ok(())
    }

    #[test]
    fn unknown_review_deduplicates_identical_provenance_sources() -> anyhow::Result<()> {
        use super::super::vulnerability::PackageCoverage;
        let provenance = AdvisoryProvenance::ArchSnapshot {
            payload_sha256: "a".repeat(64),
            fetched_at: "2026-11-23T00:05:24Z".parse()?,
            checked_at: "2026-11-23T00:05:24Z".parse()?,
        };
        let mut first = package("pkg-one");
        first.coverage = PackageCoverage::Unknown {
            reason: UnknownCoverage::SourceNotCovered,
            provenance: Some(provenance.clone()),
        };
        let mut second = package("pkg-two");
        second.coverage = PackageCoverage::Unknown {
            reason: UnknownCoverage::SourceNotCovered,
            provenance: Some(provenance),
        };
        let review = AdvisoryRiskReview::new_with_unknown(&[first, second], "upgrade")?
            .context("unknown coverage review")?;
        assert_eq!(review.details().matches("Source: ").count(), 1);
        assert_eq!(review.details().matches("Package: ").count(), 2);
        assert_eq!(review.details().matches("Coverage: unknown").count(), 2);
        assert!(review.details().contains("pkg-one"));
        assert!(review.details().contains("pkg-two"));
        Ok(())
    }

    #[test]
    fn unknown_review_hints_policy_only_for_untracked_standard_arch_repos() -> anyhow::Result<()> {
        use super::super::vulnerability::PackageCoverage;
        let make = |repo: &str| -> PackageAssessment {
            let mut assessment = package("pkg");
            assessment.package.origin = SecurityOrigin::OtherRepository {
                repository: repo.into(),
            };
            assessment.coverage = PackageCoverage::Unknown {
                reason: UnknownCoverage::SourceNotCovered,
                provenance: None,
            };
            assessment
        };
        for repo in ["core", "extra", "multilib"] {
            let review = AdvisoryRiskReview::new_with_unknown(&[make(repo)], "upgrade")?
                .context("untracked standard repo review")?;
            let details = review.details();
            assert!(
                details.contains("arch_advisory_repositories"),
                "expected policy hint for {repo}: {details}"
            );
        }
        let omarchy = AdvisoryRiskReview::new_with_unknown(&[make("omarchy")], "upgrade")?
            .context("untracked omarchy repo review")?;
        let omarchy_details = omarchy.details();
        assert!(
            !omarchy_details.contains("arch_advisory_repositories"),
            "did not expect standard Arch policy hint for omarchy: {omarchy_details}"
        );
        Ok(())
    }
}
