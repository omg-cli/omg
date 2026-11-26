//! DNF owns RPM version applicability; detailed collections are not installed inventory.
use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::core::security::scan::{
    AdvisoryProvenance, AuditCoverage, InstalledIdentity, UnassessedPackage,
};
use crate::core::security::vulnerability::UnknownCoverage;
use crate::package_managers::types::SecurityPackage;

pub(super) fn installed_coverage(
    installed: &[SecurityPackage],
    affected: &BTreeMap<String, Vec<InstalledIdentity>>,
) -> AuditCoverage {
    // An enabled repository can omit updateinfo entirely. DNF's applicable
    // rows prove positive matches, but do not report per-package coverage.
    let matched: BTreeSet<_> = affected.values().flatten().collect();
    let mut assessed = Vec::new();
    let mut unassessed = Vec::new();
    for package in installed.iter().map(InstalledIdentity::from) {
        if matched.contains(&package) {
            assessed.push(package);
        } else {
            unassessed.push(UnassessedPackage {
                package,
                reason: UnknownCoverage::EvidenceUnavailable,
            });
        }
    }
    AuditCoverage::Reported {
        assessed,
        unassessed,
        sources: vec![AdvisoryProvenance::NativeDnf],
    }
}

/// Audit queries must not silently omit an unreachable enabled repository.
pub(super) fn query_args(details: bool) -> Vec<&'static str> {
    vec![
        if details { "--cacheonly" } else { "--refresh" },
        "--setopt=*.skip_if_unavailable=false",
        "--setopt=disable_excludes=*",
        "advisory",
        if details { "info" } else { "list" },
        "--available",
        "--security",
        "--json",
    ]
}

pub(super) fn require_enabled_repositories(bytes: &[u8]) -> Result<()> {
    #[derive(Deserialize)]
    struct Repository {
        id: String,
        is_enabled: bool,
    }
    let repositories: Vec<Repository> =
        serde_json::from_slice(bytes).context("Invalid DNF repository metadata")?;
    ensure!(
        repositories
            .iter()
            .any(|repo| repo.is_enabled && !repo.id.is_empty()),
        "Cannot audit without enabled DNF repositories"
    );
    ensure!(
        repositories
            .iter()
            .all(|repo| repo.is_enabled && !repo.id.is_empty()),
        "Unexpected repository in enabled DNF metadata"
    );
    Ok(())
}

#[derive(Debug, Deserialize)]
pub(super) struct ApplicableAdvisory {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub severity: String,
    pub nevra: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct AdvisoryDetails {
    pub name: String,
    pub title: String,
    pub severity: String,
    #[serde(rename = "Type")]
    pub kind: String,
    pub description: String,
    #[serde(rename = "references")]
    pub references: Vec<AdvisoryReference>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct AdvisoryReference {
    pub id: String,
    #[serde(rename = "Type")]
    pub kind: String,
    pub url: String,
}

/// Split only the structural NEVRA fields; DNF performs RPM ordering.
pub(super) fn package_identity(nevra: &str) -> Result<(&str, &str)> {
    ensure!(
        !nevra.chars().any(|c| c.is_whitespace() || c.is_control()),
        "Invalid advisory NEVRA whitespace"
    );
    let (nvr, architecture) = nevra
        .rsplit_once('.')
        .context("Advisory NEVRA lacks architecture")?;
    let (nv, release) = nvr
        .rsplit_once('-')
        .context("Advisory NEVRA lacks release")?;
    let (name, version) = nv
        .rsplit_once('-')
        .context("Advisory NEVRA lacks version")?;
    ensure!(
        [name, version, release, architecture]
            .iter()
            .all(|field| !field.is_empty()),
        "Empty advisory NEVRA field"
    );
    if let Some((epoch, version)) = version.split_once(':') {
        ensure!(
            !epoch.is_empty()
                && epoch.bytes().all(|c| c.is_ascii_digit())
                && !version.is_empty()
                && !version.contains(':'),
            "Invalid advisory NEVRA epoch"
        );
    }
    Ok((name, architecture))
}

pub(super) fn audit_result(
    rows: Vec<(ApplicableAdvisory, AdvisoryDetails)>,
) -> Result<crate::core::security::scan::SecurityAuditResult> {
    use crate::core::security::scan::{
        AdvisoryReference as Reference, AdvisorySeverity, MinimumSeverity, NativeAdvisory,
        SecurityAuditResult, Vulnerability,
    };
    let mut packages: BTreeMap<String, Vec<Vulnerability>> = BTreeMap::new();
    let mut high_severity = 0;
    let mut total_vulnerabilities = 0;
    for (row, detail) in rows {
        let name = package_identity(&row.nevra)?.0.to_owned();
        let severity = match row.severity.to_ascii_lowercase().as_str() {
            "critical" => AdvisorySeverity::Critical,
            "important" => AdvisorySeverity::Important,
            "moderate" => AdvisorySeverity::Moderate,
            "low" => AdvisorySeverity::Low,
            _ => AdvisorySeverity::Unspecified,
        };
        let finding = Vulnerability {
            applicability: crate::core::security::scan::FindingApplicability::Applicable,
            affected_installed: Vec::new(),
            id: row.name,
            summary: detail.title,
            score: None,
            advisory_severity: Some(severity),
            native_advisory: Some(NativeAdvisory {
                source: "dnf5".into(),
                advisory_nevra: row.nevra,
                published_severity: row.severity,
                description: detail.description,
                references: detail
                    .references
                    .into_iter()
                    .map(|reference| Reference {
                        id: reference.id,
                        kind: reference.kind,
                        url: reference.url,
                    })
                    .collect(),
            }),
        };
        high_severity += usize::from(finding.meets_minimum(MinimumSeverity::High));
        total_vulnerabilities += 1;
        packages.entry(name).or_default().push(finding);
    }
    for findings in packages.values_mut() {
        findings.sort_by(|left, right| left.id.cmp(&right.id));
    }
    Ok(SecurityAuditResult {
        coverage: crate::core::security::scan::AuditCoverage::Unreported,
        total_vulnerabilities,
        high_severity,
        vulnerabilities: packages.into_iter().collect(),
    })
}

/// Join an applicable list to metadata without expanding collection packages.
/// Missing or conflicting metadata invalidates the whole result.
pub(super) fn join_advisories(
    applicable: &[u8],
    details: &[u8],
) -> Result<Vec<(ApplicableAdvisory, AdvisoryDetails)>> {
    let rows: Vec<ApplicableAdvisory> =
        serde_json::from_slice(applicable).context("Invalid DNF applicable advisory list")?;
    let metadata: Vec<&RawValue> =
        serde_json::from_slice(details).context("Invalid DNF advisory details")?;
    let mut by_id: BTreeMap<String, (&RawValue, AdvisoryDetails)> = BTreeMap::new();
    for raw in metadata {
        let detail: AdvisoryDetails =
            serde_json::from_str(raw.get()).context("Invalid DNF advisory details")?;
        ensure!(!detail.name.is_empty(), "Empty DNF advisory identity");
        match by_id.entry(detail.name.clone()) {
            Entry::Vacant(entry) => {
                entry.insert((raw, detail));
            }
            Entry::Occupied(entry) => {
                // DNF can emit the same record from multiple mirror IDs.
                // Compare the full row, including fields unused by the report.
                ensure!(
                    entry.get().0.get() == raw.get(),
                    "Conflicting DNF advisory metadata"
                );
            }
        }
    }
    // Retain each selected detail independently: one advisory may apply to
    // multiple installed packages, while unselected collection entries stay out.
    let mut joined = Vec::new();
    let mut selected = BTreeSet::new();
    for row in rows {
        ensure!(
            !row.name.is_empty() && !row.nevra.is_empty(),
            "Empty DNF advisory selection"
        );
        package_identity(&row.nevra)?;
        let (_, detail) = by_id
            .get(&row.name)
            .context("Missing DNF advisory metadata")?;
        ensure!(
            row.kind == "security" && detail.kind == "security",
            "Unexpected non-security DNF advisory"
        );
        ensure!(
            row.severity.eq_ignore_ascii_case(&detail.severity),
            "Conflicting DNF advisory severity"
        );
        if selected.insert((row.name.clone(), row.nevra.clone())) {
            joined.push((row, detail.clone()));
        }
    }
    Ok(joined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabled_feed_reports_coverage_only_for_exact_affected_identities() {
        let installed: Vec<_> = [("1-1", "x86_64"), ("2-1", "x86_64"), ("1-1", "i686")]
            .into_iter()
            .map(|(version, architecture)| SecurityPackage {
                origin: crate::package_managers::types::SecurityOrigin::DistributionPackage,
                name: "fixture".into(),
                version: version.into(),
                architecture: Some(architecture.into()),
                advisory_source: None,
                description: String::new(),
                licenses: Vec::new(),
            })
            .collect();
        let affected = InstalledIdentity::from(&installed[0]);
        let evidence =
            BTreeMap::from([("fixture-0:2-1.x86_64".to_owned(), vec![affected.clone()])]);
        assert_eq!(
            installed_coverage(&installed, &evidence),
            AuditCoverage::Reported {
                assessed: vec![affected],
                unassessed: installed[1..]
                    .iter()
                    .map(|package| UnassessedPackage {
                        package: InstalledIdentity::from(package),
                        reason: UnknownCoverage::EvidenceUnavailable,
                    })
                    .collect(),
                sources: vec![AdvisoryProvenance::NativeDnf],
            }
        );
    }

    #[test]
    #[ignore = "requires Fedora DNF5 and a metadata-only advisory fixture configuration"]
    fn native_advisory_scope_includes_excluded_installed_packages() -> Result<()> {
        let config = std::env::var("OMG_DNF_ADVISORY_FIXTURE_CONFIG")
            .context("set the isolated Fedora advisory fixture configuration")?;
        let mut responses = Vec::new();
        for details in [false, true] {
            let output = crate::core::privilege::system_command("dnf")?
                .arg(format!("--config={config}"))
                .args(["--disable-plugin=*", "--setopt=excludepkgs=glibc*"])
                .args(query_args(details))
                .output()?;
            ensure!(
                output.status.success(),
                "native advisory fixture failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            responses.push(output.stdout);
        }
        let joined = join_advisories(&responses[0], &responses[1])?;
        let findings = joined
            .iter()
            .map(|(row, _)| (row.name.as_str(), row.severity.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            findings,
            vec![("OMG-QEMU-FEDORA-616", "Important")],
            "excluded installed software must remain in security findings"
        );
        Ok(())
    }

    #[test]
    fn missing_repository_scope_cannot_be_reported_clean() {
        for bytes in [
            b"[]".as_slice(),
            b"",
            b"{}",
            br#"[{"id":"updates","is_enabled":false}]"#,
            br#"[{"id":"","is_enabled":true}]"#,
        ] {
            assert!(require_enabled_repositories(bytes).is_err());
        }
        require_enabled_repositories(br#"[{"id":"updates","is_enabled":true}]"#).unwrap();
    }

    const LIST: &[u8] = br#"[{"name":"FEDORA-test","type":"security","severity":"Important","nevra":"bind-libs-32:9.18-2.fc44.x86_64"}]"#;
    const DETAILS: &[u8] = br#"[{"Name":"FEDORA-test","Title":"Security update","Severity":"Important","Type":"security","Description":"Fix","references":[],"collections":{"packages":["bind-libs-32:9.18-2.fc44.x86_64","bind-devel-32:9.18-2.fc44.aarch64"]}}]"#;

    #[test]
    fn refresh_and_detail_queries_refuse_silent_repository_omission() {
        for details in [false, true] {
            let args = query_args(details);
            assert!(args.contains(&"--setopt=*.skip_if_unavailable=false"));
            assert!(args.contains(&"--setopt=disable_excludes=*"));
            assert!(args.contains(&"--available"));
            assert!(args.contains(&"--security"));
            assert!(!args.contains(&"--installed"));
            assert_eq!(args.contains(&"--refresh"), !details);
            assert_eq!(args.contains(&"--cacheonly"), details);
        }
    }

    #[test]
    fn selection_preserves_nevra_without_expanding_collections() {
        let rows = join_advisories(LIST, DETAILS).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0.nevra, "bind-libs-32:9.18-2.fc44.x86_64");
        assert_eq!(rows[0].1.title, "Security update");
        assert!(rows[0].1.references.is_empty());
    }

    #[test]
    fn incomplete_or_conflicting_metadata_is_not_a_clean_scan() {
        for bad in [b"".as_slice(), b"{}", b"[]", br#"[{"Name":"FEDORA-test"}]"#] {
            assert!(join_advisories(LIST, bad).is_err());
        }
        let conflicting = String::from_utf8(DETAILS.to_vec())
            .unwrap()
            .replace("Important", "Low");
        assert!(join_advisories(LIST, conflicting.as_bytes()).is_err());
        assert!(join_advisories(b"", DETAILS).is_err());
        assert!(join_advisories(b"[]", b"[]").unwrap().is_empty());
    }

    #[test]
    fn duplicate_rows_do_not_hide_distinct_architectures_or_partial_failure() {
        let row: serde_json::Value = serde_json::from_slice::<Vec<_>>(LIST).unwrap().remove(0);
        let mut other_arch = row.clone();
        other_arch["nevra"] = "bind-libs-32:9.18-2.fc44.i686".into();
        let list = serde_json::to_vec(&vec![row.clone(), row.clone(), other_arch]).unwrap();
        assert_eq!(join_advisories(&list, DETAILS).unwrap().len(), 2);
        let mut missing = row.clone();
        missing["name"] = "FEDORA-missing".into();
        let partial = serde_json::to_vec(&vec![row, missing]).unwrap();
        assert!(join_advisories(&partial, DETAILS).is_err());
        let detail: serde_json::Value =
            serde_json::from_slice::<Vec<_>>(DETAILS).unwrap().remove(0);
        let duplicated = serde_json::to_vec(&vec![detail.clone(), detail.clone()]).unwrap();
        let result = audit_result(join_advisories(&list, &duplicated).unwrap()).unwrap();
        assert_eq!(result.total_vulnerabilities, 2);
        assert_eq!(result.high_severity, 2);

        for field in ["Description", "collections"] {
            let mut different = detail.clone();
            different[field] = "Conflicting mirror data".into();
            let conflict = serde_json::to_vec(&vec![detail.clone(), different]).unwrap();
            let error = join_advisories(LIST, &conflict).unwrap_err();
            assert!(
                error.to_string().contains("Conflicting DNF advisory"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn rpm_identity_keeps_epoch_and_hyphenated_names_unambiguous() {
        assert_eq!(
            package_identity("bind-libs-32:9.18-2.fc44.x86_64").unwrap(),
            ("bind-libs", "x86_64")
        );
        assert_eq!(
            package_identity("pkg-0:1.0~rc1-3.fc44.noarch").unwrap(),
            ("pkg", "noarch")
        );
        for invalid in [
            "pkg",
            "pkg-1-2",
            "pkg--2.x86_64",
            "pkg-1-.x86_64",
            "pkg-1-2.",
            "pkg-x:1-2.x86_64",
            "pkg-:1-2.x86_64",
            "pkg-1:2:3-2.x86_64",
            "pkg-1-2.x86_64\n",
        ] {
            assert!(package_identity(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn native_result_preserves_evidence_and_uses_published_severity() {
        let rows = join_advisories(LIST, DETAILS).unwrap();
        let result = audit_result(rows).unwrap();
        assert_eq!(result.total_vulnerabilities, 1);
        assert_eq!(result.high_severity, 1);
        assert_eq!(result.vulnerabilities[0].0, "bind-libs");
        let finding = &result.vulnerabilities[0].1[0];
        assert_eq!(finding.id, "FEDORA-test");
        assert!(finding.score.is_none());
        let evidence = finding.native_advisory.as_ref().unwrap();
        assert_eq!(evidence.advisory_nevra, "bind-libs-32:9.18-2.fc44.x86_64");
        assert_eq!(evidence.description, "Fix");
        assert_eq!(evidence.published_severity, "Important");
        let list = String::from_utf8(LIST.to_vec())
            .unwrap()
            .replace("Important", "FutureLabel");
        let details = String::from_utf8(DETAILS.to_vec())
            .unwrap()
            .replace("Important", "FutureLabel");
        let unknown =
            audit_result(join_advisories(list.as_bytes(), details.as_bytes()).unwrap()).unwrap();
        assert_eq!(unknown.total_vulnerabilities, 1);
        assert_eq!(unknown.high_severity, 0);
        assert_eq!(
            unknown.vulnerabilities[0].1[0]
                .native_advisory
                .as_ref()
                .unwrap()
                .published_severity,
            "FutureLabel"
        );
    }
}
