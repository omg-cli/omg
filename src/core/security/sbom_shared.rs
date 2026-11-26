//! Shared audit findings joined to exact installed SBOM components.
use super::sbom::{
    Sbom, SbomComponent, SbomError, SbomLicense, SbomLicenseInfo, SbomMetadata, SbomProperty,
    SbomTool, SbomVulnAdvisory, SbomVulnAffects, SbomVulnRating, SbomVulnSource, SbomVulnerability,
};
use super::scan::{AdvisorySeverity, AuditCoverage, SecurityAuditResult};
use crate::core::env::distro::Distro;
use crate::package_managers::types::SbomPackage;
use anyhow::Context;
use std::borrow::Cow;

pub(super) async fn generate(include_vulns: bool) -> Result<Sbom, SbomError> {
    let result = async {
        let manager = crate::package_managers::get_package_manager()?;
        let mut installed = manager
            .sbom_inventory()
            .await
            .context("Failed to list packages")?;
        let audit = if include_vulns {
            Some(
                super::scan::scan_installed(
                    manager.as_ref(),
                    &super::vulnerability::VulnerabilityScanner::new(),
                )
                .await?,
            )
        } else {
            None
        };
        let mut after = manager
            .sbom_inventory()
            .await
            .context("Failed to list packages")?;
        let compare = |left: &SbomPackage, right: &SbomPackage| {
            let (left, right) = (&left.package, &right.package);
            (&left.name, &left.version, &left.architecture).cmp(&(
                &right.name,
                &right.version,
                &right.architecture,
            ))
        };
        installed.sort_unstable_by(compare);
        after.sort_unstable_by(compare);
        anyhow::ensure!(
            installed == after,
            "Installed inventory changed during SBOM generation"
        );
        compose(
            &installed,
            audit.as_ref(),
            crate::core::env::distro::detect_distro(),
        )
    }
    .await;
    result.map_err(|source| SbomError::Audit {
        source: super::vulnerability::PackageSource(source),
    })
}

fn purl(record: &SbomPackage, distro: Distro) -> anyhow::Result<Option<String>> {
    let package = &record.package;
    let (kind, namespace) = match distro {
        Distro::Arch => ("alpm", Some(Cow::Borrowed("arch"))),
        Distro::Debian => ("deb", Some(Cow::Borrowed("debian"))),
        Distro::Ubuntu => ("deb", Some(Cow::Borrowed("ubuntu"))),
        Distro::Fedora => (
            "rpm",
            record.rpm_vendor.as_deref().map(|vendor| {
                let vendor = vendor.trim();
                if vendor.eq_ignore_ascii_case("Fedora Project") {
                    Cow::Borrowed("fedora")
                } else {
                    Cow::Owned(vendor.to_lowercase())
                }
            }),
        ),
        _ => anyhow::bail!("Unsupported SBOM distribution"),
    };
    anyhow::ensure!(
        !package.name.is_empty() && !package.version.is_empty(),
        "Incomplete SBOM identity"
    );
    let mut qualifiers = Vec::new();
    if let Some(architecture) = &package.architecture {
        anyhow::ensure!(!architecture.is_empty(), "Empty SBOM architecture");
        qualifiers.push(format!("arch={}", urlencoding::encode(architecture)));
    }
    let version = if distro == Distro::Fedora {
        if let Some((epoch, version)) = package.version.split_once(':') {
            anyhow::ensure!(
                !epoch.is_empty()
                    && epoch.bytes().all(|b| b.is_ascii_digit())
                    && !version.is_empty(),
                "Invalid RPM epoch"
            );
            qualifiers.push(format!("epoch={epoch}"));
            version
        } else {
            &package.version
        }
    } else {
        &package.version
    };
    Ok(namespace.map(|namespace| {
        let mut value = format!(
            "pkg:{kind}/{}/{}@{}",
            urlencoding::encode(&namespace),
            urlencoding::encode(&package.name),
            urlencoding::encode(version)
        );
        if !qualifiers.is_empty() {
            value.push('?');
            value.push_str(&qualifiers.join("&"));
        }
        value
    }))
}

fn compose(
    installed: &[SbomPackage],
    audit: Option<&SecurityAuditResult>,
    distro: Distro,
) -> anyhow::Result<Sbom> {
    if let Some(audit) = audit {
        audit.validate()?;
    }
    let os_name = match distro {
        Distro::Arch => "Arch Linux",
        Distro::Debian => "Debian",
        Distro::Ubuntu => "Ubuntu",
        Distro::Fedora => "Fedora",
        _ => anyhow::bail!("Unsupported SBOM distribution"),
    };
    let mut components = Vec::new();
    let mut identities = std::collections::BTreeMap::new();
    let mut coverage = std::collections::BTreeMap::new();
    if let Some(SecurityAuditResult {
        coverage:
            AuditCoverage::Reported {
                assessed,
                unassessed,
                ..
            },
        ..
    }) = audit
    {
        for identity in assessed {
            let key = (
                identity.name.clone(),
                identity.version.clone(),
                identity.architecture.clone(),
            );
            anyhow::ensure!(
                coverage
                    .insert(
                        key,
                        vec![SbomProperty {
                            name: "omg:advisory-coverage".into(),
                            value: "assessed".into()
                        }]
                    )
                    .is_none(),
                "Duplicate audit coverage identity"
            );
        }
        for package in unassessed {
            let identity = &package.package;
            let key = (
                identity.name.clone(),
                identity.version.clone(),
                identity.architecture.clone(),
            );
            anyhow::ensure!(
                coverage
                    .insert(
                        key,
                        vec![
                            SbomProperty {
                                name: "omg:advisory-coverage".into(),
                                value: "unknown".into()
                            },
                            SbomProperty {
                                name: "omg:advisory-coverage-reason".into(),
                                value: serde_json::to_value(package.reason)?
                                    .as_str()
                                    .context("Coverage reason must be a name")?
                                    .to_owned()
                            },
                        ]
                    )
                    .is_none(),
                "Duplicate audit coverage identity"
            );
        }
    }
    for record in installed {
        let package = &record.package;
        let package_url = purl(record, distro)?;
        let reference = package_url.clone().unwrap_or_else(|| {
            format!(
                "urn:omg:rpm:{}:{}:{}",
                urlencoding::encode(&package.name),
                urlencoding::encode(&package.version),
                urlencoding::encode(package.architecture.as_deref().unwrap_or_default()),
            )
        });
        let key = (
            package.name.clone(),
            package.version.clone(),
            package.architecture.clone(),
        );
        anyhow::ensure!(
            identities.insert(key.clone(), reference.clone()).is_none(),
            "Duplicate installed SBOM identity"
        );
        let mut properties = if audit
            .is_some_and(|audit| matches!(&audit.coverage, AuditCoverage::Reported { .. }))
        {
            coverage
                .remove(&key)
                .context("Installed component lacks reported audit coverage")?
        } else {
            vec![SbomProperty {
                name: "omg:advisory-coverage".into(),
                value: if audit.is_some() {
                    "unreported"
                } else {
                    "not-performed"
                }
                .into(),
            }]
        };
        properties.push(SbomProperty {
            name: "omg:package-origin".into(),
            value: serde_json::to_string(&package.origin)?,
        });
        if let Some(vendor) = &record.rpm_vendor {
            properties.push(SbomProperty {
                name: "omg:rpm-vendor".into(),
                value: vendor.clone(),
            });
        }
        if let Some((name, version)) = &package.advisory_source {
            properties.extend([
                SbomProperty {
                    name: "omg:advisory-source-name".into(),
                    value: name.clone(),
                },
                SbomProperty {
                    name: "omg:advisory-source-version".into(),
                    value: version.clone(),
                },
            ]);
        }
        components.push(SbomComponent {
            component_type: "library".into(),
            mime_type: None,
            bom_ref: Some(reference.clone()),
            name: package.name.clone(),
            version: package.version.clone(),
            description: Some(package.description.clone()),
            purl: package_url,
            licenses: package
                .licenses
                .iter()
                .map(|license| SbomLicense {
                    license: Some(SbomLicenseInfo {
                        id: None,
                        name: Some(license.clone()),
                    }),
                    expression: None,
                })
                .collect(),
            hashes: vec![],
            external_references: vec![],
            properties: Some(properties),
        });
    }
    anyhow::ensure!(
        coverage.is_empty(),
        "Audit coverage refers to an absent installed component"
    );
    let mut vulnerabilities = Vec::new();
    if let Some(audit) = audit {
        for (name, findings) in &audit.vulnerabilities {
            for finding in findings {
                anyhow::ensure!(
                    !finding.affected_installed.is_empty(),
                    "Finding {} lacks installed identity",
                    finding.id
                );
                let mut affects = Vec::new();
                for identity in &finding.affected_installed {
                    anyhow::ensure!(
                        identity.name == *name,
                        "Finding package identity conflicts with audit group"
                    );
                    let key = (
                        identity.name.clone(),
                        identity.version.clone(),
                        identity.architecture.clone(),
                    );
                    let reference = identities.get(&key).ok_or_else(|| {
                        anyhow::anyhow!(
                            "Finding {} refers to an absent installed component",
                            finding.id
                        )
                    })?;
                    affects.push(SbomVulnAffects {
                        affects_ref: reference.clone(),
                    });
                }
                let score = finding
                    .score
                    .as_deref()
                    .and_then(super::vulnerability::parse_severity_score);
                let severity = match finding.advisory_severity {
                    Some(AdvisorySeverity::Critical) => Some("critical"),
                    Some(AdvisorySeverity::Important) => Some("high"),
                    Some(AdvisorySeverity::Moderate) => Some("medium"),
                    Some(AdvisorySeverity::Low) => Some("low"),
                    _ => None,
                };
                let ratings = if score.is_some() || severity.is_some() {
                    vec![SbomVulnRating {
                        score,
                        severity: severity.map(str::to_owned),
                        method: Some("other".into()),
                    }]
                } else {
                    vec![]
                };
                let (source, description) = if let Some(native) = &finding.native_advisory {
                    (
                        SbomVulnSource {
                            name: native.source.clone(),
                            url: None,
                        },
                        native.description.clone(),
                    )
                } else {
                    (
                        SbomVulnSource {
                            name: "OSV".into(),
                            url: Some(format!(
                                "https://osv.dev/vulnerability/{}",
                                urlencoding::encode(&finding.id)
                            )),
                        },
                        finding.summary.clone(),
                    )
                };
                let mut properties = vec![SbomProperty {
                    name: "omg:advisory-applicability".into(),
                    value: match finding.applicability {
                        super::scan::FindingApplicability::Applicable => "applicable",
                        super::scan::FindingApplicability::Possible => "possible",
                    }
                    .into(),
                }];
                if let Some(native) = &finding.native_advisory {
                    properties.extend(
                        [
                            SbomProperty {
                                name: "omg:advisory:title".into(),
                                value: finding.summary.clone(),
                            },
                            SbomProperty {
                                name: "omg:advisory:nevra".into(),
                                value: native.advisory_nevra.clone(),
                            },
                            SbomProperty {
                                name: "omg:advisory:published-severity".into(),
                                value: native.published_severity.clone(),
                            },
                        ]
                        .into_iter()
                        .filter(|property| !property.value.is_empty()),
                    );
                }
                vulnerabilities.push(SbomVulnerability {
                    id: finding.id.clone(),
                    source: Some(source),
                    ratings,
                    description: Some(description),
                    affects,
                    references: vec![],
                    advisories: finding
                        .native_advisory
                        .as_ref()
                        .map(|native| {
                            native
                                .references
                                .iter()
                                .map(|reference| SbomVulnAdvisory {
                                    title: Some(format!("{}: {}", reference.kind, reference.id)),
                                    url: reference.url.clone(),
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                    properties,
                });
            }
        }
    }
    Ok(Sbom {
        bom_format: "CycloneDX".into(),
        spec_version: "1.5".into(),
        serial_number: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        version: 1,
        metadata: SbomMetadata {
            timestamp: jiff::Timestamp::now()
                .strftime("%Y-%m-%dT%H:%M:%SZ")
                .to_string(),
            tools: vec![SbomTool {
                vendor: "OMG".into(),
                name: "omg".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            }],
            component: Some(SbomComponent {
                component_type: "operating-system".into(),
                mime_type: None,
                bom_ref: Some("omg:system".into()),
                name: os_name.into(),
                version: if distro == Distro::Arch {
                    "rolling".into()
                } else {
                    String::new()
                },
                description: None,
                purl: None,
                licenses: vec![],
                hashes: vec![],
                external_references: vec![],
                properties: Some(match audit.map(|audit| &audit.coverage) {
                    Some(AuditCoverage::Reported {
                        assessed,
                        unassessed,
                        sources,
                    }) => vec![
                        SbomProperty {
                            name: "omg:advisory-coverage".into(),
                            value: "reported".into(),
                        },
                        SbomProperty {
                            name: "omg:advisory-assessed-count".into(),
                            value: assessed.len().to_string(),
                        },
                        SbomProperty {
                            name: "omg:advisory-unknown-count".into(),
                            value: unassessed.len().to_string(),
                        },
                        SbomProperty {
                            name: "omg:advisory-sources".into(),
                            value: serde_json::to_string(sources)?,
                        },
                    ],
                    Some(AuditCoverage::Unreported) => vec![SbomProperty {
                        name: "omg:advisory-coverage".into(),
                        value: "unreported".into(),
                    }],
                    None => vec![SbomProperty {
                        name: "omg:advisory-coverage".into(),
                        value: "not-performed".into(),
                    }],
                }),
            }),
            manufacture: None,
            supplier: None,
        },
        components,
        dependencies: vec![],
        vulnerabilities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::security::scan::{InstalledIdentity, Vulnerability};
    use crate::package_managers::types::SecurityPackage;

    fn compose_fixture(
        installed: &[SecurityPackage],
        audit: Option<&SecurityAuditResult>,
        distro: Distro,
    ) -> anyhow::Result<Sbom> {
        let records: Vec<_> = installed
            .iter()
            .map(|package| SbomPackage {
                package: package.clone(),
                rpm_vendor: (distro == Distro::Fedora).then(|| "Fedora Project".into()),
            })
            .collect();
        super::compose(&records, audit, distro)
    }

    #[test]
    fn rpm_purls_use_declared_vendor_and_omit_unknown_vendor() {
        let package = SecurityPackage {
            origin: crate::package_managers::types::SecurityOrigin::DistributionPackage,
            name: "sample".into(),
            version: "2:1-4".into(),
            advisory_source: None,
            architecture: Some("x86_64".into()),
            description: String::new(),
            licenses: vec!["MIT OR Apache-2.0".into()],
        };
        let mut unlabelled = SbomPackage::from(package.clone());
        unlabelled.package.architecture = Some("i686".into());
        let records = [
            SbomPackage {
                package,
                rpm_vendor: Some("Example Vendor, LLC".into()),
            },
            unlabelled,
        ];
        let report = super::compose(&records, None, Distro::Fedora).unwrap();
        let labelled = &report.components[0];
        assert_eq!(
            labelled.purl.as_deref(),
            Some("pkg:rpm/example%20vendor%2C%20llc/sample@1-4?arch=x86_64&epoch=2")
        );
        assert!(
            labelled
                .properties
                .as_ref()
                .unwrap()
                .iter()
                .any(|property| property.name == "omg:rpm-vendor"
                    && property.value == "Example Vendor, LLC")
        );
        let unlabelled = &report.components[1];
        assert!(unlabelled.purl.is_none());
        assert_eq!(
            unlabelled.bom_ref.as_deref(),
            Some("urn:omg:rpm:sample:2%3A1-4:i686")
        );
    }

    #[test]
    fn sbom_refuses_false_clean_finding_totals_before_export() {
        let audit = SecurityAuditResult {
            coverage: AuditCoverage::Unreported,
            total_vulnerabilities: 1,
            high_severity: 0,
            vulnerabilities: Vec::new(),
        };
        compose_fixture(&[], Some(&audit), Distro::Arch)
            .expect_err("contradictory totals must not enter an SBOM");
    }

    #[test]
    fn arch_sbom_roundtrip_retains_assessed_and_unknown_components_and_applicability() {
        use crate::core::security::scan::{AdvisoryProvenance, FindingApplicability};
        use crate::core::security::vulnerability::{
            PackageAssessment, PackageCoverage, UnknownCoverage,
        };
        use crate::package_managers::types::SecurityOrigin;
        let official = SecurityPackage {
            origin: SecurityOrigin::ArchRepository {
                repository: "core".into(),
            },
            name: "official-fixture".into(),
            version: "2:1.0-1".into(),
            architecture: Some("x86_64".into()),
            advisory_source: None,
            description: String::new(),
            licenses: vec!["MIT".into()],
        };
        let archive = SecurityPackage {
            origin: SecurityOrigin::AurArchive,
            name: "aur-fixture".into(),
            ..official.clone()
        };
        let assessments = vec![
            PackageAssessment {
                package: official.clone(),
                coverage: PackageCoverage::Assessed {
                    provenance: AdvisoryProvenance::Osv {
                        ecosystem: "Arch Linux:fixture".into(),
                    },
                },
                findings: vec![Vulnerability {
                    id: "CVE-2026-1234".into(),
                    summary: "Applicable repository issue".into(),
                    score: Some("8.0".into()),
                    advisory_severity: None,
                    native_advisory: None,
                    applicability: FindingApplicability::Applicable,
                    affected_installed: vec![InstalledIdentity::from(&official)],
                }],
            },
            PackageAssessment {
                package: archive.clone(),
                coverage: PackageCoverage::Unknown {
                    reason: UnknownCoverage::OriginUnestablished,
                    provenance: None,
                },
                findings: vec![Vulnerability {
                    id: "CVE-2026-1235".into(),
                    summary: "Source review required".into(),
                    score: None,
                    advisory_severity: None,
                    native_advisory: None,
                    applicability: FindingApplicability::Possible,
                    affected_installed: vec![InstalledIdentity::from(&archive)],
                }],
            },
        ];
        let audit = SecurityAuditResult::from_assessments(assessments);
        let sbom = compose_fixture(&[official, archive], Some(&audit), Distro::Arch)
            .expect("complete Arch inventory join");
        let roundtrip: Sbom =
            serde_json::from_str(&serde_json::to_string(&sbom).expect("serialize Arch SBOM"))
                .expect("deserialize Arch SBOM");
        assert_eq!(roundtrip.components.len(), 2);
        assert_eq!(roundtrip.vulnerabilities.len(), 2);
        for (name, expected) in [("official-fixture", "assessed"), ("aur-fixture", "unknown")] {
            let component = roundtrip
                .components
                .iter()
                .find(|component| component.name == name)
                .expect("installed component");
            assert!(
                component
                    .properties
                    .as_ref()
                    .expect("component provenance")
                    .iter()
                    .any(|property| property.name == "omg:advisory-coverage"
                        && property.value == expected)
            );
            assert_eq!(component.version, "2:1.0-1");
        }
        for (id, applicability, reference) in [
            (
                "CVE-2026-1234",
                "applicable",
                "pkg:alpm/arch/official-fixture@2%3A1.0-1?arch=x86_64",
            ),
            (
                "CVE-2026-1235",
                "possible",
                "pkg:alpm/arch/aur-fixture@2%3A1.0-1?arch=x86_64",
            ),
        ] {
            let finding = roundtrip
                .vulnerabilities
                .iter()
                .find(|finding| finding.id == id)
                .expect("joined advisory");
            assert_eq!(finding.affects.len(), 1);
            assert_eq!(finding.affects[0].affects_ref, reference);
            assert!(
                finding
                    .properties
                    .iter()
                    .any(|property| property.name == "omg:advisory-applicability"
                        && property.value == applicability)
            );
        }
        let metadata = roundtrip
            .metadata
            .component
            .expect("system component")
            .properties
            .expect("audit scope");
        assert!(
            metadata
                .iter()
                .any(|property| property.name == "omg:advisory-unknown-count"
                    && property.value == "1")
        );
        assert!(metadata.iter().any(
            |property| property.name == "omg:advisory-assessed-count" && property.value == "1"
        ));
        let mut invalid = audit;
        invalid.high_severity = 0;
        assert!(
            compose_fixture(&[], Some(&invalid), Distro::Arch).is_err(),
            "counter refusal precedes any SBOM export"
        );
    }

    #[test]
    fn exports_preserve_each_distribution_identity_and_native_version() {
        let package = SecurityPackage {
            origin: crate::package_managers::types::SecurityOrigin::Unknown,
            name: "fixture+tools".into(),
            version: "2:1.0-3".into(),
            advisory_source: None,
            architecture: Some("amd64".into()),
            description: "Installed component".into(),
            licenses: vec!["custom license".into()],
        };
        for (distro, name, prefix) in [
            (Distro::Arch, "Arch Linux", "pkg:alpm/arch/"),
            (Distro::Debian, "Debian", "pkg:deb/debian/"),
            (Distro::Ubuntu, "Ubuntu", "pkg:deb/ubuntu/"),
            (Distro::Fedora, "Fedora", "pkg:rpm/fedora/"),
        ] {
            let report = compose_fixture(std::slice::from_ref(&package), None, distro).unwrap();
            assert_eq!(report.metadata.component.as_ref().unwrap().name, name);
            assert_eq!(report.components[0].version, "2:1.0-3");
            assert!(
                report.components[0]
                    .purl
                    .as_ref()
                    .unwrap()
                    .starts_with(prefix)
            );
            assert!(
                report.components[0]
                    .purl
                    .as_ref()
                    .unwrap()
                    .contains("fixture%2Btools")
            );
            assert_eq!(
                report.components[0].licenses[0]
                    .license
                    .as_ref()
                    .unwrap()
                    .name
                    .as_deref(),
                Some("custom license")
            );
            assert!(
                report.components[0].licenses[0]
                    .license
                    .as_ref()
                    .unwrap()
                    .id
                    .is_none()
            );
            assert!(report.dependencies.is_empty());
        }
        let mut sourced = package.clone();
        sourced.advisory_source = Some(("different-source".into(), "1.0".into()));
        let report = compose_fixture(&[sourced], None, Distro::Debian).unwrap();
        assert_eq!(report.components[0].name, "fixture+tools");
        assert_eq!(report.components[0].version, "2:1.0-3");
        assert!(compose_fixture(&[], None, Distro::Unknown).is_err());
        assert!(compose_fixture(&[package.clone(), package], None, Distro::Debian).is_err());
    }

    #[test]
    fn findings_bind_to_exact_components_and_missing_identity_is_an_error() {
        let old = SecurityPackage {
            origin: crate::package_managers::types::SecurityOrigin::Unknown,
            name: "fixture".into(),
            version: "1:1.0-1".into(),
            advisory_source: None,
            architecture: Some("x86_64".into()),
            description: String::new(),
            licenses: vec![],
        };
        let mut patched = old.clone();
        patched.version = "1:1.0-2".into();
        let mut other_arch = old.clone();
        other_arch.architecture = Some("i686".into());
        let installed = vec![old.clone(), patched.clone(), other_arch];
        let audit = SecurityAuditResult {
            coverage: crate::core::security::scan::AuditCoverage::Unreported,
            total_vulnerabilities: 1,
            high_severity: 0,
            vulnerabilities: vec![(
                old.name.clone(),
                vec![Vulnerability {
                    applicability: crate::core::security::scan::FindingApplicability::Possible,
                    id: "fixture-advisory".into(),
                    summary: "fixture".into(),
                    score: None,
                    advisory_severity: None,
                    native_advisory: None,
                    affected_installed: vec![InstalledIdentity::from(&old)],
                }],
            )],
        };
        let sbom = compose_fixture(&installed, Some(&audit), Distro::Fedora).unwrap();
        assert_eq!(sbom.components.len(), 3);
        assert_eq!(sbom.vulnerabilities[0].affects.len(), 1);
        assert_eq!(
            sbom.vulnerabilities[0].affects[0].affects_ref,
            "pkg:rpm/fedora/fixture@1.0-1?arch=x86_64&epoch=1"
        );
        assert!(sbom.vulnerabilities[0].ratings.is_empty());
        assert_eq!(sbom.metadata.component.as_ref().unwrap().name, "Fedora");
        let mut native_audit = audit.clone();
        native_audit.high_severity = 1;
        let finding = &mut native_audit.vulnerabilities[0].1[0];
        finding.advisory_severity = Some(AdvisorySeverity::Important);
        finding.native_advisory = Some(crate::core::security::scan::NativeAdvisory {
            source: "dnf5".into(),
            advisory_nevra: "fixture-1:1.0-2.x86_64".into(),
            published_severity: "Important".into(),
            description: "Upstream details".into(),
            references: vec![crate::core::security::scan::AdvisoryReference {
                id: "BZ-fixture".into(),
                kind: "bugzilla".into(),
                url: "https://example.test/advisory".into(),
            }],
        });
        let native = compose_fixture(&installed, Some(&native_audit), Distro::Fedora).unwrap();
        let evidence = &native.vulnerabilities[0];
        assert_eq!(evidence.ratings[0].score, None);
        assert_eq!(evidence.ratings[0].severity.as_deref(), Some("high"));
        assert_eq!(evidence.description.as_deref(), Some("Upstream details"));
        assert!(
            evidence.properties.iter().any(
                |property| property.name == "omg:advisory:title" && property.value == "fixture"
            )
        );
        assert_eq!(evidence.advisories[0].url, "https://example.test/advisory");
        assert!(evidence.references.is_empty());
        assert!(evidence.properties.iter().any(|property| property.name
            == "omg:advisory:published-severity"
            && property.value == "Important"));
        assert!(compose_fixture(&[patched], Some(&audit), Distro::Fedora).is_err());
        let ubuntu = compose_fixture(&[old], None, Distro::Ubuntu).unwrap();
        assert!(
            ubuntu.components[0]
                .purl
                .as_deref()
                .unwrap()
                .starts_with("pkg:deb/ubuntu/fixture@1%3A1.0-1")
        );
    }
    #[test]
    fn coverage17_sbom_exports_unknown_scope_and_possible_source_matches() {
        use crate::core::security::scan::{
            AdvisoryProvenance, FindingApplicability, UnassessedPackage,
        };
        let package = SecurityPackage {
            origin: crate::package_managers::types::SecurityOrigin::Unknown,
            name: "libacl1".into(),
            version: "1:2.3-1".into(),
            architecture: Some("amd64".into()),
            advisory_source: Some(("acl".into(), "1:2.3-1".into())),
            description: String::new(),
            licenses: Vec::new(),
        };
        let identity = InstalledIdentity::from(&package);
        let audit = SecurityAuditResult {
            total_vulnerabilities: 1,
            high_severity: 0,
            coverage: AuditCoverage::Reported {
                assessed: Vec::new(),
                unassessed: vec![UnassessedPackage {
                    package: identity.clone(),
                    reason:
                        crate::core::security::vulnerability::UnknownCoverage::OriginUnestablished,
                }],
                sources: vec![AdvisoryProvenance::Osv {
                    ecosystem: "Debian".into(),
                }],
            },
            vulnerabilities: vec![(
                package.name.clone(),
                vec![Vulnerability {
                    id: "possible-source-match".into(),
                    summary: "Review installed source".into(),
                    score: None,
                    advisory_severity: None,
                    native_advisory: None,
                    affected_installed: vec![identity],
                    applicability: FindingApplicability::Possible,
                }],
            )],
        };
        let report =
            compose_fixture(std::slice::from_ref(&package), Some(&audit), Distro::Debian).unwrap();
        let properties = report.components[0].properties.as_ref().unwrap();
        assert!(properties.iter().any(
            |property| property.name == "omg:advisory-coverage" && property.value == "unknown"
        ));
        assert!(
            properties
                .iter()
                .any(|property| property.name == "omg:advisory-source-name"
                    && property.value == "acl")
        );
        assert_eq!(
            report.vulnerabilities[0].affects[0].affects_ref,
            "pkg:deb/debian/libacl1@1%3A2.3-1?arch=amd64"
        );
        assert!(
            report.vulnerabilities[0]
                .properties
                .iter()
                .any(|property| property.name == "omg:advisory-applicability"
                    && property.value == "possible")
        );
        let mut missing = audit;
        missing.coverage = AuditCoverage::Reported {
            assessed: Vec::new(),
            unassessed: Vec::new(),
            sources: Vec::new(),
        };
        assert!(
            compose_fixture(&[package], Some(&missing), Distro::Debian).is_err(),
            "reported coverage may not omit an installed identity"
        );
    }
}
