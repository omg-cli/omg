//! Shared audit findings joined to exact installed SBOM components.
use super::sbom::{
    Sbom, SbomComponent, SbomError, SbomLicense, SbomLicenseInfo, SbomMetadata, SbomProperty,
    SbomTool, SbomVulnAdvisory, SbomVulnAffects, SbomVulnRating, SbomVulnSource, SbomVulnerability,
};
use super::scan::{AdvisorySeverity, SecurityAuditResult};
use crate::core::env::distro::Distro;
use crate::package_managers::types::SecurityPackage;
use anyhow::Context;

pub(super) async fn generate(include_vulns: bool) -> Result<Sbom, SbomError> {
    let result = async {
        let manager = crate::package_managers::get_package_manager()?;
        let mut installed = manager
            .security_inventory()
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
            .security_inventory()
            .await
            .context("Failed to list packages")?;
        let key = |p: &SecurityPackage| (p.name.clone(), p.version.clone(), p.architecture.clone());
        installed.sort_by_key(key);
        after.sort_by_key(key);
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

fn purl(package: &SecurityPackage, distro: Distro) -> anyhow::Result<String> {
    let (kind, namespace) = match distro {
        Distro::Arch => ("alpm", "arch"),
        Distro::Debian => ("deb", "debian"),
        Distro::Ubuntu => ("deb", "ubuntu"),
        Distro::Fedora => ("rpm", "fedora"),
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
    let mut value = format!(
        "pkg:{kind}/{namespace}/{}@{}",
        urlencoding::encode(&package.name),
        urlencoding::encode(version)
    );
    if !qualifiers.is_empty() {
        value.push('?');
        value.push_str(&qualifiers.join("&"));
    }
    Ok(value)
}

pub(super) fn compose(
    installed: &[SecurityPackage],
    audit: Option<&SecurityAuditResult>,
    distro: Distro,
) -> anyhow::Result<Sbom> {
    let os_name = match distro {
        Distro::Arch => "Arch Linux",
        Distro::Debian => "Debian",
        Distro::Ubuntu => "Ubuntu",
        Distro::Fedora => "Fedora",
        _ => anyhow::bail!("Unsupported SBOM distribution"),
    };
    let mut components = Vec::new();
    let mut identities = std::collections::BTreeMap::new();
    for package in installed {
        let reference = purl(package, distro)?;
        let key = (
            package.name.clone(),
            package.version.clone(),
            package.architecture.clone(),
        );
        anyhow::ensure!(
            identities.insert(key, reference.clone()).is_none(),
            "Duplicate installed SBOM identity"
        );
        components.push(SbomComponent {
            component_type: "library".into(),
            mime_type: None,
            bom_ref: Some(reference.clone()),
            name: package.name.clone(),
            version: package.version.clone(),
            description: Some(package.description.clone()),
            purl: Some(reference),
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
            properties: None,
        });
    }
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
                    properties: finding
                        .native_advisory
                        .as_ref()
                        .map(|native| {
                            vec![
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
                            .filter(|property| !property.value.is_empty())
                            .collect()
                        })
                        .unwrap_or_default(),
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
                properties: None,
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

    #[test]
    fn exports_preserve_each_distribution_identity_and_native_version() {
        let package = SecurityPackage {
            name: "fixture+tools".into(),
            version: "2:1.0-3".into(),
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
            let report = compose(std::slice::from_ref(&package), None, distro).unwrap();
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
        assert!(compose(&[], None, Distro::Unknown).is_err());
        assert!(compose(&[package.clone(), package], None, Distro::Debian).is_err());
    }

    #[test]
    fn findings_bind_to_exact_components_and_missing_identity_is_an_error() {
        let old = SecurityPackage {
            name: "fixture".into(),
            version: "1:1.0-1".into(),
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
            total_vulnerabilities: 1,
            high_severity: 0,
            vulnerabilities: vec![(
                old.name.clone(),
                vec![Vulnerability {
                    id: "fixture-advisory".into(),
                    summary: "fixture".into(),
                    score: None,
                    advisory_severity: None,
                    native_advisory: None,
                    affected_installed: vec![InstalledIdentity::from(&old)],
                }],
            )],
        };
        let sbom = compose(&installed, Some(&audit), Distro::Fedora).unwrap();
        assert_eq!(sbom.components.len(), 3);
        assert_eq!(sbom.vulnerabilities[0].affects.len(), 1);
        assert_eq!(
            sbom.vulnerabilities[0].affects[0].affects_ref,
            "pkg:rpm/fedora/fixture@1.0-1?arch=x86_64&epoch=1"
        );
        assert!(sbom.vulnerabilities[0].ratings.is_empty());
        assert_eq!(sbom.metadata.component.as_ref().unwrap().name, "Fedora");
        let mut native_audit = audit.clone();
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
        let native = compose(&installed, Some(&native_audit), Distro::Fedora).unwrap();
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
        assert!(compose(&[patched], Some(&audit), Distro::Fedora).is_err());
        assert!(
            purl(&old, Distro::Ubuntu)
                .unwrap()
                .starts_with("pkg:deb/ubuntu/fixture@1%3A1.0-1")
        );
    }
}
