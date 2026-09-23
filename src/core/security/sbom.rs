//! Software Bill of Materials (SBOM) generation in `CycloneDX` format
//!
//! Generates industry-standard `CycloneDX` 1.5 SBOMs for compliance,
//! supply chain security, and vulnerability tracking.

use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::core::paths;

use super::vulnerability::PackageSource;

/// `CycloneDX` SBOM format (industry standard for enterprise)
/// Compliant with `CycloneDX` 1.5 specification
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Sbom {
    pub bom_format: String,
    pub spec_version: String,
    pub serial_number: String,
    pub version: u32,
    pub metadata: SbomMetadata,
    pub components: Vec<SbomComponent>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub dependencies: Vec<SbomDependency>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub vulnerabilities: Vec<SbomVulnerability>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SbomMetadata {
    pub timestamp: String,
    pub tools: Vec<SbomTool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<SbomComponent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manufacture: Option<SbomOrganization>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supplier: Option<SbomOrganization>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SbomTool {
    pub vendor: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SbomOrganization {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SbomComponent {
    #[serde(rename = "type")]
    pub component_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(rename = "bom-ref", skip_serializing_if = "Option::is_none")]
    pub bom_ref: Option<String>,
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub licenses: Vec<SbomLicense>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub hashes: Vec<SbomHash>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub external_references: Vec<SbomExternalRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<Vec<SbomProperty>>,
}

/// Failures generating or exporting a CycloneDX SBOM.
#[derive(Debug, Error)]
pub enum SbomError {
    #[error("Failed to generate a complete security SBOM")]
    Audit {
        #[source]
        source: PackageSource,
    },
    #[error("Failed to serialize SBOM")]
    Serialize {
        #[source]
        source: serde_json::Error,
    },
    #[error("Failed to create SBOM directory '{path}'")]
    CreateDir {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("Failed to write SBOM '{path}'")]
    Write {
        path: String,
        #[source]
        source: io::Error,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SbomLicense {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<SbomLicenseInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SbomLicenseInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SbomHash {
    pub alg: String,
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SbomExternalRef {
    #[serde(rename = "type")]
    pub ref_type: String,
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SbomProperty {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SbomDependency {
    #[serde(rename = "ref")]
    pub dep_ref: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub depends_on: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SbomVulnerability {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<SbomVulnSource>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ratings: Vec<SbomVulnRating>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub affects: Vec<SbomVulnAffects>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub references: Vec<SbomVulnReference>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub advisories: Vec<SbomVulnAdvisory>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub properties: Vec<SbomProperty>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SbomVulnAdvisory {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SbomVulnReference {
    pub id: String,
    pub source: SbomVulnSource,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SbomVulnSource {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SbomVulnRating {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SbomVulnAffects {
    #[serde(rename = "ref")]
    pub affects_ref: String,
}

/// SBOM Generator for enterprise compliance
pub struct SbomGenerator {
    include_vulns: bool,
}

impl Default for SbomGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl SbomGenerator {
    #[must_use]
    pub fn new() -> Self {
        Self {
            include_vulns: true,
        }
    }

    /// Include vulnerability matching from the selected backend's advisory source.
    #[must_use]
    pub const fn with_vulnerabilities(mut self, include: bool) -> Self {
        self.include_vulns = include;
        self
    }

    /// Generate an SBOM from the shared native inventory and audit results.
    pub async fn generate_system_sbom(&self) -> Result<Sbom, SbomError> {
        super::sbom_shared::generate(self.include_vulns).await
    }

    /// Export SBOM to JSON file (atomic replace, so a crash mid-write can
    /// never leave a truncated artifact)
    pub fn export_json<P: AsRef<Path>>(&self, sbom: &Sbom, path: P) -> Result<(), SbomError> {
        let path_str = path.as_ref().display().to_string();
        let json =
            serde_json::to_string_pretty(sbom).map_err(|source| SbomError::Serialize { source })?;
        crate::core::safe_ops::atomic_write_file_sync_private(path.as_ref(), json.as_bytes())
            .map_err(|error| SbomError::Write {
                path: path_str,
                source: io::Error::other(error),
            })?;
        Ok(())
    }

    /// Export SBOM to default location
    pub fn export_default(&self, sbom: &Sbom) -> Result<std::path::PathBuf, SbomError> {
        let sbom_dir = paths::data_dir().join("sbom");
        paths::create_private_data_directory(&sbom_dir).map_err(|source| SbomError::CreateDir {
            path: sbom_dir.display().to_string(),
            source,
        })?;

        let timestamp = jiff::Zoned::now().strftime("%Y%m%d-%H%M%S").to_string();
        let filename = format!("sbom-{timestamp}.json");
        let path = sbom_dir.join(&filename);

        self.export_json(sbom, &path)?;
        Ok(path)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used)] // Idiomatic in tests: panics on failure with clear error context
mod tests {
    use super::*;

    #[test]
    fn test_sbom_serialization() {
        let json = serde_json::to_string(&sample_sbom()).unwrap();
        assert!(json.contains("CycloneDX"));
        assert!(json.contains("1.5"));
    }

    fn sample_sbom() -> Sbom {
        Sbom {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.5".to_string(),
            serial_number: "urn:uuid:test".to_string(),
            version: 1,
            metadata: SbomMetadata {
                timestamp: "2026-01-16T00:00:00Z".to_string(),
                tools: vec![SbomTool {
                    vendor: "OMG".to_string(),
                    name: "omg".to_string(),
                    version: "0.1.0".to_string(),
                }],
                component: None,
                manufacture: None,
                supplier: None,
            },
            components: vec![],
            dependencies: vec![],
            vulnerabilities: vec![],
        }
    }

    #[test]
    fn export_json_fails_closed_when_path_is_a_directory() {
        let temp = tempfile::TempDir::new().unwrap();
        let error = SbomGenerator::new()
            .export_json(&sample_sbom(), temp.path())
            .expect_err("writing an SBOM over a directory must fail");
        assert!(matches!(error, SbomError::Write { .. }), "got: {error}");
    }

    #[cfg(unix)]
    #[test]
    fn export_json_replaces_permissive_file_with_owner_only_report() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("sbom.json");
        std::fs::write(&path, b"previous report").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        SbomGenerator::new()
            .export_json(&sample_sbom(), &path)
            .unwrap();

        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let report: Sbom = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(report.bom_format, "CycloneDX");
    }
}
