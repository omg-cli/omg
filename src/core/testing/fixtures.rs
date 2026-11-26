//! Test fixtures and builders for common test scenarios.

use crate::core::{Package, PackageSource};
use crate::package_managers::parse_version_or_zero;
use crate::package_managers::types::UpdateInfo;

/// Builder for packages used by integration tests.
#[derive(Debug, Default)]
pub struct PackageFixture {
    name: String,
    version: String,
    description: String,
}

impl PackageFixture {
    /// Create an empty package fixture builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the package name.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Set the package version.
    #[must_use]
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    /// Set the package description.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Build the package, applying stable defaults to omitted fields.
    #[must_use]
    pub fn build(self) -> Package {
        let version = if self.version.is_empty() {
            "1.0.0"
        } else {
            &self.version
        };

        Package {
            name: if self.name.is_empty() {
                "test-package".to_owned()
            } else {
                self.name
            },
            version: parse_version_or_zero(version),
            description: if self.description.is_empty() {
                "Test package description".to_owned()
            } else {
                self.description
            },
            source: PackageSource::Official,
            installed: false,
        }
    }
}

/// Factory for common update scenarios.
pub struct UpdateFixture;

impl UpdateFixture {
    /// Create a typical system update scenario.
    #[must_use]
    pub fn typical_system() -> Vec<UpdateInfo> {
        vec![
            update("firefox", "1.0.0-1", "1.0.1-1"),
            update("git", "1.0.0-1", "1.1.0-1"),
            update("kernel", "1.0.0-1", "2.0.0-1"),
        ]
    }
}

fn update(name: &str, old_version: &str, new_version: &str) -> UpdateInfo {
    UpdateInfo {
        architecture: None,
        name: name.to_owned(),
        old_version: old_version.to_owned(),
        new_version: new_version.to_owned(),
        repo: "extra".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "arch")]
    fn version_text(version: &crate::package_managers::types::Version) -> String {
        version.to_string()
    }

    #[cfg(not(feature = "arch"))]
    fn version_text(version: &crate::package_managers::types::Version) -> &str {
        version.as_str()
    }

    #[test]
    fn test_package_fixture_defaults() {
        let pkg = PackageFixture::new().build();
        assert_eq!(pkg.name, "test-package");
        assert_eq!(version_text(&pkg.version), "1.0.0");
    }

    #[test]
    fn test_update_fixture_typical_system() {
        let updates = UpdateFixture::typical_system();
        assert_eq!(updates.len(), 3);
    }
}
