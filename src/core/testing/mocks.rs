//! Mock implementations for testing

use anyhow::Result;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use crate::core::{Package, PackageSource};
use crate::package_managers::parse_version_or_zero;
use crate::package_managers::{PackageManager, types::UpdateInfo};

/// Mock package manager with configurable behavior
#[derive(Default)]
pub struct TestPackageManager {
    packages: Mutex<HashMap<String, Package>>,
    installed: Mutex<std::collections::HashSet<String>>,
    updates: Mutex<Vec<UpdateInfo>>,
    fail_operations: Mutex<bool>,
}

impl TestPackageManager {
    /// Create a new test package manager
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a package to the mock database
    pub fn add_package(&self, name: &str, version: &str, description: &str) {
        let mut packages = self.packages.lock().expect("lock poisoned");
        packages.insert(
            name.to_string(),
            Package {
                name: name.to_string(),
                version: parse_version_or_zero(version),
                description: description.to_string(),
                source: PackageSource::Official,
                installed: self.installed.lock().expect("lock poisoned").contains(name),
            },
        );
    }

    /// Mark a package as installed
    pub fn install_package(&self, name: &str) {
        self.set_installed_state(name, true);
    }

    /// Keep the canonical package record and installed-name index consistent.
    /// Locks are always acquired packages-first to avoid AB-BA deadlocks.
    fn set_installed_state(&self, name: &str, installed: bool) {
        let mut packages = self.packages.lock().expect("lock poisoned");
        let mut installed_names = self.installed.lock().expect("lock poisoned");
        if installed {
            installed_names.insert(name.to_string());
        } else {
            installed_names.remove(name);
        }
        if let Some(package) = packages.get_mut(name) {
            package.installed = installed;
        }
    }

    /// Set available updates
    pub fn set_updates(&self, updates: Vec<UpdateInfo>) {
        *self.updates.lock().expect("lock poisoned") = updates;
    }

    /// Configure whether operations should fail
    pub fn set_fail_operations(&self, fail: bool) {
        *self.fail_operations.lock().expect("lock poisoned") = fail;
    }

    /// Create with common test packages
    pub fn with_defaults() -> Self {
        let pm = Self::new();
        pm.add_package("firefox", "122.0-1", "Web browser");
        pm.add_package("git", "2.43.0-1", "Version control");
        pm.add_package("pacman", "6.0.2-1", "Package manager");
        pm.add_package("vim", "9.0.0-1", "Text editor");
        pm.install_package("pacman");
        pm.install_package("git");
        pm
    }

    /// Create with update scenario
    pub fn with_updates() -> Self {
        let pm = Self::with_defaults();
        pm.set_updates(vec![
            UpdateInfo {
                name: "firefox".to_string(),
                old_version: "121.0-1".to_string(),
                new_version: "122.0-1".to_string(),
                repo: "extra".to_string(),
            },
            UpdateInfo {
                name: "vim".to_string(),
                old_version: "8.0-1".to_string(),
                new_version: "9.0.0-1".to_string(),
                repo: "extra".to_string(),
            },
        ]);
        pm
    }

    fn ensure_operation_succeeds(&self, operation: &str) -> Result<()> {
        if *self.fail_operations.lock().expect("lock poisoned") {
            anyhow::bail!("{operation} operation failed (test failure mode)");
        }
        Ok(())
    }
}

impl PackageManager for TestPackageManager {
    fn name(&self) -> &'static str {
        "test-mock"
    }

    fn search(
        &self,
        query: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Package>>> + Send + '_>> {
        let query = query.to_lowercase();
        Box::pin(async move {
            self.ensure_operation_succeeds("Search")?;
            let pkgs = self.packages.lock().expect("lock poisoned");
            Ok(pkgs
                .values()
                .filter(|p| {
                    p.name.to_lowercase().contains(&query)
                        || p.description.to_lowercase().contains(&query)
                })
                .cloned()
                .collect())
        })
    }

    fn install(
        &self,
        packages: &[String],
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let packages = packages.to_vec();
        Box::pin(async move {
            self.ensure_operation_succeeds("Install")?;
            for package in packages {
                self.set_installed_state(&package, true);
            }
            Ok(())
        })
    }

    fn remove(&self, packages: &[String]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let packages = packages.to_vec();
        Box::pin(async move {
            self.ensure_operation_succeeds("Remove")?;
            for package in packages {
                self.set_installed_state(&package, false);
            }
            Ok(())
        })
    }

    fn update(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move { self.ensure_operation_succeeds("Update") })
    }

    fn sync(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move { self.ensure_operation_succeeds("Sync") })
    }

    fn info(
        &self,
        package: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Package>>> + Send + '_>> {
        let package = package.to_string();
        Box::pin(async move {
            self.ensure_operation_succeeds("Info")?;
            Ok(self
                .packages
                .lock()
                .expect("lock poisoned")
                .get(&package)
                .cloned())
        })
    }

    fn list_installed(&self) -> Pin<Box<dyn Future<Output = Result<Vec<Package>>> + Send + '_>> {
        Box::pin(async move {
            self.ensure_operation_succeeds("List installed")?;
            let pkgs = self.packages.lock().expect("lock poisoned");
            let installed_set = self.installed.lock().expect("lock poisoned");
            Ok(pkgs
                .values()
                .filter(|p| installed_set.contains(&p.name))
                .cloned()
                .collect())
        })
    }

    fn get_status(
        &self,
        _fast: bool,
    ) -> Pin<Box<dyn Future<Output = Result<(usize, usize, usize, usize)>> + Send + '_>> {
        Box::pin(async move {
            self.ensure_operation_succeeds("Get status")?;
            let total = self.packages.lock().expect("lock poisoned").len();
            let explicit = self.installed.lock().expect("lock poisoned").len();
            let updates_count = self.updates.lock().expect("lock poisoned").len();
            Ok((total, explicit, 0, updates_count))
        })
    }

    fn list_explicit(&self) -> Pin<Box<dyn Future<Output = Result<Vec<String>>> + Send + '_>> {
        Box::pin(async move {
            self.ensure_operation_succeeds("List explicit")?;
            Ok(self
                .installed
                .lock()
                .expect("lock poisoned")
                .iter()
                .cloned()
                .collect())
        })
    }

    fn list_updates(&self) -> Pin<Box<dyn Future<Output = Result<Vec<UpdateInfo>>> + Send + '_>> {
        Box::pin(async move {
            self.ensure_operation_succeeds("List updates")?;
            Ok(self.updates.lock().expect("lock poisoned").clone())
        })
    }

    fn is_installed(
        &self,
        package: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + '_>> {
        let package = package.to_string();
        Box::pin(async move {
            Ok(self
                .installed
                .lock()
                .expect("lock poisoned")
                .contains(&package))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn aur_provenance_reaches_service_admission_without_backend_mutation() -> Result<()> {
        let backend = std::sync::Arc::new(TestPackageManager::new());
        backend.add_package("aur-fixture", "1.0.0", "AUR candidate");
        {
            let mut packages = backend.packages.lock().expect("packages");
            packages
                .get_mut("aur-fixture")
                .expect("fixture package")
                .source = PackageSource::Aur;
        }
        let service = crate::core::packages::PackageService::builder(backend.clone())
            .policy(crate::core::security::policy::SecurityPolicy {
                allow_aur: false,
                ..crate::core::security::policy::SecurityPolicy::default()
            })
            .without_history()
            .build()?;
        let error = service
            .install(&["aur-fixture".into()], true)
            .await
            .expect_err("generic backend must preserve AUR source policy");
        assert!(
            matches!(error.downcast_ref::<crate::core::security::policy::PolicyError>(),
            Some(crate::core::security::policy::PolicyError::AurDisabled {name}) if name=="aur-fixture")
        );
        assert!(backend.list_installed().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_mock_basic_operations() {
        let pm = TestPackageManager::new();
        pm.add_package("test", "1.0.0", "Test package");

        // Test search
        let results = pm.search("test").await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "test");

        // Test info
        let info = pm.info("test").await.unwrap();
        assert!(info.is_some());
        assert_eq!(info.unwrap().name, "test");
    }

    #[tokio::test]
    async fn test_mock_install_remove() {
        let pm = TestPackageManager::new();
        pm.add_package("test", "1.0.0", "Test package");

        // Initially not installed
        assert!(!pm.is_installed("test").await.unwrap());

        // Install
        pm.install(&["test".to_string()]).await.unwrap();
        assert!(pm.is_installed("test").await.unwrap());
        assert!(pm.info("test").await.unwrap().unwrap().installed);

        // List installed
        let installed = pm.list_installed().await.unwrap();
        assert_eq!(installed.len(), 1);

        // Remove
        pm.remove(&["test".to_string()]).await.unwrap();
        assert!(!pm.is_installed("test").await.unwrap());
        assert!(!pm.info("test").await.unwrap().unwrap().installed);
    }

    #[tokio::test]
    async fn test_mock_failure_mode() {
        let pm = TestPackageManager::new();
        pm.set_fail_operations(true);

        assert!(pm.search("test").await.is_err());
        assert!(pm.install(&["test".to_string()]).await.is_err());
        assert!(pm.update().await.is_err());
    }

    #[tokio::test]
    async fn test_mock_with_defaults() {
        let pm = TestPackageManager::with_defaults();
        let packages = pm.search("").await.unwrap();
        assert_eq!(packages.len(), 4);
        assert!(packages.iter().any(|package| package.name == "firefox"));
        assert!(packages.iter().any(|package| package.name == "git"));
        assert!(pm.is_installed("git").await.unwrap());
        assert!(!pm.is_installed("firefox").await.unwrap());
    }

    #[tokio::test]
    async fn test_mock_updates() {
        let pm = TestPackageManager::with_updates();
        let updates = pm.list_updates().await.unwrap();
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].name, "firefox");
    }
}
