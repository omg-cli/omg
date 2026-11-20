//! Integration tests for the update command
//!
//! These tests verify the full update flow using dependency injection
//! and mock implementations to avoid requiring root or system changes.

use omg_lib::core::packages::PackageService;
use omg_lib::core::security::vulnerability::{VulnerabilityError, VulnerabilitySource};
use omg_lib::core::testing::{TestPackageManager, UpdateFixture};
use omg_lib::package_managers::PackageManager;
use omg_lib::package_managers::types::UpdateInfo;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

#[cfg(feature = "arch")]
fn version_text(version: &omg_lib::package_managers::types::Version) -> String {
    version.to_string()
}

#[cfg(not(feature = "arch"))]
fn version_text(version: &omg_lib::package_managers::types::Version) -> &str {
    version.as_str()
}

struct NoKnownVulnerabilities;

impl VulnerabilitySource for NoKnownVulnerabilities {
    fn assess_packages<'a>(
        &'a self,
        packages: &'a [omg_lib::package_managers::types::SecurityPackage],
        _evidence_use: omg_lib::core::security::vulnerability::AssessmentUse,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        Vec<omg_lib::core::security::vulnerability::PackageAssessment>,
                        VulnerabilityError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            Ok(packages
                .iter()
                .cloned()
                .map(
                    |package| omg_lib::core::security::vulnerability::PackageAssessment {
                        package,
                        coverage:
                            omg_lib::core::security::vulnerability::PackageCoverage::Assessed {
                                provenance:
                                    omg_lib::core::security::scan::AdvisoryProvenance::Osv {
                                        ecosystem: "fixture".into(),
                                    },
                            },
                        findings: Vec::new(),
                    },
                )
                .collect())
        })
    }
}

#[tokio::test]
async fn test_update_with_no_updates() {
    let pm = Arc::new(TestPackageManager::new());
    let service = PackageService::builder(pm)
        .without_history()
        .build()
        .expect("history-disabled service should build");

    let updates = service.list_updates().await.unwrap();
    assert_eq!(updates.len(), 0);
}

#[tokio::test]
async fn test_update_with_available_updates() {
    let pm = Arc::new(TestPackageManager::with_updates());
    let service = PackageService::builder(pm)
        .without_history()
        .build()
        .expect("history-disabled service should build");

    let updates = service.list_updates().await.unwrap();
    assert_eq!(updates.len(), 2);
    assert_eq!(updates[0].name, "firefox");
    assert_eq!(updates[0].old_version, "121.0-1");
    assert_eq!(updates[0].new_version, "122.0-1");
}

#[tokio::test]
async fn test_update_execution() {
    let pm = Arc::new(TestPackageManager::with_defaults());
    pm.set_updates(vec![UpdateInfo {
        name: "firefox".to_string(),
        old_version: "121.0-1".to_string(),
        new_version: "122.0-1".to_string(),
        repo: "extra".to_string(),
    }]);

    let service = PackageService::builder(pm)
        .without_history()
        .build()
        .expect("history-disabled service should build");

    // Check for updates
    let updates = service.list_updates().await.unwrap();
    assert_eq!(updates.len(), 1);

    // Execute update
    let result = service.update().await;
    assert!(result.is_ok(), "Update should succeed: {:?}", result.err());
}

#[tokio::test]
async fn test_update_with_backend_failure() {
    let pm = Arc::new(TestPackageManager::new());
    pm.set_fail_operations(true);

    let service = PackageService::builder(pm)
        .without_history()
        .build()
        .expect("history-disabled service should build");

    let result = service.update().await;
    assert!(result.is_err(), "Update should fail when backend fails");
}

#[tokio::test]
async fn test_search_functionality() {
    let pm = Arc::new(TestPackageManager::with_defaults());
    let service = PackageService::builder(pm)
        .without_history()
        .build()
        .expect("history-disabled service should build");

    // Search for existing package
    let results = service.search("git").await.unwrap();
    assert!(!results.is_empty());
    assert!(results.iter().any(|p| p.name.contains("git")));

    // Search for non-existing package
    let results = service.search("nonexistent-package-xyz").await.unwrap();
    assert!(results.is_empty());
}

#[tokio::test]
async fn test_install_package() {
    let pm = Arc::new(TestPackageManager::new());
    pm.add_package("test-package", "1.0.0", "A test package");

    let service = PackageService::builder(pm.clone())
        .vulnerability_source(Arc::new(NoKnownVulnerabilities))
        .without_history()
        .build()
        .expect("history-disabled service should build");

    // Install the package
    let result = service.install(&["test-package".to_string()], false).await;
    assert!(result.is_ok());

    // Verify it's marked as installed
    assert!(pm.is_installed("test-package").await.unwrap());
}

#[tokio::test]
async fn test_install_nonexistent_package_fails() {
    let pm = Arc::new(TestPackageManager::new());
    let service = PackageService::builder(pm)
        .without_history()
        .build()
        .expect("history-disabled service should build");

    let result = service
        .install(&["nonexistent-package".to_string()], false)
        .await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
}

#[tokio::test]
async fn test_remove_package() {
    let pm = Arc::new(TestPackageManager::new());
    pm.add_package("test-package", "1.0.0", "A test package");
    pm.install_package("test-package");

    let service = PackageService::builder(pm.clone())
        .without_history()
        .build()
        .expect("history-disabled service should build");

    // Remove the package
    let result = service.remove(&["test-package".to_string()]).await;
    assert!(result.is_ok());

    // Verify it's no longer installed
    assert!(!pm.is_installed("test-package").await.unwrap());
}

#[tokio::test]
async fn test_get_status() {
    let pm = Arc::new(TestPackageManager::with_defaults());
    let service = PackageService::builder(pm)
        .without_history()
        .build()
        .expect("history-disabled service should build");

    let (total, explicit, orphans, updates) = service.get_status(false).await.unwrap();

    // Verify counts match the mock setup
    assert_eq!(total, 4); // firefox, git, pacman, vim
    assert_eq!(explicit, 2); // pacman, git are installed by default
    assert_eq!(orphans, 0);
    assert_eq!(updates, 0); // no updates configured
}

#[tokio::test]
async fn test_get_status_with_updates() {
    let pm = Arc::new(TestPackageManager::with_updates());
    let service = PackageService::builder(pm)
        .without_history()
        .build()
        .expect("history-disabled service should build");

    let (_total, _explicit, _orphans, updates) = service.get_status(false).await.unwrap();

    assert_eq!(updates, 2);
}

#[tokio::test]
async fn test_get_package_info() {
    let pm = Arc::new(TestPackageManager::with_defaults());
    let service = PackageService::builder(pm)
        .without_history()
        .build()
        .expect("history-disabled service should build");

    // Get existing package info
    let info = service.info("git").await.unwrap();
    assert!(info.is_some());
    let pkg = info.unwrap();
    assert_eq!(pkg.name, "git");
    assert_eq!(version_text(&pkg.version), "2.43.0-1");

    // Get non-existing package info
    let info = service.info("nonexistent").await.unwrap();
    assert!(info.is_none());
}

#[tokio::test]
async fn test_update_with_multiple_package_types() {
    let pm = Arc::new(TestPackageManager::with_defaults());

    // Configure multiple updates of different types
    pm.set_updates(UpdateFixture::typical_system());

    let service = PackageService::builder(pm)
        .without_history()
        .build()
        .expect("history-disabled service should build");

    let updates = service.list_updates().await.unwrap();
    assert_eq!(updates.len(), 3);

    // Verify all updates are present
    assert!(updates.iter().any(|u| u.name == "firefox"));
    assert!(updates.iter().any(|u| u.name == "git"));
    assert!(updates.iter().any(|u| u.name == "kernel"));
}

#[tokio::test]
async fn test_concurrent_operations() {
    let pm = Arc::new(TestPackageManager::with_defaults());
    let service = Arc::new(
        PackageService::builder(pm)
            .without_history()
            .build()
            .expect("history-disabled service should build"),
    );

    // Run multiple operations concurrently
    let search_task = tokio::spawn({
        let service = service.clone();
        async move { service.search("git").await }
    });

    let status_task = tokio::spawn({
        let service = service.clone();
        async move { service.get_status(false).await }
    });

    let info_task = tokio::spawn({
        let service = service.clone();
        async move { service.info("firefox").await }
    });

    // All operations should complete successfully and return meaningful data
    let search_result = search_task.await.unwrap();
    let status_result = status_task.await.unwrap();
    let info_result = info_task.await.unwrap();

    // search("git"): the defaults fixture contains "git"; results must reflect it
    let results = search_result.expect("concurrent search should succeed");
    assert!(
        results.iter().any(|p| p.name == "git"),
        "search for 'git' should find the 'git' package, got: {:?}",
        results.iter().map(|p| &p.name).collect::<Vec<_>>()
    );

    // get_status: with_defaults has 4 packages, 2 installed (git, pacman),
    // 0 orphans, 0 pending updates
    let status = status_result.expect("concurrent status should succeed");
    assert_eq!(status, (4, 2, 0, 0), "unexpected status counts");

    // info("firefox"): the defaults fixture registers firefox 122.0-1
    let info = info_result.expect("concurrent info should succeed");
    let package = info.expect("info('firefox') should find the registered package");
    assert_eq!(package.name, "firefox");
    // The version field type varies by backend feature.
    #[cfg(feature = "arch")]
    assert_eq!(package.version.to_string(), "122.0-1");
    #[cfg(not(feature = "arch"))]
    assert_eq!(version_text(&package.version), "122.0-1");
}

#[tokio::test]
async fn test_update_type_detection() {
    use omg_lib::cli::tea::UpdateType;

    // Test major version update
    assert_eq!(
        UpdateType::from_versions("1.0.0", "2.0.0"),
        omg_lib::cli::tea::UpdateType::Major
    );

    // Test minor version update
    assert_eq!(
        UpdateType::from_versions("1.0.0", "1.1.0"),
        omg_lib::cli::tea::UpdateType::Minor
    );

    // Test patch version update
    assert_eq!(
        UpdateType::from_versions("1.0.0", "1.0.1"),
        omg_lib::cli::tea::UpdateType::Patch
    );
}

// Property-based update contracts run in the default test suite.
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_search_returns_valid_results(query in "[a-z]{1,10}") {
            let pm = Arc::new(TestPackageManager::with_defaults());
            let service = PackageService::builder(pm)
                .without_history()
                .build()
                .expect("history-disabled service should build");

            let results = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(service.search(&query));

            // The mock backend cannot fail; an error must fail the test
            // rather than being silently swallowed by an `if let Ok` guard.
            let pkgs = results.expect("search against TestPackageManager must succeed");

            // All results should have the query in name or description
            for pkg in pkgs {
                let query_lower = query.to_lowercase();
                prop_assert!(
                    pkg.name.to_lowercase().contains(&query_lower) ||
                    pkg.description.to_lowercase().contains(&query_lower),
                    "result {:?} does not match query {query}", pkg.name
                );
            }
        }

        #[test]
        fn test_install_then_remove(package_name in "[a-z]{3,10}") {
            let pm = Arc::new(TestPackageManager::new());
            pm.add_package(&package_name, "1.0.0", "Test package");

            // Explicit review policies use this fixture source rather than
            // depending on a live advisory endpoint during package operations.
            let service = PackageService::builder(pm.clone())
                .vulnerability_source(Arc::new(NoKnownVulnerabilities))
                .without_history()
                .build()
                .expect("history-disabled service should build");

            let rt = tokio::runtime::Runtime::new().unwrap();

            // Install
            let install_result = rt.block_on(
                service.install(std::slice::from_ref(&package_name), false)
            );
            prop_assert!(install_result.is_ok());
            prop_assert!(rt.block_on(pm.is_installed(&package_name)).unwrap());

            // Remove
            let remove_result = rt.block_on(
                service.remove(std::slice::from_ref(&package_name))
            );
            prop_assert!(remove_result.is_ok());
            prop_assert!(!rt.block_on(pm.is_installed(&package_name)).unwrap());
        }
    }
}
