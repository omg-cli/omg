use crate::core::Package;
use crate::core::history::{HistoryManager, PackageChange, TransactionType};
use crate::core::security::{
    SecurityPolicy,
    vulnerability::{VulnerabilityScanner, VulnerabilitySource},
};
use crate::package_managers::types::{SecurityOrigin, SecurityPackage, UpdateInfo};
use crate::package_managers::{PackageManager, VersionDisplay};
use anyhow::Context;
use anyhow::Result;
use std::sync::Arc;

/// Service for orchestrating package operations across different backends.
pub struct PackageService {
    backend: Arc<dyn PackageManager>,
    policy: SecurityPolicy,
    vulnerability_source: Arc<dyn VulnerabilitySource>,
    history: Option<HistoryManager>,
    #[cfg(feature = "arch")]
    aur_client: Option<crate::package_managers::AurClient>,
}

impl PackageService {
    /// Create a new `PackageService` with the given backend
    pub fn new(backend: Arc<dyn PackageManager>) -> Result<Self> {
        Self::builder(backend).build()
    }

    /// Create a builder for constructing `PackageService` with custom dependencies
    pub fn builder(backend: Arc<dyn PackageManager>) -> PackageServiceBuilder {
        PackageServiceBuilder::new(backend)
    }

    fn require_persisted_policy(&self) -> Result<()> {
        anyhow::ensure!(
            cfg!(test) || self.policy == SecurityPolicy::load_default()?,
            "Custom service policy must match the persisted policy enforced by the privileged backend"
        );
        Ok(())
    }

    async fn check_candidate(
        &self,
        policy: &SecurityPolicy,
        package: SecurityPackage,
    ) -> Result<()> {
        use crate::core::security::policy::AdvisoryRequirement;
        use crate::core::security::vulnerability::{
            AssessmentUse, PackageAssessment, UnknownCoverage, validate_assessment_inventory,
        };
        let packages = [package];
        let prepared_arch_admission = cfg!(feature = "arch") && self.backend.name() == "pacman";
        let assessments = if policy.advisory_requirement == AdvisoryRequirement::Optional
            || (prepared_arch_admission
                && policy.advisory_requirement == AdvisoryRequirement::FreshSnapshot)
        {
            vec![PackageAssessment::unknown(
                packages[0].clone(),
                UnknownCoverage::NotRequested,
            )]
        } else {
            self.vulnerability_source
                .assess_packages(&packages, AssessmentUse::Admission)
                .await?
        };
        validate_assessment_inventory(&packages, &assessments)?;
        if prepared_arch_admission {
            policy.validate_advisory_scope()?;
            let package = &packages[0];
            let license = crate::core::security::policy::combined_license_expression(
                package.licenses.iter().map(String::as_str),
            );
            policy.check_source(&package.name, &package.origin, license.as_deref())?;
        } else {
            policy.check_assessments(&assessments)?;
        }
        Ok(())
    }

    fn repository_origin(&self, repository: &str) -> SecurityOrigin {
        if repository.eq_ignore_ascii_case("aur") {
            SecurityOrigin::AurArchive
        } else if repository.is_empty() {
            SecurityOrigin::Unknown
        } else if self.backend.name() == "pacman" {
            self.policy.arch_repository_origin(repository)
        } else {
            SecurityOrigin::DistributionPackage
        }
    }

    /// Search for packages
    pub async fn search(&self, query: &str) -> Result<Vec<Package>> {
        let results = self.backend.search(query).await?;
        Ok(results)
    }

    /// Install packages, automatically resolving AUR packages if on Arch
    ///
    /// The `yes` parameter is accepted for API compatibility but not used at this layer.
    /// Interactive prompts are handled by the underlying package manager implementations.
    pub async fn install(&self, packages: &[String], _yes: bool) -> Result<()> {
        self.require_persisted_policy()?;
        #[cfg(unix)]
        let pinned = crate::core::security::artifact::SnapshotInputs::capture(packages)?;
        #[cfg(unix)]
        let packages = pinned.targets.as_slice();
        let mut changes: Vec<PackageChange> = Vec::new();

        #[cfg(feature = "arch")]
        let local_metadata = {
            let mut metadata = std::collections::HashMap::new();
            for package in packages
                .iter()
                .filter(|package| crate::core::security::is_local_package_file(package))
            {
                let path = package.clone();
                let local = tokio::task::spawn_blocking(move || {
                    crate::package_managers::alpm_ops::load_local_package_metadata(&path)
                })
                .await??;
                self.check_candidate(
                    &self.policy,
                    SecurityPackage {
                        origin: SecurityOrigin::LocalArchive,
                        name: local.name.clone(),
                        version: local.version.version_string(),
                        advisory_source: None,
                        architecture: None,
                        description: String::new(),
                        licenses: local.license.iter().cloned().collect(),
                    },
                )
                .await?;
                metadata.insert(package.clone(), local);
            }
            metadata
        };

        #[cfg(feature = "arch")]
        if let Some(aur) = &self.aur_client {
            let mut official = Vec::new();
            let mut aur_pkgs = Vec::new();

            for pkg in packages {
                if let Some(local) = local_metadata.get(pkg) {
                    official.push(pkg.clone());
                    changes.push(PackageChange {
                        architecture: None,
                        name: local.name.clone(),
                        old_version: None,
                        new_version: Some(local.version.version_string()),
                        source: "local".to_string(),
                    });
                    continue;
                }

                // Check if it's in official repos. Repository lookup errors
                // are distinct from a package not being present.
                if let Some(info) = self.backend.info(pkg).await? {
                    self.check_candidate(
                        &self.policy,
                        SecurityPackage {
                            origin: SecurityOrigin::Unknown,
                            name: info.name.clone(),
                            version: info.version.version_string(),
                            advisory_source: None,
                            architecture: None,
                            description: info.description.clone(),
                            licenses: Vec::new(),
                        },
                    )
                    .await?;

                    official.push(pkg.clone());
                    changes.push(PackageChange {
                        architecture: None,
                        name: info.name,
                        old_version: None,
                        new_version: Some(info.version.version_string()),
                        source: "official".to_string(),
                    });
                } else if let Some(info) = aur.info(pkg).await? {
                    self.check_candidate(
                        &self.policy,
                        SecurityPackage {
                            origin: SecurityOrigin::AurArchive,
                            name: info.name.clone(),
                            version: info.version.version_string(),
                            advisory_source: None,
                            architecture: None,
                            description: info.description.clone(),
                            licenses: Vec::new(),
                        },
                    )
                    .await?;

                    aur_pkgs.push(pkg.clone());
                    changes.push(PackageChange {
                        architecture: None,
                        name: info.name,
                        old_version: None,
                        new_version: Some(info.version.version_string()),
                        source: "aur".to_string(),
                    });
                } else {
                    anyhow::bail!("Package not found: {pkg}");
                }
            }

            let result = async {
                if !official.is_empty() {
                    self.backend.install(&official).await?;
                }

                for pkg in aur_pkgs {
                    aur.install(&pkg).await?;
                }
                Ok(())
            }
            .await;

            return self.finish_transaction(TransactionType::Install, changes, result);
        }

        for pkg in packages {
            #[cfg(feature = "arch")]
            if let Some(local) = local_metadata.get(pkg) {
                changes.push(PackageChange {
                    architecture: None,
                    name: local.name.clone(),
                    old_version: None,
                    new_version: Some(local.version.version_string()),
                    source: "local".to_string(),
                });
                continue;
            }

            let Some(info) = self.backend.info(pkg).await? else {
                anyhow::bail!("Package not found: {pkg}");
            };
            self.check_candidate(
                &self.policy,
                SecurityPackage {
                    origin: if info.source == crate::core::PackageSource::Aur {
                        SecurityOrigin::AurArchive
                    } else if matches!(self.backend.name(), "apt" | "apt-pure" | "dnf" | "dnf5") {
                        SecurityOrigin::DistributionPackage
                    } else {
                        SecurityOrigin::Unknown
                    },
                    name: info.name.clone(),
                    version: info.version.version_string(),
                    advisory_source: None,
                    architecture: None,
                    description: info.description.clone(),
                    licenses: Vec::new(),
                },
            )
            .await?;

            changes.push(PackageChange {
                architecture: None,
                name: info.name,
                old_version: None,
                new_version: Some(info.version.version_string()),
                source: self.backend.name().to_string(),
            });
        }

        if let Some(operation) = self.backend.transact_with_history(
            TransactionType::Install,
            packages,
            self.history.as_ref(),
        ) {
            return operation.await;
        }
        let result = self.backend.install(packages).await;
        self.finish_transaction(TransactionType::Install, changes, result)
    }

    /// Remove packages using the configured backend's removal policy.
    ///
    /// Configure recursive removal on the backend before constructing this
    /// service (for example, `ArchPackageManager::with_recursive_removal`).
    /// The service records history but does not override backend removal options.
    pub async fn remove(&self, packages: &[String]) -> Result<()> {
        if let Some(operation) = self.backend.transact_with_history(
            TransactionType::Remove,
            packages,
            self.history.as_ref(),
        ) {
            return operation.await;
        }

        // Repository info may describe a newer candidate or omit retired
        // packages. Capture one installed inventory before mutation instead.
        let installed: std::collections::HashMap<_, _> = self
            .backend
            .list_installed()
            .await?
            .into_iter()
            .map(|package| (package.name, package.version.version_string()))
            .collect();
        let changes = packages
            .iter()
            .map(|name| PackageChange {
                architecture: None,
                name: name.clone(),
                // Preserve every request even if its installed version is unknown.
                old_version: installed.get(name).cloned(),
                new_version: None,
                source: self.backend.name().to_string(),
            })
            .collect();
        let result = self.backend.remove(packages).await;

        self.finish_transaction(TransactionType::Remove, changes, result)
    }

    /// Update system
    pub async fn update(&self) -> Result<()> {
        let mut changes = Vec::new();

        self.backend.sync().await?;
        let updates = self.list_updates().await?;
        for up in &updates {
            let version = crate::package_managers::parse_version(&up.new_version)
                .context("Invalid update version")?;
            // License metadata is checked on the prepared transaction.
            let mut candidate_policy = self.policy.clone();
            candidate_policy.allowed_licenses.clear();
            self.check_candidate(
                &candidate_policy,
                SecurityPackage {
                    origin: self.repository_origin(&up.repo),
                    name: up.name.clone(),
                    version: version.version_string(),
                    advisory_source: None,
                    architecture: None,
                    description: String::new(),
                    licenses: Vec::new(),
                },
            )
            .await?;

            changes.push(PackageChange {
                architecture: None,
                name: up.name.clone(),
                old_version: Some(up.old_version.clone()),
                new_version: Some(up.new_version.clone()),
                source: up.repo.clone(),
            });
        }

        self.require_persisted_policy()?;
        if let Some(operation) =
            self.backend
                .transact_with_history(TransactionType::Update, &[], self.history.as_ref())
        {
            return operation.await;
        }
        let result = async {
            self.backend.update().await?;

            #[cfg(feature = "arch")]
            if let Some(aur) = &self.aur_client {
                let aur_updates = aur.get_update_list().await?;
                for (name, _, _) in aur_updates {
                    aur.install(&name).await?;
                }
            }
            Ok(())
        }
        .await;

        self.finish_transaction(TransactionType::Update, changes, result)
    }

    fn finish_transaction(
        &self,
        transaction_type: TransactionType,
        changes: Vec<PackageChange>,
        operation_result: Result<()>,
    ) -> Result<()> {
        if let Some(history) = &self.history {
            return history.finish_operation(transaction_type, changes, operation_result);
        }
        crate::core::security::audit::record_operation(
            &transaction_type.to_string(),
            &changes
                .iter()
                .map(|change| change.name.clone())
                .collect::<Vec<_>>(),
            if operation_result.is_ok() {
                "succeeded"
            } else {
                "failed"
            },
        )?;
        operation_result
    }

    /// List available updates
    pub async fn list_updates(&self) -> Result<Vec<UpdateInfo>> {
        let updates = self.backend.list_updates().await?;

        #[cfg(feature = "arch")]
        let mut updates = updates;

        #[cfg(feature = "arch")]
        if let Some(aur) = &self.aur_client {
            for (name, old, new) in aur
                .get_update_list()
                .await
                .context("Failed to check AUR for updates")?
            {
                updates.push(UpdateInfo {
                    architecture: None,
                    name,
                    old_version: old.to_string(),
                    new_version: new.to_string(),
                    repo: "aur".to_string(),
                });
            }
        }

        Ok(updates)
    }

    /// Get package info
    pub async fn info(&self, package: &str) -> Result<Option<Package>> {
        if let Some(pkg) = self.backend.info(package).await? {
            return Ok(Some(pkg));
        }

        #[cfg(feature = "arch")]
        if let Some(aur) = &self.aur_client {
            return aur.info(package).await;
        }

        Ok(None)
    }

    /// Get system status (total, explicit, orphans, updates)
    pub async fn get_status(&self, fast: bool) -> Result<(usize, usize, usize, usize)> {
        self.backend.get_status(fast).await
    }
}

/// Builder for `PackageService` with dependency injection support
enum HistoryConfiguration {
    Default,
    Custom(HistoryManager),
    Disabled,
}

pub struct PackageServiceBuilder {
    backend: Arc<dyn PackageManager>,
    policy: Option<SecurityPolicy>,
    vulnerability_source: Arc<dyn VulnerabilitySource>,
    history: HistoryConfiguration,
    #[cfg(feature = "arch")]
    aur_client: Option<crate::package_managers::AurClient>,
}

impl PackageServiceBuilder {
    /// Create a new builder with the required backend
    pub fn new(backend: Arc<dyn PackageManager>) -> Self {
        Self {
            backend,
            policy: None,
            vulnerability_source: Arc::new(VulnerabilityScanner::new()),
            history: HistoryConfiguration::Default,
            #[cfg(feature = "arch")]
            aur_client: None,
        }
    }

    /// Set the security policy (defaults to `SecurityPolicy::default()`)
    #[must_use]
    pub fn policy(mut self, policy: SecurityPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Set the vulnerability evidence source.
    #[must_use]
    pub fn vulnerability_source(mut self, source: Arc<dyn VulnerabilitySource>) -> Self {
        self.vulnerability_source = source;
        self
    }

    /// Set the history manager (defaults to `HistoryManager::new()`)
    #[must_use]
    pub fn history(mut self, history: HistoryManager) -> Self {
        self.history = HistoryConfiguration::Custom(history);
        self
    }

    /// Disable history tracking
    #[must_use]
    pub fn without_history(mut self) -> Self {
        self.history = HistoryConfiguration::Disabled;
        self
    }

    /// Set the AUR client (Arch only)
    #[cfg(feature = "arch")]
    #[must_use]
    pub fn aur_client(mut self, client: crate::package_managers::AurClient) -> Self {
        self.aur_client = Some(client);
        self
    }

    /// Build the `PackageService`
    pub fn build(self) -> Result<PackageService> {
        #[cfg(feature = "arch")]
        let aur_client = if self.backend.name() == "pacman" {
            match self.aur_client {
                Some(client) => Some(client),
                None => Some(crate::package_managers::AurClient::new()?),
            }
        } else {
            self.aur_client
        };

        let history = match self.history {
            HistoryConfiguration::Default => Some(HistoryManager::new()?),
            HistoryConfiguration::Custom(history) => Some(history),
            HistoryConfiguration::Disabled => None,
        };

        let policy = match self.policy {
            Some(policy) => policy,
            None => SecurityPolicy::load_default().map_err(|error| anyhow::anyhow!(error))?,
        };

        Ok(PackageService {
            backend: self.backend,
            policy,
            vulnerability_source: self.vulnerability_source,
            history,
            #[cfg(feature = "arch")]
            aur_client,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;

    #[tokio::test]
    #[serial_test::serial(history_ownership)]
    async fn removal_history_records_installed_not_candidate_version() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let backend = Arc::new(crate::package_managers::mock::MockPackageManager::new_in(
            "debian",
            directory.path(),
        ));
        backend.set_installed_version("fixture", "1.0.0")?;
        backend.set_available_version("fixture", "2.0.0")?;
        let history = HistoryManager::new_in(directory.path().join("history.json"))?;
        let service = PackageService::builder(backend).history(history).build()?;
        service.remove(&["fixture".into()]).await?;
        let transactions = service.history.as_ref().unwrap().load()?;
        assert_eq!(transactions.len(), 1);
        assert_eq!(
            transactions[0].changes[0].old_version.as_deref(),
            Some("1.0.0")
        );
        Ok(())
    }

    #[tokio::test]
    async fn updates_come_from_the_injected_inventory() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let backend = Arc::new(crate::package_managers::mock::MockPackageManager::new_in(
            "debian",
            directory.path(),
        ));
        backend.set_installed_version("isolated-fixture", "1.0.0")?;
        backend.set_available_version("isolated-fixture", "2.0.0")?;
        let service = PackageService::builder(backend).without_history().build()?;
        let updates = service.list_updates().await?;
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].name, "isolated-fixture");
        assert_eq!(updates[0].old_version, "1.0.0");
        assert_eq!(updates[0].new_version, "2.0.0");
        Ok(())
    }

    #[test]
    fn builder_without_history_disables_explicit_history() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let history = HistoryManager::new_in(directory.path().join("history.json"))?;
        let backend = Arc::new(crate::core::testing::TestPackageManager::new());

        let service = PackageService::builder(backend)
            .history(history)
            .without_history()
            .build()?;

        assert!(service.history.is_none());
        Ok(())
    }

    #[cfg(feature = "arch")]
    fn write_fake_local_package(path: &std::path::Path, name: &str, version: &str) -> Result<()> {
        use flate2::{Compression, write::GzEncoder};
        use tar::{Builder, EntryType, Header};

        let pkginfo = format!(
            "pkgname = {name}\npkgbase = {name}\nxdata = pkgtype=pkg\npkgver = {version}\n\
             pkgdesc = local policy test\nbuilddate = 1700000000\npackager = test\n\
             size = 1\narch = x86_64\nlicense = MIT\n"
        );
        let mut encoder = GzEncoder::new(std::fs::File::create(path)?, Compression::default());
        let mut archive = Builder::new(&mut encoder);
        let mut header = Header::new_gnu();
        header.set_path(".PKGINFO")?;
        header.set_size(pkginfo.len() as u64);
        header.set_entry_type(EntryType::Regular);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append(&header, pkginfo.as_bytes())?;
        archive.finish()?;
        drop(archive);
        encoder.finish()?.sync_all()?;
        Ok(())
    }

    #[cfg(feature = "arch")]
    #[test]
    fn local_archive_cannot_bypass_a_banned_package_policy() -> Result<()> {
        const NAME: &str =
            "core::packages::service::tests::local_archive_cannot_bypass_a_banned_package_policy";
        if crate::core::testing::run_isolated_test(NAME) {
            return Ok(());
        }
        temp_env::with_vars(
            [
                ("SUDO_USER", None::<&str>),
                ("SUDO_HOME", None),
                ("DOAS_USER", None),
                ("OMG_TEST_MODE", None),
                ("OMG_TEST_DISTRO", None),
            ],
            || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(local_archive_policy_fixture())
            },
        )
    }

    #[cfg(feature = "arch")]
    async fn local_archive_policy_fixture() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir_in("/var/tmp")?;
        let database = directory.path().join("var/lib/pacman");
        std::fs::create_dir_all(database.join("local"))?;
        std::fs::write(database.join("local/ALPM_DB_VERSION"), b"9\n")?;
        struct ResetPaths;
        impl Drop for ResetPaths {
            fn drop(&mut self) {
                crate::core::paths::reset_test_overrides();
            }
        }
        crate::core::paths::set_test_overrides(
            Some(directory.path().to_path_buf()),
            Some(database.clone()),
        );
        let _reset = ResetPaths;
        {
            let handle = crate::package_managers::alpm_ops::open_default_alpm()?;
            assert_eq!(std::path::Path::new(handle.root()), directory.path());
            assert_eq!(std::path::Path::new(handle.dbpath()), database);
        }

        let archive = directory.path().join("renamed-1.0-1-x86_64.pkg.tar.gz");
        write_fake_local_package(&archive, "banned-local", "1.0-1")?;
        std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o600))?;
        let allowed = directory.path().join("allowed-1.0-1-x86_64.pkg.tar.gz");
        write_fake_local_package(&allowed, "allowed-local", "1.0-1")?;
        std::fs::set_permissions(&allowed, std::fs::Permissions::from_mode(0o600))?;

        let mut policy = SecurityPolicy::default();
        policy.banned_packages.push("banned-local".to_string());
        let backend = Arc::new(crate::core::testing::TestPackageManager::new());
        let service = PackageService::builder(backend.clone())
            .policy(policy)
            .without_history()
            .build()?;

        assert_eq!(backend.get_status(true).await?.1, 0);
        let error = service
            .install(&[archive.display().to_string()], false)
            .await
            .expect_err("local package metadata must be checked by policy before installation");
        assert!(
            matches!(
                error.downcast_ref::<crate::core::security::policy::PolicyError>(),
                Some(crate::core::security::policy::PolicyError::Banned { name })
                    if name == "banned-local"
            ),
            "unexpected policy error: {error:#}"
        );
        assert_eq!(backend.get_status(true).await?.1, 0);
        service
            .install(&[allowed.display().to_string()], false)
            .await?;
        assert_eq!(backend.get_status(true).await?.1, 1);
        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial(history_ownership)]
    async fn removal_history_uses_installed_versions_even_after_catalog_retirement() -> Result<()> {
        use crate::package_managers::mock::MockPackageManager;

        let directory = tempfile::tempdir()?;
        let backend = Arc::new(MockPackageManager::new_in("debian", directory.path()));
        backend
            .db
            .add_package("fixture", "2.0", "new candidate", "main");
        std::fs::write(
            directory.path().join("mock_state_apt.json"),
            serde_json::to_vec(&serde_json::json!({
                "installed": { "fixture": "1.0", "retired": "3.2" },
                "available": { "fixture": "2.0" }
            }))?,
        )?;
        assert_eq!(
            backend
                .info("fixture")
                .await?
                .unwrap()
                .version
                .version_string(),
            "2.0"
        );
        assert!(backend.info("retired").await?.is_none());
        let history_path = directory.path().join("history.json");
        let service = PackageService::builder(backend.clone())
            .history(HistoryManager::new_in(&history_path)?)
            .build()?;
        service
            .remove(&["fixture".into(), "retired".into(), "unknown".into()])
            .await?;

        let transactions = HistoryManager::new_in(&history_path)?.load()?;
        assert_eq!(transactions.len(), 1);
        assert!(transactions[0].success);
        assert_eq!(transactions[0].transaction_type, TransactionType::Remove);
        let changes = &transactions[0].changes;
        assert_eq!(
            changes.len(),
            3,
            "every requested package must remain recorded"
        );
        assert_eq!(changes[0].name, "fixture");
        assert_eq!(changes[0].old_version.as_deref(), Some("1.0"));
        assert_eq!(changes[1].name, "retired");
        assert_eq!(changes[1].old_version.as_deref(), Some("3.2"));
        assert_eq!(changes[2].name, "unknown");
        assert!(changes[2].old_version.is_none());
        assert!(changes.iter().all(|change| change.new_version.is_none()));
        assert!(backend.list_installed().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn update_refreshes_metadata_before_listing_updates() -> Result<()> {
        let backend = Arc::new(crate::core::testing::TestPackageManager::new());
        backend.set_fail_operations(true);
        let service = PackageService::builder(backend).without_history().build()?;

        let error = service
            .update()
            .await
            .expect_err("metadata refresh failure must stop the update");
        assert!(
            error.to_string().contains("Sync operation failed"),
            "{error:#}"
        );
        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial(history_ownership)]
    async fn operation_reports_history_persistence_failure() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let history_path = directory.path().join("history.json");
        let history = HistoryManager::new_in(&history_path)?;
        std::fs::create_dir(&history_path)?;

        let backend = Arc::new(crate::core::testing::TestPackageManager::new());
        backend.add_package("example", "1.0.0", "Example package");
        let service = PackageService::builder(backend)
            .history(history)
            .policy(SecurityPolicy::default())
            .build()?;

        let error = service
            .install(&["example".to_string()], false)
            .await
            .expect_err("history persistence failure must be returned");
        assert!(error.to_string().contains("history"));
        Ok(())
    }
    #[tokio::test]
    async fn coverage17_optional_policy_never_queries_and_review_rejects_missing_subjects()
    -> Result<()> {
        struct MissingSubjects;
        impl VulnerabilitySource for MissingSubjects {
            fn assess_packages<'a>(
                &'a self,
                _packages: &'a [SecurityPackage],
                _evidence_use: crate::core::security::vulnerability::AssessmentUse,
            ) -> Pin<
                Box<
                    dyn Future<
                            Output = Result<
                                Vec<crate::core::security::vulnerability::PackageAssessment>,
                                crate::core::security::vulnerability::VulnerabilityError,
                            >,
                        > + Send
                        + 'a,
                >,
            > {
                Box::pin(async { Ok(Vec::new()) })
            }
        }
        let backend = Arc::new(crate::core::testing::TestPackageManager::new());
        let service = PackageService::builder(backend)
            .policy(SecurityPolicy::default())
            .vulnerability_source(Arc::new(MissingSubjects))
            .without_history()
            .build()?;
        let package = SecurityPackage {
            origin: SecurityOrigin::Unknown,
            name: "fixture".into(),
            version: "1".into(),
            advisory_source: None,
            architecture: None,
            description: String::new(),
            licenses: Vec::new(),
        };
        service
            .check_candidate(&service.policy, package.clone())
            .await?;
        let mut review = service.policy.clone();
        review.advisory_requirement = crate::core::security::policy::AdvisoryRequirement::Review;
        let error = service
            .check_candidate(&review, package.clone())
            .await
            .expect_err("review requires an assessment for every subject");
        assert!(error.to_string().contains("inventory differs"), "{error:#}");
        let directory = tempfile::tempdir()?;
        for distro in ["arch", "debian"] {
            let backend = Arc::new(crate::package_managers::mock::MockPackageManager::new_in(
                distro,
                directory.path().join(distro).as_path(),
            ));
            let service = PackageService::builder(backend)
                .policy(SecurityPolicy::default())
                .vulnerability_source(Arc::new(MissingSubjects))
                .without_history()
                .build()?;
            let mut fresh = SecurityPolicy {
                advisory_requirement:
                    crate::core::security::policy::AdvisoryRequirement::FreshSnapshot,
                ..SecurityPolicy::default()
            };
            let result = service.check_candidate(&fresh, package.clone()).await;
            if cfg!(feature = "arch") && distro == "arch" {
                result.expect("native Arch admission is checked on the prepared transaction");
                let mut review = fresh.clone();
                review.advisory_requirement =
                    crate::core::security::policy::AdvisoryRequirement::Review;
                let error = service
                    .check_candidate(&review, package.clone())
                    .await
                    .expect_err("explicit review must validate the preflight inventory before native consent");
                assert!(error.to_string().contains("inventory differs"), "{error:#}");
                fresh.banned_packages.push(package.name.clone());
                let error = service
                    .check_candidate(&fresh, package.clone())
                    .await
                    .expect_err("prepared admission must still enforce source policy");
                assert!(matches!(
                    error.downcast_ref::<crate::core::security::policy::PolicyError>(),
                    Some(crate::core::security::policy::PolicyError::Banned { name }) if name == "fixture"
                ));
            } else {
                let error = result.expect_err("other backends must assess every candidate now");
                assert!(error.to_string().contains("inventory differs"), "{error:#}");
            }
        }
        let mut verified = service.policy.clone();
        verified.minimum_grade = crate::core::security::SecurityGrade::Verified;
        assert!(
            service.check_candidate(&verified, package).await.is_err(),
            "unknown advisory origin cannot fabricate a Verified source grade"
        );
        Ok(())
    }

    #[tokio::test]
    async fn update_assesses_repository_origins_before_backend_mutation() -> Result<()> {
        struct CapturedSubjects(std::sync::Mutex<Vec<SecurityPackage>>);
        impl VulnerabilitySource for CapturedSubjects {
            fn assess_packages<'a>(
                &'a self,
                packages: &'a [SecurityPackage],
                _evidence_use: crate::core::security::vulnerability::AssessmentUse,
            ) -> Pin<
                Box<
                    dyn Future<
                            Output = Result<
                                Vec<crate::core::security::vulnerability::PackageAssessment>,
                                crate::core::security::vulnerability::VulnerabilityError,
                            >,
                        > + Send
                        + 'a,
                >,
            > {
                Box::pin(async move {
                    self.0
                        .lock()
                        .expect("captured subjects")
                        .extend_from_slice(packages);
                    Ok(Vec::new())
                })
            }
        }
        let directory = tempfile::tempdir()?;
        for (ordinal, (distro, repository, expected)) in [
            ("arch", "aur", SecurityOrigin::AurArchive),
            ("arch", "AuR", SecurityOrigin::AurArchive),
            ("arch", "", SecurityOrigin::Unknown),
            (
                "arch",
                "core",
                SecurityOrigin::ArchRepository {
                    repository: "core".into(),
                },
            ),
            (
                "arch",
                "Core",
                SecurityOrigin::OtherRepository {
                    repository: "Core".into(),
                },
            ),
            ("debian", "", SecurityOrigin::Unknown),
            ("debian", "main", SecurityOrigin::DistributionPackage),
        ]
        .into_iter()
        .enumerate()
        {
            let backend = Arc::new(crate::package_managers::mock::MockPackageManager::new_in(
                distro,
                directory.path().join(ordinal.to_string()).as_path(),
            ));
            backend.db.add_package(
                "fixture",
                "2.0.0",
                "Repository identity fixture",
                repository,
            );
            backend.set_installed_version("fixture", "1.0.0")?;
            backend.set_available_version("fixture", "2.0.0")?;
            let source = Arc::new(CapturedSubjects(std::sync::Mutex::new(Vec::new())));
            let service = PackageService {
                backend: backend.clone(),
                policy: SecurityPolicy {
                    advisory_requirement:
                        crate::core::security::policy::AdvisoryRequirement::Review,
                    arch_advisory_repositories: ["core".to_owned()].into(),
                    ..SecurityPolicy::default()
                },
                vulnerability_source: source.clone(),
                history: None,
                #[cfg(feature = "arch")]
                aur_client: None,
            };
            let error = service
                .update()
                .await
                .expect_err("missing assessment must stop the update");
            assert!(error.to_string().contains("inventory differs"), "{error:#}");
            {
                let captured = source.0.lock().expect("captured subjects");
                assert_eq!(captured.len(), 1);
                assert_eq!(captured[0].origin, expected, "{distro}/{repository}");
                assert_eq!(captured[0].name, "fixture");
                assert_eq!(captured[0].version, "2.0.0");
            }
            let installed = backend.list_installed().await?;
            assert_eq!(installed.len(), 1);
            assert_eq!(installed[0].name, "fixture");
            assert_eq!(installed[0].version.version_string(), "1.0.0");
        }
        Ok(())
    }

    #[cfg(feature = "arch")]
    #[tokio::test]
    async fn official_install_candidate_policy_precedes_backend_mutation() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let backend = Arc::new(crate::package_managers::mock::MockPackageManager::new_in(
            "arch",
            directory.path(),
        ));
        backend
            .db
            .add_package("banned-official", "2.0.0", "Official candidate", "core");
        let service = PackageService::builder(backend.clone())
            .policy(SecurityPolicy {
                banned_packages: vec!["banned-official".into()],
                ..SecurityPolicy::default()
            })
            .without_history()
            .build()?;
        let error = service
            .install(&["banned-official".into()], true)
            .await
            .expect_err("banned official candidate must stop before backend install");
        assert!(matches!(
            error.downcast_ref::<crate::core::security::policy::PolicyError>(),
            Some(crate::core::security::policy::PolicyError::Banned { name }) if name == "banned-official"
        ));
        assert!(backend.list_installed().await?.is_empty());
        let service = PackageService::builder(backend.clone())
            .policy(SecurityPolicy::default())
            .without_history()
            .build()?;
        service.install(&["banned-official".into()], true).await?;
        let installed = backend.list_installed().await?;
        assert_eq!(installed.len(), 1);
        assert_eq!(installed[0].name, "banned-official");
        assert_eq!(installed[0].version.version_string(), "2.0.0");
        Ok(())
    }

    #[tokio::test]
    async fn distribution_install_retains_verified_source_grade() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let backend = Arc::new(crate::package_managers::mock::MockPackageManager::new_in(
            "debian",
            directory.path(),
        ));
        backend.db.add_package(
            "distribution-fixture",
            "2.0.0",
            "Distribution candidate",
            "main",
        );
        let service = PackageService::builder(backend.clone())
            .policy(SecurityPolicy {
                minimum_grade: crate::core::security::SecurityGrade::Verified,
                ..SecurityPolicy::default()
            })
            .without_history()
            .build()?;
        service
            .install(&["distribution-fixture".into()], true)
            .await?;
        let installed = backend.list_installed().await?;
        assert_eq!(installed.len(), 1);
        assert_eq!(installed[0].name, "distribution-fixture");
        assert_eq!(installed[0].version.version_string(), "2.0.0");
        Ok(())
    }

    #[cfg(feature = "arch")]
    #[test]
    fn aur_install_assesses_source_and_refuses_before_build_or_backend_mutation() -> Result<()> {
        const TEST: &str = "core::packages::service::tests::aur_install_assesses_source_and_refuses_before_build_or_backend_mutation";
        if crate::core::testing::run_isolated_test(TEST)
            || crate::config::Settings::rerun_test_unprivileged(TEST)
        {
            return Ok(());
        }
        anyhow::ensure!(
            !crate::core::is_root(),
            "AUR fixture receiver must be unprivileged"
        );
        struct CapturedSubjects(std::sync::Mutex<Vec<SecurityPackage>>);
        impl VulnerabilitySource for CapturedSubjects {
            fn assess_packages<'a>(
                &'a self,
                packages: &'a [SecurityPackage],
                _evidence_use: crate::core::security::vulnerability::AssessmentUse,
            ) -> Pin<
                Box<
                    dyn Future<
                            Output = Result<
                                Vec<crate::core::security::vulnerability::PackageAssessment>,
                                crate::core::security::vulnerability::VulnerabilityError,
                            >,
                        > + Send
                        + 'a,
                >,
            > {
                Box::pin(async move {
                    self.0
                        .lock()
                        .expect("captured subjects")
                        .extend_from_slice(packages);
                    Ok(Vec::new())
                })
            }
        }
        let directory = tempfile::tempdir_in("/var/tmp")?;
        let cache = directory.path().join("cache");
        let config = directory.path().join("config");
        let home = directory.path().join("home");
        let data = directory.path().join("data");
        std::fs::create_dir(&home)?;
        temp_env::with_vars(
            [
                ("OMG_CACHE_DIR", Some(cache.as_os_str())),
                ("OMG_CONFIG_DIR", Some(config.as_os_str())),
                ("OMG_DATA_DIR", Some(data.as_os_str())),
                ("HOME", Some(home.as_os_str())),
                ("OMG_TEST_MODE", None),
                ("OMG_TEST_DISTRO", None),
                ("SUDO_USER", None),
                ("SUDO_HOME", None),
                ("DOAS_USER", None),
            ],
            || -> Result<()> {
                assert_eq!(crate::core::paths::cache_dir(), cache);
                assert_eq!(crate::core::paths::config_dir(), config);
                let mut settings = crate::config::Settings::default();
                settings.aur.use_metadata_archive = true;
                settings.aur.metadata_cache_ttl_secs = 3600;
                settings.save()?;
                let archive = crate::package_managers::aur_metadata::metadata_path();
                std::fs::create_dir_all(archive.parent().expect("metadata parent"))?;
                let mut gzip = flate2::write::GzEncoder::new(
                    std::fs::File::create(&archive)?,
                    flate2::Compression::default(),
                );
                let metadata = serde_json::to_vec(&serde_json::json!([
                    {"Name":"aur-fixture", "Version":"2.0-1", "Description":"AUR candidate",
                     "Maintainer":null, "NumVotes":0, "Popularity":0.0, "OutOfDate":null, "LastModified":1}
                ])).expect("serialize local AUR metadata fixture");
                std::io::Write::write_all(&mut gzip, &metadata)
                    .expect("write local AUR metadata fixture");
                gzip.finish()?;
                crate::package_managers::aur_metadata::publish_test_metadata(&archive)?;
                let index = crate::package_managers::aur_metadata::open_fresh_metadata_index(
                    std::time::Duration::from_hours(1),
                )
                .expect("read published AUR metadata")
                .expect("fresh local metadata");
                assert!(index.get("aur-fixture").is_some());
                let mut before = std::fs::read_dir(cache.join("aur"))?
                    .map(|entry| entry.map(|entry| entry.file_name()))
                    .collect::<std::io::Result<Vec<_>>>()?;
                before.sort();
                tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
                let backend = Arc::new(crate::package_managers::mock::MockPackageManager::new_in(
                    "arch", directory.path().join("backend").as_path(),
                ));
                let source = Arc::new(CapturedSubjects(std::sync::Mutex::new(Vec::new())));
                let service = PackageService::builder(backend.clone())
                    .policy(SecurityPolicy {
                        advisory_requirement: crate::core::security::policy::AdvisoryRequirement::Review,
                        ..SecurityPolicy::default()
                    })
                    .vulnerability_source(source.clone()).without_history().build()?;
                let error = service.install(&["aur-fixture".into()], true).await
                    .expect_err("missing AUR assessment must stop before build");
                assert!(error.to_string().contains("inventory differs"), "{error:#}");
                {
                    let captured = source.0.lock().expect("captured subjects");
                    assert_eq!(captured.len(), 1);
                    assert_eq!(captured[0].origin, SecurityOrigin::AurArchive);
                    assert_eq!(captured[0].name, "aur-fixture");
                    assert_eq!(captured[0].version, "2.0-1");
                }
                let service = PackageService::builder(backend.clone())
                    .policy(SecurityPolicy {allow_aur: false, ..SecurityPolicy::default()})
                    .without_history().build()?;
                let error = service.install(&["aur-fixture".into()], true).await
                    .expect_err("disabled AUR must stop before build");
                assert!(matches!(error.downcast_ref::<crate::core::security::policy::PolicyError>(),
                    Some(crate::core::security::policy::PolicyError::AurDisabled {name}) if name=="aur-fixture"));

                let archive = directory.path().join("local-fixture-1.0-1-any.pkg.tar.gz");
                let gzip = flate2::write::GzEncoder::new(
                    std::fs::File::create(&archive)?,
                    flate2::Compression::fast(),
                );
                let mut package = tar::Builder::new(gzip);
                let metadata = b"pkgname = local-fixture\npkgver = 1.0-1\narch = any\nsize = 0\n";
                let mut header = tar::Header::new_gnu();
                header.set_size(metadata.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                package.append_data(&mut header, ".PKGINFO", &metadata[..])?;
                package.into_inner()?.finish()?;

                let history_path = data.join("mixed-history.json");
                let service = PackageService::builder(backend.clone())
                    .policy(SecurityPolicy::default())
                    .history(HistoryManager::new_in(&history_path)?)
                    .build()?;
                let error = service.install(&[
                    archive.to_str().expect("UTF-8 test path").into(),
                    "aur-fixture".into(),
                ], true).await.expect_err("mock backend must refuse the archived package");
                assert!(error.to_string().contains("not found in any repository"), "{error:#}");
                let records = HistoryManager::new_in(history_path)?.load()?;
                assert_eq!(records.len(), 1);
                assert!(!records[0].success);
                let changes = &records[0].changes;
                assert_eq!(changes.len(), 2);
                assert_eq!(changes[0].name, "local-fixture");
                assert_eq!(changes[0].new_version.as_deref(), Some("1.0-1"));
                assert_eq!(changes[0].source, "local");
                assert_eq!(changes[1].name, "aur-fixture");
                assert_eq!(changes[1].new_version.as_deref(), Some("2.0-1"));
                assert_eq!(changes[1].source, "aur");
                assert!(changes.iter().all(|change| change.architecture.is_none()));
                assert!(backend.list_installed().await?.is_empty());
                Ok::<(), anyhow::Error>(())
            })?;
                let mut after = std::fs::read_dir(cache.join("aur"))?
                    .map(|entry| entry.map(|entry| entry.file_name()))
                    .collect::<std::io::Result<Vec<_>>>()?;
                after.sort();
                assert_eq!(
                    after, before,
                    "refused AUR candidate must not create build storage"
                );
                Ok(())
            },
        )
    }
}
