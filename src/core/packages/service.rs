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
        let prepared_arch_admission = policy.advisory_requirement
            == AdvisoryRequirement::FreshSnapshot
            && cfg!(feature = "arch")
            && self.backend.name() == "pacman";
        let assessments = if policy.advisory_requirement == AdvisoryRequirement::Optional
            || prepared_arch_admission
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
            policy.check_sources_and_findings(&assessments)?;
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
            if self.policy.arch_advisory_repositories.contains(repository) {
                SecurityOrigin::ArchRepository {
                    repository: repository.to_owned(),
                }
            } else {
                SecurityOrigin::OtherRepository {
                    repository: repository.to_owned(),
                }
            }
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

    struct CleanVulnerabilitySource;

    impl VulnerabilitySource for CleanVulnerabilitySource {
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
                Ok(packages
                    .iter()
                    .cloned()
                    .map(
                        |package| crate::core::security::vulnerability::PackageAssessment {
                            package,
                            coverage:
                                crate::core::security::vulnerability::PackageCoverage::Assessed {
                                    provenance:
                                        crate::core::security::scan::AdvisoryProvenance::Osv {
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
            .vulnerability_source(Arc::new(CleanVulnerabilitySource))
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
            .vulnerability_source(Arc::new(CleanVulnerabilitySource))
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
        let mut verified = service.policy.clone();
        verified.minimum_grade = crate::core::security::SecurityGrade::Verified;
        assert!(
            service.check_candidate(&verified, package).await.is_err(),
            "unknown advisory origin cannot fabricate a Verified source grade"
        );
        Ok(())
    }
}
