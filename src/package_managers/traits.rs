//! Package manager trait definition

use std::future::Future;
use std::pin::Pin;

use anyhow::Result;

use super::types::{PackageStatus, SbomPackage};
use crate::core::Package;

/// A retained observation of package inventory inputs.
/// Observation checks can perform native I/O; callers must use a blocking task.
pub trait InstalledCatalogObservation: Send + Sync {
    fn is_current(&self) -> Result<bool>;
}

/// Trait for package manager backends (object-safe for dynamic dispatch)
///
/// Uses manually desugared async methods (returning `Pin<Box<dyn Future>>`)
/// to maintain object safety for `Arc<dyn PackageManager>`.
pub trait PackageManager: Send + Sync {
    /// Get the name of this package manager
    fn name(&self) -> &'static str;

    /// Capture installed inventory state for an index publication. `None` means
    /// that this backend cannot certify installed catalog freshness cheaply.
    /// Call on a blocking task, as native database observation may perform I/O.
    fn installed_catalog_observation(
        &self,
    ) -> Result<Option<std::sync::Arc<dyn InstalledCatalogObservation>>> {
        Ok(None)
    }

    /// Observe the inputs used by the search index before building it.
    /// Backends may include repository metadata. Installed status remains
    /// scoped to the installed observation. Call on a blocking task.
    fn package_index_observation(
        &self,
    ) -> Result<Option<std::sync::Arc<dyn InstalledCatalogObservation>>> {
        self.installed_catalog_observation()
    }

    /// Preserve installed package identities for security exports. Backends
    /// override this when their ordinary package view omits native identity.
    fn security_inventory(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<super::types::SecurityPackage>>> + Send + '_>> {
        Box::pin(async move {
            Ok(self
                .list_installed()
                .await?
                .into_iter()
                .map(|package| super::types::SecurityPackage {
                    origin: crate::package_managers::types::SecurityOrigin::Unknown,
                    name: package.name,
                    version: package.version.to_string(),
                    advisory_source: None,
                    architecture: None,
                    description: package.description,
                    licenses: Vec::new(),
                })
                .collect())
        })
    }

    /// Collect installed software and its native SBOM metadata.
    fn sbom_inventory(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SbomPackage>>> + Send + '_>> {
        Box::pin(async {
            Ok(self
                .security_inventory()
                .await?
                .into_iter()
                .map(SbomPackage::from)
                .collect())
        })
    }

    /// Native advisory applicability, when supported. Failures are authoritative:
    /// callers must not replace a failed native scan with a narrower source.
    fn security_audit(
        &self,
    ) -> Option<
        Pin<
            Box<
                dyn Future<Output = Result<crate::core::security::scan::SecurityAuditResult>>
                    + Send
                    + '_,
            >,
        >,
    > {
        None
    }

    /// Search for packages
    fn search(
        &self,
        query: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Package>>> + Send + '_>>;

    /// Search while another renderer owns the terminal.
    fn search_quietly(
        &self,
        query: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Package>>> + Send + '_>> {
        self.search(query)
    }

    /// List every package available to a persistent search index.
    ///
    /// Backends whose normal empty-query search is complete can use this
    /// default. Backends that cap interactive search results must override it.
    /// Fedora supplies installed rows before repository rows for the same
    /// identity so the index can keep the installed display and search both.
    fn package_index(&self) -> Pin<Box<dyn Future<Output = Result<Vec<Package>>> + Send + '_>> {
        self.search("")
    }

    /// Execute with native transaction evidence when the backend supports it.
    /// The caller owns the history destination; `None` disables OMG recording.
    /// Returning `None` leaves the operation and recording to the caller.
    fn transact_with_history<'a>(
        &'a self,
        _kind: crate::core::history::TransactionType,
        _packages: &'a [String],
        _history: Option<&'a crate::core::history::HistoryManager>,
    ) -> Option<Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>> {
        None
    }

    /// Execute a system update from already-synchronized repository metadata.
    /// Package payload downloads are still allowed. Backends that cannot bind
    /// native history to this mode leave execution to [`Self::update`].
    fn transact_cached_update_with_history<'a>(
        &'a self,
        _history: Option<&'a crate::core::history::HistoryManager>,
    ) -> Option<Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>> {
        None
    }

    /// Install packages
    fn install(&self, packages: &[String])
    -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;

    /// Remove packages
    fn remove(&self, packages: &[String]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;

    /// Resolve the complete native removal set without committing a transaction.
    /// Unsupported backends refuse instead of guessing from requested operands.
    fn removal_plan<'a>(
        &'a self,
        _packages: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<super::types::RemovalPackage>>> + Send + 'a>> {
        Box::pin(async move {
            anyhow::bail!(
                "{} cannot simulate a complete native removal transaction",
                self.name()
            )
        })
    }

    /// Update all packages (upgrade system)
    fn update(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;

    /// Synchronize package databases (refresh metadata)
    fn sync(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;

    /// Get information about a package
    fn info(
        &self,
        package: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Package>>> + Send + '_>>;

    /// List installed packages
    fn list_installed(&self) -> Pin<Box<dyn Future<Output = Result<Vec<Package>>> + Send + '_>>;

    /// Get system status (total, explicit, orphans, updates)
    fn get_status(
        &self,
        fast: bool,
    ) -> Pin<Box<dyn Future<Output = Result<(usize, usize, usize, usize)>> + Send + '_>>;

    /// Get package counts with explicit provenance for skipped maintenance checks.
    fn get_status_details(
        &self,
        fast: bool,
    ) -> Pin<Box<dyn Future<Output = Result<PackageStatus>> + Send + '_>> {
        Box::pin(async move { self.get_status(fast).await.map(PackageStatus::from) })
    }

    /// List explicitly installed package names
    fn list_explicit(&self) -> Pin<Box<dyn Future<Output = Result<Vec<String>>> + Send + '_>>;

    /// List available updates
    fn list_updates(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Vec<crate::package_managers::types::UpdateInfo>>>
                + Send
                + '_,
        >,
    >;

    /// Check if a specific package is installed
    fn is_installed(
        &self,
        package: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + '_>>;
}
