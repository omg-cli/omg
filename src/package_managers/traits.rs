//! Package manager trait definition

use std::future::Future;
use std::pin::Pin;

use anyhow::Result;

use crate::core::Package;

/// Trait for package manager backends (object-safe for dynamic dispatch)
///
/// Uses manually desugared async methods (returning `Pin<Box<dyn Future>>`)
/// to maintain object safety for `Arc<dyn PackageManager>`.
pub trait PackageManager: Send + Sync {
    /// Get the name of this package manager
    fn name(&self) -> &'static str;

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
                    name: package.name,
                    version: package.version.to_string(),
                    architecture: None,
                    description: package.description,
                    licenses: Vec::new(),
                })
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

    /// List every package available to a persistent search index.
    ///
    /// Backends whose normal empty-query search is complete can use this
    /// default. Backends that cap interactive search results must override it.
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

    /// Install packages
    fn install(&self, packages: &[String])
    -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;

    /// Remove packages
    fn remove(&self, packages: &[String]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;

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
