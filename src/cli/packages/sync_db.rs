//! Database sync functionality for packages

use crate::package_managers::get_package_manager;
use crate::package_managers::{Backend, resolve_backend};
use anyhow::Result;

/// Synchronize package databases via the active system package manager
pub async fn sync_databases() -> Result<()> {
    let backend = resolve_backend()?;
    let pm = get_package_manager()?;
    if !sync_before_refresh(pm.sync(), backend).await? {
        return Ok(());
    }

    #[cfg(feature = "arch")]
    if backend == Backend::Arch {
        let aur_start = std::time::Instant::now();
        match crate::config::Settings::load() {
            Ok(settings) => {
                if let Err(error) = crate::package_managers::aur_metadata::sync_aur_metadata(
                    crate::core::http::download_client(),
                    &settings,
                    false,
                )
                .await
                {
                    tracing::warn!("Failed to sync AUR metadata: {error}");
                } else {
                    let aur_elapsed = aur_start.elapsed();
                    if aur_elapsed >= std::time::Duration::from_millis(200) {
                        crate::cli::modern_ui::print_finished_step(
                            "AUR index",
                            &format!("in {:.2}s", aur_elapsed.as_secs_f64()),
                        );
                    }
                }
            }
            Err(error) => {
                tracing::error!("Failed to load OMG settings for AUR metadata sync: {error}");
            }
        }
    }

    #[cfg(unix)]
    crate::core::client::refresh_daemon_after_catalog_write().await?;

    Ok(())
}

async fn sync_before_refresh(
    sync: impl std::future::Future<Output = Result<()>>,
    backend: Backend,
) -> Result<bool> {
    sync.await?;
    Ok(backend != Backend::Mock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package_managers::PackageManager;

    #[tokio::test]
    async fn mock_sync_finishes_without_native_refresh() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let manager =
            crate::package_managers::mock::MockPackageManager::new_in("arch", directory.path());
        assert!(!sync_before_refresh(manager.sync(), Backend::Mock).await?);
        assert_eq!(std::fs::read_dir(directory.path())?.count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn sync_failure_is_preserved_before_refresh_decision() {
        let error = sync_before_refresh(
            async { anyhow::bail!("fixture sync failed") },
            Backend::Mock,
        )
        .await
        .expect_err("mock selection must not swallow sync failure");
        assert_eq!(error.to_string(), "fixture sync failed");
    }

    #[tokio::test]
    async fn successful_native_sync_still_requires_refresh() -> Result<()> {
        assert!(sync_before_refresh(async { Ok(()) }, Backend::Arch).await?);
        Ok(())
    }
}
