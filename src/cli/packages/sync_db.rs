//! Database sync functionality for packages

use crate::package_managers::get_package_manager;
#[cfg(feature = "arch")]
use crate::package_managers::{Backend, resolve_backend};
use anyhow::Result;

/// Synchronize package databases via the active system package manager
pub async fn sync_databases() -> Result<()> {
    #[cfg(feature = "arch")]
    let backend = resolve_backend()?;
    let pm = get_package_manager()?;
    pm.sync().await?;

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
