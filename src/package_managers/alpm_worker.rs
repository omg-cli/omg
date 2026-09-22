use std::sync::mpsc as std_mpsc;
use std::thread;

use anyhow::{Context, Result};
use tokio::sync::oneshot;

use super::alpm_ops::{
    collect_updates, configure_package_filters, configure_signature_policy, get_pkg_info_from_db,
    register_configured_syncdbs,
};
use super::pacman_db::AlpmCatalogEpoch;
use super::types::{PackageInfo, UpdateInfo};
use crate::core::paths;

struct LoadedAlpm {
    handle: alpm::Alpm,
    epoch: AlpmCatalogEpoch,
}

enum AlpmRequest {
    Info(String, oneshot::Sender<Result<Option<PackageInfo>>>),
    ListUpdates(oneshot::Sender<Result<Vec<UpdateInfo>>>),
}

pub struct AlpmWorker {
    tx: Option<tokio::sync::mpsc::Sender<AlpmRequest>>,
    thread: Option<thread::JoinHandle<()>>,
}

const ALPM_REQUEST_QUEUE_CAPACITY: usize = 128;

fn request_channel() -> (
    tokio::sync::mpsc::Sender<AlpmRequest>,
    tokio::sync::mpsc::Receiver<AlpmRequest>,
) {
    tokio::sync::mpsc::channel(ALPM_REQUEST_QUEUE_CAPACITY)
}

fn initialize_alpm_worker() -> Result<alpm::Alpm> {
    let root = paths::pacman_root_result()?.to_string_lossy().into_owned();
    let db_path = paths::pacman_db_dir_result()?
        .to_string_lossy()
        .into_owned();
    let mut alpm = alpm::Alpm::new(root, db_path).context("Failed to initialize ALPM worker")?;
    let config = crate::core::pacman_conf::PacmanConfig::parse(paths::pacman_conf_path())
        .context("Failed to load pacman.conf for ALPM worker")?;
    configure_signature_policy(&alpm, &config)?;
    register_configured_syncdbs(&alpm, &config)?;
    configure_package_filters(&mut alpm, &config)?;
    Ok(alpm)
}

fn load_alpm_worker() -> Result<LoadedAlpm> {
    let (handle, epoch) =
        AlpmCatalogEpoch::load_stable(AlpmCatalogEpoch::observe, initialize_alpm_worker)
            .context("Failed to load a stable ALPM worker snapshot")?;
    Ok(LoadedAlpm { handle, epoch })
}

fn refresh_if_catalog_changed(loaded: &mut LoadedAlpm) -> Result<()> {
    let disk = AlpmCatalogEpoch::observe().context("Failed to observe ALPM catalog epoch")?;
    if disk != loaded.epoch {
        *loaded = load_alpm_worker()?;
    }
    Ok(())
}

impl AlpmWorker {
    pub fn new() -> Result<Self> {
        let (tx, mut rx) = request_channel();
        let (ready_tx, ready_rx) = std_mpsc::sync_channel(1);

        let thread = thread::spawn(move || {
            let mut loaded = match load_alpm_worker() {
                Ok(loaded) => loaded,
                Err(error) => {
                    let message = format!("{error:#}");
                    tracing::error!("Failed to initialize ALPM worker: {message}");
                    let _ = ready_tx.send(Err(message));
                    return;
                }
            };

            tracing::info!(
                "ALPM hot worker ready ({} repos)",
                loaded.handle.syncdbs().len()
            );
            if ready_tx.send(Ok(())).is_err() {
                return;
            }

            while let Some(req) = rx.blocking_recv() {
                match req {
                    AlpmRequest::Info(name, reply) => {
                        let res = match refresh_if_catalog_changed(&mut loaded) {
                            Ok(()) => get_pkg_info_from_db(&loaded.handle, &name),
                            Err(error) => Err(error),
                        };
                        let _ = reply.send(res);
                    }
                    AlpmRequest::ListUpdates(reply) => {
                        let res = match refresh_if_catalog_changed(&mut loaded) {
                            Ok(()) => Ok(collect_updates(&loaded.handle)),
                            Err(error) => Err(error),
                        };
                        let _ = reply.send(res);
                    }
                }
            }
            tracing::debug!("ALPM worker shutting down");
        });

        ready_rx
            .recv()
            .context("ALPM worker exited during initialization")?
            .map_err(anyhow::Error::msg)?;
        Ok(Self {
            tx: Some(tx),
            thread: Some(thread),
        })
    }

    pub async fn get_info(&self, name: String) -> Result<Option<PackageInfo>> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .as_ref()
            .context("ALPM worker is shutting down")?
            .send(AlpmRequest::Info(name, tx))
            .await
            .context("ALPM worker request queue closed")?;

        rx.await
            .context("ALPM worker disconnected (it may have failed to initialize)")?
    }

    pub async fn list_updates(&self) -> Result<Vec<UpdateInfo>> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .as_ref()
            .context("ALPM worker is shutting down")?
            .send(AlpmRequest::ListUpdates(tx))
            .await
            .context("ALPM worker request queue closed")?;

        rx.await
            .context("ALPM worker disconnected (it may have failed to initialize)")?
    }
}

impl Drop for AlpmWorker {
    fn drop(&mut self) {
        // Closing the last request sender lets the owner thread leave
        // blocking_recv and destroy its native libalpm handle. Join before
        // process/runtime teardown so native destruction cannot race exit.
        self.tx.take();
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            tracing::error!("ALPM worker panicked during shutdown");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AlpmRequest, AlpmWorker, request_channel};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::oneshot;

    #[test]
    fn drop_waits_for_the_native_owner_thread() {
        let (tx, mut rx) = request_channel();
        let exited = Arc::new(AtomicBool::new(false));
        let exited_on_thread = Arc::clone(&exited);
        let thread = std::thread::spawn(move || {
            while rx.blocking_recv().is_some() {}
            std::thread::sleep(std::time::Duration::from_millis(25));
            exited_on_thread.store(true, Ordering::Release);
        });
        let worker = AlpmWorker {
            tx: Some(tx),
            thread: Some(thread),
        };

        drop(worker);

        assert!(
            exited.load(Ordering::Acquire),
            "drop returned before the native-owner thread exited"
        );
    }

    #[test]
    fn request_queue_applies_backpressure_at_its_capacity() {
        let (tx, _rx) = request_channel();
        for index in 0..128 {
            let (reply, _response) = oneshot::channel();
            tx.try_send(AlpmRequest::Info(index.to_string(), reply))
                .expect("request within the daemon connection cap must fit");
        }
        let (reply, _response) = oneshot::channel();
        assert!(
            matches!(
                tx.try_send(AlpmRequest::Info("overflow".to_owned(), reply)),
                Err(tokio::sync::mpsc::error::TrySendError::Full(_))
            ),
            "the worker queue must not grow beyond the daemon connection cap"
        );
    }

    #[test]
    #[serial_test::serial]
    fn initialization_errors_are_returned_to_the_caller() {
        if crate::core::is_root() {
            // Elevated processes ignore OMG_PACMAN_* overrides, so this
            // fixture test only applies to unprivileged runs.
            eprintln!("skipped: elevated processes ignore caller path overrides");
            return;
        }
        let directory = tempfile::tempdir().expect("temporary ALPM paths");
        let database = directory.path().join("db");
        std::fs::create_dir(&database).expect("database directory");
        let config = directory.path().join("pacman.conf");
        std::fs::write(
            &config,
            "[options]\nSigLevel = PackageSometimes\n\n[core]\nServer = https://example.invalid\n",
        )
        .expect("pacman config");

        temp_env::with_vars(
            [
                ("OMG_PACMAN_DB_DIR", Some(database.as_os_str())),
                ("OMG_PACMAN_CONF", Some(config.as_os_str())),
            ],
            || {
                let Err(error) = AlpmWorker::new() else {
                    panic!("invalid worker policy must fail");
                };
                assert!(error.to_string().contains("PackageSometimes"), "{error:#}");
            },
        );
    }
}
