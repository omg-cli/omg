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
                            Ok(()) => collect_updates(&loaded.handle),
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
pub(crate) fn worker_with_shutdown_gate(
    started: std_mpsc::Sender<()>,
    shutdown_started: std::sync::Arc<tokio::sync::Notify>,
    release: std_mpsc::Receiver<()>,
) -> AlpmWorker {
    let (tx, mut rx) = request_channel();
    let thread = thread::spawn(move || {
        while rx.blocking_recv().is_some() {}
        started.send(()).expect("fixture controller is alive");
        shutdown_started.notify_one();
        release.recv().expect("fixture releases native shutdown");
    });
    AlpmWorker {
        tx: Some(tx),
        thread: Some(thread),
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
    fn list_updates_refreshes_sync_config_and_local_catalogs() -> anyhow::Result<()> {
        const NAME: &str = "package_managers::alpm_worker::tests::list_updates_refreshes_sync_config_and_local_catalogs";
        if crate::config::Settings::rerun_test_unprivileged(NAME)
            || crate::core::testing::run_isolated_test(NAME)
        {
            return Ok(());
        }
        assert!(!crate::core::is_root(), "fixture must run as ordinary user");
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("root");
        let database = root.join("var/lib/pacman");
        let local = database.join("local");
        let sync = database.join("sync");
        std::fs::create_dir_all(local.join("widget-1-1"))?;
        std::fs::create_dir(&sync)?;
        std::fs::write(local.join("ALPM_DB_VERSION"), "9\n")?;
        let local_desc =
            |version: &str| format!("%NAME%\nwidget\n\n%VERSION%\n{version}\n\n%REASON%\n0\n\n");
        std::fs::write(local.join("widget-1-1/desc"), local_desc("1-1"))?;
        let write_sync = |version: &str| -> anyhow::Result<()> {
            let content = format!("%NAME%\nwidget\n\n%VERSION%\n{version}\n\n%ARCH%\nx86_64\n\n");
            let encoder = flate2::write::GzEncoder::new(
                std::fs::File::create(sync.join("core.db.next"))?,
                flate2::Compression::fast(),
            );
            let mut archive = tar::Builder::new(encoder);
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(
                    &mut header,
                    format!("widget-{version}/desc"),
                    content.as_bytes(),
                )
                .expect("private widget sync record is writable");
            archive.into_inner()?.finish()?;
            std::fs::rename(sync.join("core.db.next"), sync.join("core.db"))?;
            Ok(())
        };
        write_sync("2-1")?;
        let config = directory.path().join("pacman.conf");
        let configuration = "[options]\nSigLevel = Never\nArchitecture = x86_64\n[core]\n";
        std::fs::write(&config, configuration)?;
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                crate::core::paths::reset_test_overrides();
            }
        }
        let _restore = Restore;
        crate::core::paths::set_test_overrides(Some(root), Some(database));
        temp_env::with_vars(
            [
                ("OMG_TEST_MODE", None),
                ("OMG_CONFIG_DIR", Some(directory.path().as_os_str())),
                ("OMG_PACMAN_CONF", Some(config.as_os_str())),
                ("OMG_PACMAN_LOCAL_DIR", None),
                ("OMG_PACMAN_SYNC_DIR", None),
            ],
            || -> anyhow::Result<()> {
                let worker = AlpmWorker::new()?;
                let assert_update = |old_version: &str, new_version: &str| -> anyhow::Result<()> {
                    let updates = futures::executor::block_on(worker.list_updates())?;
                    assert_eq!(updates.len(), 1, "expected the private widget update");
                    let update = &updates[0];
                    assert_eq!(
                        (
                            update.name.as_str(),
                            update.old_version.as_str(),
                            update.new_version.as_str(),
                            update.repo.as_str(),
                        ),
                        ("widget", old_version, new_version, "core")
                    );
                    Ok(())
                };
                assert_update("1-1", "2-1")?;
                assert_update("1-1", "2-1")?;

                write_sync("3-1")?;
                assert_update("1-1", "3-1")?;

                std::fs::write(
                    &config,
                    "[options]\nSigLevel = Never\nArchitecture = x86_64\nIgnorePkg = widget\n[core]\n",
                )
                .expect("private ignore-package configuration is writable");
                assert!(futures::executor::block_on(worker.list_updates())?.is_empty());
                std::fs::write(&config, configuration)?;
                assert_update("1-1", "3-1")?;

                std::fs::rename(local.join("widget-1-1"), local.join("widget-2-1"))?;
                std::fs::write(local.join("widget-2-1/desc"), local_desc("2-1"))?;
                assert_update("2-1", "3-1")?;

                std::fs::rename(local.join("widget-2-1"), local.join("widget-3-1"))?;
                std::fs::write(local.join("widget-3-1/desc"), local_desc("3-1"))?;
                assert!(futures::executor::block_on(worker.list_updates())?.is_empty());
                Ok(())
            },
        )
    }

    #[test]
    #[serial_test::serial]
    fn initialization_errors_are_returned_to_the_caller() {
        const NAME: &str = "package_managers::alpm_worker::tests::initialization_errors_are_returned_to_the_caller";
        if crate::config::Settings::rerun_test_unprivileged(NAME) {
            return;
        }
        if crate::core::testing::run_isolated_test(NAME) {
            return;
        }
        assert!(!crate::core::is_root(), "fixture must run as ordinary user");
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
                let error = AlpmWorker::new()
                    .err()
                    .expect("invalid worker policy must fail");
                assert!(error.to_string().contains("PackageSometimes"), "{error:#}");
            },
        );
    }
}
