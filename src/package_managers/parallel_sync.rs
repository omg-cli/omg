//! Parallel package-database synchronization with bounded mirror selection.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client;
use std::os::unix::fs::PermissionsExt;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

use crate::cli::progress::{Accent, Outcome, ProgressTask, TaskKind, TaskSpec};
use crate::core::{http::download_client, paths};

fn begin_same_dir_temp(dest: &Path) -> Result<(std::fs::File, tempfile::TempPath)> {
    let parent = dest.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("Failed to create download directory: {}", parent.display()))?;
    tempfile::Builder::new()
        .prefix(".download-")
        .tempfile_in(parent)
        .with_context(|| {
            format!(
                "Failed to create temporary download in {}",
                parent.display()
            )
        })
        .map(tempfile::NamedTempFile::into_parts)
}

async fn persist_same_dir_temp(
    mut file: File,
    temporary_path: tempfile::TempPath,
    dest: &Path,
) -> Result<()> {
    file.flush().await.context("Failed to flush download")?;
    file.sync_all().await.context("Failed to sync download")?;
    drop(file);
    temporary_path
        .persist(dest)
        .map_err(|error| error.error)
        .with_context(|| format!("Failed to persist download at {}", dest.display()))?;
    crate::core::safe_ops::sync_parent_directory(dest.to_path_buf()).await?;
    Ok(())
}

/// Build the URL for a database file
fn build_db_url(mirror_template: &str, repo: &str) -> String {
    mirror_template
        .replace("$repo", repo)
        .replace("$arch", std::env::consts::ARCH)
        + "/"
        + repo
        + ".db"
}

fn build_signature_url(database_url: &str) -> String {
    format!("{database_url}.sig")
}

const MAX_RETRIES: u32 = 3;
const INITIAL_BACKOFF_MS: u64 = 100;
const MAX_SYNC_DB_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SYNC_SIGNATURE_BYTES: u64 = 1024 * 1024;
const MIRROR_RACE_TIMEOUT_MS: u64 = 2000;
const MAX_MIRRORS_PER_REPO: usize = 5;
const MAX_PARALLEL_REPO_SYNCS: usize = 4;
async fn race_mirrors(client: &Client, urls: &[String]) -> Option<usize> {
    use futures::future::select_all;

    if urls.is_empty() {
        return None;
    }
    if urls.len() == 1 {
        return Some(0);
    }

    let futures: Vec<_> = urls
        .iter()
        .enumerate()
        .map(|(idx, url)| {
            let client = client.clone();
            let url = url.clone();
            Box::pin(async move {
                let result = tokio::time::timeout(
                    Duration::from_millis(MIRROR_RACE_TIMEOUT_MS),
                    client.head(&url).send(),
                )
                .await;
                match result {
                    Ok(Ok(resp))
                        if resp.status().is_success()
                            || resp.status() == reqwest::StatusCode::NOT_MODIFIED =>
                    {
                        Some(idx)
                    }
                    _ => None,
                }
            })
        })
        .collect();

    let mut remaining = futures;
    while !remaining.is_empty() {
        let (result, _idx, rest) = select_all(remaining).await;
        if let Some(winner_idx) = result {
            return Some(winner_idx);
        }
        remaining = rest;
    }

    Some(0)
}

async fn download_response_to_dest(
    mut response: reqwest::Response,
    dest: &Path,
    byte_limit: u64,
    artifact: &str,
) -> Result<()> {
    if let Some(length) = response.content_length() {
        anyhow::ensure!(
            length <= byte_limit,
            "{artifact} declares {length} bytes, exceeding the {byte_limit}-byte limit"
        );
    }

    let (std_file, temporary_path) = begin_same_dir_temp(dest)?;
    let mut file = File::from_std(std_file);
    let mut downloaded = 0_u64;
    while let Some(chunk) = response.chunk().await? {
        downloaded = downloaded
            .checked_add(u64::try_from(chunk.len()).context("Download chunk is too large")?)
            .with_context(|| format!("{artifact} byte count overflowed"))?;
        anyhow::ensure!(
            downloaded <= byte_limit,
            "{artifact} exceeded the {byte_limit}-byte limit"
        );
        file.write_all(&chunk)
            .await
            .context("Write error during download")?;
    }
    persist_same_dir_temp(file, temporary_path, dest).await
}

async fn download_database_signature(
    client: &Client,
    database_url: &str,
    staged_signature: &Path,
    live_signature: &Path,
    siglevel: alpm::SigLevel,
) -> Result<()> {
    match tokio::fs::remove_file(staged_signature).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("Failed to clear a staged database signature"),
    }
    if !siglevel.contains(alpm::SigLevel::DATABASE) {
        return Ok(());
    }

    let signature_url = build_signature_url(database_url);
    let safe_url = crate::core::http::redact_url(&signature_url);
    let response = client
        .get(&signature_url)
        .send()
        .await
        .with_context(|| format!("Failed to download database signature from {safe_url}"))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND
        && siglevel.contains(alpm::SigLevel::DATABASE_OPTIONAL)
    {
        // `DatabaseOptional` allows an unsigned database, but it must never
        // let a mirror *downgrade* a repository that already carries a
        // verified signature: a mirror that simply stops serving the .sig
        // would otherwise be able to strip it and publish an unauthenticated
        // database (csf sync signature-downgrade class). Treating it as a
        // mirror failure makes the retry loop try the next mirror, and fails
        // closed when every mirror omits the signature.
        anyhow::ensure!(
            !live_signature.exists(),
            "Mirror {safe_url} served no database signature, but {} already exists; \
             refusing to downgrade this repository to an unsigned database. \
             Fix the mirror, or delete that signature file to accept unsigned databases.",
            live_signature.display()
        );
        return Ok(());
    }
    anyhow::ensure!(
        response.status().is_success(),
        "HTTP {} while downloading database signature from {safe_url}",
        response.status()
    );
    download_response_to_dest(
        response,
        staged_signature,
        MAX_SYNC_SIGNATURE_BYTES,
        "Package database signature",
    )
    .await
}

async fn download_db(
    client: &Client,
    urls: Vec<String>,
    staged_dest: &Path,
    staged_signature: &Path,
    live_dest: &Path,
    siglevel: alpm::SigLevel,
    task: &ProgressTask,
) -> Result<()> {
    // The live signature path is the live database path with `.sig` appended,
    // matching the `signature_destination` naming used when staging.
    let live_signature = {
        let mut path = live_dest.as_os_str().to_os_string();
        path.push(".sig");
        PathBuf::from(path)
    };

    let existing_mtime = if live_dest.exists() {
        tokio::fs::metadata(live_dest)
            .await
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .map(|d| httpdate::fmt_http_date(std::time::UNIX_EPOCH + d))
            })
    } else {
        None
    };

    let urls = if existing_mtime.is_some() || urls.len() <= 1 {
        urls
    } else {
        task.set_message("racing mirrors...");
        if let Some(fastest_idx) = race_mirrors(client, &urls).await {
            let mut reordered = Vec::with_capacity(urls.len());
            reordered.push(urls[fastest_idx].clone());
            for (i, url) in urls.iter().enumerate() {
                if i != fastest_idx {
                    reordered.push(url.clone());
                }
            }
            reordered
        } else {
            urls
        }
    };

    let mut last_error = None;

    for (mirror_idx, url) in urls.iter().enumerate() {
        let safe_url = crate::core::http::redact_url(url);
        if mirror_idx > 0 {
            task.set_message(&format!("mirror {}", mirror_idx + 1));
        }

        for retry in 0..MAX_RETRIES {
            if retry > 0 {
                let backoff = crate::core::http::retry_backoff(
                    Duration::from_millis(INITIAL_BACKOFF_MS),
                    retry - 1,
                );
                task.set_message(&format!("retry {retry}"));
                tokio::time::sleep(backoff).await;
            }

            let mut req = client.get(url);
            if let Some(ref mtime) = existing_mtime {
                req = req.header(reqwest::header::IF_MODIFIED_SINCE, mtime);
            }

            let response = match req.send().await {
                Ok(resp) => resp,
                Err(e) => {
                    last_error = Some(anyhow::anyhow!("Failed to connect to {safe_url}: {e}"));
                    if crate::core::http::is_retryable_error(&e) {
                        continue;
                    }
                    break;
                }
            };

            if response.status() == reqwest::StatusCode::NOT_MODIFIED {
                tokio::fs::copy(live_dest, staged_dest)
                    .await
                    .with_context(|| {
                        format!("Failed to stage unchanged database {}", live_dest.display())
                    })?;
                match download_database_signature(
                    client,
                    url,
                    staged_signature,
                    &live_signature,
                    siglevel,
                )
                .await
                {
                    Ok(()) => {
                        task.finish(Outcome::Done);
                        return Ok(());
                    }
                    Err(error) => {
                        last_error = Some(error);
                        continue;
                    }
                }
            }

            if crate::core::http::is_retryable_status(response.status()) {
                last_error = Some(anyhow::anyhow!("HTTP {}: {safe_url}", response.status()));
                continue;
            }

            if !response.status().is_success() {
                last_error = Some(anyhow::anyhow!("HTTP {}: {safe_url}", response.status()));
                break;
            }

            let total_size = response.content_length().unwrap_or(0);
            if total_size > 0 {
                task.set_total(Some(total_size));
            }

            if let Err(error) = download_response_to_dest(
                response,
                staged_dest,
                MAX_SYNC_DB_BYTES,
                "Package database",
            )
            .await
            {
                last_error = Some(error);
                continue;
            }
            if let Err(error) = download_database_signature(
                client,
                url,
                staged_signature,
                &live_signature,
                siglevel,
            )
            .await
            {
                last_error = Some(error);
                continue;
            }

            task.finish(Outcome::Done);
            return Ok(());
        }
    }

    task.finish(Outcome::Failed);
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("No mirrors available")))
}

struct StagedFile {
    staged: PathBuf,
    destination: PathBuf,
    publish: bool,
}

struct DatabasePublication {
    staged: PathBuf,
    destination: PathBuf,
    publish: bool,
    backup: Option<PathBuf>,
    published: bool,
}

fn rollback_database_publication(
    publications: &mut [DatabasePublication],
    staging: &mut tempfile::TempDir,
) -> Vec<String> {
    let mut errors = Vec::new();
    for publication in publications.iter_mut().rev() {
        if publication.published && publication.publish {
            let result = if publication.backup.is_some() {
                rustix::fs::linkat(
                    rustix::fs::CWD,
                    &publication.destination,
                    rustix::fs::CWD,
                    &publication.staged,
                    rustix::fs::AtFlags::empty(),
                )
                .map_err(std::io::Error::from)
            } else {
                std::fs::rename(&publication.destination, &publication.staged)
            };
            if let Err(error) = result {
                errors.push(format!(
                    "failed to withdraw {}: {error}",
                    publication.destination.display()
                ));
            }
        }
        if let Some(backup) = &publication.backup
            && let Err(error) = std::fs::rename(backup, &publication.destination)
        {
            errors.push(format!(
                "failed to restore {}: {error}",
                publication.destination.display()
            ));
        }
    }
    for publication in publications.iter() {
        if (publication.backup.is_some() || (publication.published && publication.publish))
            && let Err(error) =
                crate::core::safe_ops::sync_parent_directory_sync(&publication.destination)
        {
            errors.push(format!(
                "failed to sync rollback for {}: {error}",
                publication.destination.display()
            ));
        }
    }
    if !errors.is_empty() {
        staging.disable_cleanup(true);
        errors.push(format!(
            "Recovery files retained at {}",
            staging.path().display()
        ));
    }
    errors
}

#[cfg(test)]
fn commit_staged_databases(
    databases: &[(PathBuf, PathBuf)],
    failed_downloads: usize,
    staging: &mut tempfile::TempDir,
) -> Result<()> {
    let files = databases
        .iter()
        .map(|(staged, destination)| StagedFile {
            staged: staged.clone(),
            destination: destination.clone(),
            publish: true,
        })
        .collect::<Vec<_>>();
    let database_root = databases
        .first()
        .expect("nonempty database fixture")
        .1
        .parent()
        .expect("database fixture parent");
    commit_staged_files(&files, failed_downloads, database_root, staging)
}

fn commit_staged_files(
    files: &[StagedFile],
    failed_downloads: usize,
    database_root: &Path,
    staging: &mut tempfile::TempDir,
) -> Result<()> {
    anyhow::ensure!(
        failed_downloads == 0,
        "Failed to sync {failed_downloads} database(s); live databases were left unchanged"
    );

    let root = paths::pacman_root_result()?;
    let mut alpm = alpm::Alpm::new(
        root.to_str().context("Pacman root must be valid UTF-8")?,
        database_root
            .to_str()
            .context("Pacman database path must be valid UTF-8")?,
    )
    .context("Failed to initialize package database writer")?;
    crate::package_managers::alpm_ops::check_database_lock(database_root)?;
    alpm.trans_init(alpm::TransFlag::empty()).with_context(|| {
        format!(
            "Failed to acquire package database lock in {}",
            database_root.display()
        )
    })?;
    let mut publications = files
        .iter()
        .map(|file| DatabasePublication {
            staged: file.staged.clone(),
            destination: file.destination.clone(),
            publish: file.publish,
            backup: None,
            published: false,
        })
        .collect::<Vec<_>>();

    for publication in &publications {
        if !publication.publish {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&publication.staged)
            .with_context(|| format!("Missing staged database {}", publication.staged.display()))?;
        anyhow::ensure!(
            metadata.file_type().is_file(),
            "Staged database is not a regular file: {}",
            publication.staged.display()
        );
        // tempfile stages are created 0600; pacman publishes sync databases
        // 0644, and unprivileged readers (omg update/outdated) must be able
        // to parse them after an elevated sync.
        std::fs::set_permissions(&publication.staged, std::fs::Permissions::from_mode(0o644))
            .with_context(|| {
                format!(
                    "Failed to set world-readable mode on staged database {}",
                    publication.staged.display()
                )
            })?;
    }

    for index in 0..publications.len() {
        match std::fs::symlink_metadata(&publications[index].destination) {
            Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {}
            Ok(_) => {
                let rollback_errors = rollback_database_publication(&mut publications, staging);
                anyhow::bail!(
                    "Refusing to replace database path that is not a file or symlink: {}; rollback errors: {}",
                    publications[index].destination.display(),
                    rollback_errors.join("; ")
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                let rollback_errors = rollback_database_publication(&mut publications, staging);
                anyhow::bail!(
                    "Failed to inspect live database {}: {error}; rollback errors: {}",
                    publications[index].destination.display(),
                    rollback_errors.join("; ")
                );
            }
        }
        let backup = publications[index]
            .staged
            .with_extension(format!("omg-backup-{index}"));
        if !publications[index].publish {
            // This entry is not being replaced (a repository served no database
            // signature). Leave the live file untouched: deleting it would let
            // a mirror strip a signature that is already installed.
            continue;
        }
        if let Err(error) = rustix::fs::linkat(
            rustix::fs::CWD,
            &publications[index].destination,
            rustix::fs::CWD,
            &backup,
            rustix::fs::AtFlags::empty(),
        ) {
            let rollback_errors = rollback_database_publication(&mut publications, staging);
            anyhow::bail!(
                "Failed to stage live database {} for replacement: {error}; rollback errors: {}",
                publications[index].destination.display(),
                rollback_errors.join("; ")
            );
        }
        publications[index].backup = Some(backup);
    }

    for index in 0..publications.len() {
        let publication = &publications[index];
        let result = if publication.publish {
            std::fs::rename(&publication.staged, &publication.destination)
        } else {
            // Not published: the live entry is intentionally left as-is (see
            // the backup loop), so there is nothing to do.
            Ok(())
        };
        if let Err(error) = result {
            let failed_destination = publications[index].destination.display().to_string();
            let rollback_errors = rollback_database_publication(&mut publications, staging);
            anyhow::bail!(
                "Failed to publish staged package database to {failed_destination}: {error}; rollback errors: {}",
                rollback_errors.join("; ")
            );
        }
        publications[index].published = true;
    }

    // Make the complete new set durable while rollback copies still exist.
    // If a directory sync fails, restore every previous database before the
    // staging directory (which owns the backups) is dropped.
    for index in 0..publications.len() {
        if let Err(error) =
            crate::core::safe_ops::sync_parent_directory_sync(&publications[index].destination)
        {
            let failed_destination = publications[index].destination.display().to_string();
            let rollback_errors = rollback_database_publication(&mut publications, staging);
            anyhow::bail!(
                "Failed to sync published package database {failed_destination}: {error}; rollback errors: {}",
                rollback_errors.join("; ")
            );
        }
    }

    // Backup removal is cleanup after a durable commit. A stale backup in the
    // staging directory must not turn a successful publication into a false
    // transaction failure; TempDir cleanup gets another chance to remove it.
    for publication in &publications {
        if let Some(backup) = &publication.backup
            && let Err(error) = std::fs::remove_file(backup)
        {
            tracing::warn!(
                "Failed to remove database backup {} after commit: {error}",
                backup.display()
            );
        }
    }
    alpm.trans_release()
        .context("Failed to release package database lock")
}

fn verify_staged_databases(
    staged_database_root: &Path,
    config: &crate::core::pacman_conf::PacmanConfig,
) -> Result<()> {
    let root = paths::pacman_root_result()?.to_string_lossy().into_owned();
    let database_root = staged_database_root.to_string_lossy().into_owned();
    let mut alpm = alpm::Alpm::new(root, database_root)
        .context("Failed to initialize staged database verifier")?;
    crate::package_managers::alpm_ops::configure_signature_verification(&mut alpm, config)?;
    let policy = crate::package_managers::alpm_ops::signature_policy(config)?;

    for repo in &config.repos {
        let siglevel = crate::package_managers::alpm_ops::repository_siglevel(
            policy.default,
            repo.sig_level.as_deref(),
        )?;
        let database = alpm
            .register_syncdb(repo.name.as_str(), siglevel)
            .with_context(|| format!("Failed to register staged database '{}'", repo.name))?;
        database
            .is_valid()
            .with_context(|| format!("Signature verification failed for '{}'", repo.name))?;
    }
    Ok(())
}

struct StagedRepository {
    database: PathBuf,
    database_destination: PathBuf,
    signature: PathBuf,
    signature_destination: PathBuf,
}

/// Synchronize configured package databases concurrently.
pub async fn sync_databases_parallel() -> Result<()> {
    let config = crate::core::pacman_conf::PacmanConfig::parse(paths::pacman_conf_path())
        .context("Failed to load repository servers from pacman.conf")?;
    let repository_urls = repository_database_urls(&config, std::env::consts::ARCH)?;

    // Sync directory (we should already be root at this point)
    let sync_dir = paths::pacman_sync_dir_result()?;
    if !sync_dir.exists() {
        tokio::fs::create_dir_all(&sync_dir)
            .await
            .with_context(|| format!("Failed to create {}", sync_dir.display()))?;
    }

    // Download the complete repository set into a same-filesystem staging
    // directory. A failed mirror must not leave a mix of old and new live DBs.
    let staging = tempfile::Builder::new()
        .prefix(".omg-sync-")
        .tempdir_in(&sync_dir)
        .with_context(|| format!("Failed to stage databases in {}", sync_dir.display()))?;
    let staged_database_root = staging.path().join("database-root");
    let staged_sync_dir = staged_database_root.join("sync");
    tokio::fs::create_dir_all(&staged_sync_dir)
        .await
        .context("Failed to create staged pacman sync directory")?;

    // Set up progress lanes
    let client = download_client().clone();

    // Repository names do not imply a mirror source: an enterprise [core]
    // override must never be replaced with the host's global mirrorlist.
    let signature_policy = crate::package_managers::alpm_ops::signature_policy(&config)?;
    let repos_to_sync: Vec<(String, Vec<String>, PathBuf, alpm::SigLevel)> = repository_urls
        .into_iter()
        .map(|(name, urls)| {
            let repo = config
                .repos
                .iter()
                .find(|repo| repo.name == name)
                .with_context(|| format!("Missing pacman policy for repository '{name}'"))?;
            let siglevel = crate::package_managers::alpm_ops::repository_siglevel(
                signature_policy.default,
                repo.sig_level.as_deref(),
            )?;
            let destination = sync_dir.join(format!("{name}.db"));
            Ok((name, urls, destination, siglevel))
        })
        .collect::<Result<_>>()?;

    // Create progress lanes
    let progress_lanes: Vec<ProgressTask> = repos_to_sync
        .iter()
        .map(|(name, _, _, _)| {
            let task = ProgressTask::start(&TaskSpec {
                label: name.clone(),
                kind: TaskKind::Bytes { total: None },
                accent: Accent::Database,
            });
            task.set_message("connecting");
            task
        })
        .collect();

    let repos_count = repos_to_sync.len();
    let mut tasks = tokio::task::JoinSet::new();
    let sync_slots = Arc::new(tokio::sync::Semaphore::new(MAX_PARALLEL_REPO_SYNCS));

    let mut staged_repositories = Vec::with_capacity(repos_count);
    for (i, (name, urls, destination, siglevel)) in repos_to_sync.into_iter().enumerate() {
        let client = client.clone();
        let Some(task) = progress_lanes.get(i).cloned() else {
            continue;
        };
        let staged = staged_sync_dir.join(format!("{name}.db"));
        let staged_signature = staged_sync_dir.join(format!("{name}.db.sig"));
        let signature_destination = sync_dir.join(format!("{name}.db.sig"));
        staged_repositories.push(StagedRepository {
            database: staged.clone(),
            database_destination: destination.clone(),
            signature: staged_signature.clone(),
            signature_destination,
        });
        let slots = Arc::clone(&sync_slots);

        tasks.spawn(async move {
            let _permit = slots
                .acquire()
                .await
                .map_err(|error| anyhow::anyhow!("Database sync slot closed: {error}"))?;
            download_db(
                &client,
                urls,
                &staged,
                &staged_signature,
                &destination,
                siglevel,
                &task,
            )
            .await
        });
    }

    // Wait for all downloads
    let mut errors = Vec::with_capacity(repos_count);
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => errors.push(e),
            Err(e) => errors.push(anyhow::anyhow!("Task panicked: {e}")),
        }
    }

    crate::cli::modern_ui::clear_live_progress();
    println!();

    if errors.is_empty() {
        let staged_database_root = staged_database_root.clone();
        let verification_config = config.clone();
        if let Err(error) = tokio::task::spawn_blocking(move || {
            verify_staged_databases(&staged_database_root, &verification_config)
        })
        .await
        .context("Staged database verification task failed")?
        {
            errors.push(error);
        }
    }

    for error in &errors {
        tracing::error!("Sync error: {error}");
    }
    let staged_files = staged_repositories
        .into_iter()
        .flat_map(|repo| {
            let signature_present = repo.signature.is_file();
            [
                StagedFile {
                    staged: repo.database,
                    destination: repo.database_destination,
                    publish: true,
                },
                StagedFile {
                    staged: repo.signature,
                    destination: repo.signature_destination,
                    publish: signature_present,
                },
            ]
        })
        .collect::<Vec<_>>();
    let database_root = sync_dir
        .parent()
        .context("Package sync directory has no database root")?
        .to_path_buf();
    let failed_downloads = errors.len();
    tokio::task::spawn_blocking(move || {
        let mut staging = staging;
        let result = commit_staged_files(
            &staged_files,
            failed_downloads,
            &database_root,
            &mut staging,
        );
        crate::package_managers::alpm_direct::clear_alpm_cache();
        result
    })
    .await
    .context("Package database publication task failed")??;
    Ok(())
}

fn repository_database_urls(
    config: &crate::core::pacman_conf::PacmanConfig,
    architecture: &str,
) -> Result<Vec<(String, Vec<String>)>> {
    anyhow::ensure!(
        !config.repos.is_empty(),
        "pacman configuration contains no repositories"
    );
    config
        .repos
        .iter()
        .map(|repo| {
            let servers = config
                .resolve_servers(repo, architecture)
                .with_context(|| format!("Failed to resolve servers for repo '{}'", repo.name))?;
            anyhow::ensure!(
                !servers.is_empty(),
                "Repository '{}' has no configured servers",
                repo.name
            );
            let urls = servers
                .iter()
                .take(MAX_MIRRORS_PER_REPO)
                .map(|server| build_db_url(server, &repo.name))
                .collect();
            Ok((repo.name.clone(), urls))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_publication_preserves_unexpected_directories() {
        let root = tempfile::tempdir().unwrap();
        let mut staging = tempfile::tempdir_in(root.path()).unwrap();
        let destination = root.path().join("core.db");
        let staged = staging.path().join("core.staged");
        std::fs::create_dir(&destination).unwrap();
        std::fs::write(destination.join("keep"), b"existing contents").unwrap();
        std::fs::write(&staged, b"new database").unwrap();

        let result = commit_staged_databases(&[(staged, destination.clone())], 0, &mut staging);
        drop(staging);
        assert!(
            destination.is_dir(),
            "publication must not replace a directory"
        );
        let error = result.expect_err("unexpected destination kind must be refused");
        assert!(error.to_string().contains("not a file or symlink"));
        assert_eq!(
            std::fs::read(destination.join("keep")).unwrap(),
            b"existing contents"
        );
    }

    #[test]
    fn database_publication_replaces_symlinks_without_changing_their_targets() {
        let root = tempfile::tempdir().unwrap();
        let mut staging = tempfile::tempdir_in(root.path()).unwrap();
        let destination = root.path().join("core.db");
        let target = root.path().join("shared.db");
        let staged = staging.path().join("core.staged");
        std::fs::write(&target, b"shared database").unwrap();
        std::os::unix::fs::symlink(&target, &destination).unwrap();
        std::fs::write(&staged, b"new database").unwrap();

        commit_staged_databases(&[(staged, destination.clone())], 0, &mut staging).unwrap();
        drop(staging);
        assert!(std::fs::symlink_metadata(&destination).unwrap().is_file());
        assert_eq!(std::fs::read(destination).unwrap(), b"new database");
        assert_eq!(std::fs::read(target).unwrap(), b"shared database");
    }

    #[test]
    fn rollback_removes_new_database_without_a_predecessor() {
        let root = tempfile::tempdir().unwrap();
        let mut staging = tempfile::tempdir_in(root.path()).unwrap();
        let destination = root.path().join("core.db");
        let staged = staging.path().join("core.staged");
        let extra = staging.path().join("extra.staged");
        std::fs::write(&staged, b"new database").unwrap();
        std::fs::write(&extra, b"new extra database").unwrap();

        commit_staged_databases(
            &[
                (staged.clone(), destination.clone()),
                (extra, root.path().join("missing/extra.db")),
            ],
            0,
            &mut staging,
        )
        .expect_err("publication to a missing parent must fail");
        assert!(
            !destination.exists(),
            "rollback must restore the original absence"
        );
        assert_eq!(std::fs::read(staged).unwrap(), b"new database");
        drop(staging);
        assert!(!destination.exists());
    }

    #[test]
    fn failed_publication_restores_symlink_identity() {
        let root = tempfile::tempdir().unwrap();
        let mut staging = tempfile::tempdir_in(root.path()).unwrap();
        let destination = root.path().join("core.db");
        let target = root.path().join("shared.db");
        let staged = staging.path().join("core.staged");
        let extra = staging.path().join("extra.staged");
        std::fs::write(&target, b"shared database").unwrap();
        std::os::unix::fs::symlink(&target, &destination).unwrap();
        std::fs::write(&staged, b"new database").unwrap();
        std::fs::write(&extra, b"new extra database").unwrap();

        commit_staged_databases(
            &[
                (staged, destination.clone()),
                (extra, root.path().join("missing/extra.db")),
            ],
            0,
            &mut staging,
        )
        .expect_err("publication to a missing parent must fail");
        drop(staging);
        assert_eq!(std::fs::read_link(destination).unwrap(), target);
        assert_eq!(std::fs::read(target).unwrap(), b"shared database");
    }

    #[test]
    fn failed_database_rollback_retains_its_recovery_files() {
        let root = tempfile::tempdir().unwrap();
        let mut staging = tempfile::tempdir_in(root.path()).unwrap();
        let backup = staging.path().join("core.backup");
        let destination = root.path().join("core.db");
        std::fs::write(&backup, b"old database").unwrap();
        std::fs::create_dir(&destination).unwrap();
        std::fs::write(destination.join("peer-file"), b"peer").unwrap();
        let mut publications = [DatabasePublication {
            staged: staging.path().join("core.staged"),
            destination: destination.clone(),
            publish: true,
            backup: Some(backup.clone()),
            published: false,
        }];

        let errors = rollback_database_publication(&mut publications, &mut staging);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("failed to restore"))
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains(staging.path().to_str().unwrap()))
        );
        drop(staging);
        assert_eq!(
            std::fs::read(backup).expect("recovery backup must survive failed rollback"),
            b"old database"
        );
        assert_eq!(
            std::fs::read(destination.join("peer-file")).unwrap(),
            b"peer"
        );
    }

    #[test]
    fn database_publication_respects_an_existing_alpm_lease() {
        let mut directory = tempfile::tempdir().expect("database root");
        let live = directory.path().join("core.db");
        let staged = directory.path().join("core.staged");
        std::fs::write(&live, b"old").unwrap();
        std::fs::write(&staged, b"new").unwrap();
        let lease = alpm::Alpm::new("/", directory.path().to_str().unwrap()).unwrap();
        lease.trans_init(alpm::TransFlag::empty()).unwrap();

        let error = commit_staged_databases(&[(staged.clone(), live.clone())], 0, &mut directory)
            .expect_err("a leased database must refuse publication");
        assert_eq!(
            error.downcast_ref::<alpm::Error>(),
            Some(&alpm::Error::HandleLock)
        );
        assert_eq!(std::fs::read(&live).unwrap(), b"old");
        assert_eq!(std::fs::read(&staged).unwrap(), b"new");
        assert!(directory.path().join("db.lck").exists());

        drop(lease);
        commit_staged_databases(&[(staged, live.clone())], 0, &mut directory).unwrap();
        assert_eq!(std::fs::read(live).unwrap(), b"new");
        assert!(!directory.path().join("db.lck").exists());
    }

    #[test]
    fn database_publication_preserves_unheld_database_lock() -> anyhow::Result<()> {
        use std::os::unix::fs::MetadataExt;

        let mut directory = tempfile::tempdir()?;
        let live = directory.path().join("core.db");
        let staged = directory.path().join("core.staged");
        let lock = directory.path().join("db.lck");
        std::fs::write(&live, b"old")?;
        std::fs::write(&staged, b"new")?;
        std::fs::write(&lock, b"unheld-lock-evidence")?;
        let inode = std::fs::metadata(&lock)?.ino();

        let error = commit_staged_databases(&[(staged.clone(), live.clone())], 0, &mut directory)
            .expect_err("publication must refuse an existing unheld database lock");
        assert!(error.to_string().contains("lock"));
        assert_eq!(std::fs::read(&live)?, b"old");
        assert_eq!(std::fs::read(&staged)?, b"new");
        assert_eq!(std::fs::read(&lock)?, b"unheld-lock-evidence");
        assert_eq!(std::fs::metadata(&lock)?.ino(), inode);
        Ok(())
    }

    #[test]
    fn database_publication_refuses_a_stale_lock_file() {
        let mut directory = tempfile::tempdir().expect("database root");
        let live = directory.path().join("core.db");
        let staged = directory.path().join("core.staged");
        let lock = directory.path().join("db.lck");
        std::fs::write(&live, b"old").unwrap();
        std::fs::write(&staged, b"new").unwrap();
        std::fs::write(&lock, b"").unwrap();

        let error = commit_staged_databases(&[(staged.clone(), live.clone())], 0, &mut directory)
            .expect_err("an unheld lock must require deliberate recovery");
        assert_eq!(
            error.downcast_ref::<alpm::Error>(),
            Some(&alpm::Error::HandleLock)
        );
        assert_eq!(std::fs::read(live).unwrap(), b"old");
        assert_eq!(std::fs::read(staged).unwrap(), b"new");
        assert_eq!(std::fs::read(lock).unwrap(), b"");
    }

    #[test]
    fn failed_staged_set_does_not_replace_live_databases() {
        let mut directory = tempfile::tempdir().expect("database directory");
        let live = directory.path().join("core.db");
        let staged = directory.path().join("core.db.staged");
        std::fs::write(&live, b"old").expect("seed live database");
        std::fs::write(&staged, b"new").expect("seed staged database");

        let error = commit_staged_databases(&[(staged, live.clone())], 1, &mut directory)
            .expect_err("failed download set must not publish");

        assert!(error.to_string().contains("1 database"));
        assert_eq!(std::fs::read(live).expect("live database"), b"old");
    }

    #[test]
    fn missing_optional_signature_preserves_live_signature() {
        let mut directory = tempfile::tempdir().expect("database directory");
        let database_root = directory.path().to_path_buf();
        let live_database = directory.path().join("core.db");
        let live_signature = directory.path().join("core.db.sig");
        let staged_database = directory.path().join("core.staged");
        let absent_signature = directory.path().join("core.sig.absent");
        std::fs::write(&live_database, b"old").expect("seed live database");
        std::fs::write(&live_signature, b"old-signature").expect("seed live signature");
        std::fs::write(&staged_database, b"new").expect("stage database");

        commit_staged_files(
            &[
                StagedFile {
                    staged: staged_database,
                    destination: live_database.clone(),
                    publish: true,
                },
                StagedFile {
                    staged: absent_signature,
                    destination: live_signature.clone(),
                    publish: false,
                },
            ],
            0,
            &database_root,
            &mut directory,
        )
        .expect("publish unsigned optional database");

        assert_eq!(std::fs::read(live_database).unwrap(), b"new");
        // Publication must never delete a signature that was not replaced.
        // The download path already refuses to downgrade a signed repository
        // to unsigned, so this only guards the deletion itself.
        assert_eq!(
            std::fs::read(&live_signature).unwrap(),
            b"old-signature",
            "a signature the mirror did not replace must be left in place"
        );
    }

    #[test]
    fn publication_failure_restores_every_live_database() {
        let mut directory = tempfile::tempdir().expect("database directory");
        let directory_path = directory.path().to_path_buf();
        let core_live = directory.path().join("core.db");
        let core_staged = directory.path().join("core.staged");
        let extra_staged = directory.path().join("extra.staged");
        let extra_live = directory.path().join("missing-parent/extra.db");
        std::fs::write(&core_live, b"old-core").expect("seed live core");
        std::fs::write(&core_staged, b"new-core").expect("stage core");
        std::fs::write(&extra_staged, b"new-extra").expect("stage extra");

        let error = commit_staged_databases(
            &[
                (core_staged.clone(), core_live.clone()),
                (extra_staged.clone(), extra_live),
            ],
            0,
            &mut directory,
        )
        .expect_err("a mid-publication failure must roll back earlier databases");

        assert!(error.to_string().contains("Failed to publish"), "{error}");
        assert_eq!(std::fs::read(core_live).unwrap(), b"old-core");
        assert_eq!(std::fs::read(core_staged).unwrap(), b"new-core");
        assert_eq!(std::fs::read(extra_staged).unwrap(), b"new-extra");
        assert!(!directory.path().join("db.lck").exists());
        drop(directory);
        assert!(
            !directory_path.exists(),
            "successful rollback must permit cleanup"
        );
    }

    #[test]
    fn published_database_is_world_readable_like_pacman() {
        use std::os::unix::fs::PermissionsExt;

        let mut directory = tempfile::tempdir().expect("database directory");
        let live = directory.path().join("core.db");
        let staged = directory.path().join("core.db.staged");
        std::fs::write(&staged, b"new").expect("seed staged database");
        // tempfile staging creates 0600; the published database must not
        // inherit it or unprivileged readers are locked out.
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600))
            .expect("seed staged mode");

        commit_staged_databases(&[(staged, live.clone())], 0, &mut directory)
            .expect("publish staged database");

        let mode = std::fs::metadata(&live)
            .expect("live database")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o644,
            "sync databases must be 0644 like pacman"
        );
    }

    #[test]
    fn staged_database_verification_accepts_missing_optional_signature() {
        let directory = tempfile::tempdir().expect("staging root");
        let database_root = directory.path().join("database-root");
        let sync_dir = database_root.join("sync");
        let keyring = directory.path().join("gnupg");
        std::fs::create_dir_all(&sync_dir).expect("staged sync directory");
        std::fs::create_dir_all(&keyring).expect("test keyring directory");
        std::fs::write(sync_dir.join("core.db"), b"database").expect("staged database");
        let config = crate::core::pacman_conf::PacmanConfig::parse_str(&format!(
            "[options]\nGPGDir = {}\nSigLevel = Required DatabaseOptional\n\n[core]\nServer = https://mirror.example/$repo/$arch\n",
            keyring.display()
        ))
        .expect("pacman config");

        verify_staged_databases(&database_root, &config)
            .expect("DatabaseOptional must permit an absent detached signature");
    }

    #[test]
    fn staged_database_verification_rejects_invalid_signature() {
        let directory = tempfile::tempdir().expect("staging root");
        let database_root = directory.path().join("database-root");
        let sync_dir = database_root.join("sync");
        let keyring = directory.path().join("gnupg");
        std::fs::create_dir_all(&sync_dir).expect("staged sync directory");
        std::fs::create_dir_all(&keyring).expect("test keyring directory");
        std::fs::write(sync_dir.join("core.db"), b"database").expect("staged database");
        std::fs::write(sync_dir.join("core.db.sig"), b"not-an-openpgp-signature")
            .expect("invalid detached signature");
        let config = crate::core::pacman_conf::PacmanConfig::parse_str(&format!(
            "[options]\nGPGDir = {}\nSigLevel = Required DatabaseRequired\n\n[core]\nServer = https://mirror.example/$repo/$arch\n",
            keyring.display()
        ))
        .expect("pacman config");

        let error = verify_staged_databases(&database_root, &config)
            .expect_err("an invalid detached database signature must fail closed");
        assert!(error.to_string().contains("Signature verification failed"));
    }

    #[test]
    fn database_signature_url_tracks_database_url() {
        assert_eq!(
            build_signature_url("https://mirror.example/core/os/x86_64/core.db"),
            "https://mirror.example/core/os/x86_64/core.db.sig"
        );
    }

    #[test]
    fn db_urls_substitute_repo_and_runtime_arch() {
        let arch = std::env::consts::ARCH;
        let url = build_db_url("https://mirror.example.com/$repo/os/$arch", "core");
        assert_eq!(
            url,
            format!("https://mirror.example.com/core/os/{arch}/core.db")
        );
    }

    #[test]
    fn every_repository_uses_its_own_configured_servers() {
        let config = crate::core::pacman_conf::PacmanConfig::parse_str(
            "[options]\n\n[core]\nServer = https://internal.example/$repo/os/$arch\n\n\
             [chaotic-aur]\nServer = https://community.example/$repo/$arch\n",
        )
        .expect("pacman config");

        let repos =
            repository_database_urls(&config, "test-arch").expect("repository URLs should resolve");
        assert_eq!(
            repos,
            [
                (
                    "core".to_string(),
                    vec!["https://internal.example/core/os/test-arch/core.db".to_string()]
                ),
                (
                    "chaotic-aur".to_string(),
                    vec![
                        "https://community.example/chaotic-aur/test-arch/chaotic-aur.db"
                            .to_string()
                    ]
                )
            ]
        );
    }

    #[test]
    fn repositories_without_servers_fail_the_complete_sync_set() {
        let config = crate::core::pacman_conf::PacmanConfig::parse_str(
            "[options]\n\n[core]\nServer = https://mirror.example/$repo/$arch\n\n[extra]\n",
        )
        .expect("pacman config");

        let error = repository_database_urls(&config, "test-arch")
            .expect_err("missing repo policy must fail closed");
        assert!(error.to_string().contains("extra"), "{error:#}");
    }
}
