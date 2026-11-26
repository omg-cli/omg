//! `omg snapshot` - Create and restore environment snapshots

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::style;
use crate::core::env::fingerprint::EnvironmentState;
use crate::core::{paths, safe_ops};

const MAX_SNAPSHOT_BYTES: u64 = 16 * 1024 * 1024;
const PENDING_CREATE: &str = ".create.pending";
const PENDING_DELETE: &str = ".delete.pending";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: String,
    pub message: Option<String>,
    pub created_at: i64,
    pub state: EnvironmentState,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SnapshotIndex {
    snapshots: Vec<SnapshotMeta>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SnapshotMeta {
    id: String,
    message: Option<String>,
    created_at: i64,
    hash: String,
}

impl Snapshot {
    fn metadata(&self) -> SnapshotMeta {
        SnapshotMeta {
            id: self.id.clone(),
            message: self.message.clone(),
            created_at: self.created_at,
            hash: self.state.hash.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct SnapshotDeletion {
    id: String,
}

enum SnapshotUpdate {
    Create(SnapshotMeta),
    Delete(SnapshotDeletion),
}

fn snapshots_dir() -> PathBuf {
    paths::data_dir().join("snapshots")
}

fn index_path() -> PathBuf {
    snapshots_dir().join("index.json")
}

fn load_index() -> Result<SnapshotIndex> {
    let path = index_path();
    match fs::symlink_metadata(&path) {
        Ok(metadata) => anyhow::ensure!(
            !metadata.file_type().is_symlink(),
            "Refusing to read snapshot index that is a symlink: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(SnapshotIndex::default());
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Failed to inspect snapshot index: {}", path.display()));
        }
    }
    let content = safe_ops::read_bounded_regular_file(&path, "Snapshot index", MAX_SNAPSHOT_BYTES)
        .map_err(|error| anyhow::anyhow!("Failed to read snapshot index: {error:#}"))?;
    serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse snapshot index: {}", path.display()))
}

fn load_index_for_update() -> Result<(fs::File, SnapshotIndex)> {
    let directory = snapshots_dir();
    paths::create_private_data_directory(&directory)
        .context("Failed to create snapshots directory")?;
    let path = directory.join(".index.lock");
    let mut options = fs::OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
    }
    let lock = options
        .open(&path)
        .context("Failed to open snapshot index lock")?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => {
            anyhow::bail!("Another snapshot mutation is running; retry when it finishes")
        }
        Err(fs::TryLockError::Error(error)) => {
            return Err(error).context("Failed to acquire snapshot index lock");
        }
    }
    let mut index = load_index()?;
    recover_pending(&directory, &mut index)?;
    Ok((lock, index))
}

fn encode_snapshot_file(value: &impl Serialize, kind: &str) -> Result<Vec<u8>> {
    let content = serde_json::to_vec_pretty(value)?;
    anyhow::ensure!(
        content.len() as u64 <= MAX_SNAPSHOT_BYTES,
        "{kind} exceeds the {MAX_SNAPSHOT_BYTES} byte limit"
    );
    Ok(content)
}

fn stage_index(index: &SnapshotIndex) -> Result<safe_ops::StagedFileWrite> {
    let content = encode_snapshot_file(index, "Snapshot index")?;
    safe_ops::stage_atomic_write_file_sync(&index_path(), &content)
        .context("Failed to stage snapshot index")
}

fn path_present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => anyhow::bail!("Failed to inspect {}: {error}", path.display()),
    }
}

fn recover_before_read() -> Result<()> {
    let directory = snapshots_dir();
    if path_present(&directory.join(PENDING_CREATE))?
        || path_present(&directory.join(PENDING_DELETE))?
    {
        let (_lock, _) = load_index_for_update()?;
    }
    Ok(())
}

fn recover_pending(directory: &Path, index: &mut SnapshotIndex) -> Result<()> {
    let creation = directory.join(PENDING_CREATE);
    let deletion = directory.join(PENDING_DELETE);
    let has_creation = path_present(&creation)?;
    let has_deletion = path_present(&deletion)?;
    anyhow::ensure!(
        !(has_creation && has_deletion),
        "Multiple pending snapshot updates require review"
    );

    let update = if has_creation {
        let content =
            safe_ops::read_bounded_regular_file(&creation, "Pending snapshot", MAX_SNAPSHOT_BYTES)?;
        let snapshot: Snapshot =
            serde_json::from_str(&content).context("Failed to parse pending snapshot")?;
        let metadata = snapshot.metadata();
        snapshot.state.verify_saved_inventory("Pending snapshot")?;
        SnapshotUpdate::Create(metadata)
    } else if has_deletion {
        let content = safe_ops::read_bounded_regular_file(
            &deletion,
            "Pending snapshot deletion",
            MAX_SNAPSHOT_BYTES,
        )?;
        SnapshotUpdate::Delete(
            serde_json::from_str(&content).context("Failed to parse pending snapshot deletion")?,
        )
    } else {
        return Ok(());
    };
    publish_update(directory, index, update, None)
}

// The index lock serializes both regular writes and recovery. Keep the durable
// pending record until the snapshot and index are both visible and synced.
fn publish_update(
    directory: &Path,
    index: &mut SnapshotIndex,
    update: SnapshotUpdate,
    new_record: Option<&[u8]>,
) -> Result<()> {
    let is_creation = matches!(update, SnapshotUpdate::Create(_));
    let (id, pending_name) = match &update {
        SnapshotUpdate::Create(entry) => (&entry.id, PENDING_CREATE),
        SnapshotUpdate::Delete(entry) => (&entry.id, PENDING_DELETE),
    };
    validate_snapshot_id(id)?;
    let path = directory.join(format!("{id}.json"));
    let pending = directory.join(pending_name);
    match update {
        SnapshotUpdate::Create(entry) => {
            let existing = index.snapshots.iter().find(|saved| saved.id == entry.id);
            if new_record.is_some() {
                anyhow::ensure!(
                    existing.is_none() && !path_present(&path)?,
                    "Snapshot '{}' already exists; refusing to overwrite it",
                    entry.id
                );
            }
            if let Some(saved) = existing {
                anyhow::ensure!(
                    *saved == entry,
                    "Pending snapshot '{}' conflicts with the index",
                    entry.id
                );
            } else {
                index.snapshots.push(entry);
            }
        }
        SnapshotUpdate::Delete(entry) => index.snapshots.retain(|saved| saved.id != entry.id),
    }

    let index_write = stage_index(index)?;
    if let Some(content) = new_record {
        anyhow::ensure!(
            safe_ops::atomic_write_new_private_file(&pending, content)?,
            "A snapshot update is already pending"
        );
    }

    if is_creation {
        link_pending_snapshot(&pending, &path)?;
    } else if let Err(error) = fs::remove_file(&path)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(error).with_context(|| format!("Failed to remove snapshot {}", path.display()));
    }
    index_write
        .publish()
        .context("Failed to publish snapshot index")?;
    fs::remove_file(&pending).context("Failed to clear pending snapshot update")?;
    safe_ops::sync_parent_directory_sync(&pending)
}

fn link_pending_snapshot(pending: &Path, path: &Path) -> Result<()> {
    match fs::hard_link(pending, path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let staged = safe_ops::read_bounded_regular_bytes(
                pending,
                "Pending snapshot",
                MAX_SNAPSHOT_BYTES,
            )?
            .0;
            let existing = safe_ops::read_bounded_regular_bytes(
                path,
                "Existing snapshot",
                MAX_SNAPSHOT_BYTES,
            )?
            .0;
            anyhow::ensure!(
                staged == existing,
                "Pending snapshot conflicts with existing file {}",
                path.display()
            );
            Ok(())
        }
        Err(error) => {
            Err(error).with_context(|| format!("Failed to publish snapshot {}", path.display()))
        }
    }
}

fn load_snapshot(path: &Path, id: &str) -> Result<EnvironmentState> {
    recover_before_read()?;
    if let Err(error) = fs::symlink_metadata(path) {
        if error.kind() == std::io::ErrorKind::NotFound {
            anyhow::bail!("Snapshot '{id}' not found");
        }
        return Err(error)
            .with_context(|| format!("Failed to inspect snapshot: {}", path.display()));
    }
    let content = safe_ops::read_bounded_regular_file(path, "Snapshot file", MAX_SNAPSHOT_BYTES)?;
    let snapshot: Snapshot = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse snapshot: {}", path.display()))?;
    anyhow::ensure!(snapshot.id == id, "Snapshot ID does not match '{id}'");
    snapshot.state.verify_saved_inventory("Snapshot")
}

/// Create a new snapshot
pub async fn create(message: Option<String>) -> Result<()> {
    if let Some(ref msg) = message {
        // SECURITY: Validate message length
        if msg.len() > 1000 {
            anyhow::bail!("Snapshot message too long");
        }
    }

    println!("{} Creating snapshot...\n", style::runtime("OMG"));

    let state = EnvironmentState::capture().await?;
    let (_index_lock, mut index) = load_index_for_update()?;

    let id = generate_snapshot_id();
    let snapshot = Snapshot {
        id: id.clone(),
        message: message.clone(),
        created_at: jiff::Timestamp::now().as_second(),
        state,
    };

    let content = encode_snapshot_file(&snapshot, "Snapshot file")?;
    publish_update(
        &snapshots_dir(),
        &mut index,
        SnapshotUpdate::Create(snapshot.metadata()),
        Some(&content),
    )?;

    println!("  {} Snapshot created!", style::positive("✓"));
    println!("  ID: {}", style::accent(&id));
    if let Some(msg) = &message {
        println!("  Message: {}", style::sanitize_terminal_text(msg));
    }
    println!("  Runtimes: {}", snapshot.state.runtimes.len());
    println!("  Packages: {}", snapshot.state.packages.len());
    println!();
    println!(
        "  Restore with: {}",
        style::accent(&format!("omg snapshot restore {id}"))
    );

    Ok(())
}

/// List all snapshots
pub fn list() -> Result<()> {
    println!("{} Snapshots\n", style::runtime("OMG"));

    recover_before_read()?;
    let index = load_index()?;

    if index.snapshots.is_empty() {
        println!("  {} No snapshots found", style::dim("○"));
        println!();
        println!(
            "  Create one with: {}",
            style::accent("omg snapshot create")
        );
        return Ok(());
    }

    println!(
        "  {:12} {:20} {:12} {}",
        style::emphasis("ID"),
        style::emphasis("Date"),
        style::emphasis("Hash"),
        style::emphasis("Message")
    );
    println!("  {}", "─".repeat(60));

    for snap in index.snapshots.iter().rev() {
        let date = format_timestamp(snap.created_at);
        let msg = snap.message.as_deref().unwrap_or("-");
        let short_hash = short_hash(&snap.hash);

        println!(
            "  {} {} {} {}",
            style::accent(&style::sanitize_terminal_text(&snap.id)),
            style::dim(&date),
            style::dim(&style::sanitize_terminal_text(&short_hash)),
            style::sanitize_terminal_text(msg)
        );
    }

    println!();
    println!("  {} snapshots total", index.snapshots.len());

    Ok(())
}

/// Restore a snapshot
pub async fn restore(id: &str, dry_run: bool, yes: bool) -> Result<()> {
    validate_snapshot_id(id)?;

    println!(
        "{} {} snapshot {}\n",
        style::runtime("OMG"),
        if dry_run {
            "Preview restore of"
        } else {
            "Restoring"
        },
        style::caution(id)
    );

    let snapshot_path = snapshots_dir().join(format!("{id}.json"));
    let target = tokio::task::spawn_blocking({
        let id = id.to_owned();
        move || load_snapshot(&snapshot_path, &id)
    })
    .await
    .context("Snapshot reader task failed")??;
    let current = EnvironmentState::capture().await?;

    let mut runtime_changes = Vec::new();
    for (runtime, target_ver) in &target.runtimes {
        let current_ver = current.runtimes.get(runtime);
        if current_ver != Some(target_ver) {
            crate::cli::runtimes::validate_restore_request(runtime, target_ver)?;
            runtime_changes.push((runtime, current_ver.map(String::as_str), target_ver));
        }
    }

    let crate::cli::diff::PackageDiff {
        added: to_install,
        removed: to_remove,
    } = crate::cli::diff::diff_packages(&current.packages, &target.packages);
    crate::core::security::ensure_local_archive_consent(&to_install, false)?;
    crate::cli::packages::validate_install_target_syntax(
        &to_install,
        crate::core::env::distro::detect_distro(),
    )
    .map_err(|error| anyhow::anyhow!("Invalid snapshot package targets: {error}"))?;
    crate::core::security::validate_package_names(&to_remove)?;

    println!("  {}", style::emphasis("Changes to apply:"));
    println!();

    if !runtime_changes.is_empty() {
        println!("  Runtimes:");
        for (runtime, from, to) in &runtime_changes {
            let from_str = from.unwrap_or("(none)");
            println!(
                "    {} {} → {}",
                style::caution(&style::sanitize_terminal_text(runtime)),
                style::dim(&style::sanitize_terminal_text(from_str)),
                style::positive(&style::sanitize_terminal_text(to))
            );
        }
        println!();
    }

    if !to_install.is_empty() {
        println!("  Packages to install ({}):", to_install.len());
        for pkg in to_install.iter().take(10) {
            println!(
                "    {} {}",
                style::positive("+"),
                style::sanitize_terminal_text(pkg)
            );
        }
        if to_install.len() > 10 {
            println!("    ... and {} more", to_install.len() - 10);
        }
        println!();
    }

    if !to_remove.is_empty() {
        println!("  Packages to remove ({}):", to_remove.len());
        for pkg in to_remove.iter().take(10) {
            println!(
                "    {} {}",
                style::negative("-"),
                style::sanitize_terminal_text(pkg)
            );
        }
        if to_remove.len() > 10 {
            println!("    ... and {} more", to_remove.len() - 10);
        }
        println!();
    }

    if runtime_changes.is_empty() && to_install.is_empty() && to_remove.is_empty() {
        println!(
            "  {} Environment already matches snapshot!",
            style::positive("✓")
        );
        return Ok(());
    }

    if dry_run {
        println!("  {} No changes made (dry run)", style::info("ℹ"));
        println!(
            "  Run without --dry-run to apply: {}",
            style::accent(&format!("omg snapshot restore {id}"))
        );
        return Ok(());
    }

    let has_package_changes = !to_install.is_empty() || !to_remove.is_empty();
    if has_package_changes && !yes {
        println!();
        println!(
            "  {} Package changes found ({} to install, {} to remove):",
            style::caution("⚠"),
            to_install.len(),
            to_remove.len()
        );

        if console::user_attended() {
            let confirm = dialoguer::Confirm::new()
                .with_prompt("Do you want to apply all snapshot changes?")
                .default(false)
                .interact()?;

            if !confirm {
                println!("  {} Snapshot restore cancelled", style::info("ℹ"));
                return Ok(());
            }
        } else {
            anyhow::bail!(
                "This command requires an interactive terminal or the --yes flag.\n\
                 For automation, use: omg snapshot restore {id} --yes"
            );
        }
    }

    // Consent covers the complete restore. Do not mutate runtimes or packages
    // before the package-change gate above succeeds.
    println!("  {}", style::emphasis("Applying changes..."));

    for (runtime, _, target_ver) in &runtime_changes {
        println!("    Switching {runtime} to {target_ver}...");
        crate::cli::runtimes::restore_version(runtime, target_ver).await?;
    }

    if has_package_changes {
        if !to_install.is_empty() {
            println!("    Installing {} packages...", to_install.len());
            crate::cli::packages::install(&to_install, true, false, false).await?;
        }

        if !to_remove.is_empty() {
            println!("    Removing {} packages...", to_remove.len());
            crate::cli::packages::remove(&to_remove, false, true, false).await?;
        }
    }

    println!();
    println!("  {} Snapshot restore complete!", style::positive("✓"));

    Ok(())
}

fn short_hash(hash: &str) -> String {
    hash.chars().take(8).collect()
}

/// Delete a snapshot
pub fn delete(id: &str) -> Result<()> {
    validate_snapshot_id(id)?;

    let (_index_lock, mut index) = load_index_for_update()?;
    let directory = snapshots_dir();
    let snapshot_path = directory.join(format!("{id}.json"));
    let is_snapshot = match fs::symlink_metadata(&snapshot_path) {
        Ok(metadata) => metadata.is_file() || metadata.file_type().is_symlink(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!("Snapshot '{id}' not found");
        }
        Err(error) => return Err(error).context("Failed to inspect snapshot before deletion"),
    };
    anyhow::ensure!(is_snapshot, "Snapshot '{id}' is not a regular file");

    let deletion = SnapshotDeletion { id: id.to_owned() };
    let content = encode_snapshot_file(&deletion, "Pending snapshot deletion")?;
    publish_update(
        &directory,
        &mut index,
        SnapshotUpdate::Delete(deletion),
        Some(&content),
    )?;

    println!(
        "{} Deleted snapshot {}",
        style::positive("✓"),
        style::caution(id)
    );

    Ok(())
}

fn validate_snapshot_id(id: &str) -> Result<()> {
    anyhow::ensure!(
        !id.is_empty()
            && !id.eq_ignore_ascii_case("index")
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
        "Invalid snapshot ID: {}",
        style::sanitize_terminal_text(id)
    );
    Ok(())
}

fn generate_snapshot_id() -> String {
    let now = jiff::Timestamp::now();
    let date = format!("{now}").chars().take(10).collect::<String>();
    let random = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
    format!("snap-{date}-{random}")
}

fn format_timestamp(ts: i64) -> String {
    crate::cli::format_short_timestamp(ts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_hash_handles_multibyte_index_values_without_panicking() {
        assert_eq!(short_hash("éééééééémore"), "éééééééé");
        assert_eq!(short_hash("abc"), "abc");
    }

    #[test]
    fn generated_ids_are_unique_and_wellformed() {
        let first = generate_snapshot_id();
        let second = generate_snapshot_id();
        assert_ne!(first, second, "IDs must not collide within a session");
        for id in [first, second] {
            let rest = id.strip_prefix("snap-").expect("snap- prefix");
            assert_eq!(rest.len(), 19, "YYYY-MM-DD-8hex, got {id}");
            assert!(
                rest.chars().all(|c| c.is_ascii_hexdigit() || c == '-'),
                "filesystem-safe ID, got {id}"
            );
        }
    }

    #[test]
    fn timestamps_render_as_compact_strings_or_unknown() {
        assert_eq!(format_timestamp(0).len(), 16);
        assert_eq!(format_timestamp(i64::MAX), "unknown");
    }
}
