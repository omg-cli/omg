//! `omg snapshot` - Create and restore environment snapshots

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::cli::style;
use crate::core::env::fingerprint::EnvironmentState;
use crate::core::paths;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotMeta {
    id: String,
    message: Option<String>,
    created_at: i64,
    hash: String,
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
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(SnapshotIndex::default());
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Failed to inspect snapshot index: {}", path.display()));
        }
    }
    let content = read_snapshot_file(&path)
        .with_context(|| format!("Failed to read snapshot index: {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse snapshot index: {}", path.display()))
}

/// Read a snapshot-sidecar file, refusing symlinks so a planted link
/// cannot redirect the read outside the snapshots directory.
fn read_snapshot_file(path: &PathBuf) -> Result<String> {
    let is_symlink =
        std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink());
    if is_symlink {
        anyhow::bail!(
            "Refusing to read snapshot file that is a symlink: {}",
            path.display()
        );
    }
    Ok(fs::read_to_string(path)?)
}

fn load_index_for_update() -> Result<(fs::File, SnapshotIndex)> {
    let directory = snapshots_dir();
    fs::create_dir_all(&directory).context("Failed to create snapshots directory")?;
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
    let index = load_index()?;
    Ok((lock, index))
}

fn save_index(index: &SnapshotIndex) -> Result<()> {
    let path = index_path();
    crate::core::safe_ops::atomic_write_file_sync(&path, serde_json::to_string_pretty(index)?)
        .with_context(|| format!("Failed to write snapshot index: {}", path.display()))
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

    // UUID-backed IDs make collisions practically impossible; still refuse to
    // overwrite an existing snapshot instead of silently replacing it.
    let id = generate_snapshot_id();
    let snapshot_path = snapshots_dir().join(format!("{id}.json"));
    anyhow::ensure!(
        !snapshot_path.exists(),
        "Snapshot '{id}' already exists; refusing to overwrite it"
    );

    let snapshot = Snapshot {
        id: id.clone(),
        message: message.clone(),
        created_at: jiff::Timestamp::now().as_second(),
        state,
    };

    // Save snapshot file. Claim the path with a hard link instead of
    // `persist` rename: link fails with AlreadyExists when another `create`
    // wins the race, so the non-overwrite guarantee holds atomically.
    // The temp file is fully synced before linking, so no torn file lands.
    {
        use std::io::Write as _;
        let dir = snapshots_dir();
        let mut temp = tempfile::NamedTempFile::new_in(&dir)
            .with_context(|| format!("Failed to stage snapshot in {}", dir.display()))?;
        temp.write_all(serde_json::to_string_pretty(&snapshot)?.as_bytes())
            .with_context(|| format!("Failed to write snapshot: {}", snapshot_path.display()))?;
        temp.as_file()
            .sync_all()
            .with_context(|| format!("Failed to sync snapshot: {}", snapshot_path.display()))?;
        match std::fs::hard_link(temp.path(), &snapshot_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                anyhow::bail!("Snapshot '{id}' already exists; refusing to overwrite it")
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("Failed to write snapshot: {}", snapshot_path.display())
                });
            }
        }
    }

    index.snapshots.push(SnapshotMeta {
        id: id.clone(),
        message: message.clone(),
        created_at: snapshot.created_at,
        hash: snapshot.state.hash.clone(),
    });
    save_index(&index)?;

    println!("  {} Snapshot created!", style::positive("✓"));
    println!("  ID: {}", style::accent(&id));
    if let Some(msg) = &message {
        println!("  Message: {msg}");
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
            style::accent(&snap.id),
            style::dim(&date),
            style::dim(&short_hash),
            msg
        );
    }

    println!();
    println!("  {} snapshots total", index.snapshots.len());

    Ok(())
}

/// Restore a snapshot
pub async fn restore(id: &str, dry_run: bool, yes: bool) -> Result<()> {
    // SECURITY: Validate snapshot ID
    if id.chars().any(|c| !c.is_ascii_alphanumeric() && c != '-') {
        anyhow::bail!("Invalid snapshot ID: {id}");
    }

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

    // Load snapshot
    let snapshot_path = snapshots_dir().join(format!("{id}.json"));
    if !snapshot_path.exists() {
        anyhow::bail!("Snapshot '{id}' not found");
    }

    let content = read_snapshot_file(&snapshot_path)
        .with_context(|| format!("Failed to read snapshot file: {}", snapshot_path.display()))?;
    let snapshot: Snapshot = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse snapshot: {}", snapshot_path.display()))?;

    // Capture current state
    let current = EnvironmentState::capture().await?;

    // Calculate diff
    println!("  {}", style::emphasis("Changes to apply:"));
    println!();

    // Runtime changes
    let mut runtime_changes = Vec::new();
    for (runtime, target_ver) in &snapshot.state.runtimes {
        let current_ver = current.runtimes.get(runtime);
        if current_ver != Some(target_ver) {
            runtime_changes.push((runtime.clone(), current_ver.cloned(), target_ver.clone()));
        }
    }

    if !runtime_changes.is_empty() {
        println!("  Runtimes:");
        for (runtime, from, to) in &runtime_changes {
            let from_str = from.as_deref().unwrap_or("(none)");
            println!(
                "    {} {} → {}",
                style::caution(&style::sanitize_terminal_text(runtime)),
                style::dim(&style::sanitize_terminal_text(from_str)),
                style::positive(&style::sanitize_terminal_text(to))
            );
        }
        println!();
    }

    // Package changes
    let current_pkgs: std::collections::HashSet<_> = current.packages.iter().collect();
    let target_pkgs: std::collections::HashSet<_> = snapshot.state.packages.iter().collect();

    let to_install: Vec<String> = target_pkgs
        .difference(&current_pkgs)
        .map(|s| (*s).clone())
        .collect();
    let to_remove: Vec<String> = current_pkgs
        .difference(&target_pkgs)
        .map(|s| (*s).clone())
        .collect();

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
    // SECURITY: Validate snapshot ID
    if id.chars().any(|c| !c.is_ascii_alphanumeric() && c != '-') {
        anyhow::bail!("Invalid snapshot ID: {id}");
    }

    let (_index_lock, mut index) = load_index_for_update()?;
    let snapshot_path = snapshots_dir().join(format!("{id}.json"));

    if !snapshot_path.exists() {
        anyhow::bail!("Snapshot '{id}' not found");
    }

    fs::remove_file(&snapshot_path)?;
    index.snapshots.retain(|s| s.id != id);
    save_index(&index)?;

    println!(
        "{} Deleted snapshot {}",
        style::positive("✓"),
        style::caution(id)
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
