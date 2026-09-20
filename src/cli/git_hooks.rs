//! Git hooks management for OMG CLI
//!
//! Installs and manages Git hooks for environment synchronization:
//! - pre-commit: Warn if omg.lock changed but not staged
//! - post-checkout: Suggest `omg env check` when the lockfile changes
//! - post-merge: Notify of environment changes

use anyhow::{Context, Result};
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use crate::cli::style;

/// Git hook scripts
const PRE_COMMIT_HOOK: &str = r#"#!/bin/sh
# OMG Pre-commit Hook
# Warns if omg.lock has unstaged changes

if [ -f "omg.lock" ]; then
    # Check if omg.lock is modified but not staged
    if git diff --name-only | grep -q "^omg.lock$"; then
        echo ""
        echo "⚠  Warning: omg.lock has unstaged changes"
        echo "   Consider staging it with: git add omg.lock"
        echo ""
    fi
fi

# Continue with commit
exit 0
"#;

const POST_CHECKOUT_HOOK: &str = r#"#!/bin/sh
# OMG Post-checkout Hook
# Auto-syncs environment when switching branches

PREV_HEAD=$1
NEW_HEAD=$2
BRANCH_CHECKOUT=$3

# Only run on branch checkout (not file checkout)
if [ "$BRANCH_CHECKOUT" = "1" ]; then
    # Check if omg.lock changed
    if [ -f "omg.lock" ]; then
        if ! git diff --quiet "$PREV_HEAD" "$NEW_HEAD" -- omg.lock 2>/dev/null; then
            echo ""
            echo "📦 OMG: Environment changed on branch switch"
            echo "   Run 'omg env check' to see differences"
            echo "   Run 'omg env sync' to synchronize"
            echo ""
        fi
    fi
fi

exit 0
"#;

const POST_MERGE_HOOK: &str = r#"#!/bin/sh
# OMG Post-merge Hook
# Notifies of environment changes after merge

# Check if omg.lock was part of the merge
if git diff-tree -r --name-only --no-commit-id ORIG_HEAD HEAD 2>/dev/null | grep -q "^omg.lock$"; then
    echo ""
    echo "📦 OMG: Environment changed after merge"
    echo "   Run 'omg env check' to see differences"
    echo "   Run 'omg env sync' to synchronize"
    echo ""
fi

exit 0
"#;

/// Resolve the hook directory Git actually executes.
///
/// `git rev-parse --git-path hooks` honors `core.hooksPath` and the common
/// repository directory used by linked worktrees. Appending `hooks` to
/// `--git-dir` does neither.
fn get_hooks_dir_at(cwd: &Path) -> Result<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--git-path", "hooks"])
        .current_dir(cwd)
        .output()
        .context("Failed to run git rev-parse")?;

    if !output.status.success() {
        anyhow::bail!("Not a git repository");
    }

    let hooks = String::from_utf8_lossy(&output.stdout).trim().to_string();
    anyhow::ensure!(!hooks.is_empty(), "Git returned an empty hooks path");
    let hooks = PathBuf::from(hooks);
    Ok(if hooks.is_absolute() {
        hooks
    } else {
        cwd.join(hooks)
    })
}

/// Get the hooks directory for the current repository.
fn get_hooks_dir() -> Result<PathBuf> {
    get_hooks_dir_at(&std::env::current_dir().context("Failed to read current directory")?)
}

fn read_hook_file(path: &Path) -> Result<Option<String>> {
    const MAX_HOOK_BYTES: u64 = 64 * 1024;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Failed to read git hook {}", path.display()));
        }
    };
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file(),
        "Git hook is not a regular file: {}",
        path.display()
    );
    anyhow::ensure!(
        metadata.len() <= MAX_HOOK_BYTES,
        "Git hook exceeds inspection limit: {}",
        path.display()
    );
    let mut content = String::new();
    file.take(MAX_HOOK_BYTES + 1).read_to_string(&mut content)?;
    anyhow::ensure!(
        content.len() as u64 <= MAX_HOOK_BYTES,
        "Git hook exceeds inspection limit: {}",
        path.display()
    );
    Ok(Some(content))
}

fn is_generated_hook(name: &str, content: &str) -> bool {
    match name {
        "pre-commit" => content == PRE_COMMIT_HOOK,
        "post-checkout" => content == POST_CHECKOUT_HOOK,
        "post-merge" => content == POST_MERGE_HOOK,
        _ => false,
    }
}

/// Install all Git hooks
pub fn install(force: bool) -> Result<()> {
    println!("{} Installing Git hooks...\n", style::header("OMG"));

    let hooks_dir = get_hooks_dir()?;
    fs::create_dir_all(&hooks_dir)?;

    let hooks = [
        ("pre-commit", PRE_COMMIT_HOOK),
        ("post-checkout", POST_CHECKOUT_HOOK),
        ("post-merge", POST_MERGE_HOOK),
    ];

    let mut installed = 0;
    let mut skipped = 0;

    for (name, content) in hooks {
        let hook_path = hooks_dir.join(name);

        // Check if hook already exists
        if !force {
            match read_hook_file(&hook_path)? {
                Some(existing) if existing == content => {
                    println!("  {} {} (already installed)", style::dim("•"), name);
                    continue;
                }
                Some(_) => {
                    println!(
                        "  {} {} (exists, use --force to overwrite)",
                        style::warning("⚠"),
                        name
                    );
                    skipped += 1;
                    continue;
                }
                None => {}
            }
        }

        #[cfg(unix)]
        let wrote = crate::core::safe_ops::write_executable(&hook_path, content.as_bytes(), force)
            .with_context(|| format!("Failed to write {name} hook"))?;
        #[cfg(not(unix))]
        let wrote = {
            if force {
                fs::write(&hook_path, content)?;
                true
            } else {
                match fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&hook_path)
                {
                    Ok(mut file) => {
                        use std::io::Write as _;
                        file.write_all(content.as_bytes())?;
                        true
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
                    Err(error) => return Err(error.into()),
                }
            }
        };

        if wrote {
            println!("  {} {}", style::success("✓"), name);
            installed += 1;
        } else {
            println!(
                "  {} {} (appeared concurrently; skipped)",
                style::warning("⚠"),
                name
            );
            skipped += 1;
        }
    }

    println!();
    if installed > 0 {
        println!("{} Installed {} hook(s)", style::success("✓"), installed);
    }
    if skipped > 0 {
        println!(
            "{} Skipped {} existing hook(s)",
            style::warning("⚠"),
            skipped
        );
    }

    println!();
    println!("{}", style::dim("Hooks will:"));
    println!("  • Warn if omg.lock has unstaged changes (pre-commit)");
    println!("  • Notify of environment changes on branch switch (post-checkout)");
    println!("  • Notify of environment changes after merge (post-merge)");

    Ok(())
}

/// Uninstall Git hooks
pub fn uninstall() -> Result<()> {
    uninstall_from(&get_hooks_dir()?)
}

fn uninstall_from(hooks_dir: &Path) -> Result<()> {
    println!("{} Uninstalling Git hooks...\n", style::header("OMG"));
    let hooks = ["pre-commit", "post-checkout", "post-merge"];

    let mut removed = 0;

    for name in hooks {
        let hook_path = hooks_dir.join(name);

        match read_hook_file(&hook_path)? {
            None => {
                println!("  {} {} (not installed)", style::dim("•"), name);
                continue;
            }
            Some(content) if !is_generated_hook(name, &content) => {
                println!(
                    "  {} {} (not an unmodified current OMG hook, skipping)",
                    style::warning("⚠"),
                    name
                );
                continue;
            }
            Some(_) => {}
        }

        fs::remove_file(&hook_path).with_context(|| format!("Failed to remove {name} hook"))?;

        println!("  {} {}", style::success("✓"), name);
        removed += 1;
    }

    println!();
    if removed > 0 {
        println!("{} Removed {} hook(s)", style::success("✓"), removed);
    } else {
        println!("{}", style::dim("No OMG hooks to remove"));
    }

    Ok(())
}

/// Show hook status
pub fn status() -> Result<()> {
    println!("{} Git Hooks Status\n", style::header("OMG"));

    let Ok(hooks_dir) = get_hooks_dir() else {
        println!("  {} Not a git repository", style::error("✗"));
        return Ok(());
    };

    let hooks = ["pre-commit", "post-checkout", "post-merge"];

    for name in hooks {
        let hook_path = hooks_dir.join(name);

        match read_hook_file(&hook_path)? {
            None => {
                println!("  {} {} - not installed", style::dim("○"), name);
            }
            Some(content) if is_generated_hook(name, &content) => {
                println!("  {} {} - installed (OMG)", style::success("●"), name);
            }
            Some(_) => {
                println!(
                    "  {} {} - installed (unrecognized or modified)",
                    style::warning("●"),
                    name
                );
            }
        }
    }

    println!();
    println!(
        "  {} {}",
        style::dim("Hooks directory:"),
        hooks_dir.display()
    );

    Ok(())
}

/// Hooks that OMG installs and can run manually.
const MANAGED_HOOKS: &[&str] = &["pre-commit", "post-checkout", "post-merge"];

/// Run a specific hook manually
pub fn run_hook(hook_name: &str) -> Result<()> {
    // SECURITY: only the hooks OMG manages may be executed; joining raw input
    // onto the hooks directory would allow `omg hooks run ../../some/exec`
    // to escape .git/hooks entirely.
    anyhow::ensure!(
        MANAGED_HOOKS.contains(&hook_name),
        "Unknown hook '{hook_name}'. Managed hooks: {}",
        MANAGED_HOOKS.join(", ")
    );

    let hooks_dir = get_hooks_dir()?;
    let hook_path = hooks_dir.join(hook_name);

    if !hook_path.exists() {
        anyhow::bail!("Hook '{hook_name}' is not installed");
    }

    println!("{} Running {hook_name} hook...\n", style::header("OMG"));

    let status = std::process::Command::new(&hook_path)
        .status()
        .with_context(|| format!("Failed to execute {hook_name} hook"))?;

    if !status.success() {
        anyhow::bail!("Hook '{hook_name}' failed: {status}");
    }
    println!("\n{} Hook completed successfully", style::success("✓"));

    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn uninstall_preserves_custom_hooks_with_omg_markers() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let fixtures = [
            (
                "pre-commit",
                format!("{PRE_COMMIT_HOOK}\n# Custom automation\ncustom_check\n"),
            ),
            (
                "post-checkout",
                "#!/bin/sh\n# OMG integration notes\ncustom_check\n".to_string(),
            ),
            ("post-merge", PRE_COMMIT_HOOK.to_string()),
        ];
        for (name, content) in &fixtures {
            fs::write(directory.path().join(name), content)?;
        }
        uninstall_from(directory.path())?;
        for (name, content) in fixtures {
            assert_eq!(fs::read_to_string(directory.path().join(name))?, content);
        }
        Ok(())
    }

    #[test]
    fn uninstall_removes_exact_generated_hooks_only() -> Result<()> {
        let directory = tempfile::tempdir()?;
        for (name, content) in [
            ("pre-commit", PRE_COMMIT_HOOK),
            ("post-checkout", POST_CHECKOUT_HOOK),
            ("post-merge", POST_MERGE_HOOK),
        ] {
            fs::write(directory.path().join(name), content)?;
        }
        let unrelated = directory.path().join("pre-push");
        fs::write(&unrelated, "custom automation")?;
        uninstall_from(directory.path())?;
        for name in MANAGED_HOOKS {
            assert!(!directory.path().join(name).exists());
        }
        assert_eq!(fs::read_to_string(unrelated)?, "custom automation");
        uninstall_from(directory.path())?;
        Ok(())
    }

    #[test]
    fn hook_inspection_rejects_oversized_files() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("pre-commit");
        fs::File::create(&path)?.set_len(65 * 1024)?;
        assert!(uninstall_from(directory.path()).is_err());
        assert_eq!(fs::metadata(path)?.len(), 65 * 1024);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn uninstall_preserves_symlinks_and_special_files() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let target = directory.path().join("custom-managed-hook");
        fs::write(&target, PRE_COMMIT_HOOK)?;
        let path = directory.path().join("pre-commit");
        std::os::unix::fs::symlink(&target, &path)?;
        assert!(uninstall_from(directory.path()).is_err());
        assert!(fs::symlink_metadata(&path)?.file_type().is_symlink());
        assert_eq!(fs::read_to_string(target)?, PRE_COMMIT_HOOK);
        fs::remove_file(&path)?;
        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRWXU)?;
        assert!(uninstall_from(directory.path()).is_err());
        assert!(fs::symlink_metadata(path).is_ok());
        Ok(())
    }

    fn git(cwd: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(cwd)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    #[test]
    fn hooks_path_honors_core_hooks_path() {
        let directory = tempfile::tempdir().unwrap();
        git(directory.path(), &["init", "-q"]);
        git(
            directory.path(),
            &["config", "core.hooksPath", "custom-hooks"],
        );

        assert_eq!(
            get_hooks_dir_at(directory.path()).unwrap(),
            directory.path().join("custom-hooks")
        );
    }

    #[test]
    fn linked_worktree_uses_the_common_hooks_directory() {
        let directory = tempfile::tempdir().unwrap();
        let main = directory.path().join("main");
        let worktree = directory.path().join("worktree");
        fs::create_dir(&main).unwrap();
        git(&main, &["init", "-q"]);
        git(&main, &["config", "user.email", "test@example.test"]);
        git(&main, &["config", "user.name", "Test User"]);
        fs::write(main.join("tracked"), "test").unwrap();
        git(&main, &["add", "tracked"]);
        git(&main, &["commit", "-qm", "initial"]);
        git(
            &main,
            &[
                "worktree",
                "add",
                "-q",
                "-b",
                "test-worktree",
                worktree.to_str().unwrap(),
            ],
        );

        // macOS tempdirs often live under `/var/folders` while `git rev-parse`
        // reports the canonical `/private/var/folders` path.
        assert_eq!(
            get_hooks_dir_at(&worktree).unwrap().canonicalize().unwrap(),
            main.join(".git/hooks").canonicalize().unwrap()
        );
    }

    #[test]
    fn test_read_hook_file_missing_is_none() {
        let missing = tempfile::TempDir::new()
            .unwrap()
            .path()
            .join("does-not-exist");
        assert!(read_hook_file(&missing).unwrap().is_none());
    }

    #[test]
    fn test_read_hook_file_reads_content() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("pre-commit");
        fs::write(&path, "# OMG\n").unwrap();
        assert_eq!(read_hook_file(&path).unwrap().as_deref(), Some("# OMG\n"));
    }

    #[test]
    fn test_read_hook_file_unreadable_errors() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("pre-commit");
        fs::write(&path, "# OMG\n").unwrap();
        let original = fs::metadata(&path).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        }
        let blocked = fs::read_to_string(&path).is_err();
        let result = read_hook_file(&path);
        let _ = fs::set_permissions(&path, original);
        if !blocked {
            return;
        }
        assert!(
            result.is_err(),
            "unreadable hook file must fail closed, got {result:?}"
        );
    }
}
