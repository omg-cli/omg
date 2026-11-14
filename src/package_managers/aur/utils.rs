use std::path::{Path, PathBuf};

use alpm_types::SystemArchitecture;
use anyhow::{Context, Result, bail};
use tokio::process::Command;

pub(in crate::package_managers) fn current_arch() -> Option<SystemArchitecture> {
    architecture_for_rust_target(std::env::consts::ARCH)
}

fn architecture_for_rust_target(architecture: &str) -> Option<SystemArchitecture> {
    match architecture {
        "x86_64" => Some(SystemArchitecture::X86_64),
        "aarch64" => Some(SystemArchitecture::Aarch64),
        "arm" => Some(SystemArchitecture::Arm),
        "x86" => Some(SystemArchitecture::I686),
        _ => None,
    }
}

pub(in crate::package_managers) fn package_architecture_matches(
    target: &str,
    package_architecture: &str,
) -> bool {
    architecture_for_rust_target(target).is_some_and(|host| {
        package_architecture == "any" || package_architecture == host.to_string()
    })
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// SECURITY: Path Validation (TOCTOU Prevention)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Validate that a path is safely inside the expected base directory.
/// Prevents symlink attacks and directory traversal.
///
/// # Security
/// This function canonicalizes both paths and verifies the target
/// starts with the base, preventing:
/// - Symlink escapes (`build_dir/evil -> /etc`)
/// - Directory traversal (`build_dir/../../../etc`)
pub fn validate_path_inside(base: &Path, target: &Path) -> Result<PathBuf> {
    // Canonicalize base - must exist
    let base_canonical = base
        .canonicalize()
        .with_context(|| format!("Base directory does not exist: {}", base.display()))?;

    // For target, if it exists, canonicalize it. If not, canonicalize parent and append filename.
    let target_canonical = if target.exists() {
        target
            .canonicalize()
            .with_context(|| format!("Failed to canonicalize: {}", target.display()))?
    } else {
        // Path doesn't exist yet - canonicalize parent and append leaf
        let parent = target
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Path has no parent: {}", target.display()))?;
        let leaf = target
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("Path has no filename: {}", target.display()))?;

        let parent_canonical = parent
            .canonicalize()
            .with_context(|| format!("Parent directory does not exist: {}", parent.display()))?;

        parent_canonical.join(leaf)
    };

    // Verify target is inside base
    if !target_canonical.starts_with(&base_canonical) {
        bail!(
            "Security: Path escapes base directory!\n  Base: {}\n  Target: {}",
            base_canonical.display(),
            target_canonical.display()
        );
    }

    Ok(target_canonical)
}

/// Check if a path is a symlink (for critical operations that shouldn't follow symlinks).
///
/// Fails closed: a metadata error (permissions, loop, …) is returned as
/// [`Err`] so security callers reject the path instead of treating an
/// undecidable path as "not a symlink".
///
/// # Errors
/// Returns the underlying [`std::io::Error`] when `symlink_metadata` fails.
pub fn is_symlink(path: &Path) -> std::io::Result<bool> {
    Ok(path.symlink_metadata()?.file_type().is_symlink())
}

/// Validate a package build directory is safe to use.
/// Rejects symlinks and paths that escape the build root.
/// Fails closed when the directory's type cannot be determined.
pub fn validate_build_dir(build_root: &Path, package_name: &str) -> Result<PathBuf> {
    let pkg_dir = build_root.join(package_name);

    // If pkg_dir exists, verify it's not a symlink; an unreadable directory
    // is rejected rather than silently allowed through.
    match std::fs::symlink_metadata(&pkg_dir) {
        Ok(meta) if meta.file_type().is_symlink() => bail!(
            "Security: Package directory is a symlink (potential attack): {}",
            pkg_dir.display()
        ),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "Security: Cannot inspect package directory (failing closed): {}",
                    pkg_dir.display()
                )
            });
        }
    }

    // Validate containment even before the package directory exists. Waiting
    // until after creation lets an untrusted name containing `..` escape the
    // build root before there is anything to canonicalize.
    validate_path_inside(build_root, &pkg_dir)
}

#[inline]
#[must_use]
pub fn has_word_boundary_match(haystack: &str, needle: &str) -> bool {
    for (pos, _) in haystack.match_indices(needle) {
        if pos == 0
            || haystack.as_bytes()[pos - 1].is_ascii_whitespace()
            || haystack.as_bytes()[pos - 1] == b'-'
            || haystack.as_bytes()[pos - 1] == b'_'
            || haystack.as_bytes()[pos - 1] == b'.'
        {
            return true;
        }
    }
    false
}

/// User name of the original (pre-`sudo`/`doas`) invoker, regardless of
/// whether we are currently running as root.
///
/// Distinct from [`original_user`], which only resolves when running as
/// root and is used to decide whether de-escalation is needed at all.
#[must_use]
pub fn build_user() -> Option<String> {
    std::env::var("SUDO_USER")
        .ok()
        .or_else(|| std::env::var("DOAS_USER").ok())
}

pub fn original_user() -> Option<String> {
    if !crate::core::is_root() {
        return None;
    }
    build_user()
}

fn require_account_home(user: &str, home: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    let home = home.with_context(|| format!("Original user '{user}' has no system account"))?;
    anyhow::ensure!(
        home.is_absolute(),
        "System account for '{user}' has a non-absolute home: {}",
        home.display()
    );
    Ok(home)
}

pub fn original_user_home() -> anyhow::Result<Option<PathBuf>> {
    let Some(user) = original_user() else {
        return Ok(None);
    };
    let account = nix::unistd::User::from_name(&user)
        .with_context(|| format!("Failed to resolve system account for original user '{user}'"))?;
    require_account_home(&user, account.map(|account| account.dir)).map(Some)
}

pub(crate) fn sudo_as_user_program(user: &str, program: &str) -> Result<std::process::Command> {
    anyhow::ensure!(
        !user.is_empty() && !user.starts_with('-') && !user.chars().any(char::is_control),
        "Invalid original user name"
    );
    let account = nix::unistd::User::from_name(user)
        .with_context(|| format!("Failed to resolve original user '{user}'"))?
        .with_context(|| format!("Original user '{user}' has no system account"))?;
    anyhow::ensure!(
        account.uid.as_raw() != 0,
        "Refusing to de-escalate a command to the root account"
    );

    let program = crate::core::privilege::root_controlled_program_path(program)?;
    let mut command = crate::core::privilege::system_command("sudo")?;
    command.args(["-H", "-u", user, "--"]).arg(program);
    Ok(command)
}

fn sudo_as_user_command(
    user: &str,
    program: &str,
    flags: &[&str],
    path: &Path,
) -> Result<std::process::Command> {
    anyhow::ensure!(
        path.is_absolute() && path.parent().is_some_and(|parent| parent != path),
        "Refusing unsafe user-owned path: {}",
        path.display()
    );
    let mut command = sudo_as_user_program(user, program)?;
    command.args(flags).arg("--").arg(path.as_os_str());
    Ok(command)
}

fn ensure_sudo_success(
    status: std::process::ExitStatus,
    user: &str,
    operation: &str,
    path: &Path,
) -> Result<()> {
    anyhow::ensure!(
        status.success(),
        "Failed to {operation} as user '{user}': {}",
        path.display()
    );
    Ok(())
}

pub async fn create_dir_as_user(path: &Path) -> Result<()> {
    if let Some(user) = original_user() {
        let status = Command::from(sudo_as_user_command(&user, "mkdir", &["-p"], path)?)
            .status()
            .await
            .with_context(|| {
                format!(
                    "Failed to create directory as user '{user}': {}",
                    path.display()
                )
            })?;

        ensure_sudo_success(status, &user, "create directory", path)
    } else {
        tokio::fs::create_dir_all(path)
            .await
            .with_context(|| format!("Failed to create directory: {}", path.display()))
    }
}

pub async fn remove_dir_as_user(path: &Path) -> Result<()> {
    if let Some(user) = original_user() {
        let status = Command::from(sudo_as_user_command(&user, "rm", &["-rf"], path)?)
            .status()
            .await
            .with_context(|| {
                format!(
                    "Failed to remove directory as user '{user}': {}",
                    path.display()
                )
            })?;

        ensure_sudo_success(status, &user, "remove directory", path)
    } else {
        tokio::fs::remove_dir_all(path)
            .await
            .with_context(|| format!("Failed to remove directory: {}", path.display()))
    }
}

pub fn create_dir_as_user_sync(path: &Path) -> Result<()> {
    if let Some(user) = original_user() {
        let status = sudo_as_user_command(&user, "mkdir", &["-p"], path)?
            .status()
            .with_context(|| {
                format!(
                    "Failed to create directory as user '{user}': {}",
                    path.display()
                )
            })?;

        ensure_sudo_success(status, &user, "create directory", path)
    } else {
        std::fs::create_dir_all(path)
            .with_context(|| format!("Failed to create directory: {}", path.display()))
    }
}

/// Open the stable inode shared by AUR builders, metadata and cleanup.
pub(in crate::package_managers) fn open_build_lifecycle_lock(
    build_dir: &Path,
) -> Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let lock_path = build_dir.with_added_extension("lifecycle.lock");
    let parent = lock_path
        .parent()
        .context("AUR build directory has no parent")?;
    create_dir_as_user_sync(parent)?;
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    let (file, created) = match options.create_new(true).open(&lock_path) {
        Ok(file) => (file, true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            (options.create_new(false).open(&lock_path)?, false)
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!("Failed to open AUR lifecycle lock {}", lock_path.display())
            });
        }
    };
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.nlink() == 1,
        "AUR lifecycle lock must be a single-link regular file"
    );
    if let Some(user) = original_user() {
        let account = nix::unistd::User::from_name(&user)?
            .with_context(|| format!("Original user '{user}' has no system account"))?;
        if created {
            nix::unistd::fchown(&file, Some(account.uid), Some(account.gid))
                .context("Failed to set AUR lifecycle lock ownership")?;
        } else {
            anyhow::ensure!(
                metadata.uid() == account.uid.as_raw(),
                "Existing AUR lifecycle lock is not owned by the original user"
            );
        }
    }
    Ok(file)
}

/// Open an effective-user-owned coordination inode that is not group/other writable.
pub(in crate::package_managers) fn open_effective_user_lock(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    let file = match options.create_new(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            options.create_new(false).open(path)?
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Failed to open AUR lock {}", path.display()));
        }
    };
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.nlink() == 1,
        "AUR lock must be a single-link regular file: {}",
        path.display()
    );
    anyhow::ensure!(
        metadata.uid() == nix::unistd::geteuid().as_raw() && metadata.mode() & 0o022 == 0,
        "AUR lock must be owned by the effective user and not group/other writable: {}",
        path.display()
    );
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires an explicitly provisioned disposable native root fixture"]
    fn native_lifecycle_original_user_ownership() -> Result<()> {
        use std::io::Write;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        anyhow::ensure!(
            crate::core::is_root()
                && std::env::var("OMG_ARCH_INSTALL_FIXTURE").as_deref() == Ok("isolated-container"),
            "lifecycle ownership fixture requires the disposable native root environment"
        );
        let account = nix::unistd::User::from_name("nobody")?
            .context("disposable fixture requires the nobody account")?;
        anyhow::ensure!(
            account.uid.as_raw() != 0,
            "fixture account must not be root"
        );
        let owner = tempfile::Builder::new()
            .prefix("omg-root-lifecycle-")
            .permissions(std::fs::Permissions::from_mode(0o755))
            .tempdir_in("/var/tmp")?;
        let build = owner.path().join("aur");
        let path = build.with_added_extension("lifecycle.lock");
        temp_env::with_vars(
            [("SUDO_USER", Some("nobody")), ("DOAS_USER", None)],
            || -> Result<()> {
                let mut fresh = open_build_lifecycle_lock(&build)?;
                let metadata = fresh.metadata()?;
                assert_eq!(metadata.uid(), account.uid.as_raw());
                assert_eq!(metadata.gid(), account.gid.as_raw());
                assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
                fresh.write_all(b"owned lifecycle")?;
                drop(fresh);

                let existing = open_build_lifecycle_lock(&build)?;
                assert_eq!(existing.metadata()?.ino(), metadata.ino());
                assert_eq!(existing.metadata()?.uid(), account.uid.as_raw());
                nix::unistd::fchown(
                    &existing,
                    Some(nix::unistd::Uid::from_raw(0)),
                    Some(nix::unistd::Gid::from_raw(0)),
                )
                .expect("root fixture restores lifecycle ownership before testing refusal");
                drop(existing);
                let error = open_build_lifecycle_lock(&build)
                    .expect_err("an existing inode owned by root must not impersonate nobody");
                assert_eq!(
                    error.to_string(),
                    "Existing AUR lifecycle lock is not owned by the original user"
                );
                assert_eq!(std::fs::read(&path)?, b"owned lifecycle");
                assert_eq!(std::fs::metadata(&path)?.uid(), 0);
                Ok(())
            },
        )?;

        let missing = format!(
            "omg-missing-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        );
        assert!(nix::unistd::User::from_name(&missing)?.is_none());
        let absent = owner.path().join("not-created/aur");
        temp_env::with_vars(
            [("SUDO_USER", Some(missing.as_str())), ("DOAS_USER", None)],
            || {
                let error = open_build_lifecycle_lock(&absent)
                    .expect_err("an unknown original user must refuse before creating directories");
                assert_eq!(
                    error.to_string(),
                    format!("Original user '{missing}' has no system account")
                );
            },
        );
        assert!(!owner.path().join("not-created").exists());
        assert_eq!(std::fs::read(&path)?, b"owned lifecycle");
        assert_eq!(owner.path().read_dir()?.count(), 1);
        Ok(())
    }

    #[test]
    fn effective_user_locks_refuse_writable_existing_inodes_without_repair() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let owner = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("private coordination owner");
        let path = owner.path().join("coordination.lock");
        let mut file = open_effective_user_lock(&path).expect("fresh owned coordination file");
        assert_eq!(
            file.metadata()
                .expect("coordination metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        file.write_all(b"owned coordination")
            .expect("inert coordination content");
        drop(file);
        drop(open_effective_user_lock(&path).expect("existing safe coordination file"));

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
            .expect("private writable-inode fault");
        let error = open_effective_user_lock(&path)
            .expect_err("group/other writable coordination files must be refused");
        assert!(
            error.to_string().contains("not group/other writable"),
            "{error:#}"
        );
        assert_eq!(
            std::fs::read(&path).expect("preserved inode content"),
            b"owned coordination"
        );
        assert_eq!(
            std::fs::metadata(&path)
                .expect("preserved inode metadata")
                .permissions()
                .mode()
                & 0o777,
            0o666,
            "refusal must not silently repair an existing inode"
        );
    }

    #[test]
    fn effective_user_lock_open_errors_preserve_path_and_io_cause() {
        use std::os::unix::fs::PermissionsExt;

        let owner = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("private coordination owner");
        let regular_parent = owner.path().join("regular");
        std::fs::write(&regular_parent, b"unrelated parent").expect("private regular parent");
        for (path, expected) in [
            (
                owner.path().join("missing/child.lock"),
                std::io::ErrorKind::NotFound,
            ),
            (
                regular_parent.join("child.lock"),
                std::io::ErrorKind::NotADirectory,
            ),
        ] {
            let error =
                open_effective_user_lock(&path).expect_err("invalid parent must refuse opening");
            assert_eq!(
                error
                    .downcast_ref::<std::io::Error>()
                    .map(std::io::Error::kind),
                Some(expected),
                "{error:#}"
            );
            assert_eq!(
                error.to_string(),
                format!("Failed to open AUR lock {}", path.display())
            );
        }
        assert_eq!(
            std::fs::read(regular_parent).expect("preserved parent"),
            b"unrelated parent"
        );
        assert!(!owner.path().join("missing").exists());
    }

    #[test]
    fn lifecycle_lock_initial_open_errors_preserve_path_and_io_cause() {
        use std::os::unix::fs::PermissionsExt;

        const TEST: &str = "package_managers::aur::utils::tests::lifecycle_lock_initial_open_errors_preserve_path_and_io_cause";
        if crate::config::Settings::rerun_test_unprivileged(TEST) {
            return;
        }
        assert!(
            !crate::core::is_root(),
            "lifecycle fixture requires an ordinary UID"
        );
        let owner = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("private lifecycle owner");
        drop(
            open_build_lifecycle_lock(&owner.path().join("ordinary"))
                .expect("ordinary lifecycle inode"),
        );
        let build = owner.path().join("x".repeat(4096));
        let path = build.with_added_extension("lifecycle.lock");
        let error = open_build_lifecycle_lock(&build).expect_err("oversized lock name must fail");
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .and_then(std::io::Error::raw_os_error),
            Some(nix::libc::ENAMETOOLONG),
            "{error:#}"
        );
        assert_eq!(
            error.to_string(),
            format!("Failed to open AUR lifecycle lock {}", path.display())
        );
        assert_eq!(
            owner
                .path()
                .read_dir()
                .expect("private lifecycle owner entries")
                .count(),
            1
        );
    }

    #[test]
    fn rust_x86_maps_to_arch_i686() {
        assert_eq!(
            architecture_for_rust_target("x86"),
            Some(SystemArchitecture::I686)
        );
        assert!(package_architecture_matches("x86", "i686"));
        assert!(package_architecture_matches("x86", "any"));
        assert!(!package_architecture_matches("x86", "x86"));
        assert!(!package_architecture_matches("unsupported", "any"));
    }

    #[test]
    fn account_home_never_invents_a_home_directory() {
        assert_eq!(
            require_account_home("alice", Some(PathBuf::from("/var/home/alice"))).unwrap(),
            PathBuf::from("/var/home/alice")
        );
        let missing =
            require_account_home("alice", None).expect_err("missing account record must fail");
        assert!(missing.to_string().contains("no system account"));
        let relative = require_account_home("alice", Some(PathBuf::from("home/alice")))
            .expect_err("relative account home must fail");
        assert!(relative.to_string().contains("non-absolute"));
    }

    #[test]
    fn sudo_as_user_command_rejects_unsafe_identity_and_paths() {
        let error = sudo_as_user_program("-n", "rm").expect_err("unsafe user must fail");
        assert_eq!(error.to_string(), "Invalid original user name");
        for path in ["-cache", "/"] {
            let error = sudo_as_user_command("builder", "rm", &["-rf"], Path::new(path))
                .expect_err("unsafe path must fail");
            assert_eq!(
                error.to_string(),
                format!("Refusing unsafe user-owned path: {path}")
            );
        }
    }

    #[test]
    fn is_symlink_detects_symlinks_and_regular_files() {
        let temp = tempfile::tempdir().expect("temp dir");
        let file = temp.path().join("regular.txt");
        std::fs::write(&file, "x").expect("write");
        let link = temp.path().join("link");

        // Unix-only crate: symlinks are always available.
        {
            std::os::unix::fs::symlink(&file, &link).expect("symlink");
            assert!(is_symlink(&link).expect("link must be inspected"));
        }
        assert!(!is_symlink(&file).expect("file must be inspected"));
    }

    #[test]
    fn is_symlink_fails_closed_for_missing_path() {
        // Fail-closed contract: an undecidable path is an Err, never `false`.
        let temp = tempfile::tempdir().expect("private temp dir");
        let missing = temp.path().join("missing");
        assert!(
            is_symlink(&missing).is_err(),
            "missing path must propagate an error instead of reporting 'not a symlink'"
        );
    }

    #[test]
    fn validate_build_dir_rejects_nonexistent_traversal_target() {
        let temp = tempfile::tempdir().expect("temp dir");
        let build_root = temp.path().join("root");
        std::fs::create_dir_all(&build_root).expect("build root");

        let error = validate_build_dir(&build_root, "../outside")
            .expect_err("nonexistent traversal target must be rejected");
        assert!(error.to_string().contains("escapes base directory"));
        assert!(!temp.path().join("outside").exists());
    }

    #[test]
    fn validate_build_dir_fails_closed_on_uninspectable_directory() {
        use std::os::unix::fs::PermissionsExt;

        if crate::config::Settings::rerun_test_unprivileged(
            "package_managers::aur::utils::tests::validate_build_dir_fails_closed_on_uninspectable_directory",
        ) {
            return;
        }
        assert!(
            !crate::core::is_root(),
            "permission fixture must not run as root"
        );

        let temp = tempfile::tempdir().expect("temp dir");
        let build_root = temp.path().join("root");
        std::fs::create_dir_all(&build_root).expect("build root");
        let pkg_dir = build_root.join("mypkg");
        std::fs::create_dir(&pkg_dir).expect("pkg dir");

        let meta = std::fs::metadata(&build_root).expect("meta");
        let original = meta.permissions();
        let mut perms = original.clone();
        perms.set_mode(0o000);
        std::fs::set_permissions(&build_root, perms).expect("chmod");

        let result = validate_build_dir(&build_root, "mypkg");
        let denied = std::fs::symlink_metadata(&pkg_dir)
            .expect_err("fixture must enforce permission denial");
        assert_eq!(denied.kind(), std::io::ErrorKind::PermissionDenied);
        println!(
            "[omg-permission-fixture] test=package_managers::aur::utils::tests::validate_build_dir_fails_closed_on_uninspectable_directory uid={} errno=PermissionDenied",
            nix::unistd::geteuid()
        );

        std::fs::set_permissions(&build_root, original).expect("restore chmod");

        let error = result.expect_err("uninspectable directory must fail closed");
        assert!(
            error.chain().any(|cause| cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|cause| cause.kind() == std::io::ErrorKind::PermissionDenied)),
            "production must retain the permission denial: {error:#}"
        );
        assert!(error.to_string().contains("fail"), "got: {error}");
    }
}
