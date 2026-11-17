//! Selected managed-runtime authority retained through package installation.

use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};

use super::common::{RuntimeLease, get_current_version, try_lock_runtime_use};
use super::security::{ReviewMode, RuntimeAdmission, RuntimeSecurity};

pub(crate) trait ReviewedTool {
    fn verify(&self, prefix: &Path) -> Result<()>;
}

pub(crate) struct ManagedRuntime {
    runtime: String,
    versions: PathBuf,
    version: String,
    root: PathBuf,
    admission: RuntimeAdmission,
    _lease: RuntimeLease,
}

impl ManagedRuntime {
    pub(crate) fn open(
        runtime: &str,
        tools_dir: &Path,
        security: &RuntimeSecurity,
    ) -> Result<Self> {
        ensure!(
            matches!(runtime, "rust" | "go" | "python"),
            "Unsupported package-manager runtime: {runtime}"
        );
        let data_root = tools_dir
            .parent()
            .context("Tools directory has no OMG data root")?
            .canonicalize()?;
        let versions_root = data_root.join("versions");
        ensure!(
            std::fs::symlink_metadata(&versions_root)?.is_dir()
                && versions_root.canonicalize()?.parent() == Some(data_root.as_path()),
            "Managed runtime versions escape the OMG data root"
        );
        let versions = versions_root.join(runtime);
        ensure!(
            std::fs::symlink_metadata(&versions)?.is_dir()
                && versions.canonicalize()?.parent() == Some(versions_root.as_path()),
            "Managed {runtime} versions escape the OMG versions tree"
        );
        let lease = try_lock_runtime_use(&versions)?;
        let version = get_current_version(&versions).with_context(|| {
            format!(
                "Package installation requires a selected OMG-managed {runtime}; run omg use {runtime} <version> first"
            )
        })?;
        crate::core::security::validate_runtime_version(&version)?;
        let root = versions.join(&version).canonicalize()?;
        ensure!(
            root.parent() == Some(versions.as_path()),
            "Selected managed {runtime} escapes its versions tree"
        );
        let admission = security.installed(runtime, &root, ReviewMode::FreshAttended)?;
        let selected = Self {
            runtime: runtime.to_owned(),
            versions,
            version,
            root,
            admission,
            _lease: lease,
        };
        selected.verify()?;
        Ok(selected)
    }

    pub(crate) fn root(&self) -> Result<PathBuf> {
        self.verify()?;
        Ok(self.root.clone())
    }

    pub(crate) fn bin(&self) -> Result<PathBuf> {
        self.verify()?;
        let bin = self.root.join("bin").canonicalize()?;
        ensure!(
            bin.starts_with(&self.root) && bin.is_dir(),
            "Managed {} executable directory escapes its runtime",
            self.runtime
        );
        Ok(bin)
    }

    pub(crate) fn command_path(&self, name: &str) -> Result<PathBuf> {
        let mut components = Path::new(name).components();
        ensure!(
            matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none(),
            "Managed command must be a single executable name"
        );
        let command = self.bin()?.join(name).canonicalize()?;
        ensure!(
            command.starts_with(&self.root),
            "Managed {} command escapes its runtime",
            self.runtime
        );
        let metadata = std::fs::metadata(&command)?;
        ensure!(metadata.is_file(), "Managed command is not a regular file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                metadata.permissions().mode() & 0o111 != 0,
                "Managed command is not executable"
            );
        }
        self.verify()?;
        Ok(command)
    }

    pub(crate) fn verify(&self) -> Result<()> {
        ensure!(
            get_current_version(&self.versions).as_deref() == Some(self.version.as_str())
                && self.versions.join(&self.version).canonicalize()? == self.root,
            "Selected managed {} changed after advisory review",
            self.runtime
        );
        self.admission.verify(&self.root)
    }

    pub(crate) fn identity_context(&self) -> Result<String> {
        let root = self.root()?;
        Ok(serde_json::to_string(&serde_json::json!({
            "runtime": self.runtime,
            "version": self.version,
            "root": root,
            "admission": self.admission.identity_context()?,
        }))?)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn fixture(runtime: &str, commands: &[&str]) -> Result<(tempfile::TempDir, PathBuf)> {
        let owner = tempfile::tempdir()?;
        let root = owner.path().join("versions").join(runtime).join("1.78.0");
        fs::create_dir_all(root.join("bin"))?;
        fs::create_dir_all(root.join("lib"))?;
        for command in commands {
            fs::write(
                root.join("bin").join(command),
                b"controlled fixture executable",
            )?;
            fs::set_permissions(
                root.join("bin").join(command),
                fs::Permissions::from_mode(0o755),
            )?;
        }
        fs::write(
            root.join("lib/implementation"),
            b"controlled implementation",
        )?;
        super::super::security::fixture_prepare(runtime, "1.78.0", &root, &root)?;
        symlink(
            "1.78.0",
            root.parent()
                .context("Missing fixture parent")?
                .join("current"),
        )?;
        Ok((owner, root))
    }

    #[test]
    fn selected_package_runtimes_share_use_and_exclude_mutation() -> Result<()> {
        let (owner, root) = fixture("rust", &["cargo", "rustc"])?;
        let tools = owner.path().join("tools");
        let first = ManagedRuntime::open("rust", &tools, &RuntimeSecurity::fixture())?;
        let second = ManagedRuntime::open("rust", &tools, &RuntimeSecurity::fixture())?;
        assert_eq!(first.root()?, root.canonicalize()?);
        assert_eq!(
            first.command_path("cargo")?,
            root.join("bin/cargo").canonicalize()?
        );
        assert!(
            super::super::common::try_lock_runtime_file(root.parent().unwrap(), ".mutation.lock")
                .is_err()
        );
        drop(first);
        assert!(
            super::super::common::try_lock_runtime_file(root.parent().unwrap(), ".mutation.lock")
                .is_err()
        );
        drop(second);
        let _mutation =
            super::super::common::try_lock_runtime_file(root.parent().unwrap(), ".mutation.lock")?;
        Ok(())
    }

    #[test]
    fn package_runtime_rechecks_imported_content_and_selected_version() -> Result<()> {
        let (owner, root) = fixture("go", &["go"])?;
        let managed = ManagedRuntime::open(
            "go",
            &owner.path().join("tools"),
            &RuntimeSecurity::fixture(),
        )?;
        let context = managed.identity_context()?;
        assert_eq!(context, managed.identity_context()?);
        fs::write(root.join("lib/implementation"), b"changed implementation")?;
        assert!(managed.verify().is_err());
        fs::write(
            root.join("lib/implementation"),
            b"controlled implementation",
        )?;
        managed.verify()?;
        fs::remove_file(root.parent().unwrap().join("current"))?;
        assert!(managed.command_path("go").is_err());
        Ok(())
    }

    #[test]
    fn package_runtime_never_falls_back_to_an_ambient_or_external_selection() -> Result<()> {
        let owner = tempfile::tempdir()?;
        fs::create_dir_all(owner.path().join("versions/go"))?;
        assert!(
            ManagedRuntime::open(
                "go",
                &owner.path().join("tools"),
                &RuntimeSecurity::fixture()
            )
            .is_err()
        );
        let external = tempfile::tempdir()?;
        fs::create_dir(external.path().join("1.78.0"))?;
        symlink(
            external.path().join("1.78.0"),
            owner.path().join("versions/go/current"),
        )?;
        assert!(
            ManagedRuntime::open(
                "go",
                &owner.path().join("tools"),
                &RuntimeSecurity::fixture()
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn package_commands_reject_missing_nonregular_escaping_and_nonexecutable_targets() -> Result<()>
    {
        let (owner, root) = fixture("python", &["python3"])?;
        fs::create_dir(root.join("bin/directory"))?;
        fs::write(root.join("bin/not-executable"), b"not executable")?;
        fs::set_permissions(
            root.join("bin/not-executable"),
            fs::Permissions::from_mode(0o644),
        )?;
        let outside = owner.path().join("outside");
        fs::write(&outside, b"external executable")?;
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o755))?;
        symlink(&outside, root.join("bin/escaping"))?;
        // Escaping content is rejected by the full runtime admission before any command can run.
        assert!(
            ManagedRuntime::open(
                "python",
                &owner.path().join("tools"),
                &RuntimeSecurity::fixture()
            )
            .is_err()
        );
        fs::remove_file(root.join("bin/escaping"))?;
        super::super::security::fixture_prepare("python", "1.78.0", &root, &root)?;
        let managed = ManagedRuntime::open(
            "python",
            &owner.path().join("tools"),
            &RuntimeSecurity::fixture(),
        )?;
        assert!(managed.command_path("missing").is_err());
        assert!(managed.command_path("directory").is_err());
        assert!(managed.command_path("not-executable").is_err());
        assert!(managed.command_path("../outside").is_err());
        assert!(managed.command_path("/usr/bin/python3").is_err());
        Ok(())
    }

    #[test]
    fn python_command_may_resolve_a_contained_publisher_link() -> Result<()> {
        let (owner, root) = fixture("python", &["python3"])?;
        symlink("python3", root.join("bin/python"))?;
        super::super::security::fixture_prepare("python", "1.78.0", &root, &root)?;
        let managed = ManagedRuntime::open(
            "python",
            &owner.path().join("tools"),
            &RuntimeSecurity::fixture(),
        )?;
        assert_eq!(
            managed.command_path("python")?,
            root.join("bin/python3").canonicalize()?
        );
        Ok(())
    }
}
