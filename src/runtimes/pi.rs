//! Exact Pi releases share the reviewed managed npm transaction used by tools.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result, ensure};

use super::common::{self, print_already_installed, print_installed, print_using};
use super::npm::{cached_installed_npm, install_reviewed_npm, review_installed_npm};
use super::security::{ReviewMode, RuntimeSecurity};
use crate::core::security::vulnerability::{VulnerabilityScanner, VulnerabilitySource};

const PI_PACKAGE: &str = "@earendil-works/pi-coding-agent";

pub(crate) struct PiManager {
    versions_dir: PathBuf,
    advisories: Arc<dyn VulnerabilitySource>,
    security: RuntimeSecurity,
}

impl PiManager {
    pub fn new() -> Self {
        Self {
            versions_dir: super::DATA_DIR.join("versions/pi"),
            advisories: Arc::new(VulnerabilityScanner::new()),
            security: RuntimeSecurity::default(),
        }
    }

    #[cfg(test)]
    fn with_paths(versions_dir: PathBuf, _unused_ambient_npm: PathBuf) -> Self {
        Self {
            versions_dir,
            advisories: Arc::new(TestAdvisories::default()),
            security: RuntimeSecurity::fixture(),
        }
    }

    /// The blocking owner retains staging, child processes and both mutation
    /// leases even when its asynchronous caller is cancelled.
    pub async fn install(&self, version: &str) -> Result<()> {
        crate::core::security::validate_runtime_version(version)?;
        let owner = Self {
            versions_dir: self.versions_dir.clone(),
            advisories: self.advisories.clone(),
            security: self.security.clone(),
        };
        let version = version.to_owned();
        tokio::task::spawn_blocking(move || owner.install_owned(&version))
            .await
            .context("Pi installation worker failed")?
    }

    fn tools_dir(&self) -> Result<PathBuf> {
        Ok(self
            .versions_dir
            .parent()
            .and_then(Path::parent)
            .context("Pi versions directory has no data root")?
            .join("tools"))
    }

    fn install_owned(&self, version: &str) -> Result<()> {
        let lease = common::try_lock_runtime_file(&self.versions_dir, ".mutation.lock")?;
        let destination = self.versions_dir.join(version);
        if common::is_valid_version_dir(&destination) {
            self.select_owned(version, &lease)?;
            print_already_installed("Pi", version);
            return Ok(());
        }
        let staging = common::begin_staged_install(&self.versions_dir)?;
        let reviewed = install_reviewed_npm(
            &format!("{PI_PACKAGE}@{version}"),
            staging.path(),
            &destination,
            &self.tools_dir()?,
            self.advisories.as_ref(),
            &self.security,
        )?;
        let entrypoint = validate_pi_install(staging.path(), version)?;
        write_launcher(
            staging.path(),
            &destination,
            &entrypoint,
            reviewed.node_path(),
        )?;
        reviewed.verify(staging.path())?;
        let admission =
            self.security
                .prepare_staged("pi", version, staging.path(), &destination)?;
        admission.before_execution(staging.path())?;
        reviewed.verify(staging.path())?;
        common::complete_staged_install_with_lease(&staging, &destination, version, &lease)?;
        reviewed.verify(&destination)?;
        admission.verify(&destination)?;
        common::set_current_version_with_lease(&self.versions_dir, version, &lease)?;
        print_installed("Pi", version);
        print_using("Pi", version, &self.versions_dir.join("current/bin"));
        Ok(())
    }

    pub fn use_version(&self, version: &str) -> Result<()> {
        crate::core::security::validate_runtime_version(version)?;
        let lease = common::try_lock_runtime_file(&self.versions_dir, ".mutation.lock")?;
        self.select_owned(version, &lease)
    }

    fn select_owned(&self, version: &str, lease: &common::RuntimeLease) -> Result<()> {
        let prefix = self.versions_dir.join(version);
        let entrypoint = validate_pi_install(&prefix, version)?;
        if let Ok((admission, reviewed)) = (|| {
            let admission = self
                .security
                .installed("pi", &prefix, ReviewMode::CachedOnly)?;
            let reviewed = cached_installed_npm(
                &format!("{PI_PACKAGE}@{version}"),
                &prefix,
                &self.tools_dir()?,
                &self.security,
                &admission,
            )?;
            let expected = launcher_bytes(&prefix, &entrypoint, reviewed.node_path())?;
            ensure!(
                crate::core::security::npm::read_metadata(&prefix.join("bin/pi"), expected.len())?
                    == expected,
                "Cached Pi launcher changed"
            );
            Ok::<_, anyhow::Error>((admission, reviewed))
        })() {
            reviewed.verify(&prefix)?;
            admission.verify(&prefix)?;
            common::set_current_version_with_lease(&self.versions_dir, version, lease)?;
            print_using("Pi", version, &self.versions_dir.join("current/bin"));
            return Ok(());
        }
        let receipt_path = prefix.join(".omg-npm-advisory-review.json");
        let previous_receipt =
            crate::core::security::npm::read_metadata(&receipt_path, 16 * 1024 * 1024)?;
        let activation = (|| -> Result<()> {
            let reviewed = review_installed_npm(
                &format!("{PI_PACKAGE}@{version}"),
                &prefix,
                &self.tools_dir()?,
                self.advisories.as_ref(),
                &self.security,
            )?;
            let expected = launcher_bytes(&prefix, &entrypoint, reviewed.node_path())?;
            ensure!(
                crate::core::security::npm::read_metadata(&prefix.join("bin/pi"), expected.len())?
                    == expected,
                "Pi launcher does not match its reviewed managed Node; reinstall this Pi release"
            );
            let admission = self
                .security
                .installed("pi", &prefix, ReviewMode::FreshAttended)?;
            reviewed.verify(&prefix)?;
            admission.verify(&prefix)?;
            common::set_current_version_with_lease(&self.versions_dir, version, lease)
        })();
        if let Err(error) = activation {
            crate::core::safe_ops::atomic_write_file_sync(&receipt_path, previous_receipt)
                .context(
                    "Failed to restore the previous Pi dependency review after activation failed",
                )?;
            return Err(error);
        }
        print_using("Pi", version, &self.versions_dir.join("current/bin"));
        Ok(())
    }

    pub fn uninstall(&self, version: &str) -> Result<()> {
        common::uninstall_version(&self.versions_dir, version)
    }
}

crate::runtimes::common::impl_runtime_common!(PiManager);

/// Require npm's local executable to belong to the selected top-level package.
/// Legacy global installations lack a reviewed lock and require reinstallation.
fn validate_pi_install(prefix: &Path, version: &str) -> Result<PathBuf> {
    let package = prefix.join("node_modules").join(PI_PACKAGE);
    let manifest: serde_json::Value = serde_json::from_slice(
        &crate::core::security::npm::read_metadata(&package.join("package.json"), 1024 * 1024)
            .context("Pi has no reviewed local package layout. Install and select another Pi version, then remove and reinstall this version")?,
    )?;
    ensure!(
        manifest["name"] == PI_PACKAGE && manifest["version"].as_str() == Some(version),
        "Pi installed identity differs from expected {version}"
    );
    let entrypoint = prefix
        .join("node_modules/.bin/pi")
        .canonicalize()
        .context("Pi package has no contained npm executable")?;
    ensure!(
        entrypoint.starts_with(package.canonicalize()?),
        "Pi executable escapes the selected package"
    );
    ensure!(
        fs::metadata(&entrypoint)?.is_file(),
        "Pi executable is not a regular file"
    );
    Ok(entrypoint
        .strip_prefix(prefix.canonicalize()?)?
        .to_path_buf())
}

fn shell_path(path: &Path) -> Result<String> {
    let value = path.to_str().context("Pi launcher path is not UTF-8")?;
    ensure!(
        !value.contains(['\n', '\r', '\0']),
        "Invalid Pi launcher path"
    );
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}

fn launcher_bytes(destination: &Path, entrypoint: &Path, node: &Path) -> Result<Vec<u8>> {
    Ok(format!(
        "#!/bin/sh\nexec {} {} \"$@\"\n",
        shell_path(node)?,
        shell_path(&destination.join(entrypoint))?
    )
    .into_bytes())
}

fn write_launcher(prefix: &Path, destination: &Path, entrypoint: &Path, node: &Path) -> Result<()> {
    let bin = prefix.join("bin");
    fs::create_dir(&bin)?;
    let launcher = bin.join("pi");
    crate::core::safe_ops::atomic_write_file_sync(
        &launcher,
        launcher_bytes(destination, entrypoint, node)?,
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

#[cfg(test)]
#[derive(Default)]
struct TestAdvisories {
    vulnerable: bool,
    reads: AtomicUsize,
}

#[cfg(test)]
impl VulnerabilitySource for TestAdvisories {
    fn assess_packages<'a>(
        &'a self,
        packages: &'a [crate::package_managers::types::SecurityPackage],
        _use_case: crate::core::security::vulnerability::AssessmentUse,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = std::result::Result<
                        Vec<crate::core::security::vulnerability::PackageAssessment>,
                        crate::core::security::vulnerability::VulnerabilityError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            Ok(packages
                .iter()
                .map(|package| {
                    use crate::core::security::{
                        scan,
                        vulnerability::{PackageAssessment, PackageCoverage},
                    };
                    PackageAssessment {
                        package: package.clone(),
                        coverage: PackageCoverage::Assessed {
                            provenance: scan::AdvisoryProvenance::Osv {
                                ecosystem: "npm".into(),
                            },
                        },
                        findings: if self.vulnerable && package.name == "pi-fixture-dependency" {
                            vec![scan::Vulnerability {
                                applicability: scan::FindingApplicability::Applicable,
                                id: "CVE-2021-23337".into(),
                                summary: "vulnerable transitive Pi dependency".into(),
                                score: Some("7.2".into()),
                                advisory_severity: None,
                                native_advisory: None,
                                affected_installed: vec![],
                            }]
                        } else {
                            vec![]
                        },
                    }
                })
                .collect())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[cfg(unix)]
    use std::sync::atomic::AtomicBool;

    #[cfg(unix)]
    #[derive(Default)]
    struct TestRuntimeEvidence {
        refuse_pi: AtomicBool,
        pi_reads: AtomicUsize,
        reads: AtomicUsize,
    }

    #[cfg(unix)]
    impl super::super::security::RuntimeEvidenceSource for TestRuntimeEvidence {
        fn read(&self, query: &super::super::security::RuntimeQuery) -> Result<Vec<u8>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if query.runtime == "pi" {
                self.pi_reads.fetch_add(1, Ordering::SeqCst);
            }
            ensure!(
                !(query.runtime == "pi" && self.refuse_pi.load(Ordering::SeqCst)),
                "controlled Pi provider outage"
            );
            super::super::security::fixture_runtime_report(query)
        }
    }

    #[cfg(unix)]
    fn fake_npm(directory: &Path, version: &str, succeed: bool) -> Result<PathBuf> {
        let path = directory.join("npm");
        let status = if succeed { 0 } else { 17 };
        let root = shell_path(directory)?;
        let script = format!(
            r#"#!/bin/sh
set -eu
root={root}
printf '%s\n' "$@" >> "$root/npm-args"
phase=$1
printf '%s\n' "$phase" >> "$root/phases"
prefix=''
previous=''
for arg in "$@"; do
  if [ "$previous" = '--prefix' ]; then prefix=$arg; fi
  previous=$arg
done
[ -n "$prefix" ]
case "$phase" in
install) cp "$root/lock.fixture.json" "$prefix/package-lock.json" ;;
ci)
  if [ -f "$root/hold" ]; then
    printf '%s' "$prefix" > "$root/started"
    attempts=0
    while [ ! -f "$root/release" ]; do
      [ "$attempts" -lt 500 ] || exit 124
      attempts=$((attempts + 1))
      sleep 0.02
    done
  fi
  [ {status} = 0 ] || exit {status}
  mkdir -p "$prefix/node_modules/@earendil-works/pi-coding-agent/dist" "$prefix/node_modules/pi-fixture-dependency" "$prefix/node_modules/.bin"
  printf '{{"name":"@earendil-works/pi-coding-agent","version":"{version}","bin":{{"pi":"dist/cli.js"}}}}' > "$prefix/node_modules/@earendil-works/pi-coding-agent/package.json"
  printf 'console.log("pi");\n' > "$prefix/node_modules/@earendil-works/pi-coding-agent/dist/cli.js"
  printf '{{"name":"pi-fixture-dependency","version":"1.0.0"}}' > "$prefix/node_modules/pi-fixture-dependency/package.json"
  ln -s ../@earendil-works/pi-coding-agent/dist/cli.js "$prefix/node_modules/.bin/pi"
  ;;
audit) [ ! -f "$root/signature-reject" ] ;;
*) exit 21 ;;
esac
"#
        );
        fs::write(&path, script)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        let integrity = "sha512-AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==";
        let lock = serde_json::json!({"lockfileVersion":3,"packages":{
            "":{"dependencies":{PI_PACKAGE:version}},
            format!("node_modules/{PI_PACKAGE}"):{"version":version,"resolved":format!("https://registry.npmjs.org/{PI_PACKAGE}/-/pi-coding-agent-{version}.tgz"),"integrity":integrity,"dependencies":{"pi-fixture-dependency":"1.0.0"}},
            "node_modules/pi-fixture-dependency":{"version":"1.0.0","resolved":"https://registry.npmjs.org/pi-fixture-dependency/-/pi-fixture-dependency-1.0.0.tgz","integrity":integrity}
        }});
        fs::write(
            directory.join("lock.fixture.json"),
            serde_json::to_vec(&lock)?,
        )?;
        Ok(path)
    }

    #[cfg(unix)]
    fn managed_node(root: &Path, npm: &Path) -> Result<PathBuf> {
        let versions = root.join("versions/node");
        let version = versions.join("24.22.3");
        fs::create_dir_all(version.join("bin"))?;
        fs::create_dir_all(version.join("lib/node_modules/npm/bin"))?;
        let node = version.join("bin/node");
        fs::write(
            &node,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" >> {} || exit 1\nshift\nwhile [ \"${{1#--}}\" != \"$1\" ]; do shift; done\nexec {} \"$@\"\n",
                shell_path(&root.join("managed-node-args"))?,
                shell_path(npm)?
            ),
        )?;
        fs::set_permissions(&node, fs::Permissions::from_mode(0o755))?;
        let cli = version.join("lib/node_modules/npm/bin/npm-cli.js");
        fs::write(&cli, "// owned managed npm fixture\n")?;
        fs::set_permissions(&cli, fs::Permissions::from_mode(0o755))?;
        fs::write(
            version.join("lib/node_modules/npm/package.json"),
            br#"{"version":"11.15.0"}"#,
        )?;
        symlink(&cli, version.join("bin/npm"))?;
        symlink(&version, versions.join("current"))?;
        super::super::security::fixture_install_identity("node", &version)?;
        Ok(node)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pi_refuses_ambient_npm_without_a_managed_node_runtime() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let versions = temp.path().join("versions/pi");
        let npm = fake_npm(temp.path(), "0.83.0", true)?;
        let manager = PiManager::with_paths(versions.clone(), npm);
        let error = manager
            .install("0.83.0")
            .await
            .expect_err("Pi requires managed Node admission");
        assert!(format!("{error:#}").contains("OMG-managed Node"));
        assert!(!temp.path().join("npm-args").exists());
        assert!(!versions.join("0.83.0").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn install_publishes_exact_version_and_activates_it() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let versions_dir = temp.path().join("versions/pi");
        let npm = fake_npm(temp.path(), "0.83.0", true)?;
        let node = managed_node(temp.path(), &npm)?;
        let manager = PiManager::with_paths(versions_dir.clone(), npm);
        manager.install("0.83.0").await?;
        assert_eq!(manager.current_version().as_deref(), Some("0.83.0"));
        assert_eq!(manager.list_installed()?, vec!["0.83.0"]);
        assert!(
            versions_dir
                .join("current/bin/pi")
                .canonicalize()?
                .is_file()
        );
        assert_eq!(
            fs::read_to_string(temp.path().join("phases"))?,
            "install\nci\naudit\n"
        );
        let arguments = fs::read_to_string(temp.path().join("managed-node-args"))?;
        assert!(
            arguments
                .lines()
                .any(|argument| argument == "--ignore-scripts")
        );
        assert!(!arguments.lines().any(|argument| argument == "--global"));
        assert!(
            arguments
                .lines()
                .any(|argument| argument == "--package-lock-only")
        );
        assert!(
            arguments
                .lines()
                .any(|argument| argument == "--registry=https://registry.npmjs.org/")
        );
        assert!(
            arguments
                .lines()
                .any(|argument| argument == "@earendil-works/pi-coding-agent@0.83.0")
        );
        assert!(
            fs::read_to_string(manager.versions_dir.join("current/bin/pi"))?
                .contains(&shell_path(&node.canonicalize()?)?)
        );
        manager.use_version("0.83.0")?;
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hostile_version_is_rejected_before_npm_execution() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let manager =
            PiManager::with_paths(temp.path().join("versions/pi"), temp.path().join("absent"));
        assert!(manager.install("../../malicious").await.is_err());
        assert!(!manager.versions_dir.exists());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn busy_npm_remains_unpublished_and_can_be_retried_after_its_writer_closes() -> Result<()>
    {
        let temp = tempfile::tempdir()?;
        let npm = fake_npm(temp.path(), "0.83.0", true)?;
        let node = managed_node(temp.path(), &npm)?;
        let writer = fs::OpenOptions::new().write(true).open(node)?;
        let inherited = writer.try_clone()?;
        drop(writer);
        let manager = PiManager::with_paths(temp.path().join("versions/pi"), npm);
        assert!(manager.install("0.83.0").await.is_err());
        assert!(!manager.versions_dir.join("0.83.0").exists());
        assert_eq!(manager.current_version(), None);
        drop(inherited);
        manager.install("0.83.0").await?;
        assert_eq!(manager.current_version().as_deref(), Some("0.83.0"));
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_install_does_not_publish_or_replace_active_version() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let npm = fake_npm(temp.path(), "0.82.0", true)?;
        managed_node(temp.path(), &npm)?;
        let manager = PiManager::with_paths(temp.path().join("versions/pi"), npm);
        manager.install("0.82.0").await?;
        fake_npm(temp.path(), "0.83.0", false)?;
        let error = manager
            .install("0.83.0")
            .await
            .expect_err("failed npm install must remain unpublished");
        assert!(format!("{error:#}").contains("NPM frozen install"));
        assert_eq!(manager.current_version().as_deref(), Some("0.82.0"));
        assert!(!manager.versions_dir.join("0.83.0").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn mismatched_registry_version_fails_closed() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let npm = fake_npm(temp.path(), "9.9.9", true)?;
        managed_node(temp.path(), &npm)?;
        let manager = PiManager::with_paths(temp.path().join("versions/pi"), npm);
        let error = manager
            .install("0.83.0")
            .await
            .expect_err("unexpected package version must not be published");
        assert!(
            format!("{error:#}").contains("requested exact version"),
            "mismatch error must name the requested version, got: {error:#}"
        );
        assert!(!manager.versions_dir.join("0.83.0").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn pi_activation_refuses_malformed_identity_or_missing_executable() -> Result<()> {
        let prefix = tempfile::tempdir()?;
        let package = prefix.path().join("node_modules").join(PI_PACKAGE);
        fs::create_dir_all(&package)?;
        let manifest = package.join("package.json");
        fs::write(&manifest, b"{")?;
        let error = validate_pi_install(prefix.path(), "0.83.0")
            .expect_err("a malformed package identity cannot be activated");
        assert!(error.downcast_ref::<serde_json::Error>().is_some());

        fs::write(
            &manifest,
            serde_json::to_vec(&serde_json::json!({"name": PI_PACKAGE, "version": "0.83.0"}))?,
        )?;
        let error = validate_pi_install(prefix.path(), "0.83.0")
            .expect_err("an installation without an executable cannot be activated");
        assert!(format!("{error:#}").contains("Pi package has no contained npm executable"));

        let entrypoint = package.join("dist");
        fs::create_dir(&entrypoint)?;
        let bin_dir = prefix.path().join("node_modules/.bin");
        fs::create_dir(&bin_dir)?;
        symlink(entrypoint, bin_dir.join("pi"))?;
        let error = validate_pi_install(prefix.path(), "0.83.0")
            .expect_err("an executable directory cannot be activated");
        assert!(format!("{error:#}").contains("Pi executable is not a regular file"));
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn vulnerable_transitive_dependency_is_refused_before_materialization() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let npm = fake_npm(temp.path(), "0.83.0", true)?;
        managed_node(temp.path(), &npm)?;
        let mut manager = PiManager::with_paths(temp.path().join("versions/pi"), npm);
        manager.advisories = Arc::new(TestAdvisories {
            vulnerable: true,
            ..TestAdvisories::default()
        });
        assert!(manager.install("0.83.0").await.is_err());
        assert_eq!(fs::read_to_string(temp.path().join("phases"))?, "install\n");
        assert!(!manager.versions_dir.join("0.83.0").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn signature_failure_preserves_prior_version() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let npm = fake_npm(temp.path(), "0.82.0", true)?;
        managed_node(temp.path(), &npm)?;
        let manager = PiManager::with_paths(temp.path().join("versions/pi"), npm);
        manager.install("0.82.0").await?;
        fake_npm(temp.path(), "0.83.0", true)?;
        fs::write(temp.path().join("signature-reject"), "reject")?;
        let error = manager
            .install("0.83.0")
            .await
            .expect_err("signature verification stays mandatory");
        assert!(format!("{error:#}").contains("signature/provenance"));
        assert_eq!(manager.current_version().as_deref(), Some("0.82.0"));
        assert!(!manager.versions_dir.join("0.83.0").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_same_version_admission_restores_previous_dependency_review() -> Result<()> {
        if crate::core::testing::run_isolated_test(
            "runtimes::pi::tests::failed_same_version_admission_restores_previous_dependency_review",
        ) {
            return Ok(());
        }
        use crate::core::security::vulnerability::{
            AssessmentUse, PackageAssessment, PackageCoverage, VulnerabilityError,
        };
        use crate::package_managers::types::SecurityPackage;
        use std::sync::atomic::AtomicU8;

        struct RevisionSource {
            revision: AtomicU8,
            checked_at: jiff::Timestamp,
            clean: TestAdvisories,
        }
        impl VulnerabilitySource for RevisionSource {
            fn assess_packages<'a>(
                &'a self,
                packages: &'a [SecurityPackage],
                use_case: AssessmentUse,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = std::result::Result<
                                Vec<PackageAssessment>,
                                VulnerabilityError,
                            >,
                        > + Send
                        + 'a,
                >,
            > {
                Box::pin(async move {
                    let mut assessed = self.clean.assess_packages(packages, use_case).await?;
                    for assessment in &mut assessed {
                        assessment.coverage = PackageCoverage::Assessed {
                            provenance:
                                crate::core::security::scan::AdvisoryProvenance::RuntimeSnapshot {
                                    runtime: "controlled-npm-fixture".into(),
                                    source: "https://github.com/omg-cli/omg".into(),
                                    payload_sha256: format!(
                                        "{:064x}",
                                        self.revision.load(Ordering::SeqCst)
                                    ),
                                    checked_at: self.checked_at,
                                },
                        };
                    }
                    Ok(assessed)
                })
            }
        }
        let temp = tempfile::tempdir()?;
        let npm = fake_npm(temp.path(), "0.83.0", true)?;
        managed_node(temp.path(), &npm)?;
        let source = Arc::new(TestRuntimeEvidence::default());
        let npm_source = Arc::new(RevisionSource {
            revision: AtomicU8::new(1),
            checked_at: jiff::Timestamp::now(),
            clean: TestAdvisories::default(),
        });
        let mut manager = PiManager::with_paths(temp.path().join("versions/pi"), npm);
        manager.security = RuntimeSecurity::with_source(source.clone());
        manager.advisories = npm_source.clone();
        manager.install("0.83.0").await?;
        let prefix = manager.versions_dir.join("0.83.0");
        let previous = fs::read(prefix.join(".omg-npm-advisory-review.json"))?;
        let previous_reads = source.pi_reads.load(Ordering::SeqCst);
        npm_source.revision.store(2, Ordering::SeqCst);
        source.refuse_pi.store(true, Ordering::SeqCst);
        let result = temp_env::with_var(
            crate::cli::tool::ALLOW_NPM_SCRIPTS_ENV,
            Some("@earendil-works/pi-coding-agent@0.83.0"),
            || manager.use_version("0.83.0"),
        );
        assert!(result.is_err());
        assert!(
            source.pi_reads.load(Ordering::SeqCst) > previous_reads,
            "changed dependency evidence must force the actual fresh Pi admission path"
        );
        assert_eq!(
            fs::read(prefix.join(".omg-npm-advisory-review.json"))?,
            previous
        );
        assert_eq!(manager.current_version().as_deref(), Some("0.83.0"));
        manager
            .security
            .installed("pi", &prefix, ReviewMode::CachedOnly)?
            .verify(&prefix)?;

        source.refuse_pi.store(false, Ordering::SeqCst);
        npm_source.revision.store(1, Ordering::SeqCst);
        // Expire the cache while preserving the exact dependency evidence. A
        // semantic change would require a separate attended Pi risk review.
        let receipt_path = prefix.join(".omg-npm-advisory-review.json");
        let mut stale_receipt: serde_json::Value = serde_json::from_slice(&previous)?;
        stale_receipt["reviewed_at"] = "2000-01-01T00:00:00Z".into();
        let stale_receipt = serde_json::to_vec_pretty(&stale_receipt)?;
        crate::core::safe_ops::atomic_write_file_sync(&receipt_path, &stale_receipt)?;

        let current = manager.versions_dir.join("current");
        let previous_link = fs::read_link(&current)?;
        fs::remove_file(&current)?;
        fs::create_dir(&current)?;
        let error = manager
            .use_version("0.83.0")
            .expect_err("must preserve a regular current directory");
        assert!(
            format!("{error:#}").contains("Refusing to replace non-symlink"),
            "{error:#}"
        );
        assert_eq!(fs::read(&receipt_path)?, stale_receipt);
        assert!(fs::symlink_metadata(&current)?.file_type().is_dir());

        fs::remove_dir(&current)?;
        symlink(previous_link, &current)?;
        manager.use_version("0.83.0")?;
        assert_ne!(fs::read(&receipt_path)?, stale_receipt);
        manager
            .security
            .installed("pi", &prefix, ReviewMode::CachedOnly)?
            .verify(&prefix)?;
        assert_eq!(manager.current_version().as_deref(), Some("0.83.0"));
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn intact_cached_pi_selection_does_not_call_sources_or_run_npm() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let npm = fake_npm(temp.path(), "0.83.0", true)?;
        managed_node(temp.path(), &npm)?;
        let advisories = Arc::new(TestAdvisories::default());
        let evidence = Arc::new(TestRuntimeEvidence::default());
        let mut manager = PiManager::with_paths(temp.path().join("versions/pi"), npm);
        manager.advisories = advisories.clone();
        manager.security = RuntimeSecurity::with_source(evidence.clone());
        manager.install("0.83.0").await?;
        let package_reads = advisories.reads.load(Ordering::SeqCst);
        let runtime_reads = evidence.reads.load(Ordering::SeqCst);
        assert!(package_reads > 0 && runtime_reads > 0);
        let receipt_path = manager
            .versions_dir
            .join("0.83.0/.omg-npm-advisory-review.json");
        let receipt = fs::read(&receipt_path)?;
        let phases = fs::read(temp.path().join("phases"))?;
        fs::write(
            temp.path().join("signature-reject"),
            "cached selection cannot run a new audit",
        )?;
        manager.install("0.83.0").await?;
        manager.use_version("0.83.0")?;
        assert_eq!(advisories.reads.load(Ordering::SeqCst), package_reads);
        assert_eq!(evidence.reads.load(Ordering::SeqCst), runtime_reads);
        assert_eq!(manager.current_version().as_deref(), Some("0.83.0"));
        assert_eq!(
            fs::read(receipt_path)?,
            receipt,
            "cache reuse must preserve the original reviewed bytes and timestamp"
        );
        assert_eq!(
            fs::read(temp.path().join("phases"))?,
            phases,
            "cache reuse cannot materialize, audit or run scripts again"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dropped_caller_keeps_staging_and_leases_until_child_completion() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let npm = fake_npm(temp.path(), "0.83.0", true)?;
        managed_node(temp.path(), &npm)?;
        fs::write(temp.path().join("hold"), "hold")?;
        let manager = Arc::new(PiManager::with_paths(temp.path().join("versions/pi"), npm));
        let cloned = manager.clone();
        let caller = tokio::spawn(async move { cloned.install("0.83.0").await });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !temp.path().join("started").exists() && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        if !temp.path().join("started").exists() {
            fs::write(temp.path().join("release"), "release")?;
            return Err(anyhow::anyhow!(
                "Pi child did not reach the owned install phase: {:?}",
                caller.await?
            ));
        }
        let staging = PathBuf::from(fs::read_to_string(temp.path().join("started"))?);
        caller.abort();
        let _ = caller.await;
        let retained = staging.is_dir();
        let locked =
            common::try_lock_runtime_file(&manager.versions_dir, ".mutation.lock").is_err();
        fs::write(temp.path().join("release"), "release")?;
        while manager.current_version().as_deref() != Some("0.83.0")
            && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            retained && locked,
            "the blocking owner must retain staging and mutation ownership after caller cancellation"
        );
        assert_eq!(manager.current_version().as_deref(), Some("0.83.0"));
        assert!(!staging.exists());
        Ok(())
    }
}
