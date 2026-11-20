//! One managed npm transaction for tools and Pi.

use crate::cli::tool::{
    ALLOW_NPM_SCRIPTS_ENV, ALLOW_UNVERIFIED_ENV, active_security_overrides,
    host_environment_is_allowed, package_is_allowed, secured_manager_command,
};
use crate::core::security::npm::read_metadata as read_npm_metadata;
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(crate) struct ManagedNpm {
    versions_dir: PathBuf,
    version_dir: PathBuf,
    version: String,
    node: PathBuf,
    npm: PathBuf,
    identity: BTreeMap<String, String>,
    _lease: crate::runtimes::common::RuntimeLease,
}

impl ManagedNpm {
    pub(crate) fn open(tools_dir: &Path) -> Result<Self> {
        let versions_dir = tools_dir
            .parent()
            .context("Tools directory has no data root")?
            .join("versions/node");
        let lease =
            crate::runtimes::common::try_lock_runtime_file(&versions_dir, ".mutation.lock")?;
        let version = crate::runtimes::common::get_current_version(&versions_dir).context(
            "NPM admission requires an active OMG-managed Node runtime; run omg use node@lts first",
        )?;
        crate::core::security::validate_runtime_version(&version)?;
        let version_dir = versions_dir.join(&version).canonicalize()?;
        anyhow::ensure!(
            version_dir.parent() == Some(versions_dir.canonicalize()?.as_path()),
            "Managed Node escapes its versions tree"
        );
        let node = version_dir.join("bin/node").canonicalize()?;
        let npm = version_dir.join("bin/npm").canonicalize()?;
        anyhow::ensure!(
            node.starts_with(&version_dir) && npm.starts_with(&version_dir),
            "Managed Node/npm escapes its release directory"
        );
        let metadata = read_npm_metadata(
            &version_dir.join("lib/node_modules/npm/package.json"),
            1024 * 1024,
        )?;
        let metadata: serde_json::Value = serde_json::from_slice(&metadata)?;
        let npm_version = semver::Version::parse(
            metadata["version"]
                .as_str()
                .context("Bundled npm has no version")?,
        )?;
        anyhow::ensure!(
            npm_version >= semver::Version::new(11, 15, 0),
            "NPM admission requires bundled npm >=11.15.0 to block non-registry resolver sources; update the OMG-managed Node release"
        );
        let identity = crate::core::security::npm::manager_identity(&version_dir)?;
        anyhow::ensure!(
            identity.contains_key("bin/node") && identity.contains_key("bin/npm"),
            "Managed Node/npm executable identity is incomplete"
        );
        Ok(Self {
            versions_dir,
            version_dir,
            version,
            node,
            npm,
            identity,
            _lease: lease,
        })
    }

    fn command(&self, staging_dir: &Path, package: &str) -> Result<Command> {
        let mut command = secured_manager_command(&self.node, staging_dir, "npm", package)?;
        command.arg(&self.npm).current_dir(staging_dir).args([
            "--registry=https://registry.npmjs.org/",
            "--audit=false",
            "--fund=false",
            "--allow-git=none",
            "--allow-file=none",
            "--allow-directory=none",
            "--allow-remote=none",
        ]);
        Ok(command)
    }

    pub(crate) fn verify(&self) -> Result<()> {
        anyhow::ensure!(
            crate::runtimes::common::get_current_version(&self.versions_dir).as_deref()
                == Some(&self.version)
                && crate::core::security::npm::manager_identity(&self.version_dir)?
                    == self.identity,
            "Managed Node/npm changed after advisory review; installation cancelled"
        );
        Ok(())
    }
}

pub(crate) fn install_reviewed_npm<'a>(
    package: &str,
    staging_dir: &Path,
    install_dir: &Path,
    tools_dir: &Path,
    advisories: &'a dyn crate::core::security::vulnerability::VulnerabilitySource,
    security: &crate::runtimes::security::RuntimeSecurity,
) -> Result<ReviewedNpm<'a>> {
    use crate::core::security::npm::{NpmLock, NpmSpec};

    anyhow::ensure!(
        !host_environment_is_allowed("npm", package),
        "NPM advisory admission currently requires the pinned public registry; host/private registry coordinates remain UNKNOWN"
    );
    let spec = NpmSpec::parse(package)?;
    let runtime = ManagedNpm::open(tools_dir)?;
    let node_admission = security.installed(
        "node",
        &runtime.version_dir,
        crate::runtimes::security::ReviewMode::FreshAttended,
    )?;
    let overrides = active_security_overrides("npm", package);
    let allow_scripts = package_is_allowed(ALLOW_NPM_SCRIPTS_ENV, package);
    let require_signatures = !package_is_allowed(ALLOW_UNVERIFIED_ENV, &format!("npm:{package}"));
    let manifest = serde_json::json!({"name":"omg-managed-tool","version":"0.0.0","private":true});
    crate::core::safe_ops::atomic_write_file_sync(
        staging_dir.join("package.json"),
        serde_json::to_vec(&manifest)?,
    )?;
    let install_path = staging_dir
        .to_str()
        .context("npm staging path is not UTF-8")?;
    runtime.verify()?;
    node_admission.verify(&runtime.version_dir)?;
    let status = runtime
        .command(staging_dir, package)?
        .args([
            "install",
            "--prefix",
            install_path,
            "--package-lock-only",
            "--save-exact",
            "--ignore-scripts",
            "--package-lock=true",
            "--",
            package,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .status()?;
    anyhow::ensure!(
        status.success(),
        "NPM install resolution of '{package}' failed; no package was admitted"
    );
    anyhow::ensure!(
        !staging_dir.join("node_modules").try_exists()?,
        "NPM lock resolution materialized packages before advisory review"
    );
    let lock_path = staging_dir.join("package-lock.json");
    let lock = NpmLock::parse(&read_npm_metadata(&lock_path, 16 * 1024 * 1024)?, &spec)?;
    let review = review_lock(
        package,
        install_dir,
        &runtime,
        &lock,
        &overrides,
        advisories,
    )?;
    let unchanged = || -> Result<()> {
        review.verify(advisories)?;
        runtime.verify()?;
        node_admission.verify(&runtime.version_dir)?;
        anyhow::ensure!(
            active_security_overrides("npm", package) == overrides
                && NpmLock::parse(&read_npm_metadata(&lock_path, 16 * 1024 * 1024)?, &spec)?.sha256
                    == lock.sha256,
            "NPM dependencies or security options changed after advisory review; installation cancelled"
        );
        Ok(())
    };
    unchanged()?;
    let installed = runtime
        .command(staging_dir, package)?
        .args(["ci", "--prefix", install_path, "--ignore-scripts"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .status()?;
    anyhow::ensure!(
        installed.success(),
        "NPM frozen install of '{package}' failed"
    );
    lock.verify_installed(staging_dir, &spec)?;
    unchanged()?;
    if require_signatures {
        let signed = runtime
            .command(staging_dir, package)?
            .args(["audit", "signatures", "--prefix", install_path])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .status()?;
        anyhow::ensure!(
            signed.success(),
            "NPM signature/provenance verification failed for '{package}'; refusing to activate it"
        );
    }
    unchanged()?;
    if allow_scripts {
        let rebuilt = runtime
            .command(staging_dir, package)?
            .args(["rebuild", "--prefix", install_path])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .status()?;
        anyhow::ensure!(
            rebuilt.success(),
            "NPM lifecycle-script rebuild failed for '{package}'; refusing to activate it"
        );
        unchanged()?;
    }
    lock.verify_installed(staging_dir, &spec)?;
    write_receipt(
        (staging_dir, install_dir),
        package,
        &runtime,
        &lock,
        &review,
        allow_scripts,
        require_signatures,
    )?;
    Ok(ReviewedNpm {
        runtime,
        node_admission,
        spec,
        lock,
        package: package.to_owned(),
        overrides,
        advisory: NpmAdmission::Fresh {
            review,
            source: advisories,
        },
    })
}

pub(crate) struct ReviewedNpm<'a> {
    runtime: ManagedNpm,
    node_admission: crate::runtimes::security::RuntimeAdmission,
    spec: crate::core::security::npm::NpmSpec,
    lock: crate::core::security::npm::NpmLock,
    package: String,
    overrides: Vec<&'static str>,
    advisory: NpmAdmission<'a>,
}

enum NpmAdmission<'a> {
    Fresh {
        review: crate::core::security::package_review::PackageReview,
        source: &'a dyn crate::core::security::vulnerability::VulnerabilitySource,
    },
    Cached {
        receipt_sha256: String,
    },
}

impl ReviewedNpm<'_> {
    pub(crate) fn verify(&self, prefix: &Path) -> Result<()> {
        match &self.advisory {
            NpmAdmission::Fresh { review, source } => review.verify(*source)?,
            NpmAdmission::Cached { receipt_sha256 } => {
                let receipt = read_advisory_receipt(prefix)?;
                verify_receipt_freshness(&receipt)?;
                anyhow::ensure!(
                    receipt["coverage"] == "assessed"
                        && super::tool_artifacts::hash(&serde_json::to_vec(&receipt)?)
                            == *receipt_sha256,
                    "Cached npm receipt changed before activation"
                );
                super::security::admit_installed(
                    "pi",
                    prefix,
                    super::security::ReviewMode::CachedOnly,
                )?
                .verify(prefix)?;
                let policy = crate::core::security::policy::SecurityPolicy::load_current()?;
                for package in npm_inventory(&self.lock) {
                    policy.check_source(&package.name, &package.origin, None)?;
                }
            }
        }
        verify_installation(
            prefix,
            &self.runtime,
            &self.node_admission,
            &self.spec,
            &self.lock,
            (&self.package, &self.overrides),
        )
    }

    pub(crate) fn node_path(&self) -> &Path {
        &self.runtime.node
    }
}

fn verify_installation(
    prefix: &Path,
    runtime: &ManagedNpm,
    node_admission: &crate::runtimes::security::RuntimeAdmission,
    spec: &crate::core::security::npm::NpmSpec,
    lock: &crate::core::security::npm::NpmLock,
    request: (&str, &[&str]),
) -> Result<()> {
    let (package, overrides) = request;
    runtime.verify()?;
    node_admission.verify(&runtime.version_dir)?;
    anyhow::ensure!(
        active_security_overrides("npm", package) == overrides
            && crate::core::security::npm::NpmLock::parse(
                &read_npm_metadata(&prefix.join("package-lock.json"), 16 * 1024 * 1024)?,
                spec
            )?
            .sha256
                == lock.sha256,
        "NPM dependencies or security options changed after advisory review; activation cancelled"
    );
    lock.verify_installed(prefix, spec)
}

fn npm_inventory(
    lock: &crate::core::security::npm::NpmLock,
) -> Vec<crate::package_managers::types::SecurityPackage> {
    use crate::package_managers::types::{SecurityOrigin, SecurityPackage};
    lock.packages
        .values()
        .map(|item| (item.name.clone(), item.version.clone()))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|(name, version)| SecurityPackage {
            origin: SecurityOrigin::NpmRegistry,
            name,
            version,
            advisory_source: None,
            architecture: None,
            description: String::new(),
            licenses: Vec::new(),
        })
        .collect()
}

fn transaction_context(
    package: &str,
    install_dir: &Path,
    runtime: &ManagedNpm,
    lock: &crate::core::security::npm::NpmLock,
    overrides: &[&str],
) -> Result<String> {
    Ok(serde_json::to_string(&(
        package,
        install_dir,
        &lock.sha256,
        &runtime.version,
        &runtime.identity,
        overrides,
        nix::unistd::getuid().as_raw(),
        nix::unistd::geteuid().as_raw(),
    ))?)
}

fn review_lock(
    package: &str,
    install_dir: &Path,
    runtime: &ManagedNpm,
    lock: &crate::core::security::npm::NpmLock,
    overrides: &[&str],
    advisories: &dyn crate::core::security::vulnerability::VulnerabilitySource,
) -> Result<crate::core::security::package_review::PackageReview> {
    crate::core::security::package_review::review(
        &npm_inventory(lock),
        &transaction_context(package, install_dir, runtime, lock, overrides)?,
        &[],
        advisories,
    )
}

fn read_advisory_receipt(prefix: &Path) -> Result<serde_json::Value> {
    let bytes = read_npm_metadata(
        &prefix.join(".omg-npm-advisory-review.json"),
        16 * 1024 * 1024,
    )?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_receipt(
    paths: (&Path, &Path),
    package: &str,
    runtime: &ManagedNpm,
    lock: &crate::core::security::npm::NpmLock,
    review: &crate::core::security::package_review::PackageReview,
    scripts_ran: bool,
    signatures_verified: bool,
) -> Result<()> {
    use sha2::{Digest as _, Sha256};
    let (prefix, destination) = paths;
    let runtime_content_sha256 =
        hex::encode(Sha256::digest(serde_json::to_vec(&runtime.identity)?));
    let legacy_id = review.legacy_id_for_context(&transaction_context(
        package,
        destination,
        runtime,
        lock,
        &active_security_overrides("npm", package),
    )?);
    let assessed = review
        .assessments()
        .iter()
        .all(|item| item.coverage.is_assessed());
    let mut receipt = serde_json::json!({
        "schema_version":2,"package":package,"lock_sha256":lock.sha256,"node_version":runtime.version,
        "node_path":runtime.node,"runtime_content_sha256":runtime_content_sha256,
        "node_root":runtime.version_dir,"reviewed_at":jiff::Timestamp::now().to_string(),
        "review_id":legacy_id,
        "risk_accepted":review.accepted(),"coverage":if assessed { "assessed" } else { "unknown" },
        "security_overrides":active_security_overrides("npm", package),
        "lifecycle_scripts_ran":scripts_ran,"npm_signatures_verified":signatures_verified,
        "assessments":review.assessments().iter().map(|item|serde_json::json!({"name":item.package.name,"version":item.package.version,"source":item.coverage.provenance(),"findings":item.findings})).collect::<Vec<_>>(),
    });
    if !assessed {
        receipt["coverage_review_id"] = serde_json::to_value(review.id())?;
        receipt["unknown_coverage"] =
            serde_json::Value::Array(
                review
                    .assessments()
                    .iter()
                    .filter_map(|item| {
                        item.coverage.unknown_reason().map(|reason| serde_json::json!({
                "name":item.package.name,"version":item.package.version,"reason":reason,
                "source":item.coverage.provenance(),
            }))
                    })
                    .collect::<Vec<_>>(),
            );
    }
    crate::core::safe_ops::atomic_write_file_sync(
        prefix.join(".omg-npm-advisory-review.json"),
        serde_json::to_vec_pretty(&receipt)?,
    )
}

pub(crate) fn review_installed_npm<'a>(
    package: &str,
    prefix: &Path,
    tools_dir: &Path,
    advisories: &'a dyn crate::core::security::vulnerability::VulnerabilitySource,
    security: &crate::runtimes::security::RuntimeSecurity,
) -> Result<ReviewedNpm<'a>> {
    use crate::core::security::npm::{NpmLock, NpmSpec};
    anyhow::ensure!(
        !host_environment_is_allowed("npm", package),
        "NPM activation requires the pinned public registry"
    );
    let spec = NpmSpec::parse(package)?;
    let lock = NpmLock::parse(&read_npm_metadata(&prefix.join("package-lock.json"), 16 * 1024 * 1024)
        .context("This Pi installation has no reviewed dependency lock; install a current Pi release before selecting it")?, &spec)?;
    let previous = read_advisory_receipt(prefix)?;
    anyhow::ensure!(
        previous["schema_version"] == 2
            && previous["package"].as_str() == Some(package)
            && previous["lock_sha256"].as_str() == Some(lock.sha256.as_str()),
        "NPM activation receipt does not bind the selected package and dependency lock"
    );
    lock.verify_installed(prefix, &spec)?;
    let runtime = ManagedNpm::open(tools_dir)?;
    let node_admission = security.installed(
        "node",
        &runtime.version_dir,
        crate::runtimes::security::ReviewMode::FreshAttended,
    )?;
    let overrides = active_security_overrides("npm", package);
    let review = review_lock(package, prefix, &runtime, &lock, &overrides, advisories)?;
    let unchanged = || -> Result<()> {
        review.verify(advisories)?;
        verify_installation(
            prefix,
            &runtime,
            &node_admission,
            &spec,
            &lock,
            (package, &overrides),
        )
    };
    unchanged()?;
    let require_signatures = !package_is_allowed(ALLOW_UNVERIFIED_ENV, &format!("npm:{package}"));
    if require_signatures {
        let status = runtime
            .command(prefix, package)?
            .args(["audit", "signatures", "--prefix"])
            .arg(prefix)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .status()?;
        anyhow::ensure!(
            status.success(),
            "NPM signature/provenance verification failed for '{package}'; refusing to activate it"
        );
    }
    unchanged()?;
    write_receipt(
        (prefix, prefix),
        package,
        &runtime,
        &lock,
        &review,
        previous["lifecycle_scripts_ran"].as_bool().unwrap_or(false),
        require_signatures,
    )?;
    Ok(ReviewedNpm {
        runtime,
        node_admission,
        spec,
        lock,
        package: package.to_owned(),
        overrides,
        advisory: NpmAdmission::Fresh {
            review,
            source: advisories,
        },
    })
}

fn verify_receipt_freshness(receipt: &serde_json::Value) -> Result<()> {
    let reviewed_at: jiff::Timestamp = receipt["reviewed_at"]
        .as_str()
        .context("Cached npm review has no timestamp")?
        .parse()?;
    let now = jiff::Timestamp::now();
    anyhow::ensure!(
        reviewed_at <= now && now.as_second() - reviewed_at.as_second() <= 1800,
        "Cached npm review expired"
    );
    Ok(())
}

/// Reuse an intact complete review only while its Pi and Node authorities,
/// exact inventory, signatures and separately chosen overrides still match.
pub(crate) fn cached_installed_npm(
    package: &str,
    prefix: &Path,
    tools_dir: &Path,
    security: &crate::runtimes::security::RuntimeSecurity,
    pi_admission: &crate::runtimes::security::RuntimeAdmission,
) -> Result<ReviewedNpm<'static>> {
    use crate::core::security::advisory_review::AdvisoryRiskReview;
    use crate::core::security::npm::{NpmLock, NpmSpec};
    use crate::core::security::vulnerability::{PackageAssessment, PackageCoverage};
    use crate::package_managers::types::{SecurityOrigin, SecurityPackage};
    use sha2::{Digest as _, Sha256};
    pi_admission.verify(prefix)?;
    anyhow::ensure!(
        !host_environment_is_allowed("npm", package),
        "Cached npm selection requires the pinned public registry"
    );
    let spec = NpmSpec::parse(package)?;
    let lock = NpmLock::parse(
        &read_npm_metadata(&prefix.join("package-lock.json"), 16 * 1024 * 1024)?,
        &spec,
    )?;
    let receipt = read_advisory_receipt(prefix)?;
    let runtime = ManagedNpm::open(tools_dir)?;
    let node_admission = security.installed(
        "node",
        &runtime.version_dir,
        crate::runtimes::security::ReviewMode::CachedOnly,
    )?;
    let overrides = active_security_overrides("npm", package);
    let signatures = !package_is_allowed(ALLOW_UNVERIFIED_ENV, &format!("npm:{package}"));
    let manager_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&runtime.identity)?));
    anyhow::ensure!(
        receipt["schema_version"] == 2
            && receipt["package"].as_str() == Some(package)
            && receipt["coverage"] == "assessed"
            && receipt["lock_sha256"].as_str() == Some(lock.sha256.as_str())
            && receipt["node_version"].as_str() == Some(runtime.version.as_str())
            && receipt["node_root"] == serde_json::to_value(&runtime.version_dir)?
            && receipt["node_path"] == serde_json::to_value(&runtime.node)?
            && receipt["runtime_content_sha256"].as_str() == Some(manager_sha256.as_str())
            && receipt["security_overrides"] == serde_json::to_value(&overrides)?
            && receipt["npm_signatures_verified"].as_bool() == Some(signatures)
            && receipt["lifecycle_scripts_ran"].is_boolean(),
        "Cached npm review identity or security choices changed"
    );
    verify_receipt_freshness(&receipt)?;
    let coordinates = lock
        .packages
        .values()
        .map(|item| (item.name.clone(), item.version.clone()))
        .collect::<std::collections::BTreeSet<_>>();
    let rows = receipt["assessments"]
        .as_array()
        .context("Cached npm review has no complete inventory")?;
    anyhow::ensure!(
        rows.len() == coordinates.len(),
        "Cached npm review omitted dependencies"
    );
    let mut assessed = BTreeMap::new();
    for row in rows {
        let name = row["name"]
            .as_str()
            .context("Cached npm assessment has no name")?
            .to_owned();
        let version = row["version"]
            .as_str()
            .context("Cached npm assessment has no version")?
            .to_owned();
        let package = SecurityPackage {
            origin: SecurityOrigin::NpmRegistry,
            name: name.clone(),
            version: version.clone(),
            advisory_source: None,
            architecture: None,
            description: String::new(),
            licenses: vec![],
        };
        let assessment = PackageAssessment {
            package,
            coverage: PackageCoverage::Assessed {
                provenance: serde_json::from_value(row["source"].clone())?,
            },
            findings: serde_json::from_value(row["findings"].clone())?,
        };
        anyhow::ensure!(
            coordinates.contains(&(name.clone(), version.clone()))
                && assessed.insert((name, version), assessment).is_none(),
            "Cached npm review inventory changed"
        );
    }
    let assessments = assessed.into_values().collect::<Vec<_>>();
    let transaction = serde_json::to_string(&(
        package,
        prefix,
        &lock.sha256,
        &runtime.version,
        &runtime.identity,
        &overrides,
        nix::unistd::getuid().as_raw(),
        nix::unistd::geteuid().as_raw(),
    ))?;
    let review = AdvisoryRiskReview::new(&assessments, &transaction)?;
    anyhow::ensure!(
        receipt["review_id"] == serde_json::to_value(review.as_ref().map(AdvisoryRiskReview::id))?
            && receipt["risk_accepted"].as_bool() == Some(review.is_some()),
        "Cached npm risk decision does not match its complete evidence"
    );
    let binding = ReviewedNpm {
        runtime,
        node_admission,
        spec,
        lock,
        package: package.to_owned(),
        overrides,
        advisory: NpmAdmission::Cached {
            receipt_sha256: super::tool_artifacts::hash(&serde_json::to_vec(&receipt)?),
        },
    };
    binding.verify(prefix)?;
    pi_admission.verify(prefix)?;
    Ok(binding)
}

#[cfg(all(test, unix))]
mod admission_tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    const PACKAGE: &str = "@earendil-works/pi-coding-agent@0.83.0";
    struct CleanSource;
    impl crate::core::security::vulnerability::VulnerabilitySource for CleanSource {
        fn assess_packages<'a>(
            &'a self,
            packages: &'a [crate::package_managers::types::SecurityPackage],
            _: crate::core::security::vulnerability::AssessmentUse,
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
            Box::pin(async move {
                Ok(packages
                    .iter()
                    .map(
                        |package| crate::core::security::vulnerability::PackageAssessment {
                            package: package.clone(),
                            coverage:
                                crate::core::security::vulnerability::PackageCoverage::Assessed {
                                    provenance:
                                        crate::core::security::scan::AdvisoryProvenance::Osv {
                                            ecosystem: "npm".into(),
                                        },
                                },
                            findings: vec![],
                        },
                    )
                    .collect())
            })
        }
    }
    struct Fixture {
        owner: tempfile::TempDir,
        tools: PathBuf,
        prefix: PathBuf,
        node: PathBuf,
    }

    struct ChangingSource {
        phases: PathBuf,
        after_phase: Option<&'static str>,
        unknown: bool,
        changed: std::sync::atomic::AtomicBool,
    }

    impl crate::core::security::vulnerability::VulnerabilitySource for ChangingSource {
        fn assess_packages<'a>(
            &'a self,
            packages: &'a [crate::package_managers::types::SecurityPackage],
            use_case: crate::core::security::vulnerability::AssessmentUse,
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
            Box::pin(async move {
                let mut reports =
                    crate::core::security::vulnerability::VulnerabilitySource::assess_packages(
                        &CleanSource,
                        packages,
                        use_case,
                    )
                    .await?;
                if self.unknown {
                    for report in &mut reports {
                        report.coverage = crate::core::security::vulnerability::PackageCoverage::Unknown {
                            reason: crate::core::security::vulnerability::UnknownCoverage::EvidenceUnavailable,
                            provenance: None,
                        };
                    }
                }
                let changed = self.changed.load(std::sync::atomic::Ordering::SeqCst)
                    || self.after_phase.is_some_and(|phase| {
                        fs::read_to_string(&self.phases)
                            .is_ok_and(|phases| phases.lines().any(|item| item == phase))
                    });
                if changed {
                    reports[0]
                        .findings
                        .push(crate::core::security::scan::Vulnerability {
                            applicability:
                                crate::core::security::scan::FindingApplicability::Applicable,
                            id: "CVE-2021-23337".into(),
                            summary: "Newly disclosed npm dependency finding".into(),
                            score: Some("9.8".into()),
                            advisory_severity: None,
                            native_advisory: None,
                            affected_installed: vec![],
                        });
                }
                Ok(reports)
            })
        }
    }

    #[test]
    fn banned_transitive_dependency_stops_npm_before_materialization() {
        const NAME: &str = "runtimes::npm::admission_tests::banned_transitive_dependency_stops_npm_before_materialization";
        if crate::core::testing::run_isolated_test(NAME) {
            return;
        }
        if crate::config::Settings::rerun_test_unprivileged(NAME) {
            return;
        }
        assert!(
            !crate::core::is_root(),
            "policy fixtures must run as an ordinary user"
        );
        let fixture = Fixture::new();
        let config = fixture.owner.path().join("config");
        fs::create_dir(&config).expect("private npm policy directory");
        fs::write(
            config.join("policy.toml"),
            "banned_packages = ['blocked-dependency']\n",
        )
        .expect("ban an exact transitive dependency");
        let lock_path = fixture.owner.path().join("lock.fixture.json");
        let mut lock: serde_json::Value =
            serde_json::from_slice(&fs::read(&lock_path).unwrap()).unwrap();
        let mut dependency =
            lock["packages"]["node_modules/@earendil-works/pi-coding-agent"].clone();
        dependency["version"] = "1.2.3".into();
        dependency["resolved"] =
            "https://registry.npmjs.org/blocked-dependency/-/blocked-dependency-1.2.3.tgz".into();
        lock["packages"]["node_modules/blocked-dependency"] = dependency;
        lock["packages"]["node_modules/@earendil-works/pi-coding-agent"]["dependencies"] =
            serde_json::json!({"blocked-dependency":"1.2.3"});
        fs::write(lock_path, serde_json::to_vec(&lock).unwrap())
            .expect("exact transitive registry graph");
        temp_env::with_var("OMG_CONFIG_DIR", Some(config.as_os_str()), || {
            assert_eq!(
                crate::core::paths::config_dir(),
                config,
                "the private npm policy must be the effective policy"
            );
            assert_eq!(
                crate::core::security::policy::SecurityPolicy::load_current()
                    .expect("load the actual private npm policy")
                    .banned_packages,
                ["blocked-dependency"],
            );
            let error = fixture
                .install()
                .err()
                .expect("banned transitive dependency must refuse");
            assert!(format!("{error:#}").contains("blocked-dependency"));
            assert_eq!(
                fs::read_to_string(fixture.owner.path().join("phases")).unwrap(),
                "install\n"
            );
            assert!(!fixture.prefix.join("node_modules").exists());
            assert!(
                !fixture
                    .prefix
                    .join(".omg-npm-advisory-review.json")
                    .exists()
            );
        });
    }

    #[test]
    fn changed_advisories_after_ci_refuse_the_next_npm_execution() {
        let fixture = Fixture::new();
        let source = ChangingSource {
            phases: fixture.owner.path().join("phases"),
            after_phase: Some("ci"),
            unknown: false,
            changed: std::sync::atomic::AtomicBool::new(false),
        };
        let error = install_reviewed_npm(
            PACKAGE,
            &fixture.prefix,
            &fixture.prefix,
            &fixture.tools,
            &source,
            &super::super::security::RuntimeSecurity::fixture(),
        )
        .err()
        .expect("new disclosed finding must stop later execution");
        assert!(format!("{error:#}").contains("advisory evidence changed"));
        assert_eq!(fs::read_to_string(&source.phases).unwrap(), "install\nci\n");
        assert!(
            !fixture
                .prefix
                .join(".omg-npm-advisory-review.json")
                .exists()
        );
    }

    #[test]
    fn changed_advisories_after_signatures_refuse_opted_in_lifecycle_scripts() {
        const NAME: &str = "runtimes::npm::admission_tests::changed_advisories_after_signatures_refuse_opted_in_lifecycle_scripts";
        if crate::core::testing::run_isolated_test(NAME) {
            return;
        }
        temp_env::with_var(ALLOW_NPM_SCRIPTS_ENV, Some(PACKAGE), || {
            let fixture = Fixture::new();
            let source = ChangingSource {
                phases: fixture.owner.path().join("phases"),
                after_phase: Some("audit"),
                unknown: false,
                changed: std::sync::atomic::AtomicBool::new(false),
            };
            let error = install_reviewed_npm(
                PACKAGE,
                &fixture.prefix,
                &fixture.prefix,
                &fixture.tools,
                &source,
                &super::super::security::RuntimeSecurity::fixture(),
            )
            .err()
            .expect("changed finding must stop even explicitly enabled scripts");
            assert!(format!("{error:#}").contains("advisory evidence changed"));
            assert_eq!(
                fs::read_to_string(&source.phases).unwrap(),
                "install\nci\naudit\n"
            );
            assert!(
                !fixture
                    .prefix
                    .join(".omg-npm-advisory-review.json")
                    .exists()
            );
        });
    }

    #[test]
    fn retained_npm_admission_rechecks_evidence_before_publication() {
        let fixture = Fixture::new();
        let source = ChangingSource {
            phases: fixture.owner.path().join("phases"),
            after_phase: None,
            unknown: false,
            changed: std::sync::atomic::AtomicBool::new(false),
        };
        let admission = install_reviewed_npm(
            PACKAGE,
            &fixture.prefix,
            &fixture.prefix,
            &fixture.tools,
            &source,
            &super::super::security::RuntimeSecurity::fixture(),
        )
        .expect("initial complete clean admission");
        admission
            .verify(&fixture.prefix)
            .expect("unchanged evidence remains valid");
        source
            .changed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let error = admission
            .verify(&fixture.prefix)
            .expect_err("new finding must invalidate retained publication authority");
        assert!(format!("{error:#}").contains("advisory evidence changed"));
    }

    #[test]
    fn retained_npm_admission_refuses_policy_changes_before_publication() {
        const NAME: &str = "runtimes::npm::admission_tests::retained_npm_admission_refuses_policy_changes_before_publication";
        if crate::core::testing::run_isolated_test(NAME) {
            return;
        }
        if crate::config::Settings::rerun_test_unprivileged(NAME) {
            return;
        }
        assert!(
            !crate::core::is_root(),
            "policy fixtures must run as an ordinary user"
        );
        let fixture = Fixture::new();
        let config = fixture.owner.path().join("config");
        fs::create_dir(&config).expect("owned npm policy directory");
        temp_env::with_var("OMG_CONFIG_DIR", Some(config.as_os_str()), || {
            assert_eq!(
                crate::core::paths::config_dir(),
                config,
                "the private npm policy must be the effective policy"
            );
            assert!(
                crate::core::security::policy::SecurityPolicy::load_current()
                    .expect("load the initial private npm policy")
                    .banned_packages
                    .is_empty()
            );
            let admission = fixture
                .install()
                .expect("initial permitted dependency graph");
            admission
                .verify(&fixture.prefix)
                .expect("unchanged policy and source");
            fs::write(
                config.join("policy.toml"),
                "banned_packages = ['@earendil-works/pi-coding-agent']\n",
            )
            .expect("new policy bans the installed package");
            assert_eq!(
                crate::core::security::policy::SecurityPolicy::load_current()
                    .expect("load the changed private npm policy")
                    .banned_packages,
                ["@earendil-works/pi-coding-agent"],
            );
            let error = admission
                .verify(&fixture.prefix)
                .expect_err("changed policy must invalidate retained publication authority");
            assert!(format!("{error:#}").contains("policy"));
        });
    }

    #[test]
    fn attended_unknown_npm_review_stays_unknown_and_cannot_supply_cached_clean_authority() {
        const NAME: &str = "runtimes::npm::admission_tests::attended_unknown_npm_review_stays_unknown_and_cannot_supply_cached_clean_authority";
        if std::env::var_os("OMG_NPM_UNKNOWN_REVIEW_FIXTURE").is_none() {
            const DRIVER: &str = r"
import importlib.util, os, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('npm_review_terminal', sys.argv[2])
terminal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(terminal)
terminal.NAME = sys.argv[3]
code, transcript = terminal.terminal_case(Path(sys.argv[1]), 'accept', dict(os.environ), expected=(b'Coverage: unknown', b'pi-coding-agent', b'https://www.cve.org/'))
assert code == 0 and b'1 passed; 0 failed' in transcript, transcript.decode(errors='replace')
";
            let mut command = std::process::Command::new(
                crate::core::privilege::root_controlled_program_path("python3")
                    .expect("existing terminal fixture Python"),
            );
            command
                .arg("-c")
                .arg(DRIVER)
                .arg(std::env::current_exe().expect("current npm fixture executable"))
                .arg(
                    Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("scripts/test-arch-advisory-consent.py"),
                )
                .arg(NAME)
                .env("OMG_NPM_UNKNOWN_REVIEW_FIXTURE", "1");
            let output = command
                .output()
                .expect("run real controlling-PTY npm review");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(output.status.success(), "{stdout}\n{stderr}");
            return;
        }
        let fixture = Fixture::new();
        let source = ChangingSource {
            phases: fixture.owner.path().join("phases"),
            after_phase: None,
            unknown: true,
            changed: std::sync::atomic::AtomicBool::new(false),
        };
        let admission = install_reviewed_npm(
            PACKAGE,
            &fixture.prefix,
            &fixture.prefix,
            &fixture.tools,
            &source,
            &super::super::security::RuntimeSecurity::fixture(),
        )
        .expect("exact attended Unknown acceptance permits this graph only");
        admission
            .verify(&fixture.prefix)
            .expect("unchanged accepted Unknown evidence");
        let receipt =
            read_advisory_receipt(&fixture.prefix).expect("published honest Unknown receipt");
        assert_eq!(receipt["coverage"], "unknown");
        assert_eq!(receipt["risk_accepted"], true);
        assert!(
            receipt["coverage_review_id"]
                .as_str()
                .is_some_and(|id| id.len() == 64)
        );
        assert_eq!(
            receipt["unknown_coverage"][0]["reason"],
            "evidence_unavailable"
        );
        drop(admission);
        let security = super::super::security::RuntimeSecurity::fixture();
        let pi = super::super::security::fixture_prepare(
            "pi",
            "0.83.0",
            &fixture.prefix,
            &fixture.prefix,
        )
        .expect("content-bound Pi fixture authority");
        let error = cached_installed_npm(PACKAGE, &fixture.prefix, &fixture.tools, &security, &pi)
            .err()
            .expect("accepted Unknown must never become cached assessed evidence");
        assert!(format!("{error:#}").contains("Cached npm review identity"));
    }
    impl Fixture {
        fn new() -> Self {
            let owner = tempfile::tempdir().expect("owned npm fixture root");
            let tools = owner.path().join("tools");
            let node = owner.path().join("versions/node/24.22.3");
            let prefix = owner.path().join("versions/pi/0.83.0");
            fs::create_dir_all(node.join("bin")).expect("managed Node bin");
            fs::create_dir_all(node.join("lib/node_modules/npm/bin"))
                .expect("managed npm implementation");
            fs::create_dir_all(&prefix).expect("owned Pi prefix");
            fs::write(node.join("bin/node"), b"#!/bin/sh\nexec /bin/sh \"$@\"\n")
                .expect("fixture Node dispatcher");
            fs::set_permissions(node.join("bin/node"), fs::Permissions::from_mode(0o755))
                .expect("fixture Node executable");
            fs::write(
                node.join("lib/node_modules/npm/package.json"),
                br#"{"name":"npm","version":"11.15.0"}"#,
            )
            .expect("bundled npm metadata");
            fs::write(node.join("lib/node_modules/npm/bin/npm-cli.js"),br#"#!/bin/sh
set -eu
fixture=$(cd "$(dirname "$0")/../../../../../../.." && pwd)
while [ "${1#--}" != "$1" ]; do shift; done
phase=$1
shift
printf '%s\n' "$phase" >> "$fixture/phases"
prefix=''
previous=''
for arg in "$@"; do
 if [ "$previous" = '--prefix' ]; then prefix=$arg; fi
 previous=$arg
done
[ -n "$prefix" ]
case "$phase" in
 install) cp "$fixture/lock.fixture.json" "$prefix/package-lock.json" ;;
 ci)
  mkdir -p "$prefix/node_modules/@earendil-works/pi-coding-agent/bin" "$prefix/node_modules/.bin"
  cp "$fixture/package.fixture.json" "$prefix/node_modules/@earendil-works/pi-coding-agent/package.json"
  printf 'controlled executable\n' > "$prefix/node_modules/@earendil-works/pi-coding-agent/bin/run"
  chmod 755 "$prefix/node_modules/@earendil-works/pi-coding-agent/bin/run"
  ln -s ../@earendil-works/pi-coding-agent/bin/run "$prefix/node_modules/.bin/pi"
  ;;
 audit)
  [ ! -f "$fixture/signature-reject" ] || exit 17
  if [ -f "$fixture/receipt-directory" ]; then
   rm -f "$prefix/.omg-npm-advisory-review.json"
   mkdir "$prefix/.omg-npm-advisory-review.json"
  fi
  ;;
 rebuild) ;;
 *) exit 19 ;;
esac
"#).expect("owned npm phase fixture");
            fs::set_permissions(
                node.join("lib/node_modules/npm/bin/npm-cli.js"),
                fs::Permissions::from_mode(0o755),
            )
            .expect("bundled npm entrypoint executable");
            symlink(
                "../lib/node_modules/npm/bin/npm-cli.js",
                node.join("bin/npm"),
            )
            .expect("contained npm entrypoint");
            symlink("24.22.3", node.parent().unwrap().join("current"))
                .expect("selected managed Node");
            let integrity = "sha512-AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==";
            fs::write(owner.path().join("lock.fixture.json"),serde_json::to_vec(&serde_json::json!({"lockfileVersion":3,"packages":{"":{"dependencies":{"@earendil-works/pi-coding-agent":"0.83.0"}},"node_modules/@earendil-works/pi-coding-agent":{"version":"0.83.0","resolved":"https://registry.npmjs.org/@earendil-works/pi-coding-agent/-/pi-coding-agent-0.83.0.tgz","integrity":integrity}}})).unwrap()).expect("exact registry lock fixture");
            fs::write(owner.path().join("package.fixture.json"),br#"{"name":"@earendil-works/pi-coding-agent","version":"0.83.0","bin":{"pi":"bin/run"}}"#).expect("package manifest fixture");
            super::super::security::fixture_install_identity("node", &node)
                .expect("explicit controlled runtime identity");
            Self {
                owner,
                tools,
                prefix,
                node,
            }
        }
        fn install(&self) -> Result<ReviewedNpm<'static>> {
            install_reviewed_npm(
                PACKAGE,
                &self.prefix,
                &self.prefix,
                &self.tools,
                &CleanSource,
                &super::super::security::RuntimeSecurity::fixture(),
            )
        }
        fn identity_file(&self) -> PathBuf {
            fs::read_dir(self.node.parent().unwrap().join(".security"))
                .expect("runtime state directory")
                .map(|entry| entry.expect("owned runtime state entry").path())
                .find(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .ends_with(".identity.json")
                })
                .expect("controlled publisher identity")
        }
    }

    #[test]
    fn unsupported_or_unreadable_bundled_npm_metadata_never_runs_a_manager() {
        let fixture = Fixture::new();
        let metadata = fixture.node.join("lib/node_modules/npm/package.json");
        fs::remove_file(&metadata).expect("remove fixture metadata");
        assert!(ManagedNpm::open(&fixture.tools).is_err());
        fs::write(&metadata, br#"{"version":"invalid-semver"}"#).expect("invalid version fixture");
        assert!(ManagedNpm::open(&fixture.tools).is_err());
        fs::write(&metadata, br#"{"version":"11.14.0"}"#).expect("old resolver fixture");
        assert!(ManagedNpm::open(&fixture.tools).is_err());
        assert!(!fixture.owner.path().join("phases").exists());
    }

    #[test]
    fn missing_runtime_authority_and_unwritable_manifest_stop_before_resolution() {
        let fixture = Fixture::new();
        let identity = fixture.identity_file();
        let prior = fs::read(&identity).unwrap();
        fs::write(&identity, b"malformed publisher identity").expect("invalid identity fixture");
        assert!(fixture.install().is_err());
        assert!(!fixture.owner.path().join("phases").exists());
        fs::write(identity, prior).expect("restore fixture publisher");
        fs::create_dir(fixture.prefix.join("package.json")).expect("manifest write fault");
        assert!(fixture.install().is_err());
        assert!(!fixture.owner.path().join("phases").exists());
    }

    #[test]
    fn receipt_refuses_non_utf8_destination_without_replacing_existing_authority() {
        use std::os::unix::ffi::OsStringExt as _;
        let fixture = Fixture::new();
        let admission = fixture.install().expect("controlled signed installation");
        let receipt_path = fixture.prefix.join(".omg-npm-advisory-review.json");
        let previous = fs::read(&receipt_path).expect("existing exact receipt authority");
        let invalid_destination = fixture.owner.path().join(std::ffi::OsString::from_vec(
            b"invalid-destination-\xff".to_vec(),
        ));
        let review = review_lock(
            PACKAGE,
            &fixture.prefix,
            &admission.runtime,
            &admission.lock,
            &admission.overrides,
            &CleanSource,
        )
        .expect("validated shared receipt capability");
        let error = write_receipt(
            (&fixture.prefix, &invalid_destination),
            PACKAGE,
            &admission.runtime,
            &admission.lock,
            &review,
            false,
            true,
        )
        .expect_err("unrepresentable destination cannot acquire a receipt identity");
        assert!(format!("{error:#}").contains("UTF-8"));
        assert_eq!(
            fs::read(receipt_path).expect("previous authority survives refused replacement"),
            previous
        );
    }

    #[test]
    fn failed_signatures_and_failed_receipt_publication_never_return_an_admission() {
        for marker in ["signature-reject", "receipt-directory"] {
            let fixture = Fixture::new();
            fs::write(fixture.owner.path().join(marker), b"controlled fault")
                .expect("owned failure marker");
            assert!(fixture.install().is_err());
            let phases = fs::read_to_string(fixture.owner.path().join("phases"))
                .expect("observed manager phases");
            assert!(phases.contains("audit"));
            assert!(
                !fixture
                    .prefix
                    .join(".omg-npm-advisory-review.json")
                    .is_file()
            );
        }
    }

    #[test]
    fn retained_npm_admission_refuses_a_malformed_dependency_lock() {
        let fixture = Fixture::new();
        let admission = fixture.install().expect("controlled signed installation");
        admission
            .verify(&fixture.prefix)
            .expect("unchanged complete installation");
        fs::write(
            fixture.prefix.join("package-lock.json"),
            b"invalid dependency lock",
        )
        .expect("mutated lock fixture");
        assert!(admission.verify(&fixture.prefix).is_err());
    }

    #[test]
    fn existing_npm_selection_rechecks_runtime_receipts_and_signature_results() {
        let fixture = Fixture::new();
        drop(fixture.install().expect("controlled initial installation"));
        let security = super::super::security::RuntimeSecurity::fixture();
        drop(
            review_installed_npm(
                PACKAGE,
                &fixture.prefix,
                &fixture.tools,
                &CleanSource,
                &security,
            )
            .expect("unchanged existing selection"),
        );
        fs::write(
            fixture.owner.path().join("signature-reject"),
            b"controlled rejection",
        )
        .expect("signature failure marker");
        assert!(
            review_installed_npm(
                PACKAGE,
                &fixture.prefix,
                &fixture.tools,
                &CleanSource,
                &security
            )
            .is_err()
        );
        fs::remove_file(fixture.owner.path().join("signature-reject"))
            .expect("clear signature failure");
        let identity = fixture.identity_file();
        let prior = fs::read(&identity).unwrap();
        fs::write(&identity, b"invalid publisher").expect("corrupt runtime authority");
        assert!(
            review_installed_npm(
                PACKAGE,
                &fixture.prefix,
                &fixture.tools,
                &CleanSource,
                &security
            )
            .is_err()
        );
        fs::write(identity, prior).expect("restore runtime authority");
        fs::write(
            fixture.prefix.join(".omg-npm-advisory-review.json"),
            b"invalid receipt",
        )
        .expect("corrupt prior review receipt");
        assert!(
            review_installed_npm(
                PACKAGE,
                &fixture.prefix,
                &fixture.tools,
                &CleanSource,
                &security
            )
            .is_err()
        );
    }

    #[test]
    fn failed_existing_receipt_write_does_not_return_a_replacement_review() {
        let fixture = Fixture::new();
        drop(fixture.install().expect("controlled initial installation"));
        fs::write(
            fixture.owner.path().join("receipt-directory"),
            b"controlled publication failure",
        )
        .expect("receipt failure marker");
        assert!(
            review_installed_npm(
                PACKAGE,
                &fixture.prefix,
                &fixture.tools,
                &CleanSource,
                &super::super::security::RuntimeSecurity::fixture()
            )
            .is_err()
        );
        assert!(
            fixture
                .prefix
                .join(".omg-npm-advisory-review.json")
                .is_dir()
        );
    }

    #[test]
    fn package_scoped_signature_override_remains_bound_through_existing_selection() {
        const NAME: &str = "runtimes::npm::admission_tests::package_scoped_signature_override_remains_bound_through_existing_selection";
        if crate::core::testing::run_isolated_test(NAME) {
            return;
        }
        temp_env::with_var(ALLOW_UNVERIFIED_ENV, Some(format!("npm:{PACKAGE}")), || {
            let fixture = Fixture::new();
            fs::write(
                fixture.owner.path().join("signature-reject"),
                b"unverified fixture",
            )
            .expect("explicit signature rejection marker");
            let admission = fixture
                .install()
                .expect("explicit package override installation");
            admission
                .verify(&fixture.prefix)
                .expect("bound explicit override");
            drop(admission);
            let existing = review_installed_npm(
                PACKAGE,
                &fixture.prefix,
                &fixture.tools,
                &CleanSource,
                &super::super::security::RuntimeSecurity::fixture(),
            )
            .expect("same explicit override on existing selection");
            existing
                .verify(&fixture.prefix)
                .expect("unchanged override authority");
            let phases = fs::read_to_string(fixture.owner.path().join("phases"))
                .expect("observed overridden phases");
            assert!(!phases.lines().any(|phase| phase == "audit"));
            temp_env::with_var(ALLOW_UNVERIFIED_ENV, None::<&str>, || {
                assert!(
                    existing.verify(&fixture.prefix).is_err(),
                    "removing the explicit override must invalidate its capability"
                );
            });
        });
    }

    #[test]
    fn cached_npm_selection_requires_a_valid_lock_and_current_node_authority() {
        let fixture = Fixture::new();
        drop(fixture.install().expect("controlled initial installation"));
        let security = super::super::security::RuntimeSecurity::fixture();
        let pi = super::super::security::fixture_prepare(
            "pi",
            "0.83.0",
            &fixture.prefix,
            &fixture.prefix,
        )
        .expect("controlled Pi publication");
        drop(
            cached_installed_npm(PACKAGE, &fixture.prefix, &fixture.tools, &security, &pi)
                .expect("complete cached npm authority"),
        );
        let identity = fixture.identity_file();
        fs::write(identity, b"invalid publisher").expect("invalid cached Node authority");
        assert!(
            cached_installed_npm(PACKAGE, &fixture.prefix, &fixture.tools, &security, &pi).is_err()
        );
    }

    #[test]
    fn retained_cached_npm_admission_refuses_changed_receipt_expiry_or_imported_content() {
        for case in ["receipt", "expired", "implementation"] {
            let fixture = Fixture::new();
            drop(
                fixture
                    .install()
                    .expect("initial controlled signed installation"),
            );
            let security = super::super::security::RuntimeSecurity::fixture();
            let pi = super::super::security::fixture_prepare(
                "pi",
                "0.83.0",
                &fixture.prefix,
                &fixture.prefix,
            )
            .expect("complete Pi content authority");
            let cached =
                cached_installed_npm(PACKAGE, &fixture.prefix, &fixture.tools, &security, &pi)
                    .expect("initial fresh cached authority");
            cached
                .verify(&fixture.prefix)
                .expect("unchanged cached content and receipt");
            if case == "implementation" {
                fs::write(
                    fixture
                        .prefix
                        .join("node_modules/@earendil-works/pi-coding-agent/bin/run"),
                    b"changed imported implementation",
                )
                .expect("replace only the owned imported implementation");
            } else {
                let mut receipt =
                    read_advisory_receipt(&fixture.prefix).expect("owned cached receipt");
                if case == "expired" {
                    receipt["reviewed_at"] =
                        jiff::Timestamp::from_second(jiff::Timestamp::now().as_second() - 1801)
                            .expect("expired controlled timestamp")
                            .to_string()
                            .into();
                } else {
                    receipt["coverage"] = "unknown".into();
                }
                fs::write(
                    fixture.prefix.join(".omg-npm-advisory-review.json"),
                    serde_json::to_vec(&receipt).unwrap(),
                )
                .expect("change only the owned cached receipt");
            }
            let error = cached
                .verify(&fixture.prefix)
                .expect_err("retained cache must revalidate receipt and complete imported content");
            let detail = format!("{error:#}");
            assert!(
                detail.contains("changed")
                    || detail.contains("match")
                    || detail.contains("expired"),
                "{case}: {detail}"
            );
        }
    }

    #[test]
    fn malformed_advisory_receipt_cannot_establish_cached_authority() {
        let fixture = Fixture::new();
        drop(fixture.install().expect("controlled signed installation"));
        let receipt = fixture.prefix.join(".omg-npm-advisory-review.json");
        fs::remove_file(&receipt).expect("remove the controlled advisory receipt");
        let missing = read_advisory_receipt(&fixture.prefix)
            .expect_err("missing advisory receipt must not establish cached authority");
        assert_eq!(
            missing
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::NotFound),
            "receipt IO failures must remain observable"
        );
        fs::write(receipt, b"invalid published advisory receipt")
            .expect("write malformed advisory receipt fixture");
        let error = read_advisory_receipt(&fixture.prefix)
            .expect_err("malformed cached advisory receipt must refuse parsing");
        assert!(format!("{error:#}").contains("expected value"));
        assert!(
            super::super::security::fixture_prepare(
                "pi",
                "0.83.0",
                &fixture.prefix,
                &fixture.prefix,
            )
            .is_err()
        );
    }

    #[test]
    fn cached_selection_rejects_invalid_lock_even_with_a_bound_candidate_tree() {
        let fixture = Fixture::new();
        drop(fixture.install().expect("controlled signed installation"));
        fs::write(
            fixture.prefix.join("package-lock.json"),
            b"invalid dependency lock",
        )
        .expect("invalid published lock fixture");
        let pi = super::super::security::fixture_prepare(
            "pi",
            "0.83.0",
            &fixture.prefix,
            &fixture.prefix,
        )
        .expect("controlled candidate content authority");
        assert!(
            cached_installed_npm(
                PACKAGE,
                &fixture.prefix,
                &fixture.tools,
                &super::super::security::RuntimeSecurity::fixture(),
                &pi
            )
            .is_err()
        );
    }

    #[test]
    fn cached_selection_requires_admission_for_the_newly_selected_node() {
        let fixture = Fixture::new();
        drop(fixture.install().expect("controlled signed installation"));
        let pi = super::super::security::fixture_prepare(
            "pi",
            "0.83.0",
            &fixture.prefix,
            &fixture.prefix,
        )
        .expect("controlled Pi authority");
        let versions = fixture.node.parent().unwrap();
        let changed = versions.join("24.22.4");
        fs::create_dir(&changed).expect("new managed Node candidate");
        for relative in [
            "bin/node",
            "lib/node_modules/npm/package.json",
            "lib/node_modules/npm/bin/npm-cli.js",
        ] {
            let target = changed.join(relative);
            fs::create_dir_all(target.parent().unwrap()).expect("new Node component directory");
            fs::copy(fixture.node.join(relative), target).expect("copy controlled Node component");
        }
        symlink(
            "../lib/node_modules/npm/bin/npm-cli.js",
            changed.join("bin/npm"),
        )
        .expect("new Node contained npm link");
        super::super::security::fixture_install_identity("node", &changed)
            .expect("explicit publisher identity for new Node");
        fs::remove_file(versions.join("current")).expect("clear prior Node selection");
        symlink("24.22.4", versions.join("current")).expect("select unreviewed Node candidate");
        let error = cached_installed_npm(
            PACKAGE,
            &fixture.prefix,
            &fixture.tools,
            &super::super::security::RuntimeSecurity::fixture(),
            &pi,
        )
        .err()
        .expect("new Node must have its own current evidence");
        assert!(format!("{error:#}").contains("evidence is missing"));
    }
}
