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

pub(crate) fn install_reviewed_npm(
    package: &str,
    staging_dir: &Path,
    install_dir: &Path,
    tools_dir: &Path,
    advisories: &dyn crate::core::security::vulnerability::VulnerabilitySource,
    security: &crate::runtimes::security::RuntimeSecurity,
) -> Result<ReviewedNpm> {
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
        staging_dir,
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
    })
}

pub(crate) struct ReviewedNpm {
    runtime: ManagedNpm,
    node_admission: crate::runtimes::security::RuntimeAdmission,
    spec: crate::core::security::npm::NpmSpec,
    lock: crate::core::security::npm::NpmLock,
    package: String,
    overrides: Vec<&'static str>,
}

impl ReviewedNpm {
    pub(crate) fn verify(&self, prefix: &Path) -> Result<()> {
        self.runtime.verify()?;
        self.node_admission.verify(&self.runtime.version_dir)?;
        anyhow::ensure!(
            active_security_overrides("npm", &self.package) == self.overrides
                && crate::core::security::npm::NpmLock::parse(
                    &read_npm_metadata(&prefix.join("package-lock.json"), 16 * 1024 * 1024)?,
                    &self.spec
                )?
                .sha256
                    == self.lock.sha256,
            "NPM dependencies or security options changed after advisory review; activation cancelled"
        );
        self.lock.verify_installed(prefix, &self.spec)
    }

    pub(crate) fn node_path(&self) -> &Path {
        &self.runtime.node
    }
}

struct NpmReview {
    assessments: Vec<crate::core::security::vulnerability::PackageAssessment>,
    review: Option<crate::core::security::advisory_review::AdvisoryRiskReview>,
    acceptance: Option<crate::core::security::advisory_review::AdvisoryRiskAcceptance>,
}

fn review_lock(
    package: &str,
    install_dir: &Path,
    runtime: &ManagedNpm,
    lock: &crate::core::security::npm::NpmLock,
    overrides: &[&str],
    advisories: &dyn crate::core::security::vulnerability::VulnerabilitySource,
) -> Result<NpmReview> {
    use crate::core::security::advisory_review::AdvisoryRiskReview;
    use crate::core::security::vulnerability::validate_assessment_inventory;
    use crate::package_managers::types::{SecurityOrigin, SecurityPackage};
    let coordinates = lock
        .packages
        .values()
        .map(|item| (item.name.clone(), item.version.clone()))
        .collect::<std::collections::BTreeSet<_>>();
    let inventory = coordinates
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
        .collect::<Vec<_>>();
    let assessments = assess(advisories, &inventory)
        .context("NPM advisory coverage is UNKNOWN; no clean result was established and installation was cancelled")?;
    validate_assessment_inventory(&inventory, &assessments)?;
    anyhow::ensure!(
        assessments.iter().all(|item| item.coverage.is_assessed()),
        "NPM advisory coverage is UNKNOWN; installation cancelled"
    );
    let transaction = serde_json::to_string(&(
        package,
        install_dir,
        &lock.sha256,
        &runtime.version,
        &runtime.identity,
        &overrides,
        nix::unistd::getuid().as_raw(),
        nix::unistd::geteuid().as_raw(),
    ))?;
    let review = AdvisoryRiskReview::new(&assessments, &transaction)?;
    let acceptance = if let Some(review) = &review {
        crate::core::privilege::confirm_security_review(
            review.details(),
            review.id(),
            nix::unistd::getuid().as_raw(),
            &|| Ok(()),
        )?;
        Some(review.accept(&format!("accept {}", review.id()))?)
    } else {
        None
    };
    if let Some(acceptance) = &acceptance {
        let current = assess(advisories, &inventory)?;
        validate_assessment_inventory(&inventory, &current)?;
        let current_review = AdvisoryRiskReview::new(&current, &transaction)?;
        anyhow::ensure!(
            current.iter().all(|item| item.coverage.is_assessed())
                && current_review
                    .as_ref()
                    .is_some_and(|review| acceptance.matches(review)),
            "NPM advisory evidence changed after acceptance; review the new report before installing"
        );
    }
    Ok(NpmReview {
        assessments,
        review,
        acceptance,
    })
}

fn assess(
    source: &dyn crate::core::security::vulnerability::VulnerabilitySource,
    inventory: &[crate::package_managers::types::SecurityPackage],
) -> Result<Vec<crate::core::security::vulnerability::PackageAssessment>> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(source.assess_packages(
                        inventory,
                        crate::core::security::vulnerability::AssessmentUse::Admission,
                    ))
                    .map_err(anyhow::Error::from)
            })
            .join()
            .map_err(|_| anyhow::anyhow!("NPM advisory worker failed"))?
    })
}

fn write_receipt(
    prefix: &Path,
    package: &str,
    runtime: &ManagedNpm,
    lock: &crate::core::security::npm::NpmLock,
    review: &NpmReview,
    scripts_ran: bool,
    signatures_verified: bool,
) -> Result<()> {
    use crate::core::security::advisory_review::AdvisoryRiskReview;
    use sha2::{Digest as _, Sha256};
    let runtime_content_sha256 =
        hex::encode(Sha256::digest(serde_json::to_vec(&runtime.identity)?));
    let receipt = serde_json::json!({
        "schema_version":2,"package":package,"lock_sha256":lock.sha256,"node_version":runtime.version,
        "node_path":runtime.node,"runtime_content_sha256":runtime_content_sha256,
        "node_root":runtime.version_dir,"reviewed_at":jiff::Timestamp::now().to_string(),
        "review_id":review.review.as_ref().map(AdvisoryRiskReview::id),
        "risk_accepted":review.acceptance.is_some(),"coverage":"assessed",
        "lifecycle_scripts_ran":scripts_ran,"npm_signatures_verified":signatures_verified,
        "assessments":review.assessments.iter().map(|item|serde_json::json!({"name":item.package.name,"version":item.package.version,"source":item.coverage.provenance(),"findings":item.findings})).collect::<Vec<_>>(),
    });
    crate::core::safe_ops::atomic_write_file_sync(
        prefix.join(".omg-npm-advisory-review.json"),
        serde_json::to_vec_pretty(&receipt)?,
    )
}

pub(crate) fn review_installed_npm(
    package: &str,
    prefix: &Path,
    tools_dir: &Path,
    advisories: &dyn crate::core::security::vulnerability::VulnerabilitySource,
    security: &crate::runtimes::security::RuntimeSecurity,
) -> Result<ReviewedNpm> {
    use crate::core::security::npm::{NpmLock, NpmSpec};
    anyhow::ensure!(
        !host_environment_is_allowed("npm", package),
        "NPM activation requires the pinned public registry"
    );
    let spec = NpmSpec::parse(package)?;
    let lock = NpmLock::parse(&read_npm_metadata(&prefix.join("package-lock.json"), 16 * 1024 * 1024)
        .context("This Pi installation has no reviewed dependency lock; install a current Pi release before selecting it")?, &spec)?;
    let previous: serde_json::Value = serde_json::from_slice(&read_npm_metadata(
        &prefix.join(".omg-npm-advisory-review.json"),
        16 * 1024 * 1024,
    )?)?;
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
    let binding = ReviewedNpm {
        runtime,
        node_admission,
        spec,
        lock,
        package: package.to_owned(),
        overrides,
    };
    binding.verify(prefix)?;
    let require_signatures = !package_is_allowed(ALLOW_UNVERIFIED_ENV, &format!("npm:{package}"));
    if require_signatures {
        let status = binding
            .runtime
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
    binding.verify(prefix)?;
    write_receipt(
        prefix,
        package,
        &binding.runtime,
        &binding.lock,
        &review,
        previous["lifecycle_scripts_ran"].as_bool().unwrap_or(false),
        require_signatures,
    )?;
    Ok(binding)
}
