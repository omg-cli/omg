//! Resolved package admission shares one source, policy and terminal decision boundary.

use super::advisory_review::{AdvisoryRiskIdentity, AdvisoryRiskReview};
use super::policy::SecurityPolicy;
use super::vulnerability::{
    AssessmentUse, PackageAssessment, PackageCoverage, UnknownCoverage, VulnerabilitySource,
    validate_assessment_inventory,
};
use crate::package_managers::types::SecurityPackage;
use anyhow::{Context as _, Result, ensure};
use sha2::{Digest as _, Sha256};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub(crate) struct PackageReview {
    inventory: Vec<SecurityPackage>,
    context: String,
    gaps: Vec<String>,
    policy_sha256: String,
    uid: u32,
    euid: u32,
    assessments: Vec<PackageAssessment>,
    review_id: Option<String>,
    legacy_identity: Option<AdvisoryRiskIdentity>,
}

struct CancelPrompt(Arc<AtomicBool>);
impl Drop for CancelPrompt {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

fn policy_identity() -> Result<(SecurityPolicy, String)> {
    let policy = SecurityPolicy::load_current()?;
    let hash = hex::encode(Sha256::digest(serde_json::to_vec(&policy)?));
    Ok((policy, hash))
}

async fn assess(
    source: &dyn VulnerabilitySource,
    inventory: &[SecurityPackage],
    gaps: &[String],
) -> Result<Vec<PackageAssessment>> {
    let known = inventory
        .iter()
        .filter(|package| package.origin != crate::package_managers::types::SecurityOrigin::Unknown)
        .cloned()
        .collect::<Vec<_>>();
    if known.is_empty() {
        return Ok(inventory
            .iter()
            .cloned()
            .map(|package| {
                PackageAssessment::unknown(package, UnknownCoverage::OriginUnestablished)
            })
            .collect());
    }
    let known_reports = match source
        .assess_packages(&known, AssessmentUse::Admission)
        .await
    {
        Ok(reports) => {
            validate_assessment_inventory(&known, &reports)?;
            reports
        }
        Err(_) => known
            .iter()
            .cloned()
            .map(|package| {
                PackageAssessment::unknown(package, UnknownCoverage::EvidenceUnavailable)
            })
            .collect(),
    };
    let mut known_reports = known_reports.into_iter();
    let mut reports = inventory
        .iter()
        .map(|package| {
            if package.origin == crate::package_managers::types::SecurityOrigin::Unknown {
                Ok(PackageAssessment::unknown(
                    package.clone(),
                    UnknownCoverage::OriginUnestablished,
                ))
            } else {
                known_reports
                    .next()
                    .context("Missing known package assessment")
            }
        })
        .collect::<Result<Vec<_>>>()?;
    validate_assessment_inventory(inventory, &reports)?;
    if !gaps.is_empty() {
        for report in &mut reports {
            report.coverage = PackageCoverage::Unknown {
                reason: UnknownCoverage::EvidenceUnavailable,
                provenance: report.coverage.provenance().cloned(),
            };
        }
    }
    Ok(reports)
}

/// Review the proposed inventory and revalidate the evidence after consent.
pub(crate) async fn review_async(
    inventory: &[SecurityPackage],
    context: &str,
    gaps: &[String],
    source: &dyn VulnerabilitySource,
) -> Result<PackageReview> {
    ensure!(
        !inventory.is_empty() && inventory.len() <= 4096,
        "Package admission requires a bounded, nonempty proposed inventory"
    );
    ensure!(
        context.len() <= 1024 * 1024
            && gaps.len() <= 128
            && gaps.iter().all(|gap| gap.len() <= 4096),
        "Package admission context exceeds its bound"
    );
    let (policy, policy_sha256) = policy_identity()?;
    let uid = crate::core::privilege::invoking_uid()?;
    let euid = nix::unistd::geteuid().as_raw();
    let context = serde_json::to_string(&(
        "omg-package-admission-v1",
        context,
        gaps,
        &policy_sha256,
        uid,
        euid,
    ))?;
    let assessments = assess(source, inventory, gaps).await?;
    for report in &assessments {
        policy.check_source(&report.package.name, &report.package.origin, None)?;
    }
    let risk = AdvisoryRiskReview::new_with_unknown(&assessments, &context)?;
    if let Some(risk) = &risk {
        let mut details = risk.details().to_owned();
        for gap in gaps {
            details.push_str("\nCoverage gap: ");
            details.push_str(&serde_json::to_string(gap)?);
        }
        details.push_str("\nAdvisory information: https://www.cve.org/\nMissing or partial evidence does not establish that these packages are safe.");
        ensure!(
            details.len() <= 60 * 1024,
            "Package advisory review exceeds the terminal bound"
        );
        let id = risk.id().to_owned();
        let kind = risk.kind();
        let cancelled = Arc::new(AtomicBool::new(false));
        let _cancel_on_drop = CancelPrompt(Arc::clone(&cancelled));
        tokio::task::spawn_blocking(move || {
            crate::core::privilege::confirm_security_review(&details, &id, kind, uid, &|| {
                ensure!(
                    !cancelled.load(Ordering::Acquire),
                    "Package admission cancelled"
                );
                Ok(())
            })
        })
        .await
        .context("Package security terminal owner failed")??;
        risk.accept(&format!("accept {}", risk.id()))?;
    }
    let review = PackageReview {
        inventory: inventory.to_vec(),
        context,
        gaps: gaps.to_vec(),
        policy_sha256,
        uid,
        euid,
        assessments,
        review_id: risk.as_ref().map(|review| review.id().to_owned()),
        legacy_identity: risk
            .as_ref()
            .and_then(AdvisoryRiskReview::legacy_identity)
            .cloned(),
    };
    review.verify_async(source).await?;
    Ok(review)
}

pub(crate) fn review(
    inventory: &[SecurityPackage],
    context: &str,
    gaps: &[String],
    source: &dyn VulnerabilitySource,
) -> Result<PackageReview> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(review_async(inventory, context, gaps, source))
            })
            .join()
            .map_err(|_| anyhow::anyhow!("Package admission worker failed"))?
    })
}

impl PackageReview {
    pub(crate) fn assessments(&self) -> &[PackageAssessment] {
        &self.assessments
    }
    pub(crate) fn id(&self) -> Option<&str> {
        self.review_id.as_deref()
    }
    pub(crate) fn accepted(&self) -> bool {
        self.review_id.is_some()
    }

    pub(crate) fn legacy_id_for_context(&self, context: &str) -> Option<String> {
        self.legacy_identity
            .as_ref()
            .map(|identity| identity.id_for_context(context))
    }

    pub(crate) async fn verify_async(&self, source: &dyn VulnerabilitySource) -> Result<()> {
        let (_, policy) = policy_identity()?;
        ensure!(
            policy == self.policy_sha256
                && crate::core::privilege::invoking_uid()? == self.uid
                && nix::unistd::geteuid().as_raw() == self.euid,
            "Package admission policy or invoking principal changed"
        );
        let current = assess(source, &self.inventory, &self.gaps).await?;
        let risk = AdvisoryRiskReview::new_with_unknown(&current, &self.context)?;
        ensure!(
            risk.as_ref().map(AdvisoryRiskReview::id) == self.review_id.as_deref(),
            "Package advisory evidence changed; review this transaction again"
        );
        Ok(())
    }

    pub(crate) fn verify(&self, source: &dyn VulnerabilitySource) -> Result<()> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?
                        .block_on(self.verify_async(source))
                })
                .join()
                .map_err(|_| anyhow::anyhow!("Package admission verification worker failed"))?
        })
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use crate::core::security::scan::{AdvisoryProvenance, FindingApplicability, Vulnerability};
    use crate::core::security::vulnerability::VulnerabilityError;
    use crate::package_managers::types::SecurityOrigin;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::AtomicUsize;

    const CLEAN: usize = 0;
    const KNOWN: usize = 1;
    const UNAVAILABLE: usize = 2;
    const MISMATCH: usize = 3;
    const PANIC: usize = 4;
    const TEST: &str = "core::security::package_review::tests::shared_package_admission_preserves_evidence_and_requires_exact_consent";

    struct FixtureSource {
        state: AtomicUsize,
        calls: AtomicUsize,
        seen: std::sync::Mutex<Vec<Vec<SecurityPackage>>>,
    }

    impl FixtureSource {
        fn new(state: usize) -> Self {
            Self {
                state: AtomicUsize::new(state),
                calls: AtomicUsize::new(0),
                seen: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl VulnerabilitySource for FixtureSource {
        fn assess_packages<'a>(
            &'a self,
            inventory: &'a [SecurityPackage],
            evidence_use: AssessmentUse,
        ) -> Pin<
            Box<
                dyn Future<Output = std::result::Result<Vec<PackageAssessment>, VulnerabilityError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                assert_eq!(evidence_use, AssessmentUse::Admission);
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.seen
                    .lock()
                    .expect("fixture queries")
                    .push(inventory.to_vec());
                if inventory
                    .iter()
                    .any(|package| package.origin == SecurityOrigin::Unknown)
                {
                    return Err(VulnerabilityError::Unavailable {
                        reason: "registry provider refuses foreign subjects".into(),
                    });
                }
                let state = self.state.load(Ordering::SeqCst);
                assert_ne!(state, PANIC, "controlled advisory worker panic");
                if state == UNAVAILABLE {
                    return Err(VulnerabilityError::Unavailable {
                        reason: "controlled feed unavailable".into(),
                    });
                }
                Ok(inventory
                    .iter()
                    .cloned()
                    .map(|mut package| {
                        if state == MISMATCH {
                            package.version = "9.9.9".into();
                        }
                        PackageAssessment {
                            package,
                            coverage: PackageCoverage::Assessed {
                                provenance: AdvisoryProvenance::Osv {
                                    ecosystem: "npm".into(),
                                },
                            },
                            findings: if state == KNOWN {
                                vec![Vulnerability {
                                    applicability: FindingApplicability::Applicable,
                                    id: "CVE-2021-23337".into(),
                                    summary: "Controlled disclosed advisory fixture".into(),
                                    score: Some("9.8".into()),
                                    advisory_severity: None,
                                    native_advisory: None,
                                    affected_installed: Vec::new(),
                                }]
                            } else {
                                Vec::new()
                            },
                        }
                    })
                    .collect())
            })
        }
    }

    fn subject(origin: SecurityOrigin) -> SecurityPackage {
        SecurityPackage {
            origin,
            name: "omg-review-fixture".into(),
            version: "1.0.0".into(),
            advisory_source: None,
            architecture: None,
            description: String::new(),
            licenses: Vec::new(),
        }
    }

    #[tokio::test]
    async fn mixed_private_dependencies_retain_public_findings_and_original_inventory_order()
    -> Result<()> {
        let source = FixtureSource::new(KNOWN);
        let foreign = [subject(SecurityOrigin::Unknown)];
        let rejected = source
            .assess_packages(&foreign, AssessmentUse::Admission)
            .await;
        assert!(matches!(
            rejected,
            Err(VulnerabilityError::Unavailable { .. })
        ));
        assert_eq!(source.calls.swap(0, Ordering::SeqCst), 1);
        source.seen.lock().expect("queries").clear();
        let mut inventory = vec![
            subject(SecurityOrigin::Unknown),
            subject(SecurityOrigin::NpmRegistry),
            subject(SecurityOrigin::Unknown),
            subject(SecurityOrigin::NpmRegistry),
        ];
        for (index, package) in inventory.iter_mut().enumerate() {
            package.name = format!("fixture-package-{index}");
        }
        let reports = assess(&source, &inventory, &[]).await?;
        validate_assessment_inventory(&inventory, &reports)?;
        assert_eq!(
            source.seen.lock().expect("queries")[0],
            vec![inventory[1].clone(), inventory[3].clone()]
        );
        for index in [0, 2] {
            assert_eq!(
                reports[index].coverage.unknown_reason(),
                Some(UnknownCoverage::OriginUnestablished)
            );
            assert!(reports[index].findings.is_empty());
        }
        for index in [1, 3] {
            assert!(reports[index].coverage.is_assessed());
            assert_eq!(reports[index].findings[0].id, "CVE-2021-23337");
        }
        let partial = assess(
            &source,
            &inventory,
            &["direct dependency mapping incomplete".into()],
        )
        .await?;
        assert!(partial.iter().all(|report| !report.coverage.is_assessed()));
        assert_eq!(partial[1].findings[0].id, "CVE-2021-23337");
        assert_eq!(partial[3].findings[0].id, "CVE-2021-23337");
        assert_eq!(source.calls.load(Ordering::SeqCst), 2);
        Ok(())
    }

    fn configure_child(command: &mut std::process::Command, root: &std::path::Path, case: &str) {
        command
            .env("OMG_PACKAGE_REVIEW_FIXTURE", case)
            .env("OMG_PACKAGE_REVIEW_ROOT", root)
            .env("HOME", root)
            .env("XDG_CONFIG_HOME", root.join("config"))
            .env("OMG_CONFIG_DIR", root.join("config/omg"))
            .env("XDG_DATA_HOME", root.join("data"))
            .env("OMG_DATA_DIR", root.join("data/omg"))
            .env_remove("SUDO_USER")
            .env_remove("DOAS_USER");
    }

    fn run_isolated_cases() -> Result<()> {
        let executable = std::env::current_exe()?;
        for case in [
            "known-no-tty",
            "unavailable-no-tty",
            "gaps-no-tty",
            "known-with-gaps-no-tty",
            "known-mixed-private-no-tty",
            "unknown-no-source",
            "new-cve",
            "source-failure",
            "policy-change",
            "retained-principal-mismatch",
            "inventory-mismatch",
            "initial-inventory-mismatch",
            "initial-worker-panic",
            "verify-worker-panic",
            "clean",
            "clean-sync",
        ] {
            let root = tempfile::tempdir()?;
            let mut command = std::process::Command::new(&executable);
            command.args(["--exact", TEST, "--nocapture", "--test-threads=1"]);
            configure_child(&mut command, root.path(), case);
            let output = command.stdin(std::process::Stdio::null()).output()?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            ensure!(output.status.success(), "case {case}:\n{stdout}\n{stderr}");
            ensure!(
                String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
                "fixture test did not run for {case}"
            );
        }
        let root = tempfile::tempdir()?;
        let mut invalid = std::process::Command::new(&executable);
        invalid.args(["--exact", TEST, "--nocapture", "--test-threads=1"]);
        configure_child(&mut invalid, root.path(), "unrecognized-review-kind");
        let refused = invalid.stdin(std::process::Stdio::null()).output()?;
        assert!(!refused.status.success());
        assert!(
            String::from_utf8_lossy(&refused.stderr).contains("unknown controlled review case")
        );
        assert!(!root.path().join("mutation-started").exists());
        // Reuse the existing real controlling-PTY owner and exact-digest parser.
        // Each response is sent only after the package, warning and URL are visible.
        const DRIVER: &str = r"
import importlib.util, os, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('shared_review_terminal', sys.argv[2])
terminal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(terminal)
terminal.NAME = sys.argv[3]
kind = os.environ['OMG_PACKAGE_REVIEW_FIXTURE']
case = 'generic-yes' if kind == 'known-generic-yes' else 'accept'
expected = (b'omg-review-fixture', b'CVE-2021-23337', b'https://www.cve.org/') if kind.startswith('known-') else (b'Coverage: unknown', b'controlled missing dependency evidence', b'https://www.cve.org/')
code, transcript = terminal.terminal_case(Path(sys.argv[1]), case, dict(os.environ), expected=expected)
assert code == 0 and b'1 passed; 0 failed' in transcript, transcript.decode(errors='replace')
print('controlling-PTY case passed:', kind)
";
        for case in ["known-accept", "known-generic-yes", "unknown-accept"] {
            let root = tempfile::tempdir()?;
            let mut command = std::process::Command::new(
                crate::core::privilege::root_controlled_program_path("python3")?,
            );
            command
                .arg("-c")
                .arg(DRIVER)
                .arg(&executable)
                .arg(
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("scripts/test-arch-advisory-consent.py"),
                )
                .arg(TEST);
            configure_child(&mut command, root.path(), case);
            let output = command.output()?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            ensure!(
                output.status.success(),
                "PTY case {case}:\n{stdout}\n{stderr}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn shared_package_admission_preserves_evidence_and_requires_exact_consent() -> Result<()>
    {
        let Ok(case) = std::env::var("OMG_PACKAGE_REVIEW_FIXTURE") else {
            return run_isolated_cases();
        };
        let root = std::path::PathBuf::from(
            std::env::var_os("OMG_PACKAGE_REVIEW_ROOT").expect("isolated fixture root"),
        );
        if !matches!(
            case.as_str(),
            "known-accept" | "known-generic-yes" | "unknown-accept"
        ) {
            nix::unistd::setsid()?;
        }
        let config = root.join("config/omg");
        std::fs::create_dir_all(&config)?;
        assert_eq!(
            crate::core::paths::config_dir(),
            config,
            "fixture must never read host policy"
        );
        let policy_path = config.join("policy.toml");
        std::fs::write(&policy_path, toml::to_string(&SecurityPolicy::default())?)?;
        crate::core::privilege::set_yes_flag(true);
        let unknown = matches!(case.as_str(), "unknown-no-source" | "unknown-accept");
        let state = if case.starts_with("known-") {
            KNOWN
        } else if case == "unavailable-no-tty" {
            UNAVAILABLE
        } else if case == "initial-inventory-mismatch" {
            MISMATCH
        } else if case == "initial-worker-panic" {
            PANIC
        } else {
            CLEAN
        };
        let source = FixtureSource::new(state);
        let mut inventory = vec![subject(if unknown {
            SecurityOrigin::Unknown
        } else {
            SecurityOrigin::NpmRegistry
        })];
        if case == "known-mixed-private-no-tty" {
            let mut private = subject(SecurityOrigin::Unknown);
            private.name = "private-direct-dependency".into();
            inventory.insert(0, private);
        }
        let gaps = if matches!(
            case.as_str(),
            "gaps-no-tty" | "known-with-gaps-no-tty" | "unknown-accept"
        ) {
            vec!["controlled missing dependency evidence".to_owned()]
        } else {
            Vec::new()
        };
        let marker = root.join("mutation-started");
        let context = "exact controlled archive SHA256 and requested install";
        let reviewed = if matches!(case.as_str(), "clean-sync" | "initial-worker-panic") {
            review(&inventory, context, &gaps, &source)
        } else {
            review_async(&inventory, context, &gaps, &source).await
        };
        if matches!(
            case.as_str(),
            "known-no-tty"
                | "known-generic-yes"
                | "unavailable-no-tty"
                | "gaps-no-tty"
                | "known-with-gaps-no-tty"
                | "known-mixed-private-no-tty"
                | "unknown-no-source"
                | "initial-inventory-mismatch"
                | "initial-worker-panic"
        ) {
            let error = reviewed
                .err()
                .expect("unaccepted risk or mismatched inventory must refuse mutation");
            let details = format!("{error:#}");
            if case == "initial-worker-panic" {
                assert!(
                    details.contains("Package admission worker failed"),
                    "{details}"
                );
            } else if case == "initial-inventory-mismatch" {
                assert!(details.contains("inventory differs"), "{details}");
            } else if case == "known-generic-yes" {
                assert!(
                    details.contains("Security acknowledgement declined"),
                    "{details}"
                );
            } else {
                assert!(
                    details.contains("SECURITY WARNING")
                        && details.contains("https://www.cve.org/"),
                    "{details}"
                );
                assert!(details.contains("--yes cannot accept"), "{details}");
                if case.starts_with("known-") {
                    assert!(details.contains("CVE-2021-23337"), "{details}");
                }
                if case == "known-mixed-private-no-tty" {
                    assert!(
                        details.contains("private-direct-dependency")
                            && details.contains("Coverage: unknown"),
                        "{details}"
                    );
                    assert_eq!(
                        source.seen.lock().expect("queries")[0],
                        vec![inventory[1].clone()]
                    );
                }
                if !gaps.is_empty() {
                    assert!(
                        details.contains("controlled missing dependency evidence"),
                        "{details}"
                    );
                }
                if case != "known-no-tty" && case != "known-generic-yes" {
                    assert!(details.contains("Coverage: unknown"), "{details}");
                }
            }
            assert!(!marker.exists());
            assert_eq!(source.calls.load(Ordering::SeqCst), usize::from(!unknown));
            return Ok(());
        }
        let mut reviewed = reviewed?;
        let destination_context = "actual final destination archive and dependency lock";
        assert_eq!(
            reviewed.legacy_id_for_context(destination_context),
            AdvisoryRiskReview::new(reviewed.assessments(), destination_context)
                .expect("existing canonical receipt identity")
                .as_ref()
                .map(|review| review.id().to_owned()),
            "retained shared admission must preserve legacy identity without another source query"
        );
        if case == "known-accept" {
            assert!(reviewed.accepted() && reviewed.id().is_some());
            assert_eq!(reviewed.assessments()[0].findings[0].id, "CVE-2021-23337");
            reviewed.verify_async(&source).await?;
            std::fs::write(&marker, b"explicit known-risk acceptance")?;
            assert!(marker.exists());
            return Ok(());
        }
        if case == "unknown-accept" {
            assert!(reviewed.accepted() && reviewed.id().is_some());
            assert!(!reviewed.assessments()[0].coverage.is_assessed());
            reviewed.verify_async(&source).await?;
            assert_eq!(
                source.calls.load(Ordering::SeqCst),
                0,
                "unmapped subjects must never query a guessed ecosystem"
            );
            return Ok(());
        }
        assert!(!reviewed.accepted() && reviewed.id().is_none());
        assert!(reviewed.assessments()[0].coverage.is_assessed());
        assert_eq!(source.calls.load(Ordering::SeqCst), 2);
        match case.as_str() {
            "new-cve" => source.state.store(KNOWN, Ordering::SeqCst),
            "source-failure" => source.state.store(UNAVAILABLE, Ordering::SeqCst),
            "inventory-mismatch" => source.state.store(MISMATCH, Ordering::SeqCst),
            "verify-worker-panic" => source.state.store(PANIC, Ordering::SeqCst),
            "policy-change" => {
                let mut policy = SecurityPolicy::default();
                policy.banned_packages.push(inventory[0].name.clone());
                std::fs::write(policy_path, toml::to_string(&policy)?)?;
            }
            // Test retained principal binding without changing the test runner's OS credentials.
            "retained-principal-mismatch" => reviewed.euid = reviewed.euid.wrapping_add(1),
            "clean" | "clean-sync" => {}
            _ => anyhow::bail!("unknown controlled review case: {case}"),
        }
        let verification = if matches!(case.as_str(), "clean-sync" | "verify-worker-panic") {
            reviewed.verify(&source)
        } else {
            reviewed.verify_async(&source).await
        };
        if matches!(case.as_str(), "clean" | "clean-sync") {
            verification?;
            std::fs::write(&marker, b"verified exact transaction")?;
            assert!(marker.exists());
        } else {
            let error = verification.expect_err("changed evidence must invalidate before mutation");
            let details = format!("{error:#}");
            assert!(
                details.contains(if case == "inventory-mismatch" {
                    "inventory differs"
                } else if case == "verify-worker-panic" {
                    "Package admission verification worker failed"
                } else {
                    "changed"
                }),
                "{details}"
            );
            assert!(!marker.exists());
        }
        assert_eq!(
            source.calls.load(Ordering::SeqCst),
            if matches!(
                case.as_str(),
                "policy-change" | "retained-principal-mismatch"
            ) {
                2
            } else {
                3
            }
        );
        Ok(())
    }
}
