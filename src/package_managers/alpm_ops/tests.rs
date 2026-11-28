#[test]
fn explicit_pgp_requirement_overrides_optional_and_disabled_package_signatures() {
    for level in [
        alpm::SigLevel::NONE,
        alpm::SigLevel::PACKAGE | alpm::SigLevel::PACKAGE_OPTIONAL,
    ] {
        let enforced = super::enforce_required_package_signature(level, true);
        assert!(enforced.contains(alpm::SigLevel::PACKAGE));
        assert!(!enforced.contains(alpm::SigLevel::PACKAGE_OPTIONAL));
        assert_eq!(super::enforce_required_package_signature(level, false), level);
    }
}

#[test]
fn archive_acknowledgement_lists_only_private_archives_and_bounds_the_batch() {
    use crate::package_managers::types::{SecurityOrigin, SecurityPackage};
    let prepared =
        |name: &str, origin: SecurityOrigin, digest: &str| super::PreparedAdvisoryPackage {
            package: SecurityPackage {
                name: name.into(),
                version: "1-1".into(),
                architecture: Some("x86_64".into()),
                origin,
                advisory_source: None,
                description: String::new(),
                licenses: Vec::new(),
            },
            sha256: Some(digest.repeat(64)),
            archive: None,
        };
    let aur = prepared("aur-fixture", SecurityOrigin::AurArchive, "a");
    let local = prepared("local-fixture", SecurityOrigin::LocalArchive, "b");
    let repository = prepared(
        "official-fixture",
        SecurityOrigin::ArchRepository {
            repository: "core".into(),
        },
        "c",
    );
    let prompt = super::unknown_archives_prompt(
        &[aur.clone(), repository, local],
        "prepared-batch",
        1000,
    )
    .expect("mixed batch with two private archives requires acknowledgement");
    assert!(prompt.contains("Invoking UID: 1000"));
    assert!(prompt.contains("Full prepared batch SHA-256: prepared-batch"));
    assert!(prompt.contains("aur-fixture") && prompt.contains(&"a".repeat(64)));
    assert!(prompt.contains("local-fixture") && prompt.contains(&"b".repeat(64)));
    assert!(!prompt.contains("official-fixture"));
    let error = super::unknown_archives_prompt(&vec![aur; 65], "oversize", 1000)
        .expect_err("oversized archive acknowledgements must be split");
    assert!(error.to_string().contains("at most 64 archives"));
}

#[test]
fn prepared_unknown_review_is_required_and_bound_without_fabricating_snapshot_authority() {
    use crate::core::security::policy::AdvisoryRequirement;
    use crate::core::security::vulnerability::{PackageAssessment, UnknownCoverage};
    use crate::package_managers::types::{SecurityOrigin, SecurityPackage};
    let assessment = PackageAssessment::unknown(
        SecurityPackage {
            name: "fixture".into(),
            version: "1-1".into(),
            architecture: Some("x86_64".into()),
            origin: SecurityOrigin::ArchRepository {
                repository: "core".into(),
            },
            advisory_source: None,
            description: String::new(),
            licenses: vec!["MIT".into()],
        },
        UnknownCoverage::EvidenceUnavailable,
    );
    assert!(super::require_fresh_arch_coverage(&assessment, true).is_err());
    for origin in [SecurityOrigin::AurArchive, SecurityOrigin::LocalArchive] {
        let mut archive = assessment.clone();
        archive.package.origin = origin;
        assert!(super::require_fresh_arch_coverage(&archive, false).is_err());
        super::require_fresh_arch_coverage(&archive, true)
            .expect("separately acknowledged private archive is eligible for admission");
    }
    for requirement in [AdvisoryRequirement::Optional, AdvisoryRequirement::Review] {
        let review = super::prepared_risk_review(
            std::slice::from_ref(&assessment),
            "prepared-batch",
            requirement,
        )
        .expect("prepare advisory review")
        .expect("Unknown-only mutation requires an explicit decision");
        assert!(review.details().contains("EvidenceUnavailable"));
        assert!(review.accept("yes").is_err());
        let accepted = review
            .accept(&format!("accept {}", review.id()))
            .expect("the exact review identifier is accepted");
        assert!(accepted.matches(&review));
        let mut changed = assessment.clone();
        changed.package.version = "2-1".into();
        let changed = super::prepared_risk_review(&[changed], "prepared-batch", requirement)
            .expect("prepare review after a version change")
            .expect("changed version remains Unknown");
        assert!(!accepted.matches(&changed));
        assert!(
            super::prepared_risk_review(&[], "empty-batch", requirement)
                .expect("prepare review for an empty transaction")
                .is_none()
        );
    }
    let mut archive = assessment;
    archive.package.origin = SecurityOrigin::LocalArchive;
    // FreshSnapshot retains its existing separate exact-archive acknowledgement.
    assert!(
        super::prepared_risk_review(
            &[archive],
            "fresh-private-archive",
            AdvisoryRequirement::FreshSnapshot,
        )
        .expect("private archive acknowledgement is handled separately")
        .is_none()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn advisory_risk_refuses_an_unattended_session() -> anyhow::Result<()> {
    const NAME: &str =
        "package_managers::alpm_ops::tests::advisory_risk_refuses_an_unattended_session";
    if std::env::var("OMG_ISOLATED_FIXTURE_TEST").as_deref() != Ok(NAME) {
        let output = std::process::Command::new("setsid")
            .arg(std::env::current_exe()?)
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env("OMG_ISOLATED_FIXTURE_TEST", NAME)
            .output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "isolated no-terminal review failed: {stdout}\n{stderr}"
        );
        return Ok(());
    }
    assert!(std::fs::File::open("/dev/tty").is_err());
    let mut signals = super::AdmissionSignals::begin()?;
    let error = super::confirm_advisory_prompt(
        "SECURITY WARNING: fixture 1.0-1 CVE-2026-12345 https://www.cve.org/CVERecord?id=CVE-2026-12345",
        &"ab".repeat(32),
        crate::core::security::advisory_review::AdvisoryReviewKind::Advisory,
        crate::core::privilege::invoking_uid()?,
        &signals,
    )
    .expect_err("an unattended process cannot acknowledge package warnings");
    let diagnostic = error.to_string();
    assert!(
        [
            "Security review requires an attended controlling terminal",
            "Security acknowledgement requires the privileged transaction owner",
        ]
        .iter()
        .any(|reason| diagnostic.contains(reason)),
        "{error:#}"
    );
    signals.finish()?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn fresh_admission_signal_ownership_is_scoped_and_refuses_handler_conflicts()
-> anyhow::Result<()> {
    const NAME: &str = "package_managers::alpm_ops::tests::fresh_admission_signal_ownership_is_scoped_and_refuses_handler_conflicts";
    if crate::core::testing::run_isolated_test(NAME) {
        return Ok(());
    }
    let invalid_signal = super::admission_signal_action(0, None)
        .expect_err("the kernel must refuse a signal outside the sigaction domain");
    assert_eq!(invalid_signal.raw_os_error(), Some(nix::libc::EINVAL));
    let mut owned = None;
    super::ensure_prepared_review_signals(&mut owned, "first review")?;
    assert!(super::AdmissionSignals::begin().is_err());
    let error = super::ensure_prepared_review_signals(&mut None, "disclosed fixture risk")
        .expect_err("a second transaction must not take cancellation ownership");
    assert!(error.to_string().contains("disclosed fixture risk"));
    assert!(format!("{error:#}").contains("owns signal cancellation"));
    super::ensure_prepared_review_signals(&mut owned, "same transaction")?;
    assert!(
        !nix::sys::signal::SigSet::thread_get_mask()?
            .contains(nix::sys::signal::Signal::SIGINT),
        "the isolated signal fixture requires SIGINT unblocked on its receiving thread"
    );
    nix::sys::signal::raise(nix::sys::signal::Signal::SIGINT)?;
    assert!(
        format!(
            "{:#}",
            super::ensure_prepared_review_signals(&mut owned, "same transaction")
                .expect_err("a cancelled owner must refuse the review")
        )
        .contains("admission interrupted")
    );
    let mut guard = owned.expect("review preserved the original owner");
    assert!(
        guard.check().is_err(),
        "synchronous current-thread SIGINT must cancel admission"
    );
    assert!(guard.finish().is_err());
    guard.finish()?;
    for signal in [nix::libc::SIGINT, nix::libc::SIGTERM, nix::libc::SIGHUP] {
        assert_eq!(
            super::admission_signal_action(signal, None)?.sa_sigaction,
            nix::libc::SIG_DFL
        );
    }
    let default = super::admission_signal_action(nix::libc::SIGTERM, None)?;
    let mut ignored = super::admission_signal_action(nix::libc::SIGTERM, None)?;
    ignored.sa_sigaction = nix::libc::SIG_IGN;
    super::admission_signal_action(nix::libc::SIGTERM, Some(&ignored))?;
    assert!(super::AdmissionSignals::begin().is_err());
    assert_eq!(
        super::admission_signal_action(nix::libc::SIGINT, None)?.sa_sigaction,
        nix::libc::SIG_DFL,
        "partial acquisition rolls back the earlier default handler"
    );
    assert_eq!(
        super::admission_signal_action(nix::libc::SIGTERM, None)?.sa_sigaction,
        nix::libc::SIG_IGN,
        "preexisting owner remains untouched"
    );
    super::admission_signal_action(nix::libc::SIGTERM, Some(&default))?;
    let mut guard = super::AdmissionSignals::begin()?;
    super::admission_signal_action(nix::libc::SIGTERM, Some(&ignored))?;
    assert!(guard.check().is_err());
    assert!(guard.finish().is_err());
    assert_eq!(
        super::admission_signal_action(nix::libc::SIGTERM, None)?.sa_sigaction,
        nix::libc::SIG_IGN,
        "new external owner remains untouched on cleanup"
    );
    super::admission_signal_action(nix::libc::SIGTERM, Some(&default))?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn native_admission_setup_error_keeps_signal_owner_until_transaction_release()
-> anyhow::Result<()> {
    const NAME: &str = "package_managers::alpm_ops::tests::native_admission_setup_error_keeps_signal_owner_until_transaction_release";
    if crate::core::testing::run_isolated_test(NAME) {
        return Ok(());
    }
    let fixture = RepositoryFixture::new()?;
    let mut alpm = fixture.open();
    alpm.trans_init(alpm::TransFlag::empty())?;
    let lock = fixture.database().join("db.lck");
    assert!(lock.exists(), "native transaction created its private lock");
    let mut transaction =
        super::AlpmTransaction(&mut alpm, super::PreparedArchiveInspections::new(), None);
    let default = super::admission_signal_action(nix::libc::SIGTERM, None)?;
    let mut ignored = default;
    ignored.sa_sigaction = nix::libc::SIG_IGN;
    super::admission_signal_action(nix::libc::SIGTERM, Some(&ignored))?;
    assert!(super::AdmissionSignals::begin_in(&mut transaction.2).is_err());
    assert!(
        transaction.2.is_some(),
        "partial acquisition belongs to the outer transaction even on error"
    );
    assert!(lock.exists());
    assert_eq!(
        super::admission_signal_action(nix::libc::SIGINT, None)?.sa_sigaction,
        super::cancel_admission as *const () as usize
    );
    drop(transaction);
    assert!(
        !lock.exists(),
        "native release removes the lock during error cleanup"
    );
    assert_eq!(
        super::admission_signal_action(nix::libc::SIGINT, None)?.sa_sigaction,
        nix::libc::SIG_DFL
    );
    assert_eq!(
        super::admission_signal_action(nix::libc::SIGTERM, None)?.sa_sigaction,
        nix::libc::SIG_IGN
    );
    super::admission_signal_action(nix::libc::SIGTERM, Some(&default))?;
    Ok(())
}

#[test]
fn prepared_repository_without_coordinates_does_not_gain_verified_grade() -> anyhow::Result<()>
{
    use crate::core::security::policy::{AdvisoryRequirement, SecurityGrade, SecurityPolicy};
    use crate::package_managers::types::SecurityOrigin;
    let mut policy = SecurityPolicy {
        minimum_grade: SecurityGrade::Verified,
        ..SecurityPolicy::default()
    };
    for requirement in [AdvisoryRequirement::Optional, AdvisoryRequirement::Review] {
        policy.advisory_requirement = requirement;
        let origin = super::prepared_repository_origin("", &policy)?;
        assert_eq!(origin, SecurityOrigin::Unknown);
        assert!(policy.check_source("fixture", &origin, None).is_err());
    }
    policy.advisory_requirement = AdvisoryRequirement::FreshSnapshot;
    assert!(super::prepared_repository_origin("", &policy).is_err());
    Ok(())
}

#[test]
fn fresh_admission_requires_declared_repository_coordinates_even_for_core() -> anyhow::Result<()>
{
    use crate::core::security::policy::{AdvisoryRequirement, SecurityPolicy};
    use crate::package_managers::types::SecurityOrigin;
    let mut policy = SecurityPolicy::default();
    assert!(matches!(
        super::prepared_repository_origin("core", &policy)?,
        SecurityOrigin::OtherRepository { .. }
    ));
    policy.advisory_requirement = AdvisoryRequirement::FreshSnapshot;
    assert!(super::prepared_repository_origin("core", &policy).is_err());
    policy.arch_advisory_repositories.insert("core".into());
    assert!(
        matches!(super::prepared_repository_origin("core", &policy)?, SecurityOrigin::ArchRepository { repository } if repository == "core")
    );
    assert!(super::prepared_repository_origin("new-custom-dependency", &policy).is_err());
    Ok(())
}

#[test]
fn archive_acknowledgement_digest_binds_every_prepared_authority_axis() -> anyhow::Result<()> {
    use crate::package_managers::types::{SecurityOrigin, SecurityPackage};
    let package = super::PreparedAdvisoryPackage {
        package: SecurityPackage {
            name: "fixture".into(),
            version: "1-1".into(),
            architecture: Some("x86_64".into()),
            origin: SecurityOrigin::AurArchive,
            advisory_source: None,
            description: String::new(),
            licenses: vec!["MIT".into()],
        },
        sha256: Some("a".repeat(64)),
        archive: Some(("/var/tmp/private/pkg.tar.zst".into(), 1, 2, 3)),
    };
    let policy = crate::core::security::SecurityPolicy::default();
    let digest =
        super::advisory_batch_digest(std::slice::from_ref(&package), &policy, b"profile", 1000)
            .expect("digest a fully prepared archive");
    let mut variants = Vec::new();
    let mut changed = package.clone();
    changed.package.name = "other".into();
    variants.push(changed);
    let mut changed = package.clone();
    changed.package.version = "2-1".into();
    variants.push(changed);
    let mut changed = package.clone();
    changed.package.architecture = Some("aarch64".into());
    variants.push(changed);
    let mut changed = package.clone();
    changed.package.origin = SecurityOrigin::LocalArchive;
    variants.push(changed);
    let mut changed = package.clone();
    changed.sha256 = Some("b".repeat(64));
    variants.push(changed);
    let mut changed = package.clone();
    changed.archive.as_mut().expect("archive").2 = 4;
    variants.push(changed);
    for changed in variants {
        assert_ne!(
            super::advisory_batch_digest(&[changed], &policy, b"profile", 1000)?,
            digest
        );
    }
    let mut changed = policy.clone();
    changed.advisory_requirement =
        crate::core::security::policy::AdvisoryRequirement::FreshSnapshot;
    assert_ne!(
        super::advisory_batch_digest(
            std::slice::from_ref(&package),
            &changed,
            b"profile",
            1000
        )
        .expect("digest the updated advisory requirement"),
        digest
    );
    assert_ne!(
        super::advisory_batch_digest(
            std::slice::from_ref(&package),
            &policy,
            b"changed-profile",
            1000
        )
        .expect("digest the changed tool profile"),
        digest
    );
    assert_ne!(
        super::advisory_batch_digest(&[package], &policy, b"profile", 1001)?,
        digest
    );
    Ok(())
}

#[test]
fn mutation_completion_preserves_outcomes_and_primary_causes() {
    use super::MutationCompletion::{CommitFailed, Committed};

    struct Case {
        label: &'static str,
        completion: super::MutationCompletion,
        audit: anyhow::Result<()>,
        outcome: &'static str,
        primary: Option<&'static str>,
        diagnostics: &'static [&'static str],
    }

    let cause = |label| anyhow::Error::from(std::io::Error::other(label));
    let commit_error = || {
        cause("commit cause")
            .context("Transaction failed to commit; package state may have changed")
    };
    let reason_error = || {
        cause("reason cause").context(
            "Transaction completed, but installation reason could not be persisted; inspect installed state before retrying",
        )
    };
    let cases = [
        Case {
            label: "mutation, reasons and audit succeeded",
            completion: Committed { reasons: Ok(()) },
            audit: Ok(()),
            outcome: "succeeded",
            primary: None,
            diagnostics: &[],
        },
        Case {
            label: "committed mutation with audit failure",
            completion: Committed { reasons: Ok(()) },
            audit: Err(cause("audit cause")),
            outcome: "succeeded",
            primary: Some("audit cause"),
            diagnostics: &[
                "Packages committed, but audit persistence failed",
                "inspect installed state before retrying",
            ],
        },
        Case {
            label: "committed mutation with reason failure",
            completion: Committed {
                reasons: Err(reason_error()),
            },
            audit: Ok(()),
            outcome: "failed",
            primary: Some("reason cause"),
            diagnostics: &[
                "installation reason could not be persisted",
                "inspect installed state before retrying",
            ],
        },
        Case {
            label: "committed mutation with reason and audit failures",
            completion: Committed {
                reasons: Err(reason_error()),
            },
            audit: Err(cause("audit cause")),
            outcome: "failed",
            primary: Some("audit cause"),
            diagnostics: &[
                "Installation reason persistence also failed",
                "reason cause",
                "Packages committed, but audit persistence failed",
                "inspect installed state before retrying",
            ],
        },
        Case {
            label: "commit failure with persisted audit",
            completion: CommitFailed(commit_error()),
            audit: Ok(()),
            outcome: "failed",
            primary: Some("commit cause"),
            diagnostics: &["Transaction failed to commit; package state may have changed"],
        },
        Case {
            label: "commit and audit failures",
            completion: CommitFailed(commit_error()),
            audit: Err(cause("audit cause")),
            outcome: "failed",
            primary: Some("commit cause"),
            diagnostics: &[
                "Transaction failed to commit; package state may have changed",
                "Audit persistence also failed",
                "audit cause",
            ],
        },
    ];
    for case in cases {
        assert_eq!(
            case.completion.audit_outcome(),
            case.outcome,
            "{}",
            case.label
        );
        let result = case.completion.finish(case.audit);
        let Some(primary) = case.primary else {
            assert!(result.is_ok(), "{}: {result:?}", case.label);
            continue;
        };
        let error = result.expect_err(case.label);
        let diagnostic = format!("{error:#}");
        assert_eq!(
            error.root_cause().to_string(),
            primary,
            "{}: {diagnostic}",
            case.label
        );
        assert!(
            error.downcast_ref::<std::io::Error>().is_some(),
            "{} must preserve its primary typed cause: {diagnostic}",
            case.label
        );
        for expected in case.diagnostics {
            assert!(
                diagnostic.contains(expected),
                "{} must preserve {expected:?}: {diagnostic}",
                case.label
            );
        }
    }
}

struct RepositoryFixture {
    directory: tempfile::TempDir,
}

#[test]
fn install_catalog_uses_the_transaction_repository_order() -> anyhow::Result<()> {
    let fixture = RepositoryFixture::new()?;
    fixture.write_sync("lookup", &[("demo", "1-1", ""), ("search-only", "1-1", "")])?;
    fixture.write_sync("preferred", &[("demo", "2-1", "")])?;
    fixture.write_sync("fallback", &[("demo", "3-1", "")])?;
    let alpm = fixture.open();
    alpm.register_syncdb("lookup", alpm::SigLevel::NONE)?
        .set_usage(alpm::Usage::SEARCH)?;
    alpm.register_syncdb("preferred", alpm::SigLevel::NONE)?
        .set_usage(alpm::Usage::INSTALL)?;
    alpm.register_syncdb("fallback", alpm::SigLevel::NONE)?
        .set_usage(alpm::Usage::ALL)?;

    let lookup = |name| super::get_pkg_info_in_scope(&alpm, name, alpm::Usage::INSTALL);
    let info = lookup("demo")?.expect("installable package");
    assert_eq!(info.repo, "preferred");
    assert_eq!(info.version.to_string(), "2-1");
    assert!(lookup("search-only")?.is_none());
    assert_eq!(
        super::get_pkg_info_from_db(&alpm, "demo")?.unwrap().repo,
        "lookup"
    );

    std::fs::remove_file(fixture.database().join("sync/preferred.db"))?;
    let error =
        lookup("absent").expect_err("an incomplete install catalog cannot establish absence");
    assert!(format!("{error:#}").contains("preferred"));
    Ok(())
}

#[test]
#[ignore = "requires an explicitly selected native Arch host with a private catalog fixture"]
fn native_install_and_preview_resolve_locally_with_daemon_available() -> anyhow::Result<()> {
    use std::os::unix::net::UnixListener;

    const NAME: &str = "package_managers::alpm_ops::tests::native_install_and_preview_resolve_locally_with_daemon_available";
    if crate::core::testing::run_isolated_test(NAME)
        || crate::config::Settings::rerun_test_unprivileged(NAME)
    {
        return Ok(());
    }
    anyhow::ensure!(
        crate::package_managers::resolve_backend()? == crate::package_managers::Backend::Arch,
        "native Arch backend required"
    );
    let fixture = RepositoryFixture::new()?;
    fixture.write_sync("fixture", &[("install-routing-demo", "2-1", "")])?;
    let directory = fixture.directory.path();
    let root = directory.join("root");
    let conf = directory.join("pacman.conf");
    let config = format!(
        "[options]\nRootDir = {}\nDBPath = {}\nSigLevel = Required DatabaseOptional\n\
         [fixture]\nUsage = Install\nServer = file://{}\n",
        root.display(),
        fixture.database().display(),
        directory.display()
    );
    std::fs::write(&conf, config)?;
    let policy = "banned_packages = ['install-routing-demo']\n";
    std::fs::write(directory.join("policy.toml"), policy)?;
    let socket = directory.join("run/omg.sock");
    crate::core::paths::prepare_socket_parent(&socket)?;
    let listener = UnixListener::bind(&socket)?;
    listener.set_nonblocking(true)?;
    temp_env::with_vars(
        [
            ("OMG_CONFIG_DIR", Some(directory.as_os_str())),
            ("OMG_PACMAN_CONF", Some(conf.as_os_str())),
            ("OMG_SOCKET_PATH", Some(socket.as_os_str())),
            ("OMG_DISABLE_DAEMON", None),
        ],
        || -> anyhow::Result<()> {
            assert_eq!(crate::core::paths::socket_path(), socket);
            crate::core::paths::validate_socket_parent(&socket)?;
            assert_eq!(
                crate::core::paths::pacman_db_dir_result()?,
                fixture.database()
            );
            tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
                let packages = ["install-routing-demo".to_owned()];
                crate::cli::packages::install(&packages, true, true, false).await?;
                let error = crate::cli::packages::install(&packages, true, false, false)
                    .await
                    .expect_err("source policy must stop the local package before a transaction");
                assert!(matches!(
                    error.downcast_ref::<crate::core::security::PolicyError>(),
                    Some(crate::core::security::PolicyError::Banned { name }) if name == &packages[0]
                ), "{error:#}");
                std::fs::remove_file(fixture.database().join("sync/fixture.db"))?;
                let error = crate::cli::packages::install(&packages, true, true, false)
                    .await
                    .expect_err("a missing install database must stop the preview");
                assert!(format!("{error:#}").contains("Repository 'fixture' is unavailable"));
                Ok::<(), anyhow::Error>(())
            })?;
            assert_eq!(
                listener
                    .accept()
                    .expect_err("install must not query daemon search")
                    .kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert_eq!(
                std::fs::read_dir(fixture.database().join("local"))?.count(),
                1
            );
            Ok(())
        },
    )
}

impl RepositoryFixture {
    fn new() -> anyhow::Result<Self> {
        let directory = tempfile::tempdir()?;
        std::fs::create_dir(directory.path().join("root"))?;
        std::fs::create_dir_all(directory.path().join("db/local"))?;
        std::fs::create_dir(directory.path().join("db/sync"))?;
        std::fs::write(directory.path().join("db/local/ALPM_DB_VERSION"), "9\n")?;
        Ok(Self { directory })
    }

    fn database(&self) -> std::path::PathBuf {
        self.directory.path().join("db")
    }

    fn write_sync(
        &self,
        repository: &str,
        packages: &[(&str, &str, &str)],
    ) -> anyhow::Result<()> {
        let file =
            std::fs::File::create(self.database().join(format!("sync/{repository}.db")))?;
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            file,
            flate2::Compression::fast(),
        ));
        for (name, version, extra) in packages {
            let content = format!(
                "%NAME%\n{name}\n\n%VERSION%\n{version}\n\n%FILENAME%\n{name}-{version}-any.pkg.tar.zst\n\n%ARCH%\nany\n\n%CSIZE%\n1\n\n%ISIZE%\n1\n\n%PACKAGER%\nFixture Maintainer <fixture@example.invalid>\n\n{extra}"
            );
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(
                    &mut header,
                    format!("{name}-{version}/desc"),
                    content.as_bytes(),
                )
                .expect("private repository fixture record is writable");
        }
        archive.into_inner()?.finish()?;
        Ok(())
    }

    fn write_local(&self, name: &str, version: &str) -> anyhow::Result<()> {
        let package = self.database().join(format!("local/{name}-{version}"));
        std::fs::create_dir(&package)?;
        std::fs::write(
            package.join("desc"),
            format!("%NAME%\n{name}\n\n%VERSION%\n{version}\n\n%ARCH%\nany\n\n%REASON%\n0\n\n"),
        )
        .expect("private local package fixture descriptor is writable");
        Ok(())
    }

    fn open(&self) -> alpm::Alpm {
        alpm::Alpm::new(
            self.directory
                .path()
                .join("root")
                .to_str()
                .expect("UTF-8 root"),
            self.database().to_str().expect("UTF-8 database"),
        )
        .expect("private repository fixture opens in native ALPM")
    }
}

#[test]
#[ignore = "requires the isolated native advisory consent driver"]
fn native_advisory_consent_installs_only_the_accepted_transaction() -> anyhow::Result<()> {
    use anyhow::Context as _;
    use std::io::Write as _;
    anyhow::ensure!(
        crate::core::is_root()
            && std::env::var("OMG_ARCH_INSTALL_FIXTURE").as_deref() == Ok("isolated-container"),
        "native consent requires the explicitly provisioned root fixture"
    );
    for namespace in ["mnt", "net"] {
        anyhow::ensure!(
            std::fs::read_link(format!("/proc/self/ns/{namespace}"))?
                != std::fs::read_link(format!("/proc/1/ns/{namespace}"))?,
            "native consent requires private mount and network namespaces"
        );
    }
    let case = std::env::var("OMG_ADVISORY_INSTALL_CASE")?;
    let coverage =
        std::env::var("OMG_ADVISORY_INSTALL_COVERAGE").unwrap_or_else(|_| "finding".to_owned());
    anyhow::ensure!(
        ["finding", "unavailable", "unmapped"].contains(&coverage.as_str()),
        "unknown advisory coverage fixture"
    );
    anyhow::ensure!(
        [
            "accept",
            "generic-yes",
            "blank",
            "wrong-review",
            "eof",
            "no-tty",
            "archive-change",
            "policy-change",
            "interrupt",
            "terminate",
            "hangup"
        ]
        .contains(&case.as_str()),
        "unknown consent fixture case"
    );
    let policy = crate::core::security::SecurityPolicy::load_current()?;
    anyhow::ensure!(
        policy == crate::core::security::SecurityPolicy::default()
            && crate::core::paths::config_dir() == std::path::Path::new("/root/.config/omg"),
        "native consent fixture requires its empty private root configuration"
    );
    let fixture = RepositoryFixture::new()?;
    let archive_path = fixture.directory.path().join("glibc-1-1-any.pkg.tar.gz");
    let payload = b"isolated advisory consent fixture\n";
    let package_info = format!(
        "pkgname = glibc\npkgver = 1-1\npkgdesc = isolated consent fixture\nbuilddate = 1\npackager = OMG fixture\nsize = {}\narch = any\nlicense = MIT\n",
        payload.len()
    );
    let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
        std::fs::File::create(&archive_path)?,
        flate2::Compression::fast(),
    ));
    for (path, bytes) in [
        (".PKGINFO", package_info.as_bytes()),
        ("usr/share/omg-consent-fixture", payload.as_slice()),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append_data(&mut header, path, bytes)?;
    }
    archive.into_inner()?.finish()?;
    let targets = vec![
        archive_path
            .to_str()
            .context("fixture archive path")?
            .to_owned(),
    ];
    let installed_file = fixture
        .directory
        .path()
        .join("root/usr/share/omg-consent-fixture");
    let mut alpm = fixture.open();
    alpm.set_hookdirs(std::iter::empty::<&str>())?;
    alpm.set_logfile(
        fixture
            .directory
            .path()
            .join("pacman.log")
            .to_str()
            .context("fixture log path")?,
    )
    .expect("set the isolated ALPM log path");
    alpm.set_check_space(false);
    alpm.trans_init(alpm::TransFlag::empty())?;
    let mut transaction =
        super::AlpmTransaction(&mut alpm, super::PreparedArchiveInspections::new(), None);
    let package = transaction
        .0
        .pkg_load(targets[0].as_str(), true, alpm::SigLevel::NONE)?;
    transaction
        .0
        .trans_add_pkg(package)
        .map_err(|error| anyhow::anyhow!("fixture package add: {error}"))?;
    transaction
        .0
        .trans_prepare()
        .map_err(|error| anyhow::anyhow!("fixture preparation: {error}"))?;
    let prepared = super::PreparedAdvisoryAdmission::new(
        transaction.0,
        super::TransactionKind::Install,
        &targets,
        &policy,
        &transaction.1,
        &mut transaction.2,
    );
    let refused = matches!(
        case.as_str(),
        "generic-yes"
            | "blank"
            | "wrong-review"
            | "eof"
            | "no-tty"
            | "interrupt"
            | "terminate"
            | "hangup"
    );
    let rejection = if refused {
        let error = prepared
            .err()
            .expect("risk installed without an explicit attended acceptance");
        let text = format!("{error:#}");
        assert!(
            text.contains(match case.as_str() {
                "no-tty" => "attended controlling terminal",
                "interrupt" | "terminate" | "hangup" => "interrupted",
                _ => "Security acknowledgement",
            }),
            "{text}"
        );
        Some(text)
    } else {
        let admission = prepared?;
        assert!(
            admission.risk_acceptance.is_some(),
            "both actual findings and Unknown coverage need a bound acceptance"
        );
        if coverage == "unavailable" {
            assert!(
                admission.operation.is_none(),
                "no fabricated snapshot authority"
            );
        } else {
            let operation = admission
                .operation
                .as_ref()
                .context("missing actual advisory request")?;
            assert_eq!(operation.assessments().len(), 1);
            assert!(!operation.assessments()[0].coverage.is_assessed());
            assert_eq!(
                operation.assessments()[0].findings.len(),
                usize::from(coverage == "finding")
            );
            if coverage == "finding" {
                assert_eq!(
                    operation.assessments()[0].findings[0].applicability,
                    crate::core::security::scan::FindingApplicability::Possible
                );
            }
        }
        if case == "archive-change" {
            std::fs::OpenOptions::new()
                .append(true)
                .open(&archive_path)?
                .write_all(b"changed after review")?;
        } else if case == "policy-change" {
            let path = crate::core::paths::config_dir();
            std::fs::create_dir_all(&path)?;
            std::fs::write(
                path.join("policy.toml"),
                "advisory_requirement = 'optional'\nbanned_packages = ['glibc']\n",
            )
            .expect("write the post-review package policy fixture");
        }
        let validated = admission.validate(
            transaction.0,
            super::TransactionKind::Install,
            &targets,
            &mut transaction.2,
        );
        if case == "accept" {
            validated?;
            transaction
                .0
                .trans_commit()
                .map_err(|error| anyhow::anyhow!("fixture commit: {error}"))?;
            None
        } else {
            let error = validated.expect_err("changed state must invalidate the acceptance");
            let text = format!("{error:#}");
            assert!(
                text.contains(if case == "archive-change" {
                    "archive changed after advisory admission"
                } else {
                    "changed before commit"
                }),
                "{text}"
            );
            Some(text)
        }
    };
    drop(transaction);
    drop(alpm);
    let verified = fixture.open();
    let installed_version = verified
        .localdb()
        .pkg("glibc")
        .ok()
        .map(|package| package.version().as_str().to_owned());
    let installed = installed_version.is_some();
    assert_eq!(installed, case == "accept");
    assert_eq!(
        installed_version.as_deref(),
        if installed { Some("1-1") } else { None }
    );
    assert_eq!(installed_file.exists(), installed);
    if installed {
        assert_eq!(std::fs::read(&installed_file)?, payload);
    }
    let native_audit = if case == "accept" && coverage != "unmapped" {
        let status = super::super::arch::tests::native_audit_verifies_existing_advisory_fixture(
            &fixture.directory.path().join("root"),
            &fixture.database(),
            coverage == "unavailable",
        );
        assert_eq!(std::fs::read(&installed_file)?, payload);
        Some(status)
    } else {
        None
    };
    println!(
        "OMG_NATIVE_ADVISORY_CONSENT_RESULT={}",
        serde_json::to_string(&serde_json::json!({
            "case": case, "installed": installed, "rejection": rejection,
        "native_audit": native_audit,
        "package": "glibc", "version": "1-1", "installed_version": installed_version,
        "private_root": fixture.directory.path(),
        }))?
    );
    Ok(())
}

#[test]
#[ignore = "requires an explicitly provisioned isolated Arch container or QEMU guest"]
fn native_reason_write_failure_preserves_durable_reason() -> anyhow::Result<()> {
    use anyhow::Context as _;
    use std::fs;

    anyhow::ensure!(
        std::env::var("OMG_ARCH_INSTALL_FIXTURE").as_deref() == Ok("isolated-container")
            && crate::core::is_root(),
        "reason-write fixture requires the disposable native root environment"
    );
    let fixture = RepositoryFixture::new()?;
    let name = "omg-fixture-reason-failure";
    fixture.write_local(name, "1-1")?;
    let desc = fixture.database().join(format!("local/{name}-1-1/desc"));
    let original = fs::read_to_string(&desc)?.replace("%REASON%\n0\n", "%REASON%\n1\n");
    fs::write(&desc, &original)?;
    let mut alpm = fixture.open();
    assert_eq!(
        alpm.localdb().pkg(name)?.reason(),
        alpm::PackageReason::Depend
    );
    let saved = desc.with_extension("saved");
    fs::rename(&desc, &saved)?;
    fs::create_dir(&desc)?;

    let audit_path = std::path::PathBuf::from("/var/lib/omg/audit/audit.jsonl");
    let audit_before = crate::core::security::AuditLogger::new_in(&audit_path)
        .expect("initialize disposable fixture audit state")
        .get_recent(usize::MAX)
        .expect("read a valid disposable fixture audit baseline")
        .len();
    alpm.trans_init(alpm::TransFlag::empty())?;
    let mut transaction =
        super::AlpmTransaction(&mut alpm, super::PreparedArchiveInspections::new(), None);
    let task = super::ProgressTask::start(&super::TaskSpec {
        label: "Reason persistence fixture".to_owned(),
        kind: super::TaskKind::Items { total: 1 },
        accent: super::Accent::System,
    });
    let error = super::commit_alpm_transaction(
        transaction.0,
        &task,
        super::TransactionKind::InstallAurArtifact,
        &[],
        &[(name.to_owned(), alpm::PackageReason::Explicit)],
        &[],
        &[],
        &crate::core::security::SecurityPolicy::load_current()?,
        &super::PreparedArchiveInspections::new(),
        &mut transaction.2,
    )
    .expect_err("a directory in place of desc must refuse durable reason persistence");
    drop(transaction);
    let diagnostic = format!("{error:#}");
    assert!(
        diagnostic.contains(name)
            && diagnostic.contains("could not be persisted")
            && diagnostic.contains("inspect installed state before retrying"),
        "reason-write failure must identify the package and require inspection: {diagnostic}"
    );
    assert_eq!(
        error.downcast_ref::<alpm::Error>(),
        Some(&alpm::Error::DbWrite),
        "the native reason-write cause must remain available: {diagnostic}"
    );
    fs::remove_dir(&desc)?;
    fs::rename(&saved, &desc)?;
    assert_eq!(fs::read_to_string(&desc)?, original);
    drop(alpm);
    let reopened = fixture.open();
    assert_eq!(
        reopened.localdb().pkg(name)?.reason(),
        alpm::PackageReason::Depend,
        "a reopened database must retain the original durable reason after failed write"
    );
    assert!(
        !fixture.database().join("db.lck").exists(),
        "reason persistence failure must release the native transaction lock"
    );
    let audit = fs::read_to_string(audit_path)?;
    let entries = audit
        .lines()
        .skip(audit_before)
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    assert_eq!(entries.len(), 2, "one attempt and one terminal audit");
    for (entry, outcome) in entries.iter().zip(["attempt", "failed"]) {
        assert_eq!(entry["resource"].as_str(), Some(name));
        assert!(
            entry["description"]
                .as_str()
                .context("audit description")?
                .contains(&format!("Package operation install: {outcome};")),
            "reason-write audit must report {outcome}: {entry}"
        );
    }
    Ok(())
}

#[test]
fn repository_usage_controls_info_and_update_candidates() -> anyhow::Result<()> {
    let fixture = RepositoryFixture::new()?;
    fixture.write_local("helper", "1-1")?;
    fixture.write_sync("excluded", &[("helper", "9-1", "")])?;
    fixture.write_sync("eligible", &[("helper", "2-1", "")])?;
    let alpm = fixture.open();
    let excluded = alpm.register_syncdb("excluded", alpm::SigLevel::NONE)?;
    excluded.set_usage(alpm::Usage::UPGRADE)?;
    alpm.register_syncdb("eligible", alpm::SigLevel::NONE)?
        .set_usage(alpm::Usage::SEARCH | alpm::Usage::UPGRADE)?;

    let info = super::get_pkg_info_from_db(&alpm, "helper")?.expect("eligible package");
    assert_eq!(info.repo, "eligible");
    assert_eq!(info.version.to_string(), "2-1");
    assert!(
        info.installed,
        "the selected package is installed at version 1"
    );

    excluded.set_usage(alpm::Usage::SEARCH)?;
    let updates = super::collect_updates(&alpm)?;
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].name, "helper");
    assert_eq!(updates[0].old_version, "1-1");
    assert_eq!(updates[0].new_version, "2-1");
    assert_eq!(updates[0].repo, "eligible");
    Ok(())
}

#[test]
fn updates_ignore_installed_group_when_upgrade_drops_group() -> anyhow::Result<()> {
    use std::io::Write as _;

    let fixture = RepositoryFixture::new()?;
    fixture.write_local("helper", "1-1")?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(fixture.database().join("local/helper-1-1/desc"))?
        .write_all(b"%GROUPS%\nheld\n\n")?;
    fixture.write_sync("preferred", &[("helper", "2-1", "")])?;
    let mut alpm = fixture.open();
    alpm.register_syncdb("preferred", alpm::SigLevel::NONE)?
        .set_usage(alpm::Usage::UPGRADE)?;
    alpm.set_ignoregroups(std::iter::once("held"))?;

    assert!(alpm.localdb().pkg("helper")?.should_ignore());
    assert!(
        !alpm
            .syncdbs()
            .iter()
            .next()
            .expect("preferred repository")
            .pkg("helper")?
            .should_ignore(),
        "the upgrade must have dropped the ignored group"
    );
    alpm.trans_init(alpm::TransFlag::NO_LOCK)?;
    alpm.sync_sysupgrade(false)?;
    assert!(
        alpm.trans_add().is_empty(),
        "native sysupgrade must retain the installed package's ignored group"
    );
    alpm.trans_release()?;

    alpm.set_ignoregroups(std::iter::empty::<&str>())?;
    let control = super::collect_updates(&alpm)?;
    assert_eq!(control.len(), 1, "the unignored upgrade must be visible");
    assert_eq!(control[0].name, "helper");
    assert_eq!(control[0].old_version, "1-1");
    assert_eq!(control[0].new_version, "2-1");
    assert_eq!(control[0].repo, "preferred");

    alpm.set_ignoregroups(std::iter::once("held"))?;
    let updates = super::collect_updates(&alpm)?;
    assert!(
        updates.is_empty(),
        "updates must match native sysupgrade when the installed package alone is ignored: {updates:?}"
    );
    Ok(())
}

#[test]
fn updates_do_not_fall_through_ignored_preferred_repository() -> anyhow::Result<()> {
    let fixture = RepositoryFixture::new()?;
    fixture.write_local("helper", "1-1")?;
    fixture.write_sync("preferred", &[("helper", "2-1", "%GROUPS%\nheld\n\n")])?;
    fixture.write_sync("lower", &[("helper", "9-1", "")])?;
    let mut alpm = fixture.open();
    alpm.register_syncdb("preferred", alpm::SigLevel::NONE)?
        .set_usage(alpm::Usage::UPGRADE)?;
    alpm.register_syncdb("lower", alpm::SigLevel::NONE)?
        .set_usage(alpm::Usage::UPGRADE)?;
    alpm.set_ignoregroups(std::iter::once("held"))?;

    assert!(!alpm.localdb().pkg("helper")?.should_ignore());
    assert!(
        alpm.syncdbs()
            .iter()
            .next()
            .expect("preferred repository")
            .pkg("helper")?
            .should_ignore(),
        "the preferred repository candidate must belong to the ignored group"
    );
    alpm.trans_init(alpm::TransFlag::NO_LOCK)?;
    alpm.sync_sysupgrade(false)?;
    assert!(
        alpm.trans_add().is_empty(),
        "native sysupgrade must not fall through an ignored preferred repository candidate"
    );
    alpm.trans_release()?;

    alpm.set_ignoregroups(std::iter::empty::<&str>())?;
    let control = super::collect_updates(&alpm)?;
    assert_eq!(control.len(), 1, "the unignored upgrade must be visible");
    assert_eq!(control[0].name, "helper");
    assert_eq!(control[0].old_version, "1-1");
    assert_eq!(control[0].new_version, "2-1");
    assert_eq!(control[0].repo, "preferred");

    alpm.set_ignoregroups(std::iter::once("held"))?;
    let updates = super::collect_updates(&alpm)?;
    assert!(
        updates.is_empty(),
        "updates must match native sysupgrade instead of selecting the lower repository: {updates:?}"
    );
    Ok(())
}

#[test]
fn scoped_info_reads_current_metadata_after_native_cache_is_primed() -> anyhow::Result<()> {
    let fixture = RepositoryFixture::new()?;
    fixture.write_sync("core", &[("helper", "1-1", "")])?;
    let alpm = fixture.open();
    alpm.register_syncdb("core", alpm::SigLevel::NONE)?;
    assert_eq!(
        super::get_pkg_info_from_db(&alpm, "helper")?
            .unwrap()
            .version
            .to_string(),
        "1-1"
    );
    fixture.write_sync("core", &[("helper", "2-1", "")])?;
    assert_eq!(
        super::get_pkg_info_from_db(&alpm, "helper")?
            .unwrap()
            .version
            .to_string(),
        "2-1"
    );
    Ok(())
}

#[test]
fn scoped_info_reads_current_installed_state_after_native_cache_is_primed() -> anyhow::Result<()>
{
    let fixture = RepositoryFixture::new()?;
    fixture.write_sync("core", &[("helper", "2-1", "")])?;
    let alpm = fixture.open();
    alpm.register_syncdb("core", alpm::SigLevel::NONE)?;
    assert!(
        !super::get_pkg_info_from_db(&alpm, "helper")?
            .unwrap()
            .installed
    );
    fixture.write_local("helper", "1-1")?;
    assert!(
        super::get_pkg_info_from_db(&alpm, "helper")?
            .unwrap()
            .installed,
        "newly installed package must not retain an earlier missing-package cache result"
    );
    std::fs::remove_dir_all(fixture.database().join("local/helper-1-1"))?;
    assert!(
        !super::get_pkg_info_from_db(&alpm, "helper")?
            .unwrap()
            .installed
    );
    Ok(())
}

#[test]
fn scoped_info_revalidates_present_signatures_after_native_cache_is_primed()
-> anyhow::Result<()> {
    let fixture = RepositoryFixture::new()?;
    let keyring = fixture.directory.path().join("keyring");
    std::fs::create_dir(&keyring)?;
    fixture.write_sync("core", &[("helper", "1-1", "")])?;
    let mut alpm = fixture.open();
    alpm.set_gpgdir(keyring.to_str().unwrap())?;
    alpm.register_syncdb(
        "core",
        alpm::SigLevel::DATABASE | alpm::SigLevel::DATABASE_OPTIONAL,
    )
    .expect("register the fixture database with optional signatures");
    assert!(super::get_pkg_info_from_db(&alpm, "helper")?.is_some());
    fixture.write_sync("core", &[("helper", "2-1", "")])?;
    std::fs::write(
        fixture.database().join("sync/core.db.sig"),
        b"invalid signature",
    )
    .expect("replace the fixture database signature with invalid data");
    let error = super::get_pkg_info_from_db(&alpm, "helper").expect_err(
        "current metadata must not reuse an earlier native signature-validation result",
    );
    assert!(error.downcast_ref::<alpm::Error>().is_some());
    Ok(())
}

#[test]
fn info_refuses_unavailable_eligible_repositories() -> anyhow::Result<()> {
    for corrupt in [false, true] {
        let fixture = RepositoryFixture::new()?;
        fixture.write_sync("healthy", &[("helper", "2-1", "")])?;
        if corrupt {
            std::fs::write(
                fixture.database().join("sync/unavailable.db"),
                b"invalid database",
            )
            .expect("private malformed repository fixture is writable");
        }
        let alpm = fixture.open();
        alpm.register_syncdb("healthy", alpm::SigLevel::NONE)?;
        alpm.register_syncdb("unavailable", alpm::SigLevel::NONE)?
            .set_usage(alpm::Usage::SEARCH)?;
        let error = super::get_pkg_info_from_db(&alpm, "absent").expect_err(if corrupt {
            "a corrupt eligible catalog cannot establish absence"
        } else {
            "a missing eligible catalog cannot establish absence"
        });
        let message = error.to_string();
        assert!(message.contains("Repository 'unavailable'"), "{error:#}");
        if corrupt {
            assert!(
                error.chain().any(|cause| cause
                    .to_string()
                    .contains("Unsupported pacman database compression")),
                "Rust metadata validation must explain the rejected source: {error:#}"
            );
        } else {
            assert!(message.contains("is unavailable"), "{error:#}");
        }
    }
    Ok(())
}

#[test]
fn native_database_validation_refuses_a_directory() -> anyhow::Result<()> {
    let fixture = RepositoryFixture::new()?;
    let path = fixture.database().join("sync/nonregular.db");
    std::fs::create_dir(&path)?;
    let alpm = fixture.open();
    let database = alpm.register_syncdb("nonregular", alpm::SigLevel::NONE)?;
    let error = super::validate_sync_database(&alpm, database)
        .expect_err("a database path must be a regular file");
    assert!(
        error
            .to_string()
            .contains("Repository 'nonregular' is not a regular database"),
        "{error:#}"
    );
    assert!(
        path.is_dir(),
        "validation must preserve the rejected object"
    );
    Ok(())
}

#[test]
fn prepared_dependency_refuses_a_missing_repository_or_package() -> anyhow::Result<()> {
    use crate::package_managers::arch_install::OfficialTarget;
    let original = RepositoryFixture::new()?;
    original.write_sync("selected", &[("helper", "2-1", "")])?;
    let selected = {
        let alpm = original.open();
        let database = alpm.register_syncdb("selected", alpm::SigLevel::NONE)?;
        let package = database.pkg("helper")?;
        OfficialTarget {
            repository: database.name().to_owned(),
            name: package.name().to_owned(),
            relations: vec!["helper>=2".to_owned()],
        }
    };
    let changed = RepositoryFixture::new()?;
    changed.write_sync("selected", &[("other", "2-1", "")])?;
    let alpm = changed.open();
    let error = super::validate_prepared_selections(&alpm, std::slice::from_ref(&selected))
        .expect_err("a removed selected repository cannot be substituted");
    assert!(
        error
            .to_string()
            .contains("Selected repository 'selected' is no longer configured"),
        "{error:#}"
    );
    alpm.register_syncdb("selected", alpm::SigLevel::NONE)?;
    let error = super::validate_prepared_selections(&alpm, &[selected])
        .expect_err("a removed selected package cannot be substituted");
    assert!(
        error
            .to_string()
            .contains("Selected package 'selected/helper' is no longer available"),
        "{error:#}"
    );
    Ok(())
}

#[test]
fn selected_dependency_uses_installed_state_only_when_present() -> anyhow::Result<()> {
    use crate::package_managers::arch_install::OfficialTarget;
    for installed in [false, true] {
        let fixture = RepositoryFixture::new()?;
        fixture.write_sync("selected", &[("helper", "2-1", "")])?;
        if installed {
            fixture.write_local("helper", "2-1")?;
        }
        let mut alpm = fixture.open();
        alpm.register_syncdb("selected", alpm::SigLevel::NONE)?;
        let targets = if installed {
            vec!["selected/helper".to_owned()]
        } else {
            Vec::new()
        };
        let prepared = super::prepare_alpm_transaction(
            &mut alpm,
            targets,
            super::TransactionKind::Install,
            &crate::core::pacman_conf::PacmanConfig::default(),
        )
        .expect("private installed-state fixture transaction initializes");
        prepared
            .0
            .trans_prepare()
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        assert!(
            prepared.0.trans_add().is_empty(),
            "the fixture must prepare no package changes"
        );
        let selection = OfficialTarget {
            repository: "selected".to_owned(),
            name: "helper".to_owned(),
            relations: vec!["helper>=2".to_owned(), "helper<3".to_owned()],
        };
        let result = super::validate_prepared_selections(prepared.0, &[selection]);
        if installed {
            result?;
            assert_eq!(
                prepared.0.localdb().pkg("helper")?.reason(),
                alpm::PackageReason::Explicit
            );
        } else {
            let error =
                result.expect_err("a selected dependency must be prepared or installed");
            assert!(
                error
                    .to_string()
                    .contains("neither prepared nor already installed"),
                "{error:#}"
            );
        }
    }
    Ok(())
}

#[test]
fn selected_virtual_dependency_preserves_provision_constraints() -> anyhow::Result<()> {
    use crate::package_managers::arch_install::OfficialTarget;
    let fixture = RepositoryFixture::new()?;
    fixture
        .write_sync(
            "selected",
            &[("provider", "7-1", "%PROVIDES%\nvirtual-helper=2\n\n")],
        )
        .expect("private virtual-provider repository is writable");
    let mut alpm = fixture.open();
    alpm.register_syncdb("selected", alpm::SigLevel::NONE)?;
    let prepared = super::prepare_alpm_transaction(
        &mut alpm,
        vec!["selected/provider".to_owned()],
        super::TransactionKind::Install,
        &crate::core::pacman_conf::PacmanConfig::default(),
    )
    .expect("private virtual-provider fixture transaction initializes");
    prepared
        .0
        .trans_prepare()
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    assert_eq!(
        prepared
            .0
            .trans_add()
            .first()
            .expect("prepared provider")
            .name(),
        "provider"
    );
    let selection = OfficialTarget {
        repository: "selected".to_owned(),
        name: "provider".to_owned(),
        relations: vec![
            "virtual-helper>=2".to_owned(),
            "virtual-helper<3".to_owned(),
        ],
    };
    super::validate_prepared_selections(prepared.0, std::slice::from_ref(&selection))?;
    let stale = OfficialTarget {
        relations: vec!["virtual-helper>=3".to_owned()],
        ..selection
    };
    let error = super::validate_prepared_selections(prepared.0, &[stale])
        .expect_err("the provider package version must not replace its provision version");
    assert!(
        error
            .to_string()
            .contains("no longer satisfies 'virtual-helper>=3'"),
        "{error:#}"
    );
    Ok(())
}

#[test]
fn reason_persistence_reports_a_missing_installed_package() -> anyhow::Result<()> {
    let fixture = RepositoryFixture::new()?;
    fixture.write_local("unrelated", "1-1")?;
    let description = fixture.database().join("local/unrelated-1-1/desc");
    let before = std::fs::read(&description)?;
    let alpm = fixture.open();
    let error = super::persist_installation_reasons(
        &alpm,
        &[("absent".to_owned(), alpm::PackageReason::Depend)],
    )
    .expect_err("missing postcommit state must require inspection before retry");
    assert!(
        error
            .to_string()
            .contains("installed package 'absent' could not be found"),
        "{error:#}"
    );
    assert!(
        error
            .to_string()
            .contains("inspect installed state before retrying"),
        "{error:#}"
    );
    assert_eq!(std::fs::read(description)?, before);
    assert_eq!(
        alpm.localdb().pkg("unrelated")?.reason(),
        alpm::PackageReason::Explicit
    );
    Ok(())
}

#[test]
fn prepared_dependency_keeps_selected_repository_and_constraints() -> anyhow::Result<()> {
    use crate::package_managers::arch_install::OfficialTarget;
    let fixture = RepositoryFixture::new()?;
    fixture.write_sync("high", &[("helper", "1-1", "")])?;
    fixture.write_sync("low", &[("helper", "2-1", "")])?;
    let mut alpm = fixture.open();
    alpm.register_syncdb("high", alpm::SigLevel::NONE)?;
    alpm.register_syncdb("low", alpm::SigLevel::NONE)?;
    let selected = OfficialTarget {
        repository: "low".to_owned(),
        name: "helper".to_owned(),
        relations: vec!["helper>=2".to_owned(), "helper<3".to_owned()],
    };
    let config = crate::core::pacman_conf::PacmanConfig::default();
    {
        let prepared = super::prepare_alpm_transaction(
            &mut alpm,
            vec!["low/helper".to_owned()],
            super::TransactionKind::Install,
            &config,
        )
        .expect("selected-repository fixture transaction initializes");
        prepared
            .0
            .trans_prepare()
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        super::validate_prepared_selections(prepared.0, std::slice::from_ref(&selected))?;
        assert_eq!(
            prepared.0.trans_add().first().unwrap().version().as_str(),
            "2-1"
        );
        let stale = OfficialTarget {
            relations: vec!["helper>=3".to_owned()],
            ..selected.clone()
        };
        let error = super::validate_prepared_selections(prepared.0, &[stale]).unwrap_err();
        assert!(
            error.to_string().contains("no longer satisfies"),
            "{error:#}"
        );
    }
    {
        let prepared = super::prepare_alpm_transaction(
            &mut alpm,
            vec!["helper".to_owned()],
            super::TransactionKind::Install,
            &config,
        )
        .expect("unqualified fixture transaction initializes");
        prepared
            .0
            .trans_prepare()
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        let error =
            super::validate_prepared_selections(prepared.0, std::slice::from_ref(&selected))
                .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("differs from its selected repository"),
            "{error:#}"
        );
    }
    alpm.syncdbs()
        .into_iter()
        .find(|db| db.name() == "low")
        .unwrap()
        .set_usage(alpm::Usage::SEARCH)?;
    let prepared = super::prepare_alpm_transaction(
        &mut alpm,
        vec!["low/helper".to_owned()],
        super::TransactionKind::Install,
        &config,
    )
    .expect("disabled-repository fixture transaction initializes");
    prepared
        .0
        .trans_prepare()
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let error = super::validate_prepared_selections(prepared.0, &[selected]).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("no longer allows dependency installation"),
        "{error:#}"
    );
    Ok(())
}

use std::sync::Mutex;

use super::{
    AlpmQuestionRefusals, ForwardedAlpmLogLevel, TransactionKind, check_database_lock,
    classify_alpm_log_level, clean_cache, clean_cache_preview, configure_signature_policy,
    download_lane_message, ensure_mirror_servers, ensure_removals_not_held,
    format_trans_prepare_error, is_keyring_related_error, local_package_siglevel,
    package_base_name, provider_selection_message, question_refusal_error,
    register_configured_syncdbs, repository_siglevel, setup_alpm_callbacks, signature_policy,
    transaction_flags, transaction_overall_percent, validate_aur_artifact_handoffs,
    validate_transaction_targets,
};
use crate::core::paths;

#[test]
fn lock_scan_skips_a_vanished_descriptor() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let lock = directory.path().join("db.lck");
    std::fs::write(&lock, b"")?;
    let proc_root = directory.path().join("proc");
    let descriptors = proc_root.join("123/fd");
    std::fs::create_dir_all(&descriptors)?;
    std::os::unix::fs::symlink(directory.path().join("vanished"), descriptors.join("3"))?;
    assert!(!super::database_lock_has_open_holder_in_proc(
        &lock, &proc_root
    )?);
    assert!(lock.exists(), "holder inspection must not remove the lock");
    Ok(())
}

#[test]
fn lock_scan_does_not_hide_a_holder_after_an_unavailable_descriptor() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let lock = directory.path().join("db.lck");
    std::fs::write(&lock, b"")?;
    let proc_root = directory.path().join("proc");
    let descriptors = proc_root.join("123/fd");
    std::fs::create_dir_all(&descriptors)?;
    std::os::unix::fs::symlink(directory.path().join("vanished"), descriptors.join("3"))?;
    std::os::unix::fs::symlink(&lock, descriptors.join("4"))?;
    assert!(super::database_lock_has_open_holder_in_proc(
        &lock, &proc_root
    )?);
    assert!(lock.exists(), "live holder must retain its lock");
    Ok(())
}

#[test]
fn lock_scan_keeps_a_lock_when_process_inspection_is_unavailable() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let lock = directory.path().join("db.lck");
    std::fs::write(&lock, b"")?;
    assert!(super::database_lock_has_open_holder_in_proc(
        &lock,
        &directory.path().join("missing-proc")
    )?);
    assert!(
        lock.exists(),
        "unavailable process data must not reclaim a lock"
    );
    Ok(())
}

#[test]
fn transaction_preparation_preserves_unheld_database_lock() -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let directory = tempfile::tempdir()?;
    let lock = directory.path().join("db.lck");
    std::fs::write(&lock, b"unheld-lock-evidence")?;
    let inode = std::fs::metadata(&lock)?.ino();
    let mut alpm = alpm::Alpm::new("/", directory.path().to_str().expect("utf-8 path"))?;
    let result = super::prepare_alpm_transaction(
        &mut alpm,
        vec![],
        TransactionKind::Install,
        &crate::core::pacman_conf::PacmanConfig::default(),
    );
    let Err(error) = result else {
        anyhow::bail!("transaction must refuse an existing unheld database lock")
    };
    assert!(error.to_string().contains("lock"));
    assert_eq!(std::fs::read(&lock)?, b"unheld-lock-evidence");
    assert_eq!(std::fs::metadata(&lock)?.ino(), inode);
    Ok(())
}

#[test]
fn database_lock_check_preserves_an_unheld_file() {
    let directory = tempfile::tempdir().expect("database root");
    let lock = directory.path().join("db.lck");
    std::fs::write(&lock, b"").expect("stale lock");
    let error = check_database_lock(directory.path())
        .expect_err("unheld lock requires deliberate recovery");
    assert_eq!(
        error.downcast_ref::<alpm::Error>(),
        Some(&alpm::Error::HandleLock)
    );
    assert!(error.to_string().contains("refusing automatic removal"));
    assert_eq!(std::fs::read(&lock).expect("preserved lock"), b"");
}

#[test]
fn database_lock_check_keeps_a_live_lease() {
    let directory = tempfile::tempdir().expect("database root");
    let lease = alpm::Alpm::new("/", directory.path().to_str().expect("utf-8 path"))
        .expect("ALPM handle");
    lease
        .trans_init(alpm::TransFlag::empty())
        .expect("live lease");
    check_database_lock(directory.path()).expect("live lock must be left in place");
    assert!(
        directory.path().join("db.lck").exists(),
        "held lock must survive inspection"
    );
    let contender = alpm::Alpm::new("/", directory.path().to_str().expect("utf-8 path"))
        .expect("second ALPM handle");
    assert_eq!(
        contender.trans_init(alpm::TransFlag::empty()),
        Err(alpm::Error::HandleLock),
        "native lease must exclude another transaction"
    );
    drop(lease);
    check_database_lock(directory.path()).expect("released lock permits another transaction");
    contender
        .trans_init(alpm::TransFlag::empty())
        .expect("second transaction acquires after legitimate release");
}

#[test]
fn transaction_percent_spans_the_whole_set() {
    assert_eq!(transaction_overall_percent(50, 1, 9), 5);
    assert_eq!(transaction_overall_percent(100, 9, 9), 100);
    assert_eq!(transaction_overall_percent(40, 0, 0), 40);
    assert_eq!(transaction_overall_percent(-1, 0, 0), 0);
    assert_eq!(transaction_overall_percent(140, 0, 0), 100);
}

#[test]
fn download_lane_names_in_flight_and_completed_counts() {
    assert_eq!(download_lane_message(5, 3), "5 in flight · 3 done");
    assert_eq!(download_lane_message(0, 18), "0 in flight · 18 done");
}

#[test]
fn refused_replacements_fail_the_transaction_naming_the_conflict() {
    let refusals = Mutex::new(AlpmQuestionRefusals::default());
    assert!(question_refusal_error(&refusals).is_none());

    refusals
        .lock()
        .expect("unpoisoned")
        .record_refused_replacement("bar", "core", "foo");
    let error = question_refusal_error(&refusals)
        .expect("a recorded refusal must fail the transaction");
    let message = error.to_string();
    assert!(message.contains("replace bar with core/foo"), "{message}");
    assert!(
        message.contains("unconfirmed package mutation"),
        "{message}"
    );
    assert!(
        message.contains("resolve the conflict explicitly"),
        "{message}"
    );
}

#[test]
fn refused_signing_key_import_is_reported_with_other_refused_changes() {
    let refusals = Mutex::new(AlpmQuestionRefusals::default());
    assert!(question_refusal_error(&refusals).is_none());
    {
        let mut recorded = refusals.lock().expect("unpoisoned");
        recorded.record_refused_key_import();
        recorded.record_refused_replacement("old", "core", "new");
    }
    let error = question_refusal_error(&refusals)
        .expect("unconfirmed trust cannot disappear behind a generic native error");
    let message = error.to_string();
    assert!(message.contains("untrusted signing key"), "{message}");
    assert!(message.contains("replace old with core/new"), "{message}");
}

#[test]
fn refused_removals_fail_the_transaction_listing_the_packages() {
    let refusals = Mutex::new(AlpmQuestionRefusals::default());
    refusals
        .lock()
        .expect("unpoisoned")
        .record_refused_removals(&["dep-a".to_string(), "dep-b".to_string()]);
    let error = question_refusal_error(&refusals)
        .expect("a recorded removal refusal must fail the transaction");
    let message = error.to_string();
    assert!(
        message.contains("drop unresolvable package(s)"),
        "{message}"
    );
    assert!(message.contains("dep-a, dep-b"), "{message}");
}

#[test]
#[serial_test::serial]
fn replace_question_is_declined_instead_of_auto_accepted() {
    crate::core::privilege::set_yes_flag(false);
    // Real libalpm sysupgrade against an isolated database: a sync package
    // that replaces an installed package must NOT be auto-accepted. The
    // callback declines (libalpm skips the replacement) and records the
    // refusal so the transaction fails with a named error instead of
    // silently replacing (or silently skipping) an installed package.
    let temp = tempfile::tempdir().expect("temporary alpm root");
    let root = temp.path().join("root");
    let db_path = temp.path().join("db");
    std::fs::create_dir_all(&root).expect("root dir");
    std::fs::create_dir_all(db_path.join("local/bar-1.0-1")).expect("local pkg dir");
    std::fs::create_dir_all(db_path.join("sync")).expect("sync db dir");
    std::fs::write(db_path.join("local/ALPM_DB_VERSION"), "9\n")
        .expect("write ALPM_DB_VERSION");

    std::fs::write(
        db_path.join("local/bar-1.0-1/desc"),
        "%NAME%\nbar\n\n%VERSION%\n1.0-1\n\n",
    )
    .expect("write local desc");

    let sync_desc = "%NAME%\nfoo\n\n%VERSION%\n2.0-1\n\n%REPLACES%\nbar\n\n%ARCH%\nx86_64\n\n";
    let sync_content = format!(
        "%FILENAME%\nfoo-2.0-1-x86_64.pkg.tar.zst\n\n%CSIZE%\n1\n\n%ISIZE%\n1\n\n%PACKAGER%\nFixture Maintainer <fixture@example.invalid>\n\n{sync_desc}"
    );
    let db_file = std::fs::File::create(db_path.join("sync/core.db")).expect("core.db");
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        db_file,
        flate2::Compression::fast(),
    ));
    let mut header = tar::Header::new_gnu();
    header.set_path("foo-2.0-1/desc").expect("header path");
    header.set_size(sync_content.len() as u64);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append(&header, sync_content.as_bytes())
        .expect("append sync desc");
    builder
        .into_inner()
        .expect("finish core.db")
        .finish()
        .expect("flush gzip");

    let alpm = alpm::Alpm::new(
        root.to_str().expect("utf-8 root"),
        db_path.to_str().expect("utf-8 db path"),
    )
    .expect("ALPM handle");
    alpm.register_syncdb("core", alpm::SigLevel::NONE)
        .expect("register core");

    let refusals = std::sync::Arc::new(Mutex::new(AlpmQuestionRefusals::default()));
    let _progress = setup_alpm_callbacks(&alpm, &refusals);

    alpm.trans_init(alpm::TransFlag::NEEDED)
        .expect("init transaction");
    alpm.sync_sysupgrade(false).expect("compute sysupgrade");

    assert!(
        alpm.trans_add().is_empty(),
        "declined replacement must not add the replacing package"
    );
    let error = question_refusal_error(&refusals)
        .expect("replace question must be recorded as refused");
    assert!(error.to_string().contains("replace bar with core/foo"));
}

#[test]
fn omarchy_cache_pruning_refuses_the_transaction_path() -> anyhow::Result<()> {
    const NAME: &str =
        "package_managers::alpm_ops::tests::omarchy_cache_pruning_refuses_the_transaction_path";
    if crate::core::testing::run_isolated_test(NAME)
        || crate::config::Settings::rerun_test_unprivileged(NAME)
    {
        return Ok(());
    }
    let fixture = tempfile::tempdir()?;
    let pacman_conf = fixture.path().join("absent-pacman.conf");
    temp_env::with_vars(
        [
            ("OMG_CONFIG_DIR", Some(fixture.path().as_os_str())),
            ("OMG_PACMAN_CONF", Some(pacman_conf.as_os_str())),
        ],
        || {
            assert_eq!(crate::core::paths::pacman_conf_path(), pacman_conf);
            let error = super::execute_omarchy_transaction(
                super::super::arch::NativeOmarchyOperation::PruneCache,
                Vec::new(),
            )
            .expect_err("cache cleaning cannot enter an ALPM transaction");
            assert_eq!(error.to_string(), "Cache pruning is not a transaction");
            assert_eq!(std::fs::read_dir(fixture.path())?.count(), 0);
            Ok(())
        },
    )
}

#[test]
fn omarchy_install_refuses_a_package_from_a_search_only_repository() -> anyhow::Result<()> {
    const NAME: &str = "package_managers::alpm_ops::tests::omarchy_install_refuses_a_package_from_a_search_only_repository";
    if crate::core::testing::run_isolated_test(NAME)
        || crate::config::Settings::rerun_test_unprivileged(NAME)
    {
        return Ok(());
    }
    let fixture = RepositoryFixture::new()?;
    let package = "omg-fixture-search-only";
    fixture.write_sync("lookup", &[(package, "1-1", "")])?;
    let root = fixture.directory.path().join("root");
    let keyring = fixture.directory.path().join("keyring");
    std::fs::create_dir(&keyring)?;
    let pacman_conf = fixture.directory.path().join("pacman.conf");
    std::fs::write(
        &pacman_conf,
        format!(
            "[options]\nRootDir = {}\nGPGDir = {}\nSigLevel = Required DatabaseOptional\n\
             [lookup]\nUsage = Search\nServer = file://{}\n",
            root.display(),
            keyring.display(),
            fixture.directory.path().display()
        ),
    )
    .expect("write custom native repository lookup configuration");
    let mut alpm = fixture.open();
    temp_env::with_vars(
        [
            ("OMG_CONFIG_DIR", Some(fixture.directory.path().as_os_str())),
            ("OMG_PACMAN_CONF", Some(pacman_conf.as_os_str())),
        ],
        || {
            assert_eq!(crate::core::paths::pacman_conf_path(), pacman_conf);
            assert_eq!(crate::core::paths::pacman_root_result()?, root);
            let config = crate::core::pacman_conf::PacmanConfig::parse(&pacman_conf)?;
            super::register_configured_syncdbs(&alpm, &config)?;
            let lookup = alpm.syncdbs().first().expect("fixture repository");
            assert_eq!(lookup.usage()?, alpm::Usage::SEARCH);
            assert_eq!(lookup.pkg(package)?.name(), package);
            let refusal = super::omarchy_install_candidate(&alpm, package)
                .map(drop)
                .expect_err("a search-only repository cannot supply an install candidate");
            assert_eq!(
                refusal.to_string(),
                format!(
                    "Omarchy package {package} is unavailable from configured install repositories"
                )
            );

            let error = super::execute_transaction_in(
                vec![package.to_owned()],
                super::TransactionKind::Install,
                Some(&mut alpm),
                None,
                &[],
                super::TransactionPolicy::Omarchy,
            )
            .expect_err("search visibility cannot authorize a package transaction");
            assert_eq!(error.to_string(), refusal.to_string());
            assert!(alpm.localdb().pkg(package).is_err());
            assert!(!fixture.database().join("db.lck").exists());
            Ok(())
        },
    )
}

#[test]
fn transaction_mirrors_use_the_loaded_configuration_snapshot() -> anyhow::Result<()> {
    let fixture = RepositoryFixture::new()?;
    let conf = fixture.directory.path().join("pacman.conf");
    let mirrorlist = fixture.directory.path().join("mirrorlist");
    std::fs::write(&conf, "[core]\nInclude = mirrorlist\n")?;
    std::fs::write(
        &mirrorlist,
        "Server = https://mirror.example/$repo/os/$arch\n",
    )
    .expect("write the mirrorlist before loading the ALPM configuration");
    let config = crate::core::pacman_conf::PacmanConfig::parse(&conf)?;
    std::fs::remove_file(&conf)?;
    std::fs::remove_file(&mirrorlist)?;
    let mut alpm = fixture.open();
    alpm.register_syncdb("core", alpm::SigLevel::NONE)?;
    super::configure_mirrors(&mut alpm, &config)?;
    let kernel = nix::sys::utsname::uname()?;
    let expected = format!(
        "https://mirror.example/core/os/{}",
        kernel.machine().to_string_lossy()
    );
    let core = alpm.syncdbs().first().expect("test repository");
    assert_eq!(
        core.servers().iter().collect::<Vec<_>>(),
        [expected.as_str()]
    );
    alpm.register_syncdb_mut("retired", alpm::SigLevel::NONE)?
        .add_server("https://retired.example/core")?;
    let error = super::configure_mirrors(&mut alpm, &config).expect_err(
        "an existing handle must not keep a repository outside the loaded configuration",
    );
    assert!(
        error
            .to_string()
            .contains("Registered repository 'retired' is absent from pacman.conf"),
        "{error:#}"
    );
    let error = super::mirror_configuration_result("core", Err(alpm::Error::Memory))
        .expect_err("a native mirror setter error must retain the repository and cause");
    assert_eq!(
        error.to_string(),
        "Failed to set mirrors for repository 'core'"
    );
    assert_eq!(
        error.downcast_ref::<alpm::Error>(),
        Some(&alpm::Error::Memory)
    );
    Ok(())
}

#[test]
#[serial_test::serial]
fn omarchy_replacements_keep_vendor_defaults_but_unattended_conflicts_refuse() {
    for (policy, yes, relationship, accepted) in [
        (super::TransactionPolicy::Standard, true, "REPLACES", true),
        (super::TransactionPolicy::Omarchy, false, "REPLACES", true),
        (super::TransactionPolicy::Omarchy, true, "CONFLICTS", false),
    ] {
        let temp = tempfile::tempdir().expect("temporary alpm root");
        let root = temp.path().join("root");
        let db_path = temp.path().join("db");
        std::fs::create_dir_all(&root).expect("root dir");
        std::fs::create_dir_all(db_path.join("local/bar-1.0-1")).expect("local pkg dir");
        std::fs::create_dir_all(db_path.join("sync")).expect("sync db dir");
        std::fs::write(db_path.join("local/ALPM_DB_VERSION"), "9\n")
            .expect("write ALPM_DB_VERSION");

        std::fs::write(
            db_path.join("local/bar-1.0-1/desc"),
            "%NAME%\nbar\n\n%VERSION%\n1.0-1\n\n",
        )
        .expect("write local desc");

        std::fs::write(
            db_path.join("local/bar-1.0-1/files"),
            "%FILES%\nusr/bin/bar\n\n",
        )
        .expect("installed file inventory");

        let sync_desc = format!(
            "%NAME%\nfoo\n\n%VERSION%\n2.0-1\n\n%{relationship}%\nbar\n\n%ARCH%\nx86_64\n\n"
        );
        let sync_content = format!(
            "%FILENAME%\nfoo-2.0-1-x86_64.pkg.tar.zst\n\n%CSIZE%\n1\n\n%ISIZE%\n1\n\n%PACKAGER%\nFixture Maintainer <fixture@example.invalid>\n\n{sync_desc}"
        );
        let db_file = std::fs::File::create(db_path.join("sync/core.db")).expect("core.db");
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            db_file,
            flate2::Compression::fast(),
        ));
        let mut header = tar::Header::new_gnu();
        header.set_path("foo-2.0-1/desc").expect("header path");
        header.set_size(sync_content.len() as u64);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append(&header, sync_content.as_bytes())
            .expect("append sync desc");
        builder
            .into_inner()
            .expect("finish core.db")
            .finish()
            .expect("flush gzip");

        let mut alpm = alpm::Alpm::new(
            root.to_str().expect("utf-8 root"),
            db_path.to_str().expect("utf-8 db path"),
        )
        .expect("ALPM handle");
        alpm.register_syncdb("core", alpm::SigLevel::NONE)
            .expect("register core");

        let refusals = std::sync::Arc::new(Mutex::new(AlpmQuestionRefusals::default()));
        let _progress = super::setup_alpm_callbacks_in(&alpm, &refusals, policy);

        crate::core::privilege::set_yes_flag(yes);
        alpm.trans_init(alpm::TransFlag::NEEDED)
            .expect("init transaction");
        if relationship == "REPLACES" {
            let result = alpm.sync_sysupgrade(false);
            crate::core::privilege::set_yes_flag(false);
            result.expect("compute sysupgrade");
            assert_eq!(
                alpm.trans_add().len(),
                1,
                "accepted replacement is scheduled"
            );
            assert!(question_refusal_error(&refusals).is_none());
        } else {
            let package = alpm
                .syncdbs()
                .iter()
                .next()
                .expect("core")
                .pkg("foo")
                .expect("sync package");
            assert!(
                package
                    .conflicts()
                    .iter()
                    .any(|dependency| dependency.name() == "bar"),
                "fixture declares the real package conflict"
            );
            assert!(
                alpm.localdb().pkg("bar").is_ok(),
                "conflicting package is installed"
            );
            alpm.trans_add_pkg(package)
                .expect("add conflicting package");
            let prepared = alpm.trans_prepare().is_ok();
            crate::core::privilege::set_yes_flag(false);
            assert_eq!(
                prepared, accepted,
                "unattended conflict must not remove an installed package"
            );
            assert!(
                alpm.trans_remove().is_empty(),
                "refused conflict preserves the installed package"
            );
        }
    }
}

#[test]
fn provider_selection_defaults_to_the_first_provider_and_names_it() {
    let message = provider_selection_message(
        &["provider-a".to_string(), "provider-b".to_string()],
        "provider-virtual",
    );
    assert!(
        message.contains("Auto-selected provider provider-a"),
        "{message}"
    );
    assert!(message.contains("1 of 2"), "{message}");
    assert!(message.contains("dependency provider-virtual"), "{message}");

    // Pacman's provider prompt lists providers sorted and defaults to the
    // first one; the auto-answer must never pick a different index.
    let single = provider_selection_message(&["only".to_string()], "dep");
    assert!(single.contains("provider only (1 of 1)"), "{single}");
}

#[test]
fn alpm_warnings_and_errors_are_not_classified_as_debug_output() {
    assert_eq!(
        classify_alpm_log_level(alpm::LogLevel::ERROR | alpm::LogLevel::WARNING),
        ForwardedAlpmLogLevel::Error
    );
    assert_eq!(
        classify_alpm_log_level(alpm::LogLevel::WARNING),
        ForwardedAlpmLogLevel::Warning
    );
    assert_eq!(
        classify_alpm_log_level(alpm::LogLevel::DEBUG),
        ForwardedAlpmLogLevel::Debug
    );
    assert_eq!(
        classify_alpm_log_level(alpm::LogLevel::FUNCTION),
        ForwardedAlpmLogLevel::Trace
    );
}

#[test]
#[serial_test::serial]
fn pacman_transaction_options_honor_default_hooks_and_download_user() -> anyhow::Result<()> {
    struct ResetPaths;
    impl Drop for ResetPaths {
        fn drop(&mut self) {
            paths::reset_test_overrides();
        }
    }

    let directory = tempfile::tempdir()?;
    let root = directory.path();
    for path in [
        "db",
        "etc/pacman.d/gnupg",
        "etc/pacman.d/hooks",
        "usr/share/libalpm/hooks",
        "custom-hooks",
    ] {
        std::fs::create_dir_all(root.join(path))?;
    }
    paths::set_test_overrides(Some(root.to_path_buf()), None);
    let _reset = ResetPaths;
    let root_path = root.to_str().expect("UTF-8 root");
    let db = root.join("db");
    let db_path = db.to_str().expect("UTF-8 database");
    let mut alpm = alpm::Alpm::new(root_path, db_path)?;
    let config =
        crate::core::pacman_conf::PacmanConfig::parse_str("[options]\nDownloadUser = root\n")?;
    super::configure_transaction_options(&mut alpm, &config)?;
    assert_eq!(
        (
            alpm.hookdirs()
                .into_iter()
                .map(std::path::PathBuf::from)
                .collect::<Vec<_>>(),
            alpm.sandbox_user(),
        ),
        (
            vec![
                root.join("usr/share/libalpm/hooks"),
                root.join("etc/pacman.d/hooks")
            ],
            Some("root"),
        ),
    );

    let custom_hooks = "[options]\nHookDir = custom-hooks\n";
    let config = crate::core::pacman_conf::PacmanConfig::parse_str(custom_hooks)?;
    super::configure_transaction_options(&mut alpm, &config)?;
    assert_eq!(
        alpm.hookdirs()
            .into_iter()
            .map(std::path::PathBuf::from)
            .collect::<Vec<_>>(),
        vec![
            root.join("usr/share/libalpm/hooks"),
            root.join("custom-hooks")
        ],
    );
    assert_eq!(
        alpm.sandbox_user(),
        None,
        "reconfiguration must clear the old download identity"
    );
    Ok(())
}

#[test]
fn transaction_registration_rejects_partial_repository_sets() {
    let database_path = tempfile::tempdir().expect("temporary database path");
    let database_path = database_path.path().to_string_lossy();
    let alpm = alpm::Alpm::new("/", database_path.as_ref()).expect("ALPM handle");
    alpm.register_syncdb("core", alpm::SigLevel::NONE)
        .expect("initial sync database");
    let config = crate::core::pacman_conf::PacmanConfig {
        repos: vec![crate::core::pacman_conf::RepoConfig {
            name: "core".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };

    let error = register_configured_syncdbs(&alpm, &config)
        .expect_err("a failed configured repository must abort registration");
    assert!(
        error
            .to_string()
            .contains("refusing a partial repository set")
    );
}

#[test]
fn mirror_configuration_requires_at_least_one_usable_server() {
    let database_path = tempfile::tempdir().expect("temporary database path");
    let database_path = database_path.path().to_string_lossy();
    let mut alpm = alpm::Alpm::new("/", database_path.as_ref()).expect("ALPM handle");
    alpm.register_syncdb_mut("core", alpm::SigLevel::NONE)
        .expect("register sync database");

    assert!(ensure_mirror_servers(&alpm).is_err());
    alpm.syncdbs_mut()
        .into_iter()
        .next()
        .expect("registered sync database")
        .add_server("https://mirror.example/$repo/os/$arch")
        .expect("add test mirror");
    assert!(ensure_mirror_servers(&alpm).is_ok());
}

#[test]
fn mirror_configuration_preserves_the_registered_repository_set() -> anyhow::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    const TEST: &str = "package_managers::alpm_ops::tests::mirror_configuration_preserves_the_registered_repository_set";
    if crate::core::testing::run_isolated_test(TEST)
        || crate::config::Settings::rerun_test_unprivileged(TEST)
    {
        return Ok(());
    }
    assert!(
        !crate::core::is_root(),
        "mirror configuration overrides require an ordinary UID"
    );
    let owner = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let root = owner.path().join("root");
    let database = owner.path().join("db");
    for directory in [&root, &database] {
        std::fs::DirBuilder::new().mode(0o700).create(directory)?;
    }
    let mirror = owner.path().join("mirror");
    let configuration = owner.path().join("pacman.conf");
    std::fs::write(
        &configuration,
        format!(
            "[options]\nArchitecture = fixture-arch auto\n[core]\nServer = file://{}/$repo/os/$arch\n\n[configured-only]\nServer = file://{}/$repo/os/$arch\n",
            mirror.display(),
            mirror.display()
        ),
    )
    .expect("write private mirror configuration");
    let mut alpm = alpm::Alpm::new(
        root.to_str().expect("private root path"),
        database.to_str().expect("private database path"),
    )
    .expect("open the private mirror fixture database");
    alpm.register_syncdb_mut("core", alpm::SigLevel::NONE)?;
    assert!(ensure_mirror_servers(&alpm).is_err());
    alpm.syncdbs_mut()
        .into_iter()
        .next()
        .expect("registered core database")
        .add_server("https://previous.example/core")?;
    let config = crate::core::pacman_conf::PacmanConfig::parse(&configuration)?;
    super::configure_mirrors(&mut alpm, &config)?;
    super::configure_mirrors(&mut alpm, &config)?;

    let databases: Vec<_> = alpm.syncdbs().into_iter().collect();
    assert_eq!(
        databases.len(),
        1,
        "configuring mirrors must not register an additional database"
    );
    let core = databases.first().expect("registered core database");
    assert_eq!(core.name(), "core");
    let expected = format!("file://{}/core/os/fixture-arch", mirror.display());
    assert_eq!(
        core.servers().into_iter().collect::<Vec<_>>(),
        vec![expected.as_str()]
    );
    ensure_mirror_servers(&alpm)?;
    Ok(())
}

#[test]
fn native_options_use_default_local_hooks_and_configured_download_user() -> anyhow::Result<()> {
    const NAME: &str = "package_managers::alpm_ops::tests::native_options_use_default_local_hooks_and_configured_download_user";
    if crate::core::testing::run_isolated_test(NAME) {
        return Ok(());
    }
    let fixture = RepositoryFixture::new()?;
    let root = fixture.directory.path().join("root");
    let distro = root.join("usr/share/libalpm/hooks");
    let local = root.join("etc/pacman.d/hooks");
    let custom = root.join("etc/custom-hooks");
    for path in [&distro, &local, &custom] {
        std::fs::create_dir_all(path)?;
    }
    std::fs::create_dir_all(root.join("etc/pacman.d/gnupg"))?;
    crate::core::paths::set_test_overrides(Some(root), Some(fixture.database()));
    let mut alpm = fixture.open();
    let config =
        crate::core::pacman_conf::PacmanConfig::parse_str("[options]\nDownloadUser = nobody\n")
            .expect("parse the configured ALPM download account");
    super::configure_transaction_options(&mut alpm, &config)?;
    assert_eq!(alpm.sandbox_user(), Some("nobody"));
    let hooks = |alpm: &alpm::Alpm| {
        alpm.hookdirs()
            .into_iter()
            .map(|path| std::path::PathBuf::from(path.trim_end_matches('/')))
            .collect::<Vec<_>>()
    };
    assert_eq!(hooks(&alpm), vec![distro.clone(), local]);

    let config = crate::core::pacman_conf::PacmanConfig::parse_str(
        "[options]\nHookDir = etc/custom-hooks\n",
    )
    .expect("parse the custom ALPM hook directory");
    super::configure_transaction_options(&mut alpm, &config)?;
    assert_eq!(hooks(&alpm), vec![distro, custom]);
    assert_eq!(alpm.sandbox_user(), None);
    let config = crate::core::pacman_conf::PacmanConfig::parse_str(
        "[options]\nDownloadUser = omg-no-such-downloader-account\n",
    )
    .expect("an unknown account parses and must be refused during native setup");
    assert!(super::configure_transaction_options(&mut alpm, &config).is_err());
    Ok(())
}

#[test]
fn pacman_signature_policy_is_applied_to_handle_and_repositories() {
    let config = crate::core::pacman_conf::PacmanConfig::parse_str(
        "[options]\nSigLevel = Required DatabaseOptional\nLocalFileSigLevel = PackageOptional\nRemoteFileSigLevel = PackageNever\n\n[core]\nSigLevel = PackageOptional DatabaseNever\n",
    )
    .expect("signature configuration");
    let policy = signature_policy(&config).expect("parsed signature policy");

    assert!(policy.default.contains(alpm::SigLevel::PACKAGE));
    assert!(policy.default.contains(alpm::SigLevel::DATABASE));
    assert!(policy.default.contains(alpm::SigLevel::DATABASE_OPTIONAL));
    assert!(policy.local_file.contains(alpm::SigLevel::PACKAGE));
    assert!(policy.local_file.contains(alpm::SigLevel::PACKAGE_OPTIONAL));
    assert!(!policy.remote_file.contains(alpm::SigLevel::PACKAGE));

    let repository = repository_siglevel(policy.default, config.repos[0].sig_level.as_deref())
        .expect("repository signature policy");
    assert!(repository.contains(alpm::SigLevel::PACKAGE));
    assert!(repository.contains(alpm::SigLevel::PACKAGE_OPTIONAL));
    assert!(!repository.contains(alpm::SigLevel::DATABASE));

    let database_path = tempfile::tempdir().expect("temporary database path");
    let database_path = database_path.path().to_string_lossy();
    let mut alpm = alpm::Alpm::new("/", database_path.as_ref()).expect("ALPM handle");
    configure_signature_policy(&mut alpm, &config).expect("configure ALPM policy");
    assert_eq!(alpm.default_siglevel(), policy.default);
    assert_eq!(alpm.local_file_siglevel(), policy.local_file);
    assert_eq!(alpm.remote_file_siglevel(), policy.remote_file);
}

#[test]
fn invalid_pacman_signature_policy_fails_closed() {
    let config = crate::core::pacman_conf::PacmanConfig::parse_str(
        "[options]\nSigLevel = PackageSometimes\n",
    )
    .expect("syntax parser preserves policy text");
    let error = signature_policy(&config).expect_err("unknown policy must fail");
    assert!(error.to_string().contains("PackageSometimes"), "{error:#}");
}

#[test]
fn aur_artifacts_allow_missing_signatures_but_verify_present_ones() {
    let configured = alpm::SigLevel::PACKAGE | alpm::SigLevel::PACKAGE_UNKNOWN_OK;
    let regular = local_package_siglevel(TransactionKind::Install, configured);
    assert_eq!(regular, configured);

    let aur = local_package_siglevel(TransactionKind::InstallAurArtifact, configured);
    assert!(aur.contains(alpm::SigLevel::PACKAGE));
    assert!(aur.contains(alpm::SigLevel::PACKAGE_OPTIONAL));
}

#[test]
fn hold_pkg_patterns_cover_explicit_and_cascade_removals() {
    let patterns = vec!["linux".to_string(), "kde-*".to_string()];

    ensure_removals_not_held(["bash"], &patterns).expect("unheld package");
    let explicit = ensure_removals_not_held(["linux"], &patterns)
        .expect_err("explicit HoldPkg entry must be rejected");
    assert!(explicit.to_string().contains("HoldPkg pattern 'linux'"));
    let cascade = ensure_removals_not_held(["kde-libs"], &patterns)
        .expect_err("glob-protected cascade must be rejected");
    assert!(cascade.to_string().contains("HoldPkg pattern 'kde-*'"));
}

#[test]
fn hold_pkg_patterns_follow_pacman_literal_braces_and_brackets() {
    ensure_removals_not_held(["widget-git"], &["widget{,-git}".to_owned()])
        .expect("pacman does not expand brace alternatives");
    let error = ensure_removals_not_held(["widget["], &["widget[".to_owned()])
        .expect_err("unmatched bracket is a literal protected name");
    assert!(
        error
            .to_string()
            .starts_with("Package 'widget[' is protected by HoldPkg pattern 'widget['")
    );
}

#[test]
fn installable_repository_fixture_passes_native_metadata_admission() -> anyhow::Result<()> {
    let fixture = RepositoryFixture::new()?;
    fixture.write_sync("core", &[("fixture", "1-1", "")])?;
    let root = fixture.directory.path().join("root");
    let mut alpm = super::open_alpm_at(&root, &fixture.database())?;
    let repository = alpm.register_syncdb("core", alpm::SigLevel::NONE)?;
    alpm.trans_init(alpm::TransFlag::NEEDED)?;
    alpm.trans_add_pkg(repository.pkg("fixture")?)
        .map_err(|error| anyhow::anyhow!("Cannot select fixture package: {error}"))?;
    let prepared = super::prepared_advisory_packages(
        &alpm,
        TransactionKind::Install,
        &crate::core::security::SecurityPolicy::default(),
        &[],
        None,
    );
    alpm.trans_release()?;
    assert_eq!(
        prepared?.len(),
        1,
        "installable fixtures satisfy signing metadata checks"
    );
    Ok(())
}

#[test]
fn prepared_repository_metadata_requires_a_packager_before_native_key_import()
-> anyhow::Result<()> {
    for packager in [None, Some("Fixture Maintainer <fixture@example.invalid>")] {
        let owner = tempfile::tempdir()?;
        let root = owner.path().join("root");
        let database = owner.path().join("db");
        std::fs::create_dir(&root)?;
        std::fs::create_dir_all(database.join("local"))?;
        std::fs::create_dir(database.join("sync"))?;
        std::fs::write(database.join("local/ALPM_DB_VERSION"), "9\n")?;
        let mut content = "%NAME%\nfixture\n\n%VERSION%\n1-1\n\n%ARCH%\nany\n\n%FILENAME%\nfixture-1-1-any.pkg.tar.gz\n\n%CSIZE%\n1\n\n%ISIZE%\n1\n\n".to_owned();
        if let Some(packager) = packager {
            content.push_str("%PACKAGER%\n");
            content.push_str(packager);
            content.push_str("\n\n");
        }
        let compressed = flate2::write::GzEncoder::new(
            std::fs::File::create(database.join("sync/core.db"))?,
            flate2::Compression::fast(),
        );
        let mut archive = tar::Builder::new(compressed);
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append_data(&mut header, "fixture-1-1/desc", content.as_bytes())?;
        archive.into_inner()?.finish()?;
        let mut alpm = super::open_alpm_at(&root, &database)?;
        let repository = alpm.register_syncdb("core", alpm::SigLevel::NONE)?;
        alpm.trans_init(alpm::TransFlag::NEEDED)?;
        alpm.trans_add_pkg(repository.pkg("fixture")?)
            .map_err(|error| anyhow::anyhow!("Cannot add fixture package: {error}"))?;
        let result = super::prepared_advisory_packages(
            &alpm,
            TransactionKind::Install,
            &crate::core::security::SecurityPolicy::default(),
            &[],
            None,
        );
        alpm.trans_release()?;
        if packager.is_some() {
            assert_eq!(result?.len(), 1, "complete repository record is accepted");
        } else {
            let error =
                result.expect_err("Missing PACKAGER must fail before C key-import code");
            assert!(error.to_string().contains("PACKAGER"), "{error:#}");
        }
        assert!(
            !database.join("db.lck").exists(),
            "validation releases the private transaction lock"
        );
    }
    Ok(())
}

#[test]
fn signature_readers_use_the_configured_keyring() -> anyhow::Result<()> {
    let owner = tempfile::tempdir()?;
    let root = owner.path().join("root");
    let database = owner.path().join("db");
    let keyring = owner.path().join("configured-keys");
    for path in [&root, &database, &keyring] {
        std::fs::create_dir(path)?;
    }
    let mut alpm = super::open_alpm_at(&root, &database)?;
    let config = crate::core::pacman_conf::PacmanConfig {
        gpg_dir: Some(keyring.to_str().expect("fixture UTF-8").to_owned()),
        ..Default::default()
    };
    configure_signature_policy(&mut alpm, &config)?;
    assert_eq!(
        alpm.gpgdir().map(std::path::Path::new),
        Some(keyring.as_path()),
        "Read-only validation must use the same configured trust store as transactions"
    );
    Ok(())
}

#[test]
fn signature_readers_reject_nul_keyring_paths_without_panicking() -> anyhow::Result<()> {
    let owner = tempfile::tempdir()?;
    let mut alpm = super::open_alpm_at(owner.path(), owner.path())?;
    let config = crate::core::pacman_conf::PacmanConfig {
        gpg_dir: Some("/configured/keyring\0alias".to_owned()),
        ..Default::default()
    };
    let error = configure_signature_policy(&mut alpm, &config)
        .expect_err("NUL keyring paths cannot reach the C-string boundary");
    assert!(error.to_string().contains("NUL"), "{error:#}");
    Ok(())
}

#[test]
fn invalid_hold_pkg_patterns_fail_closed() {
    let error = ensure_removals_not_held(["anything"], &["held\0".to_string()])
        .expect_err("invalid HoldPkg patterns must not be ignored");
    assert!(error.to_string().contains("Invalid HoldPkg pattern"));
}

#[test]
fn system_upgrade_rejects_targets_instead_of_discarding_them() {
    validate_transaction_targets(TransactionKind::SystemUpgrade, &[])
        .expect("targetless system upgrade");
    let error = validate_transaction_targets(
        TransactionKind::SystemUpgrade,
        &["explicit-target".to_string()],
    )
    .expect_err("explicit target must not be silently discarded");
    assert!(error.to_string().contains("explicit package targets"));
    validate_transaction_targets(TransactionKind::Install, &["package".to_string()])
        .expect("install accepts targets");
}

#[test]
fn recursive_removal_matches_pacman_rs_flags() {
    let explicit = transaction_flags(TransactionKind::Remove { recursive: false });
    assert!(!explicit.contains(alpm::TransFlag::RECURSE));
    assert!(!explicit.contains(alpm::TransFlag::UNNEEDED));

    let recursive = transaction_flags(TransactionKind::Remove { recursive: true });
    assert!(recursive.contains(alpm::TransFlag::RECURSE));
    assert!(!recursive.contains(alpm::TransFlag::UNNEEDED));
}

#[test]
fn base_name_parses_simple_and_dash_containing_pkgbases() {
    assert_eq!(
        package_base_name("linux-6.7.0-1-x86_64.pkg.tar.zst"),
        Some("linux")
    );
    // Regression: pkgbases containing dashes must stay one group.
    assert_eq!(
        package_base_name("python-pip-24.0-1-any.pkg.tar.zst"),
        Some("python-pip")
    );
    assert_eq!(
        package_base_name("haskell-aeson-2.1.2.1-269-x86_64.pkg.tar.zst"),
        Some("haskell-aeson")
    );
    assert_eq!(
        package_base_name("foo-1.2-2-x86_64.pkg.tar.xz"),
        Some("foo")
    );
    assert_eq!(
        package_base_name("linux-6.7.0-1-x86_64.pkg.tar.gz"),
        Some("linux")
    );
    assert_eq!(
        package_base_name("foo-1.2-2-x86_64.pkg.tar.bz2"),
        Some("foo")
    );
    assert_eq!(
        package_base_name("lib32-mesa-1:24.0.1-1-x86_64.pkg.tar.zst"),
        Some("lib32-mesa")
    );
}

#[test]
fn base_name_rejects_unexpected_shapes() {
    assert_eq!(package_base_name("not-a-package-file.tar.zst"), None);
    assert_eq!(package_base_name("linux-6.7.0-1-x86_64.zip"), None);
    assert_eq!(package_base_name("-1-2-x86_64.pkg.tar.zst"), None);
}

#[test]
fn clean_cache_keeps_two_distinct_versions_per_architecture_across_cache_copies()
-> anyhow::Result<()> {
    const NAME: &str = "package_managers::alpm_ops::tests::clean_cache_keeps_two_distinct_versions_per_architecture_across_cache_copies";
    if crate::core::testing::run_isolated_test(NAME)
        || crate::config::Settings::rerun_test_unprivileged(NAME)
    {
        return Ok(());
    }
    assert!(!crate::core::is_root());
    let owner = tempfile::tempdir()?;
    let first = owner.path().join("first");
    let second = owner.path().join("second");
    std::fs::create_dir(&first)?;
    std::fs::create_dir(&second)?;
    let alias = owner.path().join("first-alias");
    std::os::unix::fs::symlink(&first, &alias)?;
    let mut archives = Vec::new();
    for architecture in ["x86_64", "aarch64", "any"] {
        for (directory, version, suffix, group) in [
            (&first, "1.10.0-1", "zst", "newest"),
            (&first, "1.10.0-1", "xz", "newest"),
            (&second, "1.10.0-1", "zst", "newest"),
            (&second, "1.10.0-01", "bz2", "newest"),
            (&first, "1.2.0-1", "gz", "spare"),
            (&first, "1.0.0-1", "zst", "obsolete"),
            (&second, "1.0.0-1", "xz", "spare"),
            (&second, "0.9.0-1", "zst", "obsolete"),
        ] {
            let path =
                directory.join(format!("testpkg-{version}-{architecture}.pkg.tar.{suffix}"));
            let data = format!("inert {architecture} {version} {suffix}").into_bytes();
            let signature =
                format!("inert signature {architecture} {version} {suffix}").into_bytes();
            std::fs::write(&path, &data)?;
            std::fs::write(path.with_added_extension("sig"), &signature)?;
            archives.push((path, architecture, group, data, signature));
        }
    }
    assert_eq!(
        alpm::vercmp("1.10.0-1", "1.10.0-01"),
        std::cmp::Ordering::Equal
    );
    let config = owner.path().join("pacman.conf");
    std::fs::write(
        &config,
        format!(
            "[options]\nCacheDir = {} {} {}\n",
            first.display(),
            second.display(),
            alias.display()
        ),
    )
    .expect("write the configuration for the three package cache paths");
    temp_env::with_vars(
        [
            ("OMG_PACMAN_CONF", Some(config.as_os_str())),
            ("OMG_PACMAN_CACHE_DIR", None),
            ("OMG_PACMAN_ROOT", None),
        ],
        || -> anyhow::Result<()> {
            paths::reset_test_overrides();
            let preview = clean_cache_preview(2)?;
            for (path, _, _, data, signature) in &archives {
                assert_eq!(std::fs::read(path)?, *data, "preview changed archive bytes");
                assert_eq!(
                    std::fs::read(path.with_added_extension("sig"))?,
                    *signature,
                    "preview changed signature bytes"
                );
            }
            let cleaned = clean_cache(2)?;
            for architecture in ["x86_64", "aarch64", "any"] {
                let retained = archives
                    .iter()
                    .filter(|(path, arch, _, _, _)| *arch == architecture && path.is_file())
                    .map(|(_, _, group, _, _)| *group)
                    .collect::<std::collections::BTreeSet<_>>();
                assert_eq!(
                    retained,
                    std::collections::BTreeSet::from(["newest", "spare"]),
                    "keep=2 must retain two distinct ALPM versions for {architecture}, despite duplicate files/formats/cache directories"
                );
            }
            let mut removed = 0;
            let mut freed = 0;
            for (path, _, group, data, signature) in &archives {
                assert_eq!(
                    path.is_file(),
                    *group != "obsolete",
                    "every archive of a retained version must survive: {path:?}"
                );
                if path.is_file() {
                    assert_ne!(*group, "obsolete");
                    assert_eq!(std::fs::read(path)?, *data);
                    assert_eq!(std::fs::read(path.with_added_extension("sig"))?, *signature);
                } else {
                    assert!(
                        !path.with_added_extension("sig").exists(),
                        "removed archive left its signature"
                    );
                    removed += 1;
                    freed += (data.len() + signature.len()) as u64;
                }
            }
            assert_eq!(preview, (removed, freed));
            assert_eq!(
                cleaned,
                (removed * 2, freed),
                "cleanup counts archives and their signatures; preview counts archives"
            );
            assert_eq!(clean_cache_preview(2)?, (0, 0));
            assert_eq!(clean_cache(2)?, (0, 0));
            Ok(())
        },
    )
}

#[test]
fn native_factory_rejects_non_utf8_paths_instead_of_opening_lossy_aliases() -> anyhow::Result<()>
{
    use std::os::unix::ffi::OsStringExt;

    const NAME: &str = "package_managers::alpm_ops::tests::native_factory_rejects_non_utf8_paths_instead_of_opening_lossy_aliases";
    if crate::core::testing::run_isolated_test(NAME)
        || crate::config::Settings::rerun_test_unprivileged(NAME)
    {
        return Ok(());
    }
    assert!(!crate::core::is_root());
    let owner = tempfile::tempdir()?;
    let root = owner.path().join("root");
    let database = owner.path().join("database");
    let byte_root = owner
        .path()
        .join(std::ffi::OsString::from_vec(b"root-\xff".to_vec()));
    let byte_database = owner
        .path()
        .join(std::ffi::OsString::from_vec(b"database-\xff".to_vec()));
    let alias_root = owner.path().join("root-\u{fffd}");
    let alias_database = owner.path().join("database-\u{fffd}");
    for path in [&root, &byte_root, &alias_root] {
        std::fs::create_dir(path)?;
    }
    for path in [&database, &byte_database, &alias_database] {
        std::fs::create_dir_all(path.join("local"))?;
        std::fs::create_dir(path.join("sync"))?;
        std::fs::write(path.join("local/ALPM_DB_VERSION"), b"9\n")?;
    }
    let sentinel = alias_database.join("local/alias-only-99-1/desc");
    std::fs::create_dir(sentinel.parent().expect("private sentinel parent"))?;
    let sentinel_bytes = b"%NAME%\nalias-only\n\n%VERSION%\n99-1\n\n%REASON%\n0\n\n";
    std::fs::write(&sentinel, sentinel_bytes)?;
    let config = owner.path().join("pacman.conf");
    std::fs::write(&config, "[options]\nSigLevel = Never\n")?;
    temp_env::with_vars(
        [
            ("OMG_PACMAN_CONF", Some(config.as_os_str())),
            ("OMG_PACMAN_ROOT", Some(root.as_os_str())),
            ("OMG_PACMAN_DB_DIR", Some(database.as_os_str())),
        ],
        || -> anyhow::Result<()> {
            paths::reset_test_overrides();
            assert!(super::open_default_alpm()?.localdb().pkgs().is_empty());
            for (field, selected_root, selected_database) in [
                ("root", &byte_root, &database),
                ("database", &root, &byte_database),
            ] {
                let error = temp_env::with_vars(
                    [
                        ("OMG_PACMAN_ROOT", Some(selected_root.as_os_str())),
                        ("OMG_PACMAN_DB_DIR", Some(selected_database.as_os_str())),
                    ],
                    || super::open_default_alpm().err(),
                )
                .expect(
                    "non-UTF-8 paths must refuse before opening a replacement-character alias",
                );
                let diagnostic = format!("{error:#}");
                assert!(
                    diagnostic.to_ascii_lowercase().contains("utf-8"),
                    "{field}: {diagnostic}"
                );
            }
            assert_eq!(std::fs::read(&sentinel)?, sentinel_bytes);
            assert!(!alias_database.join("db.lck").exists());
            Ok(())
        },
    )
}

#[test]
fn native_factory_rejects_nul_config_paths_without_unwinding() -> anyhow::Result<()> {
    const NAME: &str = "package_managers::alpm_ops::tests::native_factory_rejects_nul_config_paths_without_unwinding";
    if crate::core::testing::run_isolated_test(NAME)
        || crate::config::Settings::rerun_test_unprivileged(NAME)
    {
        return Ok(());
    }
    assert!(!crate::core::is_root());
    let owner = tempfile::tempdir()?;
    let root = owner.path().join("root");
    let database = owner.path().join("database");
    std::fs::create_dir(&root)?;
    std::fs::create_dir_all(database.join("local"))?;
    std::fs::create_dir(database.join("sync"))?;
    std::fs::write(database.join("local/ALPM_DB_VERSION"), b"9\n")?;
    let config = owner.path().join("pacman.conf");
    temp_env::with_vars(
        [
            ("OMG_PACMAN_CONF", Some(config.as_os_str())),
            ("OMG_PACMAN_ROOT", None),
            ("OMG_PACMAN_DB_DIR", None),
        ],
        || -> anyhow::Result<()> {
            paths::reset_test_overrides();
            let valid = format!(
                "[options]\nRootDir = {}\nDBPath = {}\nSigLevel = Never\n",
                root.display(),
                database.display()
            );
            std::fs::write(&config, &valid)?;
            assert!(super::open_default_alpm()?.localdb().pkgs().is_empty());
            for (field, bad) in [
                ("RootDir", format!("{}\0invalid", root.display())),
                ("DBPath", format!("{}\0invalid", database.display())),
            ] {
                let contents = valid
                    .lines()
                    .map(|line| {
                        if line.starts_with(field) {
                            format!("{field} = {bad}")
                        } else {
                            line.to_owned()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n";
                std::fs::write(&config, contents)?;
                let refusal = std::panic::catch_unwind(super::open_default_alpm)
                    .expect("NUL-bearing configuration must return an error without unwinding")
                    .map(drop)
                    .expect_err("NUL-bearing configuration must refuse");
                let diagnostic = format!("{refusal:#}");
                assert!(
                    diagnostic.to_ascii_lowercase().contains("nul"),
                    "{field}: {diagnostic}"
                );
            }
            Ok(())
        },
    )
}

#[test]
fn clean_cache_keeps_the_newest_archive_with_duplicate_directory_aliases() {
    const TEST: &str = "package_managers::alpm_ops::tests::clean_cache_keeps_the_newest_archive_with_duplicate_directory_aliases";
    if crate::core::testing::run_isolated_test(TEST)
        || crate::config::Settings::rerun_test_unprivileged(TEST)
    {
        return;
    }
    assert!(
        !crate::core::is_root(),
        "cache configuration overrides require an unprivileged caller"
    );
    let owner = tempfile::tempdir().expect("private cache owner");
    let cache = owner.path().join("cache");
    std::fs::create_dir(&cache).expect("private cache");
    let alias = owner.path().join("cache-alias");
    std::os::unix::fs::symlink(&cache, &alias).expect("private cache alias");
    let old = cache.join("demo-1.0-1-x86_64.pkg.tar.zst");
    let current = cache.join("demo-2.0-1-x86_64.pkg.tar.zst");
    std::fs::write(&old, b"old").expect("old archive");
    std::fs::write(&current, b"new").expect("current archive");
    let config = owner.path().join("pacman.conf");
    std::fs::write(
        &config,
        format!(
            "[options]\nCacheDir = {} {} {} {}\n",
            cache.display(),
            cache.display(),
            cache.join(".").display(),
            alias.display()
        ),
    )
    .expect("private cache configuration");
    temp_env::with_vars(
        [
            (
                "OMG_PACMAN_CONF",
                Some(config.to_str().expect("configuration path")),
            ),
            ("OMG_PACMAN_CACHE_DIR", None),
            ("OMG_PACMAN_ROOT", None),
        ],
        || {
            paths::reset_test_overrides();
            assert_eq!(clean_cache_preview(1).expect("preview"), (1, 3));
            assert!(
                old.is_file() && current.is_file(),
                "preview mutated the cache"
            );
            assert_eq!(clean_cache(1).expect("cleanup"), (1, 3));
            assert!(!old.exists());
            assert_eq!(std::fs::read(&current).expect("retained archive"), b"new");
        },
    );
}

#[test]
fn clean_cache_distinguishes_missing_and_inaccessible_directories() {
    use std::os::unix::fs::PermissionsExt;

    const TEST: &str = "package_managers::alpm_ops::tests::clean_cache_distinguishes_missing_and_inaccessible_directories";
    if crate::core::testing::run_isolated_test(TEST)
        || crate::config::Settings::rerun_test_unprivileged(TEST)
    {
        return;
    }
    assert!(
        !crate::core::is_root(),
        "permission checks require an ordinary UID"
    );
    let owner = tempfile::tempdir().expect("private cache owner");
    let cache = owner.path().join("cache");
    let blocked = owner.path().join("blocked");
    let hidden = blocked.join("cache");
    let missing = owner.path().join("missing");
    std::fs::create_dir(&cache).expect("private healthy cache");
    std::fs::create_dir_all(&hidden).expect("private inaccessible cache");
    let old = cache.join("demo-1.0-1-x86_64.pkg.tar.zst");
    let current = cache.join("demo-2.0-1-x86_64.pkg.tar.zst");
    let signature = old.with_added_extension("sig");
    std::fs::write(&old, b"old").expect("old archive");
    std::fs::write(&current, b"new").expect("current archive");
    let config = owner.path().join("pacman.conf");
    temp_env::with_vars(
        [
            (
                "OMG_PACMAN_CONF",
                Some(config.to_str().expect("private config path")),
            ),
            ("OMG_PACMAN_CACHE_DIR", None),
            ("OMG_PACMAN_ROOT", None),
        ],
        || {
            paths::reset_test_overrides();
            std::fs::write(
                &config,
                format!(
                    "[options]\nCacheDir = {} {}\n",
                    cache.display(),
                    missing.display()
                ),
            )
            .expect("missing cache configuration");
            assert_eq!(
                clean_cache(1).expect("missing directories are harmless"),
                (1, 3)
            );
            assert!(!old.exists());
            assert_eq!(std::fs::read(&current).expect("retained archive"), b"new");
            std::fs::write(&old, b"old").expect("restore private old archive");
            std::fs::write(&signature, b"sig").expect("private signature");
            std::fs::write(
                &config,
                format!(
                    "[options]\nCacheDir = {} {}\n",
                    cache.display(),
                    hidden.display()
                ),
            )
            .expect("inaccessible cache configuration");
            let restore = scopeguard::guard(blocked.clone(), |path| {
                let result =
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
                eprintln!("Private cache permission restoration: {result:?}");
            });
            std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o0))
                .expect("private permission fault");
            let result = clean_cache(1);
            drop(restore);
            let error = result.expect_err(
                "an unreadable configured cache must abort before deleting archives",
            );
            assert!(
                error.chain().any(|cause| cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|cause| cause.kind() == std::io::ErrorKind::PermissionDenied)),
                "{error:#}"
            );
            assert_eq!(std::fs::read(&old).expect("preserved old archive"), b"old");
            assert_eq!(
                std::fs::read(&signature).expect("preserved signature"),
                b"sig"
            );
            assert_eq!(
                std::fs::read(&current).expect("preserved current archive"),
                b"new"
            );
        },
    );
}

#[test]
fn clean_cache_preserves_non_regular_entries_and_their_signatures() {
    if crate::core::testing::run_isolated_test(
        "package_managers::alpm_ops::tests::clean_cache_preserves_non_regular_entries_and_their_signatures",
    ) {
        return;
    }
    temp_env::with_var_unset("OMG_PACMAN_CACHE_DIR", || {
        let owner = tempfile::tempdir().expect("private cache owner");
        let cache = owner.path().join("var/cache/pacman/pkg");
        std::fs::create_dir_all(&cache).expect("private cache");
        let old = cache.join("demo-1.0-1-x86_64.pkg.tar.zst");
        let current = cache.join("demo-2.0-1-x86_64.pkg.tar.zst");
        let directory = cache.join("demo-99.0-1-x86_64.pkg.tar.zst");
        let link = cache.join("demo-100.0-1-x86_64.pkg.tar.zst");
        let external = owner.path().join("outside-cache");
        std::fs::write(&old, b"old").expect("old archive");
        std::fs::write(&current, b"new").expect("current archive");
        std::fs::write(&external, b"owner data").expect("private symlink target");
        std::fs::create_dir(&directory).expect("package-shaped directory");
        std::fs::write(directory.with_added_extension("sig"), b"keep-signature")
            .expect("directory companion");
        std::os::unix::fs::symlink(&external, &link).expect("package-shaped symlink");
        paths::set_test_overrides(Some(owner.path().to_path_buf()), None);
        assert_eq!(clean_cache_preview(1).expect("preview"), (1, 3));
        assert_eq!(clean_cache(1).expect("cleanup"), (1, 3));
        paths::reset_test_overrides();
        assert!(!old.exists());
        assert_eq!(std::fs::read(&current).expect("retained archive"), b"new");
        assert!(directory.is_dir());
        assert!(link.is_symlink());
        assert_eq!(std::fs::read(external).expect("owner data"), b"owner data");
        assert_eq!(
            std::fs::read(directory.with_added_extension("sig")).expect("directory companion"),
            b"keep-signature"
        );
    });
}

#[test]
fn failed_cache_archive_removal_preserves_its_signature() {
    let owner = tempfile::tempdir().expect("private removal owner");
    let archive = owner.path().join("demo-1.0-1-x86_64.pkg.tar.zst");
    std::fs::create_dir(&archive).expect("archive unlink failure fixture");
    let signature = archive.with_added_extension("sig");
    std::fs::write(&signature, b"preserve").expect("signature fixture");
    let mut removed = 0;
    assert_eq!(
        super::remove_cache_file_and_signature(&archive, &mut removed),
        0
    );
    assert_eq!(removed, 0);
    assert_eq!(
        std::fs::read(signature).expect("preserved signature"),
        b"preserve"
    );
    assert!(archive.is_dir());
}

#[test]
fn clean_cache_preview_counts_detached_signature_bytes() {
    if crate::core::testing::run_isolated_test(
        "package_managers::alpm_ops::tests::clean_cache_preview_counts_detached_signature_bytes",
    ) {
        return;
    }
    temp_env::with_var_unset("OMG_PACMAN_CACHE_DIR", || {
        let temp = tempfile::tempdir().expect("private cache fixture");
        let cache = temp.path().join("var/cache/pacman/pkg");
        std::fs::create_dir_all(&cache).expect("create cache");
        let old = cache.join("demo-1.0-1-x86_64.pkg.tar.zst");
        let old_signature = old.with_added_extension("sig");
        let current = cache.join("demo-2.0-1-x86_64.pkg.tar.zst");
        let current_signature = current.with_added_extension("sig");
        std::fs::write(&old, b"old").expect("old archive");
        std::fs::write(&old_signature, b"sig").expect("old signature");
        std::fs::write(&current, b"current").expect("current archive");
        std::fs::write(&current_signature, b"current-signature").expect("current signature");
        paths::set_test_overrides(Some(temp.path().to_path_buf()), None);

        let preview = clean_cache_preview(1).expect("preview");
        assert_eq!(std::fs::read(&old).unwrap(), b"old");
        assert_eq!(std::fs::read(&old_signature).unwrap(), b"sig");
        assert_eq!(std::fs::read(&current).unwrap(), b"current");
        assert_eq!(
            std::fs::read(&current_signature).unwrap(),
            b"current-signature"
        );
        assert_eq!(preview, (1, 6), "preview must include companion bytes");

        let cleaned = clean_cache(1).expect("cleanup");
        paths::reset_test_overrides();
        assert_eq!(cleaned, (2, 6));
        assert!(!old.exists());
        assert!(!old_signature.exists());
        assert_eq!(std::fs::read(&current).unwrap(), b"current");
        assert_eq!(
            std::fs::read(&current_signature).unwrap(),
            b"current-signature"
        );
    });
}

#[test]
fn clean_cache_sorts_by_alpm_vercmp_and_keeps_newest_version() {
    if crate::core::testing::run_isolated_test(
        "package_managers::alpm_ops::tests::clean_cache_sorts_by_alpm_vercmp_and_keeps_newest_version",
    ) {
        return;
    }
    temp_env::with_var_unset("OMG_PACMAN_CACHE_DIR", || {
        let temp = tempfile::tempdir().expect("tempdir");
        let cache_dir = temp.path().join("var/cache/pacman/pkg");
        std::fs::create_dir_all(&cache_dir).expect("create cache dir");

        // Write packages with version numbers where alphabetical/mtime sorting differs from vercmp:
        // 1.10.0-1 is newer than 1.2.0-1 and 1.0.0-1
        let v1_0 = cache_dir.join("testpkg-1.0.0-1-x86_64.pkg.tar.zst");
        let v1_2 = cache_dir.join("testpkg-1.2.0-1-x86_64.pkg.tar.zst");
        let v1_10 = cache_dir.join("testpkg-1.10.0-1-x86_64.pkg.tar.zst");

        std::fs::write(&v1_0, b"content-1.0").expect("write v1.0");
        std::fs::write(&v1_2, b"content-1.2").expect("write v1.2");
        std::fs::write(&v1_10, b"content-1.10").expect("write v1.10");

        paths::set_test_overrides(Some(temp.path().to_path_buf()), None);

        let (preview_removed, preview_freed) =
            clean_cache_preview(1).expect("preview succeeds");
        assert_eq!(
            preview_removed, 2,
            "preview should identify 2 older versions"
        );
        assert_eq!(
            preview_freed, 22,
            "preview should count freed bytes accurately"
        );
        assert!(v1_0.exists());
        assert!(v1_2.exists());
        assert!(v1_10.exists());

        let (removed, freed) = clean_cache(1).expect("clean succeeds");
        paths::reset_test_overrides();

        assert_eq!(removed, 2, "clean should remove 2 older versions");
        assert_eq!(freed, 22);
        // ALPM vercmp ensures the highest version (1.10.0-1) is kept, NOT deleted!
        assert!(v1_10.exists(), "newest version 1.10.0-1 must be kept");
        assert!(!v1_0.exists(), "older version 1.0.0-1 must be removed");
        assert!(!v1_2.exists(), "older version 1.2.0-1 must be removed");
    });
}

#[test]
fn keyring_error_detection_matches_expected_keywords() {
    assert!(is_keyring_related_error(
        "invalid or corrupted package (PGP signature)"
    ));
    assert!(is_keyring_related_error("KEYRING is not writable"));
    assert!(is_keyring_related_error("SIGNATURE validation failed"));
    assert!(is_keyring_related_error("PGP validation failed"));
    assert!(is_keyring_related_error("package is CORRUPT"));
    assert!(!is_keyring_related_error("conflicting dependencies"));
}

#[test]
fn keyring_prepare_errors_include_repair_commands() {
    let msg = format_trans_prepare_error("invalid or corrupted package");
    assert!(msg.contains("archlinux-keyring"));
    assert!(msg.contains("pacman-key --init"));
    assert!(msg.contains("omg sync && omg install <package>"));
}

#[test]
fn generic_prepare_errors_keep_dependency_guidance() {
    let msg = format_trans_prepare_error("unresolvable package conflicts detected");
    assert!(msg.contains("conflicting packages or missing dependencies"));
    assert!(msg.contains("omg update && omg install <package>"));
}

#[test]
fn progress_events_throttle_percent_and_publish_on_name_change() {
    let mut last = (String::new(), 0_i32);
    assert!(super::progress_event_is_due(&mut last, "foo", 1));
    assert!(!super::progress_event_is_due(&mut last, "foo", 3));
    assert!(super::progress_event_is_due(&mut last, "foo", 6));
    assert!(super::progress_event_is_due(&mut last, "bar", 7));
    assert_eq!(last.0, "bar");
    assert!(super::progress_event_is_due(&mut last, "bar", 0));
    assert_eq!(last, ("bar".to_string(), 0));
    assert!(super::progress_event_is_due(&mut last, "bar", 100));
    assert!(super::progress_event_is_due(&mut last, "bar", 100));
    assert_eq!(last, ("bar".to_string(), 100));
}

#[test]
fn aur_transactions_require_sealed_handoff_targets() {
    let sealed = "/__omg_archive/sealed-descriptor".to_owned();
    let unsealed = "/tmp/package.pkg.tar.zst".to_owned();
    for packages in [
        vec![sealed.clone(), unsealed.clone()],
        vec![unsealed, sealed.clone()],
    ] {
        let error =
            validate_aur_artifact_handoffs(TransactionKind::InstallAurArtifact, &packages)
                .expect_err("every artifact must use a sealed handoff");
        assert_eq!(
            error.to_string(),
            "AUR artifacts must arrive through an immutable sealed handoff"
        );
    }
    validate_aur_artifact_handoffs(
        TransactionKind::InstallAurArtifact,
        &[sealed.clone(), sealed],
    )
    .expect("multiple sealed handoffs are accepted");
    assert!(
        validate_aur_artifact_handoffs(
            TransactionKind::InstallAurArtifact,
            &["/tmp/package.pkg.tar.zst".to_owned()]
        )
        .is_err()
    );
    assert!(
        validate_aur_artifact_handoffs(
            TransactionKind::InstallAurArtifact,
            &["/__omg_archive/sealed-descriptor".to_owned()]
        )
        .is_ok()
    );
    assert!(
        validate_aur_artifact_handoffs(
            TransactionKind::Install,
            &["/tmp/package.pkg.tar.zst".to_owned()]
        )
        .is_ok()
    );
}

#[test]
fn aur_archive_preparation_refuses_repository_targets_before_opening_a_transaction()
-> anyhow::Result<()> {
    let fixture = RepositoryFixture::new()?;
    fixture.write_sync("core", &[("omg-fixture-package", "1-1", "")])?;
    let mut alpm = fixture.open();
    alpm.register_syncdb("core", alpm::SigLevel::NONE)?;
    let result = super::prepare_alpm_transaction(
        &mut alpm,
        vec!["omg-fixture-package".to_owned()],
        TransactionKind::InstallAurArtifact,
        &crate::core::pacman_conf::PacmanConfig::default(),
    );
    let error = result
        .err()
        .expect("archive-only preparation must refuse a repository target");
    assert!(
        error
            .to_string()
            .contains("not a supported local package archive path")
    );
    assert!(!fixture.database().join("db.lck").exists());
    Ok(())
}

#[test]
fn removal_refuses_missing_targets_and_releases_the_private_transaction() -> anyhow::Result<()>
{
    let fixture = RepositoryFixture::new()?;
    fixture.write_local("omg-fixture-kept", "1-1")?;
    let mut alpm = fixture.open();
    let absent = "omg-fixture-absent".to_owned();
    let kept = "omg-fixture-kept".to_owned();
    let kind = TransactionKind::Remove { recursive: false };
    let config = crate::core::pacman_conf::PacmanConfig::default();
    for targets in [vec![absent.clone()], vec![kept.clone(), absent.clone()]] {
        let error = super::prepare_alpm_transaction(&mut alpm, targets, kind, &config)
            .err()
            .expect("a missing package must fail the entire removal request");
        assert!(error.to_string().contains(&absent));
        assert_eq!(
            error.downcast_ref::<alpm::Error>(),
            Some(&alpm::Error::PkgNotFound)
        );
        assert_eq!(alpm.localdb().pkg(kept.as_str())?.version().as_str(), "1-1");
        assert!(!fixture.database().join("db.lck").exists());
    }
    Ok(())
}

#[test]
fn auto_package_architecture_uses_the_running_kernel_machine() -> anyhow::Result<()> {
    let fixture = RepositoryFixture::new()?;
    let mut alpm = fixture.open();
    let kernel = nix::sys::utsname::uname()?;
    let machine = kernel.machine().to_str().expect("kernel machine is UTF-8");
    let config = crate::core::pacman_conf::PacmanConfig::parse_str(
        "[options]\nArchitecture = explicit-machine auto\n",
    )
    .expect("parse a mixed explicit and automatic architecture configuration");
    super::configure_transaction_options(&mut alpm, &config)?;
    assert_eq!(
        alpm.architectures().into_iter().collect::<Vec<_>>(),
        ["explicit-machine", machine],
    );
    Ok(())
}
