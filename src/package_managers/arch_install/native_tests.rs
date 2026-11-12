use std::fs::{self, File};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use flate2::{Compression, write::GzEncoder};

use super::{InstallIntent, InstallItem, InstallRequest, InstallTarget, execute_handoff};
use crate::core::security::artifact::ArchiveSnapshot;

const TEST: &str =
    "package_managers::arch_install::native_tests::native_installation_preserves_mixed_intents";
const CREATION_DENIAL_TEST: &str = "package_managers::arch_install::native_tests::descriptor_creation_denial_refuses_installation_handoff";
const SEALING_DENIAL_TEST: &str = "package_managers::arch_install::native_tests::descriptor_sealing_denial_refuses_installation_handoff";

fn assert_descriptor_denial(test: &str, syscall: nix::libc::c_long, argument: u32) {
    use nix::libc;

    assert_eq!(
        std::env::var("OMG_ARCH_INSTALL_FIXTURE").as_deref(),
        Ok("isolated-container"),
        "kernel-policy fault injection requires the disposable native fixture"
    );
    assert!(crate::core::is_root(), "native fixture requires root");
    if std::env::var("OMG_DESCRIPTOR_DENIAL_TEST").as_deref() == Ok(test) {
        let request = InstallRequest::new(vec![InstallItem {
            target: InstallTarget::Named("omg-fixture-denied".to_owned()),
            intent: InstallIntent::Requested,
        }])
        .expect("valid requested installation");
        let error = request
            .seal()
            .err()
            .expect("kernel denial must refuse the installation handoff");
        assert_eq!(
            error.downcast_ref::<rustix::io::Errno>(),
            Some(&rustix::io::Errno::PERM)
        );
        return;
    }
    let instruction = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
    let filters = [
        instruction((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 0, 0, 0),
        instruction(
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            0,
            3,
            syscall as u32,
        ),
        instruction(
            (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            0,
            0,
            (std::mem::offset_of!(libc::seccomp_data, args) + std::mem::size_of::<u64>()) as u32,
        ),
        instruction(
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            0,
            1,
            argument,
        ),
        instruction(
            (libc::BPF_RET | libc::BPF_K) as u16,
            0,
            0,
            libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
        ),
        instruction(
            (libc::BPF_RET | libc::BPF_K) as u16,
            0,
            0,
            libc::SECCOMP_RET_ALLOW,
        ),
    ];
    let mut bytes = Vec::new();
    for filter in filters {
        bytes.extend_from_slice(&filter.code.to_ne_bytes());
        bytes.extend_from_slice(&[filter.jt, filter.jf]);
        bytes.extend_from_slice(&filter.k.to_ne_bytes());
    }
    let directory = tempfile::tempdir().expect("private seccomp fixture");
    let path = directory.path().join("descriptor-denial.bpf");
    fs::write(&path, bytes).expect("write raw native BPF instructions");
    let output = std::process::Command::new("setpriv")
        .args(["--no-new-privs", "--seccomp-filter"])
        .arg(&path)
        .arg(std::env::current_exe().expect("fixture executable"))
        .args([
            "--exact",
            test,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("OMG_DESCRIPTOR_DENIAL_TEST", test)
        .output()
        .expect("run confined descriptor fixture");
    assert!(
        output.status.success()
            && String::from_utf8_lossy(&output.stdout)
                .contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
        "descriptor denial fixture failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "restricts only an explicitly provisioned disposable native fixture child"]
fn descriptor_creation_denial_refuses_installation_handoff() {
    use rustix::fs::MemfdFlags;
    assert_descriptor_denial(
        CREATION_DENIAL_TEST,
        nix::libc::SYS_memfd_create,
        (MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING).bits(),
    );
}

#[test]
#[ignore = "restricts only an explicitly provisioned disposable native fixture child"]
fn descriptor_sealing_denial_refuses_installation_handoff() {
    assert_descriptor_denial(
        SEALING_DENIAL_TEST,
        nix::libc::SYS_fcntl,
        nix::libc::F_ADD_SEALS as u32,
    );
}

fn archive(dir: &Path, name: &str, version: &str) -> Result<ArchiveSnapshot> {
    let path = dir.join(format!("{name}-{version}-any.pkg.tar.gz"));
    let file = File::create(&path)?;
    let mut tar = tar::Builder::new(GzEncoder::new(file, Compression::default()));
    let payload = b"fixture\n".as_slice();
    let payload_path = format!("usr/share/omg-fixture/{name}");
    let payload_size = payload.len();
    let info = format!(
        "pkgname = {name}\npkgbase = {name}\npkgver = {version}\npkgdesc = inert fixture\nurl = https://example.invalid\nbuilddate = 1\npackager = Fixture\nsize = {payload_size}\narch = any\nlicense = MIT\n"
    );
    let buildinfo = format!(
        "format = 2\npkgname = {name}\npkgbase = {name}\npkgver = {version}\npkgarch = any\n"
    );
    let mtree = format!("#mtree\n./{payload_path} type=file mode=644 size={payload_size}\n");
    for (name, contents) in [
        (".PKGINFO".to_owned(), info.as_bytes()),
        (".BUILDINFO".to_owned(), buildinfo.as_bytes()),
        (".MTREE".to_owned(), mtree.as_bytes()),
        (payload_path, payload),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, name, contents)?;
    }
    tar.into_inner()?.finish()?.sync_all()?;
    ArchiveSnapshot::capture(&path)
}

#[test]
fn fixture_archives_have_complete_admission_metadata() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let snapshot = archive(directory.path(), "omg-fixture-metadata", "1-1")?;
    let inspection =
        crate::package_managers::aur::artifact_inspector::inspect_archive(&snapshot.path())?;
    assert_eq!(inspection.package_name, "omg-fixture-metadata");
    assert_eq!(inspection.package_version, "1-1");
    inspection.enforce_profile(crate::config::AurSecurityProfile::Standard)?;
    let root = directory.path().join("root");
    let db = directory.path().join("db");
    fs::create_dir_all(&root)?;
    fs::create_dir_all(db.join("local"))?;
    let alpm = alpm::Alpm::new(
        root.to_str().context("fixture root path")?,
        db.to_str().context("fixture database path")?,
    )?;
    let snapshot_path = snapshot.path();
    let package = alpm.pkg_load(
        snapshot_path.to_str().context("fixture archive path")?,
        true,
        alpm::SigLevel::NONE,
    )?;
    assert_eq!(package.name(), inspection.package_name);
    assert_eq!(package.version().as_str(), inspection.package_version);
    assert_eq!(package.base(), Some(inspection.package_base.as_str()));
    assert_eq!(package.arch(), Some(inspection.architecture.as_str()));
    let file_list = package.files();
    let files = file_list.files();
    assert_eq!(files.len(), 1, "native ALPM must see the fixture payload");
    let payload = files
        .iter()
        .find(|file| file.name() == b"usr/share/omg-fixture/omg-fixture-metadata")
        .context("native ALPM file list is missing the fixture payload")?;
    assert_eq!(payload.size(), 8, "fixture payload is eight bytes");
    assert_eq!(
        payload.mode(),
        0o100644,
        "fixture payload is a regular file"
    );
    assert_eq!(package.isize(), payload.size());
    Ok(())
}

fn install(items: &[(&ArchiveSnapshot, InstallIntent)]) -> Result<()> {
    let request = InstallRequest::new(
        items
            .iter()
            .map(|(archive, intent)| InstallItem {
                target: InstallTarget::Archive(archive.handoff()),
                intent: *intent,
            })
            .collect(),
    )?;
    let sealed = request.seal()?;
    execute_handoff(&sealed.handoff())
}

fn installed(root: &Path, db: &Path) -> Result<Vec<(String, String, alpm::PackageReason)>> {
    let alpm = alpm::Alpm::new(
        root.to_str().context("root path")?,
        db.to_str().context("database path")?,
    )?;
    let mut packages = alpm
        .localdb()
        .pkgs()
        .iter()
        .map(|package| {
            (
                package.name().to_owned(),
                package.version().as_str().to_owned(),
                package.reason(),
            )
        })
        .collect::<Vec<_>>();
    packages.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(packages)
}

struct ResetPaths;
impl Drop for ResetPaths {
    fn drop(&mut self) {
        crate::core::paths::reset_test_overrides();
    }
}

#[test]
#[ignore = "requires an explicitly provisioned isolated Arch container or QEMU guest"]
fn native_installation_preserves_mixed_intents() -> Result<()> {
    anyhow::ensure!(
        std::env::var("OMG_ARCH_INSTALL_FIXTURE").as_deref() == Ok("isolated-container"),
        "OMG_ARCH_INSTALL_FIXTURE=isolated-container is required"
    );
    anyhow::ensure!(
        crate::core::is_root(),
        "native installation fixture requires root"
    );
    anyhow::ensure!(
        crate::core::paths::pacman_conf_path() == Path::new("/etc/pacman.conf"),
        "fixture requires native pacman configuration"
    );
    if crate::core::testing::run_isolated_test_with_timeout(
        TEST,
        std::time::Duration::from_secs(30),
    ) {
        return Ok(());
    }

    let temp = tempfile::Builder::new()
        .prefix("omg-native-intent-")
        .tempdir()?;
    let root = temp.path().join("root");
    let db = temp.path().join("db");
    for dir in [
        root.join("etc/pacman.d/gnupg"),
        db.join("local"),
        db.join("sync"),
        temp.path().join("archives"),
    ] {
        fs::create_dir_all(dir)?;
    }
    fs::write(db.join("local/ALPM_DB_VERSION"), "9\n")?;
    crate::core::paths::set_test_overrides(Some(root.clone()), Some(db.clone()));
    let _reset = ResetPaths;
    let dir: PathBuf = temp.path().join("archives");
    let explicit1 = archive(&dir, "omg-fixture-explicit", "1-1")?;
    let explicit2 = archive(&dir, "omg-fixture-explicit", "2-1")?;
    let promote = archive(&dir, "omg-fixture-promote", "1-1")?;
    let unrelated = archive(&dir, "omg-fixture-unrelated", "1-1")?;
    let requested = archive(&dir, "omg-fixture-requested", "1-1")?;
    let automatic = archive(&dir, "omg-fixture-automatic", "1-1")?;
    use InstallIntent::{Automatic, Requested};
    use alpm::PackageReason::{Depend, Explicit};
    install(&[
        (&explicit1, Requested),
        (&promote, Automatic),
        (&unrelated, Automatic),
    ])?;
    let before = installed(&root, &db)?;
    assert_eq!(
        before,
        vec![
            ("omg-fixture-explicit".into(), "1-1".into(), Explicit),
            ("omg-fixture-promote".into(), "1-1".into(), Depend),
            ("omg-fixture-unrelated".into(), "1-1".into(), Depend),
        ]
    );
    install(&[
        (&requested, Requested),
        (&automatic, Automatic),
        (&explicit2, Automatic),
        (&promote, Requested),
    ])?;
    let after = installed(&root, &db)?;
    assert_eq!(
        after,
        vec![
            ("omg-fixture-automatic".into(), "1-1".into(), Depend),
            ("omg-fixture-explicit".into(), "2-1".into(), Explicit),
            ("omg-fixture-promote".into(), "1-1".into(), Explicit),
            ("omg-fixture-requested".into(), "1-1".into(), Explicit),
            before[2].clone(),
        ]
    );
    let audit_path = Path::new("/var/lib/omg/audit/audit.jsonl");
    let audit_before = fs::read_to_string(audit_path)?.lines().count();
    install(&[(&automatic, Requested), (&explicit2, Automatic)])?;
    let audit_after = fs::read_to_string(audit_path)?;
    let reason_promotion_was_audited = audit_after.lines().count() == audit_before + 2;
    let mut expected = after;
    expected[0].2 = Explicit;
    assert_eq!(installed(&root, &db)?, expected);
    use crate::package_managers::traits::PackageManager;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(
            crate::package_managers::ArchPackageManager::new().install(&[unrelated.handoff()]),
        )?;
    let final_state = installed(&root, &db)?;
    let public_request_is_explicit = final_state
        .iter()
        .any(|(name, _, reason)| name == "omg-fixture-unrelated" && *reason == Explicit);
    assert!(
        reason_promotion_was_audited && public_request_is_explicit,
        "reason-only promotion audited={reason_promotion_was_audited}; public request promoted to explicit={public_request_is_explicit}"
    );
    let borrowed_archive = archive(&dir, "omg-fixture-borrowed", "1-1")?;
    let configuration =
        crate::core::pacman_conf::PacmanConfig::parse(crate::core::paths::pacman_conf_path())?;
    {
        let mut alpm = alpm::Alpm::new(
            root.to_str().context("fixture root")?,
            db.to_str().context("fixture database")?,
        )?;
        crate::package_managers::alpm_ops::register_configured_syncdbs(&alpm, &configuration)?;
        for attempt in 0..2 {
            let audit_before = fs::read_to_string(audit_path)?.lines().count();
            crate::package_managers::execute_transaction(
                vec![borrowed_archive.handoff()],
                crate::package_managers::TransactionKind::Install,
                Some(&mut alpm),
            )?;
            assert_eq!(
                alpm.localdb().pkg("omg-fixture-borrowed")?.reason(),
                Explicit,
                "the borrowed handle must observe its committed requested installation"
            );
            assert_eq!(
                fs::read(root.join("usr/share/omg-fixture/omg-fixture-borrowed"))?,
                b"fixture\n"
            );
            assert_eq!(
                fs::read_to_string(audit_path)?.lines().count(),
                audit_before + if attempt == 0 { 2 } else { 0 },
                "the NEEDED retry must not add a second committed installation or audit pair"
            );
            assert!(
                !db.join("db.lck").exists(),
                "each transaction must release the supplied handle's database lock"
            );
        }
        crate::package_managers::execute_transaction(
            vec!["omg-fixture-borrowed".to_owned()],
            crate::package_managers::TransactionKind::Remove { recursive: false },
            Some(&mut alpm),
        )?;
        assert!(alpm.localdb().pkg("omg-fixture-borrowed").is_err());
    }
    assert_eq!(
        installed(&root, &db)?,
        final_state,
        "borrowed installation, NEEDED retry and removal preserve unrelated packages"
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(
        crate::package_managers::ArchPackageManager::new()
            .remove(&["omg-fixture-requested".to_owned()]),
    )?;
    let mut expected = final_state;
    expected.retain(|(name, _, _)| name != "omg-fixture-requested");
    assert_eq!(installed(&root, &db)?, expected);
    assert!(
        !root
            .join("usr/share/omg-fixture/omg-fixture-requested")
            .exists(),
        "the public asynchronous removal must remove the owned fixture payload"
    );
    for test in [
        "package_managers::aur::client::tests::batch2_native_automatic_dependency_reason",
        CREATION_DENIAL_TEST,
        SEALING_DENIAL_TEST,
    ] {
        assert!(crate::core::testing::run_isolated_test_with_timeout(
            test,
            std::time::Duration::from_secs(5),
        ));
    }
    Ok(())
}
