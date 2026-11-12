use std::fs::{self, File};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use flate2::{Compression, write::GzEncoder};

use super::{InstallIntent, InstallItem, InstallRequest, InstallTarget, execute_handoff};
use crate::core::security::artifact::ArchiveSnapshot;

const TEST: &str =
    "package_managers::arch_install::native_tests::native_installation_preserves_mixed_intents";

fn archive(dir: &Path, name: &str, version: &str) -> Result<ArchiveSnapshot> {
    let path = dir.join(format!("{name}-{version}-any.pkg.tar.gz"));
    let file = File::create(&path)?;
    let mut tar = tar::Builder::new(GzEncoder::new(file, Compression::default()));
    let info = format!(
        "pkgname = {name}\npkgbase = {name}\npkgver = {version}\npkgdesc = inert fixture\nurl = https://example.invalid\nbuilddate = 1\npackager = Fixture\nsize = 8\narch = any\nlicense = MIT\n"
    );
    let buildinfo = format!(
        "format = 2\npkgname = {name}\npkgbase = {name}\npkgver = {version}\npkgarch = any\n"
    );
    for (name, contents) in [
        (".PKGINFO".to_owned(), info.as_bytes()),
        (".BUILDINFO".to_owned(), buildinfo.as_bytes()),
        (".MTREE".to_owned(), b"#mtree\n".as_slice()),
        (
            format!("usr/share/omg-fixture/{name}"),
            b"fixture\n".as_slice(),
        ),
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
    Ok(())
}
