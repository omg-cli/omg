use super::*;

#[tokio::test]
#[ignore = "requires Fedora DNF5 with the installed leaf fixture tree; stores a plan only"]
async fn native_removal_simulation_preserves_installed_inventory() -> Result<()> {
    let manager = DnfPackageManager::new();
    anyhow::ensure!(
        manager.is_installed("tree").await?,
        "installed tree fixture required"
    );
    let before = manager.security_inventory().await?;
    let plan = manager.removal_plan(&["tree".into()]).await?;
    let tree = plan
        .iter()
        .find(|package| package.name == "tree.x86_64")
        .context("tree missing from the native removal plan")?;
    let exact = format!("tree-{}.x86_64", tree.version);
    assert_eq!(manager.removal_plan(&[exact]).await?, plan);
    assert_eq!(manager.security_inventory().await?, before);
    Ok(())
}

#[test]
#[serial_test::serial]
fn removal_preview_directory_ignores_caller_tmpdir() -> Result<()> {
    if crate::core::testing::run_isolated_test(
        "package_managers::dnf::tests::removal_preview_directory_ignores_caller_tmpdir",
    ) {
        return Ok(());
    }
    let caller = tempfile::tempdir()?;
    temp_env::with_var("TMPDIR", Some(caller.path()), || -> Result<()> {
        let directory = DnfPackageManager::removal_preview_directory()?;
        assert_eq!(directory.path().parent(), Some(Path::new("/var/tmp")));
        Ok(())
    })
}

#[test]
#[cfg(unix)]
fn removal_preview_directory_is_private_and_removed_after_use() -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let directory = DnfPackageManager::removal_preview_directory()?;
    let path = directory.path().to_owned();
    let metadata = path.metadata()?;
    assert!(metadata.is_dir());
    assert_eq!(metadata.mode() & 0o777, 0o700);
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    std::fs::write(path.join("transaction.json"), b"private fixture")?;
    drop(directory);
    assert!(!path.exists());
    Ok(())
}

#[test]
#[cfg(unix)]
fn removal_preview_parent_rejects_replaceable_ancestors_and_symlink_targets() -> Result<()> {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = tempfile::Builder::new()
        .prefix("omg-dnf-parent-fixture-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(if is_root() { "/var" } else { "/var/tmp" })?;
    let parent = directory.path().join("parent");
    std::fs::create_dir(&parent)?;
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777))?;
    assert!(DnfPackageManager::trusted_removal_preview_parent(&parent).is_err());
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o1777))?;
    assert_eq!(
        DnfPackageManager::trusted_removal_preview_parent(&parent).is_ok(),
        is_root()
    );
    let child = parent.join("private");
    std::fs::create_dir(&child)?;
    std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700))?;
    // A sticky writable directory is safe only as the final allocation
    // parent, not as an ancestor of a path another user could replace.
    assert!(DnfPackageManager::trusted_removal_preview_parent(&child).is_err());
    let trap = directory.path().join("trap");
    symlink(&child, &trap)?;
    assert!(DnfPackageManager::trusted_removal_preview_parent(&trap).is_err());
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))?;
    assert_eq!(
        DnfPackageManager::trusted_removal_preview_parent(&child).is_ok(),
        is_root()
    );
    if is_root() {
        nix::unistd::chown(&child, Some(nix::unistd::Uid::from_raw(1000)), None)?;
        assert!(DnfPackageManager::trusted_removal_preview_parent(&child).is_err());
    }
    Ok(())
}

#[test]
fn stored_removal_plan_includes_dependents_and_native_identities() {
    let plan = DnfPackageManager::parse_removal_plan(
        br#"{"version":"1.0","rpms":[
        {"nevra":"library-2:1.0-1.fc44.i686","action":"Remove"},
        {"nevra":"application-2.0-1.fc44.x86_64","action":"Remove"}] }"#,
    )
    .unwrap();
    assert_eq!(
        plan,
        vec![
            super::super::types::RemovalPackage {
                name: "application.x86_64".into(),
                version: "2.0-1.fc44".into()
            },
            super::super::types::RemovalPackage {
                name: "library.i686".into(),
                version: "2:1.0-1.fc44".into()
            }
        ]
    );
    for bad in [
        br#"{"version":"2.0","rpms":[]}"#.as_slice(),
        br#"{"version":"1.0","rpms":[{"nevra":"library-1-1.x86_64","action":"Install"}]}"#,
        br#"{"version":"1.0","rpms":[{"nevra":"broken","action":"Remove"}]}"#,
        br#"{"version":"1.0","groups":[{}]}"#,
    ] {
        assert!(DnfPackageManager::parse_removal_plan(bad).is_err());
    }
}

#[test]
fn admission_handoff_accepts_only_fixed_native_modes_and_canonical_comments() {
    let args = |values: &[&str]| {
        values
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
    };
    for values in [
        vec!["install", "-y", "example"],
        vec!["install", "-y", "example-2:1.0~rc1-1.fc44.x86_64"],
        vec!["remove", "--confirm", "example"],
        vec!["remove", "--confirm", "--verbose", "example"],
        vec!["remove", "-y", "example"],
        vec![
            "--comment=omg-550e8400-e29b-41d4-a716-446655440000",
            "remove",
            "-y",
            "example",
        ],
        vec!["--setopt=cacheonly=metadata", "upgrade", "-y"],
        vec![
            "--comment=omg-550e8400-e29b-41d4-a716-446655440000",
            "upgrade",
            "-y",
        ],
    ] {
        assert!(DnfPackageManager::validate_admission_args(&args(&values)).is_ok());
    }
    for values in [
        vec!["replay", "-y", "/tmp/caller-plan"],
        vec!["install", "-y", "--installroot=/tmp/root"],
        vec!["--comment=attacker", "install", "-y", "example"],
        vec!["--setopt=plugins=1", "upgrade", "-y"],
        vec!["--setopt=cacheonly=metadata", "install", "-y", "example"],
        vec!["upgrade", "-y", "unexpected-package"],
        vec!["install", "-y"],
        vec!["install", "-y", "/tmp/local.rpm"],
        vec!["install", "-y", "example-2:1.0-1.fc44.rpm"],
        vec!["remove", "-y"],
        vec!["remove", "-y", "--quiet"],
        vec!["remove", "-y", "--quiet", "--verbose", "example"],
        vec!["remove", "--confirm", "/tmp/caller-plan"],
        vec!["remove", "--dry-run", "example"],
        vec!["remove", "--dry-run", "--quiet", "example"],
        vec!["remove", "--dry-run", "--installroot=/tmp/root"],
        vec!["--setopt=cacheonly=metadata", "remove", "-y", "example"],
        vec![
            "--comment=omg-550e8400-e29b-41d4-a716-446655440000",
            "remove",
            "--dry-run",
            "example",
        ],
    ] {
        assert!(
            DnfPackageManager::validate_admission_args(&args(&values)).is_err(),
            "{values:?}"
        );
    }
}

#[tokio::test]
async fn native_admission_evr_comparisons_preserve_rpm_order_and_batch_association() -> Result<()> {
    let mut pairs = vec![("1.0-1.fc44".to_owned(), "1.0-1.fc44".to_owned()); 129];
    pairs[0] = ("2:1.0-1.fc44".into(), "1:9.9-9.fc44".into());
    pairs[1] = ("1.0~rc1-1.fc44".into(), "1.0-1.fc44".into());
    pairs[2] = ("0:1.0-1.fc44".into(), "1.0-1.fc44".into());
    pairs[3] = ("1.0-2.fc44".into(), "1.0-10.fc44".into());
    pairs[128] = ("1.0^git1-1.fc44".into(), "1.0.1-1.fc44".into());
    let compared = DnfPackageManager::compare_native_evrs(&pairs).await?;
    assert_eq!(compared.len(), 129);
    assert_eq!(&compared[..4], &[1, -1, 0, -1]);
    assert_eq!(compared[128], -1);
    assert!(compared[4..128].iter().all(|value| *value == 0));

    let version = "123456789.".repeat(52);
    let older = format!("{version}1-1.fc44");
    let newer = format!("{version}2-1.fc44");
    let mut larger = vec![(older.clone(), newer.clone()); 129];
    larger[61] = (newer.clone(), older.clone());
    larger[62] = (newer.clone(), newer);
    let mut expected = vec![-1; larger.len()];
    expected[61] = 1;
    expected[62] = 0;
    assert_eq!(
        DnfPackageManager::compare_native_evrs(&larger).await?,
        expected
    );
    assert!(
        DnfPackageManager::compare_native_evrs(&[("1.0\n2.0".into(), "3.0".into())])
            .await
            .is_err()
    );
    Ok(())
}

#[test]
fn proposed_admission_inventory_preserves_solver_dependencies_epochs_and_multilib() -> Result<()> {
    let inventory = DnfPackageManager::proposed_inventory(
        br#"{"version":"1.0","rpms":[
        {"nevra":"app-2:1.0-1.fc44.x86_64","action":"Upgrade"},
        {"nevra":"app-1.0-1.fc44.x86_64","action":"Replaced"},
        {"nevra":"lib-part-0:1.0~rc1-2.fc44.i686","action":"Install"}] }"#,
    )?;
    assert_eq!(inventory.len(), 2);
    assert_eq!(
        (
            &*inventory[0].name,
            &*inventory[0].version,
            inventory[0].architecture.as_deref()
        ),
        ("app", "2:1.0-1.fc44", Some("x86_64"))
    );
    assert_eq!(
        (
            &*inventory[1].name,
            &*inventory[1].version,
            inventory[1].architecture.as_deref()
        ),
        ("lib-part", "0:1.0~rc1-2.fc44", Some("i686"))
    );
    for bytes in [
        br#"{"version":"1.0","rpms":[{"nevra":"x-1-1.noarch","action":"Install"},{"nevra":"x-1-1.noarch","action":"Install"}]}"#.as_slice(),
        br#"{"version":"1.0","rpms":[{"nevra":"x-1-1.noarch","action":"FutureAction"}]}"#,
        br#"{"version":"1.0","rpms":[{"nevra":"broken","action":"Install"}]}"#,
        br#"{"version":"2.0","rpms":[]}"#,
        br#"{"version":"1.0","groups":[{}]}"#,
    ] { assert!(DnfPackageManager::proposed_inventory(bytes).is_err()); }
    Ok(())
}

#[test]
fn rpm_configuration_selects_only_the_configured_sqlite_database() -> Result<()> {
    assert_eq!(
        RpmDatabaseSource::parse(b"sqlite\t/var/lib/rpm archive\n")?,
        Some(PathBuf::from("/var/lib/rpm archive/rpmdb.sqlite"))
    );
    assert!(RpmDatabaseSource::parse(b"ndb\t/var/lib/rpm\n")?.is_none());
    for invalid in [
        b"sqlite\trelative\n".as_slice(),
        b"sqlite\t/one\n/another\n",
        b"sqlite\n",
    ] {
        assert!(RpmDatabaseSource::parse(invalid).is_err());
    }
    Ok(())
}

#[test]
fn stored_admission_evidence_changes_with_archive_metadata_and_path() -> Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::write(root.path().join("transaction.json"), b"plan")?;
    std::fs::write(root.path().join("example.rpm"), b"archive")?;
    let before = DnfPackageManager::stored_tree_digest(root.path())?;
    std::fs::write(root.path().join("example.rpm"), b"changed")?;
    assert_ne!(before, DnfPackageManager::stored_tree_digest(root.path())?);
    std::fs::write(root.path().join("example.rpm"), b"archive")?;
    assert_eq!(before, DnfPackageManager::stored_tree_digest(root.path())?);
    std::fs::rename(
        root.path().join("example.rpm"),
        root.path().join("other.rpm"),
    )?;
    assert_ne!(before, DnfPackageManager::stored_tree_digest(root.path())?);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("transaction.json", root.path().join("replacement"))?;
        assert!(DnfPackageManager::stored_tree_digest(root.path()).is_err());
    }
    Ok(())
}

#[tokio::test]
async fn ordinary_inventory_preserves_epoch_and_multilib_identity() -> Result<()> {
    let make_header = |architecture: &str| {
        let mut data = b"example\0".to_vec();
        data.extend(b"1.0\0");
        data.extend(b"1.fc44\0");
        data.push(0);
        data.extend(2u32.to_be_bytes());
        data.extend(architecture.as_bytes());
        data.push(0);
        strict_header(
            &[
                (1000, 6, 0, 1),
                (1001, 6, 8, 1),
                (1002, 6, 12, 1),
                (1003, 4, 20, 1),
                (1022, 6, 24, 1),
            ],
            &data,
        )
    };
    let amd64 = make_header("x86_64");
    let i686 = make_header("i686");
    let directory = write_packages_db(&[&amd64, &i686]);
    let rpm_db_path = directory.path().join("rpmdb.sqlite");
    let manager = manager_for_database(&rpm_db_path);
    let mut installed = manager.list_installed().await?;
    installed.sort_by(|left, right| left.name.cmp(&right.name));
    assert_eq!(
        installed
            .iter()
            .map(|package| package.name.as_str())
            .collect::<Vec<_>>(),
        ["example.i686", "example.x86_64"]
    );
    assert!(
        installed
            .iter()
            .all(|package| package.version.to_string() == "2:1.0-1.fc44")
    );
    assert!(manager.info("example").await.is_err());
    assert_eq!(
        manager.info("example.i686").await?.unwrap().name,
        "example.i686"
    );
    assert!(manager.is_installed("example.i686").await?);
    assert!(manager.is_installed("example-2:1.0-1.fc44.i686").await?);
    Ok(())
}

#[tokio::test]
async fn installed_catalog_observation_survives_manager_cache_republication() -> Result<()> {
    let native = include_bytes!("../../../tests/data/fedora-publicsuffix.rpmhdr");
    let directory = write_packages_db(&[native.as_slice()]);
    let rpm_db_path = directory.path().join("rpmdb.sqlite");
    let manager = manager_for_database(&rpm_db_path);
    let observed = manager
        .installed_catalog_observation()?
        .expect("SQLite observation available");
    assert!(observed.is_current()?);
    assert_eq!(
        manager.list_installed().await?[0].name,
        "publicsuffix-list-dafsa.noarch"
    );
    let database = Connection::open(&rpm_db_path)?;
    database.execute("DELETE FROM Packages", [])?;
    assert!(manager.list_installed().await?.is_empty());
    assert!(
        !observed.is_current()?,
        "refreshing manager cache must not validate a prior daemon index"
    );
    assert!(
        manager
            .installed_catalog_observation()?
            .expect("replacement observation")
            .is_current()?
    );
    Ok(())
}

#[test]
fn installed_catalog_observation_survives_readonly_wal_permission_reapplication() -> Result<()> {
    let native = include_bytes!("../../../tests/data/fedora-publicsuffix.rpmhdr");
    let directory = write_packages_db(&[native.as_slice()]);
    let rpm_db_path = directory.path().join("rpmdb.sqlite");
    let manager = manager_for_database(&rpm_db_path);
    let database = Connection::open(&rpm_db_path)?;
    database.pragma_update(None, "journal_mode", "WAL")?;
    let observed = manager
        .installed_catalog_observation()?
        .expect("SQLite observation");
    assert!(observed.is_current()?);
    let wal = directory.path().join("rpmdb.sqlite-wal");
    let before = FileIdentity::read(&wal)?.expect("observed WAL");
    std::thread::sleep(std::time::Duration::from_millis(2));
    std::fs::set_permissions(&wal, std::fs::metadata(&wal)?.permissions())?;
    let after = FileIdentity::read(&wal)?.expect("WAL retained");
    assert_eq!(
        (after.device, after.inode, after.size, after.modified),
        (before.device, before.inode, before.size, before.modified)
    );
    assert_ne!(
        after.changed, before.changed,
        "model native SQLite chmod noise"
    );
    assert!(
        observed.is_current()?,
        "reapplying WAL permissions cannot change installed catalogue contents"
    );
    database.execute("DELETE FROM Packages", [])?;
    assert!(
        !observed.is_current()?,
        "a real SQLite commit must still invalidate the observation"
    );
    Ok(())
}

#[test]
fn installed_catalog_observation_rejects_wal_replacement() -> Result<()> {
    let directory = write_packages_db(&[]);
    let rpm_db_path = directory.path().join("rpmdb.sqlite");
    let manager = manager_for_database(&rpm_db_path);
    let database = Connection::open(&rpm_db_path)?;
    database.pragma_update(None, "journal_mode", "WAL")?;
    let observed = manager
        .installed_catalog_observation()?
        .expect("SQLite observation");
    assert!(observed.is_current()?);
    let wal = directory.path().join("rpmdb.sqlite-wal");
    std::fs::rename(&wal, directory.path().join("previous-wal"))?;
    std::fs::File::create(&wal)?;
    assert!(
        !observed.is_current()?,
        "replaced WAL identity cannot certify an old installed inventory"
    );
    Ok(())
}

#[test]
fn installed_catalog_observation_accepts_content_preserving_commits() -> Result<()> {
    for mode in ["DELETE", "WAL"] {
        let native = include_bytes!("../../../tests/data/fedora-publicsuffix.rpmhdr");
        let directory = write_packages_db(&[native.as_slice()]);
        let path = directory.path().join("rpmdb.sqlite");
        let database = Connection::open(&path)?;
        database.pragma_update(None, "journal_mode", mode)?;
        let mut observed = RpmDatabaseObservation::read(&path).expect("SQLite observation");
        database.execute("CREATE TABLE ObservationNoise (revision INTEGER)", [])?;
        database.execute("INSERT INTO ObservationNoise VALUES (1)", [])?;
        let current_generation: i64 =
            observed
                .connection
                .lock()
                .unwrap()
                .query_row("PRAGMA data_version", [], |r| r.get(0))?;
        assert_ne!(
            current_generation, observed.data_version,
            "the content-preserving write must exercise generation invalidation in {mode}"
        );
        // Isolate the generation signal, as with the existing equal-stat
        // commit regression. The installed inventory did not change.
        observed.identity = RpmDatabaseIdentity::read(&path).expect("current identity");
        assert!(
            observed.is_current(&path),
            "unchanged package bytes in {mode}"
        );
        let busy: i64 = database.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?;
        assert_eq!(busy, 0, "observer must release its transaction in {mode}");
    }
    Ok(())
}

#[test]
fn installed_catalog_observation_rejects_changed_rows_at_matching_metadata() -> Result<()> {
    for change in ["blob", "hnum", "schema"] {
        let native = include_bytes!("../../../tests/data/fedora-publicsuffix.rpmhdr");
        let directory = write_packages_db(&[native.as_slice()]);
        let path = directory.path().join("rpmdb.sqlite");
        let database = Connection::open(&path)?;
        database.pragma_update(None, "journal_mode", "WAL")?;
        let mut observed = RpmDatabaseObservation::read(&path).expect("SQLite observation");
        match change {
            "blob" => {
                let mut changed = native.to_vec();
                let last = changed.len() - 2;
                changed[last] ^= 1;
                database.execute("UPDATE Packages SET blob = ?1", [changed])?;
            }
            "hnum" => {
                database.execute("UPDATE Packages SET hnum = hnum + 10", [])?;
            }
            "schema" => {
                database.execute("DROP TABLE Packages", [])?;
            }
            _ => unreachable!(),
        }
        observed.identity = RpmDatabaseIdentity::read(&path).expect("current identity");
        assert!(!observed.is_current(&path), "must reject changed {change}");
    }
    Ok(())
}

#[tokio::test]
async fn native_advisory_identity_excludes_patched_versions_and_other_architectures() {
    use crate::core::security::scan::InstalledIdentity;

    let package = |version: &str, architecture: &str| super::super::types::SecurityPackage {
        origin: crate::package_managers::types::SecurityOrigin::DistributionPackage,
        name: "fixture".into(),
        version: version.into(),
        advisory_source: None,
        architecture: Some(architecture.into()),
        description: String::new(),
        licenses: Vec::new(),
    };
    let row = super::super::dnf_advisory::ApplicableAdvisory {
        name: "FEDORA-fixture".into(),
        kind: "security".into(),
        severity: "Important".into(),
        nevra: "fixture-1:1.0-2.x86_64".into(),
    };
    let installed = vec![
        package("0:99.0-1", "x86_64"),
        package("1:1.0-2", "x86_64"),
        package("1:1.0-3", "x86_64"),
        package("0:99.0-1", "i686"),
    ];
    let other_architecture = super::super::dnf_advisory::ApplicableAdvisory {
        name: "FEDORA-other-architecture".into(),
        kind: "security".into(),
        severity: "Important".into(),
        nevra: "fixture-0:99.0-2.i686".into(),
    };
    let affected = DnfPackageManager::affected_installed_packages(
        [&row, &other_architecture, &row],
        &installed,
        InstalledAdvisoryMatch::Exact,
    )
    .await
    .unwrap();
    assert_eq!(
        affected,
        BTreeMap::from([
            (
                row.nevra.clone(),
                vec![InstalledIdentity::from(&installed[0])]
            ),
            (
                other_architecture.nevra.clone(),
                vec![InstalledIdentity::from(&installed[3])],
            ),
        ])
    );
    assert!(
        DnfPackageManager::affected_installed_packages(
            [&other_architecture, &row],
            &installed[1..],
            InstalledAdvisoryMatch::Exact,
        )
        .await
        .is_err()
    );
    let cross_architecture = super::super::dnf_advisory::ApplicableAdvisory {
        name: "FEDORA-cross-architecture".into(),
        kind: "security".into(),
        severity: "Important".into(),
        nevra: "fixture-1:1.0-2.noarch".into(),
    };
    let possible = DnfPackageManager::affected_installed_packages(
        [&row, &cross_architecture],
        &installed,
        InstalledAdvisoryMatch::ArchitectureChange,
    )
    .await
    .unwrap();
    assert!(possible[&row.nevra].is_empty());
    assert_eq!(
        possible[&cross_architecture.nevra],
        [
            InstalledIdentity::from(&installed[0]),
            InstalledIdentity::from(&installed[3]),
        ]
    );
}

#[tokio::test]
async fn security_inventory_preserves_every_native_rpm_identity() {
    let mut reference = DnfPackageManager::rpm_query_command().unwrap();
    reference.args([
        "-qa",
        "--qf",
        "%{NAME}\t%{ARCH}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n",
    ]);
    let bytes = DnfPackageManager::query_output(reference).await.unwrap();
    // RPM stores imported keys as architecture-less synthetic gpg-pubkey
    // headers. DNF excludes these trust records from software inventory.
    let mut expected: Vec<_> = std::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .filter(|line| !line.starts_with("gpg-pubkey\t(none)\t"))
        .map(str::to_owned)
        .collect();
    let manager = DnfPackageManager::new();
    let packages = manager.security_inventory().await.unwrap();
    let identity = |package: &super::super::types::SecurityPackage| {
        format!(
            "{}\t{}\t{}",
            package.name,
            package.architecture.as_deref().unwrap(),
            package.version
        )
    };
    let mut actual: Vec<_> = packages.iter().map(identity).collect();
    expected.sort();
    actual.sort();
    assert!(
        !expected.is_empty(),
        "native RPM fixture must contain installed packages"
    );
    assert_eq!(
        actual, expected,
        "security inventory lost or changed native identities"
    );

    let records = manager.sbom_inventory().await.unwrap();
    let mut sbom_identities: Vec<_> = records
        .iter()
        .map(|record| identity(&record.package))
        .collect();
    sbom_identities.sort();
    assert_eq!(
        sbom_identities, expected,
        "SBOM inventory lost native identities"
    );
    assert!(
        records
            .iter()
            .any(|record| !record.package.licenses.is_empty())
    );
}

#[test]
fn rpm_sbom_inventory_preserves_quoted_vendor_and_licenses() {
    let inventory = DnfPackageManager::parse_rpm_sbom_inventory(
        b"'gpg-pubkey' '' 0 'public-key' '1' '' 'pubkey'\n\
          'sample' 'x86_64' 2 '1' '4' 'Example'\\''s Vendor' 'MIT OR Apache-2.0'\n\
          'sample' 'i686' 0 '1' '4' '' ''\n",
    )
    .unwrap();
    assert_eq!(inventory.len(), 2);
    assert_eq!(inventory[0].package.version, "2:1-4");
    assert_eq!(inventory[0].rpm_vendor.as_deref(), Some("Example's Vendor"));
    assert_eq!(inventory[0].package.licenses, ["MIT OR Apache-2.0"]);
    assert_eq!(inventory[1].package.architecture.as_deref(), Some("i686"));
    assert!(inventory[1].rpm_vendor.is_none());
    assert!(inventory[1].package.licenses.is_empty());
    for malformed in [
        b"'sample' 'x86_64' 2 '1' '4' 'Vendor'".as_slice(),
        b"'sample' 'x86_64' -2 '1' '4' 'Vendor' 'MIT'",
        b"'sample' 'x86_64' 2 '1' '4' 'Vendor 'MIT'",
    ] {
        assert!(DnfPackageManager::parse_rpm_sbom_inventory(malformed).is_err());
    }
}

#[tokio::test]
async fn native_advisory_and_update_queries_refuse_unavailable_repository() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    std::fs::create_dir(root.join("repos")).unwrap();
    let configure = || {
        let mut command = DnfPackageManager::advisory_command(&root.join("cache")).unwrap();
        command.args([
            format!("--setopt=reposdir={}", root.join("repos").display()),
            format!("--setopt=persistdir={}", root.join("persist").display()),
            format!("--setopt=logdir={}", root.join("logs").display()),
            format!(
                "--repofrompath=omg-fault,file://{}",
                root.join("missing").display()
            ),
            "--setopt=omg-fault.skip_if_unavailable=true".into(),
        ]);
        command
    };
    // Establish the real DNF false-clean behavior before testing our policy.
    let mut permissive = configure();
    permissive.args([
        "--refresh",
        "advisory",
        "list",
        "--available",
        "--security",
        "--json",
    ]);
    let output = DnfPackageManager::query_output(permissive).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output).unwrap(),
        serde_json::json!([])
    );
    let mut strict = configure();
    strict.args(super::super::dnf_advisory::query_args(false));
    let error = DnfPackageManager::query_output(strict).await.unwrap_err();
    assert!(error.to_string().contains("DNF query failed"), "{error:#}");

    let mut upgrades = configure();
    upgrades.env("LC_ALL", "C").args(UPGRADE_QUERY_ARGS);
    let error = DnfPackageManager::query_output(upgrades).await.unwrap_err();
    assert!(error.to_string().contains("DNF query failed"), "{error:#}");

    let mut preview = configure();
    preview
        .env("LC_ALL", "C")
        .args(["--color=never", "--assumeno"])
        .args(CACHED_UPGRADE_PREVIEW_ARGS);
    let output = DnfPackageManager::capture_query(
        "DNF",
        preview,
        std::time::Duration::from_secs(5),
        None,
        false,
    )
    .await
    .unwrap();
    let error = DnfPackageManager::transaction_preview_output(&output).unwrap_err();
    assert!(error.to_string().contains("omg-fault"), "{error:#}");

    let path = root.to_owned();
    fixture.close().unwrap();
    assert!(!path.exists());
}

#[test]
fn update_queries_never_refresh_repository_metadata() {
    for query in [RepositoryQuery::Installed, RepositoryQuery::Unneeded] {
        let args = DnfPackageManager::repository_query_args(query).unwrap();
        assert!(args.iter().any(|arg| arg == "--cacheonly"), "{args:?}");
        assert_eq!(
            args.iter().any(|arg| arg == "--setopt=disable_excludes=*"),
            query == RepositoryQuery::Installed,
            "{args:?}"
        );
    }
    assert!(UPGRADE_QUERY_ARGS.contains(&"--cacheonly"));
    assert!(UPGRADE_QUERY_ARGS.contains(&"--setopt=*.skip_if_unavailable=false"));
    assert!(!UPGRADE_QUERY_ARGS.contains(&"--setopt=disable_excludes=*"));
}

#[test]
fn local_rpm_operands_are_refused_until_they_can_be_sealed() {
    for target in [
        "package.rpm",
        "package.RPM",
        "package.RpM",
        ".rpm",
        "./package.rpm",
        "/tmp/package.rpm",
        "dir/package",
    ] {
        assert!(
            reject_unsealed_local_rpm_targets(&[target.to_owned()]).is_err(),
            "accepted local DNF operand {target:?}"
        );
    }
    assert!(reject_unsealed_local_rpm_targets(&["package-name.x86_64".to_owned()]).is_ok());
}

#[test]
fn installed_sizes_preserve_builds_architectures_epochs_and_large_values() {
    let sizes = DnfPackageManager::parse_installed_sizes(
        b"kernel-core-0:1-1.x86_64\t4294967296\nkernel-core-0:2-1.x86_64\t12\nlib-1:3-1.i686\t0\nlib-1:3-1.x86_64\t8\n",
    ).expect("native size rows");
    assert_eq!(
        sizes,
        vec![
            ("kernel-core-0:1-1.x86_64".to_owned(), 4_294_967_296),
            ("kernel-core-0:2-1.x86_64".to_owned(), 12),
            ("lib-1:3-1.i686".to_owned(), 0),
            ("lib-1:3-1.x86_64".to_owned(), 8),
        ]
    );
    assert!(
        DnfPackageManager::parse_installed_sizes(b"")
            .expect("empty RPM database")
            .is_empty()
    );
}

#[test]
fn installed_sizes_reject_malformed_native_output() {
    for malformed in [
        b"pkg".as_slice(),
        b"\t1",
        b"bad name\t1",
        b"pkg\t-1",
        b"pkg\tNaN",
        b"pkg\t9223372036854775808",
        b"pkg\t1\textra",
        b"pkg\t",
        b"\xff\t1",
        b"pkg\x1b\t1",
    ] {
        assert!(
            DnfPackageManager::parse_installed_sizes(malformed).is_err(),
            "accepted {malformed:?}"
        );
    }
}

#[test]
fn installed_reasons_preserve_native_classifications() {
    let rows = DnfPackageManager::parse_installed_reasons(
        b"a-0:1-1.noarch\tGroup\nb-1:2-1.x86_64\tExternal User\nc-0:3-1.i686\tWeak Dependency\n",
    )
    .expect("native reason rows");
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[1].identity, "b-1:2-1.x86_64");
    assert_eq!(rows[1].reason, "External User");
    assert_eq!(rows[2].reason, "Weak Dependency");
    assert!(
        DnfPackageManager::parse_installed_reasons(b"")
            .expect("empty result")
            .is_empty()
    );
}

#[test]
fn installed_reasons_reject_malformed_rows() {
    for row in [
        b"a".as_slice(),
        b"\tUser",
        b"a\t",
        b"a\t User",
        b"a\tUser\textra",
        b"a\tUser\x1b",
        b"a b\tUser",
        b"\xff\tUser",
    ] {
        assert!(
            DnfPackageManager::parse_installed_reasons(row).is_err(),
            "accepted {row:?}"
        );
    }
}

#[tokio::test]
async fn reverse_reason_query_rejects_option_injection() {
    let error =
        DnfPackageManager::installed_package_reasons(InstalledReasonQuery::RequiredBy("--help"))
            .await
            .expect_err("invalid package operand");
    assert!(error.to_string().contains("cannot start with '-'"));
}

#[test]
fn installed_details_preserve_canonical_names_and_native_versions() {
    let rows = DnfPackageManager::parse_installed_details(
        b"a\t2:1.0-3\ta-2:1.0-3.x86_64\tExternal User\n",
    )
    .expect("native detail row");
    assert_eq!(rows[0].name, "a");
    assert_eq!(rows[0].version, "2:1.0-3");
    assert_eq!(rows[0].identity, "a-2:1.0-3.x86_64");
    assert_eq!(rows[0].reason, "External User");
    for row in [
        b"a\t1\ta\t".as_slice(),
        b"a\t\ta\tUser",
        b"a\t1\ta\tUser\textra",
        b"a\t1\ta\tUser\x1b",
    ] {
        assert!(DnfPackageManager::parse_installed_details(row).is_err());
    }
}

#[test]
fn installed_details_preserve_order_and_distinct_native_reasons() {
    let rows = DnfPackageManager::parse_installed_details(
        b"tree\t2:2.2.1-4.fc44\ttree-2:2.2.1-4.fc44.x86_64\tExternal User\nhelper\t0:1.0-2.fc44\thelper-0:1.0-2.fc44.noarch\tWeak Dependency\n",
    )
    .expect("two native detail rows");
    let payloads = rows
        .iter()
        .map(|row| {
            (
                row.name.as_str(),
                row.version.as_str(),
                row.identity.as_str(),
                row.reason.as_str(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        payloads,
        [
            (
                "tree",
                "2:2.2.1-4.fc44",
                "tree-2:2.2.1-4.fc44.x86_64",
                "External User",
            ),
            (
                "helper",
                "0:1.0-2.fc44",
                "helper-0:1.0-2.fc44.noarch",
                "Weak Dependency",
            ),
        ]
    );
}

#[tokio::test]
async fn test_dnf_manager_creation() {
    let manager = DnfPackageManager::new();
    assert_eq!(manager.name(), "dnf");
}

#[tokio::test]
async fn native_fedora_update_snapshot_has_matching_installed_versions() {
    let installed = DnfPackageManager::parse_versioned_packages(include_bytes!(
        "../../../tests/data/fedora-installed.tsv"
    ))
    .expect("native installed rows");
    let candidates = DnfPackageManager::parse_versioned_packages(include_bytes!(
        "../../../tests/data/fedora-upgrades.tsv"
    ))
    .expect("native upgrade rows");
    assert!(!candidates.is_empty());
    let updates = DnfPackageManager::match_updates(&installed, &candidates)
        .await
        .expect("every native upgrade matches an installed identity");
    assert_eq!(updates.len(), candidates.len());
    for (update, candidate) in updates.iter().zip(&candidates) {
        assert_eq!(update.name, candidate.name);
        assert_eq!(
            update.architecture.as_deref(),
            Some(candidate.architecture.as_str())
        );
        assert_eq!(update.new_version, candidate.version);
        assert_eq!(update.repo, candidate.repository);
    }
}

#[tokio::test]
async fn update_matching_uses_architecture_and_preserves_native_versions() {
    let installed = DnfPackageManager::parse_versioned_packages(
        b"lib\ti686\t1:1-1\t@System\nlib\tx86_64\t1:2-1\t@System\n",
    )
    .expect("installed records");
    let candidates = DnfPackageManager::parse_versioned_packages(
        b"lib\tx86_64\t1:4-1\tupdates\nlib\ti686\t1:3-1\tupdates\n",
    )
    .expect("upgrade records");
    let updates = DnfPackageManager::match_updates(&installed, &candidates)
        .await
        .expect("matched upgrades");
    assert_eq!(updates.len(), 2);
    assert_eq!(updates[0].architecture.as_deref(), Some("x86_64"));
    assert_eq!(updates[1].architecture.as_deref(), Some("i686"));
    assert_eq!(updates[0].old_version, "1:2-1");
    assert_eq!(updates[1].old_version, "1:1-1");
    assert_eq!(updates[0].new_version, "1:4-1");
    assert_eq!(updates[0].repo, "updates");
}

#[tokio::test]
async fn update_matching_accepts_noarch_transitions_and_counts_mirrors_once() -> Result<()> {
    let installed = DnfPackageManager::parse_versioned_packages(
        concat!(
            "lib\tx86_64\t99-1\t@System\n",
            "lib\ti686\t1:1~rc-1\t@System\n",
            "tool\tnoarch\t1-1\t@System\n",
        )
        .as_bytes(),
    )?;
    let candidates = DnfPackageManager::parse_versioned_packages(
        concat!(
            "lib\tnoarch\t1:1-1\tupdates\n",
            "lib\tnoarch\t1:1-1\tmirror\n",
            "tool\tx86_64\t2-1\tupdates\n",
        )
        .as_bytes(),
    )?;

    let updates = DnfPackageManager::match_updates(&installed, &candidates).await?;

    assert_eq!(updates.len(), 2);
    assert_eq!(updates[0].old_version, "1:1~rc-1");
    assert_eq!(updates[0].new_version, "1:1-1");
    assert_eq!(updates[0].repo, "updates");
    assert_eq!(updates[1].old_version, "1-1");
    assert_eq!(updates[1].new_version, "2-1");
    Ok(())
}

#[tokio::test]
async fn update_matching_rejects_unmatched_and_unchanged_candidates() {
    let installed = DnfPackageManager::parse_versioned_packages(b"lib\tx86_64\t1-1\t@System\n")
        .expect("installed");
    let wrong_arch = DnfPackageManager::parse_versioned_packages(b"lib\ti686\t2-1\tupdates\n")
        .expect("candidate");
    assert!(
        DnfPackageManager::match_updates(&installed, &wrong_arch)
            .await
            .is_err()
    );
    assert!(
        DnfPackageManager::match_updates(&installed, &installed)
            .await
            .is_err()
    );
    assert!(
        DnfPackageManager::match_updates(&installed, &[])
            .await
            .expect("no updates")
            .is_empty()
    );
    for malformed in [
        b"lib\tx86_64\t1-1".as_slice(),
        b"lib\t\t1-1\tupdates",
        b"lib\tx86_64\t1-1\tupdates\textra",
        b"lib\tx86_64\t1-1\tup\x1bdates",
    ] {
        assert!(DnfPackageManager::parse_versioned_packages(malformed).is_err());
    }
}

#[test]
fn cached_upgrade_listing_distinguishes_empty_results_from_invalid_data() -> Result<()> {
    let parse = |output| DnfPackageManager::parse_package_listing(output, "Available upgrades");
    assert!(parse(b"\n")?.is_empty());
    let candidate = parse(b"Available upgrades\nlib.compat.noarch   2:1-1   updates\n")?;
    assert_eq!(candidate[0].name, "lib.compat");
    assert_eq!(candidate[0].version, "2:1-1");
    assert_eq!(candidate[0].architecture, "noarch");
    assert_eq!(candidate[0].repository, "updates");
    for invalid in [
        b"Unexpected heading".as_slice(),
        b"Available upgrades\nlib.noarch updates",
        b"Available upgrades\nlib 2:1-1 updates",
        b"Available upgrades\nlib.noarch 2:1-1 up\x1bdates",
    ] {
        assert!(parse(invalid).is_err());
    }
    Ok(())
}

#[tokio::test]
async fn repository_lookup_rejects_option_operands_before_spawning() {
    let error = DnfPackageManager::available_info("--config=untrusted")
        .await
        .expect_err("option-like operand must be rejected");
    assert!(
        error
            .downcast_ref::<crate::core::security::ValidationError>()
            .is_some()
    );
    for query in [
        RepositoryQuery::InstalledSizes(InstalledSizeQuery::Package("--config=untrusted")),
        RepositoryQuery::InstalledSizes(InstalledSizeQuery::RequirementProviders(
            "--config=untrusted",
        )),
        RepositoryQuery::InstalledReasons(InstalledReasonQuery::Package("--config=untrusted")),
        RepositoryQuery::InstalledReasons(InstalledReasonQuery::RequiredBy("--config=untrusted")),
        RepositoryQuery::InstalledDetails("--config=untrusted"),
    ] {
        let error = DnfPackageManager::repository_output(query)
            .await
            .expect_err("invalid operand");
        assert!(
            error
                .downcast_ref::<crate::core::security::ValidationError>()
                .is_some(),
            "{query:?} must reject the operand before resolving DNF: {error:#}"
        );
    }
}

#[test]
fn repository_query_arguments_preserve_reverse_dependency_semantics() -> Result<()> {
    assert_eq!(
        DnfPackageManager::repository_query_args(RepositoryQuery::InstalledReasons(
            InstalledReasonQuery::RequiredBy("bash"),
        ))?,
        [
            "--setopt=disable_excludes=*",
            "repoquery",
            "--installed",
            "--queryformat",
            "%{full_nevra}\t%{reason}\\n",
            "--whatrequires=bash",
        ]
    );
    assert_eq!(
        DnfPackageManager::repository_query_args(RepositoryQuery::InstalledSizes(
            InstalledSizeQuery::RequirementProviders("bash"),
        ))?,
        [
            "--setopt=disable_excludes=*",
            "repoquery",
            "--installed",
            "--queryformat",
            "%{full_nevra}\t%{installsize}\\n",
            "--providers-of=requires",
            "bash",
        ]
    );
    Ok(())
}

#[test]
fn installed_details_query_arguments_preserve_reason_format_and_package() -> Result<()> {
    assert_eq!(
        DnfPackageManager::repository_query_args(RepositoryQuery::InstalledDetails("tree"))?,
        [
            "--setopt=disable_excludes=*",
            "repoquery",
            "--installed",
            "--queryformat",
            "%{name}\t%{evr}\t%{full_nevra}\t%{reason}\\n",
            "tree",
        ]
    );
    Ok(())
}

#[test]
fn available_info_passes_the_exact_selector_without_an_architecture_override() -> Result<()> {
    for selector in ["widget.lib.i686", "widget.lib-0:1.2-3.fc44.i686"] {
        let args =
            DnfPackageManager::repository_query_args(RepositoryQuery::Available(Some(selector)))?;
        assert_eq!(args.last().map(String::as_str), Some(selector));
        assert!(
            !args.iter().any(|arg| arg.starts_with("--arch=")),
            "{args:?}"
        );
    }
    let search = DnfPackageManager::repository_query_args(RepositoryQuery::Available(None))?;
    assert!(search.contains(&format!("--arch={},noarch", std::env::consts::ARCH)));
    Ok(())
}

#[test]
fn available_info_keeps_native_preference_and_accepts_a_unique_multilib_build() -> Result<()> {
    let manager = DnfPackageManager::prefer_available_info;
    let parse = DnfPackageManager::available_info_rows;
    let host = std::env::consts::ARCH;
    let foreign = if host == "i686" { "x86_64" } else { "i686" };
    let foreign_row = format!("widget.lib.{foreign}\t1.2-3.fc44\tupdates\tMultilib package\n");
    let native_row = format!("widget.lib.{host}\t2.0-1.fc44\tupdates\tNative package\n");
    let combined = format!("{foreign_row}{native_row}");
    let selected = manager("widget.lib", parse(combined.as_bytes())?)?
        .pop()
        .context("native build")?
        .package
        .into_package();
    assert_eq!(selected.name, format!("widget.lib.{host}"));
    assert_eq!(selected.version.to_string(), "2.0-1.fc44");

    let selector = format!("widget.lib-0:1.2-3.fc44.{foreign}");
    let selected = manager(&selector, parse(foreign_row.as_bytes())?)?
        .pop()
        .context("explicit build")?
        .package
        .into_package();
    assert_eq!(selected.name, format!("widget.lib.{foreign}"));
    assert!(!selected.installed);
    let independent_row = b"widget.lib.noarch\t2.0-1.fc44\tfedora\tArchitecture-independent\n";
    let mut ambiguous = parse(native_row.as_bytes())?;
    ambiguous.extend(parse(independent_row)?);
    assert!(
        manager("widget.lib", ambiguous)
            .expect_err("multiple default builds are ambiguous")
            .to_string()
            .contains("multiple available builds")
    );
    Ok(())
}

#[test]
fn available_info_uses_the_repository_native_dnf_selected_for_the_exact_build() -> Result<()> {
    let candidates = || {
        let rows = DnfPackageManager::available_info_rows(
            b"widget.lib.noarch\t2:1-1\tfedora\tFirst summary\n\
              widget.lib.noarch\t2:1-1\tupdates\tPreferred\tsummary\n",
        )?;
        DnfPackageManager::prefer_available_info("widget.lib-2:1-1.noarch", rows)
    };
    let native = "Available packages\nwidget.lib.noarch 2:1-1 updates\n";
    let resolved =
        DnfPackageManager::available_info_from_native_selection(candidates()?, native.as_bytes())?;
    assert_eq!(resolved.name, "widget.lib.noarch");
    assert_eq!(resolved.version.to_string(), "2:1-1");
    assert_eq!(resolved.description, "Preferred\tsummary");
    for changed in [
        native.replace("updates", "other"),
        native.replace("2:1-1", "3:1-1"),
    ] {
        assert!(
            DnfPackageManager::available_info_from_native_selection(
                candidates()?,
                changed.as_bytes()
            )
            .is_err()
        );
    }
    let conflicting = DnfPackageManager::available_info_rows(
        b"widget.lib.noarch\t2:1-1\tupdates\tOriginal\n\
          widget.lib.noarch\t2:1-1\tupdates\tConflicting\n",
    )?;
    assert!(
        DnfPackageManager::available_info_from_native_selection(conflicting, native.as_bytes())
            .is_err()
    );
    Ok(())
}

#[test]
fn installed_build_selection_reports_sorted_exact_identities() -> Result<()> {
    let older = "fixture-0:1-1.noarch";
    let newer = "fixture-2:2-1.noarch";
    let select = |builds| {
        DnfPackageManager::select_installed_build(
            "fixture",
            builds,
            std::string::ToString::to_string,
        )
    };
    assert_eq!(select(vec![])?, None);
    assert_eq!(select(vec![newer])?, Some(newer));
    let error = select(vec![newer, older]).unwrap_err().to_string();
    assert!(
        error.ends_with(&format!("\n  {older}\n  {newer}")),
        "{error}"
    );
    let duplicate = select(vec![older, older]).unwrap_err().to_string();
    assert_eq!(
        duplicate,
        format!("RPM reports multiple installed records for '{older}'")
    );
    Ok(())
}

#[test]
fn repository_selectors_preserve_native_rpm_version_characters() -> Result<()> {
    for selector in [
        "widget-0:1.0_git-1.fc43.x86_64",
        "widget-1:2.0^a-1_git.x86_64",
        "widget-name-1:2.0~rc1-1^a.noarch",
        "widget-2.0^a-1_git.x86_64",
    ] {
        let args =
            DnfPackageManager::repository_query_args(RepositoryQuery::Available(Some(selector)))?;
        assert_eq!(args.last().map(String::as_str), Some(selector));
    }
    Ok(())
}

#[test]
fn repository_selectors_preserve_large_unsigned_rpm_epochs() -> Result<()> {
    for selector in [
        "widget-2147483648:2.0^a-1_git.x86_64",
        "widget-4294967295:2.0~rc1-1.fc44.noarch",
    ] {
        let args =
            DnfPackageManager::repository_query_args(RepositoryQuery::Available(Some(selector)))?;
        assert_eq!(args.last().map(String::as_str), Some(selector));
    }
    Ok(())
}

#[tokio::test]
async fn repository_selectors_reject_malformed_native_forms_before_spawning() {
    for selector in [
        "--config=untrusted",
        "widget-:2-1.x86_64",
        "widget-x:2-1.x86_64",
        "widget-1:2:3-1.x86_64",
        "widget-4294967296:2-1.x86_64",
        "widget-1:2-1:9.x86_64",
        "widget-1:2-1./tmp",
        "widget-1:2-1.x86_64\n--config=untrusted",
        "../widget-1:2-1.x86_64",
        "widget-1:2;id-1.x86_64",
    ] {
        DnfPackageManager::available_info(selector)
            .await
            .expect_err("malformed selector must fail before native spawning");
    }
}

#[test]
fn available_repository_rows_preserve_epoch_and_uninstalled_state() {
    let packages =
        DnfPackageManager::parse_available_packages(b"tree\t2:2.2.1-4.fc44\tDirectory listing\n")
            .expect("valid repository row");
    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].name, "tree");
    assert_eq!(packages[0].version.to_string(), "2:2.2.1-4.fc44");
    assert_eq!(packages[0].description, "Directory listing");
    assert!(!packages[0].installed);
}

#[test]
fn available_repository_rows_preserve_official_source_and_complete_payload() {
    let packages = DnfPackageManager::parse_available_packages(
        b"tree.x86_64\t2:2.2.1-4.fc44\tDirectory listing\n",
    )
    .expect("valid official repository row");
    assert_eq!(packages.len(), 1);
    assert_eq!(
        (
            packages[0].name.as_str(),
            packages[0].version.to_string(),
            packages[0].description.as_str(),
            packages[0].source,
            packages[0].installed,
        ),
        (
            "tree.x86_64",
            "2:2.2.1-4.fc44".to_owned(),
            "Directory listing",
            PackageSource::Official,
            false,
        )
    );
}

fn search_catalog_fixture() -> ([InstalledPackage; 2], &'static [u8]) {
    let installed =
        [("widget.lib", "x86_64"), ("widget.local", "noarch")].map(|(name, architecture)| {
            InstalledPackage {
                name: name.to_owned(),
                architecture: architecture.to_owned(),
                version: "1".to_owned(),
                release: "1".to_owned(),
                summary: "Installed summary".to_owned(),
            }
        });
    (
        installed,
        b"widget.lib.x86_64\t2-1\tRepository keyword\n\
          widget.lib.x86_64\t3-1\tAnother repository build\n\
          widget.lib.i686\t2-1\tRepository keyword\n",
    )
}

#[test]
fn search_matches_qualified_identities_and_prefers_installed_rows() {
    assert_eq!(
        DnfPackageManager::repository_query_format(&RepositoryQuery::Available(None)),
        "%{name}.%{arch}\t%{evr}\t%{summary}\\n"
    );
    let (installed_packages, output) = search_catalog_fixture();
    let search = |query| {
        DnfPackageManager::search_results(&installed_packages, output, query)
            .expect("valid repository rows")
            .into_iter()
            .map(|pkg| {
                (
                    pkg.name,
                    pkg.installed,
                    pkg.version.to_string(),
                    pkg.description,
                )
            })
            .collect::<Vec<_>>()
    };
    let installed = (
        "widget.lib.x86_64".to_owned(),
        true,
        "1-1".to_owned(),
        "Installed summary".to_owned(),
    );
    let available = (
        "widget.lib.i686".to_owned(),
        false,
        "2-1".to_owned(),
        "Repository keyword".to_owned(),
    );
    assert_eq!(search("widget.lib"), [available.clone(), installed.clone()]);
    assert_eq!(
        search("widget.lib.x86_64").as_slice(),
        std::slice::from_ref(&installed)
    );
    assert_eq!(search("repository keyword"), [available.clone(), installed]);
    assert_eq!(search("widget.lib.i686"), [available]);
    assert_eq!(
        search("widget.local.noarch"),
        [(
            "widget.local.noarch".to_owned(),
            true,
            "1-1".to_owned(),
            "Installed summary".to_owned(),
        )]
    );
}

#[test]
fn direct_search_preserves_the_first_repository_row_for_a_matching_identity() -> Result<()> {
    let output = "editor.noarch\t1-1\tPreferred repository\n\
                  editor.noarch\t1-2\tÉditeur de texte\n";
    let matches = DnfPackageManager::search_results(&[], output.as_bytes(), "éditeur")?;
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].name, "editor.noarch");
    assert_eq!(matches[0].version.to_string(), "1-1");
    assert_eq!(matches[0].description, "Preferred repository");
    assert!(!matches[0].installed);

    let malformed = "editor.noarch\t1-1\tÉditeur\nmissing-version";
    assert!(DnfPackageManager::search_results(&[], malformed.as_bytes(), "éditeur").is_err());
    Ok(())
}

#[tokio::test]
async fn search_prefers_the_latest_installed_build_without_losing_older_descriptions() -> Result<()>
{
    let installed: Vec<_> = [
        ("x86_64", "1", "2", "Older kernel"),
        ("i686", "2:1", "1", "Higher epoch kernel"),
        ("x86_64", "1", "10", "Latest native kernel"),
        ("x86_64", "1", "3", "Intermediate kernel"),
        ("i686", "1:100", "1", "Old multilib kernel"),
    ]
    .into_iter()
    .map(
        |(architecture, version, release, summary)| InstalledPackage {
            name: "kernel-test".into(),
            version: version.into(),
            release: release.into(),
            architecture: architecture.into(),
            summary: summary.into(),
        },
    )
    .collect();
    let ordered = DnfPackageManager::order_installed_search_builds(&installed).await?;
    let results = DnfPackageManager::search_results(ordered.iter().copied(), b"", "kernel")?;
    let versions = results
        .iter()
        .map(|package| (package.name.as_str(), package.version.to_string()))
        .collect::<Vec<_>>();
    assert_eq!(
        versions,
        [
            ("kernel-test.i686", "2:1-1".into()),
            ("kernel-test.x86_64", "1-10".into())
        ]
    );
    let results = DnfPackageManager::search_results(ordered.iter().copied(), b"", "older kernel")?;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].version.to_string(), "1-10");
    let candidates = DnfPackageManager::search_candidates(ordered, Vec::new());
    assert_eq!(candidates.len(), installed.len());
    assert_eq!(candidates[0].version.to_string(), "1-10");
    Ok(())
}

#[cfg(unix)]
pub(crate) fn search_parity_data(query: &str) -> (Vec<Package>, Vec<Package>) {
    let (installed, output) = search_catalog_fixture();
    let available = DnfPackageManager::parse_available_packages(output).expect("fixture rows");
    let catalog = DnfPackageManager::search_candidates(&installed, available);
    let direct =
        DnfPackageManager::search_results(&installed, output, query).expect("valid search");
    (catalog, direct)
}

#[test]
fn malformed_repository_rows_do_not_become_empty_searches() {
    for row in [
        b"tree".as_slice(),
        b"tree\t\tmissing version",
        b"bad/name\t1-1\tx",
        b"tree\t1-1\t\xff",
    ] {
        assert!(DnfPackageManager::parse_available_packages(row).is_err());
    }
    assert!(
        DnfPackageManager::parse_available_packages(b"")
            .expect("empty repo")
            .is_empty()
    );
}

#[test]
fn repository_query_formats_match_dnf5_row_terminator_contract() {
    // dnf5 passes real TABs through but silently drops a real newline
    // inside --queryformat/--qf, concatenating every row into one.
    // The row terminator must therefore be the two-character `\n`
    // escape; a literal `\t` escape is passed through as text.
    let queries = [
        RepositoryQuery::Available(None),
        RepositoryQuery::Available(Some("tree")),
        RepositoryQuery::Installed,
        RepositoryQuery::Unneeded,
        RepositoryQuery::InstalledSizes(InstalledSizeQuery::All),
        RepositoryQuery::InstalledSizes(InstalledSizeQuery::Package("tree")),
        RepositoryQuery::InstalledReasons(InstalledReasonQuery::Package("tree")),
        RepositoryQuery::InstalledReasons(InstalledReasonQuery::RequiredBy("tree")),
        RepositoryQuery::InstalledDetails("tree"),
    ];
    for query in &queries {
        let format = DnfPackageManager::repository_query_format(query);
        assert!(
            format.contains('\t'),
            "dnf5 needs real TAB separators: {format:?}"
        );
        assert!(
            !format.contains('\n'),
            "dnf5 drops real newlines and concatenates rows: {format:?}"
        );
        assert!(
            format.ends_with("\\n"),
            "dnf5 needs the literal backslash-n row terminator: {format:?}"
        );
        assert!(
            !format.contains("\\t"),
            "dnf5 passes literal backslash-t through as text: {format:?}"
        );
    }
    assert!(
        !DnfPackageManager::USER_INSTALLED_QUERY_FORMAT.contains('\n'),
        "dnf5 drops real newlines and concatenates names"
    );
    assert!(
        DnfPackageManager::USER_INSTALLED_QUERY_FORMAT.ends_with("\\n"),
        "dnf5 needs the literal backslash-n row terminator"
    );
}

#[test]
fn reads_native_fedora_sqlite_header() {
    let blob = include_bytes!("../../../tests/data/fedora-publicsuffix.rpmhdr");
    let directory = write_packages_db(&[blob.as_slice()]);
    let packages = DnfPackageManager::read_rpm_sqlite(&directory.path().join("rpmdb.sqlite"))
        .expect("native Fedora database header must decode");
    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].name, "publicsuffix-list-dafsa");
    assert_eq!(packages[0].version, "20260116");
    assert_eq!(packages[0].release, "1.fc44");
    assert_eq!(
        packages[0].summary,
        "Cross-vendor public domain suffix database in DAFSA form"
    );
}

#[test]
fn rpm_epoch_native_singleton_preserves_version_identity() {
    let native = include_bytes!("../../../tests/data/fedora-xz-libs.rpmhdr");
    let directory = write_packages_db(&[native.as_slice()]);
    let packages = DnfPackageManager::read_rpm_sqlite(&directory.path().join("rpmdb.sqlite"))
        .expect("unmodified native RPM EPOCH singleton must decode");
    assert_eq!(packages.len(), 1);
    assert_eq!(
        (
            packages[0].name.as_str(),
            packages[0].version.as_str(),
            packages[0].release.as_str(),
            packages[0].architecture.as_str()
        ),
        ("xz-libs", "1:5.8.2", "2.fc44", "x86_64")
    );
}

#[test]
fn rpm_epoch_inventory_rejects_native_identity_with_wrong_schema() {
    let native = include_bytes!("../../../tests/data/fedora-xz-libs.rpmhdr");
    let entries = u32::from_be_bytes(native[..4].try_into().unwrap()) as usize;
    let entry = (8..8 + entries * 16)
        .step_by(16)
        .find(|&offset| {
            u32::from_be_bytes(native[offset..offset + 4].try_into().unwrap()) == rpm_tags::EPOCH
        })
        .expect("native fixture contains EPOCH");
    assert_eq!(
        u32::from_be_bytes(native[entry + 4..entry + 8].try_into().unwrap()),
        4
    );
    assert_eq!(
        u32::from_be_bytes(native[entry + 12..entry + 16].try_into().unwrap()),
        1
    );
    // Preserve the same four payload bytes, changing only type/count.
    // librpm rejects the BIN/INT16/INT8 variants in the retained native
    // probe; empty and array epochs also violate the singleton schema.
    for (kind, count) in [(7u32, 4u32), (3, 2), (2, 4), (4, 0), (4, 2)] {
        let mut changed = native.to_vec();
        changed[entry + 4..entry + 8].copy_from_slice(&kind.to_be_bytes());
        changed[entry + 12..entry + 16].copy_from_slice(&count.to_be_bytes());
        let directory = write_packages_db(&[changed.as_slice()]);
        assert!(
            DnfPackageManager::read_rpm_sqlite(&directory.path().join("rpmdb.sqlite")).is_err(),
            "inventory accepted EPOCH type {kind} count {count}"
        );
    }
}

#[test]
fn rpm_inventory_rejects_identity_tags_declared_as_binary() {
    let native = include_bytes!("../../../tests/data/fedora-publicsuffix.rpmhdr");
    for tag in [
        rpm_tags::NAME,
        rpm_tags::VERSION,
        rpm_tags::RELEASE,
        rpm_tags::ARCH,
    ] {
        let mut blob = native.to_vec();
        let count = u32::from_be_bytes(blob[..4].try_into().unwrap()) as usize;
        let data_start = 8 + count * 16;
        let entry = (8..data_start)
            .step_by(16)
            .find(|&offset| u32::from_be_bytes(blob[offset..offset + 4].try_into().unwrap()) == tag)
            .expect("native fixture contains identity tag");
        let offset = u32::from_be_bytes(blob[entry + 8..entry + 12].try_into().unwrap()) as usize;
        let length = blob[data_start + offset..]
            .iter()
            .position(|&byte| byte == 0)
            .unwrap();
        blob[entry + 4..entry + 8].copy_from_slice(&7_u32.to_be_bytes());
        blob[entry + 12..entry + 16].copy_from_slice(&(length as u32).to_be_bytes());
        let directory = write_packages_db(&[blob.as_slice()]);
        let result = DnfPackageManager::read_rpm_sqlite(&directory.path().join("rpmdb.sqlite"));
        assert!(
            result.is_err(),
            "binary tag {tag} must not enter installed inventory: {result:?}"
        );
    }
    let directory = write_packages_db(&[native.as_slice()]);
    let packages = DnfPackageManager::read_rpm_sqlite(&directory.path().join("rpmdb.sqlite"))
        .expect("unmodified native header remains valid");
    assert_eq!(packages[0].name, "publicsuffix-list-dafsa");
    assert_eq!(packages[0].architecture, "noarch");
}

#[tokio::test]
async fn native_update_history_requires_a_system_wide_operation() {
    use crate::core::history::TransactionType;
    let manager = DnfPackageManager::new();
    assert!(
        manager
            .transact_with_history(TransactionType::Update, &[], None)
            .is_some()
    );
    let packages = vec!["tree".to_owned()];
    let operation = manager
        .transact_with_history(TransactionType::Update, &packages, None)
        .expect("native update capability");
    assert!(
        operation
            .await
            .unwrap_err()
            .to_string()
            .contains("do not accept package operands")
    );
}

#[test]
fn cached_update_reuses_metadata_but_allows_package_downloads() {
    assert_eq!(
        DnfPackageManager::cached_update_args(),
        ["--setopt=cacheonly=metadata", "upgrade", "-y"]
    );
}

#[test]
fn fresh_dnf_history_requires_absence_at_the_effective_location() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let config = format!(
        "[main]\ninstallroot = /\ntransaction_history_dir = {}\n",
        directory.path().display()
    );
    assert!(DnfPackageManager::history_is_missing(&config)?);
    std::fs::write(
        directory.path().join(DNF_HISTORY_DATABASE),
        b"unreadable journal format",
    )?;
    assert!(!DnfPackageManager::history_is_missing(&config)?);
    for invalid in [
        format!("{config}transaction_history_dir = /other"),
        config.replace("installroot = /", "installroot = /other"),
        "installroot = /\ntransaction_history_dir = relative".into(),
    ] {
        assert!(DnfPackageManager::history_is_missing(&invalid).is_err());
    }
    Ok(())
}

#[test]
fn native_history_correlates_only_our_transaction() {
    let mut transactions: Vec<NativeTransaction> = serde_json::from_str(r#"[
        {"id":1,"comment":"ours","status":"Ok","packages":[{"nevra":"tree-0:2.2.1-4.fc44.x86_64","action":"Install"}]},
        {"id":2,"comment":"someone-else","status":"Ok","packages":[{"nevra":"unrelated","action":"Future Action"}]}
    ]"#).expect("native history fixture");
    let NativeOutcome::Committed(changes) =
        DnfPackageManager::native_outcome(&transactions, "ours").expect("matching transaction")
    else {
        panic!("expected committed transaction");
    };
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].name, "tree");
    assert_eq!(changes[0].new_version.as_deref(), Some("0:2.2.1-4.fc44"));
    assert!(matches!(
        DnfPackageManager::native_outcome(&transactions, "no-op").unwrap(),
        NativeOutcome::NoTransaction
    ));
    transactions[1].comment = "ours".to_owned();
    assert!(DnfPackageManager::native_outcome(&transactions, "ours").is_err());
}

#[test]
fn native_history_pairs_versions_by_name_and_architecture() {
    let packages: Vec<NativeTransactionPackage> = serde_json::from_str(
        r#"[
        {"nevra":"a-b-2:1-1.x86_64","action":"Replaced"},
        {"nevra":"a-b-2:2-1.x86_64","action":"Upgrade"},
        {"nevra":"a-b-2:3-1.i686","action":"Install"}
    ]"#,
    )
    .unwrap();
    let changes = DnfPackageManager::native_changes(&packages).unwrap();
    assert_eq!(changes.len(), 2);
    let upgrade = changes
        .iter()
        .find(|change| change.old_version.is_some())
        .unwrap();
    assert_eq!(upgrade.name, "a-b");
    assert_eq!(upgrade.architecture.as_deref(), Some("x86_64"));
    assert_eq!(upgrade.old_version.as_deref(), Some("2:1-1"));
    assert_eq!(upgrade.new_version.as_deref(), Some("2:2-1"));
    assert_eq!(upgrade.source, "dnf");
    let install = changes
        .iter()
        .find(|change| change.old_version.is_none())
        .unwrap();
    assert_eq!(install.display_name(), "a-b.i686");
    assert_eq!(install.new_version.as_deref(), Some("2:3-1"));
    for package in [
        NativeTransactionPackage {
            nevra: "broken".to_owned(),
            action: "Install".to_owned(),
        },
        NativeTransactionPackage {
            nevra: "a-0:1-1.noarch".to_owned(),
            action: "Future Action".to_owned(),
        },
    ] {
        assert!(DnfPackageManager::native_changes(&[package]).is_err());
    }
}

#[test]
fn native_unresolved_transaction_reports_recorded_identity() {
    // libdnf5 marks a transaction STARTED when it is inserted and only
    // updates it from finish(OK|ERROR); the observed Fedora failure left
    // such a row behind (run 36204199869). The error must carry the
    // recorded identity instead of only the status word.
    let transactions: Vec<NativeTransaction> = serde_json::from_str(r#"[{"id":41,"comment":"omg-fixture","status":"Started","description":"/usr/bin/dnf5 --comment=omg-fixture remove --yes tree-2.2.1-4.fc44","packages":[{"nevra":"tree-0:2.2.1-4.fc44.x86_64","action":"Remove"}]}]"#).expect("native history fixture");
    // The recorded identity is carried to the final diagnostic without
    // replaying the interrupted transaction.
    match DnfPackageManager::native_outcome(&transactions, "omg-fixture")
        .expect("an unfinished transaction is reported as Interrupted")
    {
        NativeOutcome::Interrupted {
            id,
            comment,
            status,
            actions,
            command,
        } => {
            assert_eq!(comment, "omg-fixture");
            assert_eq!(id, 41, "{status} {actions} {command}");
            assert_eq!(status, "Started");
            assert_eq!(actions, 1, "package action count must be preserved");
            assert_eq!(
                command, "/usr/bin/dnf5 --comment=omg-fixture remove --yes tree-2.2.1-4.fc44",
                "the recorded command must be preserved for the failure report"
            );
        }
        other => panic!("expected Interrupted, got {other:?}"),
    }
    let without_command: Vec<NativeTransaction> = serde_json::from_str(
        r#"[{"id":7,"comment":"omg-fixture","status":"Started","packages":[]}]"#,
    )
    .expect("fixture without description");
    match DnfPackageManager::native_outcome(&without_command, "omg-fixture")
        .expect("a missing description must still be Interrupted")
    {
        NativeOutcome::Interrupted { id, command, .. } => {
            assert_eq!(id, 7);
            assert_eq!(
                command, "not recorded",
                "a missing description must not hide the failure"
            );
        }
        other => panic!("expected Interrupted, got {other:?}"),
    }
}

#[test]
fn native_interruption_preserves_prior_committed_history() -> Result<()> {
    use crate::core::history::{HistoryManager, PackageChange, Transaction, TransactionType};

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("history.json");
    let history = HistoryManager::new_in(&path)?;
    let prior = Transaction {
        id: "prior-install-001".to_owned(),
        timestamp: "2026-01-01T00:00:00Z".parse()?,
        transaction_type: TransactionType::Install,
        changes: vec![PackageChange {
            architecture: None,
            name: "tree".to_owned(),
            old_version: None,
            new_version: Some("2.2.1-4.fc44".to_owned()),
            source: "fedora".to_owned(),
        }],
        success: true,
    };
    history.save(std::slice::from_ref(&prior))?;
    let before = std::fs::read(&path)?;
    let transactions: Vec<NativeTransaction> = serde_json::from_str(
        r#"[{"id":41,"comment":"omg-started-preservation","status":"Started","description":"dnf remove tree","packages":[{"nevra":"tree-0:2.2.1-4.fc44.x86_64","action":"Remove"}]}]"#,
    )?;

    let error = DnfPackageManager::record_native_result(
        TransactionType::Remove,
        &history,
        Err(anyhow::anyhow!("original exit 1")),
        DnfPackageManager::native_outcome(&transactions, "omg-started-preservation"),
    )
    .expect_err("a Started removal must remain unresolved");
    let diagnostic = format!("{error:#}");
    for expected in [
        "original exit 1",
        "transaction 41",
        "comment 'omg-started-preservation'",
        "Started",
        "inspect native DNF history and package state before deciding on recovery",
    ] {
        assert!(
            diagnostic.contains(expected),
            "missing {expected}: {diagnostic}"
        );
    }
    assert_eq!(
        std::fs::read(&path)?,
        before,
        "an interrupted removal must preserve previously committed history bytes"
    );
    let reopened = HistoryManager::new_in(&path)?;
    assert_eq!(
        reopened.load()?,
        vec![prior],
        "prior committed history must survive reopening without a new removal record"
    );
    Ok(())
}

#[test]
fn native_interruption_is_diagnostic_only_and_preserves_operation_error() {
    let directory = tempfile::tempdir().unwrap();
    let history =
        crate::core::history::HistoryManager::new_in(directory.path().join("history.json"))
            .unwrap();
    let transactions: Vec<NativeTransaction> = serde_json::from_str(
        r#"[{"id":41,"comment":"ours","status":"Started","description":"dnf remove tree","packages":[]},
            {"id":42,"comment":"","status":"Ok","description":"dnf history redo 41","packages":[]}]"#,
    ).unwrap();
    let result = DnfPackageManager::record_native_result(
        crate::core::history::TransactionType::Remove,
        &history,
        Err(anyhow::anyhow!("original exit 1").context("DNF child failed")),
        DnfPackageManager::native_outcome(&transactions, "ours"),
    )
    .unwrap_err()
    .to_string();
    for expected in [
        "original exit 1",
        "41",
        "comment 'ours'",
        "Started",
        "0 package action(s)",
        "dnf remove tree",
        "Automatic recovery was not attempted",
    ] {
        assert!(result.contains(expected), "missing {expected}: {result}");
    }
    assert!(
        !result.contains("retry manually"),
        "must not advise blind replay: {result}"
    );
    assert!(
        history.load().unwrap().is_empty(),
        "Started is not committed history"
    );
    let result = DnfPackageManager::record_native_result(
        crate::core::history::TransactionType::Remove,
        &history,
        Ok(()),
        DnfPackageManager::native_outcome(&transactions, "ours"),
    )
    .unwrap_err();
    assert!(format!("{result:#}").contains("Automatic recovery was not attempted"));
    assert!(history.load().unwrap().is_empty());
}

#[test]
fn native_result_selection_keeps_journal_and_command_outcomes_separate() {
    use crate::core::history::{HistoryManager, PackageChange, TransactionType};
    let directory = tempfile::tempdir().unwrap();
    let history = HistoryManager::new_in(directory.path().join("history.json")).unwrap();
    let result = DnfPackageManager::record_native_result;
    let committed_changes = vec![PackageChange {
        architecture: None,
        name: "tree".into(),
        old_version: Some("0:2.2.1-4.fc44".into()),
        new_version: None,
        source: "dnf".into(),
    }];
    assert_eq!(
        result(
            TransactionType::Remove,
            &history,
            Ok(()),
            Ok(NativeOutcome::NoTransaction),
        )
        .unwrap(),
        0
    );
    assert!(
        history.load().unwrap().is_empty(),
        "no-op must not invent history"
    );
    let error = result(
        TransactionType::Remove,
        &history,
        Ok(()),
        Ok(NativeOutcome::Failed),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("failed journal transaction after command success"));
    assert!(!history.load().unwrap()[0].success);
    let error = result(
        TransactionType::Remove,
        &history,
        Err(anyhow::anyhow!("original error")),
        Ok(NativeOutcome::Committed(committed_changes.clone())),
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "original error",
        "a committed journal row is not recovery of a command error"
    );
    let entries = history.load().unwrap();
    assert_eq!(entries.len(), 2);
    assert!(
        entries[1].success,
        "record native commitment honestly despite command error"
    );
    let reopened = HistoryManager::new_in(directory.path().join("history.json"))
        .unwrap()
        .load()
        .unwrap();
    assert_eq!(reopened[1].changes, committed_changes);
    assert_eq!(reopened[1].transaction_type, TransactionType::Remove);
    for operation in [Ok(()), Err(anyhow::anyhow!("original error"))] {
        let error = result(
            TransactionType::Remove,
            &history,
            operation,
            Err(anyhow::anyhow!("invalid journal")),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("invalid journal"));
    }
    assert_eq!(
        history.load().unwrap().len(),
        2,
        "invalid journal must not invent changes"
    );
    let count = result(
        TransactionType::Update,
        &history,
        Ok(()),
        Ok(NativeOutcome::Committed(committed_changes)),
    )
    .unwrap();
    assert_eq!(count, history.load().unwrap()[2].changes.len());
    assert_eq!(count, 1);
}

#[tokio::test]
async fn native_history_query_is_noninteractive_and_bounded() {
    use std::io::{Seek, Write};
    let mut command = tokio::process::Command::new("/bin/sh");
    command.args(["-c", "if read line; then exit 9; fi; printf '[]'"]);
    let mut input = tempfile::tempfile().unwrap();
    input.write_all(b"caller input\n").unwrap();
    input.rewind().unwrap();
    command.stdin(std::process::Stdio::from(input));
    assert_eq!(
        DnfPackageManager::query_output(command).await.unwrap(),
        b"[]"
    );
    let mut command = tokio::process::Command::new("/bin/sh");
    // exec avoids a surviving shell descendant; no native DNF or sudo runs.
    command.args(["-c", "exec sleep 30"]);
    let started = std::time::Instant::now();
    let error = DnfPackageManager::query_output_with_deadline(
        command,
        std::time::Duration::from_millis(100),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("DNF query timed out"));
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    let mut command = tokio::process::Command::new("/bin/sh");
    command.args(["-c", "printf '[]'; exit 7"]);
    assert!(
        DnfPackageManager::query_output(command)
            .await
            .unwrap_err()
            .to_string()
            .contains("DNF query failed")
    );
}

#[tokio::test]
async fn native_command_does_not_wait_for_descendants_stderr() -> Result<()> {
    let fixture = tempfile::tempdir()?;
    let pid_file = fixture.path().join("child.pid");
    let mut command = std::process::Command::new("/bin/sh");
    command
        .args([
            "-c",
            "sleep 10 & printf '%s\\n' \"$!\" > \"$1\"; exit 7",
            "--",
        ])
        .arg(&pid_file);
    let status = tokio::time::timeout(
        std::time::Duration::from_secs(4),
        tokio::task::spawn_blocking(move || DnfPackageManager::run_native_command(command, false)),
    )
    .await;
    let child_pid: i32 = std::fs::read_to_string(pid_file)?.trim().parse()?;
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child_pid),
        nix::sys::signal::Signal::SIGTERM,
    );
    assert_eq!(
        status
            .context("DNF did not return after the owned command exited")???
            .code(),
        Some(7)
    );
    Ok(())
}

#[test]
fn native_cache_cleanup_reports_partial_dnf_failures() -> Result<()> {
    let run = |script: &str, cache_cleanup| {
        let mut command = std::process::Command::new("/bin/sh");
        command.args(["-c", script]);
        DnfPackageManager::run_native_command(command, cache_cleanup)
    };
    let summary =
        "printf '%s\\n' 'Removed 1 files, 1 directories (total of 8 B). 2 errors occurred.'";
    let repository = "printf '%s\\n' 'Failed to cleanup repository cache in path fixture' >&2";
    for script in [summary, repository] {
        assert_eq!(
            run(script, true).unwrap_err().to_string(),
            "DNF reported package cache cleanup errors"
        );
    }
    assert!(run(summary, false)?.success());
    assert!(
        run(
            "printf '%s\\n' 'Removed 1 files, 1 directories (total of 8 B). 0 errors occurred.'",
            true,
        )?
        .success()
    );
    assert_eq!(run(&format!("{repository}; exit 7"), true)?.code(), Some(7));

    let incomplete = "(sleep 2) & exit 0";
    let error = run(incomplete, true).expect_err("cleanup requires complete native diagnostics");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    Ok(())
}

#[tokio::test]
async fn captured_query_drains_diagnostics_and_preserves_failure_reason() -> Result<()> {
    let mut verbose = tokio::process::Command::new("/bin/sh");
    verbose
        .stderr(std::process::Stdio::piped())
        .args(["-c", "head -c 131072 /dev/zero >&2 && printf '[]'"]);
    let deadline = std::time::Duration::from_secs(5);
    assert_eq!(
        DnfPackageManager::query_output_with_deadline(verbose, deadline).await?,
        b"[]"
    );

    let mut failed = tokio::process::Command::new("/bin/sh");
    failed.stderr(std::process::Stdio::piped()).args([
        "-c",
        "yes 'Loading repositories' | head -n 4000 >&2; \
         printf 'Repository is unavailable\n' >&2; exit 7",
    ]);
    let error = DnfPackageManager::query_output(failed).await.unwrap_err();
    assert!(error.to_string().ends_with("Repository is unavailable"));

    let mut preview = tokio::process::Command::new("/bin/sh");
    preview.args([
        "-c",
        "printf 'Removing:\n leaf noarch 0:1-1\n'; \
         yes 'Loading repositories' | head -n 4000 >&2; \
         printf 'Operation aborted by the user.\n' >&2; exit 1",
    ]);
    let preview = DnfPackageManager::capture_query("DNF", preview, deadline, None, false).await?;
    assert!(preview.stderr.len() <= 64 * 1024);
    let preview = DnfPackageManager::transaction_preview_output(&preview)?;
    assert!(preview.has_changes);
    assert_eq!(preview.plan, "Removing:\n leaf noarch 0:1-1\n");

    let mut authenticated_mirror = tokio::process::Command::new("/bin/sh");
    authenticated_mirror.stderr(std::process::Stdio::piped()).args([
        "-c",
        "printf '%s\n' 'Failed to load repository example: \"https://fixture-user:fixture-pass@mirror.example/repo?secret=fixture-token#fixture-fragment\"' >&2; exit 7",
    ]);
    let error = DnfPackageManager::query_output(authenticated_mirror)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("repository example"), "{error}");
    assert!(error.contains("https://mirror.example/repo"), "{error}");
    assert!(!error.contains("fixture-"), "{error}");

    let mut over_budget = tokio::process::Command::new("/bin/sh");
    over_budget.args([
        "-c",
        "printf '%s\n%s' 'Repository example refused' 'https://fixture-user:fixture-pass' >&2; head -c 65536 /dev/zero >&2; printf '@mirror.example\n' >&2; exit 7",
    ]);
    let error = DnfPackageManager::query_output(over_budget)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.ends_with("Repository example refused"), "{error}");
    Ok(())
}

#[cfg(unix)]
#[test]
fn orphan_cleanup_preview_preserves_plan_and_protected_package_diagnostics() -> Result<()> {
    use std::os::unix::process::ExitStatusExt as _;

    let output = |code, stdout: &str, stderr: &str| std::process::Output {
        status: std::process::ExitStatus::from_raw(code << 8),
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
    };
    let preview = DnfPackageManager::transaction_preview_output;
    let protected = "Unneeded protected package: leaf-0:1-1.noarch";
    let no_changes = preview(&output(0, "Nothing to do.\n", protected))?;
    assert!(!no_changes.has_changes);
    assert_eq!(no_changes.plan, "Nothing to do.\n");
    assert_eq!(no_changes.diagnostics, protected);

    let plan = "Removing:\n leaf noarch 0:1-1\n";
    let abort = "Operation aborted by the user.\n";
    let diagnostics = format!("{protected}\n{abort}");
    let declined = preview(&output(1, plan, &diagnostics))?;
    assert!(declined.has_changes);
    assert_eq!(declined.plan, plan);
    assert_eq!(declined.diagnostics, protected);

    for failure in [
        output(7, plan, abort),
        output(1, "", abort),
        output(1, plan, "Failed to resolve the transaction\n"),
        output(1, plan, &format!("Invalid diagnostic: {abort}")),
    ] {
        assert!(preview(&failure).is_err());
    }
    let failure = preview(&output(
        1,
        "",
        "Failed to resolve the transaction\nNo match for argument: package\n  --skip-unavailable to skip unavailable packages\n",
    ))
    .expect_err("an unresolved request must fail the preview")
    .to_string();
    assert!(failure.contains("No match for argument: package"));
    assert!(failure.contains("--skip-unavailable"));

    let mirror = "https://fixture-user:fixture-pass@mirror.example/repo?secret=fixture-token";
    let message = format!("Repository example ({mirror})");
    let failed_preview = preview(&output(7, "", &message)).unwrap_err().to_string();
    let declined = preview(&output(
        1,
        &format!("{message}\n"),
        &format!("{message}\n{abort}"),
    ))?;
    for text in [failed_preview, declined.plan, declined.diagnostics] {
        assert!(text.contains("https://mirror.example/repo"), "{text}");
        assert!(!text.contains("fixture-"), "{text}");
    }
    Ok(())
}

#[tokio::test]
async fn stored_query_cancellation_reaps_child_before_removing_private_namespace() -> Result<()> {
    let control = tempfile::tempdir()?;
    let directory = tempfile::Builder::new()
        .prefix("owned-store-")
        .tempdir_in(control.path())?;
    let path = directory.path().to_owned();
    let pid_file = control.path().join("query.pid");
    let mut command = tokio::process::Command::new("/bin/sh");
    command
        .args(["-c", "printf '%s' \"$$\" > \"$1\"; exec sleep 30", "--"])
        .arg(&pid_file);
    let task = tokio::spawn(DnfPackageManager::owned_stored_transaction(
        command,
        directory,
        std::time::Duration::from_mins(1),
    ));
    let started = std::time::Instant::now();
    while !pid_file.exists() {
        anyhow::ensure!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "owned query did not start"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let pid = nix::unistd::Pid::from_raw(std::fs::read_to_string(&pid_file)?.parse()?);
    assert!(
        path.is_dir(),
        "query must retain its private input namespace"
    );
    task.abort();
    assert!(task.await.is_err());
    while path.exists() {
        anyhow::ensure!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "cancelled owner failed to settle"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        nix::sys::signal::kill(pid, None),
        Err(nix::errno::Errno::ESRCH),
        "namespace disappeared before its child was reaped"
    );
    Ok(())
}

#[tokio::test]
async fn native_query_timeout_reaps_child_before_returning() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let pid_file = directory.path().join("query.pid");
    let mut command = tokio::process::Command::new("/bin/sh");
    command
        .args(["-c", "printf '%s' \"$$\" > \"$1\"; exec sleep 30", "--"])
        .arg(&pid_file);
    let error = DnfPackageManager::query_output_with_deadline(
        command,
        std::time::Duration::from_millis(200),
    )
    .await
    .expect_err("query must time out");
    assert!(error.to_string().contains("DNF query timed out"));
    let pid = nix::unistd::Pid::from_raw(std::fs::read_to_string(pid_file)?.parse()?);
    assert_eq!(
        nix::sys::signal::kill(pid, None),
        Err(nix::errno::Errno::ESRCH)
    );
    Ok(())
}

#[tokio::test]
async fn stored_query_accepts_a_missing_manifest_only_for_native_noop() -> Result<()> {
    for (script, no_changes) in [
        ("printf 'Nothing to do.\\n'", true),
        (
            "printf 'Package Arch Version Repository Size\\nSkipping packages with broken dependencies:\\n package noarch 2-1 test 7 B\\n\\nNothing to do.\\n'",
            true,
        ),
        ("printf 'Preparing transaction\\n'", false),
        ("printf 'Nothing to do.\\nPreparing transaction\\n'", false),
        ("printf 'Warning: Nothing to do.\\n'", false),
        ("printf 'Nothing to do.\\n'; exit 1", false),
        (
            "mkdir \"$1/transaction.json\"; printf 'Nothing to do.\\n'",
            false,
        ),
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().to_owned();
        let mut command = tokio::process::Command::new("/bin/sh");
        command.args(["-c", script, "--"]).arg(&path);
        let result = DnfPackageManager::owned_stored_transaction(
            command,
            directory,
            std::time::Duration::from_secs(5),
        )
        .await;
        if no_changes {
            assert!(result?.is_none());
        } else {
            assert!(result.is_err(), "{script}");
        }
        assert!(!path.exists(), "{script}");
    }
    Ok(())
}

#[tokio::test]
async fn stored_query_returns_owned_namespace_and_exact_manifest_after_child_exit() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().to_owned();
    let mut command = tokio::process::Command::new("/bin/sh");
    command
        .args([
            "-c",
            "printf 'stored bytes' > \"$1/transaction.json\"; printf 'query output'",
            "--",
        ])
        .arg(&path);
    let (directory, bytes) = DnfPackageManager::owned_stored_transaction(
        command,
        directory,
        std::time::Duration::from_secs(5),
    )
    .await?
    .context("expected a stored transaction")?;
    assert_eq!(bytes, b"stored bytes");
    assert!(path.is_dir());
    drop(directory);
    assert!(!path.exists());
    Ok(())
}

#[tokio::test]
async fn native_history_query_rejects_output_larger_than_64_mib() -> Result<()> {
    let mut command = tokio::process::Command::new("/usr/bin/head");
    command.args(["-c", "67108864", "/dev/zero"]);
    let bytes =
        DnfPackageManager::query_output_with_deadline(command, std::time::Duration::from_secs(30))
            .await?;
    assert_eq!(bytes.len(), 67_108_864);
    assert!(
        bytes.iter().all(|byte| *byte == 0),
        "the accepted boundary payload must contain only zero bytes"
    );
    drop(bytes);

    let mut command = tokio::process::Command::new("/usr/bin/head");
    command.args(["-c", "67108865", "/dev/zero"]);
    match DnfPackageManager::query_output_with_deadline(command, std::time::Duration::from_secs(30))
        .await
    {
        Ok(bytes) => panic!(
            "DNF query accepted oversized output: received {} bytes",
            bytes.len()
        ),
        Err(error) => assert_eq!(error.to_string(), "DNF query output exceeds 64 MiB"),
    }
    Ok(())
}

#[test]
fn native_failure_does_not_turn_planned_versions_into_committed_changes() {
    let transactions: Vec<NativeTransaction> = serde_json::from_str(r#"[{"id":1,"comment":"ours","status":"Error","packages":[{"nevra":"a-0:1-1.noarch","action":"Install"}]}]"#).unwrap();
    assert!(matches!(
        DnfPackageManager::native_outcome(&transactions, "ours").unwrap(),
        NativeOutcome::Failed
    ));
}

#[test]
fn native_interruption_keeps_uuid_without_description_and_rejects_ambiguous_rows() {
    let directory = tempfile::tempdir().unwrap();
    let history =
        crate::core::history::HistoryManager::new_in(directory.path().join("history.json"))
            .unwrap();
    let comment = "omg-550e8400-e29b-41d4-a716-446655440000";
    let transactions: Vec<NativeTransaction> = serde_json::from_str(
        r#"[{"id":73,"comment":"omg-550e8400-e29b-41d4-a716-446655440000","status":"Started","packages":[]},
            {"id":74,"comment":"omg-550e8400-e29b-41d4-a716-446655440001","status":"Ok","packages":[]}]"#,
    ).unwrap();
    let outcome = DnfPackageManager::native_outcome(&transactions, comment).unwrap();
    match &outcome {
        NativeOutcome::Interrupted {
            id,
            comment: observed,
            status,
            actions,
            command,
        } => {
            assert_eq!(*id, 73);
            assert_eq!(observed, comment);
            assert_eq!(status, "Started");
            assert_eq!(*actions, 0);
            assert_eq!(command, "not recorded");
        }
        other => panic!("expected Interrupted, got {other:?}"),
    }
    let error = DnfPackageManager::record_native_result(
        crate::core::history::TransactionType::Remove,
        &history,
        Err(anyhow::anyhow!("original exit 1")),
        Ok(outcome),
    )
    .unwrap_err();
    let diagnostic = format!("{error:#}");
    for expected in [
        comment,
        "73",
        "Started",
        "0 package action(s)",
        "not recorded",
        "original exit 1",
    ] {
        assert!(
            diagnostic.contains(expected),
            "missing {expected}: {diagnostic}"
        );
    }
    assert!(history.load().unwrap().is_empty());
    assert!(matches!(
        DnfPackageManager::native_outcome(&transactions[1..], comment).unwrap(),
        NativeOutcome::NoTransaction
    ));
    let duplicates: Vec<NativeTransaction> = serde_json::from_str(
        r#"[{"id":73,"comment":"omg-550e8400-e29b-41d4-a716-446655440000","status":"Started","packages":[]},
            {"id":75,"comment":"omg-550e8400-e29b-41d4-a716-446655440000","status":"Ok","packages":[]}]"#,
    ).unwrap();
    let error = DnfPackageManager::native_outcome(&duplicates, comment).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Duplicate DNF transaction correlation")
    );
    assert!(history.load().unwrap().is_empty());
}

#[test]
fn reads_native_translated_header() {
    let blob = include_bytes!("../../../tests/data/fedora-gnat-srpm.rpmhdr");
    let directory = write_packages_db(&[blob.as_slice()]);
    let packages = DnfPackageManager::read_rpm_sqlite(&directory.path().join("rpmdb.sqlite"))
        .expect("translated native header");
    assert_eq!(
        packages
            .iter()
            .map(|package| (
                package.name.as_str(),
                package.version.as_str(),
                package.release.as_str(),
                package.architecture.as_str(),
                package.summary.as_str(),
            ))
            .collect::<Vec<_>>(),
        vec![(
            "gnat-srpm-macros",
            "7",
            "2.fc44",
            "noarch",
            "RPM macros needed when source packages that need GNAT are built",
        )]
    );
}

#[test]
fn string_arrays_require_every_declared_terminator() {
    for kind in [8, 9] {
        let valid = strict_header(&[(1004, kind, 0, 2)], b"first\0second\0");
        assert!(DnfPackageManager::parse_rpm_header(&valid).is_ok());
        let missing = strict_header(&[(1004, kind, 0, 2)], b"first\0second");
        assert!(DnfPackageManager::parse_rpm_header(&missing).is_err());
        let mut outside = missing;
        outside.push(0);
        assert!(DnfPackageManager::parse_rpm_header(&outside).is_err());
    }
}

#[test]
fn test_rpm_header_parsing() {
    let mut header = Vec::new();
    header.extend_from_slice(&[0, 0, 0, 1]); // 1 entry
    header.extend_from_slice(&[0, 0, 0, 5]); // 5 bytes data ("test\0")
    // Entry: tag=1000 (NAME), type=6 (STRING), offset=0.
    // librpm count-one invariant (rnd-pm-10): STRING carries exactly one
    // element; the old fixture's count=4 encoded pre-S1 lax parsing.
    header.extend_from_slice(&1000u32.to_be_bytes());
    header.extend_from_slice(&6u32.to_be_bytes());
    header.extend_from_slice(&0i32.to_be_bytes());
    header.extend_from_slice(&1u32.to_be_bytes());
    // Data: "test\0"
    header.extend_from_slice(b"test\0");

    let result = DnfPackageManager::parse_rpm_header(&header);
    assert!(result.is_ok());

    let tags = result.unwrap();
    assert_eq!(tags, HashMap::from([(1000, b"test".as_slice())]));
}

fn strict_header(entries: &[(u32, u32, i32, u32)], data: &[u8]) -> Vec<u8> {
    let mut header = Vec::new();
    header.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    header.extend_from_slice(&(data.len() as u32).to_be_bytes());
    for (tag, typ, off, count) in entries {
        header.extend_from_slice(&tag.to_be_bytes());
        header.extend_from_slice(&typ.to_be_bytes());
        header.extend_from_slice(&off.to_be_bytes());
        header.extend_from_slice(&count.to_be_bytes());
    }
    header.extend_from_slice(data);
    header
}

#[test]
fn s1_rejects_negative_entry_offset() {
    let blob = strict_header(&[(1000, 6, -1, 1)], b"test\0");
    assert!(DnfPackageManager::parse_rpm_header(&blob).is_err());
}

#[test]
fn s1_rejects_unknown_tag_type() {
    for bad_type in [0u32, 10, 12] {
        let blob = strict_header(&[(1000, bad_type, 0, 1)], b"abcd");
        assert!(
            DnfPackageManager::parse_rpm_header(&blob).is_err(),
            "type {bad_type} must be rejected"
        );
    }
}

#[test]
fn s1_enforces_string_count_one() {
    let blob = strict_header(&[(1000, 6, 0, 4)], b"test\0");
    assert!(DnfPackageManager::parse_rpm_header(&blob).is_err());
}

#[test]
fn s1_rejects_string_missing_terminator() {
    let blob = strict_header(&[(1004, 6, 0, 1)], b"no-nul");
    assert!(DnfPackageManager::parse_rpm_header(&blob).is_err());
}

#[test]
fn s1_rejects_data_region_outside_declared_payload() {
    // Offset points past the declared data size.
    let blob = strict_header(&[(1000, 6, 99, 1)], b"test\0");
    assert!(DnfPackageManager::parse_rpm_header(&blob).is_err());
}

#[test]
fn s1_rejects_undeclared_trailing_payload_use() {
    // Data region ends at data_start+data_size; a string terminator may
    // not be satisfied by bytes beyond it.
    let mut blob = strict_header(&[(1000, 6, 0, 1)], b"xxxxx");
    blob.extend_from_slice(b"\0"); // NUL outside the declared payload
    assert!(DnfPackageManager::parse_rpm_header(&blob).is_err());
}

#[test]
fn test_parse_rpm_header_rejects_empty_header() {
    let error = DnfPackageManager::parse_rpm_header(&[0u8; 32])
        .expect_err("an empty header must not parse as a package");
    assert!(
        error.to_string().contains("must contain entries"),
        "got: {error}"
    );
}

#[test]
fn database_reader_rejects_archive_framing() {
    let mut archive = vec![0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0];
    archive.extend(strict_header(&[(1000, 6, 0, 1)], b"test\0"));
    assert!(DnfPackageManager::parse_rpm_header(&archive).is_err());
}

#[test]
fn user_installed_output_is_parsed_as_a_name_set() {
    let names =
        DnfPackageManager::parse_user_installed_names(b"bash\n\nvim\n").expect("valid dnf output");
    assert!(names.contains("bash"));
    assert!(names.contains("vim"));
    assert_eq!(names.len(), 2);
}

#[test]
fn install_reason_failure_preserves_the_rpm_inventory() {
    let packages = [InstalledPackage {
        name: "bash".to_string(),
        version: "5.2".to_string(),
        release: "1.fc42".to_string(),
        architecture: "x86_64".to_string(),
        summary: "GNU shell".to_string(),
    }];

    let error = DnfPackageManager::explicit_package_names(
        &packages,
        Err(anyhow::anyhow!("repoquery unavailable")),
    )
    .expect_err("unavailable install reasons must not become successful zero explicit packages");
    assert!(format!("{error:#}").contains("repoquery unavailable"));

    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].name, "bash");
    assert_eq!(packages[0].version, "5.2");
    assert_eq!(packages[0].release, "1.fc42");
    assert_eq!(packages[0].summary, "GNU shell");

    let explicit = DnfPackageManager::explicit_package_names(
        &packages,
        Ok(HashSet::from(["bash".into(), "not-installed".into()])),
    )
    .unwrap();
    assert_eq!(explicit, ["bash"]);
    let explicit =
        DnfPackageManager::explicit_package_names(&packages, Ok(HashSet::new())).unwrap();
    assert!(explicit.is_empty());
}

#[tokio::test]
async fn installed_inventory_observes_external_removal() -> Result<()> {
    let blob = include_bytes!("../../../tests/data/fedora-publicsuffix.rpmhdr");
    let directory = write_packages_db(&[blob.as_slice()]);
    let rpm_db_path = directory.path().join("rpmdb.sqlite");
    let manager = manager_for_database(&rpm_db_path);
    assert_eq!(manager.list_installed().await?.len(), 1);
    assert!(manager.is_installed_fast("publicsuffix-list-dafsa")?);
    assert!(!manager.is_installed_fast("definitely-not-installed")?);
    let database = Connection::open(&rpm_db_path)?;
    database.execute("DELETE FROM Packages", [])?;

    assert!(
        !manager.is_installed("publicsuffix-list-dafsa").await?,
        "a cached positive must not survive an external RPM removal"
    );
    assert!(!manager.is_installed_fast("publicsuffix-list-dafsa")?);
    assert!(manager.list_installed().await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn installed_inventory_preserves_database_order_across_cache_hits() -> Result<()> {
    let first = named_rpm_header("first");
    let middle = named_rpm_header("middle");
    let last = rpm_string_header([
        (rpm_tags::NAME, "first"),
        (rpm_tags::VERSION, "1.0"),
        (rpm_tags::RELEASE, "1.fc44"),
        (rpm_tags::ARCH, "i686"),
    ]);
    let directory = write_packages_db(&[&first, &middle, &last]);
    let rpm_db_path = directory.path().join("rpmdb.sqlite");
    let manager = manager_for_database(&rpm_db_path);

    for _ in 0..2 {
        let names: Vec<_> = manager
            .list_installed()
            .await?
            .into_iter()
            .map(|package| package.name)
            .collect();
        assert_eq!(names, ["first.noarch", "middle.noarch", "first.i686"]);
    }
    Ok(())
}

#[tokio::test]
async fn installed_inventory_observes_commits_when_file_metadata_matches() -> Result<()> {
    for journal_mode in ["DELETE", "WAL"] {
        let blob = include_bytes!("../../../tests/data/fedora-publicsuffix.rpmhdr");
        let directory = write_packages_db(&[blob.as_slice()]);
        let rpm_db_path = directory.path().join("rpmdb.sqlite");
        let manager = manager_for_database(&rpm_db_path);
        let database = Connection::open(&rpm_db_path)?;
        database.pragma_update(None, "journal_mode", journal_mode)?;
        assert_eq!(manager.list_installed().await?.len(), 1);
        assert!(
            manager.cached_installed_packages(&rpm_db_path).is_some(),
            "first inventory read must initialize a cache in {journal_mode} mode"
        );
        database.execute("DELETE FROM Packages", [])?;

        // Model a filesystem whose timestamp granularity cannot distinguish
        // the commit: force the cached stat fingerprint to equal the current
        // one without altering the cached inventory or SQLite observer.
        manager
            .cache_write()
            .as_mut()
            .expect("cached inventory")
            .observation
            .identity = RpmDatabaseIdentity::read(&rpm_db_path).expect("database identity");
        assert!(
            !manager.is_installed("publicsuffix-list-dafsa").await?,
            "{journal_mode}"
        );
        assert!(manager.list_installed().await?.is_empty(), "{journal_mode}");

        // The observer must not leave a read transaction blocking checkpoint.
        let busy: i64 =
            database.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
        assert_eq!(busy, 0, "{journal_mode}");
    }
    Ok(())
}

#[tokio::test]
async fn installed_inventory_observes_wal_only_removal() -> Result<()> {
    let blob = include_bytes!("../../../tests/data/fedora-publicsuffix.rpmhdr");
    let directory = write_packages_db(&[blob.as_slice()]);
    let rpm_db_path = directory.path().join("rpmdb.sqlite");
    let manager = manager_for_database(&rpm_db_path);
    let database = Connection::open(&rpm_db_path)?;
    database.pragma_update(None, "journal_mode", "WAL")?;
    assert_eq!(manager.list_installed().await?.len(), 1);
    assert!(
        manager.is_installed("publicsuffix-list-dafsa").await?,
        "the private fixture package must be present before testing its removal"
    );
    let original_bytes = std::fs::read(&rpm_db_path)?;
    let original_mtime = std::fs::metadata(&rpm_db_path)?.modified()?;

    database.execute("DELETE FROM Packages", [])?;
    assert_eq!(std::fs::read(&rpm_db_path)?, original_bytes);
    assert_eq!(std::fs::metadata(&rpm_db_path)?.modified()?, original_mtime);
    assert!(
        !manager.is_installed("publicsuffix-list-dafsa").await?,
        "committed WAL changes must invalidate an unchanged main file"
    );
    Ok(())
}

#[tokio::test]
async fn installed_inventory_observes_replacement_with_preserved_mtime() -> Result<()> {
    let blob = include_bytes!("../../../tests/data/fedora-publicsuffix.rpmhdr");
    let directory = write_packages_db(&[blob.as_slice()]);
    let rpm_db_path = directory.path().join("rpmdb.sqlite");
    let manager = manager_for_database(&rpm_db_path);
    assert_eq!(manager.list_installed().await?.len(), 1);
    assert!(
        manager.is_installed("publicsuffix-list-dafsa").await?,
        "the private fixture package must be present before testing its removal"
    );
    let original_mtime = std::fs::metadata(&rpm_db_path)?.modified()?;
    let replacement = write_packages_db(&[]);
    let replacement_path = replacement.path().join("rpmdb.sqlite");
    std::fs::File::open(&replacement_path)?
        .set_times(std::fs::FileTimes::new().set_modified(original_mtime))?;
    std::fs::rename(replacement_path, &rpm_db_path)?;

    assert_eq!(std::fs::metadata(&rpm_db_path)?.modified()?, original_mtime);
    assert!(!manager.is_installed("publicsuffix-list-dafsa").await?);
    Ok(())
}

#[tokio::test]
async fn installed_inventory_refreshes_an_empty_snapshot_after_installation() -> Result<()> {
    let directory = write_packages_db(&[]);
    let rpm_db_path = directory.path().join("rpmdb.sqlite");
    let manager = manager_for_database(&rpm_db_path);
    assert_eq!(manager.installed_count()?, 0);
    assert!(manager.cache_read().is_none());
    assert!(manager.list_installed().await?.is_empty());
    assert!(
        manager
            .cached_installed_packages(&rpm_db_path)
            .expect("empty snapshot")
            .is_empty()
    );
    let database = Connection::open(&rpm_db_path)?;
    let blob = include_bytes!("../../../tests/data/fedora-publicsuffix.rpmhdr");
    database.execute("INSERT INTO Packages (blob) VALUES (?1)", [blob.as_slice()])?;

    assert!(manager.is_installed("publicsuffix-list-dafsa").await?);
    assert_eq!(manager.list_installed().await?.len(), 1);
    manager.cache_handle().invalidate_installed_cache();
    assert!(manager.cached_installed_packages(&rpm_db_path).is_none());
    Ok(())
}

#[test]
fn installed_cache_rejects_changed_or_unobserved_generation() -> Result<()> {
    let blob = include_bytes!("../../../tests/data/fedora-publicsuffix.rpmhdr");
    let directory = write_packages_db(&[blob.as_slice()]);
    let rpm_db_path = directory.path().join("rpmdb.sqlite");
    let manager = manager_for_database(&rpm_db_path);
    let mut observed = RpmDatabaseObservation::read(&rpm_db_path);
    let packages = DnfPackageManager::read_rpm_sqlite(&rpm_db_path)?;
    let database = Connection::open(&rpm_db_path)?;
    database.execute("DELETE FROM Packages", [])?;

    // Even if metadata fails to reveal a commit between the inventory read
    // and publication, the original observer must reject the old inventory.
    observed.as_mut().expect("database observer").identity =
        RpmDatabaseIdentity::read(&rpm_db_path).expect("database identity");
    let packages = Arc::new(packages);
    manager.publish_installed_packages(Some(&rpm_db_path), Arc::clone(&packages), observed);
    assert!(manager.cached_installed_packages(&rpm_db_path).is_none());
    manager.publish_installed_packages(Some(&rpm_db_path), packages, None);
    assert!(manager.cached_installed_packages(&rpm_db_path).is_none());
    Ok(())
}

#[tokio::test]
async fn installed_cache_rejects_unobservable_database_files() -> Result<()> {
    let blob = include_bytes!("../../../tests/data/fedora-publicsuffix.rpmhdr");
    let directory = write_packages_db(&[blob.as_slice()]);
    let rpm_db_path = directory.path().join("rpmdb.sqlite");
    let manager = manager_for_database(&rpm_db_path);
    assert_eq!(manager.list_installed().await?.len(), 1);
    let cached = manager
        .cached_installed_packages(&rpm_db_path)
        .expect("private fixture cache must exist before testing invalidation");
    assert_eq!(
        cached
            .iter()
            .map(|package| (
                package.name.as_str(),
                package.version.as_str(),
                package.release.as_str(),
                package.architecture.as_str(),
            ))
            .collect::<Vec<_>>(),
        vec![("publicsuffix-list-dafsa", "20260116", "1.fc44", "noarch")]
    );
    let wal = directory.path().join("rpmdb.sqlite-wal");
    std::fs::create_dir(&wal)?;
    assert!(manager.cached_installed_packages(&rpm_db_path).is_none());
    std::fs::remove_dir(wal)?;
    std::fs::remove_file(&rpm_db_path)?;
    assert!(manager.cached_installed_packages(&rpm_db_path).is_none());
    Ok(())
}

#[test]
fn installed_cache_publication_is_idempotent_and_preserves_multilib_names() {
    let directory = write_packages_db(&[]);
    let rpm_db_path = directory.path().join("rpmdb.sqlite");
    let manager = manager_for_database(&rpm_db_path);
    let identity = RpmDatabaseObservation::read(&rpm_db_path);
    let packages: Vec<_> = ["x86_64", "i686"]
        .into_iter()
        .map(|architecture| InstalledPackage {
            name: "glibc".to_string(),
            version: "2.41".to_string(),
            release: "1.fc42".to_string(),
            architecture: architecture.to_string(),
            summary: "C library".to_string(),
        })
        .collect();

    let packages = Arc::new(packages);
    manager.publish_installed_packages(Some(&rpm_db_path), Arc::clone(&packages), identity.clone());
    manager.publish_installed_packages(Some(&rpm_db_path), packages, identity);

    let cached = manager
        .cached_installed_packages(&rpm_db_path)
        .expect("populated cache");
    assert_eq!(cached.len(), 2);
    let mut identities: Vec<_> = cached
        .iter()
        .map(|package| {
            (
                package.name.as_str(),
                package.version.as_str(),
                package.release.as_str(),
                package.architecture.as_str(),
            )
        })
        .collect();
    identities.sort_unstable();
    assert_eq!(
        identities,
        [
            ("glibc", "2.41", "1.fc42", "i686"),
            ("glibc", "2.41", "1.fc42", "x86_64"),
        ]
    );
}

#[test]
fn explicit_package_names_collapse_parallel_installed_versions() {
    let packages = vec![
        InstalledPackage {
            name: "kernel-core".to_string(),
            version: "6.17.1".to_string(),
            release: "1.fc44".to_string(),
            architecture: "x86_64".to_string(),
            summary: "Kernel".to_string(),
        },
        InstalledPackage {
            name: "kernel-core".to_string(),
            version: "6.17.2".to_string(),
            release: "1.fc44".to_string(),
            architecture: "x86_64".to_string(),
            summary: "Kernel".to_string(),
        },
        InstalledPackage {
            name: "kernel-modules".to_string(),
            version: "6.17.2".to_string(),
            release: "1.fc44".to_string(),
            architecture: "x86_64".to_string(),
            summary: "Kernel modules".to_string(),
        },
    ];

    assert_eq!(
        DnfPackageManager::explicit_package_names(
            &packages,
            Ok(HashSet::from(["kernel-core".into()])),
        )
        .unwrap(),
        vec!["kernel-core"]
    );
}

#[test]
fn installed_cache_publication_replaces_the_previous_snapshot() {
    let directory = write_packages_db(&[]);
    let rpm_db_path = directory.path().join("rpmdb.sqlite");
    let manager = manager_for_database(&rpm_db_path);
    let identity = RpmDatabaseObservation::read(&rpm_db_path);
    manager.publish_installed_packages(
        Some(&rpm_db_path),
        Arc::new(vec![InstalledPackage {
            name: "glibc".to_string(),
            version: "2.41".to_string(),
            release: "1.fc42.x86_64".to_string(),
            architecture: "x86_64".to_string(),
            summary: "C library".to_string(),
        }]),
        identity.clone(),
    );
    manager.publish_installed_packages(
        Some(&rpm_db_path),
        Arc::new(vec![InstalledPackage {
            name: "bash".to_string(),
            version: "5.2".to_string(),
            release: "1.fc42".to_string(),
            architecture: "x86_64".to_string(),
            summary: "GNU shell".to_string(),
        }]),
        identity,
    );

    let cached = manager
        .cached_installed_packages(&rpm_db_path)
        .expect("populated cache");
    assert_eq!(cached.len(), 1);
    assert_eq!(cached[0].name, "bash");
    assert_eq!(cached[0].summary, "GNU shell");
}

#[test]
fn test_parse_rpm_qa_line_reads_installed_package() {
    let pkg = DnfPackageManager::parse_rpm_qa_line(
        "bash\t5.2.15\t1.fc39\t0\tx86_64\tThe GNU Bourne Again shell\twith completion",
    )
    .expect("valid rpm -qa line");
    assert_eq!(pkg.name, "bash");
    assert_eq!(pkg.version, "5.2.15");
    assert_eq!(pkg.architecture, "x86_64");
    assert_eq!(pkg.summary, "The GNU Bourne Again shell\twith completion");
}

#[test]
fn sqlite_string_values_exclude_rpm_terminators() {
    let package = DnfPackageManager::parse_package_from_blob(&named_rpm_header("bash"))
        .expect("valid RPM name header");
    assert_eq!(package.name, "bash");
}

#[test]
fn test_parse_rpm_qa_line_rejects_truncated_row() {
    let error = DnfPackageManager::parse_rpm_qa_line("bash\t5.2.15")
        .expect_err("truncated rpm -qa line must not skip the package");
    assert!(
        error.to_string().contains("malformed rpm -qa output"),
        "got: {error}"
    );
}

#[test]
fn rpm_query_rejects_incomplete_installed_identity() {
    let complete = ["bash", "5.2.15", "1.fc39", "0", "x86_64", "GNU shell"];
    for field in [0, 1, 2, 4] {
        for missing in ["", "(none)"] {
            let mut fields = complete;
            fields[field] = missing;
            assert!(
                DnfPackageManager::parse_rpm_qa_line(&fields.join("\t")).is_err(),
                "incomplete installed RPM identity accepted: {fields:?}"
            );
        }
    }
}

#[test]
fn rpm_sqlite_rejects_incomplete_installed_identity() {
    let fields = [
        (rpm_tags::NAME, "bash"),
        (rpm_tags::VERSION, "5.2.15"),
        (rpm_tags::RELEASE, "1.fc39"),
        (rpm_tags::ARCH, "x86_64"),
    ];
    for (missing, _) in fields {
        let header = rpm_string_header(fields.into_iter().filter(|(tag, _)| *tag != missing));
        let directory = write_packages_db(&[&header]);
        assert!(
            DnfPackageManager::read_rpm_sqlite(&directory.path().join("rpmdb.sqlite")).is_err(),
            "installed RPM identity accepted without tag {missing}"
        );
    }
}

#[test]
fn rpm_keeps_legacy_architectureless_trust_records() -> Result<()> {
    let header = rpm_string_header([
        (rpm_tags::NAME, "gpg-pubkey"),
        (rpm_tags::VERSION, "3b94a80e"),
        (rpm_tags::RELEASE, "6665a2fc"),
    ]);
    let stored_key = DnfPackageManager::parse_package_from_blob(&header)?;
    let queried_key = DnfPackageManager::parse_rpm_qa_line(
        "gpg-pubkey\t3b94a80e\t6665a2fc\t0\t(none)\tOpenPGP key",
    )?;
    for key in [stored_key, queried_key] {
        assert_eq!(key.identity(), "gpg-pubkey");
        assert_eq!(key.version, "3b94a80e");
        assert_eq!(key.release, "6665a2fc");
    }
    Ok(())
}

fn named_rpm_header(name: &str) -> Vec<u8> {
    rpm_string_header([
        (rpm_tags::NAME, name),
        (rpm_tags::VERSION, "1.0"),
        (rpm_tags::RELEASE, "1.fc44"),
        (rpm_tags::ARCH, "noarch"),
    ])
}

fn rpm_string_header<'a>(fields: impl IntoIterator<Item = (u32, &'a str)>) -> Vec<u8> {
    let mut entries = Vec::new();
    let mut data = Vec::new();
    for (tag, value) in fields {
        entries.push((tag, 6, i32::try_from(data.len()).unwrap(), 1));
        data.extend_from_slice(value.as_bytes());
        data.push(0);
    }
    strict_header(&entries, &data)
}

fn manager_for_database(path: &Path) -> DnfPackageManager {
    DnfPackageManager {
        rpm_database: RpmDatabaseSource::Fixture(path.to_owned()),
        ..DnfPackageManager::new()
    }
}

fn write_packages_db(blobs: &[&[u8]]) -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let db = dir.path().join("rpmdb.sqlite");
    let conn = Connection::open(&db).expect("open sqlite");
    conn.execute(
        "CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB NOT NULL)",
        [],
    )
    .expect("create Packages");
    for blob in blobs {
        conn.execute("INSERT INTO Packages (blob) VALUES (?1)", [blob.to_vec()])
            .expect("insert blob");
    }
    dir
}

#[tokio::test]
async fn installed_lookup_reads_one_package_when_an_unrelated_header_is_unreadable() -> Result<()> {
    let header = named_rpm_header("omg-indexed-read-fixture");
    let directory = write_packages_db(&[header.as_slice(), &[0; 32]]);
    let rpm_db_path = directory.path().join("rpmdb.sqlite");
    let manager = manager_for_database(&rpm_db_path);
    let database = Connection::open(&rpm_db_path)?;
    database.execute_batch(
        "CREATE TABLE Name (key TEXT NOT NULL, hnum INTEGER NOT NULL, idx INTEGER NOT NULL);
         CREATE INDEX Name_key_idx ON Name(key);
         INSERT INTO Name VALUES ('omg-indexed-read-fixture', 1, 0), ('unrelated', 2, 0);",
    )?;
    drop(database);

    assert!(manager.is_installed("omg-indexed-read-fixture").await?);
    Ok(())
}

#[tokio::test]
async fn indexed_installed_info_preserves_qualified_and_literal_matches() -> Result<()> {
    let native = include_bytes!("../../../tests/data/fedora-publicsuffix.rpmhdr");
    let literal = named_rpm_header("publicsuffix-list-dafsa.noarch");
    let directory = write_packages_db(&[native.as_slice(), &literal]);
    let rpm_db_path = directory.path().join("rpmdb.sqlite");
    let manager = manager_for_database(&rpm_db_path);
    let database = Connection::open(&rpm_db_path)?;
    database.execute_batch(
        "CREATE TABLE Name (key TEXT NOT NULL, hnum INTEGER NOT NULL, idx INTEGER NOT NULL);
         CREATE INDEX Name_key_idx ON Name(key);
         INSERT INTO Name VALUES
           ('publicsuffix-list-dafsa', 1, 0), ('publicsuffix-list-dafsa.noarch', 2, 0);",
    )?;
    drop(database);

    let exact = DnfPackageManager::parse_package_from_blob(native)?.nevra();
    let package = manager
        .info(&exact)
        .await?
        .context("missing installed package")?;
    assert_eq!(package.name, "publicsuffix-list-dafsa.noarch");
    assert!(package.installed);

    let error = manager
        .info("publicsuffix-list-dafsa.noarch")
        .await
        .expect_err("the literal package name also matches this selector");
    assert!(error.to_string().contains("multiple installed builds"));
    Ok(())
}

#[tokio::test]
async fn indexed_installed_lookup_falls_back_on_inconsistent_rows() -> Result<()> {
    let header = named_rpm_header("indexed-fallback-fixture");
    let directory = write_packages_db(&[&header]);
    let rpm_db_path = directory.path().join("rpmdb.sqlite");
    let manager = manager_for_database(&rpm_db_path);
    let database = Connection::open(&rpm_db_path)?;
    database.execute_batch(
        "CREATE TABLE Name (key TEXT NOT NULL, hnum INTEGER NOT NULL, idx INTEGER NOT NULL);
         CREATE INDEX Name_key_idx ON Name(key);
         INSERT INTO Name VALUES ('indexed-fallback-fixture', 2, 0);",
    )?;
    drop(database);

    assert!(manager.is_installed("indexed-fallback-fixture").await?);
    assert!(!manager.is_installed("indexed-fallback-absent").await?);
    Ok(())
}

#[test]
fn test_read_rpm_sqlite_malformed_blob_is_error() {
    let dir = write_packages_db(&[&[0u8; 32]]);
    let error = DnfPackageManager::read_rpm_sqlite(&dir.path().join("rpmdb.sqlite"))
        .expect_err("malformed header must not look like an empty inventory");
    let message = format!("{error:#}");
    assert!(
        message.contains("Malformed RPM header in Packages table"),
        "got: {message}"
    );
}

#[test]
fn test_read_rpm_sqlite_mixed_blobs_do_not_drop_corrupt_row() {
    let valid = named_rpm_header("bash");
    let dir = write_packages_db(&[valid.as_slice(), &[0u8; 32]]);
    let error = DnfPackageManager::read_rpm_sqlite(&dir.path().join("rpmdb.sqlite"))
        .expect_err("one corrupt row must not omit that package from the catalog");
    let message = format!("{error:#}");
    assert!(
        message.contains("Malformed RPM header in Packages table"),
        "got: {message}"
    );
}

#[test]
fn malformed_row_reports_position_decoded_count_and_cause() {
    let valid = named_rpm_header("bash");
    let dir = write_packages_db(&[valid.as_slice(), &[0u8; 32]]);
    let error = DnfPackageManager::read_rpm_sqlite(&dir.path().join("rpmdb.sqlite"))
        .expect_err("corrupt row must fail loudly");
    let message = format!("{error:#}");
    for needle in [
        "row 2",
        "1 packages decoded before the failure",
        "must contain entries",
    ] {
        assert!(message.contains(needle), "missing {needle:?} in: {message}");
    }
}

#[test]
fn ordinary_rpm_inventory_preserves_epoch() {
    let package =
        DnfPackageManager::parse_rpm_qa_line("example\t1.0\t1.fc44\t2\tx86_64\tsummary").unwrap();
    assert_eq!(package.version, "2:1.0");
}
