//! Failure Scenario Tests
//!
//! Tests critical failure modes using the isolated ALPM harness.

#![cfg(feature = "arch")]
#![expect(clippy::uninlined_format_args)]

pub mod alpm_harness;
pub mod common;
use alpm_harness::{AlpmHarness, HarnessPkg};
use anyhow::Result;
use omg_lib::package_managers::alpm_ops::{self, TransactionKind};
use serial_test::serial;

use omg_lib::core::paths;

#[test]
#[serial]
fn test_conflicting_packages_fails_gracefully() -> Result<()> {
    let harness = AlpmHarness::new()?;

    // Create two conflicting packages
    let mut pkg_a = HarnessPkg::new("pkg-a", "1.0.0-1");
    pkg_a.desc.push_str("%CONFLICTS%\npkg-b\n\n");

    let mut pkg_b = HarnessPkg::new("pkg-b", "1.0.0-1");
    pkg_b.desc.push_str("%CONFLICTS%\npkg-a\n\n");

    harness.add_sync_pkg("core", &pkg_a)?;
    harness.add_sync_pkg("extra", &pkg_b)?;

    // SAFE path overrides (no unsafe needed!)
    paths::set_test_overrides(
        Some(harness.root().to_path_buf()),
        Some(harness.db_path().to_path_buf()),
    );

    // Ensure we reset after the test
    scopeguard::defer! {
        paths::reset_test_overrides();
    }

    let mut alpm = harness.alpm()?;
    alpm.register_syncdb("core", alpm::SigLevel::NONE)?;
    alpm.register_syncdb("extra", alpm::SigLevel::NONE)?;

    // Execute transaction using the injected handle
    let result = alpm_ops::execute_transaction(
        vec!["pkg-a".to_string(), "pkg-b".to_string()],
        TransactionKind::Install,
        Some(&mut alpm),
    );

    let err = result.expect_err("conflicting packages must refuse preparation");
    assert_eq!(
        err.to_string().lines().next(),
        Some(
            format!(
                "✗ Transaction preparation failed: {}",
                alpm::Error::ConflictingDeps
            )
            .as_str()
        )
    );

    Ok(())
}

#[test]
#[serial]
fn test_unwritable_database_dir_fails_gracefully() -> Result<()> {
    if omg_lib::core::privilege::is_root() {
        common::report_skip("root bypasses directory write permissions");
        return Ok(());
    }

    let harness = AlpmHarness::new()?;

    let pkg = HarnessPkg::new("pkg-a", "1.0.0");
    harness.add_sync_pkg("core", &pkg)?;

    // Inject the fault where it actually bites the production path: an
    // UNWRITABLE database directory makes libalpm's lockfile creation
    // (db.lck) fail inside trans_init. (A read-only sync/ dir does NOT stop a
    // local install — verified: without this chmod the call fails with a
    // different, unrelated message.)
    let db_dir = harness.db_path();
    let mut perms = std::fs::metadata(db_dir)?.permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(db_dir, perms)?;

    // Restore permissions so the harness temp dir can be cleaned up.
    scopeguard::defer! {
        if let Ok(meta) = std::fs::metadata(db_dir) {
            use std::os::unix::fs::PermissionsExt;
            let mut p = meta.permissions();
            p.set_mode(0o755); // Restore standard directory permissions
            let _ = std::fs::set_permissions(db_dir, p);
        }
    }

    paths::set_test_overrides(
        Some(harness.root().to_path_buf()),
        Some(harness.db_path().to_path_buf()),
    );

    scopeguard::defer! {
        paths::reset_test_overrides();
    }

    // Production path (no injected handle): must fail gracefully with the
    // friendly locked-database mapping from prepare_alpm_transaction
    // (src/package_managers/alpm_ops.rs:472-481), never panic and never
    // report a missing package instead of the database problem.
    let result =
        alpm_ops::execute_transaction(vec!["pkg-a".to_string()], TransactionKind::Install, None);

    assert!(
        result.is_err(),
        "Transaction should fail due to unwritable database directory"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Database is locked"),
        "unwritable db dir must surface the friendly locked-database message, got: {err}"
    );

    Ok(())
}

#[test]
#[serial]
fn test_missing_dependency_fails_gracefully() -> Result<()> {
    if omg_lib::core::privilege::is_root() {
        common::report_skip("private pacman configuration requires an ordinary UID");
        return Ok(());
    }
    assert_transaction_refusal(HandleSource::Injected, TransactionFault::MissingDependency)
}

#[test]
#[serial]
fn test_owned_handle_missing_dependency_fails_gracefully() -> Result<()> {
    if omg_lib::core::privilege::is_root() {
        common::report_skip("private pacman configuration requires an ordinary UID");
        return Ok(());
    }
    assert_transaction_refusal(HandleSource::Owned, TransactionFault::MissingDependency)
}

#[test]
#[serial]
fn test_missing_repository_target_with_injected_handle() -> Result<()> {
    if omg_lib::core::privilege::is_root() {
        common::report_skip("private pacman configuration requires an ordinary UID");
        return Ok(());
    }
    assert_transaction_refusal(HandleSource::Injected, TransactionFault::MissingTarget)
}

#[test]
#[serial]
fn test_missing_repository_target_with_owned_handle() -> Result<()> {
    if omg_lib::core::privilege::is_root() {
        common::report_skip("private pacman configuration requires an ordinary UID");
        return Ok(());
    }
    assert_transaction_refusal(HandleSource::Owned, TransactionFault::MissingTarget)
}

#[derive(Clone, Copy, Debug)]
enum HandleSource {
    Injected,
    Owned,
}

#[derive(Clone, Copy, Debug)]
enum TransactionFault {
    MissingTarget,
    MissingDependency,
}

fn assert_transaction_refusal(source: HandleSource, fault: TransactionFault) -> Result<()> {
    assert!(
        !omg_lib::core::privilege::is_root(),
        "private pacman configuration requires an unprivileged caller"
    );
    let harness = AlpmHarness::new()?;

    let mut pkg_a = HarnessPkg::new("pkg-a", "1.0.0-1");
    if matches!(fault, TransactionFault::MissingDependency) {
        pkg_a.desc.push_str("%DEPENDS%\nnon-existent-dep\n\n");
    }

    harness.add_sync_pkg("core", &pkg_a)?;
    let conf = harness.root().join("pacman.conf");
    std::fs::write(
        &conf,
        format!(
            "[options]\nSigLevel = Never\nArchitecture = x86_64\n[core]\nServer = file://{}/missing\n",
            harness.root().display()
        ),
    )?;
    let config = harness.root().join("omg-config");
    let data = harness.root().join("omg-data");
    let cache = harness.root().join("omg-cache");
    for directory in [&config, &data, &cache] {
        std::fs::create_dir_all(directory)?;
    }

    paths::set_test_overrides(
        Some(harness.root().to_path_buf()),
        Some(harness.db_path().to_path_buf()),
    );

    scopeguard::defer! {
        paths::reset_test_overrides();
    }

    temp_env::with_vars(
        [
            ("OMG_PACMAN_CONF", Some(conf.as_os_str())),
            ("OMG_CONFIG_DIR", Some(config.as_os_str())),
            ("OMG_DATA_DIR", Some(data.as_os_str())),
            ("OMG_CACHE_DIR", Some(cache.as_os_str())),
        ],
        || {
            let mut alpm = harness.alpm()?;
            alpm.register_syncdb("core", alpm::SigLevel::NONE)?;
            let handle = match source {
                HandleSource::Injected => Some(&mut alpm),
                HandleSource::Owned => None,
            };
            let target = match fault {
                TransactionFault::MissingTarget => "does-not-exist",
                TransactionFault::MissingDependency => "pkg-a",
            };
            let result = alpm_ops::execute_transaction(
                vec![target.to_string()],
                TransactionKind::Install,
                handle,
            );
            let err =
                result.expect_err("an invalid private transaction must fail before installation");
            let diagnostic = err.to_string();
            match fault {
                TransactionFault::MissingTarget => {
                    assert_eq!(
                        diagnostic.lines().next(),
                        Some("✗ Package 'does-not-exist' not found in any configured repository.")
                    );
                    assert!(diagnostic.contains("Run 'omg sync'"), "{diagnostic}");
                    assert!(
                        diagnostic.contains("omg search does-not-exist"),
                        "{diagnostic}"
                    );
                }
                TransactionFault::MissingDependency => {
                    for required in [
                        "ALPM transaction aborted",
                        "unconfirmed package mutation",
                        "drop unresolvable package(s) from the transaction: pkg-a",
                        "resolve the conflict explicitly and retry",
                    ] {
                        assert!(diagnostic.contains(required), "{diagnostic}");
                    }
                }
            }
            let observed = harness.alpm()?;
            assert_eq!(
                observed.localdb().pkg("pkg-a").err(),
                Some(alpm::Error::PkgNotFound),
                "the independent observer must report package absence"
            );
            assert!(!harness.db_path().join("db.lck").exists());

            Ok(())
        },
    )
}

#[test]
#[serial]
fn test_stale_database_lock_requires_explicit_recovery() -> Result<()> {
    let harness = AlpmHarness::new()?;
    let lock_file = harness.db_path().join("db.lck");
    std::fs::File::create(&lock_file)?;

    paths::set_test_overrides(
        Some(harness.root().to_path_buf()),
        Some(harness.db_path().to_path_buf()),
    );

    scopeguard::defer! {
        paths::reset_test_overrides();
    }

    let result =
        alpm_ops::execute_transaction(vec!["any-pkg".to_string()], TransactionKind::Install, None);

    let error = result.expect_err("an existing lock must refuse automatic recovery");
    assert_eq!(
        error.downcast_ref::<alpm::Error>(),
        Some(&alpm::Error::HandleLock)
    );
    assert!(error.to_string().contains("refusing automatic removal"));
    assert_eq!(std::fs::read(lock_file)?, b"");

    Ok(())
}

#[test]
#[serial]
fn test_locked_database_shows_friendly_message() -> Result<()> {
    let harness = AlpmHarness::new()?;
    let lease = harness.alpm()?;
    lease.trans_init(alpm::TransFlag::empty())?;

    paths::set_test_overrides(
        Some(harness.root().to_path_buf()),
        Some(harness.db_path().to_path_buf()),
    );

    scopeguard::defer! {
        paths::reset_test_overrides();
    }

    let result =
        alpm_ops::execute_transaction(vec!["any-pkg".to_string()], TransactionKind::Install, None);

    assert!(result.is_err(), "Transaction should fail due to lock file");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Database is locked") || err.contains("another package manager"),
        "Error message should mention the lock, got: {}",
        err
    );

    Ok(())
}
