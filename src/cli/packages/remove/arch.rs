use anyhow::{Context, Result};

use crate::cli::{style, ui};

/// Preview explicitly requested packages. Recursive dependency cleanup is
/// disclosed separately because calculating libalpm's complete removal set
/// requires preparing the privileged transaction.
pub fn remove_dry_run(packages: &[String], recursive: bool) -> Result<()> {
    let package_info = packages
        .iter()
        .map(|package| {
            crate::package_managers::get_package_info(package)
                .with_context(|| format!("Failed to look up installed package {package}"))?
                .filter(|info| info.installed)
                .ok_or_else(|| anyhow::anyhow!("Package '{package}' is not installed"))
        })
        .collect::<Result<Vec<_>>>()?;

    crate::cli::modern_ui::print_phase_header("🗑️", "Remove Preview", "dry run");
    println!();
    println!(
        "  {} The following requested packages would be removed:\n",
        style::info("→")
    );

    let mut total_size: u64 = 0;
    for info in package_info {
        let size_mb = info.size as f64 / 1024.0 / 1024.0;
        total_size += info.size;
        println!(
            "    {} {} {} ({:.2} MB)",
            style::error("✗"),
            style::package(&info.name),
            style::version(&info.version.to_string()),
            size_mb
        );
    }

    if recursive {
        println!(
            "\n  {} Additional unneeded dependencies would also be removed; their names and sizes are not included in this preview",
            style::info("→")
        );
    }

    ui::print_spacer();
    println!(
        "  {} Requested-package space that would be freed: {:.2} MB",
        style::info("→"),
        total_size as f64 / 1024.0 / 1024.0
    );
    ui::print_dry_run_footer();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::remove_dry_run;

    fn with_native_removal_fixture(test: impl FnOnce()) {
        temp_env::with_vars(
            [("OMG_TEST_MODE", None::<&str>), ("OMG_TEST_DISTRO", None)],
            || {
                if crate::core::is_root()
                    || crate::core::env::distro::detect_distro()
                        != crate::core::env::distro::Distro::Arch
                {
                    eprintln!(
                        "skipped: native removal fixture requires an unprivileged Arch process"
                    );
                    return;
                }

                struct Restore;
                impl Drop for Restore {
                    fn drop(&mut self) {
                        crate::core::paths::reset_test_overrides();
                        crate::package_managers::alpm_direct::clear_alpm_cache();
                    }
                }

                let directory = tempfile::tempdir().expect("native removal fixture");
                let root = directory.path().join("root");
                let database = root.join("var/lib/pacman");
                let local = database.join("local");
                let sync = database.join("sync");
                std::fs::create_dir_all(local.join("installed-fixture-1.0-1"))
                    .expect("local package directory");
                std::fs::create_dir_all(&sync).expect("sync database directory");
                std::fs::write(local.join("ALPM_DB_VERSION"), "9\n")
                    .expect("local database version");
                std::fs::write(
                    local.join("installed-fixture-1.0-1/desc"),
                    "%NAME%\ninstalled-fixture\n\n%VERSION%\n1.0-1\n\n%DESC%\nInstalled removal fixture\n\n%ARCH%\nx86_64\n\n%SIZE%\n4096\n\n%REASON%\n0\n\n",
                )
                .expect("local package metadata");
                let content = "%FILENAME%\nsync-only-fixture-2.0-1-x86_64.pkg.tar.zst\n\n%NAME%\nsync-only-fixture\n\n%VERSION%\n2.0-1\n\n%DESC%\nAvailable removal fixture\n\n%ARCH%\nx86_64\n\n%CSIZE%\n1024\n\n%ISIZE%\n8192\n\n";
                let encoder = flate2::write::GzEncoder::new(
                    std::fs::File::create(sync.join("core.db")).expect("sync database archive"),
                    flate2::Compression::fast(),
                );
                let mut archive = tar::Builder::new(encoder);
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_entry_type(tar::EntryType::Regular);
                header.set_cksum();
                archive
                    .append_data(
                        &mut header,
                        "sync-only-fixture-2.0-1/desc",
                        content.as_bytes(),
                    )
                    .expect("append sync package metadata");
                archive
                    .into_inner()
                    .expect("finish sync archive")
                    .finish()
                    .expect("finish gzip stream");
                let config = directory.path().join("pacman.conf");
                std::fs::write(
                    &config,
                    "[options]\nSigLevel = Never\n[core]\nServer = https://fixture.invalid/$repo/$arch\n",
                )
                .expect("private pacman configuration");

                let _restore = Restore;
                crate::package_managers::alpm_direct::clear_alpm_cache();
                crate::core::paths::set_test_overrides(Some(root), Some(database));
                temp_env::with_var(
                    "OMG_PACMAN_CONF",
                    Some(config.to_str().expect("UTF-8 config")),
                    test,
                );
            },
        );
    }

    #[test]
    #[serial_test::serial]
    fn removal_preview_rejects_sync_only_package_but_preserves_repository_info() {
        if crate::core::testing::run_isolated_test(
            "cli::packages::remove::arch::tests::removal_preview_rejects_sync_only_package_but_preserves_repository_info",
        ) {
            return;
        }
        with_native_removal_fixture(|| {
            let info = crate::package_managers::get_package_info("sync-only-fixture")
                .expect("native package lookup")
                .expect("repository package remains queryable");
            assert_eq!(
                (
                    info.name.as_str(),
                    info.version.to_string(),
                    info.repo.as_str(),
                    info.installed,
                    info.size,
                ),
                (
                    "sync-only-fixture",
                    "2.0-1".to_string(),
                    "core",
                    false,
                    8192
                ),
            );
            let error = remove_dry_run(&["sync-only-fixture".to_string()], false)
                .expect_err("an available package is not an installed removal target");
            assert_eq!(
                error.to_string(),
                "Package 'sync-only-fixture' is not installed"
            );
        });
    }

    #[test]
    #[serial_test::serial]
    fn removal_preview_rejects_mixed_installed_and_sync_only_targets() {
        if crate::core::testing::run_isolated_test(
            "cli::packages::remove::arch::tests::removal_preview_rejects_mixed_installed_and_sync_only_targets",
        ) {
            return;
        }
        with_native_removal_fixture(|| {
            let installed = crate::package_managers::get_package_info("installed-fixture")
                .expect("native local lookup")
                .expect("installed package");
            assert_eq!((installed.installed, installed.size), (true, 4096));
            let available = crate::package_managers::get_package_info("sync-only-fixture")
                .expect("native sync lookup")
                .expect("available package");
            assert_eq!(
                (available.installed, available.version.to_string()),
                (false, "2.0-1".to_string())
            );
            let error = remove_dry_run(
                &[
                    "installed-fixture".to_string(),
                    "sync-only-fixture".to_string(),
                ],
                false,
            )
            .expect_err("every requested removal target must be installed");
            assert_eq!(
                error.to_string(),
                "Package 'sync-only-fixture' is not installed"
            );
        });
    }

    #[test]
    #[serial_test::serial]
    fn recursive_removal_preview_rejects_sync_only_package() {
        if crate::core::testing::run_isolated_test(
            "cli::packages::remove::arch::tests::recursive_removal_preview_rejects_sync_only_package",
        ) {
            return;
        }
        with_native_removal_fixture(|| {
            let info = crate::package_managers::get_package_info("sync-only-fixture")
                .expect("native sync lookup")
                .expect("available package");
            assert_eq!(
                (info.installed, info.version.to_string()),
                (false, "2.0-1".to_string())
            );
            let error = remove_dry_run(&["sync-only-fixture".to_string()], true)
                .expect_err("recursive cleanup cannot remove an uninstalled target");
            assert_eq!(
                error.to_string(),
                "Package 'sync-only-fixture' is not installed"
            );
        });
    }

    #[test]
    #[serial_test::serial]
    fn removal_preview_accepts_installed_native_package() {
        if crate::core::testing::run_isolated_test(
            "cli::packages::remove::arch::tests::removal_preview_accepts_installed_native_package",
        ) {
            return;
        }
        with_native_removal_fixture(|| {
            let info = crate::package_managers::get_package_info("installed-fixture")
                .expect("native local lookup")
                .expect("installed package");
            assert_eq!(
                (
                    info.name.as_str(),
                    info.version.to_string(),
                    info.repo.as_str(),
                    info.installed,
                    info.size,
                ),
                (
                    "installed-fixture",
                    "1.0-1".to_string(),
                    "local",
                    true,
                    4096
                ),
            );
            remove_dry_run(&["installed-fixture".to_string()], false)
                .expect("installed target must have a removal preview");
            remove_dry_run(&["installed-fixture".to_string()], true)
                .expect("installed target must also permit a recursive preview");
            let after = crate::package_managers::get_package_info("installed-fixture")
                .expect("native lookup after dry run")
                .expect("preview must leave installed package intact");
            assert_eq!(
                (after.installed, after.version.to_string(), after.size),
                (true, "1.0-1".to_string(), 4096)
            );
        });
    }

    #[test]
    #[serial_test::serial]
    fn removal_preview_refuses_package_absent_from_local_and_sync_databases() {
        if crate::core::testing::run_isolated_test(
            "cli::packages::remove::arch::tests::removal_preview_refuses_package_absent_from_local_and_sync_databases",
        ) {
            return;
        }
        with_native_removal_fixture(|| {
            let present = crate::package_managers::get_package_info("installed-fixture")
                .expect("native positive-control lookup")
                .expect("installed positive control");
            assert_eq!(
                (present.installed, present.version.to_string()),
                (true, "1.0-1".to_string())
            );
            assert!(
                crate::package_managers::get_package_info("absent-fixture")
                    .expect("native absent lookup")
                    .is_none()
            );
            let error = remove_dry_run(&["absent-fixture".to_string()], false)
                .expect_err("absent package cannot have a removal preview");
            assert_eq!(
                error.to_string(),
                "Package 'absent-fixture' is not installed"
            );
        });
    }
}
