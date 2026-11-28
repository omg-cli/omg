use super::*;
use std::fs::File;

#[test]
fn official_full_version_conversion_preserves_catalog_versions() {
    for text in [
        "foo-1",
        "1:foo-1",
        "0:1.0-1",
        "2:1.0-01",
        "2026.11.13-1",
        "1.2.3.r45.gabcdef-2.1",
        "42:1.0+git.20261113-3",
    ] {
        let full = alpm_types::FullVersion::from_str(text).expect("valid official version fixture");
        let round_trip = require_package_version(&full.to_string()).unwrap();
        let converted = Version::from(full);
        assert!(
            crate::package_managers::types::compare_versions(&converted, &round_trip).is_eq(),
            "version {text}"
        );
        assert_eq!(
            converted.to_string(),
            round_trip.to_string(),
            "version {text}"
        );
    }
}

fn batch2_write_sync(path: &Path, version: &str) {
    let content = format!("%NAME%\nwidget\n\n%VERSION%\n{version}\n\n");
    let mut archive = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive
        .append_data(
            &mut header,
            format!("widget-{version}/desc").replace('\0', "_"),
            content.as_bytes(),
        )
        .unwrap();
    let raw = archive.into_inner().unwrap();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gzip.write_all(&raw).unwrap();
    fs::write(path, gzip.finish().unwrap()).unwrap();
}

fn batch2_catalog_fixture(test_name: &str, repos: &str, run: impl FnOnce(&Path)) {
    if crate::core::testing::run_isolated_test(test_name)
        || crate::config::Settings::rerun_test_unprivileged(test_name)
    {
        return;
    }
    assert!(
        !crate::core::is_root(),
        "catalog overrides require unprivileged caller"
    );
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    let db = root.join("var/lib/pacman");
    fs::create_dir_all(db.join("sync")).unwrap();
    fs::create_dir_all(db.join("local/widget-1")).unwrap();
    fs::write(db.join("local/ALPM_DB_VERSION"), "9\n").unwrap();
    fs::write(
        db.join("local/widget-1/desc"),
        "%NAME%\nwidget\n\n%VERSION%\n1-1\n\n%REASON%\n0\n",
    )
    .unwrap();
    let conf = temp.path().join("pacman.conf");
    fs::write(
        &conf,
        format!("[options]\nSigLevel = Never\nArchitecture = x86_64\n{repos}"),
    )
    .unwrap();
    let cache = temp.path().join("cache");
    let config_dir = temp.path().join("config");
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            crate::core::paths::reset_test_overrides();
            *write_lock(&SYNC_DB_CACHE) = DbCache::default();
            *write_lock(&LOCAL_DB_CACHE) = LocalDbCache::default();
            AFTER_LOCAL_PARSE.with(|hook| {
                hook.borrow_mut().take();
            });
        }
    }
    let _restore = Restore;
    crate::core::paths::set_test_overrides(Some(root), Some(db.clone()));
    temp_env::with_vars(
        [
            ("OMG_TEST_MODE", None),
            ("OMG_PACMAN_CONF", Some(conf.to_str().unwrap())),
            ("OMG_CACHE_DIR", Some(cache.to_str().unwrap())),
            ("OMG_CONFIG_DIR", Some(config_dir.to_str().unwrap())),
        ],
        || run(&db),
    );
}

#[test]
#[serial_test::serial]
fn batch2_empty_configuration_is_empty_repository_universe() {
    batch2_catalog_fixture(
        "package_managers::pacman_db::db::tests::batch2_empty_configuration_is_empty_repository_universe",
        "",
        |db| {
            batch2_write_sync(&db.join("sync/unconfigured.db"), "99-1");
            assert!(check_updates_cached().unwrap().is_empty());
            assert_eq!(
                get_potential_aur_package_records()
                    .unwrap()
                    .into_iter()
                    .map(|package| package.name)
                    .collect::<Vec<_>>(),
                ["widget"]
            );
        },
    );
}

#[test]
#[serial_test::serial]
fn foreign_package_records_keep_identity_and_groups_across_cache_refresh() {
    batch2_catalog_fixture(
        "package_managers::pacman_db::db::tests::foreign_package_records_keep_identity_and_groups_across_cache_refresh",
        "",
        |db| {
            let desc = db.join("local/widget-1/desc");
            fs::write(
                &desc,
                "%NAME%\nwidget\n\n%VERSION%\n1-1\n\n%REASON%\n0\n\n%GROUPS%\nreviewed-group\n",
            )
            .expect("write original private package metadata");
            let held = get_potential_aur_package_records().expect("original foreign records");
            assert_eq!(held.len(), 1);
            assert_eq!(held[0].name, "widget");
            assert_eq!(held[0].version.to_string(), "1-1");
            assert_eq!(held[0].groups, ["reviewed-group"]);
            assert_eq!(
                get_potential_aur_package_records()
                    .unwrap()
                    .into_iter()
                    .map(|package| package.name)
                    .collect::<Vec<_>>(),
                ["widget"]
            );

            fs::write(
                &desc,
                "%NAME%\nwidget\n\n%VERSION%\n2-1\n\n%REASON%\n0\n\n%GROUPS%\nnew-group\n",
            )
            .expect("replace private package metadata");
            invalidate_caches().expect("refresh private package catalogs");
            let fresh = get_potential_aur_package_records().expect("refreshed foreign records");
            assert_eq!(fresh.len(), 1);
            assert_eq!(fresh[0].name, "widget");
            assert_eq!(fresh[0].version.to_string(), "2-1");
            assert_eq!(fresh[0].groups, ["new-group"]);
            assert_eq!(
                get_potential_aur_package_records()
                    .unwrap()
                    .into_iter()
                    .map(|package| package.name)
                    .collect::<Vec<_>>(),
                ["widget"]
            );

            assert_eq!(held[0].name, "widget");
            assert_eq!(held[0].version.to_string(), "1-1");
            assert_eq!(held[0].groups, ["reviewed-group"]);
        },
    );
}

#[test]
#[serial_test::serial]
fn batch2_native_search_respects_usage() {
    batch2_catalog_fixture(
        "package_managers::pacman_db::db::tests::batch2_native_search_respects_usage",
        "[hidden]\nUsage = Sync Upgrade\n[visible]\nUsage = Search\n",
        |db| {
            batch2_write_sync(&db.join("sync/hidden.db"), "9-1");
            batch2_write_sync(&db.join("sync/visible.db"), "2-1");
            let matches = crate::package_managers::alpm_direct::search_sync("widget").unwrap();
            assert_eq!(
                matches.len(),
                1,
                "search must exclude repositories without Search usage"
            );
            assert_eq!(matches[0].repo, "visible");
            assert_eq!(get_detailed_packages().unwrap()[0].repo, "visible");
        },
    );
}

#[test]
#[serial_test::serial]
fn batch2_unreadable_local_desc_rejects_installed_and_counts() {
    batch2_catalog_fixture(
        "package_managers::pacman_db::db::tests::batch2_unreadable_local_desc_rejects_installed_and_counts",
        "",
        |db| {
            use std::os::unix::fs::PermissionsExt;
            let desc = db.join("local/widget-1/desc");
            fs::set_permissions(&desc, fs::Permissions::from_mode(0o000)).unwrap();
            let installed = crate::package_managers::alpm_direct::is_installed_fast("widget");
            let counts = get_counts_fast();
            fs::set_permissions(&desc, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(
                installed.is_err(),
                "unreadable installed package cannot become absence"
            );
            assert!(
                counts.is_err(),
                "unreadable local metadata cannot produce complete counts"
            );
        },
    );
}

#[test]
#[serial_test::serial]
fn batch2_updates_choose_lower_eligible_repository() {
    batch2_catalog_fixture(
        "package_managers::pacman_db::db::tests::batch2_updates_choose_lower_eligible_repository",
        "[testing]\nUsage = Sync Search\n[stable]\n",
        |db| {
            batch2_write_sync(&db.join("sync/testing.db"), "9-1");
            batch2_write_sync(&db.join("sync/stable.db"), "2-1");
            let updates = check_updates_cached().unwrap();
            assert_eq!(updates.len(), 1);
            assert_eq!(
                updates[0].repo, "stable",
                "Upgrade must select first eligible repository"
            );
            assert_eq!(updates[0].new_version.to_string(), "2-1");
            assert_eq!(get_detailed_packages().unwrap()[0].repo, "testing");
            assert_eq!(get_sync_package("widget").unwrap().unwrap().repo, "stable");
            assert_eq!(check_updates_cached().unwrap()[0].repo, "stable");
            temp_env::with_var("OMG_TEST_MODE", Some("1"), || {
                let projected = crate::package_managers::alpm_ops::get_update_list()
                    .expect("cached native upgrades");
                assert_eq!(projected.len(), 1);
                assert_eq!(projected[0].name, "widget");
                assert_eq!(projected[0].repo, "stable");
                assert_eq!(projected[0].new_version, "2-1");
                assert_eq!(projected[0].architecture, None);
            });
        },
    );
}

#[test]
#[serial_test::serial]
fn batch2_missing_required_repository_rejects_updates_and_foreign() {
    batch2_catalog_fixture(
        "package_managers::pacman_db::db::tests::batch2_missing_required_repository_rejects_updates_and_foreign",
        "[core]\n[extra]\n",
        |db| {
            batch2_write_sync(&db.join("sync/core.db"), "2-1");
            let updates = check_updates_cached();
            assert!(
                updates.is_err(),
                "incomplete update catalog succeeded: {updates:?}"
            );
            let foreign = get_potential_aur_package_records();
            assert!(
                foreign.is_err(),
                "incomplete foreign catalog succeeded: {foreign:?}"
            );
            batch2_write_sync(&db.join("sync/extra.db"), "3-1");
            assert_eq!(check_updates_cached().unwrap()[0].repo, "core");
            assert!(get_potential_aur_package_records().unwrap().is_empty());
        },
    );
}

#[test]
#[serial_test::serial]
fn batch2_missing_ineligible_repository_allows_updates_but_not_foreign() {
    batch2_catalog_fixture(
        "package_managers::pacman_db::db::tests::batch2_missing_ineligible_repository_allows_updates_but_not_foreign",
        "[testing]\nUsage = Search\n[stable]\n",
        |db| {
            batch2_write_sync(&db.join("sync/stable.db"), "2-1");
            assert_eq!(check_updates_cached().unwrap()[0].repo, "stable");
            let foreign = get_potential_aur_package_records();
            assert!(
                foreign.is_err(),
                "foreign requires every configured repository: {foreign:?}"
            );
        },
    );
}

#[test]
#[serial_test::serial]
fn batch2_absent_sync_directory_does_not_block_local_only_queries() {
    batch2_catalog_fixture(
        "package_managers::pacman_db::db::tests::batch2_absent_sync_directory_does_not_block_local_only_queries",
        "[core]\n",
        |db| {
            fs::remove_dir(db.join("sync")).unwrap();
            assert!(get_local_package("widget").unwrap().is_some());
            assert!(
                check_updates_cached().is_err(),
                "absent sync directory is not a complete configured universe"
            );
        },
    );
}

#[test]
#[serial_test::serial]
fn batch2_corrupt_high_priority_sync_entry_is_not_absence() {
    batch2_catalog_fixture(
        "package_managers::pacman_db::db::tests::batch2_corrupt_high_priority_sync_entry_is_not_absence",
        "[first]\n[second]\n",
        |db| {
            batch2_write_sync(&db.join("sync/first.db"), "not a version!!!");
            batch2_write_sync(&db.join("sync/second.db"), "2-1");
            let result = check_updates_cached();
            assert!(
                result.is_err(),
                "corrupt first repository fell through: {result:?}"
            );
        },
    );
}

#[test]
fn batch2_corrupt_local_entries_reject_complete_catalog() {
    for desc in [
        None,
        Some("%NAME%\nwidget\n\n%VERSION%\nnot a version!!!\n"),
        Some("%VERSION%\n1-1\n"),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let entry = temp.path().join("widget-1");
        fs::create_dir(&entry).unwrap();
        if let Some(desc) = desc {
            fs::write(entry.join("desc"), desc).unwrap();
        }
        let result = parse_local_db(temp.path());
        assert!(
            result.is_err(),
            "invalid local desc {desc:?} became successful absence: {result:?}"
        );
    }
}

#[test]
#[serial_test::serial]
fn batch2_local_parse_rejects_observed_epoch_change() {
    batch2_catalog_fixture(
        "package_managers::pacman_db::db::tests::batch2_local_parse_rejects_observed_epoch_change",
        "",
        |db| {
            let desc = db.join("local/widget-1/desc");
            AFTER_LOCAL_PARSE.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    fs::write(desc, "%NAME%\nwidget\n\n%VERSION%\n22-1\n\n").unwrap();
                }));
            });
            let result = get_local_package("widget");
            assert!(
                result.is_err(),
                "changed local snapshot was returned: {result:?}"
            );
            assert_eq!(
                get_local_package("widget")
                    .unwrap()
                    .unwrap()
                    .version
                    .to_string(),
                "22-1"
            );
        },
    );
}

#[test]
#[serial_test::serial]
fn sync_cache_cannot_reuse_metadata_from_before_complete_stream_validation() {
    batch2_catalog_fixture(
        "package_managers::pacman_db::db::tests::sync_cache_cannot_reuse_metadata_from_before_complete_stream_validation",
        "[core]\n",
        |db| {
            let source = db.join("sync/core.db");
            batch2_write_sync(&source, "2-1");
            let mut damaged = fs::read(&source).unwrap();
            let checksum = damaged.len() - 8;
            damaged[checksum] ^= 1;
            fs::write(&source, damaged).unwrap();
            let old = DbCache {
                packages: vec![RepositoryPackages {
                    name: "core".to_owned(),
                    usage: RepoUsage::all(),
                    packages: Ok(HashMap::from([(
                        "widget".to_owned(),
                        SyncDbPackage {
                            name: "widget".to_owned(),
                            version: require_package_version("2-1").unwrap(),
                            repo: "core".to_owned(),
                            ..SyncDbPackage::default()
                        },
                    )])),
                }],
                last_modified: Some(
                    SyncDbEpoch::from_configured_sync_dir(&db.join("sync")).unwrap(),
                ),
                ..DbCache::default()
            };
            let original = bitcode::serialize(&old).unwrap();
            save_cache_to_disk(&old, "sync_db_source_v3").unwrap();
            assert!(
                check_updates_cached().is_err(),
                "an older derived cache must not bless a source whose compression checksum has never been checked"
            );
            assert_eq!(
                fs::read(paths::cache_dir().join("sync_db_source_v3.bin")).unwrap(),
                original
            );
        },
    );
}

#[test]
#[serial_test::serial]
fn older_caches_cannot_skip_descriptor_cardinality_validation() {
    batch2_catalog_fixture(
        "package_managers::pacman_db::db::tests::older_caches_cannot_skip_descriptor_cardinality_validation",
        "[core]\n",
        |db| {
            let sync_dir = db.join("sync");
            let sync = "%NAME%\nwidget\n\n%VERSION%\n2-1\n\n%NAME%\nwidget\n\n";
            write_sync_identity_fixture(&sync_dir.join("core.db"), &[("widget-2-1/desc", sync)]);
            let old_sync = DbCache {
                packages: vec![RepositoryPackages {
                    name: "core".into(),
                    usage: RepoUsage::ALL,
                    packages: Ok(HashMap::from([(
                        "widget".into(),
                        SyncDbPackage {
                            name: "widget".into(),
                            version: require_package_version("2-1").unwrap(),
                            repo: "core".into(),
                            ..SyncDbPackage::default()
                        },
                    )])),
                }],
                last_modified: Some(SyncDbEpoch::from_configured_sync_dir(&sync_dir).unwrap()),
                ..DbCache::default()
            };
            save_cache_to_disk(&old_sync, "sync_db_source_v4").unwrap();
            let error = check_updates_cached().expect_err("validate source before showing updates");
            assert!(format!("{error:#}").contains("Duplicate descriptor section %NAME%"));

            let local_dir = db.join("local");
            fs::write(
                local_dir.join("widget-1/desc"),
                "%NAME%\nwidget\n\n%VERSION%\n1-1\n\n%NAME%\nwidget\n\n",
            )
            .unwrap();
            let old_local = LocalDbCache {
                packages: HashMap::from([(
                    "widget".into(),
                    LocalDbPackage {
                        name: "widget".into(),
                        version: require_package_version("1-1").unwrap(),
                        ..LocalDbPackage::default()
                    },
                )]),
                last_modified: Some(LocalDbEpoch::from_local_dir(&local_dir).unwrap()),
                ..LocalDbCache::default()
            };
            save_cache_to_disk(&old_local, "local_db_source_v4").unwrap();
            let error =
                get_local_package("widget").expect_err("validate installed source metadata");
            assert!(format!("{error:#}").contains("Duplicate descriptor section %NAME%"));
        },
    );
}

#[test]
#[serial_test::serial]
fn installed_info_uses_source_metadata_instead_of_derived_cache() {
    batch2_catalog_fixture(
        "package_managers::pacman_db::db::tests::installed_info_uses_source_metadata_instead_of_derived_cache",
        "",
        |db| {
            fs::write(
                db.join("local/widget-1/desc"),
                "%NAME%\nwidget\n\n%VERSION%\n1-1\n\n%DESC%\nsource description\n\n",
            )
            .unwrap();
            assert_eq!(
                get_local_package("widget").unwrap().unwrap().desc,
                "source description"
            );
            write_lock(&LOCAL_DB_CACHE)
                .packages
                .get_mut("widget")
                .unwrap()
                .desc = "untrusted derived metadata".to_owned();
            let info = crate::package_managers::alpm_direct::get_package_info("widget")
                .unwrap()
                .unwrap();
            assert_eq!(info.description, "source description");
            save_cache_to_disk(&*read_lock(&LOCAL_DB_CACHE), LOCAL_CACHE_NAME).unwrap();
            *write_lock(&LOCAL_DB_CACHE) = LocalDbCache::default();
            assert_eq!(
                get_local_package("widget").unwrap().unwrap().desc,
                "untrusted derived metadata"
            );
            let info = crate::package_managers::alpm_direct::get_package_info("widget")
                .unwrap()
                .unwrap();
            assert_eq!(info.description, "source description");
        },
    );
}

#[test]
#[serial_test::serial]
fn cached_updates_preserve_installed_ignore_groups_across_disk_reuse() {
    batch2_catalog_fixture(
        "package_managers::pacman_db::db::tests::cached_updates_preserve_installed_ignore_groups_across_disk_reuse",
        "IgnoreGroup = pinned\n[core]\n",
        |db| {
            for (groups, expected) in [("pinned", 0), ("other", 1), ("misc\npinned", 0)] {
                fs::write(
                    db.join("local/widget-1/desc"),
                    format!(
                        "%NAME%\nwidget\n\n%VERSION%\n1-1\n\n%REASON%\n0\n\n%GROUPS%\n{groups}\n\n"
                    ),
                )
                .unwrap();
                batch2_write_sync(&db.join("sync/core.db"), "2-1");
                invalidate_caches().unwrap();
                assert_eq!(
                    check_updates_cached().unwrap().len(),
                    expected,
                    "groups {groups:?}"
                );
                *write_lock(&LOCAL_DB_CACHE) = LocalDbCache::default();
                *write_lock(&SYNC_DB_CACHE) = DbCache::default();
                assert_eq!(
                    check_updates_cached().unwrap().len(),
                    expected,
                    "disk groups {groups:?}"
                );
            }
        },
    );
}

#[test]
#[serial_test::serial]
fn cached_updates_do_not_reuse_group_unaware_local_cache() {
    batch2_catalog_fixture(
        "package_managers::pacman_db::db::tests::cached_updates_do_not_reuse_group_unaware_local_cache",
        "IgnoreGroup = pinned\n[core]\n",
        |db| {
            fs::write(
                db.join("local/widget-1/desc"),
                "%NAME%\nwidget\n\n%VERSION%\n1-1\n\n%REASON%\n0\n\n%GROUPS%\npinned\n\n",
            )
            .unwrap();
            batch2_write_sync(&db.join("sync/core.db"), "2-1");
            let legacy = LocalDbCache {
                packages: HashMap::from([(
                    "widget".to_owned(),
                    LocalDbPackage {
                        name: "widget".to_owned(),
                        version: Version::from_str("1-1").unwrap(),
                        ..LocalDbPackage::default()
                    },
                )]),
                last_modified: Some(LocalDbEpoch::from_local_dir(&db.join("local")).unwrap()),
                ..LocalDbCache::default()
            };
            let bytes = bitcode::serialize(&legacy).unwrap();
            let cache_dir = paths::cache_dir();
            fs::create_dir_all(&cache_dir).unwrap();
            let old_path = cache_dir.join("local_db_source_v2.bin");
            fs::write(&old_path, &bytes).unwrap();
            assert!(
                check_updates_cached().unwrap().is_empty(),
                "old cache must not erase installed IgnoreGroup membership"
            );
            assert_eq!(fs::read(&old_path).unwrap(), bytes);
            assert!(cache_dir.join(format!("{LOCAL_CACHE_NAME}.bin")).is_file());
        },
    );
}

#[test]
#[serial_test::serial]
fn batch3_cached_updates_reject_nul_before_native_comparison() {
    batch2_catalog_fixture(
        "package_managers::pacman_db::db::tests::batch3_cached_updates_reject_nul_before_native_comparison",
        "[core]\n",
        |db| {
            for (installed, available) in [("1\0-1", "0:2-1"), ("1-1", "0:2\0-1")] {
                fs::write(
                    db.join("local/widget-1/desc"),
                    format!("%NAME%\nwidget\n\n%VERSION%\n{installed}\n\n%REASON%\n0\n"),
                )
                .unwrap();
                batch2_write_sync(&db.join("sync/core.db"), available);
                invalidate_caches().unwrap();
                let error =
                    check_updates_cached().expect_err("malformed versions must fail closed");
                assert!(
                    format!("{error:#}").contains("Invalid package version"),
                    "installed {installed:?}, available {available:?}: {error:#}"
                );
            }
        },
    );
}

#[test]
#[serial_test::serial]
fn batch2_cached_updates_preserve_optional_epoch_and_release_semantics() {
    batch2_catalog_fixture(
        "package_managers::pacman_db::db::tests::batch2_cached_updates_preserve_optional_epoch_and_release_semantics",
        "[core]\n",
        |db| {
            for (installed, available, expected_count) in [
                ("0:2.0-1", "3.0-1", 1),
                ("3.0-1", "0:2.0-1", 0),
                ("0:1.0-1", "1.0-1", 0),
                ("1.0-1", "0:1.0-1", 0),
                ("2.0-1", "0:3.0-1", 1),
                ("0:3.0-1", "2.0-1", 0),
                ("9.0-1", "1:1.0-1", 1),
                ("1:1.0-1", "0:9.0-1", 0),
                ("1.0", "1.0-1", 0),
                ("1.0-1", "1.0", 0),
                ("1.0", "2.0-1", 1),
                ("2.0-1", "1.0", 0),
                ("1.0-1", "2.0", 1),
                ("2.0", "1.0-1", 0),
            ] {
                fs::write(
                    db.join("local/widget-1/desc"),
                    format!("%NAME%\nwidget\n\n%VERSION%\n{installed}\n\n%REASON%\n0\n"),
                )
                .unwrap();
                batch2_write_sync(&db.join("sync/core.db"), available);
                invalidate_caches().unwrap();

                let result = check_updates_cached();
                if !available.contains('-') {
                    assert!(
                        result.is_err(),
                        "a sync archive without a release has no native package identity"
                    );
                    assert_eq!(
                        usize::from(
                            crate::package_managers::types::compare_versions(
                                &Version::from_str(installed).unwrap(),
                                &Version::from_str(available).unwrap(),
                            )
                            .is_lt()
                        ),
                        expected_count,
                        "standalone version semantics remain valid for {installed} / {available}"
                    );
                    continue;
                }
                let updates = result.unwrap();
                assert_eq!(
                    updates.len(),
                    expected_count,
                    "installed {installed}, available {available}: {updates:?}"
                );
                for update in updates {
                    assert_eq!(update.name, "widget");
                    assert_eq!(
                        update.old_version.to_string(),
                        installed.strip_prefix("0:").unwrap_or(installed)
                    );
                    assert_eq!(
                        update.new_version.to_string(),
                        available.strip_prefix("0:").unwrap_or(available)
                    );
                    assert_eq!(update.repo, "core");
                }
            }
        },
    );
}

/// Regression for ARCH-N1: `alpm_types::Version`'s `Ord` impl unwraps
/// `parse::<usize>()` on numeric segments above `usize::MAX` and panics
/// inside comparators reached from `check_updates_cached`. Ordering must
/// route through `compare_versions`, stay deterministic, and preserve
/// the upstream ordering for valid versions that fit in `usize`.
#[test]
fn version_comparison_with_overflow_numeric_segment_does_not_panic() {
    use std::cmp::Ordering;

    let huge = crate::package_managers::parse_version_or_zero("1.18446744073709551616-1");
    let one = crate::package_managers::parse_version_or_zero("1.0-1");
    let compare = |a: &alpm_types::Version, b: &alpm_types::Version| {
        crate::package_managers::types::compare_versions(a, b)
    };

    // Deterministic and antisymmetric on both sides of the overflow.
    assert_eq!(compare(&huge, &one), Ordering::Greater);
    assert_eq!(compare(&one, &huge), Ordering::Less);
    assert_eq!(compare(&huge, &one), compare(&huge, &one));
    assert_eq!(compare(&huge, &huge), Ordering::Equal);

    // Versions without overflowing segments must keep the exact
    // upstream ordering (the helper must be a pure passthrough there).
    let battery = ["1.0-1", "2.0", "1:2.3.4-5", "10.1-2", "1.10", "1.9"];
    for a in battery {
        for b in battery {
            let va = crate::package_managers::parse_version_or_zero(a);
            let vb = crate::package_managers::parse_version_or_zero(b);
            assert_eq!(compare(&va, &vb), va.cmp(&vb), "{a} vs {b}");
        }
    }
}

fn write_sync_identity_fixture(path: &Path, entries: &[(&str, &str)]) {
    let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::fast(),
    ));
    for (entry, content) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, entry, content.as_bytes())
            .unwrap();
    }
    fs::write(path, archive.into_inner().unwrap().finish().unwrap()).unwrap();
}

#[test]
fn sync_catalog_remains_readable_when_worker_creation_is_refused() {
    const TEST: &str = "package_managers::pacman_db::db::tests::sync_catalog_remains_readable_when_worker_creation_is_refused";
    if crate::config::Settings::rerun_test_unprivileged(TEST) {
        return;
    }
    if std::env::var_os("OMG_SYNC_THREAD_LIMIT_FIXTURE").is_some() {
        use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
        assert!(
            !nix::unistd::Uid::current().is_root(),
            "run resource-limit checks with the unprivileged fixture runner"
        );
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("core.db");
        write_sync_identity_fixture(
            &path,
            &[("helper-1-1/desc", "%NAME%\nhelper\n\n%VERSION%\n1-1\n")],
        );
        let saved = getrlimit(Resource::Nproc);
        setrlimit(
            Resource::Nproc,
            Rlimit {
                current: Some(0),
                maximum: saved.maximum,
            },
        )
        .expect("restrict only the fixture process's worker creation");
        let parsed = std::panic::catch_unwind(|| parse_sync_db(&path, "core"));
        setrlimit(Resource::Nproc, saved).expect("restore fixture process limit");
        let packages = parsed
            .expect("worker creation failure must not panic")
            .expect("metadata must remain readable without workers");
        assert_eq!(packages["helper"].version.to_string(), "1-1");
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "package_managers::pacman_db::db::tests::sync_catalog_remains_readable_when_worker_creation_is_refused",
            "--nocapture",
        ])
        .env("OMG_SYNC_THREAD_LIMIT_FIXTURE", "1")
        .output()
        .expect("isolated resource-limit fixture");
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn long_sync_paths_preserve_early_identity_rejection() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("core.db");
    let long_path = format!("{}-1-1/desc", "a".repeat(1024 * 1024));
    let desc = b"%NAME%\nhelper\n\n%VERSION%\n1-1\n";
    let mut archive = tar::Builder::new(Vec::new());
    for name in [long_path.as_str(), "later-1-1/desc"] {
        let mut header = tar::Header::new_gnu();
        header.set_size(desc.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, name, desc.as_slice())
            .unwrap();
    }
    let mut raw = archive.into_inner().unwrap();
    let later_header = tar::Archive::new(Cursor::new(&raw))
        .entries()
        .unwrap()
        .nth(1)
        .unwrap()
        .unwrap()
        .raw_header_position();
    raw[usize::try_from(later_header).unwrap() + 148] ^= 1;
    fs::write(&path, raw).unwrap();
    let error = parse_sync_db(&path, "core")
        .expect_err("an oversized path must be validated before buffering later records");
    assert!(
        format!("{error:#}").contains("Inconsistent package identity"),
        "long path buffering consumed the damaged later header first: {error:#}"
    );
}

#[test]
fn exact_sync_projection_preserves_complete_typed_and_manual_metadata() {
    let directory = tempfile::tempdir().expect("private mixed-format repository");
    let path = directory.path().join("extra.db");
    let v2 = typed_sync_projection_fixture("typed-v2", "1:2.3-01", false);
    let v1 = typed_sync_projection_fixture("typed-v1", "0:2.3-01", true);
    let manual = "%NAME%\nmanual\n\n%VERSION%\n2.3-01\n\n%PACKAGER%\nUnknown Packager\n\n%ISIZE%\n4096\n\n%CSIZE%\n1024\n\n%DEPENDS%\ntyped-v2>=1\n\n%LICENSE%\nMIT\n\n";
    alpm_repo_db::desc::RepoDescFileV2::from_str(&v2).expect("genuine complete V2 metadata");
    alpm_repo_db::desc::RepoDescFileV1::from_str(&v1).expect("genuine complete V1 metadata");
    assert!(alpm_repo_db::desc::RepoDescFileV2::from_str(&v1).is_err());
    write_sync_identity_fixture(
        &path,
        &[
            ("typed-v2-1:2.3-01/desc", &v2),
            ("typed-v1-0:2.3-01/desc", &v1),
            ("manual-2.3-01/desc", manual),
        ],
    );
    let all = parse_sync_db(&path, "extra").expect("full mixed-format repository");
    assert_eq!(all.len(), 3);
    for name in ["typed-v2", "typed-v1", "manual"] {
        let exact = parse_sync_db_package(&path, "extra", name)
            .expect("exact lookup validates every typed and manual record")
            .expect("selected package");
        assert_eq!(
            serde_json::to_value(&exact).expect("exact complete metadata"),
            serde_json::to_value(&all[name]).expect("original full metadata"),
            "every projected field and canonical version must match for {name}"
        );
        assert!(!exact.depends.is_empty());
        assert!(!exact.licenses.is_empty());
        assert_eq!(exact.repo, "extra");
    }
    assert_eq!(all["typed-v2"].version.to_string(), "1:2.3-1");
    assert_eq!(all["typed-v1"].version.to_string(), "2.3-1");
    assert_eq!(all["typed-v2"].groups, ["fixture-group"]);
    assert_eq!(all["typed-v2"].makedepends, ["cmake>=3"]);
    assert_eq!(all["typed-v2"].optdepends, ["optional: runtime support"]);
    assert_eq!(all["typed-v2"].provides, ["virtual-widget=1"]);
    assert_eq!(all["typed-v2"].conflicts, ["incompatible-widget<2"]);
    assert_eq!(all["typed-v2"].replaces, ["older-widget"]);
    assert!(
        parse_sync_db_package(&path, "extra", "absent")
            .expect("absence requires complete typed/manual validation")
            .is_none()
    );
}

fn typed_sync_projection_fixture(name: &str, version: &str, md5: bool) -> String {
    let file_version = version
        .rsplit(':')
        .next()
        .expect("version has a final component");
    let v1_fields = if md5 {
        // V1 requires PGPSIG. This is the pinned upstream schema's example packet.
        concat!(
            "%MD5SUM%\n0123456789abcdef0123456789abcdef\n\n%PGPSIG%\n",
            "iHUEABYKAB0WIQRizHP4hOUpV7L92IObeih9mi7GCAUCaBZuVAAKCRCbeih9mi7GCIlMAP9ws/jU4f580ZRQlTQKvUiLbAZOdcB7mQQj83hD1Nc/GwD/WIHhO1/OQkpMERejUrLo3AgVmY3b4/uGhx9XufWEbgE=\n\n",
        )
    } else {
        ""
    };
    format!(
        "%FILENAME%\n{name}-{file_version}-x86_64.pkg.tar.zst\n\n%NAME%\n{name}\n\n%BASE%\n{name}\n\n%VERSION%\n{version}\n\n%DESC%\nComplete typed metadata\n\n%GROUPS%\nfixture-group\n\n%CSIZE%\n1024\n\n%ISIZE%\n4096\n\n%SHA256SUM%\n0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\n{v1_fields}%URL%\nhttps://example.invalid/widget\n\n%LICENSE%\nMIT\n\n%ARCH%\nx86_64\n\n%BUILDDATE%\n1700000000\n\n%PACKAGER%\nOMG Fixture <fixture@example.invalid>\n\n%DEPENDS%\nglibc>=2.40\n\n%MAKEDEPENDS%\ncmake>=3\n\n%CHECKDEPENDS%\npytest\n\n%OPTDEPENDS%\noptional: runtime support\n\n%PROVIDES%\nvirtual-widget=1\n\n%CONFLICTS%\nincompatible-widget<2\n\n%REPLACES%\nolder-widget\n\n"
    )
}

#[test]
fn empty_repository_has_no_full_or_exact_package_matches() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("extra.db");
    write_sync_identity_fixture(&path, &[]);
    assert!(parse_sync_db(&path, "extra")?.is_empty());
    assert!(parse_sync_db_package(&path, "extra", "widget")?.is_none());
    Ok(())
}

#[test]
fn repository_fallback_rejects_repeated_descriptor_sections_and_values() {
    let directory = tempfile::tempdir().expect("private repository fixture");
    let path = directory.path().join("extra.db");
    for legacy in [false, true] {
        let descriptor = typed_sync_projection_fixture("widget", "1-1", legacy);
        for (malformed, expected) in [
            (
                format!("{descriptor}%NAME%\nwidget\n\n"),
                "Duplicate descriptor section %NAME%",
            ),
            (
                format!("{descriptor}%LICENSE%\nMIT\n\n"),
                "Duplicate descriptor section %LICENSE%",
            ),
            (
                descriptor.replace("%VERSION%\n1-1\n", "%VERSION%\n1-1\n1-1\n"),
                "Multiple values in descriptor section %VERSION%",
            ),
        ] {
            let upstream_rejected = if legacy {
                alpm_repo_db::desc::RepoDescFileV1::from_str(&malformed).is_err()
            } else {
                alpm_repo_db::desc::RepoDescFileV2::from_str(&malformed).is_err()
            };
            assert!(
                upstream_rejected,
                "upstream requires a single descriptor section"
            );
            write_sync_identity_fixture(&path, &[("widget-1-1/desc", &malformed)]);
            let all = parse_sync_db(&path, "extra").expect_err(expected);
            assert!(format!("{all:#}").contains(expected));
            let exact = parse_sync_db_package(&path, "extra", "widget").expect_err(expected);
            assert!(format!("{exact:#}").contains(expected));
        }
    }
}

#[test]
fn local_fallback_rejects_repeated_descriptor_sections_and_values() {
    let descriptor = "%NAME%\nwidget\n\n%VERSION%\n1-1\n\n%LICENSE%\nMIT\nBSD-2-Clause\n\n";
    let ordinary = parse_local_desc_content(descriptor).expect("valid sparse installed metadata");
    assert_eq!(ordinary.licenses, ["MIT", "BSD-2-Clause"]);
    for (malformed, expected) in [
        (
            format!("{descriptor}%NAME%\nwidget\n\n"),
            "Duplicate descriptor section %NAME%",
        ),
        (
            format!("{descriptor}%LICENSE%\nMIT\n\n"),
            "Duplicate descriptor section %LICENSE%",
        ),
        (
            descriptor.replace("%VERSION%\n1-1\n", "%VERSION%\n1-1\n1-1\n"),
            "Multiple values in descriptor section %VERSION%",
        ),
    ] {
        let error = parse_local_desc_content(&malformed).expect_err(expected);
        assert!(format!("{error:#}").contains(expected));
    }
}

#[test]
fn typed_sync_versions_enforce_the_project_nul_boundary() {
    let directory = tempfile::tempdir().expect("private typed-version repository");
    let path = directory.path().join("extra.db");
    let selected = typed_sync_projection_fixture("selected", "1-1", false);
    for v1 in [false, true] {
        let malformed = typed_sync_projection_fixture("unrelated", "1-1", v1)
            .replace("%VERSION%\n1-1", "%VERSION%\n1\0-1");
        // The pinned native grammar accepts ASCII NUL; OMG's shared
        // version boundary rejects it, including on typed-parser success.
        if v1 {
            alpm_repo_db::desc::RepoDescFileV1::from_str(&malformed)
                .expect("pinned V1 grammar accepts NUL in pkgver");
        } else {
            alpm_repo_db::desc::RepoDescFileV2::from_str(&malformed)
                .expect("pinned V2 grammar accepts NUL in pkgver");
        }
        assert!(require_package_version("1\0-1").is_err());
        write_sync_identity_fixture(
            &path,
            &[
                ("selected-1-1/desc", &selected),
                ("unrelated-1-1/desc", &malformed),
            ],
        );
        let full = parse_sync_db(&path, "extra")
            .expect_err("typed full catalog must apply the project version boundary");
        let exact = parse_sync_db_package(&path, "extra", "selected")
            .expect_err("selected target must not conceal an invalid typed version");
        assert!(
            format!("{full:#}").contains("Invalid package version"),
            "{full:#}"
        );
        assert_eq!(format!("{exact:#}"), format!("{full:#}"));
    }
}

#[test]
fn exact_sync_projection_rejects_unrelated_typed_failures_in_archive_order() {
    let directory = tempfile::tempdir().expect("private typed-corruption repository");
    let path = directory.path().join("extra.db");
    let selected = typed_sync_projection_fixture("selected", "1-1", false);
    let unrelated = typed_sync_projection_fixture("unrelated", "1-1", true);
    for (entry, content, diagnostic) in [
        (
            "unrelated-1-1/desc",
            unrelated.replace("%ISIZE%\n4096", "%ISIZE%\ninvalid"),
            "Invalid installed size",
        ),
        (
            "unrelated-1-1/desc",
            unrelated.replace("%VERSION%\n1-1", "%VERSION%\n1\0-1"),
            "Invalid package version",
        ),
        (
            "nested/unrelated-1-1/desc",
            unrelated.clone(),
            "Nested sync package directory identity",
        ),
        (
            "unrelated-2-1/desc",
            unrelated,
            "Inconsistent package identity",
        ),
        (
            "selected-1-1/desc",
            selected.clone(),
            "Duplicate package identity",
        ),
    ] {
        write_sync_identity_fixture(
            &path,
            &[("selected-1-1/desc", &selected), (entry, &content)],
        );
        let full = parse_sync_db(&path, "extra").expect_err("invalid full repository");
        let exact = parse_sync_db_package(&path, "extra", "selected")
            .expect_err("found target cannot conceal unrelated typed failure");
        assert!(format!("{exact:#}").contains(diagnostic), "{exact:#}");
        assert_eq!(format!("{exact:#}"), format!("{full:#}"));
    }
}

#[test]
fn exact_sync_lookup_matches_full_metadata_and_reports_absence() {
    let directory = tempfile::tempdir().expect("private exact lookup catalog");
    let path = directory.path().join("core.db");
    write_sync_identity_fixture(
        &path,
        &[
            ("other-1-1/desc", "%NAME%\nother\n\n%VERSION%\n1-1\n\n"),
            (
                "selected-2:3.4-5/desc",
                "%NAME%\nselected\n\n%VERSION%\n2:3.4-5\n\n%DESC%\nSelected complete metadata\n\n%ISIZE%\n4096\n\n%CSIZE%\n1024\n\n%DEPENDS%\nother>=1\n\n%LICENSE%\nMIT\n\n%URL%\nhttps://example.invalid/selected\n\n",
            ),
        ],
    );
    let mut all = parse_sync_db(&path, "core").expect("full validated catalog");
    let selected = parse_sync_db_package(&path, "core", "selected")
        .expect("exact validated lookup")
        .expect("selected package");
    assert_eq!(selected.name, "selected");
    assert_eq!(selected.version.to_string(), "2:3.4-5");
    assert_eq!(selected.depends, ["other>=1"]);
    assert_eq!(
        serde_json::to_value(selected).unwrap(),
        serde_json::to_value(all.remove("selected").unwrap()).unwrap()
    );
    assert!(
        parse_sync_db_package(&path, "core", "absent")
            .expect("absence only after the complete valid stream")
            .is_none()
    );
}

#[test]
fn exact_sync_lookup_rejects_unrelated_late_metadata_and_duplicates() {
    let directory = tempfile::tempdir().expect("private late-corruption catalog");
    let path = directory.path().join("core.db");
    let mut records = vec![(
        "selected-1-1/desc".to_owned(),
        "%NAME%\nselected\n\n%VERSION%\n1-1\n\n".to_owned(),
    )];
    records.extend((0..512).map(|index| {
        (
            format!("other-{index}-1-1/desc"),
            format!("%NAME%\nother-{index}\n\n%VERSION%\n1-1\n\n"),
        )
    }));
    for (entry, desc, diagnostic) in [
        (
            "broken-1-1/desc",
            "%NAME%\nbroken\n\n",
            "Missing package version",
        ),
        (
            "nested/broken-1-1/desc",
            "%NAME%\nbroken\n\n%VERSION%\n1-1\n\n",
            "Nested sync package directory identity",
        ),
        (
            "broken-2-1/desc",
            "%NAME%\nbroken\n\n%VERSION%\n1-1\n\n",
            "Inconsistent package identity",
        ),
        (
            "other-0-2-1/desc",
            "%NAME%\nother-0\n\n%VERSION%\n2-1\n\n",
            "Duplicate package identity",
        ),
    ] {
        let mut corrupt = records.clone();
        corrupt.push((entry.to_owned(), desc.to_owned()));
        write_sync_identity_fixture(
            &path,
            &corrupt
                .iter()
                .map(|(p, d)| (p.as_str(), d.as_str()))
                .collect::<Vec<_>>(),
        );
        let error = parse_sync_db_package(&path, "core", "selected")
            .expect_err("a found target cannot conceal later invalid unrelated metadata");
        assert!(
            format!("{error:#}").contains(diagnostic),
            "{entry}: {error:#}"
        );
    }
}

#[test]
fn exact_sync_lookup_checks_late_utf8_and_compression_footer() {
    let directory = tempfile::tempdir().expect("private complete-stream lookup");
    let path = directory.path().join("core.db");
    let target = "%NAME%\nselected\n\n%VERSION%\n1-1\n\n";
    write_sync_identity_fixture(&path, &[("selected-1-1/desc", target)]);
    let mut compressed = fs::read(&path).expect("valid small gzip catalog");
    let crc = compressed.len() - 8;
    compressed[crc] ^= 1;
    fs::write(&path, compressed).expect("corrupt only the gzip footer");
    parse_sync_db_package(&path, "core", "selected")
        .expect_err("TAR termination after target must not conceal corrupt gzip CRC");
    let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::fast(),
    ));
    for (entry, bytes) in [
        ("selected-1-1/desc", target.as_bytes()),
        (
            "broken-1-1/desc",
            b"%NAME%\nbroken\n\n%VERSION%\n1-1\n\n%DESC%\n\xff\n".as_slice(),
        ),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, entry, bytes)
            .expect("small bounded archive member");
    }
    fs::write(&path, archive.into_inner().unwrap().finish().unwrap())
        .expect("late invalid UTF-8 catalog");
    let error = parse_sync_db_package(&path, "core", "selected")
        .expect_err("selected package cannot hide unrelated UTF-8 failure");
    assert!(error.downcast_ref::<std::string::FromUtf8Error>().is_some());
}

#[test]
fn large_sync_catalog_preserves_all_records_and_rejects_late_corruption() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("core.db");
    let entries: Vec<_> = (0..129)
        .map(|index| {
            let name = format!("package-{index}");
            (
                format!("{name}-1-1/desc"),
                format!(
                    "%NAME%\n{name}\n\n%VERSION%\n1-1\n\n%DESC%\n{}\n\n",
                    "catalog description ".repeat(900)
                ),
            )
        })
        .collect();
    let write = |records: &[(String, String)]| {
        write_sync_identity_fixture(
            &path,
            &records
                .iter()
                .map(|(path, desc)| (path.as_str(), desc.as_str()))
                .collect::<Vec<_>>(),
        );
    };
    write(&entries);
    let packages = parse_sync_db(&path, "core").expect("complete large catalog");
    assert_eq!(packages.len(), entries.len());
    for index in 0..entries.len() {
        assert_eq!(
            packages[&format!("package-{index}")].version.to_string(),
            "1-1"
        );
    }

    for (replacement, diagnostic) in [
        (entries[0].clone(), "Duplicate package identity"),
        (
            (
                "package-128-1-1/desc".into(),
                "%NAME%\npackage-128\n".into(),
            ),
            "Missing package version",
        ),
        (
            ("nested/package-128-1-1/desc".into(), entries[128].1.clone()),
            "Nested sync package directory identity",
        ),
    ] {
        let mut corrupted = entries.clone();
        corrupted[128] = replacement;
        write(&corrupted);
        let error = parse_sync_db(&path, "core")
            .expect_err("late corruption must reject the entire catalog");
        assert!(format!("{error:#}").contains(diagnostic), "{error:#}");
    }
}

#[test]
fn sync_archive_identity_refuses_conflicting_names_versions_and_duplicates() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("core.db");
    for entries in [
        vec![(
            "nested/actual-1-1/desc",
            "%NAME%\nnested/actual\n\n%VERSION%\n1-1\n",
        )],
        vec![("actual-1-1/desc", "%NAME%\nother\n\n%VERSION%\n1-1\n")],
        vec![("actual-1-1/desc", "%NAME%\nactual\n\n%VERSION%\n2-1\n")],
        vec![
            ("actual-1-1/desc", "%NAME%\nactual\n\n%VERSION%\n1-1\n"),
            ("actual-2-1/desc", "%NAME%\nactual\n\n%VERSION%\n2-1\n"),
        ],
    ] {
        write_sync_identity_fixture(&path, &entries);
        assert!(
            parse_sync_db(&path, "core").is_err(),
            "accepted {entries:?}"
        );
    }
    for version in ["1-1", "1:2-01", "2:1.0-3"] {
        let entry = format!("actual-package-{version}/desc");
        let desc = format!("%NAME%\nactual-package\n\n%VERSION%\n{version}\n");
        write_sync_identity_fixture(&path, &[(&entry, &desc)]);
        assert!(
            parse_sync_db(&path, "core")
                .unwrap()
                .contains_key("actual-package")
        );
    }
}

#[test]
fn sync_archive_identity_reports_invalid_package_names_at_the_flat_entry() {
    use std::os::unix::fs::PermissionsExt;

    let owner = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("private sync archive owner");
    let path = owner.path().join("audit-repo.db");
    let entry = "actual-1-1/desc";
    for name in ["bad/name", "bad name"] {
        let description = format!("%NAME%\n{name}\n\n%VERSION%\n1-1\n");
        write_sync_identity_fixture(&path, &[(entry, &description)]);
        let error = parse_sync_db(&path, "audit-repo")
            .expect_err("an invalid package name must refuse the flat sync entry");
        assert_eq!(
            error.to_string(),
            "Invalid package name in actual-1-1/desc from repository audit-repo",
            "invalid name {name:?} must identify its archive entry and repository"
        );
    }
}

#[test]
#[serial_test::serial]
fn sync_archive_identity_does_not_reuse_unvalidated_legacy_cache() {
    batch2_catalog_fixture(
        "package_managers::pacman_db::db::tests::sync_archive_identity_does_not_reuse_unvalidated_legacy_cache",
        "[core]\n",
        |db| {
            write_sync_identity_fixture(
                &db.join("sync/core.db"),
                &[("actual-1-1/desc", "%NAME%\nother\n\n%VERSION%\n1-1\n")],
            );
            let legacy = DbCache {
                packages: vec![RepositoryPackages {
                    name: "core".to_owned(),
                    usage: RepoUsage::ALL,
                    packages: Ok(HashMap::from([(
                        "widget".to_owned(),
                        SyncDbPackage {
                            name: "widget".to_owned(),
                            repo: "core".to_owned(),
                            version: Version::from_str("2-1").unwrap(),
                            ..SyncDbPackage::default()
                        },
                    )])),
                }],
                last_modified: Some(
                    SyncDbEpoch::from_configured_sync_dir(&db.join("sync")).unwrap(),
                ),
                ..DbCache::default()
            };
            save_cache_to_disk_in(&legacy, &paths::cache_dir(), "sync_db_source_v2").unwrap();
            assert!(
                check_updates_cached().is_err(),
                "old cache must not conceal inconsistent source identities"
            );
        },
    );
}

#[test]
fn sync_database_fifo_is_refused_without_waiting_for_a_writer() {
    const TEST: &str = "package_managers::pacman_db::db::tests::sync_database_fifo_is_refused_without_waiting_for_a_writer";
    if crate::core::testing::run_isolated_test_with_timeout(TEST, std::time::Duration::from_secs(1))
    {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("core.db");
    nix::unistd::mkfifo(
        &path,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .expect("create the nonregular repository database fixture");
    let error = parse_sync_db(&path, "core").expect_err("reject a FIFO with no writer");
    assert!(format!("{error:#}").contains("regular"));
}

#[test]
fn rust_sync_metadata_preserves_native_bzip2_repository_support() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("root");
    let database = directory.path().join("db");
    fs::create_dir(&root)?;
    fs::create_dir_all(database.join("local"))?;
    fs::create_dir(database.join("sync"))?;
    fs::write(database.join("local/ALPM_DB_VERSION"), "9\n")?;
    let compressed = [
        66, 90, 104, 57, 49, 65, 89, 38, 83, 89, 55, 125, 43, 15, 0, 0, 177, 95, 128, 204, 144, 66,
        3, 255, 3, 47, 103, 221, 16, 127, 173, 94, 114, 4, 8, 48, 0, 185, 33, 170, 102, 166, 147,
        212, 211, 212, 0, 61, 65, 163, 65, 181, 27, 77, 70, 77, 27, 72, 208, 195, 67, 64, 0, 0,
        104, 0, 0, 0, 1, 37, 33, 161, 26, 100, 104, 208, 3, 65, 160, 0, 13, 3, 77, 177, 85, 11, 1,
        4, 45, 16, 33, 235, 80, 12, 172, 235, 200, 16, 192, 109, 20, 252, 130, 94, 87, 6, 64, 5,
        164, 18, 83, 97, 250, 39, 89, 231, 112, 219, 93, 42, 153, 28, 99, 21, 158, 209, 187, 38,
        73, 146, 91, 165, 67, 113, 196, 192, 107, 142, 231, 245, 150, 84, 44, 96, 228, 184, 213,
        206, 93, 163, 114, 216, 210, 130, 23, 4, 52, 55, 95, 25, 220, 107, 228, 138, 19, 10, 78,
        20, 84, 13, 78, 46, 176, 35, 57, 226, 50, 141, 147, 46, 43, 193, 38, 9, 143, 131, 5, 100,
        255, 84, 204, 5, 108, 136, 93, 97, 223, 117, 160, 78, 235, 70, 55, 156, 126, 3, 188, 46,
        91, 27, 80, 76, 31, 171, 5, 69, 231, 240, 36, 131, 248, 187, 146, 41, 194, 132, 129, 187,
        233, 88, 120,
    ];
    let source = database.join("sync/core.db");
    fs::write(&source, compressed)?;
    let native = alpm::Alpm::new(root.to_str().unwrap(), database.to_str().unwrap())?;
    let repository = native.register_syncdb("core", alpm::SigLevel::NONE)?;
    assert_eq!(repository.pkg("fixture")?.version().to_string(), "1-1");
    let parsed = parse_sync_db(&source, "core")
        .expect("Rust metadata must preserve native bzip2 database support");
    let package = parsed.get("fixture").unwrap();
    assert_eq!((package.csize, package.isize), (12, 34));
    assert_eq!(package.depends, ["glibc>=2"]);
    let info =
        crate::package_managers::alpm_ops::get_pkg_info_from_db(&native, "fixture")?.unwrap();
    assert_eq!(info.version.to_string(), "1-1");
    assert_eq!(
        (info.download_size, info.install_size),
        (Some(12), Some(34))
    );
    fs::write(&source, &compressed[..compressed.len() - 4])?;
    parse_sync_db(&source, "core")
        .expect_err("truncated bzip2 footer must not hide behind tar EOF");
    let mut raw = Vec::new();
    bzip2::read::MultiBzDecoder::new(compressed.as_slice()).read_to_end(&mut raw)?;
    let mut joined = Vec::new();
    for segment in [&raw[..512], &raw[512..]] {
        let mut member = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
        member.write_all(segment)?;
        joined.extend(member.finish()?);
    }
    fs::write(&source, &joined)?;
    assert_eq!(
        parse_sync_db(&source, "core")?
            .get("fixture")
            .unwrap()
            .csize,
        12
    );
    joined.truncate(joined.len() - 4);
    fs::write(&source, joined)?;
    parse_sync_db(&source, "core")
        .expect_err("each concatenated bzip2 member must finish validation");
    Ok(())
}

#[test]
fn sync_database_checks_compression_footer_after_tar_end() {
    let directory = tempfile::tempdir().unwrap();
    let mut archive = tar::Builder::new(Vec::new());
    let desc = b"%NAME%\nfixture\n\n%VERSION%\n1-1\n\n";
    let mut header = tar::Header::new_gnu();
    header.set_size(desc.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive
        .append_data(&mut header, "fixture-1-1/desc", desc.as_slice())
        .unwrap();
    let raw = archive.into_inner().unwrap();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gzip.write_all(&raw).unwrap();
    let mut compressed = gzip.finish().unwrap();
    let path = directory.path().join("core.db");
    fs::write(&path, &compressed).unwrap();
    assert!(
        parse_sync_db(&path, "core")
            .unwrap()
            .contains_key("fixture")
    );
    let crc = compressed.len() - 8;
    compressed[crc] ^= 1;
    fs::write(&path, compressed).unwrap();
    parse_sync_db(&path, "core")
        .expect_err("a valid tar terminator must not hide a corrupted compression checksum");
}

/// Regression: the compression-format probe must rewind the stream before
/// handing it to a decoder. It previously consumed the first 4 bytes, so
/// every real sync database failed to parse ("invalid gzip header" /
/// "zstd init: BadMagicNumber").
#[test]
fn parse_sync_db_handles_gzip_and_zstd_after_magic_probe() {
    let temp = tempfile::TempDir::new().unwrap();

    // Modeled on a real core.db desc entry (single-percent sections).
    let desc = b"%FILENAME%\nbash-5.3.15-1-x86_64.pkg.tar.zst\n\n\
%NAME%\nbash\n\n\
%BASE%\nbash\n\n\
%VERSION%\n5.3.15-1\n\n\
%DESC%\nThe GNU Bourne Again shell\n\n\
%CSIZE%\n150821\n\n\
%ISIZE%\n353496\n\n\
%SHA256SUM%\ndca9ec50cf51243b86a67367a55e78b1851d31240b1edaf9c011f8511765d999\n\n\
%URL%\nhttps://www.gnu.org/software/bash/\n\n\
%LICENSE%\nGPL-3.0-or-later\n\n\
%ARCH%\nx86_64\n\n\
%BUILDDATE%\n1700000000\n\n\
%PACKAGER%\nArch Linux <archlinux@archlinux.org>\n\n";

    let build_tar = || -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(desc.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "bash-5.3.15-1/desc", &desc[..])
            .unwrap();
        tar.into_inner().unwrap()
    };
    let raw = build_tar();

    let mut gzip_bytes = Vec::new();
    flate2::write::GzEncoder::new(&mut gzip_bytes, flate2::Compression::fast())
        .write_all(&raw)
        .unwrap();
    let gzip_path = temp.path().join("core.db");
    std::fs::write(&gzip_path, &gzip_bytes).unwrap();
    let parsed = parse_sync_db(&gzip_path, "core").expect("gzip db must parse after probe");
    assert!(
        parsed.contains_key("bash"),
        "bash must be found, got keys {:?}",
        parsed.keys()
    );

    let zstd_bytes = zstd::stream::encode_all(&raw[..], 3).unwrap();
    let mut xz_bytes = Vec::new();
    lzma_rs::xz_compress(&mut Cursor::new(&raw), &mut xz_bytes).unwrap();
    let mut lz4_encoder = lz4_flex::frame::FrameEncoder::new(Vec::new());
    lz4_encoder.write_all(&raw).unwrap();
    let lz4_bytes = lz4_encoder.finish().unwrap();
    let mut bzip2 = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
    bzip2.write_all(&raw).unwrap();
    let bzip2_bytes = bzip2.finish().unwrap();

    for (name, bytes) in [
        ("bzip2", bzip2_bytes),
        ("zstd", zstd_bytes),
        ("xz", xz_bytes),
        ("lz4", lz4_bytes),
        ("raw tar", raw),
    ] {
        let path = temp.path().join(format!("{name}.db"));
        std::fs::write(&path, bytes).unwrap();
        let parsed = parse_sync_db(&path, "custom")
            .unwrap_or_else(|error| panic!("{name} db must parse: {error:#}"));
        assert!(parsed.contains_key("bash"), "{name} db omitted bash");
    }

    let unknown = temp.path().join("unknown.db");
    std::fs::write(&unknown, b"not an archive").unwrap();
    let error = parse_sync_db(&unknown, "unknown").unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Unsupported pacman database compression")
    );
}

#[test]
fn parse_sync_db_accepts_sha256_checked_xz() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("fixture.db");
    std::fs::write(
        &path,
        include_bytes!("../../../tests/data/xz-subset/pacman-sync-sha256.db.xz"),
    )
    .expect("write repository database");
    let packages = parse_sync_db(&path, "fixture").expect("decode SHA-256 checked database");
    assert_eq!(packages.len(), 1);
    assert_eq!(packages["fixture"].name, "fixture");
}

#[test]
fn malformed_sync_package_rejects_incomplete_repository() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("custom.db");
    let invalid = b"%NAME%\nbroken\n\n%VERSION%\nnot a version!!!\n\n";
    let valid = b"%NAME%\ngood\n\n%VERSION%\n1.0-1\n\n";

    let mut tar = tar::Builder::new(Vec::new());
    for (entry_path, content) in [
        ("broken-1/desc", invalid.as_slice()),
        ("good-1.0-1/desc", valid.as_slice()),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, entry_path, content).unwrap();
    }
    let raw = tar.into_inner().unwrap();
    let mut compressed = Vec::new();
    {
        let mut encoder =
            flate2::write::GzEncoder::new(&mut compressed, flate2::Compression::fast());
        encoder.write_all(&raw).unwrap();
        encoder.finish().unwrap();
    }
    std::fs::write(&path, compressed).unwrap();

    let error = parse_sync_db(&path, "custom").unwrap_err();
    assert_eq!(
        error.to_string(),
        "Malformed desc broken-1/desc from repository custom"
    );
    assert!(format!("{error:#}").contains("broken-1/desc"));
    assert!(format!("{error:#}").contains("Invalid package version"));
}

#[test]
fn malformed_sync_desc_rejects_repository_with_healthy_package() {
    let cases: [(&str, &[u8], &str); 3] = [
        (
            "invalid-utf8",
            b"%NAME%\nbroken\n\n%VERSION%\n1-1\n\n%DESC%\n\xff\n",
            "Invalid UTF-8",
        ),
        (
            "absent-name",
            b"%VERSION%\n1-1\n\n%DESC%\nNameless package\n",
            "Missing package name",
        ),
        (
            "empty-name",
            b"%NAME%\n\n%VERSION%\n1-1\n\n",
            "Missing package name",
        ),
    ];
    let temp = tempfile::tempdir().unwrap();
    let healthy = b"%NAME%\nhealthy\n\n%VERSION%\n1-1\n\n";
    for (case, malformed, diagnostic) in cases {
        let path = temp.path().join(format!("{case}.db"));
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        for (entry, content) in [
            ("healthy-1-1/desc", healthy.as_slice()),
            ("broken-1-1/desc", malformed),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(&mut header, entry, content).unwrap();
        }
        fs::write(&path, archive.into_inner().unwrap().finish().unwrap()).unwrap();

        let error = parse_sync_db(&path, "custom")
            .expect_err("a healthy package must not conceal malformed repository metadata");
        let message = format!("{error:#}");
        assert!(message.contains(diagnostic), "{case}: {message}");
        assert!(message.contains("broken-1-1/desc"), "{case}: {message}");
        assert!(message.contains("repository custom"), "{case}: {message}");
        if case == "invalid-utf8" {
            assert!(
                error.downcast_ref::<std::string::FromUtf8Error>().is_some(),
                "invalid UTF-8 must retain its decoding cause: {message}"
            );
        }
    }
}

#[test]
fn truncated_sync_desc_payload_retains_entry_and_repository_context() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("custom.db");
    let desc = b"%NAME%\nwidget\n\n%VERSION%\n1-1\n\n";
    let mut tar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(desc.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, "widget-1/desc", desc.as_slice())
        .unwrap();
    let raw = tar.into_inner().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let partial_desc_end = header.as_bytes().len() + desc.len() / 2;
    encoder.write_all(&raw[..partial_desc_end]).unwrap();
    encoder.flush().unwrap();
    let truncated_len = encoder.get_ref().len();
    encoder.write_all(&raw[partial_desc_end..]).unwrap();
    let mut compressed = encoder.finish().unwrap();
    compressed.truncate(truncated_len);
    fs::write(&path, compressed).unwrap();

    let error = parse_sync_db(&path, "custom")
        .expect_err("an interrupted desc payload must reject the repository snapshot");
    assert_eq!(
        error.to_string(),
        "Failed to read desc widget-1/desc from repo custom"
    );
    assert!(
        error.chain().any(|cause| cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|cause| cause.kind() == std::io::ErrorKind::UnexpectedEof)),
        "the truncated compressed payload must retain its I/O cause: {error:#}"
    );
}

#[test]
fn utf8_sync_desc_missing_required_version_retains_repository_context() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("custom.db");
    let desc = "%NAME%\nwidget\n\n%DESC%\nValid UTF-8 description\n\n";
    let mut tar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(desc.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, "widget-1/desc", desc.as_bytes())
        .unwrap();
    let raw = tar.into_inner().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&raw).unwrap();
    fs::write(&path, encoder.finish().unwrap()).unwrap();

    let error = parse_sync_db(&path, "custom")
        .expect_err("valid UTF-8 cannot make a desc without a package version complete");
    assert_eq!(
        error.to_string(),
        "Malformed desc widget-1/desc from repository custom"
    );
    assert!(format!("{error:#}").contains("Missing package version in repository custom"));
}

#[test]
fn oversized_sync_and_local_desc_are_rejected_before_materialization() {
    let temp = tempfile::tempdir().unwrap();
    let oversized = vec![b'a'; MAX_DESC_BYTES as usize + 1];
    let mut tar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(oversized.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, "oversized-1/desc", oversized.as_slice())
        .unwrap();
    let raw = tar.into_inner().unwrap();
    let mut compressed = Vec::new();
    flate2::write::GzEncoder::new(&mut compressed, flate2::Compression::fast())
        .write_all(&raw)
        .unwrap();
    let sync_path = temp.path().join("oversized.db");
    std::fs::write(&sync_path, compressed).unwrap();
    assert!(
        format!("{:#}", parse_sync_db(&sync_path, "oversized").unwrap_err())
            .contains("desc exceeds")
    );

    let local_path = temp.path().join("desc");
    std::fs::write(&local_path, oversized).unwrap();
    assert!(format!("{:#}", parse_local_desc(&local_path).unwrap_err()).contains("desc exceeds"));
}

#[test]
fn cached_update_filters_honour_ignored_packages_and_groups() {
    let mut package = SyncDbPackage {
        name: "linux".to_string(),
        groups: vec!["kernel".to_string()],
        ..SyncDbPackage::default()
    };
    let packages = compile_package_patterns(&["linux".to_string()], "IgnorePkg").unwrap();
    let groups = compile_package_patterns(&["kernel".to_string()], "IgnoreGroup").unwrap();
    let none = compile_package_patterns(&[], "empty").unwrap();
    assert!(package_is_ignored(
        &package.name,
        &package.groups,
        &packages,
        &none
    ));
    assert!(package_is_ignored(
        &package.name,
        &package.groups,
        &none,
        &groups
    ));
    let base = compile_package_patterns(&["base".to_string()], "IgnoreGroup").unwrap();
    assert!(!package_is_ignored(
        &package.name,
        &package.groups,
        &none,
        &base
    ));

    package.name = "linux-zen".to_string();
    package.groups = vec!["kernel-zen".to_string()];
    let packages = compile_package_patterns(&["linux-*".to_string()], "IgnorePkg").unwrap();
    let groups = compile_package_patterns(&["kernel-*".to_string()], "IgnoreGroup").unwrap();
    assert!(package_is_ignored(
        &package.name,
        &package.groups,
        &packages,
        &none
    ));
    assert!(package_is_ignored(
        &package.name,
        &package.groups,
        &none,
        &groups
    ));
}

#[test]
#[serial_test::serial]
fn sync_database_order_follows_pacman_configuration() {
    if crate::core::testing::run_isolated_test(
        "package_managers::pacman_db::db::tests::sync_database_order_follows_pacman_configuration",
    ) {
        return;
    }
    if crate::config::Settings::rerun_test_unprivileged(
        "package_managers::pacman_db::db::tests::sync_database_order_follows_pacman_configuration",
    ) {
        return;
    }
    assert!(
        !crate::core::is_root(),
        "caller path fixture must not run as root"
    );
    let temp_dir = tempfile::tempdir().unwrap();
    std::fs::write(temp_dir.path().join("core.db"), b"core").unwrap();
    std::fs::write(temp_dir.path().join("custom.db"), b"custom").unwrap();
    let config = temp_dir.path().join("pacman.conf");
    std::fs::write(
        &config,
        "[options]\n[custom]\nServer = https://custom.example/$repo/$arch\n[core]\nServer = https://core.example/$repo/$arch\n",
    )
    .unwrap();

    temp_env::with_var("OMG_PACMAN_CONF", Some(config.as_os_str()), || {
        let names = collect_sync_db_paths(temp_dir.path())
            .unwrap()
            .into_iter()
            .map(|(_, name)| name)
            .collect::<Vec<_>>();
        assert_eq!(names, ["custom", "core"]);
    });
    println!(
        "[omg-config-fixture] test=package_managers::pacman_db::db::tests::sync_database_order_follows_pacman_configuration uid={}",
        nix::unistd::geteuid()
    );
}

#[test]
#[serial_test::serial]
fn test_collect_sync_db_paths_excludes_sig_files() {
    if crate::core::testing::run_isolated_test(
        "package_managers::pacman_db::db::tests::test_collect_sync_db_paths_excludes_sig_files",
    ) {
        return;
    }
    if crate::config::Settings::rerun_test_unprivileged(
        "package_managers::pacman_db::db::tests::test_collect_sync_db_paths_excludes_sig_files",
    ) {
        return;
    }
    assert!(
        !crate::core::is_root(),
        "caller path fixture must not run as root"
    );
    let temp_dir = tempfile::TempDir::new().unwrap();
    let config = temp_dir.path().join("pacman.conf");
    std::fs::write(
        &config,
        "[options]\n[core]\nServer = https://core.example/$repo/$arch\n[extra]\nServer = https://extra.example/$repo/$arch\n[custom-repo]\nServer = https://custom.example/$repo/$arch\n",
    )
    .unwrap();

    std::fs::write(temp_dir.path().join("core.db"), b"dummy").unwrap();
    std::fs::write(temp_dir.path().join("core.db.sig"), b"signature").unwrap();
    std::fs::write(temp_dir.path().join("extra.db"), b"dummy").unwrap();
    std::fs::write(temp_dir.path().join("extra.db.sig"), b"signature").unwrap();
    std::fs::write(temp_dir.path().join("custom-repo.db"), b"dummy").unwrap();
    std::fs::write(temp_dir.path().join("custom-repo.db.sig"), b"signature").unwrap();
    std::fs::write(temp_dir.path().join("not-a-db.txt"), b"text").unwrap();

    let db_paths = temp_env::with_var("OMG_PACMAN_CONF", Some(config.as_os_str()), || {
        collect_sync_db_paths(temp_dir.path()).unwrap()
    });

    let collected_names: Vec<_> = db_paths
        .iter()
        .map(|(path, _)| path.file_name().unwrap().to_str().unwrap())
        .collect();

    assert!(
        collected_names.contains(&"core.db"),
        "Should include core.db"
    );
    assert!(
        collected_names.contains(&"extra.db"),
        "Should include extra.db"
    );
    assert!(
        collected_names.contains(&"custom-repo.db"),
        "Should include custom-repo.db"
    );
    assert!(
        !collected_names.contains(&"core.db.sig"),
        "Should NOT include .sig files"
    );
    assert!(
        !collected_names.contains(&"extra.db.sig"),
        "Should NOT include .sig files"
    );
    assert!(
        !collected_names.contains(&"custom-repo.db.sig"),
        "Should NOT include .sig files"
    );
    assert!(
        !collected_names.contains(&"not-a-db.txt"),
        "Should NOT include non-.db files"
    );
    println!(
        "[omg-config-fixture] test=package_managers::pacman_db::db::tests::test_collect_sync_db_paths_excludes_sig_files uid={}",
        nix::unistd::geteuid()
    );
}

#[test]
fn test_collect_sync_db_paths_missing_dir_is_empty() {
    let missing = tempfile::TempDir::new()
        .unwrap()
        .path()
        .join("does-not-exist");
    let db_paths = collect_sync_db_paths(&missing).unwrap();
    assert!(db_paths.is_empty());
}

#[cfg(unix)]
#[test]
#[serial_test::serial]
fn test_collect_sync_db_paths_unreadable_dir_errors() {
    if crate::core::testing::run_isolated_test(
        "package_managers::pacman_db::db::tests::test_collect_sync_db_paths_unreadable_dir_errors",
    ) {
        return;
    }
    if crate::config::Settings::rerun_test_unprivileged(
        "package_managers::pacman_db::db::tests::test_collect_sync_db_paths_unreadable_dir_errors",
    ) {
        return;
    }
    assert!(
        !crate::core::is_root(),
        "permission fixture must not run as root"
    );
    let config_dir = tempfile::TempDir::new().unwrap();
    let config = config_dir.path().join("pacman.conf");
    std::fs::write(
        &config,
        "[options]\n[core]\nServer = https://core.example/$repo/$arch\n",
    )
    .unwrap();
    let temp_dir = tempfile::TempDir::new().unwrap();
    let original = std::fs::metadata(temp_dir.path()).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(temp_dir.path(), std::fs::Permissions::from_mode(0o000)).unwrap();
    let denied =
        std::fs::read_dir(temp_dir.path()).expect_err("fixture must enforce permission denial");
    assert_eq!(denied.kind(), std::io::ErrorKind::PermissionDenied);
    println!(
        "[omg-permission-fixture] test=package_managers::pacman_db::db::tests::test_collect_sync_db_paths_unreadable_dir_errors uid={} errno=PermissionDenied",
        nix::unistd::geteuid()
    );
    let result = temp_env::with_var("OMG_PACMAN_CONF", Some(config.as_os_str()), || {
        collect_sync_db_paths(temp_dir.path())
    });
    std::fs::set_permissions(temp_dir.path(), original).expect("restore fixture permissions");
    let error = result.expect_err("unreadable sync dir must fail closed");
    assert!(
        error.chain().any(|cause| cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|cause| cause.kind() == std::io::ErrorKind::PermissionDenied)),
        "production must retain the permission denial: {error:#}"
    );
}

#[test]
fn local_identity_missing_dir_is_absent() {
    let missing = tempfile::TempDir::new()
        .unwrap()
        .path()
        .join("does-not-exist");
    assert_eq!(
        LocalDbEpoch::from_local_dir(&missing).unwrap(),
        LocalDbEpoch::UNIX_EPOCH
    );
}

#[test]
fn test_parse_local_db_missing_dir_is_empty() {
    let missing = tempfile::TempDir::new()
        .unwrap()
        .path()
        .join("does-not-exist");
    let packages = parse_local_db(&missing).unwrap();
    assert!(packages.is_empty());
}

#[test]
#[cfg(unix)]
fn inaccessible_local_database_is_not_an_empty_catalog() {
    use std::os::unix::fs::PermissionsExt;
    const TEST: &str = "package_managers::pacman_db::db::tests::inaccessible_local_database_is_not_an_empty_catalog";
    if crate::config::Settings::rerun_test_unprivileged(TEST) {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let parent = directory.path().join("blocked");
    let local = parent.join("local");
    fs::create_dir_all(&local).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o000)).unwrap();
    let result = parse_local_db(&local);
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let error =
        result.expect_err("an inaccessible local database must not become an empty catalog");
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert!(format!("{error:#}").contains(&local.display().to_string()));
}

#[test]
fn test_parse_local_db_missing_desc_is_rejected() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(temp_dir.path().join("vim-9.1.0-1")).unwrap();
    let error = parse_local_db(temp_dir.path()).unwrap_err();
    assert!(format!("{error:#}").contains("vim-9.1.0-1/desc"));
}

#[test]
fn incomplete_local_entry_rejects_snapshot_with_healthy_package() {
    let temp = tempfile::tempdir().unwrap();
    write_local_desc(&temp, "healthy", "0", "");
    let healthy_desc = temp.path().join("healthy/desc");
    let healthy_bytes = fs::read(&healthy_desc).unwrap();
    assert_eq!(parse_local_db(temp.path()).unwrap().len(), 1);

    let incomplete = temp.path().join("incomplete-1");
    fs::create_dir(&incomplete).unwrap();
    for desc in [
        None,
        Some("%NAME%\nincomplete\n\n%VERSION%\ninvalid version\n"),
    ] {
        if let Some(desc) = desc {
            fs::write(incomplete.join("desc"), desc).unwrap();
        }
        let error = parse_local_db(temp.path())
            .expect_err("a healthy package cannot conceal an incomplete local entry");
        assert_eq!(
            error.to_string(),
            format!(
                "Incomplete local package entry {}",
                incomplete.join("desc").display()
            )
        );
        assert_eq!(fs::read(&healthy_desc).unwrap(), healthy_bytes);
    }
}

#[test]
fn malformed_local_desc_rejects_snapshot_with_healthy_package() {
    let temp = tempfile::tempdir().unwrap();
    write_local_desc(&temp, "healthy", "0", "");
    let healthy_desc = temp.path().join("healthy/desc");
    let healthy_bytes = fs::read(&healthy_desc).unwrap();
    assert_eq!(parse_local_db(temp.path()).unwrap().len(), 1);
    let broken = temp.path().join("broken-1-1");
    fs::create_dir(&broken).unwrap();
    let cases: [(&str, &[u8]); 3] = [
        ("absent-name", b"%VERSION%\n1-1\n\n%REASON%\n0\n"),
        ("empty-name", b"%NAME%\n\n%VERSION%\n1-1\n\n%REASON%\n0\n"),
        (
            "invalid-utf8",
            b"%NAME%\nbroken\n\n%VERSION%\n1-1\n\n%DESC%\n\xff\n",
        ),
    ];
    for (case, content) in cases {
        fs::write(broken.join("desc"), content).unwrap();
        let error = parse_local_db(temp.path())
            .expect_err("a healthy package must not conceal malformed local metadata");
        let message = format!("{error:#}");
        assert!(
            message.contains("Incomplete local package entry"),
            "{case}: {message}"
        );
        assert!(message.contains("broken-1-1/desc"), "{case}: {message}");
        if case == "invalid-utf8" {
            assert!(
                error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|cause| { cause.kind() == std::io::ErrorKind::InvalidData }),
                "invalid UTF-8 must retain its decoding cause: {message}"
            );
        } else {
            assert!(message.contains("no NAME found"), "{case}: {message}");
        }
        assert_eq!(fs::read(&healthy_desc).unwrap(), healthy_bytes, "{case}");
    }
}

#[test]
fn official_local_desc_formats_preserve_metadata_and_refuse_nul_versions() {
    use std::fmt::Write as _;

    let fields = [
        ("NAME", "widget"),
        ("VERSION", "1:2.3-01"),
        ("BASE", "widget"),
        ("DESC", "Offline metadata fixture"),
        ("URL", "https://example.org/widget"),
        ("ARCH", "x86_64"),
        ("BUILDDATE", "1"),
        ("INSTALLDATE", "2"),
        ("PACKAGER", "Audit Fixture <fixture@example.org>"),
        ("SIZE", "123"),
        ("GROUPS", "pinned\nother"),
        ("REASON", "1"),
        ("LICENSE", "MIT"),
        ("VALIDATION", "pgp"),
        ("REPLACES", "old-widget"),
        ("DEPENDS", "glibc>=2"),
        ("OPTDEPENDS", "extra-widget: optional feature"),
        ("CONFLICTS", "incompatible-widget"),
        ("PROVIDES", "virtual-widget=1"),
    ];
    let mut v1 = String::new();
    for (key, value) in fields {
        writeln!(v1, "%{key}%\n{value}\n").expect("in-memory fixture formatting");
    }
    let v2 = format!("{v1}%XDATA%\npkgtype=pkg\n\n");
    alpm_db::desc::DbDescFileV1::from_str(&v1).expect("complete V1 fixture");
    alpm_db::desc::DbDescFileV2::from_str(&v2).expect("complete V2 fixture");
    let marker = v1
        .replace("Offline metadata fixture", "Literal %XDATA% marker")
        .replace("%INSTALLDATE%\n2\n", "%INSTALLDATE%\n0002\n");
    let explicit = v2.replace("%REASON%\n1\n", "%REASON%\n0\n");
    assert!(matches!(
        alpm_db::desc::DbDescFile::from_str(&v1),
        Ok(alpm_db::desc::DbDescFile::V1(_))
    ));
    assert!(matches!(
        alpm_db::desc::DbDescFile::from_str(&v2),
        Ok(alpm_db::desc::DbDescFile::V2(_))
    ));
    for (body, description, is_explicit) in [
        (&v1, "Offline metadata fixture", false),
        (&v2, "Offline metadata fixture", false),
        (&marker, "Literal %XDATA% marker", false),
        (&explicit, "Offline metadata fixture", true),
    ] {
        let parsed = parse_local_desc_content(body).expect("official local metadata must parse");
        assert_eq!(parsed.name, "widget");
        assert_eq!(parsed.desc, description);
        assert_eq!(parsed.version.to_string(), "1:2.3-1");
        assert_eq!(parsed.groups, ["pinned", "other"]);
        assert_eq!(parsed.explicit, is_explicit);
        assert_eq!(parsed.install_date, "2");
        assert_eq!(parsed.url.as_deref(), Some("https://example.org/widget"));
        assert_eq!(parsed.size, 123);
        assert_eq!(parsed.licenses, ["MIT"]);
        assert_eq!(parsed.depends, ["glibc>=2"]);
        assert_eq!(parsed.provides, ["virtual-widget=1"]);
        assert_eq!(parsed.optdepends, ["extra-widget: optional feature"]);
        let malformed = body.replace("1:2.3-01", "1:2\0.3-01");
        let error = parse_local_desc_content(&malformed)
            .expect_err("a NUL version must be refused by either local metadata format");
        assert!(format!("{error:#}").contains("Invalid package version"));
    }
}

#[test]
fn test_parse_local_desc_invalid_version_errors() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let pkg_dir = temp_dir.path().join("vim-bad");
    std::fs::create_dir(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("desc"),
        "%NAME%\nvim\n\n%VERSION%\nnot a version!!!\n\n%DESC%\nVi Improved\n",
    )
    .unwrap();
    let error = parse_local_db(temp_dir.path()).unwrap_err();
    assert!(format!("{error:#}").contains("Invalid package version"));
}

#[test]
fn sync_identity_missing_directory_is_absent() {
    let missing = tempfile::TempDir::new()
        .unwrap()
        .path()
        .join("does-not-exist");
    let identity = SyncDbEpoch::from_sync_dir(&missing).unwrap();
    assert_eq!(identity, SyncDbEpoch::UNIX_EPOCH);
}

#[test]
#[ignore = "bounded filesystem metadata benchmark; run optimized with --ignored --nocapture"]
fn local_identity_scan_benchmark() -> Result<()> {
    for packages in [100, 1_000, 3_000] {
        let directory = tempfile::tempdir()?;
        for number in 0..packages {
            let package = directory.path().join(format!("fixture-{number}-1"));
            fs::create_dir(&package)?;
            for name in ["desc", "files", "mtree"] {
                fs::write(package.join(name), b"synthetic metadata")?;
            }
        }
        let expected = LocalDbEpoch::from_local_dir(directory.path())?;
        let mut micros = Vec::new();
        for _ in 0..7 {
            let start = std::time::Instant::now();
            let observed = LocalDbEpoch::from_local_dir(directory.path())?;
            micros.push(start.elapsed().as_micros());
            assert_eq!(observed, expected);
            std::hint::black_box(observed);
        }
        println!(
            "LOCAL_SCAN {}",
            serde_json::json!({
                "packages": packages, "files_per_package": 3, "microseconds": micros,
                "cache_state": "one warmup; OS cache not flushed"
            })
        );
    }
    Ok(())
}

#[test]
fn local_identity_tracks_package_symlinks_and_file_removal() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let local = directory.path().join("local");
    let target = directory.path().join("package");
    fs::create_dir(&local)?;
    fs::create_dir(&target)?;
    fs::write(target.join("desc"), b"metadata")?;
    std::os::unix::fs::symlink(&target, local.join("demo-1"))?;
    let before = LocalDbEpoch::from_local_dir(&local)?;
    assert_eq!(before, LocalDbEpoch::from_local_dir(&local)?);
    fs::remove_file(target.join("desc"))?;
    let after = LocalDbEpoch::from_local_dir(&local)?;
    assert_ne!(before, after);
    assert!(!is_cache_reusable(Some(before), after, true, None));
    fs::remove_dir(&target)?;
    assert!(LocalDbEpoch::from_local_dir(&local).is_err());
    Ok(())
}

#[test]
fn local_identity_detects_desc_edits_without_root_changes() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let package = directory.path().join("demo-1");
    fs::create_dir(&package)?;
    let desc = package.join("desc");
    fs::write(&desc, b"%REASON%\n0\n")?;
    let root_mtime = fs::metadata(directory.path())?.modified()?;
    let before = LocalDbEpoch::from_local_dir(directory.path())?;
    fs::write(&desc, b"%REASON%\n1\n")?;
    File::open(&desc)?.set_times(fs::FileTimes::new().set_modified(SystemTime::UNIX_EPOCH))?;
    assert_eq!(fs::metadata(directory.path())?.modified()?, root_mtime);
    assert_ne!(
        before,
        LocalDbEpoch::from_local_dir(directory.path())?,
        "desc changes must invalidate the local source identity"
    );
    Ok(())
}

#[test]
fn catalog_load_preserves_stable_values_and_observation_failures() -> Result<()> {
    let epoch = AlpmCatalogEpoch::UNIX_EPOCH;
    let (value, observed) = AlpmCatalogEpoch::load_stable(|| Ok(epoch), || Ok("snapshot"))?;
    assert_eq!((value, observed), ("snapshot", epoch));
    let called = std::cell::Cell::new(false);
    let result = AlpmCatalogEpoch::load_stable(
        || anyhow::bail!("observation unavailable"),
        || {
            called.set(true);
            Ok(())
        },
    );
    assert!(result.is_err());
    assert!(
        !called.get(),
        "do not initialize when the initial observation fails"
    );
    let mut observations = 0;
    let result = AlpmCatalogEpoch::load_stable(
        || {
            observations += 1;
            if observations == 1 {
                Ok(epoch)
            } else {
                anyhow::bail!("source disappeared")
            }
        },
        || Ok("unpublishable"),
    );
    assert!(result.is_err());
    assert_eq!(observations, 2);
    Ok(())
}

#[test]
fn catalog_load_rejects_changes_during_construction() -> Result<()> {
    struct Probe<'a>(&'a std::cell::Cell<bool>);
    impl Drop for Probe<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("core.db");
    fs::write(&database, b"old")?;
    let dropped = std::cell::Cell::new(false);
    let result = AlpmCatalogEpoch::load_stable(
        || {
            Ok(AlpmCatalogEpoch {
                sync: SyncDbEpoch::from_sync_dir(directory.path())?,
                local: LocalDbEpoch::UNIX_EPOCH,
            })
        },
        || {
            fs::write(&database, b"new generation")?;
            Ok(Probe(&dropped))
        },
    );
    assert!(
        result.is_err(),
        "a load must not be tagged with a later source identity"
    );
    assert!(dropped.get(), "discard the unpublished loaded resource");
    Ok(())
}

#[test]
fn sync_identity_detects_changes_hidden_by_a_future_timestamp() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let future = directory.path().join("core.db");
    let changed = directory.path().join("extra.db");
    fs::write(&future, b"future")?;
    fs::write(&changed, b"before")?;
    File::open(&future)?.set_times(
        fs::FileTimes::new().set_modified(SystemTime::now() + std::time::Duration::from_hours(24)),
    )?;
    File::open(&changed)?.set_times(
        fs::FileTimes::new()
            .set_modified(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(10)),
    )?;
    let before = SyncDbEpoch::from_sync_dir(directory.path())?;
    fs::write(&changed, b"after!")?;
    File::open(&changed)?.set_times(
        fs::FileTimes::new()
            .set_modified(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(20)),
    )?;
    let after = SyncDbEpoch::from_sync_dir(directory.path())?;
    assert_ne!(
        before, after,
        "a future-dated neighbor must not mask source changes"
    );
    Ok(())
}

#[test]
fn sync_identity_detects_replacement_with_preserved_mtime() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("core.db");
    fs::write(&path, b"before")?;
    let mtime = fs::metadata(&path)?.modified()?;
    let before = SyncDbEpoch::from_sync_dir(directory.path())?;
    assert_eq!(before, SyncDbEpoch::from_sync_dir(directory.path())?);
    let replacement = directory.path().join("replacement");
    fs::write(&replacement, b"after!")?;
    File::open(&replacement)?.set_times(fs::FileTimes::new().set_modified(mtime))?;
    fs::rename(&replacement, &path)?;
    let after = SyncDbEpoch::from_sync_dir(directory.path())?;
    assert_ne!(before, after);
    assert!(!is_cache_reusable(
        Some(before),
        after,
        true,
        Some(SystemTime::now())
    ));
    assert!(is_cache_reusable(
        Some(after),
        after,
        true,
        Some(SystemTime::now())
    ));
    Ok(())
}

#[test]
fn sync_identity_tracks_symlink_targets_and_rejects_dangling_links() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let sync = directory.path().join("sync");
    fs::create_dir(&sync)?;
    let target = directory.path().join("target.db");
    fs::write(&target, b"one")?;
    std::os::unix::fs::symlink(&target, sync.join("core.db"))?;
    let before = SyncDbEpoch::from_sync_dir(&sync)?;
    fs::write(&target, b"different size")?;
    assert_ne!(before, SyncDbEpoch::from_sync_dir(&sync)?);
    fs::remove_file(&target)?;
    assert!(SyncDbEpoch::from_sync_dir(&sync).is_err());
    Ok(())
}

#[test]
fn persisted_caches_reject_nul_versions_and_accept_healthy_versions() -> Result<()> {
    let directory = tempfile::tempdir()?;
    for raw in ["1\0-1", "0:2-1"] {
        let version = Version::from_str(raw)?;
        let sync = DbCache {
            packages: vec![RepositoryPackages {
                name: "core".to_owned(),
                usage: RepoUsage::UPGRADE,
                packages: Ok(HashMap::from([(
                    "widget".to_owned(),
                    SyncDbPackage {
                        name: "widget".to_owned(),
                        version: version.clone(),
                        ..SyncDbPackage::default()
                    },
                )])),
            }],
            ..DbCache::default()
        };
        save_cache_to_disk_in(&sync, directory.path(), SYNC_CACHE_NAME)?;
        let loaded_sync: Result<DbCache> =
            load_cache_from_disk_in(directory.path(), SYNC_CACHE_NAME);
        assert_eq!(
            loaded_sync.is_ok(),
            !raw.contains('\0'),
            "sync cache {raw:?}"
        );

        let local = LocalDbCache {
            packages: HashMap::from([(
                "widget".to_owned(),
                LocalDbPackage {
                    name: "widget".to_owned(),
                    version,
                    ..LocalDbPackage::default()
                },
            )]),
            ..LocalDbCache::default()
        };
        save_cache_to_disk_in(&local, directory.path(), LOCAL_CACHE_NAME)?;
        let loaded_local: Result<LocalDbCache> =
            load_cache_from_disk_in(directory.path(), LOCAL_CACHE_NAME);
        assert_eq!(
            loaded_local.is_ok(),
            !raw.contains('\0'),
            "local cache {raw:?}"
        );
    }
    Ok(())
}

#[test]
fn sync_identity_cache_uses_versioned_namespace() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let cache = DbCache {
        last_modified: Some(SyncDbEpoch::from_sync_dir(directory.path())?),
        ..DbCache::default()
    };
    fs::write(directory.path().join("sync_db.bin"), b"legacy cache")?;
    fs::write(
        directory.path().join("sync_db_source_v4.bin"),
        b"older derived cache",
    )
    .expect("write the previous cache namespace sentinel");
    fs::write(
        directory.path().join(format!("{SYNC_CACHE_NAME}.bin")),
        bitcode::serialize(&cache)?,
    )?;
    let decoded: DbCache = load_cache_from_disk_in(directory.path(), SYNC_CACHE_NAME)?;
    assert_eq!(decoded.last_modified, cache.last_modified);
    assert_eq!(
        fs::read(directory.path().join("sync_db_source_v4.bin"))?,
        b"older derived cache"
    );
    assert_eq!(
        fs::read(directory.path().join("sync_db.bin"))?,
        b"legacy cache"
    );
    Ok(())
}

#[test]
fn invalidate_derived_cache_files_removes_live_and_legacy_names() -> Result<()> {
    let directory = tempfile::tempdir()?;
    for name in [
        "sync_db_source_v5.bin",
        "sync_db_source_v4.bin",
        "sync_db_source_v3.bin",
        "sync_db_source_v2.bin",
        "local_db_source_v5.bin",
        "local_db_source_v4.bin",
        "local_db_source_v3.bin",
        "local_db_source_v2.bin",
        "sync_db_source_v1.bin",
        "local_db_source_v1.bin",
        "sync_db.bin",
        "local_db_rdeps.bin",
        "local_db.bin",
        "unrelated.bin",
    ] {
        fs::write(directory.path().join(name), b"cache")?;
    }
    invalidate_derived_cache_files(directory.path())?;
    for name in [
        "sync_db_source_v5.bin",
        "sync_db_source_v4.bin",
        "sync_db_source_v3.bin",
        "sync_db_source_v2.bin",
        "local_db_source_v5.bin",
        "local_db_source_v4.bin",
        "local_db_source_v3.bin",
        "local_db_source_v2.bin",
        "sync_db_source_v1.bin",
        "local_db_source_v1.bin",
        "sync_db.bin",
        "local_db_rdeps.bin",
        "local_db.bin",
    ] {
        assert!(
            !directory.path().join(name).exists(),
            "{name} must be removed"
        );
    }
    assert_eq!(fs::read(directory.path().join("unrelated.bin"))?, b"cache");
    invalidate_derived_cache_files(directory.path())?;
    Ok(())
}

#[test]
fn sync_directory_additions_and_removals_change_cache_identity() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let database = temp_dir.path().join("core.db");
    let empty = SyncDbEpoch::from_sync_dir(temp_dir.path()).unwrap();
    assert_ne!(empty, SyncDbEpoch::UNIX_EPOCH);

    std::fs::write(&database, b"database").unwrap();
    let populated = SyncDbEpoch::from_sync_dir(temp_dir.path()).unwrap();
    assert_ne!(populated, empty);

    std::fs::remove_file(database).unwrap();
    let removed = SyncDbEpoch::from_sync_dir(temp_dir.path()).unwrap();
    assert_ne!(removed, populated);
}

fn assert_configuration_change_updates_catalog_epoch(test_name: &str, included: bool) {
    if crate::core::testing::run_isolated_test(test_name) {
        return;
    }
    if crate::config::Settings::rerun_test_unprivileged(test_name) {
        return;
    }
    assert!(
        !crate::core::is_root(),
        "configuration fixture requires ordinary UID"
    );
    let temp = tempfile::TempDir::new().unwrap();
    let root = temp.path().join("root");
    let db = root.join("var/lib/pacman");
    let sync = db.join("sync");
    std::fs::create_dir_all(&sync).unwrap();
    std::fs::create_dir_all(db.join("local")).unwrap();
    std::fs::write(db.join("local/ALPM_DB_VERSION"), "9\n").unwrap();
    let conf = temp.path().join("pacman.conf");
    let repos = temp.path().join("repositories.conf");
    let first = "[first]\nServer = file:///no-network\n[second]\nServer = file:///no-network\n";
    let second = "[second]\nServer = file:///no-network\n[first]\nServer = file:///no-network\n";
    let options = "[options]\nSigLevel = Never\nArchitecture = x86_64\n";
    let changed = if included {
        std::fs::write(&conf, format!("{options}Include = repositories.conf\n")).unwrap();
        std::fs::write(&repos, first).unwrap();
        repos
    } else {
        std::fs::write(&conf, format!("{options}{first}")).unwrap();
        conf.clone()
    };
    let database = soname_fixture_catalog(&db);
    let top_level = std::fs::read(&conf).unwrap();
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            crate::core::paths::reset_test_overrides();
        }
    }
    let _restore = Restore;
    crate::core::paths::set_test_overrides(Some(root), Some(db.clone()));
    temp_env::with_vars(
        [
            ("OMG_TEST_MODE", None),
            ("OMG_PACMAN_CONF", Some(conf.to_str().unwrap())),
        ],
        || {
            let metadata = SyncDbEpoch::from_sync_dir(&sync).unwrap();
            let before = AlpmCatalogEpoch::observe().unwrap();
            assert_eq!(
                before,
                AlpmCatalogEpoch::observe().unwrap(),
                "unchanged configuration is stable"
            );
            std::fs::write(
                &changed,
                if included {
                    second.to_owned()
                } else {
                    format!("{options}{second}")
                },
            )
            .unwrap();
            let after = AlpmCatalogEpoch::observe().unwrap();
            assert_eq!(
                metadata,
                SyncDbEpoch::from_sync_dir(&sync).unwrap(),
                "database metadata is unchanged"
            );
            assert_eq!(
                soname_fixture_catalog(&db),
                database,
                "catalog reads preserve fixture bytes and metadata"
            );
            if included {
                assert_eq!(
                    std::fs::read(&conf).unwrap(),
                    top_level,
                    "only included file changed"
                );
            }
            assert_eq!(before.local, after.local, "local catalog did not change");
            println!(
                "[config-epoch-fixture] included={included} uid={} before={before:?} after={after:?}",
                nix::unistd::geteuid()
            );
            assert_ne!(
                before, after,
                "repository-order configuration change must invalidate catalog state"
            );
            assert_eq!(
                after,
                AlpmCatalogEpoch::observe().unwrap(),
                "new configuration is stable"
            );
        },
    );
}

#[test]
#[serial_test::serial]
fn catalog_epoch_tracks_repository_order_configuration() {
    assert_configuration_change_updates_catalog_epoch(
        "package_managers::pacman_db::db::tests::catalog_epoch_tracks_repository_order_configuration",
        false,
    );
}

#[test]
#[serial_test::serial]
fn catalog_epoch_tracks_included_repository_order_configuration() {
    assert_configuration_change_updates_catalog_epoch(
        "package_managers::pacman_db::db::tests::catalog_epoch_tracks_included_repository_order_configuration",
        true,
    );
}

#[test]
fn catalog_epoch_changes_when_local_db_changes() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let older = AlpmCatalogEpoch::UNIX_EPOCH;
    std::fs::write(temp_dir.path().join("ALPM_DB_VERSION"), b"9\n").unwrap();
    let before = LocalDbEpoch::from_local_dir(temp_dir.path()).unwrap();
    assert_eq!(
        before,
        LocalDbEpoch::from_local_dir(temp_dir.path()).unwrap()
    );
    let package = temp_dir.path().join("fixture-1.0-1");
    std::fs::create_dir(&package).unwrap();
    std::fs::write(package.join("desc"), b"%NAME%\nfixture\n").unwrap();
    let newer = AlpmCatalogEpoch {
        sync: SyncDbEpoch::UNIX_EPOCH,
        local: LocalDbEpoch::from_local_dir(temp_dir.path()).unwrap(),
    };
    assert_ne!(
        newer.local, before,
        "local package change must alter the epoch"
    );
    assert_eq!(
        newer.local,
        LocalDbEpoch::from_local_dir(temp_dir.path()).unwrap(),
        "unchanged local database must keep the same epoch"
    );
    assert_ne!(newer, older);
    assert_ne!(newer.local, older.local);
    assert_eq!(newer.sync, older.sync);
}

#[cfg(unix)]
#[test]
fn sync_identity_unreadable_directory_errors() {
    if crate::config::Settings::rerun_test_unprivileged(
        "package_managers::pacman_db::db::tests::sync_identity_unreadable_directory_errors",
    ) {
        return;
    }
    assert!(
        !crate::core::is_root(),
        "permission fixture must not run as root"
    );
    let temp_dir = tempfile::TempDir::new().unwrap();
    let original = std::fs::metadata(temp_dir.path()).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(temp_dir.path(), std::fs::Permissions::from_mode(0o000)).unwrap();
    let denied =
        std::fs::read_dir(temp_dir.path()).expect_err("fixture must enforce permission denial");
    assert_eq!(denied.kind(), std::io::ErrorKind::PermissionDenied);
    println!(
        "[omg-permission-fixture] test=package_managers::pacman_db::db::tests::sync_identity_unreadable_directory_errors uid={} errno=PermissionDenied",
        nix::unistd::geteuid()
    );
    let result = SyncDbEpoch::from_sync_dir(temp_dir.path());
    std::fs::set_permissions(temp_dir.path(), original).expect("restore fixture permissions");
    let error = result.expect_err("unreadable sync dir must fail closed");
    assert!(
        error.chain().any(|cause| cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|cause| cause.kind() == std::io::ErrorKind::PermissionDenied)),
        "production must retain the permission denial: {error:#}"
    );
}

#[test]
fn test_remove_cache_file_allows_missing() {
    let missing = tempfile::TempDir::new()
        .unwrap()
        .path()
        .join("does-not-exist.bin");
    remove_cache_file(&missing).unwrap();
}

#[test]
fn test_remove_cache_file_rejects_directory() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let error = remove_cache_file(temp_dir.path()).expect_err("directory is not a cache file");
    assert!(
        error
            .to_string()
            .contains("Failed to remove package cache file"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn test_get_local_package() {
    // Only run if we have a real system
    if crate::core::paths::pacman_local_dir().exists() {
        // pacman should always be installed
        if let Ok(Some(pkg)) = get_local_package("pacman") {
            assert!(!pkg.version.to_string().is_empty());
        }
    }
}

#[test]
fn test_get_package_counts_consistent_on_real_systems() {
    if crate::core::paths::pacman_local_dir().exists() {
        let (total, explicit, deps) = match get_counts_fast() {
            Ok(counts) => counts,
            Err(e) => unreachable!("Failed to get counts: {e}"),
        };
        assert!(total > 0);
        // `deps` counts TRUE ORPHANS only, which are a subset of the
        // non-explicit packages — not a disjoint class that closes the
        // accounting equation (most dependencies have dependants).
        assert!(explicit <= total);
        assert!(explicit + deps <= total);
    }
}

/// Fixture helper: writes local desc files shaped like modern pacman's
/// output — no `%REQUIREDBY%`/`%OPTFOR%` sections ever — so reverse
/// dependencies exist only in other packages' `%DEPENDS%`/`%OPTDEPENDS%`
/// sections, exactly like `pacman -Qdt` sees them.
fn write_local_desc(temp: &tempfile::TempDir, name: &str, reason: &str, extra: &str) {
    let dir = temp.path().join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("desc"),
        format!("%NAME%\n{name}\n\n%VERSION%\n1.0-1\n\n%REASON%\n{reason}\n{extra}"),
    )
    .unwrap();
}

#[test]
fn doctor_rejects_local_entries_that_package_queries_skip() {
    let temp = tempfile::TempDir::new().unwrap();
    write_local_desc(&temp, "healthy-1.0-1", "0", "");
    let healthy = temp.path().join("healthy-1.0-1");
    std::fs::write(healthy.join("files"), "%FILES%\nusr/bin/healthy\n").unwrap();
    assert_eq!(check_local_db_consistency(temp.path()).unwrap(), 1);

    std::fs::remove_file(healthy.join("files")).unwrap();
    assert!(check_local_db_consistency(temp.path()).is_err());
    std::fs::write(healthy.join("files"), "%FILES%\nusr/bin/healthy\n").unwrap();

    let corrupt = temp.path().join("corrupt-1.0-1");
    std::fs::create_dir(&corrupt).unwrap();
    std::fs::write(corrupt.join("desc"), "%VERSION%\n1.0-1\n").unwrap();
    std::fs::write(corrupt.join("files"), "%FILES%\nusr/bin/corrupt\n").unwrap();
    assert!(check_local_db_consistency(temp.path()).is_err());
}

fn health_fixture() -> tempfile::TempDir {
    let temp = tempfile::TempDir::new().unwrap();
    write_local_desc(&temp, "app", "0", "");
    fs::write(temp.path().join("app/files"), "%FILES%\nusr/bin/app\n").unwrap();
    temp
}

#[test]
fn health_observation_healthy_snapshot_and_missing_dependency() {
    let temp = health_fixture();
    assert_eq!(check_local_db_health(temp.path()).unwrap(), (1, Vec::new()));
    write_local_desc(&temp, "app", "0", "\n%DEPENDS%\nabsent\n");
    assert_eq!(
        check_local_db_health(temp.path()).unwrap(),
        (
            1,
            vec![UnsatisfiedDependency {
                package: "app".into(),
                dependency: "absent".into()
            }]
        )
    );
}

#[test]
fn health_observation_rejects_missing_empty_and_not_directory() {
    let temp = tempfile::TempDir::new().unwrap();
    assert!(check_local_db_health(temp.path()).is_err());
    assert!(check_local_db_health(&temp.path().join("absent")).is_err());
    let file = temp.path().join("not-directory");
    fs::write(&file, "file").unwrap();
    assert!(check_local_db_health(&file).is_err());
}

#[test]
fn health_observation_rejects_required_file_and_malformed_declaration() {
    let temp = health_fixture();
    fs::remove_file(temp.path().join("app/files")).unwrap();
    assert!(check_local_db_health(temp.path()).is_err());
    fs::write(temp.path().join("app/files"), "").unwrap();
    fs::write(temp.path().join("app/desc"), "%VERSION%\n1.0-1\n").unwrap();
    assert!(check_local_db_health(temp.path()).is_err());
}

#[test]
fn health_observation_rejects_duplicate_package_names() {
    let temp = health_fixture();
    fs::create_dir(temp.path().join("duplicate")).unwrap();
    fs::copy(
        temp.path().join("app/desc"),
        temp.path().join("duplicate/desc"),
    )
    .unwrap();
    fs::write(temp.path().join("duplicate/files"), "").unwrap();
    assert!(
        check_local_db_health(temp.path())
            .unwrap_err()
            .to_string()
            .contains("Duplicate local package name")
    );
}

#[test]
fn health_observation_rejects_symlinks() {
    let temp = health_fixture();
    let link = temp.path().join("alias");
    std::os::unix::fs::symlink(temp.path().join("app"), &link).unwrap();
    assert!(check_local_db_health(temp.path()).is_err());
    fs::remove_file(link).unwrap();
    fs::remove_file(temp.path().join("app/files")).unwrap();
    std::os::unix::fs::symlink(temp.path().join("app/desc"), temp.path().join("app/files"))
        .unwrap();
    assert!(check_local_db_health(temp.path()).is_err());
}

#[test]
fn health_observation_rejects_unreadable_declaring_entry() {
    use std::os::unix::fs::PermissionsExt;
    if crate::config::Settings::rerun_test_unprivileged(
        "package_managers::pacman_db::db::tests::health_observation_rejects_unreadable_declaring_entry",
    ) {
        return;
    }
    let uid = nix::unistd::geteuid().as_raw();
    assert_ne!(
        uid, 0,
        "permission fixture must execute without root DAC bypass"
    );
    let temp = health_fixture();
    assert_eq!(fs::metadata(temp.path()).unwrap().uid(), uid);
    let path = temp.path().join("app/desc");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o0)).unwrap();
    let error = check_local_db_health(temp.path()).unwrap_err();
    assert!(
        error.chain().any(|cause| cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|cause| cause.kind() == std::io::ErrorKind::PermissionDenied)),
        "production health read must preserve PermissionDenied: {error:#}"
    );
    println!("[omg-alpm-permission] cause={error:#}");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn health_observation_rejects_changed_desc_files_and_entry_set() {
    for relative in ["app/desc", "app/files"] {
        let temp = health_fixture();
        let snapshot = LocalHealthSnapshot::capture(temp.path()).unwrap();
        fs::write(temp.path().join(relative), "changed").unwrap();
        assert!(snapshot.revalidate(temp.path()).is_err());
    }
    let temp = health_fixture();
    let snapshot = LocalHealthSnapshot::capture(temp.path()).unwrap();
    fs::write(temp.path().join("new-entry"), "").unwrap();
    assert!(snapshot.revalidate(temp.path()).is_err());
}

#[test]
fn health_observation_rejects_vanished_or_replaced_root() {
    let temp = health_fixture();
    let snapshot = LocalHealthSnapshot::capture(temp.path()).unwrap();
    let moved = temp.path().with_extension("moved");
    fs::rename(temp.path(), &moved).unwrap();
    assert!(snapshot.revalidate(temp.path()).is_err());
    fs::create_dir(temp.path()).unwrap();
    assert!(snapshot.revalidate(temp.path()).is_err());
    fs::remove_dir(temp.path()).unwrap();
    fs::rename(moved, temp.path()).unwrap();
}

fn health_relation_missing(required: &str, provision: &str) -> Vec<UnsatisfiedDependency> {
    let temp = health_fixture();
    write_local_desc(&temp, "app", "0", &format!("\n%DEPENDS%\n{required}\n"));
    write_local_desc(
        &temp,
        "provider",
        "1",
        &format!("\n%PROVIDES%\n{provision}\n"),
    );
    fs::write(temp.path().join("provider/files"), "").unwrap();
    check_local_db_health(temp.path()).unwrap().1
}

#[test]
fn health_matching_literal_and_self_versions_preserve_raw_diagnostics() {
    let temp = health_fixture();
    write_local_desc(&temp, "app", "0", "\n%DEPENDS%\napp>=9\nliteral>=9\n");
    write_local_desc(&temp, "literal", "1", "");
    fs::write(temp.path().join("literal/files"), "").unwrap();
    assert_eq!(
        check_local_db_health(temp.path()).unwrap().1,
        vec![
            UnsatisfiedDependency {
                package: "app".into(),
                dependency: "app>=9".into()
            },
            UnsatisfiedDependency {
                package: "app".into(),
                dependency: "literal>=9".into()
            },
        ]
    );
    write_local_desc(&temp, "app", "0", "\n%DEPENDS%\napp>=1\nliteral=1.0\n");
    assert!(check_local_db_health(temp.path()).unwrap().1.is_empty());
}

#[test]
fn health_matching_versioned_provisions_and_alternate_providers() {
    assert!(health_relation_missing("virtual>=9", "virtual").len() == 1);
    assert!(health_relation_missing("virtual>=9", "virtual=1").len() == 1);
    assert!(health_relation_missing("virtual>=9", "virtual=9").is_empty());
    let temp = health_fixture();
    write_local_desc(&temp, "app", "0", "\n%DEPENDS%\nvirtual>=9\n");
    for (name, version) in [("old", "1"), ("new", "9")] {
        write_local_desc(
            &temp,
            name,
            "1",
            &format!("\n%PROVIDES%\nvirtual={version}\n"),
        );
        fs::write(temp.path().join(name).join("files"), "").unwrap();
    }
    assert!(check_local_db_health(temp.path()).unwrap().1.is_empty());
}

#[test]
fn health_matching_soname_v1_basic_explicit_and_cross_relation() {
    assert!(health_relation_missing("libfoo.so", "libfoo.so=1-64").is_empty());
    assert_eq!(alpm::vercmp("1-64", "1"), std::cmp::Ordering::Equal);
    assert!(health_relation_missing("libfoo.so=1", "libfoo.so=1-64").is_empty());
    assert!(health_relation_missing("libfoo.so=1-64", "libfoo.so=1").is_empty());
    assert!(health_relation_missing("libfoo.so=1-64", "libfoo.so=1-64").is_empty());
    for provided in ["libfoo.so=2-64", "libfoo.so=1-32", "libfoo.so"] {
        assert_eq!(
            health_relation_missing("libfoo.so=1-64", provided).len(),
            1,
            "{provided}"
        );
    }
    assert!(health_relation_missing("libfoo.so=libfoo.so-64", "libfoo.so=libfoo.so-64").is_empty());
    assert_eq!(
        health_relation_missing("libfoo.so=libfoo.so-64", "libfoo.so=libfoo.so-32").len(),
        1
    );
}

#[test]
fn health_matching_soname_v2_preserves_prefix_and_name() {
    assert!(health_relation_missing("lib:libfoo.so.1", "lib:libfoo.so.1").is_empty());
    for provided in ["lib64:libfoo.so.1", "lib:libbar.so.1", "lib:libfoo.so.2"] {
        assert_eq!(
            health_relation_missing("lib:libfoo.so.1", provided).len(),
            1,
            "{provided}"
        );
    }
}

#[test]
fn health_matching_all_operators_epochs_releases_and_equivalent_versions() {
    for (required, provision, satisfied) in [
        ("virtual<2", "virtual=1", true),
        ("virtual<1", "virtual=1", false),
        ("virtual<=1", "virtual=1", true),
        ("virtual<=1", "virtual=2", false),
        ("virtual>1", "virtual=2", true),
        ("virtual>1", "virtual=1", false),
        ("virtual>=1", "virtual=1", true),
        ("virtual>=2", "virtual=1", false),
        ("virtual=1", "virtual=01", true),
        ("virtual=1", "virtual=2", false),
        ("virtual>1:9-9", "virtual=2:1-1", true),
        ("virtual>1.0-1", "virtual=1.0-2", true),
        ("virtual=1.0-2", "virtual=1.0-1", false),
    ] {
        assert_eq!(
            health_relation_missing(required, provision).is_empty(),
            satisfied,
            "{required} / {provision}"
        );
    }
}

#[test]
fn health_matching_optional_dependencies_remain_optional() {
    let temp = health_fixture();
    write_local_desc(&temp, "app", "0", "\n%OPTDEPENDS%\nabsent>=9: optional\n");
    assert!(check_local_db_health(temp.path()).unwrap().1.is_empty());
}

#[test]
fn health_matching_rejects_malformed_or_unsupported_relations() {
    for extra in [
        "\n%DEPENDS%\nvirtual>=\n",
        "\n%DEPENDS%\nvirtual==1\n",
        "\n%PROVIDES%\nvirtual>=9\n",
        "\n%PROVIDES%\nvirtual=\n",
    ] {
        let temp = health_fixture();
        write_local_desc(&temp, "app", "0", extra);
        assert!(check_local_db_health(temp.path()).is_err(), "{extra}");
    }
}

#[test]
fn health_matching_refuses_nul_relations_before_native_comparison() {
    for extra in [
        "\n%DEPENDS%\nprovider>=1\0\n",
        "\n%PROVIDES%\nvirtual=1\0\n",
    ] {
        let temp = health_fixture();
        write_local_desc(&temp, "app", "0", extra);
        assert!(check_local_db_health(temp.path()).is_err(), "{extra:?}");
    }
}

#[test]
fn ignore_patterns_follow_native_fnmatch_grammar() {
    for (pattern, value, expected) in [
        ("widget{,-git}", "widget", false),
        ("widget{,-git}", "widget-git", false),
        ("widget{,-git}", "widget{,-git}", true),
        ("[!a]*", "widget", true),
        ("[!a]*", "arch", false),
        ("widget[", "widget[", true),
        ("widget-*", "widget-git", true),
    ] {
        let compiled = compile_package_patterns(&[pattern.to_owned()], "IgnorePkg")
            .expect("pacman permits literal unmatched brackets");
        assert_eq!(
            compiled.is_match(value),
            expected,
            "{pattern:?} / {value:?}"
        );
    }
}

#[test]
fn health_matching_cpu_comparator_controls_relation_decisions() {
    for (candidate, required) in [
        ("1-64", "1"),
        ("01", "1"),
        ("2:1-1", "1:9-9"),
        ("1.0-2", "1.0-1"),
    ] {
        let comparison = alpm::vercmp(candidate, required);
        for (operator, expected) in [
            ("=", comparison.is_eq()),
            ("<", comparison.is_lt()),
            ("<=", !comparison.is_gt()),
            (">", comparison.is_gt()),
            (">=", !comparison.is_lt()),
        ] {
            let raw = format!("virtual{operator}{required}");
            assert_eq!(
                health_relation(&raw).unwrap().accepts(Some(candidate)),
                expected,
                "{raw} / {candidate}"
            );
        }
    }
}

fn check_local_db_consistency(path: &Path) -> Result<usize> {
    check_local_db_health(path).map(|(count, _)| count)
}

/// Parse the fixture db and apply the canonical orphan rule with
/// reverse dependencies derived from `%DEPENDS%`/`%PROVIDES%`.
fn fixture_orphans(temp: &tempfile::TempDir) -> Vec<String> {
    let packages = parse_local_db(temp.path()).unwrap();
    let required = compute_required_names(&packages).unwrap();
    let mut orphans: Vec<String> = packages
        .iter()
        .filter(|(name, pkg)| {
            crate::package_managers::types::is_orphan_package(
                pkg.explicit,
                !required.contains(name.as_str()),
            )
        })
        .map(|(name, _)| name.clone())
        .collect();
    orphans.sort();
    orphans
}

#[test]
fn dependency_relations_preserve_version_constraints_and_sonames() {
    assert_eq!(health_relation("curl").unwrap().name, "curl");
    let versioned = health_relation("curl>=7.0").unwrap();
    assert_eq!(versioned.name, "curl");
    assert_eq!(versioned.version, Some("7.0"));
    assert_eq!(health_relation("libfoo.so=1-64").unwrap().name, "libfoo.so");
}

#[test]
fn orphan_versions_match_libalpm_for_direct_and_virtual_dependencies() {
    for section in ["DEPENDS", "OPTDEPENDS"] {
        for (requirement, provision) in [
            ("provider>=2", None),
            ("virtual>=2", Some("virtual")),
            ("virtual>=2", Some("virtual=1")),
            ("virtual>=2", Some("virtual=3")),
            ("virtual=1-64", Some("virtual=1-32")),
            ("virtual", Some("virtual=1")),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let local = directory.path().join("local");
            let root = directory.path().join("root");
            std::fs::create_dir_all(&local).unwrap();
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(local.join("ALPM_DB_VERSION"), "9\n").unwrap();
            for (name, reason, extra) in [
                ("app", "0", format!("%{section}%\n{requirement}\n\n")),
                (
                    "provider",
                    "1",
                    provision.map_or_else(String::new, |value| format!("%PROVIDES%\n{value}\n\n")),
                ),
            ] {
                let entry = local.join(format!("{name}-1.0-1"));
                std::fs::create_dir(&entry).unwrap();
                std::fs::write(
                    entry.join("desc"),
                    format!("%NAME%\n{name}\n\n%VERSION%\n1.0-1\n\n%REASON%\n{reason}\n\n{extra}"),
                )
                .unwrap();
            }
            let packages = parse_local_db(&local).unwrap();
            let required = compute_required_names(&packages).unwrap();
            let alpm = alpm::Alpm::new(root.to_str().unwrap(), directory.path().to_str().unwrap())
                .unwrap();
            let provider = alpm.localdb().pkg("provider").unwrap();
            let native_required =
                !provider.required_by().is_empty() || !provider.optional_for().is_empty();
            assert_eq!(
                required.contains("provider"),
                native_required,
                "{section}: {requirement} / {provision:?}"
            );
        }
    }
}

/// #687: a local database that parses cleanly can still declare a
/// dependency nothing installed satisfies, which is what a half-removed
/// package looks like. Doctor previously accepted it.
#[test]
fn unsatisfied_dependencies_reports_only_genuinely_missing_names() {
    let temp = tempfile::TempDir::new().unwrap();
    // Direct dependency, satisfied.
    write_local_desc(&temp, "app-main", "0", "\n%DEPENDS%\nlib-used>=1.0\n");
    write_local_desc(&temp, "lib-used", "1", "");
    // Virtual dependency, satisfied only through %PROVIDES%.
    write_local_desc(&temp, "app-virtual", "0", "\n%DEPENDS%\nvirtual-svc\n");
    write_local_desc(&temp, "provider", "1", "\n%PROVIDES%\nvirtual-svc\n");
    // Self-reference and an unmet dependency on the same package.
    write_local_desc(
        &temp,
        "app-broken",
        "0",
        "\n%DEPENDS%\napp-broken\ngone-lib\n",
    );
    // optdepends are optional and must not be reported.
    write_local_desc(
        &temp,
        "app-opt",
        "0",
        "\n%OPTDEPENDS%\nnever-installed: does things\n",
    );

    let packages = parse_local_db(temp.path()).unwrap();
    let missing = unsatisfied_dependencies(&packages);

    assert_eq!(
        missing,
        vec![UnsatisfiedDependency {
            package: "app-broken".to_string(),
            dependency: "gone-lib".to_string(),
        }],
        "expected only the unmet name, with constraints and self-references resolved"
    );
}

/// A dependency whose desc lacks `%REQUIREDBY%` — as every modern pacman desc
/// does — but which another package's `%DEPENDS%` names is NOT an orphan.
#[test]
fn required_dependency_without_requireby_section_is_not_an_orphan() {
    let temp = tempfile::TempDir::new().unwrap();
    write_local_desc(&temp, "app-main", "0", "\n%DEPENDS%\nlib-used>=1.0\n");
    write_local_desc(&temp, "lib-used", "1", "");

    let packages = parse_local_db(temp.path()).unwrap();
    assert_eq!(packages["app-main"].depends, ["lib-used>=1.0".to_string()]);
    assert!(packages["lib-used"].depends.is_empty());

    assert!(!fixture_orphans(&temp).contains(&"lib-used".to_string()));
}

/// Under `pacman -Qdt` rules ("print only packages neither required nor
/// optionally required by any currently installed package"), a dependency
/// that appears in another package's `%OPTDEPENDS%` is NOT an orphan.
#[test]
fn optdepend_package_is_not_orphan_under_pacman_qdt_rules() {
    let temp = tempfile::TempDir::new().unwrap();
    write_local_desc(
        &temp,
        "app-main",
        "0",
        "\n%OPTDEPENDS%\nlib-opt: extra features\n",
    );
    write_local_desc(&temp, "lib-opt", "1", "");

    assert!(fixture_orphans(&temp).is_empty());
}

/// A dependency with neither direct dependents nor optional dependents IS an orphan.
#[test]
fn unrequired_dependency_is_counted_as_orphan() {
    let temp = tempfile::TempDir::new().unwrap();
    write_local_desc(&temp, "app-main", "0", "");
    write_local_desc(&temp, "lonely-dep", "1", "");

    assert_eq!(fixture_orphans(&temp), ["lonely-dep"]);
}

/// Explicitly installed packages are never orphans, even when unrequired.
#[test]
fn explicit_packages_are_never_orphans() {
    let temp = tempfile::TempDir::new().unwrap();
    write_local_desc(&temp, "explicit-tool", "0", "");
    write_local_desc(&temp, "explicit-with-deps", "0", "\n%DEPENDS%\nsome-lib\n");
    write_local_desc(&temp, "some-lib", "1", "");
    write_local_desc(&temp, "lonely-dep", "1", "");

    let orphans = fixture_orphans(&temp);
    assert_eq!(orphans, ["lonely-dep"]);
    assert!(!orphans.contains(&"explicit-tool".to_string()));
    assert!(!orphans.contains(&"explicit-with-deps".to_string()));
}

/// A dependency satisfied through `%PROVIDES%` keeps its provider alive,
/// matching libalpm's reverse-dependency resolution.
#[test]
fn provides_satisfies_virtual_dependency_for_orphan_counting() {
    let temp = tempfile::TempDir::new().unwrap();
    write_local_desc(&temp, "app-virtual", "0", "\n%DEPENDS%\nvirtual-svc\n");
    write_local_desc(&temp, "lib-provides", "1", "\n%PROVIDES%\nvirtual-svc\n");
    write_local_desc(&temp, "lonely-dep", "1", "");

    assert_eq!(fixture_orphans(&temp), ["lonely-dep"]);
}

/// Isolated fixture pinning the orphan-accounting rule end to end:
/// under `pacman -Qdt` semantics exactly the never-required dependency
/// is an orphan, while required, virtually-required, and explicit
/// packages are not.
#[test]
fn orphan_accounting_matches_is_orphan_package_on_synthetic_local_db() {
    let temp = tempfile::TempDir::new().unwrap();
    write_local_desc(&temp, "explicit-tool", "0", "");
    write_local_desc(
        &temp,
        "app-main",
        "0",
        "\n%DEPENDS%\nlib-used>=1.0\n\n%OPTDEPENDS%\nlib-opt: extra features\n",
    );
    write_local_desc(&temp, "lib-used", "1", "");
    write_local_desc(&temp, "lib-opt", "1", "");
    write_local_desc(&temp, "lib-provides", "1", "\n%PROVIDES%\nvirtual-svc\n");
    write_local_desc(&temp, "app-virtual", "0", "\n%DEPENDS%\nvirtual-svc\n");
    write_local_desc(&temp, "lonely-orphan", "1", "");

    let packages = parse_local_db(temp.path()).unwrap();
    assert_eq!(packages.len(), 7);
    let required = compute_required_names(&packages).unwrap();
    assert_eq!(
        required.len(),
        3,
        "lib-used + lib-opt + lib-provides: {required:?}"
    );
    assert_eq!(fixture_orphans(&temp), ["lonely-orphan"]);
}

/// The pure-Rust fast path and the libalpm-backed path must agree on the
/// same fixture local database (counts including orphan classification).
#[test]
#[serial_test::serial]
fn fast_path_and_libalpm_counts_agree_on_fixture_local_db() {
    if crate::config::Settings::rerun_test_unprivileged(
        "package_managers::pacman_db::db::tests::fast_path_and_libalpm_counts_agree_on_fixture_local_db",
    ) {
        return;
    }
    println!(
        "[omg-count-fixture-identity] uid={} euid={} groups={:?}",
        nix::unistd::getuid().as_raw(),
        nix::unistd::geteuid().as_raw(),
        nix::unistd::getgroups().expect("read fixture supplementary groups")
    );
    if crate::core::testing::run_isolated_test(
        "package_managers::pacman_db::db::tests::fast_path_and_libalpm_counts_agree_on_fixture_local_db",
    ) {
        return;
    }
    assert!(
        !crate::core::is_root(),
        "count fixture must run unprivileged"
    );
    let temp = tempfile::TempDir::new().unwrap();
    let root = temp.path().join("root");
    let db_dir = root.join("var/lib/pacman");
    let local_dir = db_dir.join("local");
    std::fs::create_dir_all(&local_dir).unwrap();
    // libalpm refuses a local database without its schema version file.
    std::fs::write(local_dir.join("ALPM_DB_VERSION"), "9\n").unwrap();

    let write_alpm_desc = |name: &str, reason: &str, extra: &str| {
        let dir = local_dir.join(format!("{name}-1.0-1"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("desc"),
            format!("%NAME%\n{name}\n\n%VERSION%\n1.0-1\n\n%REASON%\n{reason}\n{extra}"),
        )
        .unwrap();
    };
    write_alpm_desc("explicit-tool", "0", "");
    write_alpm_desc(
        "app-main",
        "0",
        "\n%DEPENDS%\nlib-used>=1.0\n\n%OPTDEPENDS%\nlib-opt: extra features\n",
    );
    write_alpm_desc("lib-used", "1", "");
    write_alpm_desc("lib-opt", "1", "");
    write_alpm_desc("lib-provides", "1", "\n%PROVIDES%\nvirtual-svc\n");
    write_alpm_desc("app-virtual", "0", "\n%DEPENDS%\nvirtual-svc\n");
    write_alpm_desc("lonely-orphan", "1", "");

    let conf = temp.path().join("pacman.conf");
    std::fs::write(&conf, "[options]\n").unwrap();
    let cache_dir = temp.path().join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();
    let config_dir = temp.path().join("omg-config");
    std::fs::create_dir_all(&config_dir).unwrap();

    crate::package_managers::alpm_direct::clear_alpm_cache();
    crate::core::paths::set_test_overrides(Some(root), Some(db_dir.clone()));
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            crate::core::paths::reset_test_overrides();
            crate::package_managers::alpm_direct::clear_alpm_cache();
        }
    }
    let _restore = Restore;

    let expected = (7, 3, 1);
    temp_env::with_vars(
        [
            ("OMG_TEST_MODE", None),
            ("OMG_TEST_DISTRO", None),
            ("OMG_PACMAN_LOCAL_DIR", None),
            ("OMG_PACMAN_SYNC_DIR", None),
            ("HOME", Some(temp.path().to_str().unwrap())),
            ("XDG_CONFIG_HOME", Some(temp.path().to_str().unwrap())),
            ("OMG_CONFIG_DIR", Some(config_dir.to_str().unwrap())),
            ("OMG_PACMAN_CONF", Some(conf.to_str().unwrap())),
            ("OMG_CACHE_DIR", Some(cache_dir.to_str().unwrap())),
        ],
        || {
            assert_eq!(
                crate::core::paths::pacman_local_dir_result().unwrap(),
                local_dir
            );
            assert_eq!(
                crate::core::paths::pacman_sync_dir_result().unwrap(),
                db_dir.join("sync")
            );
            assert_eq!(crate::core::paths::cache_dir(), cache_dir);
            assert_eq!(crate::core::paths::config_dir(), config_dir);
            let fast = get_counts_fast().expect("fast-path counts must succeed");
            let ffi = crate::package_managers::alpm_direct::get_counts()
                .expect("libalpm counts must succeed");
            let public =
                crate::package_managers::get_counts().expect("public package counts must succeed");
            assert_eq!(fast, expected, "fast path diverged on fixture");
            assert_eq!(ffi, expected, "libalpm path diverged on fixture");
            assert_eq!(public, expected, "public count routing diverged on fixture");
            assert_eq!(fast, ffi, "fast path and libalpm path must agree");
            assert_eq!(get_explicit_count().unwrap(), expected.1);
        },
    );
}

#[derive(Debug, PartialEq)]
struct SonameFixtureEntry {
    path: PathBuf,
    contents: Option<Vec<u8>>,
    device: u64,
    inode: u64,
    length: u64,
    modified: SystemTime,
}

fn soname_fixture_catalog(path: &Path) -> Vec<SonameFixtureEntry> {
    let metadata = std::fs::symlink_metadata(path).expect("fixture metadata");
    let mut entries = vec![SonameFixtureEntry {
        path: path.to_path_buf(),
        contents: metadata
            .is_file()
            .then(|| std::fs::read(path).expect("fixture contents")),
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified: metadata.modified().expect("fixture modification time"),
    }];
    if metadata.is_dir() {
        for entry in std::fs::read_dir(path).expect("fixture directory") {
            entries.extend(soname_fixture_catalog(
                &entry.expect("fixture directory entry").path(),
            ));
        }
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    entries
}

fn assert_distinct_soname_providers_have_one_orphan(test_name: &str, app_relation: &str) {
    if crate::config::Settings::rerun_test_unprivileged(test_name) {
        return;
    }
    println!(
        "[omg-count-fixture-identity] uid={} euid={} groups={:?}",
        nix::unistd::getuid().as_raw(),
        nix::unistd::geteuid().as_raw(),
        nix::unistd::getgroups().expect("read fixture supplementary groups")
    );
    if crate::core::testing::run_isolated_test(test_name) {
        return;
    }
    assert!(
        !crate::core::is_root(),
        "SONAME fixture must run unprivileged"
    );

    let temp = tempfile::TempDir::new().expect("SONAME fixture directory");
    let root = temp.path().join("root");
    let db_dir = root.join("var/lib/pacman");
    let local_dir = db_dir.join("local");
    std::fs::create_dir_all(&local_dir).expect("private local database");
    std::fs::create_dir_all(db_dir.join("sync")).expect("private sync directory");
    std::fs::write(local_dir.join("ALPM_DB_VERSION"), "9\n")
        .expect("real libalpm local database version");
    for (name, reason, relations) in [
        ("app", "0", app_relation),
        ("used", "1", "\n%PROVIDES%\nlib:libfoo.so.1\n"),
        ("unrelated", "1", "\n%PROVIDES%\nlib:libbar.so.1\n"),
    ] {
        let directory = local_dir.join(format!("{name}-1.0-1"));
        std::fs::create_dir_all(&directory).expect("private package directory");
        std::fs::write(
            directory.join("desc"),
            format!("%NAME%\n{name}\n\n%VERSION%\n1.0-1\n\n%REASON%\n{reason}\n{relations}"),
        )
        .expect("private package description");
    }

    let conf = temp.path().join("pacman.conf");
    std::fs::write(&conf, "[options]\n").expect("private pacman configuration");
    let cache_dir = temp.path().join("omg-cache");
    std::fs::create_dir_all(&cache_dir).expect("private OMG cache");
    let config_dir = temp.path().join("omg-config");
    std::fs::create_dir_all(&config_dir).expect("private OMG config");
    let database_before = soname_fixture_catalog(&db_dir);
    let configuration_before = soname_fixture_catalog(&conf);

    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            crate::core::paths::reset_test_overrides();
            crate::package_managers::alpm_direct::clear_alpm_cache();
        }
    }
    let _restore = Restore;
    crate::package_managers::alpm_direct::clear_alpm_cache();
    crate::core::paths::set_test_overrides(Some(root), Some(db_dir.clone()));
    temp_env::with_vars(
        [
            ("OMG_TEST_MODE", None),
            ("OMG_TEST_DISTRO", None),
            ("OMG_PACMAN_LOCAL_DIR", None),
            ("OMG_PACMAN_SYNC_DIR", None),
            ("HOME", Some(temp.path().to_str().unwrap())),
            ("XDG_CONFIG_HOME", Some(temp.path().to_str().unwrap())),
            ("OMG_CONFIG_DIR", Some(config_dir.to_str().unwrap())),
            (
                "OMG_PACMAN_CONF",
                Some(conf.to_str().expect("configuration path")),
            ),
            (
                "OMG_CACHE_DIR",
                Some(cache_dir.to_str().expect("cache path")),
            ),
        ],
        || {
            assert!(std::env::var_os("OMG_TEST_MODE").is_none());
            assert!(!crate::core::paths::test_mode());
            assert_eq!(
                crate::core::paths::pacman_local_dir_result().unwrap(),
                local_dir
            );
            assert_eq!(
                crate::core::paths::pacman_sync_dir_result().unwrap(),
                db_dir.join("sync")
            );
            assert_eq!(crate::core::paths::cache_dir(), cache_dir);
            assert_eq!(crate::core::paths::config_dir(), config_dir);
            let native =
                crate::package_managers::alpm_direct::get_counts().expect("real libalpm counts");
            assert_eq!(
                soname_fixture_catalog(&db_dir),
                database_before,
                "libalpm count reads must preserve the private database"
            );
            assert_eq!(soname_fixture_catalog(&conf), configuration_before);
            assert_eq!(native, (3, 1, 1), "native literal positive control");

            let fast = get_counts_fast().expect("real fast-path counts");
            assert_eq!(
                soname_fixture_catalog(&db_dir),
                database_before,
                "fast count reads must preserve the private database"
            );
            assert_eq!(soname_fixture_catalog(&conf), configuration_before);
            println!(
                "[omg-soname-fixture] test={test_name} uid={} test_mode=false native={native:?} fast={fast:?} expected=(3, 1, 1)",
                nix::unistd::geteuid()
            );
            assert_eq!(
                fast,
                (3, 1, 1),
                "distinct SONAME providers must leave unrelated as the only orphan"
            );
        },
    );
}

#[test]
#[serial_test::serial]
fn fast_path_and_libalpm_counts_preserve_distinct_soname_dependencies() {
    assert_distinct_soname_providers_have_one_orphan(
        "package_managers::pacman_db::db::tests::fast_path_and_libalpm_counts_preserve_distinct_soname_dependencies",
        "\n%DEPENDS%\nlib:libfoo.so.1\n",
    );
}

#[test]
#[serial_test::serial]
fn fast_path_and_libalpm_counts_preserve_described_soname_optdependencies() {
    assert_distinct_soname_providers_have_one_orphan(
        "package_managers::pacman_db::db::tests::fast_path_and_libalpm_counts_preserve_described_soname_optdependencies",
        "\n%OPTDEPENDS%\nlib:libfoo.so.1: optional runtime support\n",
    );
}

#[test]
fn test_is_cache_reusable_rejects_expired_entries() {
    let now = SystemTime::now();
    let expired = now - std::time::Duration::from_secs(CACHE_TTL_SECS + 5);

    assert!(!is_cache_reusable(Some(now), now, true, Some(expired)));
}

#[test]
fn test_is_cache_reusable_rejects_empty_entries() {
    let now = SystemTime::now();
    let fresh = now - std::time::Duration::from_secs(1);

    assert!(!is_cache_reusable(Some(now), now, false, Some(fresh)));
}

#[test]
fn package_cache_refuses_symlinked_parent_directories() -> Result<()> {
    use std::os::unix::fs::symlink;
    let owner = tempfile::tempdir()?;
    let destination = owner.path().join("destination");
    fs::create_dir(&destination)?;
    symlink(&destination, owner.path().join("redirect"))?;
    let cache = owner.path().join("redirect/cache");
    let result = save_cache_to_disk_in(&LocalDbCache::default(), &cache, "fixture");
    assert!(
        result.is_err(),
        "cache persistence followed a symlinked parent"
    );
    assert!(!destination.join("cache/fixture.bin").exists());
    Ok(())
}

#[test]
fn read_local_package_distinguishes_missing_records_from_catalog_read_errors() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let local = directory.path().join("local");
    assert!(read_local_package_at(&local, "widget")?.is_none());
    fs::create_dir(&local)?;
    let regular_entry = local.join("widget-1-1");
    fs::write(&regular_entry, b"regular directory entry")?;
    assert!(read_local_package_at(&local, "widget")?.is_none());
    let error = find_local_package(&regular_entry, "widget")
        .expect_err("a regular file cannot serve as a local package catalog");
    assert_eq!(error.to_string(), "Failed to read local package database");
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .map(std::io::Error::kind),
        Some(std::io::ErrorKind::NotADirectory)
    );
    Ok(())
}

#[test]
fn package_cache_rejects_parent_components_and_missing_existing_directories() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let parent = open_package_cache_directory(&directory.path().join(".."), false)
        .expect_err("the cache path must stay within its declared scope");
    assert!(
        parent
            .to_string()
            .contains("must not traverse parent directories")
    );
    let missing = directory.path().join("absent");
    assert!(open_package_cache_directory(&missing, false).is_err());
    assert!(!missing.exists());
    Ok(())
}

#[test]
fn package_cache_reports_read_only_parent_without_publishing() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    const TEST: &str = "package_managers::pacman_db::db::tests::package_cache_reports_read_only_parent_without_publishing";
    if crate::config::Settings::rerun_test_unprivileged(TEST) {
        return Ok(());
    }
    let owner = tempfile::tempdir()?;
    let existing = owner.path().join("existing");
    let missing = owner.path().join("missing");
    fs::create_dir(&existing)?;
    let writable = fs::Permissions::from_mode(0o700);
    let read_only = fs::Permissions::from_mode(0o500);
    fs::set_permissions(&existing, read_only.clone())?;
    fs::set_permissions(owner.path(), read_only)?;

    let cache = LocalDbCache::default();
    let create_directory = save_cache_to_disk_in(&cache, &missing, "fixture");
    let create_archive = save_cache_to_disk_in(&cache, &existing, "fixture");

    fs::set_permissions(owner.path(), writable.clone())?;
    fs::set_permissions(&existing, writable)?;
    for result in [create_directory, create_archive] {
        let error = result.expect_err("read-only cache setup must refuse publication");
        assert_eq!(
            error.downcast_ref::<rustix::io::Errno>(),
            Some(&rustix::io::Errno::ACCESS)
        );
    }
    assert!(!missing.exists());
    assert_eq!(fs::read_dir(existing)?.count(), 0);
    Ok(())
}

#[test]
fn failed_cache_publication_keeps_the_existing_entry_and_cleans_the_temporary_file() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let existing = directory.path().join("fixture.bin");
    fs::create_dir(&existing)?;
    fs::write(existing.join("sentinel"), b"existing cache entry")?;
    assert!(save_cache_to_disk_in(&DbCache::default(), directory.path(), "fixture").is_err());
    let owner = open_package_cache_directory(directory.path(), false)?;
    remove_temporary_package_cache(&owner, "already-gone.tmp");
    remove_temporary_package_cache(&owner, "fixture.bin");
    assert_eq!(
        fs::read(existing.join("sentinel"))?,
        b"existing cache entry"
    );
    assert_eq!(fs::read_dir(directory.path())?.count(), 1);
    Ok(())
}

#[test]
fn persisted_package_cache_rejects_symlink_and_oversized_file() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let target = directory.path().join("valid");
    fs::write(&target, bitcode::serialize(&DbCache::default())?)?;
    let path = directory.path().join("fixture.bin");
    std::os::unix::fs::symlink(&target, &path)?;
    assert!(load_cache_from_disk_in::<DbCache>(directory.path(), "fixture").is_err());
    assert!(load_cache_from_disk_in::<LocalDbCache>(directory.path(), "fixture").is_err());
    fs::remove_file(&path)?;
    let file = fs::File::create(&path)?;
    file.set_len(MAX_DERIVED_CACHE_BYTES + 1)?;
    let error = load_cache_from_disk_in::<DbCache>(directory.path(), "fixture")
        .err()
        .context("oversized cache must fail before decoding")?;
    assert!(error.to_string().contains("size limit"), "{error:#}");
    assert!(load_cache_from_disk_in::<LocalDbCache>(directory.path(), "fixture").is_err());
    Ok(())
}

#[test]
fn package_cache_refuses_shared_writable_directories() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let owner = tempfile::tempdir()?;
    let cache = owner.path().join("shared");
    fs::create_dir(&cache)?;
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o777))?;
    fs::write(
        cache.join("fixture.bin"),
        bitcode::serialize(&LocalDbCache::default())?,
    )
    .expect("write a valid cache record under the shared writable parent");
    let loaded = load_cache_from_disk_in::<LocalDbCache>(&cache, "fixture");
    let saved = save_cache_to_disk_in(&LocalDbCache::default(), &cache, "other");
    assert!(
        loaded.is_err(),
        "derived cache trusted a shared writable directory"
    );
    assert!(
        saved.is_err(),
        "derived cache wrote into a shared writable directory"
    );
    assert!(!cache.join("other.bin").exists());
    Ok(())
}

#[test]
fn package_cache_refuses_writable_and_hardlinked_files() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let owner = tempfile::tempdir()?;
    let path = owner.path().join("fixture.bin");
    fs::write(&path, bitcode::serialize(&LocalDbCache::default())?)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666))?;
    let writable_accepted =
        load_cache_from_disk_in::<LocalDbCache>(owner.path(), "fixture").is_ok();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    fs::hard_link(&path, owner.path().join("alias.bin"))?;
    let hardlink_accepted =
        load_cache_from_disk_in::<LocalDbCache>(owner.path(), "fixture").is_ok();
    assert_eq!(
        [writable_accepted, hardlink_accepted],
        [false, false],
        "unsafe cache files were accepted"
    );
    Ok(())
}

#[test]
fn package_cache_refuses_fifo_without_waiting_for_its_writer() -> Result<()> {
    const TEST: &str = "package_managers::pacman_db::db::tests::package_cache_refuses_fifo_without_waiting_for_its_writer";
    if crate::core::testing::run_isolated_test_with_timeout(TEST, std::time::Duration::from_secs(5))
    {
        return Ok(());
    }
    let owner = tempfile::tempdir()?;
    let path = owner.path().join("fixture.bin");
    nix::unistd::mkfifo(
        &path,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .expect("create the derived cache's nonregular-file fixture");
    let error = load_cache_from_disk_in::<LocalDbCache>(owner.path(), "fixture")
        .err()
        .context("reject a FIFO with no writer")?;
    assert!(format!("{error:#}").contains("regular"), "{error:#}");
    Ok(())
}

#[test]
fn package_cache_round_trips_through_atomic_persist() {
    let temp = tempfile::TempDir::new().unwrap();
    let cache = LocalDbCache {
        packages: HashMap::from([(
            "firefox".to_string(),
            LocalDbPackage {
                name: "firefox".to_string(),
                ..Default::default()
            },
        )]),
        last_modified: Some(LocalDbEpoch::from_local_dir(temp.path()).unwrap()),
        last_accessed: None,
    };

    fs::write(temp.path().join("local_db_rdeps.bin"), b"legacy cache").unwrap();
    save_cache_to_disk_in(&cache, temp.path(), LOCAL_CACHE_NAME).unwrap();
    let loaded: LocalDbCache = load_cache_from_disk_in(temp.path(), LOCAL_CACHE_NAME).unwrap();
    assert!(loaded.packages.contains_key("firefox"));
    assert_eq!(loaded.last_modified, cache.last_modified);
    assert_eq!(
        fs::read(temp.path().join("local_db_rdeps.bin")).unwrap(),
        b"legacy cache"
    );
}

#[test]
fn package_cache_persist_refuses_to_clobber_a_directory() {
    let temp = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(temp.path().join("local_db.bin")).unwrap();

    let error = save_cache_to_disk_in(&LocalDbCache::default(), temp.path(), "local_db")
        .expect_err("must refuse to persist over a directory");
    assert!(!error.to_string().is_empty());
}

#[test]
fn test_is_cache_reusable_accepts_fresh_matching_cache() {
    let now = SystemTime::now();
    let fresh = now - std::time::Duration::from_secs(2);

    assert!(is_cache_reusable(Some(now), now, true, Some(fresh)));
}
