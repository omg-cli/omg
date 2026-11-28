use super::check_native_local_db_health;
use std::path::Path;

fn package(database: &Path, name: &str, version: &str, extra: &str, files: &str) {
    let directory = database.join("local").join(format!("{name}-{version}"));
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("desc"),
        format!("%NAME%\n{name}\n\n%VERSION%\n{version}\n\n%REASON%\n0\n\n{extra}"),
    )
    .unwrap();
    std::fs::write(directory.join("files"), format!("%FILES%\n{files}\n\n")).unwrap();
}

#[tokio::test]
async fn native_health_accepts_shared_directories_without_writes_or_repository_access() {
    let owner = tempfile::tempdir().unwrap();
    let database = owner.path();
    let local = database.join("local");
    package(
        database,
        "app",
        "1.0-1",
        "%DEPENDS%\nvirtual>=2\n\n",
        "usr/\nusr/bin/app",
    );
    package(
        database,
        "provider",
        "1.0-1",
        "%PROVIDES%\nvirtual=2\n\n",
        "usr/\nusr/lib/provider",
    );
    std::fs::write(local.join("ALPM_DB_VERSION"), "9\n").unwrap();
    let before = super::LocalHealthSnapshot::capture(&local).unwrap();
    let report = check_native_local_db_health(&local).await.unwrap();
    assert_eq!(report.packages, 2);
    assert!(report.missing.is_empty());
    report.native.unwrap();
    before.revalidate(&local).unwrap();
    assert!(!database.join("db.lck").exists());
    assert!(!database.join("sync").exists());
}

#[tokio::test]
async fn native_health_accepts_an_explicit_zero_epoch_in_the_local_database() {
    let owner = tempfile::tempdir().unwrap();
    let local = owner.path().join("local");
    package(owner.path(), "app", "0:1.0-1", "", "usr/bin/app");
    std::fs::write(local.join("ALPM_DB_VERSION"), "9\n").unwrap();
    let mut before = super::LocalHealthSnapshot::capture(&local).unwrap();
    let report = check_native_local_db_health(&local).await.unwrap();
    assert_eq!(report.packages, 1);
    report.native.unwrap();
    before.revalidate(&local).unwrap();
    before.packages.get_mut("app").unwrap().version =
        super::require_package_version("1:1.0-1").unwrap();
    let mismatch = super::inspect_native_local_database(&local, &before).unwrap_err();
    assert_eq!(
        mismatch.to_string(),
        "Native local database version differs for app"
    );
    assert!(!owner.path().join("db.lck").exists());
}

#[tokio::test]
async fn native_health_refuses_missing_dependencies_conflicts_and_shared_files() {
    for (extra, files, expected) in [
        (
            "%DEPENDS%\nabsent>=2\n\n",
            "usr/bin/app",
            "requires absent>=2",
        ),
        (
            "%CONFLICTS%\nother\n\n",
            "usr/bin/app",
            "Installed package conflict",
        ),
        ("", "usr/bin/shared", "Duplicate installed file ownership"),
    ] {
        let owner = tempfile::tempdir().unwrap();
        let local = owner.path().join("local");
        package(owner.path(), "app", "1.0-1", extra, files);
        package(owner.path(), "other", "1.0-1", "", "usr/bin/shared");
        std::fs::write(local.join("ALPM_DB_VERSION"), "9\n").unwrap();
        let before = super::LocalHealthSnapshot::capture(&local).unwrap();
        let report = check_native_local_db_health(&local).await.unwrap();
        let error = report.native.expect_err("unhealthy native database");
        assert!(
            error.to_string().contains(expected),
            "{expected}: {error:#}"
        );
        before.revalidate(&local).unwrap();
        assert!(!owner.path().join("db.lck").exists());
    }
}
