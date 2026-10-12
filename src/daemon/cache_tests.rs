#![expect(clippy::unwrap_used)]

use super::*;

#[test]
fn test_cache_basic_ops() {
    let cache = PackageCache::new(10, 60);
    let pkg = PackageInfo {
        name: "test".to_string(),
        version: "1.0".to_string(),
        description: "desc".to_string(),
        source: crate::daemon::protocol::WirePackageSource::Official,
    };

    // Insert
    cache.insert_arc("query".to_string(), Arc::new(vec![pkg]));

    // Get
    let res = cache.get("query").unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].name, "test");

    // Flush Moka's pending accounting before asserting the public statistic.
    cache.sync();
    assert_eq!(cache.stats().size, 1);

    // Clear
    cache.clear();
    assert!(cache.get("query").is_none());
}

#[test]
fn test_cache_miss_handling() {
    let cache = PackageCache::new(10, 60);

    assert!(!cache.is_info_miss("missing"));
    cache.insert_info_miss("missing");
    assert!(cache.is_info_miss("missing"));

    // Inserting info should clear miss
    let info = DetailedPackageInfo {
        name: "missing".to_string(),
        version: "1.0".to_string(),
        description: String::new(),
        url: String::new(),
        size: 0,
        download_size: 0,
        repo: String::new(),
        depends: vec![],
        licenses: vec![],
        source: crate::daemon::protocol::WirePackageSource::Official,
    };
    cache.insert_info(info);
    assert!(!cache.is_info_miss("missing"));
    let cached = cache.get_info("missing");
    assert_eq!(
        cached.as_ref().map(|info| info.name.as_str()),
        Some("missing")
    );
    assert_eq!(
        cached.as_ref().map(|info| info.version.as_str()),
        Some("1.0")
    );
}

#[test]
fn oversized_search_value_is_not_admitted_to_the_byte_bounded_cache() {
    let cache = PackageCache::new(1, 60);
    let oversized = PackageInfo {
        name: "oversized".to_string(),
        version: "1".to_string(),
        description: "x".repeat(CACHE_BYTES_PER_CONFIGURED_ENTRY * 2),
        source: crate::daemon::protocol::WirePackageSource::Official,
    };

    cache.insert_arc("large".to_string(), Arc::new(vec![oversized]));
    cache.sync();

    assert!(cache.get("large").is_none());
    cache.insert_arc(
        "small".to_string(),
        Arc::new(vec![PackageInfo {
            name: "small-package".to_string(),
            version: "1.0".to_string(),
            description: "small payload".to_string(),
            source: crate::daemon::protocol::WirePackageSource::Official,
        }]),
    );
    cache.sync();
    let cached = cache.get("small");
    assert_eq!(
        cached.as_ref().map(|rows| rows[0].name.as_str()),
        Some("small-package")
    );
    assert_eq!(
        cached.as_ref().map(|rows| rows[0].version.as_str()),
        Some("1.0")
    );
}

#[test]
fn status_refresh_invalidates_the_previous_explicit_list() {
    let cache = PackageCache::new_with_ttls(10, 600, 60);
    cache.update_explicit(vec!["old-package".to_string()]);
    assert_eq!(cache.get_explicit().unwrap().as_slice(), ["old-package"]);

    cache.update_status(Arc::new(StatusResult {
        total_packages: 100,
        explicit_packages: 2,
        orphan_packages: 5,
        updates_available: 2,
        security_vulnerabilities: 0,
        vulnerabilities_scanned: true,
        runtime_versions: vec![],
    }));

    cache.sync();
    assert_eq!(cache.get_explicit_count(), Some(2));
    assert!(cache.get_explicit().is_none());
}

#[test]
fn test_system_status_cache() {
    let cache = PackageCache::new(10, 60);
    let status = StatusResult {
        total_packages: 100,
        explicit_packages: 10,
        orphan_packages: 5,
        updates_available: 2,
        security_vulnerabilities: 0,
        vulnerabilities_scanned: true,
        runtime_versions: vec![],
    };

    cache.update_status(Arc::new(status));
    let cached = cache.get_status().unwrap();
    assert_eq!(cached.total_packages, 100);
    assert_eq!(cached.explicit_packages, 10);
    assert_eq!(cached.orphan_packages, 5);
    assert_eq!(cached.updates_available, 2);
}

fn populated_cache(ttl_secs: u64, status_ttl_secs: u64) -> PackageCache {
    use crate::daemon::protocol::WirePackageSource;

    let cache = PackageCache::new_with_ttls(10, ttl_secs, status_ttl_secs);
    cache.insert_arc(
        "search".to_string(),
        Arc::new(vec![
            PackageInfo {
                name: "alpha".to_string(),
                version: "1.0".to_string(),
                description: "first result".to_string(),
                source: WirePackageSource::Official,
            },
            PackageInfo {
                name: "beta".to_string(),
                version: "2.0".to_string(),
                description: "second result".to_string(),
                source: WirePackageSource::Aur,
            },
        ]),
    );
    cache.insert_debian_arc(
        "debian".to_string(),
        Arc::new(vec![PackageInfo {
            name: "deb".to_string(),
            version: "3.0".to_string(),
            description: "Debian result".to_string(),
            source: WirePackageSource::Apt,
        }]),
    );
    cache.insert_info(DetailedPackageInfo {
        name: "found".to_string(),
        version: "4.0".to_string(),
        description: "detailed result".to_string(),
        url: "https://example.test/found".to_string(),
        size: 123,
        download_size: 45,
        repo: "fixture-repo".to_string(),
        depends: vec!["dependency".to_string()],
        licenses: vec!["MIT".to_string()],
        source: WirePackageSource::Official,
    });
    cache.insert_info_miss("missing");
    cache.update_status(Arc::new(StatusResult {
        total_packages: 12,
        explicit_packages: 2,
        orphan_packages: 3,
        updates_available: 4,
        security_vulnerabilities: 5,
        vulnerabilities_scanned: true,
        runtime_versions: vec![("rust".to_string(), "1.95".to_string())],
    }));
    cache.update_explicit(vec!["alpha".to_string(), "beta".to_string()]);
    cache.sync();
    cache
}

fn assert_general_payloads(cache: &PackageCache) {
    use crate::daemon::protocol::WirePackageSource;

    let search = cache.get("search").unwrap();
    let rows = search
        .iter()
        .map(|row| {
            (
                row.name.as_str(),
                row.version.as_str(),
                row.description.as_str(),
                row.source,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        rows,
        [
            ("alpha", "1.0", "first result", WirePackageSource::Official),
            ("beta", "2.0", "second result", WirePackageSource::Aur),
        ]
    );
    let debian = cache.get_debian("debian").unwrap();
    assert_eq!(debian.len(), 1);
    assert_eq!(
        (
            debian[0].name.as_str(),
            debian[0].version.as_str(),
            debian[0].description.as_str(),
            debian[0].source,
        ),
        ("deb", "3.0", "Debian result", WirePackageSource::Apt)
    );
    let info = cache.get_info("found").unwrap();
    assert_eq!(
        (
            info.name.as_str(),
            info.version.as_str(),
            info.description.as_str(),
            info.url.as_str(),
            info.size,
            info.download_size,
            info.repo.as_str(),
            info.source,
        ),
        (
            "found",
            "4.0",
            "detailed result",
            "https://example.test/found",
            123,
            45,
            "fixture-repo",
            WirePackageSource::Official,
        )
    );
    assert_eq!(info.depends.as_slice(), ["dependency"]);
    assert_eq!(info.licenses.as_slice(), ["MIT"]);
    assert!(cache.is_info_miss("missing"));
    assert!(!cache.is_info_miss("found"));
}

fn assert_status_payloads(cache: &PackageCache) {
    let status = cache.get_status().unwrap();
    assert_eq!(
        (
            status.total_packages,
            status.explicit_packages,
            status.orphan_packages,
            status.updates_available,
            status.security_vulnerabilities,
            status.vulnerabilities_scanned,
        ),
        (12, 2, 3, 4, 5, true)
    );
    assert_eq!(
        status.runtime_versions.as_slice(),
        [("rust".to_string(), "1.95".to_string())]
    );
    assert_eq!(cache.get_explicit().unwrap().as_slice(), ["alpha", "beta"]);
    assert_eq!(cache.get_explicit_count(), Some(2));
}

fn assert_general_empty(cache: &PackageCache) {
    assert!(cache.get("search").is_none());
    assert!(cache.get_debian("debian").is_none());
    assert!(cache.get_info("found").is_none());
    assert!(!cache.is_info_miss("missing"));
}

fn assert_status_empty(cache: &PackageCache) {
    assert!(cache.get_status().is_none());
    assert!(cache.get_explicit().is_none());
    assert!(cache.get_explicit_count().is_none());
}

#[test]
fn general_ttl_expires_without_expiring_status_values() {
    let positive = populated_cache(60, 60);
    assert_general_payloads(&positive);
    assert_status_payloads(&positive);

    let cache = populated_cache(0, 60);
    assert_general_empty(&cache);
    assert_status_payloads(&cache);
}

#[test]
fn status_ttl_expires_without_expiring_general_values() {
    let positive = populated_cache(60, 60);
    assert_general_payloads(&positive);
    assert_status_payloads(&positive);

    let cache = populated_cache(60, 0);
    assert_general_payloads(&cache);
    assert_status_empty(&cache);
}

#[test]
fn clear_removes_every_populated_cache_domain() {
    let cache = populated_cache(60, 60);
    assert_general_payloads(&cache);
    assert_status_payloads(&cache);
    assert_eq!(cache.stats().size, 7);

    cache.clear();

    assert_general_empty(&cache);
    assert_status_empty(&cache);
    assert_eq!(cache.stats().size, 0);
}

#[test]
fn explicit_refresh_replaces_status_count_without_changing_status_snapshot() {
    let cache = PackageCache::new_with_ttls(10, 60, 60);
    cache.update_status(Arc::new(StatusResult {
        total_packages: 99,
        explicit_packages: 17,
        orphan_packages: 3,
        updates_available: 4,
        security_vulnerabilities: 5,
        vulnerabilities_scanned: true,
        runtime_versions: vec![("rust".to_string(), "1.95".to_string())],
    }));
    assert_eq!(cache.get_explicit_count(), Some(17));
    assert!(cache.get_explicit().is_none());
    assert_eq!(cache.get_status().unwrap().explicit_packages, 17);

    cache.update_explicit(vec!["alpha".to_string(), "beta".to_string()]);
    cache.sync();

    assert_eq!(cache.get_explicit().unwrap().as_slice(), ["alpha", "beta"]);
    assert_eq!(cache.get_explicit_count(), Some(2));
    let status = cache.get_status().unwrap();
    assert_eq!(
        (
            status.total_packages,
            status.explicit_packages,
            status.orphan_packages,
            status.updates_available,
            status.security_vulnerabilities,
            status.vulnerabilities_scanned,
        ),
        (99, 17, 3, 4, 5, true)
    );
    assert_eq!(
        status.runtime_versions.as_slice(),
        [("rust".to_string(), "1.95".to_string())]
    );
}
