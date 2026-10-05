//! Debian/Ubuntu Performance Benchmarks
//!
//! Measures performance of the pure Rust Debian implementation.
//! Run with: `cargo bench --features debian-pure --bench debian_bench`
//!
//! Shared scenario data lives in `benches/debian_common/mod.rs`.

#[cfg(any(feature = "debian", feature = "debian-pure"))]
#[path = "debian_common/mod.rs"]
mod debian_common;

#[cfg(any(feature = "debian", feature = "debian-pure"))]
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

#[cfg(any(feature = "debian", feature = "debian-pure"))]
use std::time::Duration;

#[cfg(any(feature = "debian", feature = "debian-pure"))]
use omg_lib::package_managers::debian_db::{
    DependencyResolver, compare_versions, get_info_fast, get_package_dependencies,
    list_installed_fast, search_fast,
};

#[cfg(any(feature = "debian", feature = "debian-pure"))]
fn bench_search(c: &mut Criterion) {
    let mut group = c.benchmark_group("debian_search");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(100);

    // Ensure index is loaded once
    debian_common::warm_index();

    let queries = vec![
        "vim", "gcc", "python", "lib", "x11", "systemd", "kernel", "firefox",
    ];

    for query in queries {
        group.bench_with_input(BenchmarkId::new("search_fast", query), &query, |b, &q| {
            b.iter(|| {
                let results = search_fast(q).expect("search should succeed");
                std::hint::black_box(results)
            });
        });
    }

    group.finish();
}

#[cfg(any(feature = "debian", feature = "debian-pure"))]
fn bench_info(c: &mut Criterion) {
    let mut group = c.benchmark_group("debian_info");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(100);

    debian_common::warm_index();

    let packages = vec![
        "vim",
        "gcc",
        "libc6",
        "systemd",
        "bash",
        "coreutils",
        "util-linux",
        "dpkg",
    ];

    for pkg in packages {
        group.bench_with_input(BenchmarkId::new("get_info_fast", pkg), &pkg, |b, &p| {
            b.iter(|| {
                let info = get_info_fast(p);
                std::hint::black_box(info)
            });
        });
    }

    group.finish();
}

#[cfg(any(feature = "debian", feature = "debian-pure"))]
fn bench_list_installed(c: &mut Criterion) {
    let mut group = c.benchmark_group("debian_list");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(50);

    group.bench_function("list_installed_fast", |b| {
        b.iter(|| {
            let packages = list_installed_fast().expect("list should succeed");
            std::hint::black_box(packages)
        });
    });

    group.finish();
}

#[cfg(any(feature = "debian", feature = "debian-pure"))]
fn bench_dependencies(c: &mut Criterion) {
    let mut group = c.benchmark_group("debian_dependencies");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);

    for (name, pkg) in debian_common::RESOLVE_SCENARIOS {
        group.bench_with_input(BenchmarkId::new("get_dependencies", *name), pkg, |b, &p| {
            b.iter(|| {
                let deps = get_package_dependencies(p);
                std::hint::black_box(deps)
            });
        });
    }

    group.finish();
}

#[cfg(any(feature = "debian", feature = "debian-pure"))]
fn bench_resolver(c: &mut Criterion) {
    let mut group = c.benchmark_group("debian_resolver");
    group.measurement_time(Duration::from_secs(15));
    group.sample_size(30);

    group.bench_function("resolve_single_package", |b| {
        b.iter(|| {
            let mut resolver = DependencyResolver::new().expect("resolver creation should succeed");
            resolver
                .add_package("vim")
                .expect("add_package should succeed");
            let result = resolver.resolve();
            std::hint::black_box(result)
        });
    });

    group.bench_function("resolve_multiple_packages", |b| {
        b.iter(|| {
            let mut resolver = DependencyResolver::new().expect("resolver creation should succeed");
            resolver
                .add_package("vim")
                .expect("add_package should succeed");
            resolver
                .add_package("git")
                .expect("add_package should succeed");
            resolver
                .add_package("curl")
                .expect("add_package should succeed");
            let result = resolver.resolve();
            std::hint::black_box(result)
        });
    });

    group.bench_function("resolve_large_package", |b| {
        b.iter(|| {
            let mut resolver = DependencyResolver::new().expect("resolver creation should succeed");
            // Large packages with many dependencies
            resolver
                .add_package("build-essential")
                .expect("build-essential benchmark seed should be available");
            let result = resolver.resolve();
            std::hint::black_box(result)
        });
    });

    group.finish();
}

#[cfg(any(feature = "debian", feature = "debian-pure"))]
fn bench_version_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("debian_version_compare");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(200);

    for (name, v1, v2) in debian_common::VERSION_SCENARIOS {
        group.bench_with_input(
            BenchmarkId::new("compare_versions", *name),
            &(*v1, *v2),
            |bencher, &(ver1, ver2)| {
                bencher.iter(|| {
                    let result = compare_versions(ver1, ver2);
                    std::hint::black_box(result)
                });
            },
        );
    }

    group.finish();
}

#[cfg(any(feature = "debian", feature = "debian-pure"))]
criterion_group!(
    debian_benches,
    bench_search,
    bench_info,
    bench_list_installed,
    bench_dependencies,
    bench_resolver,
    bench_version_comparison
);

#[cfg(any(feature = "debian", feature = "debian-pure"))]
criterion_main!(debian_benches);

#[cfg(not(any(feature = "debian", feature = "debian-pure")))]
fn main() {
    println!("Debian benchmarks require --features debian-pure or --features debian");
}
