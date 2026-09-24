#[cfg(any(feature = "debian", feature = "debian-pure"))]
use omg_lib::daemon::handlers::DaemonState;
#[cfg(any(feature = "debian", feature = "debian-pure"))]
use omg_lib::daemon::protocol::Request;
#[cfg(any(feature = "debian", feature = "debian-pure"))]
use omg_lib::package_managers::debian_db;
#[cfg(any(feature = "debian", feature = "debian-pure"))]
use serde::{Deserialize, Serialize};
#[cfg(any(feature = "debian", feature = "debian-pure"))]
use serial_test::serial;
#[cfg(any(feature = "debian", feature = "debian-pure"))]
use std::sync::Arc;
#[cfg(any(feature = "debian", feature = "debian-pure"))]
use std::time::Instant;

#[cfg(any(feature = "debian", feature = "debian-pure"))]
#[derive(Debug, Serialize)]
struct BenchMetric {
    operation: String,
    mode: String,
    iterations: u32,
    total_ms: f64,
    avg_ms: f64,
    min_ms: f64,
    max_ms: f64,
}

#[cfg(any(feature = "debian", feature = "debian-pure"))]
#[derive(Debug, Serialize)]
struct BenchReport {
    distro: String,
    iterations: u32,
    metrics: Vec<BenchMetric>,
}

#[cfg(any(feature = "debian", feature = "debian-pure"))]
#[derive(Debug, Deserialize)]
struct BaselineMetric {
    operation: String,
    mode: String,
    avg_ms: f64,
}

#[cfg(any(feature = "debian", feature = "debian-pure"))]
#[derive(Debug, Deserialize)]
struct BaselineReport {
    metrics: Vec<BaselineMetric>,
}

#[cfg(any(feature = "debian", feature = "debian-pure"))]
fn summarize(operation: &str, mode: &str, samples_ms: &[f64]) -> BenchMetric {
    let total_ms: f64 = samples_ms.iter().sum();
    let min_ms = samples_ms.iter().copied().fold(f64::INFINITY, f64::min);
    let max_ms = samples_ms.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let iterations = u32::try_from(samples_ms.len()).unwrap_or(0);
    let avg_ms = if iterations == 0 {
        0.0
    } else {
        total_ms / f64::from(iterations)
    };

    BenchMetric {
        operation: operation.to_string(),
        mode: mode.to_string(),
        iterations,
        total_ms,
        avg_ms,
        min_ms,
        max_ms,
    }
}

#[cfg(any(feature = "debian", feature = "debian-pure"))]
fn maybe_write_report(report: &BenchReport) {
    if !matches!(std::env::var("OMG_BENCH_WRITE_JSON"), Ok(v) if v == "1") {
        return;
    }

    let output_path = std::env::var("OMG_BENCH_JSON_OUT")
        .unwrap_or_else(|_| "target/bench/debian-matrix.json".to_string());
    let path = std::path::PathBuf::from(&output_path);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("Failed to create benchmark report directory");
    }

    let json = serde_json::to_string_pretty(report).expect("Failed to serialize benchmark report");
    std::fs::write(path, json).expect("Failed to write benchmark report");
}

#[cfg(any(feature = "debian", feature = "debian-pure"))]
fn maybe_check_baseline(report: &BenchReport) {
    let baseline_path = match std::env::var("OMG_BENCH_BASELINE_JSON") {
        Ok(path) if !path.is_empty() => path,
        _ => return,
    };

    let multiplier = match std::env::var("OMG_BENCH_REGRESSION_MULTIPLIER") {
        Ok(raw) => {
            let parsed = raw
                .parse::<f64>()
                .expect("OMG_BENCH_REGRESSION_MULTIPLIER must be a number");
            assert!(
                parsed.is_finite() && parsed >= 1.0,
                "OMG_BENCH_REGRESSION_MULTIPLIER must be finite and at least 1.0"
            );
            parsed
        }
        Err(_) => 2.0,
    };

    let baseline_content =
        std::fs::read_to_string(&baseline_path).expect("Failed to read benchmark baseline file");
    let baseline: BaselineReport =
        serde_json::from_str(&baseline_content).expect("Failed to parse benchmark baseline JSON");

    for current in &report.metrics {
        if current.mode != "warm" {
            continue;
        }

        let base = baseline
            .metrics
            .iter()
            .find(|metric| metric.operation == current.operation && metric.mode == current.mode)
            .unwrap_or_else(|| {
                panic!(
                    "Benchmark baseline is missing {}:{}",
                    current.operation, current.mode
                )
            });

        let allowed = base.avg_ms * multiplier;
        assert!(
            current.avg_ms <= allowed,
            "Benchmark regression detected for {}:{} avg={:.4}ms baseline={:.4}ms allowed={:.4}ms (x{multiplier:.2})",
            current.operation,
            current.mode,
            current.avg_ms,
            base.avg_ms,
            allowed
        );
    }
}

#[cfg(any(feature = "debian", feature = "debian-pure"))]
#[test]
#[serial]
fn bench_debian_deterministic_matrix() {
    use omg_lib::daemon::handlers::handle_request;
    use omg_lib::package_managers::debian_db::resolver::DependencyResolver;
    use omg_lib::package_managers::debian_db::transaction;

    const WARM_ITERS: u32 = 48;

    let temp_dir = tempfile::tempdir().unwrap();
    let temp_path = temp_dir.path().to_str().unwrap().to_string();

    temp_env::with_vars(
        [
            ("OMG_TEST_MODE", Some("true")),
            ("OMG_TEST_DISTRO", Some("debian")),
            ("OMG_DATA_DIR", Some(temp_path.as_str())),
            ("OMG_DAEMON_DATA_DIR", Some(temp_path.as_str())),
        ],
        || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let state = Arc::new(DaemonState::new().unwrap());

                let mut cold_search = Vec::new();
                let mut warm_search = Vec::new();
                let mut cold_info = Vec::new();
                let mut warm_info = Vec::new();
                let mut cold_install_dry_run = Vec::new();
                let mut warm_install_dry_run = Vec::new();

                let start = Instant::now();
                let req = Request::DebianSearch {
                    id: 1,
                    query: "apt".to_string(),
                    limit: Some(10),
                };
                let _ = handle_request(state.clone(), req).await;
                cold_search.push(start.elapsed().as_secs_f64() * 1000.0);

                for i in 0..WARM_ITERS {
                    let start = Instant::now();
                    let req = Request::DebianSearch {
                        id: 1000 + u64::from(i),
                        query: "apt".to_string(),
                        limit: Some(10),
                    };
                    let _ = handle_request(state.clone(), req).await;
                    warm_search.push(start.elapsed().as_secs_f64() * 1000.0);
                }

                let start = Instant::now();
                let info_cold = debian_db::get_info_fast("apt").unwrap();
                cold_info.push(start.elapsed().as_secs_f64() * 1000.0);
                assert!(info_cold.is_some(), "Expected apt package info to exist");

                for _ in 0..WARM_ITERS {
                    let start = Instant::now();
                    let info = debian_db::get_info_fast("apt").unwrap();
                    assert!(info.is_some(), "Expected apt package info to exist");
                    warm_info.push(start.elapsed().as_secs_f64() * 1000.0);
                }

                let start = Instant::now();
                let mut cold_resolver = DependencyResolver::new().unwrap();
                cold_resolver.add_package("apt").unwrap();
                let cold_result = cold_resolver.resolve().unwrap();
                let _ = transaction::dry_run(&cold_result);
                cold_install_dry_run.push(start.elapsed().as_secs_f64() * 1000.0);

                for _ in 0..WARM_ITERS {
                    let start = Instant::now();
                    let mut resolver = DependencyResolver::new().unwrap();
                    resolver.add_package("apt").unwrap();
                    let result = resolver.resolve().unwrap();
                    let _ = transaction::dry_run(&result);
                    warm_install_dry_run.push(start.elapsed().as_secs_f64() * 1000.0);
                }

                let metrics = vec![
                    summarize("search", "cold", &cold_search),
                    summarize("search", "warm", &warm_search),
                    summarize("info", "cold", &cold_info),
                    summarize("info", "warm", &warm_info),
                    summarize("install_dry_run", "cold", &cold_install_dry_run),
                    summarize("install_dry_run", "warm", &warm_install_dry_run),
                ];

                for metric in &metrics {
                    println!(
                        "{}:{} avg={:.4}ms min={:.4}ms max={:.4}ms n={}",
                        metric.operation,
                        metric.mode,
                        metric.avg_ms,
                        metric.min_ms,
                        metric.max_ms,
                        metric.iterations
                    );
                }

                let report = BenchReport {
                    distro: "debian".to_string(),
                    iterations: WARM_ITERS,
                    metrics,
                };
                maybe_write_report(&report);
                maybe_check_baseline(&report);

                let warm_search_avg = report
                    .metrics
                    .iter()
                    .find(|m| m.operation == "search" && m.mode == "warm")
                    .map_or(999.0, |m| m.avg_ms);
                let warm_info_avg = report
                    .metrics
                    .iter()
                    .find(|m| m.operation == "info" && m.mode == "warm")
                    .map_or(999.0, |m| m.avg_ms);
                let warm_dry_run_avg = report
                    .metrics
                    .iter()
                    .find(|m| m.operation == "install_dry_run" && m.mode == "warm")
                    .map_or(999.0, |m| m.avg_ms);

                assert!(
                    warm_search_avg < 40.0,
                    "Warm Debian search avg should be <40ms, got {warm_search_avg:.4}ms"
                );
                assert!(
                    warm_info_avg < 40.0,
                    "Warm Debian info avg should be <40ms, got {warm_info_avg:.4}ms"
                );
                assert!(
                    warm_dry_run_avg < 200.0,
                    "Warm Debian install dry-run avg should be <200ms, got {warm_dry_run_avg:.4}ms"
                );
            });
        },
    );
}
