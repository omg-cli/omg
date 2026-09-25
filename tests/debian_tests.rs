#![cfg(any(feature = "debian", feature = "debian-pure"))]
#![expect(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]
//! Debian/Ubuntu CLI integration tests with mixed evidence boundaries.
//!
//! `TestProject` fixtures keep mock package operations in isolated state, but
//! some CLI read paths query the host Debian database. Opt-in system cases are
//! not hermetic and belong only in disposable environments. Enable them with:
//! `OMG_RUN_SYSTEM_TESTS=1 OMG_TEST_DISTRO=debian cargo test --locked --no-default-features --features debian-pure --test debian_tests`.
//!
//! Real package-system mutations run in disposable Docker/QEMU owners; see
//! `scripts/debian-smoke-test.sh` and the QEMU inventory.

pub mod common;
pub mod platform_semantics;

use common::fixtures::*;
use common::*;
use platform_semantics::{assert_no_arch_terms, assert_no_fedora_terms, assert_no_macos_terms};

fn assert_debian_platform_purity(result: &CommandResult, context: &str) {
    let output = result.combined_output();
    assert_no_arch_terms(&output, context);
    assert_no_fedora_terms(&output, context);
    assert_no_macos_terms(&output, context);
}

// ═══════════════════════════════════════════════════════════════════════════════
// DOCKER INTEGRATION
// ═══════════════════════════════════════════════════════════════════════════════

mod docker_integration {
    use std::path::Path;

    #[test]
    fn test_docker_smoke_test_script_exists() {
        // This ensures the smoke test script we expect for CI is present
        let script_path = Path::new("scripts/debian-smoke-test.sh");
        assert!(script_path.exists(), "debian-smoke-test.sh missing");

        // Basic check that it's executable (on unix)
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = script_path.metadata().expect("failed to get metadata");
            assert_eq!(meta.mode() & 0o111, 0o111, "Script should be executable");
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// APT INTEGRATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod apt_integration {
    use super::*;

    fn native_candidate(package: &str) -> String {
        let installed = std::process::Command::new("dpkg-query")
            .args(["-W", package])
            .output()
            .expect("query native dpkg state");
        assert!(
            installed.status.success(),
            "{package} must be installed: {}",
            String::from_utf8_lossy(&installed.stderr)
        );
        let policy = std::process::Command::new("apt-cache")
            .args(["policy", package])
            .env("LC_ALL", "C")
            .output()
            .expect("query native APT policy");
        assert!(
            policy.status.success(),
            "APT policy failed for {package}: {}",
            String::from_utf8_lossy(&policy.stderr)
        );
        String::from_utf8(policy.stdout)
            .expect("APT policy is UTF-8")
            .lines()
            .find_map(|line| line.trim().strip_prefix("Candidate: ").map(str::to_owned))
            .filter(|version| version != "(none)")
            .expect("installed package has an APT candidate")
    }

    pub(super) fn native_info(args: &[&str]) -> std::process::Output {
        let executable = assert_cmd::cargo::cargo_bin!("omg");
        if let Some(expected) = std::env::var_os("OMG_CONTRACT_EXPECTED_CLI") {
            assert_eq!(
                std::fs::canonicalize(executable).expect("CLI executable exists"),
                std::fs::canonicalize(expected).expect("receipt subject exists"),
                "native info executable differs from admitted receipt subject"
            );
        }
        let output = std::process::Command::new(executable)
            .args(args)
            .env_remove("OMG_TEST_MODE")
            .env_remove("OMG_TEST_DISTRO")
            .env("OMG_DISABLE_DAEMON", "1")
            .env("OMG_DISABLE_TELEMETRY", "1")
            .env("NO_COLOR", "1")
            .output()
            .expect("run OMG against native APT state");
        assert!(
            output.status.success(),
            "omg {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn native_status(package: &str) -> String {
        let output = std::process::Command::new("dpkg-query")
            .args(["-s", package])
            .env("LC_ALL", "C")
            .output()
            .expect("query native dpkg status");
        assert!(
            output.status.success(),
            "dpkg status failed for {package}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("dpkg status is UTF-8")
    }

    pub(super) fn native_depends_on(package: &str, dependency: &str) -> bool {
        native_status(package)
            .lines()
            .filter_map(|line| {
                line.strip_prefix("Depends: ")
                    .or_else(|| line.strip_prefix("Pre-Depends: "))
            })
            .flat_map(|field| field.split(','))
            .any(|entry| entry.split_whitespace().next() == Some(dependency))
    }

    fn search_rows(project: &TestProject, query: &str) -> Vec<serde_json::Value> {
        let result = project.run(&["search", query, "--json"]);
        result.assert_success();
        serde_json::from_str(result.stdout.trim()).unwrap_or_else(|error| {
            panic!(
                "search {query} must return a JSON array, got {}: {error}",
                result.stdout
            )
        })
    }

    fn assert_search_has_package(project: &TestProject, query: &str, package: &str) {
        let rows = search_rows(project, query);
        assert!(
            rows.iter().any(|row| row["name"] == package),
            "search {query} must return the exact package {package}, got {rows:?}"
        );
    }

    #[test]
    fn test_search_main_repo() {
        let project = TestProject::for_distro("debian");
        assert!(search_rows(&project, "bash").is_empty());
        project
            .mock_available("bash", "5.2.15")
            .expect("seed Debian repository package");
        assert_search_has_package(&project, "bash", "bash");
    }

    #[test]
    fn test_search_essential_packages() {
        let project = TestProject::for_distro("debian");
        for pkg in &["apt", "dpkg", "bash", "coreutils"] {
            project
                .mock_available(pkg, "1.2.3")
                .expect("seed essential package");
            assert_search_has_package(&project, pkg, pkg);
        }
    }

    #[test]
    fn test_search_development_packages() {
        let project = TestProject::for_distro("debian");
        for pkg in &["build-essential", "git", "curl", "wget"] {
            project
                .mock_available(pkg, "1.2.3")
                .expect("seed development package");
            assert_search_has_package(&project, pkg, pkg);
        }
    }

    #[test]
    fn test_search_with_architecture() {
        let project = TestProject::for_distro("debian");
        project
            .mock_available("libc6:amd64", "2.36.0")
            .expect("seed architecture-qualified Debian package");
        assert_search_has_package(&project, "libc6", "libc6:amd64");
    }

    #[test]
    fn test_info_installed_package() {
        let candidate = native_candidate("apt");
        let output = native_info(&["--json", "info", "apt"]);
        let row: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("info --json returns a JSON object");
        assert_eq!(row["name"], "apt");
        assert_eq!(row["installed"], true);
        assert_eq!(row["version"], candidate);
        assert!(
            row["description"]
                .as_str()
                .is_some_and(|description| !description.is_empty()),
            "native APT description missing: {row}"
        );
    }

    #[test]
    fn test_info_package_details() {
        let candidate = native_candidate("dpkg");
        let output = native_info(&["info", "dpkg"]);
        let stdout = String::from_utf8(output.stdout).expect("info text is UTF-8");
        let rows = stdout
            .lines()
            .filter_map(|line| line.trim().split_once(": "))
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(rows.get("Name"), Some(&"dpkg"), "{stdout}");
        assert_eq!(rows.get("Version"), Some(&candidate.as_str()), "{stdout}");
        assert_eq!(rows.get("Installed"), Some(&"yes"), "{stdout}");
        assert!(
            rows.get("Description")
                .is_some_and(|description| !description.is_empty()),
            "{stdout}"
        );
    }

    #[test]
    fn test_info_nonexistent_package() {
        // Contract (src/cli/packages/info.rs): an unknown package must fail
        // gracefully with an error that echoes the queried name — never a
        // panic and never a silent success.
        let result = run_omg(&["info", "nonexistent-package-xyz-99999"]);
        let combined = result.combined_output();

        assert!(
            !combined.contains("panicked at"),
            "Should not panic on nonexistent package"
        );
        if result.success {
            assert!(
                result.stdout_contains("nonexistent-package-xyz-99999"),
                "successful info must show the package. Got:\n{}",
                result.stdout
            );
        } else {
            assert!(
                combined.contains("not found")
                    && combined.contains("nonexistent-package-xyz-99999"),
                "failure for unknown package must say so and echo the name.\nGot:\n{combined}"
            );
        }
    }

    #[test]
    fn test_explicit_packages() {
        let project = TestProject::for_distro("debian");
        project
            .mock_install("apt", "2.6.1")
            .expect("seed explicit apt package");
        project
            .mock_install("dpkg", "1.21.22")
            .expect("seed explicit dpkg package");
        let result = project.run(&["explicit", "--json"]);
        result.assert_success();
        let output: serde_json::Value = serde_json::from_str(result.stdout.trim())
            .expect("explicit --json must return a JSON object");
        assert_eq!(output["packages"], serde_json::json!(["apt", "dpkg"]));
        assert_eq!(output["count"], 2);
        assert_debian_platform_purity(&result, "Debian explicit list");
    }

    #[test]
    fn test_explicit_packages_count() {
        let project = TestProject::for_distro("debian");
        project
            .mock_install("apt", "2.6.1")
            .expect("seed explicitly installed package");
        let result = project.run(&["explicit", "--count"]);
        result.assert_success();
        assert_debian_platform_purity(&result, "Debian explicit count");
        // Contract (src/cli/packages/explicit.rs print_count): plain-text mode
        // prints exactly one integer line.
        let stdout = result.stdout.trim();
        let count: usize = stdout.parse().unwrap_or_else(|error| {
            panic!("explicit --count must print an integer, got '{stdout}': {error}")
        });
        assert_eq!(count, 1, "only the seeded package may be counted");
    }

    #[test]
    fn test_update_check() {
        let project = TestProject::for_distro("debian");
        project
            .mock_install("apt", "2.6.1")
            .expect("seed installed apt package");
        project
            .mock_available("apt", "2.7.0")
            .expect("seed newer apt package");
        let result = project.run(&["update", "--check"]);
        result.assert_success();
        assert!(
            result.stdout_contains("apt") && result.stdout_contains("2.7.0"),
            "update --check must show the newer seeded apt version, got:\n{}",
            result.stdout
        );
        assert!(!result.stderr_contains("panicked at"), "Should not panic");
        assert_debian_platform_purity(&result, "Debian update check");
    }

    #[test]
    fn test_update_check_with_mock_updates() {
        let project = TestProject::for_distro("debian");

        project
            .mock_install("firefox-esr", "115.6.0")
            .expect("failed to create installed Debian mock fixture");
        project
            .mock_available("firefox-esr", "116.0.0")
            .expect("failed to create available Debian mock fixture");

        let result = project.run(&["update", "--check"]);
        result.assert_success();

        // The mock fixture pins firefox-esr 115.6.0 installed vs 116.0.0
        // available, so the check must surface that exact package as an update.
        assert!(
            result.stdout_contains("firefox-esr"),
            "update --check must list the outdated mock package. Got:\n{}",
            result.stdout
        );
        assert!(!result.stderr_contains("panicked at"), "Should not panic");
        assert_debian_platform_purity(&result, "Debian mock update check");
    }

    #[test]
    fn test_update_check_no_updates_when_current() {
        let project = TestProject::for_distro("debian");

        project
            .mock_install("firefox-esr", "116.0.0")
            .expect("failed to create installed Debian mock fixture");
        project
            .mock_available("firefox-esr", "116.0.0")
            .expect("failed to create available Debian mock fixture");

        let result = project.run(&["update", "--check"]);
        result.assert_success();

        assert!(
            result.stdout_contains("up to date"),
            "Should report up to date"
        );
        assert!(!result.stderr_contains("panicked at"), "Should not panic");
        assert_debian_platform_purity(&result, "Debian mock up-to-date check");
    }

    #[test]
    fn test_clean_orphans() {
        require_system_tests!();
        require_destructive_tests!();
        require_debian_like!();

        let result = run_omg(&["clean", "--orphans"]);
        if result.success {
            assert!(
                !result.stdout.trim().is_empty() || !result.stderr.trim().is_empty(),
                "clean --orphans must report its outcome"
            );
        } else {
            let combined = result.combined_output().to_lowercase();
            assert!(
                ["orphan", "permission", "root", "privilege"]
                    .iter()
                    .any(|cause| combined.contains(cause)),
                "failed clean --orphans must name its cause. Got: {}",
                result.combined_output()
            );
        }
    }

    #[test]
    fn test_install_remove_cycle() {
        require_system_tests!();
        require_destructive_tests!();
        require_debian_like!();

        // Ensure database is synced before installing.
        let sync_result = run_omg(&["sync"]);
        assert!(
            sync_result.success
                || sync_result.contains("permission")
                || sync_result.contains("root")
                || sync_result.contains("repository")
                || sync_result.contains("Unable"),
            "Sync should succeed or explain why it cannot run: {}",
            sync_result.combined_output()
        );

        // Use a tiny, harmless package
        let pkg = "vim-tiny";

        // 1. Install
        let result = run_omg(&["install", pkg, "-y"]);
        if !result.success {
            if result.stderr_contains("permission") || result.stderr_contains("root") {
                report_skip("install/remove test requires root");
                return;
            }
            result.assert_success();
        }

        // 2. Verify installed
        let info = run_omg(&["info", pkg]);
        info.assert_success();
        assert!(
            info.stdout_contains("Status") && !info.stdout_contains("not installed"),
            "package info must report the installed state: {}",
            info.stdout
        );

        // 3. Remove
        let result = run_omg(&["remove", pkg, "-y"]);
        result.assert_success();

        // 4. Verify removed
        let info = run_omg(&["info", pkg]);
        assert!(
            info.stdout_contains("Status") && info.stdout_contains("not installed"),
            "package info must report the removed state: {}",
            info.stdout
        );
    }

    #[test]
    fn test_why_integration() {
        assert!(
            native_depends_on("apt", "libc6"),
            "native apt must depend on libc6"
        );
        let output = native_info(&["why", "apt"]);
        let stdout = String::from_utf8(output.stdout).expect("why text is UTF-8");
        assert!(stdout.contains("Package Analysis"), "{stdout}");
        assert!(
            stdout
                .lines()
                .any(|line| line.split_whitespace().any(|part| part == "libc6")),
            "why apt omitted its native libc6 dependency: {stdout}"
        );
    }

    #[test]
    fn test_size_integration() {
        let status = native_status("apt");
        let kib: u64 = status
            .lines()
            .find_map(|line| line.strip_prefix("Installed-Size: "))
            .expect("native apt installed size")
            .parse()
            .expect("native apt size is numeric");
        assert!(kib >= 1024, "native apt fixture must exceed one MiB");
        let expected = format!("{:.1} MB", kib as f64 / 1024.0);
        let output = native_info(&["size", "--tree", "apt"]);
        let stdout = String::from_utf8(output.stdout).expect("size text is UTF-8");
        assert!(stdout.contains("Package Size Tree"), "{stdout}");
        assert!(
            stdout
                .lines()
                .any(|line| line.contains(&format!("apt: {expected}"))),
            "size --tree apt differs from native Installed-Size ({kib} KiB): {stdout}"
        );
    }
}

// Helper macro for both Debian and Ubuntu
#[macro_export]
macro_rules! require_debian_like {
    () => {
        let config = $crate::common::TestConfig::default();
        if !config.is_debian() && !config.is_ubuntu() {
            eprintln!("⏭️  Skipping test: requires Debian or Ubuntu");
            return;
        }
    };
}

// ═══════════════════════════════════════════════════════════════════════════════
// UBUNTU-SPECIFIC TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod ubuntu_specific {
    use super::*;

    #[cfg(feature = "debian")]
    fn native_candidate_in_component(package: &str, component: &str) -> String {
        let output = std::process::Command::new("apt-cache")
            .args(["policy", package])
            .env("LC_ALL", "C")
            .output()
            .expect("query native Ubuntu APT policy");
        assert!(output.status.success(), "apt-cache policy {package} failed");
        let policy = String::from_utf8(output.stdout).expect("APT policy is UTF-8");
        let candidate = policy
            .lines()
            .find_map(|line| line.trim().strip_prefix("Candidate: "))
            .filter(|version| *version != "(none)")
            .expect("Ubuntu package has an APT candidate");
        let mut candidate_entry = false;
        let mut candidate_component = false;
        for line in policy
            .lines()
            .skip_while(|line| !line.contains("Version table:"))
        {
            if line.starts_with("     ") && !line.starts_with("        ") {
                candidate_entry = line
                    .trim()
                    .trim_start_matches("***")
                    .split_whitespace()
                    .next()
                    == Some(candidate);
            } else if candidate_entry
                && line
                    .split_whitespace()
                    .any(|field| field.ends_with(&format!("/{component}")))
            {
                candidate_component = true;
            }
        }
        assert!(
            candidate_component,
            "{package} candidate {candidate} is not supplied by Ubuntu {component}: {policy}"
        );
        candidate.to_owned()
    }

    #[cfg(feature = "debian")]
    fn assert_native_search(package: &str, component: &str) {
        let candidate = native_candidate_in_component(package, component);
        let output = apt_integration::native_info(&["search", package, "--json"]);
        let rows: Vec<serde_json::Value> =
            serde_json::from_slice(&output.stdout).expect("search --json returns an array");
        assert!(
            rows.iter().any(|row| {
                row["name"] == package && row["version"] == candidate && row["source"] == "Official"
            }),
            "OMG omitted native Ubuntu {component} candidate {package} {candidate}: {rows:?}"
        );
    }

    #[cfg(feature = "debian")]
    #[test]
    fn test_ubuntu_main_repo() {
        if !TestConfig::default().is_ubuntu() {
            report_skip("native Ubuntu APT search requires Ubuntu with libapt");
            return;
        }
        assert_native_search("ubuntu-desktop", "main");
    }

    #[cfg(feature = "debian")]
    #[test]
    fn test_ubuntu_universe_repo() {
        if !TestConfig::default().is_ubuntu() {
            report_skip("native Ubuntu APT search requires Ubuntu with libapt");
            return;
        }
        assert_native_search("cowsay", "universe");
    }

    #[cfg(all(feature = "debian-pure", not(feature = "debian")))]
    #[test]
    fn test_ubuntu_main_repo() {
        report_skip("native Ubuntu APT search requires Ubuntu with libapt");
    }

    #[cfg(all(feature = "debian-pure", not(feature = "debian")))]
    #[test]
    fn test_ubuntu_universe_repo() {
        report_skip("native Ubuntu APT search requires Ubuntu with libapt");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEBIAN-SPECIFIC TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod debian_specific {
    use super::*;

    #[test]
    fn test_debian_stable_packages() {
        require_system_tests!();
        require_debian!();

        for pkg in &["apt", "dpkg", "systemd"] {
            let result = run_omg(&["search", pkg]);
            result.assert_success();
        }
    }

    #[test]
    fn test_debian_security_repo() {
        require_system_tests!();
        require_debian!();

        // Security updates should be searchable
        let result = run_omg(&["search", "openssl"]);
        result.assert_success();
    }

    #[test]
    fn test_debian_backports_awareness() {
        require_system_tests!();
        require_debian!();

        // Should handle backports if configured
        let result = run_omg(&["status"]);
        result.assert_success();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// NEW FEATURE TESTS (why, outdated, etc.)
// ═══════════════════════════════════════════════════════════════════════════════

mod new_features {
    use super::*;

    fn native_sized_package_count() -> usize {
        let output = std::process::Command::new("dpkg-query")
            .args(["-W", "-f=${Status}\t${Installed-Size}\n"])
            .env("LC_ALL", "C")
            .output()
            .expect("query native installed package sizes");
        assert!(
            output.status.success(),
            "dpkg size inventory failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("dpkg size inventory is UTF-8")
            .lines()
            .filter_map(|line| line.split_once('\t'))
            .filter(|(status, size)| {
                *status == "install ok installed" && size.parse::<u64>().is_ok_and(|kib| kib > 0)
            })
            .count()
    }

    #[test]
    fn test_why_command() {
        assert!(apt_integration::native_depends_on("bash", "libc6"));
        let output = apt_integration::native_info(&["why", "bash"]);
        let stdout = String::from_utf8(output.stdout).expect("why text is UTF-8");
        assert!(stdout.contains("Package Analysis"), "{stdout}");
        assert!(
            stdout
                .lines()
                .any(|line| line.split_whitespace().any(|part| part == "libc6")),
            "why bash omitted its native libc6 dependency: {stdout}"
        );
    }

    #[test]
    fn test_why_reverse_dependencies() {
        assert!(apt_integration::native_depends_on("apt", "libc6"));
        let output = apt_integration::native_info(&["why", "libc6", "--reverse"]);
        let stdout = String::from_utf8(output.stdout).expect("reverse why text is UTF-8");
        assert!(stdout.contains("Reverse Dependencies"), "{stdout}");
        assert!(
            stdout
                .lines()
                .any(|line| line.split_whitespace().any(|part| part == "apt:")),
            "reverse dependencies of libc6 omitted native dependent apt: {stdout}"
        );
    }

    #[test]
    fn test_outdated_command() {
        let project = TestProject::for_distro("debian");
        project
            .mock_install("apt", "1.0")
            .expect("seed installed apt");
        project
            .mock_available("apt", "1.1")
            .expect("seed newer apt candidate");
        let state = project.data_dir.path().join("mock_state_apt.json");
        let before = std::fs::read(&state).expect("read update fixture");

        let result = project.run(&["outdated"]);
        result.assert_success();
        result.assert_stdout_contains("Available Updates");
        result.assert_stdout_contains("apt 1.0 → 1.1");
        assert_eq!(std::fs::read(&state).expect("read update fixture"), before);
        project.close_checked();
    }

    #[test]
    fn test_outdated_json_output() {
        let project = TestProject::for_distro("debian");
        project
            .mock_install("apt", "1.0")
            .expect("seed installed apt");
        project
            .mock_available("apt", "1.1")
            .expect("seed newer apt candidate");
        let result = project.run(&["outdated", "--json"]);
        result.assert_success();
        let parsed: serde_json::Value = serde_json::from_str(result.stdout.trim())
            .expect("outdated --json must print only a JSON document");
        let rows = parsed.as_array().expect("outdated --json prints an array");
        assert_eq!(rows.len(), 1, "unexpected update rows: {parsed}");
        assert_eq!(rows[0]["name"], "apt");
        assert_eq!(rows[0]["current_version"], "1.0");
        assert_eq!(rows[0]["new_version"], "1.1");
        project.close_checked();
    }

    #[test]
    fn test_size_command() {
        let count = native_sized_package_count();
        assert!(
            count > 10,
            "native package inventory is too small for this fixture"
        );
        let output = apt_integration::native_info(&["size"]);
        let stdout = String::from_utf8(output.stdout).expect("size text is UTF-8");
        assert!(stdout.contains("Disk Usage Analysis"), "{stdout}");
        assert!(
            stdout.contains(&format!("Number of Packages: {count}")),
            "size count differs from native dpkg inventory ({count}): {stdout}"
        );
    }

    #[test]
    fn test_size_with_limit() {
        assert!(native_sized_package_count() > 10);
        let output = apt_integration::native_info(&["size", "--limit", "10"]);
        let stdout = String::from_utf8(output.stdout).expect("size limit text is UTF-8");
        assert!(stdout.contains("Top 10 Packages"), "{stdout}");
        let ranks = stdout
            .lines()
            .filter_map(|line| {
                let row = line.trim_start_matches([' ', '│']);
                let (rank, _) = row.split_once(". ")?;
                rank.trim().parse::<usize>().ok()
            })
            .collect::<Vec<_>>();
        assert_eq!(ranks, (1..=10).collect::<Vec<_>>(), "{stdout}");
    }

    #[test]
    fn test_blame_command() {
        let native = std::process::Command::new("dpkg-query")
            .args(["-W", "-f=${Version}", "apt"])
            .output()
            .expect("query native apt version");
        assert!(native.status.success(), "native apt is required");
        let version = String::from_utf8(native.stdout).expect("apt version is UTF-8");
        let auto = std::process::Command::new("apt-mark")
            .arg("showauto")
            .output()
            .expect("query native APT install reason");
        assert!(auto.status.success(), "apt-mark showauto failed");
        let is_auto = String::from_utf8(auto.stdout)
            .expect("APT install reasons are UTF-8")
            .lines()
            .any(|package| package == "apt");
        let output = apt_integration::native_info(&["blame", "apt"]);
        let stdout = String::from_utf8(output.stdout).expect("blame text is UTF-8");
        assert!(stdout.contains("Package History"), "{stdout}");
        assert!(stdout.contains(&format!("Version: {version}")), "{stdout}");
        let reason = if is_auto {
            "dependency (auto-installed)"
        } else {
            "explicit (user installed)"
        };
        assert!(
            stdout.contains(&format!("Install Reason: {reason}")),
            "{stdout}"
        );
    }

    #[test]
    fn test_diff_command() {
        let project = TestProject::new();
        project.with_omg_lock(locks::VALID_LOCK);

        let result = project.run(&["diff", "omg.lock"]);
        assert!(!result.stderr_contains("panicked at"), "Should not panic");
    }

    #[test]
    fn test_snapshot_create() {
        let project = TestProject::new();
        let result = project.run(&["snapshot", "create"]);
        assert!(!result.stderr_contains("panicked at"), "Should not panic");
    }

    #[test]
    fn test_snapshot_list() {
        let project = TestProject::new();
        let result = project.run(&["snapshot", "list"]);
        result.assert_success();
    }

    #[test]
    fn test_ci_init_github() {
        let project = TestProject::new();
        let result = project.run(&["ci", "init", "--provider", "github"]);
        assert!(!result.stderr_contains("panicked at"), "Should not panic");
    }

    #[test]
    fn test_migrate_export() {
        let project = TestProject::new();
        let result = project.run(&["migrate", "export", "--output", "manifest.toml"]);
        assert!(!result.stderr_contains("panicked at"), "Should not panic");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod security {
    use super::*;

    #[test]
    fn test_audit_scan_is_not_paywalled() {
        let project = TestProject::for_distro("debian");
        let state = project.data_dir.path().join("mock_state_apt.json");
        std::fs::write(&state, r#"{"installed":{},"available":{}}"#)
            .expect("seed empty Debian package inventory");
        let result = project.run(&["audit", "scan"]);
        result.assert_success();
        assert!(
            result.stdout_contains("No vulnerabilities found in scanned packages."),
            "audit scan did not complete: {}",
            result.combined_output()
        );
        let output = result.combined_output();
        assert!(
            !output.contains("requires Pro tier") && !output.contains("/pricing"),
            "audit scan must not be paywalled, got:\n{output}"
        );
        assert_eq!(
            std::fs::read(&state).expect("read package inventory"),
            br#"{"installed":{},"available":{}}"#
        );
        project.close_checked();
    }

    #[cfg(feature = "debian")]
    #[test]
    fn test_audit_sbom_generation() {
        let native = std::process::Command::new("dpkg-query")
            .args(["-W", "-f=${Version}", "apt"])
            .output()
            .expect("query native apt version");
        assert!(native.status.success(), "native apt is required");
        let version = String::from_utf8(native.stdout).expect("native version is UTF-8");
        let fixture = tempfile::tempdir().expect("create SBOM output fixture");
        let path = fixture.path().join("sbom.json");
        let output = apt_integration::native_info(&[
            "audit",
            "sbom",
            "--inventory-only",
            "--output",
            path.to_str().expect("fixture path is UTF-8"),
        ]);
        let stdout = String::from_utf8(output.stdout).expect("SBOM output is UTF-8");
        assert!(stdout.contains("advisory matching was skipped"), "{stdout}");
        let document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("inventory-only SBOM was written"))
                .expect("SBOM is valid JSON");
        assert_eq!(document["bomFormat"], "CycloneDX");
        assert_eq!(document["specVersion"], "1.5");
        assert!(
            document["components"]
                .as_array()
                .is_some_and(|components| components.iter().any(|component| {
                    component["name"] == "apt"
                        && component["version"] == version
                        && component["purl"]
                            .as_str()
                            .is_some_and(|purl| purl.starts_with("pkg:deb/"))
                })),
            "SBOM omitted native apt identity: {document}"
        );
        assert!(
            document["metadata"]["component"]["properties"]
                .as_array()
                .is_some_and(|properties| properties.iter().any(|property| {
                    property["name"] == "omg:advisory-scan" && property["value"] == "not-performed"
                })),
            "inventory-only SBOM did not disclose skipped advisory matching"
        );
        assert!(
            document["vulnerabilities"].is_null()
                || document["vulnerabilities"] == serde_json::json!([])
        );
        fixture.close().expect("remove SBOM fixture");
    }

    #[cfg(all(feature = "debian-pure", not(feature = "debian")))]
    #[test]
    fn test_audit_sbom_generation() {
        let fixture = tempfile::tempdir().expect("create SBOM output fixture");
        let path = fixture.path().join("sbom.json");
        let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("omg"))
            .args([
                "audit",
                "sbom",
                "--inventory-only",
                "--output",
                path.to_str().expect("fixture path is UTF-8"),
            ])
            .env_remove("OMG_TEST_MODE")
            .env_remove("OMG_TEST_DISTRO")
            .env("OMG_DISABLE_DAEMON", "1")
            .output()
            .expect("run pure Debian SBOM command");
        assert!(
            !output.status.success(),
            "pure indexing build generated a live SBOM"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("pure-Rust Debian indexing engine"),
            "wrong pure-backend refusal: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!path.exists(), "refused SBOM command wrote an output file");
        fixture.close().expect("remove SBOM fixture");
    }

    #[test]
    fn test_audit_secrets_scan() {
        let project = TestProject::new();
        project.create_file("config.txt", "AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE");

        let result = project.run(&["audit", "secrets"]);
        assert!(!result.stderr_contains("panicked at"), "Should not panic");
    }

    #[test]
    fn test_injection_prevention_search() {
        for input in validation::INJECTION_ATTEMPTS {
            let result = run_omg(&["search", input]);
            assert!(
                !result.stdout_contains("pwned"),
                "Should prevent injection: {input}"
            );
            assert!(
                !result.stdout_contains("/etc/passwd"),
                "Should prevent path traversal"
            );
            assert_debian_platform_purity(&result, "Debian injection prevention search");
        }
    }

    #[test]
    fn test_injection_prevention_info() {
        for input in validation::INJECTION_ATTEMPTS {
            let result = run_omg(&["info", input]);
            assert!(!result.stdout_contains("pwned"), "Should prevent injection");
            assert_debian_platform_purity(&result, "Debian injection prevention info");
        }
    }

    #[test]
    fn test_apt_source_validation() {
        // OMG should validate APT sources
        let result = run_omg(&["status"]);
        result.assert_success();
        assert_debian_platform_purity(&result, "Debian apt source validation");
    }

    #[test]
    fn test_gpg_verification_awareness() {
        let project = TestProject::for_distro("debian");
        project.with_security_policy(policies::STRICT_POLICY);
        // Root deliberately ignores OMG_CONFIG_DIR. Its XDG fallback still
        // points inside this fixture's isolated HOME.
        let root_policy = project.home_dir.path().join(".config/omg/policy.toml");
        std::fs::create_dir_all(root_policy.parent().expect("policy parent"))
            .expect("create isolated policy directory");
        std::fs::write(&root_policy, policies::STRICT_POLICY)
            .expect("write root-safe policy fixture");
        let result = project.run(&["audit", "policy"]);
        result.assert_success();
        result.assert_stdout_contains("OMG Security Policy Status");
        result.assert_stdout_contains("PGP Required: Yes");
        result.assert_stdout_contains("Minimum Grade: VERIFIED");
        result.assert_stdout_contains("AUR Allowed: No");
        project.close_checked();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════════

mod edge_cases {
    use super::*;

    #[test]
    fn test_unicode_package_names() {
        for input in validation::UNICODE_INPUTS {
            let result = run_omg(&["search", input]);
            assert!(
                !result.stderr_contains("panicked at"),
                "Should handle unicode: {input}"
            );
        }
    }

    #[test]
    fn test_very_long_query() {
        let long_query = validation::very_long_input(10000);
        let result = run_omg(&["search", &long_query]);
        assert!(
            !result.stderr_contains("panicked at"),
            "Should handle long input"
        );
    }

    #[test]
    fn test_empty_inputs() {
        for input in validation::EMPTY_INPUTS {
            let result = run_omg(&["search", input]);
            assert!(
                !result.stderr_contains("panicked at"),
                "Should handle empty input"
            );
        }
    }

    #[test]
    fn test_concurrent_operations() {
        use std::thread;

        let handles: Vec<_> = (0..10)
            .map(|_| thread::spawn(|| run_omg(&["status"])))
            .collect();

        for handle in handles {
            let result = handle.join().unwrap();
            result.assert_success();
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CROSS-DISTRO MIGRATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod migration {
    use super::*;

    #[test]
    fn test_migrate_export_format() {
        let project = TestProject::new();
        let result = project.run(&["migrate", "export", "--output", "manifest.toml"]);

        if result.success {
            assert!(
                project.file_exists("manifest.toml"),
                "successful export must create the manifest file"
            );
            let manifest = project
                .read_file("manifest.toml")
                .expect("manifest readable");
            assert!(
                !manifest.trim().is_empty(),
                "exported manifest must have content"
            );
        } else {
            assert!(
                !result.stderr.trim().is_empty(),
                "failed export must explain why on stderr. stdout:\n{}",
                result.stdout
            );
        }
    }

    #[test]
    fn test_migrate_import_dry_run() {
        let project = TestProject::new();
        // Create a minimal manifest
        project.create_file(
            "manifest.toml",
            r#"
[environment]
distro = "arch"

[packages]
git = "2.43.0"
curl = "8.5.0"
"#,
        );

        let result = project.run(&["migrate", "import", "--dry-run", "manifest.toml"]);
        // Should show what would be installed without doing it
        assert!(!result.stderr_contains("panicked at"), "Should not panic");
    }

    #[test]
    fn test_package_name_mapping() {
        // Some packages have different names across distros
        // e.g., python3-pip vs python-pip
        let project = TestProject::new();
        let result = project.run(&["migrate", "export", "--output", "test.toml"]);
        assert!(!result.stderr_contains("panicked at"), "Should not panic");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// INTEGRATION SCENARIOS
// ═══════════════════════════════════════════════════════════════════════════════

mod integration_scenarios {
    use super::*;

    #[test]
    fn scenario_full_workflow() {
        let project = TestProject::new();
        project.with_tool_versions(&[("nodejs", "20.10.0"), ("python", "3.11.0")]);

        // 1. Check status
        let result = project.run(&["status"]);
        result.assert_success();

        // 2. Capture environment
        let result = project.run(&["env", "capture"]);
        result.assert_success();
        assert!(project.file_exists("omg.lock"), "Should create omg.lock");

        // 3. Check environment
        let result = project.run(&["env", "check"]);
        assert!(!result.stderr_contains("panicked at"));

        // 4. Create snapshot
        let result = project.run(&["snapshot", "create", "--message", "Initial"]);
        assert!(!result.stderr_contains("panicked at"));
    }

    #[test]
    fn scenario_debian_to_ubuntu_migration() {
        let debian_project = TestProject::for_distro("debian");
        let ubuntu_project = TestProject::for_distro("ubuntu");

        // Simulate Debian environment
        debian_project.with_tool_versions(&[("nodejs", "20.10.0")]);
        let capture = debian_project.run(&["env", "capture"]);
        capture.assert_success();

        // Export manifest; the hand-off artifact MUST exist to migrate at all.
        let exported = debian_project.run(&["migrate", "export", "--output", "manifest.toml"]);
        exported.assert_success();
        let manifest = debian_project
            .read_file("manifest.toml")
            .expect("migrate export must produce manifest.toml");
        assert!(!manifest.trim().is_empty(), "manifest must have content");

        ubuntu_project.create_file("manifest.toml", &manifest);

        // Dry run import on "Ubuntu"
        let result = ubuntu_project.run(&["migrate", "import", "--dry-run", "manifest.toml"]);
        assert!(
            !result.combined_output().contains("panicked at"),
            "dry-run import must not panic. Output:\n{}",
            result.combined_output()
        );
    }

    #[test]
    fn scenario_team_collaboration() {
        let dev1 = TestProject::new();
        let dev2 = TestProject::new();

        // Dev1 sets up project
        dev1.with_tool_versions(&[("nodejs", "20.10.0")]);
        let capture = dev1.run(&["env", "capture"]);
        capture.assert_success();

        // Copy lock to dev2; the shared-lock workflow depends on it existing.
        let lock = dev1
            .read_file("omg.lock")
            .expect("env capture must produce omg.lock for sharing");
        dev2.create_file("omg.lock", &lock);
        dev2.with_tool_versions(&[("nodejs", "20.10.0")]);

        // Dev2 checks for drift
        let result = dev2.run(&["env", "check"]);
        assert!(
            !result.combined_output().contains("panicked at"),
            "env check with a shared lock must not panic. Output:\n{}",
            result.combined_output()
        );
    }

    #[test]
    fn scenario_ci_pipeline_simulation() {
        let project = TestProject::new();
        project.with_tool_versions(&[("nodejs", "20.10.0")]);
        project.with_omg_lock(locks::VALID_LOCK);

        // CI would run these steps:
        // 1. Validate environment against lock
        let result = project.run(&["ci", "validate"]);
        assert!(!result.stderr_contains("panicked at"));

        // 2. Check for drift
        let result = project.run(&["env", "check"]);
        assert!(!result.stderr_contains("panicked at"));

        // 3. Run security audit
        let result = project.run(&["audit"]);
        assert!(!result.stderr_contains("panicked at"));
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// RUNTIME MANAGEMENT ON DEBIAN/UBUNTU
// ═══════════════════════════════════════════════════════════════════════════════

mod runtime_management {
    use super::*;

    #[test]
    fn test_node_version_management() {
        let project = TestProject::new();
        project.with_node_project();

        let result = project.run(&["use", "node"]);
        result.assert_success();
        // Should detect version from .nvmrc
    }

    #[test]
    fn test_python_version_management() {
        let project = TestProject::new();
        project.with_python_project();

        let result = project.run(&["use", "python"]);
        result.assert_success();
        assert!(
            result.stdout_contains("Detected version 3.11.0 from file"),
            "the project pin must select the requested Python version"
        );
        let mock_runtime = project
            .data_dir
            .path()
            .join("versions/python/3.11.0/.omg-test-mock");
        assert!(
            mock_runtime.is_file(),
            "synthetic Python runtime must remain inside the isolated test data directory"
        );
    }

    #[test]
    fn test_list_available_node() {
        require_network_tests!();

        let result = run_omg(&["list", "node", "--available"]);
        result.assert_success();
    }

    #[test]
    fn test_list_available_python() {
        require_network_tests!();

        let result = run_omg(&["list", "python", "--available"]);
        result.assert_success();
    }

    #[test]
    fn test_which_node() {
        let result = run_omg(&["which", "node"]);
        result.assert_success();
    }

    #[test]
    fn test_which_python() {
        let result = run_omg(&["which", "python"]);
        result.assert_success();
    }

    #[test]
    fn test_tool_versions_detection() {
        let project = TestProject::new();
        project.with_tool_versions(&[
            ("nodejs", "20.10.0"),
            ("python", "3.11.0"),
            ("ruby", "3.2.0"),
        ]);

        let result = project.run(&["status"]);
        result.assert_success();
    }
}
