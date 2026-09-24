#![cfg(any(feature = "debian", feature = "debian-pure"))]
#![expect(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]
//! Hermetic Debian/Ubuntu CLI integration tests.
//!
//! Commands run against isolated Debian or Ubuntu mock package data and never
//! mutate the host. Enable the extended cases with:
//! `OMG_RUN_SYSTEM_TESTS=1 OMG_TEST_DISTRO=debian cargo test --locked --no-default-features --features debian-pure --test debian_tests`.
//!
//! Real package-system coverage lives in `scripts/debian-smoke-test.sh` and
//! must run inside a disposable container.

pub mod common;
pub mod platform_semantics;

use common::assertions::*;
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

    #[test]
    fn test_search_main_repo() {
        require_system_tests!();

        // In Debian, firefox is often firefox-esr
        let result = run_omg(&["search", "bash"]);
        result.assert_success();
        assert!(
            result.stdout_contains("bash") || result.stdout_contains("Bash"),
            "Should find bash"
        );
        assert_no_arch_terms(&result.combined_output(), "Debian search main repo");
    }

    #[test]
    fn test_search_essential_packages() {
        require_system_tests!();

        for pkg in &["apt", "dpkg", "bash", "coreutils"] {
            let result = run_omg(&["search", pkg]);
            result.assert_success();
            assert!(result.stdout_contains(pkg), "Should find {pkg}");
            assert_debian_platform_purity(&result, "Debian search essential packages");
        }
    }

    #[test]
    fn test_search_development_packages() {
        require_system_tests!();

        for pkg in &["build-essential", "git", "curl", "wget"] {
            let result = run_omg(&["search", pkg]);
            result.assert_success();
            assert!(
                result.stdout_contains(pkg),
                "search '{pkg}' must list the package itself. Got:\n{}",
                result.stdout
            );
            assert_debian_platform_purity(&result, "Debian search development packages");
        }
    }

    #[test]
    fn test_search_with_architecture() {
        require_system_tests!();

        // Debian packages can have architecture suffixes
        let result = run_omg(&["search", "libc6"]);
        result.assert_success();
        assert!(
            result.stdout_contains("libc6"),
            "search libc6 must list libc6 itself. Got:\n{}",
            result.stdout
        );
        assert_debian_platform_purity(&result, "Debian search architecture handling");
    }

    #[test]
    fn test_info_installed_package() {
        require_system_tests!();

        let result = run_omg(&["info", "apt"]);
        result.assert_success();
        assert_package_info(&result, "apt");
        assert_debian_platform_purity(&result, "Debian info installed package");
    }

    #[test]
    fn test_info_package_details() {
        require_system_tests!();

        let result = run_omg(&["info", "dpkg"]);
        // Must show the package name plus a real dotted version token
        // (e.g. 1.21.0); the old `contains('.')` matched almost any prose.
        assert_package_info(&result, "dpkg");
        assert_debian_platform_purity(&result, "Debian info package details");
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
        require_system_tests!();

        let result = run_omg(&["explicit"]);
        result.assert_success();
        // Should list manually installed packages
        assert_debian_platform_purity(&result, "Debian explicit list");
    }

    #[test]
    fn test_explicit_packages_count() {
        require_system_tests!();

        let result = run_omg(&["explicit", "--count"]);
        result.assert_success();
        assert_debian_platform_purity(&result, "Debian explicit count");
        // Contract (src/cli/packages/explicit.rs print_count): plain-text mode
        // prints exactly one integer line.
        let stdout = result.stdout.trim();
        let count: usize = stdout.parse().unwrap_or_else(|error| {
            panic!("explicit --count must print an integer, got '{stdout}': {error}")
        });
        assert!(
            count > 0,
            "a real Debian system always has explicit packages"
        );
    }

    #[test]
    fn test_update_check() {
        require_system_tests!();

        let result = run_omg(&["update", "--check"]);
        result.assert_success();
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
        require_system_tests!();
        require_debian_like!();

        let result = run_omg(&["why", "apt"]);
        result.assert_success();
        // The explanation is about apt specifically, so it must name it.
        assert!(
            result.stdout_contains("apt"),
            "why apt must mention the queried package. Got:\n{}",
            result.stdout
        );
    }

    #[test]
    fn test_size_integration() {
        require_system_tests!();
        require_debian_like!();

        let result = run_omg(&["size", "--tree", "apt"]);
        result.assert_success();
        assert!(
            result.stdout_contains("MB") || result.stdout_contains("KB"),
            "Should show size of apt package"
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

    #[test]
    fn test_ubuntu_main_repo() {
        require_system_tests!();
        require_ubuntu!();

        let result = run_omg(&["search", "ubuntu-desktop"]);
        result.assert_success();
        assert!(
            result.stdout_contains("ubuntu-desktop"),
            "Ubuntu main repo search must list ubuntu-desktop. Got:\n{}",
            result.stdout
        );
    }

    #[test]
    fn test_ubuntu_universe_repo() {
        require_system_tests!();
        require_ubuntu!();

        // Universe repo packages
        let result = run_omg(&["search", "htop"]);
        result.assert_success();
        assert!(
            result.stdout_contains("htop"),
            "universe search must list htop. Got:\n{}",
            result.stdout
        );
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

    #[test]
    fn test_why_command() {
        require_system_tests!();

        let result = run_omg(&["why", "bash"]);
        assert!(!result.stderr_contains("panicked at"), "Should not panic");
    }

    #[test]
    fn test_why_reverse_dependencies() {
        require_system_tests!();

        let result = run_omg(&["why", "libc6", "--reverse"]);
        assert!(!result.stderr_contains("panicked at"), "Should not panic");
    }

    #[test]
    fn test_outdated_command() {
        require_system_tests!();

        let result = run_omg(&["outdated"]);
        let output = result.combined_output();
        assert_ne!(result.exit_code, 101, "outdated panicked:\n{output}");
        if result.success {
            // A successful run always renders a report (either the up-to-date
            // banner or the sorted updates table).
            assert!(
                !result.stdout.trim().is_empty(),
                "outdated must render its report on success"
            );
        } else {
            let lowered = output.to_lowercase();
            assert!(
                [
                    "error",
                    "failed",
                    "unable",
                    "permission",
                    "not found",
                    "no such"
                ]
                .iter()
                .any(|cause| lowered.contains(cause)),
                "failed outdated must name its cause, got: {output}"
            );
        }
    }

    #[test]
    fn test_outdated_json_output() {
        require_system_tests!();

        // Contract (src/cli/outdated.rs): --json prints either `[]` when
        // current or a JSON array of outdated packages — never prose.
        let result = run_omg(&["outdated", "--json"]);
        result.assert_success();
        let parsed: serde_json::Value =
            serde_json::from_str(result.stdout.trim()).unwrap_or_else(|error| {
                panic!(
                    "outdated --json must print a JSON document, got '{}': {error}",
                    result.stdout.trim()
                )
            });
        assert!(
            parsed.is_array(),
            "outdated --json prints an array, got: {parsed}"
        );
    }

    #[test]
    fn test_size_command() {
        require_system_tests!();

        let result = run_omg(&["size"]);
        result.assert_success();
    }

    #[test]
    fn test_size_with_limit() {
        require_system_tests!();

        let result = run_omg(&["size", "--limit", "10"]);
        result.assert_success();
    }

    #[test]
    fn test_blame_command() {
        require_system_tests!();

        let result = run_omg(&["blame", "apt"]);
        assert!(!result.stderr_contains("panicked at"), "Should not panic");
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
        require_system_tests!();

        let result = run_omg(&["audit", "scan"]);
        let output = result.combined_output();
        assert!(
            !output.contains("requires Pro tier") && !output.contains("/pricing"),
            "audit scan must not be paywalled, got:\n{output}"
        );
    }

    #[test]
    fn test_audit_sbom_generation() {
        require_system_tests!();

        let project = TestProject::new();
        let result = project.run(&["audit", "sbom", "--output", "sbom.json"]);
        assert!(!result.stderr_contains("panicked at"), "Should not panic");
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
        require_system_tests!();

        let result = run_omg(&["audit", "policy"]);
        result.assert_success();
        result.assert_stdout_contains("OMG Security Policy Status");
        result.assert_stdout_contains("PGP Required:");
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
