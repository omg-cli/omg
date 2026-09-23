#![expect(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]
//! Security and Compliance Test Suite
//!
//! Enterprise-grade security testing for Fortune 500 compliance.
//!
//! Run: cargo test --test security_tests
//! With full security tests: OMG_RUN_SECURITY_TESTS=1 cargo test --test security_tests

#![expect(clippy::doc_markdown)]

pub mod common;

use common::fixtures::*;
use common::*;

// ═══════════════════════════════════════════════════════════════════════════════
// INPUT VALIDATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod input_validation {
    use super::*;

    #[test]
    fn test_command_injection_semicolon() {
        let payloads = vec![
            "; ls",
            "; cat /etc/passwd",
            "; rm -rf /",
            "test; whoami",
            "$(whoami)",
            "`whoami`",
        ];

        for payload in payloads {
            let result = run_omg(&["search", payload]);
            assert!(
                !result.stdout.contains("root:"),
                "Command injection via: {payload}"
            );
            assert!(
                !result.stdout.contains("/bin/bash"),
                "Command injection via: {payload}"
            );
        }
    }

    #[test]
    fn test_command_injection_pipe() {
        let payloads = vec![
            "| cat /etc/passwd",
            "test | whoami",
            "|| echo pwned",
            "&& cat /etc/shadow",
        ];

        for payload in payloads {
            let result = run_omg(&["search", payload]);
            assert!(
                !result.stdout.contains("root:"),
                "Pipe injection via: {payload}"
            );
        }
    }

    #[test]
    fn test_command_injection_backtick() {
        let result = run_omg(&["search", "`cat /etc/passwd`"]);
        assert!(!result.stdout.contains("root:"));
        assert!(!result.stderr.contains("root:"));
    }

    #[test]
    fn test_command_injection_dollar() {
        let payloads = vec!["$(cat /etc/passwd)", "${cat /etc/passwd}", "$((1+1))"];

        for payload in payloads {
            let result = run_omg(&["search", payload]);
            assert!(
                !result.stdout.contains("root:"),
                "Dollar injection via: {payload}"
            );
        }
    }

    #[test]
    fn test_path_traversal_basic() {
        let payloads = vec![
            "../../../etc/passwd",
            "..\\..\\..\\etc\\passwd",
            "/etc/passwd",
            "....//....//etc/passwd",
        ];

        for payload in payloads {
            let result = run_omg(&["info", payload]);
            assert!(
                !result.stdout.contains("root:x:0:0"),
                "Path traversal via: {payload}"
            );
        }
    }

    #[test]
    fn test_path_traversal_encoded() {
        let payloads = vec![
            "%2e%2e%2f%2e%2e%2fetc/passwd",
            "..%2f..%2f..%2fetc/passwd",
            "%00../etc/passwd",
        ];

        for payload in payloads {
            let result = run_omg(&["info", payload]);
            assert!(
                !result.stdout.contains("root:"),
                "Encoded path traversal via: {payload}"
            );
        }
    }

    // Note: Null byte injection test removed - std::process::Command rejects null bytes
    // at the OS level. This is expected behavior and provides security by default.

    #[test]
    fn test_sql_injection_patterns() {
        let payloads = vec![
            "'; DROP TABLE packages;--",
            "1' OR '1'='1",
            "1; DELETE FROM users",
            "UNION SELECT * FROM users",
        ];

        for payload in payloads {
            let result = run_omg(&["info", payload]);
            result.assert_failure();
            assert!(
                result.contains("Invalid character") || result.contains("Invalid package name"),
                "SQL metacharacters must be rejected as a package name, got: {}",
                result.combined_output()
            );
        }
    }

    #[test]
    fn test_xss_patterns() {
        let payloads = vec![
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ];

        for payload in payloads {
            let result = run_omg(&["info", payload]);
            result.assert_failure();
            assert!(
                result.contains("Invalid character") || result.contains("Invalid package name"),
                "markup must be rejected as a package name, got: {}",
                result.combined_output()
            );
        }
    }

    fn assert_rejected_as_package_name(payload: &str) {
        let result = run_omg(&["info", payload]);
        result.assert_failure();
        assert!(
            result.contains("Invalid character")
                || result.contains("Invalid package name")
                || result.contains("too long"),
            "payload {payload:?} must be rejected as a package name, got: {}",
            result.combined_output()
        );
    }

    #[test]
    fn test_format_string_attacks() {
        for payload in ["%s%s%s%s%s", "%x%x%x%x", "%n%n%n%n", "{0}{1}{2}"] {
            assert_rejected_as_package_name(payload);
        }
    }

    #[test]
    fn test_overflow_inputs() {
        assert_rejected_as_package_name(&"A".repeat(100_000));
    }

    #[test]
    fn test_unicode_security() {
        // Null bytes (\u{0000}) are rejected by Command before we see them.
        for payload in [
            "\u{202E}evil.txt",
            "\u{FEFF}test",
            "test\u{0085}",
            "\u{2028}line",
        ] {
            assert_rejected_as_package_name(payload);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// FILE SYSTEM SECURITY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod filesystem_security {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn test_sensitive_file_protection() {
        let project = TestProject::new();

        // Create files that look sensitive
        project.create_file(".env", "SECRET_KEY=abc123");
        project.create_file("config/secrets.toml", "password = \"secret\"");

        // OMG commands should not leak these
        let result = project.run(&["status"]);
        assert!(!result.stdout.contains("abc123"), "Leaked .env content");
        assert!(
            !result.stdout.contains("secret"),
            "Leaked secrets.toml content"
        );
    }

    #[test]
    #[cfg(any(feature = "arch", feature = "debian", feature = "debian-pure"))]
    fn test_file_permission_preservation() {
        let project = TestProject::new();
        let file_path = project.create_file("test.sh", "#!/bin/bash\necho hello");

        // Set executable permission
        #[cfg(unix)]
        {
            use std::fs;
            let mut perms = fs::metadata(&file_path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&file_path, perms).unwrap();
        }

        // Run commands; the capture must actually succeed, otherwise the
        // permission check below would pass vacuously.
        let result = project.run(&["env", "capture"]);
        result.assert_success();

        // Verify permissions unchanged
        #[cfg(unix)]
        {
            use std::fs;
            let perms = fs::metadata(&file_path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o755, "Permissions were modified");
        }
    }

    #[test]
    fn test_symlink_security() {
        let project = TestProject::new();

        #[cfg(unix)]
        {
            // Create symlink to sensitive file (fail loudly if setup breaks,
            // otherwise the leak assertion below proves nothing)
            let link_path = project.path().join("passwd_link");
            std::os::unix::fs::symlink("/etc/passwd", &link_path)
                .expect("create /etc/passwd symlink fixture");

            // OMG should not follow symlinks to sensitive locations
            let result = project.run(&["status"]);
            assert!(
                !result.stdout.contains("root:x:0:0"),
                "Followed symlink to /etc/passwd"
            );
        }
    }

    #[test]
    fn test_world_writable_cwd_does_not_break_status() {
        let project = TestProject::new();

        #[cfg(unix)]
        {
            use std::fs;
            let mut perms = fs::metadata(project.path()).unwrap().permissions();
            perms.set_mode(0o777);
            fs::set_permissions(project.path(), perms).unwrap();

            let result = project.run(&["status"]);
            assert!(
                result.contains("packages installed"),
                "a world-writable cwd must not prevent status from reporting packages, got: {}",
                result.combined_output()
            );
            assert!(
                !result.stdout.contains("root:x:0:0"),
                "status must not dump /etc/passwd because cwd is world-writable"
            );
        }
    }

    #[test]
    fn test_temp_file_security() {
        let project = TestProject::new();
        let result = project.run(&["env", "capture"]);
        let lock_path = project.path().join("omg.lock");

        if result.success {
            assert!(
                lock_path.exists(),
                "a successful capture must write omg.lock"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777;
                assert_eq!(
                    mode, 0o600,
                    "omg.lock must not be group or world accessible, got {mode:o}"
                );
            }
        } else {
            assert!(
                !lock_path.exists(),
                "a failed capture must not write a partial lockfile"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECRETS DETECTION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod secrets_detection {
    use omg_lib::core::security::secrets::{SecretScanner, SecretType};

    #[test]
    fn test_detect_aws_keys() {
        let findings = SecretScanner::new()
            .scan_content("AWS_ACCESS_KEY_ID=AKIAKLMNOPQRSTUVWXYZ\n", "config.txt");
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.secret_type, SecretType::AwsAccessKey)),
            "Should detect AWS access keys, got: {findings:?}"
        );
    }

    #[test]
    fn test_detect_private_keys() {
        let findings = SecretScanner::new().scan_content(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3...\n-----END RSA PRIVATE KEY-----",
            "key.pem",
        );
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.secret_type, SecretType::PrivateKey)),
            "Should detect private keys, got: {findings:?}"
        );
    }

    #[test]
    fn test_detect_api_tokens() {
        let findings = SecretScanner::new().scan_content(
            "GITHUB_TOKEN=ghp_aaaabbbbccccddddeeeeffffgggghhhhiiii\n",
            ".env",
        );
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.secret_type, SecretType::GithubToken)),
            "Should detect a GitHub token, got: {findings:?}"
        );
    }

    #[test]
    fn test_ignore_false_positives() {
        let findings = SecretScanner::new().scan_content(
            "Use AWS_ACCESS_KEY_ID environment variable.\n\
             Example: AWS_ACCESS_KEY_ID=your-key-here",
            "README.md",
        );
        assert!(
            findings.is_empty(),
            "placeholder examples must not be reported as secrets, got: {findings:?}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// POLICY ENFORCEMENT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod policy_enforcement {
    use super::*;
    use omg_lib::core::security::policy::{SecurityGrade, SecurityPolicy};

    /// Parse a policy fixture through the real deserializer so these tests
    /// fail if the fixture format drifts from `SecurityPolicy`.
    fn parse_policy(toml_src: &str) -> SecurityPolicy {
        toml::from_str(toml_src).expect("policy fixture must deserialize")
    }

    #[test]
    fn strict_policy_blocks_aur_packages() {
        let policy = parse_policy(policies::STRICT_POLICY);
        assert!(!policy.allow_aur, "STRICT_POLICY must disable AUR");

        let error = policy
            .check_package("yay-bin", true, Some("MIT"), SecurityGrade::Verified)
            .expect_err("AUR package must be blocked under strict policy");
        assert!(
            error.to_string().contains("AUR"),
            "rejection must cite AUR, got: {error}"
        );
    }

    #[test]
    fn strict_policy_still_allows_verified_official_packages() {
        let policy = parse_policy(policies::STRICT_POLICY);

        policy
            .check_package("pacman", false, Some("GPL-3.0"), SecurityGrade::Verified)
            .expect("verified official package within allowlist must pass strict policy");
    }

    #[test]
    fn banned_packages_are_rejected_by_name() {
        let policy = parse_policy("banned_packages = [\"telnet\", \"ftp\", \"rsh\"]");

        for name in ["telnet", "ftp", "rsh"] {
            let error = policy
                .check_package(name, false, None, SecurityGrade::Verified)
                .expect_err("banned package must be rejected by exact name");
            assert!(
                error.to_string().contains("banned"),
                "rejection must cite the ban, got: {error}"
            );
        }
        // Spelled differently but semantically the same license/name still
        // passes the name check — pin that only exact banned names match.
        let banned = parse_policy("banned_packages = [\"telnet\"]");
        banned
            .check_package("telnetd", false, None, SecurityGrade::Verified)
            .expect("prefix names must not be caught by exact-match ban");
    }

    #[test]
    fn license_allowlist_rejects_unknown_and_disallowed_licenses() {
        let policy = parse_policy("allowed_licenses = [\"MIT\", \"Apache-2.0\", \"BSD-3-Clause\"]");

        let error = policy
            .check_package("pkg", false, Some("GPL-3.0-only"), SecurityGrade::Verified)
            .expect_err("license outside the allowlist must be rejected");
        assert!(
            error.to_string().contains("GPL-3.0-only"),
            "rejection must cite the offending license, got: {error}"
        );

        let error = policy
            .check_package("pkg", false, None, SecurityGrade::Verified)
            .expect_err("unknown license must be rejected when an allowlist exists");
        assert!(
            error.to_string().to_lowercase().contains("unknown"),
            "rejection must mark the license as unknown, got: {error}"
        );
    }

    #[test]
    fn require_pgp_blocks_everything_below_verified_grade() {
        let policy = parse_policy("require_pgp = true");

        for grade in [SecurityGrade::Risk, SecurityGrade::Community] {
            let error = policy
                .check_package("pkg", false, None, grade)
                .expect_err("ungraded/unproven package must be blocked when PGP is required");
            assert!(
                error.to_string().contains("PGP")
                    || error
                        .to_string()
                        .to_lowercase()
                        .contains("below required minimum"),
                "rejection must cite PGP or the grade gate, got: {error}"
            );
        }
        policy
            .check_package("pkg", false, None, SecurityGrade::Verified)
            .expect("verified grade satisfies require_pgp");
    }

    #[test]
    fn enterprise_minimum_grade_gates_community_packages() {
        let policy = parse_policy(policies::ENTERPRISE_POLICY);
        assert_eq!(
            policy.minimum_grade,
            SecurityGrade::Verified,
            "ENTERPRISE_POLICY must demand Verified"
        );

        policy
            .check_package("aur-pkg", true, Some("MIT"), SecurityGrade::Community)
            .expect_err("community-grade package must fail enterprise minimum grade");

        policy
            .check_package("official-pkg", false, Some("MIT"), SecurityGrade::Verified)
            .expect("verified official MIT package passes enterprise policy");
    }

    /// CLI smoke: `audit policy` must load the policy written to the product
    /// config path — `$OMG_CONFIG_DIR/policy.toml`, see
    /// `SecurityPolicy::load_default` in src/core/security/policy.rs — and
    /// report its actual values instead of silently falling back to the
    /// built-in defaults (COMMUNITY grade, AUR allowed, empty ban list).
    #[test]
    fn cli_audit_policy_reports_written_strict_policy() {
        let project = TestProject::new();
        let policy_path = project.config_dir.path().join("policy.toml");
        std::fs::write(&policy_path, policies::STRICT_POLICY).expect("write strict policy fixture");

        let result = project.run(&["audit", "policy"]);
        result.assert_success();
        let output = result.combined_output();
        assert!(
            output.contains("VERIFIED"),
            "audit policy must report the strict minimum grade, got: {output}"
        );
        assert!(
            output.contains("Banned Packages") && output.contains("telnet"),
            "audit policy must list the configured banned packages, got: {output}"
        );
        assert!(
            !output.contains("COMMUNITY"),
            "audit policy must not fall back to built-in defaults, got: {output}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SBOM AND COMPLIANCE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod sbom_compliance {
    use super::*;

    #[test]
    fn test_sbom_generation_writes_cyclonedx() {
        let project = TestProject::new();
        let result = project.run(&["audit", "sbom", "--output", "sbom.json"]);
        if result.success {
            assert!(
                project.path().join("sbom.json").exists(),
                "SBOM command must write output on success"
            );
        } else {
            let output = result.combined_output();
            assert!(
                !output.contains("tier") && !output.contains("/pricing"),
                "SBOM must not be paywalled, got: {output}"
            );
        }
    }

    #[test]
    fn test_sbom_does_not_invent_spdx() {
        let project = TestProject::new();
        let result = project.run(&["audit", "sbom", "--output", "sbom.spdx"]);
        assert!(
            !project.path().join("sbom.spdx").exists()
                || project.read_file("sbom.spdx").is_some_and(|content| {
                    content.contains("bomFormat") || content.contains("components")
                }),
            "SBOM must not write a fake SPDX document"
        );
        let output = result.combined_output();
        assert!(
            !output.contains("/pricing"),
            "SBOM must not be paywalled, got: {output}"
        );
    }

    #[test]
    fn test_audit_log_is_not_paywalled() {
        let project = TestProject::new();
        let result = project.run(&["audit", "log"]);
        let output = result.combined_output();
        assert!(
            !output.contains("tier") && !output.contains("/pricing"),
            "audit log must not be paywalled, got: {output}"
        );
    }

    #[test]
    fn test_audit_log_verify_is_not_paywalled() {
        let project = TestProject::new();
        let result = project.run(&["audit", "verify"]);
        let output = result.combined_output();
        assert!(
            !output.contains("tier") && !output.contains("/pricing"),
            "audit verify must not be paywalled, got: {output}"
        );
    }

    #[test]
    fn test_slsa_check_is_not_paywalled() {
        let project = TestProject::new();
        let result = project.run(&[
            "audit",
            "slsa",
            "--certificate-identity",
            "release@example.invalid",
            "pacman",
        ]);
        let output = result.combined_output();
        assert!(
            !output.contains("tier") && !output.contains("/pricing"),
            "SLSA must not be paywalled, got: {output}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENVIRONMENT VARIABLE SECURITY
// ═══════════════════════════════════════════════════════════════════════════════

mod env_security {
    use super::*;

    #[test]
    fn test_no_secret_in_logs() {
        // Set a secret env var
        let result = run_omg_with_env(
            &["status"],
            &[
                ("SECRET_KEY", "super_secret_value"),
                ("API_TOKEN", "tok_12345"),
            ],
        );

        // Secrets should not appear in output
        assert!(
            !result.stdout.contains("super_secret_value"),
            "Secret leaked in stdout"
        );
        assert!(
            !result.stderr.contains("super_secret_value"),
            "Secret leaked in stderr"
        );
    }

    fn assert_status_reports_packages(result: &CommandResult) {
        assert!(
            result.contains("packages installed"),
            "status must still report package counts, got: {}",
            result.combined_output()
        );
        assert!(
            !result.combined_output().contains("root:x:0:0"),
            "status must not dump /etc/passwd"
        );
    }

    #[test]
    fn test_path_injection_prevention() {
        let project = TestProject::new();
        let bin_dir = project.path().join("evil-bin");
        std::fs::create_dir(&bin_dir).unwrap();
        let marker = project.path().join("pwned");
        let fake_pacman = bin_dir.join("pacman");
        std::fs::write(
            &fake_pacman,
            format!("#!/bin/sh\necho pwned > '{}'\n", marker.display()),
        )
        .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&fake_pacman).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&fake_pacman, perms).unwrap();
        }

        let path = bin_dir.to_str().expect("temp path must be UTF-8");
        let result = project.run_with_env(&["status"], &[("PATH", path)]);
        assert!(
            !marker.exists(),
            "a PATH-injected pacman must not run during status"
        );
        assert_status_reports_packages(&result);
    }

    #[test]
    fn test_ld_preload_ignored() {
        let result = run_omg_with_env(&["status"], &[("LD_PRELOAD", "/tmp/omg-test-missing.so")]);
        assert_status_reports_packages(&result);
    }

    #[test]
    fn test_home_traversal() {
        let result = run_omg_with_env(&["status"], &[("HOME", "/etc")]);
        assert_status_reports_packages(&result);
    }

    #[test]
    fn test_status_does_not_claim_clean_without_a_scan() {
        let result = run_omg(&["status"]);
        assert_status_reports_packages(&result);
        assert!(
            result.contains("Not scanned"),
            "unscanned status must not look like a clean bill of health, got: {}",
            result.combined_output()
        );
        assert!(
            !result.contains("No known issues"),
            "unscanned status must not print 'No known issues'"
        );
        assert!(
            !result.contains("Your system is healthy"),
            "unscanned status must not print 'Your system is healthy'"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// NETWORK SECURITY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod network_security {
    fn production_source(source: &str) -> &str {
        source
            .split_once("#[cfg(test)]")
            .map_or(source, |(production, _)| production)
    }

    fn assert_no_plaintext_http(source: &str, name: &str) {
        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }
            assert!(
                !trimmed.contains("\"http://"),
                "{name} must not embed a plaintext HTTP URL: {trimmed}"
            );
            assert!(
                !trimmed.contains("danger_accept_invalid_certs"),
                "{name} must not disable TLS certificate validation: {trimmed}"
            );
        }
    }

    #[test]
    fn test_runtime_and_http_clients_are_https() {
        assert_no_plaintext_http(
            production_source(include_str!("../src/core/http.rs")),
            "src/core/http.rs",
        );
        assert_no_plaintext_http(
            production_source(include_str!("../src/runtimes/common.rs")),
            "src/runtimes/common.rs",
        );
        assert_no_plaintext_http(
            include_str!("../src/runtimes/node.rs"),
            "src/runtimes/node.rs",
        );
        assert_no_plaintext_http(
            production_source(include_str!("../src/runtimes/python.rs")),
            "src/runtimes/python.rs",
        );
        assert_no_plaintext_http(include_str!("../src/runtimes/go.rs"), "src/runtimes/go.rs");
        assert_no_plaintext_http(
            production_source(include_str!("../src/runtimes/rust.rs")),
            "src/runtimes/rust.rs",
        );
        assert_no_plaintext_http(
            include_str!("../src/runtimes/ruby.rs"),
            "src/runtimes/ruby.rs",
        );
        assert_no_plaintext_http(
            include_str!("../src/runtimes/java.rs"),
            "src/runtimes/java.rs",
        );
        assert_no_plaintext_http(
            include_str!("../src/runtimes/bun.rs"),
            "src/runtimes/bun.rs",
        );
        assert_no_plaintext_http(include_str!("../src/runtimes/pi.rs"), "src/runtimes/pi.rs");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PRIVILEGE ESCALATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod privilege_tests {
    use super::*;

    #[test]
    fn test_safe_commands_run_without_root() {
        // Every command here must fully succeed as an unprivileged user and
        // report its actual result — not merely avoid demanding root.
        // Pinned surfaces: status overview, runtime listing, which lookup,
        // top-level help, generated bash completions.
        let commands: [Vec<&str>; 5] = [
            vec!["status"],
            vec!["list"],
            vec!["which", "node"],
            vec!["--help"],
            vec!["completions", "bash", "--stdout"],
        ];
        let expected_needles = [
            "packages installed",
            "runtime versions",
            "node",
            "Usage",
            "_omg_completions",
        ];

        for (args, needle) in commands.iter().zip(expected_needles) {
            let result = run_omg(args);
            result.assert_success();
            assert!(
                result.contains(needle),
                "command {args:?} must report its result without root; expected \
                 '{needle}' in: {}",
                result.combined_output()
            );
        }
    }

    #[test]
    #[cfg(any(feature = "arch", feature = "debian", feature = "debian-pure"))]
    fn test_no_suid_creation() {
        let project = TestProject::new();
        let result = project.run(&["env", "capture"]);
        // The capture must succeed, otherwise the SUID sweep below proves
        // nothing about what the tool writes.
        result.assert_success();

        // Verify no SUID files were created anywhere in the project tree
        #[cfg(unix)]
        {
            use std::fs;
            use std::os::unix::fs::PermissionsExt;

            fn collect_files(dir: &std::path::Path) -> std::io::Result<Vec<std::path::PathBuf>> {
                let mut files = Vec::new();
                for entry in fs::read_dir(dir)?.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        files.extend(collect_files(&path)?);
                    } else {
                        files.push(path);
                    }
                }
                Ok(files)
            }

            for path in collect_files(project.path()).expect("walk project directory") {
                if let Ok(meta) = fs::metadata(&path) {
                    let mode = meta.permissions().mode();
                    assert!(mode & 0o4000 == 0, "SUID file created: {path:?}");
                    assert!(mode & 0o2000 == 0, "SGID file created: {path:?}");
                }
            }
        }
    }
}
