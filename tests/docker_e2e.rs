//! Docker-based E2E Tests
//!
//! These tests run actual install/remove operations in Docker containers
//! to verify real system integration without modifying the host.
//!
//! Run with: `OMG_RUN_DOCKER_TESTS=1 cargo test --locked --no-default-features --features pgp,license --test docker_e2e -- --ignored --test-threads=1`
//! CI compiles this std-only driver directly with `rustc --edition=2024 --test`
//! and supplies the immutable ID of the image built from the checkout.

use std::process::Command;
use std::sync::OnceLock;
use std::thread;

fn require_docker_tests() {
    assert_eq!(
        std::env::var("OMG_RUN_DOCKER_TESTS").as_deref(),
        Ok("1"),
        "Docker E2E tests require OMG_RUN_DOCKER_TESTS=1",
    );
}

fn docker_available() -> bool {
    Command::new("docker")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn build_docker_image() -> bool {
    let status = Command::new("docker")
        .args([
            "build",
            "-f",
            "Dockerfile.arch-e2e",
            "-t",
            "omg-arch-e2e",
            ".",
        ])
        .status()
        .expect("Failed to build Docker image");

    status.success()
}

/// Lazily build the Docker image exactly once, regardless of test ordering.
/// Tests run alphabetically, so we can't rely on `test_docker_setup` running first.
static DOCKER_IMAGE_READY: OnceLock<String> = OnceLock::new();

fn ensure_docker_image() -> bool {
    docker_image();
    true
}

fn docker_image() -> &'static str {
    DOCKER_IMAGE_READY.get_or_init(|| {
        assert!(docker_available(), "Docker not available");
        let image = match std::env::var("OMG_DOCKER_IMAGE") {
            Ok(image) => {
                assert!(
                    image.strip_prefix("sha256:").is_some_and(|digest| {
                        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                    }),
                    "OMG_DOCKER_IMAGE must be an immutable sha256 image ID"
                );
                image
            }
            Err(std::env::VarError::NotPresent) => {
                assert!(build_docker_image(), "Failed to build Docker image");
                "omg-arch-e2e".to_owned()
            }
            Err(error) => panic!("Invalid OMG_DOCKER_IMAGE: {error}"),
        };
        let output = Command::new("docker")
            .args(["image", "inspect", "--format", "{{.Id}}", &image])
            .output()
            .expect("Failed to inspect Docker image");
        assert!(output.status.success(), "Docker image must exist locally");
        let id = String::from_utf8(output.stdout)
            .expect("Docker image ID must be UTF-8")
            .trim()
            .to_owned();
        assert!(!id.is_empty(), "Docker returned an empty image ID");
        if image.starts_with("sha256:") {
            assert_eq!(id, image, "Docker image ID differs from the build output");
        }
        id
    })
}

/// Run a single command in a fresh Docker container
fn run_in_docker(cmd: &[&str]) -> (bool, String, String) {
    run_in_docker_with_options(&[], cmd)
}

fn run_in_docker_with_options(options: &[&str], cmd: &[&str]) -> (bool, String, String) {
    let output = Command::new("docker")
        .args(["run", "--rm"])
        .args(options)
        .arg(docker_image())
        .args(cmd)
        .output()
        .expect("Failed to run Docker command");

    let success = output.status.success();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !success {
        eprintln!(
            "Docker command {cmd:?} (options {options:?}) failed with {}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}",
            output.status
        );
    }

    (success, stdout, stderr)
}

/// Run a shell script in a single Docker container (preserves state between commands)
fn run_script_in_docker(script: &str) -> (bool, String, String) {
    run_in_docker(&["sh", "-c", script])
}

/// Strip ANSI escape codes from text for reliable string matching
fn strip_ansi(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip until we find the end of the escape sequence
            for inner in chars.by_ref() {
                if inner.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

#[test]
#[ignore = "requires Docker; run the dedicated Docker E2E job with --ignored"]
fn test_docker_setup() {
    require_docker_tests();

    assert!(ensure_docker_image(), "Failed to build Docker image");
}

#[test]
#[ignore = "requires Docker; run the dedicated Docker E2E job with --ignored"]
fn test_docker_omg_search() {
    require_docker_tests();
    assert!(ensure_docker_image(), "Docker image not ready");

    let (success, stdout, _stderr) = run_in_docker(&["omg", "search", "vim"]);

    assert!(success, "Search should succeed");
    let plain = strip_ansi(&stdout);
    assert!(plain.contains("vim"), "Should find vim package");
}

#[test]
#[ignore = "requires Docker; run the dedicated Docker E2E job with --ignored"]
fn test_docker_omg_info() {
    require_docker_tests();
    assert!(ensure_docker_image(), "Docker image not ready");

    let (success, stdout, _stderr) = run_in_docker(&["omg", "info", "bash"]);

    assert!(success, "Info should succeed");
    let plain = strip_ansi(&stdout);
    assert!(plain.contains("bash"), "Should show bash package info");
    // The shared info renderer must include package metadata and provenance.
    assert!(
        plain.contains("Description:"),
        "info output must include a Description line, got: {plain}"
    );
    assert!(
        plain.contains("Source:") && plain.contains("Official repository (core)"),
        "official-repo info output must include the source repository, got: {plain}"
    );
}

#[test]
#[ignore = "requires Docker; run the dedicated Docker E2E job with --ignored"]
fn test_docker_real_install() {
    require_docker_tests();
    assert!(ensure_docker_image(), "Docker image not ready");

    // Install and verify in a single container (state persists within one docker run)
    let (success, stdout, stderr) =
        run_script_in_docker("sudo omg install -y ripgrep && pacman -Qi ripgrep");

    if !success {
        eprintln!("STDOUT: {stdout}");
        eprintln!("STDERR: {stderr}");
    }

    assert!(success, "Install and verify should succeed");
    assert!(
        stdout.contains("ripgrep"),
        "Should find installed package in pacman -Qi output"
    );
}

// NOTE: `test_docker_real_remove` was merged into
// `test_docker_install_removes_work_together`, which runs the strictly
// stronger script (it additionally verifies the install before removing).

#[test]
#[ignore = "requires Docker; run the dedicated Docker E2E job with --ignored"]
fn test_docker_update_check() {
    require_docker_tests();
    assert!(ensure_docker_image(), "Docker image not ready");

    // Dockerfile.arch-e2e installs a root-owned executable under root-controlled
    // ancestors, then runs as testuser. Self-elevation must work in plain Docker
    // without granting SYS_PTRACE or weakening protection for writable installs.
    let (success, stdout, _stderr) = run_in_docker(&["omg", "update", "--check"]);

    assert!(success, "Update check should succeed");
    // Contract: arch::update check_only path prints a phase header announcing
    // that it checks the cached package databases without refreshing them
    // (src/cli/packages/update/arch.rs update_phase_context). The transient
    // "Checking" spinner is cleared and never reaches non-TTY stdout.
    let plain = strip_ansi(&stdout);
    assert!(
        plain.contains("Checking for updates · cached"),
        "update --check must announce its check phase, got: {plain}"
    );
}

#[test]
#[ignore = "requires Docker; run the dedicated Docker E2E job with --ignored"]
fn test_docker_explicit_packages() {
    require_docker_tests();
    assert!(ensure_docker_image(), "Docker image not ready");

    let (success, stdout, _stderr) = run_in_docker(&["omg", "explicit"]);

    assert!(success, "Explicit command should succeed");
    // Base system should have some explicitly installed packages
    assert!(
        !stdout.trim().is_empty(),
        "Should list some explicit packages"
    );
}

#[test]
#[ignore = "requires Docker; run the dedicated Docker E2E job with --ignored"]
fn test_docker_status() {
    require_docker_tests();
    assert!(ensure_docker_image(), "Docker image not ready");

    let (success, stdout, _stderr) = run_in_docker(&["omg", "status"]);

    assert!(success, "Status command should succeed");
    // Contract: StatusData::render prints a Status heading and installed counts.
    let plain = strip_ansi(&stdout);
    assert!(
        plain.lines().next() == Some("Status"),
        "status must render its report header, got: {plain}"
    );
    assert!(
        plain.contains("packages installed") && plain.contains("explicit"),
        "status must include the total package count line, got: {plain}"
    );
}

#[test]
#[ignore = "requires Docker; run the dedicated Docker E2E job with --ignored"]
fn test_docker_concurrent_operations() {
    require_docker_tests();
    assert!(ensure_docker_image(), "Docker image not ready");

    // Run multiple search operations concurrently
    let handles: Vec<_> = (0..4)
        .map(|i| {
            thread::spawn(move || {
                let query = match i {
                    0 => "vim",
                    1 => "firefox",
                    2 => "git",
                    _ => "bash",
                };
                run_in_docker(&["omg", "search", query])
            })
        })
        .collect();

    for handle in handles {
        let (success, _, _) = handle.join().unwrap();
        assert!(success, "Concurrent search should succeed");
    }
}

#[test]
#[ignore = "requires Docker; run the dedicated Docker E2E job with --ignored"]
fn test_docker_nonexistent_package() {
    require_docker_tests();
    assert!(ensure_docker_image(), "Docker image not ready");

    let (_success, stdout, stderr) = run_in_docker(&["omg", "info", "package-does-not-exist-xyz"]);

    // Every info lookup path bails with this message for missing packages.
    let combined = format!("{stdout}{stderr}");
    let plain = strip_ansi(&combined);
    assert!(
        plain.contains("not found"),
        "Should report 'Package ... not found', got: {plain}"
    );
}

#[test]
#[ignore = "requires Docker; run the dedicated Docker E2E job with --ignored"]
fn test_docker_install_removes_work_together() {
    require_docker_tests();
    assert!(ensure_docker_image(), "Docker image not ready");

    // All operations in a single container to preserve state
    let (success, _stdout, _stderr) = run_script_in_docker(
        "sudo omg install -y tree \
         && which tree \
         && sudo omg remove -y tree \
         && ! which tree",
    );

    assert!(
        success,
        "Install, verify, remove, and verify-removed should all succeed"
    );
}
