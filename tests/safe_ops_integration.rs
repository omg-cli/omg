//! Integration tests for safe operations module
//!
//! This module tests the safe operations in more realistic scenarios
//! to ensure they work correctly with the broader codebase.

use omg_lib::core::safe_ops::*;
use tempfile::TempDir;
use tokio::fs;

#[cfg(target_os = "linux")]
fn assert_failed_write_is_retryable(test_name: &str, executable: bool, restrictive_umask: bool) {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
    use std::os::unix::fs::PermissionsExt;

    // Resource limits affect the whole process. Re-exec only this test with
    // SIGXFSZ ignored so the kernel returns EFBIG instead of killing the suite.
    if std::env::var("OMG_SAFE_OPS_FAULT_CHILD").as_deref() != Ok(test_name) {
        let output = std::process::Command::new("sh")
            .args([
                "-c",
                if restrictive_umask {
                    "umask 077; trap '' XFSZ; exec \"$@\""
                } else {
                    "umask 022; trap '' XFSZ; exec \"$@\""
                },
                "sh",
            ])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", test_name, "--nocapture"])
            .env("OMG_SAFE_OPS_FAULT_CHILD", test_name)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "fault subprocess failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let temp = TempDir::new().unwrap();
    let path = temp.path().join("destination");
    let contents = b"complete contents";
    let write = || {
        if executable {
            write_executable(&path, contents, false)
        } else {
            create_private_marker(&path, contents)
        }
    };
    let original = getrlimit(Resource::Fsize);
    setrlimit(
        Resource::Fsize,
        Rlimit {
            current: Some(4),
            maximum: original.maximum,
        },
    )
    .unwrap();
    let first = write();
    setrlimit(Resource::Fsize, original).unwrap();

    let error = first.expect_err("the file-size limit must cause a real write failure");
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .raw_os_error(),
        Some(nix::libc::EFBIG)
    );
    assert!(
        !path.try_exists().unwrap(),
        "failed write published a partial destination"
    );
    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
    assert!(write().unwrap(), "retry must create the complete file");
    assert_eq!(std::fs::read(&path).unwrap(), contents);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        if executable {
            if restrictive_umask { 0o700 } else { 0o755 }
        } else {
            0o600
        }
    );
    assert!(
        !write().unwrap(),
        "an existing file must not be overwritten"
    );
    assert_eq!(std::fs::read(&path).unwrap(), contents);
    temp.close().unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn executable_write_failure_preserves_retryability() {
    assert_failed_write_is_retryable(
        "executable_write_failure_preserves_retryability",
        true,
        false,
    );
}

#[cfg(target_os = "linux")]
#[test]
fn private_marker_write_failure_preserves_retryability() {
    assert_failed_write_is_retryable(
        "private_marker_write_failure_preserves_retryability",
        false,
        false,
    );
}

#[cfg(target_os = "linux")]
#[test]
fn executable_retry_respects_restrictive_umask() {
    assert_failed_write_is_retryable("executable_retry_respects_restrictive_umask", true, true);
}

#[cfg(unix)]
#[test]
fn concurrent_noclobber_writers_publish_one_complete_file() {
    for executable in [true, false] {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("destination");
        let barrier = std::sync::Barrier::new(8);
        let outcomes = std::thread::scope(|scope| {
            let handles: Vec<_> = (0_u8..8)
                .map(|index| {
                    let barrier = &barrier;
                    let path = &path;
                    scope.spawn(move || {
                        let contents = vec![index; 65536];
                        barrier.wait();
                        let created = if executable {
                            write_executable(path, &contents, false)
                        } else {
                            create_private_marker(path, &contents)
                        }
                        .unwrap();
                        (index, created)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        let winners: Vec<_> = outcomes.iter().filter(|(_, created)| *created).collect();
        assert_eq!(winners.len(), 1, "exactly one writer must claim the path");
        assert_eq!(std::fs::read(&path).unwrap(), vec![winners[0].0; 65536]);
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
        temp.close().unwrap();
    }
}

#[tokio::test]
async fn test_safe_file_operations_integration() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("integration_test.txt");
    let content = b"Integration test content";

    // Test async atomic write
    let result = atomic_write_file(&file_path, content).await;
    assert!(result.is_ok());

    // Verify content was written correctly
    let read_content = fs::read_to_string(&file_path).await.unwrap();
    assert_eq!(read_content, "Integration test content");

    // Test sync atomic write
    let sync_path = temp_dir.path().join("sync_test.txt");
    let sync_result = atomic_write_file_sync(&sync_path, content);
    assert!(sync_result.is_ok());

    // Verify sync content
    let sync_read = std::fs::read_to_string(&sync_path).unwrap();
    assert_eq!(sync_read, "Integration test content");
}

#[tokio::test]
async fn test_path_validation_integration() {
    // Test valid path
    let temp_dir = TempDir::new().unwrap();
    let valid_path = temp_dir.path();
    let result = validate_path_syntax(valid_path);
    assert!(result.is_ok());

    // Test empty path
    let empty_result = validate_path_syntax("");
    assert!(empty_result.is_err());

    // Test path with null byte
    let null_path = "/tmp/with\0null";
    let null_result = validate_path_syntax(null_path);
    assert!(null_result.is_err());
}

#[test]
fn test_nonzero_fallback_edge_cases() {
    // Test with default fallback
    let nz_default = nonzero_u32_or_default(0, 999);
    assert_eq!(nz_default.get(), 999);

    let nz_valid = nonzero_u32_or_default(123, 999);
    assert_eq!(nz_valid.get(), 123);
}
