#![cfg(any(feature = "debian", feature = "debian-pure"))]

use omg_lib::daemon::handlers::DaemonState;
use serial_test::serial;
use std::sync::Arc;

// Both tests below mutate the process environment through
// `temp_env::with_vars`. Concurrent setenv/getenv from libtest's default
// parallel threads is racy and was observed to SIGSEGV the test process, so
// they are serialized with `#[serial]`.
#[test]
#[serial]
fn test_daemon_initialization_debian_mock() {
    let temp_dir = tempfile::tempdir().unwrap();
    let temp_path = temp_dir.path().to_str().unwrap().to_string();

    let state_result = temp_env::with_vars(
        [
            ("OMG_TEST_MODE", Some("true")),
            ("OMG_TEST_DISTRO", Some("debian")),
            ("OMG_DATA_DIR", Some(temp_path.as_str())),
            ("OMG_DAEMON_DATA_DIR", Some(temp_path.as_str())),
        ],
        DaemonState::new,
    );

    // Assert success
    assert!(
        state_result.is_ok(),
        "DaemonState::new() failed: {:?}",
        state_result.err()
    );

    let _state = state_result.unwrap();
}

use omg_lib::daemon::handlers::handle_request;
use omg_lib::daemon::protocol::{Request, Response, ResponseResult};

#[tokio::test]
#[serial]
async fn test_handle_debian_search() {
    let temp_dir = tempfile::tempdir().unwrap();
    let temp_path = temp_dir.path().to_str().unwrap().to_string();

    let state = temp_env::with_vars(
        [
            ("OMG_TEST_MODE", Some("true")),
            ("OMG_TEST_DISTRO", Some("debian")),
            ("OMG_DATA_DIR", Some(temp_path.as_str())),
            ("OMG_DAEMON_DATA_DIR", Some(temp_path.as_str())),
        ],
        DaemonState::new,
    )
    .unwrap();
    let state = Arc::new(state);

    let req = Request::DebianSearch {
        id: 123,
        query: "apt".to_string(),
        limit: Some(10),
    };

    let response = handle_request(state, req).await;

    match response {
        Response::Success { id, result } => {
            assert_eq!(id, 123);
            assert!(
                matches!(result, ResponseResult::DebianSearch(_)),
                "Expected DebianSearch result"
            );
            let ResponseResult::DebianSearch(pkgs) = result else {
                return;
            };
            assert!(!pkgs.is_empty());
            assert_eq!(pkgs[0].name, "apt");
        }
        Response::Error { message, .. } => {
            unreachable!("Search failed: {message}");
        }
    }
}
