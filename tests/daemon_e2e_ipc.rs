#![cfg(feature = "arch")]

//! Unix socket request, response, timeout, and connection contracts.

use anyhow::Result;
use omg_lib::daemon::handlers::{DaemonState, handle_request};
use omg_lib::daemon::protocol::{Request, Response, ResponseResult, error_codes};
use serial_test::serial;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::{sleep, timeout};

/// Test fixture for IPC tests
struct IpcTestFixture {
    _temp_dir: TempDir,
    socket_path: std::path::PathBuf,
    state: Arc<DaemonState>,
}

impl Drop for IpcTestFixture {
    fn drop(&mut self) {
        let result = omg_lib::core::security::audit::flush_pending_audit_events();
        if !std::thread::panicking() {
            result.expect("IPC audit events must finish before the collection is removed");
        }
    }
}

impl IpcTestFixture {
    fn new() -> Result<Self> {
        let temp_dir = TempDir::new()?;
        let socket_path = temp_dir.path().join("test.sock");
        let data_dir = temp_dir.path().join("data");
        std::fs::create_dir_all(&data_dir)?;

        // Scoped env: the audit logger and daemon state capture their
        // data-dir paths during construction, so isolation holds after the
        // guard restores the process environment. All tests using this
        // fixture are #[serial]-marked.
        let state = Arc::new(temp_env::with_vars(
            [
                ("OMG_DAEMON_DATA_DIR", Some(data_dir.as_os_str())),
                ("OMG_DATA_DIR", Some(data_dir.as_os_str())),
            ],
            || {
                omg_lib::core::security::init_audit_logger()?;
                DaemonState::new()
            },
        )?);

        Ok(Self {
            _temp_dir: temp_dir,
            socket_path,
            state,
        })
    }

    /// Start a simple IPC server for testing
    async fn start_server(&self) -> Result<tokio::task::JoinHandle<()>> {
        let listener = UnixListener::bind(&self.socket_path)?;
        let state = Arc::clone(&self.state);

        let handle = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = Self::handle_connection(stream, state).await {
                        eprintln!("Connection error: {e}");
                    }
                });
            }
        });

        // Wait for socket to be ready
        sleep(Duration::from_millis(100)).await;

        Ok(handle)
    }

    async fn handle_connection(stream: UnixStream, state: Arc<DaemonState>) -> Result<()> {
        use futures::{SinkExt, StreamExt};
        use tokio_util::codec::{Framed, LengthDelimitedCodec};

        let mut framed = Framed::new(stream, LengthDelimitedCodec::new());

        while let Some(request_bytes) = framed.next().await {
            let bytes = request_bytes?;
            let request: Request =
                bitcode::deserialize(omg_lib::daemon::protocol::split_frame(&bytes)?.1)?;
            let response = handle_request(Arc::clone(&state), request).await;
            let response_bytes = omg_lib::daemon::protocol::encode_frame(&response)?;
            framed.send(response_bytes.into()).await?;
        }

        Ok(())
    }

    async fn connect(&self) -> Result<UnixStream> {
        Ok(UnixStream::connect(&self.socket_path).await?)
    }

    async fn send_request(&self, stream: &mut UnixStream, request: &Request) -> Result<Response> {
        // Serialize request
        let request_bytes = omg_lib::daemon::protocol::encode_frame(request)?;
        let len = u32::try_from(request_bytes.len())?;

        // Send length + data
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&request_bytes).await?;

        // Read response length
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let resp_len = u32::from_be_bytes(len_buf) as usize;

        // Read response data
        let mut resp_bytes = vec![0u8; resp_len];
        stream.read_exact(&mut resp_bytes).await?;

        // Deserialize response
        Ok(bitcode::deserialize(
            omg_lib::daemon::protocol::split_frame(&resp_bytes)?.1,
        )?)
    }
}

// ============================================================================
// Basic Request-Response
// ============================================================================

#[tokio::test]
#[serial]
async fn test_basic_ping_request() -> Result<()> {
    let fixture = IpcTestFixture::new()?;
    let _server = fixture.start_server().await?;

    let mut stream = fixture.connect().await?;
    let request = Request::Ping { id: 1 };
    let response = fixture.send_request(&mut stream, &request).await?;

    match response {
        Response::Success { id, result } => {
            assert_eq!(id, 1);
            assert!(matches!(result, ResponseResult::Ping(_)));
        }
        Response::Error { message, .. } => unreachable!("Ping failed: {}", message),
    }

    Ok(())
}

// ============================================================================
// Message Serialization Edge Cases
// ============================================================================

#[tokio::test]
#[serial]
async fn test_large_request_handling() -> Result<()> {
    let fixture = IpcTestFixture::new()?;
    let _server = fixture.start_server().await?;

    let mut stream = fixture.connect().await?;

    // Create a large but valid search query
    let large_query = "a".repeat(400); // Within MAX_QUERY_LENGTH (500)
    let request = Request::Search {
        id: 2,
        query: large_query,
        limit: Some(10),
    };

    let response = fixture.send_request(&mut stream, &request).await?;

    let Response::Success { id, result } = response else {
        unreachable!("A valid query within the size limit should succeed");
    };
    assert_eq!(id, 2);
    assert!(
        matches!(result, ResponseResult::Search(_)),
        "A search request should return search results"
    );

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_oversized_query_rejection() -> Result<()> {
    let fixture = IpcTestFixture::new()?;
    let _server = fixture.start_server().await?;

    let mut stream = fixture.connect().await?;

    // Create query exceeding MAX_QUERY_LENGTH (500)
    let oversized_query = "x".repeat(600);
    let request = Request::Search {
        id: 3,
        query: oversized_query,
        limit: Some(10),
    };

    let response = fixture.send_request(&mut stream, &request).await?;

    match response {
        Response::Error { code, .. } => {
            assert_eq!(
                code,
                error_codes::INVALID_PARAMS,
                "Oversized query should be rejected"
            );
        }
        Response::Success { .. } => {
            unreachable!("Oversized query should be rejected");
        }
    }

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_empty_request_handling() -> Result<()> {
    let fixture = IpcTestFixture::new()?;
    let _server = fixture.start_server().await?;

    let mut stream = fixture.connect().await?;

    // Empty search query
    let request = Request::Search {
        id: 4,
        query: String::new(),
        limit: Some(10),
    };

    let response = fixture.send_request(&mut stream, &request).await?;

    let Response::Success { id, result } = response else {
        unreachable!("An empty search query should return an empty result set");
    };
    assert_eq!(id, 4);
    let ResponseResult::Search(search_result) = result else {
        unreachable!("A search request should return search results");
    };
    assert!(
        search_result.packages.is_empty(),
        "Empty query should return no results"
    );

    Ok(())
}

// ============================================================================
// Connection Pooling and Concurrency
// ============================================================================

#[tokio::test]
#[serial]
async fn test_multiple_concurrent_connections() -> Result<()> {
    let fixture = IpcTestFixture::new()?;
    let _server = fixture.start_server().await?;

    // Spawn 10 concurrent clients
    let mut handles = vec![];
    for client_id in 0..10 {
        let socket_path = fixture.socket_path.clone();
        let handle = tokio::spawn(async move {
            let mut stream = UnixStream::connect(&socket_path).await?;
            let request = Request::Ping { id: client_id };

            // Send request
            let request_bytes = omg_lib::daemon::protocol::encode_frame(&request)?;
            let len = u32::try_from(request_bytes.len())?;
            stream.write_all(&len.to_be_bytes()).await?;
            stream.write_all(&request_bytes).await?;

            // Read response
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await?;
            let resp_len = u32::from_be_bytes(len_buf) as usize;
            let mut resp_bytes = vec![0u8; resp_len];
            stream.read_exact(&mut resp_bytes).await?;

            let response: Response =
                bitcode::deserialize(omg_lib::daemon::protocol::split_frame(&resp_bytes)?.1)?;
            Ok::<_, anyhow::Error>(response)
        });
        handles.push(handle);
    }

    // Wait for all clients
    for handle in handles {
        let response = handle.await??;
        assert!(
            matches!(response, Response::Success { .. }),
            "All clients should succeed"
        );
    }

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_sequential_requests_on_single_connection() -> Result<()> {
    let fixture = IpcTestFixture::new()?;
    let _server = fixture.start_server().await?;

    let mut stream = fixture.connect().await?;

    // Send 5 sequential requests on same connection
    for i in 0..5 {
        let request = Request::Ping { id: i };
        let response = fixture.send_request(&mut stream, &request).await?;

        match response {
            Response::Success { id, .. } => {
                assert_eq!(id, i, "Response ID should match request ID");
            }
            Response::Error { message, .. } => {
                unreachable!("Request {} failed: {}", i, message);
            }
        }
    }

    Ok(())
}

// ============================================================================
// Timeout Handling
// ============================================================================

#[tokio::test]
#[serial]
async fn test_client_disconnect_during_request() -> Result<()> {
    let fixture = IpcTestFixture::new()?;
    let _server = fixture.start_server().await?;

    {
        let mut stream = fixture.connect().await?;
        let request = Request::Status { id: 200 };

        // Send request
        let request_bytes = omg_lib::daemon::protocol::encode_frame(&request)?;
        let len = u32::try_from(request_bytes.len())?;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&request_bytes).await?;

        // Disconnect immediately without reading response
        drop(stream);
    }

    // Server should handle disconnect gracefully
    sleep(Duration::from_millis(200)).await;

    // New connection should work fine
    let mut stream = fixture.connect().await?;
    let request = Request::Ping { id: 201 };
    let response = fixture.send_request(&mut stream, &request).await?;

    assert!(
        matches!(response, Response::Success { .. }),
        "Server should recover from client disconnect"
    );

    Ok(())
}

// ============================================================================
// Protocol Error Handling
// ============================================================================

#[tokio::test]
#[serial]
async fn test_malformed_request_handling() -> Result<()> {
    let fixture = IpcTestFixture::new()?;
    let _server = fixture.start_server().await?;

    let mut stream = fixture.connect().await?;

    // Send garbage data that cannot deserialize into a `Request`.
    let garbage = vec![0xFF; 100];
    let len = u32::try_from(garbage.len())?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&garbage).await?;

    // Contract: handle_connection propagates the decode error and drops the
    // stream, so a follow-up valid request on the SAME connection must never
    // be answered with a success response — the connection is closed (read
    // failure / timeout) or explicitly rejected with an error response.
    sleep(Duration::from_millis(100)).await;

    let follow_up = Request::Ping { id: 300 };
    let outcome = timeout(
        Duration::from_secs(2),
        fixture.send_request(&mut stream, &follow_up),
    )
    .await;

    match outcome {
        Err(_) | Ok(Err(_) | Ok(Response::Error { .. })) => {}
        Ok(Ok(Response::Success { id, .. })) => panic!(
            "server answered request id {id} on a connection that previously \n            received a malformed frame",
        ),
    }

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_invalid_package_name_injection() -> Result<()> {
    let fixture = IpcTestFixture::new()?;
    let _server = fixture.start_server().await?;

    let mut stream = fixture.connect().await?;

    // Attempt command injection
    let request = Request::Info {
        id: 400,
        package: "test; rm -rf /".to_string(),
    };

    let response = fixture.send_request(&mut stream, &request).await?;

    match response {
        Response::Error { code, .. } => {
            assert_eq!(
                code,
                error_codes::INVALID_PARAMS,
                "Injection attempt should be rejected"
            );
        }
        Response::Success { .. } => {
            unreachable!("Injection attempt should be rejected");
        }
    }

    Ok(())
}

// ============================================================================
// Request ID Validation
// ============================================================================

#[tokio::test]
#[serial]
async fn test_request_id_preservation() -> Result<()> {
    let fixture = IpcTestFixture::new()?;
    let _server = fixture.start_server().await?;

    let mut stream = fixture.connect().await?;

    // Test with various ID values
    let test_ids = vec![0, 1, 42, u64::MAX - 1, u64::MAX];

    for test_id in test_ids {
        let request = Request::Ping { id: test_id };
        let response = fixture.send_request(&mut stream, &request).await?;

        match response {
            Response::Success { id, .. } => {
                assert_eq!(id, test_id, "Response ID should match request ID");
            }
            Response::Error { id, .. } => {
                assert_eq!(id, test_id, "Error response ID should match request ID");
            }
        }
    }

    Ok(())
}

// ============================================================================
// Connection Lifecycle
// ============================================================================

#[tokio::test]
#[serial]
async fn test_connection_close_after_response() -> Result<()> {
    let fixture = IpcTestFixture::new()?;
    let _server = fixture.start_server().await?;

    {
        let mut stream = fixture.connect().await?;
        let request = Request::Ping { id: 800 };
        let _response = fixture.send_request(&mut stream, &request).await?;

        // Close connection explicitly
        drop(stream);
    }

    // Should be able to create new connection
    let mut stream = fixture.connect().await?;
    let request = Request::Ping { id: 801 };
    let response = fixture.send_request(&mut stream, &request).await?;

    assert!(matches!(response, Response::Success { .. }));

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_idle_connection_stability() -> Result<()> {
    let fixture = IpcTestFixture::new()?;
    let _server = fixture.start_server().await?;

    let mut stream = fixture.connect().await?;

    // Send request
    let request = Request::Ping { id: 900 };
    let _response = fixture.send_request(&mut stream, &request).await?;

    // Keep connection idle for 2 seconds
    sleep(Duration::from_secs(2)).await;

    // Should still work
    let request = Request::Ping { id: 901 };
    let response = fixture.send_request(&mut stream, &request).await?;

    assert!(
        matches!(response, Response::Success { .. }),
        "Idle connection should remain valid"
    );

    Ok(())
}
