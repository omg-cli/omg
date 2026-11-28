use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn update_error_from_reply(
    reply: Option<&[u8]>,
    attempts: usize,
) -> Result<anyhow::Error> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}/rpc", listener.local_addr()?);
    let reply = reply.map(<[u8]>::to_vec);
    let server = tokio::spawn(async move {
        for _ in 0..attempts {
            let (mut stream, _) = listener.accept().await?;
            let mut request = Vec::new();
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                anyhow::ensure!(request.len() < 8192, "fixture request too large");
                let mut buffer = [0; 1024];
                let count = stream.read(&mut buffer).await?;
                anyhow::ensure!(count > 0, "fixture request incomplete");
                request.extend_from_slice(&buffer[..count]);
            }
            if let Some(reply) = &reply {
                stream.write_all(reply).await?;
            }
            stream.shutdown().await?;
        }
        anyhow::Ok(())
    });
    let client = AurClient {
        build_dir: PathBuf::new(),
        settings: Settings::default(),
        package_base_locks: Arc::new(dashmap::DashMap::new()),
    };
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        client.query_aur_updates_at(
            &endpoint,
            &["private-package-query".to_owned()],
            Arc::new(HashMap::new()),
        ),
    )
    .await?;
    tokio::time::timeout(Duration::from_secs(5), server).await???;
    let error = result.expect_err("failed RPC must fail update discovery");
    for cause in error.chain() {
        let message = cause.to_string();
        assert!(!message.contains("private-package-query"), "{message}");
        assert!(!message.contains("remote-secret"), "{message}");
        assert!(!message.contains(&endpoint), "{message}");
    }
    Ok(error)
}

#[tokio::test]
async fn rate_limited_updates_preserve_http_cause_and_cooldown_guidance() -> Result<()> {
    let error = update_error_from_reply(Some(
        b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 13\r\nConnection: close\r\n\r\nremote-secret",
    ), 3)
    .await?;
    assert!(update_source_unavailable(&error));
    assert_eq!(
        crate::core::error::suggest_for_anyhow(&error),
        Some("Wait for the cooldown period, then retry your request")
    );
    assert!(format!("{error:#}").contains("HTTP 429"), "{error:#}");
    Ok(())
}

#[tokio::test]
async fn failed_update_transport_preserves_redaction_and_network_guidance() -> Result<()> {
    let error = update_error_from_reply(None, 1).await?;
    assert!(update_source_unavailable(&error));
    assert_eq!(
        crate::core::error::suggest_for_anyhow(&error),
        Some("Check your internet connection and try again")
    );
    assert!(
        format!("{error:#}").contains("AUR RPC transport failed"),
        "{error:#}"
    );
    Ok(())
}

#[tokio::test]
async fn failed_update_http_status_does_not_invent_network_guidance() -> Result<()> {
    let error = update_error_from_reply(Some(
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    ), 3).await?;
    assert!(update_source_unavailable(&error));
    assert!(format!("{error:#}").contains("HTTP 503"), "{error:#}");
    assert_eq!(crate::core::error::suggest_for_anyhow(&error), None);
    Ok(())
}

#[test]
fn aur_update_availability_does_not_hide_permanent_http_or_local_errors() {
    let denied = ensure_aur_rpc_success(reqwest::StatusCode::FORBIDDEN)
        .expect_err("HTTP 403 is a hard listing failure");
    assert!(!update_source_unavailable(&denied));
    let invalid = decode_aur_rpc_body::<AurResponse>(b"{").expect_err("invalid response");
    assert!(!update_source_unavailable(&invalid));
    let local = anyhow::anyhow!("Failed to load AUR update filters from pacman.conf");
    assert!(!update_source_unavailable(&local));
}

#[tokio::test]
async fn failed_update_remote_envelope_does_not_leak_or_inject_guidance() -> Result<()> {
    let body = br#"{"type":"error","error":"remote-secret: permission denied","results":[]}"#;
    // This response is deliberately outside the retryable status path.
    let reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        String::from_utf8_lossy(body)
    );
    let error = update_error_from_reply(Some(reply.as_bytes()), 1).await?;
    assert_eq!(crate::core::error::suggest_for_anyhow(&error), None);
    Ok(())
}
