use super::AurClient;
use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn empty_info_reply_is_a_real_completed_rpc_lookup() -> Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}/rpc", listener.local_addr()?);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut bytes = Vec::new();
        while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            anyhow::ensure!(bytes.len() < 8192, "RPC fixture header exceeds 8 KiB");
            let mut chunk = [0; 1024];
            let count = stream
                .read(&mut chunk[..(8192 - bytes.len()).min(1024)])
                .await?;
            anyhow::ensure!(count > 0, "RPC fixture closed before complete header");
            bytes.extend_from_slice(&chunk[..count]);
        }
        let request = String::from_utf8(bytes)?;
        let body = r#"{"type":"multiinfo","resultcount":0,"results":[]}"#;
        let reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(reply.as_bytes()).await?;
        anyhow::Ok(request)
    });
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        AurClient::rpc_info_chunk_at(&endpoint, &["missing-fixture-package".to_owned()]),
    )
    .await??;
    let request = server.await??;
    assert!(request.starts_with("GET /rpc?v=5&type=info&"), "{request}");
    assert!(request.contains("missing-fixture-package"), "{request}");
    assert!(
        response.results.is_empty(),
        "empty successful info is absence, not a transport error"
    );
    eprintln!(
        "AUR empty-info completed request={}",
        request.lines().next().unwrap_or_default()
    );
    Ok(())
}
