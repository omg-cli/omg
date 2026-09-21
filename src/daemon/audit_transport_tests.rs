use super::*;
use crate::core::security::vulnerability::VulnerabilityScanner;
use crate::daemon::{protocol, server};
use crate::package_managers::mock::MockPackageManager;
use std::os::unix::fs::PermissionsExt;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::time::{Duration, timeout};

struct RunningTask(tokio::task::JoinHandle<anyhow::Result<()>>);
impl Drop for RunningTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn request(stream: &mut UnixStream, message: Request) -> anyhow::Result<Response> {
    timeout(Duration::from_secs(10), async {
        let frame = protocol::encode_frame(&message)?;
        stream
            .write_all(&u32::try_from(frame.len())?.to_be_bytes())
            .await?;
        stream.write_all(&frame).await?;
        let size = stream.read_u32().await? as usize;
        anyhow::ensure!(size < 1024 * 1024, "oversized test response");
        let mut response = vec![0; size];
        stream.read_exact(&mut response).await?;
        let (_, payload) = protocol::split_frame(&response)?;
        anyhow::Ok(bitcode::deserialize(payload)?)
    })
    .await?
}

async fn http_request(
    socket: &mut BufReader<tokio::net::TcpStream>,
) -> anyhow::Result<serde_json::Value> {
    let mut length = None;
    let mut consumed = 0;
    loop {
        let mut line = String::new();
        anyhow::ensure!(
            socket.read_line(&mut line).await? > 0,
            "truncated HTTP request"
        );
        consumed += line.len();
        anyhow::ensure!(consumed < 8192, "oversized HTTP headers");
        if line == "\r\n" {
            break;
        }
        if let Some((key, value)) = line.split_once(':')
            && key.eq_ignore_ascii_case("content-length")
        {
            length = Some(value.trim().parse::<usize>()?);
        }
    }
    let length = length.context("missing request content length")?;
    anyhow::ensure!(length < 8192, "oversized HTTP body");
    let mut body = vec![0; length];
    socket.read_exact(&mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

#[tokio::test]
#[serial_test::serial]
async fn real_server_fetches_scores_and_rejects_failed_scans_before_recovery() -> anyhow::Result<()>
{
    let temp = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let state_path = temp.path().join("mock_state_pacman.json");
    let package = format!("audit-wire-{}", uuid::Uuid::new_v4());
    let inventory = |version: &str| {
        serde_json::to_vec(&serde_json::json!({
            "installed": {package.clone(): version}, "available": {package.clone(): version}
        }))
    };
    std::fs::write(&state_path, inventory("1.0.0")?)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}/v1/query", listener.local_addr()?);
    let expected_package = package.clone();
    let mut http = RunningTask(tokio::spawn(async move {
        for (version, token, status, body) in [
            ("1.0.0", None, "200 OK", r#"{"next_page_token":"next"}"#),
            (
                "1.0.0",
                Some("next"),
                "200 OK",
                r#"{"vulns":[{"id":"high","summary":"vector","severity":[{"score":"4.0"},{"score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]},{"id":"medium","severity":[{"score":"6.9"}]},{"id":"unknown"}]}"#,
            ),
            ("2.0.0", None, "503 Service Unavailable", "{}"),
            (
                "2.0.0",
                None,
                "200 OK",
                r#"{"vulns":[{"id":"recovered","summary":"threshold","severity":[{"score":"7.0"}]}]}"#,
            ),
        ] {
            timeout(Duration::from_secs(15), async {
                let (socket, _) = listener.accept().await?;
                let mut socket = BufReader::new(socket);
                let body_value = http_request(&mut socket).await?;
                assert_eq!(body_value["package"]["name"], expected_package);
                assert_eq!(body_value["package"]["ecosystem"], "Arch Linux");
                assert_eq!(body_value["version"], version);
                assert_eq!(body_value.get("page_token").and_then(serde_json::Value::as_str), token);
                socket.get_mut().write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await?;
                anyhow::Ok(())
            }).await??;
        }
        anyhow::Ok(())
    }));
    let manager = Arc::new(MockPackageManager::new_in("arch", temp.path()));
    let mut state = temp_env::with_vars(
        [("OMG_DAEMON_DATA_DIR", Some(temp.path().as_os_str()))],
        || {
            crate::core::security::init_audit_logger()?;
            DaemonState::new_isolated(temp.path(), PackageIndex::empty(), manager)
        },
    )?;
    state.vulnerability_scanner = Arc::new(VulnerabilityScanner::with_osv_api_url(endpoint));
    let path = temp.path().join("audit.sock");
    let listener = UnixListener::bind(&path)?;
    let mut daemon = RunningTask(tokio::spawn(server::run(
        listener,
        Arc::new(state),
        path.clone(),
    )));
    let mut socket = UnixStream::connect(&path).await?;
    // Same real server dispatcher, scanner, HTTP client, pagination and scoring
    // as production. Only the installed inventory and remote server are fixtures.
    for id in [9300, 9301] {
        match request(&mut socket, Request::SecurityAudit { id }).await? {
            Response::Success {
                id: actual,
                result: ResponseResult::SecurityAudit(audit),
            } => {
                assert_eq!(actual, id);
                assert_eq!(audit.total_vulnerabilities, 3);
                assert_eq!(audit.high_severity, 1);
                assert_eq!(audit.vulnerabilities.len(), 1);
                assert_eq!(audit.vulnerabilities[0].0, package);
                let findings = &audit.vulnerabilities[0].1;
                assert_eq!(findings.len(), 3);
                assert_eq!(findings[0].id, "high");
                assert_eq!(findings[0].summary, "vector");
                assert_eq!(findings[0].score.as_deref(), Some("9.8"));
                assert_eq!(findings[1].id, "medium");
                assert_eq!(findings[1].score.as_deref(), Some("6.9"));
                assert_eq!(findings[2].id, "unknown");
                assert_eq!(findings[2].score, None);
            }
            other => anyhow::bail!("expected populated audit, got {other:?}"),
        }
    }
    let repaired = inventory("2.0.0")?;
    std::fs::write(&state_path, &repaired)?;
    match request(&mut socket, Request::SecurityAudit { id: 9302 }).await? {
        Response::Error { id, code, message } => {
            assert_eq!(id, 9302);
            assert_eq!(code, protocol::error_codes::INTERNAL_ERROR);
            assert_eq!(
                message,
                format!(
                    "Failed to scan package {package} for vulnerabilities: OSV vulnerability database returned an error status"
                )
            );
        }
        other @ Response::Success { .. } => {
            anyhow::bail!("failed fetch reported success: {other:?}")
        }
    }
    match request(&mut socket, Request::SecurityAudit { id: 9303 }).await? {
        Response::Success {
            id: 9303,
            result: ResponseResult::SecurityAudit(audit),
        } => {
            assert_eq!(audit.total_vulnerabilities, 1);
            assert_eq!(audit.high_severity, 1);
            assert_eq!(audit.vulnerabilities.len(), 1);
            assert_eq!(audit.vulnerabilities[0].0, package);
            assert_eq!(audit.vulnerabilities[0].1.len(), 1);
            assert_eq!(audit.vulnerabilities[0].1[0].id, "recovered");
            assert_eq!(audit.vulnerabilities[0].1[0].score.as_deref(), Some("7"));
        }
        other => anyhow::bail!("expected recovered audit, got {other:?}"),
    }
    timeout(Duration::from_secs(5), &mut http.0).await???;
    assert_eq!(std::fs::read(&state_path)?, repaired);
    drop(socket);
    nix::sys::signal::kill(nix::unistd::Pid::this(), nix::sys::signal::Signal::SIGTERM)?;
    timeout(Duration::from_secs(35), &mut daemon.0).await???;
    anyhow::ensure!(
        UnixStream::connect(&path).await.is_err(),
        "daemon survived shutdown"
    );
    let directory = temp.path().to_path_buf();
    temp.close()?;
    anyhow::ensure!(!directory.exists(), "fixture directory survived cleanup");
    Ok(())
}
