//! Unit-test HTTPS transport with real reqwest, certificate verification and fixed routes.
use anyhow::{Context as _, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, rustls};

pub(super) struct HttpsFixture {
    certificate: reqwest::Certificate,
    proxy: reqwest::Proxy,
    task: Option<JoinHandle<Result<Vec<String>>>>,
}

async fn headers(stream: &mut (impl AsyncRead + Unpin)) -> Result<String> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        anyhow::ensure!(bytes.len() < 8192, "fixture headers exceed their bound");
        bytes.push(stream.read_u8().await?);
    }
    Ok(String::from_utf8(bytes)?)
}

impl HttpsFixture {
    pub(super) async fn new(host: &str, routes: Vec<(String, Vec<u8>)>) -> Result<Self> {
        let signed = rcgen::generate_simple_self_signed(vec![host.to_owned()])?;
        let certificate = reqwest::Certificate::from_der(signed.cert.der())?;
        // Reqwest installs its normal provider; the fixture adds no crypto provider feature.
        let _client = reqwest::Client::builder().build()?;
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(signed.key_pair.serialize_der());
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![signed.cert.der().clone()], key.into())?;
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let proxy = reqwest::Proxy::all(format!("http://{}", listener.local_addr()?))?;
        let host = host.to_owned();
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for (path, body) in routes {
                let (mut stream, _) =
                    tokio::time::timeout(Duration::from_secs(5), listener.accept()).await??;
                let connect =
                    tokio::time::timeout(Duration::from_secs(5), headers(&mut stream)).await??;
                anyhow::ensure!(
                    connect.lines().next() == Some(format!("CONNECT {host}:443 HTTP/1.1").as_str()),
                    "unexpected proxy authority"
                );
                stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
                let mut stream =
                    tokio::time::timeout(Duration::from_secs(5), acceptor.accept(stream)).await??;
                let request =
                    tokio::time::timeout(Duration::from_secs(5), headers(&mut stream)).await??;
                let expected = format!("GET {path} HTTP/1.1");
                anyhow::ensure!(
                    request.lines().next() == Some(expected.as_str()),
                    "unexpected HTTPS fixture request: {request}"
                );
                requests.push(expected);
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await?;
                stream.write_all(&body).await?;
                stream.shutdown().await?;
            }
            Ok(requests)
        });
        Ok(Self {
            certificate,
            proxy,
            task: Some(task),
        })
    }

    pub(super) fn client(&self, trusted: bool) -> Result<reqwest::Client> {
        let builder = reqwest::Client::builder()
            .proxy(self.proxy.clone())
            .timeout(Duration::from_secs(5));
        Ok(if trusted {
            builder.add_root_certificate(self.certificate.clone())
        } else {
            builder
        }
        .build()?)
    }

    pub(super) async fn finish(mut self) -> Result<Vec<String>> {
        let task = self.task.as_mut().context("HTTPS fixture task is absent")?;
        let requests = tokio::time::timeout(Duration::from_secs(5), task).await???;
        self.task = None;
        Ok(requests)
    }
}

impl Drop for HttpsFixture {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

#[tokio::test]
async fn fixture_certificate_requires_explicit_client_trust() -> Result<()> {
    let fixture = HttpsFixture::new(
        "nodejs.org",
        vec![("/dist/index.json".into(), b"[]".to_vec())],
    )
    .await?;
    let result = fixture
        .client(false)?
        .get("https://nodejs.org/dist/index.json")
        .send()
        .await;
    assert!(
        result.is_err(),
        "an untrusted fixture certificate must be rejected"
    );
    assert!(
        fixture.finish().await.is_err(),
        "TLS server must observe the rejection"
    );
    Ok(())
}

/// Direct loopback HTTP is admitted only by the existing debug test-mode policy.
pub(super) struct HttpFixture {
    pub(super) address: std::net::SocketAddr,
    task: Option<JoinHandle<Result<Vec<String>>>>,
}

impl HttpFixture {
    pub(super) async fn new(routes: Vec<(String, Vec<u8>)>) -> Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for (path, body) in routes {
                let (mut stream, _) =
                    tokio::time::timeout(Duration::from_secs(5), listener.accept()).await??;
                let request =
                    tokio::time::timeout(Duration::from_secs(5), headers(&mut stream)).await??;
                let expected = format!("GET {path} HTTP/1.1");
                anyhow::ensure!(
                    request.lines().next() == Some(expected.as_str()),
                    "unexpected archive request: {request}"
                );
                anyhow::ensure!(
                    request
                        .lines()
                        .any(|line| line.eq_ignore_ascii_case(&format!("host: {address}"))),
                    "unexpected archive authority"
                );
                requests.push(expected);
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await?;
                stream.write_all(&body).await?;
                stream.shutdown().await?;
            }
            Ok(requests)
        });
        Ok(Self {
            address,
            task: Some(task),
        })
    }

    pub(super) async fn finish(mut self) -> Result<Vec<String>> {
        let task = self.task.as_mut().context("HTTP fixture task is absent")?;
        let requests = tokio::time::timeout(Duration::from_secs(5), task).await???;
        self.task = None;
        Ok(requests)
    }
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
