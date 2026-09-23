//! Shared HTTP client utilities
//!
//! Centralizes reqwest client configuration for connection pooling
//! and consistent timeouts across the codebase.

use std::sync::LazyLock;
use std::time::Duration;

use reqwest::{Client, Url, redirect};

const MAX_REDIRECTS: usize = 10;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);
const DOWNLOAD_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DOWNLOAD_READ_TIMEOUT: Duration = Duration::from_mins(1);

static SHARED_CLIENT: LazyLock<Client> = LazyLock::new(|| {
    build_client(
        Some(DEFAULT_TIMEOUT),
        DEFAULT_CONNECT_TIMEOUT,
        DEFAULT_READ_TIMEOUT,
    )
});

/// Download client with extended timeouts and read timeout for stall detection.
///
/// Uses `.read_timeout()` to detect stalled downloads - this timeout resets after
/// each successful read, unlike `.timeout()` which covers the entire request.
static DOWNLOAD_CLIENT: LazyLock<Client> =
    LazyLock::new(|| build_client(None, DOWNLOAD_CONNECT_TIMEOUT, DOWNLOAD_READ_TIMEOUT));

fn validate_redirect(previous: &[Url], next: &Url) -> Result<(), &'static str> {
    if previous.len() > MAX_REDIRECTS {
        return Err("too many redirects");
    }
    if previous
        .last()
        .is_some_and(|url| url.scheme() == "https" && next.scheme() != "https")
    {
        return Err("refusing HTTPS-to-HTTP redirect");
    }
    if is_private_or_local_host(next.host_str()) {
        return Err("refusing redirect to a private or local address");
    }
    Ok(())
}

/// Whether a URL host refers to a loopback, private, or link-local target.
///
/// Hostnames that are not IP literals are treated as public; IP literals
/// inside RFC 1918/RFC 4193 space, loopback, link-local, unspecified, and
/// IPv4-mapped private ranges are all local. `None` (no host, e.g. malformed
/// authority) counts as local so callers fail closed.
#[must_use]
pub fn is_private_or_local_host(host: Option<&str>) -> bool {
    let Some(host) = host else {
        return true;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") || host.to_ascii_lowercase().ends_with(".localhost") {
        return true;
    }
    let Ok(ip) = host.parse::<std::net::IpAddr>() else {
        return false;
    };
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
        }
        std::net::IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return mapped.is_loopback()
                    || mapped.is_private()
                    || mapped.is_link_local()
                    || mapped.is_unspecified();
            }
            let first = u16::from_be_bytes([v6.octets()[0], v6.octets()[1]]);
            v6.is_loopback()
                || v6.is_unspecified()
                || (first & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (first & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
}

/// Require a globally routable address after DNS resolution, not just a
/// public-looking hostname. Used by downloads of metadata-selected URLs.
#[must_use]
pub(crate) fn is_public_address(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(ip) => {
            let [a, b, _, _] = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_unspecified()
                && !ip.is_documentation()
                && !ip.is_broadcast()
                && a != 0
                && a < 224
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 192 && b == 0)
                && !(a == 198 && (18..=19).contains(&b))
        }
        std::net::IpAddr::V6(ip) => {
            let segments = ip.segments();
            segments[0] & 0xe000 == 0x2000
                && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
                && !(segments[0] == 0x2001 && segments[1] == 0)
                && segments[0] != 0x2002
        }
    }
}

fn validate_resolved_addresses(
    addresses: &[std::net::SocketAddr],
    loopback_fixture: bool,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !addresses.is_empty()
            && addresses.iter().all(|address| {
                is_public_address(address.ip()) || (loopback_fixture && address.ip().is_loopback())
            }),
        "Download resolves to a non-public address"
    );
    Ok(())
}

/// Connect to a metadata-selected URL only after resolving and pinning every
/// address on every redirect. The caller's ordinary client cannot enforce
/// this per-request DNS policy, so use a fresh, proxy-free client per hop.
pub(crate) async fn fetch_public_download(
    raw: &str,
    user_agent: &str,
) -> anyhow::Result<reqwest::Response> {
    fetch_public_download_with_timeout(raw, user_agent, None).await
}

pub(crate) async fn fetch_public_download_with_timeout(
    raw: &str,
    user_agent: &str,
    total_timeout: Option<Duration>,
) -> anyhow::Result<reqwest::Response> {
    let mut url = Url::parse(raw).map_err(|_| anyhow::anyhow!("Invalid download URL"))?;
    for hop in 0..=MAX_REDIRECTS {
        validate_download_url(url.as_str())?;
        anyhow::ensure!(
            url.username().is_empty() && url.password().is_none(),
            "Download URL must not contain credentials"
        );
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("Download URL has no host"))?
            .to_owned();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| anyhow::anyhow!("Download URL has no port"))?;
        let addresses: Vec<_> = tokio::time::timeout(
            DOWNLOAD_CONNECT_TIMEOUT,
            tokio::net::lookup_host((host.as_str(), port)),
        )
        .await??
        .collect();
        let loopback_fixture = url.scheme() == "http"
            && is_loopback_host(url.host_str())
            && crate::core::paths::test_mode();
        validate_resolved_addresses(&addresses, loopback_fixture)?;
        let mut builder = Client::builder()
            .no_proxy()
            .redirect(redirect::Policy::none())
            .connect_timeout(DOWNLOAD_CONNECT_TIMEOUT)
            .read_timeout(DOWNLOAD_READ_TIMEOUT)
            .resolve_to_addrs(&host, &addresses);
        if let Some(timeout) = total_timeout {
            builder = builder.timeout(timeout);
        }
        let client = builder.build()?;
        let response = client
            .get(url.clone())
            .header(reqwest::header::USER_AGENT, user_agent)
            .send()
            .await?;
        if !response.status().is_redirection() {
            return Ok(response);
        }
        anyhow::ensure!(hop < MAX_REDIRECTS, "Too many download redirects");
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .ok_or_else(|| anyhow::anyhow!("Download redirect has no location"))?
            .to_str()?;
        let next = url.join(location)?;
        anyhow::ensure!(
            url.scheme() != "https" || next.scheme() == "https",
            "Refusing HTTPS-to-HTTP download redirect"
        );
        url = next;
    }
    unreachable!("bounded redirect loop returns or errors")
}

/// Pin a downloader entry-point URL: HTTPS only, on a routable host.
///
/// Vendor metadata (release manifests, channel manifests, package indexes)
/// supplies these URLs, so a hostile or tampered metadata document must not
/// be able to aim downloads at plain HTTP or at local/private-network
/// services. Plain-HTTP loopback targets are tolerated only in hermetic
/// test mode (debug builds with `OMG_TEST_MODE=1`), where local fixture
/// servers stand in for vendors; release binaries always require TLS.
///
/// # Errors
///
/// Returns an error for unparseable URLs, non-HTTPS schemes (outside the
/// loopback test-mode carve-out), and private or local hosts.
pub fn validate_download_url(raw: &str) -> anyhow::Result<()> {
    let url = Url::parse(raw).map_err(|_| anyhow::anyhow!("Invalid download URL"))?;
    let local = is_private_or_local_host(url.host_str());
    if url.scheme() != "https" {
        // Plain HTTP is only ever tolerated for loopback targets under
        // hermetic test mode, where local fixture servers stand in for
        // vendors; every other local/private target is rejected outright.
        let loopback_fixture = url.scheme() == "http"
            && is_loopback_host(url.host_str())
            && crate::core::paths::test_mode();
        if !loopback_fixture {
            anyhow::bail!("Download must use HTTPS, refusing {}", redact_url(raw));
        }
        return Ok(());
    }
    if local {
        anyhow::bail!(
            "Download must not target a private or local address, refusing {}",
            redact_url(raw)
        );
    }
    Ok(())
}

/// Whether a URL host is a loopback target (loopback IP literal or a
/// localhost name).
fn is_loopback_host(host: Option<&str>) -> bool {
    let Some(host) = host else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") || host.to_ascii_lowercase().ends_with(".localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

fn redirect_policy() -> redirect::Policy {
    redirect::Policy::custom(
        |attempt| match validate_redirect(attempt.previous(), attempt.url()) {
            Ok(()) => attempt.follow(),
            Err(reason) => attempt.error(reason),
        },
    )
}

/// Build HTTP client with standard configuration.
///
/// This function uses `.expect()` because:
/// 1. All configuration values are static and known-valid
/// 2. Building can only fail with TLS backend issues (extremely rare)
/// 3. If this fails, the application cannot function at all (no network = no package manager)
/// 4. Panicking early on startup is better than propagating errors through the entire app
///
/// # Panics
/// Panics if the HTTP client cannot be built, which should only happen with:
/// - Missing TLS certificates (system misconfiguration)
/// - Incompatible TLS backend (build issue)
#[expect(clippy::expect_used)] // System misconfiguration or build issue; panics documented above
fn build_client(
    timeout: Option<Duration>,
    connect_timeout: Duration,
    read_timeout: Duration,
) -> Client {
    let mut builder = Client::builder()
        .user_agent("omg-package-manager")
        .redirect(redirect_policy())
        .connect_timeout(connect_timeout)
        .read_timeout(read_timeout)
        .pool_max_idle_per_host(32)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_nodelay(true);
    if let Some(timeout) = timeout {
        builder = builder.timeout(timeout);
    }
    builder
        .build()
        .expect("Failed to build HTTP client - check TLS configuration")
}

/// Calculate bounded exponential backoff for a zero-based retry number.
///
/// The exponent is capped so attacker-influenced retry counters cannot overflow
/// or create effectively unbounded sleeps.
#[must_use]
pub fn retry_backoff(initial: Duration, retry_number: u32) -> Duration {
    initial.saturating_mul(1_u32 << retry_number.min(20))
}

/// Whether an HTTP status represents a transient server-side failure.
#[must_use]
pub fn is_retryable_status(status: reqwest::StatusCode) -> bool {
    status.is_server_error()
        || status == reqwest::StatusCode::REQUEST_TIMEOUT
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
}

/// Whether a request transport failure is safe to retry.
#[must_use]
pub fn is_retryable_error(error: &reqwest::Error) -> bool {
    error.is_timeout() || error.is_connect() || error.is_body()
}

/// Render a remote URL without credentials, query parameters, or fragments.
///
/// Error messages and logs must not echo URL-embedded tokens. Invalid URLs are
/// represented by a fixed placeholder rather than reflecting unparsed input.
#[must_use]
pub fn redact_url(raw: &str) -> String {
    let Ok(mut url) = Url::parse(raw) else {
        return "<invalid URL>".to_string();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

/// Shared default HTTP client.
#[must_use]
#[inline]
pub fn shared_client() -> &'static Client {
    &SHARED_CLIENT
}

/// Shared HTTP client with extended timeouts for large downloads.
#[must_use]
#[inline]
pub fn download_client() -> &'static Client {
    &DOWNLOAD_CLIENT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolved_download_addresses_must_all_be_public() {
        use std::net::SocketAddr;

        let public: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let private: SocketAddr = "10.0.0.7:443".parse().unwrap();
        let loopback: SocketAddr = "127.0.0.1:443".parse().unwrap();
        assert!(validate_resolved_addresses(&[public], false).is_ok());
        assert!(validate_resolved_addresses(&[public, private], false).is_err());
        assert!(validate_resolved_addresses(&[loopback], false).is_err());
        assert!(validate_resolved_addresses(&[loopback], true).is_ok());
        assert!(validate_resolved_addresses(&[], false).is_err());
    }

    #[tokio::test]
    async fn download_client_allows_long_transfers_that_keep_progressing() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n")
                .await
                .unwrap();
            for byte in b"progress" {
                stream.write_all(&[*byte]).await.unwrap();
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });

        // Read timeout must stay well above the 50ms inter-byte gap so CI
        // scheduling jitter cannot look like a stalled download.
        let client = build_client(None, Duration::from_secs(1), Duration::from_secs(5));
        let body = client
            .get(format!("http://{address}"))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(&body[..], b"progress");
        server.await.unwrap();
    }

    #[test]
    fn retry_policy_is_bounded_and_rejects_client_errors() {
        assert_eq!(
            retry_backoff(Duration::from_millis(100), 0),
            Duration::from_millis(100)
        );
        assert_eq!(
            retry_backoff(Duration::from_millis(100), 2),
            Duration::from_millis(400)
        );
        assert_eq!(
            retry_backoff(Duration::MAX, u32::MAX),
            Duration::MAX,
            "backoff arithmetic must saturate"
        );
        assert!(is_retryable_status(reqwest::StatusCode::BAD_GATEWAY));
        assert!(is_retryable_status(reqwest::StatusCode::REQUEST_TIMEOUT));
        assert!(is_retryable_status(reqwest::StatusCode::TOO_MANY_REQUESTS));
        assert!(!is_retryable_status(reqwest::StatusCode::NOT_FOUND));
    }

    #[test]
    fn private_and_local_hosts_are_never_redirect_targets() {
        for host in [
            "https://127.0.0.1/steal",
            "https://10.1.2.3/steal",
            "https://192.168.0.10/steal",
            "https://172.16.5.5/steal",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/steal",
            "https://[fe80::1]/steal",
            "https://[fc00::1]/steal",
            "https://[::ffff:10.0.0.1]/steal",
            "https://localhost/steal",
            "https://metadata.localhost/steal",
        ] {
            let next = Url::parse(host).unwrap();
            assert_eq!(
                validate_redirect(std::slice::from_ref(&next), &next),
                Err("refusing redirect to a private or local address"),
                "{host}"
            );
        }
    }

    #[test]
    fn private_host_detection_matches_ip_literals_and_localhost_names() {
        for host in [
            "127.0.0.1",
            "10.0.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:192.168.1.1",
            "localhost",
            "foo.localhost",
        ] {
            assert!(is_private_or_local_host(Some(host)), "{host}");
        }
        for host in [
            "example.com",
            "static.rust-lang.org",
            "8.8.8.8",
            "2606:4700::1111",
        ] {
            assert!(!is_private_or_local_host(Some(host)), "{host}");
        }
        assert!(is_private_or_local_host(None), "missing host fails closed");
    }

    #[test]
    fn download_urls_pin_https_on_routable_hosts() {
        assert!(validate_download_url("https://static.rust-lang.org/dist/x.tar.xz").is_ok());
        for url in [
            "http://static.rust-lang.org/dist/x.tar.xz",
            "http://192.168.1.5/evil.tar.xz",
            "https://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1/evil.tar.xz",
            "ftp://static.rust-lang.org/dist/x.tar.xz",
        ] {
            let error = validate_download_url(url).expect_err(url);
            let message = error.to_string();
            assert!(
                message.contains("HTTPS") || message.contains("private or local"),
                "{url}: {message}"
            );
        }
    }

    #[test]
    fn redirect_validation_rejects_downgrades_and_excessive_hops() {
        let https = Url::parse("https://example.com/start").unwrap();
        let next_http = Url::parse("http://example.com/plaintext").unwrap();
        let next_https = Url::parse("https://example.net/secure").unwrap();
        let initial_http = Url::parse("http://mirror.example/start").unwrap();

        assert_eq!(
            validate_redirect(std::slice::from_ref(&https), &next_http),
            Err("refusing HTTPS-to-HTTP redirect")
        );
        assert_eq!(validate_redirect(&[https], &next_https), Ok(()));
        assert_eq!(validate_redirect(&[initial_http], &next_http), Ok(()));

        let ten_previous = (0..10)
            .map(|index| Url::parse(&format!("https://example.com/{index}")).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(validate_redirect(&ten_previous, &next_https), Ok(()));

        let mut eleven_previous = ten_previous;
        eleven_previous.push(next_https.clone());
        assert_eq!(
            validate_redirect(&eleven_previous, &next_https),
            Err("too many redirects")
        );
    }

    #[test]
    fn redacted_urls_never_reflect_credentials_or_query_secrets() {
        let redacted = redact_url("https://user:password@example.com/file?token=secret#fragment");
        assert_eq!(redacted, "https://example.com/file");
        for secret in ["user", "password", "token", "secret", "fragment"] {
            assert!(!redacted.contains(secret));
        }
        assert_eq!(redact_url("not a URL with secret"), "<invalid URL>");
    }
}

/// Metadata is small control-plane input, never an unbounded artifact stream.
pub(crate) trait BoundedResponseExt {
    async fn bounded_json<T: serde::de::DeserializeOwned>(self) -> anyhow::Result<T>;
    async fn bounded_text(self) -> anyhow::Result<String>;
}

async fn bounded_metadata_body(mut response: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    const LIMIT: usize = 16 * 1024 * 1024;
    tokio::time::timeout(Duration::from_secs(30), async move {
        anyhow::ensure!(
            response
                .content_length()
                .is_none_or(|length| length <= LIMIT as u64),
            "Metadata exceeds 16 MiB limit"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            anyhow::ensure!(
                chunk.len() <= LIMIT - bytes.len(),
                "Metadata exceeds 16 MiB limit"
            );
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    })
    .await
    .map_err(|_| anyhow::anyhow!("Metadata response exceeded 30 second deadline"))?
}

impl BoundedResponseExt for reqwest::Response {
    async fn bounded_json<T: serde::de::DeserializeOwned>(self) -> anyhow::Result<T> {
        Ok(serde_json::from_slice(&bounded_metadata_body(self).await?)?)
    }
    async fn bounded_text(self) -> anyhow::Result<String> {
        Ok(String::from_utf8(bounded_metadata_body(self).await?)?)
    }
}

#[cfg(test)]
mod metadata_limit_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn response(bytes: Vec<u8>) -> reqwest::Response {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 2048];
            let _ = stream.read(&mut request).await.unwrap();
            // The client may correctly reject before the entire body is sent.
            let _result = stream.write_all(&bytes).await;
        });
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(format!("http://{address}"))
            .send()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn bounded_metadata_checks_declared_and_streamed_lengths() {
        let valid = response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec()).await;
        assert_eq!(
            valid.bounded_json::<serde_json::Value>().await.unwrap(),
            serde_json::json!({})
        );
        let oversized =
            response(b"HTTP/1.1 200 OK\r\nContent-Length: 16777217\r\n\r\n".to_vec()).await;
        assert!(
            oversized
                .bounded_text()
                .await
                .unwrap_err()
                .to_string()
                .contains("16 MiB")
        );
        let mut streamed = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
        streamed.extend(std::iter::repeat_n(b'x', 16 * 1024 * 1024 + 1));
        assert!(
            response(streamed)
                .await
                .bounded_text()
                .await
                .unwrap_err()
                .to_string()
                .contains("16 MiB")
        );
    }
}
