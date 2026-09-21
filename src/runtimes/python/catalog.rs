//! Validated standard CPython downloads from Astral's public release catalog.

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

#[derive(Debug)]
pub(super) struct Download {
    pub version: String,
    pub url: String,
    pub filename: String,
    pub checksum: String,
}

#[derive(Deserialize)]
struct Entry {
    major: u32,
    minor: u32,
    patch: u32,
    prerelease: String,
    build: String,
    url: String,
    sha256: String,
}

pub(super) async fn fetch(client: &reqwest::Client, target: &str) -> Result<Vec<Download>> {
    fetch_from(client, "https://raw.githubusercontent.com/astral-sh/uv/main/crates/uv-python/download-metadata.json", target).await
}

async fn fetch_from(client: &reqwest::Client, url: &str, target: &str) -> Result<Vec<Download>> {
    use crate::core::http::BoundedResponseExt;
    let value = client
        .get(url)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .context("Failed to fetch Python download catalog")?
        .error_for_status()
        .context("Python download catalog request failed")?
        .bounded_json()
        .await
        .context("Invalid Python download catalog response")?;
    parse_catalog(value, target)
}

fn parse_catalog(value: serde_json::Value, target: &str) -> Result<Vec<Download>> {
    let (arch, os, libc) = match target {
        "x86_64-unknown-linux-gnu" => ("x86_64", "linux", "gnu"),
        "aarch64-unknown-linux-gnu" => ("aarch64", "linux", "gnu"),
        "x86_64-apple-darwin" => ("x86_64", "darwin", "none"),
        "aarch64-apple-darwin" => ("aarch64", "darwin", "none"),
        _ => anyhow::bail!("Unsupported Python catalog target: {target}"),
    };
    let serde_json::Value::Object(entries) = value else {
        anyhow::bail!("Python catalog must be an object");
    };
    ensure!(
        !entries.contains_key("version"),
        "Unsupported Python catalog schema"
    );
    let mut downloads = Vec::new();
    for (key, value) in entries {
        if value["name"] != "cpython"
            || value["os"] != os
            || value["libc"] != libc
            || value["arch"]["family"] != arch
            || !value["arch"]["variant"].is_null()
            || !value["variant"].is_null()
        {
            continue;
        }
        let entry: Entry = serde_json::from_value(value)
            .with_context(|| format!("Invalid Python catalog entry: {key}"))?;
        let version = format!(
            "{}.{}.{}{}",
            entry.major, entry.minor, entry.patch, entry.prerelease
        );
        ensure!(
            super::PythonManager::is_python_version(&version),
            "Invalid Python catalog version: {version}"
        );
        ensure!(
            key == format!("cpython-{version}-{os}-{arch}-{libc}"),
            "Python catalog key disagrees with metadata: {key}"
        );
        ensure!(
            entry.build.len() == 8 && entry.build.bytes().all(|c| c.is_ascii_digit()),
            "Invalid Python catalog build: {key}"
        );
        ensure!(
            entry.sha256.len() == 64 && entry.sha256.bytes().all(|c| c.is_ascii_hexdigit()),
            "Invalid Python catalog SHA-256: {key}"
        );
        let url = reqwest::Url::parse(&entry.url).context("Invalid Python catalog URL")?;
        ensure!(
            url.scheme() == "https"
                && url.host_str() == Some("github.com")
                && url.username().is_empty()
                && url.password().is_none()
                && url.port().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "Untrusted Python catalog URL: {key}"
        );
        let prefix = format!(
            "/astral-sh/python-build-standalone/releases/download/{}/",
            entry.build
        );
        let encoded = url
            .path()
            .strip_prefix(&prefix)
            .context("Python catalog release URL disagrees with build or source")?;
        let filename = encoded.replace("%2B", "+").replace("%2b", "+");
        // Historical full distributions use a different archive layout. They
        // must not enter the install-only gzip extraction path.
        if filename.ends_with(".tar.zst") {
            continue;
        }
        let stem = format!("cpython-{version}+{}-{target}-install_only", entry.build);
        ensure!(
            filename == format!("{stem}.tar.gz") || filename == format!("{stem}_stripped.tar.gz"),
            "Python catalog archive disagrees with version or target: {key}"
        );
        downloads.push(Download {
            version,
            url: entry.url,
            filename,
            checksum: entry.sha256.to_ascii_lowercase(),
        });
    }
    ensure!(
        !downloads.is_empty(),
        "Python catalog contains no supported downloads for {target}"
    );
    downloads.sort_by(|a, b| super::PythonManager::python_version_cmp(&b.version, &a.version));
    Ok(downloads)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn entry(target: &str, version: &str) -> Value {
        let (arch, os, libc) = match target {
            "x86_64-unknown-linux-gnu" => ("x86_64", "linux", "gnu"),
            "aarch64-unknown-linux-gnu" => ("aarch64", "linux", "gnu"),
            "x86_64-apple-darwin" => ("x86_64", "darwin", "none"),
            "aarch64-apple-darwin" => ("aarch64", "darwin", "none"),
            _ => panic!("unsupported fixture target"),
        };
        let (base, _) = super::super::PythonManager::parse_python_version(version).unwrap();
        let numbers: Vec<u64> = base.split('.').map(|part| part.parse().unwrap()).collect();
        json!({
            "name": "cpython", "arch": {"family": arch, "variant": null},
            "os": os, "libc": libc, "major": numbers[0], "minor": numbers[1],
            "patch": numbers[2], "prerelease": &version[base.len()..], "variant": null,
            "build": "20260901", "sha256": "a".repeat(64),
            "url": format!("https://github.com/astral-sh/python-build-standalone/releases/download/20260901/cpython-{version}%2B20260901-{target}-install_only_stripped.tar.gz")
        })
    }

    fn catalog(entry: Value) -> Value {
        let version = format!(
            "{}.{}.{}{}",
            entry["major"],
            entry["minor"],
            entry["patch"],
            entry["prerelease"].as_str().unwrap()
        );
        let key = format!(
            "cpython-{version}-{}-{}-{}",
            entry["os"].as_str().unwrap(),
            entry["arch"]["family"].as_str().unwrap(),
            entry["libc"].as_str().unwrap()
        );
        let mut entries = serde_json::Map::new();
        entries.insert(key, entry);
        Value::Object(entries)
    }

    #[test]
    fn validates_all_supported_targets_and_download_fields() {
        for target in [
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
        ] {
            let downloads = parse_catalog(catalog(entry(target, "3.12.14")), target).unwrap();
            assert_eq!(downloads.len(), 1);
            assert_eq!(downloads[0].version, "3.12.14");
            assert_eq!(downloads[0].checksum, "a".repeat(64));
            assert_eq!(
                downloads[0].filename,
                format!("cpython-3.12.14+20260901-{target}-install_only_stripped.tar.gz")
            );
            assert!(
                downloads[0]
                    .url
                    .starts_with("https://github.com/astral-sh/")
            );
        }
    }

    #[test]
    fn rejects_inconsistent_or_unsafe_selected_downloads() {
        let target = "x86_64-unknown-linux-gnu";
        for (field, bad) in [
            ("sha256", json!("a".repeat(63))),
            ("sha256", json!(format!("{} trailing", "a".repeat(64)))),
            ("sha256", Value::Null),
            ("build", json!("../20260901")),
            ("prerelease", json!("t")),
            ("url", json!("https://evil.example/python.tar.gz")),
        ] {
            let mut selected = entry(target, "3.12.14");
            selected[field] = bad;
            assert!(
                parse_catalog(catalog(selected), target).is_err(),
                "accepted {field}"
            );
        }
        let original = entry(target, "3.12.14");
        let url = original["url"].as_str().unwrap();
        for bad in [
            url.replace("3.12.14", "3.12.13"),
            url.replace("x86_64", "aarch64"),
            url.replace("https:", "http:"),
            url.replace("github.com/", "github.com.evil.example/"),
            format!("{url}?token=x"),
            format!("{url}#fragment"),
        ] {
            let mut selected = original.clone();
            selected["url"] = json!(bad);
            assert!(parse_catalog(catalog(selected), target).is_err());
        }
    }

    #[test]
    fn rejects_unknown_schema_and_key_disagreement() {
        let target = "x86_64-unknown-linux-gnu";
        for value in [
            json!([]),
            json!({"version": 2}),
            json!({"incorrect-key": entry(target, "3.12.14")}),
        ] {
            assert!(parse_catalog(value, target).is_err());
        }
    }

    #[test]
    fn excludes_other_platforms_and_variants_and_orders_prereleases() {
        let target = "x86_64-unknown-linux-gnu";
        let mut entries = serde_json::Map::new();
        for version in ["3.9.20", "3.15.0rc2", "3.15.0", "3.15.0b4"] {
            entries.extend(catalog(entry(target, version)).as_object().unwrap().clone());
        }
        entries.extend(
            catalog(entry("aarch64-apple-darwin", "3.16.0"))
                .as_object()
                .unwrap()
                .clone(),
        );
        let mut threaded = entry(target, "3.17.0");
        threaded["variant"] = json!("freethreaded");
        entries.insert("unsupported-threaded".into(), threaded);
        let mut optimized = entry(target, "3.18.0");
        optimized["arch"]["variant"] = json!("v3");
        entries.insert("unsupported-optimized".into(), optimized);
        let downloads = parse_catalog(Value::Object(entries), target).unwrap();
        assert_eq!(
            downloads
                .iter()
                .map(|d| d.version.as_str())
                .collect::<Vec<_>>(),
            ["3.15.0", "3.15.0rc2", "3.15.0b4", "3.9.20"]
        );
    }

    #[test]
    fn supports_unstripped_gzip_but_excludes_legacy_full_archives() {
        let target = "x86_64-unknown-linux-gnu";
        let mut gzip = entry(target, "3.12.14");
        gzip["url"] = json!(gzip["url"].as_str().unwrap().replace("_stripped", ""));
        let mut entries = catalog(gzip).as_object().unwrap().clone();
        let mut legacy = entry(target, "3.8.2");
        legacy["url"] = json!(
            "https://github.com/astral-sh/python-build-standalone/releases/download/20260901/cpython-3.8.2-x86_64-unknown-linux-gnu-pgo-20260901T2243.tar.zst"
        );
        entries.extend(catalog(legacy).as_object().unwrap().clone());
        let downloads = parse_catalog(Value::Object(entries), target).unwrap();
        assert_eq!(downloads.len(), 1);
        assert_eq!(downloads[0].version, "3.12.14");
        assert!(downloads[0].filename.ends_with("-install_only.tar.gz"));
    }

    #[tokio::test]
    async fn http_fetch_preserves_errors_and_requires_valid_catalog() -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let target = "x86_64-unknown-linux-gnu";
        let valid = catalog(entry(target, "3.12.14")).to_string();
        let client = reqwest::Client::builder().no_proxy().build()?;
        for (status, body, succeeds) in [
            ("200 OK", valid.as_str(), true),
            ("403 Forbidden", valid.as_str(), false),
            ("500 Internal Server Error", valid.as_str(), false),
            ("200 OK", "broken-json", false),
            ("200 OK", "{}", false),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let url = format!("http://{}/catalog.json", listener.local_addr()?);
            let server = async {
                let (mut socket, _) = listener.accept().await?;
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    ensure!(request.len() < 8192, "oversized fixture request");
                    request.push(socket.read_u8().await?);
                }
                socket.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await?;
                Ok::<_, anyhow::Error>(())
            };
            let (result, served) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                tokio::join!(fetch_from(&client, &url, target), server)
            })
            .await?;
            served?;
            assert_eq!(result.is_ok(), succeeds, "{status}: {result:?}");
            if succeeds {
                assert_eq!(result?.first().unwrap().version, "3.12.14");
            }
        }
        Ok(())
    }
}
