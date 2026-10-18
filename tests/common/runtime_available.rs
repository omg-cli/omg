use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};

pub fn has_expected_row(stdout: &str, expected: &str) -> bool {
    stdout.lines().any(|line| {
        let mut columns = line.split_whitespace();
        columns.next() == Some("•") && columns.next() == Some(expected)
    })
}

pub fn has_catalog_row(stdout: &str, expected: &BTreeSet<String>) -> bool {
    expected
        .iter()
        .any(|version| has_expected_row(stdout, version))
}

#[derive(Clone, Copy)]
pub enum Catalog {
    Go,
    Rust,
    Ruby,
    Java,
    Bun,
    Deno,
}

impl Catalog {
    const fn endpoint(self) -> &'static str {
        match self {
            Self::Go => "https://go.dev/dl/?mode=json&include=all",
            Self::Rust => "https://static.rust-lang.org/dist/channel-rust-stable.toml",
            Self::Ruby => "https://api.github.com/repos/ruby/ruby-builder/releases?per_page=100",
            Self::Java => "https://api.adoptium.net/v3/info/available_releases",
            Self::Bun => "https://api.github.com/repos/oven-sh/bun/releases?per_page=20",
            Self::Deno => "https://api.github.com/repos/denoland/deno/releases?per_page=30",
        }
    }
}

pub fn expected_catalog_versions(catalog: Catalog) -> Result<BTreeSet<String>> {
    let metadata = tokio::runtime::Runtime::new()?.block_on(async {
        const LIMIT: usize = 4 * 1024 * 1024;
        let mut response = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("omg-integration-catalog-oracle")
            .build()?
            .get(catalog.endpoint())
            .send()
            .await?
            .error_for_status()?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                chunk.len() <= LIMIT - bytes.len(),
                "independent catalog exceeds 4 MiB"
            );
            bytes.extend_from_slice(&chunk);
        }
        String::from_utf8(bytes).context("independent catalog is not UTF-8")
    })?;
    catalog_versions(catalog, &metadata)
}

fn catalog_versions(catalog: Catalog, metadata: &str) -> Result<BTreeSet<String>> {
    let versions = match catalog {
        Catalog::Rust => {
            let manifest: toml::Value = toml::from_str(metadata)?;
            let version = manifest
                .get("pkg")
                .and_then(|value| value.get("rustc"))
                .and_then(|value| value.get("version"))
                .and_then(toml::Value::as_str)
                .and_then(|value| value.split_whitespace().next())
                .context("independent stable manifest lacks rustc version")?;
            semver::Version::parse(version)?;
            BTreeSet::from([version.to_owned()])
        }
        Catalog::Java => {
            let metadata: serde_json::Value = serde_json::from_str(metadata)?;
            metadata
                .get("available_releases")
                .and_then(serde_json::Value::as_array)
                .context("independent Java catalog lacks available_releases")?
                .iter()
                .map(|value| {
                    let version = value.as_u64().context("invalid Java feature number")?;
                    ensure!(version > 0, "invalid Java feature number");
                    Ok(version.to_string())
                })
                .collect::<Result<BTreeSet<_>>>()?
        }
        Catalog::Go | Catalog::Ruby | Catalog::Bun | Catalog::Deno => {
            let metadata: serde_json::Value = serde_json::from_str(metadata)?;
            let rows = metadata
                .as_array()
                .context("independent catalog is not an array")?;
            let field = if matches!(catalog, Catalog::Go) {
                "version"
            } else {
                "tag_name"
            };
            let mut versions = BTreeSet::new();
            for row in rows {
                let tag = row
                    .get(field)
                    .and_then(serde_json::Value::as_str)
                    .context("independent catalog row lacks a version tag")?;
                let version = match catalog {
                    Catalog::Go => Some(
                        tag.strip_prefix("go")
                            .context("invalid Go version prefix")?,
                    ),
                    Catalog::Ruby => tag.strip_prefix("ruby-").filter(|version| {
                        let parts: Vec<_> = version.split('.').collect();
                        parts.len() == 3
                            && parts.iter().all(|part| {
                                !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
                            })
                    }),
                    Catalog::Bun => tag.strip_prefix("bun-v").or_else(|| tag.strip_prefix('v')),
                    Catalog::Deno => tag.strip_prefix('v'),
                    Catalog::Rust | Catalog::Java => unreachable!(),
                };
                if let Some(version) = version {
                    ensure!(
                        !version.is_empty(),
                        "independent catalog has an empty version"
                    );
                    versions.insert(version.to_owned());
                }
            }
            versions
        }
    };
    ensure!(
        !versions.is_empty(),
        "independent catalog has no eligible versions"
    );
    Ok(versions)
}

pub fn node_alias_from_table(table: &str, lts_only: bool) -> anyhow::Result<String> {
    let mut lines = table.lines();
    let header: Vec<_> = lines.next().unwrap_or_default().split('\t').collect();
    let version_column = header
        .iter()
        .position(|value| *value == "version")
        .ok_or_else(|| anyhow::anyhow!("Node release table lacks version column"))?;
    let lts_column = header
        .iter()
        .position(|value| *value == "lts")
        .ok_or_else(|| anyhow::anyhow!("Node release table lacks lts column"))?;
    let mut candidates = Vec::new();
    for line in lines {
        let fields: Vec<_> = line.split('\t').collect();
        anyhow::ensure!(
            fields.len() == header.len(),
            "Malformed Node release row: {line}"
        );
        let version = semver::Version::parse(fields[version_column].trim_start_matches('v'))?;
        if version.pre.is_empty() && (!lts_only || !matches!(fields[lts_column], "" | "-")) {
            candidates.push(version);
        }
    }
    candidates
        .into_iter()
        .max()
        .map(|version| version.to_string())
        .ok_or_else(|| anyhow::anyhow!("No eligible Node release in independent table"))
}

pub fn expected_node_alias(lts_only: bool) -> String {
    // Separate upstream representation and ordering rule from OMG's JSON resolver.
    let table = tokio::runtime::Runtime::new().unwrap().block_on(async {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap()
            .get("https://nodejs.org/dist/index.tab")
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .text()
            .await
            .unwrap()
    });
    node_alias_from_table(&table, lts_only).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_rows_reject_headers_substrings_and_foreign_versions() {
        assert!(has_expected_row("  • 3.12.0 (stable)\n", "3.12.0"));
        assert!(has_expected_row("  • v26.9.0\n", "v26.9.0"));
        assert!(!has_expected_row("  • v26.9.0\n", "26.9.0"));
        assert!(!has_expected_row("", "3.12.0"));
        assert!(!has_expected_row(
            "Available remote versions: 3.12.0\n",
            "3.12.0"
        ));
        assert!(!has_expected_row("  • 3.12.0-extra\n", "3.12.0"));
        assert!(!has_expected_row("  • 13.12.0\n", "3.12.0"));
        assert!(!has_expected_row("  • 3.12\n", "3.12.0"));
        assert!(!has_expected_row("3.12.0\n", "3.12.0"));
        assert!(!has_catalog_row(
            "  • 99.0.0\n",
            &BTreeSet::from(["3.12.0".to_owned()])
        ));
        assert!(!has_catalog_row("  • 3.12.0\n", &BTreeSet::new()));
    }

    #[test]
    fn independent_metadata_yields_literal_complete_versions() {
        for (catalog, metadata, expected) in [
            (Catalog::Go, r#"[{"version":"go1.26.2"}]"#, "1.26.2"),
            (
                Catalog::Rust,
                "[pkg.rustc]\nversion = '1.95.0 (abc 2026-04-14)'\n",
                "1.95.0",
            ),
            (
                Catalog::Ruby,
                r#"[{"tag_name":"jruby-9.4.0"},{"tag_name":"ruby-3.4.5"}]"#,
                "3.4.5",
            ),
            (Catalog::Java, r#"{"available_releases":[25]}"#, "25"),
            (Catalog::Bun, r#"[{"tag_name":"bun-v1.3.1"}]"#, "1.3.1"),
            (Catalog::Deno, r#"[{"tag_name":"v2.5.0"}]"#, "2.5.0"),
        ] {
            assert_eq!(
                catalog_versions(catalog, metadata).unwrap(),
                BTreeSet::from([expected.to_owned()])
            );
        }
    }

    #[test]
    fn missing_or_empty_catalogs_are_setup_errors() {
        for (catalog, metadata) in [
            (Catalog::Go, "[]"),
            (Catalog::Go, r#"[{"version":"1.26.2"}]"#),
            (Catalog::Rust, "[pkg.rustc]\n"),
            (Catalog::Ruby, r#"[{"tag_name":"toolcache"}]"#),
            (Catalog::Java, r#"{"available_releases":[]}"#),
            (Catalog::Java, r#"{"available_releases":["25"]}"#),
            (Catalog::Bun, r#"[{"tag_name":"canary"}]"#),
            (Catalog::Deno, r#"[{"tag_name":"v"}]"#),
        ] {
            assert!(catalog_versions(catalog, metadata).is_err());
        }
    }
}
