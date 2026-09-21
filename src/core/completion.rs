//! Intelligent completions with fuzzy matching and context awareness.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use jiff::Timestamp;
use nucleo_matcher::{
    Config, Matcher, Utf32String,
    pattern::{CaseMatching, Normalization, Pattern},
};

use crate::core::paths;

const MAX_AUR_COMPLETION_COMPRESSED_BYTES: usize = 16 * 1024 * 1024;
const MAX_AUR_COMPLETION_DECOMPRESSED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_AUR_COMPLETION_PACKAGES: usize = 500_000;

/// File-backed completion cache (single atomically-replaced JSON document).
///
/// Replaces the former redb table: the cache holds two keys, which does not
/// justify an embedded transactional database.
#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedCompletionCache {
    format_version: u32,
    entries: std::collections::HashMap<String, String>,
}

impl PersistedCompletionCache {
    const FORMAT_VERSION: u32 = 1;

    fn path() -> PathBuf {
        paths::data_dir().join("completion-cache.json")
    }

    fn load() -> Self {
        std::fs::read_to_string(Self::path())
            .map_or_else(|_| Self::default(), |content| Self::decode(&content))
    }

    fn decode(content: &str) -> Self {
        match serde_json::from_str::<Self>(content) {
            Ok(cache) if cache.format_version == Self::FORMAT_VERSION => cache,
            Ok(cache) => {
                tracing::debug!(
                    "Discarding completion cache format version {} (expected {})",
                    cache.format_version,
                    Self::FORMAT_VERSION
                );
                Self::default()
            }
            Err(error) => {
                tracing::debug!("Discarding malformed completion cache: {error}");
                Self::default()
            }
        }
    }

    fn save(&self) -> Result<()> {
        let content = serde_json::to_vec(self).context("Failed to serialize completion cache")?;
        paths::ensure_data_dir().context("Failed to create completion cache directory")?;
        crate::core::safe_ops::atomic_write_file_sync(Self::path(), content)
            .with_context(|| format!("Failed to write {}", Self::path().display()))
    }
}

impl Default for PersistedCompletionCache {
    fn default() -> Self {
        Self {
            format_version: Self::FORMAT_VERSION,
            entries: std::collections::HashMap::new(),
        }
    }
}

/// Intelligent completion engine
#[derive(Default)]
pub struct CompletionEngine;

impl CompletionEngine {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Rank candidates using the shared fuzzy matcher.
    #[must_use]
    pub fn fuzzy_match(&self, pattern: &str, mut candidates: Vec<String>) -> Vec<String> {
        Self::fuzzy_indices(pattern, &candidates, candidates.len())
            .into_iter()
            .map(|index| std::mem::take(&mut candidates[index]))
            .collect()
    }

    pub(crate) fn fuzzy_indices(pattern: &str, candidates: &[String], limit: usize) -> Vec<usize> {
        if pattern.is_empty() {
            return (0..candidates.len()).take(limit).collect();
        }

        let mut matcher = Matcher::new(Config::DEFAULT);
        let pat = Pattern::parse(pattern, CaseMatching::Ignore, Normalization::Smart);

        let mut matches: Vec<(usize, u32)> = candidates
            .iter()
            .enumerate()
            .filter_map(|(index, candidate)| {
                let haystack = Utf32String::from(candidate.as_str());
                let score = pat.score(haystack.slice(..), &mut matcher)?;
                Some((index, score))
            })
            .collect();

        let pattern_lower = pattern.to_ascii_lowercase();
        matches.sort_by(|a, b| {
            let a_prefix = candidates[a.0]
                .to_ascii_lowercase()
                .starts_with(&pattern_lower);
            let b_prefix = candidates[b.0]
                .to_ascii_lowercase()
                .starts_with(&pattern_lower);
            b_prefix.cmp(&a_prefix).then_with(|| {
                if a_prefix && b_prefix {
                    candidates[a.0]
                        .len()
                        .cmp(&candidates[b.0].len())
                        .then_with(|| candidates[a.0].cmp(&candidates[b.0]))
                } else {
                    b.1.cmp(&a.1)
                        .then_with(|| candidates[a.0].len().cmp(&candidates[b.0].len()))
                        .then_with(|| candidates[a.0].cmp(&candidates[b.0]))
                }
            })
        });

        matches
            .into_iter()
            .take(limit)
            .map(|(index, _)| index)
            .collect()
    }

    /// Probe context (package.json, .nvmrc, etc.) to prioritize versions
    pub fn probe_context(&self, runtime: &str) -> Result<Vec<String>> {
        let current_dir = std::env::current_dir().context("Failed to get current directory")?;
        Self::probe_context_from(&current_dir, runtime)
    }

    fn probe_context_from(start: &Path, runtime: &str) -> Result<Vec<String>> {
        let mut suggestions = Vec::new();
        let mut dir = Some(start);

        while let Some(path) = dir {
            let suggestion_checkpoint = suggestions.len();
            let probe_result = (|| -> Result<()> {
                match runtime {
                    "node" => {
                        let pkg_json = path.join("package.json");
                        if let Some(content) = read_optional_file(&pkg_json)? {
                            let value: serde_json::Value = serde_json::from_str(&content)
                                .with_context(|| {
                                    format!("Failed to parse {}", pkg_json.display())
                                })?;
                            if let Some(s) = value
                                .get("engines")
                                .and_then(|engines| engines.get("node"))
                                .and_then(serde_json::Value::as_str)
                            {
                                suggestions.push(s.to_string());
                            }
                        }
                        let nvmrc = path.join(".nvmrc");
                        if let Some(content) = read_optional_file(&nvmrc)? {
                            suggestions.push(content.trim().to_string());
                        }
                    }
                    "python" => {
                        let py_version = path.join(".python-version");
                        if let Some(content) = read_optional_file(&py_version)? {
                            suggestions.push(content.trim().to_string());
                        }
                    }
                    "rust" => {
                        let toolchain = path.join("rust-toolchain");
                        if let Some(content) = read_optional_file(&toolchain)? {
                            suggestions.push(content.trim().to_string());
                        } else {
                            let toolchain_toml = path.join("rust-toolchain.toml");
                            if let Some(content) = read_optional_file(&toolchain_toml)?
                                && content.contains("channel = \"")
                                && let Some(v) = content
                                    .split("channel = \"")
                                    .nth(1)
                                    .and_then(|s| s.split('"').next())
                            {
                                suggestions.push(v.to_string());
                            }
                        }
                    }
                    _ => {}
                }
                Ok(())
            })();

            if let Err(error) = probe_result {
                suggestions.truncate(suggestion_checkpoint);
                if path == start {
                    return Err(error);
                }
                tracing::warn!(
                    "Ignoring invalid ancestor runtime completion metadata in {}: {error:#}",
                    path.display()
                );
            }
            if !suggestions.is_empty() {
                break;
            }
            dir = path.parent();
        }

        Ok(suggestions)
    }

    /// Get AUR package names from cache or refresh if needed
    pub async fn get_aur_package_names(&self) -> Result<Vec<String>> {
        let cache = PersistedCompletionCache::load();
        if let Some(last_refresh) = cache
            .entries
            .get("aur_last_refresh")
            .and_then(|value| value.parse::<Timestamp>().ok())
        {
            let hours_since = Timestamp::now().as_second() - last_refresh.as_second();
            if hours_since < 24 * 3600
                && let Some(data) = cache.entries.get("aur_packages")
            {
                return Ok(data.split(',').map(String::from).collect());
            }
        }

        // Refresh cache
        let names = self.fetch_aur_names().await?;
        let mut cache = PersistedCompletionCache::load();
        cache
            .entries
            .insert("aur_packages".to_string(), names.join(","));
        cache
            .entries
            .insert("aur_last_refresh".to_string(), Timestamp::now().to_string());
        if let Err(error) = cache.save() {
            tracing::warn!("AUR completion cache could not be persisted: {error:#}");
        }

        Ok(names)
    }

    async fn fetch_aur_names(&self) -> Result<Vec<String>> {
        // Use the AUR RPC to get all package names
        let url = "https://aur.archlinux.org/packages.gz";
        // Shared client: bounded timeouts (a bare reqwest::get has none and
        // hung shell completions when aur.archlinux.org black-holed).
        let response = crate::core::http::shared_client()
            .get(url)
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await?
            .error_for_status()?;
        if response.content_length().is_some_and(|length| {
            length > u64::try_from(MAX_AUR_COMPLETION_COMPRESSED_BYTES).unwrap_or(u64::MAX)
        }) {
            anyhow::bail!("AUR completion response exceeds compressed-size limit");
        }

        use futures::StreamExt as _;
        let mut compressed = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("Failed to read AUR completion response")?;
            if compressed.len().saturating_add(chunk.len()) > MAX_AUR_COMPLETION_COMPRESSED_BYTES {
                anyhow::bail!("AUR completion response exceeds compressed-size limit");
            }
            compressed.extend_from_slice(&chunk);
        }

        decode_aur_names(&compressed, MAX_AUR_COMPLETION_DECOMPRESSED_BYTES)
    }
}

fn decode_aur_names(compressed: &[u8], decompressed_limit: u64) -> Result<Vec<String>> {
    use std::io::Read as _;

    let decoder = flate2::read::GzDecoder::new(compressed);
    let mut bounded = crate::runtimes::common::BudgetedReader::new(decoder, decompressed_limit);
    let mut text = String::new();
    bounded
        .read_to_string(&mut text)
        .context("AUR completion index exceeds decompressed-size limit")?;

    let mut names = Vec::new();
    for name in text.lines().filter(|name| !name.is_empty()) {
        anyhow::ensure!(
            names.len() < MAX_AUR_COMPLETION_PACKAGES,
            "AUR completion index exceeds package-count limit"
        );
        crate::core::security::validate_package_name(name)
            .context("AUR completion index contains an invalid package name")?;
        names.push(name.to_string());
    }
    Ok(names)
}

fn read_optional_file(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(content) => Ok(Some(content)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("Failed to read {}", path.display())),
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used)] // Idiomatic in tests: panics on failure with clear error context
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn gzip_text(text: &[u8]) -> Vec<u8> {
        use std::io::Write as _;

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(text).expect("compress fixture");
        encoder.finish().expect("finish fixture")
    }

    #[test]
    fn completion_cache_rejects_unknown_format_versions() {
        let decoded = PersistedCompletionCache::decode(
            r#"{"format_version":99,"entries":{"aur_packages":"unsafe"}}"#,
        );
        assert_eq!(
            decoded.format_version,
            PersistedCompletionCache::FORMAT_VERSION
        );
        assert!(decoded.entries.is_empty());
    }

    #[test]
    fn aur_completion_index_is_bounded_and_validated() {
        let valid = gzip_text(b"package-one\npackage-two\n");
        assert_eq!(
            decode_aur_names(&valid, 1024).expect("valid package index"),
            vec!["package-one", "package-two"]
        );

        let bomb = gzip_text(&vec![b'a'; 64 * 1024]);
        let error = decode_aur_names(&bomb, 1024).expect_err("inflation must be bounded");
        assert!(error.to_string().contains("decompressed-size limit"));

        let invalid = gzip_text(b"valid\n../escape\n");
        let error = decode_aur_names(&invalid, 1024).expect_err("invalid names must fail closed");
        assert!(error.to_string().contains("invalid package name"));
    }

    #[test]
    fn fuzzy_match_returns_matches() {
        let engine = CompletionEngine::new();

        let candidates = vec![
            "firefox".to_string(),
            "chromium".to_string(),
            "brave".to_string(),
        ];

        let results = engine.fuzzy_match("fire", candidates);
        assert_eq!(results.first().map(String::as_str), Some("firefox"));
    }

    #[test]
    fn fuzzy_indices_prefers_short_prefix_over_long_score() {
        let candidates = vec![
            "firefox-developer-edition-i18n-trs".to_string(),
            "firefox".to_string(),
        ];
        let ranked = CompletionEngine::fuzzy_indices("fire", &candidates, 10);
        assert_eq!(ranked.first().copied(), Some(1));
    }

    #[test]
    fn fuzzy_indices_ranks_transposed_query() {
        let candidates = vec!["firefox".to_string(), "python".to_string()];
        let ranked = CompletionEngine::fuzzy_indices("frfox", &candidates, 10);
        assert_eq!(ranked.first().copied(), Some(0));
    }

    #[test]
    fn fuzzy_match_empty_pattern_returns_all() {
        let engine = CompletionEngine::new();

        let candidates = vec!["a".to_string(), "b".to_string()];
        let results = engine.fuzzy_match("", candidates.clone());
        assert_eq!(results, candidates);
    }

    #[test]
    fn probe_context_reads_python_version() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(temp_dir.path().join(".python-version"), "3.12.0\n").unwrap();
        let suggestions = CompletionEngine::probe_context_from(temp_dir.path(), "python").unwrap();
        assert_eq!(suggestions.first().map(String::as_str), Some("3.12.0"));
    }

    #[test]
    fn probe_context_unreadable_pin_fails_closed() {
        let temp_dir = TempDir::new().unwrap();
        let pin = temp_dir.path().join(".python-version");
        std::fs::write(&pin, "3.12.0\n").unwrap();
        let original = std::fs::metadata(&pin).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&pin, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        let blocked = std::fs::read_to_string(&pin).is_err();
        let result = CompletionEngine::probe_context_from(temp_dir.path(), "python");
        let _ = std::fs::set_permissions(&pin, original);
        if !blocked {
            return;
        }
        assert!(
            result.is_err(),
            "unreadable pin must fail closed, got {result:?}"
        );
    }

    #[test]
    fn malformed_ancestor_metadata_does_not_break_child_completions() {
        let temp_dir = TempDir::new().unwrap();
        let child = temp_dir.path().join("project");
        std::fs::create_dir(&child).unwrap();
        std::fs::write(temp_dir.path().join("package.json"), "not json").unwrap();

        let suggestions = CompletionEngine::probe_context_from(&child, "node").unwrap();
        assert!(suggestions.is_empty());
    }

    #[test]
    fn probe_context_invalid_package_json_fails_closed() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(temp_dir.path().join("package.json"), "not json").unwrap();
        let error = CompletionEngine::probe_context_from(temp_dir.path(), "node").unwrap_err();
        assert!(
            error.to_string().contains("Failed to parse"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn read_optional_file_missing_is_none() {
        let missing = TempDir::new().unwrap().path().join("does-not-exist");
        assert!(read_optional_file(&missing).unwrap().is_none());
    }
}
