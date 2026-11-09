//! APT Sources.list Parser - Pure Rust Implementation
//!
//! Parses APT repository configuration from:
//! - `/etc/apt/sources.list` (legacy one-liner format)
//! - `/etc/apt/sources.list.d/*.list` (legacy format)
//! - `/etc/apt/sources.list.d/*.sources` (deb822 format, Debian 12+)
//!
//! Supports:
//! - Both `deb` and `deb-src` types
//! - Options in brackets like `[arch=amd64 signed-by=/path/to/key.gpg]`
//! - HTTP, HTTPS, and file:// URIs
//! - CDROMs and local repositories

#![cfg(any(feature = "debian", feature = "debian-pure"))]

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Represents a single APT repository source
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repository {
    /// Type: "deb" for binary packages, "deb-src" for source packages
    pub repo_type: RepoType,
    /// Base URI (e.g., `<http://deb.debian.org/debian>`)
    pub uri: String,
    /// Suite/distribution (e.g., "bookworm", "stable", "bookworm-updates")
    pub suite: String,
    /// Components (e.g., `["main", "contrib", "non-free"]`)
    pub components: Vec<String>,
    /// Architecture filter (e.g., "amd64", "i386")
    pub arch: Option<String>,
    /// Path to GPG key for signature verification
    pub signed_by: Option<PathBuf>,
    /// Whether this repository is enabled
    pub enabled: bool,
    /// Source file this repository was loaded from
    pub source_file: PathBuf,
    /// Additional options from brackets
    pub options: HashMap<String, String>,
}

impl Repository {
    /// Get the Release file URL
    #[must_use]
    pub fn release_url(&self) -> String {
        format!(
            "{}/dists/{}/InRelease",
            self.uri.trim_end_matches('/'),
            self.suite
        )
    }
}

/// Repository type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoType {
    /// Binary packages
    Binary,
    /// Source packages
    Source,
}

impl RepoType {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "deb" => Some(Self::Binary),
            "deb-src" => Some(Self::Source),
            _ => None,
        }
    }
}

/// Parse all APT sources from the system
///
/// Reads from:
/// - `/etc/apt/sources.list`
/// - `/etc/apt/sources.list.d/*.list`
/// - `/etc/apt/sources.list.d/*.sources`
pub fn parse_all_sources() -> Result<Vec<Repository>> {
    let mut repos = Vec::new();

    // Parse main sources.list
    let main_sources = Path::new("/etc/apt/sources.list");
    if main_sources.exists() {
        let parsed = require_parsed_apt_sources(parse_sources_list(main_sources))?;
        tracing::debug!(
            "Parsed {} repositories from {}",
            parsed.len(),
            main_sources.display()
        );
        repos.extend(parsed);
    } else {
        tracing::debug!("Main sources.list not found at {}", main_sources.display());
    }

    // Parse sources.list.d directory
    let sources_dir = Path::new("/etc/apt/sources.list.d");
    match sources_list_d_from_read_dir(fs::read_dir(sources_dir))? {
        Some(entries) => {
            for entry in entries {
                let entry = sources_list_d_entry(entry)?;
                let path = entry.path();
                let Some(ext) = path.extension() else {
                    continue;
                };
                let parsed = require_parsed_apt_sources(if ext == "list" {
                    parse_sources_list(&path)
                } else if ext == "sources" {
                    parse_deb822_sources(&path)
                } else {
                    continue;
                })?;
                tracing::debug!(
                    "Parsed {} repositories from {}",
                    parsed.len(),
                    path.display()
                );
                repos.extend(parsed);
            }
        }
        None => {
            tracing::debug!("Sources directory not found at {}", sources_dir.display());
        }
    }

    tracing::info!("Loaded {} total repositories from APT sources", repos.len());
    Ok(repos)
}

fn sources_list_d_from_read_dir(
    result: std::io::Result<fs::ReadDir>,
) -> Result<Option<fs::ReadDir>> {
    match result {
        Ok(entries) => Ok(Some(entries)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("Failed to read APT sources directory"),
    }
}

fn require_parsed_apt_sources(result: Result<Vec<Repository>>) -> Result<Vec<Repository>> {
    result.context("Failed to parse APT sources file")
}

fn sources_list_d_entry(result: std::io::Result<fs::DirEntry>) -> Result<fs::DirEntry> {
    result.context("Failed to read APT sources directory entry")
}

/// Parse a legacy sources.list file
///
/// Format: `deb [options] uri suite [component1] [component2] ...`
///
/// Examples:
/// ```text
/// deb http://deb.debian.org/debian bookworm main contrib non-free
/// deb [arch=amd64] https://example.com/repo stable main
/// deb-src http://deb.debian.org/debian bookworm main
/// ```
pub fn parse_sources_list(path: &Path) -> Result<Vec<Repository>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read sources.list: {}", path.display()))?;

    parse_sources_list_content(&content, path)
}

/// Parse sources.list content from a string
pub fn parse_sources_list_content(content: &str, source_file: &Path) -> Result<Vec<Repository>> {
    let mut repos = Vec::new();
    let mut line_num = 0;

    for line in content.lines() {
        line_num += 1;
        let line = line.trim();

        if line.is_empty() {
            continue;
        }

        // APT disables legacy entries by commenting out the complete `deb` or
        // `deb-src` line. Preserve those entries for configuration tooling,
        // while continuing to ignore ordinary prose comments.
        let (line, enabled) = if let Some(stripped) = line.strip_prefix('#') {
            let disabled_line = stripped.trim();
            if !disabled_line.starts_with("deb ") && !disabled_line.starts_with("deb-src ") {
                continue;
            }
            (disabled_line, false)
        } else {
            (line, true)
        };

        if let Some(repo) = parse_source_line(line, source_file, enabled) {
            repos.push(repo);
        } else {
            tracing::debug!(
                "Skipped invalid line {} in {}: {}",
                line_num,
                source_file.display(),
                line
            );
        }
    }

    Ok(repos)
}

/// Parse a single source line
fn parse_source_line(line: &str, source_file: &Path, enabled: bool) -> Option<Repository> {
    let line = line.trim();

    // Determine type. The type must be a complete word so lines like
    // "debsomething ..." are rejected instead of parsing "something" as URI.
    let (type_token, rest) = match line.split_once(char::is_whitespace) {
        Some((token, rest)) => (token, rest.trim_start()),
        None => return None,
    };
    let repo_type = match type_token {
        "deb" => RepoType::Binary,
        "deb-src" => RepoType::Source,
        _ => return None,
    };

    // Parse options in brackets [arch=amd64 signed-by=/path]. An
    // unterminated bracket is malformed and rejects the whole line rather
    // than silently dropping security-relevant options like `signed-by`.
    let (options, rest) = if let Some(body) = rest.strip_prefix('[') {
        // An unterminated bracket is malformed and rejects the whole line
        // rather than silently dropping security-relevant options like
        // `signed-by`.
        let Some(end) = body.find(']') else {
            tracing::debug!("Rejected source line with unterminated '[' options: {line}");
            return None;
        };
        let opts_str = &body[..end];
        let rest = body[end + 1..].trim();
        (parse_options(opts_str), rest)
    } else {
        (HashMap::new(), rest)
    };

    // Split remaining parts: uri suite components...
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.len() < 2 {
        return None; // Need at least URI and suite
    }

    let uri = parts[0].to_string();
    let suite = parts[1].to_string();
    let components: Vec<String> = parts[2..].iter().map(|s| (*s).to_string()).collect();

    // Extract specific options
    let arch = options.get("arch").cloned();
    let signed_by = options.get("signed-by").map(PathBuf::from);

    Some(Repository {
        repo_type,
        uri,
        suite,
        components,
        arch,
        signed_by,
        enabled,
        source_file: source_file.to_path_buf(),
        options,
    })
}

/// Parse options from bracket content
fn parse_options(opts_str: &str) -> HashMap<String, String> {
    let mut options = HashMap::new();

    for opt in opts_str.split_whitespace() {
        if let Some((key, value)) = opt.split_once('=') {
            options.insert(key.to_string(), value.to_string());
        }
    }

    options
}

/// Parse a deb822 format .sources file
///
/// Format (RFC 822-style):
/// ```text
/// Types: deb deb-src
/// URIs: http://deb.debian.org/debian
/// Suites: bookworm bookworm-updates
/// Components: main contrib non-free
/// Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
/// ```
pub fn parse_deb822_sources(path: &Path) -> Result<Vec<Repository>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read deb822 sources: {}", path.display()))?;

    parse_deb822_content(&content, path)
}

/// Parse deb822 content from a string
pub fn parse_deb822_content(content: &str, source_file: &Path) -> Result<Vec<Repository>> {
    let mut repos = Vec::new();
    let mut current_stanza: HashMap<String, String> = HashMap::new();

    let mut last_key: Option<String> = None;

    for raw_line in content.lines() {
        let trimmed = raw_line.trim();

        // Empty line separates stanzas
        if trimmed.is_empty() {
            if !current_stanza.is_empty() {
                repos.extend(expand_deb822_stanza(&current_stanza, source_file));
                current_stanza.clear();
            }
            last_key = None;
            continue;
        }

        // Skip comments
        if trimmed.starts_with('#') {
            continue;
        }

        // Continuation lines (leading whitespace) extend the previous value,
        // e.g. multi-line `Signed-By` key blocks.
        if raw_line.starts_with(' ') || raw_line.starts_with('\t') {
            if let Some(key) = &last_key
                && let Some(value) = current_stanza.get_mut(key.as_str())
            {
                value.push('\n');
                value.push_str(trimmed);
            }
            continue;
        }

        // Parse key: value
        if let Some((key, value)) = trimmed.split_once(':') {
            let key = key.trim().to_lowercase();
            let value = value.trim().to_string();
            current_stanza.insert(key.clone(), value);
            last_key = Some(key);
        }
    }

    // Process final stanza
    if !current_stanza.is_empty() {
        repos.extend(expand_deb822_stanza(&current_stanza, source_file));
    }

    Ok(repos)
}

/// Expand a deb822 stanza into multiple Repository entries
///
/// A single stanza can specify multiple types, URIs, suites, and components,
/// which we expand into individual Repository entries.
fn expand_deb822_stanza(stanza: &HashMap<String, String>, source_file: &Path) -> Vec<Repository> {
    let mut repos = Vec::new();

    // Parse types (deb, deb-src)
    let types: Vec<RepoType> = stanza.get("types").map_or_else(
        || vec![RepoType::Binary],
        |s| {
            s.split_whitespace()
                .filter_map(RepoType::from_str)
                .collect()
        },
    );

    // Parse URIs
    let uris: Vec<&str> = stanza
        .get("uris")
        .map(|s| s.split_whitespace().collect())
        .unwrap_or_default();

    if uris.is_empty() {
        return repos; // No URIs, skip this stanza
    }

    // Parse suites
    let suites: Vec<&str> = stanza
        .get("suites")
        .map(|s| s.split_whitespace().collect())
        .unwrap_or_default();

    if suites.is_empty() {
        return repos; // No suites, skip this stanza
    }

    // Parse components
    let components: Vec<String> = stanza
        .get("components")
        .map(|s| s.split_whitespace().map(String::from).collect())
        .unwrap_or_default();

    // Parse architectures
    let arch = stanza.get("architectures").cloned();

    // A deb822 Signed-By value can be either a keyring path/fingerprint or an
    // inline armored public key. Only path-shaped values belong in the typed
    // filesystem field; preserve inline key material verbatim in options.
    let signed_by_value = stanza.get("signed-by");
    let signed_by = signed_by_value
        .filter(|value| !value.contains('\n'))
        .map(PathBuf::from);

    // Check if enabled
    let enabled = stanza
        .get("enabled")
        .is_none_or(|s| s != "no" && s != "false");

    // Build options map from remaining fields
    let mut options = HashMap::new();
    for (key, value) in stanza {
        if ![
            "types",
            "uris",
            "suites",
            "components",
            "architectures",
            "signed-by",
            "enabled",
        ]
        .contains(&key.as_str())
        {
            options.insert(key.clone(), value.clone());
        }
    }
    if signed_by.is_none()
        && let Some(value) = signed_by_value
    {
        options.insert("signed-by".to_string(), value.clone());
    }

    // Expand all combinations
    for repo_type in &types {
        for uri in &uris {
            for suite in &suites {
                repos.push(Repository {
                    repo_type: *repo_type,
                    uri: (*uri).to_string(),
                    suite: (*suite).to_string(),
                    components: components.clone(),
                    arch: arch.clone(),
                    signed_by: signed_by.clone(),
                    enabled,
                    source_file: source_file.to_path_buf(),
                    options: options.clone(),
                });
            }
        }
    }

    repos
}

/// Get only enabled binary repositories
pub fn get_enabled_binary_repos() -> Result<Vec<Repository>> {
    Ok(parse_all_sources()?
        .into_iter()
        .filter(|r| r.enabled && r.repo_type == RepoType::Binary)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_source_line() {
        let line = "deb http://deb.debian.org/debian bookworm main contrib non-free";
        let repo = parse_source_line(line, Path::new("/etc/apt/sources.list"), true).unwrap();

        assert_eq!(repo.repo_type, RepoType::Binary);
        assert_eq!(repo.uri, "http://deb.debian.org/debian");
        assert_eq!(repo.suite, "bookworm");
        assert_eq!(repo.components, vec!["main", "contrib", "non-free"]);
        assert!(repo.enabled);
    }

    #[test]
    fn test_parse_source_with_options() {
        let line = "deb [arch=amd64 signed-by=/usr/share/keyrings/test.gpg] https://example.com/repo stable main";
        let repo = parse_source_line(line, Path::new("/test"), true).unwrap();

        assert_eq!(repo.arch, Some("amd64".to_string()));
        assert_eq!(
            repo.signed_by,
            Some(PathBuf::from("/usr/share/keyrings/test.gpg"))
        );
        assert_eq!(repo.uri, "https://example.com/repo");
    }

    #[test]
    fn test_parse_deb_src() {
        let line = "deb-src http://deb.debian.org/debian bookworm main";
        let repo = parse_source_line(line, Path::new("/test"), true).unwrap();

        assert_eq!(repo.repo_type, RepoType::Source);
    }

    #[test]
    fn test_parse_deb822_stanza() {
        let content = r"
Types: deb deb-src
URIs: http://deb.debian.org/debian
Suites: bookworm bookworm-updates
Components: main contrib non-free
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
";

        let repos = parse_deb822_content(content, Path::new("/test.sources")).unwrap();

        // 2 types * 1 URI * 2 suites = 4 repos
        assert_eq!(repos.len(), 4);

        // Check first repo
        let first = &repos[0];
        assert_eq!(first.repo_type, RepoType::Binary);
        assert_eq!(first.uri, "http://deb.debian.org/debian");
        assert_eq!(first.suite, "bookworm");
        assert_eq!(first.components, vec!["main", "contrib", "non-free"]);
    }

    #[test]
    fn test_parse_disabled_repo() {
        let content = r"
Types: deb
URIs: http://example.com/repo
Suites: stable
Components: main
Enabled: no
";

        let repos = parse_deb822_content(content, Path::new("/test.sources")).unwrap();
        assert_eq!(repos.len(), 1);
        assert!(!repos[0].enabled);
    }

    #[test]
    fn test_release_url() {
        let repo = Repository {
            repo_type: RepoType::Binary,
            uri: "http://deb.debian.org/debian".to_string(),
            suite: "bookworm".to_string(),
            components: vec!["main".to_string()],
            arch: None,
            signed_by: None,
            enabled: true,
            source_file: PathBuf::new(),
            options: HashMap::new(),
        };

        assert_eq!(
            repo.release_url(),
            "http://deb.debian.org/debian/dists/bookworm/InRelease"
        );
    }

    #[test]
    fn test_parse_sources_list_content() {
        let content = r"
# Main Debian repos
deb http://deb.debian.org/debian bookworm main
deb-src http://deb.debian.org/debian bookworm main

# Security updates
deb http://security.debian.org/debian-security bookworm-security main
";

        let repos =
            parse_sources_list_content(content, Path::new("/etc/apt/sources.list")).unwrap();
        assert_eq!(repos.len(), 3);

        assert_eq!(repos[0].repo_type, RepoType::Binary);
        assert_eq!(repos[1].repo_type, RepoType::Source);
        assert_eq!(repos[2].suite, "bookworm-security");
    }

    #[test]
    fn test_skip_invalid_lines() {
        let content = r"
not a valid line
deb http://example.com/repo stable main
random text here
";

        let repos = parse_sources_list_content(content, Path::new("/test")).unwrap();
        assert_eq!(repos.len(), 1);
    }

    #[test]
    fn test_sources_list_d_from_read_dir_allows_missing() {
        assert!(
            sources_list_d_from_read_dir(Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no dir",
            )))
            .expect("missing sources.list.d is not an error")
            .is_none()
        );
    }

    #[test]
    fn test_sources_list_d_from_read_dir_rejects_unreadable() {
        let error = sources_list_d_from_read_dir(Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "denied",
        )))
        .expect_err("unreadable sources.list.d must not look empty");
        assert!(
            error
                .to_string()
                .contains("Failed to read APT sources directory"),
            "got: {error}"
        );
    }

    #[test]
    fn test_require_parsed_apt_sources_allows_success() {
        let repos =
            require_parsed_apt_sources(Ok(Vec::new())).expect("successful parse must be kept");
        assert!(repos.is_empty());
    }

    #[test]
    fn test_require_parsed_apt_sources_rejects_error() {
        let error = require_parsed_apt_sources(Err(anyhow::anyhow!("corrupt")))
            .expect_err("corrupt APT sources must not look like fewer repos");
        assert!(
            error
                .to_string()
                .contains("Failed to parse APT sources file"),
            "got: {error}"
        );
    }

    #[test]
    fn test_sources_list_d_entry_allows_success() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("foo.list"), b"").unwrap();
        let entry = fs::read_dir(dir.path())
            .unwrap()
            .next()
            .expect("temp sources.list.d should contain one file");
        sources_list_d_entry(entry).expect("readable directory entry must be kept");
    }

    #[test]
    fn test_sources_list_d_entry_rejects_error() {
        let error = sources_list_d_entry(Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "denied",
        )))
        .expect_err("failed sources.list.d entry must not be skipped");
        assert!(
            error
                .to_string()
                .contains("Failed to read APT sources directory entry"),
            "got: {error}"
        );
        let cause = error
            .downcast_ref::<std::io::Error>()
            .expect("original I/O error must remain available");
        assert_eq!(cause.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(cause.to_string(), "denied");
    }
    #[test]
    fn commented_source_entries_are_preserved_as_disabled() {
        let repos = parse_sources_list_content(
            "# deb https://example.com/debian stable main\n# ordinary comment\n",
            Path::new("/t.list"),
        )
        .expect("parse sources");

        assert_eq!(repos.len(), 1);
        assert_eq!(repos[0].uri, "https://example.com/debian");
        assert!(!repos[0].enabled);
    }

    #[test]
    fn source_line_type_must_be_a_complete_word() {
        assert!(
            parse_source_line(
                "debsomething http://example.com stable main",
                Path::new("/t"),
                true
            )
            .is_none()
        );
        assert!(parse_source_line("deb", Path::new("/t"), true).is_none());
        let repo = parse_source_line("deb http://example.com stable main", Path::new("/t"), true)
            .expect("valid line");
        assert_eq!(repo.uri, "http://example.com");
    }

    #[test]
    fn unterminated_option_bracket_rejects_the_line() {
        // signed-by would be silently dropped otherwise
        assert!(
            parse_source_line(
                "deb [arch=amd64 signed-by=/key.gpg https://example.com stable main",
                Path::new("/t"),
                true,
            )
            .is_none(),
            "malformed bracket must reject the line, not drop its options"
        );
    }

    #[test]
    fn deb822_inline_signing_keys_remain_data_not_paths() {
        let content = "Types: deb\nURIs: http://example.com\nSuites: stable\nSigned-By:\n -----BEGIN PGP PUBLIC KEY BLOCK-----\n abcdef\n -----END PGP PUBLIC KEY BLOCK-----\n";

        let repos = parse_deb822_content(content, Path::new("/t.sources")).expect("parse");
        assert_eq!(repos.len(), 1);
        assert!(
            repos[0].signed_by.is_none(),
            "inline key material must not become a filesystem path"
        );
        assert_eq!(
            repos[0].options.get("signed-by").map(String::as_str),
            Some(
                "\n-----BEGIN PGP PUBLIC KEY BLOCK-----\nabcdef\n-----END PGP PUBLIC KEY BLOCK-----"
            )
        );
    }

    #[test]
    fn deb822_multiline_values_are_preserved() {
        let content = "Types: deb\nURIs: http://example.com\nSuites: stable\nComponents: main\nX-Notes: first\n second\n third\n";

        let repos = parse_deb822_content(content, Path::new("/t.sources")).expect("parse");
        assert_eq!(repos.len(), 1);
        assert_eq!(
            repos[0].options.get("x-notes").map(String::as_str),
            Some("first\nsecond\nthird")
        );
    }
}
