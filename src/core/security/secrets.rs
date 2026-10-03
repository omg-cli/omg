//! Secret detection using regex patterns and entropy analysis
//!
//! Scans files and content for accidentally committed secrets like API keys,
//! tokens, private keys, and credentials across 19 secret types.

use std::io::{self, Read};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Types of secrets that can be detected
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretType {
    AwsAccessKey,
    AwsSecretKey,
    GithubToken,
    GitlabToken,
    SlackToken,
    SlackWebhook,
    PrivateKey,
    GenericApiKey,
    GenericPassword,
    JwtToken,
    GoogleApiKey,
    StripeKey,
    TwilioKey,
    SendgridKey,
    NpmToken,
    PypiToken,
    DockerHubToken,
    HerokuApiKey,
    DigitalOceanToken,
    GoogleOAuth,
    OpenAiKey,
}

impl std::fmt::Display for SecretType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AwsAccessKey => write!(f, "AWS Access Key"),
            Self::AwsSecretKey => write!(f, "AWS Secret Key"),
            Self::GithubToken => write!(f, "GitHub Token"),
            Self::GitlabToken => write!(f, "GitLab Token"),
            Self::SlackToken => write!(f, "Slack Token"),
            Self::SlackWebhook => write!(f, "Slack Webhook"),
            Self::PrivateKey => write!(f, "Private Key"),
            Self::GenericApiKey => write!(f, "API Key"),
            Self::GenericPassword => write!(f, "Password"),
            Self::JwtToken => write!(f, "JWT Token"),
            Self::GoogleApiKey => write!(f, "Google API Key"),
            Self::StripeKey => write!(f, "Stripe Key"),
            Self::TwilioKey => write!(f, "Twilio Key"),
            Self::SendgridKey => write!(f, "SendGrid Key"),
            Self::NpmToken => write!(f, "NPM Token"),
            Self::PypiToken => write!(f, "PyPI Token"),
            Self::DockerHubToken => write!(f, "Docker Hub Token"),
            Self::HerokuApiKey => write!(f, "Heroku API Key"),
            Self::DigitalOceanToken => write!(f, "DigitalOcean Token"),
            Self::GoogleOAuth => write!(f, "Google OAuth Credential"),
            Self::OpenAiKey => write!(f, "OpenAI API Key"),
        }
    }
}

/// A detected secret finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    /// Category of credential detected.
    pub secret_type: SecretType,
    /// File the match came from (or the caller-provided source label).
    pub file_path: String,
    /// 1-based line number of the match.
    pub line_number: usize,
    /// Masked form safe for display and reports.
    pub redacted: String,
    /// Severity assigned by the pattern that matched.
    pub severity: SecretSeverity,
}

/// Severity of the secret finding
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretSeverity {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl std::fmt::Display for SecretSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Pattern definition for secret detection
struct SecretPattern {
    secret_type: SecretType,
    pattern: &'static LazyLock<Regex>,
    severity: SecretSeverity,
}

macro_rules! secret_pattern {
    ($secret_type:ident, $pattern:ident, $severity:ident) => {
        SecretPattern {
            secret_type: SecretType::$secret_type,
            pattern: &$pattern,
            severity: SecretSeverity::$severity,
        }
    };
}

// Static regex patterns compiled once at first use.
fn compile_pattern(pattern: &str) -> Regex {
    match Regex::new(pattern) {
        Ok(regex) => regex,
        Err(error) => panic!("invalid built-in secret regex: {error}"),
    }
}

static RE_AWS_ACCESS_KEY: LazyLock<Regex> =
    LazyLock::new(|| compile_pattern(r"(AKIA[0-9A-Z]{16})"));
static RE_AWS_SECRET_KEY: LazyLock<Regex> = LazyLock::new(|| {
    compile_pattern(
        r#"(?i)aws[_-]?secret[_-]?access[_-]?key['"]?\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})"#,
    )
});
static RE_GITHUB_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    compile_pattern(
        r"(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}|gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36})",
    )
});
static RE_GITLAB_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| compile_pattern(r"(glpat-[a-zA-Z0-9\-]{20,})"));
static RE_SLACK_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| compile_pattern(r"(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)"));
static RE_SLACK_WEBHOOK: LazyLock<Regex> = LazyLock::new(|| {
    compile_pattern(
        r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    )
});
static RE_PRIVATE_KEY: LazyLock<Regex> =
    LazyLock::new(|| compile_pattern(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"));
static RE_JWT: LazyLock<Regex> =
    LazyLock::new(|| compile_pattern(r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"));
static RE_GOOGLE_API_KEY: LazyLock<Regex> =
    LazyLock::new(|| compile_pattern(r"AIza[0-9A-Za-z\-_]{35}"));
static RE_GOOGLE_OAUTH: LazyLock<Regex> =
    LazyLock::new(|| compile_pattern(r"(ya29\.[a-zA-Z0-9_\-]{25,}|GOCSPX-[a-zA-Z0-9_\-]{16,})"));
static RE_OPENAI_KEY: LazyLock<Regex> =
    LazyLock::new(|| compile_pattern(r"sk-(proj-[a-zA-Z0-9_\-]{20,}|[a-zA-Z0-9]{48})"));
static RE_STRIPE_KEY: LazyLock<Regex> =
    LazyLock::new(|| compile_pattern(r"(sk_live_[0-9a-zA-Z]{24}|rk_live_[0-9a-zA-Z]{24})"));
static RE_TWILIO_KEY: LazyLock<Regex> = LazyLock::new(|| compile_pattern(r"SK[0-9a-fA-F]{32}"));
static RE_SENDGRID_KEY: LazyLock<Regex> =
    LazyLock::new(|| compile_pattern(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"));
static RE_NPM_TOKEN: LazyLock<Regex> = LazyLock::new(|| compile_pattern(r"npm_[a-zA-Z0-9]{36}"));
static RE_PYPI_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| compile_pattern(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}"));
static RE_DOCKER_HUB_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| compile_pattern(r"dckr_pat_[a-zA-Z0-9_-]{27}"));
static RE_HEROKU_API_KEY: LazyLock<Regex> = LazyLock::new(|| {
    compile_pattern(
        r#"(?i)heroku[_-]?api[_-]?key['"]?\s*[:=]\s*['"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"#,
    )
});
static RE_DIGITALOCEAN_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| compile_pattern(r"dop_v1_[a-f0-9]{64}"));
static RE_GENERIC_API_KEY: LazyLock<Regex> = LazyLock::new(|| {
    compile_pattern(r#"(?i)(api[_-]?key|apikey)['"]?\s*[:=]\s*['"]?([a-zA-Z0-9_-]{20,})"#)
});
static RE_GENERIC_PASSWORD: LazyLock<Regex> = LazyLock::new(|| {
    compile_pattern(r#"(?i)(password|passwd|pwd)['"]?\s*[:=]\s*['"]?([^\s'"]{8,})"#)
});

/// Static list of all secret patterns.
static PATTERNS: [SecretPattern; 21] = [
    secret_pattern!(AwsAccessKey, RE_AWS_ACCESS_KEY, Critical),
    secret_pattern!(AwsSecretKey, RE_AWS_SECRET_KEY, Critical),
    secret_pattern!(GithubToken, RE_GITHUB_TOKEN, Critical),
    secret_pattern!(GitlabToken, RE_GITLAB_TOKEN, Critical),
    secret_pattern!(SlackToken, RE_SLACK_TOKEN, High),
    secret_pattern!(SlackWebhook, RE_SLACK_WEBHOOK, High),
    secret_pattern!(PrivateKey, RE_PRIVATE_KEY, Critical),
    secret_pattern!(JwtToken, RE_JWT, Medium),
    secret_pattern!(GoogleApiKey, RE_GOOGLE_API_KEY, High),
    secret_pattern!(GoogleOAuth, RE_GOOGLE_OAUTH, Critical),
    secret_pattern!(OpenAiKey, RE_OPENAI_KEY, Critical),
    secret_pattern!(StripeKey, RE_STRIPE_KEY, Critical),
    secret_pattern!(TwilioKey, RE_TWILIO_KEY, High),
    secret_pattern!(SendgridKey, RE_SENDGRID_KEY, High),
    secret_pattern!(NpmToken, RE_NPM_TOKEN, High),
    secret_pattern!(PypiToken, RE_PYPI_TOKEN, High),
    secret_pattern!(DockerHubToken, RE_DOCKER_HUB_TOKEN, High),
    secret_pattern!(HerokuApiKey, RE_HEROKU_API_KEY, High),
    secret_pattern!(DigitalOceanToken, RE_DIGITALOCEAN_TOKEN, High),
    secret_pattern!(GenericApiKey, RE_GENERIC_API_KEY, Medium),
    secret_pattern!(GenericPassword, RE_GENERIC_PASSWORD, Medium),
];

/// Failures reading files or directories while scanning for secrets.
#[derive(Debug, Error)]
pub enum SecretError {
    #[error("Failed to read '{path}'")]
    Read {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("Refusing to scan '{path}' because it is not a regular file")]
    UnsupportedFileType { path: String },
    #[error("File '{path}' exceeds the maximum secret-scan size of {max} bytes ({size} bytes)")]
    FileTooLarge { path: String, size: u64, max: u64 },
    #[error("Directory nesting exceeds the maximum scan depth of {max} at '{path}'")]
    DepthExceeded { path: String, max: usize },
}

/// Secret scanner for detecting leaked credentials
pub struct SecretScanner;

impl SecretScanner {
    const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;

    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Scan a file for secrets
    pub fn scan_file<P: AsRef<Path>>(&self, path: P) -> Result<Vec<SecretFinding>, SecretError> {
        let path = path.as_ref();
        let path_str = path.display().to_string();
        let metadata = std::fs::symlink_metadata(path).map_err(|source| SecretError::Read {
            path: path_str.clone(),
            source,
        })?;
        if !metadata.file_type().is_file() {
            return Err(SecretError::UnsupportedFileType { path: path_str });
        }
        if metadata.len() > Self::MAX_FILE_BYTES {
            return Err(SecretError::FileTooLarge {
                path: path_str,
                size: metadata.len(),
                max: Self::MAX_FILE_BYTES,
            });
        }

        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
        }
        let file = options.open(path).map_err(|source| SecretError::Read {
            path: path_str.clone(),
            source,
        })?;
        if !file
            .metadata()
            .map_err(|source| SecretError::Read {
                path: path_str.clone(),
                source,
            })?
            .file_type()
            .is_file()
        {
            return Err(SecretError::UnsupportedFileType { path: path_str });
        }
        let mut content = String::new();
        let bytes_read = file
            .take(Self::MAX_FILE_BYTES + 1)
            .read_to_string(&mut content)
            .map_err(|source| SecretError::Read {
                path: path_str.clone(),
                source,
            })?;
        if bytes_read as u64 > Self::MAX_FILE_BYTES {
            return Err(SecretError::FileTooLarge {
                path: path_str,
                size: bytes_read as u64,
                max: Self::MAX_FILE_BYTES,
            });
        }

        Ok(self.scan_content(&content, &path_str))
    }

    /// Scan content for secrets
    #[must_use]
    pub fn scan_content(&self, content: &str, source: &str) -> Vec<SecretFinding> {
        let mut findings = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            for pattern in &PATTERNS {
                if let Some(captures) = pattern.pattern.captures(line) {
                    let matched = captures.get(0).map_or("", |m| m.as_str());

                    // Skip only when the captured secret value itself is an
                    // obvious placeholder; never drop findings merely because
                    // the value contains a placeholder-like substring.
                    let secret_value = captures
                        .get(captures.len() - 1)
                        .map_or(matched, |m| m.as_str());
                    if Self::is_placeholder(secret_value) {
                        continue;
                    }

                    findings.push(SecretFinding {
                        secret_type: pattern.secret_type.clone(),
                        file_path: source.to_string(),
                        line_number: line_num + 1,
                        redacted: Self::redact(matched),
                        severity: pattern.severity,
                    });
                }
            }
        }

        findings
    }

    /// Scan a directory recursively for secrets
    ///
    /// Symlinked directories are never followed (a cyclic symlink would
    /// otherwise recurse forever), and nesting deeper than
    /// [`MAX_SCAN_DEPTH`] fails closed rather than silently skipping files.
    pub fn scan_directory<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<Vec<SecretFinding>, SecretError> {
        let mut findings = Vec::new();

        self.scan_directory_recursive(path.as_ref(), &mut findings, 0)?;

        Ok(findings)
    }

    /// Maximum directory nesting followed during a scan. Deep enough for
    /// real source trees (after `node_modules`/`target` pruning) while
    /// bounding attacker-controlled recursion work.
    const MAX_SCAN_DEPTH: usize = 64;

    fn scan_directory_recursive(
        &self,
        path: &Path,
        findings: &mut Vec<SecretFinding>,
        depth: usize,
    ) -> Result<(), SecretError> {
        if depth > Self::MAX_SCAN_DEPTH {
            return Err(SecretError::DepthExceeded {
                path: path.display().to_string(),
                max: Self::MAX_SCAN_DEPTH,
            });
        }
        let path_str = path.display().to_string();
        for entry in std::fs::read_dir(path).map_err(|source| SecretError::Read {
            path: path_str.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| SecretError::Read {
                path: path_str.clone(),
                source,
            })?;
            let entry_path = entry.path();
            // DirEntry::file_type does not traverse symlinks, so symlinked
            // directories and files are skipped outright instead of being
            // descended into via the cycle-prone `Path::is_dir`.
            let file_type = entry.file_type().map_err(|source| SecretError::Read {
                path: path_str.clone(),
                source,
            })?;
            if file_type.is_symlink() {
                continue;
            }

            // Skip common non-text directories
            if file_type.is_dir() {
                let dir_name = entry_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");

                if [
                    "node_modules",
                    ".git",
                    "target",
                    "vendor",
                    "__pycache__",
                    ".venv",
                    "venv",
                ]
                .contains(&dir_name)
                {
                    continue;
                }

                self.scan_directory_recursive(&entry_path, findings, depth + 1)?;
            } else if file_type.is_file() && Self::is_scannable_file(&entry_path) {
                findings.extend(self.scan_file(&entry_path)?);
            }
        }

        Ok(())
    }

    /// Check if a file should be scanned
    fn is_scannable_file(path: &Path) -> bool {
        let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        let scannable_extensions = [
            "rs",
            "py",
            "js",
            "ts",
            "jsx",
            "tsx",
            "go",
            "rb",
            "java",
            "kt",
            "c",
            "cpp",
            "h",
            "hpp",
            "cs",
            "php",
            "sh",
            "bash",
            "zsh",
            "yaml",
            "yml",
            "json",
            "toml",
            "ini",
            "cfg",
            "conf",
            "config",
            "env",
            "properties",
            "xml",
            "md",
            "txt",
        ];

        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // Check for dotfiles that might contain secrets
        let sensitive_files = [
            ".env",
            ".env.local",
            ".env.production",
            ".env.development",
            ".npmrc",
            ".pypirc",
            ".netrc",
            ".gitconfig",
            "credentials",
            "secrets",
            "config",
        ];

        // Classic key-material files: often extensionless (.pem/.key DO get
        // extensions but id_rsa does not) and previously invisible to the
        // scanner (audit F3).
        let key_material = [
            ".pem",
            ".key",
            ".p12",
            ".pfx",
            ".keystore",
            "id_rsa",
            "id_ed25519",
            "id_ecdsa",
        ];

        scannable_extensions.contains(&extension)
            || sensitive_files.iter().any(|f| file_name.contains(f))
            || key_material.iter().any(|f| file_name.ends_with(f))
    }

    /// Check if the captured secret value looks like a placeholder.
    ///
    /// Placeholder detection must be conservative: generic words such as
    /// `test` or `123` appear inside real credentials all the time, so they
    /// are only skipped when they equal the whole value. Structural template
    /// markers (`<`, `${`, `{{`) and explicit `your_`/`my_` prefixes remain
    /// substring/prefix checks because they cannot occur in legitimate key
    /// material emitted by any provider covered by [`PATTERNS`].
    fn is_placeholder(value: &str) -> bool {
        const TEMPLATE_MARKERS: [&str; 3] = ["<", "${", "{{"];
        if TEMPLATE_MARKERS.iter().any(|marker| value.contains(marker)) {
            return true;
        }

        let normalized = value.trim().to_lowercase();
        const PLACEHOLDER_VALUES: [&str; 12] = [
            "example",
            "sample",
            "test",
            "demo",
            "placeholder",
            "xxx",
            "yyy",
            "zzz",
            "abc",
            "123",
            "fake",
            "dummy",
        ];
        if PLACEHOLDER_VALUES.contains(&normalized.as_str()) {
            return true;
        }

        normalized.starts_with("your_")
            || normalized.starts_with("my_")
            || normalized.starts_with("example_")
            || normalized.starts_with("sample_")
            || normalized.starts_with("placeholder_")
    }

    /// Redact a secret for safe display
    ///
    /// Slices on `char` boundaries only: matched secrets may contain
    /// arbitrary non-whitespace UTF-8 (e.g. via the generic password
    /// pattern), and byte-index slicing would panic on multi-byte chars.
    fn redact(text: &str) -> String {
        let visible_chars = 4;
        let total_chars = text.chars().count();
        if total_chars <= visible_chars * 2 {
            return "*".repeat(total_chars);
        }

        let prefix: String = text.chars().take(visible_chars).collect();
        let suffix: String = text
            .chars()
            .skip(total_chars.saturating_sub(visible_chars))
            .collect();
        let hidden_chars = total_chars.saturating_sub(visible_chars * 2);

        format!(
            "{}{}...{}",
            prefix,
            "*".repeat(hidden_chars.min(10)),
            suffix
        )
    }
}

impl Default for SecretScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Scan result summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretScanResult {
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub findings: Vec<SecretFinding>,
}

impl SecretScanResult {
    /// Summarize findings by severity. `#[must_use]`: dropping the summary
    /// defeats the critical/high counts callers rely on.
    #[must_use]
    pub fn from_findings(findings: Vec<SecretFinding>) -> Self {
        let [low_count, medium_count, high_count, critical_count] =
            findings.iter().fold([0; 4], |mut counts, finding| {
                counts[finding.severity as usize] += 1;
                counts
            });

        Self {
            total_findings: findings.len(),
            critical_count,
            high_count,
            medium_count,
            low_count,
            findings,
        }
    }

    #[must_use]
    pub fn has_critical(&self) -> bool {
        self.critical_count > 0
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used)] // Idiomatic in tests: panics on failure with clear error context
mod tests {
    use super::*;

    #[test]
    fn test_private_key_detection() {
        let scanner = SecretScanner::new();
        let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...";
        let findings = scanner.scan_content(content, "key.pem");

        assert!(!findings.is_empty(), "Should detect private key");
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.secret_type, SecretType::PrivateKey))
        );
    }

    #[test]
    fn test_google_oauth_and_openai_detection() {
        let scanner = SecretScanner::new();
        let oauth =
            "token = \"ya29.a0AfH6SMBx_prefix_and_64_chars_of_token_body_0123456789abcdef\"";
        assert!(
            scanner
                .scan_content(oauth, "token.json")
                .iter()
                .any(|f| matches!(f.secret_type, SecretType::GoogleOAuth)),
            "Should detect Google OAuth access token"
        );
        let client_secret = "secret = \"GOCSPX-abcdefghijklmnop1234567890AB\"";
        assert!(
            scanner
                .scan_content(client_secret, "client.json")
                .iter()
                .any(|f| matches!(f.secret_type, SecretType::GoogleOAuth)),
            "Should detect Google OAuth client secret"
        );
        let openai = "key = \"sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL\"";
        assert!(
            scanner
                .scan_content(openai, ".env")
                .iter()
                .any(|f| matches!(f.secret_type, SecretType::OpenAiKey)),
            "Should detect OpenAI API key"
        );
    }

    #[test]
    fn test_placeholder_ignored() {
        let scanner = SecretScanner::new();
        let content = "api_key = 'your_api_key_here'";
        let findings = scanner.scan_content(content, "config.py");

        assert!(findings.is_empty(), "Should ignore placeholder values");
    }

    #[test]
    fn test_redaction() {
        let secret = "secret_token_1234567890abcdef";
        let redacted = SecretScanner::redact(secret);

        assert!(
            !redacted.contains(secret),
            "must not expose the full secret"
        );
        assert_eq!(redacted, "secr**********...cdef");
    }

    #[test]
    fn redaction_never_exposes_short_multibyte_secrets() {
        let secret = "паролями";
        let redacted = SecretScanner::redact(secret);

        assert_eq!(redacted, "********");
        assert!(!secret.chars().any(|character| redacted.contains(character)));

        let long_secret = "пароль12345678";
        let longer = SecretScanner::redact(long_secret);
        assert!(
            !longer.contains(long_secret),
            "must not expose the full secret"
        );
        assert_eq!(longer, "паро******...5678");
    }

    #[cfg(unix)]
    #[test]
    fn scan_file_rejects_symlinks_before_reading() {
        let temp = tempfile::TempDir::new().expect("temp directory");
        let target = temp.path().join("secret.env");
        let link = temp.path().join("link.env");
        std::fs::write(&target, "API_KEY=real-secret-value").expect("write target");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        let error = SecretScanner::new()
            .scan_file(&link)
            .expect_err("symlink must not be scanned");
        assert!(matches!(error, SecretError::UnsupportedFileType { .. }));
    }

    #[test]
    fn scan_file_accepts_exact_bounded_read_limit_and_scans_the_tail() {
        use std::io::{Seek, SeekFrom, Write};

        let mut temp = tempfile::NamedTempFile::new().expect("temporary scan file");
        let marker = b"\n-----BEGIN RSA PRIVATE KEY-----\n";
        temp.as_file()
            .set_len(SecretScanner::MAX_FILE_BYTES)
            .expect("exact supported file size");
        let offset = SecretScanner::MAX_FILE_BYTES
            .checked_sub(u64::try_from(marker.len()).expect("marker length fits u64"))
            .expect("marker fits inside the supported limit");
        temp.seek(SeekFrom::Start(offset))
            .expect("seek to final secret marker");
        temp.write_all(marker).expect("write final secret marker");
        assert_eq!(
            temp.as_file().metadata().expect("fixture metadata").len(),
            SecretScanner::MAX_FILE_BYTES
        );

        let findings = SecretScanner::new()
            .scan_file(temp.path())
            .expect("a file exactly at the supported limit must be scanned");
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].secret_type, SecretType::PrivateKey));
        assert_eq!(findings[0].line_number, 2);
    }

    #[test]
    fn scan_file_rejects_files_over_the_bounded_read_limit() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        temp.as_file()
            .set_len(SecretScanner::MAX_FILE_BYTES + 1)
            .unwrap();

        let error = SecretScanner::new()
            .scan_file(temp.path())
            .expect_err("oversized files must not be buffered");

        assert!(matches!(error, SecretError::FileTooLarge { .. }));
    }

    #[test]
    fn scan_directory_survives_symlink_cycles() {
        // Regression: `entry_path.is_dir()` follows symlinks, so a cyclic
        // symlink (`sub/loop -> root`) recursed forever and crashed the
        // scanner with a stack overflow.
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::os::unix::fs::symlink(&root, root.join("sub").join("loop")).unwrap();
        std::fs::write(
            root.join("secrets.txt"),
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
        )
        .unwrap();

        let findings = SecretScanner::new().scan_directory(temp.path()).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.secret_type, SecretType::PrivateKey)),
            "real file inside the cycle must still be scanned"
        );
    }

    #[test]
    fn scan_directory_fails_closed_beyond_max_depth() {
        let temp = tempfile::TempDir::new().unwrap();
        let mut deep = temp.path().to_path_buf();
        for level in 0..SecretScanner::MAX_SCAN_DEPTH + 2 {
            deep = deep.join(format!("level-{level}"));
        }
        std::fs::create_dir_all(&deep).unwrap();

        let error = SecretScanner::new()
            .scan_directory(temp.path())
            .expect_err("nesting beyond the scan-depth bound must fail closed");
        assert!(
            matches!(
                error,
                SecretError::DepthExceeded {
                    max: SecretScanner::MAX_SCAN_DEPTH,
                    ..
                }
            ),
            "got: {error}"
        );
    }

    #[test]
    fn scan_directory_skips_symlinked_files_without_error() {
        let temp = tempfile::TempDir::new().unwrap();
        let real = temp.path().join("real.env");
        std::fs::write(&real, "password = super-secret-value-123").unwrap();
        std::os::unix::fs::symlink(&real, temp.path().join("link.env")).unwrap();

        let findings = SecretScanner::new().scan_directory(temp.path()).unwrap();
        assert_eq!(
            findings.len(),
            1,
            "symlink duplicates must not be scanned twice"
        );
        assert_eq!(findings[0].file_path, real.display().to_string());
    }

    #[test]
    fn real_api_key_containing_placeholder_substrings_is_still_reported() {
        // Regression: substring placeholder filtering dropped genuine keys
        // that merely contained words like `test` or `123`.
        let scanner = SecretScanner::new();
        let content = "apikey = 'abcd1234test567890efgh'";
        let findings = scanner.scan_content(content, "config.ini");

        assert!(
            !findings.is_empty(),
            "a real key containing the word 'test' must still be reported"
        );
    }

    #[test]
    fn exact_placeholder_values_are_still_skipped() {
        let scanner = SecretScanner::new();
        let content = "api_key = 'YOUR_API_KEY_HERE'\napi_key = example";
        let findings = scanner.scan_content(content, "config.py");

        assert!(
            findings.is_empty(),
            "exact placeholder values must be skipped"
        );
    }

    #[test]
    fn test_scan_result_from_findings() {
        let findings = vec![SecretFinding {
            secret_type: SecretType::PrivateKey,
            file_path: "test.pem".to_string(),
            line_number: 1,
            redacted: "****".to_string(),
            severity: SecretSeverity::Critical,
        }];

        let result = SecretScanResult::from_findings(findings);
        assert_eq!(result.total_findings, 1);
        assert_eq!(result.critical_count, 1);
        assert!(result.has_critical());
    }

    #[test]
    fn scan_directory_fails_closed_on_unreadable_file() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::write(temp.path().join("secrets.env"), [0xff, 0xfe, 0xfd]).unwrap();
        let error = SecretScanner::new()
            .scan_directory(temp.path())
            .expect_err("invalid UTF-8 in a scannable file must fail closed");
        assert!(matches!(error, SecretError::Read { .. }), "got: {error}");
    }

    #[test]
    fn scan_directory_fails_closed_when_path_is_missing() {
        let temp = tempfile::TempDir::new().unwrap();
        let missing = temp.path().join("does-not-exist");
        let error = SecretScanner::new()
            .scan_directory(&missing)
            .expect_err("a missing scan root must fail closed");
        assert!(matches!(error, SecretError::Read { .. }), "got: {error}");
    }

    #[test]
    fn scan_file_finds_private_key() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("key.pem");
        std::fs::write(&path, "-----BEGIN RSA PRIVATE KEY-----\nMIIE...").unwrap();
        let findings = SecretScanner::new().scan_file(&path).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.secret_type, SecretType::PrivateKey))
        );
    }
}
