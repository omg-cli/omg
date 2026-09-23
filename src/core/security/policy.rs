//! Security policy enforcement and package security grading
//!
//! Defines security policies for package approval/rejection based on
//! vulnerabilities, licenses, and trust levels with A-F grading.

use crate::package_managers::types::Version;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::core::paths;

const MAX_POLICY_BYTES: u64 = 1024 * 1024;

fn read_policy_file(path: &Path) -> io::Result<String> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Security policy must be a regular file",
        ));
    }
    if metadata.len() > MAX_POLICY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Security policy exceeds 1 MiB limit",
        ));
    }
    let mut content = String::new();
    file.take(MAX_POLICY_BYTES + 1)
        .read_to_string(&mut content)?;
    if content.len() as u64 > MAX_POLICY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Security policy exceeds 1 MiB limit",
        ));
    }
    Ok(content)
}

/// Failures from loading a security policy or checking a package against it.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("Failed to read security policy: {path}")]
    Read {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("Failed to parse security policy: {path}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("Security Grade '{grade}' for '{name}' is below required minimum '{minimum}'")]
    GradeTooLow {
        name: String,
        grade: SecurityGrade,
        minimum: SecurityGrade,
    },
    #[error("Package '{name}' is banned by security policy")]
    Banned { name: String },
    #[error("Package '{name}' is from AUR, which is disabled by security policy")]
    AurDisabled { name: String },
    #[error("Package '{name}' is unsigned; security policy requires PGP or checksum verification")]
    PgpRequired { name: String },
    #[error("Package '{name}' has license '{license}' which is not in allowed list")]
    LicenseNotAllowed { name: String, license: String },
    #[error("Package '{name}' has unknown license, but allowed list is enforced")]
    LicenseUnknown { name: String },
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityGrade {
    Risk = 0,      // Known vulnerabilities
    Community = 1, // AUR/Unsigned
    Verified = 2,  // PGP or Checksum
    Locked = 3,    // SLSA + PGP
}

impl std::fmt::Display for SecurityGrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Locked => write!(f, "LOCKED (SLSA + PGP)"),
            Self::Verified => write!(f, "VERIFIED (PGP/Checksum)"),
            Self::Community => write!(f, "COMMUNITY (AUR/Unsigned)"),
            Self::Risk => write!(f, "RISK (Vulnerabilities)"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecurityPolicy {
    #[serde(default = "default_minimum_grade")]
    pub minimum_grade: SecurityGrade,
    #[serde(default = "default_true")]
    pub allow_aur: bool,
    #[serde(default)]
    pub require_pgp: bool,
    #[serde(default)]
    pub allowed_licenses: Vec<String>,
    #[serde(default)]
    pub banned_packages: Vec<String>,
}

const fn default_minimum_grade() -> SecurityGrade {
    SecurityGrade::Community
}

const fn default_true() -> bool {
    true
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            minimum_grade: SecurityGrade::Community,
            allow_aur: true,
            require_pgp: false,
            allowed_licenses: Vec::new(),
            banned_packages: Vec::new(),
        }
    }
}

static INHERITED_POLICY: std::sync::OnceLock<SecurityPolicy> = std::sync::OnceLock::new();
pub const POLICY_MARKER: &str = "__omg_policy=";

/// The privileged child receives the parent's policy as bounded argv data,
/// since sudo resets XDG configuration environment variables.
///
/// The payload is authenticated by [`validate_inherited_policy`]: argv is
/// caller-controlled, so the child only accepts handoffs that match the
/// policy it re-derives from a root-trusted location.
pub fn inherit_policy(argument: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        crate::core::privilege::is_root(),
        "Only an elevated child can inherit policy"
    );
    let encoded = argument
        .strip_prefix(POLICY_MARKER)
        .ok_or_else(|| anyhow::anyhow!("Missing policy marker"))?;
    anyhow::ensure!(encoded.len() <= 65536, "Inherited policy exceeds limit");
    let policy = serde_json::from_slice(&hex::decode(encoded)?)?;
    validate_inherited_policy(&policy)?;
    INHERITED_POLICY
        .set(policy)
        .map_err(|_| anyhow::anyhow!("Duplicate inherited policy"))
}

/// Authenticate the elevation handoff. The argv payload is forgeable: anyone
/// permitted to run `sudo omg` can append their own `__omg_policy=` argument
/// and replace the enforced package policy (weaken `require_pgp`, empty the
/// license allowlist, re-enable AUR) without ever editing a policy file. The
/// child therefore re-derives the policy from a root-trusted location — the
/// invoking user's config directory, resolved through sudo's own `SUDO_USER`
/// identity, which the caller cannot influence — and only accepts a handoff
/// that matches it exactly. A parent policy loaded from a custom
/// `OMG_CONFIG_DIR` cannot be authenticated across sudo and fails closed.
fn validate_inherited_policy(policy: &SecurityPolicy) -> anyhow::Result<()> {
    let trusted =
        SecurityPolicy::load_optional(crate::core::paths::config_dir().join("policy.toml"))?;
    anyhow::ensure!(
        policy == &trusted,
        "Inherited elevation policy does not match the invoking user's trusted policy file; \
         refusing the forgeable policy handoff (custom OMG_CONFIG_DIR cannot cross sudo elevation)"
    );
    Ok(())
}

pub fn explicit_policy_exists() -> bool {
    INHERITED_POLICY.get().is_some() || paths::config_dir().join("policy.toml").exists()
}

pub fn policy_handoff() -> anyhow::Result<Option<String>> {
    if !explicit_policy_exists() {
        return Ok(None);
    }
    let bytes = serde_json::to_vec(&SecurityPolicy::load_default()?)?;
    anyhow::ensure!(
        bytes.len() <= 32768,
        "Security policy exceeds elevation handoff limit"
    );
    Ok(Some(format!("{POLICY_MARKER}{}", hex::encode(bytes))))
}

impl SecurityPolicy {
    /// Load policy from file. A missing file is not handled here; callers that
    /// want defaults for an absent policy should use [`Self::load_optional`].
    ///
    /// # Errors
    /// Returns [`PolicyError::Read`] for unreadable files and
    /// [`PolicyError::Parse`] for malformed TOML or unsupported policy fields.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let path = path.as_ref();
        let content = read_policy_file(path).map_err(|source| PolicyError::Read {
            path: path.display().to_string(),
            source,
        })?;
        toml::from_str(&content).map_err(|source| PolicyError::Parse {
            path: path.display().to_string(),
            source,
        })
    }

    /// Load a policy file, using the built-in default only when the file is absent.
    pub fn load_optional(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        match Self::load(&path) {
            Ok(policy) => Ok(policy),
            Err(PolicyError::Read { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                // Missing optional configuration is normal. Keep the fallback
                // visible once to verbose diagnostics without polluting routine
                // commands or machine-readable output.
                static MISSING_POLICY_LOGGED: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
                if !MISSING_POLICY_LOGGED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    tracing::debug!(
                        path = %path.as_ref().display(),
                        "No policy file; using permissive built-in default (AUR allowed)"
                    );
                }
                Ok(Self::default())
            }
            Err(error) => Err(error),
        }
    }

    /// Load from default location (~/.config/omg/policy.toml).
    /// A missing file uses the built-in default; a corrupt or unreadable file fails closed.
    pub fn load_default() -> Result<Self, PolicyError> {
        if let Some(policy) = INHERITED_POLICY.get() {
            return Ok(policy.clone());
        }
        Self::load_optional(paths::config_dir().join("policy.toml"))
    }

    /// Assign a security grade to a package based on metadata
    pub async fn assign_grade(
        &self,
        scanner: &dyn super::vulnerability::VulnerabilitySource,
        name: &str,
        version: &Version,
        is_official: bool,
    ) -> Result<SecurityGrade, super::vulnerability::VulnerabilityError> {
        // An unavailable evidence source must not be treated as a clean package.
        if !scanner.scan_package(name, version).await?.is_empty() {
            return Ok(SecurityGrade::Risk);
        }

        // Official packages are Verified (signed repository metadata). A Locked
        // grade requires provenance evidence, which this function does not have.
        if is_official {
            return Ok(SecurityGrade::Verified);
        }

        Ok(SecurityGrade::Community)
    }

    /// Check a package using the trust grade supplied by its source.
    ///
    /// Official repository metadata is treated as `Verified`; AUR and local
    /// inputs remain `Community` until a dedicated verification result exists.
    pub fn check_source(
        &self,
        name: &str,
        is_aur: bool,
        license: Option<&str>,
    ) -> Result<(), PolicyError> {
        let grade = if is_aur {
            SecurityGrade::Community
        } else {
            SecurityGrade::Verified
        };
        self.check_package(name, is_aur, license, grade)
    }

    /// Check if a package is allowed by policy
    pub fn check_package(
        &self,
        name: &str,
        is_aur: bool,
        license: Option<&str>,
        grade: SecurityGrade,
    ) -> Result<(), PolicyError> {
        if grade < self.minimum_grade {
            return Err(PolicyError::GradeTooLow {
                name: name.to_string(),
                grade,
                minimum: self.minimum_grade,
            });
        }

        if self.banned_packages.iter().any(|banned| banned == name) {
            return Err(PolicyError::Banned {
                name: name.to_string(),
            });
        }

        if is_aur && !self.allow_aur {
            return Err(PolicyError::AurDisabled {
                name: name.to_string(),
            });
        }

        if self.require_pgp && grade < SecurityGrade::Verified {
            return Err(PolicyError::PgpRequired {
                name: name.to_string(),
            });
        }

        if !self.allowed_licenses.is_empty() {
            match license {
                Some(lic) if license_matches_allowlist(lic, &self.allowed_licenses) => {}
                Some(lic) => {
                    return Err(PolicyError::LicenseNotAllowed {
                        name: name.to_string(),
                        license: lic.to_string(),
                    });
                }
                None => {
                    return Err(PolicyError::LicenseUnknown {
                        name: name.to_string(),
                    });
                }
            }
        }

        Ok(())
    }
}

/// Lowercase SPDX-ish tokens from a license expression.
pub(crate) fn spdx_license_tokens(license: &str) -> Vec<String> {
    license
        .split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+')))
        .filter(|token| !token.is_empty())
        .filter(|token| {
            !["AND", "OR", "WITH", "TO"]
                .iter()
                .any(|operator| token.eq_ignore_ascii_case(operator))
        })
        .map(str::to_ascii_lowercase)
        .collect()
}

/// True when `license` satisfies the allowlist under SPDX expression
/// semantics: `AND` requires every operand to be allowed, `OR` requires any
/// one operand to be allowed, and parentheses group sub-expressions. A
/// conjunction must not be satisfied by a single allowed token (e.g.
/// `GPL-3.0 AND MIT` is not covered by an allowlist containing only `MIT`).
/// Malformed expressions fail closed.
pub(crate) fn license_matches_allowlist(license: &str, allowed: &[String]) -> bool {
    let Some(expr) = SpdxParser::parse_expression(license) else {
        return false;
    };
    spdx_expr_allowed(&expr, allowed)
}

/// A parsed SPDX license expression: an identifier (optionally carrying a
/// `WITH` exception, evaluated by its base identifier), a conjunction, a
/// disjunction, or a parenthesized grouping.
#[derive(Debug, Clone, PartialEq)]
enum SpdxExpr {
    Id(String),
    With { id: String },
    And(Box<SpdxExpr>, Box<SpdxExpr>),
    Or(Box<SpdxExpr>, Box<SpdxExpr>),
}

fn spdx_expr_allowed(expr: &SpdxExpr, allowed: &[String]) -> bool {
    match expr {
        SpdxExpr::Id(id) | SpdxExpr::With { id } => spdx_id_allowed(id, allowed),
        SpdxExpr::And(left, right) => {
            spdx_expr_allowed(left, allowed) && spdx_expr_allowed(right, allowed)
        }
        SpdxExpr::Or(left, right) => {
            spdx_expr_allowed(left, allowed) || spdx_expr_allowed(right, allowed)
        }
    }
}

/// Whole-token identifier match preserving the historical `+` suffix rules:
/// `MIT+` satisfies an `MIT` entry and `MIT` satisfies an `MIT+` entry.
fn spdx_id_allowed(id: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|allowed| {
        id.eq_ignore_ascii_case(allowed)
            || id
                .strip_suffix('+')
                .is_some_and(|base| base.eq_ignore_ascii_case(allowed))
            || allowed
                .strip_suffix('+')
                .is_some_and(|base| id.eq_ignore_ascii_case(base))
    })
}

#[derive(Debug, Clone, PartialEq)]
enum SpdxToken {
    Id(String),
    And,
    Or,
    With,
    Open,
    Close,
}

fn spdx_tokenize(license: &str) -> Vec<SpdxToken> {
    fn push_word(tokens: &mut Vec<SpdxToken>, word: &mut String) {
        if word.is_empty() {
            return;
        }
        if word.eq_ignore_ascii_case("AND") {
            tokens.push(SpdxToken::And);
        } else if word.eq_ignore_ascii_case("OR") {
            tokens.push(SpdxToken::Or);
        } else if word.eq_ignore_ascii_case("WITH") {
            tokens.push(SpdxToken::With);
        } else {
            tokens.push(SpdxToken::Id(word.to_ascii_lowercase()));
        }
        word.clear();
    }

    let mut tokens = Vec::new();
    let mut word = String::new();
    for character in license.chars() {
        match character {
            '(' => {
                push_word(&mut tokens, &mut word);
                tokens.push(SpdxToken::Open);
            }
            ')' => {
                push_word(&mut tokens, &mut word);
                tokens.push(SpdxToken::Close);
            }
            c if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+') => word.push(c),
            _ => push_word(&mut tokens, &mut word),
        }
    }
    push_word(&mut tokens, &mut word);
    tokens
}

/// Recursive-descent parser for SPDX expressions with `AND` binding tighter
/// than `OR`. Juxtaposed identifiers without an operator keep the historical
/// any-token (OR) semantics instead of failing previously-accepted inputs.
struct SpdxParser {
    tokens: Vec<SpdxToken>,
    pos: usize,
}

impl SpdxParser {
    fn parse_expression(license: &str) -> Option<SpdxExpr> {
        let mut parser = Self {
            tokens: spdx_tokenize(license),
            pos: 0,
        };
        let expr = parser.parse_or()?;
        if parser.pos == parser.tokens.len() {
            Some(expr)
        } else {
            None
        }
    }

    fn peek(&self) -> Option<&SpdxToken> {
        self.tokens.get(self.pos)
    }

    fn eat(&mut self, expected: &SpdxToken) -> bool {
        if self.peek() == Some(expected) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn parse_or(&mut self) -> Option<SpdxExpr> {
        let mut expr = self.parse_and()?;
        while self.eat(&SpdxToken::Or) {
            let right = self.parse_and()?;
            expr = SpdxExpr::Or(Box::new(expr), Box::new(right));
        }
        Some(expr)
    }

    fn parse_and(&mut self) -> Option<SpdxExpr> {
        let mut expr = self.parse_atom()?;
        loop {
            if self.eat(&SpdxToken::And) {
                let right = self.parse_atom()?;
                expr = SpdxExpr::And(Box::new(expr), Box::new(right));
            } else if matches!(self.peek(), Some(SpdxToken::Id(_) | SpdxToken::Open)) {
                // Juxtaposition: legacy operator-less input stays OR-any.
                let right = self.parse_atom()?;
                expr = SpdxExpr::Or(Box::new(expr), Box::new(right));
            } else {
                break;
            }
        }
        Some(expr)
    }

    fn parse_atom(&mut self) -> Option<SpdxExpr> {
        match self.peek()? {
            SpdxToken::Open => {
                self.pos += 1;
                let expr = self.parse_or()?;
                self.eat(&SpdxToken::Close).then_some(expr)
            }
            SpdxToken::Id(id) => {
                let id = id.clone();
                self.pos += 1;
                if self.eat(&SpdxToken::With) {
                    match self.peek() {
                        Some(SpdxToken::Id(_)) => {
                            self.pos += 1;
                            Some(SpdxExpr::With { id })
                        }
                        _ => None,
                    }
                } else {
                    Some(SpdxExpr::Id(id))
                }
            }
            _ => None,
        }
    }
}

/// Separate package metadata entries describe cumulative obligations. Preserve
/// alternatives inside each entry without allowing them to escape the AND.
pub fn combined_license_expression<'a>(
    licenses: impl IntoIterator<Item = &'a str>,
) -> Option<String> {
    let entries = licenses
        .into_iter()
        .map(|license| format!("({license})"))
        .collect::<Vec<_>>();
    (!entries.is_empty()).then(|| entries.join(" AND "))
}

pub fn require_native_plan_support(backend: &str) -> anyhow::Result<()> {
    let policy = SecurityPolicy::load_default()?;
    anyhow::ensure!(
        !explicit_policy_exists() && policy == SecurityPolicy::default(),
        "{backend} cannot enforce an explicit OMG policy on its final dependency transaction; use a backend with prepared-plan policy enforcement"
    );
    Ok(())
}

/// Evaluate all additions after resolution, using actual archive/repository identities.
pub fn check_prepared_packages(
    packages: Vec<(String, Version, bool, Option<String>)>,
) -> anyhow::Result<()> {
    let policy = SecurityPolicy::load_default()?;
    if !explicit_policy_exists() {
        for (name, _, community, license) in packages {
            policy.check_source(&name, community, license.as_deref())?;
        }
        return Ok(());
    }
    // ALPM's synchronous callback may run inside a Tokio current-thread runtime.
    // A separate bounded worker owns its runtime rather than nesting block_on.
    std::thread::spawn(move || -> anyhow::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async move {
            let scanner = super::vulnerability::VulnerabilityScanner::new();
            check_prepared_with_source(&policy, packages, &scanner).await
        })
    })
    .join()
    .map_err(|_| anyhow::anyhow!("Prepared transaction policy worker failed"))?
}

async fn check_prepared_with_source(
    policy: &SecurityPolicy,
    packages: Vec<(String, Version, bool, Option<String>)>,
    scanner: &dyn super::vulnerability::VulnerabilitySource,
) -> anyhow::Result<()> {
    for (name, version, community, license) in packages {
        policy.check_source(&name, community, license.as_deref())?;
        let grade = policy
            .assign_grade(scanner, &name, &version, !community)
            .await?;
        policy.check_package(&name, community, license.as_deref(), grade)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::security::vulnerability::VulnerabilityError;

    #[test]
    fn separate_license_entries_preserve_all_obligations_and_group_alternatives() {
        let policy = SecurityPolicy {
            allowed_licenses: vec!["MIT".into()],
            ..SecurityPolicy::default()
        };
        let licenses = combined_license_expression(["MIT", "GPL-3.0"]);
        assert!(
            policy
                .check_source("multi", false, licenses.as_deref())
                .is_err()
        );
        let alternatives = combined_license_expression(["MIT OR Apache-2.0", "GPL-3.0"]);
        assert!(
            policy
                .check_source("multi", false, alternatives.as_deref())
                .is_err()
        );
        let allowed = combined_license_expression(["MIT"]);
        assert!(
            policy
                .check_source("single", false, allowed.as_deref())
                .is_ok()
        );
        assert!(combined_license_expression(std::iter::empty()).is_none());
    }

    #[test]
    fn test_grade_ordering() {
        assert!(SecurityGrade::Locked > SecurityGrade::Verified);
        assert!(SecurityGrade::Verified > SecurityGrade::Community);
        assert!(SecurityGrade::Community > SecurityGrade::Risk);
    }

    #[test]
    fn source_policy_assigns_verified_grade_only_to_official_packages() {
        let policy = SecurityPolicy {
            minimum_grade: SecurityGrade::Verified,
            ..SecurityPolicy::default()
        };
        assert!(policy.check_source("system", false, None).is_ok());
        assert!(matches!(
            policy.check_source("community", true, None),
            Err(PolicyError::GradeTooLow { .. })
        ));
    }

    #[test]
    fn test_policy_check_grade() {
        let policy = SecurityPolicy {
            minimum_grade: SecurityGrade::Verified,
            ..SecurityPolicy::default()
        };

        // Verified is allowed
        assert!(
            policy
                .check_package("test", false, None, SecurityGrade::Verified)
                .is_ok()
        );

        // Locked is allowed
        assert!(
            policy
                .check_package("test", false, None, SecurityGrade::Locked)
                .is_ok()
        );

        // Community is blocked
        let err = policy
            .check_package("test", true, None, SecurityGrade::Community)
            .expect_err("Community is below Verified");
        assert!(
            matches!(err, PolicyError::GradeTooLow { .. }),
            "grade failures must be typed, got: {err}"
        );
    }

    #[test]
    fn load_optional_uses_defaults_when_policy_is_missing() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let policy = SecurityPolicy::load_optional(temp.path().join("policy.toml"))
            .expect("missing policy should use defaults");
        assert_eq!(policy.minimum_grade, SecurityGrade::Community);
        assert!(policy.allow_aur);
    }

    #[test]
    fn load_optional_rejects_unsupported_security_fields_without_rewriting() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let path = temp.path().join("policy.toml");
        for (field, value) in [
            ("max_cve_severity", "7.0"),
            ("require_sbom", "true"),
            ("verify_slsa", "true"),
            ("trusted_maintainers", "[\"maintainer\"]"),
            ("allow_ar", "false"),
        ] {
            let input = format!("allow_aur = false\n{field} = {value}\n");
            fs::write(&path, &input).expect("write policy");
            let error = SecurityPolicy::load_optional(&path)
                .expect_err("unsupported security options must not be silently ignored");
            let PolicyError::Parse { source, .. } = error else {
                panic!("unknown security fields must produce a parse error");
            };
            assert!(source.to_string().contains("unknown field"));
            assert!(source.to_string().contains(field));
            assert_eq!(
                fs::read_to_string(&path).expect("read original policy"),
                input
            );
        }
    }

    #[test]
    fn supported_policy_roundtrips_through_file_and_elevation_payload() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let path = temp.path().join("policy.toml");
        let policy = SecurityPolicy {
            minimum_grade: SecurityGrade::Verified,
            allow_aur: false,
            require_pgp: true,
            allowed_licenses: vec!["MIT".to_string()],
            banned_packages: vec!["banned".to_string()],
        };
        fs::write(&path, toml::to_string(&policy).expect("serialize policy"))
            .expect("write policy");
        assert_eq!(
            SecurityPolicy::load_optional(&path).expect("load policy"),
            policy
        );
        let payload = serde_json::to_vec(&policy).expect("serialize elevation policy");
        assert_eq!(
            serde_json::from_slice::<SecurityPolicy>(&payload).expect("read elevation policy"),
            policy
        );
        assert!(serde_json::from_str::<SecurityPolicy>(r#"{"verify_slsa":true}"#).is_err());
    }

    #[test]
    fn load_optional_rejects_corrupt_policy() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let path = temp.path().join("policy.toml");
        fs::write(&path, "minimum_grade = [").expect("write corrupt policy");
        let error = SecurityPolicy::load_optional(&path).expect_err("corrupt policy must fail");
        assert!(
            error
                .to_string()
                .contains("Failed to parse security policy")
        );
    }

    #[cfg(unix)]
    #[test]
    fn policy_loader_rejects_symlinks_fifos_and_oversized_files() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("policy fixture");
        let valid = temp.path().join("valid.toml");
        fs::write(&valid, "allow_aur = false\n").expect("write valid policy");
        assert!(
            !SecurityPolicy::load(&valid)
                .expect("regular policy")
                .allow_aur
        );

        let linked = temp.path().join("linked.toml");
        symlink(&valid, &linked).expect("create policy symlink");
        assert!(matches!(
            SecurityPolicy::load(&linked),
            Err(PolicyError::Read { .. })
        ));

        let fifo = temp.path().join("fifo.toml");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRUSR).expect("create policy FIFO");
        assert!(matches!(
            SecurityPolicy::load(&fifo),
            Err(PolicyError::Read { .. })
        ));

        let oversized = temp.path().join("oversized.toml");
        fs::write(&oversized, vec![b' '; MAX_POLICY_BYTES as usize + 1])
            .expect("write oversized policy");
        assert!(matches!(
            SecurityPolicy::load(&oversized),
            Err(PolicyError::Read { .. })
        ));
    }

    struct EmptyVulns;

    impl super::super::vulnerability::VulnerabilitySource for EmptyVulns {
        fn scan_package<'a>(
            &'a self,
            _name: &'a str,
            _version: &'a crate::package_managers::types::Version,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            Vec<crate::core::security::vulnerability::VulnerabilityReport>,
                            VulnerabilityError,
                        >,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    struct FailingVulns;

    impl super::super::vulnerability::VulnerabilitySource for FailingVulns {
        fn scan_package<'a>(
            &'a self,
            _name: &'a str,
            _version: &'a crate::package_managers::types::Version,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            Vec<crate::core::security::vulnerability::VulnerabilityReport>,
                            VulnerabilityError,
                        >,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async {
                Err(VulnerabilityError::Unavailable {
                    reason: "osv unavailable".to_string(),
                })
            })
        }
    }

    #[tokio::test]
    async fn prepared_plan_checks_dependencies_and_actual_licenses() {
        let mut policy = SecurityPolicy {
            allowed_licenses: vec!["MIT".to_owned()],
            ..SecurityPolicy::default()
        };
        let package = |name: &str, license: &str| {
            (
                name.to_owned(),
                crate::package_managers::parse_version_or_zero("1.0"),
                false,
                Some(license.to_owned()),
            )
        };
        super::check_prepared_with_source(
            &policy,
            vec![package("app", "MIT"), package("dependency", "MIT")],
            &EmptyVulns,
        )
        .await
        .unwrap();
        policy.banned_packages.push("dependency".to_owned());
        assert!(
            super::check_prepared_with_source(
                &policy,
                vec![package("app", "MIT"), package("dependency", "MIT")],
                &EmptyVulns
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("dependency")
        );
        policy.banned_packages.clear();
        assert!(
            super::check_prepared_with_source(
                &policy,
                vec![package("app", "GPL-3.0")],
                &EmptyVulns
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn known_findings_remain_risky_without_a_numeric_score() {
        use super::super::vulnerability::{VulnerabilityReport, VulnerabilitySource};
        use crate::package_managers::types::VersionDisplay;
        struct Finding(Option<String>);
        impl VulnerabilitySource for Finding {
            fn scan_package<'a>(
                &'a self,
                name: &'a str,
                version: &'a Version,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<Vec<VulnerabilityReport>, VulnerabilityError>,
                        > + Send
                        + 'a,
                >,
            > {
                assert_eq!(name, "candidate");
                assert_eq!(version.version_string(), "1.0.0");
                Box::pin(async move {
                    Ok(vec![VulnerabilityReport {
                        id: "fixture-advisory".to_owned(),
                        summary: "Known vulnerable candidate".to_owned(),
                        score: self.0.clone(),
                    }])
                })
            }
        }
        let version = crate::package_managers::parse_version("1.0.0").unwrap();
        let policy = SecurityPolicy {
            minimum_grade: SecurityGrade::Verified,
            ..SecurityPolicy::default()
        };
        for score in [None, Some("0"), Some("9.8")] {
            for official in [false, true] {
                let source = Finding(score.map(str::to_owned));
                let grade = policy
                    .assign_grade(&source, "candidate", &version, official)
                    .await
                    .unwrap();
                assert_eq!(
                    grade,
                    SecurityGrade::Risk,
                    "score={score:?}, official={official}"
                );
                assert!(matches!(
                    policy.check_package("candidate", !official, Some("MIT"), grade),
                    Err(PolicyError::GradeTooLow {
                        grade: SecurityGrade::Risk,
                        ..
                    })
                ));
            }
        }
    }

    #[tokio::test]
    async fn official_packages_are_verified_not_locked_by_name() {
        let policy = SecurityPolicy::default();
        let version = crate::package_managers::parse_version_or_zero("2.40");
        let grade = policy
            .assign_grade(&EmptyVulns, "glibc", &version, true)
            .await
            .expect("empty vuln source");
        assert_eq!(
            grade,
            SecurityGrade::Verified,
            "package names must not mint a Locked SLSA grade"
        );
    }

    #[tokio::test]
    async fn aur_packages_are_community() {
        let policy = SecurityPolicy::default();
        let version = crate::package_managers::parse_version_or_zero("1.0");
        let grade = policy
            .assign_grade(&EmptyVulns, "yay", &version, false)
            .await
            .expect("empty vuln source");
        assert_eq!(grade, SecurityGrade::Community);
    }

    #[tokio::test]
    async fn unavailable_vuln_source_fails_closed() {
        let policy = SecurityPolicy::default();
        let version = crate::package_managers::parse_version_or_zero("1.0");
        let error = policy
            .assign_grade(&FailingVulns, "vim", &version, true)
            .await
            .expect_err("missing evidence must not look like a clean package");
        assert!(
            matches!(
                error,
                VulnerabilityError::Unavailable { ref reason } if reason == "osv unavailable"
            ),
            "scanner error must be preserved, got: {error}"
        );
    }

    #[test]
    fn require_pgp_rejects_unsigned_packages() {
        let policy = SecurityPolicy {
            require_pgp: true,
            ..SecurityPolicy::default()
        };
        let err = policy
            .check_package("yay", true, Some("MIT"), SecurityGrade::Community)
            .expect_err("AUR community packages are unsigned");
        assert!(
            matches!(err, PolicyError::PgpRequired { .. }),
            "require_pgp must be a typed unsigned-package error, got: {err}"
        );
        assert!(
            policy
                .check_package("vim", false, Some("MIT"), SecurityGrade::Verified)
                .is_ok()
        );
    }

    #[test]
    fn allowed_license_matches_spdx_tokens_not_substrings() {
        let policy = SecurityPolicy {
            allowed_licenses: vec!["MIT".to_string()],
            ..SecurityPolicy::default()
        };
        let err = policy
            .check_package("foo", false, Some("LIMITED"), SecurityGrade::Verified)
            .expect_err("LIMITED must not match MIT");
        assert!(
            matches!(err, PolicyError::LicenseNotAllowed { .. }),
            "allowlist mismatches must be typed, got: {err}"
        );
        assert!(
            policy
                .check_package(
                    "foo",
                    false,
                    Some("MIT OR Apache-2.0"),
                    SecurityGrade::Verified
                )
                .is_ok()
        );
    }

    #[test]
    fn compound_spdx_and_requires_all_operands_allowed() {
        let mit_only = SecurityPolicy {
            allowed_licenses: vec!["MIT".to_string()],
            ..SecurityPolicy::default()
        };
        // One allowed token must not satisfy an AND expression.
        let err = mit_only
            .check_package(
                "foo",
                false,
                Some("MIT AND GPL-3.0"),
                SecurityGrade::Verified,
            )
            .expect_err("AND requires every operand to be allowed");
        assert!(
            matches!(err, PolicyError::LicenseNotAllowed { .. }),
            "AND violations must be typed, got: {err}"
        );

        let both = SecurityPolicy {
            allowed_licenses: vec!["MIT".to_string(), "GPL-3.0".to_string()],
            ..SecurityPolicy::default()
        };
        assert!(
            both.check_package(
                "foo",
                false,
                Some("MIT AND GPL-3.0"),
                SecurityGrade::Verified
            )
            .is_ok()
        );
    }

    #[test]
    fn spdx_expression_precedence_is_enforced() {
        let mit = &["MIT".to_string()];
        let mit_apache = &["MIT".to_string(), "Apache-2.0".to_string()];

        // OR-any semantics are preserved.
        assert!(license_matches_allowlist("GPL-3.0 OR MIT", mit));
        assert!(license_matches_allowlist("GPL-3.0 OR MIT", mit_apache));
        assert!(license_matches_allowlist("MIT+ OR GPL-3.0", mit));

        // AND requires every operand, even inside groupings.
        assert!(!license_matches_allowlist("MIT AND GPL-3.0", mit));
        assert!(!license_matches_allowlist(
            "(GPL-3.0 OR MIT) AND Apache-2.0",
            mit
        ));
        assert!(license_matches_allowlist(
            "(GPL-3.0 OR MIT) AND Apache-2.0",
            mit_apache
        ));

        // WITH exceptions evaluate by their base identifier.
        let gpl = &["GPL-2.0".to_string()];
        assert!(license_matches_allowlist(
            "GPL-2.0 WITH Classpath-exception-2.0",
            gpl
        ));

        // Malformed expressions fail closed instead of matching loosely.
        assert!(!license_matches_allowlist("MIT AND", mit));
        assert!(!license_matches_allowlist("(MIT", mit));
        assert!(!license_matches_allowlist("MIT)", mit));
        assert!(!license_matches_allowlist("MIT OR OR Apache-2.0", mit));
        assert!(!license_matches_allowlist("MIT WITH", mit));
    }

    #[test]
    #[serial_test::serial]
    fn forged_elevation_policy_handoff_is_rejected() {
        if crate::config::Settings::rerun_config_test_unprivileged(
            "core::security::policy::tests::forged_elevation_policy_handoff_is_rejected",
        ) {
            return;
        }
        let temp = tempfile::TempDir::new().expect("temp dir");
        temp_env::with_var("OMG_CONFIG_DIR", Some(temp.path()), || {
            let strict = SecurityPolicy {
                require_pgp: true,
                allow_aur: false,
                minimum_grade: SecurityGrade::Verified,
                ..SecurityPolicy::default()
            };

            // No trusted policy file: only the built-in default may cross sudo.
            assert!(validate_inherited_policy(&SecurityPolicy::default()).is_ok());
            assert!(
                validate_inherited_policy(&strict)
                    .err()
                    .is_some_and(|error| error.to_string().contains("forgeable policy handoff")),
                "a forged permissive handoff must not replace the trusted policy"
            );

            // With a trusted policy file, only its exact content is accepted.
            fs::write(
                temp.path().join("policy.toml"),
                toml::to_string(&strict).expect("serialize policy"),
            )
            .expect("write policy");
            assert!(validate_inherited_policy(&strict).is_ok());
            assert!(validate_inherited_policy(&SecurityPolicy::default()).is_err());

            // A weakened variant of the same policy is rejected byte-for-byte.
            let weakened = SecurityPolicy {
                allow_aur: true,
                ..strict
            };
            assert!(validate_inherited_policy(&weakened).is_err());
        });
    }
}
