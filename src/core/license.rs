//! Optional dashboard account identity
//!
//! A linked account attributes opted-in usage to the OMG dashboard. It is not
//! a feature gate: every CLI command works without one.
//!
//! ## JWT identity
//! - `omg account link` stores a signed JWT from the dashboard API
//! - The token carries expiry and optional machine binding
//! - Signature is verified offline; a bad or expired token cannot attribute
//!   usage, but it never locks local commands

use anyhow::{Context, Result};
use jsonwebtoken::{DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::OnceLock;

use crate::cli::style::sanitize_terminal_text;
use crate::core::http::BoundedResponseExt;

const LICENSE_TOKEN_ISSUER: &str = super::service_api::ORIGIN;
const LICENSE_TOKEN_AUDIENCE: &str = "omg-cli";

/// Production Ed25519 public key used for offline license-token verification.
///
/// The matching public artifact is published at
/// `https://getomg.xyz/.well-known/omg-license-ed25519-v1.pem`.
const LICENSE_JWT_VERIFICATION_KEY: &[u8] = b"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA0TzkAlaX2+uVvrUh0VE4LO9HjBtDx7dt469do025EKg=
-----END PUBLIC KEY-----
";

/// Historical dashboard-plan labels carried on the JWT `tier` claim.
/// They are identity metadata only and never gate CLI features.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Free,
    Pro,
    Team,
    Enterprise,
}

/// Error returned when a tier string does not name a known tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownTier;

impl std::fmt::Display for UnknownTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("unknown account plan label")
    }
}

impl std::error::Error for UnknownTier {}

impl Tier {
    /// Parses a tier name, returning `None` for unknown input instead of
    /// silently coercing it to a tier.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        s.parse().ok()
    }

    /// Returns the string representation of this tier
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Pro => "pro",
            Self::Team => "team",
            Self::Enterprise => "enterprise",
        }
    }

    /// Returns the display name of this tier
    #[must_use]
    pub const fn display_name(&self) -> &'static str {
        match self {
            Self::Free => "Free",
            Self::Pro => "Pro",
            Self::Team => "Team",
            Self::Enterprise => "Enterprise",
        }
    }
}

impl FromStr for Tier {
    type Err = UnknownTier;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "free" => Ok(Self::Free),
            "pro" => Ok(Self::Pro),
            "team" => Ok(Self::Team),
            "enterprise" => Ok(Self::Enterprise),
            _ => Err(UnknownTier),
        }
    }
}

/// Named CLI capabilities. Every known feature is available without an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    // Free features
    Packages,
    Runtimes,
    Container,
    EnvCapture,
    EnvShare,
    // Pro features
    Sbom,
    Audit,
    Secrets,
    // Team features
    Fleet,
    TeamSync,
    TeamConfig,
    AuditLog,
    // Enterprise features
    Policy,
    Slsa,
    Sso,
    PrioritySupport,
    EnterpriseReports,
    AuditExport,
    LicenseScan,
    Compliance,
    SelfHosted,
}

impl Feature {
    /// Historical plan label associated with this feature. Unused for gating.
    #[must_use]
    pub const fn required_tier(&self) -> Tier {
        match self {
            // Free
            Self::Packages
            | Self::Runtimes
            | Self::Container
            | Self::EnvCapture
            | Self::EnvShare => Tier::Free,
            // Pro
            Self::Sbom | Self::Audit | Self::Secrets => Tier::Pro,
            // Team
            Self::Fleet | Self::TeamSync | Self::TeamConfig | Self::AuditLog => Tier::Team,
            // Enterprise
            Self::Policy
            | Self::Slsa
            | Self::Sso
            | Self::PrioritySupport
            | Self::EnterpriseReports
            | Self::AuditExport
            | Self::LicenseScan
            | Self::Compliance
            | Self::SelfHosted => Tier::Enterprise,
        }
    }

    #[expect(
        clippy::should_implement_trait,
        reason = "Returns Option instead of Result for convenience"
    )]
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "packages" => Some(Self::Packages),
            "runtimes" => Some(Self::Runtimes),
            "container" => Some(Self::Container),
            "env-capture" | "env_capture" => Some(Self::EnvCapture),
            "env-share" | "env_share" => Some(Self::EnvShare),
            "sbom" => Some(Self::Sbom),
            "audit" => Some(Self::Audit),
            "secrets" => Some(Self::Secrets),
            "fleet" => Some(Self::Fleet),
            "team-sync" | "team_sync" => Some(Self::TeamSync),
            "team-config" | "team_config" => Some(Self::TeamConfig),
            "audit-log" | "audit_log" => Some(Self::AuditLog),
            "policy" | "enterprise-policy" | "enterprise_policy" => Some(Self::Policy),
            "slsa" => Some(Self::Slsa),
            "sso" => Some(Self::Sso),
            "priority-support" | "priority_support" => Some(Self::PrioritySupport),
            "enterprise-reports" | "enterprise_reports" => Some(Self::EnterpriseReports),
            "audit-export" | "audit_export" => Some(Self::AuditExport),
            "license-scan" | "license_scan" => Some(Self::LicenseScan),
            "compliance" => Some(Self::Compliance),
            "self-hosted" | "self_hosted" => Some(Self::SelfHosted),
            _ => None,
        }
    }

    /// Returns the string representation of this feature
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Packages => "packages",
            Self::Runtimes => "runtimes",
            Self::Container => "container",
            Self::EnvCapture => "env-capture",
            Self::EnvShare => "env-share",
            Self::Sbom => "sbom",
            Self::Audit => "audit",
            Self::Secrets => "secrets",
            Self::Fleet => "fleet",
            Self::TeamSync => "team-sync",
            Self::TeamConfig => "team-config",
            Self::AuditLog => "audit-log",
            Self::Policy => "policy",
            Self::Slsa => "slsa",
            Self::Sso => "sso",
            Self::PrioritySupport => "priority-support",
            Self::EnterpriseReports => "enterprise-reports",
            Self::AuditExport => "audit-export",
            Self::LicenseScan => "license-scan",
            Self::Compliance => "compliance",
            Self::SelfHosted => "self-hosted",
        }
    }

    /// Returns the display name of this feature
    #[must_use]
    pub const fn display_name(&self) -> &'static str {
        match self {
            Self::Packages => "Package Management",
            Self::Runtimes => "Runtime Version Switching",
            Self::Container => "Container Integration",
            Self::EnvCapture => "Environment Fingerprinting",
            Self::EnvShare => "Gist Sharing",
            Self::Sbom => "SBOM Generation (CycloneDX)",
            Self::Audit => "Vulnerability Scanning",
            Self::Secrets => "Secret Detection",
            Self::Fleet => "Fleet Management",
            Self::TeamSync => "Team Environment Sync",
            Self::TeamConfig => "Shared Team Configs",
            Self::AuditLog => "Tamper-evident Audit Logs",
            Self::Policy => "Policy Enforcement",
            Self::Slsa => "SLSA Provenance Verification",
            Self::Sso => "SSO/SAML Integration",
            Self::PrioritySupport => "Priority Support",
            Self::EnterpriseReports => "Executive Reports",
            Self::AuditExport => "Compliance Audit Export",
            Self::LicenseScan => "License Compliance Scan",
            Self::Compliance => "Compliance Evidence Export",
            Self::SelfHosted => "Self-Hosted Server",
        }
    }
}

/// All features grouped by tier
pub const FREE_FEATURES: &[Feature] = &[
    Feature::Packages,
    Feature::Runtimes,
    Feature::Container,
    Feature::EnvCapture,
    Feature::EnvShare,
];

pub const PRO_FEATURES: &[Feature] = &[Feature::Sbom, Feature::Audit, Feature::Secrets];

pub const TEAM_FEATURES: &[Feature] = &[
    Feature::Fleet,
    Feature::TeamSync,
    Feature::TeamConfig,
    Feature::AuditLog,
];

pub const ENTERPRISE_FEATURES: &[Feature] = &[
    Feature::Policy,
    Feature::Slsa,
    Feature::Sso,
    Feature::PrioritySupport,
    Feature::EnterpriseReports,
    Feature::AuditExport,
    Feature::LicenseScan,
    Feature::Compliance,
    Feature::SelfHosted,
];

/// License response from the validation API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseResponse {
    pub valid: bool,
    pub tier: Option<String>,
    pub features: Option<Vec<String>>,
    pub customer: Option<String>,
    pub expires_at: Option<String>,
    pub token: Option<String>, // Signed JWT for offline validation
    pub error: Option<String>,
}

/// JWT payload structure (matches backend)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtPayload {
    pub iss: String,           // trusted licensing Worker origin
    pub aud: String,           // intended OMG CLI audience
    pub sub: String,           // customer_id
    pub tier: String,          // license tier
    pub features: Vec<String>, // enabled features
    pub exp: i64,              // expiration timestamp
    pub iat: i64,              // issued at
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mid: Option<String>, // machine_id (optional binding)
    pub lic: String,           // license_key for reference
}

/// Stored license information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredLicense {
    pub key: String,
    pub tier: String,
    pub features: Vec<String>,
    pub customer: Option<String>,
    pub expires_at: Option<String>,
    pub validated_at: i64,
    pub token: Option<String>,      // JWT token for offline validation
    pub machine_id: Option<String>, // Bound machine ID
}

/// Team member info returned from API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamMember {
    pub machine_id: String,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub arch: Option<String>,
    pub omg_version: Option<String>,
    pub last_seen_at: String,
    pub is_active: bool,
}

/// Policy rule returned from API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub scope: String,
    pub rule: String,
    pub enforced: bool,
}

/// Audit log entry returned from API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: String,
}

impl StoredLicense {
    fn verified_payload(&self) -> Option<JwtPayload> {
        self.verified_payload_with_key(LICENSE_JWT_VERIFICATION_KEY)
    }

    fn verified_payload_with_key(&self, verification_key: &[u8]) -> Option<JwtPayload> {
        let token = self.token.as_deref()?;
        // Observe wall-clock time before JWT `exp` can reject. A first run
        // after expiry must still raise the persisted floor; otherwise a
        // later clock rollback can revive the same token.
        let observed_floor = match license_clock_floor() {
            Ok(observed_floor) => observed_floor,
            Err(error) => {
                tracing::warn!(error = %error, "Failed to enforce the license clock watermark");
                return None;
            }
        };
        let payload = verify_jwt_with_key(token, verification_key)?;
        if payload.lic != self.key {
            return None;
        }
        if let Some(bound_machine_id) = payload.mid.as_deref()
            && bound_machine_id != get_machine_id()
        {
            return None;
        }
        // Clock-rollback defense: expiry is judged against a persisted
        // high-water mark of observed wall-clock time, not just the mutable
        // system clock. A token whose expiry predates the watermark is dead
        // even if the current (rolled-back) clock says otherwise.
        if payload.exp <= observed_floor {
            tracing::warn!(
                exp = payload.exp,
                observed_floor,
                "License token expired as of the observed-time high-water mark \
                 (system clock rollback suspected)"
            );
            return None;
        }
        Some(payload)
    }

    /// Return the tier authorized by the signed, unexpired license token.
    #[must_use]
    pub fn tier_enum(&self) -> Tier {
        self.verified_payload()
            .and_then(|payload| Tier::parse(&payload.tier))
            .unwrap_or(Tier::Free)
    }

    /// Check if the stored token and its license/machine bindings are valid.
    #[must_use]
    pub fn is_token_valid(&self) -> bool {
        self.verified_payload().is_some()
    }
}

/// Observed-time high-water mark for license verification (anti clock-rollback).
fn license_clock_watermark_path() -> PathBuf {
    #[cfg(test)]
    let override_path = { WATERMARK_PATH_OVERRIDE.with(|cell| cell.borrow().clone()) };
    #[cfg(test)]
    if let Some(override_path) = override_path {
        return override_path;
    }
    crate::core::paths::data_dir().join("license-clock.highwater")
}

#[cfg(test)]
thread_local! {
    static WATERMARK_PATH_OVERRIDE: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
struct WatermarkPathGuard;

#[cfg(test)]
impl Drop for WatermarkPathGuard {
    fn drop(&mut self) {
        WATERMARK_PATH_OVERRIDE.with(|slot| *slot.borrow_mut() = None);
    }
}

#[cfg(test)]
fn override_watermark_path(path: PathBuf) -> WatermarkPathGuard {
    WATERMARK_PATH_OVERRIDE.with(|slot| {
        *slot.borrow_mut() = Some(path);
    });
    WatermarkPathGuard
}

/// Read the persisted high-water mark. Missing state is initialized on first
/// use; unreadable or malformed state is rejected so clock rollback protection
/// cannot silently reset.
fn load_clock_watermark(path: &Path) -> Result<Option<i64>> {
    match std::fs::read_to_string(path) {
        Ok(content) => content
            .trim()
            .parse::<i64>()
            .map(Some)
            .with_context(|| format!("Malformed license clock watermark: {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("Failed to read license clock watermark: {}", path.display())),
    }
}

/// Advance and return the observed-time floor: `max(stored, now)`.
/// A sibling lock serializes the read-modify-write sequence across processes,
/// so a delayed writer cannot replace a newer watermark with an older value.
fn license_clock_floor_with(path: &Path, now: i64) -> Result<i64> {
    let parent = path
        .parent()
        .context("License clock watermark path must have a parent directory")?;
    crate::core::paths::create_private_data_directory(parent).with_context(|| {
        format!(
            "Failed to create license clock watermark directory: {}",
            parent.display()
        )
    })?;

    let lock_path = path.with_extension("lock");
    let mut options = std::fs::OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
    }
    let lock = options
        .open(&lock_path)
        .with_context(|| format!("Failed to open license clock lock: {}", lock_path.display()))?;
    lock.lock()
        .with_context(|| format!("Failed to lock license clock: {}", lock_path.display()))?;

    let result: Result<i64> = (|| {
        let stored = load_clock_watermark(path)?;
        let floor = stored.unwrap_or(now).max(now);
        if stored != Some(floor) {
            crate::core::safe_ops::atomic_write_file_sync(path, floor.to_string().as_bytes())
                .context("Failed to persist license clock watermark")?;
        }
        Ok(floor)
    })();

    if let Err(error) = lock.unlock() {
        return match result {
            Ok(_) => Err(error).context("Failed to unlock license clock"),
            Err(operation_error) => Err(operation_error.context(format!(
                "License clock update also failed to unlock its lock: {error}"
            ))),
        };
    }
    result
}

pub(crate) fn license_clock_floor() -> Result<i64> {
    let path = license_clock_watermark_path();
    let now = jiff::Timestamp::now().as_second();
    license_clock_floor_with(&path, now)
}

static MACHINE_ID: OnceLock<String> = OnceLock::new();

/// Get machine fingerprint for license binding.
#[must_use]
pub fn get_machine_id() -> String {
    MACHINE_ID.get_or_init(compute_machine_id).clone()
}

fn compute_machine_id() -> String {
    // Use only the machine-id source that is stable across privilege changes.
    // DMI identifiers are commonly root-readable only, so including every
    // readable source produced different fingerprints before and after sudo.
    let identity = std::fs::read_to_string("/etc/machine-id")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(persisted_machine_id_fallback);

    let hash = sha256_hex(identity.as_bytes());
    let fingerprint = &hash[..16];
    tracing::debug!("Generated machine ID fingerprint: {fingerprint}");
    fingerprint.to_string()
}

fn persisted_machine_id_fallback() -> String {
    let fallback_path = crate::core::paths::data_dir().join("machine-id");
    std::fs::read_to_string(&fallback_path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            let generated = uuid::Uuid::new_v4().to_string();
            if let Some(parent) = fallback_path.parent()
                && let Err(error) = crate::core::paths::create_private_data_directory(parent)
            {
                tracing::warn!("Failed to create machine ID directory: {error}");
                return generated;
            }
            if let Err(error) = write_private_file(&fallback_path, generated.as_bytes()) {
                tracing::warn!("Failed to persist generated machine ID: {error}");
            }
            generated
        })
}

/// SHA256 hash as hex string
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Decode and verify JWT payload.
///
/// JWT best practices (RFC 8725 §3.1, "Algorithm Verification") require the
/// verifier to pin the accepted algorithm instead of trusting the token's
/// `alg` header. `Validation::new(Algorithm::EdDSA)` does exactly that, and
/// also validates `exp` by default (`validate_exp == true`, with `exp`
/// required among spec claims).
/// https://www.rfc-editor.org/rfc/rfc8725#name-algorithm-verification
/// https://docs.rs/jsonwebtoken/latest/jsonwebtoken/struct.Validation.html
fn pem_der(pem: &[u8], begin: &str, end: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;

    let text = std::str::from_utf8(pem).context("PEM key is not UTF-8")?;
    let body = text
        .trim()
        .strip_prefix(begin)
        .and_then(|value| value.strip_suffix(end))
        .context("PEM key has an unexpected label")?;
    let encoded: String = body
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("PEM key body is not valid base64")
}

fn ed25519_public_key_from_pem(pem: &[u8]) -> Result<[u8; 32]> {
    const ED25519_SPKI_PREFIX: &[u8] = &[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let der = pem_der(
        pem,
        "-----BEGIN PUBLIC KEY-----",
        "-----END PUBLIC KEY-----",
    )?;
    anyhow::ensure!(
        der.len() == ED25519_SPKI_PREFIX.len() + 32 && der.starts_with(ED25519_SPKI_PREFIX),
        "license public key is not an Ed25519 SubjectPublicKeyInfo key"
    );
    der[ED25519_SPKI_PREFIX.len()..]
        .try_into()
        .context("Ed25519 public key has an invalid length")
}

fn verify_jwt_with_key(token: &str, public_key_pem: &[u8]) -> Option<JwtPayload> {
    let mut validation = Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.validate_exp = true;
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.set_issuer(&[LICENSE_TOKEN_ISSUER]);
    validation.set_audience(&[LICENSE_TOKEN_AUDIENCE]);

    let key = match ed25519_public_key_from_pem(public_key_pem) {
        Ok(key) => DecodingKey::from_ed_der(&key),
        Err(error) => {
            tracing::debug!("License public key rejected: {error}");
            return None;
        }
    };

    match decode::<JwtPayload>(token, &key, &validation) {
        Ok(data) => Some(data.claims),
        Err(error) => {
            // Distinguish rejection reasons (expired vs bad signature vs
            // malformed) in logs without ever failing open.
            tracing::debug!("License token rejected: {error}");
            None
        }
    }
}

/// Get the license file path
fn license_path() -> Result<PathBuf> {
    let data_dir = crate::core::paths::ensure_data_dir()?;
    Ok(data_dir.join("license.json"))
}

/// Load stored license from disk.
///
/// A missing file is the normal no-license state (`None`, silently). A
/// corrupt or unreadable file is integrity-relevant user state, so it is
/// reported before degrading to `None` — never silently discarded.
#[must_use]
pub fn load_license() -> Option<StoredLicense> {
    let path = match license_path() {
        Ok(path) => path,
        Err(error) => {
            tracing::warn!("Cannot locate license storage: {error:#}");
            return None;
        }
    };
    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            tracing::warn!(
                "Failed to read license file {}: treating as no license ({error})",
                path.display()
            );
            return None;
        }
    };
    match serde_json::from_str(&content) {
        Ok(license) => Some(license),
        Err(error) => {
            tracing::warn!(
                "Discarding malformed license file {} as if no license existed: {error}",
                path.display()
            );
            None
        }
    }
}

fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;

    let parent = path
        .parent()
        .context("Private state path must have a parent directory")?;
    crate::core::paths::create_private_data_directory(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.as_file_mut().write_all(contents)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file_mut()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }

    temporary.as_file_mut().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("Failed to replace private state file {}", path.display()))?;
    crate::core::safe_ops::sync_parent_directory_sync(path)?;
    Ok(())
}

/// Save license to owner-only storage using atomic replacement.
pub fn save_license(license: &StoredLicense) -> Result<()> {
    let path = license_path()?;
    let content = serde_json::to_vec_pretty(license)?;
    write_private_file(&path, &content)
}

/// Remove stored license
pub fn remove_license() -> Result<()> {
    let path = license_path()?;
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

/// Redact a license key for logging. Only a short prefix of plain-ASCII
/// keys is kept; any other input degrades to a fixed placeholder so
/// logging can never panic on multi-byte keys or leak their shape.
fn redact_key(key: &str) -> String {
    match key.get(..8) {
        Some(prefix) if key.len() > 8 && prefix.is_ascii() => format!("{prefix}..."),
        _ => "***".to_string(),
    }
}

/// Validate a license key with optional user info for team identification
pub async fn validate_license_with_user(
    key: &str,
    user_name: Option<&str>,
    user_email: Option<&str>,
) -> Result<LicenseResponse> {
    let machine_id = get_machine_id();

    let payload = serde_json::json!({
        "license_key": key,
        "machine_id": machine_id,
        "user_name": user_name,
        "user_email": user_email,
    });

    // Redact key and PII
    let redacted_key = redact_key(key);
    tracing::debug!(
        "Validating license. Key: {}, MachineID: {}, HasUser: {}, HasEmail: {}",
        redacted_key,
        machine_id,
        user_name.is_some(),  // Log presence only, not value
        user_email.is_some()  // Log presence only, not value
    );

    let response = crate::core::http::shared_client()
        .post(super::service_api::VALIDATE_LICENSE)
        .json(&payload)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .context("Failed to connect to dashboard")?;

    let status = response.status();
    // The body is remote input: bound it before allocation (csf_08340651).
    let response_text = response
        .bounded_text()
        .await
        .context("Failed to read license response body (or it exceeded the 16 MiB limit)")?;

    // Parse response first
    let mut resp: LicenseResponse = serde_json::from_str(&response_text).context(format!(
        "Failed to parse license response. Status: {status}"
    ))?;

    // Log only safe fields
    tracing::debug!(
        "License API response: valid={}, tier={:?}, has_token={}, error={:?}",
        resp.valid,
        resp.tier,
        resp.token.is_some(),
        resp.error
    );

    // Remote error text is echoed to the terminal by the caller via
    // anyhow; strip terminal control sequences at the trust boundary
    // (csf_861ca461).
    resp.error = resp
        .error
        .take()
        .map(|error| sanitize_terminal_text(&error));
    resp.tier = resp.tier.take().map(|tier| sanitize_terminal_text(&tier));

    Ok(resp)
}

/// Load the stored account or fail with the link hint.
fn require_license() -> Result<StoredLicense> {
    load_license().ok_or_else(|| {
        anyhow::anyhow!(
            "No dashboard account linked. Run `omg account link --token-stdin` to sync usage to the dashboard."
        )
    })
}

/// GET a licensed endpoint with bearer authentication, mapping 403 to
/// `forbidden_message` and other failures to a status error.
async fn licensed_get<T: serde::de::DeserializeOwned>(
    url: &str,
    forbidden_message: &str,
    parse_context: &str,
) -> Result<T> {
    let license = require_license()?;

    let response = crate::core::http::shared_client()
        .get(url)
        .bearer_auth(&license.key)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .context("Failed to connect to dashboard")?;

    if !response.status().is_success() {
        if response.status() == reqwest::StatusCode::FORBIDDEN {
            anyhow::bail!("{forbidden_message}");
        }
        anyhow::bail!("Request failed (status: {})", response.status());
    }

    // Dashboard metadata is remote input: cap the body before allocation
    // (csf_08340651).
    response
        .bounded_json()
        .await
        .with_context(|| format!("Failed to parse {parse_context} response"))
}

/// Neutralize terminal control sequences in remote dashboard metadata.
///
/// Team rosters, policies, and audit-log entries are attacker-adjacent
/// remote input (any linked machine contributes fields such as hostname);
/// they reach the terminal through the CLI and TUI, so every string field
/// is stripped of OSC/CSI and bidi/zero-width sequences at the fetch
/// boundary (csf_861ca461).
fn sanitize_option(value: &mut Option<String>) {
    if let Some(text) = value.take() {
        *value = Some(sanitize_terminal_text(&text));
    }
}

fn sanitize_team_members(mut members: Vec<TeamMember>) -> Vec<TeamMember> {
    for member in &mut members {
        member.machine_id = sanitize_terminal_text(&member.machine_id);
        sanitize_option(&mut member.hostname);
        sanitize_option(&mut member.os);
        sanitize_option(&mut member.arch);
        sanitize_option(&mut member.omg_version);
        member.last_seen_at = sanitize_terminal_text(&member.last_seen_at);
    }
    members
}

fn sanitize_policy_rules(mut rules: Vec<PolicyRule>) -> Vec<PolicyRule> {
    for rule in &mut rules {
        rule.scope = sanitize_terminal_text(&rule.scope);
        rule.rule = sanitize_terminal_text(&rule.rule);
    }
    rules
}

fn sanitize_audit_logs(mut logs: Vec<AuditLogEntry>) -> Vec<AuditLogEntry> {
    for log in &mut logs {
        log.action = sanitize_terminal_text(&log.action);
        sanitize_option(&mut log.resource_type);
        sanitize_option(&mut log.resource_id);
        sanitize_option(&mut log.ip_address);
        log.created_at = sanitize_terminal_text(&log.created_at);
    }
    logs
}

/// Fetch team members associated with this license
pub async fn fetch_team_members() -> Result<Vec<TeamMember>> {
    Ok(sanitize_team_members(
        licensed_get(
            super::service_api::TEAM_MEMBERS,
            "Dashboard rejected this roster request. Relink with `omg account link --token-stdin`.",
            "team members",
        )
        .await?,
    ))
}

/// Fetch enterprise policies associated with this license
pub async fn fetch_policies() -> Result<Vec<PolicyRule>> {
    Ok(sanitize_policy_rules(
        licensed_get(
            super::service_api::TEAM_POLICIES,
            "Dashboard rejected this policy request. Relink with `omg account link --token-stdin`.",
            "policies",
        )
        .await?,
    ))
}

/// Fetch audit logs associated with this license
pub async fn fetch_audit_logs() -> Result<Vec<AuditLogEntry>> {
    Ok(sanitize_audit_logs(
        licensed_get(
            super::service_api::TEAM_AUDIT_LOG,
            "Dashboard rejected this activity request. Relink with `omg account link --token-stdin`.",
            "audit logs",
        )
        .await?,
    ))
}

/// Activate a license key
pub async fn activate(key: &str) -> Result<StoredLicense> {
    activate_with_user(key, None, None).await
}

/// Activate a license key with user info for team identification
pub async fn activate_with_user(
    key: &str,
    user_name: Option<&str>,
    user_email: Option<&str>,
) -> Result<StoredLicense> {
    let response = validate_license_with_user(key, user_name, user_email).await?;

    if !response.valid {
        anyhow::bail!(
            "Invalid license: {}",
            response
                .error
                .unwrap_or_else(|| "Unknown error".to_string())
        );
    }

    let stored = StoredLicense {
        key: key.to_string(),
        tier: response.tier.unwrap_or_else(|| "free".to_string()),
        features: response.features.unwrap_or_default(),
        customer: response.customer,
        expires_at: response.expires_at,
        validated_at: jiff::Timestamp::now().as_second(),
        token: response.token,
        machine_id: Some(get_machine_id()),
    };
    validate_activated_license(&stored)?;
    save_license(&stored)?;

    Ok(stored)
}

fn validate_activated_license(stored: &StoredLicense) -> Result<()> {
    anyhow::ensure!(
        stored.is_token_valid(),
        "Dashboard returned a token that failed local signature, expiry, or machine-binding verification"
    );
    Ok(())
}

/// JWT-verified plan label for the linked account, or `Free` when unlinked.
/// This is identity metadata, not a permission check.
#[must_use]
pub fn current_tier() -> Tier {
    load_license().map_or(Tier::Free, |l| l.tier_enum())
}

/// Whether `feature_name` is a known CLI capability. Accounts never gate this.
#[must_use]
pub fn has_feature(feature_name: &str) -> bool {
    Feature::from_str(feature_name).is_some()
}

/// Accept a known feature name. Unknown names are input errors, not paywalls.
pub fn require_feature(feature_name: &str) -> Result<()> {
    if Feature::from_str(feature_name).is_some() {
        return Ok(());
    }
    anyhow::bail!("Unknown feature '{feature_name}'")
}

/// Get current license status
#[must_use]
pub fn status() -> Option<StoredLicense> {
    load_license()
}

/// Get features available for a tier
#[must_use]
pub fn features_for_tier(tier: Tier) -> Vec<&'static Feature> {
    let mut features: Vec<&Feature> = FREE_FEATURES.iter().collect();

    if tier >= Tier::Pro {
        features.extend(PRO_FEATURES.iter());
    }

    if tier >= Tier::Team {
        features.extend(TEAM_FEATURES.iter());
    }

    if tier >= Tier::Enterprise {
        features.extend(ENTERPRISE_FEATURES.iter());
    }

    features
}

#[cfg(test)]
mod tests {
    use super::*;

    // gitleaks:allow -- deterministic test-only Ed25519 fixture
    const TEST_PRIVATE_KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIIx/ifT0yOyJ/SykVkxxVR4zdDCep94lm3xLOyNn83kM\n-----END PRIVATE KEY-----\n";
    const TEST_PUBLIC_KEY: &[u8] = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAniF8d18mTVtOAi1msyk1sPU6smSFhAiiTRpLgzcFEEs=\n-----END PUBLIC KEY-----\n";

    fn signed_test_token(issuer: &str, audience: &str) -> String {
        let now = jsonwebtoken::get_current_timestamp().cast_signed();
        signed_test_token_with_claims(issuer, audience, None, now + 3600)
    }

    fn signed_test_token_with_claims(
        issuer: &str,
        audience: &str,
        machine_id: Option<String>,
        expires_at: i64,
    ) -> String {
        let payload = JwtPayload {
            iss: issuer.to_string(),
            aud: audience.to_string(),
            sub: "customer-1".to_string(),
            tier: "pro".to_string(),
            features: vec!["sbom".to_string()],
            exp: expires_at,
            iat: jsonwebtoken::get_current_timestamp().cast_signed(),
            mid: machine_id,
            lic: "license-1".to_string(),
        };
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA),
            &payload,
            &jsonwebtoken::EncodingKey::from_ed_der(
                &pem_der(
                    TEST_PRIVATE_KEY,
                    "-----BEGIN PRIVATE KEY-----",
                    "-----END PRIVATE KEY-----",
                )
                .expect("test private key must parse"),
            ),
        )
        .expect("test token must encode")
    }

    #[test]
    fn production_verification_key_matches_published_fingerprint() {
        assert_eq!(
            sha256_hex(LICENSE_JWT_VERIFICATION_KEY),
            "8bf0749afe4761500cb47a370cef66f1ab4c88415a1298c4481ead53ac4bc13c"
        );
    }

    #[test]
    fn license_tokens_require_expected_issuer_and_audience() {
        let valid = signed_test_token(LICENSE_TOKEN_ISSUER, LICENSE_TOKEN_AUDIENCE);
        assert!(verify_jwt_with_key(&valid, TEST_PUBLIC_KEY).is_some());

        let wrong_issuer = signed_test_token("https://attacker.invalid", LICENSE_TOKEN_AUDIENCE);
        assert!(verify_jwt_with_key(&wrong_issuer, TEST_PUBLIC_KEY).is_none());

        let wrong_audience = signed_test_token(LICENSE_TOKEN_ISSUER, "another-client");
        assert!(verify_jwt_with_key(&wrong_audience, TEST_PUBLIC_KEY).is_none());
    }

    /// Wave-16 durability fix: rolling the system clock back cannot revive a
    /// token whose expiry predates the persisted observed-time high-water
    /// mark. The token below is signature-valid and not yet expired by the
    /// current clock, but the watermark proves real time already passed its
    /// expiry — verification must fail.
    #[test]
    fn license_expiry_survives_system_clock_rollback() {
        let temp = tempfile::TempDir::new().unwrap();
        let watermark_path = temp.path().join("license-clock.highwater");
        let _guard = override_watermark_path(watermark_path.clone());

        let now = jsonwebtoken::get_current_timestamp().cast_signed();
        let token = signed_test_token_with_claims(
            LICENSE_TOKEN_ISSUER,
            LICENSE_TOKEN_AUDIENCE,
            Some(get_machine_id()),
            now + 3600,
        );
        let stored = StoredLicense {
            key: "license-1".to_string(),
            tier: "pro".to_string(),
            features: vec!["sbom".to_string()],
            customer: None,
            expires_at: None,
            validated_at: now,
            token: Some(token),
            machine_id: Some(get_machine_id()),
        };

        // Fresh watermark: token is valid, and verification advances the mark
        // to (at least) the current wall clock.
        assert!(stored.verified_payload_with_key(TEST_PUBLIC_KEY).is_some());
        let advanced = load_clock_watermark(&watermark_path)
            .expect("read watermark")
            .expect("watermark initialized");
        assert!(
            advanced >= now,
            "watermark must reach current time: {advanced}"
        );

        // Simulate a rollback: the machine observed real time past the
        // token's expiry before the clock was wound back. The expired-as-of-
        // watermark token must now be rejected.
        license_clock_floor_with(&watermark_path, now + 7200).expect("advance watermark");
        assert!(stored.verified_payload_with_key(TEST_PUBLIC_KEY).is_none());
        assert!(
            load_clock_watermark(&watermark_path)
                .expect("read watermark")
                .expect("watermark initialized")
                >= now + 7200
        );
        assert_eq!(
            license_clock_floor_with(&watermark_path, now).expect("read monotonic watermark"),
            now + 7200
        );
    }

    #[test]
    fn license_watermark_advances_when_jwt_expiry_rejects() {
        let temp = tempfile::TempDir::new().unwrap();
        let watermark_path = temp.path().join("license-clock.highwater");
        let _guard = override_watermark_path(watermark_path.clone());

        let now = jsonwebtoken::get_current_timestamp().cast_signed();
        let token = signed_test_token_with_claims(
            LICENSE_TOKEN_ISSUER,
            LICENSE_TOKEN_AUDIENCE,
            Some(get_machine_id()),
            now - 60,
        );
        let stored = StoredLicense {
            key: "license-1".to_string(),
            tier: "pro".to_string(),
            features: vec!["sbom".to_string()],
            customer: None,
            expires_at: None,
            validated_at: now,
            token: Some(token),
            machine_id: Some(get_machine_id()),
        };

        assert!(stored.verified_payload_with_key(TEST_PUBLIC_KEY).is_none());
        let floor = load_clock_watermark(&watermark_path)
            .expect("read watermark")
            .expect("expired verification must still persist observed time");
        assert!(
            floor >= now,
            "JWT exp rejection must still raise the watermark: {floor} < {now}"
        );
    }

    #[test]
    fn malformed_license_clock_watermark_fails_closed() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let watermark_path = temp.path().join("license-clock.highwater");
        std::fs::write(&watermark_path, "not-a-timestamp").expect("write malformed watermark");

        let error = license_clock_floor_with(&watermark_path, 1)
            .expect_err("malformed rollback state must not be reset");
        assert!(
            error
                .to_string()
                .contains("Malformed license clock watermark")
        );
    }

    #[test]
    fn license_tokens_enforce_expiry_and_machine_binding() {
        let now = jsonwebtoken::get_current_timestamp().cast_signed();
        let valid = signed_test_token_with_claims(
            LICENSE_TOKEN_ISSUER,
            LICENSE_TOKEN_AUDIENCE,
            Some(get_machine_id()),
            now + 3600,
        );
        let wrong_machine = signed_test_token_with_claims(
            LICENSE_TOKEN_ISSUER,
            LICENSE_TOKEN_AUDIENCE,
            Some("different-machine".to_string()),
            now + 3600,
        );
        let expired = signed_test_token_with_claims(
            LICENSE_TOKEN_ISSUER,
            LICENSE_TOKEN_AUDIENCE,
            Some(get_machine_id()),
            now - 3600,
        );

        let stored = |token| StoredLicense {
            key: "license-1".to_string(),
            tier: "pro".to_string(),
            features: vec!["sbom".to_string()],
            customer: None,
            expires_at: None,
            validated_at: now,
            token: Some(token),
            machine_id: Some(get_machine_id()),
        };
        assert!(
            stored(valid)
                .verified_payload_with_key(TEST_PUBLIC_KEY)
                .is_some()
        );
        assert!(
            stored(wrong_machine)
                .verified_payload_with_key(TEST_PUBLIC_KEY)
                .is_none()
        );
        assert!(
            stored(expired)
                .verified_payload_with_key(TEST_PUBLIC_KEY)
                .is_none()
        );
    }

    #[test]
    fn tier_parsing_covers_hierarchy() {
        assert!(matches!(Tier::parse("pro"), Some(Tier::Pro)));
        assert!(matches!(Tier::parse("team"), Some(Tier::Team)));
        assert!(matches!(Tier::parse("enterprise"), Some(Tier::Enterprise)));
        // Unknown input must be rejected, not coerced to a tier.
        assert_eq!(Tier::parse("unknown"), None);
        assert_eq!("nope".parse::<Tier>(), Err(UnknownTier));
    }

    #[test]
    fn key_redaction_never_panics_on_multibyte_input() {
        // Regression: slicing &key[..8] panicked when byte 8 was not a
        // char boundary (e.g. multi-byte license keys).
        assert_eq!(redact_key("abcdefgh12345678"), "abcdefgh...");
        assert_eq!(redact_key("short"), "***");
        // 3-byte CJK characters straddling byte 8 must not panic.
        assert_eq!(redact_key("\u{4e2d}\u{65ad}\u{6d4b}\u{8bd5}key"), "***");
        assert_eq!(redact_key("\u{4e2d}\u{65ad}\u{6d4b}key-more"), "***");
        assert_eq!(redact_key(""), "***");
    }

    #[test]
    fn feature_tiers_match_tier_levels() {
        assert_eq!(Feature::Packages.required_tier(), Tier::Free);
        assert_eq!(Feature::Sbom.required_tier(), Tier::Pro);
        assert_eq!(Feature::TeamSync.required_tier(), Tier::Team);
        assert_eq!(Feature::Policy.required_tier(), Tier::Enterprise);
    }

    #[test]
    fn unsigned_stored_tier_is_not_a_dashboard_identity() {
        let stored = StoredLicense {
            key: "editable-key".to_string(),
            tier: "enterprise".to_string(),
            features: Vec::new(),
            customer: None,
            expires_at: None,
            validated_at: 0,
            token: None,
            machine_id: None,
        };

        assert_eq!(stored.tier_enum(), Tier::Free);
        assert!(!stored.is_token_valid());
    }

    #[test]
    fn activation_rejects_unverifiable_server_tokens() {
        let stored = StoredLicense {
            key: "license-1".to_string(),
            tier: "pro".to_string(),
            features: vec!["sbom".to_string()],
            customer: None,
            expires_at: None,
            validated_at: jiff::Timestamp::now().as_second(),
            token: Some("not-a-verifiable-token".to_string()),
            machine_id: Some(get_machine_id()),
        };

        let error = validate_activated_license(&stored)
            .expect_err("activation must fail before persisting an unusable token");
        assert!(
            error.to_string().contains("failed local signature"),
            "{error}"
        );
    }

    #[test]
    fn garbage_signed_token_fails_closed_to_free_tier() {
        // Regression for the STUB verification key: a token that was never
        // signed by the real dashboard; it must never count as a linked
        // account, even when the stored file claims "enterprise".
        let stored = StoredLicense {
            key: "real-key".to_string(),
            tier: "enterprise".to_string(),
            features: vec!["policy".to_string()],
            customer: Some("acme".to_string()),
            expires_at: None,
            validated_at: jiff::Timestamp::now().as_second(),
            // Deliberately not a real JWT: verification must reject any
            // token it cannot validate, whatever its shape.
            token: Some("definitely-not-a-valid-license-token".to_string()),
            machine_id: Some(get_machine_id()),
        };

        assert!(!stored.is_token_valid());
        assert_eq!(stored.tier_enum(), Tier::Free);
    }

    #[cfg(unix)]
    #[test]
    fn private_state_is_atomically_replaced_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("license.json");
        std::fs::write(&path, b"old").expect("write existing state");

        write_private_file(&path, b"new").expect("replace private state");

        assert_eq!(std::fs::read(&path).expect("read state"), b"new");
        let mode = std::fs::metadata(path)
            .expect("state metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn known_features_are_available_without_an_account() {
        assert!(has_feature("packages"));
        assert!(has_feature("runtimes"));
        assert!(has_feature("container"));
        assert!(has_feature("sbom"));
        assert!(has_feature("team-sync"));
        assert!(has_feature("policy"));
        assert!(require_feature("sbom").is_ok());
        assert!(require_feature("sso").is_ok());
    }

    #[test]
    fn unknown_feature_is_denied() {
        assert!(!has_feature("not-a-real-feature"));
        match require_feature("not-a-real-feature") {
            Ok(()) => panic!("unknown feature must be denied"),
            Err(err) => assert!(err.to_string().contains("Unknown feature"), "got: {err}"),
        }
    }

    #[test]
    fn dashboard_metadata_is_stripped_of_terminal_control_sequences() {
        let hostile = "\u{1b}]52;c;pwned\u{7}host\u{1b}[31m".to_string();
        let members = sanitize_team_members(vec![TeamMember {
            machine_id: hostile.clone(),
            hostname: Some(hostile.clone()),
            os: Some(hostile.clone()),
            arch: Some(hostile.clone()),
            omg_version: Some(hostile.clone()),
            last_seen_at: hostile.clone(),
            is_active: true,
        }]);
        assert_eq!(members.len(), 1);
        let member = &members[0];
        for field in [
            member.machine_id.as_str(),
            member.hostname.as_deref().unwrap_or_default(),
            member.os.as_deref().unwrap_or_default(),
            member.arch.as_deref().unwrap_or_default(),
            member.omg_version.as_deref().unwrap_or_default(),
            member.last_seen_at.as_str(),
        ] {
            assert!(!field.contains('\u{1b}'), "ESC must be stripped: {field}");
            assert!(!field.contains('\u{7}'), "BEL must be stripped: {field}");
        }

        let policies = sanitize_policy_rules(vec![PolicyRule {
            scope: hostile.clone(),
            rule: hostile.clone(),
            enforced: true,
        }]);
        assert!(!policies[0].scope.contains('\u{1b}'));
        assert!(!policies[0].rule.contains('\u{1b}'));

        let logs = sanitize_audit_logs(vec![AuditLogEntry {
            action: hostile.clone(),
            resource_type: Some(hostile.clone()),
            resource_id: Some(hostile.clone()),
            ip_address: Some(hostile.clone()),
            created_at: hostile,
        }]);
        for field in [
            logs[0].action.as_str(),
            logs[0].resource_type.as_deref().unwrap_or_default(),
            logs[0].resource_id.as_deref().unwrap_or_default(),
            logs[0].ip_address.as_deref().unwrap_or_default(),
            logs[0].created_at.as_str(),
        ] {
            assert!(!field.contains('\u{1b}'), "ESC must be stripped: {field}");
        }
    }
}
