//! SLSA (Supply-chain Levels for Software Artifacts) provenance verification
//!
//! Verifies build provenance evidence and classifies SLSA levels (L0-L3) per
//! SLSA v1.0 specification for supply chain security attestation.

use std::collections::HashMap;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::core::http::{BoundedResponseExt, shared_client};

/// Failures when talking to Rekor or parsing a log entry.
#[derive(Debug, Error)]
pub enum RekorError {
    #[error("Rekor HTTP request failed with status {status}")]
    HttpFailed { status: u16 },
    #[error("Rekor entry {uuid} missing required field {field}")]
    EntryMissingField { uuid: String, field: &'static str },
    #[error("Rekor entry {uuid} field {field} is not a u64")]
    EntryInvalidField { uuid: String, field: &'static str },
    #[error("Rekor response missing entry {uuid}")]
    EntryNotFound { uuid: String },
    #[error("Invalid Rekor response: empty entry map")]
    EmptyEntryMap,
    #[error("Rekor entry {uuid} has a malformed SignedEntryTimestamp")]
    EntrySetMalformed { uuid: String },
    #[error(
        "Rekor entry {uuid} SignedEntryTimestamp does not verify against the pinned Rekor public key"
    )]
    EntrySetVerificationFailed { uuid: String },
    #[error("Pinned Rekor public key is malformed (build-time misconfiguration)")]
    RekorPublicKeyMalformed,
}

/// Failures hashing artifacts or talking to Rekor.
#[derive(Debug, Error)]
pub enum SlsaError {
    #[error("An exact --certificate-identity is required to establish signer trust")]
    IdentityRequired,
    #[error(transparent)]
    Rekor(#[from] RekorError),
    #[error("Failed to query Rekor")]
    RekorRequest {
        #[source]
        source: reqwest::Error,
    },
    #[error("Invalid Rekor index JSON")]
    RekorIndexJson {
        #[source]
        source: anyhow::Error,
    },
    #[error("Failed to get Rekor entry")]
    RekorEntryRequest {
        #[source]
        source: reqwest::Error,
    },
    #[error("Invalid Rekor entry JSON")]
    RekorEntryJson {
        #[source]
        source: anyhow::Error,
    },
    #[error("Malformed Rekor entry body")]
    RekorBodyDecode {
        #[source]
        source: base64::DecodeError,
    },
    #[error("Rekor entry body is not valid JSON")]
    RekorBodyJson {
        #[source]
        source: serde_json::Error,
    },
    #[error("Rekor entry body missing field '{field}'")]
    RekorBodyMissingField { field: &'static str },
    #[error("Signature bytes are malformed for the given key type")]
    SignatureMalformed,
    #[error("Failed to read '{path}'")]
    Read {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("Invalid local provenance JSON")]
    ProvenanceParse {
        #[source]
        source: serde_json::Error,
    },
}

/// SLSA Level definitions per SLSA v1.0 specification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SlsaLevel {
    /// No SLSA guarantees
    None = 0,
    /// Build process is documented
    Level1 = 1,
    /// Hosted build platform, signed provenance
    Level2 = 2,
    /// Hardened build platform, non-falsifiable provenance
    Level3 = 3,
}

impl std::fmt::Display for SlsaLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Level1 => write!(f, "SLSA Level 1"),
            Self::Level2 => write!(f, "SLSA Level 2"),
            Self::Level3 => write!(f, "SLSA Level 3"),
        }
    }
}

/// Rekor transparency log entry
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RekorEntry {
    pub uuid: String,
    pub log_index: u64,
    pub integrated_time: u64,
    pub body: String,
}

/// SLSA provenance attestation
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SlsaProvenance {
    pub build_type: String,
    pub builder: SlsaBuilder,
    pub invocation: Option<SlsaInvocation>,
    pub build_config: Option<serde_json::Value>,
    pub metadata: Option<SlsaMetadata>,
    pub materials: Vec<SlsaMaterial>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SlsaBuilder {
    pub id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SlsaInvocation {
    pub config_source: Option<ConfigSource>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigSource {
    pub uri: String,
    pub digest: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SlsaMetadata {
    pub build_invocation_id: Option<String>,
    pub build_started_on: Option<String>,
    pub build_finished_on: Option<String>,
    pub completeness: Option<SlsaCompleteness>,
    pub reproducible: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SlsaCompleteness {
    pub parameters: bool,
    pub environment: bool,
    pub materials: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SlsaMaterial {
    pub uri: String,
    pub digest: std::collections::HashMap<String, String>,
}

/// Verification result with detailed information.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// True only after cryptographic verification succeeded: a Rekor
    /// hashedrekord entry whose embedded signature over the artifact digest
    /// verifies against its embedded public key.
    pub verified: bool,
    /// Classified SLSA build level for the artifact.
    pub slsa_level: SlsaLevel,
    /// Rekor entry UUID when a transparency-log hit was found.
    pub transparency_log_entry: Option<String>,
    /// Builder identity claimed by matched provenance, when present.
    pub builder_id: Option<String>,
    /// Build timestamp from provenance metadata, when present.
    pub build_timestamp: Option<String>,
    /// Human-readable reason the artifact is not verified.
    pub error: Option<String>,
}

/// SLSA verification engine using Sigstore
#[derive(Debug, Clone)]
pub struct SlsaVerifier {
    client: reqwest::Client,
    rekor_url: String,
}

impl Default for SlsaVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Evidence available to [`classify_slsa_evidence`]. None of these are a
/// completed in-toto/SLSA verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlsaEvidence {
    None,
    /// Local JSON parsed as provenance, with no signature check.
    UnsignedLocalJson,
    /// Rekor returned an index hit for the artifact hash.
    RekorIndexHit,
}

/// Map raw evidence to a result. A Rekor UUID or unsigned JSON file is not
/// SLSA L1/L2 and must not be reported as verified.
#[must_use]
pub fn classify_slsa_evidence(evidence: SlsaEvidence) -> VerificationResult {
    match evidence {
        SlsaEvidence::None => slsa_unverified("No verified SLSA provenance"),
        SlsaEvidence::UnsignedLocalJson => {
            slsa_unverified("Local provenance JSON is not a verified attestation")
        }
        SlsaEvidence::RekorIndexHit => {
            slsa_unverified("Rekor log index hit is not in-toto/SLSA verification")
        }
    }
}

fn slsa_unverified(error: &str) -> VerificationResult {
    VerificationResult {
        verified: false,
        slsa_level: SlsaLevel::None,
        transparency_log_entry: None,
        builder_id: None,
        build_timestamp: None,
        error: Some(error.to_string()),
    }
}

fn rekor_http_must_succeed(status: reqwest::StatusCode) -> Result<(), RekorError> {
    if status.is_success() {
        Ok(())
    } else {
        Err(RekorError::HttpFailed {
            status: status.as_u16(),
        })
    }
}

fn required_u64(value: &Value, uuid: &str, field: &'static str) -> Result<u64, RekorError> {
    match value.get(field) {
        None => Err(RekorError::EntryMissingField {
            uuid: uuid.to_string(),
            field,
        }),
        Some(v) => v.as_u64().ok_or_else(|| RekorError::EntryInvalidField {
            uuid: uuid.to_string(),
            field,
        }),
    }
}

/// Verify an entry's SignedEntryTimestamp (SET) against the pinned Rekor
/// public key before its contents (body, integratedTime) may be trusted.
/// The Fulcio chain-time check in `verify_rekor_entry` relies on
/// `integrated_time`, so an unauthenticated timestamp would let a TLS-level
/// attacker forge certificate validity windows.
fn parse_rekor_entry(
    requested_uuid: &str,
    mut entry_map: HashMap<String, Value>,
) -> Result<RekorEntry, RekorError> {
    if entry_map.is_empty() {
        return Err(RekorError::EmptyEntryMap);
    }
    let value = entry_map
        .remove(requested_uuid)
        .ok_or_else(|| RekorError::EntryNotFound {
            uuid: requested_uuid.to_string(),
        })?;
    let log_index = required_u64(&value, requested_uuid, "logIndex")?;
    let integrated_time = required_u64(&value, requested_uuid, "integratedTime")?;
    let body = value
        .get("body")
        .and_then(Value::as_str)
        .ok_or_else(|| RekorError::EntryMissingField {
            uuid: requested_uuid.to_string(),
            field: "body",
        })?
        .to_string();
    let log_id = value
        .get("logID")
        .and_then(Value::as_str)
        .ok_or_else(|| RekorError::EntryMissingField {
            uuid: requested_uuid.to_string(),
            field: "logID",
        })?
        .to_string();
    let set_b64 = value
        .pointer("/verification/signedEntryTimestamp")
        .and_then(Value::as_str)
        .ok_or_else(|| RekorError::EntryMissingField {
            uuid: requested_uuid.to_string(),
            field: "verification.signedEntryTimestamp",
        })?;

    // Refuse entries whose SET cannot be verified: the entry's integrated
    // time feeds the Fulcio certificate-validity decision, so it must be
    // authenticated by the log itself, not by the TLS channel alone.
    let set_bytes = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(set_b64.trim())
            .map_err(|_| RekorError::EntrySetMalformed {
                uuid: requested_uuid.to_string(),
            })?
    };
    // Reconstructing the signed bytes interpolates `log_id` and `body` raw
    // into the JSON template, so a value containing `"` or `\` would splice
    // attacker-chosen JSON into the payload the SET is checked against. The
    // canonicalizer refuses such values; treat that as a malformed entry
    // rather than verifying over reconstructed bytes.
    let canonical =
        canonical_set_payload(&log_id, log_index, integrated_time, &body).ok_or_else(|| {
            RekorError::EntrySetMalformed {
                uuid: requested_uuid.to_string(),
            }
        })?;
    let key = rekor_verifying_key()?;
    if !verify_set_signature(canonical.as_bytes(), &set_bytes, &key) {
        return Err(RekorError::EntrySetVerificationFailed {
            uuid: requested_uuid.to_string(),
        });
    }

    Ok(RekorEntry {
        uuid: requested_uuid.to_string(),
        log_index,
        integrated_time,
        body,
    })
}

/// Canonical bytes covered by the SignedEntryTimestamp.
///
/// Rekor's server signs (`pkg/api/entries.go`, `signEntry`) the RFC 8785
/// canonicalization of the JSON object `{body, integratedTime, logID,
/// logIndex}`; clients such as sigstore-go (`pkg/tlog/entry.go`,
/// `VerifySET`) reconstruct exactly these four fields, hash them with
/// SHA-256, and verify an ECDSA P-256 signature. For this fixed field set
/// (base64 body, hex log ID, integers in 0..=2^53-1) the RFC 8785 form is
/// the key-sorted, whitespace-free JSON built here. This safe-integer subset
/// avoids rounding signed fields through IEEE-754; larger integers are refused,
/// not silently rounded. This is not a general JCS implementation.
///
/// The strings are interpolated raw, so their alphabets are checked at runtime.
/// Accepted ASCII strings need no JSON escaping, and their signed bytes remain
/// unchanged. These guards refuse malformed reconstruction inputs; they do not
/// establish a bypass of the pinned-key signature check.
fn canonical_set_payload(
    log_id: &str,
    log_index: u64,
    integrated_time: u64,
    body: &str,
) -> Option<String> {
    const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
    if log_index > MAX_SAFE_INTEGER || integrated_time > MAX_SAFE_INTEGER {
        return None;
    }
    if !log_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    if !body
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
    {
        return None;
    }
    Some(format!(
        "{{\"body\":\"{body}\",\"integratedTime\":{integrated_time},\"logID\":\"{log_id}\",\"logIndex\":{log_index}}}"
    ))
}

/// Verify the ECDSA P-256 (ASN.1 DER) SET signature over the SHA-256 digest
/// of the canonical entry bytes.
fn verify_set_signature(
    canonical: &[u8],
    set_signature_der: &[u8],
    key: &p256::ecdsa::VerifyingKey,
) -> bool {
    use p256::ecdsa::signature::Verifier as _;
    match p256::ecdsa::Signature::from_der(set_signature_der) {
        Ok(signature) => key.verify(canonical, &signature).is_ok(),
        Err(_) => false,
    }
}

/// Parse the pinned Rekor log public key (ECDSA P-256, SPKI PEM).
fn rekor_verifying_key() -> Result<p256::ecdsa::VerifyingKey, RekorError> {
    use p256::pkcs8::DecodePublicKey as _;
    p256::ecdsa::VerifyingKey::from_public_key_pem(REKOR_PUBLIC_KEY_PEM)
        .map_err(|_| RekorError::RekorPublicKeyMalformed)
}

// ---------------------------------------------------------------------------
// Sigstore Fulcio trust roots.
//
// Source: https://raw.githubusercontent.com/sigstore/root-signing/main/targets/
// (the sigstore TUF repository's targets directory; see
// https://github.com/sigstore/root-signing). Metadata cross-checked:
//   root:        subject/issuer "O=sigstore.dev, CN=sigstore",
//                valid 2021-10-07 .. 2031-10-05, ECDSA P-384
//   intermediate: subject "O=sigstore.dev, CN=sigstore-intermediate",
//                issued by the root, valid 2022-04-13 .. 2031-10-05
// Rotate deliberately when Sigstore publishes new roots via TUF.
// ---------------------------------------------------------------------------

/// Rekor transparency log public key (ECDSA P-256, SPKI PEM).
///
/// Pinned in-binary from the Sigstore TUF root-signing repository target
/// https://raw.githubusercontent.com/sigstore/root-signing/main/targets/rekor.pub
/// (see https://github.com/sigstore/root-signing; the same key is served live
/// by Rekor at https://rekor.sigstore.dev/api/v1/log/publicKey). Used to
/// verify each entry's SignedEntryTimestamp (SET) so Rekor entry contents
/// never rest on the TLS channel alone. Note: entries integrated under an
/// older, rotated log key will fail SET verification and be refused.
const REKOR_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----";

const FULCIO_ROOT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7
XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxex
X69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92j
YzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRY
wB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQ
KsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCM
WP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9
TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ
-----END CERTIFICATE-----";

const FULCIO_INTERMEDIATE_PEM: &str = "-----BEGIN CERTIFICATE-----
MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV7
7LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS
0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYB
BQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjp
KFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZI
zj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJR
nZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsP
mygUY7Ii2zbdCdliiow=
-----END CERTIFICATE-----";

/// Verify an X.509 certificate signature using the issuer's SPKI public key.
/// Supports the algorithms Sigstore/Fulcio actually issues:
/// RSA PKCS#1 v1.5 SHA-256, ECDSA P-256/SHA-256, ECDSA P-384/SHA-384.
fn verify_x509_signature(
    issuer_spki_der: &[u8],
    tbs: &[u8],
    signature_bits: &[u8],
    algorithm_oid: &str,
) -> bool {
    match algorithm_oid {
        "1.2.840.113549.1.1.11" => {
            use rsa::pkcs8::DecodePublicKey as _;
            use rsa::signature::DigestVerifier as _;
            let Ok(key) = rsa::RsaPublicKey::from_public_key_der(issuer_spki_der) else {
                return false;
            };
            let verifying = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(key);
            let Ok(sig) = rsa::pkcs1v15::Signature::try_from(signature_bits) else {
                return false;
            };
            let mut hasher = sha2::Sha256::new();
            sha2::Digest::update(&mut hasher, tbs);
            verifying.verify_digest(hasher, &sig).is_ok()
        }
        "1.2.840.10045.4.3.2" => {
            use p256::ecdsa::signature::DigestVerifier as _;
            use p256::pkcs8::DecodePublicKey as _;
            let Ok(key) = p256::PublicKey::from_public_key_der(issuer_spki_der) else {
                return false;
            };
            let verifying = p256::ecdsa::VerifyingKey::from(key);
            let Ok(sig) = p256::ecdsa::Signature::from_der(signature_bits) else {
                return false;
            };
            let mut hasher = sha2::Sha256::new();
            sha2::Digest::update(&mut hasher, tbs);
            verifying.verify_digest(hasher, &sig).is_ok()
        }
        "1.2.840.10045.4.3.3" => {
            use p384::ecdsa::signature::DigestVerifier as _;
            use p384::pkcs8::DecodePublicKey as _;
            let Ok(key) = p384::PublicKey::from_public_key_der(issuer_spki_der) else {
                return false;
            };
            let verifying = p384::ecdsa::VerifyingKey::from(key);
            let Ok(sig) = p384::ecdsa::Signature::from_der(signature_bits) else {
                return false;
            };
            let mut hasher = sha2::Sha384::new();
            sha2::Digest::update(&mut hasher, tbs);
            verifying.verify_digest(hasher, &sig).is_ok()
        }
        _ => false,
    }
}

/// Remove only complete RFC 7468 boundaries. BEGIN/END can also occur in
/// perfectly valid base64 data and must never identify a boundary by substring.
fn decode_pem_body(pem: &str, label: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine as _;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let body: String = pem
        .lines()
        .map(str::trim)
        .filter(|line| *line != begin && *line != end)
        .collect();
    base64::engine::general_purpose::STANDARD.decode(body)
}

/// Check the extension policy for the existing direct-root or one-intermediate
/// topology. `ca_below` is None for a leaf, Some(0) for an intermediate/direct
/// root, or Some(1) for a root above an intermediate. Absent KeyUsage retains
/// existing behavior; present KeyUsage must permit the certificate's role.
///
/// Critical support is deliberately narrow: BC/KU for issuers, plus codeSigning
/// EKU and identity SAN for leaves. Parser recognition alone is not support.
/// This does not implement general RFC 5280 path construction, revocation,
/// name constraints, policy processing, or self-issued rollover exceptions.
fn fulcio_extensions_permit_role(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
    ca_below: Option<u32>,
) -> bool {
    use x509_parser::extensions::ParsedExtension;

    let mut seen = std::collections::HashSet::new();
    for extension in certificate.extensions() {
        if !seen.insert(&extension.oid) {
            return false;
        }
        let supported = match extension.parsed_extension() {
            ParsedExtension::BasicConstraints(constraints) => {
                if let Some(count) = ca_below {
                    if !constraints.ca
                        || constraints
                            .path_len_constraint
                            .is_some_and(|limit| count > limit)
                    {
                        return false;
                    }
                } else if constraints.ca || constraints.path_len_constraint.is_some() {
                    return false;
                }
                true
            }
            ParsedExtension::KeyUsage(usage) => {
                let permitted = if ca_below.is_some() {
                    usage.key_cert_sign()
                } else {
                    usage.digital_signature()
                };
                if !permitted {
                    return false;
                }
                true
            }
            ParsedExtension::ExtendedKeyUsage(usage) if ca_below.is_none() => {
                if !usage.code_signing {
                    return false;
                }
                true
            }
            ParsedExtension::SubjectAlternativeName(_) if ca_below.is_none() => true,
            ParsedExtension::ParseError { .. } | ParsedExtension::Unparsed => return false,
            _ => false,
        };
        if extension.critical && !supported {
            return false;
        }
    }
    true
}

/// Bind a Fulcio leaf certificate to a signer identity by validating its
/// chain against the embedded Sigstore trust roots.
///
/// Returns `Some(identity)` when: the leaf chains to an embedded root
/// (directly or through the embedded intermediate), every link's signature
/// verifies, every validity window covers `integrated_time`, and the leaf
/// carries an RFC822/URI Subject Alternative Name identifying the signer.
/// The selected chain must also pass the narrow role/critical-extension policy
/// in `fulcio_extensions_permit_role`; this is not full PKI validation.
fn verify_fulcio_chain(
    leaf_der: &[u8],
    integrated_time: u64,
    roots: &[&str],
    intermediate_pem: &str,
) -> Option<String> {
    use x509_parser::prelude::*;

    let decode_pem_der = |pem: &str| decode_pem_body(pem, "CERTIFICATE").ok();

    let (_, leaf) = X509Certificate::from_der(leaf_der).ok()?;
    if !fulcio_extensions_permit_role(&leaf, None) {
        return None;
    }

    // An absent intermediate may be passed as an empty string; only a
    // successfully decoded, non-empty DER counts.
    let inter_der = decode_pem_der(intermediate_pem).filter(|der| !der.is_empty());

    // Roots are kept as owned DER; each check site re-parses within its own
    // scope so no borrowed certificate reference escapes this function.
    let roots_owned: Vec<Vec<u8>> = roots.iter().filter_map(|pem| decode_pem_der(pem)).collect();

    fn parse_root(der: &[u8]) -> Option<X509Certificate<'_>> {
        X509Certificate::from_der(der).ok().map(|(_, cert)| cert)
    }

    fn certificate_valid_at(certificate: &X509Certificate<'_>, at: i64) -> bool {
        let validity = certificate.validity();
        at >= validity.not_before.timestamp() && at <= validity.not_after.timestamp()
    }

    fn certificate_is_ca(certificate: &X509Certificate<'_>) -> bool {
        certificate.extensions().iter().any(|extension| {
            matches!(
                extension.parsed_extension(),
                ParsedExtension::BasicConstraints(constraints) if constraints.ca
            )
        })
    }

    let at = i64::try_from(integrated_time).unwrap_or(i64::MAX);
    tracing::trace!(
        root_count = roots_owned.len(),
        "checking Fulcio certificate chain"
    );
    let issued_directly_by_root = roots_owned.iter().any(|root_der| {
        parse_root(root_der).is_some_and(|root| {
            leaf.issuer() == root.subject()
                && certificate_valid_at(&root, at)
                && certificate_is_ca(&root)
                && fulcio_extensions_permit_role(&root, Some(0))
                && verify_x509_signature(
                    root.public_key().raw,
                    leaf.tbs_certificate.as_ref(),
                    leaf.signature_value.data.as_ref(),
                    &leaf.signature_algorithm.algorithm.to_string(),
                )
        })
    });

    if issued_directly_by_root {
        // At least one currently valid trust root verified the leaf. Other
        // roots with the same subject do not invalidate that successful chain.
    } else if let Some(intermediate_der) = inter_der.as_deref() {
        let (_, intermediate) = X509Certificate::from_der(intermediate_der).ok()?;

        if leaf.issuer() != intermediate.subject()
            || !certificate_valid_at(&intermediate, at)
            || !certificate_is_ca(&intermediate)
            || !fulcio_extensions_permit_role(&intermediate, Some(0))
        {
            return None;
        }
        if !verify_x509_signature(
            intermediate.public_key().raw,
            leaf.tbs_certificate.as_ref(),
            leaf.signature_value.data.as_ref(),
            &leaf.signature_algorithm.algorithm.to_string(),
        ) {
            return None;
        }
        let chained_to_a_root = roots_owned.iter().any(|root_der| {
            parse_root(root_der).is_some_and(|root| {
                intermediate.issuer() == root.subject()
                    && certificate_valid_at(&root, at)
                    && certificate_is_ca(&root)
                    && fulcio_extensions_permit_role(&root, Some(1))
                    && verify_x509_signature(
                        root.public_key().raw,
                        intermediate.tbs_certificate.as_ref(),
                        intermediate.signature_value.data.as_ref(),
                        &intermediate.signature_algorithm.algorithm.to_string(),
                    )
            })
        });
        if !chained_to_a_root {
            return None;
        }
    } else {
        // No intermediate provided and no direct-root match: cannot chain.
        return None;
    }

    // Every certificate in the selected chain must cover the moment Rekor
    // recorded the entry.
    if !certificate_valid_at(&leaf, at) {
        return None;
    }
    // Fulcio profile constraints on the LEAF (audit sec2 F-05):
    // - must NOT be a CA (BasicConstraints)
    // - must carry the CodeSigning extended key usage
    let mut is_ca = false;
    let mut has_code_signing_eku = false;
    for ext in leaf.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::BasicConstraints(bc) => is_ca = bc.ca,
            ParsedExtension::ExtendedKeyUsage(eku)
                // codeSigning OID 1.3.6.1.5.5.7.3.3
                if eku.code_signing => {
                    has_code_signing_eku = true;
                }
            _ => {}
        }
    }
    if is_ca || !has_code_signing_eku {
        return None;
    }

    fulcio_signer_identity(&leaf)
}

/// The OIDC identity SAN on a Fulcio leaf.
///
/// Fulcio binds keyless identities as an email (web flow) or a URI (CI
/// workload). A DNS SAN is never the OIDC identity, so it must not win over
/// a later email/URI SAN, and a first-match-return across mixed entries
/// would pick whichever name happens to be ordered first.
fn fulcio_signer_identity(leaf: &x509_parser::certificate::X509Certificate<'_>) -> Option<String> {
    use x509_parser::prelude::*;

    for ext in leaf.extensions() {
        let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() else {
            continue;
        };
        let mut first_uri = None;
        for name in &san.general_names {
            match name {
                GeneralName::RFC822Name(email) => return Some(email.to_string()),
                GeneralName::URI(uri) if first_uri.is_none() => {
                    first_uri = Some(uri.to_string());
                }
                _ => {}
            }
        }
        if let Some(uri) = first_uri {
            return Some(uri);
        }
    }
    None
}

impl SlsaVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: shared_client().clone(),
            rekor_url: "https://rekor.sigstore.dev".to_string(),
        }
    }

    /// Query Rekor transparency log for an artifact hash
    pub async fn query_rekor(&self, artifact_hash: &str) -> Result<Vec<RekorEntry>, SlsaError> {
        let url = format!("{}/api/v1/index/retrieve", self.rekor_url);

        let response = self
            .client
            .post(&url)
            .json(&serde_json::json!({
                "hash": format!("sha256:{}", artifact_hash)
            }))
            .send()
            .await
            .map_err(|source| SlsaError::RekorRequest { source })?;

        rekor_http_must_succeed(response.status())?;

        let uuids: Vec<String> = response
            .bounded_json()
            .await
            .map_err(|source| SlsaError::RekorIndexJson { source })?;

        let mut entries = Vec::new();
        for uuid in uuids.iter().take(5) {
            entries.push(self.get_rekor_entry(uuid).await?);
        }

        Ok(entries)
    }

    /// Get a specific Rekor entry by UUID.
    ///
    /// The entry's SignedEntryTimestamp is verified against the pinned Rekor
    /// public key (see [`parse_rekor_entry`]) before the entry's contents are
    /// returned; entries without a verifiable SET are refused.
    async fn get_rekor_entry(&self, uuid: &str) -> Result<RekorEntry, SlsaError> {
        let url = format!("{}/api/v1/log/entries/{}", self.rekor_url, uuid);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|source| SlsaError::RekorEntryRequest { source })?;

        rekor_http_must_succeed(response.status())?;

        let entry_map: HashMap<String, Value> = response
            .bounded_json()
            .await
            .map_err(|source| SlsaError::RekorEntryJson { source })?;
        Ok(parse_rekor_entry(uuid, entry_map)?)
    }

    /// Attempt REAL cryptographic verification of a Rekor `hashedrekord`
    /// entry against an artifact digest.
    ///
    /// Steps: decode the base64 entry body, require kind `hashedrekord`,
    /// require its recorded SHA-256 to match the artifact digest, then verify
    /// the embedded signature over that digest with the embedded public key
    /// (RSA PKCS#1 v1.5 with SHA-256, or P-256 ECDSA with SHA-256 — the two
    /// key types Sigstore issues). Other entry kinds report honestly as
    /// unverified rather than pretending.
    fn verify_rekor_entry(
        entry: &RekorEntry,
        artifact_hash: &str,
        artifact_bytes: &[u8],
        fulcio_roots: &[&str],
        fulcio_intermediate: &str,
    ) -> Result<(bool, Option<String>), SlsaError> {
        use base64::Engine as _;

        let body_json = base64::engine::general_purpose::STANDARD
            .decode(entry.body.trim())
            .map_err(|source| SlsaError::RekorBodyDecode { source })?;
        let body: serde_json::Value = serde_json::from_slice(&body_json)
            .map_err(|source| SlsaError::RekorBodyJson { source })?;

        if body.get("kind").and_then(serde_json::Value::as_str) != Some("hashedrekord") {
            // intoto/other kinds are not verified by this engine yet.
            return Ok((false, None));
        }

        let spec = body
            .get("spec")
            .ok_or(SlsaError::RekorBodyMissingField { field: "spec" })?;
        let recorded_hash = spec
            .pointer("/data/hash/value")
            .and_then(serde_json::Value::as_str)
            .ok_or(SlsaError::RekorBodyMissingField {
                field: "spec.data.hash.value",
            })?;
        // The log must be attesting THIS artifact, byte-for-byte.
        if !recorded_hash.eq_ignore_ascii_case(artifact_hash) {
            return Ok((false, None));
        }

        let signature_b64 = spec
            .pointer("/signature/content")
            .and_then(serde_json::Value::as_str)
            .ok_or(SlsaError::RekorBodyMissingField {
                field: "spec.signature.content",
            })?;
        let pem_b64 = spec
            .pointer("/signature/publicKey/content")
            .and_then(serde_json::Value::as_str)
            .ok_or(SlsaError::RekorBodyMissingField {
                field: "spec.signature.publicKey.content",
            })?;

        let base64_engine = base64::engine::general_purpose::STANDARD;
        let signature = base64_engine
            .decode(signature_b64.trim())
            .map_err(|source| SlsaError::RekorBodyDecode { source })?;
        let pem_bytes = base64_engine
            .decode(pem_b64.trim())
            .map_err(|source| SlsaError::RekorBodyDecode { source })?;
        let pem = String::from_utf8_lossy(&pem_bytes);
        let pem = pem.trim();

        // Fulcio certificate path: bind the signature to an OIDC identity by
        // validating the leaf chain against the embedded Sigstore roots.
        if pem.contains("BEGIN CERTIFICATE") {
            let der = decode_pem_body(pem, "CERTIFICATE")
                .map_err(|source| SlsaError::RekorBodyDecode { source })?;
            let Some(signer) = verify_fulcio_chain(
                &der,
                entry.integrated_time,
                fulcio_roots,
                fulcio_intermediate,
            ) else {
                return Ok((false, None));
            };
            // The artifact signature must verify with the CERTIFICATE's key.
            let spki = {
                use x509_parser::prelude::*;
                let (_, cert) =
                    X509Certificate::from_der(&der).map_err(|_| SlsaError::SignatureMalformed)?;
                cert.public_key().raw.to_vec()
            };
            return Ok((
                Self::verify_digest_with_bytes(&spki, artifact_hash, artifact_bytes, &signature),
                Some(signer),
            ));
        }

        // Plain public-key path. Rekor accepts entries from anyone, so a
        // self-consistent key+signature pair proves nothing about who built
        // the artifact. Fulcio-certified entries carry an OIDC identity and
        // are verified above; a bare key can only be trusted when pinned
        // out-of-band, which this API does not accept. Never report verified
        // here — an attacker controlling distribution can produce one for any
        // artifact bytes they ship.
        Self::verify_digest_with_spki_from_pem(pem, &signature, artifact_hash, artifact_bytes)
            .map(|(integrity_ok, _signer)| {
                if integrity_ok {
                    tracing::info!(
                        "Rekor entry is a plain public-key self-attestation;                          treated as unverified (no signer identity)"
                    );
                }
                (false, None)
            })
    }

    /// Verify `signature` over the SHA-256 digest hex over the artifact,
    /// using a PEM-encoded PUBLIC KEY.
    fn verify_digest_with_spki_from_pem(
        pem: &str,
        signature: &[u8],
        artifact_hash: &str,
        artifact_bytes: &[u8],
    ) -> Result<(bool, Option<String>), SlsaError> {
        let der = decode_pem_body(pem, "PUBLIC KEY")
            .map_err(|source| SlsaError::RekorBodyDecode { source })?;
        Ok((
            Self::verify_digest_with_bytes(&der, artifact_hash, artifact_bytes, signature),
            None,
        ))
    }

    /// Verify `signature` over `artifact_bytes` (whose SHA-256 must be
    /// `artifact_hash`) with an SPKI-DER encoded public key. Rekor
    /// hashedrekord signatures cover the artifact content; RSA is verified via
    /// its SHA-256 prehash while P-256 ECDSA hashes the message itself, so the
    /// artifact bytes travel with the call for both arms. Returns false for
    /// other key types or a digest mismatch.
    /// # Errors
    ///
    /// Propagates errors only from upstream decode paths; a cryptographic
    /// mismatch is reported as `Ok(false)`, never as `Err`.
    fn verify_digest_with_bytes(
        issuer_spki_der: &[u8],
        artifact_hash: &str,
        artifact_bytes: &[u8],
        signature: &[u8],
    ) -> bool {
        let Ok(digest) = <[u8; 32] as hex::FromHex>::from_hex(artifact_hash) else {
            return false;
        };
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, artifact_bytes);
        if !hex::encode(sha2::Digest::finalize(hasher)).eq_ignore_ascii_case(artifact_hash) {
            return false;
        }
        // The decoded digest IS SHA-256(artifact bytes): Rekor hashedrekord
        // signatures cover the artifact content with the scheme's hash, so
        // verification must treat the digest as the prehash. Feeding it
        // through a second hash would make every genuine entry fail.
        {
            use rsa::pkcs8::DecodePublicKey as _;
            if let Ok(key) = rsa::RsaPublicKey::from_public_key_der(issuer_spki_der) {
                use rsa::signature::hazmat::PrehashVerifier;
                let verifying = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(key);
                let Ok(sig) = rsa::pkcs1v15::Signature::try_from(signature) else {
                    return false;
                };
                return verifying.verify_prehash(&digest, &sig).is_ok();
            }
        }

        {
            use p256::pkcs8::DecodePublicKey as _;
            if let Ok(key) = p256::PublicKey::from_public_key_der(issuer_spki_der) {
                let verifying = p256::ecdsa::VerifyingKey::from(key);
                let Ok(sig) = p256::ecdsa::Signature::from_der(signature) else {
                    return false;
                };
                use p256::ecdsa::signature::Verifier as _;
                return verifying.verify(artifact_bytes, &sig).is_ok();
            }
        }

        false
    }

    /// Verify SLSA provenance for a package
    /// Gather provenance evidence for an artifact, then cryptographically
    /// verify it when possible.
    ///
    /// Queries the Rekor transparency log and verifies each `hashedrekord`
    /// entry's embedded signature over the artifact digest (RSA or P-256).
    /// A local provenance file is parsed for context but unsigned local JSON
    /// must not treat an `Ok` result as a verified attestation.
    pub async fn verify_provenance(
        &self,
        blob_path: impl AsRef<Path>,
        provenance_path: Option<impl AsRef<Path>>,
        required_identity: Option<&str>,
    ) -> Result<VerificationResult, SlsaError> {
        if required_identity.is_none_or(|identity| identity.trim().is_empty()) {
            return Err(SlsaError::IdentityRequired);
        }
        // Calculate artifact hash, keeping the bytes around: P-256 ECDSA
        // verification hashes the message itself, so the artifact content
        // must be available at verification time.
        let artifact_bytes = std::fs::read(&blob_path).map_err(|source| SlsaError::Read {
            path: blob_path.as_ref().display().to_string(),
            source,
        })?;
        let artifact_hash = {
            let mut hasher = sha2::Sha256::new();
            sha2::Digest::update(&mut hasher, &artifact_bytes);
            hex::encode(sha2::Digest::finalize(hasher))
        };

        // Check Rekor for transparency log entries, then attempt REAL
        // cryptographic verification of the best candidate.
        let rekor_entries = self.query_rekor(&artifact_hash).await?;

        for entry in &rekor_entries {
            let Ok((verified, signer)) = Self::verify_rekor_entry(
                entry,
                &artifact_hash,
                &artifact_bytes,
                &[FULCIO_ROOT_PEM, FULCIO_INTERMEDIATE_PEM],
                FULCIO_INTERMEDIATE_PEM,
            ) else {
                continue;
            };
            // Trust POLICY (audit sec2 F-05): a signature from any Sigstore
            // identity is cryptographically valid but only meaningful when it
            // matches the caller's expected signer. When a required identity
            // is supplied, a mismatch demotes the result to unverified.
            if verified && required_identity.is_some() && signer.as_deref() != required_identity {
                continue;
            }
            if verified {
                // Signature over this exact artifact digest verified with
                // the key embedded in the transparency-log entry. When the
                // key came from a Fulcio certificate chaining to the embedded
                // Sigstore roots, `signer` is the OIDC identity bound by the
                // CA; plain-key entries verify integrity only.
                return Ok(VerificationResult {
                    verified: true,
                    // A hashedrekord plus a valid SET proves the artifact
                    // signature and signed entry data, but this path does
                    // not verify a Merkle inclusion proof or build provenance.
                    slsa_level: SlsaLevel::None,
                    transparency_log_entry: Some(entry.uuid.clone()),
                    builder_id: signer,
                    build_timestamp: None,
                    error: None,
                });
            }
        }

        if let Some(entry) = rekor_entries.first() {
            let mut result = classify_slsa_evidence(SlsaEvidence::RekorIndexHit);
            result.transparency_log_entry = Some(entry.uuid.clone());
            return Ok(result);
        }

        if let Some(prov_path) = provenance_path
            && prov_path.as_ref().exists()
        {
            let path_str = prov_path.as_ref().display().to_string();
            let content =
                std::fs::read_to_string(prov_path.as_ref()).map_err(|source| SlsaError::Read {
                    path: path_str,
                    source,
                })?;
            let _: SlsaProvenance = serde_json::from_str(&content)
                .map_err(|source| SlsaError::ProvenanceParse { source })?;
            return Ok(classify_slsa_evidence(SlsaEvidence::UnsignedLocalJson));
        }

        Ok(classify_slsa_evidence(SlsaEvidence::None))
    }

    /// Calculate SHA-256 hash of a file
    fn calculate_hash<P: AsRef<Path>>(path: P) -> Result<String, SlsaError> {
        use std::io::Read as _;

        let path_str = path.as_ref().display().to_string();
        let mut hasher = Sha256::new();
        let mut file = std::fs::File::open(&path).map_err(|source| SlsaError::Read {
            path: path_str.clone(),
            source,
        })?;
        let mut buffer = [0u8; 8192];
        loop {
            let read = file.read(&mut buffer).map_err(|source| SlsaError::Read {
                path: path_str.clone(),
                source,
            })?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(hex::encode(hasher.finalize()))
    }

    /// Verify the SHA-256 hash of a file against an expected hex digest.
    ///
    /// The comparison accepts either hex case so uppercase digests from
    /// external attestations cannot silently mismatch.
    pub fn verify_hash<P: AsRef<Path>>(
        &self,
        path: P,
        expected_hash: &str,
    ) -> Result<bool, SlsaError> {
        let actual_hash = Self::calculate_hash(path)?;
        Ok(actual_hash.eq_ignore_ascii_case(expected_hash))
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use std::collections::HashMap;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn rekor_index_applies_body_limit_before_json_and_accepts_small_results() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fixture listener");
        let address = listener.local_addr().expect("fixture address");
        let server = tokio::spawn(async move {
            for response in [
                b"HTTP/1.1 200 OK\r\nContent-Length: 16777217\r\nConnection: close\r\n\r\n"
                    .as_slice(),
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]".as_slice(),
            ] {
                let (mut stream, _) = listener.accept().await.expect("fixture connection");
                let mut request = [0; 2048];
                let bytes_read = stream.read(&mut request).await.expect("read request");
                assert!(bytes_read > 0, "empty request");
                stream.write_all(response).await.expect("write response");
            }
        });
        let verifier = SlsaVerifier {
            client: reqwest::Client::builder()
                .no_proxy()
                .build()
                .expect("fixture client"),
            rekor_url: format!("http://{address}"),
        };
        let error = verifier
            .query_rekor(&"a".repeat(64))
            .await
            .expect_err("oversized index");
        assert!(matches!(error, SlsaError::RekorIndexJson { .. }));
        assert!(
            verifier
                .query_rekor(&"a".repeat(64))
                .await
                .expect("small index")
                .is_empty()
        );
        server.await.expect("fixture server");
    }

    #[test]
    fn pem_boundaries_never_strip_begin_or_end_from_encoded_data() {
        use base64::Engine as _;
        for label in ["CERTIFICATE", "PUBLIC KEY"] {
            for newline in ["\n", "\r\n"] {
                let encoded = "BEGINAAAENDx";
                let pem = format!(
                    "-----BEGIN {label}-----{newline}{encoded}{newline}-----END {label}-----{newline}"
                );
                let expected = base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .unwrap();
                assert_eq!(decode_pem_body(&pem, label).unwrap(), expected);
                assert_eq!(decode_pem_body(encoded, label).unwrap(), expected);
                assert!(decode_pem_body(&pem.replace("ENDx", "!NDx"), label).is_err());
                assert!(
                    decode_pem_body(
                        &pem.replace(&format!("-----END {label}-----"), "-----END WRONG-----"),
                        label
                    )
                    .is_err()
                );
            }
        }
    }

    #[test]
    fn test_slsa_level_display() {
        assert_eq!(SlsaLevel::None.to_string(), "None");
        assert_eq!(SlsaLevel::Level1.to_string(), "SLSA Level 1");
        assert_eq!(SlsaLevel::Level2.to_string(), "SLSA Level 2");
        assert_eq!(SlsaLevel::Level3.to_string(), "SLSA Level 3");
    }

    #[test]
    fn test_slsa_level_ordering() {
        assert!(SlsaLevel::Level3 > SlsaLevel::Level2);
        assert!(SlsaLevel::Level2 > SlsaLevel::Level1);
        assert!(SlsaLevel::Level1 > SlsaLevel::None);
    }

    #[test]
    fn test_calculate_hash() {
        let mut temp = NamedTempFile::new().unwrap();
        use std::io::Write;
        write!(temp, "test content").unwrap();
        temp.flush().unwrap();

        let hash = SlsaVerifier::calculate_hash(temp.path()).unwrap();

        // Verify it's a valid SHA-256 hash (64 hex characters)
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));

        // Known hash for "test content" (no newline)
        assert_eq!(
            hash,
            "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72"
        );
    }

    #[test]
    fn test_calculate_hash_empty_file() {
        let temp = NamedTempFile::new().unwrap();
        let hash = SlsaVerifier::calculate_hash(temp.path()).unwrap();

        // SHA-256 of empty file
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn calculate_hash_fails_closed_when_file_is_missing() {
        let err = SlsaVerifier::calculate_hash("/no/such/artifact.bin")
            .expect_err("a missing artifact must not produce a hash");
        assert!(matches!(err, SlsaError::Read { .. }), "got: {err}");
    }

    #[test]
    fn test_verify_hash_success() {
        let mut temp = NamedTempFile::new().unwrap();
        use std::io::Write;
        write!(temp, "test content").unwrap();
        temp.flush().unwrap();

        let verifier = SlsaVerifier::default();
        let expected = "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72";

        assert!(verifier.verify_hash(temp.path(), expected).unwrap());
    }

    #[test]
    fn test_verify_hash_mismatch() {
        let mut temp = NamedTempFile::new().unwrap();
        use std::io::Write;
        write!(temp, "test content").unwrap();
        temp.flush().unwrap();

        let verifier = SlsaVerifier::default();
        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";

        assert!(!verifier.verify_hash(temp.path(), wrong_hash).unwrap());
    }

    #[test]
    fn test_slsa_verifier_default() {
        let verifier = SlsaVerifier::default();
        assert_eq!(verifier.rekor_url, "https://rekor.sigstore.dev");
    }

    #[test]
    fn rekor_index_hit_is_not_slsa_level2() {
        let result = classify_slsa_evidence(SlsaEvidence::RekorIndexHit);
        assert!(
            !result.verified,
            "a Rekor UUID is not a verified attestation"
        );
        assert_eq!(result.slsa_level, SlsaLevel::None);
        assert!(
            result
                .error
                .as_deref()
                .is_some_and(|e| e.contains("not in-toto")),
            "got: {:?}",
            result.error
        );
    }

    #[test]
    fn unsigned_local_json_is_not_slsa_level1() {
        let result = classify_slsa_evidence(SlsaEvidence::UnsignedLocalJson);
        assert!(!result.verified, "parsed JSON is not a signature check");
        assert_eq!(result.slsa_level, SlsaLevel::None);
    }

    #[test]
    fn missing_evidence_is_unverified() {
        let result = classify_slsa_evidence(SlsaEvidence::None);
        assert!(!result.verified);
        assert_eq!(result.slsa_level, SlsaLevel::None);
    }

    #[test]
    fn rekor_http_failure_is_an_error() {
        let err = rekor_http_must_succeed(reqwest::StatusCode::INTERNAL_SERVER_ERROR)
            .expect_err("HTTP failure must not look like no entry");
        assert!(
            matches!(err, RekorError::HttpFailed { status: 500 }),
            "got: {err}"
        );
        assert!(rekor_http_must_succeed(reqwest::StatusCode::OK).is_ok());
    }

    #[test]
    fn rekor_entry_missing_fields_is_an_error() {
        let mut incomplete = HashMap::new();
        incomplete.insert(
            "abc".to_string(),
            serde_json::json!({ "logIndex": 1, "body": "x" }),
        );
        let err =
            parse_rekor_entry("abc", incomplete).expect_err("missing integratedTime must fail");
        assert!(
            matches!(
                err,
                RekorError::EntryMissingField {
                    field: "integratedTime",
                    ..
                }
            ),
            "got: {err}"
        );
    }

    #[test]
    fn rekor_entry_non_u64_field_is_an_error() {
        let mut invalid = HashMap::new();
        invalid.insert(
            "abc".to_string(),
            serde_json::json!({ "logIndex": "1", "integratedTime": 2, "body": "x" }),
        );
        let err = parse_rekor_entry("abc", invalid).expect_err("string logIndex must fail");
        assert!(
            matches!(
                err,
                RekorError::EntryInvalidField {
                    field: "logIndex",
                    ..
                }
            ),
            "got: {err}"
        );
    }

    #[test]
    fn rekor_entry_wrong_uuid_is_an_error() {
        let mut other = HashMap::new();
        other.insert(
            "other".to_string(),
            serde_json::json!({ "logIndex": 1, "integratedTime": 2, "body": "x" }),
        );
        let err = parse_rekor_entry("wanted", other).expect_err("wrong uuid must fail");
        assert!(
            matches!(err, RekorError::EntryNotFound { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn empty_rekor_entry_map_is_an_error() {
        let err = parse_rekor_entry("abc", HashMap::new()).expect_err("empty map must fail");
        assert!(matches!(err, RekorError::EmptyEntryMap), "got: {err}");
    }
    #[test]
    fn rekor_entry_verification_roundtrips_rsa_and_p256() {
        use base64::Engine as _;
        let artifact_bytes = b"omg release artifact bytes (wave-12 fixture)".to_vec();
        let mut fixture_hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut fixture_hasher, artifact_bytes.as_slice());
        let artifact_hash = hex::encode(sha2::Digest::finalize(fixture_hasher));
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);

        let make_body = |pem: &str, sig: &[u8]| {
            let body = serde_json::json!({
                "kind": "hashedrekord",
                "spec": {
                    "data": {"hash": {"algorithm": "sha256", "value": artifact_hash}},
                    "signature": {
                        "content": b64(sig),
                        "publicKey": {"content": b64(pem.as_bytes())}
                    }
                }
            });
            b64(body.to_string().as_bytes())
        };

        // --- RSA roundtrip ---
        let mut rng = rsa::rand_core::OsRng;
        let private = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        let public = rsa::RsaPublicKey::from(&private);
        let pem = {
            use rsa::pkcs8::EncodePublicKey as _;
            public
                .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
                .expect("spki pem")
        };
        let rsa_spki_der = {
            use rsa::pkcs8::EncodePublicKey as _;
            public.to_public_key_der().expect("rsa spki der")
        };
        let signing = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private);
        use rsa::signature::SignatureEncoding as _;
        use rsa::signature::hazmat::PrehashSigner as _;
        // Rekor hashedrekord signatures cover the artifact bytes; the
        // prehash is SHA-256(artifact). Wave-12 F2: the old verifier fed the
        // digest through a second hash, so genuine entries never verified.
        let prehash = {
            let mut hasher = sha2::Sha256::new();
            sha2::Digest::update(&mut hasher, artifact_bytes.as_slice());
            sha2::Digest::finalize(hasher)
        };
        let good_sig: rsa::pkcs1v15::Signature = signing.sign_prehash(&prehash).unwrap();
        let bad_sig: rsa::pkcs1v15::Signature = signing.sign_prehash(&[0u8; 32]).unwrap();

        for (sig, integrity_expected) in
            [(&good_sig.to_bytes(), true), (&bad_sig.to_bytes(), false)]
        {
            let entry = RekorEntry {
                uuid: "t".into(),
                log_index: 0,
                integrated_time: u64::try_from(jiff::Timestamp::now().as_second()).unwrap(),
                body: make_body(&pem, sig),
            };
            let (verified, _) = SlsaVerifier::verify_rekor_entry(
                &entry,
                &artifact_hash,
                artifact_bytes.as_slice(),
                &[],
                "",
            )
            .unwrap();
            assert!(
                !verified,
                "plain-key entries are self-attestations and never verify"
            );
            assert_eq!(
                SlsaVerifier::verify_digest_with_bytes(
                    rsa_spki_der.as_bytes(),
                    &artifact_hash,
                    artifact_bytes.as_slice(),
                    sig,
                ),
                integrity_expected,
                "RSA verification must distinguish correct and incorrect artifact signatures"
            );
        }

        // Hash mismatch must fail even with a valid signature.
        let entry = RekorEntry {
            uuid: "t".into(),
            log_index: 0,
            integrated_time: u64::try_from(jiff::Timestamp::now().as_second()).unwrap(),
            body: make_body(&pem, &good_sig.to_bytes()),
        };
        let (verified, _) =
            SlsaVerifier::verify_rekor_entry(&entry, &"b".repeat(64), &[0x62u8; 32], &[], "")
                .unwrap();
        assert!(!verified, "recorded-hash mismatch must not verify");

        // --- P-256 roundtrip ---
        let p256_signing = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        use p256::pkcs8::EncodePublicKey as _;
        // SigningKey derefs to its VerifyingKey; SPKI PEM of the public key.
        let p256_pem = p256_signing
            .verifying_key()
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .unwrap();
        let good_ec: p256::ecdsa::Signature = {
            use p256::ecdsa::signature::Signer as _;
            p256_signing.sign(artifact_bytes.as_slice())
        };
        let ec_der: Vec<u8> = p256::ecdsa::Signature::to_der(&good_ec).as_bytes().to_vec();
        let now = u64::try_from(jiff::Timestamp::now().as_second()).unwrap();
        let entry = RekorEntry {
            uuid: "t2".into(),
            log_index: 0,
            integrated_time: now,
            body: make_body(&p256_pem, &ec_der),
        };
        // Entry-level: plain-key is never "verified" (self-attestation).
        let (entry_verified, signer) = SlsaVerifier::verify_rekor_entry(
            &entry,
            &artifact_hash,
            artifact_bytes.as_slice(),
            &[],
            "",
        )
        .unwrap();
        assert!(!entry_verified);
        assert!(signer.is_none());
        let spki_der = {
            use p256::pkcs8::DecodePublicKey as _;
            p256::PublicKey::from_public_key_pem(&p256_pem)
                .expect("spki pem")
                .to_public_key_der()
                .expect("spki der")
                .to_vec()
        };
        // Crypto-level: the corrected ECDSA path verifies the signature over
        // the artifact content (message hashed with SHA-256 inside the scheme).
        assert!(
            SlsaVerifier::verify_digest_with_bytes(
                &spki_der,
                &artifact_hash,
                artifact_bytes.as_slice(),
                p256::ecdsa::Signature::to_der(&good_ec).as_bytes(),
            ),
            "P-256 signature over the artifact content must verify"
        );
        assert!(
            !SlsaVerifier::verify_digest_with_bytes(
                &spki_der,
                &artifact_hash,
                &[0x9u8; 32],
                p256::ecdsa::Signature::to_der(&good_ec).as_bytes(),
            ),
            "signature must not verify over other bytes"
        );

        // Non-hashedrekord kinds are honestly unverified.
        let intoto_body = b64(serde_json::json!({"kind": "intoto", "spec": {}})
            .to_string()
            .as_bytes());
        let entry = RekorEntry {
            uuid: "t3".into(),
            log_index: 0,
            integrated_time: u64::try_from(jiff::Timestamp::now().as_second()).unwrap(),
            body: intoto_body,
        };
        let (verified, signer) = SlsaVerifier::verify_rekor_entry(
            &entry,
            &artifact_hash,
            artifact_bytes.as_slice(),
            &[],
            "",
        )
        .unwrap();
        assert!(!verified, "unsupported kinds must not claim verification");
        assert!(signer.is_none());
    }
    #[test]
    fn fulcio_chain_rejects_expired_intermediate_at_rekor_time() {
        use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair};

        let root_key = KeyPair::generate().unwrap();
        let mut root_params = CertificateParams::new(vec!["root.example".to_string()]).unwrap();
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root = root_params.self_signed(&root_key).unwrap();

        let intermediate_key = KeyPair::generate().unwrap();
        let mut intermediate_params =
            CertificateParams::new(vec!["intermediate.example".to_string()]).unwrap();
        intermediate_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        intermediate_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        intermediate_params.not_after = rcgen::date_time_ymd(2021, 1, 1);
        let intermediate = intermediate_params
            .signed_by(&intermediate_key, &root, &root_key)
            .unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::new(Vec::new()).unwrap();
        leaf_params.subject_alt_names = vec![rcgen::SanType::Rfc822Name(
            "signer@example.com".try_into().unwrap(),
        )];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
        let leaf = leaf_params
            .signed_by(&leaf_key, &intermediate, &intermediate_key)
            .unwrap();

        let root_pem = root.pem();
        let roots = [root_pem.as_str()];
        let intermediate_pem = intermediate.pem();
        let before_expiry = 1_590_969_600; // 2020-06-01 UTC
        let after_expiry = 1_622_505_600; // 2021-06-01 UTC

        assert_eq!(
            verify_fulcio_chain(leaf.der(), before_expiry, &roots, &intermediate_pem).as_deref(),
            Some("signer@example.com"),
            "the same chain must bind the signer identity before intermediate expiry"
        );
        assert!(
            verify_fulcio_chain(leaf.der(), after_expiry, &roots, &intermediate_pem).is_none(),
            "an expired intermediate must invalidate the chain"
        );
    }

    #[test]
    fn fulcio_identity_ignores_dns_and_prefers_email_over_uri() {
        use rcgen::{CertificateParams, KeyPair, SanType};
        use x509_parser::prelude::{FromDer, X509Certificate};

        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["ignored.example".to_string()]).unwrap();
        params.subject_alt_names = vec![
            SanType::URI(
                "https://accounts.example.com/users/alice"
                    .try_into()
                    .unwrap(),
            ),
            SanType::DnsName("ignored.example".try_into().unwrap()),
            SanType::Rfc822Name("alice@example.com".try_into().unwrap()),
        ];
        let certificate = params.self_signed(&key).unwrap();
        let (_, parsed) = X509Certificate::from_der(certificate.der()).unwrap();

        assert_eq!(
            fulcio_signer_identity(&parsed).as_deref(),
            Some("alice@example.com")
        );
    }

    #[test]
    fn fulcio_certificate_chain_binds_signer_identity() {
        use base64::Engine as _;
        use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair};

        // Test CA standing in for the Sigstore root.
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(vec!["sigstore-test-root".to_string()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        // A valid serial deliberately puts END in a base64 BODY line. PEM
        // boundaries are whole delimiter lines, never arbitrary substrings.
        let ca = (0..3)
            .find_map(|padding| {
                let mut params = ca_params.clone();
                let mut serial = vec![1; padding];
                serial.extend([0x10, 0xd0, 0xf1].repeat(6));
                params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));
                let certificate = params.self_signed(&ca_key).unwrap();
                certificate
                    .pem()
                    .lines()
                    .any(|line| !line.starts_with("-----") && line.contains("END"))
                    .then_some(certificate)
            })
            .expect("fixture must contain END in certificate data");

        // Leaf issued to an OIDC identity, valid now. Fulcio records keyless
        // identities as URI SANs, so build the SAN explicitly (rcgen's
        // CertificateParams::new default would encode it as a DNS SAN, which
        // real Fulcio identities never are).
        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params =
            CertificateParams::new(vec!["https://accounts.example.com/users/alice".to_string()])
                .unwrap();
        leaf_params.subject_alt_names = vec![rcgen::SanType::URI(
            "https://accounts.example.com/users/alice"
                .try_into()
                .expect("ia5 uri"),
        )];
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "alice");
        // Fulcio profile: non-CA leaf with codeSigning EKU.
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
        leaf_params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        leaf_params.serial_number = Some(rcgen::SerialNumber::from_slice(
            &[0x10, 0xd0, 0xf1].repeat(6),
        ));
        let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();
        assert!(
            leaf.pem()
                .lines()
                .any(|line| !line.starts_with("-----") && line.contains("END")),
            "leaf fixture must also put END in encoded data"
        );

        let artifact_bytes = b"fulcio test artifact payload".to_vec();
        let mut fixture_hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut fixture_hasher, artifact_bytes.as_slice());
        let artifact_hash = hex::encode(sha2::Digest::finalize(fixture_hasher));
        let _ = &artifact_bytes;
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);

        let make_entry = |cert_pem: &str, sig: &[u8], when: u64| {
            let body = serde_json::json!({
                "kind": "hashedrekord",
                "spec": {
                    "data": {"hash": {"algorithm": "sha256", "value": artifact_hash}},
                    "signature": {
                        "content": b64(sig),
                        "publicKey": {"content": b64(cert_pem.as_bytes())}
                    }
                }
            });
            RekorEntry {
                uuid: "chain".into(),
                log_index: 1,
                integrated_time: when,
                body: b64(body.to_string().as_bytes()),
            }
        };

        // Sign the artifact content with the LEAF key (P-256, DER signature);
        // the verifier hashes the message with SHA-256, matching hashedrekord.
        use p256::ecdsa::signature::Signer as _;
        use p256::pkcs8::DecodePrivateKey as _;
        let signing = p256::ecdsa::SigningKey::from_pkcs8_der(&leaf_key.serialize_der()).unwrap();
        let good_sig: p256::ecdsa::Signature = signing.sign(artifact_bytes.as_slice());
        let bad_sig: p256::ecdsa::Signature = signing.sign(&[9u8; 32]);

        let cert_pem = leaf.pem();
        // The test CA stands in for the Sigstore Fulcio roots.
        let ca_pem = ca.pem();
        let ca_roots: Vec<&str> = vec![ca_pem.as_str()];
        let now = u64::try_from(jiff::Timestamp::now().as_second()).unwrap();

        assert_eq!(
            verify_fulcio_chain(leaf.der(), now, &ca_roots, "").as_deref(),
            Some("https://accounts.example.com/users/alice"),
            "generated certificate chain must bind identity"
        );
        assert!(
            SlsaVerifier::verify_digest_with_bytes(
                &leaf_key.public_key_der(),
                &artifact_hash,
                &artifact_bytes,
                good_sig.to_der().as_bytes(),
            ),
            "generated artifact signature must verify"
        );

        // Valid chain + correct signature -> verified AND identity bound.
        let entry = make_entry(&cert_pem, good_sig.to_der().as_bytes(), now);
        let (verified, signer) = SlsaVerifier::verify_rekor_entry(
            &entry,
            &artifact_hash,
            &artifact_bytes,
            &ca_roots,
            "",
        )
        .unwrap();
        assert!(verified, "valid chain + signature must verify");
        assert_eq!(
            signer.as_deref(),
            Some("https://accounts.example.com/users/alice"),
            "Fulcio SAN must be reported as the signer identity"
        );

        // Wrong signature over the same valid chain -> unverified.
        let entry = make_entry(&cert_pem, bad_sig.to_der().as_bytes(), now);
        let (verified, _) = SlsaVerifier::verify_rekor_entry(
            &entry,
            &artifact_hash,
            artifact_bytes.as_slice(),
            &ca_roots,
            "",
        )
        .unwrap();
        assert!(
            !verified,
            "wrong signature must not verify even on a valid chain"
        );

        // Entry recorded before the certificate existed -> unverified.
        let entry = make_entry(&cert_pem, good_sig.to_der().as_bytes(), 0);
        let (verified, signer) = SlsaVerifier::verify_rekor_entry(
            &entry,
            &artifact_hash,
            artifact_bytes.as_slice(),
            &ca_roots,
            "",
        )
        .unwrap();
        assert!(
            !verified && signer.is_none(),
            "certificate validity window must gate verification"
        );
    }

    // Immutable upstream fixture, copied byte-for-byte from sigstore/sigstore-go
    // 5845298281875c153f40da081466ca716ff1abc6, pkg/testing/data/sigstoreBundle.json.
    // Blob 314f907ce302717882d21faefa5ed4de55018d0b; raw SHA-256
    // b3f8ae41764e44961cc795d585122560dbd77ef8e5652f202f8adeddcb57d132.
    // This proves captured SET acceptance only, not Merkle inclusion/provenance.
    fn captured_rekor_response() -> HashMap<String, Value> {
        use base64::Engine as _;
        let bundle: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/rekor-sigstore-bundle.json"
        ))
        .unwrap();
        let entry = &bundle["verificationMaterial"]["tlogEntries"][0];
        let log_id = hex::encode(
            base64::engine::general_purpose::STANDARD
                .decode(entry["logId"]["keyId"].as_str().unwrap())
                .unwrap(),
        );
        HashMap::from([(
            "captured".to_string(),
            serde_json::json!({
                "body": entry["canonicalizedBody"],
                "integratedTime": entry["integratedTime"].as_str().unwrap().parse::<u64>().unwrap(),
                "logIndex": entry["logIndex"].as_str().unwrap().parse::<u64>().unwrap(),
                "logID": log_id,
                "verification": {"signedEntryTimestamp": entry["inclusionPromise"]["signedEntryTimestamp"]}
            }),
        )])
    }

    #[test]
    fn captured_rekor_set_verifies_with_production_pin_and_rejects_tampering() {
        let response = captured_rekor_response();
        let verified = parse_rekor_entry("captured", response.clone()).unwrap();
        assert_eq!(verified.log_index, 6_800_908);
        assert_eq!(verified.integrated_time, 1_668_034_836);
        assert_eq!(
            verified.body,
            response["captured"]["body"].as_str().unwrap()
        );
        for (field, replacement) in [
            ("integratedTime", serde_json::json!(1_668_034_837_u64)),
            ("logIndex", serde_json::json!(6_800_909_u64)),
            ("body", serde_json::json!("YWx0ZXJlZA==")),
            (
                "logID",
                serde_json::json!(
                    "d0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"
                ),
            ),
        ] {
            let mut tampered = response.clone();
            tampered.get_mut("captured").unwrap()[field] = replacement;
            assert!(
                matches!(
                    parse_rekor_entry("captured", tampered),
                    Err(RekorError::EntrySetVerificationFailed { .. })
                ),
                "unchanged pinned SET must refuse tampered {field}"
            );
        }
        for field in ["body", "logID"] {
            for malformed in ["quote\"", "back\\slash", "non-ASCII-é"] {
                let mut response = captured_rekor_response();
                response.get_mut("captured").unwrap()[field] = serde_json::json!(malformed);
                assert!(
                    matches!(
                        parse_rekor_entry("captured", response),
                        Err(RekorError::EntrySetMalformed { .. })
                    ),
                    "malformed {field} must be refused before signature verification"
                );
            }
        }
    }

    #[test]
    fn rekor_safe_integer_boundaries_preserve_bytes_and_refuse_out_of_domain_fields() {
        const MAX: u64 = 9_007_199_254_740_991;
        for (index, time) in [(0, 0), (MAX, 0), (0, MAX), (MAX, MAX)] {
            assert_eq!(
                canonical_set_payload("ab", index, time, "YQ=="),
                Some(format!(
                    "{{\"body\":\"YQ==\",\"integratedTime\":{time},\"logID\":\"ab\",\"logIndex\":{index}}}"
                ))
            );
        }
        for field in ["logIndex", "integratedTime"] {
            for value in [MAX + 1, MAX + 2, u64::MAX] {
                let (index, time) = if field == "logIndex" {
                    (value, 0)
                } else {
                    (0, value)
                };
                assert!(canonical_set_payload("ab", index, time, "YQ==").is_none());
                let mut response = captured_rekor_response();
                response.get_mut("captured").unwrap()[field] = serde_json::json!(value);
                assert!(
                    matches!(
                        parse_rekor_entry("captured", response),
                        Err(RekorError::EntrySetMalformed { .. })
                    ),
                    "out-of-domain {field}={value} must be a typed refusal"
                );
            }
        }
    }

    fn policy_certificate_params(role: &str) -> rcgen::CertificateParams {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
            KeyUsagePurpose, SanType,
        };
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, role);
        if role == "leaf" {
            params.subject_alt_names = vec![SanType::Rfc822Name(
                "signer@example.com".try_into().unwrap(),
            )];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        } else {
            params.is_ca = IsCa::Ca(BasicConstraints::Constrained(u8::from(role == "root")));
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        }
        params
    }

    fn signed_policy_chain(
        root_params: rcgen::CertificateParams,
        intermediate_params: Option<rcgen::CertificateParams>,
        leaf_params: rcgen::CertificateParams,
    ) -> (rcgen::Certificate, String, String) {
        let root_key = rcgen::KeyPair::generate().unwrap();
        let root = root_params.self_signed(&root_key).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        if let Some(params) = intermediate_params {
            let intermediate_key = rcgen::KeyPair::generate().unwrap();
            let intermediate = params
                .signed_by(&intermediate_key, &root, &root_key)
                .unwrap();
            let leaf = leaf_params
                .signed_by(&leaf_key, &intermediate, &intermediate_key)
                .unwrap();
            (leaf, root.pem(), intermediate.pem())
        } else {
            let leaf = leaf_params.signed_by(&leaf_key, &root, &root_key).unwrap();
            (leaf, root.pem(), String::new())
        }
    }

    fn assert_policy_chain(chain: &(rcgen::Certificate, String, String), expected: bool) {
        let identity =
            verify_fulcio_chain(chain.0.der(), 1_700_000_000, &[chain.1.as_str()], &chain.2);
        assert_eq!(
            identity.as_deref(),
            expected.then_some("signer@example.com")
        );
    }

    fn policy_extension(oid: &[u64], content: Vec<u8>, critical: bool) -> rcgen::CustomExtension {
        let mut extension = rcgen::CustomExtension::from_oid_content(oid, content);
        extension.set_criticality(critical);
        extension
    }

    #[test]
    fn fulcio_signed_chains_enforce_present_role_key_usage() {
        for role in ["leaf", "intermediate", "root"] {
            for usage in [None, Some(true), Some(false)] {
                let mut root = policy_certificate_params("root");
                let mut intermediate = policy_certificate_params("intermediate");
                let mut leaf = policy_certificate_params("leaf");
                let selected = match role {
                    "root" => &mut root,
                    "intermediate" => &mut intermediate,
                    _ => &mut leaf,
                };
                selected.key_usages = match usage {
                    None => Vec::new(),
                    Some(true) if role == "leaf" => vec![rcgen::KeyUsagePurpose::DigitalSignature],
                    Some(true) => vec![rcgen::KeyUsagePurpose::KeyCertSign],
                    Some(false) => vec![rcgen::KeyUsagePurpose::KeyEncipherment],
                };
                assert_policy_chain(
                    &signed_policy_chain(root, Some(intermediate), leaf),
                    usage != Some(false),
                );
            }
        }
    }

    #[test]
    fn fulcio_signed_chains_refuse_unhandled_critical_extensions_by_selected_role() {
        for role in ["leaf", "intermediate", "root"] {
            for critical in [false, true] {
                for (oid, content) in [
                    (vec![1, 2, 3, 4], vec![0x05, 0x00]),
                    // Valid CertificatePolicies, recognized but not enforced.
                    (
                        vec![2, 5, 29, 32],
                        vec![0x30, 0x07, 0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04],
                    ),
                ] {
                    let mut root = policy_certificate_params("root");
                    let mut intermediate = policy_certificate_params("intermediate");
                    let mut leaf = policy_certificate_params("leaf");
                    let selected = match role {
                        "root" => &mut root,
                        "intermediate" => &mut intermediate,
                        _ => &mut leaf,
                    };
                    selected
                        .custom_extensions
                        .push(policy_extension(&oid, content, critical));
                    assert_policy_chain(
                        &signed_policy_chain(root, Some(intermediate), leaf),
                        !critical,
                    );
                }
            }
        }
    }

    #[test]
    fn fulcio_signed_chains_refuse_malformed_and_duplicate_extensions() {
        for role in ["leaf", "intermediate", "root"] {
            for duplicate in [false, true] {
                let mut root = policy_certificate_params("root");
                let mut intermediate = policy_certificate_params("intermediate");
                let mut leaf = policy_certificate_params("leaf");
                let selected = match role {
                    "root" => &mut root,
                    "intermediate" => &mut intermediate,
                    _ => &mut leaf,
                };
                let content = if duplicate {
                    vec![0x03, 0x02, 0x00, 0x84]
                } else {
                    vec![0xff]
                };
                if !duplicate {
                    selected.key_usages.clear();
                }
                selected
                    .custom_extensions
                    .push(policy_extension(&[2, 5, 29, 15], content, true));
                assert_policy_chain(&signed_policy_chain(root, Some(intermediate), leaf), false);
            }
        }
    }

    #[test]
    fn fulcio_supported_critical_leaf_extensions_and_unsupported_issuer_eku() {
        let mut leaf = policy_certificate_params("leaf");
        leaf.subject_alt_names.clear();
        leaf.extended_key_usages.clear();
        let email = b"signer@example.com";
        let mut san = vec![
            0x30,
            u8::try_from(email.len() + 2).unwrap(),
            0x81,
            u8::try_from(email.len()).unwrap(),
        ];
        san.extend_from_slice(email);
        let eku = vec![
            0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03,
        ];
        leaf.custom_extensions
            .push(policy_extension(&[2, 5, 29, 17], san, true));
        leaf.custom_extensions
            .push(policy_extension(&[2, 5, 29, 37], eku.clone(), true));
        assert_policy_chain(
            &signed_policy_chain(
                policy_certificate_params("root"),
                Some(policy_certificate_params("intermediate")),
                leaf,
            ),
            true,
        );
        for role in ["root", "intermediate"] {
            for critical in [false, true] {
                let mut root = policy_certificate_params("root");
                let mut intermediate = policy_certificate_params("intermediate");
                let selected = if role == "root" {
                    &mut root
                } else {
                    &mut intermediate
                };
                selected.custom_extensions.push(policy_extension(
                    &[2, 5, 29, 37],
                    eku.clone(),
                    critical,
                ));
                assert_policy_chain(
                    &signed_policy_chain(
                        root,
                        Some(intermediate),
                        policy_certificate_params("leaf"),
                    ),
                    !critical,
                );
            }
        }
    }

    #[test]
    fn fulcio_fixed_topology_path_lengths_roles_and_unselected_roots() {
        let mut root_zero = policy_certificate_params("root");
        root_zero.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        let direct =
            signed_policy_chain(root_zero.clone(), None, policy_certificate_params("leaf"));
        assert_policy_chain(&direct, true);
        assert_policy_chain(
            &signed_policy_chain(
                root_zero,
                Some(policy_certificate_params("intermediate")),
                policy_certificate_params("leaf"),
            ),
            false,
        );
        let valid = signed_policy_chain(
            policy_certificate_params("root"),
            Some(policy_certificate_params("intermediate")),
            policy_certificate_params("leaf"),
        );
        assert_policy_chain(&valid, true);
        for role in ["leaf", "intermediate", "root"] {
            let mut root = policy_certificate_params("root");
            let mut intermediate = policy_certificate_params("intermediate");
            let mut leaf = policy_certificate_params("leaf");
            let selected = match role {
                "root" => &mut root,
                "intermediate" => &mut intermediate,
                _ => &mut leaf,
            };
            selected.is_ca = if role == "leaf" {
                rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained)
            } else {
                rcgen::IsCa::ExplicitNoCa
            };
            assert_policy_chain(&signed_policy_chain(root, Some(intermediate), leaf), false);
        }
        let mut invalid_root = policy_certificate_params("root");
        invalid_root.custom_extensions.push(policy_extension(
            &[1, 2, 3, 4],
            vec![0x05, 0x00],
            true,
        ));
        let invalid_pem = invalid_root
            .self_signed(&rcgen::KeyPair::generate().unwrap())
            .unwrap()
            .pem();
        for roots in [
            [invalid_pem.as_str(), valid.1.as_str()],
            [valid.1.as_str(), invalid_pem.as_str()],
        ] {
            assert_eq!(
                verify_fulcio_chain(valid.0.der(), 1_700_000_000, &roots, &valid.2).as_deref(),
                Some("signer@example.com")
            );
        }
    }

    #[test]
    fn pinned_fulcio_issuer_extensions_fit_the_fixed_topology_policy() {
        use x509_parser::prelude::*;
        for (pem, count) in [(FULCIO_ROOT_PEM, 1), (FULCIO_INTERMEDIATE_PEM, 0)] {
            let der = decode_pem_body(pem, "CERTIFICATE").unwrap();
            let (_, certificate) = X509Certificate::from_der(&der).unwrap();
            assert!(fulcio_extensions_permit_role(&certificate, Some(count)));
        }
    }

    #[test]
    fn rekor_set_signature_over_canonical_form_roundtrips() {
        use p256::ecdsa::signature::Signer as _;

        let log_id = "c0d23d6ad406973f9559f3ba2d1ca01f";
        let body = "aGVsbG8="; // base64
        let canonical = canonical_set_payload(log_id, 12, 1_700_000_000, body).unwrap();
        // RFC 8785 form: keys sorted, no whitespace.
        assert_eq!(
            canonical,
            "{\"body\":\"aGVsbG8=\",\"integratedTime\":1700000000,\"logID\":\"c0d23d6ad406973f9559f3ba2d1ca01f\",\"logIndex\":12}"
        );

        let signing = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let key = signing.verifying_key();
        let signature: p256::ecdsa::Signature = signing.sign(canonical.as_bytes());
        let sig_der = signature.to_der();

        assert!(
            verify_set_signature(canonical.as_bytes(), sig_der.as_bytes(), key),
            "a valid ECDSA P-256 DER signature over the canonical form must verify"
        );
        // Tampered canonical bytes (one body character) must not verify.
        let tampered_body = canonical_set_payload(log_id, 12, 1_700_000_000, "aGVsbG9f").unwrap();
        assert!(
            !verify_set_signature(tampered_body.as_bytes(), sig_der.as_bytes(), key),
            "a tampered body must fail SET verification"
        );
        // Tampered integratedTime must not verify.
        let tampered_time = canonical_set_payload(log_id, 12, 1_700_000_001, body).unwrap();
        assert!(
            !verify_set_signature(tampered_time.as_bytes(), sig_der.as_bytes(), key),
            "a tampered integratedTime must fail SET verification"
        );
        // Tampered logID must not verify.
        let tampered_log = canonical_set_payload("deadbeef", 12, 1_700_000_000, body).unwrap();
        assert!(
            !verify_set_signature(tampered_log.as_bytes(), sig_der.as_bytes(), key),
            "a tampered logID must fail SET verification"
        );
        // Wrong key must not verify.
        let other = p256::ecdsa::SigningKey::from_slice(&[11u8; 32]).unwrap();
        assert!(
            !verify_set_signature(
                canonical.as_bytes(),
                sig_der.as_bytes(),
                other.verifying_key()
            ),
            "a signature from a different key must fail SET verification"
        );
        // Truncated DER signature must not verify.
        let der = sig_der.as_bytes();
        assert!(!verify_set_signature(
            canonical.as_bytes(),
            &der[..der.len() - 1],
            key
        ));
        // Non-DER garbage must not verify.
        assert!(!verify_set_signature(canonical.as_bytes(), &[0u8; 64], key));
    }

    /// Build a single-entry Rekor response map with a SET signed by the
    /// given P-256 signing key over the canonical form of the entry.
    fn rekor_response_with_set(
        uuid: &str,
        log_id: &str,
        log_index: u64,
        integrated_time: u64,
        body: &str,
        signing: &p256::ecdsa::SigningKey,
    ) -> HashMap<String, serde_json::Value> {
        use base64::Engine as _;
        use p256::ecdsa::signature::Signer as _;
        let canonical = canonical_set_payload(log_id, log_index, integrated_time, body).unwrap();
        let set: p256::ecdsa::Signature = signing.sign(canonical.as_bytes());
        HashMap::from([(
            uuid.to_string(),
            serde_json::json!({
                "body": body,
                "integratedTime": integrated_time,
                "logID": log_id,
                "logIndex": log_index,
                "verification": {
                    "signedEntryTimestamp":
                        base64::engine::general_purpose::STANDARD.encode(set.to_der().as_bytes())
                }
            }),
        )])
    }

    #[test]
    fn rekor_entry_without_signed_entry_timestamp_is_refused() {
        let mut no_verification = HashMap::new();
        no_verification.insert(
            "abc".to_string(),
            serde_json::json!({
                "logIndex": 1,
                "integratedTime": 2,
                "logID": "c0d23d6ad406973f9559f3ba2d1ca01f",
                "body": "aGVsbG8="
            }),
        );
        let err =
            parse_rekor_entry("abc", no_verification).expect_err("missing SET must be refused");
        assert!(
            matches!(
                err,
                RekorError::EntryMissingField {
                    field: "verification.signedEntryTimestamp",
                    ..
                }
            ),
            "got: {err}"
        );

        let mut no_set = HashMap::new();
        no_set.insert(
            "abc".to_string(),
            serde_json::json!({
                "logIndex": 1,
                "integratedTime": 2,
                "logID": "c0d23d6ad406973f9559f3ba2d1ca01f",
                "body": "aGVsbG8=",
                "verification": {}
            }),
        );
        let err = parse_rekor_entry("abc", no_set).expect_err("missing SET must be refused");
        assert!(
            matches!(
                err,
                RekorError::EntryMissingField {
                    field: "verification.signedEntryTimestamp",
                    ..
                }
            ),
            "got: {err}"
        );
    }

    #[test]
    fn rekor_entry_with_invalid_set_signature_is_rejected() {
        // A self-made key is NOT the pinned Rekor key, so even a well-formed,
        // self-consistent SET must be rejected by the pinned-key path.
        let signing = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let response = rekor_response_with_set(
            "abc",
            "c0d23d6ad406973f9559f3ba2d1ca01f",
            12,
            1_700_000_000,
            "aGVsbG8=",
            &signing,
        );
        let err = parse_rekor_entry("abc", response).expect_err("foreign-key SET must be rejected");
        assert!(
            matches!(err, RekorError::EntrySetVerificationFailed { .. }),
            "got: {err}"
        );
    }

    #[test]
    fn rekor_entry_with_tampered_body_is_rejected() {
        // Sign a valid SET, then tamper with the body: even if the signature
        // came from the pinned key, the tampered canonical bytes must fail.
        let signing = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let mut response = rekor_response_with_set(
            "abc",
            "c0d23d6ad406973f9559f3ba2d1ca01f",
            12,
            1_700_000_000,
            "aGVsbG8=",
            &signing,
        );
        response
            .get_mut("abc")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("body".to_string(), serde_json::json!("YWx0ZXJlZA=="));
        // The pinned key rejects first (foreign signature); a foreign-key
        // tampered body can never slip through either way.
        let err = parse_rekor_entry("abc", response)
            .expect_err("tampered body with foreign SET must be rejected");
        assert!(
            matches!(err, RekorError::EntrySetVerificationFailed { .. }),
            "got: {err}"
        );

        // Prove tampering alone is fatal: verify the ORIGINAL canonical bytes
        // against a signature made over TAMPERED canonical bytes.
        let key = signing.verifying_key();
        let original = canonical_set_payload(
            "c0d23d6ad406973f9559f3ba2d1ca01f",
            12,
            1_700_000_000,
            "aGVsbG8=",
        )
        .unwrap();
        let tampered = canonical_set_payload(
            "c0d23d6ad406973f9559f3ba2d1ca01f",
            12,
            1_700_000_000,
            "YWx0ZXJlZA==",
        )
        .unwrap();
        use p256::ecdsa::signature::Signer as _;
        let sig_over_tampered: p256::ecdsa::Signature = signing.sign(tampered.as_bytes());
        assert!(
            !verify_set_signature(
                original.as_bytes(),
                sig_over_tampered.to_der().as_bytes(),
                key
            ),
            "signature over tampered bytes must not verify over the original"
        );
    }

    #[test]
    fn rekor_entry_with_malformed_set_base64_is_refused() {
        let mut bad = HashMap::new();
        bad.insert(
            "abc".to_string(),
            serde_json::json!({
                "logIndex": 1,
                "integratedTime": 2,
                "logID": "c0d23d6ad406973f9559f3ba2d1ca01f",
                "body": "aGVsbG8=",
                "verification": {"signedEntryTimestamp": "!!!not-base64!!!"}
            }),
        );
        let err = parse_rekor_entry("abc", bad).expect_err("malformed SET base64 must be refused");
        assert!(
            matches!(err, RekorError::EntrySetMalformed { .. }),
            "got: {err}"
        );
    }

    /// The canonical bytes are built by raw `format!` interpolation, so a
    /// value that is not hex (logID) / not standard base64 (body) must be
    /// refused at runtime, not only under `debug_assert!` (stripped in
    /// release). Otherwise a body containing `"` splices extra JSON keys into
    /// the payload the SET is checked against.
    #[test]
    fn canonical_set_payload_rejects_non_base64_body_and_non_hex_log_id() {
        let log_id = "c0d23d6ad406973f9559f3ba2d1ca01f";
        // Quote-injecting body would splice duplicate keys into the template.
        // This tests input refusal, not acceptance of a pinned-key signature.
        assert!(
            canonical_set_payload(
                log_id,
                12,
                1_700_000_000,
                "aGVsbG8=\",\"integratedTime\":0,\"x"
            )
            .is_none(),
            "a body containing a double quote must be rejected"
        );
        assert!(
            canonical_set_payload(log_id, 12, 1_700_000_000, "aG\\s=\"b").is_none(),
            "a body containing a backslash must be rejected"
        );
        assert!(
            canonical_set_payload(log_id, 12, 1_700_000_000, "aGVsbG8=?").is_none(),
            "a body containing a non-base64 character must be rejected"
        );
        // Same for the logID slot.
        assert!(
            canonical_set_payload("deadbeef\", \"x\": 1", 12, 1_700_000_000, "aGVsbG8=").is_none(),
            "a non-hex logID must be rejected"
        );
        // Valid inputs are byte-identical to the pre-fix template output.
        let body = "aGVsbG8=";
        assert_eq!(
            canonical_set_payload(log_id, 12, 1_700_000_000, body),
            Some("{\"body\":\"aGVsbG8=\",\"integratedTime\":1700000000,\"logID\":\"c0d23d6ad406973f9559f3ba2d1ca01f\",\"logIndex\":12}".to_string())
        );
        // A padded base64 body with `+`/`/` and an empty body are still accepted.
        assert_eq!(
            canonical_set_payload(log_id, 1, 2, "a+b/c=="),
            Some("{\"body\":\"a+b/c==\",\"integratedTime\":2,\"logID\":\"c0d23d6ad406973f9559f3ba2d1ca01f\",\"logIndex\":1}".to_string())
        );
        assert_eq!(
            canonical_set_payload(log_id, 1, 2, ""),
            Some("{\"body\":\"\",\"integratedTime\":2,\"logID\":\"c0d23d6ad406973f9559f3ba2d1ca01f\",\"logIndex\":1}".to_string())
        );
    }

    /// A quote-injecting body must be refused before signature verification.
    /// AAAA is three zero bytes, not a genuine DER SET signature; this test
    /// checks validation order only.
    #[test]
    fn rekor_entry_with_quote_injecting_body_is_refused() {
        let mut bad = HashMap::new();
        bad.insert(
            "abc".to_string(),
            serde_json::json!({
                "logIndex": 1,
                "integratedTime": 2,
                "logID": "c0d23d6ad406973f9559f3ba2d1ca01f",
                "body": "aGVsbG8=\",\"integratedTime\":1700000000,\"x",
                "verification": {"signedEntryTimestamp": "AAAA"}
            }),
        );
        let err = parse_rekor_entry("abc", bad)
            .expect_err("a body that splices JSON into the canonical form must be refused");
        assert!(
            matches!(err, RekorError::EntrySetMalformed { .. }),
            "got: {err}"
        );
    }
}

#[cfg(test)]
mod required_signer_tests {
    #[tokio::test]
    async fn no_identity_fails_before_file_or_network_access() {
        for identity in [None, Some(""), Some("   ")] {
            let error = super::SlsaVerifier::default()
                .verify_provenance("/nonexistent/artifact", None::<&str>, identity)
                .await
                .unwrap_err();
            assert!(matches!(error, super::SlsaError::IdentityRequired));
        }
    }
}
