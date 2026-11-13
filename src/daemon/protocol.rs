//! IPC Protocol Types (Binary)
//!
//! Uses bitcode for maximum performance (fastest Rust serializer).
//! Uses serde integration to avoid recursion limit issues with recursive types.

use serde::{Deserialize, Serialize};

/// Wire-protocol version. Bump on any change to `Request`/`Response` shape.
///
/// Every frame is `[u32 LE version][bitcode payload]`. Peers reject frames
/// whose version differs instead of attempting a decode that could
/// silently mis-map same-shaped variants.
pub const PROTOCOL_VERSION: u32 = 5;

/// Frame layout error for [`encode_frame`] / [`split_frame`].
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame too short to contain the protocol version header")]
    TooShort,
    #[error(
        "unsupported peer protocol version {peer} (this build speaks {ours}); update omg so client and daemon match"
    )]
    VersionMismatch { peer: u32, ours: u32 },
    #[error("failed to encode payload: {0}")]
    Encode(String),
}

/// Serialize `value` into a versioned frame:
/// `[u32 LE PROTOCOL_VERSION][bitcode payload]`.
pub fn encode_frame<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, FrameError> {
    let payload = bitcode::serialize(value).map_err(|e| FrameError::Encode(e.to_string()))?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Split a received frame into its protocol version and payload bytes,
/// rejecting versions this build cannot speak.
pub fn split_frame(frame: &[u8]) -> Result<(u32, &[u8]), FrameError> {
    if frame.len() < 4 {
        return Err(FrameError::TooShort);
    }
    let peer = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]);
    if peer != PROTOCOL_VERSION {
        return Err(FrameError::VersionMismatch {
            peer,
            ours: PROTOCOL_VERSION,
        });
    }
    Ok((peer, &frame[4..]))
}

/// Request ID type
pub type RequestId = u64;

/// Unified Request Enum
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    Search {
        id: RequestId,
        query: String,
        limit: Option<usize>,
    },
    Info {
        id: RequestId,
        package: String,
    },
    Status {
        id: RequestId,
    },
    Explicit {
        id: RequestId,
    },
    ExplicitCount {
        id: RequestId,
    },
    SecurityAudit {
        id: RequestId,
    },
    Ping {
        id: RequestId,
    },
    CacheStats {
        id: RequestId,
    },
    CacheClear {
        id: RequestId,
    },
    /// Rebuild the package index from the synchronized system databases.
    RefreshIndex {
        id: RequestId,
    },
    /// Get system metrics (Prometheus-style)
    Metrics {
        id: RequestId,
    },
    /// Get fuzzy suggestions for a package name
    Suggest {
        id: RequestId,
        query: String,
        limit: Option<usize>,
    },
    /// Search Debian/Ubuntu packages (apt)
    DebianSearch {
        id: RequestId,
        query: String,
        limit: Option<usize>,
    },
    /// Get daemon health status
    Health {
        id: RequestId,
    },
    /// List available package updates (uses hot ALPM worker)
    ListUpdates {
        id: RequestId,
    },
}

impl Request {
    #[must_use]
    pub const fn id(&self) -> RequestId {
        match self {
            Self::Search { id, .. }
            | Self::Info { id, .. }
            | Self::Status { id }
            | Self::Explicit { id }
            | Self::ExplicitCount { id }
            | Self::SecurityAudit { id }
            | Self::Ping { id }
            | Self::CacheStats { id }
            | Self::CacheClear { id }
            | Self::RefreshIndex { id }
            | Self::Metrics { id }
            | Self::Suggest { id, .. }
            | Self::DebianSearch { id, .. }
            | Self::Health { id }
            | Self::ListUpdates { id } => *id,
        }
    }

    /// Daemon queries that must not serve a frozen libalpm or index snapshot.
    #[must_use]
    pub const fn reads_arch_sync_catalog(&self) -> bool {
        matches!(
            self,
            Self::Search { .. }
                | Self::Info { .. }
                | Self::Suggest { .. }
                | Self::Status { .. }
                | Self::Explicit { .. }
                | Self::ExplicitCount { .. }
                | Self::SecurityAudit { .. }
        )
    }

    /// Returns the variant name as a static string for tracing/logging
    #[must_use]
    pub const fn variant_name(&self) -> &'static str {
        match self {
            Self::Search { .. } => "search",
            Self::Info { .. } => "info",
            Self::Status { .. } => "status",
            Self::Explicit { .. } => "explicit",
            Self::ExplicitCount { .. } => "explicit_count",
            Self::SecurityAudit { .. } => "security_audit",
            Self::Ping { .. } => "ping",
            Self::CacheStats { .. } => "cache_stats",
            Self::CacheClear { .. } => "cache_clear",
            Self::RefreshIndex { .. } => "refresh_index",
            Self::Metrics { .. } => "metrics",
            Self::Suggest { .. } => "suggest",
            Self::DebianSearch { .. } => "debian_search",
            Self::Health { .. } => "health",
            Self::ListUpdates { .. } => "list_updates",
        }
    }
}

/// Unified Response Enum
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Success {
        id: RequestId,
        result: ResponseResult,
    },
    Error {
        id: RequestId,
        code: i32,
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseResult {
    Search(SearchResult),
    Info(DetailedPackageInfo),
    Status(StatusResult),
    Explicit(ExplicitResult),
    ExplicitCount(usize),
    SecurityAudit(
        #[serde(
            serialize_with = "serialize_security_audit",
            deserialize_with = "deserialize_security_audit"
        )]
        SecurityAuditResult,
    ),
    Ping(String),
    CacheStats {
        size: usize,
        max_size: usize,
    },
    IndexRefreshed {
        packages: usize,
    },
    Metrics(MetricsSnapshot),
    Suggest(Vec<String>),
    Message(String),
    /// Debian search results (list of package info)
    DebianSearch(Vec<PackageInfo>),
    Health(HealthStatus),
    ListUpdates(Vec<UpdateEntry>),
}

#[derive(Serialize, Deserialize)]
struct BinaryAuditResult<C, F> {
    coverage: C,
    total_vulnerabilities: usize,
    high_severity: usize,
    vulnerabilities: F,
}

#[derive(Serialize, Deserialize)]
enum BinaryAuditCoverage<A, U, S> {
    Unreported,
    Reported {
        assessed: A,
        unassessed: U,
        sources: S,
    },
}

#[derive(Serialize, Deserialize)]
enum BinaryAdvisoryProvenance<T> {
    ArchSnapshot {
        payload_sha256: T,
        fetched_at: jiff::Timestamp,
        checked_at: jiff::Timestamp,
    },
    Osv {
        ecosystem: T,
    },
    NativeDnf,
}

fn serialize_security_audit<S: serde::Serializer>(
    audit: &SecurityAuditResult,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use crate::core::security::scan::{AdvisoryProvenance, AuditCoverage};
    if serializer.is_human_readable() {
        return audit.serialize(serializer);
    }
    let coverage = match &audit.coverage {
        AuditCoverage::Unreported => BinaryAuditCoverage::Unreported,
        AuditCoverage::Reported {
            assessed,
            unassessed,
            sources,
        } => BinaryAuditCoverage::Reported {
            assessed: assessed.as_slice(),
            unassessed: unassessed.as_slice(),
            sources: sources
                .iter()
                .map(|source| match source {
                    AdvisoryProvenance::ArchSnapshot {
                        payload_sha256,
                        fetched_at,
                        checked_at,
                    } => BinaryAdvisoryProvenance::ArchSnapshot {
                        payload_sha256: payload_sha256.as_str(),
                        fetched_at: *fetched_at,
                        checked_at: *checked_at,
                    },
                    AdvisoryProvenance::Osv { ecosystem } => BinaryAdvisoryProvenance::Osv {
                        ecosystem: ecosystem.as_str(),
                    },
                    AdvisoryProvenance::NativeDnf => BinaryAdvisoryProvenance::NativeDnf,
                })
                .collect::<Vec<_>>(),
        },
    };
    BinaryAuditResult {
        coverage,
        total_vulnerabilities: audit.total_vulnerabilities,
        high_severity: audit.high_severity,
        vulnerabilities: audit.vulnerabilities.as_slice(),
    }
    .serialize(serializer)
}

fn deserialize_security_audit<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<SecurityAuditResult, D::Error> {
    use crate::core::security::scan::{
        AdvisoryProvenance, AuditCoverage, InstalledIdentity, UnassessedPackage,
    };
    if deserializer.is_human_readable() {
        return SecurityAuditResult::deserialize(deserializer);
    }
    type Coverage = BinaryAuditCoverage<
        Vec<InstalledIdentity>,
        Vec<UnassessedPackage>,
        Vec<BinaryAdvisoryProvenance<String>>,
    >;
    let audit: BinaryAuditResult<Coverage, Vec<(String, Vec<Vulnerability>)>> =
        Deserialize::deserialize(deserializer)?;
    let coverage = match audit.coverage {
        BinaryAuditCoverage::Unreported => AuditCoverage::Unreported,
        BinaryAuditCoverage::Reported {
            assessed,
            unassessed,
            sources,
        } => AuditCoverage::Reported {
            assessed,
            unassessed,
            sources: sources
                .into_iter()
                .map(|source| match source {
                    BinaryAdvisoryProvenance::ArchSnapshot {
                        payload_sha256,
                        fetched_at,
                        checked_at,
                    } => AdvisoryProvenance::ArchSnapshot {
                        payload_sha256,
                        fetched_at,
                        checked_at,
                    },
                    BinaryAdvisoryProvenance::Osv { ecosystem } => {
                        AdvisoryProvenance::Osv { ecosystem }
                    }
                    BinaryAdvisoryProvenance::NativeDnf => AdvisoryProvenance::NativeDnf,
                })
                .collect(),
        },
    };
    Ok(SecurityAuditResult {
        coverage,
        total_vulnerabilities: audit.total_vulnerabilities,
        high_severity: audit.high_severity,
        vulnerabilities: audit.vulnerabilities,
    })
}

// Error codes
pub mod error_codes {
    /// Malformed payload that could not be deserialized into a [`Request`].
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
    pub const PACKAGE_NOT_FOUND: i32 = -1001;
    pub const RATE_LIMITED: i32 = -1002;
    /// Encoded response exceeded the daemon's response budget and could
    /// not be truncated to fit.
    ///
    /// The budget is `daemon::server::MAX_RESPONSE_SIZE`. This stays a valid
    /// [`Response`] the client decodes normally — used instead of
    /// [`INTERNAL_ERROR`] so a size limit is never misreported as a daemon
    /// bug.
    pub const RESPONSE_TOO_LARGE: i32 = -1003;
}

/// Search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub packages: Vec<PackageInfo>,
    /// Number of matches in the daemon's backing result set. This is capped
    /// at the daemon's maximum search limit (1000), not the true total: a
    /// query with 5000 hits reports `total <= 1000`.
    pub total: usize,
}

/// Explicit packages result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplicitResult {
    pub packages: Vec<String>,
}

/// Status result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResult {
    pub total_packages: usize,
    pub explicit_packages: usize,
    pub orphan_packages: usize,
    pub updates_available: usize,
    pub security_vulnerabilities: usize,
    /// True only while this status carries a reported current scan scope.
    pub vulnerabilities_scanned: bool,
    /// Reported uncovered package count. Legacy peers omit coverage entirely.
    #[serde(default)]
    pub security_unknown_packages: Option<usize>,
    pub runtime_versions: Vec<(String, String)>,
}

impl StatusResult {
    /// Findings from a completed scan with no uncovered packages.
    #[must_use]
    pub const fn scanned_vulnerability_count(&self) -> Option<usize> {
        match self.scanned_vulnerability_summary() {
            Some((count, 0)) => Some(count),
            _ => None,
        }
    }

    /// Findings and uncovered packages from an explicitly reported scan scope.
    #[must_use]
    pub const fn scanned_vulnerability_summary(&self) -> Option<(usize, usize)> {
        if self.vulnerabilities_scanned {
            match self.security_unknown_packages {
                Some(unknown) => Some((self.security_vulnerabilities, unknown)),
                None => None,
            }
        } else {
            None
        }
    }

    pub(crate) fn invalidate_security_scope(&mut self) {
        self.vulnerabilities_scanned = false;
        self.security_unknown_packages = None;
    }
}

/// Closed package-source vocabulary for the daemon wire protocol.
///
/// Adding a variant requires a protocol-version bump so older peers reject the
/// frame before decoding instead of interpreting a new source as an old value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WirePackageSource {
    Official,
    Aur,
    Apt,
}

impl WirePackageSource {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Official => "official",
            Self::Aur => "aur",
            Self::Apt => "apt",
        }
    }
}

impl From<WirePackageSource> for crate::core::PackageSource {
    fn from(source: WirePackageSource) -> Self {
        match source {
            WirePackageSource::Official | WirePackageSource::Apt => Self::Official,
            WirePackageSource::Aur => Self::Aur,
        }
    }
}

impl std::fmt::Display for WirePackageSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.label())
    }
}

/// Package info for IPC (minimal)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub source: WirePackageSource,
}

/// Detailed package info for IPC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedPackageInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub url: String,
    pub size: u64,
    pub download_size: u64,
    pub repo: String,
    pub depends: Vec<String>,
    pub licenses: Vec<String>,
    pub source: WirePackageSource,
}

pub use crate::core::security::scan::{SecurityAuditResult, Vulnerability};

/// System metrics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub requests_total: u64,
    pub requests_failed: u64,
    pub rate_limit_hits: u64,
    pub validation_failures: u64,
    pub active_connections: i64,
    pub security_audit_requests: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub search_requests: u64,
    pub info_requests: u64,
    pub status_requests: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: String,
    pub uptime_seconds: u64,
    /// Resident memory of the daemon process, read from procfs `VmRSS`.
    pub memory_usage_mb: u64,
    pub cache_size: usize,
    pub active_connections: i64,
    /// Times the singleton background status worker has died unexpectedly.
    /// Non-zero means cached status/search data may be stale.
    pub background_worker_failures: u64,
}

/// Update entry for IPC (matches `UpdateInfo` from `package_managers::types`)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateEntry {
    pub name: String,
    pub old_version: String,
    pub new_version: String,
    pub repo: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// Synchronous framing helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Maximum frame size accepted by [`read_frame`] (10 MiB).
///
/// Bounds client-side allocation from a hostile or corrupt peer. This is
/// also the transport ceiling for daemon responses: the daemon's response
/// budget (`daemon::server::MAX_RESPONSE_SIZE`) sits strictly below it, so
/// a frame at the response budget is always deliverable to every reader.
pub const MAX_FRAME_SIZE: usize = 10 * 1024 * 1024;

/// Write a length-delimited frame: big-endian `u32` length prefix + payload.
///
/// # Errors
/// Returns `InvalidInput` if the payload exceeds `u32::MAX`, or propagates
/// the underlying I/O error.
pub fn write_frame<W: std::io::Write>(writer: &mut W, payload: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(payload.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "payload too large for protocol framing",
        )
    })?;
    // Single write: one syscall, no interleaving risk on a shared socket.
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(payload);
    writer.write_all(&buf)
}

/// Read a length-delimited frame written by [`write_frame`].
///
/// # Errors
/// Returns `InvalidData` if the announced length exceeds [`MAX_FRAME_SIZE`],
/// or propagates the underlying I/O error.
pub fn read_frame<R: std::io::Read>(reader: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame length {len} exceeds maximum {MAX_FRAME_SIZE}"),
        ));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_package_source_round_trips_through_the_versioned_wire_format() {
        for source in [
            WirePackageSource::Official,
            WirePackageSource::Aur,
            WirePackageSource::Apt,
        ] {
            let package = PackageInfo {
                name: "package".to_string(),
                version: "1".to_string(),
                description: String::new(),
                source,
            };
            let frame = encode_frame(&package).expect("encode package frame");
            let (_, payload) = split_frame(&frame).expect("accept current protocol frame");
            let decoded: PackageInfo = bitcode::deserialize(payload).expect("decode package frame");
            assert_eq!(decoded.source, source);
        }
    }

    #[test]
    fn search_info_and_suggest_read_the_arch_sync_catalog() {
        assert!(
            Request::Search {
                id: 1,
                query: "pkg".to_string(),
                limit: None,
            }
            .reads_arch_sync_catalog()
        );
        assert!(
            Request::Info {
                id: 1,
                package: "pkg".to_string(),
            }
            .reads_arch_sync_catalog()
        );
        assert!(
            Request::Suggest {
                id: 1,
                query: "pkg".to_string(),
                limit: None,
            }
            .reads_arch_sync_catalog()
        );
        assert!(!Request::ListUpdates { id: 1 }.reads_arch_sync_catalog());
        assert!(Request::Status { id: 1 }.reads_arch_sync_catalog());
        assert!(Request::Explicit { id: 1 }.reads_arch_sync_catalog());
        assert!(Request::ExplicitCount { id: 1 }.reads_arch_sync_catalog());
        assert!(Request::SecurityAudit { id: 1 }.reads_arch_sync_catalog());
        assert!(!Request::Ping { id: 1 }.reads_arch_sync_catalog());
    }

    #[test]
    fn security_advisory_severity_survives_wire_roundtrip() {
        use crate::core::security::scan::AdvisorySeverity;
        let response = Response::Success {
            id: 73,
            result: ResponseResult::SecurityAudit(SecurityAuditResult {
                coverage: crate::core::security::scan::AuditCoverage::Unreported,
                total_vulnerabilities: 1,
                high_severity: 1,
                vulnerabilities: vec![(
                    "package".into(),
                    vec![Vulnerability {
                        applicability:
                            crate::core::security::scan::FindingApplicability::Applicable,
                        affected_installed: vec![crate::core::security::scan::InstalledIdentity {
                            name: "package".into(),
                            version: "0:1-1".into(),
                            architecture: Some("x86_64".into()),
                        }],
                        id: "FEDORA-fixture".into(),
                        summary: "Published severity without CVSS".into(),
                        score: None,
                        advisory_severity: Some(AdvisorySeverity::Important),
                        native_advisory: Some(crate::core::security::scan::NativeAdvisory {
                            source: "dnf5".into(),
                            advisory_nevra: "package-1-2.x86_64".into(),
                            published_severity: "Important".into(),
                            description: "Published finding".into(),
                            references: vec![crate::core::security::scan::AdvisoryReference {
                                id: "CVE-fixture".into(),
                                kind: "cve".into(),
                                url: "https://example.test/advisory".into(),
                            }],
                        }),
                    }],
                )],
            }),
        };
        let frame = encode_frame(&response).unwrap();
        let (_, payload) = split_frame(&frame).unwrap();
        let decoded: Response = bitcode::deserialize(payload).unwrap();
        assert_eq!(
            serde_json::to_value(decoded).unwrap(),
            serde_json::to_value(response).unwrap()
        );

        let mut old_frame = frame;
        old_frame[..4].copy_from_slice(&3u32.to_le_bytes());
        assert!(matches!(
            split_frame(&old_frame),
            Err(FrameError::VersionMismatch {
                peer: 3,
                ours: PROTOCOL_VERSION
            })
        ));
    }

    #[test]
    fn previous_string_source_protocol_version_is_rejected_before_decode() {
        let mut old_frame = 1u32.to_le_bytes().to_vec();
        old_frame.extend_from_slice(b"old string-source payload");

        assert!(matches!(
            split_frame(&old_frame),
            Err(FrameError::VersionMismatch {
                peer: 1,
                ours: PROTOCOL_VERSION,
            })
        ));
    }
    #[test]
    fn coverage17_legacy_status_and_failed_refresh_cannot_claim_clean() {
        let mut status: StatusResult = serde_json::from_value(serde_json::json!({
            "total_packages": 3, "explicit_packages": 1, "orphan_packages": 0,
            "updates_available": 0, "security_vulnerabilities": 0,
            "vulnerabilities_scanned": true, "runtime_versions": []
        }))
        .expect("legacy status remains decodable");
        assert_eq!(status.scanned_vulnerability_count(), None);
        status.security_unknown_packages = Some(2);
        assert_eq!(status.scanned_vulnerability_count(), None);
        assert_eq!(status.scanned_vulnerability_summary(), Some((0, 2)));
        status.security_unknown_packages = Some(0);
        assert_eq!(status.scanned_vulnerability_count(), Some(0));
        status.invalidate_security_scope();
        assert_eq!(status.scanned_vulnerability_count(), None);
        assert_eq!(status.security_unknown_packages, None);
        assert_eq!(
            status.security_vulnerabilities, 0,
            "numeric last-known value is not fresh coverage"
        );
    }

    #[test]
    fn coverage17_previous_wire_version_is_rejected_before_bitcode_decode() {
        let response = Response::Success {
            id: 17,
            result: ResponseResult::Status(StatusResult {
                total_packages: 7,
                explicit_packages: 3,
                orphan_packages: 0,
                updates_available: 0,
                security_vulnerabilities: 2,
                vulnerabilities_scanned: true,
                security_unknown_packages: Some(7),
                runtime_versions: Vec::new(),
            }),
        };
        let frame = encode_frame(&response).expect("encode current security status");
        let (_, payload) = split_frame(&frame).expect("matching client and daemon protocol");
        let decoded: Response = bitcode::deserialize(payload).expect("current payload decodes");
        let Response::Success {
            result: ResponseResult::Status(status),
            ..
        } = decoded
        else {
            panic!("security status response changed kind");
        };
        assert_eq!(status.scanned_vulnerability_summary(), Some((2, 7)));

        let mut previous = frame;
        previous[..4].copy_from_slice(&4u32.to_le_bytes());
        assert!(
            matches!(
                split_frame(&previous),
                Err(FrameError::VersionMismatch {
                    peer: 4,
                    ours: PROTOCOL_VERSION
                })
            ),
            "previous security semantics cannot decode as current coverage"
        );

        previous.truncate(4);
        previous.extend_from_slice(b"not a bitcode response");
        assert!(
            matches!(
                split_frame(&previous),
                Err(FrameError::VersionMismatch {
                    peer: 4,
                    ours: PROTOCOL_VERSION
                })
            ),
            "the version boundary must reject before attempting payload decoding"
        );
    }

    #[test]
    fn coverage17_binary_audit_roundtrip_preserves_all_sources_unknown_and_possible() {
        use crate::core::security::scan::{
            AdvisoryProvenance, AuditCoverage, FindingApplicability, InstalledIdentity,
            UnassessedPackage,
        };
        let identity = |name: &str| InstalledIdentity {
            name: name.into(),
            version: "1:2.0-3".into(),
            architecture: Some("x86_64".into()),
        };
        let now: jiff::Timestamp = "2026-11-13T12:00:00Z".parse().expect("fixture timestamp");
        let audit = SecurityAuditResult {
            coverage: AuditCoverage::Reported {
                assessed: vec![identity("distribution")],
                unassessed: vec![UnassessedPackage {
                    package: identity("unknown"),
                    reason:
                        crate::core::security::vulnerability::UnknownCoverage::OriginUnestablished,
                }],
                sources: vec![
                    AdvisoryProvenance::ArchSnapshot {
                        payload_sha256: "ab".repeat(32),
                        fetched_at: now,
                        checked_at: now,
                    },
                    AdvisoryProvenance::Osv {
                        ecosystem: "Debian:12".into(),
                    },
                    AdvisoryProvenance::NativeDnf,
                ],
            },
            total_vulnerabilities: 1,
            high_severity: 1,
            vulnerabilities: vec![(
                "unknown".into(),
                vec![Vulnerability {
                    applicability: FindingApplicability::Possible,
                    id: "possible-advisory".into(),
                    summary: "source review required".into(),
                    score: Some("8.1".into()),
                    advisory_severity: None,
                    native_advisory: None,
                    affected_installed: vec![identity("unknown")],
                }],
            )],
        };
        let json = serde_json::to_value(&audit).expect("public JSON audit");
        assert_eq!(json["coverage"]["status"], "reported");
        assert_eq!(json["coverage"]["sources"][0]["kind"], "arch_snapshot");
        assert_eq!(json["coverage"]["sources"][1]["kind"], "osv");
        assert_eq!(json["coverage"]["sources"][2]["kind"], "native_dnf");
        assert_eq!(
            json["vulnerabilities"][0][1][0]["applicability"],
            "possible"
        );
        let response = Response::Success {
            id: 1701,
            result: ResponseResult::SecurityAudit(audit),
        };
        let frame = encode_frame(&response).expect("binary security audit frame");
        let (_, payload) = split_frame(&frame).expect("current protocol frame");
        let decoded: Response =
            bitcode::deserialize(payload).expect("typed binary coverage and provenance decode");
        let expected = serde_json::to_value(&response).expect("expected public response");
        assert_eq!(
            serde_json::to_value(&decoded).expect("decoded public response"),
            expected
        );
        let json_decoded: Response = serde_json::from_value(expected.clone())
            .expect("public JSON response remains decodable");
        assert_eq!(
            serde_json::to_value(json_decoded).expect("JSON roundtrip"),
            expected
        );
    }
}
