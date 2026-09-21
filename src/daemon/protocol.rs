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
pub const PROTOCOL_VERSION: u32 = 2;

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
    SecurityAudit(SecurityAuditResult),
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
    /// False when `security_vulnerabilities` was not produced by a scan.
    pub vulnerabilities_scanned: bool,
    pub runtime_versions: Vec<(String, String)>,
}

impl StatusResult {
    /// Vulnerability count from a completed scan. `None` means not scanned.
    #[must_use]
    pub const fn scanned_vulnerability_count(&self) -> Option<usize> {
        if self.vulnerabilities_scanned {
            Some(self.security_vulnerabilities)
        } else {
            None
        }
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
}
