//! Status-publication policy for the daemon.
//!
//! These rules are domain policy, not wire format: a failed vulnerability
//! scan must never qualify a clean zero. Numeric last-known counts require
//! scope invalidation after a failed refresh. These rules live apart from
//! [`super::protocol`] so the wire
//! types stay declarative and the invariants stay tested in one place.

use super::protocol::StatusResult;
use crate::core::security::scan::{AuditCoverage, SecurityAuditResult};

pub(super) fn reported_vulnerability_counts(
    scan: SecurityAuditResult,
) -> anyhow::Result<(usize, usize)> {
    match scan.coverage {
        AuditCoverage::Reported { unassessed, .. } => {
            Ok((scan.total_vulnerabilities, unassessed.len()))
        }
        AuditCoverage::Unreported => {
            Err(anyhow::anyhow!("Security scan omitted advisory coverage"))
        }
    }
}

/// Map a vulnerability scan onto a previously published count.
///
/// A failed scan keeps numeric last-known counts, not their freshness claim.
/// Publication must invalidate the reported scope when retaining these after an error.
pub fn vulnerability_count_from_scan<E>(
    scan: &Result<(usize, usize), E>,
    previous: Option<(usize, usize)>,
) -> Option<(usize, usize)> {
    match scan {
        Ok(count) => Some(*count),
        Err(_) => previous,
    }
}

/// Build a status snapshot. Only a completed vulnerability scan may be cached.
pub fn status_snapshot(
    total_packages: usize,
    explicit_packages: usize,
    orphan_packages: usize,
    updates_available: usize,
    runtime_versions: Vec<(String, String)>,
    scanned_vulnerabilities: Option<(usize, usize)>,
) -> (StatusResult, bool) {
    let security_vulnerabilities = scanned_vulnerabilities.map_or(0, |(count, _)| count);
    let security_unknown_packages = scanned_vulnerabilities.map(|(_, unknown)| unknown);
    (
        StatusResult {
            total_packages,
            explicit_packages,
            orphan_packages,
            updates_available,
            security_vulnerabilities,
            security_unknown_packages,
            vulnerabilities_scanned: scanned_vulnerabilities.is_some(),
            runtime_versions,
        },
        scanned_vulnerabilities.is_some(),
    )
}

#[cfg(test)]
mod tests {
    use super::{reported_vulnerability_counts, status_snapshot, vulnerability_count_from_scan};
    use crate::core::security::scan::{AuditCoverage, SecurityAuditResult};

    #[test]
    fn successful_scan_replaces_the_previous_count() {
        assert_eq!(
            vulnerability_count_from_scan::<()>(&Ok((3, 0)), Some((5, 0))),
            Some((3, 0))
        );
    }

    #[test]
    fn failed_scan_keeps_the_previous_count() {
        assert_eq!(
            vulnerability_count_from_scan(&Err("alsa unavailable"), Some((5, 0))),
            Some((5, 0))
        );
    }

    #[test]
    fn failed_scan_without_a_prior_count_does_not_invent_zero() {
        assert_eq!(
            vulnerability_count_from_scan(&Err("alsa unavailable"), None),
            None
        );
    }

    #[test]
    fn unreported_package_coverage_does_not_replace_the_last_scan() {
        let scan = SecurityAuditResult {
            coverage: AuditCoverage::Unreported,
            total_vulnerabilities: 0,
            high_severity: 0,
            vulnerabilities: Vec::new(),
        };
        let summary = reported_vulnerability_counts(scan);
        assert_eq!(
            summary
                .as_ref()
                .expect_err("unreported scan must refuse")
                .to_string(),
            "Security scan omitted advisory coverage"
        );
        assert_eq!(vulnerability_count_from_scan(&summary, None), None);
        assert_eq!(
            vulnerability_count_from_scan(&summary, Some((5, 2))),
            Some((5, 2))
        );
    }

    #[test]
    fn unscanned_status_is_not_cacheable() {
        let (status, cacheable) = status_snapshot(10, 4, 1, 2, vec![], None);
        assert!(!cacheable);
        assert!(!status.vulnerabilities_scanned);
        assert_eq!(status.scanned_vulnerability_summary(), None);
        assert_eq!(status.security_vulnerabilities, 0);
        assert_eq!(status.total_packages, 10);
    }

    #[test]
    fn scanned_status_is_cacheable() {
        let (status, cacheable) = status_snapshot(10, 4, 1, 2, vec![], Some((7, 0)));
        assert!(cacheable);
        assert!(status.vulnerabilities_scanned);
        assert_eq!(status.scanned_vulnerability_summary(), Some((7, 0)));
        assert_eq!(status.security_vulnerabilities, 7);
    }

    #[test]
    fn completed_scan_preserves_known_findings_and_unknown_package_count() {
        let (status, cacheable) = status_snapshot(10, 4, 1, 2, vec![], Some((7, 4)));
        assert!(cacheable);
        assert!(status.vulnerabilities_scanned);
        assert_eq!(status.security_vulnerabilities, 7);
        assert_eq!(status.security_unknown_packages, Some(4));
    }
}
