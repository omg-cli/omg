//! Native binding upgrade regression: Debian ordering and Rust slice bounds.
#![cfg(all(target_os = "linux", feature = "debian"))]

#[test]
fn native_version_comparison_matches_dpkg_for_bounded_slices() {
    use std::cmp::Ordering;

    let cases = [
        ("1:1.0-1", "2.0-1", Ordering::Greater),
        ("1.0~rc1-1", "1.0-1", Ordering::Less),
        ("1.0-2", "1.0-10", Ordering::Less),
        ("1.0", "1.0-0", Ordering::Equal),
        ("1.0+really0.9-1", "1.0-1", Ordering::Greater),
    ];
    for (left, right, expected) in cases {
        let operator = match expected {
            Ordering::Less => "lt",
            Ordering::Equal => "eq",
            Ordering::Greater => "gt",
        };
        let oracle = std::process::Command::new("dpkg")
            .args(["--compare-versions", left, operator, right])
            .status()
            .expect("dpkg oracle must be installed on native APT test hosts");
        assert!(
            oracle.success(),
            "invalid ordering fixture: {left} {operator} {right}"
        );

        // Deliberately retain non-NUL trailing bytes behind each slice. FFI
        // must honor Rust's lengths rather than compare the backing strings.
        let left_backing = format!("{left}999999");
        let right_backing = format!("{right}000001");
        let bounded_left = &left_backing[..left.len()];
        let bounded_right = &right_backing[..right.len()];
        assert_eq!(
            rust_apt::util::cmp_versions(bounded_left, bounded_right),
            expected
        );
        assert_eq!(
            rust_apt::util::cmp_versions(bounded_right, bounded_left),
            expected.reverse()
        );
        assert_eq!(
            rust_apt::util::cmp_versions(bounded_left, left),
            Ordering::Equal
        );
    }
}
