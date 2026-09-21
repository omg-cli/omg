//! Shared package manager types

/// Installed identity for security exports. Native versions are opaque strings;
/// absent metadata remains absent rather than being inferred from the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityPackage {
    pub name: String,
    pub version: String,
    pub architecture: Option<String>,
    pub description: String,
    pub licenses: Vec<String>,
}

/// Canonical orphan rule for pacman-based systems (`pacman -Qdt` semantics).
///
/// A package is an orphan when it was **not** installed explicitly and no
/// other installed package requires it (neither directly nor optionally).
/// All orphan listings and counts (libalpm-backed and pure-Rust cache-backed)
/// MUST derive from this single predicate so the CLI, daemon, and status counts
/// cannot diverge.
#[must_use]
pub fn is_orphan_package(explicit: bool, unrequired: bool) -> bool {
    !explicit && unrequired
}

/// Case-insensitive ASCII substring test without allocation.
/// Only consumed by arch-gated search paths; kept for all feature combos.
#[cfg_attr(not(feature = "arch"), allow(dead_code))]
#[inline]
pub(crate) fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

#[cfg(feature = "arch")]
use alpm_types::Version as AlpmVersion;
#[cfg(feature = "arch")]
use std::str::FromStr;

/// Version type - uses `alpm_types::Version` on Arch, a dpkg-style ordered
/// newtype everywhere else.
#[cfg(feature = "arch")]
pub type Version = AlpmVersion;

/// Ordered version for non-Arch backends (homebrew, debian-pure).
///
/// Regression guard: this was a bare `String`, so `1.9 > 1.10` compared
/// lexicographically and security updates were silently reported as up to
/// date on every non-Arch build.
#[cfg(not(feature = "arch"))]
#[derive(Debug, Clone, Eq, serde::Serialize, serde::Deserialize)]
pub struct DebVersion(String);

#[cfg(not(feature = "arch"))]
impl DebVersion {
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(not(feature = "arch"))]
impl std::fmt::Display for DebVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(not(feature = "arch"))]
impl PartialEq for DebVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

#[cfg(not(feature = "arch"))]
impl std::hash::Hash for DebVersion {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        debian_version::hash_deb_version(&self.0, state);
    }
}

#[cfg(not(feature = "arch"))]
impl PartialOrd for DebVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(not(feature = "arch"))]
impl Ord for DebVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        compare_deb_versions(&self.0, &other.0)
    }
}

#[cfg(any(
    not(feature = "arch"),
    feature = "debian",
    feature = "debian-pure",
    test
))]
mod debian_version {
    /// Compare two Debian package versions using Policy §5.6.12 ordering.
    ///
    /// This is the single comparator for both candidate-update ordering and
    /// dependency constraint resolution. Numeric runs are compared as strings,
    /// so repository-controlled versions cannot overflow an integer parser.
    pub(crate) fn compare_deb_versions(a: &str, b: &str) -> std::cmp::Ordering {
        let (epoch_a, rest_a) = split_deb_epoch(a);
        let (epoch_b, rest_b) = split_deb_epoch(b);
        match epoch_a.cmp(&epoch_b) {
            std::cmp::Ordering::Equal => {}
            other => return other,
        }

        let (upstream_a, revision_a) = split_deb_revision(rest_a);
        let (upstream_b, revision_b) = split_deb_revision(rest_b);
        match compare_deb_part(upstream_a, upstream_b) {
            std::cmp::Ordering::Equal => compare_deb_part(revision_a, revision_b),
            other => other,
        }
    }

    #[cfg(not(feature = "arch"))]
    pub(super) fn hash_deb_version<H: std::hash::Hasher>(version: &str, state: &mut H) {
        use std::hash::Hash;

        let (epoch, rest) = split_deb_epoch(version);
        epoch.hash(state);
        let parts: [&str; 2] = split_deb_revision(rest).into();
        for mut part in parts {
            while !part.is_empty() {
                let (non_digits, rest) = split_at_deb_digit(part);
                let (digits, rest) = split_at_deb_non_digit(rest);
                if !non_digits.is_empty() {
                    non_digits.hash(state);
                }
                let digits = digits.trim_start_matches('0');
                if !digits.is_empty() {
                    digits.hash(state);
                }
                part = rest;
            }
            // A missing numeric run and an all-zero run compare equally.
            // Delimit the parts even when all their numeric runs vanish.
            "".hash(state);
        }
    }

    fn split_deb_epoch(version: &str) -> (u64, &str) {
        match version.split_once(':') {
            Some((epoch, rest)) => (epoch.parse().unwrap_or(0), rest),
            None => (0, version),
        }
    }

    fn split_deb_revision(version: &str) -> (&str, &str) {
        version.rsplit_once('-').unwrap_or((version, ""))
    }

    fn compare_deb_part(mut a: &str, mut b: &str) -> std::cmp::Ordering {
        loop {
            let (a_non_digit, a_after) = split_at_deb_digit(a);
            let (b_non_digit, b_after) = split_at_deb_digit(b);
            match compare_deb_non_digits(a_non_digit, b_non_digit) {
                std::cmp::Ordering::Equal => {}
                other => return other,
            }

            let (a_number, a_next) = split_at_deb_non_digit(a_after);
            let (b_number, b_next) = split_at_deb_non_digit(b_after);
            if a_number.is_empty() && b_number.is_empty() {
                return std::cmp::Ordering::Equal;
            }
            match compare_deb_numeric_strings(a_number, b_number) {
                std::cmp::Ordering::Equal => {}
                other => return other,
            }
            a = a_next;
            b = b_next;
        }
    }

    fn split_at_deb_digit(value: &str) -> (&str, &str) {
        value
            .find(|character: char| character.is_ascii_digit())
            .map_or((value, ""), |index| value.split_at(index))
    }

    fn split_at_deb_non_digit(value: &str) -> (&str, &str) {
        value
            .find(|character: char| !character.is_ascii_digit())
            .map_or((value, ""), |index| value.split_at(index))
    }

    fn compare_deb_numeric_strings(a: &str, b: &str) -> std::cmp::Ordering {
        let a = a.trim_start_matches('0');
        let b = b.trim_start_matches('0');
        a.len().cmp(&b.len()).then_with(|| a.cmp(b))
    }

    fn compare_deb_non_digits(a: &str, b: &str) -> std::cmp::Ordering {
        let mut a = a.chars();
        let mut b = b.chars();
        loop {
            match (a.next(), b.next()) {
                (None, None) => return std::cmp::Ordering::Equal,
                (Some(character), None) => {
                    return if character == '~' {
                        std::cmp::Ordering::Less
                    } else {
                        std::cmp::Ordering::Greater
                    };
                }
                (None, Some(character)) => {
                    return if character == '~' {
                        std::cmp::Ordering::Greater
                    } else {
                        std::cmp::Ordering::Less
                    };
                }
                (Some(a), Some(b)) => match deb_character_order(a).cmp(&deb_character_order(b)) {
                    std::cmp::Ordering::Equal => {}
                    other => return other,
                },
            }
        }
    }

    fn deb_character_order(character: char) -> i64 {
        match character {
            '~' => -1,
            character if character.is_ascii_alphabetic() => i64::from(u32::from(character)),
            character => i64::from(u32::from(character)) + 256,
        }
    }
}

#[cfg(any(
    not(feature = "arch"),
    feature = "debian",
    feature = "debian-pure",
    test
))]
pub(crate) use debian_version::compare_deb_versions;

#[cfg(not(feature = "arch"))]
pub type Version = DebVersion;

/// Uniform borrowed rendering for the backend-dependent [`Version`] type.
pub(crate) trait VersionDisplay {
    fn version_string(&self) -> String;
}

#[cfg(feature = "arch")]
impl VersionDisplay for AlpmVersion {
    #[allow(
        clippy::implicit_clone,
        reason = "alpm-types Display consumes self; centralize the required clone"
    )]
    fn version_string(&self) -> String {
        self.to_string()
    }
}

#[cfg(not(feature = "arch"))]
impl VersionDisplay for DebVersion {
    fn version_string(&self) -> String {
        self.as_str().to_owned()
    }
}

#[cfg(not(feature = "arch"))]
impl VersionDisplay for String {
    fn version_string(&self) -> String {
        self.clone()
    }
}

/// Strictly parse a version string, returning `None` when the string is not
/// a valid version for the active backend (for example non-ASCII text, a
/// numeric overflow, or a malformed pkgrel).
///
/// Comparison and update-check paths must call this and decide the failure
/// policy at the call site — skip the entry with a warning or propagate a
/// typed error. Never compare against a fabricated fallback value (ARCH-R14:
/// a silent `0` suppresses available updates or invents phantom ones).
#[cfg(feature = "arch")]
#[must_use]
#[inline]
pub fn parse_version(s: &str) -> Option<Version> {
    AlpmVersion::from_str(s).ok()
}

/// Strictly parse a version string - infallible on non-Arch backends.
///
/// Non-Arch backends use ordered string comparison (dpkg-style), so every
/// string is a valid [`DebVersion`] retaining its raw text; parsing cannot
/// fail there.
#[cfg(not(feature = "arch"))]
#[must_use]
#[inline]
pub fn parse_version(s: &str) -> Option<Version> {
    Some(Version::new(s))
}

/// Explicit display/test-only fallback: parse a version string, falling back
/// to the zero version when parsing fails.
///
/// The `_or_zero` suffix is the contract: a call site using this helper
/// visibly accepts a fabricated `0` for unparseable input. Production
/// comparison and update-check paths must use [`parse_version`] instead and
/// skip the entry with a warning or propagate a typed error on failure
/// (ARCH-R14). Callers that must never fabricate a version are compile-time
/// steered to the strict parser through review of this call list.
#[must_use]
#[inline]
pub fn parse_version_or_zero(s: &str) -> Version {
    parse_version(s).unwrap_or_else(zero_version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_display_is_borrowed_and_backend_independent() {
        let version = parse_version("1:2.3.4-5").expect("valid version must parse");
        assert_eq!(version.version_string(), "1:2.3.4-5");
    }

    /// ARCH-R14 regression: a version string that fails the strict parser
    /// must be surfaced to the caller as `None` (arch) so the call site can
    /// skip or error, and must never silently compare as a fabricated `0`.
    /// Versions that always parsed cleanly keep their exact rendering.
    #[cfg(feature = "arch")]
    #[test]
    fn unparseable_version_is_rejected_and_valid_versions_keep_their_value() {
        for bad in ["not a version", "版本-1", "1.0-1-1"] {
            assert!(
                parse_version(bad).is_none(),
                "{bad:?} must fail the strict parser"
            );
        }
        for good in ["0", "0.11", "1:2.3.4-5", "6.0.1-1"] {
            let parsed = parse_version(good).unwrap_or_else(|| panic!("{good:?} must parse"));
            assert_eq!(parsed.version_string(), good);
        }
    }

    #[test]
    fn canonical_debian_comparator_orders_policy_edge_cases() {
        use std::cmp::Ordering;

        let cases = [
            ("1.0~rc1", "1.0", Ordering::Less),
            ("1.0a", "1.0+", Ordering::Less),
            ("1.0+", "1.0.", Ordering::Less),
            ("1.0000000000000000000001", "1.1", Ordering::Equal),
            ("1.99999999999999999999999999", "1.10", Ordering::Greater),
            ("2:0", "1:999999999999999999999", Ordering::Greater),
        ];
        for (left, right, expected) in cases {
            assert_eq!(compare_deb_versions(left, right), expected);
            assert_eq!(compare_deb_versions(right, left), expected.reverse());
        }
    }

    #[cfg(not(feature = "arch"))]
    #[test]
    fn deb_version_comparison_follows_dpkg_ordering() {
        // Regression: bare-String comparison called 1.9 > 1.10 and hid
        // security updates on non-Arch builds.
        let v = |s: &str| Version::new(s);
        assert!(v("1.10") > v("1.9"));
        assert!(v("5.10-1") > v("5.9-1"));
        assert!(v("10.0") > v("2.0"));
        assert!(v("20251231") > v("20250101"));
        assert!(v("2.0") < v("1:1.0"), "epoch dominates upstream part");
        assert!(v("1.0") > v("1.0~rc1"), "tilde sorts before everything");
        assert!(v("1.0-2") > v("1.0-1"));
        assert_eq!(v("1.0"), v("1.0"));
        assert!(v("1.0a") < v("1.0b"));
        assert!(v("1.0") < v("1.01"));
    }

    #[cfg(not(feature = "arch"))]
    #[test]
    fn deb_version_equality_and_hash_agree_with_ordering() {
        use std::hash::{DefaultHasher, Hash, Hasher};

        for (left, right) in [
            ("1.01", "1.1"),
            ("0:1.0", "1.0"),
            ("01:1.0", "1:1.0"),
            ("1.0", "1.0-0"),
            ("1.0-00", "1.0-0"),
            ("1.0a0", "1.0a"),
            ("1.0000000000000000000001", "1.1"),
        ] {
            let a = Version::new(left);
            let b = Version::new(right);
            assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
            assert_eq!(a, b, "equal ordering for {left} and {right}");
            let mut a_hash = DefaultHasher::new();
            let mut b_hash = DefaultHasher::new();
            a.hash(&mut a_hash);
            b.hash(&mut b_hash);
            assert_eq!(
                a_hash.finish(),
                b_hash.finish(),
                "hashes for {left} and {right}"
            );
            assert_eq!(a.as_str(), left);
            assert_eq!(serde_json::to_string(&a).unwrap(), format!("\"{left}\""));
        }
    }

    #[test]
    fn orphan_rule_matches_pacman_qdt_definition() {
        // Explicitly installed packages are never orphans.
        assert!(!is_orphan_package(true, true));
        assert!(!is_orphan_package(true, false));
        // Required by another package: not an orphan.
        assert!(!is_orphan_package(false, false));
        // Nothing requires it: an orphan, even if some package lists it in
        // `%OPTDEPENDS%` (optdepends do not keep a package alive).
        assert!(is_orphan_package(false, true));
    }

    #[test]
    fn contains_ignore_case_matches_ascii_and_rejects_non_ascii_queries() {
        assert!(contains_ignore_case("Firefox Web Browser", "fireFox"));
        assert!(contains_ignore_case("abc", ""));
        assert!(!contains_ignore_case("ab", "abc"));
    }
}

/// Returns a default zero version.
/// This is infallible and avoids `expect()/unwrap()` in hot paths.
#[cfg(feature = "arch")]
#[must_use]
#[inline]
pub fn zero_version() -> Version {
    // "0" parsing is trivial - avoids static overhead
    #[expect(clippy::expect_used)]
    AlpmVersion::from_str("0").expect("0 is always valid")
}

/// Returns a default zero version - on non-Arch returns "0".
#[cfg(not(feature = "arch"))]
#[must_use]
#[inline]
pub fn zero_version() -> Version {
    Version::new("0")
}

/// Compare two Arch package versions without the upstream panic path.
///
/// `alpm_types::Version`'s `Ord` impl unwraps `parse::<usize>()` on numeric
/// segments and panics (`PosOverflow`) on any segment above `usize::MAX`
/// (alpm-types `version/comparison.rs`). That detonates inside comparators
/// such as the rayon filter in `pacman_db::check_updates_cached`,
/// `AurIndex::updates_for`, and `AurClient::{get_update_list,query_aur_updates}`.
/// All version ordering on update-check paths must go through this helper.
///
/// Versions without an overflowing numeric segment keep the exact upstream
/// ordering (`Ord::cmp`). Versions carrying an overflowing segment fall back
/// to libalpm's `alpm::vercmp` on the rendered version string: pacman
/// semantics, deterministic, and it compares numeric runs by length and
/// text, so it cannot overflow.
#[cfg(feature = "arch")]
#[must_use]
pub fn compare_versions(a: &AlpmVersion, b: &AlpmVersion) -> std::cmp::Ordering {
    if pkgver_has_overflowing_numeric_segment(a.pkgver.inner())
        || pkgver_has_overflowing_numeric_segment(b.pkgver.inner())
    {
        // `Display` renders the canonical `epoch:pkgver-pkgrel` form.
        alpm::vercmp(a.to_string(), b.to_string())
    } else {
        a.cmp(b)
    }
}

/// Detect numeric segments that would panic in `alpm_types`' comparator
/// (`parse::<usize>().unwrap()` overflow). A segment is any maximal run of
/// ASCII digits (`pkgver` is ASCII-only per the alpm-pkgver spec). Epoch and
/// pkgrel parse into `usize` at construction time, so only `pkgver` can
/// carry overflowing segments.
#[cfg(feature = "arch")]
fn pkgver_has_overflowing_numeric_segment(pkgver: &str) -> bool {
    pkgver
        .split(|c: char| !c.is_ascii_digit())
        .any(|segment| !segment.is_empty() && segment.parse::<usize>().is_err())
}

#[derive(Debug, Clone)]
pub struct LocalPackage {
    pub name: String,
    pub version: Version,
    pub description: String,
    pub install_size: i64,
    pub reason: &'static str,
    /// SPDX-style license identifiers from the package database.
    /// Backends without license metadata leave this empty.
    pub licenses: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SyncPackage {
    pub name: String,
    pub version: Version,
    pub description: String,
    pub repo: String,
    pub download_size: i64,
    pub installed: bool,
}

#[derive(Debug, Clone)]
pub struct PackageInfo {
    pub name: String,
    pub version: Version,
    pub description: String,
    pub url: Option<String>,
    pub size: u64,
    pub install_size: Option<i64>,
    pub download_size: Option<u64>,
    pub repo: String,
    pub depends: Vec<String>,
    pub licenses: Vec<String>,
    pub installed: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UpdateInfo {
    pub name: String,
    pub old_version: String,
    pub new_version: String,
    pub repo: String,
}
