//! Version-change classification used by update and outdated-package output.

use semver::Version;

/// Type of update, used for styling and JSON output.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum UpdateType {
    Major,
    Minor,
    Patch,
    Unknown,
}

impl std::fmt::Display for UpdateType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Major => write!(f, "major"),
            Self::Minor => write!(f, "minor"),
            Self::Patch => write!(f, "patch"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl UpdateType {
    /// Parse version strings and determine update type.
    #[must_use]
    pub fn from_versions(old_ver: &str, new_ver: &str) -> Self {
        let old_str = old_ver.trim_start_matches(|character: char| !character.is_numeric());
        let new_str = new_ver.trim_start_matches(|character: char| !character.is_numeric());

        match (Version::parse(old_str), Version::parse(new_str)) {
            (Ok(old), Ok(new)) => {
                if new <= old {
                    Self::Unknown
                } else if new.major > old.major {
                    Self::Major
                } else if new.minor > old.minor {
                    Self::Minor
                } else {
                    Self::Patch
                }
            }
            _ => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_type_detection() {
        assert_eq!(
            UpdateType::from_versions("1.0.0", "2.0.0"),
            UpdateType::Major
        );
        assert_eq!(
            UpdateType::from_versions("1.0.0", "1.1.0"),
            UpdateType::Minor
        );
        assert_eq!(
            UpdateType::from_versions("1.0.0", "1.0.1"),
            UpdateType::Patch
        );
        for (kind, label) in [
            (UpdateType::Major, "major"),
            (UpdateType::Minor, "minor"),
            (UpdateType::Patch, "patch"),
            (UpdateType::Unknown, "unknown"),
        ] {
            assert_eq!(kind.to_string(), label);
        }
    }

    #[test]
    fn test_update_type_pacman_version() {
        assert_eq!(
            UpdateType::from_versions("1.15.6-1", "1.15.8-1"),
            UpdateType::Patch
        );
        assert_eq!(
            UpdateType::from_versions("1.20.0-1", "1.21.0-1"),
            UpdateType::Minor
        );
    }

    #[test]
    fn non_increasing_versions_are_not_updates() {
        assert_eq!(
            UpdateType::from_versions("2.0.0", "1.9.9"),
            UpdateType::Unknown
        );
        assert_eq!(
            UpdateType::from_versions("1.2.3", "1.2.3"),
            UpdateType::Unknown
        );
    }
}
