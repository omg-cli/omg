//! Privileged package-operation state.
//!
//! OMG never authorizes package database writes through executable file
//! capabilities. Mutations run either as root or through the explicit sudo
//! delegation paths in [`crate::core::privilege`].

/// Check if this process is the root child created by OMG's sudo delegation.
///
/// The marker alone is not authority: effective root identity is mandatory.
#[inline]
#[must_use]
pub fn is_elevated() -> bool {
    std::env::var_os("OMG_ELEVATED").is_some() && crate::core::privilege::is_root()
}

/// Check whether this process may write the package database directly.
///
/// Direct mutation is root-only. Non-root callers must use the explicit sudo
/// delegation path rather than inheritable executable capabilities.
pub fn can_write_pacman_db() -> bool {
    crate::core::privilege::is_root()
}

/// Show a one-time hint about prompt-light sudo credential caching.
///
/// Returns `true` when the hint was shown.
#[cfg(target_os = "linux")]
pub fn maybe_show_turbo_hint() -> bool {
    if is_elevated() || crate::core::privilege::is_root() {
        return false;
    }

    let hint_file = crate::core::paths::data_dir().join(".turbo_hint_shown");
    #[cfg(unix)]
    match crate::core::safe_ops::create_private_marker(&hint_file, b"1") {
        Ok(true) => {}
        Ok(false) | Err(_) => return false,
    }

    eprintln!();
    eprintln!(
        "  {} {}",
        crate::cli::style::runtime("TIP:"),
        crate::cli::style::dim("Prime sudo credentials for prompt-light package operations:")
    );
    eprintln!(
        "       {}",
        crate::cli::style::runtime("omg doctor --turbo")
    );
    eprintln!(
        "       {}",
        crate::cli::style::dim("(uses sudo credential caching; grants no permanent privileges)")
    );
    eprintln!();

    true
}

#[cfg(not(target_os = "linux"))]
pub fn maybe_show_turbo_hint() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_elevated_with_env() {
        temp_env::with_var("OMG_ELEVATED", Some("1"), || {
            assert_eq!(
                is_elevated(),
                crate::core::privilege::is_root(),
                "OMG_ELEVATED without root must not count as elevated"
            );
        });
    }

    #[test]
    fn test_is_elevated_without_env_explicit() {
        temp_env::with_var_unset("OMG_ELEVATED", || {
            assert!(!is_elevated());
        });
    }

    #[test]
    fn direct_package_database_access_is_root_only() {
        assert_eq!(can_write_pacman_db(), crate::core::privilege::is_root());
    }
}
