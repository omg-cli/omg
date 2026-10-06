//! Error suggestion helpers for user-facing CLI failures.
//!
//! The former typed `OmgError` contract was deleted (wave-9): production code
//! uniformly uses `anyhow::Error`, so pattern-matching on message text at the
//! single CLI exit boundary is the only consumer of error context.

/// Common error suggestions for anyhow errors
#[cold]
#[must_use]
pub fn suggest_for_anyhow(err: &anyhow::Error) -> Option<&'static str> {
    let msg = format!("{err:#}").to_lowercase();

    if msg.contains("package not found") || msg.contains("no such package") {
        return Some("Try: omg search <query> to find available packages");
    }
    if msg.contains("version not found") || msg.contains("no matching version") {
        return Some("Try: omg list <runtime> --available to see available versions");
    }
    if msg.contains("permission denied") || msg.contains("access denied") {
        return Some("Try running with sudo, or check file/directory permissions");
    }
    if msg.contains("not found") && msg.contains("command") {
        return Some("The required tool is not installed. Try: omg tool install <name>");
    }
    if msg.contains("daemon") {
        return Some("Start the daemon with: omg daemon");
    }
    if msg.contains("rate limit") || msg.contains("too many requests") {
        return Some("Wait for the cooldown period, then retry your request");
    }
    if msg.contains("no such file") || msg.contains("file not found") {
        return Some("Check that the file path is correct and the file exists");
    }
    if msg.contains("lock") && (msg.contains("exists") || msg.contains("conflict")) {
        return Some(
            "A lock file exists. Another process might be running, or remove the lock file manually.",
        );
    }
    if msg.contains("connection") || msg.contains("network") || msg.contains("timeout") {
        return Some("Check your internet connection and try again");
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suggest_for_anyhow_permission() {
        let err = anyhow::anyhow!("permission denied: /etc/foo");
        assert!(suggest_for_anyhow(&err).is_some());
    }

    #[test]
    fn test_suggest_for_anyhow_network() {
        let err = anyhow::anyhow!("connection refused");
        assert!(suggest_for_anyhow(&err).is_some());
    }

    #[test]
    fn test_suggest_for_anyhow_none() {
        let err = anyhow::anyhow!("some random error");
        assert!(suggest_for_anyhow(&err).is_none());
    }

    #[test]
    fn neutral_context_preserves_permission_guidance() {
        let err = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            .context("omg doctor");
        assert_eq!(
            suggest_for_anyhow(&err),
            Some("Try running with sudo, or check file/directory permissions")
        );
    }

    #[test]
    fn generic_network_context_does_not_hide_specific_permission_cause() {
        let err = anyhow::anyhow!("Permission denied: credentials")
            .context("Preparing request")
            .context("Network operation timed out");
        assert_eq!(
            suggest_for_anyhow(&err),
            Some("Try running with sudo, or check file/directory permissions")
        );
    }

    #[test]
    fn neutral_context_preserves_remote_network_guidance() {
        let err = anyhow::anyhow!("Connection refused by remote HTTPS endpoint")
            .context("Installing runtime");
        assert_eq!(
            suggest_for_anyhow(&err),
            Some("Check your internet connection and try again")
        );
    }

    #[test]
    fn daemon_transport_failures_do_not_recommend_internet_recovery() {
        for err in [
            anyhow::anyhow!("Daemon request timeout"),
            anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
                .context("Failed to connect to daemon at /tmp/omgd.sock"),
            anyhow::anyhow!("Timeout receiving response").context("Calling local daemon"),
        ] {
            assert_eq!(
                suggest_for_anyhow(&err),
                Some("Start the daemon with: omg daemon")
            );
        }
    }

    #[test]
    fn specific_causes_take_precedence_over_generic_network_context() {
        let cases = [
            (
                "Too many requests",
                "Wait for the cooldown period, then retry your request",
            ),
            (
                "No such file: config",
                "Check that the file path is correct and the file exists",
            ),
        ];
        for (cause, expected) in cases {
            let err = anyhow::anyhow!(cause).context("Network operation failed");
            assert_eq!(suggest_for_anyhow(&err), Some(expected));
        }
    }

    #[test]
    fn unknown_error_chain_remains_without_suggestion() {
        let err = anyhow::anyhow!("unclassified failure").context("omg operation");
        assert_eq!(suggest_for_anyhow(&err), None);
    }
}
