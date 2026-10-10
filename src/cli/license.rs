//! Optional dashboard account CLI (`omg account`)

use anyhow::Result;
use owo_colors::OwoColorize;
use std::io::{self, Write};

use crate::cli::style;
use crate::core::license::{self, StoredLicense};

/// Prompt for user input
fn prompt(message: &str) -> String {
    print!("{message}");
    let _ = io::stdout().flush();
    let mut input = String::new();
    let _ = io::stdin().read_line(&mut input);
    input.trim().to_string()
}

/// Link this machine to the OMG dashboard.
///
/// # Errors
///
/// Returns an error when the token format is invalid or the link
/// request fails (network, server rejection, or persistence failure).
pub async fn activate(key: &str) -> Result<()> {
    if key.len() > 128 || key.chars().any(|c| !c.is_ascii_alphanumeric() && c != '-') {
        anyhow::bail!("Invalid dashboard token format");
    }

    println!("{} Linking dashboard account...\n", style::runtime("OMG"));

    let (user_name, user_email) = if console::user_attended() {
        println!(
            "  {} Optional identity so the dashboard can name this machine. Press Enter to skip.\n",
            style::maybe_color("📋", |t| t.cyan().to_string())
        );
        (
            prompt("  Your name (optional): "),
            prompt("  Your email (optional): "),
        )
    } else {
        (String::new(), String::new())
    };

    let user_name_opt = if user_name.is_empty() {
        None
    } else {
        Some(user_name.as_str())
    };
    let user_email_opt = if user_email.is_empty() {
        None
    } else {
        Some(user_email.as_str())
    };

    println!("\n  Validating token...");

    report_activation(license::activate_with_user(key, user_name_opt, user_email_opt).await)
}

/// Prints link outcome. Failed validation must be `Err` so the CLI exits non-zero.
fn report_activation(result: Result<license::StoredLicense>) -> Result<()> {
    match result {
        Ok(stored) => {
            println!(
                "\n{} Dashboard account linked.\n",
                style::maybe_color("✓", |t| t.green().to_string())
            );
            if let Some(customer) = &stored.customer {
                println!("  Account: {}", style::sanitize_terminal_text(customer));
            }
            if let Some(expires) = &stored.expires_at {
                println!("  Expires: {}", style::sanitize_terminal_text(expires));
            }
            println!(
                "\n  {}",
                style::dim(
                    "Linking is optional. Local commands work without an account.\n  Opted-in usage is attributed to this dashboard when telemetry is enabled."
                )
            );
            Ok(())
        }
        Err(e) => {
            println!(
                "\n{} Link failed: {}",
                style::maybe_color("✗", |t| t.red().to_string()),
                e
            );
            println!(
                "\n  Get a dashboard token from your OMG dashboard, then run `omg account link --token-stdin`."
            );
            Err(e)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredLicenseStatus {
    Active,
    Invalid,
}

fn stored_license_status(stored: &StoredLicense) -> StoredLicenseStatus {
    if stored.is_token_valid() {
        StoredLicenseStatus::Active
    } else {
        StoredLicenseStatus::Invalid
    }
}

/// Show whether this machine is linked to the dashboard.
pub fn status() -> Result<()> {
    println!("{} Dashboard account\n", style::runtime("OMG"));

    let stored = license::status();

    if let Some(stored) = &stored {
        match stored_license_status(stored) {
            StoredLicenseStatus::Active => {
                println!("  Status: {} ✓", style::version("Linked"));
                if let Some(customer) = &stored.customer {
                    println!("  Account: {}", style::sanitize_terminal_text(customer));
                }
                if let Some(expires) = &stored.expires_at {
                    println!("  Expires: {}", style::sanitize_terminal_text(expires));
                }
            }
            StoredLicenseStatus::Invalid => {
                println!(
                    "  Status: {}",
                    style::maybe_color("Stored token is invalid or expired", |text| text
                        .yellow()
                        .to_string())
                );
                if let Some(expires) = &stored.expires_at {
                    println!(
                        "  Stored expiry: {}",
                        style::sanitize_terminal_text(expires)
                    );
                }
                println!("  Relink: {}", style::dim("omg account link --token-stdin"));
            }
        }
    } else {
        println!(
            "  Status: {}",
            style::maybe_color("Not linked", |t| t.yellow().to_string())
        );
        println!(
            "\n  Linking is optional. Run `omg account link --token-stdin` to attribute opted-in usage to your dashboard."
        );
    }

    Ok(())
}

/// Unlink this machine from the dashboard.
pub fn deactivate() -> Result<()> {
    println!("{} Unlinking dashboard account...", style::runtime("OMG"));

    license::remove_license()?;

    println!(
        "\n{} Dashboard account unlinked.",
        style::maybe_color("✓", |t| t.green().to_string())
    );
    println!("  Local commands are unchanged.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activation_metadata_output_neutralizes_terminal_controls() -> Result<()> {
        const CHILD: &str = "OMG_ACCOUNT_OUTPUT_CONTRACT_CHILD";
        const NAME: &str =
            "cli::license::tests::activation_metadata_output_neutralizes_terminal_controls";
        if std::env::var(CHILD).as_deref() == Ok(NAME) {
            // This exercises the successful presentation path only. It does
            // not simulate signed-token authentication or contact the API.
            for (customer, expires_at) in [
                ("Normal Customer", "2030-01-01"),
                (
                    "\u{1b}]52;c;fixture\u{7}Customer\u{202e}",
                    "\u{1b}[31mexpiry\u{2066}",
                ),
            ] {
                report_activation(Ok(StoredLicense {
                    key: "private-account-fixture-key".into(),
                    tier: "free".into(),
                    features: Vec::new(),
                    customer: Some(customer.into()),
                    expires_at: Some(expires_at.into()),
                    validated_at: 0,
                    token: None,
                    machine_id: None,
                }))?;
            }
            println!("ACCOUNT_OUTPUT_CONTRACT_COMPLETED");
            return Ok(());
        }
        let output = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", NAME, "--nocapture"])
            .env(CHILD, NAME)
            .env("NO_COLOR", "1")
            .output()?;
        let stdout = String::from_utf8(output.stdout)?;
        anyhow::ensure!(
            output.status.success(),
            "presentation child failed: {stdout}"
        );
        anyhow::ensure!(
            stdout.contains("ACCOUNT_OUTPUT_CONTRACT_COMPLETED")
                && stdout.contains("1 passed; 0 failed; 0 ignored"),
            "presentation child did not execute: {stdout}"
        );
        assert!(stdout.contains("Account: Normal Customer"), "{stdout:?}");
        assert!(stdout.contains("Expires: 2030-01-01"), "{stdout:?}");
        assert!(!stdout.contains("private-account-fixture-key"));
        for forbidden in ['\u{1b}', '\u{7}', '\u{202e}', '\u{2066}'] {
            assert!(
                !stdout.contains(forbidden),
                "unsafe account output: {stdout:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn invalid_stored_license_is_not_displayed_as_active() {
        let stored = StoredLicense {
            key: "OMG-invalid".to_string(),
            tier: "enterprise".to_string(),
            features: vec!["policy".to_string()],
            customer: None,
            expires_at: Some("2000-01-01".to_string()),
            validated_at: 0,
            token: Some("not-a-jwt".to_string()),
            machine_id: None,
        };

        assert_eq!(stored_license_status(&stored), StoredLicenseStatus::Invalid);
    }

    #[test]
    fn activation_failure_returns_err() {
        let err = anyhow::anyhow!("Invalid license: revoked");
        let result = report_activation(Err(err));
        assert!(
            result.is_err(),
            "failed activation must be a CLI error so the process exits non-zero"
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid license: revoked"),
            "original activation error must be preserved"
        );
    }
}
