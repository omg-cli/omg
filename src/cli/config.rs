//! Configuration management for OMG CLI
//!
//! Handles getting, setting, validating, and displaying configuration.

use anyhow::{Context, Result};
use dialoguer::Confirm;

use crate::cli::style;
use crate::config::Settings;

/// Get a configuration value
pub fn get(key: &str) -> Result<()> {
    // SECURITY: Validate config key
    validate_key(key)?;

    let settings = Settings::load().context("Failed to load OMG settings")?;

    let value = match key {
        "data_dir" => settings.data_dir.display().to_string(),
        "socket" => settings.socket_path.display().to_string(),
        "telemetry.enabled" => settings.telemetry_enabled.to_string(),
        "aur.build_concurrency" => settings.aur.build_concurrency.to_string(),
        "aur.enable_ccache" => settings.aur.enable_ccache.to_string(),
        "aur.enable_sccache" => settings.aur.enable_sccache.to_string(),
        "aur.secure_makepkg" => settings.aur.secure_makepkg.to_string(),
        "aur.security_profile" => settings.aur.security_profile.as_str().to_owned(),
        "aur.makeflags" => settings
            .aur
            .makeflags
            .as_deref()
            .map_or_else(|| "(not set)".to_string(), str::to_string),
        _ => anyhow::bail!("Unknown config key: '{key}'"),
    };

    println!("{value}");
    Ok(())
}

/// Set a configuration value
pub fn set(key: &str, value: &str) -> Result<()> {
    // SECURITY: Validate config key and value
    validate_key(key)?;
    validate_value(value)?;

    let _write_lock = Settings::write_lock()?;
    let mut settings = Settings::load().context("Failed to load OMG settings")?;

    match key {
        "aur.security_profile" => {
            settings.aur.security_profile = value.parse()?;
        }
        "telemetry.enabled" => {
            settings.telemetry_enabled = value.parse().context("Invalid boolean value")?;
        }
        "aur.build_concurrency" => {
            let concurrency: usize = value.parse().context("Invalid number")?;
            // Security: same rule as Settings::load enforces on the file.
            crate::config::validate_build_concurrency(concurrency)?;
            settings.aur.build_concurrency = concurrency;
        }
        "aur.enable_ccache" => {
            settings.aur.enable_ccache = value.parse().context("Invalid boolean value")?;
        }
        "aur.enable_sccache" => {
            settings.aur.enable_sccache = value.parse().context("Invalid boolean value")?;
        }
        "aur.secure_makepkg" => {
            settings.aur.secure_makepkg = value.parse().context("Invalid boolean value")?;
        }
        "aur.makeflags" => {
            settings.aur.makeflags = if value.is_empty() {
                None
            } else {
                // Security: same rule as Settings::load enforces on the file.
                crate::config::validate_makeflags(value)?;
                Some(value.to_string())
            };
        }
        _ => {
            anyhow::bail!(
                "Unknown config key: '{key}'. \
                 Writable keys: telemetry.enabled, aur.build_concurrency, aur.enable_ccache, \
                 aur.enable_sccache, aur.secure_makepkg, aur.security_profile, aur.makeflags"
            );
        }
    }

    settings.save()?;
    println!("{} Set {} = {}", style::success("✓"), key, value);
    Ok(())
}

/// List all configuration values
pub fn list() -> Result<()> {
    let settings = Settings::load().context("Failed to load OMG settings")?;

    println!("{}", style::header("OMG Configuration"));
    println!();

    // Paths (read-only)
    println!("  {}", style::dim("Paths:"));
    println!(
        "    {} = {}",
        style::info("data_dir"),
        settings.data_dir.display()
    );
    println!(
        "    {} = {}",
        style::info("socket"),
        settings.socket_path.display()
    );
    println!(
        "    {} = {}",
        style::info("config_file"),
        Settings::config_path()?.display()
    );

    // General settings
    println!();
    println!("  {}", style::dim("General:"));
    println!(
        "    {} = {}",
        style::info("telemetry.enabled"),
        settings.telemetry_enabled
    );
    // AUR settings
    println!();
    println!("  {}", style::dim("AUR Build:"));
    println!(
        "    {} = {}",
        style::info("aur.security_profile"),
        settings.aur.security_profile.as_str()
    );
    println!(
        "    {} = {}",
        style::info("aur.build_concurrency"),
        settings.aur.build_concurrency
    );
    println!(
        "    {} = {}",
        style::info("aur.enable_ccache"),
        settings.aur.enable_ccache
    );
    println!(
        "    {} = {}",
        style::info("aur.enable_sccache"),
        settings.aur.enable_sccache
    );
    println!(
        "    {} = {}",
        style::info("aur.secure_makepkg"),
        settings.aur.secure_makepkg
    );
    println!(
        "    {} = {}",
        style::info("aur.makeflags"),
        settings.aur.makeflags.as_deref().unwrap_or("(not set)")
    );

    println!();
    Ok(())
}

/// Validate configuration file
pub fn validate() -> Result<()> {
    println!("{} Validating configuration...", style::info("→"));
    println!();

    let config_file = Settings::config_path()?;
    let Some((bytes, metadata)) =
        Settings::read_config(&config_file).context("Configuration validation failed")?
    else {
        println!(
            "  {} No config file found (using defaults)",
            style::dim("•")
        );
        println!("    Path: {}", config_file.display());
        println!();
        println!(
            "{} Configuration is valid (using defaults)",
            style::success("✓")
        );
        return Ok(());
    };

    println!(
        "  {} Found config file: {}",
        style::success("✓"),
        config_file.display()
    );

    let content = std::str::from_utf8(&bytes).context("Config is not UTF-8")?;
    let table = match toml::from_str::<toml::Table>(content) {
        Ok(table) => {
            println!("  {} TOML syntax is valid", style::success("✓"));
            table
        }
        Err(error) => {
            println!("  {} TOML syntax error: {}", style::error("✗"), error);
            return Err(error).context("Configuration validation failed");
        }
    };

    let settings = match Settings::from_config_table(&config_file, table) {
        Ok(settings) => {
            println!("  {} Configuration schema is valid", style::success("✓"));
            settings
        }
        Err(error) => {
            println!(
                "  {} Failed to load configuration: {:#}",
                style::error("✗"),
                error
            );
            return Err(error).context("Configuration validation failed");
        }
    };

    let mut issues = 0;
    if settings.aur.build_concurrency == 0 {
        println!(
            "  {} aur.build_concurrency should be > 0",
            style::warning("⚠")
        );
        issues += 1;
    }
    if settings.aur.build_concurrency > 8 {
        println!(
            "  {} aur.build_concurrency is unusually high ({})",
            style::warning("⚠"),
            settings.aur.build_concurrency
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            let perm_str = format!("{:o}", mode & 0o777);
            println!(
                "  {} Config file has loose permissions ({perm_str})",
                style::warning("⚠")
            );
            println!("    Consider running: chmod 600 {}", config_file.display());
            issues += 1;
        } else {
            println!("  {} File permissions are secure", style::success("✓"));
        }
    }
    #[cfg(not(unix))]
    let _ = metadata;

    println!();
    if issues == 0 {
        println!("{} Configuration is valid!", style::success("✓"));
    } else {
        println!("{} Found {} issue(s)", style::warning("⚠"), issues);
        anyhow::bail!("Configuration validation failed: {issues} issue(s)");
    }

    Ok(())
}

/// Reset configuration to defaults
pub fn reset(yes: bool) -> Result<()> {
    let config_file = Settings::config_path()?;
    match std::fs::symlink_metadata(&config_file) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("{} No config file exists", style::dim("•"));
            return Ok(());
        }
        Err(error) => return Err(error).context("Failed to inspect configuration file"),
    }

    if !yes {
        let confirm = Confirm::new()
            .with_prompt("Reset configuration to defaults? This cannot be undone.")
            .default(false)
            .interact()?;

        if !confirm {
            println!("{} Cancelled", style::dim("•"));
            return Ok(());
        }
    }

    let _write_lock = Settings::write_lock()?;
    let Some((bytes, _)) = Settings::read_config(&config_file)? else {
        println!("{} No config file exists", style::dim("•"));
        return Ok(());
    };
    let backup_path = config_file.with_extension("toml.backup");
    // Replace the backup entry atomically; copying into an existing symlink or
    // hard link would overwrite an unrelated file. Backups remain owner-only.
    crate::core::safe_ops::atomic_write_file_sync_private(&backup_path, bytes)
        .context("Failed to back up configuration")?;
    println!(
        "  {} Created backup at {}",
        style::dim("•"),
        backup_path.display()
    );

    crate::core::safe_ops::atomic_write_file_sync_private(
        &config_file,
        toml::to_string_pretty(&Settings::default())?,
    )
    .context("Failed to reset configuration")?;

    println!("{} Configuration reset to defaults", style::success("✓"));
    Ok(())
}

/// Show configuration file path
pub fn path() -> Result<()> {
    println!("{}", Settings::config_path()?.display());
    Ok(())
}

/// Validate a configuration key
fn validate_key(key: &str) -> Result<()> {
    if key
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && c != '.' && c != '_')
    {
        anyhow::bail!("Invalid configuration key: {key}");
    }
    if key.len() > 64 {
        anyhow::bail!("Configuration key too long");
    }
    Ok(())
}

/// Validate a configuration value
fn validate_value(value: &str) -> Result<()> {
    if value.len() > 1024 {
        anyhow::bail!("Configuration value too long");
    }
    Ok(())
}
