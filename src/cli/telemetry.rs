use std::io::{BufWriter, Write as _};
use std::path::Path;

use anyhow::{Context, Result};
use owo_colors::OwoColorize;

use crate::cli::style;
use crate::config::Settings;
use crate::core::safe_ops;
use crate::core::telemetry::{
    is_telemetry_opt_out, set_telemetry_preference, telemetry_disabled_by_environment,
};

const MAX_PRIVACY_EXPORT_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PRIVACY_EXPORT_SOURCE_BYTES: u64 = 128 * 1024 * 1024;

// =============================================================================
// Privacy Rights (GDPR/CCPA - Available Globally)
// =============================================================================

/// Show local privacy settings and direct account-level requests to the authenticated website.
pub fn privacy_status() -> Result<()> {
    let settings = Settings::load().context("Failed to load OMG settings")?;
    println!(
        "{}",
        style::maybe_color("OMG Privacy Settings", |t| t.bold().underline().to_string())
    );
    println!();
    println!(
        "  Telemetry: {}",
        if settings.telemetry_enabled && !is_telemetry_opt_out() {
            style::maybe_color("Enabled", |t| t.green().to_string())
        } else {
            style::maybe_color("Disabled", |t| t.red().to_string())
        }
    );
    println!();
    println!("  omg privacy export   Export local OMG data");
    println!("  omg privacy opt-out  Disable telemetry collection");
    println!("  omg privacy opt-in   Re-enable telemetry");
    println!();
    println!("  Account export and deletion require an authenticated session:");
    println!("  https://getomg.xyz/privacy/");
    Ok(())
}

/// Export all user data (Right to Portability)
pub fn export_data(output_path: Option<&str>) -> Result<()> {
    println!(
        "  {} Collecting local data...",
        style::maybe_color("⏳", |_| "⏳".to_string())
    );

    let data = serde_json::json!({
        "exported_at": jiff::Timestamp::now().to_string(),
        "scope": "local",
        "local": collect_local_privacy_data()?,
    });
    let path = output_path.map_or_else(
        || {
            let date = jiff::Zoned::now().date().to_string();
            format!("omg-data-export-{date}.json")
        },
        String::from,
    );
    write_private_export(Path::new(&path), &data)?;

    println!(
        "  {} Data exported to: {}",
        style::maybe_color("✓", |t| t.green().to_string()),
        style::path(&style::sanitize_terminal_text(&path))
    );
    Ok(())
}

fn collect_local_privacy_data() -> Result<serde_json::Value> {
    collect_local_privacy_data_from(
        &crate::core::paths::data_dir(),
        &crate::core::paths::config_dir(),
    )
}

fn collect_local_privacy_data_from(
    data_dir: &Path,
    config_dir: &Path,
) -> Result<serde_json::Value> {
    let mut files = serde_json::Map::new();
    let mut remaining_bytes = MAX_PRIVACY_EXPORT_SOURCE_BYTES;

    for name in [
        "usage.json",
        "telemetry_queue.json",
        "telemetry_session.json",
        "history.json",
        "completion-cache.json",
        ".installed",
    ] {
        if let Some(value) = read_json_file(&data_dir.join(name), &mut remaining_bytes)? {
            files.insert(name.to_string(), value);
        }
    }

    if let Some(value) = read_license_export(&data_dir.join("license.json"), &mut remaining_bytes)?
    {
        files.insert("license.json".to_string(), value);
    }

    for name in [
        "machine-id",
        "license-clock.highwater",
        "history.json.archive.jsonl",
    ] {
        if let Some(value) = read_text_file(&data_dir.join(name), &mut remaining_bytes)? {
            files.insert(name.to_string(), serde_json::Value::String(value));
        }
    }

    if let Some(value) =
        collect_text_directory(&data_dir.join("audit"), &mut remaining_bytes, |name| {
            name == "audit.jsonl"
                || name
                    .strip_prefix("audit.jsonl.")
                    .is_some_and(|suffix| suffix.parse::<usize>().is_ok())
        })?
    {
        files.insert("audit".to_string(), value);
    }

    for category in ["sbom", "snapshots"] {
        if let Some(value) = collect_json_directory(&data_dir.join(category), &mut remaining_bytes)?
        {
            files.insert(category.to_string(), value);
        }
    }

    if let Some(config) = read_text_file(&config_dir.join("config.toml"), &mut remaining_bytes)? {
        files.insert("config.toml".to_string(), serde_json::Value::String(config));
    }

    Ok(serde_json::Value::Object(files))
}

fn write_private_export(path: &Path, value: &serde_json::Value) -> Result<()> {
    safe_ops::atomic_write_file_sync_private_with(path, |file| {
        let mut writer = BufWriter::with_capacity(64 * 1024, file);
        serde_json::to_writer_pretty(&mut writer, value)
            .context("Failed to serialize privacy export")?;
        writer.flush().context("Failed to flush privacy export")
    })
}

fn read_privacy_file(path: &Path, remaining_bytes: &mut u64) -> Result<Option<Vec<u8>>> {
    let bytes = match safe_ops::read_bounded_regular_bytes(
        path,
        "Privacy export source",
        MAX_PRIVACY_EXPORT_FILE_BYTES,
    ) {
        Ok((bytes, _)) => bytes,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|cause| cause.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    *remaining_bytes = remaining_bytes.checked_sub(bytes.len() as u64).with_context(|| {
        format!("Privacy export exceeds the combined source byte limit ({MAX_PRIVACY_EXPORT_SOURCE_BYTES}): {}", path.display())
    })?;
    Ok(Some(bytes))
}

fn read_json_file(path: &Path, remaining_bytes: &mut u64) -> Result<Option<serde_json::Value>> {
    read_privacy_file(path, remaining_bytes)?
        .map(|bytes| {
            serde_json::from_slice(&bytes)
                .with_context(|| format!("Failed to parse {}", path.display()))
        })
        .transpose()
}

fn read_license_export(
    path: &Path,
    remaining_bytes: &mut u64,
) -> Result<Option<serde_json::Value>> {
    let Some(bytes) = read_privacy_file(path, remaining_bytes)? else {
        return Ok(None);
    };
    let license: crate::core::license::StoredLicense = serde_json::from_slice(&bytes)
        .with_context(|| format!("Failed to parse {}", path.display()))?;
    Ok(Some(serde_json::json!({
        "tier": license.tier,
        "features": license.features,
        "customer": license.customer,
        "expires_at": license.expires_at,
        "validated_at": license.validated_at,
        "machine_id": license.machine_id,
    })))
}

fn read_text_file(path: &Path, remaining_bytes: &mut u64) -> Result<Option<String>> {
    read_privacy_file(path, remaining_bytes)?
        .map(|bytes| {
            String::from_utf8(bytes)
                .with_context(|| format!("{} is not valid UTF-8", path.display()))
        })
        .transpose()
}

fn regular_directory_entries(path: &Path) -> Result<Option<Vec<(String, std::path::PathBuf)>>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("Failed to inspect {}", path.display()));
        }
    };
    anyhow::ensure!(
        metadata.file_type().is_dir(),
        "Privacy export source is not a regular directory: {}",
        path.display()
    );

    let mut entries = std::fs::read_dir(path)
        .with_context(|| format!("Failed to read {}", path.display()))?
        .map(|entry| {
            let entry = entry.with_context(|| format!("Failed to read {}", path.display()))?;
            let name = entry.file_name().into_string().map_err(|_| {
                anyhow::anyhow!(
                    "Privacy export filename is not valid UTF-8 in {}",
                    path.display()
                )
            })?;
            Ok((name, entry.path()))
        })
        .collect::<Result<Vec<_>>>()?;
    entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    Ok(Some(entries))
}

fn collect_json_directory(
    path: &Path,
    remaining_bytes: &mut u64,
) -> Result<Option<serde_json::Value>> {
    let Some(entries) = regular_directory_entries(path)? else {
        return Ok(None);
    };
    let mut files = serde_json::Map::new();
    for (name, entry_path) in entries {
        if entry_path
            .extension()
            .is_some_and(|extension| extension == "json")
            && let Some(value) = read_json_file(&entry_path, remaining_bytes)?
        {
            files.insert(name, value);
        }
    }
    Ok(Some(serde_json::Value::Object(files)))
}

fn collect_text_directory(
    path: &Path,
    remaining_bytes: &mut u64,
    include: impl Fn(&str) -> bool,
) -> Result<Option<serde_json::Value>> {
    let Some(entries) = regular_directory_entries(path)? else {
        return Ok(None);
    };
    let mut files = serde_json::Map::new();
    for (name, entry_path) in entries {
        if include(&name)
            && let Some(value) = read_text_file(&entry_path, remaining_bytes)?
        {
            files.insert(name, serde_json::Value::String(value));
        }
    }
    Ok(Some(serde_json::Value::Object(files)))
}

/// Disable telemetry on this machine.
pub fn opt_out_api() -> Result<()> {
    set_telemetry_preference(false)?;
    println!(
        "  {} Telemetry disabled locally",
        style::maybe_color("✓", |t| t.green().to_string())
    );
    Ok(())
}

/// Enable telemetry on this machine.
pub fn opt_in_api() -> Result<()> {
    set_telemetry_preference(true)?;
    let message = if telemetry_disabled_by_environment() {
        "Telemetry enabled locally in settings. An environment override keeps telemetry disabled."
    } else {
        "Telemetry enabled locally"
    };
    println!(
        "  {} {message}",
        style::maybe_color("✓", |t| t.green().to_string())
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_optional_privacy_files_produce_an_empty_export() {
        let directory = tempfile::tempdir().expect("temp directory");
        let export = collect_local_privacy_data_from(
            &directory.path().join("data"),
            &directory.path().join("config"),
        )
        .expect("collect absent local privacy data");

        assert_eq!(export, serde_json::json!({}));
    }

    #[test]
    fn local_export_represents_every_durable_privacy_category() {
        let directory = tempfile::tempdir().expect("temp directory");
        let data_dir = directory.path().join("data");
        let config_dir = directory.path().join("config");
        std::fs::create_dir_all(data_dir.join("audit")).expect("audit directory");
        std::fs::create_dir_all(data_dir.join("sbom")).expect("SBOM directory");
        std::fs::create_dir_all(data_dir.join("snapshots")).expect("snapshots directory");
        std::fs::create_dir_all(&config_dir).expect("config directory");

        for name in [
            "usage.json",
            "telemetry_queue.json",
            "telemetry_session.json",
            "history.json",
            "completion-cache.json",
            ".installed",
        ] {
            std::fs::write(data_dir.join(name), br#"{"fixture":true}"#)
                .expect("write JSON fixture");
        }
        std::fs::write(
            data_dir.join("license.json"),
            br#"{"key":"secret-key","tier":"pro","features":["sbom"],"customer":"customer@example.com","expires_at":null,"validated_at":1700000000,"token":"secret-token","machine_id":"bound-machine"}"#,
        )
        .expect("write license fixture");
        let archive = "{\"id\":\"older\"}\n{\"id\":\"newer\"}\n";
        std::fs::write(data_dir.join("history.json.archive.jsonl"), archive)
            .expect("write history archive fixture");
        std::fs::write(data_dir.join("machine-id"), "machine-fixture")
            .expect("write machine ID fixture");
        std::fs::write(data_dir.join("license-clock.highwater"), "1700000000")
            .expect("write license clock fixture");
        std::fs::write(data_dir.join("audit/audit.jsonl"), "audit-fixture\n")
            .expect("write audit fixture");
        std::fs::write(data_dir.join("sbom/z-last.json"), br#"{"name":"z"}"#)
            .expect("write final SBOM fixture");
        std::fs::write(data_dir.join("sbom/a-first.json"), br#"{"name":"a"}"#)
            .expect("write first SBOM fixture");
        std::fs::write(
            data_dir.join("snapshots/index.json"),
            br#"{"snapshots":[]}"#,
        )
        .expect("write snapshot index fixture");
        std::fs::write(
            data_dir.join("snapshots/snapshot-1.json"),
            br#"{"id":"snapshot-1"}"#,
        )
        .expect("write snapshot fixture");
        std::fs::write(
            config_dir.join("config.toml"),
            "telemetry_enabled = false\n",
        )
        .expect("write config fixture");

        let export = collect_local_privacy_data_from(&data_dir, &config_dir)
            .expect("collect local privacy data");
        let files = export.as_object().expect("local export object");

        for category in [
            "usage.json",
            "telemetry_queue.json",
            "telemetry_session.json",
            "history.json",
            "history.json.archive.jsonl",
            "license.json",
            "machine-id",
            "license-clock.highwater",
            "completion-cache.json",
            ".installed",
            "audit",
            "sbom",
            "snapshots",
            "config.toml",
        ] {
            assert!(files.contains_key(category), "missing category {category}");
        }
        assert_eq!(files["history.json.archive.jsonl"], archive);
        assert_eq!(files["audit"]["audit.jsonl"], "audit-fixture\n");
        assert_eq!(files["license.json"]["tier"], "pro");
        assert_eq!(files["license.json"]["machine_id"], "bound-machine");
        assert!(files["license.json"].get("key").is_none());
        assert!(files["license.json"].get("token").is_none());
        let sbom_keys = files["sbom"]
            .as_object()
            .expect("SBOM category object")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert_eq!(sbom_keys, ["a-first.json", "z-last.json"]);
        assert_eq!(files["sbom"]["a-first.json"]["name"], "a");
        assert_eq!(files["sbom"]["z-last.json"]["name"], "z");
        assert_eq!(files["snapshots"]["snapshot-1.json"]["id"], "snapshot-1");
    }

    #[cfg(unix)]
    #[test]
    fn privacy_export_is_owner_only_even_when_replacing_a_permissive_file() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("export.json");
        std::fs::write(&path, b"old").expect("write existing export");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("make existing export permissive");

        let value = serde_json::json!({"export": "new"});
        write_private_export(&path, &value).expect("write private export");
        let written: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read export"))
                .expect("parse export");
        assert_eq!(written, value);
        assert_eq!(
            std::fs::metadata(&path)
                .expect("export metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn privacy_export_rejects_oversized_regular_files() {
        let directory = tempfile::tempdir().expect("temp directory");
        let data_dir = directory.path().join("data");
        let config_dir = directory.path().join("config");
        let path = data_dir.join("sbom/oversized.json");
        std::fs::create_dir_all(path.parent().expect("SBOM parent"))
            .expect("create SBOM directory");
        let file = std::fs::File::create(&path).expect("create oversized fixture");
        file.set_len(MAX_PRIVACY_EXPORT_FILE_BYTES + 1)
            .expect("size oversized fixture");

        let error = collect_local_privacy_data_from(&data_dir, &config_dir)
            .expect_err("oversized file must fail");

        assert!(error.to_string().contains("exceeds the"));
        assert!(error.to_string().contains(&path.display().to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn privacy_export_rejects_symlinked_files() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temp directory");
        let data_dir = directory.path().join("data");
        let config_dir = directory.path().join("config");
        let target = directory.path().join("target.json");
        let link = data_dir.join("sbom/linked.json");
        std::fs::create_dir_all(link.parent().expect("SBOM parent"))
            .expect("create SBOM directory");
        std::fs::write(&target, br#"{"private":true}"#).expect("write symlink target");
        symlink(&target, &link).expect("create symlink fixture");

        let error =
            collect_local_privacy_data_from(&data_dir, &config_dir).expect_err("symlink must fail");

        assert!(error.to_string().contains("must be a regular file"));
        assert!(error.to_string().contains(&link.display().to_string()));
    }

    #[test]
    #[serial_test::serial]
    fn opt_out_api_purges_the_queue_and_is_idempotent() {
        if crate::core::testing::run_isolated_test(
            "cli::telemetry::tests::opt_out_api_purges_the_queue_and_is_idempotent",
        ) {
            return;
        }
        if crate::core::is_root() {
            // Elevated processes resolve the data directory to /var/lib/omg
            // regardless of OMG_DATA_DIR, so this fixture-based purge test is
            // only meaningful unprivileged (root containers skip it).
            eprintln!("skipped: opt-out purge fixture requires an unprivileged process");
            return;
        }
        let directory = tempfile::tempdir().expect("temp directory");
        let data_dir = directory.path().join("data");
        let config_dir = directory.path().join("config");
        std::fs::create_dir_all(&data_dir).expect("create data directory");
        std::fs::write(data_dir.join("telemetry_queue.json"), b"queued")
            .expect("write queue fixture");

        temp_env::with_vars(
            [
                ("OMG_DATA_DIR", Some(data_dir.as_os_str())),
                ("OMG_CONFIG_DIR", Some(config_dir.as_os_str())),
            ],
            || {
                opt_out_api().expect("first opt-out");
                opt_out_api().expect("repeated opt-out");

                assert!(!data_dir.join("telemetry_queue.json").exists());
                assert!(!Settings::load().expect("load settings").telemetry_enabled);
            },
        );
    }
}
