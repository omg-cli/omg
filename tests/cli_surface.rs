//! Compiled parser contracts and isolated Doctor output contracts.
//! Parser checks prove grammar; Doctor checks execute the CLI with local fixtures.
#[path = "support/cli_surface.rs"]
mod cli_surface;
pub mod common;

use clap::{Arg, ArgAction, ArgGroup, Command, CommandFactory, Parser, error::ErrorKind};
use omg_lib::cli::{Cli, Commands};
use serde_json::{Value, json};

#[cfg(feature = "license")]
fn account_expiry_output_fixture(expiry: &str) -> anyhow::Result<String> {
    let project = common::TestProject::new();
    let path = project.data_dir.path().join("license.json");
    let bytes = serde_json::to_vec(&json!({
        "key": "private-account-fixture-key",
        "tier": "free",
        "features": [],
        "customer": null,
        "expires_at": expiry,
        "validated_at": 0,
        "token": null,
        "machine_id": null
    }))?;
    std::fs::write(&path, &bytes)?;
    let result = project.run(&["account", "status"]);
    let after = std::fs::read(path)?;
    project.close_checked();
    assert_eq!(after, bytes, "account status must preserve stored metadata");
    assert!(result.success, "{}", result.combined_output());
    assert!(result.stdout.contains("Stored token is invalid or expired"));
    assert!(!result.stdout.contains("private-account-fixture-key"));
    Ok(result.stdout)
}

#[cfg(feature = "license")]
#[test]
fn account_status_neutralizes_stored_expiry_terminal_controls() -> anyhow::Result<()> {
    let output = account_expiry_output_fixture("\u{1b}]52;c;fixture\u{7}expiry\u{1b}[31m\u{202e}")?;
    assert!(output.contains("Stored expiry:"), "{output:?}");
    for forbidden in ['\u{1b}', '\u{7}', '\u{202e}'] {
        assert!(
            !output.contains(forbidden),
            "unsafe account output: {output:?}"
        );
    }
    Ok(())
}

#[cfg(feature = "license")]
#[test]
fn account_status_preserves_normal_expiry_text_and_storage() -> anyhow::Result<()> {
    let output = account_expiry_output_fixture("2030-01-01")?;
    assert!(output.contains("Stored expiry: 2030-01-01"), "{output}");
    Ok(())
}

fn audit_output_entry() -> omg_lib::core::security::audit::AuditEntry {
    use omg_lib::core::security::audit::{AuditEntry, AuditEventType, AuditSeverity};
    AuditEntry {
        id: "fixture-entry".into(),
        timestamp: "2030-01-01T00:00:00Z".into(),
        event_type: AuditEventType::SecurityAudit,
        severity: AuditSeverity::Info,
        user: "fixture-user".into(),
        resource: "normal-resource".into(),
        description: "normal-description".into(),
        metadata: None,
        prev_hash: "genesis".into(),
        hash_version: 1,
        hash: None,
    }
}

fn audit_output_project(
    entry: &omg_lib::core::security::audit::AuditEntry,
) -> anyhow::Result<(common::TestProject, std::path::PathBuf, Vec<u8>)> {
    let project = common::TestProject::new();
    let path = project.data_dir.path().join("audit/audit.jsonl");
    std::fs::create_dir_all(path.parent().unwrap())?;
    let mut bytes = serde_json::to_vec(entry)?;
    bytes.push(b'\n');
    std::fs::write(&path, &bytes)?;
    Ok((project, path, bytes))
}

fn audit_log_output_fixture(field: &str) -> anyhow::Result<()> {
    let mut entry = audit_output_entry();
    let hostile = "\u{1b}]52;c;fixture\u{7}visible\u{1b}[31m\nforged\u{202e}";
    match field {
        "timestamp" => entry.timestamp = hostile.into(),
        "description" => entry.description = hostile.into(),
        "resource" => entry.resource = hostile.into(),
        _ => panic!("unknown fixture field"),
    }
    entry.hash = Some(entry.compute_hash());
    let (project, path, before) = audit_output_project(&entry)?;
    let result = project.run(&["audit", "log"]);
    let after = std::fs::read(path)?;
    project.close_checked();
    assert_eq!(
        after, before,
        "display must preserve hash-bearing audit bytes"
    );
    assert!(result.success, "{}", result.combined_output());
    assert!(result.stdout.contains("visible"), "{:?}", result.stdout);
    for forbidden in ['\u{1b}', '\u{7}', '\u{202e}'] {
        assert!(
            !result.stdout.contains(forbidden),
            "unsafe {field}: {:?}",
            result.stdout
        );
    }
    assert!(!result.stdout.contains("\nforged"), "{:?}", result.stdout);
    Ok(())
}

#[test]
fn audit_log_display_neutralizes_timestamp_controls() -> anyhow::Result<()> {
    audit_log_output_fixture("timestamp")
}

#[test]
fn audit_log_display_neutralizes_description_controls() -> anyhow::Result<()> {
    audit_log_output_fixture("description")
}

#[test]
fn audit_log_display_neutralizes_resource_controls() -> anyhow::Result<()> {
    audit_log_output_fixture("resource")
}

#[test]
fn audit_verify_display_neutralizes_invalid_entry_id() -> anyhow::Result<()> {
    let mut entry = audit_output_entry();
    entry.id = "\u{1b}]52;c;fixture\u{7}Invalid\u{1b}[31m\nforged\u{2066}".into();
    entry.hash = Some("incorrect-hash".into());
    let (project, path, before) = audit_output_project(&entry)?;
    let result = project.run(&["audit", "verify"]);
    let after = std::fs::read(path)?;
    project.close_checked();
    assert_eq!(after, before);
    assert!(!result.success, "bad hash must remain an integrity failure");
    assert!(result.stdout.contains("Audit log integrity FAILED"));
    assert!(result.stdout.contains("First Invalid:"));
    for forbidden in ['\u{1b}', '\u{7}', '\u{2066}'] {
        assert!(
            !result.stdout.contains(forbidden),
            "unsafe ID: {:?}",
            result.stdout
        );
    }
    assert!(!result.stdout.contains("\nforged"), "{:?}", result.stdout);
    Ok(())
}

#[test]
fn audit_exports_preserve_raw_evidence_fields_and_source() -> anyhow::Result<()> {
    let mut entry = audit_output_entry();
    let raw = "\u{1b}]52;c;fixture\u{7}raw\u{1b}[31m\nsecond-line";
    entry.timestamp = raw.into();
    entry.description = raw.into();
    entry.resource = raw.into();
    entry.hash = Some(entry.compute_hash());
    let (project, path, before) = audit_output_project(&entry)?;
    for format in ["json", "csv"] {
        let output = project.path().join(format!("evidence.{format}"));
        let result = project.run(&["audit", "log", "--export", output.to_str().unwrap()]);
        assert!(result.success, "{}", result.combined_output());
        let bytes = std::fs::read(output)?;
        if format == "json" {
            let exported: Value = serde_json::from_slice(&bytes)?;
            assert_eq!(exported, json!([entry]));
        } else {
            let mut reader = csv::Reader::from_reader(bytes.as_slice());
            let rows = reader.records().collect::<Result<Vec<_>, _>>()?;
            assert_eq!(rows.len(), 1);
            for index in [0, 3, 4] {
                assert_eq!(rows[0].get(index), Some(raw));
            }
        }
        assert_eq!(std::fs::read(&path)?, before);
    }
    project.close_checked();
    Ok(())
}

#[cfg(unix)]
fn doctor_eol_fixture(version: Option<&str>) -> anyhow::Result<common::CommandResult> {
    let project = common::TestProject::new();
    if let Some(version) = version {
        let versions = project.data_dir.path().join("versions/node");
        std::fs::create_dir_all(versions.join(version).join("bin"))?;
        std::os::unix::fs::symlink(version, versions.join("current"))?;
    }
    let result = project.run(&["doctor", "--eol"]);
    project.close_checked();
    Ok(result)
}

#[cfg(unix)]
#[test]
fn doctor_eol_unknown_cycle_does_not_claim_supported() -> anyhow::Result<()> {
    let result = doctor_eol_fixture(Some("99.1.0"))?;
    let output = result.combined_output();
    assert!(
        result.success,
        "unknown lifecycle is not proven EOL: {output}"
    );
    assert!(
        output.contains("node") && output.contains("99.1.0"),
        "{output}"
    );
    assert!(output.contains("Support data unavailable"), "{output}");
    assert!(
        !output.contains("All detected runtimes are within support period"),
        "{output}"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn doctor_eol_empty_inventory_has_no_support_verdict() -> anyhow::Result<()> {
    let result = doctor_eol_fixture(None)?;
    let output = result.combined_output();
    assert!(result.success, "{output}");
    assert!(
        output.contains("No managed runtimes were detected"),
        "{output}"
    );
    assert!(
        !output.contains("All detected runtimes are within support period"),
        "{output}"
    );
    assert!(!output.contains("Support data unavailable"), "{output}");
    Ok(())
}

#[cfg(unix)]
#[test]
fn doctor_eol_known_expired_cycle_remains_an_issue() -> anyhow::Result<()> {
    let result = doctor_eol_fixture(Some("16.1.0"))?;
    let output = result.combined_output();
    assert!(!result.success, "{output}");
    assert!(output.contains("EOL since 2023-09-11"), "{output}");
    assert!(!output.contains("Support data unavailable"), "{output}");
    Ok(())
}

#[test]
fn daemon_request_inventory_matches_every_compiled_variant() {
    use omg_lib::daemon::protocol::{PROTOCOL_VERSION, Request, encode_frame, split_frame};
    use std::collections::BTreeSet;

    // Generate the exhaustive match and witnesses from the same list. A new
    // variant cannot be acknowledged in the match while omitted from witnesses.
    macro_rules! request_inventory {
        ($($variant:ident { $($field:ident: $value:expr),* $(,)? }),+ $(,)?) => {{
            fn identity(request: &Request) -> &'static str {
                match request {
                    $(Request::$variant { .. } => concat!("ipc:", stringify!($variant))),+
                }
            }
            let requests = [$(Request::$variant { $($field: $value),* }),+];
            let mut identities = BTreeSet::new();
            for (index, request) in requests.iter().enumerate() {
                assert_eq!(request.id(), index as u64 + 1);
                let encoded = encode_frame(request).unwrap();
                let (version, payload) = split_frame(&encoded).unwrap();
                assert_eq!(version, PROTOCOL_VERSION);
                let decoded: Request = bitcode::deserialize(payload).unwrap();
                assert_eq!(serde_json::to_value(&decoded).unwrap(), serde_json::to_value(request).unwrap());
                assert!(identities.insert(identity(request).to_owned()));
            }
            identities
        }};
    }

    let observed = request_inventory! {
        Search { id: 1, query: "literal -- query".into(), limit: Some(0) },
        Info { id: 2, package: "fixture-package".into() },
        Status { id: 3 },
        Explicit { id: 4 },
        ExplicitCount { id: 5 },
        SecurityAudit { id: 6 },
        Ping { id: 7 },
        CacheStats { id: 8 },
        CacheClear { id: 9 },
        RefreshIndex { id: 10 },
        Metrics { id: 11 },
        Suggest { id: 12, query: "package".into(), limit: None },
        DebianSearch { id: 13, query: "two words".into(), limit: Some(17) },
        Health { id: 14 },
        ListUpdates { id: 15 },
    };
    let manifest: Value = serde_json::from_str(include_str!("contracts/manifest.json")).unwrap();
    let declared: BTreeSet<_> = manifest["interfaces"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row["id"].as_str().filter(|id| id.starts_with("ipc:")))
        .map(str::to_owned)
        .collect();
    assert_eq!(
        observed, declared,
        "daemon request inventory requires review"
    );
}

fn command<'a>(document: &'a Value, path: &str) -> &'a Value {
    document["commands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["path"] == path)
        .expect("canonical command")
}

fn argument<'a>(command: &'a Value, id: &str) -> &'a Value {
    command["arguments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == id)
        .expect("canonical argument")
}

fn fixture() -> Command {
    Command::new("fixture")
        .version("1.2.3")
        .arg(
            Arg::new("verbose")
                .short('v')
                .global(true)
                .action(ArgAction::Count),
        )
        .subcommand(
            Command::new("hidden")
                .hide(true)
                .alias("secret")
                .visible_alias("h")
                .arg(Arg::new("input").required(true))
                .arg(
                    Arg::new("mode")
                        .short('m')
                        .short_alias('M')
                        .long("mode")
                        .alias("style")
                        .value_parser([
                            clap::builder::PossibleValue::new("safe").alias("s"),
                            clap::builder::PossibleValue::new("fast").hide(true),
                        ])
                        .default_value("safe"),
                )
                .arg(Arg::new("left").long("left").action(ArgAction::SetTrue))
                .arg(Arg::new("right").long("right").action(ArgAction::SetTrue))
                .group(ArgGroup::new("side").args(["left", "right"]).required(true)),
        )
}

#[test]
fn surface_includes_hidden_aliases_globals_defaults_and_generated_arguments() {
    let document = cli_surface::surface(fixture());
    let root = command(&document, "fixture");
    assert_eq!(argument(root, "help")["action"], "Help");
    assert_eq!(argument(root, "version")["action"], "Version");
    let hidden = command(&document, "fixture hidden");
    assert_eq!(hidden["hidden"], true);
    assert_eq!(hidden["aliases"], json!(["h", "secret"]));
    assert_eq!(argument(hidden, "verbose")["global"], true);
    assert_eq!(argument(hidden, "input")["index"], 1);
    assert_eq!(argument(hidden, "input")["required"], true);
    let mode = argument(hidden, "mode");
    assert_eq!(mode["short"], "m");
    assert_eq!(mode["short_aliases"], json!(["M"]));
    assert_eq!(mode["long_aliases"], json!(["style"]));
    assert_eq!(mode["defaults"], json!(["safe"]));
    assert_eq!(
        mode["possible_values"],
        json!([
            {"name":"fast", "aliases":[], "hidden":true},
            {"name":"safe", "aliases":["s"], "hidden":false},
        ])
    );
    let group = hidden["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == "side")
        .unwrap();
    assert_eq!(group["required"], true);
    assert_eq!(group["multiple"], false);
    assert_eq!(group["arguments"], json!(["left", "right"]));
}

#[test]
fn surface_is_stable_across_declaration_order() {
    let make = |reverse| {
        let children = if reverse {
            vec![Command::new("b"), Command::new("a")]
        } else {
            vec![Command::new("a"), Command::new("b")]
        };
        Command::new("fixture").subcommands(children)
    };
    assert_eq!(
        cli_surface::surface(make(false)),
        cli_surface::surface(make(true))
    );
}

#[test]
#[should_panic(expected = "duplicate argument")]
fn duplicate_argument_id_cannot_overwrite_evidence() {
    let _ = cli_surface::surface(
        Command::new("fixture")
            .arg(Arg::new("duplicate").long("one"))
            .arg(Arg::new("duplicate").long("two")),
    );
}

#[test]
fn synthetic_constraints_have_exact_parser_oracles() {
    let matches = fixture()
        .try_get_matches_from(["fixture", "secret", "payload", "-M", "s", "--left", "-vv"])
        .unwrap();
    let child = matches.subcommand_matches("hidden").unwrap();
    assert_eq!(child.get_one::<String>("input").unwrap(), "payload");
    // A String parser preserves the accepted alias; ValueEnum parsers may normalize it.
    assert_eq!(child.get_one::<String>("mode").unwrap(), "s");
    assert_eq!(child.get_count("verbose"), 2);
    for (args, error) in [
        (
            vec!["fixture", "h", "payload"],
            ErrorKind::MissingRequiredArgument,
        ),
        (
            vec!["fixture", "h", "payload", "--left", "--right"],
            ErrorKind::ArgumentConflict,
        ),
        (
            vec!["fixture", "h", "payload", "--left", "--mode", "unknown"],
            ErrorKind::InvalidValue,
        ),
    ] {
        assert_eq!(
            fixture().try_get_matches_from(args).unwrap_err().kind(),
            error
        );
    }
}

#[test]
fn export_omg_surface() {
    let document = cli_surface::surface(Cli::command());
    assert_eq!(document["schema_version"], 1);
    assert_eq!(
        argument(command(&document, "omg search"), "limit")["defaults"],
        json!(["15"])
    );
    assert_eq!(
        argument(command(&document, "omg update"), "aur_only")["conflicts"],
        json!(["fast", "turbo"])
    );
    assert_eq!(
        document["commands"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["path"] == "omg account"),
        cfg!(feature = "license")
    );
    cli_surface::write_artifact("omg", document);
}

#[cfg(not(unix))]
#[test]
fn export_omgd_unavailable() {
    cli_surface::write_artifact(
        "omgd",
        json!({
            "schema_version": 1, "binary": "omgd", "available": false,
            "reason": "daemon requires Unix", "commands": [],
        }),
    );
}

#[test]
fn omg_search_aliases_options_and_boundary_values_round_trip() {
    for name in ["search", "s"] {
        for limit in [0, 1, usize::MAX] {
            for option in ["--limit", "-l"] {
                let value = limit.to_string();
                let parsed =
                    Cli::try_parse_from(["omg", name, "-vv", "--json", option, &value, "--", "-V"])
                        .unwrap();
                assert_eq!(parsed.verbose, 2);
                assert!(parsed.json);
                match parsed.command {
                    Commands::Search {
                        query,
                        limit: actual,
                        ..
                    } => {
                        assert_eq!(query, "-V");
                        assert_eq!(actual, limit);
                    }
                    other => panic!("unexpected command: {other:?}"),
                }
            }
        }
    }
    for args in [
        vec!["omg", "search", "pkg", "--limit", "no"],
        vec!["omg", "search", "pkg", "--limit", "18446744073709551616"],
    ] {
        assert_eq!(
            Cli::try_parse_from(args).unwrap_err().kind(),
            ErrorKind::ValueValidation
        );
    }
    assert_eq!(
        Cli::try_parse_from(["omg", "search", "pkg", "-l", "1", "-l", "2"])
            .unwrap_err()
            .kind(),
        ErrorKind::ArgumentConflict
    );
}

#[test]
fn omg_conflicts_and_forwarding_do_not_change_argument_meaning() {
    for flag in ["--fast", "--turbo"] {
        assert_eq!(
            Cli::try_parse_from(["omg", "update", "--aur-only", flag])
                .unwrap_err()
                .kind(),
            ErrorKind::ArgumentConflict
        );
    }
    let parsed =
        Cli::try_parse_from(["omg", "run", "build", "--", "--watch", "--", "two words"]).unwrap();
    match parsed.command {
        Commands::Run {
            task, args, watch, ..
        } => {
            assert_eq!(task, "build");
            assert!(!watch);
            assert_eq!(args, ["--watch", "--", "two words"]);
        }
        other => panic!("unexpected command: {other:?}"),
    }
}
