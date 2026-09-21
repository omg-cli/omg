//! Compiled parser contracts. These prove grammar, not successful operations.
#[path = "support/cli_surface.rs"]
mod cli_surface;

use clap::{Arg, ArgAction, ArgGroup, Command, CommandFactory, Parser, error::ErrorKind};
use omg_lib::cli::{Cli, Commands};
use serde_json::{Value, json};

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
