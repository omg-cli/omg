//! Test-only reflection of the compiled parser, shared with the private OMGD parser.
use std::collections::BTreeSet;

use clap::Command;
use serde_json::{Value, json};

fn sorted<T: Ord>(values: impl IntoIterator<Item = T>) -> Vec<T> {
    let mut values: Vec<_> = values.into_iter().collect();
    values.sort();
    values
}

fn validate_ids(command: &Command) {
    let mut arguments = BTreeSet::new();
    for arg in command.get_arguments() {
        assert!(
            arguments.insert(arg.get_id().as_str()),
            "duplicate argument ID"
        );
    }
    let mut children = BTreeSet::new();
    for child in command.get_subcommands() {
        assert!(children.insert(child.get_name()), "duplicate command name");
        validate_ids(child);
    }
}

#[must_use]
pub fn surface(mut command: Command) -> Value {
    validate_ids(&command);
    command.build();
    validate_ids(&command);
    let mut commands = Vec::new();
    walk(&command, command.get_name(), &mut commands);
    commands.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    let mut paths = BTreeSet::new();
    for entry in &commands {
        assert!(
            paths.insert(entry["path"].as_str().unwrap()),
            "duplicate canonical command path"
        );
    }
    json!({
        "schema_version": 1,
        "binary": command.get_name(),
        "available": true,
        "commands": commands,
        // Reflection is an inventory, not proof of custom validation or behavior.
        "reflection_limits": ["conditional requirements", "custom value parsers", "runtime behavior"],
    })
}

fn walk(command: &Command, path: &str, commands: &mut Vec<Value>) {
    let mut arguments: Vec<_> = command.get_arguments().map(|arg| {
        let mut possible_values: Vec<_> = arg.get_possible_values().iter().map(|value| json!({
            "name": value.get_name(),
            "aliases": sorted(value.get_name_and_aliases().filter(|alias| *alias != value.get_name())),
            "hidden": value.is_hide_set(),
        })).collect();
        possible_values.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        json!({
            "id": arg.get_id().as_str(),
            "long": arg.get_long(),
            "short": arg.get_short().map(|value| value.to_string()),
            "long_aliases": sorted(arg.get_all_aliases().unwrap_or_default()),
            "short_aliases": sorted(arg.get_all_short_aliases().unwrap_or_default().into_iter().map(|value| value.to_string())),
            "index": arg.get_index(),
            "global": arg.is_global_set(),
            "required": arg.is_required_set(),
            "hidden": arg.is_hide_set(),
            "action": format!("{:?}", arg.get_action()),
            "arity": arg.get_num_args().map(|range| json!({"min": range.min_values(), "max": range.max_values()})),
            "value_names": arg.get_value_names().map(|names| names.iter().map(|name| name.as_str()).collect::<Vec<_>>()),
            "value_delimiter": arg.get_value_delimiter().map(|value| value.to_string()),
            "value_terminator": arg.get_value_terminator().map(|value| value.as_str()),
            "possible_values": possible_values,
            "defaults": arg.get_default_values().iter().map(|value| value.to_str().expect("UTF-8 parser default")).collect::<Vec<_>>(),
            "env": arg.get_env().map(|value| value.to_str().expect("UTF-8 parser env name")),
            "last": arg.is_last_set(),
            "trailing_var_arg": arg.is_trailing_var_arg_set(),
            "exclusive": arg.is_exclusive_set(),
            "require_equals": arg.is_require_equals_set(),
            "ignore_case": arg.is_ignore_case_set(),
            "allow_hyphen_values": arg.is_allow_hyphen_values_set(),
            "allow_negative_numbers": arg.is_allow_negative_numbers_set(),
            "conflicts": sorted(command.get_arg_conflicts_with(arg).iter().map(|other| other.get_id().as_str())),
        })
    }).collect();
    arguments.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    let mut groups: Vec<_> = command
        .get_groups()
        .map(|group| {
            let multiple = group.clone().is_multiple();
            json!({
                "id": group.get_id().as_str(),
                "arguments": sorted(group.get_args().map(|id| id.as_str())),
                "required": group.is_required_set(),
                "multiple": multiple,
            })
        })
        .collect();
    groups.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    commands.push(json!({
        "path": path,
        "aliases": sorted(command.get_all_aliases()),
        "short_flag": command.get_short_flag().map(|value| value.to_string()),
        "long_flag": command.get_long_flag(),
        "short_flag_aliases": sorted(command.get_all_short_flag_aliases().map(|value| value.to_string())),
        "long_flag_aliases": sorted(command.get_all_long_flag_aliases()),
        "hidden": command.is_hide_set(),
        "subcommand_required": command.is_subcommand_required_set(),
        "arg_required_else_help": command.is_arg_required_else_help_set(),
        "allow_external_subcommands": command.is_allow_external_subcommands_set(),
        "args_conflicts_with_subcommands": command.is_args_conflicts_with_subcommands_set(),
        "subcommand_negates_reqs": command.is_subcommand_negates_reqs_set(),
        "arguments": arguments,
        "groups": groups,
    }));
    for child in command.get_subcommands() {
        walk(child, &format!("{path} {}", child.get_name()), commands);
    }
}

pub fn write_artifact(binary: &str, mut document: Value) {
    let Ok(directory) = std::env::var("OMG_CONTRACT_SURFACE_OUT") else {
        return;
    };
    let source_sha = std::env::var("OMG_CONTRACT_SOURCE_SHA").expect("surface source SHA");
    assert!(
        source_sha.len() == 40 && source_sha.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid source SHA"
    );
    let platform = std::env::var("OMG_CONTRACT_PLATFORM").expect("surface platform owner");
    let features: Vec<_> = [
        ("arch", cfg!(feature = "arch")),
        ("debian", cfg!(feature = "debian")),
        ("debian-pure", cfg!(feature = "debian-pure")),
        ("default", cfg!(feature = "default")),
        ("docker_tests", cfg!(feature = "docker_tests")),
        ("fedora", cfg!(feature = "fedora")),
        ("license", cfg!(feature = "license")),
        ("macos", cfg!(feature = "macos")),
        ("pgp", cfg!(feature = "pgp")),
    ]
    .into_iter()
    .filter_map(|(name, active)| active.then_some(name))
    .collect();
    document["build"] = json!({
        "os": std::env::consts::OS, "arch": std::env::consts::ARCH,
        "platform": platform, "source_sha": source_sha,
        "features": features, "feature_scope": "declared public Cargo features, including default",
    });
    std::fs::create_dir_all(&directory).expect("surface output directory");
    let path = std::path::Path::new(&directory).join(format!("{binary}.json"));
    std::fs::write(path, serde_json::to_vec_pretty(&document).unwrap())
        .expect("write parser surface");
}
