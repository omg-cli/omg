//! Broad CLI smoke and behavior contracts for OMG commands.

// These contracts use isolated mock package state and child-local configuration.
// Exercise each Linux backend build instead of silently selecting zero tests.
#![cfg(all(
    target_os = "linux",
    any(
        feature = "arch",
        feature = "debian",
        feature = "debian-pure",
        feature = "fedora"
    )
))]

pub mod common;

use clap::{CommandFactory, Parser};
use common::*;
use omg_lib::cli::Cli;

#[test]
fn explicit_shortcut_uses_the_same_isolated_state_as_explicit_count() {
    for distro in ["arch", "debian", "fedora"] {
        let project = TestProject::for_distro(distro);
        project.mock_available("available-only", "9.0.0").unwrap();
        let backend = match distro {
            "arch" => "pacman",
            "fedora" => "dnf",
            _ => "apt",
        };
        let state = project
            .data_dir
            .path()
            .join(format!("mock_state_{backend}.json"));
        for expected in [&[][..], &["alpha", "git", "zulu"][..]] {
            // Deliberately insert out of order. Expected records come from the
            // fixture, never another product query or its reported count.
            if !expected.is_empty() {
                for name in ["zulu", "git", "alpha"] {
                    project.mock_install(name, "2.43.0").unwrap();
                }
            }
            let before = std::fs::read(&state).unwrap();
            for args in [
                &["--json", "explicit"][..],
                &["explicit", "--json", "--quiet"][..],
            ] {
                let listing = project.run(args);
                listing.assert_success();
                listing.assert_no_ansi();
                let payload: serde_json::Value = serde_json::from_str(&listing.stdout).unwrap();
                assert_eq!(
                    payload,
                    serde_json::json!({"packages": expected, "count": expected.len()})
                );
            }
            for command in [&["explicit", "--count"][..], &["ec"][..]] {
                let result = project.run(command);
                result.assert_success();
                assert_eq!(result.stdout.trim(), expected.len().to_string());
                let mut json_args = vec!["--json"];
                json_args.extend_from_slice(command);
                let json = project.run(&json_args);
                json.assert_success();
                json.assert_no_ansi();
                let actual: serde_json::Value = serde_json::from_str(&json.stdout).unwrap();
                assert_eq!(actual, serde_json::json!({"count": expected.len()}));
            }
            assert_eq!(
                std::fs::read(&state).unwrap(),
                before,
                "{distro}: read-only query changed package state"
            );
        }
        project.close_checked();
    }
}

#[test]
fn prompt_counters_preserve_exact_counts_with_global_flags_and_reject_extra_arguments() {
    let project = TestProject::new();
    project.mock_install("counter-installed", "1.0.0").unwrap();
    project
        .mock_available("counter-installed", "2.0.0")
        .unwrap();
    project
        .mock_available("counter-available-only", "3.0.0")
        .unwrap();
    for (command, expected) in [("ec", 1), ("tc", 1), ("oc", 0), ("uc", 1)] {
        for args in [
            vec![command],
            vec!["--quiet", command],
            vec![command, "-q"],
            vec!["-vv", command],
        ] {
            let result = project.run(&args);
            result.assert_success();
            assert_eq!(result.stdout.trim(), expected.to_string(), "{args:?}");
        }
        for args in [
            vec!["--json", command],
            vec![command, "--json"],
            vec!["-q", command, "--json"],
        ] {
            let result = project.run(&args);
            result.assert_success();
            result.assert_no_ansi();
            let actual: serde_json::Value = serde_json::from_str(&result.stdout).unwrap();
            assert_eq!(actual, serde_json::json!({"count": expected}), "{args:?}");
        }
        let invalid = project.run(&[command, "unexpected-positional"]);
        invalid.assert_failure();
        assert!(
            invalid.stderr.contains("unexpected argument"),
            "{}",
            invalid.combined_output()
        );
        assert!(invalid.stdout.is_empty());
        let help = project.run(&[command, "--help"]);
        help.assert_success();
        assert!(help.stdout.contains(&format!("omg {command}")));
    }
    project.close_checked();
}

#[test]
fn search_json_preserves_exact_records_ranking_limits_and_package_state() {
    let distro = if cfg!(feature = "arch") {
        "arch"
    } else if cfg!(feature = "fedora") {
        "fedora"
    } else {
        "debian"
    };
    let project = TestProject::for_distro(distro);
    for (name, version) in [
        ("qprobe", "1.2.3"),
        ("qprobe-extra", "2.3.4"),
        ("addon-qprobe", "3.4.5"),
        ("unrelated", "4.5.6"),
    ] {
        project
            .mock_available(name, version)
            .expect("seed query fixture");
    }
    let backend = match distro {
        "arch" => "pacman",
        "fedora" => "dnf",
        _ => "apt",
    };
    let state = project
        .data_dir
        .path()
        .join(format!("mock_state_{backend}.json"));
    let before = std::fs::read(&state).expect("fixture state");
    // Independently specified exact > prefix > word-boundary ordering.
    let expected = [
        serde_json::json!({"name":"qprobe","version":"1.2.3","description":"","source":"Official"}),
        serde_json::json!({"name":"qprobe-extra","version":"2.3.4","description":"","source":"Official"}),
        serde_json::json!({"name":"addon-qprobe","version":"3.4.5","description":"","source":"Official"}),
    ];
    for command in ["search", "s"] {
        for limit in [0usize, 1, 2, 9] {
            for flags in [
                &[][..],
                &["--detailed", "--no-aur"][..],
                &["-d", "--quiet"][..],
            ] {
                let limit_arg = limit.to_string();
                let mut args = vec!["--json", command, "QPROBE", "-l", &limit_arg];
                args.extend_from_slice(flags);
                let result = project.run(&args);
                result.assert_success();
                result.assert_no_ansi();
                let actual: Vec<serde_json::Value> = serde_json::from_str(&result.stdout)
                    .expect("stdout must contain only the package JSON array");
                assert_eq!(actual, expected[..limit.min(expected.len())], "{args:?}");
                assert_eq!(
                    std::fs::read(&state).unwrap(),
                    before,
                    "search mutated package state: {args:?}"
                );
            }
        }
    }
    project.close_checked();
}

fn command_paths() -> Vec<Vec<String>> {
    fn collect(command: &clap::Command, prefix: &mut Vec<String>, paths: &mut Vec<Vec<String>>) {
        for subcommand in command.get_subcommands() {
            prefix.push(subcommand.get_name().to_string());
            paths.push(prefix.clone());
            collect(subcommand, prefix, paths);
            prefix.pop();
        }
    }

    let command = Cli::command();
    let mut paths = vec![Vec::new()];
    collect(&command, &mut Vec::new(), &mut paths);
    paths
}

#[test]
fn every_declared_command_renders_binary_help() {
    use std::fmt::Write as _;

    let paths = command_paths();
    let evidence_dir = std::env::var_os("OMG_CLI_SMOKE_EVIDENCE_DIR").map(std::path::PathBuf::from);
    if let Some(dir) = &evidence_dir {
        std::fs::create_dir_all(dir).expect("create CLI smoke evidence directory");
    }
    let mut index = String::from("command\texit\tstdout_bytes\tstderr_bytes\n");

    for path in paths {
        let mut args: Vec<&str> = path.iter().map(String::as_str).collect();
        args.push("--help");
        let result = run_omg(&args);
        let command = if path.is_empty() {
            "omg".to_string()
        } else {
            format!("omg {}", path.join(" "))
        };
        assert!(
            result.success && result.stdout.contains("Usage:"),
            "`{command} --help` did not render help\nstdout: {}\nstderr: {}",
            result.stdout,
            result.stderr
        );

        if let Some(dir) = &evidence_dir {
            let filename = if path.is_empty() {
                "omg.txt".to_string()
            } else {
                format!("omg-{}.txt", path.join("-"))
            };
            let transcript = format!(
                "command: {command} --help\nexit: {}\n--- stdout ---\n{}--- stderr ---\n{}",
                result.exit_code, result.stdout, result.stderr
            );
            std::fs::write(dir.join(filename), transcript).expect("write CLI help transcript");
            writeln!(
                index,
                "{command}\t{}\t{}\t{}",
                result.exit_code,
                result.stdout.len(),
                result.stderr.len()
            )
            .expect("write CLI smoke index row");
        }
    }

    if let Some(dir) = evidence_dir {
        std::fs::write(dir.join("index.tsv"), index).expect("write CLI smoke index");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Safety {
    Read,
    IsolatedWrite,
    ControlledError,
    HelpBoundary,
    PackageMutation,
    ServiceMutation,
    Interactive,
}

impl Safety {
    fn parse(raw: &str, line_number: usize) -> Self {
        match raw {
            "read" => Self::Read,
            "isolated-write" => Self::IsolatedWrite,
            "controlled-error" => Self::ControlledError,
            "help-boundary" => Self::HelpBoundary,
            "package-mutation" => Self::PackageMutation,
            "service-mutation" => Self::ServiceMutation,
            "interactive" => Self::Interactive,
            other => {
                panic!("unknown safety class on behavior inventory line {line_number}: {other}")
            }
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::IsolatedWrite => "isolated-write",
            Self::ControlledError => "controlled-error",
            Self::HelpBoundary => "help-boundary",
            Self::PackageMutation => "package-mutation",
            Self::ServiceMutation => "service-mutation",
            Self::Interactive => "interactive",
        }
    }
}

#[test]
fn behavior_inventory_keeps_hook_and_workspace_assertions() {
    let cases = behavior_cases();
    for case in &cases {
        assert_eq!(Safety::parse(case.safety.as_str(), 1), case.safety);
    }
    for (id, assertion) in [
        ("hooks-install", Assertion::HooksInstalled),
        ("hooks-install-force", Assertion::HooksInstalled),
        ("workspace-run-parallel-all", Assertion::WorkspaceAllOutput),
    ] {
        let case = cases
            .iter()
            .find(|case| case.id == id)
            .expect("required behavioral case");
        assert!(
            case.assertions.contains(&assertion),
            "{id} lost its behavioral assertion"
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UxState {
    Pass,
    Declared,
}

impl UxState {
    fn parse(raw: &str, line_number: usize) -> Self {
        match raw {
            "pass" => Self::Pass,
            "declared" => Self::Declared,
            other => panic!(
                "unknown expected_ux state on behavior inventory line {line_number}: {other}"
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Tier {
    Hermetic,
    Container,
    Qemu,
    Pty,
    NestedContainer,
    Network,
    Credentialed,
}

impl Tier {
    fn parse(raw: &str, line_number: usize) -> Self {
        match raw {
            "hermetic" => Self::Hermetic,
            "container" => Self::Container,
            "qemu" => Self::Qemu,
            "pty" => Self::Pty,
            "nested-container" => Self::NestedContainer,
            "network" => Self::Network,
            "credentialed" => Self::Credentialed,
            other => {
                panic!("unknown execution tier on behavior inventory line {line_number}: {other}")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Distro {
    Arch,
    Debian,
    Ubuntu,
    Fedora,
}

impl Distro {
    fn parse(raw: &str, line_number: usize) -> Self {
        match raw {
            "arch" => Self::Arch,
            "debian" => Self::Debian,
            "ubuntu" => Self::Ubuntu,
            "fedora" => Self::Fedora,
            other => panic!("unknown distro on behavior inventory line {line_number}: {other}"),
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Arch => 0,
            Self::Debian => 1,
            Self::Ubuntu => 2,
            Self::Fedora => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReleaseExpectation {
    Pass,
    ExpectedRejection,
    KnownDefect,
    Blocked,
    NotApplicable,
    Pending,
}

/// Expected exit codes per distribution, in [`Distro::index`] order.
/// A bare code (`0`) applies to every distro; backend-divergent rows spell
/// out all four (`arch:0,debian:1,ubuntu:1,fedora:1`, #303). Partial
/// matrices are rejected so a missing distro can never silently inherit
/// another's expectation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExpectedExits([i32; 4]);

impl ExpectedExits {
    fn parse(raw: &str, line_number: usize) -> Self {
        if let Ok(code) = raw.parse::<i32>() {
            return Self([code; 4]);
        }
        let mut exits = [None; 4];
        for entry in raw.split(',') {
            let (distro, code) = entry.split_once(':').unwrap_or_else(|| {
                panic!(
                    "expected exit on behavior inventory line {line_number} must be a code or distro:code: {entry}"
                )
            });
            let distro = Distro::parse(distro, line_number);
            let slot = &mut exits[distro.index()];
            assert!(
                slot.is_none(),
                "duplicate distro exit on behavior inventory line {line_number}: {distro:?}"
            );
            *slot = Some(code.parse().unwrap_or_else(|error| {
                panic!("invalid exit code on behavior inventory line {line_number}: {error}")
            }));
        }
        let [Some(arch), Some(debian), Some(ubuntu), Some(fedora)] = exits else {
            panic!(
                "expected exits on behavior inventory line {line_number} must classify arch, debian, ubuntu, and fedora"
            );
        };
        Self([arch, debian, ubuntu, fedora])
    }

    const fn exit_for(self, distro: Distro) -> i32 {
        self.0[distro.index()]
    }
}

impl ReleaseExpectation {
    fn parse(raw: &str, line_number: usize) -> Self {
        match raw {
            "pass" => Self::Pass,
            "expected-rejection" => Self::ExpectedRejection,
            "known-defect" => Self::KnownDefect,
            "blocked" => Self::Blocked,
            "not-applicable" => Self::NotApplicable,
            "pending" => Self::Pending,
            other => panic!(
                "unknown release expectation on behavior inventory line {line_number}: {other}"
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TargetExpectations {
    HermeticPass,
    ReleaseMatrix([ReleaseExpectation; 4]),
}

impl TargetExpectations {
    fn parse(raw: &str, line_number: usize) -> Self {
        if raw == "hermetic:pass" {
            return Self::HermeticPass;
        }

        let mut expectations = [None; 4];
        for entry in raw.split(',') {
            let (distro, expectation) = entry.split_once(':').unwrap_or_else(|| {
                panic!(
                    "release target on behavior inventory line {line_number} must be distro:expectation: {entry}"
                )
            });
            let distro = Distro::parse(distro, line_number);
            let slot = &mut expectations[distro.index()];
            assert!(
                slot.is_none(),
                "duplicate distro on behavior inventory line {line_number}: {distro:?}"
            );
            *slot = Some(ReleaseExpectation::parse(expectation, line_number));
        }

        let [Some(arch), Some(debian), Some(ubuntu), Some(fedora)] = expectations else {
            panic!(
                "release targets on behavior inventory line {line_number} must classify arch, debian, ubuntu, and fedora"
            );
        };
        Self::ReleaseMatrix([arch, debian, ubuntu, fedora])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Assertion {
    JsonStdout,
    Artifact(String),
    WorkspaceFilteredOutput,
    WorkspaceAllOutput,
    HooksInstalled,
    HooksAbsent,
}

impl Assertion {
    fn parse(raw: &str, line_number: usize) -> Self {
        match raw {
            "json-stdout" => Self::JsonStdout,
            "workspace-filtered-output" => Self::WorkspaceFilteredOutput,
            "workspace-all-output" => Self::WorkspaceAllOutput,
            "hooks-installed" => Self::HooksInstalled,
            "hooks-absent" => Self::HooksAbsent,
            _ => match Self::parse_artifact_path(raw) {
                Ok(relative) => Self::Artifact(relative),
                Err(reason) => panic!(
                    "artifact assertion on behavior inventory line {line_number} must be `artifact:<root-relative path>` without traversal ({reason}): {raw}"
                ),
            },
        }
    }

    fn parse_artifact_path(raw: &str) -> Result<String, String> {
        let relative = raw
            .strip_prefix("artifact:")
            .ok_or_else(|| "missing `artifact:` prefix".to_string())?;
        let path = std::path::Path::new(relative);
        if relative.is_empty()
            || path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
            || relative
                .split('/')
                .any(|component| component.is_empty() || component == "." || component == "..")
        {
            return Err(
                "path must be relative with no root, prefix, `.`, `..`, or empty components"
                    .to_string(),
            );
        }
        Ok(relative.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cleanup {
    TempdirDrop,
    None,
    ContainerPrune,
    HostStateRestore,
    VmRevert,
    DaemonStop,
}

impl Cleanup {
    fn parse(raw: &str, line_number: usize) -> Self {
        match raw {
            "tempdir-drop" => Self::TempdirDrop,
            "none" => Self::None,
            "container-prune" => Self::ContainerPrune,
            "host-state-restore" => Self::HostStateRestore,
            "vm-revert" => Self::VmRevert,
            "daemon-stop" => Self::DaemonStop,
            other => {
                panic!("unknown cleanup scope on behavior inventory line {line_number}: {other}")
            }
        }
    }
}

#[derive(Debug)]
struct BehaviorCase {
    id: String,
    line: usize,
    args: Vec<String>,
    safety: Safety,
    expected_exit: Option<ExpectedExits>,
    expected_ux: UxState,
    requires: Vec<String>,
    tiers: Vec<Tier>,
    targets: TargetExpectations,
    assertions: Vec<Assertion>,
    cleanup: Cleanup,
}

impl BehaviorCase {
    fn validate_schema(&self) {
        assert!(
            !self.tiers.is_empty(),
            "case {} on line {}: execution tiers cannot be empty",
            self.id,
            self.line
        );
        let unique_tiers: std::collections::HashSet<Tier> = self.tiers.iter().copied().collect();
        assert_eq!(
            unique_tiers.len(),
            self.tiers.len(),
            "case {} on line {}: execution tiers must be unique",
            self.id,
            self.line
        );

        match self.expected_ux {
            UxState::Pass => {
                assert!(
                    self.expected_exit.is_some(),
                    "case {} on line {}: executable rows must declare an expected exit code",
                    self.id,
                    self.line
                );
                if self.runs_hermetically() {
                    assert_eq!(
                        self.targets,
                        TargetExpectations::HermeticPass,
                        "case {} on line {}: hermetic rows must target hermetic:pass",
                        self.id,
                        self.line
                    );
                    assert_eq!(
                        self.cleanup,
                        Cleanup::TempdirDrop,
                        "case {} on line {}: hermetic rows clean up by dropping the tempdir fixture",
                        self.id,
                        self.line
                    );
                    assert!(
                        !matches!(
                            self.safety,
                            Safety::PackageMutation | Safety::ServiceMutation | Safety::Interactive
                        ),
                        "case {} on line {}: mutation and interactive cases cannot run hermetically",
                        self.id,
                        self.line
                    );
                } else {
                    let TargetExpectations::ReleaseMatrix(expectations) = &self.targets else {
                        panic!(
                            "case {} on line {}: non-hermetic executable rows need release expectations",
                            self.id, self.line
                        );
                    };
                    assert!(
                        expectations
                            .iter()
                            .all(|expectation| *expectation != ReleaseExpectation::Pending),
                        "case {} on line {}: executable release expectations cannot remain pending",
                        self.id,
                        self.line
                    );
                }
            }
            UxState::Declared => {
                assert!(
                    !self.tiers.contains(&Tier::Hermetic),
                    "case {} on line {}: declaration rows must name non-hermetic tiers",
                    self.id,
                    self.line
                );
                assert!(
                    self.expected_exit.is_none(),
                    "case {} on line {}: declaration rows cannot claim an exit code",
                    self.id,
                    self.line
                );
                let TargetExpectations::ReleaseMatrix(expectations) = &self.targets else {
                    panic!(
                        "case {} on line {}: declaration rows need release expectations",
                        self.id, self.line
                    );
                };
                assert!(
                    expectations
                        .iter()
                        .all(|expectation| *expectation == ReleaseExpectation::Pending),
                    "case {} on line {}: declaration rows must remain pending until executed",
                    self.id,
                    self.line
                );
                assert!(
                    self.cleanup != Cleanup::TempdirDrop,
                    "case {} on line {}: declaration rows do not use hermetic cleanup",
                    self.id,
                    self.line
                );
            }
        }
    }

    fn runs_hermetically(&self) -> bool {
        self.tiers == [Tier::Hermetic] && self.expected_ux == UxState::Pass
    }
}

const BEHAVIOR_INVENTORY_HEADER: &str = "case\targs_json\tsafety\texpected_exit\texpected_ux\trequires\ttier\ttargets\tassertions\tcleanup";

fn behavior_cases() -> Vec<BehaviorCase> {
    let mut lines = include_str!("cli_behavior_inventory.tsv").lines();
    assert_eq!(
        lines.next(),
        Some(BEHAVIOR_INVENTORY_HEADER),
        "behavior inventory header must match the ten-column contract exactly"
    );
    lines
        .enumerate()
        .filter(|(_, line)| !line.is_empty())
        .map(|(line_index, line)| {
            let line_number = line_index + 2;
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(
                fields.len(),
                10,
                "behavior inventory line {line_number} must have ten columns (case, args_json, safety, expected_exit, expected_ux, requires, tier, targets, assertions, cleanup): {line}"
            );
            let expected_exit = if fields[3] == "-" {
                None
            } else {
                Some(ExpectedExits::parse(fields[3], line_number))
            };
            let case = BehaviorCase {
                id: fields[0].to_string(),
                line: line_number,
                args: serde_json::from_str(fields[1]).unwrap_or_else(|error| {
                    panic!("invalid args JSON on behavior inventory line {line_number}: {error}")
                }),
                safety: Safety::parse(fields[2], line_number),
                expected_exit,
                expected_ux: UxState::parse(fields[4], line_number),
                requires: if fields[5] == "-" {
                    Vec::new()
                } else {
                    fields[5]
                        .split(',')
                        .map(str::to_string)
                        .collect()
                },
                tiers: fields[6]
                    .split(',')
                    .map(|raw| Tier::parse(raw, line_number))
                    .collect(),
                targets: TargetExpectations::parse(fields[7], line_number),
                assertions: if fields[8] == "-" {
                    Vec::new()
                } else {
                    fields[8]
                        .split(',')
                        .map(|raw| Assertion::parse(raw, line_number))
                        .collect()
                },
                cleanup: Cleanup::parse(fields[9], line_number),
            };
            case.validate_schema();
            case
        })
        .collect()
}

// `self-update --version` shares Clap's generated version argument ID, but the
// command disables the generated flag.
fn declared_long_flags() -> Vec<(Vec<String>, String)> {
    fn collect(
        command: &clap::Command,
        prefix: &mut Vec<String>,
        flags: &mut Vec<(Vec<String>, String)>,
    ) {
        for argument in command.get_arguments() {
            if argument.get_id() == "help"
                || (argument.get_id() == "version" && !command.is_disable_version_flag_set())
            {
                continue;
            }
            if let Some(long_flag) = argument.get_long() {
                flags.push((prefix.clone(), long_flag.to_string()));
            }
        }
        for subcommand in command.get_subcommands() {
            prefix.push(subcommand.get_name().to_string());
            collect(subcommand, prefix, flags);
            prefix.pop();
        }
    }

    let command = Cli::command();
    let mut flags = Vec::new();
    collect(&command, &mut Vec::new(), &mut flags);
    flags
}

fn global_long_flags() -> Vec<String> {
    Cli::command()
        .get_arguments()
        .filter(|argument| {
            argument.is_global_set()
                && argument.get_long().is_some()
                && !matches!(argument.get_id().as_str(), "help" | "version")
        })
        .filter_map(|argument| argument.get_long().map(str::to_string))
        .collect()
}

fn command_args_without_global_flags(args: &[String]) -> &[String] {
    let globals: Vec<String> = global_long_flags()
        .iter()
        .map(|flag| format!("--{flag}"))
        .collect();
    let command_index = args
        .iter()
        .position(|arg| !globals.contains(arg))
        .unwrap_or(args.len());
    &args[command_index..]
}

#[test]
fn behavior_inventory_covers_every_declared_command() {
    let cases = behavior_cases();
    let executable: Vec<&BehaviorCase> = cases
        .iter()
        .filter(|case| case.expected_ux == UxState::Pass)
        .collect();

    let missing: Vec<String> = command_paths()
        .into_iter()
        .filter(|path| !path.is_empty())
        .filter(|path| {
            !executable
                .iter()
                .any(|case| normalized_command_path(&case.args).starts_with(path.as_slice()))
        })
        .map(|path| format!("omg {}", path.join(" ")))
        .collect();
    assert!(
        missing.is_empty(),
        "declared commands missing behavior cases: {missing:?}"
    );
}

#[test]
fn behavior_inventory_covers_every_declared_long_flag() {
    let cases = behavior_cases();
    let contract_args: Vec<(Vec<String>, &Vec<String>)> = cases
        .iter()
        .map(|case| (normalized_command_path(&case.args), &case.args))
        .collect();

    let covered = |flag_path: &[String], flag: &str| {
        let needle = format!("--{flag}");
        contract_args.iter().any(|(path, args)| {
            args.contains(&needle) && (flag_path.is_empty() || path.as_slice() == flag_path)
        })
    };

    let missing: Vec<String> = declared_long_flags()
        .iter()
        .filter(|(path, flag)| !covered(path, flag))
        .map(|(path, flag)| format!("omg {} --{flag}", path.join(" ")))
        .collect();
    assert!(
        missing.is_empty(),
        "declared long flags missing contract rows:\n{}",
        missing.join("\n")
    );
}

#[test]
fn behavior_inventory_contract_keys_are_unique() {
    let cases = behavior_cases();
    let mut ids = std::collections::HashSet::new();
    let mut keys = std::collections::HashSet::<(Vec<String>, Vec<String>, Vec<String>)>::new();
    for case in &cases {
        assert!(
            ids.insert(case.id.clone()),
            "duplicate case id {} on line {}",
            case.id,
            case.line
        );
        let key = (
            normalized_command_path(&case.args),
            case.args.clone(),
            case.requires.clone(),
        );
        assert!(
            keys.insert(key),
            "duplicate contract key (command path, args, prerequisites) for case {} on line {}",
            case.id,
            case.line
        );
    }
}

#[test]
fn behavior_inventory_prerequisites_resolve_to_earlier_rows() {
    let cases = behavior_cases();
    let mut seen = std::collections::HashSet::new();
    for case in &cases {
        for prerequisite in &case.requires {
            assert!(
                seen.contains(prerequisite),
                "case {} on line {} requires {prerequisite}, which is not an earlier case",
                case.id,
                case.line
            );
        }
        seen.insert(case.id.clone());
    }
}

fn normalized_command_path(args: &[String]) -> Vec<String> {
    let stripped = command_args_without_global_flags(args);
    command_paths()
        .into_iter()
        .filter(|path| !path.is_empty() && stripped.starts_with(path.as_slice()))
        .max_by_key(Vec::len)
        .unwrap_or_default()
}

#[test]
fn behavior_inventory_header_matches_the_ten_column_contract() {
    assert_eq!(
        include_str!("cli_behavior_inventory.tsv").lines().next(),
        Some(BEHAVIOR_INVENTORY_HEADER),
        "behavior inventory must open with the exact ten-column header"
    );
}

#[test]
fn behavior_inventory_artifact_parser_rejects_escaping_paths() {
    for raw in ["artifact:/etc", "artifact:../x", "artifact:a/../x"] {
        assert!(
            Assertion::parse_artifact_path(raw).is_err(),
            "artifact parser must reject {raw}"
        );
    }
    assert_eq!(
        Assertion::parse_artifact_path("artifact:manifest.json").as_deref(),
        Ok("manifest.json")
    );
}

#[test]
fn behavior_inventory_release_targets_classify_every_distro_once() {
    let valid = "arch:pending,debian:pending,ubuntu:pending,fedora:pending";
    assert!(matches!(
        TargetExpectations::parse(valid, 1),
        TargetExpectations::ReleaseMatrix(_)
    ));
    for invalid in [
        "arch:pending,debian:pending,ubuntu:pending",
        "arch:pending,arch:pending,ubuntu:pending,fedora:pending",
    ] {
        assert!(
            std::panic::catch_unwind(|| TargetExpectations::parse(invalid, 1)).is_err(),
            "release target parser must reject {invalid}"
        );
    }
}

#[test]
fn behavior_inventory_expected_exits_support_per_distro_overrides() {
    // Bare codes apply to every distro, preserving the existing contract.
    let uniform = ExpectedExits::parse("0", 1);
    for distro in [Distro::Arch, Distro::Debian, Distro::Ubuntu, Distro::Fedora] {
        assert_eq!(uniform.exit_for(distro), 0);
    }
    // #303: backends that gracefully refuse an Arch-only operation record
    // the refusal per distro while arch keeps passing.
    let split = ExpectedExits::parse("arch:0,debian:1,ubuntu:1,fedora:1", 1);
    assert_eq!(split.exit_for(Distro::Arch), 0);
    assert_eq!(split.exit_for(Distro::Debian), 1);
    assert_eq!(split.exit_for(Distro::Ubuntu), 1);
    assert_eq!(split.exit_for(Distro::Fedora), 1);
    for invalid in [
        "arch:0,debian:1,ubuntu:1",
        "arch:0,arch:1,debian:1,ubuntu:1,fedora:1",
        "arch:0,debian:1,ubuntu:1,centos:1",
        "arch:0,debian:x,ubuntu:1,fedora:1",
        "arch:0,debian:1,ubuntu:1,fedora:",
    ] {
        assert!(
            std::panic::catch_unwind(|| ExpectedExits::parse(invalid, 1)).is_err(),
            "expected-exit parser must reject {invalid}"
        );
    }
}

#[test]
fn behavior_inventory_declaration_args_parse() {
    for case in behavior_cases()
        .into_iter()
        .filter(|case| case.expected_ux == UxState::Declared)
    {
        let args = std::iter::once("omg".to_string()).chain(case.args.clone());
        assert!(
            Cli::try_parse_from(args).is_ok(),
            "declaration case {} on line {} must use valid CLI arguments",
            case.id,
            case.line
        );
    }
}

#[cfg(feature = "arch")]
fn prepare_behavior_fixture(project: &TestProject) -> (String, String) {
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::Command;

    project.create_file("Makefile", ".PHONY: smoke overlap\nsmoke:\n\t@echo smoke-task-ok\noverlap:\n\t@sh workspace-overlap.sh . primary\n");
    project.create_file(
        "workspace-overlap.sh",
        include_str!("../scripts/workspace-overlap-fixture.sh"),
    );
    project.create_file("README.md", "# CLI behavior smoke fixture\n");
    project.create_file("project/README.md", "# Nested audit fixture\n");
    project.create_file(
        "project/Makefile",
        ".PHONY: smoke overlap\nsmoke:\n\t@echo nested-smoke-task-ok\noverlap:\n\t@sh ../workspace-overlap.sh .. nested\n",
    );

    let pacman_local = project
        .pacman_root
        .path()
        .join("var/lib/pacman/local/pacman-7.0.0-1");
    std::fs::create_dir_all(&pacman_local).expect("create isolated pacman local database");
    std::fs::create_dir_all(project.pacman_root.path().join("var/lib/pacman/sync"))
        .expect("create isolated pacman sync database");
    std::fs::write(
        project
            .pacman_root
            .path()
            .join("var/lib/pacman/local/ALPM_DB_VERSION"),
        "9\n",
    )
    .expect("write isolated pacman database version");
    std::fs::write(
        pacman_local.join("desc"),
        "%NAME%\npacman\n\n%VERSION%\n7.0.0-1\n\n%DESC%\nIsolated package manager fixture\n\n%ARCH%\nx86_64\n\n%BUILDDATE%\n1700000000\n\n%INSTALLDATE%\n1700000000\n\n%PACKAGER%\nOMG Smoke <smoke@example.invalid>\n\n%SIZE%\n1048576\n\n%REASON%\n0\n\n%LICENSE%\nGPL-2.0-or-later\n\n",
    )
    .expect("write isolated pacman package metadata");

    let home = project.create_dir("home");
    std::fs::write(home.join(".bashrc"), "").expect("write isolated bashrc");
    std::fs::write(home.join(".zshrc"), "").expect("write isolated zshrc");

    let bin = project.create_dir("bin");
    for (name, body) in [
        (
            "docker",
            "#!/bin/sh\necho 'permission denied while connecting to isolated Docker fixture' >&2\nexit 1\n",
        ),
        (
            "cargo",
            "#!/bin/sh\necho 'error: no Rust toolchain is configured in the isolated fixture' >&2\nexit 1\n",
        ),
    ] {
        let path = bin.join(name);
        std::fs::write(&path, body).expect("write isolated command stub");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("make isolated command stub executable");
    }

    let git = |args: &[&str]| {
        let output = Command::new("git")
            .args(args)
            .current_dir(project.path())
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("run git fixture command");
        assert!(
            output.status.success(),
            "git fixture command failed: git {}\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&["init", "--quiet", "--initial-branch=main"]);
    git(&["add", "README.md", "Makefile"]);
    git(&[
        "-c",
        "user.name=OMG Smoke",
        "-c",
        "user.email=smoke@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
    ]);

    let inherited_path = std::env::var("PATH").unwrap_or_default();
    (
        home.to_string_lossy().into_owned(),
        format!("{}:{inherited_path}", bin.display()),
    )
}

#[cfg(feature = "arch")]
fn has_ansi(text: &str) -> bool {
    text.as_bytes().windows(2).any(|pair| pair == b"\x1b[")
}

#[test]
#[serial]
#[cfg(feature = "arch")] // This inventory fixture explicitly seeds a pacman database.
fn behavior_inventory_runs_in_hermetic_state() {
    use std::fmt::Write as _;
    use std::time::Instant;

    let project = TestProject::for_distro("arch");
    let (home, path) = prepare_behavior_fixture(&project);
    let evidence_dir =
        std::env::var_os("OMG_CLI_BEHAVIOR_EVIDENCE_DIR").map(std::path::PathBuf::from);
    if let Some(dir) = &evidence_dir {
        std::fs::create_dir_all(dir).expect("create CLI behavior evidence directory");
    }

    let mut index = String::from(
        "case\tcommand\tsafety\texpected_exit\texit\tstdout_bytes\tstderr_bytes\telapsed_ms\tissues\tux_verdict\n",
    );
    let mut failures = Vec::new();

    for (number, case) in behavior_cases().into_iter().enumerate() {
        // Missing-input probes must not inherit files written by earlier rows
        // such as env-capture. Keep the shared fixture for dependent cases.
        let empty_environment = matches!(
            case.id.as_str(),
            "env-export-missing-lock" | "env-plan-missing-manifest"
        )
        .then(|| TestProject::for_distro("arch"));
        let project = empty_environment.as_ref().unwrap_or(&project);
        let root = project.path().to_string_lossy().into_owned();
        let expanded_args: Vec<String> = case
            .args
            .iter()
            .map(|arg| arg.replace("${ROOT}", &root))
            .collect();
        let command = format!("omg {}", expanded_args.join(" "));
        if !case.runs_hermetically() {
            writeln!(
                index,
                "{}\t{command}\t{}\t-\t-\t-\t-\t-\tdeclared\tdeclared",
                case.id,
                case.safety.as_str()
            )
            .expect("write CLI behavior index row");
            continue;
        }
        // The hermetic fixture always runs the arch mock backend, so the
        // arch expectation governs here; release lanes resolve their own.
        let expected_exit = case
            .expected_exit
            .expect("executable rows declare an exit code")
            .exit_for(Distro::Arch);
        let args: Vec<&str> = expanded_args.iter().map(String::as_str).collect();
        let started = Instant::now();
        let result = project.run_with_env(
            &args,
            &[
                ("HOME", &home),
                ("PATH", &path),
                ("SHELL", "/bin/bash"),
                ("NO_COLOR", "1"),
                ("TERM", "dumb"),
                ("GIT_CONFIG_GLOBAL", "/dev/null"),
                ("GIT_CONFIG_NOSYSTEM", "1"),
                ("OMG_TEST_COMMAND_TIMEOUT_SECS", "20"),
            ],
        );
        let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
        let mut issues = Vec::new();
        if result.exit_code != expected_exit {
            issues.push(format!(
                "expected exit {expected_exit}, got {}",
                result.exit_code
            ));
        }
        if has_ansi(&result.stdout) || has_ansi(&result.stderr) {
            issues.push("ANSI escape sequence in redirected output".to_string());
        }
        let combined = result.combined_output();
        if combined.contains("panicked at") || combined.contains("thread 'main' panicked") {
            issues.push("Rust panic report".to_string());
        }
        if case.safety == Safety::HelpBoundary && !result.stdout.contains("Usage:") {
            issues.push("help boundary did not render Usage".to_string());
        }
        if case
            .expected_exit
            .is_some_and(|exits| exits.exit_for(Distro::Arch) != 0)
            && result.stderr.trim().is_empty()
        {
            issues.push("failure did not explain itself on stderr".to_string());
        }
        let audit_success = match case.id.as_str() {
            "audit" | "audit-scan" => Some("No vulnerabilities found in scanned packages."),
            "audit-fix" | "audit-fix-flags" => Some("No vulnerabilities found!"),
            _ => None,
        };
        if let Some(expected) = audit_success
            && !result.stdout.contains(expected)
        {
            issues.push("empty-inventory audit did not report its completed scan".to_string());
        }
        for assertion in &case.assertions {
            match assertion {
                Assertion::HooksInstalled | Assertion::HooksAbsent => {
                    use std::os::unix::fs::PermissionsExt as _;
                    for (name, label) in [
                        ("pre-commit", "Pre-commit"),
                        ("post-checkout", "Post-checkout"),
                        ("post-merge", "Post-merge"),
                    ] {
                        let path = project.path().join(".git/hooks").join(name);
                        let valid = if matches!(assertion, Assertion::HooksAbsent) {
                            path.symlink_metadata()
                                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
                        } else {
                            let marker = format!("# OMG {label} Hook");
                            path.symlink_metadata().is_ok_and(|metadata| {
                                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
                            }) && std::fs::read_to_string(&path)
                                .is_ok_and(|text| text.lines().any(|line| line == marker))
                                && std::process::Command::new("sh")
                                    .arg("-n")
                                    .arg(&path)
                                    .output()
                                    .is_ok_and(|output| output.status.success())
                        };
                        if !valid {
                            issues.push(format!("hook {name} did not satisfy {assertion:?}"));
                        }
                    }
                }
                Assertion::WorkspaceFilteredOutput | Assertion::WorkspaceAllOutput => {
                    let primary = result
                        .stdout
                        .lines()
                        .filter(|line| *line == "smoke-task-ok")
                        .count();
                    let nested = result
                        .stdout
                        .lines()
                        .filter(|line| *line == "nested-smoke-task-ok")
                        .count();
                    let expected_nested =
                        usize::from(matches!(assertion, Assertion::WorkspaceAllOutput));
                    if primary != 1 || nested != expected_nested {
                        issues.push(format!("workspace task counts primary={primary} nested={nested}; expected primary=1 nested={expected_nested}"));
                    }
                }
                Assertion::JsonStdout => {
                    if serde_json::from_str::<serde_json::Value>(&result.stdout).is_err() {
                        issues.push("JSON output did not parse".to_string());
                    }
                }
                Assertion::Artifact(relative) => {
                    let path = project.path().join(relative);
                    if std::fs::read_to_string(&path)
                        .ok()
                        .and_then(|contents| {
                            serde_json::from_str::<serde_json::Value>(&contents).ok()
                        })
                        .is_none()
                    {
                        issues.push(format!(
                            "artifact {relative} was not written as valid JSON at {}",
                            path.display()
                        ));
                    }
                }
            }
        }

        let actual_ux = if issues.is_empty() { "pass" } else { "fail" };
        if actual_ux != "pass" {
            failures.push(format!("{}: {}", case.id, issues.join("; ")));
        }
        let issue_summary = if issues.is_empty() {
            "none".to_string()
        } else {
            issues.join("; ")
        };
        writeln!(
            index,
            "{}\t{command}\t{}\t{expected_exit}\t{}\t{}\t{}\t{elapsed_ms:.1}\t{}\t{actual_ux}",
            case.id,
            case.safety.as_str(),
            result.exit_code,
            result.stdout.len(),
            result.stderr.len(),
            issue_summary.replace('\t', " ")
        )
        .expect("write CLI behavior index row");

        if let Some(dir) = &evidence_dir {
            let transcript = format!(
                "command: {command}\nsafety: {}\nexpected_exit: {expected_exit}\nexit: {}\nelapsed_ms: {elapsed_ms:.1}\nissues: {issue_summary}\nux_verdict: {actual_ux}\n--- stdout ---\n{}\n--- stderr ---\n{}",
                case.safety.as_str(),
                result.exit_code,
                result.stdout,
                result.stderr
            );
            std::fs::write(
                dir.join(format!("{:03}-{}.txt", number + 1, case.id)),
                transcript,
            )
            .expect("write CLI behavior transcript");
        }
    }

    if let Some(dir) = evidence_dir {
        std::fs::write(dir.join("index.tsv"), index).expect("write CLI behavior index");
    }
    assert!(
        failures.is_empty(),
        "CLI behavior inventory failures:\n{}",
        failures.join("\n")
    );
}

#[test]
fn root_help_prioritizes_common_commands() {
    let result = run_omg(&["--help"]);

    result.assert_success();
    result.assert_stdout_contains("Usage: omg");
    result.assert_stdout_contains("search");
    assert!(!result.stdout.contains("enterprise"), "{}", result.stdout);
    result.assert_stdout_contains("omg --help --all-commands");
}

#[test]
fn redirected_status_has_no_terminal_escape_sequences() {
    let result = run_omg(&["status"]);

    result.assert_success();
    assert!(
        !result.stdout.contains('\u{1b}'),
        "redirected status output contains terminal escapes: {:?}",
        result.stdout
    );
}

#[test]
fn tui_commands_require_an_attended_terminal() {
    for args in [&["dash"][..], &["team", "dashboard"][..]] {
        let result = run_omg(args);

        assert!(!result.success, "{args:?} unexpectedly succeeded");
        assert!(
            result.stderr.contains("requires an interactive terminal"),
            "{args:?} produced an unclear error: {}",
            result.stderr
        );
        assert!(
            !result.combined_output().contains('\u{1b}'),
            "{args:?} emitted terminal escapes without a terminal"
        );
    }
}

#[test]
fn all_commands_help_exposes_advanced_commands() {
    let result = run_omg(&["--help", "--all-commands"]);

    result.assert_success();
    result.assert_stdout_contains("enterprise");
    result.assert_stdout_contains("workspace");
}

#[test]
fn completions_help_stays_scoped_after_the_shell_argument() {
    let result = run_omg(&["completions", "bash", "--help"]);

    result.assert_success();
    result.assert_stdout_contains("Generate shell completions");
    result.assert_stdout_contains("Usage: omg completions");
    assert!(
        !result.stdout.contains("Essential Commands"),
        "{}",
        result.stdout
    );
}

#[cfg(unix)]
#[test]
fn closed_stdout_uses_sigpipe_without_a_panic_report() {
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::{Command, Stdio};

    let runtime_dir = tempfile::tempdir().expect("runtime directory");
    let (reader, writer) = UnixStream::pair().expect("stdout socket pair");
    drop(reader);
    let writer = std::os::fd::OwnedFd::from(writer);

    let child = Command::new(env!("CARGO_BIN_EXE_omg"))
        .arg("daemon-status")
        .env("OMG_DISABLE_DAEMON", "1")
        .env("OMG_DISABLE_TELEMETRY", "1")
        .env("XDG_RUNTIME_DIR", runtime_dir.path())
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn omg with closed stdout");
    let output = child.wait_with_output().expect("wait for omg");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.signal(), Some(nix::libc::SIGPIPE));
    assert!(
        !stderr.contains("panicked"),
        "unexpected panic report: {stderr}"
    );
}

// =======================
// CORE PACKAGE MANAGEMENT
// =======================

mod install_tests {
    use super::*;

    #[test]
    fn test_install_help() {
        let result = run_omg(&["install", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("install");
    }

    // Contract: installing a package that exists nowhere must FAIL and name the
    // cause (observed: "Error: Package not found in official repos"). The old
    // `!success || ...` disjunction also passed when install wrongly succeeded.
    #[test]
    fn test_install_nonexistent() {
        let result = run_omg(&[
            "install",
            "--yes",
            "package-that-definitely-does-not-exist-12345",
        ]);
        result.assert_failure();
        let combined = result.combined_output();
        assert!(
            combined.to_lowercase().contains("not found"),
            "Failure must name the missing package cause: {combined}"
        );
    }

    // Contract: dry-run exits 0 and explicitly promises no changes
    // (observed: "No changes will be made (dry run)").
    #[test]
    #[cfg(feature = "arch")] // The installed package fixture is pacman.
    fn test_install_dry_run() {
        let result = run_omg(&["install", "--dry-run", "pacman"]);
        result.assert_success();
        let combined = result.combined_output();
        assert!(
            combined
                .to_lowercase()
                .contains("no changes will be made (dry run)"),
            "Dry run must state that no changes are made: {combined}"
        );
        result.assert_no_ansi();
    }
}

mod remove_tests {
    use super::*;

    #[test]
    fn test_remove_help() {
        let result = run_omg(&["remove", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("remove");
    }

    #[test]
    fn test_remove_nonexistent() {
        let result = run_omg(&["remove", "package-never-installed-xyz", "--yes"]);
        result.assert_success();
        result.assert_stdout_contains("Remove");
        result.assert_no_ansi();
    }
}

mod update_tests {
    use super::*;

    #[test]
    fn test_update_help() {
        let result = run_omg(&["update", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("update");
    }

    // Contract: --check lists pending updates without refreshing package
    // databases or requesting elevation.
    #[test]
    fn test_update_dry_run() {
        let result = run_omg(&["update", "--check"]);
        result.assert_success();
        result.assert_stdout_contains("Checking for updates · cached");
        result.assert_no_ansi();
        assert!(
            !result.stdout.contains("Synced"),
            "--check refreshed package metadata"
        );
        for flag in ["--dry-run", "--no-sync"] {
            let preview = run_omg(&["update", flag]);
            preview.assert_success();
            assert!(
                !preview.stdout.contains("Synced"),
                "{flag} refreshed package metadata: {}",
                preview.stdout
            );
        }
    }
}

// ====================
// RUNTIME MANAGEMENT
// ====================

mod runtime_tests {
    use super::*;

    #[test]
    fn test_hook_bash() {
        let result = run_omg(&["hook", "bash"]);
        result.assert_success();
        result.assert_stdout_contains("eval");
    }

    #[test]
    fn test_hook_zsh() {
        let result = run_omg(&["hook", "zsh"]);
        result.assert_success();
        result.assert_stdout_contains("eval");
    }

    #[test]
    fn test_hook_fish() {
        let result = run_omg(&["hook", "fish"]);
        result.assert_success();
        // Fish hook generation in src/hooks/mod.rs uses `source` instead of
        // the `eval` emitted for POSIX shells.
        result.assert_stdout_contains("source");
    }

    #[test]
    fn test_use_invalid_runtime() {
        let result = run_omg(&["use", "invalid-runtime", "1.0.0"]);
        assert!(!result.success, "Should fail for invalid runtime");
    }

    #[test]
    fn test_which_help() {
        let result = run_omg(&["which", "--help"]);
        result.assert_success();
    }

    #[test]
    fn redirected_runtime_install_output_has_no_ansi() {
        let project = TestProject::new();
        let result = project.run(&["use", "python", "3.12.0"]);
        result.assert_success();
        result.assert_no_ansi();
    }
}

// ===================
// PROJECT WORKFLOWS
// ===================

mod project_tests {
    use super::*;

    #[test]
    fn test_run_help() {
        let result = run_omg(&["run", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("run");
    }

    #[test]
    fn test_new_help() {
        let result = run_omg(&["new", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("template");
    }

    #[test]
    fn test_tool_help() {
        let result = run_omg(&["tool", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("tool");
    }

    #[test]
    fn test_tool_list() {
        let result = run_omg(&["tool", "list"]);
        let output = result.combined_output();
        assert!(
            result.success || output.to_lowercase().contains("no tools"),
            "Tool list should succeed or explain that no tools are installed: {output}"
        );
    }
}

// ====================
// ENVIRONMENT & TEAM
// ====================

mod env_tests {
    use super::*;

    #[test]
    fn test_env_help() {
        let result = run_omg(&["env", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("env");
    }

    #[test]
    fn test_team_help() {
        let result = run_omg(&["team", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("team");
    }

    #[test]
    fn test_hooks_help() {
        let result = run_omg(&["hooks", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("hooks");
    }

    #[test]
    fn git_hook_uninstall_preserves_composed_and_custom_automation() {
        let repository = tempfile::tempdir().unwrap();
        let hooks = repository.path().join("managed-hooks");
        for args in [
            vec!["init", "-q"],
            vec!["config", "core.hooksPath", hooks.to_str().unwrap()],
        ] {
            assert!(
                std::process::Command::new("git")
                    .args(args)
                    .current_dir(repository.path())
                    .status()
                    .unwrap()
                    .success()
            );
        }
        run_omg_in_dir(&["hooks", "install"], repository.path()).assert_success();
        let pre_commit = hooks.join("pre-commit");
        let composed = format!(
            "{}\n# custom automation\ncustom_check\n",
            std::fs::read_to_string(&pre_commit).unwrap()
        );
        let custom = "#!/bin/sh\n# OMG integration notes\ncustom_check\n";
        std::fs::write(&pre_commit, &composed).unwrap();
        std::fs::write(hooks.join("post-merge"), custom).unwrap();
        run_omg_in_dir(&["hooks", "install"], repository.path()).assert_success();
        let status = run_omg_in_dir(&["hooks", "status"], repository.path());
        status.assert_success();
        status.assert_stdout_contains("unrecognized or modified");
        let result = run_omg_in_dir(&["hooks", "uninstall"], repository.path());
        result.assert_success();
        result.assert_stdout_contains("Removed 1 hook(s)");
        assert_eq!(std::fs::read_to_string(pre_commit).unwrap(), composed);
        assert_eq!(
            std::fs::read_to_string(hooks.join("post-merge")).unwrap(),
            custom
        );
        assert!(!hooks.join("post-checkout").exists());
    }

    #[test]
    fn test_snapshot_help() {
        let result = run_omg(&["snapshot", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("snapshot");
    }

    #[test]
    fn redirected_snapshot_output_has_no_ansi() {
        for args in [
            ["snapshot", "create", "--message", "smoke"].as_slice(),
            ["snapshot", "list"].as_slice(),
            ["snapshot", "restore", "missing", "--dry-run"].as_slice(),
        ] {
            run_omg(args).assert_no_ansi();
        }
    }

    #[test]
    #[cfg(any(feature = "arch", feature = "debian", feature = "debian-pure"))]
    fn redirected_environment_drift_output_has_no_ansi() {
        let project = TestProject::new();
        let capture = project.run(&["env", "capture"]);
        capture.assert_success();
        capture.assert_no_ansi();

        let check = project.run(&["env", "check"]);
        check.assert_success();
        check.assert_no_ansi();
    }
}

// ==================
// CONTAINER & CI
// ==================

mod devops_tests {
    use super::*;

    #[test]
    fn test_container_help() {
        let result = run_omg(&["container", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("container");
    }

    #[test]
    fn test_ci_help() {
        let result = run_omg(&["ci", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("ci");
    }
}

// ========================
// SECURITY & COMPLIANCE
// ========================

mod security_tests {
    use super::*;

    #[test]
    fn test_audit_help() {
        let result = run_omg(&["audit", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("audit");
    }

    #[test]
    fn test_audit_sbom_help() {
        let result = run_omg(&["audit", "sbom", "--help"]);
        result.assert_success();
    }

    #[test]
    fn test_audit_secrets_help() {
        let result = run_omg(&["audit", "secrets", "--help"]);
        result.assert_success();
    }

    #[test]
    fn test_audit_licenses_help() {
        let result = run_omg(&["audit", "licenses", "--help"]);
        result.assert_success();
    }

    #[test]
    #[cfg(feature = "license")]
    fn test_account_help() {
        let result = run_omg(&["account", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("link");
    }

    #[test]
    #[cfg(feature = "license")]
    fn account_link_does_not_prompt_without_a_terminal() {
        let result = run_omg_with_env(
            &["account", "link", "invalid-token"],
            &[
                ("HTTP_PROXY", "http://127.0.0.1:9"),
                ("HTTPS_PROXY", "http://127.0.0.1:9"),
            ],
        );

        result.assert_failure();
        assert!(
            !result.stdout.contains("Your name") && !result.stdout.contains("Your email"),
            "non-interactive account linking must not consume stdin:\n{}",
            result.stdout
        );
    }

    #[test]
    #[cfg(not(feature = "license"))]
    fn account_is_explicitly_unavailable_without_license_feature() {
        let result = run_omg(&["account", "--help"]);
        assert_eq!(result.exit_code, 2);
        result.assert_stderr_contains("unrecognized subcommand 'account'");
    }
}

// ====================
// SYSTEM MANAGEMENT
// ====================

mod system_tests {
    use super::*;

    #[test]
    fn test_doctor_help() {
        let result = run_omg(&["doctor", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("doctor");
    }

    #[test]
    fn test_doctor_run() {
        let result = run_omg(&["doctor"]);
        // Doctor should always work (shows diagnostic info)
        assert!(result.success, "Doctor command should succeed");
    }

    #[test]
    fn test_config_help() {
        let result = run_omg(&["config", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("config");
    }

    #[test]
    fn test_config_list() {
        let result = run_omg(&["config", "list"]);
        // Should render the configuration header with real settings
        result.assert_success();
        result.assert_stdout_contains("OMG Configuration");
    }

    #[test]
    fn test_daemon_help() {
        let result = run_omg(&["daemon", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("daemon");
    }

    #[test]
    fn test_daemon_status_basic() {
        let result = run_omg(&["daemon-status"]);
        // On Unix, daemon-status always exits 0 and prints its header,
        // whether the daemon is reachable or not (daemon_status.rs:17-90).
        result.assert_success();
        result.assert_stdout_contains("Daemon Status");
    }

    #[test]
    fn test_history_help() {
        let result = run_omg(&["history", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("history");
    }

    #[test]
    fn test_rollback_help() {
        let result = run_omg(&["rollback", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("rollback");
    }

    #[test]
    fn test_migrate_help() {
        let result = run_omg(&["migrate", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("migrate");
    }
}

// ================
// UI & UTILITIES
// ================

mod ui_tests {
    use super::*;

    #[test]
    fn test_dash_help() {
        let result = run_omg(&["dash", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("dash");
    }

    #[test]
    fn test_stats_help() {
        let result = run_omg(&["stats", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("stats");
    }

    #[test]
    fn test_metrics_help() {
        let result = run_omg(&["metrics", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("metrics");
    }

    #[test]
    fn test_completions_bash() {
        let result = run_omg(&["completions", "bash", "--stdout"]);
        result.assert_success();
        // Should generate bash completion script
        assert!(!result.stdout.is_empty());
    }

    #[test]
    fn test_completions_fish() {
        let result = run_omg(&["completions", "fish", "--stdout"]);
        result.assert_success();
        assert!(!result.stdout.is_empty());
    }

    #[test]
    fn test_completions_powershell() {
        let result = run_omg(&["completions", "powershell", "--stdout"]);
        result.assert_success();
        assert!(!result.stdout.is_empty());
    }

    #[test]
    fn redirected_completion_install_output_has_no_ansi() {
        let home = tempfile::TempDir::new().expect("temporary home");
        let result = run_omg_with_env(
            &["completions", "bash"],
            &[("HOME", home.path().to_str().expect("UTF-8 temporary path"))],
        );
        result.assert_success();
        result.assert_no_ansi();
        assert!(
            home.path()
                .join(".local/share/bash-completion/completions/omg")
                .is_file()
        );
    }

    #[test]
    fn test_generate_man_help() {
        let result = run_omg(&["generate-man", "--help"]);
        result.assert_success();
    }

    #[test]
    fn test_diff_help() {
        let result = run_omg(&["diff", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("diff");
    }
}

// ===================
// ENTERPRISE & FLEET
// ===================

mod enterprise_tests {
    use super::*;

    #[test]
    fn test_fleet_help() {
        let result = run_omg(&["fleet", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("fleet");
    }

    #[test]
    fn test_enterprise_help() {
        let result = run_omg(&["enterprise", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("enterprise");
    }
}

// ==============
// META COMMANDS
// ==============

mod meta_tests {
    use super::*;

    #[test]
    fn test_self_update_help() {
        let result = run_omg(&["self-update", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("update");
    }

    // REMOVED (WRONG-CONTRACT): `self-update --check` — there is no --check flag
    // (src/cli/args.rs:484-491), so this gated test failed whenever network tests
    // were enabled. The downgrade-protection replacement lives in
    // e2e_system_commands.rs::test_self_update_downgrade_protection.

    #[test]
    fn test_init_help() {
        let result = run_omg(&["init", "--help"]);
        result.assert_success();
        result.assert_stdout_contains("init");
    }
}

// ===================
// PACKAGE OPERATIONS
// ===================

#[cfg(feature = "arch")]
mod package_ops_tests {
    use super::*;

    // WRONG-CONTRACT FIX: `clean` takes flags (--cache/--orphans), not positional
    // subcommands (src/cli/args.rs:172-189). The old invocations were clap errors
    // whose message happened to contain "cache"/"orphans", so they passed vacuously.
    #[test]
    #[cfg(feature = "arch")] // Cache cleanup support and this preview are Arch-specific.
    fn test_clean_cache_dry_run() {
        let result = run_omg(&["clean", "--cache", "--dry-run"]);
        result.assert_success();
        result.assert_no_ansi();
        let output = result.stdout;
        assert!(
            output.contains("Would clear package cache"),
            "Dry run must preview the cache cleanup: {output}"
        );
        assert!(
            output.contains("No changes made (dry run)"),
            "Dry run must promise no mutations: {output}"
        );
    }

    #[test]
    #[cfg(feature = "arch")] // This fixture supplies Arch orphan metadata.
    fn test_clean_orphans_dry_run() {
        let result = run_omg(&["clean", "--orphans", "--dry-run"]);
        result.assert_success();
        result.assert_no_ansi();
        let output = result.stdout;
        assert!(
            output.contains("Would remove") && output.to_lowercase().contains("orphan"),
            "Dry run must preview orphan removal: {output}"
        );
        assert!(
            output.contains("No changes made (dry run)"),
            "Dry run must promise no mutations: {output}"
        );
    }
}

// ==============
// ERROR HANDLING
// ==============

mod error_tests {
    use super::*;

    #[test]
    fn test_invalid_command() {
        let result = run_omg(&["this-command-does-not-exist"]);
        assert!(!result.success, "Should fail for invalid command");
        let combined = result.combined_output();
        assert!(
            combined.contains("error")
                || combined.contains("not found")
                || combined.contains("unrecognized"),
            "Should show error message"
        );
    }

    #[test]
    fn test_invalid_subcommand() {
        let result = run_omg(&["audit", "invalid-subcommand"]);
        assert!(!result.success);
    }

    #[test]
    fn test_missing_required_arg() {
        let result = run_omg(&["info"]);
        assert!(!result.success, "Should fail when package name missing");
    }

    // RE-CONTRACTED: --json/--quiet are GLOBAL args (src/cli/args.rs:24-29), not
    // conflicting search flags — the invocation is valid and must exit 0 with
    // machine-readable JSON on stdout.
    #[test]
    fn test_global_json_flag_emits_json() {
        let result = run_omg(&["search", "--json", "--quiet", "test"]);
        result.assert_success();
        let parsed: serde_json::Value =
            serde_json::from_str(result.stdout.trim()).expect("search --json must emit valid JSON");
        assert!(
            parsed.is_array(),
            "search --json must emit a JSON array, got: {parsed}"
        );
    }
}

// =======================
// CROSS-COMMAND WORKFLOWS
// =======================

mod workflow_tests {
    use super::*;

    #[test]
    #[cfg(feature = "arch")] // This fixture resolves git through the Arch fast info path.
    fn test_search_then_info() {
        // Workflow: search for package, then get info
        let search_result = run_omg(&["search", "git"]);
        search_result.assert_success();

        let info_result = run_omg(&["info", "git"]);
        info_result.assert_success();

        let verbose_info = run_omg(&["--verbose", "info", "git"]);
        verbose_info.assert_success();
        verbose_info.assert_no_ansi();
    }

    #[test]
    fn test_status_then_explicit() {
        // Workflow: check status, list explicit packages
        let status_result = run_omg(&["status"]);
        status_result.assert_success();
        status_result.assert_no_ansi();

        let verbose_status = run_omg(&["--verbose", "status"]);
        verbose_status.assert_success();
        verbose_status.assert_no_ansi();

        let explicit_result = run_omg(&["explicit"]);
        explicit_result.assert_success();
        explicit_result.assert_no_ansi();
    }
}
