//! Read-only portable intent planning. Never installs, sources, or copies files.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

const TARGETS: &[&str] = &[
    "arch-x86_64",
    "debian-x86_64",
    "ubuntu-x86_64",
    "fedora-x86_64",
    "macos-aarch64",
];

#[derive(Deserialize, Serialize)]
struct Project {
    environment: Manifest,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    #[serde(default)]
    tools: BTreeSet<String>,
    #[serde(default)]
    runtimes: BTreeMap<String, String>,
    #[serde(default)]
    packages: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(default)]
    dotfiles: BTreeMap<String, String>,
}

/// Desired mappings only: no installed-state, availability or lock resolution claim.
#[derive(Debug, Serialize)]
pub struct EnvironmentPlan {
    pub schema_version: u32,
    pub target: String,
    pub packages: BTreeMap<String, String>,
    pub unmapped_tools: Vec<String>,
    pub runtimes: BTreeMap<String, String>,
    pub dotfiles: BTreeMap<String, String>,
    pub notices: Vec<&'static str>,
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.starts_with(|c: char| c.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._+-".contains(&c))
}

fn relative_file(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.contains(['\\', ':', '~'])
        && !value.chars().any(char::is_control)
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// Parse the environment namespace while preserving existing project namespaces.
pub fn plan(content: &str, target: &str) -> Result<EnvironmentPlan> {
    ensure!(
        content.len() <= 262_144,
        "Environment manifest exceeds 256 KiB"
    );
    ensure!(
        TARGETS.contains(&target),
        "Unsupported environment target: {target}"
    );
    // Do not echo parser source excerpts: a project file can contain private data.
    let project: Project = toml::from_str(content)
        .map_err(|_| anyhow::anyhow!("Invalid .omg.toml environment manifest"))?;
    let manifest = project.environment;
    ensure!(
        manifest.schema_version == 1,
        "Unsupported environment schema"
    );
    ensure!(manifest.tools.len() <= 512, "Too many environment tools");
    ensure!(manifest.dotfiles.len() <= 128, "Too many dotfile mappings");
    for name in &manifest.tools {
        ensure!(identifier(name), "Invalid tool identifier");
    }
    for (runtime, version) in &manifest.runtimes {
        ensure!(identifier(runtime), "Invalid runtime identifier");
        ensure!(
            !version.is_empty() && version.len() <= 128 && !version.chars().any(char::is_control),
            "Invalid runtime requirement"
        );
    }
    for (platform, mappings) in &manifest.packages {
        ensure!(
            TARGETS.contains(&platform.as_str()),
            "Unsupported mapping target"
        );
        for (alias, package) in mappings {
            ensure!(
                manifest.tools.contains(alias),
                "Package mapping references an undeclared tool"
            );
            // Deliberately accepts only simple native package names in this version.
            ensure!(identifier(package), "Invalid native package name");
        }
    }
    let mut destinations = BTreeSet::new();
    for (source, destination) in &manifest.dotfiles {
        ensure!(
            relative_file(source),
            "Dotfile source must be a relative file path"
        );
        ensure!(
            relative_file(destination),
            "Dotfile destination must be relative to the home directory"
        );
        ensure!(
            destinations.insert(destination),
            "Multiple dotfiles target the same destination"
        );
    }
    let packages = manifest.packages.get(target).cloned().unwrap_or_default();
    let unmapped_tools = manifest
        .tools
        .iter()
        .filter(|name| !packages.contains_key(*name))
        .cloned()
        .collect();
    Ok(EnvironmentPlan {
        schema_version: 1,
        target: target.to_string(),
        packages,
        unmapped_tools,
        runtimes: manifest.runtimes,
        dotfiles: manifest.dotfiles,
        notices: vec![
            "Read-only intent preview: no packages installed and no files copied.",
            "Package availability, runtime compatibility and installed state are not checked.",
            "Dotfile existence, permissions and destination conflicts require later review.",
            "This is not an omg.lock resolution or an executable migration recipe.",
        ],
    })
}

/// Machine-readable output avoids rendering untrusted text as terminal controls.
pub fn to_json(content: &str, target: &str) -> Result<String> {
    serde_json::to_string_pretty(&plan(content, target)?)
        .context("Cannot serialize environment plan")
}

/// Export observed names as intent, mapped only to the caller-declared source.
/// The old lock schema cannot establish its capture platform or exact packages.
pub fn from_snapshot(
    runtimes: BTreeMap<String, String>,
    packages: Vec<String>,
    source_target: &str,
) -> Result<String> {
    ensure!(
        TARGETS.contains(&source_target),
        "Unsupported source target"
    );
    let tools: BTreeSet<String> = packages.into_iter().collect();
    let mappings = tools
        .iter()
        .map(|name| (name.clone(), name.clone()))
        .collect();
    let project = Project {
        environment: Manifest {
            schema_version: 1,
            tools,
            runtimes,
            packages: BTreeMap::from([(source_target.to_string(), mappings)]),
            dotfiles: BTreeMap::new(),
        },
    };
    let content =
        toml::to_string_pretty(&project).context("Cannot serialize environment manifest")?;
    // Apply the same bounds and identifier rules as a handwritten manifest.
    plan(&content, source_target)?;
    Ok(format!(
        "# Starter intent from omg.lock; review before use.\n\
         # Source platform is user-declared; package versions are not captured.\n\
         # Other platforms require explicit mappings. No dotfiles or secrets exported.\n\n{content}"
    ))
}

#[cfg(test)]
mod tests {
    use super::plan;

    #[test]
    fn snapshot_export_roundtrips_without_guessing_other_platforms() {
        let content = super::from_snapshot(
            std::collections::BTreeMap::from([("node".into(), "22.1.0".into())]),
            vec!["git".into(), "git".into()],
            "arch-x86_64",
        )
        .unwrap();
        let source = plan(&content, "arch-x86_64").unwrap();
        assert_eq!(source.packages.len(), 1);
        assert_eq!(source.packages["git"], "git");
        assert!(source.dotfiles.is_empty());
        let destination = plan(&content, "ubuntu-x86_64").unwrap();
        assert!(destination.packages.is_empty());
        assert_eq!(destination.unmapped_tools, vec!["git"]);
        assert_eq!(destination.runtimes["node"], "22.1.0");
    }

    #[test]
    fn snapshot_export_refuses_unsafe_names_and_unknown_platforms() {
        for package in ["--root", "a\nmalicious", "../path"] {
            assert!(
                super::from_snapshot(
                    std::collections::BTreeMap::new(),
                    vec![package.into()],
                    "arch-x86_64"
                )
                .is_err()
            );
        }
        assert!(
            super::from_snapshot(std::collections::BTreeMap::new(), vec![], "unknown").is_err()
        );
    }

    const MANIFEST: &str = r#"
[scripts]
test = "cargo test"
[environment]
schema_version = 1
tools = ["git", "compiler"]
[environment.runtimes]
node = "22"
[environment.packages.ubuntu-x86_64]
git = "git"
compiler = "build-essential"
[environment.packages.arch-x86_64]
git = "git"
compiler = "base-devel"
[environment.dotfiles]
"dotfiles/editor.toml" = ".config/editor/config.toml"
"#;

    #[test]
    fn explicit_mappings_differ_without_claiming_installed_state() {
        let ubuntu = plan(MANIFEST, "ubuntu-x86_64").unwrap();
        let arch = plan(MANIFEST, "arch-x86_64").unwrap();
        assert_eq!(ubuntu.packages["compiler"], "build-essential");
        assert_eq!(arch.packages["compiler"], "base-devel");
        assert_eq!(ubuntu.runtimes["node"], "22");
        assert!(ubuntu.unmapped_tools.is_empty());
        assert_eq!(ubuntu.dotfiles.len(), 1);
    }

    #[test]
    fn missing_target_never_falls_back_to_package_names() {
        let result = plan(MANIFEST, "fedora-x86_64").unwrap();
        assert!(result.packages.is_empty());
        assert_eq!(result.unmapped_tools, vec!["compiler", "git"]);
    }

    #[test]
    fn rejects_unknown_schema_fields_and_unsupported_targets() {
        assert!(
            plan(
                &MANIFEST.replace("schema_version = 1", "schema_version = 2"),
                "ubuntu-x86_64"
            )
            .is_err()
        );
        assert!(plan(&MANIFEST.replace("tools =", "toolz ="), "ubuntu-x86_64").is_err());
        assert!(plan(MANIFEST, "nixos-x86_64").is_err());
        assert!(plan("[scripts]\ntest = 'true'", "ubuntu-x86_64").is_err());
    }

    #[test]
    fn rejects_unsafe_dotfile_paths_even_in_unselected_configuration() {
        for bad in [
            "../escape",
            "/etc/passwd",
            "C:/secret",
            "a/../secret",
            "a\\secret",
            "~/secret",
        ] {
            let input = MANIFEST.replace(".config/editor/config.toml", bad);
            assert!(plan(&input, "ubuntu-x86_64").is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn rejects_option_injection_and_terminal_controls() {
        assert!(
            plan(
                &MANIFEST.replace("build-essential", "--root=/tmp"),
                "ubuntu-x86_64"
            )
            .is_err()
        );
        assert!(
            plan(
                &MANIFEST.replace("node = \"22\"", "node = \"\\u001b[2J\""),
                "ubuntu-x86_64"
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_conflicting_destinations_and_unused_aliases() {
        let duplicate = MANIFEST.replace(
            "[environment.dotfiles]",
            "[environment.dotfiles]\n\"dotfiles/other\" = \".config/editor/config.toml\"",
        );
        assert!(plan(&duplicate, "ubuntu-x86_64").is_err());
        let extra = MANIFEST.replace("compiler = \"base-devel\"", "unknown = \"base-devel\"");
        assert!(plan(&extra, "ubuntu-x86_64").is_err());
    }

    #[test]
    fn input_bound_and_deterministic_output() {
        assert!(plan(&" ".repeat(262_145), "ubuntu-x86_64").is_err());
        let a = serde_json::to_string(&plan(MANIFEST, "ubuntu-x86_64").unwrap()).unwrap();
        let b = serde_json::to_string(&plan(MANIFEST, "ubuntu-x86_64").unwrap()).unwrap();
        assert_eq!(a, b);
    }
}
