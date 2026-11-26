//! `omg outdated` - Show what packages would be updated

use anyhow::Result;
use serde::Serialize;

use crate::cli::tea::{Cmd, UpdateType};
use crate::core::packages::PackageService;
use crate::package_managers::get_package_manager;
use crate::package_managers::types::update_package_name;

#[derive(Debug, Serialize)]
pub struct OutdatedPackage {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    pub current_version: String,
    pub new_version: String,
    pub update_type: UpdateType,
    pub repo: String,
}

impl OutdatedPackage {
    fn package_label(&self) -> std::borrow::Cow<'_, str> {
        update_package_name(&self.name, self.architecture.as_deref())
    }
}

struct UpdateGroups<'a> {
    major: Vec<&'a OutdatedPackage>,
    minor: Vec<&'a OutdatedPackage>,
    patch: Vec<&'a OutdatedPackage>,
    unknown: Vec<&'a OutdatedPackage>,
}

impl UpdateGroups<'_> {
    fn total(&self) -> usize {
        self.major.len() + self.minor.len() + self.patch.len() + self.unknown.len()
    }
}

fn group_updates(updates: &[OutdatedPackage]) -> UpdateGroups<'_> {
    let mut groups = UpdateGroups {
        major: Vec::new(),
        minor: Vec::new(),
        patch: Vec::new(),
        unknown: Vec::new(),
    };
    for update in updates {
        match update.update_type {
            UpdateType::Major => groups.major.push(update),
            UpdateType::Minor => groups.minor.push(update),
            UpdateType::Patch => groups.patch.push(update),
            UpdateType::Unknown => groups.unknown.push(update),
        }
    }
    groups
}

/// Show outdated packages
pub async fn run(json: bool) -> Result<()> {
    use crate::cli::components::Components;

    // SECURITY: This command has no string inputs, but we validate environment state
    if !json {
        crate::cli::packages::execute_cmd(Components::loading("Checking for updates"))?;
    }

    let pm = get_package_manager()?;
    let service = PackageService::builder(pm).without_history().build()?;
    let updates = service.list_updates().await?;

    if updates.is_empty() {
        if json {
            println!("[]");
        } else {
            crate::cli::packages::execute_cmd(Components::up_to_date())?;
        }
        return Ok(());
    }

    let mut outdated: Vec<OutdatedPackage> = updates
        .into_iter()
        .map(|u| OutdatedPackage {
            update_type: classify_update(&u.old_version, &u.new_version),
            name: u.name,
            architecture: u.architecture,
            current_version: u.old_version,
            new_version: u.new_version,
            repo: u.repo,
        })
        .collect();

    outdated.sort_by(|a, b| (&a.name, &a.architecture).cmp(&(&b.name, &b.architecture)));

    if json {
        println!("{}", serde_json::to_string_pretty(&outdated)?);
        return Ok(());
    }

    let groups = group_updates(&outdated);

    let mut commands = vec![
        Cmd::spacer(),
        Cmd::header(
            "Available Updates",
            format!("{} packages total", groups.total()),
        ),
        Cmd::spacer(),
    ];

    if !groups.major.is_empty() {
        let major_shown = groups.major.len().min(15);
        commands.push(Cmd::card(
            "Major Updates (may have breaking changes)".to_string(),
            groups
                .major
                .iter()
                .take(major_shown)
                .map(|p| {
                    format!(
                        "{} {} → {} ({})",
                        p.package_label(),
                        p.current_version,
                        p.new_version,
                        p.repo
                    )
                })
                .collect(),
        ));
        if groups.major.len() > 15 {
            use crate::cli::tea::{StyledTextConfig, TextStyle};
            commands.push(Cmd::styled_text(StyledTextConfig {
                text: format!("... and {} more major updates", groups.major.len() - 15),
                style: TextStyle::Muted,
            }));
        }
        commands.push(Cmd::spacer());
    }

    // Minor updates
    if !groups.minor.is_empty() {
        let minor_count = groups.minor.len().min(10);
        commands.push(Cmd::card(
            "Minor Updates (new features)".to_string(),
            groups
                .minor
                .iter()
                .take(minor_count)
                .map(|p| {
                    format!(
                        "{} {} → {}",
                        p.package_label(),
                        p.current_version,
                        p.new_version
                    )
                })
                .collect(),
        ));

        if groups.minor.len() > 10 {
            use crate::cli::tea::{StyledTextConfig, TextStyle};
            commands.push(Cmd::styled_text(StyledTextConfig {
                text: format!("... and {} more minor updates", groups.minor.len() - 10),
                style: TextStyle::Muted,
            }));
        }
        commands.push(Cmd::spacer());
    }

    // Patch updates
    if !groups.patch.is_empty() {
        let patch_count = groups.patch.len().min(5);
        commands.push(Cmd::card(
            "Patch Updates (bug fixes)".to_string(),
            groups
                .patch
                .iter()
                .take(patch_count)
                .map(|p| {
                    format!(
                        "{} {} → {}",
                        p.package_label(),
                        p.current_version,
                        p.new_version
                    )
                })
                .collect(),
        ));

        if groups.patch.len() > 5 {
            use crate::cli::tea::{StyledTextConfig, TextStyle};
            commands.push(Cmd::styled_text(StyledTextConfig {
                text: format!("... and {} more patch updates", groups.patch.len() - 5),
                style: TextStyle::Muted,
            }));
        }
        commands.push(Cmd::spacer());
    }

    if !groups.unknown.is_empty() {
        let unknown_shown = groups.unknown.len().min(15);
        commands.push(Cmd::card(
            "Other Updates (unclassified versions)".to_string(),
            groups
                .unknown
                .iter()
                .take(unknown_shown)
                .map(|package| {
                    format!(
                        "{} {} → {} ({})",
                        package.package_label(),
                        package.current_version,
                        package.new_version,
                        package.repo
                    )
                })
                .collect(),
        ));
        if groups.unknown.len() > 15 {
            use crate::cli::tea::{StyledTextConfig, TextStyle};
            commands.push(Cmd::styled_text(StyledTextConfig {
                text: format!("... and {} more other updates", groups.unknown.len() - 15),
                style: TextStyle::Muted,
            }));
        }
        commands.push(Cmd::spacer());
    }

    // Summary
    commands.push(Components::kv_list(
        Some("Summary"),
        vec![
            ("Major Updates", &groups.major.len().to_string()),
            ("Minor Updates", &groups.minor.len().to_string()),
            ("Patch Updates", &groups.patch.len().to_string()),
            ("Other Updates", &groups.unknown.len().to_string()),
        ],
    ));
    commands.push(Cmd::spacer());

    // Actions
    commands.push(Cmd::info("Run 'omg update' to update all packages"));

    crate::cli::packages::execute_cmd(Cmd::batch(commands))?;

    Ok(())
}

/// Classify an update by comparing the parsed versions; falls back to
/// [`UpdateType::Unknown`] when either side is not valid semver.
fn classify_update(old: &str, new: &str) -> UpdateType {
    UpdateType::from_versions(old, new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_versions_remain_visible_in_output_groups() {
        let packages = vec![OutdatedPackage {
            name: "rolling-package".to_string(),
            architecture: None,
            current_version: "release-a".to_string(),
            new_version: "release-b".to_string(),
            update_type: UpdateType::Unknown,
            repo: "custom".to_string(),
        }];

        let groups = group_updates(&packages);

        assert_eq!(groups.unknown.len(), 1);
        assert_eq!(groups.total(), packages.len());
        assert_eq!(groups.unknown[0].package_label(), "rolling-package");
        assert!(
            serde_json::to_value(groups.unknown[0])
                .expect("JSON package without an architecture")
                .get("architecture")
                .is_none()
        );
    }

    #[test]
    fn multilib_rows_keep_their_names_in_json_and_distinct_terminal_labels() {
        for (architecture, label) in [("i686", "lib.i686"), ("x86_64", "lib.x86_64")] {
            let package = OutdatedPackage {
                name: "lib".into(),
                architecture: Some(architecture.into()),
                current_version: "1-1".into(),
                new_version: "2-1".into(),
                update_type: UpdateType::Unknown,
                repo: "updates".into(),
            };
            assert_eq!(package.package_label(), label);
            let row = serde_json::to_value(package).expect("multilib update row");
            assert_eq!(row["name"], "lib");
            assert_eq!(row["architecture"], architecture);
        }
    }

    #[test]
    fn classify_update_uses_version_change_not_cve_status() {
        assert!(matches!(
            classify_update("1.0.0", "2.0.0"),
            UpdateType::Major
        ));
        assert!(matches!(
            classify_update("1.0.0", "1.1.0"),
            UpdateType::Minor
        ));
        assert!(matches!(
            classify_update("1.0.0", "1.0.1"),
            UpdateType::Patch
        ));
    }
}
