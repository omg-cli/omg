//! Human approval for package contents that acquire privileges at install time.
//!
//! Pacman install hooks can run before/after extraction, upgrade, and removal:
//! https://man.archlinux.org/man/PKGBUILD.5#INSTALL/UPGRADE/REMOVE_SCRIPTING

use anyhow::Result;
use std::fmt::Write as _;

use super::artifact_inspector::ArtifactInspection;

const MAX_PROMPT_BYTES: usize = 32 * 1024;

pub(crate) fn exception_prompt(inspections: &[ArtifactInspection]) -> Result<Option<String>> {
    let exceptional = inspections
        .iter()
        .filter(|inspection| inspection.requires_exception())
        .collect::<Vec<_>>();
    if exceptional.is_empty() {
        return Ok(None);
    }

    let mut prompt =
        String::from("AUR package contents request exceptional install-time privileges:\n");
    for inspection in exceptional {
        write!(
            prompt,
            "\n{} {} [{}]",
            crate::cli::style::sanitize_terminal_text(&inspection.package_name),
            crate::cli::style::sanitize_terminal_text(&inspection.package_version),
            inspection.archive_sha256
        )?;
        if let Some(hook) = &inspection.install_hook {
            write!(prompt, "\n  .INSTALL hook sha256={hook}")?;
        }
        for file in &inspection.privileged_files {
            let path = crate::cli::style::sanitize_terminal_text(&file.path);
            write!(prompt, "\n  {path} mode={:04o}", file.mode & 0o7777)?;
            if let Some(capability) = &file.capability {
                write!(prompt, " capability={capability}")?;
            }
        }
    }
    prompt.push_str("\n\nInstall these exact inspected archives?");
    anyhow::ensure!(
        prompt.len() <= MAX_PROMPT_BYTES,
        "AUR privilege summary exceeds display limit"
    );
    Ok(Some(prompt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package_managers::aur::artifact_inspector::{
        ArtifactInspection, INSPECTION_POLICY_VERSION, PrivilegedFile,
    };

    fn inspection() -> ArtifactInspection {
        ArtifactInspection {
            policy_version: INSPECTION_POLICY_VERSION,
            archive_sha256: "a".repeat(64),
            package_name: "demo".into(),
            package_version: "1-1".into(),
            package_base: "demo".into(),
            architecture: "x86_64".into(),
            member_count: 4,
            executable_files: Vec::new(),
            privileged_files: Vec::new(),
            install_hook: None,
            paired_build_reasons: Vec::new(),
        }
    }

    #[test]
    fn ordinary_archive_needs_no_exception_prompt() -> Result<()> {
        assert!(exception_prompt(&[inspection()])?.is_none());
        Ok(())
    }

    #[test]
    fn prompt_names_exact_hook_and_privileged_file() -> Result<()> {
        let mut inspection = inspection();
        inspection.install_hook = Some("b".repeat(64));
        inspection.privileged_files.push(PrivilegedFile {
            path: "usr/bin/demo".into(),
            mode: 0o4755,
            capability: Some("010203".into()),
        });
        let prompt = exception_prompt(&[inspection])?.expect("exception prompt");
        assert!(prompt.contains(".INSTALL hook sha256="));
        assert!(prompt.contains("usr/bin/demo mode=4755"));
        assert!(prompt.contains(&"a".repeat(64)));
        assert_eq!(
            prompt,
            format!(
                "AUR package contents request exceptional install-time privileges:\n\ndemo 1-1 [{}]\n  .INSTALL hook sha256={}\n  usr/bin/demo mode=4755 capability=010203\n\nInstall these exact inspected archives?",
                "a".repeat(64),
                "b".repeat(64)
            )
        );
        Ok(())
    }
}
