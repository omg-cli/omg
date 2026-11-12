//! Human approval for package contents that acquire privileges at install time.
//!
//! Pacman install hooks can run before/after extraction, upgrade, and removal:
//! https://man.archlinux.org/man/PKGBUILD.5#INSTALL/UPGRADE/REMOVE_SCRIPTING

use anyhow::Result;
use std::fmt::Write as _;

use super::artifact_inspector::ArtifactInspection;

const MAX_PROMPT_BYTES: usize = 32 * 1024;

#[derive(Debug, Default)]
struct Prompt(String);

impl std::fmt::Write for Prompt {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        if value.len() > MAX_PROMPT_BYTES - self.0.len() {
            return Err(std::fmt::Error);
        }
        self.0.push_str(value);
        Ok(())
    }
}

pub(crate) fn exception_prompt(inspections: &[ArtifactInspection]) -> Result<Option<String>> {
    if !inspections
        .iter()
        .any(ArtifactInspection::requires_exception)
    {
        return Ok(None);
    }

    let mut prompt = Prompt::default();
    let formatted = (|| -> std::fmt::Result {
        prompt.write_str("AUR package contents request exceptional install-time privileges:\n")?;
        for inspection in inspections
            .iter()
            .filter(|inspection| inspection.requires_exception())
        {
            write!(
                prompt,
                "\n{} {} [{}]",
                crate::cli::style::display_terminal_text(&inspection.package_name),
                crate::cli::style::display_terminal_text(&inspection.package_version),
                inspection.archive_sha256
            )?;
            if let Some(hook) = &inspection.install_hook {
                write!(prompt, "\n  .INSTALL hook sha256={hook}")?;
            }
            for file in &inspection.privileged_files {
                let path = crate::cli::style::display_terminal_text(&file.path);
                write!(prompt, "\n  {path} mode={:04o}", file.mode & 0o7777)?;
                if let Some(capability) = &file.capability {
                    write!(prompt, " capability={capability}")?;
                }
            }
        }
        prompt.write_str("\n\nInstall these exact inspected archives?")
    })();
    anyhow::ensure!(
        formatted.is_ok(),
        "AUR privilege summary exceeds display limit"
    );
    Ok(Some(prompt.0))
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
    fn many_privileged_outputs_cannot_truncate_the_approval_summary() {
        let inspections: Vec<_> = (0..512)
            .map(|index| {
                let mut output = inspection();
                output.package_name = format!("demo-{index}");
                output.install_hook = Some("b".repeat(64));
                output
            })
            .collect();
        let error = exception_prompt(&inspections)
            .expect_err("all requested outputs must fit before approval can be offered");
        assert_eq!(
            error.to_string(),
            "AUR privilege summary exceeds display limit"
        );
    }

    #[test]
    fn prompt_buffer_refuses_overflow_without_extending_it() {
        let mut prompt = Prompt::default();
        prompt
            .write_str(&"x".repeat(MAX_PROMPT_BYTES - 2))
            .expect("text within budget");
        prompt
            .write_char('é')
            .expect("UTF-8 text exactly fills byte budget");
        let capacity = prompt.0.capacity();
        assert!(prompt.write_char('x').is_err());
        assert!(prompt.write_str("é").is_err());
        assert_eq!(prompt.0.len(), MAX_PROMPT_BYTES);
        assert_eq!(prompt.0.capacity(), capacity);
        assert!(prompt.0.ends_with('é'));
    }

    #[test]
    fn exception_prompt_enforces_exact_budget_and_streams_sanitized_paths() {
        let mut inspection = inspection();
        inspection.privileged_files.push(PrivilegedFile {
            path: "usr/bin/marker".to_owned(),
            mode: 0o4755,
            capability: Some(String::new()),
        });
        let original = exception_prompt(std::slice::from_ref(&inspection))
            .expect("ordinary privilege summary formats")
            .expect("set-ID file needs a summary");
        let room = MAX_PROMPT_BYTES - original.len();
        inspection.privileged_files[0].capability = Some("a".repeat(room));
        let exact = exception_prompt(std::slice::from_ref(&inspection))
            .expect("exactly bounded privilege summary formats")
            .expect("set-ID file needs a summary");
        assert_eq!(exact.len(), MAX_PROMPT_BYTES);
        inspection.privileged_files[0]
            .capability
            .as_mut()
            .expect("fixture capability")
            .push('a');
        let error = exception_prompt(std::slice::from_ref(&inspection))
            .expect_err("one additional byte must refuse the summary");
        assert_eq!(
            error.to_string(),
            "AUR privilege summary exceeds display limit"
        );

        inspection.privileged_files[0].capability = None;
        inspection.privileged_files[0].path = "usr/\u{1b}[31mbin/\u{202e}marker\n".to_owned();
        let summary = exception_prompt(&[inspection])
            .expect("sanitized summary formats")
            .expect("set-ID summary");
        assert!(summary.contains("usr/[31mbin/marker mode=4755"));
        assert!(!summary.contains(['\u{1b}', '\u{202e}']));
        assert_eq!(
            summary.matches('\n').count(),
            original.matches('\n').count()
        );
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
        inspection.privileged_files.push(PrivilegedFile {
            path: "usr/bin/group-tool".into(),
            mode: 0o2755,
            capability: None,
        });
        let prompt = exception_prompt(&[inspection])?.expect("exception prompt");
        assert!(prompt.contains(".INSTALL hook sha256="));
        assert!(prompt.contains("usr/bin/demo mode=4755"));
        assert!(prompt.contains(&"a".repeat(64)));
        assert_eq!(
            prompt,
            format!(
                "AUR package contents request exceptional install-time privileges:\n\ndemo 1-1 [{}]\n  .INSTALL hook sha256={}\n  usr/bin/demo mode=4755 capability=010203\n  usr/bin/group-tool mode=2755\n\nInstall these exact inspected archives?",
                "a".repeat(64),
                "b".repeat(64)
            )
        );
        Ok(())
    }
}
