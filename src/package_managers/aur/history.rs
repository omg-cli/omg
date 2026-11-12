//! AUR history selection with one budget from clone through checkout.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::process::Command;
use tokio::time::Instant;

use super::git_process::{GitLimits, run_bounded_git};

// Application compatibility limits, shared across every operation in one rollback.
const HISTORY_DURATION: Duration = Duration::from_mins(15);
const HISTORY_LIMITS: HistoryLimits = HistoryLimits {
    commits: 10_000,
    show_bytes: 16 * 1024 * 1024,
    total_show_bytes: 64 * 1024 * 1024,
    git: GitLimits {
        stdout_bytes: 1024 * 1024,
        stderr_bytes: 1024 * 1024,
        staging_bytes: 2 * 1024 * 1024 * 1024,
        staging_entries: 200_000,
        poll_interval: Duration::from_millis(250),
    },
};

#[derive(Clone, Copy)]
struct HistoryLimits {
    commits: usize,
    show_bytes: u64,
    total_show_bytes: u64,
    git: GitLimits,
}

fn git_command() -> Command {
    let mut command = Command::new("git");
    command.env("GIT_TERMINAL_PROMPT", "0").stdin(Stdio::null());
    command
}

fn history_log_command(directory: &Path, records: usize) -> Command {
    let mut command = git_command();
    command
        .arg("-C")
        .arg(directory)
        .args(["log", "--no-show-signature", "--format=%H"])
        .arg(format!("--max-count={records}"));
    command
}

fn stderr_text(output: &std::process::Output) -> String {
    crate::cli::style::sanitize_terminal_text(&String::from_utf8_lossy(&output.stderr))
}

pub(super) async fn checkout_version(
    url: &str,
    directory: &Path,
    base: &str,
    version: &str,
) -> Result<()> {
    checkout_version_with_limits(
        url,
        directory,
        base,
        version,
        HISTORY_LIMITS,
        Instant::now() + HISTORY_DURATION,
    )
    .await
}

async fn checkout_version_with_limits(
    url: &str,
    directory: &Path,
    base: &str,
    version: &str,
    limits: HistoryLimits,
    deadline: Instant,
) -> Result<()> {
    let mut clone = git_command();
    clone
        .args(["clone", "--filter=blob:none", "--", url])
        .arg(directory);
    let clone = run_bounded_git(&mut clone, directory, limits.git, deadline)
        .await
        .map_err(|error| {
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|cause| cause.kind() == std::io::ErrorKind::NotFound)
            {
                error.context("git is required for AUR version rollback")
            } else {
                error.context(format!("Failed to clone AUR history for '{base}'"))
            }
        })?;
    anyhow::ensure!(
        clone.status.success(),
        "Failed to clone AUR history for '{base}': {}",
        stderr_text(&clone).trim()
    );

    let log_records = limits
        .commits
        .checked_add(1)
        .context("AUR history commit limit overflowed")?;
    let log_bytes = u64::try_from(log_records)
        .ok()
        .and_then(|count| count.checked_mul(65))
        .context("AUR history log limit overflowed")?;
    let mut log = history_log_command(directory, log_records);
    let log = run_bounded_git(
        &mut log,
        directory,
        GitLimits {
            stdout_bytes: log_bytes,
            ..limits.git
        },
        deadline,
    )
    .await
    .context("Failed to list AUR repository history")?;
    anyhow::ensure!(
        log.status.success(),
        "Failed to list AUR history for '{base}': {}",
        stderr_text(&log).trim()
    );
    let shas =
        std::str::from_utf8(&log.stdout).context("AUR history contains invalid commit IDs")?;
    let mut total_show_bytes = 0u64;
    let mut matched_sha = None;
    for (index, sha) in shas.lines().enumerate() {
        anyhow::ensure!(
            matches!(sha.len(), 40 | 64) && sha.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "AUR history contains an invalid full commit ID"
        );
        anyhow::ensure!(
            index < limits.commits,
            "AUR history search reached its {}-commit budget before finding version {version} of '{base}'; restore a cached archive or inspect the repository manually",
            limits.commits
        );
        let remaining = limits
            .total_show_bytes
            .checked_sub(total_show_bytes)
            .context("AUR history cumulative metadata size overflowed")?;
        let mut show = git_command();
        show.arg("-C")
            .arg(directory)
            .args(["show", &format!("{sha}:.SRCINFO")]);
        let show = run_bounded_git(
            &mut show,
            directory,
            GitLimits { stdout_bytes: limits.show_bytes.min(remaining), ..limits.git },
            deadline,
        )
        .await
        .with_context(|| {
            format!(
                "Failed to read .SRCINFO from history within the {}-byte per-file and {}-byte cumulative metadata budgets; restore a cached archive or inspect the repository manually",
                limits.show_bytes, limits.total_show_bytes
            )
        })?;
        total_show_bytes = total_show_bytes
            .checked_add(
                u64::try_from(show.stdout.len())
                    .context("AUR history metadata length overflowed")?,
            )
            .context("AUR history cumulative metadata size overflowed")?;
        if !show.status.success() {
            continue;
        }
        let content = String::from_utf8_lossy(&show.stdout);
        if srcinfo_version(&content).as_deref() == Some(version) {
            matched_sha = Some(sha);
            break;
        }
    }
    let sha = matched_sha.with_context(|| historical_version_not_found_message(base, version))?;

    let mut checkout = git_command();
    checkout
        .arg("-C")
        .arg(directory)
        .args(["checkout", "--detach", sha]);
    let checkout = run_bounded_git(&mut checkout, directory, limits.git, deadline)
        .await
        .context("Failed to checkout historical commit")?;
    anyhow::ensure!(
        checkout.status.success(),
        "Failed to checkout commit {sha} of '{base}': {}",
        stderr_text(&checkout).trim()
    );
    Ok(())
}

pub(super) fn historical_version_not_found_message(base: &str, version: &str) -> String {
    format!(
        "version {version} of '{base}' was not found in the AUR git history (the repository may have been force-pushed since it was installed)"
    )
}

/// Extract the first recorded version fields without requiring modern .SRCINFO syntax.
pub(super) fn srcinfo_version(content: &str) -> Option<String> {
    let mut epoch: Option<&str> = None;
    let mut pkgver: Option<&str> = None;
    let mut pkgrel: Option<&str> = None;
    for line in content.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "epoch" if epoch.is_none() => epoch = Some(value.trim()),
            "pkgver" if pkgver.is_none() => pkgver = Some(value.trim()),
            "pkgrel" if pkgrel.is_none() => pkgrel = Some(value.trim()),
            _ => {}
        }
    }
    let prefix = epoch
        .filter(|value| !value.is_empty())
        .map_or_else(String::new, |value| format!("{value}:"));
    match (pkgver, pkgrel) {
        (Some(v), Some(r)) => Some(format!("{prefix}{v}-{r}")),
        (Some(v), None) => Some(format!("{prefix}{v}")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(directory: &Path, arguments: &[&str]) -> std::process::Output {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(directory)
            .args(arguments)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "OMG history fixture")
            .env("GIT_AUTHOR_EMAIL", "history@example.invalid")
            .env("GIT_COMMITTER_NAME", "OMG history fixture")
            .env("GIT_COMMITTER_EMAIL", "history@example.invalid")
            .output()
            .expect("Git is required for the history fixture");
        assert!(
            output.status.success(),
            "Git fixture {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn commit(directory: &Path, version: Option<&str>, marker: &str) {
        if let Some(version) = version {
            std::fs::write(
                directory.join(".SRCINFO"),
                format!(
                    "pkgbase = example\n\tpkgver = {version}\n\tpkgrel = 1\npkgname = example\n"
                ),
            )
            .expect("fixture metadata");
        } else {
            std::fs::remove_file(directory.join(".SRCINFO")).expect("remove fixture metadata");
        }
        std::fs::write(directory.join("marker"), marker).expect("fixture commit marker");
        git(directory, &["add", "--all"]);
        git(
            directory,
            &[
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "-m",
                marker,
            ],
        );
    }

    fn history_fixture() -> tempfile::TempDir {
        let repository = tempfile::tempdir().expect("isolated history fixture");
        git(
            repository.path(),
            &["init", "--quiet", "--initial-branch=main"],
        );
        commit(repository.path(), Some("1.0"), "oldest matching commit");
        commit(repository.path(), Some("1.0"), "newest matching commit");
        commit(repository.path(), None, "missing metadata");
        commit(repository.path(), Some("2.0"), "latest version");
        repository
    }

    fn fixture_url(repository: &Path) -> &str {
        repository.to_str().expect("fixture path must be UTF-8")
    }

    #[tokio::test]
    async fn failed_history_clone_reports_sanitized_repository_diagnostics() {
        let owner = tempfile::tempdir().expect("owned missing repository");
        let missing = owner.path().join("missing-repository\u{1b}[31m");
        let checkout = tempfile::tempdir().expect("owned failed checkout");
        let error = checkout_version(fixture_url(&missing), checkout.path(), "example", "1.0-1")
            .await
            .expect_err("a missing repository cannot produce a historical checkout");
        let diagnostic = error.to_string();
        assert!(
            diagnostic.contains("Failed to clone AUR history"),
            "{diagnostic}"
        );
        assert!(diagnostic.contains("missing-repository"), "{diagnostic}");
        assert!(
            !diagnostic.chars().any(char::is_control),
            "Git stderr must not control the review terminal: {diagnostic:?}"
        );
        assert!(!missing.exists());
        assert!(!checkout.path().join(".git").exists());
    }

    #[tokio::test]
    async fn empty_history_reports_log_failure_instead_of_an_absent_version() {
        let repository = tempfile::tempdir().expect("owned empty history");
        git(
            repository.path(),
            &["init", "--quiet", "--initial-branch=main"],
        );
        let checkout = tempfile::tempdir().expect("owned empty checkout");
        let error = checkout_version(
            fixture_url(repository.path()),
            checkout.path(),
            "example",
            "1.0-1",
        )
        .await
        .expect_err("an unborn branch cannot establish version absence");
        let diagnostic = error.to_string();
        assert!(
            diagnostic.contains("Failed to list AUR history"),
            "{diagnostic}"
        );
        assert!(!diagnostic.contains("was not found"), "{diagnostic}");
        assert!(!checkout.path().join("marker").exists());
        assert!(!repository.path().join("marker").exists());
    }

    #[test]
    fn missing_git_reports_the_required_tool_without_creating_a_checkout() {
        const TEST: &str = "package_managers::aur::history::tests::missing_git_reports_the_required_tool_without_creating_a_checkout";
        if crate::core::testing::run_isolated_test(TEST) {
            return;
        }
        let empty_path = tempfile::tempdir().expect("private empty executable path");
        let checkout = tempfile::tempdir().expect("owned missing-tool checkout");
        temp_env::with_var("PATH", Some(empty_path.path()), || {
            let error = tokio::runtime::Runtime::new()
                .expect("private history runtime")
                .block_on(checkout_version(
                    "/unused-local-history",
                    checkout.path(),
                    "example",
                    "1.0-1",
                ))
                .expect_err("rollback cannot continue without Git");
            assert!(
                error
                    .to_string()
                    .contains("git is required for AUR version rollback"),
                "{error:#}"
            );
            assert_eq!(
                error
                    .downcast_ref::<std::io::Error>()
                    .map(std::io::Error::kind),
                Some(std::io::ErrorKind::NotFound),
                "the missing executable cause must remain available to callers"
            );
        });
        assert_eq!(
            std::fs::read_dir(checkout.path())
                .expect("checkout inventory")
                .count(),
            0
        );
    }

    #[test]
    fn history_checkout_refuses_to_overwrite_untracked_content() {
        use std::os::unix::fs::PermissionsExt;

        const TEST: &str = "package_managers::aur::history::tests::history_checkout_refuses_to_overwrite_untracked_content";
        if crate::core::testing::run_isolated_test(TEST) {
            return;
        }
        let repository = tempfile::tempdir().expect("private historical repository");
        git(
            repository.path(),
            &["init", "--quiet", "--initial-branch=main"],
        );
        std::fs::write(
            repository.path().join("historical-only"),
            "old tracked content",
        )
        .expect("historical file");
        commit(repository.path(), Some("1.0"), "historical marker");
        std::fs::remove_file(repository.path().join("historical-only"))
            .expect("retire historical-only path from current tree");
        commit(repository.path(), Some("2.0"), "current marker");
        let actual_git = which::which("git").expect("real Git fixture executable");
        let programs = tempfile::tempdir().expect("private Git wrapper directory");
        let wrapper = programs.path().join("git");
        std::fs::write(
            &wrapper,
            "#!/bin/sh\nif [ \"$1\" = -C ] && [ \"$3\" = checkout ]; then\n  printf 'preserve untracked content' > \"$2/historical-only\"\nfi\nexec \"$OMG_HISTORY_REAL_GIT\" \"$@\"\n",
        )
        .expect("private conflict-injection wrapper");
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755))
            .expect("private executable mode");
        let checkout = tempfile::tempdir().expect("owned conflicting checkout");
        temp_env::with_vars(
            [
                ("PATH", Some(programs.path().as_os_str())),
                ("OMG_HISTORY_REAL_GIT", Some(actual_git.as_os_str())),
            ],
            || {
                let error = tokio::runtime::Runtime::new()
                    .expect("private history runtime")
                    .block_on(checkout_version(
                        fixture_url(repository.path()),
                        checkout.path(),
                        "example",
                        "1.0-1",
                    ))
                    .expect_err("historical checkout must refuse the real Git file conflict");
                let diagnostic = error.to_string();
                assert!(
                    diagnostic.contains("Failed to checkout commit"),
                    "{diagnostic}"
                );
                assert!(diagnostic.contains("historical-only"), "{diagnostic}");
            },
        );
        assert_eq!(
            std::fs::read_to_string(checkout.path().join("historical-only"))
                .expect("preserved untracked file"),
            "preserve untracked content"
        );
        for directory in [checkout.path(), repository.path()] {
            assert_eq!(
                std::fs::read_to_string(directory.join("marker")).expect("preserved current tree"),
                "current marker"
            );
        }
    }

    #[tokio::test]
    async fn history_log_remains_hash_only_when_signature_display_is_configured() {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt;

        let repository = history_fixture();
        let tree = git(
            repository.path(),
            &["show", "--no-show-signature", "-s", "--format=%T", "HEAD"],
        );
        let tree = String::from_utf8(tree.stdout).expect("fixture tree ID");
        let commit = format!(
            "tree {}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\ngpgsig -----BEGIN PGP SIGNATURE-----\n inert-fixture\n -----END PGP SIGNATURE-----\n\nInert signature display fixture\n",
            tree.trim()
        );
        let mut writer = std::process::Command::new("git")
            .arg("-C")
            .arg(repository.path())
            .args(["hash-object", "-t", "commit", "-w", "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("private Git commit writer");
        writer
            .stdin
            .take()
            .expect("private commit input")
            .write_all(commit.as_bytes())
            .expect("write inert commit metadata");
        let written = writer
            .wait_with_output()
            .expect("private commit writer exits");
        assert!(written.status.success());
        let sha = String::from_utf8(written.stdout).expect("fixture commit ID");
        git(
            repository.path(),
            &["update-ref", "refs/heads/main", sha.trim()],
        );
        let program = repository.path().join("signature-status");
        std::fs::write(
            &program,
            "#!/bin/sh\nprintf 'fixture signature status\\n' >&2\nexit 1\n",
        )
        .expect("private inert signature status program");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
            .expect("private status program mode");

        let mut ordinary = git_command();
        ordinary
            .arg("-C")
            .arg(repository.path())
            .args(["log", "--format=%H", "--max-count=1"]);
        let mut protected = history_log_command(repository.path(), 1);
        for command in [&mut ordinary, &mut protected] {
            command
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_COUNT", "2")
                .env("GIT_CONFIG_KEY_0", "log.showSignature")
                .env("GIT_CONFIG_VALUE_0", "true")
                .env("GIT_CONFIG_KEY_1", "gpg.program")
                .env("GIT_CONFIG_VALUE_1", &program);
        }
        let ordinary = ordinary.output().await.expect("ordinary fixture log");
        assert!(ordinary.status.success());
        assert!(
            String::from_utf8_lossy(&ordinary.stdout).contains("fixture signature status"),
            "the fixture must actually exercise configured signature display"
        );
        let protected = protected.output().await.expect("protected fixture log");
        assert!(protected.status.success());
        assert_eq!(
            String::from_utf8_lossy(&protected.stdout).trim(),
            sha.trim()
        );
    }

    #[tokio::test]
    async fn selects_newest_matching_version_and_skips_missing_metadata() {
        let repository = history_fixture();
        let checkout = tempfile::tempdir().expect("owned rollback checkout");
        checkout_version(
            fixture_url(repository.path()),
            checkout.path(),
            "example",
            "1.0-1",
        )
        .await
        .expect("historical version must be selected");
        assert_eq!(
            std::fs::read_to_string(checkout.path().join("marker")).expect("checked out marker"),
            "newest matching commit"
        );
        assert_eq!(
            srcinfo_version(
                &std::fs::read_to_string(checkout.path().join(".SRCINFO"))
                    .expect("checked out metadata")
            )
            .as_deref(),
            Some("1.0-1")
        );
        let head = git(checkout.path(), &["rev-parse", "--abbrev-ref", "HEAD"]);
        assert_eq!(String::from_utf8_lossy(&head.stdout).trim(), "HEAD");
    }

    #[tokio::test]
    async fn exhausted_history_is_distinct_from_a_commit_budget_refusal() {
        let repository = history_fixture();
        let checkout = tempfile::tempdir().expect("owned rollback checkout");
        let absent = checkout_version(
            fixture_url(repository.path()),
            checkout.path(),
            "example",
            "missing",
        )
        .await
        .expect_err("a genuinely absent version must be reported");
        assert_eq!(
            absent.to_string(),
            historical_version_not_found_message("example", "missing")
        );

        let checkout = tempfile::tempdir().expect("owned bounded checkout");
        let error = checkout_version_with_limits(
            fixture_url(repository.path()),
            checkout.path(),
            "example",
            "1.0-1",
            HistoryLimits {
                commits: 2,
                ..HISTORY_LIMITS
            },
            Instant::now() + Duration::from_secs(10),
        )
        .await
        .expect_err("search must refuse before inspecting the third commit");
        assert!(error.to_string().contains("2-commit budget"), "{error:#}");
        assert!(!error.to_string().contains("was not found"), "{error:#}");

        let checkout = tempfile::tempdir().expect("owned exact-boundary checkout");
        checkout_version_with_limits(
            fixture_url(repository.path()),
            checkout.path(),
            "example",
            "1.0-1",
            HistoryLimits {
                commits: 3,
                ..HISTORY_LIMITS
            },
            Instant::now() + Duration::from_secs(10),
        )
        .await
        .expect("the last permitted commit must be searched before the sentinel");
        assert_eq!(
            std::fs::read_to_string(checkout.path().join("marker")).expect("checked out marker"),
            "newest matching commit"
        );
    }

    #[tokio::test]
    async fn historical_metadata_obeys_individual_and_cumulative_byte_budgets() {
        let repository = history_fixture();
        let metadata_bytes = std::fs::metadata(repository.path().join(".SRCINFO"))
            .expect("fixture metadata size")
            .len();
        for limits in [
            HistoryLimits {
                show_bytes: metadata_bytes - 1,
                ..HISTORY_LIMITS
            },
            HistoryLimits {
                total_show_bytes: metadata_bytes,
                ..HISTORY_LIMITS
            },
        ] {
            let checkout = tempfile::tempdir().expect("owned bounded checkout");
            let error = checkout_version_with_limits(
                fixture_url(repository.path()),
                checkout.path(),
                "example",
                "1.0-1",
                limits,
                Instant::now() + Duration::from_secs(10),
            )
            .await
            .expect_err("metadata byte budget must refuse before matching");
            let message = format!("{error:#}");
            assert!(
                message.contains("metadata budgets")
                    && message.contains("stdout exceeded its captured-output limit"),
                "{message}"
            );
        }

        let checkout = tempfile::tempdir().expect("owned exact-budget checkout");
        checkout_version_with_limits(
            fixture_url(repository.path()),
            checkout.path(),
            "example",
            "1.0-1",
            HistoryLimits {
                show_bytes: metadata_bytes,
                total_show_bytes: metadata_bytes * 2,
                ..HISTORY_LIMITS
            },
            Instant::now() + Duration::from_secs(10),
        )
        .await
        .expect("exact per-file and cumulative metadata budgets must allow the match");
    }

    #[tokio::test]
    async fn history_clone_obeys_staging_and_deadline_budgets() {
        let repository = history_fixture();
        let checkout = tempfile::tempdir().expect("owned bounded checkout");
        let error = checkout_version_with_limits(
            fixture_url(repository.path()),
            checkout.path(),
            "example",
            "1.0-1",
            HistoryLimits {
                git: GitLimits {
                    staging_entries: 1,
                    ..HISTORY_LIMITS.git
                },
                ..HISTORY_LIMITS
            },
            Instant::now() + Duration::from_secs(10),
        )
        .await
        .expect_err("clone must obey the shared staging budget");
        assert!(
            format!("{error:#}").contains("staged-entry limit"),
            "{error:#}"
        );

        let checkout = tempfile::tempdir().expect("owned expired checkout");
        let error = checkout_version_with_limits(
            fixture_url(repository.path()),
            checkout.path(),
            "example",
            "1.0-1",
            HISTORY_LIMITS,
            Instant::now(),
        )
        .await
        .expect_err("an expired overall deadline must not start cloning");
        assert!(format!("{error:#}").contains("duration limit"), "{error:#}");
        assert!(!checkout.path().join(".git").exists());
    }

    #[test]
    fn historical_version_fields_keep_first_occurrence_and_epoch_behavior() {
        assert_eq!(
            srcinfo_version("pkgver = 1.0\npkgrel = 2\npkgver = 9.0\npkgrel = 4"),
            Some("1.0-2".to_owned())
        );
        assert_eq!(
            srcinfo_version("pkgver = 1.0~rc1\npkgrel = 3\nepoch = 2"),
            Some("2:1.0~rc1-3".to_owned())
        );
        assert_eq!(
            srcinfo_version("epoch = \npkgver = 1.0"),
            Some("1.0".to_owned())
        );
        assert_eq!(srcinfo_version("pkgname = example"), None);
    }
}
