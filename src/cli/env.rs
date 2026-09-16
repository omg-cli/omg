use crate::cli::components::Components;
use crate::cli::tea::Cmd;
use crate::cli::{CliContext, EnvCommands, LocalCommandRunner};
use crate::core::env::fingerprint::{DriftReport, EnvironmentState};
use crate::core::http::{BoundedResponseExt, shared_client};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

impl LocalCommandRunner for EnvCommands {
    async fn execute(&self, _ctx: &CliContext) -> Result<()> {
        match self {
            EnvCommands::Plan { target } => {
                let content = crate::core::env::fingerprint::read_lockfile(Path::new(".omg.toml"))
                    .context("Cannot read .omg.toml for environment planning")?;
                let output = crate::core::env::portable::to_json(&content, target)?;
                println!("{output}");
                Ok(())
            }
            EnvCommands::Capture => capture().await,
            EnvCommands::Check => check().await,
            EnvCommands::Share {
                description,
                public,
            } => share(description.clone(), *public).await,
            EnvCommands::Sync { url } => sync(url.clone()).await,
        }
    }
}

/// Capture environment state
pub async fn capture() -> Result<()> {
    use crate::cli::packages::execute_cmd;

    execute_cmd(Components::loading("Capturing environment state..."))?;

    let state = EnvironmentState::capture().await?;
    state.save("omg.lock")?;

    execute_cmd(Cmd::batch([
        Cmd::success("Environment state captured"),
        Components::kv_list(
            Some("Capture Details"),
            vec![
                ("File", "omg.lock"),
                ("Hash", &state.hash[..16]),
                ("Packages", &state.packages.len().to_string()),
            ],
        ),
        Components::complete("Environment state saved to omg.lock"),
    ]))?;

    Ok(())
}

/// Check for environment drift
pub async fn check() -> Result<()> {
    use crate::cli::packages::execute_cmd;

    if !std::path::Path::new("omg.lock").exists() {
        execute_cmd(Components::error_with_suggestion(
            "No omg.lock file found",
            "Run 'omg env capture' to create an environment lockfile",
        ))?;
        anyhow::bail!("No omg.lock file found");
    }

    execute_cmd(Components::loading("Checking for environment drift..."))?;

    let expected = EnvironmentState::load("omg.lock")?;
    let current = EnvironmentState::capture().await?;

    let report = DriftReport::compare(&expected, &current);

    if report.has_drift {
        execute_cmd(Cmd::batch([
            Cmd::warning("Environment drift detected"),
            Cmd::spacer(),
            Cmd::println("  The following differences were found:"),
        ]))?;
        report.print();
        anyhow::bail!("Environment drift detected");
    }

    execute_cmd(Cmd::batch([
        Cmd::success("Environment is in sync"),
        Cmd::spacer(),
        Components::kv_list(
            Some("Environment Status"),
            vec![("Lockfile", "omg.lock"), ("Status", "No drift detected")],
        ),
    ]))?;

    Ok(())
}

#[derive(Serialize)]
struct CreateGist {
    description: String,
    public: bool,
    files: HashMap<String, GistFile>,
}

#[derive(Serialize)]
struct GistFile {
    content: String,
}

#[derive(Deserialize)]
struct GistResponse {
    html_url: String,
    files: HashMap<String, GistFileResponse>,
}

#[derive(Deserialize)]
struct GistFileResponse {
    raw_url: String,
    content: Option<String>,
}

fn parse_gist_id(input: &str) -> Result<String> {
    let gist_id = if input.starts_with("https://") {
        let url = reqwest::Url::parse(input).context("Invalid Gist URL")?;
        anyhow::ensure!(
            url.scheme() == "https" && url.host_str() == Some("gist.github.com"),
            "Gist URL must use https://gist.github.com"
        );
        anyhow::ensure!(
            url.query().is_none() && url.fragment().is_none(),
            "Gist URL must not contain a query or fragment"
        );
        url.path_segments()
            .and_then(|mut segments| segments.rfind(|segment| !segment.is_empty()))
            .context("Gist URL does not contain an ID")?
            .to_string()
    } else {
        input.to_string()
    };

    anyhow::ensure!(
        (7..=64).contains(&gist_id.len())
            && gist_id
                .chars()
                .all(|character| character.is_ascii_hexdigit()),
        "Gist ID must be 7 to 64 hexadecimal characters"
    );
    Ok(gist_id)
}

/// Share environment state to GitHub Gist
fn sanitize_remote_error_body(body: &str) -> String {
    crate::cli::style::sanitize_terminal_text(body)
        .chars()
        .take(200)
        .collect()
}

pub async fn share(description: String, public: bool) -> Result<()> {
    use crate::cli::packages::execute_cmd;

    // SECURITY: Validate description
    if description.len() > 1000 {
        execute_cmd(Cmd::error("Description too long (max 1000 characters)"))?;
        anyhow::bail!("Description too long");
    }

    if !std::path::Path::new("omg.lock").exists() {
        execute_cmd(Components::error_with_suggestion(
            "No omg.lock file found",
            "Run 'omg env capture' to create an environment lockfile",
        ))?;
        anyhow::bail!("No omg.lock file found");
    }

    let token =
        std::env::var("GITHUB_TOKEN").context("GITHUB_TOKEN environment variable not set")?;
    let content = crate::core::env::fingerprint::read_lockfile(Path::new("omg.lock"))
        .context("Failed to read omg.lock for sharing")?;

    let mut files = HashMap::new();
    files.insert("omg.lock".to_string(), GistFile { content });

    let gist = CreateGist {
        description,
        public,
        files,
    };

    execute_cmd(Components::loading("Uploading to GitHub Gist..."))?;

    let client = shared_client();

    let response = client
        .post("https://api.github.com/gists")
        .header("Authorization", format!("token {token}"))
        .json(&gist)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        // Error bodies are remote input: bound them before allocation.
        let body = response
            .bounded_text()
            .await
            .unwrap_or_else(|error| format!("<unreadable error body: {error}>"));
        let safe_body = sanitize_remote_error_body(&body);
        tracing::debug!(status = %status, body_bytes = body.len(), "GitHub Gist request failed");
        execute_cmd(Cmd::error(format!(
            "Failed to create gist: {status} - {safe_body}"
        )))?;
        anyhow::bail!("Failed to create gist: {status} - {safe_body}");
    }

    let gist_resp: GistResponse = response
        .bounded_json()
        .await
        .context("Failed to read gist response (is it larger than the 16 MiB limit?)")?;

    execute_cmd(Cmd::batch([
        Cmd::success("Environment shared successfully!"),
        Components::kv_list(
            Some("Gist Details"),
            vec![
                ("URL", &gist_resp.html_url),
                (
                    "Visibility",
                    &(if public {
                        "Public".to_string()
                    } else {
                        "Private".to_string()
                    }),
                ),
            ],
        ),
    ]))?;

    Ok(())
}

/// Sync environment from Gist into the current directory.
pub async fn sync(url_or_id: String) -> Result<()> {
    use crate::cli::packages::execute_cmd;

    if url_or_id.len() > 255 || url_or_id.chars().any(char::is_control) {
        execute_cmd(Cmd::error("Invalid Gist URL or ID"))?;
        anyhow::bail!("Invalid Gist URL or ID");
    }

    execute_cmd(Components::loading("Syncing environment..."))?;
    sync_lockfile(&url_or_id, Path::new(".")).await?;
    execute_cmd(Cmd::batch([
        Cmd::success("omg.lock updated from Gist"),
        Cmd::info("Running environment check..."),
    ]))?;
    check().await
}

/// Fetch and validate a Gist lockfile into an explicit workspace root.
///
/// Team pulls use this entry point so a caller's process directory cannot
/// redirect the lockfile write away from the team workspace.
pub(crate) async fn sync_at(url_or_id: &str, root: &Path) -> Result<()> {
    sync_lockfile(url_or_id, root).await
}

async fn sync_lockfile(url_or_id: &str, root: &Path) -> Result<()> {
    if url_or_id.len() > 255 || url_or_id.chars().any(char::is_control) {
        anyhow::bail!("Invalid Gist URL or ID");
    }

    let client = shared_client();
    let gist_id = parse_gist_id(url_or_id)?;
    let api_url = format!("https://api.github.com/gists/{gist_id}");

    let mut req = client.get(&api_url);
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        req = req.header("Authorization", format!("token {token}"));
    }

    let response = req.send().await?.error_for_status()?;
    // Gist metadata and raw lockfile content are remote input: cap both
    // before allocation so a huge response cannot exhaust memory
    // (csf_08340651, csf_4fe23b28).
    let gist_resp: GistResponse = response
        .bounded_json()
        .await
        .context("Failed to read gist response (is it larger than the 16 MiB limit?)")?;
    let file = gist_resp
        .files
        .get("omg.lock")
        .context("Gist does not contain omg.lock")?;
    let content = if let Some(content) = &file.content {
        content.clone()
    } else {
        client
            .get(&file.raw_url)
            .send()
            .await?
            .error_for_status()?
            .bounded_text()
            .await?
    };

    EnvironmentState::parse_lockfile(&content)
        .context("Downloaded Gist contains an invalid omg.lock")?;
    backup_replaced_lock(root, &content)?;
    crate::core::safe_ops::atomic_write_file_sync(root.join("omg.lock"), content)
        .context("Failed to write omg.lock from Gist")?;
    Ok(())
}

/// Preserve the local lock before a pull overwrites it with the team
/// version. Returns whether a backup was taken: only when a local lock
/// exists and actually differs from the incoming content.
fn backup_replaced_lock(root: &Path, incoming: &str) -> Result<bool> {
    let lock_path = root.join("omg.lock");
    // Read through the hardened lockfile reader: symlinks and oversized
    // files are refused instead of being pulled into memory
    // (csf_4fe23b28).
    let Ok(existing) = crate::core::env::fingerprint::read_lockfile(&lock_path) else {
        return Ok(false);
    };
    if existing == incoming {
        return Ok(false);
    }
    let backup = root.join("omg.lock.backup");
    crate::core::safe_ops::atomic_write_file_sync(&backup, existing)
        .context("Failed to back up local omg.lock before pull")?;
    tracing::info!(
        "Replaced local omg.lock with the team version; previous copy kept at {}",
        backup.display()
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::{backup_replaced_lock, parse_gist_id, sanitize_remote_error_body};

    #[test]
    fn replaced_lock_is_backed_up_once_and_identical_content_is_not() {
        let dir = tempfile::TempDir::new().expect("isolated workspace");
        // No local lock: nothing to preserve.
        assert!(!backup_replaced_lock(dir.path(), "new").expect("backup"));
        assert!(!dir.path().join("omg.lock.backup").exists());
        // Identical content: no backup taken.
        std::fs::write(dir.path().join("omg.lock"), "same").expect("seed lock");
        assert!(!backup_replaced_lock(dir.path(), "same").expect("backup"));
        assert!(!dir.path().join("omg.lock.backup").exists());
        // Differing content: previous copy preserved.
        assert!(backup_replaced_lock(dir.path(), "new").expect("backup"));
        assert_eq!(
            std::fs::read_to_string(dir.path().join("omg.lock.backup")).expect("backup"),
            "same"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_local_lock_is_refused_during_backup() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::TempDir::new().expect("isolated workspace");
        let outside = dir.path().join("outside.lock");
        std::fs::write(&outside, "big or foreign lock").expect("seed target");
        symlink(&outside, dir.path().join("omg.lock")).expect("seed symlink");

        // A symlinked local lock must be refused (treated as absent) rather
        // than read through, and no backup may follow it either.
        assert!(!backup_replaced_lock(dir.path(), "new").expect("backup"));
        assert!(!dir.path().join("omg.lock.backup").exists());
        assert_eq!(
            std::fs::read_to_string(&outside).expect("target untouched"),
            "big or foreign lock"
        );
    }

    #[test]
    fn gist_ids_are_extracted_and_strictly_validated() {
        assert_eq!(
            parse_gist_id("https://gist.github.com/alice/0123abcdef").unwrap(),
            "0123abcdef"
        );
        assert_eq!(parse_gist_id("0123abcdef").unwrap(), "0123abcdef");

        for invalid in [
            "https://gist.github.com/",
            "https://gist.github.com/alice/0123abcdef?file=omg.lock",
            "https://example.com/alice/0123abcdef",
            "not-a-gist-id",
            "123",
        ] {
            assert!(parse_gist_id(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn remote_error_body_is_terminal_safe_and_bounded() {
        let body = format!("\u{1b}]52;c;secret\u{7}{}", "x".repeat(400));
        let safe = sanitize_remote_error_body(&body);
        assert!(!safe.contains('\u{1b}'));
        assert!(!safe.contains('\u{7}'));
        assert_eq!(safe.chars().count(), 200);
    }
}
