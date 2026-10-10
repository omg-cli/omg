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
            EnvCommands::Export { source_target } => {
                let state = EnvironmentState::load("omg.lock")?;
                let output = crate::core::env::portable::from_snapshot(
                    state.runtimes,
                    state.packages,
                    source_target,
                )?;
                print!("{output}");
                Ok(())
            }
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
    #[serde(default)]
    truncated: bool,
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
    sync_lockfile_with_api_base(url_or_id, root, "https://api.github.com").await
}

async fn sync_lockfile_with_api_base(url_or_id: &str, root: &Path, api_base: &str) -> Result<()> {
    if url_or_id.len() > 255 || url_or_id.chars().any(char::is_control) {
        anyhow::bail!("Invalid Gist URL or ID");
    }

    let client = shared_client();
    let gist_id = parse_gist_id(url_or_id)?;
    let api_url = format!("{api_base}/gists/{gist_id}");

    let mut req = client.get(&api_url);
    if api_base == "https://api.github.com"
        && let Ok(token) = std::env::var("GITHUB_TOKEN")
    {
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
    // GitHub includes a partial `content` field when `truncated` is true.
    let content = if let (Some(content), false) = (&file.content, file.truncated) {
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
    match std::fs::symlink_metadata(&lock_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => return Ok(false),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).context("Failed to inspect local omg.lock before pull");
        }
    }
    // Read through the hardened lockfile reader: symlinks and oversized
    // files are refused instead of being pulled into memory
    // (csf_4fe23b28).
    let existing = crate::core::env::fingerprint::read_lockfile(&lock_path)
        .context("Failed to read local omg.lock before pull")?;
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
    use super::{
        EnvironmentState, backup_replaced_lock, parse_gist_id, sanitize_remote_error_body,
        sync_lockfile_with_api_base,
    };
    use std::collections::BTreeMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn lockfile_with_package(package: &str) -> String {
        let mut state = EnvironmentState {
            schema_version: EnvironmentState::SCHEMA_VERSION,
            runtimes: BTreeMap::new(),
            packages: vec![package.to_string()],
            timestamp: 1_700_000_000,
            hash: String::new(),
        };
        state.hash = state.calculate_hash();
        toml::to_string_pretty(&state).expect("serialize valid lockfile")
    }

    async fn sync_from_inline_gist_fixture(
        root: &std::path::Path,
        content: &str,
    ) -> anyhow::Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback gist fixture");
        let api_base = format!("http://{}", listener.local_addr().expect("fixture address"));
        let metadata = serde_json::json!({
            "html_url": "https://gist.github.com/0123abcdef",
            "files": {"omg.lock": {
                "raw_url": "http://127.0.0.1:1/never-fetch",
                "content": content,
                "truncated": false
            }}
        })
        .to_string();
        let fixture = tokio::spawn(async move {
            let (mut stream, _) =
                tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                    .await
                    .expect("expected gist metadata request")
                    .expect("accept gist metadata request");
            let mut request = [0_u8; 4096];
            let count = stream.read(&mut request).await.expect("read request");
            assert!(request[..count].starts_with(b"GET /gists/0123abcdef "));
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{metadata}",
                metadata.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write gist response");
        });
        let result = sync_lockfile_with_api_base("0123abcdef", root, &api_base).await;
        tokio::time::timeout(std::time::Duration::from_secs(5), fixture)
            .await
            .expect("gist fixture completed")
            .expect("gist fixture passed");
        result
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sync_preserves_unreadable_regular_local_lock() {
        const NAME: &str = "cli::env::tests::sync_preserves_unreadable_regular_local_lock";
        if crate::config::Settings::rerun_test_unprivileged(NAME) {
            return;
        }
        assert!(
            !crate::core::is_root(),
            "permission fixture must run as ordinary user"
        );
        use std::os::unix::fs::PermissionsExt;
        let workspace = tempfile::tempdir().expect("isolated workspace");
        let lock = workspace.path().join("omg.lock");
        let original = lockfile_with_package("local-package");
        std::fs::write(&lock, &original).expect("seed local lock");
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o000))
            .expect("deny local lock reads");
        let denied = std::fs::read(&lock).expect_err("fixture must deny reads");
        assert_eq!(denied.kind(), std::io::ErrorKind::PermissionDenied);
        let result = sync_from_inline_gist_fixture(
            workspace.path(),
            &lockfile_with_package("remote-package"),
        )
        .await;
        let mode = std::fs::metadata(&lock)
            .expect("retained lock")
            .permissions()
            .mode()
            & 0o777;
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600))
            .expect("restore fixture readability");
        let retained = std::fs::read(&lock).expect("read retained bytes");
        println!(
            "[omg-lock-sync] uid={} result={result:?} mode={mode:o} retained={} backup={}",
            nix::unistd::geteuid(),
            retained == original.as_bytes(),
            workspace.path().join("omg.lock.backup").exists()
        );
        assert_eq!(
            retained,
            original.as_bytes(),
            "sync must retain unreadable local lock bytes"
        );
        assert_eq!(mode, 0o000, "failed sync must preserve the original mode");
        assert!(!workspace.path().join("omg.lock.backup").exists());
        let error = result.expect_err("unreadable regular lock must refuse replacement");
        assert!(
            error.chain().any(|cause| cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|cause| cause.kind() == std::io::ErrorKind::PermissionDenied)),
            "sync must retain the permission error: {error:#}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sync_preserves_oversized_regular_local_lock() {
        const NAME: &str = "cli::env::tests::sync_preserves_oversized_regular_local_lock";
        if crate::config::Settings::rerun_test_unprivileged(NAME) {
            return;
        }
        assert!(
            !crate::core::is_root(),
            "lock preservation fixture must run as ordinary user"
        );
        use std::os::unix::fs::PermissionsExt;
        let workspace = tempfile::tempdir().expect("isolated workspace");
        let lock = workspace.path().join("omg.lock");
        let original = format!(
            "{}# {}",
            lockfile_with_package("local-package"),
            "x".repeat(16 * 1024 * 1024)
        );
        std::fs::write(&lock, &original).expect("seed oversized local lock");
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o640))
            .expect("set original mode");
        let result = sync_from_inline_gist_fixture(
            workspace.path(),
            &lockfile_with_package("remote-package"),
        )
        .await;
        let retained = std::fs::read(&lock).expect("read retained bytes");
        let mode = std::fs::metadata(&lock)
            .expect("retained lock")
            .permissions()
            .mode()
            & 0o777;
        println!(
            "[omg-lock-sync] uid={} result={result:?} original_len={} retained_len={} mode={mode:o} backup={}",
            nix::unistd::geteuid(),
            original.len(),
            retained.len(),
            workspace.path().join("omg.lock.backup").exists()
        );
        assert_eq!(
            retained.len(),
            original.len(),
            "sync must retain oversized local lock length"
        );
        assert_eq!(
            retained,
            original.as_bytes(),
            "sync must retain oversized local lock bytes"
        );
        assert_eq!(mode, 0o640, "failed sync must preserve the original mode");
        assert!(!workspace.path().join("omg.lock.backup").exists());
        result.expect_err("oversized regular lock must refuse replacement");
    }

    #[tokio::test]
    async fn sync_missing_identical_and_different_local_lock_controls() {
        let incoming = lockfile_with_package("remote-package");
        let different = lockfile_with_package("local-package");
        for (label, original, expected_backup) in [
            ("missing", None, None),
            ("identical", Some(incoming.as_str()), None),
            (
                "different",
                Some(different.as_str()),
                Some(different.as_str()),
            ),
        ] {
            let workspace = tempfile::tempdir().expect("isolated workspace");
            if let Some(original) = original {
                std::fs::write(workspace.path().join("omg.lock"), original)
                    .expect("seed local lock");
            }
            sync_from_inline_gist_fixture(workspace.path(), &incoming)
                .await
                .expect(label);
            assert_eq!(
                std::fs::read_to_string(workspace.path().join("omg.lock")).expect("synced lock"),
                incoming,
                "{label}"
            );
            match expected_backup {
                Some(expected) => assert_eq!(
                    std::fs::read_to_string(workspace.path().join("omg.lock.backup"))
                        .expect("backup"),
                    expected,
                    "{label}"
                ),
                None => assert!(
                    !workspace.path().join("omg.lock.backup").exists(),
                    "{label}"
                ),
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sync_replaces_symlink_without_reading_or_changing_its_target() {
        use std::os::unix::fs::symlink;
        let workspace = tempfile::tempdir().expect("isolated workspace");
        let outside = tempfile::tempdir().expect("external target directory");
        let target = outside.path().join("outside.lock");
        std::fs::write(&target, "external-sentinel").expect("seed target");
        let lock = workspace.path().join("omg.lock");
        symlink(&target, &lock).expect("seed local symlink");
        let incoming = lockfile_with_package("remote-package");
        sync_from_inline_gist_fixture(workspace.path(), &incoming)
            .await
            .expect("sync replaces link itself");
        assert!(
            std::fs::symlink_metadata(&lock)
                .expect("synced lock")
                .is_file()
        );
        assert_eq!(
            std::fs::read_to_string(&lock).expect("synced lock"),
            incoming
        );
        assert_eq!(
            std::fs::read_to_string(&target).expect("untouched target"),
            "external-sentinel"
        );
        assert!(!workspace.path().join("omg.lock.backup").exists());
    }

    #[tokio::test]
    async fn sync_fetches_raw_lock_when_gist_inline_content_is_truncated() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback gist fixture");
        let api_base = format!("http://{}", listener.local_addr().expect("fixture address"));
        let raw_content = lockfile_with_package("new-package");
        let metadata = serde_json::json!({
            "html_url": "https://gist.github.com/0123abcdef",
            "files": {"omg.lock": {
                "raw_url": format!("{api_base}/raw/omg.lock"),
                "content": "truncated content is not a valid lockfile",
                "truncated": true
            }}
        })
        .to_string();
        let served_content = raw_content.clone();
        let fixture = tokio::spawn(async move {
            for (path, body) in [
                ("/gists/0123abcdef", metadata),
                ("/raw/omg.lock", served_content),
            ] {
                let (mut stream, _) =
                    tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                        .await
                        .expect("expected gist request")
                        .expect("accept gist request");
                let mut request = [0_u8; 4096];
                let count = stream.read(&mut request).await.expect("read request");
                assert!(
                    request[..count].starts_with(format!("GET {path} ").as_bytes()),
                    "unexpected gist request: {}",
                    String::from_utf8_lossy(&request[..count])
                );
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write gist response");
            }
        });

        let workspace = tempfile::TempDir::new().expect("isolated workspace");
        let old_content = lockfile_with_package("old-package");
        std::fs::write(workspace.path().join("omg.lock"), &old_content).expect("seed old lockfile");
        let result = sync_lockfile_with_api_base("0123abcdef", workspace.path(), &api_base).await;
        if result.is_err() {
            fixture.abort();
            assert_eq!(
                std::fs::read_to_string(workspace.path().join("omg.lock")).unwrap(),
                old_content,
                "failed sync replaced the existing lockfile"
            );
            assert!(
                !workspace.path().join("omg.lock.backup").exists(),
                "failed sync created a backup"
            );
        }
        result.expect("truncated gist must fetch its complete raw lockfile");
        tokio::time::timeout(std::time::Duration::from_secs(5), fixture)
            .await
            .expect("gist fixture completed")
            .expect("gist fixture passed");
        assert_eq!(
            std::fs::read_to_string(workspace.path().join("omg.lock")).unwrap(),
            raw_content
        );
        assert_eq!(
            std::fs::read_to_string(workspace.path().join("omg.lock.backup")).unwrap(),
            old_content
        );
        workspace.close().expect("clean gist workspace");
    }

    #[tokio::test]
    async fn sync_uses_complete_inline_lock_without_fetching_raw_url() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback gist fixture");
        let api_base = format!("http://{}", listener.local_addr().expect("fixture address"));
        let content = lockfile_with_package("inline-package");
        let metadata = serde_json::json!({
            "html_url": "https://gist.github.com/0123abcdef",
            "files": {"omg.lock": {
                "raw_url": "http://127.0.0.1:1/never-fetch",
                "content": &content,
                "truncated": false
            }}
        })
        .to_string();
        let fixture = tokio::spawn(async move {
            let (mut stream, _) =
                tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                    .await
                    .expect("expected gist metadata request")
                    .expect("accept gist metadata request");
            let mut request = [0_u8; 4096];
            let count = stream.read(&mut request).await.expect("read request");
            assert!(request[..count].starts_with(b"GET /gists/0123abcdef "));
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{metadata}",
                metadata.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write gist response");
        });

        let workspace = tempfile::TempDir::new().expect("isolated workspace");
        sync_lockfile_with_api_base("0123abcdef", workspace.path(), &api_base)
            .await
            .expect("complete inline lockfile must sync without raw fetch");
        tokio::time::timeout(std::time::Duration::from_secs(5), fixture)
            .await
            .expect("gist fixture completed")
            .expect("gist fixture passed");
        assert_eq!(
            std::fs::read_to_string(workspace.path().join("omg.lock")).unwrap(),
            content
        );
        assert!(!workspace.path().join("omg.lock.backup").exists());
        workspace.close().expect("clean gist workspace");
    }

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
