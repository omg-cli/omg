//! Contract tests for `src/cli/team.rs` — team init/join/status/push/pull CLI handlers.
//!
//! Team workspace commands are local and do not require a dashboard account.
//! Roster/activity commands that talk to the dashboard fail with a link hint
//! when no account is linked.

pub mod common;

use common::serial;
use common::{CommandResult, TestProject};
use std::fs;
use std::path::Path;

#[cfg(any(feature = "arch", feature = "debian", feature = "debian-pure"))]
use omg_lib::core::env::fingerprint::EnvironmentState;

const ACCOUNT_LINK_HINT: &str = "No dashboard account linked";

/// Craft a valid initialized team workspace (`.omg/team.toml` + status file)
/// without going through `team init`.
fn craft_workspace(project: &TestProject) {
    let omg_dir = project.path().join(".omg");
    fs::create_dir_all(&omg_dir).expect("create .omg dir");
    // `remote_url` intentionally omitted: absent means "no remote", which makes
    // push/pull operate purely on local state without any network access.
    fs::write(
        omg_dir.join("team.toml"),
        r#"team_id = "acme/backend"
name = "Acme Backend"
member_id = "probe-user"
auto_push = false
"#,
    )
    .expect("write team.toml");
    fs::write(
        omg_dir.join("team-status.json"),
        r#"{
  "format_version": 1,
  "config": {
    "team_id": "acme/backend",
    "name": "Acme Backend",
    "member_id": "probe-user",
    "remote_url": null,
    "auto_push": false
  },
  "lock_hash": "",
  "members": [],
  "updated_at": 1700000000
}
"#,
    )
    .expect("write team-status.json");
}

fn workspace_marker_exists(project: &TestProject) -> bool {
    Path::new(&project.path().join(".omg/team.toml")).exists()
}

fn assert_account_link_required(res: &CommandResult, context: &str) {
    res.assert_failure();
    res.assert_stderr_contains(ACCOUNT_LINK_HINT);
    assert!(
        !res.stderr_contains("/pricing"),
        "{context}: paywall URL must not appear:\n{}",
        res.stderr
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// team init
// ═══════════════════════════════════════════════════════════════════════════

/// Contract: `team init` rejects a team ID containing characters outside
/// [A-Za-z0-9/_-], names the offending ID verbatim in the final error, offers
/// the alphanumeric suggestion, and leaves NO workspace marker behind.
#[test]
#[serial]
fn init_rejects_invalid_team_id_and_writes_nothing() {
    let project = TestProject::new();
    let res = project.run(&["team", "init", "bad team!"]);
    res.assert_failure();
    res.assert_stderr_contains("Invalid team ID");
    res.assert_stderr_contains("Error: Invalid team ID: bad team!");
    res.assert_stdout_contains("Team IDs must be alphanumeric with /, -, or _ allowed");
    assert!(
        !workspace_marker_exists(&project),
        "a rejected init must not create .omg/team.toml"
    );
}

/// Contract: a team display name containing a control character is rejected
/// with the exact validation message before any filesystem work.
#[test]
#[serial]
fn init_rejects_control_char_team_name() {
    let project = TestProject::new();
    let name_with_newline = "backend\nrm";
    let res = project.run(&["team", "init", "acme/backend", "--name", name_with_newline]);
    res.assert_failure();
    res.assert_stderr_contains("Invalid team name (too long or contains control characters)");
    res.assert_stderr_contains("Error: Invalid team name");
    assert!(
        !workspace_marker_exists(&project),
        "a rejected init must not create .omg/team.toml"
    );
}

/// Contract: a team name longer than 128 bytes is rejected with the same
/// exact validation message.
#[test]
#[serial]
fn init_rejects_overlong_team_name() {
    let project = TestProject::new();
    let long_name = "x".repeat(129);
    let res = project.run(&["team", "init", "acme/backend", "--name", &long_name]);
    res.assert_failure();
    res.assert_stderr_contains("Invalid team name (too long or contains control characters)");
    assert!(
        !workspace_marker_exists(&project),
        "a rejected init must not create .omg/team.toml"
    );
}

/// Contract: `init` does not require a dashboard account.
#[test]
#[serial]
fn init_succeeds_without_a_dashboard_account() {
    let project = TestProject::new();
    let res = project.run(&["team", "init", "acme/backend", "--name", "Backend"]);
    res.assert_success();
    res.assert_stdout_contains("Team workspace initialized!");
    assert!(
        workspace_marker_exists(&project),
        "init must create .omg/team.toml"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// team join
// ═══════════════════════════════════════════════════════════════════════════

/// Contract: `join` refuses plaintext HTTP URLs, tells the user exactly what
/// to do instead, and writes nothing to disk.
#[test]
#[serial]
fn join_rejects_http_url_with_https_remedy() {
    let project = TestProject::new();
    let res = project.run(&["team", "join", "http://example.com/acme/backend"]);
    res.assert_failure();
    res.assert_stderr_contains("Only HTTPS URLs allowed for security");
    res.assert_stderr_contains("Error: Only HTTPS URLs allowed for security");
    res.assert_stdout_contains("Use https:// instead of http://");
    assert!(
        !workspace_marker_exists(&project),
        "a rejected join must not create .omg/team.toml"
    );
}

/// Contract: remote URLs containing control characters fail validation even
/// when they start with https:// .
#[test]
#[serial]
fn join_rejects_control_char_url() {
    let project = TestProject::new();
    let url_with_newline = format!("https://example.com/{}\n/evil", "acme");
    let res = project.run(&["team", "join", &url_with_newline]);
    res.assert_failure();
    res.assert_stderr_contains("Invalid remote URL");
    assert!(
        !workspace_marker_exists(&project),
        "a rejected join must not create .omg/team.toml"
    );
}

/// Contract: remote URLs longer than 1024 bytes fail validation.
#[test]
#[serial]
fn join_rejects_overlong_url() {
    let project = TestProject::new();
    let url = format!("https://example.com/{}", "a".repeat(1100));
    let res = project.run(&["team", "join", &url]);
    res.assert_failure();
    res.assert_stderr_contains("Invalid remote URL");
    assert!(
        !workspace_marker_exists(&project),
        "a rejected join must not create .omg/team.toml"
    );
}

/// Contract: unsupported HTTPS remotes are rejected before the team workspace
/// is initialized, so the following pull cannot be guaranteed to work.
#[test]
#[serial]
fn join_rejects_unsupported_https_remote_before_mutation() {
    let project = TestProject::new();
    let res = project.run(&["team", "join", "https://github.com/acme/backend"]);
    res.assert_failure();
    res.assert_stderr_contains("gist.github.com");
    assert!(
        !workspace_marker_exists(&project),
        "unsupported remotes must not initialize a workspace"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// team status
// ═══════════════════════════════════════════════════════════════════════════

/// Contract: `status` outside a workspace names the missing workspace, not a paywall.
#[test]
#[serial]
fn status_outside_workspace_names_the_missing_workspace() {
    let project = TestProject::new();
    let res = project.run(&["team", "status"]);
    res.assert_failure();
    res.assert_stderr_contains("Not a team workspace");
}

/// Contract: inside a crafted workspace, `status` reports team identity.
#[test]
#[serial]
#[cfg(any(feature = "arch", feature = "debian", feature = "debian-pure"))]
fn team_status_reports_local_workspace_without_an_account() {
    let project = TestProject::new();
    craft_workspace(&project);
    let res = project.run(&["team", "status"]);
    res.assert_success();
    res.assert_stdout_contains("[Team Status]");
}

#[test]
#[serial]
#[cfg(any(feature = "arch", feature = "debian", feature = "debian-pure"))]
fn status_after_join_reports_the_current_remote() {
    let project = TestProject::new();
    craft_workspace(&project);
    let remote = "https://gist.github.com/fixture/lock";
    let mut workspace = omg_lib::core::env::team::TeamWorkspace::new(project.path()).unwrap();
    workspace.join(remote).unwrap();
    let result = project.run(&["team", "status"]);
    result.assert_success();
    result.assert_stdout_contains(&format!("Remote: {remote}"));
    let status = workspace.load_status().unwrap();
    assert_eq!(status.config.remote_url.as_deref(), Some(remote));
    assert_eq!(status.members.len(), 1);
}

/// Contract: in a crafted initialized workspace, `status` succeeds and reports
/// the team identity, the empty-lock sentinel "none", and the 1/1 sync ratio
/// produced by registering the configured local member.
#[test]
#[serial]
#[cfg(any(feature = "arch", feature = "debian", feature = "debian-pure"))]
fn status_in_workspace_reports_identity_empty_lock_and_member_count() {
    let project = TestProject::new();
    craft_workspace(&project);
    let res = project.run(&["team", "status"]);
    res.assert_success();
    res.assert_stdout_contains("[Team Status] 1/1 members in sync");
    res.assert_stdout_contains("Team: Acme Backend (acme/backend)");
    res.assert_stdout_contains("Lock hash: none");
    res.assert_stdout_contains("in sync");
}

// ═══════════════════════════════════════════════════════════════════════════
// team push / pull
// ═══════════════════════════════════════════════════════════════════════════

/// Contract: `push` writes an integrity-valid `omg.lock`, records its hash as
/// the team lock hash in the durable status file, and registers the configured
/// member as in-sync.
#[test]
#[serial]
#[cfg(any(feature = "arch", feature = "debian", feature = "debian-pure"))]
fn push_writes_valid_lockfile_and_records_lock_hash_in_status() {
    let project = TestProject::new();
    craft_workspace(&project);

    let res = project.run(&["team", "push"]);
    res.assert_success();
    res.assert_stdout_contains("Team lock updated!");

    let lock_path = project.path().join("omg.lock");
    let state =
        EnvironmentState::load(&lock_path).expect("push must leave an integrity-valid omg.lock");
    assert_eq!(
        state.hash.len(),
        64,
        "lockfile hash must be a full SHA256 hex digest"
    );
    assert!(
        state.hash.chars().all(|c| c.is_ascii_hexdigit()),
        "lockfile hash must be hex, got {}",
        state.hash
    );

    let status_raw =
        fs::read_to_string(project.path().join(".omg/team-status.json")).expect("read status");
    let status: serde_json::Value =
        serde_json::from_str(&status_raw).expect("parse team-status.json");
    assert_eq!(
        status["lock_hash"].as_str(),
        Some(state.hash.as_str()),
        "status lock_hash must equal the pushed lockfile hash"
    );
    let members = status["members"].as_array().expect("members array");
    assert!(
        members
            .iter()
            .any(|m| m["id"] == "probe-user" && m["in_sync"] == true),
        "configured member must be recorded as in-sync, got: {members:?}"
    );
}

/// Contract: after a successful push, `pull` (no remote configured) compares
/// purely local state and reports in-sync with a zero exit code.
#[test]
#[serial]
#[cfg(any(feature = "arch", feature = "debian", feature = "debian-pure"))]
fn pull_after_push_reports_local_sync_success() {
    let project = TestProject::new();
    craft_workspace(&project);

    let push_res = project.run(&["team", "push"]);
    push_res.assert_success();

    let res = project.run(&["team", "pull"]);
    res.assert_success();
    res.assert_stdout_contains("Environment is in sync with team!");
}

/// Contract: when the committed lock differs from the live environment (valid
/// integrity, different content), `pull` exits non-zero, warns about drift on
/// stdout, and names the `omg env check` diagnostic command.
#[test]
#[serial]
#[cfg(any(feature = "arch", feature = "debian", feature = "debian-pure"))]
fn pull_detects_drift_when_lock_differs_from_environment() {
    let project = TestProject::new();
    craft_workspace(&project);

    let push_res = project.run(&["team", "push"]);
    push_res.assert_success();

    // Rewrite the lock with a different-but-integrity-valid state.
    let lock_path = project.path().join("omg.lock");
    let mut drifted = EnvironmentState::load(&lock_path).expect("load pushed lock");
    drifted
        .runtimes
        .insert("node".to_string(), "99.0.0-drifted".to_string());
    drifted.save(&lock_path).expect("rewrite drifted lock");
    // Sanity: save() must keep the file integrity-valid, otherwise this test
    // would exercise the corruption path instead of the drift path.
    EnvironmentState::load(&lock_path).expect("drifted lock must stay integrity-valid");

    let res = project.run(&["team", "pull"]);
    res.assert_failure();
    res.assert_stdout_contains("Environment drift detected!");
    res.assert_stdout_contains("Run 'omg env check' to see differences");
    res.assert_stderr_contains("Error: Environment drift detected");
}

/// Contract: a lockfile whose stored hash does not match its contents is
/// rejected loudly (integrity error naming the mismatch) rather than being
/// silently treated as in-sync or as drift.
#[test]
#[serial]
#[cfg(any(feature = "arch", feature = "debian", feature = "debian-pure"))]
fn corrupted_lockfile_fails_pull_loudly_instead_of_reporting_state() {
    let project = TestProject::new();
    craft_workspace(&project);

    let push_res = project.run(&["team", "push"]);
    push_res.assert_success();

    let lock_path = project.path().join("omg.lock");
    let mut tampered = EnvironmentState::load(&lock_path).expect("load pushed lock");
    tampered.hash = "f".repeat(64);
    let tampered_toml = toml::to_string_pretty(&tampered).expect("serialize tampered lock");
    fs::write(&lock_path, tampered_toml).expect("write tampered lock");

    let res = project.run(&["team", "pull"]);
    res.assert_failure();
    res.assert_stderr_contains("Lockfile integrity check failed");
    res.assert_stderr_contains("stored hash does not match contents");
}

/// Backend-free builds must refuse fingerprint-dependent operations without
/// publishing an empty environment or changing the durable team state.
#[test]
#[serial]
#[cfg(not(any(feature = "arch", feature = "debian", feature = "debian-pure")))]
fn team_fingerprint_operations_without_backend_preserve_workspace() {
    for operation in ["status", "push", "pull"] {
        let project = TestProject::new();
        craft_workspace(&project);
        let status_path = project.path().join(".omg/team-status.json");
        let config_path = project.path().join(".omg/team.toml");
        let original_status = fs::read(&status_path).expect("read original status");
        let original_config = fs::read(&config_path).expect("read original config");
        let result = project.run(&["team", operation]);
        result.assert_failure();
        result.assert_stderr_contains(
            "Environment fingerprinting is not available without an Arch or Debian package backend",
        );
        assert!(!project.path().join("omg.lock").exists());
        assert_eq!(fs::read(&status_path).unwrap(), original_status);
        assert_eq!(fs::read(&config_path).unwrap(), original_config);
    }
}

/// Contract: pulling with a remote that is not a gist.github.com URL fails
/// with an error naming the unsupported URL and the supported scheme, instead
/// of reporting local-only state as a successful team sync.
#[test]
#[serial]
fn pull_rejects_non_gist_remote_url_instead_of_reporting_fake_sync() {
    let project = TestProject::new();
    craft_workspace(&project);
    let cfg = project.path().join(".omg/team.toml");
    let mut content = fs::read_to_string(&cfg).expect("read team.toml");
    content.insert_str(0, "remote_url = \"https://github.com/acme/backend\"\n");
    fs::write(&cfg, content).expect("add github remote");

    let res = project.run(&["team", "pull"]);
    res.assert_failure();
    res.assert_stderr_contains("Unsupported team remote URL 'https://github.com/acme/backend'");
    res.assert_stderr_contains("pull currently supports only HTTPS gist.github.com remotes");
}

// ═══════════════════════════════════════════════════════════════════════════
// golden-path templates
// ═══════════════════════════════════════════════════════════════════════════

/// Contract: template names allow only alphanumerics and hyphens.
#[test]
#[serial]
fn golden_path_create_rejects_invalid_template_name() {
    let project = TestProject::new();
    let res = project.run(&["team", "golden-path", "create", "bad name!"]);
    res.assert_failure();
    res.assert_stderr_contains("Invalid template name");
    res.assert_stdout_contains("Template names must be alphanumeric with hyphens only");
    res.assert_stderr_contains("Error: Invalid template name (alphanumeric and hyphens only)");
    assert!(
        !project.config_dir.path().join("golden-paths.toml").exists(),
        "rejected create must not write golden-paths.toml"
    );
}

/// Contract: unsafe Node version strings are rejected before any config write.
#[test]
#[serial]
fn golden_path_create_rejects_unsafe_node_version() {
    let project = TestProject::new();
    let res = project.run(&[
        "team",
        "golden-path",
        "create",
        "my-template",
        "--node",
        "20:~evil",
    ]);
    res.assert_failure();
    res.assert_stderr_contains("Invalid Node version:");
    assert!(
        !project.config_dir.path().join("golden-paths.toml").exists(),
        "rejected create must not write golden-paths.toml"
    );
}

/// Contract: package lists containing unsafe package names are rejected.
#[test]
#[serial]
fn golden_path_create_rejects_unsafe_package_name() {
    let project = TestProject::new();
    let res = project.run(&[
        "team",
        "golden-path",
        "create",
        "my-template",
        "--packages",
        "good-pkg,bad;pkg",
    ]);
    res.assert_failure();
    res.assert_stderr_contains("Invalid package name:");
    assert!(
        !project.config_dir.path().join("golden-paths.toml").exists(),
        "rejected create must not write golden-paths.toml"
    );
}

/// Contract: a syntactically valid `golden-path create` persists locally.
#[test]
#[serial]
fn golden_path_create_valid_input_persists_without_an_account() {
    let project = TestProject::new();
    let res = project.run(&[
        "team",
        "golden-path",
        "create",
        "my-template",
        "--node",
        "20",
    ]);
    res.assert_success();
    assert!(
        project.config_dir.path().join("golden-paths.toml").exists(),
        "create must persist golden-paths.toml"
    );
}

/// Contract: `golden-path list` works without an account.
#[test]
#[serial]
fn golden_path_list_works_without_an_account() {
    let project = TestProject::new();
    let res = project.run(&["team", "golden-path", "list"]);
    res.assert_success();
}

/// Contract: `golden-path delete` of a missing template warns, without a paywall.
#[test]
#[serial]
fn golden_path_delete_missing_template_warns() {
    let project = TestProject::new();
    let res = project.run(&["team", "golden-path", "delete", "whatever"]);
    res.assert_success();
    res.assert_stdout_contains("Template 'whatever' not found");
}

// ═══════════════════════════════════════════════════════════════════════════
// remaining team surface
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn team_roles_list_works_without_an_account() {
    let project = TestProject::new();
    let res = project.run(&["team", "roles", "list"]);
    res.assert_success();
    res.assert_stdout_contains("Team Roles");
}

#[test]
#[serial]
fn team_members_requires_a_linked_dashboard_account() {
    let project = TestProject::new();
    let res = project.run(&["team", "members"]);
    assert_account_link_required(&res, "members");
}

#[test]
#[serial]
fn team_activity_requires_a_linked_dashboard_account() {
    let project = TestProject::new();
    let res = project.run(&["team", "activity", "--days", "7"]);
    assert_account_link_required(&res, "activity");
}

/// Contract: `compliance` is honest about having no local evaluation engine.
#[test]
#[serial]
fn team_compliance_reports_no_local_data() {
    let project = TestProject::new();
    let res = project.run(&["team", "compliance"]);
    res.assert_success();
    res.assert_stdout_contains("No local data");
}

#[test]
#[serial]
fn team_compliance_export_names_missing_data() {
    let project = TestProject::new();
    let res = project.run(&["team", "compliance", "--export", "/tmp/cov5-export.md"]);
    res.assert_failure();
    res.assert_stderr_contains("No compliance data is available to export");
}
