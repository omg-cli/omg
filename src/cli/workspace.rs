//! Workspace management for OMG CLI
//!
//! Enables monorepo support with:
//! - Multi-project management
//! - Shared runtime versions
//! - Parallel task execution with dependency awareness

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use crate::cli::style;
use crate::core::env::{
    fingerprint::{EnvironmentState, MAX_LOCKFILE_BYTES, read_lockfile},
    lock_regular_file,
};
use crate::core::safe_ops;

/// Workspace configuration file name
const WORKSPACE_FILE: &str = "omg-workspace.toml";
const WORKSPACE_WRITE_LOCK: &str = ".omg-workspace.write.lock";
const MAX_WORKSPACE_FILE_BYTES: u64 = 16 * 1024 * 1024;

fn is_missing(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|cause| cause.kind() == ErrorKind::NotFound)
}

fn lock_existing_workspace() -> Result<fs::File> {
    let path = Path::new(WORKSPACE_FILE);
    match path.symlink_metadata() {
        Ok(_) => lock_regular_file(Path::new(WORKSPACE_WRITE_LOCK)),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            anyhow::bail!("No workspace found. Run 'omg workspace init' first.");
        }
        Err(error) => Err(error).context("Failed to inspect workspace file"),
    }
}

/// Workspace configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    /// Workspace name
    pub name: String,
    /// Projects in the workspace
    #[serde(default)]
    pub projects: HashMap<String, WorkspaceProject>,
    /// Created timestamp
    pub created_at: String,
}

/// Project within a workspace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceProject {
    /// Path relative to workspace root
    pub path: String,
    /// Project dependencies (other projects it depends on)
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// Project-specific commands
    #[serde(default)]
    pub commands: HashMap<String, String>,
}

impl Default for Workspace {
    fn default() -> Self {
        Self {
            name: "workspace".to_string(),
            projects: HashMap::new(),
            created_at: jiff::Timestamp::now().to_string(),
        }
    }
}

impl Workspace {
    /// Load workspace from file
    pub fn load() -> Result<Self> {
        let content = safe_ops::read_bounded_regular_file(
            Path::new(WORKSPACE_FILE),
            "Workspace file",
            MAX_WORKSPACE_FILE_BYTES,
        )
        .map_err(|error| {
            if is_missing(&error) {
                error.context("No workspace found. Run 'omg workspace init' first.")
            } else {
                error
            }
        })?;
        toml::from_str(&content).context("Failed to parse workspace file")
    }

    /// Save workspace to file
    pub fn save(&self) -> Result<()> {
        let _guard = lock_regular_file(Path::new(WORKSPACE_WRITE_LOCK))?;
        self.save_locked()
    }

    fn encoded(&self) -> Result<String> {
        let content = toml::to_string_pretty(self).context("Failed to serialize workspace")?;
        anyhow::ensure!(
            content.len() as u64 <= MAX_WORKSPACE_FILE_BYTES,
            "Workspace file exceeds the {MAX_WORKSPACE_FILE_BYTES} byte limit"
        );
        Ok(content)
    }

    fn save_locked(&self) -> Result<()> {
        safe_ops::atomic_write_file_sync(WORKSPACE_FILE, self.encoded()?)
            .context("Failed to write workspace file")
    }

    fn project_for_removal(&self, selector: &str) -> Result<&str> {
        if let Some((name, _)) = self.projects.get_key_value(selector) {
            return Ok(name);
        }

        let root = std::env::current_dir()?;
        let requested = root.join(selector);
        let mut matches = self.projects.iter().filter_map(|(name, project)| {
            (root.join(&project.path) == requested).then_some(name.as_str())
        });
        let name = matches
            .next()
            .with_context(|| format!("Project '{selector}' not found in workspace"))?;
        anyhow::ensure!(
            matches.next().is_none(),
            "Path '{selector}' matches multiple projects; use the project name"
        );
        Ok(name)
    }

    /// Get topologically sorted projects (respecting dependencies)
    pub fn sorted_projects(&self) -> Result<Vec<String>> {
        let mut result = Vec::with_capacity(self.projects.len());
        let mut visited = HashSet::new();
        let mut active = HashSet::new();
        let mut stack = Vec::new();
        let mut names: Vec<_> = self.projects.keys().map(String::as_str).collect();
        names.sort_unstable();

        for root in names {
            stack.push((root, false));
            while let Some((name, complete)) = stack.pop() {
                if complete {
                    active.remove(name);
                    visited.insert(name);
                    result.push(name.to_owned());
                } else if !visited.contains(name) {
                    anyhow::ensure!(
                        active.insert(name),
                        "Circular dependency detected involving project: {name}"
                    );
                    let project = self.projects.get(name).with_context(|| {
                        format!(
                            "Unknown project '{name}' referenced in depends_on; add it with \
                             'omg workspace add' or fix the reference"
                        )
                    })?;
                    stack.push((name, true));
                    stack.extend(
                        project
                            .depends_on
                            .iter()
                            .rev()
                            .map(|dep| (dep.as_str(), false)),
                    );
                }
            }
        }
        Ok(result)
    }
}

/// Initialize a new workspace
pub fn init(name: &str) -> Result<()> {
    let _guard = lock_regular_file(Path::new(WORKSPACE_WRITE_LOCK))?;
    let path = Path::new(WORKSPACE_FILE);
    match path.symlink_metadata() {
        Ok(_) => {
            anyhow::bail!("Workspace already exists. Delete {WORKSPACE_FILE} to reinitialize.")
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("Failed to inspect workspace file"),
    }

    println!(
        "{} Initializing workspace '{}'\n",
        style::header("OMG"),
        name
    );

    let workspace = Workspace {
        name: name.to_string(),
        ..Default::default()
    };

    anyhow::ensure!(
        safe_ops::atomic_write_new_private_file(path, workspace.encoded()?.as_bytes())?,
        "Workspace already exists. Delete {WORKSPACE_FILE} to reinitialize."
    );

    println!("{} Created {}", style::success("✓"), WORKSPACE_FILE);
    println!();
    println!("{}", style::dim("Next steps:"));
    println!("  • Add projects: omg workspace add ./api");
    println!("  • Run commands: omg workspace run build");

    Ok(())
}

/// Add a project to the workspace
pub fn add(path: &str, name: Option<&str>) -> Result<()> {
    let _guard = lock_existing_workspace()?;
    let mut workspace = Workspace::load()?;

    let project_path = PathBuf::from(path);
    let metadata = match project_path.metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            anyhow::bail!("Project path does not exist: {path}");
        }
        Err(error) => return Err(error).context("Failed to inspect project path"),
    };
    anyhow::ensure!(metadata.is_dir(), "Project path is not a directory: {path}");

    // Determine project name
    let project_name = name
        .or_else(|| project_path.file_name().and_then(|name| name.to_str()))
        .unwrap_or("project")
        .to_string();

    if workspace.projects.contains_key(&project_name) {
        anyhow::bail!("Project '{project_name}' already exists in workspace");
    }

    // Detect project type and commands
    let commands = detect_project_commands(&project_path);

    let project = WorkspaceProject {
        path: path.to_string(),
        depends_on: Vec::new(),
        commands,
    };

    workspace.projects.insert(project_name.clone(), project);
    workspace.save_locked()?;

    println!(
        "{} Added project '{project_name}' ({path})",
        style::success("✓")
    );

    Ok(())
}

/// Remove a project from the workspace
pub fn remove(project: &str) -> Result<()> {
    let _guard = lock_existing_workspace()?;
    let mut workspace = Workspace::load()?;
    let name = workspace.project_for_removal(project)?.to_owned();
    workspace.projects.remove(&name);

    for project in workspace.projects.values_mut() {
        project.depends_on.retain(|dependency| dependency != &name);
    }

    workspace.save_locked()?;

    println!("{} Removed project '{name}'", style::success("✓"));

    Ok(())
}

/// List all projects in the workspace
pub fn list() -> Result<()> {
    let workspace = Workspace::load()?;

    println!("{} Workspace: {}\n", style::header("OMG"), workspace.name);

    if workspace.projects.is_empty() {
        println!("  {}", style::dim("No projects in workspace"));
        println!("  Run 'omg workspace add ./path' to add a project");
        return Ok(());
    }

    // Get sorted order
    let sorted = workspace.sorted_projects()?;

    for (i, name) in sorted.iter().enumerate() {
        if let Some(project) = workspace.projects.get(name) {
            let deps = if project.depends_on.is_empty() {
                String::new()
            } else {
                format!(" (depends on: {})", project.depends_on.join(", "))
            };

            println!(
                "  {}. {} → {}{}",
                i + 1,
                style::package(name),
                style::dim(&project.path),
                style::dim(&deps)
            );

            // Show available commands
            if !project.commands.is_empty() {
                let cmds: Vec<&str> = project
                    .commands
                    .keys()
                    .map(std::string::String::as_str)
                    .collect();
                println!("     {} {}", style::dim("commands:"), cmds.join(", "));
            }
        }
    }

    Ok(())
}

/// Run a command across all projects
pub async fn run(
    command: &str,
    args: &[String],
    parallel: bool,
    filter: Option<&str>,
) -> Result<()> {
    let workspace = Workspace::load()?;

    println!(
        "{} Running '{command}' across workspace...\n",
        style::header("OMG")
    );

    // Get sorted projects
    let sorted = workspace.sorted_projects()?;

    // Filter projects if requested
    let projects: Vec<&str> = sorted
        .iter()
        .filter(|name| filter.is_none_or(|f| name.contains(f)))
        .map(String::as_str)
        .collect();

    if projects.is_empty() {
        println!("  {}", style::dim("No matching projects"));
        return Ok(());
    }

    if parallel {
        // Run in parallel using tokio
        run_parallel(&workspace, &projects, command, args).await?;
    } else {
        // Run sequentially
        run_sequential(&workspace, &projects, command, args)?;
    }

    Ok(())
}

/// Print the outcome summary and fail loudly when anything failed.
///
/// A partial workspace failure must surface as a nonzero exit code so scripts
/// and CI wrapping `omg workspace run` observe it instead of a misleading zero.
fn print_summary(command: &str, success: usize, failed: usize) -> Result<()> {
    println!();
    println!(
        "{} {success} succeeded, {failed} failed",
        if failed == 0 {
            style::success("✓")
        } else {
            style::warning("⚠")
        }
    );

    if failed == 0 {
        Ok(())
    } else {
        anyhow::bail!("{failed} project(s) failed to run '{command}'")
    }
}

fn run_sequential(
    workspace: &Workspace,
    projects: &[&str],
    command: &str,
    args: &[String],
) -> Result<()> {
    let mut success = 0;
    let mut failed = 0;
    let selected: HashSet<&str> = projects.iter().copied().collect();
    let mut failed_projects = HashSet::new();

    for name in dependency_levels(workspace, projects)?
        .into_iter()
        .flatten()
    {
        if let Some(project) = workspace.projects.get(&name) {
            if dependency_failed(project, &selected, &failed_projects) {
                println!(
                    "{} {} skipped because a dependency failed",
                    style::error("✗"),
                    style::package(&name)
                );
                failed_projects.insert(name);
                failed += 1;
                continue;
            }
            println!("{} {}", style::arrow("→"), style::package(&name));

            let result = run_project_command(&project.path, project, command, args);

            match result {
                Ok(()) => {
                    println!("  {}", style::success("✓ completed"));
                    success += 1;
                }
                Err(e) => {
                    println!("  {} {e}", style::error("✗"));
                    failed_projects.insert(name);
                    failed += 1;
                }
            }
            println!();
        }
    }

    print_summary(command, success, failed)
}

fn dependency_failed(
    project: &WorkspaceProject,
    selected: &HashSet<&str>,
    failed: &HashSet<String>,
) -> bool {
    project
        .depends_on
        .iter()
        .any(|dependency| selected.contains(dependency.as_str()) && failed.contains(dependency))
}

struct DependencyQueue<'a> {
    remaining: HashMap<&'a str, usize>,
    dependents: HashMap<&'a str, Vec<&'a str>>,
    ready: BTreeSet<&'a str>,
}

impl<'a> DependencyQueue<'a> {
    fn new(workspace: &Workspace, projects: &[&'a str]) -> Result<Self> {
        let selected: HashSet<_> = projects.iter().copied().collect();
        let mut queue = Self {
            remaining: HashMap::with_capacity(selected.len()),
            dependents: HashMap::new(),
            ready: BTreeSet::new(),
        };
        for &name in &selected {
            let project = workspace
                .projects
                .get(name)
                .context("Unknown scheduled project")?;
            let mut pending = 0;
            for dependency in &project.depends_on {
                if let Some(&dependency) = selected.get(dependency.as_str()) {
                    queue.dependents.entry(dependency).or_default().push(name);
                    pending += 1;
                }
            }
            queue.remaining.insert(name, pending);
            if pending == 0 {
                queue.ready.insert(name);
            }
        }
        Ok(queue)
    }

    fn completed(&mut self, name: &str) -> Result<()> {
        self.remaining.remove(name);
        for dependent in self.dependents.remove(name).into_iter().flatten() {
            let pending = self
                .remaining
                .get_mut(dependent)
                .context("Unknown dependent project")?;
            *pending -= 1;
            if *pending == 0 {
                self.ready.insert(dependent);
            }
        }
        Ok(())
    }
}

fn dependency_levels(workspace: &Workspace, projects: &[&str]) -> Result<Vec<Vec<String>>> {
    let mut queue = DependencyQueue::new(workspace, projects)?;
    let mut levels = Vec::new();

    while !queue.remaining.is_empty() {
        let ready = std::mem::take(&mut queue.ready);
        anyhow::ensure!(
            !ready.is_empty(),
            "Circular dependency detected while scheduling workspace tasks"
        );
        let mut level = Vec::with_capacity(ready.len());
        for name in ready {
            queue.completed(name)?;
            level.push(name.to_owned());
        }
        levels.push(level);
    }

    Ok(levels)
}

async fn run_parallel(
    workspace: &Workspace,
    projects: &[&str],
    command: &str,
    args: &[String],
) -> Result<()> {
    let mut queue = DependencyQueue::new(workspace, projects)?;
    let selected: HashSet<&str> = projects.iter().copied().collect();
    let mut failed_projects = HashSet::new();
    let mut running = tokio::task::JoinSet::new();
    let worker_limit = std::thread::available_parallelism()
        .map_or(2, std::num::NonZeroUsize::get)
        .clamp(2, 32);
    let mut success = 0;
    let mut failed = 0;

    loop {
        while running.len() < worker_limit
            && let Some(name) = queue.ready.pop_first()
        {
            let project = &workspace.projects[name];
            if dependency_failed(project, &selected, &failed_projects) {
                println!(
                    "{} {} {}",
                    style::error("✗"),
                    style::package(&consent_text(name)),
                    style::dim("skipped because a dependency failed")
                );
                failed_projects.insert(name.to_owned());
                failed += 1;
                queue.completed(name)?;
                continue;
            }

            // One coordinator owns the consent prompts. Child processes run
            // on the blocking pool and report completion independently.
            let prepared = prepare_project_command(&project.path, project, command, args);
            let name = name.to_owned();
            running.spawn_blocking(move || (name, prepared.and_then(PreparedProjectCommand::run)));
        }

        let Some(result) = running.join_next().await else {
            anyhow::ensure!(
                queue.remaining.is_empty(),
                "Circular dependency detected while scheduling workspace tasks"
            );
            break;
        };
        let (name, result) = result?;
        queue.completed(&name)?;
        match result {
            Ok(()) => {
                println!(
                    "{} {} {}",
                    style::success("✓"),
                    style::package(&consent_text(&name)),
                    style::dim("completed")
                );
                success += 1;
            }
            Err(error) => {
                println!(
                    "{} {} {error}",
                    style::error("✗"),
                    style::package(&consent_text(&name))
                );
                failed_projects.insert(name);
                failed += 1;
            }
        }
    }

    print_summary(command, success, failed)
}

struct PreparedProjectCommand {
    command: std::process::Command,
    label: String,
    path: String,
}

impl PreparedProjectCommand {
    fn run(mut self) -> Result<()> {
        let status = self
            .command
            .status()
            .with_context(|| format!("Failed to execute '{}' in '{}'", self.label, self.path))?;
        anyhow::ensure!(
            status.success(),
            "'{}' in '{}' exited with code {}",
            self.label,
            self.path,
            status.code().unwrap_or(-1)
        );
        Ok(())
    }
}

fn run_project_command(
    path: &str,
    project: &WorkspaceProject,
    command: &str,
    args: &[String],
) -> Result<()> {
    prepare_project_command(path, project, command, args)?.run()
}

fn prepare_project_command(
    path: &str,
    project: &WorkspaceProject,
    command: &str,
    args: &[String],
) -> Result<PreparedProjectCommand> {
    // Check for custom command first
    if let Some(custom_cmd) = project.commands.get(command) {
        // Repo-defined shell: ask before running it in an attended
        // terminal. Automation without a terminal keeps working, and the
        // command is always echoed so logs show what ran.
        println!(
            "  {} Running repo-defined command: {}",
            style::arrow("→"),
            consent_text(custom_cmd)
        );
        // Fail closed without a terminal: a planted workspace file must not
        // auto-execute in CI. Only an explicit --yes opts in.
        if !console::user_attended() && !crate::core::privilege::get_yes_flag() {
            anyhow::bail!(
                "Refusing to run '{command}' from the workspace file in '{path}' without an interactive terminal (re-run with --yes to allow it explicitly)"
            );
        }
        if console::user_attended()
            && !dialoguer::Confirm::new()
                .with_prompt(consent_prompt(command, path))
                .default(false)
                .interact()?
        {
            anyhow::bail!("Cancelled '{command}' in '{path}'");
        }
        // POSIX sh: operands after the -c command string become positional
        // parameters ($1, "$@", ...) inside the script, so extra args reach the
        // command without ad-hoc shell quoting of interpolated values.
        // https://pubs.opengroup.org/onlinepubs/9699919799/utilities/sh.html
        let mut process = std::process::Command::new("sh");
        process
            .arg("-c")
            .arg(custom_cmd)
            .arg("sh")
            .args(args)
            .current_dir(path);
        return Ok(PreparedProjectCommand {
            command: process,
            label: consent_text(command),
            path: consent_text(path),
        });
    }

    Ok(PreparedProjectCommand {
        command: workspace_task_command(Path::new(path), command, args)?,
        label: format!("omg run {}", consent_text(command)),
        path: consent_text(path),
    })
}

fn workspace_task_command(
    project: &Path,
    task: &str,
    args: &[String],
) -> Result<std::process::Command> {
    let binary = std::env::current_exe().context("Could not locate the running omg binary")?;
    let mut command = std::process::Command::new(binary);
    command.arg("run").arg(task).args(args).current_dir(project);
    Ok(command)
}

/// Text rendered from project-controlled strings in the consent UI.
///
/// Workspace files and project paths are repository data: OSC/CSI escape
/// sequences could otherwise redraw the terminal and spoof the yes/no
/// consent preview for the command about to run.
fn consent_text(text: &str) -> String {
    style::sanitize_terminal_text(text)
}

/// The yes/no prompt shown before a repo-defined command runs.
fn consent_prompt(command: &str, path: &str) -> String {
    format!(
        "Run '{}' from the workspace file in '{}'?",
        consent_text(command),
        consent_text(path)
    )
}

fn load_project_lock(project: &Path) -> Result<EnvironmentState> {
    EnvironmentState::load(project.join("omg.lock")).map_err(|error| {
        if is_missing(&error) {
            error.context("No omg.lock file found")
        } else {
            error
        }
    })
}

/// Show environment diff across workspace
pub fn diff(branch: &str) -> Result<()> {
    let workspace = Workspace::load()?;
    validate_git_revision(branch)?;

    println!(
        "{} Comparing workspace environments vs {}\n",
        style::header("OMG"),
        consent_text(branch)
    );
    let mut names: Vec<_> = workspace.projects.keys().collect();
    names.sort_unstable();
    let mut failed = 0;
    for name in names {
        let project = Path::new(&workspace.projects[name].path);
        println!(
            "{} {}",
            style::arrow("→"),
            style::package(&consent_text(name))
        );
        match git_lockfile_diff(project, branch) {
            Ok(None) => println!("  {}", style::dim("No omg.lock file")),
            Ok(Some((0, 0))) => println!("  {}", style::success("No changes")),
            Ok(Some((added, removed))) => println!(
                "  {} +{added} lines, -{removed} lines",
                style::warning("Changes:")
            ),
            Err(error) => {
                eprintln!("  {}", consent_text(&format!("{error:#}")));
                failed += 1;
            }
        }
        println!();
    }
    anyhow::ensure!(
        failed == 0,
        "{failed} project(s) failed to compare environment lockfiles"
    );
    Ok(())
}

fn validate_git_revision(branch: &str) -> Result<()> {
    anyhow::ensure!(
        !branch.trim_start().starts_with('-'),
        "Git branch or revision must not begin with '-'"
    );
    Ok(())
}

fn git_inspection_command() -> Result<std::process::Command> {
    let mut command = crate::core::privilege::system_command("git")?;
    command
        .arg("--no-replace-objects")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_OPTIONAL_LOCKS", "0");
    for variable in [
        "GIT_DIR",
        "GIT_COMMON_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ] {
        command.env_remove(variable);
    }
    Ok(command)
}

fn git_lockfile_diff(project_path: &Path, branch: &str) -> Result<Option<(usize, usize)>> {
    validate_git_revision(branch)?;
    let metadata = project_path
        .metadata()
        .with_context(|| format!("Missing project directory: {}", project_path.display()))?;
    anyhow::ensure!(
        metadata.is_dir(),
        "Project path is not a directory: {}",
        project_path.display()
    );
    let current = match read_lockfile(&project_path.join("omg.lock")) {
        Ok(current) => Some(current),
        Err(error) if is_missing(&error) => None,
        Err(error) => return Err(error),
    };

    // A project without Git or a working lockfile has no environment diff.
    if current.is_none()
        && !std::env::current_dir()?
            .join(project_path)
            .ancestors()
            .any(|path| path.join(".git").symlink_metadata().is_ok())
    {
        return Ok(None);
    }
    let reference = read_reference_lock(project_path, branch).with_context(|| {
        format!(
            "git diff failed in {} against {branch}",
            project_path.display()
        )
    })?;
    match (reference.as_deref(), current.as_deref()) {
        (None, None) => Ok(None),
        (None, Some(current)) => Ok(Some((current.lines().count(), 0))),
        (Some(reference), None) => Ok(Some((0, reference.lines().count()))),
        (Some(reference), Some(current)) if reference == current => Ok(Some((0, 0))),
        (Some(reference), Some(current)) => count_changed_lines(reference, current).map(Some),
    }
}

fn read_reference_lock(project_path: &Path, branch: &str) -> Result<Option<String>> {
    let tree = git_inspection_command()?
        .args([
            "ls-tree",
            "-l",
            "-z",
            &format!("{branch}^{{tree}}"),
            "--",
            "omg.lock",
        ])
        .current_dir(project_path)
        .output()
        .context("Failed to inspect the reference Git tree")?;
    anyhow::ensure!(
        tree.status.success(),
        "{}",
        String::from_utf8_lossy(&tree.stderr).trim()
    );
    if tree.stdout.is_empty() {
        return Ok(None);
    }
    let entry = std::str::from_utf8(&tree.stdout)?;
    let (fields, path) = entry.split_once('\t').context("Invalid Git tree entry")?;
    let fields: Vec<_> = fields.split_ascii_whitespace().collect();
    let [mode, kind, object, size] = fields.as_slice() else {
        anyhow::bail!("Invalid Git tree entry for omg.lock");
    };
    anyhow::ensure!(path == "omg.lock\0", "Invalid reference path for omg.lock");
    anyhow::ensure!(
        matches!(*mode, "100644" | "100755") && *kind == "blob",
        "Reference omg.lock must be a regular file"
    );
    anyhow::ensure!(
        matches!(object.len(), 40 | 64) && object.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Invalid Git object for omg.lock"
    );
    let size = size
        .parse::<u64>()
        .context("Invalid reference omg.lock size")?;
    anyhow::ensure!(
        size <= MAX_LOCKFILE_BYTES,
        "Reference omg.lock exceeds the {MAX_LOCKFILE_BYTES} byte limit"
    );

    let blob = git_inspection_command()?
        .args(["cat-file", "blob", object])
        .current_dir(project_path)
        .output()
        .context("Failed to read the reference Git lockfile")?;
    anyhow::ensure!(
        blob.status.success(),
        "{}",
        String::from_utf8_lossy(&blob.stderr).trim()
    );
    anyhow::ensure!(
        blob.stdout.len() as u64 == size,
        "Reference omg.lock size changed"
    );
    String::from_utf8(blob.stdout)
        .map(Some)
        .context("Reference omg.lock is not UTF-8")
}

fn line_diff_command() -> Result<std::process::Command> {
    let mut git = git_inspection_command()?;
    git.args([
        "diff",
        "--no-index",
        "--no-ext-diff",
        "--no-textconv",
        "--numstat",
        "--text",
    ]);
    Ok(git)
}

fn count_changed_lines(old: &str, new: &str) -> Result<(usize, usize)> {
    let scratch = tempfile::tempdir().context("Failed to create private lockfile comparison")?;
    fs::write(scratch.path().join("reference.lock"), old)?;
    fs::write(scratch.path().join("working.lock"), new)?;
    let diff = line_diff_command()?
        .args(["--", "reference.lock", "working.lock"])
        .current_dir(scratch.path())
        .output()
        .context("Failed to compare lockfile lines")?;
    anyhow::ensure!(
        matches!(diff.status.code(), Some(0 | 1)),
        "{}",
        String::from_utf8_lossy(&diff.stderr).trim()
    );
    if diff.stdout.is_empty() && diff.status.success() {
        return Ok((0, 0));
    }
    let mut fields = std::str::from_utf8(&diff.stdout)?.splitn(3, '\t');
    let added = fields
        .next()
        .context("No added line count in Git diff")?
        .parse()?;
    let removed = fields
        .next()
        .context("No removed line count in Git diff")?
        .parse()?;
    Ok((added, removed))
}

/// Check all project environments without mutating them.
pub async fn check() -> Result<()> {
    let workspace = Workspace::load()?;

    println!(
        "{} Checking workspace environments...\n",
        style::header("OMG")
    );

    // Projects needing attention make the command exit nonzero so scripts can
    // distinguish a healthy workspace from an incomplete environment.
    let mut ok_count = 0usize;
    let mut attention_count = 0usize;
    let mut error_count = 0usize;

    // Sort names so output order is deterministic despite HashMap iteration
    let mut names: Vec<&String> = workspace.projects.keys().collect();
    names.sort();

    // A fingerprint describes this host and data directory. Capture it
    // only once, and only after a project supplies a usable lockfile.
    let mut current = None;
    for name in names {
        let project = Path::new(&workspace.projects[name].path);
        println!(
            "{} {}",
            style::arrow("→"),
            style::package(&consent_text(name))
        );
        match project.metadata() {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => {
                println!("  {} Project path is not a directory", style::error("✗"));
                error_count += 1;
                continue;
            }
            Err(error) => {
                println!("  {} {error}", style::error("✗"));
                error_count += 1;
                continue;
            }
        }

        let result = match load_project_lock(project) {
            Ok(expected) => {
                let captured = match &current {
                    Some(captured) => captured,
                    None => current.insert(EnvironmentState::capture().await),
                };
                match captured {
                    Ok(captured) => super::env::report_environment_check(&expected, captured),
                    Err(error) => Err(anyhow::anyhow!("{error:#}")),
                }
            }
            Err(error) => Err(error),
        };
        match result {
            Ok(()) => {
                println!("  {}", style::success("✓ checked"));
                ok_count += 1;
            }
            Err(error) => {
                eprintln!("Error: {}", consent_text(&error.to_string()));
                println!("  {}", style::warning("⚠ needs attention"));
                attention_count += 1;
            }
        }
    }

    println!();
    if attention_count == 0 && error_count == 0 {
        println!(
            "  {} All {} project environment(s) healthy",
            style::success("✓"),
            ok_count
        );
        Ok(())
    } else {
        anyhow::bail!(
            "{attention_count} project(s) need attention, {error_count} failed to check \
             (of {} total)",
            workspace.projects.len()
        )
    }
}

/// Show workspace status
pub fn status() -> Result<()> {
    let workspace = Workspace::load()?;

    println!(
        "{} Workspace Status: {}\n",
        style::header("OMG"),
        workspace.name
    );

    println!(
        "  {} {} projects",
        style::info("Projects:"),
        workspace.projects.len()
    );

    // Check each project's status
    let mut healthy = 0;
    let mut needs_attention = 0;

    // Sort names so output order is deterministic despite HashMap iteration
    let mut names: Vec<&String> = workspace.projects.keys().collect();
    names.sort();

    for name in names {
        let project = &workspace.projects[name];
        let path = Path::new(&project.path);
        let (status_icon, status_text) = match path.metadata() {
            Ok(metadata) if metadata.is_dir() => match load_project_lock(path) {
                Ok(_) => {
                    healthy += 1;
                    (style::success("●"), "ok")
                }
                Err(error) if is_missing(&error) => (style::warning("○"), "no omg.lock"),
                Err(_) => (style::warning("○"), "invalid omg.lock"),
            },
            Ok(_) => (style::error("✗"), "path is not a directory"),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                (style::error("✗"), "path not found")
            }
            Err(_) => (style::error("✗"), "cannot inspect path"),
        };
        needs_attention += usize::from(status_text != "ok");

        println!(
            "    {} {} - {}",
            status_icon,
            style::package(&consent_text(name)),
            style::dim(status_text)
        );
    }

    println!();
    println!(
        "  {} {} healthy, {} need attention",
        if needs_attention == 0 {
            style::success("✓")
        } else {
            style::warning("⚠")
        },
        healthy,
        needs_attention
    );

    Ok(())
}

/// Detect project commands based on files present
fn detect_project_commands(path: &Path) -> HashMap<String, String> {
    let mut commands = HashMap::new();

    // Node.js (package.json)
    if path.join("package.json").exists() {
        commands.insert("build".to_string(), "npm run build".to_string());
        commands.insert("test".to_string(), "npm test".to_string());
        commands.insert("lint".to_string(), "npm run lint".to_string());
    }

    // Rust (Cargo.toml)
    if path.join("Cargo.toml").exists() {
        commands.insert("build".to_string(), "cargo build".to_string());
        commands.insert("test".to_string(), "cargo test".to_string());
        commands.insert("lint".to_string(), "cargo clippy".to_string());
    }

    // Python (pyproject.toml or setup.py)
    if path.join("pyproject.toml").exists() || path.join("setup.py").exists() {
        commands.insert("test".to_string(), "pytest".to_string());
        commands.insert("lint".to_string(), "ruff check .".to_string());
    }

    // Go (go.mod)
    if path.join("go.mod").exists() {
        commands.insert("build".to_string(), "go build ./...".to_string());
        commands.insert("test".to_string(), "go test ./...".to_string());
        commands.insert("lint".to_string(), "golangci-lint run".to_string());
    }

    // Makefile
    if path.join("Makefile").exists() {
        commands.insert("build".to_string(), "make build".to_string());
        commands.insert("test".to_string(), "make test".to_string());
    }

    commands
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(path: &str, depends_on: &[&str]) -> WorkspaceProject {
        WorkspaceProject {
            path: path.to_string(),
            depends_on: depends_on.iter().map(|name| (*name).to_string()).collect(),
            commands: HashMap::new(),
        }
    }

    #[test]
    fn sorted_projects_are_dependency_first_and_deterministic() {
        let mut workspace = Workspace::default();
        workspace
            .projects
            .insert("web".to_string(), project("web", &["api"]));
        workspace
            .projects
            .insert("db".to_string(), project("db", &[]));
        workspace
            .projects
            .insert("api".to_string(), project("api", &["db"]));

        assert_eq!(workspace.sorted_projects().unwrap(), ["db", "api", "web"]);
        assert_eq!(
            dependency_levels(&workspace, &["web", "db", "api"]).unwrap(),
            vec![
                vec!["db".to_string()],
                vec!["api".to_string()],
                vec!["web".to_string()]
            ]
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn both_schedulers_skip_failed_dependents_and_run_independent_projects() {
        let _guard = YesFlagGuard(crate::core::privilege::get_yes_flag());
        crate::core::privilege::set_yes_flag(true);
        for parallel in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let mut workspace = Workspace::default();
            for (name, dependencies, command) in [
                ("bad", vec![], "exit 1"),
                ("child", vec!["bad"], "touch child"),
                ("grandchild", vec!["child"], "touch grandchild"),
                ("independent", vec![], "touch independent"),
            ] {
                let mut entry = project(name, &dependencies);
                entry.path = directory.path().display().to_string();
                entry.commands.insert("probe".into(), command.into());
                workspace.projects.insert(name.into(), entry);
            }
            let projects = ["bad", "child", "grandchild", "independent"];
            let result = if parallel {
                run_parallel(&workspace, &projects, "probe", &[]).await
            } else {
                run_sequential(&workspace, &projects, "probe", &[])
            };
            assert!(result.is_err());
            assert!(directory.path().join("independent").exists());
            assert!(
                !directory.path().join("child").exists(),
                "failed dependency ran in parallel={parallel}"
            );
            assert!(!directory.path().join("grandchild").exists());
        }
    }

    #[test]
    fn large_dependency_chain_keeps_its_order() -> Result<()> {
        const COUNT: usize = 8000;
        let mut workspace = Workspace::default();
        for index in 0..COUNT {
            let name = format!("project-{index:04}");
            let mut node = project(".", &[]);
            if index + 1 < COUNT {
                node.depends_on.push(format!("project-{:04}", index + 1));
            }
            workspace.projects.insert(name, node);
        }
        let ordered = workspace.sorted_projects()?;
        assert_eq!(ordered.len(), COUNT);
        assert_eq!(ordered.first().map(String::as_str), Some("project-7999"));
        assert_eq!(ordered.last().map(String::as_str), Some("project-0000"));
        let selected: Vec<_> = ordered.iter().map(String::as_str).collect();
        let levels = dependency_levels(&workspace, &selected)?;
        assert_eq!(levels.len(), COUNT);
        assert!(levels.into_iter().flatten().eq(ordered));
        Ok(())
    }

    #[test]
    fn independent_projects_share_a_parallel_level() {
        let mut workspace = Workspace::default();
        workspace
            .projects
            .insert("web".to_string(), project("web", &["api"]));
        workspace
            .projects
            .insert("docs".to_string(), project("docs", &[]));
        workspace
            .projects
            .insert("api".to_string(), project("api", &[]));

        assert_eq!(
            dependency_levels(&workspace, &["web", "docs", "api"]).unwrap(),
            vec![
                vec!["api".to_string(), "docs".to_string()],
                vec!["web".to_string()]
            ]
        );
    }

    /// Restores the global yes flag on drop: the refusal gate below reads
    /// process-global state, so the test must neither leak its own value
    /// nor run concurrently with other flag users.
    struct YesFlagGuard(bool);
    impl Drop for YesFlagGuard {
        fn drop(&mut self) {
            crate::core::privilege::set_yes_flag(self.0);
        }
    }

    #[test]
    #[serial_test::serial]
    fn repo_defined_command_refuses_without_terminal_or_explicit_yes() {
        let _guard = YesFlagGuard(crate::core::privilege::get_yes_flag());
        crate::core::privilege::set_yes_flag(false);
        let directory = tempfile::tempdir().expect("temp directory");
        let mut commands = HashMap::new();
        commands.insert("evil".to_string(), "touch pwned".to_string());
        let project = WorkspaceProject {
            path: directory.path().to_string_lossy().into_owned(),
            depends_on: Vec::new(),
            commands,
        };
        let error = run_project_command(&directory.path().to_string_lossy(), &project, "evil", &[])
            .expect_err("unattended repo-defined commands must refuse without --yes");
        assert!(error.to_string().contains("Refusing"));
        assert!(!directory.path().join("pwned").exists());
    }

    #[test]
    #[serial_test::serial]
    fn repo_defined_command_allows_explicit_yes_without_terminal() {
        let _guard = YesFlagGuard(crate::core::privilege::get_yes_flag());
        crate::core::privilege::set_yes_flag(true);
        let directory = tempfile::tempdir().expect("temp directory");
        let mut commands = HashMap::new();
        commands.insert("ok".to_string(), "exit 0".to_string());
        let project = WorkspaceProject {
            path: directory.path().to_string_lossy().into_owned(),
            depends_on: Vec::new(),
            commands,
        };
        run_project_command(&directory.path().to_string_lossy(), &project, "ok", &[])
            .expect("explicit --yes must allow unattended repo-defined commands");
    }

    #[test]
    fn git_diff_rejects_option_injection_before_spawning_git() {
        let directory = tempfile::tempdir().expect("temp directory");
        let output = directory.path().join("injected-output");
        let branch = format!("--output={}", output.display());

        let error = git_lockfile_diff(directory.path(), &branch)
            .expect_err("option-like revisions must be rejected");

        assert!(error.to_string().contains("must not begin with '-'"));
        assert!(!output.exists());
    }

    #[test]
    #[cfg(unix)]
    fn git_inspection_uses_a_trusted_program_and_disables_external_filters() {
        let command = line_diff_command().expect("trusted Git");
        assert!(Path::new(command.get_program()).is_absolute());
        let arguments: Vec<_> = command.get_args().collect();
        assert!(arguments.contains(&std::ffi::OsStr::new("--no-ext-diff")));
        assert!(arguments.contains(&std::ffi::OsStr::new("--no-textconv")));
        assert!(command.get_envs().any(|(key, value)| key == "PATH"
            && value == Some(std::ffi::OsStr::new(crate::core::privilege::SYSTEM_PATH))));
    }

    #[test]
    fn git_diff_failures_are_not_reported_as_no_changes() {
        let directory = tempfile::tempdir().expect("temp directory");
        fs::write(directory.path().join("omg.lock"), "fixture lock").expect("working lockfile");

        let error = git_lockfile_diff(directory.path(), "main")
            .expect_err("a non-repository must fail instead of returning an empty diff");

        assert!(error.to_string().contains("git diff failed"), "{error}");
    }

    /// A planted workspace file must not be able to redraw the terminal or
    /// fake the consent preview with OSC/CSI sequences.
    #[test]
    fn consent_prompt_neutralizes_control_sequences() {
        for (command, path) in [
            ("build\u{1b}]0;pwned\u{7}", "api"),
            ("build", "api\u{1b}[2Jfake prompt"),
            ("\u{1b}]8;;http://evil\u{1b}\\click", "x\u{202e}spoof"),
        ] {
            let prompt = consent_prompt(command, path);
            assert!(!prompt.contains('\u{1b}'), "prompt: {prompt:?}");
            assert!(!prompt.contains('\u{7}'), "prompt: {prompt:?}");
            assert!(!prompt.contains('\u{202e}'), "prompt: {prompt:?}");
            // The echoed command text goes through the same filter.
            assert!(!consent_text(command).contains('\u{1b}'));
        }
    }

    #[test]
    fn workspace_task_command_uses_the_running_binary_without_a_path_lookup() -> Result<()> {
        let project = tempfile::tempdir()?;
        let args = ["one value".to_owned()];
        let command = workspace_task_command(project.path(), "build", &args)?;
        assert_eq!(command.get_program(), std::env::current_exe()?.as_os_str());
        assert_eq!(command.get_current_dir(), Some(project.path()));
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["run", "build", "one value"]
        );
        Ok(())
    }
}
