use crate::cli::{CliContext, LocalCommandRunner, ToolCommands};
use anyhow::{Context, Result};
use console::user_attended;
use dialoguer::{Select, theme::ColorfulTheme};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read as _;
#[cfg(unix)]
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cli::style;

const ALLOW_NPM_SCRIPTS_ENV: &str = "OMG_TOOL_DANGEROUSLY_ALLOW_ALL_NPM_SCRIPTS";
const ALLOW_PIP_SDISTS_ENV: &str = "OMG_TOOL_ALLOW_PIP_SDISTS";
const ALLOW_CARGO_UNLOCKED_ENV: &str = "OMG_TOOL_ALLOW_CARGO_UNLOCKED";
const ALLOW_HOST_ENV: &str = "OMG_TOOL_ALLOW_HOST_ENV";
const ALLOW_UNVERIFIED_ENV: &str = "OMG_TOOL_ALLOW_UNVERIFIED";
const ALLOW_GO_CGO_ENV: &str = "OMG_TOOL_ALLOW_GO_CGO";
const ALLOW_GO_TOOLCHAIN_ENV: &str = "OMG_TOOL_ALLOW_GO_TOOLCHAIN_DOWNLOAD";

#[cfg(unix)]
const TOOL_SYSTEM_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

fn package_is_allowed(variable: &str, package: &str) -> bool {
    std::env::var(variable).is_ok_and(|value| {
        value
            .split(',')
            .map(str::trim)
            .any(|allowed| !allowed.is_empty() && allowed == package)
    })
}

fn host_environment_is_allowed(manager: &str, package: &str) -> bool {
    package_is_allowed(ALLOW_HOST_ENV, &format!("{manager}:{package}"))
}

fn restrict_manager_process(command: &mut Command) {
    // Package-manager builds are non-interactive children of OMG. Closing
    // stdin prevents publisher-controlled install hooks from borrowing the
    // caller's terminal to request credentials or sudo authentication.
    command.stdin(std::process::Stdio::null());
}

#[cfg(target_os = "linux")]
fn restricted_manager_command(
    program: impl AsRef<std::ffi::OsStr>,
    staging_dir: &Path,
) -> Result<Command> {
    let mut command = manager_command(
        crate::core::privilege::trusted_program("setpriv")?,
        staging_dir,
    );
    command
        .arg("--no-new-privs")
        .arg("--")
        .arg(program.as_ref());
    Ok(command)
}

#[cfg(not(target_os = "linux"))]
fn restricted_manager_command(
    program: impl AsRef<std::ffi::OsStr>,
    staging_dir: &Path,
) -> Result<Command> {
    Ok(manager_command(program, staging_dir))
}

fn validate_managed_package(manager: &str, package: &str) -> Result<()> {
    crate::core::security::validate_package_name(package)?;
    let registry_name = |value: &str| {
        !value.is_empty()
            && value
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "-_.+".contains(character))
    };
    let valid = match manager {
        "npm" => {
            package
                .strip_prefix('@')
                .and_then(|value| value.split_once('/'))
                .is_some_and(|(scope, name)| registry_name(scope) && registry_name(name))
                || (!package.contains('/') && !package.contains('@') && registry_name(package))
        }
        "cargo" | "pip" | "pacman" => {
            !package.contains('/') && !package.contains('@') && registry_name(package)
        }
        "go" => {
            let (module, version) = package
                .rsplit_once('@')
                .map_or((package, None), |(module, version)| (module, Some(version)));
            module.split('/').all(registry_name)
                && version
                    .is_none_or(|version| crate::core::security::validate_version(version).is_ok())
        }
        _ => false,
    };
    if !valid {
        anyhow::bail!(
            "Invalid {manager} registry package '{package}': paths, URLs, Git shorthands, and alternate sources are not accepted by omg tool"
        );
    }
    Ok(())
}

fn active_security_overrides(manager: &str, package: &str) -> Vec<&'static str> {
    let mut active = Vec::new();
    if manager == "npm" && package_is_allowed(ALLOW_NPM_SCRIPTS_ENV, package) {
        active.push(ALLOW_NPM_SCRIPTS_ENV);
    }
    if manager == "pip" && package_is_allowed(ALLOW_PIP_SDISTS_ENV, package) {
        active.push(ALLOW_PIP_SDISTS_ENV);
    }
    if manager == "cargo" && package_is_allowed(ALLOW_CARGO_UNLOCKED_ENV, package) {
        active.push(ALLOW_CARGO_UNLOCKED_ENV);
    }
    if manager == "go" && package_is_allowed(ALLOW_GO_CGO_ENV, package) {
        active.push(ALLOW_GO_CGO_ENV);
    }
    if manager == "go" && package_is_allowed(ALLOW_GO_TOOLCHAIN_ENV, package) {
        active.push(ALLOW_GO_TOOLCHAIN_ENV);
    }
    if host_environment_is_allowed(manager, package) {
        active.push(ALLOW_HOST_ENV);
    }
    if package_is_allowed(ALLOW_UNVERIFIED_ENV, &format!("{manager}:{package}")) {
        active.push(ALLOW_UNVERIFIED_ENV);
    }
    active
}

fn write_security_receipt(staging_dir: &Path, manager: &str, package: &str) -> Result<()> {
    let host_environment = host_environment_is_allowed(manager, package);
    let unverified = package_is_allowed(ALLOW_UNVERIFIED_ENV, &format!("{manager}:{package}"));
    let npm_scripts_disabled =
        (manager == "npm").then(|| !package_is_allowed(ALLOW_NPM_SCRIPTS_ENV, package));
    let npm_signatures_verified = (manager == "npm").then_some(!unverified);
    let pip_binary_only =
        (manager == "pip").then(|| !package_is_allowed(ALLOW_PIP_SDISTS_ENV, package));
    let cargo_locked =
        (manager == "cargo").then(|| !package_is_allowed(ALLOW_CARGO_UNLOCKED_ENV, package));
    let go_checksum_database = (manager == "go").then_some(!host_environment);
    let go_cgo_disabled = (manager == "go").then(|| !package_is_allowed(ALLOW_GO_CGO_ENV, package));
    let go_local_toolchain_only =
        (manager == "go").then(|| !package_is_allowed(ALLOW_GO_TOOLCHAIN_ENV, package));
    let executable_hashes = tool_binary_hashes(staging_dir)?;
    let receipt = serde_json::json!({
        "format_version": 1,
        "manager": manager,
        "package": package,
        "source_policy": if host_environment { "host-configured" } else { "pinned-public" },
        "active_overrides": active_security_overrides(manager, package),
        "executable_sha256": executable_hashes,
        "protections": {
            "isolated_environment": !host_environment,
            "installer_stdin_closed": true,
            "linux_no_new_privs": cfg!(target_os = "linux"),
            "npm_scripts_disabled": npm_scripts_disabled,
            "npm_signatures_verified": npm_signatures_verified,
            "pip_binary_only": pip_binary_only,
            "cargo_locked": cargo_locked,
            "go_checksum_database": go_checksum_database,
            "go_cgo_disabled": go_cgo_disabled,
            "go_local_toolchain_only": go_local_toolchain_only,
        }
    });
    let content = serde_json::to_vec_pretty(&receipt).context("Serialize tool security receipt")?;
    crate::core::safe_ops::atomic_write_file_sync(
        staging_dir.join(".omg-security-receipt.json"),
        content,
    )
    .context("Write tool security receipt")
}

fn tool_binary_hashes(install_dir: &Path) -> Result<BTreeMap<String, String>> {
    let canonical_install = fs::canonicalize(install_dir)?;
    let is_venv = install_dir.join("pyvenv.cfg").is_file();
    let mut hashes = BTreeMap::new();
    for directory in tool_binary_dirs(install_dir) {
        if !crate::runtimes::common::is_valid_version_dir(&directory) {
            continue;
        }
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if is_venv && path.file_name().is_some_and(is_venv_base_tool) {
                continue;
            }
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_file() && !metadata.is_symlink() {
                continue;
            }
            let target = fs::canonicalize(&path)?;
            if !target.starts_with(&canonical_install) || !target.is_file() {
                anyhow::bail!("Cannot hash uncontained tool binary: {}", path.display());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                if fs::metadata(&target)?.permissions().mode() & 0o111 == 0 {
                    continue;
                }
            }
            let mut file = fs::File::open(&target)?;
            let mut hasher = Sha256::new();
            let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
            let relative = path.strip_prefix(install_dir).unwrap_or(&path);
            hashes.insert(
                relative.to_string_lossy().replace('\\', "/"),
                hex::encode(hasher.finalize()),
            );
        }
    }
    Ok(hashes)
}

fn tool_binary_dirs(install_dir: &Path) -> [PathBuf; 2] {
    [
        install_dir.join("bin"),
        install_dir.join("node_modules").join(".bin"),
    ]
}

fn validate_tool_binary_containment(install_dir: &Path) -> Result<()> {
    let canonical_install = fs::canonicalize(install_dir).with_context(|| {
        format!(
            "Failed to resolve staged tool directory {}",
            install_dir.display()
        )
    })?;
    let is_venv = install_dir.join("pyvenv.cfg").is_file();
    for directory in tool_binary_dirs(install_dir) {
        if !crate::runtimes::common::is_valid_version_dir(&directory) {
            continue;
        }
        for entry in fs::read_dir(&directory)? {
            let path = entry?.path();
            if is_venv && path.file_name().is_some_and(is_venv_base_tool) {
                continue;
            }
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_file() && !metadata.is_symlink() {
                continue;
            }
            let target = fs::canonicalize(&path).with_context(|| {
                format!("Tool binary entry cannot be resolved: {}", path.display())
            })?;
            if !target.starts_with(&canonical_install) {
                anyhow::bail!(
                    "Refusing tool binary entry outside its installation: {} -> {}",
                    path.display(),
                    target.display()
                );
            }
        }
    }
    Ok(())
}

/// Construct a package-manager command with a minimal environment.
///
/// Package build and lifecycle scripts inherit their manager's environment.
/// Clearing it here prevents an untrusted package from reading ambient registry,
/// Git, SSH, cloud, and CI credentials. Private registries can opt out for one
/// exact manager/package pair through `OMG_TOOL_ALLOW_HOST_ENV`.
fn secured_manager_command(
    program: impl AsRef<std::ffi::OsStr>,
    staging_dir: &Path,
    manager: &str,
    package: &str,
) -> Result<Command> {
    let allow_host_environment = host_environment_is_allowed(manager, package);

    let requested_program = Path::new(program.as_ref());
    let resolved_program = if requested_program.components().count() == 1 {
        which::which(requested_program).with_context(|| {
            format!(
                "Failed to resolve {manager} executable '{}'",
                requested_program.display()
            )
        })?
    } else {
        requested_program.to_path_buf()
    };
    let manager_bin = resolved_program
        .parent()
        .context("Package-manager executable has no parent directory")?;
    if let Ok(project_dir) = std::env::current_dir() {
        let is_project = [
            ".git",
            "package.json",
            "Cargo.toml",
            "pyproject.toml",
            "go.mod",
        ]
        .iter()
        .any(|marker| project_dir.join(marker).exists());
        if is_project
            && manager_bin.starts_with(&project_dir)
            && !manager_bin.starts_with(staging_dir)
        {
            anyhow::bail!(
                "Refusing project-local {manager} executable: {}",
                resolved_program.display()
            );
        }
    }
    let mut command = restricted_manager_command(&resolved_program, staging_dir)?;
    if allow_host_environment {
        restrict_manager_process(&mut command);
        return Ok(command);
    }
    #[cfg(unix)]
    command.current_dir("/");

    let home = staging_dir.join(".manager-home");
    let config = home.join("config");
    let cache = home.join("cache");
    let data = home.join("data");
    let temp = home.join("tmp");
    for directory in [&home, &config, &cache, &data, &temp] {
        fs::create_dir_all(directory)?;
    }

    command.env_clear();
    #[cfg(unix)]
    {
        let mut paths = vec![manager_bin.to_path_buf()];
        paths.extend(std::env::split_paths(TOOL_SYSTEM_PATH));
        command.env(
            "PATH",
            std::env::join_paths(paths).context("Manager executable path is not representable")?,
        );
    }
    #[cfg(windows)]
    if let Some(path) = std::env::var_os("PATH") {
        // Windows development builds need the discovered manager and its
        // runtime on PATH. Production OMG package installs run on Unix, where
        // the fixed root-controlled path above is enforced.
        command.env("PATH", path);
    }
    for variable in ["SystemRoot", "WINDIR", "PATHEXT"] {
        if let Some(value) = std::env::var_os(variable) {
            command.env(variable, value);
        }
    }
    command
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", &config)
        .env("XDG_CACHE_HOME", &cache)
        .env("XDG_DATA_HOME", &data)
        .env("TMPDIR", &temp)
        .env("TMP", &temp)
        .env("TEMP", &temp)
        .env("LC_ALL", "C.UTF-8")
        .env("LANG", "C.UTF-8");

    if manager == "cargo" {
        command
            .env("CARGO_HOME", home.join(".cargo"))
            .env("CARGO_NET_GIT_FETCH_WITH_CLI", "false")
            .env("CARGO_REGISTRIES_CRATES_IO_PROTOCOL", "sparse");
    }
    if manager == "pip" {
        #[cfg(unix)]
        command.env("PIP_CONFIG_FILE", "/dev/null");
        #[cfg(windows)]
        command.env("PIP_CONFIG_FILE", "NUL");
    }

    // A rustup-installed `cargo` is a proxy and still needs the existing
    // toolchain store. Cargo configuration remains isolated in the staged
    // HOME; only rustup's immutable toolchain location crosses the boundary.
    if manager == "cargo" {
        let rustup_home = std::env::var_os("RUSTUP_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .or_else(|| std::env::var_os("USERPROFILE"))
                    .map(PathBuf::from)
                    .map(|home| home.join(".rustup"))
            });
        if let Some(rustup_home) = rustup_home.filter(|path| path.is_absolute()) {
            command.env("RUSTUP_HOME", rustup_home);
        }
    }

    restrict_manager_process(&mut command);
    Ok(command)
}

/// A resolved registry entry: `(manager, package, description)`.
type RegistryEntry = (&'static str, &'static str, &'static str);

/// Resolve a registered tool name to its `(manager, package, description)`.
///
/// Returns `Some(Err(_))` for a malformed source tag so callers can report the
/// bad entry explicitly instead of failing on an opaque split error.
fn find_registry_entry(tool: &str) -> Option<anyhow::Result<RegistryEntry>> {
    TOOL_REGISTRY
        .iter()
        .find(|(name, _, _, _)| *name == tool)
        .map(|(_, source, desc, _)| {
            let (manager, pkg) = source.split_once(':').ok_or_else(|| {
                anyhow::anyhow!("Invalid registry source '{source}' for tool '{tool}'")
            })?;
            Ok((manager, pkg, *desc))
        })
}

/// Whether `name` is base-environment plumbing of a Python virtualenv rather
/// than an installed tool's entry point (`python`, pip, activate variants).
fn is_venv_base_tool(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let name = name.strip_suffix(".exe").unwrap_or(name);
    name == "pip"
        || name == "pip3"
        || name.starts_with("pip3.")
        || name.starts_with("python")
        || name.starts_with("pydoc")
        || matches!(
            name,
            "activate" | "activate.csh" | "activate.fish" | "Activate.ps1"
        )
}

/// Pick the best available CPython launcher.
///
/// PEP 394: upstream recommends `python3`, and minimal distributions may not
/// provide an unversioned `python` at all, so probe `python3` first.
/// https://peps.python.org/pep-0394/
fn python_binary() -> &'static str {
    for candidate in ["python3", "python"] {
        let available = Command::new(candidate)
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        if available {
            return candidate;
        }
    }
    "python3" // default; the venv step surfaces a clear error when missing
}

impl LocalCommandRunner for ToolCommands {
    async fn execute(&self, _ctx: &CliContext) -> Result<()> {
        match self {
            ToolCommands::Install { name } => install(name).await,
            ToolCommands::List => list(),
            ToolCommands::Remove { name } => remove(name).await,
            ToolCommands::Update { name } => update(name).await,
            ToolCommands::Search { query } => search(query),
            ToolCommands::Registry => registry(),
        }
    }
}

/// Tool registry - maps common tool names to their optimal installation source
/// Format: (name, source, description, category)
const TOOL_REGISTRY: &[(&str, &str, &str, &str)] = &[
    // System tools (pacman)
    (
        "ripgrep",
        "pacman:ripgrep",
        "Ultra-fast regex search tool",
        "search",
    ),
    ("rg", "pacman:ripgrep", "Alias for ripgrep", "search"),
    ("fd", "pacman:fd", "Fast find alternative", "search"),
    ("fzf", "pacman:fzf", "Fuzzy finder", "search"),
    ("jq", "pacman:jq", "JSON processor", "data"),
    ("yq", "pacman:yq", "YAML processor", "data"),
    ("bat", "pacman:bat", "Cat with syntax highlighting", "files"),
    ("eza", "pacman:eza", "Modern ls replacement", "files"),
    (
        "zoxide",
        "pacman:zoxide",
        "Smarter cd command",
        "navigation",
    ),
    ("delta", "pacman:git-delta", "Better git diffs", "git"),
    ("lazygit", "pacman:lazygit", "Terminal UI for git", "git"),
    (
        "htop",
        "pacman:htop",
        "Interactive process viewer",
        "system",
    ),
    ("btop", "pacman:btop", "Resource monitor", "system"),
    ("dust", "pacman:dust", "Disk usage analyzer", "system"),
    ("duf", "pacman:duf", "Disk usage/free utility", "system"),
    ("procs", "pacman:procs", "Modern ps replacement", "system"),
    (
        "hyperfine",
        "pacman:hyperfine",
        "Command benchmarking",
        "dev",
    ),
    ("tokei", "pacman:tokei", "Code statistics", "dev"),
    ("just", "pacman:just", "Command runner", "dev"),
    ("watchexec", "pacman:watchexec", "File watcher", "dev"),
    // Node.js tools (npm)
    ("tldr", "npm:tldr", "Simplified man pages", "docs"),
    ("serve", "npm:serve", "Static file server", "web"),
    (
        "http-server",
        "npm:http-server",
        "Simple HTTP server",
        "web",
    ),
    ("yarn", "npm:yarn", "Package manager", "node"),
    ("pnpm", "npm:pnpm", "Fast package manager", "node"),
    ("tsx", "npm:tsx", "TypeScript execute", "node"),
    ("nodemon", "npm:nodemon", "Node.js auto-restart", "node"),
    ("prettier", "npm:prettier", "Code formatter", "formatting"),
    ("eslint", "npm:eslint", "JavaScript linter", "linting"),
    (
        "typescript",
        "npm:typescript",
        "TypeScript compiler",
        "node",
    ),
    ("turbo", "npm:turbo", "Monorepo build system", "node"),
    ("vercel", "npm:vercel", "Vercel CLI", "deploy"),
    ("netlify-cli", "npm:netlify-cli", "Netlify CLI", "deploy"),
    (
        "wrangler",
        "npm:wrangler",
        "Cloudflare Workers CLI",
        "deploy",
    ),
    // Rust tools (cargo)
    (
        "cargo-watch",
        "cargo:cargo-watch",
        "Watch and rebuild",
        "rust",
    ),
    (
        "cargo-edit",
        "cargo:cargo-edit",
        "Cargo add/rm/upgrade",
        "rust",
    ),
    (
        "cargo-expand",
        "cargo:cargo-expand",
        "Macro expansion",
        "rust",
    ),
    (
        "cargo-nextest",
        "cargo:cargo-nextest",
        "Fast test runner",
        "rust",
    ),
    (
        "cargo-audit",
        "cargo:cargo-audit",
        "Security audits",
        "rust",
    ),
    (
        "cargo-outdated",
        "cargo:cargo-outdated",
        "Check outdated deps",
        "rust",
    ),
    ("diesel", "cargo:diesel_cli", "Diesel ORM CLI", "rust"),
    ("sqlx", "cargo:sqlx-cli", "SQLx CLI", "rust"),
    ("bacon", "cargo:bacon", "Background code checker", "rust"),
    (
        "sccache",
        "cargo:sccache",
        "Shared compilation cache",
        "rust",
    ),
    // Python tools (pip)
    ("yt-dlp", "pip:yt-dlp", "Video downloader", "media"),
    ("glances", "pip:glances", "System monitor", "system"),
    ("httpie", "pip:httpie", "HTTP client", "web"),
    ("black", "pip:black", "Python formatter", "python"),
    ("ruff", "pip:ruff", "Fast Python linter", "python"),
    ("mypy", "pip:mypy", "Python type checker", "python"),
    ("poetry", "pip:poetry", "Python packaging", "python"),
    ("pipx", "pip:pipx", "Install Python apps", "python"),
    ("rich-cli", "pip:rich-cli", "Rich text in terminal", "cli"),
    // Go tools
    (
        "hey",
        "go:github.com/rakyll/hey",
        "HTTP load generator",
        "web",
    ),
    (
        "dive",
        "go:github.com/wagoodman/dive",
        "Docker image explorer",
        "docker",
    ),
    (
        "lazydocker",
        "go:github.com/jesseduffield/lazydocker",
        "Docker TUI",
        "docker",
    ),
    (
        "glow",
        "go:github.com/charmbracelet/glow",
        "Markdown renderer",
        "docs",
    ),
    ("air", "go:github.com/cosmtrek/air", "Go live reload", "go"),
    (
        "golangci-lint",
        "go:github.com/golangci/golangci-lint/cmd/golangci-lint",
        "Go linter",
        "go",
    ),
];

#[must_use]
pub fn registry_tool_names() -> Vec<String> {
    TOOL_REGISTRY
        .iter()
        .map(|(name, _, _, _)| (*name).to_string())
        .collect()
}

pub fn installed_tool_names() -> Result<Vec<String>> {
    let (tools_dir, _bin_dir) = get_dirs();
    installed_tool_names_in(&tools_dir)
}

fn installed_tool_names_in(tools_dir: &Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    let mut legacy_registry_paths = std::collections::HashSet::new();

    for (name, _, _, _) in TOOL_REGISTRY {
        let Some(entry) = find_registry_entry(name) else {
            continue;
        };
        let (manager, package, _) = entry?;
        if manager == "pacman" {
            continue;
        }
        let current = tools_dir.join(manager).join(name);
        let legacy = tools_dir.join(manager).join(package);
        if current.is_dir() || legacy.is_dir() {
            names.push((*name).to_string());
        }
        if current != legacy {
            legacy_registry_paths.insert(legacy);
        }
    }

    for manager in ["cargo", "npm", "pip", "go"] {
        let manager_dir = tools_dir.join(manager);
        let entries = match fs::read_dir(&manager_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("Failed to list managed tools in {}", manager_dir.display())
                });
            }
        };
        for entry in entries {
            let entry = entry.with_context(|| {
                format!(
                    "Failed to read managed tool entry in {}",
                    manager_dir.display()
                )
            })?;
            let path = entry.path();
            // Hidden siblings (.name.staging-*, .name.backup-*) are transient
            // install-swap directories, never installed tools.
            let hidden = entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with('.'));
            if hidden || legacy_registry_paths.contains(&path) || !looks_like_tool_install(&path) {
                continue;
            }
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
    }

    names.sort();
    names.dedup();
    Ok(names)
}

fn looks_like_tool_install(path: &Path) -> bool {
    path.is_dir()
        && (path.join("bin").is_dir()
            || path.join("node_modules/.bin").is_dir()
            || path.join("pyvenv.cfg").is_file())
}

/// Unique suffix for transient staging/backup install directories.
fn unique_install_suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{}-{nanos}", std::process::id())
}

/// Spawn configuration for a package-manager command.
///
/// cargo and npm discover configuration by walking up from the current
/// working directory, so running an install from inside a project would let
/// that project's `.cargo/config.toml` or `.npmrc` inject build settings,
/// source replacements, and environment into a tool build executed with the
/// user's trust. Commands are therefore always rooted at the isolated
/// staging directory, never at (or below) the user's project.
fn manager_command(program: impl AsRef<std::ffi::OsStr>, staging_dir: impl AsRef<Path>) -> Command {
    let mut command = Command::new(program);
    command.current_dir(staging_dir);
    command
}

/// Base directories
fn get_dirs() -> (PathBuf, PathBuf) {
    let data_dir = crate::core::paths::data_dir();
    let tools_dir = data_dir.join("tools");
    let bin_dir = data_dir.join("bin"); // This should be in PATH via omg hook
    (tools_dir, bin_dir)
}

pub async fn install(name: &str) -> Result<()> {
    // SECURITY: Validate tool name
    crate::core::security::validate_package_name(name)?;

    println!(
        "{} Installing tool '{}'...",
        style::header("OMG Tool"),
        style::package(name)
    );

    let (tools_dir, bin_dir) = get_dirs();
    crate::core::paths::create_private_data_directory(&tools_dir)?;
    crate::core::paths::create_private_data_directory(&bin_dir)?;

    // 1. Check Registry
    if let Some(resolved) = find_registry_entry(name) {
        let (manager, pkg, desc) = resolved?;
        println!(
            "{} Found in registry: {} ({})",
            style::success("✓"),
            style::package(pkg),
            style::info(manager)
        );
        println!("  {} {}", style::dim("→"), desc);
        return install_managed(manager, pkg, name, &tools_dir, &bin_dir).await;
    }

    // 2. Interactive Fallback
    // In test mode or non-interactive terminals, fail immediately
    if !user_attended() || crate::core::paths::test_mode() {
        anyhow::bail!(
            "Tool '{name}' not in registry. Re-run in an interactive shell to choose a source.\n\
             Available sources: Pacman, Cargo, NPM, Pip, Go\n\
             Example: omg install {name}  # for system installation"
        );
    }
    let choices = [
        "Pacman (System)",
        "Cargo (Isolated)",
        "NPM (Isolated)",
        "Pip (Isolated)",
        "Go (Isolated)",
    ];
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt(format!("Tool '{name}' not in registry. Source?"))
        .default(0)
        .items(choices.as_slice())
        .interact()?;

    match selection {
        0 => crate::cli::packages::install(&[name.to_string()], false, false, false).await,
        1 => install_managed("cargo", name, name, &tools_dir, &bin_dir).await,
        2 => install_managed("npm", name, name, &tools_dir, &bin_dir).await,
        3 => install_managed("pip", name, name, &tools_dir, &bin_dir).await,
        4 => install_managed("go", name, name, &tools_dir, &bin_dir).await,
        _ => Ok(()),
    }
}

async fn install_managed(
    manager: &str,
    pkg: &str,
    install_name: &str,
    tools_dir: &Path,
    bin_dir: &Path,
) -> Result<()> {
    crate::core::security::validate_package_name(install_name)?;
    validate_managed_package(manager, pkg)?;
    // Keep storage flat and keyed by the user-facing registry name. Package
    // identifiers such as Go module paths are installer inputs, not paths.
    let install_dir = tools_dir.join(manager).join(install_name);
    let has_previous_install = match fs::symlink_metadata(&install_dir) {
        Ok(metadata) if metadata.is_dir() => true,
        Ok(_) => {
            anyhow::bail!(
                "Refusing to replace non-directory tool path: {}",
                install_dir.display()
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "Failed to inspect existing tool path {}",
                    install_dir.display()
                )
            });
        }
    };

    if manager == "pacman" {
        // Pacman installs globally, breaks isolation pattern but is preferred for OS tools
        // We just delegate and return
        return crate::cli::packages::install(&[pkg.to_string()], false, false, false).await;
    }

    for variable in active_security_overrides(manager, pkg) {
        eprintln!(
            "{} {variable} weakens install security for {manager}:{pkg}",
            style::warning("Security override:")
        );
    }

    // Stage the new version in a hidden sibling directory so a failed install
    // never destroys the previously working tool (W4-A-01): the old install is
    // only replaced after the package manager has succeeded.
    let staging_dir = tools_dir.join(manager).join(format!(
        ".{install_name}.staging-{}",
        unique_install_suffix()
    ));
    fs::create_dir_all(&staging_dir)?;

    let pb = style::spinner(&format!("Installing {pkg} via {manager}..."));

    // The closure keeps `?`/`bail!` exits inside `outcome` so the staging
    // directory is always cleaned up on failure.
    let run_install = || -> Result<()> {
        match manager {
            "npm" => {
                // Lifecycle scripts are publisher-controlled code. Keep them
                // disabled unless this exact package is explicitly approved.
                let install_path = staging_dir
                    .to_str()
                    .context("Install directory path contains invalid UTF-8")?;
                let allow_scripts = package_is_allowed(ALLOW_NPM_SCRIPTS_ENV, pkg);
                let allow_host_environment = host_environment_is_allowed(manager, pkg);
                let mut command = secured_manager_command("npm", &staging_dir, manager, pkg)?;
                command.args(["install", "--prefix", install_path]);
                if !allow_host_environment {
                    command.arg("--registry=https://registry.npmjs.org/");
                }
                // Download and materialize the tree without executing it. An
                // approved script phase happens only after signature checks.
                command.arg("--ignore-scripts");
                let status = command
                    .args(["--", pkg])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::inherit())
                    .status()?;

                if !status.success() {
                    anyhow::bail!(
                        "NPM install of '{pkg}' failed. If the reviewed package requires lifecycle scripts, retry with {ALLOW_NPM_SCRIPTS_ENV}={pkg}"
                    );
                }
                if !package_is_allowed(ALLOW_UNVERIFIED_ENV, &format!("npm:{pkg}")) {
                    let mut verification =
                        secured_manager_command("npm", &staging_dir, manager, pkg)?;
                    verification.args(["audit", "signatures", "--prefix", install_path]);
                    if !allow_host_environment {
                        verification.arg("--registry=https://registry.npmjs.org/");
                    }
                    let signature_status = verification
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::inherit())
                        .status()?;
                    if !signature_status.success() {
                        anyhow::bail!(
                            "NPM signature/provenance verification failed for '{pkg}'; refusing to activate it. A trusted private registry without signature support can be scoped with {ALLOW_UNVERIFIED_ENV}=npm:{pkg}"
                        );
                    }
                }
                if allow_scripts {
                    let rebuild_status =
                        secured_manager_command("npm", &staging_dir, manager, pkg)?
                            .args(["rebuild", "--prefix", install_path])
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::inherit())
                            .status()?;
                    if !rebuild_status.success() {
                        anyhow::bail!(
                            "NPM lifecycle-script rebuild failed for '{pkg}'; refusing to activate it"
                        );
                    }
                }
                Ok(())
            }
            "cargo" => {
                let install_path = staging_dir
                    .to_str()
                    .context("Install directory path contains invalid UTF-8")?;
                let mut command = secured_manager_command("cargo", &staging_dir, manager, pkg)?;
                command.args(["install", "--root", install_path]);
                if !package_is_allowed(ALLOW_CARGO_UNLOCKED_ENV, pkg) {
                    command.arg("--locked");
                }
                let status = command
                    .args(["--", pkg])
                    .stdout(std::process::Stdio::null()) // Cargo is noisy
                    .status()?;

                if !status.success() {
                    anyhow::bail!(
                        "Cargo install of '{pkg}' failed. If the reviewed crate does not publish Cargo.lock, retry with {ALLOW_CARGO_UNLOCKED_ENV}={pkg}"
                    );
                }
                Ok(())
            }
            "pip" => {
                // 1. Create venv (PEP 394-aware launcher resolution, see python_binary)
                let install_path = staging_dir
                    .to_str()
                    .context("Install directory path contains invalid UTF-8")?;
                let status_venv =
                    secured_manager_command(python_binary(), &staging_dir, manager, pkg)?
                        .args(["-m", "venv", "--", install_path])
                        .status()?;

                if !status_venv.success() {
                    anyhow::bail!("Failed to create python venv at '{install_path}'");
                }

                // 2. Install into venv
                let pip_path = staging_dir.join("bin").join("pip");
                let mut command = secured_manager_command(&pip_path, &staging_dir, manager, pkg)?;
                command.args(["install", "--disable-pip-version-check"]);
                if !host_environment_is_allowed(manager, pkg) {
                    command.args(["--index-url", "https://pypi.org/simple"]);
                }
                if !package_is_allowed(ALLOW_PIP_SDISTS_ENV, pkg) {
                    command.arg("--only-binary=:all:");
                }
                let status_install = command
                    .args(["--", pkg])
                    .stdout(std::process::Stdio::null())
                    .status()?;

                if !status_install.success() {
                    anyhow::bail!(
                        "Pip install of '{pkg}' failed. If the reviewed package has no wheel, retry with {ALLOW_PIP_SDISTS_ENV}={pkg}"
                    );
                }
                Ok(())
            }
            "go" => {
                // GOBIN=<dir>/bin go install <pkg>@latest
                let target = if pkg.contains('@') {
                    pkg.to_string()
                } else {
                    format!("{pkg}@latest")
                };

                // Go installs to $GOBIN
                let go_bin = staging_dir.join("bin");
                fs::create_dir_all(&go_bin)?;

                let mut command = secured_manager_command("go", &staging_dir, manager, pkg)?;
                command
                    .arg("install")
                    .args(["--", &target])
                    .env("GOBIN", &go_bin);
                if !host_environment_is_allowed(manager, pkg) {
                    command
                        .env("GOPROXY", "https://proxy.golang.org")
                        .env("GOSUMDB", "sum.golang.org")
                        .env("GOPRIVATE", "")
                        .env("GONOPROXY", "")
                        .env("GONOSUMDB", "")
                        .env("GOENV", "off");
                }
                if !package_is_allowed(ALLOW_GO_CGO_ENV, pkg) {
                    command.env("CGO_ENABLED", "0");
                }
                if !package_is_allowed(ALLOW_GO_TOOLCHAIN_ENV, pkg) {
                    command.env("GOTOOLCHAIN", "local");
                }
                let status = command.stdout(std::process::Stdio::null()).status()?;

                if !status.success() {
                    anyhow::bail!(
                        "Go install of '{pkg}' failed. Reviewed packages may opt into CGO with {ALLOW_GO_CGO_ENV}={pkg} or toolchain downloads with {ALLOW_GO_TOOLCHAIN_ENV}={pkg}"
                    );
                }
                Ok(())
            }
            _ => anyhow::bail!(
                "Unknown package manager '{manager}'. Supported: npm, cargo, pip, go, pacman"
            ),
        }
    };
    let outcome: Result<()> = run_install();

    if let Err(error) = outcome {
        pb.finish_and_clear();
        let _ = fs::remove_dir_all(&staging_dir);
        return Err(error);
    }

    if let Err(error) = validate_tool_binary_containment(&staging_dir) {
        pb.finish_and_clear();
        let _ = fs::remove_dir_all(&staging_dir);
        return Err(error);
    }
    if let Err(error) = write_security_receipt(&staging_dir, manager, pkg) {
        pb.finish_and_clear();
        let _ = fs::remove_dir_all(&staging_dir);
        return Err(error);
    }

    // Keep the backup until shared-bin activation also succeeds. Directory
    // promotion and command linking are one logical transaction.
    let mut backup_dir = None;
    if has_previous_install {
        let backup = tools_dir.join(manager).join(format!(
            ".{install_name}.backup-{}",
            unique_install_suffix()
        ));
        fs::rename(&install_dir, &backup).with_context(|| {
            format!("Failed to move previous install of '{install_name}' aside")
        })?;
        if let Err(error) = fs::rename(&staging_dir, &install_dir) {
            let _ = fs::rename(&backup, &install_dir);
            let _ = fs::remove_dir_all(&staging_dir);
            pb.finish_and_clear();
            return Err(error)
                .with_context(|| format!("Failed to promote staged install of '{install_name}'"));
        }
        backup_dir = Some(backup);
    } else if let Err(error) = fs::rename(&staging_dir, &install_dir) {
        let _ = fs::remove_dir_all(&staging_dir);
        pb.finish_and_clear();
        return Err(error)
            .with_context(|| format!("Failed to promote staged install of '{install_name}'"));
    }

    pb.finish_and_clear();
    println!("  {} Installation successful", style::success("✓"));
    // LINKING PHASE
    // PEP 405: a venv is identified by a pyvenv.cfg marker next to bin/.
    // Base interpreter files (python, pip, activate) in a venv are environment
    // plumbing, not the installed tool's entry points, so don't link them into
    // the shared bin dir where they would shadow system Python/pip.
    // https://peps.python.org/pep-0405/
    let is_venv = install_dir.join("pyvenv.cfg").is_file();
    if let Err(error) = link_binaries(&install_dir, bin_dir, is_venv) {
        let failed_dir = tools_dir.join(manager).join(format!(
            ".{install_name}.failed-{}",
            unique_install_suffix()
        ));
        fs::rename(&install_dir, &failed_dir)
            .context("Managed tool activation failed and rollback could not move it aside")?;
        if let Some(backup) = &backup_dir {
            fs::rename(backup, &install_dir).context(
                "Managed tool activation failed and the previous version could not be restored",
            )?;
            cleanup_broken_managed_links(bin_dir, &install_dir)?;
            let previous_is_venv = install_dir.join("pyvenv.cfg").is_file();
            let _ = link_binaries(&install_dir, bin_dir, previous_is_venv);
        } else {
            cleanup_broken_managed_links(bin_dir, &install_dir)?;
        }
        let _ = fs::remove_dir_all(&failed_dir);
        return Err(error).context("Failed to activate managed tool; previous version restored");
    }
    cleanup_broken_managed_links(bin_dir, &install_dir)?;
    if let Some(backup) = backup_dir
        && let Err(error) = fs::remove_dir_all(&backup)
    {
        tracing::warn!(path = %backup.display(), %error, "failed to remove previous tool backup");
    }

    Ok(())
}

/// Whether an existing shared-bin entry may be replaced by a new link.
///
/// The shared bin directory is exposed on PATH via the omg shell hook, so a
/// tool install must never replace commands it does not own: only symlinks
/// that point back into this package's install directory are ours to swap.
/// Regular files (the user's own scripts or real system-style installs) and
/// links into other locations are left untouched.
fn is_managed_link(dest: &Path, install_dir: &Path) -> bool {
    #[cfg(unix)]
    {
        fs::symlink_metadata(dest).is_ok_and(|metadata| {
            metadata.is_symlink()
                && fs::read_link(dest).is_ok_and(|target| {
                    target.strip_prefix(install_dir).is_ok_and(|relative| {
                        relative.components().next().is_some()
                            && relative
                                .components()
                                .all(|part| matches!(part, std::path::Component::Normal(_)))
                    })
                })
        })
    }
    #[cfg(not(unix))]
    {
        // Non-Unix installs copy files instead of symlinking; without a link
        // target there is no ownership proof, so existing entries are never
        // replaced and installs of a colliding name fail loudly below.
        !dest.exists()
    }
}

fn cleanup_broken_managed_links(bin_dir: &Path, install_dir: &Path) -> Result<()> {
    #[cfg(unix)]
    if let Ok(entries) = fs::read_dir(bin_dir) {
        for entry in entries {
            let path = entry?.path();
            if is_managed_link(&path, install_dir) && !path.exists() {
                fs::remove_file(path)?;
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (bin_dir, install_dir);
    Ok(())
}

fn link_binaries(install_dir: &Path, bin_dir: &Path, skip_venv_base_tools: bool) -> Result<()> {
    println!("  {} Linking binaries...", style::dim("→"));

    // Find binaries in standard locations within the isolated install dir
    // Standard locations: /bin, /node_modules/.bin (npm)

    let search_dirs = tool_binary_dirs(install_dir);
    let canonical_install = fs::canonicalize(install_dir)?;

    let mut linked = 0;

    for dir in search_dirs {
        if !crate::runtimes::common::is_valid_version_dir(&dir) {
            continue;
        }

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                let Some(filename) = path.file_name() else {
                    continue;
                };
                if skip_venv_base_tools && is_venv_base_tool(filename) {
                    continue;
                }
                let target = fs::canonicalize(&path)?;
                if !target.starts_with(&canonical_install) {
                    anyhow::bail!(
                        "Refusing tool binary entry outside its installation: {} -> {}",
                        path.display(),
                        target.display()
                    );
                }
                // Check if executable (heuristic)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = path.metadata()
                        && meta.permissions().mode() & 0o111 == 0
                    {
                        continue; // Not executable
                    }
                }

                let dest = bin_dir.join(filename);

                // Remove existing link only if it is one of ours
                if dest.symlink_metadata().is_ok() {
                    if !is_managed_link(&dest, install_dir) {
                        println!(
                            "    {} Refusing to replace existing command {} (not owned by this tool)",
                            style::warning("⚠"),
                            filename.to_string_lossy()
                        );
                        continue;
                    }
                    fs::remove_file(&dest)?;
                }

                // Create symlink on Unix, copy on Windows
                #[cfg(unix)]
                symlink(&path, &dest).context("Failed to symlink binary")?;
                #[cfg(not(unix))]
                std::fs::copy(&path, &dest).context("Failed to copy binary")?;

                // If the tool name matches the binary name, or if we requested a specific tool, print it
                println!(
                    "    {} Linked {}",
                    style::success("+"),
                    filename.to_string_lossy()
                );
                linked += 1;
            }
        }
    }

    if linked == 0 {
        println!("  {} No binaries found to link!", style::warning("⚠"));
        // Heuristic failed?
    } else {
        println!(
            "  {} {} binaries available in {}",
            style::success("✓"),
            linked,
            style::info(&bin_dir.to_string_lossy())
        );
    }

    Ok(())
}

pub fn list() -> Result<()> {
    let (_, bin_dir) = get_dirs();
    if !crate::runtimes::common::is_valid_version_dir(&bin_dir) {
        println!("{}", style::dim("No tools installed via omg tool."));
        return Ok(());
    }

    println!("{} Installed Tools:", style::header("OMG"));

    for entry in fs::read_dir(bin_dir)? {
        let entry = entry?;
        let path = entry.path();
        if let Ok(target) = fs::read_link(&path) {
            println!(
                "  {} {} -> {}",
                style::package(
                    &path
                        .file_name()
                        .map(|f| f.to_string_lossy())
                        .unwrap_or_default()
                ),
                style::arrow("points to"),
                style::dim(&target.to_string_lossy())
            );
        }
    }
    Ok(())
}

pub async fn remove(name: &str) -> Result<()> {
    crate::core::security::validate_package_name(name)?;

    let (tools_dir, bin_dir) = get_dirs();
    let mut candidates = Vec::new();
    if let Some(entry) = find_registry_entry(name) {
        let (manager, package, _) = entry?;
        if manager == "pacman" {
            return crate::cli::packages::remove(&[package.to_string()], false, false, false).await;
        }
        candidates.push((manager, tools_dir.join(manager).join(name)));
        let legacy = tools_dir.join(manager).join(package);
        if legacy != candidates[0].1 {
            candidates.push((manager, legacy));
        }
    } else {
        candidates.extend(
            ["cargo", "npm", "pip", "go"]
                .into_iter()
                .map(|manager| (manager, tools_dir.join(manager).join(name))),
        );
    }

    let mut found = false;
    for (manager, install_path) in candidates {
        if crate::runtimes::common::is_valid_version_dir(&install_path) {
            println!(
                "{} Removing {} from {}...",
                style::header("OMG"),
                name,
                manager
            );
            fs::remove_dir_all(&install_path)?;
            found = true;
        }
    }

    anyhow::ensure!(found, "Tool '{name}' not found in managed storage");

    // Cleanup symlinks (broken links)
    println!("  {} Cleaning symlinks...", style::dim("→"));
    match fs::read_dir(&bin_dir) {
        Ok(entries) => {
            for entry in entries {
                let path = entry?.path();
                if let Ok(target) = fs::read_link(&path)
                    && !target.exists()
                {
                    fs::remove_file(&path)?;
                    println!(
                        "    {} Removed link {}",
                        style::error("-"),
                        path.file_name()
                            .map(|f| f.to_string_lossy())
                            .unwrap_or_default()
                    );
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Failed to inspect tool links in {}", bin_dir.display()));
        }
    }

    println!("\n{}", style::success("Removal complete"));
    Ok(())
}

/// Update an installed tool to latest version
pub async fn update(name: &str) -> Result<()> {
    // SECURITY: Validate tool name (or 'all')
    if name != "all" {
        crate::core::security::validate_package_name(name)?;
    }

    let (tools_dir, bin_dir) = get_dirs();

    if name == "all" {
        println!("{} Updating all tools...\n", style::header("OMG Tool"));
        let installed = installed_tool_names()?;
        if installed.is_empty() {
            println!("{}", style::dim("No tools installed."));
            return Ok(());
        }
        let mut failed = Vec::new();
        for tool in installed {
            println!(
                "\n{} Updating {}...",
                style::dim("→"),
                style::package(&tool)
            );
            match find_registry_entry(&tool) {
                Some(Ok((manager, pkg, _))) => {
                    if let Err(error) =
                        install_managed(manager, pkg, &tool, &tools_dir, &bin_dir).await
                    {
                        println!(
                            "  {}",
                            style::error(&format!("Failed to update {tool}: {error}"))
                        );
                        failed.push(tool);
                    }
                }
                Some(Err(error)) => {
                    println!("  {}", style::error(&format!("{error}")));
                    failed.push(tool);
                }
                None => {
                    println!(
                        "  {}",
                        style::error(&format!("{tool} is not in the tool registry"))
                    );
                    failed.push(tool);
                }
            }
        }
        if failed.is_empty() {
            println!("\n{}", style::success("All tools updated!"));
            return Ok(());
        }
        anyhow::bail!(
            "Failed to update {} tool(s): {}",
            failed.len(),
            failed.join(", ")
        );
    }

    println!(
        "{} Updating tool '{}'...",
        style::header("OMG Tool"),
        style::package(name)
    );

    // Find the tool in registry or installed
    match find_registry_entry(name) {
        Some(resolved) => {
            let (manager, pkg, _) = resolved?;
            install_managed(manager, pkg, name, &tools_dir, &bin_dir).await?;
            println!("\n{}", style::success("Update complete!"));
        }
        None => {
            anyhow::bail!("Tool '{name}' not found in registry. Cannot determine update source.");
        }
    }

    Ok(())
}

/// Search for tools in the registry
pub fn search(query: &str) -> Result<()> {
    // SECURITY: Validate search query
    if query.len() > 100 {
        anyhow::bail!("Search query too long");
    }

    println!(
        "{} Searching for '{}'...\n",
        style::header("OMG Tool"),
        query
    );

    let query_lower = query.to_lowercase();
    let matches: Vec<_> = TOOL_REGISTRY
        .iter()
        .filter(|(name, _, desc, category)| {
            name.to_lowercase().contains(&query_lower)
                || desc.to_lowercase().contains(&query_lower)
                || category.to_lowercase().contains(&query_lower)
        })
        .collect();

    if matches.is_empty() {
        println!("{}", style::dim("No tools found matching your query."));
        println!("\nTry: omg tool registry  # to see all available tools");
        return Ok(());
    }

    println!("  Found {} tools:\n", matches.len());
    for (name, source, desc, category) in matches {
        let manager = source.split(':').next().unwrap_or("unknown");
        println!(
            "  {} {} {}",
            style::package(name),
            style::dim(&format!("[{category}]")),
            style::dim(&format!("via {manager}"))
        );
        println!("    {desc}\n");
    }

    println!("Install with: omg tool install <name>");
    Ok(())
}

/// Show all available tools in the registry
pub fn registry() -> Result<()> {
    println!("{} Tool Registry\n", style::header("OMG"));

    // Group by category
    let mut categories: std::collections::HashMap<&str, Vec<(&str, &str, &str)>> =
        std::collections::HashMap::new();

    for (name, source, desc, category) in TOOL_REGISTRY {
        categories
            .entry(*category)
            .or_default()
            .push((*name, *source, *desc));
    }

    let mut sorted_cats: Vec<_> = categories.keys().collect();
    sorted_cats.sort();

    for category in sorted_cats {
        let tools = &categories[category];
        println!(
            "  {} {}",
            style::info(&format!("[{category}]")),
            style::dim(&format!("({} tools)", tools.len()))
        );
        for (name, source, desc) in tools {
            let manager = source.split(':').next().unwrap_or("?");
            println!(
                "    {} {} - {}",
                style::package(name),
                style::dim(&format!("({manager})")),
                desc
            );
        }
        println!();
    }

    println!("Total: {} tools available", TOOL_REGISTRY.len());
    println!("\nInstall with: omg tool install <name>");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtualenv_activation_scripts_are_not_linkable_tools() {
        for script in ["activate", "activate.csh", "activate.fish", "Activate.ps1"] {
            assert!(is_venv_base_tool(std::ffi::OsStr::new(script)), "{script}");
        }
        assert!(!is_venv_base_tool(std::ffi::OsStr::new("reactivate")));
    }

    /// Package-manager commands must be rooted at the isolated staging
    /// directory, never at the caller's project: cargo and npm walk up from
    /// the CWD to discover `.cargo/config.toml` / `.npmrc`.
    #[test]
    fn package_manager_commands_run_from_the_staging_directory() {
        let staging = tempfile::tempdir().expect("staging directory");
        for program in ["cargo", "npm", "go", "/tmp/whatever/python3"] {
            let command = manager_command(program, staging.path());
            assert_eq!(command.get_current_dir(), Some(staging.path()), "{program}");
        }
    }

    #[test]
    fn package_exceptions_require_an_exact_comma_delimited_match() {
        temp_env::with_var(
            ALLOW_NPM_SCRIPTS_ENV,
            Some("eslint,@scope/tool, exact "),
            || {
                assert!(package_is_allowed(ALLOW_NPM_SCRIPTS_ENV, "eslint"));
                assert!(package_is_allowed(ALLOW_NPM_SCRIPTS_ENV, "@scope/tool"));
                assert!(package_is_allowed(ALLOW_NPM_SCRIPTS_ENV, "exact"));
                assert!(!package_is_allowed(ALLOW_NPM_SCRIPTS_ENV, "es"));
                assert!(!package_is_allowed(ALLOW_NPM_SCRIPTS_ENV, "tool"));
            },
        );
    }

    #[test]
    fn managed_package_grammar_rejects_alternate_sources() {
        for (manager, package) in [
            ("npm", "owner/repository"),
            ("npm", "@scope/name/extra"),
            ("pip", "relative/package"),
            ("cargo", "relative/crate"),
        ] {
            assert!(
                validate_managed_package(manager, package).is_err(),
                "{manager} accepted {package}"
            );
        }
        for (manager, package) in [
            ("npm", "eslint"),
            ("npm", "@angular/cli"),
            ("pip", "yt-dlp"),
            ("cargo", "cargo-audit"),
            ("go", "github.com/rakyll/hey"),
            ("go", "github.com/rakyll/hey@v0.1.4"),
        ] {
            validate_managed_package(manager, package)
                .unwrap_or_else(|error| panic!("{manager} rejected {package}: {error}"));
        }
    }

    #[test]
    fn host_environment_exception_is_scoped_to_manager_and_package() {
        temp_env::with_var(ALLOW_HOST_ENV, Some("npm:private-cli"), || {
            assert!(host_environment_is_allowed("npm", "private-cli"));
            assert!(!host_environment_is_allowed("cargo", "private-cli"));
            assert!(!host_environment_is_allowed("npm", "other"));
        });
    }

    #[test]
    fn active_overrides_report_only_the_matching_manager_and_package() {
        temp_env::with_vars(
            [
                (ALLOW_NPM_SCRIPTS_ENV, Some("reviewed")),
                (ALLOW_PIP_SDISTS_ENV, Some("reviewed")),
                (ALLOW_HOST_ENV, Some("npm:reviewed")),
                (ALLOW_UNVERIFIED_ENV, Some("npm:reviewed")),
                (ALLOW_GO_CGO_ENV, Some("reviewed")),
                (ALLOW_GO_TOOLCHAIN_ENV, Some("reviewed")),
            ],
            || {
                assert_eq!(
                    active_security_overrides("npm", "reviewed"),
                    vec![ALLOW_NPM_SCRIPTS_ENV, ALLOW_HOST_ENV, ALLOW_UNVERIFIED_ENV]
                );
                assert_eq!(
                    active_security_overrides("pip", "reviewed"),
                    vec![ALLOW_PIP_SDISTS_ENV]
                );
                assert_eq!(
                    active_security_overrides("go", "reviewed"),
                    vec![ALLOW_GO_CGO_ENV, ALLOW_GO_TOOLCHAIN_ENV]
                );
                assert!(active_security_overrides("npm", "other").is_empty());
            },
        );
    }

    #[test]
    fn security_receipt_records_effective_policy() {
        let staging = tempfile::tempdir().expect("staging directory");
        fs::create_dir_all(staging.path().join("bin")).expect("bin directory");
        fs::write(staging.path().join("bin/tool"), b"verified executable").expect("tool fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(
                staging.path().join("bin/tool"),
                fs::Permissions::from_mode(0o755),
            )
            .expect("executable fixture");
        }
        temp_env::with_vars(
            [
                (ALLOW_GO_CGO_ENV, Some("example.com/tool")),
                (ALLOW_GO_TOOLCHAIN_ENV, None),
                (ALLOW_HOST_ENV, None),
            ],
            || {
                write_security_receipt(staging.path(), "go", "example.com/tool")
                    .expect("security receipt");
            },
        );
        let receipt: serde_json::Value = serde_json::from_slice(
            &fs::read(staging.path().join(".omg-security-receipt.json"))
                .expect("read security receipt"),
        )
        .expect("parse security receipt");
        assert_eq!(receipt["manager"], "go");
        assert_eq!(receipt["source_policy"], "pinned-public");
        assert_eq!(receipt["protections"]["go_checksum_database"], true);
        assert_eq!(receipt["protections"]["go_cgo_disabled"], false);
        assert_eq!(receipt["protections"]["go_local_toolchain_only"], true);
        assert_eq!(receipt["protections"]["installer_stdin_closed"], true);
        assert_eq!(
            receipt["protections"]["linux_no_new_privs"],
            cfg!(target_os = "linux")
        );
        assert_eq!(
            receipt["executable_sha256"]["bin/tool"],
            hex::encode(Sha256::digest(b"verified executable"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn binary_preflight_rejects_links_outside_the_installation() {
        let staging = tempfile::tempdir().expect("staging directory");
        let external = tempfile::NamedTempFile::new().expect("external file fixture");
        let bin = staging.path().join("bin");
        fs::create_dir_all(&bin).expect("bin directory");
        symlink(external.path(), bin.join("escaped")).expect("external link fixture");
        let error = validate_tool_binary_containment(staging.path())
            .expect_err("external binary link must fail closed");
        assert!(
            error.to_string().contains("outside its installation"),
            "unexpected rejection: {error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn rollback_cleanup_removes_only_broken_links_owned_by_the_tool() {
        let temp = tempfile::tempdir().expect("temp directory");
        let install = temp.path().join("tools/npm/example");
        let bin = temp.path().join("bin");
        fs::create_dir_all(&bin).expect("bin directory");
        symlink(install.join("bin/new-only"), bin.join("new-only")).expect("managed broken link");
        symlink("/missing/foreign", bin.join("foreign")).expect("foreign broken link");

        cleanup_broken_managed_links(&bin, &install).expect("cleanup");

        assert!(fs::symlink_metadata(bin.join("new-only")).is_err());
        assert!(fs::symlink_metadata(bin.join("foreign")).is_ok());
    }

    #[test]
    fn secured_commands_use_an_isolated_home() {
        let staging = tempfile::tempdir().expect("staging directory");
        let executable = staging.path().join("bin/manager");
        fs::create_dir_all(executable.parent().expect("manager parent"))
            .expect("manager directory");
        fs::write(&executable, b"fixture").expect("manager fixture");
        let command = secured_manager_command(&executable, staging.path(), "npm", "eslint")
            .expect("secured command");
        let variables: std::collections::HashMap<_, _> = command
            .get_envs()
            .filter_map(|(name, value)| value.map(|value| (name.to_owned(), value.to_owned())))
            .collect();
        assert_eq!(
            variables.get(std::ffi::OsStr::new("HOME")),
            Some(&staging.path().join(".manager-home").into_os_string())
        );
        assert!(!variables.contains_key(std::ffi::OsStr::new("NPM_TOKEN")));
        assert!(!variables.contains_key(std::ffi::OsStr::new("SSH_AUTH_SOCK")));
        assert!(!variables.contains_key(std::ffi::OsStr::new("AWS_SECRET_ACCESS_KEY")));
        #[cfg(unix)]
        {
            assert_eq!(command.get_current_dir(), Some(Path::new("/")));
            let path = variables
                .get(std::ffi::OsStr::new("PATH"))
                .expect("isolated PATH");
            let entries: Vec<_> = std::env::split_paths(path).collect();
            assert_eq!(entries.first().map(PathBuf::as_path), executable.parent());
            assert!(entries.contains(&PathBuf::from("/usr/bin")));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn secured_commands_close_stdin_and_forbid_new_privileges() {
        let staging = tempfile::tempdir().expect("staging directory");
        let assert_restricted = || {
            let status = secured_manager_command("/bin/sh", staging.path(), "npm", "eslint")
                .expect("secured command")
                .args([
                    "-c",
                    "grep -Eq '^NoNewPrivs:[[:space:]]+1$' /proc/self/status && ! read value",
                ])
                .status()
                .expect("execute secured command");
            assert!(status.success());
        };
        assert_restricted();
        temp_env::with_var(ALLOW_HOST_ENV, Some("npm:eslint"), assert_restricted);
    }

    /// Tool installs may only swap their own package's links. Other packages,
    /// foreign symlinks and plain files must survive an install.
    #[cfg(unix)]
    #[test]
    fn linking_never_replaces_commands_omg_does_not_manage() {
        let temp = tempfile::tempdir().expect("temp directory");
        let tools_dir = temp.path().join("tools");
        let bin_dir = temp.path().join("bin");
        let install_dir = tools_dir.join("cargo").join("fake-tool");
        fs::create_dir_all(install_dir.join("bin")).expect("install fixture");

        #[cfg(unix)]
        let executable = |path: &Path, contents: &[u8]| {
            use std::os::unix::fs::PermissionsExt;
            fs::write(path, contents).expect("binary fixture");
            fs::set_permissions(path, fs::Permissions::from_mode(0o755))
                .expect("binary permissions");
        };
        #[cfg(not(unix))]
        let executable = |path: &Path, contents: &[u8]| {
            fs::write(path, contents).expect("binary fixture");
        };

        // A previous managed install's link, a foreign symlink, and a plain
        // user file all collide with binaries shipped by the new install.
        executable(&install_dir.join("bin").join("ours"), b"new");
        executable(&install_dir.join("bin").join("foreign"), b"new");
        executable(&install_dir.join("bin").join("userfile"), b"new");
        executable(&install_dir.join("bin").join("fresh"), b"new");
        executable(&install_dir.join("bin").join("upgrade"), b"upgraded");

        let previous_install = tools_dir.join("cargo").join("previous");
        fs::create_dir_all(previous_install.join("bin")).expect("previous fixture");
        executable(&previous_install.join("bin").join("ours"), b"old");

        fs::create_dir_all(&bin_dir).expect("bin fixture");
        symlink(
            previous_install.join("bin").join("ours"),
            bin_dir.join("ours"),
        )
        .expect("managed link fixture");
        symlink(
            install_dir.join("bin").join("upgrade"),
            bin_dir.join("upgrade"),
        )
        .expect("same package link fixture");
        symlink("/etc/hostname", bin_dir.join("foreign")).expect("foreign link fixture");
        fs::write(bin_dir.join("userfile"), b"user data").expect("user file fixture");

        link_binaries(&install_dir, &bin_dir, false).expect("linking");

        // Another managed package owns this name and must survive installation.
        assert_eq!(
            fs::read_link(bin_dir.join("ours")).expect("other package link preserved"),
            previous_install.join("bin").join("ours")
        );
        // Foreign symlink and user file: untouched.
        assert_eq!(
            fs::read_link(bin_dir.join("foreign")).expect("foreign link preserved"),
            PathBuf::from("/etc/hostname")
        );
        assert_eq!(
            fs::read(bin_dir.join("userfile")).expect("user file preserved"),
            b"user data"
        );
        // Unclaimed names still link.
        assert_eq!(
            fs::read_link(bin_dir.join("fresh")).expect("fresh link created"),
            install_dir.join("bin").join("fresh")
        );
        assert_eq!(
            fs::read(bin_dir.join("upgrade")).expect("same package upgrade available"),
            b"upgraded"
        );
    }

    #[cfg(unix)]
    #[test]
    fn link_replacement_requires_the_same_package_and_contained_target() {
        let temp = tempfile::tempdir().expect("temp directory");
        let install = temp.path().join("tools/cargo/package");
        let dest = temp.path().join("command");
        for (target, replaceable) in [
            (install.join("bin/command"), true),
            (install.join("../other/bin/command"), false),
            (temp.path().join("tools/npm/package/bin/command"), false),
        ] {
            symlink(target, &dest).expect("link fixture");
            assert_eq!(is_managed_link(&dest, &install), replaceable);
            fs::remove_file(&dest).expect("remove fixture");
        }
    }

    #[test]
    fn installed_names_resolve_flat_and_legacy_registry_layouts() {
        let temp = tempfile::tempdir().expect("temp directory");
        let tools = temp.path();
        for path in [
            "go/github.com/rakyll/hey/bin",
            "cargo/diesel_cli/bin",
            "go/glow/bin",
            "cargo/custom-tool/bin",
        ] {
            fs::create_dir_all(tools.join(path)).expect("tool fixture");
        }

        let names = installed_tool_names_in(tools).expect("installed names");

        assert!(names.contains(&"hey".to_string()));
        assert!(names.contains(&"diesel".to_string()));
        assert!(names.contains(&"glow".to_string()));
        assert!(names.contains(&"custom-tool".to_string()));
        assert!(!names.contains(&"github.com".to_string()));
        assert!(!names.contains(&"diesel_cli".to_string()));
    }

    /// W4-A-01 regression: a failed install must leave the previously working
    /// tool in place and runnable instead of deleting it before reinstalling.
    #[tokio::test]
    async fn failed_install_keeps_previous_tool_intact_and_runnable() {
        let temp = tempfile::tempdir().expect("temp directory");
        let tools_dir = temp.path().join("tools");
        let bin_dir = temp.path().join("bin");
        let install_dir = tools_dir.join("cargo").join("fake-tool");
        fs::create_dir_all(install_dir.join("bin")).expect("tool fixture");
        let tool_binary = install_dir.join("bin").join("fake-tool");
        fs::write(&tool_binary, "#!/bin/sh\necho previous-tool-ok\n").expect("tool fixture");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tool_binary, fs::Permissions::from_mode(0o755))
                .expect("tool fixture");
        }

        let error = install_managed(
            "cargo",
            "omg-definitely-not-a-real-crate-000",
            "fake-tool",
            &tools_dir,
            &bin_dir,
        )
        .await
        .expect_err("installing a nonexistent crate must fail");
        assert!(
            error.to_string().contains("Cargo install"),
            "error: {error}"
        );

        // The previous install survived the failed update...
        assert!(
            install_dir.is_dir(),
            "previous install must survive a failed update"
        );
        assert!(
            tool_binary.is_file(),
            "previous tool binary must survive a failed update"
        );
        // ...no staging/backup leftovers remain...
        let leftovers: Vec<std::path::PathBuf> = fs::read_dir(tools_dir.join("cargo"))
            .expect("manager dir")
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(".fake-tool."))
            })
            .collect();
        assert!(leftovers.is_empty(), "staging leftovers: {leftovers:?}");
        // ...and the tool is still runnable.
        #[cfg(unix)]
        {
            let output = Command::new(&tool_binary)
                .stdin(std::process::Stdio::null())
                .output()
                .expect("run previous tool");
            assert!(output.status.success(), "previous tool must still run");
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("previous-tool-ok"),
                "unexpected output: {:?}",
                output.stdout
            );
        }
    }
}
