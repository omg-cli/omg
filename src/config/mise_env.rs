//! mise `[env]` parity: project environment variables from `mise.toml`.
//!
//! mise supplies `[env]` entries to `mise exec`, tasks, and activated shells
//! ([`Environments`](https://mise.jdx.dev/environments/)). OMG resolves the
//! same table natively for explicit `omg run` and task execution. Automatic
//! shell hooks only select installed runtimes and never import project env.
//!
//! Supported subset (one intentional deviation each, documented below):
//! - `KEY = "value"` / `KEY = 123` — plain assignments.
//! - `KEY = false` — unset a previously set variable.
//! - `KEY = { default = "…" }` — fill in only when unset or empty.
//! - `KEY = { value = "…", tools = true }` — resolve after tool `PATH`s are
//!   computed (lazy eval); otherwise entries resolve before tools.
//! - `KEY = { value = "…", redact = true }` plus top-level
//!   `redactions = [...]` glob patterns — recorded on [`ResolvedEnv`] so
//!   output paths can mask secrets.
//! - `KEY = { required = true }` — fail when unset or empty in explicit
//!   `run`/task contexts. Automatic hooks never load these directives.
//! - `_.path` — directories prepended to `PATH` (after tool bin dirs),
//!   relative paths resolving against the declaring file's directory
//!   (mise `config_root`).
//! - `_.file` — dotenv, JSON, or TOML files merged into the environment.
//!   YAML is rejected with an explicit error (no YAML parser vendored).
//!   Missing files fail closed in strict contexts; lenient loaders warn and skip.
//! - `_.source` — shell scripts evaluated by explicit `run` and task
//!   execution via `bash -c … && env -0` snapshots. Automatic hooks ignore
//!   all project environment directives.
//! - `{{env.NAME}}` / `{{config_root}}` templates in TOML string values.
//!   Full Tera is out of scope: any other `{{…}}` is a hard error rather
//!   than a silently literal string.
//!
//! Project configuration includes local overrides, selected `MISE_ENV` layers,
//! and grouped configuration files. Encrypted-secret backends and per-plugin
//! env directives remain out of scope.

use std::collections::{HashMap, HashSet};
use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Untrusted repo input: refuse absurdly large env files before parsing.
const MAX_ENV_FILE_BYTES: u64 = 1024 * 1024;

/// What one `[env]` entry does to a variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EnvAction {
    /// Assign unconditionally.
    Set(String),
    /// Assign only when the variable is unset or empty.
    Default(String),
    /// Fail when the variable is unset or empty; never assigns.
    Required { redact: bool },
    /// Remove the variable.
    Unset,
}

/// One resolved `[env]` entry, in declaration order.
#[derive(Debug, Clone)]
pub(crate) struct EnvEntry {
    /// Variable name (validated: `[A-Za-z_][A-Za-z0-9_]*`).
    pub name: String,
    /// Assignment semantics.
    pub action: EnvAction,
    /// mise `tools = true`: resolve after tool `PATH`s are computed.
    pub tools_phase: bool,
    /// Sensitive value: mask wherever OMG echoes environments.
    pub redact: bool,
}

/// An `_.file` directive: load variables from a dotenv/JSON/TOML file.
#[derive(Debug, Clone)]
pub(crate) struct EnvFileDirective {
    /// File path; relative paths resolve against the declaring file's dir.
    pub path: PathBuf,
    /// Mark every variable loaded from this file as sensitive.
    pub redact: bool,
    /// Load after tool `PATH`s are computed.
    pub tools_phase: bool,
    /// Allow `$NAME`/`${NAME}` references to previously loaded values.
    pub expand: bool,
}

/// Parsed `[env]` table of one `mise.toml` file.
#[derive(Debug, Default, Clone)]
pub(crate) struct MiseEnv {
    /// Variable entries in declaration order.
    pub entries: Vec<EnvEntry>,
    /// `_.path` additions as `(dir, tools_phase)` in declaration order.
    pub paths: Vec<(PathBuf, bool)>,
    /// `_.file` directives in declaration order.
    pub files: Vec<EnvFileDirective>,
    /// `_.source` scripts as `(script, tools_phase)` in declaration order.
    pub sources: Vec<(PathBuf, bool)>,
    /// Top-level `redactions = [...]` glob patterns (`*` wildcards).
    pub redactions: Vec<String>,
}

/// Fully resolved environment: ordered assignments plus removals.
#[derive(Debug, Default, Clone)]
pub(crate) struct ResolvedEnv {
    /// `(name, value)` assignments in application order; later wins.
    pub set: Vec<(String, String)>,
    /// Variables to remove.
    pub unset: Vec<String>,
    /// Directories to prepend to `PATH` (after tool bin dirs), in order.
    pub path_additions: Vec<String>,
    /// `_.source` scripts to evaluate (config-root-resolved).
    pub sources: Vec<PathBuf>,
    /// Names whose values must be masked in echoed output.
    pub redacted: HashSet<String>,
}

impl ResolvedEnv {
    /// Whether `name` matches a redaction flag or glob pattern.
    fn is_redacted(name: &str, entry_redact: bool, patterns: &[String]) -> bool {
        if entry_redact {
            return true;
        }
        patterns.iter().any(|pattern| glob_match(pattern, name))
    }
}

/// `*`-only glob match used by mise `redactions` patterns.
fn glob_match(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == name;
    }
    let mut rest = name;
    if !pattern.starts_with('*') {
        let first = parts[0];
        if let Some(stripped) = rest.strip_prefix(first) {
            rest = stripped;
        } else {
            return false;
        }
    }
    for part in parts.iter().skip(1) {
        if part.is_empty() {
            continue;
        }
        match rest.find(part) {
            Some(index) => rest = &rest[index + part.len()..],
            None => return false,
        }
    }
    if !pattern.ends_with('*') {
        return rest.is_empty();
    }
    true
}

/// Repo-supplied variable names are untrusted input: only plain shell
/// identifiers are accepted, so a hostile key can never smuggle quoting or
/// whitespace into generated hook output.
pub(crate) fn validate_env_name(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !name.is_empty() && first_ok && rest_ok {
        Ok(())
    } else {
        anyhow::bail!("Invalid environment variable name: {name:?}")
    }
}

/// Overlay `PATH` for `tools = true` resolution: tool bin dirs are already
/// known while the rest of the environment is not yet resolved, so lazy
/// entries referencing `{{env.PATH}}` see the final tool-augmented value.
pub(crate) fn with_path_overlay(
    base: &HashMap<String, String>,
    tool_bins: &[String],
) -> HashMap<String, String> {
    let mut overlaid = base.clone();
    if !tool_bins.is_empty() {
        let current = base.get("PATH").cloned().unwrap_or_default();
        let joined = if current.is_empty() {
            tool_bins.join(":")
        } else {
            format!("{}:{current}", tool_bins.join(":"))
        };
        overlaid.insert("PATH".to_string(), joined);
    }
    overlaid
}

/// Expand `{{env.NAME}}` and `{{config_root}}` templates in a TOML value.
///
/// `lookup` sees already-resolved variables first, then the base environment.
/// Any other `{{…}}` is a hard error: silently leaving Tera syntax literal
/// would set a wrong value that looks right.
pub(crate) fn expand_templates(
    value: &str,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<String> {
    let mut output = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find("{{") {
        output.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            anyhow::bail!("Unclosed template expression in env value: {value:?}");
        };
        let expression = after[..end].trim();
        if let Some(var) = expression.strip_prefix("env.") {
            let var = var.trim();
            match lookup(var) {
                Some(resolved) => output.push_str(&resolved),
                None => anyhow::bail!("Unknown template variable {{{{{var}}}}} in env value"),
            }
        } else if expression == "config_root" {
            match lookup("\0config_root") {
                Some(root) => output.push_str(&root),
                None => anyhow::bail!("{{config_root}} is unavailable in this context"),
            }
        } else {
            anyhow::bail!("Unsupported template expression {{{{{expression}}}}} in env value");
        }
        rest = &after[end + 2..];
    }
    output.push_str(rest);
    Ok(output)
}

/// Expand `$NAME` / `${NAME}` against `lookup`; unknown names expand empty
/// (dotenv semantics). Used for dotenv files and `expand = true` files.
fn expand_dollar(value: &str, lookup: &dyn Fn(&str) -> Option<String>) -> String {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(char) = chars.next() {
        if char != '$' {
            output.push(char);
            continue;
        }
        match chars.peek() {
            Some('{') => {
                chars.next();
                let mut name = String::new();
                while let Some(c) = chars.next_if(|c| *c != '}') {
                    name.push(c);
                }
                if chars.next().is_none() {
                    output.push_str("${");
                    output.push_str(&name);
                } else if let Some(resolved) = lookup(&name) {
                    output.push_str(&resolved);
                }
            }
            Some(c) if c.is_ascii_alphabetic() || *c == '_' => {
                let mut name = String::new();
                while let Some(c) = chars.next_if(|c| c.is_ascii_alphanumeric() || *c == '_') {
                    name.push(c);
                }
                if let Some(resolved) = lookup(&name) {
                    output.push_str(&resolved);
                }
            }
            _ => output.push('$'),
        }
    }
    output
}

/// Parse one `[env]` variable spec into an [`EnvEntry`].
///
/// `false` unsets; `{ default = … }` fills gaps; `{ required = true }`
/// validates; `{ value = …, tools = …, redact = … }` assigns with options.
/// Plain strings and integers assign directly. Anything else is rejected.
fn parse_entry(name: &str, spec: &toml::Value) -> Result<EnvEntry> {
    validate_env_name(name)?;
    let mut tools_phase = false;
    let mut redact = false;
    let action = match spec {
        toml::Value::String(value) => EnvAction::Set(value.clone()),
        toml::Value::Integer(number) => EnvAction::Set(number.to_string()),
        toml::Value::Boolean(false) => EnvAction::Unset,
        toml::Value::Boolean(true) => EnvAction::Set("true".to_string()),
        toml::Value::Table(table) => {
            for key in table.keys() {
                match key.as_str() {
                    "value" | "default" | "required" | "tools" | "redact" => {}
                    other => anyhow::bail!("Unknown option {other:?} in [env] {name}"),
                }
            }
            tools_phase = table
                .get("tools")
                .and_then(toml::Value::as_bool)
                .unwrap_or(false);
            redact = table
                .get("redact")
                .and_then(toml::Value::as_bool)
                .unwrap_or(false);
            if let Some(default) = table.get("default") {
                let fallback = match default {
                    toml::Value::String(value) => value.clone(),
                    toml::Value::Integer(number) => number.to_string(),
                    other => anyhow::bail!(
                        "Unsupported default value {other} in [env] {name}: want string or integer"
                    ),
                };
                EnvAction::Default(fallback)
            } else if table
                .get("required")
                .and_then(toml::Value::as_bool)
                .unwrap_or(false)
            {
                EnvAction::Required { redact }
            } else if let Some(value) = table.get("value") {
                let assigned = match value {
                    toml::Value::String(value) => value.clone(),
                    toml::Value::Integer(number) => number.to_string(),
                    other => anyhow::bail!(
                        "Unsupported value {other} in [env] {name}: want string or integer"
                    ),
                };
                EnvAction::Set(assigned)
            } else {
                anyhow::bail!("[env] {name} needs one of `value`, `default`, or `required`");
            }
        }
        other => anyhow::bail!("Unsupported value {other} in [env] {name}"),
    };
    Ok(EnvEntry {
        name: name.to_string(),
        action,
        tools_phase,
        redact,
    })
}

/// Collect path strings from a directive value: a single string, an array of
/// strings and `{ path = … }` objects, or a bare `{ path = … }` object. The
/// deprecated `value`/`values` spellings are accepted as `path` aliases so
/// older configs keep working.
pub(crate) fn directive_paths(spec: &toml::Value, directive: &str) -> Result<Vec<(String, bool)>> {
    fn one(item: &toml::Value, directive: &str) -> Result<Vec<(String, bool)>> {
        match item {
            toml::Value::String(path) => Ok(vec![(path.clone(), false)]),
            toml::Value::Table(table) => {
                let raw = table
                    .get("path")
                    .or_else(|| table.get("value"))
                    .or_else(|| table.get("values"));
                let paths = match raw {
                    Some(toml::Value::String(path)) => vec![path.clone()],
                    Some(toml::Value::Array(paths)) => paths
                        .iter()
                        .map(|path| {
                            path.as_str().map(str::to_owned).with_context(|| {
                                format!("{directive} entry `path` must be a string or string array")
                            })
                        })
                        .collect::<Result<Vec<_>>>()?,
                    _ => anyhow::bail!("{directive} entry needs a `path` string"),
                };
                let tools_phase = table
                    .get("tools")
                    .and_then(toml::Value::as_bool)
                    .unwrap_or(false);
                Ok(paths.into_iter().map(|path| (path, tools_phase)).collect())
            }
            other => anyhow::bail!("Unsupported {directive} entry: {other}"),
        }
    }
    match spec {
        toml::Value::Array(items) => {
            let mut merged = Vec::new();
            for item in items {
                merged.extend(one(item, directive)?);
            }
            Ok(merged)
        }
        single => one(single, directive),
    }
}

/// Parse one `_.file` object: `{ path, redact, tools, expand }` (plus the
/// deprecated `value`/`values` aliases for `path`).
pub(crate) fn parse_file_directive(item: &toml::Value) -> Result<EnvFileDirective> {
    let (path, tools_phase) = match item {
        toml::Value::String(path) => (PathBuf::from(path), false),
        toml::Value::Table(table) => {
            let raw = table
                .get("path")
                .or_else(|| table.get("value"))
                .or_else(|| table.get("values"));
            let Some(path) = raw.and_then(toml::Value::as_str) else {
                anyhow::bail!("_.file entry needs a `path` string");
            };
            for key in table.keys() {
                match key.as_str() {
                    "path" | "value" | "values" | "redact" | "tools" | "expand" => {}
                    other => anyhow::bail!("Unknown option {other:?} in _.file entry"),
                }
            }
            let tools_phase = table
                .get("tools")
                .and_then(toml::Value::as_bool)
                .unwrap_or(false);
            (PathBuf::from(path), tools_phase)
        }
        other => anyhow::bail!("Unsupported _.file entry: {other}"),
    };
    let table = item.as_table();
    let redact = table
        .and_then(|table| table.get("redact"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(false);
    let expand = table
        .and_then(|table| table.get("expand"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(false);
    Ok(EnvFileDirective {
        path,
        redact,
        tools_phase,
        expand,
    })
}

/// Resolve a directive path against the declaring file's directory
/// (mise `config_root`; here the containing directory).
fn resolve_against(path: &str, config_root: &Path) -> PathBuf {
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() {
        candidate
    } else {
        config_root.join(candidate)
    }
}

/// Parse the `[env]` table of one `mise.toml` document.
///
/// `config_root` is the declaring file's directory; relative `_.path`,
/// `_.file`, and `_.source` entries resolve against it.
pub(crate) fn parse_mise_env(document: &toml::Value, config_root: &Path) -> Result<MiseEnv> {
    let mut parsed = MiseEnv::default();
    let Some(env) = document.get("env").and_then(toml::Value::as_table) else {
        return Ok(parsed);
    };
    for (name, spec) in env {
        if name == "_" {
            let Some(directives) = spec.as_table() else {
                anyhow::bail!("env._ must be a table of directives");
            };
            for (directive, value) in directives {
                match directive.as_str() {
                    "path" => {
                        for (raw, tools_phase) in directive_paths(value, "_.path")? {
                            parsed
                                .paths
                                .push((resolve_against(&raw, config_root), tools_phase));
                        }
                    }
                    "file" => {
                        let items = match value {
                            toml::Value::Array(items) => items.clone(),
                            single => vec![single.clone()],
                        };
                        for item in &items {
                            let mut entry = parse_file_directive(item)?;
                            entry.path =
                                resolve_against(&entry.path.to_string_lossy(), config_root);
                            parsed.files.push(entry);
                        }
                    }
                    "source" => {
                        for (raw, tools_phase) in directive_paths(value, "_.source")? {
                            parsed
                                .sources
                                .push((resolve_against(&raw, config_root), tools_phase));
                        }
                    }
                    other => anyhow::bail!("Unknown env directive _.{other}"),
                }
            }
            continue;
        }
        parsed.entries.push(parse_entry(name, spec)?);
    }
    if let Some(patterns) = document.get("redactions").and_then(toml::Value::as_array) {
        for pattern in patterns {
            let Some(pattern) = pattern.as_str() else {
                anyhow::bail!("redactions entries must be strings");
            };
            parsed.redactions.push(pattern.to_string());
        }
    }
    Ok(parsed)
}

/// Read through one bounded, regular-file descriptor. Nonblocking open prevents
/// FIFO replacement races; no-follow rejects final-component symlinks. Missing
/// files remain `None` for the caller's strict/lenient policy.
pub(crate) fn read_bounded_regular_file(path: &Path) -> Result<Option<String>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOFOLLOW);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "Failed to read {} as a regular file (symlinks are not a regular file)",
                    path.display()
                )
            });
        }
    };
    let metadata = file
        .metadata()
        .with_context(|| format!("Failed to stat {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file(),
        "Env file {} is not a regular file; refusing to load",
        path.display()
    );
    anyhow::ensure!(
        metadata.len() <= MAX_ENV_FILE_BYTES,
        "Env file {} exceeds {} bytes; refusing to load",
        path.display(),
        MAX_ENV_FILE_BYTES
    );

    // Read from the opened handle with a hard take() bound so a file that
    // lies about its size (or grows while being read) cannot exhaust memory.
    let mut buffer = Vec::with_capacity(
        usize::try_from(metadata.len()).unwrap_or(MAX_ENV_FILE_BYTES as usize) + 1,
    );
    file.take(MAX_ENV_FILE_BYTES + 1)
        .read_to_end(&mut buffer)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    anyhow::ensure!(
        buffer.len() as u64 <= MAX_ENV_FILE_BYTES,
        "Env file {} exceeds {} bytes; refusing to load",
        path.display(),
        MAX_ENV_FILE_BYTES
    );
    let content = String::from_utf8(buffer)
        .with_context(|| format!("Env file {} is not valid UTF-8", path.display()))?;
    Ok(Some(content))
}

fn read_env_file(path: &Path) -> Result<Option<String>> {
    read_bounded_regular_file(path)
}

/// Parse dotenv content: `KEY=value`, optional `export` prefix, `#`
/// comments, single/double quotes. Malformed lines are hard errors —
/// silently skipping a line would set a partial environment that looks
/// complete.
fn parse_dotenv(content: &str, path: &Path) -> Result<Vec<(String, String)>> {
    let mut pairs = Vec::new();
    for (index, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").map_or(line, str::trim);
        let Some((key, value)) = line.split_once('=') else {
            anyhow::bail!(
                "Malformed line {} in {}: expected KEY=value",
                index + 1,
                path.display()
            );
        };
        let key = key.trim();
        validate_env_name(key)?;
        let value = value.trim();
        let unquoted = if value.len() >= 2
            && ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\'')))
        {
            &value[1..value.len() - 1]
        } else {
            value
        };
        // A trailing ` # comment` ends an unquoted value (dotenvy keeps
        // comments inside quotes intact by construction here).
        let unquoted = if value == unquoted {
            unquoted.split(" #").next().unwrap_or(unquoted).trim_end()
        } else {
            unquoted
        };
        pairs.push((key.to_string(), unquoted.to_string()));
    }
    Ok(pairs)
}

/// Scalar to string for JSON/TOML env files. Nested containers are rejected:
///
/// environment values are flat strings downstream.
fn flat_scalar(value: &serde_json::Value, key: &str, path: &Path) -> Result<Option<String>> {
    match value {
        serde_json::Value::String(text) => Ok(Some(text.clone())),
        serde_json::Value::Number(number) => Ok(Some(number.to_string())),
        serde_json::Value::Bool(flag) => Ok(Some(flag.to_string())),
        serde_json::Value::Null => Ok(None),
        other => anyhow::bail!("Non-scalar value for {key} in {}: {other}", path.display()),
    }
}

/// Load one `_.file` directive. Returns `Ok(None)` when the file is missing;
/// strict callers turn that into an error, lenient callers warn and skip.
pub(crate) fn load_env_file(directive: &EnvFileDirective) -> Result<Option<Vec<(String, String)>>> {
    let Some(content) = read_env_file(&directive.path)? else {
        return Ok(None);
    };
    let extension = directive
        .path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    // Extensionless files and `.env*` are dotenv; JSON/TOML select their own
    // parser. YAML has no vendored parser and fails closed with guidance.
    let pairs = match extension.as_str() {
        "json" => {
            let parsed: serde_json::Value = serde_json::from_str(&content)
                .with_context(|| format!("Failed to parse {}", directive.path.display()))?;
            let Some(table) = parsed.as_object() else {
                anyhow::bail!(
                    "Env file {} must hold a top-level object",
                    directive.path.display()
                );
            };
            let mut pairs = Vec::with_capacity(table.len());
            for (key, value) in table {
                validate_env_name(key)?;
                if let Some(text) = flat_scalar(value, key, &directive.path)? {
                    pairs.push((key.clone(), text));
                }
            }
            pairs
        }
        "toml" => {
            let parsed: toml::Value = toml::from_str(&content)
                .with_context(|| format!("Failed to parse {}", directive.path.display()))?;
            let Some(table) = parsed.as_table() else {
                anyhow::bail!(
                    "Env file {} must hold a top-level table",
                    directive.path.display()
                );
            };
            let mut pairs = Vec::with_capacity(table.len());
            for (key, value) in table {
                validate_env_name(key)?;
                match value {
                    toml::Value::String(text) => pairs.push((key.clone(), text.clone())),
                    toml::Value::Integer(number) => pairs.push((key.clone(), number.to_string())),
                    toml::Value::Boolean(flag) => pairs.push((key.clone(), flag.to_string())),
                    other => anyhow::bail!(
                        "Non-scalar value for {key} in {}: {other}",
                        directive.path.display()
                    ),
                }
            }
            pairs
        }
        "yaml" | "yml" => {
            anyhow::bail!(
                "Env file {} is YAML, which OMG cannot parse; convert it to dotenv, JSON, or TOML",
                directive.path.display()
            );
        }
        _ => parse_dotenv(&content, &directive.path)?,
    };
    Ok(Some(pairs))
}

/// How strictly to treat missing inputs.
///
/// Explicit `run` and task execution fail closed. Automatic hooks no longer
/// resolve project environments; tests retain the legacy lenient mode as a
/// comparison for required-input handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Strictness {
    /// Fail closed on missing files and unmet `required` entries.
    Strict,
    /// Warn once and skip missing files and unmet `required` entries.
    #[cfg(test)]
    Lenient,
}

/// Accumulator for one resolution pass.
struct Resolver<'a> {
    /// Base environment (process snapshot): never mutated, only read.
    base: &'a HashMap<String, String>,
    /// config_root for `{{config_root}}` templates.
    config_root: String,
    /// Ordered assignments; later entries override earlier ones.
    assigned: Vec<(String, String)>,
    /// Index into `assigned` for override-in-place.
    index: HashMap<String, usize>,
    unset: Vec<String>,
    redacted: HashSet<String>,
    patterns: &'a [String],
    strict: Strictness,
    warned: bool,
}

impl Resolver<'_> {
    fn lookup(&self, name: &str) -> Option<String> {
        if name == "\0config_root" {
            return Some(self.config_root.clone());
        }
        if self.unset.iter().any(|removed| removed == name) {
            return None;
        }
        self.index
            .get(name)
            .and_then(|position| self.assigned.get(*position))
            .map(|(_, value)| value.clone())
            .or_else(|| self.base.get(name).cloned())
    }

    fn warn(&mut self, message: &str) {
        if !self.warned {
            self.warned = true;
            tracing::warn!("{message}");
        }
    }

    fn assign(&mut self, name: &str, value: String, redact: bool) {
        if ResolvedEnv::is_redacted(name, redact, self.patterns) {
            self.redacted.insert(name.to_string());
        }
        if let Some(position) = self.index.get(name) {
            self.assigned[*position] = (name.to_string(), value);
        } else {
            self.index.insert(name.to_string(), self.assigned.len());
            self.assigned.push((name.to_string(), value));
        }
        self.unset.retain(|removed| removed != name);
    }

    fn remove(&mut self, name: &str) {
        if let Some(position) = self.index.remove(name) {
            self.assigned.remove(position);
            self.index.clear();
            for (slot, (key, _)) in self.assigned.iter().enumerate() {
                self.index.insert(key.clone(), slot);
            }
        }
        if !self.unset.contains(&name.to_string()) {
            self.unset.push(name.to_string());
        }
    }

    /// Apply one entry in the current phase. Returns `Ok(false)` when the
    /// entry belongs to the other phase.
    fn apply_entry(&mut self, entry: &EnvEntry, tools_phase: bool) -> Result<bool> {
        if entry.tools_phase != tools_phase {
            return Ok(false);
        }
        match &entry.action {
            EnvAction::Set(raw) => {
                let value = expand_templates(raw, &|name| self.lookup(name))?;
                self.assign(&entry.name, value, entry.redact);
            }
            EnvAction::Default(raw) => {
                let current = self.lookup(&entry.name);
                if current.as_deref().is_none_or(str::is_empty) {
                    let value = expand_templates(raw, &|name| self.lookup(name))?;
                    self.assign(&entry.name, value, entry.redact);
                } else if let Some(value) = current {
                    self.assign(&entry.name, value, entry.redact);
                }
            }
            EnvAction::Required { .. } => {
                let current = self.lookup(&entry.name);
                if current.as_deref().is_none_or(str::is_empty) {
                    let message = format!(
                        "Required environment variable {} is not set; define it in the shell or mise.local.toml",
                        entry.name
                    );
                    if self.strict == Strictness::Strict {
                        anyhow::bail!("{message}");
                    }
                    self.warn(&message);
                } else if let Some(value) = current {
                    self.assign(&entry.name, value, entry.redact);
                }
            }
            EnvAction::Unset => self.remove(&entry.name),
        }
        Ok(true)
    }

    /// Apply one loaded file's pairs in the current phase.
    fn apply_file(
        &mut self,
        directive: &EnvFileDirective,
        pairs: Vec<(String, String)>,
        tools_phase: bool,
    ) {
        if directive.tools_phase != tools_phase {
            return;
        }
        for (key, raw) in pairs {
            let value = if directive.expand {
                expand_dollar(&raw, &|name| self.lookup(name))
            } else {
                raw
            };
            self.assign(&key, value, directive.redact);
        }
    }
}

/// Resolve one parsed `[env]` in two phases: entries without `tools = true`
/// first (so tool installs see them), then the lazy `tools = true` phase
/// once `PATH` is final.
fn resolve_one(
    parsed: &MiseEnv,
    file_pairs: &[(EnvFileDirective, Vec<(String, String)>)],
    base: &HashMap<String, String>,
    config_root: &Path,
    patterns: &[String],
    strict: Strictness,
) -> Result<ResolvedEnv> {
    let mut resolver = Resolver {
        base,
        config_root: config_root.display().to_string(),
        assigned: Vec::new(),
        index: HashMap::new(),
        unset: Vec::new(),
        redacted: HashSet::new(),
        patterns,
        strict,
        warned: false,
    };
    for tools_phase in [false, true] {
        for (directive, pairs) in file_pairs {
            resolver.apply_file(directive, pairs.clone(), tools_phase);
        }
        for entry in &parsed.entries {
            resolver.apply_entry(entry, tools_phase)?;
        }
        let paths: Vec<String> = parsed
            .paths
            .iter()
            .filter(|(_, phase)| *phase == tools_phase)
            .map(|(path, _)| path.display().to_string())
            .collect();
        if !paths.is_empty() {
            let current = resolver.lookup("PATH").unwrap_or_default();
            let path = if current.is_empty() {
                paths.join(":")
            } else {
                format!("{}:{current}", paths.join(":"))
            };
            // PATH is an ordered layer effect like any other assignment.
            // Deferring it would hide parent paths from later source scripts
            // and let a parent source overwrite a child's later directive.
            resolver.assign("PATH", path, false);
        }
        for (script, phase) in &parsed.sources {
            if *phase != tools_phase {
                continue;
            }
            #[cfg(unix)]
            {
                // Resolve source effects in their declaring layer so later
                // documents see them and can override them. Do not replay
                // these scripts after the chain has already been merged.
                let mut effective = resolver.base.clone();
                effective.extend(resolver.assigned.iter().cloned());
                for name in &resolver.unset {
                    effective.remove(name);
                }
                let sourced = eval_sourced_file(script, &effective)?;
                for (key, value) in sourced.set {
                    resolver.assign(&key, value, false);
                }
                for key in sourced.unset {
                    resolver.remove(&key);
                }
            }
            #[cfg(not(unix))]
            anyhow::bail!(
                "_.source scripts require a Unix shell: {}",
                script.display()
            );
        }
    }
    Ok(ResolvedEnv {
        set: resolver.assigned,
        unset: resolver.unset,
        path_additions: Vec::new(),
        sources: Vec::new(),
        redacted: resolver.redacted,
    })
}

pub(crate) fn resolve_task_env(
    parsed: &MiseEnv,
    base: &HashMap<String, String>,
    config_root: &Path,
) -> Result<ResolvedEnv> {
    let file_pairs = parsed
        .files
        .iter()
        .map(|directive| {
            let pairs = load_env_file(directive)?.with_context(|| {
                format!("Task env file not found: {}", directive.path.display())
            })?;
            Ok((directive.clone(), pairs))
        })
        .collect::<Result<Vec<_>>>()?;
    resolve_one(
        parsed,
        &file_pairs,
        base,
        config_root,
        &parsed.redactions,
        Strictness::Strict,
    )
}

/// Merge one [`ResolvedEnv`] into an accumulated chain result: later files
/// override earlier assignments, removals win over prior assignments, and
/// path additions, sources, and redactions accumulate in order.
fn merge_chain(accumulated: &mut ResolvedEnv, next: ResolvedEnv) {
    let mut index: HashMap<String, usize> = HashMap::new();
    for (slot, (key, _)) in accumulated.set.iter().enumerate() {
        index.insert(key.clone(), slot);
    }
    for (key, value) in next.set {
        accumulated.unset.retain(|removed| removed != &key);
        if let Some(slot) = index.get(&key).copied() {
            accumulated.set[slot] = (key, value);
        } else {
            index.insert(key.clone(), accumulated.set.len());
            accumulated.set.push((key, value));
        }
    }
    for removed in next.unset {
        accumulated.set.retain(|(key, _)| key != &removed);
        if !accumulated.unset.contains(&removed) {
            accumulated.unset.push(removed);
        }
    }
    accumulated.path_additions.extend(next.path_additions);
    for script in next.sources {
        if !accumulated.sources.contains(&script) {
            accumulated.sources.push(script);
        }
    }
    accumulated.redacted.extend(next.redacted);
}

/// Load and resolve `[env]` from `start` and its ancestors.
///
/// `base` is the process environment snapshot. Production callers use
/// [`Strictness::Strict`] and fail closed on missing required inputs.
pub(crate) fn load_mise_env_chain(
    start: &Path,
    base: &HashMap<String, String>,
    strict: Strictness,
) -> Result<ResolvedEnv> {
    let mut merged = ResolvedEnv::default();
    let mut effective = base.clone();
    let mut patterns: Vec<String> = Vec::new();
    for document in super::mise_config::load(start, base)? {
        let parsed = parse_mise_env(&document.value, &document.root)
            .with_context(|| format!("Invalid mise environment in {}", document.path.display()))?;
        patterns.extend(parsed.redactions.iter().cloned());
        let config_root = &document.root;
        let mut file_pairs = Vec::new();
        for directive in &parsed.files {
            match load_env_file(directive)? {
                Some(pairs) => file_pairs.push((directive.clone(), pairs)),
                None if strict == Strictness::Strict => {
                    anyhow::bail!("Env file not found: {}", directive.path.display());
                }
                // Same warn-once-per-process pattern as stale pins in the
                // hook: a deleted `.env` must not spam every prompt.
                None => {
                    use std::sync::atomic::{AtomicBool, Ordering};
                    static WARNED_MISSING_ENV_FILE: AtomicBool = AtomicBool::new(false);
                    if !WARNED_MISSING_ENV_FILE.swap(true, Ordering::Relaxed) {
                        tracing::warn!("Ignoring missing env file: {}", directive.path.display());
                    }
                }
            }
        }
        let resolved = resolve_one(
            &parsed,
            &file_pairs,
            &effective,
            config_root,
            &patterns,
            strict,
        )?;
        effective.extend(resolved.set.iter().cloned());
        for name in &resolved.unset {
            effective.remove(name);
        }
        merge_chain(&mut merged, resolved);
    }
    Ok(merged)
}

/// Evaluate a `_.source` script and return the variables it defines.
///
/// Runs the script with `bash` (falling back to `sh`), snapshots
/// `env -0` before and after inside the same shell, and returns the
/// difference. A non-zero script exit is a hard error: a half-sourced
/// environment must never silently apply.
#[cfg(unix)]
pub(crate) fn eval_sourced_file(
    script: &Path,
    base: &HashMap<String, String>,
) -> Result<ResolvedEnv> {
    fn snapshot(
        shell: &str,
        script: Option<&Path>,
        base: &HashMap<String, String>,
    ) -> Result<HashMap<String, String>> {
        let mut command = std::process::Command::new(shell);
        command.env_clear().envs(base);
        command.arg("-c");
        if let Some(script) = script {
            command.arg(". \"$0\" >/dev/null 2>&1 && env -0");
            command.arg(script);
        } else {
            command.arg("env -0");
        }
        // A hostile script path must not become shell syntax: it travels as
        // `$0`, never interpolated into the program text.
        let output = command.output().with_context(|| {
            format!(
                "Failed to run {shell} for {}",
                script.map_or_else(|| "-".into(), |s: &Path| s.display().to_string())
            )
        })?;
        if !output.status.success() {
            let which = script.map_or_else(
                || "baseline snapshot".to_string(),
                |s| format!("sourcing {}", s.display()),
            );
            anyhow::bail!("{shell} failed while {which}");
        }
        Ok(parse_nul_env(&output.stdout))
    }

    let shell = if which_shell("bash") { "bash" } else { "sh" };
    let before = snapshot(shell, None, base)?;
    let after = snapshot(shell, Some(script), base)?;
    let unset = before
        .keys()
        .filter(|key| !after.contains_key(*key))
        .cloned()
        .collect();
    Ok(ResolvedEnv {
        set: after
            .into_iter()
            .filter(|(key, value)| before.get(key) != Some(value))
            .collect(),
        unset,
        ..ResolvedEnv::default()
    })
}

/// Whether `shell` resolves on `PATH` (checked without spawning it).
#[cfg(unix)]
fn which_shell(name: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(name).is_file()))
}

/// Parse NUL-separated `KEY=value` records from `env -0` output. Records
/// without `=` cannot come from `env` and are ignored defensively.
fn parse_nul_env(output: &[u8]) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    for record in output.split(|byte| *byte == 0) {
        let Ok(text) = std::str::from_utf8(record) else {
            continue;
        };
        if let Some((key, value)) = text.split_once('=')
            && !key.is_empty()
            && validate_env_name(key).is_ok()
        {
            vars.insert(key.to_string(), value.to_string());
        }
    }
    vars
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mise_config_reads_are_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mise.toml");
        std::fs::write(&path, "#".repeat(1024 * 1024 + 1)).unwrap();
        assert!(load_mise_env_chain(dir.path(), &HashMap::new(), Strictness::Strict).is_err());
        std::fs::write(&path, "[env]\nLEGITIMATE = 'preserved'\n").unwrap();
        let env = load_mise_env_chain(dir.path(), &HashMap::new(), Strictness::Strict).unwrap();
        assert_eq!(env.set, [("LEGITIMATE".into(), "preserved".into())]);
    }

    #[cfg(unix)]
    #[test]
    fn bounded_reader_rejects_fifo_without_a_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pipe.env");
        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRUSR).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            tx.send(read_env_file(&path).is_err()).unwrap();
        });
        assert!(rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap());
    }

    /// Env-file reads reachable from completion and shell hooks must reject
    /// special files (hang/stream-forever vectors) before opening them.
    #[cfg(unix)]
    #[test]
    fn env_file_reads_reject_special_files() {
        let dir = tempfile::tempdir().expect("temp directory");

        // Symlinks are rejected outright.
        std::os::unix::fs::symlink("/etc/passwd", dir.path().join("linked.env"))
            .expect("symlink fixture");
        let error = read_env_file(&dir.path().join("linked.env"))
            .expect_err("symlinked env files must be rejected");
        assert!(error.to_string().contains("not a regular file"), "{error}");

        // A directory passes open() but is not a regular file.
        let error = read_env_file(dir.path()).expect_err("directory env files must be rejected");
        assert!(error.to_string().contains("not a regular file"), "{error}");

        // Character devices (e.g. /dev/zero via an absolute directive)
        // stream forever; they are not regular files.
        let error =
            read_env_file(Path::new("/dev/zero")).expect_err("device files must be rejected");
        assert!(error.to_string().contains("not a regular file"), "{error}");
    }

    /// Env-file reads must stay bounded even when a file lies about (or
    /// outgrows) its reported size.
    #[test]
    fn env_file_reads_are_bounded() {
        let dir = tempfile::tempdir().expect("temp directory");
        let path = dir.path().join("fat.env");
        let oversized = "KEY=0123456789\n".repeat(100_000); // ~1.3 MiB
        std::fs::write(&path, oversized).expect("oversized fixture");

        let error = read_env_file(&path).expect_err("oversized env files must be rejected");
        assert!(error.to_string().contains("refusing to load"), "{error}");

        // A normal file still loads.
        std::fs::write(&path, "A=1\n").expect("valid fixture");
        let content = read_env_file(&path).expect("valid env file loads");
        assert_eq!(content.as_deref(), Some("A=1\n"));

        // Missing files stay `Ok(None)` for caller policy.
        assert_eq!(
            read_env_file(&dir.path().join("missing.env")).expect("missing is None"),
            None
        );
    }

    fn base(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect()
    }

    fn parse_env(toml_text: &str, root: &Path) -> MiseEnv {
        let document: toml::Value = toml::from_str(toml_text).expect("test TOML parses");
        parse_mise_env(&document, root).expect("test [env] parses")
    }

    fn resolve_text(
        toml_text: &str,
        base_map: &HashMap<String, String>,
        strict: Strictness,
    ) -> ResolvedEnv {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let parsed = parse_env(toml_text, dir.path());
        resolve_one(
            &parsed,
            &[],
            base_map,
            dir.path(),
            &parsed.redactions,
            strict,
        )
        .expect("test resolve succeeds")
    }

    fn get(resolved: &ResolvedEnv, name: &str) -> Option<String> {
        resolved
            .set
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    }

    #[test]
    fn plain_string_int_and_unset() {
        let resolved = resolve_text(
            "[env]\nA = \"1\"\nB = 42\nC = false\n",
            &base(&[]),
            Strictness::Strict,
        );
        assert_eq!(get(&resolved, "A").as_deref(), Some("1"));
        assert_eq!(get(&resolved, "B").as_deref(), Some("42"));
        assert!(resolved.unset.contains(&"C".to_string()));
    }

    #[test]
    fn invalid_names_and_options_rejected() {
        assert!(parse_entry("BAD-NAME", &toml::Value::String("x".into())).is_err());
        assert!(parse_entry("", &toml::Value::String("x".into())).is_err());
        assert!(parse_entry("9LIVES", &toml::Value::String("x".into())).is_err());
        let table: toml::Value = toml::from_str("key = { bogus = 1 }").expect("toml");
        let spec = table.get("key").expect("key");
        assert!(parse_entry("KEY", spec).is_err());
    }

    #[test]
    fn default_fills_only_gaps() {
        let empty = base(&[]);
        let present = base(&[("MODE", "prod")]);
        let blank = base(&[("MODE", "")]);
        let text = "[env]\nMODE = { default = \"dev\" }\n";
        assert_eq!(
            get(&resolve_text(text, &empty, Strictness::Strict), "MODE").as_deref(),
            Some("dev")
        );
        assert_eq!(
            get(&resolve_text(text, &present, Strictness::Strict), "MODE").as_deref(),
            Some("prod")
        );
        assert_eq!(
            get(&resolve_text(text, &blank, Strictness::Strict), "MODE").as_deref(),
            Some("dev")
        );
    }

    #[test]
    fn required_strict_fails_lenient_skips() {
        let text = "[env]\nTOKEN = { required = true }\n";
        let empty = base(&[]);
        let dir = tempfile::TempDir::new().expect("tempdir");
        let parsed = parse_env(text, dir.path());
        assert!(resolve_one(&parsed, &[], &empty, dir.path(), &[], Strictness::Strict).is_err());
        let lenient =
            resolve_one(&parsed, &[], &empty, dir.path(), &[], Strictness::Lenient).expect("skips");
        assert!(get(&lenient, "TOKEN").is_none());
        let filled = resolve_text(text, &base(&[("TOKEN", "s3cret")]), Strictness::Strict);
        assert_eq!(get(&filled, "TOKEN").as_deref(), Some("s3cret"));
    }

    #[test]
    fn templates_expand_from_base_and_earlier_entries() {
        let text = "[env]\nROOT = \"/opt/app\"\nBIN = \"{{env.ROOT}}/bin\"\nHOME_BIN = \"{{env.HOME}}/bin\"\n";
        let resolved = resolve_text(text, &base(&[("HOME", "/root")]), Strictness::Strict);
        assert_eq!(get(&resolved, "BIN").as_deref(), Some("/opt/app/bin"));
        assert_eq!(get(&resolved, "HOME_BIN").as_deref(), Some("/root/bin"));
    }

    #[test]
    fn unknown_and_unclosed_templates_fail() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        for text in [
            "[env]\nA = \"{{tools.node.version}}\"\n",
            "[env]\nA = \"{{env.MISSING_VAR_XYZ}}\"\n",
            "[env]\nA = \"prefix {{env.HOME\"\n",
        ] {
            let parsed = parse_env(text, dir.path());
            assert!(
                resolve_one(
                    &parsed,
                    &[],
                    &base(&[]),
                    dir.path(),
                    &[],
                    Strictness::Strict
                )
                .is_err(),
                "must fail: {text}"
            );
        }
    }

    #[test]
    fn dotenv_parsing_quotes_comments_export() {
        let path = PathBuf::from("test.env");
        let pairs = parse_dotenv(
            "# comment\nexport A=1\nB=\"two words\"\nC='three'\nD=four # trailing\nE=\n",
            &path,
        )
        .expect("dotenv parses");
        let map: HashMap<&str, &str> = pairs
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        assert_eq!(map["A"], "1");
        assert_eq!(map["B"], "two words");
        assert_eq!(map["C"], "three");
        assert_eq!(map["D"], "four");
        assert_eq!(map["E"], "");
        assert!(parse_dotenv("NO_EQUALS_HERE\n", &path).is_err());
    }

    #[test]
    fn json_toml_and_yaml_files() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let json_path = dir.path().join("vars.env.json");
        std::fs::write(&json_path, r#"{"A": "1", "B": 2, "C": true, "D": null}"#)
            .expect("write json");
        let pairs = load_env_file(&EnvFileDirective {
            path: json_path,
            redact: false,
            tools_phase: false,
            expand: false,
        })
        .expect("json loads")
        .expect("present");
        let map: HashMap<&str, &str> = pairs
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        assert_eq!(map["A"], "1");
        assert_eq!(map["B"], "2");
        assert_eq!(map["C"], "true");
        assert!(!map.contains_key("D"));

        let toml_path = dir.path().join("vars.env.toml");
        std::fs::write(&toml_path, "X = \"yes\"\nY = 7\n").expect("write toml");
        let pairs = load_env_file(&EnvFileDirective {
            path: toml_path,
            redact: false,
            tools_phase: false,
            expand: false,
        })
        .expect("toml loads")
        .expect("present");
        assert!(pairs.contains(&("X".to_string(), "yes".to_string())));
        assert!(pairs.contains(&("Y".to_string(), "7".to_string())));

        let yaml_path = dir.path().join("vars.env.yaml");
        std::fs::write(&yaml_path, "Z: 1\n").expect("write yaml");
        assert!(
            load_env_file(&EnvFileDirective {
                path: yaml_path,
                redact: false,
                tools_phase: false,
                expand: false,
            })
            .is_err()
        );
    }

    #[test]
    fn expand_dollar_references_earlier_values() {
        assert_eq!(
            expand_dollar("$A/${B}/lit", &|name| match name {
                "A" => Some("x".to_string()),
                "B" => Some("y".to_string()),
                _ => None,
            }),
            "x/y/lit"
        );
        assert_eq!(expand_dollar("$-$${", &|_| None), "$-$${");
        assert_eq!(expand_dollar("${UNFINISHED", &|_| None), "${UNFINISHED");
    }

    #[test]
    fn redaction_flags_and_patterns() {
        assert!(glob_match("*_TOKEN", "API_TOKEN"));
        assert!(glob_match("SECRET_*", "SECRET_KEY"));
        assert!(glob_match("*KEY*", "MONKEY_BUSINESS"));
        assert!(!glob_match("SECRET_*", "MY_SECRET"));
        assert!(glob_match("*", "ANYTHING"));
        assert!(!glob_match("EXACT", "exact"));

        let text = "redactions = [\"*_TOKEN\"]\n[env]\nA = \"1\"\nB = { value = \"s\", redact = true }\nC = \"x\"\n";
        let resolved = resolve_text(text, &base(&[]), Strictness::Strict);
        assert!(!resolved.redacted.contains("A"));
        assert!(resolved.redacted.contains("B"));
        assert!(!resolved.redacted.contains("C"));
    }

    #[test]
    fn directives_resolve_against_config_root() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let parsed = parse_env(
            "[env]\n_.path = [\"bin\", { path = \"tools\", tools = true }]\n_.file = \".env\"\n_.source = \"scripts/env.sh\"\n",
            dir.path(),
        );
        assert_eq!(parsed.paths.len(), 2);
        assert_eq!(parsed.paths[0].0, dir.path().join("bin"));
        assert!(!parsed.paths[0].1);
        assert!(parsed.paths[1].1);
        assert_eq!(parsed.files.len(), 1);
        assert_eq!(parsed.files[0].path, dir.path().join(".env"));
        assert_eq!(parsed.sources.len(), 1);
        assert_eq!(parsed.sources[0].0, dir.path().join("scripts/env.sh"));
    }

    #[test]
    fn chain_child_overrides_parent_and_unset_wins() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        std::fs::write(
            dir.path().join("mise.toml"),
            "[env]\nA = \"parent\"\nB = \"keep\"\n",
        )
        .expect("parent");
        let child = dir.path().join("child");
        std::fs::create_dir(&child).expect("child dir");
        std::fs::write(child.join("mise.toml"), "[env]\nA = \"child\"\nB = false\n")
            .expect("child");
        let resolved =
            load_mise_env_chain(&child, &base(&[]), Strictness::Strict).expect("chain resolves");
        assert_eq!(get(&resolved, "A").as_deref(), Some("child"));
        assert!(get(&resolved, "B").is_none());
        assert!(resolved.unset.contains(&"B".to_string()));
    }

    #[test]
    #[cfg(unix)]
    fn chain_parent_source_supplies_child_templates_and_requirements() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        std::fs::write(
            dir.path().join("mise.toml"),
            "[env._]\nsource = \"parent.sh\"\n",
        )
        .expect("parent config");
        std::fs::write(
            dir.path().join("parent.sh"),
            "export FROM_SOURCE=parent\nexport MODE=parent\n",
        )
        .expect("parent source");
        let child = dir.path().join("child");
        std::fs::create_dir(&child).expect("child directory");
        std::fs::write(child.join("mise.toml"), "[env]\nMODE = \"child\"\nCOPY = \"{{env.FROM_SOURCE}}\"\nFROM_SOURCE = { required = true }\n").expect("child config");
        let resolved = load_mise_env_chain(&child, &std::env::vars().collect(), Strictness::Strict)
            .expect("source precedes child resolution");
        assert_eq!(get(&resolved, "COPY").as_deref(), Some("parent"));
        assert_eq!(get(&resolved, "MODE").as_deref(), Some("child"));
        assert!(
            resolved.sources.is_empty(),
            "sources must be evaluated exactly once in their layer"
        );
    }

    #[test]
    fn child_assignment_replaces_parent_removal() {
        let mut accumulated = ResolvedEnv {
            unset: vec!["A".to_string()],
            ..ResolvedEnv::default()
        };
        merge_chain(
            &mut accumulated,
            ResolvedEnv {
                set: vec![("A".to_string(), "child".to_string())],
                ..ResolvedEnv::default()
            },
        );
        assert_eq!(get(&accumulated, "A").as_deref(), Some("child"));
        assert!(accumulated.unset.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn sourced_script_errors_fail_closed() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let script = dir.path().join("env.sh");
        let env = std::env::vars().collect();
        assert!(eval_sourced_file(&script, &env).is_err());
        std::fs::write(&script, "export PARTIAL=yes\nreturn 1\n").expect("script");
        assert!(eval_sourced_file(&script, &env).is_err());
    }

    #[test]
    fn missing_file_strict_fails_lenient_skips() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        std::fs::write(
            dir.path().join("mise.toml"),
            "[env]\n_.file = \"gone.env\"\nA = \"1\"\n",
        )
        .expect("mise.toml");
        assert!(load_mise_env_chain(dir.path(), &base(&[]), Strictness::Strict).is_err());
        let lenient = load_mise_env_chain(dir.path(), &base(&[]), Strictness::Lenient)
            .expect("lenient skips");
        assert_eq!(get(&lenient, "A").as_deref(), Some("1"));
    }

    #[test]
    #[cfg(unix)]
    fn sourced_script_uses_resolved_environment_and_preserves_removals() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let script = dir.path().join("env.sh");
        std::fs::write(&script, "export RESULT=\"$CONFIGURED/bin\"\nunset SECRET\n")
            .expect("script");
        let mut env: HashMap<String, String> = std::env::vars().collect();
        env.insert("CONFIGURED".into(), "/resolved".into());
        env.insert("SECRET".into(), "removed".into());
        let resolved = eval_sourced_file(&script, &env).expect("source");
        assert_eq!(get(&resolved, "RESULT").as_deref(), Some("/resolved/bin"));
        assert!(resolved.unset.iter().any(|key| key == "SECRET"));
    }

    #[test]
    fn nul_env_parsing_skips_junk() {
        let vars = parse_nul_env(b"GOOD=1\x00NOEQUALS\x00BAD-NAME=2\x00EMPTY=\x00");
        assert_eq!(vars.get("GOOD").map(String::as_str), Some("1"));
        assert!(!vars.contains_key("BAD-NAME"));
        assert_eq!(vars.get("EMPTY").map(String::as_str), Some(""));
    }

    #[test]
    #[cfg(unix)]
    fn sourced_script_diff_returns_new_vars() {
        if !which_shell("bash") && !which_shell("sh") {
            return;
        }
        let dir = tempfile::TempDir::new().expect("tempdir");
        let script = dir.path().join("env.sh");
        std::fs::write(
            &script,
            "export OMG_SWARM_PROBE_$RANDOM=1\nexport OMG_FIXED_PROBE=yes\n",
        )
        .expect("script");
        // `$RANDOM` differs per shell invocation, so only the fixed variable
        // can be asserted deterministically.
        let vars = eval_sourced_file(&script, &std::env::vars().collect()).expect("eval succeeds");
        assert_eq!(get(&vars, "OMG_FIXED_PROBE").as_deref(), Some("yes"));
    }
}
