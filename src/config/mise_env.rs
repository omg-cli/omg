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
//!   execution using one shell with before/after environment snapshots. Hooks ignore
//!   all project environment directives.
//! - `{{env.NAME}}` / `{{config_root}}` templates in TOML string values.
//!   Full Tera is out of scope: any other `{{…}}` is a hard error rather
//!   than a silently literal string.
//!
//! Project configuration includes local overrides, selected `MISE_ENV` layers,
//! and grouped configuration files. Encrypted-secret backends and per-plugin
//! env directives remain out of scope.

use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
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
    Required,
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

#[derive(Debug, Clone)]
pub(crate) struct EnvPathDirective {
    path: PathBuf,
    tools_phase: bool,
    redact: bool,
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
    /// `_.source` scripts in declaration order.
    pub sources: Vec<EnvPathDirective>,
    /// Top-level `redactions = [...]` glob patterns (`*` wildcards).
    pub redactions: Vec<String>,
}

pub(crate) type Environment = HashMap<OsString, OsString>;

/// Fully resolved environment: ordered native assignments plus removals.
#[derive(Debug, Default, Clone)]
pub(crate) struct ResolvedEnv {
    /// `(name, value)` assignments in application order; later wins.
    pub set: Vec<(String, OsString)>,
    /// Variables to remove.
    pub unset: Vec<String>,
    /// Names whose values must be masked in echoed output.
    pub redacted: HashSet<String>,
}

impl ResolvedEnv {
    pub(crate) fn apply_to(&self, environment: &mut Environment) {
        environment.extend(
            self.set
                .iter()
                .map(|(name, value)| (OsString::from(name), value.clone())),
        );
        for name in &self.unset {
            environment.remove(OsStr::new(name));
        }
    }

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
    for (index, part) in parts.iter().enumerate().skip(1) {
        if part.is_empty() {
            continue;
        }
        if index == parts.len() - 1 {
            break;
        }
        match rest.find(part) {
            Some(index) => rest = &rest[index + part.len()..],
            None => return false,
        }
    }
    if !pattern.ends_with('*') {
        return rest.ends_with(parts[parts.len() - 1]);
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

/// Prepend complete entries while preserving the bytes and order of the existing PATH.
pub(crate) fn prepend_paths<'a>(
    paths: impl IntoIterator<Item = &'a Path>,
    current: Option<&OsStr>,
) -> Result<OsString> {
    let inherited = current
        .filter(|path| !path.is_empty())
        .into_iter()
        .flat_map(std::env::split_paths);
    std::env::join_paths(paths.into_iter().map(Path::to_path_buf).chain(inherited))
        .context("Cannot prepend directories to PATH")
}

/// Expand `{{env.NAME}}` and `{{config_root}}` templates in a TOML value.
///
/// `lookup` sees already-resolved variables first, then the base environment.
/// Any other `{{…}}` is a hard error: silently leaving Tera syntax literal
/// would set a wrong value that looks right.
fn expand_templates<'a>(
    value: &str,
    lookup: &dyn Fn(&str) -> Result<Option<&'a str>>,
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
            match lookup(var)? {
                Some(resolved) => output.push_str(resolved),
                None => anyhow::bail!("Unknown template variable {{{{{var}}}}} in env value"),
            }
        } else if expression == "config_root" {
            match lookup("\0config_root")? {
                Some(root) => output.push_str(root),
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
fn expand_dollar<'a>(
    value: &str,
    literal_dollars: &[usize],
    lookup: &dyn Fn(&str) -> Result<Option<&'a str>>,
) -> Result<String> {
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;
    let mut literals = literal_dollars.iter().copied().peekable();
    for (start, _) in value.match_indices('$') {
        if literals.next_if_eq(&start).is_some() || start < cursor {
            continue;
        }
        let tail = &value[start + 1..];
        let (name, length) = if let Some(braced) = tail.strip_prefix('{') {
            let Some((name, _)) = braced.split_once('}') else {
                break;
            };
            (name, name.len() + 2)
        } else if tail
            .as_bytes()
            .first()
            .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_')
        {
            let length = tail
                .bytes()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == b'_')
                .count();
            (&tail[..length], length)
        } else {
            continue;
        };
        output.push_str(&value[cursor..start]);
        if let Some(resolved) = lookup(name)? {
            output.push_str(resolved);
        }
        cursor = start + 1 + length;
    }
    output.push_str(&value[cursor..]);
    Ok(output)
}

fn boolean_option(table: &toml::Table, key: &str, context: impl std::fmt::Display) -> Result<bool> {
    match table.get(key) {
        Some(value) => value
            .as_bool()
            .with_context(|| format!("{key} must be a boolean in {context}")),
        None => Ok(false),
    }
}

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
                anyhow::ensure!(
                    matches!(
                        key.as_str(),
                        "value" | "default" | "required" | "tools" | "redact"
                    ),
                    "Unknown option {key:?} in [env] {name}"
                );
            }
            tools_phase = boolean_option(table, "tools", format_args!("[env] {name}"))?;
            redact = boolean_option(table, "redact", format_args!("[env] {name}"))?;
            let required = boolean_option(table, "required", format_args!("[env] {name}"))?;
            match (table.get("value"), table.get("default"), required) {
                (Some(value), None, false) => {
                    let text = assignment_text(value).with_context(|| {
                        format!("Unsupported value in [env] {name}: want string or integer")
                    })?;
                    EnvAction::Set(text)
                }
                (None, Some(default), false) => {
                    let text = assignment_text(default).with_context(|| {
                        format!("Unsupported default value in [env] {name}: want string or integer")
                    })?;
                    EnvAction::Default(text)
                }
                (None, None, true) => EnvAction::Required,
                _ => anyhow::bail!(
                    "[env] {name} needs exactly one of `value`, `default`, or `required = true`"
                ),
            }
        }
        _ => anyhow::bail!(
            "Unsupported value in [env] {name}: want string, integer, boolean, or table"
        ),
    };
    Ok(EnvEntry {
        name: name.to_owned(),
        action,
        tools_phase,
        redact,
    })
}

fn assignment_text(value: &toml::Value) -> Option<String> {
    match value {
        toml::Value::String(text) => Some(text.clone()),
        toml::Value::Integer(number) => Some(number.to_string()),
        _ => None,
    }
}

fn directive_table_path<'a>(
    table: &'a toml::Table,
    directive: &str,
    options: &[&str],
) -> Result<&'a toml::Value> {
    let known_paths = ["path", "value", "values"];
    for key in table.keys() {
        anyhow::ensure!(
            known_paths.contains(&key.as_str()) || options.contains(&key.as_str()),
            "Unknown option {key:?} in {directive} entry"
        );
    }
    let mut paths = known_paths.into_iter().filter_map(|key| table.get(key));
    let path = paths
        .next()
        .with_context(|| format!("{directive} entry needs a `path` string"))?;
    anyhow::ensure!(
        paths.next().is_none(),
        "{directive} entry accepts only one path spelling"
    );
    Ok(path)
}

fn directive_items(value: &toml::Value) -> &[toml::Value] {
    value
        .as_array()
        .map_or_else(|| std::slice::from_ref(value), Vec::as_slice)
}

/// Parse path and source directives, including legacy path aliases.
fn directive_paths(
    spec: &toml::Value,
    directive: &str,
    config_root: &Path,
) -> Result<Vec<EnvPathDirective>> {
    let source = directive == "_.source";
    let options: &[&str] = if source {
        &["tools", "redact"]
    } else {
        &["tools", "position"]
    };
    let mut paths = Vec::new();
    for item in directive_items(spec) {
        let (raw, tools_phase, redact) = match item {
            toml::Value::String(_) => (item, false, false),
            toml::Value::Table(table) => {
                let raw = directive_table_path(table, directive, options)?;
                if let Some(position) = table.get("position") {
                    anyhow::ensure!(
                        position.as_str() == Some("prepend"),
                        "_.path position must be 'prepend'"
                    );
                }
                (
                    raw,
                    boolean_option(table, "tools", directive)?,
                    source && boolean_option(table, "redact", directive)?,
                )
            }
            _ => anyhow::bail!("Unsupported {directive} entry: want string or table"),
        };
        for candidate in directive_items(raw) {
            let path = candidate.as_str().with_context(|| {
                format!("{directive} entry `path` must be a string or string array")
            })?;
            paths.push(EnvPathDirective {
                path: config_root.join(path),
                tools_phase,
                redact,
            });
        }
    }
    Ok(paths)
}

fn parse_file_directive(item: &toml::Value, config_root: &Path) -> Result<EnvFileDirective> {
    let (path, redact, tools_phase, expand) = match item {
        toml::Value::String(path) => (path.as_str(), false, false, false),
        toml::Value::Table(table) => {
            let path = directive_table_path(table, "_.file", &["redact", "tools", "expand"])?
                .as_str()
                .context("_.file entry needs a `path` string")?;
            (
                path,
                boolean_option(table, "redact", "_.file")?,
                boolean_option(table, "tools", "_.file")?,
                boolean_option(table, "expand", "_.file")?,
            )
        }
        _ => anyhow::bail!("Unsupported _.file entry: want string or table"),
    };
    Ok(EnvFileDirective {
        path: config_root.join(path),
        redact,
        tools_phase,
        expand,
    })
}

/// Parse the `[env]` table and redaction patterns of one document.
/// Relative directive paths resolve against the declaring root.
pub(crate) fn parse_mise_env(document: &toml::Value, config_root: &Path) -> Result<MiseEnv> {
    let mut parsed = MiseEnv::default();
    if let Some(value) = document.get("redactions") {
        let patterns = value
            .as_array()
            .context("redactions must be an array of strings")?;
        for pattern in patterns {
            let pattern = pattern
                .as_str()
                .context("redactions entries must be strings")?;
            parsed.redactions.push(pattern.to_owned());
        }
    }
    let Some(env) = document.get("env") else {
        return Ok(parsed);
    };
    let env = env.as_table().context("env must be a table")?;
    for (name, spec) in env {
        if name != "_" {
            parsed.entries.push(parse_entry(name, spec)?);
            continue;
        }
        let directives = spec
            .as_table()
            .context("env._ must be a table of directives")?;
        for (directive, value) in directives {
            match directive.as_str() {
                "path" => parsed.paths.extend(
                    directive_paths(value, "_.path", config_root)?
                        .into_iter()
                        .map(|entry| (entry.path, entry.tools_phase)),
                ),
                "file" => {
                    for item in directive_items(value) {
                        parsed.files.push(parse_file_directive(item, config_root)?);
                    }
                }
                "source" => parsed
                    .sources
                    .extend(directive_paths(value, "_.source", config_root)?),
                other => anyhow::bail!("Unknown env directive _.{other}"),
            }
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

struct EnvFileValue {
    text: String,
    // Expansion can be disabled for the directive or by single quotes.
    // Otherwise these sorted byte offsets mark escaped dollar signs.
    literal_dollars: Option<Vec<usize>>,
}

impl EnvFileValue {
    fn new(text: String, expand: bool) -> Self {
        Self {
            text,
            literal_dollars: expand.then(Vec::new),
        }
    }

    fn push_literal_dollar(&mut self) {
        if let Some(offsets) = &mut self.literal_dollars {
            offsets.push(self.text.len());
        }
        self.text.push('$');
    }
}

type FileBindings = Vec<(String, EnvFileValue)>;

fn quoted_dotenv_value<'a>(
    mut line: &'a str,
    quote: char,
    lines: &mut impl Iterator<Item = (usize, &'a str)>,
    expand: bool,
) -> Result<EnvFileValue> {
    let mut value = EnvFileValue::new(String::with_capacity(line.len()), expand && quote == '"');
    loop {
        let mut chars = line.char_indices().peekable();
        while let Some((offset, char)) = chars.next() {
            if char == quote {
                let rest = line[offset + 1..].trim_start();
                anyhow::ensure!(
                    rest.is_empty() || rest.starts_with('#'),
                    "unexpected characters after closing quote"
                );
                return Ok(value);
            }
            if char == '\\' && quote == '"' {
                match chars.peek().map(|(_, next)| *next) {
                    Some('$') => {
                        chars.next();
                        value.push_literal_dollar();
                        continue;
                    }
                    Some(next @ ('"' | '\\' | 'n' | 'r' | 't')) => {
                        chars.next();
                        value.text.push(match next {
                            'n' => '\n',
                            'r' => '\r',
                            't' => '\t',
                            other => other,
                        });
                        continue;
                    }
                    _ => {}
                }
            }
            value.text.push(char);
        }
        let (_, next) = lines.next().context("missing closing quote")?;
        value.text.push('\n');
        line = next;
    }
}

fn unquoted_dotenv_value(raw: &str, expand: bool) -> EnvFileValue {
    let end = raw
        .match_indices('#')
        .find(|(offset, _)| raw[..*offset].ends_with(char::is_whitespace))
        .map_or(raw.len(), |(offset, _)| offset);
    let text = raw[..end].trim();
    if !expand || !text.contains("\\$") {
        return EnvFileValue::new(text.to_owned(), expand);
    }
    let mut value = EnvFileValue::new(String::with_capacity(text.len()), true);
    for (index, part) in text.split("\\$").enumerate() {
        if index > 0 {
            value.push_literal_dollar();
        }
        value.text.push_str(part);
    }
    value
}

fn parse_dotenv(content: &str, path: &Path, expand: bool) -> Result<FileBindings> {
    let mut pairs = Vec::new();
    let mut lines = content.lines().enumerate();
    while let Some((index, raw_line)) = lines.next() {
        let line = raw_line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line
            .strip_prefix("export")
            .filter(|rest| rest.starts_with(char::is_whitespace))
            .map_or(line, str::trim_start);
        let Some((key, raw)) = line.split_once('=') else {
            anyhow::bail!(
                "Malformed line {} in {}: expected KEY=value",
                index + 1,
                path.display()
            );
        };
        let key = key.trim();
        validate_env_name(key)?;
        let text = raw.trim_start();
        let value = match text.chars().next() {
            Some(quote @ ('\'' | '"')) => {
                quoted_dotenv_value(&text[1..], quote, &mut lines, expand).with_context(|| {
                    format!("Malformed line {} in {}", index + 1, path.display())
                })?
            }
            _ => unquoted_dotenv_value(raw, expand),
        };
        pairs.push((key.to_owned(), value));
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
        _ => anyhow::bail!("Non-scalar value for {key} in {}", path.display()),
    }
}

/// Load one `_.file` directive. Returns `Ok(None)` when the file is missing;
/// strict callers turn that into an error, lenient callers warn and skip.
fn load_env_file(directive: &EnvFileDirective) -> Result<Option<FileBindings>> {
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
                    pairs.push((key.clone(), EnvFileValue::new(text, directive.expand)));
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
                let text = match value {
                    toml::Value::String(text) => text.clone(),
                    toml::Value::Integer(number) => number.to_string(),
                    toml::Value::Boolean(flag) => flag.to_string(),
                    _ => {
                        anyhow::bail!("Non-scalar value for {key} in {}", directive.path.display())
                    }
                };
                pairs.push((key.clone(), EnvFileValue::new(text, directive.expand)));
            }
            pairs
        }
        "yaml" | "yml" => {
            anyhow::bail!(
                "Env file {} is YAML, which OMG cannot parse; convert it to dotenv, JSON, or TOML",
                directive.path.display()
            );
        }
        _ => parse_dotenv(&content, &directive.path, directive.expand)?,
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
    base: &'a Environment,
    /// config_root for `{{config_root}}` templates.
    config_root: &'a Path,
    /// Ordered assignments; later entries override earlier ones.
    assigned: Vec<(String, OsString)>,
    /// Index into `assigned` for override-in-place.
    index: HashMap<String, usize>,
    unset: Vec<String>,
    redacted: HashSet<String>,
    patterns: &'a [String],
    required: &'a mut Vec<String>,
}

impl Resolver<'_> {
    fn lookup(&self, name: &str) -> Option<&OsStr> {
        if self.unset.iter().any(|removed| removed == name) {
            return None;
        }
        self.index
            .get(name)
            .and_then(|position| self.assigned.get(*position))
            .map(|(_, value)| value.as_os_str())
            .or_else(|| self.base.get(OsStr::new(name)).map(OsString::as_os_str))
    }

    fn lookup_text(&self, name: &str) -> Result<Option<&str>> {
        if name == "\0config_root" {
            return self
                .config_root
                .to_str()
                .map(Some)
                .context("Mise config root is not UTF-8");
        }
        self.lookup(name)
            .map(|value| {
                value
                    .to_str()
                    .with_context(|| format!("Environment variable {name} is not UTF-8"))
            })
            .transpose()
    }

    fn mark_redacted(&mut self, name: &str, redact: bool) {
        if ResolvedEnv::is_redacted(name, redact, self.patterns) {
            self.redacted.insert(name.to_owned());
        }
    }

    fn assign(&mut self, name: &str, value: OsString, redact: bool) {
        self.mark_redacted(name, redact);
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

    fn apply_entry(&mut self, entry: &EnvEntry, tools_phase: bool) -> Result<()> {
        if entry.tools_phase != tools_phase {
            return Ok(());
        }
        match &entry.action {
            EnvAction::Set(raw) => {
                let value = expand_templates(raw, &|name| self.lookup_text(name))?;
                self.assign(&entry.name, value.into(), entry.redact);
            }
            EnvAction::Default(raw) => {
                let current = self.lookup(&entry.name);
                if current.is_none_or(OsStr::is_empty) {
                    let value = expand_templates(raw, &|name| self.lookup_text(name))?;
                    self.assign(&entry.name, value.into(), entry.redact);
                } else if let Some(value) = current {
                    self.assign(&entry.name, value.to_owned(), entry.redact);
                }
            }
            EnvAction::Required => {
                self.required.push(entry.name.clone());
                self.mark_redacted(&entry.name, entry.redact);
            }
            EnvAction::Unset => self.remove(&entry.name),
        }
        Ok(())
    }

    /// Apply one loaded file's pairs in the current phase.
    fn apply_file(
        &mut self,
        directive: &EnvFileDirective,
        pairs: &[(String, EnvFileValue)],
        tools_phase: bool,
    ) -> Result<()> {
        if directive.tools_phase != tools_phase {
            return Ok(());
        }
        for (key, raw) in pairs {
            let value = if let Some(literals) = &raw.literal_dollars {
                expand_dollar(&raw.text, literals, &|name| self.lookup_text(name))?
            } else {
                raw.text.clone()
            };
            self.assign(key, value.into(), directive.redact);
        }
        Ok(())
    }
}

/// Resolve one parsed `[env]` in two phases: entries without `tools = true`
/// first (so tool installs see them), then the lazy `tools = true` phase
/// once `PATH` is final.
fn resolve_one(
    parsed: &MiseEnv,
    file_pairs: &[(EnvFileDirective, FileBindings)],
    base: &Environment,
    config_root: &Path,
    patterns: &[String],
    required: &mut Vec<String>,
) -> Result<ResolvedEnv> {
    let mut resolver = Resolver {
        base,
        config_root,
        assigned: Vec::new(),
        index: HashMap::new(),
        unset: Vec::new(),
        redacted: HashSet::new(),
        patterns,
        required,
    };
    for tools_phase in [false, true] {
        for (directive, pairs) in file_pairs {
            resolver.apply_file(directive, pairs, tools_phase)?;
        }
        for entry in &parsed.entries {
            resolver.apply_entry(entry, tools_phase)?;
        }
        let mut paths = parsed
            .paths
            .iter()
            .filter(|(_, phase)| *phase == tools_phase)
            .map(|(path, _)| path.as_path())
            .peekable();
        if paths.peek().is_some() {
            let path = prepend_paths(paths, resolver.lookup("PATH"))?;
            // PATH is an ordered layer effect and must be visible to later sources.
            resolver.assign("PATH", path, false);
        }
        for source in &parsed.sources {
            if source.tools_phase != tools_phase {
                continue;
            }
            #[cfg(unix)]
            {
                // Resolve source effects in their declaring layer so later
                // documents see them and can override them. Do not replay
                // these scripts after the chain has already been merged.
                let mut effective = resolver.base.clone();
                effective.extend(
                    resolver
                        .assigned
                        .iter()
                        .map(|(key, value)| (OsString::from(key), value.clone())),
                );
                for name in &resolver.unset {
                    effective.remove(OsStr::new(name));
                }
                let sourced = eval_sourced_file(&source.path, &effective)?;
                for (key, value) in sourced.set {
                    resolver.assign(&key, value, source.redact);
                }
                for key in sourced.unset {
                    resolver.remove(&key);
                }
            }
            #[cfg(not(unix))]
            anyhow::bail!(
                "_.source scripts require a Unix shell: {}",
                source.path.display()
            );
        }
    }
    Ok(ResolvedEnv {
        set: resolver.assigned,
        unset: resolver.unset,
        redacted: resolver.redacted,
    })
}

fn resolve_task_overlay(
    parsed: &MiseEnv,
    base: &Environment,
    config_root: &Path,
    required: &mut Vec<String>,
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
        required,
    )
}

#[cfg(test)]
pub(crate) fn resolve_task_env(
    parsed: &MiseEnv,
    base: &Environment,
    config_root: &Path,
) -> Result<ResolvedEnv> {
    resolve_launch_env(
        &[],
        base.clone(),
        Some((parsed, config_root)),
        Strictness::Strict,
    )
}

/// Merge one [`ResolvedEnv`] into an accumulated chain result: later files
/// override earlier assignments, removals win over prior assignments, and
/// redactions accumulate in order.
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
    accumulated.redacted.extend(next.redacted);
}

/// Load and resolve `[env]` from `start` and its ancestors.
///
/// `base` is the process environment snapshot. Production callers use
/// [`Strictness::Strict`] and fail closed on missing required inputs.
#[cfg(test)]
pub(crate) fn load_mise_env_chain(
    start: &Path,
    base: &Environment,
    strict: Strictness,
) -> Result<ResolvedEnv> {
    let selection = super::mise_config::environment_selection(
        base.get(OsStr::new("MISE_ENV")).map(OsString::as_os_str),
    )?;
    let documents = super::mise_config::load(start, &selection)?;
    resolve_launch_env(&documents, base.clone(), None, strict)
}

/// Resolve all applicable layers and check requirements against the child's
/// final environment.
pub(crate) fn resolve_launch_env(
    documents: &[super::mise_config::Document],
    mut effective: Environment,
    task: Option<(&MiseEnv, &Path)>,
    strict: Strictness,
) -> Result<ResolvedEnv> {
    let mut required = Vec::new();
    let mut merged = resolve_mise_env_chain(documents, &mut effective, &mut required, strict)?;
    if let Some((parsed, root)) = task {
        let overlay = resolve_task_overlay(parsed, &effective, root, &mut required)?;
        overlay.apply_to(&mut effective);
        merge_chain(&mut merged, overlay);
    }
    if let Some(name) = required.iter().find(|name| {
        effective
            .get(OsStr::new(name))
            .is_none_or(|value| value.is_empty())
    }) {
        let message = format!(
            "Required environment variable {name} is not set. Define it in the shell, project configuration, or task environment"
        );
        if strict == Strictness::Strict {
            anyhow::bail!("{message}");
        }
        tracing::warn!("{message}");
    }
    Ok(merged)
}

fn resolve_mise_env_chain(
    documents: &[super::mise_config::Document],
    effective: &mut Environment,
    required: &mut Vec<String>,
    strict: Strictness,
) -> Result<ResolvedEnv> {
    let mut merged = ResolvedEnv::default();
    let mut patterns: Vec<String> = Vec::new();
    for document in documents {
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
            effective,
            config_root,
            &patterns,
            required,
        )?;
        resolved.apply_to(effective);
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
pub(crate) fn eval_sourced_file(script: &Path, base: &Environment) -> Result<ResolvedEnv> {
    use crate::core::runtime_resolver::find_in_path;

    // Resolve the collector and shell before applying the project's PATH. A
    // source script can change PATH again or reset its own positional arguments.
    let shell = find_in_path("bash")
        .or_else(|| find_in_path("sh"))
        .or_else(|| find_in_path("/bin/sh"))
        .context("No shell found for mise environment source")?;
    let collector = find_in_path("env")
        .or_else(|| find_in_path("/usr/bin/env"))
        .or_else(|| find_in_path("/bin/env"))
        .context("No env executable found for mise environment source")?;
    let output = std::process::Command::new(&shell)
        .env_clear()
        .envs(base)
        .arg("-c")
        .arg(
            r#"
readonly __omg_source_env_program="$1"
shift
command printf '\000omg-source-snapshot\000'
"$__omg_source_env_program" -0 || exit $?
command printf '\000omg-source-snapshot\000'
. "$0" >/dev/null 2>&1
case $? in 0) ;; *) exit $? ;; esac
"$__omg_source_env_program" -0 || exit $?
command printf '\000omg-source-snapshot\000'
"#,
        )
        .arg(script)
        .arg(collector)
        .stderr(std::process::Stdio::null())
        .output()
        .with_context(|| format!("Failed to run {} for {}", shell.display(), script.display()))?;

    anyhow::ensure!(
        output.status.success(),
        "{} failed while sourcing {}",
        shell.display(),
        script.display()
    );

    const BOUNDARY: &[u8] = b"omg-source-snapshot";
    let incomplete = || {
        format!(
            "Incomplete environment snapshot while sourcing {}",
            script.display()
        )
    };
    // A boundary is a separate NUL-delimited record. It cannot match a
    // binding, and the final one distinguishes an empty env from an early exit.
    let mut records = output.stdout.split(|byte| *byte == 0);
    anyhow::ensure!(records.any(|record| record == BOUNDARY), incomplete());
    let mut snapshots = std::iter::from_fn(|| {
        let mut ended = false;
        let values = parse_nul_env(records.by_ref().take_while(|record| {
            ended = *record == BOUNDARY;
            !ended
        }));
        ended.then_some(values)
    });
    let before = snapshots.next().with_context(incomplete)?;
    let after = snapshots.next().with_context(incomplete)?;
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

/// Parse NUL-separated `KEY=value` records from `env -0` output. Records
/// without `=` cannot come from `env` and are ignored defensively.
#[cfg(unix)]
fn parse_nul_env<'a>(records: impl Iterator<Item = &'a [u8]>) -> HashMap<String, OsString> {
    use std::os::unix::ffi::OsStringExt as _;

    let mut vars = HashMap::new();
    for record in records {
        let mut parts = record.splitn(2, |byte| *byte == b'=');
        if let (Some(key), Some(value)) = (parts.next(), parts.next())
            && let Ok(key) = std::str::from_utf8(key)
            && validate_env_name(key).is_ok()
        {
            vars.insert(key.to_owned(), OsString::from_vec(value.to_vec()));
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

    fn base(pairs: &[(&str, &str)]) -> Environment {
        pairs
            .iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value)))
            .collect()
    }

    fn parse_env(toml_text: &str, root: &Path) -> MiseEnv {
        let document: toml::Value = toml::from_str(toml_text).expect("test TOML parses");
        parse_mise_env(&document, root).expect("test [env] parses")
    }

    fn resolve_text(toml_text: &str, base_map: &Environment, strict: Strictness) -> ResolvedEnv {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let parsed = parse_env(toml_text, dir.path());
        resolve_launch_env(&[], base_map.clone(), Some((&parsed, dir.path())), strict)
            .expect("test resolve succeeds")
    }

    fn get(resolved: &ResolvedEnv, name: &str) -> Option<String> {
        resolved
            .set
            .iter()
            .find(|(key, _)| key == name)
            .and_then(|(_, value)| value.to_str().map(str::to_owned))
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
        let text = "[env]\nTOKEN = { required = true, redact = true }\n";
        let dir = tempfile::TempDir::new().expect("tempdir");
        let parsed = parse_env(text, dir.path());
        let task = Some((&parsed, dir.path()));
        let missing = resolve_launch_env(&[], base(&[]), task, Strictness::Strict)
            .expect_err("task launch requires TOKEN");
        assert!(
            missing
                .to_string()
                .contains("Required environment variable TOKEN")
        );
        let lenient = resolve_launch_env(&[], base(&[]), task, Strictness::Lenient).expect("skips");
        assert!(get(&lenient, "TOKEN").is_none());
        let mut inherited = base(&[("TOKEN", "fixture-value")]);
        let filled = resolve_launch_env(&[], inherited.clone(), task, Strictness::Strict)
            .expect("inherited value satisfies requirement");
        assert!(get(&filled, "TOKEN").is_none());
        assert!(filled.redacted.contains("TOKEN"));
        filled.apply_to(&mut inherited);
        assert_eq!(
            inherited.get(OsStr::new("TOKEN")).map(OsString::as_os_str),
            Some(OsStr::new("fixture-value"))
        );
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
                resolve_task_env(&parsed, &base(&[]), dir.path()).is_err(),
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
            false,
        )
        .expect("dotenv parses");
        let map: HashMap<&str, &str> = pairs
            .iter()
            .map(|(key, value)| (key.as_str(), value.text.as_str()))
            .collect();
        assert_eq!(map["A"], "1");
        assert_eq!(map["B"], "two words");
        assert_eq!(map["C"], "three");
        assert_eq!(map["D"], "four");
        assert_eq!(map["E"], "");
        assert!(parse_dotenv("NO_EQUALS_HERE\n", &path, false).is_err());
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
            .map(|(key, value)| (key.as_str(), value.text.as_str()))
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
        let map: HashMap<&str, &str> = pairs
            .iter()
            .map(|(key, value)| (key.as_str(), value.text.as_str()))
            .collect();
        assert_eq!(map["X"], "yes");
        assert_eq!(map["Y"], "7");

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
            expand_dollar("$A/${B}/lit", &[], &|name| Ok(match name {
                "A" => Some("x"),
                "B" => Some("y"),
                _ => None,
            }))
            .unwrap(),
            "x/y/lit"
        );
        assert_eq!(expand_dollar("$-$${", &[], &|_| Ok(None)).unwrap(), "$-$${");
        assert_eq!(
            expand_dollar("${UNFINISHED", &[], &|_| Ok(None)).unwrap(),
            "${UNFINISHED"
        );
    }

    #[test]
    fn redaction_flags_and_patterns() {
        assert!(glob_match("*_TOKEN", "API_TOKEN"));
        assert!(glob_match("SECRET_*", "SECRET_KEY"));
        assert!(glob_match("*KEY*", "MONKEY_BUSINESS"));
        assert!(!glob_match("SECRET_*", "MY_SECRET"));
        assert!(glob_match("*", "ANYTHING"));
        assert!(!glob_match("EXACT", "exact"));
        for (pattern, name, expected) in [
            ("A*_TOKEN", "API_TOKEN_OLD_TOKEN", true),
            ("*API*_TOKEN", "API_TOKEN_OLD_TOKEN", true),
            ("*A*A", "A", false),
            ("A*A", "A", false),
            ("A*A", "AA", true),
            ("**_TOKEN", "API_TOKEN_OLD_TOKEN", true),
            ("*_TOKEN", "API_TOKEN_SUFFIX", false),
            ("*MISSING*", "API_TOKEN", false),
            ("**", "", true),
        ] {
            assert_eq!(glob_match(pattern, name), expected, "{pattern:?} {name:?}");
        }

        let text = "redactions = [\"*_TOKEN\"]\n[env]\nA = \"1\"\nB = { value = \"s\", redact = true }\nC = \"x\"\n";
        let resolved = resolve_text(text, &base(&[]), Strictness::Strict);
        assert!(!resolved.redacted.contains("A"));
        assert!(resolved.redacted.contains("B"));
        assert!(!resolved.redacted.contains("C"));
    }

    #[test]
    fn redaction_patterns_match_repeated_suffixes_without_changing_values() {
        let resolved = resolve_text(
            "redactions = ['*_TOKEN']\n[env]\nAPI_TOKEN = 'first'\nAPI_TOKEN_OLD_TOKEN = 'repeated'\nAPI_TOKEN_SUFFIX = 'visible'\nTOKEN = 'plain'\nFLAGGED = { value = 'explicit', redact = true }\n",
            &base(&[]),
            Strictness::Strict,
        );
        assert_eq!(
            resolved
                .set
                .into_iter()
                .map(|(key, value)| (OsString::from(key), value))
                .collect::<Environment>(),
            base(&[
                ("API_TOKEN", "first"),
                ("API_TOKEN_OLD_TOKEN", "repeated"),
                ("API_TOKEN_SUFFIX", "visible"),
                ("TOKEN", "plain"),
                ("FLAGGED", "explicit"),
            ])
        );
        assert_eq!(
            resolved.redacted,
            HashSet::from([
                "API_TOKEN".to_string(),
                "API_TOKEN_OLD_TOKEN".to_string(),
                "FLAGGED".to_string(),
            ])
        );
        assert!(resolved.unset.is_empty());
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
        assert_eq!(parsed.sources[0].path, dir.path().join("scripts/env.sh"));
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
            "printf x >> \"$0.calls\"\nexport FROM_SOURCE=parent\nexport MODE=parent\n",
        )
        .expect("parent source");
        let child = dir.path().join("child");
        std::fs::create_dir(&child).expect("child directory");
        std::fs::write(child.join("mise.toml"), "[env]\nMODE = \"child\"\nCOPY = \"{{env.FROM_SOURCE}}\"\nFROM_SOURCE = { required = true }\n").expect("child config");
        let resolved =
            load_mise_env_chain(&child, &std::env::vars_os().collect(), Strictness::Strict)
                .expect("source precedes child resolution");
        assert_eq!(get(&resolved, "COPY").as_deref(), Some("parent"));
        assert_eq!(get(&resolved, "MODE").as_deref(), Some("child"));
        assert_eq!(
            std::fs::read_to_string(dir.path().join("parent.sh.calls")).expect("source ran"),
            "x",
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
                set: vec![("A".to_string(), "child".into())],
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
        let env = std::env::vars_os().collect();
        assert!(eval_sourced_file(&script, &env).is_err());
        std::fs::write(&script, "export PARTIAL=yes\nreturn 1\n").expect("script");
        assert!(eval_sourced_file(&script, &env).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn source_redaction_and_parent_patterns_reach_the_resolved_environment() {
        let root = tempfile::tempdir().unwrap();
        let child = root.path().join("child");
        std::fs::create_dir(&child).unwrap();
        std::fs::write(root.path().join("mise.toml"), "redactions = ['*_TOKEN']\n").unwrap();
        std::fs::write(
            child.join("mise.toml"),
            "[env]\nLOCAL_TOKEN = 'fixture'\n[env._]\nsource = { path = 'source.sh', redact = true }\n",
        )
        .unwrap();
        std::fs::write(child.join("source.sh"), "export OMG_SOURCE_FIXTURE=ready\n").unwrap();
        let resolved =
            load_mise_env_chain(&child, &std::env::vars_os().collect(), Strictness::Strict)
                .expect("load configured environment");
        assert_eq!(
            resolved.redacted,
            HashSet::from(["LOCAL_TOKEN".to_owned(), "OMG_SOURCE_FIXTURE".to_owned()])
        );
        assert_eq!(
            get(&resolved, "OMG_SOURCE_FIXTURE").as_deref(),
            Some("ready")
        );
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
        let mut env: Environment = std::env::vars_os().collect();
        env.insert("CONFIGURED".into(), "/resolved".into());
        env.insert("SECRET".into(), "removed".into());
        let resolved = eval_sourced_file(&script, &env).expect("source");
        assert_eq!(get(&resolved, "RESULT").as_deref(), Some("/resolved/bin"));
        assert!(resolved.unset.iter().any(|key| key == "SECRET"));
    }

    #[cfg(unix)]
    #[test]
    fn nul_env_parsing_skips_junk() {
        let records = b"GOOD=1\x00NOEQUALS\x00BAD-NAME=2\x00EMPTY=\x00".split(|byte| *byte == 0);
        let vars = parse_nul_env(records);
        assert_eq!(vars.get("GOOD").and_then(|value| value.to_str()), Some("1"));
        assert!(!vars.contains_key("BAD-NAME"));
        assert_eq!(vars.get("EMPTY").and_then(|value| value.to_str()), Some(""));
    }

    #[test]
    #[cfg(unix)]
    fn sourced_script_diff_returns_new_vars() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let script = dir.path().join("env.sh");
        std::fs::write(
            &script,
            "export OMG_SWARM_PROBE_$RANDOM=1\nexport OMG_FIXED_PROBE=yes\n",
        )
        .expect("script");
        // `$RANDOM` differs per shell invocation, so only the fixed variable
        // can be asserted deterministically.
        let vars =
            eval_sourced_file(&script, &std::env::vars_os().collect()).expect("eval succeeds");
        assert_eq!(get(&vars, "OMG_FIXED_PROBE").as_deref(), Some("yes"));
    }
}
