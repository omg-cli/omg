//! OMG Settings and Configuration

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::core::paths;

/// Set by `omg install --review` / `omg update --review` for this process.
static CLI_REVIEW_PKGBUILD: AtomicBool = AtomicBool::new(false);

/// Maximum config file size (1MB) to prevent `DoS` via large configs
const MAX_CONFIG_SIZE: u64 = 1024 * 1024;

/// Maximum metadata cache TTL (7 days in seconds)
const MAX_CACHE_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// Maximum concurrent AUR builds: the `omg config set` CLI rejects values
/// outside `1..=MAX_BUILD_CONCURRENCY`, and every consumer clamps
/// (`build_concurrency()` floors at 1, parallel builds clamp 1..=8).
pub(crate) const MAX_BUILD_CONCURRENCY: usize = 8;

/// Reject concurrency outside `1..=MAX_BUILD_CONCURRENCY`.
///
/// # Errors
/// Returns an error when `value` is zero or above the maximum, so a
/// poisoned config fails closed instead of exhausting resources.
pub(crate) fn validate_build_concurrency(value: usize) -> Result<()> {
    if value == 0 {
        anyhow::bail!("aur.build_concurrency must be at least 1");
    }
    if value > MAX_BUILD_CONCURRENCY {
        anyhow::bail!(
            "aur.build_concurrency exceeds maximum of {MAX_BUILD_CONCURRENCY}. \
             Use a value between 1 and {MAX_BUILD_CONCURRENCY}."
        );
    }
    Ok(())
}

/// Reject MAKEFLAGS containing anything outside the allowlist.
///
/// The allowlist already excludes every shell metacharacter, so no
/// separate denylist is needed.
///
/// # Errors
/// Returns an error naming the allowed characters when `value` contains
/// anything else, so a poisoned config fails closed instead of reaching
/// a build command.
pub(crate) fn validate_makeflags(value: &str) -> Result<()> {
    let is_safe = value.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '-' || c == '=' || c == ' ' || c == ',' || c == '.'
    });
    if !is_safe {
        anyhow::bail!(
            "Invalid MAKEFLAGS: only alphanumeric, '-', '=', space, comma, and '.' \
             are allowed (e.g. '-j8'). Shell metacharacters such as '$()' are rejected."
        );
    }
    Ok(())
}

/// Convert a serialized TOML value into its editable counterpart for
/// comment-preserving config merges.
fn edit_item(value: toml::Value) -> toml_edit::Item {
    match value {
        toml::Value::Table(table) => {
            let mut edit = toml_edit::Table::new();
            for (key, value) in table {
                edit.insert(&key, toml_edit::Item::Value(edit_value(value)));
            }
            toml_edit::Item::Table(edit)
        }
        value => toml_edit::Item::Value(edit_value(value)),
    }
}

fn edit_value(value: toml::Value) -> toml_edit::Value {
    match value {
        toml::Value::String(text) => toml_edit::Value::from(text),
        toml::Value::Integer(number) => toml_edit::Value::from(number),
        toml::Value::Float(number) => toml_edit::Value::from(number),
        toml::Value::Boolean(flag) => toml_edit::Value::from(flag),
        toml::Value::Datetime(stamp) => stamp
            .to_string()
            .parse::<toml_edit::Datetime>()
            .map_or_else(
                |_| toml_edit::Value::from(stamp.to_string()),
                toml_edit::Value::from,
            ),
        toml::Value::Array(items) => items
            .into_iter()
            .map(edit_value)
            .collect::<toml_edit::Value>(),
        toml::Value::Table(table) => {
            let mut inline = toml_edit::InlineTable::new();
            for (key, value) in table {
                inline.insert(&key, edit_value(value));
            }
            toml_edit::Value::InlineTable(inline)
        }
    }
}

/// Validate a path doesn't contain path traversal sequences
fn validate_config_path(path: &Path, field_name: &str) -> Result<()> {
    let path_str = path.to_string_lossy();

    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        anyhow::bail!("Config error: {field_name} contains a parent-directory component");
    }

    if path_str.contains('\0') {
        anyhow::bail!("Config error: {field_name} contains null byte");
    }

    if path.is_absolute() {
        let home = dirs::home_dir();
        let temp = std::env::temp_dir();
        let is_safe = home.as_ref().is_some_and(|home| path.starts_with(home))
            || path.starts_with(&temp)
            || path.starts_with("/var/cache")
            || path.starts_with("/var/tmp");

        if !is_safe {
            anyhow::bail!(
                "Config error: {field_name} absolute path must be under the current home directory, {}, /var/cache, or /var/tmp",
                temp.display()
            );
        }

        // Shared-writable build dirs let another local user plant files the
        // build later trusts. Sticky dirs (like /tmp) still allow planting,
        // so say so loudly instead of failing closed on common setups.
        #[cfg(unix)]
        if let Ok(meta) = std::fs::metadata(path) {
            use std::os::unix::fs::MetadataExt as _;
            if meta.mode() & 0o022 != 0 {
                eprintln!(
                    "Warning: {field_name} '{}' is group/world-writable; another local user could plant build inputs there.",
                    path.display()
                );
            }
        }
    }

    Ok(())
}

/// OMG configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// OMG data directory, resolved from the current environment at load time.
    #[serde(skip, default = "paths::data_dir")]
    pub data_dir: PathBuf,

    /// Daemon socket path, resolved from the current environment at load time.
    #[serde(skip, default = "paths::socket_path")]
    pub socket_path: PathBuf,

    /// Whether telemetry is enabled
    pub telemetry_enabled: bool,

    /// AUR build configuration
    pub aur: AurBuildSettings,
}

/// AUR build configuration
#[expect(clippy::struct_excessive_bools)] // Configuration struct: booleans map to user-facing toggle options
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AurBuildSettings {
    /// Build method for AUR packages
    pub build_method: AurBuildMethod,
    /// Maximum concurrent AUR builds
    pub build_concurrency: usize,
    /// Require interactive PKGBUILD review before building.
    /// On by default; disable with `aur.review_pkgbuild = false` (CI only).
    pub review_pkgbuild: bool,
    /// Use stricter makepkg flags (cleanbuild/verifysource)
    pub secure_makepkg: bool,
    /// Allow native builds without sandboxing
    pub allow_unsafe_builds: bool,
    /// Explicitly expose host networking to sandboxed build code.
    pub allow_network: bool,
    /// Use AUR metadata archive for bulk update checks
    pub use_metadata_archive: bool,
    /// Metadata archive cache TTL (seconds)
    pub metadata_cache_ttl_secs: u64,
    /// Custom MAKEFLAGS (overrides auto -jN)
    pub makeflags: Option<String>,
    /// Custom PKGDEST (shared package cache)
    pub pkgdest: Option<PathBuf>,
    /// Custom SRCDEST (shared source cache)
    pub srcdest: Option<PathBuf>,
    /// Enable build cache re-use based on PKGBUILD hash
    pub cache_builds: bool,
    /// Enable ccache integration
    pub enable_ccache: bool,
    /// Optional ccache directory
    pub ccache_dir: Option<PathBuf>,
    /// Enable sccache integration
    pub enable_sccache: bool,
    /// Optional sccache directory
    pub sccache_dir: Option<PathBuf>,
}

/// AUR build method options
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AurBuildMethod {
    Bubblewrap,
    Chroot,
    Native,
}

impl Default for Settings {
    fn default() -> Self {
        let data_dir = paths::data_dir();

        // Socket in XDG_RUNTIME_DIR or /tmp
        let socket_path = paths::socket_path();

        Self {
            data_dir,
            socket_path,
            telemetry_enabled: false,
            aur: AurBuildSettings::default(),
        }
    }
}

impl Default for AurBuildSettings {
    fn default() -> Self {
        Self {
            build_method: AurBuildMethod::Bubblewrap,
            build_concurrency: 1,
            review_pkgbuild: true,
            secure_makepkg: true,
            allow_unsafe_builds: false,
            allow_network: false,
            use_metadata_archive: true,
            metadata_cache_ttl_secs: 300,
            makeflags: None,
            pkgdest: None,
            srcdest: None,
            cache_builds: true,
            enable_ccache: false,
            ccache_dir: None,
            enable_sccache: false,
            sccache_dir: None,
        }
    }
}

impl Settings {
    /// Load settings from config file
    /// Reject unknown top-level and `aur`-table keys before deserialization.
    ///
    /// Serde would otherwise silently ignore typos, fabricating a working-looking
    /// config from misspelled settings.
    fn validate_known_keys(content: &str) -> Result<()> {
        let table: toml::Table = toml::from_str(content).context("Config is not valid TOML")?;
        crate::core::security::policy::validate_legacy_security_config(
            &table,
            std::path::Path::new("config.toml"),
        )?;

        const ROOT_KEYS: [&str; 2] = ["telemetry_enabled", "aur"];
        const AUR_KEYS: [&str; 16] = [
            "build_method",
            "build_concurrency",
            "review_pkgbuild",
            "secure_makepkg",
            "allow_unsafe_builds",
            "allow_network",
            "use_metadata_archive",
            "metadata_cache_ttl_secs",
            "makeflags",
            "pkgdest",
            "srcdest",
            "cache_builds",
            "enable_ccache",
            "ccache_dir",
            "enable_sccache",
            "sccache_dir",
        ];

        // Legacy sections written by older omg releases. They carry no
        // settings the current schema consumes; recognize them so existing
        // installs keep working, but tell the user they are ignored. Populated
        // security controls were rejected above and never reach this fallback.
        const LEGACY_KEYS: [&str; 8] = [
            "cache",
            "general",
            "security",
            "data_dir",
            "socket_path",
            "shims_enabled",
            "default_shell",
            "auto_update",
        ];

        let mut unknown = Vec::new();
        for key in table.keys() {
            if ROOT_KEYS.contains(&key.as_str()) {
                continue;
            }
            if LEGACY_KEYS.contains(&key.as_str()) {
                // Settings::load runs many times per invocation (telemetry
                // gates, completions, ...); warn once per process so a daily
                // command is not spammed with the same notice. This stays a
                // warn (not debug): RUST_LOG=warn must surface it, per the
                // tracing-diagnostics contract test.
                use std::sync::atomic::{AtomicBool, Ordering};
                static WARNED: AtomicBool = AtomicBool::new(false);
                if !WARNED.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        key = key.as_str(),
                        "config section '{key}' is deprecated and ignored by this omg version"
                    );
                }
                continue;
            }
            unknown.push(key.clone());
        }
        if let Some(aur) = table.get("aur").and_then(|value| value.as_table()) {
            for key in aur.keys() {
                if !AUR_KEYS.contains(&key.as_str()) {
                    unknown.push(format!("aur.{key}"));
                }
            }
        }

        if unknown.is_empty() {
            return Ok(());
        }
        anyhow::bail!(
            "unknown configuration keys: {}. Allowed top-level keys: {}; allowed 'aur' keys: {}",
            unknown.join(", "),
            ROOT_KEYS.join(", "),
            AUR_KEYS.join(", ")
        )
    }

    /// Opt into PKGBUILD review for this invocation (`--review`).
    pub fn enable_cli_review_pkgbuild() {
        CLI_REVIEW_PKGBUILD.store(true, Ordering::SeqCst);
    }

    /// Run environment-selected config fixtures as an ordinary user, including
    /// when the container test runner is root. Production root path resolution
    /// deliberately ignores OMG_CONFIG_DIR and must stay exercised unchanged.
    #[cfg(test)]
    pub(crate) fn rerun_config_test_unprivileged(test_name: &str) -> bool {
        #[cfg(unix)]
        if crate::core::is_root() {
            use std::os::unix::fs::PermissionsExt;
            use std::os::unix::process::CommandExt;

            let account = nix::unistd::User::from_name("nobody")
                .expect("look up unprivileged fixture account")
                .expect("root test containers must provide nobody");
            assert_ne!(account.uid.as_raw(), 0, "fixture account must not be root");
            // Copy outside potentially root-only checkout ancestors. The parent
            // keeps ownership so the child cannot replace its test executable.
            let fixture = tempfile::TempDir::new_in("/tmp").expect("test executable directory");
            std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o755))
                .expect("allow fixture account to traverse executable directory");
            let executable = fixture.path().join("config-test");
            std::fs::copy(
                std::env::current_exe().expect("test executable"),
                &executable,
            )
            .expect("copy test executable");
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
                .expect("allow fixture account to execute tests");
            let output = std::process::Command::new(&executable)
                .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
                .current_dir(fixture.path())
                .env("TMPDIR", "/tmp")
                .uid(account.uid.as_raw())
                .gid(account.gid.as_raw())
                .output()
                .expect("execute unprivileged config fixture");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                output.status.success() && stdout.contains("1 passed; 0 failed"),
                "unprivileged {test_name} failed or did not run: {}\n{stdout}\n{stderr}",
                output.status
            );
            return true;
        }
        let _ = test_name;
        false
    }

    #[cfg(test)]
    fn reset_cli_review_pkgbuild() {
        CLI_REVIEW_PKGBUILD.store(false, Ordering::SeqCst);
    }

    pub fn load() -> Result<Self> {
        let config_path = Self::config_path()?;

        if config_path.exists() {
            // Security: refuse symlinks and non-files before reading, so a
            // planted link cannot redirect the config read.
            let metadata = std::fs::symlink_metadata(&config_path)
                .with_context(|| format!("Failed to stat config: {}", config_path.display()))?;
            if metadata.file_type().is_symlink() {
                anyhow::bail!("Config must not be a symlink: {}", config_path.display());
            }
            if !metadata.file_type().is_file() {
                anyhow::bail!("Config must be a regular file: {}", config_path.display());
            }
            // Security: Check file size before reading to prevent DoS
            if metadata.len() > MAX_CONFIG_SIZE {
                anyhow::bail!(
                    "Config file too large: {} bytes (max {} bytes)",
                    metadata.len(),
                    MAX_CONFIG_SIZE
                );
            }

            let content = std::fs::read_to_string(&config_path)
                .with_context(|| format!("Failed to read config: {}", config_path.display()))?;
            Self::validate_known_keys(&content).with_context(|| {
                format!(
                    "Invalid config: {} (unknown keys are rejected to catch typos)",
                    config_path.display()
                )
            })?;
            let settings: Self = toml::from_str(&content)
                .with_context(|| format!("Failed to parse config: {}", config_path.display()))?;

            // Security: Validate all path fields to prevent path traversal
            settings.validate_paths()?;

            // Security: Validate TTL bounds
            if settings.aur.metadata_cache_ttl_secs > MAX_CACHE_TTL_SECS {
                anyhow::bail!(
                    "aur.metadata_cache_ttl_secs too large: {} (max {} = 7 days)",
                    settings.aur.metadata_cache_ttl_secs,
                    MAX_CACHE_TTL_SECS
                );
            }
            // Security: the `omg config set` CLI validates MAKEFLAGS, but
            // the file itself is a trust boundary (shared dotfiles,
            // OMG_CONFIG_DIR). Enforce the same allowlist here so
            // direct-TOML edits cannot smuggle shell metacharacters into
            // build commands.
            // Note: build_concurrency is deliberately NOT range-checked
            // here. The pinned contract
            // (tests/coverage_1.rs
            // `build_concurrency_clamps_configured_zero_to_one`) requires
            // that a configured 0 loads and clamps to 1 at the consumer,
            // and every consumer already bounds the value
            // (`build_concurrency()` floors at 1, update checks clamp
            // 4..=16, parallel builds clamp 1..=8). Rejecting here would
            // hard-fail every command on out-of-range files for no gain.
            if let Some(makeflags) = &settings.aur.makeflags {
                validate_makeflags(makeflags)?;
            }

            Ok(settings.with_runtime_overrides())
        } else {
            if let Some(dir) = std::env::var_os("OMG_CONFIG_DIR").filter(|v| !v.is_empty()) {
                tracing::warn!(
                    "OMG_CONFIG_DIR {} is set but {} is missing; using defaults",
                    PathBuf::from(&dir).display(),
                    config_path.display()
                );
            }
            Ok(Self::default().with_runtime_overrides())
        }
    }

    fn with_runtime_overrides(mut self) -> Self {
        if CLI_REVIEW_PKGBUILD.load(Ordering::SeqCst) {
            self.aur.review_pkgbuild = true;
        }
        self
    }

    /// Validate all path fields to prevent path traversal attacks
    fn validate_paths(&self) -> Result<()> {
        if let Some(ref path) = self.aur.pkgdest {
            validate_config_path(path, "aur.pkgdest")?;
        }
        if let Some(ref path) = self.aur.srcdest {
            validate_config_path(path, "aur.srcdest")?;
        }
        if let Some(ref path) = self.aur.ccache_dir {
            validate_config_path(path, "aur.ccache_dir")?;
        }
        if let Some(ref path) = self.aur.sccache_dir {
            validate_config_path(path, "aur.sccache_dir")?;
        }
        Ok(())
    }

    /// Hold this lease across the complete read-modify-save operation.
    pub(crate) fn write_lock() -> Result<std::fs::File> {
        let path = Self::config_path()?.with_extension("lock");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create config directory")?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
        }
        let lock = options
            .open(path)
            .context("Failed to open configuration lock")?;
        match lock.try_lock() {
            Ok(()) => Ok(lock),
            Err(std::fs::TryLockError::WouldBlock) => {
                anyhow::bail!("Another configuration mutation is running; retry when it finishes")
            }
            Err(std::fs::TryLockError::Error(error)) => {
                Err(error).context("Failed to acquire configuration lock")
            }
        }
    }

    /// Save a complete settings value, replacing all managed values rather than patching a field.
    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_path()?;

        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config dir: {}", parent.display()))?;
        }

        // Merge into the existing document instead of reserializing: a full
        // rewrite destroys user comments and unknown keys. Only managed
        // tables are touched; everything else keeps its text verbatim.
        let content = match std::fs::read_to_string(&config_path) {
            Ok(existing) => match existing.parse::<toml_edit::DocumentMut>() {
                Ok(mut document) => {
                    self.merge_settings(&mut document)?;
                    document.to_string()
                }
                Err(_) => self.serialize_full()?,
            },
            Err(_) => self.serialize_full()?,
        };
        crate::core::safe_ops::atomic_write_file_sync(&config_path, content)
            .with_context(|| format!("Failed to write config: {}", config_path.display()))
    }

    fn serialize_full(&self) -> Result<String> {
        toml::to_string_pretty(self).context("Failed to serialize config")
    }

    /// Known keys per managed table. A key present here but absent from the
    /// serialized update is a cleared `Option` and is removed; any other
    /// absent key is the user's own and is preserved.
    const TOP_LEVEL_KEYS: &[&str] = &["telemetry_enabled", "aur"];
    const AUR_KEYS: &[&str] = &[
        "build_method",
        "build_concurrency",
        "review_pkgbuild",
        "secure_makepkg",
        "allow_unsafe_builds",
        "allow_network",
        "use_metadata_archive",
        "metadata_cache_ttl_secs",
        "makeflags",
        "pkgdest",
        "srcdest",
        "cache_builds",
        "enable_ccache",
        "ccache_dir",
        "enable_sccache",
        "sccache_dir",
    ];

    fn merge_settings(&self, document: &mut toml_edit::DocumentMut) -> Result<()> {
        let table = toml::Value::try_from(self).context("Failed to serialize config")?;
        let toml::Value::Table(map) = table else {
            anyhow::bail!("Settings did not serialize to a TOML table");
        };
        Self::merge_table(document.as_table_mut(), map, Self::TOP_LEVEL_KEYS);
        Ok(())
    }

    /// Assign a merged value while keeping the key's existing decor
    /// (comments, whitespace). `Table::insert` replaces decor; occupied
    /// assignment keeps it.
    fn set_preserving_decor(document: &mut toml_edit::Table, key: &str, item: toml_edit::Item) {
        match document.entry(key) {
            toml_edit::Entry::Occupied(mut entry) => {
                *entry.get_mut() = item;
            }
            toml_edit::Entry::Vacant(entry) => {
                entry.insert(item);
            }
        }
    }

    fn merge_table(
        document: &mut toml_edit::Table,
        update: toml::map::Map<String, toml::Value>,
        known: &[&str],
    ) {
        let mut seen = std::collections::HashSet::with_capacity(update.len());
        for (key, value) in update {
            seen.insert(key.clone());
            let nested = match key.as_str() {
                "aur" => Some(Self::AUR_KEYS),
                _ => None,
            };
            match (nested, value) {
                (Some(nested_known), toml::Value::Table(nested_update)) => {
                    let entry = document
                        .entry(&key)
                        .or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
                    if let Some(table) = entry.as_table_mut() {
                        Self::merge_table(table, nested_update, nested_known);
                    } else {
                        *entry = edit_item(toml::Value::Table(nested_update));
                    }
                }
                (_, value) => {
                    Self::set_preserving_decor(document, &key, edit_item(value));
                }
            }
        }
        for key in known {
            if !seen.contains(*key) {
                document.remove(key);
            }
        }
    }

    /// Get the config file path
    pub fn config_path() -> Result<PathBuf> {
        let config_dir = paths::config_dir();

        Ok(config_dir.join("config.toml"))
    }

    /// Get the versions directory
    #[must_use]
    pub fn versions_dir(&self) -> PathBuf {
        self.data_dir.join("versions")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_paths_check_components_instead_of_dot_substrings() {
        assert!(validate_config_path(Path::new("pkg..cache/output"), "pkgdest").is_ok());
        assert!(validate_config_path(Path::new("cache/../escape"), "pkgdest").is_err());
    }

    #[test]
    fn config_paths_accept_the_current_home_and_reject_unrelated_roots() {
        if let Some(home) = dirs::home_dir() {
            assert!(validate_config_path(&home.join(".cache/omg"), "pkgdest").is_ok());
        }
        assert!(validate_config_path(Path::new("/etc/omg-output"), "pkgdest").is_err());
    }

    #[test]
    fn telemetry_requires_explicit_opt_in() {
        assert!(!Settings::default().telemetry_enabled);
    }

    #[test]
    fn aur_build_concurrency_defaults_to_one() {
        assert_eq!(Settings::default().aur.build_concurrency, 1);
    }

    #[test]
    fn example_security_defaults_match_runtime_defaults() -> Result<()> {
        let example = include_str!("../../examples/config.toml")
            .lines()
            .map(|line| {
                let candidate = line.strip_prefix('#').unwrap_or(line);
                match candidate.split_once(" = ") {
                    Some((
                        "telemetry_enabled"
                        | "build_method"
                        | "review_pkgbuild"
                        | "secure_makepkg"
                        | "allow_unsafe_builds",
                        _,
                    )) => candidate,
                    _ => line,
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let example: Settings = toml::from_str(&example)?;
        let defaults = Settings::default();
        assert_eq!(example.telemetry_enabled, defaults.telemetry_enabled);
        assert_eq!(
            std::mem::discriminant(&example.aur.build_method),
            std::mem::discriminant(&defaults.aur.build_method)
        );
        assert_eq!(example.aur.review_pkgbuild, defaults.aur.review_pkgbuild);
        assert_eq!(example.aur.secure_makepkg, defaults.aur.secure_makepkg);
        assert_eq!(
            example.aur.allow_unsafe_builds,
            defaults.aur.allow_unsafe_builds
        );
        Ok(())
    }

    #[test]
    #[serial_test::serial]
    fn cli_review_flag_enables_pkgbuild_review() {
        Settings::reset_cli_review_pkgbuild();
        assert!(
            Settings::default().aur.review_pkgbuild,
            "PKGBUILD review is on by default"
        );
        Settings::enable_cli_review_pkgbuild();
        let settings = Settings::default().with_runtime_overrides();
        Settings::reset_cli_review_pkgbuild();
        assert!(
            settings.aur.review_pkgbuild,
            "--review must keep PKGBUILD review on for this process"
        );
        assert!(
            Settings::default().aur.review_pkgbuild,
            "the process flag must not mutate Settings::default"
        );
    }

    /// Saving must preserve user comments and unknown keys, applying only
    /// the managed fields. Serial: save() resolves the process-global
    /// config path.
    #[serial_test::serial]
    #[test]
    fn save_preserves_comments_and_unknown_keys() {
        if Settings::rerun_config_test_unprivileged(
            "config::settings::tests::save_preserves_comments_and_unknown_keys",
        ) {
            return;
        }
        let dir = tempfile::TempDir::new().expect("isolated config dir");
        let dir_str = dir.path().to_string_lossy().into_owned();
        let vars: Vec<(&str, Option<&str>)> = vec![("OMG_CONFIG_DIR", Some(dir_str.as_str()))];
        temp_env::with_vars(&vars, || {
            // A newer OMG may have written keys this build does not know:
            // saving must keep them. load() rejects unknown keys, so the
            // settings under test are built programmatically instead.
            std::fs::write(
                Settings::config_path().expect("config path"),
                "# my comment\ntelemetry_enabled = false\nmy_custom_key = 42\n\n[aur]\n# aur comment\nbuild_concurrency = 4\n",
            )
            .expect("seed config");
            let settings = Settings {
                telemetry_enabled: true,
                aur: AurBuildSettings {
                    build_concurrency: 4,
                    ..Default::default()
                },
                ..Default::default()
            };
            settings.save().expect("save");
            let content = std::fs::read_to_string(Settings::config_path().expect("config path"))
                .expect("read back");
            assert!(content.contains("# my comment"), "{content}");
            assert!(content.contains("my_custom_key = 42"), "{content}");
            assert!(content.contains("# aur comment"), "{content}");
            assert!(content.contains("telemetry_enabled = true"), "{content}");
            assert!(content.contains("build_concurrency = 4"), "{content}");
        });
    }

    /// Clearing an `Option` removes its key instead of leaving the old
    /// value behind. Serial: save() resolves the process-global config path.
    #[serial_test::serial]
    #[test]
    fn save_removes_cleared_option_keys() {
        if Settings::rerun_config_test_unprivileged(
            "config::settings::tests::save_removes_cleared_option_keys",
        ) {
            return;
        }
        let dir = tempfile::TempDir::new().expect("isolated config dir");
        let dir_str = dir.path().to_string_lossy().into_owned();
        let vars: Vec<(&str, Option<&str>)> = vec![("OMG_CONFIG_DIR", Some(dir_str.as_str()))];
        temp_env::with_vars(&vars, || {
            std::fs::write(
                Settings::config_path().expect("config path"),
                "[aur]\nmakeflags = \"-j8\"\n",
            )
            .expect("seed config");
            let mut settings = Settings::load().expect("load seeded config");
            assert_eq!(settings.aur.makeflags.as_deref(), Some("-j8"));
            settings.aur.makeflags = None;
            settings.save().expect("save");
            let content = std::fs::read_to_string(Settings::config_path().expect("config path"))
                .expect("read back");
            assert!(!content.contains("makeflags"), "{content}");
        });
    }

    /// The merge key lists must mirror the serialized struct: every managed
    /// key is updatable, and no unknown key is ever removed.
    #[test]
    fn merge_key_lists_match_the_serialized_schema() {
        let table = toml::Value::try_from(Settings::default()).expect("serialize");
        let toml::Value::Table(top) = table else {
            panic!("settings must serialize to a table");
        };
        let mut top_keys: Vec<&str> = top.keys().map(String::as_str).collect();
        top_keys.sort_unstable();
        let mut expected = Settings::TOP_LEVEL_KEYS.to_vec();
        expected.sort_unstable();
        assert_eq!(top_keys, expected);

        let mut everything = Settings::default();
        everything.aur.makeflags = Some("-j1".to_string());
        everything.aur.pkgdest = Some(PathBuf::from("/tmp/pkg"));
        everything.aur.srcdest = Some(PathBuf::from("/tmp/src"));
        everything.aur.ccache_dir = Some(PathBuf::from("/tmp/ccache"));
        everything.aur.sccache_dir = Some(PathBuf::from("/tmp/sccache"));
        let table = toml::Value::try_from(&everything).expect("serialize");
        let toml::Value::Table(top) = table else {
            panic!("settings must serialize to a table");
        };
        let toml::Value::Table(aur) = &top["aur"] else {
            panic!("aur must serialize to a table");
        };
        let mut aur_keys: Vec<&str> = aur.keys().map(String::as_str).collect();
        aur_keys.sort_unstable();
        let mut expected = Settings::AUR_KEYS.to_vec();
        expected.sort_unstable();
        assert_eq!(aur_keys, expected);
    }

    #[test]
    fn serialized_settings_do_not_freeze_environment_resolved_paths() {
        let settings = Settings::default();
        let serialized = toml::to_string(&settings).expect("serialize settings");

        for obsolete in [
            "data_dir",
            "socket_path",
            "shims_enabled",
            "default_shell",
            "auto_update",
        ] {
            assert!(!serialized.contains(obsolete), "{serialized}");
        }
    }

    #[test]
    fn legacy_persisted_paths_are_ignored_on_read() {
        let parsed: Settings = toml::from_str(
            r#"
                data_dir = "/stale/data"
                socket_path = "/stale/socket"
                shims_enabled = true
                default_shell = "fish"
                auto_update = true
            "#,
        )
        .expect("legacy config remains readable");

        assert_eq!(parsed.data_dir, paths::data_dir());
        assert_eq!(parsed.socket_path, paths::socket_path());
    }

    #[serial_test::serial]
    #[test]
    fn legacy_security_settings_fail_closed_and_preserve_existing_configuration() {
        if Settings::rerun_config_test_unprivileged(
            "config::settings::tests::legacy_security_settings_fail_closed_and_preserve_existing_configuration",
        ) {
            return;
        }
        let dir = tempfile::TempDir::new().expect("isolated config dir");
        temp_env::with_var("OMG_CONFIG_DIR", Some(dir.path()), || {
            let config_path = Settings::config_path().unwrap();
            let policy_path = dir.path().join("policy.toml");
            let policy = "allow_aur = true\n";
            std::fs::write(&policy_path, policy).unwrap();
            for content in [
                "[security]\nallow_aur = false\n",
                "[security]\nminimum_grade = 'community'\n",
                "security = true\n",
            ] {
                std::fs::write(&config_path, content).unwrap();
                let error = Settings::load().expect_err("populated legacy security must fail");
                assert!(
                    format!("{error:#}").contains("Manually migrate"),
                    "{error:#}"
                );
                assert!(crate::core::security::SecurityPolicy::load_default().is_err());
                assert_eq!(std::fs::read_to_string(&config_path).unwrap(), content);
                assert_eq!(std::fs::read_to_string(&policy_path).unwrap(), policy);
            }
            std::fs::write(&config_path, "[security]\n[aur]\nreview_pkgbuild = true\n").unwrap();
            assert!(Settings::load().unwrap().aur.review_pkgbuild);
        });
    }

    /// A missing env-pointed config dir falls back to defaults (with a warn
    /// on stderr via tracing). Serial: load() resolves the process-global
    /// config path.
    #[serial_test::serial]
    #[test]
    fn config_missing_env_dir_loads_defaults() {
        if Settings::rerun_config_test_unprivileged(
            "config::settings::tests::config_missing_env_dir_loads_defaults",
        ) {
            return;
        }
        let missing = std::env::temp_dir().join("omg-missing-config-dir-probe");
        let _ = std::fs::remove_dir_all(&missing);
        let dir_str = missing.to_string_lossy().into_owned();
        assert!(!missing.exists());
        let vars: Vec<(&str, Option<&str>)> = vec![("OMG_CONFIG_DIR", Some(dir_str.as_str()))];
        temp_env::with_vars(&vars, || {
            let loaded = Settings::load().expect("missing env dir must load defaults");
            assert_eq!(
                format!("{loaded:?}"),
                format!("{:?}", Settings::default().with_runtime_overrides())
            );
        });
    }

    /// Direct-TOML edits must face the same MAKEFLAGS allowlist as the
    /// `omg config set` CLI. Serial: load() resolves the process-global
    /// config path.
    #[serial_test::serial]
    #[test]
    fn load_rejects_poisoned_makeflags() {
        if Settings::rerun_config_test_unprivileged(
            "config::settings::tests::load_rejects_poisoned_makeflags",
        ) {
            return;
        }
        let dir = tempfile::TempDir::new().expect("isolated config dir");
        let dir_str = dir.path().to_string_lossy().into_owned();
        let vars: Vec<(&str, Option<&str>)> = vec![("OMG_CONFIG_DIR", Some(dir_str.as_str()))];
        temp_env::with_vars(&vars, || {
            std::fs::write(
                Settings::config_path().expect("config path"),
                "[aur]\nmakeflags = \"-j8; rm -rf ~\"\n",
            )
            .expect("seed config");
            let error = Settings::load().expect_err("poisoned MAKEFLAGS must fail closed");
            assert!(error.to_string().contains("Invalid MAKEFLAGS"), "{error:?}");
        });
    }

    /// Extreme concurrency values must still load: the deliberate contract
    /// (see `build_concurrency_clamps_configured_zero_to_one` in
    /// tests/coverage_1.rs) clamps at the consumer instead of failing the
    /// whole config. Serial: load() resolves the process-global path.
    #[serial_test::serial]
    #[test]
    fn load_tolerates_extreme_concurrency_for_consumer_clamping() {
        if Settings::rerun_config_test_unprivileged(
            "config::settings::tests::load_tolerates_extreme_concurrency_for_consumer_clamping",
        ) {
            return;
        }
        for contents in [
            "[aur]\nbuild_concurrency = 0\n",
            "[aur]\nbuild_concurrency = 1000000\n",
        ] {
            let dir = tempfile::TempDir::new().expect("isolated config dir");
            let dir_str = dir.path().to_string_lossy().into_owned();
            let vars: Vec<(&str, Option<&str>)> = vec![("OMG_CONFIG_DIR", Some(dir_str.as_str()))];
            temp_env::with_vars(&vars, || {
                std::fs::write(Settings::config_path().expect("config path"), contents)
                    .expect("seed config");
                Settings::load().expect("extreme concurrency must load; consumers clamp");
            });
        }
    }

    /// Boundary values the CLI accepts must also load from TOML.
    #[serial_test::serial]
    #[test]
    fn load_accepts_valid_hardening_values() {
        if Settings::rerun_config_test_unprivileged(
            "config::settings::tests::load_accepts_valid_hardening_values",
        ) {
            return;
        }
        let dir = tempfile::TempDir::new().expect("isolated config dir");
        let dir_str = dir.path().to_string_lossy().into_owned();
        let vars: Vec<(&str, Option<&str>)> = vec![("OMG_CONFIG_DIR", Some(dir_str.as_str()))];
        temp_env::with_vars(&vars, || {
            std::fs::write(
                Settings::config_path().expect("config path"),
                "[aur]\nbuild_concurrency = 8\nmakeflags = \"-j8\"\n",
            )
            .expect("seed config");
            let settings = Settings::load().expect("valid values must load");
            assert_eq!(settings.aur.build_concurrency, 8);
            assert_eq!(settings.aur.makeflags.as_deref(), Some("-j8"));
        });
    }

    /// Unit coverage for the shared allowlist (also enforced by load()).
    #[test]
    fn makeflags_allowlist_rejects_shell_metacharacters() {
        for valid in ["-j8", "-j 8", "V=1", "a,b.c"] {
            validate_makeflags(valid)
                .unwrap_or_else(|error| panic!("allowlist must accept {valid}: {error:?}"));
        }
        for poisoned in [
            "$(reboot)",
            "a;b",
            "`id`",
            "a|b",
            "a&b",
            "a>b",
            "$HOME/x",
            "a'b",
        ] {
            assert!(
                validate_makeflags(poisoned).is_err(),
                "allowlist must reject {poisoned}"
            );
        }
    }
}
