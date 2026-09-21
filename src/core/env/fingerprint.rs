//! Environment fingerprinting and drift detection
//!
//! Captures the state of all managed runtimes and system packages
//! to detect environment drift and ensure reproducibility.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use tokio::task;

use crate::runtimes::{SUPPORTED_RUNTIMES, probe_version, tool_registry::REGISTRY_TOOLS};

/// Represents the captured state of the environment
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct EnvironmentState {
    /// Lockfile schema version. Written on save; `load` rejects files written
    /// by a NEWER schema instead of guessing at unknown fields.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// Runtime versions (`runtime_name` -> version)
    pub runtimes: BTreeMap<String, String>,
    /// Explicitly installed system packages
    pub packages: Vec<String>,
    /// Timestamp of capture
    pub timestamp: i64,
    /// SHA256 hash of the state (runtimes + packages)
    pub hash: String,
}

fn default_schema_version() -> u32 {
    EnvironmentState::SCHEMA_VERSION
}

impl EnvironmentState {
    /// Current lockfile schema version.
    pub const SCHEMA_VERSION: u32 = 1;

    /// Capture the current environment state
    pub async fn capture() -> Result<Self> {
        // One bounded filesystem pass covers the same registered names as the
        // runtime CLI. A hand-maintained subset silently misses drift.
        let runtimes = task::spawn_blocking(|| {
            SUPPORTED_RUNTIMES
                .iter()
                .copied()
                .chain(REGISTRY_TOOLS.iter().map(|tool| tool.name))
                .filter_map(|runtime| {
                    probe_version(runtime)
                        .map(|version| (runtime.to_owned(), version.trim().to_owned()))
                })
                .collect::<BTreeMap<_, _>>()
        })
        .await
        .context("Failed to probe managed runtime versions")?;

        let packages = explicit_packages_for_fingerprint().await?;

        let timestamp = jiff::Timestamp::now().as_second();

        let mut state = Self {
            schema_version: Self::SCHEMA_VERSION,
            runtimes,
            packages,
            timestamp,
            hash: String::new(),
        };

        state.normalize();

        // Calculate hash
        state.hash = state.calculate_hash();

        Ok(state)
    }

    /// Calculate SHA256 hash of the state
    #[must_use]
    pub fn calculate_hash(&self) -> String {
        let mut hasher = Sha256::new();

        let (runtimes, packages) = self.normalized_parts();

        for (key, value) in runtimes {
            hasher.update(key.as_bytes());
            hasher.update(b":");
            hasher.update(value.as_bytes());
            hasher.update(b";");
        }

        for pkg in packages {
            hasher.update(pkg.as_bytes());
            hasher.update(b";");
        }

        hex::encode(hasher.finalize())
    }

    /// Save state to omg.lock file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut normalized = self.clone();
        normalized.schema_version = Self::SCHEMA_VERSION;
        normalized.normalize();
        normalized.hash = normalized.calculate_hash();
        let content = toml::to_string_pretty(&normalized)?;
        write_lockfile(path.as_ref(), content.as_bytes())
    }

    /// Load and verify state from an omg.lock file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let content = read_lockfile(path)?;
        Self::parse_lockfile(&content)
            .map_err(|error| anyhow::anyhow!("Invalid lockfile {}: {error}", path.display()))
    }

    /// Parse and verify lockfile content before it is persisted.
    pub fn parse_lockfile(content: &str) -> Result<Self> {
        // Reject files written by a newer schema BEFORE parsing, so unknown
        // future fields produce an actionable message instead of accidental
        // best-effort deserialization.
        if let Ok(raw) = toml::from_str::<toml::Value>(content) {
            let file_version = raw
                .get("schema_version")
                .and_then(toml::Value::as_integer)
                .unwrap_or_else(|| i64::from(Self::SCHEMA_VERSION));
            if file_version > i64::from(Self::SCHEMA_VERSION) {
                anyhow::bail!(
                    "Lockfile was written by a newer omg (schema version {file_version}). \
                     Upgrade omg to read it."
                );
            }
        }
        let mut state: Self = toml::from_str(content).context("Failed to parse lockfile")?;
        // Corruption check, not authentication: the hash is recomputed from
        // the same content, so anyone who can write the file can forge it.
        // Trust comes from the transport (gist ownership, file ownership),
        // never from this comparison.
        let stored_hash = state.hash.clone();
        state.normalize();
        let calculated_hash = state.calculate_hash();
        if stored_hash != calculated_hash {
            anyhow::bail!("Lockfile integrity check failed: stored hash does not match contents");
        }
        state.hash = calculated_hash;
        Ok(state)
    }

    fn normalize(&mut self) {
        let (runtimes, packages) = self.normalized_parts();
        self.runtimes = runtimes.into_iter().collect();
        self.packages = packages;
    }

    fn normalized_parts(&self) -> (Vec<(String, String)>, Vec<String>) {
        let mut runtimes: Vec<(String, String)> = self
            .runtimes
            .iter()
            .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            .collect();
        runtimes.sort_by(|a, b| a.0.cmp(&b.0));

        let mut packages: Vec<String> = self
            .packages
            .iter()
            .map(|pkg| pkg.trim().to_string())
            .filter(|pkg| !pkg.is_empty())
            .collect();
        packages.sort_unstable();
        packages.dedup();

        (runtimes, packages)
    }
}

#[allow(
    clippy::unused_async,
    reason = "backend builds await a blocking package probe while backend-free builds fail directly"
)]
async fn explicit_packages_for_fingerprint() -> Result<Vec<String>> {
    #[cfg(any(feature = "arch", feature = "debian", feature = "debian-pure"))]
    {
        tokio::task::spawn_blocking(crate::package_managers::list_explicit_fast)
            .await
            .context("Explicit package probe task failed")?
    }

    #[cfg(not(any(feature = "arch", feature = "debian", feature = "debian-pure")))]
    fingerprint_requires_backend()
}

#[cfg(any(
    not(any(feature = "arch", feature = "debian", feature = "debian-pure")),
    test
))]
fn fingerprint_requires_backend() -> Result<Vec<String>> {
    anyhow::bail!(
        "Environment fingerprinting is not available without an Arch or Debian package backend"
    )
}

pub(crate) fn read_lockfile(path: &Path) -> Result<String> {
    use std::io::Read as _;

    const MAX_LOCKFILE_BYTES: u64 = 16 * 1024 * 1024;

    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("Failed to inspect lockfile {}", path.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "Refusing to read lockfile that is not a regular file: {}",
        path.display()
    );

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .with_context(|| format!("Failed to open lockfile {} safely", path.display()))?;
    anyhow::ensure!(
        file.metadata()?.file_type().is_file(),
        "Refusing to read lockfile that is not a regular file: {}",
        path.display()
    );

    let mut bytes = Vec::new();
    file.take(MAX_LOCKFILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("Failed to read lockfile {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_LOCKFILE_BYTES,
        "Lockfile exceeds the {} byte limit: {}",
        MAX_LOCKFILE_BYTES,
        path.display()
    );
    String::from_utf8(bytes).with_context(|| format!("Lockfile is not UTF-8: {}", path.display()))
}

fn write_lockfile(path: &Path, content: &[u8]) -> Result<()> {
    use std::io::Write;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("Failed to create lockfile directory {}", parent.display()))?;

    let mut temporary = tempfile::NamedTempFile::new_in(parent).with_context(|| {
        format!(
            "Failed to create temporary lockfile in {}",
            parent.display()
        )
    })?;
    temporary
        .as_file_mut()
        .write_all(content)
        .with_context(|| format!("Failed to write lockfile {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file_mut()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .with_context(|| format!("Failed to set lockfile permissions {}", path.display()))?;
    }

    temporary
        .as_file_mut()
        .sync_all()
        .with_context(|| format!("Failed to sync lockfile {}", path.display()))?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("Failed to replace lockfile {}", path.display()))?;
    crate::core::safe_ops::sync_parent_directory_sync(path)?;
    Ok(())
}

/// Drift analysis result
#[derive(Debug)]
pub struct DriftReport {
    pub has_drift: bool,
    pub missing_runtimes: Vec<String>,
    pub different_runtimes: Vec<(String, String, String)>, // (name, expected, actual)
    pub extra_runtimes: Vec<String>,
    pub missing_packages: Vec<String>,
    pub extra_packages: Vec<String>,
}

impl DriftReport {
    /// Compare two states and generate a drift report
    #[must_use]
    pub fn compare(expected: &EnvironmentState, actual: &EnvironmentState) -> Self {
        let mut report = Self {
            has_drift: false,
            missing_runtimes: Vec::new(),
            different_runtimes: Vec::new(),
            extra_runtimes: Vec::new(),
            missing_packages: Vec::new(),
            extra_packages: Vec::new(),
        };

        // Check runtimes
        for (name, ver) in &expected.runtimes {
            if let Some(actual_ver) = actual.runtimes.get(name) {
                if ver != actual_ver {
                    report
                        .different_runtimes
                        .push((name.clone(), ver.clone(), actual_ver.clone()));
                    report.has_drift = true;
                }
            } else {
                report.missing_runtimes.push(name.clone());
                report.has_drift = true;
            }
        }

        for name in actual.runtimes.keys() {
            if !expected.runtimes.contains_key(name) {
                report.extra_runtimes.push(name.clone());
                report.has_drift = true;
            }
        }

        // Check packages
        for pkg in &expected.packages {
            if !actual.packages.contains(pkg) {
                report.missing_packages.push(pkg.clone());
                report.has_drift = true;
            }
        }

        for pkg in &actual.packages {
            if !expected.packages.contains(pkg) {
                report.extra_packages.push(pkg.clone());
                report.has_drift = true;
            }
        }

        report
    }

    /// Print the drift report
    /// Render the drift report as terminal-safe lines.
    ///
    /// Lockfile fields (and package-manager metadata) are remote/user input;
    /// every dynamic string is stripped of terminal control sequences before
    /// display so a hostile lockfile cannot inject OSC/CSI output
    /// (csf_dd687683).
    #[must_use]
    pub fn render_lines(&self) -> Vec<String> {
        let clean = |text: &str| crate::cli::style::sanitize_terminal_text(text);
        let mut lines = Vec::new();
        if !self.has_drift {
            lines.push(format!(
                "{} No drift detected. Environment matches lockfile.",
                crate::cli::style::positive("✓")
            ));
            return lines;
        }

        lines.push(format!(
            "{} Environment drift detected!\n",
            crate::cli::style::caution("⚠")
        ));

        if !self.missing_runtimes.is_empty() {
            lines.push(crate::cli::style::negative("Missing Runtimes:"));
            for r in &self.missing_runtimes {
                lines.push(format!("  - {}", clean(r)));
            }
        }

        if !self.different_runtimes.is_empty() {
            lines.push(crate::cli::style::caution("Version Mismatches:"));
            for (name, expected, actual) in &self.different_runtimes {
                lines.push(format!(
                    "  ~ {} (expected: {}, actual: {})",
                    clean(name),
                    crate::cli::style::positive(&clean(expected)),
                    crate::cli::style::negative(&clean(actual))
                ));
            }
        }

        if !self.extra_runtimes.is_empty() {
            lines.push(crate::cli::style::informative(
                "Extra Runtimes (not in lockfile):",
            ));
            for r in &self.extra_runtimes {
                lines.push(format!("  + {}", clean(r)));
            }
        }

        if !self.missing_packages.is_empty() {
            lines.push(String::new());
            lines.push(crate::cli::style::negative("Missing Packages:"));
            for p in &self.missing_packages {
                lines.push(format!("  - {}", clean(p)));
            }
        }

        if !self.extra_packages.is_empty() {
            lines.push(String::new());
            lines.push(crate::cli::style::informative(
                "Extra Packages (not in lockfile):",
            ));
            for p in &self.extra_packages {
                lines.push(format!("  + {}", clean(p)));
            }
        }
        lines
    }

    /// Print the drift report.
    pub fn print(&self) {
        for line in self.render_lines() {
            println!("{line}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drift_report_never_renders_terminal_control_sequences() {
        let hostile = "\u{1b}]52;c;pwned\u{7}pkg\u{1b}[31mred".to_string();
        let report = DriftReport {
            has_drift: true,
            missing_runtimes: vec![hostile.clone()],
            different_runtimes: vec![(hostile.clone(), hostile.clone(), hostile.clone())],
            extra_runtimes: vec![hostile.clone()],
            missing_packages: vec![hostile.clone()],
            extra_packages: vec![hostile],
        };

        let rendered = report.render_lines().join("\n");
        assert!(!rendered.contains('\u{1b}'), "ESC must be stripped");
        assert!(!rendered.contains('\u{7}'), "BEL must be stripped");
        assert!(rendered.contains("pkg"), "legible text must survive");
        assert_eq!(
            DriftReport {
                has_drift: false,
                ..report
            }
            .render_lines()
            .join("\n"),
            crate::cli::style::positive("✓") + " No drift detected. Environment matches lockfile."
        );
    }

    #[test]
    fn lockfile_runtime_keys_are_serialized_in_order() {
        let mut state = EnvironmentState {
            schema_version: EnvironmentState::SCHEMA_VERSION,
            runtimes: std::collections::BTreeMap::from([
                ("zsh".to_string(), "1".to_string()),
                ("bash".to_string(), "2".to_string()),
            ]),
            packages: Vec::new(),
            timestamp: 0,
            hash: String::new(),
        };
        state.hash = state.calculate_hash();

        let serialized = toml::to_string_pretty(&state).expect("serialize lockfile");
        assert!(serialized.find("bash =").unwrap() < serialized.find("zsh =").unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn save_creates_owner_only_lockfile() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::TempDir::new().expect("temp dir");
        let path = directory.path().join("omg.lock");
        let state = EnvironmentState {
            schema_version: EnvironmentState::SCHEMA_VERSION,
            runtimes: BTreeMap::new(),
            packages: vec!["foo".to_string()],
            timestamp: 0,
            hash: "abc".to_string(),
        };

        state.save(&path).expect("save lockfile");

        let mode = std::fs::metadata(&path)
            .expect("lockfile metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "lockfile must not be group or world accessible, got {mode:o}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_symlinked_lockfiles() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::TempDir::new().expect("temp dir");
        let target = directory.path().join("target.lock");
        let link = directory.path().join("omg.lock");
        let state = EnvironmentState {
            schema_version: EnvironmentState::SCHEMA_VERSION,
            runtimes: BTreeMap::new(),
            packages: vec!["curl".to_string()],
            timestamp: 0,
            hash: String::new(),
        };
        state.save(&target).expect("save target lockfile");
        symlink(&target, &link).expect("create lockfile symlink");

        let error = EnvironmentState::load(&link).expect_err("symlinked lockfile must be rejected");
        assert!(
            error.to_string().contains("regular file"),
            "error must name the rejected file type: {error}"
        );
    }

    #[test]
    fn load_rejects_lockfiles_from_newer_schema_versions() {
        let directory = tempfile::TempDir::new().expect("temp dir");
        let path = directory.path().join("omg.lock");

        // A file written by a hypothetical future omg with schema_version 99
        // must be rejected with an actionable message, not deserialized by
        // best-effort field matching.
        let newer_schema =
            "schema_version = 99\nruntimes = {}\npackages = []\ntimestamp = 0\nhash = 'x'\n";
        std::fs::write(&path, newer_schema).expect("write future lockfile");

        let error = EnvironmentState::load(&path).expect_err("future schema must be rejected");
        assert!(
            error.to_string().contains("newer omg"),
            "error must explain the version mismatch: {error}"
        );
    }

    #[test]
    fn save_recomputes_hash_from_normalized_contents() {
        let directory = tempfile::TempDir::new().expect("temp dir");
        let path = directory.path().join("omg.lock");
        let state = EnvironmentState {
            schema_version: EnvironmentState::SCHEMA_VERSION,
            runtimes: BTreeMap::from([("node".to_string(), " 22 ".to_string())]),
            packages: vec!["zlib".to_string(), "curl".to_string()],
            timestamp: 0,
            hash: "stale".to_string(),
        };

        state.save(&path).expect("save lockfile");
        let loaded = EnvironmentState::load(&path).expect("load verified lockfile");

        assert_ne!(loaded.hash, "stale");
        assert_eq!(loaded.hash, loaded.calculate_hash());
        assert_eq!(loaded.runtimes["node"], "22");
    }

    #[test]
    fn load_rejects_contents_that_do_not_match_stored_hash() {
        let directory = tempfile::TempDir::new().expect("temp dir");
        let path = directory.path().join("omg.lock");
        let mut state = EnvironmentState {
            schema_version: EnvironmentState::SCHEMA_VERSION,
            runtimes: BTreeMap::new(),
            packages: vec!["curl".to_string()],
            timestamp: 0,
            hash: String::new(),
        };
        state.hash = state.calculate_hash();
        state.packages.push("tampered".to_string());
        fs::write(
            &path,
            toml::to_string_pretty(&state).expect("serialize state"),
        )
        .expect("write tampered lockfile");

        let error = EnvironmentState::load(&path)
            .expect_err("tampered lockfile must fail its integrity check");

        assert!(error.to_string().contains("integrity check failed"));
    }

    #[test]
    fn fingerprint_without_backend_is_an_error() {
        let error = fingerprint_requires_backend()
            .expect_err("env capture with no backend must not invent an empty package list");
        assert!(
            error
                .to_string()
                .contains("not available without an Arch or Debian package backend"),
            "got: {error}"
        );
    }
}
