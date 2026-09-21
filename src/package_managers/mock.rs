//! Mock package manager for isolated testing and CLI verification
//!
//! Enabled only when `OMG_TEST_MODE=1` is set.
//! Persists state to a JSON file in `OMG_DATA_DIR` to allow stateful tests across CLI runs.

use std::collections::HashMap;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::core::{Package, PackageSource, paths};
use crate::package_managers::traits::PackageManager;
use crate::package_managers::types::{UpdateInfo, parse_version_or_zero};

#[derive(Serialize, Deserialize, Default, Clone)]
struct MockState {
    installed: HashMap<String, String>,
    available: HashMap<String, String>,
}

/// Mock package database
#[derive(Default, Clone)]
pub struct MockPackageDb {
    pub packages: Arc<Mutex<HashMap<String, MockPackage>>>,
}

#[derive(Clone, Debug)]
pub struct MockPackage {
    pub name: String,
    pub version: String,
    pub description: String,
    pub repo: String,
}

impl MockPackageDb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_package(&self, name: &str, version: &str, description: &str, repo: &str) {
        self.packages
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                name.to_string(),
                MockPackage {
                    name: name.to_string(),
                    version: version.to_string(),
                    description: description.to_string(),
                    repo: repo.to_string(),
                },
            );
    }

    pub fn arch_defaults() -> Self {
        let db = Self::new();
        db.add_package("pacman", "6.0.2", "Arch package manager", "core");
        db.add_package("firefox", "122.0", "Web browser", "extra");
        db.add_package("git", "2.43.0", "Version control", "extra");
        db
    }

    pub fn debian_defaults() -> Self {
        let db = Self::new();
        db.add_package("apt", "2.6.1", "Debian package manager", "main");
        db.add_package("firefox-esr", "115.6.0", "Web browser", "main");
        db.add_package("git", "2.39.2", "Version control", "main");
        db
    }

    pub fn fedora_defaults() -> Self {
        let db = Self::new();
        db.add_package("dnf", "4.18.0", "Fedora package manager", "fedora");
        db.add_package("firefox", "122.0", "Web browser", "fedora");
        db.add_package("git", "2.43.0", "Version control", "fedora");
        db.add_package("vim-enhanced", "9.0.2103", "Text editor", "fedora");
        db.add_package("rust", "1.75.0", "Rust programming language", "fedora");
        db
    }

    pub fn macos_defaults() -> Self {
        let db = Self::new();
        db.add_package("homebrew", "4.2.0", "Homebrew package manager", "homebrew");
        db.add_package("wget", "1.21.4", "Network downloader", "homebrew");
        db.add_package("git", "2.43.0", "Version control", "homebrew");
        db.add_package("node", "20.11.0", "JavaScript runtime", "homebrew");
        db.add_package("python@3.12", "3.12.1", "Python interpreter", "homebrew");
        db
    }
}

pub struct MockPackageManager {
    pub db: MockPackageDb,
    pub distro_name: &'static str,
    state_dir: Option<PathBuf>,
}

/// Return the persistent-state backend name used by a mock distro.
#[must_use]
pub fn backend_name_for_distro(distro: &str) -> &'static str {
    match distro {
        "arch" => "pacman",
        "debian" | "ubuntu" => "apt",
        "fedora" | "rhel" => "dnf",
        "macos" | "darwin" => "homebrew",
        _ => "mock",
    }
}

impl MockPackageManager {
    pub fn new(distro: &str) -> Self {
        // Root production paths deliberately ignore caller overrides. Mock
        // fixtures must never share that production state: the explicit debug
        // test adapter has its own directory, including in root-run containers.
        let state_dir = crate::core::paths::test_mode()
            .then(|| std::env::var_os("OMG_DATA_DIR").filter(|value| !value.is_empty()))
            .flatten()
            .map(PathBuf::from);
        Self::build(distro, state_dir)
    }

    /// Create a mock whose persistent state is isolated to `data_dir`.
    pub fn new_in(distro: &str, data_dir: impl AsRef<Path>) -> Self {
        Self::build(distro, Some(data_dir.as_ref().to_path_buf()))
    }

    fn build(distro: &str, state_dir: Option<PathBuf>) -> Self {
        let db = match distro {
            "arch" => MockPackageDb::arch_defaults(),
            "debian" | "ubuntu" => MockPackageDb::debian_defaults(),
            "fedora" | "rhel" => MockPackageDb::fedora_defaults(),
            "macos" | "darwin" => MockPackageDb::macos_defaults(),
            _ => MockPackageDb::new(),
        };
        Self {
            db,
            distro_name: backend_name_for_distro(distro),
            state_dir,
        }
    }

    pub fn arch() -> Self {
        Self::new("arch")
    }

    pub fn debian() -> Self {
        Self::new("debian")
    }

    pub fn fedora() -> Self {
        Self::new("fedora")
    }

    pub fn macos() -> Self {
        Self::new("macos")
    }

    pub fn set_installed_version(&self, name: &str, version: &str) -> Result<()> {
        let mut state = self.load_state()?;
        state
            .installed
            .insert(name.to_string(), version.to_string());
        state
            .available
            .insert(name.to_string(), version.to_string());
        self.save_state(&state)?;
        Ok(())
    }

    pub fn set_available_version(&self, name: &str, version: &str) -> Result<()> {
        let mut state = self.load_state()?;
        state
            .available
            .insert(name.to_string(), version.to_string());
        self.save_state(&state)?;
        Ok(())
    }

    fn state_path(&self) -> PathBuf {
        let file_name = format!("mock_state_{}.json", self.distro_name);
        match &self.state_dir {
            Some(data_dir) => data_dir.join(file_name),
            None => paths::data_dir().join(file_name),
        }
    }

    fn load_state(&self) -> Result<MockState> {
        let path = self.state_path();
        let data = match fs::read_to_string(&path) {
            Ok(data) => data,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(MockState::default());
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read mock state at {}", path.display()));
            }
        };

        let value: serde_json::Value = serde_json::from_str(&data)
            .with_context(|| format!("failed to parse mock state at {}", path.display()))?;

        if let Some(installed_values) = value.get("installed").and_then(|value| value.as_array()) {
            let installed = installed_values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(|name| (name.to_string(), "0".to_string()))
                        .ok_or_else(|| anyhow!("legacy mock state contains a non-string package"))
                })
                .collect::<Result<HashMap<_, _>>>()?;
            let available = value
                .get("available")
                .cloned()
                .map(serde_json::from_value)
                .transpose()
                .context("failed to parse available packages in legacy mock state")?
                .unwrap_or_default();
            return Ok(MockState {
                installed,
                available,
            });
        }

        serde_json::from_value(value)
            .with_context(|| format!("invalid mock state schema at {}", path.display()))
    }

    fn save_state(&self, state: &MockState) -> Result<()> {
        let path = self.state_path();
        tracing::debug!("Mock saving state to {}", path.display());
        let data = serde_json::to_vec(state).context("failed to serialize mock state")?;
        crate::core::safe_ops::atomic_write_file_sync(path, data)
    }
}

impl PackageManager for MockPackageManager {
    fn name(&self) -> &'static str {
        self.distro_name
    }

    fn search(
        &self,
        query: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Package>>> + Send + '_>> {
        let query = query.to_lowercase();
        Box::pin(async move {
            let db = self.db.clone();
            let state = self.load_state()?;
            let pkgs = db
                .packages
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut results: Vec<Package> = pkgs
                .values()
                .filter(|p| {
                    p.name.to_lowercase().contains(&query)
                        || p.description.to_lowercase().contains(&query)
                })
                .map(|p| Package {
                    name: p.name.clone(),
                    version: parse_version_or_zero(&p.version),
                    description: p.description.clone(),
                    source: PackageSource::Official,
                    installed: state.installed.contains_key(&p.name),
                })
                .collect();
            results.extend(
                state
                    .available
                    .iter()
                    .filter(|(name, _)| {
                        !pkgs.contains_key(*name) && name.to_lowercase().contains(&query)
                    })
                    .map(|(name, version)| Package {
                        name: name.clone(),
                        version: parse_version_or_zero(version),
                        description: String::new(),
                        source: PackageSource::Official,
                        installed: state.installed.contains_key(name),
                    }),
            );
            results.sort_by(|left, right| left.name.cmp(&right.name));
            Ok(results)
        })
    }

    fn install(
        &self,
        packages: &[String],
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let packages = packages.to_vec();
        Box::pin(async move {
            let mut state = self.load_state()?;
            let pkgs = self
                .db
                .packages
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);

            for pkg in &packages {
                let exists = state.available.contains_key(pkg) || pkgs.contains_key(pkg);
                if !exists {
                    anyhow::bail!("Package {pkg} not found in any repository");
                }
            }

            for pkg in &packages {
                let version = state
                    .available
                    .get(pkg)
                    .or_else(|| pkgs.get(pkg).map(|p| &p.version))
                    .cloned()
                    .unwrap_or_else(|| "0".to_string());
                state.installed.insert(pkg.clone(), version);
            }
            drop(pkgs);
            self.save_state(&state)?;
            Ok(())
        })
    }

    fn remove(&self, packages: &[String]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let packages = packages.to_vec();
        Box::pin(async move {
            let mut state = self.load_state()?;
            for pkg in &packages {
                state.installed.remove(pkg);
            }
            self.save_state(&state)?;
            Ok(())
        })
    }

    fn update(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move { Ok(()) })
    }

    fn sync(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move { Ok(()) })
    }

    fn info(
        &self,
        package: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Package>>> + Send + '_>> {
        let package = package.to_string();
        Box::pin(async move {
            let db = self.db.clone();
            let state = self.load_state()?;
            let pkgs = db
                .packages
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Ok(pkgs.get(&package).map_or_else(
                || {
                    state.available.get(&package).map(|version| Package {
                        name: package.clone(),
                        version: parse_version_or_zero(version),
                        description: String::new(),
                        source: PackageSource::Official,
                        installed: state.installed.contains_key(&package),
                    })
                },
                |p| {
                    Some(Package {
                        name: p.name.clone(),
                        version: parse_version_or_zero(&p.version),
                        description: p.description.clone(),
                        source: PackageSource::Official,
                        installed: state.installed.contains_key(&p.name),
                    })
                },
            ))
        })
    }

    fn list_installed(&self) -> Pin<Box<dyn Future<Output = Result<Vec<Package>>> + Send + '_>> {
        Box::pin(async move {
            let db = self.db.clone();
            let state = self.load_state()?;
            let pkgs = db
                .packages
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Ok(state
                .installed
                .iter()
                .map(|(name, version)| {
                    if let Some(p) = pkgs.get(name) {
                        Package {
                            name: p.name.clone(),
                            version: parse_version_or_zero(version),
                            description: p.description.clone(),
                            source: PackageSource::Official,
                            installed: true,
                        }
                    } else {
                        // Package installed but not in db (e.g. manually added to mock state)
                        Package {
                            name: name.clone(),
                            version: parse_version_or_zero(version),
                            description: "Mock package".to_string(),
                            source: PackageSource::Official,
                            installed: true,
                        }
                    }
                })
                .collect())
        })
    }

    fn get_status(
        &self,
        _fast: bool,
    ) -> Pin<Box<dyn Future<Output = Result<(usize, usize, usize, usize)>> + Send + '_>> {
        Box::pin(async move {
            let state = self.load_state()?;
            // total = all installed packages
            // explicit = explicitly installed packages (in mock, all are explicit since no dependency tracking)
            let total = state.installed.len();
            let explicit = total; // All installed packages are explicit in the mock
            let updates = self.list_updates().await?.len();
            Ok((total, explicit, 0, updates))
        })
    }

    fn list_explicit(&self) -> Pin<Box<dyn Future<Output = Result<Vec<String>>> + Send + '_>> {
        Box::pin(async move {
            let state = self.load_state()?;
            Ok(state.installed.keys().cloned().collect())
        })
    }

    fn list_updates(&self) -> Pin<Box<dyn Future<Output = Result<Vec<UpdateInfo>>> + Send + '_>> {
        Box::pin(async move {
            let db = self.db.clone();
            let state = self.load_state()?;
            let pkgs = db
                .packages
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut updates = Vec::new();

            for (pkg_name, installed_ver) in &state.installed {
                if let Some(available_ver) = state.available.get(pkg_name) {
                    // Use repo from db if available, else "unknown"
                    let repo = pkgs
                        .get(pkg_name)
                        .map_or_else(|| "unknown".to_string(), |p| p.repo.clone());

                    let is_update_needed =
                        parse_version_or_zero(available_ver) > parse_version_or_zero(installed_ver);

                    if is_update_needed {
                        updates.push(UpdateInfo {
                            name: pkg_name.clone(),
                            old_version: installed_ver.clone(),
                            new_version: available_ver.clone(),
                            repo,
                        });
                    }
                }
            }

            Ok(updates)
        })
    }

    fn is_installed(
        &self,
        package: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + '_>> {
        let package = package.to_string();
        Box::pin(async move {
            let state = self.load_state()?;
            Ok(state.installed.contains_key(&package))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn backend_names_match_persistent_state_contract() {
        for (distro, backend) in [
            ("arch", "pacman"),
            ("debian", "apt"),
            ("ubuntu", "apt"),
            ("fedora", "dnf"),
            ("rhel", "dnf"),
            ("macos", "homebrew"),
            ("darwin", "homebrew"),
            ("unknown", "mock"),
        ] {
            assert_eq!(backend_name_for_distro(distro), backend);
            assert_eq!(MockPackageManager::new(distro).distro_name, backend);
        }
    }

    #[test]
    fn test_mock_persistence() -> Result<()> {
        let dir = tempdir()?;
        let pm1 = MockPackageManager::new_in("arch", dir.path());
        pm1.db
            .add_package("test-pkg", "1.0.0", "Test package", "extra");
        futures::executor::block_on(pm1.install(&["test-pkg".to_string()]))?;

        let pm2 = MockPackageManager::new_in("arch", dir.path());
        let installed = futures::executor::block_on(pm2.list_explicit())?;
        assert!(installed.iter().any(|package| package == "test-pkg"));
        Ok(())
    }

    #[test]
    fn mock_search_and_status_are_case_insensitive_and_consistent() -> Result<()> {
        let dir = tempdir()?;
        let package_manager = MockPackageManager::new_in("arch", dir.path());
        package_manager
            .db
            .add_package("UpperCase", "1.0.0", "Example package", "extra");
        package_manager.set_installed_version("UpperCase", "1.0.0")?;
        package_manager.set_available_version("UpperCase", "2.0.0")?;

        let search = futures::executor::block_on(package_manager.search("uppercase"))?;
        assert_eq!(search.len(), 1);
        let status = futures::executor::block_on(package_manager.get_status(false))?;
        assert_eq!(status.3, 1, "status must expose the pending mock update");
        Ok(())
    }

    #[test]
    fn available_only_packages_are_searchable_and_have_info() -> Result<()> {
        let dir = tempdir()?;
        let package_manager = MockPackageManager::new_in("arch", dir.path());
        package_manager.set_available_version("fixture-only", "2.4.0")?;

        let search = futures::executor::block_on(package_manager.search("fixture"))?;
        assert_eq!(search.len(), 1);
        assert_eq!(search[0].name, "fixture-only");
        assert_eq!(search[0].version.to_string(), "2.4.0");

        let info = futures::executor::block_on(package_manager.info("fixture-only"))?
            .expect("available-only package info");
        assert_eq!(info.version.to_string(), "2.4.0");
        assert!(!info.installed);
        Ok(())
    }

    #[test]
    fn mock_updates_compare_numeric_version_components() -> Result<()> {
        let dir = tempdir()?;
        let package_manager = MockPackageManager::new_in("debian", dir.path());
        package_manager
            .db
            .add_package("example", "0.10", "Example package", "main");
        package_manager.set_installed_version("example", "0.9")?;
        package_manager.set_available_version("example", "0.10")?;

        let updates = futures::executor::block_on(package_manager.list_updates())?;
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].old_version, "0.9");
        assert_eq!(updates[0].new_version, "0.10");
        Ok(())
    }

    #[test]
    fn malformed_mock_state_is_reported() -> Result<()> {
        let dir = tempdir()?;
        fs::write(dir.path().join("mock_state_pacman.json"), b"not json")?;
        let package_manager = MockPackageManager::new_in("arch", dir.path());

        let Err(error) = futures::executor::block_on(package_manager.search("git")) else {
            anyhow::bail!("malformed persisted state must not be discarded");
        };

        assert!(error.to_string().contains("failed to parse mock state"));
        Ok(())
    }
}
