use anyhow::Result;
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;

use crate::cli::style;
use crate::core::env::distro::detect_distro;
use crate::core::env::fingerprint::EnvironmentState;

const MANIFEST_FORMAT_VERSION: &str = "1.0";

#[derive(Debug, Serialize, Deserialize)]
pub struct MigrationManifest {
    pub version: String,
    pub source_distro: String,
    pub created_at: i64,
    pub runtimes: BTreeMap<String, String>,
    pub packages: Vec<PackageMapping>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PackageMapping {
    pub original_name: String,
    pub category: String,
    pub description: Option<String>,
    pub alternatives: Vec<String>,
}

pub async fn export(output: &str) -> Result<()> {
    println!("{} Exporting environment...\n", style::runtime("OMG"));

    let state = EnvironmentState::capture().await?;
    let distro = format!("{:?}", detect_distro()).to_lowercase();
    let runtime_count = state.runtimes.len();
    let package_count = state.packages.len();

    let packages = state
        .packages
        .iter()
        .map(|name| create_package_mapping(name))
        .collect();

    let manifest = MigrationManifest {
        version: MANIFEST_FORMAT_VERSION.to_string(),
        source_distro: distro,
        created_at: jiff::Timestamp::now().as_second(),
        runtimes: state.runtimes,
        packages,
    };

    let content = serde_json::to_string_pretty(&manifest)?;
    crate::core::safe_ops::atomic_write_file_sync(output, content)?;

    println!(
        "  {} Exported to {}",
        style::maybe_color("✓", |t| t.green().to_string()),
        style::maybe_color(output, |t| t.cyan().to_string())
    );
    println!();
    println!("  Source distro: {}", style::path(&manifest.source_distro));
    println!("  Runtimes: {runtime_count}");
    println!("  Packages: {package_count}");
    println!();
    println!(
        "  {}",
        style::maybe_color("To import on another machine:", |t| {
            t.bold().to_string()
        })
    );
    println!(
        "    1. Copy {} to the target machine",
        style::maybe_color(output, |t| t.cyan().to_string())
    );
    println!(
        "    2. Run {}",
        style::command(&format!("omg migrate import {output}"))
    );

    Ok(())
}

pub async fn import(manifest_path: &str, dry_run: bool) -> Result<()> {
    let manifest_path = crate::core::safe_ops::validate_path_syntax(manifest_path)?;

    println!(
        "{} {} manifest...\n",
        style::runtime("OMG"),
        if dry_run { "Previewing" } else { "Importing" }
    );

    let content = fs::read_to_string(&manifest_path)?;
    let manifest: MigrationManifest = serde_json::from_str(&content)?;

    validate_manifest_version(&manifest)?;

    let target_distro = format!("{:?}", detect_distro()).to_lowercase();

    println!(
        "  Source: {} → Target: {}",
        style::path(&manifest.source_distro),
        style::maybe_color(&target_distro, |t| t.cyan().to_string())
    );
    println!();

    println!(
        "  {}",
        style::maybe_color("Package mapping:", |t| t.bold().to_string())
    );

    let import_plan = ImportPlan {
        runtimes: &manifest.runtimes,
        packages: plan_package_migration(
            &manifest.packages,
            &manifest.source_distro,
            &target_distro,
        ),
    };

    for (original, target) in &import_plan.packages.mapped {
        println!(
            "    {} {} → {}",
            style::maybe_color("✓", |t| t.green().to_string()),
            style::dim(&style::sanitize_terminal_text(original)),
            style::maybe_color(&style::sanitize_terminal_text(target), |t| t
                .cyan()
                .to_string())
        );
    }
    if !import_plan.packages.unmapped.is_empty() {
        println!("    Unmapped (kept original names):");
        for package in &import_plan.packages.unmapped {
            println!("      - {}", style::sanitize_terminal_text(package));
        }
    }

    println!();
    println!(
        "  Mapped: {}/{} packages ({} unmapped)",
        style::version(&import_plan.packages.mapped.len().to_string()),
        manifest.packages.len(),
        import_plan.packages.unmapped.len()
    );

    println!();
    println!(
        "  {}",
        style::maybe_color("Runtimes:", |t| t.bold().to_string())
    );
    for (runtime, version) in import_plan.runtimes {
        println!(
            "    {} {} @ {}",
            style::maybe_color("→", |t| t.blue().to_string()),
            runtime,
            style::maybe_color(version, |t| t.cyan().to_string())
        );
    }

    println!();
    println!(
        "  Mutation summary: {} package installation(s), {} runtime installation(s)",
        import_plan.packages.to_install.len(),
        import_plan.runtimes.len()
    );

    if dry_run {
        println!();
        println!(
            "  {} No changes made (dry run)",
            style::maybe_color("ℹ", |t| t.blue().to_string())
        );
        println!(
            "  Run without --dry-run to install: {}",
            style::command(&format!("omg migrate import {}", manifest_path.display()))
        );
        return Ok(());
    }

    if import_plan.has_mutations() && !confirm_import(&import_plan).await? {
        println!();
        println!(
            "  {} Migration import cancelled; no changes made",
            style::maybe_color("ℹ", |t| t.blue().to_string())
        );
        return Ok(());
    }

    println!();
    println!(
        "  {}",
        style::maybe_color("Applying...", |t| t.bold().to_string())
    );

    let mut runtime_failures = 0usize;
    for (runtime, version) in import_plan.runtimes {
        println!(
            "    Installing {} {}...",
            style::sanitize_terminal_text(runtime),
            style::sanitize_terminal_text(version)
        );
        if let Err(e) = install_import_runtime(runtime, version).await {
            println!(
                "      {} Failed to install {runtime}: {e}",
                style::maybe_color("✗", |t| t.red().to_string())
            );
            runtime_failures += 1;
        }
    }

    let mut package_failed = false;
    if !import_plan.packages.to_install.is_empty() {
        println!();
        println!(
            "    Installing {} packages...",
            import_plan.packages.to_install.len()
        );
        if let Err(e) = install_import_packages(&import_plan.packages.to_install).await {
            println!(
                "      {} Package installation failed: {e}",
                style::maybe_color("✗", |t| t.red().to_string())
            );
            package_failed = true;
        }
    }

    finish_apply(runtime_failures, package_failed)
}

fn finish_apply(runtime_failures: usize, package_failed: bool) -> Result<()> {
    if runtime_failures == 0 && !package_failed {
        println!();
        println!(
            "  {} Migration complete!",
            style::maybe_color("✓", |t| t.green().to_string())
        );
        Ok(())
    } else {
        anyhow::bail!(
            "Migration failed ({runtime_failures} runtime install failure(s), package install {})",
            if package_failed { "failed" } else { "ok" }
        )
    }
}

fn validate_manifest_version(manifest: &MigrationManifest) -> Result<()> {
    anyhow::ensure!(
        manifest.version == MANIFEST_FORMAT_VERSION,
        "Unsupported migration manifest version '{}' (this build reads '{}'); \
         regenerate the manifest with a matching omg version",
        manifest.version,
        MANIFEST_FORMAT_VERSION
    );
    Ok(())
}

struct ImportPlan<'a> {
    runtimes: &'a BTreeMap<String, String>,
    packages: PackageMigrationPlan,
}

impl ImportPlan<'_> {
    fn has_mutations(&self) -> bool {
        !self.runtimes.is_empty() || !self.packages.to_install.is_empty()
    }
}

struct PackageMigrationPlan {
    to_install: Vec<String>,
    mapped: Vec<(String, String)>,
    unmapped: Vec<String>,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
enum ImportEvent {
    Consent,
    Runtime {
        name: String,
        version: String,
    },
    Packages {
        names: Vec<String>,
        assume_yes: bool,
    },
}

#[cfg(test)]
#[derive(Clone)]
struct ImportTestState {
    inner: std::rc::Rc<std::cell::RefCell<ImportTestStateInner>>,
}

#[cfg(test)]
struct ImportTestStateInner {
    attended: bool,
    confirmed: bool,
    events: Vec<ImportEvent>,
}

#[cfg(test)]
impl ImportTestState {
    fn new(attended: bool, confirmed: bool) -> Self {
        Self {
            inner: std::rc::Rc::new(std::cell::RefCell::new(ImportTestStateInner {
                attended,
                confirmed,
                events: Vec::new(),
            })),
        }
    }

    fn events(&self) -> Vec<ImportEvent> {
        self.inner.borrow().events.clone()
    }

    fn confirm(&self) -> Result<bool> {
        let mut inner = self.inner.borrow_mut();
        validate_import_consent(inner.attended)?;
        inner.events.push(ImportEvent::Consent);
        Ok(inner.confirmed)
    }

    fn record(&self, event: ImportEvent) {
        self.inner.borrow_mut().events.push(event);
    }
}

#[cfg(test)]
thread_local! {
    static IMPORT_TEST_STATE: std::cell::RefCell<Option<ImportTestState>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
struct ImportTestStateGuard(Option<ImportTestState>);

#[cfg(test)]
impl Drop for ImportTestStateGuard {
    fn drop(&mut self) {
        IMPORT_TEST_STATE.with(|slot| {
            slot.replace(self.0.take());
        });
    }
}

#[cfg(test)]
fn install_import_test_state(state: ImportTestState) -> ImportTestStateGuard {
    let previous = IMPORT_TEST_STATE.with(|slot| slot.replace(Some(state)));
    ImportTestStateGuard(previous)
}

#[cfg(test)]
fn import_test_state() -> Option<ImportTestState> {
    IMPORT_TEST_STATE.with(|slot| slot.borrow().clone())
}

fn validate_import_consent(attended: bool) -> Result<()> {
    anyhow::ensure!(
        attended,
        "Migration import requires an interactive terminal confirmation before making changes. \
         Review the plan with --dry-run, then run the import from an interactive terminal."
    );
    Ok(())
}

async fn confirm_import(plan: &ImportPlan<'_>) -> Result<bool> {
    #[cfg(test)]
    if let Some(state) = import_test_state() {
        return state.confirm();
    }

    validate_import_consent(console::user_attended())?;

    let package_count = plan.packages.to_install.len();
    let runtime_count = plan.runtimes.len();
    tokio::task::spawn_blocking(move || {
        dialoguer::Confirm::with_theme(&crate::cli::ui::prompt_theme())
            .with_prompt(format!(
                "Apply this migration plan ({package_count} package installation(s), \
                 {runtime_count} runtime installation(s))?"
            ))
            .default(false)
            .interact()
    })
    .await
    .map_err(|error| anyhow::anyhow!("Migration confirmation prompt task failed: {error}"))?
    .map_err(Into::into)
}

async fn install_import_runtime(runtime: &str, version: &str) -> Result<()> {
    #[cfg(test)]
    if let Some(state) = import_test_state() {
        state.record(ImportEvent::Runtime {
            name: runtime.to_owned(),
            version: version.to_owned(),
        });
        return Ok(());
    }

    crate::cli::runtimes::restore_version(runtime, version).await
}

async fn install_import_packages(packages: &[String]) -> Result<()> {
    #[cfg(test)]
    if let Some(state) = import_test_state() {
        state.record(ImportEvent::Packages {
            names: packages.to_vec(),
            assume_yes: true,
        });
        return Ok(());
    }

    crate::cli::packages::install(packages, true, false, false).await
}

fn plan_package_migration(
    packages: &[PackageMapping],
    source_distro: &str,
    target_distro: &str,
) -> PackageMigrationPlan {
    let mut plan = PackageMigrationPlan {
        to_install: Vec::with_capacity(packages.len()),
        mapped: Vec::new(),
        unmapped: Vec::new(),
    };
    for package in packages {
        let target = map_package(&package.original_name, source_distro, target_distro);
        if target == package.original_name {
            plan.unmapped.push(package.original_name.clone());
        } else {
            plan.mapped
                .push((package.original_name.clone(), target.clone()));
        }
        plan.to_install.push(target);
    }
    plan
}

fn create_package_mapping(name: &str) -> PackageMapping {
    PackageMapping {
        original_name: name.to_string(),
        category: categorize_package(name).to_string(),
        description: None,
        alternatives: get_alternatives(name),
    }
}

fn categorize_package(name: &str) -> &'static str {
    if name.contains("lib") {
        "library"
    } else if name.contains("dev") || name.contains("devel") {
        "development"
    } else if name.ends_with("-doc") || name.ends_with("-docs") {
        "documentation"
    } else {
        "application"
    }
}

fn get_alternatives(name: &str) -> Vec<String> {
    let alternatives: &[&str] = match name {
        "vim" => &["vim", "vim-nox", "neovim"],
        "gcc" | "make" => &[name, "build-essential"],
        "git" | "curl" | "wget" => &[name],
        "python" => &["python3", "python"],
        "nodejs" => &["nodejs", "node"],
        _ => &[],
    };
    alternatives.iter().map(ToString::to_string).collect()
}

fn map_package(name: &str, from: &str, to: &str) -> String {
    match (from, to) {
        ("arch", "debian" | "ubuntu") => match name {
            "base-devel" => "build-essential",
            "python" => "python3",
            "python-pip" => "python3-pip",
            "linux-headers" => "linux-headers-generic",
            "lib32-glibc" => "libc6-i386",
            other => other,
        },
        ("debian" | "ubuntu", "arch") => match name {
            "build-essential" => "base-devel",
            "python3" => "python",
            "python3-pip" => "python-pip",
            "linux-headers-generic" => "linux-headers",
            other => other,
        },
        _ => name,
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_categorize_package() {
        assert_eq!(categorize_package("libc6"), "library");
        assert_eq!(categorize_package("libssl-dev"), "library");
        assert_eq!(categorize_package("python3-dev"), "development");
        assert_eq!(categorize_package("gcc-docs"), "documentation");
        assert_eq!(categorize_package("firefox"), "application");
    }

    #[test]
    fn test_get_alternatives() {
        let alts = get_alternatives("vim");
        assert!(alts.contains(&"neovim".to_string()));
        assert!(alts.contains(&"vim".to_string()));

        let empty = get_alternatives("nonexistent-pkg-123");
        assert!(empty.is_empty());
    }

    #[test]
    fn apply_failure_is_an_error() {
        let result = finish_apply(1, false);
        assert!(
            result.is_err(),
            "failed runtime installs must be a CLI error so the process exits non-zero"
        );
        let package_result = finish_apply(0, true);
        assert!(
            package_result.is_err(),
            "failed package installs must be a CLI error so the process exits non-zero"
        );
    }

    #[test]
    fn apply_success_is_ok() {
        assert!(finish_apply(0, false).is_ok());
    }

    #[test]
    fn migration_plan_distinguishes_mapped_and_unmapped_packages() {
        let packages = vec![
            create_package_mapping("base-devel"),
            create_package_mapping("custom-tool"),
        ];

        let plan = plan_package_migration(&packages, "arch", "debian");

        assert_eq!(plan.to_install, vec!["build-essential", "custom-tool"]);
        assert_eq!(plan.mapped.len(), 1);
        assert_eq!(plan.unmapped, vec!["custom-tool"]);
    }

    #[test]
    fn test_map_package() {
        assert_eq!(
            map_package("base-devel", "arch", "debian"),
            "build-essential"
        );
        assert_eq!(map_package("python", "arch", "ubuntu"), "python3");

        assert_eq!(
            map_package("build-essential", "debian", "arch"),
            "base-devel"
        );
        assert_eq!(map_package("python3", "ubuntu", "arch"), "python");

        assert_eq!(
            map_package("my-custom-pkg", "arch", "debian"),
            "my-custom-pkg"
        );
    }

    fn import_fixture() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("migration.json");
        std::fs::write(
            &path,
            r#"{
                "version":"1.0",
                "source_distro":"test",
                "created_at":0,
                "runtimes":{"node":"22"},
                "packages":[{
                    "original_name":"example-package",
                    "category":"application",
                    "description":null,
                    "alternatives":[]
                }]
            }"#,
        )
        .expect("write manifest");
        (dir, path)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dry_run_returns_before_consent_or_mutation() {
        let (_dir, path) = import_fixture();
        let state = ImportTestState::new(false, false);
        let _guard = install_import_test_state(state.clone());

        import(path.to_str().expect("UTF-8 path"), true)
            .await
            .expect("dry run");

        assert!(state.events().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_import_performs_no_mutations() {
        let (_dir, path) = import_fixture();
        let state = ImportTestState::new(true, false);
        let _guard = install_import_test_state(state.clone());

        import(path.to_str().expect("UTF-8 path"), false)
            .await
            .expect("cancelled import");

        assert_eq!(state.events(), vec![ImportEvent::Consent]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unattended_import_fails_before_consent_or_mutation() {
        let (_dir, path) = import_fixture();
        let state = ImportTestState::new(false, true);
        let _guard = install_import_test_state(state.clone());

        let error = import(path.to_str().expect("UTF-8 path"), false)
            .await
            .expect_err("unattended import must fail");

        assert!(error.to_string().contains("interactive terminal"));
        assert!(state.events().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn accepted_import_consents_once_before_mutation() {
        let (_dir, path) = import_fixture();
        let state = ImportTestState::new(true, true);
        let _guard = install_import_test_state(state.clone());

        import(path.to_str().expect("UTF-8 path"), false)
            .await
            .expect("accepted import");

        assert_eq!(
            state.events(),
            vec![
                ImportEvent::Consent,
                ImportEvent::Runtime {
                    name: "node".to_string(),
                    version: "22".to_string(),
                },
                ImportEvent::Packages {
                    names: vec!["example-package".to_string()],
                    assume_yes: true,
                },
            ]
        );
    }

    #[test]
    fn import_rejects_unknown_manifest_versions() {
        let manifest = |version: &str| {
            format!(
                r#"{{"version":"{version}","source_distro":"arch","created_at":0,
                    "runtimes":{{}},"packages":[]}}"#
            )
        };
        let dir = tempfile::tempdir().expect("temp dir");

        let write_and_parse = |version: &str| {
            let path = dir.path().join(format!("manifest-{version}.json"));
            std::fs::write(&path, manifest(version)).expect("write manifest");
            let content = std::fs::read_to_string(&path).expect("read manifest");
            serde_json::from_str::<MigrationManifest>(&content).expect("fixture must deserialize")
        };

        let supported = write_and_parse("1.0");
        assert_eq!(supported.version, MANIFEST_FORMAT_VERSION);

        let future = write_and_parse("2.0");
        let error = validate_manifest_version(&future)
            .expect_err("forward versions must be rejected, not silently imported");
        assert!(
            error
                .to_string()
                .contains("Unsupported migration manifest version")
        );
    }
}
