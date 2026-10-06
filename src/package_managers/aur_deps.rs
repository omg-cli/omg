//! Smart dependency resolution for AUR packages
//!
//! Parses .SRCINFO and checks which dependencies are already installed
//! to avoid redundant pacman operations.

use alpm_srcinfo::SourceInfoV1;
use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Parsed dependency information from .SRCINFO
#[derive(Debug, Clone)]
pub struct DependencyInfo {
    /// External dependencies that need to be installed.
    pub missing: Vec<String>,
    /// Requested outputs plus same-base runtime dependencies.
    pub package_outputs: Vec<String>,
}

pub(crate) fn dependency_name(dependency: &str) -> &str {
    dependency
        .find(['>', '<', '='])
        .map_or(dependency, |index| &dependency[..index])
}

/// Parse .SRCINFO and check dependencies for the requested output closure.
pub fn check_dependencies_for_outputs(
    pkg_dir: &Path,
    requested_outputs: &[String],
) -> Result<DependencyInfo> {
    let srcinfo_path = pkg_dir.join(".SRCINFO");

    if !srcinfo_path.exists() {
        return Ok(DependencyInfo {
            missing: Vec::new(),
            package_outputs: requested_outputs.to_vec(),
        });
    }

    let content = std::fs::read_to_string(&srcinfo_path).context("Failed to read .SRCINFO")?;
    let srcinfo = SourceInfoV1::from_string(&content).context("Failed to parse .SRCINFO")?;
    // Ask libalpm to evaluate the complete dependency expression. A package
    // with the right name but an older version is not a satisfier, while a
    // compatible virtual provider can be.
    crate::package_managers::alpm_direct::with_handle(|alpm| {
        let installed = alpm.localdb().pkgs();
        dependency_info(&srcinfo, requested_outputs, |dependency| {
            installed.find_satisfier(dependency.to_string()).is_some()
        })
    })
}

fn dependency_info(
    srcinfo: &SourceInfoV1,
    requested_outputs: &[String],
    is_installed: impl Fn(&str) -> bool,
) -> Result<DependencyInfo> {
    let (all_deps, package_outputs) = dependency_plan(srcinfo, requested_outputs)?;
    let missing = all_deps
        .into_iter()
        .filter(|dependency| !is_installed(dependency))
        .collect::<Vec<_>>();
    let same_base_names = srcinfo
        .packages
        .iter()
        .map(|package| package.name.to_string())
        .collect::<BTreeSet<_>>();
    let missing_build_inputs = missing
        .iter()
        .filter(|dependency| same_base_names.contains(dependency_name(dependency)))
        .collect::<Vec<_>>();
    anyhow::ensure!(
        missing_build_inputs.is_empty(),
        "Same-base build/check dependencies must be installed before building: {}. Building these outputs afterward cannot satisfy this build; install a compatible existing package or correct the recipe's build dependencies",
        missing_build_inputs
            .into_iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    );

    Ok(DependencyInfo {
        missing,
        package_outputs,
    })
}

fn dependency_plan(
    srcinfo: &SourceInfoV1,
    requested_outputs: &[String],
) -> Result<(Vec<String>, Vec<String>)> {
    let arch = super::aur::utils::current_arch()
        .context("Unsupported host architecture for AUR dependency resolution")?;
    let packages = srcinfo
        .packages_for_architecture(arch)
        .map(|package| (package.name.to_string(), package))
        .collect::<BTreeMap<_, _>>();
    let all_outputs = packages.keys().cloned().collect::<BTreeSet<_>>();
    let mut selected_outputs = if requested_outputs.is_empty() {
        all_outputs.clone()
    } else {
        requested_outputs.iter().cloned().collect::<BTreeSet<_>>()
    };

    for output in &selected_outputs {
        anyhow::ensure!(
            all_outputs.contains(output),
            "Requested output '{output}' is absent from .SRCINFO"
        );
    }

    let mut pending_outputs = selected_outputs.iter().cloned().collect::<Vec<_>>();
    while let Some(output) = pending_outputs.pop() {
        let package = &packages[&output];
        for dependency in &package.dependencies {
            let dependency = dependency.to_string();
            let name = dependency_name(&dependency);
            if let Some(sibling) = packages.get(name) {
                let version = sibling.version.to_string();
                anyhow::ensure!(
                    output_version_satisfies(&dependency, &version),
                    "Same-base runtime dependency '{dependency}' cannot be satisfied by output '{name}' at version {version}; correct the recipe's dependency or output version"
                );
                if selected_outputs.insert(name.to_string()) {
                    pending_outputs.push(name.to_string());
                }
            } else {
                anyhow::ensure!(
                    !srcinfo
                        .packages
                        .iter()
                        .any(|sibling| sibling.name.to_string() == name),
                    "Same-base runtime output '{name}' required by '{output}' is unavailable for the host architecture"
                );
            }
        }
    }

    let mut dependencies = Vec::new();
    for output in &selected_outputs {
        let package = &packages[output];
        dependencies.extend(
            package
                .dependencies
                .iter()
                .map(ToString::to_string)
                .filter(|dependency| !all_outputs.contains(dependency_name(dependency))),
        );
        // These inputs are needed before packaging. Keep complete expressions
        // even when a later output from this pkgbase has the same name.
        dependencies.extend(package.make_dependencies.iter().map(ToString::to_string));
        dependencies.extend(package.check_dependencies.iter().map(ToString::to_string));
    }
    dependencies.sort();
    dependencies.dedup();

    Ok((dependencies, selected_outputs.into_iter().collect()))
}

fn output_version_satisfies(dependency: &str, candidate: &str) -> bool {
    let dependency = alpm::Depend::new(dependency);
    let Some(required) = dependency.version() else {
        return true;
    };
    let comparison = alpm::vercmp(candidate, required.to_string().as_str());
    match dependency.depmod() {
        alpm::DepMod::Any => true,
        alpm::DepMod::Eq => comparison.is_eq(),
        alpm::DepMod::Ge => !comparison.is_lt(),
        alpm::DepMod::Le => !comparison.is_gt(),
        alpm::DepMod::Gt => comparison.is_gt(),
        alpm::DepMod::Lt => comparison.is_lt(),
    }
}

#[cfg(test)]
mod tests {
    use super::{SourceInfoV1, dependency_info, dependency_plan, output_version_satisfies};

    fn split_fixture(base_dependencies: &str, packages: &str) -> SourceInfoV1 {
        SourceInfoV1::from_string(&format!(
            "pkgbase = example\n\tpkgdesc = dependency plan fixture\n\tpkgver = 1.0.0\n\tpkgrel = 1\n\tarch = any\n{base_dependencies}\n{packages}"
        ))
        .expect("valid split .SRCINFO")
    }

    fn installed_fixture(packages: &[(&str, &str)]) -> (tempfile::TempDir, alpm::Alpm) {
        let directory = tempfile::tempdir().expect("temporary database");
        let root = directory.path().join("root");
        let db = directory.path().join("db");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(db.join("local")).expect("local db");
        std::fs::create_dir_all(db.join("sync")).expect("sync db");
        std::fs::write(db.join("local/ALPM_DB_VERSION"), "9\n").expect("database version");
        for (name, version) in packages {
            let entry = db.join("local").join(format!("{name}-{version}"));
            std::fs::create_dir_all(&entry).expect("package entry");
            std::fs::write(entry.join("desc"), format!("%NAME%\n{name}\n\n%VERSION%\n{version}\n\n%DESC%\nIsolated planning fixture\n\n%ARCH%\nx86_64\n\n")).expect("description");
        }
        let alpm = alpm::Alpm::new(
            root.to_str().expect("root path"),
            db.to_str().expect("db path"),
        )
        .expect("isolated libalpm handle");
        (directory, alpm)
    }

    #[test]
    fn same_base_build_requirements_use_actual_installed_version_satisfaction() {
        for kind in ["makedepends", "checkdepends"] {
            let srcinfo = split_fixture(
                &format!("\t{kind} = example-helper>=1.0.0\n\tdepends = external>=3\n"),
                "pkgname = example-cli\npkgname = example-helper\n",
            );
            for version in [None, Some("0.9-1"), Some("1.0.0-1")] {
                let packages = version
                    .map(|version| vec![("example-helper", version)])
                    .unwrap_or_default();
                let (_directory, alpm) = installed_fixture(&packages);
                let installed = alpm.localdb().pkgs();
                let result =
                    dependency_info(&srcinfo, &["example-cli".to_string()], |dependency| {
                        installed.find_satisfier(dependency.to_string()).is_some()
                    });
                if version == Some("1.0.0-1") {
                    let plan = result.expect("installed matching prerequisite");
                    assert_eq!(plan.missing, ["external>=3"]);
                    assert_eq!(plan.package_outputs, ["example-cli"]);
                } else {
                    let message = format!(
                        "{:#}",
                        result.expect_err("missing or stale sibling must not vanish")
                    );
                    assert!(message.contains("example-helper>=1.0.0"));
                    assert!(message.contains("installed before building"));
                }
            }
        }
    }

    #[test]
    fn self_build_cycle_is_refused_without_an_installed_bootstrap() {
        let srcinfo = split_fixture(
            "\tmakedepends = example-cli>=1.0\n",
            "pkgname = example-cli\n",
        );
        let (_directory, alpm) = installed_fixture(&[]);
        let error = dependency_info(&srcinfo, &["example-cli".to_string()], |dependency| {
            alpm.localdb()
                .pkgs()
                .find_satisfier(dependency.to_string())
                .is_some()
        })
        .expect_err("cannot build a missing tool using that same missing tool");
        assert!(format!("{error:#}").contains("example-cli>=1.0"));
    }

    #[test]
    fn same_base_build_requirement_accepts_an_installed_virtual_provider() {
        let srcinfo = split_fixture(
            "\tmakedepends = example-helper>=1.0\n",
            "pkgname = example-cli\npkgname = example-helper\n",
        );
        let (directory, alpm) = installed_fixture(&[("bootstrap-tool", "7.0-1")]);
        let desc = directory.path().join("db/local/bootstrap-tool-7.0-1/desc");
        let mut content = std::fs::read_to_string(&desc).expect("fixture description");
        content.push_str("%PROVIDES%\nexample-helper=1.0\n\n");
        std::fs::write(desc, content).expect("fixture provision");
        let installed = alpm.localdb().pkgs();
        let plan = dependency_info(&srcinfo, &["example-cli".to_string()], |dependency| {
            installed.find_satisfier(dependency.to_string()).is_some()
        })
        .expect("installed compatible provider");
        assert!(plan.missing.is_empty());
        assert_eq!(plan.package_outputs, ["example-cli"]);
    }

    #[test]
    fn runtime_sibling_unavailable_on_host_architecture_is_refused() {
        let other_arch = if super::super::aur::utils::current_arch()
            .expect("host arch")
            .to_string()
            == "aarch64"
        {
            "x86_64"
        } else {
            "aarch64"
        };
        let srcinfo = split_fixture(
            "",
            &format!(
                "pkgname = example-cli\n\tdepends = example-lib\npkgname = example-lib\n\tarch = {other_arch}\n"
            ),
        );
        let error = dependency_plan(&srcinfo, &["example-cli".to_string()])
            .expect_err("cannot select a sibling for another architecture");
        assert!(format!("{error:#}").contains("unavailable for the host architecture"));
    }

    #[test]
    fn conflicting_build_and_check_versions_report_both_requirements() {
        let srcinfo = split_fixture(
            "\tmakedepends = example-helper>=2\n\tcheckdepends = example-helper<1\n",
            "pkgname = example-cli\npkgname = example-helper\n",
        );
        let (_directory, alpm) = installed_fixture(&[("example-helper", "1.5-1")]);
        let error = dependency_info(&srcinfo, &["example-cli".to_string()], |dependency| {
            alpm.localdb()
                .pkgs()
                .find_satisfier(dependency.to_string())
                .is_some()
        })
        .expect_err("contradictory installed requirements");
        let message = format!("{error:#}");
        assert!(message.contains("example-helper>=2"));
        assert!(message.contains("example-helper<1"));
    }

    #[test]
    fn runtime_version_comparison_respects_epoch_pkgrel_and_all_operators() {
        for (requirement, candidate, expected) in [
            ("example-lib", "1.0-1", true),
            ("example-lib=1.0", "1.0-2", true),
            ("example-lib=1.0-2", "1.0-1", false),
            ("example-lib>=2:1.0", "1:9.0-1", false),
            ("example-lib>=2:1.0", "2:1.0-1", true),
            ("example-lib>1.0", "1.0-1", false),
            ("example-lib<2.0", "1.0-1", true),
            ("example-lib<=1.0", "1.0-1", true),
        ] {
            assert_eq!(
                output_version_satisfies(requirement, candidate),
                expected,
                "{requirement} / {candidate}"
            );
        }
    }

    #[test]
    fn same_base_build_and_check_requirements_do_not_disappear() {
        for kind in ["makedepends", "checkdepends"] {
            let srcinfo = split_fixture(
                &format!("\t{kind} = example-helper>=1.0.0\n"),
                "pkgname = example-cli\npkgname = example-helper\n",
            );
            let (dependencies, outputs) =
                dependency_plan(&srcinfo, &["example-cli".to_string()]).expect("plan");
            assert_eq!(dependencies, ["example-helper>=1.0.0"], "{kind}");
            assert_eq!(outputs, ["example-cli"]);
        }
    }

    #[test]
    fn incompatible_same_base_runtime_version_is_refused() {
        for requirement in ["example-lib>=2.0", "example-lib<1.0", "example-lib=7"] {
            let srcinfo = split_fixture(
                "",
                &format!(
                    "pkgname = example-cli\n\tdepends = {requirement}\npkgname = example-lib\n"
                ),
            );
            let error = dependency_plan(&srcinfo, &["example-cli".to_string()])
                .expect_err("new same-base output cannot satisfy this version");
            assert!(format!("{error:#}").contains(requirement));
        }
    }

    #[test]
    fn transitive_same_base_runtime_closure_preserves_external_constraints() {
        let srcinfo = split_fixture(
            "",
            "pkgname = example-cli\n\tdepends = example-lib>=1.0\npkgname = example-lib\n\tdepends = example-core=1.0.0\npkgname = example-core\n\tdepends = external>=3\npkgname = example-docs\n\tdepends = docs-tool\n",
        );
        let (dependencies, outputs) =
            dependency_plan(&srcinfo, &["example-cli".to_string()]).expect("plan");
        assert_eq!(dependencies, ["external>=3"]);
        assert_eq!(outputs, ["example-cli", "example-core", "example-lib"]);
    }

    #[test]
    fn satisfiable_runtime_cycle_selects_each_output_once() {
        let srcinfo = split_fixture(
            "",
            "pkgname = example-cli\n\tdepends = example-lib=1.0.0\npkgname = example-lib\n\tdepends = example-cli>=1.0\n",
        );
        let (dependencies, outputs) =
            dependency_plan(&srcinfo, &["example-cli".to_string()]).expect("plan");
        assert!(dependencies.is_empty());
        assert_eq!(outputs, ["example-cli", "example-lib"]);
    }

    #[test]
    fn preserves_version_constraints_for_all_dependency_kinds() {
        let srcinfo = SourceInfoV1::from_string(
            "pkgbase = example\n\
             \tpkgdesc = dependency constraint fixture\n\
             \tpkgver = 1.0.0\n\
             \tpkgrel = 1\n\
             \tarch = any\n\
             \tdepends = runtime>=1.2\n\
             \tmakedepends = compiler=3.4\n\
             \tcheckdepends = test-runner<5\n\
             \n\
             pkgname = example\n",
        )
        .expect("valid .SRCINFO fixture");

        let (dependencies, outputs) =
            dependency_plan(&srcinfo, &["example".to_string()]).expect("dependency plan");
        assert_eq!(
            dependencies,
            ["compiler=3.4", "runtime>=1.2", "test-runner<5"]
        );
        assert_eq!(outputs, ["example"]);
    }

    #[test]
    fn includes_split_output_dependency_overrides_but_not_sibling_outputs() {
        let srcinfo = SourceInfoV1::from_string(
            "pkgbase = example\n\
             \tpkgdesc = split dependency fixture\n\
             \tpkgver = 1.0.0\n\
             \tpkgrel = 1\n\
             \tarch = any\n\
             \tdepends = base-runtime\n\
             \n\
             pkgname = example-cli\n\
             \tdepends = helper>=2\n\
             \tdepends = example-lib=1.0.0\n\
             pkgname = example-lib\n\
             \tdepends = example-core\n\
             \tdepends = lib-runtime\n\
             pkgname = example-core\n\
             pkgname = example-docs\n\
             \tdepends = docs-tool\n",
        )
        .expect("valid split .SRCINFO fixture");

        let (dependencies, outputs) =
            dependency_plan(&srcinfo, &["example-cli".to_string()]).expect("dependency plan");
        assert_eq!(dependencies, ["base-runtime", "helper>=2", "lib-runtime"]);
        assert_eq!(outputs, ["example-cli", "example-core", "example-lib"]);
    }
}
