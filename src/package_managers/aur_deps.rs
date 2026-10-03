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
    let (all_deps, package_outputs) = dependency_plan(&srcinfo, requested_outputs)?;
    // Ask libalpm to evaluate the complete dependency expression. A package
    // with the right name but an older version is not a satisfier, while a
    // compatible virtual provider can be.
    let missing = crate::package_managers::alpm_direct::with_handle(|alpm| {
        let installed = alpm.localdb().pkgs();
        Ok(all_deps
            .into_iter()
            .filter(|dependency| installed.find_satisfier(dependency.clone()).is_none())
            .collect::<Vec<_>>())
    })?;

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
            if all_outputs.contains(name) && selected_outputs.insert(name.to_string()) {
                pending_outputs.push(name.to_string());
            }
        }
    }

    let mut dependencies = Vec::new();
    for output in &selected_outputs {
        let package = &packages[output];
        dependencies.extend(package.dependencies.iter().map(ToString::to_string));
        dependencies.extend(package.make_dependencies.iter().map(ToString::to_string));
        dependencies.extend(package.check_dependencies.iter().map(ToString::to_string));
    }
    dependencies.retain(|dependency| !all_outputs.contains(dependency_name(dependency)));
    dependencies.sort();
    dependencies.dedup();

    Ok((dependencies, selected_outputs.into_iter().collect()))
}

#[cfg(test)]
mod tests {
    use super::{SourceInfoV1, dependency_plan};

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
