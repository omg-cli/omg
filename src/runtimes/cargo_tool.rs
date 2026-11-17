//! Review the exact packaged crates.io graph before invoking a Rust build.

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::package_manager::{ManagedRuntime, ReviewedTool};
use super::tool_artifacts as artifacts;
use crate::core::security::vulnerability::VulnerabilitySource;
use crate::package_managers::types::{SecurityOrigin, SecurityPackage};

#[derive(Deserialize)]
struct Lock {
    package: Vec<LockedCrate>,
}
#[derive(Deserialize)]
struct LockedCrate {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
    #[serde(default)]
    dependencies: Vec<String>,
}

fn crate_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
}
fn selector(request: &str) -> Result<(&str, String)> {
    let (name, version) = request
        .rsplit_once('@')
        .map_or((request, None), |(name, version)| (name, Some(version)));
    ensure!(crate_name(name), "Expected a crates.io package name");
    let version = match version {
        Some(version) => {
            let parsed = semver::Version::parse(version)?;
            ensure!(
                parsed.to_string() == version,
                "Cargo version must be exact and canonical"
            );
            format!("={version}")
        }
        None => "*".into(),
    };
    Ok((name, version))
}
pub(crate) fn validate_request(request: &str) -> Result<()> {
    selector(request).map(|_| ())
}
fn public_source(source: &str) -> bool {
    matches!(
        source,
        "registry+https://github.com/rust-lang/crates.io-index" | "sparse+https://index.crates.io/"
    )
}

fn inventory(
    bytes: &[u8],
    root: &str,
    version: &str,
) -> Result<(
    Vec<SecurityPackage>,
    BTreeMap<(String, String), String>,
    Vec<String>,
)> {
    let lock: Lock = toml::from_str(std::str::from_utf8(bytes)?)?;
    ensure!(
        !lock.package.is_empty() && lock.package.len() <= 4096,
        "Cargo lock inventory exceeds its bound"
    );
    let mut packages = BTreeMap::new();
    let mut checksums = BTreeMap::new();
    let mut gaps = Vec::new();
    for item in lock.package {
        ensure!(crate_name(&item.name), "Invalid Cargo lock crate identity");
        let parsed = semver::Version::parse(&item.version)?;
        ensure!(
            parsed.to_string() == item.version,
            "Cargo lock version is not exact"
        );
        let selected = item.name == root && item.version == version && item.source.is_none();
        let known = selected || item.source.as_deref().is_some_and(public_source);
        if !known {
            gaps.push(format!(
                "Cargo dependency {} {} has no public crates.io source identity",
                item.name, item.version
            ));
        }
        if !selected && known {
            let checksum = item
                .checksum
                .context("Cargo registry dependency has no SHA-256 checksum")?;
            ensure!(
                checksum.len() == 64
                    && checksum
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
                "Invalid Cargo registry checksum"
            );
            checksums.insert((item.name.clone(), item.version.clone()), checksum);
        }
        let key = (item.name.clone(), item.version.clone());
        ensure!(
            packages
                .insert(
                    key,
                    SecurityPackage {
                        origin: if known {
                            SecurityOrigin::CargoRegistry
                        } else {
                            SecurityOrigin::Unknown
                        },
                        name: item.name,
                        version: item.version,
                        advisory_source: None,
                        architecture: None,
                        description: String::new(),
                        licenses: vec![]
                    }
                )
                .is_none(),
            "Cargo lock contains ambiguous duplicate coordinates"
        );
    }
    ensure!(
        packages.contains_key(&(root.into(), version.into())),
        "Cargo lock omits the selected crate"
    );
    Ok((packages.into_values().collect(), checksums, gaps))
}

fn command(
    runtime: &ManagedRuntime,
    staging: &Path,
    request: &str,
    work: &Path,
) -> Result<std::process::Command> {
    let mut command = crate::cli::tool::secured_manager_command(
        runtime.command_path("cargo")?,
        staging,
        "cargo",
        request,
    )?;
    command
        .current_dir(work.join("plan"))
        .env("CARGO_HOME", work.join("cargo-home"))
        .env("CARGO_TARGET_DIR", work.join("target"))
        .env("RUSTC", runtime.command_path("rustc")?)
        .env("RUSTC_WRAPPER", "")
        .env("RUSTC_WORKSPACE_WRAPPER", "")
        .env("RUSTUP_HOME", work.join("unused-rustup-home"))
        .env("CARGO_REGISTRIES_CRATES_IO_PROTOCOL", "sparse")
        .env(
            "CARGO_REGISTRIES_CRATES_IO_INDEX",
            "sparse+https://index.crates.io/",
        );
    Ok(command)
}

fn checked_cache_archive(
    cache: &Path,
    name: &str,
    version: &str,
    expected: &str,
) -> Result<PathBuf> {
    let base = cache.join("registry/cache");
    let mut found = None;
    for index in fs::read_dir(&base)? {
        let index = index?;
        ensure!(
            index.file_type()?.is_dir(),
            "Cargo registry cache is redirected"
        );
        let path = index.path().join(format!("{name}-{version}.crate"));
        if path.try_exists()? {
            ensure!(
                found.is_none(),
                "Cargo checksum cache contains ambiguous archives"
            );
            ensure!(
                artifacts::hash(&artifacts::read(&path, 128 * 1024 * 1024)?) == expected,
                "Cargo downloaded archive differs from its reviewed registry checksum"
            );
            found = Some(path);
        }
    }
    found.context("Cargo did not fetch a checksum-bound locked dependency")
}

fn extract_verified_archive(
    archive: &Path,
    checksum: &str,
    destination: &Path,
    prefix: &str,
    work: &Path,
) -> Result<()> {
    let bytes = artifacts::read(archive, 128 * 1024 * 1024)?;
    ensure!(
        artifacts::hash(&bytes) == checksum,
        "Cargo archive changed before source verification"
    );
    let private = tempfile::Builder::new()
        .prefix("crate-")
        .tempfile_in(work)?;
    fs::write(private.path(), bytes)?;
    super::common::extract_component_tar_gz(
        private.path(),
        destination,
        1024 * 1024 * 1024,
        &|path| {
            use std::path::Component;
            let components = path.components().collect::<Vec<_>>();
            ensure!(
                !components.is_empty()
                    && components
                        .iter()
                        .all(|part| matches!(part, Component::Normal(_))),
                "Cargo archive contains an unsafe path"
            );
            ensure!(
                components[0].as_os_str() == std::ffi::OsStr::new(prefix),
                "Cargo archive has a different crate root"
            );
            let relative = components[1..].iter().collect::<PathBuf>();
            Ok((!relative.as_os_str().is_empty()).then_some(relative))
        },
    )?;
    source_files(destination, false)?;
    Ok(())
}

fn source_files(root: &Path, cargo_markers: bool) -> Result<BTreeMap<PathBuf, String>> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = BTreeMap::new();
    let mut count = 0;
    while let Some(directory) = pending.pop() {
        for child in fs::read_dir(directory)? {
            let child = child?;
            count += 1;
            ensure!(
                count <= 200_000,
                "Cargo extracted source exceeds its entry bound"
            );
            let path = child.path();
            let relative = path.strip_prefix(root)?.to_owned();
            if cargo_markers
                && (relative == Path::new(".cargo-ok")
                    || relative == Path::new(".cargo-checksum.json"))
            {
                continue;
            }
            let kind = child.file_type()?;
            if kind.is_dir() {
                pending.push(path);
            } else {
                ensure!(
                    kind.is_file(),
                    "Cargo packaged source contains a link or special file"
                );
                files.insert(
                    relative,
                    artifacts::hash(&artifacts::read(&path, 128 * 1024 * 1024)?),
                );
            }
        }
    }
    Ok(files)
}

fn verify_extracted_archive(
    cache: &Path,
    archive: &Path,
    checksum: &str,
    name: &str,
    version: &str,
    work: &Path,
) -> Result<()> {
    let private = tempfile::Builder::new()
        .prefix("verified-crate-")
        .tempdir_in(work)?;
    let prefix = format!("{name}-{version}");
    extract_verified_archive(archive, checksum, private.path(), &prefix, work)?;
    let expected = source_files(private.path(), false)?;
    let mut found = false;
    for index in fs::read_dir(cache.join("registry/src"))? {
        let index = index?;
        ensure!(
            index.file_type()?.is_dir(),
            "Cargo source index is redirected"
        );
        let path = index.path().join(&prefix);
        if path.try_exists()? {
            ensure!(
                !found && fs::symlink_metadata(&path)?.is_dir(),
                "Cargo extracted source is ambiguous or redirected"
            );
            ensure!(
                source_files(&path, true)? == expected,
                "Cargo extracted dependency differs from its checksum-bound archive"
            );
            found = true;
        }
    }
    ensure!(found, "Cargo dependency has no verified extracted source");
    Ok(())
}

fn reject_config(source: &Path) -> Result<()> {
    let mut pending = vec![source.to_path_buf()];
    let mut count = 0;
    while let Some(directory) = pending.pop() {
        for item in fs::read_dir(directory)? {
            let item = item?;
            count += 1;
            ensure!(count <= 200_000, "Cargo source inventory exceeds its bound");
            let path = item.path();
            ensure!(
                !(item.file_name() == "config" || item.file_name() == "config.toml")
                    || path.parent().and_then(Path::file_name)
                        != Some(std::ffi::OsStr::new(".cargo")),
                "Publisher Cargo configuration can execute wrappers or redirect registry sources; frozen admission requires configuration-free source"
            );
            if item.file_type()?.is_dir() {
                pending.push(path);
            }
        }
    }
    Ok(())
}

pub(crate) fn install_reviewed(
    request: &str,
    staging: &Path,
    destination: &Path,
    tools: &Path,
    source: Arc<dyn VulnerabilitySource>,
    security: &super::security::RuntimeSecurity,
) -> Result<Box<dyn ReviewedTool>> {
    ensure!(
        !crate::cli::tool::host_environment_is_allowed("cargo", request),
        "Private Cargo configuration is UNKNOWN and cannot supply a public frozen graph"
    );
    let (name, requirement) = selector(request)?;
    let runtime = ManagedRuntime::open("rust", tools, security)?;
    let owner = tempfile::Builder::new()
        .prefix(".cargo-review-")
        .tempdir_in(staging)?;
    let work = owner.path();
    let plan = work.join("plan");
    fs::create_dir_all(plan.join("src"))?;
    fs::write(plan.join("src/lib.rs"), b"")?;
    fs::write(
        plan.join("Cargo.toml"),
        format!(
            "[package]\nname=\"omg-admission-plan\"\nversion=\"0.0.0\"\nedition=\"2021\"\n[dependencies]\n{name}=\"{requirement}\"\n"
        ),
    )?;
    runtime.verify()?;
    let mut metadata = command(&runtime, staging, request, work)?;
    metadata
        .args(["metadata", "--format-version=1", "--manifest-path"])
        .arg(plan.join("Cargo.toml"));
    let _: serde_json::Value = serde_json::from_slice(&artifacts::run(
        metadata,
        "Cargo metadata resolution",
        false,
    )?)?;
    let seed_lock: Lock = toml::from_str(std::str::from_utf8(&artifacts::read(
        &plan.join("Cargo.lock"),
        16 * 1024 * 1024,
    )?)?)?;
    ensure!(
        seed_lock.package.len() <= 4096,
        "Cargo initial lock exceeds its package bound"
    );
    let roots = seed_lock
        .package
        .iter()
        .filter(|item| {
            item.name == "omg-admission-plan" && item.version == "0.0.0" && item.source.is_none()
        })
        .collect::<Vec<_>>();
    ensure!(
        roots.len() == 1 && roots[0].dependencies.len() == 1,
        "Cargo initial lock omitted its sole direct registry dependency"
    );
    let direct = roots[0].dependencies[0]
        .split_whitespace()
        .collect::<Vec<_>>();
    ensure!(
        !direct.is_empty() && direct.len() <= 3 && direct[0] == name,
        "Cargo initial lock changed the requested direct dependency"
    );
    if let Some(origin) = direct.get(2) {
        ensure!(
            origin
                .strip_prefix('(')
                .and_then(|source| source.strip_suffix(')'))
                .is_some_and(public_source),
            "Cargo direct dependency selected a non-public registry"
        );
    }
    let required = semver::VersionReq::parse(&requirement)?;
    let selected = seed_lock
        .package
        .iter()
        .filter(|item| {
            item.name == name
                && item.source.as_deref().is_some_and(public_source)
                && direct.get(1).is_none_or(|version| *version == item.version)
                && semver::Version::parse(&item.version)
                    .is_ok_and(|version| required.matches(&version))
        })
        .collect::<Vec<_>>();
    ensure!(
        selected.len() == 1,
        "Cargo did not resolve one exact requested registry crate"
    );
    let version = selected[0].version.as_str();
    let checksum = selected[0]
        .checksum
        .as_deref()
        .context("Selected Cargo archive has no registry checksum")?;
    let cache = work.join("cargo-home");
    let archive = checked_cache_archive(&cache, name, version, checksum)?;
    let project = work.join("source");
    extract_verified_archive(
        &archive,
        checksum,
        &project,
        &format!("{name}-{version}"),
        work,
    )?;
    reject_config(&project)?;
    let generated = !project.join("Cargo.lock").try_exists()?;
    let mut metadata = command(&runtime, staging, request, work)?;
    metadata
        .args(["metadata", "--format-version=1", "--manifest-path"])
        .arg(project.join("Cargo.toml"));
    if !generated {
        metadata.arg("--locked");
    }
    runtime.verify()?;
    let resolved = artifacts::run(metadata, "Cargo locked dependency metadata", false)?;
    let lock = artifacts::read(&project.join("Cargo.lock"), 16 * 1024 * 1024)?;
    let (inventory, checksums, mut gaps) = inventory(&lock, name, version)?;
    if generated {
        gaps.push("The publisher did not include Cargo.lock; this exact frozen lock was generated by metadata resolution".into());
    }
    let mut fetch = command(&runtime, staging, request, work)?;
    fetch
        .args(["fetch", "--locked", "--manifest-path"])
        .arg(project.join("Cargo.toml"));
    artifacts::run(fetch, "Cargo locked source download", false)?;
    for ((name, version), checksum) in &checksums {
        let archive = checked_cache_archive(&cache, name, version, checksum)?;
        verify_extracted_archive(&cache, &archive, checksum, name, version, work)?;
    }
    let metadata: serde_json::Value = serde_json::from_slice(&resolved)?;
    let resolved_packages = metadata["packages"]
        .as_array()
        .context("Cargo omitted resolved source identities")?;
    ensure!(
        resolved_packages.len() <= 4096,
        "Cargo metadata package count exceeds its bound"
    );
    let owned = work.canonicalize()?;
    let lock_ids = inventory
        .iter()
        .map(|package| (package.name.as_str(), package.version.as_str()))
        .collect::<BTreeSet<_>>();
    for package in resolved_packages {
        let name = package["name"]
            .as_str()
            .context("Cargo metadata omitted crate name")?;
        let version = package["version"]
            .as_str()
            .context("Cargo metadata omitted crate version")?;
        ensure!(
            lock_ids.contains(&(name, version)),
            "Cargo resolved a source absent from the exact reviewed lock"
        );
        let manifest = Path::new(
            package["manifest_path"]
                .as_str()
                .context("Cargo metadata omitted manifest path")?,
        )
        .canonicalize()?;
        ensure!(
            manifest.starts_with(&owned),
            "Cargo local dependency escapes the isolated frozen source tree"
        );
        reject_config(manifest.parent().context("Cargo manifest has no parent")?)?;
    }
    let mut inputs = vec![
        project.clone(),
        cache.join("registry/src"),
        cache.join("registry/cache"),
    ];
    if cache.join("git").try_exists()? {
        inputs.push(cache.join("git"));
    }
    let seals = inputs
        .iter()
        .map(|path| artifacts::tree(path))
        .collect::<Result<Vec<_>>>()?;
    let graph = serde_json::json!({"crate":name,"version":version,"registry_sha256":checksum,"lock_sha256":artifacts::hash(&lock),"metadata_sha256":artifacts::hash(&resolved),"source_trees":seals});
    let context = artifacts::context("cargo", request, destination, &runtime, &graph, &gaps)?;
    let review = crate::core::security::package_review::review(
        &inventory,
        &context,
        &gaps,
        source.as_ref(),
    )?;
    runtime.verify()?;
    review.verify(source.as_ref())?;
    for (path, expected) in inputs.iter().zip(&seals) {
        ensure!(
            &artifacts::tree(path)? == expected,
            "Cargo source changed after advisory review"
        );
    }
    let mut install = command(&runtime, staging, request, work)?;
    install
        .args(["install", "--frozen", "--offline", "--locked", "--root"])
        .arg(staging)
        .arg("--path")
        .arg(&project);
    artifacts::run(install, "Cargo frozen reviewed build", true)?;
    for (path, expected) in inputs.iter().zip(&seals) {
        ensure!(
            &artifacts::tree(path)? == expected,
            "Cargo source changed while building"
        );
    }
    runtime.verify()?;
    review.verify(source.as_ref())?;
    drop(owner);
    artifacts::InstalledReview::finish("cargo", request, staging, runtime, review, source, &graph)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cargo_lock_binds_full_registry_coordinates_and_preserves_unknown_sources() -> Result<()> {
        let lock = format!(
            "[[package]]\nname='tool'\nversion='1.0.0'\n[[package]]\nname='dependency'\nversion='2.3.4'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{}'\n[[package]]\nname='private-dependency'\nversion='3.0.0'\nsource='git+https://example.invalid/project#abcd'\n",
            "a".repeat(64)
        );
        let (packages, checksums, gaps) = inventory(lock.as_bytes(), "tool", "1.0.0")?;
        assert_eq!(packages.len(), 3);
        assert_eq!(checksums.len(), 1);
        assert_eq!(gaps.len(), 1);
        assert_eq!(
            packages
                .iter()
                .find(|package| package.name == "private-dependency")
                .unwrap()
                .origin,
            SecurityOrigin::Unknown
        );
        assert!(
            inventory(
                lock.replace("checksum=", "wrong=").as_bytes(),
                "tool",
                "1.0.0"
            )
            .is_err()
        );
        Ok(())
    }
}
