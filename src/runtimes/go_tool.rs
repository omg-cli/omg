//! Freeze the actual public Go module graph before building a tool package.

use super::package_manager::{ManagedRuntime, ReviewedTool};
use super::tool_artifacts as artifacts;
use crate::core::security::vulnerability::VulnerabilitySource;
use crate::package_managers::types::{SecurityOrigin, SecurityPackage};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Module {
    path: String,
    version: Option<String>,
    dir: Option<PathBuf>,
    sum: Option<String>,
    go_mod_sum: Option<String>,
    zip: Option<PathBuf>,
    replace: Option<serde_json::Value>,
    error: Option<serde_json::Value>,
    #[serde(default)]
    main: bool,
}
fn modules(bytes: &[u8]) -> Result<Vec<Module>> {
    let rows = serde_json::Deserializer::from_slice(bytes)
        .into_iter::<Module>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        !rows.is_empty() && rows.len() <= 4096,
        "Go module inventory exceeds its bound"
    );
    Ok(rows)
}
fn module_path(path: &str) -> bool {
    path.len() <= 1024
        && path.split('/').count() >= 2
        && path.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-._~!+".contains(&byte))
        })
}
fn exact(version: &str) -> Result<()> {
    let parsed = semver::Version::parse(
        version
            .strip_prefix('v')
            .context("Go version lacks v prefix")?,
    )?;
    ensure!(
        format!("v{parsed}") == version,
        "Go module version is not exact and canonical"
    );
    Ok(())
}
pub(crate) fn validate_request(request: &str) -> Result<()> {
    let (package, query) = request
        .rsplit_once('@')
        .map_or((request, "latest"), |(path, version)| (path, version));
    ensure!(
        module_path(package) && (query == "latest" || exact(query).is_ok()),
        "Expected a Go package with an exact version or latest"
    );
    Ok(())
}
fn checksum(value: &str) -> Result<()> {
    ensure!(
        STANDARD
            .decode(
                value
                    .strip_prefix("h1:")
                    .context("Go module has no checksum-database digest")?
            )?
            .len()
            == 32,
        "Invalid Go module checksum"
    );
    Ok(())
}
fn verify_module_files(
    directory: &Path,
    module: &str,
    version: &str,
    expected: &str,
) -> Result<()> {
    use sha2::{Digest as _, Sha256};
    let mut pending = vec![directory.to_path_buf()];
    let mut rows = BTreeMap::new();
    let mut count = 0;
    let mut total = 0u64;
    let mut hasher = artifacts::RegularFileHasher::new();
    while let Some(parent) = pending.pop() {
        for child in fs::read_dir(parent)? {
            let child = child?;
            count += 1;
            ensure!(count <= 200_000, "Go module source exceeds its entry bound");
            let path = child.path();
            let metadata = child.metadata()?;
            if metadata.is_dir() {
                pending.push(path);
            } else {
                ensure!(
                    metadata.is_file(),
                    "Go module contains a link or special file"
                );
                let relative = path
                    .strip_prefix(directory)?
                    .to_str()
                    .context("Go source path is not UTF-8")?;
                #[cfg(windows)]
                let relative = relative.replace('\\', "/");
                ensure!(
                    !relative.contains(['\n', '\\']),
                    "Go module source has an ambiguous checksum path"
                );
                let allowance = (1024 * 1024 * 1024 - total).min(256 * 1024 * 1024);
                let (digest, bytes) = hasher.hash(&path, &metadata, allowance)?;
                total += bytes;
                rows.insert(format!("{module}@{version}/{relative}"), digest);
            }
        }
    }
    let mut digest = Sha256::new();
    for (name, hash) in rows {
        digest.update(format!("{hash}  {name}\n"));
    }
    ensure!(
        format!("h1:{}", STANDARD.encode(digest.finalize())) == expected,
        "Go module source differs from its checksum-database identity"
    );
    Ok(())
}
fn command(
    runtime: &ManagedRuntime,
    staging: &Path,
    request: &str,
    work: &Path,
    cwd: &Path,
    frozen: bool,
) -> Result<std::process::Command> {
    let mut command = crate::cli::tool::secured_manager_command(
        runtime.command_path("go")?,
        staging,
        "go",
        request,
    )?;
    command
        .current_dir(cwd)
        .env("GOPATH", work.join("gopath"))
        .env("GOMODCACHE", work.join("modules"))
        .env("GOCACHE", work.join("build-cache"))
        .env("GOWORK", "off")
        .env("GOENV", "off")
        .env("GOTOOLCHAIN", "local")
        .env("GOPRIVATE", "")
        .env("GONOPROXY", "")
        .env("GONOSUMDB", "")
        .env("GOINSECURE", "")
        .env(
            "GOPROXY",
            if frozen {
                "off"
            } else {
                "https://proxy.golang.org"
            },
        )
        .env("GOSUMDB", if frozen { "off" } else { "sum.golang.org" })
        .env(
            "CGO_ENABLED",
            if crate::cli::tool::package_is_allowed("OMG_TOOL_ALLOW_GO_CGO", request) {
                "1"
            } else {
                "0"
            },
        );
    if frozen {
        command.env("GOFLAGS", "-mod=readonly");
    } else {
        command.env("GOFLAGS", "");
    }
    Ok(command)
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
        !crate::cli::tool::host_environment_is_allowed("go", request),
        "Private Go configuration cannot establish a public frozen module graph"
    );
    let (package, query) = request
        .rsplit_once('@')
        .map_or((request, "latest"), |(path, version)| (path, version));
    ensure!(
        module_path(package) && (query == "latest" || exact(query).is_ok()),
        "Expected a Go package with an exact version or latest"
    );
    let runtime = ManagedRuntime::open("go", tools, security)?;
    let owner = tempfile::Builder::new()
        .prefix(".go-review-")
        .tempdir_in(staging)?;
    let work = owner.path();
    let plan = work.join("plan");
    fs::create_dir_all(&plan)?;
    let mut candidate = package.to_owned();
    let mut selected = None;
    loop {
        let mut lookup = command(&runtime, staging, request, work, &plan, false)?;
        lookup
            .args(["list", "-m", "-json"])
            .arg(format!("{candidate}@{query}"));
        runtime.verify()?;
        match artifacts::run(lookup, "Go public module metadata", false) {
            Ok(bytes) => {
                let module: Module = serde_json::from_slice(&bytes)?;
                ensure!(
                    module.path == candidate && module.error.is_none(),
                    "Go proxy returned a different module"
                );
                selected = Some(module);
                break;
            }
            Err(error) => {
                let message = format!("{error:#}");
                if !message.contains("404") && !message.contains("410") {
                    return Err(error);
                }
                let Some((parent, _)) = candidate
                    .rsplit_once('/')
                    .filter(|(parent, _)| module_path(parent))
                else {
                    break;
                };
                candidate = parent.into();
            }
        }
    }
    let selected = selected
        .context("Go package has no exact public module identity; no build was admitted")?;
    let version = selected
        .version
        .as_deref()
        .context("Go proxy omitted its exact version")?;
    exact(version)?;
    let mut download = command(&runtime, staging, request, work, &plan, false)?;
    download
        .args(["mod", "download", "-json"])
        .arg(format!("{}@{version}", selected.path));
    let downloaded = modules(&artifacts::run(
        download,
        "Go verified root module download",
        false,
    )?)?;
    ensure!(
        downloaded.len() == 1
            && downloaded[0].path == selected.path
            && downloaded[0].version.as_deref() == Some(version)
            && downloaded[0].error.is_none(),
        "Go root download changed the selected module"
    );
    let downloaded = &downloaded[0];
    checksum(
        downloaded
            .sum
            .as_deref()
            .context("Go root download has no checksum")?,
    )?;
    checksum(
        downloaded
            .go_mod_sum
            .as_deref()
            .context("Go root manifest has no checksum")?,
    )?;
    let cache = work.join("modules").canonicalize()?;
    let extracted = downloaded
        .dir
        .as_ref()
        .context("Go root download has no verified source")?
        .canonicalize()?;
    ensure!(
        extracted.starts_with(&cache),
        "Go source escaped the private verified module cache"
    );
    let archive = downloaded
        .zip
        .as_ref()
        .context("Go root download has no archive identity")?;
    ensure!(
        archive.canonicalize()?.starts_with(&cache),
        "Go module archive escaped its private cache"
    );
    let (archive_sha256, _) = artifacts::RegularFileHasher::new().hash(
        archive,
        &fs::symlink_metadata(archive)?,
        256 * 1024 * 1024,
    )?;
    artifacts::tree(&extracted)?;
    let project = work.join("source");
    super::common::copy_regular_tree(&extracted, &project, false)?;
    verify_module_files(
        &project,
        &selected.path,
        version,
        downloaded
            .sum
            .as_deref()
            .context("Go root checksum missing")?,
    )?;
    let mut edit = command(&runtime, staging, request, work, &project, false)?;
    edit.args(["mod", "edit", "-json"]);
    let manifest: serde_json::Value = serde_json::from_slice(&artifacts::run(
        edit,
        "Go module manifest inspection",
        false,
    )?)?;
    ensure!(
        manifest["Module"]["Path"].as_str() == Some(selected.path.as_str()),
        "Go source manifest changed the requested module"
    );
    let replacements = manifest["Replace"]
        .as_array()
        .is_some_and(|rows| !rows.is_empty());
    if replacements {
        let inventory = [SecurityPackage {
            origin: SecurityOrigin::Unknown,
            name: selected.path.clone(),
            version: version.into(),
            advisory_source: None,
            architecture: None,
            description: String::new(),
            licenses: vec![],
        }];
        let gaps=vec!["The Go module declares replacements; a public checksum-complete build graph cannot be established without resolving those separate source identities".into()];
        let graph = serde_json::json!({"module":selected.path,"version":version,"manifest":manifest,"archive_sha256":archive_sha256});
        crate::core::security::package_review::review(
            &inventory,
            &artifacts::context("go", request, destination, &runtime, &graph, &gaps)?,
            &gaps,
            source.as_ref(),
        )?;
        anyhow::bail!(
            "Go replacement sources remain unresolved; frozen installation was not admitted"
        );
    }
    let mut download = command(&runtime, staging, request, work, &project, false)?;
    download.args(["mod", "download", "-json", "all"]);
    let downloaded_bytes = artifacts::run(
        download,
        "Go complete checksum-bound module download",
        false,
    )?;
    let dependencies = if downloaded_bytes.iter().all(u8::is_ascii_whitespace) {
        Vec::new()
    } else {
        modules(&downloaded_bytes)?
    };
    let mut list = command(&runtime, staging, request, work, &project, false)?;
    list.args(["list", "-mod=readonly", "-m", "-json", "all"]);
    let graph_bytes = artifacts::run(list, "Go complete frozen module graph", false)?;
    let graph_modules = modules(&graph_bytes)?;
    let mut inventory = BTreeMap::new();
    let mut graph_ids = BTreeSet::new();
    let mut downloaded_ids = BTreeSet::new();
    let mut proofs = Vec::new();
    inventory.insert(
        (selected.path.clone(), version.to_owned()),
        SecurityPackage {
            origin: SecurityOrigin::GoModule,
            name: selected.path.clone(),
            version: version.into(),
            advisory_source: None,
            architecture: None,
            description: String::new(),
            licenses: vec![],
        },
    );
    for module in &dependencies {
        ensure!(
            module.error.is_none() && module.replace.is_none() && module_path(&module.path),
            "Go module graph includes an unresolved or replaced source"
        );
        let exact_version = module
            .version
            .as_deref()
            .context("Go dependency omitted its exact version")?;
        exact(exact_version)?;
        let sum = module
            .sum
            .as_deref()
            .context("Go dependency omitted its source checksum")?;
        checksum(sum)?;
        let mod_sum = module
            .go_mod_sum
            .as_deref()
            .context("Go dependency omitted its manifest checksum")?;
        checksum(mod_sum)?;
        let directory = module
            .dir
            .as_ref()
            .context("Go dependency omitted its source directory")?
            .canonicalize()?;
        ensure!(
            directory.starts_with(&cache),
            "Go dependency escaped its checksum-verified cache"
        );
        verify_module_files(&directory, &module.path, exact_version, sum)?;
        let key = (module.path.clone(), exact_version.to_owned());
        ensure!(
            downloaded_ids.insert(key.clone()),
            "Go graph has duplicate dependency identities"
        );
        inventory.insert(
            key,
            SecurityPackage {
                origin: SecurityOrigin::GoModule,
                name: module.path.clone(),
                version: exact_version.into(),
                advisory_source: None,
                architecture: None,
                description: String::new(),
                licenses: vec![],
            },
        );
        proofs.push(serde_json::json!({"module":module.path,"version":exact_version,"sum":sum,"go_mod_sum":mod_sum}));
    }
    for module in graph_modules {
        ensure!(
            module.error.is_none() && module.replace.is_none(),
            "Go listed an unresolved replacement"
        );
        if module.main {
            ensure!(
                module.path == selected.path,
                "Go selected a different main module"
            );
            continue;
        }
        let version = module
            .version
            .context("Go graph dependency has no version")?;
        ensure!(
            graph_ids.insert((module.path, version)),
            "Go graph repeats a module identity"
        );
    }
    ensure!(
        graph_ids == downloaded_ids,
        "Go downloaded inventory does not match the complete build graph"
    );
    let mut verify = command(&runtime, staging, request, work, &project, true)?;
    verify.args(["mod", "verify"]);
    artifacts::run(verify, "Go source checksum verification", false)?;
    let inputs = [project.clone(), cache];
    let seals = inputs
        .iter()
        .map(|path| artifacts::tree(path))
        .collect::<Result<Vec<_>>>()?;
    let graph = serde_json::json!({"module":selected.path,"version":version,"package":package,"archive_sha256":archive_sha256,"modules":proofs,"graph_sha256":artifacts::hash(&graph_bytes),"source_trees":seals});
    let context = artifacts::context("go", request, destination, &runtime, &graph, &[])?;
    let review = crate::core::security::package_review::review(
        &inventory.into_values().collect::<Vec<_>>(),
        &context,
        &[],
        source.as_ref(),
    )?;
    runtime.verify()?;
    review.verify(source.as_ref())?;
    for (path, expected) in inputs.iter().zip(&seals) {
        ensure!(
            &artifacts::tree(path)? == expected,
            "Go source changed after advisory review"
        );
    }
    let suffix = package
        .strip_prefix(&selected.path)
        .context("Go package is outside its resolved module")?;
    ensure!(
        suffix.is_empty() || suffix.starts_with('/'),
        "Go package prefix is not a module boundary"
    );
    let target = if suffix.is_empty() {
        ".".to_owned()
    } else {
        format!(".{suffix}")
    };
    fs::create_dir_all(staging.join("bin"))?;
    let name = destination
        .file_name()
        .context("Go destination has no tool name")?;
    let mut build = command(&runtime, staging, request, work, &project, true)?;
    build
        .args([
            "build",
            "-mod=readonly",
            "-trimpath",
            "-buildvcs=false",
            "-o",
        ])
        .arg(staging.join("bin").join(name))
        .arg(&target);
    artifacts::run(build, "Go frozen reviewed build", true)?;
    for (path, expected) in inputs.iter().zip(&seals) {
        ensure!(
            &artifacts::tree(path)? == expected,
            "Go source or checksums changed during its reviewed build"
        );
    }
    runtime.verify()?;
    review.verify(source.as_ref())?;
    drop(owner);
    artifacts::InstalledReview::finish("go", request, staging, runtime, review, source, &graph)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn go_inventory_uses_module_identity_and_rejects_unverified_sources() -> Result<()> {
        let rows=modules(br#"{"Path":"example.com/tool","Version":"v1.2.3","Sum":"h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
{"Path":"example.com/dependency","Version":"v2.3.4"}"#)?;
        assert_eq!(rows[0].path, "example.com/tool");
        assert_ne!(rows[0].path, "example.com/tool/cmd/cli");
        checksum(rows[0].sum.as_deref().unwrap())?;
        assert!(checksum("h1:not-a-checksum").is_err());
        assert!(!module_path("example.com/../local"));
        assert!(exact("v1.2.3-0.20260910120000-0123456789ab").is_ok());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn go_command_refuses_a_project_local_manager_before_spawn() -> Result<()> {
        use crate::runtimes::tool_artifacts::tests as fixtures;
        const NAME: &str =
            "runtimes::go_tool::tests::go_command_refuses_a_project_local_manager_before_spawn";
        if crate::core::testing::run_isolated_test(NAME) {
            return Ok(());
        }
        let (owner, data, stage) = fixtures::fixture("go", "go", fixtures::GO)?;
        fs::create_dir(owner.path().join(".git"))?;
        let runtime = ManagedRuntime::open(
            "go",
            &owner.path().join("tools"),
            &crate::runtimes::security::RuntimeSecurity::fixture(),
        )
        .expect("open sealed Go fixture runtime");
        let original = std::env::current_dir()?;
        std::env::set_current_dir(owner.path())?;
        let result = command(&runtime, &stage, "example.com/tool", &data, &stage, false);
        std::env::set_current_dir(original)?;
        let error = result.expect_err("Project-local Go must not start");
        assert!(format!("{error:#}").contains("Refusing project-local go executable"));
        assert!(!data.join("phases").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn go_owner_refuses_resolution_checksum_and_unattended_replacement_failures() -> Result<()> {
        use crate::runtimes::tool_artifacts::tests as fixtures;
        const NAME: &str = "runtimes::go_tool::tests::go_owner_refuses_resolution_checksum_and_unattended_replacement_failures";
        if crate::core::testing::run_isolated_test(NAME) {
            return Ok(());
        }
        nix::unistd::setsid()?;
        for fault in [
            "not-found",
            "download-json",
            "root-checksum",
            "manifest-checksum",
            "source-mutation",
            "manifest-json",
            "dependency-download",
            "replacement",
        ] {
            let script = match fault {
                "not-found" => fixtures::GO.replace("'list -m') printf '{\"Path\":\"example.com/tool\",\"Version\":\"v1.2.3\"}' ;;", "'list -m') printf '410 module not found' >&2; exit 1 ;;"),
                "download-json" => fixtures::GO.replace("'mod download')", "'mod download') printf 'invalid module JSON'; exit 0;"),
                "manifest-checksum" => fixtures::GO.replace("\"GoModSum\":\"h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"", "\"GoModSum\":\"h1:invalid\""),
                "manifest-json" => fixtures::GO.replace("'mod edit') printf '{\"Module\":{\"Path\":\"example.com/tool\"},\"Replace\":[]}' ;;", "'mod edit') printf 'invalid manifest JSON' ;;"),
                "dependency-download" => fixtures::GO.replace("if [ \"$4\" = 'all' ]; then", "if [ \"$4\" = 'all' ]; then printf 'dependency transport unavailable' >&2; exit 1;"),
                "replacement" => fixtures::GO.replace("\"Replace\":[]", "\"Replace\":[{\"New\":{\"Path\":\"./private\"}}]"),
                _ => fixtures::GO.to_owned(),
            };
            let (owner, data, stage) = fixtures::fixture("go", "go", &script)?;
            fixtures::go_source(&data, "root", "example.com/tool", "v1.2.3")?;
            fixtures::go_source(&data, "dependency", "example.com/dependency", "v2.3.4")?;
            if fault == "root-checksum" {
                fs::write(data.join("root.sum"), b"h1:invalid")?;
            }
            if fault == "source-mutation" {
                fs::write(
                    data.join("root/go.mod"),
                    b"module different.example/unreviewed\n",
                )
                .expect("write mismatched Go module source fixture");
            }
            let destination = fixtures::previous(owner.path(), "go")?;
            let source = Arc::new(fixtures::TransitiveFinding {
                no_findings: true,
                ..Default::default()
            });
            let result = install_reviewed(
                "example.com/tool@v1.2.3",
                &stage,
                &destination,
                &owner.path().join("tools"),
                source.clone(),
                &crate::runtimes::security::RuntimeSecurity::fixture(),
            );
            let error = result
                .err()
                .context(format!("Go {fault} failure was admitted"))?;
            let error = format!("{error:#}");
            if fault == "not-found" {
                assert!(error.contains("no exact public module identity"), "{error}");
            }
            if fault == "replacement" {
                assert!(
                    error.contains("terminal") || error.contains("accept"),
                    "{error}"
                );
            }
            assert!(
                source.seen.lock().unwrap().is_empty(),
                "Unresolved {fault} graph reached public assessment"
            );
            assert!(
                !data.join("MATERIALIZED").exists(),
                "Unresolved {fault} graph reached build"
            );
            assert_eq!(
                fs::read(destination.join("bin/fixture-tool"))?,
                b"previous reviewed tool"
            );
        }
        Ok(())
    }

    #[test]
    fn go_module_checksum_authenticates_nested_source_and_rejects_mutation() -> Result<()> {
        let owner = tempfile::tempdir()?;
        fs::create_dir_all(owner.path().join("cmd/tool"))?;
        fs::write(
            owner.path().join("go.mod"),
            b"module example.com/tool\n\ngo 1.20\n",
        )
        .expect("write exact Go checksum fixture manifest");
        let main = owner.path().join("cmd/tool/main.go");
        fs::write(&main, b"package main\nfunc main() {}\n")?;
        let expected = "h1:l3Hn2tVlaVfKySuCI6EM3TnGNhovQeBjLOKxNdMT0jc=";
        verify_module_files(owner.path(), "example.com/tool", "v1.2.3", expected)?;
        assert!(
            verify_module_files(owner.path(), "example.com/other", "v1.2.3", expected).is_err()
        );
        fs::write(&main, b"package main\nfunc main() { panic(1) }\n")?;
        assert!(verify_module_files(owner.path(), "example.com/tool", "v1.2.3", expected).is_err());
        fs::write(&main, b"package main\nfunc main() {}\n")?;
        #[cfg(unix)]
        {
            let link = owner.path().join("cmd/tool/redirect.go");
            std::os::unix::fs::symlink("main.go", &link)?;
            assert!(
                verify_module_files(owner.path(), "example.com/tool", "v1.2.3", expected).is_err()
            );
            fs::remove_file(link)?;
            fs::write(
                owner.path().join("ambiguous\nname"),
                b"not a valid checksum path",
            )
            .expect("write ambiguous Go checksum fixture path");
            assert!(
                verify_module_files(owner.path(), "example.com/tool", "v1.2.3", expected).is_err()
            );
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn go_module_checksum_refuses_literal_backslashes() -> Result<()> {
        let owner = tempfile::tempdir()?;
        fs::write(owner.path().join("docs\\readme"), b"ordinary fixture")?;
        let error = verify_module_files(
            owner.path(),
            "example.com/tool",
            "v1.2.3",
            "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )
        .expect_err("Go paths with literal backslashes are outside the module format");
        assert!(
            error.to_string().contains("ambiguous checksum path"),
            "{error:#}"
        );
        Ok(())
    }

    #[test]
    fn go_module_checksum_hashes_large_regular_file() -> Result<()> {
        let owner = tempfile::tempdir()?;
        fs::File::create(owner.path().join("payload.bin"))?.set_len(64 * 1024 * 1024)?;
        verify_module_files(
            owner.path(),
            "example.com/tool",
            "v1.2.3",
            "h1:mzZm1lljEYJgsQxrEx4xE/NJaL9VLzj5Rl/O0te01Uc=",
        )
    }

    #[test]
    fn go_requests_refuse_noncanonical_versions_and_unsafe_paths() {
        for request in [
            "example.com/tool",
            "example.com/tool@latest",
            "example.com/tool/cmd/cli@v1.2.3",
        ] {
            assert!(validate_request(request).is_ok(), "{request}");
        }
        for request in [
            "example.com/tool@v1.2",
            "example.com/tool@v01.2.3",
            "example.com/tool@branch",
            "example.com/tool@1.2.3",
            "example.com/../tool",
            "example.com/tool;sh",
        ] {
            assert!(validate_request(request).is_err(), "{request}");
        }
        assert!(modules(b" ").is_err());
        assert!(modules(br#"{"Path":"example.com/tool"}garbage"#).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn go_owner_resolves_parent_module_and_freezes_dependency_free_subpackage_build() -> Result<()>
    {
        use crate::runtimes::tool_artifacts::tests as fixtures;
        const NAME: &str = "runtimes::go_tool::tests::go_owner_resolves_parent_module_and_freezes_dependency_free_subpackage_build";
        if crate::core::testing::run_isolated_test(NAME) {
            return Ok(());
        }
        let lookup = "'list -m') case \"$4\" in example.com/tool@*) printf '{\"Path\":\"example.com/tool\",\"Version\":\"v1.2.3\"}' ;; *) printf '404 module not found' >&2; exit 1 ;; esac ;;";
        let script = fixtures::GO
            .replace("'list -m') printf '{\"Path\":\"example.com/tool\",\"Version\":\"v1.2.3\"}' ;;", lookup)
            .replace("printf '{\"Path\":\"example.com/dependency\",\"Version\":\"v2.3.4\",\"Dir\":\"%s/dependency\",\"Sum\":\"%s\",\"GoModSum\":\"h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}' \"$GOMODCACHE\" \"$(cat \"$fixture/dependency.sum\")\"", ":")
            .replace("printf '{\"Path\":\"example.com/tool\",\"Main\":true}\\n{\"Path\":\"example.com/dependency\",\"Version\":\"v2.3.4\"}'", "printf '{\"Path\":\"example.com/tool\",\"Main\":true}'")
            .replace("mkdir -p \"$fixture/MATERIALIZED\" \"$(dirname \"$destination\")\"", "[ \"$argument\" = './cmd/cli' ] || exit 97\n  mkdir -p \"$fixture/MATERIALIZED\" \"$(dirname \"$destination\")\"");
        let (owner, data, stage) = fixtures::fixture("go", "go", &script)?;
        fixtures::go_source(&data, "root", "example.com/tool", "v1.2.3")?;
        fixtures::go_source(&data, "dependency", "example.com/dependency", "v2.3.4")?;
        let destination = fixtures::previous(owner.path(), "go")?;
        let source = Arc::new(fixtures::TransitiveFinding {
            no_findings: true,
            ..Default::default()
        });
        temp_env::with_var(
            "OMG_TOOL_ALLOW_GO_CGO",
            Some("example.com/tool/cmd/cli@v1.2.3"),
            || {
                let capability = install_reviewed(
                    "example.com/tool/cmd/cli@v1.2.3",
                    &stage,
                    &destination,
                    &owner.path().join("tools"),
                    source.clone(),
                    &crate::runtimes::security::RuntimeSecurity::fixture(),
                )
                .expect("admit exact controlled dependency-free Go graph");
                capability.verify(&stage)
            },
        )
        .expect("verify controlled Go owner with scoped CGO option");
        assert!(data.join("MATERIALIZED").is_dir());
        let seen = source.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].name, "example.com/tool");
        assert_eq!(seen[0].version, "v1.2.3");
        assert_eq!(
            fs::read_to_string(data.join("phases"))?
                .matches("list -m\n")
                .count(),
            3
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn go_replacement_graph_never_builds_after_exact_risk_acceptance() -> Result<()> {
        const NAME: &str = "runtimes::go_tool::tests::go_replacement_graph_never_builds_after_exact_risk_acceptance";
        if std::env::var("OMG_GO_REPLACEMENT_PTY").as_deref() != Ok("1") {
            const DRIVER: &str = r"
import importlib.util, os, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('consent', sys.argv[2])
terminal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(terminal)
terminal.NAME = sys.argv[3]
code, transcript = terminal.terminal_case(Path(sys.argv[1]), 'accept', dict(os.environ), expected=(b'Coverage: unknown', b'Go module declares replacements', b'https://www.cve.org/'))
assert code == 0 and b'1 passed; 0 failed' in transcript, transcript.decode(errors='replace')
";
            let root = tempfile::tempdir()?;
            let output = std::process::Command::new(
                crate::core::privilege::root_controlled_program_path("python3")?,
            )
            .arg("-c")
            .arg(DRIVER)
            .arg(std::env::current_exe()?)
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/test-arch-advisory-consent.py"),
            )
            .arg(NAME)
            .env("OMG_GO_REPLACEMENT_PTY", "1")
            .env("HOME", root.path())
            .env("XDG_CONFIG_HOME", root.path().join("config"))
            .env("OMG_CONFIG_DIR", root.path().join("config/omg"))
            .env("XDG_DATA_HOME", root.path().join("data"))
            .env("OMG_DATA_DIR", root.path().join("data/omg"))
            .env_remove("SUDO_USER")
            .env_remove("DOAS_USER")
            .output()?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(output.status.success(), "{stdout}\n{stderr}");
            return Ok(());
        }
        use crate::runtimes::tool_artifacts::tests as fixtures;
        let script = fixtures::GO.replace("\"Replace\":[]", "\"Replace\":[{\"Old\":{\"Path\":\"example.com/dependency\"},\"New\":{\"Path\":\"./local\"}}]");
        let (owner, data, stage) = fixtures::fixture("go", "go", &script)?;
        fixtures::go_source(&data, "root", "example.com/tool", "v1.2.3")?;
        fixtures::go_source(&data, "dependency", "example.com/dependency", "v2.3.4")?;
        let destination = fixtures::previous(owner.path(), "go")?;
        let source = Arc::new(fixtures::TransitiveFinding {
            no_findings: true,
            ..Default::default()
        });
        let result = install_reviewed(
            "example.com/tool@v1.2.3",
            &stage,
            &destination,
            &owner.path().join("tools"),
            source.clone(),
            &crate::runtimes::security::RuntimeSecurity::fixture(),
        );
        let error = result
            .err()
            .context("Unresolved replacement sources produced an installed tool")?;
        let error = format!("{error:#}");
        assert!(
            error.contains("Go replacement sources remain unresolved"),
            "{error}"
        );
        assert!(
            source.seen.lock().unwrap().is_empty(),
            "Private replacement must not be queried as a public module"
        );
        assert!(!data.join("MATERIALIZED").exists());
        assert_eq!(
            fs::read_to_string(data.join("phases"))?,
            "list -m\nmod download\nmod edit\n"
        );
        Ok(())
    }
}
