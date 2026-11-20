//! Resolve a complete wheel inventory, review it, then install frozen offline.

use super::package_manager::{ManagedRuntime, ReviewedTool};
use super::tool_artifacts as artifacts;
use crate::core::security::vulnerability::VulnerabilitySource;
use crate::package_managers::types::{SecurityOrigin, SecurityPackage};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone, Debug, serde::Serialize)]
struct Wheel {
    name: String,
    version: String,
    url: String,
    filename: String,
    sha256: String,
    public: bool,
}
#[derive(Deserialize)]
struct Report {
    version: String,
    install: Vec<ReportItem>,
}
#[derive(Deserialize)]
struct ReportItem {
    download_info: Download,
    metadata: Metadata,
    #[serde(default)]
    is_direct: bool,
    #[serde(default)]
    requested: bool,
}
#[derive(Deserialize)]
struct Metadata {
    name: String,
    version: String,
}
#[derive(Deserialize)]
struct Download {
    url: String,
    archive_info: ArchiveInfo,
}
#[derive(Deserialize)]
struct ArchiveInfo {
    hashes: BTreeMap<String, String>,
}
fn normalized(name: &str) -> Result<String> {
    ensure!(
        !name.is_empty()
            && name.len() <= 214
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)),
        "Invalid Python registry package name"
    );
    let mut result = String::new();
    for byte in name.bytes() {
        if b"-_.".contains(&byte) {
            if !result.ends_with('-') {
                result.push('-');
            }
        } else {
            result.push(char::from(byte.to_ascii_lowercase()));
        }
    }
    ensure!(
        !result.starts_with('-') && !result.ends_with('-'),
        "Invalid canonical Python package identity"
    );
    Ok(result)
}
fn version(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 160
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".!_+-".contains(&byte)),
        "Python wheel has no bounded exact version"
    );
    Ok(())
}
fn selector(request: &str) -> Result<(&str, Option<&str>)> {
    let (name, exact) = request
        .rsplit_once('@')
        .map_or((request, None), |(name, exact)| (name, Some(exact)));
    normalized(name)?;
    if let Some(exact) = exact {
        version(exact)?;
    }
    Ok((name, exact))
}
pub(crate) fn validate_request(request: &str) -> Result<()> {
    selector(request).map(|_| ())
}
fn report(bytes: &[u8], requested: Option<&str>) -> Result<(Vec<Wheel>, Vec<String>)> {
    let parsed: Report = serde_json::from_slice(bytes)?;
    ensure!(
        parsed.version == "1" && !parsed.install.is_empty() && parsed.install.len() <= 4096,
        "Pip report has no bounded complete wheel inventory"
    );
    let mut wheels = BTreeMap::new();
    let mut roots = Vec::new();
    let mut gaps = Vec::new();
    for item in parsed.install {
        let name = normalized(&item.metadata.name)?;
        version(&item.metadata.version)?;
        let url = reqwest::Url::parse(&item.download_info.url)?;
        ensure!(
            url.username().is_empty() && url.password().is_none() && url.fragment().is_none(),
            "Python artifact URL contains credentials or a fragment"
        );
        let public = url.scheme() == "https"
            && url.host_str() == Some("files.pythonhosted.org")
            && url.port_or_known_default() == Some(443)
            && url.query().is_none()
            && !item.is_direct;
        let filename = url
            .path_segments()
            .and_then(Iterator::last)
            .context("Python wheel URL has no filename")?
            .to_owned();
        ensure!(
            Path::new(&filename)
                .extension()
                .is_some_and(|extension| extension == "whl")
                && filename.len() <= 250
                && filename
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte)),
            "Only exact binary wheel artifacts can be admitted"
        );
        let sha256 = item
            .download_info
            .archive_info
            .hashes
            .get("sha256")
            .context("Python wheel has no SHA-256 identity")?
            .clone();
        ensure!(
            sha256.len() == 64
                && sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "Invalid Python wheel SHA-256"
        );
        if item.requested {
            roots.push(name.clone());
        }
        if !public {
            gaps.push(format!(
                "Python dependency {name} {} has a direct or non-public artifact origin",
                item.metadata.version
            ));
        }
        let wheel = Wheel {
            name: name.clone(),
            version: item.metadata.version,
            url: item.download_info.url,
            filename,
            sha256,
            public,
        };
        ensure!(
            wheels.insert(name, wheel).is_none(),
            "Pip report contains duplicate package identities"
        );
    }
    if let Some(requested) = requested {
        let (name, exact) = selector(requested)?;
        ensure!(
            roots == [normalized(name)?],
            "Pip report changed the selected package"
        );
        if let Some(exact) = exact {
            ensure!(
                wheels
                    .get(&normalized(name)?)
                    .is_some_and(|wheel| wheel.version == exact),
                "Pip report changed the requested exact version"
            );
        }
    }
    Ok((wheels.into_values().collect(), gaps))
}
fn inventory(wheels: &[Wheel]) -> Vec<SecurityPackage> {
    wheels
        .iter()
        .map(|wheel| SecurityPackage {
            origin: if wheel.public {
                SecurityOrigin::PyPiRegistry
            } else {
                SecurityOrigin::Unknown
            },
            name: wheel.name.clone(),
            version: wheel.version.clone(),
            advisory_source: None,
            architecture: None,
            description: String::new(),
            licenses: vec![],
        })
        .collect()
}
fn pip(
    runtime: &ManagedRuntime,
    python: &Path,
    staging: &Path,
    request: &str,
    cache: &Path,
) -> Result<std::process::Command> {
    runtime.verify()?;
    let mut command = crate::cli::tool::secured_manager_command(python, staging, "pip", request)?;
    command
        .args([
            "-I",
            "-B",
            "-m",
            "pip",
            "--isolated",
            "--disable-pip-version-check",
            "--no-input",
            "--cache-dir",
        ])
        .arg(cache);
    Ok(command)
}
fn inspect_wheel(path: &Path, wheel: &Wheel) -> Result<()> {
    use std::io::Read as _;
    let mut archive = zip::ZipArchive::new(fs::File::open(path)?)?;
    ensure!(archive.len() <= 100_000, "Wheel has too many members");
    let mut selected = None;
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        let name = entry.name()?;
        if name.ends_with(".dist-info/METADATA") && name.split('/').count() == 2 {
            ensure!(
                selected.replace(index).is_none() && entry.size() <= 1024 * 1024,
                "Wheel metadata is ambiguous or oversized"
            );
        }
    }
    let mut metadata = String::new();
    archive
        .by_index(selected.context("Wheel contains no distribution metadata")?)?
        .take(1024 * 1024 + 1)
        .read_to_string(&mut metadata)?;
    ensure!(
        metadata.len() <= 1024 * 1024,
        "Wheel metadata exceeds its bound"
    );
    let mut name = None;
    let mut found_version = None;
    for line in metadata.lines().take_while(|line| !line.is_empty()) {
        if let Some(value) = line.strip_prefix("Name: ") {
            ensure!(
                name.replace(normalized(value)?).is_none(),
                "Wheel metadata repeats its package name"
            );
        }
        if let Some(value) = line.strip_prefix("Version: ") {
            ensure!(
                found_version.replace(value.to_owned()).is_none(),
                "Wheel metadata repeats its version"
            );
        }
        ensure!(
            !(line.starts_with("Requires-Dist:")
                || line.starts_with(' ')
                || line.starts_with('\t'))
                || !line.contains('@'),
            "Wheel declares a direct dependency source that is outside the reviewed registry graph"
        );
    }
    ensure!(
        name.as_deref() == Some(&wheel.name) && found_version.as_deref() == Some(&wheel.version),
        "Downloaded wheel metadata differs from the reviewed identity"
    );
    Ok(())
}
pub(super) trait WheelDownloader {
    fn download(&self, url: &str, path: &Path) -> Result<()>;
}

struct PublicWheelDownloader;
impl WheelDownloader for PublicWheelDownloader {
    fn download(&self, url: &str, path: &Path) -> Result<()> {
        artifacts::scoped_future(async {
            use tokio::io::AsyncWriteExt as _;
            let mut response = crate::core::http::fetch_public_download_with_timeout(
                url,
                "omg-reviewed-wheel",
                Some(std::time::Duration::from_mins(2)),
            )
            .await?
            .error_for_status()?;
            let mut output = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .await?;
            let mut bytes = 0u64;
            while let Some(chunk) = response.chunk().await? {
                bytes += chunk.len() as u64;
                ensure!(
                    bytes <= 512 * 1024 * 1024,
                    "Python wheel exceeds its download bound"
                );
                output.write_all(&chunk).await?;
            }
            output.sync_all().await?;
            Ok(())
        })
    }
}

fn fetch_wheel(wheel: &Wheel, path: &Path, downloader: &dyn WheelDownloader) -> Result<()> {
    ensure!(
        wheel.public,
        "Private Python wheel sources remain UNKNOWN and cannot be fetched through the fixed public transport"
    );
    downloader.download(&wheel.url, path)?;
    let (sha256, _) = super::security::file_digest(path, 512 * 1024 * 1024)?;
    ensure!(
        sha256 == wheel.sha256,
        "Downloaded Python wheel differs from its reviewed hash"
    );
    Ok(())
}

fn installed_distributions(prefix: &Path) -> Result<BTreeMap<String, String>> {
    let mut rows = BTreeMap::new();
    let library = prefix.join("lib");
    for python in fs::read_dir(&library)? {
        let python = python?;
        ensure!(
            python.file_type()?.is_dir(),
            "Python library layout is redirected"
        );
        let packages = python.path().join("site-packages");
        if !packages.try_exists()? {
            continue;
        }
        ensure!(
            fs::symlink_metadata(&packages)?.is_dir(),
            "Python package inventory is redirected"
        );
        for item in fs::read_dir(packages)? {
            let item = item?;
            if !item.file_name().to_string_lossy().ends_with(".dist-info") {
                continue;
            }
            ensure!(
                item.file_type()?.is_dir() && rows.len() < 4096,
                "Python installed distribution inventory is redirected or oversized"
            );
            let metadata = artifacts::read(&item.path().join("METADATA"), 1024 * 1024)?;
            let metadata = std::str::from_utf8(&metadata)?;
            let mut name = None;
            let mut exact = None;
            for line in metadata.lines().take_while(|line| !line.is_empty()) {
                if let Some(value) = line.strip_prefix("Name: ") {
                    ensure!(
                        name.replace(normalized(value)?).is_none(),
                        "Python installed metadata repeats its name"
                    );
                }
                if let Some(value) = line.strip_prefix("Version: ") {
                    version(value)?;
                    ensure!(
                        exact.replace(value.to_owned()).is_none(),
                        "Python installed metadata repeats its version"
                    );
                }
            }
            ensure!(
                rows.insert(
                    name.context("Python installed metadata omitted its name")?,
                    exact.context("Python installed metadata omitted its version")?
                )
                .is_none(),
                "Python installed inventory repeats a distribution"
            );
        }
    }
    Ok(rows)
}

pub(crate) fn install_reviewed(
    request: &str,
    staging: &Path,
    destination: &Path,
    tools: &Path,
    source: Arc<dyn VulnerabilitySource>,
    security: &super::security::RuntimeSecurity,
) -> Result<Box<dyn ReviewedTool>> {
    install_reviewed_with_downloader(
        request,
        staging,
        destination,
        tools,
        source,
        security,
        &PublicWheelDownloader,
    )
}

pub(super) fn install_reviewed_with_downloader(
    request: &str,
    staging: &Path,
    destination: &Path,
    tools: &Path,
    source: Arc<dyn VulnerabilitySource>,
    security: &super::security::RuntimeSecurity,
    downloader: &dyn WheelDownloader,
) -> Result<Box<dyn ReviewedTool>> {
    ensure!(
        !crate::cli::tool::host_environment_is_allowed("pip", request),
        "Private pip configuration cannot establish a public wheel graph"
    );
    let (name, exact) = selector(request)?;
    let requirement = exact.map_or_else(|| name.to_owned(), |version| format!("{name}=={version}"));
    let runtime = ManagedRuntime::open("python", tools, security)?;
    let python = runtime
        .command_path("python3")
        .or_else(|_| runtime.command_path("python"))?;
    let owner = tempfile::Builder::new()
        .prefix(".pip-review-")
        .tempdir_in(staging)?;
    let work = owner.path();
    let cache = work.join("cache");
    let wheelhouse = work.join("wheels");
    fs::create_dir_all(&wheelhouse)?;
    let mut venv = crate::cli::tool::secured_manager_command(&python, staging, "pip", request)?;
    venv.args(["-I", "-B", "-m", "venv", "--copies"])
        .arg(staging);
    artifacts::run(venv, "Create isolated managed-Python installer", false)?;
    let isolated = staging.join("bin/python");
    ensure!(
        isolated
            .canonicalize()?
            .starts_with(staging.canonicalize()?),
        "Python venv interpreter escaped the owned staging tree"
    );
    let interpreter_sha256 = artifacts::hash(&artifacts::read(&python, 512 * 1024 * 1024)?);
    ensure!(
        artifacts::hash(&artifacts::read(&isolated, 512 * 1024 * 1024)?) == interpreter_sha256,
        "Venv interpreter differs from the reviewed managed Python"
    );
    let installer_roots = [staging.join("bin"), staging.join("lib")];
    let installer_seals = installer_roots
        .iter()
        .map(|path| artifacts::tree(path))
        .collect::<Result<Vec<_>>>()?;
    let configuration_sha256 =
        artifacts::hash(&artifacts::read(&staging.join("pyvenv.cfg"), 1024 * 1024)?);
    let bootstrap = installed_distributions(staging)?;
    let verify_installer = || -> Result<()> {
        ensure!(
            artifacts::hash(&artifacts::read(&staging.join("pyvenv.cfg"), 1024 * 1024)?)
                == configuration_sha256,
            "Python venv configuration changed after resolution"
        );
        for (path, expected) in installer_roots.iter().zip(&installer_seals) {
            ensure!(
                artifacts::tree(path)? == *expected,
                "Pip installer changed after dependency resolution"
            );
        }
        Ok(())
    };
    let bootstrap_inventory = bootstrap
        .iter()
        .map(|(name, version)| SecurityPackage {
            origin: SecurityOrigin::PyPiRegistry,
            name: name.clone(),
            version: version.clone(),
            advisory_source: None,
            architecture: None,
            description: String::new(),
            licenses: vec![],
        })
        .collect::<Vec<_>>();
    let bootstrap_graph = serde_json::json!({"phase":"pip-bootstrap-before-untrusted-metadata","installer_trees":installer_seals,"interpreter_sha256":interpreter_sha256,"venv_configuration_sha256":configuration_sha256,"bootstrap_distributions":bootstrap});
    let preflight = if bootstrap_inventory.is_empty() {
        None
    } else {
        Some(crate::core::security::package_review::review(
            &bootstrap_inventory,
            &artifacts::context("pip", request, destination, &runtime, &bootstrap_graph, &[])?,
            &[],
            source.as_ref(),
        )?)
    };
    runtime.verify()?;
    if let Some(preflight) = &preflight {
        preflight.verify(source.as_ref())?;
    }
    verify_installer()?;
    let output = work.join("resolved.json");
    let mut resolve = pip(&runtime, &isolated, staging, request, &cache)?;
    resolve
        .args([
            "install",
            "--dry-run",
            "--ignore-installed",
            "--only-binary=:all:",
            "--index-url",
            "https://pypi.org/simple",
            "--report",
        ])
        .arg(&output)
        .args(["--", &requirement]);
    artifacts::run(resolve, "Pip binary-only dependency metadata", false)?;
    verify_installer()?;
    if let Some(preflight) = &preflight {
        preflight.verify(source.as_ref())?;
    }
    let (wheels, gaps) = report(&artifacts::read(&output, 16 * 1024 * 1024)?, Some(request))?;
    let graph = serde_json::json!({"wheels":wheels,"report_sha256":artifacts::hash(&artifacts::read(&output,16*1024*1024)?),"installer_trees":installer_seals,"interpreter_sha256":interpreter_sha256,"venv_configuration_sha256":configuration_sha256,"bootstrap_distributions":bootstrap});
    let context = artifacts::context("pip", request, destination, &runtime, &graph, &gaps)?;
    let full_inventory = bootstrap_inventory
        .into_iter()
        .chain(inventory(&wheels))
        .map(|package| ((package.name.clone(), package.version.clone()), package))
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect::<Vec<_>>();
    let review = crate::core::security::package_review::review(
        &full_inventory,
        &context,
        &gaps,
        source.as_ref(),
    )?;
    runtime.verify()?;
    review.verify(source.as_ref())?;
    verify_installer()?;
    let mut total = 0u64;
    let mut requirements = String::new();
    for wheel in &wheels {
        let path = wheelhouse.join(&wheel.filename);
        fetch_wheel(wheel, &path, downloader)?;
        total += fs::metadata(&path)?.len();
        ensure!(
            total <= 2 * 1024 * 1024 * 1024,
            "Frozen Python wheel inventory exceeds its byte allowance"
        );
        inspect_wheel(&path, wheel)?;
        let _ = writeln!(
            requirements,
            "{}=={} --hash=sha256:{}",
            wheel.name, wheel.version, wheel.sha256
        );
    }
    let requirements_path = work.join("requirements.txt");
    fs::write(&requirements_path, &requirements)?;
    let recipe_sha256 = artifacts::hash(requirements.as_bytes());
    let input_seal = artifacts::tree(&wheelhouse)?;
    let local_report = work.join("frozen.json");
    verify_installer()?;
    ensure!(
        artifacts::hash(&artifacts::read(&requirements_path, 1024 * 1024)?) == recipe_sha256,
        "Pip frozen requirements changed before metadata verification"
    );
    let mut frozen = pip(&runtime, &isolated, staging, request, &cache)?;
    frozen
        .args([
            "install",
            "--dry-run",
            "--ignore-installed",
            "--only-binary=:all:",
            "--no-index",
            "--require-hashes",
            "--find-links",
        ])
        .arg(&wheelhouse)
        .arg("--report")
        .arg(&local_report)
        .arg("--requirement")
        .arg(&requirements_path);
    artifacts::run(frozen, "Pip offline wheel dependency verification", false)?;
    let (local, _) = report(&artifacts::read(&local_report, 16 * 1024 * 1024)?, None)?;
    let identity = |rows: &[Wheel]| {
        rows.iter()
            .map(|wheel| {
                (
                    wheel.name.clone(),
                    wheel.version.clone(),
                    wheel.sha256.clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    ensure!(
        identity(&local) == identity(&wheels),
        "Offline wheel metadata changed the reviewed dependency graph"
    );
    runtime.verify()?;
    review.verify(source.as_ref())?;
    verify_installer()?;
    ensure!(
        artifacts::hash(&artifacts::read(&requirements_path, 1024 * 1024)?) == recipe_sha256,
        "Pip frozen requirements changed before installation"
    );
    ensure!(
        artifacts::tree(&wheelhouse)? == input_seal,
        "Python wheel inputs changed after review"
    );
    let mut install = pip(&runtime, &isolated, staging, request, &cache)?;
    install
        .args([
            "install",
            "--only-binary=:all:",
            "--no-index",
            "--no-deps",
            "--require-hashes",
            "--find-links",
        ])
        .arg(&wheelhouse)
        .arg("--requirement")
        .arg(&requirements_path);
    artifacts::run(install, "Pip frozen reviewed wheel install", true)?;
    let mut expected_distributions = bootstrap;
    for wheel in &wheels {
        expected_distributions.insert(wheel.name.clone(), wheel.version.clone());
    }
    ensure!(
        installed_distributions(staging)? == expected_distributions,
        "Installed Python distributions differ from the reviewed wheel and trusted bootstrap inventory"
    );
    ensure!(
        artifacts::hash(&artifacts::read(&staging.join("pyvenv.cfg"), 1024 * 1024)?)
            == configuration_sha256,
        "Wheel installation changed the reviewed venv configuration"
    );
    ensure!(
        artifacts::hash(&artifacts::read(&requirements_path, 1024 * 1024)?) == recipe_sha256,
        "Pip frozen requirements changed during installation"
    );
    ensure!(
        artifacts::hash(&artifacts::read(&isolated, 512 * 1024 * 1024)?) == interpreter_sha256,
        "Wheel installation replaced the reviewed Python interpreter"
    );
    ensure!(
        artifacts::tree(&wheelhouse)? == input_seal,
        "Python wheel inputs changed while installing"
    );
    runtime.verify()?;
    review.verify(source.as_ref())?;
    crate::cli::tool::relocate_venv_entry_points(staging, destination)?;
    drop(owner);
    artifacts::InstalledReview::finish("pip", request, staging, runtime, review, source, &graph)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wheel_fixture(path: &Path, metadata: &str) -> Result<Wheel> {
        use std::io::Write as _;
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        writer
            .start_file(
                "fixture/__init__.py",
                zip::write::SimpleFileOptions::default(),
            )
            .expect("create controlled wheel payload entry");
        writer.write_all(b"# controlled wheel payload\n")?;
        writer
            .start_file(
                "fixture-1.2.3.dist-info/METADATA",
                zip::write::SimpleFileOptions::default(),
            )
            .expect("create controlled wheel metadata entry");
        writer.write_all(metadata.as_bytes())?;
        let bytes = writer.finish()?.into_inner();
        fs::write(path, &bytes)?;
        Ok(Wheel {
            name: "fixture".into(),
            version: "1.2.3".into(),
            url: "https://files.pythonhosted.org/packages/fixture-1.2.3-py3-none-any.whl".into(),
            filename: "fixture-1.2.3-py3-none-any.whl".into(),
            sha256: artifacts::hash(&bytes),
            public: true,
        })
    }

    #[test]
    fn pip_report_preserves_complete_exact_wheel_versions_and_hashes() -> Result<()> {
        let item = |name: &str, url: &str, requested: bool| serde_json::json!({"metadata":{"name":name,"version":"1.2.3"},"requested":requested,"is_direct":false,"download_info":{"url":url,"archive_info":{"hashes":{"sha256":"a".repeat(64)}}}});
        let data = serde_json::json!({"version":"1","install":[item("Fixture_Tool","https://files.pythonhosted.org/packages/fixture_tool-1.2.3-py3-none-any.whl",true),item("dependency","https://private.example/dependency-1.2.3-py3-none-any.whl",false)]});
        let (wheels, gaps) = report(&serde_json::to_vec(&data)?, Some("fixture-tool"))?;
        assert_eq!(wheels.len(), 2);
        assert_eq!(gaps.len(), 1);
        assert_eq!(inventory(&wheels)[0].origin, SecurityOrigin::Unknown);
        assert!(report(&serde_json::to_vec(&data)?, Some("other-tool")).is_err());
        assert_eq!(normalized("Foo...BAR___baz")?, "foo-bar-baz");
        Ok(())
    }

    #[test]
    fn pip_wheel_metadata_requires_exact_identity_and_refuses_direct_dependency_sources()
    -> Result<()> {
        let owner = tempfile::tempdir()?;
        let archive = owner.path().join("fixture.whl");
        let valid = "Metadata-Version: 2.3\nName: fixture\nVersion: 1.2.3\nRequires-Dist: dependency (>=1)\n\ncontrolled description\n";
        let wheel = wheel_fixture(&archive, valid)?;
        inspect_wheel(&archive, &wheel)?;
        for metadata in [
            valid.replace("Name: fixture", "Name: different"),
            valid.replace("Version: 1.2.3", "Version: 9.9.9"),
            valid.replace("Name: fixture", "Name: fixture\nName: fixture"),
            valid.replace(
                "Requires-Dist: dependency (>=1)",
                "Requires-Dist: dependency @ https://private.example/dependency.whl",
            ),
            valid.replace(
                "Requires-Dist: dependency (>=1)",
                "Requires-Dist: dependency\n @ https://private.example/dependency.whl",
            ),
        ] {
            wheel_fixture(&archive, &metadata)?;
            assert!(inspect_wheel(&archive, &wheel).is_err(), "{metadata}");
        }
        Ok(())
    }

    #[test]
    fn pip_inventory_ignores_ordinary_modules_but_rejects_ambiguous_distribution_identity()
    -> Result<()> {
        let owner = tempfile::tempdir()?;
        let library = owner.path().join("lib");
        fs::create_dir_all(library.join("python-without-site-packages"))?;
        let packages = library.join("python3.14/site-packages");
        fs::create_dir_all(packages.join("fixture-1.2.3.dist-info"))?;
        fs::write(
            packages.join("ordinary.py"),
            b"# ordinary imported module\n",
        )
        .expect("write ordinary Python module fixture");
        let metadata = packages.join("fixture-1.2.3.dist-info/METADATA");
        fs::write(&metadata, b"Name: fixture\nVersion: 1.2.3\n\n")?;
        assert_eq!(
            installed_distributions(owner.path())?,
            BTreeMap::from([("fixture".into(), "1.2.3".into())])
        );
        fs::write(&metadata, b"Name: fixture\nName: other\nVersion: 1.2.3\n\n")?;
        assert!(installed_distributions(owner.path()).is_err());
        Ok(())
    }

    #[test]
    fn pip_private_wheel_refusal_precedes_any_transport_request() -> Result<()> {
        struct RecordingTransport {
            source: std::path::PathBuf,
            calls: std::sync::atomic::AtomicUsize,
        }
        impl WheelDownloader for RecordingTransport {
            fn download(&self, _: &str, path: &Path) -> Result<()> {
                self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                fs::copy(&self.source, path)?;
                Ok(())
            }
        }
        let owner = tempfile::tempdir()?;
        let archive = owner.path().join("fixture.whl");
        let mut wheel = wheel_fixture(&archive, "Name: fixture\nVersion: 1.2.3\n\n")?;
        let transport = RecordingTransport {
            source: archive.clone(),
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        wheel.public = false;
        let destination = owner.path().join("download.whl");
        assert!(fetch_wheel(&wheel, &destination, &transport).is_err());
        assert_eq!(transport.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(!destination.exists());
        wheel.public = true;
        fetch_wheel(&wheel, &destination, &transport)?;
        assert_eq!(transport.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(fs::read(&archive)?, fs::read(&destination)?);
        Ok(())
    }

    #[test]
    fn pip_public_downloader_streams_real_http_and_preserves_existing_files() -> Result<()> {
        const NAME: &str = "runtimes::pip_tool::tests::pip_public_downloader_streams_real_http_and_preserves_existing_files";
        if crate::core::testing::run_isolated_test(NAME) {
            return Ok(());
        }
        temp_env::with_var("OMG_TEST_MODE", Some("1"), || {
            artifacts::scoped_future(async {
                let body = b"controlled bounded wheel bytes".to_vec();
                let fixture = crate::runtimes::test_https::HttpFixture::new(vec![
                    ("/fixture.whl".into(), body.clone()),
                    (
                        "/fixture.whl".into(),
                        b"must not replace existing bytes".to_vec(),
                    ),
                ])
                .await?;
                let url = format!("http://{}/fixture.whl", fixture.address);
                let owner = tempfile::tempdir()?;
                let path = owner.path().join("fixture.whl");
                let requested_path = path.clone();
                let requested_url = url.clone();
                tokio::task::spawn_blocking(move || {
                    PublicWheelDownloader.download(&requested_url, &requested_path)
                })
                .await??;
                assert_eq!(fs::read(&path)?, body);
                let requested_path = path.clone();
                let result = tokio::task::spawn_blocking(move || {
                    PublicWheelDownloader.download(&url, &requested_path)
                })
                .await?;
                assert!(
                    result.is_err(),
                    "Downloader must create a fresh owned artifact"
                );
                assert_eq!(fs::read(&path)?, body);
                assert_eq!(fixture.finish().await?.len(), 2);
                Ok(())
            })
        })
    }

    #[cfg(unix)]
    #[test]
    fn pip_owner_retains_reviewed_bootstrap_through_frozen_install() -> Result<()> {
        use crate::runtimes::tool_artifacts::tests as fixtures;
        let (owner, data, stage) = fixtures::fixture("python", "python3", fixtures::PYTHON)?;
        fs::write(
            data.join("bootstrap-metadata"),
            b"Name: pip\nVersion: 24.0\n\n",
        )
        .expect("write controlled trusted pip bootstrap metadata");
        let wheels = fixtures::pip_wheels(&data, false)?;
        let destination = fixtures::previous(owner.path(), "pip")?;
        let source = Arc::new(fixtures::TransitiveFinding {
            no_findings: true,
            ..Default::default()
        });
        let capability = install_reviewed_with_downloader(
            "fixture-tool@1.2.3",
            &stage,
            &destination,
            &owner.path().join("tools"),
            source.clone(),
            &crate::runtimes::security::RuntimeSecurity::fixture(),
            &wheels,
        )
        .expect("install controlled complete bootstrap and wheel graph");
        capability.verify(&stage)?;
        let distributions = installed_distributions(&stage)?;
        assert_eq!(distributions.len(), 3);
        assert_eq!(distributions.get("pip").map(String::as_str), Some("24.0"));
        let seen = source.seen.lock().unwrap();
        assert_eq!(seen.len(), 3);
        assert!(
            seen.iter()
                .any(|row| row.name == "pip" && row.version == "24.0")
        );
        assert_eq!(
            fs::read_to_string(data.join("phases"))?,
            "venv\nresolve\noffline-resolve\ninstall\n"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn pip_owner_accepts_an_admitted_python_only_runtime_through_publication() -> Result<()> {
        use crate::runtimes::tool_artifacts::tests as fixtures;
        use std::process::Command;

        let (owner, data, stage) = fixtures::fixture("python", "python3", fixtures::PYTHON)?;
        let runtime = owner.path().join("versions/python/1.78.0");
        fs::rename(runtime.join("bin/python3"), runtime.join("bin/python"))
            .expect("create the controlled python-only managed layout");
        crate::runtimes::security::fixture_prepare("python", "1.78.0", &runtime, &runtime)
            .expect("admit the complete python-only managed fixture");
        assert!(!runtime.join("bin/python3").exists());
        let wheels = fixtures::pip_wheels(&data, false)?;
        let destination = fixtures::previous(owner.path(), "pip")?;
        let source = Arc::new(fixtures::TransitiveFinding {
            no_findings: true,
            ..Default::default()
        });
        let capability = install_reviewed_with_downloader(
            "fixture-tool@1.2.3",
            &stage,
            &destination,
            &owner.path().join("tools"),
            source,
            &crate::runtimes::security::RuntimeSecurity::fixture(),
            &wheels,
        )
        .expect("install the fully reviewed wheel graph with managed bin/python");
        capability.verify(&stage)?;
        let backup = destination.with_extension("previous");
        fs::rename(&destination, &backup)?;
        fs::rename(&stage, &destination)?;
        capability.verify(&destination)?;
        let output = Command::new(destination.join("bin/fixture-tool")).output()?;
        assert!(output.status.success());
        assert_eq!(output.stdout, b"reviewed-tool-success\n");
        assert_eq!(
            fs::read(backup.join("bin/fixture-tool"))?,
            b"previous reviewed tool"
        );
        assert_eq!(
            fs::read_to_string(data.join("phases"))?,
            "venv\nresolve\noffline-resolve\ninstall\n"
        );
        Ok(())
    }
}
