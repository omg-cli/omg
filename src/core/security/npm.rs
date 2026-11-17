//! Exact public npm identities admitted before package materialization.

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NpmSpec {
    pub(crate) name: String,
    pub(crate) version: Option<String>,
}

impl NpmSpec {
    pub(crate) fn parse(input: &str) -> Result<Self> {
        ensure!(input.len() <= 380, "npm selector exceeds its limit");
        let (name, version) = match input.rsplit_once('@') {
            Some((name, version)) if !name.is_empty() => {
                exact_version(version)?;
                (name, Some(version.to_owned()))
            }
            _ => (input, None),
        };
        ensure!(
            registry_name(name),
            "Expected a public npm registry package name"
        );
        Ok(Self {
            name: name.to_owned(),
            version,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NpmPackage {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) resolved: String,
    pub(crate) integrity: String,
}

#[derive(Debug)]
pub(crate) struct NpmLock {
    pub(crate) sha256: String,
    pub(crate) packages: BTreeMap<String, NpmPackage>,
}

impl NpmLock {
    pub(crate) fn verify_installed(
        &self,
        staging: &std::path::Path,
        requested: &NpmSpec,
    ) -> Result<()> {
        self.verify_installed_with(staging, requested, &|path| std::fs::symlink_metadata(path))
    }

    fn verify_installed_with(
        &self,
        staging: &std::path::Path,
        requested: &NpmSpec,
        metadata: &dyn Fn(&std::path::Path) -> std::io::Result<std::fs::Metadata>,
    ) -> Result<()> {
        let mut pending = vec![(staging.join("node_modules"), false)];
        let mut seen = std::collections::BTreeSet::new();
        let mut examined = 0;
        while let Some((directory, scope)) = pending.pop() {
            ensure!(
                metadata(&directory)?.is_dir(),
                "npm package directory is not a real directory"
            );
            for entry in std::fs::read_dir(&directory)? {
                examined += 1;
                ensure!(
                    examined <= self.packages.len() * 4 + 2,
                    "Installed npm tree exceeds the reviewed inventory bound"
                );
                let entry = entry?;
                let filename = entry.file_name();
                let name = filename
                    .to_str()
                    .context("Installed npm path is not UTF-8")?;
                if !scope && matches!(name, ".bin" | ".package-lock.json") {
                    continue;
                }
                let path = entry.path();
                ensure!(
                    entry.file_type()?.is_dir(),
                    "Installed npm package is a link or non-directory"
                );
                if !scope && name.starts_with('@') {
                    pending.push((path, true));
                    continue;
                }
                let relative = path
                    .strip_prefix(staging)?
                    .to_str()
                    .context("Installed npm path is not UTF-8")?
                    .replace('\\', "/");
                let expected = self
                    .packages
                    .get(&relative)
                    .context("Installed npm package was not reviewed")?;
                let bytes = read_metadata(&path.join("package.json"), 1024 * 1024)?;
                let package: serde_json::Value = serde_json::from_slice(&bytes)?;
                ensure!(
                    package["name"].as_str() == Some(expected.name.as_str())
                        && package["version"].as_str() == Some(expected.version.as_str()),
                    "Installed npm identity differs from the reviewed version"
                );
                seen.insert(relative);
                let nested = path.join("node_modules");
                match metadata(&nested) {
                    Ok(metadata) => {
                        ensure!(
                            metadata.is_dir(),
                            "Nested npm inventory is not a real directory"
                        );
                        pending.push((nested, false));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        ensure!(
            seen.contains(&format!("node_modules/{}", requested.name)),
            "The requested npm package was not installed"
        );
        Ok(())
    }

    pub(crate) fn parse(bytes: &[u8], requested: &NpmSpec) -> Result<Self> {
        ensure!(bytes.len() <= 16 * 1024 * 1024, "npm lock exceeds 16 MiB");
        let lock: RawLock = serde_json::from_slice(bytes).context("Invalid npm lock")?;
        ensure!(
            lock.lockfile_version == 3,
            "npm advisory review requires a version 3 lock"
        );
        ensure!(
            (2..=4097).contains(&lock.packages.len()),
            "npm lock inventory must contain 1 to 4096 packages"
        );
        ensure!(
            registry_name(&requested.name),
            "Invalid requested npm identity"
        );
        let root = lock
            .packages
            .get("")
            .context("npm lock has no project root")?;
        let selected = lock
            .packages
            .get(&format!("node_modules/{}", requested.name))
            .context("npm lock omits the selected package")?;
        let selected_version = selected
            .version
            .as_deref()
            .context("Selected npm package has no exact version")?;
        ensure!(
            root.dependencies.len() == 1
                && root
                    .dependencies
                    .get(&requested.name)
                    .is_some_and(|version| version == selected_version),
            "npm lock root differs from the selected package"
        );
        ensure!(
            requested
                .version
                .as_deref()
                .is_none_or(|version| version == selected_version),
            "npm lock changed the requested exact version"
        );
        let mut packages = BTreeMap::new();
        for (path, entry) in &lock.packages {
            if path.is_empty() {
                continue;
            }
            ensure!(path.len() <= 4096, "npm lock path exceeds its limit");
            let relative = path
                .strip_prefix("node_modules/")
                .context("npm lock contains a non-package path")?;
            let mut name = "";
            for component in relative.split("/node_modules/") {
                ensure!(
                    registry_name(component),
                    "npm lock contains an invalid nested package path"
                );
                name = component;
            }
            ensure!(
                !entry.link,
                "npm lock links cannot establish registry identity"
            );
            ensure!(
                entry
                    .name
                    .as_deref()
                    .is_none_or(|declared| declared == name),
                "npm lock aliases cannot establish registry identity"
            );
            let version = entry
                .version
                .as_deref()
                .context("npm lock package has no version")?;
            exact_version(version)?;
            let resolved = entry
                .resolved
                .as_deref()
                .context("npm lock package has no registry tarball")?;
            let basename = name
                .rsplit('/')
                .next()
                .context("npm package has no basename")?;
            ensure!(
                resolved == format!("https://registry.npmjs.org/{name}/-/{basename}-{version}.tgz"),
                "npm lock tarball does not bind its public registry package and version"
            );
            let integrity = entry
                .integrity
                .as_deref()
                .context("npm lock package has no integrity")?;
            let digest = integrity
                .strip_prefix("sha512-")
                .context("npm lock requires SHA-512 integrity")?;
            ensure!(
                STANDARD.decode(digest)?.len() == 64,
                "npm lock has invalid SHA-512 integrity"
            );
            packages.insert(
                path.clone(),
                NpmPackage {
                    name: name.into(),
                    version: version.into(),
                    resolved: resolved.into(),
                    integrity: integrity.into(),
                },
            );
        }
        for (path, entry) in &lock.packages {
            for dependency in entry
                .dependencies
                .keys()
                .chain(entry.optional_dependencies.keys())
            {
                ensure!(
                    registry_name(dependency),
                    "npm dependency has no registry identity"
                );
                let mut parent = path.as_str();
                loop {
                    let candidate = if parent.is_empty() {
                        format!("node_modules/{dependency}")
                    } else {
                        format!("{parent}/node_modules/{dependency}")
                    };
                    if packages.contains_key(&candidate) {
                        break;
                    }
                    ensure!(!parent.is_empty(), "npm lock omits a resolved dependency");
                    parent = parent
                        .rsplit_once("/node_modules/")
                        .map_or("", |(ancestor, _)| ancestor);
                }
            }
        }
        Ok(Self {
            sha256: hex::encode(Sha256::digest(bytes)),
            packages,
        })
    }
}

pub(crate) fn read_metadata(path: &std::path::Path, limit: usize) -> Result<Vec<u8>> {
    use std::io::Read as _;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "npm metadata is not a regular file"
    );
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "npm metadata exceeds its byte limit");
    Ok(bytes)
}

pub(crate) fn manager_identity(release: &std::path::Path) -> Result<BTreeMap<String, String>> {
    use std::fs;
    use std::io::Read as _;
    let root = release.canonicalize()?;
    let npm = root.join("lib/node_modules/npm");
    ensure!(
        fs::symlink_metadata(&npm)?.is_dir(),
        "Bundled npm must have a real implementation directory"
    );
    let mut pending = vec![npm.clone(), root.join("bin/npm"), root.join("bin/node")];
    let mut directories = std::collections::BTreeSet::new();
    let mut identity = BTreeMap::new();
    let mut entries = 0usize;
    let mut npm_bytes = 0u64;
    let mut buffer = vec![0u8; 64 * 1024];
    while let Some(path) = pending.pop() {
        entries += 1;
        ensure!(
            entries <= 16_384,
            "Bundled npm implementation exceeds its entry limit"
        );
        let relative = path
            .strip_prefix(&root)?
            .to_str()
            .context("npm implementation path is not UTF-8")?
            .replace('\\', "/");
        let target = path.canonicalize()?;
        ensure!(
            target.starts_with(&root),
            "npm implementation escapes its managed release"
        );
        if path.starts_with(&npm) || path == root.join("bin/npm") {
            ensure!(
                target.starts_with(&npm),
                "npm implementation escapes its package directory"
            );
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_symlink() {
            let target_name = target
                .strip_prefix(&root)?
                .to_str()
                .context("npm link target is not UTF-8")?;
            identity.insert(
                format!("link:{relative}"),
                hex::encode(Sha256::digest(target_name.as_bytes())),
            );
        }
        let expected = fs::symlink_metadata(&target)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            identity.insert(
                format!("metadata:{relative}"),
                hex::encode(Sha256::digest(
                    format!("{}:{}:{}", expected.mode(), expected.uid(), expected.gid()).as_bytes(),
                )),
            );
        }
        if expected.is_dir() {
            ensure!(
                directories.insert(target.clone()),
                "npm implementation contains a directory alias or cycle"
            );
            identity.insert(
                format!("directory:{relative}"),
                hex::encode(Sha256::digest([])),
            );
            for entry in fs::read_dir(&path)? {
                ensure!(
                    entries + pending.len() < 16_384,
                    "Bundled npm implementation exceeds its entry limit"
                );
                pending.push(entry?.path());
            }
            continue;
        }
        ensure!(
            expected.is_file(),
            "npm implementation contains a special file"
        );
        let is_node = path == root.join("bin/node");
        let binary = is_node || path == root.join("bin/npm");
        #[cfg(unix)]
        if binary {
            use std::os::unix::fs::PermissionsExt as _;
            ensure!(
                expected.permissions().mode() & 0o111 != 0,
                "Managed Node/npm entry point is not executable"
            );
        }
        #[cfg(not(unix))]
        let _ = binary;
        let limit = if is_node {
            512 * 1024 * 1024
        } else {
            32 * 1024 * 1024
        };
        ensure!(
            expected.len() <= limit,
            "npm implementation file exceeds its byte limit"
        );
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
        }
        let mut file = options.open(&target)?;
        let opened = file.metadata()?;
        ensure!(opened.is_file(), "npm implementation is not a regular file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            ensure!(
                opened.dev() == expected.dev() && opened.ino() == expected.ino(),
                "npm implementation changed while opening it"
            );
        }
        let mut bytes = 0u64;
        let mut digest = Sha256::new();
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            bytes += count as u64;
            ensure!(
                bytes <= limit,
                "npm implementation grew beyond its byte limit"
            );
            if !is_node {
                npm_bytes += count as u64;
                ensure!(
                    npm_bytes <= 128 * 1024 * 1024,
                    "Bundled npm implementation exceeds 128 MiB"
                );
            }
            digest.update(&buffer[..count]);
        }
        let after = file.metadata()?;
        ensure!(
            bytes == opened.len()
                && after.len() == opened.len()
                && after.modified()? == opened.modified()?
                && path.canonicalize()? == target,
            "npm implementation changed while hashing it"
        );
        identity.insert(relative, hex::encode(digest.finalize()));
    }
    ensure!(
        identity.contains_key("bin/node")
            && identity.contains_key("bin/npm")
            && identity.contains_key("lib/node_modules/npm/package.json"),
        "Managed Node/npm content identity is incomplete"
    );
    Ok(identity)
}

fn exact_version(version: &str) -> Result<()> {
    ensure!(version.len() <= 160, "npm version exceeds its limit");
    let parsed =
        semver::Version::parse(version).context("npm requires an exact semantic version")?;
    ensure!(
        parsed.to_string() == version,
        "npm version is not canonical"
    );
    Ok(())
}

fn registry_name(name: &str) -> bool {
    let part = |value: &str| {
        !value.is_empty()
            && !value.starts_with(['.', '_', '-'])
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_.".contains(&byte)
            })
    };
    name.len() <= 214
        && match name.strip_prefix('@') {
            Some(scoped) => scoped
                .split_once('/')
                .is_some_and(|(scope, name)| part(scope) && part(name)),
            None => part(name),
        }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawLock {
    lockfile_version: u32,
    packages: BTreeMap<String, RawPackage>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawPackage {
    name: Option<String>,
    version: Option<String>,
    resolved: Option<String>,
    integrity: Option<String>,
    #[serde(default)]
    link: bool,
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
    #[serde(default)]
    optional_dependencies: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[cfg(unix)]
    fn manager_tree(root: &std::path::Path) {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::create_dir_all(root.join("lib/node_modules/npm/lib")).unwrap();
        std::fs::write(root.join("bin/node"), b"node").unwrap();
        std::fs::set_permissions(
            root.join("bin/node"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::fs::write(
            root.join("lib/node_modules/npm/lib/cli.js"),
            b"module.exports = 1;\n",
        )
        .unwrap();
        std::fs::set_permissions(
            root.join("lib/node_modules/npm/lib/cli.js"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::fs::write(
            root.join("lib/node_modules/npm/package.json"),
            br#"{"version":"11.15.0"}"#,
        )
        .unwrap();
        symlink("../lib/node_modules/npm/lib/cli.js", root.join("bin/npm")).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn manager_identity_binds_imported_code_metadata_and_internal_link_targets() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        manager_tree(root);
        let original = manager_identity(root).unwrap();
        assert_eq!(original["bin/node"], hex::encode(Sha256::digest(b"node")));
        let imported = root.join("lib/node_modules/npm/lib/cli.js");
        std::fs::write(&imported, b"module.exports = 2;\n").unwrap();
        assert_ne!(manager_identity(root).unwrap(), original);
        std::fs::write(&imported, b"module.exports = 1;\n").unwrap();
        assert_eq!(manager_identity(root).unwrap(), original);
        std::fs::write(
            root.join("lib/node_modules/npm/package.json"),
            br#"{"version":"11.16.0"}"#,
        )
        .unwrap();
        assert_ne!(manager_identity(root).unwrap(), original);
    }

    #[cfg(unix)]
    #[test]
    fn manager_identity_rejects_external_links_and_directory_cycles() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("node");
        manager_tree(&root);
        let external = directory.path().join("external.js");
        std::fs::write(&external, b"unreviewed").unwrap();
        let imported = root.join("lib/node_modules/npm/lib/external.js");
        symlink(&external, &imported).unwrap();
        assert!(manager_identity(&root).is_err());
        std::fs::remove_file(&imported).unwrap();
        symlink("..", root.join("lib/node_modules/npm/lib/cycle")).unwrap();
        assert!(manager_identity(&root).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn manager_identity_rejects_special_files_and_oversized_content_before_reading() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir_in("/var/tmp").unwrap();
        let root = directory.path();
        manager_tree(root);
        let fifo = root.join("lib/node_modules/npm/lib/pipe");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRUSR).unwrap();
        assert!(manager_identity(root).is_err());
        std::fs::remove_file(&fifo).unwrap();
        let oversized = root.join("lib/node_modules/npm/lib/oversized");
        std::fs::File::create(&oversized)
            .unwrap()
            .set_len(32 * 1024 * 1024 + 1)
            .unwrap();
        assert!(manager_identity(root).is_err());
        std::fs::remove_file(oversized).unwrap();
        std::fs::set_permissions(
            root.join("bin/node"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(manager_identity(root).is_err());
    }

    fn spec() -> NpmSpec {
        NpmSpec {
            name: "app".into(),
            version: Some("1.0.0".into()),
        }
    }

    fn package(name: &str, version: &str) -> Value {
        json!({
            "version": version,
            "resolved": format!("https://registry.npmjs.org/{name}/-/{}-{version}.tgz", name.rsplit('/').next().unwrap()),
            "integrity": format!("sha512-{}", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw=="),
        })
    }

    fn lock() -> Value {
        let mut document = json!({
            "lockfileVersion": 3,
            "packages": {
                "": { "dependencies": {"app": "1.0.0"} },
                "node_modules/app": package("app", "1.0.0"),
                "node_modules/app/node_modules/@scope/dep": package("@scope/dep", "2.3.4-beta.1"),
                "node_modules/optional-dep": package("optional-dep", "4.5.6"),
            }
        });
        document["packages"]["node_modules/app"]["dependencies"] =
            json!({"@scope/dep":"2.3.4-beta.1","optional-dep":"4.5.6"});
        document["packages"]["node_modules/app/node_modules/@scope/dep"]["dependencies"] =
            json!({"optional-dep":"4.5.6"});
        document
    }

    #[test]
    fn exact_scoped_selectors_preserve_registry_identity() -> Result<()> {
        assert_eq!(
            NpmSpec::parse("@scope/name@1.2.3-beta.1")?,
            NpmSpec {
                name: "@scope/name".into(),
                version: Some("1.2.3-beta.1".into())
            }
        );
        assert_eq!(NpmSpec::parse("@scope/name")?.version, None);
        assert_eq!(
            NpmSpec::parse("lodash@4.17.20")?.version.as_deref(),
            Some("4.17.20")
        );
        for invalid in [
            "",
            "../app",
            "https://registry.npmjs.org/app",
            "user/repo",
            "app@latest",
            "app@^1.0.0",
            "app@1",
            "app@v1.0.0",
            "app@npm:other@1.0.0",
            "@scope/name/extra",
            "-app",
            ".app",
            "app\n",
            "@scope/name@1.0.0@2.0.0",
        ] {
            assert!(NpmSpec::parse(invalid).is_err(), "{invalid:?}");
        }
        Ok(())
    }

    #[test]
    fn lock_review_keeps_nested_and_optional_exact_coordinates() -> Result<()> {
        let bytes = serde_json::to_vec(&lock())?;
        let reviewed = NpmLock::parse(&bytes, &spec())?;
        assert_eq!(reviewed.packages.len(), 3);
        assert_eq!(
            reviewed.packages["node_modules/app/node_modules/@scope/dep"].name,
            "@scope/dep"
        );
        assert_eq!(
            reviewed.packages["node_modules/app/node_modules/@scope/dep"].version,
            "2.3.4-beta.1"
        );
        assert_eq!(
            reviewed.packages["node_modules/optional-dep"].version,
            "4.5.6"
        );
        assert_eq!(reviewed.sha256.len(), 64);
        let mut changed = lock();
        changed["packages"]["node_modules/optional-dep"]["optional"] = json!(true);
        assert_ne!(
            NpmLock::parse(&serde_json::to_vec(&changed)?, &spec())?.sha256,
            reviewed.sha256
        );
        Ok(())
    }

    #[test]
    fn lock_refuses_aliases_links_foreign_tarballs_and_weak_integrities() -> Result<()> {
        for (field, value) in [
            ("name", json!("another-package")),
            ("version", json!("^1.0.0")),
            ("link", json!(true)),
            ("resolved", json!("file:../../escape.tgz")),
            ("resolved", json!("https://evil.test/app/-/app-1.0.0.tgz")),
            (
                "resolved",
                json!("https://registry.npmjs.org/other/-/other-1.0.0.tgz"),
            ),
            (
                "resolved",
                json!("https://registry.npmjs.org/app/-/app-1.0.0.tgz?redirect=evil"),
            ),
            ("integrity", json!("sha1-AQID")),
            ("integrity", json!("sha512-AQID")),
            ("integrity", json!(null)),
        ] {
            let mut document = lock();
            document["packages"]["node_modules/app"][field] = value;
            assert!(
                NpmLock::parse(&serde_json::to_vec(&document)?, &spec()).is_err(),
                "{field}: {document}"
            );
        }
        for path in [
            "../node_modules/escape",
            "node_modules/app/../escape",
            "/node_modules/app",
            "node_modules/@scope",
            "node_modules/app/not-node_modules/dep",
        ] {
            let mut document = lock();
            document["packages"][path] = package("escape", "1.0.0");
            assert!(
                NpmLock::parse(&serde_json::to_vec(&document)?, &spec()).is_err(),
                "{path}"
            );
        }
        Ok(())
    }

    #[test]
    fn lock_requires_the_requested_root_and_complete_bounded_inventory() -> Result<()> {
        for pointer in [
            "/packages/",
            "/packages/node_modules~1app",
            "/packages/node_modules~1optional-dep/integrity",
        ] {
            let mut document = lock();
            *document.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(
                NpmLock::parse(&serde_json::to_vec(&document)?, &spec()).is_err(),
                "{pointer}"
            );
        }
        let mut document = lock();
        document["lockfileVersion"] = json!(2);
        assert!(NpmLock::parse(&serde_json::to_vec(&document)?, &spec()).is_err());
        let mut requested = spec();
        requested.version = Some("1.0.1".into());
        assert!(NpmLock::parse(&serde_json::to_vec(&lock())?, &requested).is_err());
        assert!(NpmLock::parse(&vec![b' '; 16 * 1024 * 1024 + 1], &spec()).is_err());
        let mut missing = lock();
        missing["packages"]["node_modules/app"]["dependencies"]["unresolved"] = json!("1.0.0");
        assert!(NpmLock::parse(&serde_json::to_vec(&missing)?, &spec()).is_err());
        Ok(())
    }

    fn materialize_fixture(staging: &std::path::Path, reviewed: &NpmLock) -> Result<()> {
        std::fs::create_dir_all(staging.join("node_modules/.bin"))?;
        std::fs::write(staging.join("node_modules/.package-lock.json"), b"{}")?;
        for (path, package) in &reviewed.packages {
            let directory = staging.join(path);
            std::fs::create_dir_all(&directory)?;
            let bytes =
                serde_json::to_vec(&json!({"name":package.name,"version":package.version}))?;
            std::fs::write(directory.join("package.json"), bytes)?;
        }
        Ok(())
    }

    #[test]
    fn materialized_versions_must_match_the_reviewed_coordinates() -> Result<()> {
        let staging = tempfile::tempdir()?;
        let reviewed = NpmLock::parse(&serde_json::to_vec(&lock())?, &spec())?;
        materialize_fixture(staging.path(), &reviewed)?;
        reviewed.verify_installed(staging.path(), &spec())?;
        std::fs::write(
            staging.path().join("node_modules/app/package.json"),
            br#"{"name":"app","version":"9.0.0"}"#,
        )
        .expect("write the changed-version fixture");
        assert!(reviewed.verify_installed(staging.path(), &spec()).is_err());
        Ok(())
    }

    #[test]
    fn materialized_tree_refuses_unreviewed_packages_and_redirected_directories() -> Result<()> {
        let staging = tempfile::tempdir()?;
        let reviewed = NpmLock::parse(&serde_json::to_vec(&lock())?, &spec())?;
        materialize_fixture(staging.path(), &reviewed)?;
        let extra = staging.path().join("node_modules/unreviewed");
        std::fs::create_dir(&extra)?;
        std::fs::write(
            extra.join("package.json"),
            br#"{"name":"unreviewed","version":"1.0.0"}"#,
        )
        .expect("write the unreviewed-package fixture");
        assert!(reviewed.verify_installed(staging.path(), &spec()).is_err());
        std::fs::remove_dir_all(&extra)?;
        let installed = staging.path().join("node_modules/app");
        std::fs::rename(&installed, staging.path().join("saved-app"))?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(staging.path().join("saved-app"), &installed)?;
        assert!(reviewed.verify_installed(staging.path(), &spec()).is_err());
        Ok(())
    }

    #[test]
    fn filesystem_failure_cannot_become_an_absent_optional_inventory() -> Result<()> {
        let staging = tempfile::tempdir()?;
        let bytes = serde_json::to_vec(&lock())?;
        let reviewed = NpmLock::parse(&bytes, &spec())?;
        materialize_fixture(staging.path(), &reviewed)?;
        let failed = staging.path().join("node_modules/app/node_modules");
        let error = reviewed
            .verify_installed_with(staging.path(), &spec(), &|path| {
                if path == failed {
                    Err(std::io::Error::other("nested inventory I/O failure"))
                } else {
                    std::fs::symlink_metadata(path)
                }
            })
            .expect_err("an I/O failure cannot be treated as an absent dependency directory");
        assert!(error.to_string().contains("nested inventory I/O failure"));
        Ok(())
    }

    #[test]
    fn metadata_reads_enforce_bounds_and_reject_special_files_without_blocking() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("metadata");
        std::fs::write(&path, b"12345678")?;
        assert_eq!(read_metadata(&path, 8)?, b"12345678");
        assert!(read_metadata(&path, 4).is_err());
        assert!(read_metadata(directory.path(), 8).is_err());
        #[cfg(unix)]
        {
            let link = directory.path().join("link");
            std::os::unix::fs::symlink(&path, &link)?;
            assert!(read_metadata(&link, 8).is_err());
            let pipe_directory = tempfile::tempdir_in("/var/tmp")?;
            let pipe = pipe_directory.path().join("pipe");
            nix::unistd::mkfifo(
                &pipe,
                nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
            )
            .expect("create the native FIFO fixture");
            assert!(read_metadata(&pipe, 8).is_err());
        }
        Ok(())
    }
}
