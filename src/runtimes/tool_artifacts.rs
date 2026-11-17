//! Bounded process and artifact ownership shared by reviewed registry installs.

use anyhow::{Context, Result, ensure};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;

use super::package_manager::{ManagedRuntime, ReviewedTool};
use crate::core::security::package_review::PackageReview;
use crate::core::security::vulnerability::VulnerabilitySource;

pub(crate) fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    crate::core::security::npm::read_metadata(path, limit)
}

pub(crate) fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(crate) fn run(mut command: Command, phase: &str, build: bool) -> Result<Vec<u8>> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let child = command
        .spawn()
        .with_context(|| format!("Failed to start {phase}"))?;
    struct ChildOwner {
        child: std::process::Child,
        reaped: bool,
    }
    impl ChildOwner {
        fn stop_group(&self) {
            #[cfg(unix)]
            if let Ok(pid) = i32::try_from(self.child.id()) {
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
        }
        fn stop(&mut self) {
            if self.reaped {
                return;
            }
            self.stop_group();
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.reaped = true;
        }
    }
    impl Drop for ChildOwner {
        fn drop(&mut self) {
            self.stop();
        }
    }
    let mut owner = ChildOwner {
        child,
        reaped: false,
    };
    let child = &mut owner.child;
    let stdout = child.stdout.take().context("Missing manager stdout")?;
    let stderr = child.stderr.take().context("Missing manager stderr")?;
    #[cfg(unix)]
    {
        use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
        fcntl_setfl(&stdout, fcntl_getfl(&stdout)? | OFlags::NONBLOCK)?;
        fcntl_setfl(&stderr, fcntl_getfl(&stderr)? | OFlags::NONBLOCK)?;
    }
    let exceeded = AtomicBool::new(false);
    let completed = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(if build { 3600 } else { 600 });
    std::thread::scope(|scope| {
        let bounded =
            |mut reader: Box<dyn std::io::Read + Send>, limit: usize| -> Result<Vec<u8>> {
                let mut bytes = Vec::new();
                let mut buffer = [0u8; 16384];
                loop {
                    match reader.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(count) => {
                            bytes.extend_from_slice(&buffer[..count]);
                            if bytes.len() > limit {
                                exceeded.store(true, Ordering::Release);
                                break;
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if completed.load(Ordering::Acquire) || Instant::now() >= deadline {
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => {
                            exceeded.store(true, Ordering::Release);
                            return Err(error.into());
                        }
                    }
                }
                Ok(bytes)
            };
        let out = scope.spawn(move || bounded(Box::new(stdout), 32 * 1024 * 1024));
        let err = scope.spawn(move || bounded(Box::new(stderr), 1024 * 1024));
        let status = loop {
            if exceeded.load(Ordering::Acquire) || Instant::now() >= deadline {
                owner.stop();
                break Err(anyhow::anyhow!(
                    "{phase} exceeded its output or time allowance"
                ));
            }
            #[cfg(unix)]
            {
                use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};
                let observed = Pid::from_raw(i32::try_from(owner.child.id())?)
                    .context("Invalid manager process ID")?;
                match waitid(
                    WaitId::Pid(observed),
                    WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
                ) {
                    Ok(Some(_)) => {
                        // Retain the unreaped leader until its process group is stopped.
                        owner.stop_group();
                        let status = owner.child.wait();
                        owner.reaped = status.is_ok();
                        break status.map_err(Into::into);
                    }
                    Ok(None) => {}
                    Err(error) if error == rustix::io::Errno::INTR => continue,
                    Err(error) => {
                        owner.stop();
                        break Err(error.into());
                    }
                }
            }
            #[cfg(not(unix))]
            match owner.child.try_wait() {
                Ok(Some(status)) => {
                    owner.reaped = true;
                    break Ok(status);
                }
                Ok(None) => {}
                Err(error) => {
                    owner.stop();
                    break Err(error.into());
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        completed.store(true, Ordering::Release);
        let out = out
            .join()
            .map_err(|_| anyhow::anyhow!("Manager stdout reader failed"))??;
        let err = err
            .join()
            .map_err(|_| anyhow::anyhow!("Manager stderr reader failed"))??;
        ensure!(
            !exceeded.load(Ordering::Acquire),
            "{phase} exceeded the bounded output allowance"
        );
        ensure!(Instant::now() < deadline, "{phase} exceeded its deadline");
        ensure!(
            status?.success(),
            "{phase} failed: {}",
            crate::cli::style::sanitize_terminal_text(&String::from_utf8_lossy(&err))
                .chars()
                .take(2000)
                .collect::<String>()
        );
        Ok(out)
    })
}

pub(crate) fn tree(root: &Path) -> Result<String> {
    let canonical = root.canonicalize()?;
    let mut pending = vec![root.to_path_buf()];
    let mut rows = BTreeMap::new();
    let mut total = 0u64;
    let mut entries = 0usize;
    while let Some(directory) = pending.pop() {
        ensure!(
            fs::symlink_metadata(&directory)?.is_dir(),
            "Registry source is not a real directory"
        );
        for child in fs::read_dir(&directory)? {
            let path = child?.path();
            entries += 1;
            ensure!(
                entries <= 200_000 && pending.len() <= 200_000,
                "Registry source exceeds its entry bound"
            );
            let relative = path.strip_prefix(root)?.to_path_buf();
            let metadata = fs::symlink_metadata(&path)?;
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt as _;
                metadata.permissions().mode() & 0o777
            };
            #[cfg(not(unix))]
            let mode = 0;
            if metadata.is_dir() {
                rows.insert(relative, ("dir", mode, String::new()));
                pending.push(path);
            } else if metadata.is_symlink() {
                ensure!(
                    path.canonicalize()?.starts_with(&canonical),
                    "Registry source link escapes its owned tree"
                );
                rows.insert(
                    relative,
                    (
                        "link",
                        mode,
                        fs::read_link(path)?
                            .to_str()
                            .context("Registry link is not UTF-8")?
                            .to_owned(),
                    ),
                );
            } else {
                ensure!(
                    metadata.is_file() && metadata.len() <= 1024 * 1024 * 1024,
                    "Registry source contains an unbounded or special file"
                );
                let mut options = fs::OpenOptions::new();
                options.read(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt as _;
                    options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
                }
                let mut file = options.open(&path)?;
                let before = file.metadata()?;
                ensure!(before.is_file(), "Registry content changed type");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt as _;
                    ensure!(
                        before.dev() == metadata.dev() && before.ino() == metadata.ino(),
                        "Registry content was replaced while opening"
                    );
                }
                let mut digest = Sha256::new();
                let mut count = 0u64;
                let mut buffer = vec![0u8; 65536].into_boxed_slice();
                loop {
                    let size = file.read(&mut buffer)?;
                    if size == 0 {
                        break;
                    }
                    count += size as u64;
                    total += size as u64;
                    ensure!(
                        total <= 2 * 1024 * 1024 * 1024 && count <= 1024 * 1024 * 1024,
                        "Registry source exceeds its byte allowance"
                    );
                    digest.update(&buffer[..size]);
                }
                let after = file.metadata()?;
                ensure!(
                    count == before.len()
                        && before.len() == after.len()
                        && before.modified()? == after.modified()?,
                    "Registry source changed while hashing"
                );
                rows.insert(relative, ("file", mode, hex::encode(digest.finalize())));
            }
        }
    }
    Ok(hash(&serde_json::to_vec(&rows)?))
}

pub(crate) fn context(
    manager: &str,
    request: &str,
    destination: &Path,
    runtime: &ManagedRuntime,
    graph: &serde_json::Value,
    gaps: &[String],
) -> Result<String> {
    Ok(serde_json::to_string(&(
        "omg-registry-tool-v1",
        manager,
        request,
        destination,
        runtime.identity_context()?,
        graph,
        gaps,
        crate::core::security::policy::SecurityPolicy::load_current()?,
        nix::unistd::getuid().as_raw(),
        nix::unistd::geteuid().as_raw(),
        crate::cli::tool::active_security_overrides(manager, request),
    ))?)
}

pub(crate) struct InstalledReview {
    manager: String,
    request: String,
    runtime: ManagedRuntime,
    review: PackageReview,
    source: Arc<dyn VulnerabilitySource>,
    overrides: Vec<&'static str>,
    output: String,
    receipt: String,
}
impl InstalledReview {
    pub(crate) fn finish(
        manager: &str,
        request: &str,
        prefix: &Path,
        runtime: ManagedRuntime,
        review: PackageReview,
        source: Arc<dyn VulnerabilitySource>,
        graph: &serde_json::Value,
    ) -> Result<Box<dyn ReviewedTool>> {
        runtime.verify()?;
        review.verify(source.as_ref())?;
        let overrides = crate::cli::tool::active_security_overrides(manager, request);
        let receipt = serde_json::to_vec_pretty(
            &serde_json::json!({"schema_version":1,"manager":manager,"request":request,"runtime":runtime.identity_context()?,"graph":graph,"overrides":overrides,"review_id":review.id(),"risk_accepted":review.accepted(),
            "assessments":review.assessments().iter().map(|row|serde_json::json!({"name":row.package.name,"version":row.package.version,"origin":row.package.origin,"coverage":format!("{:?}",row.coverage),"findings":row.findings})).collect::<Vec<_>>()}),
        )?;
        crate::core::safe_ops::atomic_write_file_sync(
            prefix.join(".omg-package-advisory-review.json"),
            &receipt,
        )?;
        crate::cli::tool::write_security_receipt(prefix, manager, request)?;
        ensure!(
            prefix.join("bin").is_dir(),
            "Reviewed tool produced no executable directory"
        );
        let output = tree(prefix)?;
        Ok(Box::new(Self {
            manager: manager.into(),
            request: request.into(),
            runtime,
            review,
            source,
            overrides,
            output,
            receipt: hash(&receipt),
        }))
    }
}
impl ReviewedTool for InstalledReview {
    fn verify(&self, prefix: &Path) -> Result<()> {
        self.runtime.verify()?;
        self.review.verify(self.source.as_ref())?;
        ensure!(
            crate::cli::tool::active_security_overrides(&self.manager, &self.request)
                == self.overrides,
            "Registry security choices changed before activation"
        );
        ensure!(
            hash(&read(
                &prefix.join(".omg-package-advisory-review.json"),
                16 * 1024 * 1024
            )?) == self.receipt,
            "Registry advisory receipt changed before activation"
        );
        ensure!(
            tree(prefix)? == self.output,
            "Reviewed tool content changed before activation"
        );
        Ok(())
    }
}

pub(crate) fn scoped_future<T: Send>(
    future: impl std::future::Future<Output = Result<T>> + Send,
) -> Result<T> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(future)
            })
            .join()
            .map_err(|_| anyhow::anyhow!("Registry metadata worker failed"))?
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::core::security::scan::{AdvisoryProvenance, FindingApplicability, Vulnerability};
    use crate::core::security::vulnerability::{
        AssessmentUse, PackageAssessment, PackageCoverage, VulnerabilityError,
    };
    use crate::package_managers::types::SecurityPackage;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::path::PathBuf;

    #[derive(Default)]
    struct TransitiveFinding {
        seen: std::sync::Mutex<Vec<SecurityPackage>>,
        bootstrap_vulnerable: bool,
        no_findings: bool,
    }
    impl VulnerabilitySource for TransitiveFinding {
        fn assess_packages<'a>(
            &'a self,
            packages: &'a [SecurityPackage],
            _: AssessmentUse,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = std::result::Result<Vec<PackageAssessment>, VulnerabilityError>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                *self.seen.lock().unwrap() = packages.to_vec();
                Ok(packages.iter().map(|package| PackageAssessment {
                    package: package.clone(),
                    coverage: PackageCoverage::Assessed { provenance: AdvisoryProvenance::Osv { ecosystem: match package.origin { crate::package_managers::types::SecurityOrigin::CargoRegistry => "crates.io", crate::package_managers::types::SecurityOrigin::GoModule => "Go", _ => "PyPI" }.into() } },
                    findings: if !self.no_findings && (package.name.ends_with("dependency") || (self.bootstrap_vulnerable && package.name == "pip")) { vec![Vulnerability { applicability: FindingApplicability::Applicable, id:"CVE-2021-23337".into(), summary:"Controlled transitive advisory fixture".into(), score:None, advisory_severity:None, native_advisory:None, affected_installed:vec![] }] } else { vec![] }
                }).collect())
            })
        }
    }

    fn quote(path: &Path) -> String {
        format!("'{}'", path.to_str().unwrap().replace('\'', "'\\''"))
    }
    fn fixture(
        runtime: &str,
        command: &str,
        script: &str,
    ) -> Result<(tempfile::TempDir, PathBuf, PathBuf)> {
        let owner = tempfile::tempdir()?;
        let data = owner.path().join("fixture");
        fs::create_dir(&data)?;
        let root = owner.path().join("versions").join(runtime).join("1.78.0");
        fs::create_dir_all(root.join("bin"))?;
        let executable = root.join("bin").join(command);
        fs::write(&executable, script.replace("@FIXTURE@", &quote(&data)))?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))?;
        if runtime == "rust" {
            fs::write(root.join("bin/rustc"), b"#!/bin/sh\nexit 0\n")?;
            fs::set_permissions(root.join("bin/rustc"), fs::Permissions::from_mode(0o755))?;
        }
        super::super::security::fixture_prepare(runtime, "1.78.0", &root, &root)?;
        symlink("1.78.0", root.parent().unwrap().join("current"))?;
        fs::create_dir_all(owner.path().join("tools"))?;
        let stage = owner.path().join("stage");
        fs::create_dir(&stage)?;
        Ok((owner, data, stage))
    }
    fn previous(owner: &Path, manager: &str) -> Result<PathBuf> {
        let destination = owner.join("tools").join(manager).join("fixture-tool");
        fs::create_dir_all(destination.join("bin"))?;
        fs::write(
            destination.join("bin/fixture-tool"),
            b"previous reviewed tool",
        )?;
        Ok(destination)
    }
    fn assert_refused(
        result: Result<Box<dyn ReviewedTool>>,
        data: &Path,
        destination: &Path,
        source: &TransitiveFinding,
        phases: &str,
    ) -> Result<()> {
        let error = match result {
            Ok(_) => anyhow::bail!("Disclosed transitive CVE was installed without consent"),
            Err(error) => format!("{error:#}"),
        };
        ensure!(
            error.contains("terminal") || error.contains("review") || error.contains("accept"),
            "Unexpected pre-admission failure: {error}"
        );
        assert_eq!(fs::read_to_string(data.join("phases"))?, phases);
        assert_eq!(
            fs::read(destination.join("bin/fixture-tool"))?,
            b"previous reviewed tool"
        );
        let seen = source.seen.lock().unwrap();
        assert_eq!(
            seen.len(),
            2,
            "Full transitive graph must reach the real advisory decision"
        );
        assert!(
            seen.iter()
                .any(|package| package.name.ends_with("dependency"))
        );
        Ok(())
    }
    fn crate_archive(
        data: &Path,
        name: &str,
        version: &str,
        files: &[(&str, Vec<u8>)],
    ) -> Result<String> {
        let writer = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let mut archive = tar::Builder::new(writer);
        for (path, bytes) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(
                &mut header,
                format!("{name}-{version}/{path}"),
                bytes.as_slice(),
            )?;
        }
        let bytes = archive.into_inner()?.finish()?;
        fs::write(data.join(format!("{name}-{version}.crate")), &bytes)?;
        let source = data.join(format!("{name}-{version}"));
        for (path, bytes) in files {
            fs::create_dir_all(source.join(path).parent().unwrap())?;
            fs::write(source.join(path), bytes)?;
        }
        Ok(hash(&bytes))
    }

    const CARGO: &str = r#"#!/bin/sh
set -eu
fixture=@FIXTURE@
printf '%s\n' "$1" >> "$fixture/phases"
previous=''
for argument in "$@"; do
  if [ "$previous" = '--manifest-path' ]; then manifest="$argument"; fi
  if [ "$previous" = '--root' ]; then destination="$argument"; fi
  previous="$argument"
done
case "$1" in
metadata)
  mkdir -p "$CARGO_HOME/registry/cache/public" "$CARGO_HOME/registry/src/public"
  cp "$fixture/fixture-tool-1.0.0.crate" "$fixture/fixture-dependency-2.3.4.crate" "$CARGO_HOME/registry/cache/public/"
  for name in fixture-tool-1.0.0 fixture-dependency-2.3.4; do
    if [ ! -d "$CARGO_HOME/registry/src/public/$name" ]; then cp -R "$fixture/$name" "$CARGO_HOME/registry/src/public/$name"; fi
  done
  case "$manifest" in
  */plan/Cargo.toml)
    cp "$fixture/seed.lock" "$(dirname "$manifest")/Cargo.lock"
    printf '{"packages":[],"resolve":{"root":"plan-id","nodes":[{"id":"plan-id","dependencies":[]}]}}'
    ;;
  *) printf '{"packages":[{"name":"fixture-tool","version":"1.0.0","manifest_path":"%s"},{"name":"fixture-dependency","version":"2.3.4","manifest_path":"%s/registry/src/public/fixture-dependency-2.3.4/Cargo.toml"}]}' "$manifest" "$CARGO_HOME" ;;
  esac
  ;;
fetch) ;;
install)
  mkdir -p "$fixture/MATERIALIZED" "$destination/bin"
  printf '#!/bin/sh\necho reviewed-tool-success\n' > "$destination/bin/fixture-tool"
  chmod 755 "$destination/bin/fixture-tool"
  ;;
*) exit 91 ;;
esac
"#;
    #[test]
    fn cargo_transitive_cve_refusal_precedes_build_and_preserves_previous_tool() -> Result<()> {
        let name = "runtimes::tool_artifacts::tests::cargo_transitive_cve_refusal_precedes_build_and_preserves_previous_tool";
        if crate::core::testing::run_isolated_test(name) {
            return Ok(());
        }
        nix::unistd::setsid()?;
        let (owner, data, stage) = fixture("rust", "cargo", CARGO)?;
        let dep = crate_archive(
            &data,
            "fixture-dependency",
            "2.3.4",
            &[
                (
                    "Cargo.toml",
                    b"[package]\nname='fixture-dependency'\nversion='2.3.4'\n".to_vec(),
                ),
                ("src/lib.rs", b"pub fn dependency() {}".to_vec()),
            ],
        )?;
        let lock = format!(
            "version=3\n[[package]]\nname='fixture-tool'\nversion='1.0.0'\n[[package]]\nname='fixture-dependency'\nversion='2.3.4'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{dep}'\n"
        );
        let top = crate_archive(
            &data,
            "fixture-tool",
            "1.0.0",
            &[
                (
                    "Cargo.toml",
                    b"[package]\nname='fixture-tool'\nversion='1.0.0'\n".to_vec(),
                ),
                ("Cargo.lock", lock.into_bytes()),
                ("src/main.rs", b"fn main() {}".to_vec()),
            ],
        )?;
        fs::write(
            data.join("seed.lock"),
            format!(
                "[[package]]\nname='omg-admission-plan'\nversion='0.0.0'\ndependencies=['fixture-tool']\n[[package]]\nname='fixture-tool'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{top}'\n"
            ),
        )?;
        let destination = previous(owner.path(), "cargo")?;
        let source = Arc::new(TransitiveFinding::default());
        let result = super::super::cargo_tool::install_reviewed(
            "fixture-tool@1.0.0",
            &stage,
            &destination,
            &owner.path().join("tools"),
            source.clone(),
            &super::super::security::RuntimeSecurity::fixture(),
        );
        assert_refused(
            result,
            &data,
            &destination,
            &source,
            "metadata\nmetadata\nfetch\n",
        )?;
        assert!(!data.join("MATERIALIZED").exists());
        Ok(())
    }

    const GO: &str = r#"#!/bin/sh
set -eu
fixture=@FIXTURE@
printf '%s %s\n' "$1" "${2:-}" >> "$fixture/phases"
mkdir -p "$GOMODCACHE/root" "$GOMODCACHE/dependency"
if [ ! -f "$GOMODCACHE/root/go.mod" ]; then cp -R "$fixture/root/." "$GOMODCACHE/root/"; cp -R "$fixture/dependency/." "$GOMODCACHE/dependency/"; printf 'controlled archive' > "$GOMODCACHE/root.zip"; fi
case "$1 $2" in
'list -m') printf '{"Path":"example.com/tool","Version":"v1.2.3"}' ;;
'mod download')
  if [ "$4" = 'all' ]; then
    printf '{"Path":"example.com/dependency","Version":"v2.3.4","Dir":"%s/dependency","Sum":"%s","GoModSum":"h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}' "$GOMODCACHE" "$(cat "$fixture/dependency.sum")"
  else
    printf '{"Path":"example.com/tool","Version":"v1.2.3","Dir":"%s/root","Zip":"%s/root.zip","Sum":"%s","GoModSum":"h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}' "$GOMODCACHE" "$GOMODCACHE" "$(cat "$fixture/root.sum")"
  fi ;;
'mod edit') printf '{"Module":{"Path":"example.com/tool"},"Replace":[]}' ;;
'list -mod=readonly') printf '{"Path":"example.com/tool","Main":true}\n{"Path":"example.com/dependency","Version":"v2.3.4"}' ;;
'mod verify') ;;
'build -mod=readonly')
  previous=''
  for argument in "$@"; do
    if [ "$previous" = '-o' ]; then destination="$argument"; fi
    previous="$argument"
  done
  mkdir -p "$fixture/MATERIALIZED" "$(dirname "$destination")"
  printf '#!/bin/sh\necho reviewed-tool-success\n' > "$destination"
  chmod 755 "$destination"
  ;;
*) exit 92 ;;
esac
"#;
    fn go_source(data: &Path, directory: &str, module: &str, version: &str) -> Result<()> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let bytes = format!("module {module}\n\ngo 1.20\n");
        fs::create_dir(data.join(directory))?;
        fs::write(data.join(directory).join("go.mod"), &bytes)?;
        let row = format!("{}  {module}@{version}/go.mod\n", hash(bytes.as_bytes()));
        fs::write(
            data.join(format!("{directory}.sum")),
            format!("h1:{}", STANDARD.encode(Sha256::digest(row.as_bytes()))),
        )?;
        Ok(())
    }
    #[test]
    fn go_transitive_cve_refusal_precedes_build_and_uses_module_identity() -> Result<()> {
        let name = "runtimes::tool_artifacts::tests::go_transitive_cve_refusal_precedes_build_and_uses_module_identity";
        if crate::core::testing::run_isolated_test(name) {
            return Ok(());
        }
        nix::unistd::setsid()?;
        let (owner, data, stage) = fixture("go", "go", GO)?;
        go_source(&data, "root", "example.com/tool", "v1.2.3")?;
        go_source(&data, "dependency", "example.com/dependency", "v2.3.4")?;
        let destination = previous(owner.path(), "go")?;
        let source = Arc::new(TransitiveFinding::default());
        let result = super::super::go_tool::install_reviewed(
            "example.com/tool@v1.2.3",
            &stage,
            &destination,
            &owner.path().join("tools"),
            source.clone(),
            &super::super::security::RuntimeSecurity::fixture(),
        );
        assert_refused(
            result,
            &data,
            &destination,
            &source,
            "list -m\nmod download\nmod edit\nmod download\nlist -mod=readonly\nmod verify\n",
        )?;
        assert!(
            source
                .seen
                .lock()
                .unwrap()
                .iter()
                .all(|package| !package.name.contains("/cmd/"))
        );
        assert!(!data.join("MATERIALIZED").exists());
        Ok(())
    }

    const PYTHON: &str = r#"#!/bin/sh
set -eu
fixture=@FIXTURE@
previous=''; module=''; report=''; last=''
for argument in "$@"; do
  if [ "$previous" = '-m' ]; then module="$argument"; fi
  if [ "$previous" = '--report' ]; then report="$argument"; fi
  previous="$argument"; last="$argument"
done
case "$module" in
venv)
  printf 'venv\n' >> "$fixture/phases"
  mkdir -p "$last/bin" "$last/lib"
  cp "$0" "$last/bin/python"
  printf 'controlled managed base' > "$last/pyvenv.cfg"
  if [ -f "$fixture/bootstrap-metadata" ]; then
    mkdir -p "$last/lib/pythonfixture/site-packages/pip-24.0.dist-info"
    cp "$fixture/bootstrap-metadata" "$last/lib/pythonfixture/site-packages/pip-24.0.dist-info/METADATA"
  fi
  ;;
pip)
  if [ -n "$report" ]; then
    case "$report" in */frozen.json) printf 'offline-resolve\n' >> "$fixture/phases" ;; *) printf 'resolve\n' >> "$fixture/phases" ;; esac
    cp "$fixture/report.json" "$report"
  else
    printf 'install\n' >> "$fixture/phases"
    mkdir -p "$fixture/MATERIALIZED"
    prefix="$(dirname "$(dirname "$0")")"
    for name in fixture-tool fixture-dependency; do
      mkdir -p "$prefix/lib/pythonfixture/site-packages/$name-1.2.3.dist-info"
      cp "$fixture/$name.metadata" "$prefix/lib/pythonfixture/site-packages/$name-1.2.3.dist-info/METADATA"
    done
    printf '#!/bin/sh\necho reviewed-tool-success\n' > "$prefix/bin/fixture-tool"
    chmod 755 "$prefix/bin/fixture-tool"
  fi
  ;;
*) exit 93 ;;
esac
"#;
    #[test]
    fn pip_transitive_cve_refusal_precedes_wheel_fetch_and_install() -> Result<()> {
        let name = "runtimes::tool_artifacts::tests::pip_transitive_cve_refusal_precedes_wheel_fetch_and_install";
        if crate::core::testing::run_isolated_test(name) {
            return Ok(());
        }
        nix::unistd::setsid()?;
        let (owner, data, stage) = fixture("python", "python3", PYTHON)?;
        let item = |name: &str, requested: bool| serde_json::json!({"metadata":{"name":name,"version":"1.2.3"},"requested":requested,"download_info":{"url":format!("https://files.pythonhosted.org/packages/{name}-1.2.3-py3-none-any.whl"),"archive_info":{"hashes":{"sha256":"a".repeat(64)}}}});
        fs::write(
            data.join("report.json"),
            serde_json::to_vec(
                &serde_json::json!({"version":"1","install":[item("fixture-tool",true),item("fixture-dependency",false)]}),
            )?,
        )?;
        let destination = previous(owner.path(), "pip")?;
        let source = Arc::new(TransitiveFinding::default());
        let result = super::super::pip_tool::install_reviewed(
            "fixture-tool@1.2.3",
            &stage,
            &destination,
            &owner.path().join("tools"),
            source.clone(),
            &super::super::security::RuntimeSecurity::fixture(),
        );
        assert_refused(result, &data, &destination, &source, "venv\nresolve\n")?;
        assert!(!data.join("MATERIALIZED").exists());
        Ok(())
    }

    #[test]
    fn pip_bootstrap_cve_refusal_precedes_untrusted_metadata_resolution() -> Result<()> {
        let name = "runtimes::tool_artifacts::tests::pip_bootstrap_cve_refusal_precedes_untrusted_metadata_resolution";
        if crate::core::testing::run_isolated_test(name) {
            return Ok(());
        }
        nix::unistd::setsid()?;
        let (owner, data, stage) = fixture("python", "python3", PYTHON)?;
        fs::write(
            data.join("bootstrap-metadata"),
            b"Metadata-Version: 2.1\nName: pip\nVersion: 24.0\n\nControlled fixture\n",
        )?;
        let destination = previous(owner.path(), "pip")?;
        let source = Arc::new(TransitiveFinding {
            bootstrap_vulnerable: true,
            ..TransitiveFinding::default()
        });
        let result = super::super::pip_tool::install_reviewed(
            "fixture-tool@1.2.3",
            &stage,
            &destination,
            &owner.path().join("tools"),
            source.clone(),
            &super::super::security::RuntimeSecurity::fixture(),
        );
        assert!(
            result.is_err(),
            "Vulnerable bundled pip must require consent before it processes target metadata"
        );
        assert_eq!(fs::read_to_string(data.join("phases"))?, "venv\n");
        let seen = source.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].name, "pip");
        assert_eq!(seen[0].version, "24.0");
        assert_eq!(
            fs::read(destination.join("bin/fixture-tool"))?,
            b"previous reviewed tool"
        );
        Ok(())
    }

    #[test]
    fn tree_rejects_escaping_links_and_binds_root_payloads() -> Result<()> {
        let owner = tempfile::tempdir()?;
        let root = owner.path().join("prefix");
        fs::create_dir(&root)?;
        fs::write(root.join("payload"), b"reviewed")?;
        let before = tree(&root)?;
        fs::write(root.join("payload"), b"changed")?;
        assert_ne!(tree(&root)?, before);
        symlink("../outside", root.join("redirect"))?;
        fs::write(owner.path().join("outside"), b"external")?;
        assert!(tree(&root).is_err());
        Ok(())
    }

    #[test]
    fn manager_exit_stops_owned_background_children_before_returning() -> Result<()> {
        let owner = tempfile::tempdir()?;
        let marker = owner.path().join("late-write");
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            &format!(
                "(sleep 0.3; printf late > {}) & printf owned",
                quote(&marker)
            ),
        ]);
        let started = std::time::Instant::now();
        assert_eq!(run(command, "controlled manager", false)?, b"owned");
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        std::thread::sleep(std::time::Duration::from_millis(400));
        assert!(
            !marker.exists(),
            "Manager descendants must not retain access to staging after completion"
        );
        Ok(())
    }

    fn assert_successful_publication(
        capability: &dyn ReviewedTool,
        stage: &Path,
        destination: &Path,
        data: &Path,
        source: &TransitiveFinding,
        phases: &str,
    ) -> Result<()> {
        capability.verify(stage)?;
        assert_eq!(fs::read_to_string(data.join("phases"))?, phases);
        let backup = destination.with_extension("previous");
        fs::rename(destination, &backup)?;
        fs::rename(stage, destination)?;
        assert!(!stage.exists());
        capability.verify(destination)?;
        assert_eq!(
            fs::read(backup.join("bin/fixture-tool"))?,
            b"previous reviewed tool"
        );
        let output = Command::new(destination.join("bin/fixture-tool")).output()?;
        ensure!(
            output.status.success(),
            "Published tool failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"reviewed-tool-success\n");
        let receipt: serde_json::Value = serde_json::from_slice(&read(
            &destination.join(".omg-package-advisory-review.json"),
            1024 * 1024,
        )?)?;
        assert_eq!(receipt["risk_accepted"], false);
        assert_eq!(
            receipt["assessments"].as_array().unwrap().len(),
            source.seen.lock().unwrap().len()
        );
        assert!(destination.join(".omg-security-receipt.json").is_file());
        fs::write(
            destination.join("unreviewed-root-payload"),
            b"changed after publication",
        )?;
        assert!(
            capability.verify(destination).is_err(),
            "Complete published prefix must remain bound, including root payloads"
        );
        Ok(())
    }

    #[test]
    fn cargo_clean_full_owner_builds_and_binds_published_payload() -> Result<()> {
        let (owner, data, stage) = fixture("rust", "cargo", CARGO)?;
        let dep = crate_archive(
            &data,
            "fixture-dependency",
            "2.3.4",
            &[
                (
                    "Cargo.toml",
                    b"[package]\nname='fixture-dependency'\nversion='2.3.4'\n".to_vec(),
                ),
                ("src/lib.rs", b"pub fn dependency() {}".to_vec()),
            ],
        )?;
        let lock = format!(
            "version=3\n[[package]]\nname='fixture-tool'\nversion='1.0.0'\n[[package]]\nname='fixture-dependency'\nversion='2.3.4'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{dep}'\n"
        );
        let top = crate_archive(
            &data,
            "fixture-tool",
            "1.0.0",
            &[
                (
                    "Cargo.toml",
                    b"[package]\nname='fixture-tool'\nversion='1.0.0'\n".to_vec(),
                ),
                ("Cargo.lock", lock.into_bytes()),
                ("src/main.rs", b"fn main() {}".to_vec()),
            ],
        )?;
        fs::write(
            data.join("seed.lock"),
            format!(
                "[[package]]\nname='omg-admission-plan'\nversion='0.0.0'\ndependencies=['fixture-tool']\n[[package]]\nname='fixture-tool'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{top}'\n"
            ),
        )?;
        let destination = previous(owner.path(), "cargo")?;
        let source = Arc::new(TransitiveFinding {
            no_findings: true,
            ..TransitiveFinding::default()
        });
        let capability = super::super::cargo_tool::install_reviewed(
            "fixture-tool@1.0.0",
            &stage,
            &destination,
            &owner.path().join("tools"),
            source.clone(),
            &super::super::security::RuntimeSecurity::fixture(),
        )?;
        assert!(data.join("MATERIALIZED").is_dir());
        assert_successful_publication(
            capability.as_ref(),
            &stage,
            &destination,
            &data,
            &source,
            "metadata\nmetadata\nfetch\ninstall\n",
        )
    }

    #[test]
    fn go_clean_full_owner_builds_and_binds_published_payload() -> Result<()> {
        let (owner, data, stage) = fixture("go", "go", GO)?;
        go_source(&data, "root", "example.com/tool", "v1.2.3")?;
        go_source(&data, "dependency", "example.com/dependency", "v2.3.4")?;
        let destination = previous(owner.path(), "go")?;
        let source = Arc::new(TransitiveFinding {
            no_findings: true,
            ..TransitiveFinding::default()
        });
        let capability = super::super::go_tool::install_reviewed(
            "example.com/tool@v1.2.3",
            &stage,
            &destination,
            &owner.path().join("tools"),
            source.clone(),
            &super::super::security::RuntimeSecurity::fixture(),
        )?;
        assert!(data.join("MATERIALIZED").is_dir());
        assert_successful_publication(
            capability.as_ref(),
            &stage,
            &destination,
            &data,
            &source,
            "list -m\nmod download\nmod edit\nmod download\nlist -mod=readonly\nmod verify\nbuild -mod=readonly\n",
        )
    }

    struct FixtureWheels {
        bodies: BTreeMap<String, Vec<u8>>,
        corrupt: bool,
        downloads: std::sync::Mutex<Vec<String>>,
    }
    impl super::super::pip_tool::WheelDownloader for FixtureWheels {
        fn download(&self, url: &str, path: &Path) -> Result<()> {
            use std::io::Write as _;
            let body = self
                .bodies
                .get(url)
                .context("Unrequested wheel transport route")?;
            self.downloads.lock().unwrap().push(url.to_owned());
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?;
            output.write_all(body)?;
            if self.corrupt {
                output.write_all(b"corrupt-transport-bytes")?;
            }
            output.sync_all()?;
            Ok(())
        }
    }
    fn pip_wheels(data: &Path, corrupt: bool) -> Result<FixtureWheels> {
        use std::io::Write as _;
        let mut bodies = BTreeMap::new();
        let mut rows = Vec::new();
        for name in ["fixture-tool", "fixture-dependency"] {
            let distribution = name.replace('-', "_");
            let metadata = format!("Metadata-Version: 2.1\nName: {name}\nVersion: 1.2.3\n\n");
            fs::write(data.join(format!("{name}.metadata")), &metadata)?;
            let mut wheel = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            wheel.start_file(
                format!("{distribution}-1.2.3.dist-info/METADATA"),
                zip::write::SimpleFileOptions::default(),
            )?;
            wheel.write_all(metadata.as_bytes())?;
            let bytes = wheel.finish()?.into_inner();
            let url = format!(
                "https://files.pythonhosted.org/packages/{distribution}-1.2.3-py3-none-any.whl"
            );
            rows.push(serde_json::json!({"metadata":{"name":name,"version":"1.2.3"},"requested":name=="fixture-tool","download_info":{"url":url,"archive_info":{"hashes":{"sha256":hash(&bytes)}}}}));
            bodies.insert(url, bytes);
        }
        fs::write(
            data.join("report.json"),
            serde_json::to_vec(&serde_json::json!({"version":"1","install":rows}))?,
        )?;
        Ok(FixtureWheels {
            bodies,
            corrupt,
            downloads: std::sync::Mutex::new(Vec::new()),
        })
    }
    #[test]
    fn pip_clean_full_owner_installs_and_binds_published_payload() -> Result<()> {
        let (owner, data, stage) = fixture("python", "python3", PYTHON)?;
        let wheels = pip_wheels(&data, false)?;
        let destination = previous(owner.path(), "pip")?;
        let source = Arc::new(TransitiveFinding {
            no_findings: true,
            ..TransitiveFinding::default()
        });
        let capability = super::super::pip_tool::install_reviewed_with_downloader(
            "fixture-tool@1.2.3",
            &stage,
            &destination,
            &owner.path().join("tools"),
            source.clone(),
            &super::super::security::RuntimeSecurity::fixture(),
            &wheels,
        )?;
        assert_eq!(wheels.downloads.lock().unwrap().len(), 2);
        assert!(data.join("MATERIALIZED").is_dir());
        assert_successful_publication(
            capability.as_ref(),
            &stage,
            &destination,
            &data,
            &source,
            "venv\nresolve\noffline-resolve\ninstall\n",
        )
    }
    #[test]
    fn pip_corrupt_transport_is_refused_before_frozen_install_and_preserves_prior_tool()
    -> Result<()> {
        let (owner, data, stage) = fixture("python", "python3", PYTHON)?;
        let wheels = pip_wheels(&data, true)?;
        let destination = previous(owner.path(), "pip")?;
        let source = Arc::new(TransitiveFinding {
            no_findings: true,
            ..TransitiveFinding::default()
        });
        let result = super::super::pip_tool::install_reviewed_with_downloader(
            "fixture-tool@1.2.3",
            &stage,
            &destination,
            &owner.path().join("tools"),
            source,
            &super::super::security::RuntimeSecurity::fixture(),
            &wheels,
        );
        let error = match result {
            Ok(_) => anyhow::bail!("Corrupt wheel was admitted"),
            Err(error) => format!("{error:#}"),
        };
        assert!(error.contains("differs from its reviewed hash"), "{error}");
        assert_eq!(fs::read_to_string(data.join("phases"))?, "venv\nresolve\n");
        assert_eq!(wheels.downloads.lock().unwrap().len(), 1);
        assert!(!data.join("MATERIALIZED").exists());
        assert_eq!(
            fs::read(destination.join("bin/fixture-tool"))?,
            b"previous reviewed tool"
        );
        Ok(())
    }
}
