#![cfg(all(target_os = "linux", feature = "fedora"))]

use anyhow::{Context, Result};
use omg_lib::package_managers::{DnfPackageManager, PackageManager};

pub mod common;
pub mod platform_semantics;

use platform_semantics::{assert_no_arch_terms, assert_no_debian_terms, assert_no_macos_terms};

/// Compare the selected installed identities against RPM's own name/arch/EVR
/// records. Keep duplicates so multilib and install-only versions cannot vanish.
fn assert_installed_rpm_selection(
    installed: &[omg_lib::core::Package],
    selection: &str,
) -> Result<()> {
    let output = std::process::Command::new("/usr/bin/rpm")
        .args([
            "-q",
            "--queryformat",
            "%{NAME}\t%{ARCH}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\n",
            selection,
        ])
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "native RPM selection {selection} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut expected = Vec::new();
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let fields: Vec<_> = line.split('\t').collect();
        anyhow::ensure!(
            fields.len() == 5
                && fields[0] == selection
                && !fields[1].is_empty()
                && !fields[3].is_empty()
                && !fields[4].is_empty(),
            "invalid native RPM selection record: {line:?}"
        );
        let epoch: u32 = fields[2].parse()?;
        let version = if epoch == 0 {
            format!("{}-{}", fields[3], fields[4])
        } else {
            format!("{epoch}:{}-{}", fields[3], fields[4])
        };
        expected.push((format!("{}.{}", fields[0], fields[1]), version, true));
    }
    anyhow::ensure!(
        !expected.is_empty(),
        "native RPM selection must be installed"
    );
    let mut actual: Vec<_> = installed
        .iter()
        .filter(|package| {
            package.name == selection
                || package
                    .name
                    .rsplit_once('.')
                    .is_some_and(|(name, _)| name == selection)
        })
        .map(|package| {
            (
                package.name.clone(),
                package.version.to_string(),
                package.installed,
            )
        })
        .collect();
    actual.sort();
    expected.sort();
    anyhow::ensure!(
        actual == expected,
        "listed RPM selection differs for {selection}: actual={actual:?}, native={expected:?}"
    );
    Ok(())
}

mod dnf_integration {
    use super::*;

    #[test]
    fn native_daemon_starts_and_searches_without_installed_inventory_changes() -> Result<()> {
        use omg_lib::daemon::protocol::{Request, Response, ResponseResult};
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;
        use std::os::unix::net::UnixStream;
        use std::time::{Duration, Instant};

        anyhow::ensure!(
            cfg!(debug_assertions),
            "native daemon fixture requires a debug binary for persistent-state isolation"
        );

        struct NativeDaemon(std::process::Child);
        impl Drop for NativeDaemon {
            fn drop(&mut self) {
                if let Err(error) = self.0.kill()
                    && error.kind() != std::io::ErrorKind::InvalidInput
                {
                    eprintln!("native daemon cleanup kill failed: {error}");
                }
                if let Err(error) = self.0.wait() {
                    eprintln!("native daemon cleanup wait failed: {error}");
                }
            }
        }

        let rpm_inventory = || -> Result<Vec<u8>> {
            let output = std::process::Command::new("/usr/bin/rpm")
                .args(["-qa", "--queryformat", "%{NEVRA}\\n"])
                .output()?;
            anyhow::ensure!(output.status.success(), "native RPM inventory failed");
            Ok(output.stdout)
        };
        let before = rpm_inventory()?;
        let native = std::process::Command::new("/usr/bin/rpm")
            .args([
                "-q",
                "bash",
                "--queryformat",
                "%{NAME}.%{ARCH}\t%{EPOCHNUM}\t%{VERSION}-%{RELEASE}",
            ])
            .output()?;
        anyhow::ensure!(native.status.success(), "native bash fixture missing");
        let native = std::str::from_utf8(&native.stdout)?;
        let fields: Vec<_> = native.split('\t').collect();
        anyhow::ensure!(fields.len() == 3, "unexpected native bash identity");
        let version = if fields[1] == "0" {
            fields[2].to_string()
        } else {
            format!("{}:{}", fields[1], fields[2])
        };
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let data_dir = directory.path().join("data");
        std::fs::create_dir(&data_dir)?;
        std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o700))?;
        let socket = directory.path().join("omg.sock");
        let log_path = directory.path().join("daemon.log");
        let log = std::fs::File::create(&log_path)?;
        let mut child = NativeDaemon(
            std::process::Command::new(assert_cmd::cargo::cargo_bin!("omgd"))
                .arg("--socket")
                .arg(&socket)
                .env("OMG_TEST_MODE", "0")
                .env("OMG_NATIVE_TEST_DATA_DIR", "1")
                .env("OMG_DATA_DIR", &data_dir)
                .env("OMG_DAEMON_DATA_DIR", &data_dir)
                .env("OMG_DISABLE_TELEMETRY", "1")
                .stdout(log.try_clone()?)
                .stderr(log)
                .spawn()?,
        );
        let outcome = (|| -> Result<()> {
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut stream = loop {
                anyhow::ensure!(
                    child.0.try_wait()?.is_none(),
                    "native daemon exited before serving its catalogue"
                );
                if let Ok(stream) = UnixStream::connect(&socket) {
                    break stream;
                }
                anyhow::ensure!(
                    Instant::now() < deadline,
                    "native daemon startup exceeded deadline"
                );
                std::thread::sleep(Duration::from_millis(100));
            };
            stream.set_read_timeout(Some(Duration::from_secs(10)))?;
            stream.set_write_timeout(Some(Duration::from_secs(10)))?;
            for request in [
                Request::Ping { id: 1 },
                Request::Search {
                    id: 2,
                    query: fields[0].into(),
                    limit: Some(10),
                },
            ] {
                let expected_id = request.id();
                let frame = omg_lib::daemon::protocol::encode_frame(&request)?;
                stream.write_all(&u32::try_from(frame.len())?.to_be_bytes())?;
                stream.write_all(&frame)?;
                let frame = omg_lib::daemon::protocol::read_frame(&mut stream)?;
                let (_, payload) = omg_lib::daemon::protocol::split_frame(&frame)?;
                let response: Response = bitcode::deserialize(payload)?;
                match response {
                    Response::Success {
                        id: 1,
                        result: ResponseResult::Ping(message),
                    } if expected_id == 1 => {
                        anyhow::ensure!(message == "pong", "native daemon ping mismatch");
                    }
                    Response::Success {
                        id: 2,
                        result: ResponseResult::Search(search),
                    } if expected_id == 2 => anyhow::ensure!(
                        search
                            .packages
                            .iter()
                            .any(|package| package.name == fields[0] && package.version == version),
                        "native daemon search differs from installed RPM identity"
                    ),
                    other => anyhow::bail!("unexpected native daemon response: {other:?}"),
                }
            }
            Ok(())
        })();
        drop(child);
        outcome.with_context(|| {
            format!(
                "native daemon startup log:\n{}",
                std::fs::read_to_string(&log_path)
                    .unwrap_or_else(|error| format!("log unreadable: {error}"))
            )
        })?;
        anyhow::ensure!(
            rpm_inventory()? == before,
            "native daemon queries changed installed RPM inventory"
        );
        Ok(())
    }

    #[test]
    fn native_catalog_observation_survives_readonly_rpm_and_dnf_queries() -> Result<()> {
        let manager = DnfPackageManager::new();
        let observed = manager
            .installed_catalog_observation()?
            .context("native SQLite observation missing")?;
        anyhow::ensure!(
            observed.is_current()?,
            "new native observation is already stale"
        );
        for (program, arguments) in [
            ("/usr/bin/rpm", vec!["-q", "bash"]),
            ("/usr/bin/dnf", vec!["repoquery", "--available", "bash"]),
        ] {
            let output = std::process::Command::new(program)
                .args(arguments)
                .output()?;
            anyhow::ensure!(
                output.status.success(),
                "read-only native query failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            anyhow::ensure!(
                observed.is_current()?,
                "read-only {program} query invalidated unchanged installed RPM inventory"
            );
        }
        Ok(())
    }

    #[test]
    fn native_catalog_observation_survives_ordinary_user_readonly_wal() -> Result<()> {
        use std::os::unix::fs::PermissionsExt as _;
        const CHILD: &str = "OMG_NATIVE_OBSERVER_UID_CHILD";
        if std::env::var_os(CHILD).is_some() {
            anyhow::ensure!(
                !omg_lib::core::is_root(),
                "observer child must be unprivileged"
            );
            let manager = DnfPackageManager::new();
            let observed = manager
                .installed_catalog_observation()?
                .context("native observer")?;
            let started = std::time::Instant::now();
            for _ in 0..20 {
                anyhow::ensure!(
                    observed.is_current()?,
                    "unchanged ordinary-user inventory is stale"
                );
            }
            println!(
                "20 ordinary-user observation checks: {:?}",
                started.elapsed()
            );
            return native_catalog_observation_survives_readonly_rpm_and_dnf_queries();
        }
        if !omg_lib::core::is_root() {
            let manager = DnfPackageManager::new();
            let observed = manager
                .installed_catalog_observation()?
                .context("native observer")?;
            for _ in 0..20 {
                anyhow::ensure!(
                    observed.is_current()?,
                    "unchanged ordinary-user inventory is stale"
                );
            }
            return native_catalog_observation_survives_readonly_rpm_and_dnf_queries();
        }
        // Copy only this test runner into a private disposable fixture, since
        // a root Cargo target may itself be inaccessible to the ordinary user.
        let fixture = tempfile::tempdir()?;
        std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o755))?;
        let executable = fixture.path().join("fedora-tests");
        std::fs::copy(std::env::current_exe()?, &executable)?;
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))?;
        let home = fixture.path().join("home");
        std::fs::create_dir(&home)?;
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))?;
        let ownership = std::process::Command::new("/usr/bin/chown")
            .arg("1000:1000")
            .arg(&home)
            .status()?;
        anyhow::ensure!(ownership.success(), "could not assign private child home");
        let output = std::process::Command::new("/usr/bin/setpriv")
            .args([
                "--reuid=1000",
                "--regid=1000",
                "--clear-groups",
                "--no-new-privs",
            ])
            .arg(&executable)
            .args([
                "--exact",
                "dnf_integration::native_catalog_observation_survives_ordinary_user_readonly_wal",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("HOME", &home)
            .env("OMG_TEST_MODE", "0")
            .env_remove("XDG_STATE_HOME")
            .output()?;
        anyhow::ensure!(
            output.status.success(),
            "ordinary-user native observer failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        anyhow::ensure!(
            String::from_utf8_lossy(&output.stdout)
                .contains("20 ordinary-user observation checks:"),
            "ordinary-user child did not execute its observation checks"
        );
        println!("{}", String::from_utf8_lossy(&output.stdout));
        Ok(())
    }

    fn uninstalled_repository_package() -> Result<&'static str> {
        for candidate in ["tree", "htop", "nano", "rsync", "jq"] {
            let installed = std::process::Command::new("rpm")
                .args(["-q", candidate])
                .output()?;
            anyhow::ensure!(
                installed.status.success() || installed.status.code() == Some(1),
                "RPM could not determine whether {candidate} is installed"
            );
            if installed.status.success() {
                continue;
            }
            let available = std::process::Command::new("dnf")
                .args([
                    "--cacheonly",
                    "repoquery",
                    "--available",
                    "--queryformat",
                    "%{name}\\n",
                    "--latest-limit=1",
                    candidate,
                ])
                .output()?;
            anyhow::ensure!(
                available.status.success(),
                "DNF could not query {candidate}: {}",
                String::from_utf8_lossy(&available.stderr)
            );
            if String::from_utf8(available.stdout)?
                .lines()
                .any(|name| name == candidate)
            {
                return Ok(candidate);
            }
        }
        anyhow::bail!("no known available, uninstalled Fedora package for native fixture")
    }

    #[tokio::test]
    async fn test_dnf_package_manager_creation() {
        let pm = DnfPackageManager::new();
        assert_eq!(pm.name(), "dnf");
        let identity = pm.name().to_string();
        assert_no_debian_terms(&identity, "Fedora package manager identity");
        assert_no_arch_terms(&identity, "Fedora package manager identity");
        assert_no_macos_terms(&identity, "Fedora package manager identity");
    }

    #[tokio::test]
    async fn repository_lookup_finds_uninstalled_package() -> Result<()> {
        let package = uninstalled_repository_package()?;
        let expected_name = format!("{package}.{}", std::env::consts::ARCH);
        let pm = DnfPackageManager::new();
        assert!(
            !pm.list_installed()
                .await?
                .iter()
                .any(|installed| installed.name == package),
            "native RPM reports {package} absent but OMG reports it installed"
        );
        let search = pm.search(package).await?;
        assert!(
            search
                .iter()
                .any(|result| result.name == expected_name && !result.installed)
        );
        let info = pm
            .info(package)
            .await?
            .expect("available repository package");
        assert_eq!(info.name, expected_name);
        assert!(!info.installed);

        for arguments in [vec!["info", package], vec!["--json", "info", package]] {
            let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("omg"))
                .args(arguments)
                .output()?;
            assert!(
                output.status.success(),
                "CLI info failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains(package));
        }
        Ok(())
    }

    #[tokio::test]
    async fn repository_info_resolves_architecture_and_nevra_selectors() -> Result<()> {
        let package = uninstalled_repository_package()?;
        let native = std::process::Command::new("dnf")
            .args([
                "--cacheonly",
                "repoquery",
                "--available",
                "--latest-limit=1",
                "--queryformat",
                "%{name}.%{arch}\t%{full_nevra}\t%{evr}\\n",
                package,
            ])
            .output()?;
        anyhow::ensure!(native.status.success(), "native available selection failed");
        let text = std::str::from_utf8(&native.stdout)?;
        let fields: Vec<_> = text
            .lines()
            .next()
            .context("available fixture missing")?
            .split('\t')
            .collect();
        anyhow::ensure!(fields.len() == 3, "invalid native available fixture");
        let manager = DnfPackageManager::new();
        for selector in [&fields[0], &fields[1]] {
            let info = manager
                .info(selector)
                .await?
                .expect("native selector resolves an available package");
            assert_eq!(info.name, fields[0]);
            assert_eq!(info.version.to_string(), fields[2]);
            assert!(!info.installed);
        }
        assert!(manager.info("omg-no-such-package.x86_64").await?.is_none());
        Ok(())
    }

    fn installed_bash_full_nevra() -> Result<(String, String, String)> {
        let output = std::process::Command::new("/usr/bin/rpm")
            .args(["-q", "--queryformat", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\t%{NAME}.%{ARCH}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n", "bash"])
            .output()?;
        anyhow::ensure!(output.status.success(), "native bash fixture query failed");
        let text = std::str::from_utf8(&output.stdout)?;
        let fields: Vec<_> = text
            .lines()
            .next()
            .context("native bash missing")?
            .split('\t')
            .collect();
        anyhow::ensure!(fields.len() == 3, "invalid native bash identity");
        let version = fields[2].strip_prefix("0:").unwrap_or(fields[2]);
        Ok((fields[0].into(), fields[1].into(), version.into()))
    }

    #[tokio::test]
    async fn installed_info_resolves_native_full_nevra_with_zero_epoch() -> Result<()> {
        let (selector, name, version) = installed_bash_full_nevra()?;
        let info = DnfPackageManager::new()
            .info(&selector)
            .await?
            .expect("installed native full NEVRA");
        assert_eq!(
            (info.name, info.version.to_string(), info.installed),
            (name, version, true)
        );
        Ok(())
    }

    #[tokio::test]
    async fn installed_status_resolves_native_full_nevra_with_zero_epoch() -> Result<()> {
        let (selector, name, _) = installed_bash_full_nevra()?;
        let manager = DnfPackageManager::new();
        assert!(
            manager.is_installed(&selector).await?,
            "cold RPM observation must resolve explicit zero epoch"
        );
        assert!(
            manager.is_installed(&name).await?,
            "native name.arch stays installed"
        );
        assert!(
            manager.is_installed(&selector).await?,
            "warm RPM observation must resolve explicit zero epoch"
        );
        Ok(())
    }

    #[test]
    fn cli_info_resolves_native_full_nevra() -> Result<()> {
        let (selector, name, version) = installed_bash_full_nevra()?;
        let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("omg"))
            .args(["info", &selector])
            .env("OMG_DISABLE_DAEMON", "1")
            .env("OMG_TEST_MODE", "0")
            .env_remove("OMG_TEST_DISTRO")
            .env_remove("OMG_TEST_BACKEND")
            .output()?;
        assert!(
            output.status.success(),
            "plain CLI selector failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout)?;
        assert!(
            text.contains(&name) && text.contains(&version),
            "native installed metadata absent: {text}"
        );
        Ok(())
    }

    #[test]
    fn cli_json_info_resolves_native_full_nevra() -> Result<()> {
        let (selector, name, version) = installed_bash_full_nevra()?;
        let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("omg"))
            .args(["--json", "info", &selector])
            .env("OMG_DISABLE_DAEMON", "1")
            .env("OMG_TEST_MODE", "0")
            .env_remove("OMG_TEST_DISTRO")
            .env_remove("OMG_TEST_BACKEND")
            .output()?;
        assert!(
            output.status.success(),
            "JSON CLI selector failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(value["name"], name);
        assert_eq!(value["version"], version);
        assert_eq!(value["installed"], true);
        Ok(())
    }

    #[tokio::test]
    async fn repository_search_has_one_installed_row_per_architecture() -> Result<()> {
        let manager = DnfPackageManager::new();
        let search = manager.search("bash").await?;
        let installed = manager.list_installed().await?;
        let expected: Vec<_> = installed
            .iter()
            .filter(|package| package.name.starts_with("bash."))
            .map(|package| (package.name.clone(), true))
            .collect();
        anyhow::ensure!(!expected.is_empty(), "native bash fixture missing");
        let actual: Vec<_> = search
            .iter()
            .filter(|package| package.name == "bash" || package.name.starts_with("bash."))
            .map(|package| (package.name.clone(), package.installed))
            .collect();
        assert_eq!(
            actual, expected,
            "repository rows must retain the installed identity and state"
        );
        Ok(())
    }

    #[tokio::test]
    async fn explicit_cli_matches_native_backend_without_a_daemon() -> Result<()> {
        let mut expected = DnfPackageManager::new().list_explicit().await?;
        expected.sort();
        expected.dedup();
        let binary = assert_cmd::cargo::cargo_bin!("omg");
        let listing = std::process::Command::new(binary)
            .args(["--json", "explicit"])
            .output()?;
        assert!(
            listing.status.success(),
            "{}",
            String::from_utf8_lossy(&listing.stderr)
        );
        let listing: serde_json::Value = serde_json::from_slice(&listing.stdout)?;
        assert_eq!(listing["packages"], serde_json::json!(expected));
        let count = std::process::Command::new(binary)
            .args(["--json", "explicit", "--count"])
            .output()?;
        assert!(
            count.status.success(),
            "{}",
            String::from_utf8_lossy(&count.stderr)
        );
        let count: serde_json::Value = serde_json::from_slice(&count.stdout)?;
        assert_eq!(count["count"], serde_json::json!(expected.len()));
        Ok(())
    }

    #[test]
    fn size_cli_matches_native_installed_packages() -> Result<()> {
        let before = std::process::Command::new("rpm")
            .args([
                "-qa",
                "--qf",
                "%{NAME}\t%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\t%{SIZE}\n",
            ])
            .output()?;
        assert!(before.status.success());
        let snapshot = String::from_utf8(before.stdout)?;
        let mut packages = snapshot
            .lines()
            .filter(|line| !line.starts_with("gpg-pubkey\t"))
            .map(|line| -> Result<(&str, i64)> {
                let (_, sized_identity) = line.split_once('\t').expect("RPM package name");
                let (name, size) = sized_identity.split_once('\t').expect("RPM size row");
                Ok((name, size.parse()?))
            })
            .collect::<Result<Vec<_>>>()?;
        packages.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(right.0)));
        let binary = assert_cmd::cargo::cargo_bin!("omg");
        let top = std::process::Command::new(binary)
            .env("NO_COLOR", "1")
            .env("LC_ALL", "C")
            .args(["size", "--limit", "3"])
            .output()?;
        assert!(
            top.status.success(),
            "{}",
            String::from_utf8_lossy(&top.stderr)
        );
        let top = String::from_utf8(top.stdout)?;
        let mut cursor = 0;
        for (name, _) in packages.iter().take(3) {
            cursor += top[cursor..].find(name).expect("ranked native identity") + name.len();
        }
        assert!(top.contains(&format!("Number of Packages: {}", packages.len())));
        let selector = format!("glibc.{}", std::env::consts::ARCH);
        let providers = std::process::Command::new("dnf")
            .args([
                "--setopt=disable_excludes=*",
                "repoquery",
                "--installed",
                "--providers-of=requires",
                "--qf",
                "%{full_nevra}\n",
                &selector,
            ])
            .output()?;
        assert!(providers.status.success());
        let providers = String::from_utf8(providers.stdout)?;
        let root = std::process::Command::new("rpm")
            .args([
                "-q",
                &selector,
                "--qf",
                "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n",
            ])
            .output()?;
        assert!(root.status.success());
        let root = String::from_utf8(root.stdout)?;
        let expected: std::collections::BTreeSet<_> =
            providers.lines().chain(root.lines()).collect();
        let tree = std::process::Command::new(binary)
            .env("NO_COLOR", "1")
            .env("LC_ALL", "C")
            .args(["size", "--tree", &selector, "--limit", "10000"])
            .output()?;
        assert!(
            tree.status.success(),
            "{}",
            String::from_utf8_lossy(&tree.stderr)
        );
        let tree = String::from_utf8(tree.stdout)?;
        for name in &expected {
            assert!(tree.contains(name), "missing provider {name}");
        }
        assert!(tree.contains(&format!("Number of Packages: {}", expected.len())));
        assert!(tree.contains("not a minimal dependency closure"));
        let missing = std::process::Command::new(binary)
            .args(["size", "--tree", "omg-no-such-package"])
            .output()?;
        assert!(!missing.status.success());
        assert!(String::from_utf8_lossy(&missing.stderr).contains("is not installed"));
        let after = std::process::Command::new("rpm")
            .args([
                "-qa",
                "--qf",
                "%{NAME}\t%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\t%{SIZE}\n",
            ])
            .output()?;
        assert!(after.status.success());
        let after = String::from_utf8(after.stdout)?;
        let mut before: Vec<_> = snapshot.lines().collect();
        let mut after: Vec<_> = after.lines().collect();
        before.sort_unstable();
        after.sort_unstable();
        assert_eq!(before, after);
        Ok(())
    }

    #[test]
    fn installed_metadata_does_not_hide_excluded_packages() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let cache = dirs::cache_dir().expect("user cache directory");
        std::fs::create_dir_all(&cache)?;
        let fixture = tempfile::tempdir_in(cache)?;
        let dnf = fixture.path().join("dnf");
        std::fs::write(
            &dnf,
            "#!/bin/sh\nexec /usr/bin/dnf --setopt=excludepkgs=glibc \"$@\"\n",
        )?;
        std::fs::set_permissions(&dnf, std::fs::Permissions::from_mode(0o700))?;
        let hidden = std::process::Command::new(&dnf)
            .args(["repoquery", "--installed", "--qf", "%{name}\n", "glibc"])
            .output()?;
        assert!(hidden.status.success());
        assert!(
            hidden.stdout.is_empty(),
            "exclusion fixture must hide glibc from ordinary queries"
        );
        let selector = format!("glibc.{}", std::env::consts::ARCH);
        let inherited = std::env::var_os("PATH").expect("native command PATH");
        let path = std::env::join_paths(
            std::iter::once(fixture.path().to_path_buf()).chain(std::env::split_paths(&inherited)),
        )?;
        for arguments in [
            vec!["size", "--limit", "0"],
            vec!["size", "--tree", &selector],
            vec!["why", &selector],
            vec!["why", "--reverse", &selector],
            vec!["blame", &selector],
        ] {
            let baseline = std::process::Command::new(assert_cmd::cargo::cargo_bin!("omg"))
                .env("NO_COLOR", "1")
                .args(&arguments)
                .output()?;
            assert!(
                baseline.status.success(),
                "{}",
                String::from_utf8_lossy(&baseline.stderr)
            );
            let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("omg"))
                .env("PATH", &path)
                .env("NO_COLOR", "1")
                .args(&arguments)
                .output()?;
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                baseline.stdout, output.stdout,
                "exclusions changed {arguments:?}"
            );
        }
        fixture.close()?;
        Ok(())
    }

    #[test]
    fn why_cli_matches_native_reasons_and_reverse_requirements() -> Result<()> {
        let selector = format!("glibc.{}", std::env::consts::ARCH);
        #[expect(
            clippy::literal_string_with_formatting_args,
            reason = "DNF interprets these query placeholders, not Rust"
        )]
        let format = "%{full_nevra}\t%{reason}\n";
        let native = std::process::Command::new("dnf")
            .args([
                "--setopt=disable_excludes=*",
                "repoquery",
                "--installed",
                "--qf",
                format,
                &selector,
            ])
            .output()?;
        assert!(native.status.success());
        let native = String::from_utf8(native.stdout)?;
        assert_eq!(native.lines().count(), 1);
        let (identity, reason) = native
            .trim_end_matches('\n')
            .split_once('\t')
            .expect("native installation reason");
        let binary = assert_cmd::cargo::cargo_bin!("omg");
        let output = std::process::Command::new(binary)
            .env("NO_COLOR", "1")
            .args(["why", &selector])
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = String::from_utf8(output.stdout)?;
        assert!(output.contains(identity));
        assert!(output.contains(&format!("Reason: {reason}")));
        let native = std::process::Command::new("dnf")
            .args([
                "--setopt=disable_excludes=*",
                "repoquery",
                "--installed",
                "--qf",
                format,
                &format!("--whatrequires={selector}"),
            ])
            .output()?;
        assert!(native.status.success());
        let native = String::from_utf8(native.stdout)?;
        let expected: Vec<_> = native
            .lines()
            .map(|line| line.split_once('\t').expect("native dependent"))
            .filter(|(name, _)| *name != identity)
            .collect();
        let output = std::process::Command::new(binary)
            .env("NO_COLOR", "1")
            .args(["why", "--reverse", &selector])
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = String::from_utf8(output.stdout)?;
        for (identity, reason) in &expected {
            assert!(
                output.contains(&format!("{identity}: {reason}")),
                "missing {identity}"
            );
        }
        assert!(
            !expected.is_empty(),
            "glibc fixture must have native requiring packages"
        );
        assert!(output.contains(&format!("Dependents ({})", expected.len())));
        assert!(!output.contains("Safe to remove:"));
        for arguments in [
            vec!["why", "omg-no-such-package"],
            vec!["why", "--reverse", "omg-no-such-package"],
        ] {
            let output = std::process::Command::new(binary)
                .args(arguments)
                .output()?;
            assert!(!output.status.success());
            assert!(String::from_utf8_lossy(&output.stderr).contains("is not installed"));
        }
        Ok(())
    }

    #[test]
    fn blame_cli_uses_native_details_and_canonical_omg_history() -> Result<()> {
        use omg_lib::core::history::{HistoryManager, PackageChange, Transaction, TransactionType};
        let fixture = tempfile::Builder::new()
            .prefix("omg-fedora-blame-")
            .tempdir_in("/tmp")?;
        let selector = format!("glibc.{}", std::env::consts::ARCH);
        let invoke = || {
            std::process::Command::new(assert_cmd::cargo::cargo_bin!("omg"))
                .env("OMG_NATIVE_TEST_DATA_DIR", "1")
                .env("OMG_DATA_DIR", fixture.path())
                .env("NO_COLOR", "1")
                .args(["blame", &selector])
                .output()
        };
        let empty = invoke()?;
        assert!(
            empty.status.success(),
            "{}",
            String::from_utf8_lossy(&empty.stderr)
        );
        let empty = String::from_utf8(empty.stdout)?;
        assert!(empty.contains("No OMG transaction history found"));
        let native = std::process::Command::new("dnf")
            .args([
                "--setopt=disable_excludes=*",
                "repoquery",
                "--installed",
                "--qf",
                "%{name}\t%{evr}\t%{full_nevra}\t%{reason}\n",
                &selector,
            ])
            .output()?;
        assert!(native.status.success());
        let native = String::from_utf8(native.stdout)?;
        let fields: Vec<_> = native.trim_end_matches('\n').split('\t').collect();
        assert_eq!(fields.len(), 4);
        assert!(empty.contains(&format!("Version: {}", fields[1])));
        assert!(empty.contains(fields[2]));
        assert!(empty.contains(&format!("Install Reason: {}", fields[3])));
        let requiring = std::process::Command::new("dnf")
            .args([
                "--setopt=disable_excludes=*",
                "repoquery",
                "--installed",
                "--qf",
                "%{full_nevra}\n",
                &format!("--whatrequires={selector}"),
            ])
            .output()?;
        assert!(requiring.status.success());
        let requiring = String::from_utf8(requiring.stdout)?;
        for identity in requiring.lines().filter(|identity| *identity != fields[2]) {
            assert!(
                empty.contains(identity),
                "missing native requiring package {identity}"
            );
        }
        let transaction = |id: &str, timestamp: &str, success: bool| -> Result<Transaction> {
            Ok(Transaction {
                id: id.to_owned(),
                timestamp: timestamp.parse()?,
                transaction_type: TransactionType::Install,
                changes: vec![PackageChange {
                    name: fields[0].to_owned(),
                    old_version: None,
                    new_version: Some(id.to_owned()),
                    source: "qa-fixture".to_owned(),
                }],
                success,
            })
        };
        let history_path = fixture.path().join("history.json");
        HistoryManager::new_in(&history_path)?.save(&[
            transaction("fixture-old", "2026-01-01T00:00:00Z", true)?,
            transaction("fixture-failed", "2026-01-02T00:00:00Z", false)?,
        ])?;
        let before = std::fs::read(&history_path)?;
        let output = invoke()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = String::from_utf8(output.stdout)?;
        assert!(output.contains("failed to install → fixture-failed"));
        assert!(output.contains("installed → fixture-old"));
        assert!(output.find("fixture-failed") < output.find("fixture-old"));
        assert!(output.contains("matched by package name"));
        assert_eq!(before, std::fs::read(&history_path)?);
        std::fs::write(&history_path, b"invalid history")?;
        let corrupt = invoke()?;
        assert!(!corrupt.status.success());
        assert!(!String::from_utf8(corrupt.stdout)?.contains("No OMG transaction history"));
        assert_eq!(std::fs::read(&history_path)?, b"invalid history");
        fixture.close()?;
        Ok(())
    }

    #[test]
    fn native_transactions_record_install_remove_and_ignore_noops() -> Result<()> {
        use omg_lib::core::history::{HistoryManager, TransactionType};
        let package = uninstalled_repository_package()?;
        let snapshot = || -> Result<Vec<String>> {
            let output = std::process::Command::new("rpm")
                .args(["-qa", "--qf", "%{NAME}\t%{NEVRA}\n"])
                .output()?;
            anyhow::ensure!(output.status.success(), "RPM inventory failed");
            let mut rows = Vec::new();
            for line in std::str::from_utf8(&output.stdout)?.lines() {
                let (name, identity) = line
                    .split_once('\t')
                    .ok_or_else(|| anyhow::anyhow!("Invalid RPM inventory row"))?;
                if name != "gpg-pubkey" {
                    rows.push(identity.to_owned());
                }
            }
            rows.sort();
            Ok(rows)
        };
        let before = snapshot()?;
        let fixture = tempfile::Builder::new()
            .prefix("omg-fedora-transaction-")
            .tempdir_in("/tmp")?;
        let history = HistoryManager::new_in(fixture.path().join("history.json"))?;
        let run = |arguments: &[&str]| {
            std::process::Command::new(assert_cmd::cargo::cargo_bin!("omg"))
                .env("OMG_NATIVE_TEST_DATA_DIR", "1")
                .env("OMG_DATA_DIR", fixture.path())
                .env("NO_COLOR", "1")
                .stdin(std::process::Stdio::null())
                .args(arguments)
                .output()
        };
        let verified = (|| -> Result<()> {
            let install = run(&["install", package, "--yes"])?;
            anyhow::ensure!(
                install.status.success(),
                "Install failed: {}",
                String::from_utf8_lossy(&install.stderr)
            );
            let records = history.load()?;
            anyhow::ensure!(
                records.len() == 1,
                "Expected exactly one installation transaction"
            );
            let record = &records[0];
            anyhow::ensure!(
                record.success && record.transaction_type == TransactionType::Install,
                "Incorrect installation outcome"
            );
            let change = record
                .changes
                .iter()
                .find(|change| change.name == package)
                .ok_or_else(|| anyhow::anyhow!("Installation history omitted {package}"))?;
            let native = std::process::Command::new("rpm")
                .args(["-q", package, "--qf", "%{EPOCHNUM}:%{VERSION}-%{RELEASE}"])
                .output()?;
            anyhow::ensure!(native.status.success(), "Native installed version failed");
            anyhow::ensure!(
                change.old_version.is_none()
                    && change.new_version.as_deref() == Some(std::str::from_utf8(&native.stdout)?),
                "Recorded version differs from RPM"
            );
            let noop = run(&["install", package, "--yes"])?;
            anyhow::ensure!(noop.status.success(), "No-op install failed");
            anyhow::ensure!(history.load()?.len() == 1, "No-op invented a transaction");
            let blame = run(&["blame", package])?;
            anyhow::ensure!(
                blame.status.success()
                    && String::from_utf8(blame.stdout)?.contains("OMG Transaction History (1)"),
                "blame did not find real installation history"
            );
            Ok(())
        })();
        let present = std::process::Command::new("rpm")
            .args(["-q", package])
            .output()?;
        if present.status.success() {
            let removed = run(&["remove", package, "--yes"])?;
            if !removed.status.success() {
                let fallback = std::process::Command::new("dnf")
                    .args(["remove", "-y", package])
                    .output()?;
                anyhow::ensure!(
                    fallback.status.success(),
                    "OMG removal failed: {}; native cleanup also failed: {}",
                    String::from_utf8_lossy(&removed.stderr),
                    String::from_utf8_lossy(&fallback.stderr)
                );
                anyhow::ensure!(snapshot()? == before, "RPM inventory was not restored");
                anyhow::bail!(
                    "OMG removal failed after native cleanup: {}",
                    String::from_utf8_lossy(&removed.stderr)
                );
            }
        } else {
            anyhow::ensure!(
                present.status.code() == Some(1),
                "Cannot determine fixture package state"
            );
        }
        anyhow::ensure!(snapshot()? == before, "RPM inventory was not restored");
        verified?;
        let records = history.load()?;
        anyhow::ensure!(records.len() == 2, "Expected install and remove history");
        let removed = &records[1];
        anyhow::ensure!(
            removed.success && removed.transaction_type == TransactionType::Remove,
            "Incorrect removal outcome"
        );
        anyhow::ensure!(
            removed.changes.iter().any(|change| change.name == package
                && change.old_version.is_some()
                && change.new_version.is_none()),
            "Removal history omitted {package}"
        );
        fixture.close()?;
        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial(history_ownership)]
    async fn native_history_honors_custom_and_disabled_service_history() -> Result<()> {
        use omg_lib::core::history::HistoryManager;
        use omg_lib::core::packages::PackageService;
        let package = uninstalled_repository_package()?;
        let inventory = || -> Result<Vec<String>> {
            let output = std::process::Command::new("rpm")
                .args(["-qa", "--qf", "%{NEVRA}\\n"])
                .output()?;
            anyhow::ensure!(output.status.success(), "RPM inventory failed");
            let mut rows = String::from_utf8(output.stdout)?
                .lines()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            rows.sort();
            Ok(rows)
        };
        let before = inventory()?;
        let fixture = tempfile::Builder::new()
            .prefix("omg-fedora-history-owner-")
            .tempdir_in("/tmp")?;
        let custom_path = fixture.path().join("custom.json");
        let default = HistoryManager::new()?;
        let default_before = serde_json::to_vec(&default.load()?)?;
        let manager = std::sync::Arc::new(DnfPackageManager::new());
        let packages = vec![package.to_owned()];
        enum Owner {
            Service,
            Disabled,
            Parent,
        }
        for owner in [Owner::Service, Owner::Disabled, Owner::Parent] {
            if let Err(error) = manager.install(&packages).await {
                let remaining = std::process::Command::new("rpm")
                    .args(["-q", package])
                    .output()?;
                if remaining.status.success() {
                    manager.remove(&packages).await?;
                }
                return Err(error);
            }
            let builder = PackageService::builder(manager.clone());
            let service = match owner {
                Owner::Service | Owner::Parent => builder
                    .history(HistoryManager::new_in(&custom_path)?)
                    .build()?,
                Owner::Disabled => builder.without_history().build()?,
            };
            omg_lib::core::privilege::set_parent_owns_history(matches!(owner, Owner::Parent));
            let outcome = service.remove(&packages).await;
            omg_lib::core::privilege::set_parent_owns_history(false);
            let remaining = std::process::Command::new("rpm")
                .args(["-q", package])
                .output()?;
            if remaining.status.success() {
                manager.remove(&packages).await?;
            }
            outcome?;
            anyhow::ensure!(
                remaining.status.code() == Some(1),
                "Service removal did not remove {package}"
            );
            anyhow::ensure!(inventory()? == before, "RPM inventory was not restored");
            anyhow::ensure!(
                HistoryManager::new_in(&custom_path)?.load()?.len() == 1,
                "Service history setting was not respected"
            );
            anyhow::ensure!(
                serde_json::to_vec(&default.load()?)? == default_before,
                "Backend wrote to the default history unexpectedly"
            );
        }
        fixture.close()?;
        Ok(())
    }

    #[tokio::test]
    async fn cleanup_preview_preserves_installed_packages() -> Result<()> {
        let snapshot = || -> Result<Vec<String>> {
            let output = std::process::Command::new("rpm")
                .args(["-qa", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n"])
                .output()?;
            assert!(output.status.success());
            let mut packages: Vec<String> = String::from_utf8(output.stdout)?
                .lines()
                .map(str::to_owned)
                .collect();
            packages.sort();
            Ok(packages)
        };
        let before = snapshot()?;
        let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("omg"))
            .args(["clean", "--all", "--dry-run"])
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8(output.stdout)?.contains("No changes made (dry run)"));
        assert_eq!(snapshot()?, before);
        Ok(())
    }

    #[tokio::test]
    async fn test_search_common_package() {
        let pm = DnfPackageManager::new();

        let results = pm.search("vim").await.unwrap();

        assert!(!results.is_empty(), "Should find vim package");
        assert!(
            results.iter().any(|p| p.name.contains("vim")),
            "Results should contain vim"
        );
    }

    /// A missing name must stay absent when repository search is available.
    #[tokio::test]
    async fn test_search_nonexistent_package() -> Result<()> {
        let pm = DnfPackageManager::new();

        let results = pm.search("nonexistent-package-xyz-12345").await?;

        assert!(results.is_empty(), "Should not find nonexistent package");

        Ok(())
    }

    #[tokio::test]
    async fn test_list_installed_packages() -> Result<()> {
        let pm = DnfPackageManager::new();

        let installed = pm.list_installed().await?;

        assert!(
            !installed.is_empty(),
            "Should have installed packages on Fedora system"
        );
        assert_installed_rpm_selection(&installed, "bash")?;
        assert!(
            installed.iter().all(|package| package.installed),
            "installed inventory must not contain available-only packages"
        );
        Ok(())
    }

    #[tokio::test]
    async fn installed_rpm_selection_rejects_inexact_or_noninstalled_records() -> Result<()> {
        let installed = DnfPackageManager::new().list_installed().await?;
        assert_installed_rpm_selection(&installed, "bash")?;
        let selected = installed
            .iter()
            .position(|package| {
                package
                    .name
                    .rsplit_once('.')
                    .is_some_and(|(name, _)| name == "bash")
            })
            .expect("independently verified bash identity");
        let mut unrelated = installed.clone();
        let mut addon = installed[selected].clone();
        addon.name = "bash.addon.x86_64".into();
        unrelated.push(addon);
        assert_installed_rpm_selection(&unrelated, "bash")?;
        for mutation in [
            "bare",
            "architecture",
            "version",
            "available",
            "missing",
            "duplicate",
        ] {
            let mut changed = installed.clone();
            match mutation {
                "bare" => changed[selected].name = "bash".into(),
                "architecture" => changed[selected].name = "bash.omg_wrong_arch".into(),
                "version" => {
                    changed[selected].version = omg_lib::package_managers::parse_version("0")
                        .expect("valid counterexample version");
                }
                "available" => changed[selected].installed = false,
                "missing" => {
                    changed.remove(selected);
                }
                "duplicate" => changed.push(changed[selected].clone()),
                _ => unreachable!(),
            }
            let error = assert_installed_rpm_selection(&changed, "bash")
                .expect_err("inexact selected inventory must be rejected");
            assert!(
                error.to_string().contains("listed RPM selection differs"),
                "{mutation}: {error}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_list_updates() -> Result<()> {
        let native_query = |selection: &str| -> Result<Vec<(String, String, String, String)>> {
            let output = std::process::Command::new("dnf")
                .args([
                    "--cacheonly",
                    "repoquery",
                    selection,
                    "--queryformat",
                    "%{name}\t%{arch}\t%{evr}\t%{repoid}\\n",
                    "--latest-limit=1",
                ])
                .output()?;
            anyhow::ensure!(
                output.status.success(),
                "native DNF {selection} query failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout)?
                .lines()
                .map(|line| {
                    let fields = line.split('\t').collect::<Vec<_>>();
                    anyhow::ensure!(fields.len() == 4, "invalid native DNF row: {line}");
                    Ok((
                        fields[0].to_owned(),
                        fields[1].to_owned(),
                        fields[2].to_owned(),
                        fields[3].to_owned(),
                    ))
                })
                .collect()
        };
        let installed = native_query("--installed")?;
        let upgrades = native_query("--upgrades")?;
        let mut expected = Vec::new();
        for (name, arch, new_version, repo) in upgrades {
            let matching = installed
                .iter()
                .filter(|(installed_name, installed_arch, _, _)| {
                    installed_name == &name && installed_arch == &arch
                })
                .collect::<Vec<_>>();
            anyhow::ensure!(
                matching.len() == 1,
                "native DNF upgrade {name}.{arch} has {} installed matches",
                matching.len()
            );
            let old_version = &matching[0].2;
            anyhow::ensure!(
                old_version != &new_version,
                "unchanged DNF upgrade {name}.{arch}"
            );
            expected.push((name, old_version.clone(), new_version, repo));
        }
        expected.sort();

        let mut actual = DnfPackageManager::new()
            .list_updates()
            .await?
            .into_iter()
            .map(|update| {
                (
                    update.name,
                    update.old_version,
                    update.new_version,
                    update.repo,
                )
            })
            .collect::<Vec<_>>();
        actual.sort();
        assert_eq!(
            actual, expected,
            "OMG update inventory differs from native DNF"
        );

        let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("omg"))
            .args(["outdated", "--json"])
            .output()?;
        anyhow::ensure!(
            output.status.success(),
            "omg outdated --json failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let rows = parsed
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("outdated --json must return an array"))?;
        let mut cli = rows
            .iter()
            .map(|row| -> Result<(String, String, String, String)> {
                Ok((
                    row["name"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("missing name"))?
                        .to_owned(),
                    row["current_version"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("missing current version"))?
                        .to_owned(),
                    row["new_version"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("missing new version"))?
                        .to_owned(),
                    row["repo"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("missing repo"))?
                        .to_owned(),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        cli.sort();
        assert_eq!(cli, expected, "CLI outdated JSON differs from native DNF");
        Ok(())
    }

    #[tokio::test]
    async fn test_is_installed_check() {
        let pm = DnfPackageManager::new();

        let is_bash_installed = pm.is_installed("bash").await.unwrap();
        assert!(
            is_bash_installed,
            "bash should be installed on Fedora system"
        );
        assert!(
            !pm.is_installed("omg-no-such-package-xyz-12345")
                .await
                .unwrap(),
            "unknown package must not be reported as installed"
        );
    }
}

mod dnf_rpm_database {
    use super::*;

    #[tokio::test]
    async fn test_rpm_database_query() -> Result<()> {
        let pm = DnfPackageManager::new();

        let installed = pm.list_installed().await?;

        assert!(
            !installed.is_empty(),
            "Should read packages from RPM database"
        );

        assert_installed_rpm_selection(&installed, "rpm")?;
        Ok(())
    }
}

mod dnf_operations {
    use super::*;

    #[tokio::test]
    #[ignore = "requires a disposable VM; installs and removes an orphan fixture"]
    async fn test_orphan_cleanup_history() -> Result<()> {
        use omg_lib::core::history::{HistoryManager, TransactionType};
        use std::io::Write;
        let installed = || -> Result<bool> {
            let output = std::process::Command::new("rpm")
                .args(["-q", "tree"])
                .output()?;
            anyhow::ensure!(
                matches!(output.status.code(), Some(0 | 1)),
                "Cannot inspect fixture state"
            );
            Ok(output.status.success())
        };
        let orphans = std::process::Command::new("dnf")
            .args(["repoquery", "--unneeded", "--queryformat", "%{name}\n"])
            .output()?;
        anyhow::ensure!(
            orphans.status.success() && orphans.stdout.is_empty(),
            "Fixture requires no pre-existing orphans"
        );
        anyhow::ensure!(!installed()?, "Fixture requires tree to be absent");
        let fixture = tempfile::tempdir_in(dirs::cache_dir().expect("user cache directory"))?;
        let history = HistoryManager::new_in(fixture.path().join("history.json"))?;
        let run = |args: &[&str], answer: &[u8]| -> Result<std::process::Output> {
            let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin!("omg"))
                .env("OMG_DATA_DIR", fixture.path())
                .args(args)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()?;
            child
                .stdin
                .take()
                .ok_or_else(|| anyhow::anyhow!("Missing fixture input pipe"))?
                .write_all(answer)?;
            Ok(child.wait_with_output()?)
        };
        let manager = DnfPackageManager::new();
        let packages = vec!["tree".to_owned()];
        manager.install(&packages).await?;
        let verified = (|| -> Result<()> {
            let native = std::process::Command::new("rpm")
                .args(["-q", "tree", "--qf", "%{EPOCHNUM}:%{VERSION}-%{RELEASE}"])
                .output()?;
            anyhow::ensure!(native.status.success(), "Cannot read fixture version");
            let version = String::from_utf8(native.stdout)?;
            let mark = std::process::Command::new("sudo")
                .args(["-n", "dnf", "-y", "mark", "dependency", "tree"])
                .stdin(std::process::Stdio::null())
                .output()?;
            anyhow::ensure!(mark.status.success(), "Cannot mark fixture as dependency");
            let selected = std::process::Command::new("dnf")
                .args(["repoquery", "--unneeded", "--queryformat", "%{name}\n"])
                .output()?;
            anyhow::ensure!(
                selected.status.success()
                    && std::str::from_utf8(&selected.stdout)?.trim() == "tree",
                "Unexpected native orphan selection"
            );
            let preview = run(&["clean", "--orphans", "--dry-run"], b"")?;
            anyhow::ensure!(
                preview.status.success() && installed()? && history.load()?.is_empty(),
                "Preview mutated state or history"
            );
            let decline = run(&["clean", "--orphans"], b"n\n")?;
            anyhow::ensure!(
                decline.status.code() == Some(1) && installed()?,
                "Native decline did not preserve the fixture"
            );
            let declined = history.load()?;
            anyhow::ensure!(
                declined.len() == 1 && !declined[0].success && declined[0].changes.is_empty(),
                "Unexpected decline history: {declined:?}; stderr: {}",
                String::from_utf8_lossy(&decline.stderr)
            );
            let accepted = run(&["clean", "--orphans"], b"y\n")?;
            anyhow::ensure!(
                accepted.status.success() && !installed()?,
                "Accepted cleanup did not remove the orphan"
            );
            let records = history.load()?;
            anyhow::ensure!(
                records.len() == 2
                    && records[1].success
                    && records[1].transaction_type == TransactionType::Remove,
                "Missing cleanup history"
            );
            anyhow::ensure!(
                records[1].changes.len() == 1
                    && records[1].changes[0].name == "tree"
                    && records[1].changes[0].old_version.as_deref() == Some(version.as_str())
                    && records[1].changes[0].new_version.is_none(),
                "Cleanup history differs from native removal"
            );
            anyhow::ensure!(
                run(&["clean", "--orphans"], b"")?.status.success(),
                "Empty cleanup failed"
            );
            anyhow::ensure!(
                run(&["clean", "--cache"], b"")?.status.success(),
                "Cache cleanup failed"
            );
            anyhow::ensure!(
                history.load()?.len() == 2,
                "Empty or cache cleanup invented package history"
            );
            Ok(())
        })();
        if installed()? {
            manager.remove(&packages).await?;
        }
        verified?;
        fixture.close()?;
        Ok(())
    }

    #[test]
    #[ignore = "upgrades the system; requires a disposable VM snapshot and external rollback"]
    fn test_update_all_packages() -> Result<()> {
        use omg_lib::core::history::{HistoryManager, TransactionType};
        use std::collections::BTreeSet;
        #[derive(PartialEq, Eq, PartialOrd, Ord)]
        struct Installed {
            name: String,
            version: String,
            architecture: String,
        }
        let snapshot = || -> Result<BTreeSet<Installed>> {
            let output = std::process::Command::new("rpm")
                .args([
                    "-qa",
                    "--qf",
                    "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n",
                ])
                .output()?;
            anyhow::ensure!(output.status.success(), "RPM inventory failed");
            let mut packages = BTreeSet::new();
            for line in std::str::from_utf8(&output.stdout)?.lines() {
                let fields: Vec<_> = line.split('\t').collect();
                anyhow::ensure!(
                    fields.len() == 3 && fields.iter().all(|field| !field.is_empty()),
                    "Invalid RPM inventory row"
                );
                if fields[0] == "gpg-pubkey" {
                    continue;
                }
                anyhow::ensure!(
                    packages.insert(Installed {
                        name: fields[0].to_owned(),
                        version: fields[1].to_owned(),
                        architecture: fields[2].to_owned()
                    }),
                    "Duplicate native installed identity"
                );
            }
            Ok(packages)
        };
        let before = snapshot()?;
        let fixture = tempfile::tempdir_in(dirs::cache_dir().expect("user cache directory"))?;
        let history = HistoryManager::new_in(fixture.path().join("history.json"))?;
        let update = || {
            std::process::Command::new(assert_cmd::cargo::cargo_bin!("omg"))
                .env("OMG_DATA_DIR", fixture.path())
                .stdin(std::process::Stdio::null())
                .args(["update", "--yes"])
                .output()
        };
        let applied = update()?;
        anyhow::ensure!(
            applied.status.success(),
            "Update failed: {}",
            String::from_utf8_lossy(&applied.stderr)
        );
        let after = snapshot()?;
        anyhow::ensure!(
            before != after,
            "This fixture requires available package upgrades"
        );
        let records = history.load()?;
        anyhow::ensure!(
            records.len() == 1
                && records[0].success
                && records[0].transaction_type == TransactionType::Update,
            "Expected one successful update record: {records:?}"
        );
        let mut removed: Vec<_> = before
            .difference(&after)
            .map(|package| (package.name.clone(), package.version.clone()))
            .collect();
        let mut added: Vec<_> = after
            .difference(&before)
            .map(|package| (package.name.clone(), package.version.clone()))
            .collect();
        let mut recorded_removed: Vec<_> = records[0]
            .changes
            .iter()
            .filter_map(|change| {
                change
                    .old_version
                    .as_ref()
                    .map(|version| (change.name.clone(), version.clone()))
            })
            .collect();
        let mut recorded_added: Vec<_> = records[0]
            .changes
            .iter()
            .filter_map(|change| {
                change
                    .new_version
                    .as_ref()
                    .map(|version| (change.name.clone(), version.clone()))
            })
            .collect();
        removed.sort();
        added.sort();
        recorded_removed.sort();
        recorded_added.sort();
        anyhow::ensure!(
            removed == recorded_removed,
            "Recorded removed versions differ from the native RPM delta"
        );
        anyhow::ensure!(
            added == recorded_added,
            "Recorded added versions differ from the native RPM delta"
        );
        println!(
            "Native RPM delta matched: {} removed builds, {} added builds",
            removed.len(),
            added.len()
        );
        println!("OMG update record: {}", serde_json::to_string(&records)?);
        let noop = update()?;
        anyhow::ensure!(
            noop.status.success(),
            "No-op update failed: {}",
            String::from_utf8_lossy(&noop.stderr)
        );
        anyhow::ensure!(
            snapshot()? == after && history.load()?.len() == 1,
            "No-op update changed package state or invented history"
        );
        fixture.close()?;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires root privileges and modifies system"]
    async fn test_sync_repository_metadata() -> Result<()> {
        let pm = DnfPackageManager::new();

        pm.sync().await?;

        Ok(())
    }
}

mod dnf_error_handling {
    use super::*;

    #[tokio::test]
    async fn test_install_invalid_package() {
        if !omg_lib::core::is_root() {
            common::report_skip("requires root privileges");
            return;
        }

        let pm = DnfPackageManager::new();

        let result = pm
            .install(&["nonexistent-package-xyz-12345".to_string()])
            .await;

        assert!(
            result.is_err(),
            "Should fail to install nonexistent package"
        );
    }
}
