#![cfg(target_os = "macos")]

use anyhow::{Context, Result};
use omg_lib::package_managers::{HomebrewPackageManager, PackageManager};

pub mod platform_semantics;

use platform_semantics::{assert_no_arch_terms, assert_no_debian_terms, assert_no_fedora_terms};

mod homebrew_integration {
    use super::*;

    #[tokio::test]
    async fn offline_inventory_counters_work_without_a_status_snapshot() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        let total = HomebrewPackageManager::new().list_installed().await?.len();
        assert!(total > 0, "the native gate installs Homebrew formulas");
        let root = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in("/tmp")?;
        let socket = root.path().join("omg.sock");
        omg_lib::core::paths::validate_socket_parent(&socket)?;
        let proxy = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
        let proxy_url = format!("http://{}", proxy.local_addr()?);
        let attempts = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&attempts);
        let reject_proxy = tokio::spawn(async move {
            while let Ok((connection, _)) = proxy.accept().await {
                observed.fetch_add(1, Ordering::Relaxed);
                drop(connection);
            }
        });
        let run = async |args: &[&str], daemon_disabled: bool| -> Result<std::process::Output> {
            let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_omg"));
            command
                .args(args)
                .env("HOME", root.path())
                .env("XDG_CACHE_HOME", root.path().join("cache"))
                .env("HOMEBREW_CACHE", root.path().join("brew-cache"))
                .env("OMG_CONFIG_DIR", root.path().join("config"))
                .env("OMG_DATA_DIR", root.path().join("data"))
                .env("OMG_SOCKET_PATH", &socket)
                .env(
                    "OMG_DISABLE_DAEMON",
                    if daemon_disabled { "1" } else { "0" },
                )
                .env("OMG_DISABLE_TELEMETRY", "1")
                .env("OMG_NO_UPDATE_CHECK", "1")
                .env("HTTPS_PROXY", &proxy_url)
                .env("https_proxy", &proxy_url)
                .env_remove("NO_PROXY")
                .env_remove("no_proxy")
                .env_remove("OMG_TEST_MODE")
                .kill_on_drop(true);
            Ok(
                tokio::time::timeout(std::time::Duration::from_secs(20), command.output())
                    .await??,
            )
        };

        for (command, expected) in [("tc", total), ("oc", 0)] {
            let output = run(&[command], true).await?;
            assert!(output.status.success(), "{command}: {:?}", output);
            assert_eq!(
                String::from_utf8(output.stdout)?.trim(),
                expected.to_string()
            );
            let output = run(&[command, "--json"], true).await?;
            assert!(output.status.success(), "{command} --json: {:?}", output);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&output.stdout)?,
                serde_json::json!({"count": expected})
            );
        }
        assert_eq!(attempts.load(Ordering::Relaxed), 0);

        for args in [
            &["status"][..],
            &["status", "--fast"][..],
            &["status", "--json"][..],
            &["uc"][..],
            &["uc", "--json"][..],
        ] {
            let before = attempts.load(Ordering::Relaxed);
            let output = run(args, true).await?;
            let stderr = String::from_utf8(output.stderr)?;
            assert_eq!(output.status.code(), Some(1), "{args:?}: {stderr}");
            assert!(
                stderr.contains("Homebrew update count unavailable"),
                "{args:?}: {stderr}"
            );
            let stdout = String::from_utf8(output.stdout)?;
            assert!(
                !stdout.contains("Updates") && !stdout.contains("updates_available"),
                "{args:?}: {stdout}"
            );
            if args.contains(&"--json") || args[0] == "uc" {
                assert!(stdout.is_empty(), "{args:?}: {stdout}");
            }
            assert!(
                attempts.load(Ordering::Relaxed) > before,
                "{args:?} did not query the catalog"
            );
        }

        omg_lib::core::fast_status::FastStatus::new(total + 1, 0, 0, 9)
            .write_to_file(&root.path().join("omg.status"))?;
        let before = attempts.load(Ordering::Relaxed);
        for (daemon_disabled, command, expected) in [
            (true, "tc", total),
            (false, "tc", total + 1),
            (false, "uc", 9),
        ] {
            let output = run(&[command, "--json"], daemon_disabled).await?;
            assert!(
                output.status.success(),
                "{command} --json with daemon disabled={daemon_disabled}: {output:?}"
            );
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&output.stdout)?,
                serde_json::json!({"count": expected}),
                "{command} --json with daemon disabled={daemon_disabled}"
            );
        }
        assert_eq!(attempts.load(Ordering::Relaxed), before);
        reject_proxy.abort();
        Ok(())
    }

    #[tokio::test]
    async fn test_homebrew_package_manager_creation() {
        let pm = HomebrewPackageManager::new();
        assert_eq!(pm.name(), "brew");
        let identity = pm.name().to_string();
        assert_no_arch_terms(&identity, "macOS package manager identity");
        assert_no_debian_terms(&identity, "macOS package manager identity");
        assert_no_fedora_terms(&identity, "macOS package manager identity");
    }

    #[tokio::test]
    #[ignore = "requires network access to Homebrew API"]
    async fn test_search_common_formula() -> Result<()> {
        let pm = HomebrewPackageManager::new();

        let results = pm.search("wget").await?;

        assert!(!results.is_empty(), "Should find wget formula");
        assert!(
            results.iter().any(|p| p.name == "wget"),
            "Results should contain wget"
        );

        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires network access to Homebrew API"]
    async fn test_search_nonexistent_formula() -> Result<()> {
        let pm = HomebrewPackageManager::new();

        let results = pm.search("nonexistent-formula-xyz-12345").await?;

        assert!(results.is_empty(), "Should not find nonexistent formula");

        Ok(())
    }

    #[tokio::test]
    async fn test_list_installed_formulae() -> Result<()> {
        // CI installs wget before this test. Homebrew's own inventory is the
        // oracle, so an empty OMG inventory cannot make this test pass.
        let brew = std::process::Command::new("brew")
            .args(["list", "--formula", "--versions", "wget"])
            .output()
            .context("run brew list --formula --versions wget")?;
        assert!(
            brew.status.success(),
            "brew could not list installed wget: {}",
            String::from_utf8_lossy(&brew.stderr)
        );
        let output = String::from_utf8(brew.stdout).context("brew inventory is not UTF-8")?;
        let lines: Vec<_> = output
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        assert_eq!(
            lines.len(),
            1,
            "expected one wget inventory row: {output:?}"
        );
        let mut fields = lines[0].split_whitespace();
        assert_eq!(
            fields.next(),
            Some("wget"),
            "unexpected brew inventory: {output:?}"
        );
        let brew_versions: Vec<_> = fields.collect();
        assert!(
            !brew_versions.is_empty(),
            "brew reported wget without an installed version: {output:?}"
        );

        let pm = HomebrewPackageManager::new();
        let installed = pm.list_installed().await?;
        assert!(
            !installed.is_empty(),
            "OMG missed Homebrew's installed wget"
        );
        for pkg in &installed {
            assert!(!pkg.name.is_empty(), "installed entries must have a name");
        }
        let wget = installed
            .iter()
            .find(|pkg| pkg.name == "wget")
            .expect("OMG inventory must include Homebrew's installed wget");
        assert!(wget.installed, "OMG must mark wget as installed");
        let omg_version = wget.version.to_string();
        assert!(
            brew_versions.contains(&omg_version.as_str()),
            "OMG wget version {omg_version:?} differs from Homebrew versions {brew_versions:?}"
        );

        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires network access to Homebrew API"]
    async fn test_formula_info() -> Result<()> {
        let pm = HomebrewPackageManager::new();

        // Network-gated: the API is reachable, so wget MUST resolve. A None
        // here is a regression, not an acceptable pass.
        let pkg = pm
            .info("wget")
            .await?
            .expect("wget formula must resolve against the live Homebrew API");
        assert_eq!(pkg.name, "wget");
        assert!(
            !pkg.description.is_empty(),
            "Description should not be empty"
        );

        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires network access to Homebrew API"]
    async fn test_list_updates() -> Result<()> {
        let pm = HomebrewPackageManager::new();

        let _updates = pm.list_updates().await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_is_installed_check() -> Result<()> {
        let pm = HomebrewPackageManager::new();

        // Deterministic, offline contract: a formula that cannot exist
        // reports Ok(false) rather than an error (mirrors the src-side unit
        // test at src/package_managers/homebrew.rs:994).
        let installed = pm
            .is_installed("this-formula-definitely-does-not-exist-12345")
            .await?;
        assert!(
            !installed,
            "a nonexistent formula must report installed=false"
        );

        Ok(())
    }
}

mod homebrew_cellar_operations {
    use super::*;

    #[tokio::test]
    #[ignore = "installs and removes a real Homebrew formula; requires macOS with live Homebrew and network access"]
    async fn test_install_and_remove_formula() -> Result<()> {
        let pm = HomebrewPackageManager::new();

        let test_formula = "hello";

        let initial_check = pm.is_installed(test_formula).await.unwrap();
        if initial_check {
            pm.remove(&[test_formula.to_string()]).await?;
        }

        pm.install(&[test_formula.to_string()]).await?;
        assert!(
            pm.is_installed(test_formula).await.unwrap(),
            "Formula should be installed"
        );

        pm.remove(&[test_formula.to_string()]).await?;
        assert!(
            !pm.is_installed(test_formula).await.unwrap(),
            "Formula should be removed"
        );

        Ok(())
    }

    #[tokio::test]
    #[ignore = "performs a real `brew upgrade` across all formulae; requires macOS with live Homebrew and network access"]
    async fn test_update_all_formulae() -> Result<()> {
        let pm = HomebrewPackageManager::new();

        pm.update().await?;

        Ok(())
    }

    #[tokio::test]
    #[ignore = "runs a real `brew update` metadata sync; requires macOS with live Homebrew and network access"]
    async fn test_sync_formula_metadata() -> Result<()> {
        let pm = HomebrewPackageManager::new();

        pm.sync().await?;

        Ok(())
    }
}

mod homebrew_error_handling {
    use super::*;

    #[tokio::test]
    async fn test_install_invalid_formula() {
        let pm = HomebrewPackageManager::new();

        let result = pm
            .install(&["nonexistent-formula-xyz-12345".to_string()])
            .await;

        assert!(
            result.is_err(),
            "Should fail to install nonexistent formula"
        );
    }
}

mod homebrew_api {
    use super::*;

    #[tokio::test]
    #[ignore = "requires network access to Homebrew API"]
    async fn test_formula_api_fetch() -> Result<()> {
        let pm = HomebrewPackageManager::new();

        pm.sync().await?;

        let results = pm.search("node").await?;
        assert!(!results.is_empty(), "Should find formulae after sync");

        Ok(())
    }
}
