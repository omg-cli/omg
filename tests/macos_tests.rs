#![cfg(target_os = "macos")]

use anyhow::Result;
use omg_lib::package_managers::{HomebrewPackageManager, PackageManager};

pub mod platform_semantics;

use platform_semantics::{assert_no_arch_terms, assert_no_debian_terms, assert_no_fedora_terms};

#[test]
fn doctor_turbo_rejects_unsupported_macos() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_omg"))
        .args(["doctor", "--turbo"])
        .output()
        .expect("run macOS doctor turbo");
    assert!(!output.status.success(), "unsupported turbo mode must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Turbo setup is only available on Linux"),
        "unexpected refusal: {stderr}"
    );
}

mod homebrew_integration {
    use super::*;

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
        let pm = HomebrewPackageManager::new();

        // The operation must succeed, and every returned entry must carry a
        // usable identity — not just "run without error".
        let installed = pm.list_installed().await?;
        for pkg in &installed {
            assert!(!pkg.name.is_empty(), "installed entries must have a name");
        }

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
