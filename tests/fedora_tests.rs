#![cfg(all(target_os = "linux", feature = "fedora"))]

use anyhow::Result;
use omg_lib::package_managers::{DnfPackageManager, PackageManager};

pub mod common;
pub mod platform_semantics;

use platform_semantics::{assert_no_arch_terms, assert_no_debian_terms, assert_no_macos_terms};

mod dnf_integration {
    use super::*;

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
    async fn repository_lookup_finds_tree_before_installation() -> Result<()> {
        if common::TestConfig::default().skip_if_no_system("dnf_uninstalled_repository_lookup") {
            common::report_skip("system tests disabled (set OMG_RUN_SYSTEM_TESTS=1)");
            return Ok(());
        }
        let pm = DnfPackageManager::new();
        assert!(
            !pm.list_installed()
                .await?
                .iter()
                .any(|package| package.name == "tree"),
            "run this regression in the fresh Fedora smoke image with tree absent"
        );
        let search = pm.search("tree").await?;
        assert!(
            search
                .iter()
                .any(|package| package.name == "tree" && !package.installed)
        );
        let info = pm
            .info("tree")
            .await?
            .expect("available repository package");
        assert_eq!(info.name, "tree");
        assert!(!info.installed);

        for arguments in [vec!["info", "tree"], vec!["--json", "info", "tree"]] {
            let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("omg"))
                .args(arguments)
                .output()?;
            assert!(
                output.status.success(),
                "CLI info failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("tree"));
        }
        Ok(())
    }

    #[tokio::test]
    async fn explicit_cli_matches_native_backend_without_a_daemon() -> Result<()> {
        if common::TestConfig::default().skip_if_no_system("dnf_explicit_cli") {
            common::report_skip("system tests disabled (set OMG_RUN_SYSTEM_TESTS=1)");
            return Ok(());
        }
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
        if common::TestConfig::default().skip_if_no_system("dnf_size_cli") {
            common::report_skip("system tests disabled (set OMG_RUN_SYSTEM_TESTS=1)");
            return Ok(());
        }
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
        let providers = std::process::Command::new("dnf")
            .args([
                "--setopt=disable_excludes=*",
                "repoquery",
                "--installed",
                "--providers-of=requires",
                "--qf",
                "%{full_nevra}\n",
                "glibc",
            ])
            .output()?;
        assert!(providers.status.success());
        let providers = String::from_utf8(providers.stdout)?;
        let root = std::process::Command::new("rpm")
            .args([
                "-q",
                "glibc",
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
            .args(["size", "--tree", "glibc", "--limit", "10000"])
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

        if common::TestConfig::default().skip_if_no_system("dnf_installed_metadata_exclusions") {
            common::report_skip("system tests disabled (set OMG_RUN_SYSTEM_TESTS=1)");
            return Ok(());
        }
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
        if common::TestConfig::default().skip_if_no_system("dnf_why_cli") {
            common::report_skip("system tests disabled (set OMG_RUN_SYSTEM_TESTS=1)");
            return Ok(());
        }
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

        if common::TestConfig::default().skip_if_no_system("dnf_blame_cli") {
            common::report_skip("system tests disabled (set OMG_RUN_SYSTEM_TESTS=1)");
            return Ok(());
        }
        let cache = dirs::cache_dir().expect("user cache directory");
        std::fs::create_dir_all(&cache)?;
        let fixture = tempfile::tempdir_in(cache)?;
        let selector = format!("glibc.{}", std::env::consts::ARCH);
        let invoke = || {
            std::process::Command::new(assert_cmd::cargo::cargo_bin!("omg"))
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
        if common::TestConfig::default().skip_if_no_system("dnf_transaction_history") {
            common::report_skip("system tests disabled (set OMG_RUN_SYSTEM_TESTS=1)");
            return Ok(());
        }
        let absent = std::process::Command::new("rpm")
            .args(["-q", "tree"])
            .output()?;
        anyhow::ensure!(
            absent.status.code() == Some(1),
            "tree must be absent before this lifecycle fixture"
        );
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
        let cache = dirs::cache_dir().expect("user cache directory");
        std::fs::create_dir_all(&cache)?;
        let fixture = tempfile::tempdir_in(cache)?;
        let history = HistoryManager::new_in(fixture.path().join("history.json"))?;
        let run = |arguments: &[&str]| {
            std::process::Command::new(assert_cmd::cargo::cargo_bin!("omg"))
                .env("OMG_DATA_DIR", fixture.path())
                .env("NO_COLOR", "1")
                .stdin(std::process::Stdio::null())
                .args(arguments)
                .output()
        };
        let verified = (|| -> Result<()> {
            let install = run(&["install", "tree", "--yes"])?;
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
                .find(|change| change.name == "tree")
                .ok_or_else(|| anyhow::anyhow!("Installation history omitted tree"))?;
            let native = std::process::Command::new("rpm")
                .args(["-q", "tree", "--qf", "%{EPOCHNUM}:%{VERSION}-%{RELEASE}"])
                .output()?;
            anyhow::ensure!(native.status.success(), "Native installed version failed");
            anyhow::ensure!(
                change.old_version.is_none()
                    && change.new_version.as_deref() == Some(std::str::from_utf8(&native.stdout)?),
                "Recorded version differs from RPM"
            );
            let noop = run(&["install", "tree", "--yes"])?;
            anyhow::ensure!(noop.status.success(), "No-op install failed");
            anyhow::ensure!(history.load()?.len() == 1, "No-op invented a transaction");
            let blame = run(&["blame", "tree"])?;
            anyhow::ensure!(
                blame.status.success()
                    && String::from_utf8(blame.stdout)?.contains("OMG Transaction History (1)"),
                "blame did not find real installation history"
            );
            Ok(())
        })();
        let present = std::process::Command::new("rpm")
            .args(["-q", "tree"])
            .output()?;
        if present.status.success() {
            let removed = run(&["remove", "tree", "--yes"])?;
            anyhow::ensure!(snapshot()? == before, "RPM inventory was not restored");
            anyhow::ensure!(
                removed.status.success(),
                "Fixture cleanup failed: {}",
                String::from_utf8_lossy(&removed.stderr)
            );
        } else {
            anyhow::ensure!(
                present.status.code() == Some(1),
                "Cannot determine fixture package state"
            );
            anyhow::ensure!(snapshot()? == before, "RPM inventory was not restored");
        }
        verified?;
        let records = history.load()?;
        anyhow::ensure!(records.len() == 2, "Expected install and remove history");
        let removed = &records[1];
        anyhow::ensure!(
            removed.success && removed.transaction_type == TransactionType::Remove,
            "Incorrect removal outcome"
        );
        anyhow::ensure!(
            removed.changes.iter().any(|change| change.name == "tree"
                && change.old_version.is_some()
                && change.new_version.is_none()),
            "Removal history omitted tree"
        );
        fixture.close()?;
        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial(history_ownership)]
    async fn native_history_honors_custom_and_disabled_service_history() -> Result<()> {
        use omg_lib::core::history::HistoryManager;
        use omg_lib::core::packages::PackageService;
        if common::TestConfig::default().skip_if_no_system("dnf_history_ownership") {
            common::report_skip("system tests disabled (set OMG_RUN_SYSTEM_TESTS=1)");
            return Ok(());
        }
        let absent = std::process::Command::new("rpm")
            .args(["-q", "tree"])
            .output()?;
        anyhow::ensure!(absent.status.code() == Some(1), "tree must be absent");
        let fixture = tempfile::tempdir_in(dirs::cache_dir().expect("user cache directory"))?;
        let custom_path = fixture.path().join("custom.json");
        let default = HistoryManager::new()?;
        let default_before = serde_json::to_vec(&default.load()?)?;
        let manager = std::sync::Arc::new(DnfPackageManager::new());
        let packages = vec!["tree".to_owned()];
        enum Owner {
            Service,
            Disabled,
            Parent,
        }
        for owner in [Owner::Service, Owner::Disabled, Owner::Parent] {
            manager.install(&packages).await?;
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
                .args(["-q", "tree"])
                .output()?;
            if remaining.status.success() {
                manager.remove(&packages).await?;
            }
            outcome?;
            anyhow::ensure!(
                remaining.status.code() == Some(1),
                "Service removal did not remove tree"
            );
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
        if common::TestConfig::default().skip_if_no_system("dnf_cleanup_preview") {
            common::report_skip("system tests disabled (set OMG_RUN_SYSTEM_TESTS=1)");
            return Ok(());
        }
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
    async fn test_list_installed_packages() {
        let pm = DnfPackageManager::new();

        let installed = pm.list_installed().await.unwrap();

        assert!(
            !installed.is_empty(),
            "Should have installed packages on Fedora system"
        );
        assert!(
            installed.iter().any(|package| package.name == "bash"),
            "RPM inventory must include the installed bash package"
        );
        assert!(
            installed.iter().all(|package| package.installed),
            "installed inventory must not contain available-only packages"
        );
    }

    #[tokio::test]
    async fn test_list_updates() -> Result<()> {
        // Gate inline (instead of require_system_tests!, whose `return;` is
        // incompatible with this test's Result signature).
        if common::TestConfig::default().skip_if_no_system("dnf_list_updates") {
            common::report_skip("system tests disabled (set OMG_RUN_SYSTEM_TESTS=1)");
            return Ok(());
        }

        let pm = DnfPackageManager::new();

        // The call must succeed on a real system, and every reported update
        // must be well-formed: named package with distinct old/new versions.
        let updates = pm.list_updates().await?;
        for update in &updates {
            assert!(
                !update.name.is_empty(),
                "every update entry needs a package name"
            );
            assert!(
                update.old_version != update.new_version,
                "update for {} must change version ({} -> {})",
                update.name,
                update.old_version,
                update.new_version
            );
        }

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
    async fn test_rpm_database_query() {
        let pm = DnfPackageManager::new();

        let installed = pm.list_installed().await.unwrap();

        assert!(
            !installed.is_empty(),
            "Should read packages from RPM database"
        );

        let has_rpm = installed.iter().any(|p| p.name == "rpm" && p.installed);
        assert!(has_rpm, "Should find rpm package itself in database");
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
