pub mod common;

#[test]
fn sbom_without_daemon_exports_shared_inventory_and_preserves_report_on_failure()
-> anyhow::Result<()> {
    let project = common::TestProject::new();
    let state = project.data_dir.path().join("mock_state_pacman.json");
    let clean = br#"{"installed":{},"available":{}}"#;
    std::fs::write(&state, clean)?;
    let output = project.dir.path().join("security-sbom.json");
    let output_arg = output.to_str().expect("fixture path is UTF-8");
    let args = ["audit", "sbom", "--output", output_arg];
    let result = project.run(&args);
    result.assert_success();
    let bytes = std::fs::read(&output)?;
    let report: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(report["bomFormat"], "CycloneDX");
    assert_eq!(report["specVersion"], "1.5");
    assert_eq!(report["components"], serde_json::json!([]));
    assert!(
        report
            .get("vulnerabilities")
            .is_none_or(|value| value == &serde_json::json!([]))
    );
    std::fs::write(&state, b"{broken")?;
    let failed = project.run(&args);
    failed.assert_failure();
    assert!(
        failed.stderr.contains("Failed to list packages"),
        "{}",
        failed.stderr
    );
    assert_eq!(
        std::fs::read(&output)?,
        bytes,
        "failed scan replaced the previous report"
    );
    assert_eq!(std::fs::read(&state)?, b"{broken");
    std::fs::write(&state, clean)?;
    project.run(&args).assert_success();
    project.close_checked();
    Ok(())
}

#[test]
fn tui_security_scan_uses_shared_inventory_failures_without_a_daemon() -> anyhow::Result<()> {
    let project = common::TestProject::new();
    let path = project.data_dir.path().join("mock_state_pacman.json");
    let clean = br#"{"installed":{},"available":{}}"#;
    std::fs::write(&path, clean)?;
    temp_env::with_vars(
        [
            ("OMG_TEST_MODE", Some(std::ffi::OsStr::new("1"))),
            ("OMG_TEST_DISTRO", Some(std::ffi::OsStr::new("arch"))),
            ("OMG_DISABLE_DAEMON", Some(std::ffi::OsStr::new("1"))),
            ("OMG_DATA_DIR", Some(project.data_dir.path().as_os_str())),
        ],
        || -> anyhow::Result<()> {
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(async {
                assert_eq!(omg_lib::cli::tui::app::App::run_security_audit().await?, 0);
                std::fs::write(&path, b"{broken")?;
                let error = omg_lib::cli::tui::app::App::run_security_audit()
                    .await
                    .expect_err("corrupt inventory must fail");
                assert!(
                    error.to_string().contains("Failed to list packages"),
                    "{error:#}"
                );
                assert_eq!(std::fs::read(&path)?, b"{broken");
                std::fs::write(&path, clean)?;
                assert_eq!(omg_lib::cli::tui::app::App::run_security_audit().await?, 0);
                anyhow::Ok(())
            })
        },
    )?;
    assert_eq!(std::fs::read(&path)?, clean);
    project.close_checked();
    Ok(())
}

#[test]
fn security_scan_without_daemon_preserves_inventory_errors_and_recovers() -> anyhow::Result<()> {
    let project = common::TestProject::new();
    let path = project.data_dir.path().join("mock_state_pacman.json");
    let clean = br#"{"installed":{},"available":{}}"#;
    std::fs::write(&path, clean)?;
    let result = project.run(&["audit", "scan"]);
    result.assert_success();
    assert!(
        result
            .stdout
            .contains("No vulnerabilities found in scanned packages.")
    );
    project.run(&["audit", "fix", "--dry-run"]).assert_success();
    for args in [vec!["audit", "scan"], vec!["audit", "fix", "--dry-run"]] {
        std::fs::write(&path, b"{broken")?;
        let failed = project.run(&args);
        failed.assert_failure();
        assert!(
            failed.stderr.contains("Failed to list packages"),
            "{}",
            failed.stderr
        );
        assert!(!failed.stdout.contains("No vulnerabilities found"));
        assert_eq!(std::fs::read(&path)?, b"{broken");
        std::fs::write(&path, clean)?;
        project.run(&args).assert_success();
    }
    assert_eq!(std::fs::read(&path)?, clean);
    project.close_checked();
    Ok(())
}
