pub mod common;

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
