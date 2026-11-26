//! `omg enterprise` - Enterprise features (reports, policies, compliance)

use crate::cli::components::Components;
use crate::cli::tea::Cmd;
use crate::cli::{CliContext, EnterpriseCommands, EnterprisePolicyCommands, LocalCommandRunner};
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::cli::security::{LicenseCategory, spreadsheet_safe_cell};
use crate::cli::style::sanitize_terminal_text;
use crate::core::env::distro::Distro;
use crate::core::license;
use crate::package_managers::types::SecurityPackage;

fn artifact_stamp() -> String {
    format!(
        "{}-{}",
        jiff::Timestamp::now().as_nanosecond(),
        std::process::id()
    )
}

impl LocalCommandRunner for EnterpriseCommands {
    async fn execute(&self, ctx: &CliContext) -> Result<()> {
        match self {
            EnterpriseCommands::Reports { report_type } => reports(report_type.as_str(), ctx).await,
            EnterpriseCommands::Policy { command } => match command {
                EnterprisePolicyCommands::Show { scope } => {
                    policy::show(scope.as_deref(), ctx).await
                }
            },
            EnterpriseCommands::AuditExport {
                framework,
                period,
                output,
            } => audit_export(framework.as_str(), period.as_deref(), output, ctx).await,
            EnterpriseCommands::LicenseScan { export } => {
                license_scan(export.as_ref().map(|value| value.as_str()), ctx).await
            }
        }
    }
}

/// Generate executive reports
pub async fn reports(report_type: &str, _ctx: &CliContext) -> Result<()> {
    use crate::cli::packages::execute_cmd;

    execute_cmd(Components::loading(format!(
        "Generating {report_type} report..."
    )))?;

    let report = generate_report(report_type).await?;
    let filename = format!("omg-report-{report_type}-{}.json", artifact_stamp());

    let content = serde_json::to_string_pretty(&report)?;
    crate::core::safe_ops::atomic_write_file_sync(&filename, &content)?;

    let mut report_sections = vec!["Observed fleet machine count".to_string()];
    if report.summary.validation_failures.is_some() {
        report_sections.extend([
            "Local daemon validation failure count".to_string(),
            "Local daemon rate-limit event count".to_string(),
            "Local daemon security audit request count".to_string(),
        ]);
    } else {
        report_sections.push("Local daemon counters unavailable".to_string());
    }

    execute_cmd(Cmd::batch([
        Cmd::success(format!("Generated {filename}")),
        Cmd::spacer(),
        Components::kv_list(
            Some("Report Details"),
            vec![
                ("Type", report_type),
                ("Format", "json"),
                ("File", &filename),
            ],
        ),
        Cmd::spacer(),
        Cmd::card("Report Contents", report_sections),
    ]))?;

    Ok(())
}

/// Export audit evidence for compliance
pub async fn audit_export(
    format: &str,
    period: Option<&str>,
    output: &str,
    _ctx: &CliContext,
) -> Result<()> {
    use crate::cli::packages::execute_cmd;

    if let Err(error) =
        crate::cli::security::validate_compliance_export_inputs(format, period, output)
    {
        execute_cmd(Cmd::error(format!(
            "Invalid compliance export input: {error}"
        )))?;
        return Err(error);
    }

    execute_cmd(Components::loading(format!(
        "Exporting {format} audit evidence..."
    )))?;

    let period_str = period.unwrap_or("current");
    // Generate both inventory documents from the same installed package observation.
    let (distro, inventory) = collect_compliance_inventory().await?;
    let sbom = crate::core::security::sbom::from_installed_inventory(&inventory, distro)?;
    let inventory_csv =
        serialize_installed_packages_csv_rows(inventory.into_iter().map(|package| {
            let name = inventory_package_name(&package, distro);
            (name, package.version, package.description)
        }))?;
    let files = vec![
        ("limitations.json", generate_audit_export_limitations()?),
        ("change-log.json", generate_change_log_json()?),
        ("policy-enforcement.json", generate_policy_json()?),
        ("installed-packages.csv", inventory_csv),
        ("sbom-inventory.json", serde_json::to_string_pretty(&sbom)?),
    ];
    fs::create_dir_all(output)?;

    let mut file_list = vec![];
    for (filename, content) in &files {
        let path = Path::new(output).join(filename);
        // Inventory-bearing exports use the same owner-only writer as
        // `omg audit export`: contents must never inherit a permissive mode.
        crate::core::safe_ops::atomic_write_file_sync_private(&path, content)?;
        file_list.push(path.display().to_string());
    }

    execute_cmd(Cmd::batch([
        Cmd::success("Audit evidence exported"),
        Cmd::spacer(),
        Components::kv_list(
            Some("Export Details"),
            vec![
                ("Framework", format),
                ("Period", period_str),
                ("Output", output),
            ],
        ),
        Cmd::spacer(),
        Cmd::card("Generated Files", file_list),
        Cmd::spacer(),
        Components::complete("Ready for auditor review"),
    ]))?;

    Ok(())
}

/// Scan for license compliance issues
pub async fn license_scan(export: Option<&str>, _ctx: &CliContext) -> Result<()> {
    use crate::cli::packages::execute_cmd;

    if let Some(fmt) = export {
        // Only formats with real serializers are offered; 'spdx' previously
        // emitted JSON under an .spdx name, misrepresenting the artifact.
        if !matches!(fmt.to_lowercase().as_str(), "json" | "csv") {
            anyhow::bail!("Unsupported license export format '{fmt}'. Valid formats: json, csv");
        }
    }

    let (distro, inventory) = collect_compliance_inventory().await?;
    let scan = perform_license_scan(inventory, distro);

    // Display results. Percentages are license assignments over all observed
    // assignments, not packages: a package may legitimately declare more than
    // one license, so package-count denominators can exceed 100%.
    let license_inventory = license_inventory_rows(&scan);

    let mut violations = vec![];
    for violation in &scan.violations {
        violations.push(format!(
            "{} - {}",
            sanitize_terminal_text(&violation.package),
            violation.reason
        ));
    }

    let mut unknown = vec![];
    for pkg in scan.unknown.iter().take(5) {
        unknown.push(sanitize_terminal_text(pkg));
    }
    if scan.unknown.len() > 5 {
        unknown.push(format!("... and {} more", scan.unknown.len() - 5));
    }

    execute_cmd(Cmd::batch([
        Cmd::header(
            "License Compliance Scan",
            format!("{} total packages", scan.total),
        ),
        Cmd::spacer(),
        Components::limited_card("License Inventory", license_inventory, 20),
        Cmd::card(
            "Unresolved License Review",
            vec![format!(
                "{} unresolved assignments; {} packages without license metadata",
                scan.unresolved_review.len(),
                scan.unknown.len()
            )],
        ),
        if violations.is_empty() {
            Cmd::none()
        } else {
            Cmd::batch([
                Cmd::spacer(),
                Components::limited_card("Policy Violations", violations, 20),
            ])
        },
        if unknown.is_empty() {
            Cmd::none()
        } else {
            Cmd::batch([Cmd::spacer(), Cmd::card("Unknown Licenses", unknown)])
        },
        if let Some(format) = export {
            Cmd::batch([Cmd::spacer(), {
                let filename = format!("license-scan-{}.{}", artifact_stamp(), format);
                let content = if format.eq_ignore_ascii_case("csv") {
                    generate_license_csv(&scan)?
                } else {
                    serde_json::to_string_pretty(&scan)?
                };
                crate::core::safe_ops::atomic_write_file_sync_private(&filename, content)?;
                Cmd::success(format!("Exported to {filename}"))
            }])
        } else {
            Cmd::none()
        },
    ]))?;

    Ok(())
}

/// Enterprise policy management
pub mod policy {
    use super::{CliContext, Result, license};
    use crate::cli::packages::execute_cmd;
    use crate::cli::tea::Cmd;

    pub async fn show(scope: Option<&str>, _ctx: &CliContext) -> Result<()> {
        if let Some(s) = scope
            && (s.len() > 64
                || s.chars()
                    .any(|c| !c.is_ascii_alphanumeric() && c != ':' && c != '-'))
        {
            execute_cmd(Cmd::error("Invalid policy scope"))?;
            anyhow::bail!("Invalid policy scope");
        }

        let policies = license::fetch_policies().await?;

        if policies.is_empty() {
            execute_cmd(Cmd::batch([
                Cmd::header("Policy Configuration", "No active policies"),
                Cmd::spacer(),
                Cmd::info("Enterprise policies can be configured in the dashboard"),
            ]))?;
            return Ok(());
        }

        let mut policy_list = vec![];
        for p in &policies {
            if let Some(s) = scope
                && p.scope != s
            {
                continue;
            }

            let enforced = if p.enforced { "Yes" } else { "No (Audit only)" };
            policy_list.push(format!(
                "{} (Scope: {}) - Enforced: {}",
                p.rule, p.scope, enforced
            ));
        }

        let policy_count = policy_list.len();
        execute_cmd(Cmd::batch([
            Cmd::header(
                "Policy Configuration",
                format!("{policy_count} active policies"),
            ),
            Cmd::spacer(),
            Cmd::card("Active Policies", policy_list),
        ]))?;

        Ok(())
    }
}

// Helper types and functions

#[derive(Debug, Serialize)]
struct Report {
    generated_at: i64,
    #[serde(rename = "report_type")]
    kind: String,
    summary: ReportSummary,
}

#[derive(Debug, Serialize)]
struct ReportSummary {
    total_machines: usize,
    daemon_metrics_scope: &'static str,
    validation_failures: Option<u64>,
    rate_limit_hits: Option<u64>,
    security_audit_requests: Option<u64>,
}

impl ReportSummary {
    fn new(total_machines: usize) -> Self {
        Self {
            total_machines,
            daemon_metrics_scope: "local_daemon",
            validation_failures: None,
            rate_limit_hits: None,
            security_audit_requests: None,
        }
    }

    #[cfg(unix)]
    async fn with_daemon_metrics(mut self) -> Self {
        let response = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let mut client = crate::core::client::DaemonClient::connect().await?;
            client.metrics().await
        })
        .await;
        if let Ok(Ok(metrics)) = response {
            self.validation_failures = Some(metrics.validation_failures);
            self.rate_limit_hits = Some(metrics.rate_limit_hits);
            self.security_audit_requests = Some(metrics.security_audit_requests);
        }
        self
    }
}

async fn generate_report(report_type: &str) -> Result<Report> {
    // A failed team lookup must not become a fabricated zero-machine report.
    let members = license::fetch_team_members()
        .await
        .context("Failed to fetch team members for enterprise report")?;
    let summary = ReportSummary::new(members.len());
    #[cfg(unix)]
    let summary = summary.with_daemon_metrics().await;

    Ok(Report {
        generated_at: jiff::Timestamp::now().as_second(),
        kind: report_type.to_string(),
        summary,
    })
}

fn generate_audit_export_limitations() -> Result<String> {
    serde_json::to_string_pretty(&serde_json::json!({
        "unavailable_evidence": [{
            "artifact": "access-control-matrix",
            "reason": "No authoritative identity-provider role source is configured; OMG will not fabricate access-control evidence."
        }]
    }))
    .context("Failed to serialize audit export limitations")
}

fn generate_change_log_json() -> Result<String> {
    let logger = crate::core::security::audit::AuditLogger::new()
        .context("Failed to open audit log for enterprise export")?;
    let entries = match logger.get_recent(100) {
        Ok(entries) => entries,
        Err(error) if error.is_not_found() => Vec::new(),
        Err(error) => {
            return Err(error).context("Failed to read audit log entries for enterprise export");
        }
    };
    serde_json::to_string(&entries).context("Failed to serialize audit log entries")
}

fn generate_policy_json() -> Result<String> {
    let policy = crate::core::security::SecurityPolicy::load_default()
        .context("Failed to load security policy for enterprise export")?;
    serde_json::to_string_pretty(&policy).context("Failed to serialize security policy")
}

fn serialize_installed_packages_csv_rows(
    rows: impl IntoIterator<Item = (String, String, String)>,
) -> Result<String> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer.write_record(["package", "version", "description"])?;
    for (name, version, description) in rows {
        let name = spreadsheet_safe_cell(&name);
        let version = spreadsheet_safe_cell(&version);
        let description = spreadsheet_safe_cell(&description);
        writer.write_record([&*name, &*version, &*description])?;
    }
    let bytes = writer
        .into_inner()
        .map_err(|error| anyhow::anyhow!("Failed to finish installed-package CSV: {error}"))?;
    String::from_utf8(bytes).context("Installed-package CSV was not UTF-8")
}

async fn collect_compliance_inventory() -> Result<(Distro, Vec<SecurityPackage>)> {
    #[cfg(any(feature = "arch", feature = "fedora"))]
    use crate::package_managers::Backend;

    tokio::task::spawn_blocking(|| match crate::package_managers::resolve_backend()? {
        #[cfg(feature = "fedora")]
        Backend::Fedora => Ok((
            Distro::Fedora,
            crate::package_managers::DnfPackageManager::new().installed_compliance_inventory()?,
        )),
        #[cfg(feature = "arch")]
        Backend::Arch | Backend::Mock => Ok((
            Distro::Arch,
            crate::package_managers::alpm_direct::security_inventory()?,
        )),
        backend => {
            anyhow::bail!("Native installed compliance inventory is unavailable for {backend:?}")
        }
    })
    .await
    .context("Installed inventory worker failed")?
}

fn inventory_package_name(package: &SecurityPackage, distro: Distro) -> String {
    match (distro, package.architecture.as_deref()) {
        (Distro::Fedora, Some(architecture)) => format!("{}.{architecture}", package.name),
        _ => package.name.clone(),
    }
}

#[derive(Debug, Serialize)]
struct LicenseScan {
    total: usize,
    by_license: HashMap<String, usize>,
    violations: Vec<LicenseViolation>,
    unknown: Vec<String>,
    unresolved_review: Vec<LicenseReview>,
}

#[derive(Debug, Serialize)]
struct LicenseReview {
    package: String,
    license: String,
}

#[derive(Debug, Serialize)]
struct LicenseViolation {
    package: String,
    license: String,
    reason: String,
}

/// Keep license classification consistent with the audit command.
fn enterprise_license_review_reason(license: &str) -> Option<&'static str> {
    match LicenseCategory::from_license(license) {
        LicenseCategory::StrongCopyleft => {
            Some("Strong copyleft license (AGPL) requires legal review")
        }
        LicenseCategory::Copyleft => Some("Copyleft license requires legal review"),
        _ => None,
    }
}

fn perform_license_scan(packages: Vec<SecurityPackage>, distro: Distro) -> LicenseScan {
    let mut scan = LicenseScan {
        total: packages.len(),
        by_license: HashMap::new(),
        violations: Vec::new(),
        unknown: Vec::new(),
        unresolved_review: Vec::new(),
    };
    for package in packages {
        let name = inventory_package_name(&package, distro);
        if package.licenses.is_empty() {
            scan.unknown.push(name);
            continue;
        }
        for license in package.licenses {
            if crate::core::security::policy::assess_license_expression(&license).unresolved_review
            {
                scan.unresolved_review.push(LicenseReview {
                    package: name.clone(),
                    license: license.clone(),
                });
            }
            if let Some(reason) = enterprise_license_review_reason(&license) {
                scan.violations.push(LicenseViolation {
                    package: name.clone(),
                    license: license.clone(),
                    reason: reason.to_owned(),
                });
            }
            *scan.by_license.entry(license).or_default() += 1;
        }
    }
    scan
}

fn license_inventory_rows(scan: &LicenseScan) -> Vec<String> {
    let assignments = scan.by_license.values().copied().sum::<usize>();
    let mut rows = scan
        .by_license
        .iter()
        .map(|(license, count)| {
            let percentage = if assignments == 0 {
                0.0
            } else {
                (*count as f32 / assignments as f32) * 100.0
            };
            let review = if crate::core::security::policy::assess_license_expression(license)
                .unresolved_review
            {
                " [unresolved license review]"
            } else {
                ""
            };
            let license = sanitize_terminal_text(license);
            format!("{license}: {count} assignments ({percentage:.0}%){review}")
        })
        .collect::<Vec<_>>();
    rows.sort_unstable();
    rows
}

fn generate_license_csv(scan: &LicenseScan) -> Result<String> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer.write_record(["license", "count", "unresolved_review"])?;
    let mut licenses: Vec<_> = scan.by_license.iter().collect();
    licenses.sort_unstable_by_key(|(left, _)| *left);
    for (license, count) in licenses {
        let unresolved_review =
            crate::core::security::policy::assess_license_expression(license).unresolved_review;
        let license = spreadsheet_safe_cell(license);
        writer.write_record([
            &*license,
            count.to_string().as_str(),
            if unresolved_review { "true" } else { "false" },
        ])?;
    }
    let bytes = writer
        .into_inner()
        .map_err(|error| anyhow::anyhow!("Failed to finish license CSV: {error}"))?;
    String::from_utf8(bytes).context("License CSV was not UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executive_summary_distinguishes_unavailable_daemon_counters() {
        let summary = serde_json::to_value(ReportSummary::new(3)).unwrap();
        assert_eq!(summary["total_machines"], 3);
        assert_eq!(summary["daemon_metrics_scope"], "local_daemon");
        for metric in [
            "validation_failures",
            "rate_limit_hits",
            "security_audit_requests",
        ] {
            assert_eq!(summary.get(metric), Some(&serde_json::Value::Null));
        }
    }

    #[cfg(unix)]
    #[test]
    fn executive_summary_reads_observed_local_daemon_counters() {
        use crate::daemon::protocol::{
            MetricsSnapshot, Request, Response, ResponseResult, encode_frame, split_frame,
        };
        use futures::{SinkExt as _, StreamExt as _};
        use std::os::unix::fs::PermissionsExt as _;
        use tokio_util::codec::{Framed, LengthDelimitedCodec};

        const TEST: &str =
            "cli::enterprise::tests::executive_summary_reads_observed_local_daemon_counters";
        if crate::core::testing::run_isolated_test(TEST) {
            return;
        }

        let directory = tempfile::tempdir().expect("private daemon directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private socket ownership");
        let socket = directory.path().join("report.sock");
        temp_env::with_vars(
            [
                ("OMG_SOCKET_PATH", socket.to_str()),
                ("OMG_DISABLE_DAEMON", None),
                ("OMG_TEST_MODE", None),
            ],
            || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
                    let serve = async {
                        let (stream, _) = listener.accept().await.unwrap();
                        let mut peer = Framed::new(stream, LengthDelimitedCodec::new());
                        let frame = peer.next().await.unwrap().unwrap();
                        let (_, payload) = split_frame(&frame).unwrap();
                        let Request::Metrics { id } =
                            bitcode::deserialize::<Request>(payload).unwrap()
                        else {
                            panic!("the report must query the daemon's metrics");
                        };
                        let response = Response::Success {
                            id,
                            result: ResponseResult::Metrics(MetricsSnapshot {
                                validation_failures: 4,
                                rate_limit_hits: 0,
                                security_audit_requests: 6,
                                requests_total: 0,
                                requests_failed: 0,
                                active_connections: 0,
                                bytes_received: 0,
                                bytes_sent: 0,
                                cache_hits: 0,
                                cache_misses: 0,
                                search_requests: 0,
                                info_requests: 0,
                                status_requests: 0,
                            }),
                        };
                        peer.send(encode_frame(&response).unwrap().into())
                            .await
                            .unwrap();
                    };
                    let ((), summary) =
                        tokio::time::timeout(std::time::Duration::from_secs(3), async {
                            tokio::join!(serve, ReportSummary::new(3).with_daemon_metrics())
                        })
                        .await
                        .expect("report and daemon must finish");
                    let summary = serde_json::to_value(summary).unwrap();
                    assert_eq!(summary["total_machines"], 3);
                    assert_eq!(summary["daemon_metrics_scope"], "local_daemon");
                    assert_eq!(summary["validation_failures"], 4);
                    assert_eq!(summary["rate_limit_hits"], 0);
                    assert_eq!(summary["security_audit_requests"], 6);

                    drop(listener);
                    std::fs::remove_file(&socket).unwrap();
                    let unavailable = ReportSummary::new(3).with_daemon_metrics().await;
                    assert!(unavailable.validation_failures.is_none());
                });
            },
        );
    }

    #[test]
    fn audit_export_limitations_do_not_fabricate_access_control_evidence() {
        let limitations = generate_audit_export_limitations().expect("limitations JSON");

        assert!(limitations.contains("access-control-matrix"));
        assert!(limitations.contains("authoritative"));
        assert!(!limitations.contains("owner,global,all"));
    }

    #[test]
    fn enterprise_csv_exports_quote_fields_and_neutralize_formulas() {
        let installed = serialize_installed_packages_csv_rows([(
            "=package".to_string(),
            "+1.0".to_string(),
            "description, with comma".to_string(),
        )])
        .expect("installed package CSV");
        assert!(installed.contains("'=package,'+1.0,\"description, with comma\""));

        let scan = LicenseScan {
            total: 1,
            by_license: HashMap::from([("=HYPERLINK(\"https://example.com\")".to_string(), 1)]),
            violations: Vec::new(),
            unknown: Vec::new(),
            unresolved_review: Vec::new(),
        };
        let licenses = generate_license_csv(&scan).expect("license CSV");
        assert!(licenses.contains("\"'=HYPERLINK(\"\"https://example.com\"\")\",1"));
    }

    #[test]
    fn enterprise_review_reason_classifies_the_copyleft_family() {
        // The three cases a "GPL" substring test got wrong.
        assert_eq!(
            enterprise_license_review_reason("MPL-2.0"),
            Some("Copyleft license requires legal review"),
            "MPL-2.0 is copyleft but contains no GPL substring"
        );
        assert_eq!(
            enterprise_license_review_reason("AGPL-3.0"),
            Some("Strong copyleft license (AGPL) requires legal review"),
            "AGPL must not be reported as plain copyleft"
        );
        assert_eq!(
            enterprise_license_review_reason("LGPL-2.1"),
            Some("Copyleft license requires legal review"),
            "LGPL is copyleft and must not be named GPL"
        );
    }

    #[test]
    fn enterprise_review_reason_matches_the_audit_classifier() {
        // AGPL and ordinary copyleft must agree with `omg audit`, and
        // permissive or unknown licenses must not be flagged for review.
        for license in ["GPL-2.0", "GPL-3.0", "LGPL-2.1", "MPL-2.0", "AGPL-3.0"] {
            let audit_says_copyleft = matches!(
                LicenseCategory::from_license(license),
                LicenseCategory::Copyleft | LicenseCategory::StrongCopyleft
            );
            assert_eq!(
                enterprise_license_review_reason(license).is_some(),
                audit_says_copyleft,
                "enterprise and audit disagree for {license}"
            );
        }
        for license in [
            "MIT",
            "Apache-2.0",
            "BSD-3-Clause",
            "Unlicense",
            "SSPL-1.0",
            "BUSL-1.1",
            "LicenseRef-Proprietary",
            "LIMITED",
        ] {
            assert_eq!(
                enterprise_license_review_reason(license),
                None,
                "{license} should not require copyleft review"
            );
        }
    }

    #[test]
    fn unresolved_license_assignments_survive_enterprise_inventory_and_exports() {
        let expression = "MIT AND LicenseRef-private";
        let scan = LicenseScan {
            total: 1,
            by_license: HashMap::from([(expression.into(), 2)]),
            violations: Vec::new(),
            unknown: Vec::new(),
            unresolved_review: vec![
                LicenseReview {
                    package: "mixed".into(),
                    license: expression.into(),
                },
                LicenseReview {
                    package: "mixed".into(),
                    license: expression.into(),
                },
            ],
        };
        assert_eq!(scan.unresolved_review.len(), 2);
        assert_eq!(
            license_inventory_rows(&scan),
            ["MIT AND LicenseRef-private: 2 assignments (100%) [unresolved license review]"]
        );
        let json = serde_json::to_value(&scan).unwrap();
        assert_eq!(json["unresolved_review"][0]["package"], "mixed");
        assert_eq!(json["unresolved_review"][0]["license"], expression);
        assert_eq!(json["by_license"][expression], 2);
        let csv = generate_license_csv(&scan).unwrap();
        assert!(csv.contains("license,count,unresolved_review"));
        assert!(csv.contains("MIT AND LicenseRef-private,2,true"));
    }

    #[test]
    fn license_inventory_display_sanitizes_metadata_and_retains_evidence() {
        let license = "MIT\u{202e}";
        let scan = LicenseScan {
            total: 1,
            by_license: HashMap::from([(license.to_owned(), 1)]),
            violations: Vec::new(),
            unknown: Vec::new(),
            unresolved_review: Vec::new(),
        };

        let rows = license_inventory_rows(&scan);
        assert!(rows[0].starts_with("MIT: 1 assignments"), "{rows:?}");
        assert_eq!(
            serde_json::to_value(&scan).unwrap()["by_license"][license],
            1
        );
    }

    #[test]
    fn license_inventory_handles_empty_and_multi_license_scans() {
        let empty = LicenseScan {
            total: 0,
            by_license: HashMap::new(),
            violations: Vec::new(),
            unknown: Vec::new(),
            unresolved_review: Vec::new(),
        };
        assert!(license_inventory_rows(&empty).is_empty());

        let scan = LicenseScan {
            total: 2,
            by_license: HashMap::from([("MIT".to_string(), 2), ("Apache-2.0".to_string(), 1)]),
            violations: Vec::new(),
            unknown: Vec::new(),
            unresolved_review: Vec::new(),
        };
        let rows = license_inventory_rows(&scan);
        assert!(
            rows.iter()
                .any(|row| row.contains("MIT: 2 assignments (67%)"))
        );
        assert!(
            rows.iter()
                .any(|row| row.contains("Apache-2.0: 1 assignments (33%)"))
        );
        assert!(!rows.iter().any(|row| row.contains("NaN")));
    }
}
