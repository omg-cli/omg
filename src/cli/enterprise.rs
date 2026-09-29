//! `omg enterprise` - Enterprise features (reports, policies, compliance)

use crate::cli::components::Components;
use crate::cli::tea::Cmd;
use crate::cli::{CliContext, EnterpriseCommands, EnterprisePolicyCommands, LocalCommandRunner};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::cli::security::{LicenseCategory, spreadsheet_safe_cell};
use crate::core::license;

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
            } => audit_export(framework.as_str(), period.as_deref(), output, ctx),
            EnterpriseCommands::LicenseScan { export } => {
                license_scan(export.as_ref().map(|value| value.as_str()), ctx)
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

    let report_sections = vec![
        "Observed fleet machine count".to_string(),
        "Validation failure count".to_string(),
        "Rate-limit event count".to_string(),
        "Security audit request count".to_string(),
    ];

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
pub fn audit_export(
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
    fs::create_dir_all(output)?;

    // Generate audit files
    let files = vec![
        ("limitations.json", generate_audit_export_limitations()?),
        ("change-log.json", generate_change_log_json()?),
        ("policy-enforcement.json", generate_policy_json()?),
        ("installed-packages.csv", generate_installed_packages_csv()?),
        ("sbom-inventory.json", generate_sbom_json()?),
    ];

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
pub fn license_scan(export: Option<&str>, _ctx: &CliContext) -> Result<()> {
    use crate::cli::packages::execute_cmd;

    if let Some(fmt) = export {
        // Only formats with real serializers are offered; 'spdx' previously
        // emitted JSON under an .spdx name, misrepresenting the artifact.
        if !matches!(fmt.to_lowercase().as_str(), "json" | "csv") {
            anyhow::bail!("Unsupported license export format '{fmt}'. Valid formats: json, csv");
        }
    }

    let scan = perform_license_scan()?;

    // Display results. Percentages are license assignments over all observed
    // assignments, not packages: a package may legitimately declare more than
    // one license, so package-count denominators can exceed 100%.
    let license_inventory = license_inventory_rows(&scan);

    let mut violations = vec![];
    for violation in &scan.violations {
        violations.push(format!("{} - {}", violation.package, violation.reason));
    }

    let mut unknown = vec![];
    for pkg in scan.unknown.iter().take(5) {
        unknown.push(pkg.clone());
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
                crate::core::safe_ops::atomic_write_file_sync(&filename, content)?;
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

#[derive(Debug, Serialize, Deserialize)]
struct Report {
    generated_at: i64,
    #[serde(rename = "report_type")]
    kind: String,
    summary: ReportSummary,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReportSummary {
    total_machines: usize,
    validation_failures: u64,
    rate_limit_hits: u64,
    security_audit_requests: u64,
}

fn observed_report_summary(
    total_machines: usize,
    validation_failures: u64,
    rate_limit_hits: u64,
    security_audit_requests: u64,
) -> ReportSummary {
    ReportSummary {
        total_machines,
        validation_failures,
        rate_limit_hits,
        security_audit_requests,
    }
}

async fn generate_report(report_type: &str) -> Result<Report> {
    // A failed team lookup must not become a fabricated zero-machine report.
    let members = license::fetch_team_members()
        .await
        .context("Failed to fetch team members for enterprise report")?;
    let machine_count = members.len();

    let metrics = crate::core::metrics::GLOBAL_METRICS.snapshot();

    Ok(Report {
        generated_at: jiff::Timestamp::now().as_second(),
        kind: report_type.to_string(),
        summary: observed_report_summary(
            machine_count,
            metrics.validation_failures,
            metrics.rate_limit_hits,
            metrics.security_audit_requests,
        ),
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

#[cfg(any(feature = "arch", test))]
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

fn generate_installed_packages_csv() -> Result<String> {
    #[cfg(feature = "arch")]
    {
        let packages = crate::package_managers::list_installed_fast()
            .context("Failed to list installed packages for enterprise export")?;
        serialize_installed_packages_csv_rows(packages.into_iter().map(|package| {
            (
                package.name,
                package.version.to_string(),
                package.description,
            )
        }))
    }

    #[cfg(not(feature = "arch"))]
    {
        anyhow::bail!("Installed-package export requires the Arch package backend");
    }
}

fn generate_sbom_json() -> Result<String> {
    #[cfg(feature = "arch")]
    {
        let packages = crate::package_managers::list_installed_fast()
            .context("Failed to list installed packages for SBOM export")?;
        let components: Vec<serde_json::Value> = packages
            .into_iter()
            .map(|pkg| {
                serde_json::json!({
                    "type": "library",
                    "name": pkg.name,
                    "version": pkg.version.to_string(),
                    "description": pkg.description,
                })
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": components,
        }))
        .context("Failed to serialize SBOM inventory")
    }
    #[cfg(not(feature = "arch"))]
    anyhow::bail!("SBOM inventory export requires the Arch package backend")
}

#[derive(Debug, Serialize)]
struct LicenseScan {
    total: usize,
    by_license: HashMap<String, usize>,
    violations: Vec<LicenseViolation>,
    unknown: Vec<String>,
}

#[derive(Debug, Serialize)]
struct LicenseViolation {
    package: String,
    license: String,
    reason: String,
}

/// Reason text for a license that needs legal review, or `None` when the
/// license does not require review.
///
/// This deliberately shares `LicenseCategory::from_license` with `omg audit`
/// (src/cli/security.rs) so both commands agree on what counts as copyleft.
/// A previous `"GPL" in <uppercase>` substring test misreported three ways: it
/// understated AGPL as plain copyleft, missed MPL-2.0 entirely because "MPL"
/// has no "GPL" substring, and only caught LGPL by accident because "GPL" is a
/// substring of "LGPL-2.1" while still naming GPL in the reason.
///
/// `scripts/qemu-license-oracle.py` mirrors this mapping.
fn enterprise_license_review_reason(license: &str) -> Option<&'static str> {
    match LicenseCategory::from_license(license) {
        LicenseCategory::StrongCopyleft => {
            Some("Strong copyleft license (AGPL) requires legal review")
        }
        LicenseCategory::Copyleft => Some("Copyleft license requires legal review"),
        _ => None,
    }
}

fn perform_license_scan() -> Result<LicenseScan> {
    #[cfg(not(feature = "arch"))]
    anyhow::bail!("Enterprise license scan requires the Arch package backend");

    #[cfg(feature = "arch")]
    {
        let packages = crate::package_managers::pacman_db::list_local_cached()
            .context("Failed to list installed packages for license scan")?;
        let mut by_license: HashMap<String, usize> = HashMap::new();
        let mut violations: Vec<LicenseViolation> = Vec::new();
        let mut unknown: Vec<String> = Vec::new();
        let total = packages.len();
        for pkg in packages {
            if pkg.licenses.is_empty() {
                unknown.push(pkg.name.clone());
            } else {
                for lic in &pkg.licenses {
                    *by_license.entry(lic.clone()).or_insert(0) += 1;
                    if let Some(reason) = enterprise_license_review_reason(lic) {
                        violations.push(LicenseViolation {
                            package: pkg.name.clone(),
                            license: lic.clone(),
                            reason: reason.to_string(),
                        });
                    }
                }
            }
        }
        Ok(LicenseScan {
            total,
            by_license,
            violations,
            unknown,
        })
    }
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
            format!("{license}: {count} assignments ({percentage:.0}%)")
        })
        .collect::<Vec<_>>();
    rows.sort_unstable();
    rows
}

fn generate_license_csv(scan: &LicenseScan) -> Result<String> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer.write_record(["license", "count"])?;
    let mut licenses: Vec<_> = scan.by_license.iter().collect();
    licenses.sort_unstable_by_key(|(left, _)| *left);
    for (license, count) in licenses {
        let license = spreadsheet_safe_cell(license);
        writer.write_record([&*license, count.to_string().as_str()])?;
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
    fn executive_summary_uses_observed_counters_without_estimates() {
        let summary = observed_report_summary(3, 4, 5, 6);

        assert_eq!(summary.total_machines, 3);
        assert_eq!(summary.validation_failures, 4);
        assert_eq!(summary.rate_limit_hits, 5);
        assert_eq!(summary.security_audit_requests, 6);
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
    fn license_inventory_handles_empty_and_multi_license_scans() {
        let empty = LicenseScan {
            total: 0,
            by_license: HashMap::new(),
            violations: Vec::new(),
            unknown: Vec::new(),
        };
        assert!(license_inventory_rows(&empty).is_empty());

        let scan = LicenseScan {
            total: 2,
            by_license: HashMap::from([("MIT".to_string(), 2), ("Apache-2.0".to_string(), 1)]),
            violations: Vec::new(),
            unknown: Vec::new(),
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
