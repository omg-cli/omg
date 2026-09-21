//! Security audit command implementations
//!
//! Provides CLI handlers for vulnerability scanning, SBOM generation, secret detection,
//! license compliance, SLSA verification, and audit log management.

use anyhow::{Context, Result};
use owo_colors::OwoColorize;

fn write_private_export(path: &std::path::Path, contents: impl AsRef<[u8]>) -> Result<()> {
    // Security exports must never inherit a previously permissive mode from
    // the file they replace - force owner-only (0o600) through the replace.
    crate::core::safe_ops::atomic_write_file_sync_private(path, contents)
        .with_context(|| format!("Failed to write security export to {}", path.display()))
}

fn read_audit_entries(
    logger: &AuditLogger,
    limit: usize,
    severity_filter: Option<&str>,
) -> Result<Vec<crate::core::security::audit::AuditEntry>> {
    let result = if let Some(sev) = severity_filter {
        let min_severity = match sev.to_lowercase().as_str() {
            "debug" => AuditSeverity::Debug,
            "info" => AuditSeverity::Info,
            "warning" | "warn" => AuditSeverity::Warning,
            "error" => AuditSeverity::Error,
            "critical" => AuditSeverity::Critical,
            _ => anyhow::bail!("Invalid severity: {sev}"),
        };
        logger.filter_by_severity(min_severity).map(|mut entries| {
            entries.reverse();
            entries
        })
    } else {
        logger.get_recent(limit)
    };
    match result {
        Ok(entries) => Ok(entries.into_iter().take(limit).collect()),
        Err(error) if error.is_not_found() => Ok(Vec::new()),
        Err(error) => Err(error).context("Failed to read audit log entries"),
    }
}

use crate::cli::{AuditCommands, CliContext, LocalCommandRunner, style, ui};
#[cfg(unix)]
use crate::core::client::DaemonClient;
use crate::core::security::{AuditLogger, AuditSeverity, SbomGenerator, SecurityPolicy};
use crate::runtimes::eol::{eol_warning_cutoff, version_components};

impl LocalCommandRunner for AuditCommands {
    async fn execute(&self, ctx: &CliContext) -> Result<()> {
        let machine_stdout = matches!(
            self,
            AuditCommands::Licenses { format, export: None, .. } if format.as_str() != "table"
        );
        if !machine_stdout {
            ui::print_spacer();
        }
        match self {
            AuditCommands::Scan => scan(ctx).await,
            AuditCommands::Sbom { output } => {
                // SBOMs always include vulnerability data; the former `--vulns`
                // flag was dead (a SetTrue bool defaulting to true).
                generate_sbom(output.clone(), true, ctx).await
            }
            AuditCommands::Secrets { path } => scan_secrets(path.clone(), ctx),
            AuditCommands::Log {
                limit,
                severity,
                export,
            } => view_audit_log(
                *limit,
                severity.as_ref().map(|value| value.as_str()),
                export.clone(),
                ctx,
            ),
            AuditCommands::Verify => verify_audit_log(ctx),
            AuditCommands::Policy => show_policy(ctx),
            AuditCommands::Slsa {
                package,
                certificate_identity,
            } => check_slsa(package, certificate_identity.as_deref(), ctx).await,
            AuditCommands::Licenses {
                format,
                export,
                filter,
                check_policy,
            } => scan_licenses(
                format.as_str(),
                export.clone(),
                filter.clone(),
                *check_policy,
                ctx,
            ),
            AuditCommands::Fix {
                dry_run,
                yes,
                min_severity,
            } => fix_vulnerabilities(*dry_run, *yes, min_severity.as_str(), ctx).await,
            AuditCommands::Export {
                framework,
                period,
                output,
            } => export_compliance(framework.as_str(), period.clone(), output, ctx).await,
            AuditCommands::Eol => check_eol(ctx),
        }?;
        if !machine_stdout {
            ui::print_spacer();
        }
        Ok(())
    }
}

/// Prefer the warm daemon, but keep scanning available without it.
pub(super) async fn security_audit_result()
-> Result<crate::core::security::scan::SecurityAuditResult> {
    #[cfg(unix)]
    if let Ok(mut client) = DaemonClient::connect().await {
        return client
            .security_audit()
            .await
            .context("Failed to run security audit");
    }
    let manager = crate::package_managers::get_package_manager()?;
    let scanner = crate::core::security::VulnerabilityScanner::new();
    crate::core::security::scan::scan_installed(manager.as_ref(), &scanner).await
}

/// Perform security audit (vulnerability scan)
pub async fn scan(_ctx: &CliContext) -> Result<()> {
    ui::print_header("Secure", "Vulnerability Scan");

    #[cfg(unix)]
    {
        let res = security_audit_result().await?;
        if res.total_vulnerabilities == 0 {
            ui::print_success("No vulnerabilities found in scanned packages.");
        } else {
            ui::print_warning(format!(
                "Found {} vulnerabilities ({} high severity)",
                res.total_vulnerabilities, res.high_severity
            ));
            println!();
            for (pkg, vulns) in res.vulnerabilities {
                println!(
                    "  {} ({} issues):",
                    style::maybe_color(&style::sanitize_terminal_text(&pkg), |t| t
                        .white()
                        .bold()
                        .to_string()),
                    vulns.len()
                );
                for vuln in vulns {
                    let score = vuln
                        .score
                        .map(|s| format!(" [Score: {}]", style::sanitize_terminal_text(&s)))
                        .unwrap_or_default();
                    println!(
                        "    {} {} - {}{}",
                        style::maybe_color("→", |t| t.red().to_string()),
                        style::maybe_color(&style::sanitize_terminal_text(&vuln.id), |t| t
                            .yellow()
                            .to_string()),
                        style::sanitize_terminal_text(&vuln.summary),
                        style::dim(&score)
                    );
                }
                println!();
            }
            ui::print_tip("Run 'omg audit sbom' to generate a full security report.");
        }
        Ok(())
    }

    #[cfg(not(unix))]
    {
        anyhow::bail!(
            "Security audit requires the daemon, which is only available on Unix systems."
        );
    }
}

/// Generate SBOM (Software Bill of Materials)
pub async fn generate_sbom(
    output: Option<String>,
    include_vulns: bool,
    _ctx: &CliContext,
) -> Result<()> {
    println!(
        "{} Generating Software Bill of Materials (CycloneDX 1.5)...\n",
        style::runtime("OMG")
    );

    let generator = SbomGenerator::new().with_vulnerabilities(include_vulns);

    // The format string mirrors what `SbomGenerator` actually emits; keep the
    // two in sync when bumping spec versions.
    // Spec registry: https://cyclonedx.org/spec-version/
    let sbom = generator
        .generate_system_sbom()
        .await
        .context("Failed to generate system SBOM")?;

    let path = if let Some(output_path) = output {
        let path = std::path::PathBuf::from(&output_path);
        generator.export_json(&sbom, &path)?;
        path
    } else {
        generator.export_default(&sbom)?
    };

    println!(
        "{} SBOM generated with {} components",
        style::maybe_color("✓", |t| t.green().to_string()),
        style::runtime(&sbom.components.len().to_string())
    );

    if !sbom.vulnerabilities.is_empty() {
        println!(
            "{} {} vulnerabilities included",
            style::maybe_color("⚠", |t| t.yellow().to_string()),
            style::maybe_color(&sbom.vulnerabilities.len().to_string(), |t| {
                t.yellow().bold().to_string()
            })
        );
    }

    println!(
        "\n  {} {}",
        style::dim("Output:"),
        style::maybe_color(&path.display().to_string(), |t| t.white().to_string())
    );
    println!("  {} CycloneDX 1.5 (JSON)", style::dim("Format:"));

    Ok(())
}

/// View audit log entries
pub fn view_audit_log(
    limit: Option<usize>,
    severity_filter: Option<&str>,
    export: Option<String>,
    _ctx: &CliContext,
) -> Result<()> {
    let effective_limit = limit.unwrap_or_else(|| if export.is_some() { usize::MAX } else { 20 });
    let logger = AuditLogger::new().context("Failed to open audit log")?;
    let entries = read_audit_entries(&logger, effective_limit, severity_filter)?;

    if let Some(export_path) = export {
        println!(
            "{} Exporting audit log to {}...",
            style::runtime("OMG"),
            style::maybe_color(&export_path, |t| t.white().to_string())
        );
        let path = std::path::PathBuf::from(&export_path);
        let format = if std::path::Path::new(&export_path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("csv"))
        {
            "csv"
        } else {
            "json"
        };

        if format == "csv" {
            let mut csv = Vec::new();
            {
                let mut writer = csv::Writer::from_writer(&mut csv);
                writer.write_record([
                    "Timestamp",
                    "Severity",
                    "Event",
                    "Description",
                    "Resource",
                ])?;
                for entry in &entries {
                    let severity = entry.severity.to_string();
                    let event = format!("{:?}", entry.event_type);
                    let description = spreadsheet_safe_cell(&entry.description);
                    let resource = spreadsheet_safe_cell(&entry.resource);
                    writer.write_record([
                        entry.timestamp.as_str(),
                        severity.as_str(),
                        event.as_str(),
                        description.as_ref(),
                        resource.as_ref(),
                    ])?;
                }
                writer.flush()?;
            }
            write_private_export(&path, csv)?;
        } else {
            let json = serde_json::to_vec_pretty(&entries)?;
            write_private_export(&path, json)?;
        }
        println!(
            "{} Export successful",
            style::maybe_color("✓", |t| t.green().to_string())
        );
        return Ok(());
    }

    println!("{} Security Audit Log\n", style::runtime("OMG"));

    if entries.is_empty() {
        println!(
            "  {} No audit entries found.",
            style::maybe_color("ℹ", |t| t.blue().to_string())
        );
        return Ok(());
    }

    for entry in entries.iter().take(effective_limit) {
        let sev_str = entry.severity.to_string();
        let severity_color = match entry.severity {
            AuditSeverity::Debug => style::dim(&sev_str),
            AuditSeverity::Info => style::maybe_color(&sev_str, |t| t.blue().to_string()),
            AuditSeverity::Warning => style::maybe_color(&sev_str, |t| t.yellow().to_string()),
            AuditSeverity::Error => style::maybe_color(&sev_str, |t| t.red().to_string()),
            AuditSeverity::Critical => style::maybe_color(&sev_str, |t| t.red().bold().to_string()),
        };

        println!(
            "  {} [{}] {} - {}",
            style::dim(&entry.timestamp),
            severity_color,
            style::maybe_color(&format!("{:?}", entry.event_type), |t| {
                t.cyan().to_string()
            }),
            entry.description
        );
        if !entry.resource.is_empty() {
            println!("      {} {}", style::dim("Resource:"), entry.resource);
        }
    }

    println!(
        "\n  {} Showing {} of {} entries",
        style::maybe_color("ℹ", |t| t.blue().to_string()),
        entries.len().min(effective_limit),
        entries.len()
    );

    Ok(())
}

/// Verify audit log integrity
pub fn verify_audit_log(_ctx: &CliContext) -> Result<()> {
    println!(
        "{} Verifying Audit Log Integrity...\n",
        style::runtime("OMG")
    );

    crate::core::security::audit::ensure_complete_collection(
        &crate::core::paths::data_dir().join("audit/incomplete"),
    )?;
    let logger = AuditLogger::new().context("Failed to open audit log")?;
    let report = match logger.verify_integrity() {
        Ok(report) => report,
        Err(error) if error.is_not_found() => {
            println!(
                "  {} No audit log exists yet.",
                style::maybe_color("ℹ", |t| t.blue().to_string())
            );
            return Ok(());
        }
        Err(error) => {
            return Err(error).context("Failed to verify audit log integrity");
        }
    };

    if report.is_valid() {
        println!(
            "{} Local audit chain consistency verified",
            style::maybe_color("✓", |t| t.green().to_string())
        );
        println!(
            "  {} {} entries",
            style::dim("Total:"),
            report.total_entries
        );
        println!(
            "  {} {} entries",
            style::dim("Valid:"),
            report.valid_entries
        );
        println!(
            "  {} Internally consistent; not authenticated",
            style::dim("Chain:")
        );
        println!(
            "  A log owner can rewrite and rehash history; this check does not prove authenticity or completeness."
        );
    } else {
        println!(
            "{} Audit log integrity FAILED",
            style::maybe_color("✗", |t| t.red().bold().to_string())
        );
        println!(
            "  {} {} entries",
            style::dim("Total:"),
            report.total_entries
        );
        println!(
            "  {} {} entries",
            style::dim("Valid:"),
            report.valid_entries
        );
        let chain_status = if report.chain_valid {
            "Intact".to_string()
        } else {
            style::maybe_color("BROKEN", |t| t.red().to_string())
        };
        println!("  {} {}", style::dim("Chain:"), chain_status);
        if let Some(first_invalid) = &report.first_invalid_entry {
            println!(
                "  {} {}",
                style::dim("First Invalid:"),
                style::maybe_color(first_invalid, |t| t.red().to_string())
            );
        }
    }

    println!(
        "\n  {} {}",
        style::dim("Log Path:"),
        report.log_path.display()
    );

    require_audit_integrity(report.is_valid())
}

/// Show security policy status
pub fn show_policy(_ctx: &CliContext) -> Result<()> {
    println!("{} Security Policy Status\n", style::runtime("OMG"));

    let policy = SecurityPolicy::load_default().context("Failed to load security policy")?;

    println!(
        "  {} {}",
        style::dim("Minimum Grade:"),
        style::maybe_color(&policy.minimum_grade.to_string(), |t| {
            t.cyan().to_string()
        })
    );
    println!(
        "  {} {}",
        style::dim("AUR Allowed:"),
        if policy.allow_aur {
            style::version("Yes")
        } else {
            style::maybe_color("No", |t| t.red().to_string())
        }
    );
    println!(
        "  {} {}",
        style::dim("PGP Required:"),
        if policy.require_pgp {
            style::version("Yes")
        } else {
            style::maybe_color("No", |t| t.yellow().to_string())
        }
    );

    if !policy.banned_packages.is_empty() {
        println!(
            "\n  {} Banned Packages:",
            style::maybe_color("⚠", |t| t.yellow().to_string())
        );
        for pkg in &policy.banned_packages {
            println!(
                "    {} {}",
                style::maybe_color("•", |t| t.red().to_string()),
                pkg
            );
        }
    }

    if !policy.allowed_licenses.is_empty() {
        println!(
            "\n  {} Allowed Licenses:",
            style::maybe_color("ℹ", |t| t.blue().to_string())
        );
        for lic in &policy.allowed_licenses {
            println!(
                "    {} {}",
                style::maybe_color("•", |t| t.green().to_string()),
                lic
            );
        }
    }

    println!(
        "\n  {} Edit ~/.config/omg/policy.toml to customize",
        style::maybe_color("ℹ", |t| t.blue().to_string())
    );

    Ok(())
}

fn enforce_secret_scan_result(result: &crate::core::security::SecretScanResult) -> Result<()> {
    anyhow::ensure!(
        !result.has_critical(),
        "Secret scan failed: {} critical secret finding(s) require remediation",
        result.critical_count
    );
    Ok(())
}

/// Scan for leaked secrets
pub fn scan_secrets(path: Option<String>, _ctx: &CliContext) -> Result<()> {
    use crate::core::security::SecretScanner;

    /// Number of findings printed before the "... and N more" summary.
    const DISPLAY_LIMIT: usize = 20;

    let scan_path = path.unwrap_or_else(|| ".".to_string());

    println!(
        "{} Scanning for secrets in {}...\n",
        style::runtime("OMG"),
        style::maybe_color(&scan_path, |t| t.white().to_string())
    );

    let scanner = SecretScanner::new();
    let findings = if std::path::Path::new(&scan_path).is_file() {
        scanner
            .scan_file(&scan_path)
            .with_context(|| format!("Failed to scan file {scan_path}"))?
    } else {
        scanner
            .scan_directory(&scan_path)
            .with_context(|| format!("Failed to scan directory {scan_path}"))?
    };

    if findings.is_empty() {
        println!(
            "{} No secrets detected.",
            style::maybe_color("✓", |t| t.green().to_string())
        );
        return Ok(());
    }

    let result = crate::core::security::SecretScanResult::from_findings(findings);

    println!(
        "{} Found {} potential secrets:\n",
        style::maybe_color("⚠", |t| t.yellow().bold().to_string()),
        style::maybe_color(&result.total_findings.to_string(), |t| {
            t.red().bold().to_string()
        })
    );

    if result.critical_count > 0 {
        println!(
            "  {} {} CRITICAL",
            style::maybe_color("●", |t| t.red().to_string()),
            result.critical_count
        );
    }
    if result.high_count > 0 {
        println!(
            "  {} {} HIGH",
            style::maybe_color("●", |t| t.yellow().to_string()),
            result.high_count
        );
    }
    if result.medium_count > 0 {
        println!(
            "  {} {} MEDIUM",
            style::maybe_color("●", |t| t.blue().to_string()),
            result.medium_count
        );
    }
    if result.low_count > 0 {
        println!("  {} {} LOW", style::dim("●"), result.low_count);
    }

    println!();

    for finding in result.findings.iter().take(DISPLAY_LIMIT) {
        let sev_str = finding.severity.to_string();
        let severity_color = match finding.severity {
            crate::core::security::secrets::SecretSeverity::Critical => {
                style::maybe_color(&sev_str, |t| t.red().bold().to_string())
            }
            crate::core::security::secrets::SecretSeverity::High => {
                style::maybe_color(&sev_str, |t| t.yellow().to_string())
            }
            crate::core::security::secrets::SecretSeverity::Medium => {
                style::maybe_color(&sev_str, |t| t.blue().to_string())
            }
            crate::core::security::secrets::SecretSeverity::Low => style::dim(&sev_str),
        };

        println!(
            "  [{}] {} in {}:{}",
            severity_color,
            style::maybe_color(&finding.secret_type.to_string(), |t| {
                t.cyan().to_string()
            }),
            style::dim(&finding.file_path),
            finding.line_number
        );
        println!("      {}", style::dim(&finding.redacted));
    }

    if result.total_findings > DISPLAY_LIMIT {
        println!(
            "\n  {} ... and {} more",
            style::maybe_color("ℹ", |t| t.blue().to_string()),
            result.total_findings - DISPLAY_LIMIT
        );
    }

    if result.has_critical() {
        println!(
            "\n{} Critical secrets found! Remove them before committing.",
            style::maybe_color("⚠", |t| t.red().bold().to_string())
        );
    }

    enforce_secret_scan_result(&result)
}

/// Check SLSA provenance for a package
pub async fn check_slsa(
    package: &str,
    certificate_identity: Option<&str>,
    _ctx: &CliContext,
) -> Result<()> {
    use crate::core::security::SlsaVerifier;

    // SECURITY: Validate path
    crate::core::security::validate_relative_path(package)?;

    println!(
        "{} Checking SLSA provenance for {}...\n",
        style::runtime("OMG"),
        style::maybe_color(package, |t| t.white().to_string())
    );

    let path = std::path::Path::new(package);
    if !path.exists() {
        anyhow::bail!("File not found: {package}");
    }

    let verifier = SlsaVerifier::new();
    let result = verifier
        .verify_provenance(path, None::<&std::path::Path>, certificate_identity)
        .await?;

    // Trust-policy honesty (audit sec2 F-05): without an identity predicate,
    // ANY Sigstore signer's valid signature "verifies" - cryptographically
    // true but meaningless as a trust statement. Say so loudly instead of
    // implying the artifact came from a trusted builder.
    if result.verified && certificate_identity.is_none() {
        println!(
            "  {} No --certificate-identity was specified: the signature is \nvalid but the SIGNER is unbounded (identity: {}). \nSupply --certificate-identity to enforce a trust policy.",
            style::warning("⚠"),
            result.builder_id.as_deref().unwrap_or("unknown")
        );
    }

    require_slsa_verified(result.verified, result.error.as_deref())?;

    println!(
        "{} SLSA verification passed",
        style::maybe_color("✓", |t| t.green().to_string())
    );
    println!(
        "  {} {}",
        style::dim("Level:"),
        style::maybe_color(&result.slsa_level.to_string(), |t| t.cyan().to_string())
    );

    if let Some(entry) = &result.transparency_log_entry {
        println!("  {} {}", style::dim("Rekor Entry:"), entry);
    }
    if let Some(builder) = &result.builder_id {
        println!("  {} {}", style::dim("Builder:"), builder);
    }
    if let Some(timestamp) = &result.build_timestamp {
        println!("  {} {}", style::dim("Build Time:"), timestamp);
    }

    Ok(())
}

fn require_slsa_verified(verified: bool, error: Option<&str>) -> Result<()> {
    if verified {
        return Ok(());
    }
    match error {
        Some(reason) => anyhow::bail!("SLSA verification failed: {reason}"),
        None => anyhow::bail!("SLSA verification failed"),
    }
}

fn require_audit_integrity(is_valid: bool) -> Result<()> {
    if is_valid {
        Ok(())
    } else {
        anyhow::bail!("Audit log integrity FAILED")
    }
}

/// License categories for compliance
#[derive(Debug, Clone, PartialEq, Eq)]
enum LicenseCategory {
    Permissive,     // MIT, BSD, Apache
    Copyleft,       // GPL, LGPL, MPL
    StrongCopyleft, // AGPL
    Proprietary,
    Unknown,
}

impl LicenseCategory {
    fn from_license(license: &str) -> Self {
        let tokens = crate::core::security::policy::spdx_license_tokens(license);
        let mut category = Self::Unknown;
        for token in &tokens {
            if token.contains("agpl") {
                return Self::StrongCopyleft;
            }
            if token.contains("gpl") || token.contains("lgpl") || token.contains("mpl") {
                category = Self::Copyleft;
                continue;
            }
            if token_is_permissive(token) {
                if category == Self::Unknown {
                    category = Self::Permissive;
                }
                continue;
            }
            if (token.contains("proprietary") || token.contains("commercial"))
                && category == Self::Unknown
            {
                category = Self::Proprietary;
            }
        }
        category
    }

    fn color(&self) -> String {
        match self {
            Self::Permissive => style::success("Permissive"),
            Self::Copyleft => style::warning("Copyleft"),
            Self::StrongCopyleft => style::error("Strong Copyleft"),
            Self::Proprietary => style::error("Proprietary"),
            Self::Unknown => style::dim("Unknown"),
        }
    }
}

fn token_is_permissive(token: &str) -> bool {
    matches!(
        token,
        "mit" | "isc" | "unlicense" | "cc0" | "cc0-1.0" | "0bsd" | "bsd" | "apache"
    ) || token.starts_with("bsd-")
        || token.starts_with("apache-")
}

type LicenseRow = (String, String, String, LicenseCategory);

pub(crate) fn spreadsheet_safe_cell(value: &str) -> std::borrow::Cow<'_, str> {
    if value.starts_with(['=', '+', '-', '@']) {
        std::borrow::Cow::Owned(format!("'{value}"))
    } else {
        std::borrow::Cow::Borrowed(value)
    }
}

fn serialize_license_rows(format: &str, rows: &[LicenseRow]) -> Result<Vec<u8>> {
    match format {
        "json" => {
            let data: Vec<_> = rows
                .iter()
                .map(|(name, license, version, category)| {
                    serde_json::json!({
                        "name": name,
                        "version": version,
                        "license": license,
                        "category": format!("{category:?}")
                    })
                })
                .collect();
            serde_json::to_vec_pretty(&data).map_err(Into::into)
        }
        "csv" => {
            let mut writer = csv::Writer::from_writer(Vec::new());
            writer.write_record(["Package", "Version", "License", "Category"])?;
            for (name, license, version, category) in rows {
                let name = spreadsheet_safe_cell(name);
                let version = spreadsheet_safe_cell(version);
                let license = spreadsheet_safe_cell(license);
                let category = format!("{category:?}");
                writer.write_record([
                    name.as_ref(),
                    version.as_ref(),
                    license.as_ref(),
                    category.as_str(),
                ])?;
            }
            writer
                .into_inner()
                .map_err(|error| anyhow::anyhow!("Failed to finish license CSV: {error}"))
        }
        "table" => {
            use std::fmt::Write as _;
            let mut content = String::from("Package\tVersion\tLicense\tCategory\n");
            for (name, license, version, category) in rows {
                let _ = writeln!(content, "{name}\t{version}\t{license}\t{category:?}");
            }
            Ok(content.into_bytes())
        }
        other => anyhow::bail!("Unsupported output format '{other}'"),
    }
}

/// Scan for software license compliance
pub fn scan_licenses(
    format: &str,
    export: Option<String>,
    filter: Option<String>,
    check_policy: bool,
    _ctx: &CliContext,
) -> Result<()> {
    // Validate the requested format up front instead of silently rendering any
    // unknown value with the table renderer.
    if !matches!(format, "table" | "json" | "csv") {
        anyhow::bail!("Unsupported output format '{format}'. Valid formats: table, json, csv");
    }

    if export.is_some() || format == "table" {
        println!(
            "{} Scanning installed packages for license information...\n",
            style::runtime("OMG")
        );
    }

    // Get installed packages and their licenses
    let packages = installed_packages_with_licenses()?;

    // Filter by license if specified, categorizing each package once.
    // `from_license` tokenizes the expression, so it must not be recomputed
    // separately for the summary, policy check, AND export.
    let filter_terms: Vec<String> = filter
        .map(|f| f.split(',').map(|s| s.trim().to_lowercase()).collect())
        .unwrap_or_default();

    let filtered_packages: Vec<LicenseRow> = packages
        .into_iter()
        .filter(|(_, license, _)| {
            if filter_terms.is_empty() {
                true
            } else {
                let tokens = crate::core::security::policy::spdx_license_tokens(license);
                filter_terms.iter().any(|term| {
                    tokens.iter().any(|token| {
                        token == term
                            || token.strip_suffix('+') == Some(term.as_str())
                            || token.starts_with(&format!("{term}-"))
                    })
                })
            }
        })
        .map(|(name, license, version)| {
            let category = LicenseCategory::from_license(&license);
            (name, license, version, category)
        })
        .collect();

    if export.is_none() && matches!(format, "json" | "csv") {
        use std::io::Write as _;
        let report = serialize_license_rows(format, &filtered_packages)?;
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(&report)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
        return Ok(());
    }

    // Print summary
    println!("  {}", style::header("License Summary"));
    println!(
        "    {} {}",
        style::success("Permissive:"),
        filtered_packages
            .iter()
            .filter(|(_, _, _, c)| *c == LicenseCategory::Permissive)
            .count()
    );
    println!(
        "    {} {}",
        style::warning("Copyleft:"),
        filtered_packages
            .iter()
            .filter(|(_, _, _, c)| *c == LicenseCategory::Copyleft)
            .count()
    );
    let strong_copyleft = filtered_packages
        .iter()
        .filter(|(_, _, _, c)| *c == LicenseCategory::StrongCopyleft)
        .count();
    if strong_copyleft > 0 {
        println!(
            "    {} {}",
            style::error("Strong Copyleft (AGPL):"),
            strong_copyleft
        );
    }
    let proprietary = filtered_packages
        .iter()
        .filter(|(_, _, _, c)| *c == LicenseCategory::Proprietary)
        .count();
    if proprietary > 0 {
        println!("    {} {}", style::error("Proprietary:"), proprietary);
    }
    let unknown = filtered_packages
        .iter()
        .filter(|(_, _, _, c)| *c == LicenseCategory::Unknown)
        .count();
    if unknown > 0 {
        println!("    {} {}", style::dim("Unknown:"), unknown);
    }
    println!();

    // Check against policy if requested
    if check_policy {
        let policy = SecurityPolicy::load_default().context("Failed to load security policy")?;
        let mut violations = Vec::new();

        for (name, license, _, _) in &filtered_packages {
            // Check against allowed licenses (if policy specifies them)
            if !policy.allowed_licenses.is_empty()
                && !crate::core::security::policy::license_matches_allowlist(
                    license,
                    &policy.allowed_licenses,
                )
            {
                violations.push((
                    name.clone(),
                    license.clone(),
                    "Not in allowed list".to_string(),
                ));
            }

            // Check for AGPL (commonly restricted in commercial use)
            if license.to_lowercase().contains("agpl") {
                violations.push((
                    name.clone(),
                    license.clone(),
                    "AGPL requires review".to_string(),
                ));
            }
        }

        if violations.is_empty() {
            println!(
                "  {} All packages comply with license policy\n",
                style::success("✓")
            );
        } else {
            println!("  {} License Policy Violations:\n", style::warning("⚠"));
            for (name, license, reason) in &violations {
                println!(
                    "    {} {} ({}) - {}",
                    style::error("✗"),
                    name,
                    license,
                    reason
                );
            }
            println!();
        }
    }

    // Export if requested
    if let Some(export_path) = export {
        let path = std::path::PathBuf::from(&export_path);

        let report = serialize_license_rows(format, &filtered_packages)?;
        write_private_export(&path, report)?;

        println!(
            "{} Exported {} packages to {}",
            style::success("✓"),
            filtered_packages.len(),
            export_path
        );
    } else if format == "table" {
        // Show first 20 packages in table format
        println!("  {}", style::header("Packages"));
        for (name, license, _, category) in filtered_packages.iter().take(20) {
            println!(
                "    {} {} ({})",
                style::package(name),
                style::dim(license),
                category.color()
            );
        }
        if filtered_packages.len() > 20 {
            println!(
                "\n  {} Showing 20 of {} packages. Use --export to see all.",
                style::dim("..."),
                filtered_packages.len()
            );
        }
    }

    Ok(())
}

fn installed_packages_with_licenses() -> Result<Vec<(String, String, String)>> {
    #[cfg(feature = "arch")]
    {
        crate::package_managers::alpm_direct::list_installed_with_licenses()
    }
    #[cfg(not(feature = "arch"))]
    license_scan_requires_arch()
}

#[cfg(any(not(feature = "arch"), test))]
fn license_scan_requires_arch() -> Result<Vec<(String, String, String)>> {
    anyhow::bail!(
        "License scanning of installed packages is not available without the Arch backend"
    )
}

#[cfg(any(not(feature = "arch"), test))]
fn fix_requires_arch() -> Result<()> {
    anyhow::bail!(
        "Vulnerability auto-fix is not available without the Arch backend; upgrade the affected packages manually"
    )
}

fn package_has_available_update(package: &str) -> Result<bool> {
    #[cfg(feature = "arch")]
    {
        crate::package_managers::alpm_direct::has_update(package)
            .with_context(|| format!("Failed to check whether {package} has an available update"))
    }
    #[cfg(not(feature = "arch"))]
    {
        anyhow::bail!(
            "Cannot determine whether {package} has an available update without the Arch backend"
        )
    }
}

/// Best-effort CVSS base score for a vulnerability; unparsable or missing
/// scores count as 0.0 so they never cross a severity threshold by accident.
fn vuln_score(score: Option<&str>) -> f64 {
    score
        .and_then(crate::core::security::vulnerability::parse_severity_score)
        .unwrap_or(0.0)
}

/// Auto-fix vulnerabilities by upgrading packages
pub async fn fix_vulnerabilities(
    dry_run: bool,
    yes: bool,
    min_severity: &str,
    _ctx: &CliContext,
) -> Result<()> {
    println!(
        "{} Scanning for fixable vulnerabilities...\n",
        style::runtime("OMG")
    );

    #[cfg(unix)]
    let scan_result = security_audit_result().await?;

    #[cfg(not(unix))]
    {
        anyhow::bail!(
            "Vulnerability scanning requires the daemon, which is only available on Unix systems."
        );
    }

    #[cfg(unix)]
    {
        if scan_result.total_vulnerabilities == 0 {
            println!("{} No vulnerabilities found!", style::success("✓"));
            return Ok(());
        }

        // Determine minimum severity threshold. Bands follow the CVSS v3.1
        // qualitative scale: medium >= 4.0, high >= 7.0, critical >= 9.0.
        // https://www.first.org/data/specs/cvss-v3.1#CVSS-v3.1-Qualitative-Severity-Rating-Scale
        let min_sev = match min_severity.to_lowercase().as_str() {
            "critical" => 9.0,
            "high" => 7.0,
            "low" => 0.0,
            _ => 4.0, // Default to medium or unknown
        };

        // Find packages with fixable vulnerabilities (single pass; each
        // vulnerability's CVSS string is parsed exactly once).
        let mut to_upgrade: Vec<String> = Vec::new();
        let mut unfixable: Vec<(String, String)> = Vec::new();

        for (pkg, vulns) in &scan_result.vulnerabilities {
            let severe_vulns: Vec<&str> = vulns
                .iter()
                .filter(|v| vuln_score(v.score.as_deref()) >= min_sev)
                .map(|v| v.id.as_str())
                .collect();
            if severe_vulns.is_empty() {
                continue;
            }
            if package_has_available_update(pkg)? {
                to_upgrade.push(pkg.clone());
            } else {
                unfixable.extend(
                    severe_vulns
                        .into_iter()
                        .map(|id| (pkg.clone(), id.to_string())),
                );
            }
        }

        if to_upgrade.is_empty() {
            println!("{} No packages can be auto-fixed.", style::dim("•"));
            if !unfixable.is_empty() {
                println!(
                    "\n  {} Unfixable vulnerabilities (no update available):\n",
                    style::warning("⚠")
                );
                for (pkg, vuln) in &unfixable {
                    println!("    {} {} - {}", style::error("✗"), pkg, vuln);
                }
                println!(
                    "\n  {} These may require manual intervention or upstream patches.",
                    style::dim("ℹ")
                );
            }
            return Ok(());
        }

        println!(
            "{} Found {} packages to upgrade:\n",
            style::success("✓"),
            to_upgrade.len()
        );
        for pkg in &to_upgrade {
            println!("    {} {}", style::arrow("→"), style::package(pkg));
        }

        if dry_run {
            println!("\n{} Dry run - no changes made.", style::dim("•"));
            return Ok(());
        }

        if !yes {
            println!();
            let confirm = dialoguer::Confirm::new()
                .with_prompt("Proceed with upgrades?")
                .default(true)
                .interact()?;

            if !confirm {
                println!("{} Cancelled.", style::dim("•"));
                return Ok(());
            }
        }

        #[cfg(all(feature = "arch", not(test)))]
        {
            let pacman = crate::package_managers::ArchPackageManager::new();
            let history = crate::core::history::HistoryManager::new()?;
            apply_security_updates(&pacman, &history, &to_upgrade).await?;
        }
        #[cfg(any(not(feature = "arch"), test))]
        fix_requires_arch()?;

        println!(
            "\n{} Fixed {} packages.",
            style::success("✓"),
            to_upgrade.len()
        );

        if !unfixable.is_empty() {
            println!(
                "\n{} {} vulnerabilities remain unfixable.",
                style::warning("⚠"),
                unfixable.len()
            );
        }
    }

    Ok(())
}

#[cfg(any(feature = "arch", test))]
async fn apply_security_updates(
    backend: &dyn crate::package_managers::PackageManager,
    history: &crate::core::history::HistoryManager,
    packages: &[String],
) -> Result<()> {
    use crate::core::history::{PackageChange, TransactionType};

    let updates = backend.list_updates().await?;
    let changes = packages
        .iter()
        .map(|package| {
            let update = updates
                .iter()
                .find(|update| update.name == *package)
                .with_context(|| {
                    format!("{package} no longer has an available update; rescan before fixing")
                })?;
            Ok(PackageChange {
                name: update.name.clone(),
                old_version: Some(update.old_version.clone()),
                new_version: Some(update.new_version.clone()),
                source: update.repo.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let result = backend.install(packages).await;
    history.finish_operation(TransactionType::Update, changes, result)
}

pub(crate) fn validate_compliance_export_inputs(
    framework: &str,
    period: Option<&str>,
    output: &str,
) -> Result<()> {
    let valid_frameworks = ["soc2", "iso27001", "fedramp", "hipaa", "pci-dss"];
    anyhow::ensure!(
        valid_frameworks.contains(&framework.to_ascii_lowercase().as_str()),
        "Invalid compliance framework: {framework}"
    );
    if let Some(period) = period {
        anyhow::ensure!(
            period.len() <= 64
                && period
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-'),
            "Invalid period format"
        );
    }
    crate::core::security::validate_relative_path(output)?;
    Ok(())
}

/// Export compliance evidence for audit frameworks
pub async fn export_compliance(
    framework: &str,
    period: Option<String>,
    output: &str,
    _ctx: &CliContext,
) -> Result<()> {
    validate_compliance_export_inputs(framework, period.as_deref(), output)?;

    println!(
        "{} Generating {} compliance evidence...\n",
        style::runtime("OMG"),
        framework.to_uppercase()
    );

    let output_dir = std::path::PathBuf::from(output);
    std::fs::create_dir_all(&output_dir)?;

    let now = jiff::Timestamp::now();
    let timestamp = now.strftime("%Y%m%d_%H%M%S").to_string();

    // Generate different evidence based on framework
    match framework.to_lowercase().as_str() {
        "soc2" => {
            // SOC 2 requires:
            // - Audit log of changes
            // - Vulnerability scan results
            // - SBOM
            // - Configuration documentation

            // 1. Export audit log
            let logger =
                AuditLogger::new().context("Failed to open audit log for compliance export")?;
            let entries = read_audit_entries(&logger, 1000, None)?;
            let json = serde_json::to_string_pretty(&entries)?;
            let log_path = output_dir.join(format!("audit-log-{timestamp}.json"));
            write_private_export(&log_path, json)?;
            println!(
                "  {} Audit log: {}",
                style::success("✓"),
                log_path.display()
            );

            // 2. Export vulnerability scan
            #[cfg(unix)]
            {
                let scan = security_audit_result().await?;
                let json = serde_json::to_string_pretty(&scan)?;
                let scan_path = output_dir.join(format!("vulnerability-scan-{timestamp}.json"));
                write_private_export(&scan_path, json)?;
                println!(
                    "  {} Vulnerability scan: {}",
                    style::success("✓"),
                    scan_path.display()
                );
            }

            #[cfg(not(unix))]
            println!(
                "  {} Vulnerability scan skipped: daemon unavailable on this platform",
                style::warning("⚠")
            );

            // 3. Generate SBOM
            let generator = SbomGenerator::new().with_vulnerabilities(true);
            let sbom = generator
                .generate_system_sbom()
                .await
                .context("Failed to generate SBOM for compliance export")?;
            let sbom_filename = format!("sbom-{timestamp}.json");
            let sbom_path = output_dir.join(sbom_filename);
            generator.export_json(&sbom, &sbom_path)?;
            println!("  {} SBOM: {}", style::success("✓"), sbom_path.display());

            // 4. Configuration snapshot
            let config_snapshot = serde_json::json!({
                "framework": "SOC2",
                "generated_at": now.to_string(),
                "period": period,
                "policy": SecurityPolicy::load_default()
                    .context("Failed to load security policy")?,
            });
            let config_path = output_dir.join(format!("config-snapshot-{timestamp}.json"));
            write_private_export(
                &config_path,
                serde_json::to_string_pretty(&config_snapshot)?,
            )?;
            println!(
                "  {} Configuration: {}",
                style::success("✓"),
                config_path.display()
            );
        }
        "iso27001" | "hipaa" | "pci-dss" | "fedramp" => {
            // Honest failure: no evidence generator exists for these frameworks
            // yet. Falling through to the success message below would claim an
            // export that never happened.
            anyhow::bail!(
                "{} compliance evidence export is not implemented in this build; \
                 only 'soc2' generates evidence files",
                framework.to_uppercase()
            );
        }
        other => {
            // Unreachable when reached through the CLI (validated upstream),
            // but must not fall through to a success message.
            anyhow::bail!(
                "Unknown compliance framework: {other}. Supported: soc2, iso27001, hipaa, pci-dss, fedramp"
            );
        }
    }

    println!(
        "\n{} Evidence exported to {}",
        style::success("✓"),
        output_dir.display()
    );

    Ok(())
}

fn parse_eol_timestamp(eol_date: &str) -> Result<jiff::Timestamp> {
    let eol_ts = jiff::civil::Date::strptime("%Y-%m-%d", eol_date)
        .map_err(|error| anyhow::anyhow!("Invalid EOL date '{eol_date}': {error}"))?;
    let zoned = eol_ts
        .at(0, 0, 0, 0)
        .to_zoned(jiff::tz::TimeZone::UTC)
        .with_context(|| format!("Failed to convert EOL date '{eol_date}' to UTC"))?;
    Ok(zoned.timestamp())
}

/// Check end-of-life status for installed runtimes
pub fn check_eol(_ctx: &CliContext) -> Result<()> {
    println!("{} Checking runtime EOL status...\n", style::runtime("OMG"));

    let now = jiff::Timestamp::now();
    // Loop-invariant warning window: a runtime within six calendar months of
    // its EOL date counts as "Ending Soon".
    let warning_ts = eol_warning_cutoff(now).context("Failed to compute EOL warning window")?;
    let runtimes = [
        "node", "python", "rust", "go", "ruby", "java", "bun", "deno",
    ];
    let mut issues = 0;

    for runtime in &runtimes {
        if let Some(version) = crate::runtimes::probe_version(runtime) {
            let installed_components = version_components(&version);
            let mut status = "Active";
            let mut eol_date_str = "Unknown";
            let mut is_eol = false;
            let mut is_warning = false;

            // Check EOL status using the shared component-prefix matcher.
            if let Some(entry) =
                crate::runtimes::eol::find_eol_entry(runtime, &installed_components)
            {
                let eol_date = entry.eol_date;
                eol_date_str = eol_date;
                let eol_timestamp = parse_eol_timestamp(eol_date).with_context(|| {
                    format!(
                        "Invalid EOL date '{eol_date}' for {runtime} {}",
                        entry
                            .version_prefix
                            .iter()
                            .map(std::string::ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(".")
                    )
                })?;

                if now > eol_timestamp {
                    status = "EOL";
                    is_eol = true;
                    issues += 1;
                } else if warning_ts > eol_timestamp {
                    status = "Ending Soon";
                    is_warning = true;
                    issues += 1;
                }
            }

            let status_display = if is_eol {
                style::error(status)
            } else if is_warning {
                style::warning(status)
            } else {
                style::success(status)
            };

            println!(
                "  {} {} v{} - {} (EOL: {})",
                if is_eol {
                    style::error("✗")
                } else if is_warning {
                    style::warning("⚠")
                } else {
                    style::success("✓")
                },
                style::runtime(runtime),
                style::version(&version),
                status_display,
                eol_date_str
            );
        }
    }

    println!();
    if issues == 0 {
        println!(
            "{} All runtimes are within support period.",
            style::success("✓")
        );
    } else {
        println!(
            "{} {} runtime(s) need attention. Consider upgrading to supported versions.",
            style::warning("⚠"),
            issues
        );
    }

    println!("\n{} Data source: endoflife.date", style::dim("ℹ"));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[serial_test::serial(history_ownership)]
    async fn security_updates_reject_missing_version_metadata_before_install() -> Result<()> {
        use crate::package_managers::PackageManager;

        let directory = tempfile::tempdir()?;
        let history =
            crate::core::history::HistoryManager::new_in(directory.path().join("history.json"))?;
        let backend = crate::core::testing::TestPackageManager::new();
        backend.add_package("example", "2.0", "Example");

        let error = apply_security_updates(&backend, &history, &["example".to_string()])
            .await
            .expect_err("do not mutate without rollback metadata");

        assert!(error.to_string().contains("rescan before fixing"));
        assert!(!backend.is_installed("example").await?);
        assert!(history.load()?.is_empty());
        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial(history_ownership)]
    async fn security_updates_propagate_history_failure() -> Result<()> {
        use crate::package_managers::{PackageManager, types::UpdateInfo};

        let directory = tempfile::tempdir()?;
        let path = directory.path().join("history.json");
        std::fs::create_dir(&path)?;
        let history = crate::core::history::HistoryManager::new_in(path)?;
        let backend = crate::core::testing::TestPackageManager::new();
        backend.add_package("example", "2.0", "Example");
        backend.set_updates(vec![UpdateInfo {
            name: "example".to_string(),
            old_version: "1.0".to_string(),
            new_version: "2.0".to_string(),
            repo: "core".to_string(),
        }]);

        let error = apply_security_updates(&backend, &history, &["example".to_string()])
            .await
            .expect_err("history failure must not report complete success");

        assert!(backend.is_installed("example").await?);
        assert!(error.to_string().contains("Package operation succeeded"));
        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial(history_ownership)]
    async fn security_updates_record_one_update_with_rollback_versions() -> Result<()> {
        use crate::core::history::{HistoryManager, TransactionType};
        use crate::core::testing::TestPackageManager;
        use crate::package_managers::types::UpdateInfo;

        let directory = tempfile::tempdir()?;
        let history = HistoryManager::new_in(directory.path().join("history.json"))?;
        let backend = TestPackageManager::new();
        backend.add_package("example", "2.0", "Example");
        backend.set_updates(vec![UpdateInfo {
            name: "example".to_string(),
            old_version: "1.0".to_string(),
            new_version: "2.0".to_string(),
            repo: "core".to_string(),
        }]);

        apply_security_updates(&backend, &history, &["example".to_string()]).await?;

        let transactions = history.load()?;
        assert_eq!(transactions.len(), 1);
        assert!(transactions[0].success);
        assert_eq!(transactions[0].transaction_type, TransactionType::Update);
        assert_eq!(transactions[0].changes.len(), 1);
        let change = &transactions[0].changes[0];
        assert_eq!(change.name, "example");
        assert_eq!(change.old_version.as_deref(), Some("1.0"));
        assert_eq!(change.new_version.as_deref(), Some("2.0"));
        assert_eq!(change.source, "core");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn security_exports_replace_permissive_files_with_private_atomic_files() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("export directory");
        let export = directory.path().join("audit.json");
        std::fs::write(&export, b"old").expect("seed export");
        std::fs::set_permissions(&export, std::fs::Permissions::from_mode(0o644))
            .expect("set permissive fixture mode");

        write_private_export(&export, b"new").expect("private export");

        assert_eq!(
            std::fs::metadata(&export)
                .expect("export metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(std::fs::read(&export).expect("export contents"), b"new");
    }

    #[test]
    fn severity_filter_returns_the_newest_matching_entries() {
        let directory = tempfile::tempdir().expect("audit directory");
        let mut logger =
            AuditLogger::new_in(directory.path().join("audit.jsonl")).expect("audit logger");
        for description in ["first", "second", "third"] {
            logger
                .log(
                    crate::core::security::audit::AuditEventType::PolicyViolation,
                    AuditSeverity::Error,
                    "policy",
                    description,
                )
                .expect("audit entry");
        }

        let entries = read_audit_entries(&logger, 2, Some("error")).expect("filtered entries");
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.description.as_str())
                .collect::<Vec<_>>(),
            ["third", "second"]
        );
    }

    #[test]
    fn license_machine_formats_include_package_rows() {
        let rows = vec![(
            "demo".to_string(),
            "MIT".to_string(),
            "1.2.3".to_string(),
            LicenseCategory::Permissive,
        )];

        let json = serialize_license_rows("json", &rows).expect("JSON report");
        let value: serde_json::Value = serde_json::from_slice(&json).expect("valid JSON");
        assert_eq!(value.as_array().map(Vec::len), Some(1));
        assert_eq!(value[0]["name"], "demo");

        let csv = serialize_license_rows("csv", &rows).expect("CSV report");
        let csv = String::from_utf8(csv).expect("UTF-8 CSV");
        assert!(csv.contains("Package,Version,License,Category"));
        assert!(csv.contains("demo,1.2.3,MIT,Permissive"));
    }

    #[test]
    fn critical_secret_findings_fail_the_command() {
        use crate::core::security::secrets::{SecretFinding, SecretSeverity, SecretType};

        let result = crate::core::security::SecretScanResult::from_findings(vec![SecretFinding {
            secret_type: SecretType::PrivateKey,
            file_path: "fixture.env".to_string(),
            line_number: 1,
            redacted: "***".to_string(),
            severity: SecretSeverity::Critical,
        }]);

        let error = enforce_secret_scan_result(&result)
            .expect_err("critical leaked secrets must produce a failing exit status");
        assert!(error.to_string().contains("critical secret"));
    }

    #[test]
    fn csv_cells_neutralize_spreadsheet_formulas() {
        assert_eq!(spreadsheet_safe_cell("=cmd()"), "'=cmd()");
        assert_eq!(spreadsheet_safe_cell("+1"), "'+1");
        assert_eq!(spreadsheet_safe_cell("normal"), "normal");
    }

    #[test]
    fn limited_is_not_classified_as_mit() {
        assert_eq!(
            LicenseCategory::from_license("LIMITED"),
            LicenseCategory::Unknown
        );
        assert_eq!(
            LicenseCategory::from_license("MIT"),
            LicenseCategory::Permissive
        );
        assert_eq!(
            LicenseCategory::from_license("MIT OR Apache-2.0"),
            LicenseCategory::Permissive
        );
        assert_eq!(
            LicenseCategory::from_license("AGPL-3.0"),
            LicenseCategory::StrongCopyleft
        );
        assert_eq!(
            LicenseCategory::from_license("GPL-2.0"),
            LicenseCategory::Copyleft
        );
    }

    #[test]
    fn slsa_check_fails_when_provenance_is_unverified() {
        let err = require_slsa_verified(false, Some("no attestation"))
            .expect_err("unverified provenance must fail the command");
        assert!(
            err.to_string().contains("SLSA verification failed"),
            "got: {err}"
        );
        assert!(
            err.to_string().contains("no attestation"),
            "failure reason must be preserved, got: {err}"
        );
        assert!(require_slsa_verified(true, None).is_ok());
        let missing_reason =
            require_slsa_verified(false, None).expect_err("unverified without details still fails");
        assert!(
            missing_reason
                .to_string()
                .contains("SLSA verification failed")
        );
    }

    #[test]
    fn audit_integrity_failure_is_an_error() {
        let err =
            require_audit_integrity(false).expect_err("broken audit chain must fail the command");
        assert!(err.to_string().contains("integrity FAILED"), "got: {err}");
        assert!(require_audit_integrity(true).is_ok());
    }

    #[test]
    fn version_components_parse_numeric_prefixes_only() {
        assert_eq!(version_components("3.13.1-1"), vec![3, 13, 1]);
        assert_eq!(version_components("1.20"), vec![1, 20]);
        assert_eq!(version_components("20.10.0"), vec![20, 10, 0]);
        assert_eq!(version_components("v22"), vec![22]);
        assert_eq!(version_components("lts/hydrogen"), Vec::<u64>::new());
    }

    #[test]
    fn eol_prefix_match_never_confuses_component_boundaries() {
        // Python 3.13 must not match a hypothetical [3, 1] row, and Go 1.30
        // must not match a [1, 3] row: component-wise starts_with is exact.
        let installed = version_components("3.13.2");
        assert!(installed.starts_with(&[3, 13][..]));
        assert!(!installed.starts_with(&[3, 1][..]));

        let go = version_components("1.30.1");
        assert!(go.starts_with(&[1, 30][..]));
        assert!(!go.starts_with(&[1, 3][..]));
    }

    #[test]
    fn parse_eol_timestamp_accepts_iso_dates() {
        let ts = parse_eol_timestamp("2025-04-30").expect("valid EOL date");
        assert!(ts.as_second() > 0);
    }

    #[test]
    fn parse_eol_timestamp_rejects_garbage() {
        let err = parse_eol_timestamp("not-a-date").expect_err("garbage must fail closed");
        assert!(err.to_string().contains("Invalid EOL date"), "got: {err}");
    }

    #[test]
    #[cfg(not(feature = "arch"))]
    fn auto_fix_update_check_without_arch_fails() {
        let error = package_has_available_update("bash")
            .expect_err("auto-fix must not treat missing update checks as unfixable");
        assert!(
            error.to_string().contains("without the Arch backend"),
            "got: {error}"
        );
    }

    #[test]
    fn license_scan_without_arch_fails() {
        let error = license_scan_requires_arch()
            .expect_err("license scan must not treat a missing backend as zero packages");
        assert!(
            error
                .to_string()
                .contains("not available without the Arch backend"),
            "got: {error}"
        );
    }

    #[test]
    fn auto_fix_upgrade_without_arch_fails() {
        let error = fix_requires_arch()
            .expect_err("auto-fix must not report success when it cannot upgrade");
        assert!(
            error.to_string().contains("without the Arch backend"),
            "got: {error}"
        );
    }

    #[test]
    fn compliance_export_inputs_reject_unsafe_paths_and_periods() {
        assert!(
            validate_compliance_export_inputs("soc2", Some("2025-Q4"), "audit-evidence").is_ok()
        );
        assert!(
            validate_compliance_export_inputs("soc2", Some("2025/04"), "audit-evidence").is_err()
        );
        assert!(validate_compliance_export_inputs("soc2", None, "/tmp/evidence").is_err());
        assert!(validate_compliance_export_inputs("unknown", None, "audit-evidence").is_err());
    }
}
