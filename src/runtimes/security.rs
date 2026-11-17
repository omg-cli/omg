//! Runtime advisory authority is bound to source evidence, installed bytes and the caller.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::core::security::advisory_review::AdvisoryRiskReview;
use crate::core::security::policy::SecurityPolicy;
use crate::core::security::scan::{
    AdvisoryProvenance, AdvisoryReference, AdvisorySeverity, FindingApplicability,
    InstalledIdentity, NativeAdvisory, Vulnerability,
};
use crate::core::security::vulnerability::{PackageAssessment, PackageCoverage, UnknownCoverage};
use crate::package_managers::types::{SecurityOrigin, SecurityPackage};

const ENDPOINT: &str = "https://omg-advisories.latham.workers.dev/v1/runtimes/";
const MAX_REPORT: usize = 2 * 1024 * 1024;
const MAX_TREE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_TREE_ENTRIES: usize = 200_000;
const MAX_AGE_SECONDS: i64 = 30 * 60;
const OWNED_MARKERS: &[&str] = &[".omg-install-complete", ".omg-installing"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReviewMode {
    FreshAttended,
    CachedOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeQuery {
    pub(crate) runtime: String,
    pub(crate) vendor: String,
    pub(crate) version: String,
    pub(crate) os: String,
    pub(crate) arch: String,
}

pub(crate) trait RuntimeEvidenceSource: Send + Sync {
    fn read(&self, query: &RuntimeQuery) -> Result<Vec<u8>>;
}

#[derive(Clone)]
pub(crate) struct RuntimeSecurity {
    source: Arc<dyn RuntimeEvidenceSource>,
}

impl Default for RuntimeSecurity {
    fn default() -> Self {
        Self::with_source(Arc::new(HttpSource))
    }
}

struct HttpSource;
impl RuntimeEvidenceSource for HttpSource {
    fn read(&self, query: &RuntimeQuery) -> Result<Vec<u8>> {
        let mut url = reqwest::Url::parse(&format!("{ENDPOINT}{}", query.runtime))?;
        url.query_pairs_mut()
            .append_pair("version", &query.version)
            .append_pair("vendor", &query.vendor)
            .append_pair("os", &query.os)
            .append_pair("arch", &query.arch);
        super::tool_artifacts::scoped_future(async move {
            let response = crate::core::http::fetch_public_download_fresh(
                url.as_str(),
                "omg-runtime-advisories/1",
                Some(std::time::Duration::from_secs(20)),
            )
            .await?;
            runtime_response_bytes(response).await
        })
        .context("Runtime advisory transport failed")
    }
}

async fn runtime_response_bytes(mut response: reqwest::Response) -> Result<Vec<u8>> {
    ensure!(
        response.status().is_success(),
        "Runtime advisory provider returned HTTP {}",
        response.status()
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= MAX_REPORT,
            "Runtime advisory response exceeds its bound"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceReceipt {
    name: String,
    url: String,
    revision: Option<String>,
    payload_sha256: String,
    checked_at: jiff::Timestamp,
    complete: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Finding {
    id: String,
    summary: String,
    applicability: FindingApplicability,
    severity: Option<String>,
    urls: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Coverage {
    Assessed,
    Partial,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema_version: u32,
    identity: RuntimeQuery,
    checked_at: jiff::Timestamp,
    coverage: Coverage,
    findings: Vec<Finding>,
    gaps: Vec<String>,
    sources: Vec<SourceReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallIdentity {
    schema_version: u32,
    runtime: String,
    requested: String,
    version: String,
    vendor: String,
    build: String,
    source_url: String,
    artifact_sha256: String,
    components: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheRecord {
    schema_version: u32,
    destination: PathBuf,
    query: RuntimeQuery,
    content_sha256: String,
    identity_sha256: String,
    policy_sha256: String,
    #[serde(default)]
    local_gaps: Vec<String>,
    uid: u32,
    euid: u32,
    report: Envelope,
    accepted_review: Option<String>,
}

#[derive(Debug)]
pub(crate) struct RuntimeAdmission {
    record: CacheRecord,
    tree: PathBuf,
    _lease: Option<super::common::RuntimeLease>,
}

impl RuntimeAdmission {
    pub(crate) fn identity_context(&self) -> Result<String> {
        self.verify_before_execution()?;
        Ok(serde_json::to_string(&(
            &self.record.query,
            &self.record.destination,
            &self.record.content_sha256,
            &self.record.identity_sha256,
            &self.record.policy_sha256,
            self.record.uid,
            self.record.euid,
        ))?)
    }
    pub(crate) fn verify_before_execution(&self) -> Result<()> {
        self.verify_tree(&self.tree)
    }

    pub(crate) fn before_execution(&self, tree: &Path) -> Result<()> {
        self.verify_tree(tree)
    }
    pub(crate) fn verify(&self, version_dir: &Path) -> Result<()> {
        let root = canonical_destination(version_dir)?;
        ensure!(
            root == self.record.destination,
            "Runtime advisory admission names another destination"
        );
        self.verify_tree(version_dir)
    }

    fn verify_tree(&self, tree: &Path) -> Result<()> {
        let canonical = canonical_destination(tree)?;
        ensure!(
            canonical == self.tree || canonical == self.record.destination,
            "Runtime advisory execution names another tree"
        );
        ensure!(
            principal() == (self.record.uid, self.record.euid),
            "Runtime advisory principal changed"
        );
        ensure!(
            policy_digest()? == self.record.policy_sha256,
            "Runtime advisory policy changed"
        );
        ensure!(
            tree_digest(tree)? == self.record.content_sha256,
            "Runtime content changed after advisory review"
        );
        let identity = read_identity(&self.record.destination)?;
        ensure!(
            identity_digest(identity.as_ref())? == self.record.identity_sha256,
            "Runtime identity or publisher changed after advisory review"
        );
        validate_envelope(
            &self.record.report,
            &self.record.query,
            jiff::Timestamp::now(),
        )?;
        validate_acceptance(&self.record)?;
        if self.record.query.runtime == "pi" {
            verify_pi_dependency(tree)?;
        }
        Ok(())
    }
}

pub(crate) fn admit_installed(
    runtime: &str,
    version_dir: &Path,
    mode: ReviewMode,
) -> Result<RuntimeAdmission> {
    admit_installed_with_source(runtime, version_dir, mode, &HttpSource)
}

pub(crate) fn admit_installed_with_source(
    runtime: &str,
    version_dir: &Path,
    mode: ReviewMode,
    source: &dyn RuntimeEvidenceSource,
) -> Result<RuntimeAdmission> {
    let _admission_lease = lock_admission(version_dir)?;
    let version = version_dir
        .file_name()
        .and_then(|name| name.to_str())
        .context("Runtime advisory version has no valid name")?;
    admit_tree(
        runtime,
        version,
        version_dir,
        version_dir,
        mode,
        source,
        false,
    )
}

impl RuntimeSecurity {
    pub(crate) fn with_source(source: Arc<dyn RuntimeEvidenceSource>) -> Self {
        Self { source }
    }

    pub(crate) fn installed(
        &self,
        runtime: &str,
        version_dir: &Path,
        mode: ReviewMode,
    ) -> Result<RuntimeAdmission> {
        admit_installed_with_source(runtime, version_dir, mode, self.source.as_ref())
    }

    pub(crate) fn prepare_staged(
        &self,
        runtime: &str,
        version: &str,
        staging: &Path,
        destination: &Path,
    ) -> Result<RuntimeAdmission> {
        admit_tree(
            runtime,
            version,
            staging,
            destination,
            ReviewMode::FreshAttended,
            self.source.as_ref(),
            true,
        )
    }

    #[cfg(test)]
    pub(crate) fn fixture() -> Self {
        Self::with_source(Arc::new(FixtureSource))
    }
}

/// Common mutation helpers can consume only a validated, already reviewed installation.
pub(crate) fn require_prepared(tree: &Path, destination: &Path) -> Result<RuntimeAdmission> {
    let destination = canonical_destination(destination)?;
    let record = load_cache(&destination)?.context(
        "Runtime advisory review is missing; run explicit omg use to review this version",
    )?;
    let admission = RuntimeAdmission {
        record,
        tree: canonical_destination(tree)?,
        _lease: None,
    };
    admission.verify_tree(tree)?;
    Ok(admission)
}

/// Automatic hooks may validate current evidence, but cannot fetch or prompt.
pub(crate) fn require_selected_path(runtime: &str, binary_dir: &Path) -> Result<RuntimeAdmission> {
    admit_selected_path(runtime, binary_dir, ReviewMode::CachedOnly)
}

pub(crate) fn admit_selected_path(
    runtime: &str,
    binary_dir: &Path,
    mode: ReviewMode,
) -> Result<RuntimeAdmission> {
    let root = match runtime {
        "bun" | "dotnet" => binary_dir.to_path_buf(),
        "swift" => binary_dir
            .parent()
            .and_then(Path::parent)
            .context("Swift runtime advisory root is missing")?
            .to_path_buf(),
        _ => binary_dir
            .parent()
            .context("Runtime advisory root is missing")?
            .to_path_buf(),
    };
    let versions = root
        .parent()
        .context("Runtime advisory root has no versions parent")?;
    ensure!(
        versions.file_name().and_then(|name| name.to_str()) == Some(runtime)
            && versions
                .parent()
                .and_then(Path::file_name)
                .and_then(|name| name.to_str())
                == Some("versions"),
        "System or unversioned runtime has no managed advisory identity; install and select it with omg use {runtime} <version>"
    );
    let lease = super::common::try_lock_runtime_use(versions)?;
    let admission = admit_installed(runtime, &root, mode)?;
    ensure!(
        admission.record.query.runtime == runtime,
        "Runtime advisory path belongs to another product"
    );
    Ok(RuntimeAdmission {
        _lease: Some(lease),
        ..admission
    })
}

fn admit_tree(
    runtime: &str,
    requested: &str,
    tree: &Path,
    destination: &Path,
    mode: ReviewMode,
    source: &dyn RuntimeEvidenceSource,
    candidate: bool,
) -> Result<RuntimeAdmission> {
    let destination = canonical_destination(destination)?;
    let prior = load_cache(&destination)?;
    if mode == ReviewMode::CachedOnly {
        ensure!(
            prior.is_some(),
            "Runtime advisory evidence is missing; run explicit omg use to review this version"
        );
    }
    let identity = read_identity(&destination)?;
    let (query, identity_gap) = resolve_identity(runtime, requested, tree, identity.as_ref())?;
    let content = tree_digest(tree)?;
    let identity_sha256 = identity_digest(identity.as_ref())?;
    let policy = SecurityPolicy::load_current()?;
    let policy_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&policy)?));
    let (uid, euid) = principal();
    if mode == ReviewMode::CachedOnly || !candidate {
        let cached = prior
            .as_ref()
            .map(|record| -> Result<RuntimeAdmission> {
                ensure!(
                    record.query == query
                        && record.content_sha256 == content
                        && record.policy_sha256 == policy_sha256,
                    "Runtime advisory evidence changed; run explicit omg use for a new review"
                );
                let admission = RuntimeAdmission {
                    record: record.clone(),
                    tree: canonical_destination(tree)?,
                    _lease: None,
                };
                admission.verify(tree)?;
                Ok(admission)
            })
            .transpose();
        match cached {
            Ok(Some(admission)) => return Ok(admission),
            Err(error) if mode == ReviewMode::CachedOnly => return Err(error),
            Ok(None) if mode == ReviewMode::CachedOnly => anyhow::bail!(
                "Runtime advisory evidence is missing; run explicit omg use to review this version"
            ),
            Ok(None) | Err(_) => {}
        }
    }
    let mut local_gaps = if candidate {
        Vec::new()
    } else {
        prior
            .as_ref()
            .map(|record| record.local_gaps.clone())
            .unwrap_or_default()
    };
    local_gaps.extend(identity_gap);
    if !candidate
        && prior
            .as_ref()
            .is_some_and(|record| record.content_sha256 != content)
    {
        local_gaps.push("Installed runtime content differs from the previous verified content; its declared version no longer establishes unchanged publisher identity".to_owned());
    }
    if !candidate
        && prior
            .as_ref()
            .is_some_and(|record| record.identity_sha256 != identity_sha256)
    {
        local_gaps.push("Installed publisher identity differs from the previous verified identity; new archive metadata does not authenticate unchanged installed bytes".to_owned());
    }
    local_gaps.sort();
    local_gaps.dedup();
    let mut report = read_report(source, &query, prior.as_ref().map(|record| &record.report));
    if !local_gaps.is_empty() {
        report.coverage = Coverage::Unknown;
        report.gaps.extend(local_gaps.iter().cloned());
    }
    validate_envelope(&report, &query, jiff::Timestamp::now())?;
    let mut record = CacheRecord {
        schema_version: 1,
        destination,
        query,
        content_sha256: content,
        identity_sha256,
        policy_sha256,
        local_gaps: local_gaps.clone(),
        uid,
        euid,
        report,
        accepted_review: None,
    };
    let evaluated = assessments(&record.report)?;
    for assessment in &evaluated {
        policy.check_source(&assessment.package.name, &assessment.package.origin, None)?;
    }
    let context = context(&record)?;
    if let Some(review) = AdvisoryRiskReview::new_with_unknown(&evaluated, &context)? {
        let reusable = prior.as_ref().is_some_and(|previous| {
            previous.accepted_review.as_deref() == Some(review.id())
                && validate_acceptance(previous).is_ok()
        });
        if !reusable {
            let mut details = review.details().to_owned();
            for gap in &record.report.gaps {
                let _ = write!(details, "\nCoverage gap: {}", serde_json::to_string(gap)?);
            }
            for source in &record.report.sources {
                let _ = write!(
                    details,
                    "\nSource: {}\n{}",
                    serde_json::to_string(&source.name)?,
                    source.url
                );
            }
            ensure!(
                details.len() <= 60 * 1024,
                "Runtime advisory review exceeds the terminal display bound"
            );
            crate::core::privilege::confirm_security_review(
                &details,
                review.id(),
                uid,
                &|| Ok(()),
            )?;
        }
        let fresh = read_report(source, &record.query, Some(&record.report));
        let mut current = fresh;
        if !local_gaps.is_empty() {
            current.coverage = Coverage::Unknown;
            current.gaps.extend(local_gaps.iter().cloned());
        }
        let current_review =
            AdvisoryRiskReview::new_with_unknown(&assessments(&current)?, &context)?;
        let acceptance = review.accept(&format!("accept {}", review.id()))?;
        ensure!(
            current_review
                .as_ref()
                .is_some_and(|review| acceptance.matches(review)),
            "Runtime advisory evidence changed after acceptance; review again"
        );
        record.report = current;
        record.accepted_review = Some(review.id().to_owned());
    }
    let admission = RuntimeAdmission {
        record,
        tree: canonical_destination(tree)?,
        _lease: None,
    };
    admission.verify_tree(tree)?;
    save_cache(&admission.record)?;
    Ok(admission)
}

fn context(record: &CacheRecord) -> Result<String> {
    Ok(serde_json::to_string(&(
        "omg-runtime-admission-v1",
        &record.destination,
        &record.query,
        &record.content_sha256,
        &record.identity_sha256,
        &record.policy_sha256,
        record.uid,
        record.euid,
    ))?)
}

fn validate_acceptance(record: &CacheRecord) -> Result<()> {
    ensure!(
        record.schema_version == 1,
        "Unsupported runtime advisory cache schema"
    );
    ensure!(
        record.local_gaps.is_empty()
            || (record.report.coverage == Coverage::Unknown
                && record
                    .local_gaps
                    .iter()
                    .all(|gap| record.report.gaps.contains(gap))),
        "Unresolved local runtime integrity cannot become assessed coverage"
    );
    let review =
        AdvisoryRiskReview::new_with_unknown(&assessments(&record.report)?, &context(record)?)?;
    ensure!(
        match review {
            Some(review) => record.accepted_review.as_deref() == Some(review.id()),
            None => record.accepted_review.is_none(),
        },
        "Runtime advisory decision does not match current evidence"
    );
    Ok(())
}

fn read_report(
    source: &dyn RuntimeEvidenceSource,
    query: &RuntimeQuery,
    previous: Option<&Envelope>,
) -> Envelope {
    let result = source.read(query).and_then(|raw| {
        ensure!(
            raw.len() <= MAX_REPORT,
            "Runtime advisory response exceeds its bound"
        );
        let report: Envelope =
            serde_json::from_slice(&raw).context("Malformed runtime advisory response")?;
        validate_envelope(&report, query, jiff::Timestamp::now())?;
        Ok(report)
    });
    match result {
        Ok(report) => report,
        Err(error) => Envelope {
            schema_version: 1,
            identity: query.clone(),
            checked_at: jiff::Timestamp::now(),
            coverage: Coverage::Unknown,
            findings: previous
                .map(|report| report.findings.clone())
                .unwrap_or_default(),
            gaps: vec![format!(
                "Runtime advisory provider is unavailable: {}",
                crate::cli::style::sanitize_terminal_text(&format!("{error:#}"))
                    .chars()
                    .take(500)
                    .collect::<String>()
            )],
            sources: Vec::new(),
        },
    }
}

fn validate_envelope(report: &Envelope, query: &RuntimeQuery, now: jiff::Timestamp) -> Result<()> {
    ensure!(
        report.schema_version == 1 && report.identity == *query,
        "Runtime advisory identity or schema mismatch"
    );
    fresh(report.checked_at, now)?;
    ensure!(
        report.findings.len() <= 512 && report.gaps.len() <= 64 && report.sources.len() <= 16,
        "Runtime advisory inventory exceeds its bound"
    );
    ensure!(
        report.coverage != Coverage::Assessed
            || (!report.sources.is_empty()
                && report.sources.iter().all(|source| source.complete)
                && report.gaps.is_empty()),
        "Incomplete runtime advisory source cannot establish assessed coverage"
    );
    ensure!(
        !report.sources.is_empty()
            || (report.coverage == Coverage::Unknown && !report.gaps.is_empty()),
        "Empty runtime sources require explicit Unknown coverage"
    );
    ensure!(
        report.coverage != Coverage::Unknown || !report.gaps.is_empty(),
        "Unknown runtime advisory coverage lacks a reason"
    );
    let mut ids = BTreeSet::new();
    for finding in &report.findings {
        text(&finding.id, 160)?;
        text(&finding.summary, 256)?;
        ensure!(
            ids.insert(&finding.id),
            "Duplicate runtime advisory identity"
        );
        ensure!(
            finding.urls.len() <= 4,
            "Runtime advisory references exceed their bound"
        );
        for url in &finding.urls {
            source_url(url)?;
        }
        if let Some(severity) = &finding.severity {
            text(severity, 64)?;
        }
    }
    for gap in &report.gaps {
        text(gap, 1024)?;
    }
    for source in &report.sources {
        text(&source.name, 128)?;
        source_url(&source.url)?;
        if let Some(revision) = &source.revision {
            text(revision, 256)?;
        }
        digest(&source.payload_sha256)?;
        fresh(source.checked_at, now)?;
        ensure!(
            report.checked_at <= source.checked_at,
            "Runtime advisory aggregate timestamp exceeds its source timestamp"
        );
    }
    Ok(())
}

fn assessments(report: &Envelope) -> Result<Vec<PackageAssessment>> {
    let mut findings = report.findings.clone();
    for finding in &mut findings {
        finding.urls.sort();
    }
    findings.sort_by(|a, b| a.id.cmp(&b.id));
    let mut gaps = report.gaps.clone();
    gaps.sort();
    gaps.dedup();
    let mut sources = report
        .sources
        .iter()
        .map(|source| {
            (
                &source.name,
                &source.url,
                &source.revision,
                &source.payload_sha256,
                source.complete,
            )
        })
        .collect::<Vec<_>>();
    sources.sort();
    let semantic = serde_json::to_vec(&(report.coverage, findings, gaps, sources))?;
    let provenance = AdvisoryProvenance::RuntimeSnapshot {
        runtime: report.identity.runtime.clone(),
        source: ENDPOINT.to_owned(),
        payload_sha256: hex::encode(Sha256::digest(semantic)),
        checked_at: report.checked_at,
    };
    let package = SecurityPackage {
        origin: SecurityOrigin::RuntimeVendor {
            runtime: report.identity.runtime.clone(),
            vendor: report.identity.vendor.clone(),
        },
        name: report.identity.runtime.clone(),
        version: report.identity.version.clone(),
        advisory_source: None,
        architecture: Some(report.identity.arch.clone()),
        description: String::new(),
        licenses: Vec::new(),
    };
    let finding_identity = InstalledIdentity::from(&package);
    let findings = report
        .findings
        .iter()
        .map(|finding| Vulnerability {
            applicability: finding.applicability,
            id: finding.id.clone(),
            summary: finding.summary.clone(),
            score: None,
            advisory_severity: finding.severity.as_deref().and_then(|value| {
                match value.to_ascii_lowercase().as_str() {
                    "critical" => Some(AdvisorySeverity::Critical),
                    "high" | "important" => Some(AdvisorySeverity::Important),
                    "medium" | "moderate" => Some(AdvisorySeverity::Moderate),
                    "low" => Some(AdvisorySeverity::Low),
                    _ => None,
                }
            }),
            native_advisory: Some(NativeAdvisory {
                source: "runtime-vendor".to_owned(),
                advisory_nevra: report.identity.version.clone(),
                published_severity: finding
                    .severity
                    .clone()
                    .unwrap_or_else(|| "unspecified".to_owned()),
                description: report.gaps.join("; "),
                references: finding
                    .urls
                    .iter()
                    .map(|url| AdvisoryReference {
                        id: finding.id.clone(),
                        kind: "vendor".to_owned(),
                        url: url.clone(),
                    })
                    .collect(),
            }),
            affected_installed: vec![finding_identity.clone()],
        })
        .collect();
    Ok(vec![PackageAssessment {
        package,
        coverage: if report.coverage == Coverage::Assessed {
            PackageCoverage::Assessed { provenance }
        } else {
            PackageCoverage::Unknown {
                reason: UnknownCoverage::EvidenceUnavailable,
                provenance: Some(provenance),
            }
        },
        findings,
    }])
}

fn fresh(checked: jiff::Timestamp, now: jiff::Timestamp) -> Result<()> {
    ensure!(
        checked <= now && now.as_second() - checked.as_second() <= MAX_AGE_SECONDS,
        "Runtime advisory evidence is stale or future-dated: checked={checked}, now={now}, maximum_age_seconds={MAX_AGE_SECONDS}"
    );
    Ok(())
}
fn text(value: &str, limit: usize) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= limit && !value.chars().any(char::is_control),
        "Invalid bounded runtime advisory text"
    );
    Ok(())
}
fn digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "Invalid runtime advisory digest"
    );
    Ok(())
}
fn source_url(value: &str) -> Result<()> {
    text(value, 1024)?;
    let url = reqwest::Url::parse(value)?;
    ensure!(
        url.scheme() == "https" && url.username().is_empty() && url.password().is_none(),
        "Runtime advisory source must use HTTPS without credentials"
    );
    crate::core::http::validate_download_url(value)?;
    Ok(())
}
fn principal() -> (u32, u32) {
    (
        nix::unistd::getuid().as_raw(),
        nix::unistd::geteuid().as_raw(),
    )
}
fn policy_digest() -> Result<String> {
    let policy = SecurityPolicy::load_current()?;
    let bytes = serde_json::to_vec(&policy)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn vendor(runtime: &str) -> &'static str {
    match runtime {
        "node" => "nodejs",
        "python" => "cpython",
        "go" => "golang",
        "rust" => "rust-lang",
        "ruby" => "ruby-lang",
        "java" => "temurin",
        "bun" => "oven-sh",
        "pi" => "earendil-works",
        "deno" => "denoland",
        "zig" => "ziglang",
        "dotnet" => "microsoft",
        "erlang" => "erlang",
        "php" => "php",
        "swift" => "swiftlang",
        _ => "unmapped",
    }
}

fn resolve_identity(
    runtime: &str,
    requested: &str,
    tree: &Path,
    identity: Option<&InstallIdentity>,
) -> Result<(RuntimeQuery, Option<String>)> {
    let vendor = vendor(runtime);
    crate::core::security::validate_runtime_version(requested)?;
    let mut version = requested.trim_start_matches('v').to_owned();
    let mut gap = (vendor == "unmapped")
        .then(|| format!("No supported runtime advisory product mapping exists for {runtime}"));
    if let Some(identity) = identity {
        ensure!(
            identity.schema_version == 1
                && identity.runtime == runtime
                && identity.vendor == vendor
                && identity.requested == requested,
            "Runtime publisher identity does not match installation"
        );
        version.clone_from(&identity.version);
    } else if runtime == "rust" {
        let bytes = read_regular(&tree.join(".omg-toolchain.toml"), 1024 * 1024)?;
        if let Some(bytes) = bytes {
            let metadata: toml::Value = toml::from_str(std::str::from_utf8(&bytes)?)?;
            if let Some(release) = metadata.get("release").and_then(toml::Value::as_str) {
                release
                    .split_whitespace()
                    .next()
                    .unwrap_or(release)
                    .clone_into(&mut version);
            }
        }
    }
    if runtime == "java"
        && version.split('.').count() < 3
        && let Some(bytes) = read_regular(&tree.join("release"), 1024 * 1024)?
    {
        let release = std::str::from_utf8(&bytes)?;
        if let Some(value) = release
            .lines()
            .find_map(|line| line.strip_prefix("JAVA_VERSION=\""))
            && let Some(value) = value.strip_suffix('"')
        {
            value.clone_into(&mut version);
        }
    }
    if runtime == "php" && version.split('.').count() < 3 {
        for header in [
            "include/php/main/php_version.h",
            "include/php8/main/php_version.h",
            "include/php/main/php.h",
        ] {
            if let Some(raw) = read_regular(&tree.join(header), 1024 * 1024)?
                && let Some(value) = std::str::from_utf8(&raw)?
                    .lines()
                    .find_map(|line| line.trim().strip_prefix("#define PHP_VERSION "))
                    .map(str::trim)
                    .and_then(|value| value.strip_prefix('"'))
                    .and_then(|value| value.strip_suffix('"'))
            {
                value.clone_into(&mut version);
                break;
            }
        }
    }
    if identity.is_none() && runtime != "pi" {
        gap = Some(format!(
            "Publisher artifact identity is unavailable for existing {runtime} {requested}; advisory version metadata does not authenticate the installed content"
        ));
    }
    if !version.split('+').next().is_some_and(|value| {
        value.split('.').count()
            >= if matches!(runtime, "erlang" | "swift") {
                2
            } else {
                3
            }
            && value
                .split('.')
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    }) {
        gap = Some(format!(
            "Exact runtime identity for {runtime} {requested} could not be established without executing it"
        ));
    }
    let (mut os, mut arch) = (
        std::env::consts::OS.to_owned(),
        std::env::consts::ARCH.to_owned(),
    );
    if runtime == "rust" {
        let host = super::rust::RustToolchainSpec::parse(requested)?.host;
        let platform = match host.as_str() {
            "x86_64-unknown-linux-gnu" | "x86_64-unknown-linux-musl" => Some(("linux", "x86_64")),
            "aarch64-unknown-linux-gnu" | "aarch64-unknown-linux-musl" => {
                Some(("linux", "aarch64"))
            }
            "x86_64-apple-darwin" => Some(("macos", "x86_64")),
            "aarch64-apple-darwin" => Some(("macos", "aarch64")),
            _ => None,
        };
        if let Some((artifact_os, artifact_arch)) = platform {
            artifact_os.clone_into(&mut os);
            artifact_arch.clone_into(&mut arch);
        } else {
            "unknown".clone_into(&mut os);
            "unknown".clone_into(&mut arch);
            gap = Some(format!(
                "Rust compiler host {host} has no supported advisory platform mapping"
            ));
        }
    }
    text(&version, 128)?;
    Ok((
        RuntimeQuery {
            runtime: runtime.to_owned(),
            vendor: vendor.to_owned(),
            version,
            os,
            arch,
        },
        gap,
    ))
}

fn identity_digest(identity: Option<&InstallIdentity>) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&identity)?)))
}

fn canonical_destination(path: &Path) -> Result<PathBuf> {
    ensure!(
        path.is_absolute(),
        "Runtime advisory destination must be absolute"
    );
    let parent = path
        .parent()
        .context("Runtime advisory destination has no parent")?
        .canonicalize()?;
    let name = path
        .file_name()
        .context("Runtime advisory destination has no filename")?;
    let result = parent.join(name);
    if let Ok(metadata) = fs::symlink_metadata(&result) {
        ensure!(
            metadata.is_dir() && !metadata.is_symlink(),
            "Runtime advisory destination is not a real directory"
        );
    }
    Ok(result)
}

fn state_path(destination: &Path, suffix: &str) -> Result<PathBuf> {
    let parent = destination
        .parent()
        .context("Runtime advisory destination has no parent")?;
    let directory = parent.join(".security");
    if let Ok(metadata) = fs::symlink_metadata(&directory) {
        use std::os::unix::fs::MetadataExt as _;
        ensure!(
            metadata.is_dir()
                && !metadata.is_symlink()
                && metadata.uid() == nix::unistd::geteuid().as_raw()
                && metadata.mode().trailing_zeros() >= 6,
            "Unsafe runtime advisory state directory"
        );
    }
    let key = hex::encode(Sha256::digest(serde_json::to_vec(&destination)?));
    Ok(directory.join(format!("{key}.{suffix}.json")))
}

fn read_regular(path: &Path, limit: usize) -> Result<Option<Vec<u8>>> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path);
    let mut file = match file {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("Read runtime advisory metadata"),
    };
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.len() <= limit as u64
            && metadata.uid() == nix::unistd::geteuid().as_raw()
            && metadata.permissions().mode() & 0o022 == 0,
        "Unsafe runtime advisory metadata"
    );
    let mut bytes = Vec::new();
    file.by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit,
        "Runtime advisory metadata exceeds its bound"
    );
    Ok(Some(bytes))
}

fn load_cache(destination: &Path) -> Result<Option<CacheRecord>> {
    let Some(bytes) = read_regular(&state_path(destination, "admission")?, MAX_REPORT * 2)? else {
        return Ok(None);
    };
    let record: CacheRecord =
        serde_json::from_slice(&bytes).context("Invalid runtime advisory cache")?;
    ensure!(
        record.destination == destination,
        "Runtime advisory cache names another installation"
    );
    Ok(Some(record))
}
fn read_identity(destination: &Path) -> Result<Option<InstallIdentity>> {
    read_regular(&state_path(destination, "identity")?, 1024 * 1024)?
        .map(|bytes| serde_json::from_slice(&bytes).context("Invalid runtime publisher identity"))
        .transpose()
}
fn write_state(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let parent = path
        .parent()
        .context("Runtime advisory state has no parent")?;
    crate::core::paths::create_private_data_directory(parent)?;
    let metadata = fs::symlink_metadata(parent)?;
    ensure!(
        metadata.is_dir()
            && !metadata.is_symlink()
            && metadata.uid() == nix::unistd::geteuid().as_raw()
            && metadata.permissions().mode().trailing_zeros() >= 6,
        "Unsafe runtime advisory state ownership"
    );
    crate::core::safe_ops::atomic_write_file_sync_private(path, bytes)
}
fn save_cache(record: &CacheRecord) -> Result<()> {
    write_state(
        &state_path(&record.destination, "admission")?,
        &serde_json::to_vec(record)?,
    )
}

fn lock_admission(destination: &Path) -> Result<super::common::RuntimeLease> {
    let destination = canonical_destination(destination)?;
    let version = destination
        .file_name()
        .and_then(|value| value.to_str())
        .context("Runtime admission version is missing")?;
    crate::core::security::validate_runtime_version(version)?;
    super::common::try_lock_runtime_file(
        destination
            .parent()
            .context("Runtime admission parent is missing")?,
        &format!(".admission-{version}.lock"),
    )
}

/// Preserve the published authority until its candidate is actually published.
#[must_use]
pub(crate) struct PublisherTransaction {
    state: Vec<(PathBuf, Option<Vec<u8>>)>,
    _lease: super::common::RuntimeLease,
    committed: bool,
}

impl PublisherTransaction {
    fn begin(destination: &Path) -> Result<Self> {
        let lease = lock_admission(destination)?;
        let mut state = Vec::new();
        for (suffix, limit) in [("identity", MAX_REPORT), ("admission", MAX_REPORT * 2)] {
            let path = state_path(destination, suffix)?;
            state.push((path.clone(), read_regular(&path, limit)?));
        }
        Ok(Self {
            state,
            _lease: lease,
            committed: false,
        })
    }

    pub(crate) fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for PublisherTransaction {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for (path, prior) in &self.state {
            let result = match prior {
                Some(bytes) => write_state(path, bytes),
                None => match fs::remove_file(path) {
                    Ok(()) => Ok(()),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(error) => Err(error.into()),
                },
            };
            if let Err(error) = result {
                tracing::error!(path = %path.display(), %error, "Failed to restore runtime publisher authority after cancelled publication");
            }
        }
    }
}

/// The caller invokes this only after its existing publisher/checksum verification.
pub(crate) fn record_download(
    runtime: &str,
    version: &str,
    destination: &Path,
    archive: &Path,
    source: &str,
) -> Result<PublisherTransaction> {
    let destination = canonical_destination(destination)?;
    source_url(source)?;
    let transaction = PublisherTransaction::begin(&destination)?;
    let identity = InstallIdentity {
        schema_version: 1,
        runtime: runtime.to_owned(),
        requested: version.to_owned(),
        version: version.to_owned(),
        vendor: vendor(runtime).to_owned(),
        build: String::new(),
        source_url: source.to_owned(),
        artifact_sha256: file_digest(archive, MAX_TREE_BYTES)?.0,
        components: BTreeMap::new(),
    };
    write_state(
        &state_path(&destination, "identity")?,
        &serde_json::to_vec(&identity)?,
    )?;
    Ok(transaction)
}

pub(crate) fn record_manifest(
    runtime: &str,
    requested: &str,
    destination: &Path,
    source: &str,
    manifest: &[u8],
) -> Result<PublisherTransaction> {
    let destination = canonical_destination(destination)?;
    source_url(source)?;
    let transaction = PublisherTransaction::begin(&destination)?;
    ensure!(
        manifest.len() <= 16 * 1024 * 1024,
        "Runtime publisher manifest exceeds its bound"
    );
    let identity = InstallIdentity {
        schema_version: 1,
        runtime: runtime.to_owned(),
        requested: requested.to_owned(),
        version: requested.to_owned(),
        vendor: vendor(runtime).to_owned(),
        build: String::new(),
        source_url: source.to_owned(),
        artifact_sha256: hex::encode(Sha256::digest(manifest)),
        components: BTreeMap::new(),
    };
    write_state(
        &state_path(&destination, "identity")?,
        &serde_json::to_vec(&identity)?,
    )?;
    Ok(transaction)
}

pub(crate) fn record_exact_release(
    destination: &Path,
    version: &str,
    build: &str,
    components: BTreeMap<String, String>,
) -> Result<()> {
    text(version, 128)?;
    let destination = canonical_destination(destination)?;
    let mut identity =
        read_identity(&destination)?.context("Runtime verified publisher identity is missing")?;
    version.clone_into(&mut identity.version);
    build.clone_into(&mut identity.build);
    identity.components = components;
    write_state(
        &state_path(&destination, "identity")?,
        &serde_json::to_vec(&identity)?,
    )
}

pub(crate) fn validate_java_release(tree: &Path, destination: &Path) -> Result<()> {
    let Some(raw) = read_regular(&tree.join("release"), 1024 * 1024)? else {
        return Ok(());
    };
    let release = std::str::from_utf8(&raw)?;
    let declared = release
        .lines()
        .find_map(|line| line.strip_prefix("JAVA_VERSION=\""))
        .and_then(|value| value.strip_suffix('"'));
    if let Some(declared) = declared {
        let declared = declared.split('+').next().unwrap_or(declared);
        let declared = match declared.strip_prefix("1.8.0_") {
            Some(update)
                if !update.is_empty() && update.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                format!("8.0.{update}")
            }
            _ => declared.to_owned(),
        };
        let identity = read_identity(&canonical_destination(destination)?)?
            .context("Java publisher identity is missing")?;
        ensure!(
            identity.version.split('+').next() == Some(declared.as_str()),
            "Java archive release disagrees with exact publisher metadata"
        );
    }
    Ok(())
}

pub(crate) fn file_digest(path: &Path, limit: u64) -> Result<(String, u64)> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.len() <= limit,
        "Runtime content is not a bounded regular file"
    );
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut count = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        count += read as u64;
        ensure!(count <= limit, "Runtime content exceeds its byte budget");
        hasher.update(&buffer[..read]);
    }
    let after = file.metadata()?;
    ensure!(
        before.len() == after.len()
            && before.modified()? == after.modified()?
            && count == after.len(),
        "Runtime content changed while being reviewed"
    );
    Ok((hex::encode(hasher.finalize()), count))
}

fn tree_digest(root: &Path) -> Result<String> {
    use std::os::unix::fs::PermissionsExt as _;
    let metadata = fs::symlink_metadata(root)?;
    ensure!(
        metadata.is_dir() && !metadata.is_symlink(),
        "Runtime advisory tree is not a real directory"
    );
    let canonical = root.canonicalize()?;
    let mut pending = vec![root.to_path_buf()];
    let mut rows = BTreeMap::new();
    let mut bytes = 0_u64;
    let mut entries = 0_usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            let relative = path.strip_prefix(root)?.to_path_buf();
            if relative.components().count() == 1
                && OWNED_MARKERS.iter().any(|name| relative == Path::new(name))
            {
                continue;
            }
            entries += 1;
            ensure!(
                entries <= MAX_TREE_ENTRIES,
                "Runtime inventory exceeds its entry budget"
            );
            let metadata = fs::symlink_metadata(&path)?;
            let mode = metadata.permissions().mode() & 0o777;
            if metadata.is_dir() {
                rows.insert(relative, ("directory", mode, String::new(), 0));
                pending.push(path);
            } else if metadata.is_file() {
                let (hash, size) = if relative == Path::new(".omg-npm-advisory-review.json") {
                    let raw =
                        read_regular(&path, MAX_REPORT)?.context("Missing npm advisory review")?;
                    let mut receipt: serde_json::Value = serde_json::from_slice(&raw)?;
                    let object = receipt
                        .as_object_mut()
                        .context("Invalid npm advisory review object")?;
                    let checked: jiff::Timestamp = object
                        .remove("reviewed_at")
                        .and_then(|value| value.as_str().map(str::to_owned))
                        .context("Missing npm review timestamp")?
                        .parse()?;
                    fresh(checked, jiff::Timestamp::now())?;
                    let semantic = serde_json::to_vec(&receipt)?;
                    (
                        hex::encode(Sha256::digest(&semantic)),
                        semantic.len() as u64,
                    )
                } else {
                    file_digest(&path, MAX_TREE_BYTES.saturating_sub(bytes))?
                };
                bytes += size;
                rows.insert(relative, ("file", mode, hash, size));
            } else if metadata.is_symlink() {
                let target = fs::read_link(&path)?;
                let resolved = path.canonicalize()?;
                ensure!(
                    resolved.starts_with(&canonical),
                    "Runtime advisory inventory contains an escaping link"
                );
                rows.insert(
                    relative,
                    (
                        "symlink",
                        mode,
                        target
                            .to_str()
                            .context("Runtime link is not UTF-8")?
                            .to_owned(),
                        0,
                    ),
                );
            } else {
                anyhow::bail!("Runtime advisory inventory contains a special file");
            }
        }
    }
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&rows)?)))
}

fn verify_pi_dependency(tree: &Path) -> Result<()> {
    let bytes = read_regular(&tree.join(".omg-npm-advisory-review.json"), MAX_REPORT)?
        .context("Pi npm advisory receipt is missing; reinstall through reviewed npm")?;
    let receipt: serde_json::Value = serde_json::from_slice(&bytes)?;
    let reviewed: jiff::Timestamp = receipt["reviewed_at"]
        .as_str()
        .context("Pi npm advisory review has no freshness timestamp")?
        .parse()?;
    fresh(reviewed, jiff::Timestamp::now())?;
    let node_root = PathBuf::from(
        receipt["node_root"]
            .as_str()
            .context("Pi npm advisory review has no managed Node identity")?,
    );
    let node_version = receipt["node_version"]
        .as_str()
        .context("Pi npm advisory review has no Node version")?;
    ensure!(
        node_root.is_absolute()
            && node_root.file_name().and_then(|name| name.to_str()) == Some(node_version),
        "Pi npm advisory Node identity mismatch"
    );
    let node_admission = admit_installed("node", &node_root, ReviewMode::CachedOnly)?;
    let node_path = PathBuf::from(
        receipt["node_path"]
            .as_str()
            .context("Pi npm advisory review has no Node executable path")?,
    );
    ensure!(
        node_root.canonicalize()? == node_root
            && node_path.is_absolute()
            && node_path.starts_with(&node_root)
            && node_path == node_root.join("bin/node").canonicalize()?,
        "Pi npm advisory Node executable no longer matches the reviewed canonical path"
    );
    let expected = receipt["runtime_content_sha256"]
        .as_str()
        .context("Pi npm advisory review has no complete Node/npm content identity")?;
    digest(expected)?;
    let identity = crate::core::security::npm::manager_identity(&node_root)?;
    ensure!(
        hex::encode(Sha256::digest(serde_json::to_vec(&identity)?)) == expected,
        "Pi Node/npm implementation changed since tool review; run explicit omg use pi <version> to re-review its dependencies"
    );
    node_admission.verify(&node_root)
}

#[cfg(test)]
struct FixtureSource;
#[cfg(test)]
impl RuntimeEvidenceSource for FixtureSource {
    fn read(&self, query: &RuntimeQuery) -> Result<Vec<u8>> {
        fixture_runtime_report(query)
    }
}

#[cfg(test)]
pub(crate) fn fixture_runtime_report(query: &RuntimeQuery) -> Result<Vec<u8>> {
    // Model already-fetched evidence; completion-time ordering has a dedicated regression.
    let now = jiff::Timestamp::from_second(jiff::Timestamp::now().as_second() - 1)?;
    Ok(serde_json::to_vec(&Envelope {
        schema_version: 1,
        identity: query.clone(),
        checked_at: now,
        coverage: Coverage::Assessed,
        findings: Vec::new(),
        gaps: Vec::new(),
        sources: vec![SourceReceipt {
            name: "controlled-runtime-fixture".to_owned(),
            url: "https://github.com/omg-cli/omg".to_owned(),
            revision: Some("fixture-v1".to_owned()),
            payload_sha256: hex::encode(Sha256::digest(b"controlled runtime fixture")),
            checked_at: now,
            complete: true,
        }],
    })?)
}

#[cfg(test)]
fn fixture_exact_version(runtime: &str, requested: &str) -> Result<String> {
    let normalized = requested.trim_start_matches('v');
    let coordinate = if runtime == "rust" {
        normalized.split('-').next().unwrap_or(normalized)
    } else {
        normalized
    };
    if runtime == "rust"
        && !coordinate
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_digit)
    {
        return Ok("1.78.0".to_owned());
    }
    let numeric = coordinate.split('+').next().unwrap_or(coordinate);
    if numeric
        .split('.')
        .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        let mut exact = numeric.to_owned();
        for _ in numeric.split('.').count()..3 {
            exact.push_str(".0");
        }
        if let Some((_, build)) = coordinate.split_once('+') {
            exact.push('+');
            exact.push_str(build);
        }
        return Ok(exact);
    }
    anyhow::bail!("Controlled runtime fixture has no exact numeric coordinate: {requested}")
}

#[cfg(test)]
pub(crate) fn fixture_install_identity(runtime: &str, version_dir: &Path) -> Result<()> {
    let version = version_dir
        .file_name()
        .and_then(|value| value.to_str())
        .context("Fixture runtime version missing")?;
    let destination = canonical_destination(version_dir)?;
    let identity = InstallIdentity {
        schema_version: 1,
        runtime: runtime.to_owned(),
        requested: version.to_owned(),
        version: fixture_exact_version(runtime, version)?,
        vendor: vendor(runtime).to_owned(),
        build: "owned-test-fixture".to_owned(),
        source_url: "https://github.com/omg-cli/omg".to_owned(),
        artifact_sha256: tree_digest(version_dir)?,
        components: BTreeMap::new(),
    };
    write_state(
        &state_path(&destination, "identity")?,
        &serde_json::to_vec(&identity)?,
    )
}

#[cfg(test)]
pub(crate) fn fixture_bind_candidate(
    runtime: &str,
    requested: &str,
    tree: &Path,
    destination: &Path,
) -> Result<()> {
    let destination = canonical_destination(destination)?;
    let version = fixture_exact_version(runtime, requested)?;
    let identity = InstallIdentity {
        schema_version: 1,
        runtime: runtime.to_owned(),
        requested: requested.to_owned(),
        version,
        vendor: vendor(runtime).to_owned(),
        build: "controlled fixture build".to_owned(),
        source_url: "https://github.com/omg-cli/omg".to_owned(),
        artifact_sha256: tree_digest(tree)?,
        components: BTreeMap::new(),
    };
    write_state(
        &state_path(&destination, "identity")?,
        &serde_json::to_vec(&identity)?,
    )
}

#[cfg(test)]
pub(crate) fn fixture_prepare(
    runtime: &str,
    requested: &str,
    tree: &Path,
    destination: &Path,
) -> Result<RuntimeAdmission> {
    fixture_bind_candidate(runtime, requested, tree, destination)?;
    RuntimeSecurity::fixture().prepare_staged(runtime, requested, tree, destination)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    #[ignore = "requires the fixed public advisory provider; selected explicitly by genuine Node coverage"]
    fn public_http_source_provides_complete_node_evidence() {
        assert!(
            std::env::var("OMG_RUN_NETWORK_TESTS").as_deref() == Ok("1"),
            "Public runtime source probe requires explicit network-test selection"
        );
        let query = RuntimeQuery {
            runtime: "node".into(),
            vendor: "nodejs".into(),
            version: "26.13.1".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
        };
        let bytes = HttpSource
            .read(&query)
            .expect("read the fixed public runtime advisory source");
        let report: Envelope = serde_json::from_slice(&bytes)
            .expect("decode the actual public runtime source response");
        validate_envelope(&report, &query, jiff::Timestamp::now())
            .expect("validate exact public Node identity, freshness and source evidence");
        assert_eq!(
            report.coverage,
            Coverage::Assessed,
            "Public Node advisory source must provide complete assessed evidence"
        );
        assert!(
            report.sources.iter().any(|source| {
                source.complete && source.url == "https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json"
            }),
            "Public runtime report must retain its complete official Node source receipt"
        );
        println!(
            "OMG_RUNTIME_PUBLIC_SOURCE_PROBE={}",
            serde_json::json!({
                "schema_version": 1,
                "identity": report.identity,
                "checked_at": report.checked_at,
                "sources": report.sources,
                "findings_count": report.findings.len(),
            })
        );
    }

    struct CountingSource {
        calls: AtomicUsize,
    }
    impl RuntimeEvidenceSource for CountingSource {
        fn read(&self, query: &RuntimeQuery) -> Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            fixture_runtime_report(query)
        }
    }

    fn node_fixture() -> Result<(tempfile::TempDir, PathBuf)> {
        let owner = tempfile::tempdir()?;
        let root = owner.path().join("versions/node/24.22.3");
        fs::create_dir_all(root.join("bin"))?;
        fs::create_dir_all(root.join("lib/node_modules/npm/lib"))?;
        fs::write(root.join("bin/node"), b"controlled node executable")?;
        fs::write(
            root.join("lib/node_modules/npm/lib/install.js"),
            b"controlled imported npm implementation",
        )
        .expect("controlled Node tree fixture setup failed");
        fixture_install_identity("node", &root)?;
        let root = root.canonicalize()?;
        Ok((owner, root))
    }

    #[test]
    fn provider_completion_timestamp_is_validated_after_transport_returns() -> Result<()> {
        struct DelayedSource(jiff::Timestamp);
        impl RuntimeEvidenceSource for DelayedSource {
            fn read(&self, query: &RuntimeQuery) -> Result<Vec<u8>> {
                std::thread::sleep(std::time::Duration::from_millis(2));
                let mut report: Envelope = serde_json::from_slice(
                    &fixture_runtime_report(query).expect("controlled delayed report"),
                )
                .expect("controlled delayed report schema");
                let completed = jiff::Timestamp::now();
                assert!(
                    completed > self.0,
                    "timing fixture must advance beyond request start"
                );
                report.checked_at = completed;
                for source in &mut report.sources {
                    source.checked_at = completed;
                }
                Ok(serde_json::to_vec(&report).expect("serialize controlled completion timestamp"))
            }
        }
        let (_owner, root) = node_fixture()?;
        let identity = read_identity(&root)?;
        let (query, _) = resolve_identity("node", "24.22.3", &root, identity.as_ref())?;
        let started = jiff::Timestamp::now();
        let report = read_report(&DelayedSource(started), &query, None);
        assert!(report.checked_at > started);
        assert_eq!(
            report.coverage,
            Coverage::Assessed,
            "evidence checked while handling a request must not be labeled future-dated against request-start time"
        );
        Ok(())
    }

    #[test]
    fn failed_same_version_publication_preserves_prior_advisory_authority() -> Result<()> {
        let (owner, root) = node_fixture()?;
        RuntimeSecurity::fixture()
            .installed("node", &root, ReviewMode::FreshAttended)?
            .verify(&root)?;
        let identity_before = read_regular(&state_path(&root, "identity")?, MAX_REPORT)?;
        let admission_before = read_regular(&state_path(&root, "admission")?, MAX_REPORT * 2)?;
        {
            let archive = owner.path().join("controlled-verified-archive");
            fs::write(&archive, b"controlled replacement archive")?;
            let _publisher = record_download(
                "node",
                "24.22.3",
                &root,
                &archive,
                "https://nodejs.org/dist/v24.22.3/controlled.tar.gz",
            )
            .expect("same-version rollback fixture setup failed");
            let staging = super::super::common::begin_staged_install(
                root.parent().context("Missing versions directory")?,
            )
            .expect("same-version rollback fixture setup failed");
            fs::create_dir(staging.path().join("bin"))?;
            fs::write(
                staging.path().join("bin/node"),
                b"different verified candidate",
            )
            .expect("same-version rollback fixture setup failed");
            RuntimeSecurity::fixture().prepare_staged("node", "24.22.3", staging.path(), &root)?;
            assert!(
                super::super::common::complete_staged_install(&staging, &root, "24.22.3").is_err(),
                "existing installation must not be clobbered"
            );
        }
        assert_eq!(
            read_regular(&state_path(&root, "identity")?, MAX_REPORT)?,
            identity_before,
            "failed publication changed the active publisher identity"
        );
        assert_eq!(
            read_regular(&state_path(&root, "admission")?, MAX_REPORT * 2)?,
            admission_before,
            "failed publication changed active advisory authority"
        );
        admit_installed("node", &root, ReviewMode::CachedOnly)?.verify(&root)?;
        Ok(())
    }

    #[test]
    fn candidate_owner_excludes_competing_admission_and_releases_after_cancel() -> Result<()> {
        let (owner, root) = node_fixture()?;
        RuntimeSecurity::fixture().installed("node", &root, ReviewMode::FreshAttended)?;
        let archive = owner.path().join("controlled-verified-archive");
        fs::write(&archive, b"controlled archive")?;
        let publisher = record_download(
            "node",
            "24.22.3",
            &root,
            &archive,
            "https://nodejs.org/dist/controlled.tar.gz",
        )
        .expect("candidate cancellation fixture setup failed");
        assert!(
            admit_installed("node", &root, ReviewMode::CachedOnly).is_err(),
            "concurrent selection must not read a provisional publisher identity"
        );
        assert!(
            record_download(
                "node",
                "24.22.3",
                &root,
                &archive,
                "https://nodejs.org/dist/controlled.tar.gz"
            )
            .is_err(),
            "two candidates must not overwrite the same publisher state"
        );
        drop(publisher);
        admit_installed("node", &root, ReviewMode::CachedOnly)?.verify(&root)?;
        Ok(())
    }

    #[test]
    fn successful_publication_commits_candidate_authority() -> Result<()> {
        let owner = tempfile::tempdir()?;
        let versions = owner.path().join("versions/node");
        let staging = super::super::common::begin_staged_install(&versions)?;
        fs::create_dir(staging.path().join("bin"))?;
        fs::write(staging.path().join("bin/node"), b"controlled candidate")?;
        let root = versions.join("24.22.3");
        let archive = owner.path().join("controlled-verified-archive");
        fs::write(&archive, b"controlled archive")?;
        let publisher = record_download(
            "node",
            "24.22.3",
            &root,
            &archive,
            "https://nodejs.org/dist/controlled.tar.gz",
        )
        .expect("candidate publication fixture setup failed");
        RuntimeSecurity::fixture().prepare_staged("node", "24.22.3", staging.path(), &root)?;
        super::super::common::complete_staged_install(&staging, &root, "24.22.3")?;
        publisher.commit();
        admit_installed("node", &root, ReviewMode::CachedOnly)?.verify(&root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn changed_publisher_identity_cannot_silently_rebind_unchanged_installed_bytes() -> Result<()> {
        use std::os::unix::process::CommandExt as _;
        const NAME: &str = "runtimes::security::tests::changed_publisher_identity_cannot_silently_rebind_unchanged_installed_bytes";
        const CHILD: &str = "OMG_RUNTIME_IDENTITY_RECHECK_CHILD";
        if std::env::var(CHILD).as_deref() != Ok(NAME) {
            let output = std::process::Command::new(std::env::current_exe()?)
                .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
                .env(CHILD, NAME)
                .process_group(0)
                .output()?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            ensure!(
                output.status.success(),
                "Identity-change security regression failed: {stdout}\n{stderr}"
            );
            return Ok(());
        }
        let (_owner, root) = node_fixture()?;
        let source = Arc::new(CountingSource {
            calls: AtomicUsize::new(0),
        });
        let security = RuntimeSecurity::with_source(source.clone());
        security.installed("node", &root, ReviewMode::FreshAttended)?;
        let initial_calls = source.calls.load(Ordering::SeqCst);
        let admission_before = read_regular(&state_path(&root, "admission")?, MAX_REPORT * 2)?;
        let mut identity = read_identity(&root)?.context("Missing publisher fixture identity")?;
        identity.artifact_sha256 =
            hex::encode(Sha256::digest(b"different provisional publisher archive"));
        write_state(
            &state_path(&root, "identity")?,
            &serde_json::to_vec(&identity)?,
        )
        .expect("publisher identity change fixture setup failed");
        let error = security
            .installed("node", &root, ReviewMode::FreshAttended)
            .err()
            .context("changed publisher identity silently rebound installed bytes without Unknown acceptance")?;
        ensure!(
            format!("{error:#}").contains("Security"),
            "Expected explicit security acceptance refusal, got {error:#}"
        );
        ensure!(
            source.calls.load(Ordering::SeqCst) > initial_calls,
            "Changed identity incorrectly reused cached authority"
        );
        assert_eq!(
            read_regular(&state_path(&root, "admission")?, MAX_REPORT * 2)?,
            admission_before,
            "unaccepted identity change replaced previous advisory authority"
        );
        Ok(())
    }

    #[test]
    fn java8_archive_release_matches_exact_adoptium_coordinate() -> Result<()> {
        let owner = tempfile::tempdir()?;
        let versions = owner.path().join("versions/java");
        fs::create_dir_all(&versions)?;
        let destination = versions.join("8");
        let archive = owner.path().join("controlled-java8-archive");
        fs::write(&archive, b"controlled Java8 publisher archive")?;
        let _publisher = record_download(
            "java",
            "8",
            &destination,
            &archive,
            "https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u452-b09/controlled.tar.gz",
        ).expect("Java8 publisher fixture setup failed");
        record_exact_release(&destination, "8.0.452+9", "jdk8u452-b09", BTreeMap::new())?;
        let staging = super::super::common::begin_staged_install(&versions)?;
        fs::write(
            staging.path().join("release"),
            "JAVA_VERSION=\"1.8.0_452\"\nIMPLEMENTOR=\"Eclipse Adoptium\"\n",
        )
        .expect("Java8 publisher fixture setup failed");
        validate_java_release(staging.path(), &destination)
            .context(
                "historical Java8 JAVA_VERSION must match its exact Adoptium semver coordinate",
            )
            .expect("Java8 publisher fixture setup failed");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn cached_pi_refuses_a_different_independently_admitted_node_implementation() -> Result<()> {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let (owner, node) = node_fixture()?;
        fs::create_dir_all(node.join("lib/node_modules/npm/bin"))?;
        fs::write(
            node.join("lib/node_modules/npm/package.json"),
            br#"{"name":"npm","version":"11.15.0"}"#,
        )
        .expect("Pi dependency binding fixture setup failed");
        fs::write(
            node.join("lib/node_modules/npm/bin/npm-cli.js"),
            b"controlled npm entry point",
        )
        .expect("Pi dependency binding fixture setup failed");
        fs::set_permissions(node.join("bin/node"), fs::Permissions::from_mode(0o755))?;
        fs::set_permissions(
            node.join("lib/node_modules/npm/bin/npm-cli.js"),
            fs::Permissions::from_mode(0o755),
        )
        .expect("Pi dependency binding fixture setup failed");
        symlink(
            "../lib/node_modules/npm/bin/npm-cli.js",
            node.join("bin/npm"),
        )
        .expect("Pi dependency binding fixture setup failed");
        fixture_install_identity("node", &node)?;
        RuntimeSecurity::fixture().installed("node", &node, ReviewMode::FreshAttended)?;
        let original_manager = crate::core::security::npm::manager_identity(&node)?;
        let pi = owner.path().join("versions/pi/0.83.0");
        fs::create_dir_all(pi.join("bin"))?;
        fs::write(pi.join("bin/pi"), b"controlled Pi launcher")?;
        fs::write(
            pi.join(".omg-npm-advisory-review.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema_version":2,"package":"@earendil-works/pi-coding-agent@0.83.0",
                "reviewed_at":jiff::Timestamp::now().to_string(),"node_root":&node,"node_version":"24.22.3",
                "node_path":node.join("bin/node"),"runtime_content_sha256":hex::encode(Sha256::digest(serde_json::to_vec(&original_manager)?))
            })).expect("serialize exact Pi dependency receipt"),
        ).expect("Pi dependency binding fixture setup failed");
        fixture_prepare("pi", "0.83.0", &pi, &pi)?;
        admit_installed("pi", &pi, ReviewMode::CachedOnly)?.verify(&pi)?;
        let versions = node.parent().context("Missing Node versions directory")?;
        let staging = super::super::common::begin_staged_install(versions)?;
        fs::create_dir_all(staging.path().join("bin"))?;
        fs::create_dir_all(staging.path().join("lib/node_modules/npm/bin"))?;
        fs::write(
            staging.path().join("lib/node_modules/npm/package.json"),
            br#"{"name":"npm","version":"11.15.0"}"#,
        )
        .expect("Pi dependency binding fixture setup failed");
        fs::create_dir_all(staging.path().join("lib/node_modules/npm/lib"))?;
        fs::write(
            staging.path().join("bin/node"),
            b"controlled node executable",
        )
        .expect("Pi dependency binding fixture setup failed");
        fs::write(
            staging.path().join("lib/node_modules/npm/bin/npm-cli.js"),
            b"controlled npm entry point",
        )
        .expect("Pi dependency binding fixture setup failed");
        fs::write(
            staging.path().join("lib/node_modules/npm/lib/install.js"),
            b"new independently reviewed npm implementation",
        )
        .expect("Pi dependency binding fixture setup failed");
        fs::set_permissions(
            staging.path().join("bin/node"),
            fs::Permissions::from_mode(0o755),
        )
        .expect("Pi dependency binding fixture setup failed");
        fs::set_permissions(
            staging.path().join("lib/node_modules/npm/bin/npm-cli.js"),
            fs::Permissions::from_mode(0o755),
        )
        .expect("Pi dependency binding fixture setup failed");
        symlink(
            "../lib/node_modules/npm/bin/npm-cli.js",
            staging.path().join("bin/npm"),
        )
        .expect("Pi dependency binding fixture setup failed");
        let archive = owner.path().join("controlled-new-node-archive");
        fs::write(
            &archive,
            b"independently authenticated replacement Node archive",
        )
        .expect("Pi dependency binding fixture setup failed");
        let publisher = record_download(
            "node",
            "24.22.3",
            &node,
            &archive,
            "https://nodejs.org/dist/controlled.tar.gz",
        )
        .expect("Pi dependency binding fixture setup failed");
        RuntimeSecurity::fixture().prepare_staged("node", "24.22.3", staging.path(), &node)?;
        super::super::common::replace_staged_install(&staging, &node, "24.22.3")?;
        publisher.commit();
        admit_installed("node", &node, ReviewMode::CachedOnly)?.verify(&node)?;
        assert!(
            admit_installed("pi", &pi, ReviewMode::CachedOnly).is_err(),
            "cached Pi reused an old npm receipt against a different independently admitted Node/npm implementation"
        );
        Ok(())
    }

    #[test]
    fn rust_foreign_host_uses_artifact_platform_and_unknown_host_requires_review() -> Result<()> {
        let owner = tempfile::tempdir()?;
        let requested = "1.93.1-aarch64-unknown-linux-gnu".to_owned();
        let mut identity = InstallIdentity {
            schema_version: 1,
            runtime: "rust".into(),
            requested,
            version: "1.93.1".into(),
            vendor: "rust-lang".into(),
            build: "controlled foreign host compiler".into(),
            source_url: "https://static.rust-lang.org/dist/channel-rust-1.93.1.toml".into(),
            artifact_sha256: hex::encode(Sha256::digest(b"controlled compiler manifest")),
            components: BTreeMap::new(),
        };
        for (host, os, arch) in [
            ("x86_64-unknown-linux-gnu", "linux", "x86_64"),
            ("aarch64-unknown-linux-gnu", "linux", "aarch64"),
            ("x86_64-apple-darwin", "macos", "x86_64"),
            ("aarch64-apple-darwin", "macos", "aarch64"),
        ] {
            identity.requested = format!("1.93.1-{host}");
            let (query, gap) =
                resolve_identity("rust", &identity.requested, owner.path(), Some(&identity))?;
            assert_eq!(
                query.arch, arch,
                "advisory architecture must follow the artifact host"
            );
            assert_eq!(query.os, os);
            assert!(
                gap.is_none(),
                "supported compiler host must retain exact identity: {gap:?}"
            );
        }
        identity.requested = "1.93.1-x86_64-acme-unrecognized".into();
        let (_, gap) =
            resolve_identity("rust", &identity.requested, owner.path(), Some(&identity))?;
        assert!(
            gap.is_some(),
            "unmapped compiler host must not inherit a clean current-host assessment"
        );
        Ok(())
    }

    #[test]
    fn accepted_local_integrity_gap_survives_provider_refresh_until_verified_replacement()
    -> Result<()> {
        let (owner, root) = node_fixture()?;
        let source = Arc::new(CountingSource {
            calls: AtomicUsize::new(0),
        });
        let security = RuntimeSecurity::with_source(source.clone());
        security.installed("node", &root, ReviewMode::FreshAttended)?;
        fs::write(
            root.join("lib/node_modules/npm/lib/install.js"),
            b"modified local implementation",
        )
        .expect("durable integrity gap fixture setup failed");
        let mut record = load_cache(&root)?.context("Missing fixture admission")?;
        record.content_sha256 = tree_digest(&root)?;
        record.local_gaps = vec!["Installed runtime content differs from the previous verified content; its declared version no longer establishes unchanged publisher identity".to_owned()];
        record.report.coverage = Coverage::Unknown;
        record.report.gaps = record.local_gaps.clone();
        let review =
            AdvisoryRiskReview::new_with_unknown(&assessments(&record.report)?, &context(&record)?)
                .expect("construct local integrity review fixture")
                .context("Expected local integrity review")?;
        let accepted = review.accept(&format!("accept {}", review.id()))?;
        ensure!(
            accepted.matches(&review),
            "Controlled fixture did not accept exact Unknown review"
        );
        record.accepted_review = Some(review.id().to_owned());
        let expired =
            jiff::Timestamp::from_second(jiff::Timestamp::now().as_second() - MAX_AGE_SECONDS - 1)?;
        record.report.checked_at = expired;
        for receipt in &mut record.report.sources {
            receipt.checked_at = expired;
        }
        save_cache(&record)?;
        let initial_calls = source.calls.load(Ordering::SeqCst);
        let refreshed = security.installed("node", &root, ReviewMode::FreshAttended)?;
        assert!(source.calls.load(Ordering::SeqCst) > initial_calls);
        assert_eq!(
            refreshed.record.report.coverage,
            Coverage::Unknown,
            "clean vendor version evidence cannot authenticate locally changed bytes after acceptance"
        );
        assert_eq!(refreshed.record.local_gaps, record.local_gaps);
        let versions = root.parent().context("Missing versions directory")?;
        let staging = super::super::common::begin_staged_install(versions)?;
        super::super::common::copy_regular_tree(&root, staging.path())?;
        fs::write(
            staging.path().join("lib/node_modules/npm/lib/install.js"),
            b"verified replacement implementation",
        )
        .expect("durable integrity gap fixture setup failed");
        let archive = owner.path().join("controlled-authenticated-repair-archive");
        fs::write(&archive, b"controlled authenticated repair")?;
        let publisher = record_download(
            "node",
            "24.22.3",
            &root,
            &archive,
            "https://nodejs.org/dist/controlled.tar.gz",
        )
        .expect("durable integrity gap fixture setup failed");
        security.prepare_staged("node", "24.22.3", staging.path(), &root)?;
        super::super::common::replace_staged_install(&staging, &root, "24.22.3")?;
        publisher.commit();
        let repaired = security.installed("node", &root, ReviewMode::CachedOnly)?;
        assert_eq!(repaired.record.report.coverage, Coverage::Assessed);
        assert!(repaired.record.local_gaps.is_empty());
        Ok(())
    }

    #[test]
    fn simultaneous_selected_tasks_share_use_but_exclude_mutation_until_both_release() -> Result<()>
    {
        let (_owner, root) = node_fixture()?;
        RuntimeSecurity::fixture().installed("node", &root, ReviewMode::FreshAttended)?;
        let first = admit_selected_path("node", &root.join("bin"), ReviewMode::CachedOnly)?;
        let second = admit_selected_path("node", &root.join("bin"), ReviewMode::CachedOnly)
            .context("parallel tasks must share current reviewed runtime use")?;
        first.verify_before_execution()?;
        second.verify_before_execution()?;
        let versions = root.parent().context("Missing versions parent")?;
        assert!(super::super::common::try_lock_runtime_file(versions, ".mutation.lock").is_err());
        drop(first);
        assert!(
            super::super::common::try_lock_runtime_file(versions, ".mutation.lock").is_err(),
            "the second task still owns runtime use"
        );
        drop(second);
        let _mutation = super::super::common::try_lock_runtime_file(versions, ".mutation.lock")?;
        Ok(())
    }

    #[test]
    fn cached_admission_never_contacts_provider_and_rejects_imported_js_changes() -> Result<()> {
        let (_owner, root) = node_fixture()?;
        let source = Arc::new(CountingSource {
            calls: AtomicUsize::new(0),
        });
        let security = RuntimeSecurity::with_source(source.clone());
        let admission = security.installed("node", &root, ReviewMode::FreshAttended)?;
        let calls = source.calls.load(Ordering::SeqCst);
        security
            .installed("node", &root, ReviewMode::CachedOnly)?
            .verify(&root)?;
        assert_eq!(source.calls.load(Ordering::SeqCst), calls);
        fs::write(
            root.join("lib/node_modules/npm/lib/install.js"),
            b"changed imported npm implementation",
        )
        .expect("mutate imported npm implementation fixture");
        assert!(admission.verify(&root).is_err());
        assert!(
            security
                .installed("node", &root, ReviewMode::CachedOnly)
                .is_err()
        );
        assert_eq!(source.calls.load(Ordering::SeqCst), calls);
        Ok(())
    }

    #[test]
    fn explicit_existing_selection_reuses_only_current_bound_admission() -> Result<()> {
        let (_owner, root) = node_fixture()?;
        let source = Arc::new(CountingSource {
            calls: AtomicUsize::new(0),
        });
        let security = RuntimeSecurity::with_source(source.clone());
        security
            .installed("node", &root, ReviewMode::FreshAttended)?
            .verify(&root)?;
        let initial_calls = source.calls.load(Ordering::SeqCst);
        security
            .installed("node", &root, ReviewMode::FreshAttended)?
            .verify(&root)?;
        assert_eq!(
            source.calls.load(Ordering::SeqCst),
            initial_calls,
            "unchanged installation with fresh exact admission must not contact upstream again"
        );
        let mut record = load_cache(&root)?.context("Expected admission cache")?;
        let expired =
            jiff::Timestamp::from_second(jiff::Timestamp::now().as_second() - MAX_AGE_SECONDS - 1)?;
        record.report.checked_at = expired;
        for receipt in &mut record.report.sources {
            receipt.checked_at = expired;
        }
        save_cache(&record)?;
        security
            .installed("node", &root, ReviewMode::FreshAttended)?
            .verify(&root)?;
        assert!(
            source.calls.load(Ordering::SeqCst) > initial_calls,
            "expired installation admission must refresh upstream evidence"
        );
        Ok(())
    }

    #[test]
    fn cached_admission_rejects_expiry_and_another_destination() -> Result<()> {
        let (owner, root) = node_fixture()?;
        let admission =
            RuntimeSecurity::fixture().installed("node", &root, ReviewMode::FreshAttended)?;
        let other = owner.path().join("versions/node/24.22.4");
        fs::create_dir(&other)?;
        assert!(admission.verify(&other).is_err());
        let mut record = load_cache(&root)?.context("Expected admission cache")?;
        let expired =
            jiff::Timestamp::from_second(jiff::Timestamp::now().as_second() - MAX_AGE_SECONDS - 1)?;
        record.report.checked_at = expired;
        for source in &mut record.report.sources {
            source.checked_at = expired;
        }
        save_cache(&record)?;
        assert!(admit_installed("node", &root, ReviewMode::CachedOnly).is_err());
        Ok(())
    }

    #[test]
    fn mismatched_or_incomplete_provider_evidence_is_unknown_and_preserves_findings() -> Result<()>
    {
        struct WrongVendor;
        impl RuntimeEvidenceSource for WrongVendor {
            fn read(&self, query: &RuntimeQuery) -> Result<Vec<u8>> {
                let mut report: Envelope = serde_json::from_slice(&fixture_runtime_report(query)?)?;
                report.identity.vendor = "another-publisher".into();
                serde_json::to_vec(&report).map_err(Into::into)
            }
        }
        let (_owner, root) = node_fixture()?;
        let identity = read_identity(&root)?;
        let (query, _) = resolve_identity("node", "24.22.3", &root, identity.as_ref())?;
        let report = read_report(&WrongVendor, &query, None);
        assert_eq!(report.coverage, Coverage::Unknown);
        assert!(!report.gaps.is_empty());
        assert!(
            AdvisoryRiskReview::new_with_unknown(&assessments(&report)?, "controlled transaction")?
                .is_some()
        );
        let mut empty: Envelope = serde_json::from_slice(&fixture_runtime_report(&query)?)?;
        empty.sources.clear();
        assert!(validate_envelope(&empty, &query, jiff::Timestamp::now()).is_err());
        Ok(())
    }

    #[test]
    fn receipt_refresh_keeps_semantic_content_but_changed_package_identity_does_not() -> Result<()>
    {
        let owner = tempfile::tempdir()?;
        let path = owner.path().join(".omg-npm-advisory-review.json");
        let mut receipt = serde_json::json!({"schema_version":2,"reviewed_at":jiff::Timestamp::now().to_string(),"lock_sha256":"exact lock","runtime_content_sha256":"exact npm implementation"});
        fs::write(&path, serde_json::to_vec(&receipt)?)?;
        let first = tree_digest(owner.path())?;
        receipt["reviewed_at"] =
            jiff::Timestamp::from_second(jiff::Timestamp::now().as_second() - 1)?
                .to_string()
                .into();
        fs::write(&path, serde_json::to_vec(&receipt)?)?;
        assert_eq!(tree_digest(owner.path())?, first);
        receipt["lock_sha256"] = "different lock".into();
        fs::write(&path, serde_json::to_vec(&receipt)?)?;
        assert_ne!(tree_digest(owner.path())?, first);
        Ok(())
    }

    #[test]
    fn unversioned_system_path_is_rejected_before_provider_or_content_inventory() {
        let error = admit_selected_path("node", Path::new("/usr/bin"), ReviewMode::FreshAttended)
            .expect_err("system binaries have no managed vendor authority");
        assert!(format!("{error:#}").contains("System or unversioned runtime"));
    }

    #[test]
    fn source_timestamps_do_not_change_semantic_unknown_review_identity() -> Result<()> {
        let (_owner, root) = node_fixture()?;
        let identity = read_identity(&root)?;
        let (query, _) = resolve_identity("node", "24.22.3", &root, identity.as_ref())?;
        let mut report: Envelope = serde_json::from_slice(&fixture_runtime_report(&query)?)?;
        report.coverage = Coverage::Partial;
        report.gaps = vec!["Exact component applicability is not established".into()];
        let first =
            AdvisoryRiskReview::new_with_unknown(&assessments(&report)?, "same bound transaction")?
                .context("Expected Unknown review")?;
        report.checked_at = jiff::Timestamp::from_second(report.checked_at.as_second() - 1)?;
        report.sources[0].checked_at = report.checked_at;
        let second =
            AdvisoryRiskReview::new_with_unknown(&assessments(&report)?, "same bound transaction")?
                .context("Expected Unknown review")?;
        assert_eq!(first.id(), second.id());
        report.gaps.push("Another source is missing".into());
        let changed =
            AdvisoryRiskReview::new_with_unknown(&assessments(&report)?, "same bound transaction")?
                .context("Expected Unknown review")?;
        assert_ne!(first.id(), changed.id());
        Ok(())
    }

    #[test]
    fn legacy_vendor_metadata_recovers_exact_queries_but_never_publisher_authority() -> Result<()> {
        let owner = tempfile::tempdir()?;
        fs::write(
            owner.path().join(".omg-toolchain.toml"),
            "release = \"1.93.1 (controlled build)\"\n",
        )
        .expect("legacy release metadata fixture setup failed");
        let (rust, gap) = resolve_identity("rust", "stable", owner.path(), None)?;
        assert_eq!(rust.version, "1.93.1");
        assert!(gap.is_some());
        fs::write(owner.path().join("release"), "JAVA_VERSION=\"25.0.1\"\n")?;
        let (java, gap) = resolve_identity("java", "25", owner.path(), None)?;
        assert_eq!(java.version, "25.0.1");
        assert_eq!(java.vendor, "temurin");
        assert!(gap.is_some());
        fs::create_dir_all(owner.path().join("include/php/main"))?;
        fs::write(
            owner.path().join("include/php/main/php.h"),
            "#define PHP_VERSION \"8.4.4\"\n",
        )
        .expect("legacy release metadata fixture setup failed");
        let (php, gap) = resolve_identity("php", "8.4", owner.path(), None)?;
        assert_eq!(php.version, "8.4.4");
        assert!(gap.is_some());
        assert!(
            RuntimeSecurity::fixture()
                .installed("php", owner.path(), ReviewMode::CachedOnly)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn unresolved_legacy_and_unmapped_products_never_gain_exact_identity() {
        let owner = tempfile::tempdir().expect("owned unresolved runtime fixtures");
        for (runtime, requested) in [
            ("rust", "stable"),
            ("java", "25"),
            ("php", "8.4"),
            ("unsupported", "1.2.3"),
        ] {
            let (query, gap) = resolve_identity(runtime, requested, owner.path(), None)
                .expect("bounded legacy identity query");
            assert!(
                gap.is_some(),
                "unverified {runtime} must retain an explicit gap"
            );
            if runtime == "unsupported" {
                assert_eq!(query.vendor, "unmapped");
            }
        }
        fs::write(
            owner.path().join(".omg-toolchain.toml"),
            "release = 'nightly'\n",
        )
        .expect("unresolved Rust release metadata");
        let (_, gap) = resolve_identity("rust", "stable", owner.path(), None)
            .expect("unresolved Rust metadata query");
        assert!(gap.unwrap().contains("Exact runtime identity"));
        fs::write(owner.path().join("release"), "JAVA_VERSION=\"25\n")
            .expect("incomplete Java release metadata");
        let (_, gap) = resolve_identity("java", "25", owner.path(), None)
            .expect("incomplete Java metadata query");
        assert!(gap.unwrap().contains("Exact runtime identity"));
        fs::write(owner.path().join(".omg-toolchain.toml"), "invalid = [")
            .expect("malformed Rust metadata fixture");
        assert!(resolve_identity("rust", "stable", owner.path(), None).is_err());
    }

    #[test]
    fn native_vendor_severity_levels_retain_bounded_advisory_meaning() {
        let (_owner, root) = node_fixture().expect("controlled severity fixture");
        let identity = read_identity(&root).expect("controlled publisher metadata");
        let (query, _) = resolve_identity("node", "24.22.3", &root, identity.as_ref())
            .expect("exact severity query");
        let mut report: Envelope =
            serde_json::from_slice(&fixture_runtime_report(&query).expect("controlled report"))
                .expect("valid report fixture");
        for (severity, expected) in [
            (Some("critical"), Some(AdvisorySeverity::Critical)),
            (Some("important"), Some(AdvisorySeverity::Important)),
            (Some("moderate"), Some(AdvisorySeverity::Moderate)),
            (Some("low"), Some(AdvisorySeverity::Low)),
            (None, None),
        ] {
            report.findings = vec![Finding {
                id: "CVE-2026-7001".into(),
                summary: "Controlled vendor disclosure".into(),
                applicability: FindingApplicability::Applicable,
                severity: severity.map(str::to_owned),
                urls: vec!["https://example.org/disclosure".into()],
            }];
            let assessed = assessments(&report).expect("evaluate controlled severity");
            assert_eq!(assessed[0].findings[0].advisory_severity, expected);
            assert_eq!(
                assessed[0].findings[0]
                    .native_advisory
                    .as_ref()
                    .unwrap()
                    .published_severity,
                severity.unwrap_or("unspecified")
            );
        }
        let mut second = report.findings[0].clone();
        second.id = "CVE-2026-6000".into();
        report.findings.push(second);
        let ordered = assessments(&report).expect("ordered native vendor findings");
        assert_eq!(ordered[0].findings.len(), 2);
        report.findings.reverse();
        let reordered = assessments(&report).expect("equivalent reordered vendor findings");
        assert_eq!(ordered[0].coverage, reordered[0].coverage);
    }

    #[test]
    fn advisory_text_and_reference_boundaries_reject_unsafe_provider_values() {
        for value in ["", "too-long", "\n", "\u{1b}"] {
            assert!(text(value, 3).is_err());
        }
        assert!(text("safe", 4).is_ok());
        assert!(source_url("https://example.org/advisory").is_ok());
        for url in [
            "not a URL",
            "http://example.org/advisory",
            "https://127.0.0.1/private",
            "https://user:secret@example.org/advisory",
        ] {
            assert!(source_url(url).is_err(), "{url}");
        }
    }

    #[test]
    fn malformed_current_policy_refuses_runtime_authority_digest() {
        const NAME: &str =
            "runtimes::security::tests::malformed_current_policy_refuses_runtime_authority_digest";
        if crate::core::testing::run_isolated_test(NAME) {
            return;
        }
        let owner = tempfile::tempdir().expect("owned runtime policy fixture");
        let config = owner.path().join("config");
        let policy_dir = config.join("omg");
        fs::create_dir_all(&policy_dir).expect("owned runtime policy directory");
        temp_env::with_vars(
            [
                (
                    "XDG_CONFIG_HOME",
                    Some(config.to_str().expect("fixture config path")),
                ),
                ("SUDO_USER", None),
                ("DOAS_USER", None),
            ],
            || {
                assert_eq!(crate::core::paths::config_dir(), policy_dir);
                fs::write(policy_dir.join("policy.toml"), b"invalid = [")
                    .expect("write malformed runtime policy fixture");
                assert!(policy_digest().is_err());
            },
        );
    }

    #[test]
    fn swift_automatic_selection_binds_usr_bin_to_its_reviewed_root() -> Result<()> {
        let owner = tempfile::tempdir()?;
        let root = owner.path().join("versions/swift/6.2.0");
        fs::create_dir_all(root.join("usr/bin"))?;
        fs::write(root.join("usr/bin/swift"), b"controlled compiler")?;
        fixture_prepare("swift", "6.2.0", &root, &root)?;
        let admission = require_selected_path("swift", &root.join("usr/bin"))?;
        admission.verify(&root)?;
        fs::write(root.join("usr/bin/swift"), b"unreviewed compiler")?;
        assert!(admission.verify_before_execution().is_err());
        assert!(admit_selected_path("swift", Path::new("bin"), ReviewMode::CachedOnly).is_err());
        Ok(())
    }

    #[test]
    fn partial_vendor_reports_preserve_unknown_severity_and_reject_invalid_receipts() -> Result<()>
    {
        struct Report(Vec<u8>);
        impl RuntimeEvidenceSource for Report {
            fn read(&self, _: &RuntimeQuery) -> Result<Vec<u8>> {
                Ok(self.0.clone())
            }
        }
        let (_owner, root) = node_fixture()?;
        let identity = read_identity(&root)?;
        let (query, _) = resolve_identity("node", "24.22.3", &root, identity.as_ref())?;
        let mut report: Envelope = serde_json::from_slice(&fixture_runtime_report(&query)?)?;
        report.coverage = Coverage::Partial;
        report.gaps = vec!["Component applicability is incomplete".into()];
        report.findings.push(Finding {
            id: "CVE-2026-7000".into(),
            summary: "Vendor disclosure".into(),
            applicability: FindingApplicability::Possible,
            severity: Some("vendor-specific".into()),
            urls: vec!["https://example.org/advisory".into()],
        });
        validate_envelope(&report, &query, jiff::Timestamp::now())?;
        let evaluated = assessments(&report)?;
        assert!(!evaluated[0].coverage.is_assessed());
        assert_eq!(evaluated[0].findings[0].advisory_severity, None);
        assert_eq!(
            evaluated[0].findings[0]
                .native_advisory
                .as_ref()
                .unwrap()
                .published_severity,
            "vendor-specific"
        );
        assert!(
            AdvisoryRiskReview::new_with_unknown(&evaluated, "controlled partial transaction")?
                .is_some()
        );
        let mut optional = report.clone();
        optional.findings[0].severity = None;
        optional.sources[0].revision = None;
        validate_envelope(&optional, &query, jiff::Timestamp::now())
            .expect("optional provider severity and revision do not invent coverage");
        assert!(
            !assessments(&optional).expect("partial optional provider evidence")[0]
                .coverage
                .is_assessed()
        );
        for invalid_revision in ["", "bad\nrevision"] {
            let mut invalid = report.clone();
            invalid.sources[0].revision = Some(invalid_revision.into());
            let failed = read_report(
                &Report(serde_json::to_vec(&invalid)?),
                &query,
                Some(&report),
            );
            assert_eq!(failed.coverage, Coverage::Unknown);
            assert_eq!(failed.findings[0].id, "CVE-2026-7000");
            assert!(!failed.gaps.is_empty());
        }
        let mut invalid = report.clone();
        invalid.findings[0].severity = Some("bad\nseverity".into());
        assert_eq!(
            read_report(
                &Report(serde_json::to_vec(&invalid)?),
                &query,
                Some(&report)
            )
            .coverage,
            Coverage::Unknown
        );
        Ok(())
    }

    #[test]
    fn changed_authority_types_and_special_runtime_files_fail_closed() -> Result<()> {
        use std::os::unix::fs::symlink;
        let (_owner, root) = node_fixture()?;
        let security = RuntimeSecurity::fixture();
        security.installed("node", &root, ReviewMode::FreshAttended)?;
        let identity = state_path(&root, "identity")?;
        fs::remove_file(&identity)?;
        symlink(root.join("bin/node"), &identity)?;
        assert!(
            format!(
                "{:#}",
                security
                    .installed("node", &root, ReviewMode::CachedOnly)
                    .unwrap_err()
            )
            .contains("Read runtime advisory metadata")
        );
        fs::remove_file(identity)?;
        fixture_install_identity("node", &root)?;
        let socket = std::os::unix::net::UnixListener::bind(root.join("unreviewed.sock"))?;
        assert!(
            format!(
                "{:#}",
                security
                    .installed("node", &root, ReviewMode::CachedOnly)
                    .unwrap_err()
            )
            .contains("special file")
        );
        drop(socket);
        Ok(())
    }

    #[test]
    fn failed_rollback_cannot_publish_a_clean_authority() -> Result<()> {
        let owner = tempfile::tempdir()?;
        let root = owner.path().join("24.22.3");
        fs::create_dir(&root)?;
        let transaction = PublisherTransaction::begin(&root)?;
        let identity = state_path(&root, "identity")?;
        fs::create_dir_all(&identity)?;
        drop(transaction);
        assert!(identity.is_dir());
        assert!(
            RuntimeSecurity::fixture()
                .installed("node", &root, ReviewMode::CachedOnly)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn modern_java_release_build_metadata_is_checked_against_publisher_identity() -> Result<()> {
        let owner = tempfile::tempdir()?;
        let root = owner.path().join("25.0.1+7");
        fs::create_dir(&root)?;
        fs::write(root.join("release"), "JAVA_VERSION=\"25.0.1+7\"\n")?;
        fixture_install_identity("java", &root)?;
        validate_java_release(&root, &root)?;
        assert_eq!(read_identity(&root)?.unwrap().version, "25.0.1+7");
        fs::write(root.join("release"), "JAVA_VERSION=\"25.0.2+7\"\n")?;
        assert!(validate_java_release(&root, &root).is_err());
        fs::write(root.join("release"), "IMPLEMENTOR=\"Eclipse Adoptium\"\n")
            .expect("Java optional release metadata fixture");
        validate_java_release(&root, &root)
            .expect("optional release field does not replace publisher identity");
        assert_eq!(read_identity(&root)?.unwrap().version, "25.0.1+7");
        let invalid = owner.path().join("unresolved");
        fs::create_dir(&invalid)?;
        assert!(fixture_install_identity("node", &invalid).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn runtime_http_status_truncation_and_size_errors_do_not_return_evidence() -> Result<()> {
        use std::io::{Read, Write};
        for (status, declared, body, accepted) in [
            (200, 2, vec![b'[', b']'], true),
            (503, 2, vec![b'[', b']'], false),
            (200, 10, b"short".to_vec(), false),
            (200, MAX_REPORT + 1, vec![b'x'; MAX_REPORT + 1], false),
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            let address = listener.local_addr()?;
            let server = std::thread::spawn(move || -> Result<()> {
                let (mut stream, _) = listener.accept()?;
                let mut request = [0; 4096];
                let _ = stream.read(&mut request)?;
                write!(
                    stream,
                    "HTTP/1.1 {status} Controlled\r\nContent-Length: {declared}\r\nConnection: close\r\n\r\n"
                )?;
                if let Err(error) = stream.write_all(&body) {
                    ensure!(
                        matches!(
                            error.kind(),
                            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                        ),
                        "unexpected fixture write: {error}"
                    );
                }
                Ok(())
            });
            let response = reqwest::Client::builder()
                .no_proxy()
                .build()?
                .get(format!("http://{address}"))
                .send()
                .await?;
            let result = runtime_response_bytes(response).await;
            assert_eq!(result.is_ok(), accepted);
            if accepted {
                assert_eq!(result?, b"[]");
            }
            server.join().expect("owned HTTP fixture thread")?;
        }
        Ok(())
    }

    #[test]
    fn failed_publisher_state_writes_preserve_previous_runtime_authority() -> Result<()> {
        const NAME: &str = "runtimes::security::tests::failed_publisher_state_writes_preserve_previous_runtime_authority";
        if crate::core::testing::run_isolated_test(NAME) {
            return Ok(());
        }
        use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};
        use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
        struct Restore {
            limit: Rlimit,
            signal: SigAction,
        }
        impl Drop for Restore {
            fn drop(&mut self) {
                setrlimit(Resource::Fsize, self.limit).expect("restore fixture file limit failed");
                // SAFETY: the saved handler belongs only to this isolated fixture process.
                #[expect(
                    unsafe_code,
                    reason = "restore the saved SIGXFSZ disposition in an isolated exact-test child"
                )]
                unsafe { sigaction(Signal::SIGXFSZ, &self.signal) }
                    .expect("restore fixture signal failed");
            }
        }
        let (owner, root) = node_fixture()?;
        let security = RuntimeSecurity::fixture();
        security.installed("node", &root, ReviewMode::FreshAttended)?;
        let identity = state_path(&root, "identity")?;
        let previous = fs::read(&identity)?;
        let archive = owner.path().join("controlled-archive");
        fs::write(&archive, b"authenticated fixture archive")?;
        let limit = getrlimit(Resource::Fsize);
        let ignore = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());
        // SAFETY: only this disposable child changes SIGXFSZ; Restore reinstates it before profile flush.
        #[expect(
            unsafe_code,
            reason = "isolated exact-test child needs EFBIG instead of process termination for real write failures"
        )]
        let signal = unsafe { sigaction(Signal::SIGXFSZ, &ignore) }?;
        let restore = Restore { limit, signal };
        setrlimit(
            Resource::Fsize,
            Rlimit {
                current: Some(0),
                maximum: restore.limit.maximum,
            },
        )
        .context("set fixture resource limit")?;
        let download = record_download(
            "node",
            "24.22.3",
            &root,
            &archive,
            "https://nodejs.org/dist/controlled.tar.gz",
        );
        let manifest = record_manifest(
            "node",
            "24.22.3",
            &root,
            "https://nodejs.org/dist/manifest",
            b"controlled authenticated manifest",
        );
        // Restore both states before assertions, error reporting, or LLVM profile persistence.
        drop(restore);
        assert!(download.is_err());
        assert!(manifest.is_err());
        assert_eq!(
            fs::read(identity)?,
            previous,
            "failed atomic recording must not replace prior publisher bytes"
        );
        security
            .installed("node", &root, ReviewMode::CachedOnly)?
            .verify(&root)?;
        Ok(())
    }
}
