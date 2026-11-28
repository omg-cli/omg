//! DNF/Fedora package manager backend
//!
//! Reads installed packages directly from the RPM `SQLite` database for
//! fast queries without CLI overhead.
//!
//! ## Architecture
//! 1. Read installed packages from RPM's configured SQLite database
//!    (`rpm -qa` subprocess fallback for BDB/NDB systems)
//! 2. Parse RPM header blobs for metadata extraction
//!
//! ## Known limitation
//!
//! Repository queries and transactions use DNF's configured repository policy.
//! DNF selects upgrades and unneeded packages. A standalone Rust repository
//! index is not implemented yet.

use std::future::Future;
use std::pin::Pin;

use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use crate::cli::modern_ui::OutputMode;
use crate::cli::style::sanitize_terminal_diagnostic;
use crate::core::{Package, PackageSource, is_root};
use crate::package_managers::PackageManager;
use crate::package_managers::types::{PackageStatus, UpdateInfo, parse_version_or_zero};

use rusqlite::{Connection, OpenFlags};
use zerocopy::{FromBytes, Immutable, KnownLayout, big_endian::U32};

mod catalog;

const DNF_HISTORY_DATABASE: &str = "transaction_history.sqlite";

#[cfg(all(test, unix))]
pub(crate) use tests::search_parity_data;

/// RPM tag constants for parsing header entries
#[cfg(feature = "fedora")]
mod rpm_tags {
    pub const NAME: u32 = 1000;
    pub const VERSION: u32 = 1001;
    pub const RELEASE: u32 = 1002;
    pub const EPOCH: u32 = 1003;
    pub const SUMMARY: u32 = 1004;
    pub const ARCH: u32 = 1022;
}

// RPM header data types (librpm numbering): 1=CHAR 2=INT8 3=INT16 4=INT32
// 5=INT64 6=STRING 7=BIN 8=STRING_ARRAY 9=I18NSTRING. The parser matches on
// these numerals directly; see parse_rpm_header for the invariant table.

/// DNF Package Manager implementation
pub struct DnfPackageManager {
    rpm_database: RpmDatabaseSource,
    /// Complete RPM inventory bound to database/WAL identity and SQLite commits.
    /// Install reasons belong to DNF's separate state and are queried on demand.
    installed_cache: Arc<RwLock<Option<InstalledSnapshot>>>,
}

#[derive(Clone)]
enum RpmDatabaseSource {
    System,
    #[cfg(test)]
    Fixture(PathBuf),
}

impl RpmDatabaseSource {
    fn sqlite_path(&self) -> Result<Option<PathBuf>> {
        match self {
            Self::System => {
                // Resolve each observation against native configuration. A
                // live daemon can outlast an administrator's macro change.
                let output = DnfPackageManager::rpm_query(
                    ["--eval", "%{_db_backend}\t%{_dbpath}"],
                    std::time::Duration::from_secs(2),
                )
                .context("Could not read RPM database configuration")?;
                Self::parse(&output)
            }
            #[cfg(test)]
            Self::Fixture(path) => Ok(Some(path.clone())),
        }
    }

    fn parse(output: &[u8]) -> Result<Option<PathBuf>> {
        let (backend, directory) = std::str::from_utf8(output)
            .context("RPM database configuration is not UTF-8")?
            .trim_end_matches('\n')
            .split_once('\t')
            .context("RPM database configuration must specify backend and path")?;
        if backend != "sqlite" {
            return Ok(None);
        }
        let path = Path::new(directory);
        anyhow::ensure!(
            path.is_absolute() && !directory.chars().any(char::is_control),
            "RPM database path must be an absolute path without control characters"
        );
        Ok(Some(path.join("rpmdb.sqlite")))
    }
}

#[derive(Debug)]
struct InstalledSnapshot {
    observation: RpmDatabaseObservation,
    packages: Arc<Vec<InstalledPackage>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl FileIdentity {
    fn read(path: &Path) -> std::io::Result<Option<Self>> {
        let metadata = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if !metadata.is_file() {
            return Err(std::io::Error::other(
                "RPM cache input is not a regular file",
            ));
        }
        Ok(Some(Self::from_metadata(&metadata)))
    }

    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;

        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RpmDatabaseIdentity {
    database: FileIdentity,
    wal: Option<FileIdentity>,
}

impl RpmDatabaseIdentity {
    fn read(path: &Path) -> Option<Self> {
        let database = FileIdentity::read(path).ok()??;
        let mut wal_path = path.as_os_str().to_os_string();
        wal_path.push("-wal");
        // An absent WAL is valid; an unreadable one must not validate a hit.
        let wal = FileIdentity::read(Path::new(&wal_path)).ok()?;
        Some(Self { database, wal })
    }

    fn same_inventory_files(self, observed: Self) -> bool {
        if self.database != observed.database {
            return false;
        }
        match (self.wal, observed.wal) {
            (None, None) => true,
            (Some(current), Some(previous)) => {
                // Native SQLite readers reapply WAL permissions, changing
                // ctime without changing inventory. Keep inode, size and
                // mtime checks; the observer also checks SQLite generation
                // and package contents when that generation changes.
                (
                    current.device,
                    current.inode,
                    current.size,
                    current.modified,
                ) == (
                    previous.device,
                    previous.inode,
                    previous.size,
                    previous.modified,
                )
            }
            _ => false,
        }
    }
}

/// SQLite's data_version is connection-local. Keep the same read-only observer
/// alive for the snapshot instead of comparing values from fresh connections.
/// No read transaction is retained between observation calls.
#[derive(Debug, Clone)]
struct RpmDatabaseObservation {
    identity: RpmDatabaseIdentity,
    connection: Arc<Mutex<Connection>>,
    data_version: i64,
    inventory_fingerprint: [u8; 32],
}

struct RpmInstalledCatalogObservation {
    source: RpmDatabaseSource,
    path: PathBuf,
    database: RpmDatabaseObservation,
}

impl super::InstalledCatalogObservation for RpmInstalledCatalogObservation {
    fn is_current(&self) -> Result<bool> {
        Ok(self.source.sqlite_path()?.as_ref() == Some(&self.path)
            && self.database.is_current(&self.path))
    }
}

impl RpmDatabaseObservation {
    fn fingerprint_inventory(connection: &Connection) -> Result<[u8; 32]> {
        use sha2::{Digest as _, Sha256};

        // One SELECT holds a coherent read snapshot while its cursor exists.
        // Length/domain framing binds row identities, every header byte, and
        // the row count without retaining the entire installed RPM database.
        let mut digest = Sha256::new();
        digest.update(b"OMG RPM Packages inventory v1\0");
        let mut statement = connection.prepare("SELECT hnum, blob FROM Packages ORDER BY hnum")?;
        let mut rows = statement.query([])?;
        let mut count = 0_u64;
        while let Some(row) = rows.next()? {
            let hnum: i64 = row.get(0)?;
            let blob = row.get_ref(1)?.as_blob()?;
            digest.update([1]);
            digest.update(hnum.to_be_bytes());
            digest.update(u64::try_from(blob.len())?.to_be_bytes());
            digest.update(blob);
            count = count
                .checked_add(1)
                .context("RPM inventory row count overflow")?;
        }
        digest.update([0]);
        digest.update(count.to_be_bytes());
        Ok(digest.finalize().into())
    }

    fn read(path: &Path) -> Option<Self> {
        let before_open = RpmDatabaseIdentity::read(path)?;
        let connection =
            Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
        let transaction = connection.unchecked_transaction().ok()?;
        let data_version = transaction
            .query_row("PRAGMA data_version", [], |row| row.get(0))
            .ok()?;
        let inventory_fingerprint = Self::fingerprint_inventory(&transaction).ok()?;
        transaction.commit().ok()?;
        // The first read of a WAL database can create its empty WAL file,
        // even through a read-only connection. Capture that initialized WAL
        // identity while still rejecting replacement of the main database.
        // The baseline read is finished before returning; concurrent commits
        // are covered by generation/content checks at publication.
        let identity = RpmDatabaseIdentity::read(path)?;
        if identity.database != before_open.database {
            return None;
        }
        let initialized_empty_wal =
            before_open.wal.is_none() && identity.wal.is_some_and(|wal| wal.size == 0);
        if !identity.same_inventory_files(before_open) && !initialized_empty_wal {
            return None;
        }
        Some(Self {
            identity,
            connection: Arc::new(Mutex::new(connection)),
            data_version,
            inventory_fingerprint,
        })
    }

    fn is_current(&self, path: &Path) -> bool {
        if !RpmDatabaseIdentity::read(path)
            .is_some_and(|current| current.same_inventory_files(self.identity))
        {
            return false;
        }
        let Ok(connection) = self.connection.lock() else {
            return false;
        };
        let generation_matches = connection
            .query_row("PRAGMA data_version", [], |row| row.get::<_, i64>(0))
            .map(|version| version == self.data_version);
        let contents_match = match generation_matches {
            Ok(true) => true,
            // Read-only, unwritable SHM with an empty WAL causes SQLite to
            // invalidate its page cache (and data_version) on every read.
            // Accept only identical, cryptographically fingerprinted package
            // rows; real inventory changes and query/schema errors fail closed.
            Ok(false) => Self::fingerprint_inventory(&connection)
                .is_ok_and(|fingerprint| fingerprint == self.inventory_fingerprint),
            Err(_) => false,
        };
        contents_match
            && RpmDatabaseIdentity::read(path)
                .is_some_and(|current| current.same_inventory_files(self.identity))
    }
}

/// Installed package information from RPM database
#[derive(Debug, Clone)]
struct InstalledPackage {
    name: String,
    version: String,
    release: String,
    architecture: String,
    summary: String,
}

impl InstalledPackage {
    fn identity(&self) -> String {
        if self.architecture.is_empty() {
            self.name.clone()
        } else {
            format!("{}.{}", self.name, self.architecture)
        }
    }

    fn nevra(&self) -> String {
        format!(
            "{}-{}-{}.{}",
            self.name, self.version, self.release, self.architecture
        )
    }

    fn full_nevra(&self) -> String {
        if self.version.contains(':') {
            self.nevra()
        } else {
            format!(
                "{}-0:{}-{}.{}",
                self.name, self.version, self.release, self.architecture
            )
        }
    }

    fn matches_selector(&self, selector: &str) -> bool {
        self.name == selector
            || self.identity() == selector
            || self.nevra() == selector
            || (!self.version.contains(':') && self.full_nevra() == selector)
    }

    fn as_package(&self) -> Package {
        Package {
            name: self.identity(),
            version: parse_version_or_zero(&self.evr()),
            description: self.summary.clone(),
            source: PackageSource::Official,
            installed: true,
        }
    }

    fn evr(&self) -> String {
        format!("{}-{}", self.version, self.release)
    }
}

#[derive(Debug)]
struct AvailablePackage<'a> {
    name: &'a str,
    version: &'a str,
    summary: &'a str,
}

#[derive(Debug)]
struct AvailableInfo<'a> {
    package: AvailablePackage<'a>,
    repository: &'a str,
}

impl AvailablePackage<'_> {
    fn into_package(self) -> Package {
        Package {
            name: self.name.to_owned(),
            version: parse_version_or_zero(self.version),
            description: self.summary.to_owned(),
            source: PackageSource::Official,
            installed: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RepositoryQuery<'a> {
    Available(Option<&'a str>),
    Installed,
    Unneeded,
    InstalledSizes(InstalledSizeQuery<'a>),
    InstalledReasons(InstalledReasonQuery<'a>),
    InstalledDetails(&'a str),
}

const REQUIRE_ALL_REPOSITORIES: &str = "--setopt=*.skip_if_unavailable=false";
const CACHED_UPGRADE_METADATA: &str = "--setopt=cacheonly=metadata";

const UPGRADE_QUERY_ARGS: [&str; 6] = [
    "--quiet",
    "--color=never",
    "--cacheonly",
    REQUIRE_ALL_REPOSITORIES,
    "list",
    "--upgrades",
];

const CACHED_UPGRADE_PREVIEW_ARGS: [&str; 3] = ["--cacheonly", REQUIRE_ALL_REPOSITORIES, "upgrade"];

const REPOSITORY_REFRESH_ARGS: [&str; 4] =
    ["--refresh", REQUIRE_ALL_REPOSITORIES, "makecache", "-y"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstalledSizeQuery<'a> {
    All,
    Package(&'a str),
    RequirementProviders(&'a str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstalledReasonQuery<'a> {
    Package(&'a str),
    RequiredBy(&'a str),
}

#[derive(Debug)]
pub(crate) struct InstalledPackageReason {
    pub(crate) identity: String,
    pub(crate) reason: String,
}

#[derive(Debug)]
pub(crate) struct InstalledPackageDetails {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) identity: String,
    pub(crate) reason: String,
}

#[derive(Debug, serde::Deserialize)]
struct NativeTransaction {
    id: u64,
    comment: String,
    status: String,
    /// `dnf5 history info --json` records the command line that started the
    /// transaction as `description` (dnf5 history(8), JSON Output).
    #[serde(default)]
    description: String,
    packages: Vec<NativeTransactionPackage>,
}

#[derive(Debug, serde::Deserialize)]
struct NativeTransactionPackage {
    nevra: String,
    action: String,
}

#[derive(Debug)]
pub(crate) struct DnfTransactionPreview {
    pub(crate) plan: String,
    pub(crate) diagnostics: String,
    pub(crate) has_changes: bool,
}

pub(crate) struct PreparedDnfRemoval {
    directory: tempfile::TempDir,
    packages: Vec<super::types::RemovalPackage>,
}

impl PreparedDnfRemoval {
    pub(crate) fn packages(&self) -> &[super::types::RemovalPackage] {
        &self.packages
    }
}

enum DnfAdmission<'a> {
    Install,
    Upgrade {
        cached: bool,
    },
    Remove {
        packages: &'a [String],
        comment: Option<&'a str>,
        yes: bool,
        output: OutputMode,
    },
}

#[derive(serde::Deserialize)]
struct StoredRemovalTransaction {
    version: String,
    #[serde(default)]
    rpms: Vec<NativeTransactionPackage>,
    #[serde(default)]
    groups: Vec<serde_json::Value>,
    #[serde(default)]
    environments: Vec<serde_json::Value>,
}

#[derive(Default)]
struct NativeVersionChanges {
    removed: BTreeSet<String>,
    added: BTreeSet<String>,
}

#[derive(Debug)]
enum NativeOutcome {
    NoTransaction,
    Committed(Vec<crate::core::history::PackageChange>),
    Failed,
    /// libdnf5 left a journal row in a non-terminal state. This is not proof
    /// of committed package changes; retain its identity for diagnosis only.
    Interrupted {
        id: u64,
        comment: String,
        status: String,
        actions: usize,
        command: String,
    },
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum DnfCleanup {
    Orphans { yes: bool },
    PackageCache,
}

#[derive(Debug)]
struct VersionedPackage {
    name: String,
    architecture: String,
    version: String,
    repository: String,
}

struct PlannedDnfAdvisories;

enum AdvisoryLookup<'a> {
    ArchitectureChanges,
    Proposed(&'a [super::types::SecurityPackage]),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InstalledAdvisoryMatch {
    Exact,
    ArchitectureChange,
}

struct CancelStoredQuery(Option<tokio::sync::oneshot::Sender<()>>);

impl Drop for CancelStoredQuery {
    fn drop(&mut self) {
        if let Some(cancel) = self.0.take() {
            let _ = cancel.send(());
        }
    }
}

impl crate::core::security::vulnerability::VulnerabilitySource for PlannedDnfAdvisories {
    fn assess_packages<'a>(
        &'a self,
        packages: &'a [super::types::SecurityPackage],
        _evidence_use: crate::core::security::vulnerability::AssessmentUse,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = std::result::Result<
                        Vec<crate::core::security::vulnerability::PackageAssessment>,
                        crate::core::security::vulnerability::VulnerabilityError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            use crate::core::security::scan::{AdvisoryProvenance, FindingApplicability};
            use crate::core::security::vulnerability::{
                PackageAssessment, PackageCoverage, UnknownCoverage, VulnerabilityError,
            };
            let assess = async {
                let (mut rows, mut supplemental) =
                    DnfPackageManager::native_advisories(AdvisoryLookup::Proposed(packages))
                        .await?;
                let native_ids: BTreeSet<_> = rows
                    .iter()
                    .map(|(row, _)| (row.name.as_str(), row.nevra.as_str()))
                    .collect();
                supplemental.retain(|(row, _)| {
                    !native_ids.contains(&(row.name.as_str(), row.nevra.as_str()))
                });
                rows.extend(supplemental);
                let native = super::dnf_advisory::audit_result(rows)?;
                let mut assessments = Vec::with_capacity(packages.len());
                let mut comparisons = Vec::new();
                let mut candidates = Vec::new();
                for package in packages {
                    let mut assessment = PackageAssessment::unknown(
                        package.clone(),
                        UnknownCoverage::SourceNotCovered,
                    );
                    assessment.coverage = PackageCoverage::Unknown {
                        reason: UnknownCoverage::SourceNotCovered,
                        provenance: Some(AdvisoryProvenance::NativeDnf),
                    };
                    for (_, findings) in native
                        .vulnerabilities
                        .iter()
                        .filter(|(name, _)| name == &package.name)
                    {
                        for finding in findings {
                            let native = finding
                                .native_advisory
                                .as_ref()
                                .context("Missing native DNF advisory identity")?;
                            let (name, architecture) =
                                super::dnf_advisory::package_identity(&native.advisory_nevra)?;
                            if package.architecture.as_deref() != Some(architecture) {
                                continue;
                            }
                            let fixed = &native.advisory_nevra[name.len() + 1
                                ..native.advisory_nevra.len() - architecture.len() - 1];
                            anyhow::ensure!(
                                comparisons.len() < 10_000,
                                "Native advisory comparison exceeds its bound"
                            );
                            comparisons.push((package.version.clone(), fixed.to_owned()));
                            candidates.push((assessments.len(), finding.clone()));
                        }
                    }
                    assessments.push(assessment);
                }
                let compared = DnfPackageManager::compare_native_evrs(&comparisons).await?;
                for ((index, mut finding), comparison) in candidates.into_iter().zip(compared) {
                    if comparison < 0 {
                        finding.applicability = FindingApplicability::Possible;
                        assessments[index].findings.push(finding);
                    }
                }
                for assessment in &mut assessments {
                    assessment.findings.sort_by(|left, right| {
                        left.id.cmp(&right.id).then_with(|| {
                            left.native_advisory
                                .as_ref()
                                .map(|native| native.advisory_nevra.as_str())
                                .cmp(
                                    &right
                                        .native_advisory
                                        .as_ref()
                                        .map(|native| native.advisory_nevra.as_str()),
                                )
                        })
                    });
                    assessment.findings.dedup();
                }
                Ok::<_, anyhow::Error>(assessments)
            }
            .await;
            assess.map_err(|error| VulnerabilityError::Unavailable {
                reason: format!("Native DNF planned-package advisories unavailable: {error:#}"),
            })
        })
    }
}

impl Default for DnfPackageManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DnfPackageManager {
    async fn compare_native_evrs(pairs: &[(String, String)]) -> Result<Vec<i32>> {
        const MAX_INPUT_BYTES: usize = 64 * 1024;
        let mut results = Vec::with_capacity(pairs.len());
        let mut pairs = pairs.iter().peekable();
        while pairs.peek().is_some() {
            let mut input = String::new();
            let mut pair_count = 0;
            while let Some((left, right)) = pairs.peek() {
                let pair_bytes = left.len() + right.len() + 2;
                anyhow::ensure!(
                    pair_bytes <= MAX_INPUT_BYTES,
                    "Native RPM comparison input exceeds limit"
                );
                if input.len() + pair_bytes > MAX_INPUT_BYTES {
                    break;
                }
                anyhow::ensure!(
                    [left, right]
                        .iter()
                        .all(|value| !value.is_empty() && !value.chars().any(char::is_control)),
                    "Invalid native comparison input"
                );
                input.push_str(left);
                input.push('\n');
                input.push_str(right);
                input.push('\n');
                let _ = pairs.next();
                pair_count += 1;
            }
            let mut command = Self::rpm_query_command()?;
            command.env("OMG_EVR_PAIRS", input).args(["--eval", r#"%{lua:local left=nil; for value in string.gmatch(os.getenv("OMG_EVR_PAIRS"), "[^\n]+") do if left then print(string.format("%d\n",rpm.vercmp(left,value))); left=nil else left=value end end; if left then error("incomplete comparison") end}"#]);
            let output = Self::controlled_query_output(
                "RPM",
                command,
                std::time::Duration::from_mins(1),
                None,
            )
            .await?;
            let compared = std::str::from_utf8(&output)?
                .split_whitespace()
                .map(|value| match value {
                    "-1" => Ok(-1),
                    "0" => Ok(0),
                    "1" => Ok(1),
                    _ => Err(anyhow::anyhow!(
                        "Invalid native RPM version comparison result"
                    )),
                })
                .collect::<Result<Vec<_>>>()?;
            anyhow::ensure!(
                compared.len() == pair_count,
                "Incomplete native RPM version comparisons"
            );
            results.extend(compared);
        }
        Ok(results)
    }

    fn parse_removal_plan(bytes: &[u8]) -> Result<Vec<super::types::RemovalPackage>> {
        let transaction: StoredRemovalTransaction = serde_json::from_slice(bytes)
            .context("DNF5 did not produce a valid stored removal transaction")?;
        anyhow::ensure!(
            transaction.version == "1.0",
            "Unsupported DNF5 stored transaction version"
        );
        anyhow::ensure!(
            transaction.groups.is_empty() && transaction.environments.is_empty(),
            "DNF removal would also modify groups or environments"
        );
        let mut seen = BTreeSet::new();
        let mut plan = transaction
            .rpms
            .into_iter()
            .map(|package| {
                anyhow::ensure!(
                    package.action == "Remove",
                    "DNF removal would also perform '{}'; inspect the transaction with dnf",
                    package.action
                );
                anyhow::ensure!(
                    seen.insert(package.nevra.clone()),
                    "Duplicate DNF removal identity"
                );
                let (name, architecture) = super::dnf_advisory::package_identity(&package.nevra)?;
                let version =
                    &package.nevra[name.len() + 1..package.nevra.len() - architecture.len() - 1];
                Ok(super::types::RemovalPackage {
                    name: format!("{name}.{architecture}"),
                    version: version.to_owned(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        plan.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.version.cmp(&right.version))
        });
        Ok(plan)
    }

    #[cfg(unix)]
    fn trusted_removal_preview_parent(parent: &Path) -> Result<PathBuf> {
        use std::os::unix::fs::MetadataExt;

        let canonical = parent
            .canonicalize()
            .context("Could not resolve DNF removal preview parent")?;
        for ancestor in canonical.ancestors() {
            let metadata = ancestor
                .metadata()
                .context("Could not inspect DNF removal preview ancestor")?;
            anyhow::ensure!(
                metadata.is_dir() && metadata.uid() == 0,
                "DNF removal preview ancestors must be root-owned directories"
            );
            let writable = metadata.mode() & 0o022 != 0;
            let protected_sticky_parent = ancestor == canonical && metadata.mode() & 0o1000 != 0;
            anyhow::ensure!(
                !writable || protected_sticky_parent,
                "DNF removal preview ancestor is writable without a safe sticky parent"
            );
        }
        Ok(canonical)
    }

    fn removal_preview_directory() -> Result<tempfile::TempDir> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // The elevated process must not follow caller TMPDIR into a
            // replaceable directory. Immutable ancestors plus a root-owned
            // sticky parent protect the private 0700 child's pathname.
            let parent = Self::trusted_removal_preview_parent(Path::new("/var/tmp"))?;
            tempfile::Builder::new()
                .prefix("omg-dnf-removal-")
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir_in(parent)
                .context("Could not create private DNF removal preview directory")
        }
        #[cfg(not(unix))]
        anyhow::bail!("DNF removal preview requires a Unix filesystem ownership boundary")
    }

    async fn simulate_removal(packages: &[String]) -> Result<Vec<super::types::RemovalPackage>> {
        Ok(Self::prepare_removal(packages)
            .await?
            .map_or_else(Vec::new, |plan| plan.packages))
    }

    pub(crate) async fn prepare_removal(packages: &[String]) -> Result<Option<PreparedDnfRemoval>> {
        Self::validate_package_selectors(packages)?;
        let directory = Self::removal_preview_directory()?;
        let mut command: tokio::process::Command = Self::native_package_command("dnf")?.into();
        command
            .env("LC_ALL", "C")
            .args([
                "--cacheonly".to_owned(),
                format!("--setopt=logdir={}", directory.path().display()),
                "remove".to_owned(),
                "--assumeyes".to_owned(),
                format!("--store={}", directory.path().display()),
            ])
            .args(packages);
        let Some((directory, bytes)) =
            Self::owned_stored_transaction(command, directory, std::time::Duration::from_mins(1))
                .await
                .context("Could not simulate removal with DNF5 --store")?
        else {
            return Ok(None);
        };
        let packages = Self::parse_removal_plan(&bytes)?;
        Ok(Some(PreparedDnfRemoval {
            directory,
            packages,
        }))
    }

    pub(crate) async fn replay_removal(
        &self,
        plan: PreparedDnfRemoval,
        history: &crate::core::history::HistoryManager,
    ) -> Result<()> {
        Self::record_native_mutation(
            crate::core::history::TransactionType::Remove,
            Some(history),
            |comment| self.replay_removal_plan(plan, comment),
        )
        .await
        .map(|_| ())
    }

    async fn replay_removal_plan(
        &self,
        plan: PreparedDnfRemoval,
        comment: Option<String>,
    ) -> Result<()> {
        // Replay normally loads available repositories. Removal uses only
        // installed packages, and DNF rejects a disable glob with no matches.
        let mut command: tokio::process::Command = Self::native_package_command("dnf")?.into();
        command.args(["repo", "list", "--all", "--json"]);
        let output = Self::query_output(command).await?;
        let repositories: Vec<serde::de::IgnoredAny> =
            serde_json::from_slice(&output).context("Invalid DNF repository list")?;
        let options: &'static [&'static str] = if repositories.is_empty() {
            &[]
        } else {
            &["--disable-repo=*"]
        };
        self.replay_stored_transaction(plan.directory, options, comment)
            .await
    }

    pub(crate) async fn remove_with_elevation(packages: &[String], yes: bool) -> Result<()> {
        let mode = if yes { "-y" } else { "--confirm" };
        let output = match crate::cli::modern_ui::output_mode() {
            OutputMode::Quiet => Some("--quiet"),
            OutputMode::Verbose => Some("--verbose"),
            OutputMode::Plain | OutputMode::Interactive => None,
        };
        let operation = |comment: Option<String>| async move {
            let mut args: Vec<_> = comment.into_iter().collect();
            args.extend(["remove".to_owned(), mode.to_owned()]);
            args.extend(output.map(str::to_owned));
            args.extend_from_slice(packages);
            crate::core::privilege::run_privileged_dnf(&args).await
        };
        let history = crate::core::history::HistoryManager::new()?;
        Self::record_native_mutation(
            crate::core::history::TransactionType::Remove,
            Some(&history),
            operation,
        )
        .await
        .map(|_| ())
    }
    fn cached_update_args() -> Vec<String> {
        [CACHED_UPGRADE_METADATA, "upgrade", "-y"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    /// Return the recorded package-change count when this caller owns history.
    pub(crate) async fn update_with_history(
        &self,
        cached: bool,
        history: Option<&crate::core::history::HistoryManager>,
    ) -> Result<Option<usize>> {
        let args = if cached {
            Self::cached_update_args()
        } else {
            vec!["upgrade".to_owned(), "-y".to_owned()]
        };
        self.recorded_mutation(crate::core::history::TransactionType::Update, args, history)
            .await
    }

    #[must_use]
    pub fn new() -> Self {
        Self {
            rpm_database: RpmDatabaseSource::System,
            installed_cache: Arc::new(RwLock::new(None)),
        }
    }

    /// Recover from a poisoned lock. A panic while holding the cache only
    /// leaves derived inventory unspecified; later package operations still
    /// work via `PoisonError::into_inner`.
    fn cache_read(&self) -> std::sync::RwLockReadGuard<'_, Option<InstalledSnapshot>> {
        self.installed_cache
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn cache_write(&self) -> std::sync::RwLockWriteGuard<'_, Option<InstalledSnapshot>> {
        self.installed_cache
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn invalidate_installed_cache(&self) {
        *self.cache_write() = None;
    }

    fn cached_installed_packages(&self, path: &Path) -> Option<Arc<Vec<InstalledPackage>>> {
        self.cache_read()
            .as_ref()
            .filter(|snapshot| snapshot.observation.is_current(path))
            .map(|snapshot| Arc::clone(&snapshot.packages))
    }

    fn publish_installed_packages(
        &self,
        path: Option<&Path>,
        packages: Arc<Vec<InstalledPackage>>,
        observed_identity: Option<RpmDatabaseObservation>,
    ) {
        // Never label an old read with a newer generation, or cache a CLI
        // fallback whose actual database was not observed. Empty inventories
        // are valid snapshots too.
        let snapshot = path
            .zip(observed_identity)
            .filter(|(path, observation)| observation.is_current(path))
            .map(|(_, observation)| InstalledSnapshot {
                observation,
                packages,
            });
        *self.cache_write() = snapshot;
    }

    /// DNF reports install reasons by package name, while RPM can retain
    /// multiple installed versions of the same name (notably kernels).
    /// Explicit-package APIs are name inventories, so collapse those parallel
    /// versions before returning a listing or count.
    fn explicit_package_names(
        packages: &[InstalledPackage],
        user_installed: Result<HashSet<String>>,
    ) -> Result<Vec<String>> {
        let user_installed = user_installed.context("Could not load DNF install reasons")?;
        Ok(packages
            .iter()
            .map(|package| package.name.as_str())
            .filter(|name| user_installed.contains(*name))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(str::to_owned)
            .collect())
    }

    /// Count installed RPM entries without querying DNF repositories.
    ///
    /// # Errors
    /// Returns an error when the installed RPM inventory cannot be read.
    pub fn installed_count(&self) -> Result<usize> {
        let path = self.rpm_database.sqlite_path()?;
        let (packages, _) = Self::read_rpm_database(path.as_deref(), false)?;
        Ok(packages.len())
    }

    /// Load installed packages from RPM `SQLite` database
    ///
    /// Reads directly from the configured SQLite database and parses RPM header blobs
    /// to extract package metadata. Caches results in memory for subsequent calls.
    async fn load_installed_packages(&self) -> Result<Arc<Vec<InstalledPackage>>> {
        let manager = self.cache_handle();
        tokio::task::spawn_blocking(move || manager.load_installed_packages_blocking()).await?
    }

    fn load_installed_packages_blocking(&self) -> Result<Arc<Vec<InstalledPackage>>> {
        let path = self.rpm_database.sqlite_path()?;
        self.load_installed_packages_at(path.as_deref())
    }

    fn load_installed_packages_at(
        &self,
        path: Option<&Path>,
    ) -> Result<Arc<Vec<InstalledPackage>>> {
        if let Some(cached) = path.and_then(|path| self.cached_installed_packages(path)) {
            return Ok(cached);
        }
        let (packages, identity) = Self::read_rpm_database(path, true)?;
        let packages = Arc::new(packages);
        self.publish_installed_packages(path, Arc::clone(&packages), identity);
        Ok(packages)
    }

    pub(crate) fn is_installed_fast(&self, package: &str) -> Result<bool> {
        Ok(!self.matching_installed_packages(package)?.is_empty())
    }

    fn matching_installed_packages(&self, selector: &str) -> Result<Vec<InstalledPackage>> {
        let path = self.rpm_database.sqlite_path()?;
        if let Some(path) = &path {
            match Self::read_rpm_name_index(path, selector) {
                Ok(packages) if !packages.is_empty() => return Ok(packages),
                Ok(_) => {}
                Err(error) => tracing::debug!("RPM name lookup unavailable: {error:#}"),
            }
        }
        Ok(self
            .load_installed_packages_at(path.as_deref())?
            .iter()
            .filter(|package| package.matches_selector(selector))
            .cloned()
            .collect())
    }

    fn read_rpm_name_index(path: &Path, selector: &str) -> Result<Vec<InstalledPackage>> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(std::time::Duration::ZERO)?;
        // A literal package name can also look like a qualified selector.
        // Read every plausible name in a single snapshot before matching.
        let name_arch = selector.rsplit_once('.').map(|(name, _)| name);
        let nevra_name = super::dnf_advisory::package_identity(selector)
            .ok()
            .map(|(name, _)| name);
        let mut statement = connection.prepare(
            "SELECT Name.key, Name.hnum, Packages.blob
             FROM Name LEFT JOIN Packages USING (hnum)
             WHERE Name.key IN (?1, ?2, ?3)",
        )?;
        let mut rows = statement.query(rusqlite::params![selector, name_arch, nevra_name])?;
        let mut headers = HashSet::new();
        let mut packages = Vec::new();
        while let Some(row) = rows.next()? {
            let name = row.get_ref(0)?.as_str()?;
            let header: i64 = row.get(1)?;
            let package = Self::parse_package_from_blob(row.get_ref(2)?.as_blob()?)?;
            anyhow::ensure!(
                package.name == name && headers.insert(header),
                "Inconsistent RPM name index"
            );
            if package.matches_selector(selector) {
                packages.push(package);
            }
        }
        Ok(packages)
    }

    async fn current_explicit_package_names(packages: &[InstalledPackage]) -> Result<Vec<String>> {
        Self::explicit_package_names(packages, Self::read_user_installed_names().await)
    }

    /// Read RPM database, trying `SQLite` first then falling back to subprocess
    fn read_rpm_database(
        db_path: Option<&Path>,
        observe_snapshot: bool,
    ) -> Result<(Vec<InstalledPackage>, Option<RpmDatabaseObservation>)> {
        if let Some(db_path) = db_path.filter(|path| path.exists()) {
            let identity = observe_snapshot
                .then(|| RpmDatabaseObservation::read(db_path))
                .flatten();
            // Opening another SQLite connection can chmod the WAL and change
            // its ctime even without a commit. Read through the observer so
            // the inventory and its commit generation share one connection.
            let result = if let Some(observation) = &identity {
                let connection = observation
                    .connection
                    .lock()
                    .map_err(|_| anyhow::anyhow!("RPM observer connection lock poisoned"))?;
                Self::read_rpm_sqlite_connection(&connection)
            } else {
                Self::read_rpm_sqlite(db_path)
            };
            match result {
                Ok(packages) => return Ok((packages, identity)),
                Err(e) => {
                    tracing::warn!("SQLite access failed: {e:#}, falling back to rpm -qa");
                }
            }
        }

        // Fallback to subprocess for BDB/NDB systems or when SQLite fails
        Ok((Self::read_rpm_via_query()?, None))
    }

    /// Parse installed packages using `rpm -qa` subprocess
    ///
    /// Fallback for systems without `SQLite` RPM database (`BerkeleyDB`, `NDB`).
    fn read_rpm_via_query() -> Result<Vec<InstalledPackage>> {
        let output = Self::rpm_query(
            [
                "-qa",
                "--queryformat",
                "%{NAME}\t%{VERSION}\t%{RELEASE}\t%{EPOCHNUM}\t%{ARCH}\t%{SUMMARY}\n",
            ],
            std::time::Duration::from_mins(1),
        )?;

        let stdout = String::from_utf8_lossy(&output);
        let mut packages = Vec::with_capacity(2048);

        for line in stdout.lines() {
            if line.is_empty() {
                continue;
            }
            packages.push(Self::parse_rpm_qa_line(line)?);
        }

        Ok(packages)
    }

    fn native_package_command(program: &str) -> Result<std::process::Command> {
        let mut command = crate::core::privilege::system_command(program)?;
        // Libdnf loads RPM macros too. Use the same system database as RPM
        // queries, while retaining DNF's writable user cache and log paths.
        command.env("HOME", "/").env_remove("XDG_STATE_HOME");
        if !is_root() {
            let home = home::home_dir()
                .filter(|path| path.is_absolute())
                .context("DNF requires an absolute home directory for user cache and state")?;
            let state = std::env::var_os("XDG_STATE_HOME")
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .unwrap_or_else(|| home.join(".local/state"));
            command
                .env("XDG_CACHE_HOME", home.join(".cache"))
                .env("XDG_STATE_HOME", state);
        }
        Ok(command)
    }

    fn rpm_query_command() -> Result<tokio::process::Command> {
        let mut command =
            tokio::process::Command::from(crate::core::privilege::system_command("rpm")?);
        // Exclude caller macros and preserve the system macro configuration.
        command.env("HOME", "/").env("LC_ALL", "C");
        Ok(command)
    }

    const RPM_SBOM_QUERY_FORMAT: &str = concat!(
        "%{NAME:shescape} %|ARCH?{%{ARCH:shescape}}:{''}| %{EPOCHNUM} ",
        "%{VERSION:shescape} %{RELEASE:shescape} ",
        "%|VENDOR?{%{VENDOR:shescape}}:{''}| %|LICENSE?{%{LICENSE:shescape}}:{''}|\\n",
    );

    fn parse_rpm_sbom_inventory(output: &[u8]) -> Result<Vec<super::types::SbomPackage>> {
        use super::types::{SbomPackage, SecurityOrigin, SecurityPackage};

        let output = std::str::from_utf8(output).context("RPM SBOM inventory is not UTF-8")?;
        let fields = shell_words::split(output).context("Invalid quoted RPM SBOM inventory")?;
        let (records, remainder) = fields.as_chunks::<7>();
        anyhow::ensure!(remainder.is_empty(), "Truncated RPM SBOM record");
        let mut inventory = Vec::with_capacity(records.len());
        for [name, architecture, epoch, version, release, vendor, license] in records {
            // Imported RPM keys are trust records rather than installed software.
            if name == "gpg-pubkey" && architecture.is_empty() {
                continue;
            }
            Self::validate_versioned_fields(&[name, architecture, epoch, version, release])?;
            anyhow::ensure!(
                epoch.bytes().all(|byte| byte.is_ascii_digit()),
                "Invalid RPM epoch"
            );
            inventory.push(SbomPackage {
                package: SecurityPackage {
                    origin: SecurityOrigin::DistributionPackage,
                    name: name.clone(),
                    version: format!("{epoch}:{version}-{release}"),
                    advisory_source: None,
                    architecture: Some(architecture.clone()),
                    description: String::new(),
                    licenses: (!license.trim().is_empty())
                        .then(|| license.clone())
                        .into_iter()
                        .collect(),
                },
                rpm_vendor: (!vendor.trim().is_empty()).then(|| vendor.clone()),
            });
        }
        Ok(inventory)
    }

    fn rpm_query<const N: usize>(
        arguments: [&str; N],
        deadline: std::time::Duration,
    ) -> Result<Vec<u8>> {
        let mut command = Self::rpm_query_command()?;
        command.args(arguments);
        crate::cli::tea::run_blocking_future(Self::controlled_query_output(
            "RPM", command, deadline, None,
        ))?
    }

    fn parse_user_installed_names(output: &[u8]) -> Result<HashSet<String>> {
        let output =
            std::str::from_utf8(output).context("dnf user-installed output was not UTF-8")?;
        Ok(output
            .lines()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(ToOwned::to_owned)
            .collect())
    }

    /// `--qf` value for `dnf repoquery --userinstalled`. Same dnf5 contract
    /// as [`Self::repository_query_format`]: the row terminator must be the
    /// two-character escape `\n`; a real newline is silently dropped and all
    /// names concatenate into one row.
    const USER_INSTALLED_QUERY_FORMAT: &str = "%{name}\\n";

    pub(crate) async fn read_user_installed_names() -> Result<HashSet<String>> {
        // --userinstalled reads the system repo only. An unmatched repo glob
        // would reject a valid local inventory on a host with no configured repos.
        let mut command: tokio::process::Command = Self::native_package_command("dnf")?.into();
        command.args([
            "--cacheonly",
            "--setopt=disable_excludes=*",
            "repoquery",
            "--userinstalled",
            "--qf",
            Self::USER_INSTALLED_QUERY_FORMAT,
        ]);
        Self::parse_user_installed_names(&Self::query_output(command).await?)
    }

    fn parse_rpm_qa_line(line: &str) -> Result<InstalledPackage> {
        // The free-form summary can contain tabs, so keep the final field intact.
        let fields: Vec<&str> = line.splitn(6, '\t').collect();
        if fields.len() != 6 {
            anyhow::bail!(
                "malformed rpm -qa output: expected 6 fields, got {}",
                fields.len()
            );
        }

        let epoch: u32 = fields[3].parse().context("Malformed RPM epoch")?;
        let missing = |value: &str| value.is_empty() || value == "(none)";
        anyhow::ensure!(
            ![fields[0], fields[1], fields[2]].into_iter().any(missing),
            "Incomplete package identity in rpm -qa output"
        );
        let architecture = if missing(fields[4]) {
            anyhow::ensure!(fields[0] == "gpg-pubkey", "RPM architecture is missing");
            String::new()
        } else {
            fields[4].to_owned()
        };
        Ok(InstalledPackage {
            name: fields[0].to_string(),
            version: if epoch == 0 {
                fields[1].to_owned()
            } else {
                format!("{epoch}:{}", fields[1])
            },
            release: fields[2].to_string(),
            architecture,
            summary: fields[5].to_owned(),
        })
    }

    /// Database blobs omit the magic/reserved prefix used in RPM archive headers.
    /// All entries are validated, but only the package fields are retained.
    fn parse_rpm_header(blob: &[u8]) -> Result<HashMap<u32, &[u8]>> {
        const MAX_HEADER_ENTRIES: u32 = 100_000;

        #[derive(FromBytes, KnownLayout, Immutable)]
        #[repr(C)]
        struct HeaderIntro {
            num_entries: U32,
            data_size: U32,
        }

        #[derive(FromBytes, KnownLayout, Immutable)]
        #[repr(C)]
        struct IndexEntry {
            tag: U32,
            tag_type: U32,
            offset: [u8; 4],
            count: U32,
        }

        if blob.len() < size_of::<HeaderIntro>() {
            anyhow::bail!("RPM header too short");
        }
        let (intro_bytes, rest) = blob.split_at(size_of::<HeaderIntro>());
        let intro = HeaderIntro::ref_from_bytes(intro_bytes).expect("intro length checked above");
        let num_entries = intro.num_entries.get();
        anyhow::ensure!(num_entries > 0, "RPM database header must contain entries");
        anyhow::ensure!(
            num_entries <= MAX_HEADER_ENTRIES,
            "RPM header declares {num_entries} entries (limit {MAX_HEADER_ENTRIES})"
        );
        let data_size = intro.data_size.get() as usize;

        let entries_len = num_entries as usize * size_of::<IndexEntry>();
        // The data area starts immediately after the index (librpm layout);
        // deriving it from the tail would let appended bytes shift the
        // payload window and satisfy string terminators outside the
        // declared region.
        let data_start = entries_len;
        anyhow::ensure!(
            data_start
                .checked_add(data_size)
                .is_some_and(|end| end <= rest.len()),
            "RPM header truncated"
        );

        let payload = &rest[data_start..data_start + data_size];
        let mut tags = HashMap::with_capacity(6);
        for chunk in rest[..data_start].chunks_exact(size_of::<IndexEntry>()) {
            let entry =
                IndexEntry::ref_from_bytes(chunk).expect("chunk length checked by chunks_exact");
            let tag = entry.tag.get();
            let tag_type = entry.tag_type.get();
            let count = entry.count.get() as usize;

            if matches!(
                tag,
                rpm_tags::NAME | rpm_tags::VERSION | rpm_tags::RELEASE | rpm_tags::ARCH
            ) {
                anyhow::ensure!(
                    tag_type == 6 && count == 1,
                    "RPM identity tag {tag} must be a single string"
                );
            }
            if tag == rpm_tags::EPOCH {
                anyhow::ensure!(
                    tag_type == 4 && count == 1,
                    "RPM EPOCH identity tag must be a single INT32"
                );
            }

            anyhow::ensure!(
                (1..=9).contains(&tag_type),
                "RPM tag {tag} has unsupported type {tag_type}"
            );
            anyhow::ensure!(
                tag_type != 6 || count == 1,
                "RPM string tag {tag} must have count 1, got {count}"
            );

            let rel = i32::from_be_bytes(entry.offset);
            anyhow::ensure!(rel >= 0, "RPM tag {tag} has negative data offset {rel}");
            let base = rel as usize;
            anyhow::ensure!(
                base < payload.len(),
                "RPM tag {tag} data offset outside payload"
            );

            // Region length this tag occupies inside the payload.
            let region: usize = match tag_type {
                1 | 2 => count.saturating_mul(1),
                3 => count.saturating_mul(2),
                4 => count.saturating_mul(4),
                5 => count.saturating_mul(8),
                7 => count,
                6 | 8 | 9 => {
                    let last = count.checked_sub(1).context("RPM string array is empty")?;
                    memchr::memchr_iter(0, &payload[base..])
                        .nth(last)
                        .ok_or_else(|| anyhow::anyhow!("RPM tag {tag} string missing terminator"))?
                }
                _ => unreachable!("type range validated above"),
            };

            let abs_end = base
                .checked_add(region)
                .ok_or_else(|| anyhow::anyhow!("RPM tag {tag} data region overflows"))?;
            anyhow::ensure!(
                abs_end <= payload.len(),
                "RPM tag {tag} data region exceeds payload"
            );

            if matches!(
                tag,
                rpm_tags::NAME
                    | rpm_tags::VERSION
                    | rpm_tags::RELEASE
                    | rpm_tags::EPOCH
                    | rpm_tags::SUMMARY
                    | rpm_tags::ARCH
            ) {
                tags.insert(tag, &payload[base..abs_end]);
            }
        }

        Ok(tags)
    }

    /// Parse an RPM blob into an `InstalledPackage`
    ///
    /// Extracts name, version, release, and summary from the RPM header blob.
    /// Installation reason is loaded from DNF's system-state query.
    fn parse_package_from_blob(blob: &[u8]) -> Result<InstalledPackage> {
        let tags = Self::parse_rpm_header(blob)?;

        // Helper to extract string from tag data
        let get_string = |tag: u32| -> String {
            tags.get(&tag)
                .and_then(|data| data.split(|&byte| byte == 0).next())
                .map(|data| String::from_utf8_lossy(data).to_string())
                .unwrap_or_default()
        };

        let name = get_string(rpm_tags::NAME);
        if name.is_empty() {
            anyhow::bail!("RPM header missing NAME tag");
        }

        let epoch = tags
            .get(&rpm_tags::EPOCH)
            .map(|bytes| {
                let bytes: [u8; 4] = (*bytes).try_into().context("Malformed RPM EPOCH tag")?;
                Ok::<_, anyhow::Error>(u32::from_be_bytes(bytes))
            })
            .transpose()?
            .unwrap_or(0);
        let version = get_string(rpm_tags::VERSION);
        let release = get_string(rpm_tags::RELEASE);
        let architecture = get_string(rpm_tags::ARCH);
        anyhow::ensure!(!version.is_empty(), "RPM header missing VERSION tag");
        anyhow::ensure!(!release.is_empty(), "RPM header missing RELEASE tag");
        // Legacy RPM databases store imported keys as architecture-less records.
        anyhow::ensure!(
            !architecture.is_empty() || name == "gpg-pubkey",
            "RPM header missing ARCH tag"
        );
        Ok(InstalledPackage {
            name,
            version: if epoch == 0 {
                version
            } else {
                format!("{epoch}:{version}")
            },
            release,
            architecture,
            summary: get_string(rpm_tags::SUMMARY),
        })
    }

    /// Read RPM database directly from `SQLite` (Fedora 33+, RHEL 9+)
    ///
    /// Opens the configured database in read-only mode and parses
    /// RPM header blobs from the `Packages` table without a subprocess.
    fn read_rpm_sqlite(db_path: &Path) -> Result<Vec<InstalledPackage>> {
        let conn = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .context("Failed to open RPM SQLite database")?;

        Self::read_rpm_sqlite_connection(&conn)
    }

    fn read_rpm_sqlite_connection(conn: &Connection) -> Result<Vec<InstalledPackage>> {
        conn.busy_timeout(std::time::Duration::from_secs(5))?;

        let mut stmt = conn.prepare("SELECT blob FROM Packages ORDER BY hnum")?;
        let mut packages = Vec::with_capacity(2048);

        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let blob = row.get_ref(0)?.as_blob()?;
            let pkg = Self::parse_package_from_blob(blob).with_context(|| {
                format!(
                    "Malformed RPM header in Packages table (row {}, {} packages decoded before the failure)",
                    packages.len() + 1,
                    packages.len()
                )
            })?;
            packages.push(pkg);
        }

        tracing::debug!("Loaded {} packages from SQLite database", packages.len());
        Ok(packages)
    }

    fn available_rows(output: &[u8]) -> Result<impl Iterator<Item = Result<AvailablePackage<'_>>>> {
        let text = std::str::from_utf8(output).context("DNF repository output is not UTF-8")?;
        Ok(text.lines().filter(|line| !line.is_empty()).map(|line| {
            let mut fields = line.splitn(3, '\t');
            let name = fields.next().context("DNF repository row has no name")?;
            let version = fields.next().context("DNF repository row has no version")?;
            let summary = fields.next().context("DNF repository row has no summary")?;
            anyhow::ensure!(
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"+._-".contains(&byte)),
                "DNF repository row has invalid package name"
            );
            anyhow::ensure!(
                !version.is_empty() && !version.chars().any(char::is_whitespace),
                "DNF repository row has invalid version"
            );
            Ok(AvailablePackage {
                name,
                version,
                summary,
            })
        }))
    }

    fn parse_available_packages(output: &[u8]) -> Result<Vec<Package>> {
        Self::available_rows(output)?
            .map(|row| row.map(AvailablePackage::into_package))
            .collect()
    }

    async fn available_packages() -> Result<Vec<Package>> {
        let bytes = Self::repository_output(RepositoryQuery::Available(None)).await?;
        Self::parse_available_packages(&bytes)
    }

    pub(crate) fn select_installed_build<T>(
        selector: &str,
        mut candidates: Vec<T>,
        identity: impl Fn(&T) -> String,
    ) -> Result<Option<T>> {
        if candidates.len() <= 1 {
            return Ok(candidates.pop());
        }
        let mut identities: Vec<_> = candidates.iter().map(identity).collect();
        identities.sort_unstable();
        identities.dedup();
        anyhow::ensure!(
            identities.len() > 1,
            "RPM reports multiple installed records for '{}'",
            identities[0]
        );
        anyhow::bail!(
            "Package '{selector}' matches multiple installed builds. Choose an exact installed identity.\n  {}",
            identities.join("\n  ")
        )
    }

    fn search_repository_paths() -> Result<(catalog::RepositoryPaths, catalog::Stamps)> {
        let mut paths = catalog::RepositoryPaths::default();
        let before = paths.configuration_stamps()?;
        let mut command: tokio::process::Command = Self::native_package_command("dnf")?.into();
        command.env("LC_ALL", "C").arg("--dump-main-config");
        let config = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(Self::query_output_with_deadline(
                command,
                std::time::Duration::from_secs(3),
            ))?;
        paths.add_effective_paths(std::str::from_utf8(&config)?)?;
        anyhow::ensure!(
            before == catalog::RepositoryPaths::default().configuration_stamps()?,
            "DNF configuration changed while resolving repository inputs"
        );
        let configuration = paths.configuration_stamps()?;
        Ok((paths, configuration))
    }

    async fn search_repository_metadata(
        cache_only: bool,
    ) -> Result<Vec<catalog::RepositoryMetadata>> {
        let mut command: tokio::process::Command = Self::native_package_command("dnf")?.into();
        command.env("LC_ALL", "C");
        if cache_only {
            command.arg("--cacheonly");
        }
        command.args(["repo", "info", "--enabled", "--json"]);
        let output = Self::query_output(command).await?;
        serde_json::from_slice(&output).context("Invalid DNF repository metadata")
    }

    async fn search_cached_repositories(
        repositories: &[&catalog::RepositoryMetadata],
    ) -> Result<Vec<Package>> {
        if repositories.is_empty() {
            return Ok(Vec::new());
        }
        let mut ids = Vec::with_capacity(repositories.len());
        for repo in repositories {
            anyhow::ensure!(
                !repo.id.is_empty()
                    && repo
                        .id
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte)),
                "Invalid native DNF repository ID"
            );
            ids.push(repo.id.as_str());
        }
        // Normal DNF can skip an expired, unavailable repo whose stale
        // metadata is still readable with --cacheonly. Admit only repositories
        // that the normal query actually loaded.
        let mut command: tokio::process::Command = Self::native_package_command("dnf")?.into();
        command.args(["--cacheonly", &format!("--repo={}", ids.join(","))]);
        command.args(Self::repository_query_args(RepositoryQuery::Available(
            None,
        ))?);
        let output = Self::query_output(command).await?;
        Self::parse_available_packages(&output)
    }

    fn available_info_rows(output: &[u8]) -> Result<Vec<AvailableInfo<'_>>> {
        Self::available_rows(output)?
            .map(|row| {
                let row = row?;
                let (repository, summary) = row
                    .summary
                    .split_once('\t')
                    .context("DNF package info row lacks repository or summary")?;
                anyhow::ensure!(
                    !repository.is_empty() && !repository.chars().any(char::is_control),
                    "Invalid DNF package info repository"
                );
                Ok(AvailableInfo {
                    package: AvailablePackage { summary, ..row },
                    repository,
                })
            })
            .collect()
    }

    fn prefer_available_info<'a>(
        selector: &str,
        mut candidates: Vec<AvailableInfo<'a>>,
    ) -> Result<Vec<AvailableInfo<'a>>> {
        let preferred = |candidate: &AvailableInfo<'_>| {
            candidate
                .package
                .name
                .rsplit_once('.')
                .is_some_and(|(_, arch)| arch == std::env::consts::ARCH || arch == "noarch")
        };
        // DNF resolves an architecture-qualified selector before returning rows.
        // Bare names can include several architectures for the same package.
        if candidates.iter().any(preferred) {
            candidates.retain(preferred);
        }
        if let Some(first) = candidates.first() {
            anyhow::ensure!(
                candidates.iter().all(|candidate| {
                    candidate.package.name == first.package.name
                        && candidate.package.version == first.package.version
                }),
                "Package '{selector}' has multiple available builds; specify the full NEVRA"
            );
        }
        Ok(candidates)
    }

    fn available_info_from_native_selection(
        candidates: Vec<AvailableInfo<'_>>,
        output: &[u8],
    ) -> Result<Package> {
        let native = Self::parse_package_listing(output, "Available packages")?;
        let [selected] = native.as_slice() else {
            anyhow::bail!("DNF did not select one available build for the exact NEVRA");
        };
        let identity = format!("{}.{}", selected.name, selected.architecture);
        let mut matches = candidates.into_iter().filter(|candidate| {
            candidate.package.name == identity
                && candidate.package.version == selected.version
                && candidate.repository == selected.repository
        });
        let chosen = matches.next().context(
            "DNF selected a build or repository absent from the package info candidates",
        )?;
        anyhow::ensure!(
            matches.next().is_none(),
            "The selected DNF repository returned conflicting metadata for the same build"
        );
        Ok(chosen.package.into_package())
    }

    async fn available_info(selector: &str) -> Result<Option<Package>> {
        let output = Self::repository_output(RepositoryQuery::Available(Some(selector))).await?;
        let mut candidates =
            Self::prefer_available_info(selector, Self::available_info_rows(&output)?)?;
        if candidates
            .windows(2)
            .all(|pair| pair[0].package.summary == pair[1].package.summary)
        {
            return Ok(candidates
                .pop()
                .map(|candidate| candidate.package.into_package()));
        }

        let first = &candidates[0].package;
        let (name, arch) = first
            .name
            .rsplit_once('.')
            .context("DNF package info lacks architecture")?;
        let epoch = if first.version.contains(':') {
            ""
        } else {
            "0:"
        };
        let exact = format!("{name}-{epoch}{}.{arch}", first.version);
        Self::validate_query_selector(&exact)?;
        // DNF's package listing applies repository priority to the exact build.
        // Use it only when repositories disagree on the summary for the same build.
        let mut command: tokio::process::Command = Self::native_package_command("dnf")?.into();
        command
            .env("LC_ALL", "C")
            .args(["--color=never", "list", "--available", &exact]);
        let selected = Self::query_output(command).await?;
        Self::available_info_from_native_selection(candidates, &selected).map(Some)
    }

    // Put the native newest build first for each installed identity. Keep
    // older descriptions searchable in both direct and daemon paths.
    async fn order_installed_search_builds(
        installed: &[InstalledPackage],
    ) -> Result<Vec<&InstalledPackage>> {
        let mut first = HashMap::with_capacity(installed.len());
        let mut contenders = BTreeMap::<usize, Vec<usize>>::new();
        for (index, package) in installed.iter().enumerate() {
            let identity = (package.name.as_str(), package.architecture.as_str());
            let first = *first.entry(identity).or_insert(index);
            if first != index {
                contenders
                    .entry(first)
                    .or_insert_with(|| vec![first])
                    .push(index);
            }
        }

        // RPM compares only parallel builds. Batch a round across all
        // identities, carrying an unpaired build into the next round.
        while contenders.values().any(|builds| builds.len() > 1) {
            let pairs: Vec<_> = contenders
                .values()
                .flat_map(|builds| builds.chunks_exact(2))
                .map(|pair| (installed[pair[0]].evr(), installed[pair[1]].evr()))
                .collect();
            let mut order = Self::compare_native_evrs(&pairs).await?.into_iter();
            for builds in contenders.values_mut() {
                let pairs = builds.chunks_exact(2);
                let mut winners = pairs
                    .clone()
                    .map(|pair| {
                        if order.next().expect("validated RPM comparison count") < 0 {
                            pair[1]
                        } else {
                            pair[0]
                        }
                    })
                    .collect::<Vec<_>>();
                winners.extend_from_slice(pairs.remainder());
                *builds = winners;
            }
        }

        let mut ordered: Vec<_> = installed.iter().collect();
        for (first, builds) in contenders {
            ordered.swap(first, builds[0]);
        }
        Ok(ordered)
    }

    fn search_candidates<'a>(
        installed: impl IntoIterator<Item = &'a InstalledPackage>,
        available: Vec<Package>,
    ) -> Vec<Package> {
        let mut candidates: Vec<_> = installed
            .into_iter()
            .map(InstalledPackage::as_package)
            .collect();
        candidates.extend(available);
        candidates
    }

    fn search_results<'a>(
        installed: impl IntoIterator<Item = &'a InstalledPackage>,
        output: &[u8],
        query_lower: &str,
    ) -> Result<Vec<Package>> {
        let available = Self::available_rows(output)?.collect::<Result<Vec<_>>>()?;
        let installed: Vec<_> = installed
            .into_iter()
            .map(InstalledPackage::as_package)
            .collect();
        let matches_query = |name: &str, summary: &str| {
            name.to_lowercase().contains(query_lower)
                || summary.to_lowercase().contains(query_lower)
        };
        // Any matching summary admits the identity. The installed row, or the
        // first repository row for an uninstalled identity, supplies its fields.
        let mut matching_identities: HashSet<_> = installed
            .iter()
            .filter(|pkg| matches_query(&pkg.name, &pkg.description))
            .map(|pkg| pkg.name.as_str())
            .chain(
                available
                    .iter()
                    .filter(|row| matches_query(row.name, row.summary))
                    .map(|row| row.name),
            )
            .collect();
        let mut results: Vec<_> = installed
            .iter()
            .filter(|pkg| matching_identities.remove(pkg.name.as_str()))
            .cloned()
            .collect();
        results.extend(
            available
                .into_iter()
                .filter(|row| matching_identities.remove(row.name))
                .map(AvailablePackage::into_package),
        );
        results.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        Ok(results)
    }

    pub(crate) async fn installed_package_sizes(
        query: InstalledSizeQuery<'_>,
    ) -> Result<Vec<(String, i64)>> {
        let output = Self::repository_output(RepositoryQuery::InstalledSizes(query)).await?;
        Self::parse_installed_sizes(&output)
    }

    fn parse_installed_sizes(output: &[u8]) -> Result<Vec<(String, i64)>> {
        let text = std::str::from_utf8(output).context("DNF installed sizes are not UTF-8")?;
        text.lines()
            .map(|line| {
                let (identity, bytes) = line
                    .split_once('\t')
                    .context("DNF installed size row must contain identity and bytes")?;
                anyhow::ensure!(
                    !identity.is_empty()
                        && !identity
                            .chars()
                            .any(|ch| ch.is_whitespace() || ch.is_control()),
                    "DNF installed size row has an invalid package identity"
                );
                let bytes: i64 = bytes.parse().context("Invalid DNF installed size")?;
                anyhow::ensure!(bytes >= 0, "DNF installed size must not be negative");
                Ok((identity.to_owned(), bytes))
            })
            .collect()
    }

    pub(crate) async fn installed_package_reasons(
        query: InstalledReasonQuery<'_>,
    ) -> Result<Vec<InstalledPackageReason>> {
        let output = Self::repository_output(RepositoryQuery::InstalledReasons(query)).await?;
        Self::parse_installed_reasons(&output)
    }

    fn parse_installed_reasons(output: &[u8]) -> Result<Vec<InstalledPackageReason>> {
        let text = std::str::from_utf8(output).context("DNF installed reasons are not UTF-8")?;
        text.lines()
            .map(|line| {
                let (identity, reason) = line
                    .split_once('\t')
                    .context("DNF reason row must contain identity and reason")?;
                anyhow::ensure!(
                    !identity.is_empty()
                        && !identity
                            .chars()
                            .any(|ch| ch.is_whitespace() || ch.is_control()),
                    "DNF reason row has an invalid package identity"
                );
                anyhow::ensure!(
                    !reason.is_empty()
                        && reason.trim() == reason
                        && !reason.chars().any(char::is_control),
                    "DNF reason row has an invalid installation reason"
                );
                Ok(InstalledPackageReason {
                    identity: identity.to_owned(),
                    reason: reason.to_owned(),
                })
            })
            .collect()
    }

    pub(crate) async fn installed_package_details(
        package: &str,
    ) -> Result<Vec<InstalledPackageDetails>> {
        let output = Self::repository_output(RepositoryQuery::InstalledDetails(package)).await?;
        Self::parse_installed_details(&output)
    }

    fn parse_installed_details(output: &[u8]) -> Result<Vec<InstalledPackageDetails>> {
        let text = std::str::from_utf8(output).context("DNF installed details are not UTF-8")?;
        text.lines()
            .map(|line| {
                let fields: Vec<_> = line.split('\t').take(5).collect();
                anyhow::ensure!(
                    fields.len() == 4,
                    "DNF installed details require four fields"
                );
                anyhow::ensure!(
                    fields[..3].iter().all(|field| !field.is_empty()
                        && !field
                            .chars()
                            .any(|ch| ch.is_whitespace() || ch.is_control())),
                    "Invalid DNF installed identity fields"
                );
                anyhow::ensure!(
                    !fields[3].is_empty()
                        && fields[3].trim() == fields[3]
                        && !fields[3].chars().any(char::is_control),
                    "Invalid DNF installed reason"
                );
                Ok(InstalledPackageDetails {
                    name: fields[0].to_owned(),
                    version: fields[1].to_owned(),
                    identity: fields[2].to_owned(),
                    reason: fields[3].to_owned(),
                })
            })
            .collect()
    }

    /// Query-format strings for `dnf repoquery --queryformat`.
    ///
    /// dnf5 contract (verified against dnf5 on Fedora 44): field separators
    /// must be real TAB characters (passed through verbatim), but the row
    /// terminator must be the two-character escape `\n`. A real newline
    /// inside the format is silently dropped, concatenating every row into
    /// one mega-row that fails parsing; a literal `\t` escape is passed
    /// through as text instead of a tab, which also fails parsing.
    fn repository_query_format(query: &RepositoryQuery<'_>) -> &'static str {
        match query {
            RepositoryQuery::Available(None) => "%{name}.%{arch}\t%{evr}\t%{summary}\\n",
            RepositoryQuery::Available(Some(_)) => {
                "%{name}.%{arch}\t%{evr}\t%{repoid}\t%{summary}\\n"
            }
            RepositoryQuery::InstalledSizes(_) => "%{full_nevra}\t%{installsize}\\n",
            RepositoryQuery::InstalledReasons(_) => "%{full_nevra}\t%{reason}\\n",
            RepositoryQuery::InstalledDetails(_) => "%{name}\t%{evr}\t%{full_nevra}\t%{reason}\\n",
            RepositoryQuery::Installed | RepositoryQuery::Unneeded => {
                "%{name}\t%{arch}\t%{evr}\t%{repoid}\\n"
            }
        }
    }

    async fn repository_output(query: RepositoryQuery<'_>) -> Result<Vec<u8>> {
        Self::query_output(Self::repository_command(query)?).await
    }

    fn repository_command(query: RepositoryQuery<'_>) -> Result<tokio::process::Command> {
        let args = Self::repository_query_args(query)?;
        let mut command: tokio::process::Command = Self::native_package_command("dnf")?.into();
        command.args(args);
        Ok(command)
    }

    fn repository_query_args(query: RepositoryQuery<'_>) -> Result<Vec<String>> {
        let query_format = Self::repository_query_format(&query);
        let selection = match query {
            RepositoryQuery::Available(_) => "--available",
            RepositoryQuery::Installed
            | RepositoryQuery::InstalledSizes(_)
            | RepositoryQuery::InstalledReasons(_)
            | RepositoryQuery::InstalledDetails(_) => "--installed",
            RepositoryQuery::Unneeded => "--unneeded",
        };
        let mut args = Vec::new();
        // Installed and orphan queries are cached reads. Their callers own any
        // explicit sync; repoquery must not refresh metadata behind a read.
        if matches!(
            query,
            RepositoryQuery::Installed | RepositoryQuery::Unneeded
        ) {
            args.push("--cacheonly".to_owned());
        }
        // Installed records describe what is on disk, including an older
        // build excluded from repository selection. DNF still selects the
        // upgrades using the configured policy.
        if matches!(
            query,
            RepositoryQuery::Installed
                | RepositoryQuery::InstalledSizes(_)
                | RepositoryQuery::InstalledReasons(_)
                | RepositoryQuery::InstalledDetails(_)
        ) {
            args.push("--setopt=disable_excludes=*".to_owned());
        }
        args.extend(["repoquery", selection, "--queryformat", query_format].map(str::to_owned));
        if matches!(
            query,
            RepositoryQuery::Available(_) | RepositoryQuery::Installed
        ) {
            args.push("--latest-limit=1".to_owned());
        }
        if matches!(query, RepositoryQuery::Available(None)) {
            args.push(format!("--arch={},noarch", std::env::consts::ARCH));
        }
        let package = match query {
            RepositoryQuery::Available(package) => package,
            RepositoryQuery::InstalledSizes(InstalledSizeQuery::Package(package))
            | RepositoryQuery::InstalledReasons(InstalledReasonQuery::Package(package))
            | RepositoryQuery::InstalledDetails(package) => Some(package),
            RepositoryQuery::InstalledSizes(InstalledSizeQuery::RequirementProviders(package)) => {
                args.push("--providers-of=requires".to_owned());
                Some(package)
            }
            RepositoryQuery::InstalledReasons(InstalledReasonQuery::RequiredBy(package)) => {
                Self::validate_query_selector(package)?;
                args.push(format!("--whatrequires={package}"));
                None
            }
            RepositoryQuery::Installed
            | RepositoryQuery::Unneeded
            | RepositoryQuery::InstalledSizes(InstalledSizeQuery::All) => None,
        };
        if let Some(name) = package {
            Self::validate_query_selector(name)?;
            args.push(name.to_owned());
        }
        Ok(args)
    }

    /// Validate a DNF package name, architecture identity, or full NEVRA.
    /// RPM version syntax is local to this backend; generic package validators
    /// continue to reject epochs and RPM prerelease/postrelease modifiers.
    pub fn validate_query_selector(selector: &str) -> Result<()> {
        if !selector.contains([':', '~', '^']) {
            return crate::core::security::validate_package_name(selector).map_err(Into::into);
        }
        let (nvr, architecture) = selector
            .rsplit_once('.')
            .context("DNF selector lacks architecture")?;
        let (nv, release) = nvr.rsplit_once('-').context("DNF selector lacks release")?;
        let (name, version) = nv.rsplit_once('-').context("DNF selector lacks version")?;
        crate::core::security::validate_package_name(name)?;
        crate::core::security::validate_package_name(architecture)?;
        anyhow::ensure!(
            [name, architecture].iter().all(|field| field
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"+._-".contains(&byte))),
            "Invalid DNF selector name or architecture"
        );
        let version = if let Some((epoch, version)) = version.split_once(':') {
            anyhow::ensure!(
                !epoch.is_empty() && epoch.bytes().all(|byte| byte.is_ascii_digit()),
                "Invalid DNF selector epoch"
            );
            epoch
                .parse::<u32>()
                .context("DNF selector epoch exceeds RPM range")?;
            version
        } else {
            version
        };
        for field in [version, release] {
            anyhow::ensure!(
                !field.is_empty()
                    && field.len() <= 128
                    && field
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._+~^".contains(&byte)),
                "Invalid DNF selector version or release"
            );
        }
        Ok(())
    }

    /// Validate DNF install selectors without allowing unsealed local RPMs.
    #[doc(hidden)]
    pub fn validate_install_selectors(packages: &[String]) -> Result<()> {
        reject_unsealed_local_rpm_targets(packages)?;
        Self::validate_package_selectors(packages)
    }

    /// Validate operands passed to a native DNF package command.
    #[doc(hidden)]
    pub fn validate_package_selectors(packages: &[String]) -> Result<()> {
        packages
            .iter()
            .try_for_each(|package| Self::validate_query_selector(package))
    }

    async fn query_output(command: tokio::process::Command) -> Result<Vec<u8>> {
        Self::query_output_with_deadline(command, std::time::Duration::from_mins(1)).await
    }

    async fn query_output_with_deadline(
        command: tokio::process::Command,
        deadline: std::time::Duration,
    ) -> Result<Vec<u8>> {
        Self::controlled_query_output("DNF", command, deadline, None).await
    }

    async fn controlled_query_output(
        program: &str,
        command: tokio::process::Command,
        deadline: std::time::Duration,
        cancelled: Option<tokio::sync::oneshot::Receiver<()>>,
    ) -> Result<Vec<u8>> {
        let output = Self::capture_query(program, command, deadline, cancelled, false).await?;
        Self::require_query_success(program, &output)?;
        Ok(output.stdout)
    }

    fn require_query_success(program: &str, output: &std::process::Output) -> Result<()> {
        if output.status.success() {
            return Ok(());
        }
        let diagnostics = String::from_utf8_lossy(&output.stderr);
        if let Some(detail) = diagnostics
            .lines()
            .map(str::trim)
            .rfind(|line| !line.is_empty())
        {
            let detail = sanitize_terminal_diagnostic(detail);
            anyhow::bail!("{program} query failed: {}: {detail}", output.status);
        }
        anyhow::bail!("{program} query failed: {}", output.status);
    }

    const MAX_NATIVE_LINE_BYTES: usize = 64 * 1024;

    async fn capture_query_diagnostics(
        stderr: tokio::process::ChildStderr,
        forward: bool,
    ) -> std::io::Result<Vec<u8>> {
        let limit = Self::MAX_NATIVE_LINE_BYTES;
        let mut bytes = std::collections::VecDeque::new();
        let mut forward_budget = if forward { limit } else { 0 };
        Self::read_native_lines(stderr, |line| {
            if line.len() <= forward_budget {
                let raw = String::from_utf8_lossy(line);
                eprintln!("{}", sanitize_terminal_diagnostic(raw.trim_end()));
            }
            forward_budget = forward_budget.saturating_sub(line.len());
            // DNF puts the final error or preview outcome after progress.
            // Evict complete lines so a URL cannot be clipped before redaction.
            while bytes.len() + line.len() > limit {
                let oldest_line_bytes = bytes
                    .iter()
                    .position(|&byte| byte == b'\n')
                    .map_or(bytes.len(), |index| index + 1);
                bytes.drain(..oldest_line_bytes);
            }
            bytes.extend(line);
        })
        .await?;
        Ok(bytes.into())
    }

    async fn capture_query(
        program: &str,
        mut command: tokio::process::Command,
        deadline: std::time::Duration,
        mut cancelled: Option<tokio::sync::oneshot::Receiver<()>>,
        forward_diagnostics: bool,
    ) -> Result<std::process::Output> {
        use tokio::io::AsyncReadExt;
        const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
        if let Some(cancelled) = cancelled.as_mut() {
            anyhow::ensure!(
                matches!(
                    cancelled.try_recv(),
                    Err(tokio::sync::oneshot::error::TryRecvError::Empty)
                ),
                "{program} stored query cancelled before execution"
            );
        }
        let mut child = command
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("Could not start {program} query"))?;
        let result = {
            let operation = async {
                let stdout = child
                    .stdout
                    .take()
                    .with_context(|| format!("{program} stdout was not captured"))?;
                let stderr = child
                    .stderr
                    .take()
                    .with_context(|| format!("{program} stderr was not captured"))?;
                let output = async {
                    let mut bytes = Vec::new();
                    stdout
                        .take(MAX_OUTPUT_BYTES + 1)
                        .read_to_end(&mut bytes)
                        .await?;
                    anyhow::ensure!(
                        bytes.len() as u64 <= MAX_OUTPUT_BYTES,
                        "{program} query output exceeds 64 MiB"
                    );
                    Ok(bytes)
                };
                let diagnostics = async {
                    Ok(Self::capture_query_diagnostics(stderr, forward_diagnostics).await?)
                };
                let (stdout, stderr) = tokio::try_join!(output, diagnostics)?;
                let status = child
                    .wait()
                    .await
                    .with_context(|| format!("Could not wait for {program} query"))?;
                Ok(std::process::Output {
                    status,
                    stdout,
                    stderr,
                })
            };
            let cancellation = async {
                match cancelled {
                    Some(cancelled) => {
                        let _ = cancelled.await;
                    }
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::select! {
                result = tokio::time::timeout(deadline, operation) => match result {
                    Ok(result) => result,
                    Err(error) => Err(anyhow::Error::new(error).context(format!("{program} query timed out after {} seconds", deadline.as_secs()))),
                },
                () = cancellation => Err(anyhow::anyhow!("{program} stored query cancelled")),
            }
        };
        if result.is_err() {
            if let Err(error) = child.start_kill() {
                tracing::debug!(%error, %program, "Query may have exited before cancellation kill");
            }
            child
                .wait()
                .await
                .with_context(|| format!("Could not reap {program} query"))?;
        }
        result
    }

    fn search_with_progress(
        &self,
        query: &str,
        progress: bool,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Package>>> + Send + '_>> {
        let query_lower = query.to_lowercase();
        Box::pin(async move {
            let installed = self.load_installed_packages().await?;
            let command = Self::repository_command(RepositoryQuery::Available(None))?;
            let (installed, output) = tokio::try_join!(
                Self::order_installed_search_builds(&installed),
                Self::capture_query(
                    "DNF",
                    command,
                    std::time::Duration::from_mins(1),
                    None,
                    progress
                )
            )?;
            Self::require_query_success("DNF", &output)?;
            Self::search_results(installed, &output.stdout, &query_lower)
        })
    }

    async fn owned_stored_transaction(
        mut command: tokio::process::Command,
        directory: tempfile::TempDir,
        deadline: std::time::Duration,
    ) -> Result<Option<(tempfile::TempDir, Vec<u8>)>> {
        let (cancel, cancelled) = tokio::sync::oneshot::channel();
        let _cancel_on_drop = CancelStoredQuery(Some(cancel));
        command.env("LC_ALL", "C");
        tokio::task::spawn_blocking(move || -> Result<_> {
            use std::io::Read;
            let output = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(Self::controlled_query_output(
                    "DNF",
                    command,
                    deadline,
                    Some(cancelled),
                ))?;
            let path = directory.path().join("transaction.json");
            let metadata = match path.symlink_metadata() {
                // DNF prints the empty-transaction line after any skipped packages.
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        && output.trim_ascii_end().rsplit(|&byte| byte == b'\n').next()
                            == Some(b"Nothing to do.".as_slice()) =>
                {
                    return Ok(None);
                }
                result => result.context("DNF5 did not store a transaction")?,
            };
            anyhow::ensure!(
                metadata.is_file(),
                "DNF stored transaction is not a regular file"
            );
            let file =
                std::fs::File::open(path).context("Cannot read the stored DNF transaction")?;
            let mut bytes = Vec::new();
            file.take(64 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
            anyhow::ensure!(
                bytes.len() <= 64 * 1024 * 1024,
                "DNF stored transaction exceeds 64 MiB"
            );
            Ok(Some((directory, bytes)))
        })
        .await
        .context("DNF stored transaction owner failed")?
    }

    fn advisory_command(cache: &Path) -> Result<tokio::process::Command> {
        let cache = cache
            .to_str()
            .context("DNF advisory cache path is not UTF-8")?;
        let mut command: tokio::process::Command = Self::native_package_command("dnf")?.into();
        // A fresh user's cache can otherwise be populated from root's stale
        // cache even with --refresh. Use one audit-owned cache for both paths.
        command.args([
            format!("--setopt=cachedir={cache}"),
            format!("--setopt=system_cachedir={cache}"),
            "--setopt=cacheonly=none".into(),
        ]);
        Ok(command)
    }

    async fn affected_installed_packages<'a>(
        rows: impl IntoIterator<Item = &'a super::dnf_advisory::ApplicableAdvisory>,
        installed: &[super::types::SecurityPackage],
        scope: InstalledAdvisoryMatch,
    ) -> Result<BTreeMap<String, Vec<crate::core::security::scan::InstalledIdentity>>> {
        use crate::core::security::scan::InstalledIdentity;
        use std::collections::btree_map::Entry;

        let mut by_name: HashMap<_, Vec<_>> = HashMap::new();
        for package in installed {
            if let Some(architecture) = package.architecture.as_deref() {
                by_name
                    .entry(package.name.as_str())
                    .or_default()
                    .push((architecture, package));
            }
        }

        let mut selected = BTreeMap::new();
        let mut comparisons = Vec::new();
        let mut candidates = Vec::new();
        for row in rows {
            let Entry::Vacant(entry) = selected.entry(row.nevra.as_str()) else {
                continue;
            };
            let (name, architecture) = super::dnf_advisory::package_identity(&row.nevra)?;
            let evr = &row.nevra[name.len() + 1..row.nevra.len() - architecture.len() - 1];
            for &(installed_arch, package) in by_name.get(name).into_iter().flatten() {
                let matches = match scope {
                    InstalledAdvisoryMatch::Exact => installed_arch == architecture,
                    InstalledAdvisoryMatch::ArchitectureChange => {
                        installed_arch != architecture
                            && (installed_arch == "noarch" || architecture == "noarch")
                    }
                };
                if !matches {
                    continue;
                }
                anyhow::ensure!(
                    scope == InstalledAdvisoryMatch::Exact || comparisons.len() < 10_000,
                    "Supplemental RPM comparisons exceed their bound"
                );
                comparisons.push((package.version.clone(), evr.to_owned()));
                candidates.push((row.nevra.as_str(), package));
            }
            entry.insert((row.name.as_str(), Vec::new()));
        }
        let compared = Self::compare_native_evrs(&comparisons).await?;
        for ((nevra, package), order) in candidates.into_iter().zip(compared) {
            if order < 0 {
                selected
                    .get_mut(nevra)
                    .context("Missing native advisory selection")?
                    .1
                    .push(InstalledIdentity::from(package));
            }
        }
        selected
            .into_iter()
            .map(|(nevra, (advisory, affected))| {
                anyhow::ensure!(
                    scope == InstalledAdvisoryMatch::ArchitectureChange || !affected.is_empty(),
                    "Advisory {advisory} has no affected installed identity: {nevra}"
                );
                Ok((nevra.to_owned(), affected))
            })
            .collect()
    }

    async fn native_advisories(
        mode: AdvisoryLookup<'_>,
    ) -> Result<(
        super::dnf_advisory::AdvisoryRows,
        super::dnf_advisory::AdvisoryRows,
    )> {
        let cache = crate::core::paths::cache_dir().join("dnf-security");
        let mut outputs = Vec::with_capacity(2);
        for details in [false, true] {
            let mut command = Self::advisory_command(&cache)?;
            command.args(super::dnf_advisory::query_args(details));
            outputs.push(Self::query_output(command).await?);
        }
        let mut repositories = Self::advisory_command(&cache)?;
        repositories.args([
            "--cacheonly",
            REQUIRE_ALL_REPOSITORIES,
            "repo",
            "info",
            "--enabled",
            "--json",
        ]);
        let repository_ids =
            super::dnf_advisory::enabled_repository_ids(&Self::query_output(repositories).await?)?;
        let native = super::dnf_advisory::join_advisories(&outputs[0], &outputs[1])?;
        let supplemental = Self::cached_advisory_lookup(&cache, &repository_ids, mode)
            .await
            .unwrap_or_else(|error| {
                tracing::warn!("Supplemental Fedora advisory lookup unavailable: {error:#}");
                Vec::new()
            });
        Ok((native, supplemental))
    }

    async fn cached_advisory_lookup(
        cache: &Path,
        repository_ids: &BTreeSet<String>,
        lookup: AdvisoryLookup<'_>,
    ) -> Result<super::dnf_advisory::AdvisoryRows> {
        let (mode, subjects) = match lookup {
            AdvisoryLookup::ArchitectureChanges => ("architecture-changes", Vec::new()),
            AdvisoryLookup::Proposed(packages) => {
                let subjects: Vec<_> = packages
                    .iter()
                    .filter_map(|package| {
                        let architecture = package.architecture.as_deref()?;
                        let epoch = if package.version.contains(':') {
                            ""
                        } else {
                            "0:"
                        };
                        Some(format!(
                            "{}-{epoch}{}.{architecture}",
                            package.name, package.version
                        ))
                    })
                    .collect();
                if subjects.is_empty() {
                    return Ok(Vec::new());
                }
                ("proposed", subjects)
            }
        };
        anyhow::ensure!(
            subjects.len() <= 10_000
                && subjects.iter().map(|id| id.len() + 1).sum::<usize>() <= 512 * 1024,
            "Supplemental advisory subjects exceed their bound"
        );
        for subject in &subjects {
            Self::validate_query_selector(subject)?;
        }
        let repositories = serde_json::to_string(repository_ids)?;
        anyhow::ensure!(
            repositories.len() <= 64 * 1024,
            "DNF repository scope exceeds its bound"
        );
        let mut command: tokio::process::Command = Self::native_package_command("python3")?.into();
        command
            .args(["-I", "-B", "-c", include_str!("dnf_advisory_lookup.py")])
            .arg(cache)
            .args([mode, &repositories])
            .args(subjects);
        let output =
            Self::query_output_with_deadline(command, std::time::Duration::from_secs(30)).await?;
        super::dnf_advisory::cached_lookup_result(&output)
    }

    async fn native_history(since: Option<u64>) -> Result<Vec<NativeTransaction>> {
        let range = since.map_or_else(|| "last".to_owned(), |id| format!("{}..last", id.max(1)));
        // DNF can initialize its journal as root; an ordinary caller cannot.
        // Avoid an error message on a fresh default installation, but still ask
        // DNF for its effective path before deciding that there is no journal.
        let unprivileged = !is_root();
        let check_before_query = unprivileged
            && !Path::new("/usr/lib/sysimage/libdnf5")
                .join(DNF_HISTORY_DATABASE)
                .exists();
        if check_before_query
            && Self::native_history_is_missing()
                .await
                .is_ok_and(|missing| missing)
        {
            return Ok(Vec::new());
        }
        let mut command: tokio::process::Command = Self::native_package_command("dnf")?.into();
        command.args(["history", "info", "--json", &range]);
        let output = match Self::query_output(command).await {
            Err(_)
                if unprivileged
                    && !check_before_query
                    && Self::native_history_is_missing()
                        .await
                        .is_ok_and(|missing| missing) =>
            {
                return Ok(Vec::new());
            }
            result => result?,
        };
        let transactions: Vec<NativeTransaction> =
            serde_json::from_slice(&output).context("Invalid native DNF history")?;
        anyhow::ensure!(
            transactions.iter().all(|transaction| transaction.id > 0),
            "Invalid native transaction ID"
        );
        Ok(transactions)
    }

    async fn native_history_is_missing() -> Result<bool> {
        let mut command: tokio::process::Command = Self::native_package_command("dnf")?.into();
        command.arg("--dump-main-config");
        let config = Self::query_output(command).await?;
        Self::history_is_missing(std::str::from_utf8(&config)?)
    }

    fn history_is_missing(config: &str) -> Result<bool> {
        let effective = |key: &str| -> Result<&str> {
            let mut values = config.lines().filter_map(|line| {
                let (name, value) = line.split_once('=')?;
                (name.trim() == key).then(|| value.trim())
            });
            let value = values
                .next()
                .with_context(|| format!("Missing DNF {key}"))?;
            anyhow::ensure!(values.next().is_none(), "Ambiguous DNF {key}");
            Ok(value)
        };
        anyhow::ensure!(
            effective("installroot")? == "/",
            "Unexpected DNF install root"
        );
        let directory = Path::new(effective("transaction_history_dir")?);
        anyhow::ensure!(directory.is_absolute(), "Relative DNF history directory");
        match directory.join(DNF_HISTORY_DATABASE).symlink_metadata() {
            Ok(_) => Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error).context("Cannot verify DNF history path"),
        }
    }

    fn native_outcome(transactions: &[NativeTransaction], comment: &str) -> Result<NativeOutcome> {
        let mut matching = transactions
            .iter()
            .filter(|transaction| transaction.comment == comment);
        let Some(transaction) = matching.next() else {
            return Ok(NativeOutcome::NoTransaction);
        };
        anyhow::ensure!(
            matching.next().is_none(),
            "Duplicate DNF transaction correlation"
        );
        match transaction.status.as_str() {
            "Ok" => Ok(NativeOutcome::Committed(Self::native_changes(
                &transaction.packages,
            )?)),
            "Error" => Ok(NativeOutcome::Failed),
            status => {
                // libdnf5 inserts a transaction row as STARTED and only replaces
                // that state from finish(OK|ERROR)
                // (libdnf5/transaction/transaction.hpp: TransactionState
                // { STARTED = 1, OK = 2, ERROR = 3 }, start(), finish()).
                // A row still marked STARTED was interrupted before it could
                // finish. Redo creates a separate transaction, not a terminal
                // state on this row, and can change packages/reasons again.
                // Do not infer success or initiate repair from this row.
                let command = if transaction.description.is_empty() {
                    "not recorded".to_owned()
                } else {
                    transaction.description.clone()
                };
                tracing::warn!(
                    "DNF transaction {} is still '{status}' after {} package action(s); \
                     recorded command: {command}",
                    transaction.id,
                    transaction.packages.len()
                );
                Ok(NativeOutcome::Interrupted {
                    id: transaction.id,
                    comment: transaction.comment.clone(),
                    status: status.to_owned(),
                    actions: transaction.packages.len(),
                    command,
                })
            }
        }
    }

    fn native_changes(
        packages: &[NativeTransactionPackage],
    ) -> Result<Vec<crate::core::history::PackageChange>> {
        use crate::core::history::PackageChange;
        let mut grouped: BTreeMap<(&str, &str), NativeVersionChanges> = BTreeMap::new();
        for package in packages {
            anyhow::ensure!(
                !package
                    .nevra
                    .chars()
                    .any(|ch| ch.is_whitespace() || ch.is_control()),
                "Invalid native NEVRA"
            );
            let (nvr, architecture) = package
                .nevra
                .rsplit_once('.')
                .context("Native NEVRA has no architecture")?;
            let (nv, release) = nvr
                .rsplit_once('-')
                .context("Native NEVRA has no release")?;
            let (name, version) = nv.rsplit_once('-').context("Native NEVRA has no version")?;
            anyhow::ensure!(
                [name, version, release, architecture]
                    .iter()
                    .all(|field| !field.is_empty()),
                "Native NEVRA has an empty field"
            );
            let evr = &nvr[name.len() + 1..];
            let changes = grouped.entry((name, architecture)).or_default();
            match package.action.as_str() {
                "Install" | "Upgrade" | "Downgrade" => {
                    changes.added.insert(evr.to_owned());
                }
                "Remove" | "Replaced" => {
                    changes.removed.insert(evr.to_owned());
                }
                "Reinstall" => {
                    changes.removed.insert(evr.to_owned());
                    changes.added.insert(evr.to_owned());
                }
                "Reason Change" => {}
                action => anyhow::bail!("Unsupported native DNF action '{action}'"),
            }
        }
        let mut result = Vec::new();
        for ((name, architecture), changes) in grouped {
            let change = |old_version, new_version| PackageChange {
                name: name.to_owned(),
                architecture: Some(architecture.to_owned()),
                old_version,
                new_version,
                source: "dnf".to_owned(),
            };
            if changes.removed.len() == 1 && changes.added.len() == 1 {
                result.push(change(
                    changes.removed.into_iter().next(),
                    changes.added.into_iter().next(),
                ));
            } else {
                result.extend(
                    changes
                        .removed
                        .into_iter()
                        .map(|version| change(Some(version), None)),
                );
                result.extend(
                    changes
                        .added
                        .into_iter()
                        .map(|version| change(None, Some(version))),
                );
            }
        }
        Ok(result)
    }

    async fn execute_dnf(&self, args: Vec<String>) -> Result<()> {
        let guarded = args
            .iter()
            .find(|arg| !arg.starts_with('-'))
            .is_some_and(|arg| matches!(arg.as_str(), "install" | "upgrade"));
        if guarded {
            crate::core::security::policy::require_native_plan_support("DNF")?;
        }
        let operation = if guarded && !is_root() {
            crate::core::privilege::run_privileged_dnf(&args).await
        } else if guarded {
            self.execute_reviewed_transaction(&args).await
        } else if is_root() {
            let manager = self.cache_handle();
            tokio::task::spawn_blocking(move || {
                let arguments: Vec<_> = args.iter().map(String::as_str).collect();
                manager.run_dnf(&arguments)
            })
            .await
            .map_err(anyhow::Error::from)
            .and_then(std::convert::identity)
        } else {
            let arguments: Vec<_> = args.iter().map(String::as_str).collect();
            crate::core::privilege::run_privileged_program("dnf", &arguments).await
        };
        self.invalidate_installed_cache();
        operation
    }

    /// Only fixed transaction modes and validated package selectors cross elevation.
    #[doc(hidden)]
    pub fn validate_admission_args(args: &[String]) -> Result<()> {
        Self::admission_request(args).map(|_| ())
    }

    fn admission_request(args: &[String]) -> Result<DnfAdmission<'_>> {
        anyhow::ensure!(
            args.len() <= 10_004,
            "DNF transaction has too many arguments"
        );
        let mut remaining = args;
        let mut correlation = None;
        if let Some(comment) = remaining
            .first()
            .and_then(|value| value.strip_prefix("--comment=omg-"))
        {
            let id = uuid::Uuid::parse_str(comment).context("Invalid DNF transaction comment")?;
            anyhow::ensure!(
                id.to_string() == comment,
                "Noncanonical DNF transaction comment"
            );
            correlation = remaining.first().map(String::as_str);
            remaining = &remaining[1..];
        }
        let cached = remaining
            .first()
            .is_some_and(|value| value == CACHED_UPGRADE_METADATA);
        if cached {
            remaining = &remaining[1..];
        }
        let [action, mode, packages @ ..] = remaining else {
            anyhow::bail!("Incomplete DNF admission request");
        };
        anyhow::ensure!(
            !cached || action == "upgrade",
            "Cached metadata mode is only supported for upgrades"
        );
        if action == "remove" {
            let (output, packages) = match packages {
                [flag, rest @ ..] if flag == "--quiet" => (OutputMode::Quiet, rest),
                [flag, rest @ ..] if flag == "--verbose" => (OutputMode::Verbose, rest),
                _ => (OutputMode::Plain, packages),
            };
            anyhow::ensure!(!packages.is_empty(), "Remove requires package operands");
            let yes = match mode.as_str() {
                "-y" => true,
                "--confirm" => false,
                _ => anyhow::bail!("Unsupported DNF removal mode"),
            };
            Self::validate_package_selectors(packages)?;
            return Ok(DnfAdmission::Remove {
                packages,
                comment: correlation,
                yes,
                output,
            });
        }
        anyhow::ensure!(
            matches!(action.as_str(), "install" | "upgrade") && mode == "-y",
            "Unsupported DNF admission request"
        );
        anyhow::ensure!(
            action != "upgrade" || packages.is_empty(),
            "System upgrade does not accept operands"
        );
        anyhow::ensure!(
            action != "install" || !packages.is_empty(),
            "Install requires package operands"
        );
        Self::validate_install_selectors(packages)?;
        if action == "upgrade" {
            Ok(DnfAdmission::Upgrade { cached })
        } else {
            Ok(DnfAdmission::Install)
        }
    }

    #[doc(hidden)]
    pub async fn execute_elevated_admission(args: &[String]) -> Result<()> {
        anyhow::ensure!(is_root(), "Native DNF admission requires root");
        anyhow::ensure!(
            super::resolve_backend()? == super::Backend::Fedora,
            "Native DNF admission requires the Fedora backend"
        );
        let manager = Self::new();
        match Self::admission_request(args)? {
            DnfAdmission::Install | DnfAdmission::Upgrade { .. } => {
                manager.execute_reviewed_transaction(args).await
            }
            DnfAdmission::Remove {
                packages,
                comment,
                yes,
                output,
            } => {
                crate::cli::modern_ui::configure_output(
                    u8::from(output == OutputMode::Verbose),
                    output == OutputMode::Quiet,
                );
                let Some(plan) = crate::cli::packages::review_fedora_removal(packages, yes).await?
                else {
                    return Ok(());
                };
                crate::cli::packages::common::report_removal(
                    packages,
                    manager.replay_removal_plan(plan, comment.map(str::to_owned)),
                )
                .await
            }
        }
    }

    async fn execute_reviewed_transaction(&self, args: &[String]) -> Result<()> {
        let (prepare_options, replay_options): (&[&str], &'static [&'static str]) =
            match Self::admission_request(args)? {
                DnfAdmission::Install => (&[], &[]),
                DnfAdmission::Upgrade { cached: false } => {
                    (&[REQUIRE_ALL_REPOSITORIES], &[REQUIRE_ALL_REPOSITORIES])
                }
                DnfAdmission::Upgrade { cached: true } => (
                    &[REQUIRE_ALL_REPOSITORIES],
                    &[REQUIRE_ALL_REPOSITORIES, CACHED_UPGRADE_METADATA],
                ),
                DnfAdmission::Remove { .. } => {
                    anyhow::bail!("DNF install/upgrade admission requires an install or upgrade");
                }
            };
        crate::core::security::policy::require_native_plan_support("DNF")?;
        anyhow::ensure!(
            is_root(),
            "DNF stored transaction must be prepared by its root owner"
        );
        let directory = Self::removal_preview_directory()?;
        let mut command: tokio::process::Command = Self::native_package_command("dnf")?.into();
        command
            .args(prepare_options)
            .args(args)
            .arg(format!("--store={}", directory.path().display()));
        let Some((directory, bytes)) =
            Self::owned_stored_transaction(command, directory, std::time::Duration::from_mins(30))
                .await
                .context("Could not prepare a stored DNF5 installation transaction")?
        else {
            crate::cli::modern_ui::print_info("DNF reported no package changes");
            return Ok(());
        };
        let inventory = Self::proposed_inventory(&bytes)?;
        if inventory.is_empty() {
            return Ok(());
        }
        let (directory, digest) = tokio::task::spawn_blocking(move || -> Result<_> {
            let digest = Self::stored_tree_digest(directory.path())?;
            Ok((directory, digest))
        })
        .await??;
        let context = serde_json::to_string(&("omg-native-dnf-stored-v1", args, &digest))?;
        let gaps = vec!["Fedora advisory matches are possible findings. Vendor fixed versions do not establish introduced ranges or branch applicability. CVE and disclosed zero-day coverage remains unknown. https://dnf5.readthedocs.io/en/stable/commands/advisory.8.html".into()];
        let source = PlannedDnfAdvisories;
        crate::core::security::package_review::review_async(&inventory, &context, &gaps, &source)
            .await?;
        let (directory, checked) = tokio::task::spawn_blocking(move || -> Result<_> {
            let digest = Self::stored_tree_digest(directory.path())?;
            Ok((directory, digest))
        })
        .await??;
        anyhow::ensure!(
            checked == digest,
            "DNF stored artifacts or repository evidence changed after review"
        );
        let comment = args
            .first()
            .filter(|value| value.starts_with("--comment=omg-"))
            .cloned();
        self.replay_stored_transaction(directory, replay_options, comment)
            .await
    }

    async fn replay_stored_transaction(
        &self,
        directory: tempfile::TempDir,
        options: &'static [&'static str],
        comment: Option<String>,
    ) -> Result<()> {
        anyhow::ensure!(
            is_root(),
            "DNF stored transactions require their root owner"
        );
        let manager = self.cache_handle();
        tokio::task::spawn_blocking(move || {
            let mut args = options.to_vec();
            args.extend([
                "replay",
                directory.path().to_str().context("Invalid DNF plan path")?,
                "-y",
            ]);
            if let Some(comment) = comment.as_deref() {
                args.insert(0, comment);
            }
            let result = manager.run_dnf(&args);
            manager.invalidate_installed_cache();
            result
        })
        .await?
    }

    fn proposed_inventory(bytes: &[u8]) -> Result<Vec<super::types::SecurityPackage>> {
        let transaction: StoredRemovalTransaction = serde_json::from_slice(bytes)
            .context("Invalid DNF5 stored installation transaction")?;
        anyhow::ensure!(
            transaction.version == "1.0",
            "Unsupported DNF stored transaction version"
        );
        anyhow::ensure!(
            transaction.groups.is_empty() && transaction.environments.is_empty(),
            "DNF group/environment changes require separate review support"
        );
        let mut inventory = Vec::new();
        let mut seen = BTreeSet::new();
        for package in transaction.rpms {
            anyhow::ensure!(
                seen.insert((package.nevra.clone(), package.action.clone())),
                "Duplicate DNF stored transaction operation"
            );
            match package.action.as_str() {
                "Remove" | "Replaced" => continue,
                "Install" | "Upgrade" | "Downgrade" | "Reinstall" => {}
                _ => anyhow::bail!("Unsupported DNF stored action: {}", package.action),
            }
            let (name, architecture) = super::dnf_advisory::package_identity(&package.nevra)?;
            inventory.push(super::types::SecurityPackage {
                origin: super::types::SecurityOrigin::DistributionPackage,
                name: name.into(),
                version: package.nevra
                    [name.len() + 1..package.nevra.len() - architecture.len() - 1]
                    .into(),
                advisory_source: None,
                architecture: Some(architecture.into()),
                description: String::new(),
                licenses: Vec::new(),
            });
        }
        inventory.sort_by(|left, right| {
            (&left.name, &left.version, &left.architecture).cmp(&(
                &right.name,
                &right.version,
                &right.architecture,
            ))
        });
        Ok(inventory)
    }

    fn stored_tree_digest(root: &Path) -> Result<String> {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        let mut hash = Sha256::new();
        let mut pending = vec![root.to_owned()];
        let mut files = BTreeMap::new();
        let mut count = 0usize;
        let mut total = 0u64;
        while let Some(path) = pending.pop() {
            count += 1;
            anyhow::ensure!(count <= 100_000, "DNF stored tree has too many entries");
            let metadata = path.symlink_metadata()?;
            anyhow::ensure!(
                !metadata.file_type().is_symlink(),
                "DNF stored tree contains a symlink"
            );
            if metadata.is_dir() {
                for entry in std::fs::read_dir(&path)? {
                    anyhow::ensure!(
                        pending.len() + count < 100_000,
                        "DNF stored tree has too many entries"
                    );
                    pending.push(entry?.path());
                }
            } else {
                anyhow::ensure!(
                    metadata.is_file(),
                    "DNF stored tree contains a nonregular file"
                );
                total = total
                    .checked_add(metadata.len())
                    .context("DNF stored tree size overflow")?;
                anyhow::ensure!(
                    total <= 32 * 1024 * 1024 * 1024,
                    "DNF stored tree exceeds 32 GiB"
                );
                files.insert(path.strip_prefix(root)?.to_owned(), (path, metadata.len()));
            }
        }
        let mut buffer = vec![0u8; 64 * 1024];
        for (relative, (path, length)) in files {
            let encoded = serde_json::to_vec(&relative)?;
            hash.update((encoded.len() as u64).to_be_bytes());
            hash.update(encoded);
            hash.update(length.to_be_bytes());
            let mut file = std::fs::File::open(path)?;
            let mut read = 0u64;
            loop {
                let length = file.read(&mut buffer)?;
                if length == 0 {
                    break;
                }
                read += length as u64;
                anyhow::ensure!(
                    read <= 32 * 1024 * 1024 * 1024,
                    "DNF stored file grew beyond limit"
                );
                hash.update(&buffer[..length]);
            }
            anyhow::ensure!(read == length, "DNF stored file changed while hashing");
        }
        Ok(hex::encode(hash.finalize()))
    }

    async fn recorded_mutation(
        &self,
        kind: crate::core::history::TransactionType,
        args: Vec<String>,
        history: Option<&crate::core::history::HistoryManager>,
    ) -> Result<Option<usize>> {
        Self::record_native_mutation(kind, history, |comment| {
            let mut args = args;
            if let Some(comment) = comment {
                args.insert(0, comment);
            }
            self.execute_dnf(args)
        })
        .await
    }

    async fn record_native_mutation<F>(
        kind: crate::core::history::TransactionType,
        history: Option<&crate::core::history::HistoryManager>,
        operation: impl FnOnce(Option<String>) -> F,
    ) -> Result<Option<usize>>
    where
        F: Future<Output = Result<()>>,
    {
        let Some(history) = history.filter(|_| !crate::core::privilege::parent_owns_history())
        else {
            return operation(None).await.map(|()| None);
        };
        let before = Self::native_history(None)
            .await?
            .iter()
            .map(|transaction| transaction.id)
            .max()
            .unwrap_or(0);
        let comment = format!("omg-{}", uuid::Uuid::new_v4());
        let operation = operation(Some(format!("--comment={comment}"))).await;
        let observed = match Self::native_history(Some(before)).await {
            Ok(transactions) => Self::native_outcome(&transactions, &comment),
            Err(error) => Err(error),
        };
        // Observing a non-terminal journal row must not initiate another
        // package mutation. A redo would need its own correlation and native
        // state proof, plus explicit confirmation/elevation/deadline policy.
        Self::record_native_result(kind, history, operation, observed).map(Some)
    }

    fn record_native_result(
        kind: crate::core::history::TransactionType,
        history: &crate::core::history::HistoryManager,
        operation: Result<()>,
        observed: Result<NativeOutcome>,
    ) -> Result<usize> {
        let persistence = match observed {
            Ok(NativeOutcome::NoTransaction) if operation.is_ok() => Ok(0),
            Ok(NativeOutcome::NoTransaction | NativeOutcome::Failed) => history
                .add_transaction(kind, Vec::new(), false)
                .and_then(|()| {
                    anyhow::ensure!(
                        operation.is_err(),
                        "DNF reported a failed journal transaction after command success"
                    );
                    Ok(0)
                }),
            Ok(NativeOutcome::Committed(changes)) => {
                let count = changes.len();
                history.add_transaction(kind, changes, true).map(|()| count)
            }
            Ok(NativeOutcome::Interrupted {
                id,
                comment,
                status,
                actions,
                command,
            }) => Err(anyhow::anyhow!(
                "DNF transaction {id} with comment '{comment}' has unresolved status '{status}' for {actions} \
                 package action(s); recorded command: {command}. Automatic recovery was not attempted; \
                 inspect native DNF history and package state before deciding on recovery"
            )),
            Err(error) => Err(error),
        };
        match (operation, persistence) {
            (Ok(()), Ok(count)) => Ok(count),
            (Err(error), Ok(_)) => Err(error),
            (Ok(()), Err(error)) => {
                Err(error.context("DNF operation succeeded but its history could not be recorded"))
            }
            (Err(operation), Err(history)) => anyhow::bail!(
                "DNF operation failed: {operation:#}; history recording also failed: {history:#}"
            ),
        }
    }

    fn parse_versioned_packages(output: &[u8]) -> Result<Vec<VersionedPackage>> {
        let text = std::str::from_utf8(output).context("DNF version query is not UTF-8")?;
        text.lines()
            .filter(|line| !line.is_empty())
            .map(|line| {
                let fields: Vec<_> = line.split('\t').take(5).collect();
                anyhow::ensure!(fields.len() == 4, "DNF version row must have four fields");
                Self::validate_versioned_fields(&fields)?;
                Ok(VersionedPackage {
                    name: fields[0].to_owned(),
                    architecture: fields[1].to_owned(),
                    version: fields[2].to_owned(),
                    repository: fields[3].to_owned(),
                })
            })
            .collect()
    }

    fn validate_versioned_fields(fields: &[&str]) -> Result<()> {
        anyhow::ensure!(
            fields.iter().all(|field| !field.is_empty()
                && !field
                    .chars()
                    .any(|ch| ch.is_whitespace() || ch.is_control())),
            "DNF version row has an invalid field"
        );
        Ok(())
    }

    fn parse_package_listing(output: &[u8], heading: &str) -> Result<Vec<VersionedPackage>> {
        let text = std::str::from_utf8(output).context("DNF package listing is not UTF-8")?;
        let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
        let Some(header) = lines.next() else {
            return Ok(Vec::new());
        };
        anyhow::ensure!(header == heading, "Invalid DNF package listing heading");
        lines
            .map(|line| {
                let fields: Vec<_> = line.split_ascii_whitespace().take(4).collect();
                let &[name_arch, version, repository] = fields.as_slice() else {
                    anyhow::bail!("DNF package listing row must have three fields");
                };
                let (name, architecture) = name_arch
                    .rsplit_once('.')
                    .context("DNF package listing row lacks architecture")?;
                Self::validate_versioned_fields(&[name, architecture, version, repository])?;
                Ok(VersionedPackage {
                    name: name.to_owned(),
                    architecture: architecture.to_owned(),
                    version: version.to_owned(),
                    repository: repository.to_owned(),
                })
            })
            .collect()
    }

    async fn match_updates(
        installed: &[VersionedPackage],
        upgrades: &[VersionedPackage],
    ) -> Result<Vec<UpdateInfo>> {
        let mut by_name: HashMap<&str, Vec<&VersionedPackage>> = HashMap::new();
        for package in installed {
            let installed = by_name.entry(package.name.as_str()).or_default();
            anyhow::ensure!(
                !installed
                    .iter()
                    .any(|other| other.architecture == package.architecture),
                "DNF returned duplicate installed name/architecture"
            );
            installed.push(package);
        }
        let mut updates = Vec::with_capacity(upgrades.len());
        let mut seen = BTreeSet::new();
        for candidate in upgrades {
            let arch = candidate.architecture.as_str();
            // DNF has already filtered by repository priority and latest EVR.
            // Tied mirrors are alternative sources for the same update.
            if !seen.insert((candidate.name.as_str(), arch)) {
                continue;
            }
            let same_name = by_name
                .get(candidate.name.as_str())
                .map(Vec::as_slice)
                .unwrap_or_default();
            let mut compatible = same_name.iter().filter(|package| {
                let installed_arch = package.architecture.as_str();
                installed_arch == arch
                    || ((installed_arch == "noarch" || arch == "noarch")
                        && !matches!(installed_arch, "src" | "nosrc")
                        && !matches!(arch, "src" | "nosrc"))
            });
            let mut old = compatible.next().with_context(|| {
                format!(
                    "DNF upgrade {}.{arch} has no matching installed package",
                    candidate.name
                )
            })?;
            // When noarch crosses architectures, use the newest compatible
            // installed EVR, the same version DNF compares against.
            for package in compatible {
                if package.version != old.version
                    && Self::compare_native_evrs(&[(old.version.clone(), package.version.clone())])
                        .await?[0]
                        < 0
                {
                    old = package;
                }
            }
            anyhow::ensure!(
                old.version != candidate.version,
                "DNF upgrade has an unchanged version"
            );
            updates.push(UpdateInfo {
                architecture: Some(candidate.architecture.clone()),
                name: candidate.name.clone(),
                old_version: old.version.clone(),
                new_version: candidate.version.clone(),
                repo: candidate.repository.clone(),
            });
        }
        Ok(updates)
    }

    /// A handle sharing this manager's caches, so blocking workers mutate
    /// the same state as the caller instead of a throwaway copy.
    #[must_use]
    fn cache_handle(&self) -> Self {
        Self {
            rpm_database: self.rpm_database.clone(),
            installed_cache: Arc::clone(&self.installed_cache),
        }
    }

    async fn unneeded_packages() -> Result<Vec<VersionedPackage>> {
        let output = Self::repository_output(RepositoryQuery::Unneeded).await?;
        Self::parse_versioned_packages(&output)
    }

    #[doc(hidden)]
    pub async fn orphan_count() -> Result<usize> {
        Ok(Self::unneeded_packages().await?.len())
    }

    pub(crate) async fn orphan_packages() -> Result<Vec<String>> {
        Ok(Self::unneeded_packages()
            .await?
            .into_iter()
            .map(|package| format!("{}.{}", package.name, package.architecture))
            .collect())
    }

    pub(crate) async fn preview_orphan_cleanup() -> Result<DnfTransactionPreview> {
        Self::preview_declined_transaction(["--cacheonly", "autoremove"]).await
    }

    pub(crate) async fn preview_cached_upgrade() -> Result<DnfTransactionPreview> {
        Self::preview_declined_transaction(CACHED_UPGRADE_PREVIEW_ARGS).await
    }

    pub(crate) async fn preview_removal(packages: &[String]) -> Result<DnfTransactionPreview> {
        Self::validate_package_selectors(packages)?;
        Self::preview_declined_transaction(
            ["--cacheonly", "remove"]
                .into_iter()
                .chain(packages.iter().map(String::as_str)),
        )
        .await
    }

    pub(crate) async fn preview_install(packages: &[String]) -> Result<DnfTransactionPreview> {
        Self::validate_install_selectors(packages)?;
        Self::preview_declined_transaction(
            std::iter::once("install").chain(packages.iter().map(String::as_str)),
        )
        .await
    }

    async fn preview_declined_transaction<'a>(
        args: impl IntoIterator<Item = &'a str>,
    ) -> Result<DnfTransactionPreview> {
        let mut command: tokio::process::Command = Self::native_package_command("dnf")?.into();
        command
            .env("LC_ALL", "C")
            .args(["--color=never", "--setopt=assumeyes=false", "--assumeno"])
            .args(args);
        let output = Self::capture_query(
            "DNF",
            command,
            std::time::Duration::from_mins(1),
            None,
            false,
        )
        .await?;
        Self::transaction_preview_output(&output)
    }

    fn transaction_preview_output(output: &std::process::Output) -> Result<DnfTransactionPreview> {
        let redact = |text: &str| {
            let mut output = String::with_capacity(text.len());
            for line in text.split_inclusive('\n') {
                let (line, newline) = line
                    .strip_suffix('\n')
                    .map_or((line, ""), |line| (line, "\n"));
                output.push_str(&sanitize_terminal_diagnostic(line));
                output.push_str(newline);
            }
            output
        };
        let plan = String::from_utf8_lossy(&output.stdout);
        let diagnostics = String::from_utf8_lossy(&output.stderr);
        // DNF5 exits 1 after displaying a nonempty plan that --assumeno declined.
        if output.status.code() == Some(1)
            && !plan.trim().is_empty()
            && let Some(prefix) = diagnostics
                .trim_end()
                .strip_suffix("Operation aborted by the user.")
            && (prefix.is_empty() || prefix.ends_with('\n'))
        {
            return Ok(DnfTransactionPreview {
                plan: redact(&plan),
                diagnostics: redact(prefix.trim_end()),
                has_changes: true,
            });
        }
        if !output.status.success() && !diagnostics.trim().is_empty() {
            let diagnostics = redact(diagnostics.trim());
            anyhow::bail!("DNF query failed ({})\n{diagnostics}", output.status);
        }
        Self::require_query_success("DNF", output)?;
        Ok(DnfTransactionPreview {
            plan: redact(&plan),
            diagnostics: redact(&diagnostics),
            has_changes: false,
        })
    }

    pub(crate) async fn cleanup(
        &self,
        operation: DnfCleanup,
        history: Option<&crate::core::history::HistoryManager>,
    ) -> Result<()> {
        match operation {
            DnfCleanup::Orphans { yes } => {
                let mut arguments = vec!["autoremove".to_owned()];
                if yes {
                    arguments.push("--assumeyes".to_owned());
                } else {
                    // The CLI owns opt-in. DNF's config may skip the prompt or
                    // select yes when the user's answer is blank.
                    arguments.extend(
                        ["--setopt=assumeyes=false", "--setopt=defaultyes=false"]
                            .map(str::to_owned),
                    );
                }
                self.recorded_mutation(
                    crate::core::history::TransactionType::Remove,
                    arguments,
                    history,
                )
                .await
                .map(|_| ())
            }
            DnfCleanup::PackageCache => {
                self.execute_dnf(vec!["clean".to_owned(), "packages".to_owned()])
                    .await
            }
        }
    }

    fn run_dnf(&self, args: &[&str]) -> Result<()> {
        if args
            .iter()
            .find(|arg| !arg.starts_with('-'))
            .is_some_and(|arg| matches!(*arg, "install" | "upgrade"))
        {
            crate::core::security::policy::require_native_plan_support("DNF")?;
        }
        let mut cmd = Self::native_package_command("dnf")?;

        let targets = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
        crate::core::security::audit::record_operation("dnf", &targets, "attempt")?;
        cmd.args(args);
        let status = Self::run_native_command(cmd, args == ["clean", "packages"]);
        crate::core::security::audit::record_operation(
            "dnf",
            &targets,
            if status.as_ref().is_ok_and(std::process::ExitStatus::success) {
                "succeeded"
            } else {
                "failed"
            },
        )?;

        let status = status?;
        if status.success() {
            self.invalidate_installed_cache();
            Ok(())
        } else {
            anyhow::bail!("dnf command failed with status {status}")
        }
    }

    /// Run DNF on its blocking owner. Foreground transactions retain stdout
    /// for prompts and progress. Cache cleanup also inspects native stdout.
    pub(crate) fn run_native_command(
        mut command: std::process::Command,
        cache_cleanup: bool,
    ) -> std::io::Result<std::process::ExitStatus> {
        if cache_cleanup {
            command
                .env("LC_ALL", "C")
                .stdout(std::process::Stdio::piped());
        }
        std::thread::Builder::new()
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                runtime.block_on(Self::native_command_status(command.into(), cache_cleanup))
            })?
            .join()
            .map_err(|_| std::io::Error::other("DNF command owner panicked"))?
    }

    async fn native_command_status(
        mut command: tokio::process::Command,
        cache_cleanup: bool,
    ) -> std::io::Result<std::process::ExitStatus> {
        let mut child = command.stderr(std::process::Stdio::piped()).spawn()?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take().expect("DNF stderr is piped");
        #[cfg(unix)]
        let forward = {
            use nix::sys::signal::{SigSet, Signal};
            // Only the relay thread blocks SIGPIPE. DNF has already spawned,
            // and the thread exits without unblocking a pending write signal.
            let mut signals = SigSet::empty();
            signals.add(Signal::SIGPIPE);
            signals.thread_block().is_ok()
        };
        #[cfg(not(unix))]
        let forward = true;
        let mut removal_failed = false;
        let mut repository_failed = false;
        let (status, diagnostic_result) = {
            let diagnostics = async {
                let stdout = async {
                    if let Some(stdout) = stdout {
                        Self::forward_native_lines(stdout, std::io::stdout(), forward, |line| {
                            removal_failed |= Self::cache_cleanup_report_has_errors(line);
                        })
                        .await?;
                    }
                    Ok(())
                };
                let stderr =
                    Self::forward_native_lines(stderr, std::io::stderr(), forward, |line| {
                        repository_failed |= cache_cleanup
                            && line.starts_with("Failed to cleanup repository cache in path ");
                    });
                let (stdout, stderr) = tokio::join!(stdout, stderr);
                stdout.and(stderr)
            };
            tokio::pin!(diagnostics);
            tokio::select! {
                result = &mut diagnostics => (child.wait().await?, result),
                status = child.wait() => {
                    // Descendants can retain pipes after DNF itself has exited.
                    let result = tokio::time::timeout(
                        std::time::Duration::from_secs(1),
                        &mut diagnostics,
                    ).await.unwrap_or_else(|_| Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "Timed out reading DNF diagnostics",
                    )));
                    (status?, result)
                }
            }
        };
        if cache_cleanup && status.success() {
            if removal_failed || repository_failed {
                return Err(std::io::Error::other(
                    "DNF reported package cache cleanup errors",
                ));
            }
            diagnostic_result?;
        } else if let Err(error) = diagnostic_result {
            tracing::debug!(%error, "Could not forward DNF diagnostics");
        }
        Ok(status)
    }

    fn cache_cleanup_report_has_errors(line: &str) -> bool {
        // DNF5 can exit zero even after reporting failed cache deletions.
        line.strip_prefix("Removed ")
            .and_then(|line| line.rsplit_once("). "))
            .and_then(|(_, report)| report.strip_suffix(" errors occurred."))
            .and_then(|count| count.parse::<u64>().ok())
            .is_some_and(|count| count != 0)
    }

    async fn read_native_lines(
        input: impl tokio::io::AsyncRead + Unpin,
        mut inspect_line: impl FnMut(&[u8]),
    ) -> std::io::Result<()> {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

        let mut reader = BufReader::new(input);
        let mut line = Vec::new();
        let mut discarding_line = false;
        loop {
            line.clear();
            let count = (&mut reader)
                .take(Self::MAX_NATIVE_LINE_BYTES as u64 + 1)
                .read_until(b'\n', &mut line)
                .await?;
            if count == 0 {
                break;
            }
            if discarding_line || count > Self::MAX_NATIVE_LINE_BYTES {
                discarding_line = !line.ends_with(b"\n");
                continue;
            }
            inspect_line(&line);
        }
        Ok(())
    }

    async fn forward_native_lines(
        input: impl tokio::io::AsyncRead + Unpin,
        mut terminal: impl std::io::Write,
        mut forward: bool,
        mut inspect_line: impl FnMut(&str),
    ) -> std::io::Result<()> {
        Self::read_native_lines(input, |line| {
            let raw = String::from_utf8_lossy(line);
            let raw = raw.trim_end_matches(['\r', '\n']);
            inspect_line(raw);
            if forward {
                let mut safe = sanitize_terminal_diagnostic(raw);
                safe.push('\n');
                // Continue inspecting after a log reader closes its pipe.
                forward = terminal.write_all(safe.as_bytes()).is_ok();
            }
        })
        .await?;
        if forward && let Err(error) = terminal.flush() {
            tracing::debug!(%error, "Could not flush DNF diagnostics to terminal");
        }
        Ok(())
    }
}

impl PackageManager for DnfPackageManager {
    fn installed_catalog_observation(
        &self,
    ) -> Result<Option<Arc<dyn super::InstalledCatalogObservation>>> {
        let path = self
            .rpm_database
            .sqlite_path()?
            .context("RPM catalog observation requires a SQLite database")?;
        let database = RpmDatabaseObservation::read(&path)
            .context("Cannot observe RPM SQLite inventory for daemon catalog")?;
        Ok(Some(Arc::new(RpmInstalledCatalogObservation {
            source: self.rpm_database.clone(),
            path,
            database,
        })))
    }

    fn observed_package_index(
        &self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Option<super::traits::ObservedPackageIndex>>> + Send + '_>,
    > {
        use super::InstalledCatalogObservation as _;
        Box::pin(async move {
            for _ in 0..3 {
                let (paths, config) =
                    tokio::task::spawn_blocking(Self::search_repository_paths).await??;
                let repos = Self::search_repository_metadata(false).await?;
                let admitted: Vec<_> = repos
                    .iter()
                    .filter(|repo| repo.available_pkgs != 0)
                    .collect();
                if !admitted.is_empty() && !paths.cache_only {
                    // Cache-only repo info can touch metadata. Verify its revision
                    // before observing the read-only index query.
                    let cached = Self::search_repository_metadata(true).await?;
                    if admitted.iter().any(|repo| !cached.contains(repo)) {
                        continue;
                    }
                }
                let refresh_at = if paths.cache_only {
                    None
                } else {
                    catalog::RepositoryMetadata::refresh_at(&repos)?
                };
                let owner = self.cache_handle();
                let observation = tokio::task::spawn_blocking(move || {
                    if config != paths.configuration_stamps()? {
                        return Ok::<_, anyhow::Error>(None);
                    }
                    let rpm = owner
                        .installed_catalog_observation()?
                        .context("Cannot observe the installed RPM search catalog")?;
                    let observation = catalog::PackageCatalog::new(rpm, paths, refresh_at)?;
                    Ok((observation.configuration_matches(&config)?).then_some(observation))
                })
                .await??;
                let Some(observation) = observation else {
                    continue;
                };
                let (installed, available) = tokio::try_join!(
                    self.load_installed_packages(),
                    Self::search_cached_repositories(&admitted),
                )?;
                let installed = Self::order_installed_search_builds(&installed).await?;
                let packages = Self::search_candidates(installed, available);
                let observation = tokio::task::spawn_blocking(move || {
                    observation
                        .is_current()
                        .map(|current| current.then_some(observation))
                })
                .await??;
                if let Some(observation) = observation {
                    return Ok(Some((
                        packages,
                        Arc::new(observation) as Arc<dyn super::InstalledCatalogObservation>,
                    )));
                }
            }
            anyhow::bail!(
                "Package catalog inputs changed during three package index rebuild attempts"
            )
        })
    }
    fn security_inventory(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<super::types::SecurityPackage>>> + Send + '_>> {
        Box::pin(async {
            let mut command: tokio::process::Command = Self::native_package_command("dnf")?.into();
            // Query every installed version and architecture, even excluded
            // packages. Installed inventory needs no repository metadata.
            command.args([
                "--cacheonly",
                "--setopt=disable_excludes=*",
                "repoquery",
                "--installed",
                "--queryformat",
                "%{name}\t%{arch}\t%{epoch}:%{version}-%{release}\t%{repoid}\\n",
            ]);
            let output = Self::query_output(command).await?;
            Ok(Self::parse_versioned_packages(&output)?
                .into_iter()
                .map(|package| super::types::SecurityPackage {
                    origin: crate::package_managers::types::SecurityOrigin::DistributionPackage,
                    name: package.name,
                    version: package.version,
                    advisory_source: None,
                    architecture: Some(package.architecture),
                    description: String::new(),
                    licenses: Vec::new(),
                })
                .collect())
        })
    }

    fn sbom_inventory(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<super::types::SbomPackage>>> + Send + '_>> {
        Box::pin(async {
            let mut command = Self::rpm_query_command()?;
            command.args(["-qa", "--qf", Self::RPM_SBOM_QUERY_FORMAT]);
            let output = Self::controlled_query_output(
                "RPM",
                command,
                std::time::Duration::from_mins(1),
                None,
            )
            .await?;
            Self::parse_rpm_sbom_inventory(&output)
        })
    }

    fn security_audit(
        &self,
    ) -> Option<
        Pin<
            Box<
                dyn Future<Output = Result<crate::core::security::scan::SecurityAuditResult>>
                    + Send
                    + '_,
            >,
        >,
    > {
        Some(Box::pin(async move {
            async {
                let installed = self.security_inventory().await?;
                let (rows, supplemental) =
                    Self::native_advisories(AdvisoryLookup::ArchitectureChanges).await?;
                let affected = Self::affected_installed_packages(
                    rows.iter().map(|(row, _)| row),
                    &installed,
                    InstalledAdvisoryMatch::Exact,
                )
                .await?;
                let possible = Self::affected_installed_packages(
                    supplemental.iter().map(|(row, _)| row),
                    &installed,
                    InstalledAdvisoryMatch::ArchitectureChange,
                )
                .await
                .unwrap_or_else(|error| {
                    tracing::warn!("Could not associate supplemental Fedora advisories: {error:#}");
                    BTreeMap::new()
                });
                let mut after = self.security_inventory().await?;
                let mut before = installed;
                let cmp_identity =
                    |a: &super::types::SecurityPackage, b: &super::types::SecurityPackage| {
                        (&a.name, &a.version, &a.architecture).cmp(&(
                            &b.name,
                            &b.version,
                            &b.architecture,
                        ))
                    };
                before.sort_by(cmp_identity);
                after.sort_by(cmp_identity);
                anyhow::ensure!(
                    before == after,
                    "Installed packages changed during native security audit"
                );
                let mut result = super::dnf_advisory::audit_result(rows)?;
                result.coverage = super::dnf_advisory::installed_coverage(&before, &affected);
                for (_, findings) in &mut result.vulnerabilities {
                    for finding in findings {
                        let native = finding
                            .native_advisory
                            .as_ref()
                            .context("Native advisory evidence missing")?;
                        finding.affected_installed = affected
                            .get(&native.advisory_nevra)
                            .context("Installed advisory identity missing")?
                            .clone();
                    }
                }
                super::dnf_advisory::add_architecture_findings(
                    &mut result,
                    supplemental,
                    &possible,
                )?;
                Ok(result)
            }
            .await
            .context("Failed to query native security advisories")
        }))
    }

    fn name(&self) -> &'static str {
        "dnf"
    }

    fn transact_with_history<'a>(
        &'a self,
        kind: crate::core::history::TransactionType,
        packages: &'a [String],
        history: Option<&'a crate::core::history::HistoryManager>,
    ) -> Option<Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>> {
        use crate::core::history::TransactionType;
        let action = match kind {
            TransactionType::Install => "install",
            TransactionType::Remove => "remove",
            TransactionType::Update => "upgrade",
            TransactionType::Sync => return None,
        };
        Some(Box::pin(async move {
            anyhow::ensure!(
                kind != TransactionType::Update || packages.is_empty(),
                "System updates do not accept package operands"
            );
            if kind == TransactionType::Install {
                Self::validate_install_selectors(packages)?;
            } else {
                Self::validate_package_selectors(packages)?;
            }
            let mut args = vec![action.to_owned(), "-y".to_owned()];
            args.extend_from_slice(packages);
            self.recorded_mutation(kind, args, history)
                .await
                .map(|_| ())
        }))
    }

    fn transact_cached_update_with_history<'a>(
        &'a self,
        history: Option<&'a crate::core::history::HistoryManager>,
    ) -> Option<Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>> {
        Some(Box::pin(async move {
            self.update_with_history(true, history).await.map(|_| ())
        }))
    }

    fn search(
        &self,
        query: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Package>>> + Send + '_>> {
        self.search_with_progress(query, true)
    }

    fn search_quietly(
        &self,
        query: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Package>>> + Send + '_>> {
        self.search_with_progress(query, false)
    }

    fn package_index(&self) -> Pin<Box<dyn Future<Output = Result<Vec<Package>>> + Send + '_>> {
        Box::pin(async move {
            let installed = self.load_installed_packages().await?;
            let (installed, available) = tokio::try_join!(
                Self::order_installed_search_builds(&installed),
                Self::available_packages()
            )?;
            Ok(Self::search_candidates(installed, available))
        })
    }

    fn install(
        &self,
        packages: &[String],
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let packages = packages.to_vec();
        Box::pin(async move {
            Self::validate_install_selectors(&packages)?;

            let mut args = vec!["install".to_owned(), "-y".to_owned()];
            args.extend(packages);
            self.execute_dnf(args).await
        })
    }

    fn remove(&self, packages: &[String]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let packages = packages.to_vec();
        Box::pin(async move {
            Self::validate_package_selectors(&packages)?;

            let mut args = vec!["remove".to_owned(), "-y".to_owned()];
            args.extend(packages);
            self.execute_dnf(args).await
        })
    }

    fn removal_plan<'a>(
        &'a self,
        packages: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<super::types::RemovalPackage>>> + Send + 'a>> {
        Box::pin(Self::simulate_removal(packages))
    }

    fn update(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(self.execute_dnf(vec!["upgrade".to_owned(), "-y".to_owned()]))
    }

    fn sync(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            // Force fresh repository metadata in the caller's cache before
            // list_updates() reads it with --cacheonly. A root-only refresh
            // leaves an unprivileged caller's existing cache stale.
            self.invalidate_installed_cache();

            tokio::task::spawn_blocking({
                let manager = self.cache_handle();
                move || manager.run_dnf(&REPOSITORY_REFRESH_ARGS)
            })
            .await??;

            if !is_root() {
                crate::core::privilege::run_privileged_program("dnf", &REPOSITORY_REFRESH_ARGS)
                    .await?;
            }
            Ok(())
        })
    }

    fn info(
        &self,
        package: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Package>>> + Send + '_>> {
        let package = package.to_string();
        Box::pin(async move {
            Self::validate_query_selector(&package)?;
            let manager = self.cache_handle();
            let selector = package.clone();
            let matches =
                tokio::task::spawn_blocking(move || manager.matching_installed_packages(&selector))
                    .await??;
            if let Some(pkg) =
                Self::select_installed_build(&package, matches, InstalledPackage::full_nevra)?
            {
                return Ok(Some(Package {
                    name: pkg.identity(),
                    version: parse_version_or_zero(&format!("{}-{}", pkg.version, pkg.release)),
                    description: pkg.summary,
                    source: PackageSource::Official,
                    installed: true,
                }));
            }

            Self::available_info(&package).await
        })
    }

    fn list_installed(&self) -> Pin<Box<dyn Future<Output = Result<Vec<Package>>> + Send + '_>> {
        Box::pin(async move {
            let installed = self.load_installed_packages().await?;

            Ok(installed.iter().map(InstalledPackage::as_package).collect())
        })
    }

    fn get_status(
        &self,
        fast: bool,
    ) -> Pin<Box<dyn Future<Output = Result<(usize, usize, usize, usize)>> + Send + '_>> {
        Box::pin(async move {
            self.get_status_details(fast)
                .await
                .map(PackageStatus::into_counts)
        })
    }

    fn get_status_details(
        &self,
        fast: bool,
    ) -> Pin<Box<dyn Future<Output = Result<PackageStatus>> + Send + '_>> {
        Box::pin(async move {
            let installed = self.load_installed_packages().await?;
            let total = installed.len();
            let reasons = Self::current_explicit_package_names(&installed);
            let (explicit, maintenance) = if fast {
                (reasons.await?, None)
            } else {
                let (explicit, orphans, updates) =
                    tokio::try_join!(reasons, Self::orphan_count(), self.list_updates())?;
                (explicit, Some((orphans, updates.len())))
            };

            Ok(PackageStatus {
                total,
                explicit: explicit.len(),
                maintenance,
            })
        })
    }

    fn list_explicit(&self) -> Pin<Box<dyn Future<Output = Result<Vec<String>>> + Send + '_>> {
        Box::pin(async {
            let mut names: Vec<_> = Self::read_user_installed_names()
                .await
                .context("Could not load DNF install reasons")?
                .into_iter()
                .collect();
            names.sort_unstable();
            Ok(names)
        })
    }

    fn list_updates(&self) -> Pin<Box<dyn Future<Output = Result<Vec<UpdateInfo>>> + Send + '_>> {
        Box::pin(async move {
            let mut command: tokio::process::Command = Self::native_package_command("dnf")?.into();
            // list honors repository priority. JSON for list requires DNF5 5.4.
            command.env("LC_ALL", "C").args(UPGRADE_QUERY_ARGS);
            let (installed, upgrades) = tokio::try_join!(
                Self::repository_output(RepositoryQuery::Installed),
                Self::query_output(command)
            )?;
            Self::match_updates(
                &Self::parse_versioned_packages(&installed)?,
                &Self::parse_package_listing(&upgrades, "Available upgrades")?,
            )
            .await
        })
    }

    fn is_installed(
        &self,
        package: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + '_>> {
        let package = package.to_string();
        let manager = self.cache_handle();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || manager.is_installed_fast(&package)).await?
        })
    }
}

/// DNF accepts local RPM filenames as install operands. OMG does not yet seal
/// RPM inputs across sudo re-exec the way it does Arch and Debian archives, so
/// accepting one here would bypass the local-archive consent and immutable
/// handoff boundary.
fn reject_unsealed_local_rpm_targets(packages: &[String]) -> Result<()> {
    for package in packages {
        let is_rpm = package
            .rsplit_once('.')
            .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("rpm"));
        anyhow::ensure!(
            !is_rpm && !package.contains('/') && !package.contains('\\'),
            "Local RPM installation is not supported securely yet: '{package}'. Install repository packages by name; local RPM support requires a sealed archive handoff"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;

