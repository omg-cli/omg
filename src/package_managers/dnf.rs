//! DNF/Fedora package manager backend
//!
//! Reads installed packages directly from the RPM `SQLite` database for
//! fast queries without CLI overhead.
//!
//! ## Architecture
//! 1. Read installed packages from `/var/lib/rpm/rpmdb.sqlite`
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
use crate::core::{Package, PackageSource, is_root};
use crate::package_managers::PackageManager;
use crate::package_managers::types::{PackageStatus, UpdateInfo, parse_version_or_zero};

use rusqlite::{Connection, OpenFlags};
use zerocopy::{FromBytes, Immutable, KnownLayout, big_endian::U32};

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
    /// Path to RPM `SQLite` database
    rpm_db_path: PathBuf,
    /// Path to yum repository configuration (used by the `dnf` CLI)
    repos_dir: PathBuf,
    /// Complete RPM inventory bound to database/WAL identity and SQLite commits.
    /// Install reasons belong to DNF's separate state and are queried on demand.
    installed_cache: Arc<RwLock<Option<InstalledSnapshot>>>,
}

#[derive(Debug)]
struct InstalledSnapshot {
    observation: RpmDatabaseObservation,
    packages: Arc<Vec<InstalledPackage>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RpmFileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl RpmFileIdentity {
    fn read(path: &Path) -> std::io::Result<Option<Self>> {
        use std::os::unix::fs::MetadataExt;

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
        Ok(Some(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RpmDatabaseIdentity {
    database: RpmFileIdentity,
    wal: Option<RpmFileIdentity>,
}

impl RpmDatabaseIdentity {
    fn read(path: &Path) -> Option<Self> {
        let database = RpmFileIdentity::read(path).ok()??;
        let mut wal_path = path.as_os_str().to_os_string();
        wal_path.push("-wal");
        // An absent WAL is valid; an unreadable one must not validate a hit.
        let wal = RpmFileIdentity::read(Path::new(&wal_path)).ok()?;
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
    path: PathBuf,
    database: RpmDatabaseObservation,
}

impl super::InstalledCatalogObservation for RpmInstalledCatalogObservation {
    fn is_current(&self) -> Result<bool> {
        Ok(self.database.is_current(&self.path))
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

    fn matches_selector(&self, selector: &str) -> bool {
        self.name == selector
            || self.identity() == selector
            || self.nevra() == selector
            || (!self.version.contains(':')
                && format!(
                    "{}-0:{}-{}.{}",
                    self.name, self.version, self.release, self.architecture
                ) == selector)
    }

    fn as_package(&self) -> Package {
        Package {
            name: self.identity(),
            version: parse_version_or_zero(&format!("{}-{}", self.version, self.release)),
            description: self.summary.clone(),
            source: PackageSource::Official,
            installed: true,
        }
    }
}

struct AvailablePackage<'a> {
    name: &'a str,
    version: &'a str,
    summary: &'a str,
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

const UPGRADE_QUERY_ARGS: [&str; 6] = [
    "--quiet",
    "--color=never",
    "--cacheonly",
    "--setopt=*.skip_if_unavailable=false",
    "list",
    "--upgrades",
];

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
    InstallOrUpgrade,
    Remove {
        packages: &'a [String],
        comment: Option<&'a str>,
        yes: bool,
        dry_run: bool,
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
        let mut results = Vec::with_capacity(pairs.len());
        for chunk in pairs.chunks(128) {
            let mut input = String::new();
            for (left, right) in chunk {
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
            }
            anyhow::ensure!(
                input.len() <= 64 * 1024,
                "Native RPM comparison input exceeds limit"
            );
            let mut command =
                tokio::process::Command::from(crate::core::privilege::system_command("rpm")?);
            command.env("OMG_EVR_PAIRS", input).args(["--eval", r#"%{lua:local left=nil; for value in string.gmatch(os.getenv("OMG_EVR_PAIRS"), "[^\n]+") do if left then print(string.format("%d\n",rpm.vercmp(left,value))); left=nil else left=value end end; if left then error("incomplete comparison") end}"#]);
            let output = Self::query_output(command).await?;
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
                compared.len() == chunk.len(),
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
        Ok(Self::prepare_removal(packages).await?.packages)
    }

    pub(crate) async fn prepare_removal(packages: &[String]) -> Result<PreparedDnfRemoval> {
        Self::validate_package_selectors(packages)?;
        let directory = Self::removal_preview_directory()?;
        let mut command =
            tokio::process::Command::from(crate::core::privilege::system_command("dnf")?);
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
        let (directory, bytes) =
            Self::owned_stored_transaction(command, directory, std::time::Duration::from_mins(1))
                .await
                .context("Could not simulate removal with DNF5 --store")?;
        let packages = Self::parse_removal_plan(&bytes)?;
        Ok(PreparedDnfRemoval {
            directory,
            packages,
        })
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
    }

    async fn replay_removal_plan(
        &self,
        plan: PreparedDnfRemoval,
        comment: Option<String>,
    ) -> Result<()> {
        // Replay normally loads available repositories. Removal uses only
        // installed packages, and DNF rejects a disable glob with no matches.
        let mut command =
            tokio::process::Command::from(crate::core::privilege::system_command("dnf")?);
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

    pub(crate) async fn remove_with_elevation(
        packages: &[String],
        yes: bool,
        dry_run: bool,
    ) -> Result<()> {
        let mode = if dry_run {
            "--dry-run"
        } else if yes {
            "-y"
        } else {
            "--confirm"
        };
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
        if dry_run {
            return operation(None).await;
        }
        let history = crate::core::history::HistoryManager::new()?;
        Self::record_native_mutation(
            crate::core::history::TransactionType::Remove,
            Some(&history),
            operation,
        )
        .await
    }
    fn cached_update_args() -> Vec<String> {
        ["--setopt=cacheonly=metadata", "upgrade", "-y"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    #[must_use]
    pub fn new() -> Self {
        Self {
            rpm_db_path: PathBuf::from("/var/lib/rpm/rpmdb.sqlite"),
            repos_dir: PathBuf::from("/etc/yum.repos.d"),
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

    fn cached_installed_packages(&self) -> Option<Arc<Vec<InstalledPackage>>> {
        self.cache_read()
            .as_ref()
            .filter(|snapshot| snapshot.observation.is_current(&self.rpm_db_path))
            .map(|snapshot| Arc::clone(&snapshot.packages))
    }

    fn publish_installed_packages(
        &self,
        packages: Arc<Vec<InstalledPackage>>,
        observed_identity: Option<RpmDatabaseObservation>,
    ) {
        // Never label an old read with a newer generation, or cache a CLI
        // fallback whose actual database was not observed. Empty inventories
        // are valid snapshots too.
        let snapshot = observed_identity
            .filter(|observation| observation.is_current(&self.rpm_db_path))
            .map(|observation| InstalledSnapshot {
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
        Ok(self.load_installed_packages_blocking()?.len())
    }

    /// Load installed packages from RPM `SQLite` database
    ///
    /// Reads directly from `/var/lib/rpm/rpmdb.sqlite` and parses RPM header blobs
    /// to extract package metadata. Caches results in memory for subsequent calls.
    async fn load_installed_packages(&self) -> Result<Arc<Vec<InstalledPackage>>> {
        let manager = self.cache_handle();
        tokio::task::spawn_blocking(move || manager.load_installed_packages_blocking()).await?
    }

    fn load_installed_packages_blocking(&self) -> Result<Arc<Vec<InstalledPackage>>> {
        if let Some(cached) = self.cached_installed_packages() {
            return Ok(cached);
        }
        let (packages, identity) = Self::read_rpm_database(&self.rpm_db_path)?;
        let packages = Arc::new(packages);
        self.publish_installed_packages(Arc::clone(&packages), identity);
        Ok(packages)
    }

    pub(crate) fn is_installed_fast(&self, package: &str) -> Result<bool> {
        Ok(!self.matching_installed_packages(package)?.is_empty())
    }

    fn matching_installed_packages(&self, selector: &str) -> Result<Vec<InstalledPackage>> {
        match Self::read_rpm_name_index(&self.rpm_db_path, selector) {
            Ok(packages) if !packages.is_empty() => return Ok(packages),
            Ok(_) => {}
            Err(error) => tracing::debug!("RPM name lookup unavailable: {error:#}"),
        }
        Ok(self
            .load_installed_packages_blocking()?
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
        let mut command = tokio::process::Command::from(Self::user_installed_command()?);
        command.stderr(std::process::Stdio::piped());
        let user_installed = Self::query_output(command)
            .await
            .and_then(|output| Self::parse_user_installed_names(&output));
        Self::explicit_package_names(packages, user_installed)
    }

    /// Read RPM database, trying `SQLite` first then falling back to subprocess
    #[cfg(feature = "fedora")]
    fn read_rpm_database(
        db_path: &Path,
    ) -> Result<(Vec<InstalledPackage>, Option<RpmDatabaseObservation>)> {
        // Try SQLite first (Fedora 33+, RHEL 9+) - 50-100x faster
        if db_path.exists() {
            let identity = RpmDatabaseObservation::read(db_path);
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
        let output = crate::core::privilege::system_command("rpm")?
            .args([
                "-qa",
                "--queryformat",
                "%{NAME}\t%{VERSION}\t%{RELEASE}\t%{SUMMARY}\t%{EPOCHNUM}\t%{ARCH}\n",
            ])
            .output()
            .context("Failed to execute rpm -qa")?;

        if !output.status.success() {
            anyhow::bail!("rpm command failed: {}", output.status);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::with_capacity(2048);

        for line in stdout.lines() {
            if line.is_empty() {
                continue;
            }
            packages.push(Self::parse_rpm_qa_line(line)?);
        }

        Ok(packages)
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

    fn user_installed_command() -> Result<std::process::Command> {
        // --userinstalled reads the system repo only. An unmatched repo glob
        // would reject a valid local inventory on a host with no configured repos.
        let mut command = crate::core::privilege::system_command("dnf")?;
        command.args([
            "--cacheonly",
            "--setopt=disable_excludes=*",
            "repoquery",
            "--userinstalled",
            "--qf",
            Self::USER_INSTALLED_QUERY_FORMAT,
        ]);
        Ok(command)
    }

    pub(crate) fn read_user_installed_names() -> Result<HashSet<String>> {
        let output = Self::user_installed_command()?
            .output()
            .context("Failed to execute dnf repoquery --userinstalled")?;
        if !output.status.success() {
            let stderr =
                crate::cli::style::sanitize_terminal_text(&String::from_utf8_lossy(&output.stderr));
            anyhow::bail!("dnf repoquery --userinstalled failed: {}", stderr.trim());
        }
        Self::parse_user_installed_names(&output.stdout)
    }

    fn parse_rpm_qa_line(line: &str) -> Result<InstalledPackage> {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 6 {
            anyhow::bail!(
                "malformed rpm -qa output: expected 6 fields, got {}",
                fields.len()
            );
        }

        let epoch: u32 = fields[4].parse().context("Malformed RPM epoch")?;
        let missing = |value: &str| value.is_empty() || value == "(none)";
        anyhow::ensure!(
            ![fields[0], fields[1], fields[2]].into_iter().any(missing),
            "Incomplete package identity in rpm -qa output"
        );
        let architecture = if missing(fields[5]) {
            anyhow::ensure!(fields[0] == "gpg-pubkey", "RPM architecture is missing");
            String::new()
        } else {
            fields[5].to_owned()
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
            summary: fields[3].to_string(),
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
    /// Opens `/var/lib/rpm/rpmdb.sqlite` in read-only mode and parses
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

    async fn available_packages(package: Option<&str>) -> Result<Vec<Package>> {
        let bytes = Self::repository_output(RepositoryQuery::Available(package)).await?;
        Self::parse_available_packages(&bytes)
    }

    fn select_available_info(
        selector: &str,
        mut candidates: Vec<Package>,
    ) -> Result<Option<Package>> {
        let preferred = |package: &Package| {
            package
                .name
                .rsplit_once('.')
                .is_some_and(|(_, arch)| arch == std::env::consts::ARCH || arch == "noarch")
        };
        // DNF resolves an architecture-qualified selector before returning rows.
        // Bare names can include several architectures for the same package.
        if candidates.iter().any(preferred) {
            candidates.retain(preferred);
        }
        anyhow::ensure!(
            candidates.len() <= 1,
            "Package '{selector}' has multiple available builds; specify the full NEVRA"
        );
        Ok(candidates.pop())
    }

    fn search_candidates(installed: &[InstalledPackage], available: Vec<Package>) -> Vec<Package> {
        let mut candidates: Vec<_> = installed.iter().map(InstalledPackage::as_package).collect();
        candidates.extend(available);
        candidates
    }

    fn search_results(
        installed: &[InstalledPackage],
        output: &[u8],
        query_lower: &str,
    ) -> Result<Vec<Package>> {
        let available = Self::available_rows(output)?.collect::<Result<Vec<_>>>()?;
        let installed: Vec<_> = installed.iter().map(InstalledPackage::as_package).collect();
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
            RepositoryQuery::Available(_) => "%{name}.%{arch}\t%{evr}\t%{summary}\\n",
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
        let mut command =
            tokio::process::Command::from(crate::core::privilege::system_command("dnf")?);
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
        if matches!(
            query,
            RepositoryQuery::InstalledSizes(_)
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
        Self::controlled_query_output(command, deadline, None).await
    }

    async fn controlled_query_output(
        command: tokio::process::Command,
        deadline: std::time::Duration,
        cancelled: Option<tokio::sync::oneshot::Receiver<()>>,
    ) -> Result<Vec<u8>> {
        let output = Self::capture_query(command, deadline, cancelled).await?;
        Self::require_query_success(&output)?;
        Ok(output.stdout)
    }

    fn require_query_success(output: &std::process::Output) -> Result<()> {
        if output.status.success() {
            return Ok(());
        }
        let diagnostics = String::from_utf8_lossy(&output.stderr);
        if let Some(detail) = diagnostics
            .lines()
            .map(str::trim)
            .rfind(|line| !line.is_empty())
        {
            let detail = crate::cli::style::sanitize_terminal_text(detail);
            anyhow::bail!("DNF query failed: {}: {detail}", output.status);
        }
        anyhow::bail!("DNF query failed: {}", output.status);
    }

    async fn capture_query(
        mut command: tokio::process::Command,
        deadline: std::time::Duration,
        mut cancelled: Option<tokio::sync::oneshot::Receiver<()>>,
    ) -> Result<std::process::Output> {
        use tokio::io::AsyncReadExt;
        const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
        const MAX_DIAGNOSTIC_BYTES: u64 = 64 * 1024;
        if let Some(cancelled) = cancelled.as_mut() {
            anyhow::ensure!(
                matches!(
                    cancelled.try_recv(),
                    Err(tokio::sync::oneshot::error::TryRecvError::Empty)
                ),
                "DNF stored query cancelled before execution"
            );
        }
        let mut child = command
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("Could not start DNF query")?;
        let result = {
            let operation = async {
                let stdout = child.stdout.take().context("DNF stdout was not captured")?;
                let stderr = child.stderr.take();
                let output = async {
                    let mut bytes = Vec::new();
                    stdout
                        .take(MAX_OUTPUT_BYTES + 1)
                        .read_to_end(&mut bytes)
                        .await?;
                    anyhow::ensure!(
                        bytes.len() as u64 <= MAX_OUTPUT_BYTES,
                        "DNF query output exceeds 64 MiB"
                    );
                    Ok(bytes)
                };
                let diagnostics = async {
                    let mut bytes = Vec::new();
                    if let Some(mut stderr) = stderr {
                        (&mut stderr)
                            .take(MAX_DIAGNOSTIC_BYTES)
                            .read_to_end(&mut bytes)
                            .await?;
                        tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await?;
                    }
                    Ok(bytes)
                };
                let (stdout, stderr) = tokio::try_join!(output, diagnostics)?;
                let status = child.wait().await.context("Could not wait for DNF query")?;
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
                    Err(error) => Err(anyhow::Error::new(error).context(format!("DNF query timed out after {} seconds", deadline.as_secs()))),
                },
                () = cancellation => Err(anyhow::anyhow!("DNF stored query cancelled")),
            }
        };
        if result.is_err() {
            if let Err(error) = child.start_kill() {
                tracing::debug!(%error, "DNF query may have exited before cancellation kill");
            }
            child.wait().await.context("Could not reap DNF query")?;
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
            let mut command = Self::repository_command(RepositoryQuery::Available(None))?;
            if !progress {
                command.stderr(std::process::Stdio::piped());
            }
            let output = Self::query_output(command).await?;
            Self::search_results(&installed, &output, &query_lower)
        })
    }

    async fn owned_stored_transaction(
        command: tokio::process::Command,
        directory: tempfile::TempDir,
        deadline: std::time::Duration,
    ) -> Result<(tempfile::TempDir, Vec<u8>)> {
        let (cancel, cancelled) = tokio::sync::oneshot::channel();
        let _cancel_on_drop = CancelStoredQuery(Some(cancel));
        tokio::task::spawn_blocking(move || -> Result<_> {
            use std::io::Read;
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(Self::controlled_query_output(
                    command,
                    deadline,
                    Some(cancelled),
                ))?;
            let file = std::fs::File::open(directory.path().join("transaction.json"))
                .context("DNF5 did not store a transaction")?;
            anyhow::ensure!(
                file.metadata()?.is_file(),
                "DNF stored transaction is not a regular file"
            );
            let mut bytes = Vec::new();
            file.take(64 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
            anyhow::ensure!(
                bytes.len() <= 64 * 1024 * 1024,
                "DNF stored transaction exceeds 64 MiB"
            );
            Ok((directory, bytes))
        })
        .await
        .context("DNF stored transaction owner failed")?
    }

    fn advisory_command(cache: &Path) -> Result<tokio::process::Command> {
        let cache = cache
            .to_str()
            .context("DNF advisory cache path is not UTF-8")?;
        let mut command =
            tokio::process::Command::from(crate::core::privilege::system_command("dnf")?);
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
            "--setopt=*.skip_if_unavailable=false",
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
        let mut command =
            tokio::process::Command::from(crate::core::privilege::system_command("python3")?);
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
        let mut command =
            tokio::process::Command::from(crate::core::privilege::system_command("dnf")?);
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
        let mut command =
            tokio::process::Command::from(crate::core::privilege::system_command("dnf")?);
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
        for ((name, _architecture), changes) in grouped {
            if changes.removed.len() == 1 && changes.added.len() == 1 {
                result.push(PackageChange {
                    name: name.to_owned(),
                    old_version: changes.removed.into_iter().next(),
                    new_version: changes.added.into_iter().next(),
                    source: "dnf".to_owned(),
                });
            } else {
                result.extend(changes.removed.into_iter().map(|version| PackageChange {
                    name: name.to_owned(),
                    old_version: Some(version),
                    new_version: None,
                    source: "dnf".to_owned(),
                }));
                result.extend(changes.added.into_iter().map(|version| PackageChange {
                    name: name.to_owned(),
                    old_version: None,
                    new_version: Some(version),
                    source: "dnf".to_owned(),
                }));
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
            .is_some_and(|value| value == "--setopt=cacheonly=metadata");
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
            let (yes, dry_run) = match mode.as_str() {
                "-y" => (true, false),
                "--confirm" => (false, false),
                "--dry-run" if correlation.is_none() => (false, true),
                _ => anyhow::bail!("Unsupported DNF removal mode"),
            };
            Self::validate_package_selectors(packages)?;
            return Ok(DnfAdmission::Remove {
                packages,
                comment: correlation,
                yes,
                dry_run,
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
        Ok(DnfAdmission::InstallOrUpgrade)
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
            DnfAdmission::InstallOrUpgrade => manager.execute_reviewed_transaction(args).await,
            DnfAdmission::Remove {
                packages,
                comment,
                yes,
                dry_run,
                output,
            } => {
                crate::cli::modern_ui::configure_output(
                    u8::from(output == OutputMode::Verbose),
                    output == OutputMode::Quiet,
                );
                let Some(plan) =
                    crate::cli::packages::review_fedora_removal(packages, yes, dry_run).await?
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
        anyhow::ensure!(
            matches!(
                Self::admission_request(args)?,
                DnfAdmission::InstallOrUpgrade
            ),
            "DNF install/upgrade admission requires an install or upgrade"
        );
        crate::core::security::policy::require_native_plan_support("DNF")?;
        anyhow::ensure!(
            is_root(),
            "DNF stored transaction must be prepared by its root owner"
        );
        let directory = Self::removal_preview_directory()?;
        let mut command =
            tokio::process::Command::from(crate::core::privilege::system_command("dnf")?);
        command
            .args(args)
            .arg(format!("--store={}", directory.path().display()));
        let (directory, bytes) =
            Self::owned_stored_transaction(command, directory, std::time::Duration::from_mins(30))
                .await
                .context("Could not prepare a stored DNF5 installation transaction")?;
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
        self.replay_stored_transaction(directory, &[], comment)
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
        for (relative, (path, length)) in files {
            let encoded = serde_json::to_vec(&relative)?;
            hash.update((encoded.len() as u64).to_be_bytes());
            hash.update(encoded);
            hash.update(length.to_be_bytes());
            let mut file = std::fs::File::open(path)?;
            let mut read = 0u64;
            let mut buffer = vec![0u8; 64 * 1024];
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
    ) -> Result<()> {
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
    ) -> Result<()>
    where
        F: Future<Output = Result<()>>,
    {
        let Some(history) = history.filter(|_| !crate::core::privilege::parent_owns_history())
        else {
            return operation(None).await;
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
        Self::record_native_result(kind, history, operation, observed)
    }

    fn record_native_result(
        kind: crate::core::history::TransactionType,
        history: &crate::core::history::HistoryManager,
        operation: Result<()>,
        observed: Result<NativeOutcome>,
    ) -> Result<()> {
        let persistence = match observed {
            Ok(NativeOutcome::NoTransaction) if operation.is_ok() => Ok(()),
            Ok(NativeOutcome::NoTransaction | NativeOutcome::Failed) => history
                .add_transaction(kind, Vec::new(), false)
                .and_then(|()| {
                    anyhow::ensure!(
                        operation.is_err(),
                        "DNF reported a failed journal transaction after command success"
                    );
                    Ok(())
                }),
            Ok(NativeOutcome::Committed(changes)) => history.add_transaction(kind, changes, true),
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
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
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

    fn parse_available_upgrades(output: &[u8]) -> Result<Vec<VersionedPackage>> {
        let text = std::str::from_utf8(output).context("DNF upgrade listing is not UTF-8")?;
        let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
        let Some(header) = lines.next() else {
            return Ok(Vec::new());
        };
        anyhow::ensure!(
            header == "Available upgrades",
            "Invalid DNF upgrade heading"
        );
        lines
            .map(|line| {
                let fields: Vec<_> = line.split_ascii_whitespace().take(4).collect();
                let &[name_arch, version, repository] = fields.as_slice() else {
                    anyhow::bail!("DNF upgrade row must have three fields");
                };
                let (name, architecture) = name_arch
                    .rsplit_once('.')
                    .context("DNF upgrade row lacks architecture")?;
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
            rpm_db_path: self.rpm_db_path.clone(),
            repos_dir: self.repos_dir.clone(),
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

    pub(crate) async fn preview_orphan_cleanup() -> Result<(String, String)> {
        let mut command =
            tokio::process::Command::from(crate::core::privilege::system_command("dnf")?);
        command
            .env("LC_ALL", "C")
            .stderr(std::process::Stdio::piped())
            .args([
                "--cacheonly",
                "--color=never",
                "--setopt=assumeyes=false",
                "--assumeno",
                "autoremove",
            ]);
        let output = Self::capture_query(command, std::time::Duration::from_mins(1), None).await?;
        Self::orphan_cleanup_preview_output(&output)
    }

    fn orphan_cleanup_preview_output(output: &std::process::Output) -> Result<(String, String)> {
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
            return Ok((plan.into_owned(), prefix.trim_end().to_owned()));
        }
        Self::require_query_success(output)?;
        Ok((plan.into_owned(), diagnostics.into_owned()))
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
                }
                self.recorded_mutation(
                    crate::core::history::TransactionType::Remove,
                    arguments,
                    history,
                )
                .await
            }
            DnfCleanup::PackageCache => {
                self.execute_dnf(vec!["clean".to_owned(), "packages".to_owned()])
                    .await
            }
        }
    }

    fn run_dnf(&self, args: &[&str]) -> Result<()> {
        if args
            .first()
            .is_some_and(|arg| matches!(*arg, "install" | "upgrade"))
        {
            crate::core::security::policy::require_native_plan_support("DNF")?;
        }
        let mut cmd = crate::core::privilege::system_command("dnf")?;

        let targets = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
        crate::core::security::audit::record_operation("dnf", &targets, "attempt")?;
        let status = cmd.args(args).status()?;
        crate::core::security::audit::record_operation(
            "dnf",
            &targets,
            if status.success() {
                "succeeded"
            } else {
                "failed"
            },
        )?;

        if status.success() {
            self.invalidate_installed_cache();
            Ok(())
        } else {
            anyhow::bail!("dnf command failed with status {status}")
        }
    }
}

impl PackageManager for DnfPackageManager {
    fn installed_catalog_observation(
        &self,
    ) -> Result<Option<Arc<dyn super::InstalledCatalogObservation>>> {
        let database = RpmDatabaseObservation::read(&self.rpm_db_path)
            .context("Cannot observe RPM SQLite inventory for daemon catalog")?;
        Ok(Some(Arc::new(RpmInstalledCatalogObservation {
            path: self.rpm_db_path.clone(),
            database,
        })))
    }
    fn security_inventory(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<super::types::SecurityPackage>>> + Send + '_>> {
        Box::pin(async {
            let mut command =
                tokio::process::Command::from(crate::core::privilege::system_command("dnf")?);
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
                let identity = |package: &super::types::SecurityPackage| {
                    (
                        package.name.clone(),
                        package.version.clone(),
                        package.architecture.clone(),
                    )
                };
                before.sort_by_key(identity);
                after.sort_by_key(identity);
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
            self.recorded_mutation(kind, args, history).await
        }))
    }

    fn transact_cached_update_with_history<'a>(
        &'a self,
        history: Option<&'a crate::core::history::HistoryManager>,
    ) -> Option<Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>> {
        Some(Box::pin(async move {
            self.recorded_mutation(
                crate::core::history::TransactionType::Update,
                Self::cached_update_args(),
                history,
            )
            .await
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
            let available = Self::available_packages(None).await?;
            Ok(Self::search_candidates(&installed, available))
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
                move || manager.run_dnf(&["--refresh", "makecache", "-y"])
            })
            .await??;

            if !is_root() {
                crate::core::privilege::run_privileged_program(
                    "dnf",
                    &["--refresh", "makecache", "-y"],
                )
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
            let mut matches =
                tokio::task::spawn_blocking(move || manager.matching_installed_packages(&selector))
                    .await??;
            anyhow::ensure!(
                matches.len() <= 1,
                "Package '{package}' has multiple installed builds; specify the full NEVRA"
            );
            if let Some(pkg) = matches.pop() {
                return Ok(Some(Package {
                    name: pkg.identity(),
                    version: parse_version_or_zero(&format!("{}-{}", pkg.version, pkg.release)),
                    description: pkg.summary,
                    source: PackageSource::Official,
                    installed: true,
                }));
            }

            let available = Self::available_packages(Some(&package)).await?;
            Self::select_available_info(&package, available)
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
            let explicit = Self::current_explicit_package_names(&installed)
                .await?
                .len();

            let maintenance = if fast {
                None
            } else {
                Some((
                    Self::orphan_count().await?,
                    self.list_updates().await?.len(),
                ))
            };

            Ok(PackageStatus {
                total,
                explicit,
                maintenance,
            })
        })
    }

    fn list_explicit(&self) -> Pin<Box<dyn Future<Output = Result<Vec<String>>> + Send + '_>> {
        Box::pin(async move {
            let installed = self.load_installed_packages().await?;
            Self::current_explicit_package_names(&installed).await
        })
    }

    fn list_updates(&self) -> Pin<Box<dyn Future<Output = Result<Vec<UpdateInfo>>> + Send + '_>> {
        Box::pin(async move {
            let installed = Self::repository_output(RepositoryQuery::Installed).await?;
            let mut command =
                tokio::process::Command::from(crate::core::privilege::system_command("dnf")?);
            // list honors repository priority. JSON for list requires DNF5 5.4.
            command.env("LC_ALL", "C").args(UPGRADE_QUERY_ARGS);
            let upgrades = Self::query_output(command).await?;
            Self::match_updates(
                &Self::parse_versioned_packages(&installed)?,
                &Self::parse_available_upgrades(&upgrades)?,
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
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires Fedora DNF5 with the installed leaf fixture tree; stores a plan only"]
    async fn native_removal_simulation_preserves_installed_inventory() -> Result<()> {
        let manager = DnfPackageManager::new();
        anyhow::ensure!(
            manager.is_installed("tree").await?,
            "installed tree fixture required"
        );
        let before = manager.security_inventory().await?;
        let plan = manager.removal_plan(&["tree".into()]).await?;
        let tree = plan
            .iter()
            .find(|package| package.name == "tree.x86_64")
            .context("tree missing from the native removal plan")?;
        let exact = format!("tree-{}.x86_64", tree.version);
        assert_eq!(manager.removal_plan(&[exact]).await?, plan);
        assert_eq!(manager.security_inventory().await?, before);
        Ok(())
    }

    #[test]
    #[serial_test::serial]
    fn removal_preview_directory_ignores_caller_tmpdir() -> Result<()> {
        if crate::core::testing::run_isolated_test(
            "package_managers::dnf::tests::removal_preview_directory_ignores_caller_tmpdir",
        ) {
            return Ok(());
        }
        let caller = tempfile::tempdir()?;
        temp_env::with_var("TMPDIR", Some(caller.path()), || -> Result<()> {
            let directory = DnfPackageManager::removal_preview_directory()?;
            assert_eq!(directory.path().parent(), Some(Path::new("/var/tmp")));
            Ok(())
        })
    }

    #[test]
    #[cfg(unix)]
    fn removal_preview_directory_is_private_and_removed_after_use() -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let directory = DnfPackageManager::removal_preview_directory()?;
        let path = directory.path().to_owned();
        let metadata = path.metadata()?;
        assert!(metadata.is_dir());
        assert_eq!(metadata.mode() & 0o777, 0o700);
        assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
        std::fs::write(path.join("transaction.json"), b"private fixture")?;
        drop(directory);
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn removal_preview_parent_rejects_replaceable_ancestors_and_symlink_targets() -> Result<()> {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let directory = tempfile::Builder::new()
            .prefix("omg-dnf-parent-fixture-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(if is_root() { "/var" } else { "/var/tmp" })?;
        let parent = directory.path().join("parent");
        std::fs::create_dir(&parent)?;
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777))?;
        assert!(DnfPackageManager::trusted_removal_preview_parent(&parent).is_err());
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o1777))?;
        assert_eq!(
            DnfPackageManager::trusted_removal_preview_parent(&parent).is_ok(),
            is_root()
        );
        let child = parent.join("private");
        std::fs::create_dir(&child)?;
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700))?;
        // A sticky writable directory is safe only as the final allocation
        // parent, not as an ancestor of a path another user could replace.
        assert!(DnfPackageManager::trusted_removal_preview_parent(&child).is_err());
        let trap = directory.path().join("trap");
        symlink(&child, &trap)?;
        assert!(DnfPackageManager::trusted_removal_preview_parent(&trap).is_err());
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))?;
        assert_eq!(
            DnfPackageManager::trusted_removal_preview_parent(&child).is_ok(),
            is_root()
        );
        if is_root() {
            nix::unistd::chown(&child, Some(nix::unistd::Uid::from_raw(1000)), None)?;
            assert!(DnfPackageManager::trusted_removal_preview_parent(&child).is_err());
        }
        Ok(())
    }

    #[test]
    fn stored_removal_plan_includes_dependents_and_native_identities() {
        let plan = DnfPackageManager::parse_removal_plan(
            br#"{"version":"1.0","rpms":[
            {"nevra":"library-2:1.0-1.fc44.i686","action":"Remove"},
            {"nevra":"application-2.0-1.fc44.x86_64","action":"Remove"}] }"#,
        )
        .unwrap();
        assert_eq!(
            plan,
            vec![
                super::super::types::RemovalPackage {
                    name: "application.x86_64".into(),
                    version: "2.0-1.fc44".into()
                },
                super::super::types::RemovalPackage {
                    name: "library.i686".into(),
                    version: "2:1.0-1.fc44".into()
                }
            ]
        );
        for bad in [
            br#"{"version":"2.0","rpms":[]}"#.as_slice(),
            br#"{"version":"1.0","rpms":[{"nevra":"library-1-1.x86_64","action":"Install"}]}"#,
            br#"{"version":"1.0","rpms":[{"nevra":"broken","action":"Remove"}]}"#,
            br#"{"version":"1.0","groups":[{}]}"#,
        ] {
            assert!(DnfPackageManager::parse_removal_plan(bad).is_err());
        }
    }

    #[test]
    fn admission_handoff_accepts_only_fixed_native_modes_and_canonical_comments() {
        let args = |values: &[&str]| {
            values
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>()
        };
        for values in [
            vec!["install", "-y", "example"],
            vec!["install", "-y", "example-2:1.0~rc1-1.fc44.x86_64"],
            vec!["remove", "--dry-run", "example"],
            vec!["remove", "--dry-run", "--quiet", "example"],
            vec!["remove", "--confirm", "example"],
            vec!["remove", "--confirm", "--verbose", "example"],
            vec!["remove", "-y", "example"],
            vec![
                "--comment=omg-550e8400-e29b-41d4-a716-446655440000",
                "remove",
                "-y",
                "example",
            ],
            vec!["--setopt=cacheonly=metadata", "upgrade", "-y"],
            vec![
                "--comment=omg-550e8400-e29b-41d4-a716-446655440000",
                "upgrade",
                "-y",
            ],
        ] {
            assert!(DnfPackageManager::validate_admission_args(&args(&values)).is_ok());
        }
        for values in [
            vec!["replay", "-y", "/tmp/caller-plan"],
            vec!["install", "-y", "--installroot=/tmp/root"],
            vec!["--comment=attacker", "install", "-y", "example"],
            vec!["--setopt=plugins=1", "upgrade", "-y"],
            vec!["--setopt=cacheonly=metadata", "install", "-y", "example"],
            vec!["upgrade", "-y", "unexpected-package"],
            vec!["install", "-y"],
            vec!["install", "-y", "/tmp/local.rpm"],
            vec!["install", "-y", "example-2:1.0-1.fc44.rpm"],
            vec!["remove", "-y"],
            vec!["remove", "-y", "--quiet"],
            vec!["remove", "-y", "--quiet", "--verbose", "example"],
            vec!["remove", "--confirm", "/tmp/caller-plan"],
            vec!["remove", "--dry-run", "--installroot=/tmp/root"],
            vec!["--setopt=cacheonly=metadata", "remove", "-y", "example"],
            vec![
                "--comment=omg-550e8400-e29b-41d4-a716-446655440000",
                "remove",
                "--dry-run",
                "example",
            ],
        ] {
            assert!(
                DnfPackageManager::validate_admission_args(&args(&values)).is_err(),
                "{values:?}"
            );
        }
    }

    #[tokio::test]
    async fn native_admission_evr_comparisons_preserve_rpm_order_and_batch_association()
    -> Result<()> {
        let mut pairs = vec![("1.0-1.fc44".to_owned(), "1.0-1.fc44".to_owned()); 129];
        pairs[0] = ("2:1.0-1.fc44".into(), "1:9.9-9.fc44".into());
        pairs[1] = ("1.0~rc1-1.fc44".into(), "1.0-1.fc44".into());
        pairs[128] = ("1.0^git1-1.fc44".into(), "1.0.1-1.fc44".into());
        let compared = DnfPackageManager::compare_native_evrs(&pairs).await?;
        assert_eq!(compared.len(), 129);
        assert_eq!((compared[0], compared[1], compared[128]), (1, -1, -1));
        assert!(compared[2..128].iter().all(|value| *value == 0));
        assert!(
            DnfPackageManager::compare_native_evrs(&[("1.0\n2.0".into(), "3.0".into())])
                .await
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn proposed_admission_inventory_preserves_solver_dependencies_epochs_and_multilib() -> Result<()>
    {
        let inventory = DnfPackageManager::proposed_inventory(
            br#"{"version":"1.0","rpms":[
            {"nevra":"app-2:1.0-1.fc44.x86_64","action":"Upgrade"},
            {"nevra":"app-1.0-1.fc44.x86_64","action":"Replaced"},
            {"nevra":"lib-part-0:1.0~rc1-2.fc44.i686","action":"Install"}] }"#,
        )?;
        assert_eq!(inventory.len(), 2);
        assert_eq!(
            (
                &*inventory[0].name,
                &*inventory[0].version,
                inventory[0].architecture.as_deref()
            ),
            ("app", "2:1.0-1.fc44", Some("x86_64"))
        );
        assert_eq!(
            (
                &*inventory[1].name,
                &*inventory[1].version,
                inventory[1].architecture.as_deref()
            ),
            ("lib-part", "0:1.0~rc1-2.fc44", Some("i686"))
        );
        for bytes in [
            br#"{"version":"1.0","rpms":[{"nevra":"x-1-1.noarch","action":"Install"},{"nevra":"x-1-1.noarch","action":"Install"}]}"#.as_slice(),
            br#"{"version":"1.0","rpms":[{"nevra":"x-1-1.noarch","action":"FutureAction"}]}"#,
            br#"{"version":"1.0","rpms":[{"nevra":"broken","action":"Install"}]}"#,
            br#"{"version":"2.0","rpms":[]}"#,
            br#"{"version":"1.0","groups":[{}]}"#,
        ] { assert!(DnfPackageManager::proposed_inventory(bytes).is_err()); }
        Ok(())
    }

    #[test]
    fn stored_admission_evidence_changes_with_archive_metadata_and_path() -> Result<()> {
        let root = tempfile::tempdir()?;
        std::fs::write(root.path().join("transaction.json"), b"plan")?;
        std::fs::write(root.path().join("example.rpm"), b"archive")?;
        let before = DnfPackageManager::stored_tree_digest(root.path())?;
        std::fs::write(root.path().join("example.rpm"), b"changed")?;
        assert_ne!(before, DnfPackageManager::stored_tree_digest(root.path())?);
        std::fs::write(root.path().join("example.rpm"), b"archive")?;
        assert_eq!(before, DnfPackageManager::stored_tree_digest(root.path())?);
        std::fs::rename(
            root.path().join("example.rpm"),
            root.path().join("other.rpm"),
        )?;
        assert_ne!(before, DnfPackageManager::stored_tree_digest(root.path())?);
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("transaction.json", root.path().join("replacement"))?;
            assert!(DnfPackageManager::stored_tree_digest(root.path()).is_err());
        }
        Ok(())
    }

    #[tokio::test]
    async fn ordinary_inventory_preserves_epoch_and_multilib_identity() -> Result<()> {
        let make_header = |architecture: &str| {
            let mut data = b"example\0".to_vec();
            data.extend(b"1.0\0");
            data.extend(b"1.fc44\0");
            data.push(0);
            data.extend(2u32.to_be_bytes());
            data.extend(architecture.as_bytes());
            data.push(0);
            strict_header(
                &[
                    (1000, 6, 0, 1),
                    (1001, 6, 8, 1),
                    (1002, 6, 12, 1),
                    (1003, 4, 20, 1),
                    (1022, 6, 24, 1),
                ],
                &data,
            )
        };
        let amd64 = make_header("x86_64");
        let i686 = make_header("i686");
        let directory = write_packages_db(&[&amd64, &i686]);
        let mut manager = DnfPackageManager::new();
        manager.rpm_db_path = directory.path().join("rpmdb.sqlite");
        let mut installed = manager.list_installed().await?;
        installed.sort_by(|left, right| left.name.cmp(&right.name));
        assert_eq!(
            installed
                .iter()
                .map(|package| package.name.as_str())
                .collect::<Vec<_>>(),
            ["example.i686", "example.x86_64"]
        );
        assert!(
            installed
                .iter()
                .all(|package| package.version.to_string() == "2:1.0-1.fc44")
        );
        assert!(manager.info("example").await.is_err());
        assert_eq!(
            manager.info("example.i686").await?.unwrap().name,
            "example.i686"
        );
        assert!(manager.is_installed("example.i686").await?);
        assert!(manager.is_installed("example-2:1.0-1.fc44.i686").await?);
        Ok(())
    }

    #[tokio::test]
    async fn installed_catalog_observation_survives_manager_cache_republication() -> Result<()> {
        let native = include_bytes!("../../tests/data/fedora-publicsuffix.rpmhdr");
        let directory = write_packages_db(&[native.as_slice()]);
        let mut manager = DnfPackageManager::new();
        manager.rpm_db_path = directory.path().join("rpmdb.sqlite");
        let observed = manager
            .installed_catalog_observation()?
            .expect("SQLite observation available");
        assert!(observed.is_current()?);
        assert_eq!(
            manager.list_installed().await?[0].name,
            "publicsuffix-list-dafsa.noarch"
        );
        let database = Connection::open(&manager.rpm_db_path)?;
        database.execute("DELETE FROM Packages", [])?;
        assert!(manager.list_installed().await?.is_empty());
        assert!(
            !observed.is_current()?,
            "refreshing manager cache must not validate a prior daemon index"
        );
        assert!(
            manager
                .installed_catalog_observation()?
                .expect("replacement observation")
                .is_current()?
        );
        Ok(())
    }

    #[test]
    fn installed_catalog_observation_survives_readonly_wal_permission_reapplication() -> Result<()>
    {
        let native = include_bytes!("../../tests/data/fedora-publicsuffix.rpmhdr");
        let directory = write_packages_db(&[native.as_slice()]);
        let mut manager = DnfPackageManager::new();
        manager.rpm_db_path = directory.path().join("rpmdb.sqlite");
        let database = Connection::open(&manager.rpm_db_path)?;
        database.pragma_update(None, "journal_mode", "WAL")?;
        let observed = manager
            .installed_catalog_observation()?
            .expect("SQLite observation");
        assert!(observed.is_current()?);
        let wal = directory.path().join("rpmdb.sqlite-wal");
        let before = RpmFileIdentity::read(&wal)?.expect("observed WAL");
        std::thread::sleep(std::time::Duration::from_millis(2));
        std::fs::set_permissions(&wal, std::fs::metadata(&wal)?.permissions())?;
        let after = RpmFileIdentity::read(&wal)?.expect("WAL retained");
        assert_eq!(
            (after.device, after.inode, after.size, after.modified),
            (before.device, before.inode, before.size, before.modified)
        );
        assert_ne!(
            after.changed, before.changed,
            "model native SQLite chmod noise"
        );
        assert!(
            observed.is_current()?,
            "reapplying WAL permissions cannot change installed catalogue contents"
        );
        database.execute("DELETE FROM Packages", [])?;
        assert!(
            !observed.is_current()?,
            "a real SQLite commit must still invalidate the observation"
        );
        Ok(())
    }

    #[test]
    fn installed_catalog_observation_rejects_wal_replacement() -> Result<()> {
        let directory = write_packages_db(&[]);
        let mut manager = DnfPackageManager::new();
        manager.rpm_db_path = directory.path().join("rpmdb.sqlite");
        let database = Connection::open(&manager.rpm_db_path)?;
        database.pragma_update(None, "journal_mode", "WAL")?;
        let observed = manager
            .installed_catalog_observation()?
            .expect("SQLite observation");
        assert!(observed.is_current()?);
        let wal = directory.path().join("rpmdb.sqlite-wal");
        std::fs::rename(&wal, directory.path().join("previous-wal"))?;
        std::fs::File::create(&wal)?;
        assert!(
            !observed.is_current()?,
            "replaced WAL identity cannot certify an old installed inventory"
        );
        Ok(())
    }

    #[test]
    fn installed_catalog_observation_accepts_content_preserving_commits() -> Result<()> {
        for mode in ["DELETE", "WAL"] {
            let native = include_bytes!("../../tests/data/fedora-publicsuffix.rpmhdr");
            let directory = write_packages_db(&[native.as_slice()]);
            let path = directory.path().join("rpmdb.sqlite");
            let database = Connection::open(&path)?;
            database.pragma_update(None, "journal_mode", mode)?;
            let mut observed = RpmDatabaseObservation::read(&path).expect("SQLite observation");
            database.execute("CREATE TABLE ObservationNoise (revision INTEGER)", [])?;
            database.execute("INSERT INTO ObservationNoise VALUES (1)", [])?;
            let current_generation: i64 =
                observed
                    .connection
                    .lock()
                    .unwrap()
                    .query_row("PRAGMA data_version", [], |r| r.get(0))?;
            assert_ne!(
                current_generation, observed.data_version,
                "the content-preserving write must exercise generation invalidation in {mode}"
            );
            // Isolate the generation signal, as with the existing equal-stat
            // commit regression. The installed inventory did not change.
            observed.identity = RpmDatabaseIdentity::read(&path).expect("current identity");
            assert!(
                observed.is_current(&path),
                "unchanged package bytes in {mode}"
            );
            let busy: i64 =
                database.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?;
            assert_eq!(busy, 0, "observer must release its transaction in {mode}");
        }
        Ok(())
    }

    #[test]
    fn installed_catalog_observation_rejects_changed_rows_at_matching_metadata() -> Result<()> {
        for change in ["blob", "hnum", "schema"] {
            let native = include_bytes!("../../tests/data/fedora-publicsuffix.rpmhdr");
            let directory = write_packages_db(&[native.as_slice()]);
            let path = directory.path().join("rpmdb.sqlite");
            let database = Connection::open(&path)?;
            database.pragma_update(None, "journal_mode", "WAL")?;
            let mut observed = RpmDatabaseObservation::read(&path).expect("SQLite observation");
            match change {
                "blob" => {
                    let mut changed = native.to_vec();
                    let last = changed.len() - 2;
                    changed[last] ^= 1;
                    database.execute("UPDATE Packages SET blob = ?1", [changed])?;
                }
                "hnum" => {
                    database.execute("UPDATE Packages SET hnum = hnum + 10", [])?;
                }
                "schema" => {
                    database.execute("DROP TABLE Packages", [])?;
                }
                _ => unreachable!(),
            }
            observed.identity = RpmDatabaseIdentity::read(&path).expect("current identity");
            assert!(!observed.is_current(&path), "must reject changed {change}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn native_advisory_identity_excludes_patched_versions_and_other_architectures() {
        use crate::core::security::scan::InstalledIdentity;

        let package = |version: &str, architecture: &str| super::super::types::SecurityPackage {
            origin: crate::package_managers::types::SecurityOrigin::DistributionPackage,
            name: "fixture".into(),
            version: version.into(),
            advisory_source: None,
            architecture: Some(architecture.into()),
            description: String::new(),
            licenses: Vec::new(),
        };
        let row = super::super::dnf_advisory::ApplicableAdvisory {
            name: "FEDORA-fixture".into(),
            kind: "security".into(),
            severity: "Important".into(),
            nevra: "fixture-1:1.0-2.x86_64".into(),
        };
        let installed = vec![
            package("0:99.0-1", "x86_64"),
            package("1:1.0-2", "x86_64"),
            package("1:1.0-3", "x86_64"),
            package("0:99.0-1", "i686"),
        ];
        let other_architecture = super::super::dnf_advisory::ApplicableAdvisory {
            name: "FEDORA-other-architecture".into(),
            kind: "security".into(),
            severity: "Important".into(),
            nevra: "fixture-0:99.0-2.i686".into(),
        };
        let affected = DnfPackageManager::affected_installed_packages(
            [&row, &other_architecture, &row],
            &installed,
            InstalledAdvisoryMatch::Exact,
        )
        .await
        .unwrap();
        assert_eq!(
            affected,
            BTreeMap::from([
                (
                    row.nevra.clone(),
                    vec![InstalledIdentity::from(&installed[0])]
                ),
                (
                    other_architecture.nevra.clone(),
                    vec![InstalledIdentity::from(&installed[3])],
                ),
            ])
        );
        assert!(
            DnfPackageManager::affected_installed_packages(
                [&other_architecture, &row],
                &installed[1..],
                InstalledAdvisoryMatch::Exact,
            )
            .await
            .is_err()
        );
        let cross_architecture = super::super::dnf_advisory::ApplicableAdvisory {
            name: "FEDORA-cross-architecture".into(),
            kind: "security".into(),
            severity: "Important".into(),
            nevra: "fixture-1:1.0-2.noarch".into(),
        };
        let possible = DnfPackageManager::affected_installed_packages(
            [&row, &cross_architecture],
            &installed,
            InstalledAdvisoryMatch::ArchitectureChange,
        )
        .await
        .unwrap();
        assert!(possible[&row.nevra].is_empty());
        assert_eq!(
            possible[&cross_architecture.nevra],
            [
                InstalledIdentity::from(&installed[0]),
                InstalledIdentity::from(&installed[3]),
            ]
        );
    }

    #[tokio::test]
    async fn security_inventory_preserves_every_native_rpm_identity() {
        let mut reference =
            tokio::process::Command::from(crate::core::privilege::system_command("rpm").unwrap());
        reference.args([
            "-qa",
            "--qf",
            "%{NAME}\t%{ARCH}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n",
        ]);
        let bytes = DnfPackageManager::query_output(reference).await.unwrap();
        // RPM stores imported keys as architecture-less synthetic gpg-pubkey
        // headers. DNF excludes these trust records from software inventory.
        let mut expected: Vec<_> = std::str::from_utf8(&bytes)
            .unwrap()
            .lines()
            .filter(|line| !line.starts_with("gpg-pubkey\t(none)\t"))
            .map(str::to_owned)
            .collect();
        let packages = DnfPackageManager::new().security_inventory().await.unwrap();
        let mut actual: Vec<_> = packages
            .into_iter()
            .map(|package| {
                format!(
                    "{}\t{}\t{}",
                    package.name,
                    package.architecture.unwrap(),
                    package.version
                )
            })
            .collect();
        expected.sort();
        actual.sort();
        assert!(
            !expected.is_empty(),
            "native RPM fixture must contain installed packages"
        );
        assert_eq!(
            actual, expected,
            "security inventory lost or changed native identities"
        );
    }

    #[tokio::test]
    async fn native_advisory_and_update_queries_refuse_unavailable_repository() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        std::fs::create_dir(root.join("repos")).unwrap();
        let configure = || {
            let mut command = DnfPackageManager::advisory_command(&root.join("cache")).unwrap();
            command.args([
                format!("--setopt=reposdir={}", root.join("repos").display()),
                format!("--setopt=persistdir={}", root.join("persist").display()),
                format!("--setopt=logdir={}", root.join("logs").display()),
                format!(
                    "--repofrompath=omg-fault,file://{}",
                    root.join("missing").display()
                ),
                "--setopt=omg-fault.skip_if_unavailable=true".into(),
            ]);
            command
        };
        // Establish the real DNF false-clean behavior before testing our policy.
        let mut permissive = configure();
        permissive.args([
            "--refresh",
            "advisory",
            "list",
            "--available",
            "--security",
            "--json",
        ]);
        let output = DnfPackageManager::query_output(permissive).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output).unwrap(),
            serde_json::json!([])
        );
        let mut strict = configure();
        strict.args(super::super::dnf_advisory::query_args(false));
        let error = DnfPackageManager::query_output(strict).await.unwrap_err();
        assert!(error.to_string().contains("DNF query failed"), "{error:#}");

        let mut upgrades = configure();
        upgrades.env("LC_ALL", "C").args(UPGRADE_QUERY_ARGS);
        let error = DnfPackageManager::query_output(upgrades).await.unwrap_err();
        assert!(error.to_string().contains("DNF query failed"), "{error:#}");

        let path = root.to_owned();
        fixture.close().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn update_queries_never_refresh_repository_metadata() {
        for query in [RepositoryQuery::Installed, RepositoryQuery::Unneeded] {
            let args = DnfPackageManager::repository_query_args(query).unwrap();
            assert!(args.iter().any(|arg| arg == "--cacheonly"), "{args:?}");
        }
        assert!(UPGRADE_QUERY_ARGS.contains(&"--cacheonly"));
        assert!(UPGRADE_QUERY_ARGS.contains(&"--setopt=*.skip_if_unavailable=false"));
    }

    #[test]
    fn local_rpm_operands_are_refused_until_they_can_be_sealed() {
        for target in [
            "package.rpm",
            "package.RPM",
            "package.RpM",
            ".rpm",
            "./package.rpm",
            "/tmp/package.rpm",
            "dir/package",
        ] {
            assert!(
                reject_unsealed_local_rpm_targets(&[target.to_owned()]).is_err(),
                "accepted local DNF operand {target:?}"
            );
        }
        assert!(reject_unsealed_local_rpm_targets(&["package-name.x86_64".to_owned()]).is_ok());
    }

    #[test]
    fn installed_sizes_preserve_builds_architectures_epochs_and_large_values() {
        let sizes = DnfPackageManager::parse_installed_sizes(
            b"kernel-core-0:1-1.x86_64\t4294967296\nkernel-core-0:2-1.x86_64\t12\nlib-1:3-1.i686\t0\nlib-1:3-1.x86_64\t8\n",
        ).expect("native size rows");
        assert_eq!(
            sizes,
            vec![
                ("kernel-core-0:1-1.x86_64".to_owned(), 4_294_967_296),
                ("kernel-core-0:2-1.x86_64".to_owned(), 12),
                ("lib-1:3-1.i686".to_owned(), 0),
                ("lib-1:3-1.x86_64".to_owned(), 8),
            ]
        );
        assert!(
            DnfPackageManager::parse_installed_sizes(b"")
                .expect("empty RPM database")
                .is_empty()
        );
    }

    #[test]
    fn installed_sizes_reject_malformed_native_output() {
        for malformed in [
            b"pkg".as_slice(),
            b"\t1",
            b"bad name\t1",
            b"pkg\t-1",
            b"pkg\tNaN",
            b"pkg\t9223372036854775808",
            b"pkg\t1\textra",
            b"pkg\t",
            b"\xff\t1",
            b"pkg\x1b\t1",
        ] {
            assert!(
                DnfPackageManager::parse_installed_sizes(malformed).is_err(),
                "accepted {malformed:?}"
            );
        }
    }

    #[test]
    fn installed_reasons_preserve_native_classifications() {
        let rows = DnfPackageManager::parse_installed_reasons(b"a-0:1-1.noarch\tGroup\nb-1:2-1.x86_64\tExternal User\nc-0:3-1.i686\tWeak Dependency\n").expect("native reason rows");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[1].identity, "b-1:2-1.x86_64");
        assert_eq!(rows[1].reason, "External User");
        assert_eq!(rows[2].reason, "Weak Dependency");
        assert!(
            DnfPackageManager::parse_installed_reasons(b"")
                .expect("empty result")
                .is_empty()
        );
    }

    #[test]
    fn installed_reasons_reject_malformed_rows() {
        for row in [
            b"a".as_slice(),
            b"\tUser",
            b"a\t",
            b"a\t User",
            b"a\tUser\textra",
            b"a\tUser\x1b",
            b"a b\tUser",
            b"\xff\tUser",
        ] {
            assert!(
                DnfPackageManager::parse_installed_reasons(row).is_err(),
                "accepted {row:?}"
            );
        }
    }

    #[tokio::test]
    async fn reverse_reason_query_rejects_option_injection() {
        let error = DnfPackageManager::installed_package_reasons(InstalledReasonQuery::RequiredBy(
            "--help",
        ))
        .await
        .expect_err("invalid package operand");
        assert!(error.to_string().contains("cannot start with '-'"));
    }

    #[test]
    fn installed_details_preserve_canonical_names_and_native_versions() {
        let rows = DnfPackageManager::parse_installed_details(
            b"a\t2:1.0-3\ta-2:1.0-3.x86_64\tExternal User\n",
        )
        .expect("native detail row");
        assert_eq!(rows[0].name, "a");
        assert_eq!(rows[0].version, "2:1.0-3");
        assert_eq!(rows[0].identity, "a-2:1.0-3.x86_64");
        assert_eq!(rows[0].reason, "External User");
        for row in [
            b"a\t1\ta\t".as_slice(),
            b"a\t\ta\tUser",
            b"a\t1\ta\tUser\textra",
            b"a\t1\ta\tUser\x1b",
        ] {
            assert!(DnfPackageManager::parse_installed_details(row).is_err());
        }
    }

    #[test]
    fn installed_details_preserve_order_and_distinct_native_reasons() {
        let rows = DnfPackageManager::parse_installed_details(
            b"tree\t2:2.2.1-4.fc44\ttree-2:2.2.1-4.fc44.x86_64\tExternal User\nhelper\t0:1.0-2.fc44\thelper-0:1.0-2.fc44.noarch\tWeak Dependency\n",
        )
        .expect("two native detail rows");
        let payloads = rows
            .iter()
            .map(|row| {
                (
                    row.name.as_str(),
                    row.version.as_str(),
                    row.identity.as_str(),
                    row.reason.as_str(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            payloads,
            [
                (
                    "tree",
                    "2:2.2.1-4.fc44",
                    "tree-2:2.2.1-4.fc44.x86_64",
                    "External User",
                ),
                (
                    "helper",
                    "0:1.0-2.fc44",
                    "helper-0:1.0-2.fc44.noarch",
                    "Weak Dependency",
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_dnf_manager_creation() {
        let manager = DnfPackageManager::new();
        assert_eq!(manager.name(), "dnf");
    }

    #[tokio::test]
    async fn native_fedora_update_snapshot_has_matching_installed_versions() {
        let installed = DnfPackageManager::parse_versioned_packages(include_bytes!(
            "../../tests/data/fedora-installed.tsv"
        ))
        .expect("native installed rows");
        let candidates = DnfPackageManager::parse_versioned_packages(include_bytes!(
            "../../tests/data/fedora-upgrades.tsv"
        ))
        .expect("native upgrade rows");
        assert!(!candidates.is_empty());
        let updates = DnfPackageManager::match_updates(&installed, &candidates)
            .await
            .expect("every native upgrade matches an installed identity");
        assert_eq!(updates.len(), candidates.len());
        for (update, candidate) in updates.iter().zip(&candidates) {
            assert_eq!(update.name, candidate.name);
            assert_eq!(update.new_version, candidate.version);
            assert_eq!(update.repo, candidate.repository);
        }
    }

    #[tokio::test]
    async fn update_matching_uses_architecture_and_preserves_native_versions() {
        let installed = DnfPackageManager::parse_versioned_packages(
            b"lib\ti686\t1:1-1\t@System\nlib\tx86_64\t1:2-1\t@System\n",
        )
        .expect("installed records");
        let candidates = DnfPackageManager::parse_versioned_packages(
            b"lib\tx86_64\t1:4-1\tupdates\nlib\ti686\t1:3-1\tupdates\n",
        )
        .expect("upgrade records");
        let updates = DnfPackageManager::match_updates(&installed, &candidates)
            .await
            .expect("matched upgrades");
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].old_version, "1:2-1");
        assert_eq!(updates[1].old_version, "1:1-1");
        assert_eq!(updates[0].new_version, "1:4-1");
        assert_eq!(updates[0].repo, "updates");
    }

    #[tokio::test]
    async fn update_matching_accepts_noarch_transitions_and_counts_mirrors_once() -> Result<()> {
        let installed = DnfPackageManager::parse_versioned_packages(
            concat!(
                "lib\tx86_64\t99-1\t@System\n",
                "lib\ti686\t1:1~rc-1\t@System\n",
                "tool\tnoarch\t1-1\t@System\n",
            )
            .as_bytes(),
        )?;
        let candidates = DnfPackageManager::parse_versioned_packages(
            concat!(
                "lib\tnoarch\t1:1-1\tupdates\n",
                "lib\tnoarch\t1:1-1\tmirror\n",
                "tool\tx86_64\t2-1\tupdates\n",
            )
            .as_bytes(),
        )?;

        let updates = DnfPackageManager::match_updates(&installed, &candidates).await?;

        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].old_version, "1:1~rc-1");
        assert_eq!(updates[0].new_version, "1:1-1");
        assert_eq!(updates[0].repo, "updates");
        assert_eq!(updates[1].old_version, "1-1");
        assert_eq!(updates[1].new_version, "2-1");
        Ok(())
    }

    #[tokio::test]
    async fn update_matching_rejects_unmatched_and_unchanged_candidates() {
        let installed = DnfPackageManager::parse_versioned_packages(b"lib\tx86_64\t1-1\t@System\n")
            .expect("installed");
        let wrong_arch = DnfPackageManager::parse_versioned_packages(b"lib\ti686\t2-1\tupdates\n")
            .expect("candidate");
        assert!(
            DnfPackageManager::match_updates(&installed, &wrong_arch)
                .await
                .is_err()
        );
        assert!(
            DnfPackageManager::match_updates(&installed, &installed)
                .await
                .is_err()
        );
        assert!(
            DnfPackageManager::match_updates(&installed, &[])
                .await
                .expect("no updates")
                .is_empty()
        );
        for malformed in [
            b"lib\tx86_64\t1-1".as_slice(),
            b"lib\t\t1-1\tupdates",
            b"lib\tx86_64\t1-1\tupdates\textra",
            b"lib\tx86_64\t1-1\tup\x1bdates",
        ] {
            assert!(DnfPackageManager::parse_versioned_packages(malformed).is_err());
        }
    }

    #[test]
    fn cached_upgrade_listing_distinguishes_empty_results_from_invalid_data() -> Result<()> {
        assert!(DnfPackageManager::parse_available_upgrades(b"\n")?.is_empty());
        let candidate = DnfPackageManager::parse_available_upgrades(
            b"Available upgrades\nlib.compat.noarch   2:1-1   updates\n",
        )?;
        assert_eq!(candidate[0].name, "lib.compat");
        assert_eq!(candidate[0].version, "2:1-1");
        assert_eq!(candidate[0].architecture, "noarch");
        assert_eq!(candidate[0].repository, "updates");
        for invalid in [
            b"Unexpected heading".as_slice(),
            b"Available upgrades\nlib.noarch updates",
            b"Available upgrades\nlib 2:1-1 updates",
            b"Available upgrades\nlib.noarch 2:1-1 up\x1bdates",
        ] {
            assert!(DnfPackageManager::parse_available_upgrades(invalid).is_err());
        }
        Ok(())
    }

    #[tokio::test]
    async fn repository_lookup_rejects_option_operands_before_spawning() {
        let error = DnfPackageManager::available_packages(Some("--config=untrusted"))
            .await
            .expect_err("option-like operand must be rejected");
        assert!(
            error
                .downcast_ref::<crate::core::security::ValidationError>()
                .is_some()
        );
        for query in [
            RepositoryQuery::InstalledSizes(InstalledSizeQuery::Package("--config=untrusted")),
            RepositoryQuery::InstalledSizes(InstalledSizeQuery::RequirementProviders(
                "--config=untrusted",
            )),
            RepositoryQuery::InstalledReasons(InstalledReasonQuery::Package("--config=untrusted")),
            RepositoryQuery::InstalledReasons(InstalledReasonQuery::RequiredBy(
                "--config=untrusted",
            )),
            RepositoryQuery::InstalledDetails("--config=untrusted"),
        ] {
            let error = DnfPackageManager::repository_output(query)
                .await
                .expect_err("invalid operand");
            assert!(
                error
                    .downcast_ref::<crate::core::security::ValidationError>()
                    .is_some(),
                "{query:?} must reject the operand before resolving DNF: {error:#}"
            );
        }
    }

    #[test]
    fn repository_query_arguments_preserve_reverse_dependency_semantics() -> Result<()> {
        assert_eq!(
            DnfPackageManager::repository_query_args(RepositoryQuery::InstalledReasons(
                InstalledReasonQuery::RequiredBy("bash"),
            ))?,
            [
                "--setopt=disable_excludes=*",
                "repoquery",
                "--installed",
                "--queryformat",
                "%{full_nevra}\t%{reason}\\n",
                "--whatrequires=bash",
            ]
        );
        assert_eq!(
            DnfPackageManager::repository_query_args(RepositoryQuery::InstalledSizes(
                InstalledSizeQuery::RequirementProviders("bash"),
            ))?,
            [
                "--setopt=disable_excludes=*",
                "repoquery",
                "--installed",
                "--queryformat",
                "%{full_nevra}\t%{installsize}\\n",
                "--providers-of=requires",
                "bash",
            ]
        );
        Ok(())
    }

    #[test]
    fn installed_details_query_arguments_preserve_reason_format_and_package() -> Result<()> {
        assert_eq!(
            DnfPackageManager::repository_query_args(RepositoryQuery::InstalledDetails("tree"))?,
            [
                "--setopt=disable_excludes=*",
                "repoquery",
                "--installed",
                "--queryformat",
                "%{name}\t%{evr}\t%{full_nevra}\t%{reason}\\n",
                "tree",
            ]
        );
        Ok(())
    }

    #[test]
    fn available_info_passes_the_exact_selector_without_an_architecture_override() -> Result<()> {
        for selector in ["widget.lib.i686", "widget.lib-0:1.2-3.fc44.i686"] {
            let args = DnfPackageManager::repository_query_args(RepositoryQuery::Available(Some(
                selector,
            )))?;
            assert_eq!(args.last().map(String::as_str), Some(selector));
            assert!(
                !args.iter().any(|arg| arg.starts_with("--arch=")),
                "{args:?}"
            );
        }
        let search = DnfPackageManager::repository_query_args(RepositoryQuery::Available(None))?;
        assert!(search.contains(&format!("--arch={},noarch", std::env::consts::ARCH)));
        Ok(())
    }

    #[test]
    fn available_info_keeps_native_preference_and_accepts_a_unique_multilib_build() -> Result<()> {
        let manager = DnfPackageManager::select_available_info;
        let parse = DnfPackageManager::parse_available_packages;
        let host = std::env::consts::ARCH;
        let foreign = if host == "i686" { "x86_64" } else { "i686" };
        let foreign_row = format!("widget.lib.{foreign}\t1.2-3.fc44\tMultilib package\n");
        let native_row = format!("widget.lib.{host}\t2.0-1.fc44\tNative package\n");
        let combined = format!("{foreign_row}{native_row}");
        let selected =
            manager("widget.lib", parse(combined.as_bytes())?)?.context("native build")?;
        assert_eq!(selected.name, format!("widget.lib.{host}"));
        assert_eq!(selected.version.to_string(), "2.0-1.fc44");

        let selector = format!("widget.lib-0:1.2-3.fc44.{foreign}");
        let selected =
            manager(&selector, parse(foreign_row.as_bytes())?)?.context("explicit build")?;
        assert_eq!(selected.name, format!("widget.lib.{foreign}"));
        assert!(!selected.installed);
        let independent_row = b"widget.lib.noarch\t2.0-1.fc44\tArchitecture-independent\n";
        let mut ambiguous = parse(native_row.as_bytes())?;
        ambiguous.extend(parse(independent_row)?);
        assert!(
            manager("widget.lib", ambiguous)
                .expect_err("multiple default builds are ambiguous")
                .to_string()
                .contains("multiple available builds")
        );
        Ok(())
    }

    #[test]
    fn repository_selectors_preserve_native_rpm_version_characters() -> Result<()> {
        for selector in [
            "widget-0:1.0_git-1.fc43.x86_64",
            "widget-1:2.0^a-1_git.x86_64",
            "widget-name-1:2.0~rc1-1^a.noarch",
            "widget-2.0^a-1_git.x86_64",
        ] {
            let args = DnfPackageManager::repository_query_args(RepositoryQuery::Available(Some(
                selector,
            )))?;
            assert_eq!(args.last().map(String::as_str), Some(selector));
        }
        Ok(())
    }

    #[test]
    fn repository_selectors_preserve_large_unsigned_rpm_epochs() -> Result<()> {
        for selector in [
            "widget-2147483648:2.0^a-1_git.x86_64",
            "widget-4294967295:2.0~rc1-1.fc44.noarch",
        ] {
            let args = DnfPackageManager::repository_query_args(RepositoryQuery::Available(Some(
                selector,
            )))?;
            assert_eq!(args.last().map(String::as_str), Some(selector));
        }
        Ok(())
    }

    #[tokio::test]
    async fn repository_selectors_reject_malformed_native_forms_before_spawning() {
        for selector in [
            "--config=untrusted",
            "widget-:2-1.x86_64",
            "widget-x:2-1.x86_64",
            "widget-1:2:3-1.x86_64",
            "widget-4294967296:2-1.x86_64",
            "widget-1:2-1:9.x86_64",
            "widget-1:2-1./tmp",
            "widget-1:2-1.x86_64\n--config=untrusted",
            "../widget-1:2-1.x86_64",
            "widget-1:2;id-1.x86_64",
        ] {
            DnfPackageManager::available_packages(Some(selector))
                .await
                .expect_err("malformed selector must fail before native spawning");
        }
    }

    #[test]
    fn available_repository_rows_preserve_epoch_and_uninstalled_state() {
        let packages = DnfPackageManager::parse_available_packages(
            b"tree\t2:2.2.1-4.fc44\tDirectory listing\n",
        )
        .expect("valid repository row");
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "tree");
        assert_eq!(packages[0].version.to_string(), "2:2.2.1-4.fc44");
        assert_eq!(packages[0].description, "Directory listing");
        assert!(!packages[0].installed);
    }

    #[test]
    fn available_repository_rows_preserve_official_source_and_complete_payload() {
        let packages = DnfPackageManager::parse_available_packages(
            b"tree.x86_64\t2:2.2.1-4.fc44\tDirectory listing\n",
        )
        .expect("valid official repository row");
        assert_eq!(packages.len(), 1);
        assert_eq!(
            (
                packages[0].name.as_str(),
                packages[0].version.to_string(),
                packages[0].description.as_str(),
                packages[0].source,
                packages[0].installed,
            ),
            (
                "tree.x86_64",
                "2:2.2.1-4.fc44".to_owned(),
                "Directory listing",
                PackageSource::Official,
                false,
            )
        );
    }

    fn search_catalog_fixture() -> ([InstalledPackage; 2], &'static [u8]) {
        let installed =
            [("widget.lib", "x86_64"), ("widget.local", "noarch")].map(|(name, architecture)| {
                InstalledPackage {
                    name: name.to_owned(),
                    architecture: architecture.to_owned(),
                    version: "1".to_owned(),
                    release: "1".to_owned(),
                    summary: "Installed summary".to_owned(),
                }
            });
        (
            installed,
            b"widget.lib.x86_64\t2-1\tRepository keyword\n\
              widget.lib.x86_64\t3-1\tAnother repository build\n\
              widget.lib.i686\t2-1\tRepository keyword\n",
        )
    }

    #[test]
    fn search_matches_qualified_identities_and_prefers_installed_rows() {
        assert_eq!(
            DnfPackageManager::repository_query_format(&RepositoryQuery::Available(None)),
            "%{name}.%{arch}\t%{evr}\t%{summary}\\n"
        );
        let (installed_packages, output) = search_catalog_fixture();
        let search = |query| {
            DnfPackageManager::search_results(&installed_packages, output, query)
                .expect("valid repository rows")
                .into_iter()
                .map(|pkg| {
                    (
                        pkg.name,
                        pkg.installed,
                        pkg.version.to_string(),
                        pkg.description,
                    )
                })
                .collect::<Vec<_>>()
        };
        let installed = (
            "widget.lib.x86_64".to_owned(),
            true,
            "1-1".to_owned(),
            "Installed summary".to_owned(),
        );
        let available = (
            "widget.lib.i686".to_owned(),
            false,
            "2-1".to_owned(),
            "Repository keyword".to_owned(),
        );
        assert_eq!(search("widget.lib"), [available.clone(), installed.clone()]);
        assert_eq!(
            search("widget.lib.x86_64").as_slice(),
            std::slice::from_ref(&installed)
        );
        assert_eq!(search("repository keyword"), [available.clone(), installed]);
        assert_eq!(search("widget.lib.i686"), [available]);
        assert_eq!(
            search("widget.local.noarch"),
            [(
                "widget.local.noarch".to_owned(),
                true,
                "1-1".to_owned(),
                "Installed summary".to_owned(),
            )]
        );
    }

    #[test]
    fn direct_search_preserves_the_first_repository_row_for_a_matching_identity() -> Result<()> {
        let output = "editor.noarch\t1-1\tPreferred repository\n\
                      editor.noarch\t1-2\tÉditeur de texte\n";
        let matches = DnfPackageManager::search_results(&[], output.as_bytes(), "éditeur")?;
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "editor.noarch");
        assert_eq!(matches[0].version.to_string(), "1-1");
        assert_eq!(matches[0].description, "Preferred repository");
        assert!(!matches[0].installed);

        let malformed = "editor.noarch\t1-1\tÉditeur\nmissing-version";
        assert!(DnfPackageManager::search_results(&[], malformed.as_bytes(), "éditeur").is_err());
        Ok(())
    }

    #[cfg(unix)]
    pub(crate) fn search_parity_data(query: &str) -> (Vec<Package>, Vec<Package>) {
        let (installed, output) = search_catalog_fixture();
        let available = DnfPackageManager::parse_available_packages(output).expect("fixture rows");
        let catalog = DnfPackageManager::search_candidates(&installed, available);
        let direct =
            DnfPackageManager::search_results(&installed, output, query).expect("valid search");
        (catalog, direct)
    }

    #[test]
    fn malformed_repository_rows_do_not_become_empty_searches() {
        for row in [
            b"tree".as_slice(),
            b"tree\t\tmissing version",
            b"bad/name\t1-1\tx",
            b"tree\t1-1\t\xff",
        ] {
            assert!(DnfPackageManager::parse_available_packages(row).is_err());
        }
        assert!(
            DnfPackageManager::parse_available_packages(b"")
                .expect("empty repo")
                .is_empty()
        );
    }

    #[test]
    fn repository_query_formats_match_dnf5_row_terminator_contract() {
        // dnf5 passes real TABs through but silently drops a real newline
        // inside --queryformat/--qf, concatenating every row into one.
        // The row terminator must therefore be the two-character `\n`
        // escape; a literal `\t` escape is passed through as text.
        let queries = [
            RepositoryQuery::Available(None),
            RepositoryQuery::Available(Some("tree")),
            RepositoryQuery::Installed,
            RepositoryQuery::Unneeded,
            RepositoryQuery::InstalledSizes(InstalledSizeQuery::All),
            RepositoryQuery::InstalledSizes(InstalledSizeQuery::Package("tree")),
            RepositoryQuery::InstalledReasons(InstalledReasonQuery::Package("tree")),
            RepositoryQuery::InstalledReasons(InstalledReasonQuery::RequiredBy("tree")),
            RepositoryQuery::InstalledDetails("tree"),
        ];
        for query in &queries {
            let format = DnfPackageManager::repository_query_format(query);
            assert!(
                format.contains('\t'),
                "dnf5 needs real TAB separators: {format:?}"
            );
            assert!(
                !format.contains('\n'),
                "dnf5 drops real newlines and concatenates rows: {format:?}"
            );
            assert!(
                format.ends_with("\\n"),
                "dnf5 needs the literal backslash-n row terminator: {format:?}"
            );
            assert!(
                !format.contains("\\t"),
                "dnf5 passes literal backslash-t through as text: {format:?}"
            );
        }
        assert!(
            !DnfPackageManager::USER_INSTALLED_QUERY_FORMAT.contains('\n'),
            "dnf5 drops real newlines and concatenates names"
        );
        assert!(
            DnfPackageManager::USER_INSTALLED_QUERY_FORMAT.ends_with("\\n"),
            "dnf5 needs the literal backslash-n row terminator"
        );
    }

    #[test]
    fn reads_native_fedora_sqlite_header() {
        let blob = include_bytes!("../../tests/data/fedora-publicsuffix.rpmhdr");
        let directory = write_packages_db(&[blob.as_slice()]);
        let packages = DnfPackageManager::read_rpm_sqlite(&directory.path().join("rpmdb.sqlite"))
            .expect("native Fedora database header must decode");
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "publicsuffix-list-dafsa");
        assert_eq!(packages[0].version, "20260116");
        assert_eq!(packages[0].release, "1.fc44");
        assert_eq!(
            packages[0].summary,
            "Cross-vendor public domain suffix database in DAFSA form"
        );
    }

    #[test]
    fn rpm_epoch_native_singleton_preserves_version_identity() {
        let native = include_bytes!("../../tests/data/fedora-xz-libs.rpmhdr");
        let directory = write_packages_db(&[native.as_slice()]);
        let packages = DnfPackageManager::read_rpm_sqlite(&directory.path().join("rpmdb.sqlite"))
            .expect("unmodified native RPM EPOCH singleton must decode");
        assert_eq!(packages.len(), 1);
        assert_eq!(
            (
                packages[0].name.as_str(),
                packages[0].version.as_str(),
                packages[0].release.as_str(),
                packages[0].architecture.as_str()
            ),
            ("xz-libs", "1:5.8.2", "2.fc44", "x86_64")
        );
    }

    #[test]
    fn rpm_epoch_inventory_rejects_native_identity_with_wrong_schema() {
        let native = include_bytes!("../../tests/data/fedora-xz-libs.rpmhdr");
        let entries = u32::from_be_bytes(native[..4].try_into().unwrap()) as usize;
        let entry = (8..8 + entries * 16)
            .step_by(16)
            .find(|&offset| {
                u32::from_be_bytes(native[offset..offset + 4].try_into().unwrap())
                    == rpm_tags::EPOCH
            })
            .expect("native fixture contains EPOCH");
        assert_eq!(
            u32::from_be_bytes(native[entry + 4..entry + 8].try_into().unwrap()),
            4
        );
        assert_eq!(
            u32::from_be_bytes(native[entry + 12..entry + 16].try_into().unwrap()),
            1
        );
        // Preserve the same four payload bytes, changing only type/count.
        // librpm rejects the BIN/INT16/INT8 variants in the retained native
        // probe; empty and array epochs also violate the singleton schema.
        for (kind, count) in [(7u32, 4u32), (3, 2), (2, 4), (4, 0), (4, 2)] {
            let mut changed = native.to_vec();
            changed[entry + 4..entry + 8].copy_from_slice(&kind.to_be_bytes());
            changed[entry + 12..entry + 16].copy_from_slice(&count.to_be_bytes());
            let directory = write_packages_db(&[changed.as_slice()]);
            assert!(
                DnfPackageManager::read_rpm_sqlite(&directory.path().join("rpmdb.sqlite")).is_err(),
                "inventory accepted EPOCH type {kind} count {count}"
            );
        }
    }

    #[test]
    fn rpm_inventory_rejects_identity_tags_declared_as_binary() {
        let native = include_bytes!("../../tests/data/fedora-publicsuffix.rpmhdr");
        for tag in [
            rpm_tags::NAME,
            rpm_tags::VERSION,
            rpm_tags::RELEASE,
            rpm_tags::ARCH,
        ] {
            let mut blob = native.to_vec();
            let count = u32::from_be_bytes(blob[..4].try_into().unwrap()) as usize;
            let data_start = 8 + count * 16;
            let entry = (8..data_start)
                .step_by(16)
                .find(|&offset| {
                    u32::from_be_bytes(blob[offset..offset + 4].try_into().unwrap()) == tag
                })
                .expect("native fixture contains identity tag");
            let offset =
                u32::from_be_bytes(blob[entry + 8..entry + 12].try_into().unwrap()) as usize;
            let length = blob[data_start + offset..]
                .iter()
                .position(|&byte| byte == 0)
                .unwrap();
            blob[entry + 4..entry + 8].copy_from_slice(&7_u32.to_be_bytes());
            blob[entry + 12..entry + 16].copy_from_slice(&(length as u32).to_be_bytes());
            let directory = write_packages_db(&[blob.as_slice()]);
            let result = DnfPackageManager::read_rpm_sqlite(&directory.path().join("rpmdb.sqlite"));
            assert!(
                result.is_err(),
                "binary tag {tag} must not enter installed inventory: {result:?}"
            );
        }
        let directory = write_packages_db(&[native.as_slice()]);
        let packages = DnfPackageManager::read_rpm_sqlite(&directory.path().join("rpmdb.sqlite"))
            .expect("unmodified native header remains valid");
        assert_eq!(packages[0].name, "publicsuffix-list-dafsa");
        assert_eq!(packages[0].architecture, "noarch");
    }

    #[tokio::test]
    async fn native_update_history_requires_a_system_wide_operation() {
        use crate::core::history::TransactionType;
        let manager = DnfPackageManager::new();
        assert!(
            manager
                .transact_with_history(TransactionType::Update, &[], None)
                .is_some()
        );
        let packages = vec!["tree".to_owned()];
        let operation = manager
            .transact_with_history(TransactionType::Update, &packages, None)
            .expect("native update capability");
        assert!(
            operation
                .await
                .unwrap_err()
                .to_string()
                .contains("do not accept package operands")
        );
    }

    #[test]
    fn cached_update_reuses_metadata_but_allows_package_downloads() {
        assert_eq!(
            DnfPackageManager::cached_update_args(),
            ["--setopt=cacheonly=metadata", "upgrade", "-y"]
        );
    }

    #[test]
    fn fresh_dnf_history_requires_absence_at_the_effective_location() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let config = format!(
            "[main]\ninstallroot = /\ntransaction_history_dir = {}\n",
            directory.path().display()
        );
        assert!(DnfPackageManager::history_is_missing(&config)?);
        std::fs::write(
            directory.path().join(DNF_HISTORY_DATABASE),
            b"unreadable journal format",
        )?;
        assert!(!DnfPackageManager::history_is_missing(&config)?);
        for invalid in [
            format!("{config}transaction_history_dir = /other"),
            config.replace("installroot = /", "installroot = /other"),
            "installroot = /\ntransaction_history_dir = relative".into(),
        ] {
            assert!(DnfPackageManager::history_is_missing(&invalid).is_err());
        }
        Ok(())
    }

    #[test]
    fn native_history_correlates_only_our_transaction() {
        let mut transactions: Vec<NativeTransaction> = serde_json::from_str(r#"[
            {"id":1,"comment":"ours","status":"Ok","packages":[{"nevra":"tree-0:2.2.1-4.fc44.x86_64","action":"Install"}]},
            {"id":2,"comment":"someone-else","status":"Ok","packages":[{"nevra":"unrelated","action":"Future Action"}]}
        ]"#).expect("native history fixture");
        let NativeOutcome::Committed(changes) =
            DnfPackageManager::native_outcome(&transactions, "ours").expect("matching transaction")
        else {
            panic!("expected committed transaction");
        };
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].name, "tree");
        assert_eq!(changes[0].new_version.as_deref(), Some("0:2.2.1-4.fc44"));
        assert!(matches!(
            DnfPackageManager::native_outcome(&transactions, "no-op").unwrap(),
            NativeOutcome::NoTransaction
        ));
        transactions[1].comment = "ours".to_owned();
        assert!(DnfPackageManager::native_outcome(&transactions, "ours").is_err());
    }

    #[test]
    fn native_history_pairs_versions_by_name_and_architecture() {
        let packages: Vec<NativeTransactionPackage> = serde_json::from_str(
            r#"[
            {"nevra":"a-b-2:1-1.x86_64","action":"Replaced"},
            {"nevra":"a-b-2:2-1.x86_64","action":"Upgrade"},
            {"nevra":"a-b-2:3-1.i686","action":"Install"}
        ]"#,
        )
        .unwrap();
        let changes = DnfPackageManager::native_changes(&packages).unwrap();
        assert_eq!(changes.len(), 2);
        let upgrade = changes
            .iter()
            .find(|change| change.old_version.is_some())
            .unwrap();
        assert_eq!(upgrade.name, "a-b");
        assert_eq!(upgrade.old_version.as_deref(), Some("2:1-1"));
        assert_eq!(upgrade.new_version.as_deref(), Some("2:2-1"));
        assert_eq!(upgrade.source, "dnf");
        for package in [
            NativeTransactionPackage {
                nevra: "broken".to_owned(),
                action: "Install".to_owned(),
            },
            NativeTransactionPackage {
                nevra: "a-0:1-1.noarch".to_owned(),
                action: "Future Action".to_owned(),
            },
        ] {
            assert!(DnfPackageManager::native_changes(&[package]).is_err());
        }
    }

    #[test]
    fn native_unresolved_transaction_reports_recorded_identity() {
        // libdnf5 marks a transaction STARTED when it is inserted and only
        // updates it from finish(OK|ERROR); the observed Fedora failure left
        // such a row behind (run 36204199869). The error must carry the
        // recorded identity instead of only the status word.
        let transactions: Vec<NativeTransaction> = serde_json::from_str(r#"[{"id":41,"comment":"omg-fixture","status":"Started","description":"/usr/bin/dnf5 --comment=omg-fixture remove --yes tree-2.2.1-4.fc44","packages":[{"nevra":"tree-0:2.2.1-4.fc44.x86_64","action":"Remove"}]}]"#).expect("native history fixture");
        // The recorded identity is carried to the final diagnostic without
        // replaying the interrupted transaction.
        match DnfPackageManager::native_outcome(&transactions, "omg-fixture")
            .expect("an unfinished transaction is reported as Interrupted")
        {
            NativeOutcome::Interrupted {
                id,
                comment,
                status,
                actions,
                command,
            } => {
                assert_eq!(comment, "omg-fixture");
                assert_eq!(id, 41, "{status} {actions} {command}");
                assert_eq!(status, "Started");
                assert_eq!(actions, 1, "package action count must be preserved");
                assert_eq!(
                    command, "/usr/bin/dnf5 --comment=omg-fixture remove --yes tree-2.2.1-4.fc44",
                    "the recorded command must be preserved for the failure report"
                );
            }
            other => panic!("expected Interrupted, got {other:?}"),
        }
        let without_command: Vec<NativeTransaction> = serde_json::from_str(
            r#"[{"id":7,"comment":"omg-fixture","status":"Started","packages":[]}]"#,
        )
        .expect("fixture without description");
        match DnfPackageManager::native_outcome(&without_command, "omg-fixture")
            .expect("a missing description must still be Interrupted")
        {
            NativeOutcome::Interrupted { id, command, .. } => {
                assert_eq!(id, 7);
                assert_eq!(
                    command, "not recorded",
                    "a missing description must not hide the failure"
                );
            }
            other => panic!("expected Interrupted, got {other:?}"),
        }
    }

    #[test]
    fn native_interruption_preserves_prior_committed_history() -> Result<()> {
        use crate::core::history::{HistoryManager, PackageChange, Transaction, TransactionType};

        let directory = tempfile::tempdir()?;
        let path = directory.path().join("history.json");
        let history = HistoryManager::new_in(&path)?;
        let prior = Transaction {
            id: "prior-install-001".to_owned(),
            timestamp: "2026-01-01T00:00:00Z".parse()?,
            transaction_type: TransactionType::Install,
            changes: vec![PackageChange {
                name: "tree".to_owned(),
                old_version: None,
                new_version: Some("2.2.1-4.fc44".to_owned()),
                source: "fedora".to_owned(),
            }],
            success: true,
        };
        history.save(std::slice::from_ref(&prior))?;
        let before = std::fs::read(&path)?;
        let transactions: Vec<NativeTransaction> = serde_json::from_str(
            r#"[{"id":41,"comment":"omg-started-preservation","status":"Started","description":"dnf remove tree","packages":[{"nevra":"tree-0:2.2.1-4.fc44.x86_64","action":"Remove"}]}]"#,
        )?;

        let error = DnfPackageManager::record_native_result(
            TransactionType::Remove,
            &history,
            Err(anyhow::anyhow!("original exit 1")),
            DnfPackageManager::native_outcome(&transactions, "omg-started-preservation"),
        )
        .expect_err("a Started removal must remain unresolved");
        let diagnostic = format!("{error:#}");
        for expected in [
            "original exit 1",
            "transaction 41",
            "comment 'omg-started-preservation'",
            "Started",
            "inspect native DNF history and package state before deciding on recovery",
        ] {
            assert!(
                diagnostic.contains(expected),
                "missing {expected}: {diagnostic}"
            );
        }
        assert_eq!(
            std::fs::read(&path)?,
            before,
            "an interrupted removal must preserve previously committed history bytes"
        );
        let reopened = HistoryManager::new_in(&path)?;
        assert_eq!(
            reopened.load()?,
            vec![prior],
            "prior committed history must survive reopening without a new removal record"
        );
        Ok(())
    }

    #[test]
    fn native_interruption_is_diagnostic_only_and_preserves_operation_error() {
        let directory = tempfile::tempdir().unwrap();
        let history =
            crate::core::history::HistoryManager::new_in(directory.path().join("history.json"))
                .unwrap();
        let transactions: Vec<NativeTransaction> = serde_json::from_str(
            r#"[{"id":41,"comment":"ours","status":"Started","description":"dnf remove tree","packages":[]},
                {"id":42,"comment":"","status":"Ok","description":"dnf history redo 41","packages":[]}]"#,
        ).unwrap();
        let result = DnfPackageManager::record_native_result(
            crate::core::history::TransactionType::Remove,
            &history,
            Err(anyhow::anyhow!("original exit 1").context("DNF child failed")),
            DnfPackageManager::native_outcome(&transactions, "ours"),
        )
        .unwrap_err()
        .to_string();
        for expected in [
            "original exit 1",
            "41",
            "comment 'ours'",
            "Started",
            "0 package action(s)",
            "dnf remove tree",
            "Automatic recovery was not attempted",
        ] {
            assert!(result.contains(expected), "missing {expected}: {result}");
        }
        assert!(
            !result.contains("retry manually"),
            "must not advise blind replay: {result}"
        );
        assert!(
            history.load().unwrap().is_empty(),
            "Started is not committed history"
        );
        let result = DnfPackageManager::record_native_result(
            crate::core::history::TransactionType::Remove,
            &history,
            Ok(()),
            DnfPackageManager::native_outcome(&transactions, "ours"),
        )
        .unwrap_err();
        assert!(format!("{result:#}").contains("Automatic recovery was not attempted"));
        assert!(history.load().unwrap().is_empty());
    }

    #[test]
    fn native_result_selection_keeps_journal_and_command_outcomes_separate() {
        use crate::core::history::{HistoryManager, PackageChange, TransactionType};
        let directory = tempfile::tempdir().unwrap();
        let history = HistoryManager::new_in(directory.path().join("history.json")).unwrap();
        let result = DnfPackageManager::record_native_result;
        let committed_changes = vec![PackageChange {
            name: "tree".into(),
            old_version: Some("0:2.2.1-4.fc44".into()),
            new_version: None,
            source: "dnf".into(),
        }];
        result(
            TransactionType::Remove,
            &history,
            Ok(()),
            Ok(NativeOutcome::NoTransaction),
        )
        .unwrap();
        assert!(
            history.load().unwrap().is_empty(),
            "no-op must not invent history"
        );
        let error = result(
            TransactionType::Remove,
            &history,
            Ok(()),
            Ok(NativeOutcome::Failed),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("failed journal transaction after command success"));
        assert!(!history.load().unwrap()[0].success);
        let error = result(
            TransactionType::Remove,
            &history,
            Err(anyhow::anyhow!("original error")),
            Ok(NativeOutcome::Committed(committed_changes.clone())),
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "original error",
            "a committed journal row is not recovery of a command error"
        );
        let entries = history.load().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(
            entries[1].success,
            "record native commitment honestly despite command error"
        );
        let reopened = HistoryManager::new_in(directory.path().join("history.json"))
            .unwrap()
            .load()
            .unwrap();
        assert_eq!(reopened[1].changes, committed_changes);
        assert_eq!(reopened[1].transaction_type, TransactionType::Remove);
        for operation in [Ok(()), Err(anyhow::anyhow!("original error"))] {
            let error = result(
                TransactionType::Remove,
                &history,
                operation,
                Err(anyhow::anyhow!("invalid journal")),
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains("invalid journal"));
        }
        assert_eq!(
            history.load().unwrap().len(),
            2,
            "invalid journal must not invent changes"
        );
    }

    #[tokio::test]
    async fn native_history_query_is_noninteractive_and_bounded() {
        use std::io::{Seek, Write};
        let mut command = tokio::process::Command::new("/bin/sh");
        command.args(["-c", "if read line; then exit 9; fi; printf '[]'"]);
        let mut input = tempfile::tempfile().unwrap();
        input.write_all(b"caller input\n").unwrap();
        input.rewind().unwrap();
        command.stdin(std::process::Stdio::from(input));
        assert_eq!(
            DnfPackageManager::query_output(command).await.unwrap(),
            b"[]"
        );
        let mut command = tokio::process::Command::new("/bin/sh");
        // exec avoids a surviving shell descendant; no native DNF or sudo runs.
        command.args(["-c", "exec sleep 30"]);
        let started = std::time::Instant::now();
        let error = DnfPackageManager::query_output_with_deadline(
            command,
            std::time::Duration::from_millis(100),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("DNF query timed out"));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        let mut command = tokio::process::Command::new("/bin/sh");
        command.args(["-c", "printf '[]'; exit 7"]);
        assert!(
            DnfPackageManager::query_output(command)
                .await
                .unwrap_err()
                .to_string()
                .contains("DNF query failed")
        );
    }

    #[tokio::test]
    async fn captured_query_drains_diagnostics_and_preserves_failure_reason() -> Result<()> {
        let mut verbose = tokio::process::Command::new("/bin/sh");
        verbose
            .stderr(std::process::Stdio::piped())
            .args(["-c", "head -c 131072 /dev/zero >&2 && printf '[]'"]);
        let deadline = std::time::Duration::from_secs(5);
        assert_eq!(
            DnfPackageManager::query_output_with_deadline(verbose, deadline).await?,
            b"[]"
        );

        let mut failed = tokio::process::Command::new("/bin/sh");
        failed.stderr(std::process::Stdio::piped()).args([
            "-c",
            "printf 'Loading repositories\nRepository is unavailable\n' >&2; exit 7",
        ]);
        let error = DnfPackageManager::query_output(failed).await.unwrap_err();
        assert!(error.to_string().ends_with("Repository is unavailable"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn orphan_cleanup_preview_preserves_plan_and_protected_package_diagnostics() -> Result<()> {
        use std::os::unix::process::ExitStatusExt as _;

        let output = |code, stdout: &str, stderr: &str| std::process::Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        };
        let preview = DnfPackageManager::orphan_cleanup_preview_output;
        let protected = "Unneeded protected package: leaf-0:1-1.noarch";
        assert_eq!(
            preview(&output(0, "Nothing to do.\n", protected))?,
            ("Nothing to do.\n".into(), protected.into())
        );

        let plan = "Removing:\n leaf noarch 0:1-1\n";
        let abort = "Operation aborted by the user.\n";
        let diagnostics = format!("{protected}\n{abort}");
        assert_eq!(
            preview(&output(1, plan, &diagnostics))?,
            (plan.into(), protected.into())
        );

        for failure in [
            output(7, plan, abort),
            output(1, "", abort),
            output(1, plan, "Failed to resolve the transaction\n"),
            output(1, plan, &format!("Invalid diagnostic: {abort}")),
        ] {
            assert!(preview(&failure).is_err());
        }
        Ok(())
    }

    #[tokio::test]
    async fn stored_query_cancellation_reaps_child_before_removing_private_namespace() -> Result<()>
    {
        let control = tempfile::tempdir()?;
        let directory = tempfile::Builder::new()
            .prefix("owned-store-")
            .tempdir_in(control.path())?;
        let path = directory.path().to_owned();
        let pid_file = control.path().join("query.pid");
        let mut command = tokio::process::Command::new("/bin/sh");
        command
            .args(["-c", "printf '%s' \"$$\" > \"$1\"; exec sleep 30", "--"])
            .arg(&pid_file);
        let task = tokio::spawn(DnfPackageManager::owned_stored_transaction(
            command,
            directory,
            std::time::Duration::from_mins(1),
        ));
        let started = std::time::Instant::now();
        while !pid_file.exists() {
            anyhow::ensure!(
                started.elapsed() < std::time::Duration::from_secs(5),
                "owned query did not start"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let pid = nix::unistd::Pid::from_raw(std::fs::read_to_string(&pid_file)?.parse()?);
        assert!(
            path.is_dir(),
            "query must retain its private input namespace"
        );
        task.abort();
        assert!(task.await.is_err());
        while path.exists() {
            anyhow::ensure!(
                started.elapsed() < std::time::Duration::from_secs(5),
                "cancelled owner failed to settle"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(
            nix::sys::signal::kill(pid, None),
            Err(nix::errno::Errno::ESRCH),
            "namespace disappeared before its child was reaped"
        );
        Ok(())
    }

    #[tokio::test]
    async fn native_query_timeout_reaps_child_before_returning() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let pid_file = directory.path().join("query.pid");
        let mut command = tokio::process::Command::new("/bin/sh");
        command
            .args(["-c", "printf '%s' \"$$\" > \"$1\"; exec sleep 30", "--"])
            .arg(&pid_file);
        let error = DnfPackageManager::query_output_with_deadline(
            command,
            std::time::Duration::from_millis(200),
        )
        .await
        .expect_err("query must time out");
        assert!(error.to_string().contains("DNF query timed out"));
        let pid = nix::unistd::Pid::from_raw(std::fs::read_to_string(pid_file)?.parse()?);
        assert_eq!(
            nix::sys::signal::kill(pid, None),
            Err(nix::errno::Errno::ESRCH)
        );
        Ok(())
    }

    #[tokio::test]
    async fn stored_query_returns_owned_namespace_and_exact_manifest_after_child_exit() -> Result<()>
    {
        let directory = tempfile::tempdir()?;
        let path = directory.path().to_owned();
        let mut command = tokio::process::Command::new("/bin/sh");
        command
            .args([
                "-c",
                "printf 'stored bytes' > \"$1/transaction.json\"; printf 'query output'",
                "--",
            ])
            .arg(&path);
        let (directory, bytes) = DnfPackageManager::owned_stored_transaction(
            command,
            directory,
            std::time::Duration::from_secs(5),
        )
        .await?;
        assert_eq!(bytes, b"stored bytes");
        assert!(path.is_dir());
        drop(directory);
        assert!(!path.exists());
        Ok(())
    }

    #[tokio::test]
    async fn native_history_query_rejects_output_larger_than_64_mib() -> Result<()> {
        let mut command = tokio::process::Command::new("/usr/bin/head");
        command.args(["-c", "67108864", "/dev/zero"]);
        let bytes = DnfPackageManager::query_output_with_deadline(
            command,
            std::time::Duration::from_secs(30),
        )
        .await?;
        assert_eq!(bytes.len(), 67_108_864);
        assert!(
            bytes.iter().all(|byte| *byte == 0),
            "the accepted boundary payload must contain only zero bytes"
        );
        drop(bytes);

        let mut command = tokio::process::Command::new("/usr/bin/head");
        command.args(["-c", "67108865", "/dev/zero"]);
        match DnfPackageManager::query_output_with_deadline(
            command,
            std::time::Duration::from_secs(30),
        )
        .await
        {
            Ok(bytes) => panic!(
                "DNF query accepted oversized output: received {} bytes",
                bytes.len()
            ),
            Err(error) => assert_eq!(error.to_string(), "DNF query output exceeds 64 MiB"),
        }
        Ok(())
    }

    #[test]
    fn native_failure_does_not_turn_planned_versions_into_committed_changes() {
        let transactions: Vec<NativeTransaction> = serde_json::from_str(r#"[{"id":1,"comment":"ours","status":"Error","packages":[{"nevra":"a-0:1-1.noarch","action":"Install"}]}]"#).unwrap();
        assert!(matches!(
            DnfPackageManager::native_outcome(&transactions, "ours").unwrap(),
            NativeOutcome::Failed
        ));
    }

    #[test]
    fn native_interruption_keeps_uuid_without_description_and_rejects_ambiguous_rows() {
        let directory = tempfile::tempdir().unwrap();
        let history =
            crate::core::history::HistoryManager::new_in(directory.path().join("history.json"))
                .unwrap();
        let comment = "omg-550e8400-e29b-41d4-a716-446655440000";
        let transactions: Vec<NativeTransaction> = serde_json::from_str(
            r#"[{"id":73,"comment":"omg-550e8400-e29b-41d4-a716-446655440000","status":"Started","packages":[]},
                {"id":74,"comment":"omg-550e8400-e29b-41d4-a716-446655440001","status":"Ok","packages":[]}]"#,
        ).unwrap();
        let outcome = DnfPackageManager::native_outcome(&transactions, comment).unwrap();
        match &outcome {
            NativeOutcome::Interrupted {
                id,
                comment: observed,
                status,
                actions,
                command,
            } => {
                assert_eq!(*id, 73);
                assert_eq!(observed, comment);
                assert_eq!(status, "Started");
                assert_eq!(*actions, 0);
                assert_eq!(command, "not recorded");
            }
            other => panic!("expected Interrupted, got {other:?}"),
        }
        let error = DnfPackageManager::record_native_result(
            crate::core::history::TransactionType::Remove,
            &history,
            Err(anyhow::anyhow!("original exit 1")),
            Ok(outcome),
        )
        .unwrap_err();
        let diagnostic = format!("{error:#}");
        for expected in [
            comment,
            "73",
            "Started",
            "0 package action(s)",
            "not recorded",
            "original exit 1",
        ] {
            assert!(
                diagnostic.contains(expected),
                "missing {expected}: {diagnostic}"
            );
        }
        assert!(history.load().unwrap().is_empty());
        assert!(matches!(
            DnfPackageManager::native_outcome(&transactions[1..], comment).unwrap(),
            NativeOutcome::NoTransaction
        ));
        let duplicates: Vec<NativeTransaction> = serde_json::from_str(
            r#"[{"id":73,"comment":"omg-550e8400-e29b-41d4-a716-446655440000","status":"Started","packages":[]},
                {"id":75,"comment":"omg-550e8400-e29b-41d4-a716-446655440000","status":"Ok","packages":[]}]"#,
        ).unwrap();
        let error = DnfPackageManager::native_outcome(&duplicates, comment).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Duplicate DNF transaction correlation")
        );
        assert!(history.load().unwrap().is_empty());
    }

    #[test]
    fn reads_native_translated_header() {
        let blob = include_bytes!("../../tests/data/fedora-gnat-srpm.rpmhdr");
        let directory = write_packages_db(&[blob.as_slice()]);
        let packages = DnfPackageManager::read_rpm_sqlite(&directory.path().join("rpmdb.sqlite"))
            .expect("translated native header");
        assert_eq!(
            packages
                .iter()
                .map(|package| (
                    package.name.as_str(),
                    package.version.as_str(),
                    package.release.as_str(),
                    package.architecture.as_str(),
                    package.summary.as_str(),
                ))
                .collect::<Vec<_>>(),
            vec![(
                "gnat-srpm-macros",
                "7",
                "2.fc44",
                "noarch",
                "RPM macros needed when source packages that need GNAT are built",
            )]
        );
    }

    #[test]
    fn string_arrays_require_every_declared_terminator() {
        for kind in [8, 9] {
            let valid = strict_header(&[(1004, kind, 0, 2)], b"first\0second\0");
            assert!(DnfPackageManager::parse_rpm_header(&valid).is_ok());
            let missing = strict_header(&[(1004, kind, 0, 2)], b"first\0second");
            assert!(DnfPackageManager::parse_rpm_header(&missing).is_err());
            let mut outside = missing;
            outside.push(0);
            assert!(DnfPackageManager::parse_rpm_header(&outside).is_err());
        }
    }

    #[test]
    fn test_rpm_header_parsing() {
        let mut header = Vec::new();
        header.extend_from_slice(&[0, 0, 0, 1]); // 1 entry
        header.extend_from_slice(&[0, 0, 0, 5]); // 5 bytes data ("test\0")
        // Entry: tag=1000 (NAME), type=6 (STRING), offset=0.
        // librpm count-one invariant (rnd-pm-10): STRING carries exactly one
        // element; the old fixture's count=4 encoded pre-S1 lax parsing.
        header.extend_from_slice(&1000u32.to_be_bytes());
        header.extend_from_slice(&6u32.to_be_bytes());
        header.extend_from_slice(&0i32.to_be_bytes());
        header.extend_from_slice(&1u32.to_be_bytes());
        // Data: "test\0"
        header.extend_from_slice(b"test\0");

        let result = DnfPackageManager::parse_rpm_header(&header);
        assert!(result.is_ok());

        let tags = result.unwrap();
        assert_eq!(tags, HashMap::from([(1000, b"test".as_slice())]));
    }

    fn strict_header(entries: &[(u32, u32, i32, u32)], data: &[u8]) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        header.extend_from_slice(&(data.len() as u32).to_be_bytes());
        for (tag, typ, off, count) in entries {
            header.extend_from_slice(&tag.to_be_bytes());
            header.extend_from_slice(&typ.to_be_bytes());
            header.extend_from_slice(&off.to_be_bytes());
            header.extend_from_slice(&count.to_be_bytes());
        }
        header.extend_from_slice(data);
        header
    }

    #[test]
    fn s1_rejects_negative_entry_offset() {
        let blob = strict_header(&[(1000, 6, -1, 1)], b"test\0");
        assert!(DnfPackageManager::parse_rpm_header(&blob).is_err());
    }

    #[test]
    fn s1_rejects_unknown_tag_type() {
        for bad_type in [0u32, 10, 12] {
            let blob = strict_header(&[(1000, bad_type, 0, 1)], b"abcd");
            assert!(
                DnfPackageManager::parse_rpm_header(&blob).is_err(),
                "type {bad_type} must be rejected"
            );
        }
    }

    #[test]
    fn s1_enforces_string_count_one() {
        let blob = strict_header(&[(1000, 6, 0, 4)], b"test\0");
        assert!(DnfPackageManager::parse_rpm_header(&blob).is_err());
    }

    #[test]
    fn s1_rejects_string_missing_terminator() {
        let blob = strict_header(&[(1004, 6, 0, 1)], b"no-nul");
        assert!(DnfPackageManager::parse_rpm_header(&blob).is_err());
    }

    #[test]
    fn s1_rejects_data_region_outside_declared_payload() {
        // Offset points past the declared data size.
        let blob = strict_header(&[(1000, 6, 99, 1)], b"test\0");
        assert!(DnfPackageManager::parse_rpm_header(&blob).is_err());
    }

    #[test]
    fn s1_rejects_undeclared_trailing_payload_use() {
        // Data region ends at data_start+data_size; a string terminator may
        // not be satisfied by bytes beyond it.
        let mut blob = strict_header(&[(1000, 6, 0, 1)], b"xxxxx");
        blob.extend_from_slice(b"\0"); // NUL outside the declared payload
        assert!(DnfPackageManager::parse_rpm_header(&blob).is_err());
    }

    #[test]
    fn test_parse_rpm_header_rejects_empty_header() {
        let error = DnfPackageManager::parse_rpm_header(&[0u8; 32])
            .expect_err("an empty header must not parse as a package");
        assert!(
            error.to_string().contains("must contain entries"),
            "got: {error}"
        );
    }

    #[test]
    fn database_reader_rejects_archive_framing() {
        let mut archive = vec![0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0];
        archive.extend(strict_header(&[(1000, 6, 0, 1)], b"test\0"));
        assert!(DnfPackageManager::parse_rpm_header(&archive).is_err());
    }

    #[test]
    fn user_installed_output_is_parsed_as_a_name_set() {
        let names = DnfPackageManager::parse_user_installed_names(b"bash\n\nvim\n")
            .expect("valid dnf output");
        assert!(names.contains("bash"));
        assert!(names.contains("vim"));
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn install_reason_failure_preserves_the_rpm_inventory() {
        let packages = [InstalledPackage {
            name: "bash".to_string(),
            version: "5.2".to_string(),
            release: "1.fc42".to_string(),
            architecture: "x86_64".to_string(),
            summary: "GNU shell".to_string(),
        }];

        let error = DnfPackageManager::explicit_package_names(
            &packages,
            Err(anyhow::anyhow!("repoquery unavailable")),
        )
        .expect_err(
            "unavailable install reasons must not become successful zero explicit packages",
        );
        assert!(format!("{error:#}").contains("repoquery unavailable"));

        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "bash");
        assert_eq!(packages[0].version, "5.2");
        assert_eq!(packages[0].release, "1.fc42");
        assert_eq!(packages[0].summary, "GNU shell");

        let explicit = DnfPackageManager::explicit_package_names(
            &packages,
            Ok(HashSet::from(["bash".into(), "not-installed".into()])),
        )
        .unwrap();
        assert_eq!(explicit, ["bash"]);
        let explicit =
            DnfPackageManager::explicit_package_names(&packages, Ok(HashSet::new())).unwrap();
        assert!(explicit.is_empty());
    }

    #[tokio::test]
    async fn installed_inventory_observes_external_removal() -> Result<()> {
        let blob = include_bytes!("../../tests/data/fedora-publicsuffix.rpmhdr");
        let directory = write_packages_db(&[blob.as_slice()]);
        let mut manager = DnfPackageManager::new();
        manager.rpm_db_path = directory.path().join("rpmdb.sqlite");
        assert_eq!(manager.list_installed().await?.len(), 1);
        assert!(manager.is_installed_fast("publicsuffix-list-dafsa")?);
        assert!(!manager.is_installed_fast("definitely-not-installed")?);
        let database = Connection::open(&manager.rpm_db_path)?;
        database.execute("DELETE FROM Packages", [])?;

        assert!(
            !manager.is_installed("publicsuffix-list-dafsa").await?,
            "a cached positive must not survive an external RPM removal"
        );
        assert!(!manager.is_installed_fast("publicsuffix-list-dafsa")?);
        assert!(manager.list_installed().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn installed_inventory_preserves_database_order_across_cache_hits() -> Result<()> {
        let first = named_rpm_header("first");
        let middle = named_rpm_header("middle");
        let last = rpm_string_header([
            (rpm_tags::NAME, "first"),
            (rpm_tags::VERSION, "1.0"),
            (rpm_tags::RELEASE, "1.fc44"),
            (rpm_tags::ARCH, "i686"),
        ]);
        let directory = write_packages_db(&[&first, &middle, &last]);
        let mut manager = DnfPackageManager::new();
        manager.rpm_db_path = directory.path().join("rpmdb.sqlite");

        for _ in 0..2 {
            let names: Vec<_> = manager
                .list_installed()
                .await?
                .into_iter()
                .map(|package| package.name)
                .collect();
            assert_eq!(names, ["first.noarch", "middle.noarch", "first.i686"]);
        }
        Ok(())
    }

    #[tokio::test]
    async fn installed_inventory_observes_commits_when_file_metadata_matches() -> Result<()> {
        for journal_mode in ["DELETE", "WAL"] {
            let blob = include_bytes!("../../tests/data/fedora-publicsuffix.rpmhdr");
            let directory = write_packages_db(&[blob.as_slice()]);
            let mut manager = DnfPackageManager::new();
            manager.rpm_db_path = directory.path().join("rpmdb.sqlite");
            let database = Connection::open(&manager.rpm_db_path)?;
            database.pragma_update(None, "journal_mode", journal_mode)?;
            assert_eq!(manager.list_installed().await?.len(), 1);
            assert!(
                manager.cached_installed_packages().is_some(),
                "first inventory read must initialize a cache in {journal_mode} mode"
            );
            database.execute("DELETE FROM Packages", [])?;

            // Model a filesystem whose timestamp granularity cannot distinguish
            // the commit: force the cached stat fingerprint to equal the current
            // one without altering the cached inventory or SQLite observer.
            manager
                .cache_write()
                .as_mut()
                .expect("cached inventory")
                .observation
                .identity =
                RpmDatabaseIdentity::read(&manager.rpm_db_path).expect("database identity");
            assert!(
                !manager.is_installed("publicsuffix-list-dafsa").await?,
                "{journal_mode}"
            );
            assert!(manager.list_installed().await?.is_empty(), "{journal_mode}");

            // The observer must not leave a read transaction blocking checkpoint.
            let busy: i64 =
                database.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
            assert_eq!(busy, 0, "{journal_mode}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn installed_inventory_observes_wal_only_removal() -> Result<()> {
        let blob = include_bytes!("../../tests/data/fedora-publicsuffix.rpmhdr");
        let directory = write_packages_db(&[blob.as_slice()]);
        let mut manager = DnfPackageManager::new();
        manager.rpm_db_path = directory.path().join("rpmdb.sqlite");
        let database = Connection::open(&manager.rpm_db_path)?;
        database.pragma_update(None, "journal_mode", "WAL")?;
        assert_eq!(manager.list_installed().await?.len(), 1);
        assert!(
            manager.is_installed("publicsuffix-list-dafsa").await?,
            "the private fixture package must be present before testing its removal"
        );
        let original_bytes = std::fs::read(&manager.rpm_db_path)?;
        let original_mtime = std::fs::metadata(&manager.rpm_db_path)?.modified()?;

        database.execute("DELETE FROM Packages", [])?;
        assert_eq!(std::fs::read(&manager.rpm_db_path)?, original_bytes);
        assert_eq!(
            std::fs::metadata(&manager.rpm_db_path)?.modified()?,
            original_mtime
        );
        assert!(
            !manager.is_installed("publicsuffix-list-dafsa").await?,
            "committed WAL changes must invalidate an unchanged main file"
        );
        Ok(())
    }

    #[tokio::test]
    async fn installed_inventory_observes_replacement_with_preserved_mtime() -> Result<()> {
        let blob = include_bytes!("../../tests/data/fedora-publicsuffix.rpmhdr");
        let directory = write_packages_db(&[blob.as_slice()]);
        let mut manager = DnfPackageManager::new();
        manager.rpm_db_path = directory.path().join("rpmdb.sqlite");
        assert_eq!(manager.list_installed().await?.len(), 1);
        assert!(
            manager.is_installed("publicsuffix-list-dafsa").await?,
            "the private fixture package must be present before testing its removal"
        );
        let original_mtime = std::fs::metadata(&manager.rpm_db_path)?.modified()?;
        let replacement = write_packages_db(&[]);
        let replacement_path = replacement.path().join("rpmdb.sqlite");
        std::fs::File::open(&replacement_path)?
            .set_times(std::fs::FileTimes::new().set_modified(original_mtime))?;
        std::fs::rename(replacement_path, &manager.rpm_db_path)?;

        assert_eq!(
            std::fs::metadata(&manager.rpm_db_path)?.modified()?,
            original_mtime
        );
        assert!(!manager.is_installed("publicsuffix-list-dafsa").await?);
        Ok(())
    }

    #[tokio::test]
    async fn installed_inventory_refreshes_an_empty_snapshot_after_installation() -> Result<()> {
        let directory = write_packages_db(&[]);
        let mut manager = DnfPackageManager::new();
        manager.rpm_db_path = directory.path().join("rpmdb.sqlite");
        assert!(manager.list_installed().await?.is_empty());
        assert!(
            manager
                .cached_installed_packages()
                .expect("empty snapshot")
                .is_empty()
        );
        let database = Connection::open(&manager.rpm_db_path)?;
        let blob = include_bytes!("../../tests/data/fedora-publicsuffix.rpmhdr");
        database.execute("INSERT INTO Packages (blob) VALUES (?1)", [blob.as_slice()])?;

        assert!(manager.is_installed("publicsuffix-list-dafsa").await?);
        assert_eq!(manager.list_installed().await?.len(), 1);
        manager.cache_handle().invalidate_installed_cache();
        assert!(manager.cached_installed_packages().is_none());
        Ok(())
    }

    #[test]
    fn installed_cache_rejects_changed_or_unobserved_generation() -> Result<()> {
        let blob = include_bytes!("../../tests/data/fedora-publicsuffix.rpmhdr");
        let directory = write_packages_db(&[blob.as_slice()]);
        let mut manager = DnfPackageManager::new();
        manager.rpm_db_path = directory.path().join("rpmdb.sqlite");
        let mut observed = RpmDatabaseObservation::read(&manager.rpm_db_path);
        let packages = DnfPackageManager::read_rpm_sqlite(&manager.rpm_db_path)?;
        let database = Connection::open(&manager.rpm_db_path)?;
        database.execute("DELETE FROM Packages", [])?;

        // Even if metadata fails to reveal a commit between the inventory read
        // and publication, the original observer must reject the old inventory.
        observed.as_mut().expect("database observer").identity =
            RpmDatabaseIdentity::read(&manager.rpm_db_path).expect("database identity");
        let packages = Arc::new(packages);
        manager.publish_installed_packages(Arc::clone(&packages), observed);
        assert!(manager.cached_installed_packages().is_none());
        manager.publish_installed_packages(packages, None);
        assert!(manager.cached_installed_packages().is_none());
        Ok(())
    }

    #[tokio::test]
    async fn installed_cache_rejects_unobservable_database_files() -> Result<()> {
        let blob = include_bytes!("../../tests/data/fedora-publicsuffix.rpmhdr");
        let directory = write_packages_db(&[blob.as_slice()]);
        let mut manager = DnfPackageManager::new();
        manager.rpm_db_path = directory.path().join("rpmdb.sqlite");
        assert_eq!(manager.list_installed().await?.len(), 1);
        let cached = manager
            .cached_installed_packages()
            .expect("private fixture cache must exist before testing invalidation");
        assert_eq!(
            cached
                .iter()
                .map(|package| (
                    package.name.as_str(),
                    package.version.as_str(),
                    package.release.as_str(),
                    package.architecture.as_str(),
                ))
                .collect::<Vec<_>>(),
            vec![("publicsuffix-list-dafsa", "20260116", "1.fc44", "noarch")]
        );
        let wal = directory.path().join("rpmdb.sqlite-wal");
        std::fs::create_dir(&wal)?;
        assert!(manager.cached_installed_packages().is_none());
        std::fs::remove_dir(wal)?;
        std::fs::remove_file(&manager.rpm_db_path)?;
        assert!(manager.cached_installed_packages().is_none());
        Ok(())
    }

    #[test]
    fn installed_cache_publication_is_idempotent_and_preserves_multilib_names() {
        let directory = write_packages_db(&[]);
        let mut manager = DnfPackageManager::new();
        manager.rpm_db_path = directory.path().join("rpmdb.sqlite");
        let identity = RpmDatabaseObservation::read(&manager.rpm_db_path);
        let packages: Vec<_> = ["x86_64", "i686"]
            .into_iter()
            .map(|architecture| InstalledPackage {
                name: "glibc".to_string(),
                version: "2.41".to_string(),
                release: "1.fc42".to_string(),
                architecture: architecture.to_string(),
                summary: "C library".to_string(),
            })
            .collect();

        let packages = Arc::new(packages);
        manager.publish_installed_packages(Arc::clone(&packages), identity.clone());
        manager.publish_installed_packages(packages, identity);

        let cached = manager
            .cached_installed_packages()
            .expect("populated cache");
        assert_eq!(cached.len(), 2);
        let mut identities: Vec<_> = cached
            .iter()
            .map(|package| {
                (
                    package.name.as_str(),
                    package.version.as_str(),
                    package.release.as_str(),
                    package.architecture.as_str(),
                )
            })
            .collect();
        identities.sort_unstable();
        assert_eq!(
            identities,
            [
                ("glibc", "2.41", "1.fc42", "i686"),
                ("glibc", "2.41", "1.fc42", "x86_64"),
            ]
        );
    }

    #[test]
    fn explicit_package_names_collapse_parallel_installed_versions() {
        let packages = vec![
            InstalledPackage {
                name: "kernel-core".to_string(),
                version: "6.17.1".to_string(),
                release: "1.fc44".to_string(),
                architecture: "x86_64".to_string(),
                summary: "Kernel".to_string(),
            },
            InstalledPackage {
                name: "kernel-core".to_string(),
                version: "6.17.2".to_string(),
                release: "1.fc44".to_string(),
                architecture: "x86_64".to_string(),
                summary: "Kernel".to_string(),
            },
            InstalledPackage {
                name: "kernel-modules".to_string(),
                version: "6.17.2".to_string(),
                release: "1.fc44".to_string(),
                architecture: "x86_64".to_string(),
                summary: "Kernel modules".to_string(),
            },
        ];

        assert_eq!(
            DnfPackageManager::explicit_package_names(
                &packages,
                Ok(HashSet::from(["kernel-core".into()])),
            )
            .unwrap(),
            vec!["kernel-core"]
        );
    }

    #[test]
    fn installed_cache_publication_replaces_the_previous_snapshot() {
        let directory = write_packages_db(&[]);
        let mut manager = DnfPackageManager::new();
        manager.rpm_db_path = directory.path().join("rpmdb.sqlite");
        let identity = RpmDatabaseObservation::read(&manager.rpm_db_path);
        manager.publish_installed_packages(
            Arc::new(vec![InstalledPackage {
                name: "glibc".to_string(),
                version: "2.41".to_string(),
                release: "1.fc42.x86_64".to_string(),
                architecture: "x86_64".to_string(),
                summary: "C library".to_string(),
            }]),
            identity.clone(),
        );
        manager.publish_installed_packages(
            Arc::new(vec![InstalledPackage {
                name: "bash".to_string(),
                version: "5.2".to_string(),
                release: "1.fc42".to_string(),
                architecture: "x86_64".to_string(),
                summary: "GNU shell".to_string(),
            }]),
            identity,
        );

        let cached = manager
            .cached_installed_packages()
            .expect("populated cache");
        assert_eq!(cached.len(), 1);
        assert_eq!(cached[0].name, "bash");
        assert_eq!(cached[0].summary, "GNU shell");
    }

    #[test]
    fn test_parse_rpm_qa_line_reads_installed_package() {
        let pkg = DnfPackageManager::parse_rpm_qa_line(
            "bash\t5.2.15\t1.fc39\tThe GNU Bourne Again shell\t0\tx86_64",
        )
        .expect("valid rpm -qa line");
        assert_eq!(pkg.name, "bash");
        assert_eq!(pkg.version, "5.2.15");
        assert_eq!(pkg.architecture, "x86_64");
    }

    #[test]
    fn sqlite_string_values_exclude_rpm_terminators() {
        let package = DnfPackageManager::parse_package_from_blob(&named_rpm_header("bash"))
            .expect("valid RPM name header");
        assert_eq!(package.name, "bash");
    }

    #[test]
    fn test_parse_rpm_qa_line_rejects_truncated_row() {
        let error = DnfPackageManager::parse_rpm_qa_line("bash\t5.2.15")
            .expect_err("truncated rpm -qa line must not skip the package");
        assert!(
            error.to_string().contains("malformed rpm -qa output"),
            "got: {error}"
        );
    }

    #[test]
    fn rpm_query_rejects_incomplete_installed_identity() {
        let complete = ["bash", "5.2.15", "1.fc39", "GNU shell", "0", "x86_64"];
        for field in [0, 1, 2, 5] {
            for missing in ["", "(none)"] {
                let mut fields = complete;
                fields[field] = missing;
                assert!(
                    DnfPackageManager::parse_rpm_qa_line(&fields.join("\t")).is_err(),
                    "incomplete installed RPM identity accepted: {fields:?}"
                );
            }
        }
    }

    #[test]
    fn rpm_sqlite_rejects_incomplete_installed_identity() {
        let fields = [
            (rpm_tags::NAME, "bash"),
            (rpm_tags::VERSION, "5.2.15"),
            (rpm_tags::RELEASE, "1.fc39"),
            (rpm_tags::ARCH, "x86_64"),
        ];
        for (missing, _) in fields {
            let header = rpm_string_header(fields.into_iter().filter(|(tag, _)| *tag != missing));
            let directory = write_packages_db(&[&header]);
            assert!(
                DnfPackageManager::read_rpm_sqlite(&directory.path().join("rpmdb.sqlite")).is_err(),
                "installed RPM identity accepted without tag {missing}"
            );
        }
    }

    #[test]
    fn rpm_keeps_legacy_architectureless_trust_records() -> Result<()> {
        let header = rpm_string_header([
            (rpm_tags::NAME, "gpg-pubkey"),
            (rpm_tags::VERSION, "3b94a80e"),
            (rpm_tags::RELEASE, "6665a2fc"),
        ]);
        let stored_key = DnfPackageManager::parse_package_from_blob(&header)?;
        let queried_key = DnfPackageManager::parse_rpm_qa_line(
            "gpg-pubkey\t3b94a80e\t6665a2fc\tOpenPGP key\t0\t(none)",
        )?;
        for key in [stored_key, queried_key] {
            assert_eq!(key.identity(), "gpg-pubkey");
            assert_eq!(key.version, "3b94a80e");
            assert_eq!(key.release, "6665a2fc");
        }
        Ok(())
    }

    fn named_rpm_header(name: &str) -> Vec<u8> {
        rpm_string_header([
            (rpm_tags::NAME, name),
            (rpm_tags::VERSION, "1.0"),
            (rpm_tags::RELEASE, "1.fc44"),
            (rpm_tags::ARCH, "noarch"),
        ])
    }

    fn rpm_string_header<'a>(fields: impl IntoIterator<Item = (u32, &'a str)>) -> Vec<u8> {
        let mut entries = Vec::new();
        let mut data = Vec::new();
        for (tag, value) in fields {
            entries.push((tag, 6, i32::try_from(data.len()).unwrap(), 1));
            data.extend_from_slice(value.as_bytes());
            data.push(0);
        }
        strict_header(&entries, &data)
    }

    fn write_packages_db(blobs: &[&[u8]]) -> tempfile::TempDir {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let db = dir.path().join("rpmdb.sqlite");
        let conn = Connection::open(&db).expect("open sqlite");
        conn.execute(
            "CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB NOT NULL)",
            [],
        )
        .expect("create Packages");
        for blob in blobs {
            conn.execute("INSERT INTO Packages (blob) VALUES (?1)", [blob.to_vec()])
                .expect("insert blob");
        }
        dir
    }

    #[tokio::test]
    async fn installed_lookup_reads_one_package_when_an_unrelated_header_is_unreadable()
    -> Result<()> {
        let header = named_rpm_header("omg-indexed-read-fixture");
        let directory = write_packages_db(&[header.as_slice(), &[0; 32]]);
        let mut manager = DnfPackageManager::new();
        manager.rpm_db_path = directory.path().join("rpmdb.sqlite");
        let database = Connection::open(&manager.rpm_db_path)?;
        database.execute_batch(
            "CREATE TABLE Name (key TEXT NOT NULL, hnum INTEGER NOT NULL, idx INTEGER NOT NULL);
             CREATE INDEX Name_key_idx ON Name(key);
             INSERT INTO Name VALUES ('omg-indexed-read-fixture', 1, 0), ('unrelated', 2, 0);",
        )?;
        drop(database);

        assert!(manager.is_installed("omg-indexed-read-fixture").await?);
        Ok(())
    }

    #[tokio::test]
    async fn indexed_installed_info_preserves_qualified_and_literal_matches() -> Result<()> {
        let native = include_bytes!("../../tests/data/fedora-publicsuffix.rpmhdr");
        let literal = named_rpm_header("publicsuffix-list-dafsa.noarch");
        let directory = write_packages_db(&[native.as_slice(), &literal]);
        let mut manager = DnfPackageManager::new();
        manager.rpm_db_path = directory.path().join("rpmdb.sqlite");
        let database = Connection::open(&manager.rpm_db_path)?;
        database.execute_batch(
            "CREATE TABLE Name (key TEXT NOT NULL, hnum INTEGER NOT NULL, idx INTEGER NOT NULL);
             CREATE INDEX Name_key_idx ON Name(key);
             INSERT INTO Name VALUES
               ('publicsuffix-list-dafsa', 1, 0), ('publicsuffix-list-dafsa.noarch', 2, 0);",
        )?;
        drop(database);

        let exact = DnfPackageManager::parse_package_from_blob(native)?.nevra();
        let package = manager
            .info(&exact)
            .await?
            .context("missing installed package")?;
        assert_eq!(package.name, "publicsuffix-list-dafsa.noarch");
        assert!(package.installed);

        let error = manager
            .info("publicsuffix-list-dafsa.noarch")
            .await
            .expect_err("the literal package name also matches this selector");
        assert!(error.to_string().contains("multiple installed builds"));
        Ok(())
    }

    #[tokio::test]
    async fn indexed_installed_lookup_falls_back_on_inconsistent_rows() -> Result<()> {
        let header = named_rpm_header("indexed-fallback-fixture");
        let directory = write_packages_db(&[&header]);
        let mut manager = DnfPackageManager::new();
        manager.rpm_db_path = directory.path().join("rpmdb.sqlite");
        let database = Connection::open(&manager.rpm_db_path)?;
        database.execute_batch(
            "CREATE TABLE Name (key TEXT NOT NULL, hnum INTEGER NOT NULL, idx INTEGER NOT NULL);
             CREATE INDEX Name_key_idx ON Name(key);
             INSERT INTO Name VALUES ('indexed-fallback-fixture', 2, 0);",
        )?;
        drop(database);

        assert!(manager.is_installed("indexed-fallback-fixture").await?);
        assert!(!manager.is_installed("indexed-fallback-absent").await?);
        Ok(())
    }

    #[test]
    fn test_read_rpm_sqlite_malformed_blob_is_error() {
        let dir = write_packages_db(&[&[0u8; 32]]);
        let error = DnfPackageManager::read_rpm_sqlite(&dir.path().join("rpmdb.sqlite"))
            .expect_err("malformed header must not look like an empty inventory");
        let message = format!("{error:#}");
        assert!(
            message.contains("Malformed RPM header in Packages table"),
            "got: {message}"
        );
    }

    #[test]
    fn test_read_rpm_sqlite_mixed_blobs_do_not_drop_corrupt_row() {
        let valid = named_rpm_header("bash");
        let dir = write_packages_db(&[valid.as_slice(), &[0u8; 32]]);
        let error = DnfPackageManager::read_rpm_sqlite(&dir.path().join("rpmdb.sqlite"))
            .expect_err("one corrupt row must not omit that package from the catalog");
        let message = format!("{error:#}");
        assert!(
            message.contains("Malformed RPM header in Packages table"),
            "got: {message}"
        );
    }

    #[test]
    fn malformed_row_reports_position_decoded_count_and_cause() {
        let valid = named_rpm_header("bash");
        let dir = write_packages_db(&[valid.as_slice(), &[0u8; 32]]);
        let error = DnfPackageManager::read_rpm_sqlite(&dir.path().join("rpmdb.sqlite"))
            .expect_err("corrupt row must fail loudly");
        let message = format!("{error:#}");
        for needle in [
            "row 2",
            "1 packages decoded before the failure",
            "must contain entries",
        ] {
            assert!(message.contains(needle), "missing {needle:?} in: {message}");
        }
    }
}
#[test]
fn ordinary_rpm_inventory_preserves_epoch() {
    let package =
        DnfPackageManager::parse_rpm_qa_line("example\t1.0\t1.fc44\tsummary\t2\tx86_64").unwrap();
    assert_eq!(package.version, "2:1.0");
}
