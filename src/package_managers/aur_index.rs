//! Persistent rkyv-based index for AUR metadata
//!
//! This module provides a fast, zero-copy binary index for AUR package metadata,
//! reading the cache into an owned, aligned snapshot before accessing entries.

use std::fs::File;
use std::io::{BufReader, Read, Write as _};
use std::path::Path;

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use rkyv::util::AlignedVec;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use tempfile::NamedTempFile;

use crate::package_managers::aur_metadata::AurJsonPackage;
use crate::package_managers::parse_version;
use crate::package_managers::types::compare_versions;

/// Minimal AUR package metadata stored in the index.
/// Using rkyv for zero-copy deserialization.
#[derive(Archive, RkyvDeserialize, RkyvSerialize, Debug, Clone, PartialEq)]
pub struct AurEntry {
    pub name: String,
    pub version: String,
    pub maintainer: Option<String>,
    pub last_modified: Option<i64>,
    pub description: Option<String>,
    pub num_votes: i32,
    pub popularity: f64,
    pub out_of_date: Option<i64>,
}

/// The root of the rkyv archive
#[derive(Archive, RkyvDeserialize, RkyvSerialize, Debug)]
pub struct AurArchive {
    /// Entries sorted by name for binary search
    pub entries: Vec<AurEntry>,
}

const MAX_AUR_INDEX_BYTES: u64 = 512 * 1024 * 1024;

pub struct AurIndex {
    bytes: AlignedVec,
}

impl std::fmt::Debug for AurIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AurIndex").finish_non_exhaustive()
    }
}

impl AurIndex {
    /// Read and validate an owned snapshot before exposing archived references.
    pub fn open(path: &Path) -> Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)
            .with_context(|| format!("Failed to open index at {}", path.display()))?;
        let metadata = file.metadata()?;
        anyhow::ensure!(metadata.is_file(), "AUR index must be a regular file");
        anyhow::ensure!(
            metadata.len() <= MAX_AUR_INDEX_BYTES,
            "AUR index exceeds size limit"
        );

        let mut bytes = AlignedVec::new();
        bytes.extend_from_reader(&mut Read::by_ref(&mut file).take(MAX_AUR_INDEX_BYTES))?;
        let mut extra = [0];
        anyhow::ensure!(file.read(&mut extra)? == 0, "AUR index exceeds size limit");
        let index = Self { bytes };
        index.archive()?;
        Ok(index)
    }

    /// Access the archived data with validation
    fn archive(&self) -> Result<&ArchivedAurArchive> {
        rkyv::access::<rkyv::Archived<AurArchive>, rkyv::rancor::Error>(&self.bytes)
            .map_err(|e| anyhow::anyhow!("Corrupted AUR index: {e}"))
    }

    /// Get metadata for a specific package (zero-copy)
    ///
    /// Returns a reference into the owned snapshot, independent of later file writes.
    pub fn get(&self, name: &str) -> Result<Option<&ArchivedAurEntry>> {
        let archive = self.archive()?;
        let Ok(idx) = archive
            .entries
            .binary_search_by_key(&name, |e: &ArchivedAurEntry| e.name.as_str())
        else {
            return Ok(None);
        };
        Ok(Some(&archive.entries[idx]))
    }

    /// Search for packages matching a query (substring match in name or description).
    ///
    /// Case-insensitive comparison reuses a single scratch buffer instead of
    /// allocating two lowercase copies per entry (the index holds ~90k rows).
    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<&ArchivedAurEntry>> {
        let archive = self.archive()?;
        let query_lower = query.to_lowercase();
        let mut lower_buf = String::new();

        Ok(archive
            .entries
            .iter()
            .filter(|e| {
                lower_buf.clear();
                lower_buf.extend(e.name.as_str().chars().flat_map(char::to_lowercase));
                if lower_buf.contains(&query_lower) {
                    return true;
                }
                match e.description.as_ref() {
                    Some(desc) => {
                        lower_buf.clear();
                        lower_buf.extend(desc.as_str().chars().flat_map(char::to_lowercase));
                        lower_buf.contains(&query_lower)
                    }
                    None => false,
                }
            })
            .take(limit)
            .collect())
    }

    /// Batch update check against the index.
    ///
    /// Returns `(updates, missing)`:
    /// - `updates`: remote versions newer than the local ones, for packages
    ///   present in the index;
    /// - `missing`: queried package names absent from this index, or whose
    ///   index version fails strict parsing, so callers can fall back to the
    ///   RPC for exactly those names instead of either treating them as
    ///   up-to-date or re-querying everything.
    pub fn updates_for(
        &self,
        local_pkgs: &[(String, alpm_types::Version)],
    ) -> Result<(
        Vec<(String, alpm_types::Version, alpm_types::Version)>,
        Vec<String>,
    )> {
        let mut updates = Vec::new();
        let mut missing = Vec::new();
        let archive = self.archive()?;

        for (name, local_version) in local_pkgs {
            match archive
                .entries
                .binary_search_by_key(&name.as_str(), |e: &ArchivedAurEntry| e.name.as_str())
            {
                Ok(idx) => {
                    let entry = &archive.entries[idx];
                    // A remote version that fails the strict parser must not
                    // compare as a fabricated 0 (ARCH-R14). Report the name as
                    // missing so the caller re-checks it through the live RPC
                    // instead of silently treating the package as current.
                    let remote_version = parse_version(entry.version.as_str());
                    match remote_version {
                        Some(remote_version)
                            if compare_versions(&remote_version, local_version)
                                == std::cmp::Ordering::Greater =>
                        {
                            updates.push((name.clone(), local_version.clone(), remote_version));
                        }
                        Some(_) => {}
                        None => {
                            tracing::warn!(
                                "AUR index entry '{name}' has unparseable version '{}'; rechecking via RPC",
                                entry.version.as_str()
                            );
                            missing.push(name.clone());
                        }
                    }
                }
                Err(_) => missing.push(name.clone()),
            }
        }

        Ok((updates, missing))
    }
}

/// Build the binary index from the AUR JSON archive
pub fn build_index(json_path: &Path, output_path: &Path) -> Result<()> {
    let file = File::open(json_path).context("Failed to open AUR JSON")?;
    let reader = BufReader::new(file);
    let decoder = GzDecoder::new(reader);

    // Parse the JSON array. AUR's metadata is a large array of objects.
    let mut raw_entries: Vec<AurJsonPackage> = serde_json::from_reader::<_, BoundedPackages>(
        crate::runtimes::common::BudgetedReader::new(decoder, 256 * 1024 * 1024),
    )
    .context("Failed to parse bounded AUR JSON metadata")?
    .0;

    // Sort by name for binary search (critical for zero-copy lookups)
    raw_entries.sort_by(|a, b| a.name.cmp(&b.name));

    let entries = raw_entries
        .into_iter()
        .map(|p| AurEntry {
            name: p.name,
            version: p.version,
            maintainer: p.maintainer,
            last_modified: p.last_modified,
            description: p.description,
            num_votes: p.num_votes.unwrap_or(0),
            popularity: p.popularity.unwrap_or(0.0),
            out_of_date: p.out_of_date,
        })
        .collect();

    let archive = AurArchive { entries };

    // Serialize to rkyv format
    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&archive)
        .map_err(|e| anyhow::anyhow!("Serialization error: {e}"))?;

    // Use a temporary file for atomic update to avoid corrupting the index
    let parent = output_path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp =
        NamedTempFile::new_in(parent).context("Failed to create temporary index file")?;
    temp.write_all(&bytes)
        .context("Failed to write index data")?;
    temp.as_file_mut()
        .sync_all()
        .context("Failed to sync AUR index")?;
    temp.persist(output_path)
        .map_err(|error| error.error)
        .context("Failed to persist index file")?;

    Ok(())
}

struct BoundedPackages(Vec<AurJsonPackage>);
impl<'de> serde::Deserialize<'de> for BoundedPackages {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct PackagesVisitor;
        impl<'de> serde::de::Visitor<'de> for PackagesVisitor {
            type Value = BoundedPackages;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a bounded AUR package array")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut packages = Vec::new();
                while let Some(package) = seq.next_element::<AurJsonPackage>()? {
                    if packages.len() == 250_000
                        || package.name.len() > 256
                        || package
                            .description
                            .as_ref()
                            .is_some_and(|text| text.len() > 65536)
                    {
                        return Err(serde::de::Error::custom(
                            "AUR metadata exceeds record/field limit",
                        ));
                    }
                    packages.push(package);
                }
                Ok(BoundedPackages(packages))
            }
        }
        deserializer.deserialize_seq(PackagesVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Strict-parse helper for fixtures: every test version is expected to
    /// parse; failures must never fall back to a fabricated zero.
    fn v(s: &str) -> alpm_types::Version {
        parse_version(s).expect("valid test version")
    }

    fn open_test_index(data: &str) -> Result<(tempfile::TempDir, AurIndex)> {
        let temp_dir = tempfile::tempdir()?;
        let json_path = temp_dir.path().join("metadata.json.gz");
        let index_path = temp_dir.path().join("metadata.rkyv");
        let file = File::create(&json_path)?;
        let mut encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, data.as_bytes())?;
        encoder.finish()?;
        build_index(&json_path, &index_path)?;
        let index = AurIndex::open(&index_path)?;
        Ok((temp_dir, index))
    }

    #[test]
    fn index_open_rejects_unsafe_or_oversized_inputs() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("index");
        std::fs::write(&path, b"invalid archive")?;
        assert!(AurIndex::open(&path).is_err());
        assert_eq!(std::fs::read(&path)?, b"invalid archive");
        File::create(&path)?.set_len(MAX_AUR_INDEX_BYTES + 1)?;
        let error = AurIndex::open(&path).unwrap_err();
        assert!(error.to_string().contains("exceeds"));
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&path, &link)?;
        assert!(AurIndex::open(&link).is_err());
        assert!(AurIndex::open(directory.path()).is_err());
        let fifo = directory.path().join("fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU)?;
        assert!(AurIndex::open(&fifo).is_err());
        Ok(())
    }

    #[test]
    fn index_retains_owned_entries_after_external_mutation() -> Result<()> {
        let (directory, index) =
            open_test_index(r#"[{"Name":"demo","Version":"1.0","LastModified":1}]"#)?;
        let (replacement_directory, _replacement_index) =
            open_test_index(r#"[{"Name":"demo","Version":"2.0","LastModified":1}]"#)?;
        let path = directory.path().join("metadata.rkyv");
        let replacement = std::fs::read(replacement_directory.path().join("metadata.rkyv"))?;
        assert_eq!(std::fs::metadata(&path)?.len(), replacement.len() as u64);
        let mut writer = std::fs::OpenOptions::new().write(true).open(&path)?;
        let entry = index.get("demo")?.expect("fixture entry");
        assert_eq!(entry.version.as_str(), "1.0");
        writer.write_all(&replacement)?;
        assert_eq!(entry.version.as_str(), "1.0");
        assert_eq!(
            AurIndex::open(&path)?
                .get("demo")?
                .unwrap()
                .version
                .as_str(),
            "2.0"
        );
        writer.set_len(0)?;
        assert_eq!(entry.version.as_str(), "1.0");
        assert_eq!(index.search("demo", 1)?.len(), 1);
        assert!(AurIndex::open(&path).is_err());
        Ok(())
    }

    #[test]
    fn oversized_gzip_field_preserves_previous_index() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let json_path = directory.path().join("source.gz");
        let index_path = directory.path().join("index.bin");
        std::fs::write(&index_path, b"previous-index")?;
        let data = serde_json::json!([{"Name":"example", "Version":"1", "Description":"x".repeat(65537), "LastModified":1}]);
        let mut encoder = flate2::write::GzEncoder::new(
            File::create(&json_path)?,
            flate2::Compression::default(),
        );
        encoder.write_all(data.to_string().as_bytes())?;
        encoder.finish()?;
        assert!(build_index(&json_path, &index_path).is_err());
        assert_eq!(std::fs::read(&index_path)?, b"previous-index");
        Ok(())
    }

    #[test]
    fn test_build_index() -> Result<()> {
        let data = r#"[
            {"Name": "pkg-a", "Version": "1.0", "Maintainer": "user1", "LastModified": 100, "Description": "desc a", "NumVotes": 10, "Popularity": 0.5},
            {"Name": "pkg-b", "Version": "2.0", "Maintainer": null, "LastModified": 200, "Description": null, "NumVotes": 5, "Popularity": 0.1},
            {"Name": "Another-Pkg", "Version": "0.1", "Maintainer": "user2", "LastModified": 300, "Description": "another", "NumVotes": 0, "Popularity": 0.0}
        ]"#;
        let (_temp_dir, index) = open_test_index(data)?;
        assert!(index.get("pkg-a")?.is_some());
        assert!(index.get("pkg-b")?.is_some());
        assert!(index.get("Another-Pkg")?.is_some());

        let pkg_a = index.get("pkg-a")?.unwrap();
        assert_eq!(pkg_a.name.as_str(), "pkg-a");
        assert_eq!(pkg_a.version.as_str(), "1.0");
        assert_eq!(pkg_a.description.as_ref().unwrap().as_str(), "desc a");
        assert_eq!(pkg_a.num_votes, 10);

        // Test search
        let results = index.search("pkg", 10)?;
        assert_eq!(results.len(), 3); // pkg-a, pkg-b, Another-Pkg (contains 'pkg')

        let results = index.search("another", 10)?;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name.as_str(), "Another-Pkg");

        Ok(())
    }

    /// Regression test for the AUR update fallback bug (fixed in v0.1.215)
    /// and its partial-staleness extension. `updates_for()` must report
    /// queried packages absent from the index via the `missing` vec so the
    /// caller (`AurClient::get_update_list`) can fall back to the RPC for
    /// exactly those names instead of treating them as up-to-date.
    #[test]
    fn test_updates_for_reports_missing_packages() -> Result<()> {
        // Index contains only pkg-a and pkg-b
        let data = r#"[
            {"Name": "pkg-a", "Version": "1.0", "Maintainer": "user1", "LastModified": 100, "Description": "desc a", "NumVotes": 10, "Popularity": 0.5},
            {"Name": "pkg-b", "Version": "2.0", "Maintainer": null, "LastModified": 200, "Description": null, "NumVotes": 5, "Popularity": 0.1}
        ]"#;
        let (_temp_dir, index) = open_test_index(data)?;

        // Query for packages NOT in the index — simulates a stale index
        // that doesn't contain the user's installed AUR packages
        let local_pkgs = vec![
            ("my-custom-pkg".to_string(), v("1.0")),
            ("another-missing".to_string(), v("0.5")),
        ];

        let (updates, missing) = index.updates_for(&local_pkgs)?;
        assert_eq!(
            missing,
            vec!["my-custom-pkg".to_string(), "another-missing".to_string()],
            "packages absent from the index must be reported as missing \
             so the caller can query the RPC for exactly those names"
        );
        assert!(
            updates.is_empty(),
            "missing packages must produce no updates"
        );

        Ok(())
    }

    /// Verify that a partially stale index both reports known updates and
    /// names the entries it is missing, instead of truncating results.
    #[test]
    fn test_updates_for_partial_staleness_keeps_updates_and_missing() -> Result<()> {
        let data = r#"[
            {"Name": "pkg-a", "Version": "2.0", "Maintainer": null, "LastModified": 100, "Description": null, "NumVotes": 1, "Popularity": 0.1}
        ]"#;
        let (_temp_dir, index) = open_test_index(data)?;
        let local_pkgs = vec![
            ("pkg-a".to_string(), v("1.0")),      // in index, newer remote
            ("stale-only".to_string(), v("0.5")), // absent from index
        ];

        let (updates, missing) = index.updates_for(&local_pkgs)?;
        assert_eq!(
            updates.len(),
            1,
            "pkg-a update must survive partial staleness"
        );
        assert_eq!(updates[0].0, "pkg-a");
        assert_eq!(missing, vec!["stale-only".to_string()]);

        assert_eq!(
            updates
                .iter()
                .map(|(name, local, remote)| {
                    (name.as_str(), local.to_string(), remote.to_string())
                })
                .collect::<Vec<_>>(),
            vec![("pkg-a", "1.0".to_string(), "2.0".to_string())],
            "updates must preserve complete name/local/remote tuples"
        );

        Ok(())
    }

    /// Verify that `updates_for()` correctly detects when the remote version
    /// is newer than the local version.
    #[test]
    fn test_updates_for_detects_newer_version() -> Result<()> {
        let data = r#"[
            {"Name": "pkg-a", "Version": "2.0", "Maintainer": "user1", "LastModified": 100, "Description": "desc a", "NumVotes": 10, "Popularity": 0.5},
            {"Name": "pkg-b", "Version": "1.0", "Maintainer": null, "LastModified": 200, "Description": null, "NumVotes": 5, "Popularity": 0.1}
        ]"#;
        let (_temp_dir, index) = open_test_index(data)?;

        let local_pkgs = vec![
            ("pkg-a".to_string(), v("1.0")), // remote 2.0 > local 1.0
            ("pkg-b".to_string(), v("1.0")), // remote 1.0 == local 1.0
        ];

        let (updates, missing) = index.updates_for(&local_pkgs)?;
        assert!(missing.is_empty());
        assert_eq!(updates.len(), 1, "Only pkg-a should have an update");
        assert_eq!(updates[0].0, "pkg-a");

        assert_eq!(
            updates
                .iter()
                .map(|(name, local, remote)| {
                    (name.as_str(), local.to_string(), remote.to_string())
                })
                .collect::<Vec<_>>(),
            vec![("pkg-a", "1.0".to_string(), "2.0".to_string())],
            "updates must preserve complete name/local/remote tuples"
        );

        Ok(())
    }

    /// Verify that `updates_for()` reports no updates when local versions are
    /// already at or ahead of the index versions (no updates available).
    #[test]
    fn test_updates_for_no_updates_when_current() -> Result<()> {
        let data = r#"[
            {"Name": "pkg-a", "Version": "1.0", "Maintainer": "user1", "LastModified": 100, "Description": "desc a", "NumVotes": 10, "Popularity": 0.5}
        ]"#;
        let (_temp_dir, index) = open_test_index(data)?;

        // Local version matches remote — no update
        let local_same = vec![("pkg-a".to_string(), v("1.0"))];
        let (updates_same, _) = index.updates_for(&local_same)?;
        assert!(updates_same.is_empty());

        // Local version ahead of remote — no update
        let local_ahead = vec![("pkg-a".to_string(), v("2.0"))];
        let (updates_ahead, _) = index.updates_for(&local_ahead)?;
        assert!(updates_ahead.is_empty());

        Ok(())
    }

    /// ARCH-R14 regression: an index entry whose version fails the strict
    /// parser must never compare as a fabricated 0 (which would invent an
    /// update). The name is reported as `missing` so the caller re-checks it
    /// through the live RPC, and no update is pushed.
    #[test]
    fn test_updates_for_unparseable_remote_version_is_rechecked_not_zero() -> Result<()> {
        let data = r#"[
            {"Name": "pkg-bad", "Version": "1.0-1-1", "Maintainer": null, "LastModified": 100, "Description": null, "NumVotes": 1, "Popularity": 0.1},
            {"Name": "pkg-ok", "Version": "2.0", "Maintainer": null, "LastModified": 100, "Description": null, "NumVotes": 1, "Popularity": 0.1}
        ]"#;
        let (_temp_dir, index) = open_test_index(data)?;

        let local_pkgs = vec![
            ("pkg-bad".to_string(), v("0.5")),
            ("pkg-ok".to_string(), v("1.0")),
        ];

        let (updates, missing) = index.updates_for(&local_pkgs)?;
        assert_eq!(
            missing,
            vec!["pkg-bad".to_string()],
            "the unparseable entry must be rechecked via RPC, not compared as 0"
        );
        assert_eq!(
            updates
                .iter()
                .map(|(name, _, _)| name.as_str())
                .collect::<Vec<_>>(),
            vec!["pkg-ok"],
            "the parseable update must survive; no fabricated 0-update for pkg-bad"
        );

        assert_eq!(
            updates
                .iter()
                .map(|(name, local, remote)| {
                    (name.as_str(), local.to_string(), remote.to_string())
                })
                .collect::<Vec<_>>(),
            vec![("pkg-ok", "1.0".to_string(), "2.0".to_string())],
            "updates must preserve complete name/local/remote tuples"
        );

        Ok(())
    }
}
