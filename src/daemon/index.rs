//! In-memory package index with string interning for the daemon.
//!
//! Provides O(1) package lookups and SIMD-accelerated substring search
//! for the daemon's hot path. Uses a string pool to deduplicate package
//! metadata and reduce memory allocations.

use std::sync::Arc;

use ahash::AHashMap;
use anyhow::Result;

use crate::daemon::protocol::{DetailedPackageInfo, PackageInfo, WirePackageSource};
use crate::package_managers::{PackageManager, SearchNameKind};

struct PackageBloomFilter {
    bits: Vec<u64>,
    num_bits: usize,
}

impl PackageBloomFilter {
    fn new(expected_items: usize) -> Self {
        let num_bits = (expected_items * 8).max(4096);
        let num_words = num_bits.div_ceil(64);
        Self {
            bits: vec![0u64; num_words],
            num_bits,
        }
    }

    #[inline]
    fn hash_positions(&self, name: &str) -> [usize; 3] {
        use std::hash::{Hash, Hasher};
        let mut hasher = ahash::AHasher::default();
        name.hash(&mut hasher);
        let h1 = hasher.finish() as usize;
        let h2 = h1.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        let h3 = h2.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        [h1 % self.num_bits, h2 % self.num_bits, h3 % self.num_bits]
    }

    fn insert(&mut self, name: &str) {
        for pos in self.hash_positions(name) {
            let word_idx = pos / 64;
            let bit_idx = pos % 64;
            self.bits[word_idx] |= 1u64 << bit_idx;
        }
    }

    #[inline]
    fn might_contain(&self, name: &str) -> bool {
        for pos in self.hash_positions(name) {
            let word_idx = pos / 64;
            let bit_idx = pos % 64;
            if self.bits[word_idx] & (1u64 << bit_idx) == 0 {
                return false;
            }
        }
        true
    }
}

/// String interner sharing each allocation between its pool and dedup map.
///
/// The returned handle indexes a flat vector, giving O(1), allocation-free
/// borrowed lookup.
#[derive(Default)]
struct StringPool {
    strings: Vec<Arc<str>>,
    dedup: AHashMap<Arc<str>, u32>,
}

impl StringPool {
    fn intern(&mut self, s: &str) -> u32 {
        if let Some(&handle) = self.dedup.get(s) {
            return handle;
        }
        let arc: Arc<str> = Arc::from(s);
        let handle = self.strings.len() as u32;
        self.strings.push(Arc::clone(&arc));
        self.dedup.insert(arc, handle);
        handle
    }

    #[inline]
    fn get(&self, handle: u32) -> &str {
        &self.strings[handle as usize]
    }
}

/// Trigram index mapping 3-byte substrings to package indices.
///
/// At build time, extracts all trigrams from each lowercased package name.
/// At search time, intersects the posting lists of query trigrams to produce
/// a small candidate set, turning O(n) linear scan into O(k) where k << n.
struct TrigramIndex {
    postings: AHashMap<[u8; 3], Vec<u32>>,
}

impl TrigramIndex {
    fn new(capacity: usize) -> Self {
        Self {
            postings: AHashMap::with_capacity(capacity),
        }
    }

    fn insert(&mut self, name_lower: &str, idx: u32) {
        let bytes = name_lower.as_bytes();
        if bytes.len() < 3 {
            return;
        }
        let mut seen = ahash::AHashSet::with_capacity(bytes.len().saturating_sub(2));
        for window in bytes.windows(3) {
            let trigram = [window[0], window[1], window[2]];
            if seen.insert(trigram) {
                self.postings.entry(trigram).or_default().push(idx);
            }
        }
    }

    fn candidates(&self, query_lower: &str) -> Option<Vec<u32>> {
        let bytes = query_lower.as_bytes();
        if bytes.len() < 3 {
            return None;
        }

        let mut result: Option<Vec<u32>> = None;
        for window in bytes.windows(3) {
            let trigram = [window[0], window[1], window[2]];
            match self.postings.get(&trigram) {
                Some(posting) => {
                    result = Some(match result {
                        None => posting.clone(),
                        Some(prev) => {
                            let set: ahash::AHashSet<u32> = posting.iter().copied().collect();
                            prev.into_iter().filter(|idx| set.contains(idx)).collect()
                        }
                    });
                }
                None => return Some(Vec::new()),
            }
        }
        result
    }
}

pub struct PackageIndex {
    name_kind: SearchNameKind,
    items: Vec<CompactPackageInfo>,
    pool: StringPool,
    name_to_idx: AHashMap<String, usize>,
    bloom: PackageBloomFilter,
    trigrams: TrigramIndex,
}

struct CompactPackageInfo {
    rpm_eligible: bool,
    name_offset: u32,
    name_lower_offset: u32,
    version_offset: u32,
    description_offset: u32,
    description_lower_offset: u32,
    url_offset: u32,
    size: u64,
    download_size: u64,
    repo_offset: u32,
    depends: Vec<String>,
    licenses: Vec<String>,
    source: WirePackageSource,
}

/// Relevance score for a search match
/// Higher scores = better matches
///
/// Ordering: We use reverse sort (b.cmp(a)), so:
/// - Higher rank values are better (5 > 4 > 3 > 2 > 1 > 0)
/// - Lower `name_len` is better (shorter = more specific)
/// - Lower idx is better (stable sort tiebreaker)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct RelevanceScore {
    /// Primary rank: exact name match > prefix match > word boundary > substring
    rank: u8,
    /// Secondary sort: shorter package names preferred (more specific)
    /// We use reverse length for proper ordering with reverse sort
    name_len_rev: usize, // usize::MAX - name_len, so shorter names have higher values
    /// Package index (tiebreaker for stable sorting)
    /// We use reverse index for proper ordering with reverse sort
    idx_rev: usize, // usize::MAX - idx, so earlier indices have higher values
}

impl RelevanceScore {
    const EXACT_NAME_MATCH: u8 = 5;
    const RPM_BASENAME_MATCH: u8 = 4;
    const PREFIX_MATCH: u8 = 3;
    const WORD_BOUNDARY_MATCH: u8 = 2;
    const SUBSTRING_MATCH: u8 = 1;
    const DESCRIPTION_ONLY: u8 = 0;

    fn new(rank: u8, name_len: usize, idx: usize) -> Self {
        Self {
            rank,
            name_len_rev: usize::MAX.saturating_sub(name_len),
            idx_rev: usize::MAX.saturating_sub(idx),
        }
    }
}

impl PackageIndex {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            name_kind: SearchNameKind::Literal,
            items: Vec::with_capacity(capacity),
            pool: StringPool::default(),
            name_to_idx: AHashMap::with_capacity(capacity),
            bloom: PackageBloomFilter::new(capacity),
            trigrams: TrigramIndex::new(capacity),
        }
    }

    fn push(
        &mut self,
        name: &str,
        version: &str,
        description: &str,
        url: &str,
        size: u64,
        download_size: u64,
        repo: &str,
        depends: &[String],
        licenses: &[String],
    ) {
        let name_lower = name.to_ascii_lowercase();
        let idx = self.items.len();
        self.items.push(CompactPackageInfo {
            rpm_eligible: true,
            name_offset: self.pool.intern(name),
            name_lower_offset: self.pool.intern(&name_lower),
            version_offset: self.pool.intern(version),
            description_offset: self.pool.intern(description),
            description_lower_offset: self.pool.intern(&description.to_ascii_lowercase()),
            url_offset: self.pool.intern(url),
            size,
            download_size,
            repo_offset: self.pool.intern(repo),
            depends: depends.to_vec(),
            licenses: licenses.to_vec(),
            source: WirePackageSource::Official,
        });
        self.trigrams.insert(&name_lower, idx as u32);
        self.name_to_idx.entry(name.to_owned()).or_insert(idx);
        self.bloom.insert(name);
    }

    /// Create an empty index for isolated handler tests and explicitly empty states.
    ///
    /// Production startup should use [`Self::new`] so a missing or unsynced package
    /// database remains an actionable error outside hermetic test mode.
    pub fn empty() -> Self {
        Self::with_capacity(0)
    }

    /// Build a hermetic index from explicit package records.
    ///
    /// Used by tests that need ranking, suggestion, and lookup behavior without
    /// reading the host package database.
    #[cfg(test)]
    pub(crate) fn from_records(records: &[(&str, &str, &str)]) -> Self {
        let mut index = Self::with_capacity(records.len());
        for &(name, version, description) in records {
            index.push(name, version, description, "", 0, 0, "extra", &[], &[]);
        }
        index
    }

    #[cfg(test)]
    pub(crate) fn from_rpm_records(records: &[(&str, &str, &str)]) -> Self {
        let mut index = Self::from_records(records);
        index.name_kind = SearchNameKind::RpmIdentity;
        index
    }

    fn from_packages(packages: Vec<crate::core::Package>, name_kind: SearchNameKind) -> Self {
        let mut index = Self::with_capacity(packages.len());
        index.name_kind = name_kind;
        for package in packages {
            let idx = index.items.len();
            index.push(
                &package.name,
                &package.version.to_string(),
                &package.description,
                "",
                0,
                0,
                "official",
                &[],
                &[],
            );
            // Keep original source provenance for ranking without changing wire output.
            index.items[idx].rpm_eligible = package.source == crate::core::PackageSource::Official;
        }
        index
    }

    fn uses_manager_inventory(package_manager: &dyn PackageManager) -> bool {
        crate::core::paths::test_mode()
            || matches!(package_manager.name(), "dnf" | "brew" | "homebrew")
    }

    pub fn for_package_manager_blocking(package_manager: Arc<dyn PackageManager>) -> Result<Self> {
        if !Self::uses_manager_inventory(package_manager.as_ref()) {
            return Self::new();
        }

        std::thread::Builder::new()
            .name("omg-index-init".to_string())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                runtime.block_on(Self::for_package_manager(package_manager))
            })?
            .join()
            .map_err(|_| anyhow::anyhow!("package index initialization worker panicked"))?
    }

    pub async fn for_package_manager(package_manager: Arc<dyn PackageManager>) -> Result<Self> {
        if Self::uses_manager_inventory(package_manager.as_ref()) {
            let name_kind = SearchNameKind::for_manager(
                package_manager.name(),
                crate::core::paths::test_mode(),
            );
            return Ok(Self::from_packages(
                package_manager.package_index().await?,
                name_kind,
            ));
        }

        tokio::task::spawn_blocking(Self::new).await?
    }

    pub fn new() -> Result<Self> {
        match crate::package_managers::resolve_backend()? {
            #[cfg(feature = "arch")]
            crate::package_managers::Backend::Arch => Self::new_alpm(),
            #[cfg(feature = "debian")]
            crate::package_managers::Backend::Debian => Self::new_apt(),
            backend => anyhow::bail!(
                "The selected {backend:?} backend needs its package manager inventory"
            ),
        }
    }

    #[cfg(feature = "debian")]
    fn new_apt() -> Result<Self> {
        #[cfg(feature = "debian")]
        if !crate::core::paths::test_mode() {
            let packages = crate::package_managers::apt::candidate_index_packages()?;
            let mut index = Self::with_capacity(packages.len());
            for pkg in packages {
                index.push(
                    &pkg.name,
                    &pkg.version.to_string(),
                    &pkg.description,
                    "",
                    pkg.install_size
                        .and_then(|size| u64::try_from(size).ok())
                        .unwrap_or(0),
                    pkg.download_size.unwrap_or(0),
                    "apt",
                    &pkg.depends,
                    &pkg.licenses,
                );
            }
            return Ok(index);
        }

        use crate::package_managers::debian_db;
        debian_db::ensure_index_loaded()?;

        let db_packages = debian_db::get_detailed_best_candidates()?;
        let mut index = Self::with_capacity(db_packages.len());
        for pkg in db_packages {
            index.push(
                &pkg.name,
                &pkg.version,
                &pkg.description,
                &pkg.homepage,
                pkg.installed_size,
                pkg.size,
                &pkg.section,
                &pkg.depends,
                &[],
            );
        }
        Ok(index)
    }

    #[cfg(feature = "arch")]
    fn new_alpm() -> Result<Self> {
        use crate::package_managers::pacman_db;
        let db_packages = pacman_db::get_detailed_packages()?;
        let mut index = Self::with_capacity(db_packages.len());
        for pkg in db_packages {
            index.push(
                &pkg.name,
                &pkg.version.to_string(),
                &pkg.desc,
                &pkg.url,
                pkg.isize,
                pkg.csize,
                &pkg.repo,
                &pkg.depends,
                &pkg.licenses,
            );
        }
        Ok(index)
    }

    pub fn search(&self, query: &str, limit: usize) -> Vec<PackageInfo> {
        if query.is_empty() || limit == 0 {
            // limit == 0 previously underflowed at `limit - 1` below,
            // panicking inside the daemon's blocking pool.
            return Vec::new();
        }
        let query_lower = query.to_ascii_lowercase();
        let query_bytes = query_lower.as_bytes();

        let desc_finder = memchr::memmem::Finder::new(query_bytes);

        let mut scored_matches: Vec<(RelevanceScore, u32)> = Vec::with_capacity(limit * 2);
        let mut name_match_count: usize = 0;

        // Use trigram index for queries >= 3 chars to narrow candidates
        if let Some(candidates) = self.trigrams.candidates(&query_lower) {
            for &idx in &candidates {
                let item = &self.items[idx as usize];
                let name_lower = self.pool.get(item.name_lower_offset);

                if let Some(score) = self.score_name_match(&query_lower, name_lower, idx as usize) {
                    scored_matches.push((score, idx));
                    name_match_count += 1;
                }
            }

            // Fall through to description scan if we need more results
            if name_match_count < limit {
                for (idx, item) in self.items.iter().enumerate() {
                    if name_match_count + scored_matches.len() >= limit * 4 {
                        break;
                    }
                    let desc_lower = self.pool.get(item.description_lower_offset);
                    if desc_finder.find(desc_lower.as_bytes()).is_some() {
                        let name_lower = self.pool.get(item.name_lower_offset);
                        if self
                            .score_name_match(&query_lower, name_lower, idx)
                            .is_none()
                        {
                            scored_matches.push((
                                RelevanceScore::new(
                                    RelevanceScore::DESCRIPTION_ONLY,
                                    name_lower.len(),
                                    idx,
                                ),
                                idx as u32,
                            ));
                        }
                    }
                }
            }
        } else {
            // Short queries (< 3 chars): full scan (trigrams need 3+ chars)
            for (idx, item) in self.items.iter().enumerate() {
                let name_lower = self.pool.get(item.name_lower_offset);

                if let Some(score) = self.score_name_match(&query_lower, name_lower, idx) {
                    scored_matches.push((score, idx as u32));
                    name_match_count += 1;
                } else if name_match_count < limit {
                    let desc_lower = self.pool.get(item.description_lower_offset);
                    if desc_finder.find(desc_lower.as_bytes()).is_some() {
                        scored_matches.push((
                            RelevanceScore::new(
                                RelevanceScore::DESCRIPTION_ONLY,
                                name_lower.len(),
                                idx,
                            ),
                            idx as u32,
                        ));
                    }
                }
            }
        }

        if scored_matches.len() > limit {
            scored_matches.select_nth_unstable_by(limit - 1, |a, b| b.0.cmp(&a.0));
            scored_matches.truncate(limit);
        }
        scored_matches.sort_unstable_by_key(|&(score, _)| std::cmp::Reverse(score));

        scored_matches
            .into_iter()
            .filter_map(|(_, idx)| {
                let item = self.items.get(idx as usize)?;
                Some(PackageInfo {
                    name: self.pool.get(item.name_offset).to_string(),
                    version: self.pool.get(item.version_offset).to_string(),
                    description: self.pool.get(item.description_offset).to_string(),
                    source: item.source,
                })
            })
            .collect()
    }

    fn score_name_match(
        &self,
        query_lower: &str,
        name_lower: &str,
        idx: usize,
    ) -> Option<RelevanceScore> {
        if name_lower != query_lower
            && self.items[idx].rpm_eligible
            && self.items[idx].source == WirePackageSource::Official
            && self.name_kind.exact_key(query_lower, name_lower).is_some()
        {
            return Some(RelevanceScore::new(
                RelevanceScore::RPM_BASENAME_MATCH,
                name_lower.len(),
                idx,
            ));
        }
        let query_len = query_lower.len();
        let mut found_substring = false;

        for (pos, _) in name_lower.match_indices(query_lower) {
            if pos == 0 && name_lower.len() == query_len {
                return Some(RelevanceScore::new(
                    RelevanceScore::EXACT_NAME_MATCH,
                    name_lower.len(),
                    idx,
                ));
            }
            if pos == 0 {
                return Some(RelevanceScore::new(
                    RelevanceScore::PREFIX_MATCH,
                    name_lower.len(),
                    idx,
                ));
            }
            let prev = name_lower.as_bytes()[pos - 1];
            if prev == b'-' || prev == b'_' || prev == b'.' || prev.is_ascii_whitespace() {
                return Some(RelevanceScore::new(
                    RelevanceScore::WORD_BOUNDARY_MATCH,
                    name_lower.len(),
                    idx,
                ));
            }
            found_substring = true;
        }

        found_substring
            .then(|| RelevanceScore::new(RelevanceScore::SUBSTRING_MATCH, name_lower.len(), idx))
    }

    #[inline]
    pub fn get(&self, name: &str) -> Option<DetailedPackageInfo> {
        if !self.bloom.might_contain(name) {
            return None;
        }

        let &idx = self.name_to_idx.get(name)?;
        let item = &self.items[idx];

        Some(DetailedPackageInfo {
            name: self.pool.get(item.name_offset).to_string(),
            version: self.pool.get(item.version_offset).to_string(),
            description: self.pool.get(item.description_offset).to_string(),
            url: self.pool.get(item.url_offset).to_string(),
            size: item.size,
            download_size: item.download_size,
            repo: self.pool.get(item.repo_offset).to_string(),
            depends: item.depends.clone(),
            licenses: item.licenses.clone(),
            source: item.source,
        })
    }

    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn suggest(&self, query: &str, limit: usize) -> Vec<String> {
        if query.is_empty() {
            return Vec::new();
        }
        let mut names: Vec<String> = self
            .items
            .iter()
            .map(|item| self.pool.get(item.name_offset).to_string())
            .collect();
        crate::core::completion::CompletionEngine::fuzzy_indices(query, &names, limit)
            .into_iter()
            .map(|index| std::mem::take(&mut names[index]))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rpm_fixture_index(records: &[(&str, &str, &str)]) -> PackageIndex {
        PackageIndex::from_rpm_records(records)
    }

    #[test]
    fn fedora_search_index_ranks_rpm_basename_before_limit() {
        let index = rpm_fixture_index(&[
            ("tree2.i686", "1", "prefix"),
            ("tree.x86_64", "2:2.2.1-4.fc44", "exact RPM basename"),
        ]);
        assert!("tree2.i686".len() < "tree.x86_64".len());
        let results = index.search("tree", 1);
        assert_eq!(results[0].name, "tree.x86_64");
        assert_eq!(results[0].version, "2:2.2.1-4.fc44");
        assert_eq!(results[0].description, "exact RPM basename");
        assert_eq!(results[0].source, WirePackageSource::Official);
        assert_eq!(index.get("tree.x86_64").unwrap().name, "tree.x86_64");
        assert!(index.get("tree").is_none());
        assert!(index.search("tree", 0).is_empty());
        assert!(index.search("", 1).is_empty());
    }

    #[test]
    fn fedora_search_index_full_identity_precedes_colliding_basename() {
        let index = rpm_fixture_index(&[
            ("tree.x86_64.aarch64", "1", "RPM basename equals query"),
            ("tree.x86_64", "2", "full identity equals query"),
            ("tree.x86_64-extra.i686", "3", "prefix"),
        ]);
        for limit in [1, 10] {
            let results = index.search("tree.x86_64", limit);
            assert_eq!(results[0].name, "tree.x86_64");
            if limit == 10 {
                assert_eq!(results[1].name, "tree.x86_64.aarch64");
            }
        }
    }

    #[test]
    fn fedora_search_index_preserves_dotted_multiarch_and_short_query_order() {
        let python = rpm_fixture_index(&[
            ("python3.13-tools.i686", "1", "prefix"),
            ("python3.13.x86_64", "2", "dotted basename"),
        ]);
        assert_eq!(python.search("python3.13", 1)[0].name, "python3.13.x86_64");
        let index = rpm_fixture_index(&[
            ("tree.noarch", "1", "first equal-length identity"),
            ("tree.x86_64", "2", "second equal-length identity"),
            ("tree.aarch64", "3", "longer identity"),
            ("tree2.i686", "4", "shorter prefix"),
        ]);
        let results = index.search("tree", 10);
        assert_eq!(
            results
                .iter()
                .map(|package| package.name.as_str())
                .collect::<Vec<_>>(),
            ["tree.noarch", "tree.x86_64", "tree.aarch64", "tree2.i686"]
        );
        let short = rpm_fixture_index(&[("go2.x", "1", "prefix"), ("go.x86_64", "2", "exact")]);
        assert_eq!(short.search("go", 1)[0].name, "go.x86_64");
    }

    #[test]
    fn fedora_search_index_generic_records_remain_literal() {
        let records = [
            ("tree2.i686", "1", "shorter prefix"),
            ("tree.x86_64", "2", "dotted literal"),
        ];
        assert_eq!(
            PackageIndex::from_records(&records).search("tree", 1)[0].name,
            "tree2.i686"
        );
        let mut index = rpm_fixture_index(&records);
        index.items[1].source = WirePackageSource::Aur;
        assert_eq!(index.search("tree", 1)[0].name, "tree2.i686");
    }

    struct DnfRankingCatalog(crate::package_managers::mock::MockPackageManager);
    type RankingFuture<'a, T> =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<T>> + Send + 'a>>;

    impl PackageManager for DnfRankingCatalog {
        fn name(&self) -> &'static str {
            self.0.name()
        }
        fn package_index(&self) -> RankingFuture<'_, Vec<crate::core::Package>> {
            Box::pin(async {
                let mut packages = self.0.package_index().await?;
                let target = packages
                    .iter_mut()
                    .find(|package| package.name == "tree.x86_64")
                    .expect("AUR fixture identity");
                target.source = crate::core::PackageSource::Aur;
                Ok(packages)
            })
        }
        fn search(&self, query: &str) -> RankingFuture<'_, Vec<crate::core::Package>> {
            self.0.search(query)
        }
        fn install(&self, packages: &[String]) -> RankingFuture<'_, ()> {
            self.0.install(packages)
        }
        fn remove(&self, packages: &[String]) -> RankingFuture<'_, ()> {
            self.0.remove(packages)
        }
        fn update(&self) -> RankingFuture<'_, ()> {
            self.0.update()
        }
        fn sync(&self) -> RankingFuture<'_, ()> {
            self.0.sync()
        }
        fn info(&self, package: &str) -> RankingFuture<'_, Option<crate::core::Package>> {
            self.0.info(package)
        }
        fn list_installed(&self) -> RankingFuture<'_, Vec<crate::core::Package>> {
            self.0.list_installed()
        }
        fn get_status(&self, fast: bool) -> RankingFuture<'_, (usize, usize, usize, usize)> {
            self.0.get_status(fast)
        }
        fn list_explicit(&self) -> RankingFuture<'_, Vec<String>> {
            self.0.list_explicit()
        }
        fn list_updates(
            &self,
        ) -> RankingFuture<'_, Vec<crate::package_managers::types::UpdateInfo>> {
            self.0.list_updates()
        }
        fn is_installed(&self, package: &str) -> RankingFuture<'_, bool> {
            self.0.is_installed(package)
        }
    }

    #[test]
    fn fedora_search_manager_construction_respects_explicit_mock_mode() {
        const CHILD: &str = "OMG_RPM_RANK_CONSTRUCTION_CHILD";
        if let Ok(mode) = std::env::var(CHILD) {
            let directory = tempfile::tempdir().expect("private construction catalog");
            let manager = crate::package_managers::mock::MockPackageManager::new_in(
                "fedora",
                directory.path(),
            );
            manager.db.packages.lock().unwrap().clear();
            manager
                .db
                .add_package("tree2.i686", "1", "prefix", "fedora");
            manager
                .db
                .add_package("tree.x86_64", "2", "exact", "fedora");
            assert_eq!(manager.name(), "dnf");
            let manager: Arc<dyn PackageManager> = if mode == "aur" {
                Arc::new(DnfRankingCatalog(manager))
            } else {
                Arc::new(manager)
            };
            let index = PackageIndex::for_package_manager_blocking(manager).unwrap();
            assert_eq!(
                index.get("tree.x86_64").unwrap().source,
                WirePackageSource::Official,
                "preexisting output mapping is retained"
            );
            let expected = if mode == "rpm" {
                "tree.x86_64"
            } else {
                "tree2.i686"
            };
            assert_eq!(index.search("tree", 1)[0].name, expected, "{mode}");
            println!("RANK_CONSTRUCTION mode={mode} expected={expected}");
            return;
        }
        let mut failures = Vec::new();
        for mode in ["rpm", "mock", "aur"] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command.args(["--exact", "daemon::index::tests::fedora_search_manager_construction_respects_explicit_mock_mode", "--nocapture", "--test-threads=1"])
                .env(CHILD, mode).env("RUST_BACKTRACE", "0")
                .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
            if mode == "mock" {
                command.env("OMG_TEST_MODE", "1");
            } else {
                command.env_remove("OMG_TEST_MODE");
            }
            let mut child = command.spawn().expect("spawn bounded construction child");
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    child
                        .kill()
                        .expect("terminate timed out construction child");
                    child.wait().expect("reap construction child");
                    panic!("construction child timed out: {mode}");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let output = child.wait_with_output().unwrap();
            println!("{}", String::from_utf8_lossy(&output.stdout));
            if !output.status.success() {
                failures.push((mode, output));
            }
        }
        assert!(failures.is_empty(), "construction failures: {failures:?}");
    }

    fn portable_manager_cases() -> [(
        crate::package_managers::mock::MockPackageManager,
        &'static str,
    ); 2] {
        [
            (
                crate::package_managers::mock::MockPackageManager::fedora(),
                "vim-enhanced",
            ),
            (
                crate::package_managers::mock::MockPackageManager::macos(),
                "python@3.12",
            ),
        ]
    }

    #[test]
    fn portable_managers_supply_the_initial_daemon_index() {
        for (manager, expected) in portable_manager_cases() {
            let index = PackageIndex::for_package_manager_blocking(Arc::new(manager)).unwrap();
            assert!(index.get(expected).is_some(), "missing {expected}");
            assert!(index.len() >= 5);
        }
    }

    #[tokio::test]
    async fn portable_managers_supply_the_refreshed_daemon_index() {
        for (manager, expected) in portable_manager_cases() {
            let index = PackageIndex::for_package_manager(Arc::new(manager))
                .await
                .unwrap();
            assert!(index.get(expected).is_some(), "missing {expected}");
            assert!(index.len() >= 5);
        }
    }

    #[test]
    fn empty_index_has_no_observable_packages() {
        let index = PackageIndex::empty();

        assert!(index.is_empty());
        assert_eq!(index.len(), 0);
        assert!(index.search("anything", 10).is_empty());
        assert!(index.search("anything", 0).is_empty());
        assert!(index.search("", 10).is_empty());
        assert!(index.suggest("anything", 10).is_empty());
        assert!(index.get("anything").is_none());
    }

    fn fixture_index() -> PackageIndex {
        PackageIndex::from_records(&[
            (
                "firefox",
                "146.0",
                "Standalone web browser from mozilla.org",
            ),
            (
                "firefox-developer-edition",
                "147.0b1",
                "Developer edition of firefox",
            ),
            ("librewolf", "146.0", "Privacy-focused firefox fork"),
            ("python", "3.13.1", "High-level scripting language"),
            ("git", "2.47.1", "Distributed version control system"),
        ])
    }

    #[test]
    fn repeated_name_trigrams_do_not_duplicate_search_results() {
        let index = PackageIndex::from_records(&[("aaaa", "1.0", "repeated trigram")]);

        let results = index.search("aaa", 10);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "aaaa");
    }

    #[test]
    fn populated_index_ranks_exact_name_matches_first() {
        let index = fixture_index();
        let results = index.search("firefox", 10);

        assert!(!results.is_empty());
        assert_eq!(results[0].name, "firefox");
        assert!(
            results
                .iter()
                .any(|pkg| pkg.name == "firefox-developer-edition")
        );
        assert!(results.iter().any(|pkg| pkg.name == "librewolf"));
        assert!(!results.iter().any(|pkg| pkg.name == "python"));
    }

    #[test]
    fn populated_index_suggests_prefix_matches_and_looks_up_exact_names() {
        let index = fixture_index();

        let fire = index.suggest("fire", 10);
        assert!(fire.iter().any(|name| name == "firefox"));
        assert!(fire.iter().any(|name| name == "firefox-developer-edition"));
        assert_eq!(fire.first().map(String::as_str), Some("firefox"));
        assert!(
            index
                .suggest("frfox", 10)
                .iter()
                .any(|name| name == "firefox"),
            "suggest must rank fuzzy matches, not prefix-only"
        );
        assert!(index.suggest("zzz", 10).is_empty());
        assert!(index.suggest("", 10).is_empty());

        let firefox = index.get("firefox").expect("exact name must resolve");
        assert_eq!(firefox.version, "146.0");
        assert_eq!(firefox.source, WirePackageSource::Official);
        assert!(index.get("missing").is_none());
    }

    #[test]
    fn duplicate_names_do_not_replace_the_first_bare_lookup() {
        let index = PackageIndex::from_records(&[
            ("libexample", "2.0-amd64", "native"),
            ("libexample", "2.0-i386", "foreign"),
        ]);

        let package = index.get("libexample").expect("bare lookup");
        assert_eq!(package.version, "2.0-amd64");
    }

    #[test]
    fn exact_lookup_preserves_dependency_and_license_metadata() {
        let mut index = PackageIndex::empty();
        let depends = vec!["openssl".to_string()];
        let licenses = vec!["MIT".to_string()];
        index.push(
            "example",
            "1.0.0",
            "example package",
            "https://example.invalid",
            10,
            5,
            "extra",
            &depends,
            &licenses,
        );

        let info = index.get("example").expect("metadata entry");
        assert_eq!(info.depends, depends);
        assert_eq!(info.licenses, licenses);
    }

    #[test]
    fn test_string_pool_interning() {
        let mut pool = StringPool::default();
        let off1 = pool.intern("hello");
        let off2 = pool.intern("world");
        let off3 = pool.intern("hello");

        assert_eq!(off1, off3);
        assert_ne!(off1, off2);
        assert_eq!(pool.get(off1), "hello");
        assert_eq!(pool.get(off2), "world");
    }

    #[test]
    fn test_string_pool_empty_and_special() {
        let mut pool = StringPool::default();
        let off_empty = pool.intern("");
        let off_space = pool.intern(" ");
        let off_unicode = pool.intern("🦀");

        assert_eq!(pool.get(off_empty), "");
        assert_eq!(pool.get(off_space), " ");
        assert_eq!(pool.get(off_unicode), "🦀");
    }

    #[test]
    fn test_string_pool_large() {
        let mut pool = StringPool::default();
        for i in 0..1000 {
            let s = format!("string-{i}");
            let off = pool.intern(&s);
            assert_eq!(pool.get(off), s);
        }
    }

    #[test]
    fn test_relevance_score_ordering() {
        // Test that RelevanceScore sorts correctly
        let idx1 = 0;
        let idx2 = 1;
        let idx3 = 2;

        let exact = RelevanceScore::new(RelevanceScore::EXACT_NAME_MATCH, 5, idx1);
        let prefix = RelevanceScore::new(RelevanceScore::PREFIX_MATCH, 5, idx2);
        let word_boundary = RelevanceScore::new(RelevanceScore::WORD_BOUNDARY_MATCH, 5, idx3);
        let substring = RelevanceScore::new(RelevanceScore::SUBSTRING_MATCH, 5, 0);
        let description = RelevanceScore::new(RelevanceScore::DESCRIPTION_ONLY, 5, 0);

        // Higher ranks should come first (higher value = better)
        assert!(exact > prefix);
        assert!(prefix > word_boundary);
        assert!(word_boundary > substring);
        assert!(substring > description);
    }

    #[test]
    fn test_relevance_score_tiebreaker() {
        // When ranks are equal, shorter names should come first
        let short = RelevanceScore::new(RelevanceScore::PREFIX_MATCH, 5, 0);
        let long = RelevanceScore::new(RelevanceScore::PREFIX_MATCH, 15, 0);

        // Shorter name (len=5) should have higher value than longer name (len=15)
        assert!(short > long);
    }

    #[test]
    fn test_relevance_score_stable_sort() {
        // When rank and length are equal, lower index should come first
        let first = RelevanceScore::new(RelevanceScore::PREFIX_MATCH, 10, 0);
        let second = RelevanceScore::new(RelevanceScore::PREFIX_MATCH, 10, 1);

        // Lower index should have higher value (comes first in results)
        assert!(first > second);
    }
}
