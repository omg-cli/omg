//! Shared package search validation and display ranking.
use std::cmp::Reverse;

use crate::package_managers::SearchNameKind;
use nucleo_matcher::{
    Config, Matcher, Utf32Str,
    pattern::{CaseMatching, Normalization, Pattern},
};

pub(crate) const MAX_SEARCH_QUERY_BYTES: usize = 100;

pub(crate) fn validate_search_query(query: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        query.len() <= MAX_SEARCH_QUERY_BYTES,
        "Search query too long (max 100 characters)"
    );
    anyhow::ensure!(
        !query.chars().any(char::is_control),
        "Search query contains invalid characters"
    );
    anyhow::ensure!(
        !query.contains('/') && !query.contains('\\') && !query.contains(".."),
        "Invalid search query: path traversal detected"
    );
    anyhow::ensure!(
        !query.chars().any(|character| ";|&><$".contains(character)),
        "Invalid search query: shell metacharacters detected"
    );
    Ok(())
}

pub(crate) fn validate_aur_search_length(query: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        query.trim().len() >= 2,
        "AUR search requires at least 2 non-whitespace bytes"
    );
    Ok(())
}

#[cfg(feature = "arch")]
pub(crate) fn validate_aur_search_query(query: &str) -> anyhow::Result<()> {
    validate_search_query(query)?;
    validate_aur_search_length(query)
}

/// Display tier for one search hit. Lower sorts first. A single table owns
/// result ordering for the daemon, native, and AUR paths together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum MatchTier {
    Exact,
    RpmBasenameExact,
    Prefix,
    WordBoundary,
    Fuzzy,
    Substring,
}

/// Language packs flood generic queries (`firefox` matches hundreds of
/// `firefox-*-i18n-*`). They sort after real packages in every tier and
/// collapse into one group row unless the query names them directly.
fn is_langpack_lower(lower: &str) -> bool {
    lower.contains("-i18n-")
        || lower.ends_with("-i18n")
        || lower.ends_with("-l10n")
        || lower.ends_with("-lang")
        || lower.ends_with("-locale")
}

fn match_tier(query: &str, name: &str) -> MatchTier {
    if name == query {
        return MatchTier::Exact;
    }
    if name.starts_with(query) {
        return MatchTier::Prefix;
    }
    if name.split(['-', '_', ' ']).any(|word| word == query) {
        return MatchTier::WordBoundary;
    }
    MatchTier::Substring
}

pub(crate) type SearchScore = (MatchTier, bool, Reverse<u32>);

pub(crate) struct SearchRanker {
    query_lower: String,
    pattern: Pattern,
    matcher: Matcher,
    utf32_buf: Vec<char>,
}

impl SearchRanker {
    pub(crate) fn new(query: &str) -> Self {
        let query_lower = query.to_lowercase();
        let pattern = Pattern::parse(&query_lower, CaseMatching::Ignore, Normalization::Smart);
        Self {
            query_lower,
            pattern,
            matcher: Matcher::new(Config::DEFAULT),
            utf32_buf: Vec::new(),
        }
    }

    pub(crate) fn score(&mut self, name_lower: &str, name_kind: SearchNameKind) -> SearchScore {
        let exact_key = name_kind.exact_key(&self.query_lower, name_lower);
        let mut tier = if name_lower != self.query_lower && exact_key.is_some() {
            MatchTier::RpmBasenameExact
        } else {
            match_tier(&self.query_lower, name_lower)
        };
        let target = exact_key.unwrap_or(name_lower);
        let haystack = Utf32Str::new(target, &mut self.utf32_buf);
        let fuzzy = self
            .pattern
            .score(haystack, &mut self.matcher)
            .unwrap_or(0);
        if tier == MatchTier::Substring && fuzzy > 0 {
            tier = MatchTier::Fuzzy;
        }
        (tier, is_langpack_lower(name_lower), Reverse(fuzzy))
    }
}
