//! Canonical package display ranking shared with authoritative RPM catalog search.
use std::cmp::Reverse;

use crate::package_managers::SearchNameKind;
use nucleo_matcher::{
    Config, Matcher, Utf32String,
    pattern::{CaseMatching, Normalization, Pattern},
};

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
pub(crate) fn is_langpack(name: &str) -> bool {
    let lower = name.to_lowercase();
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
}

impl SearchRanker {
    pub(crate) fn new(query: &str) -> Self {
        let query_lower = query.to_lowercase();
        let pattern = Pattern::parse(&query_lower, CaseMatching::Ignore, Normalization::Smart);
        Self {
            query_lower,
            pattern,
            matcher: Matcher::new(Config::DEFAULT),
        }
    }

    pub(crate) fn score(&mut self, name_lower: &str, name_kind: SearchNameKind) -> SearchScore {
        let exact_key = name_kind.exact_key(&self.query_lower, name_lower);
        let mut tier = if name_lower != self.query_lower && exact_key.is_some() {
            MatchTier::RpmBasenameExact
        } else {
            match_tier(&self.query_lower, name_lower)
        };
        let haystack = Utf32String::from(exact_key.unwrap_or(name_lower));
        let fuzzy = self
            .pattern
            .score(haystack.slice(..), &mut self.matcher)
            .unwrap_or(0);
        if tier == MatchTier::Substring && fuzzy > 0 {
            tier = MatchTier::Fuzzy;
        }
        (tier, is_langpack(name_lower), Reverse(fuzzy))
    }
}
