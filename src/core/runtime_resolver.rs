//! Runtime executable resolution.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};

/// Alias rejection is distinct from an I/O failure: interactive hooks may
/// ignore unusable aliases, while task execution must report them.
#[derive(Debug, thiserror::Error)]
pub(crate) enum NvmAliasRejection {
    #[error("Invalid nvm alias path {0:?}")]
    InvalidPath(String),
    #[error("Nvm alias escapes its installation or alias directory")]
    Escape,
    #[error("Nvm alias cycle at {0:?}")]
    Cycle(String),
    #[error("Nvm alias chain exceeds 64 resolutions")]
    TooDeep,
}

/// Resolve NVM's on-disk aliases without executing shell code or reading
/// unbounded/special files. A missing initial alias is not a version lookup.
pub(crate) fn resolve_nvm_alias(nvm_dir: &Path, alias: &str) -> Result<Option<String>> {
    fn validate(alias: &str) -> Result<()> {
        if alias.is_empty()
            || !Path::new(alias)
                .components()
                .all(|part| matches!(part, Component::Normal(_)))
        {
            return Err(NvmAliasRejection::InvalidPath(alias.to_owned()).into());
        }
        Ok(())
    }

    validate(alias)?;
    let root = match nvm_dir.join("alias").canonicalize() {
        Ok(root) => root,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("Failed to resolve nvm alias directory"),
    };
    if !root.starts_with(nvm_dir.canonicalize()?) {
        return Err(NvmAliasRejection::Escape.into());
    }

    let mut current = alias.to_owned();
    let mut seen = HashSet::new();
    let mut resolved_alias = false;
    for _ in 0..64 {
        validate(&current)?;
        if !seen.insert(current.clone()) {
            return Err(NvmAliasRejection::Cycle(current).into());
        }
        let mut candidate = root.join(&current);
        // NVM stores the default LTS alias in the literal file alias/lts/*.
        if current == "lts" && candidate.is_dir() {
            candidate.push("*");
        }
        match std::fs::symlink_metadata(&candidate) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(resolved_alias.then_some(current));
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("Failed to inspect nvm alias {}", candidate.display())
                });
            }
        }
        let canonical = candidate
            .canonicalize()
            .with_context(|| format!("Failed to resolve nvm alias {}", candidate.display()))?;
        if !canonical.starts_with(&root) {
            return Err(NvmAliasRejection::Escape.into());
        }
        let Some(content) = crate::config::mise_env::read_bounded_regular_file(&canonical)
            .with_context(|| format!("Failed to read nvm alias {}", candidate.display()))?
        else {
            return Ok(None);
        };
        let Some(next) = content
            .lines()
            .map(|line| line.split('#').next().unwrap_or_default().trim())
            .find(|line| !line.is_empty())
        else {
            return Ok(None);
        };
        next.clone_into(&mut current);
        resolved_alias = true;
    }
    Err(NvmAliasRejection::TooDeep.into())
}

/// Find an executable in the system `PATH`.
pub fn find_in_path(binary: &str) -> Option<PathBuf> {
    which::which(binary).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_in_path_finds_known_binaries() {
        // sh should exist on all Unix systems
        #[cfg(unix)]
        assert!(find_in_path("sh").is_some());
    }

    #[test]
    fn test_find_in_path_returns_none_for_nonexistent() {
        assert!(find_in_path("this-binary-definitely-does-not-exist-12345").is_none());
    }
}
