//! Shared, ordered mise project configuration. Discovery never executes project code.

use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

pub(crate) const MAX_CONFIG_FILES: usize = 256;

#[derive(Debug, Clone)]
pub(crate) struct Document {
    pub path: PathBuf,
    /// Declaring configuration root, preserving mise's grouped-file semantics.
    pub root: PathBuf,
    pub value: toml::Value,
}

pub(crate) fn environment_selection(value: Option<&OsStr>) -> Result<HashMap<String, String>> {
    let mut selection = HashMap::new();
    if let Some(value) = value {
        let value = value
            .to_str()
            .context("Environment variable MISE_ENV is not UTF-8")?;
        selection.insert("MISE_ENV".to_owned(), value.to_owned());
    }
    Ok(selection)
}

fn selected_environments(env: &HashMap<String, String>) -> Result<Vec<String>> {
    let mut selected = Vec::new();
    for name in env
        .get("MISE_ENV")
        .into_iter()
        .flat_map(|value| value.split(','))
    {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        anyhow::ensure!(
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || "_-".contains(c)),
            "Invalid mise environment name; expected letters, digits, underscores or hyphens"
        );
        selected.retain(|existing| existing != name);
        selected.push(name.to_owned());
    }
    Ok(selected)
}

fn add_document(
    documents: &mut Vec<Document>,
    seen: &mut HashSet<PathBuf>,
    path: PathBuf,
    root: &Path,
) -> Result<()> {
    if seen.contains(&path) {
        return Ok(());
    }
    let content = match super::mise_env::read_bounded_regular_file(&path) {
        Ok(content) => content,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|source| source.kind() == std::io::ErrorKind::NotADirectory) =>
        {
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let Some(text) = content else {
        return Ok(());
    };
    anyhow::ensure!(
        documents.len() < MAX_CONFIG_FILES,
        "Too many mise configuration files"
    );
    let value: toml::Value = toml::from_str(&text)
        .with_context(|| format!("Failed to parse mise configuration {}", path.display()))?;
    // mise's legacy `.config/mise/mise*.toml` aliases resolve relative
    // directives beside the file; grouped `config*.toml` uses the project root.
    let config_root = if [".config/mise/mise.toml", ".config/mise/mise.local.toml"]
        .iter()
        .any(|name| path == root.join(name))
    {
        root.join(".config/mise")
    } else {
        root.to_owned()
    };
    seen.insert(path.clone());
    documents.push(Document {
        path,
        root: config_root,
        value,
    });
    Ok(())
}

fn add_fragments(
    documents: &mut Vec<Document>,
    seen: &mut HashSet<PathBuf>,
    directory: &Path,
    root: &Path,
) -> Result<()> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(());
        }
        Err(error) => return Err(error).with_context(|| format!("Read {}", directory.display())),
    };
    let mut files = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "toml")
            && path
                .file_name()
                .is_some_and(|name| !name.to_string_lossy().starts_with('.'))
        {
            anyhow::ensure!(files.len() < 256, "Too many mise configuration fragments");
            files.push(path);
        }
    }
    files.sort();
    for path in files {
        add_document(documents, seen, path, root)?;
    }
    Ok(())
}

/// Return low-to-high precedence documents, preserving each declaring root.
/// `env` is supplied by the caller so configuration resolution never mutates process state.
pub(crate) fn load(start: &Path, env: &HashMap<String, String>) -> Result<Vec<Document>> {
    let selected = selected_environments(env)?;
    let mut roots: Vec<_> = start.ancestors().collect();
    roots.reverse();
    let mut documents = Vec::new();
    let mut seen = HashSet::new();
    for root in roots {
        append_directory(root, &selected, &mut documents, &mut seen)?;
    }
    Ok(documents)
}

/// Load only this directory's layers so callers can preserve their ancestor policy.
pub(crate) fn load_directory(root: &Path, env: &HashMap<String, String>) -> Result<Vec<Document>> {
    let selected = selected_environments(env)?;
    let mut documents = Vec::new();
    let mut seen = HashSet::new();
    append_directory(root, &selected, &mut documents, &mut seen)?;
    Ok(documents)
}

fn append_directory(
    root: &Path,
    selected: &[String],
    documents: &mut Vec<Document>,
    seen: &mut HashSet<PathBuf>,
) -> Result<()> {
    // Pinned upstream LOCAL_CONFIG_FILENAMES order, with overlays applied
    // at each directory rather than above the complete project hierarchy.
    for group in [".config/mise", ".mise", "mise"] {
        add_fragments(documents, seen, &root.join(group).join("conf.d"), root)?;
        add_document(documents, seen, root.join(group).join("config.toml"), root)?;
        if group == ".config/mise" {
            add_document(documents, seen, root.join(".config/mise/mise.toml"), root)?;
            add_document(documents, seen, root.join(".config/mise.toml"), root)?;
        }
    }
    for name in ["mise.toml", ".mise.toml"] {
        add_document(documents, seen, root.join(name), root)?;
    }
    let stems = [
        ".config/mise/config",
        ".config/mise",
        "mise/config",
        "mise",
        ".mise/config",
        ".mise",
    ];
    for name in [
        ".config/mise/config.local.toml",
        ".config/mise/mise.local.toml",
        ".config/mise.local.toml",
        ".mise/config.local.toml",
        "mise/config.local.toml",
        "mise.local.toml",
        ".mise.local.toml",
    ] {
        add_document(documents, seen, root.join(name), root)?;
    }
    // Upstream appends each selected environment, including its local
    // overrides, after the entire ordinary/local configuration list.
    for selected_env in selected {
        for stem in stems {
            add_document(
                documents,
                seen,
                root.join(format!("{stem}.{selected_env}.toml")),
                root,
            )?;
        }
        for stem in stems {
            add_document(
                documents,
                seen,
                root.join(format!("{stem}.{selected_env}.local.toml")),
                root,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod compatibility {
    use super::super::mise_env::{Strictness, load_mise_env_chain};
    use std::collections::HashMap;
    use std::fs;

    #[test]
    fn directory_loader_does_not_read_ancestor_configuration() {
        let root = tempfile::tempdir().unwrap();
        let child = root.path().join("child");
        fs::create_dir(&child).unwrap();
        fs::write(root.path().join("mise.toml"), "invalid toml = [").unwrap();
        fs::write(child.join("mise.toml"), "[tools]\nnode='20'\n").unwrap();
        fs::write(child.join("mise.local.toml"), "[tools]\nnode='22'\n").unwrap();
        let documents = super::load_directory(&child, &HashMap::new()).unwrap();
        assert_eq!(documents.len(), 2);
        assert_eq!(documents[0].value["tools"]["node"].as_str(), Some("20"));
        assert_eq!(documents[1].value["tools"]["node"].as_str(), Some("22"));
    }

    #[test]
    fn unrelated_files_do_not_block_optional_grouped_discovery() {
        let root = tempfile::tempdir().unwrap();
        for filename in [".config", "mise", ".mise"] {
            fs::write(root.path().join(filename), "not a directory").unwrap();
        }
        fs::write(root.path().join("mise.toml"), "[env]\nMODE='base'\n").unwrap();
        let env = load_mise_env_chain(root.path(), &HashMap::new(), Strictness::Strict).unwrap();
        assert!(env.set.contains(&("MODE".into(), "base".into())));
    }

    #[test]
    fn selected_environment_overrides_generic_local_configuration() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("mise.local.toml"), "[env]\nMODE='local'\n").unwrap();
        fs::write(root.path().join("mise.test.toml"), "[env]\nMODE='test'\n").unwrap();
        let base = HashMap::from([("MISE_ENV".into(), "test".into())]);
        let env = load_mise_env_chain(root.path(), &base, Strictness::Strict).unwrap();
        assert!(env.set.contains(&("MODE".into(), "test".into())));
    }

    #[test]
    fn later_selected_environment_overrides_earlier_environment_local() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("mise.test.local.toml"),
            "[env]\nMODE='test-local'\n",
        )
        .unwrap();
        fs::write(root.path().join("mise.prod.toml"), "[env]\nMODE='prod'\n").unwrap();
        let base = HashMap::from([("MISE_ENV".into(), "test,prod".into())]);
        let env = load_mise_env_chain(root.path(), &base, Strictness::Strict).unwrap();
        assert!(env.set.contains(&("MODE".into(), "prod".into())));
    }

    #[test]
    fn selected_environments_reject_paths_and_keep_last_duplicate() {
        let env = HashMap::from([("MISE_ENV".into(), " test,prod,test, ".into())]);
        assert_eq!(
            super::selected_environments(&env).unwrap(),
            ["prod", "test"]
        );
        for name in ["../secrets", "a/b", "a\\b", "a.b"] {
            let env = HashMap::from([("MISE_ENV".into(), name.into())]);
            assert!(super::selected_environments(&env).is_err());
        }
    }

    #[test]
    fn grouped_configuration_retains_its_project_root() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join(".config/mise");
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("config.toml"),
            "[env]\nROOT='{{config_root}}'\n",
        )
        .unwrap();
        let env = load_mise_env_chain(root.path(), &HashMap::new(), Strictness::Strict).unwrap();
        assert!(
            env.set
                .contains(&("ROOT".into(), root.path().as_os_str().to_owned()))
        );
    }

    #[test]
    fn legacy_grouped_mise_aliases_retain_their_file_directory() {
        for filename in ["mise.toml", "mise.local.toml"] {
            let root = tempfile::tempdir().unwrap();
            let directory = root.path().join(".config/mise");
            fs::create_dir_all(&directory).unwrap();
            fs::write(directory.join(filename), "[env]\nROOT='{{config_root}}'\n").unwrap();
            let env =
                load_mise_env_chain(root.path(), &HashMap::new(), Strictness::Strict).unwrap();
            assert!(
                env.set
                    .contains(&("ROOT".into(), directory.as_os_str().to_owned()))
            );
        }
    }

    #[test]
    fn fragments_merge_in_filename_order_before_main_configuration() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join(".config/mise/conf.d");
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("20-last.toml"),
            "[env]\nORDER='last'\nMAIN='fragment'\n",
        )
        .unwrap();
        fs::write(directory.join("10-first.toml"), "[env]\nORDER='first'\n").unwrap();
        fs::write(directory.join(".hidden.toml"), "[env]\nHIDDEN='no'\n").unwrap();
        fs::write(
            root.path().join(".config/mise/config.toml"),
            "[env]\nMAIN='config'\n",
        )
        .unwrap();
        let env = load_mise_env_chain(root.path(), &HashMap::new(), Strictness::Strict).unwrap();
        assert!(env.set.contains(&("ORDER".into(), "last".into())));
        assert!(env.set.contains(&("MAIN".into(), "config".into())));
        assert!(!env.set.iter().any(|(name, _)| name == "HIDDEN"));
    }

    #[test]
    fn invalid_environment_identifies_its_declaring_file() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("mise.local.toml");
        fs::write(&file, "[env]\nBAD-NAME='invalid'\n").unwrap();
        let error =
            load_mise_env_chain(root.path(), &HashMap::new(), Strictness::Strict).unwrap_err();
        assert!(error.to_string().contains(&file.display().to_string()));
    }

    #[test]
    fn excessive_fragments_fail_before_environment_resolution() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join(".config/mise/conf.d");
        fs::create_dir_all(&directory).unwrap();
        for index in 0..257 {
            fs::write(directory.join(format!("{index:03}.toml")), "[env]\n").unwrap();
        }
        let error =
            load_mise_env_chain(root.path(), &HashMap::new(), Strictness::Strict).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Too many mise configuration fragments")
        );
    }

    #[test]
    fn local_environment_overrides_project_configuration() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("mise.toml"), "[env]\nMODE='base'\n").unwrap();
        fs::write(root.path().join("mise.local.toml"), "[env]\nMODE='local'\n").unwrap();
        let env = load_mise_env_chain(root.path(), &HashMap::new(), Strictness::Strict).unwrap();
        assert!(env.set.contains(&("MODE".into(), "local".into())));
    }

    #[test]
    fn selected_environment_applies_before_its_local_override() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("mise.toml"), "[env]\nMODE='base'\n").unwrap();
        fs::write(
            root.path().join("mise.test.toml"),
            "[env]\nMODE='test'\nTEST_ONLY='yes'\n",
        )
        .unwrap();
        fs::write(
            root.path().join("mise.test.local.toml"),
            "[env]\nMODE='local-test'\n",
        )
        .unwrap();
        let base = HashMap::from([("MISE_ENV".into(), "test".into())]);
        let env = load_mise_env_chain(root.path(), &base, Strictness::Strict).unwrap();
        assert!(env.set.contains(&("MODE".into(), "local-test".into())));
        assert!(env.set.contains(&("TEST_ONLY".into(), "yes".into())));
    }

    #[test]
    fn child_base_overrides_parent_selected_environment() {
        let root = tempfile::tempdir().unwrap();
        let child = root.path().join("child");
        fs::create_dir(&child).unwrap();
        fs::write(
            root.path().join("mise.test.toml"),
            "[env]\nMODE='parent'\nINHERITED='yes'\n",
        )
        .unwrap();
        fs::write(child.join("mise.toml"), "[env]\nMODE='child'\n").unwrap();
        let base = HashMap::from([("MISE_ENV".into(), "test".into())]);
        let env = load_mise_env_chain(&child, &base, Strictness::Strict).unwrap();
        assert!(env.set.contains(&("MODE".into(), "child".into())));
        assert!(env.set.contains(&("INHERITED".into(), "yes".into())));
    }
}
