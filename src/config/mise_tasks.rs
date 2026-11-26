//! Native mise task declarations and dependency planning, without executing code.

use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

use super::{mise_config::Document, mise_env::MiseEnv};

#[derive(Debug, Clone)]
pub(crate) struct NativeTask {
    pub name: String,
    pub runs: Vec<String>,
    pub depends: Vec<String>,
    pub source: PathBuf,
    pub root: PathBuf,
    pub directory: PathBuf,
    pub env: MiseEnv,
}

impl NativeTask {
    pub fn shell_args(&self) -> [String; 3] {
        // The outer group parses every entry before execution. Check each
        // step after it runs so an && condition cannot suppress errexit inside it.
        let mut script = String::from("{\n:\n");
        for run in &self.runs {
            script.push_str("{\n:\n");
            script.push_str(run);
            script.push_str("\n}\ncase $? in 0) ;; *) exit $? ;; esac\n");
        }
        script.push_str("}\n");
        ["-ec".to_owned(), script, self.name.clone()]
    }
}

fn strings(value: Option<&toml::Value>, key: &str) -> Result<Vec<String>> {
    match value {
        None => Ok(Vec::new()),
        Some(toml::Value::String(value)) => Ok(vec![value.clone()]),
        Some(toml::Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .with_context(|| format!("{key} requires only strings"))
            })
            .collect(),
        Some(_) => anyhow::bail!("{key} requires a string or string array"),
    }
}

fn parse_task(name: &str, spec: &toml::Value, document: &Document) -> Result<Option<NativeTask>> {
    let (runs, depends, directory, env) = if let Some(run) = spec.as_str() {
        (
            vec![run.to_owned()],
            Vec::new(),
            document.root.clone(),
            MiseEnv::default(),
        )
    } else {
        let table = spec.as_table().context("Task requires a string or table")?;
        // Fail visibly rather than dropping execution controls such as shell,
        // confirmation, sandboxing, conditions, or post-dependencies.
        for key in table.keys() {
            ensure!(
                matches!(
                    key.as_str(),
                    "run" | "depends" | "dir" | "env" | "description" | "hide"
                ),
                "Unsupported mise task property: {key}"
            );
        }
        let runs = strings(table.get("run"), "run")?;
        let depends = strings(table.get("depends"), "depends")?;
        for dependency in &depends {
            ensure!(
                !dependency.is_empty()
                    && dependency
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "-_:.".contains(c)),
                "Unsupported dependency {dependency:?}; expected a plain task name without arguments or patterns"
            );
        }
        let directory = if let Some(value) = table.get("dir") {
            let value = value.as_str().context("Task dir requires a string")?;
            ensure!(
                !value.contains("{{") && !value.contains("{%") && !value.starts_with('~'),
                "Task dir templates and home expansion are not supported"
            );
            document.root.join(value)
        } else {
            document.root.clone()
        };
        (
            runs,
            depends,
            directory,
            super::mise_env::parse_mise_env(spec, &document.root)?,
        )
    };
    for run in &runs {
        ensure!(
            !run.contains("{{") && !run.contains("{%"),
            "Task run templates are not supported"
        );
    }
    if runs.is_empty() && depends.is_empty() {
        return Ok(None);
    }
    Ok(Some(NativeTask {
        name: name.to_owned(),
        runs,
        depends,
        source: document.path.clone(),
        root: document.root.clone(),
        directory,
        env,
    }))
}

pub(crate) fn parse(documents: &[Document]) -> Result<BTreeMap<String, NativeTask>> {
    // Select whole declarations first: an overridden task must not leak its
    // old commands, dependency edges, or environment into the replacement.
    let mut declarations = BTreeMap::new();
    for document in documents {
        ensure!(
            document.value.get("task_config").is_none(),
            "Unsupported mise task_config in {}",
            document.path.display()
        );
        if let Some(value) = document.value.get("tasks") {
            let table = value.as_table().context("mise tasks requires a table")?;
            for (name, spec) in table {
                declarations.insert(name.clone(), (spec, document));
            }
        }
    }
    ensure!(
        declarations.len() <= 1024,
        "Too many mise tasks (maximum 1024)"
    );
    let mut tasks = BTreeMap::new();
    for (name, (spec, document)) in declarations {
        if let Some(task) = parse_task(&name, spec, document)
            .with_context(|| format!("Invalid mise task {name:?} in {}", document.path.display()))?
        {
            tasks.insert(name, task);
        }
    }
    Ok(tasks)
}

pub(crate) fn plan<'a>(
    tasks: &'a BTreeMap<String, NativeTask>,
    name: &str,
) -> Result<Vec<&'a NativeTask>> {
    // Explicit stack avoids recursion on untrusted dependency depth.
    let mut pending = vec![(name, false)];
    let mut active = HashSet::new();
    let mut complete = HashSet::new();
    let mut ordered = Vec::new();
    while let Some((name, leaving)) = pending.pop() {
        if complete.contains(name) {
            continue;
        }
        let task = tasks
            .get(name)
            .with_context(|| format!("Missing mise task dependency: {name}"))?;
        if leaving {
            active.remove(name);
            complete.insert(name);
            ordered.push(task);
        } else {
            ensure!(active.insert(name), "Mise task dependency cycle at {name}");
            pending.push((name, true));
            for dependency in task.depends.iter().rev() {
                pending.push((dependency, false));
            }
        }
    }
    Ok(ordered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;

    fn fixture(source: &str) -> (tempfile::TempDir, Vec<super::super::mise_config::Document>) {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("mise.toml"), source).unwrap();
        let docs = super::super::mise_config::load_directory(root.path(), &HashMap::new()).unwrap();
        (root, docs)
    }

    #[test]
    fn diamond_dependencies_run_once_before_dependency_only_root() {
        let (_root, docs) = fixture(
            "[tasks]\nsetup='echo setup'\n[tasks.left]\ndepends='setup'\nrun='echo left'\n[tasks.right]\ndepends=['setup']\nrun=['echo right','true']\n[tasks.all]\ndepends=['left','right']\n",
        );
        let tasks = parse(&docs).unwrap();
        let plan = plan(&tasks, "all").unwrap();
        assert_eq!(
            plan.iter()
                .map(|task| task.name.as_str())
                .collect::<Vec<_>>(),
            ["setup", "left", "right", "all"]
        );
        assert!(plan.last().unwrap().runs.is_empty());
    }

    #[test]
    fn cycles_and_missing_dependencies_fail_before_execution() {
        for source in [
            "[tasks.a]\ndepends=['b']\n[tasks.b]\ndepends=['a']",
            "[tasks.a]\ndepends=['missing']",
        ] {
            let (_root, docs) = fixture(source);
            assert!(plan(&parse(&docs).unwrap(), "a").is_err());
        }
    }

    #[test]
    fn selected_task_replaces_base_and_keeps_declaring_root() {
        let (root, mut docs) = fixture("[tasks]\nbuild='old'\n");
        let mut selected = docs[0].clone();
        selected.path = root.path().join("mise.test.toml");
        selected.value = toml::from_str("[tasks.build]\nrun='new'\ndir='subdir'").unwrap();
        docs.push(selected);
        let tasks = parse(&docs).unwrap();
        assert_eq!(tasks["build"].runs, ["new"]);
        assert_eq!(tasks["build"].directory, root.path().join("subdir"));
        assert_eq!(tasks["build"].root, root.path());
    }

    #[test]
    fn malformed_steps_and_unsupported_execution_fields_are_errors() {
        for spec in [
            "run=['echo first',1]",
            "depends=['build --release']",
            "run='true'\ndepends_post=['cleanup']",
            "run='true'\ndir='{{cwd}}'",
            "run='true'\ndeny_net=true",
        ] {
            let (_root, docs) = fixture(&format!("[tasks.bad]\n{spec}"));
            assert!(parse(&docs).is_err(), "accepted {spec}");
        }
    }

    #[test]
    fn discovery_validates_environment_without_reading_source_scripts() {
        let (_root, docs) = fixture(
            "[tasks.build]\nrun='true'\n[ tasks.build.env._ ]\nsource='missing.sh'\nfile='missing.env'",
        );
        assert!(parse(&docs).is_ok());
        let (_root, docs) = fixture("[tasks.build]\nrun='true'\n[ tasks.build.env._ ]\nbogus='no'");
        assert!(parse(&docs).is_err());
    }
}
