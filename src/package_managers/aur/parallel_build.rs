use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::task::JoinSet;

use super::{AurClient, client::AuthorizedBuild};

#[derive(Debug, Clone)]
pub struct BuildJob {
    /// AUR package base to clone and build.
    pub package: String,
    /// Split-package outputs from this base that should be installed.
    pub outputs: Vec<String>,
    /// Other package bases in this update set that must finish first.
    pub dependencies: Vec<String>,
}

impl BuildJob {
    #[must_use]
    pub fn new(package: String, dependencies: Vec<String>) -> Self {
        Self {
            outputs: vec![package.clone()],
            package,
            dependencies,
        }
    }

    #[must_use]
    pub fn for_package_base(
        package_base: String,
        mut outputs: Vec<String>,
        mut dependencies: Vec<String>,
    ) -> Self {
        outputs.sort();
        outputs.dedup();
        dependencies.sort();
        dependencies.dedup();
        Self {
            package: package_base,
            outputs,
            dependencies,
        }
    }
}

#[derive(Debug, Default)]
pub struct ParallelBuildSummary {
    succeeded_outputs: Vec<String>,
    failed_outputs: Vec<String>,
    skipped_outputs: Vec<String>,
    failures: Vec<(String, anyhow::Error)>,
}

impl ParallelBuildSummary {
    #[must_use]
    pub fn succeeded_output_count(&self) -> usize {
        self.succeeded_outputs.len()
    }

    #[must_use]
    pub fn failed_output_count(&self) -> usize {
        self.failed_outputs.len()
    }

    #[must_use]
    pub fn skipped_output_count(&self) -> usize {
        self.skipped_outputs.len()
    }

    pub fn failures(&self) -> impl Iterator<Item = (&str, &anyhow::Error)> {
        self.failures
            .iter()
            .map(|(package_base, error)| (package_base.as_str(), error))
    }

    #[must_use]
    pub fn skipped_outputs(&self) -> &[String] {
        &self.skipped_outputs
    }

    fn record_job_result(&mut self, job: &BuildJob, result: Result<()>) {
        match result {
            Ok(()) => self.succeeded_outputs.extend(job.outputs.iter().cloned()),
            Err(error) => {
                self.failed_outputs.extend(job.outputs.iter().cloned());
                self.failures.push((job.package.clone(), error));
            }
        }
    }

    fn record_skipped(&mut self, job: &BuildJob) {
        self.skipped_outputs.extend(job.outputs.iter().cloned());
    }

    fn merge(&mut self, mut other: Self) {
        self.succeeded_outputs.append(&mut other.succeeded_outputs);
        self.failed_outputs.append(&mut other.failed_outputs);
        self.skipped_outputs.append(&mut other.skipped_outputs);
        self.failures.append(&mut other.failures);
    }
}

pub struct ParallelBuilder {
    client: Arc<AurClient>,
    max_concurrent: usize,
}

impl ParallelBuilder {
    /// # Panics
    /// Never panics; a `max_concurrent` of 0 is clamped to 1 so a wave can
    /// never silently skip every package.
    #[must_use]
    pub fn new(client: Arc<AurClient>, max_concurrent: usize) -> Self {
        Self {
            client,
            // Clamp to >=1: a zero limit would spawn no tasks per wave and
            // report success without building anything.
            max_concurrent: max_concurrent.max(1),
        }
    }

    pub async fn build_packages(&self, jobs: Vec<BuildJob>) -> Result<ParallelBuildSummary> {
        if jobs.is_empty() {
            return Ok(ParallelBuildSummary::default());
        }
        Self::validate_unique_jobs(&jobs)?;

        // PKGBUILD review blocks on interactive input; without a terminal it
        // would fail only after cloning and dependency resolution work.
        // Decide that up front, before any network or filesystem side effect.
        if self.client.requires_interactive_review() && !console::user_attended() {
            anyhow::bail!(
                "AUR PKGBUILD review is enabled, but this session has no interactive terminal. Run in an interactive terminal to review each PKGBUILD, or set aur.review_pkgbuild=false if you accept unreviewed AUR code."
            );
        }

        let dep_graph = Self::build_dependency_graph(&jobs);
        let build_levels = Self::topological_levels(&dep_graph)?;
        let jobs_by_package: HashMap<String, BuildJob> = jobs
            .into_iter()
            .map(|job| (job.package.clone(), job))
            .collect();

        let mut authorized_jobs = HashMap::with_capacity(jobs_by_package.len());
        for package in build_levels.iter().flatten() {
            let job = jobs_by_package
                .get(package)
                .with_context(|| format!("Missing build job for package base '{package}'"))?;
            let authorized = self
                .client
                .authorize_package_outputs(&job.package, &job.outputs)
                .await?;
            authorized_jobs.insert(package.clone(), authorized);
        }

        if !crate::core::caps::can_write_pacman_db() {
            let package = jobs_by_package
                .values()
                .next()
                .expect("invariant: jobs checked non-empty above");
            AurClient::preacquire_install_privileges(&package.package, "parallel AUR build")
                .await?;
        }

        let _sudoloop = if crate::core::sudoloop::can_use_sudoloop() {
            tracing::debug!("Starting shared sudoloop for parallel AUR builds");
            Some(crate::core::sudoloop::SudoLoop::start())
        } else {
            None
        };

        tracing::info!(
            "Building {} package base(s) in {} parallel wave(s)",
            jobs_by_package.len(),
            build_levels.len()
        );

        let mut summary = ParallelBuildSummary::default();
        for (level_idx, level) in build_levels.iter().enumerate() {
            let level_summary = self
                .build_level(
                    level_idx + 1,
                    build_levels.len(),
                    level,
                    &jobs_by_package,
                    &mut authorized_jobs,
                )
                .await?;
            let wave_failed = level_summary.failed_output_count() > 0;
            summary.merge(level_summary);

            if wave_failed {
                // Preserve the existing fail-fast dependency behavior. Later
                // waves were not attempted, so none of their outputs can be
                // reported as upgraded.
                for blocked_package in build_levels.iter().skip(level_idx + 1).flatten() {
                    let blocked_job = jobs_by_package.get(blocked_package).with_context(|| {
                        format!("Missing build job for package base '{blocked_package}'")
                    })?;
                    summary.record_skipped(blocked_job);
                }
                break;
            }
        }

        // _sudoloop is dropped here after all waves complete
        Ok(summary)
    }

    fn validate_unique_jobs(jobs: &[BuildJob]) -> Result<()> {
        let mut package_bases = HashSet::with_capacity(jobs.len());
        for job in jobs {
            anyhow::ensure!(
                package_bases.insert(job.package.as_str()),
                "Duplicate AUR build job for package base '{}'",
                job.package
            );
        }
        Ok(())
    }

    #[must_use]
    pub fn build_dependency_graph(jobs: &[BuildJob]) -> HashMap<String, HashSet<String>> {
        let mut graph: HashMap<String, HashSet<String>> = HashMap::new();

        let all_packages: HashSet<String> = jobs.iter().map(|j| j.package.clone()).collect();

        for job in jobs {
            let deps: HashSet<String> = job
                .dependencies
                .iter()
                .filter(|dep| all_packages.contains(*dep))
                .cloned()
                .collect();

            graph.insert(job.package.clone(), deps);
        }

        graph
    }

    pub fn topological_levels(
        graph: &HashMap<String, HashSet<String>>,
    ) -> Result<Vec<Vec<String>>> {
        let mut levels: Vec<Vec<String>> = Vec::new();
        let mut remaining: HashSet<String> = graph.keys().cloned().collect();
        let mut satisfied: HashSet<String> = HashSet::new();

        while !remaining.is_empty() {
            let mut current_level: Vec<String> = remaining
                .iter()
                .filter(|pkg| {
                    graph
                        .get(*pkg)
                        .is_none_or(|deps| deps.iter().all(|dep| satisfied.contains(dep)))
                })
                .cloned()
                .collect();

            if current_level.is_empty() {
                let cycle_packages: Vec<_> = remaining.iter().take(5).cloned().collect();
                anyhow::bail!("Circular dependency detected in AUR packages: {cycle_packages:?}");
            }

            current_level.sort();

            for pkg in &current_level {
                remaining.remove(pkg);
                satisfied.insert(pkg.clone());
            }

            levels.push(current_level);
        }

        Ok(levels)
    }

    /// Wave concurrency for a level. Clamped to >= 1: a zero limit would
    /// spawn no tasks and silently report success without building anything.
    #[must_use]
    fn concurrency_for_level(max_concurrent: usize, level_len: usize) -> usize {
        max_concurrent.max(1).min(level_len)
    }

    async fn build_level(
        &self,
        level_num: usize,
        total_levels: usize,
        packages: &[String],
        jobs: &HashMap<String, BuildJob>,
        authorized_jobs: &mut HashMap<String, AuthorizedBuild>,
    ) -> Result<ParallelBuildSummary> {
        // Builds within a wave run concurrently. Successful archives install
        // once per wave; INSTALL_LOCK serializes ALPM.
        crate::cli::modern_ui::print_section(&format!(
            "AUR wave {level_num}/{total_levels} ({} package{})",
            packages.len(),
            if packages.len() == 1 { "" } else { "s" }
        ));

        let concurrency = Self::concurrency_for_level(self.max_concurrent, packages.len());

        let mut tasks = JoinSet::new();
        let mut in_flight_jobs = HashMap::new();
        let mut package_iter = packages.iter();
        let mut wave_archives = Vec::new();

        // Drain the independent wave even after a failure; aborting a native
        // build's setsid waiter can leave its compiler process group running.
        let mut summary = ParallelBuildSummary::default();
        loop {
            while tasks.len() < concurrency {
                let Some(package) = package_iter.next() else {
                    break;
                };
                let client = Arc::clone(&self.client);
                let job = jobs
                    .get(package)
                    .with_context(|| format!("Missing build job for package base '{package}'"))?;
                let authorized = authorized_jobs.remove(package).with_context(|| {
                    format!("Missing authorization for package base '{package}'")
                })?;

                tracing::info!("Building {} for outputs {:?}", job.package, job.outputs);
                let task = tasks.spawn(async move {
                    client
                        .install_authorized_package_outputs(authorized, None)
                        .await
                });
                in_flight_jobs.insert(task.id(), job);
            }

            let Some(result) = tasks.join_next_with_id().await else {
                break;
            };
            let (task_id, build_result) = match result {
                Ok((task_id, build_result)) => (task_id, build_result),
                Err(join_error) => {
                    let task_id = join_error.id();
                    (task_id, Err(join_error.into()))
                }
            };
            let job = in_flight_jobs
                .remove(&task_id)
                .with_context(|| format!("Missing build job for completed task {task_id}"))?;
            let failed = build_result.is_err();
            match build_result {
                Ok(archives) => {
                    wave_archives.extend(archives);
                    summary.record_job_result(job, Ok(()));
                }
                Err(error) => summary.record_job_result(job, Err(error)),
            }
            if failed {
                let remaining = tasks.len() + package_iter.len();
                if remaining > 0 {
                    crate::cli::modern_ui::print_warning(&format!(
                        "A build in this wave failed; still waiting on {remaining} remaining build(s) before reporting"
                    ));
                }
            }
        }

        if !wave_archives.is_empty() {
            crate::cli::modern_ui::print_info(&format!(
                "Installing {} package{}",
                wave_archives.len(),
                if wave_archives.len() == 1 { "" } else { "s" }
            ));
            AurClient::install_built_packages(&wave_archives, None).await?;
        }

        Ok(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dependency_graph_simple() {
        let jobs = vec![
            BuildJob::new("a".to_string(), vec![]),
            BuildJob::new("b".to_string(), vec!["a".to_string()]),
            BuildJob::new("c".to_string(), vec!["b".to_string()]),
        ];

        let graph = ParallelBuilder::build_dependency_graph(&jobs);

        assert_eq!(graph.get("a").unwrap().len(), 0);
        assert!(graph.get("b").unwrap().contains("a"));
        assert!(graph.get("c").unwrap().contains("b"));
    }

    #[test]
    fn duplicate_package_base_jobs_are_rejected() {
        let jobs = vec![
            BuildJob::new("shared-base".to_string(), Vec::new()),
            BuildJob::new("shared-base".to_string(), Vec::new()),
        ];

        let error = ParallelBuilder::validate_unique_jobs(&jobs)
            .expect_err("duplicate package bases must not be silently collapsed");
        assert!(
            error.to_string().contains("Duplicate AUR build job"),
            "{error}"
        );
    }

    #[test]
    fn test_topological_levels() {
        let mut graph = HashMap::new();
        graph.insert("a".to_string(), HashSet::new());
        graph.insert("b".to_string(), ["a".to_string()].into());
        graph.insert("c".to_string(), ["a".to_string()].into());
        graph.insert("d".to_string(), ["b".to_string(), "c".to_string()].into());

        let levels = ParallelBuilder::topological_levels(&graph).unwrap();

        assert_eq!(levels.len(), 3);
        assert_eq!(levels[0], vec!["a"]);
        assert_eq!(levels[1].len(), 2);
        assert!(levels[1].contains(&"b".to_string()));
        assert!(levels[1].contains(&"c".to_string()));
        assert_eq!(levels[2], vec!["d"]);
    }

    #[test]
    fn test_independent_packages() {
        let mut graph = HashMap::new();
        graph.insert("pkg1".to_string(), HashSet::new());
        graph.insert("pkg2".to_string(), HashSet::new());
        graph.insert("pkg3".to_string(), HashSet::new());

        let levels = ParallelBuilder::topological_levels(&graph).unwrap();

        assert_eq!(levels.len(), 1);
        assert_eq!(levels[0].len(), 3);
    }

    #[test]
    fn test_zero_max_concurrent_is_clamped_to_one() {
        // Regression: max_concurrent == 0 used to spawn zero tasks per wave,
        // silently skipping every package while reporting success.
        assert_eq!(ParallelBuilder::concurrency_for_level(0, 5), 1);
        assert_eq!(ParallelBuilder::concurrency_for_level(2, 5), 2);
        assert_eq!(ParallelBuilder::concurrency_for_level(8, 3), 3);
    }

    #[test]
    fn partial_wave_counts_successful_and_failed_outputs_separately() {
        let mut wave = ParallelBuildSummary::default();
        let postgresql = BuildJob::for_package_base(
            "postgresql18".to_string(),
            vec!["postgresql18".to_string(), "postgresql18-libs".to_string()],
            vec![],
        );
        let huggingface = BuildJob::new("python-huggingface-hub-git".to_string(), vec![]);

        wave.record_job_result(&postgresql, Ok(()));
        wave.record_job_result(&huggingface, Err(anyhow::anyhow!("build failed")));
        let mut summary = ParallelBuildSummary::default();
        summary.merge(wave);

        assert_eq!(summary.succeeded_output_count(), 2);
        assert_eq!(summary.failed_output_count(), 1);
        assert_eq!(summary.skipped_output_count(), 0);
        assert_eq!(
            summary
                .failures()
                .map(|(package, error)| (package, error.to_string()))
                .collect::<Vec<_>>(),
            [("python-huggingface-hub-git", "build failed".to_string())]
        );

        let mut second_wave = ParallelBuildSummary::default();
        let tool = BuildJob::new("second-tool".to_string(), vec![]);
        let failed_tool = BuildJob::new("second-failed-tool".to_string(), vec![]);
        second_wave.record_job_result(&tool, Ok(()));
        second_wave.record_job_result(&failed_tool, Err(anyhow::anyhow!("second failure")));
        summary.merge(second_wave);

        assert_eq!(summary.succeeded_output_count(), 3);
        assert_eq!(summary.failed_output_count(), 2);
        assert_eq!(summary.skipped_output_count(), 0);
        assert_eq!(
            summary
                .failures()
                .map(|(package, error)| (package, error.to_string()))
                .collect::<Vec<_>>(),
            [
                ("python-huggingface-hub-git", "build failed".to_string()),
                ("second-failed-tool", "second failure".to_string()),
            ]
        );
    }

    #[test]
    fn failures_and_dependency_skips_remain_distinct() {
        let mut summary = ParallelBuildSummary::default();
        let first = BuildJob::new("first-base".to_string(), vec![]);
        let second = BuildJob::new("second-base".to_string(), vec![]);
        let blocked = BuildJob::for_package_base(
            "blocked-base".to_string(),
            vec!["blocked-one".to_string(), "blocked-two".to_string()],
            vec!["first-base".to_string()],
        );

        summary.record_job_result(&first, Err(anyhow::anyhow!("first failure")));
        summary.record_job_result(&second, Err(anyhow::anyhow!("second failure")));
        summary.record_skipped(&blocked);

        assert_eq!(summary.failed_output_count(), 2);
        assert_eq!(summary.skipped_output_count(), 2);
        assert_eq!(summary.skipped_outputs(), ["blocked-one", "blocked-two"]);
        assert_eq!(
            summary
                .failures()
                .map(|(package, error)| (package, error.to_string()))
                .collect::<Vec<_>>(),
            [
                ("first-base", "first failure".to_string()),
                ("second-base", "second failure".to_string())
            ]
        );
    }

    #[test]
    fn test_circular_dependency_detection() {
        let mut graph = HashMap::new();
        graph.insert("a".to_string(), ["b".to_string()].into());
        graph.insert("b".to_string(), ["a".to_string()].into());

        let result = ParallelBuilder::topological_levels(&graph);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Circular dependency")
        );
    }
}
