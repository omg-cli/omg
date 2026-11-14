//! Status Model - Elm Architecture implementation for status command
//!
//! Modern, stylish system status dashboard with Bubble Tea-inspired UX.

use crate::cli::style;
use crate::cli::tea::{Cmd, Model};
#[cfg(unix)]
use crate::core::client::DaemonClient;
#[cfg(unix)]
use crate::daemon::protocol::{Request, ResponseResult};
use crate::package_managers::get_package_manager;
use std::fmt::Write;

/// Status data structure
#[derive(Debug, Clone, Default)]
pub struct StatusData {
    pub total_packages: usize,
    pub explicit_packages: usize,
    pub orphan_packages: usize,
    pub updates_available: usize,
    /// Reported findings and uncovered packages; None when coverage is unreported.
    pub advisory_coverage: Option<(usize, usize)>,
    pub duration_ms: f64,
    pub fast_mode: bool,
}

impl StatusData {
    pub(crate) fn render(&self) -> String {
        let mut output = format!(
            "{}\n\n  {} packages installed · {} explicit\n",
            style::emphasis("Status"),
            self.total_packages,
            self.explicit_packages,
        );
        match self.advisory_coverage {
            Some((findings, unknown)) => {
                let summary = if findings == 0 {
                    style::info("No reported findings")
                } else {
                    style::negative(&format!("{findings} findings"))
                };
                let _ = writeln!(output, "  {:<10} {summary}", "Security");
                if unknown > 0 {
                    let _ = writeln!(
                        output,
                        "    {}",
                        style::warning(&format!(
                            "{unknown} packages have unknown advisory applicability"
                        ))
                    );
                }
            }
            None => {
                let _ = writeln!(output, "  {:<10} Advisory coverage unreported", "Security");
            }
        }
        if self.fast_mode {
            let _ = writeln!(
                output,
                "\n  Updates and orphans not checked. Run omg status for a full check."
            );
            return output;
        }

        let _ = writeln!(output, "\n  {:<10} {}", "Updates", self.updates_available);
        let _ = writeln!(output, "  {:<10} {}", "Orphans", self.orphan_packages);
        if self.updates_available > 0 {
            let _ = writeln!(
                output,
                "\n  Review updates with {}",
                style::accent("omg outdated")
            );
        }
        if self.orphan_packages > 0 {
            let _ = writeln!(
                output,
                "\n  Preview orphan removal with {}",
                style::accent("omg clean --orphans --dry-run")
            );
        }
        output
    }
}

/// Status state machine
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusState {
    Idle,
    Loading,
    Complete,
    Failed,
}

/// Status messages
#[derive(Debug, Clone)]
pub enum StatusMsg {
    Load,
    Loaded(StatusData),
    Error(String),
}

/// Status model state
#[derive(Debug, Clone)]
pub struct StatusModel {
    pub data: Option<StatusData>,
    pub state: StatusState,
    pub error: Option<String>,
    pub fast_mode: bool,
}

impl Default for StatusModel {
    fn default() -> Self {
        Self {
            data: None,
            state: StatusState::Idle,
            error: None,
            fast_mode: false,
        }
    }
}

impl StatusModel {
    /// Create new status model
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set fast mode
    #[must_use]
    pub const fn with_fast_mode(mut self, fast: bool) -> Self {
        self.fast_mode = fast;
        self
    }
}

impl Model for StatusModel {
    type Msg = StatusMsg;

    fn init(&self) -> Cmd<Self::Msg> {
        Cmd::exec(|| StatusMsg::Load)
    }

    fn update(&mut self, msg: Self::Msg) -> Cmd<Self::Msg> {
        match msg {
            StatusMsg::Load => {
                self.state = StatusState::Loading;
                let fast = self.fast_mode;

                Cmd::exec(move || {
                    // This logic mirrors the original status.rs logic
                    let start = std::time::Instant::now();

                    // 1. Try Daemon (Hot Path)
                    #[cfg(unix)]
                    let daemon_result =
                        crate::cli::tea::async_bridge::run_blocking_future(async move {
                            tokio::time::timeout(std::time::Duration::from_millis(500), async {
                                if let Ok(mut client) = DaemonClient::connect().await
                                    && let Ok(ResponseResult::Status(status)) =
                                        client.call(Request::Status { id: 0 }).await
                                {
                                    return Some(StatusData {
                                        total_packages: status.total_packages,
                                        explicit_packages: status.explicit_packages,
                                        orphan_packages: status.orphan_packages,
                                        updates_available: status.updates_available,
                                        advisory_coverage: status.scanned_vulnerability_summary(),
                                        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
                                        fast_mode: fast,
                                    });
                                }
                                None
                            })
                            .await
                            .unwrap_or(None)
                        })
                        .unwrap_or(None);

                    #[cfg(not(unix))]
                    let daemon_result: Option<StatusData> = None;

                    if let Some(data) = daemon_result {
                        return StatusMsg::Loaded(data);
                    }

                    // 2. Fallback to direct path
                    let fallback_result =
                        crate::cli::tea::async_bridge::run_blocking_future(async move {
                            let pm = get_package_manager()?;
                            pm.get_status(fast).await
                        })
                        .and_then(std::convert::identity);

                    match fallback_result {
                        Ok((total, explicit, orphans, updates)) => StatusMsg::Loaded(StatusData {
                            total_packages: total,
                            explicit_packages: explicit,
                            orphan_packages: orphans,
                            updates_available: updates,
                            advisory_coverage: None,
                            duration_ms: start.elapsed().as_secs_f64() * 1000.0,
                            fast_mode: fast,
                        }),
                        Err(e) => StatusMsg::Error(e.to_string()),
                    }
                })
            }
            StatusMsg::Loaded(data) => {
                self.data = Some(data);
                self.state = StatusState::Complete;
                Cmd::none()
            }
            StatusMsg::Error(err) => {
                self.state = StatusState::Failed;
                let message = format!("Status check failed: {err}");
                self.error = Some(err);
                Cmd::error(message)
            }
        }
    }

    fn view(&self) -> String {
        match self.state {
            // The returned failure command leaves reporting to the process owner.
            StatusState::Idle | StatusState::Failed => String::new(),
            StatusState::Loading => style::accent("⟳ Gathering system status..."),
            StatusState::Complete => {
                if let Some(data) = &self.data {
                    data.render()
                } else {
                    "No data available".to_string()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_without_scan_never_claims_security_health() {
        for fast_mode in [false, true] {
            let output = StatusData {
                fast_mode,
                ..StatusData::default()
            }
            .render();
            assert!(output.contains("Advisory coverage unreported"));
            assert!(!output.contains("No known issues"));
            assert!(!output.contains("Your system is healthy"));
        }
    }

    #[test]
    fn reported_status_keeps_findings_and_unknown_coverage_together() {
        for fast_mode in [false, true] {
            for (findings, unknown) in [(0, 0), (2, 0), (0, 3), (2, 3)] {
                let output = StatusData {
                    advisory_coverage: Some((findings, unknown)),
                    fast_mode,
                    ..StatusData::default()
                }
                .render();
                assert_eq!(
                    output
                        .lines()
                        .filter(|line| line.split_whitespace().next() == Some("Security"))
                        .count(),
                    1
                );
                assert!(!output.contains("unreported") && !output.contains("Not scanned"));
                assert_eq!(output.contains("No reported findings"), findings == 0);
                assert_eq!(output.contains("2 findings"), findings == 2);
                assert_eq!(
                    output.contains("3 packages have unknown advisory applicability"),
                    unknown == 3
                );
            }
        }
    }

    #[test]
    fn fast_status_does_not_recommend_unchecked_cleanup() {
        let data = StatusData {
            total_packages: 120,
            explicit_packages: 40,
            orphan_packages: 8,
            updates_available: 3,
            fast_mode: true,
            ..StatusData::default()
        };
        let output = data.render();
        assert!(output.contains("120 packages installed · 40 explicit"));
        assert!(output.contains("Updates and orphans not checked"));
        assert!(!output.contains("omg clean"));
        assert!(!output.contains("omg outdated"));
    }

    #[test]
    fn complete_status_only_recommends_actions_for_observed_findings() {
        let clean = StatusData::default().render();
        assert!(!clean.contains("omg clean"));
        assert!(!clean.contains("omg outdated"));
        let data = StatusData {
            orphan_packages: 2,
            updates_available: 5,
            ..StatusData::default()
        };
        let output = data.render();
        assert!(output.contains("omg clean --orphans --dry-run"));
        assert!(output.contains("omg outdated"));
        assert!(
            output
                .lines()
                .any(|line| line.split_whitespace().eq(["Updates", "5"]))
        );
        assert!(
            output
                .lines()
                .any(|line| line.split_whitespace().eq(["Orphans", "2"]))
        );
        let mut model = StatusModel::new();
        let _ = model.update(StatusMsg::Loaded(data));
        assert_eq!(model.view(), output);
    }

    #[test]
    fn test_status_model_initial_state() {
        let model = StatusModel::new();
        assert_eq!(model.state, StatusState::Idle);
        assert!(model.data.is_none());
        assert!(!model.fast_mode);
    }

    #[test]
    fn test_status_model_fast_mode() {
        let model = StatusModel::new().with_fast_mode(true);
        assert!(model.fast_mode);
    }

    #[test]
    fn test_status_model_loading() {
        let mut model = StatusModel::new();
        let _cmd = model.update(StatusMsg::Load);
        assert_eq!(model.state, StatusState::Loading);
    }

    #[test]
    fn test_status_model_loaded() {
        let mut model = StatusModel::new();
        let data = StatusData {
            total_packages: 100,
            explicit_packages: 50,
            orphan_packages: 2,
            updates_available: 5,
            duration_ms: 10.0,
            fast_mode: false,
            advisory_coverage: None,
        };
        let _cmd = model.update(StatusMsg::Loaded(data));
        assert_eq!(model.state, StatusState::Complete);
        assert!(model.data.is_some());
        let received = model.data.as_ref().unwrap();
        assert_eq!(
            (
                received.total_packages,
                received.explicit_packages,
                received.orphan_packages,
                received.updates_available,
            ),
            (100, 50, 2, 5)
        );
        assert!(
            model
                .view()
                .contains("100 packages installed · 50 explicit")
        );
    }
}
