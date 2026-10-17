//! Info Model - Elm Architecture implementation for info command
//!
//! Modern, stylish package information display with Bubble Tea-inspired UX.

use crate::cli::style;
use crate::cli::tea::{Cmd, Model};
#[cfg(unix)]
use crate::core::PackageSource;
#[cfg(unix)]
use crate::core::client::DaemonClient;
use crate::package_managers::get_package_manager;
use std::fmt::Write;
use std::time::Duration;

#[cfg(feature = "arch")]
use crate::package_managers::{AurClient, search_detailed};

const DAEMON_INFO_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(feature = "arch")]
const AUR_INFO_TIMEOUT: Duration = Duration::from_secs(8);

/// Source of package information
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InfoSource {
    Official,
    Aur,
}

impl InfoSource {
    pub fn styled_label(&self) -> String {
        match self {
            Self::Official => style::accent("Official Repository"),
            Self::Aur => style::caution("AUR (Arch User Repository)"),
        }
    }
}

#[cfg(any(test, feature = "arch", feature = "debian"))]
fn non_negative_install_size(size: i64) -> Option<u64> {
    u64::try_from(size).ok()
}

/// Package information structure
#[derive(Debug, Clone)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub source: InfoSource,
    pub repo: String,
    pub url: Option<String>,
    pub size: Option<u64>,
    pub licenses: Vec<String>,
    pub maintainer: Option<String>,
    pub popularity: Option<f64>,
    pub out_of_date: bool,
    pub installed: bool,
}

/// Info state machine
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InfoState {
    Idle,
    Loading,
    Complete,
}

/// Info messages
#[derive(Debug, Clone)]
pub enum InfoMsg {
    Fetch(String),
    InfoReceived(PackageInfo),
    NotFound(String),
    Error(String),
}

/// The Info Model
#[derive(Debug, Clone)]
pub struct InfoModel {
    pub package_name: String,
    pub info: Option<PackageInfo>,
    pub state: InfoState,
}

impl Default for InfoModel {
    fn default() -> Self {
        Self {
            package_name: String::new(),
            info: None,
            state: InfoState::Idle,
        }
    }
}

impl InfoModel {
    /// Create new info model
    #[must_use]
    pub fn new(package_name: String) -> Self {
        Self {
            package_name,
            ..Default::default()
        }
    }

    /// Get package name
    #[must_use]
    pub fn package_name(&self) -> &str {
        &self.package_name
    }

    /// Render a key-value pair
    fn render_kv(key: &str, value: &str) -> String {
        format!("  {:<15} {}", style::emphasis(key), value)
    }
}

impl Model for InfoModel {
    type Msg = InfoMsg;

    fn init(&self) -> Cmd<Self::Msg> {
        let pkg = self.package_name.clone();
        Cmd::exec(move || InfoMsg::Fetch(pkg))
    }

    fn update(&mut self, msg: Self::Msg) -> Cmd<Self::Msg> {
        match msg {
            InfoMsg::Fetch(pkg) => {
                self.package_name.clone_from(&pkg);
                self.state = InfoState::Loading;

                Cmd::exec(move || {
                    let pkg_name = pkg;

                    crate::cli::tea::async_bridge::run_blocking_future(async move {
                        fetch_info(&pkg_name).await
                    })
                    .unwrap_or_else(|err| InfoMsg::Error(err.to_string()))
                })
            }
            InfoMsg::InfoReceived(info) => {
                self.info = Some(info);
                self.state = InfoState::Complete;
                Cmd::none()
            }
            InfoMsg::NotFound(pkg) => {
                self.package_name = pkg;
                self.state = InfoState::Idle;
                Cmd::error(format!("Package '{}' not found", self.package_name))
            }
            InfoMsg::Error(err) => {
                self.state = InfoState::Idle;
                Cmd::error(format!("Failed to fetch info: {err}"))
            }
        }
    }

    fn view(&self) -> String {
        match self.state {
            InfoState::Idle => String::new(),
            InfoState::Loading => {
                style::accent(&format!("⟳ Fetching info for '{}'...", self.package_name))
            }
            InfoState::Complete => {
                if let Some(info) = &self.info {
                    let mut output = String::new();
                    let subtitle = style::sanitize_terminal_text(&info.name);
                    let _ = writeln!(
                        output,
                        "{}",
                        crate::cli::modern_ui::phase_header_text("Info", &subtitle)
                    );

                    let _ = writeln!(
                        output,
                        "{}",
                        Self::render_kv(
                            "Name",
                            &style::package(&style::sanitize_terminal_text(&info.name))
                        )
                    );
                    let _ = writeln!(
                        output,
                        "{}",
                        Self::render_kv(
                            "Version",
                            &style::version(&style::sanitize_terminal_text(&info.version))
                        )
                    );

                    let source_val = if info.repo == "aur" {
                        info.source.styled_label()
                    } else {
                        format!(
                            "{} ({})",
                            info.source.styled_label(),
                            style::info(&style::sanitize_terminal_text(&info.repo))
                        )
                    };
                    let _ = writeln!(output, "{}", Self::render_kv("Source", &source_val));
                    let _ = writeln!(
                        output,
                        "{}",
                        Self::render_kv("Installed", if info.installed { "yes" } else { "no" })
                    );
                    let _ = writeln!(
                        output,
                        "{}",
                        Self::render_kv(
                            "Description",
                            &style::sanitize_terminal_text(&info.description)
                        )
                    );

                    if info.out_of_date {
                        let _ = writeln!(
                            output,
                            "{}",
                            Self::render_kv("Status", &style::error("OUT OF DATE"))
                        );
                    }

                    if crate::cli::modern_ui::is_verbose() {
                        if let Some(url) = &info.url {
                            let _ = writeln!(
                                output,
                                "{}",
                                Self::render_kv(
                                    "URL",
                                    &style::url(&style::sanitize_terminal_text(url))
                                )
                            );
                        }

                        if let Some(size) = info.size {
                            let _ =
                                writeln!(output, "{}", Self::render_kv("Size", &style::size(size)));
                        }

                        if !info.licenses.is_empty() {
                            let _ = writeln!(
                                output,
                                "{}",
                                Self::render_kv(
                                    "License",
                                    &style::sanitize_terminal_text(&info.licenses.join(", "))
                                )
                            );
                        }

                        if let Some(maintainer) = &info.maintainer {
                            let _ = writeln!(
                                output,
                                "{}",
                                Self::render_kv(
                                    "Maintainer",
                                    &style::sanitize_terminal_text(maintainer)
                                )
                            );
                        }

                        if let Some(pop) = info.popularity {
                            let _ = writeln!(
                                output,
                                "{}",
                                Self::render_kv("Popularity", &format!("{pop:.2}%"))
                            );
                        }
                    }

                    output
                } else {
                    "No info available".to_string()
                }
            }
        }
    }
}

fn package_is_installed(name: &str) -> bool {
    crate::package_managers::is_installed_fast(name).unwrap_or(false)
}

/// Helper function to fetch package info
async fn fetch_info(package: &str) -> InfoMsg {
    // 1. Try Daemon first
    #[cfg(unix)]
    if let Ok(Ok(info)) = tokio::time::timeout(DAEMON_INFO_TIMEOUT, async {
        let mut client = DaemonClient::connect().await?;
        client.info(package).await
    })
    .await
    {
        return InfoMsg::InfoReceived(PackageInfo {
            name: info.name,
            version: info.version,
            description: info.description,
            source: if PackageSource::from(info.source) == PackageSource::Official {
                InfoSource::Official
            } else {
                InfoSource::Aur
            },
            repo: info.repo,
            url: if info.url.is_empty() {
                None
            } else {
                Some(info.url)
            },
            size: Some(info.size),
            licenses: info.licenses,
            maintainer: None,
            popularity: None,
            out_of_date: false,
            installed: package_is_installed(package),
        });
    }

    // 2. Fallback to local package manager
    let pm = match get_package_manager() {
        Ok(pm) => pm,
        Err(error) => return InfoMsg::Error(error.to_string()),
    };
    if pm.name() == "pacman" {
        #[cfg(feature = "arch")]
        {
            match crate::package_managers::get_sync_pkg_info(package) {
                Ok(Some(info)) => {
                    return InfoMsg::InfoReceived(PackageInfo {
                        name: info.name,
                        version: info.version.to_string(),
                        description: info.description,
                        source: InfoSource::Official,
                        repo: info.repo,
                        url: info.url,
                        size: info.install_size.and_then(non_negative_install_size),
                        licenses: vec![],
                        maintainer: None,
                        popularity: None,
                        out_of_date: false,
                        installed: info.installed,
                    });
                }
                Ok(None) => {}
                Err(error) => return InfoMsg::Error(error.to_string()),
            }
        }
    } else if pm.name() == "apt" || pm.name() == "apt-pure" {
        #[cfg(feature = "debian")]
        {
            match crate::package_managers::apt_get_sync_pkg_info(package) {
                Ok(Some(info)) => {
                    return InfoMsg::InfoReceived(PackageInfo {
                        name: info.name,
                        version: info.version.to_string(),
                        description: info.description,
                        source: InfoSource::Official,
                        repo: "apt".to_string(),
                        url: info.url,
                        size: info.install_size.and_then(non_negative_install_size),
                        licenses: vec![],
                        maintainer: None,
                        popularity: None,
                        out_of_date: false,
                        installed: info.installed,
                    });
                }
                Ok(None) => return InfoMsg::NotFound(package.to_string()),
                Err(error) => return InfoMsg::Error(error.to_string()),
            }
        }
        #[cfg(all(not(feature = "debian"), feature = "debian-pure"))]
        {
            match crate::package_managers::debian_db::get_info_fast(package) {
                Ok(Some(pkg)) => {
                    return InfoMsg::InfoReceived(PackageInfo {
                        name: pkg.name,
                        version: pkg.version.to_string(),
                        description: pkg.description,
                        source: InfoSource::Official,
                        repo: "apt".to_string(),
                        url: None,
                        size: None,
                        licenses: vec![],
                        maintainer: None,
                        popularity: None,
                        out_of_date: false,
                        installed: pkg.installed,
                    });
                }
                Ok(None) => return InfoMsg::NotFound(package.to_string()),
                Err(error) => return InfoMsg::Error(error.to_string()),
            }
        }
    }

    // 3. AUR Fallback (Arch Only)
    #[cfg(feature = "arch")]
    {
        let aur = match AurClient::new() {
            Ok(client) => client,
            Err(error) => return InfoMsg::Error(error.to_string()),
        };
        let aur_info = tokio::time::timeout(AUR_INFO_TIMEOUT, aur.info(package)).await;
        let info = match aur_info {
            Ok(Ok(Some(info))) => info,
            Ok(Ok(None)) => return InfoMsg::NotFound(package.to_string()),
            Ok(Err(error)) => return InfoMsg::Error(error.to_string()),
            Err(_) => return InfoMsg::Error(format!("Timed out looking up {package} on the AUR")),
        };
        {
            // Get more details if possible
            let mut popularity = None;
            let mut maintainer = None;
            let mut out_of_date = false;
            let mut url = None;
            let mut licenses = vec![];

            // Try detailed search to enrich
            if let Ok(Ok(detailed)) =
                tokio::time::timeout(AUR_INFO_TIMEOUT, search_detailed(package)).await
                && let Some(d) = detailed.into_iter().find(|p| p.name == info.name)
            {
                popularity = Some(d.popularity);
                if let Some(lic) = d.license {
                    licenses = lic;
                }
                url = d.url;
                maintainer = d.maintainer;
                out_of_date = d.out_of_date.is_some();
            }

            InfoMsg::InfoReceived(PackageInfo {
                name: info.name,
                version: info.version.to_string(),
                description: info.description,
                source: InfoSource::Aur,
                repo: "aur".to_string(),
                url,
                size: None, // AUR packages don't have binary size until built
                licenses,
                maintainer,
                popularity,
                out_of_date,
                installed: package_is_installed(package),
            })
        }
    }

    #[cfg(not(feature = "arch"))]
    {
        info_requires_backend(package)
    }
}

#[cfg(any(not(feature = "arch"), test))]
fn info_requires_backend(package: &str) -> InfoMsg {
    InfoMsg::Error(format!(
        "Package information for '{package}' is not available without an Arch or Debian package backend"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_info_model_initial_state() {
        let model = InfoModel::new("test".to_string());
        assert!(model.info.is_none());
        assert_eq!(model.state, InfoState::Idle);
        assert_eq!(model.package_name(), "test");
    }

    #[test]
    fn test_info_model_fetch_message() {
        let mut model = InfoModel::new("test".to_string());
        let _cmd = model.update(InfoMsg::Fetch("test-pkg".to_string()));
        assert_eq!(model.state, InfoState::Loading);
        assert_eq!(model.package_name, "test-pkg");
    }

    #[test]
    fn test_info_model_info_received() {
        let mut model = InfoModel::new("test".to_string());
        let test_info = PackageInfo {
            name: "test-pkg".to_string(),
            version: "1.0.0".to_string(),
            description: "Test".to_string(),
            source: InfoSource::Official,
            repo: "extra".to_string(),
            url: None,
            size: None,
            licenses: vec![],
            maintainer: None,
            popularity: None,
            out_of_date: false,
            installed: false,
        };
        let _cmd = model.update(InfoMsg::InfoReceived(test_info));
        assert_eq!(model.state, InfoState::Complete);
        assert_eq!(model.info.as_ref().unwrap().name, "test-pkg");
        assert_eq!(model.info.as_ref().unwrap().version, "1.0.0");
    }

    #[test]
    fn test_info_view_with_data() {
        let mut model = InfoModel::new("test".to_string());
        let _ = model.update(InfoMsg::InfoReceived(PackageInfo {
            name: "test-pkg".to_string(),
            version: "1.0.0\u{200b}\u{1b}[31m\u{202e}spoofed".to_string(),
            description: "A package for displaying fixture metadata".to_string(),
            source: InfoSource::Official,
            repo: "extra\u{1b}[31m\u{202e}repo".to_string(),
            url: None,
            size: None,
            licenses: vec![],
            maintainer: None,
            popularity: None,
            out_of_date: false,
            installed: false,
        }));
        let view = model.view();
        assert!(view.contains("test-pkg"));
        assert!(view.contains("Official Repository"));
        assert!(view.contains("A package for displaying fixture metadata"));
        assert!(
            !view.contains("\u{1b}[31m"),
            "view must exclude the raw ANSI control sequence, got: {view}"
        );
        assert!(
            !view.contains('\u{202e}') && !view.contains('\u{200b}'),
            "view must exclude the bidi override and zero-width chars, got: {view}"
        );
        assert!(view.contains("Installed"));
        assert!(
            !view.contains("URL") && !view.contains("Size"),
            "compact view must hide verbose fields, got: {view}"
        );
    }

    #[test]
    fn negative_install_sizes_are_not_cast_to_huge_values() {
        assert_eq!(non_negative_install_size(-1), None);
        assert_eq!(non_negative_install_size(0), Some(0));
        assert_eq!(non_negative_install_size(42), Some(42));
    }

    #[test]
    fn info_without_backend_is_an_error_not_not_found() {
        match info_requires_backend("bash") {
            InfoMsg::Error(message) => {
                assert!(
                    message.contains("not available without an Arch or Debian package backend"),
                    "got: {message}"
                );
            }
            other => panic!("missing backend must not look like a missing package, got: {other:?}"),
        }
    }
}
