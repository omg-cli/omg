use anyhow::{Context, Result};
use tokio::time::Duration;

use crate::cli::style;
#[cfg(unix)]
use crate::core::client::DaemonClient;
use crate::core::env::distro::{Distro, detect_distro};
use crate::core::http::shared_client;

/// Mirror endpoints to test connectivity.
/// `ARCH_MIRROR_ENDPOINTS` only applies to the Arch backend (W3-A-02).
const ARCH_MIRROR_ENDPOINTS: &[(&str, &str)] = &[
    ("Arch Linux", "https://archlinux.org"),
    ("Kernel.org", "https://kernel.org"),
    ("GitHub", "https://github.com"),
    ("AUR", "https://aur.archlinux.org"),
];

const GENERIC_MIRROR_ENDPOINTS: &[(&str, &str)] = &[
    ("Kernel.org", "https://kernel.org"),
    ("GitHub", "https://github.com"),
];

const ARCH_DNS_HOSTS: &[&str] = &["archlinux.org", "aur.archlinux.org", "github.com"];
const GENERIC_DNS_HOSTS: &[&str] = &["kernel.org", "github.com"];

fn mirror_status_is_issue(status: reqwest::StatusCode) -> bool {
    !status.is_success() && !status.is_redirection()
}

// EOL data lives in `runtimes::eol` (shared with security.rs).

/// Run all health checks
///
/// Exit contract (W3-A-03): `Ok(())` when the system is healthy (0 issues),
/// `Err` when any issue was found, so automation can detect failure — the
/// process exits 0 healthy / 1 on found issues.
pub async fn run(network: bool, eol: bool) -> Result<()> {
    println!(
        "{} Checking system health...\n",
        style::header("OMG Doctor")
    );

    let mut issues = 0;
    let mut warnings = 0;
    let distro = detected_distro();
    let arch_backend = matches!(distro, Distro::Arch);

    // 1. OS Check — every supported backend distro is healthy; only an
    //    unsupported system is an issue (W3-A-02: a supported Debian system
    //    must not be reported as permanently unhealthy).
    if let Some(label) = supported_distro_label(distro) {
        println!("  {}", style::success(label));
    } else {
        println!(
            "  {}",
            style::warning("Unsupported system detected (no package-manager backend)")
        );
        issues += 1;
    }

    // 2. Internet Connectivity (basic check)
    match check_internet(distro).await {
        Ok(endpoint) => println!(
            "  {}",
            style::success(&format!("Internet connectivity ({endpoint} reachable)"))
        ),
        Err([(first, first_result), (second, second_result)]) => {
            println!(
                "  {}",
                style::error(&format!(
                    "Connectivity probes failed ({first}: {}; {second}: {})",
                    first_result.diagnostic(),
                    second_result.diagnostic()
                ))
            );
            issues += 1;
        }
    }

    // 3. Executables required by the selected backend. Privileged operations
    //    resolve root-controlled system tools independently of the caller's
    //    PATH; doctor must make its verdict using that same resolver. Runtime
    //    downloads and archive extraction use Rust libraries, not curl/tar.
    if matches!(distro, Distro::Debian | Distro::Ubuntu) {
        check_required_system_command("apt-get", &mut issues);
    }
    if matches!(
        distro,
        Distro::Arch | Distro::Debian | Distro::Ubuntu | Distro::Fedora
    ) && !crate::core::is_root()
    {
        check_required_system_command("sudo", &mut issues);
    }
    // Git supports project, hook, and team commands on every backend; Arch
    // additionally uses it for AUR checkouts. Neither is required to read or
    // mutate an official package database.
    if supported_distro_label(distro).is_some() {
        check_optional_command("git", "project and Git integration", &mut warnings);
    }
    if arch_backend {
        // Arch documents makepkg as part of pacman. base-devel supplies the
        // build tools for AUR packages; installing it does not repair a
        // missing makepkg executable.
        check_optional_command(
            "makepkg",
            "Arch AUR builds (provided by pacman)",
            &mut warnings,
        );
    }
    #[cfg(any(feature = "macos", target_os = "macos"))]
    if matches!(distro, Distro::MacOS) {
        issues += check_macos_infra().await;
    }

    // 3b. Backend-specific infrastructure (what the compiled backend itself
    //     reads — no invented checks).
    add_native_infra_issues(distro, &mut issues, check_fedora_infra()).await;

    // 4. Daemon Status. The daemon accelerates Linux reads; macOS uses its
    // direct Homebrew backend and should not warn users to start one.
    if matches!(distro, Distro::MacOS) {
        println!("  {}", style::dim("Daemon is not used on macOS"));
    } else {
        match check_daemon().await {
            DaemonStatus::Running => {
                println!("  {}", style::success("Daemon is running"));
            }
            DaemonStatus::Down => {
                println!(
                    "  {}",
                    style::warning("Daemon is not running (run 'omg daemon')")
                );
                warnings += 1;
            }
            DaemonStatus::SocketStale => {
                warnings += 1;
            }
        }
    }

    // 5. PATH Configuration
    match check_path() {
        PathStatus::Current => println!("  {}", style::success("PATH configured correctly")),
        PathStatus::Missing => {
            println!("  {}", style::error("omg executable not found on PATH"));
            issues += 1;
        }
        PathStatus::Shadowed(found) => {
            let found = style::sanitize_terminal_text(&found.display().to_string());
            println!(
                "  {}",
                style::error(&format!(
                    "PATH resolves a different omg executable first: \"{found}\""
                ))
            );
            issues += 1;
        }
        PathStatus::Unverifiable => {
            println!(
                "  {}",
                style::error("Could not verify the omg executable on PATH")
            );
            issues += 1;
        }
    }

    // 6. Shell Hook. A missing hook only costs shell integration,
    // so it warns without failing the run.
    if check_shell_hook() {
        println!("  {}", style::success("Shell hook active"));
    } else {
        println!(
            "  {}",
            style::warning("Shell hook not found in your login shell's rc file (run 'omg init')")
        );
        warnings += 1;
    }

    // 7. Network diagnostics (if requested)
    if network {
        println!();
        println!("{}", style::header("Network Diagnostics"));
        issues += check_network(arch_backend).await;
    }

    // 8. EOL runtime checks (if requested)
    if eol {
        println!();
        println!("{}", style::header("Runtime EOL Status"));
        issues += check_eol_runtimes()?;
    }

    finish_doctor(issues, warnings)
}

/// Print the verdict and select the exit outcome (W3-A-03): healthy runs
/// return `Ok(())` (exit 0); found issues return `Err` so the process exits
/// nonzero (1) and automation can detect failure. Warnings never fail the
/// run, but the verdict names them so a warning never hides behind
/// "healthy".
fn finish_doctor(issues: usize, warnings: usize) -> Result<()> {
    println!();
    if issues == 0 {
        if warnings == 0 {
            println!("{}", style::success("System is healthy! Ready to rock."));
        } else {
            println!(
                "{} System is healthy with {} warning(s).",
                style::success("✓"),
                warnings
            );
        }
        Ok(())
    } else {
        println!(
            "{} Found {} issue(s). Please review.",
            style::warning("→"),
            issues
        );
        Err(anyhow::anyhow!("doctor found {issues} health issue(s)"))
    }
}

/// Add backend health failures to the same count that controls the CLI verdict.
async fn add_native_infra_issues(
    distro: Distro,
    issues: &mut usize,
    fedora_check: impl std::future::Future<Output = usize>,
) {
    *issues += match distro {
        Distro::Debian | Distro::Ubuntu => check_debian_infra(),
        Distro::Arch => check_arch_infra(),
        Distro::Fedora => fedora_check.await,
        Distro::MacOS | Distro::Unknown => 0,
    };
}

/// Distro detected for this doctor run.
///
/// Test mode mirrors the mock-backend default (`arch`) when
/// `OMG_TEST_DISTRO` is unset, so doctor output is hermetic regardless of
/// the host OS.
fn detected_distro() -> Distro {
    if crate::core::paths::test_mode() {
        return std::env::var("OMG_TEST_DISTRO")
            .ok()
            .as_deref()
            .map_or(Distro::Arch, parse_test_distro);
    }
    detect_distro()
}

/// Parse an `OMG_TEST_DISTRO` value (same vocabulary as distro detection).
fn parse_test_distro(value: &str) -> Distro {
    match value.to_lowercase().as_str() {
        "arch" => Distro::Arch,
        "debian" => Distro::Debian,
        "ubuntu" => Distro::Ubuntu,
        "fedora" | "rhel" | "centos" | "rocky" | "alma" => Distro::Fedora,
        "macos" | "darwin" => Distro::MacOS,
        _ => Distro::Unknown,
    }
}

/// Success label for a supported distro (`None` = unsupported system).
fn supported_distro_label(distro: Distro) -> Option<&'static str> {
    match distro {
        Distro::Arch => Some("Arch Linux detected"),
        Distro::Debian | Distro::Ubuntu => Some("Debian/Ubuntu detected (apt backend)"),
        Distro::Fedora => Some("Fedora/RHEL detected (dnf backend)"),
        Distro::MacOS => Some("macOS detected (Homebrew backend)"),
        Distro::Unknown => None,
    }
}

fn doctor_dependencies(distro: Distro) -> Vec<&'static str> {
    let mut deps = vec!["git", "curl", "tar"];
    // Homebrew's supported macOS prefixes need sudo only for the initial
    // installation, not routine package operations.
    if !matches!(distro, Distro::MacOS) {
        deps.push("sudo");
    }
    if matches!(distro, Distro::Debian | Distro::Ubuntu) {
        deps.push("apt-get");
    }
    if matches!(distro, Distro::Arch) {
        deps.push("makepkg");
    }
    deps
}

/// Whether a lists-dir entry is a package index the apt backend can parse:
/// the name carries `_Packages` and the encoding is one
/// `package_managers::debian_db` reads (uncompressed, lz4, gz, xz).
/// InRelease metadata, lock files, and pdiff fragments do not count.
fn is_apt_packages_index(path: &std::path::Path) -> bool {
    let Some(filename) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    apt_lists_entry_has_index(filename)
}

/// Whether a lists directory holds at least one parseable package index.
fn apt_lists_have_packages(lists: &std::path::Path) -> bool {
    lists.is_dir()
        && std::fs::read_dir(lists).is_ok_and(|entries| {
            entries
                .filter_map(Result::ok)
                .any(|entry| is_apt_packages_index(&entry.path()))
        })
}

/// Check the Debian/Ubuntu infrastructure the apt backend actually depends
/// on (W3-A-02): the dpkg status database and the APT package indexes that
/// `package_managers::debian_db` parses directly. No other infrastructure is
/// invented; repo reachability for apt is exactly these on-disk indexes.
fn check_debian_infra() -> usize {
    if crate::core::paths::test_mode() {
        // Hermetic like the other checks: report healthy under test mode.
        return 0;
    }

    let mut issues = 0;

    let status = std::path::Path::new("/var/lib/dpkg/status");
    if status.exists() {
        println!(
            "  {}",
            style::success("dpkg package database (/var/lib/dpkg/status)")
        );
    } else {
        println!(
            "  {}",
            style::error("dpkg package database missing (/var/lib/dpkg/status)")
        );
        issues += 1;
    }

    let lists = std::path::Path::new("/var/lib/apt/lists");
    let has_indexes = apt_lists_have_packages(lists);
    if has_indexes {
        println!(
            "  {}",
            style::success("APT package indexes (/var/lib/apt/lists)")
        );
    } else {
        println!(
            "  {} APT package indexes missing or empty (/var/lib/apt/lists) — run 'sudo apt-get update'",
            style::error("✗")
        );
        issues += 1;
    }

    issues
}

/// Check the tools and local package database used by the Fedora backend.
/// Repository metadata is irrelevant to this check; it must not refresh repos.
async fn check_fedora_infra() -> usize {
    if crate::core::paths::test_mode() {
        return 0;
    }

    let mut issues = 0;
    let dnf = match crate::core::privilege::system_command("dnf") {
        Ok(command) => Some(command),
        Err(error) => {
            println!("  {} DNF backend unavailable: {error}", style::error("✗"));
            issues += 1;
            None
        }
    };
    let rpm = match crate::core::privilege::system_command("rpm") {
        Ok(command) => Some(command),
        Err(error) => {
            println!("  {} RPM backend unavailable: {error}", style::error("✗"));
            issues += 1;
            None
        }
    };
    if let Some(command) = rpm {
        issues += check_fedora_installed_db(command, Duration::from_secs(15)).await;
    }
    if let Some(command) = dnf {
        issues += check_fedora_package_db(command, Duration::from_secs(15)).await;
    }
    issues
}

/// `dnf check` accepts an empty RPM database as consistent. Require RPM to
/// enumerate at least one installed package as a separate read-only check.
async fn check_fedora_installed_db(command: std::process::Command, deadline: Duration) -> usize {
    let mut command = tokio::process::Command::from(command);
    // RPM loads per-user macros from HOME, which can redirect _dbpath away
    // from the system database. system_command also removes XDG_CONFIG_HOME.
    command.env("HOME", "/").arg("-qa").kill_on_drop(true);
    match tokio::time::timeout(deadline, command.output()).await {
        Ok(Ok(output))
            if output.status.success() && !output.stdout.iter().all(u8::is_ascii_whitespace) =>
        {
            println!(
                "  {}",
                style::success("RPM installed package database nonempty")
            );
            0
        }
        Ok(Ok(output)) if output.status.success() => {
            println!(
                "  {} RPM installed package database is empty",
                style::error("✗")
            );
            1
        }
        Ok(Ok(output)) => {
            println!(
                "  {} RPM installed package query failed ({})",
                style::error("✗"),
                output.status
            );
            1
        }
        Ok(Err(error)) => {
            println!(
                "  {} RPM installed package query failed: {error}",
                style::error("✗")
            );
            1
        }
        Err(_) => {
            println!(
                "  {} RPM installed package query timed out",
                style::error("✗")
            );
            1
        }
    }
}

async fn check_fedora_package_db(command: std::process::Command, deadline: Duration) -> usize {
    // Fedora's dnf executable resolves to dnf5; RHEL-family DNF4 uses the
    // older spelling. Both support --cacheonly and `check`.
    let disable_repo = if command.get_program().to_string_lossy().ends_with("dnf5") {
        "--disable-repo=*"
    } else {
        "--disablerepo=*"
    };
    let mut command = tokio::process::Command::from(command);
    command
        .args(["--cacheonly", disable_repo, "check"])
        .kill_on_drop(true);
    match tokio::time::timeout(deadline, command.output()).await {
        Ok(Ok(output)) if output.status.success() => {
            println!("  {}", style::success("DNF local package database healthy"));
            0
        }
        Ok(Ok(output)) => {
            let detail = if output.stderr.is_empty() {
                &output.stdout
            } else {
                &output.stderr
            };
            let detail = String::from_utf8_lossy(detail);
            let detail = detail
                .lines()
                .find(|line| !line.trim().is_empty())
                .map(|line| {
                    style::sanitize_terminal_text(line)
                        .chars()
                        .take(160)
                        .collect::<String>()
                });
            println!(
                "  {} DNF local package database check failed ({}){}",
                style::error("✗"),
                output.status,
                detail.map(|line| format!(": {line}")).unwrap_or_default()
            );
            1
        }
        Ok(Err(error)) => {
            println!(
                "  {} DNF local package database check failed: {error}",
                style::error("✗")
            );
            1
        }
        Err(_) => {
            println!(
                "  {} DNF local package database check timed out",
                style::error("✗")
            );
            1
        }
    }
}

/// Check the same Homebrew installation that the package backend reads and
/// executes. A working `brew` elsewhere on PATH cannot validate that backend.
#[cfg(any(feature = "macos", target_os = "macos"))]
async fn check_macos_infra() -> usize {
    if crate::core::paths::test_mode() {
        return 0;
    }

    let manager = crate::package_managers::homebrew::HomebrewPackageManager::new();
    let caskroom = manager.caskroom();
    let brew = manager.brew_executable();
    check_homebrew_paths(
        &brew,
        [
            ("--prefix", manager.prefix()),
            ("--cellar", manager.cellar()),
            ("--caskroom", &caskroom),
        ],
    )
    .await
}

#[cfg(any(feature = "macos", target_os = "macos"))]
async fn check_homebrew_paths(
    brew: &std::path::Path,
    expected: [(&str, &std::path::Path); 3],
) -> usize {
    if !brew.is_file() {
        println!(
            "  {} Homebrew executable missing ({})",
            style::error("✗"),
            brew.display()
        );
        return 1;
    }

    let mut issues = 0;
    for (option, path) in expected {
        match query_homebrew_path(brew, option, Duration::from_secs(5)).await {
            Ok(actual) if actual == path => {
                if option != "--prefix" {
                    match std::fs::read_dir(path) {
                        Ok(_) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => {
                            println!(
                                "  {} Homebrew {option} inventory cannot be read: {error}",
                                style::error("✗")
                            );
                            issues += 1;
                            continue;
                        }
                    }
                }
                println!(
                    "  {} Homebrew {option} matches backend ({})",
                    style::success("✓"),
                    path.display()
                );
            }
            Ok(actual) => {
                println!(
                    "  {} Homebrew {option} differs from backend: brew={}, omg={}",
                    style::error("✗"),
                    style::sanitize_terminal_text(&actual.display().to_string())
                        .chars()
                        .take(160)
                        .collect::<String>(),
                    path.display()
                );
                issues += 1;
            }
            Err(error) => {
                println!("  {} Homebrew {option} failed: {error}", style::error("✗"));
                issues += 1;
            }
        }
    }
    issues
}

#[cfg(any(feature = "macos", target_os = "macos"))]
async fn query_homebrew_path(
    brew: &std::path::Path,
    option: &str,
    deadline: Duration,
) -> Result<std::path::PathBuf> {
    use anyhow::{bail, ensure};

    let mut command = tokio::process::Command::new(brew);
    command.arg(option).kill_on_drop(true);
    let output = tokio::time::timeout(deadline, command.output())
        .await
        .with_context(|| format!("{option} timed out after {deadline:?}"))?
        .with_context(|| format!("could not execute {option}"))?;
    if !output.status.success() {
        let detail = style::sanitize_terminal_text(&String::from_utf8_lossy(&output.stderr));
        let detail: String = detail.chars().take(160).collect();
        bail!("exit {}: {detail}", output.status);
    }
    let value = String::from_utf8(output.stdout).context("Homebrew path was not UTF-8")?;
    let value = value.strip_suffix('\n').unwrap_or(&value);
    ensure!(
        !value.is_empty()
            && !value.chars().any(|ch| matches!(ch, '\n' | '\r'))
            && value.starts_with('/'),
        "Homebrew returned an invalid path"
    );
    Ok(std::path::PathBuf::from(value))
}

/// Whether an APT lists entry carries a package index. Modern APT acquires
/// compressed indexes (`_Packages.lz4`, `.gz`, `.xz` depending on
/// server/config — see #299), so the compression suffix must be stripped
/// before testing the `_Packages` stem. `InRelease`/`Release` files alone
/// are not indexes.
fn apt_lists_entry_has_index(file_name: &str) -> bool {
    file_name.ends_with("_Packages")
        || file_name.rsplit_once('.').is_some_and(|(name, encoding)| {
            name.ends_with("_Packages")
                && ["lz4", "gz", "xz"]
                    .iter()
                    .any(|supported| encoding.eq_ignore_ascii_case(supported))
        })
}

/// Check the Arch Linux infrastructure the ALPM backend depends on:
/// the pacman configuration file (`/etc/pacman.conf`) and the ALPM local
/// package database directory (`/var/lib/pacman/local`).
#[cfg(feature = "arch")]
fn check_arch_infra() -> usize {
    if crate::core::paths::test_mode() {
        return 0;
    }

    let mut issues = 0;

    let conf_path = crate::core::paths::pacman_conf_path();
    let mut db_path: Option<String> = None;
    if conf_path.exists() {
        match crate::core::pacman_conf::PacmanConfig::parse(&conf_path) {
            Ok(config) => {
                println!(
                    "  {} pacman configuration ({}, {} repos configured)",
                    style::success("✓"),
                    conf_path.display(),
                    config.repos.len()
                );
                db_path = config.db_path;
            }
            Err(e) => {
                println!(
                    "  {} invalid pacman configuration ({}): {e}",
                    style::error("✗"),
                    conf_path.display()
                );
                issues += 1;
            }
        }
    } else {
        println!(
            "  {} pacman configuration missing ({})",
            style::error("✗"),
            conf_path.display()
        );
        issues += 1;
    }

    let local_dir = crate::core::paths::pacman_local_dir();
    if local_dir.is_dir() {
        match crate::package_managers::pacman_db::check_local_db_consistency(&local_dir) {
            Ok(packages) => println!(
                "  {} ALPM local package database ({}, {packages} packages verified)",
                style::success("✓"),
                local_dir.display()
            ),
            Err(error) => {
                println!(
                    "  {} ALPM local package database inconsistent ({}): {error}",
                    style::error("✗"),
                    local_dir.display()
                );
                issues += 1;
            }
        }
    } else {
        println!(
            "  {} ALPM local package database missing ({})",
            style::error("✗"),
            local_dir.display()
        );
        issues += 1;
    }

    issues += check_pacman_lock(db_path.as_deref());

    issues
}

/// Check network connectivity to backend-appropriate mirrors
#[cfg(not(feature = "arch"))]
const fn check_arch_infra() -> usize {
    0
}

async fn check_network(arch_backend: bool) -> usize {
    let client = shared_client();
    let mut issues = 0;

    // Arch-only mirrors (archlinux.org, AUR) do not apply to other backends.
    let endpoints: &[(&str, &str)] = if arch_backend {
        ARCH_MIRROR_ENDPOINTS
    } else {
        GENERIC_MIRROR_ENDPOINTS
    };

    for (name, url) in endpoints {
        let start = std::time::Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(5), client.get(*url).send()).await;

        match result {
            Ok(Ok(response)) => {
                let latency = start.elapsed().as_millis();
                let status = response.status();
                if mirror_status_is_issue(status) {
                    println!(
                        "  {} {} (HTTP {})",
                        style::warning("⚠"),
                        name,
                        status.as_u16()
                    );
                    issues += 1;
                } else {
                    println!("  {} {} ({} ms)", style::success("✓"), name, latency);
                }
            }
            Ok(Err(e)) => {
                println!("  {} {} ({})", style::error("✗"), name, e);
                issues += 1;
            }
            Err(_) => {
                println!("  {} {} (timeout)", style::error("✗"), name);
                issues += 1;
            }
        }
    }

    // DNS resolution test
    println!();
    println!("  {}", style::dim("DNS Resolution:"));
    let dns_hosts: &[&str] = if arch_backend {
        ARCH_DNS_HOSTS
    } else {
        GENERIC_DNS_HOSTS
    };
    for host in dns_hosts {
        // A dead resolver blocks ToSocketAddrs forever and would hang the
        // whole doctor run, so resolve off the executor with a hard timeout.
        let lookup = format!("{host}:443");
        let resolved = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::task::spawn_blocking(move || {
                std::net::ToSocketAddrs::to_socket_addrs(lookup.as_str())
                    .map(std::iter::Iterator::count)
            }),
        )
        .await;
        match resolved {
            Ok(Ok(Ok(count))) => {
                println!("    {} {} ({} addresses)", style::success("✓"), host, count);
            }
            Ok(Ok(Err(e))) => {
                println!("    {} {} ({})", style::error("✗"), host, e);
                issues += 1;
            }
            Ok(Err(e)) => {
                println!(
                    "    {} {} (resolver task failed: {e})",
                    style::error("✗"),
                    host
                );
                issues += 1;
            }
            Err(_) => {
                println!("    {} {} (DNS timeout)", style::error("✗"), host);
                issues += 1;
            }
        }
    }

    issues
}

/// A package-manager process holding the ALPM database lock, by binary name.
/// Kept small and exact: anything else holding db.lck is either a wrapper
/// around these or a stale lock from a crashed run.
#[cfg(feature = "arch")]
const DB_LOCK_HOLDERS: &[&str] = &["pacman", "yay", "paru", "pikaur", "omg"];

/// Whether any package-manager process is currently running, by binary
/// name. Shared by the lock check and its test so both agree on liveness.
///
/// The calling process is excluded by PID: without this, `omg doctor`
/// (comm `omg`) always matches itself and a stale lock is misreported as
/// held by a running manager.
#[cfg(feature = "arch")]
fn package_manager_running() -> bool {
    any_manager_running(std::path::Path::new("/proc"), std::process::id())
}

/// Testable core of [`package_manager_running`]: scan `proc_root` for
/// [`DB_LOCK_HOLDERS`] entries other than `self_pid`.
#[cfg(feature = "arch")]
fn any_manager_running(proc_root: &std::path::Path, self_pid: u32) -> bool {
    std::fs::read_dir(proc_root)
        .into_iter()
        .flatten()
        .flatten()
        .any(|entry| {
            let name = entry.file_name();
            let Some(pid) = name
                .to_str()
                .filter(|name| name.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|name| name.parse::<u32>().ok())
                .filter(|pid| *pid != self_pid)
            else {
                return false;
            };
            let comm = std::fs::read_to_string(proc_root.join(pid.to_string()).join("comm"))
                .map(|comm| comm.trim().to_string())
                .unwrap_or_default();
            DB_LOCK_HOLDERS.contains(&comm.as_str())
        })
}

/// Report a stale pacman database lock. A live lock means a manager is
/// mid-transaction and doctor stays quiet; a lock with no manager behind
/// it blocks every future transaction until removed.
#[cfg(feature = "arch")]
fn check_pacman_lock(db_path: Option<&str>) -> usize {
    let lock = std::path::Path::new(db_path.unwrap_or("/var/lib/pacman")).join("db.lck");
    if !lock.exists() {
        return 0;
    }
    if package_manager_running() {
        println!(
            "  {} Database lock held by a running package manager ({})",
            style::success("✓"),
            lock.display()
        );
        return 0;
    }
    println!(
        "  {} Stale database lock with no package manager running ({})",
        style::error("✗"),
        lock.display()
    );
    println!(
        "    {} Remove it: sudo rm {}",
        style::dim("→"),
        lock.display()
    );
    1
}

/// Check for end-of-life runtimes
fn check_eol_runtimes() -> Result<usize> {
    let mut issues = 0;
    let mut probed = 0;
    let now = jiff::Timestamp::now();
    let warning_ts = crate::runtimes::eol::eol_warning_cutoff(now)
        .context("Failed to compute EOL warning window")?;

    // Get installed runtime versions
    let runtimes = [
        "node", "python", "rust", "go", "ruby", "java", "bun", "deno",
    ];

    for runtime in &runtimes {
        if let Some(version) = crate::runtimes::probe_version(runtime) {
            probed += 1;
            // Check against EOL dates. The canonical table is application
            // data, so malformed dates are a defect and must not silently
            // classify an unsupported runtime as healthy.
            let mut eol_warning = None;

            let components = crate::runtimes::eol::version_components(&version);
            if let Some(entry) = crate::runtimes::eol::find_eol_entry(runtime, &components) {
                let eol_date = jiff::civil::Date::strptime("%Y-%m-%d", entry.eol_date)
                    .with_context(|| {
                        format!(
                            "Invalid EOL date {:?} for {runtime} in the canonical runtime table",
                            entry.eol_date
                        )
                    })?;
                let zoned = eol_date
                    .at(0, 0, 0, 0)
                    .to_zoned(jiff::tz::TimeZone::UTC)
                    .context("Failed to convert runtime EOL date to UTC")?;
                let eol_timestamp = zoned.timestamp();
                if now > eol_timestamp {
                    eol_warning = Some(format!("EOL since {}", entry.eol_date));
                } else if warning_ts > eol_timestamp {
                    eol_warning = Some(format!("EOL on {}", entry.eol_date));
                }
            }

            if let Some(warning) = eol_warning {
                println!(
                    "  {} {} {} - {}",
                    style::warning("⚠"),
                    style::runtime(runtime),
                    style::version(&version),
                    style::error(&warning)
                );
                issues += 1;
            } else {
                println!(
                    "  {} {} {}",
                    style::success("✓"),
                    style::runtime(runtime),
                    style::version(&version)
                );
            }
        }
    }

    if probed == 0 {
        println!("  {}", style::dim("No managed runtimes were detected."));
    } else if issues == 0 {
        println!(
            "  {}",
            style::dim("All detected runtimes are within support period.")
        );
    }

    Ok(issues)
}

#[derive(Debug, PartialEq, Eq)]
enum EndpointProbe {
    Healthy,
    HttpStatus(u16),
    DeadlineExceeded(Duration),
    RequestTimeout,
    ConnectFailure(String),
    RequestFailure(String),
}

impl EndpointProbe {
    fn diagnostic(&self) -> String {
        match self {
            Self::Healthy => "healthy".to_owned(),
            Self::HttpStatus(status) => format!("HTTP {status}"),
            Self::DeadlineExceeded(deadline) => format!("deadline exceeded after {deadline:?}"),
            Self::RequestTimeout => "request timed out".to_owned(),
            Self::ConnectFailure(error) => format!("connection error: {error}"),
            Self::RequestFailure(error) => format!("request error: {error}"),
        }
    }
}

fn bounded_request_error(error: reqwest::Error) -> String {
    // A redirect or proxy error can contain an untrusted URL. Remove the URL
    // and bound terminal-safe detail before including it in doctor output.
    style::sanitize_terminal_text(&error.without_url().to_string())
        .chars()
        .take(160)
        .collect()
}

async fn probe_endpoint(client: &reqwest::Client, url: &str, deadline: Duration) -> EndpointProbe {
    match tokio::time::timeout(deadline, client.get(url).send()).await {
        Ok(Ok(response)) if !mirror_status_is_issue(response.status()) => EndpointProbe::Healthy,
        Ok(Ok(response)) => EndpointProbe::HttpStatus(response.status().as_u16()),
        Ok(Err(error)) if error.is_timeout() => EndpointProbe::RequestTimeout,
        Ok(Err(error)) if error.is_connect() => {
            EndpointProbe::ConnectFailure(bounded_request_error(error))
        }
        Ok(Err(error)) => EndpointProbe::RequestFailure(bounded_request_error(error)),
        Err(_) => EndpointProbe::DeadlineExceeded(deadline),
    }
}

async fn check_internet(
    distro: Distro,
) -> std::result::Result<&'static str, [(&'static str, EndpointProbe); 2]> {
    // This is a basic Internet check, not a claim that any configured package
    // repository is healthy. Repositories can use arbitrary user-configured
    // mirrors, and one public site's outage does not mean Internet is down.
    let endpoints = if matches!(distro, Distro::Arch) {
        [
            ("archlinux.org", "https://archlinux.org"),
            ("kernel.org", "https://kernel.org"),
        ]
    } else {
        [
            ("github.com", "https://github.com"),
            ("kernel.org", "https://kernel.org"),
        ]
    };
    if crate::core::paths::test_mode() {
        return Ok(endpoints[0].0);
    }
    // The detailed mirror probe already uses five seconds. Start both sites
    // together so the basic check has the same ceiling, even when one stalls.
    probe_connectivity(shared_client(), endpoints, Duration::from_secs(5)).await
}

async fn probe_connectivity(
    client: &reqwest::Client,
    [(first_name, first_url), (second_name, second_url)]: [(&'static str, &str); 2],
    deadline: Duration,
) -> std::result::Result<&'static str, [(&'static str, EndpointProbe); 2]> {
    let first_probe = probe_endpoint(client, first_url, deadline);
    let second_probe = probe_endpoint(client, second_url, deadline);
    tokio::pin!(first_probe, second_probe);
    let (first_finished, result) = tokio::select! {
        result = &mut first_probe => (true, result),
        result = &mut second_probe => (false, result),
    };
    if result == EndpointProbe::Healthy {
        return Ok(if first_finished {
            first_name
        } else {
            second_name
        });
    }
    let remaining = if first_finished {
        second_probe.await
    } else {
        first_probe.await
    };
    if remaining == EndpointProbe::Healthy {
        return Ok(if first_finished {
            second_name
        } else {
            first_name
        });
    }
    Err(if first_finished {
        [(first_name, result), (second_name, remaining)]
    } else {
        [(first_name, remaining), (second_name, result)]
    })
}

fn check_optional_command(cmd: &str, purpose: &str, warnings: &mut usize) {
    let available = if crate::core::paths::test_mode() {
        true
    } else {
        which::which(cmd).is_ok()
    };
    if available {
        println!(
            "  {}",
            style::success(&format!("Optional tool available: {cmd}"))
        );
    } else {
        println!(
            "  {}",
            style::warning(&format!("Optional tool unavailable: {cmd} ({purpose})"))
        );
        *warnings += 1;
    }
}

fn check_required_system_command(cmd: &str, issues: &mut usize) {
    if crate::core::paths::test_mode() {
        println!("  {}", style::success(&format!("Found dependency: {cmd}")));
        return;
    }
    if crate::core::privilege::trusted_program(cmd).is_ok() {
        println!("  {}", style::success(&format!("Found dependency: {cmd}")));
    } else {
        println!("  {}", style::error(&format!("Missing dependency: {cmd}")));
        *issues += 1;
    }
}

/// Daemon reachability. `Down` means no socket at all; `SocketStale`
/// means a socket file exists but no daemon answers behind it. Both warn
/// without failing the run: the daemon only accelerates reads.
#[derive(Debug, PartialEq, Eq)]
enum DaemonStatus {
    Running,
    Down,
    SocketStale,
}

async fn check_daemon() -> DaemonStatus {
    if crate::core::paths::test_mode() {
        return DaemonStatus::Running;
    }

    #[cfg(not(unix))]
    {
        // Daemon not supported on Windows
        return DaemonStatus::Down;
    }

    #[cfg(unix)]
    match DaemonClient::connect().await {
        Ok(_) => DaemonStatus::Running,
        Err(e) => {
            // Provide diagnostic feedback
            let socket_path = crate::core::paths::socket_path();
            if socket_path.exists() {
                // Check if it's a permission issue (common under sudo)
                if let Ok(meta) = std::fs::metadata(&socket_path) {
                    use std::os::unix::fs::MetadataExt;
                    let socket_uid = meta.uid();
                    let current_uid = rustix::process::getuid().as_raw();

                    if socket_uid != current_uid {
                        println!(
                            "    {} Socket exists at {}, but belongs to UID {} (you are UID {})",
                            style::error("✗"),
                            socket_path.display(),
                            socket_uid,
                            current_uid
                        );
                        println!(
                            "      Hint: The daemon was likely started by a different user. Try restarting it."
                        );
                        return DaemonStatus::SocketStale;
                    }
                }

                println!(
                    "    {} Socket exists at {}, but connection failed: {:#}",
                    style::warning("⚠"),
                    socket_path.display(),
                    e
                );
                DaemonStatus::SocketStale
            } else {
                // Check if we can find it in common locations despite environment
                let uid = rustix::process::getuid().as_raw();
                let common_path = std::path::PathBuf::from(format!("/run/user/{uid}/omg.sock"));
                if common_path.exists() {
                    println!(
                        "    {} Daemon socket found at {} but client failed to connect!",
                        style::warning("⚠"),
                        common_path.display()
                    );
                    println!("      Hint: Check if the daemon process is actually alive.");
                    DaemonStatus::SocketStale
                } else {
                    DaemonStatus::Down
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PathStatus {
    Current,
    Missing,
    Shadowed(std::path::PathBuf),
    Unverifiable,
}

fn check_path() -> PathStatus {
    if crate::core::paths::test_mode() {
        return PathStatus::Current;
    }
    let Some(path_var) = std::env::var_os("PATH") else {
        return PathStatus::Missing;
    };
    let (Ok(cwd), Ok(current_exe)) = (std::env::current_dir(), std::env::current_exe()) else {
        return PathStatus::Unverifiable;
    };
    path_status(&path_var, &cwd, &current_exe)
}

fn path_status(
    path_var: &std::ffi::OsStr,
    cwd: &std::path::Path,
    current_exe: &std::path::Path,
) -> PathStatus {
    // Shell lookup uses the first runnable match, including relative PATH
    // entries. Resolve each entry against the caller's cwd before probing so
    // this stays testable without changing the process-wide working directory.
    for entry in std::env::split_paths(path_var) {
        let directory = if entry.is_absolute() {
            entry
        } else {
            cwd.join(entry)
        };
        let Ok(mut matches) = which::which_in_global("omg", Some(directory.as_os_str())) else {
            continue;
        };
        let Some(found) = matches.next() else {
            continue;
        };
        // `which` decides executability from mode bits alone, so a directory
        // carrying any execute bit can be returned as a match. A directory is
        // not a runnable `omg`; keep searching the remaining PATH entries.
        if !found.is_file() {
            continue;
        }
        return match same_executable_file(&found, current_exe) {
            Some(true) => PathStatus::Current,
            Some(false) => PathStatus::Shadowed(found),
            None => PathStatus::Unverifiable,
        };
    }
    PathStatus::Missing
}

#[cfg(unix)]
fn same_executable_file(found: &std::path::Path, running: &std::path::Path) -> Option<bool> {
    use std::os::unix::fs::MetadataExt;

    let found = found.metadata().ok()?;
    let running = running.metadata().ok()?;
    Some(found.dev() == running.dev() && found.ino() == running.ino())
}

#[cfg(not(unix))]
fn same_executable_file(found: &std::path::Path, running: &std::path::Path) -> Option<bool> {
    Some(found.canonicalize().ok()? == running.canonicalize().ok()?)
}

fn check_shell_hook() -> bool {
    if crate::core::paths::test_mode() {
        return true;
    }
    // A doctor subshell cannot inspect live shell functions, so verify the
    // hook the same way `omg init` installs it: $SHELL's rc file contains the
    // hook line. The previous stub was hard-wired to `true`, which made doctor
    // report "Shell hook active" unconditionally — false confidence in a
    // diagnostics tool.
    crate::cli::init::shell_from_env().is_some_and(crate::cli::init::shell_rc_has_hook)
}

/// Enable turbo mode — SECURE REDESIGN (audit F-01, CRITICAL).
///
/// The old implementation ran `sudo setcap` on the omg binary, granting
/// CAP_DAC_OVERRIDE/CAP_FOWNER/CAP_CHOWN to EVERY local account on the
/// machine: any user could execute omg and exercise root-equivalent file
/// power. File capabilities cannot be scoped per-user, so this mode was a
/// privilege-escalation primitive on multi-user systems.
///
/// The replacement keeps the zero-friction goal without permanent privilege:
/// 1. removes any file capabilities previously granted by older versions,
/// 2. relies on sudo's credential cache + omg's sudoloop for near-zero-prompt
///    operation (the same model as yay/paru),
/// 3. explains that package operations retain their normal sudo authorization.
#[cfg(target_os = "linux")]
pub fn enable_turbo_mode() -> Result<()> {
    let exe = std::env::current_exe()?;
    let exe_path = exe.display();

    crate::cli::modern_ui::print_phase_header("⚡", "TURBO MODE", "Fast package operations");

    // Strip capabilities an older omg version may have granted. This runs
    // a privileged command, so ask first in an attended terminal.
    println!(
        "  {} Removing legacy file capabilities from {}...",
        crate::cli::style::accent("→"),
        exe_path
    );
    let cleanup_done = if console::user_attended()
        && !dialoguer::Confirm::new()
            .with_prompt("Run `sudo setcap -r` on the omg binary?")
            .default(true)
            .interact()?
    {
        println!(
            "  {} Skipped capability cleanup",
            crate::cli::style::info("ℹ")
        );
        false
    } else {
        true
    };
    if cleanup_done {
        let setcap = crate::core::privilege::trusted_program("setcap")?;
        let remove = crate::core::privilege::system_command("sudo")?
            .arg("--")
            .arg(setcap)
            .arg("-r")
            .arg(&exe)
            .status();
        match remove {
            Ok(status) if status.success() => {
                println!(
                    "  {} No file capabilities remain (or none were set)",
                    crate::cli::style::positive("✓")
                );
            }
            Ok(status) => {
                println!(
                    "  {} `setcap -r` exited with code {}",
                    crate::cli::style::caution("⚠"),
                    status.code().unwrap_or(-1)
                );
            }
            Err(error) => {
                println!(
                    "  {} Could not run `setcap -r`: {error}",
                    crate::cli::style::caution("⚠")
                );
            }
        }
    }
    println!();

    // Warm the sudo credential cache so subsequent operations are
    // prompt-free for the timestamp window; sudoloop keeps it alive during
    // long AUR builds.
    println!("  {} Turbo now means:", crate::cli::style::accent("→"));
    println!(
        "    {} Sudo credential caching (sudoloop) — one prompt per session",
        crate::cli::style::dim("•")
    );
    println!(
        "    {} Native package-manager execution with exact arguments",
        crate::cli::style::dim("•")
    );
    println!(
        "    {} No permanent privileges granted to any binary",
        crate::cli::style::dim("•")
    );
    println!();

    println!(
        "  Authenticate when prompted. Broad passwordless package-manager rules grant unrestricted root authority."
    );

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn enable_turbo_mode() -> Result<()> {
    println!();
    println!(
        "  {} Turbo mode is only available on Linux",
        crate::cli::style::info("ℹ")
    );
    println!();
    println!("  Prompt-light sudo credential caching is only available on Linux.");
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn doctor_dependencies_match_native_backend() {
        assert_eq!(doctor_dependencies(Distro::MacOS), ["git", "curl", "tar"]);
        assert!(doctor_dependencies(Distro::Arch).contains(&"makepkg"));
        assert!(doctor_dependencies(Distro::Ubuntu).contains(&"apt-get"));
        assert!(doctor_dependencies(Distro::Fedora).contains(&"sudo"));
    }

    #[cfg(all(unix, any(feature = "macos", target_os = "macos")))]
    fn fake_brew(prefix: &std::path::Path, script: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let bin = prefix.join("bin");
        std::fs::create_dir_all(&bin).expect("fake brew bin");
        let brew = bin.join("brew");
        std::fs::write(&brew, script).expect("fake brew executable");
        std::fs::set_permissions(&brew, std::fs::Permissions::from_mode(0o755))
            .expect("executable mode");
        brew
    }

    #[cfg(all(unix, any(feature = "macos", target_os = "macos")))]
    #[tokio::test]
    async fn homebrew_doctor_requires_real_matching_backend_paths() {
        let root = tempfile::tempdir().expect("temporary prefix");
        let cellar = root.path().join("Cellar");
        let caskroom = root.path().join("Caskroom");
        let expected = || {
            [
                ("--prefix", root.path()),
                ("--cellar", cellar.as_path()),
                ("--caskroom", caskroom.as_path()),
            ]
        };
        let brew = root.path().join("bin/brew");
        assert_eq!(check_homebrew_paths(&brew, expected()).await, 1);

        let valid = "#!/bin/sh\nprefix=${0%/bin/brew}\ncase \"$1\" in\n  --prefix) printf '%s\\n' \"$prefix\";;\n  --cellar) printf '%s/Cellar\\n' \"$prefix\";;\n  --caskroom) printf '%s/Caskroom\\n' \"$prefix\";;\n  *) exit 64;;\nesac\n";
        let brew = fake_brew(root.path(), valid);
        assert_eq!(check_homebrew_paths(&brew, expected()).await, 0);

        std::fs::write(&cellar, b"not a directory").expect("bad inventory path");
        assert_eq!(check_homebrew_paths(&brew, expected()).await, 1);
        std::fs::remove_file(&cellar).expect("remove bad inventory path");

        let mismatch = valid.replace("'%s/Caskroom\\n' \"$prefix\"", "'/other/Caskroom\\n'");
        fake_brew(root.path(), &mismatch);
        let count = check_homebrew_paths(&brew, expected()).await;
        assert_eq!(count, 1, "mismatched cask inventory must be an issue");
        assert!(finish_doctor(count, 0).is_err());

        let failed = valid.replace(
            "--cellar) printf '%s/Cellar\\n' \"$prefix\";;",
            "--cellar) printf 'broken' >&2; exit 23;;",
        );
        fake_brew(root.path(), &failed);
        assert_eq!(check_homebrew_paths(&brew, expected()).await, 1);
    }

    #[cfg(all(unix, any(feature = "macos", target_os = "macos")))]
    #[tokio::test]
    async fn homebrew_doctor_bounds_hung_probe_and_rejects_bad_output() {
        let root = tempfile::tempdir().expect("temporary prefix");
        let brew = fake_brew(
            root.path(),
            "#!/bin/sh\nsleep 1\nprintf '/opt/homebrew\\n'\n",
        );
        let timeout = query_homebrew_path(&brew, "--prefix", Duration::from_millis(20)).await;
        assert!(
            timeout
                .expect_err("hung brew must fail")
                .to_string()
                .contains("timed out")
        );

        fake_brew(
            root.path(),
            "#!/bin/sh\nprintf '/opt/homebrew\\n/other\\n'\n",
        );
        assert!(
            query_homebrew_path(&brew, "--prefix", Duration::from_secs(1))
                .await
                .is_err()
        );
    }

    async fn serve_probe_response(
        response: &'static [u8],
        delay: Duration,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local probe listener");
        let url = format!(
            "http://{}",
            listener.local_addr().expect("listener address")
        );
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("probe connection");
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.ends_with(b"\r\n\r\n") {
                let count = socket.read(&mut chunk).await.expect("probe request read");
                assert!(count > 0, "probe request ended before headers");
                request.extend_from_slice(&chunk[..count]);
                assert!(request.len() <= 8192, "probe request headers too large");
            }
            tokio::time::sleep(delay).await;
            if delay.is_zero() {
                socket
                    .write_all(response)
                    .await
                    .expect("probe response write");
            } else {
                // The timeout test intentionally drops the client request.
                let _ = socket.write_all(response).await;
            }
        });
        (url, server)
    }

    async fn finish_probe_server(mut server: tokio::task::JoinHandle<()>) {
        if let Ok(result) = tokio::time::timeout(Duration::from_secs(2), &mut server).await {
            result.expect("local probe server");
        } else {
            server.abort();
            panic!("local probe server did not finish");
        }
    }

    #[tokio::test]
    async fn connectivity_probe_distinguishes_http_status_and_transport_failures() {
        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("local probe client");
        const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        const ERROR: &[u8] =
            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let (url, server) = serve_probe_response(OK, Duration::ZERO).await;
        assert_eq!(
            probe_endpoint(&client, &url, Duration::from_secs(1)).await,
            EndpointProbe::Healthy
        );
        finish_probe_server(server).await;

        let (url, server) = serve_probe_response(ERROR, Duration::ZERO).await;
        let status = probe_endpoint(&client, &url, Duration::from_secs(1)).await;
        assert_eq!(status, EndpointProbe::HttpStatus(500));
        assert_eq!(status.diagnostic(), "HTTP 500");
        finish_probe_server(server).await;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("refused probe listener");
        let url = format!(
            "http://{}",
            listener.local_addr().expect("listener address")
        );
        // Close the listener: a bound, non-listening socket need not refuse on every OS.
        drop(listener);
        let refused = probe_endpoint(&client, &url, Duration::from_secs(1)).await;
        assert!(
            matches!(refused, EndpointProbe::ConnectFailure(_)),
            "closed loopback listener must refuse the connection: {refused:?}"
        );
        assert!(refused.diagnostic().starts_with("connection error: "));

        let deadline = Duration::from_millis(50);
        let (url, server) = serve_probe_response(OK, Duration::from_millis(250)).await;
        let elapsed = probe_endpoint(&client, &url, deadline).await;
        assert_eq!(elapsed, EndpointProbe::DeadlineExceeded(deadline));
        assert_eq!(elapsed.diagnostic(), "deadline exceeded after 50ms");
        server.abort();
        let result = server.await;
        assert!(result.is_ok() || result.is_err_and(|error| error.is_cancelled()));

        let short_client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(50))
            .build()
            .expect("short-timeout client");
        let (url, server) = serve_probe_response(OK, Duration::from_millis(250)).await;
        let timed_out = probe_endpoint(&short_client, &url, Duration::from_secs(1)).await;
        assert_eq!(timed_out, EndpointProbe::RequestTimeout);
        assert_eq!(timed_out.diagnostic(), "request timed out");
        server.abort();
        let result = server.await;
        assert!(result.is_ok() || result.is_err_and(|error| error.is_cancelled()));

        let (url, server) =
            serve_probe_response(b"not an HTTP response\r\n\r\n", Duration::ZERO).await;
        let malformed = probe_endpoint(&client, &url, Duration::from_secs(1)).await;
        assert!(matches!(malformed, EndpointProbe::RequestFailure(_)));
        assert!(malformed.diagnostic().starts_with("request error: "));
        finish_probe_server(server).await;
    }

    #[tokio::test]
    async fn basic_connectivity_uses_an_independent_site_but_fails_when_both_fail() {
        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("local probe client");
        const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        const ERROR: &[u8] =
            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

        let (bad_url, bad_server) = serve_probe_response(ERROR, Duration::ZERO).await;
        // Let the failing site answer first: the alternate must still be
        // awaited and allowed to establish connectivity.
        let (good_url, good_server) = serve_probe_response(OK, Duration::from_millis(50)).await;
        assert_eq!(
            probe_connectivity(
                &client,
                [("primary", &bad_url), ("alternate", &good_url)],
                Duration::from_secs(1)
            )
            .await,
            Ok("alternate")
        );
        finish_probe_server(bad_server).await;
        finish_probe_server(good_server).await;

        let (first_url, first_server) = serve_probe_response(ERROR, Duration::ZERO).await;
        let (second_url, second_server) = serve_probe_response(ERROR, Duration::ZERO).await;
        assert_eq!(
            probe_connectivity(
                &client,
                [("primary", &first_url), ("alternate", &second_url)],
                Duration::from_secs(1)
            )
            .await,
            Err([
                ("primary", EndpointProbe::HttpStatus(500)),
                ("alternate", EndpointProbe::HttpStatus(500))
            ])
        );
        finish_probe_server(first_server).await;
        finish_probe_server(second_server).await;
    }

    #[tokio::test]
    async fn basic_connectivity_returns_before_an_unneeded_slow_site() {
        const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("local probe client");
        let (fast_url, fast_server) = serve_probe_response(OK, Duration::ZERO).await;
        let (slow_url, slow_server) = serve_probe_response(OK, Duration::from_secs(3)).await;
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            probe_connectivity(
                &client,
                [("primary", &fast_url), ("alternate", &slow_url)],
                Duration::from_secs(4),
            ),
        )
        .await
        .expect("a healthy primary must not wait for the slow alternate");
        assert_eq!(result, Ok("primary"));
        finish_probe_server(fast_server).await;
        slow_server.abort();
        let result = slow_server.await;
        assert!(result.is_ok() || result.is_err_and(|error| error.is_cancelled()));
    }

    #[test]
    fn apt_index_detection_accepts_plain_and_compressed_entries() {
        // Citations: #299 evidence — bookworm lists carry *_Packages.lz4 +
        // InRelease; .gz/.xz depend on server/config.
        assert!(apt_lists_entry_has_index(
            "deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages"
        ));
        assert!(apt_lists_entry_has_index(
            "deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages.lz4"
        ));
        assert!(apt_lists_entry_has_index("mirror_Packages.gz"));
        assert!(apt_lists_entry_has_index("mirror_Packages.xz"));
        assert!(!apt_lists_entry_has_index("deb.debian.org_InRelease"));
        assert!(!apt_lists_entry_has_index("lock"));
        assert!(!apt_lists_entry_has_index("partial"));
    }

    #[test]
    fn non_success_non_redirect_mirror_status_is_an_issue() {
        assert!(mirror_status_is_issue(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR
        ));
        assert!(!mirror_status_is_issue(reqwest::StatusCode::OK));
        assert!(!mirror_status_is_issue(
            reqwest::StatusCode::TEMPORARY_REDIRECT
        ));
    }

    #[cfg(feature = "arch")]
    #[test]
    fn manager_scan_ignores_self_pid_but_finds_other_managers() {
        let proc = tempfile::TempDir::new().expect("isolated proc dir");
        let self_pid = 4242;
        std::fs::create_dir(proc.path().join(self_pid.to_string())).expect("self pid dir");
        std::fs::write(proc.path().join(self_pid.to_string()).join("comm"), "omg\n")
            .expect("self comm");
        // Only ourselves present: no other manager running.
        assert!(!any_manager_running(proc.path(), self_pid));
        // An unrelated process does not count either.
        std::fs::create_dir(proc.path().join("999")).expect("other pid dir");
        std::fs::write(proc.path().join("999").join("comm"), "bash\n").expect("other comm");
        assert!(!any_manager_running(proc.path(), self_pid));
        // A real second manager does count.
        std::fs::write(proc.path().join("999").join("comm"), "pacman\n").expect("pacman comm");
        assert!(any_manager_running(proc.path(), self_pid));
    }

    /// A lock file with no package manager behind it is stale and counts
    /// as an issue; a missing lock is healthy. The live-manager branch is
    /// not unit-tested: it depends on real process state.
    #[cfg(feature = "arch")]
    #[test]
    fn stale_lock_without_a_manager_is_an_issue() {
        // Host-state dependent: a genuinely running manager means the lock
        // is live, so the stale assertion only runs on quiet machines.
        if package_manager_running() {
            return;
        }
        let dir = tempfile::TempDir::new().expect("isolated db dir");
        let dir_str = dir.path().to_string_lossy().into_owned();
        assert_eq!(check_pacman_lock(Some(&dir_str)), 0);
        std::fs::write(dir.path().join("db.lck"), b"").expect("stale lock");
        assert_eq!(check_pacman_lock(Some(&dir_str)), 1);
    }

    // W3-A-02: every supported backend distro must get a healthy OS verdict;
    // only an unsupported system is an issue.
    #[test]
    fn supported_distros_are_healthy_and_unknown_is_an_issue() {
        assert_eq!(
            supported_distro_label(Distro::Arch),
            Some("Arch Linux detected")
        );
        assert!(supported_distro_label(Distro::Debian).is_some());
        assert!(supported_distro_label(Distro::Ubuntu).is_some());
        assert!(supported_distro_label(Distro::Fedora).is_some());
        assert!(supported_distro_label(Distro::MacOS).is_some());
        assert_eq!(supported_distro_label(Distro::Unknown), None);
    }

    #[test]
    fn test_distro_vocabulary_matches_mock_backend() {
        assert_eq!(parse_test_distro("arch"), Distro::Arch);
        assert_eq!(parse_test_distro("debian"), Distro::Debian);
        assert_eq!(parse_test_distro("ubuntu"), Distro::Ubuntu);
        assert_eq!(parse_test_distro("rhel"), Distro::Fedora);
        assert_eq!(parse_test_distro("darwin"), Distro::MacOS);
        assert_eq!(parse_test_distro("nonsense"), Distro::Unknown);
    }

    /// #299: stock Debian/Ubuntu ships compressed indexes
    /// (`*_Packages.lz4`, no uncompressed `*_Packages`), which the apt
    /// backend parses — doctor must accept the same files it depends on.
    #[test]
    fn compressed_packages_indexes_count_as_healthy() {
        let dir = tempfile::TempDir::new().expect("isolated lists dir");
        for name in [
            "deb.debian.org_debian_dists_bookworm_InRelease",
            "deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages.lz4",
            "lock",
        ] {
            std::fs::write(dir.path().join(name), b"").expect("fixture file");
        }
        assert!(apt_lists_have_packages(dir.path()));

        let dir = tempfile::TempDir::new().expect("isolated lists dir");
        for name in [
            "mirror_dists_noble_main_binary-amd64_Packages.gz",
            "mirror_dists_noble_main_binary-amd64_Packages.xz",
            "mirror_dists_noble_main_binary-amd64_Packages",
        ] {
            std::fs::write(dir.path().join(name), b"").expect("fixture file");
        }
        assert!(apt_lists_have_packages(dir.path()));
    }

    #[test]
    fn dotted_host_packages_indexes_count_as_healthy() {
        for suffix in ["", ".lz4", ".gz", ".xz", ".LZ4", ".GZ", ".XZ"] {
            let dir = tempfile::TempDir::new().expect("isolated lists dir");
            let name =
                format!("deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages{suffix}");
            std::fs::write(dir.path().join(name), b"").expect("index fixture");
            assert!(apt_lists_have_packages(dir.path()), "suffix {suffix:?}");
        }
    }

    /// InRelease metadata, lock files, and pdiff fragments are not package
    /// indexes; an empty or index-free lists dir stays an issue.
    #[test]
    fn non_index_lists_content_stays_an_issue() {
        let dir = tempfile::TempDir::new().expect("isolated lists dir");
        assert!(!apt_lists_have_packages(dir.path()));
        for name in [
            "deb.debian.org_debian_dists_bookworm_InRelease",
            "lock",
            "partial",
            "mirror_main_binary-amd64_Packages.diff_Index",
            "deb.debian.org_main_binary-amd64_Packages.bz2",
            "deb.debian.org_main_binary-amd64_Packages.diff.gz",
            "mirror_main_binary-amd64_Packages_backup",
            "mirror_main_binary-amd64_Packages.gz.bak",
        ] {
            std::fs::write(dir.path().join(name), b"").expect("fixture file");
        }
        assert!(!apt_lists_have_packages(dir.path()));
    }

    // W3-A-03: exit contract — 0 issues is Ok (exit 0); any issue count is
    // Err (exit 1) so automation can detect failure. Warnings never fail.
    #[test]
    fn zero_issues_is_ok_and_found_issues_are_err() {
        assert!(finish_doctor(0, 0).is_ok());
        assert!(finish_doctor(0, 2).is_ok());
        let err = finish_doctor(3, 0).expect_err("issues must produce Err");
        assert!(err.to_string().contains('3'), "err: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn path_requires_an_executable_omg_not_just_a_listed_bin_directory() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = tempfile::TempDir::new().expect("isolated PATH fixture");
        let bin = fixture.path().join(".local/bin");
        std::fs::create_dir_all(&bin).expect("user bin fixture");
        let path = std::env::join_paths([&bin]).expect("fixture PATH");

        let status = || path_status(&path, fixture.path(), &bin.join("omg"));
        assert_eq!(status(), PathStatus::Missing, "empty bin is not proof");
        let other = bin.join("omgd");
        std::fs::write(&other, b"#!/bin/sh\nexit 0\n").expect("other executable");
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o700))
            .expect("executable permissions");
        assert_eq!(status(), PathStatus::Missing, "omgd does not satisfy omg");

        let omg = bin.join("omg");
        std::fs::write(&omg, b"#!/bin/sh\nexit 0\n").expect("omg fixture");
        std::fs::set_permissions(&omg, std::fs::Permissions::from_mode(0o600))
            .expect("non-executable permissions");
        assert_eq!(
            status(),
            PathStatus::Missing,
            "non-executable omg is not runnable"
        );
        std::fs::set_permissions(&omg, std::fs::Permissions::from_mode(0o700))
            .expect("executable permissions");
        assert_eq!(status(), PathStatus::Current, "runnable omg must be found");
    }

    #[cfg(unix)]
    #[test]
    fn path_rejects_a_directory_named_omg_and_keeps_searching() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = tempfile::TempDir::new().expect("isolated PATH fixture");
        let decoy = fixture.path().join("decoy");
        let real = fixture.path().join("real");
        std::fs::create_dir_all(&decoy).expect("decoy bin fixture");
        std::fs::create_dir_all(&real).expect("real bin fixture");
        let path = std::env::join_paths([&decoy, &real]).expect("fixture PATH");

        // `which` decides executability from mode bits alone, so a directory
        // carrying the execute bit can be handed back as a match. A directory
        // is not a runnable `omg` and must not satisfy the check.
        let as_directory = decoy.join("omg");
        std::fs::create_dir_all(&as_directory).expect("omg directory fixture");
        std::fs::set_permissions(&as_directory, std::fs::Permissions::from_mode(0o755))
            .expect("executable directory permissions");

        let status = || path_status(&path, fixture.path(), &real.join("omg"));
        assert_eq!(
            status(),
            PathStatus::Missing,
            "a directory named omg is not a runnable omg"
        );

        let omg = real.join("omg");
        std::fs::write(&omg, b"#!/bin/sh\nexit 0\n").expect("omg fixture");
        std::fs::set_permissions(&omg, std::fs::Permissions::from_mode(0o700))
            .expect("executable permissions");
        assert_eq!(
            status(),
            PathStatus::Current,
            "a runnable omg later on PATH must still be found"
        );
    }

    #[cfg(unix)]
    #[test]
    fn path_follows_a_runnable_symlink_and_rejects_a_broken_one() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let fixture = tempfile::TempDir::new().expect("isolated PATH fixture");
        let bin = fixture.path().join("bin");
        std::fs::create_dir(&bin).expect("bin fixture");
        let target = fixture.path().join("real-omg");
        symlink(&target, bin.join("omg")).expect("omg symlink");
        let path = std::env::join_paths([&bin]).expect("fixture PATH");
        assert_eq!(
            path_status(&path, fixture.path(), &target),
            PathStatus::Missing,
            "broken symlink is not runnable"
        );

        std::fs::write(&target, b"#!/bin/sh\nexit 0\n").expect("symlink target");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700))
            .expect("executable permissions");
        assert_eq!(
            path_status(&path, fixture.path(), &target),
            PathStatus::Current,
            "runnable symlink must be found"
        );

        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("non-executable permissions");
        assert_eq!(
            path_status(&path, fixture.path(), &target),
            PathStatus::Missing,
            "symlink target must be runnable"
        );
    }

    #[cfg(unix)]
    #[test]
    fn path_uses_relative_entries_and_rejects_an_earlier_shadowing_binary() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = tempfile::TempDir::new().expect("isolated PATH fixture");
        let bin = fixture.path().join("bin");
        let stale = fixture.path().join("stale");
        std::fs::create_dir(&bin).expect("current bin");
        std::fs::create_dir(&stale).expect("stale bin");
        let current = bin.join("omg");
        let shadow = stale.join("omg");
        for executable in [&current, &shadow] {
            std::fs::write(executable, b"#!/bin/sh\nexit 0\n").expect("executable fixture");
            std::fs::set_permissions(executable, std::fs::Permissions::from_mode(0o700))
                .expect("executable permissions");
        }

        let relative = std::env::join_paths(["./bin"]).expect("relative PATH");
        assert_eq!(
            path_status(&relative, fixture.path(), &current),
            PathStatus::Current,
            "a relative PATH entry launches the current OMG from this directory"
        );

        let hardlink_bin = fixture.path().join("hardlink-bin");
        std::fs::create_dir(&hardlink_bin).expect("hardlink bin");
        std::fs::hard_link(&current, hardlink_bin.join("omg")).expect("same executable hardlink");
        let hardlinked = std::env::join_paths([&hardlink_bin, &bin]).expect("hardlink PATH");
        assert_eq!(
            path_status(&hardlinked, fixture.path(), &current),
            PathStatus::Current,
            "an earlier hardlink to the running binary is not a shadow"
        );

        let shadowed = std::env::join_paths([&stale, &bin]).expect("shadowed PATH");
        assert_eq!(
            path_status(&shadowed, fixture.path(), &current),
            PathStatus::Shadowed(shadow),
            "the first executable on PATH controls the next plain omg command"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn fedora_local_db_check_requires_exact_offline_command_and_success() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = tempfile::TempDir::new().expect("isolated DNF fixture");
        let program = fixture.path().join("dnf5");
        for (name, repo_flag) in [("dnf5", "--disable-repo=*"), ("dnf", "--disablerepo=*")] {
            let program = fixture.path().join(name);
            std::fs::write(
                &program,
                format!(
                    "#!/bin/sh\n[ \"$1\" = --cacheonly ] && [ \"$2\" = '{repo_flag}' ] && [ \"$3\" = check ] && [ \"$#\" = 3 ]\n"
                ),
            )
            .expect("DNF fixture");
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700))
                .expect("executable DNF fixture");
            assert_eq!(
                check_fedora_package_db(
                    std::process::Command::new(&program),
                    Duration::from_secs(2)
                )
                .await,
                0,
                "{name} should use its documented offline flags"
            );
        }
        std::fs::write(&program, b"#!/bin/sh\nexit 23\n").expect("failing DNF fixture");
        let issues =
            check_fedora_package_db(std::process::Command::new(&program), Duration::from_secs(2))
                .await;
        assert_eq!(issues, 1);
        let mut doctor_issues = 0;
        add_native_infra_issues(Distro::Fedora, &mut doctor_issues, async { issues }).await;
        assert_eq!(doctor_issues, 1);
        let error = finish_doctor(doctor_issues, 0).expect_err("failed DNF must fail doctor");
        assert!(error.to_string().contains("1 health issue"));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn fedora_empty_rpm_inventory_is_a_health_issue() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = tempfile::TempDir::new().expect("isolated RPM fixture");
        let program = fixture.path().join("rpm");
        let caller_home = fixture.path().join("caller-home");
        std::fs::create_dir(&caller_home).expect("caller home");
        std::fs::write(caller_home.join(".rpmmacros"), "%_dbpath /alternate-db\n")
            .expect("user RPM macro fixture");
        let probe = || {
            let mut command = std::process::Command::new(&program);
            command.env("HOME", &caller_home);
            check_fedora_installed_db(command, Duration::from_secs(2))
        };
        for (script, expected) in [
            (
                "#!/bin/sh\n[ \"$HOME\" = / ] && [ \"$1\" = -qa ] && printf 'filesystem-1-1\\n'\n",
                0,
            ),
            ("#!/bin/sh\n[ \"$1\" = -qa ]\n", 1),
            ("#!/bin/sh\nexit 23\n", 1),
        ] {
            std::fs::write(&program, script).expect("RPM fixture");
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700))
                .expect("executable RPM fixture");
            assert_eq!(probe().await, expected);
        }
        let doctor_issues = probe().await;
        assert_eq!(doctor_issues, 1);
        assert!(finish_doctor(doctor_issues, 0).is_err());
    }
}
