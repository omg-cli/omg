use anyhow::{Context, Result};

use crate::cli::{style, ui};
use crate::runtimes::{
    BunManager, DenoManager, DotnetManager, ErlangManager, GenericToolManager, GoManager,
    JavaManager, NodeManager, PhpManager, PiManager, PythonManager, RubyManager, RustManager,
    SUPPORTED_RUNTIMES, SwiftManager, ZigManager,
};

pub fn resolve_active_version(runtime: &str) -> Result<Option<String>> {
    resolve_active_version_in(runtime, None)
}

pub(crate) fn resolve_active_version_in(
    runtime: &str,
    data_dir: Option<&std::path::Path>,
) -> Result<Option<String>> {
    // File-based detection (.tool-versions, .nvmrc, ...) is keyed by canonical
    // tool names ("node", "python"), so aliases such as "nodejs" or "golang"
    // must be normalized before lookup.
    let runtime = canonical_runtime_name(runtime);
    let versions = crate::hooks::get_active_versions()?;
    if let Some(version) = versions.get(&runtime) {
        return Ok(Some(version.clone()));
    }
    if SUPPORTED_RUNTIMES.contains(&runtime.as_str())
        || crate::runtimes::tool_registry::is_registry_tool(&runtime)
    {
        return Ok(match data_dir {
            Some(data_dir) => crate::runtimes::probe_version_in(&runtime, data_dir),
            None => crate::runtimes::probe_version(&runtime),
        });
    }
    Ok(None)
}

pub fn ensure_active_version(runtime: &str) -> Result<Option<String>> {
    if let Some(version) = resolve_active_version(runtime)? {
        return Ok(Some(version));
    }
    Ok(None)
}

pub(crate) fn ensure_active_version_in(
    runtime: &str,
    data_dir: &std::path::Path,
) -> Result<Option<String>> {
    resolve_active_version_in(runtime, Some(data_dir))
}

pub fn known_runtimes() -> Result<Vec<String>> {
    let mut runtimes: Vec<String> = SUPPORTED_RUNTIMES
        .iter()
        .chain(
            crate::runtimes::tool_registry::REGISTRY_TOOLS
                .iter()
                .map(|tool| &tool.name),
        )
        .map(|name| (*name).to_string())
        .collect();

    runtimes.sort();
    runtimes.dedup();
    Ok(runtimes)
}

/// Strip a single leading `v` prefix (Node tags like `v20.10.0`) while keeping
/// the rest of the string intact. Unlike `trim_start_matches`, this cannot
/// over-trim repeated prefixes (`trim_start_matches` would turn "vv1" into "1").
#[must_use]
fn strip_version_prefix(version: &str) -> &str {
    // https://doc.rust-lang.org/std/primitive.str.html#method.strip_prefix
    version.strip_prefix('v').unwrap_or(version)
}

trait RuntimeInstallUse {
    fn list_installed(&self) -> Result<Vec<String>>;
    fn use_version(&self, version: &str) -> Result<()>;
    async fn install(&self, version: &str) -> Result<()>;
}

macro_rules! impl_runtime_install_use {
    ($($t:ty),+ $(,)?) => {
        $(
            impl RuntimeInstallUse for $t {
                fn list_installed(&self) -> Result<Vec<String>> { self.list_installed() }
                fn use_version(&self, version: &str) -> Result<()> { self.use_version(version) }
                async fn install(&self, version: &str) -> Result<()> { self.install(version).await }
            }
        )+
    };
}

impl_runtime_install_use!(
    NodeManager,
    PythonManager,
    GoManager,
    RubyManager,
    JavaManager,
    BunManager,
    PiManager,
    DenoManager,
    GenericToolManager,
    ZigManager,
    DotnetManager,
    ErlangManager,
    PhpManager,
    SwiftManager
);

/// Use an already-installed version, or install it first if missing.
async fn install_or_use<M: RuntimeInstallUse + Sync>(mgr: &M, version: &str) -> Result<()> {
    let installed = mgr
        .list_installed()
        .context("Failed to list installed runtime versions")?;
    if installed.iter().any(|v| v == version) {
        mgr.use_version(version)?;
    } else {
        mgr.install(version).await?;
    }
    Ok(())
}

fn canonical_runtime_name(runtime: &str) -> String {
    match runtime.to_ascii_lowercase().as_str() {
        "nodejs" => "node".to_string(),
        "python3" => "python".to_string(),
        "golang" => "go".to_string(),
        "rustlang" => "rust".to_string(),
        "jdk" | "openjdk" => "java".to_string(),
        "bunjs" => "bun".to_string(),
        "ziglang" => "zig".to_string(),
        normalized => normalized.to_string(),
    }
}

fn validate_requested_version(runtime: &str, version: &str) -> Result<()> {
    let version = if runtime == "node" {
        version.strip_prefix("lts/").unwrap_or(version)
    } else {
        version
    };
    crate::core::security::validate_runtime_version(version)?;
    Ok(())
}

pub async fn use_version(runtime: &str, version: Option<&str>) -> Result<()> {
    select_version(runtime, version, false).await
}

/// Restore saved state without refreshing an already-installed PHP channel.
/// Explicit `use` retains PHP's documented rolling-channel refresh behavior.
pub(crate) async fn restore_version(runtime: &str, version: &str) -> Result<()> {
    select_version(runtime, Some(version), true).await
}

async fn select_version(runtime: &str, version: Option<&str>, restoring: bool) -> Result<()> {
    crate::core::security::validate_package_name(runtime)?;
    let runtime = canonical_runtime_name(runtime);

    let version = if let Some(v) = version {
        v.to_string()
    } else {
        let active = crate::hooks::get_active_versions()?;
        let Some(v) = active.get(&runtime) else {
            anyhow::bail!("No version specified and none detected in .tool-versions, .nvmrc, etc.");
        };
        println!(
            "{} Detected version {} from file",
            style::informative("→"),
            style::caution(v)
        );
        v.clone()
    };
    validate_requested_version(&runtime, &version)?;
    crate::core::paths::ensure_data_dir().context("Failed to create runtime data directory")?;

    ui::print_header("OMG", &format!("Switching {runtime} to version {version}"));
    ui::print_spacer();

    match runtime.as_str() {
        "node" => {
            install_or_use(&NodeManager::new(), strip_version_prefix(&version)).await?;
        }
        "python" => {
            install_or_use(&PythonManager::new(), strip_version_prefix(&version)).await?;
        }
        "rust" => {
            // Rust manager handles toolchains internally; always delegates to install
            RustManager::new().install(&version).await?;
        }
        "go" => {
            install_or_use(&GoManager::new(), strip_version_prefix(&version)).await?;
        }
        "ruby" => {
            install_or_use(&RubyManager::new(), strip_version_prefix(&version)).await?;
        }
        "java" => {
            install_or_use(&JavaManager::new(), &version).await?;
        }
        "bun" => {
            install_or_use(&BunManager::new(), strip_version_prefix(&version)).await?;
        }
        "pi" => {
            install_or_use(&PiManager::new(), strip_version_prefix(&version)).await?;
        }
        "deno" => {
            install_or_use(&DenoManager::new(), strip_version_prefix(&version)).await?;
        }
        "zig" => {
            install_or_use(&ZigManager::new(), strip_version_prefix(&version)).await?;
        }
        "dotnet" => {
            install_or_use(&DotnetManager::new(), strip_version_prefix(&version)).await?;
        }
        "erlang" => {
            install_or_use(&ErlangManager::new(), strip_version_prefix(&version)).await?;
        }
        "php" => {
            let manager = PhpManager::new();
            if restoring {
                install_or_use(&manager, strip_version_prefix(&version)).await?;
            } else {
                manager.install(strip_version_prefix(&version)).await?;
            }
        }
        "swift" => {
            install_or_use(&SwiftManager::new(), strip_version_prefix(&version)).await?;
        }
        other => {
            let Some(manager) = GenericToolManager::for_name(other) else {
                anyhow::bail!(
                    "Unsupported runtime '{runtime}'. Supported runtimes: {}",
                    known_runtimes().unwrap_or_default().join(", ")
                );
            };
            install_or_use(&manager, strip_version_prefix(&version)).await?;
        }
    }

    crate::core::usage::track_runtime_switch(&runtime);
    Ok(())
}

/// Remove an installed runtime version. The version is required and must
/// not be the active one; removal deletes only that version's directory.
pub fn uninstall_version(runtime: &str, version: &str) -> Result<()> {
    crate::core::security::validate_package_name(runtime)?;
    let runtime = canonical_runtime_name(runtime);
    crate::core::security::validate_runtime_version(version)?;

    ui::print_header("OMG", &format!("Removing {runtime} version {version}"));
    ui::print_spacer();

    match runtime.as_str() {
        "node" => NodeManager::new().uninstall(strip_version_prefix(version))?,
        "python" => PythonManager::new().uninstall(strip_version_prefix(version))?,
        "rust" => RustManager::new().uninstall(version)?,
        "go" => GoManager::new().uninstall(strip_version_prefix(version))?,
        "ruby" => RubyManager::new().uninstall(strip_version_prefix(version))?,
        "java" => JavaManager::new().uninstall(version)?,
        "bun" => BunManager::new().uninstall(strip_version_prefix(version))?,
        "pi" => PiManager::new().uninstall(strip_version_prefix(version))?,
        "deno" => DenoManager::new().uninstall(strip_version_prefix(version))?,
        "zig" => ZigManager::new().uninstall(strip_version_prefix(version))?,
        "dotnet" => DotnetManager::new().uninstall(strip_version_prefix(version))?,
        "erlang" => ErlangManager::new().uninstall(strip_version_prefix(version))?,
        "php" => PhpManager::new().uninstall(strip_version_prefix(version))?,
        "swift" => SwiftManager::new().uninstall(strip_version_prefix(version))?,
        other => {
            let Some(manager) = GenericToolManager::for_name(other) else {
                anyhow::bail!(
                    "Unsupported runtime '{runtime}'. Supported runtimes: {}",
                    known_runtimes().unwrap_or_default().join(", ")
                );
            };
            manager.uninstall(strip_version_prefix(version))?;
        }
    }

    println!("{} Removed {runtime} {version}", style::positive("✓"));
    Ok(())
}

/// Probe one natively supported runtime's installed and active versions.
/// Aliases (`nodejs`, `golang`, `jdk`, ...) are normalized via
/// `canonical_runtime_name` before dispatch.
fn native_version_info(runtime: &str) -> Option<(Result<Vec<String>>, Option<String>)> {
    macro_rules! probe {
        ($mgr:expr) => {{
            let mgr = $mgr;
            Some((mgr.list_installed(), mgr.current_version()))
        }};
    }
    match canonical_runtime_name(runtime).as_str() {
        "node" => probe!(NodeManager::new()),
        "python" => probe!(PythonManager::new()),
        "rust" => probe!(RustManager::new()),
        "go" => probe!(GoManager::new()),
        "ruby" => probe!(RubyManager::new()),
        "java" => probe!(JavaManager::new()),
        "bun" => probe!(BunManager::new()),
        "pi" => probe!(PiManager::new()),
        "deno" => probe!(DenoManager::new()),
        "zig" => probe!(ZigManager::new()),
        "dotnet" => probe!(DotnetManager::new()),
        "erlang" => probe!(ErlangManager::new()),
        "php" => probe!(PhpManager::new()),
        "swift" => probe!(SwiftManager::new()),
        other => GenericToolManager::for_name(other)
            .map(|manager| (manager.list_installed(), manager.current_version())),
    }
}

fn print_installed_versions(installed: Vec<String>, current: Option<&str>) {
    for v in installed {
        let meta = if current == Some(v.as_str()) {
            Some("(active)")
        } else {
            None
        };
        ui::print_list_item(&v, meta);
    }
}

fn print_listed_versions(
    runtime: &str,
    installed: Result<Vec<String>>,
    current: Option<&str>,
) -> Result<()> {
    print_installed_versions(
        installed.with_context(|| format!("Failed to list installed {runtime} versions"))?,
        current,
    );
    Ok(())
}

/// Build one JSON object describing a runtime's installed versions.
fn runtime_versions_value(
    runtime: &str,
    installed: Result<Vec<String>>,
    current: Option<&str>,
) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "runtime": runtime,
        "current": current,
        "installed": installed
            .with_context(|| format!("Failed to list installed {runtime} versions"))?,
    }))
}

/// JSON entry for a natively supported runtime.
fn installed_json_entry(runtime: &str) -> Result<Option<serde_json::Value>> {
    let Some((installed, current)) = native_version_info(runtime) else {
        return Ok(None);
    };
    runtime_versions_value(
        &canonical_runtime_name(runtime),
        installed,
        current.as_deref(),
    )
    .map(Some)
}

/// JSON output for installed runtime versions.
fn list_installed_json(runtime: Option<&str>) -> Result<()> {
    if let Some(rt) = runtime {
        let Some(entry) = installed_json_entry(rt)? else {
            anyhow::bail!("Unsupported runtime '{rt}'");
        };
        println!("{}", serde_json::to_string_pretty(&entry)?);
        return Ok(());
    }

    let mut entries = Vec::new();
    for rt in known_runtimes()? {
        if let Some(entry) = installed_json_entry(&rt)? {
            entries.push(entry);
        }
    }
    println!("{}", serde_json::to_string_pretty(&entries)?);
    Ok(())
}

pub fn list_versions_sync(runtime: Option<&str>, json: bool) -> Result<()> {
    if json {
        return list_installed_json(runtime);
    }

    if let Some(rt) = runtime {
        ui::print_header("OMG", &format!("{rt} versions"));
        ui::print_spacer();

        match native_version_info(rt) {
            Some((installed, current)) => {
                print_listed_versions(&canonical_runtime_name(rt), installed, current.as_deref())?;
            }
            None => anyhow::bail!("Unsupported runtime '{rt}'"),
        }
    } else {
        ui::print_header("OMG", "Installed runtime versions");
        ui::print_spacer();

        for runtime in known_runtimes()? {
            if let Some((installed, current)) = native_version_info(&runtime) {
                for version in installed
                    .with_context(|| format!("Failed to list installed {runtime} versions"))?
                {
                    let metadata =
                        (current.as_deref() == Some(version.as_str())).then_some("(active)");
                    ui::print_list_item(&format!("{runtime} {version}"), metadata);
                }
            }
        }
    }

    ui::print_spacer();
    Ok(())
}

pub async fn list_versions(runtime: Option<&str>, available: bool, json: bool) -> Result<()> {
    if !available {
        return list_versions_sync(runtime, json);
    }

    if json {
        anyhow::bail!("--json is not supported together with --available");
    }

    let Some(rt) = runtime else {
        // List all installed runtimes (parallel probe)
        ui::print_header("OMG", "Installed runtime versions");
        ui::print_spacer();

        let (
            node_res,
            py_res,
            rust_res,
            go_res,
            ruby_res,
            java_res,
            bun_res,
            pi_res,
            deno_res,
            zig_res,
            dotnet_res,
            erlang_res,
            php_res,
            swift_res,
        ) = tokio::join!(
            tokio::task::spawn_blocking(|| NodeManager::new().current_version()),
            tokio::task::spawn_blocking(|| PythonManager::new().current_version()),
            tokio::task::spawn_blocking(|| RustManager::new().current_version()),
            tokio::task::spawn_blocking(|| GoManager::new().current_version()),
            tokio::task::spawn_blocking(|| RubyManager::new().current_version()),
            tokio::task::spawn_blocking(|| JavaManager::new().current_version()),
            tokio::task::spawn_blocking(|| BunManager::new().current_version()),
            tokio::task::spawn_blocking(|| PiManager::new().current_version()),
            tokio::task::spawn_blocking(|| DenoManager::new().current_version()),
            tokio::task::spawn_blocking(|| ZigManager::new().current_version()),
            tokio::task::spawn_blocking(|| DotnetManager::new().current_version()),
            tokio::task::spawn_blocking(|| ErlangManager::new().current_version()),
            tokio::task::spawn_blocking(|| PhpManager::new().current_version()),
            tokio::task::spawn_blocking(|| SwiftManager::new().current_version()),
        );

        for (name, res) in [
            ("Node.js", node_res),
            ("Python", py_res),
            ("Rust", rust_res),
            ("Go", go_res),
            ("Ruby", ruby_res),
            ("Java", java_res),
            ("Bun", bun_res),
            ("Pi", pi_res),
            ("Deno", deno_res),
            ("Zig", zig_res),
            (".NET", dotnet_res),
            ("Erlang/OTP", erlang_res),
            ("PHP", php_res),
            ("Swift", swift_res),
        ] {
            let version = res.with_context(|| format!("Failed to inspect {name} versions"))?;
            if let Some(v) = version {
                ui::print_list_item(name, Some(&v));
            }
        }

        ui::print_spacer();
        return Ok(());
    };

    ui::print_header("OMG", &format!("{rt} versions"));
    ui::print_spacer();

    // `!available` already returned above, so all arms here list remote versions
    match rt.to_lowercase().as_str() {
        "node" | "nodejs" => {
            let mgr = NodeManager::new();
            println!("{} Available remote versions:", style::informative("→"));
            for v in mgr.list_available().await?.iter().take(20) {
                let lts = crate::runtimes::node::get_lts_name(v)
                    .map(|s| format!(" ({})", style::accent(s)))
                    .unwrap_or_default();
                ui::print_list_item(&v.version, Some(&lts));
            }
        }
        "python" => {
            let mgr = PythonManager::new();
            println!(
                "{} Available remote versions (python-build-standalone):",
                style::informative("→")
            );
            for v in mgr.list_available().await?.iter().take(20) {
                let pre = if v.prerelease { " (pre-release)" } else { "" };
                ui::print_list_item(&v.version, Some(pre));
            }
        }
        "rust" => {
            let mgr = RustManager::new();
            println!("{} Available remote versions:", style::informative("→"));
            for v in mgr.list_available().await?.iter().take(20) {
                ui::print_list_item(&v.version, Some(&v.channel));
            }
        }
        "go" | "golang" => {
            let mgr = GoManager::new();
            println!("{} Available remote versions:", style::informative("→"));
            for v in mgr.list_available().await?.iter().take(20) {
                let stable = if v.stable() { " (stable)" } else { "" };
                ui::print_list_item(v.version(), Some(stable));
            }
        }
        "ruby" => {
            let mgr = RubyManager::new();
            println!(
                "{} Available remote versions (ruby-builder):",
                style::informative("→")
            );
            for v in mgr.list_available().await?.iter().take(20) {
                ui::print_list_item(&v.version, None);
            }
        }
        "java" | "jdk" => {
            let mgr = JavaManager::new();
            println!(
                "{} Available remote versions (Adoptium):",
                style::informative("→")
            );
            for v in mgr.list_available().await?.iter().take(20) {
                let lts = if v.lts { " (LTS)" } else { "" };
                ui::print_list_item(&v.version, Some(lts));
            }
        }
        "bun" | "bunjs" => {
            let mgr = BunManager::new();
            println!("{} Available remote versions:", style::informative("→"));
            for v in mgr.list_available().await?.iter().take(20) {
                let pre = if v.prerelease { " (pre-release)" } else { "" };
                ui::print_list_item(&v.version, Some(pre));
            }
        }
        "pi" => {
            anyhow::bail!(
                "Remote Pi version listing is not yet supported; specify an exact npm version"
            );
        }
        "deno" => {
            let mgr = DenoManager::new();
            println!(
                "{} Available remote versions (denoland/deno):",
                style::informative("→")
            );
            for v in mgr.list_available().await?.iter().take(20) {
                let pre = if v.prerelease { " (pre-release)" } else { "" };
                ui::print_list_item(&v.version, Some(pre));
            }
        }
        "zig" => {
            let mgr = ZigManager::new();
            println!(
                "{} Available remote versions (ziglang.org):",
                style::informative("→")
            );
            for v in mgr.list_available().await?.iter().take(20) {
                ui::print_list_item(&v.version, None);
            }
        }
        "dotnet" => {
            let mgr = DotnetManager::new();
            println!(
                "{} Available remote versions (builds.dotnet.microsoft.com):",
                style::informative("→")
            );
            for v in mgr.list_available().await?.iter().take(20) {
                let pre = if v.prerelease { " (pre-release)" } else { "" };
                ui::print_list_item(&v.version, Some(pre));
            }
        }
        "erlang" => {
            let mgr = ErlangManager::new();
            println!(
                "{} Available remote versions (builds.hex.pm / erlef/otp_builds):",
                style::informative("→")
            );
            for v in mgr.list_available().await?.iter().take(20) {
                ui::print_list_item(&v.version, None);
            }
        }
        "swift" => {
            let mgr = SwiftManager::new();
            println!("{} Available remote versions:", style::informative("→"));
            for version in mgr.list_available().await?.iter().take(20) {
                ui::print_list_item(&version.version, None);
            }
        }
        "php" => {
            let mgr = PhpManager::new();
            println!(
                "{} Available remote channels (shivammathur/php-builder):",
                style::informative("→")
            );
            for v in mgr.list_available().await?.iter().take(20) {
                ui::print_list_item(&v.version, None);
            }
        }
        other => {
            let Some(mgr) = GenericToolManager::for_name(other) else {
                anyhow::bail!("Unsupported runtime '{rt}'");
            };
            println!(
                "{} Available {} versions ({}):",
                style::informative("→"),
                other,
                mgr.description()
            );
            for v in mgr.list_available().await?.iter().take(20) {
                let pre = if v.prerelease { " (pre-release)" } else { "" };
                ui::print_list_item(&v.version, Some(pre));
            }
        }
    }

    ui::print_spacer();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{canonical_runtime_name, validate_requested_version};

    #[test]
    fn node_lts_requests_do_not_relax_directory_validation() {
        assert!(validate_requested_version("node", "lts/iron").is_ok());
        assert!(validate_requested_version("node", "lts/jod").is_ok());
        assert!(validate_requested_version("node", "22.0.0").is_ok());
        for version in ["lts/", "lts/..", "lts/../../tmp", "lts/iron/extra"] {
            assert!(
                validate_requested_version("node", version).is_err(),
                "{version}"
            );
        }
        assert!(validate_requested_version("python", "lts/iron").is_err());
        assert!(crate::core::security::validate_runtime_version("lts/iron").is_err());
    }

    #[test]
    fn runtime_versions_value_is_valid_json_with_expected_fields() {
        let current = "20.10.0".to_string();
        let value = super::runtime_versions_value(
            "node",
            Ok(vec!["20.10.0".to_string(), "18.0.0".to_string()]),
            Some(current.as_str()),
        )
        .expect("version payload must serialize");
        assert_eq!(value["runtime"], "node");
        assert_eq!(value["current"], "20.10.0");
        assert_eq!(
            value["installed"].as_array().map(std::vec::Vec::len),
            Some(2)
        );
    }

    #[test]
    fn installed_json_entry_rejects_unsupported_runtimes() {
        let entry = super::installed_json_entry("cobol").expect("probe must succeed");
        assert!(entry.is_none(), "unsupported runtimes have no JSON entry");
    }

    #[test]
    fn installed_json_entry_covers_newly_supported_erlang() {
        // Erlang graduated from unsupported (previous assertion above used
        // it as the example) to a native manager: it must resolve to an
        // entry, empty when nothing is installed.
        let entry = super::installed_json_entry("erlang").expect("probe must succeed");
        assert!(entry.is_some(), "native runtimes need a JSON entry");
    }

    #[test]
    fn runtime_aliases_normalize_before_dispatch() {
        for (alias, canonical) in [
            ("NodeJS", "node"),
            ("python3", "python"),
            ("GOLANG", "go"),
            ("rustlang", "rust"),
            ("jdk", "java"),
            ("openjdk", "java"),
            ("bunjs", "bun"),
        ] {
            assert_eq!(canonical_runtime_name(alias), canonical);
        }
    }

    #[test]
    fn unsupported_runtime_names_are_preserved_for_diagnostics() {
        assert_eq!(canonical_runtime_name("Erlang"), "erlang");
        assert_eq!(canonical_runtime_name("deno"), "deno");
    }

    #[test]
    fn known_runtimes_covers_fourteen_natives_plus_fifty_four_registry_tools() {
        let runtimes = super::known_runtimes().expect("runtime list must build");
        assert_eq!(
            runtimes.len(),
            68,
            "14 natives + 54 registry tools: {runtimes:?}"
        );
        for name in [
            "node",
            "zig",
            "dotnet",
            "erlang",
            "php",
            "swift",
            "ripgrep",
            "kustomize",
            "kotlin",
            "scala",
            "elixir",
            "ghcup",
        ] {
            assert!(
                runtimes.iter().any(|runtime| runtime == name),
                "{name} is known"
            );
        }
    }

    #[test]
    fn registry_tools_reach_generic_uninstall_dispatch() {
        // Mirrors the e2e dispatch contract: a registry tool must reach its
        // uninstall implementation ("not installed") rather than fail as an
        // unsupported runtime.
        let error = super::uninstall_version("ripgrep", "999.999.999")
            .expect_err("missing version must fail");
        assert!(
            error.to_string().contains("not installed"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn registry_tools_have_version_info_dispatch() {
        // Uninstalled registry tools still resolve to a (empty) version entry.
        let entry = super::installed_json_entry("ripgrep").expect("probe must succeed");
        assert!(entry.is_some(), "registry tools need a JSON entry");
    }
}
