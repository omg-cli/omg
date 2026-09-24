use std::path::PathBuf;

use crate::core::paths;

pub(crate) mod eol;

static DATA_DIR: std::sync::LazyLock<PathBuf> = std::sync::LazyLock::new(paths::data_dir);

pub(crate) mod bun;
pub(crate) mod common;
pub(crate) mod deno;
pub(crate) mod dotnet;
pub(crate) mod erlang;
pub(crate) mod github_tool;
pub(crate) mod go;
pub(crate) mod java;
pub(crate) mod node;
pub(crate) mod php;
pub(crate) mod pi;
pub(crate) mod python;
pub(crate) mod ruby;
pub(crate) mod rust;
pub(crate) mod swift;
pub(crate) mod tool_registry;
pub(crate) mod zig;

pub(crate) use bun::BunManager;
pub(crate) use deno::DenoManager;
pub(crate) use dotnet::DotnetManager;
pub(crate) use erlang::ErlangManager;
pub(crate) use github_tool::GenericToolManager;
pub(crate) use go::GoManager;
pub(crate) use java::JavaManager;
pub(crate) use node::NodeManager;
pub(crate) use php::PhpManager;
pub(crate) use pi::PiManager;
pub(crate) use python::PythonManager;
pub(crate) use ruby::RubyManager;
pub(crate) use rust::RustManager;
pub(crate) use swift::SwiftManager;
pub(crate) use zig::ZigManager;

/// Bespoke language managers with vendor-specific release APIs.
pub(crate) const NATIVE_RUNTIMES: &[&str] = &[
    "node", "python", "go", "rust", "ruby", "java", "bun", "pi", "deno", "zig", "dotnet", "erlang",
    "php", "swift",
];

/// Runtimes managed natively by OMG.
pub(crate) const SUPPORTED_RUNTIMES: &[&str] = NATIVE_RUNTIMES;

/// Resolve a partial version request (`20`, `20.1`) against known release
/// names. Exact and non-numeric requests pass through unchanged. One shared
/// shape so the five managers cannot drift apart.
#[must_use]
pub(crate) fn resolve_version_request(names: &[String], requested: &str) -> String {
    if !common::is_partial_version(requested) {
        return requested.to_owned();
    }
    common::resolve_partial_version(names, requested).unwrap_or_else(|| requested.to_owned())
}

/// Fast probing for active runtime versions. The current symlink must
/// resolve to a real version directory inside the runtime versions tree;
/// missing or external targets are not reported as active.
#[must_use]
pub(crate) fn probe_version(runtime: &str) -> Option<String> {
    probe_version_in(runtime, &DATA_DIR)
}

#[must_use]
pub(crate) fn probe_version_in(runtime: &str, data_dir: &std::path::Path) -> Option<String> {
    common::get_current_version(&data_dir.join("versions").join(runtime))
}
