//! Declarative registry of GitHub-release CLI tools managed natively by OMG.
//!
//! This is the data half of OMG's answer to mise's `github:`/`ubi` backend:
//! each entry names a GitHub repo plus the primary executable to expose, and
//! all download/verify/activate logic lives in [`super::github_tool`]. Adding
//! coverage for a new single-binary tool is one table row, not a new manager.
//!
//! Source for the shortlist: the mise default registry (`jdx/mise`
//! `registry.toml`, tier-1/2 backends) intersected with tools that publish
//! per-platform release archives. Repo paths below mirror those registry
//! entries; binary names are the upstream executable names.

/// One natively managed GitHub-release tool.
pub(crate) struct RegistryTool {
    /// Canonical tool name (`omg use ripgrep <version>`).
    pub name: &'static str,
    /// GitHub `owner/repo` used for the releases API.
    pub repo: &'static str,
    /// Primary executable to expose on `PATH`.
    pub binary: &'static str,
    /// One-line description for listings.
    pub description: &'static str,
    /// Required substring of the release asset name (e.g. `"kotlin-compiler"`
    /// steers past same-release native images). `None` accepts any asset.
    pub asset_must_contain: Option<&'static str>,
    /// Asset names containing this substring are never selected (e.g. documentation
    /// archives published next to the real payload). `None` disables the veto.
    pub asset_must_not_contain: Option<&'static str>,
}

/// Fifty-four GitHub-release tools. Together with the bespoke language
/// managers in [`super`], OMG registers 68 runtimes/tools.
pub(crate) const REGISTRY_TOOLS: &[RegistryTool] = &[
    RegistryTool {
        name: "ripgrep",
        repo: "BurntSushi/ripgrep",
        binary: "rg",
        description: "Ultra-fast regex search tool",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "fd",
        repo: "sharkdp/fd",
        binary: "fd",
        description: "Fast find alternative",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "bat",
        repo: "sharkdp/bat",
        binary: "bat",
        description: "Cat with syntax highlighting",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "eza",
        repo: "eza-community/eza",
        binary: "eza",
        description: "Modern ls replacement",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "fzf",
        repo: "junegunn/fzf",
        binary: "fzf",
        description: "Fuzzy finder",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "zoxide",
        repo: "ajeetdsouza/zoxide",
        binary: "zoxide",
        description: "Smarter cd command",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "starship",
        repo: "starship/starship",
        binary: "starship",
        description: "Cross-shell prompt",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "just",
        repo: "casey/just",
        binary: "just",
        description: "Command runner",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "task",
        repo: "go-task/task",
        binary: "task",
        description: "Task runner / build tool",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "jq",
        repo: "jqlang/jq",
        binary: "jq",
        description: "JSON processor",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "yq",
        repo: "mikefarah/yq",
        binary: "yq",
        description: "YAML processor",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "gh",
        repo: "cli/cli",
        binary: "gh",
        description: "GitHub CLI",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "lazygit",
        repo: "jesseduffield/lazygit",
        binary: "lazygit",
        description: "Terminal UI for git",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "delta",
        repo: "dandavison/delta",
        binary: "delta",
        description: "Better git diffs",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "neovim",
        repo: "neovim/neovim",
        binary: "nvim",
        description: "Hyperextensible Vim-based editor",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "helix",
        repo: "helix-editor/helix",
        binary: "hx",
        description: "Post-modern modal editor",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "zellij",
        repo: "zellij-org/zellij",
        binary: "zellij",
        description: "Terminal multiplexer",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "helm",
        repo: "helm/helm",
        binary: "helm",
        description: "Kubernetes package manager",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "k9s",
        repo: "derailed/k9s",
        binary: "k9s",
        description: "Kubernetes terminal UI",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "terraform",
        repo: "hashicorp/terraform",
        binary: "terraform",
        description: "Infrastructure as code",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "opentofu",
        repo: "opentofu/opentofu",
        binary: "tofu",
        description: "Open-source Terraform fork",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "vault",
        repo: "hashicorp/vault",
        binary: "vault",
        description: "Secrets management",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "consul",
        repo: "hashicorp/consul",
        binary: "consul",
        description: "Service mesh and discovery",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "minikube",
        repo: "kubernetes/minikube",
        binary: "minikube",
        description: "Local Kubernetes clusters",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "kind",
        repo: "kubernetes-sigs/kind",
        binary: "kind",
        description: "Kubernetes in Docker",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "kustomize",
        repo: "kubernetes-sigs/kustomize",
        binary: "kustomize",
        description: "Kubernetes manifest templating",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "tilt",
        repo: "tilt-dev/tilt",
        binary: "tilt",
        description: "Local Kubernetes development",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "skaffold",
        repo: "GoogleContainerTools/skaffold",
        binary: "skaffold",
        description: "Kubernetes continuous development",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "lazydocker",
        repo: "jesseduffield/lazydocker",
        binary: "lazydocker",
        description: "Terminal UI for Docker",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "glow",
        repo: "charmbracelet/glow",
        binary: "glow",
        description: "Markdown renderer for the terminal",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "pandoc",
        repo: "jgm/pandoc",
        binary: "pandoc",
        description: "Universal document converter",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "shellcheck",
        repo: "koalaman/shellcheck",
        binary: "shellcheck",
        description: "Shell script linter",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "shfmt",
        repo: "mvdan/sh",
        binary: "shfmt",
        description: "Shell script formatter",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "hadolint",
        repo: "hadolint/hadolint",
        binary: "hadolint",
        description: "Dockerfile linter",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "actionlint",
        repo: "rhysd/actionlint",
        binary: "actionlint",
        description: "GitHub Actions linter",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "hyperfine",
        repo: "sharkdp/hyperfine",
        binary: "hyperfine",
        description: "Command benchmarking",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "tokei",
        repo: "XAMPPRocky/tokei",
        binary: "tokei",
        description: "Code statistics",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "dust",
        repo: "bootandy/dust",
        binary: "dust",
        description: "Disk usage analyzer",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "duf",
        repo: "muesli/duf",
        binary: "duf",
        description: "Disk usage/free utility",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "procs",
        repo: "dalance/procs",
        binary: "procs",
        description: "Modern ps replacement",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "ruff",
        repo: "astral-sh/ruff",
        binary: "ruff",
        description: "Fast Python linter and formatter",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "uv",
        repo: "astral-sh/uv",
        binary: "uv",
        description: "Fast Python package manager",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "fnm",
        repo: "Schniz/fnm",
        binary: "fnm",
        description: "Fast Node.js version manager",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "protoc",
        repo: "protocolbuffers/protobuf",
        binary: "protoc",
        description: "Protocol Buffers compiler",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "terragrunt",
        repo: "gruntwork-io/terragrunt",
        binary: "terragrunt",
        description: "Terraform wrapper",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "packer",
        repo: "hashicorp/packer",
        binary: "packer",
        description: "Machine image builder",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "dive",
        repo: "wagoodman/dive",
        binary: "dive",
        description: "Docker image layer explorer",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "golangci-lint",
        repo: "golangci/golangci-lint",
        binary: "golangci-lint",
        description: "Go linters aggregator",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "delve",
        repo: "go-delve/delve",
        binary: "dlv",
        description: "Go debugger",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "stylua",
        repo: "JohnnyMorganz/StyLua",
        binary: "stylua",
        description: "Lua code formatter",
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "kotlin",
        repo: "JetBrains/kotlin",
        binary: "kotlinc",
        description: "Kotlin compiler",
        // Same releases also ship per-platform native images; only the
        // JVM compiler archive carries the `kotlinc` launcher.
        asset_must_contain: Some("kotlin-compiler"),
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "scala",
        repo: "scala/scala3",
        binary: "scala",
        description: "Scala 3 compiler and runner",
        asset_must_contain: None,
        // Guard against documentation archives published beside the payload.
        asset_must_not_contain: Some("docs"),
    },
    RegistryTool {
        name: "elixir",
        repo: "elixir-lang/elixir",
        binary: "elixir",
        description: "Functional language on the Erlang VM (requires Erlang/OTP)",
        // Per-OTP prebuilt zips (`elixir-otp-25.zip`, …) all qualify; the
        // selector's smallest-name tie-break picks the lowest OTP variant,
        // which runs on the widest range of installed OTP releases.
        asset_must_contain: None,
        asset_must_not_contain: None,
    },
    RegistryTool {
        name: "ghcup",
        repo: "haskell/ghcup-hs",
        binary: "ghcup",
        description: "Haskell toolchain installer (GHC, cabal, HLS via GHCup)",
        // Releases also ship a `SHA256SUMS` manifest and `-src` tarball.
        asset_must_contain: Some("ghcup"),
        asset_must_not_contain: None,
    },
];

/// Look up a registry tool by canonical name.
#[must_use]
pub(crate) fn find_tool(name: &str) -> Option<&'static RegistryTool> {
    REGISTRY_TOOLS.iter().find(|tool| tool.name == name)
}

/// Whether `name` is a registry tool (vs. a bespoke language manager).
#[must_use]
pub(crate) fn is_registry_tool(name: &str) -> bool {
    find_tool(name).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_covers_fifty_four_tools() {
        assert_eq!(
            REGISTRY_TOOLS.len(),
            54,
            "registry must hold exactly 54 tools"
        );
    }

    #[test]
    fn registry_names_are_unique_and_valid() {
        let mut names: Vec<&str> = REGISTRY_TOOLS.iter().map(|tool| tool.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), REGISTRY_TOOLS.len(), "duplicate tool names");
        for tool in REGISTRY_TOOLS {
            crate::core::security::validate_package_name(tool.name)
                .expect("registry name must be a safe path component");
            assert!(
                std::path::Path::new(tool.binary)
                    .components()
                    .eq([std::path::Component::Normal(std::ffi::OsStr::new(
                        tool.binary
                    ))])
                    && !tool.binary.contains(['/', '\\'])
                    && !tool.binary.chars().any(char::is_control),
                "{} needs a single safe binary path component: {:?}",
                tool.name,
                tool.binary
            );
            let mut repo_components = tool.repo.split('/');
            let owner = repo_components.next().unwrap_or_default();
            let repo = repo_components.next().unwrap_or_default();
            let safe_component = |component: &str| {
                let mut components = std::path::Path::new(component).components();
                !component.is_empty()
                    && !matches!(component, "." | "..")
                    && matches!(components.next(), Some(std::path::Component::Normal(_)))
                    && components.next().is_none()
                    && !component.contains(['\\', '?', '#', '%'])
                    && !component.chars().any(char::is_control)
            };
            assert!(
                repo_components.next().is_none() && safe_component(owner) && safe_component(repo),
                "{} needs a safe owner/repo path: {:?}",
                tool.name,
                tool.repo
            );
        }
    }

    #[test]
    fn registry_does_not_shadow_bespoke_managers() {
        for tool in REGISTRY_TOOLS {
            assert!(
                !super::super::NATIVE_RUNTIMES.contains(&tool.name),
                "{} collides with a bespoke manager",
                tool.name
            );
        }
    }
}
