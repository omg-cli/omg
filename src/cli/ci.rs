//! `omg ci` - Generate CI/CD configuration

use anyhow::Result;
use owo_colors::OwoColorize;
use std::fs;
use std::io::Write as _;

use crate::cli::style;

/// Initialize CI configuration
pub fn init(provider: &str, advanced: bool) -> Result<()> {
    // SECURITY: Validate provider
    let valid_providers = ["github", "gitlab", "circleci"];
    if !valid_providers.contains(&provider.to_lowercase().as_str()) {
        anyhow::bail!("Unknown CI provider '{provider}'. Supported: github, gitlab, circleci");
    }

    let mode_str = if advanced {
        style::maybe_color("advanced", |t| t.magenta().to_string())
    } else {
        style::maybe_color("basic", |t| t.blue().to_string())
    };

    println!(
        "{} Generating {} CI configuration ({} mode)...\n",
        style::runtime("OMG"),
        style::path(provider),
        mode_str
    );

    match provider.to_lowercase().as_str() {
        "github" => generate_github_actions(advanced)?,
        "gitlab" => generate_gitlab_ci(advanced)?,
        "circleci" => generate_circleci(advanced)?,
        _ => anyhow::bail!("Unknown CI provider '{provider}'. Supported: github, gitlab, circleci"),
    }

    Ok(())
}

/// Validate environment matches CI expectations
pub async fn validate() -> Result<()> {
    println!("{} Validating CI environment...\n", style::runtime("OMG"));

    let lock_path = std::path::Path::new("omg.lock");
    require_ci_lockfile(lock_path)?;
    let state = crate::core::env::fingerprint::EnvironmentState::capture().await?;
    let lock = crate::core::env::fingerprint::EnvironmentState::load(lock_path)?;

    if state.hash == lock.hash {
        println!(
            "  {} Environment matches omg.lock",
            style::maybe_color("✓", |t| t.green().to_string())
        );
        Ok(())
    } else {
        println!(
            "  {} Environment drift detected!",
            style::maybe_color("✗", |t| t.red().to_string())
        );
        println!(
            "  Run {} to see differences",
            style::command("omg diff omg.lock")
        );
        anyhow::bail!("Environment drift detected")
    }
}

fn require_ci_lockfile(path: &std::path::Path) -> Result<()> {
    anyhow::ensure!(
        path.is_file(),
        "No omg.lock found; run 'omg env capture' before CI validation"
    );
    Ok(())
}

/// Generate cache manifest for CI
pub fn cache() -> Result<()> {
    println!("{} CI Cache Paths\n", style::runtime("OMG"));

    println!(
        "  {}",
        style::maybe_color("Recommended cache paths:", |t| t.bold().to_string())
    );
    println!();
    println!("  # OMG data directory");
    println!("  ~/.local/share/omg/");
    println!();
    println!("  # Runtime versions");
    println!("  ~/.local/share/omg/versions/");
    println!();

    #[cfg(feature = "arch")]
    {
        println!("  # Pacman cache (Arch)");
        println!("  /var/cache/pacman/pkg/");
        println!();
    }

    println!("  # Cargo cache");
    println!("  ~/.cargo/registry/");
    println!("  ~/.cargo/git/");
    println!();
    println!("  # NPM cache");
    println!("  ~/.npm/");
    println!();

    println!(
        "  {}",
        style::maybe_color("Cache key suggestion:", |t| t.bold().to_string())
    );
    println!(
        "  {}",
        style::maybe_color("omg-${{ runner.os }}-${{ hashFiles('omg.lock') }}", |t| t
            .cyan()
            .to_string())
    );

    Ok(())
}

/// Write a generated config file, previewing instead of overwriting.
fn write_config_file(path: &str, config: &str) -> Result<()> {
    let config = render_ci_config(config);
    let config = config.as_str();
    ensure_safe_config_parent(std::path::Path::new(path))?;

    let created = create_new_config_file(std::path::Path::new(path), config)?;

    if created {
        println!(
            "  {} Created {}",
            style::maybe_color("✓", |t| t.green().to_string()),
            style::maybe_color(path, |t| t.cyan().to_string())
        );
    } else {
        println!(
            "  {} {} already exists - not overwriting",
            style::maybe_color("⚠", |t| t.yellow().to_string()),
            path
        );
        println!("  Here's what we'd generate:\n");
        println!("{}", style::dim(config));
    }
    Ok(())
}

fn render_ci_config(config: &str) -> String {
    config.replace("__OMG_VERSION__", env!("CARGO_PKG_VERSION"))
}

fn create_new_config_file(path: &std::path::Path, config: &str) -> Result<bool> {
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut file) => {
            file.write_all(config.as_bytes())?;
            file.sync_all()?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn ensure_safe_config_parent(path: &std::path::Path) -> Result<()> {
    use std::path::Component;

    anyhow::ensure!(!path.is_absolute(), "CI config path must be relative");
    let mut directory = std::path::PathBuf::new();
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    for component in parent.components() {
        match component {
            Component::CurDir => continue,
            Component::Normal(name) => directory.push(name),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                anyhow::bail!("CI config path must stay inside the current repository")
            }
        }
        match fs::symlink_metadata(&directory) {
            Ok(metadata) => anyhow::ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "Refusing symlinked or non-directory CI config ancestor: {}",
                directory.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&directory)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

// CI build/test jobs run project-defined OMG tasks. The advanced security job
// inventories Cargo dependencies, never packages installed on the CI runner.
fn github_actions_config(advanced: bool) -> &'static str {
    if advanced {
        r#"name: CI

on: [push, pull_request]

permissions:
  contents: read

jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Require GitHub CLI for OMG provenance verification
        run: |
          command -v gh >/dev/null || {
            echo "::error::Install GitHub CLI (gh) to verify OMG release provenance"
            exit 1
          }
      - name: Install verified OMG release
        run: |
          curl -fsSLo omg-install.sh https://raw.githubusercontent.com/omg-cli/omg/v__OMG_VERSION__/install.sh
          OMG_VERSION=v__OMG_VERSION__ OMG_NO_TELEMETRY=1 OMG_SKIP_SHELL=1 bash omg-install.sh
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"
      - name: Check committed OMG environment
        run: |
          if test -f omg.lock; then omg env check; else echo "No omg.lock; skipping environment check"; fi
      - name: Build project
        run: omg run build
      - name: Test project
        run: omg run test

  security:
    name: Rust dependency audit and SBOM
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Require Rust project
        run: test -f Cargo.toml || { echo "::error::Advanced security requires Cargo.toml"; exit 1; }
      - name: Audit Rust dependencies
        run: |
          cargo install cargo-audit --locked
          cargo audit
      # This describes Cargo dependencies, not packages installed on the runner.
      - name: Generate Rust dependency SBOM
        run: |
          cargo install cargo-cyclonedx --version 0.5.9 --locked
          cargo metadata --locked --format-version 1 > /dev/null
          sbom_name="rust-dependencies-$(cat /proc/sys/kernel/random/uuid).cdx"
          cargo cyclonedx --format json --all --override-filename "$sbom_name"
          mkdir -p security-sboms
          find . -type f -name "$sbom_name.json" -not -path './target/*' -not -path './security-sboms/*' -exec cp --parents {} security-sboms/ \;
          test -n "$(find security-sboms -type f -name "$sbom_name.json" -print -quit)"
          git diff --exit-code -- Cargo.lock
      - name: Upload Rust dependency SBOM
        uses: actions/upload-artifact@v4
        with:
          name: rust-dependencies-sbom
          path: security-sboms/
          if-no-files-found: error
"#
    } else {
        r#"name: CI

on: [push, pull_request]

permissions:
  contents: read

jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Require GitHub CLI for OMG provenance verification
        run: |
          command -v gh >/dev/null || {
            echo "::error::Install GitHub CLI (gh) to verify OMG release provenance"
            exit 1
          }
      - name: Install verified OMG release
        run: |
          curl -fsSLo omg-install.sh https://raw.githubusercontent.com/omg-cli/omg/v__OMG_VERSION__/install.sh
          OMG_VERSION=v__OMG_VERSION__ OMG_NO_TELEMETRY=1 OMG_SKIP_SHELL=1 bash omg-install.sh
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"
      - name: Check committed OMG environment
        run: |
          if test -f omg.lock; then omg env check; else echo "No omg.lock; skipping environment check"; fi
      - name: Build project
        run: omg run build
      - name: Test project
        run: omg run test
"#
    }
}

fn generate_github_actions(advanced: bool) -> Result<()> {
    write_config_file(".github/workflows/ci.yml", github_actions_config(advanced))?;
    println!();
    println!(
        "  {}",
        style::maybe_color("Next steps:", |t| t.bold().to_string())
    );
    println!("    1. Review and commit the workflow file");
    println!("    2. Ensure your project defines build and test tasks");
    println!("    3. Push to trigger the workflow");
    Ok(())
}

fn gitlab_ci_config(advanced: bool) -> &'static str {
    if advanced {
        r#"# Provision a runner or image from a verified OMG release before using this template.
# This preflight checks executable health, not release provenance.
# Advanced security also requires Cargo.toml and a committed Cargo.lock.
stages:
  - build
  - test
  - security

default:
  before_script:
    - |
      if ! command -v omg >/dev/null 2>&1; then
        echo "OMG is missing. Configure a runner/image with a verified OMG release; install with gh attestation verification." >&2
        exit 1
      fi
      omg --version >/dev/null || { echo "OMG is present but cannot execute" >&2; exit 1; }
    - |
      if test -f omg.lock; then omg env check; else echo "No omg.lock; skipping environment check"; fi

build:
  stage: build
  script:
    - omg run build

test:
  stage: test
  script:
    - omg run test

security:
  stage: security
  image: rust:latest
  before_script: []
  script:
    - test -f Cargo.toml || { echo "Advanced security requires Cargo.toml" >&2; exit 1; }
    - cargo install cargo-audit --locked
    - cargo audit
    # This describes Cargo dependencies, not packages installed on the runner.
    - cargo install cargo-cyclonedx --version 0.5.9 --locked
    - cargo metadata --locked --format-version 1 > /dev/null
    - |
      sbom_name="rust-dependencies-$(cat /proc/sys/kernel/random/uuid).cdx"
      cargo cyclonedx --format json --all --override-filename "$sbom_name"
      mkdir -p security-sboms
      find . -type f -name "$sbom_name.json" -not -path './target/*' -not -path './security-sboms/*' -exec cp --parents {} security-sboms/ \;
      test -n "$(find security-sboms -type f -name "$sbom_name.json" -print -quit)"
    - git diff --exit-code -- Cargo.lock
  artifacts:
    paths:
      - security-sboms/
"#
    } else {
        r#"# Provision a runner or image from a verified OMG release before using this template.
# This preflight checks executable health, not release provenance.
stages:
  - build
  - test

default:
  before_script:
    - |
      if ! command -v omg >/dev/null 2>&1; then
        echo "OMG is missing. Configure a runner/image with a verified OMG release; install with gh attestation verification." >&2
        exit 1
      fi
      omg --version >/dev/null || { echo "OMG is present but cannot execute" >&2; exit 1; }
    - |
      if test -f omg.lock; then omg env check; else echo "No omg.lock; skipping environment check"; fi

build:
  stage: build
  script:
    - omg run build

test:
  stage: test
  script:
    - omg run test
"#
    }
}

fn generate_gitlab_ci(advanced: bool) -> Result<()> {
    write_config_file(".gitlab-ci.yml", gitlab_ci_config(advanced))
}

fn circleci_config(advanced: bool) -> &'static str {
    if advanced {
        r#"version: 2.1

jobs:
  build-and-test:
    docker:
      # Replace this with an image built from a verified OMG release.
      - image: cimg/base:stable
    steps:
      - checkout
      - run:
          name: Require working OMG on this runner
          command: |
            if ! command -v omg >/dev/null 2>&1; then
              echo "OMG is missing. Use an image with a verified OMG release; install with gh attestation verification." >&2
              exit 1
            fi
            omg --version >/dev/null || { echo "OMG is present but cannot execute" >&2; exit 1; }
      - run:
          name: Check committed OMG environment
          command: |
            if test -f omg.lock; then omg env check; else echo "No omg.lock; skipping environment check"; fi
      - run:
          name: Build and test project
          command: |
            omg run build
            omg run test

  security:
    docker:
      - image: cimg/rust:1.97.1
    steps:
      - checkout
      - run:
          name: Require Rust project
          command: test -f Cargo.toml || { echo "Advanced security requires Cargo.toml" >&2; exit 1; }
      - run:
          name: Audit Rust dependencies
          command: |
            cargo install cargo-audit --locked
            cargo audit
      - run:
          name: Generate Rust dependency SBOM
          command: |
            # This describes Cargo dependencies, not packages installed on the runner.
            cargo install cargo-cyclonedx --version 0.5.9 --locked
            cargo metadata --locked --format-version 1 > /dev/null
            sbom_name="rust-dependencies-$(cat /proc/sys/kernel/random/uuid).cdx"
            cargo cyclonedx --format json --all --override-filename "$sbom_name"
            mkdir -p security-sboms
            find . -type f -name "$sbom_name.json" -not -path './target/*' -not -path './security-sboms/*' -exec cp --parents {} security-sboms/ \;
            test -n "$(find security-sboms -type f -name "$sbom_name.json" -print -quit)"
            git diff --exit-code -- Cargo.lock
      - store_artifacts:
          path: security-sboms/

workflows:
  build-and-test:
    jobs:
      - build-and-test
      - security
"#
    } else {
        r#"version: 2.1

jobs:
  build-and-test:
    docker:
      # Replace this with an image built from a verified OMG release.
      - image: cimg/base:stable
    steps:
      - checkout
      - run:
          name: Require working OMG on this runner
          command: |
            if ! command -v omg >/dev/null 2>&1; then
              echo "OMG is missing. Use an image with a verified OMG release; install with gh attestation verification." >&2
              exit 1
            fi
            omg --version >/dev/null || { echo "OMG is present but cannot execute" >&2; exit 1; }
      - run:
          name: Check committed OMG environment
          command: |
            if test -f omg.lock; then omg env check; else echo "No omg.lock; skipping environment check"; fi
      - run:
          name: Build and test project
          command: |
            omg run build
            omg run test

workflows:
  build-and-test:
    jobs:
      - build-and-test
"#
    }
}

fn generate_circleci(advanced: bool) -> Result<()> {
    write_config_file(".circleci/config.yml", circleci_config(advanced))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ci_templates_keep_project_tasks_and_truthful_security_scope() {
        for (provider, advanced, config) in [
            ("github", false, github_actions_config(false)),
            ("github", true, github_actions_config(true)),
            ("gitlab", false, gitlab_ci_config(false)),
            ("gitlab", true, gitlab_ci_config(true)),
            ("circleci", false, circleci_config(false)),
            ("circleci", true, circleci_config(true)),
        ] {
            for forbidden in [
                "PyRo1121",
                "CI-MOCK-KEY",
                "license.json",
                "omg audit sbom",
                "omg env check ||",
            ] {
                assert!(
                    !config.contains(forbidden),
                    "{provider} advanced={advanced} unexpectedly contains {forbidden}"
                );
            }
            assert!(config.contains("omg run build"));
            assert!(config.contains("omg run test"));
            assert!(config.contains("if test -f omg.lock; then omg env check"));
            if provider == "github" {
                let rendered = render_ci_config(config);
                let pinned_tag = format!("v{}", env!("CARGO_PKG_VERSION"));
                assert!(rendered.contains(&format!(
                    "https://raw.githubusercontent.com/omg-cli/omg/{pinned_tag}/install.sh"
                )));
                assert!(rendered.contains(&format!("OMG_VERSION={pinned_tag}")));
                assert!(!rendered.contains("__OMG_VERSION__"));
                assert!(config.contains("command -v gh"));
                assert!(config.contains("bash omg-install.sh"));
            } else {
                assert!(config.contains("command -v omg"));
                assert!(config.contains("omg --version"));
                assert!(!config.contains("Require verified OMG on this runner"));
                assert!(config.contains("verified OMG release"));
                assert!(!config.contains("install.sh"));
            }
            if advanced {
                assert!(config.contains("cargo audit"));
                assert!(config.contains(
                    "sbom_name=\"rust-dependencies-$(cat /proc/sys/kernel/random/uuid).cdx\""
                ));
                assert!(config.contains(
                    "cargo cyclonedx --format json --all --override-filename \"$sbom_name\""
                ));
                assert!(config.contains("-name \"$sbom_name.json\""));
                assert!(config.contains("cp --parents {} security-sboms/"));
                let artifact_path = if provider == "gitlab" {
                    "- security-sboms/"
                } else {
                    "path: security-sboms/"
                };
                assert!(config.contains(artifact_path));
                assert!(config.contains("not packages installed on the runner"));
                assert!(config.contains("git diff --exit-code -- Cargo.lock"));
                let artifact_step = match provider {
                    "github" => "actions/upload-artifact@v4",
                    "gitlab" => "artifacts:",
                    "circleci" => "store_artifacts:",
                    _ => unreachable!("only known providers are in this fixture"),
                };
                assert!(config.contains(artifact_step));
            } else {
                assert!(!config.contains("cargo cyclonedx"));
                assert!(!config.contains("cargo audit"));
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn ci_generation_refuses_a_dangling_destination_symlink() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir_in(".").expect("relative temp directory");
        let outside = directory.path().join("outside.yml");
        let destination = directory.path().join("ci.yml");
        let outside_absolute = std::fs::canonicalize(directory.path())
            .expect("canonical fixture directory")
            .join("outside.yml");
        symlink(&outside_absolute, &destination).expect("dangling destination symlink");

        let created = create_new_config_file(&destination, "untrusted overwrite")
            .expect("existing destination is a preview, not an error");

        assert!(!created, "an existing symlink must not be replaced");
        assert!(!outside.exists(), "writer must not follow the symlink");
        assert!(
            destination.is_symlink(),
            "existing entry must remain intact"
        );
    }

    #[cfg(unix)]
    #[test]
    fn ci_generation_refuses_a_symlinked_parent_directory() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir_in(".").expect("relative temp directory");
        let outside = directory.path().join("outside");
        std::fs::create_dir(&outside).expect("outside directory");
        let outside_absolute = std::fs::canonicalize(&outside).expect("canonical outside");
        let linked_parent = directory.path().join(".github");
        symlink(outside_absolute, &linked_parent).expect("linked parent");

        // tempfile returns an absolute path even for tempdir_in("."). Use the
        // relative fixture path so this reaches ancestor validation rather than
        // passing accidentally at the absolute-path guard.
        let destination = std::path::Path::new(directory.path().file_name().expect("fixture name"))
            .join(".github/workflows/ci.yml");
        let error =
            ensure_safe_config_parent(&destination).expect_err("symlinked parent must be refused");
        assert!(error.to_string().contains("Refusing symlinked"), "{error}");
        assert!(!outside.join("workflows").exists());
    }

    #[test]
    fn ci_generation_creates_a_relative_config_without_overwriting() {
        let directory = tempfile::tempdir_in(".").expect("fixture directory");
        let destination = std::path::Path::new(directory.path().file_name().expect("fixture name"))
            .join(".github/workflows/ci.yml");
        let path = destination.to_str().expect("UTF-8 fixture path");
        write_config_file(path, "original config").expect("create config");
        write_config_file(path, "replacement config").expect("preview existing config");
        assert_eq!(
            fs::read_to_string(destination).expect("config"),
            "original config"
        );
    }

    #[test]
    fn ci_validation_fails_closed_without_lockfile() {
        let directory = tempfile::tempdir().expect("temp directory");
        let missing = directory.path().join("omg.lock");

        let error =
            require_ci_lockfile(&missing).expect_err("CI validation without a lockfile must fail");

        assert!(error.to_string().contains("No omg.lock found"), "{error}");
    }
}
