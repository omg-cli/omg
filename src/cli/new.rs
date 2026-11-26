use anyhow::{Context, Result};
use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::process::Command;

use crate::cli::{args::ProjectStack, style};
use ScaffoldEntry::{Directory, File};

fn require_command_success(status: std::process::ExitStatus, operation: &str) -> Result<()> {
    anyhow::ensure!(status.success(), "{operation} failed with {status}");
    Ok(())
}

fn canonical_stack(stack: &str) -> Option<ProjectStack> {
    <ProjectStack as clap::ValueEnum>::from_str(stack, true).ok()
}

fn validate_manifest_name(stack: ProjectStack, name: &str, path: &str) -> Result<()> {
    let first = name.as_bytes().first().copied().unwrap_or_default();
    let last = name.as_bytes().last().copied().unwrap_or_default();
    let valid = match stack {
        ProjectStack::Rust => {
            (first.is_ascii_alphabetic() || first == b'_')
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
        }
        ProjectStack::React | ProjectStack::Node => {
            name.len() <= 214
                && (first.is_ascii_lowercase() || first.is_ascii_digit())
                && name.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_.".contains(&byte)
                })
        }
        ProjectStack::Python => {
            first.is_ascii_alphanumeric()
                && last.is_ascii_alphanumeric()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        }
        ProjectStack::Go => path.split('/').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        }),
    };
    anyhow::ensure!(
        valid,
        "Invalid {} project manifest name: {name}",
        stack.as_str()
    );
    Ok(())
}

/// Create a new project
pub fn run(stack: &str, name: &str) -> Result<()> {
    // SECURITY: Validate project name (reuse package name rules as they are safe for directories)
    crate::core::security::validate_package_name(name)?;
    // Scaffold writes outside the current directory are never intended:
    // reject absolute paths and parent escapes, while still allowing
    // nested relative paths like `examples/demo`.
    {
        use std::path::Component;
        let path = std::path::Path::new(name);
        if path.is_absolute()
            || path
                .components()
                .any(|component| component == Component::ParentDir)
        {
            anyhow::bail!("Invalid project name '{name}': absolute paths and '..' are not allowed");
        }
    }

    let relative = Path::new(name);
    let canonical_stack = canonical_stack(stack).ok_or_else(|| {
        anyhow::anyhow!("Unknown stack: {stack}. Supported: rust, react, node, python, go")
    })?;
    let project_name = relative
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(name);
    validate_manifest_name(canonical_stack, project_name, name)?;

    println!(
        "{} Creating new {} project: {}\n",
        style::header("OMG Scaffolder"),
        style::info(stack),
        style::package(name)
    );

    publish_scaffold(relative, |target_dir| {
        populate_scaffold(target_dir, canonical_stack, project_name, name)
    })?;

    println!("\n{}", style::success("Project created successfully! 🚀"));
    println!("\nTo get started:");
    println!("  cd {name}");
    if matches!(canonical_stack, ProjectStack::React | ProjectStack::Node) {
        println!(
            "  Review and install the dependencies listed in package.json before running the project."
        );
    }

    Ok(())
}

fn populate_scaffold(
    target: &Path,
    stack: ProjectStack,
    project_name: &str,
    relative_name: &str,
) -> Result<()> {
    match stack {
        ProjectStack::Rust => scaffold_rust(target, project_name)?,
        ProjectStack::React => scaffold_react(target, project_name)?,
        ProjectStack::Node => scaffold_node(target, project_name)?,
        ProjectStack::Python => scaffold_python(target, project_name)?,
        ProjectStack::Go => scaffold_go(target, relative_name)?,
    }

    println!("\n{}", style::header("Finalizing..."));
    lock_runtimes(target, stack.as_str())?;
    println!("  {} Initializing git...", style::dim("→"));
    let status = Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(target)
        .status()
        .context("Failed to launch git init")?;
    require_command_success(status, "git init")
}

#[cfg(target_os = "linux")]
use publication::publish_scaffold;

#[cfg(not(target_os = "linux"))]
fn publish_scaffold(relative: &Path, populate: impl FnOnce(&Path) -> Result<()>) -> Result<()> {
    let target = std::env::current_dir()?.join(relative);
    if target.symlink_metadata().is_ok() {
        anyhow::bail!("Directory '{}' already exists", relative.display());
    }
    let parent = target
        .parent()
        .context("Project directory needs a parent")?;
    fs::create_dir_all(parent).context("Failed to create project parent directories")?;
    fs::create_dir(&target)?;
    populate(&target)
}

#[cfg(target_os = "linux")]
mod publication {
    use anyhow::{Context as _, Result};
    use rustix::fd::{AsRawFd as _, OwnedFd};
    use rustix::fs::{CWD, Mode, OFlags, RenameFlags, openat, renameat_with};
    use rustix::io::Errno;
    use std::ffi::OsStr;
    use std::fs;
    use std::path::{Path, PathBuf};

    const DIRECTORY_FLAGS: OFlags = OFlags::PATH
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);

    struct Parent {
        path: PathBuf,
        fd: OwnedFd,
    }

    impl Parent {
        fn child(&self, name: &OsStr) -> Result<Option<Self>> {
            let path = self.path.join(name);
            match openat(&self.fd, name, DIRECTORY_FLAGS, Mode::empty()) {
                Ok(fd) => Ok(Some(Self { path, fd })),
                Err(Errno::NOENT) => Ok(None),
                Err(error) => Err(error).with_context(|| {
                    format!("Project parent {} must be a real directory", path.display())
                }),
            }
        }

        fn access_path(&self) -> PathBuf {
            PathBuf::from(format!("/proc/self/fd/{}", self.fd.as_raw_fd()))
        }
    }

    pub(super) fn publish_scaffold(
        relative: &Path,
        populate: impl FnOnce(&Path) -> Result<()>,
    ) -> Result<()> {
        let mut parent = Parent {
            path: std::env::current_dir()?,
            fd: openat(CWD, ".", DIRECTORY_FLAGS, Mode::empty())
                .context("Failed to open current project directory")?,
        };
        let components: Vec<_> = relative.iter().collect();
        let mut missing = components.as_slice();
        while let [first, rest @ ..] = missing {
            if rest.is_empty() {
                break;
            }
            let Some(child) = parent
                .child(first)
                .context("Failed to create project parent directories")?
            else {
                break;
            };
            parent = child;
            missing = rest;
        }

        let [first, rest @ ..] = missing else {
            anyhow::bail!("Project directory needs a name");
        };
        let access = parent.access_path();
        if rest.is_empty() {
            match fs::symlink_metadata(access.join(first)) {
                Ok(_) => anyhow::bail!("Directory '{}' already exists", relative.display()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("Failed to inspect project directory"),
            }
        }

        let staging = tempfile::Builder::new()
            .prefix(".omg-new-")
            .tempdir_in(access)
            .context("Failed to stage project beside its destination")?;
        let target = missing
            .iter()
            .fold(staging.path().to_path_buf(), |path, part| path.join(part));
        fs::create_dir_all(&target).context("Failed to create staged project directory")?;
        populate(&target)?;
        publish(&parent, staging.path(), missing, relative)
    }

    fn publish(parent: &Parent, staging: &Path, missing: &[&OsStr], relative: &Path) -> Result<()> {
        let [first, rest @ ..] = missing else {
            anyhow::bail!("Project directory needs a name");
        };
        let from = staging.join(first);
        match renameat_with(CWD, &from, &parent.fd, *first, RenameFlags::NOREPLACE) {
            Ok(()) => Ok(()),
            Err(Errno::EXIST) if !rest.is_empty() => {
                // A concurrent scaffold published a shared parent. The rest
                // of our tree can still be published without replacing it.
                let child = parent
                    .child(first)?
                    .context("Concurrent project parent disappeared; retry the scaffold")?;
                publish(&child, &from, rest, relative)
            }
            Err(Errno::EXIST) => anyhow::bail!("Directory '{}' already exists", relative.display()),
            Err(error) => Err(error)
                .with_context(|| format!("Failed to publish project at {}", relative.display())),
        }
    }
}

enum ScaffoldEntry<'a> {
    Directory(&'static str),
    File(&'static str, &'a [u8]),
}

fn write_scaffold(root: &Path, stack: &str, entries: &[ScaffoldEntry<'_>]) -> Result<()> {
    entries.iter().try_for_each(|entry| match entry {
        Directory(path) => fs::create_dir(root.join(path))
            .with_context(|| format!("Failed to create the {stack} directory {path}")),
        File(path, contents) => fs::File::create_new(root.join(path))
            .and_then(|mut file| file.write_all(contents))
            .with_context(|| format!("Failed to write the {stack} {path}")),
    })
}

fn scaffold_rust(root: &Path, name: &str) -> Result<()> {
    let manifest =
        format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n");
    write_scaffold(
        root,
        "Rust",
        &[
            File("Cargo.toml", manifest.as_bytes()),
            Directory("src"),
            File(
                "src/main.rs",
                b"fn main() {\n    println!(\"Hello from OMG!\");\n}\n",
            ),
            File(".gitignore", b"/target\n"),
        ],
    )
}

fn scaffold_react(root: &Path, name: &str) -> Result<()> {
    let package = serde_json::json!({
        "name": name,
        "version": "0.1.0",
        "private": true,
        "type": "module",
        "scripts": {
            "dev": "vite",
            "build": "tsc --noEmit && vite build",
            "preview": "vite preview"
        },
        "dependencies": {"react": "^19.3.1", "react-dom": "^19.3.1"},
        "devDependencies": {
            "@types/react": "^19.3.0",
            "@types/react-dom": "^19.3.0",
            "typescript": "^5.9.3",
            "vite": "^8.3.8"
        }
    });
    write_scaffold(
        root,
        "React",
        &[
            File("package.json", format!("{package:#}").as_bytes()),
            File(
                "tsconfig.json",
                br#"{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "jsx": "react-jsx",
    "strict": true,
    "skipLibCheck": true,
    "noEmit": true
  },
  "include": ["src"]
}
"#,
            ),
            File(
                "index.html",
                br#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>React starter</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
"#,
            ),
            Directory("src"),
            File(
                "src/main.tsx",
                br#"import { createRoot } from "react-dom/client";

const root = document.getElementById("root");
if (root) {
  createRoot(root).render(<h1>Hello from OMG!</h1>);
}
"#,
            ),
            File(".gitignore", b"node_modules\ndist\n.env\n"),
        ],
    )
}

fn scaffold_node(root: &Path, name: &str) -> Result<()> {
    let package = serde_json::json!({
        "name": name,
        "version": "0.1.0",
        "private": true,
        "type": "module",
        "scripts": {
            "start": "tsx src/index.ts",
            "build": "tsc",
            "dev": "tsx watch src/index.ts"
        },
        "devDependencies": {
            "typescript": "^5.9.3",
            "tsx": "^4.23.15",
            "@types/node": "^22.0.0"
        }
    });
    write_scaffold(
        root,
        "Node",
        &[
            File("package.json", format!("{package:#}").as_bytes()),
            File(
                "tsconfig.json",
                br#"{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "strict": true,
    "skipLibCheck": true,
    "outDir": "./dist"
  },
  "include": ["src"]
}
"#,
            ),
            Directory("src"),
            File("src/index.ts", b"console.log(\"Hello from OMG!\");\n"),
            File(".gitignore", b"node_modules\ndist\n.env\n"),
        ],
    )
}

fn scaffold_python(root: &Path, name: &str) -> Result<()> {
    let manifest =
        format!("[project]\nname = \"{name}\"\nversion = \"0.1.0\"\ndependencies = []\n");
    write_scaffold(
        root,
        "Python",
        &[
            File("pyproject.toml", manifest.as_bytes()),
            File("requirements.txt", b""),
            File("main.py", b"print('Hello from OMG!')\n"),
            File(".gitignore", b".venv/\n__pycache__/\n.env\n"),
        ],
    )
}

fn scaffold_go(root: &Path, name: &str) -> Result<()> {
    let manifest = format!("module {name}\n\ngo 1.21.0\n");
    write_scaffold(
        root,
        "Go",
        &[
            File("go.mod", manifest.as_bytes()),
            File(
                "main.go",
                br#"package main

import "fmt"

func main() {
	fmt.Println("Hello from OMG!")
}
"#,
            ),
            File(
                "Taskfile.yml",
                br"version: '3'

tasks:
  build:
    cmds:
      - go build -v .
  run:
    cmds:
      - go run main.go
",
            ),
        ],
    )
}

fn lock_runtimes(target_dir: &Path, stack: &str) -> Result<()> {
    let runtime = if stack == "react" { "node" } else { stack };
    let versions = crate::core::paths::data_dir()
        .join("versions")
        .join(runtime);
    if let Some(version) = crate::runtimes::common::get_current_version(&versions) {
        crate::core::security::validate_runtime_version(&version)?;
        let lock = format!("{runtime} {version}\n");
        write_scaffold(
            target_dir,
            "runtime",
            &[File(".tool-versions", lock.as_bytes())],
        )?;
        println!("  {} Locked {runtime} to {version}", style::success("✓"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_aliases_share_their_runtime_lock_family() {
        assert_eq!(canonical_stack("react-ts"), Some(ProjectStack::React));
        assert_eq!(canonical_stack("typescript"), Some(ProjectStack::Node));
        assert_eq!(canonical_stack("py"), Some(ProjectStack::Python));
        assert_eq!(canonical_stack("golang"), Some(ProjectStack::Go));
        assert_eq!(canonical_stack("rs"), Some(ProjectStack::Rust));
        assert_eq!(canonical_stack("RUST"), Some(ProjectStack::Rust));
        assert_eq!(canonical_stack("unknown"), None);
    }

    #[test]
    fn scaffold_diagnostics_name_the_file_that_cannot_be_written() -> Result<()> {
        type Scaffold = fn(&Path, &str) -> Result<()>;
        let cases: [(&str, [&str; 2], Scaffold); 5] = [
            ("Rust", ["Cargo.toml", ".gitignore"], scaffold_rust),
            ("React", ["package.json", ".gitignore"], scaffold_react),
            ("Node", ["package.json", ".gitignore"], scaffold_node),
            ("Python", ["pyproject.toml", ".gitignore"], scaffold_python),
            ("Go", ["go.mod", "Taskfile.yml"], scaffold_go),
        ];
        for (stack, [first, last], scaffold) in cases {
            for (file, contents) in [(first, Some("previous project file\n")), (last, None)] {
                let owner = tempfile::tempdir()?;
                let existing = owner.path().join(file);
                if let Some(contents) = contents {
                    fs::write(&existing, contents)?;
                } else {
                    fs::create_dir(&existing)?;
                }
                let error = scaffold(owner.path(), "scaffold-fixture")
                    .expect_err("scaffolding must leave existing entries intact");
                assert_eq!(
                    error.to_string(),
                    format!("Failed to write the {stack} {file}")
                );
                if let Some(contents) = contents {
                    assert_eq!(fs::read_to_string(&existing)?, contents);
                    assert!(!owner.path().join(last).exists());
                } else {
                    assert!(existing.is_dir());
                    assert!(owner.path().join(first).is_file());
                }
            }
        }
        Ok(())
    }

    #[test]
    fn scaffold_source_directory_collision_preserves_existing_contents() -> Result<()> {
        let owner = tempfile::tempdir()?;
        let source = owner.path().join("src");
        fs::create_dir(&source)?;
        let previous = source.join("main.rs");
        fs::write(&previous, "original source\n")?;
        let error = scaffold_rust(owner.path(), "scaffold-fixture")
            .expect_err("scaffolding must leave an existing source directory alone");
        assert_eq!(error.to_string(), "Failed to create the Rust directory src");
        assert_eq!(fs::read_to_string(previous)?, "original source\n");
        assert!(owner.path().join("Cargo.toml").is_file());
        assert!(!owner.path().join(".gitignore").exists());
        Ok(())
    }

    #[test]
    fn failed_scaffold_commands_are_errors() {
        let status = Command::new("sh")
            .args(["-c", "exit 23"])
            .status()
            .expect("run fixture command");

        let error = require_command_success(status, "fixture scaffold")
            .expect_err("non-zero scaffold command must fail");
        assert!(error.to_string().contains("fixture scaffold"));
        assert!(error.to_string().contains("23"));
    }
}
