use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::cli::style;

fn require_command_success(status: std::process::ExitStatus, operation: &str) -> Result<()> {
    anyhow::ensure!(status.success(), "{operation} failed with {status}");
    Ok(())
}

fn canonical_stack(stack: &str) -> Option<&'static str> {
    match stack.to_ascii_lowercase().as_str() {
        "rust" | "rs" => Some("rust"),
        "react" | "react-ts" => Some("react"),
        "node" | "ts" | "typescript" => Some("node"),
        "python" | "py" => Some("python"),
        "go" | "golang" => Some("go"),
        _ => None,
    }
}

fn validate_manifest_name(stack: &str, name: &str, path: &str) -> Result<()> {
    let first = name.as_bytes().first().copied().unwrap_or_default();
    let last = name.as_bytes().last().copied().unwrap_or_default();
    let valid = match stack {
        "rust" => {
            (first.is_ascii_alphabetic() || first == b'_')
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
        }
        "react" | "node" => {
            name.len() <= 214
                && (first.is_ascii_lowercase() || first.is_ascii_digit())
                && name.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_.".contains(&byte)
                })
        }
        "python" => {
            first.is_ascii_alphanumeric()
                && last.is_ascii_alphanumeric()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        }
        "go" => path.split('/').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        }),
        _ => false,
    };
    anyhow::ensure!(valid, "Invalid {stack} project manifest name: {name}");
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

    let target_dir = std::env::current_dir()?.join(name);
    if target_dir.exists() {
        anyhow::bail!("Directory '{name}' already exists");
    }

    println!(
        "{} Creating new {} project: {}\n",
        style::header("OMG Scaffolder"),
        style::info(stack),
        style::package(name)
    );

    let canonical_stack = canonical_stack(stack).ok_or_else(|| {
        anyhow::anyhow!("Unknown stack: {stack}. Supported: rust, react, node, python, go")
    })?;
    let project_name = target_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(name);
    validate_manifest_name(canonical_stack, project_name, name)?;
    if let Some(parent) = target_dir.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir(&target_dir)?;
    match canonical_stack {
        "rust" => scaffold_rust(&target_dir, project_name)?,
        "react" => scaffold_react(&target_dir, project_name)?,
        "node" => scaffold_node(&target_dir, project_name)?,
        "python" => scaffold_python(&target_dir, project_name)?,
        "go" => scaffold_go(&target_dir, name)?,
        _ => unreachable!("canonical_stack returned an unknown family"),
    }

    // Post-scaffold setup
    println!("\n{}", style::header("Finalizing..."));

    let tool_versions_path = target_dir.join(".tool-versions");
    if !tool_versions_path.exists() {
        lock_runtimes(&target_dir, canonical_stack)?;
    }

    if !target_dir.join(".git").exists() {
        println!("  {} Initializing git...", style::dim("→"));
        let status = Command::new("git")
            .arg("init")
            .current_dir(&target_dir)
            .status()
            .context("Failed to launch git init")?;
        require_command_success(status, "git init")?;
    }

    println!("\n{}", style::success("Project created successfully! 🚀"));
    println!("\nTo get started:");
    println!("  cd {name}");
    if matches!(canonical_stack, "react" | "node") {
        println!(
            "  Review and install the dependencies listed in package.json before running the project."
        );
    }

    Ok(())
}

fn scaffold_rust(root: &Path, name: &str) -> Result<()> {
    fs::write(
        root.join("Cargo.toml"),
        format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
    )?;
    fs::create_dir(root.join("src"))?;
    fs::write(
        root.join("src/main.rs"),
        "fn main() {\n    println!(\"Hello from OMG!\");\n}\n",
    )?;
    fs::write(root.join(".gitignore"), "/target\n")?;
    Ok(())
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
    fs::write(
        root.join("package.json"),
        serde_json::to_vec_pretty(&package)?,
    )?;
    fs::write(
        root.join("tsconfig.json"),
        r#"{
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
    )?;
    fs::write(
        root.join("index.html"),
        r#"<!doctype html>
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
    )?;
    fs::create_dir(root.join("src"))?;
    fs::write(
        root.join("src/main.tsx"),
        r#"import { createRoot } from "react-dom/client";

const root = document.getElementById("root");
if (root) {
  createRoot(root).render(<h1>Hello from OMG!</h1>);
}
"#,
    )?;
    fs::write(root.join(".gitignore"), "node_modules\ndist\n.env\n")?;
    Ok(())
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
    fs::write(
        root.join("package.json"),
        serde_json::to_vec_pretty(&package)?,
    )?;
    fs::write(
        root.join("tsconfig.json"),
        r#"{
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
    )?;
    fs::create_dir(root.join("src"))?;
    fs::write(
        root.join("src/index.ts"),
        "console.log(\"Hello from OMG!\");\n",
    )?;
    fs::write(root.join(".gitignore"), "node_modules\ndist\n.env\n")?;
    Ok(())
}

fn scaffold_python(root: &Path, name: &str) -> Result<()> {
    fs::write(
        root.join("pyproject.toml"),
        format!(
            "[project]\nname = \"{name}\"\nversion = \"0.1.0\"\nrequires-python = \">=3.10\"\ndependencies = []\n"
        ),
    )?;
    fs::write(root.join("requirements.txt"), "")?;
    fs::write(root.join("main.py"), "print('Hello from OMG!')\n")?;
    fs::write(root.join(".gitignore"), ".venv/\n__pycache__/\n.env\n")?;
    Ok(())
}

fn scaffold_go(root: &Path, name: &str) -> Result<()> {
    fs::write(root.join("go.mod"), format!("module {name}\n\ngo 1.21.0\n"))?;
    fs::write(
        root.join("main.go"),
        r#"package main

import "fmt"

func main() {
	fmt.Println("Hello from OMG!")
}
"#,
    )?;
    fs::write(
        root.join("Taskfile.yml"),
        r"version: '3'

tasks:
  build:
    cmds:
      - go build -v .
  run:
    cmds:
      - go run main.go
",
    )?;
    Ok(())
}

fn lock_runtimes(target_dir: &Path, stack: &str) -> Result<()> {
    let runtime = if stack == "react" { "node" } else { stack };
    let versions = crate::core::paths::data_dir()
        .join("versions")
        .join(runtime);
    if let Some(version) = crate::runtimes::common::get_current_version(&versions) {
        crate::core::security::validate_runtime_version(&version)?;
        fs::write(
            target_dir.join(".tool-versions"),
            format!("{runtime} {version}\n"),
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
        assert_eq!(canonical_stack("react-ts"), Some("react"));
        assert_eq!(canonical_stack("typescript"), Some("node"));
        assert_eq!(canonical_stack("py"), Some("python"));
        assert_eq!(canonical_stack("golang"), Some("go"));
        assert_eq!(canonical_stack("rs"), Some("rust"));
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
