---
title: Task Runner
sidebar_position: 13
description: Unified task execution across ecosystems
---

# Task Runner

**In plain words:** a project usually defines its own commands, such as `build` or `test`.
`omg run` finds the right one for the project you are in and runs it, so you do not have to
remember which tool this particular project uses.

> New to the terminal? Read [Getting started](./getting-started.md) and
> [the glossary](./glossary.md) first. `omg run` executes code that lives in the project
> folder, so only run tasks in projects you trust.

**Unified Task Execution Across All Ecosystems**

OMG's task runner (`omg run`) detects supported project files and resolves a named task. It executes project-controlled code, not a sandboxed command. Review untrusted repositories before running tasks or accepting setup prompts. Missing tools or malformed configuration can cause explicit failures; detection does not guarantee dependency installation or a successful build.

---

## Overview

Instead of remembering:

- `npm run dev` or `yarn dev` or `pnpm dev` or `bun dev`
- `cargo test` or `make test` or `poetry run test`
- Which package manager to use for each project

Just use:

```bash
omg run dev
omg run test
omg run build
```

OMG automatically:

1. **Detects** the project type from config files
2. **Activates** the correct runtime version (from `.nvmrc`, etc.)
3. **Selects** the appropriate package manager
4. **Executes** the task with proper arguments

---

## Supported Project Types

| Config File | Detected Runtime | Task Execution |
| ------------- | ------------------ | ---------------- |
| `package.json` | Node.js/Bun | npm/yarn/pnpm/bun |
| `deno.json` | Deno | `deno task` |
| `Cargo.toml` | Rust | `cargo` |
| `Makefile` | Make | `make` |
| `Taskfile.yml` | Task | `task` |
| `pyproject.toml` | Python (Poetry) | `poetry run` |
| `Pipfile` | Python (Pipenv) | `pipenv run` |
| `composer.json` | PHP (Composer) | `composer run-script` |
| `pom.xml` | Java (Maven) | `mvn` |
| `build.gradle` | Java (Gradle) | `gradle` |

---

## Basic Usage

### Running Tasks

Tasks allow you to interact with your project's lifecycle without needing to remember ecosystem-specific commands.

- **Action Execution**: Run named tasks defined in your project configuration (e.g., `dev`, `test`, `build`).
- **Dynamic Discovery**: View all tasks supported by your current project type.
- **Parameter Passing**: Forward custom flags and arguments directly to the underlying tool.

### How Tasks Are Resolved

The system uses a sophisticated 11-tier discovery engine to determine the correct execution path, now enhanced with an intelligent priority hierarchy and ambiguity resolution:

1. **Project Identification**: The detector inspects supported configuration files in the current directory, including Cargo, Node/Bun, Python, Maven/Gradle, Composer, and Deno files. It is not a recursive breadth-first repository search.
2. **Ecosystem Priority**: If a task name exists in multiple ecosystems (e.g., both `Cargo.toml` and `package.json`), OMG uses a weighted priority system:
    - **Rust (Cargo)**: 100
    - **JavaScript/TypeScript (Node/Bun)**: 90
    - **Python (Poetry/Pipenv)**: 80
    - **Go (Task)**: 75
    - **Ruby (Rake)**: 70
    - **Java (Maven/Gradle)**: 60
    - **PHP (Composer)**: 50
    - **mise tasks** (`mise.toml` / `.mise.toml` `[tasks]`): 45
    - **Make**: 40
3. **Ambiguity Resolution**: If priorities are equal or user preferences are not defined, OMG will:
    - **Interactive Prompt**: Ask you which ecosystem you intended to use.
    - **Explicit Override**: Respect the `--using <ecosystem>` flag (e.g., `omg run test --using node`).
    - **Multi-Execution**: Run across all detected ecosystems if the `--all` flag is provided.
4. **Project Configuration**: You can permanently resolve ambiguity by creating a `.omg.toml` file in your project root:

    ```toml
    [scripts]
    test = "rust"
    build = "node"
    ```

5. **Runtime Activation**: Before execution, the system detects and activates the required runtime version from files like `.nvmrc` or `rust-toolchain.toml`.
6. **Manager Selection**: For multi-manager ecosystems (like JavaScript), the system follows a strict priority logic:
    - Explicit `packageManager` field in the configuration.
    - Lockfile detection (prioritizing modern alternatives like `bun.lockb` or `pnpm-lock.yaml`).
    - System default (falling back to standard managers if no preference is found).
7. **Task Matching**: Discovered scripts or targets are matched against the user request and executed within the optimized environment.

### Resolution Flow

```mermaid
flowchart TD
    Start([omg run task]) --> Detect[Scan for Project Files]
    Detect --> Match{Task Matches?}
    Match -- No --> Fallback[Smart Guessing]
    Match -- Yes --> Config{Config in .omg.toml?}

    Config -- Yes --> Exec[Execute with Configured Ecosystem]
    Config -- No --> Multi{Multiple Matches?}

    Multi -- No --> Exec
    Multi -- Yes --> Priority{Priority Difference?}

    Priority -- Yes --> High[Pick Highest Priority] --> Exec
    Priority -- No --> All{--all flag?}

    All -- Yes --> ExecAll[Run in All Ecosystems]
    All -- No --> Using{--using flag?}

    Using -- Yes --> ExecUsing[Run Specific Ecosystem]
    Using -- No --> Prompt[Interactive Selection] --> Exec
```

---

## Advanced Options

| Flag | Description | Example |
| ------ | ------------- | --------- |
| `--using` | Force a specific ecosystem | `omg run test --using rs` |
| `--all` | Run task in all detected ecosystems | `omg run build --all` |
| `--watch`, `-w` | Re-run on file changes | `omg run test --watch` |
| `--parallel`, `-p` | Run multiple tasks in parallel | `omg run build,test -p` |

---

## JavaScript/TypeScript Projects

### Package Manager Detection

OMG selects the package manager in this order:

1. **`packageManager` field** in `package.json` (highest priority)
2. **Lockfile detection**:
   - `bun.lockb` → Bun
   - `pnpm-lock.yaml` → pnpm
   - `yarn.lock` → Yarn
   - `package-lock.json` → npm
3. **Default**: Bun (if installed) → npm (fallback)

### Examples

```bash
# Project with package.json
omg run dev        # → npm run dev (or bun/yarn/pnpm)
omg run build      # → npm run build
omg run test       # → npm run test

# With arguments
omg run test -- --coverage
```

### packageManager Field

OMG respects the `packageManager` field in `package.json`:

```json
{
  "name": "my-app",
  "packageManager": "bun@1.1.0"
}
```

This ensures all team members use the same package manager version.

Supported values:

- `bun@1.1.0`
- `pnpm@9.0.0`
- `yarn@4.0.0`
- `npm@10.0.0`

### Corepack Integration

If `packageManager` specifies pnpm or yarn, OMG can enable them via corepack:

```bash
# OMG will prompt:
# "pnpm is not installed. Enable via corepack? [Y/n]"
omg run dev
```

### Runtime Version Detection

OMG checks for Node/Bun version files:

| File | Example Content |
| ------ | ----------------- |
| `.nvmrc` | `20.10.0` |
| `.node-version` | `20` |
| `.bun-version` | `1.0.25` |
| `package.json` engines | `{ "node": ">=18" }` |
| `package.json` volta | `{ "node": "20.10.0" }` |

---

## Rust Projects

### Detection

Rust projects are detected by `Cargo.toml`.

### Task Mapping

| omg run | cargo equivalent |
| --------- | ------------------ |
| `omg run build` | `cargo build` |
| `omg run test` | `cargo test` |
| `omg run run` | `cargo run` |
| `omg run check` | `cargo check` |
| `omg run bench` | `cargo bench` |
| `omg run doc` | `cargo doc` |
| `omg run fmt` | `cargo fmt` |
| `omg run clippy` | `cargo clippy` |

### Examples

```bash
# Build release
omg run build -- --release

# Run with arguments
omg run run -- --help

# Test specific module
omg run test -- tests::my_test
```

### Toolchain Detection

OMG reads `rust-toolchain.toml`:

```toml
[toolchain]
channel = "1.75.0"
components = ["rustfmt", "clippy"]
```

The correct toolchain is activated before running tasks.

---

## Python Projects

### Poetry Projects (pyproject.toml)

For projects with Poetry:

```bash
omg run serve     # → poetry run serve
omg run test      # → poetry run pytest
omg run lint      # → poetry run lint
```

### Pipenv Projects (Pipfile)

For projects with Pipenv:

```bash
omg run dev       # → pipenv run dev
omg run test      # → pipenv run test
```

### Virtual Environment Activation

OMG automatically activates the correct Python version from `.python-version`:

```bash
# When .python-version contains "3.12.0"
omg run test
# Runs with Python 3.12.0 activated
```

---

## Makefile Projects

### Detection

Projects with `Makefile` in the root.

### Task Mapping

Make targets become `omg run` tasks:

```makefile
# Makefile
build:
 go build -o bin/app

test:
 go test ./...

clean:
 rm -rf bin/
```

```bash
omg run build   # → make build
omg run test    # → make test
omg run clean   # → make clean
```

### Listing Targets

`omg run` has no `--list` flag. To see available targets, inspect the project
file directly (`make help`, or read the Makefile), then run them via
`omg run <task>`.

---

## Taskfile Projects

### Detection

Projects with `Taskfile.yml` or `Taskfile.yaml`.

### Example Taskfile

```yaml
# Taskfile.yml
version: '3'

tasks:
  build:
    cmds:
      - go build -o bin/app
    desc: Build the application

  test:
    cmds:
      - go test ./...
    desc: Run tests
```

### Usage

```bash
omg run build   # → task build
omg run test    # → task test
```

---

## Java Projects

### Maven (pom.xml)

```bash
omg run test     # → mvn test
omg run package  # → mvn package
omg run install  # → mvn install
omg run clean    # → mvn clean
```

### Gradle (build.gradle)

```bash
omg run test     # → gradle test
omg run build    # → gradle build
omg run run      # → gradle run
```

---

## Deno Projects

### Detection

Projects with `deno.json` or `deno.jsonc`.

### Example

```json
{
  "tasks": {
    "dev": "deno run --watch main.ts",
    "test": "deno test"
  }
}
```

```bash
omg run dev    # → deno task dev
omg run test   # → deno task test
```

---

## PHP Projects

### Composer (composer.json)

```json
{
  "scripts": {
    "test": "phpunit",
    "lint": "phpcs"
  }
}
```

```bash
omg run test   # → composer run-script test
omg run lint   # → composer run-script lint
```

---

## Runtime Resolution

`omg run` resolves project pins through OMG's native runtime managers. There is no backend override or implicit fallback manager.

---

## Auto-Install Prompts

When required tools are missing, OMG prompts to install:

### Rust Toolchains

```bash
$ omg run build
# rust-toolchain.toml specifies 1.75.0
# → "Rust 1.75.0 not installed. Install now? [Y/n]"
```

### Node.js Versions

```bash
$ omg run dev
# .nvmrc specifies 20.10.0
# → "Node 20.10.0 not installed. Install now? [Y/n]"
```

### Package Managers

```bash
$ omg run dev
# packageManager: "pnpm@9.0.0"
# → "pnpm not installed. Enable via corepack? [Y/n]"
```

---

## Task Discovery

There is no `omg run --list` flag today — discovery happens by inspecting your
project files:

**For package.json:** read the `scripts` block (`dev`, `build`, `test`, `lint`, …).

**For Cargo.toml:** standard cargo targets apply (`build`, `test`, `run`, `check`).

**For Makefile:** run `make help` or read the targets directly (`all`, `test`,
`clean`, …).

Any script/target you find can be executed with `omg run <task>`.

---

## Best Practices

### 1. Use Version Files

Always include version files for reproducibility:

```bash
# Node.js project
echo "20.10.0" > .nvmrc

# Python project
echo "3.12.0" > .python-version

# Rust project
cat > rust-toolchain.toml << 'EOF'
[toolchain]
channel = "stable"
EOF
```

### 2. Use packageManager Field

For JavaScript projects, specify the package manager:

```json
{
  "packageManager": "bun@1.1.0"
}
```

### 3. Document Available Tasks

Use descriptive script names and comments:

```json
{
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "test": "vitest",
    "test:watch": "vitest --watch",
    "lint": "eslint src/"
  }
}
```

### 4. Capture Environment

Lock the complete environment:

```bash
omg env capture
git add omg.lock
git commit -m "chore: update environment lockfile"
```

---

## Troubleshooting

### Wrong Runtime Version

```bash
# Check which version is active
omg which node

# Force specific version
omg use node 20.10.0

# Run task with explicit version
omg run dev
```

### Task Not Found

```bash
# List available tasks by reading the project file
jq '.scripts' package.json   # npm-style projects
make -qp 2>/dev/null | awk -F':' '/^[a-zA-Z0-9][^$#\/\t=]*:/ {print $1}'   # Makefile

# Check project file is detected
ls -la package.json Cargo.toml Makefile

# Try direct execution
npm run dev
```

### Wrong Package Manager

There is no dry-run listing — run the task and OMG prints which manager it uses:

```bash
omg run dev        # Output shows "via npm" / "via bun" / "via pnpm" etc.

# Set explicitly in package.json
{
  "packageManager": "pnpm@9.0.0"
}
```

---

## See Also

- [Runtime Management](./runtimes.md) — Version file formats and runtime setup
- [Shell Integration](./shell-integration.md) — PATH management
- [Configuration](./configuration.md) — runtime and task settings
- [Workflows](./workflows.md) — Complete project setup workflows
