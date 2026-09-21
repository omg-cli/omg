---
title: Containers
sidebar_position: 44
description: Docker and Podman command wrappers
---

# Containers

**In plain words:** A container is a small, disposable copy of a system that you can throw away. This page shows how OMG starts one for testing a project.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

OMG wraps selected Docker and Podman operations. The engine, images, project code, and host mounts remain trust boundaries. Container execution is not a guarantee of safe execution of untrusted code.

## Inspect the engine

```bash
omg container status
omg container list
omg container images
omg container --help
```

Install and configure an engine separately. Do not expose its socket to a project merely to make a command work; engine access can grant substantial host privileges.

## Development shell and execution

```bash
omg container shell
omg container run alpine -- echo hello
```

These commands create/run containers and can pull images. The development shell mounts the project; review what host data will be writable. A tag can change upstream. Use an approved immutable image digest when repeatability matters.

Environment arguments must be `KEY=VALUE`. Volume arguments currently accept `HOST:CONTAINER` only. A suffix such as `:ro` is rejected, not implemented. If a read-only mount is required, use the native engine's verified read-only mount controls rather than dropping the suffix and creating a writable mount. Never mount credentials or private directories as a troubleshooting shortcut.

## Build

```bash
omg container build -t myapp .
omg container build -f Dockerfile.prod -t myapp .
```

Builds execute the selected recipe. Supported options include `--no-cache`, `--build-arg`, and `--target`; inspect `omg container build --help` for their values. Do not put secrets in build arguments or image layers.

## Generate a recipe

```bash
omg container init
```

This writes `Dockerfile.omg`, based on detected project files and runtime selectors. Generation is not verification that the recipe builds, pins all dependencies, or uses a backend-compatible release. Inspect the file before building, including any installer download and execution. Use a reviewed pinned installer and verified archive per [installation](./installation.md), not an unreviewed moving `curl | bash` command.

Build the generated file explicitly:

```bash
omg container build -f Dockerfile.omg -t myapp .
```

## Existing containers

`pull` downloads an image, `stop` changes a running container's state, and `exec` executes code in an existing container. Confirm the exact name or ID before using these commands. Do not stop unrelated containers or prune shared images as part of verification.

See [integrations](./integrations.md), [task runner](./task-runner.md), and [CLI reference](./cli.md).
