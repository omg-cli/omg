---
title: Containers
sidebar_position: 44
description: Docker and Podman command wrappers
---

# Containers

**In plain words:** a container is a small, disposable copy of a system that you can throw
away. This page shows how OMG starts one for testing a project, and where the trust
boundaries are.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

OMG wraps selected Docker and Podman operations. The engine, the images you pull, the project
code, and any host mount remain trust boundaries: running something in a container is not a
guarantee that untrusted code is safe.

## What each subcommand does

| Command | What it does | Notable options |
| :--- | :--- | :--- |
| `omg container status` | Reports which engine OMG found and whether it answers | — |
| `omg container list` | Lists running containers | — |
| `omg container images` | Lists local images | — |
| `omg container run <image>` | Runs a command in a new container | `--name`, `--detach`, `--interactive`, `--env KEY=VALUE`, `--volume HOST:CONTAINER`, `--workdir` |
| `omg container shell` | Opens an interactive shell with the project mounted | `--image`, `--workdir`, `--env`, `--volume` |
| `omg container build` | Builds an image from a recipe | `--dockerfile/-f`, `--tag/-t`, `--no-cache`, `--build-arg KEY=VALUE`, `--target` |
| `omg container init` | Writes a project recipe (see below) | `--base` |
| `omg container pull <image>` | Downloads an image | — |
| `omg container stop <container>` | Stops a running container | — |
| `omg container exec <container> -- <cmd>` | Runs a command in an existing container | — |

```bash
omg container status          # is there an engine to talk to?
omg container --help          # the exact surface for your build
```

Install and configure the engine separately. Do not expose its socket to a project just to
make a command work: engine access can grant substantial host privileges.

## Shells, runs, and mounts

```bash
omg container shell                          # interactive shell, project mounted
omg container run alpine -- echo hello       # one command in a throwaway container
```

These commands create containers and can pull images. The development shell mounts the
project, so review which host paths become writable first. A tag can change upstream; use an
approved immutable image digest when repeatability matters.

```bash
# Environment arguments must be KEY=VALUE.
omg container run alpine --env FOO=bar -- printenv FOO

# Volume arguments are HOST:CONTAINER only.
omg container run alpine --volume "$PWD/data:/data" -- ls /data
```

**Limit:** a `:ro` suffix is rejected rather than implemented. If you need a read-only mount,
use the native engine's verified read-only controls instead of dropping the suffix and
creating a writable mount by accident. Never mount credentials or private directories as a
troubleshooting shortcut.


## Generate a recipe

```bash
omg container init                        # writes Dockerfile.omg for this project
omg container build -f Dockerfile.omg -t myapp
```

Generation checks for `package.json`, `Cargo.toml`, `go.mod`, `pyproject.toml`, and
`requirements.txt` in the current directory. It writes `Dockerfile.omg` and adds protective
ignore rules to `.dockerignore` and existing Dockerfile-specific or Podman ignore files.
It refuses to overwrite an existing `Dockerfile.omg`.

The generator pins every remote installer it emits to a digest. If it cannot establish those
digests it refuses to write the file at all, with a message that says so, rather than emitting
a recipe that runs unverified downloads as root.

**Limit:** generation is not verification. Treat the file as a starting point: inspect it
before building, including any download-and-execute step, and prefer a reviewed, pinned
installer and a verified archive as described in [installation](./installation.md) over a
moving `curl | bash` line.

## Existing containers

`pull` downloads an image, `stop` changes a running container's state, and `exec` runs code
inside a container that already exists. Confirm the exact name or ID first, and do not stop
unrelated containers or prune shared images as part of checking something else.

## Limits

- **An engine is a prerequisite.** OMG talks to Docker or Podman; it does not install or
  manage one for you, and `omg container status` is the quickest way to see which answered.
- **Not a sandbox verdict.** Container isolation depends on the engine, its configuration, and
  the mounts you grant. A container run does not make community code trustworthy, and it does
  not replace the review and policy controls that apply to AUR packages.
- **Images are trust inputs.** A tag can move, and an image runs its own code. Pin digests when
  a result must be repeatable, and review a new image as you would any other dependency.
- **Host access is explicit.** Every `--volume` and `--workdir` you pass widens what the
  container can read or change on your machine.

## If something goes wrong

| What you see | What to do |
| --- | --- |
| `No container runtime detected` | Install and start Docker or Podman, then run `omg container status`. |
| `Dockerfile.omg already exists` | Review the existing file. Use `omg container build -f Dockerfile.omg` to build it. |
| A digest cannot be pinned | Retry when the publisher is reachable. Inspect the generated recipe before building. |
| A volume option is rejected | OMG accepts `HOST:CONTAINER` only. Use the native engine if you need a read-only mount. |

## Where to go next

- [Task runner](./task-runner.md) to run project tasks without a container at all.
- [Integrations](./integrations.md) for how OMG fits with the rest of your toolchain.
- [CLI reference](./cli.md) for the complete container command surface.
