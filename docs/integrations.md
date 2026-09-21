---
title: Integrations
sidebar_position: 45
description: Use OMG from shells, editors, and automation
---

# Integrations

**In plain words:** How to use OMG alongside the tools you already have, including your operating system package manager.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

OMG can be called from existing development tools. Examples here are command-line integration patterns, not claims of official editor extensions or hosted-provider support.

## Shells and editors

Install using [installation](./installation.md), then configure the appropriate Bash, Zsh, or Fish hook using [shell integration](./shell-integration.md). Configure editor tasks to invoke OMG from the intended project directory:

```bash
omg which node
omg run build
```

An editor's environment may differ from a login shell. Confirm the selected runtime and executable path before debugging the build. Do not copy configuration for a different shell or append duplicate hooks.

`omg run` executes project-controlled commands. Opening an untrusted repository does not authorize running its tasks or accepting dependency-install prompts.

## CI and build automation

Use a backend-compatible runner. Pin the reviewed installer and release artifact to the intended release; verify the archive checksum and GitHub attestation according to [installation](./installation.md). Do not pipe a moving download into a shell or treat a checksum downloaded from the same source as independent provenance.

Prepare dependencies explicitly, then run the checks appropriate to the project:

```bash
omg env check
omg run build
```

An environment check detects drift; it does not install dependencies or prove reproducible builds. Preserve ecosystem lockfiles. A global `--json` option does not imply every command emits a stable machine-readable result, and vulnerability findings alone do not make `omg audit scan` fail. Inspect command-specific behavior before using it as a CI gate.

Keep tokens in the CI secret store. Do not expose publishing credentials to untrusted pull requests or write them into shell startup files. Cache only rebuildable artifacts, with backend and version in the cache key; do not publish account credentials, history, or audit data as a build cache.

## Containers

OMG wraps selected Docker/Podman operations; it does not provide an isolation boundary stronger than the configured engine. Review generated files and mounts before building or running them. Images, build recipes, and project scripts execute code. Prefer immutable image digests for repeatable inputs.

See [containers](./containers.md) for supported flags and mount restrictions. A container with writable host mounts or a mounted engine socket must not be treated as safe execution of arbitrary code.

## Native package tools

OMG and native package tools use the same underlying system package state. Avoid concurrent transactions and retain native recovery tools. Backend support differs: an Arch-oriented automation recipe is not automatically valid for APT, DNF, or Homebrew.

## Account and team services

Local package/runtime use does not require linking a dashboard account. Optional account linking consumes a token through standard input:

```bash
omg account link --token-stdin
```

Feed it from an approved credential source, never a literal argv value. Environment sharing uploads inventory; obtain permission and review it first. See [team environments](./team.md).

## Verification

Record OMG version, backend, project revision, working directory, exit status, and the actual command used. Local builds do not verify hosted authentication, billing, or invitation delivery. Troubleshoot those at their owning service rather than inventing a client-side workaround.

See [workflows](./workflows.md), [configuration](./configuration.md), and [troubleshooting](./troubleshooting.md).
