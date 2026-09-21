---
title: Team Environments
sidebar_position: 40
description: Share environment records and inspect drift
---

# Team environments

**In plain words:** This page explains how to share a record of a project environment with other people, what that record contains, and what it exposes.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

OMG can capture and share environment records. It does not ensure identical machines, install all dependencies during synchronization, or replace your source-control and access-management policies.

## Capture and review

From the project directory:

```bash
omg env capture
omg env check
```

Capture writes `omg.lock`. Review its runtime versions, explicit package inventory, and fingerprint before committing or uploading it. It may disclose internal package names or other private environment information. A fingerprint describes recorded inputs; it is not a proof of complete reproducibility.

## Share a record

```bash
omg env share
```

Supply the required `GITHUB_TOKEN` through an approved credential manager or CI secret store. Do not type literal tokens into shell commands, commit them, print them, or add them to `.zshrc`. Use the minimum permissions needed and revoke credentials through your provider when no longer needed.

The default Gist is secret, meaning unlisted, not encrypted or restricted to named team members. `--public` makes it public. Obtain approval before uploading private inventory or changing its visibility.

## Receive and compare

```bash
omg env sync https://gist.github.com/USER/GIST_ID
omg env check
```

Sync downloads the environment record and checks drift; it installs nothing. Review the downloaded record before applying changes. Install required runtimes and packages explicitly with backend-compatible commands, then check again. A major runtime selector such as `22` is not an exact version pin.

A successful drift check does not establish identical transitive dependencies, operating-system state, secrets, compiler flags, or build outputs. Retain ecosystem lockfiles and your normal build verification.

## Team commands are a separate interface

Inspect `omg team --help` for workspace initialization, joining, status, push/pull, membership, activity, and golden-path commands. Their service availability and authorization requirements are separate from Gist sharing. Joining, pushing, or running setup instructions can modify local or remote state. Review the target and operation before proceeding.

CLI environment sharing is not proof of website organization membership, billing entitlement, invitation delivery, or enterprise compliance. Those have separate authorization and verification boundaries.

## CI

Prepare a backend-compatible runner using a reviewed, pinned installer and verified release archive as described in [installation](./installation.md). Do not execute a moving installer URL directly from the network. Provide only the credentials required by that job; pull-request code must not gain access to publishing or organization tokens.

Run `omg env check` against a reviewed record after preparing the environment. Treat `omg run` as execution of repository-controlled code, not a sandbox. See [task runner](./task-runner.md) and [integrations](./integrations.md).

## Troubleshooting

For missing credentials, inspect credential-manager configuration without printing values. For drift, inspect the reported package/runtime differences rather than overwriting the shared lockfile to clear the failure. For failed downloads or malformed records, preserve the error and original file; do not weaken validation.

See [runtimes](./runtimes.md), [security](./security.md), and [CLI reference](./cli.md).
