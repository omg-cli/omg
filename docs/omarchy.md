---
title: OMG on Omarchy
sidebar_position: 47
description: What OMG adds to an Omarchy setup, and what Omarchy keeps doing itself
---

# OMG on Omarchy

**In plain words:** Omarchy is an Arch Linux setup with its own update workflow.
This page explains where OMG can fit and which update steps should stay with Omarchy.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

OMG can manage developer tools and AUR packages on Arch. Its managed tool installers
apply the checks described below. Those checks do not apply to every direct use of npm,
pip, Cargo, Go, or pacman. Omarchy should continue to own operating-system updates,
migrations, and recovery.

This is a proposal for evaluation, not an announcement of Omarchy adoption or endorsement.

## Before you try an integration

Use a build that includes the Arch backend. Keep Omarchy's updater as the owner of
system upgrades. To inspect AUR updates without installing them, run:

```bash
omg update --aur-only --check
```

You should see AUR update candidates or an up-to-date message. This command skips the
official update lane. An Omarchy integration should place `omg update --aur-only` only
where its updater already delegates AUR work; it should retain Omarchy's surrounding
preflight checks, migrations, snapshots, and recovery steps.

## What Omarchy already provides

Omarchy already makes Arch approachable through package menus and a coordinated update workflow. Its updater handles system packages and installed AUR packages, together with snapshots and migrations. Direct system upgrades can skip that coordination, so Omarchy explicitly guards them. OMG should preserve this behavior. [Omarchy updates](https://omarchy.org/manual/updates/)

Its development menu already offers many language environments, most managed through mise. OMG already reads supported mise tool pins, task definitions, and project environment settings natively. That gives existing mise projects a practical starting point: reuse supported configuration while adopting OMG's package and tool workflows. [Development tools](https://omarchy.org/manual/development-tools/)

Omarchy also supplies an existing security baseline, including disk encryption and a firewall. Its base package selection primarily uses official repositories and its own repository; optional AUR installations introduce a different trust decision. [Security](https://omarchy.org/manual/security/)

The AUR menu makes community software accessible, but community availability is not publisher vetting. Omarchy's manual explicitly explains this distinction. This is where clearer decisions and enforced installation boundaries can help a newcomer. [Other packages](https://omarchy.org/manual/other-packages/)

## Where OMG adds value

The important distinction is between a tool supporting a security option and an installation workflow applying that option for the user. OMG uses existing package tools where appropriate, while adding policy around the operations it manages.

**Evidence status:** the managed-tool and AUR controls below are in the current tree and are described as release behavior in [v0.1.223](releases/v0.1.223.md). The September 13, 2026 research notes cited [PR #399](https://github.com/omg-cli/omg/pull/399) while that work was still open. Check [releases](https://github.com/omg-cli/omg/releases) for the build you have installed.

| User task | What OMG adds on its managed path | Why it matters |
| --- | --- | --- |
| Install an npm-distributed CLI | Installs into staging with lifecycle scripts disabled, then runs npm signature verification before activation; scripts require an explicit package-scoped exception. | Installation does not silently grant every dependency an install-script execution opportunity. |
| Install a Python CLI | Uses a dedicated virtual environment and requests wheels only by default. Source distributions require an explicit exception. | Separates tool dependencies and avoids source-build execution on the default path. |
| Install a Cargo CLI | Requests the published lockfile with `--locked` unless explicitly overridden. | Makes dependency selection more constrained; it does not sandbox Rust build scripts. |
| Install a Go CLI | Sets checksum/proxy policy, disables CGO and automatic toolchain downloads by default, and exposes explicit exceptions. | Reduces implicit inputs and surprise compiler/toolchain behavior. |
| Update a managed tool | Stages the replacement, checks managed entrypoints, and supports rollback when activation fails. | A failed replacement should not require the user to reconstruct a previously working installation. |
| Build an AUR package | Reviews and rechecks sources, then uses an offline Bubblewrap build with a private home and cleared environment by default. | Limits build-time access instead of relying entirely on the user recognizing dangerous shell code. |
| Install an AUR build result | Inspects archive paths, metadata, links, hooks, and privileged contents before handing sealed bytes to the elevated transaction. Selected system-integrating packages require matching private rebuilds. | Adds checks between community build output and a privileged installation. |

The managed-tool defaults and exception handling are visible in [`src/cli/tool.rs`](https://github.com/omg-cli/omg/blob/cc67ab89541f07af7b433bf29d142a78954cd882/src/cli/tool.rs). The [AUR workflow](aur.md) documents its gates, required confirmations, and compatibility opt-ins.

### A concrete npm distinction

For an npm-distributed command-line tool, OMG's managed installer first materializes the dependency tree with `--ignore-scripts`. It then runs `npm audit signatures` and refuses activation if that check fails, unless the user explicitly allows an unverified installation for that package. An approved script phase runs after verification. [Verification ordering commit](https://github.com/omg-cli/omg/commit/d356fee5)

That is a specific advantage over an install performed without those controls. It builds on npm's capabilities and makes their application part of OMG's workflow. Signature verification authenticates evidence about packages; it does not establish that signed code is harmless.

### Compare the actual defaults

The baseline matters. These comparisons use upstream documentation checked on September 13, 2026, and the OMG implementation linked above. They describe specific behaviors, not a measured percentage reduction in compromise risk.

| Underlying tool | Documented baseline | OMG's managed workflow |
| --- | --- | --- |
| npm 11.19.1 | Unreviewed dependency scripts can run with a notice unless strict script policy or script suppression is configured. | Suppresses lifecycle scripts during the initial install and checks signatures before activation or an explicitly allowed script phase. |
| npm 12 | Unapproved dependency scripts are already blocked with a warning. Script blocking alone is therefore not an exclusive OMG advantage. | Combines script suppression with a required signature-check step before activation, controlled manager configuration, staging, and policy receipts. |
| pip | Can install source distributions; `--only-binary=:all:` is an available option that rejects them. | Applies that option by default for managed Python tools, in a dedicated virtual environment, unless explicitly overridden. |
| Cargo | `cargo install` normally ignores a packaged lockfile and resolves dependencies again. | Supplies `--locked` by default. This constrains dependency drift, but a lockfile can also retain older dependencies; it is not a vulnerability verdict. |

Sources: [npm 11 script policy](https://docs.npmjs.com/cli/v11/using-npm/config/#strict-allow-scripts), [npm 12 script policy](https://docs.npmjs.com/cli/v12/using-npm/config/#strict-allow-scripts), [npm signature verification](https://docs.npmjs.com/verifying-registry-signatures/), [pip binary-only option](https://pip.pypa.io/en/stable/cli/pip_install/#cmdoption-only-binary), and [Cargo lockfile behavior](https://doc.rust-lang.org/cargo/commands/cargo-install.html#dealing-with-the-lockfile).

The practical benefit is reduced reliance on remembering and configuring these controls separately. A knowledgeable user can reproduce many of them with native tools. OMG makes their application repeatable on its managed paths and adds installation handoff and activation controls. Commit links establish inspectable implementation; neither commit volume nor these comparisons establish that OMG is safer than every possible native-tool configuration.

This applies to `omg tool install`'s managed npm path. Selecting Node through `omg use node` puts its vendor tools on PATH; subsequent direct `npm install` commands are not intercepted or automatically hardened by OMG. Project tasks also execute project code. See [runtime management](runtimes.md).

### Protection without pretending exceptions disappear

Some tools need lifecycle scripts, Python source builds, CGO, private registries, or other settings outside the defaults. OMG makes those exceptions explicit and records installation policy receipts. A stricter default can produce a refusal where an unrestricted command would proceed; useful error messages and documented exceptions are part of the product's value. [Policy receipts](https://github.com/omg-cli/omg/commit/1fc5d2a8), [visible overrides](https://github.com/omg-cli/omg/commit/f4a89bd4)

On Linux, managed installer subprocesses use `no_new_privs` to prevent execution from gaining new privileges. This does not itself isolate the filesystem or network. AUR's Bubblewrap policy is a separate control. [Privilege restriction](https://github.com/omg-cli/omg/commit/b76bf0c7)

## How it should fit into Omarchy

The proposed first integration is optional managed developer-tool installation and delegation of Omarchy's existing AUR-update step to `omg update --aur-only`. System upgrade ownership stays with Omarchy.

| Area | Proposed responsibility |
| --- | --- |
| OS upgrades, mirror/channel selection, migrations, snapshots | Omarchy's existing update workflow. Do not substitute unrestricted `omg update` or bypass Omarchy's upgrade guard. |
| Existing mise projects | Reuse supported `[tools]`, `[tasks]`, and `[env]` declarations directly in OMG. Keep mise for unsupported features and choose one active shell runtime selector. |
| Managed developer CLIs | Evaluate OMG's defaults, exceptions, activation behavior, and removal experience on a defined set of tools. |
| AUR updates | Omarchy may optionally call `omg update --aur-only` where its updater currently invokes the AUR helper. This mode cannot refresh official databases, query the official update lane, or perform a system upgrade; every selected AUR update retains OMG's normal review, build, archive-inspection, and privileged-install gates. |
| AUR installation | Evaluate the complete transaction, including dependency installation and compatibility with Omarchy's selected repository channel. |
| Recovery | Preserve native package tools and Omarchy recovery. OMG tool activation rollback is not a whole-system snapshot. |

These are integration requirements, not a claim that Omarchy-specific compatibility has already been tested. In particular, an Arch backend alone does not establish that every package transaction respects Omarchy's additional update coordination. Omarchy's stable mirror also intentionally trails current Arch packages; AUR dependency availability must be assessed against the selected channel. [Update channels and guards](https://omarchy.org/manual/updates/)

The delegation point is deliberately narrow. Omarchy's update transaction remains responsible for its preflight checks, migrations, official package upgrade, snapshots, restart handling, and recovery. Its documented update sequence already separates the AUR helper from those stages, so an integration should replace only that helper call and preserve its position in the transaction. [Omarchy update process](https://github.com/omacom/omarchy/blob/quattro/docs/update-process.md)

`--aur-only` narrows package selection; it is not a reduced-security mode. AUR recipes still use the same policy and build path as a normal OMG update. Arch's `makepkg` verifies the integrity arrays declared by a PKGBUILD, but a recipe can declare `SKIP`, so checksum presence alone is not publisher authentication. OMG continues to surface and enforce its recipe policy around that boundary. [PKGBUILD integrity fields](https://man.archlinux.org/man/PKGBUILD.5.en#cksums_(array))

### Existing mise compatibility

OMG implements the following configuration support natively; these workflows do not shell out to mise:

| Existing configuration | What OMG already supports |
| --- | --- |
| `[tools]` across project mise layers | Plain version strings and tables with a string `version` for supported native runtimes/tools. Native aliases normalize before layer overrides. Dedicated ecosystem version files take precedence within the same directory. |
| `[tasks.<name>]` and shorthand tasks | String/array commands, plain-name dependencies, dependency-only tasks, task environments, and literal working directories. Shared dependencies run once; invalid graphs fail before execution and failed dependencies stop their parents. |
| Project and task `[env]` | Assignments, unsets, defaults, required values, supported templates, PATH additions, and environment files during explicit run/task execution. Supported environment files include dotenv, JSON, and TOML. |
| Project configuration layers | Local overrides, selected `MISE_ENV` environments, selected-environment local overrides, grouped project configurations, and sorted fragments, with child projects overriding ancestors. Environment resolution, tool pins, and task discovery use shared bounded discovery. |
| Explicit environment sourcing | Supported `_.source` scripts are evaluated during explicit run/task execution. Automatic shell hooks select installed runtimes without importing project environment directives. |

This means users can already reuse supported parts of their mise project configuration with OMG, rather than maintaining a separate set of version pins and simple tasks. The implementation is visible in [tool-pin parsing](https://github.com/omg-cli/omg/blob/cc67ab89541f07af7b433bf29d142a78954cd882/src/hooks/mod.rs), [task execution](https://github.com/omg-cli/omg/blob/cc67ab89541f07af7b433bf29d142a78954cd882/src/core/task_runner.rs), and [environment resolution](https://github.com/omg-cli/omg/blob/cc67ab89541f07af7b433bf29d142a78954cd882/src/config/mise_env.rs).

The compatibility boundary is specific: backend-qualified tool entries such as `github:owner/repo` are skipped by the mise pin parser. Task execution is sequential; dependency arguments/patterns, post-dependencies, file tasks, custom shells, conditions, and run/directory templates are unsupported and produce errors instead of silently losing execution controls. Environment support excludes encrypted-secret backends, per-plugin directives, YAML environment files, and full Tera templates. Applying previously ignored local and selected-environment layers changes pins, tasks, and explicit command environments, including inherited home-directory configuration for projects beneath that directory. Follow [Check a project before migrating](mise-compatibility.md#check-a-project-before-migrating) before upgrading. This is configuration compatibility, not a claim of complete mise parity or automatic reuse of mise's installed tool directories. [Runtime management](runtimes.md)

## What would justify making it a default?

A default needs evidence about ordinary users' experience as well as security mechanisms. An Omarchy evaluation should demonstrate:

1. Successful installation, update, and removal of a representative set of developer tools and AUR packages on a named Omarchy version and channel.
2. Preservation of Omarchy's update guards, migrations, snapshots, and native recovery workflow.
3. Clear failures for rejected packages and understandable, narrowly scoped exceptions for legitimate incompatibilities.
4. Predictable PATH behavior alongside the existing mise setup, with a straightforward way to undo the integration.
5. Release artifacts containing the evaluated hardening, with reproducible commands and linked test results.

This document does not report those integration tests as completed. OMG's [CI evidence](https://github.com/omg-cli/omg/actions) and [security timeline](https://getomg.xyz/security/) provide separate implementation and verification history. Generic Arch or QEMU success should not be presented as an Omarchy compatibility result unless the run actually tested that environment.

## Follow the implementation

| State | Meaning |
| --- | --- |
| In review | Implemented changes in an open PR, not yet on main. |
| On main | Merged changes; release inclusion still needs checking. |
| Released | Included in an identified tagged build users can install. |

For the current work, start with [PR #399](https://github.com/omg-cli/omg/pull/399), the [public security timeline](https://getomg.xyz/security/), and the [security model](security.md). Individual changes include [manager configuration isolation](https://github.com/omg-cli/omg/commit/7b0749d2), [managed entrypoint hashing](https://github.com/omg-cli/omg/commit/8bb84cbc), and [activation rollback](https://github.com/omg-cli/omg/commit/8e44e924).

**The proposal:** give Omarchy users an approachable installation workflow that applies additional controls at the point they need them, with public evidence explaining what those controls do. Evaluate that fit on real Omarchy systems, then use the results to decide whether broader adoption is warranted.
