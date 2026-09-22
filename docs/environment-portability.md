---
title: Portable environment planning
sidebar_position: 41
description: Preview explicit package mappings for another supported platform
---

# Portable environment planning

This page helps you describe the tools a project needs on several operating systems. OMG can print a read-only plan for one target. The plan does not install packages or copy files.

If you are new to terminals or package managers, start with [getting started](./getting-started.md) and the [glossary](./glossary.md).

## Start from an existing capture

On a backend supported by `omg env capture`, capture the current machine and
print a starter manifest:

```bash
omg env capture
omg env export --source-target arch-x86_64
```

Specify the platform where the capture was made, not the intended destination.
The old lock schema cannot verify this declaration. Export validates the existing
lockfile, prints TOML, and does not overwrite `.omg.toml`. Review and merge the
printed `[environment]` section into your configuration. It includes captured
runtime versions and package names, not package versions, dotfile contents, or
machine credentials. The existing capture's runtime/backend coverage limits apply.

For a different OS, add explicit package mappings, then preview that target.
Export never assumes matching package names are equivalent across platforms.

## Preview the destination

`omg env plan --target ubuntu-x86_64` reads the current directory's `.omg.toml`
and prints a JSON preview. It does not install tools, execute scripts, copy
dotfiles, contact registries, or change `omg.lock`.

```toml
[environment]
schema_version = 1
tools = ["git", "compiler"]

[environment.runtimes]
node = "22"

[environment.packages.ubuntu-x86_64]
git = "git"
compiler = "build-essential"

[environment.packages.arch-x86_64]
git = "git"
compiler = "base-devel"

[environment.dotfiles]
"dotfiles/editor.toml" = ".config/editor/config.toml"
```

Targets: `arch-x86_64`, `debian-x86_64`, `ubuntu-x86_64`, `fedora-x86_64`,
and `macos-aarch64`. Target selection is explicit; it does not need to match
the machine generating the preview. Existing `[scripts]` configuration can coexist.

Every requested tool needs an explicit native package mapping for the selected
target. Missing mappings appear in `unmapped_tools`; OMG never guesses an
equivalent package. Exit success means the manifest is valid, not that every
tool is mapped or installable. Runtime requirements remain uninterpreted intent.
Package names in this initial schema accept letters, digits, dots, underscores,
pluses and hyphens, starting with a letter or digit.

Dotfile sources are relative to the manifest directory; destinations are relative
to the user's home. Paths are validated lexically only. No file contents are read,
and existence, symlinks, ownership, conflicts and permissions are not checked by
this preview. Do not include credentials or employer-private data in shared files.

The environment section uses schema version 1. The planner accepts a manifest up
to 256 KiB, at most 512 tools, and at most 128 dotfile mappings. Tool and package
identifiers may be up to 128 characters; relative dotfile paths may be up to 1024
characters. Invalid targets, undeclared tool mappings, unsafe paths, and duplicate
dotfile destinations fail validation.

This is the first portability increment. Cross-platform resolution, reviewed
application, dotfile backups and an expanded lock schema remain unimplemented.
Existing `omg env capture`, `check`, `share` and `sync` retain their existing
behavior. A captured lockfile is not yet a portable installation recipe.

## Where to go next

Read [team environments](./team.md) for capture and drift checks. See
[configuration](./configuration.md) for the separate OMG settings file and
[troubleshooting](./troubleshooting.md) for help with a failed plan.
