---
title: Glossary
sidebar_position: 100
description: Plain-language definitions of the words used in OMG documentation
---

# Glossary

**In plain words:** these docs use some computer words. This page explains each one in
everyday language. You do not need to read it from top to bottom. Look up a word when a
page uses it and you are not sure what it means.

If a word is missing here, please
[open an issue](https://github.com/omg-cli/omg/issues) so it can be added.

## Computer words you will see in almost every page

**Terminal** (also called a console or a command prompt) — the window where you type
instructions instead of clicking with a mouse. On macOS you open the app called
**Terminal**. On Linux the app might be called **Terminal**, **Konsole**, or **GNOME
Terminal**.

**Shell** — the program inside the terminal that reads what you type and runs it. The
common shells are **bash**, **zsh**, and **fish**. Which one you have depends on your
computer's setup, not on OMG.

**Command** — a word or phrase you type, followed by the Enter key, that tells the
computer to do something. In these docs a command looks like this:

```bash
omg search ripgrep
```

**CLI** — short for "command-line interface". A program you use by typing commands
instead of clicking buttons. OMG is a CLI.

**Option** (also called a flag) — an extra word starting with `-` or `--` that changes
how a command behaves. In `omg search ripgrep --limit 10` the option is `--limit 10`.

**Alias** — a shorter spelling of a command that does exactly the same thing. `omg s` is
an alias for `omg search`.

**Argument** — a word you give to a command, such as a package name. In
`omg install firefox`, `firefox` is the argument.

**Prompt** — the text your shell shows before you type, for example
`alex@laptop:~$`. It is not something you type.

**PATH** — the list of folders your computer searches when you type the name of a
program. If a program is not in a folder on this list, the computer says
"command not found".

**Environment variable** — a named setting your shell keeps for the programs it starts.
For example, `OMG_TELEMETRY=0` turns off OMG's optional usage reporting for that
session.

**Home folder** — your personal folder. These docs write it as `~`, so `~/.config`
means "the folder named `.config` inside your home folder". A folder name that starts
with a dot is hidden by default; it still exists.

**Symbols you will see in examples**

| Symbol | What it means |
| --- | --- |
| `$` at the start of a line | The rest of the line is what you type. Do not type the `$`. |
| `#` at the start of a line | A note for the reader. Do not type it. |
| `~` | Your home folder. |
| `\|` | Send the output of one command into another. |
| `&&` | Run the next command only if the first one succeeded. |
| `--` on its own | Everything after it belongs to the project's own tool, not to OMG. |
| `<something>` | Replace this, including the angle brackets, with your own value. |

---

## Packages and installing software

**Package** — a bundle of software that your computer can install, update, and remove as
one unit.

**Package manager** — the program that installs, updates, and removes packages. Every
operating system family has one: `pacman` on Arch Linux, `apt` on Debian and Ubuntu,
`dnf` on Fedora, and Homebrew on macOS.

**Backend** — which of those package managers OMG talks to on your machine. OMG asks the
package manager to do the work; it does not replace it.

**Repository** — an online collection of packages that your computer can install from.

**AUR** (Arch User Repository) — a collection of build recipes written by Arch Linux
users rather than by the distribution itself. An AUR package is built on your machine
from community-supplied instructions. See [AUR packages](./aur.md).

**PKGBUILD** — the file inside an AUR entry that says how to download and build that
package. It is community code, which is why OMG shows it to you for review before
building by default.

**Dependency** — another package that a package needs in order to work.

**Reverse dependency** — a package that needs the package you are looking at.

**Orphan** — a package that was installed only because something else needed it, and
that nothing needs any more.

**Explicit package** — a package you asked for directly, rather than one that arrived as
a dependency.

**Transaction** — one recorded change to your packages, such as installing or removing
something.

**Sync** — refresh your computer's list of what the repositories currently offer. On
team features, `omg env sync` instead downloads a shared record; the two uses of the
word are unrelated.

**Dry run** — a rehearsal. The command prints what it would do and changes nothing.
Usually written as `--dry-run`.

**Rollback** — return to an earlier recorded state. It is not a full machine backup. See
[history and rollback](./history.md).

**sudo**, **root**, **privilege** — the all-powerful account on Linux and macOS.
Installing system packages usually needs it. You will be asked for your password.
OMG will not ask you to run OMG itself as root to work around a problem.

## Runtimes and project tools

**Runtime** — the program that runs code written in a particular programming language,
such as Node.js for JavaScript or Python for Python code. See
[runtime management](./runtimes.md).

**Version pin** — a small file in a project folder that says which version of a runtime
the project expects, such as `.nvmrc` for Node.js. The OMG shell hook reads it when you
enter the folder.

**Shell hook** — a few lines added to your shell's start-up file. The hook runs when you
change folders and puts the right runtime version at the front of your PATH. It is
optional. See [shell integration](./shell-integration.md).

**Completion** — the ability to press Tab and have your shell finish a command or a
package name for you.

**Task** — a named piece of work a project defines, such as `build` or `test`.
`omg run build` runs the task your project already defines. See
[task runner](./task-runner.md).
