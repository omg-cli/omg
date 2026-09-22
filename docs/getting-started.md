---
title: Getting started for beginners
sidebar_position: 2
description: A first walkthrough for people who have never used a terminal before
---

# Getting started

**In plain words:** OMG is a program you use by typing short instructions. It installs
and updates other programs for you, and it can also choose which version of a
programming language a project needs. This page walks you through it one step at a time.
Nothing on this page deletes your files. The steps that change your computer are marked
clearly, and you can stop after any step.

If a word here is unfamiliar, [the glossary](./glossary.md) explains it in everyday
language. If you would rather have a friend or colleague help you, show them this page.

**OMG is approaching beta.** The people who make it still change how it works. Use it on
a computer you can reinstall if something goes wrong, and keep your normal package
installer available. On Arch Linux that is `pacman`, on Debian and Ubuntu it is `apt`, on
Fedora it is `dnf`, and on macOS it is Homebrew.

## Step 1: Find out what kind of computer you have

You need this to choose the right download. Look at the table below and find the row that
matches your computer.

| Your computer | What OMG needs | Where to continue |
| --- | --- | --- |
| Mac with Apple silicon | macOS on ARM64 | This page, then [installation](./installation.md) |
| Mac with an Intel processor | Not supported by OMG releases | Use a supported computer or a Linux virtual machine |
| Linux, Arch Linux | Arch Linux x86_64 | This page, then [installation](./installation.md) |
| Linux, Debian or Ubuntu | Debian or Ubuntu x86_64 | This page, then [installation](./installation.md) |
| Linux, Fedora | Fedora x86_64 | This page, then [installation](./installation.md) |
| Windows | OMG runs inside WSL, which is a real Linux system in Windows | [install a Linux distribution in WSL](https://learn.microsoft.com/windows/wsl/install), then follow the Linux steps |

To check a Mac: click the Apple menu in the top-left corner, choose **About This Mac**,
and look at the line that says **Chip** or **Processor**.

To check a Linux computer: open the terminal (Step 2) and type this. It prints the name
of your Linux distribution.

```bash
cat /etc/os-release
```

If your system is not in the table, there is no supported OMG release for it. Do not
download a package with a similar name from another source; it may be a different program.

## Step 2: Open the terminal

The terminal is the window where you type instructions instead of clicking buttons. It
looks plain and old-fashioned. That is normal.

- **On a Mac:** hold `Command` and press the space bar, type `Terminal`, then press
  Enter.
- **On Linux:** open the activities or applications menu and type `Terminal`, then press
  Enter. Some systems call it `Console` or `Konsole`.
- **On Windows:** complete the WSL step in the table above first, then open the Linux
  terminal inside it.

You should now see a window with a line of text ending in a `$` or `%` sign. That line is
called the prompt. You do not type the prompt. You type your instruction after it and
press Enter.

Test it with this command, which only prints a greeting:

```bash
echo "hello"
```

You should see `hello` printed on the next line. If you do, your terminal works.


## Step 3: Install OMG

Installing means copying the OMG program onto your computer. You need an internet
connection for this step.

The installer downloads a ready-made file, checks that the file is the one the OMG
project published, and then copies it into a folder inside your home folder. This
prebuilt-release path does not change system files or need an administrator password.
The separate source-build path can offer to install missing build tools with `sudo`.

**Read the script before you run it.** The first command below only downloads it, so you
can look at it. The second command runs it.

```bash
curl --proto '=https' --tlsv1.2 -fsSL https://getomg.xyz/install.sh -o omg-install.sh
less omg-install.sh
```

`less` shows the file one screen at a time. Press the space bar for the next screen and
the letter `q` to quit. You do not have to understand everything in the file. The point
is that you can see what you are about to run.

Installation also needs the GitHub command-line program, called `gh`, because it checks
the proof that the download came from the OMG build system. If `gh` is missing, the
installer stops and tells you so. In that case, install `gh` from your system's software
store first, then run the installer again.

```bash
OMG_NO_TELEMETRY=1 OMG_SKIP_SHELL=1 bash omg-install.sh
```

`OMG_NO_TELEMETRY=1` means "do not send any usage information". `OMG_SKIP_SHELL=1` means
"do not edit my shell start-up files". You can add those options later on purpose; see
[installation](./installation.md).

You should see a sequence of short status lines ending with
`Installed prebuilt binaries to ...`.

The installer puts the program in `~/.local/bin`, which is a folder inside your home
folder. Your computer may not look there yet, so run this command:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Now check that the program runs:

```bash
omg --version
```

You should see one line like `omg 0.1.223`. The number is the version of OMG you
installed; yours may be newer. If instead you see `omg: command not found`, the folder is
still not on your PATH. Close the terminal window, open a new one, or repeat the
`export PATH=...` line in the window you are using.

If you want OMG to set itself up automatically, run this once. It can add the shell hook
(a few lines added to your shell start-up file) and start the optional background helper.

```bash
omg init
```

`omg init` asks questions before it changes anything. You can skip it for now and run it
later: nothing else on this page needs it.

## Step 4: Try commands that change nothing

These commands inspect your system without installing or removing packages. Run them
in any order.

```bash
omg --help
```

Prints the list of things OMG can do. Some commands are hidden from this list; add
`--all-commands` to see everything, advanced commands included.

```bash
omg doctor
```

Checks your computer for common problems: is OMG in a sensible folder, can it reach the
package sources, and so on. Read the lines that say something is wrong. If you want a
network check as well, type `omg doctor --network`. If there is a problem, the command
ends with a failure code, which some scripts use to stop early. The list of checks is the
useful part.

```bash
omg status
```

Shows a short summary of your computer: how many packages are installed, how many could
be updated, and how many are no longer needed. Add `--fast` to skip the slower checks.

```bash
omg search ripgrep
```

Searches the configured package sources for matching programs. In an interactive
terminal, OMG may offer a picker to show details for one result; that picker does not
install it. On Arch Linux the list includes community entries from the AUR; add
`--no-aur` to leave those out. You can search for anything, for example
`omg search chess`.

```bash
omg info ripgrep
```

Shows details for one package. The available fields vary by package source and
operating system. For example, a Debian lookup may show only its name, version,
description, and whether it is installed.

```bash
omg why ripgrep
```

Explains why a package is on your computer. Add `--reverse` to see what needs it.

## Step 5: Make your first real change (optional)

**Warning:** the commands in this step install and then remove a program on your
computer. Installing changes your system. Read the output before agreeing to anything.
If the computer is not yours, or you cannot reinstall it, skip this step.

Preview this installation with `--dry-run`. The `install`, `remove`, `update`, and
`clean` commands accept this option; read each command's help before using it:

```bash
omg install --dry-run ripgrep
```

When the preview looks right, remove `--dry-run`:

```bash
omg install ripgrep
```

You may be asked to confirm the installation, and your computer's normal package
installer may ask for your password. That is expected for system packages. Read the list
of packages it wants to add before you agree.

Now check that the program is there:

```bash
rg --version
```

Finally, remove it again, because this was only practice:

```bash
omg remove --dry-run ripgrep
omg remove ripgrep
```

To update managed system packages and runtimes, use `omg update`. Preview available
updates first with `omg update --check`, which only lists them.

## Step 6: Choose a version of a programming language (optional)

If you write software, a project often needs one particular version of a programming
language such as Node.js, Python, or Rust. OMG can install that version **inside your home
folder**, which means no password and nothing changed outside your own account.

```bash
omg use node 22
```

The first time you run this, OMG downloads that version of Node.js. You should see
progress lines and then a message that the version is selected.

```bash
omg which node
```

Prints the selected Node.js version. It does not print the executable path.

To see what is installed, and what else is available:

```bash
omg list node
omg list node --available
```

If you change your mind, you can remove a version again. Switch to a different one first,
or OMG will refuse:

```bash
omg use node 20
omg use node 22 --uninstall
```

If you want OMG to pick the right version automatically when you enter a project folder,
follow [shell integration](./shell-integration.md). That page explains the small edit to
your shell start-up file, and how to undo it.

## Step 7: If you see an error message

An error message is information, not damage. Read the last few lines first; that is where
the reason usually is.

| What you see | What it usually means | What to do |
| --- | --- | --- |
| `omg: command not found` | Your computer cannot find the OMG program | Repeat the `export PATH="$HOME/.local/bin:$PATH"` line, or open a new terminal window |
| `Permission denied` | A system package operation needs elevation, or a file belongs to someone else | Read the full error. Let OMG request elevation for a package operation; do not run OMG itself as root or change file ownership without identifying the owner |
| `Could not connect` or a timeout | No internet, or the package sources are unreachable | Check your internet connection, then run `omg doctor --network` |
| `Checksum` or `attestation` failure | The downloaded file did not match the published proof | Stop. Do not try to disable the check. Report it, see below |
| A long list of packages you did not ask for | Those are the dependencies: the packages your choice needs | Read the list. Cancel if you do not recognise the package names |
| `Exit status` or `exit code` other than 0 | The command did not finish successfully | Run `omg doctor`, then read [troubleshooting](./troubleshooting.md) |

Rules that keep you safe:

- Do not run OMG with `sudo` to make an error disappear. The system package step asks for
  your password on its own when it needs to.
- Do not delete folders under `~/.local/share/omg` to clear an error. That folder holds
  your installed language versions and your record of what changed.
- Do not turn off checksums, signatures, or policy checks. Those checks are the reason the
  installation can be trusted.
- When you ask for help, copy the command you ran and the message you got. Remove
  passwords, tokens, and private folder names first.

The safest first aid for almost any problem is:

```bash
omg doctor
omg status
omg daemon-status
```

## Words and symbols used on this page

| Symbol | What it means |
| --- | --- |
| `$` at the start of a line | The rest of the line is what you type. Do not type the `$`. |
| `~` | Your home folder. |
| `\|` | Sends the output of one command into another command. |
| `<something>` | Replace this, including the angle brackets, with your own value. |

Words such as package, dependency, runtime, hook, and daemon are explained in
[the glossary](./glossary.md).

## Where to go next

- [Quickstart](./quickstart.md) — the short version for a project you already have.
- [Installation](./installation.md) — all installer options, source builds, and removal.
- [Cheat sheet](./cheatsheet.md) — the everyday commands on one page.
- [Package management](./packages.md) — search, install, update, remove, clean.
- [Runtime management](./runtimes.md) — all 14 supported language runtimes.
- [Troubleshooting](./troubleshooting.md) — what to check, and what not to do.
- [FAQ](./faq.md) — short answers to common questions.

If something looks wrong in these instructions, or a command does not behave as
described, please [report it](https://github.com/omg-cli/omg/issues) with your OMG version
(`omg --version`), your Linux distribution or macOS version, the exact command, and the
message you saw. Report security problems privately, as described in
[SECURITY.md](../SECURITY.md).
