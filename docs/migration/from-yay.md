---
title: Migrating from yay
sidebar_label: From yay
sidebar_position: 1
description: Command mapping and migration guide from yay to OMG
---

# Migrating from yay

**In plain words:** if you used the yay helper before, this page maps the commands you already
know to their OMG equivalents and states plainly where the behaviour differs.

> New to the terminal? Read [Getting started](../getting-started.md) and keep
> [the glossary](../glossary.md) open while you work.

OMG is not a drop-in replacement for every yay flag. It is a different program with a
different security model, so the honest way to migrate is: map the commands you actually use,
check the ones this page says do not map, and keep `pacman` and `yay` installed until your
workflows are validated on your own machine.

## Install OMG first

Use the reviewed installer from [installation](../installation.md):

```bash
curl --proto '=https' --tlsv1.2 -fsSL https://getomg.xyz/install.sh -o omg-install.sh
less omg-install.sh
OMG_NO_TELEMETRY=1 OMG_SKIP_SHELL=1 bash omg-install.sh
export PATH="$HOME/.local/bin:$PATH"
omg --version
```

Do **not** assume an `omg` or `omg-bin` package exists in the AUR, or that OMG publishes a
crate: the project promises neither, and a similarly named package is not the same program.
Check `command -v omg` afterwards to see which binary your shell actually finds.

## Command mapping

| yay | OMG | Notes |
| :--- | :--- | :--- |
| `yay -Ss <query>` | `omg search <query>` | Official repositories and the AUR on Arch; `--no-aur` restricts it to official results |
| `yay -Si <pkg>` | `omg info <pkg>` | Package details from the selected backend |
| `yay -S <pkg>` | `omg install <pkg>` | AUR entries are detected; review applies before the build |
| `yay -S --noconfirm` | `omg install -y` | `-y` skips confirmation prompts, not the attended approval for privileged AUR output |
| `yay -R <pkg>` | `omg remove <pkg>` | Review the removal plan before confirming |
| `yay -Rns <pkg>` | `omg remove --recursive <pkg>` | Arch only: also removes dependencies nothing else needs |
| `yay -Syu` | `omg update` | Syncs and upgrades, official packages and AUR |
| `yay -Sua` | `omg update --aur-only` | Refreshes AUR packages and leaves official upgrades to `pacman -Syu` |
| `yay -Sy` | `omg sync` | Refreshes repository metadata only |
| `yay -Qu` | `omg outdated` | Lists packages with a newer version available |
| `yay -Qe` | `omg explicit` | Lists packages you asked for yourself |
| `yay -Qtd` | `omg clean --orphans` | Removes dependencies nothing needs any more |
| `yay -Sc` | `omg clean --cache` | Requests package-cache cleanup |

Preview first when a command changes state: `omg install --dry-run`, `omg remove --dry-run`,
`omg update --check`, and `omg clean --dry-run --all`.

## What does not map

| yay behaviour | Status in OMG |
| :--- | :--- |
| `yay -G` (download a PKGBUILD without building) | Not provided. OMG fetches sources as the first step of a reviewed build; to read a recipe only, use the AUR web page or clone the AUR repository. |
| `yay --editmenu`, `--cleanafter` and similar flags | Not provided. Review is a prompted step in the build path, not a configurable menu. |
| yay's interactive number-key selection | Not provided. Bare `omg install` opens OMG's own package picker. |
| `~/.config/yay/config.json` | Not read. OMG uses `~/.config/omg/config.toml`; migrate only the settings you recognise — see [configuration](../configuration.md). |
| AUR comments, votes, and popularity as a workflow | Search can show source metadata such as votes, but OMG is not an AUR web client. |

If one of those is essential to your workflow, keep yay for that case rather than working
around it.


## What changes in how AUR builds run

Run OMG as your regular account. Fetching, review, and building stay unprivileged, and OMG asks
for elevation only for the validated package transaction. `sudo omg …` is deprecated, and AUR
builds refuse to run at all when OMG starts as root.

Once a recipe is accepted, OMG re-hashes the source tree, builds offline in Bubblewrap by
default, inspects the resulting archive, and hands sealed bytes to the privileged step.
Archives containing install hooks, setuid/setgid files, or file capabilities require a separate
attended confirmation that `--yes` does not answer. These controls follow Arch's documented
[PKGBUILD execution and install-script model](https://man.archlinux.org/man/PKGBUILD.5),
Bubblewrap's [caller-defined sandbox model](https://github.com/containers/bubblewrap/blob/main/README.md#sandbox-security),
and Linux's [`memfd_create(2)` sealing semantics](https://man7.org/linux/man-pages/man2/memfd_create.2.html).
The full gate list is in [AUR support](../aur.md).

**Limit:** these controls reduce specific risks; they do not make community build code benign.
AUR recipes still execute on your machine, and matching hashes are tamper evidence rather than a
publisher signature.

## What you gain beyond package management

```bash
# Runtime versions per project, installed inside your home folder
omg use node 20
omg list node --available
omg which node

# The task a project already defines
omg run build

# A recorded environment, checked for drift
omg env capture
omg env check
```

Environment capture needs the Arch or Debian backend, so it works on the same machines where
yay did. `omg env check` reports drift and does not install anything.

Security commands have their own scope: `omg audit scan` needs the daemon, and `omg audit sbom`
needs the Arch backend plus advisory access. Neither is a compliance certification; see
[security](../security.md).

## Next steps

- [Installation](../installation.md) for update and uninstall procedures.
- [Package management](../packages.md) for the full package workflow and backend limits.
- [AUR support](../aur.md) for the review, sandbox, and approval rules in detail.
- [CLI reference](../cli.md) for every flag, including the ones this page does not use.
