---
title: Local CI runner
sidebar_position: 99
description: Maintain OMG's restricted self-hosted Linux runner and hosted fallback
---

# Local CI runner

> **Who this page is for:** OMG maintainers who operate the GitHub Actions runner.
> Contributors do not need a local runner to open a pull request.

OMG keeps its GitHub Actions workflows. A repository variable opts one trusted
Fedora x86_64 QEMU guest into the local runner. The hosted label remains the
default; clearing the variable restores it without changing workflow files.

| Work | Runner |
| --- | --- |
| Fedora x86_64 QEMU guest on push, schedule, or dispatch from `main` | `OMG_CI_LINUX_RUNNER` when set; otherwise `ubuntu-24.04` |
| Other Linux jobs, pull requests, merge queue, and dispatch from another branch | GitHub-hosted `ubuntu-24.04` |
| Native ARM64 builds and QEMU guests | GitHub-hosted `ubuntu-24.04-arm`, or the explicitly configured native ARM runner |
| macOS builds and smoke tests | GitHub-hosted `macos-14` |

This narrow pilot keeps the parallel native builds and the other three QEMU
guests hosted. In the fully hosted #519 run, the native Linux jobs and four
guest jobs overlapped; their durations would total roughly 79 minutes if sent
through one serial runner. Measure the Fedora pilot before routing more jobs.

## Why the runner belongs to an organization group

This repository is public. A repository-level self-hosted runner can be selected
by a workflow in a proposed pull request. The `runs-on` expression in a workflow
is a routing preference, not a security boundary: a PR can edit that expression.

Register the machine **only as an organization runner** in a group named
`omg-local-ci`. Configure the group with all of these restrictions before adding
the runner:

1. Repository access: selected repositories, with only `omg-cli/omg` selected.
2. Allow public repositories for this group.
3. Workflow access: selected workflows, pinned to `@refs/heads/main`. The pilot
   needs only this reusable workflow:

```text
omg-cli/omg/.github/workflows/qemu-lane.yml@refs/heads/main
```

The configured group now allows only this workflow. Do not replace it with an
unrestricted group or a repository runner. Review the group settings after any
organization change. The runner's
Docker access and passwordless `sudo` allow jobs to administer its WSL distro;
keep personal files and credentials out of that distro. WSL is not a security
boundary against malicious code.

## Machine setup

Use a dedicated Ubuntu 24.04 WSL 2 distro on Windows, not the development Arch
distro. The runner account is `omgci`; it owns `/home/omgci/actions-runner` and
belongs to the `docker` group. Docker runs as a systemd service.
Its `/etc/wsl.conf` enables systemd and disables automatic Windows-drive mounts
and Windows process interop. This reduces accidental access to host files, but
does not replace the organization runner-group restriction.

[WSL's `automount=false` setting](https://learn.microsoft.com/en-us/windows/wsl/wsl-config)
does not prevent a later manual DrvFs mount. The QEMU
job checks `/proc/self/mounts` and refuses to run if a Windows drive is visible.
After a local diagnostic that mounts `/mnt/c`, unmount it before the next
trusted CI run:

```bash
sudo umount /mnt/c
test ! -e /mnt/c/Users
```

WSL 2 distros [share the device tree](https://learn.microsoft.com/en-us/windows/wsl/about).
Starting another distro can change `/dev/kvm`'s group and
remove the runner's ACL while a job is already executing; this happened within
four seconds between the QEMU preflight and controller launch. Provision a
separate character node on the Ubuntu distro's ext4 filesystem instead. The
repo-owned helper [creates a character node with the live device's major/minor](https://man7.org/linux/man-pages/man2/mknod.2.html), permits only
`root:omgci` with mode `0660`, and verifies `KVM_GET_API_VERSION == 12`. It
rejects an existing wrong node, symlink, or inherited extended ACL. Do not put
this alias under `/run`:
that WSL mount has [`nodev`](https://man7.org/linux/man-pages/man2/mount.2.html),
so a device node there cannot be opened.

From a checkout of this repository, install the root-owned helper and systemd
unit in the Ubuntu runner distro. Run these commands there before starting the
runner service:

```bash
sudo install -D -o root -g root -m 0755 scripts/omg-kvm-device.py /usr/local/libexec/omg-kvm-device.py
sudo install -D -o root -g root -m 0644 scripts/omg-kvm-device.service /etc/systemd/system/omg-kvm-device.service
sudo systemctl daemon-reload
sudo systemctl enable --now omg-kvm-device.service
sudo -u omgci python3 /usr/local/libexec/omg-kvm-device.py check
```

Both commands must succeed. The helper's `check` also runs in the QEMU job;
the job fails if the alias disappears, changes ownership, or stops opening KVM.
The alias is on ext4 and stays restricted even when another WSL distro changes
the shared `/dev/kvm` inode. Re-run the install commands after updating the
helper or unit in this repository.
[Docker's `--device` mapping](https://docs.docker.com/reference/cli/docker/container/run/#add-host-device-to-container---device)
exposes that private host node as `/dev/kvm` in the QEMU controller.

Before registration, verify these from PowerShell:

```powershell
wsl.exe --distribution Ubuntu-24.04 --user omgci --exec bash -lc 'test "$(id -un)" = omgci; docker info --format "{{.ServerVersion}}"; test ! -e /mnt/c/Users; sudo -n true'
wsl.exe --distribution Ubuntu-24.04 --user omgci --exec python3 /usr/local/libexec/omg-kvm-device.py check
```

The KVM API check must report `12`. Download the current x64 Linux runner from
the official `actions/runner` release, verify its SHA-256 from that release's
asset metadata, and extract it under `/home/omgci/actions-runner`. Obtain a
short-lived organization registration token from GitHub. Register as `omgci`
with the group and custom label:

```bash
cd /home/omgci/actions-runner
./config.sh --unattended --url https://github.com/omg-cli \
  --token "$REGISTRATION_TOKEN" --name omg-wsl-x64 \
  --runnergroup omg-local-ci --labels omg-local-ci-x64 \
  --work _work --replace
sudo ./svc.sh install omgci
mapfile -t units < <(systemctl list-unit-files --no-legend 'actions.runner.*.service' | awk '{print $1}')
test "${#units[@]}" -eq 1
unit="${units[0]}"
sudo install -d -o root -g root -m 0755 "/etc/systemd/system/$unit.d"
sudo install -o root -g root -m 0644 scripts/omg-runner-kvm-dependency.conf \
  "/etc/systemd/system/$unit.d/10-kvm-device.conf"
sudo systemctl daemon-reload
sudo ./svc.sh start
sudo ./svc.sh status
```

The unit's [requirement and ordering dependencies](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html)
make alias setup a prerequisite of every runner start.
If KVM is absent or the alias is wrong, the runner does not start; repair the
device or the service instead of widening `/dev/kvm` permissions. On an
already-registered runner, install the same drop-in and restart its runner
service during a quiet period so the dependency takes effect.

Do not commit or log the registration token. The systemd service starts when
this WSL distro starts. On the maintainer PC, the Windows scheduled task
`OMG Local CI Runner WSL` launches the distro at sign-in and keeps it running.
Check that task and the runner's GitHub status after a reboot before expecting
jobs to leave the GitHub queue. To start the distro manually, run
`wsl.exe --distribution Ubuntu-24.04 --exec /usr/bin/sleep infinity` in a
separate terminal.

The QEMU controller checks that its metadata-service probe increments its own
firewall reject rule before it boots a guest. Its source-scoped chain is hooked
at the start of `FORWARD` and `INPUT`; this keeps the rule reachable even if
Docker places `DOCKER-USER` behind bridge `ACCEPT` rules. The controller removes
both hooks after the container exits. If the probe still times out with a zero
reject counter, inspect `sudo iptables -S FORWARD` and the job's egress receipt
before rerunning. Do not disable the probe: a green guest without proven egress
confinement is invalid evidence. See [Docker's iptables chain order](https://docs.docker.com/engine/network/firewall-iptables/).

## Enable and verify routing

After the runner group and runner are healthy, set the repository Actions
variable `OMG_CI_LINUX_RUNNER` to `omg-local-ci-x64`. Run staged QEMU through a
trusted push or dispatch on `main`, then inspect job details in GitHub Actions.
Only the Fedora x86_64 guest should report runner name `omg-wsl-x64`; every
other job should report a GitHub-hosted runner.

The runner processes one job at a time. Compare Fedora's queue time and guest
duration with the hosted baseline before claiming a speedup. If more local
capacity is justified, each extra runner needs its own installation, service,
label, and enough WSL memory.

## Roll back or pause

Clear `OMG_CI_LINUX_RUNNER` in repository Actions variables. New Fedora guest jobs
then use `ubuntu-24.04` again. Let the current local job finish or cancel it in
GitHub Actions. Stop the runner service with `sudo ./svc.sh stop` from its
installation directory. Do not delete the workflow files: they hold the hosted
fallback. Keep the restricted group in place while a runner is registered.

If jobs remain queued, check the runner's online status, label, group access,
and service log with `journalctl -u 'actions.runner.*'`. GitHub does not
automatically reroute an already queued self-hosted job when the variable is
cleared; rerun it after the change.
