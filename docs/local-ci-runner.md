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
belongs to the `docker` and `kvm` groups. Docker runs as a systemd service.
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

Install the ACL utility before enabling QEMU jobs. WSL can expose `/dev/kvm`
with a group other than `kvm`, even when `omgci` belongs to that group. The
workflow grants `omgci` access to this device when needed; it requires
`setfacl` and must not widen access to all local users:

```bash
sudo apt-get update
sudo apt-get install -y acl
command -v setfacl
sudo setfacl -m u:omgci:rw /dev/kvm
```

Before registration, verify these from PowerShell:

```powershell
wsl.exe --distribution Ubuntu-24.04 --user omgci --exec bash -lc 'test "$(id -un)" = omgci; docker info --format "{{.ServerVersion}}"; test ! -e /mnt/c/Users; sudo -n true'
wsl.exe --distribution Ubuntu-24.04 --user omgci --exec python3 -c 'import fcntl,os; f=os.open("/dev/kvm",os.O_RDWR); print(fcntl.ioctl(f,0xAE00,0)); os.close(f)'
```

The KVM API check must print `12`. Download the current x64 Linux runner from
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
sudo ./svc.sh start
sudo ./svc.sh status
```

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
