# Local CI runner rollout

## Goal

Pilot the trusted-main Fedora x86_64 QEMU guest on the owner's dedicated WSL Ubuntu 24.04 runner. Keep every other job on GitHub-hosted runners and preserve a one-variable rollback.

## Constraints

- This is a public repository. A repository-wide self-hosted runner would be reachable from untrusted pull-request workflows. Place the runner in an organization runner group restricted to reviewed workflows at `refs/heads/main` before registering it.
- Linux container jobs need Docker. Native x86 QEMU jobs need accessible `/dev/kvm`. Native ARM64 QEMU needs ARM64 hardware and remains hosted.
- GitHub assigns work only to an idle self-hosted runner. On the fully hosted #519 run, native Linux builds and QEMU guests overlapped; their durations would add to roughly 79 minutes if serialized on one runner. Do not route the full matrix to one machine.

## Sequence

1. Route only `qemu-lane.yml`'s Fedora x86_64 `guest` job to `OMG_CI_LINUX_RUNNER` for push, schedule, or dispatch on `main`. Keep PRs, merge queues, non-main dispatch, other distros, and every build/release job hosted.
2. Retain the dedicated Ubuntu 24.04 WSL distro with Docker, KVM, and the official Actions runner under a non-root account. Restrict the organization runner group to reviewed workflows pinned to `refs/heads/main`.
3. Check workflow syntax, routing policy, QEMU fixtures, and a trusted-main canary. Compare queue time, guest duration, and evidence with the hosted baseline before expanding routing.
4. If the pilot stalls or slows the gate, clear `OMG_CI_LINUX_RUNNER` and rerun the job on a hosted runner.

## Rollback

Unset `OMG_CI_LINUX_RUNNER` to return the Fedora guest to `ubuntu-24.04`. The workflow and hosted fallback remain in place. Stop the local runner separately after its current job drains.
