---
title: CI security controls
sidebar_position: 98
description: Maintainer guide to CI gates, QEMU evidence, and failure reporting
---

# CI security controls

> **Who this page is for:** OMG maintainers and contributors. It documents continuous-integration controls.
> It is not an everyday user guide. If you are new to OMG, start with
> [Getting started](./getting-started.md).

OMG treats a successful PR, a successful main commit, and a verified published
archive as separate evidence. Publication waits for the latest successful push
runs of CI, Benchmark, Security Audit, Secret Scanning, CodeQL, Coverage, Docker
E2E and QEMU for the exact source commit.

The trusted-main Fedora x86_64 QEMU guest can use the
[restricted local runner](local-ci-runner.md). All other jobs remain on
GitHub-hosted runners. Clearing the runner variable restores hosted Fedora
QEMU without changing the evidence gates below.

## Repository enforcement

The checked-in ruleset definitions are recorded in `.github/security-rules/`. Confirm their
live enforcement in GitHub repository settings before relying on them:

- `main.json` requires a PR, resolved review conversations, an up-to-date branch,
  `CI Success` and `Generate Coverage Report` from the GitHub Actions integration.
  Both checks run on every PR, so documentation changes cannot deadlock on a
  path-filtered required workflow. Main cannot be deleted or force-pushed.
- `release-tags.json` prevents updates and deletion of `v*` tags. New version tags remain
  permitted so the gated release workflow can create them.

No actor is listed for bypass. The sole-maintainer policy requires zero external
approvals; it does not claim independent human review. Administrators can still
change repository rules, so this is a technical enforcement boundary rather than
protection against the repository owner. An emergency policy change must record
the reason, affected rule and restoration evidence in a PR or issue. Do not move
an existing release tag; publish a new version.

Generated changelog and weekly benchmark-history updates are attached as
30-day review artifacts. Those workflows have read-only repository permissions
and do not attempt direct main pushes. Apply reviewed generated changes in a PR;
the repository's disabled Actions PR-approval setting remains unchanged.

## QEMU evidence admission

The controller verifies the installed QEMU security floor before parsing a guest
image. QEMU runs as UID/GID 65534 with seccomp, zero effective capabilities,
`NoNewPrivs`, no monitor and no root/TCG fallback. Docker bounds CPU, memory,
process count and its log rotation.

A final health check requires a live guest, complete boot-scoped kernel evidence,
no recognized fatal kernel signatures or OMG coredump records, and a running
controller without an OOM receipt. Serial evidence is independently checked.
Missing, malformed or oversized required evidence fails admission. Only selected
crash identity fields are queried; core dumps and process environments are not
uploaded. These checks detect specified failure classes, not every possible bug.

Health receipt schema 2 requires positive `crash_channel` evidence for the same
boot. The supported channel is the systemd pipe handler: the running kernel's
`core_pattern` must name an executable `systemd-coredump` under `/usr/lib`,
`/usr/lib64`, `/lib` or `/lib64`, with `%P %u %g %s %t %c %h` and optional
trailing `%d`, `%d %F` or `%d %F %I` arguments. `systemd-coredump.socket` must be loaded, active,
listening and successful; an inert processor instance must load the unmasked
template, remain inactive/dead and report success. Both units must be static
or enabled. These observations must agree before and after journal collection;
the boot identity must also remain unchanged. Existing pending/failed processor
checks still run on both sides of journal collection. Old receipts without
capability evidence are rejected, including preparation and transaction receipts.

| Guest | Supported crash observation contract |
| --- | --- |
| Arch | systemd pipe handler, socket and processor template as above |
| Debian bookworm / trixie | `systemd-coredump` package providing the same channel |
| Ubuntu | `systemd-coredump` channel; apport alone is unsupported |
| Fedora | systemd pipe channel; ABRT alone is unsupported |

Missing packages, disabled/masked units, alternate handlers (including the newer
kernel socket protocol), failed queries or a changing channel fail admission.
The collector observes capability; it does not install packages, change sysctls
or start services. Guest preparation must establish this contract before trials.
The host helper test checks explicit collector refusal when its native handler is
unsupported. That negative control is not positive crash-observation evidence;
actual guest collection and admission still require the complete schema 2 receipt.
This is configured-capability evidence, not an injected-crash delivery receipt
or proof that the channel was enabled throughout earlier workload execution.
Exact-head hosted guest gates remain required. No core contents, command lines,
environments or backtraces are read to establish capability.

Primary contracts: [systemd handler and socket invocation](https://github.com/systemd/systemd/blob/v257/man/systemd-coredump.xml),
[kernel pipe routing](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#core-pattern),
and [Debian's systemd-coredump package](https://packages.debian.org/bookworm/systemd-coredump).

`tests/qemu-inventory-policy.json` indexes reviewed inventory digests and pins
the SHA-256 of each separately bounded file in `tests/qemu-inventory-policy.d/`.
Each file retains the selected tiers, network scopes and permitted per-case
skips for one exact inventory, including historical release inventories. The
index has no paths: a validated digest determines the snapshot filename, and
symlinked files or directories are refused. Changing the inventory requires a
policy review. CI always supplies the index to the harness. Its
receipt reports selected, executed, passed, failed, blocked and skipped counts
separately; a declared CLI-shape test is not advertised as an executed VM case.
Ad hoc local inventories may run without this release policy.

To add an inventory, copy the nearest reviewed snapshot to a temporary JSON
file, edit its cases and release labels to match the new TSV exactly, then run:

```sh
python3 scripts/add-qemu-inventory-snapshot.py \
  --policy tests/qemu-inventory-policy.json \
  --inventory tests/cli_behavior_inventory.tsv \
  --snapshot /path/to/reviewed-snapshot.json
```

The command adds one digest-named snapshot and one hash entry; it refuses a
missing, duplicate or mismatched case set and never rewrites old snapshots.
Review the new file and index entry together. The trusted failure reporter
loads every pinned snapshot so historical case IDs remain reportable.

The policy also declares each case's network scope. Offline cases run in a fresh
network namespace as the guest user with no new privileges. Networked cases are
explicit, including older inventory rows whose tier names incorrectly imply
offline operation. Their expected exits and required coverage are unchanged.

The controller's host firewall permits public HTTP/HTTPS, DNS to two explicit
resolvers and NTP to two configured public time servers. It rejects private, link-local/metadata and runner-local destinations
and other outbound ports. A metadata connection probe must increment the reject
rule's packet counter before setup continues. The controller has neither
`NET_RAW` nor `NET_ADMIN`; the rule is removed only after controller removal is
verified. This is an address/port policy, not a domain allowlist. Public web
destinations remain reachable for distro mirrors and runtime downloads.
Time-server addresses follow [Cloudflare's published NTP endpoints](https://developers.cloudflare.com/time-services/ntp/usage/);
the guest time service uses the same addresses so Arch's boot-time synchronization
does not require arbitrary outbound UDP.
The deny rules also cover [Azure's special platform address](https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16),
`168.63.129.16`, which falls outside private and link-local address ranges.
This restriction applies to controller traffic, not the runner's own Azure agent.

One independent reset trial per tool and operation checks OMG and native
install/remove behavior, package state, boot identity and health. Separate
privacy-export tests exercise full temporary storage, a read-only mount, an
injected `fsync` I/O error and a kill at `fsync`. They require observed fault
activation, preservation of the old export and a successful private export
after recovery. They do not establish physical disk or whole-system power-loss
recovery. Faults run only inside a marked disposable guest; exported evidence
contains results, not file contents or raw syscall traces.

Image provenance has a review deadline and a daily advance-warning issue.
See [image renewal](qemu-image-renewal.md) for the signature, controller-advisory
and hosted-validation review procedure. New signing keys are never accepted
automatically.

## Failure reporting

`qemu-report.yml` uses `workflow_run` to report completed QEMU failures from
pushes, manual runs and scheduled runs. Pull-request runs cannot enter this
privileged job: their artifacts are controlled by the proposed change, while a
`workflow_run` job has secrets and a write token. The reporter checks out the
default-branch SHA. ZIP members are parsed as bounded data without
extraction or execution. Repository, workflow, commit and run-attempt identities
are checked against GitHub before processing; old-attempt artifacts cannot close
a current failure.

Issues include the observed case, exit status, duration, commit, failed job/step,
attempt and evidence link. An exit status is not asserted to be a root cause.
Missing or invalid results create a workflow-level harness issue. More than 25
case failures also produce an aggregate issue linking the full evidence.
Superseded/cancelled and skipped runs remain visible in Actions without opening
product-failure issues. Recurring failures use the existing case fingerprint.
Only a successful push run whose commit still equals current `main` can close
matching issues. PR runs and older green runs cannot create, update, or close
issues.

The reporter becomes active after its workflow lands on the default branch.
Confirm an actual completed-run report after merging; local parser tests alone
do not prove GitHub delivery.

References: [GitHub secure use](https://docs.github.com/en/actions/reference/security/secure-use),
[repository rules API](https://docs.github.com/en/rest/repos/rules),
[QEMU security](https://www.qemu.org/docs/master/system/security.html),
[journalctl](https://www.freedesktop.org/software/systemd/man/journalctl), and
[SLSA artifact verification](https://slsa.dev/spec/v1.2/verifying-artifacts).

## Where to go next

- [Security model](./security.md) for the limits of user-facing audit evidence.
- [QEMU image renewal](./qemu-image-renewal.md) for pin review and hosted validation.
- [Contributing](../CONTRIBUTING.md) for the contribution workflow.
