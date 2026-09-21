# QA repeat loop: pipeline files it, agents fix it, pipeline verifies it

> **Who this page is for:** OMG maintainers and contributors. It documents release checks and evidence.
> It is not an everyday user guide. If you are new to OMG, start with
> [Getting started](./getting-started.md).

Three scheduled pipelines test every supported platform; one script turns
failures into agent-actionable issues and green runs into auto-closes.

## Legs (all supported platforms)

| Leg | Workflow | Distros | Trigger |
|---|---|---|---|
| Container smoke | `release-smoke.yml` (`smoke`) | arch, debian, ubuntu, fedora (x86_64) | PR, dispatch, nightly |
| Native macOS smoke | `release-smoke.yml` (`smoke-macos`) | macos (`macos-14`, `--executor native`) | PR, dispatch, nightly |
| QEMU x86_64 guests | `qemu-matrix.yml` (`guest`) | arch, debian, ubuntu, fedora | PR staged, dispatch, nightly published |
| QEMU arm64 guests | `qemu-matrix.yml` (`guest-arm`) | debian, ubuntu, fedora (staged-only; no published `aarch64-linux` archives exist, and upstream has no aarch64 Arch cloud image) | PR staged, dispatch staged |

Every leg uploads per-case `results.json` evidence in the same schema
(`case_id`, `distro`, `result`, `exit_code`, `elapsed_seconds`).

## Filing (nightly only, never fails the build)

Each workflow has a `file-issues` job (`schedule` only,
`continue-on-error: true`) that runs `scripts/qa-file-issue.sh` per
`results.json` with `--source qemu-matrix` or `--source release-smoke`:

- Fingerprint is `source:distro:case` (not the verdict), carried in an
  HTML marker, so flapping verdicts update one issue instead of dupes.
- New issues carry: case/distro/result/exit/elapsed, run link, a
  **scrubbed failure tail** (transcript, `guest-check.log`, or inventory
  row log), evidence paths, and an **agent runbook** with the rerun
  command and resolve criteria. Only allowlisted result fields plus
  scrubbed excerpts leave the machine; full logs stay in run artifacts.
- Repeat failures while open land as comments (with a fresh excerpt);
  a recurrence after a close files a follow-up linking the closed issue.
- Cases reporting `PASS`/`EXPECTED_REJECTION` in a run **close** their
  open issue (comment + close), scoped strictly to cases present in that
  run's input — one distro's run never closes another's issues.
- Schema violations fail closed before any `gh` mutation; `--dry-run`
  plans creates/comments/closes without mutating.

## Agent runbook (the repeat part)

Publishing dispatches must use the version-tag ref so their attestations can
also pass existing-tag resync verification. Branch dispatches remain available
for non-publishing dry runs. CI and Benchmark must have passed for the exact
source commit. Their path filters intentionally omit unrelated documentation
changes; manually dispatch both at that ref before publishing a documentation-
only commit. Never substitute a successful run from a different commit.

Smoke resolves a release tag once and waits for its runner fixtures before
starting distro jobs. Its artifacts remain separated per distro during issue
collection. Reporting configuration is passed as environment data; failed
setup gets a sanitized fallback record when no harness results exist.

1. Pick an open `qa-failure` issue. The body has everything: failing
   case, distro, excerpt, evidence paths, rerun command.
2. Repro with the runbook command (same release tag as the linked run).
3. Fix, land the change through the normal PR/CI path.
4. Do nothing else: the next scheduled run comments and closes the issue
   on green, or appends a fresh excerpt on red. If it regresses later, a
   follow-up issue links back here.

## What the loop cannot cover (by design)

- `nested-container` inventory rows: guests have no docker-in-guest yet.
- `network,credentialed` rows: need a real token (`--allow-credentialed`
  is never passed in CI).
- `validation-pending` target flips: only on real-guest runs, never by
  editing expectations to match.
- Pixel screenshots of TUI commands: issues carry transcript excerpts
  (the honest "screenshot" for CLI output). True framebuffer captures
  would need a display device on the guests (`screendump` over VNC) or
  `script(1)` typescripts in containers — designed but not built; no
  fake screenshots are ever attached.
- Auto-fix PRs: intentionally not wired — opening PRs needs the human
  risk call first.

## One-time human bootstrap

- Create the `qa-failure` label.
- Add the `OMG_SMOKE_SENTRY_DSN` secret (smoke Sentry reporting; absence
  is a visible notice, not a silent no-op).
