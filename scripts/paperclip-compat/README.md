# PER-471: audited checkout attribution candidate

This explicit local runtime addon is staged for independent security review. It
does not load automatically, install packages, or write the running server.
Paperclip task: [PER-471](/PER/issues/PER-471). Publication identity restoration:
[PER-477](/PER/issues/PER-477), owned by OMG CTO Orchestrator. GitHub issue and PR
are not available yet: the assigned managed connection returned
`github_identity_unavailable`. Do not infer publication from local tests.

## Cause and source contracts

Inspected installed `@paperclipai/server` version `2026.1001.0`; its
`dist/build-info.json` reports source commit
`8f8a0ab7effbd6a0584107d8038736c134ee5047`. This is package provenance, not an
independently verified upstream checkout. Attempting to fetch the corresponding
GitHub source page returned a cache miss. Installed source is the verified
primary evidence:

- `dist/services/cross-issue-influence-limit.js:16-25` reads only snapshot
  `issueId`/`taskId`; lines 50-71 validate/lock the run then reject missing source.
  Lines 77-113 count and log attempts for that run; line 6 sets cap 20.
  Exact file SHA-256:
  `99ad0be24af09f1b5e214db4fb7435766b6f9095c9085a4347e83a18d6e86c86`.
- `dist/routes/issues.js:2455-2472` calls that guard using the authenticated
  actor's run. Lines 10776-10799 perform checkout and record
  `issue.checked_out` under `getActorInfo(req)`.
- `dist/services/issues.js:7431-7590` validates checkout eligibility and updates
  issue locks; it does not attach the issue to the heartbeat snapshot.
- `dist/middleware/auth.js:285-334` binds the local JWT to its claimed run and
  rejects mismatched run headers. This patch does not change authentication.
- `dist/routes/activity.js:282-283` restricts arbitrary activity insertion to
  board callers. The fallback uses server checkout audit records, not an agent
  comment or an untrusted header as source attribution.

Authenticated historical reads in heartbeat
`58c688c5-d222-46f9-9a4c-531fd5e75879` found:

- Delivery Manager run `9faffcd7-d48c-42e1-bd48-2b064bfc7d0f` is `legacy`, invoked
  by timer; persisted snapshot contains `wakeReason: heartbeat_timer` and
  `source: scheduler`, with no `issueId` or `taskId`.
- `GET /api/issues/958f6f8e-f551-4a65-88b5-e3cf796195ee/activity` records that run's
  successful checkout of PER-442 at `2026-10-04T02:30:33.226Z`.
- Historical task-scoped run `5a258c6f-2b8c-414b-83ce-ee79992ff518` contains the
  PER-442 UUID. Existing server logs record a successful cross-issue observation
  with that source. This is a positive control, not candidate rollout proof.
- Company agent-action audit returned `403 Board access required`; no board
  identity was used. Issue-scoped activity supplied the checkout evidence.

Expected: an authenticated timer run that has successfully checked out its task
can route authorized cross-issue work with a durable source and the same cap.
Actual: the original guard ignores the checkout audit and returns
`cross_issue_influence_run_context_required`. Legacy mode itself is not the cause.

## Candidate and reproduction

`cross-issue-attribution.mjs` transforms only the exact installed service hash.
When the snapshot lacks a source, it selects the first checkout audit record
ordered by creation time and ID for the same company, run, agent and actor, with
action `issue.checked_out`, entity type `issue`, and a valid issue UUID.
Snapshot attribution remains authoritative. No checkout still means refusal.
The run lock, rate cap, counting and route authorization remain in place.

This ordering assumes server-authored audit timestamps are reliable. No live
database repair, retrospective backdating, or audit rewriting is supported.
The audit remains the source on each request; this candidate does not modify the
heartbeat snapshot or change task/environment identity.

PowerShell, from this workspace:

```powershell
$env:PAPERCLIP_LOCAL_ROOT='C:/Users/olen/Documents/Codex/paperclip-local'
$env:NODE_ENV='production'
$env:PAPERCLIP_LOG_LEVEL='silent'
$env:PER_471_CANDIDATE='0'
node --test scripts/paperclip-compat/cross-issue-attribution.test.mjs
$env:PER_471_CANDIDATE='1'
node --test scripts/paperclip-compat/cross-issue-attribution.test.mjs
git diff --check
```

The test requires the injected `PAPERCLIP_RUN_SCRATCH_DIR`. It starts separate
PostgreSQL on a dynamically selected loopback port with synthetic fixture rows,
using installed `embedded-postgres`, `pg`, and Drizzle dependencies. Fixture
UUIDs are never used as live API run headers. PostgreSQL stops in `finally`;
its data stays in run scratch for harness cleanup. No company database, vault,
OAuth credentials, agent homes, global settings or security policy are changed.

Initial harness attempt failed with PostgreSQL `42P08` (mixed text/UUID bound
parameter); explicit fixture casts corrected the harness before the valid red
run. Latest baseline: exit 1, 5 passes and 5 failures (four failing behaviors plus
the enclosing test). Candidate: exit 0, 11 passes, zero failures/skips. The
candidate checks timer attribution, authoritative snapshots, same-task counting,
missing checkout, foreign company/agent/run, malformed run, actor/action/entity
filters, later checkout source stability, concurrent 22 attempts (20 allowed,
two refused), and source-hash drift refusal. TAP receipts are attached to the
Paperclip task with this candidate.

Broader local compatibility checks:

```powershell
node --test C:/Users/olen/Documents/Codex/paperclip-local/runtime/codex-mcp-headers.test.mjs C:/Users/olen/Documents/Codex/paperclip-local/runtime/review-routing.test.mjs C:/Users/olen/Documents/Codex/paperclip-local/runtime/windows-links.test.mjs
```

Result: exit 0, 7 passes. No Rust, QEMU guest, full server suite, hosted CI,
independent exact-head QA, live route retry, publication, or merge pass claimed.
The installed service hash remained unchanged after candidate tests.

## Admission and next action

1. CTO restores the sanctioned managed GitHub execution identity via PER-477;
   Platform publishes the exact committed addon and canonical issue/PR links.
2. Add native security review and Delivery approval to this canonical task.
   Independent Security Reviewer verifies the attribution boundary, exact head,
   regression receipts and applicable runtime checks. No bridge QA child task.
3. After technical review, a controlled rollout must integrate the transformer
   into the existing explicit runtime addon. Coordinate draining/restarting the
   local runtime through its supported lifecycle so concurrent work is preserved.
   Do not hot-patch an already imported module or infer deployment from a disk
   edit. Validate a fresh real Delivery Manager timer run after sanctioned
   checkout and verify its source/counter audit under its own injected identity.
4. Delivery alone admits any eligible merge. Platform then retries mode-preserving
   publication on [PER-456](/PER/issues/PER-456). Until live verification and
   required independent gates pass, PER-471 is not a completed repair.
