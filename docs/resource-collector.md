# Scoped Linux resource collector

Optional preparation for [PER-803](http://127.0.0.1:3100/PER/issues/PER-803)
and the canonical [resource baseline](http://127.0.0.1:3100/PER/issues/PER-469).
This script does not schedule a measurement window or run product benchmarks.

Run one trusted, bounded command on Linux:

```sh
python3 scripts/resource_collector.py --scratch-dir "$PAPERCLIP_RUN_SCRATCH_DIR" \
  --timeout 60 -- /absolute/path/to/command argument
```

The scratch path must be translated to a Linux path when invoking through WSL.
The JSON record preserves argv, child PID, signed child exit code, timeout flag,
monotonic elapsed seconds, user/system CPU seconds, maximum RSS in KiB, output
byte counts and SHA256 hashes. The CLI returns the child's exit status; signal
termination becomes 128 plus signal, and collector timeout returns 124.
Launch/collector errors fail the invocation rather than produce a successful
sample. Output content is captured in temporary files and discarded after hashing.
Check workload-specific output assertions separately before collecting samples.

## Accounting and limits

[Python os.wait4](https://docs.python.org/3/library/os.html#os.wait4) returns
resource usage for the selected waited child. The collector never subtracts
cumulative RUSAGE_CHILDREN RSS. [Linux getrusage](https://man7.org/linux/man-pages/man2/getrusage.2.html)
defines CPU accounting and KiB maximum RSS; descendant accounting depends on
intermediate parents waiting for children. Maximum RSS is a high-water value,
not simultaneous aggregate tree memory. Persistent daemons, detached/unwaited
descendants and other workers are not measured by this collector.

Elapsed timing uses monotonic time from before spawn to after reaping, including
spawn and polling overhead, excluding output hashing. Polling sleeps 1 ms.
Timeout kills the owned process group and reaps the direct child. Commands that
escape that group are unsupported. This is not an adversarial process sandbox;
unbounded output, a stuck kernel operation, or descendants left alive after a
normal child exit require a separate workload/lifecycle contract. CPU/RSS and
elapsed are different clocks/accounting domains; do not infer precision beyond
the host's actual resolution. Linux-only units are explicitly enforced.

## Verification

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_resource_collector.py -v
```

Seven real-process controls cover CPU load, touched 64 MiB memory, a following
small child (detecting cumulative RSS contamination), nonzero exit, binary stdout
and stderr hashes, timeout and reaping, sleep elapsed distinct from CPU, invalid
timeouts, missing executable, and the CLI failure contract. Before implementation,
all seven failed with the explicit missing-collector assertion. After implementation
all passed on WSL archlinux as omg-audit, Python 3.14.7. These numbers validate
the collector only; they are not an OMG performance baseline. Exact commands,
hashes and run output are retained in the Paperclip task evidence.

## Canonical next-wake checks and admission

Using the next owner's actual run authentication, GET `/api/issues/PER-469`,
then GET `/api/execution-workspaces/<returned executionWorkspaceId>`, then inspect
`currentExecutionWorkspace` in `/api/issues/PER-469/heartbeat-context`. Require an
active workspace whose sourceIssueId is the canonical task, distinct from PER-4.
Verify cwd with `git rev-parse --show-toplevel`, `git rev-parse --git-dir`,
`git branch --show-current`, `git rev-parse HEAD`, and `git status --porcelain=v1`.
Do not substitute PER-803's child workspace as proof.

Manager retains measurement admission after independent CI and Guest Quality
review and Delivery approval of this candidate: at most ten minutes preparation
outside samples, task-specific target and CARGO_BUILD_JOBS=2, three warmups and
twenty samples per case capped at sixty seconds, no competing guest/heavy build.
Performance remains canonical baseline owner. No active reservation is created
by these instructions. A future canonical source head must contain the approved
collector (or use its separately verified immutable path); workspace realization
does not establish collector availability on the pinned baseline source.
