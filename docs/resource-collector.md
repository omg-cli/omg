# Scoped Linux resource collector

Optional preparation tracked in [issue847](https://github.com/omg-cli/omg/issues/847).
This script does not schedule a measurement window or run product benchmarks.

Run one trusted, bounded command on Linux:

```sh
(
  task_scratch=$(mktemp -d) || exit
  trap 'rmdir -- "$task_scratch"' EXIT
  python3 scripts/resource_collector.py --scratch-dir "$task_scratch" \
    --timeout 60 -- /absolute/path/to/command argument
)
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

`max_rss_kib` is raw process-lifetime RSS, including the child's pre-exec
image, rather than executable-only memory. Linux preserves resource usage
across exec (the Notes section of the Linux contract above). A child spawned
from a loaded caller can therefore retain a pre-exec RSS floor larger than
the executable's own peak. This is distinct from previous-child cumulative
accounting; neither a caller-floor subtraction nor an RSS delta is valid.
For comparable samples, launch the CLI as a fresh lightweight process that
then launches the workload, and keep that launcher and environment consistent.
Exec of the collector does not reset its own lifetime accounting, but frees
the loaded image before the collector launches the measured child. The
reported PID and usage belong to that measured child, not to the outer CLI.
Other launch mechanisms/platforms can differ; this does not promise a
universal floor or establish the allocation in an earlier hosted failure.

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

Nine real-process controls cover CPU load, touched 64 MiB memory, a following
small child in the same fresh collector (detecting cumulative RSS contamination),
the same pair while the test caller retains 96 MiB, direct loaded-caller raw
RSS floor, nonzero exit, binary stdout
and stderr hashes, timeout and reaping, sleep elapsed distinct from CPU, invalid
timeouts, missing executable, and the CLI failure contract. The memory pair
retains its 64 MiB allocation and strict 32 MiB separation assertion. Before
the isolation repair, the retained loaded-caller regression failed that
assertion; direct raw collection remains intentionally subject to the floor.
The original seven missing-collector failures and subsequent positive-control
passes are historical evidence, not proof that the isolation defect was absent.
These controls validate
the collector only; they are not an OMG performance baseline. Exact commands,
hashes and run output should be retained with the measurement records.

## Reproducible measurement preparation

Before collecting a product baseline, record the tested commit, checkout state,
collector hash, toolchain and command. Verify that the collector exists on the
pinned source, or use its separately verified immutable path. Keep preparation
outside the measured samples and avoid competing guest or heavy build workloads.
Use a task-specific Cargo target with `CARGO_BUILD_JOBS=2` when building fixtures.

A repeatable protocol can use three warmups and twenty samples per case capped
at sixty seconds. Report actual output assertions, failures and exclusions with
the resource records; these instructions do not create a measurement reservation
or establish a product performance baseline. Review the collector and workload
contract before relying on numerical comparisons.
