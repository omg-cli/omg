# SQLite WAL-reset regression probe

Issue [#908](https://github.com/omg-cli/omg/issues/908) tracks the Fedora native
SQLite baseline. This opt-in Linux fixture checks whether concurrent WAL
checkpoints lose committed rows or make the database unreadable. It loads the
explicit library path with `dlopen`; it does not install a package.

SQLite documents the race and fixed versions in its
[WAL-reset bug description](https://sqlite.org/wal.html#walresetbug). The workload
uses the large mapping/checkpoint interleaving described by the reproducer's
author in [Another look at SQLite's WAL-Reset bug](https://theconsensus.dev/p/2026/08/23/another-look-at-sqlite-wal-reset.html).
The fixture independently implements that public-API scenario.

Use an ordinary Linux user, a disposable directory in a memory filesystem with
at least 600 MiB available, a C compiler, SQLite development headers, and
`timeout`/`prlimit`. Never pass a real package-manager database. A typical run
uses about 270 MiB for the temporary database; the mapping may reserve 1 GiB.
Set `library` to an absolute, independently verified shared-library path.

```bash
library=/absolute/path/to/libsqlite3.so
repo=$PWD
scratch=$(mktemp -d /dev/shm/omg-wal-probe.XXXXXX)
trap 'rm -f -- "$scratch/probe" "$scratch/race.db" "$scratch/race.db-wal" "$scratch/race.db-shm"; rmdir -- "$scratch"' EXIT
cc -O2 -Wall -Wextra -Werror "$repo/tests/fixtures/sqlite-wal-reset.c" \
  -o "$scratch/probe" -ldl -pthread
sha256sum "$repo/tests/fixtures/sqlite-wal-reset.c" "$library"
ulimit -c 0
timeout --kill-after=5s 60s prlimit --cpu=50 --as=2147483648 \
  --fsize=536870912 "$scratch/probe" "$library" "$scratch/race.db"
```

Retain stdout, stderr, exit code, elapsed time, library digest and source ID
before cleanup. Exit 1 means missing/unreadable committed rows or a failed
integrity check. Exit 2 means a harness/setup error; timeout or signal termination
is also a harness failure. Exit 0 means this bounded run recovered all committed
rows and passed the integrity check. The race is timing-dependent: a green run
alone does not establish that an affected build is fixed. Confirm the publisher's
package signature and source patch or a known fixed upstream version as well.

The initial differential on October 10, 2026 used the authenticated Fedora
`sqlite-libs-3.51.2-1.fc44` library, SHA-256
`cd5973b41be9764a186b4e2b1e6300b7769f510cdde272a63f9aa402edd7ae12`.
It failed on round 3 with 1,119 committed rows, unreadable recovered rows and a
failed integrity check. A local SQLite 3.53.4 control completed 200 rounds with
121,775 committed and recovered rows and a passing integrity check. The control
is not a verified Fedora replacement package. See #908 for the retained receipt.

This probe does not reproduce DNF's historical crash in
[#626](https://github.com/omg-cli/omg/issues/626), certify an image renewal, or
replace native package transactions and QEMU guest admission. It remains a
manual diagnostic so a scheduling-dependent race does not become a flaky CI gate.