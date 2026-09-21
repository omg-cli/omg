# QEMU installed Python behavior

Continue the approved verification plan by strengthening the existing runtime row, without adding another build or download.

1. Observe a failing harness regression: a version-only shell executable and a zero-exit no-op must not satisfy installed Python behavior.
2. Run the installed interpreter in isolated mode, checking its actual version and executable location, standard-library work, SQLite, SSL verification defaults, and creation of a private venv with bundled pip. Require an exact completion marker after every assertion and successful pip execution; bound runtime and preserve failure output.
3. Extend the SSH supervisor budget for the bounded probe, retain existing row cleanup and evidence identity, and document the precise scope. SSL defaults are not evidence of successful remote certificate verification.
4. Run runner fault-injection tests and the exact oracle against the four already-installed WSL runtimes. Preserve any new failure instead of weakening the probe. Keep this follow-up separate from the currently running #443 revision.

Python documents ensurepip as bundled and offline: https://docs.python.org/3.12/library/ensurepip.html. Do not add a network pip install or assume an eagerly populated CA store; certificate directories load lazily (https://docs.python.org/3.12/library/ssl.html#ssl.SSLContext.get_ca_certs).

Fixture-only success markers test runner admission, not runtime feature coverage. Real WSL and hosted interpreter execution supply the positive product evidence. This is a bounded improvement within the full verification objective, not a claim of complete Python lifecycle or global 95% coverage.

## Execution evidence

- The original runner admitted three bad interpreters; the regression failed for version-only, no-op, and execution-failure fixtures. The updated runner rejects each, preserves the failure cause, and accepts the explicitly synthetic admission fixture.
- All 30 output-oracle and inventory-policy tests passed. Shell syntax checks passed.
- The final exact oracle passed against installed 3.12.14 runtimes on Arch, Debian, Ubuntu and Fedora WSL. No second download was needed.
- Temporarily removing Ubuntu's installed `gzip.py` caused the real oracle to fail with `ModuleNotFoundError`; restoring the byte-identical module recovered. SQLite is built into this upstream distribution, so the initial attempt to locate a removable `_sqlite3` file made no changes and was replaced by this valid fault injection.
- Issue #461 retains the original coverage gap. Hosted validation of this follow-up remains pending; the currently running #443 revision intentionally does not include it.
