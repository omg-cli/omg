# Node runtime behavioral verification

The QEMU inventory currently exercises an actual Python download but has no equivalent Node.js download row. Native fixture tests do not establish that the published runtime and bundled npm work on each supported distro.

## Scope and evidence

- Add a bounded, isolated `runtime-node-install` row on Arch, Debian, Ubuntu and Fedora, using an exact published release. The official index observed on 2026-09-21 identifies v24.21.0 as Krypton LTS with npm 11.19.0. Do not infer LTS from the highest major version.
- Verify the selected version directory, current symlink and executable are confined to the row's data directory; require exact `process.version` and `process.execPath`.
- Execute real JavaScript that checks a known SHA-256 digest, compression roundtrip, filesystem writes/reads and a child process using the same executable. Require completion after all assertions, not version output alone.
- Exercise bundled npm through the installed Node executable, using a private cache and offline mode. Run a dependency-free local package script and assert its output file, so npm version output alone is insufficient.
- Keep network access limited to the installation phase where practical. No package registry dependency is needed for the behavior oracle.
- Test missing/inactive/escaped installations, version-only/no-op interpreters, failing JavaScript, missing/broken npm and omitted script side effects. Preserve useful failure diagnostics and explicit cleanup assertions.
- Update the inventory hash policy and owning tests together. Existing release inventory identities remain historical records.
- Validate first with real WSL installations on all four distros, then fresh hosted QEMU. Local incremental binaries are not exact-revision hosted proof. Leave broader runtime contracts and coverage claims open.

## Research

Exa primary-source research on 2026-09-21:

- https://nodejs.org/api/crypto.html documents `createHash` and that crypto support may be absent, supporting a real known-value operation rather than assuming availability from version output.
- https://nodejs.org/api/worker_threads.html documents real parallel JavaScript workers; worker behavior remains a separate follow-up rather than being claimed by a synchronous smoke test.
- https://nodejs.org/api/index.html identifies independently testable standard-library surfaces. A small smoke test does not establish exhaustive upstream Node correctness.
- https://nodejs.org/dist/index.json supplies exact release/LTS/npm metadata; the test should pin its selected release and document later updates.

This is an implementation slice of the approved verification plan, not a reduction of the full OMG/OMGD coverage objective.

## Initial feasibility evidence

On 2026-09-21, existing incremental WSL debug binaries successfully installed Node 24.21.0 as unprivileged `omg-audit` on all four distros. Each run verified the current link and executable confinement, exact version/executable, SHA-256, gzip roundtrip, same-runtime child execution and filesystem JSON readback. Bundled npm reported 11.19.0 and executed a dependency-free offline package script whose output file had exact expected bytes.

Preserved isolated fixture directories under `/home/omg-audit/`:

- Ubuntu: `omg-node-behavior.wjl6qS`
- Arch: `omg-node-behavior.vAQxug`
- Debian: `omg-node-behavior.0KHm9D`
- Fedora: `omg-node-behavior.tQx60a`

These exploratory probes establish feasibility only. They used existing incremental binaries, retained fixtures for inspection and are not admitted coverage receipts or evidence of QEMU integration. Next implement the runner oracle, adversarial admission fixtures, policy identity and cleanup checks before collecting exact-revision evidence.
