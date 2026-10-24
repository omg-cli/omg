# Worker type boundaries

These patches correct Worker type boundaries and preserve reviewed runtime behavior. The Sandbox patch awaits RPC disconnects, retains the stopped client identity and checks execution fences. The Containers patch checks the lifecycle hook before starting a replacement. The CI patch validates finite command completion and retains raw logs.

- `@cloudflare/containers@0.3.7` uses the official Worker Request and Response types at its container boundary.
- `@cloudflare/sandbox@0.12.14` uses the same Worker Request, Response and ReadableStream types at its public container boundary.
- `@cloudflare/ci@0.2.0` carries Worker streams from Sandbox through runner logs into Workflow steps. Its local constructor declaration describes the actual Worker global and emits no JavaScript.
- `capnweb@0.8.0` maps tuple elements without spreading a union containing promises. Optional positions, readonly tuples, variadic tails and promise values retain their types.

Run `bun run check` to compile source, Bun tests and public API type fixtures separately. `type-tests/capnweb-tuples.ts` checks valid and invalid RPC argument shapes without diagnostic suppressions. `type-tests/worker-boundaries.ts` checks actual Worker requests, responses and persisted log streams.

The [official Worker typing guide](https://developers.cloudflare.com/workers/languages/typescript/#generate-types) recommends generated types for applications and workers-types for shared libraries. The [reported Node/Worker stream conflict](https://github.com/cloudflare/workers-sdk/issues/6211) explains why mixing ambient type families changes API assignability. The installed [Containers source](https://github.com/cloudflare/containers) and [native CI source](https://github.com/cloudflare/ci) target Workers. Sandbox 1.x changes the runtime API and is not a drop-in typing correction for this pinned 0.x pipeline.

Finite commands use `sandbox.exec` with an independent completion watchdog. The adapter validates terminal exit code and success consistency, retains raw logs, and never restarts the command. Missing or inconsistent completion cannot pass. `sdk-workflow-logs.test.mjs` exercises the patched SDK through Workerd and R2 for normal, failed, missing, invalid, timed-out and late process results.
