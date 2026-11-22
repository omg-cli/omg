# Isolated advisory baseline staging

`wrangler.example.json` is a disabled example for the isolated Nov 21 baseline stage, not deployment configuration. Do not target production or enable the stage without separate operator approval. The stage uses its own Wrangler config, Worker, D1 database and private R2 bucket. Its only admitted hostname is `https://omg-advisories-stage-20261121-1d6c61c4.latham.workers.dev`; keep version previews off. Configure the exact hostname's Cloudflare Access application before exposing it and use its application AUD as `STAGE_ACCESS_AUD`. The Worker requires the trusted invocation's Access context with that AUD, not an Access or forwarding header supplied by the caller. Confirm Service Auth ingress on the existing plan, rather than enabling Access account-wide.

After independently checking both resource bindings, record the fresh database's `database_instance.id` as `STAGE_DATABASE_INSTANCE_ID`. Only the approved isolated bucket gets the empty marker object `stage-isolation/<database instance id>`. Both checks must match before the stage handler can read or write advisory state. Enable `STAGE_MODE=isolated-baseline-v1` only with these checks and distinct stage-only `STAGE_INGEST_TOKEN` and `STAGE_RUNTIME_REFRESH_SECRET` secrets, neither copied from production. Cron remains off unless separately configured and enabled with `STAGE_ENABLE_CRON=true`.

The stage operator targets only the pinned host, refuses redirects, and uses `STAGE_ACCESS_CLIENT_ID` and `STAGE_ACCESS_CLIENT_SECRET` plus the respective stage operation secret from the environment. Proof also needs the usual ephemeral GitHub installation token. The operator doesn't accept an endpoint or a token file. Its private checkpoint envelope is incompatible with the production tools. Do not use the production advisory workflow on staging.

The stage handler binds private baseline operations to the fixed production origin from the first write, without sending anything to production or changing which environment receives the request. Switching the resource bindings of the **unmodified** production Worker after separately approved proof and cutover can preserve the exact canonical session. Do not copy or edit an endpoint in a receipt to make promotion work. Stage cron and writers must be stopped before promotion; rollback reselects the intact incumbent Worker and resource pair. Cloud deployment, Access enforcement, real resource IDs, limits, import and cutover still require operator receipts; an offline fixture or a dry bundle cannot establish them.

## Physical admission before routing

After separate approval, boot an inert stage stub with `STAGE_MODE=disabled`, no D1/R2, no Cron, routes, workers.dev subdomain or Version URLs. Do not deploy the example directly. Independently record the approved physical D1 UUID and Standard R2 bucket name/default jurisdiction in a local JSON manifest with `account_id`, `worker`, `d1_id`, `r2_bucket` and `r2_jurisdiction`. Use the approved UUID in the stage config, not the placeholder. Confirm the exact title/identity of the resources and reserve the quota before uploading an enabled draft. Upload the reviewed candidate as a version with the subdomain and Version URLs off; do not deploy it or create a route. The latest active version stays the inert stub.

Use a read-only Cloudflare API credential through the existing approved environment mechanism. Do not pass it on the command line. With the explicit JSON config used for the upload and the exact returned version ID:

```sh
bun services/advisory-staging/admission.ts --approved "$APPROVED_IDS" --config "$STAGE_CONFIG" --version "$DRAFT_VERSION"
```

The admission command does not change resources. It queries Cloudflare's exact effective draft and serving versions and reads the named D1/R2 resources in the expected account. It refuses unknown or incumbent identities, active candidates, a non-inert stub, enabled stage ingress/previews, and config/effective mismatches. The logical instance and bucket marker are additional runtime protections, not proof of which physical stores Cloudflare bound. Save the receipt, recheck admission immediately before any separately approved activation, and use only the returned version ID. Never shortcut with a normal `wrangler deploy`. Require the exact host's Access policy independently before enabling that host, leave previews and any alternate routes off, and verify both positive and denied live probes before any import. If any provider data is missing, ambiguous or no longer matches, leave routing off. Cron remains off for this admission; a later staged Cron change must preserve both admitted bindings and be independently checked without changing production.

Once the operator has approved the protected route, verified actual bindings and the delta window, and obtained separate import authorization:

```sh
bun services/advisory-staging/operator.ts ingest --state "$PRIVATE_STAGE_STATE" --archive "$EXACT_ZIP" --max-records 256
bun services/advisory-staging/operator.ts finalize --state "$PRIVATE_STAGE_STATE"
bun services/advisory-staging/operator.ts prove --state "$PRIVATE_STAGE_STATE"
```

The remaining ingest waves are serial, at most 1,000 records, and must finish with the archive exhausted before finalization. Finalize only after fresh catch-up; proof is capped at 20 calls. The stage operator is qualified for the exact Nov 21 digest and tag commit, not for newer sources. Stop on mismatch or missing receipts. No command here authorizes provisioning, import, cutover, merge, or release.
