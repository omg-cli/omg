# Tier 3 credit coverage for the OMG pipeline

Reviewed October 20, 2026 against the deployed OMG resources and Cloudflare's current public documentation. This is an eligibility and account-status review, not a guarantee of future invoice treatment.

## Confirmed program terms

The current [Startup Program page](https://www.cloudflare.com/startups/) gives Tier 3 a $10,000 shared credit balance and caps Workers AI consumption of that balance at $2,500. R2 has a $10,000 product ceiling, bounded by the remaining shared balance. These are not additional grants. If the full AI allowance is used, $7,500 of the original balance remains for other eligible charges. The page explicitly lists Workers, Workers for Platforms, Durable Objects, Workflows and R2 as covered services.

The same page excludes AI Gateway, Registrar purchases, enterprise feature add-ons by default, and specified premium network services. Credits expire after one year or when consumed. Overage charges and taxes must not be described as covered by an unlimited allowance.

## Actual service inventory and evidence

| Pipeline dependency | Actual use | Published coverage evidence | Conclusion |
| --- | --- | --- | --- |
| Workers | `omg-cloud-ci`, `omg-ci-inspector`, `omg-ci-coder` | Explicitly listed on the [Startup page](https://www.cloudflare.com/startups/). | Usage is documented as eligible while the award is active and has balance. |
| Durable Objects and SQLite | Separate verifier Sandbox and coder namespaces | Both the compute category and Durable Objects are listed on the [Startup page](https://www.cloudflare.com/startups/). | Documented eligibility. |
| Workflows | `omg-cloud-ci` | Explicitly listed on the [Startup page](https://www.cloudflare.com/startups/). | Documented eligibility. |
| Workers AI | Direct AI binding in inspector/coder | Tier 3's $2,500 limit is explicit on the [Startup page](https://www.cloudflare.com/startups/). | Eligible within that subcap and the shared balance. No AI Gateway is configured. |
| R2 | Private `omg-ci-private` bucket for snapshots, logs and evidence | R2 and its product ceiling are explicit on the [Startup page](https://www.cloudflare.com/startups/). [R2 pricing](https://developers.cloudflare.com/r2/pricing/) defines storage and operation charges. | Documented eligibility. Do not treat the R2 ceiling as another $10,000 grant. |
| Sandbox execution / Containers | `omg-cloud-ci-cisandbox`, standard-4, maximum two instances | [Containers pricing](https://developers.cloudflare.com/containers/platform/pricing/) defines active CPU, memory, disk, network egress and logging charges. Cloudflare's [program announcement](https://blog.cloudflare.com/expanding-cloudflares-startup-program/) states broad pay-as-you-go eligibility. | Eligibility is supported by the general policy, but the current Startup page does not name Containers. Account-specific deduction has not been established. |
| Artifacts | Namespace `omg-ci`, repository `omg` | [Artifacts pricing](https://developers.cloudflare.com/artifacts/platform/pricing/) defines repository operations and GB-month storage on Workers Paid. The [program announcement](https://blog.cloudflare.com/expanding-cloudflares-startup-program/) supplies the general pay-as-you-go statement. | Supported by the general policy, without named-SKU or invoice confirmation. |
| Managed image registry | Private `omg-cloud-ci` image in `registry.cloudflare.com` | [Image management](https://developers.cloudflare.com/containers/guides/image-management/) documents the registry and push path. The reviewed pricing pages did not establish a separate registry charge or its credit mapping. | Do not invent a free tier or claim an independently verified deduction. Confirm whether there is a separate billable SKU. |
| Workers Paid subscription | Required by Containers and Artifacts | Both product pricing pages require Workers Paid. The Startup page describes usage-based coverage, but does not establish this account's treatment of the fixed monthly subscription separately. | Fixed subscription treatment remains an invoice/support question. |
| Code Mode and OpenCode SDK | Worker loader and local SDK dependencies, direct Workers AI | These use the existing Worker/AI/DO bindings. [OpenCode on Cloudflare](https://developers.cloudflare.com/agents/harnesses/opencode/) describes that execution model. | No separate external model-provider endpoint or AI Gateway was found in the deployed implementation. This does not establish the price of any future integration. |
| Workers Logs | Observability currently disabled in all three configurations | [Containers pricing](https://developers.cloudflare.com/containers/platform/pricing/) explains its integration with Workers Logs. | No broad logging was enabled during this review. Recheck costs if it is enabled. |
| GitHub Actions / native / QEMU, Firecrawl, local Codex and WSL | Existing external checks and operator tools | These are outside Cloudflare billing. | A Cloudflare grant cannot pay these providers or local hardware costs. Their own plans and allowances apply. |

The program announcement predates the current tier amounts. Its broad product-policy statement is supporting evidence only; the current Startup page controls the Tier 3 amount, AI subcap and exclusions.

## Account verification

The signed-in Cloudflare dashboard for the deployment account showed an active $10,000 award, $10,000 estimated remaining, zero percent consumed, start October 6, 2026 and expiry October 6, 2027. The dashboard explicitly says the final balance is confirmed on the monthly invoice. Its generic $50,000 AI label does not override the current Tier 3 $2,500 limit.

Current billable usage showed no available usage data and a $0 estimate. That is not proof that the deployed resources used no capacity, nor that a particular SKU has already received a credit deduction. Finalized invoices were listed, but readable line items were not obtained through the available download control. The billing API rejected the connected OAuth credential because that endpoint requires Billing Read; no broader token was created.

## Remaining confirmation needed

A definitive all-SKU guarantee is not supported by the evidence above. Obtain written account-specific confirmation from the Startup team, or a finalized invoice containing the relevant charge and matching deduction, for Containers, Artifacts, any managed-registry charge and the Workers Paid base subscription. Keep documented eligibility separate from actual invoice application.

Suggested question to Cloudflare, not sent by this job:

> For our active Tier 3 $10,000 Startup award, please confirm that Containers CPU/memory/disk/egress, Artifacts operations and storage, any managed container-registry storage, and the Workers Paid monthly subscription deduct from the same award. Please identify any excluded SKU or additional cap. We already understand the $2,500 Workers AI subcap and the R2 ceiling. Please also confirm whether any Sandbox or Worker Loader charge is billed separately from those covered primitives.

The user can supply their account ID privately when sending that question. No support message, payment, subscription change or credit-policy change was made here.
