# Issue489 scheduling investigation and proposed correction
Observed failure: QEMU independent PR workflow waits up to25minutes for CI native producer, then consumer admission has short deadline. PR485 Fedora producer had no runner/artifact when guest admission expired. Do not claim why runner allocation was delayed.

Preferred design to validate: make automatic QEMU a reusable workflow called by CI with needs on native Linux/Ubuntu producers. Keep schedule and workflow_dispatch as standalone QEMU entry points. Preserve current source checkout/event and all artifact digest/provenance/attempt checks. No fallback duplicate compilation. The dependency prevents a consumer runner from waiting while producer jobs remain queued; remove automatic readiness polling only once the explicit dependency exists.

Required integration surfaces before implementation can claim correctness:
- CI scope classifier must request native builds whenever automatic QEMU requires them, including harness-only changes.
- CI Success must fail on required QEMU failures or unexpected skips; docs-only paths remain explicit.
- Main release-tag must depend on that QEMU result; remove external QEMU workflow-success lookup for the integrated automatic path to avoid a cycle. Review release.yml and every require-workflow-success caller similarly.
- QEMU failure reporter must support trusted CI-completion artifacts as well as standalone QEMU, authenticate workflow identity/source/event, keep PR artifacts outside issue-write path, and retain detailed failure catalogs. Update reporter allowlist and fixtures, not just trigger YAML.
- Reusable nesting retains caller github context; distinct concurrency groups must not cancel the caller. Permissions may only narrow. Do not inherit extra secrets.
- Native artifact lookup must select exact current CI run/attempt and immutable matching checkout. Test rejection of stale/foreign producer artifacts unchanged.
- Exercise delayed producer graph, failed producer, guest product failure, missing evidence, docs-only, PR, push/main, nightly and staged dispatch. Confirm issue creation/update/history on trusted path using controlled fixtures plus actual retained evidence.
- Fresh hosted run must prove native builds precede QEMU, same artifact pairs used, failures propagate and no release cycle exists.

Primary references researched through Exa:
https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows
https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax
https://github.com/github/docs/blob/main/content/actions/reference/workflows-and-actions/reusing-workflow-configurations.md

Implemented locally: CI calls QEMU after native producers, CI Success requires the selected guest result, and release checks use that integrated gate. Nightly/manual QEMU remain standalone. Trusted reporting accepts main-push CI evidence and refuses incomplete four-distro evidence before closing historical issues.

Local validation: 297 script tests passed with two explicit skips, all 20 QEMU workflow tests passed, and Actionlint 1.7.12 accepted the four changed workflows with shellcheck/pyflakes disabled. These establish local regression and syntax results, not hosted scheduling or 95% behavioral coverage. Fresh hosted execution and final review remain required. This branch includes the pending artifact-discovery fix from PR486; merge that prerequisite first.
