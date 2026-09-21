# Daemon concurrency assertion audit

The cache read/clear and cache-update tests discarded search responses, so all failed searches could still satisfy their completion counts. The metrics race test used a cumulative lower bound rather than its own request delta. These are test gaps, not demonstrated product defects.

The repair requires successful Search envelopes with matching IDs, an empty package list and exact zero total for the fixture's empty index. Clears require matching IDs and the exact `cleared` message. Concurrent Ping results require matching IDs and `pong`; metrics require exactly 101 new requests (100 pings and the final metrics request) and unchanged failed-request count.

The shared fixture injects a mock backend and an empty index without native Arch APIs. Its availability and this concurrency suite therefore move from the Arch feature gate to Unix, allowing the same handler assertions on supported Linux and macOS owners. This does not turn direct handler tests into Unix IPC evidence; existing production-server tests remain separate.

Research: [Tokio Barrier](https://docs.rs/tokio/latest/tokio/sync/struct.Barrier.html) can coordinate task starts, and [JoinSet](https://docs.rs/tokio/latest/tokio/task/struct.JoinSet.html) defines cancellation and draining. This repair preserves the existing scheduling fixture; it does not claim exhaustive interleavings, bounded standalone lifecycle, or independent task cleanup verification.

Local validation: all nine suite tests passed on Arch (arch features), Debian, Ubuntu (debian,pgp,license) and Fedora (fedora,pgp,license), with no ignored or filtered tests. These are incremental local builds, not hosted receipts. No coverage manifest gap is removed by this change alone.

In an isolated Ubuntu checkout, a negative control made the production Search dispatcher return an explicit error after its normal lookup. Both strengthened cache tests rejected that response. The existing concurrent-search test also failed. Source restoration was checked byte-for-byte. A first recovery invocation reused the mutant binary because restoration preserved the old source timestamp; it remained a failure. Updating that timestamp forced Cargo to recompile the restored source, after which all nine tests passed. Negative-control logs and recovery logs remain separate. The Windows product source was never mutated.

## Adjacent cache suite audit

The separate cache-coherency test requested `bash`, absent from the isolated mock catalog, and accepted two equal errors as evidence of successful caching. It now requires the known `git` package's literal version, description, source and response IDs, plus exact miss-then-hit metric deltas. The missing-package test separately requires the exact not-found code, package-specific message and IDs. Search hit-rate and clear tests now require successful empty-index payloads; hit-rate increments are exact rather than lower bounds. The mock-backed suite is enabled on Unix owners.

All seven tests passed separately on Arch, Debian, Ubuntu and Fedora WSL using the same feature selections above. These assertions establish bounded handler behavior, not native package contents, IPC, or full cache concurrency/lifecycle coverage. Hosted evidence and manifest reconciliation remain pending.

The subsequent status audit removes equality-only assertions: repeated and concurrent empty-fixture status reads now require matching IDs, zero package/update counts, no runtime versions and explicitly unscanned vulnerabilities. A bounded deadlock check also verifies those responses instead of discarding them. Same-key concurrent searches require exact empty payloads and IDs rather than merely agreeing with each other. Both suites passed again on all four WSL owners (seven cache and nine concurrency tests per owner).

## Required execution ownership

The follow-up review found these two strengthened suites were absent from the native runner's explicit target list. Add both to every Unix native owner's selected targets and declared platform policy. The selection checker already requires every selected binary to discover tests, and the CI profile uses zero retries; whole-suite admission preserves failures even without new contract bindings. A six-feature regression first failed for every owner, then passed after selection was added. The Windows verifier suite ran18 tests successfully with one Linux-runuser test skipped; that skip is not coverage evidence. Actual hosted execution of the added targets remains required before integration. No behavioral gap is closed merely by adding them to the runner.

Further assertion review still found generic Success-only checks in the concurrent-search and mixed-workload tests. Those require stronger payload assertions before claiming exhaustive handler coverage; they are not silently credited by this selection fix.

## Search and mixed-workload payload follow-through

Concurrent searches now require the Search variant, matching request ID, empty packages and zero total. Mixed requests check all four operation types against the originating request: searches, empty unscanned status, cache-clear acknowledgement and metrics. Metrics snapshots stay within the current batch's request bounds, and the final snapshot requires exactly51 additional requests with no new failures or rate limiting. This catches swapped responses and successful envelopes containing the wrong payload.

Research through Exa used [Tokio JoinHandle documentation](https://docs.rs/tokio/latest/tokio/task/struct.JoinHandle.html): each handle owns its task's result even if other tasks finish earlier. The existing insertion-ordered handles therefore retain request identity without assuming completion order.

The modified suite passed all9 tests on Debian WSL, with no ignored or filtered tests. A production Search dispatcher mutation returned a successful Ping payload after performing the lookup; both strengthened tests failed. The isolated handler was restored byte-for-byte, recompiled, and all9 tests passed again. Negative and restored logs are separate. Rustfmt and diff whitespace checks pass. This is bounded direct-handler evidence, not IPC or a95% claim. Other distro execution and hosted checks remain required.
