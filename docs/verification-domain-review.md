# Behavioral domain review

This ledger reviews the requirements behind provisional inventory gaps. A reviewed
surface earns execution credit only when all its owning contracts pass admission
for the current source and platform. This document does not set the global
`behavioral_inventory_reviewed` flag or certify 95% coverage. The final independent
whole-branch review remains required.

## OMGD Ping

Sources: `Request::Ping { id: u64 }` in `src/daemon/protocol.rs`, its unconditional
`pong` branch in `src/daemon/handlers.rs`, and the shared request framing and rate
limiter in `src/daemon/server.rs`.

The request accepts every `u64` ID and has no package, path, query or mutation
argument. It must return exactly `pong` and preserve the ID. Backend package state
must remain unchanged. Distinct simultaneous clients must receive their own
responses. An incomplete, half-closed request must be closed without a successful
response and must not prevent a fresh client from succeeding. Rate limiting must
preserve request identity, provide the defined refusal and keep the connection
usable after refill. Each test must drain the server and check fixture cleanup.

| Requirement | Owning production-server test |
| --- | --- |
| Exact response, IDs 0/1/u64::MAX-1/u64::MAX and intermediate values, 16 connected clients released together, unchanged backend state | `concurrent_pings_preserve_boundary_ids_and_backend_state` |
| Partial length header and partial frame body, bounded EOF after write shutdown, subsequent exact pong | `incomplete_frames_disconnect_without_breaking_a_fresh_client` |
| Successful burst replies, exact RATE_LIMITED envelopes, same-connection recovery | `rate_limited_burst_rejects_with_exact_envelope_and_keeps_connection_open` |

The three `omgd.ping-*.server-fixture` contracts replace Ping's generic provisional
all-kinds gap. All three remain required; a pass in one or two cannot earn surface
credit. The target remains false until the whole inventory is reviewed. Native
package transactions do not apply to this backend-independent request. General
protocol version/decoding limits, authorization, connection capacity, process
lifecycle and worker supervision retain their separate open surfaces; this review
does not claim to close them or exhaust every scheduler interleaving.

[Tokio documents write-half shutdown](https://docs.rs/tokio/latest/tokio/net/struct.UnixStream.html)
as EOF at the peer while leaving the local read half available. The interrupted
request assertion uses that behavior to verify the server's actual close, rather
than dropping the client and inferring that the server released the connection.

## Connection capacity lifecycle evidence

`connection_capacity_refuses_overflow_and_recovers_released_permits` holds
128 real production-server connections, proves each accepted client can receive
an exact Pong, and observes clean EOF for connection 129. It releases one client,
observes the count fall, proves a replacement works, rejects overflow again, then
releases all clients and checks continued service and SIGTERM cleanup.

Metrics use an already held control connection: opening a probe connection at
capacity would itself hit the refusal under test. Bounded polling observes task
cleanup; it does not retry the refused request until it happens to succeed.

The root path is listener accept -> nonblocking semaphore acquisition -> owned
permit held by the connection task -> task completion -> permit release.
[Tokio's owned permit documentation](https://docs.rs/tokio/latest/tokio/sync/struct.OwnedSemaphorePermit.html)
confirms that dropping the permit releases its capacity. Changing the product
limit from 128 to 129 in an isolated negative control fails the overflow assertion.
This closes a specific test gap; it does not establish a production defect or
claim complete capacity coverage. The bounded contract is admitted through production-server behavioral receipts;
the broader connection-capacity gap remains open.

## Frame refusal and exact size boundaries

Five bounded frame contracts now use real production-server receipts: future
protocol version, short version header, undecodable request body, oversized
announcement, and exact accepted framing sizes. Each checks the appropriate
wire refusal, connection teardown, exactly one failed-request metric increment,
and fixture shutdown/cleanup. The body test checks the diagnostic cause prefix;
it does not certify an exact bitcode diagnostic or the separate validation-failure
counter merely because its historical test name mentions that counter.

`exact_frame_size_boundaries_reach_protocol_validation` checks lengths 0, 1, 2,
3, 4, 1 MiB minus one, and exactly 1 MiB. An exact protocol error proves delivery
to protocol validation instead of rejection by the framing codec. A final exact
Pong proves service remains available. The existing oversized test covers cap
plus one and requires silent teardown, allowing a kernel reset when unread bytes
remain. No malformed request earns successful-handler credit.

[Tokio's length codec documentation](https://docs.rs/tokio-util/latest/tokio_util/codec/length_delimited/struct.LengthDelimitedCodec.html)
defines the maximum as the largest accepted frame size. An isolated mutation
lowering the limit by one byte fails the new boundary test; source restoration is
checked. Cancellation, backpressure, exhaustive payload decoding, and response
size boundaries remain open. These contracts do not close the broad frame gap.

## DebianSearch transport and cache evidence

`debian_search_preserves_catalog_limits_cache_and_refusal_over_real_ipc` seeds
1,005 literal package records and checks exact names, versions, descriptions and
APT source tags through the production server. The first query requests zero
results, followed by limits one, default fifty, one thousand and usize::MAX.
One cache miss and four hits must still return the correct wider results; caching
only the first response would fail. An isolated mutation doing exactly that fails
at the first wider request, with source restoration checked afterward.

Empty and 500-byte unmatched queries return empty results; a 501-byte query must
return the exact invalid-parameter envelope. The backend state file remains
unchanged, a subsequent Ping succeeds, and shutdown and directory cleanup are
checked. These assertions are admitted as a bounded DebianSearch contract on the
Unix production-server lane. They do not certify native APT integration, refresh
races, every text-search ordering case or standalone process behavior, so the
broader DebianSearch gap remains open.

## SecurityAudit inventory admission and recovery

`security_audit_backend_failure_cannot_report_a_clean_scan` checks the actual
server's empty-inventory result, then corrupts the isolated backend state. The
next request must return the exact INTERNAL_ERROR, request ID and inventory
failure cause; it must preserve the corrupt bytes and keep serving Ping. After
repair, the empty result must recover, all three audit requests must be counted,
and shutdown/cleanup must complete. An isolated mutation converting inventory
errors to an empty package list fails as a false clean scan.

This is an inventory admission/refusal contract, not vulnerability scanner
coverage. No installed packages are scanned here, so advisory networking,
positive findings, severity scores, scanner errors and cancellation remain open.
The generic SecurityAudit gap is retained.

## Beta advisory fetching: pagination repair design

The beta requirement includes real advisory fetching and vulnerability scoring,
not just inventory admission. Source review found that OsvResponse ignored
next_page_token, and scan_package cached the first response as complete. OSV's
query specification explicitly allows pages with only a continuation token.
This can lose findings or cache a false empty result.

The repair will keep package/ecosystem/version fixed while following page_token,
accumulate findings until completion, and only then publish the cache entry.
Continuation cycles or a bounded page-budget exhaustion must be errors, never
successful partial scans. Regression fixtures must include an empty intermediate
page, multiple findings with numeric/CVSS scores, exact outgoing continuation
requests, and no cache entry after a later-page error. Full OMGD/CLI fetching and
scoring verification remains required after the scanner-level repair.

Primary source: https://google.github.io/osv.dev/post-v1-query/

Pagination regression evidence: the original scanner returned zero findings
instead of two from a three-page fixture. The repaired scanner passes that test
and later-page HTTP503, malformed JSON, and repeated-token cases. Each failure
must return its typed error; a subsequent scan must fetch a fresh complete
finding instead of returning the earlier partial page. Numeric 7.5/8.1 and CVSS
3.1 vector9.8 are verified from HTTP responses. The final cache check runs after
the fixture listener closes, proving complete results are reused.

This repair follows tokens with a100-page budget and rejects token cycles.
The page-budget failure branch still needs explicit exercise. It does not yet
establish full daemon/CLI fetching or scoring coverage; those integrations remain
beta requirements, not optional follow-ups.

## Optional daemon: shared scanning architecture

The CLI's audit scan, fix and vulnerability export paths now call one helper:
use a reachable daemon, otherwise use the package manager and shared security
scanner directly. An actual error from a connected daemon remains an error;
it is not hidden by a second scan. The package audit result models and aggregation
live in core/security/scan.rs; the daemon protocol reexports the same models,
preserving field layout. Both paths share concurrency, failure propagation,
severity thresholding and audit completion logging.

The real CLI regression first failed solely because OMG_DISABLE_DAEMON disabled
OMGD. It now verifies empty inventory scanning and fix dry-run, corrupt inventory
failure without false-clean output or state loss, and recovery after repair.
The production daemon/Unix-socket/HTTP test verifies populated paginated scans,
9.8 CVSS and6.9 numeric findings, unknown scores, warm-cache reuse, package-version
change,503 refusal, recovery and the7.0 high-severity boundary. SIGTERM drain and
fixture cleanup are asserted. Advisory endpoints are customizable only in cfg(test).

Four-distro local batches pass these tests, scanner tests and coverage_18. This
is still not native advisory-ecosystem certification. In particular, Fedora has
no configured OSV ecosystem today. Native Fedora advisory fetching and scoring
remain required for beta; DNF5's official advisory list/info JSON documentation
is the next primary source: https://dnf5.readthedocs.io/en/stable/commands/advisory.8.html

The pagination page-budget branch is now explicitly exercised:100 unique
continuations must fail, then a fresh complete scan succeeds without partial
cache reuse.

TUI parity follow-through: `App::run_security_audit` now uses the same optional-
daemon scan helper as CLI audit commands. A Fedora regression first failed
because the old path required an Arch/Debian backend. It now passes on all four
Linux test builds with the daemon disabled, proving empty-inventory success,
corrupt-inventory refusal, repaired-state recovery and checked fixture cleanup.
This does not certify populated native Fedora scans.

One production legacy caller remains: `server.rs` background status refresh
still calls `VulnerabilityScanner::scan_system`. Consolidation must verify cache
publication and concurrent background/on-demand fetching; replacing it without
those checks could introduce duplicate requests or stale status claims.

Background scan consolidation: production status refresh now uses the same
shared scan as requested audits, with a daemon-owned asynchronous scan lock.
Isolated daemon construction disables unsolicited background advisory fetching;
fixtures that test it must explicitly enable it and inject their HTTP endpoint.
The real-server test requires status publication of all three paginated findings
before requested audits, preserving the subsequent cache/error/recovery checks.
Its previous implementation failed that publication deadline on Fedora.

All production call sites of the older ALSA-only `scan_system` path have now
been removed. The legacy public method and its tests remain; this change does
not remove API compatibility. Explicit contention/cancellation coverage of the
new scan lock and native advisory ecosystem coverage remain outstanding.

Cancellation evidence now covers the shared daemon scan task: a real HTTP
response is withheld, an explicitly polled waiting scan is dropped, the active
task is aborted, its HTTP connection must close, and a new scan must obtain fresh
findings. The fixture checks inventory preservation and cleanup. Removing the
scan lock causes the test to fail. This proves task cancellation and lock release;
it does not claim that an arbitrary IPC disconnect cancels an in-flight scan.

Hosted revision7f068ff1 exposed stale integration expectations: cli_comprehensive
still expected four empty-inventory audit commands to fail without a daemon, and
coverage_2 expected the daemon gate. Those checks now require successful scan
output, with corrupt-inventory refusal retained in security_daemon_optional.
The inventory digest is updated in the QEMU allowlist while retaining historical
entries. Local inventory, paywall, QEMU/release harness and lint checks pass;
the failed hosted runs remain recorded and need fresh revision validation.
