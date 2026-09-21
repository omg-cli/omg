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
claim complete capacity coverage. This test is not yet admitted to behavioral
coverage receipts; the broader connection-capacity gap remains open.
