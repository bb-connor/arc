# PR #1173 code review and repairs

This review follows the executable changes in the verifiable-work session,
including native admission and settlement, delegated continuations, federation,
protocol adapters, the funded-work and comparison programs, and the evidence
tooling. The W1-W4 design plans remain plans. Their acceptance criteria are not
treated as implemented functionality.

The initial candidate was `c3b423557727129f374f7711e498f1e4bce756e0`.
It contained 575 source or tooling paths among 2,879 changed paths against its
original merge base. Integration with the current security and retention branch
is part of this review. The retained records distinguish historical failures,
focused repaired runs, and the final source-bound native qualification.

## Confirmed findings

| Priority | Defect | Repair and regression boundary |
| --- | --- | --- |
| P1 | The native security participant reader rejected supported admission schema 36, blocking ordinary native operations. | Accept the supported successor schema without changing the native catalog digest; reject unsupported versions and verify the live catalog. |
| P2 | An already resolved checked-output denial could be stranded when output authority expired before recovery. | Resume its exact retained zero-charge obligation without fresh output release; retain frozen transform, decision, pricing, digest and settlement checks. Allow replay still requires live guards. |
| P2 | Unknown-payment release could use a backdated caller timestamp to accept expired consent. | Qualify fresh consent against owner time and reject decisions before issuance; already accepted obligations remain recoverable. |
| P2 | Combined native admission omitted an earlier receiver-side governance deadline. | Intersect both signed presentation windows into the native dispatch deadline. |
| P2 | The example HTTPS server accepted unbounded request headers before authentication. | Bound the complete header block before the HTTP parser, require explicit framing and close semantics, and retain bounded bodies. Test oversized single and aggregate TLS headers. |
| P2 | Buyer accounting counted released reservations as still reserved. | Exclude released reservations and assert exact available, reserved and spent balances. |
| P2 | Future and reversed issue times defeated the comparison receiver's maximum token lifetime. | Use checked time arithmetic and reject invalid issuance windows before dispatch. |
| P2 | Missing or malformed comparison amounts silently became zero. | Reject absent, null, fractional, negative and nonnumeric amounts in both profiles. |
| P2 | Federation experiment heartbeats could install a fresh root with missing or stale revocation subjects. | Require an origin-signed complete subject snapshot bound to the exact root before publishing or accepting each epoch; reject conflicting, incomplete and mixed batches atomically. |
| P2 | Second-rounded federation timestamps could already be stale under the current millisecond authority clock. | Use the exact publish time under the existing freshness policy. |
| P2 | The experiment counted rejected or mismatched root acknowledgements as delivery. | Accept only the exact acknowledged epoch. |
| P2 | The admission timing wrapper omitted the store's atomic trust-floor method, denying valid network calls. | Forward the atomic operation and the related retained-source lookups unchanged; test predecessor rejection without mutation and a valid successor. |
| P2 | Hosted live C++ conformance lacked the enforcing host fixture required by the current CLI. | Prepare and qualify the existing native fixture and build the real-enforcement CLI before the five live consumers. Hosted x86 evidence remains necessary. |
| P2 | New A2A v1 tests used the old parsed-value ingress API and failed to compile against the security base. | Serialize the test requests and exercise the bounded original-byte API. |

Integration also repairs schema-migration fixtures, shared-clock fixture wiring,
module size violations, schema registration, and security-reader inventory drift.
The named reader witnesses are finite lexical regression tripwires. Their source
checks supplement the owning Rust tests; they do not prove authentication or
whole-program dataflow. No raw-input baseline is promoted merely to pass a gate.

The pinned ERC-8183 capture is stored as deterministic gzip. Its decompressed
41,976 bytes and original SHA-256 are unchanged. The artifact checker validates
that pin, rejects invalid metadata and confined-path violations, and limits
decompression before accepting the source.

## Evidence and limits

`logs.json` inventories retained diagnostic streams with uncompressed hashes.
Initial failures and partial campaigns remain present. The HTTPS summary covers
19 scenarios. The federation summary is a small debug network smoke with real
loopback peers, denial cases, duplicate races, and revocation/cut recovery; it is
not a performance benchmark or independent operation.

The current source-bound native qualification is maintained at
`docs/research/dynamic-delegation/evidence/qualification.json`. Historical native
inventories and benchmark results retain their original revisions. The six
chain-dependent tests ignored by the default funded-work suite are explicitly
opt-in tests, not passes from that suite.

This review does not establish external operation, production deployment,
release qualification of the complete workspace, or the whitepaper's open
economic and foundational claims. `publish_ready` and `breakthrough_established`
remain false. Exact-head hosted status must be read from the PR after the repair
commit is pushed; local aarch64 checks cannot qualify the x86 enforcing fixture.
